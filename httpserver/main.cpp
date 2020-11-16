#include "channel_encryption.hpp"
#include "command_line.h"
#include "http_connection.h"
#include "italo_logger.h"
#include "italod_key.h"
#include "rate_limiter.h"
#include "security.h"
#include "service_node.h"
#include "swarm.h"
#include "utils.hpp"
#include "version.h"

#include "lmq_server.h"
#include "request_handler.h"

#include <boost/filesystem.hpp>
#include <sodium.h>

#include <cstdlib>
#include <iostream>
#include <vector>

#ifdef ENABLE_SYSTEMD
extern "C" {
#include <systemd/sd-daemon.h>
}
#endif

namespace fs = boost::filesystem;

static std::optional<fs::path> get_home_dir() {

    /// TODO: support default dir for Windows
#ifdef WIN32
    return std::nullopt;
#endif

    char* pszHome = getenv("HOME");
    if (pszHome == NULL || strlen(pszHome) == 0)
        return std::nullopt;

    return fs::path(pszHome);
}

#ifdef ENABLE_SYSTEMD
static void systemd_watchdog_tick(boost::asio::steady_timer& timer,
                                  const italo::ServiceNode& sn) {
    using namespace std::literals;
    sd_notify(0, ("WATCHDOG=1\nSTATUS=" + sn.get_status_line()).c_str());
    timer.expires_after(10s);
    timer.async_wait([&](const boost::system::error_code&) {
        systemd_watchdog_tick(timer, sn);
    });
}
#endif

constexpr int EXIT_INVALID_PORT = 2;

int main(int argc, char* argv[]) {

    italo::command_line_parser parser;

    try {
        parser.parse_args(argc, argv);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        parser.print_usage();
        return EXIT_FAILURE;
    }

    auto options = parser.get_options();

    if (options.print_help) {
        parser.print_usage();
        return EXIT_SUCCESS;
    }

    if (options.print_version) {
        std::cout << version_info();
        return EXIT_SUCCESS;
    }

    if (options.data_dir.empty()) {
        if (auto home_dir = get_home_dir()) {
            if (options.testnet) {
                options.data_dir =
                    (*home_dir / ".italo" / "testnet" / "storage").string();
            } else {
                options.data_dir = (*home_dir / ".italo" / "storage").string();
            }
        }
    }

    if (!fs::exists(options.data_dir)) {
        fs::create_directories(options.data_dir);
    }

    italo::LogLevel log_level;
    if (!italo::parse_log_level(options.log_level, log_level)) {
        std::cerr << "Incorrect log level: " << options.log_level << std::endl;
        italo::print_log_levels();
        return EXIT_FAILURE;
    }

    italo::init_logging(options.data_dir, log_level);

    if (options.testnet) {
        italo::set_testnet();
        ITALO_LOG(warn,
                 "Starting in testnet mode, make sure this is intentional!");
    }

    // Always print version for the logs
    print_version();

    if (options.ip == "127.0.0.1") {
        ITALO_LOG(critical,
                 "Tried to bind italo-storage to localhost, please bind "
                 "to outward facing address");
        return EXIT_FAILURE;
    }

    if (options.port == options.italod_rpc_port) {
        ITALO_LOG(error, "Storage server port must be different from that of "
                        "Italod! Terminating.");
        exit(EXIT_INVALID_PORT);
    }

    ITALO_LOG(info, "Setting log level to {}", options.log_level);
    ITALO_LOG(info, "Setting database location to {}", options.data_dir);
    ITALO_LOG(info, "Setting Italod RPC to {}:{}", options.italod_rpc_ip,
             options.italod_rpc_port);
    ITALO_LOG(info, "Https server is listening at {}:{}", options.ip,
             options.port);
    ITALO_LOG(info, "ItaloMQ is listening at {}:{}", options.ip,
             options.lmq_port);

    boost::asio::io_context ioc{1};
    boost::asio::io_context worker_ioc{1};

    if (sodium_init() != 0) {
        ITALO_LOG(error, "Could not initialize libsodium");
        return EXIT_FAILURE;
    }

    if (crypto_aead_aes256gcm_is_available() == 0) {
        ITALO_LOG(error, "AES-256-GCM is not available on this CPU");
        return EXIT_FAILURE;
    }

    {
        const auto fd_limit = util::get_fd_limit();
        if (fd_limit != -1) {
            ITALO_LOG(debug, "Open file descriptor limit: {}", fd_limit);
        } else {
            ITALO_LOG(debug, "Open descriptor limit: N/A");
        }
    }

    try {

        auto italod_client = italo::ItalodClient(ioc, options.italod_rpc_ip,
                                              options.italod_rpc_port);

        // Normally we request the key from daemon, but in integrations/swarm
        // testing we are not able to do that, so we extract the key as a
        // command line option:
        italo::private_key_t private_key;
        italo::private_key_ed25519_t private_key_ed25519; // Unused at the moment
        italo::private_key_t private_key_x25519;
#ifndef INTEGRATION_TEST
        std::tie(private_key, private_key_ed25519, private_key_x25519) =
            italod_client.wait_for_privkey();
#else
        private_key = italo::italodKeyFromHex(options.italod_key);
        ITALO_LOG(info, "ITALOD LEGACY KEY: {}", options.italod_key);

        private_key_x25519 = italo::italodKeyFromHex(options.italod_x25519_key);
        ITALO_LOG(info, "x25519 SECRET KEY: {}", options.italod_x25519_key);

        private_key_ed25519 =
            italo::private_key_ed25519_t::from_hex(options.italod_ed25519_key);

        ITALO_LOG(info, "ed25519 SECRET KEY: {}", options.italod_ed25519_key);
#endif

        const auto public_key = italo::derive_pubkey_legacy(private_key);
        ITALO_LOG(info, "Retrieved keys from Italod; our SN pubkey is: {}",
                 util::as_hex(public_key));

        // TODO: avoid conversion to vector
        const std::vector<uint8_t> priv(private_key_x25519.begin(),
                                        private_key_x25519.end());
        ChannelEncryption<std::string> channel_encryption(priv);

        italo::italod_key_pair_t italod_key_pair{private_key, public_key};

        const auto public_key_x25519 =
            italo::derive_pubkey_x25519(private_key_x25519);

        ITALO_LOG(info, "SN x25519 pubkey is: {}",
                 util::as_hex(public_key_x25519));

        const auto public_key_ed25519 =
            italo::derive_pubkey_ed25519(private_key_ed25519);

        const std::string pubkey_ed25519_hex = util::as_hex(public_key_ed25519);

        ITALO_LOG(info, "SN ed25519 pubkey is: {}", pubkey_ed25519_hex);

        italo::italod_key_pair_t italod_key_pair_x25519{private_key_x25519,
                                                     public_key_x25519};

        for (const auto& key : options.stats_access_keys) {
            ITALO_LOG(info, "Stats access key: {}", key);
        }

        // We pass port early because we want to send it in the first ping to
        // Italod (in ServiceNode's constructor), but don't want to initialize
        // the rest of lmq server before we have a reference to ServiceNode
        italo::ItalomqServer italomq_server(options.lmq_port);

        // TODO: SN doesn't need italomq_server, just the lmq components
        italo::ServiceNode service_node(ioc, worker_ioc, options.port,
                                       italomq_server, italod_key_pair,
                                       pubkey_ed25519_hex, options.data_dir,
                                       italod_client, options.force_start);

        italo::RequestHandler request_handler(ioc, service_node, italod_client,
                                             channel_encryption);

        italomq_server.init(&service_node, &request_handler,
                           italod_key_pair_x25519, options.stats_access_keys);

        RateLimiter rate_limiter;

        italo::Security security(italod_key_pair, options.data_dir);

#ifdef ENABLE_SYSTEMD
        sd_notify(0, "READY=1");
        boost::asio::steady_timer systemd_watchdog_timer(ioc);
        systemd_watchdog_tick(systemd_watchdog_timer, service_node);
#endif

        italo::http_server::run(ioc, options.ip, options.port, options.data_dir,
                               service_node, request_handler, rate_limiter,
                               security);
    } catch (const std::exception& e) {
        // It seems possible for logging to throw its own exception,
        // in which case it will be propagated to libc...
        std::cerr << "Exception caught in main: " << e.what() << std::endl;
        return EXIT_FAILURE;
    } catch (...) {
        std::cerr << "Unknown exception caught in main." << std::endl;
        return EXIT_FAILURE;
    }
}
