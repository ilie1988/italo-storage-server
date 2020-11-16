#include "lmq_server.h"

#include "dev_sink.h"
#include "italo_common.h"
#include "italo_logger.h"
#include "italod_key.h"
#include "request_handler.h"
#include "service_node.h"
#include "utils.hpp"

#include <italomq/hex.h>
#include <italomq/italomq.h>

#include <optional>

namespace italo {

std::string ItalomqServer::peer_lookup(std::string_view pubkey_bin) const {

    ITALO_LOG(trace, "[LMQ] Peer Lookup");

    // TODO: don't create a new string here
    std::optional<sn_record_t> sn =
        this->service_node_->find_node_by_x25519_bin(std::string(pubkey_bin));

    if (sn) {
        return fmt::format("tcp://{}:{}", sn->ip(), sn->lmq_port());
    } else {
        ITALO_LOG(debug, "[LMQ] peer node not found {}!", pubkey_bin);
        return "";
    }
}

void ItalomqServer::handle_sn_data(italomq::Message& message) {

    ITALO_LOG(debug, "[LMQ] handle_sn_data");
    ITALO_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    ITALO_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    std::stringstream ss;

    // We are only expecting a single part message, so consider removing this
    for (auto& part : message.data) {
        ss << part;
    }

    // TODO: proces push batch should move to "Request handler"
    service_node_->process_push_batch(ss.str());

    ITALO_LOG(debug, "[LMQ] send reply");

    // TODO: Investigate if the above could fail and whether we should report
    // that to the sending SN
    message.send_reply();
};

void ItalomqServer::handle_sn_proxy_exit(italomq::Message& message) {

    ITALO_LOG(debug, "[LMQ] handle_sn_proxy_exit");
    ITALO_LOG(debug, "[LMQ]   thread id: {}", std::this_thread::get_id());
    ITALO_LOG(debug, "[LMQ]   from: {}", util::as_hex(message.conn.pubkey()));

    if (message.data.size() != 2) {
        ITALO_LOG(debug, "Expected 2 message parts, got {}",
                 message.data.size());
        return;
    }

    const auto& client_key = message.data[0];
    const auto& payload = message.data[1];

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    // TODO: accept string_view?
    request_handler_->process_proxy_exit(
        std::string(client_key), std::string(payload),
        [this, origin_pk, reply_tag](italo::Response res) {
            ITALO_LOG(debug, "    Proxy exit status: {}", res.status());

            if (res.status() == Status::OK) {
                this->italomq_->send(origin_pk, "REPLY", reply_tag,
                                    res.message());

            } else {
                // We reply with 2 messages which will be treated as
                // an error (rather than timeout)
                this->italomq_->send(origin_pk, "REPLY", reply_tag,
                                    fmt::format("{}", res.status()),
                                    res.message());
                ITALO_LOG(debug, "Error: status is not OK for proxy_exit: {}",
                         res.status());
            }
        });
}

void ItalomqServer::handle_onion_request(italomq::Message& message, bool v2) {

    ITALO_LOG(debug, "Got an onion request over ITALOMQ");

    auto& reply_tag = message.reply_tag;
    auto& origin_pk = message.conn.pubkey();

    auto on_response = [this, origin_pk,
                        reply_tag](italo::Response res) mutable {
        ITALO_LOG(trace, "on response: {}", to_string(res));

        std::string status = std::to_string(static_cast<int>(res.status()));

        italomq_->send(origin_pk, "REPLY", reply_tag, std::move(status),
                      res.message());
    };

    if (message.data.size() == 1 && message.data[0] == "ping") {
        // Before 2.0.3 we reply with a bad request, below, but reply here to
        // avoid putting the error message in the log on 2.0.3+ nodes. (the
        // reply code here doesn't actually matter; the ping test only requires
        // that we provide *some* response).
        ITALO_LOG(debug, "Remote pinged me");
        service_node_->update_last_ping(ReachType::ZMQ);
        on_response(italo::Response{Status::OK, "pong"});
        return;
    }

    if (message.data.size() != 2) {
        ITALO_LOG(error, "Expected 2 message parts, got {}",
                 message.data.size());
        on_response(italo::Response{Status::BAD_REQUEST,
                                   "Incorrect number of messages"});
        return;
    }

    const auto& eph_key = message.data[0];
    const auto& ciphertext = message.data[1];

    request_handler_->process_onion_req(std::string(ciphertext),
                                        std::string(eph_key), on_response, v2);
}

void ItalomqServer::handle_get_logs(italomq::Message& message) {

    ITALO_LOG(debug, "Received get_logs request via LMQ");

    auto dev_sink = dynamic_cast<italo::dev_sink_mt*>(
        spdlog::get("italo_logger")->sinks()[2].get());

    if (dev_sink == nullptr) {
        ITALO_LOG(critical, "Sink #3 should be dev sink");
        assert(false);
        auto err_msg = "Developer error: sink #3 is not a dev sink.";
        message.send_reply(err_msg);
    }

    nlohmann::json val;
    val["entries"] = dev_sink->peek();
    message.send_reply(val.dump(4));
}

void ItalomqServer::handle_get_stats(italomq::Message& message) {

    ITALO_LOG(debug, "Received get_stats request via LMQ");

    auto payload = service_node_->get_stats();

    message.send_reply(payload);
}

void ItalomqServer::init(ServiceNode* sn, RequestHandler* rh,
                        const italod_key_pair_t& keypair,
                        const std::vector<std::string>& stats_access_keys) {

    using italomq::Allow;

    service_node_ = sn;
    request_handler_ = rh;

    for (const auto& key : stats_access_keys) {
        this->stats_access_keys.push_back(italomq::from_hex(key));
    }

    auto pubkey = key_to_string(keypair.public_key);
    auto seckey = key_to_string(keypair.private_key);

    auto logger = [](italomq::LogLevel level, const char* file, int line,
                     std::string message) {
#define LMQ_LOG_MAP(LMQ_LVL, SS_LVL)                                           \
    case italomq::LogLevel::LMQ_LVL:                                            \
        ITALO_LOG(SS_LVL, "[{}:{}]: {}", file, line, message);                  \
        break;
        switch (level) {
            LMQ_LOG_MAP(fatal, critical);
            LMQ_LOG_MAP(error, error);
            LMQ_LOG_MAP(warn, warn);
            LMQ_LOG_MAP(info, info);
            LMQ_LOG_MAP(trace, trace);
        default:
            ITALO_LOG(debug, "[{}:{}]: {}", file, line, message);
        };
#undef LMQ_LOG_MAP
    };

    auto lookup_fn = [this](auto pk) { return this->peer_lookup(pk); };

    italomq_.reset(new ItaloMQ{pubkey, seckey, true /* is service node */,
                             lookup_fn, logger});

    ITALO_LOG(info, "ItaloMQ is listenting on port {}", port_);

    italomq_->log_level(italomq::LogLevel::info);
    // clang-format off
    italomq_->add_category("sn", italomq::Access{italomq::AuthLevel::none, true, false})
        .add_request_command("data", [this](auto& m) { this->handle_sn_data(m); })
        .add_request_command("proxy_exit", [this](auto& m) { this->handle_sn_proxy_exit(m); })
        .add_request_command("onion_req", [this](auto& m) { this->handle_onion_request(m, false); })
        .add_request_command("onion_req_v2", [this](auto& m) { this->handle_onion_request(m, true); })
        ;

    italomq_->add_category("service", italomq::AuthLevel::admin)
        .add_request_command("get_stats", [this](auto& m) { this->handle_get_stats(m); })
        .add_request_command("get_logs", [this](auto& m) { this->handle_get_logs(m); });

    // clang-format on
    italomq_->set_general_threads(1);

    italomq_->listen_curve(
        fmt::format("tcp://0.0.0.0:{}", port_),
        [this](std::string_view /*ip*/, std::string_view pk, bool /*sn*/) {
            const auto& keys = this->stats_access_keys;
            const auto it = std::find(keys.begin(), keys.end(), pk);
            return it == keys.end() ? italomq::AuthLevel::none
                                    : italomq::AuthLevel::admin;
        });

    italomq_->MAX_MSG_SIZE =
        10 * 1024 * 1024; // 10 MB (needed by the fileserver)

    italomq_->start();
}

ItalomqServer::ItalomqServer(uint16_t port) : port_(port){};
ItalomqServer::~ItalomqServer() = default;

} // namespace italo
