#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace italomq {
class ItaloMQ;
struct Allow;
class Message;
} // namespace italomq

using italomq::ItaloMQ;

namespace italo {

struct italod_key_pair_t;
class ServiceNode;
class RequestHandler;

class ItalomqServer {

    std::unique_ptr<ItaloMQ> italomq_;

    // Has information about current SNs
    ServiceNode* service_node_;

    RequestHandler* request_handler_;

    // Get nodes' address
    std::string peer_lookup(std::string_view pubkey_bin) const;

    // Handle Session data coming from peer SN
    void handle_sn_data(italomq::Message& message);

    // Handle Session client requests arrived via proxy
    void handle_sn_proxy_exit(italomq::Message& message);

    // v2 indicates whether to use the new (v2) protocol
    void handle_onion_request(italomq::Message& message, bool v2);

    void handle_get_logs(italomq::Message& message);

    void handle_get_stats(italomq::Message& message);

    uint16_t port_ = 0;

    // Access keys for the 'service' category as binary
    std::vector<std::string> stats_access_keys;

  public:
    ItalomqServer(uint16_t port);
    ~ItalomqServer();

    // Initialize italomq
    void init(ServiceNode* sn, RequestHandler* rh,
              const italod_key_pair_t& keypair,
              const std::vector<std::string>& stats_access_key);

    uint16_t port() { return port_; }

    /// True if ItaloMQ instance has been set
    explicit operator bool() const { return (bool)italomq_; }
    /// Dereferencing via * or -> accesses the contained ItaloMQ instance.
    ItaloMQ& operator*() const { return *italomq_; }
    ItaloMQ* operator->() const { return italomq_.get(); }
};

} // namespace italo
