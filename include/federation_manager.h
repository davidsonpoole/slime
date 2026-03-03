#pragma once

#include <string>
#include <map>
#include <mutex>
#include "json.h"
#include "database_manager.h"
#include "key_manager.h"
#include "httplib.h"

using json = nlohmann::json;

class FederationManager {
public:
    FederationManager(DatabaseManager& db, KeyManager& key_manager);

    // Send a transaction of events to a remote server
    bool send_transaction(const std::string& destination,
                          const std::vector<json>& pdus,
                          const std::vector<json>& edus = {});

    // Fetch and cache remote server's verify key
    // Returns base64 public key or empty string on failure
    std::string get_remote_key(const std::string& server_name,
                                const std::string& key_id);

    // Build Authorization header value for outbound requests
    std::string make_auth_header(const std::string& method,
                                  const std::string& uri,
                                  const std::string& destination,
                                  const json& content = json()) const;

    // Verify an incoming request's Authorization header
    bool verify_auth_header(const std::string& auth_header,
                             const std::string& method,
                             const std::string& uri,
                             const json& content = json());

private:
    DatabaseManager& db_;
    KeyManager& key_manager_;
    mutable std::mutex cache_mutex_;
    std::map<std::string, std::pair<std::string,int64_t>> key_cache_; // server -> (pubkey, valid_until)

    std::string resolve_server(const std::string& server_name) const;
    int64_t txn_counter_ = 0;
};
