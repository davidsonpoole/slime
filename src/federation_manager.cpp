#include "federation_manager.h"
#include "matrix_crypto.h"
#include <chrono>
#include <sstream>
#include <iostream>

FederationManager::FederationManager(DatabaseManager& db, KeyManager& key_manager)
    : db_(db), key_manager_(key_manager) {}

std::string FederationManager::resolve_server(const std::string& server_name) const {
    // Simple resolution: server_name as-is (port 8448)
    // In production, do DNS SRV lookup
    return server_name;
}

std::string FederationManager::get_remote_key(const std::string& server_name,
                                               const std::string& key_id) {
    // Check cache
    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = key_cache_.find(server_name + ":" + key_id);
        if (it != key_cache_.end()) {
            int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            if (it->second.second > now) return it->second.first;
        }
    }

    // Try DB cache
    std::string cached = db_.get_text(
        "SELECT public_key FROM server_keys WHERE key_id=?",
        {server_name + ":" + key_id});
    if (!cached.empty()) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        key_cache_[server_name + ":" + key_id] = {cached,
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count()
            + 24LL * 60 * 60 * 1000};
        return cached;
    }

    // Fetch from remote
    try {
        httplib::Client cli(server_name, 8448);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(10, 0);
        auto res = cli.Get("/_matrix/key/v2/server");
        if (res && res->status == 200) {
            json body = json::parse(res->body);
            if (body.contains("verify_keys") && body["verify_keys"].contains(key_id)) {
                std::string pubkey = body["verify_keys"][key_id]["key"].get<std::string>();
                int64_t valid_until = body.value("valid_until_ts",
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()).count()
                    + 24LL * 60 * 60 * 1000);

                // Cache in DB
                try {
                    db_.execute(
                        "INSERT OR REPLACE INTO server_keys(key_id, public_key, private_key, valid_until) "
                        "VALUES(?,?,'',?)",
                        {server_name + ":" + key_id, pubkey, std::to_string(valid_until)});
                } catch (...) {}

                std::lock_guard<std::mutex> lock(cache_mutex_);
                key_cache_[server_name + ":" + key_id] = {pubkey, valid_until};
                return pubkey;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Failed to fetch key from " << server_name << ": " << e.what() << std::endl;
    }
    return "";
}

std::string FederationManager::make_auth_header(const std::string& method,
                                                 const std::string& uri,
                                                 const std::string& destination,
                                                 const json& content) const {
    json auth_obj = {
        {"method", method},
        {"uri", uri},
        {"origin", key_manager_.server_name()},
        {"destination", destination}
    };
    if (!content.is_null() && !content.empty()) {
        auth_obj["content"] = content;
    }
    std::string canonical = MatrixCrypto::canonical_json(auth_obj);
    std::string sig = key_manager_.sign(canonical);

    return "X-Matrix origin=" + key_manager_.server_name()
        + ",key=\"" + key_manager_.key_id()
        + "\",sig=\"" + sig + "\"";
}

bool FederationManager::send_transaction(const std::string& destination,
                                          const std::vector<json>& pdus,
                                          const std::vector<json>& edus) {
    ++txn_counter_;
    std::string txn_id = std::to_string(txn_counter_);

    json body = {
        {"origin", key_manager_.server_name()},
        {"origin_server_ts", std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()},
        {"pdus", pdus},
        {"edus", edus}
    };

    std::string uri = "/_matrix/federation/v1/send/" + txn_id;
    std::string auth = make_auth_header("PUT", uri, destination, body);

    try {
        httplib::Client cli(resolve_server(destination), 8448);
        cli.set_connection_timeout(5, 0);
        cli.set_read_timeout(30, 0);

        httplib::Headers headers = {{"Authorization", auth}};
        auto res = cli.Put(uri, headers, body.dump(), "application/json");
        if (res && (res->status == 200 || res->status == 202)) {
            return true;
        }
        std::cerr << "Federation send failed to " << destination
                  << ": " << (res ? res->status : 0) << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Federation send error: " << e.what() << std::endl;
    }
    return false;
}

bool FederationManager::verify_auth_header(const std::string& auth_header,
                                            const std::string& method,
                                            const std::string& uri,
                                            const json& content) {
    // Parse "X-Matrix origin=...,key="...",sig="..."
    if (auth_header.find("X-Matrix") == std::string::npos) return false;

    std::string origin, key_id, sig;
    std::istringstream ss(auth_header.substr(auth_header.find("X-Matrix") + 9));
    std::string token;
    while (std::getline(ss, token, ',')) {
        // trim whitespace
        while (!token.empty() && (token.front() == ' ' || token.front() == '\t'))
            token.erase(token.begin());
        if (token.find("origin=") == 0) origin = token.substr(7);
        else if (token.find("key=\"") == 0)
            key_id = token.substr(5, token.size() - 6);
        else if (token.find("sig=\"") == 0)
            sig = token.substr(5, token.size() - 6);
    }

    if (origin.empty() || key_id.empty() || sig.empty()) return false;

    std::string pubkey_b64 = get_remote_key(origin, key_id);
    if (pubkey_b64.empty()) return false;

    // Reconstruct signed object
    json auth_obj = {
        {"method", method},
        {"uri", uri},
        {"origin", origin},
        {"destination", key_manager_.server_name()}
    };
    if (!content.is_null() && !content.empty()) {
        auth_obj["content"] = content;
    }
    std::string canonical = MatrixCrypto::canonical_json(auth_obj);
    std::string pubkey_raw = MatrixCrypto::base64_decode(pubkey_b64);
    std::string sig_raw = MatrixCrypto::base64_decode(sig);

    if (pubkey_raw.size() != crypto_sign_PUBLICKEYBYTES) return false;
    if (sig_raw.size() != crypto_sign_BYTES) return false;

    return crypto_sign_verify_detached(
        reinterpret_cast<const unsigned char*>(sig_raw.data()),
        reinterpret_cast<const unsigned char*>(canonical.data()), canonical.size(),
        reinterpret_cast<const unsigned char*>(pubkey_raw.data())) == 0;
}
