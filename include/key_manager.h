#pragma once

#include <string>
#include <sodium.h>
#include "database_manager.h"
#include "json.h"

using json = nlohmann::json;

class KeyManager {
public:
    KeyManager(const std::string& key_path, const std::string& server_name,
               DatabaseManager& db);

    // Return the public key as base64
    std::string public_key_b64() const { return public_key_b64_; }
    std::string key_id() const { return key_id_; }
    std::string server_name() const { return server_name_; }
    int64_t valid_until() const { return valid_until_ts_; }

    // Sign data with the server key; returns base64-encoded signature
    std::string sign(const std::string& data) const;

    // Build /_matrix/key/v2/server response JSON (unsigned)
    json server_key_json() const;

private:
    std::string key_path_;
    std::string server_name_;
    std::string key_id_;
    std::string public_key_b64_;
    int64_t valid_until_ts_ = 0;
    unsigned char public_key_[crypto_sign_PUBLICKEYBYTES];
    unsigned char secret_key_[crypto_sign_SECRETKEYBYTES];

    void load_or_generate(DatabaseManager& db);
};
