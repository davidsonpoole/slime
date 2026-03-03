#include "key_manager.h"
#include "matrix_crypto.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <chrono>
#include <iostream>

KeyManager::KeyManager(const std::string& key_path, const std::string& server_name,
                        DatabaseManager& db)
    : key_path_(key_path), server_name_(server_name), key_id_("ed25519:a") {
    load_or_generate(db);
}

void KeyManager::load_or_generate(DatabaseManager& db) {
    // Try loading from file first
    std::ifstream f(key_path_);
    if (f.is_open()) {
        // Format: "ed25519 <key_id> <base64_secret_key>"
        std::string type, kid, b64key;
        f >> type >> kid >> b64key;
        if (type == "ed25519" && !b64key.empty()) {
            key_id_ = "ed25519:" + kid;
            std::string raw = MatrixCrypto::base64_decode(b64key);
            if (raw.size() == crypto_sign_SECRETKEYBYTES) {
                memcpy(secret_key_, raw.data(), crypto_sign_SECRETKEYBYTES);
                // Derive public key from secret key
                crypto_sign_ed25519_sk_to_pk(public_key_, secret_key_);
                public_key_b64_ = MatrixCrypto::base64_encode(
                    std::string(reinterpret_cast<char*>(public_key_), crypto_sign_PUBLICKEYBYTES));
                valid_until_ts_ = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch()).count()
                    + 7LL * 24 * 60 * 60 * 1000;
                std::cout << "Loaded signing key: " << key_id_ << std::endl;
                return;
            }
        }
    }

    // Generate new keypair
    crypto_sign_keypair(public_key_, secret_key_);
    public_key_b64_ = MatrixCrypto::base64_encode(
        std::string(reinterpret_cast<char*>(public_key_), crypto_sign_PUBLICKEYBYTES));
    std::string secret_b64 = MatrixCrypto::base64_encode(
        std::string(reinterpret_cast<char*>(secret_key_), crypto_sign_SECRETKEYBYTES));

    valid_until_ts_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count()
        + 7LL * 24 * 60 * 60 * 1000;

    // Save to file
    std::ofstream out(key_path_);
    if (out.is_open()) {
        out << "ed25519 a " << secret_b64 << "\n";
        std::cout << "Generated new signing key: " << key_id_ << std::endl;
    } else {
        std::cerr << "Warning: could not save signing key to " << key_path_ << std::endl;
    }

    // Also persist in DB
    try {
        db.execute(
            "INSERT OR REPLACE INTO server_keys(key_id, public_key, private_key, valid_until) "
            "VALUES(?,?,?,?)",
            {key_id_, public_key_b64_, secret_b64, std::to_string(valid_until_ts_)});
    } catch (...) {}
}

std::string KeyManager::sign(const std::string& data) const {
    unsigned char sig[crypto_sign_BYTES];
    unsigned long long sig_len;
    crypto_sign_detached(sig, &sig_len,
        reinterpret_cast<const unsigned char*>(data.data()), data.size(),
        secret_key_);
    return MatrixCrypto::base64_encode(
        std::string(reinterpret_cast<char*>(sig), sig_len));
}

json KeyManager::server_key_json() const {
    json j = {
        {"server_name", server_name_},
        {"valid_until_ts", valid_until_ts_},
        {"verify_keys", {
            {key_id_, {{"key", public_key_b64_}}}
        }},
        {"old_verify_keys", json::object()}
    };
    // Add self-signature
    std::string canonical = MatrixCrypto::canonical_json(j);
    std::string sig = sign(canonical);
    j["signatures"] = {{server_name_, {{key_id_, sig}}}};
    return j;
}
