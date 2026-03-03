#pragma once

#include <unordered_map>
#include <string>
#include <shared_mutex>
#include "types.h"
#include "database_manager.h"

class UserManager {
public:
    UserManager(const std::string& domain, DatabaseManager& db);

    bool create_user(const std::string& username, const std::string& password);
    bool verify_credentials(const std::string& username, const std::string& password);
    bool user_exists(const std::string& username) const;
    std::string get_user_id(const std::string& username) const;
    std::string create_session(const std::string& username, const std::string& device_id);
    bool validate_token(const std::string& access_token) const;
    TokenInfo get_token_info(const std::string& access_token) const;
    bool revoke_token(const std::string& access_token);
    void revoke_all_tokens(const std::string& username);

    // Profile
    Profile get_profile(const std::string& user_id) const;
    void set_displayname(const std::string& user_id, const std::string& name);
    void set_avatar_url(const std::string& user_id, const std::string& url);

    // Devices
    std::vector<Device> get_devices(const std::string& username) const;
    Device get_device(const std::string& username, const std::string& device_id) const;
    void update_device(const std::string& username, const std::string& device_id,
                       const std::string& display_name);
    void delete_device(const std::string& username, const std::string& device_id);

    // User directory search
    std::vector<json> search_users(const std::string& term, int limit = 10) const;

    // Presence
    void set_presence(const std::string& user_id, const std::string& presence,
                      const std::string& status_msg = "");
    json get_presence(const std::string& user_id) const;

    // Account data
    void set_account_data(const std::string& user_id, const std::string& type,
                          const json& content, const std::string& room_id = "");
    json get_account_data(const std::string& user_id, const std::string& type,
                          const std::string& room_id = "") const;
    std::vector<json> get_all_account_data(const std::string& user_id,
                                            const std::string& room_id = "") const;

    const std::string& domain() const { return homeserver_domain_; }

private:
    DatabaseManager& db_;
    const std::string homeserver_domain_;
    mutable std::shared_mutex mutex_;

    // LRU token cache (max 10k entries)
    mutable std::unordered_map<std::string, TokenInfo> token_cache_;
    mutable std::shared_mutex cache_mutex_;

    std::string hash_password(const std::string& password) const;
    bool verify_password(const std::string& password, const std::string& hash) const;
};
