#include "user_manager.h"
#include "utils.h"
#include <sodium.h>
#include <chrono>
#include <algorithm>
#include <stdexcept>
#include <iostream>

UserManager::UserManager(const std::string& domain, DatabaseManager& db)
    : db_(db), homeserver_domain_(domain) {}

std::string UserManager::hash_password(const std::string& password) const {
    char hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hash, password.c_str(), password.size(),
                          crypto_pwhash_OPSLIMIT_INTERACTIVE,
                          crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        throw std::runtime_error("Password hashing failed (out of memory?)");
    }
    return std::string(hash);
}

bool UserManager::verify_password(const std::string& password,
                                   const std::string& hash) const {
    // Support legacy plaintext passwords (migration path)
    if (hash.substr(0, 7) != "$argon2") {
        return password == hash;
    }
    return crypto_pwhash_str_verify(hash.c_str(), password.c_str(),
                                     password.size()) == 0;
}

bool UserManager::create_user(const std::string& username, const std::string& password) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (user_exists(username)) return false;

    std::string user_id = "@" + username + ":" + homeserver_domain_;
    std::string hash = hash_password(password);
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    db_.execute("INSERT INTO users(username, user_id, password_hash, created_at) VALUES(?,?,?,?)",
                {username, user_id, hash, std::to_string(ts)});
    db_.execute("INSERT OR IGNORE INTO profiles(user_id, displayname, avatar_url) VALUES(?,?,?)",
                {user_id, username, ""});
    return true;
}

bool UserManager::verify_credentials(const std::string& username,
                                      const std::string& password) {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string hash = db_.get_text(
        "SELECT password_hash FROM users WHERE username=?", {username});
    if (hash.empty()) return false;
    return verify_password(password, hash);
}

bool UserManager::user_exists(const std::string& username) const {
    // Called with lock already held or internally
    std::string found = db_.get_text(
        "SELECT username FROM users WHERE username=?", {username});
    return !found.empty();
}

std::string UserManager::get_user_id(const std::string& username) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    return db_.get_text("SELECT user_id FROM users WHERE username=?", {username});
}

std::string UserManager::create_session(const std::string& username,
                                         const std::string& device_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::string token = Utils::generate_token();
    db_.execute("INSERT OR REPLACE INTO tokens(token, username, device_id) VALUES(?,?,?)",
                {token, username, device_id});
    db_.execute("INSERT OR IGNORE INTO devices(device_id, username, display_name) VALUES(?,?,?)",
                {device_id, username, ""});

    // Update cache
    {
        std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
        if (token_cache_.size() >= 10000) token_cache_.clear();
        token_cache_[token] = {username, device_id};
    }
    return token;
}

bool UserManager::validate_token(const std::string& access_token) const {
    // Check cache first
    {
        std::shared_lock<std::shared_mutex> cache_lock(cache_mutex_);
        if (token_cache_.count(access_token)) return true;
    }
    std::string found = db_.get_text(
        "SELECT token FROM tokens WHERE token=?", {access_token});
    if (!found.empty()) {
        // Populate cache
        std::string username = db_.get_text(
            "SELECT username FROM tokens WHERE token=?", {access_token});
        std::string device_id = db_.get_text(
            "SELECT device_id FROM tokens WHERE token=?", {access_token});
        std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
        if (token_cache_.size() >= 10000) token_cache_.clear();
        token_cache_[access_token] = {username, device_id};
        return true;
    }
    return false;
}

TokenInfo UserManager::get_token_info(const std::string& access_token) const {
    // Check cache first
    {
        std::shared_lock<std::shared_mutex> cache_lock(cache_mutex_);
        auto it = token_cache_.find(access_token);
        if (it != token_cache_.end()) return it->second;
    }
    TokenInfo info;
    db_.query("SELECT username, device_id FROM tokens WHERE token=?",
              {access_token},
              [&](sqlite3_stmt* stmt) {
                  const char* u = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                  const char* d = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                  if (u) info.username = u;
                  if (d) info.device_id = d;
              });
    if (!info.username.empty()) {
        std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
        if (token_cache_.size() >= 10000) token_cache_.clear();
        token_cache_[access_token] = info;
    }
    return info;
}

bool UserManager::revoke_token(const std::string& access_token) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    int changed = db_.execute("DELETE FROM tokens WHERE token=?", {access_token});
    {
        std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
        token_cache_.erase(access_token);
    }
    return changed > 0;
}

void UserManager::revoke_all_tokens(const std::string& username) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    // Collect tokens to remove from cache
    std::vector<std::string> tokens;
    db_.query("SELECT token FROM tokens WHERE username=?", {username},
              [&](sqlite3_stmt* stmt) {
                  const char* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                  if (t) tokens.push_back(t);
              });
    db_.execute("DELETE FROM tokens WHERE username=?", {username});
    {
        std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
        for (const auto& tok : tokens) token_cache_.erase(tok);
    }
}

Profile UserManager::get_profile(const std::string& user_id) const {
    Profile p;
    p.user_id = user_id;
    db_.query("SELECT displayname, avatar_url FROM profiles WHERE user_id=?",
              {user_id},
              [&](sqlite3_stmt* stmt) {
                  const char* dn = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                  const char* av = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                  if (dn) p.displayname = dn;
                  if (av) p.avatar_url = av;
              });
    return p;
}

void UserManager::set_displayname(const std::string& user_id,
                                   const std::string& name) {
    db_.execute("INSERT OR REPLACE INTO profiles(user_id, displayname, avatar_url) "
                "VALUES(?, ?, COALESCE((SELECT avatar_url FROM profiles WHERE user_id=?), ''))",
                {user_id, name, user_id});
}

void UserManager::set_avatar_url(const std::string& user_id,
                                  const std::string& url) {
    db_.execute("INSERT OR REPLACE INTO profiles(user_id, displayname, avatar_url) "
                "VALUES(?, COALESCE((SELECT displayname FROM profiles WHERE user_id=?), ''), ?)",
                {user_id, user_id, url});
}

std::vector<Device> UserManager::get_devices(const std::string& username) const {
    std::vector<Device> devices;
    db_.query("SELECT device_id, username, display_name FROM devices WHERE username=?",
              {username},
              [&](sqlite3_stmt* stmt) {
                  Device d;
                  const char* did = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                  const char* u = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                  const char* dn = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                  if (did) d.device_id = did;
                  if (u) d.username = u;
                  if (dn) d.display_name = dn;
                  devices.push_back(d);
              });
    return devices;
}

Device UserManager::get_device(const std::string& username,
                                const std::string& device_id) const {
    Device d;
    d.username = username;
    d.device_id = device_id;
    db_.query("SELECT display_name FROM devices WHERE username=? AND device_id=?",
              {username, device_id},
              [&](sqlite3_stmt* stmt) {
                  const char* dn = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
                  if (dn) d.display_name = dn;
              });
    return d;
}

void UserManager::update_device(const std::string& username,
                                 const std::string& device_id,
                                 const std::string& display_name) {
    db_.execute("UPDATE devices SET display_name=? WHERE username=? AND device_id=?",
                {display_name, username, device_id});
}

void UserManager::delete_device(const std::string& username,
                                 const std::string& device_id) {
    db_.execute("DELETE FROM tokens WHERE username=? AND device_id=?",
                {username, device_id});
    db_.execute("DELETE FROM devices WHERE username=? AND device_id=?",
                {username, device_id});
    // Invalidate cache entries for this device
    std::unique_lock<std::shared_mutex> cache_lock(cache_mutex_);
    for (auto it = token_cache_.begin(); it != token_cache_.end(); ) {
        if (it->second.username == username && it->second.device_id == device_id) {
            it = token_cache_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<json> UserManager::search_users(const std::string& term, int limit) const {
    std::vector<json> results;
    std::string pattern = "%" + term + "%";
    db_.query(
        "SELECT u.user_id, p.displayname FROM users u "
        "LEFT JOIN profiles p ON p.user_id = u.user_id "
        "WHERE u.username LIKE ? OR p.displayname LIKE ? LIMIT ?",
        {pattern, pattern, std::to_string(limit)},
        [&](sqlite3_stmt* stmt) {
            const char* uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* dn  = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            json entry = {
                {"user_id", uid ? uid : ""},
                {"display_name", dn ? dn : ""}
            };
            results.push_back(entry);
        });
    return results;
}

void UserManager::set_presence(const std::string& user_id,
                                const std::string& presence,
                                const std::string& status_msg) {
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    db_.execute(
        "INSERT OR REPLACE INTO presence(user_id, presence, status_msg, last_active) "
        "VALUES(?,?,?,?)",
        {user_id, presence, status_msg, std::to_string(ts)});
}

json UserManager::get_presence(const std::string& user_id) const {
    json result = {
        {"presence", "offline"},
        {"last_active_ago", 0},
        {"currently_active", false}
    };
    db_.query(
        "SELECT presence, status_msg, last_active FROM presence WHERE user_id=?",
        {user_id},
        [&](sqlite3_stmt* stmt) {
            const char* p = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* s = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            int64_t la = sqlite3_column_int64(stmt, 2);
            if (p) result["presence"] = p;
            if (s && s[0]) result["status_msg"] = s;
            int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            result["last_active_ago"] = now - la;
        });
    return result;
}

void UserManager::set_account_data(const std::string& user_id,
                                    const std::string& type,
                                    const json& content,
                                    const std::string& room_id) {
    db_.execute(
        "INSERT OR REPLACE INTO account_data(user_id, type, room_id, content) VALUES(?,?,?,?)",
        {user_id, type, room_id, content.dump()});
}

json UserManager::get_account_data(const std::string& user_id,
                                    const std::string& type,
                                    const std::string& room_id) const {
    std::string raw = db_.get_text(
        "SELECT content FROM account_data WHERE user_id=? AND type=? AND room_id=?",
        {user_id, type, room_id});
    if (raw.empty()) return json::object();
    try { return json::parse(raw); } catch (...) { return json::object(); }
}

std::vector<json> UserManager::get_all_account_data(const std::string& user_id,
                                                      const std::string& room_id) const {
    std::vector<json> result;
    db_.query(
        "SELECT type, content FROM account_data WHERE user_id=? AND room_id=?",
        {user_id, room_id},
        [&](sqlite3_stmt* stmt) {
            const char* type = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            const char* content = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            try {
                result.push_back({
                    {"type", type ? type : ""},
                    {"content", content ? json::parse(content) : json::object()}
                });
            } catch (...) {}
        });
    return result;
}
