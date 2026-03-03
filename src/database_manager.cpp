#include "database_manager.h"
#include <stdexcept>
#include <iostream>

static const char* SCHEMA = R"SQL(
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-65536;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT NOT NULL,
    username TEXT NOT NULL,
    display_name TEXT DEFAULT '',
    PRIMARY KEY(device_id, username)
);

CREATE TABLE IF NOT EXISTS tokens (
    token TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    device_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT PRIMARY KEY,
    version TEXT NOT NULL DEFAULT '10',
    creator TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS room_members (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    membership TEXT NOT NULL DEFAULT 'join',
    PRIMARY KEY(room_id, user_id)
);

CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    sender TEXT NOT NULL,
    state_key TEXT DEFAULT NULL,
    content TEXT NOT NULL DEFAULT '{}',
    origin_server_ts INTEGER NOT NULL,
    depth INTEGER NOT NULL DEFAULT 0,
    auth_events TEXT DEFAULT '[]',
    prev_events TEXT DEFAULT '[]',
    signatures TEXT DEFAULT '{}',
    hashes TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS room_state (
    room_id TEXT NOT NULL,
    type TEXT NOT NULL,
    state_key TEXT NOT NULL DEFAULT '',
    event_id TEXT NOT NULL,
    PRIMARY KEY(room_id, type, state_key)
);

CREATE TABLE IF NOT EXISTS profiles (
    user_id TEXT PRIMARY KEY,
    displayname TEXT DEFAULT '',
    avatar_url TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS room_aliases (
    alias TEXT PRIMARY KEY,
    room_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS filters (
    filter_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    filter TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS media (
    media_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL DEFAULT '',
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size INTEGER NOT NULL DEFAULT 0,
    uploader TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS push_rules (
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(user_id, rule_id)
);

CREATE TABLE IF NOT EXISTS server_keys (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,
    valid_until INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS account_data (
    user_id TEXT NOT NULL,
    type TEXT NOT NULL,
    room_id TEXT NOT NULL DEFAULT '',
    content TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY(user_id, type, room_id)
);

CREATE TABLE IF NOT EXISTS read_receipts (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    ts INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(room_id, user_id)
);

CREATE TABLE IF NOT EXISTS presence (
    user_id TEXT PRIMARY KEY,
    presence TEXT NOT NULL DEFAULT 'offline',
    status_msg TEXT DEFAULT '',
    last_active INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_events_room ON events(room_id, depth);
CREATE INDEX IF NOT EXISTS idx_room_members_user ON room_members(user_id);
CREATE INDEX IF NOT EXISTS idx_tokens_username ON tokens(username);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(room_id, type);
)SQL";

DatabaseManager::DatabaseManager(const std::string& db_path) : db_(nullptr) {
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("Cannot open database: ") + sqlite3_errmsg(db_));
    }
    sqlite3_busy_timeout(db_, 5000);
    init_schema();
}

DatabaseManager::~DatabaseManager() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void DatabaseManager::init_schema() {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, SCHEMA, nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("Schema init failed: " + msg);
    }
}

void DatabaseManager::exec(const std::string& sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err);
    if (rc != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw std::runtime_error("SQL exec failed: " + msg);
    }
}

void DatabaseManager::query(const std::string& sql,
                             const std::vector<std::string>& params,
                             std::function<void(sqlite3_stmt*)> row_cb) const {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("Prepare failed: ") + sqlite3_errmsg(db_));
    }
    for (int i = 0; i < (int)params.size(); ++i) {
        sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        row_cb(stmt);
    }
    sqlite3_finalize(stmt);
}

int DatabaseManager::execute(const std::string& sql, const std::vector<std::string>& params) {
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        throw std::runtime_error(std::string("Prepare failed: ") + sqlite3_errmsg(db_));
    }
    for (int i = 0; i < (int)params.size(); ++i) {
        sqlite3_bind_text(stmt, i + 1, params[i].c_str(), -1, SQLITE_TRANSIENT);
    }
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        throw std::runtime_error(std::string("Execute failed: ") + sqlite3_errmsg(db_));
    }
    return sqlite3_changes(db_);
}

std::string DatabaseManager::get_text(const std::string& sql,
                                       const std::vector<std::string>& params) const {
    std::string result;
    query(sql, params, [&](sqlite3_stmt* stmt) {
        const unsigned char* text = sqlite3_column_text(stmt, 0);
        if (text) result = reinterpret_cast<const char*>(text);
    });
    return result;
}

int64_t DatabaseManager::get_int(const std::string& sql,
                                  const std::vector<std::string>& params,
                                  int64_t def) const {
    int64_t result = def;
    bool found = false;
    query(sql, params, [&](sqlite3_stmt* stmt) {
        if (!found) {
            result = sqlite3_column_int64(stmt, 0);
            found = true;
        }
    });
    return result;
}
