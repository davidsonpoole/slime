#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <ctime>
#include "json.h"

using json = nlohmann::json;

struct User {
    std::string user_id;
    std::string username;
    std::string password_hash;
    std::vector<std::string> access_tokens;
    std::vector<std::string> device_ids;
    time_t created_at;
};

struct TokenInfo {
    std::string username;
    std::string device_id;
};

struct AuthSession {
    std::string session_id;
    std::vector<std::string> completed_stages;
    std::string username;
    std::string password;
    time_t created_at;
};

struct Device {
    std::string device_id;
    std::string username;
    std::string display_name;
};

struct Profile {
    std::string user_id;
    std::string displayname;
    std::string avatar_url;
};

struct Event {
    std::string event_id;
    std::string type;
    std::string sender;
    std::string room_id;
    int64_t origin_server_ts;
    json content;
    std::string state_key;
    std::string txn_id;
    int64_t depth = 0;
};

struct Room {
    std::string room_id;
    std::string room_version;
    std::string creator;
    std::unordered_set<std::string> members;
    std::vector<Event> timeline;
    std::map<std::string, json> state;  // "type|state_key" -> content
    time_t created_at;
};

struct SyncState {
    std::string next_batch;
    int64_t position;
};

struct ReadReceipt {
    std::string room_id;
    std::string user_id;
    std::string event_id;
    int64_t ts;
};
