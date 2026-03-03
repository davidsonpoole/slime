#include "room_manager.h"
#include "utils.h"
#include "matrix_crypto.h"
#include <algorithm>
#include <chrono>
#include <sstream>
#include <iostream>

RoomManager::RoomManager(const std::string& domain, DatabaseManager& db)
    : db_(db), homeserver_domain_(domain), sync_position_(0) {
    // Restore sync_position from highest event depth
    int64_t max_depth = db_.get_int("SELECT COALESCE(MAX(depth),0) FROM events", {});
    sync_position_ = max_depth;
}

int64_t RoomManager::next_depth(const std::string& room_id) const {
    int64_t d = db_.get_int(
        "SELECT COALESCE(MAX(depth),0) FROM events WHERE room_id=?", {room_id});
    return d + 1;
}

std::string RoomManager::create_room(const std::string& creator_user_id,
                                      const json& options) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    std::string room_id = Utils::generate_room_id(homeserver_domain_);
    std::string room_version = options.value("room_version", "10");
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();

    db_.execute("INSERT INTO rooms(room_id, version, creator, created_at) VALUES(?,?,?,?)",
                {room_id, room_version, creator_user_id, std::to_string(ts)});

    // Creator auto-joins
    db_.execute("INSERT OR REPLACE INTO room_members(room_id, user_id, membership) VALUES(?,?,?)",
                {room_id, creator_user_id, "join"});

    // Inject initial state events (lock already held, call internal helpers directly)
    inject_state_events(room_id, creator_user_id, options);

    ++sync_position_;
    return room_id;
}

void RoomManager::inject_state_events(const std::string& room_id,
                                       const std::string& creator_user_id,
                                       const json& options) {
    // m.room.create
    add_event(room_id, "m.room.create", creator_user_id,
              {{"creator", creator_user_id}, {"room_version", options.value("room_version", "10")}},
              "");

    // m.room.member (creator join)
    add_event(room_id, "m.room.member", creator_user_id,
              {{"membership", "join"}, {"displayname", ""}},
              creator_user_id);

    // m.room.power_levels
    json power_levels = {
        {"ban", 50}, {"events_default", 0}, {"invite", 0}, {"kick", 50},
        {"redact", 50}, {"state_default", 50}, {"users_default", 0},
        {"users", {{creator_user_id, 100}}},
        {"events", {{"m.room.name", 50}, {"m.room.power_levels", 100},
                    {"m.room.history_visibility", 100}, {"m.room.canonical_alias", 50},
                    {"m.room.avatar", 50}}}
    };
    add_event(room_id, "m.room.power_levels", creator_user_id, power_levels, "");

    // m.room.join_rules
    std::string preset = options.value("preset", "private_chat");
    std::string join_rule = (preset == "public_chat") ? "public" : "invite";
    add_event(room_id, "m.room.join_rules", creator_user_id,
              {{"join_rule", join_rule}}, "");

    // m.room.history_visibility
    std::string hist_vis = (preset == "public_chat") ? "shared" : "invited";
    add_event(room_id, "m.room.history_visibility", creator_user_id,
              {{"history_visibility", hist_vis}}, "");

    // m.room.guest_access
    std::string guest_access = (preset == "public_chat") ? "can_join" : "forbidden";
    add_event(room_id, "m.room.guest_access", creator_user_id,
              {{"guest_access", guest_access}}, "");

    // Apply user-provided initial_state
    if (options.contains("initial_state") && options["initial_state"].is_array()) {
        for (const auto& state_ev : options["initial_state"]) {
            std::string type = state_ev.value("type", "");
            std::string sk = state_ev.value("state_key", "");
            json content = state_ev.value("content", json::object());
            if (!type.empty()) {
                add_event(room_id, type, creator_user_id, content, sk);
            }
        }
    }

    // m.room.name
    if (options.contains("name") && !options["name"].get<std::string>().empty()) {
        add_event(room_id, "m.room.name", creator_user_id,
                  {{"name", options["name"].get<std::string>()}}, "");
    }

    // m.room.topic
    if (options.contains("topic") && !options["topic"].get<std::string>().empty()) {
        add_event(room_id, "m.room.topic", creator_user_id,
                  {{"topic", options["topic"].get<std::string>()}}, "");
    }
}

bool RoomManager::room_exists(const std::string& room_id) const {
    std::string found = db_.get_text("SELECT room_id FROM rooms WHERE room_id=?", {room_id});
    return !found.empty();
}

bool RoomManager::add_member(const std::string& room_id, const std::string& user_id,
                              const std::string& membership) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    if (!room_exists(room_id)) return false;
    db_.execute(
        "INSERT OR REPLACE INTO room_members(room_id, user_id, membership) VALUES(?,?,?)",
        {room_id, user_id, membership});
    return true;
}

bool RoomManager::remove_member(const std::string& room_id, const std::string& user_id) {
    std::unique_lock<std::shared_mutex> lock(mutex_);
    db_.execute(
        "UPDATE room_members SET membership='leave' WHERE room_id=? AND user_id=?",
        {room_id, user_id});
    return true;
}

bool RoomManager::is_member(const std::string& room_id, const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string m = db_.get_text(
        "SELECT membership FROM room_members WHERE room_id=? AND user_id=?",
        {room_id, user_id});
    return m == "join";
}

std::string RoomManager::get_membership(const std::string& room_id,
                                         const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string m = db_.get_text(
        "SELECT membership FROM room_members WHERE room_id=? AND user_id=?",
        {room_id, user_id});
    return m.empty() ? "leave" : m;
}

std::vector<std::string> RoomManager::get_members(const std::string& room_id,
                                                    const std::string& membership) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> result;
    db_.query(
        "SELECT user_id FROM room_members WHERE room_id=? AND membership=?",
        {room_id, membership},
        [&](sqlite3_stmt* stmt) {
            const char* uid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (uid) result.push_back(uid);
        });
    return result;
}

std::string RoomManager::add_event(const std::string& room_id,
                                    const std::string& event_type,
                                    const std::string& sender,
                                    const json& content,
                                    const std::string& state_key) {
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    int64_t depth = next_depth(room_id);

    // Build event for ID computation
    json event_for_hash = {
        {"room_id", room_id},
        {"type", event_type},
        {"sender", sender},
        {"content", content},
        {"origin_server_ts", ts},
        {"depth", depth}
    };
    if (!state_key.empty() || event_type == "m.room.create"
        || event_type == "m.room.member"
        || event_type == "m.room.power_levels"
        || event_type == "m.room.join_rules"
        || event_type == "m.room.history_visibility"
        || event_type == "m.room.guest_access"
        || event_type == "m.room.name"
        || event_type == "m.room.topic"
        || event_type == "m.room.canonical_alias"
        || event_type == "m.room.avatar") {
        event_for_hash["state_key"] = state_key;
    }

    std::string event_id = "$" + MatrixCrypto::reference_hash(event_for_hash);

    db_.execute(
        "INSERT OR IGNORE INTO events(event_id, room_id, type, sender, state_key, "
        "content, origin_server_ts, depth) VALUES(?,?,?,?,?,?,?,?)",
        {event_id, room_id, event_type, sender, state_key,
         content.dump(), std::to_string(ts), std::to_string(depth)});

    // Update room state for state events
    bool is_state = !state_key.empty()
        || event_type == "m.room.create"
        || event_type == "m.room.power_levels"
        || event_type == "m.room.join_rules"
        || event_type == "m.room.history_visibility"
        || event_type == "m.room.guest_access"
        || event_type == "m.room.name"
        || event_type == "m.room.topic"
        || event_type == "m.room.canonical_alias"
        || event_type == "m.room.avatar"
        || event_type == "m.room.member";

    if (is_state) {
        db_.execute(
            "INSERT OR REPLACE INTO room_state(room_id, type, state_key, event_id) VALUES(?,?,?,?)",
            {room_id, event_type, state_key, event_id});
    }

    ++sync_position_;
    return event_id;
}

Event RoomManager::get_event(const std::string& event_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    Event e;
    db_.query(
        "SELECT event_id, room_id, type, sender, state_key, content, "
        "origin_server_ts, depth FROM events WHERE event_id=?",
        {event_id},
        [&](sqlite3_stmt* stmt) {
            auto col = [&](int i) -> std::string {
                const char* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                return t ? t : "";
            };
            e.event_id = col(0);
            e.room_id = col(1);
            e.type = col(2);
            e.sender = col(3);
            e.state_key = col(4);
            try { e.content = json::parse(col(5)); } catch (...) { e.content = json::object(); }
            e.origin_server_ts = sqlite3_column_int64(stmt, 6);
            e.depth = sqlite3_column_int64(stmt, 7);
        });
    return e;
}

std::vector<Event> RoomManager::get_timeline(const std::string& room_id,
                                              int64_t since_depth,
                                              int limit) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<Event> events;
    db_.query(
        "SELECT event_id, room_id, type, sender, state_key, content, "
        "origin_server_ts, depth FROM events "
        "WHERE room_id=? AND depth>? ORDER BY depth ASC LIMIT ?",
        {room_id, std::to_string(since_depth), std::to_string(limit)},
        [&](sqlite3_stmt* stmt) {
            Event e;
            auto col = [&](int i) -> std::string {
                const char* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                return t ? t : "";
            };
            e.event_id = col(0);
            e.room_id = col(1);
            e.type = col(2);
            e.sender = col(3);
            e.state_key = col(4);
            try { e.content = json::parse(col(5)); } catch (...) { e.content = json::object(); }
            e.origin_server_ts = sqlite3_column_int64(stmt, 6);
            e.depth = sqlite3_column_int64(stmt, 7);
            events.push_back(e);
        });
    return events;
}

std::vector<Event> RoomManager::get_room_state(const std::string& room_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<Event> events;
    db_.query(
        "SELECT e.event_id, e.room_id, e.type, e.sender, e.state_key, "
        "e.content, e.origin_server_ts, e.depth "
        "FROM room_state rs JOIN events e ON rs.event_id=e.event_id "
        "WHERE rs.room_id=?",
        {room_id},
        [&](sqlite3_stmt* stmt) {
            Event e;
            auto col = [&](int i) -> std::string {
                const char* t = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                return t ? t : "";
            };
            e.event_id = col(0);
            e.room_id = col(1);
            e.type = col(2);
            e.sender = col(3);
            e.state_key = col(4);
            try { e.content = json::parse(col(5)); } catch (...) { e.content = json::object(); }
            e.origin_server_ts = sqlite3_column_int64(stmt, 6);
            e.depth = sqlite3_column_int64(stmt, 7);
            events.push_back(e);
        });
    return events;
}

json RoomManager::get_state_event(const std::string& room_id,
                                   const std::string& type,
                                   const std::string& state_key) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::string content = db_.get_text(
        "SELECT e.content FROM room_state rs JOIN events e ON rs.event_id=e.event_id "
        "WHERE rs.room_id=? AND rs.type=? AND rs.state_key=?",
        {room_id, type, state_key});
    if (content.empty()) return json();
    try { return json::parse(content); } catch (...) { return json::object(); }
}

std::vector<std::string> RoomManager::get_user_rooms(const std::string& user_id) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<std::string> result;
    db_.query(
        "SELECT room_id FROM room_members WHERE user_id=? AND membership='join'",
        {user_id},
        [&](sqlite3_stmt* stmt) {
            const char* rid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (rid) result.push_back(rid);
        });
    return result;
}

std::vector<json> RoomManager::get_public_rooms(int limit, int since) const {
    std::shared_lock<std::shared_mutex> lock(mutex_);
    std::vector<json> result;
    db_.query(
        "SELECT r.room_id, r.creator FROM rooms r "
        "JOIN room_state rs ON rs.room_id=r.room_id AND rs.type='m.room.join_rules' "
        "JOIN events e ON rs.event_id=e.event_id "
        "WHERE json_extract(e.content,'$.join_rule')='public' "
        "LIMIT ? OFFSET ?",
        {std::to_string(limit), std::to_string(since)},
        [&](sqlite3_stmt* stmt) {
            const char* rid = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            if (!rid) return;
            std::string room_id = rid;

            // Get name
            std::string name_raw = db_.get_text(
                "SELECT e.content FROM room_state rs JOIN events e ON rs.event_id=e.event_id "
                "WHERE rs.room_id=? AND rs.type='m.room.name' AND rs.state_key=''",
                {room_id});
            std::string name;
            try {
                if (!name_raw.empty()) name = json::parse(name_raw).value("name", "");
            } catch (...) {}

            int64_t num_members = db_.get_int(
                "SELECT COUNT(*) FROM room_members WHERE room_id=? AND membership='join'",
                {room_id});

            result.push_back({
                {"room_id", room_id},
                {"name", name},
                {"num_joined_members", num_members},
                {"world_readable", false},
                {"guest_can_join", false}
            });
        });
    return result;
}

bool RoomManager::set_alias(const std::string& alias, const std::string& room_id) {
    try {
        db_.execute("INSERT OR REPLACE INTO room_aliases(alias, room_id) VALUES(?,?)",
                    {alias, room_id});
        return true;
    } catch (...) { return false; }
}

std::string RoomManager::resolve_alias(const std::string& alias) const {
    return db_.get_text("SELECT room_id FROM room_aliases WHERE alias=?", {alias});
}

bool RoomManager::delete_alias(const std::string& alias) {
    return db_.execute("DELETE FROM room_aliases WHERE alias=?", {alias}) > 0;
}

int64_t RoomManager::get_sync_position() const {
    return sync_position_;
}

std::vector<Event> RoomManager::get_events_since(const std::string& room_id,
                                                   int64_t since_pos) const {
    // since_pos is treated as a depth threshold
    return get_timeline(room_id, since_pos, 100);
}

int RoomManager::get_user_power_level(const std::string& room_id,
                                       const std::string& user_id) const {
    json pl = get_state_event(room_id, "m.room.power_levels", "");
    if (pl.is_null() || pl.is_discarded()) return 0;
    if (pl.contains("users") && pl["users"].contains(user_id)) {
        return pl["users"][user_id].get<int>();
    }
    return pl.value("users_default", 0);
}

int RoomManager::get_required_power_level(const std::string& room_id,
                                           const std::string& action) const {
    json pl = get_state_event(room_id, "m.room.power_levels", "");
    if (pl.is_null() || pl.is_discarded()) {
        if (action == "kick" || action == "ban" || action == "redact") return 50;
        return 0;
    }
    if (action == "kick") return pl.value("kick", 50);
    if (action == "ban") return pl.value("ban", 50);
    if (action == "invite") return pl.value("invite", 0);
    if (action == "state") return pl.value("state_default", 50);
    return pl.value("events_default", 0);
}
