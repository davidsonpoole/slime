#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include <shared_mutex>
#include "types.h"
#include "json.h"
#include "database_manager.h"

using json = nlohmann::json;

class RoomManager {
public:
    RoomManager(const std::string& domain, DatabaseManager& db);

    // Room lifecycle
    std::string create_room(const std::string& creator_user_id,
                            const json& options = json::object());
    bool room_exists(const std::string& room_id) const;

    // Membership
    bool add_member(const std::string& room_id, const std::string& user_id,
                    const std::string& membership = "join");
    bool remove_member(const std::string& room_id, const std::string& user_id);
    bool is_member(const std::string& room_id, const std::string& user_id) const;
    std::string get_membership(const std::string& room_id, const std::string& user_id) const;
    std::vector<std::string> get_members(const std::string& room_id,
                                          const std::string& membership = "join") const;

    // Events
    std::string add_event(const std::string& room_id,
                          const std::string& event_type,
                          const std::string& sender,
                          const json& content,
                          const std::string& state_key = "");
    Event get_event(const std::string& event_id) const;
    std::vector<Event> get_timeline(const std::string& room_id,
                                     int64_t since_depth = 0,
                                     int limit = 50) const;
    std::vector<Event> get_room_state(const std::string& room_id) const;
    json get_state_event(const std::string& room_id, const std::string& type,
                         const std::string& state_key = "") const;

    // Queries
    std::vector<std::string> get_user_rooms(const std::string& user_id) const;
    std::vector<json> get_public_rooms(int limit = 100, int since = 0) const;

    // Aliases
    bool set_alias(const std::string& alias, const std::string& room_id);
    std::string resolve_alias(const std::string& alias) const;
    bool delete_alias(const std::string& alias);

    // Sync helpers
    int64_t get_sync_position() const;
    std::vector<Event> get_events_since(const std::string& room_id, int64_t since_pos) const;

    // Power level helpers
    int get_user_power_level(const std::string& room_id, const std::string& user_id) const;
    int get_required_power_level(const std::string& room_id,
                                  const std::string& action) const;

    const std::string& domain() const { return homeserver_domain_; }

private:
    DatabaseManager& db_;
    const std::string homeserver_domain_;
    mutable std::shared_mutex mutex_;
    int64_t sync_position_ = 0;

    int64_t next_depth(const std::string& room_id) const;
    void inject_state_events(const std::string& room_id,
                              const std::string& creator_user_id,
                              const json& options);
};
