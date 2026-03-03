#pragma once

#include <string>
#include <map>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <functional>
#include "types.h"
#include "json.h"

using json = nlohmann::json;

struct SyncEvent {
    int64_t position;
    std::string room_id;
    Event event;
};

// Per-user presence update
struct PresenceUpdate {
    int64_t position;
    std::string user_id;
    std::string presence;
    std::string status_msg;
};

class SyncManager {
public:
    SyncManager();

    // Called whenever a new room event is appended
    void notify_event(const std::string& room_id, const Event& event);

    // Called for ephemeral events (typing, receipts)
    void notify_ephemeral(const std::string& room_id, const json& event);

    // Called for presence updates
    void notify_presence(const std::string& user_id, const std::string& presence,
                         const std::string& status_msg = "");

    // Get current stream position
    int64_t current_position() const;

    // Long-poll: wait for events since `since_pos` for `timeout_ms`, building a sync response
    // joined_rooms: set of room_ids the user is a member of
    // Returns the sync response JSON
    json wait_for_sync(const std::string& user_id,
                       int64_t since_pos,
                       int timeout_ms,
                       const std::vector<std::string>& joined_rooms,
                       const std::function<std::vector<Event>(const std::string&, int64_t)>& get_room_events,
                       const std::function<std::vector<Event>(const std::string&)>& get_room_state);

    // Get ephemeral events for a room since a position
    std::vector<json> get_ephemeral(const std::string& room_id, int64_t since_pos) const;

private:
    std::atomic<int64_t> position_{0};
    mutable std::mutex mutex_;
    std::condition_variable cv_;

    // Recent events in order (capped at last 50k)
    std::vector<SyncEvent> event_log_;

    // Ephemeral events per room
    std::map<std::string, std::vector<std::pair<int64_t, json>>> ephemeral_log_;

    // Presence updates
    std::vector<PresenceUpdate> presence_log_;
};
