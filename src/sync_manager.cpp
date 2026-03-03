#include "sync_manager.h"
#include <chrono>
#include <algorithm>

SyncManager::SyncManager() {}

void SyncManager::notify_event(const std::string& room_id, const Event& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t pos = ++position_;
        event_log_.push_back({pos, room_id, event});
        // Cap at 50k events to avoid unbounded memory growth
        if (event_log_.size() > 50000) {
            event_log_.erase(event_log_.begin(), event_log_.begin() + 10000);
        }
    }
    cv_.notify_all();
}

void SyncManager::notify_ephemeral(const std::string& room_id, const json& event) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t pos = ++position_;
        auto& room_eph = ephemeral_log_[room_id];
        room_eph.push_back({pos, event});
        if (room_eph.size() > 1000) {
            room_eph.erase(room_eph.begin(), room_eph.begin() + 500);
        }
    }
    cv_.notify_all();
}

void SyncManager::notify_presence(const std::string& user_id,
                                   const std::string& presence,
                                   const std::string& status_msg) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        int64_t pos = ++position_;
        presence_log_.push_back({pos, user_id, presence, status_msg});
        if (presence_log_.size() > 10000) {
            presence_log_.erase(presence_log_.begin(), presence_log_.begin() + 5000);
        }
    }
    cv_.notify_all();
}

int64_t SyncManager::current_position() const {
    return position_.load();
}

std::vector<json> SyncManager::get_ephemeral(const std::string& room_id,
                                              int64_t since_pos) const {
    std::vector<json> result;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = ephemeral_log_.find(room_id);
    if (it == ephemeral_log_.end()) return result;
    for (const auto& [pos, ev] : it->second) {
        if (pos > since_pos) result.push_back(ev);
    }
    return result;
}

json SyncManager::wait_for_sync(
    const std::string& user_id,
    int64_t since_pos,
    int timeout_ms,
    const std::vector<std::string>& joined_rooms,
    const std::function<std::vector<Event>(const std::string&, int64_t)>& get_room_events,
    const std::function<std::vector<Event>(const std::string&)>& get_room_state)
{
    // Wait for new events if we're up-to-date
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (since_pos >= position_.load()) {
            auto deadline = std::chrono::steady_clock::now()
                + std::chrono::milliseconds(timeout_ms);
            cv_.wait_until(lock, deadline, [&] {
                return position_.load() > since_pos;
            });
        }
    }

    int64_t new_pos = position_.load();

    // Build sync response
    json joined = json::object();

    for (const auto& room_id : joined_rooms) {
        // Get new timeline events
        auto timeline_events = get_room_events(room_id, since_pos);

        // Get state if this is an initial sync (since_pos == 0)
        std::vector<Event> state_events;
        if (since_pos == 0) {
            state_events = get_room_state(room_id);
        }

        // Get ephemeral events
        std::vector<json> eph_events;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = ephemeral_log_.find(room_id);
            if (it != ephemeral_log_.end()) {
                for (const auto& [pos, ev] : it->second) {
                    if (pos > since_pos) eph_events.push_back(ev);
                }
            }
        }

        if (timeline_events.empty() && state_events.empty() && eph_events.empty()
            && since_pos != 0) {
            continue; // No updates for this room
        }

        auto event_to_json = [](const Event& e) -> json {
            json j = {
                {"event_id", e.event_id},
                {"type", e.type},
                {"sender", e.sender},
                {"room_id", e.room_id},
                {"origin_server_ts", e.origin_server_ts},
                {"content", e.content}
            };
            if (!e.state_key.empty() || e.type.find(".member") != std::string::npos
                || e.type == "m.room.create"
                || e.type == "m.room.name"
                || e.type == "m.room.topic"
                || e.type == "m.room.power_levels"
                || e.type == "m.room.join_rules"
                || e.type == "m.room.history_visibility"
                || e.type == "m.room.guest_access"
                || e.type == "m.room.canonical_alias") {
                j["state_key"] = e.state_key;
            }
            return j;
        };

        json timeline_arr = json::array();
        for (const auto& e : timeline_events) timeline_arr.push_back(event_to_json(e));

        json state_arr = json::array();
        for (const auto& e : state_events) state_arr.push_back(event_to_json(e));

        json eph_arr = json::array();
        for (const auto& e : eph_events) eph_arr.push_back(e);

        joined[room_id] = {
            {"timeline", {
                {"events", timeline_arr},
                {"limited", false},
                {"prev_batch", "s" + std::to_string(since_pos)}
            }},
            {"state", {{"events", state_arr}}},
            {"ephemeral", {{"events", eph_arr}}},
            {"account_data", {{"events", json::array()}}}
        };
    }

    // Build presence section
    json presence_arr = json::array();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& pu : presence_log_) {
            if (pu.position > since_pos) {
                presence_arr.push_back({
                    {"type", "m.presence"},
                    {"sender", pu.user_id},
                    {"content", {
                        {"presence", pu.presence},
                        {"status_msg", pu.status_msg}
                    }}
                });
            }
        }
    }

    return {
        {"next_batch", "s" + std::to_string(new_pos)},
        {"rooms", {
            {"join", joined},
            {"invite", json::object()},
            {"leave", json::object()}
        }},
        {"presence", {{"events", presence_arr}}},
        {"account_data", {{"events", json::array()}}}
    };
}
