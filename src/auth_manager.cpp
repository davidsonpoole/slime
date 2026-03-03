#include "auth_manager.h"
#include "utils.h"
#include <algorithm>
#include <ctime>

AuthManager::AuthManager()
    : auth_flows_({
        {"m.login.dummy"},
        {"m.login.recaptcha", "m.login.terms"}
    }) {}

std::string AuthManager::create_session(const std::string& username, const std::string& password) {
    std::string session_id = Utils::generate_random_string();

    AuthSession session;
    session.session_id = session_id;
    session.username = username;
    session.password = password;
    session.created_at = std::time(nullptr);

    active_sessions_[session_id] = session;
    return session_id;
}

bool AuthManager::session_exists(const std::string& session_id) const {
    return active_sessions_.find(session_id) != active_sessions_.end();
}

AuthSession& AuthManager::get_session(const std::string& session_id) {
    return active_sessions_[session_id];
}

void AuthManager::update_session_credentials(const std::string& session_id,
                                             const std::string& username,
                                             const std::string& password) {
    if (active_sessions_.find(session_id) != active_sessions_.end()) {
        if (!username.empty()) {
            active_sessions_[session_id].username = username;
        }
        if (!password.empty()) {
            active_sessions_[session_id].password = password;
        }
    }
}

bool AuthManager::complete_stage(const std::string& session_id, const std::string& stage_type) {
    if (active_sessions_.find(session_id) == active_sessions_.end()) {
        return false;
    }

    auto& session = active_sessions_[session_id];
    session.completed_stages.push_back(stage_type);
    return true;
}

bool AuthManager::is_flow_complete(const std::string& session_id) const {
    auto it = active_sessions_.find(session_id);
    if (it == active_sessions_.end()) {
        return false;
    }

    const auto& completed = it->second.completed_stages;

    for (const auto& flow : auth_flows_) {
        bool all_stages_complete = true;
        for (const auto& required_stage : flow) {
            if (std::find(completed.begin(), completed.end(), required_stage) == completed.end()) {
                all_stages_complete = false;
                break;
            }
        }
        if (all_stages_complete) {
            return true;
        }
    }

    return false;
}

json AuthManager::get_flows_response(const std::string& session_id) const {
    json flows_array = json::array();
    for (const auto& flow : auth_flows_) {
        flows_array.push_back({{"stages", flow}});
    }

    json response = {
        {"flows", flows_array},
        {"session", session_id},
        {"completed", active_sessions_.at(session_id).completed_stages},
        {"params", nullptr}
    };

    return response;
}

void AuthManager::destroy_session(const std::string& session_id) {
    active_sessions_.erase(session_id);
}
