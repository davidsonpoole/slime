#pragma once

#include <unordered_map>
#include <vector>
#include <string>
#include "types.h"
#include "json.h"

using json = nlohmann::json;

class AuthManager {
private:
    std::unordered_map<std::string, AuthSession> active_sessions_;
    const std::vector<std::vector<std::string>> auth_flows_;

public:
    AuthManager();

    std::string create_session(const std::string& username, const std::string& password);
    bool session_exists(const std::string& session_id) const;
    AuthSession& get_session(const std::string& session_id);
    void update_session_credentials(const std::string& session_id,
                                     const std::string& username,
                                     const std::string& password);
    bool complete_stage(const std::string& session_id, const std::string& stage_type);
    bool is_flow_complete(const std::string& session_id) const;
    json get_flows_response(const std::string& session_id) const;
    void destroy_session(const std::string& session_id);
};
