#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <random>
#include <sstream>
#include <algorithm>
#include <ctime>
#include "../include/httplib.h"
#include "../include/json.h"

using json = nlohmann::json;

// ============================================================================
// Data Structures
// ============================================================================

struct User {
    std::string user_id;
    std::string username;
    std::string password_hash;  // In production, use bcrypt/argon2
    std::vector<std::string> access_tokens;
    std::vector<std::string> device_ids;
    time_t created_at;
};

struct TokenInfo {
    std::string username;  // Key to look up User in users map
    std::string device_id;
};

struct AuthSession {
    std::string session_id;
    std::vector<std::string> completed_stages;
    std::string username;
    std::string password;
    time_t created_at;
};

// ============================================================================
// Utility Functions
// ============================================================================

class Utils {
public:
    static std::string generate_random_string(size_t length = 32) {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> dis(0, 15);

        std::stringstream ss;
        for (size_t i = 0; i < length; i++) {
            ss << std::hex << dis(gen);
        }
        return ss.str();
    }

    static std::string generate_token() {
        return "syt_" + generate_random_string(40);
    }

    static std::string generate_device_id() {
        return "DEVICE_" + generate_random_string(16);
    }

    static bool validate_captcha(const std::string& captcha) {
        // For development: accept any non-empty captcha
        // In production, this should call reCAPTCHA API
        return !captcha.empty();
    }

    static std::string extract_username(const std::string& user_id) {
        // Remove @ prefix and domain if present
        std::string username = user_id;
        if (!username.empty() && username[0] == '@') {
            size_t colon_pos = username.find(':');
            if (colon_pos != std::string::npos) {
                username = username.substr(1, colon_pos - 1);
            } else {
                username = username.substr(1);
            }
        }
        return username;
    }
};

// ============================================================================
// User Manager
// ============================================================================

class UserManager {
private:
    std::unordered_map<std::string, User> users_;
    std::unordered_map<std::string, TokenInfo> tokens_;
    const std::string homeserver_domain_;

public:
    UserManager(const std::string& domain = "example.com")
        : homeserver_domain_(domain) {}

    bool create_user(const std::string& username, const std::string& password) {
        if (users_.find(username) != users_.end()) {
            return false;  // User already exists
        }

        User user;
        user.username = username;
        user.user_id = "@" + username + ":" + homeserver_domain_;
        user.password_hash = password;  // In production, use bcrypt/argon2
        user.created_at = std::time(nullptr);

        users_[username] = user;
        return true;
    }

    bool verify_credentials(const std::string& username, const std::string& password) {
        if (users_.find(username) == users_.end()) {
            return false;
        }
        return users_[username].password_hash == password;
    }

    bool user_exists(const std::string& username) const {
        return users_.find(username) != users_.end();
    }

    std::string get_user_id(const std::string& username) const {
        auto it = users_.find(username);
        if (it != users_.end()) {
            return it->second.user_id;
        }
        return "";
    }

    std::string create_session(const std::string& username, const std::string& device_id) {
        std::string access_token = Utils::generate_token();

        TokenInfo token_info;
        token_info.username = username;
        token_info.device_id = device_id;
        tokens_[access_token] = token_info;

        users_[username].access_tokens.push_back(access_token);

        // Add device if not already present
        auto& user_devices = users_[username].device_ids;
        if (std::find(user_devices.begin(), user_devices.end(), device_id) == user_devices.end()) {
            user_devices.push_back(device_id);
        }

        return access_token;
    }

    bool validate_token(const std::string& access_token) const {
        return tokens_.find(access_token) != tokens_.end();
    }

    TokenInfo get_token_info(const std::string& access_token) const {
        auto it = tokens_.find(access_token);
        if (it != tokens_.end()) {
            return it->second;
        }
        return TokenInfo{};
    }

    bool revoke_token(const std::string& access_token) {
        auto it = tokens_.find(access_token);
        if (it == tokens_.end()) {
            return false;
        }

        std::string username = it->second.username;
        tokens_.erase(it);

        // Remove from user's token list
        auto& user_tokens = users_[username].access_tokens;
        user_tokens.erase(
            std::remove(user_tokens.begin(), user_tokens.end(), access_token),
            user_tokens.end()
        );

        return true;
    }
};

// ============================================================================
// Authentication Manager
// ============================================================================

class AuthManager {
private:
    std::unordered_map<std::string, AuthSession> active_sessions_;
    const std::vector<std::vector<std::string>> auth_flows_ = {
        {"m.login.dummy"},
        {"m.login.recaptcha", "m.login.terms"}
    };

public:
    std::string create_session(const std::string& username, const std::string& password) {
        std::string session_id = Utils::generate_random_string();

        AuthSession session;
        session.session_id = session_id;
        session.username = username;
        session.password = password;
        session.created_at = std::time(nullptr);

        active_sessions_[session_id] = session;
        return session_id;
    }

    bool session_exists(const std::string& session_id) const {
        return active_sessions_.find(session_id) != active_sessions_.end();
    }

    AuthSession& get_session(const std::string& session_id) {
        return active_sessions_[session_id];
    }

    void update_session_credentials(const std::string& session_id,
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

    bool complete_stage(const std::string& session_id, const std::string& stage_type) {
        if (active_sessions_.find(session_id) == active_sessions_.end()) {
            return false;
        }

        auto& session = active_sessions_[session_id];
        session.completed_stages.push_back(stage_type);
        return true;
    }

    bool is_flow_complete(const std::string& session_id) const {
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

    json get_flows_response(const std::string& session_id) const {
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

    void destroy_session(const std::string& session_id) {
        active_sessions_.erase(session_id);
    }
};

// ============================================================================
// HTTP Handlers
// ============================================================================

class MatrixServer {
private:
    UserManager user_manager_;
    AuthManager auth_manager_;
    httplib::Server server_;
    const std::string homeserver_url_;

public:
    MatrixServer(const std::string& homeserver_url = "http://localhost:8080")
        : homeserver_url_(homeserver_url) {
        setup_routes();
    }

    void setup_routes() {
        // Server discovery
        server_.Get("/.well-known/matrix/client", [this](const httplib::Request& req, httplib::Response& res) {
            handle_well_known(req, res);
        });

        // Login endpoints
        server_.Get("/_matrix/client/v3/login", [this](const httplib::Request& req, httplib::Response& res) {
            handle_get_login_types(req, res);
        });

        server_.Post("/_matrix/client/v3/login", [this](const httplib::Request& req, httplib::Response& res) {
            handle_login(req, res);
        });

        // Registration
        server_.Post("/_matrix/client/v3/register", [this](const httplib::Request& req, httplib::Response& res) {
            handle_register(req, res);
        });

        // Session management
        server_.Post("/_matrix/client/v3/logout", [this](const httplib::Request& req, httplib::Response& res) {
            handle_logout(req, res);
        });

        server_.Get("/_matrix/client/v3/account/whoami", [this](const httplib::Request& req, httplib::Response& res) {
            handle_whoami(req, res);
        });
    }

    void start(const std::string& host = "0.0.0.0", int port = 8080) {
        std::cout << "Starting Matrix homeserver on " << host << ":" << port << std::endl;
        if (!server_.listen(host, port)) {
            std::cerr << "Failed to start server\n";
        }
    }

private:
    void handle_well_known(const httplib::Request& req, httplib::Response& res) {
        json response = {
            {"m.homeserver", {
                {"base_url", homeserver_url_}
            }}
        };
        res.set_content(response.dump(), "application/json");
    }

    void handle_get_login_types(const httplib::Request& req, httplib::Response& res) {
        json response = {
            {"flows", {
                {{"type", "m.login.password"}},
                {{"type", "m.login.token"}}
            }}
        };
        res.status = 200;
        res.set_content(response.dump(), "application/json");
    }

    void handle_login(const httplib::Request& req, httplib::Response& res) {
        json body = json::parse(req.body);
        std::string login_type = body.value("type", "");

        if (login_type == "m.login.password") {
            handle_password_login(body, res);
        } else if (login_type == "m.login.token") {
            send_error(res, 400, "M_UNKNOWN", "Token login not implemented");
        } else {
            send_error(res, 400, "M_UNKNOWN", "Unknown login type");
        }
    }

    void handle_password_login(const json& body, httplib::Response& res) {
        // Extract username
        std::string username;
        if (body.contains("identifier") && body["identifier"].contains("type")) {
            std::string identifier_type = body["identifier"]["type"];
            if (identifier_type == "m.id.user") {
                username = body["identifier"]["user"].get<std::string>();
            }
        } else if (body.contains("user")) {
            username = body["user"].get<std::string>();
        }

        username = Utils::extract_username(username);
        std::string password = body.value("password", "");

        // Verify credentials
        if (!user_manager_.verify_credentials(username, password)) {
            send_error(res, 403, "M_FORBIDDEN", "Invalid username or password");
            return;
        }

        // Get or generate device_id
        std::string device_id = body.contains("device_id")
            ? body["device_id"].get<std::string>()
            : Utils::generate_device_id();

        // Create session
        std::string access_token = user_manager_.create_session(username, device_id);

        json response = {
            {"user_id", user_manager_.get_user_id(username)},
            {"access_token", access_token},
            {"device_id", device_id}
        };

        res.status = 200;
        res.set_content(response.dump(), "application/json");
    }

    void handle_register(const httplib::Request& req, httplib::Response& res) {
        json body = json::parse(req.body);

        // Get or create session
        std::string session_id;
        if (body.contains("auth") && body["auth"].contains("session")) {
            session_id = body["auth"]["session"].get<std::string>();
        } else {
            std::string username = body.value("username", "");
            std::string password = body.value("password", "");
            session_id = auth_manager_.create_session(username, password);
        }

        // Update session credentials if provided
        if (body.contains("username") || body.contains("password")) {
            std::string username = body.value("username", "");
            std::string password = body.value("password", "");
            auth_manager_.update_session_credentials(session_id, username, password);
        }

        // Process authentication stage
        if (body.contains("auth")) {
            process_auth_stage(session_id, body["auth"]);
        }

        // Check if authentication is complete
        if (auth_manager_.is_flow_complete(session_id)) {
            complete_registration(session_id, res);
        } else {
            // More authentication needed
            json response = auth_manager_.get_flows_response(session_id);
            res.status = 401;
            res.set_content(response.dump(), "application/json");
        }
    }

    void process_auth_stage(const std::string& session_id, const json& auth) {
        std::string auth_type = auth["type"].get<std::string>();

        if (auth_type == "m.login.recaptcha") {
            if (auth.contains("response")) {
                std::string captcha_response = auth["response"].get<std::string>();
                if (Utils::validate_captcha(captcha_response)) {
                    auth_manager_.complete_stage(session_id, "m.login.recaptcha");
                }
            }
        } else if (auth_type == "m.login.terms") {
            auth_manager_.complete_stage(session_id, "m.login.terms");
        } else if (auth_type == "m.login.dummy") {
            auth_manager_.complete_stage(session_id, "m.login.dummy");
        }
    }

    void complete_registration(const std::string& session_id, httplib::Response& res) {
        auto& session = auth_manager_.get_session(session_id);
        std::string username = session.username;
        std::string password = session.password;

        // Create user
        if (!user_manager_.create_user(username, password)) {
            send_error(res, 400, "M_USER_IN_USE", "Username already taken");
            auth_manager_.destroy_session(session_id);
            return;
        }

        // Generate tokens
        std::string device_id = Utils::generate_device_id();
        std::string access_token = user_manager_.create_session(username, device_id);

        auth_manager_.destroy_session(session_id);

        json response = {
            {"user_id", user_manager_.get_user_id(username)},
            {"access_token", access_token},
            {"device_id", device_id}
        };

        res.status = 200;
        res.set_content(response.dump(), "application/json");
    }

    void handle_logout(const httplib::Request& req, httplib::Response& res) {
        std::string access_token = extract_bearer_token(req);

        if (user_manager_.revoke_token(access_token)) {
            json response = {};
            res.status = 200;
            res.set_content(response.dump(), "application/json");
        } else {
            send_error(res, 401, "M_UNKNOWN_TOKEN", "Access token not found");
        }
    }

    void handle_whoami(const httplib::Request& req, httplib::Response& res) {
        std::string access_token = extract_bearer_token(req);

        if (!user_manager_.validate_token(access_token)) {
            send_error(res, 401, "M_UNKNOWN_TOKEN", "Access token not found");
            return;
        }

        TokenInfo token_info = user_manager_.get_token_info(access_token);
        std::string user_id = user_manager_.get_user_id(token_info.username);

        json response = {
            {"user_id", user_id},
            {"device_id", token_info.device_id}
        };

        res.status = 200;
        res.set_content(response.dump(), "application/json");
    }

    std::string extract_bearer_token(const httplib::Request& req) const {
        std::string auth_header = req.get_header_value("Authorization");
        if (auth_header.find("Bearer ") == 0) {
            return auth_header.substr(7);
        }
        return "";
    }

    void send_error(httplib::Response& res, int status,
                   const std::string& errcode, const std::string& error) {
        json response = {
            {"errcode", errcode},
            {"error", error}
        };
        res.status = status;
        res.set_content(response.dump(), "application/json");
    }
};

// ============================================================================
// Main
// ============================================================================

int main() {
    MatrixServer server;
    server.start("0.0.0.0", 8080);
    return 0;
}
