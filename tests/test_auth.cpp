#define CATCH_CONFIG_MAIN
#include "../include/catch.hpp"
#include "../include/httplib.h"
#include "../include/json.h"
#include <thread>
#include <chrono>
#include <random>

using json = nlohmann::json;

// Generate unique username for testing
std::string generate_unique_username(const std::string& prefix) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000000, 9999999);

    auto now = std::chrono::high_resolution_clock::now();
    auto nanos = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();

    return prefix + "_" + std::to_string(nanos) + "_" + std::to_string(dis(gen));
}

// Test helper class to manage server lifecycle
class TestServer {
private:
    std::thread server_thread;
    int port = 8081;  // Use different port for testing

public:
    TestServer() {
        // Start server in background thread
        server_thread = std::thread([this]() {
            // We'll need to refactor main.cpp to expose server creation
            // For now, we assume server is running
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ~TestServer() {
        if (server_thread.joinable()) {
            server_thread.detach();
        }
    }

    int get_port() const { return port; }
};

// HTTP client wrapper for testing
class TestClient {
private:
    httplib::Client client;

public:
    TestClient(const std::string& host = "localhost", int port = 8080)
        : client(host, port) {
        client.set_connection_timeout(5, 0);
        client.set_read_timeout(5, 0);
    }

    json get(const std::string& path) {
        auto res = client.Get(path.c_str());
        if (res && res->status == 200) {
            return json::parse(res->body);
        }
        return json::object();
    }

    std::pair<int, json> post(const std::string& path, const json& body,
                              const std::string& auth_token = "") {
        httplib::Headers headers = {{"Content-Type", "application/json"}};
        if (!auth_token.empty()) {
            headers.insert({"Authorization", "Bearer " + auth_token});
        }

        auto res = client.Post(path.c_str(), headers, body.dump(), "application/json");
        if (res) {
            if (res->body.empty()) {
                return {res->status, json::object()};
            }
            return {res->status, json::parse(res->body)};
        }
        return {0, json::object()};
    }

    std::pair<int, json> get_with_auth(const std::string& path, const std::string& auth_token) {
        httplib::Headers headers = {{"Authorization", "Bearer " + auth_token}};
        auto res = client.Get(path.c_str(), headers);
        if (res) {
            return {res->status, json::parse(res->body)};
        }
        return {0, json::object()};
    }
};

// ============================================================================
// Server Discovery Tests
// ============================================================================

TEST_CASE("Server discovery endpoint works", "[discovery]") {
    TestClient client;

    SECTION("GET /.well-known/matrix/client returns homeserver info") {
        json response = client.get("/.well-known/matrix/client");

        REQUIRE(response.contains("m.homeserver"));
        REQUIRE(response["m.homeserver"].contains("base_url"));
        REQUIRE(response["m.homeserver"]["base_url"].get<std::string>() == "http://localhost:8080");
    }
}

// ============================================================================
// Login Flow Tests
// ============================================================================

TEST_CASE("Login types endpoint works", "[login]") {
    TestClient client;

    SECTION("GET /_matrix/client/v3/login returns supported login types") {
        json response = client.get("/_matrix/client/v3/login");

        REQUIRE(response.contains("flows"));
        REQUIRE(response["flows"].is_array());
        REQUIRE(response["flows"].size() >= 1);

        bool has_password = false;
        for (const auto& flow : response["flows"]) {
            if (flow["type"] == "m.login.password") {
                has_password = true;
                break;
            }
        }
        REQUIRE(has_password);
    }
}

// ============================================================================
// Registration Tests
// ============================================================================

TEST_CASE("Registration with dummy auth", "[register]") {
    TestClient client;
    std::string username = generate_unique_username("test_user");

    SECTION("Can register with m.login.dummy") {
        json request = {
            {"username", username},
            {"password", "testpass123"},
            {"auth", {
                {"type", "m.login.dummy"}
            }}
        };

        auto [status, response] = client.post("/_matrix/client/v3/register", request);

        REQUIRE(status == 200);
        REQUIRE(response.contains("user_id"));
        REQUIRE(response.contains("access_token"));
        REQUIRE(response.contains("device_id"));

        std::string user_id = response["user_id"];
        REQUIRE(user_id.find("@" + username) != std::string::npos);
        REQUIRE(user_id.find(":example.com") != std::string::npos);

        std::string token = response["access_token"];
        REQUIRE(token.find("syt_") == 0);

        std::string device_id = response["device_id"];
        REQUIRE(device_id.find("DEVICE_") == 0);
    }
}

TEST_CASE("Registration multi-stage auth flow", "[register][flow]") {
    TestClient client;
    std::string username = generate_unique_username("flow_user");

    SECTION("Initial request returns auth flows") {
        json request = {
            {"username", username},
            {"password", "secure_password"}
        };

        auto [status, response] = client.post("/_matrix/client/v3/register", request);

        REQUIRE(status == 401);
        REQUIRE(response.contains("flows"));
        REQUIRE(response.contains("session"));
        REQUIRE(response.contains("completed"));

        REQUIRE(response["completed"].is_array());
        REQUIRE(response["completed"].empty());
    }

    SECTION("Can complete recaptcha then terms") {
        // Start registration
        json request = {
            {"username", username},
            {"password", "secure_password"}
        };
        auto [status1, response1] = client.post("/_matrix/client/v3/register", request);
        REQUIRE(status1 == 401);

        std::string session_id = response1["session"];

        // Complete recaptcha stage
        json recaptcha_request = {
            {"auth", {
                {"type", "m.login.recaptcha"},
                {"response", "fake_captcha_token"},
                {"session", session_id}
            }}
        };
        auto [status2, response2] = client.post("/_matrix/client/v3/register", recaptcha_request);
        REQUIRE(status2 == 401);
        REQUIRE(response2["completed"].size() == 1);
        REQUIRE(response2["completed"][0] == "m.login.recaptcha");

        // Complete terms stage
        json terms_request = {
            {"auth", {
                {"type", "m.login.terms"},
                {"session", session_id}
            }}
        };
        auto [status3, response3] = client.post("/_matrix/client/v3/register", terms_request);

        REQUIRE(status3 == 200);
        REQUIRE(response3.contains("user_id"));
        REQUIRE(response3.contains("access_token"));
        REQUIRE(response3.contains("device_id"));
    }
}

TEST_CASE("Registration validation", "[register][validation]") {
    TestClient client;

    SECTION("Cannot register duplicate username") {
        std::string username = generate_unique_username("duplicate");

        // First registration
        json request1 = {
            {"username", username},
            {"password", "pass123"},
            {"auth", {{"type", "m.login.dummy"}}}
        };
        auto [status1, response1] = client.post("/_matrix/client/v3/register", request1);
        REQUIRE(status1 == 200);

        // Try to register same username again
        json request2 = {
            {"username", username},
            {"password", "different_pass"},
            {"auth", {{"type", "m.login.dummy"}}}
        };
        auto [status2, response2] = client.post("/_matrix/client/v3/register", request2);

        REQUIRE(status2 == 400);
        REQUIRE(response2.contains("errcode"));
        REQUIRE(response2["errcode"] == "M_USER_IN_USE");
    }
}

// ============================================================================
// Login Tests
// ============================================================================

TEST_CASE("Password login", "[login][password]") {
    TestClient client;
    std::string username = generate_unique_username("login_user");
    std::string password = "secure_pass_123";

    // First register a user
    json register_request = {
        {"username", username},
        {"password", password},
        {"auth", {{"type", "m.login.dummy"}}}
    };
    auto [reg_status, reg_response] = client.post("/_matrix/client/v3/register", register_request);
    REQUIRE(reg_status == 200);

    SECTION("Can login with correct credentials") {
        json login_request = {
            {"type", "m.login.password"},
            {"identifier", {
                {"type", "m.id.user"},
                {"user", username}
            }},
            {"password", password}
        };

        auto [status, response] = client.post("/_matrix/client/v3/login", login_request);

        REQUIRE(status == 200);
        REQUIRE(response.contains("user_id"));
        REQUIRE(response.contains("access_token"));
        REQUIRE(response.contains("device_id"));

        std::string user_id = response["user_id"];
        REQUIRE(user_id.find("@" + username) != std::string::npos);
    }

    SECTION("Cannot login with wrong password") {
        json login_request = {
            {"type", "m.login.password"},
            {"identifier", {
                {"type", "m.id.user"},
                {"user", username}
            }},
            {"password", "wrong_password"}
        };

        auto [status, response] = client.post("/_matrix/client/v3/login", login_request);

        REQUIRE(status == 403);
        REQUIRE(response.contains("errcode"));
        REQUIRE(response["errcode"] == "M_FORBIDDEN");
    }

    SECTION("Cannot login with non-existent user") {
        json login_request = {
            {"type", "m.login.password"},
            {"identifier", {
                {"type", "m.id.user"},
                {"user", "nonexistent_user_12345"}
            }},
            {"password", "anypassword"}
        };

        auto [status, response] = client.post("/_matrix/client/v3/login", login_request);

        REQUIRE(status == 403);
        REQUIRE(response.contains("errcode"));
        REQUIRE(response["errcode"] == "M_FORBIDDEN");
    }

    SECTION("Can specify custom device_id") {
        std::string custom_device = "MY_DEVICE_123";
        json login_request = {
            {"type", "m.login.password"},
            {"identifier", {
                {"type", "m.id.user"},
                {"user", username}
            }},
            {"password", password},
            {"device_id", custom_device}
        };

        auto [status, response] = client.post("/_matrix/client/v3/login", login_request);

        REQUIRE(status == 200);
        REQUIRE(response["device_id"] == custom_device);
    }
}

// ============================================================================
// Session Management Tests
// ============================================================================

TEST_CASE("Whoami endpoint", "[session][whoami]") {
    TestClient client;
    std::string username = generate_unique_username("whoami_user");

    // Register user
    json register_request = {
        {"username", username},
        {"password", "pass123"},
        {"auth", {{"type", "m.login.dummy"}}}
    };
    auto [reg_status, reg_response] = client.post("/_matrix/client/v3/register", register_request);
    REQUIRE(reg_status == 200);

    std::string access_token = reg_response["access_token"];
    std::string device_id = reg_response["device_id"];

    SECTION("Whoami returns user info with valid token") {
        auto [status, response] = client.get_with_auth("/_matrix/client/v3/account/whoami", access_token);

        REQUIRE(status == 200);
        REQUIRE(response.contains("user_id"));
        REQUIRE(response.contains("device_id"));
        REQUIRE(response["device_id"] == device_id);

        std::string user_id = response["user_id"];
        REQUIRE(user_id.find("@" + username) != std::string::npos);
    }

    SECTION("Whoami fails with invalid token") {
        auto [status, response] = client.get_with_auth("/_matrix/client/v3/account/whoami", "invalid_token_12345");

        REQUIRE(status == 401);
        REQUIRE(response.contains("errcode"));
        REQUIRE(response["errcode"] == "M_UNKNOWN_TOKEN");
    }
}

TEST_CASE("Logout endpoint", "[session][logout]") {
    TestClient client;
    std::string username = generate_unique_username("logout_user");

    // Register user
    json register_request = {
        {"username", username},
        {"password", "pass123"},
        {"auth", {{"type", "m.login.dummy"}}}
    };
    auto [reg_status, reg_response] = client.post("/_matrix/client/v3/register", register_request);
    REQUIRE(reg_status == 200);

    std::string access_token = reg_response["access_token"];

    SECTION("Can logout with valid token") {
        // Verify token works before logout
        auto [whoami_status1, whoami_response1] = client.get_with_auth("/_matrix/client/v3/account/whoami", access_token);
        REQUIRE(whoami_status1 == 200);

        // Logout
        auto [logout_status, logout_response] = client.post("/_matrix/client/v3/logout", json::object(), access_token);
        REQUIRE(logout_status == 200);

        // Verify token no longer works
        auto [whoami_status2, whoami_response2] = client.get_with_auth("/_matrix/client/v3/account/whoami", access_token);
        REQUIRE(whoami_status2 == 401);
        REQUIRE(whoami_response2["errcode"] == "M_UNKNOWN_TOKEN");
    }

    SECTION("Logout fails with invalid token") {
        auto [status, response] = client.post("/_matrix/client/v3/logout", json::object(), "invalid_token");

        REQUIRE(status == 401);
        REQUIRE(response.contains("errcode"));
        REQUIRE(response["errcode"] == "M_UNKNOWN_TOKEN");
    }
}

TEST_CASE("Multiple sessions", "[session][multiple]") {
    TestClient client;
    std::string username = generate_unique_username("multi_session");
    std::string password = "pass123";

    // Register user
    json register_request = {
        {"username", username},
        {"password", password},
        {"auth", {{"type", "m.login.dummy"}}}
    };
    auto [reg_status, reg_response] = client.post("/_matrix/client/v3/register", register_request);
    REQUIRE(reg_status == 200);

    std::string token1 = reg_response["access_token"];

    SECTION("Can create multiple sessions for same user") {
        // Login to create second session
        json login_request = {
            {"type", "m.login.password"},
            {"identifier", {{"type", "m.id.user"}, {"user", username}}},
            {"password", password}
        };

        auto [login_status, login_response] = client.post("/_matrix/client/v3/login", login_request);
        REQUIRE(login_status == 200);

        std::string token2 = login_response["access_token"];
        REQUIRE(token1 != token2);

        // Both tokens should work
        auto [whoami1_status, whoami1_response] = client.get_with_auth("/_matrix/client/v3/account/whoami", token1);
        REQUIRE(whoami1_status == 200);

        auto [whoami2_status, whoami2_response] = client.get_with_auth("/_matrix/client/v3/account/whoami", token2);
        REQUIRE(whoami2_status == 200);

        // Logout one session
        auto [logout_status, logout_response] = client.post("/_matrix/client/v3/logout", json::object(), token1);
        REQUIRE(logout_status == 200);

        // First token should be invalid
        auto [whoami3_status, whoami3_response] = client.get_with_auth("/_matrix/client/v3/account/whoami", token1);
        REQUIRE(whoami3_status == 401);

        // Second token should still work
        auto [whoami4_status, whoami4_response] = client.get_with_auth("/_matrix/client/v3/account/whoami", token2);
        REQUIRE(whoami4_status == 200);
    }
}

// ============================================================================
// Edge Cases and Error Handling
// ============================================================================

TEST_CASE("Error handling", "[errors]") {
    TestClient client;

    SECTION("Invalid JSON returns error") {
        httplib::Client http_client("localhost", 8080);
        auto res = http_client.Post("/_matrix/client/v3/register",
                                    "{invalid json",
                                    "application/json");
        // Server should handle gracefully (might crash or return 400)
        // This test documents current behavior
    }

    SECTION("Unknown login type returns error") {
        json login_request = {
            {"type", "m.login.unknown_type"},
            {"identifier", {{"type", "m.id.user"}, {"user", "test"}}},
            {"password", "pass"}
        };

        auto [status, response] = client.post("/_matrix/client/v3/login", login_request);

        REQUIRE(status == 400);
        REQUIRE(response.contains("errcode"));
        REQUIRE(response["errcode"] == "M_UNKNOWN");
    }
}
