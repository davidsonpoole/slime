#include "matrix_server.h"
#include "utils.h"
#include <iostream>
#include <thread>
#include <chrono>

// ── Constructor / Start ─────────────────────────────────────────────────────

MatrixServer::MatrixServer(const Config& config)
    : config_(config),
      db_(config.db_path),
      user_manager_(config.server_name, db_),
      auth_manager_(),
      room_manager_(config.server_name, db_),
      sync_manager_(),
      media_manager_(config.media_path, config.server_name, db_),
      key_manager_(config.signing_key_path, config.server_name, db_),
      federation_manager_(db_, key_manager_)
{
    // Phase 1.4: thread pool — 2 workers per hardware core
    server_.new_task_queue = [] {
        return new httplib::ThreadPool(std::thread::hardware_concurrency() * 2);
    };
    setup_routes();
}

void MatrixServer::start() {
    std::cout << "Starting Slime Matrix homeserver on 0.0.0.0:"
              << config_.port << " (server_name=" << config_.server_name << ")\n";
    if (!server_.listen("0.0.0.0", config_.port)) {
        std::cerr << "Failed to start server on port " << config_.port << "\n";
    }
}

// ── Routes ──────────────────────────────────────────────────────────────────

void MatrixServer::setup_routes() {
    // Phase 1.2: CORS middleware — apply to every request
    server_.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
        if (req.method == "OPTIONS") {
            res.status = 200;
            res.set_content("", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // ── Discovery ────────────────────────────────────────────────────────────
    server_.Get("/.well-known/matrix/client", [this](auto& req, auto& res) {
        handle_well_known(req, res);
    });
    // Phase 1.3
    server_.Get("/_matrix/client/versions", [this](auto& req, auto& res) {
        handle_versions(req, res);
    });
    server_.Get("/_matrix/client/v3/capabilities", [this](auto& req, auto& res) {
        handle_capabilities(req, res);
    });

    // ── Auth ─────────────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/login", [this](auto& req, auto& res) {
        handle_get_login_types(req, res);
    });
    server_.Post("/_matrix/client/v3/login", [this](auto& req, auto& res) {
        handle_login(req, res);
    });
    server_.Post("/_matrix/client/v3/register", [this](auto& req, auto& res) {
        handle_register(req, res);
    });
    server_.Post("/_matrix/client/v3/logout", [this](auto& req, auto& res) {
        handle_logout(req, res);
    });
    server_.Post("/_matrix/client/v3/logout/all", [this](auto& req, auto& res) {
        handle_logout_all(req, res);
    });
    server_.Get("/_matrix/client/v3/account/whoami", [this](auto& req, auto& res) {
        handle_whoami(req, res);
    });

    // ── Rooms ────────────────────────────────────────────────────────────────
    server_.Post("/_matrix/client/v3/createRoom", [this](auto& req, auto& res) {
        handle_create_room(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/join", [this](auto& req, auto& res) {
        handle_join_room(req, res);
    });
    server_.Post("/_matrix/client/v3/join/:roomIdOrAlias", [this](auto& req, auto& res) {
        handle_join_by_alias(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/leave", [this](auto& req, auto& res) {
        handle_leave_room(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/forget", [this](auto& req, auto& res) {
        handle_forget_room(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/invite", [this](auto& req, auto& res) {
        handle_invite(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/kick", [this](auto& req, auto& res) {
        handle_kick(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/ban", [this](auto& req, auto& res) {
        handle_ban(req, res);
    });
    server_.Post("/_matrix/client/v3/rooms/:roomId/unban", [this](auto& req, auto& res) {
        handle_unban(req, res);
    });
    server_.Put("/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId",
                [this](auto& req, auto& res) { handle_send_event(req, res); });
    server_.Put("/_matrix/client/v3/rooms/:roomId/state/:eventType",
                [this](auto& req, auto& res) { handle_send_state_event(req, res); });
    server_.Put("/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
                [this](auto& req, auto& res) { handle_send_state_event(req, res); });
    server_.Get("/_matrix/client/v3/rooms/:roomId/messages", [this](auto& req, auto& res) {
        handle_get_messages(req, res);
    });
    server_.Get("/_matrix/client/v3/rooms/:roomId/event/:eventId", [this](auto& req, auto& res) {
        handle_get_event(req, res);
    });
    server_.Get("/_matrix/client/v3/rooms/:roomId/state", [this](auto& req, auto& res) {
        handle_get_state(req, res);
    });
    server_.Get("/_matrix/client/v3/rooms/:roomId/state/:eventType", [this](auto& req, auto& res) {
        handle_get_state_event(req, res);
    });
    server_.Get("/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey",
                [this](auto& req, auto& res) { handle_get_state_event(req, res); });
    server_.Get("/_matrix/client/v3/rooms/:roomId/members", [this](auto& req, auto& res) {
        handle_get_members(req, res);
    });
    server_.Get("/_matrix/client/v3/rooms/:roomId/joined_members", [this](auto& req, auto& res) {
        handle_get_joined_members(req, res);
    });
    server_.Get("/_matrix/client/v3/joined_rooms", [this](auto& req, auto& res) {
        handle_get_joined_rooms(req, res);
    });
    server_.Get("/_matrix/client/v3/publicRooms", [this](auto& req, auto& res) {
        handle_public_rooms_get(req, res);
    });
    server_.Post("/_matrix/client/v3/publicRooms", [this](auto& req, auto& res) {
        handle_public_rooms_post(req, res);
    });

    // ── Room aliases ─────────────────────────────────────────────────────────
    server_.Put("/_matrix/client/v3/directory/room/:roomAlias", [this](auto& req, auto& res) {
        handle_put_alias(req, res);
    });
    server_.Get("/_matrix/client/v3/directory/room/:roomAlias", [this](auto& req, auto& res) {
        handle_get_alias(req, res);
    });
    server_.Delete("/_matrix/client/v3/directory/room/:roomAlias", [this](auto& req, auto& res) {
        handle_delete_alias(req, res);
    });

    // ── Sync ─────────────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/sync", [this](auto& req, auto& res) {
        handle_sync(req, res);
    });

    // ── Filters ──────────────────────────────────────────────────────────────
    server_.Post("/_matrix/client/v3/user/:userId/filter", [this](auto& req, auto& res) {
        handle_put_filter(req, res);
    });
    server_.Get("/_matrix/client/v3/user/:userId/filter/:filterId", [this](auto& req, auto& res) {
        handle_get_filter(req, res);
    });

    // ── Profile ──────────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/profile/:userId", [this](auto& req, auto& res) {
        handle_get_profile(req, res);
    });
    server_.Get("/_matrix/client/v3/profile/:userId/displayname", [this](auto& req, auto& res) {
        handle_get_displayname(req, res);
    });
    server_.Put("/_matrix/client/v3/profile/:userId/displayname", [this](auto& req, auto& res) {
        handle_put_displayname(req, res);
    });
    server_.Get("/_matrix/client/v3/profile/:userId/avatar_url", [this](auto& req, auto& res) {
        handle_get_avatar_url(req, res);
    });
    server_.Put("/_matrix/client/v3/profile/:userId/avatar_url", [this](auto& req, auto& res) {
        handle_put_avatar_url(req, res);
    });

    // ── Presence ─────────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/presence/:userId/status", [this](auto& req, auto& res) {
        handle_get_presence(req, res);
    });
    server_.Put("/_matrix/client/v3/presence/:userId/status", [this](auto& req, auto& res) {
        handle_put_presence(req, res);
    });

    // ── Typing ───────────────────────────────────────────────────────────────
    server_.Put("/_matrix/client/v3/rooms/:roomId/typing/:userId", [this](auto& req, auto& res) {
        handle_put_typing(req, res);
    });

    // ── Read receipts ────────────────────────────────────────────────────────
    server_.Post("/_matrix/client/v3/rooms/:roomId/receipt/:receiptType/:eventId",
                 [this](auto& req, auto& res) { handle_post_receipt(req, res); });

    // ── Account data ─────────────────────────────────────────────────────────
    server_.Put("/_matrix/client/v3/user/:userId/account_data/:type",
                [this](auto& req, auto& res) { handle_put_account_data(req, res); });
    server_.Get("/_matrix/client/v3/user/:userId/account_data/:type",
                [this](auto& req, auto& res) { handle_get_account_data(req, res); });
    server_.Put("/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
                [this](auto& req, auto& res) { handle_put_room_account_data(req, res); });
    server_.Get("/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type",
                [this](auto& req, auto& res) { handle_get_room_account_data(req, res); });

    // ── Devices ──────────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/devices", [this](auto& req, auto& res) {
        handle_get_devices(req, res);
    });
    server_.Get("/_matrix/client/v3/devices/:deviceId", [this](auto& req, auto& res) {
        handle_get_device(req, res);
    });
    server_.Put("/_matrix/client/v3/devices/:deviceId", [this](auto& req, auto& res) {
        handle_put_device(req, res);
    });
    server_.Delete("/_matrix/client/v3/devices/:deviceId", [this](auto& req, auto& res) {
        handle_delete_device(req, res);
    });
    server_.Post("/_matrix/client/v3/delete_devices", [this](auto& req, auto& res) {
        handle_delete_devices(req, res);
    });

    // ── User directory ───────────────────────────────────────────────────────
    server_.Post("/_matrix/client/v3/user_directory/search", [this](auto& req, auto& res) {
        handle_user_directory_search(req, res);
    });

    // ── Push rules ───────────────────────────────────────────────────────────
    server_.Get("/_matrix/client/v3/pushrules/", [this](auto& req, auto& res) {
        handle_get_pushrules(req, res);
    });
    server_.Put("/_matrix/client/v3/pushrules/:scope/:kind/:ruleId",
                [this](auto& req, auto& res) { handle_put_pushrule(req, res); });
    server_.Delete("/_matrix/client/v3/pushrules/:scope/:kind/:ruleId",
                   [this](auto& req, auto& res) { handle_delete_pushrule(req, res); });

    // ── Media ────────────────────────────────────────────────────────────────
    server_.Post("/_matrix/media/v3/upload", [this](auto& req, auto& res) {
        handle_media_upload(req, res);
    });
    server_.Get("/_matrix/media/v3/download/:serverName/:mediaId",
                [this](auto& req, auto& res) { handle_media_download(req, res); });
    server_.Get("/_matrix/media/v3/thumbnail/:serverName/:mediaId",
                [this](auto& req, auto& res) { handle_media_thumbnail(req, res); });
    // Legacy r0 aliases
    server_.Post("/_matrix/media/r0/upload", [this](auto& req, auto& res) {
        handle_media_upload(req, res);
    });
    server_.Get("/_matrix/media/r0/download/:serverName/:mediaId",
                [this](auto& req, auto& res) { handle_media_download(req, res); });
    server_.Get("/_matrix/media/r0/thumbnail/:serverName/:mediaId",
                [this](auto& req, auto& res) { handle_media_thumbnail(req, res); });

    // ── Federation ───────────────────────────────────────────────────────────
    // Phase 1.3
    server_.Get("/_matrix/federation/v1/version", [this](auto& req, auto& res) {
        handle_federation_version(req, res);
    });
    server_.Get("/_matrix/key/v2/server", [this](auto& req, auto& res) {
        handle_server_key(req, res);
    });
    server_.Get("/_matrix/key/v2/query", [this](auto& req, auto& res) {
        handle_key_query(req, res);
    });
    server_.Put("/_matrix/federation/v1/send/:txnId", [this](auto& req, auto& res) {
        handle_federation_send(req, res);
    });
    server_.Get("/_matrix/federation/v1/make_join/:roomId/:userId",
                [this](auto& req, auto& res) { handle_make_join(req, res); });
    server_.Put("/_matrix/federation/v1/send_join/:roomId/:userId",
                [this](auto& req, auto& res) { handle_send_join(req, res); });
    server_.Put("/_matrix/federation/v2/send_join/:roomId/:userId",
                [this](auto& req, auto& res) { handle_send_join(req, res); });
    server_.Get("/_matrix/federation/v1/make_leave/:roomId/:userId",
                [this](auto& req, auto& res) { handle_make_leave(req, res); });
    server_.Put("/_matrix/federation/v1/send_leave/:roomId/:userId",
                [this](auto& req, auto& res) { handle_send_leave(req, res); });
    server_.Get("/_matrix/federation/v1/event/:eventId", [this](auto& req, auto& res) {
        handle_federation_event(req, res);
    });
    server_.Get("/_matrix/federation/v1/state/:roomId", [this](auto& req, auto& res) {
        handle_federation_state(req, res);
    });
    server_.Get("/_matrix/federation/v1/state_ids/:roomId", [this](auto& req, auto& res) {
        handle_federation_state_ids(req, res);
    });
    server_.Get("/_matrix/federation/v1/backfill/:roomId", [this](auto& req, auto& res) {
        handle_federation_backfill(req, res);
    });
    server_.Get("/_matrix/federation/v1/query/:queryType", [this](auto& req, auto& res) {
        handle_federation_query(req, res);
    });
}

// ── Helpers ─────────────────────────────────────────────────────────────────

std::string MatrixServer::extract_bearer_token(const httplib::Request& req) const {
    std::string auth = req.get_header_value("Authorization");
    if (auth.find("Bearer ") == 0) return auth.substr(7);
    if (req.has_param("access_token")) return req.get_param_value("access_token");
    return "";
}

std::string MatrixServer::require_auth(const httplib::Request& req, httplib::Response& res) {
    std::string token = extract_bearer_token(req);
    if (token.empty()) {
        send_error(res, 401, "M_MISSING_TOKEN", "Missing access token");
        return "";
    }
    if (!user_manager_.validate_token(token)) {
        send_error(res, 401, "M_UNKNOWN_TOKEN", "Access token not recognized");
        return "";
    }
    return user_manager_.get_token_info(token).username;
}

void MatrixServer::send_error(httplib::Response& res, int status,
                              const std::string& errcode, const std::string& error) {
    json j = {{"errcode", errcode}, {"error", error}};
    res.status = status;
    res.set_content(j.dump(), "application/json");
}

json MatrixServer::event_to_client_json(const Event& e) const {
    static const std::unordered_set<std::string> state_types = {
        "m.room.create", "m.room.member", "m.room.power_levels",
        "m.room.join_rules", "m.room.history_visibility", "m.room.guest_access",
        "m.room.name", "m.room.topic", "m.room.canonical_alias", "m.room.avatar"
    };
    json j = {
        {"event_id", e.event_id},
        {"type", e.type},
        {"sender", e.sender},
        {"room_id", e.room_id},
        {"origin_server_ts", e.origin_server_ts},
        {"content", e.content}
    };
    if (!e.state_key.empty() || state_types.count(e.type)) {
        j["state_key"] = e.state_key;
    }
    return j;
}

// ── Discovery ────────────────────────────────────────────────────────────────

void MatrixServer::handle_well_known(const httplib::Request&, httplib::Response& res) {
    json j = {{"m.homeserver", {{"base_url", config_.homeserver_url}}}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

// Phase 1.3
void MatrixServer::handle_versions(const httplib::Request&, httplib::Response& res) {
    json j = {
        {"versions", {"v1.1","v1.2","v1.3","v1.4","v1.5",
                      "v1.6","v1.7","v1.8","v1.9","v1.10","v1.11"}},
        {"unstable_features", json::object()}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

// Phase 1.3
void MatrixServer::handle_capabilities(const httplib::Request&, httplib::Response& res) {
    json j = {
        {"capabilities", {
            {"m.change_password", {{"enabled", true}}},
            {"m.room_versions", {
                {"default", "10"},
                {"available", {{"10", "stable"}}}
            }}
        }}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

// ── Auth ─────────────────────────────────────────────────────────────────────

void MatrixServer::handle_get_login_types(const httplib::Request&, httplib::Response& res) {
    json j = {{"flows", {{{"type", "m.login.password"}}}}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_login(const httplib::Request& req, httplib::Response& res) {
    try {
        json body = json::parse(req.body);
        std::string type = body.value("type", "");
        if (type == "m.login.password") {
            handle_password_login(body, res);
        } else {
            send_error(res, 400, "M_UNKNOWN", "Unsupported login type: " + type);
        }
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Request body is not valid JSON");
    }
}

void MatrixServer::handle_password_login(const json& body, httplib::Response& res) {
    std::string username;
    if (body.contains("identifier") && body["identifier"].contains("type")) {
        if (body["identifier"]["type"] == "m.id.user" && body["identifier"].contains("user")) {
            username = body["identifier"]["user"].get<std::string>();
        }
    }
    if (username.empty() && body.contains("user")) {
        username = body["user"].get<std::string>();
    }
    username = Utils::extract_username(username);
    std::string password = body.value("password", "");

    if (username.empty() || password.empty()) {
        send_error(res, 400, "M_MISSING_PARAM", "username and password are required");
        return;
    }
    if (!user_manager_.verify_credentials(username, password)) {
        send_error(res, 403, "M_FORBIDDEN", "Invalid username or password");
        return;
    }
    std::string device_id = body.value("device_id", Utils::generate_device_id());
    std::string token = user_manager_.create_session(username, device_id);
    json j = {
        {"user_id", "@" + username + ":" + config_.server_name},
        {"access_token", token},
        {"device_id", device_id}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_register(const httplib::Request& req, httplib::Response& res) {
    try {
        json body = json::parse(req.body);
        std::string session_id;
        if (body.contains("auth") && body["auth"].contains("session")) {
            session_id = body["auth"]["session"].get<std::string>();
        }
        std::string username = body.value("username", "");
        std::string password = body.value("password", "");
        if (session_id.empty()) {
            session_id = auth_manager_.create_session(username, password);
        } else {
            auth_manager_.update_session_credentials(session_id, username, password);
        }
        if (body.contains("auth")) {
            process_auth_stage(session_id, body["auth"]);
        }
        if (auth_manager_.is_flow_complete(session_id)) {
            complete_registration(session_id, res);
        } else {
            json flow_res = auth_manager_.get_flows_response(session_id);
            res.status = 401;
            res.set_content(flow_res.dump(), "application/json");
        }
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Request body is not valid JSON");
    }
}

void MatrixServer::process_auth_stage(const std::string& session_id, const json& auth) {
    std::string auth_type = auth.value("type", "");
    if (auth_type == "m.login.dummy") {
        auth_manager_.complete_stage(session_id, "m.login.dummy");
    } else if (auth_type == "m.login.recaptcha" && auth.contains("response")) {
        if (Utils::validate_captcha(auth["response"].get<std::string>())) {
            auth_manager_.complete_stage(session_id, "m.login.recaptcha");
        }
    } else if (auth_type == "m.login.terms") {
        auth_manager_.complete_stage(session_id, "m.login.terms");
    }
}

void MatrixServer::complete_registration(const std::string& session_id, httplib::Response& res) {
    auto& session = auth_manager_.get_session(session_id);
    std::string username = session.username;
    std::string password = session.password;
    if (username.empty()) {
        send_error(res, 400, "M_MISSING_PARAM", "username is required");
        auth_manager_.destroy_session(session_id);
        return;
    }
    if (!user_manager_.create_user(username, password)) {
        send_error(res, 400, "M_USER_IN_USE", "Username already taken");
        auth_manager_.destroy_session(session_id);
        return;
    }
    std::string device_id = Utils::generate_device_id();
    std::string token = user_manager_.create_session(username, device_id);
    auth_manager_.destroy_session(session_id);
    json j = {
        {"user_id", "@" + username + ":" + config_.server_name},
        {"access_token", token},
        {"device_id", device_id}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_logout(const httplib::Request& req, httplib::Response& res) {
    std::string token = extract_bearer_token(req);
    if (token.empty()) {
        send_error(res, 401, "M_MISSING_TOKEN", "Missing access token");
        return;
    }
    user_manager_.revoke_token(token);
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_logout_all(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    user_manager_.revoke_all_tokens(username);
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_whoami(const httplib::Request& req, httplib::Response& res) {
    std::string token = extract_bearer_token(req);
    if (token.empty() || !user_manager_.validate_token(token)) {
        send_error(res, 401, "M_UNKNOWN_TOKEN", "Access token not recognized");
        return;
    }
    TokenInfo ti = user_manager_.get_token_info(token);
    json j = {
        {"user_id", "@" + ti.username + ":" + config_.server_name},
        {"device_id", ti.device_id}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

// ── Rooms ────────────────────────────────────────────────────────────────────

void MatrixServer::handle_create_room(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json body = req.body.empty() ? json::object() : json::parse(req.body);
        std::string room_id = room_manager_.create_room(user_id, body);
        // Notify sync about all initial state events
        auto events = room_manager_.get_room_state(room_id);
        for (const auto& e : events) sync_manager_.notify_event(room_id, e);
        res.status = 200;
        res.set_content(json{{"room_id", room_id}}.dump(), "application/json");
    } catch (const std::exception& e) {
        send_error(res, 500, "M_UNKNOWN", e.what());
    }
}

void MatrixServer::handle_join_room(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    if (!room_manager_.room_exists(room_id)) {
        send_error(res, 404, "M_NOT_FOUND", "Room not found");
        return;
    }
    room_manager_.add_member(room_id, user_id, "join");
    std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id,
                                               {{"membership", "join"}}, user_id);
    sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
    res.status = 200;
    res.set_content(json{{"room_id", room_id}}.dump(), "application/json");
}

void MatrixServer::handle_join_by_alias(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string id_or_alias = req.path_params.at("roomIdOrAlias");
    std::string room_id = id_or_alias;
    if (!id_or_alias.empty() && id_or_alias[0] == '#') {
        room_id = room_manager_.resolve_alias(id_or_alias);
        if (room_id.empty()) { send_error(res, 404, "M_NOT_FOUND", "Alias not found"); return; }
    }
    if (!room_manager_.room_exists(room_id)) {
        send_error(res, 404, "M_NOT_FOUND", "Room not found");
        return;
    }
    room_manager_.add_member(room_id, user_id, "join");
    std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id,
                                               {{"membership", "join"}}, user_id);
    sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
    res.status = 200;
    res.set_content(json{{"room_id", room_id}}.dump(), "application/json");
}

void MatrixServer::handle_leave_room(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    room_manager_.remove_member(room_id, user_id);
    std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id,
                                               {{"membership", "leave"}}, user_id);
    sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_forget_room(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_invite(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    try {
        json body = json::parse(req.body);
        std::string invitee = body.value("user_id", "");
        if (invitee.empty()) { send_error(res, 400, "M_MISSING_PARAM", "user_id required"); return; }
        int power = room_manager_.get_user_power_level(room_id, user_id);
        if (power < room_manager_.get_required_power_level(room_id, "invite")) {
            send_error(res, 403, "M_FORBIDDEN", "Insufficient power level"); return;
        }
        room_manager_.add_member(room_id, invitee, "invite");
        std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id,
                                                   {{"membership", "invite"}}, invitee);
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_kick(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    try {
        json body = json::parse(req.body);
        std::string target = body.value("user_id", "");
        if (target.empty()) { send_error(res, 400, "M_MISSING_PARAM", "user_id required"); return; }
        if (room_manager_.get_user_power_level(room_id, user_id) <
            room_manager_.get_required_power_level(room_id, "kick")) {
            send_error(res, 403, "M_FORBIDDEN", "Insufficient power level"); return;
        }
        room_manager_.remove_member(room_id, target);
        json content = {{"membership", "leave"}};
        std::string reason = body.value("reason", "");
        if (!reason.empty()) content["reason"] = reason;
        std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id, content, target);
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_ban(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    try {
        json body = json::parse(req.body);
        std::string target = body.value("user_id", "");
        if (target.empty()) { send_error(res, 400, "M_MISSING_PARAM", "user_id required"); return; }
        if (room_manager_.get_user_power_level(room_id, user_id) <
            room_manager_.get_required_power_level(room_id, "ban")) {
            send_error(res, 403, "M_FORBIDDEN", "Insufficient power level"); return;
        }
        room_manager_.add_member(room_id, target, "ban");
        json content = {{"membership", "ban"}};
        std::string reason = body.value("reason", "");
        if (!reason.empty()) content["reason"] = reason;
        std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id, content, target);
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_unban(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    try {
        json body = json::parse(req.body);
        std::string target = body.value("user_id", "");
        if (target.empty()) { send_error(res, 400, "M_MISSING_PARAM", "user_id required"); return; }
        if (room_manager_.get_user_power_level(room_id, user_id) <
            room_manager_.get_required_power_level(room_id, "ban")) {
            send_error(res, 403, "M_FORBIDDEN", "Insufficient power level"); return;
        }
        room_manager_.remove_member(room_id, target);
        std::string eid = room_manager_.add_event(room_id, "m.room.member", user_id,
                                                   {{"membership", "leave"}}, target);
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_send_event(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    std::string event_type = req.path_params.at("eventType");
    if (!room_manager_.is_member(room_id, user_id)) {
        send_error(res, 403, "M_FORBIDDEN", "Not a member of this room"); return;
    }
    try {
        json content = json::parse(req.body);
        std::string eid = room_manager_.add_event(room_id, event_type, user_id, content, "");
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content(json{{"event_id", eid}}.dump(), "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_send_state_event(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    std::string event_type = req.path_params.at("eventType");
    std::string state_key = req.path_params.count("stateKey") ? req.path_params.at("stateKey") : "";
    if (!room_manager_.is_member(room_id, user_id)) {
        send_error(res, 403, "M_FORBIDDEN", "Not a member of this room"); return;
    }
    if (room_manager_.get_user_power_level(room_id, user_id) <
        room_manager_.get_required_power_level(room_id, "state")) {
        send_error(res, 403, "M_FORBIDDEN", "Insufficient power level"); return;
    }
    try {
        json content = json::parse(req.body);
        std::string eid = room_manager_.add_event(room_id, event_type, user_id, content, state_key);
        sync_manager_.notify_event(room_id, room_manager_.get_event(eid));
        res.status = 200;
        res.set_content(json{{"event_id", eid}}.dump(), "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_messages(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    int limit = 50;
    if (req.has_param("limit")) { try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {} }
    int64_t since = 0;
    if (req.has_param("from")) {
        std::string from = req.get_param_value("from");
        if (from.size() > 1 && from[0] == 't') { try { since = std::stoll(from.substr(1)); } catch (...) {} }
    }
    auto events = room_manager_.get_timeline(room_id, since, limit);
    json chunk = json::array();
    for (const auto& e : events) chunk.push_back(event_to_client_json(e));
    int64_t end_tok = events.empty() ? since : events.back().depth;
    json j = {
        {"start", "t" + std::to_string(since)},
        {"end", "t" + std::to_string(end_tok)},
        {"chunk", chunk}
    };
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_get_event(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string eid = req.path_params.at("eventId");
    Event e = room_manager_.get_event(eid);
    if (e.event_id.empty()) { send_error(res, 404, "M_NOT_FOUND", "Event not found"); return; }
    res.status = 200;
    res.set_content(event_to_client_json(e).dump(), "application/json");
}

void MatrixServer::handle_get_state(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    auto events = room_manager_.get_room_state(room_id);
    json arr = json::array();
    for (const auto& e : events) arr.push_back(event_to_client_json(e));
    res.status = 200;
    res.set_content(arr.dump(), "application/json");
}

void MatrixServer::handle_get_state_event(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    std::string event_type = req.path_params.at("eventType");
    std::string state_key = req.path_params.count("stateKey") ? req.path_params.at("stateKey") : "";
    json content = room_manager_.get_state_event(room_id, event_type, state_key);
    if (content.is_null()) { send_error(res, 404, "M_NOT_FOUND", "State event not found"); return; }
    res.status = 200;
    res.set_content(content.dump(), "application/json");
}

void MatrixServer::handle_get_members(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    std::string membership = req.has_param("membership") ? req.get_param_value("membership") : "join";
    auto members = room_manager_.get_members(room_id, membership);
    json chunk = json::array();
    for (const auto& uid : members) {
        chunk.push_back({
            {"type", "m.room.member"},
            {"state_key", uid},
            {"content", {{"membership", membership}}},
            {"room_id", room_id},
            {"sender", uid}
        });
    }
    res.status = 200;
    res.set_content(json{{"chunk", chunk}}.dump(), "application/json");
}

void MatrixServer::handle_get_joined_members(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    auto members = room_manager_.get_members(room_id, "join");
    json joined = json::object();
    for (const auto& uid : members) {
        Profile p = user_manager_.get_profile(uid);
        joined[uid] = {{"display_name", p.displayname}, {"avatar_url", p.avatar_url}};
    }
    res.status = 200;
    res.set_content(json{{"joined", joined}}.dump(), "application/json");
}

void MatrixServer::handle_get_joined_rooms(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    auto rooms = room_manager_.get_user_rooms(user_id);
    res.status = 200;
    res.set_content(json{{"joined_rooms", rooms}}.dump(), "application/json");
}

void MatrixServer::handle_public_rooms_get(const httplib::Request& req, httplib::Response& res) {
    int limit = 100;
    if (req.has_param("limit")) { try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {} }
    auto rooms = room_manager_.get_public_rooms(limit, 0);
    res.status = 200;
    res.set_content(json{{"chunk", rooms}, {"total_room_count_estimate", (int)rooms.size()}}.dump(),
                    "application/json");
}

void MatrixServer::handle_public_rooms_post(const httplib::Request& req, httplib::Response& res) {
    int limit = 100;
    try { json body = json::parse(req.body); limit = body.value("limit", 100); } catch (...) {}
    auto rooms = room_manager_.get_public_rooms(limit, 0);
    res.status = 200;
    res.set_content(json{{"chunk", rooms}, {"total_room_count_estimate", (int)rooms.size()}}.dump(),
                    "application/json");
}

// ── Room aliases ─────────────────────────────────────────────────────────────

void MatrixServer::handle_put_alias(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string alias = req.path_params.at("roomAlias");
    try {
        json body = json::parse(req.body);
        std::string room_id = body.value("room_id", "");
        if (room_id.empty()) { send_error(res, 400, "M_MISSING_PARAM", "room_id required"); return; }
        if (!room_manager_.set_alias(alias, room_id)) {
            send_error(res, 409, "M_UNKNOWN", "Alias already exists"); return;
        }
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_alias(const httplib::Request& req, httplib::Response& res) {
    std::string alias = req.path_params.at("roomAlias");
    std::string room_id = room_manager_.resolve_alias(alias);
    if (room_id.empty()) { send_error(res, 404, "M_NOT_FOUND", "Alias not found"); return; }
    json j = {{"room_id", room_id}, {"servers", {config_.server_name}}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_delete_alias(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string alias = req.path_params.at("roomAlias");
    if (!room_manager_.delete_alias(alias)) {
        send_error(res, 404, "M_NOT_FOUND", "Alias not found"); return;
    }
    res.status = 200;
    res.set_content("{}", "application/json");
}

// ── Sync ─────────────────────────────────────────────────────────────────────

void MatrixServer::handle_sync(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    int64_t since_pos = 0;
    if (req.has_param("since")) {
        std::string since = req.get_param_value("since");
        if (since.size() > 1 && since[0] == 's') {
            try { since_pos = std::stoll(since.substr(1)); } catch (...) {}
        }
    }
    int timeout_ms = 0;
    if (req.has_param("timeout")) {
        try { timeout_ms = std::stoi(req.get_param_value("timeout")); } catch (...) {}
    }
    if (timeout_ms > 30000) timeout_ms = 30000;
    auto joined_rooms = room_manager_.get_user_rooms(user_id);
    json response = sync_manager_.wait_for_sync(
        user_id, since_pos, timeout_ms, joined_rooms,
        [this](const std::string& room_id, int64_t since) {
            return room_manager_.get_events_since(room_id, since);
        },
        [this](const std::string& room_id) {
            return room_manager_.get_room_state(room_id);
        });
    res.status = 200;
    res.set_content(response.dump(), "application/json");
}

// ── Filters ──────────────────────────────────────────────────────────────────

void MatrixServer::handle_put_filter(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json filter = json::parse(req.body);
        std::string filter_id = Utils::generate_random_string(8);
        db_.execute("INSERT OR REPLACE INTO filters(filter_id, user_id, filter) VALUES(?,?,?)",
                    {filter_id, user_id, filter.dump()});
        res.status = 200;
        res.set_content(json{{"filter_id", filter_id}}.dump(), "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_filter(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string filter_id = req.path_params.at("filterId");
    std::string raw = db_.get_text("SELECT filter FROM filters WHERE filter_id=?", {filter_id});
    if (raw.empty()) { send_error(res, 404, "M_NOT_FOUND", "Filter not found"); return; }
    res.status = 200;
    res.set_content(raw, "application/json");
}

// ── Profile ───────────────────────────────────────────────────────────────────

void MatrixServer::handle_get_profile(const httplib::Request& req, httplib::Response& res) {
    std::string user_id = req.path_params.at("userId");
    Profile p = user_manager_.get_profile(user_id);
    res.status = 200;
    res.set_content(json{{"displayname", p.displayname}, {"avatar_url", p.avatar_url}}.dump(),
                    "application/json");
}

void MatrixServer::handle_get_displayname(const httplib::Request& req, httplib::Response& res) {
    std::string user_id = req.path_params.at("userId");
    Profile p = user_manager_.get_profile(user_id);
    res.status = 200;
    res.set_content(json{{"displayname", p.displayname}}.dump(), "application/json");
}

void MatrixServer::handle_put_displayname(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json body = json::parse(req.body);
        user_manager_.set_displayname(user_id, body.value("displayname", ""));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_avatar_url(const httplib::Request& req, httplib::Response& res) {
    std::string user_id = req.path_params.at("userId");
    Profile p = user_manager_.get_profile(user_id);
    res.status = 200;
    res.set_content(json{{"avatar_url", p.avatar_url}}.dump(), "application/json");
}

void MatrixServer::handle_put_avatar_url(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json body = json::parse(req.body);
        user_manager_.set_avatar_url(user_id, body.value("avatar_url", ""));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

// ── Presence ──────────────────────────────────────────────────────────────────

void MatrixServer::handle_get_presence(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = req.path_params.at("userId");
    json j = user_manager_.get_presence(user_id);
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_put_presence(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json body = json::parse(req.body);
        std::string presence = body.value("presence", "online");
        std::string status_msg = body.value("status_msg", "");
        user_manager_.set_presence(user_id, presence, status_msg);
        sync_manager_.notify_presence(user_id, presence, status_msg);
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

// ── Typing ────────────────────────────────────────────────────────────────────

void MatrixServer::handle_put_typing(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    std::string user_id = "@" + username + ":" + config_.server_name;
    try {
        json body = json::parse(req.body);
        bool typing = body.value("typing", false);
        json eph = {
            {"type", "m.typing"},
            {"content", {{"user_ids", typing ? json::array({user_id}) : json::array()}}}
        };
        sync_manager_.notify_ephemeral(room_id, eph);
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

// ── Read receipts ─────────────────────────────────────────────────────────────

void MatrixServer::handle_post_receipt(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string room_id = req.path_params.at("roomId");
    std::string event_id = req.path_params.at("eventId");
    std::string user_id = "@" + username + ":" + config_.server_name;
    int64_t ts = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    db_.execute("INSERT OR REPLACE INTO read_receipts(room_id, user_id, event_id, ts) VALUES(?,?,?,?)",
                {room_id, user_id, event_id, std::to_string(ts)});
    json eph = {
        {"type", "m.receipt"},
        {"content", {{event_id, {{"m.read", {{user_id, {{"ts", ts}}}}}}}}}
    };
    sync_manager_.notify_ephemeral(room_id, eph);
    res.status = 200;
    res.set_content("{}", "application/json");
}

// ── Account data ──────────────────────────────────────────────────────────────

void MatrixServer::handle_put_account_data(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string type = req.path_params.at("type");
    try {
        json content = json::parse(req.body);
        user_manager_.set_account_data(user_id, type, content);
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_account_data(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string type = req.path_params.at("type");
    json content = user_manager_.get_account_data(user_id, type);
    res.status = 200;
    res.set_content(content.dump(), "application/json");
}

void MatrixServer::handle_put_room_account_data(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    std::string type = req.path_params.at("type");
    try {
        json content = json::parse(req.body);
        user_manager_.set_account_data(user_id, type, content, room_id);
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_get_room_account_data(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string room_id = req.path_params.at("roomId");
    std::string type = req.path_params.at("type");
    json content = user_manager_.get_account_data(user_id, type, room_id);
    res.status = 200;
    res.set_content(content.dump(), "application/json");
}

// ── Devices ───────────────────────────────────────────────────────────────────

void MatrixServer::handle_get_devices(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    auto devices = user_manager_.get_devices(username);
    json arr = json::array();
    for (const auto& d : devices) {
        arr.push_back({{"device_id", d.device_id}, {"display_name", d.display_name}});
    }
    res.status = 200;
    res.set_content(json{{"devices", arr}}.dump(), "application/json");
}

void MatrixServer::handle_get_device(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string device_id = req.path_params.at("deviceId");
    Device d = user_manager_.get_device(username, device_id);
    res.status = 200;
    res.set_content(json{{"device_id", d.device_id}, {"display_name", d.display_name}}.dump(),
                    "application/json");
}

void MatrixServer::handle_put_device(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string device_id = req.path_params.at("deviceId");
    try {
        json body = json::parse(req.body);
        user_manager_.update_device(username, device_id, body.value("display_name", ""));
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_delete_device(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    user_manager_.delete_device(username, req.path_params.at("deviceId"));
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_delete_devices(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    try {
        json body = json::parse(req.body);
        if (body.contains("devices") && body["devices"].is_array()) {
            for (const auto& did : body["devices"]) {
                user_manager_.delete_device(username, did.get<std::string>());
            }
        }
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

// ── User directory ────────────────────────────────────────────────────────────

void MatrixServer::handle_user_directory_search(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    try {
        json body = json::parse(req.body);
        std::string term = body.value("search_term", "");
        int limit = body.value("limit", 10);
        auto results = user_manager_.search_users(term, limit);
        res.status = 200;
        res.set_content(json{{"results", results}, {"limited", false}}.dump(), "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

// ── Push rules ────────────────────────────────────────────────────────────────

void MatrixServer::handle_get_pushrules(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    json j = {{"global", {
        {"override", json::array()}, {"content", json::array()},
        {"room", json::array()}, {"sender", json::array()}, {"underride", json::array()}
    }}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_put_pushrule(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string rule_id = req.path_params.at("ruleId");
    try {
        json rule = json::parse(req.body);
        db_.execute("INSERT OR REPLACE INTO push_rules(user_id, rule_id, rule_json) VALUES(?,?,?)",
                    {user_id, rule_id, rule.dump()});
        res.status = 200;
        res.set_content("{}", "application/json");
    } catch (const json::exception&) {
        send_error(res, 400, "M_NOT_JSON", "Not valid JSON");
    }
}

void MatrixServer::handle_delete_pushrule(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    db_.execute("DELETE FROM push_rules WHERE user_id=? AND rule_id=?",
                {user_id, req.path_params.at("ruleId")});
    res.status = 200;
    res.set_content("{}", "application/json");
}

// ── Media ─────────────────────────────────────────────────────────────────────

void MatrixServer::handle_media_upload(const httplib::Request& req, httplib::Response& res) {
    std::string username = require_auth(req, res);
    if (username.empty()) return;
    std::string user_id = "@" + username + ":" + config_.server_name;
    std::string content_type = req.get_header_value("Content-Type");
    if (content_type.empty()) content_type = "application/octet-stream";
    std::string filename = req.has_param("filename") ? req.get_param_value("filename") : "";
    try {
        std::string mxc = media_manager_.upload(req.body, content_type, filename, user_id);
        res.status = 200;
        res.set_content(json{{"content_uri", mxc}}.dump(), "application/json");
    } catch (const std::exception& e) {
        send_error(res, 500, "M_UNKNOWN", e.what());
    }
}

void MatrixServer::handle_media_download(const httplib::Request& req, httplib::Response& res) {
    std::string server_name = req.path_params.at("serverName");
    std::string media_id = req.path_params.at("mediaId");
    auto [data, ct] = media_manager_.download(server_name, media_id);
    if (data.empty()) { send_error(res, 404, "M_NOT_FOUND", "Media not found"); return; }
    res.status = 200;
    res.set_content(data, ct);
}

void MatrixServer::handle_media_thumbnail(const httplib::Request& req, httplib::Response& res) {
    handle_media_download(req, res);
}

// ── Federation ────────────────────────────────────────────────────────────────

// Phase 1.3
void MatrixServer::handle_federation_version(const httplib::Request&, httplib::Response& res) {
    json j = {{"server", {{"name", "Slime"}, {"version", "1.0.0"}}}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_server_key(const httplib::Request&, httplib::Response& res) {
    json j = key_manager_.server_key_json();
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_key_query(const httplib::Request&, httplib::Response& res) {
    json j = {{"server_keys", {key_manager_.server_key_json()}}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_federation_send(const httplib::Request&, httplib::Response& res) {
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_make_join(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    std::string user_id = req.path_params.at("userId");
    json event = {
        {"type", "m.room.member"}, {"room_id", room_id},
        {"sender", user_id}, {"state_key", user_id},
        {"content", {{"membership", "join"}}},
        {"origin", config_.server_name}
    };
    res.status = 200;
    res.set_content(json{{"room_version", "10"}, {"event", event}}.dump(), "application/json");
}

void MatrixServer::handle_send_join(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    auto state = room_manager_.get_room_state(room_id);
    json state_arr = json::array();
    for (const auto& e : state) state_arr.push_back(event_to_client_json(e));
    json j = {{"origin", config_.server_name}, {"state", state_arr}, {"auth_chain", json::array()}};
    res.status = 200;
    res.set_content(j.dump(), "application/json");
}

void MatrixServer::handle_make_leave(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    std::string user_id = req.path_params.at("userId");
    json event = {
        {"type", "m.room.member"}, {"room_id", room_id},
        {"sender", user_id}, {"state_key", user_id},
        {"content", {{"membership", "leave"}}},
        {"origin", config_.server_name}
    };
    res.status = 200;
    res.set_content(json{{"room_version", "10"}, {"event", event}}.dump(), "application/json");
}

void MatrixServer::handle_send_leave(const httplib::Request&, httplib::Response& res) {
    res.status = 200;
    res.set_content("{}", "application/json");
}

void MatrixServer::handle_federation_event(const httplib::Request& req, httplib::Response& res) {
    std::string eid = req.path_params.at("eventId");
    Event e = room_manager_.get_event(eid);
    if (e.event_id.empty()) { send_error(res, 404, "M_NOT_FOUND", "Event not found"); return; }
    res.status = 200;
    res.set_content(json{{"pdus", {event_to_client_json(e)}}}.dump(), "application/json");
}

void MatrixServer::handle_federation_state(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    auto state = room_manager_.get_room_state(room_id);
    json state_arr = json::array();
    for (const auto& e : state) state_arr.push_back(event_to_client_json(e));
    res.status = 200;
    res.set_content(json{{"pdus", state_arr}, {"auth_chain", json::array()}}.dump(), "application/json");
}

void MatrixServer::handle_federation_state_ids(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    auto state = room_manager_.get_room_state(room_id);
    json ids = json::array();
    for (const auto& e : state) ids.push_back(e.event_id);
    res.status = 200;
    res.set_content(json{{"pdu_ids", ids}, {"auth_chain_ids", json::array()}}.dump(), "application/json");
}

void MatrixServer::handle_federation_backfill(const httplib::Request& req, httplib::Response& res) {
    std::string room_id = req.path_params.at("roomId");
    int limit = 10;
    if (req.has_param("limit")) { try { limit = std::stoi(req.get_param_value("limit")); } catch (...) {} }
    auto events = room_manager_.get_timeline(room_id, 0, limit);
    json pdus = json::array();
    for (const auto& e : events) pdus.push_back(event_to_client_json(e));
    res.status = 200;
    res.set_content(json{{"origin", config_.server_name}, {"pdus", pdus}}.dump(), "application/json");
}

void MatrixServer::handle_federation_query(const httplib::Request& req, httplib::Response& res) {
    std::string query_type = req.path_params.at("queryType");
    if (query_type == "directory") {
        std::string alias = req.get_param_value("room_alias");
        std::string room_id = room_manager_.resolve_alias(alias);
        if (room_id.empty()) { send_error(res, 404, "M_NOT_FOUND", "Alias not found"); return; }
        res.status = 200;
        res.set_content(json{{"room_id", room_id}, {"servers", {config_.server_name}}}.dump(),
                        "application/json");
    } else if (query_type == "profile") {
        std::string user_id = req.get_param_value("user_id");
        Profile p = user_manager_.get_profile(user_id);
        res.status = 200;
        res.set_content(json{{"displayname", p.displayname}, {"avatar_url", p.avatar_url}}.dump(),
                        "application/json");
    } else {
        send_error(res, 400, "M_UNRECOGNIZED", "Unknown query type: " + query_type);
    }
}
