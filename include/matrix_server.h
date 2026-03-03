#pragma once

#include <string>
#include <memory>
#include "config.h"
#include "database_manager.h"
#include "user_manager.h"
#include "auth_manager.h"
#include "room_manager.h"
#include "sync_manager.h"
#include "media_manager.h"
#include "key_manager.h"
#include "federation_manager.h"
#include "httplib.h"
#include "json.h"

using json = nlohmann::json;

class MatrixServer {
public:
    explicit MatrixServer(const Config& config);
    void start();

private:
    Config config_;
    DatabaseManager db_;
    UserManager user_manager_;
    AuthManager auth_manager_;
    RoomManager room_manager_;
    SyncManager sync_manager_;
    MediaManager media_manager_;
    KeyManager key_manager_;
    FederationManager federation_manager_;
    httplib::Server server_;

    void setup_routes();

    // ── Discovery ──────────────────────────────────────────────────────────
    void handle_well_known(const httplib::Request&, httplib::Response&);
    void handle_versions(const httplib::Request&, httplib::Response&);
    void handle_capabilities(const httplib::Request&, httplib::Response&);

    // ── Auth ───────────────────────────────────────────────────────────────
    void handle_get_login_types(const httplib::Request&, httplib::Response&);
    void handle_login(const httplib::Request&, httplib::Response&);
    void handle_password_login(const json& body, httplib::Response&);
    void handle_register(const httplib::Request&, httplib::Response&);
    void process_auth_stage(const std::string& session_id, const json& auth);
    void complete_registration(const std::string& session_id, httplib::Response&);
    void handle_logout(const httplib::Request&, httplib::Response&);
    void handle_logout_all(const httplib::Request&, httplib::Response&);
    void handle_whoami(const httplib::Request&, httplib::Response&);

    // ── Rooms ──────────────────────────────────────────────────────────────
    void handle_create_room(const httplib::Request&, httplib::Response&);
    void handle_join_room(const httplib::Request&, httplib::Response&);
    void handle_join_by_alias(const httplib::Request&, httplib::Response&);
    void handle_leave_room(const httplib::Request&, httplib::Response&);
    void handle_forget_room(const httplib::Request&, httplib::Response&);
    void handle_invite(const httplib::Request&, httplib::Response&);
    void handle_kick(const httplib::Request&, httplib::Response&);
    void handle_ban(const httplib::Request&, httplib::Response&);
    void handle_unban(const httplib::Request&, httplib::Response&);
    void handle_send_event(const httplib::Request&, httplib::Response&);
    void handle_send_state_event(const httplib::Request&, httplib::Response&);
    void handle_get_messages(const httplib::Request&, httplib::Response&);
    void handle_get_event(const httplib::Request&, httplib::Response&);
    void handle_get_state(const httplib::Request&, httplib::Response&);
    void handle_get_state_event(const httplib::Request&, httplib::Response&);
    void handle_get_members(const httplib::Request&, httplib::Response&);
    void handle_get_joined_members(const httplib::Request&, httplib::Response&);
    void handle_get_joined_rooms(const httplib::Request&, httplib::Response&);
    void handle_public_rooms_get(const httplib::Request&, httplib::Response&);
    void handle_public_rooms_post(const httplib::Request&, httplib::Response&);

    // ── Room aliases ───────────────────────────────────────────────────────
    void handle_put_alias(const httplib::Request&, httplib::Response&);
    void handle_get_alias(const httplib::Request&, httplib::Response&);
    void handle_delete_alias(const httplib::Request&, httplib::Response&);

    // ── Sync ───────────────────────────────────────────────────────────────
    void handle_sync(const httplib::Request&, httplib::Response&);

    // ── Filters ───────────────────────────────────────────────────────────
    void handle_put_filter(const httplib::Request&, httplib::Response&);
    void handle_get_filter(const httplib::Request&, httplib::Response&);

    // ── Profile ───────────────────────────────────────────────────────────
    void handle_get_profile(const httplib::Request&, httplib::Response&);
    void handle_get_displayname(const httplib::Request&, httplib::Response&);
    void handle_put_displayname(const httplib::Request&, httplib::Response&);
    void handle_get_avatar_url(const httplib::Request&, httplib::Response&);
    void handle_put_avatar_url(const httplib::Request&, httplib::Response&);

    // ── Presence ──────────────────────────────────────────────────────────
    void handle_get_presence(const httplib::Request&, httplib::Response&);
    void handle_put_presence(const httplib::Request&, httplib::Response&);

    // ── Typing ────────────────────────────────────────────────────────────
    void handle_put_typing(const httplib::Request&, httplib::Response&);

    // ── Read receipts ─────────────────────────────────────────────────────
    void handle_post_receipt(const httplib::Request&, httplib::Response&);

    // ── Account data ──────────────────────────────────────────────────────
    void handle_put_account_data(const httplib::Request&, httplib::Response&);
    void handle_get_account_data(const httplib::Request&, httplib::Response&);
    void handle_put_room_account_data(const httplib::Request&, httplib::Response&);
    void handle_get_room_account_data(const httplib::Request&, httplib::Response&);

    // ── Devices ───────────────────────────────────────────────────────────
    void handle_get_devices(const httplib::Request&, httplib::Response&);
    void handle_get_device(const httplib::Request&, httplib::Response&);
    void handle_put_device(const httplib::Request&, httplib::Response&);
    void handle_delete_device(const httplib::Request&, httplib::Response&);
    void handle_delete_devices(const httplib::Request&, httplib::Response&);

    // ── User directory ────────────────────────────────────────────────────
    void handle_user_directory_search(const httplib::Request&, httplib::Response&);

    // ── Push rules ────────────────────────────────────────────────────────
    void handle_get_pushrules(const httplib::Request&, httplib::Response&);
    void handle_put_pushrule(const httplib::Request&, httplib::Response&);
    void handle_delete_pushrule(const httplib::Request&, httplib::Response&);

    // ── Media ─────────────────────────────────────────────────────────────
    void handle_media_upload(const httplib::Request&, httplib::Response&);
    void handle_media_download(const httplib::Request&, httplib::Response&);
    void handle_media_thumbnail(const httplib::Request&, httplib::Response&);

    // ── Federation ────────────────────────────────────────────────────────
    void handle_federation_version(const httplib::Request&, httplib::Response&);
    void handle_server_key(const httplib::Request&, httplib::Response&);
    void handle_key_query(const httplib::Request&, httplib::Response&);
    void handle_federation_send(const httplib::Request&, httplib::Response&);
    void handle_make_join(const httplib::Request&, httplib::Response&);
    void handle_send_join(const httplib::Request&, httplib::Response&);
    void handle_make_leave(const httplib::Request&, httplib::Response&);
    void handle_send_leave(const httplib::Request&, httplib::Response&);
    void handle_federation_event(const httplib::Request&, httplib::Response&);
    void handle_federation_state(const httplib::Request&, httplib::Response&);
    void handle_federation_state_ids(const httplib::Request&, httplib::Response&);
    void handle_federation_backfill(const httplib::Request&, httplib::Response&);
    void handle_federation_query(const httplib::Request&, httplib::Response&);

    // ── Helpers ───────────────────────────────────────────────────────────
    std::string extract_bearer_token(const httplib::Request&) const;
    // Returns username if token valid, else sends 401 and returns ""
    std::string require_auth(const httplib::Request&, httplib::Response&);
    void send_error(httplib::Response&, int status,
                    const std::string& errcode, const std::string& error);
    json event_to_client_json(const Event& e) const;
};
