# Slime Matrix Server — Completion Plan

## Context
Slime currently implements only auth/session endpoints (login, register, logout, whoami, .well-known). The RoomManager class exists but has zero HTTP routes wired. There is no sync endpoint, no persistence, no CORS, no thread safety, no password hashing, and no federation. The goal is a production-worthy Matrix homeserver that:
- Works fully with Element (web and desktop)
- Federates with the broader Matrix ecosystem (matrix.org etc.)
- Persists all data via SQLite
- Is fast: thread pool, shared_mutex, prepared statements, in-memory caching

---

## Architecture Overview

```
Element Client
     │ HTTPS (nginx terminates TLS)
     ▼
Slime (HTTP :8448 client-server + :8448 federation, or split ports)
     │
     ├── MatrixServer (httplib thread pool, route dispatch)
     ├── UserManager    ─┐
     ├── RoomManager    ─┼─ SQLite WAL db via DatabaseManager
     ├── AuthManager    ─┘
     ├── SyncManager    (long-poll, event streams)
     ├── MediaManager   (local file storage)
     ├── FederationManager (outbound + inbound S-S API)
     └── KeyManager     (Ed25519 server key, signing)
```

---

## New Dependencies (add to CMakeLists.txt)
| Library | Use | How |
|---------|-----|-----|
| SQLite3 | Persistence | Embed amalgamation (`sqlite3.h` + `sqlite3.c`) |
| libsodium | Ed25519 signing + Argon2 password hash | `find_package` or FetchContent |
| OpenSSL | HTTPS in httplib (for outbound federation HTTP client calls) | `find_package` |

httplib already supports OpenSSL for its *client* (outbound calls to fetch remote keys). The server itself runs plain HTTP behind nginx.

---

## Phase 1 — Foundation (enables Element to connect at all) ✅ COMPLETE

### 1.1 Config File (`config.json` + `Config` struct)
New file: `include/config.h`, `src/config.cpp`
- Fields: `server_name` (domain), `port`, `db_path`, `media_path`, `signing_key_path`
- Parse at startup via nlohmann/json; command-line arg `--config config.json`
- `main.cpp`: accept config path, construct `MatrixServer` with config

### 1.2 CORS Middleware
In `MatrixServer::setup_routes()`, add a global `server_.set_pre_routing_handler`:
- `Access-Control-Allow-Origin: *`
- `Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS`
- `Access-Control-Allow-Headers: Authorization, Content-Type`
- Handle `OPTIONS` preflight → 200 with empty body

### 1.3 Required Discovery Endpoints
Add to `setup_routes()`:
- `GET /_matrix/client/versions` → `{"versions": ["v1.1","v1.2","v1.3","v1.4","v1.5","v1.6","v1.7","v1.8","v1.9","v1.10","v1.11"], "unstable_features": {}}`
- `GET /_matrix/client/v3/capabilities` → `{"capabilities": {"m.change_password": {"enabled": true}, "m.room_versions": {"default": "10", "available": {"10": "stable"}}}}`
- `GET /_matrix/federation/v1/version` → `{"server": {"name": "Slime", "version": "1.0.0"}}`

### 1.4 Thread Safety
Add `std::shared_mutex` to `UserManager`, `RoomManager`, `AuthManager`:
- Reads: `std::shared_lock`
- Writes: `std::unique_lock`
Tune httplib thread pool in `MatrixServer` constructor:
```cpp
server_.new_task_queue = [] { return new httplib::ThreadPool(std::thread::hardware_concurrency() * 2); };
```

---

## Phase 2 — SQLite Persistence

### 2.1 DatabaseManager
New file: `include/database_manager.h`, `src/database_manager.cpp`
- Wraps SQLite3 with prepared statements
- WAL mode: `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`
- Schema (single file, created on first run):

```sql
CREATE TABLE users (username TEXT PRIMARY KEY, user_id TEXT, password_hash TEXT, created_at INTEGER);
CREATE TABLE devices (device_id TEXT PRIMARY KEY, username TEXT, display_name TEXT);
CREATE TABLE tokens (token TEXT PRIMARY KEY, username TEXT, device_id TEXT);
CREATE TABLE rooms (room_id TEXT PRIMARY KEY, version TEXT, creator TEXT, created_at INTEGER);
CREATE TABLE room_members (room_id TEXT, user_id TEXT, membership TEXT, PRIMARY KEY(room_id, user_id));
CREATE TABLE events (event_id TEXT PRIMARY KEY, room_id TEXT, type TEXT, sender TEXT,
    state_key TEXT, content TEXT, origin_server_ts INTEGER, depth INTEGER,
    auth_events TEXT, prev_events TEXT, signatures TEXT, hashes TEXT);
CREATE TABLE room_state (room_id TEXT, type TEXT, state_key TEXT, event_id TEXT,
    PRIMARY KEY(room_id, type, state_key));
CREATE TABLE profiles (user_id TEXT PRIMARY KEY, displayname TEXT, avatar_url TEXT);
CREATE TABLE room_aliases (alias TEXT PRIMARY KEY, room_id TEXT);
CREATE TABLE filters (filter_id TEXT PRIMARY KEY, user_id TEXT, filter TEXT);
CREATE TABLE media (media_id TEXT PRIMARY KEY, filename TEXT, content_type TEXT, size INTEGER, uploader TEXT);
CREATE TABLE push_rules (user_id TEXT, rule_id TEXT, rule_json TEXT, PRIMARY KEY(user_id, rule_id));
CREATE TABLE server_keys (key_id TEXT PRIMARY KEY, public_key TEXT, private_key TEXT, valid_until INTEGER);
-- Indices for performance
CREATE INDEX idx_events_room ON events(room_id, depth);
CREATE INDEX idx_room_members_user ON room_members(user_id);
```

### 2.2 Migrate Managers to Use SQLite
- `UserManager`: all reads/writes go through `DatabaseManager`; keep hot LRU cache (unordered_map, max 1000 entries) for token lookups
- `RoomManager`: same pattern; cache room state for active rooms
- `AuthManager`: keep in-memory (sessions are ephemeral)

### 2.3 Password Hashing
Replace plaintext storage with libsodium `crypto_pwhash_str` / `crypto_pwhash_str_verify`:
```cpp
// hash
char hash[crypto_pwhash_STRBYTES];
crypto_pwhash_str(hash, password.c_str(), password.size(),
    crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
// verify
crypto_pwhash_str_verify(stored_hash.c_str(), password.c_str(), password.size())
```

---

## Phase 3 — Client-Server API (Room Operations)

### 3.1 Room Creation
`POST /_matrix/client/v3/createRoom`
- Parse body: `name`, `topic`, `preset` (public_chat/private_chat/trusted_private_chat), `invite[]`, `initial_state[]`, `room_version`
- `RoomManager::create_room()` → generates room_id
- Inject initial state events in order: `m.room.create`, `m.room.member` (creator join), `m.room.power_levels`, `m.room.join_rules`, `m.room.history_visibility`, `m.room.guest_access`, then user-provided `initial_state`, then `m.room.name`/`m.room.topic` if set
- Return `{"room_id": "!xxx:domain"}`

### 3.2 Room Join/Leave/Invite/Kick/Ban
- `POST /_matrix/client/v3/rooms/{roomId}/join` / `POST /_matrix/client/v3/join/{roomIdOrAlias}`
- `POST /_matrix/client/v3/rooms/{roomId}/leave`
- `POST /_matrix/client/v3/rooms/{roomId}/forget`
- `POST /_matrix/client/v3/rooms/{roomId}/invite`
- `POST /_matrix/client/v3/rooms/{roomId}/kick`
- `POST /_matrix/client/v3/rooms/{roomId}/ban`
- `POST /_matrix/client/v3/rooms/{roomId}/unban`
- Each creates the appropriate `m.room.member` state event with correct membership value
- Check power levels before allowing kick/ban/invite

### 3.3 Sending Events
`PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`
- Check membership
- Build event, assign `event_id` = `$` + base64url(SHA-256(canonical_json(event)))  (Room v10 reference hash format)
- Persist and fan-out to `/sync` waiters

`PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}`
- Same as above but for state events

### 3.4 Reading Events
- `GET /_matrix/client/v3/rooms/{roomId}/messages` — paginate with `from`/`to`/`dir`/`limit`
- `GET /_matrix/client/v3/rooms/{roomId}/event/{eventId}`
- `GET /_matrix/client/v3/rooms/{roomId}/state` — full state array
- `GET /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}`
- `GET /_matrix/client/v3/rooms/{roomId}/members`
- `GET /_matrix/client/v3/rooms/{roomId}/joined_members`
- `GET /_matrix/client/v3/joined_rooms`
- `GET /_matrix/client/v3/publicRooms` (POST variant too)

### 3.5 Room Directory (Aliases)
- `PUT/GET/DELETE /_matrix/client/v3/directory/room/{roomAlias}`

---

## Phase 4 — Sync Engine

### 4.1 SyncManager
New file: `include/sync_manager.h`, `src/sync_manager.cpp`
- Maintains a global monotonic `int64_t stream_position` (incremented on every event)
- `std::map<int64_t, Event>` ordered event log in memory (also backed by SQLite)
- Long-poll: `GET /_matrix/client/v3/sync?since=s{N}&timeout=30000`
  - If new events since `N`: return immediately
  - If no events: block thread up to `timeout` ms using `std::condition_variable`
  - Notify all waiters when new event arrives
- Sync token format: `s{stream_position}` (simple integer, not batch token)
- Response format: joined rooms with `timeline.events[]`, `state.events[]`, `ephemeral.events[]`, `account_data`

### 4.2 Filter Support
- `POST /_matrix/client/v3/user/{userId}/filter`
- `GET /_matrix/client/v3/user/{userId}/filter/{filterId}`
- Apply filter when building sync response (room filter, event type filter, limit)

---

## Phase 5 — User Features

### 5.1 Profile
- `GET/PUT /_matrix/client/v3/profile/{userId}/displayname`
- `GET/PUT /_matrix/client/v3/profile/{userId}/avatar_url`
- `GET /_matrix/client/v3/profile/{userId}` (both fields)
- On displayname/avatar update, emit `m.room.member` state event update in all joined rooms

### 5.2 Presence
- `GET/PUT /_matrix/client/v3/presence/{userId}/status`
- Store in-memory per user; fan out via sync `presence` section
- Default: `offline` if not set

### 5.3 Typing Notifications
- `PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`
- Body: `{"typing": true, "timeout": 30000}`
- Broadcast via sync `ephemeral` → `m.typing` event with current typers list
- Expire typing after `timeout` ms using a background cleanup timer

### 5.4 Read Receipts
- `POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}`
- Persist `m.read` receipt; deliver via sync `ephemeral`

### 5.5 Account Data
- `PUT/GET /_matrix/client/v3/user/{userId}/account_data/{type}`
- `PUT/GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}`
- Deliver via sync `account_data`

### 5.6 Devices
- `GET /_matrix/client/v3/devices`
- `GET/PUT /_matrix/client/v3/devices/{deviceId}`
- `DELETE /_matrix/client/v3/devices/{deviceId}` (requires UIA re-auth)
- `POST /_matrix/client/v3/delete_devices`

### 5.7 User Directory Search
- `POST /_matrix/client/v3/user_directory/search` — SQLite LIKE query on username/displayname

### 5.8 Push Rules
- `GET /_matrix/client/v3/pushrules/` — return default ruleset
- `PUT/DELETE /_matrix/client/v3/pushrules/{scope}/{kind}/{ruleId}` — store custom rules

### 5.9 Logout All
- `POST /_matrix/client/v3/logout/all` — revoke all tokens for the authenticated user

---

## Phase 6 — Media Server

### 6.1 MediaManager
New file: `include/media_manager.h`, `src/media_manager.cpp`
- Upload: `POST /_matrix/media/v3/upload` — store file in `media_path/{mediaId}`, record in DB
- Download: `GET /_matrix/media/v3/download/{serverName}/{mediaId}` — serve file; if remote serverName, proxy fetch from remote (for federated avatars)
- Thumbnail: `GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}` — for now return the full image; can add libjpeg/libpng resize later
- MXC URI format: `mxc://server_name/mediaId`
- `mediaId` = random 24-char base62 string
- Supported old endpoints: `/_matrix/media/r0/...` (alias)

---

## Phase 7 — Federation

### 7.1 KeyManager
New file: `include/key_manager.h`, `src/key_manager.cpp`
- On startup: load Ed25519 keypair from `signing_key_path` (file format: `ed25519 <key_id> <base64_private_key>`), or generate+save if missing
- libsodium: `crypto_sign_ed25519_keypair()`, key_id = `ed25519:a` (first key)
- `valid_until`: now + 7 days (key rotation window)
- Endpoint: `GET /_matrix/key/v2/server` → `{"server_name": "...", "valid_until_ts": ..., "verify_keys": {"ed25519:a": {"key": "<base64_pubkey>"}}, "old_verify_keys": {}, "signatures": {...}}`
- `GET /_matrix/key/v2/query` — fetch and cache remote server keys (for signature verification)

### 7.2 Canonical JSON + Event Signing
New file: `include/matrix_crypto.h`, `src/matrix_crypto.cpp`
- `canonical_json(json)` → deterministic string (recursively sort object keys, no whitespace)
- `reference_hash(event)` → base64url(SHA-256(canonical_json(event without signatures/hashes)))
- `sign_event(event)` → add `{"signatures": {"<server_name>": {"ed25519:a": "<base64_sig>"}}}` and `{"hashes": {"sha256": "<hash>"}}`
- `verify_event(event, remote_pubkey)` → verify signature
- All events stored and sent must be signed

### 7.3 FederationManager + Outbound
New file: `include/federation_manager.h`, `src/federation_manager.cpp`
- Resolve server address: DNS SRV `_matrix._tcp.<server>` → fall back to port 8448
- Fetch remote server key via `/_matrix/key/v2/server`
- Cache remote keys in `server_keys` table with `valid_until`
- Outbound transaction: `PUT /_matrix/federation/v2/send/{txnId}` to remote servers when local events affect federated rooms
- Use httplib::Client with OpenSSL for HTTPS outbound requests
- Sign outbound requests with `Authorization: X-Matrix origin=<server_name>,key="ed25519:a",sig="<sig>"` header

### 7.4 Inbound Federation Routes
Add to `setup_routes()`:
- `GET /_matrix/federation/v1/version`
- `GET /_matrix/key/v2/server` (from 7.1)
- `GET /_matrix/key/v2/query`
- `GET /_matrix/federation/v1/query/directory`
- `GET /_matrix/federation/v1/query/profile`
- `GET /_matrix/federation/v1/event/{eventId}`
- `GET /_matrix/federation/v1/state/{roomId}` (with `event_id` param)
- `GET /_matrix/federation/v1/state_ids/{roomId}`
- `GET /_matrix/federation/v1/backfill/{roomId}`
- `PUT /_matrix/federation/v1/send/{txnId}` — receive events; verify sender signature, run auth rules, insert events, notify sync
- `GET /_matrix/federation/v1/make_join/{roomId}/{userId}`
- `PUT /_matrix/federation/v1/send_join/{roomId}/{userId}` (v1 and v2)
- `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}`
- `PUT /_matrix/federation/v1/send_leave/{roomId}/{userId}`

### 7.5 Event Authorization Rules (Room Version 10)
In `src/room_event_auth.cpp`:
- Implement the Matrix v10 auth rules: power level checks, join rules, membership state machine, ban checks
- Run for every inbound federated event before acceptance

### 7.6 State Resolution (v2 — Room Version 10)
In `src/state_resolution.cpp`:
- Implement the Matrix v2 state resolution algorithm:
  1. Separate conflicted vs unconflicted state
  2. Sort by power level + topological order
  3. Iteratively apply auth rules

---

## Phase 8 — Performance Hardening

- **Thread pool**: `hardware_concurrency() * 2` httplib workers
- **Shared mutex**: `std::shared_mutex` in UserManager, RoomManager (read-mostly paths)
- **SQLite WAL + cache**: `PRAGMA cache_size=-65536` (64MB page cache)
- **Prepared statements**: all hot queries use `sqlite3_stmt*` cached on startup
- **In-memory caches**: LRU cache (max 10k entries) for token→user and room_state lookups; invalidate on write
- **Event ID computation**: SHA-256 via OpenSSL EVP (not slow string concatenation)
- **Sync fan-out**: `std::condition_variable` per waiting connection (not polling)
- **Replace `std::vector` member lists** with `std::unordered_set<std::string>` in Room struct

---

## CMakeLists.txt Changes
```cmake
# SQLite amalgamation (place sqlite3.h + sqlite3.c in third_party/)
add_library(sqlite3 STATIC third_party/sqlite3.c)
target_compile_options(sqlite3 PRIVATE -O3)

# libsodium
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# OpenSSL (for httplib outbound TLS + SHA-256)
find_package(OpenSSL REQUIRED)
set(CPPHTTPLIB_OPENSSL_SUPPORT ON)

target_link_libraries(Slime PRIVATE
    Threads::Threads sqlite3 ${SODIUM_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto)
target_compile_definitions(Slime PRIVATE CPPHTTPLIB_OPENSSL_SUPPORT)
```

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `include/config.h` + `src/config.cpp` | Create |
| `include/database_manager.h` + `src/database_manager.cpp` | Create |
| `include/sync_manager.h` + `src/sync_manager.cpp` | Create |
| `include/media_manager.h` + `src/media_manager.cpp` | Create |
| `include/key_manager.h` + `src/key_manager.cpp` | Create |
| `include/federation_manager.h` + `src/federation_manager.cpp` | Create |
| `include/matrix_crypto.h` + `src/matrix_crypto.cpp` | Create |
| `src/room_event_auth.cpp` | Create |
| `src/state_resolution.cpp` | Create |
| `third_party/sqlite3.h` + `third_party/sqlite3.c` | Add (download amalgamation) |
| `include/matrix_server.h` | Modify (add new manager members, new handler declarations) |
| `src/matrix_server.cpp` | Major: add all missing routes + handlers |
| `include/types.h` | Modify (add Device, Profile, Receipt, Filter structs; fix Room to use unordered_set) |
| `include/room_manager.h` + `src/room_manager.cpp` | Modify (SQLite, auth rules, signing) |
| `include/user_manager.h` + `src/user_manager.cpp` | Modify (SQLite, Argon2 hashing, LRU cache) |
| `src/main.cpp` | Modify (config loading, sodium_init()) |
| `CMakeLists.txt` | Modify (add dependencies) |
| `config.json.example` | Create |

---

## Implementation Order (priority)
1. Phase 1 (foundation + CORS + versions endpoint) — Element will at least load
2. Phase 2 (SQLite + password hashing) — data survives restarts
3. Phase 3 (rooms) + Phase 4 (sync) — can send/receive messages in Element
4. Phase 5 (user features) — full Element UX
5. Phase 6 (media) — avatar/image upload works
6. Phase 7.1–7.2 (keys + signing) — prerequisite for federation
7. Phase 7.3–7.6 (full federation) — connect to matrix.org
8. Phase 8 (performance hardening) — production-ready
