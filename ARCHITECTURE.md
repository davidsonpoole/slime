# Slime — How It Works

Slime is a homeserver for the **Matrix** open messaging protocol, written in C++17. This document explains what Matrix is, what a homeserver does, and exactly how every feature in Slime is implemented.

---

## Table of Contents

1. [What is Matrix?](#1-what-is-matrix)
2. [The Homeserver's Role](#2-the-homeservers-role)
3. [Building and Running](#3-building-and-running)
4. [Configuration](#4-configuration)
5. [Architecture Overview](#5-architecture-overview)
6. [HTTP Layer — httplib](#6-http-layer--httplib)
7. [Database Layer — SQLite](#7-database-layer--sqlite)
8. [User Accounts and Authentication](#8-user-accounts-and-authentication)
9. [Rooms and Events](#9-rooms-and-events)
10. [The Sync Engine — How Messages Reach Clients](#10-the-sync-engine--how-messages-reach-clients)
11. [Profiles and Presence](#11-profiles-and-presence)
12. [Ephemeral Events — Typing and Read Receipts](#12-ephemeral-events--typing-and-read-receipts)
13. [Account Data](#13-account-data)
14. [Devices](#14-devices)
15. [Media](#15-media)
16. [Server Keys and Cryptography](#16-server-keys-and-cryptography)
17. [Federation](#17-federation)
18. [Thread Safety](#18-thread-safety)
19. [Complete API Reference](#19-complete-api-reference)
20. [Data Structures Reference](#20-data-structures-reference)

---

## 1. What is Matrix?

Matrix is an open, decentralized protocol for real-time communication. Think of it like email, but for chat: anyone can run their own server, and servers automatically talk to each other so users on different servers can still be in the same room together.

Key concepts:

**Homeserver** — The server that stores your account and messages. When you sign up for Matrix you choose a homeserver (e.g. `matrix.org`). Your user ID is `@username:homeserver.name`. Slime is a homeserver.

**User ID** — A globally unique identifier in the format `@username:server_name`. Example: `@alice:example.com`.

**Room** — The core unit of conversation. A room is a persistent, ordered list of events. Rooms have IDs like `!randomchars:server_name`. Rooms are not "owned" by a single server — they exist across every server whose users have joined.

**Event** — Everything in a room is an event. Sending a message is an event. Joining a room is an event. Changing the room name is an event. Events are immutable once created.

**State Events** — A special class of events that define the current "state" of a room — its name, who's a member, what the power levels are, etc. The current state of a room is the latest state event for each `(type, state_key)` pair.

**Federation** — The mechanism by which different homeservers synchronize rooms. When Alice on `server-a.com` and Bob on `server-b.com` are in the same room, both servers store copies of all events and exchange new events in real time via the Server-Server (S-S) API.

**Client-Server API** — The API clients like Element use to talk to their homeserver. This is what most of Slime serves.

**Access Token** — A bearer token that a client presents with every request to prove who they are, obtained at login.

---

## 2. The Homeserver's Role

A homeserver is responsible for:

1. **Identity** — Storing user accounts, passwords, and access tokens
2. **Persistence** — Storing all events in all rooms that any of its users belong to
3. **Sync** — Delivering new events to connected clients in real time
4. **Federation** — Sharing events with other homeservers
5. **Media** — Storing uploaded images, files, and avatars
6. **Key Management** — Signing events and authenticating to other servers with Ed25519 cryptography

Slime implements the [Matrix Client-Server API v1.1–v1.11](https://spec.matrix.org/latest/client-server-api/) and the core parts of the [Federation API](https://spec.matrix.org/latest/server-server-api/).

---

## 3. Building and Running

### Dependencies

| Library | Version | Purpose |
|---------|---------|---------|
| **httplib** | bundled in `include/` | HTTP server and client |
| **nlohmann/json** | bundled in `include/json.h` | JSON parsing/serialization |
| **SQLite3** | bundled in `third_party/` | Persistence (amalgamation) |
| **libsodium** | system (`pkg-config libsodium`) | Argon2 password hashing, Ed25519 signing |
| **OpenSSL** | system (`find_package(OpenSSL)`) | SHA-256 for event IDs, TLS for outbound federation |

### Build

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DSKIP_TESTS=ON
make -j$(nproc)
```

The `LANGUAGES CXX C` declaration in CMakeLists.txt is required because the SQLite amalgamation (`sqlite3.c`) is plain C, not C++.

### Run

```bash
./Slime                       # uses defaults (port 8448, localhost)
./Slime --config config.json  # load from file
```

---

## 4. Configuration

Slime reads a JSON config file. All fields are optional — the defaults work for local development.

```json
{
  "server_name":       "localhost",
  "port":              8448,
  "db_path":           "slime.db",
  "media_path":        "media",
  "signing_key_path":  "slime.signing.key",
  "homeserver_url":    "http://localhost:8448"
}
```

| Field | Purpose |
|-------|---------|
| `server_name` | The domain name of this homeserver, used in user IDs and event IDs |
| `port` | TCP port to listen on |
| `db_path` | Path to the SQLite database file (created on first run) |
| `media_path` | Directory for uploaded media files (created on first run) |
| `signing_key_path` | Path to the Ed25519 private key file (generated on first run) |
| `homeserver_url` | Base URL returned to clients in `.well-known` for discovery |

Config loading happens in `src/config.cpp`. If the file doesn't exist or is empty, all defaults are used. This is intentional so that `./Slime` with no arguments works out of the box.

**`main.cpp` startup sequence:**
1. Call `sodium_init()` — initializes libsodium's random number generator and CPU feature detection. This *must* happen before any crypto calls.
2. Parse `--config` CLI argument.
3. Call `load_config()`.
4. Construct `MatrixServer(config)` — this initializes all subsystems and registers all HTTP routes.
5. Call `server.start()` — blocks forever, serving requests.

---

## 5. Architecture Overview

```
                      ┌─────────────────────────────────────┐
 Element (browser)    │           MatrixServer               │
 or any Matrix  ──────►  httplib thread pool (2× CPU cores)  │
 client               │           ↓                          │
                      │      CORS middleware                  │
                      │           ↓                          │
                      │      Route dispatch                   │
                      │    ┌──────┴──────┐                   │
                      │    │             │                    │
                      │  Client-Server  Federation           │
                      │    API routes   API routes           │
                      │    ↓                                  │
                      │  ┌─────────────────────────────────┐ │
                      │  │ UserManager  │  RoomManager      │ │
                      │  │ AuthManager  │  SyncManager      │ │
                      │  │ MediaManager │  KeyManager       │ │
                      │  │ FederationManager                │ │
                      │  └──────────────────┬──────────────┘ │
                      │                     │                 │
                      │              DatabaseManager          │
                      │           (SQLite3, WAL mode)         │
                      └─────────────────────────────────────┘
```

Each manager is a C++ class that owns a specific domain. They are all constructed in `MatrixServer`'s constructor initializer list in dependency order:

```cpp
MatrixServer::MatrixServer(const Config& config)
    : config_(config),
      db_(config.db_path),           // 1. database first
      user_manager_(config.server_name, db_),
      auth_manager_(),
      room_manager_(config.server_name, db_),
      sync_manager_(),
      media_manager_(config.media_path, config.server_name, db_),
      key_manager_(config.signing_key_path, config.server_name, db_),
      federation_manager_(db_, key_manager_)
```

The ordering matters: `db_` must be fully constructed before any manager that uses it, because C++ initializes members in declaration order.

---

## 6. HTTP Layer — httplib

Slime uses [cpp-httplib](https://github.com/yhirose/cpp-httplib), a single-header HTTP server. It handles:

- Parsing incoming HTTP requests (method, path, headers, body, query params)
- Path parameters like `/:roomId` extracted into `req.path_params`
- Query parameters accessed via `req.has_param()` / `req.get_param_value()`
- Thread pooling for concurrent request handling

### Thread Pool

```cpp
server_.new_task_queue = [] {
    return new httplib::ThreadPool(std::thread::hardware_concurrency() * 2);
};
```

On a 4-core machine this creates 8 worker threads. Each incoming request is handled by one thread. The thread pool allows multiple clients to be served simultaneously without blocking.

### CORS Middleware

Cross-Origin Resource Sharing headers are required so that web-based Matrix clients (like Element Web running at `app.element.io`) can make HTTP requests to your homeserver from a browser. Without CORS, the browser blocks the request.

```cpp
server_.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
    res.set_header("Access-Control-Allow-Origin", "*");
    res.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.set_header("Access-Control-Allow-Headers", "Authorization, Content-Type");
    if (req.method == "OPTIONS") {
        res.status = 200;
        return httplib::Server::HandlerResponse::Handled;  // stop here, don't route
    }
    return httplib::Server::HandlerResponse::Unhandled;    // continue to route handler
});
```

The `set_pre_routing_handler` runs before every request is routed. For `OPTIONS` (a browser "preflight" check), it returns 200 immediately. For all other methods, it adds the headers and continues normally.

---

## 7. Database Layer — SQLite

`DatabaseManager` (`src/database_manager.cpp`) wraps SQLite3 and provides a small, safe API.

### WAL Mode

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA cache_size=-65536;  -- 64 MB page cache
PRAGMA foreign_keys=ON;
```

WAL (Write-Ahead Logging) allows simultaneous readers and one writer, which is important since multiple threads may be serving requests concurrently. `synchronous=NORMAL` is a good balance between crash safety and speed. The 64 MB page cache keeps hot data in memory.

### Schema — All Tables

| Table | Purpose |
|-------|---------|
| `users` | Registered accounts: username, user_id, password_hash, created_at |
| `devices` | Client devices: device_id, username, display_name |
| `tokens` | Active access tokens: token → (username, device_id) |
| `rooms` | Room metadata: room_id, version, creator, created_at |
| `room_members` | Membership state: (room_id, user_id) → membership |
| `events` | All room events, immutable once written |
| `room_state` | Current state snapshot: (room_id, type, state_key) → event_id |
| `profiles` | Display names and avatar URLs |
| `room_aliases` | `#alias:server` → room_id mappings |
| `filters` | Client sync filters |
| `media` | Uploaded file metadata |
| `push_rules` | Per-user notification rules |
| `server_keys` | This server's and cached remote servers' Ed25519 keys |
| `account_data` | Per-user arbitrary JSON blobs |
| `read_receipts` | Last-read event per user per room |
| `presence` | Online/offline/unavailable status per user |

### Indices

```sql
CREATE INDEX idx_events_room ON events(room_id, depth);
CREATE INDEX idx_room_members_user ON room_members(user_id);
CREATE INDEX idx_tokens_username ON tokens(username);
CREATE INDEX idx_events_type ON events(room_id, type);
```

These indices make the hot paths fast: fetching a room's timeline (by room_id + depth), finding all rooms a user is in (by user_id), and looking up tokens by username.

### DatabaseManager API

```cpp
// Run arbitrary SQL (schema creation, etc.)
void exec(const std::string& sql);

// SELECT — calls row_cb for each result row
void query(const std::string& sql,
           const std::vector<std::string>& params,
           std::function<void(sqlite3_stmt*)> row_cb) const;

// INSERT/UPDATE/DELETE — returns rows changed
int execute(const std::string& sql, const std::vector<std::string>& params);

// Convenience: get single text value
std::string get_text(const std::string& sql, const std::vector<std::string>& params) const;

// Convenience: get single int64 value
int64_t get_int(const std::string& sql, const std::vector<std::string>& params, int64_t def = 0) const;
```

All parameters are passed as strings (SQLite binds them safely), preventing SQL injection. The query/execute functions prepare statements fresh for each call — in a future optimization these could be cached as `sqlite3_stmt*` handles.

---

## 8. User Accounts and Authentication

### Registration

Matrix uses a multi-stage authentication mechanism called **UIA (User-Interactive Authentication)**. The flow for registration:

1. **Client sends** `POST /_matrix/client/v3/register` with `{username, password}`
2. **Server creates** a session with a session ID and returns 401 with available auth flows
3. **Client picks** an auth flow (e.g. `m.login.dummy`) and posts back with `{auth: {type, session}}`
4. **Server validates** the stage and either asks for more stages or completes registration
5. **On completion** — user is created, access token returned

Available auth flows (defined in `AuthManager`):
- `["m.login.dummy"]` — just tick a box, no real verification
- `["m.login.recaptcha", "m.login.terms"]` — complete both stages

The `AuthManager` stores in-memory session state during this multi-step process. Sessions are ephemeral and destroyed immediately after registration succeeds or fails.

### Password Hashing

Passwords are **never stored in plaintext**. They are hashed with **Argon2id** via libsodium:

```cpp
char hash[crypto_pwhash_STRBYTES];  // 128 bytes
crypto_pwhash_str(hash, password.c_str(), password.size(),
    crypto_pwhash_OPSLIMIT_INTERACTIVE,   // ~2 ops (memory-hard)
    crypto_pwhash_MEMLIMIT_INTERACTIVE);  // ~64 MB memory cost
```

Argon2id is a memory-hard function that is resistant to GPU/ASIC brute-force attacks. The `INTERACTIVE` parameters are calibrated to take ~100ms on a modern CPU — slow enough to be expensive for attackers, fast enough to not annoy users.

Verification:
```cpp
crypto_pwhash_str_verify(stored_hash.c_str(), password.c_str(), password.size());
```

There is a migration path: if the stored hash doesn't start with `$argon2`, it's compared as plaintext (to support upgrading from an older insecure version).

### Login

`POST /_matrix/client/v3/login`

Supports `m.login.password`. The client sends:
```json
{
  "type": "m.login.password",
  "identifier": {"type": "m.id.user", "user": "alice"},
  "password": "hunter2",
  "device_id": "MYDEVICE"  // optional
}
```

On success, returns an access token:
```json
{
  "user_id": "@alice:localhost",
  "access_token": "syt_abc123...",
  "device_id": "MYDEVICE"
}
```

Access tokens are random 40-character hex strings prefixed with `syt_` (generated by `Utils::generate_token()`).

### Token Validation and Caching

Every authenticated endpoint calls `require_auth()`, which:
1. Extracts the bearer token from the `Authorization: Bearer <token>` header (or `access_token` query param)
2. Checks the **in-memory LRU cache** first (max 10,000 entries)
3. Falls back to a `SELECT` from the `tokens` table
4. On DB hit, populates the cache for future requests

The cache stores `token → {username, device_id}`. When it reaches 10,000 entries, it clears entirely (simple but effective for typical workloads). Cache entries are invalidated individually on logout or device deletion.

### Logout

- `POST /_matrix/client/v3/logout` — revokes the current token
- `POST /_matrix/client/v3/logout/all` — revokes all tokens for the authenticated user

Both remove from the database and evict from the cache.

---

## 9. Rooms and Events

### What Is a Room?

A room is a persistent, append-only log of events with a current state. Every room has:
- A **room ID** like `!abc123:localhost` (generated with `Utils::generate_room_id()`)
- A **room version** (Slime uses version 10, the current stable version)
- A **timeline** — ordered events starting from creation
- A **state** — the current value of each state event type

### Room Creation

`POST /_matrix/client/v3/createRoom`

When a room is created, Slime injects a fixed set of state events in a specific order (required by the spec):

| # | Event Type | state_key | Purpose |
|---|-----------|-----------|---------|
| 1 | `m.room.create` | `""` | Establishes creator and room version |
| 2 | `m.room.member` | creator's user_id | Creator auto-joins |
| 3 | `m.room.power_levels` | `""` | Who can do what (creator gets 100) |
| 4 | `m.room.join_rules` | `""` | `invite` or `public` based on preset |
| 5 | `m.room.history_visibility` | `""` | Who can see history: `shared` or `invited` |
| 6 | `m.room.guest_access` | `""` | Can guests join? |
| 7 | `initial_state[]` | varies | User-supplied initial state events |
| 8 | `m.room.name` | `""` | Room name (if provided) |
| 9 | `m.room.topic` | `""` | Room topic (if provided) |

The `preset` field controls defaults:
- `public_chat` → join_rule=`public`, history=`shared`, guest=`can_join`
- `private_chat` / `trusted_private_chat` → join_rule=`invite`, history=`invited`, guest=`forbidden`

Power levels set at creation:
```json
{
  "ban": 50, "kick": 50, "redact": 50,
  "invite": 0, "events_default": 0,
  "state_default": 50,
  "users_default": 0,
  "users": {"@creator:server": 100}
}
```

The creator has power level 100 (admin). Everyone else defaults to 0.

### Event IDs — How They Are Computed

Event IDs in Matrix room version 10 are **content-addressed**: the ID is derived from the event's content, so no two different events can have the same ID, and you can't forge an event without changing its ID.

The process (`MatrixCrypto::reference_hash()`):

1. Build the event JSON (room_id, type, sender, content, origin_server_ts, depth, state_key if applicable)
2. Remove `signatures` and `hashes` fields (these are added after hashing)
3. **Canonical JSON** — serialize with keys sorted alphabetically, no extra whitespace:
   ```
   {"content":{"membership":"join"},"depth":2,"room_id":"!abc:loc","sender":"@a:loc",...}
   ```
4. **SHA-256** the canonical JSON bytes
5. **Base64-URL** encode the 32-byte hash (no padding `=` characters)
6. Prepend `$`: `$TwHJU3T9Y8rjdvHXJ3yrmWZG6nkDJYQB1q8n5x7fVRg`

This uses OpenSSL's `SHA256()` function and a hand-written base64-url encoder.

### The `depth` Field

Every event has a `depth` integer that increases monotonically within a room. Slime tracks `sync_position_` (an `int64_t` that increments on each event) and uses the current max depth + 1 for each new event:

```cpp
int64_t next_depth(const std::string& room_id) const {
    int64_t d = db_.get_int("SELECT COALESCE(MAX(depth),0) FROM events WHERE room_id=?", {room_id});
    return d + 1;
}
```

Depth is used as the sync position token — clients request "events since depth N".

### State vs. Timeline Events

**State events** define the current properties of a room. They have a `state_key` (which can be an empty string). The room state is a map of `(type, state_key)` → latest content. For example:

- `(m.room.name, "")` → `{"name": "My Room"}`
- `(m.room.member, "@alice:server")` → `{"membership": "join"}`
- `(m.room.member, "@bob:server")` → `{"membership": "leave"}`

State events appear in *both* the timeline (they happened) and the state snapshot (they represent current truth).

**Timeline events** are non-state events like `m.room.message`. They appear only in the timeline.

The `room_state` table is a snapshot: whenever a state event is written, `room_state` is upserted with the new event_id. So querying current state is a single indexed join:

```sql
SELECT e.content FROM room_state rs
JOIN events e ON rs.event_id = e.event_id
WHERE rs.room_id=? AND rs.type=? AND rs.state_key=?
```

### Membership

Membership is managed through `m.room.member` state events. Possible values:

| Membership | Meaning |
|------------|---------|
| `join` | Active member, can see events and send |
| `invite` | Invited but hasn't accepted yet |
| `leave` | Has left the room |
| `ban` | Banned, cannot rejoin |

Key endpoints:
- `POST /rooms/{roomId}/join` — become a member
- `POST /join/{roomIdOrAlias}` — join by room ID or alias like `#general:server`
- `POST /rooms/{roomId}/leave` — leave
- `POST /rooms/{roomId}/invite` — invite another user (requires power level ≥ `invite` threshold)
- `POST /rooms/{roomId}/kick` — set someone's membership to `leave` (requires PL ≥ 50)
- `POST /rooms/{roomId}/ban` — ban a user (requires PL ≥ 50)
- `POST /rooms/{roomId}/unban` — lift a ban

### Power Level Checks

Before privileged operations, Slime checks the acting user's power level against the required threshold:

```cpp
int power = room_manager_.get_user_power_level(room_id, user_id);
int required = room_manager_.get_required_power_level(room_id, "kick");
if (power < required) { send_error(403, "M_FORBIDDEN", ...); }
```

`get_user_power_level` reads the `m.room.power_levels` state event and looks up the user's level (or `users_default` if not listed). Required levels for actions:

| Action | Default required PL |
|--------|-------------------|
| Send message | 0 |
| Change state | 50 |
| Invite | 0 |
| Kick | 50 |
| Ban | 50 |

### Room Aliases

Room aliases like `#general:localhost` are human-readable names that resolve to room IDs. Stored in the `room_aliases` table.

- `PUT /_matrix/client/v3/directory/room/{alias}` — set alias
- `GET /_matrix/client/v3/directory/room/{alias}` — resolve alias → room ID
- `DELETE /_matrix/client/v3/directory/room/{alias}` — remove alias

### Sending Events

`PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}`

The `txnId` is a client-provided transaction ID for idempotency (so retried requests don't duplicate messages). Currently stored but not deduplicated — full idempotency is a future improvement.

`PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}`

For state events. Requires power level ≥ `state_default` (50 by default).

After writing any event, Slime notifies the sync manager so waiting long-poll clients wake up:
```cpp
sync_manager_.notify_event(room_id, event);
```

### Reading Events

| Endpoint | Returns |
|----------|---------|
| `GET /rooms/{roomId}/messages` | Paginated timeline, params: `from`, `limit`, `dir` |
| `GET /rooms/{roomId}/event/{eventId}` | A single event by ID |
| `GET /rooms/{roomId}/state` | Full state array (all current state events) |
| `GET /rooms/{roomId}/state/{type}/{stateKey}` | Content of a specific state event |
| `GET /rooms/{roomId}/members` | All members (optionally filter by membership) |
| `GET /rooms/{roomId}/joined_members` | Joined members with profile info |
| `GET /joined_rooms` | All rooms the authenticated user has joined |
| `GET /publicRooms` | Rooms with `join_rule=public` |

---

## 10. The Sync Engine — How Messages Reach Clients

Sync is the heartbeat of a Matrix client. The client calls `GET /_matrix/client/v3/sync` in a loop, and the server holds the connection open until there's something new to deliver. This is called **long-polling**.

### How It Works

```
Client                                   Server
  |                                         |
  |-- GET /sync?since=s42&timeout=30000 -->|
  |                           (waits up to 30s)
  |                 (someone sends a message)
  |<-- 200 OK {next_batch: "s43", rooms: {}}|
  |                                         |
  |-- GET /sync?since=s43&timeout=30000 -->|
  |                           (waits again...)
```

### The Stream Position

Every event, ephemeral event, and presence update advances a global `int64_t position_` counter in `SyncManager`. A sync token like `s42` means "I've seen everything up to position 42."

### `wait_for_sync()` Step by Step

```cpp
json SyncManager::wait_for_sync(user_id, since_pos, timeout_ms, joined_rooms,
                                 get_room_events, get_room_state)
```

1. **Check if up to date**: If `since_pos >= position_`, there's nothing new. Block on `cv_.wait_until()` with a `std::condition_variable` until either:
   - The timeout expires
   - `cv_.notify_all()` is called (happens on any new event)

2. **Collect timeline events**: For each room the user is in, call `get_room_events(room_id, since_pos)` to get events with `depth > since_pos`.

3. **Initial sync**: If `since_pos == 0` (first sync), also return the full current state of each room so the client can render it.

4. **Ephemeral events**: Collect typing notifications and read receipts for each room since `since_pos`.

5. **Presence updates**: Collect presence changes since `since_pos`.

6. **Return**:
```json
{
  "next_batch": "s43",
  "rooms": {
    "join": {
      "!room:server": {
        "timeline": {
          "events": [...],
          "limited": false,
          "prev_batch": "s42"
        },
        "state": {"events": [...]},
        "ephemeral": {"events": [...]},
        "account_data": {"events": [...]}
      }
    },
    "invite": {},
    "leave": {}
  },
  "presence": {"events": [...]},
  "account_data": {"events": [...]}
}
```

### Notification Chain

When any event is added to a room:
```
RoomManager::add_event()
    → writes to SQLite
    → MatrixServer::handle_* calls sync_manager_.notify_event()
        → increments position_
        → appends to event_log_ (capped at 50k events)
        → cv_.notify_all()  ← wakes all blocked /sync requests
```

Ephemeral events (typing, receipts) go through `notify_ephemeral()` and follow the same pattern. The `event_log_` is trimmed to 50,000 entries to bound memory usage.

---

## 11. Profiles and Presence

### Profiles

Every user has a display name and avatar URL stored in the `profiles` table. These are separate from the account itself — you can have a `@alice:server` account but present as "Alice Smith" with a photo.

- `GET /_matrix/client/v3/profile/{userId}` — get display name + avatar (no auth required)
- `PUT /_matrix/client/v3/profile/{userId}/displayname` — set display name
- `PUT /_matrix/client/v3/profile/{userId}/avatar_url` — set avatar (an `mxc://` URI to uploaded media)

Profiles are public by design in Matrix — anyone can look up anyone's display name.

### Presence

Presence tracks whether a user is online, offline, or unavailable.

- `GET /_matrix/client/v3/presence/{userId}/status` — get current presence
- `PUT /_matrix/client/v3/presence/{userId}/status` — set presence

```json
{
  "presence": "online",      // "online", "offline", "unavailable"
  "status_msg": "In a meeting"
}
```

Stored in the `presence` table. When updated, `sync_manager_.notify_presence()` is called so other clients receive the update in their next `/sync` response under the `presence.events` array.

---

## 12. Ephemeral Events — Typing and Read Receipts

Ephemeral events are not stored in the room timeline — they're transient signals.

### Typing Notifications

`PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`

```json
{"typing": true, "timeout": 30000}
```

Slime emits an `m.typing` ephemeral event with the current list of typing users:
```json
{
  "type": "m.typing",
  "content": {"user_ids": ["@alice:server"]}
}
```

This is sent to `sync_manager_.notify_ephemeral()` and delivered to other room members via the `ephemeral` section of their next sync response.

Note: Slime's current implementation is simple — it doesn't track per-user typing state or expire typing after the timeout. Each PUT sets the typing list to just that user or empty. Full typing state management with expiry timers is a future improvement.

### Read Receipts

`POST /_matrix/client/v3/rooms/{roomId}/receipt/{receiptType}/{eventId}`

Marks that the user has read up to a given event. Receipt types include `m.read` (read receipt) and `m.read.private` (private, not shared with others).

Receipt is stored in `read_receipts` table and also broadcast as an ephemeral event:
```json
{
  "type": "m.receipt",
  "content": {
    "$event_id": {
      "m.read": {
        "@alice:server": {"ts": 1234567890}
      }
    }
  }
}
```

---

## 13. Account Data

Account data is arbitrary JSON stored per user (or per user per room). Clients use it to store settings, direct message room lists, push notification rules, etc.

- `PUT/GET /_matrix/client/v3/user/{userId}/account_data/{type}` — global account data
- `PUT/GET /_matrix/client/v3/user/{userId}/rooms/{roomId}/account_data/{type}` — room-scoped account data

Common types: `m.direct` (DM room list), `m.push_rules`, `m.ignored_user_list`.

Stored in the `account_data` table with a `room_id` column (empty string for global data). The `(user_id, type, room_id)` triple is the primary key.

---

## 14. Devices

In Matrix, a "device" represents a logged-in client session. The same user might be logged in from their phone, laptop, and web browser simultaneously — each is a separate device with its own `device_id` and access token.

Devices matter for end-to-end encryption (E2EE): keys are per-device, so messages encrypted on one device can be decrypted on another only if keys are shared.

Slime implements the device management API:

| Endpoint | Action |
|----------|--------|
| `GET /devices` | List all devices for the authenticated user |
| `GET /devices/{deviceId}` | Get a specific device |
| `PUT /devices/{deviceId}` | Update device display name |
| `DELETE /devices/{deviceId}` | Delete a device and revoke its token |
| `POST /delete_devices` | Delete multiple devices |

Devices are created automatically on login or registration. Each has a `device_id` (random string), `username`, and optional `display_name`.

### Sync Filters

Clients can upload a filter to control what the sync response contains — which rooms to include, which event types to filter, how many events per room:

- `POST /_matrix/client/v3/user/{userId}/filter` → returns `filter_id`
- `GET /_matrix/client/v3/user/{userId}/filter/{filterId}` → returns filter JSON

Filters are stored in the `filters` table. Slime stores and returns them correctly but does not yet apply them when building sync responses (Phase 4 improvement from PLAN.md).

---

## 15. Media

Matrix uses `mxc://` URIs for all media (images, files, avatars). The format is:
```
mxc://server_name/media_id
```

### Upload

`POST /_matrix/media/v3/upload`

The raw file bytes are the request body. Content-Type and filename are passed as headers/params. Slime:
1. Generates a random 24-character alphanumeric `media_id`
2. Writes the raw bytes to `{media_path}/{media_id}` on disk
3. Records metadata in the `media` table (filename, content_type, size, uploader)
4. Returns `{"content_uri": "mxc://server/media_id"}`

### Download

`GET /_matrix/media/v3/download/{serverName}/{mediaId}`

For local media (serverName matches this server), reads the file from disk and returns it with the stored Content-Type. For remote media (different serverName), Slime currently returns 404 — proxying remote media is a future feature.

### Thumbnail

`GET /_matrix/media/v3/thumbnail/{serverName}/{mediaId}`

Currently returns the full-size image. Actual resizing (via libjpeg/libpng) is a future improvement.

Both `v3` and the legacy `r0` paths are supported.

---

## 16. Server Keys and Cryptography

### Why Servers Need Keys

Federation requires servers to sign events with a private key so that other servers can verify:
1. "This event really came from server X"
2. "The content of this event has not been tampered with"

This prevents a malicious server from injecting fake events into a federated room.

### Ed25519 Key Generation

On startup, `KeyManager` does the following (in `load_or_generate()`):

1. **Try to load** from the key file at `signing_key_path`:
   ```
   ed25519 a <base64_encoded_secret_key>
   ```
   The secret key is 64 bytes (libsodium's combined format: 32 bytes private + 32 bytes public). The `a` is the key ID suffix.

2. **If not found**, generate a new keypair:
   ```cpp
   crypto_sign_keypair(public_key_, secret_key_);  // libsodium Ed25519
   ```
   Write to file and persist in the `server_keys` table.

3. Set `valid_until_ts` = now + 7 days (after which the key should be rotated).

The key ID is `ed25519:a`. The public key is exposed at `GET /_matrix/key/v2/server` so other servers can verify signatures.

### Event Signing

Every event signed by Slime has:
```json
{
  "signatures": {
    "localhost": {
      "ed25519:a": "<base64_signature>"
    }
  },
  "hashes": {
    "sha256": "<base64url_sha256_of_content>"
  }
}
```

The signing process:
1. Canonical JSON of the event (minus `signatures`/`hashes`)
2. Sign with `crypto_sign_detached()` → 64-byte signature
3. Base64 encode

### Canonical JSON

A deterministic JSON serialization required by the spec. Implementation in `MatrixCrypto::canonical_json()`:
- Object keys are **sorted alphabetically**
- No extra whitespace
- Strings and values use standard JSON encoding
- Arrays preserve their order (only object keys are sorted)

Example:
```json
Input:  {"b": 2, "a": 1}
Output: {"a":1,"b":2}
```

This is necessary because different JSON libraries might produce different key orderings, which would produce different signatures over the same logical content.

### `/_matrix/key/v2/server`

Returns this server's public key, signed by itself:
```json
{
  "server_name": "localhost",
  "valid_until_ts": 1234567890000,
  "verify_keys": {
    "ed25519:a": {
      "key": "<base64_public_key>"
    }
  },
  "old_verify_keys": {},
  "signatures": {
    "localhost": {
      "ed25519:a": "<self_signature>"
    }
  }
}
```

---

## 17. Federation

Federation is how different homeservers communicate. When a user on `server-a.com` and a user on `server-b.com` are in the same room, both servers need to exchange events.

### The X-Matrix Authorization Header

Outbound federation requests are authenticated with a special `Authorization` header:

```
Authorization: X-Matrix origin=server-a.com,key="ed25519:a",sig="<base64_sig>"
```

The signature is over a canonical JSON object:
```json
{
  "method": "PUT",
  "uri": "/_matrix/federation/v1/send/1",
  "origin": "server-a.com",
  "destination": "server-b.com",
  "content": { ...the request body... }
}
```

Built by `FederationManager::make_auth_header()`. Verified by `FederationManager::verify_auth_header()`, which fetches the origin server's public key (from cache, DB, or by calling `/_matrix/key/v2/server` on the remote server).

### Inbound Federation Routes

| Endpoint | Purpose |
|----------|---------|
| `GET /_matrix/federation/v1/version` | Identify this server |
| `GET /_matrix/key/v2/server` | Serve this server's public key |
| `GET /_matrix/key/v2/query` | Return key info (serves own key) |
| `PUT /_matrix/federation/v1/send/{txnId}` | Receive event transactions from other servers |
| `GET /_matrix/federation/v1/make_join/{roomId}/{userId}` | Get a template join event |
| `PUT /_matrix/federation/v1/send_join/{roomId}/{userId}` | Process a remote join + return room state |
| `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}` | Get a template leave event |
| `PUT /_matrix/federation/v1/send_leave/{roomId}/{userId}` | Process a remote leave |
| `GET /_matrix/federation/v1/event/{eventId}` | Serve a single event |
| `GET /_matrix/federation/v1/state/{roomId}` | Serve full room state |
| `GET /_matrix/federation/v1/state_ids/{roomId}` | Serve state event IDs |
| `GET /_matrix/federation/v1/backfill/{roomId}` | Serve historical events |
| `GET /_matrix/federation/v1/query/directory` | Resolve room alias |
| `GET /_matrix/federation/v1/query/profile` | Look up user profile |

### Outbound Federation (`FederationManager::send_transaction()`)

When local events need to be sent to remote servers, `send_transaction()` builds a federation transaction:

```json
{
  "origin": "localhost",
  "origin_server_ts": 1234567890,
  "pdus": [...events...],
  "edus": [...ephemeral data units...]
}
```

And sends it with `PUT /_matrix/federation/v2/send/{txnId}` to the destination server using an `httplib::Client`.

### Remote Key Caching

`FederationManager::get_remote_key()` fetches and caches remote servers' public keys:
1. Check in-memory `key_cache_` map (valid_until check)
2. Check `server_keys` table in SQLite
3. HTTP GET `/_matrix/key/v2/server` from the remote server
4. Cache in both memory and DB

---

## 18. Thread Safety

Multiple requests run simultaneously in the httplib thread pool. Several managers protect their data:

### `UserManager`

```cpp
mutable std::shared_mutex mutex_;       // protects user/token operations
mutable std::shared_mutex cache_mutex_; // protects token cache separately
```

Reads use `std::shared_lock` (multiple concurrent readers), writes use `std::unique_lock` (exclusive). The token cache has its own mutex so cache reads don't block writes to the main data.

### `RoomManager`

```cpp
mutable std::shared_mutex mutex_;
```

Same pattern: shared locks for reads (timeline, state queries), exclusive locks for writes (add_event, create_room, add_member).

### `SyncManager`

```cpp
mutable std::mutex mutex_;
std::condition_variable cv_;
std::atomic<int64_t> position_{0};
```

The position counter is `std::atomic` so it can be incremented and read lock-free. The `cv_` uses a plain `std::mutex` (not shared_mutex) because `condition_variable` requires it. Multiple threads can block in `wait_for_sync()` simultaneously, all woken by a single `cv_.notify_all()`.

### `FederationManager`

```cpp
mutable std::mutex cache_mutex_;
```

Plain mutex for the key cache map.

### SQLite

SQLite itself is opened in WAL mode, which allows concurrent readers. The `DatabaseManager::query()` and `execute()` functions each prepare and finalize their own statements, making them re-entrant. SQLite's built-in busy timeout (5 seconds) handles write contention.

---

## 19. Complete API Reference

### Discovery

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/matrix/client` | No | Server discovery: homeserver base URL |
| GET | `/_matrix/client/versions` | No | Supported spec versions |
| GET | `/_matrix/client/v3/capabilities` | No | Server capabilities |
| GET | `/_matrix/federation/v1/version` | No | Federation server name/version |
| GET | `/_matrix/key/v2/server` | No | Server signing keys |
| GET | `/_matrix/key/v2/query` | No | Query signing keys |

### Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/_matrix/client/v3/login` | No | List login flows |
| POST | `/_matrix/client/v3/login` | No | Login with password |
| POST | `/_matrix/client/v3/register` | No | Register new account |
| POST | `/_matrix/client/v3/logout` | Yes | Revoke current token |
| POST | `/_matrix/client/v3/logout/all` | Yes | Revoke all tokens |
| GET | `/_matrix/client/v3/account/whoami` | Yes | Get current user ID |

### Rooms

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/_matrix/client/v3/createRoom` | Yes | Create a room |
| POST | `/_matrix/client/v3/rooms/:roomId/join` | Yes | Join by room ID |
| POST | `/_matrix/client/v3/join/:roomIdOrAlias` | Yes | Join by ID or alias |
| POST | `/_matrix/client/v3/rooms/:roomId/leave` | Yes | Leave a room |
| POST | `/_matrix/client/v3/rooms/:roomId/forget` | Yes | Forget a room (no-op) |
| POST | `/_matrix/client/v3/rooms/:roomId/invite` | Yes | Invite a user |
| POST | `/_matrix/client/v3/rooms/:roomId/kick` | Yes | Kick a user |
| POST | `/_matrix/client/v3/rooms/:roomId/ban` | Yes | Ban a user |
| POST | `/_matrix/client/v3/rooms/:roomId/unban` | Yes | Unban a user |
| PUT | `/_matrix/client/v3/rooms/:roomId/send/:type/:txnId` | Yes | Send a room event |
| PUT | `/_matrix/client/v3/rooms/:roomId/state/:type` | Yes | Send state event |
| PUT | `/_matrix/client/v3/rooms/:roomId/state/:type/:stateKey` | Yes | Send state event |
| GET | `/_matrix/client/v3/rooms/:roomId/messages` | Yes | Get room timeline |
| GET | `/_matrix/client/v3/rooms/:roomId/event/:eventId` | Yes | Get single event |
| GET | `/_matrix/client/v3/rooms/:roomId/state` | Yes | Get full room state |
| GET | `/_matrix/client/v3/rooms/:roomId/state/:type` | Yes | Get state event |
| GET | `/_matrix/client/v3/rooms/:roomId/state/:type/:stateKey` | Yes | Get state event |
| GET | `/_matrix/client/v3/rooms/:roomId/members` | Yes | Get room members |
| GET | `/_matrix/client/v3/rooms/:roomId/joined_members` | Yes | Get joined members |
| GET | `/_matrix/client/v3/joined_rooms` | Yes | List joined rooms |
| GET/POST | `/_matrix/client/v3/publicRooms` | No | List public rooms |

### Room Aliases

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/_matrix/client/v3/directory/room/:alias` | Yes | Create alias |
| GET | `/_matrix/client/v3/directory/room/:alias` | No | Resolve alias |
| DELETE | `/_matrix/client/v3/directory/room/:alias` | Yes | Delete alias |

### Sync

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/_matrix/client/v3/sync` | Yes | Long-poll sync |

Params: `since` (sync token), `timeout` (ms, max 30000), `filter`.

### Filters

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/_matrix/client/v3/user/:userId/filter` | Yes | Upload filter |
| GET | `/_matrix/client/v3/user/:userId/filter/:filterId` | Yes | Get filter |

### Profile and Presence

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/_matrix/client/v3/profile/:userId` | No | Get full profile |
| GET | `/_matrix/client/v3/profile/:userId/displayname` | No | Get display name |
| PUT | `/_matrix/client/v3/profile/:userId/displayname` | Yes | Set display name |
| GET | `/_matrix/client/v3/profile/:userId/avatar_url` | No | Get avatar |
| PUT | `/_matrix/client/v3/profile/:userId/avatar_url` | Yes | Set avatar |
| GET | `/_matrix/client/v3/presence/:userId/status` | Yes | Get presence |
| PUT | `/_matrix/client/v3/presence/:userId/status` | Yes | Set presence |

### Ephemeral

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/_matrix/client/v3/rooms/:roomId/typing/:userId` | Yes | Send typing notification |
| POST | `/_matrix/client/v3/rooms/:roomId/receipt/:type/:eventId` | Yes | Send read receipt |

### Account Data

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| PUT | `/_matrix/client/v3/user/:userId/account_data/:type` | Yes | Set account data |
| GET | `/_matrix/client/v3/user/:userId/account_data/:type` | Yes | Get account data |
| PUT | `/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type` | Yes | Set room account data |
| GET | `/_matrix/client/v3/user/:userId/rooms/:roomId/account_data/:type` | Yes | Get room account data |

### Devices

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/_matrix/client/v3/devices` | Yes | List devices |
| GET | `/_matrix/client/v3/devices/:deviceId` | Yes | Get device |
| PUT | `/_matrix/client/v3/devices/:deviceId` | Yes | Update device |
| DELETE | `/_matrix/client/v3/devices/:deviceId` | Yes | Delete device |
| POST | `/_matrix/client/v3/delete_devices` | Yes | Delete multiple devices |

### User Directory

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/_matrix/client/v3/user_directory/search` | Yes | Search users by name |

### Push Rules

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/_matrix/client/v3/pushrules/` | Yes | Get all push rules |
| PUT | `/_matrix/client/v3/pushrules/:scope/:kind/:ruleId` | Yes | Set push rule |
| DELETE | `/_matrix/client/v3/pushrules/:scope/:kind/:ruleId` | Yes | Delete push rule |

### Media

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/_matrix/media/v3/upload` | Yes | Upload file |
| GET | `/_matrix/media/v3/download/:server/:mediaId` | No | Download file |
| GET | `/_matrix/media/v3/thumbnail/:server/:mediaId` | No | Get thumbnail |
| POST | `/_matrix/media/r0/upload` | Yes | Upload (legacy) |
| GET | `/_matrix/media/r0/download/:server/:mediaId` | No | Download (legacy) |
| GET | `/_matrix/media/r0/thumbnail/:server/:mediaId` | No | Thumbnail (legacy) |

### Federation (Server-Server)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/_matrix/federation/v1/version` | Server identification |
| GET | `/_matrix/key/v2/server` | Signing keys |
| GET | `/_matrix/key/v2/query` | Key query |
| PUT | `/_matrix/federation/v1/send/:txnId` | Receive events |
| GET | `/_matrix/federation/v1/make_join/:roomId/:userId` | Join template |
| PUT | `/_matrix/federation/v1/send_join/:roomId/:userId` | Process remote join |
| PUT | `/_matrix/federation/v2/send_join/:roomId/:userId` | Process remote join (v2) |
| GET | `/_matrix/federation/v1/make_leave/:roomId/:userId` | Leave template |
| PUT | `/_matrix/federation/v1/send_leave/:roomId/:userId` | Process remote leave |
| GET | `/_matrix/federation/v1/event/:eventId` | Fetch single event |
| GET | `/_matrix/federation/v1/state/:roomId` | Fetch room state |
| GET | `/_matrix/federation/v1/state_ids/:roomId` | Fetch state event IDs |
| GET | `/_matrix/federation/v1/backfill/:roomId` | Fetch historical events |
| GET | `/_matrix/federation/v1/query/directory` | Resolve room alias |
| GET | `/_matrix/federation/v1/query/profile` | Fetch user profile |

---

## 20. Data Structures Reference

### `Config`

```cpp
struct Config {
    std::string server_name  = "localhost";
    int port                 = 8448;
    std::string db_path      = "slime.db";
    std::string media_path   = "media";
    std::string signing_key_path = "slime.signing.key";
    std::string homeserver_url   = "http://localhost:8448";
};
```

### `Event`

```cpp
struct Event {
    std::string event_id;          // "$<base64url_sha256>"
    std::string type;              // "m.room.message", "m.room.member", etc.
    std::string sender;            // "@user:server"
    std::string room_id;           // "!roomid:server"
    int64_t     origin_server_ts;  // Unix timestamp in milliseconds
    json        content;           // Arbitrary JSON content
    std::string state_key;         // "" for non-keyed state, user_id for membership, etc.
    std::string txn_id;            // Client-supplied idempotency key
    int64_t     depth = 0;         // Monotonically increasing within a room
};
```

### `TokenInfo`

```cpp
struct TokenInfo {
    std::string username;
    std::string device_id;
};
```

### `AuthSession` (UIA, in-memory only)

```cpp
struct AuthSession {
    std::string session_id;
    std::vector<std::string> completed_stages;
    std::string username;
    std::string password;
    time_t created_at;
};
```

### `Device`

```cpp
struct Device {
    std::string device_id;
    std::string username;
    std::string display_name;
};
```

### `Profile`

```cpp
struct Profile {
    std::string user_id;
    std::string displayname;
    std::string avatar_url;  // "mxc://server/media_id" or ""
};
```

### `Room` (in-memory, not persisted as a struct)

The room data lives in the SQLite tables (`rooms`, `room_members`, `events`, `room_state`). The `Room` struct in `types.h` is defined for future in-memory caching:

```cpp
struct Room {
    std::string room_id;
    std::string room_version;
    std::string creator;
    std::unordered_set<std::string> members;
    std::vector<Event> timeline;
    std::map<std::string, json> state;  // "type|state_key" → content
    time_t created_at;
};
```

### `SyncEvent` (in SyncManager memory)

```cpp
struct SyncEvent {
    int64_t position;
    std::string room_id;
    Event event;
};
```

### `ReadReceipt`

```cpp
struct ReadReceipt {
    std::string room_id;
    std::string user_id;
    std::string event_id;
    int64_t ts;  // Unix timestamp in milliseconds
};
```

---

*For the implementation roadmap and planned features, see [PLAN.md](PLAN.md).*
