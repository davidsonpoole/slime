#include "config.h"
#include "json.h"
#include <fstream>
#include <stdexcept>

using json = nlohmann::json;

Config load_config(const std::string& path) {
    Config cfg;
    std::ifstream f(path);
    if (!f.is_open()) {
        return cfg; // return defaults
    }
    json j;
    try { j = json::parse(f); } catch (...) { return cfg; }
    if (j.contains("server_name"))   cfg.server_name   = j["server_name"].get<std::string>();
    if (j.contains("port"))          cfg.port          = j["port"].get<int>();
    if (j.contains("db_path"))       cfg.db_path       = j["db_path"].get<std::string>();
    if (j.contains("media_path"))    cfg.media_path    = j["media_path"].get<std::string>();
    if (j.contains("signing_key_path")) cfg.signing_key_path = j["signing_key_path"].get<std::string>();
    if (j.contains("homeserver_url")) cfg.homeserver_url = j["homeserver_url"].get<std::string>();
    return cfg;
}
