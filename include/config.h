#pragma once

#include <string>

struct Config {
    std::string server_name = "localhost";
    int port = 8448;
    std::string db_path = "slime.db";
    std::string media_path = "media";
    std::string signing_key_path = "slime.signing.key";
    std::string homeserver_url = "http://localhost:8448";
};

Config load_config(const std::string& path);
