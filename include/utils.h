#pragma once

#include <string>
#include <random>
#include <sstream>

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
        return !captcha.empty();
    }

    static std::string extract_username(const std::string& user_id) {
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

    static std::string generate_room_id(const std::string& domain) {
        return "!" + generate_random_string(18) + ":" + domain;
    }

    static std::string generate_event_id() {
        return "$" + generate_random_string(43);
    }

    static int64_t get_next_sync_position() {
        static int64_t position = 0;
        return ++position;
    }
};
