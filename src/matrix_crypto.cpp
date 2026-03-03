#include "matrix_crypto.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace MatrixCrypto {

std::string canonical_json(const json& j) {
    if (j.is_object()) {
        // Collect keys, sort them
        std::vector<std::string> keys;
        for (auto it = j.begin(); it != j.end(); ++it) {
            keys.push_back(it.key());
        }
        std::sort(keys.begin(), keys.end());

        std::string result = "{";
        bool first = true;
        for (const auto& k : keys) {
            if (!first) result += ",";
            first = false;
            // key
            result += "\"";
            for (char c : k) {
                if (c == '"') result += "\\\"";
                else if (c == '\\') result += "\\\\";
                else if (c == '\n') result += "\\n";
                else if (c == '\r') result += "\\r";
                else if (c == '\t') result += "\\t";
                else result += c;
            }
            result += "\":";
            result += canonical_json(j[k]);
        }
        result += "}";
        return result;
    } else if (j.is_array()) {
        std::string result = "[";
        bool first = true;
        for (const auto& item : j) {
            if (!first) result += ",";
            first = false;
            result += canonical_json(item);
        }
        result += "]";
        return result;
    } else if (j.is_string()) {
        // Use nlohmann's dump which properly escapes
        return j.dump();
    } else {
        return j.dump();
    }
}

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    return std::string(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
}

static const char B64URL[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
static const char B64STD[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode_impl(const std::string& data, const char* alphabet, bool padding) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);
    unsigned char buf[3];
    int i = 0;
    for (unsigned char c : data) {
        buf[i++] = c;
        if (i == 3) {
            result += alphabet[(buf[0] >> 2) & 0x3F];
            result += alphabet[((buf[0] & 0x3) << 4) | ((buf[1] >> 4) & 0xF)];
            result += alphabet[((buf[1] & 0xF) << 2) | ((buf[2] >> 6) & 0x3)];
            result += alphabet[buf[2] & 0x3F];
            i = 0;
        }
    }
    if (i == 1) {
        result += alphabet[(buf[0] >> 2) & 0x3F];
        result += alphabet[(buf[0] & 0x3) << 4];
        if (padding) { result += '='; result += '='; }
    } else if (i == 2) {
        result += alphabet[(buf[0] >> 2) & 0x3F];
        result += alphabet[((buf[0] & 0x3) << 4) | ((buf[1] >> 4) & 0xF)];
        result += alphabet[(buf[1] & 0xF) << 2];
        if (padding) result += '=';
    }
    return result;
}

std::string base64url_encode(const std::string& data) {
    return base64_encode_impl(data, B64URL, false);
}

std::string base64_encode(const std::string& data) {
    return base64_encode_impl(data, B64STD, true);
}

std::string base64_decode(const std::string& data) {
    // Build decode table
    static const int decode_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,62,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };
    std::string result;
    int val = 0, bits = -8;
    for (unsigned char c : data) {
        if (c == '=') break;
        int d = decode_table[c];
        if (d == -1) continue;
        val = (val << 6) + d;
        bits += 6;
        if (bits >= 0) {
            result += static_cast<char>((val >> bits) & 0xFF);
            bits -= 8;
        }
    }
    return result;
}

std::string reference_hash(const json& event) {
    // Remove signatures and hashes fields for hashing
    json stripped = event;
    stripped.erase("signatures");
    stripped.erase("hashes");
    std::string canonical = canonical_json(stripped);
    std::string hash = sha256(canonical);
    return base64url_encode(hash);
}

} // namespace MatrixCrypto
