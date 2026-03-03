#pragma once

#include <string>
#include "json.h"

using json = nlohmann::json;

namespace MatrixCrypto {

// Produce canonical (sorted-key) JSON string
std::string canonical_json(const json& j);

// Compute reference hash (base64url, no padding) for an event
std::string reference_hash(const json& event);

// Compute SHA-256 of data and return raw bytes
std::string sha256(const std::string& data);

// base64url encode (no padding)
std::string base64url_encode(const std::string& data);

// standard base64 encode
std::string base64_encode(const std::string& data);

// standard base64 decode
std::string base64_decode(const std::string& data);

} // namespace MatrixCrypto
