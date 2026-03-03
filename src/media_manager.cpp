#include "media_manager.h"
#include "utils.h"
#include <fstream>
#include <filesystem>
#include <stdexcept>
#include <iostream>

namespace fs = std::filesystem;

MediaManager::MediaManager(const std::string& media_path, const std::string& server_name,
                            DatabaseManager& db)
    : media_path_(media_path), server_name_(server_name), db_(db) {
    // Create media directory if it doesn't exist
    try {
        fs::create_directories(media_path_);
    } catch (const std::exception& e) {
        std::cerr << "Warning: could not create media directory: " << e.what() << std::endl;
    }
}

std::string MediaManager::generate_media_id() const {
    // 24-char random alphanumeric
    static const char chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::string id;
    id.reserve(24);
    std::string rand = Utils::generate_random_string(24);
    // Map hex chars to alphanumeric (simple enough)
    for (char c : rand) {
        int idx = (c >= '0' && c <= '9') ? (c - '0') : (10 + c - 'a');
        id += chars[idx % 62];
    }
    return id;
}

std::string MediaManager::file_path(const std::string& media_id) const {
    return media_path_ + "/" + media_id;
}

std::string MediaManager::upload(const std::string& data,
                                  const std::string& content_type,
                                  const std::string& filename,
                                  const std::string& uploader) {
    std::string media_id = generate_media_id();
    std::string path = file_path(media_id);

    std::ofstream f(path, std::ios::binary);
    if (!f.is_open()) {
        throw std::runtime_error("Could not open media file for writing: " + path);
    }
    f.write(data.data(), data.size());
    f.close();

    db_.execute(
        "INSERT OR REPLACE INTO media(media_id, filename, content_type, size, uploader) "
        "VALUES(?,?,?,?,?)",
        {media_id, filename, content_type, std::to_string(data.size()), uploader});

    return "mxc://" + server_name_ + "/" + media_id;
}

std::pair<std::string, std::string> MediaManager::download(
    const std::string& server_name, const std::string& media_id) const {

    // Only serve local media
    if (server_name != server_name_) {
        return {"", ""};
    }

    std::string path = file_path(media_id);
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return {"", ""};

    std::string data((std::istreambuf_iterator<char>(f)),
                      std::istreambuf_iterator<char>());

    std::string ct = db_.get_text(
        "SELECT content_type FROM media WHERE media_id=?", {media_id});
    if (ct.empty()) ct = "application/octet-stream";

    return {data, ct};
}

bool MediaManager::exists(const std::string& media_id) const {
    std::string found = db_.get_text(
        "SELECT media_id FROM media WHERE media_id=?", {media_id});
    return !found.empty();
}
