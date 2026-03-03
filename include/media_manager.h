#pragma once

#include <string>
#include "database_manager.h"
#include "json.h"

using json = nlohmann::json;

class MediaManager {
public:
    MediaManager(const std::string& media_path, const std::string& server_name,
                 DatabaseManager& db);

    // Returns mxc URI on success, empty on failure
    std::string upload(const std::string& data, const std::string& content_type,
                       const std::string& filename, const std::string& uploader);

    // Returns file data + content_type; empty data = not found
    std::pair<std::string, std::string> download(const std::string& server_name,
                                                  const std::string& media_id) const;

    // Returns true if media exists
    bool exists(const std::string& media_id) const;

    const std::string& media_path() const { return media_path_; }
    const std::string& server_name() const { return server_name_; }

private:
    std::string media_path_;
    std::string server_name_;
    DatabaseManager& db_;

    std::string generate_media_id() const;
    std::string file_path(const std::string& media_id) const;
};
