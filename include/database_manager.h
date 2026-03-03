#pragma once

#include <string>
#include <vector>
#include <functional>
#include <stdexcept>
#include "../third_party/sqlite3.h"

class DatabaseManager {
public:
    explicit DatabaseManager(const std::string& db_path);
    ~DatabaseManager();

    // Non-copyable
    DatabaseManager(const DatabaseManager&) = delete;
    DatabaseManager& operator=(const DatabaseManager&) = delete;

    void exec(const std::string& sql);

    // Execute a query and call callback for each row
    // callback receives column names and values
    void query(const std::string& sql,
               const std::vector<std::string>& params,
               std::function<void(sqlite3_stmt*)> row_cb) const;

    // Execute a statement that modifies data; returns rows changed
    int execute(const std::string& sql, const std::vector<std::string>& params);

    // Get single text value or empty string
    std::string get_text(const std::string& sql, const std::vector<std::string>& params) const;

    // Get single int64 value or default
    int64_t get_int(const std::string& sql, const std::vector<std::string>& params, int64_t def = 0) const;

    sqlite3* db() const { return db_; }

private:
    sqlite3* db_;
    void init_schema();
};
