#include "matrix_server.h"
#include "config.h"
#include <sodium.h>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium\n";
        return 1;
    }

    std::string config_path = "config.json";
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    Config config = load_config(config_path);
    std::cout << "Loaded config: server_name=" << config.server_name
              << " port=" << config.port << "\n";

    MatrixServer server(config);
    server.start();
    return 0;
}
