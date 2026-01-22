cmake_minimum_required(VERSION 3.14)

project(Slime VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(SKIP_TESTS "Skip building and running tests" OFF)

# Find threads (required by httplib)
find_package(Threads REQUIRED)

# Main executable
add_executable(Slime src/main.cpp)
target_link_libraries(Slime PRIVATE Threads::Threads)

# Include directories
target_include_directories(Slime PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Testing (enabled by default)
if(NOT SKIP_TESTS)
    enable_testing()

    # Test executable (excluded from default build)
    add_executable(SlimeTests EXCLUDE_FROM_ALL tests/test_auth.cpp)
    target_include_directories(SlimeTests PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(SlimeTests PRIVATE Threads::Threads)

    # Add test
    add_test(NAME AuthTests COMMAND SlimeTests)

    # Create test runner script
    file(WRITE ${CMAKE_BINARY_DIR}/run_tests.sh "#!/bin/bash\n\
echo '========================================='\n\
echo 'Starting Matrix server for tests...'\n\
echo '========================================='\n\
${CMAKE_BINARY_DIR}/Slime > /tmp/slime_test.log 2>&1 &\n\
SERVER_PID=\\$!\n\
sleep 2\n\
echo ''\n\
echo '========================================='\n\
echo 'Running tests...'\n\
echo '========================================='\n\
cd ${CMAKE_BINARY_DIR}\n\
if ${CMAKE_CTEST_COMMAND} --output-on-failure; then\n\
    echo ''\n\
    echo '========================================='\n\
    echo 'All tests passed!'\n\
    echo '========================================='\n\
    kill \\$SERVER_PID 2>/dev/null || true\n\
    exit 0\n\
else\n\
    echo ''\n\
    echo '========================================='\n\
    echo 'Tests failed!'\n\
    echo '========================================='\n\
    kill \\$SERVER_PID 2>/dev/null || true\n\
    exit 1\n\
fi\n")

    # Make script executable
    file(CHMOD ${CMAKE_BINARY_DIR}/run_tests.sh
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)

    # Custom target to run tests with server
    add_custom_target(run_tests
        COMMAND ${CMAKE_BINARY_DIR}/run_tests.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        DEPENDS Slime SlimeTests
        COMMENT "Building and testing Slime Matrix server"
    )
else()
    message(STATUS "Tests are SKIPPED (SKIP_TESTS=ON)")
endif()

# Installation
install(TARGETS Slime DESTINATION bin)

# Print configuration
message(STATUS "")
message(STATUS "==========================================")
message(STATUS "Slime Matrix Server Configuration")
message(STATUS "==========================================")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build & Run Tests: ${SKIP_TESTS}")
message(STATUS "")
message(STATUS "Usage:")
if(NOT SKIP_TESTS)
    message(STATUS "  make           - Build server")
    message(STATUS "  make run_tests - Build and run tests")
else()
    message(STATUS "  make           - Build server only (tests skipped)")
endif()
message(STATUS "")
message(STATUS "To skip tests, run:")
message(STATUS "  cmake -DSKIP_TESTS=ON ..")
message(STATUS "==========================================")
message(STATUS "")
