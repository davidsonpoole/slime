# Slime Matrix Server - Testing Guide

## Overview

The Slime Matrix server includes comprehensive integration tests for all authentication endpoints. Tests are built and run automatically by default using CMake.

## Quick Start

### Build and Run Server

```bash
cd build
cmake ..
make
./Slime
```

This will build the Matrix server.

### Run Tests

```bash
make run_tests
```

This will:
1. Build the Matrix server and tests (if needed)
2. Start the server in the background
3. Run all tests
4. Stop the server
5. Report results

### Build Without Tests

```bash
cd build
cmake -DSKIP_TESTS=ON ..
make
```

### Run Tests Manually

If you want to run tests against a server you're already running:

```bash
# Terminal 1: Start server
./Slime

# Terminal 2: Run tests
cd build
ctest --output-on-failure
```

## Test Coverage

The test suite covers:

### Server Discovery
- ✅ `.well-known/matrix/client` endpoint
- ✅ Homeserver configuration

### Registration
- ✅ Single-stage auth (m.login.dummy)
- ✅ Multi-stage auth flow (recaptcha + terms)
- ✅ Session management across stages
- ✅ Username validation
- ✅ Duplicate username prevention

### Login
- ✅ Password-based authentication
- ✅ Custom device ID support
- ✅ Invalid credentials handling
- ✅ Non-existent user handling

### Session Management
- ✅ Token validation (whoami endpoint)
- ✅ Logout functionality
- ✅ Token invalidation after logout
- ✅ Multiple concurrent sessions
- ✅ Device tracking

### Error Handling
- ✅ Invalid tokens
- ✅ Unknown login types
- ✅ Matrix-compliant error responses

## Running Specific Tests

### Run tests by tag

```bash
# Run only registration tests
./SlimeTests "[register]"

# Run login and session tests
./SlimeTests "[login],[session]"

# Run specific test case
./SlimeTests "Registration with dummy auth"
```

### Verbose output

```bash
./SlimeTests -s  # Show successful assertions
./SlimeTests -d yes  # Show test durations
```

## CMake Targets

| Target | Description |
|--------|-------------|
| `make` | Build server (default) |
| `make run_tests` | Build and run tests with server |
| `ctest` | Run tests (requires server running) |

## Test Results

### Success Output
```
=========================================
All tests passed!
=========================================
100% tests passed, 0 tests failed out of 1
```

### Failure Output
```
=========================================
Tests failed!
=========================================
The following tests FAILED:
    1 - AuthTests (Failed)
```

## Test Performance

Current test suite:
- **10 test cases**
- **64+ assertions**
- **~0.5 seconds** execution time
- **100% pass rate**

## Continuous Integration

For CI/CD pipelines:

```bash
# Build and test
cmake ..
make run_tests

# Check exit code
echo $?  # 0 = success, non-zero = failure
```
