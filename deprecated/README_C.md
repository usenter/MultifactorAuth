# TCP Server and Client in C

This directory contains C implementations of the TCP server and client programs.

## Files

- `tcp_server.c` - Multi-threaded TCP server
- `tcp_client.c` - Simple TCP client for testing
- `multi_client_test.c` - Multi-client test program
- `Makefile` - Compilation rules

## Compilation

### Using Makefile (Recommended)
```bash
# Compile all programs
make

# Or compile individually
make tcp_server
make tcp_client
make multi_client_test

# Clean compiled files
make clean
```

### Manual Compilation
```bash
# Compile server
gcc -Wall -Wextra -std=c99 -pthread -o tcp_server tcp_server.c

# Compile client
gcc -Wall -Wextra -std=c99 -pthread -o tcp_client tcp_client.c

# Compile multi-client test
gcc -Wall -Wextra -std=c99 -pthread -o multi_client_test multi_client_test.c
```

## Usage

### 1. Start the Server
```bash
./tcp_server
```
The server will start listening on port 12345.

### 2. Test with Single Client
```bash
./tcp_client
```

### 3. Test with Multiple Clients
```bash
# Run 5 clients simultaneously
./multi_client_test 5

# Run default 3 clients
./multi_client_test
```

### 4. Manual Multiple Clients
Open multiple terminals and run:
```bash
# Terminal 1: Server
./tcp_server

# Terminal 2: Client 1
./tcp_client

# Terminal 3: Client 2
./tcp_client

# Terminal 4: Client 3
./tcp_client
```

## Features

### Server Features
- Multi-threaded to handle multiple clients simultaneously
- Echo service (sends back received messages)
- Automatic client connection handling
- Proper cleanup on client disconnect

### Client Features
- Connects to localhost:12345
- Sends predefined test messages
- Receives and displays server responses
- Automatic disconnection after sending messages

### Multi-Client Test Features
- Runs multiple clients in separate threads
- Each client sends unique messages with client ID
- Random delays between messages
- Configurable number of clients via command line

## Key Differences from Python Version

### Memory Management
- Manual memory allocation/deallocation with `malloc()` and `free()`
- Need to handle memory leaks carefully

### Error Handling
- More explicit error checking required
- Use of `perror()` for system error messages
- Return value checking for all system calls

### Threading
- POSIX threads (`pthread`) instead of Python's threading
- Manual thread creation and cleanup
- Thread detachment for automatic cleanup

### Socket Programming
- Lower-level socket API
- Manual buffer management
- Explicit byte counting and null termination

## System Requirements

- GCC compiler
- POSIX-compliant system (Linux, macOS, WSL)
- pthread library (usually included with GCC)

## Troubleshooting

### Compilation Issues
- Ensure you have GCC installed
- On some systems, you may need to install build tools
- For Windows, use WSL or MinGW

### Runtime Issues
- Make sure port 12345 is not in use
- Check firewall settings
- Ensure server is running before starting clients

### Memory Issues
- The code includes proper memory management
- Use tools like Valgrind to check for memory leaks
- Monitor system resources when running many clients 