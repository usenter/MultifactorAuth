# TCP Server/Client Project with Authentication (Linux)

## Project Structure

1. **`unified_server.c`** - Server supporting basic echo mode and chat mode with authentication
2. **`unified_client.c`** - Unified client with authentication support and message storage
3. **`simple_test_client.c`** - Simple test client for automated testing
4. **`auth_system.c/h`** - Authentication system implementation

### Unified Server (`unified_server.c`)
- **Basic Mode**: Echo server requiring authentication before use
- **Chat Mode**: Multi-client chat server with authentication and nicknames
- **Authentication**: Username/password login and registration
- **Command Line**: `./unified_server basic` or `./unified_server chat`

### Unified Client (`unified_client.c`)
- **Authentication Support**: Handles login/registration automatically
- **Basic Mode**: Authenticates then sends test messages
- **Chat Mode(Default)**: Interactive chat client with authentication
- **Message Storage**: Stores received messages in memory buffer
- **Auto-Registration**: Tries to register if login fails
- **Command Line**: `./unified_client basic` or `./unified_client chat`

### Simple Test Client (`simple_test_client.c`)
- Automated testing client without authentication
- Useful for testing basic server functionality

## Authentication System



### Authentication Commands
- `/login <username> <password>` - Login
- `/register <username> <password>` - Register new user
- Sessions expire after 5 minutes of inactivity

### How to Use:
1. **Start server**: `./unified_server chat`
2. **Start client**: `./unified_client chat`
3. **Create users.txt and put usernames as <user>:<password>**
3. **Enter username and password** when prompted


**Chat Commands:**
- `/nick <name>` - Change nickname
- `/list` - List connected clients  
- `/quit` - Disconnect

**Security Notes:**
- Passwords are hashed for storage
- Sessions timeout after 5 minutes
- For production: use proper crypto hashing and SSL/TLS

## Building and Running

### Prerequisites
- Clang compiler
- POSIX threads library (pthread)
- Linux/Unix system

### Build Commands
```bash
# Build all executables
make all

# Build individual components
make unified_server
make unified_client
make simple_test_client

# Clean build files
make clean
```

### Run Commands
```bash
# Run server in basic mode
make run-server-basic

# Run server in chat mode
make run-server-chat

# Run client in basic mode
make run-client-basic

# Run client in chat mode
make run-client-chat

# Run simple test client
make run-test-client
```

### Manual Execution
```bash
# Terminal 1: Start server
./unified_server chat

# Terminal 2: Start client
./unified_client chat

# Terminal 3: Start simple test client
./simple_test_client
```

## Features

### Unified Client Features
- **Automatic Authentication**: Handles login/registration seamlessly
- **Message Storage**: Stores up to 100 received messages in memory
- **Dual Mode Support**: Works in both basic echo and chat modes
- **Error Handling**: Graceful handling of authentication failures
- **Interactive Interface**: User-friendly prompts and responses

### Server Features
- **Multi-threaded**: Handles multiple clients simultaneously
- **Session Management**: Tracks authenticated users with timeouts
- **Hashmap Storage**: Efficient user storage and lookup
- **Persistent Users**: Saves/loads user data to/from file
- **Secure Hashing**: Password hashing (DJB2 algorithm)

## Testing

### Basic Test
```bash
# Terminal 1
./unified_server basic

# Terminal 2
./unified_client basic
# Enter username when prompted
```

### Chat Test
```bash
# Terminal 1
./unified_server chat

# Terminal 2
./unified_client chat
# Enter username when prompted

# Terminal 3
./unified_client chat
# Enter different username
```

## File Structure
```
MultifactorAuth/
├── unified_server.c      # Main server implementation
├── unified_client.c      # Unified client with authentication
├── simple_test_client.c  # Basic test client
├── auth_system.c         # Authentication system
├── auth_system.h         # Authentication headers
├── hashmap/              # Hashmap library
│   ├── hashmap.c         # Hashmap implementation
│   └── hashmap.h         # Hashmap headers
├── Makefile             # Build configuration
├── README.md            # This file
└── users.txt            # User database (created at runtime)
``` 