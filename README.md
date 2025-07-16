# TCP Server/Client Project with Authentication

## Project Structure

1. **`unified_server.c`** - Server supporting basic echo mode and chat mode with authentication
2. **`unified_client.c`** - Original client without authentication
3. **`authenticated_client.c`** - New client with authentication support
4. **`simple_test_client.c`** - Simple test client for automated testing
5. **`auth_system.c/h`** - Authentication system implementation

### Unified Server (`unified_server.c`)
- **Basic Mode**: Echo server requiring authentication before use
- **Chat Mode**: Multi-client chat server with authentication and nicknames
- **Authentication**: Username/password login and registration
- **Command Line**: `./unified_server.exe basic` or `./unified_server.exe chat`

### Authenticated Client (`authenticated_client.c`)
- **Basic Mode**: Authenticates then sends test messages
- **Chat Mode**: Interactive chat client with authentication
- **Auto-login**: Prompts for username, uses default password "password123"
- **Command Line**: `./authenticated_client.exe basic` or `./authenticated_client.exe chat`

### Original Client (`unified_client.c`)
- **Basic Mode**: Sends predefined test messages (no auth required)
- **Chat Mode**: Interactive chat client (no auth required)
- **Command Line**: `./unified_client.exe basic` or `./unified_client.exe chat`

### Simple Test Client (`simple_test_client.c`)
- Automated testing client without authentication
- Useful for testing basic server functionality

## Authentication System

### Default Users
- `admin` / `admin123`
- `user1` / `password1` 
- `user2` / `password2`

### Authentication Commands
- `AUTH_LOGIN username password` - Login
- `AUTH_REGISTER username password` - Register new user
- Sessions expire after 5 minutes of inactivity

### How to Use:
1. **Start server**: `./unified_server.exe chat`
2. **Start authenticated client**: `./authenticated_client.exe chat`
3. **Enter username** when prompted
4. **Client auto-authenticates** with password "password123"

**Chat Commands:**
- `/nick <name>` - Change nickname
- `/list` - List connected clients  
- `/quit` - Disconnect

**Security Notes:**
- Passwords are hashed for storage
- Sessions timeout after 5 minutes
- For production: use proper crypto hashing and SSL/TLS 