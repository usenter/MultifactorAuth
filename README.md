# TCP Server/Client Project with Authentication (Linux)






## Project Structure

1. **`unified_server.c`** - Server supporting basic echo mode and chat mode with authentication
2. **`unified_client.c`** - Unified client with authentication support and message storage
3. **`simple_test_client.c`** - Simple test client for automated testing
4. **`auth_system.c/h`** - Authentication system implementation
5. **`encryptionTools.c/h`** - Decrypts user database file and securely loads into server
6. **`hashmap/`** - Tidwall's hashmap implementation in C https://github.com/tidwall/hashmap.c
7. **`userEncryptionTools/`** - Tools for you to manually encrypt and decrypt a text file

### Unified Server (`unified_server.c`)
- **Chat Mode**: Multi-client chat server with authentication and nicknames
- **Authentication**: Username/password login and registration
- **Password protected user database**: User:password info is decrypted and stored on startup
- **Command Line**: `./unified_server <password>` 

### Unified Client (`unified_client.c`)
- **Authentication Support**: Handles login/registration automatically
- **Chat Mode**: Interactive chat client with authentication
- **Message Storage**: Stores received messages in memory buffer
- **Command Line**: `./unified_client`after starting server


## Authentication System



### Authentication Commands
- `/login <username> <password>` - Login
- `/register <username> <password>` - Register new user
- Sessions expire after 5 minutes of inactivity

### How to Use:
1.  **Encrypt your private user.txt file** - ./user_encryptor encrypt <users.txt> encrypted_users.txt <password>. You can change the name of destination file, but you need change it in unified_server.c as well. 
2. **Start server**: `./unified_server <password>`
3. **Start client**: `./unified_client`
4. **Enter username and password** - using the /login command


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
make user_encryptor

# Clean build files
make clean
```



### Manual Execution
```bash
# Terminal 1: Start server
./unified_server <password>

# Terminal 2: Start client
./unified_client


```

## Features

### Unified Client Features
- **Automatic Authentication**: Handles login/registration seamlessly
- **Message Storage**: Stores up to 100 received messages in memory
- **Error Handling**: Handling of authentication failures

### Server Features
- **Multi-threaded**: Handles multiple clients simultaneously
- **Session Management**: Tracks authenticated users with timeouts
- **Hashmap Storage**: Efficient user storage and lookup
- **Persistent Users**: Saves/loads user data to/from encryted file
- **Hashing**: Password hashing (DJB2 algorithm)

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
./unified_server rabbit

# Terminal 2
./unified_client
# Log in with account

# Terminal 3
./unified_client
# Log in with different account
```


```
## Project File Structure

```
MultifactorAuth/
├── unified_server.c         # Secure authenticated chat server
├── unified_client.c         # Multi-mode client application
├── simple_test_client.c     # Basic test client (no auth)
├── auth_system.c/h          # Authentication and session management
├── encryptionTools.c/h      # Encryption library for server
├── userEncryptionTools/     # Standalone encryption tools
│   └── user_encryptor.c     # File encryption/decryption tool
├── hashmap/                 # Third-party hashmap library
│   ├── hashmap.c           # Hashmap implementation
│   └── hashmap.h           # Hashmap headers
├── Makefile                # Build configuration
├── README.md               # This documentation
├── users.txt               # Example user database (create manually)
└── encrypted_users.txt     # Encrypted database (generated)
``` 
