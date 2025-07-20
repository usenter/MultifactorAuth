# MultifactorAuth - Secure Chat Server

Authenticated chat server with RSA two-factor authentication and encrypted user database.

## Features

- **Two-Factor Authentication**: RSA cryptographic challenge + username/password
- **Encrypted User Database**: AES-256-CBC encrypted user storage  
- **Session Management**: Automatic timeout and cleanup
- **Multi-Client Chat**: Nicknames, user list, message broadcasting

## Project Structure

```
MultifactorAuth/
├── unified_server.c         # Secure authenticated chat server
├── unified_client.c         # Chat client with automatic RSA auth
├── auth_system.c/h          # Authentication and RSA implementation
├── encryptionTools.c/h      # Database encryption/decryption
├── generate_rsa_keys.c      # RSA key pair generation utility
├── user_encryptor.c         # User database encryption tool
├── hashmap/                 # Third-party hashmap library
└── Makefile                 # Build configuration
```

## Setup

### 1. Build
```bash
make all
```

### 2. Create User Database
Create `users.txt` with format `username:password` (one per line):
```
alice:password123
bob:secretpass
```

Encrypt it:
```bash
./user_encryptor encrypt users.txt encrypted_users.txt myDatabasePassword
```
Replace names as you wish, but the encrypted file name must be changed in unified_server.c


### 3. Create a folder ####RSAkeys/####. Then generate RSA Keys:
```bash
# Generate server keys
./generate_rsa_keys server

# Generate client keys (one per client)
./generate_rsa_keys client <name>
./generate_rsa_keys client <name>
```

### 4. Run
```bash
# Start server
./unified_server myDatabasePassword

# Connect clients
./unified_client alice
./unified_client bob
```

## Usage

### Authentication
```
auth> /login alice password123
auth> /register newuser newpassword
```

### Chat Commands
```
> /nick Alice          # Change nickname
> /list               # Show connected users
> /quit               # Leave chat
> Hello everyone!     # Send message
```

## Requirements

- Linux/Unix system
- OpenSSL library
- POSIX threads (pthread)
- Clang compiler

