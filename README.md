# MultifactorAuth - Secure Chat Server

Authenticated chat server with RSA authentication, password protection, and an encrypted user database.

## Features

- **Authentication**: RSA cryptographic challenge + username/password
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
Create `users.txt` with format `accountID:username:password:email:address:phone number` (one per line):
```
alice:password123
bob:secretpass
```

Encrypt it:
```bash
./user_encryptor encrypt users.txt encrypted_users.txt myDatabasePassword
```
Replace names as you wish, but the encrypted file name must be changed in unified_server.c


### 3. Create a folder `RSAkeys/`. Then generate RSA Keys:
```bash
# Generate server keys
./generate_rsa_keys server

# Generate client keys (one per client)
./generate_rsa_keys client <name1>
./generate_rsa_keys client <name2>
```

### 4. Run. The example encrypted_users.txt in the repository uses the password '''rabbit'''
```bash
# Start server
./unified_server myDatabasePassword

# Connect clients
./unified_client <name1>
./unified_client <name2>
```

## Usage

### Authentication
```
auth> /login <name1> <password1>
auth> /register newuser newpassword
```

### Chat Commands
```
> /nick <name>        # Change nickname
> /list               # Show connected users
> /quit               # Leave chat
> Hello everyone!     # Send message
```

## Requirements

- Linux/Unix system
- OpenSSL library
- POSIX threads (pthread)
- Clang compiler

