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
├── fileOperations.c/h       # Handles all file interface commands
├── encryptionTools.c/h      # Database encryption/decryption
├── generate_rsa_keys.c      # RSA key pair generation utility
├── user_encryptor.c         # User database encryption tool
├── hashmap/                 # Third-party hashmap library
├── UserDirectory/           # Client-accesible directory for file handling
└── Makefile                 # Build configuration
```

## Setup

### 1. Build
```bash
make all
```

### 2. Create User Database
Create `users.txt` with format `accountID:username:password:email:address:phone number:authorityGroup(integer from 0-9)` (one per line):
```
1:alice:password123:alice@email.com:address1:phone#:9
2:bob:secretpass:bob@email.com:address2:phone#:4
```

Encrypt it:
```bash
./user_encryptor encrypt users.txt encrypted_users.txt myDatabasePassword
```
Replace names as you wish, but the encrypted file name must be changed in unified_server.c


### 3. Create a folder `RSAkeys/`. Then generate Server RSA Key:
```bash
# Generate server keys
./generate_rsa_keys server
```
Client keys are auto generated.

### 4. Create an emailConfig.json for ease of testing(sets default bcc email and sending email)
```
example confif file:
  {
    "sender": "<sender email>@gmail.com",
    "receiver": "<bcc email>@gmail.com",
    "password": "<generate app password via gmail>"
  }
```

If you do not want this functionality, set `useJSON = 0` in emailTest.c, and define a from email.

### 5. Run. The example encrypted_users.txt in the repository uses the password ```rabbit```
```bash
# Start server
./unified_server myDatabasePassword

# Connect clients
./unified_client <name1>
./unified_client <name2>
```

## Usage

### Authentication via Password
```
auth> /login <name1> <password1>
```

### Authentication via email: check your email for token
```
auth> /token <token>
```

### Chat Commands
```
> /nick <name>        # Change nickname
> /list               # Show connected users
> /quit               # End program
> /file               # Enter file handling mode
> Hello everyone!     # Send message
```

### File commands
```
> /help               # Lists usable file commands(like ls, cd, touch)
> /chat               # Switch back to chat mode
> /quit               # kill program
```

## Requirements

- Linux/Unix system
- OpenSSL library
- POSIX threads (pthread)


###Requirements for Scripts and Makefiles###
- Net-tools package for Linux(monitoring server during stress test)
- `Expect` command(for multi-user log in) 
- Clang compiler(for Makefile)
