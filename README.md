## MultifactorAuth

Authenticated chat server with RSA authentication, password protection, and an encrypted user database.

## Features

- **Authentication**: RSA cryptographic challenge + username/password
- **Encrypted User Database**: AES-256-CBC encrypted user storage  
- **Session Management**: Automatic timeout and cleanup
- **DOS Protection**: Creates tunable IP Table rules to limit DOS attacks
- **Multi-Client Chat**: Nicknames, user list, message broadcasting

### Project layout

```
MultifactorAuth/
├── unified_server.c                 # Server
├── unified_client.c                 # Client (auto RSA keygen on first run)
├── auth_system.c / auth_system.h    # Auth flows and checks
├── encryption_tools/                # AES, key ops (encryptionOperations.c/.h)
├── fileOperation_tools/             # File handling (sandboxed user dir)
├── emailHandling_tools/             # Email token delivery utilities
├── config_tools/                    # Server config loader (JSON)
├── socketHandling_tools/            # Socket helpers
├── IPTable_tools/                   # IPTables rules helpers
├── REST_tools/                      # rest_client and server REST helpers
├── userDBencryption_tools/          # user_encryptor utility
├── RSAkeys/                         # Generated keys/certs (created at runtime)
├── UserDirectory/                   # Client-accessible working directory
├── TestingScripts/                  # Stress and utility scripts
├── logs/                            # Runtime logs (e.g., logs/server.log)
└── Makefile                         # Build targets
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

### 4. Create an emailConfig.json for ease of testing(sets default bcc email and sending email). A template is provided in ```config_tools/```

If you do not want to do this, set `useJSON = 0` in emailTest.c, and define a from email.

### 5. Run. The example encrypted_users.txt in the repository uses the password ```rabbit```
```bash
# Start server
./unified_server myDatabasePassword

# Connect clients
./unified_client <name1>
./unified_client <name2>
```

## Client usage

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

## REST client
Interactive helper to query status/logs and toggle enhanced logging.
```bash
./rest_client [config_tools/serverConf.json]

# Inside the REPL:
query username <username>
query account <id>
logs username <username> [start="YYYY-MM-DD HH:MM" end="YYYY-MM-DD HH:MM"]
logs account <id> [start="YYYY-MM-DD HH:MM" end="YYYY-MM-DD HH:MM"]
enhance username <username>
enhance account <id>
disable
status
```

## Requirements

- Linux/Unix system
- OpenSSL library
- POSIX threads (pthread)


###Requirements for Scripts and Makefiles###
- Net-tools package for Linux(monitoring server during stress test)
- `Expect` command(for multi-user log in) 
- Clang compiler(for Makefile)

### Make targets
- all: unified_server, unified_client, encryptionOperations, user_encryptor, generate_rsa_keys, rest_client
- clean: remove binaries/objects

### Logs
- Server and client logs under `logs/` (e.g., `logs/server.log`). Client may generate debug reports on failures.
