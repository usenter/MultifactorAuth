# JWT Integration for MultifactorAuth

This directory contains an improved JWT system that provides partial tokens for different authentication stages, allowing clients to resume authentication without repeating completed steps.

## Features

- **Staged Authentication**: JWT tokens are issued at each auth milestone (password, email, full)
- **Token Versioning**: Automatic version increment prevents token reuse after auth progression
- **Stateless Verification**: Server doesn't store tokens, only verifies signatures and claims
- **Progressive Resume**: Clients can resume from any completed auth stage
- **Automatic Cleanup**: Token version management prevents old tokens from working

## Files

- `jwtOperations.h` - Header with JWT types, functions, and structures
- `jwtOperations.c` - Implementation of JWT operations
- `server_integration_example.c` - Example server integration code
- `client_integration_example.c` - Example client integration code
- `README.md` - This file

## JWT Token Structure

Each JWT contains these claims:
```json
{
  "sub": 123,                    // Account ID
  "username": "john",            // Username
  "stage": "password",           // Auth stage: "password", "email", "full"
  "ver": 2,                      // Token version (for revocation)
  "iat": 1640995200,             // Issued at timestamp
  "exp": 1640998800              // Expiration timestamp
}
```

## Authentication Stages

1. **JWT_TYPE_NONE** (0) - No authentication
2. **JWT_TYPE_PASSWORD** (1) - Password verified
3. **JWT_TYPE_EMAIL** (2) - Email token verified  
4. **JWT_TYPE_FULL** (3) - Fully authenticated

## Server Integration

### 1. Initialize JWT System

In `unified_server.c` main():
```c
#include "JWT_tools/jwtOperations.h"

// After other initialization
if (!init_jwt_system()) {
    printf("ERROR: JWT system initialization failed\n");
    exit(1);
}
```

### 2. Issue JWT After Password Verification

In `auth_system.c` `authenticate_user()`:
```c
if (verify_password(password, found_ptr->password_hash)) {
    // ... existing code ...
    
    // Issue JWT for password stage
    int current_version = jwt_get_current_version(account_id);
    char* token = jwt_issue_hs256_staged(account_id, username, 
                                        JWT_TYPE_PASSWORD, current_version, 900);
    if (token) {
        char jwt_msg[1200];
        snprintf(jwt_msg, sizeof(jwt_msg), "JWT %s\n", token);
        // Send to client (you'll need to pass client_socket)
        send(client_socket, jwt_msg, strlen(jwt_msg), 0);
        
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
}
```

### 3. Issue JWT After Full Authentication

In `unified_server.c` `promote_to_authenticated()`:
```c
// After sending AUTH_SUCCESS
user_t *user = find_user(account_id);
if (user) {
    int current_version = jwt_get_current_version(account_id);
    char* token = jwt_issue_hs256_staged(account_id, user->username, 
                                        JWT_TYPE_FULL, current_version, 3600);
    if (token) {
        char jwt_msg[1200];
        snprintf(jwt_msg, sizeof(jwt_msg), "JWT %s\n", token);
        send_secure(socket, jwt_msg, strlen(jwt_msg));
        
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
}
```

### 4. Handle Resume Commands

In `unified_server.c` auth thread (after RSA+ECDH):
```c
// After decrypt_inplace_if_needed(...)
if (strncmp(buffer, "/resume ", 8) == 0) {
    const char* jwt = buffer + 8;
    
    unsigned int acc = 0;
    jwt_type_t stage;
    int ver = 0;
    long iat = 0, exp = 0;
    char uname[64];
    
    if (jwt_verify_hs256(jwt, &acc, &stage, &ver, &iat, &exp, uname, sizeof(uname))) {
        // Token valid - check if we can resume from this stage
        if (stage == JWT_TYPE_FULL) {
            // Fully authenticated - promote directly
            session_t* sess = find_session(acc);
            if (sess) sess->auth_status = AUTH_FULLY_AUTHENTICATED;
            promote_to_authenticated(client_socket, (unsigned int)acc);
            continue;
        } else if (stage == JWT_TYPE_PASSWORD) {
            // Password verified - skip to email phase
            session_t* sess = find_session(acc);
            if (sess) sess->auth_status = AUTH_PASSWORD;
            const char* msg = "PHASE:EMAIL Password verified from JWT. Please enter email token.\n";
            send_secure(client_socket, msg, strlen(msg), 0);
            continue;
        }
    }
    
    // Token invalid or stage not suitable
    const char* msg = "AUTH_FAILED Invalid or expired token. Please /login again.\n";
    send_secure(client_socket, msg, strlen(msg), 0);
    continue;
}
```

### 5. Cleanup on Shutdown

In `unified_server.c` main():
```c
// Before exit
cleanup_jwt_system();
```

## Client Integration

### 1. Load JWT on Startup

In `unified_client.c` main():
```c
// After other initialization
load_jwt_token_from_file();
```

### 2. Capture JWT Tokens

In message handling loop:
```c
if (strncmp(buffer, "JWT ", 4) == 0) {
    store_jwt_token(buffer);
    continue;
}
```

### 3. Attempt Resume After RSA+ECDH

After RSA and ECDH are ready:
```c
if (rsa_completed && ecdh_ready) {
    if (has_valid_jwt_token()) {
        printf("Attempting to resume authentication with JWT token...\n");
        if (send_resume_command(client_socket)) {
            // Wait for server response
            continue;
        }
    }
    printf("Please login with /login <username> <password>\n");
}
```

### 4. Handle Resume Responses

```c
if (strstr(buffer, "AUTH_SUCCESS")) {
    if (strstr(buffer, "Resumed from JWT")) {
        printf("Successfully resumed authentication!\n");
        // Set appropriate auth flags
        return MSG_CONTINUE;
    }
}

if (strstr(buffer, "AUTH_FAILED")) {
    if (strstr(buffer, "Invalid or expired token")) {
        printf("JWT token expired or invalid, clearing...\n");
        clear_jwt_token();
        // Fall back to normal login
    }
}
```

### 5. Clear Token on Logout

```c
// On logout or auth failure
clear_jwt_token();
```

## Build Integration

### 1. Update Makefile

Add JWT tools to server build:
```makefile
# Add to OBJS
OBJS = ... jwtOperations.o

# Add compilation rule
jwtOperations.o: JWT_tools/jwtOperations.c JWT_tools/jwtOperations.h
	$(CC) $(CFLAGS) -c $< -o $@
```

### 2. Include Headers

In files that use JWT:
```c
#include "JWT_tools/jwtOperations.h"
```

## Security Features

- **HMAC-SHA256**: Uses server secret for signing
- **Token Versioning**: Automatic revocation on auth progression
- **Short TTLs**: Password stage (15 min), full auth (1 hour)
- **Stateless**: No server-side token storage
- **Automatic Cleanup**: Memory cleanup and version management

## Token Lifecycle

1. **Password Stage**: JWT issued after password verification (15 min TTL)
2. **Email Stage**: JWT issued after email verification (15 min TTL)  
3. **Full Auth**: JWT issued after complete authentication (1 hour TTL)
4. **Resume**: Client sends JWT, server verifies and resumes from appropriate stage
5. **Version Increment**: Each auth progression increments token version
6. **Automatic Expiry**: Tokens expire based on TTL

## Benefits

- **Faster Reconnects**: Skip completed auth steps
- **Better UX**: No repeated password/email prompts
- **Stateless**: No server-side session storage
- **Secure**: Cryptographic verification and automatic revocation
- **Flexible**: Resume from any completed stage

## Example Flow

1. User connects and completes RSA+ECDH
2. User logs in with password → receives password-stage JWT
3. User enters email token → receives full-auth JWT
4. User disconnects and reconnects
5. After RSA+ECDH, client sends `/resume <full_jwt>`
6. Server verifies JWT and promotes directly to chat
7. No password or email re-entry required

## Troubleshooting

- **JWT not working**: Check JWT secret file permissions and path
- **Resume failing**: Verify token hasn't expired and version matches
- **Build errors**: Ensure JWT tools are included in Makefile
- **Memory leaks**: Check that tokens are properly freed after sending

## Future Enhancements

- **Device Binding**: Include client public key hash in JWT
- **Role-Based**: Add permissions/roles to JWT claims
- **Audit Logging**: Log JWT usage for security monitoring
- **Rate Limiting**: Limit resume attempts per account