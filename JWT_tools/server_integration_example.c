/*
 * Server Integration Example for JWT Operations
 * 
 * This file shows exactly how to integrate JWT tokens into the existing
 * authentication flow in unified_server.c and auth_system.c
 */

#include "jwtOperations.h"
#include "auth_system.h"
#include <stdio.h>
#include <string.h>

// Example: Initialize JWT system during server startup
int init_jwt_system(void) {
    // Initialize JWT secret (generate if not exists)
    if (!jwt_init_secret("config/jwt_secret.bin")) {
        printf("ERROR: Failed to initialize JWT secret\n");
        return 0;
    }
    printf("JWT system initialized successfully\n");
    return 1;
}

// Example: Issue JWT token after password authentication
void issue_password_jwt(int account_id, const char* username) {
    // Get current token version for this account
    int current_version = jwt_get_current_version(account_id);
    
    // Issue JWT for password stage (15 minute TTL)
    char* token = jwt_issue_hs256_staged(account_id, username, 
                                        JWT_TYPE_PASSWORD, current_version, 900);
    
    if (token) {
        // Send JWT to client
        char jwt_msg[1200];
        snprintf(jwt_msg, sizeof(jwt_msg), "JWT %s\n", token);
        
        // Find client socket and send
        // Note: You'll need to pass the client_socket to this function
        // send(client_socket, jwt_msg, strlen(jwt_msg), 0);
        
        printf("Issued password-stage JWT for account %d\n", account_id);
        
        // Clean up token
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
}

// Example: Issue JWT token after full authentication
void issue_full_auth_jwt(int account_id, const char* username) {
    // Get current token version for this account
    int current_version = jwt_get_current_version(account_id);
    
    // Issue JWT for full authentication (1 hour TTL)
    char* token = jwt_issue_hs256_staged(account_id, username, 
                                        JWT_TYPE_FULL, current_version, 3600);
    
    if (token) {
        // Send JWT to client
        char jwt_msg[1200];
        snprintf(jwt_msg, sizeof(jwt_msg), "JWT %s\n", token);
        
        // Find client socket and send
        // Note: You'll need to pass the client_socket to this function
        // send(client_socket, jwt_msg, strlen(jwt_msg), 0);
        
        printf("Issued full-auth JWT for account %d\n", account_id);
        
        // Clean up token
        OPENSSL_cleanse(token, strlen(token));
        free(token);
    }
}

// Example: Handle /resume command from client
int handle_resume_command(const char* buffer, int client_socket, int* account_id_out) {
    if (strncmp(buffer, "/resume ", 8) != 0) {
        return 0; // Not a resume command
    }
    
    const char* jwt_token = buffer + 8;
    
    // Verify the JWT token
    unsigned int account_id;
    jwt_type_t stage;
    int token_version;
    long iat, exp;
    char username[64];
    
    if (!jwt_verify_hs256(jwt_token, &account_id, &stage, &token_version, 
                          &iat, &exp, username, sizeof(username))) {
        // Token invalid - send failure message
        const char* msg = "AUTH_FAILED Invalid or expired token. Please /login again.\n";
        send(client_socket, msg, strlen(msg), 0);
        return 0;
    }
    
    // Token is valid - check if we can resume from this stage
    if (stage == JWT_TYPE_FULL) {
        // Fully authenticated - promote directly to chat
        printf("Resuming full authentication for account %d\n", account_id);
        
        // Update session to fully authenticated
        session_t* session = find_session(account_id);
        if (session) {
            session->auth_status = AUTH_FULLY_AUTHENTICATED;
        }
        
        // Send success message
        const char* msg = "AUTH_SUCCESS Resumed from JWT token. Welcome back!\n";
        send(client_socket, msg, strlen(msg), 0);
        
        if (account_id_out) *account_id_out = (int)account_id;
        return 1;
        
    } else if (stage == JWT_TYPE_PASSWORD) {
        // Password verified but email not done - skip to email phase
        printf("Resuming from password stage for account %d\n", account_id);
        
        // Update session to password authenticated
        session_t* session = find_session(account_id);
        if (session) {
            session->auth_status = AUTH_PASSWORD;
        }
        
        // Send email phase message
        const char* msg = "PHASE:EMAIL Password verified from JWT. Please enter email token.\n";
        send(client_socket, msg, strlen(msg), 0);
        
        if (account_id_out) *account_id_out = (int)account_id;
        return 1;
        
    } else {
        // Invalid stage for resume
        const char* msg = "AUTH_FAILED Token stage not suitable for resume. Please /login again.\n";
        send(client_socket, msg, strlen(msg), 0);
        return 0;
    }
}

// Example: Integration into existing auth flow
// Add this to auth_system.c after password verification succeeds
void integrate_jwt_after_password(int account_id, const char* username) {
    // After password is verified, issue JWT
    issue_password_jwt(account_id, username);
}

// Example: Integration into existing promotion flow
// Add this to unified_server.c in promote_to_authenticated function
void integrate_jwt_after_full_auth(int account_id, const char* username) {
    // After full authentication, issue JWT
    issue_full_auth_jwt(account_id, username);
}

// Example: Cleanup on server shutdown
void cleanup_jwt_system(void) {
    jwt_cleanup_states();
    printf("JWT system cleaned up\n");
}

/*
 * INTEGRATION STEPS:
 * 
 * 1. In unified_server.c main(), add:
 *    if (!init_jwt_system()) exit(1);
 * 
 * 2. In auth_system.c authenticate_user(), after password verification:
 *    if (verify_password(...)) {
 *        // ... existing code ...
 *        integrate_jwt_after_password(account_id, username);
 *    }
 * 
 * 3. In unified_server.c promote_to_authenticated(), after AUTH_SUCCESS:
 *    // ... existing code ...
 *    integrate_jwt_after_full_auth(account_id, user->username);
 * 
 * 4. In unified_server.c auth thread, add resume command handling:
 *    if (handle_resume_command(buffer, client_socket, &account_id)) {
 *        // Resume successful - continue with existing logic
 *        continue;
 *    }
 * 
 * 5. In unified_server.c main(), before exit:
 *    cleanup_jwt_system();
 */
