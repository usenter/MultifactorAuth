/*
 * Client Integration Example for JWT Operations
 * 
 * This file shows exactly how to integrate JWT tokens into the existing
 * client authentication flow in unified_client.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// JWT token storage for the client
static char g_jwt_token[2048] = {0};
static int g_jwt_stage = 0; // 0=none, 1=password, 2=email, 3=full

// JWT stage constants (should match server)
#define JWT_STAGE_NONE 0
#define JWT_STAGE_PASSWORD 1
#define JWT_STAGE_EMAIL 2
#define JWT_STAGE_FULL 3

// Example: Store JWT token received from server
void store_jwt_token(const char* jwt_line) {
    if (strncmp(jwt_line, "JWT ", 4) != 0) {
        return; // Not a JWT line
    }
    
    const char* token = jwt_line + 4;
    
    // Store the token
    strncpy(g_jwt_token, token, sizeof(g_jwt_token) - 1);
    g_jwt_token[sizeof(g_jwt_token) - 1] = '\0';
    
    // Remove trailing newline/CR if present
    char* end = strpbrk(g_jwt_token, "\r\n");
    if (end) *end = '\0';
    
    printf("Stored JWT token for resume\n");
    
    // Optional: Save to file for persistence across client restarts
    FILE* f = fopen("client_jwt.txt", "w");
    if (f) {
        fprintf(f, "%s\n", g_jwt_token);
        fclose(f);
        printf("JWT token saved to file\n");
    }
}

// Example: Load JWT token from file on client startup
void load_jwt_token_from_file(void) {
    FILE* f = fopen("client_jwt.txt", "r");
    if (!f) {
        printf("No saved JWT token found\n");
        return;
    }
    
    if (fgets(g_jwt_token, sizeof(g_jwt_token), f)) {
        // Remove trailing newline/CR
        char* end = strpbrk(g_jwt_token, "\r\n");
        if (end) *end = '\0';
        
        printf("Loaded JWT token from file\n");
    }
    
    fclose(f);
}

// Example: Send resume command to server
int send_resume_command(int client_socket) {
    if (g_jwt_token[0] == '\0') {
        printf("No JWT token available for resume\n");
        return 0;
    }
    
    char resume_cmd[2048];
    snprintf(resume_cmd, sizeof(resume_cmd), "/resume %s\n", g_jwt_token);
    
    // Send the resume command
    if (send(client_socket, resume_cmd, strlen(resume_cmd), 0) < 0) {
        printf("Failed to send resume command\n");
        return 0;
    }
    
    printf("Sent resume command with JWT token\n");
    return 1;
}

// Example: Clear JWT token (e.g., on logout or auth failure)
void clear_jwt_token(void) {
    memset(g_jwt_token, 0, sizeof(g_jwt_token));
    g_jwt_stage = JWT_STAGE_NONE;
    
    // Remove saved file
    unlink("client_jwt.txt");
    printf("JWT token cleared\n");
}

// Example: Check if we have a valid JWT token for resume
int has_valid_jwt_token(void) {
    return (g_jwt_token[0] != '\0');
}

// Example: Integration into existing client auth flow
// Add this to unified_client.c in the main authentication loop

/*
 * INTEGRATION STEPS FOR CLIENT:
 * 
 * 1. In main() or initialization, add:
 *    load_jwt_token_from_file();
 * 
 * 2. In the message handling loop, add JWT token capture:
 *    if (strncmp(buffer, "JWT ", 4) == 0) {
 *        store_jwt_token(buffer);
 *        continue;
 *    }
 * 
 * 3. After RSA+ECDH are ready, try resume before prompting for login:
 *    if (rsa_completed && ecdh_ready) {
 *        if (has_valid_jwt_token()) {
 *            printf("Attempting to resume authentication with JWT token...\n");
 *            if (send_resume_command(client_socket)) {
 *                // Wait for server response
 *                // If AUTH_SUCCESS, we're done
 *                // If AUTH_FAILED, fall back to normal login
 *                continue;
 *            }
 *        }
 *        printf("Please login with /login <username> <password>\n");
 *    }
 * 
 * 4. On logout or auth failure, clear the token:
 *    clear_jwt_token();
 * 
 * 5. Handle server responses to resume command:
 *    if (strstr(buffer, "AUTH_SUCCESS")) {
 *        if (strstr(buffer, "Resumed from JWT")) {
 *            printf("Successfully resumed authentication!\n");
 *            // Set appropriate auth flags based on resume
 *            return MSG_CONTINUE;
 *        }
 *    }
 *    if (strstr(buffer, "AUTH_FAILED")) {
 *        if (strstr(buffer, "Invalid or expired token")) {
 *            printf("JWT token expired or invalid, clearing...\n");
 *            clear_jwt_token();
 *            // Fall back to normal login flow
 *        }
 *    }
 */

// Example: Enhanced message handling for JWT integration
typedef enum {
    MSG_PROCESSED,    // Message handled, show prompt
    MSG_CONTINUE,     // Message handled, don't show prompt
    MSG_EXIT,         // Exit the loop
    MSG_JWT_RECEIVED, // JWT token received
    MSG_RESUME_ATTEMPT // Resume attempt made
} MessageResult;

MessageResult handle_jwt_messages(const char* buffer) {
    // Handle JWT token reception
    if (strncmp(buffer, "JWT ", 4) == 0) {
        store_jwt_token(buffer);
        return MSG_JWT_RECEIVED;
    }
    
    // Handle resume command responses
    if (strstr(buffer, "AUTH_SUCCESS")) {
        if (strstr(buffer, "Resumed from JWT")) {
            printf("Successfully resumed authentication with JWT token!\n");
            return MSG_CONTINUE;
        }
    }
    
    if (strstr(buffer, "AUTH_FAILED")) {
        if (strstr(buffer, "Invalid or expired token")) {
            printf("JWT token expired or invalid, clearing...\n");
            clear_jwt_token();
            return MSG_CONTINUE;
        }
    }
    
    if (strstr(buffer, "PHASE:EMAIL")) {
        if (strstr(buffer, "Password verified from JWT")) {
            printf("Resumed to email verification phase\n");
            return MSG_CONTINUE;
        }
    }
    
    return MSG_NOT_HANDLED;
}

/*
 * COMPLETE CLIENT FLOW:
 * 
 * 1. Client connects and completes RSA+ECDH handshake
 * 2. Client checks if JWT token exists
 * 3. If yes, sends /resume <jwt> command
 * 4. Server verifies JWT and responds:
 *    - AUTH_SUCCESS if fully authenticated
 *    - PHASE:EMAIL if password verified but email pending
 *    - AUTH_FAILED if token invalid/expired
 * 5. Client handles response and either:
 *    - Proceeds to chat (full auth)
 *    - Continues with email verification
 *    - Falls back to normal login flow
 * 6. During normal auth, client receives JWT tokens at each stage
 * 7. Client stores latest JWT for future resume attempts
 */
