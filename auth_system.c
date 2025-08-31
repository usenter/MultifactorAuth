#include "auth_system.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include "hashmap/uthash.h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/crypto.h>
#include "JWT_tools/jwtOperations.h"


// Global variables
user_t *user_map = NULL;
session_t *session_map = NULL;  // Maps account_id -> session_t
username_t *username_map = NULL;
pthread_mutex_t user_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t session_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t username_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rsa_system_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;


static int user_count = 0;
static int session_count = 0;
 // number of divisions for permissions

// RSA Authentication global variables
static rsa_keypair_t server_keys = {NULL, NULL};
static int rsa_system_initialized = 0;


// Function to check if enhanced logging should be applied for a specific account ID
int should_apply_enhanced_logging_for_account_id(unsigned int account_id) {
    if (account_id <= 0) return 0;
    
    // Find user by account_id and check enhanced logging flag
    user_t *user = find_user(account_id);
    if (user && user->enhanced_logging_enabled) {
        return 1;
    }
    
    return 0;
}

// Function to enable enhanced logging for an account ID
void enable_enhanced_logging_for_account_id(unsigned int account_id) {
    if (account_id <= 0) return;
    
    user_t *user = find_user(account_id);
    if (user) {
        user->enhanced_logging_enabled = 1;
        printf("Enhanced logging enabled for account ID: %d (username: %s)\n", account_id, user->username);
    }
}

// Function to disable enhanced logging for an account ID
void disable_enhanced_logging_for_account_id(unsigned int account_id) {
    if (account_id <= 0) return;
    
    user_t *user = find_user(account_id);
    if (user) {
        user->enhanced_logging_enabled = 0;
        printf("Enhanced logging disabled for account ID: %d (username: %s)\n", account_id, user->username);
    }
}

// Function to get enhanced logging status for an account ID
int get_account_enhanced_logging_status(unsigned int account_id) {
    if (account_id <= 0) return 0;
    
    user_t *user = find_user(account_id);
    if (user) {
        return user->enhanced_logging_enabled;
    }
    return 0;
}

void FILE_LOG(const char* message){
    pthread_mutex_lock(&log_mutex);
    
    // Always log to main server log
    FILE* file = fopen(SERVER_LOG_FILE, "a");
    if(file){
        time_t now = time(NULL);
        char time_str[20];
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
        fprintf(file, "[%s] ", time_str);
        fprintf(file, "%s", message);
        fclose(file);
    }
    
    // Check if this message contains an account ID and if enhanced logging is enabled
    // Extract account ID from message if it contains [ID:number] pattern
    const char *id_marker = strstr(message, "[ID:");
    if (id_marker) {
        const char *id_start = id_marker + 4; // Skip "[ID:"
        const char *id_end = strchr(id_start, ']');
        if (id_end) {
            // Extract account ID
            char id_str[16];
            int id_len = id_end - id_start;
            if (id_len < sizeof(id_str)) {
                strncpy(id_str, id_start, id_len);
                id_str[id_len] = '\0';
                unsigned int account_id = atoi(id_str);
                
                                    if (account_id > 0) {
                        // Check if this account ID should get enhanced logging
                        if (should_apply_enhanced_logging_for_account_id(account_id)) {
                        // Find username for this account ID
                        username_t *uname_entry = find_username_by_account_id(account_id);
                        if (uname_entry) {
                            // Create enhanced log entry
                            char user_log_path[256];
                            snprintf(user_log_path, sizeof(user_log_path), "logs/enhanced_%s.log", uname_entry->username);
                            
                            FILE* enhanced_file = fopen(user_log_path, "a");
                            if(enhanced_file){
                                time_t now = time(NULL);
                                char time_str[20];
                                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
                                fprintf(enhanced_file, "[%s][ENHANCED][%s][ID:%d] ", time_str, uname_entry->username, account_id);
                                fprintf(enhanced_file, "%s", message);
                                fclose(enhanced_file);
                            }
                        }
                    }
                }
            }
        }
    }
    
    pthread_mutex_unlock(&log_mutex);
}



// Simple hash function (in production, use a proper cryptographic hash)
void hash_password(const char* password, char* hash) {
    unsigned long hash_val = 5381;
    int c;
    
    while ((c = *password++)) {
        hash_val = ((hash_val << 5) + hash_val) + c; // hash * 33 + c
    }
    
    sprintf(hash, "%08lx", hash_val);
}
// Verify password against hash
int verify_password(const char* password, const char* hash) {
    char computed_hash[MAX_HASH_LEN];
    hash_password(password, computed_hash);

    return strcmp(computed_hash, hash) == 0;
}

int init_encrypted_auth_system(char* userFile, char* key) {
    user_map = NULL;
    session_map = NULL;
    user_count = 0;
    session_count = 0;
    
    return load_users_from_encrypted_file(userFile, key);
}

int init_email_system(char* email_file) {
    char log_message[BUFFER_SIZE];
    FILE_LOG("[INFO][AUTH_SYSTEM] Initializing email system...\n");
    
    // Check if email is disabled in server config
    extern int is_email_disabled(void);
    if (is_email_disabled()) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Email system disabled in server configuration\n");
        FILE_LOG(log_message);
        return 1; // Not an error, just disabled
    }
    
    // Initialize email configuration
    if (!init_email_config()) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Failed to initialize email configuration\n");
        FILE_LOG(log_message);
        return 0;
    }
    sprintf(log_message, "[INFO][AUTH_SYSTEM] Email configuration initialized\n");
    FILE_LOG(log_message);
    FILE* file = fopen(email_file, "r");
    if (!file) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] No lockout status file found at %s\n", email_file);
        FILE_LOG(log_message);
        return 1; // Not an error condition
    }
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Reading in lockout status file\n");
    FILE_LOG(log_message);
    char line[1024];
    time_t now = time(NULL);
    int success = 1;

    while (fgets(line, sizeof(line), file)) {
        int account_id, seconds_remaining;
        
        // Parse line with validation (format: "account_id:seconds_remaining")
        if (sscanf(line, "%d:%d", &account_id, &seconds_remaining) != 2) {
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM] Warning: Invalid format in line: %s", line);
            FILE_LOG(log_message);
            printf("Warning: Invalid format in line: %s", line);
            continue;
        }
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Parsed line: %d:%d\n", account_id, account_id, seconds_remaining);
        FILE_LOG(log_message);

        // Skip if no lockout time remaining
        if (seconds_remaining <= 0) {
            continue;
        }
        session_t *session = NULL;
        // Create or get session with proper locking
        HASH_FIND_INT(session_map, &account_id, session);
        
        if (!session) {
            if (!create_auth_session(account_id)) {
                snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] Failed to create session\n", account_id);
                FILE_LOG(log_message);
                continue;
            }
            HASH_FIND_INT(session_map, &account_id, session);
        }
        
        if (session) {
            // Convert relative seconds remaining to absolute unlock time
            session->lockout_info.lockout_start_time = now + seconds_remaining;
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Restored lockout - will unlock in %d seconds (at time %ld)\n", 
                   account_id, seconds_remaining, session->lockout_info.lockout_start_time);
            FILE_LOG(log_message);
        }
        
        
    }

    fclose(file);
    
    // Clear the file since we've loaded all statuses
    file = fopen(email_file, "w");
    if (file) {
        fclose(file);
    }
    
    return success;
}

int add_user(int account_id, const char* username, const char* password) {
    user_t *user = malloc(sizeof(user_t));
    char log_message[BUFFER_SIZE];
    if(!user) { 
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Failed to allocate memory for user\n", account_id);
        FILE_LOG(log_message);
        return 0;
    }

    user->account_id = account_id;
    strncpy(user->username, username, MAX_USERNAME_LEN - 1);
    user->username[MAX_USERNAME_LEN - 1] = '\0';
    hash_password(password, user->password_hash);
    user->active = 1;

    // Use server config for max users
    extern int get_max_users(void);
    int max_users = get_max_users();
    if (user_count >= max_users) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] User count is at the maximum (%d)\n", max_users);
        FILE_LOG(log_message);
        return 0; // No space
    }
    if(find_user(account_id) == NULL) {
        pthread_mutex_lock(&user_map_mutex);
        HASH_ADD_INT(user_map, account_id, user);
        pthread_mutex_unlock(&user_map_mutex);
        user_count++;
    }
    

    else{
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] User already exists\n", account_id);
        FILE_LOG(log_message);
        cleanup_user(user);
        return 0;
    }   

    
    return 1; // Success
}

user_t* find_user(int account_id) {
    user_t *user = NULL;
    HASH_FIND_INT(user_map, &account_id, user);
    return user;
}

int authenticate_user(const char* username, const char* password, int account_id) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Authenticating user %s\n", account_id, username);
    FILE_LOG(log_message);
    
    // Check if password authentication is disabled
    extern int is_password_disabled(void);
    if (is_password_disabled()) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Password authentication disabled, skipping\n", account_id);
        FILE_LOG(log_message);
        return 1; // Skip password auth
    }
    
    // Get current session with proper locking
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
   
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Authenticating user\n", account_id);
    FILE_LOG(log_message);
    if (session) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Session auth_status: %d\n", account_id, session->auth_status);
        FILE_LOG(log_message);
    }
    
    if (!session) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] No active session found\n", account_id);
        FILE_LOG(log_message);
        return 0;
    }
    
    // Check RSA authentication
    extern int is_rsa_disabled(void);
    if (!is_rsa_disabled() && rsa_system_initialized && !(session->auth_status & AUTH_RSA)) {
        printf("SECURITY BLOCK: RSA authentication required but not completed for user: %s from socket %d\n", 
               username, account_id);
        return 0;
    }
    
    // Verify user exists and is active
    user_t *found_ptr = NULL;
    pthread_mutex_lock(&user_map_mutex);
    HASH_FIND_INT(user_map, &account_id, found_ptr);
    pthread_mutex_unlock(&user_map_mutex);
    
    if (!found_ptr || !found_ptr->active) {
        printf("User not found or inactive for account %d\n", account_id);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] User not found or inactive\n", account_id);
        FILE_LOG(log_message);
        return 0;
    }
    
    // Check username matches
    if (strncmp(username, found_ptr->username, MAX_USERNAME_LEN) != 0) {
        printf("Username mismatch: provided '%s', expected '%s' for account_id %d\n", 
               username, found_ptr->username, account_id);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Username mismatch: provided '%s', expected '%s'\n", account_id, username, found_ptr->username);
        FILE_LOG(log_message);
        return 0;
    }
    
    // Verify password
    snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_SYSTEM][ID:%d] Verifying password for user '%s' (found user: '%s', account_id: %d)\n", 
             account_id, username, found_ptr->username, found_ptr->account_id);
    FILE_LOG(log_message);
    
    if (!verify_password(password, found_ptr->password_hash)) {
        printf("Password incorrect for user: %s from socket %d\n", username, account_id);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Password incorrect for user: %s (expected user: %s)\n", 
                 account_id, username, found_ptr->username);
        FILE_LOG(log_message);
        return 0;
    }
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_SYSTEM][ID:%d] Password verification SUCCEEDED for user '%s'\n", 
             account_id, username);
    FILE_LOG(log_message);
    
    // Update session with password authentication
   
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Setting AUTH_PASSWORD for account %d (previous status: %d)\n", account_id, account_id, session->auth_status);
    FILE_LOG(log_message);
    session->auth_status |= AUTH_PASSWORD;
    
    
    // Verify the session was updated correctly
    session_t *verify_session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, verify_session);
    if (verify_session) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Verified session auth_status after update: %d\n", account_id, verify_session->auth_status);
        FILE_LOG(log_message);
    }
    pthread_mutex_unlock(&session_map_mutex);
    
    // Check if email verification is required and user has email
    if (found_ptr->email && is_email_required()) {
        sendEmailVerification(session);
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Email verification sent\n", account_id);
        FILE_LOG(log_message);
        return 2; // Special return code: password verified, email token sent
    } else if (found_ptr->email && !is_email_required()) {
        // Email verification disabled - automatically promote to fully authenticated
        session->auth_status |= AUTH_EMAIL;
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Email verification disabled - auto-promoted to fully authenticated\n", account_id);
        FILE_LOG(log_message);
        return 1; // Password verified, email auto-verified
    }
    
    return 1; // Password verified, no email verification needed
}

int create_session(int account_id) {
    if (!session_map) {
        return 0;
    }
    
    // Check if session already exists (from RSA phase)
    session_t *existing_session = NULL;
    HASH_FIND_INT(session_map, &account_id, existing_session);
    
    if (existing_session) {
        // Update existing session with password authentication
        existing_session->auth_status |= AUTH_PASSWORD;
        return 1;
    }
    
    // Create new session
    session_t *session = malloc(sizeof(session_t));
    if (!session) {
        return 0;
    }
    
    session->account_id = account_id;
    session->user = find_user(account_id);
    session->login_time = time(NULL);
    session->auth_status = AUTH_PASSWORD;  // Set password authentication flag
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    
    pthread_mutex_lock(&session_map_mutex);
    HASH_ADD_INT(session_map, account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    session_count++;
    
    
    return 1; // Success
}

void remove_session(int account_id) {
    if (!session_map) {
        return;
    }
    
    session_t *found = NULL;
    HASH_FIND_INT(session_map, &account_id, found);
    if(found && found->auth_status & AUTH_STATUS_LOCKED){
        found->user->active = 0;
        return;
    }
    if (found && !(found->auth_status & AUTH_STATUS_LOCKED)) { // Only proceed if not locked
        pthread_mutex_lock(&session_map_mutex);
        HASH_DEL(session_map, found);
        pthread_mutex_unlock(&session_map_mutex);
        cleanup_session(found);
        session_count--;
    }
    
}

int update_session(int account_id, const session_t* updated_session) {
    if (!session_map || !updated_session) {
        return 0;
    }
    
    session_t *found = NULL;
    HASH_FIND_INT(session_map, &account_id, found);
    if (found) {
        found->login_time = updated_session->login_time;
        found->auth_status = updated_session->auth_status;
        memcpy(found->challenge, updated_session->challenge, RSA_CHALLENGE_SIZE);
        return 1;
    }
    return 0;
}

session_t* find_session(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    return session;
}

//Functions for verifying user
int generateVerificationCode(const char* username) {
    // Create a seed using username and current time
    unsigned int seed = 0;
    const char* ptr = username;
    while (*ptr) {
        seed = seed * 31 + *ptr;
        ptr++;
    }
    seed = seed ^ (unsigned int)time(NULL);
    
    // Use this thread's random number generator to avoid conflicts
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    seed = seed ^ ((unsigned int)ts.tv_nsec);
    
    srand(seed);
    
    // Generate a number between 100000 and 999999 (6 digits)
    return 100000 + (rand() % 900000);
}

void sendEmailVerification(session_t* session){
    // Allocate memory for email payload
    char log_message[BUFFER_SIZE];
    emailContent_t *email_payload = malloc(sizeof(emailContent_t));
    if (!email_payload) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Failed to allocate memory for email payload\n");
        FILE_LOG(log_message);
        return;
    }
    
    // Initialize the structure
    memset(email_payload, 0, sizeof(emailContent_t));
    
    // Allocate memory for strings
    email_payload->TO = strdup(session->user->email);
    char subject[1024];
    snprintf(subject, 1024, "Verification code for chat server for %s", session->user->username);
    email_payload->subject = strdup(subject);
    email_payload->body = malloc(1024);
    
    if (!email_payload->TO || !email_payload->subject || !email_payload->body) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Failed to allocate memory for email content\n");
        FILE_LOG(log_message);
        cleanup_email_content(email_payload);
        free(email_payload); // Free the structure itself
        return;
    }
    
    // Generate token and reset token lifetime
    session->email_token.token = generateVerificationCode(session->user->username);
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Generated token: %d for user %s\n", session->account_id, session->email_token.token, session->user->username);
    FILE_LOG(log_message);
    session->email_token.created_time = time(NULL); 
    
    
    // Format email body
    snprintf(email_payload->body, 1024, 
             "Hello %s. Your verification code is: %d\nPlease enter this code with the /token command to verify your account.", 
             session->user->username, session->email_token.token);
    
    // Send email
    char* email_result = send_email(email_payload);
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d]  %s\n", session->account_id, email_result);
    FILE_LOG(log_message);
    //free(email_result);
    cleanup_email_content(email_payload);
    free(email_payload); // Free the structure itself
}

// New authentication flow functions
int create_auth_session(int account_id) {
    // Check if session already exists
    session_t *existing_session = NULL;
    HASH_FIND_INT(session_map, &account_id, existing_session);
    
    if (existing_session) {
        // Session already exists - only reset if this is a new login attempt
        // Check if user is trying to start fresh (by checking if they're fully authenticated)
        if (existing_session->auth_status == AUTH_FULLY_AUTHENTICATED) {
            // User is already authenticated, no need to reset
            existing_session->login_time = time(NULL);
            return 1;
        } else {
            // User has partial authentication - only reset if it's a completely new login
            // Don't reset the auth status as it may have partial progress
            existing_session->login_time = time(NULL);
            return 1;
        }
    }
    
    // Create new session
    session_t *session = malloc(sizeof(session_t));
    if (!session) {
        return 0;
    }
    
    session->account_id = account_id;
    session->user = find_user(account_id);
    session->login_time = time(NULL);
    session->auth_status = AUTH_NONE;  // Start with no authentication
    session->lockout_info.failed_attempts = 0;
    session->lockout_info.is_locked = 0;
    session->lockout_info.lockout_start_time = 0;
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    memset(&session->email_token, 0, sizeof(email_token_t));
    session->ecdh_keypair = NULL;
    memset(session->session_key, 0, sizeof(session->session_key));
    memset(session->ecdh_peer_pub, 0, sizeof(session->ecdh_peer_pub));
    session->ecdh_peer_pub_len = 0;
    
    pthread_mutex_lock(&session_map_mutex);
    HASH_ADD_INT(session_map, account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    session_count++;

    return 1;
}

// Reset auth session for a fresh login attempt
int reset_auth_session(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session) {
        // No session exists, create one
        return create_auth_session(account_id);
    }
    
    // Reset session state for fresh authentication
    session->auth_status = AUTH_NONE;
    session->login_time = time(NULL);
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    memset(&session->email_token, 0, sizeof(email_token_t));
    
    // Reset lockout info if not persistently locked
    session->lockout_info.failed_attempts = 0;
    session->lockout_info.is_locked = 0;
    
    // Ensure ECDH material is cleared for a fresh handshake on new connections
    reset_session_ecdh(account_id);

    return 1;
}

// Get current authentication status
auth_flags_t get_auth_status(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session) {
        return AUTH_NONE;
    }
    return session->auth_status;
}

// Check if lockout has expired and send unlock message if needed
int check_and_send_unlock_message(int account_id, char* response, size_t response_size) {
    session_t *session = find_session(account_id);
    if (session && (session->auth_status & AUTH_STATUS_LOCKED)) {
        int remaining_time = get_remaining_lockout_time(account_id);
        if (remaining_time <= 0) {
            // Lockout expired - unlock the account
            session->auth_status = AUTH_RSA;
            session->lockout_info.is_locked = 0;
            session->lockout_info.failed_attempts = 0;
            session->lockout_info.lockout_start_time = 0;
            
            user_t *user = find_user(account_id);
            if (user) {
                snprintf(response, response_size, "%s Account %s is unlocked. Please login with: /login <username> <password>\n", 
                        AUTH_STATUS_UNLOCKED, user->username);
                return 1; // Unlock message sent
            }
        }
    }
    return 0; // No unlock message needed
}

// Process authentication message based on current status
auth_result_t process_auth_message(const char* message, int account_id, char* response, size_t response_size, char* jwt_token_out, size_t jwt_token_size, int* has_jwt_token_out) {
    auth_result_t result;
    char log_message[BUFFER_SIZE];
    memset(&result, 0, sizeof(result)); // Initialize result struct

    // Initialize output parameters
    if (jwt_token_out && jwt_token_size > 0) {
        jwt_token_out[0] = '\0';
    }
    if (has_jwt_token_out) {
        *has_jwt_token_out = 0;
    }
    
    if (!message || !response) {
        result.success = 0;
        result.authenticated = 0;
        return result;
    }
    
    // Always initialize response buffer to prevent contamination between users
    response[0] = '\0';
    
    // Check for lockout expiration first
    if (check_and_send_unlock_message(account_id, response, response_size)) {
        result.success = 1;
        result.authenticated = 0;
        strncpy(result.response, response, sizeof(result.response) - 1);
        result.response[sizeof(result.response) - 1] = '\0';
        return result; // Unlock message sent
    }
    
    auth_flags_t status = get_auth_status(account_id);
    
    // Check if fully authenticated
    if (status == AUTH_FULLY_AUTHENTICATED) {
        snprintf(result.response, sizeof(result.response), "You are already fully authenticated.");
        result.success = 1;
        result.authenticated = 1;
        return result;
    }
    
    // RSA authentication phase
    if (!(status & AUTH_RSA)) {
        if (is_rsa_command(message)) {
            rsa_challenge_result_t rsa_result = process_rsa_command(message, account_id);
            if (rsa_result.success && strstr(rsa_result.response, "RSA authentication successful")) {
                snprintf(result.response, sizeof(result.response), "%s You may now login with your username and password.", rsa_result.response);
                result.success = 1;
                result.authenticated = 0;
                return result;
            } else {
                snprintf(result.response, sizeof(result.response), "PHASE:RSA %s", rsa_result.response);
                result.success = 1;
                result.authenticated = 0;
                return result;
            }
        }
        snprintf(result.response, sizeof(result.response), "RSA authentication required first. Use /rsa_start to begin.");
        result.success = 1;
        result.authenticated = 0;
        return result;
    }

    // Password authentication phase
    else if (!(status & AUTH_PASSWORD)) {
        if (is_auth_command(message)) {
            char temp_jwt_token[2048];
            int temp_has_jwt_token = 0;
            auth_result_t auth_result = process_auth_command(message, account_id, temp_jwt_token, sizeof(temp_jwt_token), &temp_has_jwt_token);
            // Use the response from process_auth_command directly - it already handles email verification
            snprintf(result.response, sizeof(result.response), "%s", auth_result.response);
            result.success = 1;
            result.authenticated = 0;

            // Copy JWT token data to output parameters if any
            if (temp_has_jwt_token && strlen(temp_jwt_token) > 0) {
                if (jwt_token_out && jwt_token_size > 0) {
                    strncpy(jwt_token_out, temp_jwt_token, jwt_token_size - 1);
                    jwt_token_out[jwt_token_size - 1] = '\0';
                }
                if (has_jwt_token_out) {
                    *has_jwt_token_out = 1;
                }
            }

            return result;
        }
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] In password phase,  '%s' is not an appropriate auth command\n", account_id, message);
        FILE_LOG(log_message);
        snprintf(result.response, sizeof(result.response), "PHASE:PASSWORD Please login with: /login <username> <password>");
        result.success = 1;
        result.authenticated = 0;
        return result;
    }
    // Email token authentication phase
    else if (!(status & AUTH_EMAIL)) {  // Only allow token commands after password auth
        snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_SYSTEM][ID:%d] In email phase, auth_status=%d, message='%s'\n",
                account_id, status, message);
        FILE_LOG(log_message);

        // Check lockout status FIRST before processing any token commands
        if (status & AUTH_STATUS_LOCKED) {
            int remaining = get_remaining_lockout_time(account_id);
            if(remaining > 0){
                snprintf(result.response, sizeof(result.response), 
                        "%s Account is locked for %d more seconds due to too many failed attempts.\n", 
                        AUTH_LOCKED, remaining);
                result.success = 1;
                result.authenticated = 0;
                return result;
            }
            else{
                //unlocking takes back to password auth (keep RSA, remove password and email)
                session_t *session = find_session(account_id);
                if(session){
                    session->auth_status = AUTH_RSA; 
                }
            }
        }
        
        // Check if this is a token command - if so, process it (lockout check already done above)
        if (is_token_command(message)) {
            if (strncmp(message, AUTH_TOKEN, strlen(AUTH_TOKEN)) == 0) {
                char token[EMAIL_TOKEN_LENGTH + 1];
                const char* token_start = message + strlen(AUTH_TOKEN);
                
                // Skip any whitespace
                while (*token_start == ' ' || *token_start == '\t') {
                    token_start++;
                }
                
                // Check if we have exactly 6 digits
                if (strlen(token_start) != EMAIL_TOKEN_LENGTH || 
                    sscanf(token_start, "%6s", token) != 1 ||
                    strlen(token) != EMAIL_TOKEN_LENGTH) {
                    snprintf(result.response, sizeof(result.response), 
                            "%s Invalid format. Use: /token <6-digit-code>\n", 
                            AUTH_FAILED);
                    result.success = 1;
                    result.authenticated = 0;
                    return result;
                }
                

                // Verify token
                int verify_result = verify_email_token(account_id, token);

                if (verify_result == 1) {
                    // Get user for JWT token issuance
                    user_t *user = find_user(account_id);
                    if (!user) {
                        snprintf(result.response, sizeof(result.response), "%s Internal error - user not found", AUTH_FAILED);
                        result.success = 0;
                        result.authenticated = 0;
                        return result;
                    }

                    // Issue JWT token for full authentication
                    int current_version = jwt_get_current_version(account_id);
                    char* jwt_token = jwt_issue_hs256_staged(account_id, user->username,
                                                        JWT_TYPE_FULL, current_version, 3600);
                    if (jwt_token) {
                        // Copy JWT token to output parameters so server can send it
                        if (jwt_token_out && jwt_token_size > 0) {
                            strncpy(jwt_token_out, jwt_token, jwt_token_size - 1);
                            jwt_token_out[jwt_token_size - 1] = '\0';
                        }
                        if (has_jwt_token_out) {
                            *has_jwt_token_out = 1;
                        }

                        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Created full-auth JWT for account %d, length=%zu, has_jwt_token=%d\n",
                                account_id, account_id, strlen(jwt_token), has_jwt_token_out ? *has_jwt_token_out : 0);
                        FILE_LOG(log_message);

                        // Clean up token
                        OPENSSL_cleanse(jwt_token, strlen(jwt_token));
                        free(jwt_token);
                    } else {
                        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] Failed to issue JWT for account %d\n", account_id, account_id);
                        FILE_LOG(log_message);
                    }

                    // Wait a little bit before sending AUTH_SUCCESS
                    usleep(500000); // 500ms delay

                    snprintf(result.response, sizeof(result.response),
                            "PHASE:EMAIL EMAIL_AUTH_SUCCESS Email token verified successfully! You are now fully authenticated.\n");
                    result.success = 1;
                    result.authenticated = 1;
                    return result;
                } 
                else if (verify_result == -3) {
                    snprintf(result.response, sizeof(result.response), 
                            "PHASE:TOKEN TOKEN_EXPIRED Token has expired. Use /newToken to request a new one.\n");
                    result.success = 1;
                    result.authenticated = 0;
                    return result;
                } 
                else if (verify_result == -2) {
                    int remaining = get_remaining_lockout_time(account_id);
                    snprintf(result.response, sizeof(result.response), 
                            "%s[AUTH System] Account locked for %d seconds due to too many failed attempts.\n", 
                            AUTH_LOCKED, remaining);
                    result.success = 1;
                    result.authenticated = 0;
                    result.response[sizeof(result.response) - 1] = '\0';
                    return result;
                } 
                else {
                    snprintf(result.response, sizeof(result.response), 
                            "PHASE:TOKEN TOKEN_FAIL Invalid token. Please check your email and try again. %d attempts remaining.\n", 
                            MAX_TOKEN_ATTEMPTS - get_current_failed_attempts(account_id));
                    result.success = 1;
                    result.authenticated = 0;
                    return result;
                }
            } 
            else if (strncmp(message, AUTH_NEW_TOKEN, strlen(AUTH_NEW_TOKEN)) == 0) {
                if (generate_new_token(account_id)) {
                    snprintf(result.response, sizeof(result.response), 
                            "PHASE:TOKEN TOKEN_GEN_SUCCESS A new token has been sent to your email. You have %d attempts remaining.\n", 
                            MAX_TOKEN_ATTEMPTS - get_current_failed_attempts(account_id));
                } else {
                    snprintf(result.response, sizeof(result.response), 
                            "%s Failed to generate new token.\n", 
                            AUTH_FAILED);
                }
                result.success = 1;
                result.authenticated = 0;
                return result;
            }
            else if(strstr(message, "/login") != NULL){
                snprintf(result.response, sizeof(result.response), "PHASE:EMAIL Password verified.");
                result.success = 1;
                result.authenticated = 0;
                return result;
            }
            else{
                snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] Command '%s' is not recognized as a token command\n", account_id, message);
                FILE_LOG(log_message);
                snprintf(result.response, sizeof(result.response), 
                        "PHASE:EMAIL Please enter your email token with: /token <code> or request a new one with: /newToken");
                result.success = 1;
                result.authenticated = 0;
                return result;
            }
        }
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] Command '%s' is not recognized as a token command\n", account_id, message);
        FILE_LOG(log_message);
        snprintf(result.response, sizeof(result.response), 
                "PHASE:EMAIL Please enter your email token with: /token <code> or request a new one with: /newToken");
        result.success = 1;
        result.authenticated = 0;
        return result;
    }
    else{
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM][ID:%d] Not in email token auth phase\n!(status&auth_email) = %d\nstatus&password = %d\n", account_id, !(status & AUTH_EMAIL), (status & AUTH_PASSWORD));
        FILE_LOG(log_message);
    }
    
    
    // Check if we're missing any authentication steps
    const char* missing_step = NULL;
    if (!(status & AUTH_RSA)) {
        missing_step = "RSA authentication";
    } else if (!(status & AUTH_PASSWORD)) {
        missing_step = "password verification";
    } else if (!(status & AUTH_EMAIL)) {
        missing_step = "email verification";
    }
    
    user_t *found_ptr = NULL;
    HASH_FIND_INT(user_map, &account_id, found_ptr);
    char username[MAX_USERNAME_LEN];
    strcpy(username, found_ptr->username);
    
    if (missing_step) {
        if (!(status & AUTH_RSA)) {
            snprintf(response, response_size, "PHASE:RSA %s Please complete %s first.", AUTH_FAILED, missing_step);
        } else if (!(status & AUTH_PASSWORD)) {
            snprintf(response, response_size, "PHASE:PASSWORD %s Please complete %s first.", AUTH_FAILED, missing_step);
        } else if (!(status & AUTH_EMAIL)) {
            snprintf(response, response_size, "PHASE:EMAIL %s Please complete %s first.", AUTH_FAILED, missing_step);
        }
        result.success = 1;
        result.authenticated = 0;
        return result;
    }
    snprintf(result.response, sizeof(result.response), "Authentication error occurred.\n");
    result.success = 1;
    result.authenticated = 0;
    return result;
}

// Generate new email token
int generate_new_token(int account_id) {
    // Get session
    char log_message[BUFFER_SIZE];
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session || !session->user || !session->user->email) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] No valid session or email\n", account_id);
        FILE_LOG(log_message);
        return 0;
    }
    
    // Send new verification email
    sendEmailVerification(session);
    return 1;
}

// Get remaining lockout time in seconds
int get_remaining_lockout_time(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session) return 0;
    
    time_t now = time(NULL);
    time_t lockout_end_time = session->lockout_info.lockout_start_time + LOCKOUT_DURATION;
    
    if (now < lockout_end_time) {
        return (int)(lockout_end_time - now);
    }
    return 0; // Lockout expired
}

// Handle failed token attempt and return whether user is now locked out
int handle_failed_token_attempt(int account_id) {
    record_failed_attempt(account_id);
    char response[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    
    // Get current failed attempts count
    int current_attempts = get_current_failed_attempts(account_id);
    
    // Check if this failure caused a lockout (should happen at 3 attempts)
    if (current_attempts >= 3) {
        int remaining_time = check_persistent_lockout(account_id);
        snprintf(response, sizeof(response), 
                 "%s Account locked for %d seconds due to too many failed attempts.\n", 
                 AUTH_LOCKED, remaining_time);
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Account locked for %d seconds due to too many failed attempts (attempts: %d).\n", account_id, remaining_time, current_attempts);
        FILE_LOG(log_message);
        return 0; // Authentication failed
    } else {
        snprintf(response, sizeof(response), 
                 "AUTH_TOKEN_FAIL Invalid token. You have %d attempts remaining before lockout.\n", 
                 3 - current_attempts);
        return 0;
    }
}
int get_current_failed_attempts(unsigned int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (session) {
        return session->lockout_info.failed_attempts;
    }
    return 0;
}


// Reset token attempts counter
void reset_token_attempts(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (session) {
        session->lockout_info.failed_attempts = 0;
    }
}

// Verify email token
int verify_email_token(int account_id, const char* token) {
    char log_message[BUFFER_SIZE];
    if (!token) return 0;
    
    session_t *session = find_session(account_id);
    if (!session) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] No session found\n", account_id);
        FILE_LOG(log_message);
        return 0;
    }
    
    // Check if token has expired (1 minute)
    time_t now = time(NULL);
    if (now - session->email_token.created_time > get_email_token_expiry()) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Token expired\n", account_id);
        FILE_LOG(log_message);
        return -3; // Token expired
    }
    
    // Convert string token to integer
    int token_value;
    if (sscanf(token, "%d", &token_value) != 1) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Invalid token format\n", account_id);
        FILE_LOG(log_message);
        if (handle_failed_token_attempt(account_id)) {
            return -2; // User is now locked out
        }
        return 0;
    }
    
    // Verify token
    if (token_value == session->email_token.token) {
        // Token is correct
        session->auth_status |= AUTH_EMAIL;
        reset_token_attempts(account_id); // Reset attempts on success
        
        // Clear any lockout status on successful authentication
        session->lockout_info.failed_attempts = 0;
        session->lockout_info.lockout_start_time = 0;
        session->lockout_info.is_locked = 0;
        session->auth_status = AUTH_FULLY_AUTHENTICATED; 
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Token verified successfully\n", account_id);
        FILE_LOG(log_message);
        return 1;
    }
    
    // Token is incorrect
    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Invalid token provided for account %d\n", account_id, account_id);
    FILE_LOG(log_message);
    if (handle_failed_token_attempt(account_id)) {
        return -2; // User is now locked out
    }
    return 0;
}

// Check if a user is RSA authenticated
int is_rsa_authenticated(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session || !(session->auth_status & AUTH_RSA)) {
        return 0;
    }
    return 1;
}

// Check if a user is authenticated
int is_authenticated(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session || !(session->auth_status & AUTH_FULLY_AUTHENTICATED)) {
        return 0;
    }
    
    // Check if session has expired
    if (time(NULL) - session->login_time > AUTH_TIMEOUT) {
        remove_session(account_id);
        return 0;
    }
    
    // Check if email authentication is required and completed
    
    
    return 1;
}

// Clean up expired sessions
void cleanup_expired_sessions(void) {
    if (!session_map) {
        return; // Nothing to clean up
    }
    
    session_t *current, *temp;
    pthread_mutex_lock(&session_map_mutex);
    HASH_ITER(hh, session_map, current, temp) {
       HASH_DEL(session_map, current);
       cleanup_session(current);
       session_count--;
    }
    pthread_mutex_unlock(&session_map_mutex);
}

username_t* find_username(const char* username) {
    username_t *found = NULL;
    HASH_FIND_STR(username_map, username, found);
    return found;
}

// Function to find username by account ID
username_t* find_username_by_account_id(unsigned int account_id) {
    if (account_id <= 0) return NULL;
    
    username_t* entry;
    pthread_mutex_lock(&username_map_mutex);
    
    // Iterate through username map to find matching account_id
    for (entry = username_map; entry != NULL; entry = entry->hh.next) {
        if (entry->account_id == account_id) {
            pthread_mutex_unlock(&username_map_mutex);
            return entry;
        }
    }
    
    pthread_mutex_unlock(&username_map_mutex);
    return NULL;
}

int load_users_from_encrypted_file(const char* encrypted_filename, const char* key) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Loading users from encrypted file: %s\n", encrypted_filename);
    FILE_LOG(log_message);
    
    // Decrypt file directly to memory using library function
    decryption_result_t decrypt_result = decrypt_file_to_memory(encrypted_filename, key);
    
    if (!decrypt_result.success) {
        snprintf(log_message, sizeof(log_message), "[FATAL][AUTH_SYSTEM] Failed to decrypt file: %s\n", encrypted_filename);
        FILE_LOG(log_message);
        return 0;
    }
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Successfully decrypted file, processing users...\n");
    FILE_LOG(log_message);
    
    unsigned int account_id;
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];  // Plaintext password from decrypted data
    char email[MAX_EMAIL_LEN];
    char address[MAX_ADDRESS_LEN];
    char phone_number[MAX_PHONE_NUMBER_LEN];
    //format for permString is:
    //auth0 auth1 auth2 auth3 auth4 auth5 auth6 auth7 auth8 auth9 '\0'
    // 0     0     0     0     0     0     0     0     0     0    
    int auth; // the auth level of the user is the index of the perm string we need to look at 
    int loaded_count = 0;
    
    // Parse decrypted data line by line
    char* data = decrypt_result.data;
    char* line_start = data;
    char* line_end;
    
    extern int get_max_users(void);
    int max_users = get_max_users();
    while ((line_end = strchr(line_start, '\n')) != NULL && user_count < max_users) {
        // Null-terminate the line temporarily
        *line_end = '\0';
        
        // Remove carriage return if present
        char* cr = strchr(line_start, '\r');
        if (cr) *cr = '\0';
        
        // Parse id:username:password:pubkey_path:email:address:phone_number format
        char email[128], address[128], phone_number[12];
        if (sscanf(line_start, "%u:%31[^:]:%63[^:]:%127[^:]:%127[^:]:%11[^:]:%1d[^:]",
                   &account_id, username, password, email, address, phone_number, &auth) == 7) {
            user_t *new_user = malloc(sizeof(user_t));
            username_t *new_username = malloc(sizeof(username_t));
            if (!new_user) {
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Failed to allocate memory for user\n");
                FILE_LOG(log_message);
                free(new_username);
                continue;
            }
            if (!new_username) {
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Failed to allocate memory for username\n");
                FILE_LOG(log_message);
                free(new_user);
                continue;
            }
            //stores the username as a tie to the account_id
            new_username->account_id = account_id;
            new_user->account_id = account_id;
            strncpy(new_user->username, username, MAX_USERNAME_LEN - 1);
            new_user->username[MAX_USERNAME_LEN - 1] = '\0';
            new_username->username = strdup(username);
            new_user->public_key = NULL;
            // Hash the plaintext password immediately
            hash_password(password, new_user->password_hash);
            new_user->password_hash[MAX_HASH_LEN - 1] = '\0';
            new_user->email = strdup(email);
            new_user->address = strdup(address);
            new_user->phone_number = strdup(phone_number);
            new_user->active = 1;
            new_user->authLevel = auth;
            new_user->enhanced_logging_enabled = 0;  // Initialize enhanced logging as disabled
            // Check if user already exists
            pthread_mutex_lock(&user_map_mutex);
            pthread_mutex_lock(&username_map_mutex);
            if (find_user(account_id) == NULL && find_username(username) == NULL) {
                HASH_ADD_INT(user_map, account_id, new_user);
                HASH_ADD_STR(username_map, username, new_username);
                
                loaded_count++;
                user_count++;
            } else {
               
                snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM] Skipping duplicate account ID: %u\n", account_id);
                FILE_LOG(log_message);
                cleanup_user(new_user);
                free(new_username);
                new_username = NULL;
            }
            pthread_mutex_unlock(&username_map_mutex);
            pthread_mutex_unlock(&user_map_mutex);
            
            // Clear the plaintext password from memory immediately
            memset(password, 0, sizeof(password));
        }
        else {
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Invalid line format: %s\n", line_start);
            FILE_LOG(log_message);
        }
        // Restore newline and move to next line
        *line_end = '\n';
        line_start = line_end + 1;
    }
    
    // Handle last line if it doesn't end with newline
    if (line_start < data + decrypt_result.size && user_count < max_users) {
        char email[128], address[128], phone_number[12];
        if (sscanf(line_start, "%u:%31[^:]:%63[^:]:%127[^:]:%127[^:]:%11[^:]:%1d[^:]",
                   &account_id, username, password, email, address, phone_number, &auth) == 7) {
            user_t *new_user = malloc(sizeof(user_t));
            username_t *new_username = malloc(sizeof(username_t));
            if (new_user && new_username) {
                new_user->account_id = account_id;
                strncpy(new_user->username, username, MAX_USERNAME_LEN - 1);
                new_user->username[MAX_USERNAME_LEN - 1] = '\0';
                new_username->username = strdup(username);
                new_username->account_id = account_id;
                new_user->public_key = NULL;
                hash_password(password, new_user->password_hash);
                new_user->password_hash[MAX_HASH_LEN - 1] = '\0';
                new_user->email = strdup(email);
                new_user->address = strdup(address);
                new_user->phone_number = strdup(phone_number);
                new_user->active = 1;
                new_user->authLevel = auth;
                new_user->enhanced_logging_enabled = 0;  // Initialize enhanced logging as disabled
                pthread_mutex_lock(&user_map_mutex);
                pthread_mutex_lock(&username_map_mutex);
                if (find_user(account_id) == NULL && find_username(username) == NULL) {
                    
                    HASH_ADD_INT(user_map, account_id, new_user);
                    
                    HASH_ADD_STR(username_map, username, new_username);
                    
                    loaded_count++;
                    user_count++;
                } else {
                    snprintf(log_message, sizeof(log_message), "[WARN][AUTH_SYSTEM] Skipping duplicate user ID: %u\n", account_id);
                    FILE_LOG(log_message);
                    cleanup_user(new_user); 
                    free(new_username);
                    new_username = NULL;
                }
                pthread_mutex_unlock(&user_map_mutex);
                pthread_mutex_unlock(&username_map_mutex);
                memset(password, 0, sizeof(password));
            }
        }
        else{
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Invalid last line format: %s\n", line_start);
            FILE_LOG(log_message);
        }
    }
    // Free the decrypted data (this also clears sensitive data)
    free_decryption_result(&decrypt_result);
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Loaded %d users from encrypted database\n", loaded_count);
    FILE_LOG(log_message);
    printf("Loaded %d users from encrypted database\n", loaded_count);
    rsa_system_initialized = (loaded_count > 0);  // RSA system is initialized if we loaded any users with keys
    
    return loaded_count > 0;
}

int is_auth_command(const char* message) {
    return (strncmp(message, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
            strncmp(message, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0 ||
            strncmp(message, AUTH_LOGOUT, strlen(AUTH_LOGOUT)) == 0 ||
  
            is_rsa_command(message));
}

int is_token_command(const char* message) {
    int is_token = (strncmp(message, AUTH_TOKEN, strlen(AUTH_TOKEN)) == 0 ||
                   strncmp( message, AUTH_NEW_TOKEN, strlen(AUTH_NEW_TOKEN)) == 0);
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] the result of %s is %d\n", message, is_token);
    FILE_LOG(log_message);
    return is_token;
}

auth_result_t process_auth_command(const char* message, int account_id, char* jwt_token_out, size_t jwt_token_size, int* has_jwt_token_out) {
    char log_message[BUFFER_SIZE];
    auth_result_t result = {0};

    // Initialize output parameters
    if (jwt_token_out && jwt_token_size > 0) {
        jwt_token_out[0] = '\0';
    }
    if (has_jwt_token_out) {
        *has_jwt_token_out = 0;
    }
    char command[64], username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN];
    
    // Parse the authentication message
    if (sscanf(message, "%63s %31s %63s", command, username, password) != 3) {
        result.success = 0;
        result.authenticated = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Invalid format. Use: /login <username> <password> or /register <username> <password>\n", 
                AUTH_FAILED);
        return result;
    }
    
    // Copy username for logging
    strncpy(result.username, username, MAX_USERNAME_LEN - 1);
    result.username[MAX_USERNAME_LEN - 1] = '\0';
    
    if (strcmp(command, AUTH_LOGIN) == 0) {
        int auth_result = authenticate_user(username, password, account_id);
        if (auth_result == 1) {
            // Password verified, no email verification needed
            result.success = 1;
            result.authenticated = 1;
            snprintf(result.response, sizeof(result.response), 
                    "PHASE:FINAL FINAL_AUTH_SUCCESS Welcome, %s! You are now fully authenticated.", 
                    username);
        } else if (auth_result == 2) {
            // Password verified, email token sent
            result.success = 1;
            result.authenticated = 0;  // Not fully authenticated yet

            // Issue JWT token with password auth immediately after password verification
            int current_version = jwt_get_current_version(account_id);
            char* jwt_token = jwt_issue_hs256_staged(account_id, username,
                                                JWT_TYPE_PASSWORD, current_version, 900);
            if (jwt_token) {
                // Copy JWT token to output parameters so server can send it
                if (jwt_token_out && jwt_token_size > 0) {
                    strncpy(jwt_token_out, jwt_token, jwt_token_size - 1);
                    jwt_token_out[jwt_token_size - 1] = '\0';
                }
                if (has_jwt_token_out) {
                    *has_jwt_token_out = 1;
                }

                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Created password-stage JWT for account %d, length=%zu, has_jwt_token=%d\n",
                        account_id, account_id, strlen(jwt_token), has_jwt_token_out ? *has_jwt_token_out : 0);
                FILE_LOG(log_message);

                // Clean up token
                OPENSSL_cleanse(jwt_token, strlen(jwt_token));
                free(jwt_token);
            } else {
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Failed to create password-stage JWT for account %d\n", account_id, account_id);
                FILE_LOG(log_message);
            }

            // Wait a little bit before sending PHASE:EMAIL
            usleep(500000); // 500ms delay

            snprintf(result.response, sizeof(result.response),
                    "PHASE:PASSWORD PASSWORD_AUTH_SUCCESS Password verified. Please check your email for a 6-digit token and enter it with: /token <code>");
        } else {
            // Authentication failed
            result.success = 0;
            result.authenticated = 0;
            if (rsa_system_initialized && !is_rsa_authenticated(account_id)) {
                snprintf(result.response, sizeof(result.response), 
                        "%s RSA authentication required. Use %s first", AUTH_FAILED, RSA_AUTH_START);
            } else {
                snprintf(result.response, sizeof(result.response), 
                        "%s Invalid username or password\n", AUTH_FAILED);
            }
        }
    } else if (strcmp(command, AUTH_REGISTER) == 0) {
        if (add_user(account_id, username, password)) {
            result.success = 1;
            result.authenticated = 0; // Still need to login after registration
            snprintf(result.response, sizeof(result.response), 
                    "PHASE:REGISTER REGISTER_SUCCESS User %s registered successfully. You can now login.", 
                    username);
        } else {
            result.success = 0;
            result.authenticated = 0;
            snprintf(result.response, sizeof(result.response), 
                    "%s Registration failed. Username may already exist.", 
                    AUTH_FAILED);
        }
    } else if (strcmp(command, AUTH_LOGOUT) == 0) {
        remove_session(account_id);
        result.success = 1;
        result.authenticated = 0;
        snprintf(result.response, sizeof(result.response), 
                "PHASE:LOGOUT LOGOUT_SUCCESS You have been logged out.");
    } else {
        result.success = 0;
        result.authenticated = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Unknown command. Use /login, /register, or /logout", 
                AUTH_FAILED);
    }
    
    return result;
} 

int init_rsa_system(const char* server_private_key_file, const char* server_public_key_file) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Initializing RSA authentication system...\n");
    FILE_LOG(log_message);
    
    // Load server keys
    rsa_keypair_t* loaded_keys = load_rsa_keys(server_private_key_file, server_public_key_file);
    if (!loaded_keys) {
        snprintf(log_message, sizeof(log_message), "[FATAL][AUTH_SYSTEM] Failed to load server RSA keys\n");
        FILE_LOG(log_message);
        printf("Failed to load server RSA keys\n");
        return 0;
    }
    
    server_keys = *loaded_keys;
    free(loaded_keys);
    
    // RSA system is considered initialized if server keys are loaded
    // (client keys are now managed with user data)
    rsa_system_initialized = 1;
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] RSA authentication system initialized successfully\n");
    FILE_LOG(log_message);
    printf("RSA authentication system initialized successfully\n");
    return 1;
}

// Generate RSA key pair and save to files
int generate_rsa_keypair(const char* private_key_file, const char* public_key_file) {
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bp_public = NULL, *bp_private = NULL;
    int ret = 0;
    
    printf("Generating RSA %d-bit key pair...\n", RSA_KEY_SIZE);
    
    // Generate RSA key pair using EVP interface
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        printf("Error creating EVP context\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Error initializing key generation\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
        printf("Error setting RSA key size\n");
        goto cleanup;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Error generating RSA key pair\n");
        goto cleanup;
    }
    
    // Save private key
    bp_private = BIO_new_file(private_key_file, "w+");
    if (!bp_private) {
        printf("Error creating private key file: %s\n", private_key_file);
        goto cleanup;
    }
    
    if (PEM_write_bio_PrivateKey(bp_private, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        printf("Error writing private key to file\n");
        goto cleanup;
    }
    
    // Save public key
    bp_public = BIO_new_file(public_key_file, "w+");
    if (!bp_public) {
        printf("Error creating public key file: %s\n", public_key_file);
        goto cleanup;
    }
    
    if (PEM_write_bio_PUBKEY(bp_public, pkey) != 1) {
        printf("Error writing public key to file\n");
        goto cleanup;
    }
    
    printf("RSA key pair generated successfully!\n");
    printf("Private key saved to: %s\n", private_key_file);
    printf("Public key saved to: %s\n", public_key_file);
    ret = 1;
    
cleanup:
    if (bp_private) BIO_free_all(bp_private);
    if (bp_public) BIO_free_all(bp_public);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

// Load RSA key pair from files
rsa_keypair_t* load_rsa_keys(const char* private_key_file, const char* public_key_file) {
    rsa_keypair_t* keys = malloc(sizeof(rsa_keypair_t));
    char log_message[BUFFER_SIZE];

    if (!keys) return NULL;
    
    keys->private_key = NULL;
    keys->public_key = NULL;
    
    // Load private key
    FILE* fp_private = fopen(private_key_file, "r");
    if (!fp_private) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Error opening private key file: %s\n", private_key_file);
        FILE_LOG(log_message);
        free(keys);
        return NULL;
    }
    
    keys->private_key = PEM_read_PrivateKey(fp_private, NULL, NULL, NULL);
    fclose(fp_private);
    
    if (!keys->private_key) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Error reading private key from file\n");
        FILE_LOG(log_message);
        free(keys);
        return NULL;
    }
    
    // Load public key
    FILE* fp_public = fopen(public_key_file, "r");
    if (!fp_public) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Error opening public key file: %s\n", public_key_file);
        FILE_LOG(log_message);
        EVP_PKEY_free(keys->private_key);
        free(keys);
        return NULL;
    }
    
    keys->public_key = PEM_read_PUBKEY(fp_public, NULL, NULL, NULL);
    fclose(fp_public);
    
    if (!keys->public_key) {
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM] Error reading public key from file\n");
        FILE_LOG(log_message);
        EVP_PKEY_free(keys->private_key);
        free(keys);
        return NULL;
    }
    
    return keys;
}

// Load a single public key from file
EVP_PKEY* load_public_key(const char* public_key_file) {
    FILE* fp = fopen(public_key_file, "r");
    if (!fp) {
        printf("Error opening public key file: %s\n", public_key_file);
        return NULL;
    }
    
    EVP_PKEY* public_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!public_key) {
        printf("Error reading public key from file\n");
        return NULL;
    }
    
    return public_key;
}

// Start RSA challenge for a client
rsa_challenge_result_t start_rsa_challenge_for_client(int account_id, EVP_PKEY* client_pubkey) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    
    // Check if RSA is disabled first
    extern int is_rsa_disabled(void);
    if (is_rsa_disabled()) {
        snprintf(result.response, sizeof(result.response), "%s RSA authentication disabled", RSA_AUTH_FAILED);
        return result;
    }
    
    if (!rsa_system_initialized) {
        snprintf(result.response, sizeof(result.response), "%s RSA system not initialized", RSA_AUTH_FAILED);
        return result;
    }
    // Find the user
    pthread_mutex_lock(&user_map_mutex);
    user_t *user = find_user(account_id);
    pthread_mutex_unlock(&user_map_mutex);
    if (!user) {
        snprintf(result.response, sizeof(result.response), "%s No user found for account", RSA_AUTH_FAILED);
        return result;
    }
    // Initialize session for RSA challenge
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session) {
        session = malloc(sizeof(session_t));
        memset(session, 0, sizeof(session_t));
        session->account_id = account_id;
        session->user = user;
        session->login_time = time(NULL);
        session->auth_status = AUTH_NONE;  // Start with no authentication
        memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
        // Store the client's public key in the session
        session->user->public_key = EVP_PKEY_dup(client_pubkey);
        session->lockout_info.failed_attempts = 0;
        session->lockout_info.is_locked = 0;
        session->lockout_info.lockout_start_time = 0;
        pthread_mutex_lock(&session_map_mutex);
        HASH_ADD_INT(session_map, account_id, session);
        pthread_mutex_unlock(&session_map_mutex);
        session_count++;
        printf("[DEBUG] Created session for account %d and stored client_pubkey.\n", account_id);
    }
    //If existing session, check if it is locked
    if(session && session->auth_status & AUTH_STATUS_LOCKED && get_remaining_lockout_time(account_id) > 0){
        snprintf(result.response, sizeof(result.response), "%s Account %s is locked for %d more seconds due to too many failed attempts.\n", 
                AUTH_LOCKED, user->username, get_remaining_lockout_time(account_id));
        result.success = 0;
        return result;
    }
    //if existing session has ran out of lockout time, unlock it, and tell client
    else if(session && session->auth_status & AUTH_STATUS_LOCKED && get_remaining_lockout_time(account_id) <= 0){
        session->auth_status &= ~AUTH_STATUS_LOCKED;
        session->lockout_info.is_locked = 0;
        session->lockout_info.failed_attempts = 0;
        session->lockout_info.lockout_start_time = time(NULL);
        snprintf(result.response, sizeof(result.response), "%s Account %s is unlocked. Please login with: /login <username> <password>\n", 
                AUTH_STATUS_UNLOCKED, user->username);
    }
    // Generate random challenge
    if (RAND_bytes(session->challenge, RSA_CHALLENGE_SIZE) != 1) {
        snprintf(result.response, sizeof(result.response), "%s Failed to generate challenge", RSA_AUTH_FAILED);
        cleanup_session(session);
        return result;
    }

    //store challenge as a salt
    memcpy(session->hkdf_salt, session->challenge, RSA_CHALLENGE_SIZE);
    session->hkdf_salt_len = RSA_CHALLENGE_SIZE;

    // Use the provided public key for encryption
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(session->user->public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), "%s Failed to setup encryption", RSA_AUTH_FAILED);
        cleanup_session(session);
        return result;
    }
    size_t outlen = MAX_RSA_ENCRYPTED_SIZE;
    if (EVP_PKEY_encrypt(ctx, result.encrypted_challenge, &outlen, session->challenge, RSA_CHALLENGE_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), "%s Failed to encrypt challenge", RSA_AUTH_FAILED);
        return result;
    }
    result.encrypted_size = outlen;
    EVP_PKEY_CTX_free(ctx);
    memcpy(result.challenge, session->challenge, RSA_CHALLENGE_SIZE);
    result.success = 1;
    snprintf(result.response, sizeof(result.response), "%s Challenge generated", RSA_AUTH_SUCCESS);
    return result;
}

// Verify RSA response from client
rsa_challenge_result_t verify_rsa_response(int account_id, const unsigned char* encrypted_response, int response_size) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    char log_message[BUFFER_SIZE];

    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Verifying RSA challenge\n", account_id);
    FILE_LOG(log_message);
    if (!rsa_system_initialized || !server_keys.private_key) {
        snprintf(result.response, sizeof(result.response), 
                "%s RSA system not initialized", RSA_AUTH_FAILED);
        FILE_LOG(result.response);
        return result;
    }
    

    // Find session
    pthread_mutex_lock(&user_map_mutex);
    user_t *user = find_user(account_id);
    pthread_mutex_unlock(&user_map_mutex);
    if (!user) {
        snprintf(result.response, sizeof(result.response), 
                "%s No user for account %d", RSA_AUTH_FAILED, account_id);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] No user found for account %d\n", account_id, account_id);
        FILE_LOG(log_message);
        return result;
    }
    
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    if (!session) {
        snprintf(result.response, sizeof(result.response), 
                "%s No active session", RSA_AUTH_FAILED);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] No active session found for account %d\n", account_id, account_id);
        FILE_LOG(log_message);
        return result;
    }
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Found session(auth stage is %d)\n", 
           account_id, (session->auth_status & AUTH_PASSWORD) ? 1 : 0);
    FILE_LOG(log_message);
    
    // Decrypt the response with server's private key
    unsigned char decrypted_challenge[RSA_DECRYPT_BUFFER_SIZE];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_keys.private_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        ERR_print_errors_fp(stdout);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to setup decryption", RSA_AUTH_FAILED);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Failed to setup decryption\n", account_id);
        FILE_LOG(log_message);
        return result;
    }
    
    size_t outlen = sizeof(decrypted_challenge);  // Use actual buffer size

    
    int decrypt_result = EVP_PKEY_decrypt(ctx, decrypted_challenge, &outlen, encrypted_response, response_size);
   
    if (decrypt_result <= 0) {
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to decrypt response", RSA_AUTH_FAILED);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Decryption failed\n", account_id);
        FILE_LOG(log_message);
        return result;
    }
    
    if (outlen != RSA_CHALLENGE_SIZE) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Decrypted size mismatch", RSA_AUTH_FAILED);
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Length mismatch - got %zu bytes, expected %d bytes\n", 
               account_id, outlen, RSA_CHALLENGE_SIZE);
        FILE_LOG(log_message);
        return result;
    }
    
    EVP_PKEY_CTX_free(ctx);
   
    // Verify challenge matches
    if (memcmp(session->challenge, decrypted_challenge, RSA_CHALLENGE_SIZE) == 0) {
        session->auth_status |= AUTH_RSA;  // Set RSA authentication flag
        result.success = 1;
        snprintf(result.response, sizeof(result.response), 
                "PHASE:RSA RSA_AUTH_SUCCESS RSA authentication successful.");
        
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] RSA authentication successful\n", account_id);
        FILE_LOG(log_message);
    } 
    else {
        result.success = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Challenge verification failed", RSA_AUTH_FAILED);
        
        snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] RSA challenge verification failed\n", account_id);
        FILE_LOG(log_message);
    }
    
    // Clear the challenge from memory and update session
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    update_session(account_id, session);
    
    return result;
}

// Check if message is an RSA command
int is_rsa_command(const char* message) {
    return (strncmp(message, RSA_AUTH_START, strlen(RSA_AUTH_START)) == 0 ||
            strncmp(message, RSA_AUTH_RESPONSE, strlen(RSA_AUTH_RESPONSE)) == 0);
}

// Process RSA authentication command
rsa_challenge_result_t process_rsa_command(const char* message, int account_id) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Processing RSA command\n", account_id);
    FILE_LOG(log_message);
    if (strncmp(message, RSA_AUTH_RESPONSE, strlen(RSA_AUTH_RESPONSE)) == 0) {
        // Process RSA response
        char command[64];
        char hex_response[RSA_HEX_BUFFER_SIZE];
        if (sscanf(message, "%63s %512s", command, hex_response) != 2) {
            snprintf(result.response, sizeof(result.response), 
                    "%s Invalid format. Use: %s <hex_encrypted_response>", 
                    RSA_AUTH_FAILED, RSA_AUTH_RESPONSE);
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Invalid format. Use: %s <hex_encrypted_response>\n", account_id, RSA_AUTH_RESPONSE);
            FILE_LOG(log_message);
            return result;
        }
        
        // Convert hex string to binary
        unsigned char encrypted_response[MAX_RSA_ENCRYPTED_SIZE];
        int response_size = strlen(hex_response) / 2;
        
        if (response_size > MAX_RSA_ENCRYPTED_SIZE) {
            snprintf(result.response, sizeof(result.response), 
                    "%s Response too large", RSA_AUTH_FAILED);
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Response too large\n", account_id);
            FILE_LOG(log_message);
            return result;
        }
        
        for (int i = 0; i < response_size; i++) {
            sscanf(hex_response + (i * 2), "%2hhx", &encrypted_response[i]);
        }
        
        return verify_rsa_response(account_id, encrypted_response, response_size);
    }
    
    snprintf(result.response, sizeof(result.response), 
            "%s Unknown RSA command", RSA_AUTH_FAILED);
    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_SYSTEM][ID:%d] Unknown RSA command\n", account_id);
    FILE_LOG(log_message);
    return result;
}

// Check if RSA system is initialized
int is_rsa_system_initialized(void) {
    return rsa_system_initialized;
}

void cleanup_user(user_t *user) {
    if (user == NULL) {
        return;
    }
    
    if (user->public_key != NULL) {
        EVP_PKEY_free(user->public_key);
        user->public_key = NULL;
    }
    if (user->email != NULL) {
        free(user->email);
        user->email = NULL;
    }
    if (user->address != NULL) {
        free(user->address);
        user->address = NULL;
    }
    if (user->phone_number != NULL) {
        free(user->phone_number);
        user->phone_number = NULL;
    }
    free(user);
}

void save_lockout_state(void) {
    pthread_mutex_lock(&session_map_mutex);
    FILE *fp = fopen("lockout_state.dat", "w");
    if (fp) {
        session_t *entry, *tmp;
        HASH_ITER(hh, session_map, entry, tmp) {
            fprintf(fp, "%u,%ld,%d,%d\n", entry->account_id, 
                   entry->lockout_info.lockout_start_time, entry->lockout_info.failed_attempts, entry->lockout_info.is_locked);
        }
        fclose(fp);
    }
pthread_mutex_unlock(&session_map_mutex);
}

void load_lockout_state(void) {
    pthread_mutex_lock(&session_map_mutex);
    FILE *fp = fopen("lockout_state.dat", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            unsigned int account_id;
            time_t lockout_start;
            int failed_attempts, is_locked;
            
            if (sscanf(line, "%u,%ld,%d,%d", &account_id, &lockout_start, 
                      &failed_attempts, &is_locked) == 4) {
                
                // Check if lockout has expired
                time_t now = time(NULL);
                if (is_locked && (now - lockout_start) >= LOCKOUT_DURATION) {
                    // Lockout expired, don't load this entry
                    continue;
                }
                
                session_t *entry = malloc(sizeof(session_t));
                if (entry) {
                    entry->account_id = account_id;
                    entry->lockout_info.lockout_start_time = lockout_start;
                    entry->lockout_info.failed_attempts = failed_attempts;
                    entry->lockout_info.is_locked = is_locked;
                    entry->auth_status = AUTH_NONE; // Initialize auth status
                    if (is_locked) {
                        entry->auth_status |= AUTH_STATUS_LOCKED; // Set lockout flag if locked
                    }
                    HASH_ADD_INT(session_map, account_id, entry);
                }
            }
        }
        fclose(fp);
    }
pthread_mutex_unlock(&session_map_mutex);
}

int check_persistent_lockout(unsigned int account_id) {
    
    session_t *entry = NULL;
    HASH_FIND_INT(session_map, &account_id, entry);
    
    if (!entry) {
        // No session in memory - check persistent file
        
        // Load from persistent storage
        FILE *fp = fopen("lockout_state.dat", "r");
        if (!fp) {
            return 0; // No lockout file
        }
        
        char line[256];
        time_t now = time(NULL);
        int result = 0;
        
        while (fgets(line, sizeof(line), fp)) {
            unsigned int file_account_id, lockout_start, failed_attempts, is_locked;
            if (sscanf(line, "%u,%lu,%d,%d", &file_account_id, 
                      (unsigned long*)&lockout_start, &failed_attempts, &is_locked) == 4) {
                
                if (file_account_id == account_id && is_locked) {
                    time_t elapsed = now - lockout_start;
                    if (elapsed < LOCKOUT_DURATION) {
                        result = LOCKOUT_DURATION - elapsed;
                        break;
                    }
                }
            }
        }
        fclose(fp);
        return result;
    }
    
    if (!entry->lockout_info.is_locked) {
        return 0; // Not locked
    }
    
    time_t now = time(NULL);
    time_t elapsed = now - entry->lockout_info.lockout_start_time;
    
    if (elapsed >= LOCKOUT_DURATION) {
        // Lockout expired
        entry->lockout_info.is_locked = 0;
        entry->lockout_info.failed_attempts = 0;
        entry->auth_status = AUTH_RSA;
        save_lockout_state(); // Persist the unlock
        return 0; // No longer locked
    }
    
    return (LOCKOUT_DURATION - elapsed); // Return remaining lockout time
}

void record_failed_attempt(unsigned int account_id) {
    
    char log_message[BUFFER_SIZE];
    session_t *entry = NULL;
    HASH_FIND_INT(session_map, &account_id, entry);
    
    if (!entry) {
        return;
    }
    
    if (entry) {
        entry->lockout_info.failed_attempts++;
        
        if (entry->lockout_info.failed_attempts >= 3) {
            entry->lockout_info.is_locked = 1;
            entry->lockout_info.lockout_start_time = time(NULL);
            entry->auth_status |= AUTH_STATUS_LOCKED; // Set the lockout flag
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Account %u locked due to %d failed attempts\n", 
                   account_id, account_id, entry->lockout_info.failed_attempts);
            FILE_LOG(log_message);
        }
    }
    
    save_lockout_state(); // Persist immediately
}



void init_persistent_lockout_system(void) {
    load_lockout_state();
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Persistent lockout system initialized\n");
    FILE_LOG(log_message);
}


void cleanup_session(session_t *session) {    
    if (session == NULL) {
        return;
    }
    
    // Cleanse sensitive ECDH/session materials
    OPENSSL_cleanse(session->session_key, sizeof(session->session_key));
    OPENSSL_cleanse(session->ecdh_peer_pub, sizeof(session->ecdh_peer_pub));
    session->ecdh_peer_pub_len = 0;
    OPENSSL_cleanse(session->challenge, sizeof(session->challenge));
    
    // Session doesn't own the user - just clear the reference
    // The user will be freed separately when cleaning up the user_map
    session->user = NULL;
    if (session->ecdh_keypair) {
        EVP_PKEY_free(session->ecdh_keypair);
        session->ecdh_keypair = NULL;
    }
    
    free(session);
}

// Reset per-connection ECDH/session keying material without destroying the session
void reset_session_ecdh(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    if (!session) {
        return;
    }
    if (session->ecdh_keypair) {
        EVP_PKEY_free(session->ecdh_keypair);
        session->ecdh_keypair = NULL;
    }
    memset(session->session_key, 0, sizeof(session->session_key));
    memset(session->ecdh_peer_pub, 0, sizeof(session->ecdh_peer_pub));
    session->ecdh_peer_pub_len = 0;
}
// Cleanup RSA system
void cleanup_rsa_system(void) {
    char log_message[BUFFER_SIZE];
    if (server_keys.private_key) {
        EVP_PKEY_free(server_keys.private_key);
        server_keys.private_key = NULL;
    }
    
    if (server_keys.public_key) {
        EVP_PKEY_free(server_keys.public_key);
        server_keys.public_key = NULL;
    }
    
    rsa_system_initialized = 0;
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] RSA authentication system cleaned up\n");
    FILE_LOG(log_message);
}

// Clean up auth system resources
void cleanup_auth_system(void) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Starting authentication system cleanup...\n");
    FILE_LOG(log_message);
    
    // Step 1: Clean up sessions first (they reference users but don't own them)
    if (session_map) {
        session_t *current, *temp;
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Cleaning up %d sessions...\n", session_count);
        FILE_LOG(log_message);
        pthread_mutex_lock(&session_map_mutex);
        HASH_ITER(hh, session_map, current, temp) {
            HASH_DEL(session_map, current);
            cleanup_session(current);
        }
        session_map = NULL; // Clear the hash table pointer
        pthread_mutex_unlock(&session_map_mutex);
    }
    
    // Step 2: Clean up users (now safe since sessions no longer reference them)
    if (user_map) {
        user_t *current, *temp;
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Cleaning up %d users...\n", user_count);
        FILE_LOG(log_message);
        pthread_mutex_lock(&user_map_mutex);
        HASH_ITER(hh, user_map, current, temp) {
            HASH_DEL(user_map, current);
            cleanup_user(current);
        }
        user_map = NULL; // Clear the hash table pointer
        pthread_mutex_unlock(&user_map_mutex);
    }
    
    // Step 3: Clean up username map
    if (username_map) {
        username_t *current, *temp;
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Cleaning up username mappings...\n");
        FILE_LOG(log_message);
        pthread_mutex_lock(&username_map_mutex);
        HASH_ITER(hh, username_map, current, temp) {
            HASH_DEL(username_map, current);
            if (current->username != NULL) {
                free(current->username);
                current->username = NULL;
            }
            free(current);
        }
        username_map = NULL; // Clear the hash table pointer
        pthread_mutex_unlock(&username_map_mutex);
    }
    
    // Reset counters
    user_count = 0;
    session_count = 0;
    pthread_mutex_destroy(&user_map_mutex);
    pthread_mutex_destroy(&session_map_mutex);
    pthread_mutex_destroy(&username_map_mutex);
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM] Authentication system cleanup complete\n");
    FILE_LOG(log_message);
    printf("\nAuthentication system cleanup complete\n");
}
