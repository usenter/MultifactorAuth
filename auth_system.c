#include "auth_system.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include "hashmap/uthash.h"
#include <openssl/evp.h>


// Global variables
user_t *user_map = NULL;
session_t *session_map = NULL;  // Maps account_id -> session_t
username_t *username_map = NULL;
pthread_mutex_t user_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t session_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t username_map_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t rsa_system_mutex = PTHREAD_MUTEX_INITIALIZER;


static int user_count = 0;
static int session_count = 0;
 // number of divisions for permissions

// RSA Authentication global variables
static rsa_keypair_t server_keys = {NULL, NULL};
static int rsa_system_initialized = 0;

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
    // Try to open the file - it's okay if it doesn't exist
    FILE* file = fopen(email_file, "r");
    if (!file) {
        printf("No lockout status file found at %s\n", email_file);
        return 1; // Not an error condition
    }

    char line[1024];
    time_t now = time(NULL);
    int success = 1;

    while (fgets(line, sizeof(line), file)) {
        int account_id, seconds_remaining;
        
        // Parse line with validation (format: "account_id:seconds_remaining")
        if (sscanf(line, "%d:%d", &account_id, &seconds_remaining) != 2) {
            printf("Warning: Invalid format in line: %s", line);
            continue;
        }

        // Skip if no lockout time remaining
        if (seconds_remaining <= 0) {
            continue;
        }

        // Create or get session with proper locking
        pthread_mutex_lock(&session_map_mutex);
        
        session_t *session = NULL;
        HASH_FIND_INT(session_map, &account_id, session);
        
        if (!session) {
            if (!create_auth_session(account_id)) {
                printf("Warning: Failed to create session for account %d\n", account_id);
                pthread_mutex_unlock(&session_map_mutex);
                continue;
            }
            HASH_FIND_INT(session_map, &account_id, session);
        }

        if (session) {
            // Convert relative seconds remaining to absolute unlock time
            session->email_token.lockout_until = now + seconds_remaining;
            printf("Restored lockout for account %d - will unlock in %d seconds (at time %ld)\n", 
                   account_id, seconds_remaining, session->email_token.lockout_until);
        }
        
        pthread_mutex_unlock(&session_map_mutex);
    }

    fclose(file);
    
    // Clear the file since we've loaded all statuses
    file = fopen(email_file, "w");
    if (file) {
        fclose(file);
    }
    
    return success;
}

// Add a new user
int add_user(int account_id, const char* username, const char* password) {
    user_t *user = malloc(sizeof(user_t));
    if(!user) { 
        perror("Failed to allocate memory for user");
        return 0;
    }

    user->account_id = account_id;
    strncpy(user->username, username, MAX_USERNAME_LEN - 1);
    user->username[MAX_USERNAME_LEN - 1] = '\0';
    hash_password(password, user->password_hash);
    user->active = 1;

    if (user_count >= MAX_USERS) {
        printf("User count is at the maximum\n");
        return 0; // No space
    }
    pthread_mutex_lock(&user_map_mutex);
    if(find_user(account_id) == NULL) {
        HASH_ADD_INT(user_map, account_id, user);
        user_count++;
        pthread_mutex_unlock(&user_map_mutex);
    }
    

    else{
        pthread_mutex_unlock(&user_map_mutex);
        printf("User already exists\n");
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

// Authenticate a user (now REQUIRES RSA authentication first when RSA is enabled)
int authenticate_user(const char* username, const char* password, int account_id) {
    printf("DEBUG: authenticate_user password for account %d\n", account_id);
    // Get current session
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    printf("DEBUG: authenticate_user for account %d, session found: %s\n", account_id, session ? "YES" : "NO");
    if (session) {
        printf("DEBUG: Session auth_status before: %d\n", session->auth_status);
    }
    
    if (!session) {
        printf("No active session found for account %d\n", account_id);
        return 0;
    }
    
    // Check RSA authentication
    if (rsa_system_initialized && !(session->auth_status & AUTH_RSA)) {
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
        return 0;
    }
    
    // Check username matches
    if (strncmp(username, found_ptr->username, MAX_USERNAME_LEN) != 0) {
        printf("Username mismatch: provided '%s', expected '%s' for account_id %d\n", 
               username, found_ptr->username, account_id);
        return 0;
    }
    
    // Verify password
    if (!verify_password(password, found_ptr->password_hash)) {
        printf("Password incorrect for user: %s from socket %d\n", username, account_id);
        return 0;
    }
    
    // Update session with password authentication
    pthread_mutex_lock(&session_map_mutex);
    printf("DEBUG: Setting AUTH_PASSWORD for account %d (previous status: %d)\n", account_id, session->auth_status);
    session->auth_status |= AUTH_PASSWORD;
    printf("DEBUG: New auth_status for account %d: %d\n", account_id, session->auth_status);
    pthread_mutex_unlock(&session_map_mutex);
    
    // Verify the session was updated correctly
    session_t *verify_session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, verify_session);
    pthread_mutex_unlock(&session_map_mutex);
    if (verify_session) {
        printf("DEBUG: Verified session auth_status after update: %d\n", verify_session->auth_status);
    }
    
    // If user has email, send verification token
    if (found_ptr->email) {
        sendEmailVerification(session);
        return 2; // Special return code: password verified, email token sent
    }
    
    return 1; // Password verified, no email verification needed
}

// Create a new session
int create_session(int account_id) {
    if (!session_map) {
        return 0;
    }
    
    // Check if session already exists (from RSA phase)
    session_t *existing_session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, existing_session);
    pthread_mutex_unlock(&session_map_mutex);
    
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
    session_count++;
    pthread_mutex_unlock(&session_map_mutex);
    
    return 1; // Success
}

// Remove a session
void remove_session(int account_id) {
    if (!session_map) {
        return;
    }
    
    session_t *found = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, found);
    pthread_mutex_unlock(&session_map_mutex);
    if (found && (found->auth_status & AUTH_PASSWORD)) { // Only proceed if password authenticated
        pthread_mutex_lock(&session_map_mutex);
        HASH_DEL(session_map, found);
        pthread_mutex_unlock(&session_map_mutex);
        cleanup_session(found);
        session_count--;
    }
}

// Update session data safely
int update_session(int account_id, const session_t* updated_session) {
    if (!session_map || !updated_session) {
        return 0;
    }
    
    session_t *found = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, found);
    pthread_mutex_unlock(&session_map_mutex);
    if (found) {
        found->login_time = updated_session->login_time;
        found->auth_status = updated_session->auth_status;
        memcpy(found->challenge, updated_session->challenge, RSA_CHALLENGE_SIZE);
        // Don't update account_id or user pointer as they shouldn't change
        return 1;
    }
    return 0;
}

session_t* find_session(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
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
    emailContent_t *email_payload = malloc(sizeof(emailContent_t));
    if (!email_payload) {
        printf("Failed to allocate memory for email payload\n");
        return;
    }
    
    // Initialize the structure
    memset(email_payload, 0, sizeof(emailContent_t));
    
    // Allocate memory for strings
    email_payload->TO = strdup(session->user->email);
    email_payload->subject = strdup("Verification Code for Chat Server");
    email_payload->body = malloc(1024);
    
    if (!email_payload->TO || !email_payload->subject || !email_payload->body) {
        printf("Failed to allocate memory for email content\n");
        cleanup_email_content(email_payload);
        free(email_payload); // Free the structure itself
        return;
    }
    
    // Generate token and set session data
    session->email_token.token = generateVerificationCode(session->user->username);
    printf("DEBUG: Generated token: %d for user %s\n", session->email_token.token, session->user->username);
    session->email_token.created_time = time(NULL);
    session->email_token.attempts = 0;
    
    // Format email body
    snprintf(email_payload->body, 1024, 
             "Hello %s. Your verification code is: %d\nPlease enter this code to verify your account.", 
             session->user->username, session->email_token.token);
    
    // Send email
    send_email(email_payload);
    cleanup_email_content(email_payload);
    free(email_payload); // Free the structure itself
}

// New authentication flow functions
int create_auth_session(int account_id) {
    // Check if session already exists
    session_t *existing_session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, existing_session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (existing_session) {
        // Session already exists, don't reset auth status - just update login time
        existing_session->login_time = time(NULL);
        existing_session->auth_status = AUTH_NONE;
        // Only reset email token if we're starting fresh (no auth flags set)
        if (existing_session->auth_status == AUTH_NONE) {
            memset(&existing_session->email_token, 0, sizeof(email_token_t));
        }
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
    session->auth_status = AUTH_NONE;  // Start with no authentication
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    memset(&session->email_token, 0, sizeof(email_token_t));
    
    pthread_mutex_lock(&session_map_mutex);
    HASH_ADD_INT(session_map, account_id, session);
    session_count++;
    pthread_mutex_unlock(&session_map_mutex);
    
    return 1;
}

// Get current authentication status
auth_flags_t get_auth_status(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (!session) {
        return AUTH_NONE;
    }
    
    return session->auth_status;
}

// Process authentication message based on current status
int process_auth_message(const char* message, int account_id, char* response, size_t response_size) {
    if (!message || !response) return 0;
    
    auth_flags_t status = get_auth_status(account_id);
    
    // Check if fully authenticated
    if (status == AUTH_FULLY_AUTHENTICATED) {
        snprintf(response, response_size, "You are already fully authenticated.");
        return 1;
    }
    
    // RSA authentication phase
    if (!(status & AUTH_RSA)) {
        if (is_rsa_command(message)) {
            rsa_challenge_result_t rsa_result = process_rsa_command(message, account_id);
            if (rsa_result.success && strstr(rsa_result.response, "RSA authentication successful")) {
                snprintf(response, response_size, 
                        "RSA authentication successful. Please login with: /login <username> <password>\n");
            } else {
                snprintf(response, response_size, "%s", rsa_result.response);
            }
            return 1;
        }
        snprintf(response, response_size, "RSA authentication required first.");
        return 1;
    }
    
    // Email token authentication phase
    if (!(status & AUTH_EMAIL) && (status & AUTH_PASSWORD)) {  // Only allow token commands after password auth
        printf("DEBUG: In email token phase, checking if '%s' is a token command\n", message);
        if (is_token_command(message)) {
            if (strncmp(message, AUTH_TOKEN, strlen(AUTH_TOKEN)) == 0) {
                // Extract token from message - handle both "/token 123456" and "/token123456"
                printf("DEBUG: Extracting token from message: '%s'\n", message);
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
                    snprintf(response, response_size, 
                            "%s Invalid format. Use: /token <6-digit-code>\n", 
                            AUTH_FAILED);
                    return 1;
                }
                
                // Check if user is locked out first
                if (is_user_locked_out(account_id)) {
                    int remaining = get_remaining_lockout_time(account_id);
                    snprintf(response, response_size, 
                            "%s Account is locked for %d more seconds due to too many failed attempts.\n", 
                            AUTH_LOCKED, remaining);
                    return 1;
                }
                printf("verifying token: %s\n", token);

                // Verify token
                int verify_result = verify_email_token(account_id, token);

                printf("DEBUG: verify_result = %d\n", verify_result);
                if (verify_result == 1) {
                    snprintf(response, response_size, 
                            "%s Email token verified successfully! You are now fully authenticated.\n", 
                            AUTH_SUCCESS);
                    return 1;
                } 
                else if (verify_result == -3) {
                    snprintf(response, response_size, 
                            "%s Token has expired. Use /newToken to request a new one.\n", 
                            AUTH_TOKEN_EXPIRED);
                    return 1;
                } 
                else if (verify_result == -2) {
                    int remaining = get_remaining_lockout_time(account_id);
                    snprintf(response, response_size, 
                            "%s Account locked for %d seconds due to too many failed attempts.\n", 
                            AUTH_LOCKED, remaining);
                    return 1;
                } 
                else {
                    snprintf(response, response_size, 
                            "%s Invalid token. Please check your email and try again. %d attempts remaining.\n", 
                            AUTH_TOKEN_FAIL, MAX_TOKEN_ATTEMPTS - get_session_attempts(account_id));
                    return 1;
                }
            } 
            else if (strncmp(message, AUTH_NEW_TOKEN, strlen(AUTH_NEW_TOKEN)) == 0) {
                if (generate_new_token(account_id)) {
                    snprintf(response, response_size, 
                            "%s A new token has been sent to your email.\n", 
                            AUTH_SUCCESS);
                } else {
                    snprintf(response, response_size, 
                            "%s Failed to generate new token.\n", 
                            AUTH_FAILED);
                }
                return 1;
            }
            else{
                printf("DEBUG: Command '%s' is not recognized as a token command\n", message);
                snprintf(response, response_size, 
                        "Please enter your email token with: /token <code> or request a new one with: /newToken\n");
                return 1;
            }
        }
        printf("DEBUG: Command '%s' is not recognized as a token command\n", message);
        snprintf(response, response_size, 
                "Please enter your email token with: /token <code> or request a new one with: /newToken\n");
        return 1;
    }
    else{
        printf("DEBUG: Not in email token auth phase\n!(status&auth_email) = %d\nstatus&password = %d\n", !(status & AUTH_EMAIL), (status & AUTH_PASSWORD));
        printf("DEBUG: status = %d\n", status);
        printf("DEBUG: looking at session %d\n", account_id);
        session_t *session = find_session(account_id);
        if (session) {
            printf("DEBUG: Session auth_status: %d\n", session->auth_status);
        }
    }
    // Password authentication phase
    if (!(status & AUTH_PASSWORD)) {
        printf("DEBUG: In password phase, checking if '%s' is an auth command\n", message);
        if (is_auth_command(message)) {
            auth_result_t auth_result = process_auth_command(message, account_id);
            if (auth_result.success && auth_result.authenticated) {
                // Send email token
                session_t *session = NULL;
                pthread_mutex_lock(&session_map_mutex);
                HASH_FIND_INT(session_map, &account_id, session);
                if (session) {
                    sendEmailVerification(session);
                }
                pthread_mutex_unlock(&session_map_mutex);
                
                snprintf(response, response_size, 
                        "Password verified. Check your email for a 6-digit token and enter it with: /token <code>");
            } else {
                snprintf(response, response_size, "%s", auth_result.response);
            }
            return 1;
        }
        snprintf(response, response_size, "Please login with: /login <username> <password>\n");
        return 1;
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
    
    if (missing_step) {
        snprintf(response, response_size, "%s Please complete %s first.\n", AUTH_FAILED, missing_step);
        return 1;
    }
    snprintf(response, response_size, "Authentication error occurred.\n");
    return 0;
}

// Generate new email token
int generate_new_token(int account_id) {
    // Get session
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (!session || !session->user || !session->user->email) {
        printf("No valid session or email for account %d\n", account_id);
        return 0;
    }
    
    // Send new verification email
    sendEmailVerification(session);
    return 1;
}

// Check if a user is locked out
int is_user_locked_out(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (!session) return 0;
    
    time_t now = time(NULL);
    return (session->email_token.lockout_until > now);
}

// Get remaining lockout time in seconds
int get_remaining_lockout_time(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (!session) return 0;
    
    time_t now = time(NULL);
    if (session->email_token.lockout_until > now) {
        return (int)(session->email_token.lockout_until - now);
    }
    return 0;
}

// Handle failed token attempt and return whether user is now locked out
int handle_failed_token_attempt(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    
    if (!session) {
        pthread_mutex_unlock(&session_map_mutex);
        return 0;
    }
    
    session->email_token.attempts++;
    
    // Check if we should lock the account
    if (session->email_token.attempts >= MAX_TOKEN_ATTEMPTS) {
        time_t now = time(NULL);
        session->email_token.lockout_until = now + LOCKOUT_DURATION;
        session->email_token.attempts = 0; // Reset attempts counter
        pthread_mutex_unlock(&session_map_mutex);
        return 1; // User is now locked out
    }
    
    pthread_mutex_unlock(&session_map_mutex);
    return 0; // User is not locked out
}

// Get current number of failed attempts
int get_session_attempts(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    int attempts = session ? session->email_token.attempts : 0;
    pthread_mutex_unlock(&session_map_mutex);
    return attempts;
}

// Reset token attempts counter
void reset_token_attempts(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    if (session) {
        session->email_token.attempts = 0;
    }
    pthread_mutex_unlock(&session_map_mutex);
}

// Verify email token
int verify_email_token(int account_id, const char* token) {
    if (!token) return 0;
    
    // Check if user is locked out
    if (is_user_locked_out(account_id)) {
        int remaining = get_remaining_lockout_time(account_id);
        printf("Account %d is locked out for %d more seconds\n", account_id, remaining);
        return -2; // User is locked out
    }
    
    // Get session
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    
    if (!session) {
        printf("No session found for account %d\n", account_id);
        return 0;
    }
    
    // Check if token has expired (1 minute)
    time_t now = time(NULL);
    if (now - session->email_token.created_time > TOKEN_EXPIRY_TIME) {
        printf("Token expired for account %d\n", account_id);
        return -3; // Token expired
    }
    
    // Convert string token to integer
    int token_value;
    if (sscanf(token, "%d", &token_value) != 1) {
        printf("Invalid token format for account %d\n", account_id);
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
        printf("Token verified successfully for account %d\n", account_id);
        return 1;
    }
    
    // Token is incorrect
    printf("Invalid token provided for account %d\n", account_id);
    if (handle_failed_token_attempt(account_id)) {
        return -2; // User is now locked out
    }
    return 0;
}

// Check if a user is RSA authenticated
int is_rsa_authenticated(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    if (!session || !(session->auth_status & AUTH_RSA)) {
        return 0;
    }
    return 1;
}

// Check if a user is authenticated
int is_authenticated(int account_id) {
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
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



int load_users_from_encrypted_file(const char* encrypted_filename, const char* key) {
    printf("Loading users from encrypted file: %s\n", encrypted_filename);
    
    // Decrypt file directly to memory using library function
    decryption_result_t decrypt_result = decrypt_file_to_memory(encrypted_filename, key);
    
    if (!decrypt_result.success) {
        printf("Failed to decrypt file: %s\n", encrypted_filename);
        printf("Check that the encryption key is correct.\n");
        return 0;
    }
    
    printf("Successfully decrypted file, processing users...\n");
    
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
    
    while ((line_end = strchr(line_start, '\n')) != NULL && user_count < MAX_USERS) {
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
                printf("Failed to allocate memory for user\n");
                free(new_username);
                continue;
            }
            if (!new_username) {
                printf("Failed to allocate memory for username\n");
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
            // Check if user already exists
            pthread_mutex_lock(&user_map_mutex);
            pthread_mutex_lock(&username_map_mutex);
            if (find_user(account_id) == NULL && find_username(username) == NULL) {
                HASH_ADD_INT(user_map, account_id, new_user);
                HASH_ADD_STR(username_map, username, new_username);
                
                loaded_count++;
                user_count++;
            } else {
               
                printf("Skipping duplicate account ID: %u\n", account_id);
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
            printf("Invalid line format: %s\n", line_start);
        }
        // Restore newline and move to next line
        *line_end = '\n';
        line_start = line_end + 1;
    }
    
    // Handle last line if it doesn't end with newline
    if (line_start < data + decrypt_result.size && user_count < MAX_USERS) {
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
                pthread_mutex_lock(&user_map_mutex);
                pthread_mutex_lock(&username_map_mutex);
                if (find_user(account_id) == NULL && find_username(username) == NULL) {
                    
                    HASH_ADD_INT(user_map, account_id, new_user);
                    
                    HASH_ADD_STR(username_map, username, new_username);
                    
                    loaded_count++;
                    user_count++;
                } else {
                    printf("Skipping duplicate user ID: %u\n", account_id);
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
            printf("Invalid last line format: %s\n", line_start);
        }
    }
    // Free the decrypted data (this also clears sensitive data)
    free_decryption_result(&decrypt_result);
    
    printf("Loaded %d users from encrypted database\n", loaded_count);
    rsa_system_initialized = (loaded_count > 0);  // RSA system is initialized if we loaded any users with keys
    
    return loaded_count > 0;
}

// Check if a message is an authentication command
int is_auth_command(const char* message) {
    return (strncmp(message, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
            strncmp(message, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0 ||
            strncmp(message, AUTH_LOGOUT, strlen(AUTH_LOGOUT)) == 0 ||
  
            is_rsa_command(message));
}

int is_token_command(const char* message) {
    int is_token = (strncmp(message, AUTH_TOKEN, strlen(AUTH_TOKEN)) == 0 ||
                   strncmp(message, AUTH_NEW_TOKEN, strlen(AUTH_NEW_TOKEN)) == 0);
    printf("DEBUG: is_token_command('%s') = %d (AUTH_TOKEN='%s', AUTH_NEW_TOKEN='%s')\n", 
           message, is_token, AUTH_TOKEN, AUTH_NEW_TOKEN);
    printf("the result of is_token_command is %d\n", is_token);
    return is_token;
}




// Process authentication command and return result
auth_result_t process_auth_command(const char* message, int account_id) {
    auth_result_t result = {0};
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
                    "%s Welcome, %s! You are now fully authenticated.", 
                    AUTH_SUCCESS, username);
        } else if (auth_result == 2) {
            // Password verified, email token sent
            result.success = 1;
            result.authenticated = 0;  // Not fully authenticated yet
            snprintf(result.response, sizeof(result.response), 
                    "%s Password verified. Please check your email for a 6-digit token and enter it with: /token <code>", 
                    AUTH_SUCCESS);
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
                    "%s User %s registered successfully. You can now login.", 
                    AUTH_SUCCESS, username);
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
                "%s You have been logged out.", AUTH_SUCCESS);
    } else {
        result.success = 0;
        result.authenticated = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Unknown command. Use /login, /register, or /logout", 
                AUTH_FAILED);
    }
    
    return result;
} 





// Initialize RSA system - now just verifies server keys
int init_rsa_system(const char* server_private_key_file, const char* server_public_key_file) {
    printf("Initializing RSA authentication system...\n");
    
    // Load server keys
    rsa_keypair_t* loaded_keys = load_rsa_keys(server_private_key_file, server_public_key_file);
    if (!loaded_keys) {
        printf("Failed to load server RSA keys\n");
        return 0;
    }
    
    server_keys = *loaded_keys;
    free(loaded_keys);
    
    // RSA system is considered initialized if server keys are loaded
    // (client keys are now managed with user data)
    rsa_system_initialized = 1;
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
    if (!keys) return NULL;
    
    keys->private_key = NULL;
    keys->public_key = NULL;
    
    // Load private key
    FILE* fp_private = fopen(private_key_file, "r");
    if (!fp_private) {
        printf("Error opening private key file: %s\n", private_key_file);
        free(keys);
        return NULL;
    }
    
    keys->private_key = PEM_read_PrivateKey(fp_private, NULL, NULL, NULL);
    fclose(fp_private);
    
    if (!keys->private_key) {
        printf("Error reading private key from file\n");
        free(keys);
        return NULL;
    }
    
    // Load public key
    FILE* fp_public = fopen(public_key_file, "r");
    if (!fp_public) {
        printf("Error opening public key file: %s\n", public_key_file);
        EVP_PKEY_free(keys->private_key);
        free(keys);
        return NULL;
    }
    
    keys->public_key = PEM_read_PUBKEY(fp_public, NULL, NULL, NULL);
    fclose(fp_public);
    
    if (!keys->public_key) {
        printf("Error reading public key from file\n");
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
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
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
        pthread_mutex_lock(&session_map_mutex);
        HASH_ADD_INT(session_map, account_id, session);
        pthread_mutex_unlock(&session_map_mutex);
        session_count++;
        printf("[DEBUG] Created session for account %d and stored client_pubkey.\n", account_id);
    }
    // Generate random challenge
    if (RAND_bytes(session->challenge, RSA_CHALLENGE_SIZE) != 1) {
        snprintf(result.response, sizeof(result.response), "%s Failed to generate challenge", RSA_AUTH_FAILED);
        cleanup_session(session);
        return result;
    }
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
    printf("\nCurrently verifying challenge in verify_rsa_response.\n");
    if (!rsa_system_initialized || !server_keys.private_key) {
        snprintf(result.response, sizeof(result.response), 
                "%s RSA system not initialized", RSA_AUTH_FAILED);
        return result;
    }
    
    printf("RSA system initialized and server private key loaded.\n");
    // Find session
    pthread_mutex_lock(&user_map_mutex);
    user_t *user = find_user(account_id);
    pthread_mutex_unlock(&user_map_mutex);
    if (!user) {
        snprintf(result.response, sizeof(result.response), 
                "%s No user for account %d", RSA_AUTH_FAILED, account_id);
        printf("ERROR: No user found for account %d\n", account_id);
        return result;
    }
    
    session_t *session = NULL;
    pthread_mutex_lock(&session_map_mutex);
    HASH_FIND_INT(session_map, &account_id, session);
    pthread_mutex_unlock(&session_map_mutex);
    if (!session) {
        snprintf(result.response, sizeof(result.response), 
                "%s No active session", RSA_AUTH_FAILED);
        printf("ERROR: No active session found for account %d\n", account_id);
        return result;
    }
    
    printf("SUCCESS: Found session for account %d (auth=%d, rsa_auth=%d)\n", 
           account_id, (session->auth_status & AUTH_PASSWORD) ? 1 : 0, 
           (session->auth_status & AUTH_RSA) ? 1 : 0);
    
    // Decrypt the response with server's private key
    unsigned char decrypted_challenge[RSA_DECRYPT_BUFFER_SIZE];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_keys.private_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        ERR_print_errors_fp(stdout);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to setup decryption", RSA_AUTH_FAILED);
        printf("failed to setup decryption\n");
        return result;
    }
    
    size_t outlen = sizeof(decrypted_challenge);  // Use actual buffer size

    
    int decrypt_result = EVP_PKEY_decrypt(ctx, decrypted_challenge, &outlen, encrypted_response, response_size);
   
    if (decrypt_result <= 0) {
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to decrypt response", RSA_AUTH_FAILED);
        printf("ERROR: Decryption failed\n");
        return result;
    }
    
    if (outlen != RSA_CHALLENGE_SIZE) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Decrypted size mismatch", RSA_AUTH_FAILED);
        printf("ERROR: Length mismatch - got %zu bytes, expected %d bytes\n", 
               outlen, RSA_CHALLENGE_SIZE);
        return result;
    }
    
    EVP_PKEY_CTX_free(ctx);
   
    // Verify challenge matches
    if (memcmp(session->challenge, decrypted_challenge, RSA_CHALLENGE_SIZE) == 0) {
        session->auth_status |= AUTH_RSA;  // Set RSA authentication flag
        result.success = 1;
        snprintf(result.response, sizeof(result.response), 
                "%s RSA authentication successful", RSA_AUTH_SUCCESS);
        
        printf("RSA authentication successful for account %d\n", account_id);
    } else {
        result.success = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Challenge verification failed", RSA_AUTH_FAILED);
        
        printf("RSA challenge verification failed for account %d\n", account_id);
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
    
    printf("\n\nProcessing RSA command...\n");
   if (strncmp(message, RSA_AUTH_RESPONSE, strlen(RSA_AUTH_RESPONSE)) == 0) {
        // Process RSA response
        char command[64];
        char hex_response[RSA_HEX_BUFFER_SIZE];
        printf("Recieved RSA response command\n");
        if (sscanf(message, "%63s %512s", command, hex_response) != 2) {
            snprintf(result.response, sizeof(result.response), 
                    "%s Invalid format. Use: %s <hex_encrypted_response>", 
                    RSA_AUTH_FAILED, RSA_AUTH_RESPONSE);
            return result;
        }
        
        // Convert hex string to binary
        unsigned char encrypted_response[MAX_RSA_ENCRYPTED_SIZE];
        int response_size = strlen(hex_response) / 2;
        
        if (response_size > MAX_RSA_ENCRYPTED_SIZE) {
            snprintf(result.response, sizeof(result.response), 
                    "%s Response too large", RSA_AUTH_FAILED);
            return result;
        }
        
        for (int i = 0; i < response_size; i++) {
            sscanf(hex_response + (i * 2), "%2hhx", &encrypted_response[i]);
        }
        
        printf("Verifying RSA response...\n");
        return verify_rsa_response(account_id, encrypted_response, response_size);
    }
    
    snprintf(result.response, sizeof(result.response), 
            "%s Unknown RSA command", RSA_AUTH_FAILED);
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

void save_lockout_status_for_session(session_t *session) {
    if (!session) return;
    
    time_t now = time(NULL);
    // Convert absolute unlock time to relative seconds remaining
    int seconds_remaining = session->email_token.lockout_until - now;
    
    // Only save if there's remaining lockout time
    if (seconds_remaining > 0) {
        FILE* file = fopen("userStatus.txt", "a");
        if (file) {
            // Store as "account_id:seconds_remaining"
            fprintf(file, "%d:%d\n", session->account_id, seconds_remaining);
            fclose(file);
        }
    }
}

void cleanup_session(session_t *session) {    
    if (session == NULL) {
        return;
    }
    
    // Save lockout status if needed
    if (session->email_token.lockout_until > 0) {
        save_lockout_status_for_session(session);
        session->email_token.lockout_until = 0;
    }
    
    // Session doesn't own the user - just clear the reference
    // The user will be freed separately when cleaning up the user_map
    session->user = NULL;
    
    free(session);
}
// Cleanup RSA system
void cleanup_rsa_system(void) {
    if (server_keys.private_key) {
        EVP_PKEY_free(server_keys.private_key);
        server_keys.private_key = NULL;
    }
    
    if (server_keys.public_key) {
        EVP_PKEY_free(server_keys.public_key);
        server_keys.public_key = NULL;
    }
    
    rsa_system_initialized = 0;
    printf("RSA authentication system cleaned up\n");
}

// Clean up auth system resources
void cleanup_auth_system(void) {
    printf("Starting authentication system cleanup...\n");
    
    // Step 1: Clean up sessions first (they reference users but don't own them)
    if (session_map) {
        session_t *current, *temp;
        printf("Cleaning up %d sessions...\n", session_count);
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
        printf("Cleaning up %d users...\n", user_count);
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
        printf("Cleaning up username mappings...\n");
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
    printf("Authentication system cleanup complete\n");
}

rsa_challenge_result_t start_rsa_challenge_with_pubkey(EVP_PKEY* pubkey) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    if (!rsa_system_initialized) {
        snprintf(result.response, sizeof(result.response), "%s RSA system not initialized", RSA_AUTH_FAILED);
        return result;
    }
    // Generate random challenge
    unsigned char challenge[RSA_CHALLENGE_SIZE];
    if (RAND_bytes(challenge, RSA_CHALLENGE_SIZE) != 1) {
        snprintf(result.response, sizeof(result.response), "%s Failed to generate challenge", RSA_AUTH_FAILED);
        return result;
    }
    // Use the provided public key for encryption
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pubkey, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), "%s Failed to setup encryption", RSA_AUTH_FAILED);
        return result;
    }
    size_t outlen = MAX_RSA_ENCRYPTED_SIZE;
    if (EVP_PKEY_encrypt(ctx, result.encrypted_challenge, &outlen, challenge, RSA_CHALLENGE_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), "%s Failed to encrypt challenge", RSA_AUTH_FAILED);
        return result;
    }
    result.encrypted_size = outlen;
    EVP_PKEY_CTX_free(ctx);
    memcpy(result.challenge, challenge, RSA_CHALLENGE_SIZE);
    result.success = 1;
    snprintf(result.response, sizeof(result.response), "%s Challenge generated", RSA_AUTH_SUCCESS);
    return result;
}