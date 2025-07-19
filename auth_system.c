#include "auth_system.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include "hashmap/hashmap.h"


// Global variables
static struct hashmap *users = NULL;

static session_t sessions[MAX_USERS];
static int user_count = 0;
static int session_count = 0;

// Simple hash function (in production, use a proper cryptographic hash)
void hash_password(const char* password, char* hash) {
    unsigned long hash_val = 5381;
    int c;
    
    while ((c = *password++)) {
        hash_val = ((hash_val << 5) + hash_val) + c; // hash * 33 + c
    }
    
    sprintf(hash, "%08lx", hash_val);
}
int user_compare(const void *a, const void *b, void* udata) {
    const user_t *ua = a;
    const user_t *ub = b;
    return strcmp(ua->username, ub->username);
}

bool user_iter(const void *item, void* udata) {
    const user_t *user = item;
    printf("%s\n", user->username);
    return true;
}

uint64_t user_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const user_t *user = item;
    return hashmap_sip(user->username, strlen(user->username), seed0, seed1);
}

// Constructor: create a user_t with just a username (for lookups)
user_t create_user(const char* username) {
    user_t user;
    strncpy(user.username, username, MAX_USERNAME_LEN - 1);
    user.username[MAX_USERNAME_LEN - 1] = '\0';
    user.password_hash[0] = '\0';  // Empty password hash
    user.active = 0;               // Default to inactive
    return user;
}
// Verify password against hash
int verify_password(const char* password, const char* hash) {
    char computed_hash[MAX_HASH_LEN];
    hash_password(password, computed_hash);
    printf("recieved: %s expected: %s", computed_hash, hash);

    return strcmp(computed_hash, hash) == 0;
}

// Initialize authentication system
void init_auth_system(void) {
    users = hashmap_new(sizeof(user_t), 0, 0, 0, user_hash, user_compare, NULL, NULL);

    user_count = 0;
    session_count = 0;
    
    load_users_from_file("users.txt");
    
}

int init_encrypted_auth_system(char* userFile, char* key) {
    users = hashmap_new(sizeof(user_t), 0, 0, 0, user_hash, user_compare, NULL, NULL);
    user_count = 0;
    session_count = 0;
    
    load_users_from_encrypted_file(userFile, key);
    
}

// Add a new user
int add_user(const char* username, const char* password) {
    if (user_count >= MAX_USERS) {
        return 0; // No space
    }
    
    // Check if username already exists
    user_t lookup_user = create_user(username);
    
    const user_t *found_ptr = hashmap_get(users, &lookup_user);
    if (found_ptr != NULL) {
        return 0; // Username already exists
    }
    
    // Create new user with password and active status
    hash_password(password, lookup_user.password_hash);
    lookup_user.active = 1;
    hashmap_set(users, &lookup_user);
    

    
    return 1; // Success
}

// Authenticate a user
int authenticate_user(const char* username, const char* password) {
    user_t lookup_user = create_user(username);
    
    const user_t *found_ptr = hashmap_get(users, &lookup_user);
    if (found_ptr != NULL) {
        user_t found_user = *found_ptr;  // Copy the contents, not the pointer
        if (found_user.active) {
            return verify_password(password, found_user.password_hash);
        }
    }
    return 0; // User not found or password incorrect
}

// Create a new session
int create_session(const char* username, int client_socket) {
    // Remove any existing session for this socket
    remove_session(client_socket);
    
    if (session_count >= MAX_USERS) {
        return 0; // No space
    }
    
    strncpy(sessions[session_count].username, username, MAX_USERNAME_LEN - 1);
    sessions[session_count].username[MAX_USERNAME_LEN - 1] = '\0';
    sessions[session_count].client_socket = client_socket;
    sessions[session_count].login_time = time(NULL);
    sessions[session_count].authenticated = 1;
    session_count++;
    
    return 1; // Success
}

// Remove a session
void remove_session(int client_socket) {
    for (int i = 0; i < session_count; i++) {
        if (sessions[i].authenticated && sessions[i].client_socket == client_socket) {
            // Move last session to this position
            if (i < session_count - 1) {
                sessions[i] = sessions[session_count - 1];
            }
            session_count--;
            break;
        }
    }
}

// Get session for a socket
session_t* get_session(int client_socket) {
    for (int i = 0; i < session_count; i++) {
        if (sessions[i].authenticated && sessions[i].client_socket == client_socket) {
            return &sessions[i];
        }
    }
    return NULL;
}

// Check if a socket is authenticated
int is_authenticated(int client_socket) {
    session_t* session = get_session(client_socket);
    if (!session) return 0;
    
    // Check if session has expired
    if (time(NULL) - session->login_time > AUTH_TIMEOUT) {
        remove_session(client_socket);
        return 0;
    }
    
    return 1;
}

// Clean up expired sessions
void cleanup_expired_sessions(void) {
    time_t current_time = time(NULL);
    for (int i = session_count - 1; i >= 0; i--) {
        if (current_time - sessions[i].login_time > AUTH_TIMEOUT) {
            printf("Session expired for user: %s\n", sessions[i].username);
            remove_session(sessions[i].client_socket);
        }
    }
}

// Save users to file
/*void save_users_to_file(const char* filename) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        printf("Failed to open file for writing: %s\n", filename);
        return;
    }
    
    for (int i = 0; i < user_count; i++) {
        if (users[i].active) {
            fprintf(file, "%s:%s\n", users[i].username, users[i].password_hash);
        }
    }
    
    fclose(file);
    printf("Users saved to %s\n", filename);
}*/

// Load users from file
void load_users_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Failed to open file for reading: %s\n", filename);
        return;
    }
    
    char line[256];
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    int loaded_count = 0;
    
    while (fgets(line, sizeof(line), file) && user_count < MAX_USERS) {
        if (sscanf(line, "%31[^:]:%64s", username, password_hash) == 2) {
            user_t new_user = create_user(username);
            strncpy(new_user.password_hash, password_hash, MAX_HASH_LEN - 1);
            new_user.password_hash[MAX_HASH_LEN - 1] = '\0';
            new_user.active = 1;

            // Check if user already exists
            user_t lookup_user = create_user(username);
            const user_t *found_ptr = hashmap_get(users, &lookup_user);
            
            if (found_ptr == NULL) {
                // User doesn't exist, add them
                hashmap_set(users, &new_user);
                loaded_count++;
                user_count++;
            }    
        }
    }
    
    fclose(file);
    printf("Loaded %d new users from %s", loaded_count, filename);
    
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
    
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];  // Plaintext password from decrypted data
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
        
        // Parse username:password format
        if (sscanf(line_start, "%31[^:]:%63s", username, password) == 2) {
            user_t new_user = create_user(username);
            
            // Hash the plaintext password immediately
            hash_password(password, new_user.password_hash);
            new_user.password_hash[MAX_HASH_LEN - 1] = '\0';
            new_user.active = 1;

            // Check if user already exists
            user_t lookup_user = create_user(username);
            const user_t *found_ptr = hashmap_get(users, &lookup_user);
            
            if (found_ptr == NULL) {
                // User doesn't exist, add them
                hashmap_set(users, &new_user);
                loaded_count++;
                user_count++;
                printf("Loaded user: %s\n", username);

            }
            
            // Clear the plaintext password from memory immediately
            memset(password, 0, sizeof(password));
        }
        
        // Restore newline and move to next line
        *line_end = '\n';
        line_start = line_end + 1;
    }
    
    // Handle last line if it doesn't end with newline
    if (line_start < data + decrypt_result.size && user_count < MAX_USERS) {
        if (sscanf(line_start, "%31[^:]:%63s", username, password) == 2) {
            user_t new_user = create_user(username);
            
            hash_password(password, new_user.password_hash);
            new_user.password_hash[MAX_HASH_LEN - 1] = '\0';
            new_user.active = 1;

            user_t lookup_user = create_user(username);
            const user_t *found_ptr = hashmap_get(users, &lookup_user);
            
            if (found_ptr == NULL) {
                hashmap_set(users, &new_user);
                loaded_count++;
                user_count++;
                printf("Loaded user: %s\n", username);
            }
            
            memset(password, 0, sizeof(password));
        }
    }
    
    // Free the decrypted data (this also clears sensitive data)
    free_decryption_result(&decrypt_result);
    
    printf("Successfully loaded %d users from encrypted file\n", loaded_count);
    return 1;
}

// Check if a message is an authentication command
int is_auth_command(const char* message) {
    return (strncmp(message, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
            strncmp(message, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0 ||
            strncmp(message, AUTH_LOGOUT, strlen(AUTH_LOGOUT)) == 0);
}

// Process authentication command and return result
auth_result_t process_auth_command(const char* message, int client_socket) {
    auth_result_t result = {0};
    char command[64], username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN];
    
    // Parse the authentication message
    if (sscanf(message, "%63s %31s %63s", command, username, password) != 3) {
        result.success = 0;
        result.authenticated = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Invalid format. Use: /login <username> <password> or /register <username> <password>", 
                AUTH_FAILED);
        return result;
    }
    
    // Copy username for logging
    strncpy(result.username, username, MAX_USERNAME_LEN - 1);
    result.username[MAX_USERNAME_LEN - 1] = '\0';
    
    if (strcmp(command, AUTH_LOGIN) == 0) {
        if (authenticate_user(username, password)) {
            if (create_session(username, client_socket)) {
                result.success = 1;
                result.authenticated = 1;
                snprintf(result.response, sizeof(result.response), 
                        "%s Welcome, %s! You are now authenticated.", 
                        AUTH_SUCCESS, username);
            } else {
                result.success = 0;
                result.authenticated = 0;
                snprintf(result.response, sizeof(result.response), 
                        "%s Session creation failed", AUTH_FAILED);
            }
        } else {
            result.success = 0;
            result.authenticated = 0;
            snprintf(result.response, sizeof(result.response), 
                    "%s Invalid username or password\n", AUTH_FAILED);
        }
    } else if (strcmp(command, AUTH_REGISTER) == 0) {
        if (add_user(username, password)) {
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
        remove_session(client_socket);
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