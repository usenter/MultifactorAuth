#include "auth_system.h"
#include <time.h>

// Global variables
static user_t users[MAX_USERS];
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

// Verify password against hash
int verify_password(const char* password, const char* hash) {
    char computed_hash[MAX_HASH_LEN];
    hash_password(password, computed_hash);
    return strcmp(computed_hash, hash) == 0;
}

// Initialize authentication system
void init_auth_system(void) {
    memset(users, 0, sizeof(users));
    memset(sessions, 0, sizeof(sessions));
    user_count = 0;
    session_count = 0;
    
    // Add some default users
    add_user("admin", "admin123");
    add_user("user1", "password1");
    add_user("user2", "password2");
    
    printf("Authentication system initialized with %d default users\n", user_count);
}

// Add a new user
int add_user(const char* username, const char* password) {
    if (user_count >= MAX_USERS) {
        return 0; // No space
    }
    
    // Check if username already exists
    for (int i = 0; i < user_count; i++) {
        if (users[i].active && strcmp(users[i].username, username) == 0) {
            return 0; // Username already exists
        }
    }
    
    // Add new user
    strncpy(users[user_count].username, username, MAX_USERNAME_LEN - 1);
    users[user_count].username[MAX_USERNAME_LEN - 1] = '\0';
    hash_password(password, users[user_count].password_hash);
    users[user_count].active = 1;
    user_count++;
    
    return 1; // Success
}

// Authenticate a user
int authenticate_user(const char* username, const char* password) {
    for (int i = 0; i < user_count; i++) {
        if (users[i].active && strcmp(users[i].username, username) == 0) {
            return verify_password(password, users[i].password_hash);
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
void save_users_to_file(const char* filename) {
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
}

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
    
    while (fgets(line, sizeof(line), file) && user_count < MAX_USERS) {
        if (sscanf(line, "%31[^:]:%64s", username, password_hash) == 2) {
            strncpy(users[user_count].username, username, MAX_USERNAME_LEN - 1);
            users[user_count].username[MAX_USERNAME_LEN - 1] = '\0';
            strncpy(users[user_count].password_hash, password_hash, MAX_HASH_LEN - 1);
            users[user_count].password_hash[MAX_HASH_LEN - 1] = '\0';
            users[user_count].active = 1;
            user_count++;
        }
    }
    
    fclose(file);
    printf("Loaded %d users from %s\n", user_count, filename);
} 