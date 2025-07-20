#include "auth_system.h"
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include "hashmap/hashmap.h"


// Global variables
static struct hashmap *users = NULL;

static session_t sessions[MAX_USERS];
static int user_count = 0;
static int session_count = 0;

// RSA Authentication global variables
static rsa_keypair_t server_keys = {NULL, NULL};
static struct hashmap *client_keys_map = NULL;  // Maps client_id -> client_key_entry_t
static int client_key_count = 0;
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

// Hashmap functions for client key entries
int client_key_compare(const void *a, const void *b, void* udata) {
    const client_key_entry_t *ca = a;
    const client_key_entry_t *cb = b;
    return strcmp(ca->client_id, cb->client_id);
}

uint64_t client_key_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const client_key_entry_t *entry = item;
    return hashmap_sip(entry->client_id, strlen(entry->client_id), seed0, seed1);
}

// Create a client key entry for lookup
client_key_entry_t create_client_key_entry(const char* client_id) {
    client_key_entry_t entry;
    strncpy(entry.client_id, client_id, MAX_USERNAME_LEN - 1);
    entry.client_id[MAX_USERNAME_LEN - 1] = '\0';
    entry.public_key = NULL;
    return entry;
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

// Initialize authentication system - deprecated
/*void init_auth_system(void) {
    users = hashmap_new(sizeof(user_t), 0, 0, 0, user_hash, user_compare, NULL, NULL);

    user_count = 0;
    session_count = 0;
    
    load_users_from_file("users.txt");
    
}*/

int init_encrypted_auth_system(char* userFile, char* key) {
    users = hashmap_new(sizeof(user_t), 0, 0, 0, user_hash, user_compare, NULL, NULL);
    user_count = 0;
    session_count = 0;
    
    return load_users_from_encrypted_file(userFile, key);
    
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

// Authenticate a user (now REQUIRES RSA authentication first when RSA is enabled)
int authenticate_user(const char* username, const char* password, int client_socket) {
    // MANDATORY: RSA authentication must be completed first when RSA system is active
    if (rsa_system_initialized) {
        if (!is_rsa_authenticated(client_socket)) {
            printf("SECURITY BLOCK: RSA authentication required but not completed for user: %s from socket %d\n", 
                   username, client_socket);
            return 0; // HARD BLOCK - no login without RSA
        }
        printf("RSA authentication verified for user: %s from socket %d\n", username, client_socket);
    }
    
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

// Load users from file - deprecated
/*
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
*/

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
            strncmp(message, AUTH_LOGOUT, strlen(AUTH_LOGOUT)) == 0 ||
            is_rsa_command(message));
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
        if (authenticate_user(username, password, client_socket)) {
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
            if (rsa_system_initialized && !is_rsa_authenticated(client_socket)) {
                snprintf(result.response, sizeof(result.response), 
                        "%s RSA authentication required. Use %s first", AUTH_FAILED, RSA_AUTH_START);
            } else {
                snprintf(result.response, sizeof(result.response), 
                        "%s Invalid username or password", AUTH_FAILED);
            }
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

// ================================
// RSA AUTHENTICATION IMPLEMENTATION
// ================================

// Dynamically load all client public keys from directory
int load_all_client_keys_dynamic(void) {
    DIR *dir;
    struct dirent *ent;
    
    // Initialize client keys hashmap
    if (client_keys_map) {
        hashmap_free(client_keys_map);
    }
    client_keys_map = hashmap_new(sizeof(client_key_entry_t), 0, 0, 0, 
                                  client_key_hash, client_key_compare, NULL, NULL);
    client_key_count = 0;
    
    // Open current directory
    dir = opendir(".");
    if (!dir) {
        printf("Could not open current directory for key scanning\n");
        return 0;
    }
    
    printf("Scanning for client public key files...\n");
    
    // Scan for files matching pattern client_*_public.pem
    while ((ent = readdir(dir)) != NULL && client_key_count < MAX_USERS) {
        // Check if filename matches pattern: client_*_public.pem
        if (strncmp(ent->d_name, "client_", 7) == 0 && 
            strstr(ent->d_name, "_public.pem") != NULL) {
            
            // Extract client_id from filename
            char client_id[MAX_USERNAME_LEN];
            const char* start = ent->d_name + 7;  // Skip "client_"
            const char* end = strstr(start, "_public.pem");
            
            if (end && (end - start) < MAX_USERNAME_LEN - 1) {
                strncpy(client_id, start, end - start);
                client_id[end - start] = '\0';
                
                // Load the public key
                EVP_PKEY* key = load_public_key(ent->d_name);
                if (key) {
                    // Create and store client key entry
                    client_key_entry_t entry = create_client_key_entry(client_id);
                    entry.public_key = key;
                    
                    hashmap_set(client_keys_map, &entry);
                    client_key_count++;
                    printf("Loaded client public key for '%s': %s\n", client_id, ent->d_name);
                }
            }
        }
    }
    
    closedir(dir);
    printf("Loaded %d client public keys\n", client_key_count);
    return client_key_count;
}

// Find a client's public key by client_id
EVP_PKEY* find_client_public_key(const char* client_id) {
    if (!client_keys_map || !client_id) {
        return NULL;
    }
    
    client_key_entry_t lookup = create_client_key_entry(client_id);
    const client_key_entry_t *found = hashmap_get(client_keys_map, &lookup);
    
    return found ? found->public_key : NULL;
}

// Get count of loaded client keys
int get_loaded_client_count(void) {
    return client_key_count;
}

// Initialize RSA authentication system
int init_rsa_system(const char* server_private_key_file, const char* server_public_key_file) {
    
    printf("Initializing RSA authentication system...\n");
    
    // Load server keys
    server_keys.private_key = NULL;
    server_keys.public_key = NULL;
    
    rsa_keypair_t* loaded_keys = load_rsa_keys(server_private_key_file, server_public_key_file);
    if (!loaded_keys) {
        printf("Failed to load server RSA keys\n");
        return 0;
    }
    
    server_keys = *loaded_keys;
    free(loaded_keys);
    
    // Load all available client public keys dynamically
    int loaded_clients = load_all_client_keys_dynamic();
    if (loaded_clients == 0) {
        printf("Failed to load any client public keys\n");
        cleanup_rsa_system();
        return 0;
    }
    
    printf("Loaded %d client public key(s)\n", loaded_clients);
    
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
rsa_challenge_result_t start_rsa_challenge(int client_socket) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    
    if (!rsa_system_initialized || client_key_count == 0) {
        snprintf(result.response, sizeof(result.response), 
                "%s RSA system not initialized", RSA_AUTH_FAILED);
        return result;
    }
    
    // Find or create session
    session_t* session = get_session(client_socket);
    if (!session) {
        // Create temporary session for RSA auth
        if (session_count >= MAX_USERS) {
            snprintf(result.response, sizeof(result.response), 
                    "%s Server full", RSA_AUTH_FAILED);
            return result;
        }
        
        sessions[session_count].client_socket = client_socket;
        sessions[session_count].login_time = time(NULL);
        sessions[session_count].authenticated = 0;
        sessions[session_count].rsa_authenticated = 0;
        session = &sessions[session_count];
        session_count++;
    }
    
    // Generate random challenge
    if (RAND_bytes(session->challenge, RSA_CHALLENGE_SIZE) != 1) {
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to generate challenge", RSA_AUTH_FAILED);
        return result;
    }
    
    // Get any available client public key for challenge encryption
    // Note: This uses the first available key - in practice, the client with the matching
    // private key will be able to decrypt it, others will fail gracefully
    EVP_PKEY* first_client_key = NULL;
    
    // Iterate through hashmap to find first available key
    size_t iter = 0;
    void *item;
    while (hashmap_iter(client_keys_map, &iter, &item)) {
        client_key_entry_t *entry = (client_key_entry_t*)item;
        if (entry && entry->public_key) {
            first_client_key = entry->public_key;
            break;
        }
    }
    
    if (!first_client_key) {
        snprintf(result.response, sizeof(result.response), 
                "%s No client public keys available", RSA_AUTH_FAILED);
        return result;
    }
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(first_client_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to setup encryption", RSA_AUTH_FAILED);
        return result;
    }
    
    size_t outlen = MAX_RSA_ENCRYPTED_SIZE;
    if (EVP_PKEY_encrypt(ctx, result.encrypted_challenge, &outlen, session->challenge, RSA_CHALLENGE_SIZE) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to encrypt challenge", RSA_AUTH_FAILED);
        return result;
    }
    
    result.encrypted_size = outlen;
    EVP_PKEY_CTX_free(ctx);
    
    // Copy challenge for verification later
    memcpy(result.challenge, session->challenge, RSA_CHALLENGE_SIZE);
    
    result.success = 1;
    snprintf(result.response, sizeof(result.response), 
            "%s Challenge generated", RSA_AUTH_SUCCESS);
    
    printf("RSA challenge generated for client socket %d\n", client_socket);
    return result;
}

// Verify RSA response from client
rsa_challenge_result_t verify_rsa_response(int client_socket, const unsigned char* encrypted_response, int response_size) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    
    if (!rsa_system_initialized || !server_keys.private_key) {
        snprintf(result.response, sizeof(result.response), 
                "%s RSA system not initialized", RSA_AUTH_FAILED);
        return result;
    }
    
    // Find session
    session_t* session = get_session(client_socket);
    if (!session) {
        snprintf(result.response, sizeof(result.response), 
                "%s No active session", RSA_AUTH_FAILED);
        return result;
    }
    
    // Decrypt the response with server's private key
    unsigned char decrypted_challenge[RSA_CHALLENGE_SIZE + 1];
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_keys.private_key, NULL);
    if (!ctx || EVP_PKEY_decrypt_init(ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to setup decryption", RSA_AUTH_FAILED);
        return result;
    }
    
    size_t outlen = RSA_CHALLENGE_SIZE;
    if (EVP_PKEY_decrypt(ctx, decrypted_challenge, &outlen, encrypted_response, response_size) <= 0 ||
        outlen != RSA_CHALLENGE_SIZE) {
        EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), 
                "%s Failed to decrypt response", RSA_AUTH_FAILED);
        return result;
    }
    
    EVP_PKEY_CTX_free(ctx);
    
    // Verify challenge matches
    if (memcmp(session->challenge, decrypted_challenge, RSA_CHALLENGE_SIZE) == 0) {
        session->rsa_authenticated = 1;
        result.success = 1;
        snprintf(result.response, sizeof(result.response), 
                "%s RSA authentication successful", RSA_AUTH_SUCCESS);
        
        printf("RSA authentication successful for client socket %d\n", client_socket);
    } else {
        result.success = 0;
        snprintf(result.response, sizeof(result.response), 
                "%s Challenge verification failed", RSA_AUTH_FAILED);
        
        printf("RSA challenge verification failed for client socket %d\n", client_socket);
    }
    
    // Clear the challenge from memory
    memset(session->challenge, 0, RSA_CHALLENGE_SIZE);
    
    return result;
}

// Check if message is an RSA command
int is_rsa_command(const char* message) {
    return (strncmp(message, RSA_AUTH_START, strlen(RSA_AUTH_START)) == 0 ||
            strncmp(message, RSA_AUTH_RESPONSE, strlen(RSA_AUTH_RESPONSE)) == 0);
}

// Process RSA authentication command
rsa_challenge_result_t process_rsa_command(const char* message, int client_socket) {
    rsa_challenge_result_t result;
    memset(&result, 0, sizeof(result));
    
    if (strncmp(message, RSA_AUTH_START, strlen(RSA_AUTH_START)) == 0) {
        // Start RSA challenge
        return start_rsa_challenge(client_socket);
        
    } else if (strncmp(message, RSA_AUTH_RESPONSE, strlen(RSA_AUTH_RESPONSE)) == 0) {
        // Process RSA response
        char command[64];
        char hex_response[MAX_RSA_ENCRYPTED_SIZE * 2 + 1];
        
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
        
        return verify_rsa_response(client_socket, encrypted_response, response_size);
    }
    
    snprintf(result.response, sizeof(result.response), 
            "%s Unknown RSA command", RSA_AUTH_FAILED);
    return result;
}

// Check if client has completed RSA authentication
int is_rsa_authenticated(int client_socket) {
    session_t* session = get_session(client_socket);
    return session ? session->rsa_authenticated : 0;
}

// Check if RSA system is initialized
int is_rsa_system_initialized(void) {
    return rsa_system_initialized;
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
    
    // Clean up client keys hashmap
    if (client_keys_map) {
        // First, free all the EVP_PKEY objects
        size_t iter = 0;
        void *item;
        while (hashmap_iter(client_keys_map, &iter, &item)) {
            client_key_entry_t *entry = (client_key_entry_t*)item;
            if (entry && entry->public_key) {
                EVP_PKEY_free(entry->public_key);
                entry->public_key = NULL;
            }
        }
        
        // Free the hashmap itself
        hashmap_free(client_keys_map);
        client_keys_map = NULL;
    }
    client_key_count = 0;
    
    rsa_system_initialized = 0;
    printf("RSA authentication system cleaned up\n");
}