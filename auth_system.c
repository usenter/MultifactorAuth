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
/*
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
}*/



/*
// Hashmap functions for sessions
int session_compare(const void *a, const void *b, void* udata) {
    const session_t *sa = a;
    const session_t *sb = b;
    return sa->client_socket - sb->client_socket;
}

uint64_t session_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    const session_t *session = item;
    return hashmap_sip(&session->client_socket, sizeof(session->client_socket), seed0, seed1);
}
    */
/*
// Create a session for lookup
session_t create_session_lookup(int client_socket) {
    session_t session;
    memset(&session, 0, sizeof(session));
    session.client_socket = client_socket;
    return session;
}

// Constructor: create a user_t with just a username (for lookups)
user_t create_user(const char* username) {
    user_t user;
    strncpy(user.username, username, MAX_USERNAME_LEN - 1);
    user.username[MAX_USERNAME_LEN - 1] = '\0';
    user.password_hash[0] = '\0';  // Empty password hash
    user.active = 0;               // Default to inactive
    return user;
}*/
// Verify password against hash
int verify_password(const char* password, const char* hash) {
    char computed_hash[MAX_HASH_LEN];
    hash_password(password, computed_hash);

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
    user_map = NULL;
    session_map = NULL;
    user_count = 0;
    session_count = 0;
    
    return load_users_from_encrypted_file(userFile, key);
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
    if(find_user(account_id) == NULL) {
        HASH_ADD_INT(user_map, account_id, user);
        user_count++;
    }
    else{
        printf("User already exists\n");
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
    // MANDATORY: RSA authentication must be completed first when RSA system is active
    if (rsa_system_initialized) {
        if (!is_rsa_authenticated(account_id)) {
            printf("SECURITY BLOCK: RSA authentication required but not completed for user: %s from socket %d\n", 
                   username, account_id);
            return 0; // HARD BLOCK - no login without RSA
        }

    }
    
   
    
    user_t *found_ptr = NULL;
    HASH_FIND_INT(user_map, &account_id, found_ptr);
    if (found_ptr != NULL) {
        if (found_ptr->active) {
            // Check that the username matches the account_id's username
            if (strncmp(username, found_ptr->username, MAX_USERNAME_LEN) != 0) {
                // Username mismatch
                printf("Username mismatch: provided '%s', expected '%s' for account_id %d\n", username, found_ptr->username, account_id);
                return 0;
            }
            return verify_password(password, found_ptr->password_hash);
        }
    }
    return 0; // User not found or password incorrect
}

// Create a new session
int create_session(int account_id) {
    // Find the user first
    user_t *user = find_user(account_id);
    if (!user) {
        printf("Cannot create session: user not found\n");
        return 0;
    }
       
    // Check if session already exists (from RSA phase)
    session_t *existing_session = NULL;
    HASH_FIND_INT(session_map, &account_id, existing_session);
    if (existing_session) {
        // Update existing session
        existing_session->authenticated = 1;
        existing_session->login_time = time(NULL);
        return 1; // Success
    }
    
    // No existing session - create new one
    if (session_count >= MAX_USERS) {
        return 0; // No space
    }
    
    session_t *session = malloc(sizeof(session_t));
    if (!session) {
        printf("Failed to allocate memory for session\n");
        return 0;
    }
    memset(session, 0, sizeof(session_t));
    session->account_id = account_id;
    session->user = user;
    session->login_time = time(NULL);
    session->authenticated = 1;
    session->rsa_authenticated = 0;
    
    HASH_ADD_INT(session_map, account_id, session);
    session_count++;
    
    return 1; // Success
}

// Remove a session
void remove_session(int account_id) {
    if (!session_map) {
        return;
    }
    
    session_t *found = NULL;
    HASH_FIND_INT(session_map, &account_id, found);
    
    if (found && found->authenticated) {
        HASH_DEL(session_map, found);
        free(found);
        session_count--;
    }
}

// Update session data safely
int update_session(int account_id, const session_t* updated_session) {
    if (!session_map || !updated_session) {
        return 0;
    }
    
    session_t *found = NULL;
    HASH_FIND_INT(session_map, &account_id, found);
    
    if (found) {
        found->login_time = updated_session->login_time;
        found->authenticated = updated_session->authenticated;
        found->rsa_authenticated = updated_session->rsa_authenticated;
        memcpy(found->challenge, updated_session->challenge, RSA_CHALLENGE_SIZE);
        // Don't update account_id or user pointer as they shouldn't change
        return 1;
    }
    return 0;
}

// Check if a user is RSA authenticated
int is_rsa_authenticated(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session || !session->rsa_authenticated) {
        return 0;
    }
    return 1;
}

// Check if a user is authenticated
int is_authenticated(int account_id) {
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session || !session->authenticated) {
        return 0;
    }
    
    // Check if session has expired
    if (time(NULL) - session->login_time > AUTH_TIMEOUT) {
        remove_session(account_id);
        return 0;
    }
    
    return 1;
}

// Clean up expired sessions
void cleanup_expired_sessions(void) {
    if (!session_map) {
        return; // Nothing to clean up
    }
    
    
    
    session_t *current, *temp;
    HASH_ITER(hh, session_map, current, temp) {
       HASH_DEL(session_map, current);
       free(current);
       session_count--;
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
}

// Load users from file - deprecated

void load_users_from_file(const char* filename) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        printf("Failed to open file for reading: %s\n", filename);
        return;
    }
    
    char line[MAX_LINE_BUFFER_SIZE];
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
            if (find_user(account_id) == NULL && find_username(username) == NULL) {
                HASH_ADD_INT(user_map, account_id, new_user);
                HASH_ADD_STR(username_map, username, new_username);
                loaded_count++;
                user_count++;
            } else {
                printf("Skipping duplicate account ID: %u\n", account_id);
                free(new_user->email);
                free(new_user->address);
                free(new_user->phone_number);
                free(new_user);
                free(new_username->username);
                free(new_username);
            }
            
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
                if (find_user(account_id) == NULL && find_username(username) == NULL) {
                    HASH_ADD_INT(user_map, account_id, new_user);
                    HASH_ADD_STR(username_map, username, new_username);
                    loaded_count++;
                    user_count++;
                } else {
                    printf("Skipping duplicate user ID: %u\n", account_id);
                    free(new_user->email);
                    free(new_user->address);
                    free(new_user->phone_number);
                    free(new_user);
                    free(new_username->username);
                    free(new_username);
                }
               
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
        if (authenticate_user(username, password, account_id)) {
            if (create_session(account_id)) {
                result.success = 1;
                result.authenticated = 1;
                snprintf(result.response, sizeof(result.response), 
                        "%s Welcome, %s! ", 
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

// ================================
// RSA AUTHENTICATION IMPLEMENTATION
// ================================

// Get a user's public key by account_id
EVP_PKEY* get_client_public_key(int account_id) {
    user_t *user = find_user(account_id);
    return user ? user->public_key : NULL;
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
    user_t *user = find_user(account_id);
    if (!user) {
        snprintf(result.response, sizeof(result.response), "%s No user found for account", RSA_AUTH_FAILED);
        return result;
    }
    if(create_session(account_id)){
        printf("SUCCESS: Created session for account %d\n", account_id);
    }
    else{
        printf("ERROR: Failed to create session for account %d\n", account_id);
        snprintf(result.response, sizeof(result.response), "%s Failed to create session", RSA_AUTH_FAILED);
        return result;
    }
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session) {
        session = malloc(sizeof(session_t));
        memset(session, 0, sizeof(session_t));
        session->account_id = account_id;
        session->user = user;
        session->login_time = time(NULL);
        session->authenticated = 0;
        session->rsa_authenticated = 0;
        // Store the client's public key in the session
        session->user->public_key = EVP_PKEY_dup(client_pubkey);
        HASH_ADD_INT(session_map, account_id, session);
        session_count++;
        printf("[DEBUG] Created session for account %d and stored client_pubkey.\n", account_id);
    }
    // Generate random challenge
    if (RAND_bytes(session->challenge, RSA_CHALLENGE_SIZE) != 1) {
        snprintf(result.response, sizeof(result.response), "%s Failed to generate challenge", RSA_AUTH_FAILED);
        return result;
    }
    // Use the provided public key for encryption
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(session->user->public_key, NULL);
    if (!ctx || EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        snprintf(result.response, sizeof(result.response), "%s Failed to setup encryption", RSA_AUTH_FAILED);
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
    user_t *user = find_user(account_id);
    if (!user) {
        snprintf(result.response, sizeof(result.response), 
                "%s No user for account %d", RSA_AUTH_FAILED, account_id);
        printf("ERROR: No user found for account %d\n", account_id);
        return result;
    }
    
    session_t *session = NULL;
    HASH_FIND_INT(session_map, &account_id, session);
    if (!session) {
        snprintf(result.response, sizeof(result.response), 
                "%s No active session", RSA_AUTH_FAILED);
        printf("ERROR: No active session found for account %d\n", account_id);
        return result;
    }
    
    printf("SUCCESS: Found session for account %d (auth=%d, rsa_auth=%d)\n", 
           account_id, session->authenticated, session->rsa_authenticated);
    
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
    //printf("DEBUG: About to decrypt client response of %d bytes\n", response_size);
    //printf("DEBUG: Expected response size: %d bytes\n", MAX_RSA_ENCRYPTED_SIZE);
    //printf("DEBUG: Decryption buffer size: %zu bytes\n", outlen);
    
    int decrypt_result = EVP_PKEY_decrypt(ctx, decrypted_challenge, &outlen, encrypted_response, response_size);
    /*
    printf("DEBUG: Decryption result: %d\n", decrypt_result);
    printf("DEBUG: Actual decrypted size: %zu bytes\n", outlen);
    printf("DEBUG: Expected decrypted size: %d bytes\n", RSA_CHALLENGE_SIZE);
    */
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
        session->rsa_authenticated = 1;
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
    if (user_map) {
        user_t *current, *temp;
        HASH_ITER(hh, user_map, current, temp) {
            HASH_DEL(user_map, current);
            if (current->public_key) {
                EVP_PKEY_free(current->public_key);
                current->public_key = NULL;
            }
            free(current);
        }
    }
    if (username_map) {
        username_t *current, *temp;
        HASH_ITER(hh, username_map, current, temp) {
            HASH_DEL(username_map, current);
            free(current->username);
            free(current);
        }
    }
    if (session_map) {
        session_t *current, *temp;
        HASH_ITER(hh, session_map, current, temp) {
            HASH_DEL(session_map, current);
            free(current);
        }
    }
    user_count = 0;
    session_count = 0;
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