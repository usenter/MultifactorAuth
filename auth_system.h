#ifndef AUTH_SYSTEM_H
#define AUTH_SYSTEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "hashmap/uthash.h"
#include "decryptionFunctions/encryptionTools.h"
#include "emailFunctions/emailFunction.h"


#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64
#define MAX_HASH_LEN 65  // SHA-256 hash is 64 chars + null terminator
#define MAX_USERS 100
#define AUTH_TIMEOUT 300  // 5 minutes in seconds
#define MAX_EMAIL_LEN 64
#define MAX_ADDRESS_LEN 64
#define MAX_PHONE_NUMBER_LEN 12
#define numAuths 10

// RSA Authentication constants
#define RSA_KEY_SIZE 2048
#define RSA_CHALLENGE_SIZE 32  // 256 bits of random data
#define RSA_OAEP_PADDING_OVERHEAD 42  // OAEP padding overhead in bytes
#define RSA_MAX_ENCRYPT_SIZE (RSA_KEY_SIZE/8 - RSA_OAEP_PADDING_OVERHEAD)  // Max plaintext size
#define MAX_RSA_ENCRYPTED_SIZE (RSA_KEY_SIZE/8)  // Encrypted output size (256 bytes for 2048-bit)
#define RSA_DECRYPT_BUFFER_SIZE MAX_RSA_ENCRYPTED_SIZE  // Buffer for RSA decryption operations
#define RSA_HEX_BUFFER_SIZE (MAX_RSA_ENCRYPTED_SIZE * 2 + 64)  // Hex string + prefix/suffix
#define MAX_FILE_PATH_LEN 512  // Maximum file path length for key files and such
#define MAX_LINE_BUFFER_SIZE 512  // General line buffer for file reading

// Verify challenge size is safe for OAEP padding
#if RSA_CHALLENGE_SIZE > RSA_MAX_ENCRYPT_SIZE
#error "RSA_CHALLENGE_SIZE too large for OAEP padding! Max size is RSA_MAX_ENCRYPT_SIZE bytes"
#endif




// User structure
typedef struct {
    unsigned int account_id;
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    int active;
    EVP_PKEY *public_key;  // Client's public key for RSA auth
    char* email;
    char* address;
    char* phone_number;
    int authLevel;
    UT_hash_handle hh;
} user_t;

// RSA Key pair structure
typedef struct {
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
} rsa_keypair_t;

// Email token authentication constants
#define EMAIL_TOKEN_LENGTH 6
#define MAX_TOKEN_ATTEMPTS 3
#define LOCKOUT_DURATION 600  // 10 minutes in seconds
#define TOKEN_EXPIRY_TIME 60  // 1 minute in seconds

// Email token structure
typedef struct {
    int token;
    time_t created_time;
    int attempts;
    time_t lockout_until;
} email_token_t;

// Authentication flags using bit operations
typedef enum {
    AUTH_NONE = 0,
    AUTH_PASSWORD = (1 << 0),    // 0001 - Password authentication completed
    AUTH_RSA = (1 << 1),         // 0010 - RSA challenge-response completed
    AUTH_EMAIL = (1 << 2),       // 0100 - Email challenge-response completed
    AUTH_STATUS_LOCKED = (1 << 3),      // 1000 - Account is locked
    AUTH_FULLY_AUTHENTICATED = AUTH_PASSWORD | AUTH_RSA | AUTH_EMAIL  // 0111 - Password, RSA, and Email
} auth_flags_t;

// Session structure
typedef struct {
    unsigned int account_id;  // Key for lookup
    user_t *user;            // Pointer to the authenticated user
    time_t login_time;
    unsigned char challenge[RSA_CHALLENGE_SIZE];
    auth_flags_t auth_status;  // Authentication flags with bit operations
    email_token_t email_token;  // Email token for 2FA
    UT_hash_handle hh;  // Required for hash table functionality
} session_t;

typedef struct{
    char* username;
    unsigned int account_id;
    UT_hash_handle hh;
} username_t;



// RSA challenge result structure
typedef struct {
    int success;
    char response[1024];
    unsigned char challenge[RSA_CHALLENGE_SIZE];
    unsigned char encrypted_challenge[MAX_RSA_ENCRYPTED_SIZE];
    int encrypted_size;
} rsa_challenge_result_t;



// Authentication commands
#define AUTH_LOGIN "/login"
#define AUTH_REGISTER "/register"
#define AUTH_SUCCESS "AUTH_SUCCESS"
#define AUTH_FAILED "AUTH_FAILED"
#define AUTH_LOGOUT "/logout"

#define AUTH_TOKEN "/token"
#define AUTH_NEW_TOKEN "/newToken"
#define AUTH_LOCKED "AUTH_LOCKED"
#define AUTH_TOKEN_EXPIRED "AUTH_TOKEN_EXPIRED"
#define AUTH_TOKEN_FAIL "AUTH_TOKEN_FAIL"
#define AUTH_TOKEN_PROMPT "AUTH_TOKEN_PROMPT"
#define AUTH_TOKEN_GEN_SUCCESS "AUTH_TOKEN_GEN_SUCCESS"

// RSA Authentication commands
#define RSA_AUTH_START "/rsa_start"
#define RSA_AUTH_RESPONSE "/rsa_response"
#define RSA_AUTH_SUCCESS "RSA_AUTH_SUCCESS"
#define RSA_AUTH_FAILED "RSA_AUTH_FAILED"
#define RSA_CHALLENGE_PREFIX "RSA_CHALLENGE:"

// Authentication result structure
typedef struct {
    int success;                    // 1 if authentication succeeded, 0 otherwise
    int authenticated;              // 1 if user is now authenticated, 0 otherwise
    char response[1024];           // Response message to send to client
    char username[MAX_USERNAME_LEN]; // Username from the command (for logging)
} auth_result_t;

// Function declarations
void init_auth_system(void);
int init_encrypted_auth_system(char* userFile, char* key);
int add_user(int account_id, const char* username, const char* password);
user_t* find_user(int account_id);
username_t* find_username(const char* username);
int authenticate_user(const char* username, const char* password, int account_id);
int create_session( int account_id);
void remove_session(int account_id);
int update_session(int account_id, const session_t* updated_session);
int is_authenticated(int account_id);
void cleanup_expired_sessions(void);
void cleanup_session(session_t *session);
void cleanup_user(user_t *user);
void hash_password(const char* password, char* hash);
int verify_password(const char* password, const char* hash);
void save_users_to_file(const char* filename);
void load_users_from_file(const char* filename);
int load_users_from_encrypted_file(const char* encrypted_filename, const char* key);

// New authentication processing functions
auth_result_t process_auth_command(const char* message, int account_id);
int is_auth_command(const char* message);
int is_token_command(const char* message);

// RSA Authentication functions
int init_rsa_system(const char* server_private_key_file, const char* server_public_key_file);
int generate_rsa_keypair(const char* private_key_file, const char* public_key_file);
int is_rsa_authenticated(int account_id);
rsa_keypair_t* load_rsa_keys(const char* private_key_file, const char* public_key_file);
EVP_PKEY* load_public_key(const char* public_key_file);
EVP_PKEY* get_client_public_key(int account_id);

void cleanup_rsa_system(void);
void cleanup_auth_system(void);
// Updated function for RSA challenge with account_id and client_pubkey
rsa_challenge_result_t start_rsa_challenge_for_client(int account_id, EVP_PKEY* client_pubkey);
rsa_challenge_result_t verify_rsa_response(int account_id, const unsigned char* encrypted_response, int response_size);
int is_rsa_command(const char* message);
rsa_challenge_result_t process_rsa_command(const char* message, int account_id);
int is_rsa_authenticated(int account_id);
int is_rsa_system_initialized(void);
void sendEmailVerification(session_t* session);
int is_email_command(const char* message);
int process_email_command(const char* message, int account_id);

// New authentication flow functions
int init_email_system(char* email_file);
int create_auth_session(int account_id);
auth_flags_t get_auth_status(int account_id);
int process_auth_message(const char* message, int account_id, char* response, size_t response_size);
int verify_email_token(int account_id, const char* token);
int generate_new_token(int account_id);
int is_token_expired(int account_id);
int get_remaining_lockout_time(int account_id);
int handle_token_command(const char* message, int account_id);
int handle_new_token_command(int account_id);
void load_lockout_status(const char* filename);
void save_lockout_status(const char* filename);
int get_session_attempts(int account_id);
void reset_token_attempts(int account_id);
session_t* find_session(int account_id);
// New function for RSA challenge with direct public key
//rsa_challenge_result_t start_rsa_challenge_with_pubkey(EVP_PKEY* pubkey);

#endif // AUTH_SYSTEM_H 