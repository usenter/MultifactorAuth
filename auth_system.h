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

// Session structure
typedef struct {
    unsigned int account_id;  // Key for lookup
    user_t *user;            // Pointer to the authenticated user
    time_t login_time;
    int authenticated;
    int rsa_authenticated;   // RSA challenge-response completed
    unsigned char challenge[RSA_CHALLENGE_SIZE];  // Current challenge
    UT_hash_handle hh;
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
void hash_password(const char* password, char* hash);
int verify_password(const char* password, const char* hash);
void save_users_to_file(const char* filename);
void load_users_from_file(const char* filename);
int load_users_from_encrypted_file(const char* encrypted_filename, const char* key);

// New authentication processing functions
auth_result_t process_auth_command(const char* message, int account_id);
int is_auth_command(const char* message);

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

// New function for RSA challenge with direct public key
//rsa_challenge_result_t start_rsa_challenge_with_pubkey(EVP_PKEY* pubkey);

#endif // AUTH_SYSTEM_H 