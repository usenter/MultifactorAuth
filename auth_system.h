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
#include "hashmap/hashmap.h"
#include "encryptionTools.h"

#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64
#define MAX_HASH_LEN 65  // SHA-256 hash is 64 chars + null terminator
#define MAX_USERS 100
#define AUTH_TIMEOUT 300  // 5 minutes in seconds

// RSA Authentication constants
#define RSA_KEY_SIZE 2048
#define RSA_CHALLENGE_SIZE 32  // 256 bits of random data
#define RSA_MAX_ENCRYPT_SIZE (RSA_KEY_SIZE/8 - 42)  // OAEP padding overhead
#define MAX_RSA_ENCRYPTED_SIZE (RSA_KEY_SIZE/8)  // 256 bytes for 2048-bit key

// User structure
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    int active;
} user_t;

// Session structure
typedef struct {
    char username[MAX_USERNAME_LEN];
    int client_socket;
    time_t login_time;
    int authenticated;
    int rsa_authenticated;  // RSA challenge-response completed
    unsigned char challenge[RSA_CHALLENGE_SIZE];  // Current challenge
} session_t;

// RSA Key pair structure
typedef struct {
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
} rsa_keypair_t;

// RSA challenge result structure
typedef struct {
    int success;
    char response[1024];
    unsigned char challenge[RSA_CHALLENGE_SIZE];
    unsigned char encrypted_challenge[MAX_RSA_ENCRYPTED_SIZE];
    int encrypted_size;
} rsa_challenge_result_t;

// Client key mapping structure for hashmap storage
typedef struct {
    char client_id[MAX_USERNAME_LEN];  // Client identifier (e.g., "alice", "bob", "default")
    EVP_PKEY *public_key;              // Client's public key
} client_key_entry_t;

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
int add_user(const char* username, const char* password);
int authenticate_user(const char* username, const char* password, int client_socket);
int create_session(const char* username, int client_socket);
void remove_session(int client_socket);
session_t* get_session(int client_socket);
int is_authenticated(int client_socket);
void cleanup_expired_sessions(void);
void hash_password(const char* password, char* hash);
int verify_password(const char* password, const char* hash);
void save_users_to_file(const char* filename);
void load_users_from_file(const char* filename);
int load_users_from_encrypted_file(const char* encrypted_filename, const char* key);

// New authentication processing functions
auth_result_t process_auth_command(const char* message, int client_socket);
int is_auth_command(const char* message);

// RSA Authentication functions
int init_rsa_system(const char* server_private_key_file, const char* server_public_key_file);
int generate_rsa_keypair(const char* private_key_file, const char* public_key_file);
rsa_keypair_t* load_rsa_keys(const char* private_key_file, const char* public_key_file);
EVP_PKEY* load_public_key(const char* public_key_file);

// Client key management functions
int load_all_client_keys_dynamic(void);
EVP_PKEY* find_client_public_key(const char* client_id);
int get_loaded_client_count(void);

void cleanup_rsa_system(void);
rsa_challenge_result_t start_rsa_challenge(int client_socket);
rsa_challenge_result_t verify_rsa_response(int client_socket, const unsigned char* encrypted_response, int response_size);
int is_rsa_command(const char* message);
rsa_challenge_result_t process_rsa_command(const char* message, int client_socket);
int is_rsa_authenticated(int client_socket);
int is_rsa_system_initialized(void);

#endif // AUTH_SYSTEM_H 