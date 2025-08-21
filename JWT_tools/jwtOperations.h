#ifndef JWT_H
#define JWT_H

#include <stddef.h>
#include <time.h>
#include "../hashmap/uthash.h"

// JWT token types for different authentication stages
typedef enum {
    JWT_TYPE_NONE = 0,
    JWT_TYPE_RSA = 1,
    JWT_TYPE_SESSKEY = 2,
    JWT_TYPE_PASSWORD = 3,        // After password verification
    JWT_TYPE_EMAIL = 4,           // After email token verification
    JWT_TYPE_FULL = 5            // Fully authenticated
} jwt_type_t;

// JWT token structure for server-side management
typedef struct {
    unsigned int account_id;
    int token_version;            // For revocation/rotation
    jwt_type_t token_type;        // Current auth stage
    time_t last_issued;           // Last token issuance time
    UT_hash_handle hh;
} jwt_state_t;

int jwt_init_secret(const char* secret_file_path); // 32 bytes; generates if missing

// Issue a new JWT token for a specific auth stage
char* jwt_issue_hs256_staged(unsigned int account_id, 
                             const char* username, 
                             jwt_type_t stage,
                             int token_version,
                             int ttl_seconds);

// Verify a JWT token and extract all claims
int jwt_verify_hs256(const char* token,
                     unsigned int* account_id_out,
                     jwt_type_t* stage_out,
                     int* token_version_out,
                     long* iat_out,
                     long* exp_out,
                     char* username_out, 
                     size_t username_out_sz);

// Legacy function for backward compatibility
char* jwt_issue_hs256(unsigned int account_id, const char* username, int auth_flags, int ttl_seconds);

// Helper function to get JWT type string
const char* jwt_type_to_string(jwt_type_t type);

// Helper function to parse JWT type from string
jwt_type_t jwt_type_from_string(const char* type_str);

// Utility functions for JWT state management
void jwt_cleanup_states(void);
int jwt_get_current_version(unsigned int account_id);
int jwt_revoke_account(unsigned int account_id);
jwt_type_t jwt_get_current_stage(unsigned int account_id);

// Base64URL encoding/decoding utilities
int b64url_to_raw(const char* in, unsigned char* out, size_t out_max, size_t* out_len);
void b64url_from_raw(const unsigned char* in, size_t in_len, char* out, size_t out_sz);

#endif