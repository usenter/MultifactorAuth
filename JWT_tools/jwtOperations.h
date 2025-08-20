#ifndef JWT_H
#define JWT_H

#include <stddef.h>

int jwt_init_secret(const char* secret_file_path); // 32 bytes; generates if missing

// Returns malloc'ed token string; caller frees
char* jwt_issue_hs256(unsigned int account_id, const char* username, int auth_flags, int ttl_seconds);

// Returns 1 on valid; fills outs; username_out is optional
int jwt_verify_hs256(const char* token,
                     unsigned int* account_id_out,
                     int* auth_flags_out,
                     long* iat_out,
                     long* exp_out,
                     char* username_out, size_t username_out_sz);

#endif