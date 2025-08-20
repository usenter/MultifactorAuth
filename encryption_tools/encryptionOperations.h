#ifndef ENCRYPTION_TOOLS_H
#define ENCRYPTION_TOOLS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AES_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 2048

typedef struct {
    char* data;
    size_t size;
    int success;
} decryption_result_t;

// Function declarations
void generate_key_from_password(const char *password, unsigned char *key);
void generate_iv(unsigned char *iv);
decryption_result_t decrypt_file_to_memory(const char* encrypted_filename, const char* password);
void free_decryption_result(decryption_result_t* result);

#endif 