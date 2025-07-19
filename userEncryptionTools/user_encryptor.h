#ifndef USER_ENCRYPTOR_H
#define USER_ENCRYPTOR_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Structure to hold decrypted data in memory
typedef struct {
    char* data;
    size_t size;
    int success;
} decryption_result_t;

// Function declarations
decryption_result_t decrypt_file_to_memory(const char* encrypted_filename, const char* password);
int encrypt_file_with_key(const char* input_file, const char* output_file, const char* password);
void free_decryption_result(decryption_result_t* result);

#endif // USER_ENCRYPTOR_H 