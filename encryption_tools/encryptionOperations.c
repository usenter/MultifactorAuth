

#include "encryptionOperations.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

void generate_key_from_password(const char *password, unsigned char *key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int key_len = 0;
    
    if (mdctx == NULL) {    
        fprintf(stderr, "Error creating MD context\n");
        exit(1);
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error initializing digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    
    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        fprintf(stderr, "Error updating digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    
    if (EVP_DigestFinal_ex(mdctx, key, &key_len) != 1) {
        fprintf(stderr, "Error finalizing digest\n");
        EVP_MD_CTX_free(mdctx);
        exit(1);
    }
    
    EVP_MD_CTX_free(mdctx);
}

void generate_iv(unsigned char *iv) {
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error generating IV\n");
        exit(1);
    }
}

decryption_result_t decrypt_file_to_memory(const char* encrypted_filename, const char* password) {
    decryption_result_t result;
    result.data = NULL;
    result.size = 0;
    result.success = 0;

    // Open the encrypted file
    FILE* in = fopen(encrypted_filename, "rb");
    if (!in) {
        printf("Failed to open encrypted file: %s\n", encrypted_filename);
        return result;
    }
    
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    generate_key_from_password(password, key);

    // Read IV from the beginning of the file
    if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Error reading IV from file\n");
        fclose(in);
        result.success = 0;
        return result;
    }
    
    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        fclose(in);
        result.success = 0;
        return result;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        result.success = 0;
        return result;
    }
// Allocate memory for decrypted data (initial size)
    size_t buffer_size = BUFFER_SIZE * 4;  // Start with 4KB
    char* decrypted_data = malloc(buffer_size);
    if (!decrypted_data) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        result.success = 0;
        return result;
    }
    
    // Decrypt file
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    size_t total_decrypted = 0;
    
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error during decryption\n");
            free(decrypted_data);
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            result.success = 0;
            return result;
        }
        
        // Ensure buffer is large enough
        if (total_decrypted + outlen >= buffer_size) {
            buffer_size *= 2;
            char* temp = realloc(decrypted_data, buffer_size);
            if (!temp) {
                fprintf(stderr, "Memory reallocation failed\n");
                free(decrypted_data);
                EVP_CIPHER_CTX_free(ctx);
                fclose(in);
                result.success = 0;
                return result;
            }
            decrypted_data = temp;
        }
        
        memcpy(decrypted_data + total_decrypted, outbuf, outlen);
        total_decrypted += outlen;
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        free(decrypted_data);
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        result.success = 0;
        return result;
    }
    
    // Ensure buffer is large enough for final block
    if (total_decrypted + outlen >= buffer_size) {
        buffer_size += outlen + 1;
        char* temp = realloc(decrypted_data, buffer_size);
        if (!temp) {
            fprintf(stderr, "Memory reallocation failed\n");
            free(decrypted_data);
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            result.success = 0;
            return result;
        }
        decrypted_data = temp;
    }
    
    memcpy(decrypted_data + total_decrypted, outbuf, outlen);
    total_decrypted += outlen;
    
    // Null-terminate the decrypted data
    decrypted_data[total_decrypted] = '\0';
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    
    // Clear sensitive data from memory
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    // Return successful result
    result.data = decrypted_data;
    result.size = total_decrypted;
    result.success = 1;
    return result;
}

void free_decryption_result(decryption_result_t* result) {
    if (result && result->data) {
        // Clear sensitive data before freeing
        memset(result->data, 0, result->size);
        free(result->data);
        result->data = NULL;
        result->size = 0;
        result->success = 0;
    }
}

#ifdef TEST_MAIN
int main() {
    printf("Encryption Tools Library Test\n");
    printf("=============================\n");
    printf("Available functions:\n");
    printf("- generate_key_from_password()\n");
    printf("- generate_iv()\n");
    printf("- decrypt_file_to_memory()\n");
    printf("- free_decryption_result()\n\n");
    
    printf("Library compiled successfully!\n");
    printf("To use these functions, include 'encryptionTools.h' in your program.\n");
    
    return 0;
}
#endif