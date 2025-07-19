#include "user_encryptor.h"
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32  // 256 bits
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024

// Generate AES key from password using SHA-256
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

// Generate random IV
void generate_iv(unsigned char *iv) {
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        exit(1);
    }
}

// Encrypt users file
int encrypt_users_file(const char *input_file, const char *output_file, const char *password) {
    FILE *in = fopen(input_file, "r");
    FILE *out = fopen(output_file, "wb");
    
    if (!in || !out) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }
    
    // Generate key from password
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    generate_key_from_password(password, key);
    generate_iv(iv);
    
    // Write IV to the beginning of the file
    fwrite(iv, 1, AES_BLOCK_SIZE, out);
    
    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Encrypt file
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error during encryption\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    fwrite(outbuf, 1, outlen, out);
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    printf("Users file encrypted successfully!\n");
    printf("Encrypted file: %s\n", output_file);
    printf("Use password '%s' to decrypt\n", password);
    
    return 0;
}

// Decrypt users file
int decrypt_users_file(const char *input_file, const char *password) {
    FILE *in = fopen(input_file, "rb");
    
    if (!in) {
        fprintf(stderr, "Error opening files\n");
        return 1;
    }
    
    // Generate key from password
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    generate_key_from_password(password, key);
    
    // Read IV from the beginning of the file
    if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Error reading IV from file\n");
        fclose(in);
       
        return 1;
    }
    
    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        fclose(in);
        return 1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        return 1;
    }
    
    // Decrypt file
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error during decryption\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            return 1;
        }
        fwrite(outbuf, 1, outlen, stdout);
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        return 1;
    }
    printf("%s", outbuf);
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    
    //printf("\nUsers file decrypted successfully and printed to stdout\n");
    
    return 0;
}

// Test function to verify encryption/decryption
int test_encryption(const char *password) {
    printf("Testing encryption with password: %s\n", password);
    
    // Create test file
    FILE *test = fopen("test_users.txt", "w");
    if (!test) {
        fprintf(stderr, "Error creating test file\n");
        return 1;
    }
    
    fprintf(test, "john:5d41402abc4b2a76b9719d911017c592\n");
    fprintf(test, "alice:098f6bcd4621d373cade4e832627b4f6\n");
    fprintf(test, "bob:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8\n");
    fclose(test);
    
    // Encrypt
    if (encrypt_users_file("test_users.txt", "test_users_encrypted.bin", password) != 0) {
        return 1;
    }
    
    // Decrypt
    if (decrypt_users_file("test_users_encrypted.bin", password) != 0) {
        return 1;
    }
    
    // Compare files
    FILE *original = fopen("test_users.txt", "r");
    FILE *decrypted = fopen("test_users_decrypted.txt", "r");
    
    if (!original || !decrypted) {
        fprintf(stderr, "Error opening files for comparison\n");
        return 1;
    }
    
    char orig_line[256], dec_line[256];
    int line_num = 1;
    int files_match = 1;
    
    while (fgets(orig_line, sizeof(orig_line), original) && 
           fgets(dec_line, sizeof(dec_line), decrypted)) {
        if (strcmp(orig_line, dec_line) != 0) {
            printf("Mismatch at line %d\n", line_num);
            files_match = 0;
            break;
        }
        line_num++;
    }
    
    fclose(original);
    fclose(decrypted);
    
    if (files_match) {
        printf("✓ Test passed - encryption/decryption works correctly!\n");
        // Clean up test files
        remove("test_users.txt");
        remove("test_users_encrypted.bin");
        remove("test_users_decrypted.txt");
        return 0;
    } else {
        printf("✗ Test failed - files don't match\n");
        return 1;
    }
}

// Library function: Decrypt file directly to memory
decryption_result_t decrypt_file_to_memory(const char* encrypted_filename, const char* password) {
    decryption_result_t result = {0};
    FILE *in = fopen(encrypted_filename, "rb");
    
    if (!in) {
        fprintf(stderr, "Error opening encrypted file: %s\n", encrypted_filename);
        result.success = 0;
        return result;
    }
    
    // Generate key from password
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

// Library function: Encrypt file (wrapper for existing function)
int encrypt_file_with_key(const char* input_file, const char* output_file, const char* password) {
    return encrypt_users_file(input_file, output_file, password);
}

// Library function: Free memory allocated by decrypt_file_to_memory
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

int main(int argc, char *argv[]) {
    if (argc == 2 && strcmp(argv[1], "test") == 0) {
        return test_encryption("mySecretKey123");
    }
    
    if (argc != 5 && argc != 4) {
        printf("Usage: %s <encrypt|decrypt> <input_file> <output_file> <password>\n", argv[0]);
        printf("       %s test  (run encryption test)\n", argv[0]);
        printf("\nExamples:\n");
        printf("  %s encrypt users.txt users_encrypted.bin mySecretKey123\n", argv[0]);
        printf("  %s decrypt users_encrypted.bin users_decrypted.txt mySecretKey123\n", argv[0]);
        printf("\nFor use with unified_server:\n");
        printf("  1. Create users.txt with user:password_hash entries\n");
        printf("  2. Encrypt: %s encrypt users.txt users.enc myKey\n", argv[0]);
        printf("  3. Modify auth_system.c to decrypt users.enc with myKey\n");
        return 1;
    }
    
    const char *mode = argv[1];
    const char *input_file = argv[2];
    
    
    if (strcmp(mode, "encrypt") == 0) {
        const char *output_file = argv[3];
        const char *password = argv[4];
        return encrypt_users_file(input_file, output_file, password);
    } else if (strcmp(mode, "decrypt") == 0) {
        const char *password = argv[3];
        return decrypt_users_file(input_file, password);
    } else {
        fprintf(stderr, "Invalid mode. Use 'encrypt' or 'decrypt'\n");
        return 1;
    }
} 