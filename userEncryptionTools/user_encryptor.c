#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

#define AES_KEY_SIZE 32    // 256 bits
#define AES_BLOCK_SIZE 16
#define BUFFER_SIZE 1024
#define MAX_PATH_LEN 512

// Program information
#define PROGRAM_NAME "FileEncryptor"
#define VERSION "1.0"

// Generate AES key from password using SHA-256
int generate_key_from_password(const char *password, unsigned char *key) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int key_len = 0;
    
    if (mdctx == NULL) {
        fprintf(stderr, "Error: Failed to create MD context\n");
        return 0;
    }
    
    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        fprintf(stderr, "Error: Failed to initialize digest\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    if (EVP_DigestUpdate(mdctx, password, strlen(password)) != 1) {
        fprintf(stderr, "Error: Failed to update digest\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    if (EVP_DigestFinal_ex(mdctx, key, &key_len) != 1) {
        fprintf(stderr, "Error: Failed to finalize digest\n");
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    
    EVP_MD_CTX_free(mdctx);
    return 1;
}

// Generate random IV
int generate_iv(unsigned char *iv) {
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        fprintf(stderr, "Error: Failed to generate random IV\n");
        return 0;
    }
    return 1;
}

// Check if file exists and is readable
int file_exists(const char *filename) {
    return access(filename, F_OK | R_OK) == 0;
}

// Get file size
long get_file_size(FILE *file) {
    long size;
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    fseek(file, 0, SEEK_SET);
    return size;
}

// Encrypt a file
int encrypt_file(const char *input_file, const char *output_file, const char *password) {
    // Validate input
    if (!file_exists(input_file)) {
        fprintf(stderr, "Error: Input file '%s' does not exist or is not readable\n", input_file);
        return 1;
    }
    
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }
    
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return 1;
    }
    
    // Get input file size for progress indication
    long file_size = get_file_size(in);
    printf("Encrypting file: %s (%ld bytes)\n", input_file, file_size);
    
    // Generate key from password
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    
    if (!generate_key_from_password(password, key)) {
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (!generate_iv(iv)) {
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Write IV to the beginning of the encrypted file
    if (fwrite(iv, 1, AES_BLOCK_SIZE, out) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Failed to write IV to output file\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Initialize encryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Encrypt file in chunks
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    long bytes_processed = 0;
    
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error: Encryption failed\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "Error: Failed to write encrypted data\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        
        bytes_processed += inlen;
        if (file_size > 0) {
            printf("\rProgress: %.1f%% (%ld/%ld bytes)", 
                   (double)bytes_processed / file_size * 100, bytes_processed, file_size);
            fflush(stdout);
        }
    }
    
    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "\nError: Failed to finalize encryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        fprintf(stderr, "\nError: Failed to write final encrypted block\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    // Clear sensitive data
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    printf("\n✓ Encryption successful!\n");
    printf("Input file:  %s\n", input_file);
    printf("Output file: %s\n", output_file);
    
    return 0;
}

// Decrypt a file
int decrypt_file(const char *input_file, const char *output_file, const char *password) {
    // Validate input
    if (!file_exists(input_file)) {
        fprintf(stderr, "Error: Input file '%s' does not exist or is not readable\n", input_file);
        return 1;
    }
    
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");
    
    if (!in) {
        fprintf(stderr, "Error: Cannot open input file '%s'\n", input_file);
        return 1;
    }
    
    if (!out) {
        fprintf(stderr, "Error: Cannot create output file '%s'\n", output_file);
        fclose(in);
        return 1;
    }
    
    // Get input file size for progress indication
    long file_size = get_file_size(in);
    printf("Decrypting file: %s (%ld bytes)\n", input_file, file_size);
    
    // Generate key from password
    unsigned char key[AES_KEY_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    
    if (!generate_key_from_password(password, key)) {
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Read IV from the beginning of the file
    if (fread(iv, 1, AES_BLOCK_SIZE, in) != AES_BLOCK_SIZE) {
        fprintf(stderr, "Error: Failed to read IV from encrypted file\n");
        fprintf(stderr, "File may be corrupted or not encrypted with this tool\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Initialize decryption context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create cipher context\n");
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error: Failed to initialize decryption\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Decrypt file in chunks
    unsigned char inbuf[BUFFER_SIZE];
    unsigned char outbuf[BUFFER_SIZE + AES_BLOCK_SIZE];
    int inlen, outlen;
    long bytes_processed = AES_BLOCK_SIZE; // Already read IV
    
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, in)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error: Decryption failed\n");
            fprintf(stderr, "Wrong password or corrupted file\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        
        if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
            fprintf(stderr, "Error: Failed to write decrypted data\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in);
            fclose(out);
            return 1;
        }
        
        bytes_processed += inlen;
        if (file_size > 0) {
            printf("\rProgress: %.1f%% (%ld/%ld bytes)", 
                   (double)bytes_processed / file_size * 100, bytes_processed, file_size);
            fflush(stdout);
        }
    }
    
    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "\nError: Failed to finalize decryption\n");
        fprintf(stderr, "Wrong password or corrupted file\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    if (fwrite(outbuf, 1, outlen, out) != (size_t)outlen) {
        fprintf(stderr, "\nError: Failed to write final decrypted block\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in);
        fclose(out);
        return 1;
    }
    
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(in);
    fclose(out);
    
    // Clear sensitive data
    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    
    printf("\n✓ Decryption successful!\n");
    printf("Input file:  %s\n", input_file);
    printf("Output file: %s\n", output_file);
    
    return 0;
}

// Print usage information
void print_usage(const char *program_name) {
    printf("%s v%s - File Encryption/Decryption Tool\n", PROGRAM_NAME, VERSION);
    printf("Uses AES-256-CBC encryption with SHA-256 key derivation\n\n");
    
    printf("USAGE:\n");
    printf("  %s encrypt <input_file> <output_file> <password>\n", program_name);
    printf("  %s decrypt <input_file> <output_file> <password>\n", program_name);
    printf("  %s --help\n", program_name);
    printf("  %s --version\n", program_name);
    
    printf("\nEXAMPLES:\n");
    printf("  Encrypt a text file:\n");
    printf("    %s encrypt document.txt document.enc mySecretPassword\n\n", program_name);
    
    printf("  Decrypt a file:\n");
    printf("    %s decrypt document.enc document_decrypted.txt mySecretPassword\n\n", program_name);
    
    printf("SECURITY NOTES:\n");
    printf("  • Uses AES-256-CBC with random IV for each encryption\n");
    printf("  • Password is hashed with SHA-256 to generate encryption key\n");
    printf("  • IV is stored at the beginning of encrypted files\n");
    printf("  • Use strong, unique passwords for maximum security\n");
    printf("  • Keep your password safe - files cannot be recovered without it\n\n");
    
    printf("FILE FORMATS:\n");
    printf("  • Input: Any file (text, binary, etc.)\n");
    printf("  • Encrypted output: Binary file with IV + encrypted data\n");
    printf("  • Decrypted output: Original file format restored\n");
}

// Print version information
void print_version(void) {
    printf("%s v%s\n", PROGRAM_NAME, VERSION);
    printf("Built with OpenSSL for AES-256-CBC encryption\n");
    printf("Copyright (c) 2024 - File Encryption Tool\n");
}

int main(int argc, char *argv[]) {
    // Handle special arguments
    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            print_version();
            return 0;
        }
    }
    
    // Validate argument count
    if (argc != 5) {
        fprintf(stderr, "Error: Invalid number of arguments\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char *mode = argv[1];
    const char *input_file = argv[2];
    const char *output_file = argv[3];
    const char *password = argv[4];
    
    // Validate password length
    if (strlen(password) < 8) {
        fprintf(stderr, "Warning: Password is less than 8 characters. Consider using a stronger password.\n");
    }
    
    // Validate mode and execute
    if (strcmp(mode, "encrypt") == 0) {
        printf("Starting encryption...\n");
        return encrypt_file(input_file, output_file, password);
    } else if (strcmp(mode, "decrypt") == 0) {
        printf("Starting decryption...\n");
        return decrypt_file(input_file, output_file, password);
    } else {
        fprintf(stderr, "Error: Invalid mode '%s'. Use 'encrypt' or 'decrypt'\n\n", mode);
        print_usage(argv[0]);
        return 1;
    }
} 