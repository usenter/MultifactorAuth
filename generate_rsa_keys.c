#include <stdio.h>
#include <string.h>
#include "auth_system.h"

int main(int argc, char *argv[]) {
    printf("RSA Key Pair Generator for Authentication System\n");
    printf("===============================================\n\n");
    
    if (argc < 2 || argc > 3) {
        printf("Usage: %s <entity> [client_id]\n", argv[0]);
        printf("Where <entity> is either 'server' or 'client'\n");
        printf("For multiple clients, specify unique client_id\n\n");
        printf("Examples:\n");
        printf("  %s server              # Generate server key pair\n", argv[0]);
        printf("  %s client              # Generate default client key pair\n", argv[0]);
        printf("  %s client alice        # Generate client key pair for 'alice'\n", argv[0]);
        printf("  %s client bob          # Generate client key pair for 'bob'\n", argv[0]);
        return 1;
    }
    
    char *entity = argv[1];
    char *client_id = (argc == 3) ? argv[2] : "default";
    char private_key_file[256];
    char public_key_file[256];
    
    if (strcmp(entity, "server") == 0) {
        if (argc == 3) {
            printf("Warning: Client ID ignored for server keys\n");
        }
        snprintf(private_key_file, sizeof(private_key_file), "RSAkeys/server_private.pem");
        snprintf(public_key_file, sizeof(public_key_file), "RSAkeys/server_public.pem");
    } else if (strcmp(entity, "client") == 0) {
        snprintf(private_key_file, sizeof(private_key_file), "RSAkeys/client_%s_private.pem", client_id);
        snprintf(public_key_file, sizeof(public_key_file), "RSAkeys/client_%s_public.pem", client_id);
    } else {
        printf("Error: Invalid entity '%s'. Use 'server' or 'client'\n", entity);
        return 1;
    }
    
    printf("Generating %s RSA key pair...\n", entity);
    printf("Private key file: %s\n", private_key_file);
    printf("Public key file:  %s\n", public_key_file);
    printf("\n");
    
    if (generate_rsa_keypair(private_key_file, public_key_file)) {
        printf("\n✓ Success! %s RSA key pair generated.\n", entity);
        printf("\nIMPORTANT SECURITY NOTES:\n");
        printf("- Keep the private key (%s) SECURE and SECRET\n", private_key_file);
        printf("- The public key (%s) can be shared\n", public_key_file);
        printf("- Set proper file permissions: chmod 600 %s\n", private_key_file);
        printf("- For production, store keys in a secure key management system\n");
        return 0;
    } else {
        printf("\n✗ Failed to generate %s RSA key pair\n", entity);
        return 1;
    }
} 