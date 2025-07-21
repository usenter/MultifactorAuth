#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_MESSAGES 100
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64
#define RSA_KEY_SIZE 2048
#define RSA_CHALLENGE_SIZE 32
#define MAX_RSA_ENCRYPTED_SIZE (RSA_KEY_SIZE/8)  // 256 bytes for 2048-bit key
#define RSA_DECRYPT_BUFFER_SIZE MAX_RSA_ENCRYPTED_SIZE
#define RSA_HEX_BUFFER_SIZE (MAX_RSA_ENCRYPTED_SIZE * 2 + 64)
#define MAX_FILE_PATH_LEN 512

volatile int running = 1;
int authenticated = 0;
int rsa_completed = 0;

// RSA keys for automatic authentication
EVP_PKEY* client_private_key = NULL;
EVP_PKEY* server_public_key = NULL;
char client_id[64] = "";  // Must be specified by user

// Authentication response checking
#define AUTH_SUCCESS "AUTH_SUCCESS"

// Global message storage
typedef struct {
    char message[BUFFER_SIZE];
    int valid;
} stored_message_t;

stored_message_t message_buffer[MAX_MESSAGES];
int message_count = 0;
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to store a message
void store_message(const char* msg) {
    pthread_mutex_lock(&message_mutex);
    if (message_count < MAX_MESSAGES) {
        strncpy(message_buffer[message_count].message, msg, BUFFER_SIZE - 1);
        message_buffer[message_count].message[BUFFER_SIZE - 1] = '\0';
        message_buffer[message_count].valid = 1;
        message_count++;
    }
    pthread_mutex_unlock(&message_mutex);
}

// Function to get stored messages
int get_stored_messages(char messages[][BUFFER_SIZE], int max_count) {
    pthread_mutex_lock(&message_mutex);
    int count = (message_count < max_count) ? message_count : max_count;
    for (int i = 0; i < count; i++) {
        if (message_buffer[i].valid) {
            strcpy(messages[i], message_buffer[i].message);
        }
    }
    pthread_mutex_unlock(&message_mutex);
    return count;
}

// RSA Authentication Functions
// Load client's private key
int load_client_private_key(const char* client_id) {
    char key_file[MAX_FILE_PATH_LEN];
    snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", client_id);
    
    FILE* fp = fopen(key_file, "r");
    if (!fp) {
        printf("ERROR: Could not open client private key: %s\n", key_file);
        return 0;
    }
    
    client_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!client_private_key) {
        printf("ERROR: Could not read client private key from: %s\n", key_file);
        return 0;
    }
    

    return 1;
}

// Load server's public key
int load_server_public_key(void) {
    FILE* fp = fopen("RSAkeys/server_public.pem", "r");
    if (!fp) {
        printf("ERROR: Could not open server public key: RSAkeys/server_public.pem\n");
        return 0;
    }
    
    server_public_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!server_public_key) {
        printf("ERROR: Could not read server public key\n");
        return 0;
    }

    return 1;
}

// Handle RSA challenge automatically
int handle_rsa_challenge(int socket, const char* hex_challenge) {
    if (!client_private_key || !server_public_key) {
        printf("RSA keys not loaded - cannot handle RSA challenge!\n");
        return 0;
    }
    
    printf("Authenticating with server...\n");
    
    // Convert hex challenge back to binary
    size_t challenge_len = strlen(hex_challenge) / 2;
    unsigned char encrypted_challenge[MAX_RSA_ENCRYPTED_SIZE];
    /*
    printf("DEBUG: Hex challenge length: %zu chars, Binary length: %zu bytes\n", 
           strlen(hex_challenge), challenge_len);
    printf("DEBUG: Expected encrypted size for 2048-bit RSA: %d bytes\n", MAX_RSA_ENCRYPTED_SIZE);
    */
    if (challenge_len != MAX_RSA_ENCRYPTED_SIZE) {
        printf("ERROR: Encrypted challenge length mismatch! Expected %d, got %zu\n", 
               MAX_RSA_ENCRYPTED_SIZE, challenge_len);
        return 0;
    }
    
    for (size_t i = 0; i < challenge_len; i++) {
        sscanf(hex_challenge + (i * 2), "%2hhx", &encrypted_challenge[i]);
    }
    
    // Decrypt challenge with client private key
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_private_key, NULL);
    if (!decrypt_ctx || EVP_PKEY_decrypt_init(decrypt_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (decrypt_ctx) EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to setup RSA decryption\n");
        return 0;
    }
    
    unsigned char decrypted_challenge[RSA_DECRYPT_BUFFER_SIZE];
    size_t decrypted_len = sizeof(decrypted_challenge);
    
    /*
    printf("DEBUG: About to decrypt %zu bytes of encrypted data\n", challenge_len);
    printf("DEBUG: Decryption buffer size: %zu bytes\n", decrypted_len);
    printf("DEBUG: Expected decrypted size: %d bytes\n", RSA_CHALLENGE_SIZE);
        */
    //decrypt the challenge using the client private key
    if (EVP_PKEY_decrypt(decrypt_ctx, decrypted_challenge, &decrypted_len, encrypted_challenge, challenge_len) <= 0) {
        ERR_print_errors_fp(stdout);
        PEM_write_PrivateKey(stdout, client_private_key, NULL, NULL, 0, NULL, NULL);
        EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to decrypt RSA challenge\n");
        return 0;
    }
    EVP_PKEY_CTX_free(decrypt_ctx);
    
    //printf("DEBUG: Successfully decrypted %zu bytes (expected %d bytes)\n", 
    //       decrypted_len, RSA_CHALLENGE_SIZE);
    
    if (decrypted_len != RSA_CHALLENGE_SIZE) {
        printf("WARNING: Decrypted length mismatch! Expected %d, got %zu\n", 
               RSA_CHALLENGE_SIZE, decrypted_len);
    }
    
    // Encrypt decrypted challenge with server public key
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(server_public_key, NULL);
    if (!encrypt_ctx || EVP_PKEY_encrypt_init(encrypt_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (encrypt_ctx) EVP_PKEY_CTX_free(encrypt_ctx);
        printf("Failed to setup RSA encryption\n");
        return 0;
    }
    
    unsigned char encrypted_response[MAX_RSA_ENCRYPTED_SIZE];
    size_t encrypted_len = sizeof(encrypted_response);
    
    // Use RSA_CHALLENGE_SIZE instead of decrypted_len for consistency
    size_t input_len = RSA_CHALLENGE_SIZE;
    //printf("DEBUG: About to re-encrypt %zu bytes with server public key\n", input_len);
    //printf("DEBUG: Output buffer size: %zu bytes\n", encrypted_len);
    
    if (EVP_PKEY_encrypt(encrypt_ctx, encrypted_response, &encrypted_len, decrypted_challenge, input_len) <= 0) {
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(encrypt_ctx);
        printf("Failed to encrypt RSA response\n");
        return 0;
    }
    EVP_PKEY_CTX_free(encrypt_ctx);
    
    //printf("DEBUG: Successfully re-encrypted to %zu bytes (expected %d bytes)\n", 
    //      encrypted_len, MAX_RSA_ENCRYPTED_SIZE);
    
    if (encrypted_len != MAX_RSA_ENCRYPTED_SIZE) {
        printf("WARNING: Re-encrypted length mismatch! Expected %d, got %zu\n", 
               MAX_RSA_ENCRYPTED_SIZE, encrypted_len);
    }
    
    // Convert response to hex and send
    char hex_response[RSA_HEX_BUFFER_SIZE];
    snprintf(hex_response, sizeof(hex_response), "/rsa_response ");
    char* hex_ptr = hex_response + strlen(hex_response);
    
    for (size_t i = 0; i < encrypted_len; i++) {
        sprintf(hex_ptr + (i * 2), "%02x", encrypted_response[i]);
    }
    
    if (send(socket, hex_response, strlen(hex_response), 0) < 0) {
        printf("Failed to send RSA response\n");
        return 0;
    }
    
    printf("RSA response sent successfully\n");
    
    // Clear sensitive data
    memset(decrypted_challenge, 0, sizeof(decrypted_challenge));
    memset(encrypted_response, 0, sizeof(encrypted_response));
    
    return 1;
}

// Cleanup RSA keys
void cleanup_rsa_keys(void) {
    if (client_private_key) {
        EVP_PKEY_free(client_private_key);
        client_private_key = NULL;
    }
    if (server_public_key) {
        EVP_PKEY_free(server_public_key);
        server_public_key = NULL;
    }
}

// Authentication is now handled by users typing /login commands directly

// Function to receive messages from server (chat mode)
void* receive_messages(void* arg) {
    int client_socket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Check for RSA challenge (handle automatically and transparently)
        if (strstr(buffer, "RSA_CHALLENGE:") && !rsa_completed) {
            char* challenge_start = strstr(buffer, "RSA_CHALLENGE:") + 14;  // Skip "RSA_CHALLENGE:"
            char* challenge_end = strchr(challenge_start, '\n');
            if (challenge_end) *challenge_end = '\0';
            
            printf("\n[RSA] Performing RSA mutual authentication...\n");
            if (handle_rsa_challenge(client_socket, challenge_start)) {
                rsa_completed = 1;
                printf("[RSA] SUCCESS: RSA mutual authentication completed!\n");
                printf("[RSA] Secure encrypted channel established between client and server.\n");
                printf("[RSA] You may now login with your username and password.\n");
                printf("\n");
            } else {
                printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
            }
            return NULL; // Don't process this message further
        }
        
        // Check for RSA failure
        if (strstr(buffer, "RSA_FAILED")) {
            printf("\nRSA authentication failed - connection may be terminated by server.\n");
            running = 0;
            return NULL;
        }
        
        // Check for security errors
        if (strstr(buffer, "SECURITY_ERROR")) {
            printf("\nSECURITY ERROR: RSA authentication is required but failed.\n");
            printf("Make sure you have the correct RSA keys for your client.\n");
            return NULL; // Don't process further
        }
        
        // Check for server shutdown/disconnect messages
        if (strstr(buffer, "Server is shutting down") || 
            strstr(buffer, "server disconnected") ||
            strstr(buffer, "Server disconnected")) {
            printf("\n%s", buffer);
            printf("Client shutting down automatically...\n");
            running = 0;
            shutdown(client_socket, SHUT_RDWR);  // This will wake up the main thread
            return NULL;
        }
        
        // Store the message
        store_message(buffer);
        
        // Check if we got authenticated
        if (strncmp(buffer, "AUTH_SUCCESS", 12) == 0) {
            authenticated = 1;
            printf("\n%s", buffer);
            printf("You are now authenticated!\n");
            printf("Chat commands: /nick <name>, /list, /quit\n");
            printf("Type your messages below:\n");
        } else {
            printf("\n%s", buffer);
        }
        
        // Show prompt based on authentication state
        if (authenticated) {
            printf("> ");
        } else {
            printf("auth> ");
        }
        fflush(stdout);
    }
    
    return NULL;
}



// Function to handle secure chat client
void client_mode(int client_socket) {
    char buffer[BUFFER_SIZE];
    pthread_t receive_thread;
    
    printf("Connected to secure MultiFactor Authentication chat server!\n");
    printf("Starting RSA challenge-response authentication...\n");
    
    // Display initial server message (but check for RSA challenge first)
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        
        // Check if the first message is an RSA challenge
        if (strstr(buffer, "RSA_CHALLENGE:") && !rsa_completed) {
            char* challenge_start = strstr(buffer, "RSA_CHALLENGE:") + 14;  // Skip "RSA_CHALLENGE:"
            char* challenge_end = strchr(challenge_start, '\n');
            if (challenge_end) *challenge_end = '\0';
            
            printf("\n[RSA] Performing RSA mutual authentication...\n");
            if (handle_rsa_challenge(client_socket, challenge_start)) {
                rsa_completed = 1;
                printf("[RSA] SUCCESS: RSA mutual authentication completed!\n");
                printf("[RSA] Secure encrypted channel established between client and server.\n");
                printf("[RSA] You may now login with your username and password.\n");
                printf("\n");
            } else {
                printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
            }
        } else {
            // Regular server message - display normally
            printf("Server: %s", buffer);
        }
    }
    
    
    
    // Create thread to receive messages
    if (pthread_create(&receive_thread, NULL, receive_messages, &client_socket) != 0) {
        printf("Failed to create receive thread\n");
        return;
    }
    
    // RSA authentication and prompts are now handled automatically
    // The server will send the login prompt after RSA completes
    
    // Main loop to send messages
    printf("auth> ");
    while (running && fgets(buffer, BUFFER_SIZE, stdin)) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        // Check if we should exit due to server disconnection
        if (!running) {
            break;
        }
        
        if (strcmp(buffer, "/quit") == 0) {
            running = 0;
            break;
        }
        
        if (strlen(buffer) > 0) {
            // Check authentication state and command restrictions
            if (!authenticated) {
                // Only allow authentication commands when not authenticated
                if (strncmp(buffer, "/login", 6) == 0 || 
                    strncmp(buffer, "/register", 9) == 0) {
                    // Send authentication command
                    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                    // Don't show prompt immediately - wait for server response
                    continue;
                } else {
                    printf("Please authenticate first. Use: /login <username> <password> or /register <username> <password>\n");
                    printf("auth> ");
                    continue;
                }
            } else {
                // Send any command when authenticated
                if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                    printf("Failed to send message\n");
                    running = 0;
                    break;
                }
            }
        }
        
        // Show appropriate prompt (only for non-auth commands)
        if (authenticated) {
            printf("> ");
        } else {
            printf("auth> ");
        }
    }
    
    // Cleanup
    running = 0;
    shutdown(client_socket, SHUT_RDWR);
    pthread_join(receive_thread, NULL);
    printf("Disconnected from chat server\n");
}

int main(int argc, char *argv[]) {
    int client_socket;
    struct sockaddr_in server_addr;
    
    // Parse command line arguments - client_id is REQUIRED
    if (argc != 2) {
        printf("Usage: %s <client_id>\n", argv[0]);
        printf("  client_id: Your unique client identifier (REQUIRED)\n");
        printf("\nNote: You must have generated RSA keys for your client_id first:\n");
        printf("  ./generate_rsa_keys client <client_id>\n");
        printf("\nExample:\n");
        printf("  %s alice    # Connect as client 'alice'\n", argv[0]);
        return 1;
    }
    
    // First argument is always client_id
    strncpy(client_id, argv[1], sizeof(client_id) - 1);
    client_id[sizeof(client_id) - 1] = '\0';
    
    printf("Client ID: %s\n", client_id);
    
    // Load RSA keys for automatic authentication
    printf("\nLoading RSA authentication keys...\n");
    if (load_client_private_key(client_id) && load_server_public_key()) {
        printf("RSA authentication enabled.\n");
    } else {
        printf("ERROR: RSA keys not found for client '%s'!\n", client_id);
        printf("You must generate RSA keys first:\n");
        printf("  ./generate_rsa_keys client %s\n", client_id);
        printf("  ./generate_rsa_keys server  # (if server keys don't exist)\n");
        printf("\nConnection will likely fail - server requires RSA authentication.\n");
        return 1;
    }
    
    // No need to prompt for username/password - users will type /login commands
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        printf("Socket creation failed\n");
        return 1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        close(client_socket);
        return 1;
    }
    
    // Connect to server
    printf("Connecting to secure chat server...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed\n");
        close(client_socket);
        return 1;
    }
    
    // Send client ID to server immediately for RSA key selection
    printf("Identifying client to server...\n");
    char client_id_msg[128];
    snprintf(client_id_msg, sizeof(client_id_msg), "CLIENT_ID:%s\n", client_id);
    if (send(client_socket, client_id_msg, strlen(client_id_msg), 0) < 0) {
        printf("Failed to send client ID\n");
        close(client_socket);
        return 1;
    }
    
    // Run secure chat client
    client_mode(client_socket);
    
    // Cleanup
    close(client_socket);
    pthread_mutex_destroy(&message_mutex);
    cleanup_rsa_keys();
    return 0;
} 