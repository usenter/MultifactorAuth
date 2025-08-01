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
#include <openssl/x509.h>
#include <openssl/x509v3.h>
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
#define PROGRAM_NAME "AuthenticatedChatClient"

volatile int running = 1;
int password_authenticated = 0;
int rsa_completed = 0;
int email_authenticated = 0;


// RSA keys for automatic authentication
EVP_PKEY* client_private_key = NULL;
EVP_PKEY* server_public_key = NULL;
char client_id[64] = "";  // Must be specified by user
unsigned int account_id = 0;  // Add account_id

// Authentication response checking
#define AUTH_SUCCESS "AUTH_SUCCESS"

// Function to cleanup client resources
void cleanup_client_resources(int client_socket);

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
int load_client_private_key(const char* username) {
    char key_file[MAX_FILE_PATH_LEN];
    snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", username);
    
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

//function for file handling mode
int file_handling(const char* username){
    printf("File handling for user %s\n", username);
    return 1;

}

// Authentication is now handled by users typing /login commands directly

// Function to receive messages from server (chat mode)
void* receive_messages(void* arg) {
    int client_socket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    //printf("[DEBUG] receive_messages thread started for socket %d\n", client_socket);
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\n Server disconnected or recv error (bytes_received=%d)\n", bytes_received);
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
            printf("\nRSA authentication failed - :connection may be terminated by server.\n");
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
            printf("Server is shutting down. Client exiting immediately...\n");
            running = 0;
            cleanup_client_resources(client_socket);
            exit(0); // Exit immediately
        }
        
        // Store the message
        store_message(buffer);
        
        // Check for token expiry
        if (strstr(buffer, "AUTH_TOKEN_EXPIRED")) {
            printf("\nYour token has expired. Use /newToken to request a new one.\n");
        }
        // Check for token failure
        else if (strstr(buffer, "AUTH_TOKEN_FAIL")) {
            printf("\nInvalid token. Please check your email and try again.\n");
        }
        // Check for lockout
        else if (strstr(buffer, "AUTH_LOCKED")) {
            printf("\nAccount locked due to too many failed attempts. Please try again later.\n");
        }
        // Check if we got authenticated
        else if (strncmp(buffer, "AUTH_SUCCESS", 12) == 0) {
            if (strstr(buffer, "Email token verified successfully")) {
                printf("\nEmail verification successful! You are now fully authenticated.\n");
                email_authenticated = 1;
            } else if (strstr(buffer, "Password verified")) {
                password_authenticated = 1;
                printf("\nPassword verified. Please check your email for a 6-digit token.\n");
                printf("Use /token <code> to enter the token, or /newToken to request a new one.\n");
            } else {
                printf("\n%s", buffer);
                printf("You are now authenticated\n");
            }
        } else {
            printf("\n%s", buffer);
        }
        
        // Show prompt based on authentication state
        if (password_authenticated && email_authenticated) {
            printf("> ");
        } else {
            printf("auth> ");
        }
        fflush(stdout);
    }
    //printf("[DEBUG] receive_messages thread exiting for socket %d\n", client_socket);
    return NULL;
}

// Function to cleanup client resources
void cleanup_client_resources(int client_socket) {
    printf("Cleaning up client resources...\n");
    
    // Close socket
    if (client_socket >= 0) {
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
    }
    
    // Cleanup RSA keys
    cleanup_rsa_keys();
    
    // Cleanup message mutex
    pthread_mutex_destroy(&message_mutex);
    
    // Clear message buffer
    pthread_mutex_lock(&message_mutex);
    for (int i = 0; i < message_count; i++) {
        message_buffer[i].valid = 0;
        memset(message_buffer[i].message, 0, BUFFER_SIZE);
    }
    message_count = 0;
    pthread_mutex_unlock(&message_mutex);
    
    printf("Client cleanup complete\n");
}

// Function to handle secure chat client
int client_mode(int client_socket, const char* username) {
    char buffer[BUFFER_SIZE];
    pthread_t receive_thread;

    printf("Connected to secure MultiFactor Authentication chat server!\n");
    printf("Starting RSA challenge-response authentication...\n");

    // Synchronously wait for and handle RSA challenge before starting receive thread
    int rsa_ok = 0;
    while (!rsa_ok && running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            return 0;
        }

        buffer[bytes_received] = '\0';
        if (strstr(buffer, "RSA_CHALLENGE:") && !rsa_completed) {
            char* challenge_start = strstr(buffer, "RSA_CHALLENGE:") + 14;
            char* challenge_end = strchr(challenge_start, '\n');
            if (challenge_end) *challenge_end = '\0';
            printf("[RSA] Performing RSA mutual authentication...\n");
            if (handle_rsa_challenge(client_socket, challenge_start)) {
                rsa_completed = 1;
                rsa_ok = 1;
                printf("[RSA] SUCCESS: RSA mutual authentication completed!\n");
                printf("[RSA] You may now login with your username and password.\n");
            } else {
                printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
                running = 0;
                return 0;
            }
        } else if (strstr(buffer, "RSA_FAILED")) {
            printf("\nRSA authentication failed - connection may be terminated by server.\n");
            running = 0;
            return 0;
        } else if (strstr(buffer, "SECURITY_ERROR")) {
            printf("\nSECURITY ERROR: RSA authentication is required but failed.\n");
            printf("Make sure you have the correct RSA keys for your client.\n");
            running = 0;
            return 0;
        } else {
            // Print any other server message (e.g., banner, info)
            printf("%s", buffer);
        }
        
    }

    // Now start the receive thread for chat and further messages
    if (pthread_create(&receive_thread, NULL, receive_messages, &client_socket) != 0) {
        printf("Failed to create receive thread\n");
        return 0;
    }

    // Main loop to send messages
    while (running && fgets(buffer, BUFFER_SIZE, stdin)) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (!running) break;
        if (strcmp(buffer, "/quit") == 0) {
            running = 0;
            break;
        }
        if (strlen(buffer) > 0) {
            if (!password_authenticated) {
                if (strncmp(buffer, "/login", 6) == 0 || strncmp(buffer, "/register", 9) == 0) {
                    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                }
                else {
                    printf("Please authenticate first. Use: /login <username> <password> or /register <username> <password>\n");
                    printf("auth> ");
                    continue;
                }
            }
            else if(!email_authenticated) {
                if(strncmp(buffer, "/token", 6) == 0 || strncmp(buffer, "/newToken", 9) == 0){
                    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                }
                else {
                    printf("Please authenticate first. Use: /token <code> or /newToken\n");
                    printf("auth> ");
                    continue;
                }
            } else {
                if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                    printf("Failed to send message\n");
                    running = 0;
                    break;
                }
            }
        }
        if (password_authenticated && email_authenticated) {
            if(strncmp(buffer, "/file", 5) == 0){
                file_handling(username);
            }
            printf("> ");
        } else {
            printf("auth> ");
        }
    }
    running = 0;
    shutdown(client_socket, SHUT_RDWR);
    pthread_join(receive_thread, NULL);
    printf("Disconnected from chat server\n");
    cleanup_client_resources(client_socket);
    return 1; // cleaned up and returned successfully
}

// Helper function to generate a self-signed certificate
int generate_self_signed_cert(const char* username) {
    char privkey_path[MAX_FILE_PATH_LEN];
    char cert_path[MAX_FILE_PATH_LEN];
    snprintf(privkey_path, sizeof(privkey_path), "RSAkeys/client_%s_private.pem", username);
    snprintf(cert_path, sizeof(cert_path), "RSAkeys/client_%s_cert.pem", username);

    FILE* fp = fopen(privkey_path, "r");
    if (!fp) {
        printf("ERROR: Private key not found for certificate generation.\n");
        return 0;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        printf("ERROR: Could not read private key for certificate generation.\n");
        return 0;
    }

    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        printf("ERROR: Could not allocate X509 certificate.\n");
        return 0;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)username, -1, -1, 0);
    X509_set_issuer_name(x509, name); // self-signed

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        printf("ERROR: Failed to sign certificate.\n");
        return 0;
    }

    FILE* cert_fp = fopen(cert_path, "w");
    if (!cert_fp) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        printf("ERROR: Could not open cert file for writing.\n");
        return 0;
    }
    PEM_write_X509(cert_fp, x509);
    fclose(cert_fp);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    printf("Self-signed certificate generated: %s\n", cert_path);
    return 1;
}

int main(int argc, char *argv[]) {
    
    struct sockaddr_in server_addr;
    
    // Parse command line arguments - client_id is REQUIRED
    if (argc != 2) {
        printf("Usage: %s <username>\n", argv[0]);
        printf("Example: %s alice\n", argv[0]);
        return 1;
    }
    
    const char* username = argv[1];
    
    // Automatically generate RSA keys if they do not exist
    char key_file[MAX_FILE_PATH_LEN];
    snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", username);
    FILE* fp = fopen(key_file, "r");
    if (!fp) {
        printf("Private key not found for user '%s'. Generating new RSA keys...\n", username);
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "./generate_rsa_keys client %s", username);
        int ret = system(cmd);
        if (ret != 0) {
            printf("Failed to generate RSA keys for user '%s'!\n", username);
            return 1;
        }
    } else {
        fclose(fp);
    }
    
    // After key generation, check for certificate
    char cert_file[MAX_FILE_PATH_LEN];
    snprintf(cert_file, sizeof(cert_file), "RSAkeys/client_%s_cert.pem", username);
    FILE* cert_fp = fopen(cert_file, "r");
    if (!cert_fp) {
        printf("Certificate not found for user '%s'. Generating self-signed certificate...\n", username);
        if (!generate_self_signed_cert(username)) {
            printf("Failed to generate self-signed certificate for user '%s'!\n", username);
            return 1;
        }
    } else {
        fclose(cert_fp);
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    // Load RSA keys
    if (!load_client_private_key(username) || !load_server_public_key()) {
        printf("Failed to load RSA keys\n");
        return 1;
    }
    
    // Connect to server
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }
    
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        return 1;
    }
    printf("Connected to server. Sending certificate...\n");
    // Send certificate as first message
    cert_fp = fopen(cert_file, "r");
    if (!cert_fp) {
        printf("ERROR: Could not open certificate file for sending.\n");
        close(sock);
        return 1;
    }
    char cert_buf[2048];
    size_t cert_len = fread(cert_buf, 1, sizeof(cert_buf) - 1, cert_fp);
    fclose(cert_fp);
    cert_buf[cert_len] = '\0';
    // Send certificate length first (as 4-byte int, network order)
    uint32_t net_cert_len = htonl(cert_len);
    if (send(sock, &net_cert_len, sizeof(net_cert_len), 0) != sizeof(net_cert_len)) {
        printf("ERROR: Failed to send certificate length.\n");
        close(sock);
        return 1;
    }
    // Send certificate data
    ssize_t sent_bytes = send(sock, cert_buf, cert_len, 0);
    if (sent_bytes != (ssize_t)cert_len) {
        printf("ERROR: Failed to send certificate data.\n");
        close(sock);
        return 1;
    }
    printf("Certificate sent to server. Starting authentication...\n");
    // Send username after certificate
    char id_msg[BUFFER_SIZE];
    snprintf(id_msg, sizeof(id_msg), "USERNAME:%s\n", username);
    if (send(sock, id_msg, strlen(id_msg), 0) < 0) {
        perror("Failed to send username");
        close(sock);
        return 1;
    }
    // Run secure chat client
    if(client_mode(sock, username)){
        close(sock);
        return 1;
    }
    
    // Cleanup
    cleanup_client_resources(sock);
    return 0;
} 