#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#include "auth_system.h"
#include "hashmap/uthash.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 20
#define DEFAULT_USER_FILE "encrypted_users.txt"

// Program information
#define PROGRAM_NAME "AuthenticatedChatServer"

// Add a list to track client handler threads
#define MAX_CLIENT_THREADS 1024
pthread_t client_threads[MAX_CLIENT_THREADS];
int client_thread_count = 0;

// Structure to hold authenticated client information
typedef struct client {
    int socket;
    struct sockaddr_in addr;
    char nickname[32];
    char username[MAX_USERNAME_LEN];
    unsigned int account_id;
    int active;
    time_t connect_time;
    UT_hash_handle hh; // For uthash
} client_t;

// Global variables
client_t *clients_map = NULL; // Hashmap root
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int server_running = 1;
char* user_file = DEFAULT_USER_FILE;

// Make server_socket global for signal handler access
int server_socket = -1;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\nServer shutdown requested...\n");
    server_running = 0;
    // Close server socket to unblock accept()
    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
}

// Function to add a new authenticated client
void add_authenticated_client(client_t *new_client) {
    pthread_mutex_lock(&clients_mutex);
    HASH_ADD_INT(clients_map, socket, new_client);
    client_count++;
    pthread_mutex_unlock(&clients_mutex);
}

// Function to find client by socket
client_t* find_client_by_socket(int client_socket) {
    client_t *c = NULL;
    pthread_mutex_lock(&clients_mutex);
    HASH_FIND_INT(clients_map, &client_socket, c);
    pthread_mutex_unlock(&clients_mutex);
    return c;
}

// Function to find client by nickname
client_t* find_client_by_nickname(const char* nickname) {
    client_t *c, *result = NULL;
    pthread_mutex_lock(&clients_mutex);
    HASH_ITER(hh, clients_map, c, result) {
        if (c->active && strcmp(c->nickname, nickname) == 0) {
            result = c;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return result;
}

// Function to broadcast message to all authenticated clients except sender
void broadcast_message(const char* message, int sender_socket) {
    char* message_with_newline = malloc(strlen(message) + 2);
    strncpy(message_with_newline, message, strlen(message));
    strncat(message_with_newline, "\n", 1);
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active && c->socket != sender_socket) {
            //printf("[DEBUG] Broadcasting to socket %d: %s\n", c->socket, message_with_newline);
            if (send(c->socket, message_with_newline, strlen(message_with_newline), 0) < 0) {
                //printf("[DEBUG] WARNING: Failed to send to socket %d\n", c->socket);
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    free(message_with_newline);
}

// Function to remove a client
void remove_client(int client_socket) {
    pthread_mutex_lock(&clients_mutex);
    client_t *c = NULL;
    HASH_FIND_INT(clients_map, &client_socket, c);
    if (c) {
        printf("User '%s' (%s) left the chat (Total clients: %d)\n", 
               c->username, c->nickname, client_count - 1);
        // Notify other clients about the departure
        char departure_msg[BUFFER_SIZE];
        snprintf(departure_msg, sizeof(departure_msg), 
                 "%s has left the chat", c->nickname);
        // Broadcast departure message (before removing the client)
        int departing_socket = c->socket;
        c->active = 0; // Mark as inactive to exclude from broadcast
        pthread_mutex_unlock(&clients_mutex);
        broadcast_message(departure_msg, departing_socket);
        pthread_mutex_lock(&clients_mutex);
        close(departing_socket);
        HASH_DEL(clients_map, c);
        free(c);
        client_count--;
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to get list of connected clients
void get_client_list(char* list_buffer, size_t buffer_size) {
    pthread_mutex_lock(&clients_mutex);
    snprintf(list_buffer, buffer_size, "Connected users (%d): ", client_count);
    int first = 1;
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            if (!first) {
                strncat(list_buffer, ", ", buffer_size - strlen(list_buffer) - 1);
            }
            strncat(list_buffer, c->nickname, buffer_size - strlen(list_buffer) - 1);
            first = 0;
        }
    }
    strncat(list_buffer, "\n", buffer_size - strlen(list_buffer) - 1);
    pthread_mutex_unlock(&clients_mutex);
}

// Function to handle individual authenticated client
void* handle_authenticated_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg); // Free the allocated memory for the index
    
    //client_t *c = find_client_by_socket(client_socket);
    
    char buffer[BUFFER_SIZE];
    char broadcast_msg[BUFFER_SIZE];
    
    // Send welcome message and instructions
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Welcome to %s!\n"
             "Commands:\n"
             "  /nick <name> - Change your nickname\n"
             "  /list - Show connected users\n"
             "  /help - Show this help\n"
             "  /quit - Leave the chat\n"
             "Type your messages to chat with everyone!\n\n", 
             PROGRAM_NAME);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    // Announce new user to everyone
    client_t *c = find_client_by_socket(client_socket);
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "%s joined the chat", c->nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    // Main message handling loop
    while (server_running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            client_t *c = find_client_by_socket(client_socket);
            printf("Client %s disconnected\n", c->nickname);
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0; // Remove newlines
        
        // Skip empty messages
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Check if session is still valid
        c = find_client_by_socket(client_socket);
        if (!is_authenticated(c->account_id)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Session expired. Please reconnect and authenticate again.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Handle quit command
        if (strcmp(buffer, "/quit") == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Goodbye! You have left the chat.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Handle nickname change
        if (strncmp(buffer, "/nick ", 6) == 0) {
            printf("[DEBUG] Handling /nick command from socket %d\n", client_socket);
            char new_nick[32];
            memset(new_nick, 0, sizeof(new_nick)); // Clear buffer
            strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
            new_nick[sizeof(new_nick) - 1] = '\0'; // Ensure null-termination
            // Remove trailing whitespace/newlines
            new_nick[strcspn(new_nick, "\r\n ")] = 0;

            // Validate nickname
            if (strlen(new_nick) == 0) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "Invalid nickname. Usage: /nick <name>\n");
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
                continue;
            }
            
            // Check if nickname is already taken
            if (find_client_by_nickname(new_nick)) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "Nickname '%s' is already taken. Choose a different one.\n", new_nick);
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
                continue;
            }
            
            char old_nick[32];
            pthread_mutex_lock(&clients_mutex);
            strncpy(old_nick, c->nickname, sizeof(old_nick) - 1);
            strncpy(c->nickname, new_nick, sizeof(c->nickname) - 1);
            c->nickname[sizeof(c->nickname) - 1] = '\0';
            pthread_mutex_unlock(&clients_mutex);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Nickname changed to '%s'\n", new_nick);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s is now known as %s", old_nick, new_nick);
            broadcast_message(broadcast_msg, client_socket);
            continue;
        }
        
        // Handle list command
        if (strcmp(buffer, "/list") == 0) {
            printf("[DEBUG] Handling /list command from socket %d\n", client_socket);
            get_client_list(broadcast_msg, sizeof(broadcast_msg));
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            continue;
        }
        
        // Handle help command
        if (strcmp(buffer, "/help") == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg),
                     "Chat Commands:\n"
                     "  /nick <name> - Change your nickname\n"
                     "  /list - Show connected users\n"
                     "  /help - Show this help\n"
                     "  /quit - Leave the chat\n"
                     "Just type any message to chat with everyone!\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            continue;
        }
        
        // Handle commands that start with / but aren't recognized
        if (buffer[0] == '/') {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Unknown command. Type /help for available commands.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            continue;
        }
        
        // Regular chat message - broadcast to everyone
        if (strlen(buffer) > 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s: %s", c->nickname, buffer);
            broadcast_message(broadcast_msg, client_socket);
            
            // Log the message
            printf("CHAT [%s] %s: %s\n", c->username, c->nickname, buffer);
        }
    }
    
    // Clean up session and remove client
    client_t *final_c = find_client_by_socket(client_socket);
    unsigned int account_id = 0;
    if (final_c) {
        account_id = final_c->account_id;
    }
    remove_client(client_socket);
    if (account_id != 0) {
        remove_session(account_id);
    }
    pthread_mutex_unlock(&clients_mutex);
    return NULL;
}

EVP_PKEY* extract_public_key(X509* client_cert, int client_socket){
    uint32_t net_cert_len;
    int recvd = recv(client_socket, &net_cert_len, sizeof(net_cert_len), MSG_WAITALL);
    if (recvd != sizeof(net_cert_len)) {
        printf("Failed to receive certificate length from client.\n");
        close(client_socket);
        return NULL;
    }
    uint32_t cert_len = ntohl(net_cert_len);
    if (cert_len == 0 || cert_len > 8192) {
        printf("Invalid certificate length received: %u\n", cert_len);
        close(client_socket);
        return NULL;
    }
    char* cert_buf = malloc(cert_len + 1);
    if (!cert_buf) {
        printf("Memory allocation failed for certificate buffer.\n");
        close(client_socket);
        return NULL;
    }
    recvd = recv(client_socket, cert_buf, cert_len, MSG_WAITALL);
    if (recvd != (int)cert_len) {
        printf("Failed to receive certificate data from client.\n");
        free(cert_buf);
        close(client_socket);
        return NULL;
    }
    cert_buf[cert_len] = '\0';
    BIO* cert_bio = BIO_new_mem_buf(cert_buf, cert_len);
    client_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    
    BIO_free(cert_bio);
    free(cert_buf);
    if (!client_cert) {
        printf("Failed to parse client certificate.\n");
        close(client_socket);
        return NULL;
    }
    
    EVP_PKEY* client_pubkey = X509_get_pubkey(client_cert);
    if (!client_pubkey) {
        printf("Failed to extract public key from client certificate.\n");
        X509_free(client_cert);
        return NULL;
    }
    return client_pubkey;
}

// New function to extract client certificate from socket
X509* extract_client_cert(int client_socket) {
    uint32_t net_cert_len;
    int recvd = recv(client_socket, &net_cert_len, sizeof(net_cert_len), MSG_WAITALL);
    if (recvd != sizeof(net_cert_len)) {
        printf("Failed to receive certificate length from client.\n");
        close(client_socket);
        return NULL;
    }
    uint32_t cert_len = ntohl(net_cert_len);
    if (cert_len == 0 || cert_len > 8192) {
        printf("Invalid certificate length received: %u\n", cert_len);
        close(client_socket);
        return NULL;
    }
    char* cert_buf = malloc(cert_len + 1);
    if (!cert_buf) {
        printf("Memory allocation failed for certificate buffer.\n");
        close(client_socket);
        return NULL;
    }
    recvd = recv(client_socket, cert_buf, cert_len, MSG_WAITALL);
    if (recvd != (int)cert_len) {
        printf("Failed to receive certificate data from client.\n");
        free(cert_buf);
        close(client_socket);
        return NULL;
    }
    cert_buf[cert_len] = '\0';
    BIO* cert_bio = BIO_new_mem_buf(cert_buf, cert_len);
    X509* client_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    BIO_free(cert_bio);
    free(cert_buf);
    if (!client_cert) {
        printf("Failed to parse client certificate.\n");
        close(client_socket);
        return NULL;
    }
    return client_cert;
}

// Function to handle new client connections (authentication phase)
void* handle_new_connection(void* arg) {
    int client_socket = *(int*)arg;
    free(arg); // Free the allocated memory for the socket
    
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    
    printf("New connection from %s:%d (authentication required)\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    // --- Receive certificate as first message ---
    X509* client_cert = extract_client_cert(client_socket);
    if (!client_cert) {
        printf("Client certificate extraction failed. Closing connection.\n");
        close(client_socket);
        return NULL;
    }
    EVP_PKEY* client_pubkey = X509_get_pubkey(client_cert);
    if (!client_pubkey) {
        printf("Failed to extract public key from client certificate.\n");
        X509_free(client_cert);
        close(client_socket);
        return NULL;
    }
    // Print subject CN for debug
    X509_NAME* subj = X509_get_subject_name(client_cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
    printf("Received client certificate. Subject CN: %s\n", cn);

    // --- Receive username as next message ---
    char username_buffer[BUFFER_SIZE];
    int name_bytes = recv(client_socket, username_buffer, BUFFER_SIZE - 1, 0);
    char username[MAX_USERNAME_LEN] = "";
    unsigned int account_id = 0;
    if (name_bytes <= 0) {
        printf("Client disconnected before sending username\n");
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        close(client_socket);
        return NULL;
    }
    username_buffer[name_bytes] = '\0';
    username_buffer[strcspn(username_buffer, "\r\n")] = 0; // Remove newlines


    if (strncmp(username_buffer, "USERNAME:", 9) == 0) {
        strncpy(username, username_buffer + 9, MAX_USERNAME_LEN - 1);
        username[MAX_USERNAME_LEN - 1] = '\0';
        username_t *uname_entry = find_username(username);
        if (!uname_entry) {
            printf("Invalid username received: %s\n", username);
            snprintf(response, sizeof(response), "ERROR: Invalid username\n");
            send(client_socket, response, strlen(response), 0);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            close(client_socket);
            return NULL;
        }
        account_id = uname_entry->account_id;
        user_t *user = find_user(account_id);
        if (!user) {
            printf("Invalid account_id received: %u\n", account_id);
            snprintf(response, sizeof(response), "ERROR: Invalid account_id\n");
            send(client_socket, response, strlen(response), 0);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            close(client_socket);
            return NULL;
        }
        user->public_key = client_pubkey;
        client_pubkey = NULL; // Ownership transferred, don't free here
        printf("Valid username received: %s (account_id: %u)\n", username, account_id);
        
        // Now generate and send the RSA challenge using the auth_system
        if (is_rsa_system_initialized()) {
            printf("Initiating automatic RSA challenge for %s%s:%d\n", username, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            rsa_challenge_result_t rsa_result = start_rsa_challenge_for_client(account_id, user->public_key);
            if (rsa_result.success && rsa_result.encrypted_size > 0) {
                char hex_output[RSA_HEX_BUFFER_SIZE];
                snprintf(hex_output, sizeof(hex_output), "RSA_CHALLENGE:");
                char *hex_ptr = hex_output + strlen(hex_output);
                for (int i = 0; i < rsa_result.encrypted_size; i++) {
                    sprintf(hex_ptr + (i * 2), "%02x", rsa_result.encrypted_challenge[i]);
                }
                strcat(hex_output, "\n");
                send(client_socket, hex_output, strlen(hex_output), 0);
                printf("RSA challenge sent to %s\n", username);
            } else {
                printf("Failed to generate/send RSA challenge for %s\n", username);
                EVP_PKEY_free(client_pubkey);
                X509_free(client_cert);
                close(client_socket);
                return NULL;
            }
        }
    } else {
        printf("Invalid username format received\n");
        snprintf(response, sizeof(response), "ERROR: Invalid username format\n");
        send(client_socket, response, strlen(response), 0);
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        close(client_socket);
        return NULL;
    }
    if (client_pubkey) {
        EVP_PKEY_free(client_pubkey); // Only free if not stored in user
    }
    X509_free(client_cert);
    
    // Authentication prompt
    if (!is_rsa_system_initialized()) {
        snprintf(response, sizeof(response),
                 "%s - Authentication Required\n"
                 "========================================\n"
                 "Password-only mode (RSA keys not configured).\n\n"
                 "Please authenticate to access the chat:\n"
                 "  /login <username> <password> - Login with existing account\n"
                 "  /register <username> <password> - Create new account\n\n"
                 "Note: For enhanced security, configure RSA keys.\n", PROGRAM_NAME);
        send(client_socket, response, strlen(response), 0);
    }
    
    // Authentication loop
    while (server_running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Client %s:%d disconnected during authentication\n", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0; // Remove newlines
        
        // Skip empty commands
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Check if this is an authentication command
        if (is_auth_command(buffer)) {
            // Handle RSA response automatically (transparent to user)
            if (is_rsa_command(buffer)) {
                rsa_challenge_result_t rsa_result = process_rsa_command(buffer, account_id);
                
                if (rsa_result.success && strstr(rsa_result.response, "RSA authentication successful")) {
                    
                    // Send authentication prompt NOW that RSA is complete
                    snprintf(response, sizeof(response),
                             "Please authenticate to access the secure chat:\n"
                             "  /login <username> <password> - Login with existing account\n"
                             "  /register <username> <password> - Create new account\n\n"
                             "Ready for secure login.\n");
                    send(client_socket, response, strlen(response), 0);
                } else if (!rsa_result.success) {
                    printf("RSA authentication FAILED for account %u - connection will be terminated\n", 
                           account_id);
                    snprintf(response, sizeof(response), 
                             "RSA_FAILED - RSA authentication failed. Connection terminated.\n");
                    send(client_socket, response, strlen(response), 0);
                    break;
                }
            } 
            else {
                
                // Handle regular auth commands (login/register/logout)
                auth_result_t auth_result = process_auth_command(buffer, account_id);
                send(client_socket, auth_result.response, strlen(auth_result.response), 0);
                
                if (auth_result.success && auth_result.authenticated) {
                    // Add to authenticated clients list and start chat handler
                    client_t *new_client = malloc(sizeof(client_t));
                    if (new_client) {
                        new_client->socket = client_socket;
                        new_client->addr = client_addr;
                        new_client->active = 1;
                        new_client->connect_time = time(NULL);
                        new_client->account_id = account_id;
                        
                        // Set username and initial nickname
                        strncpy(new_client->username, username, MAX_USERNAME_LEN - 1);
                        new_client->username[MAX_USERNAME_LEN - 1] = '\0';
                        snprintf(new_client->nickname, sizeof(new_client->nickname), "%s", username);
                        
                        add_authenticated_client(new_client);
                        
                        // Start chat handler thread
                        int* arg = malloc(sizeof(int));
                        if (arg) {
                            *arg = client_socket; // Pass socket for remove_client
                            pthread_t chat_thread;
                            if (pthread_create(&chat_thread, NULL, handle_authenticated_client, arg) == 0) {
                                pthread_mutex_lock(&clients_mutex);
                                if (client_thread_count < MAX_CLIENT_THREADS) {
                                    client_threads[client_thread_count++] = chat_thread;
                                }
                                pthread_mutex_unlock(&clients_mutex);
                                // Do not detach here; join in cleanup
                                return NULL;
                            } else {
                                printf("Failed to create chat handler thread\n");
                                free(arg);
                                remove_client(client_socket);
                            }
                        }
                    }
                    break;
                }
            }
        } else {
            snprintf(response, sizeof(response), 
                     "Please authenticate first using /login or /register\n");
            send(client_socket, response, strlen(response), 0);
        }
    }
    
    close(client_socket);
    return NULL;
}

// Function to broadcast shutdown message to all authenticated clients
void broadcast_shutdown_message(void) {
    char shutdown_msg[BUFFER_SIZE];
    snprintf(shutdown_msg, sizeof(shutdown_msg), 
             "Server is shutting down. Goodbye!\n");
    
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            send(c->socket, shutdown_msg, strlen(shutdown_msg), 0);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Print usage information
void print_usage(const char *program_name) {
    printf("%s - Secure Authenticated Chat Server\n", PROGRAM_NAME);
    printf("Requires encrypted user database to start\n\n");
    
    printf("USAGE:\n");
    printf("  %s <database_password>\n", program_name);
    printf("  %s --help\n", program_name);
    printf("  %s --version\n", program_name);
    
    printf("\nDESCRIPTION:\n");
    printf("  Starts a secure chat server that requires user authentication.\n");
    printf("  All clients must authenticate before accessing the chat.\n");
    printf("  Uses encrypted user database file: %s\n", DEFAULT_USER_FILE);
    
    printf("\nEXAMPLE:\n");
    printf("  %s myDatabasePassword\n", program_name);
    
    printf("\nSETUP:\n");
    printf("  1. Create a users.txt file with format: username:password_hash\n");
    printf("  2. Encrypt it: ./user_encryptor encrypt users.txt %s <password>\n", DEFAULT_USER_FILE);
    printf("  3. Start server: %s <password>\n", program_name);
    printf("  4. Clients connect and authenticate to join chat\n");
    
    printf("\nFEATURES:\n");
    printf("  - Mandatory user authentication\n");
    printf("  - Encrypted user database\n");
    printf("  - Multi-client chat with nicknames\n");
    printf("  - Session management and timeout\n");
    printf("  - Graceful shutdown with Ctrl+C\n");
}

// Print version information
void print_version(void) {
    printf("%s\n", PROGRAM_NAME);
    printf("Secure authenticated chat server with encrypted user database\n");
    printf("Built with OpenSSL encryption and POSIX threads\n");
}

// Cleanup function for graceful shutdown
void cleanup_server(void) {
    printf("Cleaning up server resources...\n");
    
    // Close all client connections
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        char goodbye_msg[] = "Server is shutting down. Goodbye!\n";
        send(c->socket, goodbye_msg, strlen(goodbye_msg), 0);
        close(c->socket);
        HASH_DEL(clients_map, c);
        free(c);
    }
    pthread_mutex_unlock(&clients_mutex);
    
    pthread_mutex_destroy(&clients_mutex);
    printf("Server cleanup complete\n");
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
    
    // Validate arguments
    if (argc != 2) {
        fprintf(stderr, "Error: Database password required\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char* database_password = argv[1];
    
    printf("Starting %s...\n", PROGRAM_NAME);
    printf("User database file: %s\n", user_file);
    
    // Initialize authentication system with encrypted database
    printf("Decrypting user database...\n");
    if(!init_encrypted_auth_system(user_file, (char*)database_password)){
        printf("Failed to initialize authentication system\n");
        return 0;
    }
    printf("User database loaded successfully!\n");
    
    // Initialize RSA authentication system
    printf("Initializing RSA authentication...\n");
    if (!init_rsa_system("RSAkeys/server_private.pem", "RSAkeys/server_public.pem")) {
        printf("ERROR: RSA authentication keys not found!\n");
        printf("This server requires RSA two-factor authentication.\n");
        printf("\nTo generate required keys:\n");
        printf("  1. Run: ./generate_rsa_keys server\n");
        printf("  2. Run: ./generate_rsa_keys client [username]  # e.g., alice, bob, etc.\n");
        printf("\nServer cannot start without RSA keys.\n");
        return 1;
    }
    printf("RSA two-factor authentication enabled!\n");
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        fprintf(stderr, "Socket creation failed\n");
        return 1;
    }
    
    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "setsockopt failed\n");
        close(server_socket);
        return 1;
    }
    
    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Bind failed on port %d\n", PORT);
        close(server_socket);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        fprintf(stderr, "Listen failed\n");
        close(server_socket);
        return 1;
    }
    
    printf("Server listening on port %d\n", PORT);
    printf("Maximum clients: %d\n", MAX_CLIENTS);
    printf("Session timeout: %d minutes\n", AUTH_TIMEOUT / 60);
    printf("Server ready! Press Ctrl+C to exit\n");
    printf("========================================================================\n");
    
    // Main server loop - accept client connections
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            if (server_running) {
                printf("Accept failed\n");
            }
            continue;
        }
        
        // Create thread to handle authentication for this client
        pthread_t auth_thread;
        int* socket_ptr = malloc(sizeof(int));
        if (socket_ptr) {
            *socket_ptr = client_socket;
            if (pthread_create(&auth_thread, NULL, handle_new_connection, socket_ptr) != 0) {
                printf("Failed to create authentication thread\n");
                free(socket_ptr);
                close(client_socket);
            } else {
                pthread_detach(auth_thread);
            }
        } else {
            printf("Memory allocation failed\n");
            close(client_socket);
        }
    }
    
    printf("Broadcasting shutdown message to all clients\n");
    broadcast_shutdown_message();
    
    // Give clients a moment to receive the shutdown message
    sleep(1); // 100ms delay
    
    printf("Closing all client sockets\n");
    // Close all client sockets to unblock handler threads
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        printf("Closing client socket %s\n", c->nickname);
        close(c->socket); // This will unblock recv() in handler threads
    }
    pthread_mutex_unlock(&clients_mutex);

    printf("Joining all client handler threads\n");
    // Now join all client handler threads
    for (int i = client_thread_count-1; i >= 0; i--) {
        printf("Joining client handler thread %d\n", i);
        pthread_join(client_threads[i], NULL);
    }

    printf("Safely freeing all remaining clients\n");
    // Now, safely free all remaining clients
    pthread_mutex_lock(&clients_mutex);
    HASH_ITER(hh, clients_map, c, tmp) {
        HASH_DEL(clients_map, c);
        free(c);
    }
    pthread_mutex_unlock(&clients_mutex);
    printf("Cleaning up RSA system\n");
    // Cleanup and shutdown
    close(server_socket);
    printf("Server socket closed\n");
    cleanup_server();
    printf("Cleaning up authentication system\n");
    cleanup_auth_system(); // Clean up authentication system hashmaps
    
    printf("%s shutdown complete\n", PROGRAM_NAME);
    return 0;
} 