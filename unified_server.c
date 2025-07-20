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

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 20
#define DEFAULT_USER_FILE "encrypted_users.txt"

// Program information
#define PROGRAM_NAME "AuthenticatedChatServer"

// Structure to hold authenticated client information
typedef struct {
    int socket;
    struct sockaddr_in addr;
    char nickname[32];
    char username[MAX_USERNAME_LEN];
    int active;
    time_t connect_time;
} client_t;

// Global variables
client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int server_running = 1;
char* user_file = DEFAULT_USER_FILE;

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    printf("\nServer shutdown requested...\n");
    server_running = 0;
    cleanup_rsa_system();  // Clean up RSA resources
}

// Function to find client index by socket
int find_client_by_socket(int client_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].socket == client_socket) {
            pthread_mutex_unlock(&clients_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1;
}

// Function to find client by nickname
int find_client_by_nickname(const char* nickname) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].nickname, nickname) == 0) {
            pthread_mutex_unlock(&clients_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1;
}

// Function to broadcast message to all authenticated clients except sender
void broadcast_message(const char* message, int sender_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].socket != sender_socket) {
            if (send(clients[i].socket, message, strlen(message), 0) < 0) {
                printf("WARNING: Failed to send message to client %s\n", clients[i].nickname);
            }
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to add a new authenticated client
int add_authenticated_client(int client_socket, struct sockaddr_in client_addr, const char* username) {
    pthread_mutex_lock(&clients_mutex);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].socket = client_socket;
            clients[i].addr = client_addr;
            clients[i].active = 1;
            clients[i].connect_time = time(NULL);
            
            // Set username and initial nickname
            strncpy(clients[i].username, username, MAX_USERNAME_LEN - 1);
            clients[i].username[MAX_USERNAME_LEN - 1] = '\0';
            snprintf(clients[i].nickname, sizeof(clients[i].nickname), "%s", username);
            
            client_count++;
            printf("User '%s' joined the chat from %s:%d (Total clients: %d)\n", 
                   username, inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port), client_count);
            
            pthread_mutex_unlock(&clients_mutex);
            return i;
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
    return -1; // Server full
}

// Function to remove a client
void remove_client(int client_index) {
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        pthread_mutex_lock(&clients_mutex);
        
        printf("User '%s' (%s) left the chat (Total clients: %d)\n", 
               clients[client_index].username, clients[client_index].nickname, client_count - 1);
        
        // Notify other clients about the departure
        char departure_msg[BUFFER_SIZE];
        snprintf(departure_msg, sizeof(departure_msg), 
                 "%s has left the chat", clients[client_index].nickname);
        
        // Broadcast departure message (before removing the client)
        int departing_socket = clients[client_index].socket;
        clients[client_index].active = 0; // Mark as inactive to exclude from broadcast
        broadcast_message(departure_msg, departing_socket);
        
        close(departing_socket);
        memset(&clients[client_index], 0, sizeof(client_t)); // Clear the slot
        client_count--;
        
        pthread_mutex_unlock(&clients_mutex);
    }
}

// Function to get list of connected clients
void get_client_list(char* list_buffer, size_t buffer_size) {
    pthread_mutex_lock(&clients_mutex);
    
    snprintf(list_buffer, buffer_size, "Connected users (%d): ", client_count);
    
    int first = 1;
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            if (!first) {
                strncat(list_buffer, ", ", buffer_size - strlen(list_buffer) - 1);
            }
            strncat(list_buffer, clients[i].nickname, buffer_size - strlen(list_buffer) - 1);
            first = 0;
        }
    }
    
    strncat(list_buffer, "\n", buffer_size - strlen(list_buffer) - 1);
    pthread_mutex_unlock(&clients_mutex);
}

// Function to handle individual authenticated client
void* handle_authenticated_client(void* arg) {
    int client_index = *(int*)arg;
    free(arg); // Free the allocated memory for the index
    
    int client_socket = clients[client_index].socket;
    
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
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "%s joined the chat", clients[client_index].nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    // Main message handling loop
    while (server_running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Client %s disconnected\n", clients[client_index].nickname);
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0; // Remove newlines
        
        // Skip empty messages
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Check if session is still valid
        if (!is_authenticated(client_socket)) {
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
            char new_nick[32];
            strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
            new_nick[sizeof(new_nick) - 1] = '\0';
            
            // Validate nickname
            if (strlen(new_nick) == 0) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "Invalid nickname. Usage: /nick <name>\n");
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
                continue;
            }
            
            // Check if nickname is already taken
            if (find_client_by_nickname(new_nick) != -1) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "Nickname '%s' is already taken. Choose a different one.\n", new_nick);
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
                continue;
            }
            
            char old_nick[32];
            pthread_mutex_lock(&clients_mutex);
            strncpy(old_nick, clients[client_index].nickname, sizeof(old_nick) - 1);
            strncpy(clients[client_index].nickname, new_nick, sizeof(clients[client_index].nickname) - 1);
            clients[client_index].nickname[sizeof(clients[client_index].nickname) - 1] = '\0';
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
                     "%s: %s", clients[client_index].nickname, buffer);
            broadcast_message(broadcast_msg, client_socket);
            
            // Log the message
            printf("CHAT [%s] %s: %s\n", clients[client_index].username, 
                   clients[client_index].nickname, buffer);
        }
    }
    
    // Clean up session and remove client
    remove_session(client_socket);
    remove_client(client_index);
    return NULL;
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
    
    // Automatically initiate RSA challenge if RSA system is initialized
    if (is_rsa_system_initialized()) {
        printf("Initiating automatic RSA challenge for %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Automatically start RSA challenge
        rsa_challenge_result_t rsa_result = start_rsa_challenge(client_socket);
        
        if (rsa_result.success && rsa_result.encrypted_size > 0) {
            // Send RSA challenge automatically
            char hex_output[MAX_RSA_ENCRYPTED_SIZE * 2 + 64];
            snprintf(hex_output, sizeof(hex_output), "RSA_CHALLENGE:");
            char *hex_ptr = hex_output + strlen(hex_output);
            
            // Convert binary challenge to hex string
            for (int i = 0; i < rsa_result.encrypted_size; i++) {
                sprintf(hex_ptr + (i * 2), "%02x", rsa_result.encrypted_challenge[i]);
            }
            strcat(hex_output, "\n");
            send(client_socket, hex_output, strlen(hex_output), 0);
            
            printf("RSA challenge sent automatically to %s:%d\n", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        }
    }
    
    // Send authentication prompt (with security requirements)
    snprintf(response, sizeof(response),
             "%s - Secure Authentication Required\n"
             "========================================\n"
             "%s"
             "Please authenticate to access the secure chat:\n"
             "  /login <username> <password> - Login with existing account\n"
             "  /register <username> <password> - Create new account\n\n"
             "%s\n", 
             PROGRAM_NAME,
             is_rsa_system_initialized() ? 
             "SECURITY: RSA cryptographic authentication is REQUIRED.\n"
             "Your client must complete RSA challenge before login.\n\n" :
             "Password-only mode (RSA keys not configured).\n\n",
             is_rsa_system_initialized() ? 
             "Note: Ensure your client supports RSA authentication or you will be blocked." :
             "Note: For enhanced security, configure RSA keys.");
    send(client_socket, response, strlen(response), 0);
    
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
                rsa_challenge_result_t rsa_result = process_rsa_command(buffer, client_socket);
                
                if (rsa_result.success && strstr(rsa_result.response, "RSA authentication successful")) {
                    printf("✓ RSA authentication completed for %s:%d\n", 
                           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    // Send confirmation that RSA is complete (optional feedback)
                    snprintf(response, sizeof(response), 
                             "RSA_COMPLETE - You may now login with username/password\n");
                    send(client_socket, response, strlen(response), 0);
                } else if (!rsa_result.success) {
                    printf("✗ RSA authentication FAILED for %s:%d - connection will be terminated\n", 
                           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    snprintf(response, sizeof(response), 
                             "RSA_FAILED - RSA authentication failed. Connection terminated.\n");
                    send(client_socket, response, strlen(response), 0);
                    break; // Terminate connection on RSA failure
                }
            } else {
                // Handle regular auth commands (login/register/logout)
                // SECURITY CHECK: Block login attempts if RSA is required but not completed
                if (is_rsa_system_initialized() && 
                    (strncmp(buffer, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
                     strncmp(buffer, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0)) {
                    
                    if (!is_rsa_authenticated(client_socket)) {
                        printf("SECURITY BLOCK: Login attempt without RSA authentication from %s:%d\n", 
                               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                        snprintf(response, sizeof(response), 
                                 "SECURITY_ERROR - RSA authentication required but not completed. Please ensure your client supports RSA authentication.\n");
                        send(client_socket, response, strlen(response), 0);
                        continue; // Block this attempt but don't terminate connection
                    }
                }
                
                auth_result_t auth_result = process_auth_command(buffer, client_socket);
                
                // Send response to client
                send(client_socket, auth_result.response, strlen(auth_result.response), 0);
                
                if (auth_result.success && auth_result.authenticated) {
                    // Authentication successful - add to chat
                    printf("✓ Full authentication successful for user '%s' from %s:%d\n", 
                           auth_result.username, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    
                    int client_index = add_authenticated_client(client_socket, client_addr, auth_result.username);
                    if (client_index == -1) {
                        snprintf(response, sizeof(response), "Server is full. Please try again later.\n");
                        send(client_socket, response, strlen(response), 0);
                        break;
                    }
                    
                    // Create thread to handle this authenticated client
                    pthread_t client_thread;
                    int* index_ptr = malloc(sizeof(int));
                    if (index_ptr) {
                        *index_ptr = client_index;
                        if (pthread_create(&client_thread, NULL, handle_authenticated_client, index_ptr) == 0) {
                            pthread_detach(client_thread);
                            return NULL; // Successfully handed off to client handler
                        } else {
                            printf("Failed to create client thread\n");
                            free(index_ptr);
                            remove_client(client_index);
                        }
                    } else {
                        printf("Memory allocation failed\n");
                        remove_client(client_index);
                    }
                    break;
                } else if (auth_result.success && !auth_result.authenticated) {
                    // Registration successful
                    printf("User '%s' registered from %s:%d\n", 
                           auth_result.username, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    snprintf(response, sizeof(response), 
                             "Registration successful! Please login with your new credentials.\n");
                    send(client_socket, response, strlen(response), 0);
                } else {
                    // Authentication failed
                    printf("Authentication failed for %s:%d - reason: %s\n", 
                           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
                           auth_result.response);
                }
            }
        } else {
            // Check if RSA is required and not completed
            if (is_rsa_system_initialized() && !is_rsa_authenticated(client_socket)) {
                snprintf(response, sizeof(response), 
                         "Please complete RSA authentication first. Your client should handle this automatically.\n");
            } else {
                snprintf(response, sizeof(response), 
                         "Please use /login <username> <password> or /register <username> <password>\n");
            }
            send(client_socket, response, strlen(response), 0);
        }
    }
    
    // Close connection if authentication failed or attempts exceeded
    close(client_socket);
    return NULL;
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
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active) {
            char goodbye_msg[] = "Server is shutting down. Goodbye!\n";
            send(clients[i].socket, goodbye_msg, strlen(goodbye_msg), 0);
            close(clients[i].socket);
            clients[i].active = 0;
        }
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
    if (!init_rsa_system("server_private.pem", "server_public.pem")) {
        printf("WARNING: RSA authentication disabled - key files not found\n");
        printf("To enable RSA authentication:\n");
        printf("  1. Run: ./generate_rsa_keys server\n");
        printf("  2. Run: ./generate_rsa_keys client [client_id]  # e.g., alice, bob, etc.\n");
        printf("  3. Set proper permissions: chmod 600 *.pem\n");
        printf("Server will continue with password-only authentication.\n");
    } else {
        printf("RSA two-factor authentication enabled!\n");
    }
    
    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
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
    
    // Cleanup and shutdown
    close(server_socket);
    cleanup_server();
    cleanup_rsa_system();  // Clean up RSA authentication resources
    
    printf("%s shutdown complete\n", PROGRAM_NAME);
    return 0;
} 