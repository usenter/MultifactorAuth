#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "auth_system.h"

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Structure to hold client information (for chat mode)
typedef struct {
    int socket;
    struct sockaddr_in addr;
    char nickname[32];
    int active;
} client_t;

// Structure to pass client info to thread (for basic mode)
typedef struct {
    int client_socket;
    struct sockaddr_in client_addr;
} client_info_t;

// Global variables for chat mode
client_t clients[MAX_CLIENTS];
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to handle authentication
int handle_authentication(int client_socket, const char* message) {
    char command[64], username[MAX_USERNAME_LEN], password[MAX_PASSWORD_LEN];
    char response[BUFFER_SIZE];
    
    // Parse the authentication message
    if (sscanf(message, "%63s %31s %63s", command, username, password) != 3) {
        snprintf(response, BUFFER_SIZE, "%s Invalid format. Use: /login <username> <password> or /register <username> <password>", AUTH_FAILED);
        send(client_socket, response, strlen(response), 0);
        return 0;
    }
    
    if (strcmp(command, AUTH_LOGIN) == 0) {
        if (authenticate_user(username, password)) {
            if (create_session(username, client_socket)) {
                snprintf(response, BUFFER_SIZE, "%s Welcome, %s! You are now authenticated.", AUTH_SUCCESS, username);
                send(client_socket, response, strlen(response), 0);
                printf("User %s logged in successfully\n", username);
                return 1;
            } else {
                snprintf(response, BUFFER_SIZE, "%s Session creation failed", AUTH_FAILED);
                send(client_socket, response, strlen(response), 0);
                return 0;
            }
        } else {
            snprintf(response, BUFFER_SIZE, "%s Invalid username or password", AUTH_FAILED);
            send(client_socket, response, strlen(response), 0);
            return 0;
        }
    } else if (strcmp(command, AUTH_REGISTER) == 0) {
        if (add_user(username, password)) {
            snprintf(response, BUFFER_SIZE, "%s User %s registered successfully. You can now login.", AUTH_SUCCESS, username);
            send(client_socket, response, strlen(response), 0);
            printf("New user registered: %s\n", username);
            return 0; // Still need to login
        } else {
            snprintf(response, BUFFER_SIZE, "%s Registration failed. Username may already exist.", AUTH_FAILED);
            send(client_socket, response, strlen(response), 0);
            return 0;
        }
    } else {
        snprintf(response, BUFFER_SIZE, "%s Unknown command. Use /login or /register", AUTH_FAILED);
        send(client_socket, response, strlen(response), 0);
        return 0;
    }
}

// Function to find client by nickname
int find_client_by_nickname(const char* nickname) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].nickname, nickname) == 0) {
            return i;
        }
    }
    return -1;
}

// Function to broadcast message to all clients except sender (chat mode)
void broadcast_message(const char* message, int sender_socket) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].socket != sender_socket) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
}

// Function to add a new client (chat mode)
int add_client(int client_socket, struct sockaddr_in client_addr) {
    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].socket = client_socket;
            clients[i].addr = client_addr;
            clients[i].active = 1;
            snprintf(clients[i].nickname, sizeof(clients[i].nickname), "Client%d", i + 1);
            client_count++;
            printf("Client %s connected from %s:%d (Total clients: %d)\n", 
                   clients[i].nickname, inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port), client_count);
            pthread_mutex_unlock(&clients_mutex);
            return i;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return -1;
}

// Function to remove a client (chat mode)
void remove_client(int client_index) {
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        pthread_mutex_lock(&clients_mutex);
        printf("Client %s disconnected (Total clients: %d)\n", 
               clients[client_index].nickname, client_count - 1);
        close(clients[client_index].socket);
        clients[client_index].active = 0;
        client_count--;
        pthread_mutex_unlock(&clients_mutex);
    }
}

// Function to handle individual client in basic mode
void* handle_basic_client(void* arg) {
    client_info_t *client_data = (client_info_t *)arg;
    int client_socket = client_data->client_socket;
    struct sockaddr_in client_addr = client_data->client_addr;
    
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    int authenticated = 0;
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    // Send authentication prompt
    snprintf(response, BUFFER_SIZE, "Authentication required. Use: /login <username> <password> or /register <username> <password>\n");
    send(client_socket, response, strlen(response), 0);
    
    while (1) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Client %s:%d disconnected\n", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        printf("Received from %s:%d: %s\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
        
        // Check if this is an authentication message
        if (!authenticated && (strncmp(buffer, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
                              strncmp(buffer, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0)) {
            authenticated = handle_authentication(client_socket, buffer);
            if (authenticated) {
                snprintf(response, BUFFER_SIZE, "Authentication successful! You can now use the echo service.\n");
                send(client_socket, response, strlen(response), 0);
            }
            continue;
        }
        
        // If not authenticated, require authentication
        if (!authenticated) {
            snprintf(response, BUFFER_SIZE, "Please authenticate first. Use: /login <username> <password>\n");
            send(client_socket, response, strlen(response), 0);
            continue;
        }
        
        // Check if session is still valid
        if (!is_authenticated(client_socket)) {
            snprintf(response, BUFFER_SIZE, "Session expired. Please authenticate again.\n");
            send(client_socket, response, strlen(response), 0);
            authenticated = 0;
            continue;
        }
        
        // Handle regular echo message
        size_t max_copy = BUFFER_SIZE - strlen("Server received: ") - 1;
        size_t safe_len = strnlen(buffer, max_copy);
        snprintf(response, BUFFER_SIZE, "Server received: %.*s", (int)safe_len, buffer);
        send(client_socket, response, strlen(response), 0);
    }
    
    // Clean up session
    remove_session(client_socket);
    close(client_socket);
    free(client_data);
    return NULL;
}

// Function to handle individual client in chat mode
void* handle_chat_client(void* arg) {
    int client_index = *(int*)arg;
    int client_socket = clients[client_index].socket;
    struct sockaddr_in client_addr = clients[client_index].addr;
    
    char buffer[BUFFER_SIZE];
    char broadcast_msg[BUFFER_SIZE];
    int authenticated = 0;
    
    printf("Chat client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    // Send authentication prompt
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Authentication required. Use: /login <username> <password> or /register <username> <password>\n");
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    while (1) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Chat client %s:%d disconnected\n", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        // Check if this is an authentication message
        if (!authenticated && (strncmp(buffer, AUTH_LOGIN, strlen(AUTH_LOGIN)) == 0 || 
                              strncmp(buffer, AUTH_REGISTER, strlen(AUTH_REGISTER)) == 0)) {
            authenticated = handle_authentication(client_socket, buffer);
            if (authenticated) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), "Server: %s joined the chat", clients[client_index].nickname);
                broadcast_message(broadcast_msg, client_socket);
            }
            continue;
        }
        
        // If not authenticated, require authentication
        if (!authenticated) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Please authenticate first. Use: /login <username> <password>\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            continue;
        }
        
        // Check if session is still valid
        if (!is_authenticated(client_socket)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Session expired. Please authenticate again.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            authenticated = 0;
            continue;
        }
        
        if (strcmp(buffer, "/quit") == 0) break;
        
        if (strncmp(buffer, "/nick ", 6) == 0) {
            char new_nick[32];
            strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
            new_nick[sizeof(new_nick) - 1] = '\0';
            char old_nick[32];
            
            pthread_mutex_lock(&clients_mutex);
            strncpy(old_nick, clients[client_index].nickname, sizeof(clients[client_index].nickname) - 1);
            strncpy(clients[client_index].nickname, new_nick, sizeof(clients[client_index].nickname) - 1);
            clients[client_index].nickname[sizeof(clients[client_index].nickname) - 1] = '\0';
            pthread_mutex_unlock(&clients_mutex);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Server: %s changed nickname to %s", 
                     old_nick, new_nick);
            broadcast_message(broadcast_msg, client_socket);
            continue;
        }
        
        if (strcmp(buffer, "/list") == 0) {
            char list_msg[BUFFER_SIZE] = "Connected clients: ";
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active) {
                    strcat(list_msg, clients[i].nickname);
                    strcat(list_msg, " ");
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            strcat(list_msg, "\n");
            send(client_socket, list_msg, strlen(list_msg), 0);
            continue;
        }
        
        // Regular message
        if (strlen(buffer) > 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s: %s", clients[client_index].nickname, buffer);
            broadcast_message(broadcast_msg, client_socket);
        }
    }
    
    // Clean up session
    remove_session(client_socket);
    remove_client(client_index);
    free(arg);
    return NULL;
}

int main(int argc, char *argv[]) {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    pthread_t thread_id;
    int mode = 1; // 0 = basic, 1 = chat
    
    // Parse command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "chat") == 0) {
            mode = 1;
        } else if (strcmp(argv[1], "basic") == 0) {
            mode = 0;
        } else {
            printf("Usage: %s [basic|chat]\n", argv[0]);
            printf("  basic: Simple echo server (default)\n");
            printf("  chat:  Multi-client chat server\n");
            return 1;
        }
    }
    
    // Initialize authentication system
    init_auth_system();
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        printf("Socket creation failed\n");
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        printf("setsockopt failed\n");
        close(server_socket);
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Bind failed\n");
        close(server_socket);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        printf("Listen failed\n");
        close(server_socket);
        return 1;
    }
    
    printf("%s server started on port %d\n", mode == 1 ? "Chat" : "Basic", PORT);
    printf("Waiting for client connections...\n");
    
    // Accept client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            printf("Accept failed\n");
            continue;
        }
        
        if (mode == 0) {
            // Basic mode
            client_info_t *client_data = malloc(sizeof(client_info_t));
            if (client_data == NULL) {
                printf("Memory allocation failed\n");
                close(client_socket);
                continue;
            }
            
            client_data->client_socket = client_socket;
            client_data->client_addr = client_addr;
            
            if (pthread_create(&thread_id, NULL, handle_basic_client, (void*)client_data) != 0) {
                printf("Thread creation failed\n");
                free(client_data);
                close(client_socket);
                continue;
            }
            pthread_detach(thread_id);
        } else {
            // Chat mode
            int client_index = add_client(client_socket, client_addr);
            if (client_index == -1) {
                printf("No space for new client\n");
                close(client_socket);
                continue;
            }
            
            int *client_index_ptr = malloc(sizeof(int));
            if (client_index_ptr == NULL) {
                printf("Memory allocation failed\n");
                remove_client(client_index);
                continue;
            }
            *client_index_ptr = client_index;
            
            if (pthread_create(&thread_id, NULL, handle_chat_client, (void*)client_index_ptr) != 0) {
                printf("Thread creation failed\n");
                free(client_index_ptr);
                remove_client(client_index);
                continue;
            }
            pthread_detach(thread_id);
        }
    }
    
    close(server_socket);
    pthread_mutex_destroy(&clients_mutex);
    return 0;
} 