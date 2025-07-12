#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>


#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Structure to hold client information
typedef struct {
    SOCKET socket;
    struct sockaddr_in addr;
    char nickname[32];
    int active;
    int dm_partner;  // Index of DM partner (-1 if not in DM)
} client_t;

// Global variables for client management
client_t clients[MAX_CLIENTS];
int client_count = 0;
CRITICAL_SECTION clients_cs; // acts as a lock to prevent race conditions

// Function to find client by nickname
int find_client_by_nickname(const char* nickname) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && strcmp(clients[i].nickname, nickname) == 0) {
            return i;
        }
    }
    return -1; // Not found
}

// Function to send direct message
void send_dm(int sender_index, int receiver_index, const char* message) {
    if (receiver_index >= 0 && receiver_index < MAX_CLIENTS && clients[receiver_index].active) {
        char dm_msg[BUFFER_SIZE + 64];
        snprintf(dm_msg, sizeof(dm_msg), "[DM from %s]: %s", 
                 clients[sender_index].nickname, message);
        send(clients[receiver_index].socket, dm_msg, strlen(dm_msg), 0);
        
        // Echo to sender
        snprintf(dm_msg, sizeof(dm_msg), "[DM to %s]: %s", 
                 clients[receiver_index].nickname, message);
        send(clients[sender_index].socket, dm_msg, strlen(dm_msg), 0);
    }
}

// Function to broadcast message to all clients except sender
void broadcast_message(const char* message, SOCKET sender_socket) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].socket != sender_socket) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
    
    LeaveCriticalSection(&clients_cs); //exit lock
}

// Function to add a new client
int add_client(SOCKET client_socket, struct sockaddr_in client_addr) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i].active) {
            clients[i].socket = client_socket;
            clients[i].addr = client_addr;
            clients[i].active = 1;
            clients[i].dm_partner = -1;  // Not in DM initially
            snprintf(clients[i].nickname, sizeof(clients[i].nickname), "Client%d", i + 1);
            client_count++;
            
            printf("Client %s connected from %s:%d (Total clients: %d)\n", 
                   clients[i].nickname,
                   inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port),
                   client_count);
            
            LeaveCriticalSection(&clients_cs);
            return i;
        }
    }
    
    LeaveCriticalSection(&clients_cs);
    return -1; // No space available
}

// Function to remove a client
void remove_client(int client_index) {
    if (client_index >= 0 && client_index < MAX_CLIENTS && clients[client_index].active) {
        EnterCriticalSection(&clients_cs);
        
        printf("Client %s disconnected (Total clients: %d)\n", 
               clients[client_index].nickname, client_count - 1);
        
        closesocket(clients[client_index].socket);
        clients[client_index].active = 0;
        client_count--;
        
        LeaveCriticalSection(&clients_cs);
    }
}

// Function to handle individual client
DWORD WINAPI handle_client(LPVOID arg) {
    int client_index = *(int*)arg;
    free(arg); // Free the allocated memory
    
    SOCKET client_socket = clients[client_index].socket;
    struct sockaddr_in client_addr = clients[client_index].addr;
    char buffer[BUFFER_SIZE];
    char broadcast_msg[BUFFER_SIZE + 64];
    
    // Send welcome message
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Server: %s has joined the chat!", clients[client_index].nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    // Send personal welcome
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Welcome to the chat! You are %s. Type your messages below:\n", 
             clients[client_index].nickname);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    while (1) {
        // Receive data from client
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            break;
        }
        
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
        
        // Remove newline characters
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        // Check for quit command
        if (strcmp(buffer, "/quit") == 0) {
            break;
        }
        
        // Check for nickname change
        if (strncmp(buffer, "/nick ", 6) == 0) {
            char new_nick[32];
            strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
            new_nick[sizeof(new_nick) - 1] = '\0';
            
            EnterCriticalSection(&clients_cs);
            strncpy(clients[client_index].nickname, new_nick, sizeof(clients[client_index].nickname) - 1);
            clients[client_index].nickname[sizeof(clients[client_index].nickname) - 1] = '\0';
            LeaveCriticalSection(&clients_cs);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Server: %s changed nickname to %s", 
                     inet_ntoa(client_addr.sin_addr), new_nick);
            broadcast_message(broadcast_msg, client_socket);
            continue;
        }
        
        // Check for list command
        if (strcmp(buffer, "/list") == 0) {
            char list_msg[BUFFER_SIZE] = "Connected clients: ";
            EnterCriticalSection(&clients_cs);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i].active) {
                    strcat(list_msg, clients[i].nickname);
                    strcat(list_msg, " ");
                }
            }
            LeaveCriticalSection(&clients_cs);
            strcat(list_msg, "\n");
            send(client_socket, list_msg, strlen(list_msg), 0);
            continue;
        }
        
        // Check for DM start command
        if (strncmp(buffer, "/dm ", 4) == 0) {
            char target_nickname[32];
            strncpy(target_nickname, buffer + 4, sizeof(target_nickname) - 1);
            target_nickname[sizeof(target_nickname) - 1] = '\0';
            
            EnterCriticalSection(&clients_cs);
            int target_index = find_client_by_nickname(target_nickname);
            
            if (target_index == -1) {
                char error_msg[BUFFER_SIZE];
                snprintf(error_msg, sizeof(error_msg), "Error: User '%s' not found\n", target_nickname);
                send(client_socket, error_msg, strlen(error_msg), 0);
                LeaveCriticalSection(&clients_cs);
                continue;
            }
            
            if (target_index == client_index) {
                char error_msg[BUFFER_SIZE] = "Error: Cannot DM yourself\n";
                send(client_socket, error_msg, strlen(error_msg), 0);
                LeaveCriticalSection(&clients_cs);
                continue;
            }
            
            // Start DM session
            clients[client_index].dm_partner = target_index;
            clients[target_index].dm_partner = client_index;
            
            char dm_start_msg[BUFFER_SIZE];
            snprintf(dm_start_msg, sizeof(dm_start_msg), 
                     "Started DM with %s. Type /exit to end DM.\n", target_nickname);
            send(client_socket, dm_start_msg, strlen(dm_start_msg), 0);
            
            snprintf(dm_start_msg, sizeof(dm_start_msg), 
                     "%s started a DM with you. Type /exit to end DM.\n", clients[client_index].nickname);
            send(clients[target_index].socket, dm_start_msg, strlen(dm_start_msg), 0);
            
            LeaveCriticalSection(&clients_cs);
            continue;
        }
        
        // Check for DM exit command
        if (strcmp(buffer, "/exit") == 0) {
            EnterCriticalSection(&clients_cs);
            
            if (clients[client_index].dm_partner != -1) {
                int partner_index = clients[client_index].dm_partner;
                
                // End DM for both users
                clients[client_index].dm_partner = -1;
                clients[partner_index].dm_partner = -1;
                
                char dm_end_msg[BUFFER_SIZE];
                snprintf(dm_end_msg, sizeof(dm_end_msg), 
                         "DM ended with %s\n", clients[partner_index].nickname);
                send(client_socket, dm_end_msg, strlen(dm_end_msg), 0);
                
                snprintf(dm_end_msg, sizeof(dm_end_msg), 
                         "DM ended with %s\n", clients[client_index].nickname);
                send(clients[partner_index].socket, dm_end_msg, strlen(dm_end_msg), 0);
            } else {
                char error_msg[BUFFER_SIZE] = "You are not in a DM session\n";
                send(client_socket, error_msg, strlen(error_msg), 0);
            }
            
            LeaveCriticalSection(&clients_cs);
            continue;
        }
        
        // Handle regular messages (broadcast or DM)
        if (strlen(buffer) > 0) {
            EnterCriticalSection(&clients_cs);
            
            if (clients[client_index].dm_partner != -1) {
                // User is in DM mode - send message only to DM partner
                send_dm(client_index, clients[client_index].dm_partner, buffer);
            } else {
                // User is in public chat - broadcast to all
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "%s: %s", clients[client_index].nickname, buffer);
                broadcast_message(broadcast_msg, client_socket);
                
                // Echo to sender for confirmation
                snprintf(broadcast_msg, sizeof(broadcast_msg), 
                         "You: %s", buffer);
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            }
            
            LeaveCriticalSection(&clients_cs);
        }
    }
    
    // Send disconnect notification
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Server: %s has left the chat!", clients[client_index].nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    // Remove client
    remove_client(client_index);
    
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    HANDLE thread_handle;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Initialize critical section
    InitializeCriticalSection(&clients_cs);
    
    // Initialize clients array
    memset(clients, 0, sizeof(clients));
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) < 0) {
        printf("setsockopt failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket to address
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Bind failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 5) < 0) {
        printf("Listen failed\n");
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Chat Server started on port %d\n", PORT);
    printf("Waiting for client connections...\n");
    printf("Commands available to clients:\n");
    printf("  /nick <name> - Change nickname\n");
    printf("  /list - List connected clients\n");
    printf("  /dm <name> - Start direct message with user\n");
    printf("  /exit - Exit direct message session\n");
    printf("  /quit - Disconnect from server\n\n");
    
    // Accept client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }
        
        // Check if we have room for more clients
        if (client_count >= MAX_CLIENTS) {
            printf("Maximum clients reached. Rejecting connection from %s:%d\n",
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            closesocket(client_socket);
            continue;
        }
        
        // Add client to our list
        int client_index = add_client(client_socket, client_addr);
        if (client_index == -1) {
            printf("Failed to add client\n");
            closesocket(client_socket);
            continue;
        }
        
        // Allocate memory for client index
        int* client_index_ptr = malloc(sizeof(int));
        if (client_index_ptr == NULL) {
            printf("Memory allocation failed\n");
            remove_client(client_index);
            continue;
        }
        *client_index_ptr = client_index;
        
        // Create thread for this client
        thread_handle = CreateThread(NULL, 0, handle_client, (LPVOID)client_index_ptr, 0, NULL);
        if (thread_handle == NULL) {
            printf("Thread creation failed\n");
            free(client_index_ptr);
            remove_client(client_index);
            continue;
        }
        
        // Close thread handle (thread will continue running)
        CloseHandle(thread_handle);
    }
    
    // Cleanup
    DeleteCriticalSection(&clients_cs);
    closesocket(server_socket);
    WSACleanup();
    return 0;
}