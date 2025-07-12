#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Structure to hold client information (for chat mode)
typedef struct {
    SOCKET socket;
    struct sockaddr_in addr;
    char nickname[32];
    int active;
} client_t;

// Structure to pass client info to thread (for basic mode)
typedef struct {
    SOCKET client_socket;
    struct sockaddr_in client_addr;
} client_info_t;

// Global variables for chat mode
client_t clients[MAX_CLIENTS];
int client_count = 0;
CRITICAL_SECTION clients_cs;

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
void broadcast_message(const char* message, SOCKET sender_socket) {
    EnterCriticalSection(&clients_cs);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i].active && clients[i].socket != sender_socket) {
            send(clients[i].socket, message, strlen(message), 0);
        }
    }
    LeaveCriticalSection(&clients_cs);
}

// Function to add a new client (chat mode)
int add_client(SOCKET client_socket, struct sockaddr_in client_addr) {
    EnterCriticalSection(&clients_cs);
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
            LeaveCriticalSection(&clients_cs);
            return i;
        }
    }
    LeaveCriticalSection(&clients_cs);
    return -1;
}

// Function to remove a client (chat mode)
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

// Function to handle individual client in basic mode
DWORD WINAPI handle_basic_client(LPVOID arg) {
    client_info_t *client_data = (client_info_t *)arg;
    SOCKET client_socket = client_data->client_socket;
    struct sockaddr_in client_addr = client_data->client_addr;
    
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    
    while (1) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("Client %s:%d disconnected\n", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
            break;
        }
        
        buffer[bytes_received] = '\0';
        printf("Received from %s:%d: %s\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), buffer);
        
        size_t max_copy = BUFFER_SIZE - strlen("Server received: ") - 1;
        size_t safe_len = strnlen(buffer, max_copy);
        snprintf(response, BUFFER_SIZE, "Server received: %.*s", (int)safe_len, buffer);
        send(client_socket, response, strlen(response), 0);
    }
    
    closesocket(client_socket);
    free(client_data);
    return 0;
}

// Function to handle individual client in chat mode
DWORD WINAPI handle_chat_client(LPVOID arg) {
    int client_index = *(int*)arg;
    free(arg);
    
    SOCKET client_socket = clients[client_index].socket;
    struct sockaddr_in client_addr = clients[client_index].addr;
    char buffer[BUFFER_SIZE];
    char broadcast_msg[BUFFER_SIZE + 64];
    
    // Send welcome message
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Server: %s has joined the chat!", clients[client_index].nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Welcome to the chat! You are %s. Commands: /nick <name>, /list, /quit\n", 
             clients[client_index].nickname);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    while (1) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) break;
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        if (strcmp(buffer, "/quit") == 0) break;
        
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
        
        // Regular message
        if (strlen(buffer) > 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s: %s", clients[client_index].nickname, buffer);
            broadcast_message(broadcast_msg, client_socket);
        }
    }
    
    remove_client(client_index);
    return 0;
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    HANDLE thread_handle;
    int mode = 0; // 0 = basic, 1 = chat
    
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
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Initialize critical section for chat mode
    if (mode == 1) {
        InitializeCriticalSection(&clients_cs);
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Set socket options
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
    
    // Bind socket
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
    
    printf("%s server started on port %d\n", mode == 1 ? "Chat" : "Basic", PORT);
    printf("Waiting for client connections...\n");
    
    // Accept client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }
        
        if (mode == 0) {
            // Basic mode
            client_info_t *client_data = malloc(sizeof(client_info_t));
            if (client_data == NULL) {
                printf("Memory allocation failed\n");
                closesocket(client_socket);
                continue;
            }
            
            client_data->client_socket = client_socket;
            client_data->client_addr = client_addr;
            
            thread_handle = CreateThread(NULL, 0, handle_basic_client, (LPVOID)client_data, 0, NULL);
            if (thread_handle == NULL) {
                printf("Thread creation failed\n");
                free(client_data);
                closesocket(client_socket);
                continue;
            }
            CloseHandle(thread_handle);
        } else {
            // Chat mode
            int client_index = add_client(client_socket, client_addr);
            if (client_index == -1) {
                printf("No space for new client\n");
                closesocket(client_socket);
                continue;
            }
            
            int *client_index_ptr = malloc(sizeof(int));
            if (client_index_ptr == NULL) {
                printf("Memory allocation failed\n");
                remove_client(client_index);
                continue;
            }
            *client_index_ptr = client_index;
            
            thread_handle = CreateThread(NULL, 0, handle_chat_client, (LPVOID)client_index_ptr, 0, NULL);
            if (thread_handle == NULL) {
                printf("Thread creation failed\n");
                free(client_index_ptr);
                remove_client(client_index);
                continue;
            }
            CloseHandle(thread_handle);
        }
    }
    
    closesocket(server_socket);
    if (mode == 1) {
        DeleteCriticalSection(&clients_cs);
    }
    WSACleanup();
    return 0;
} 