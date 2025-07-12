#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>


#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Structure to pass client info to thread
typedef struct {
    SOCKET client_socket;
    struct sockaddr_in client_addr;
} client_info_t;

// Function to handle individual client
DWORD WINAPI handle_client(LPVOID arg) {
    client_info_t *client_data = (client_info_t *)arg;
    SOCKET client_socket = client_data->client_socket;
    struct sockaddr_in client_addr = client_data->client_addr;
    
    char buffer[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    
    printf("Client connected from %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), 
           ntohs(client_addr.sin_port));
    
    while (1) {
        // Receive data from client
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        
        if (bytes_received <= 0) {
            printf("Client %s:%d disconnected\n", 
                   inet_ntoa(client_addr.sin_addr), 
                   ntohs(client_addr.sin_port));
            printf("Waiting for client connections...\n");
            break;
        }
        
        // Null-terminate the received data
        buffer[bytes_received] = '\0';
        
        printf("Received from %s:%d: %s\n", 
               inet_ntoa(client_addr.sin_addr), 
               ntohs(client_addr.sin_port), 
               buffer);
        
        // Prepare response
        size_t max_copy = BUFFER_SIZE - strlen("Server recieved: ") - 1;
        size_t safe_len = strnlen(buffer, max_copy) ;
        snprintf(response, BUFFER_SIZE, "Server received: %.*s", (int)safe_len, buffer);
        
        // Send response back to client
        send(client_socket, response, strlen(response), 0);
    }
    
    // Clean up
    closesocket(client_socket);
    free(client_data);
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
    server_addr.sin_addr.s_addr = INADDR_ANY;  // Listen on all interfaces
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
    
    printf("Server started on port %d\n", PORT);
    printf("Waiting for client connections...\n");
    
    // Accept client connections
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }
        
        // Allocate memory for client info
        client_info_t *client_data = malloc(sizeof(client_info_t));
        if (client_data == NULL) {
            printf("Memory allocation failed\n");
            closesocket(client_socket);
            continue;
        }
        
        client_data->client_socket = client_socket;
        client_data->client_addr = client_addr;
        
        // Create thread for this client
        thread_handle = CreateThread(NULL, 0, handle_client, (LPVOID)client_data, 0, NULL);
        if (thread_handle == NULL) {
            printf("Thread creation failed\n");
            free(client_data);
            closesocket(client_socket);
            continue;
        }
        
        // Close thread handle (thread will continue running)
        CloseHandle(thread_handle);
    }
    
    closesocket(server_socket);
    WSACleanup();
    return 0;
} 