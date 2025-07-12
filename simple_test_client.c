#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define PORT 12345
#define BUFFER_SIZE 1024

// Simple test client that sends a few messages and exits
int main() {
    WSADATA wsaData;
    SOCKET client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char *test_messages[] = {
        "Hello, Server!",
        "This is a test message",
        "Goodbye!"
    };
    int num_messages = sizeof(test_messages) / sizeof(test_messages[0]);
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // Connect to server
    printf("Connecting to server...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, (int)sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Connected to server at 127.0.0.1:%d\n", PORT);
    
    // Send test messages
    for (unsigned int i = 0; i < (unsigned int)num_messages; i++) {
        printf("Sending: %s\n", test_messages[i]);
        
        if (send(client_socket, test_messages[i], (int)strlen(test_messages[i]), 0) < 0) {
            printf("Send failed\n");
            break;
        }
        
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server response: %s\n", buffer);
        } else if (bytes_received == 0) {
            printf("Server closed connection\n");
            break;
        } else {
            printf("Receive failed\n");
            break;
        }
        
        Sleep((DWORD)500); // Wait 0.5 seconds between messages
    }
    
    printf("Test client finished\n");
    closesocket(client_socket);
    WSACleanup();
    return 0;
} 