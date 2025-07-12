#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pthread.h>
#include <time.h>

#define PORT 12345
#define BUFFER_SIZE 1024

volatile int running = 1; // Global flag to signal thread to stop

// Function to receive messages from server
DWORD WINAPI receive_messages(LPVOID arg) {
    SOCKET client_socket = *(SOCKET*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0; // Signal main thread to exit if server disconnects
            break;
        }
        
        buffer[bytes_received] = '\0';
        printf("\n%s\n", buffer);
        printf("> "); // Re-print prompt
        fflush(stdout);
    }
    
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    HANDLE receive_thread;

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);

    // Convert IP address from string to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // Connect to server
    printf("Connecting to chat server...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection failed: %d\n", WSAGetLastError());
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    printf("Connected to chat server!\n");
    printf("Commands: /nick <name>, /list, /quit\n");
    printf("Type your messages below:\n\n");

    // Create thread to receive messages
    receive_thread = CreateThread(NULL, 0, receive_messages, &client_socket, 0, NULL);
    if (receive_thread == NULL) {
        printf("Failed to create receive thread\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }

    // Main loop to send messages
    printf("> ");
    while (fgets(buffer, BUFFER_SIZE, stdin)) {
        // Remove newline
        buffer[strcspn(buffer, "\r\n")] = 0;

        // Check for quit command
        if (strcmp(buffer, "/quit") == 0) {
            running = 0; // Signal receive thread to exit
            break;
        }

        // Send message to server
        if (strlen(buffer) > 0) {
            if (send(client_socket, buffer, (int)strlen(buffer), 0) == SOCKET_ERROR) {
                printf("Failed to send message: %d\n", WSAGetLastError());
                running = 0;
                break;
            }
        }

        printf("> ");
    }

    // Cleanup
    running = 0;
    shutdown(client_socket, SD_BOTH); // Shutdown the socket to unblock recv
    WaitForSingleObject(receive_thread, INFINITE); // Wait for receive thread to finish
    CloseHandle(receive_thread);
    closesocket(client_socket);
    WSACleanup();
    printf("Disconnected from server\n");
    return 0;
}
