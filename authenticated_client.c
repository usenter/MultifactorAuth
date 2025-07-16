#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64

volatile int running = 1;
int authenticated = 0;
char username[MAX_USERNAME_LEN];

// Authentication commands
#define AUTH_LOGIN "AUTH_LOGIN"
#define AUTH_REGISTER "AUTH_REGISTER"
#define AUTH_SUCCESS "AUTH_SUCCESS"
#define AUTH_FAILED "AUTH_FAILED"

// Function to handle authentication
int authenticate_with_server(SOCKET client_socket, const char* username, const char* password, int is_register) {
    char auth_message[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    
    // Create authentication message
    if (is_register) {
        snprintf(auth_message, BUFFER_SIZE, "%s %s %s", AUTH_REGISTER, username, password);
    } else {
        snprintf(auth_message, BUFFER_SIZE, "%s %s %s", AUTH_LOGIN, username, password);
    }
    
    // Send authentication request
    if (send(client_socket, auth_message, strlen(auth_message), 0) == SOCKET_ERROR) {
        printf("Failed to send authentication request\n");
        return 0;
    }
    
    // Receive response
    int bytes_received = recv(client_socket, response, BUFFER_SIZE - 1, 0);
    if (bytes_received <= 0) {
        printf("Failed to receive authentication response\n");
        return 0;
    }
    
    response[bytes_received] = '\0';
    printf("Server: %s", response);
    
    // Check if authentication was successful
    if (strncmp(response, AUTH_SUCCESS, strlen(AUTH_SUCCESS)) == 0) {
        return 1;
    }
    
    return 0;
}

// Function to receive messages from server (chat mode)
DWORD WINAPI receive_messages(LPVOID arg) {
    SOCKET client_socket = *(SOCKET*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            break;
        }
        
        buffer[bytes_received] = '\0';
        printf("\n%s", buffer);
        if (authenticated) {
            printf("> ");
        }
        fflush(stdout);
    }
    
    return 0;
}

// Function to handle basic client mode with authentication
void basic_client_mode(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    char *test_messages[] = {
        "Hello, Server!",
        "How are you?",
        "Goodbye!"
    };
    int num_messages = sizeof(test_messages) / sizeof(test_messages[0]);
    
    printf("Connected to authenticated basic server at 127.0.0.1:%d\n", PORT);
    
    // Wait for authentication prompt
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Server: %s", buffer);
    }
    
    // Perform authentication
    if (!authenticate_with_server(client_socket, username, "password123", 0)) {
        printf("Authentication failed. Trying to register...\n");
        if (!authenticate_with_server(client_socket, username, "password123", 1)) {
            printf("Registration failed. Exiting.\n");
            return;
        }
        printf("Registration successful. Now logging in...\n");
        if (!authenticate_with_server(client_socket, username, "password123", 0)) {
            printf("Login failed after registration. Exiting.\n");
            return;
        }
    }
    
    authenticated = 1;
    printf("Authentication successful!\n");
    
    // Wait for success message
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Server: %s", buffer);
    }
    
    // Send test messages
    for (int i = 0; i < num_messages; i++) {
        printf("Sending: %s\n", test_messages[i]);
        
        if (send(client_socket, test_messages[i], strlen(test_messages[i]), 0) < 0) {
            printf("Send failed\n");
            break;
        }
        
        bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Server response: %s", buffer);
        } else if (bytes_received == 0) {
            printf("Server closed connection\n");
            break;
        } else {
            printf("Receive failed\n");
            break;
        }
        
        Sleep(1000); // Wait 1 second between messages
    }
    
    printf("Basic client finished\n");
}

// Function to handle chat client mode with authentication
void chat_client_mode(SOCKET client_socket) {
    char buffer[BUFFER_SIZE];
    HANDLE receive_thread;
    
    printf("Connected to authenticated chat server!\n");
    
    // Wait for authentication prompt
    int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Server: %s", buffer);
    }
    
    // Perform authentication
    if (!authenticate_with_server(client_socket, username, "password123", 0)) {
        printf("Authentication failed. Trying to register...\n");
        if (!authenticate_with_server(client_socket, username, "password123", 1)) {
            printf("Registration failed. Exiting.\n");
            return;
        }
        printf("Registration successful. Now logging in...\n");
        if (!authenticate_with_server(client_socket, username, "password123", 0)) {
            printf("Login failed after registration. Exiting.\n");
            return;
        }
    }
    
    authenticated = 1;
    printf("Authentication successful!\n");
    
    // Wait for welcome message
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Server: %s", buffer);
    }
    
    printf("Commands: /nick <name>, /list, /quit\n");
    printf("Type your messages below:\n\n");
    
    // Create thread to receive messages
    receive_thread = CreateThread(NULL, 0, receive_messages, &client_socket, 0, NULL);
    if (receive_thread == NULL) {
        printf("Failed to create receive thread\n");
        return;
    }
    
    // Main loop to send messages
    printf("> ");
    while (fgets(buffer, BUFFER_SIZE, stdin)) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        
        if (strcmp(buffer, "/quit") == 0) {
            running = 0;
            break;
        }
        
        if (strlen(buffer) > 0) {
            if (send(client_socket, buffer, (int)strlen(buffer), 0) == SOCKET_ERROR) {
                printf("Failed to send message\n");
                running = 0;
                break;
            }
        }
        
        printf("> ");
    }
    
    // Cleanup
    running = 0;
    shutdown(client_socket, SD_BOTH);
    WaitForSingleObject(receive_thread, INFINITE);
    CloseHandle(receive_thread);
    printf("Disconnected from chat server\n");
}

int main(int argc, char *argv[]) {
    WSADATA wsaData;
    SOCKET client_socket;
    struct sockaddr_in server_addr;
    int mode = 0; // 0 = basic, 1 = chat
    
    // Parse command line arguments
    if (argc > 1) {
        if (strcmp(argv[1], "chat") == 0) {
            mode = 1;
        } else if (strcmp(argv[1], "basic") == 0) {
            mode = 0;
        } else {
            printf("Usage: %s [basic|chat]\n", argv[0]);
            printf("  basic: Simple echo client with authentication (default)\n");
            printf("  chat:  Interactive chat client with authentication\n");
            return 1;
        }
    }
    
    // Get username from user
    printf("Enter username: ");
    if (fgets(username, MAX_USERNAME_LEN, stdin) == NULL) {
        printf("Failed to read username\n");
        return 1;
    }
    username[strcspn(username, "\r\n")] = 0;
    
    if (strlen(username) == 0) {
        printf("Username cannot be empty\n");
        return 1;
    }
    
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
    printf("Connecting to %s server...\n", mode == 1 ? "authenticated chat" : "authenticated basic");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Connection failed\n");
        closesocket(client_socket);
        WSACleanup();
        return 1;
    }
    
    // Run in appropriate mode
    if (mode == 0) {
        basic_client_mode(client_socket);
    } else {
        chat_client_mode(client_socket);
    }
    
    // Cleanup
    closesocket(client_socket);
    WSACleanup();
    return 0;
} 