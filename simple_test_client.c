#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 12345
#define BUFFER_SIZE 1024

// Simple test client that sends a few messages and exits
int main() {
    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    char *test_messages[] = {
        "Hello, Server!",
        "This is a test message",
        "Goodbye!"
    };
    int num_messages = sizeof(test_messages) / sizeof(test_messages[0]);
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket < 0) {
        printf("Socket creation failed\n");
        return 1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        printf("Invalid address\n");
        close(client_socket);
        return 1;
    }
    
    // Connect to server
    printf("Connecting to server...\n");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed\n");
        close(client_socket);
        return 1;
    }
    
    printf("Connected to server at 127.0.0.1:%d\n", PORT);
    
    // Send test messages
    for (int i = 0; i < num_messages; i++) {
        printf("Sending: %s\n", test_messages[i]);
        
        if (send(client_socket, test_messages[i], strlen(test_messages[i]), 0) < 0) {
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
        
        sleep(1); // Wait 1 second between messages
    }
    
    printf("Test client finished\n");
    close(client_socket);
    return 0;
} 