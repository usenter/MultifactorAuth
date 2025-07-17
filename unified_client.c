#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_MESSAGES 100

volatile int running = 1;

// Global message storage
typedef struct {
    char message[BUFFER_SIZE];
    int valid;
} stored_message_t;

stored_message_t message_buffer[MAX_MESSAGES];
int message_count = 0;
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to store a message
void store_message(const char* msg) {
    pthread_mutex_lock(&message_mutex);
    if (message_count < MAX_MESSAGES) {
        strncpy(message_buffer[message_count].message, msg, BUFFER_SIZE - 1);
        message_buffer[message_count].message[BUFFER_SIZE - 1] = '\0';
        message_buffer[message_count].valid = 1;
        message_count++;
    }
    pthread_mutex_unlock(&message_mutex);
}

// Function to get stored messages
int get_stored_messages(char messages[][BUFFER_SIZE], int max_count) {
    pthread_mutex_lock(&message_mutex);
    int count = (message_count < max_count) ? message_count : max_count;
    for (int i = 0; i < count; i++) {
        if (message_buffer[i].valid) {
            strcpy(messages[i], message_buffer[i].message);
        }
    }
    pthread_mutex_unlock(&message_mutex);
    return count;
}

// Function to receive messages from server (chat mode)
void* receive_messages(void* arg) {
    int client_socket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Store the message
        store_message(buffer);
        
        printf("\n%s\n", buffer);
        printf("> ");
        fflush(stdout);
    }
    
    return NULL;
}

// Function to handle basic client mode (simple send/receive)
void basic_client_mode(int client_socket) {
    char buffer[BUFFER_SIZE];
    char *test_messages[] = {
        "Hello, Server!",
        "How are you?",
        "Goodbye!"
    };
    int num_messages = sizeof(test_messages) / sizeof(test_messages[0]);
    
    printf("Connected to basic server at 127.0.0.1:%d\n", PORT);
    
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
    
    printf("Basic client finished\n");
}

// Function to handle chat client mode (interactive)
void chat_client_mode(int client_socket) {
    char buffer[BUFFER_SIZE];
    pthread_t receive_thread;
    
    printf("Connected to chat server!\n");
    printf("Commands: /nick <name>, /list, /quit\n");
    printf("Type your messages below:\n\n");
    
    // Create thread to receive messages
    if (pthread_create(&receive_thread, NULL, receive_messages, &client_socket) != 0) {
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
            if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                printf("Failed to send message\n");
                running = 0;
                break;
            }
        }
        
        printf("> ");
    }
    
    // Cleanup
    running = 0;
    shutdown(client_socket, SHUT_RDWR);
    pthread_join(receive_thread, NULL);
    printf("Disconnected from chat server\n");
}

int main(int argc, char *argv[]) {
    int client_socket;
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
            printf("  basic: Simple echo client (default)\n");
            printf("  chat:  Interactive chat client\n");
            return 1;
        }
    }
    
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
    printf("Connecting to %s server...\n", mode == 1 ? "chat" : "basic");
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed\n");
        close(client_socket);
        return 1;
    }
    
    // Run in appropriate mode
    if (mode == 0) {
        basic_client_mode(client_socket);
    } else {
        chat_client_mode(client_socket);
    }
    
    // Cleanup
    close(client_socket);
    pthread_mutex_destroy(&message_mutex);
    return 0;
} 