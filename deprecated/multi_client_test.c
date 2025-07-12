#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <pthread.h>
#include <time.h>


#define PORT 12345
#define BUFFER_SIZE 1024

// Structure to pass client info to thread
typedef struct {
    int client_id;
} client_thread_data_t;

// Function to handle individual client
void *client_worker(void *arg) {
    client_thread_data_t *data = (client_thread_data_t *)arg;
    int client_id = data->client_id;
    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    
    // Create socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        printf("Client %d: Socket creation failed\n", client_id);
        free(data);
        pthread_exit(NULL);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        printf("Client %d: Invalid address\n", client_id);
        close(client_socket);
        free(data);
        pthread_exit(NULL);
    }
    
    // Connect to server
    if (connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("Client %d: Connection failed\n", client_id);
        close(client_socket);
        free(data);
        pthread_exit(NULL);
    }
    
    printf("Client %d: Connected to server\n", client_id);
    
    // Send messages with client ID
    char messages[3][BUFFER_SIZE];
    snprintf(messages[0], BUFFER_SIZE, "Hello from Client %d!", client_id);
    snprintf(messages[1], BUFFER_SIZE, "Client %d is working", client_id);
    snprintf(messages[2], BUFFER_SIZE, "Goodbye from Client %d!", client_id);
    
    for (int i = 0; i < 3; i++) {
        printf("Client %d: Sending - %s\n", client_id, messages[i]);
        
        // Send message
        if (send(client_socket, messages[i], strlen(messages[i]), 0) < 0) {
            printf("Client %d: Send failed\n", client_id);
            break;
        }
        
        // Receive response
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Client %d: Received - %s\n", client_id, buffer);
        } else if (bytes_received == 0) {
            printf("Client %d: Server closed connection\n", client_id);
            break;
        } else {
            printf("Client %d: Receive failed\n", client_id);
            break;
        }
        
        // Random delay between messages
        usleep((rand() % 1500 + 500) * 1000); // 0.5 to 2.0 seconds
    }
    
    printf("Client %d: Disconnected\n", client_id);
    close(client_socket);
    free(data);
    return NULL;
}

void run_multiple_clients(int num_clients) {
    printf("Starting %d clients...\n", num_clients);
    
    // Seed random number generator
    srand(time(NULL));
    
    // Create threads for each client
    pthread_t threads[num_clients];
    client_thread_data_t *client_data[num_clients];
    
    for (int i = 0; i < num_clients; i++) {
        client_data[i] = malloc(sizeof(client_thread_data_t));
        if (client_data[i] == NULL) {
            printf("Memory allocation failed for client %d\n", i + 1);
            continue;
        }
        
        client_data[i]->client_id = i + 1;
        
        if (pthread_create(&threads[i], NULL, client_worker, (void *)client_data[i]) != 0) {
            printf("Thread creation failed for client %d\n", i + 1);
            free(client_data[i]);
            continue;
        }
        
        // Small delay between client starts
        usleep(500000); // 0.5 seconds
    }
    
    // Wait for all threads to finish
    for (int i = 0; i < num_clients; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("All clients finished!\n");
}

int main(int argc, char *argv[]) {
    int num_clients = 3; // Default number of clients
    
    // Get number of clients from command line argument
    if (argc > 1) {
        num_clients = atoi(argv[1]);
        if (num_clients <= 0) {
            printf("Invalid number of clients. Using default: 3\n");
            num_clients = 3;
        }
    }
    
    run_multiple_clients(num_clients);
    return 0;
} 