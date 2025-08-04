#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include "auth_system.h"
#include "hashmap/uthash.h"
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "fileOperations.h" // File mode operations
#include "socketHandling/socketHandling.h"


int setup_initial_connection(int client_socket);
void* handle_authenticated_client(void* arg);
#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 20
#define DEFAULT_USER_FILE "encrypted_users.txt"
#define MAX_EVENTS 100
// Program information
#define PROGRAM_NAME "AuthenticatedChatServer"
char default_cwd[256] = "UserDirectory/";
// Add a list to track client handler threads
#define MAX_CLIENT_THREADS 1024
pthread_t client_threads[MAX_CLIENT_THREADS];
int client_thread_count = 0;
int overrideBroadcast = 0; // when true, messages are broadcast to all clients, not just chat mode clients
// Socket state tracking
typedef enum {
    SOCKET_STATE_NEW,           // Just connected, needs auth
    SOCKET_STATE_AUTHENTICATING,// In authentication process
    SOCKET_STATE_AUTHENTICATED  // Fully authenticated
} socket_state_t;

typedef struct {
    int socket;
    socket_state_t state;
    time_t last_activity;
    int account_id;            // Set after successful auth
    UT_hash_handle hh;        // For hash table
} socket_info_t;

// Global socket state tracking
socket_info_t *socket_map = NULL;
pthread_mutex_t socket_map_mutex = PTHREAD_MUTEX_INITIALIZER;

// Thread communication
typedef struct {
    int epoll_fd;            // epoll fd for this thread
    pthread_t thread_id;
    volatile int running;
} thread_context_t;

thread_context_t auth_thread_ctx;
thread_context_t cmd_thread_ctx;

// Global variables with proper mutex protection
client_t *clients_map = NULL; // Hashmap root
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t thread_count_mutex = PTHREAD_MUTEX_INITIALIZER; // NEW: protect thread array
volatile int server_running = 1;
char* user_file = DEFAULT_USER_FILE;
char* emailPassword = NULL; // Fill this in if you disable useJSON parameter in emailTest.c
// Socket management functions
socket_info_t* get_socket_info(int socket) {
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_map_mutex);
    HASH_FIND_INT(socket_map, &socket, info);
    pthread_mutex_unlock(&socket_map_mutex);
    return info;
}

int check_and_handle_lockout(int account_id, int client_socket) {
    // First check persistent lockout state
    int remaining_time = check_persistent_lockout(account_id);
    
    if (remaining_time > 0) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), 
                 "%s[PERSISTENT] Account is locked for %d more seconds due to failed authentication attempts.\n"
                 "This lockout persists across connections. Please wait before trying again.\n", 
                 AUTH_LOCKED, remaining_time);
        send(client_socket, response, strlen(response), 0);
        
        printf("[LOCKOUT] Account %d attempted connection while locked (%d sec remaining)\n", 
               account_id, remaining_time);
        return 1; // Account is locked
    }
    
    // Also check the existing auth system lockout
    if (get_auth_status(account_id) & AUTH_STATUS_LOCKED) {
        int auth_remaining = get_remaining_lockout_time(account_id);
        if (auth_remaining > 0) {
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), 
                     "%s[SESSION] Account is locked for %d more seconds.\n", 
                     AUTH_LOCKED, auth_remaining);
            send(client_socket, response, strlen(response), 0);
            return 1; // Account is locked
        } else {
            // Session lockout expired, send unlock message
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), 
                     "%s Account lockout has expired. You may now login.\n", 
                     AUTH_STATUS_UNLOCKED);
            send(client_socket, response, strlen(response), 0);
            return 0; // Account is now unlocked
        }
    }
    
    return 0; // Account is not locked
}
void add_socket_info(int socket) {
    socket_info_t *info = malloc(sizeof(socket_info_t));
    if (!info) return;
    
    info->socket = socket;
    info->state = SOCKET_STATE_NEW;
    info->last_activity = time(NULL);
    info->account_id = -1;
    
    pthread_mutex_lock(&socket_map_mutex);
    HASH_ADD_INT(socket_map, socket, info);
    pthread_mutex_unlock(&socket_map_mutex);
}
// Function to find client by socket - IMPROVED
client_t* find_client_by_socket(int client_socket) {
    client_t *c = NULL;
    pthread_mutex_lock(&clients_mutex);
    HASH_FIND_INT(clients_map, &client_socket, c);
    // Only return active clients to prevent accessing freed memory
    if (c && !c->active) {
        c = NULL;
    }
    pthread_mutex_unlock(&clients_mutex);
    return c;
}
void remove_socket_info(int socket) {
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_map_mutex);
    HASH_FIND_INT(socket_map, &socket, info);
    if (info) {
        HASH_DEL(socket_map, info);
        free(info);
    }
    pthread_mutex_unlock(&socket_map_mutex);
}

void broadcast_message(const char* message, int sender_socket) {
    if (!message) return;
    
    char* message_with_newline = malloc(strlen(message) + 2);
    if (!message_with_newline) {
        printf("Failed to allocate memory for broadcast message\n");
        return;
    }
    memset(message_with_newline, 0, strlen(message) + 2);
    
    strncpy(message_with_newline, message, strlen(message));
    strncat(message_with_newline, "\n", 1);
    
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if ((c->active && c->socket != sender_socket) && 
            (c->mode == CLIENT_MODE_CHAT || overrideBroadcast)) {
            
            // Send with error checking but don't hold mutex during send
            int client_socket = c->socket;
            pthread_mutex_unlock(&clients_mutex);
            
            if (send(client_socket, message_with_newline, strlen(message_with_newline), 0) < 0) {
                char log_message[BUFFER_SIZE];
                snprintf(log_message, sizeof(log_message), "[WARN][MAIN_THREAD] Failed to send to socket %d\n", client_socket);
                FILE_LOG(log_message);
                client_t *c = find_client_by_socket(client_socket);
                if(c){
                    c->active = 0;
                }
            }
            
            pthread_mutex_lock(&clients_mutex);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    free(message_with_newline);
}
void remove_client(int client_socket) {
    printf("[CLEANUP] Starting cleanup for socket %d\n", client_socket);
    
    pthread_mutex_lock(&clients_mutex);
    
    client_t *c = NULL;
    HASH_FIND_INT(clients_map, &client_socket, c);
    if (!c) {
        pthread_mutex_unlock(&clients_mutex);
        printf("[CLEANUP] No client found for socket %d\n", client_socket);
        return; // Client not found
    }
    
    // Mark as inactive first to prevent further operations
    c->active = 0;
    
    // Copy necessary data for logging and broadcasting
    char username_copy[MAX_USERNAME_LEN];
    char nickname_copy[32];
    unsigned int account_id = c->account_id;
    
    strncpy(username_copy, c->username, sizeof(username_copy) - 1);
    username_copy[sizeof(username_copy) - 1] = '\0';
    strncpy(nickname_copy, c->nickname, sizeof(nickname_copy) - 1);
    nickname_copy[sizeof(nickname_copy) - 1] = '\0';
    
    printf("[CLEANUP] User '%s' (%s) left the chat (Total clients: %d)\n", 
           username_copy, nickname_copy, client_count - 1);
    
    // Remove from hash table
    pthread_mutex_lock(&clients_mutex);
    HASH_DEL(clients_map, c);
    client_count--;
    pthread_mutex_unlock(&clients_mutex);
    
    // Remove from socket tracking
    remove_socket_info(client_socket);
    
    // Remove from epoll (both auth and command threads)
    epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
    epoll_ctl(cmd_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
    
    // Close socket outside of mutex
    close(client_socket);
    
    // Broadcast departure message
    char departure_msg[BUFFER_SIZE];
    snprintf(departure_msg, sizeof(departure_msg), 
             "%s has left the chat", nickname_copy);
    
    overrideBroadcast = 1;
    broadcast_message(departure_msg, client_socket);
    overrideBroadcast = 0;
    
    // Remove session BEFORE freeing the client structure
    if (account_id != 0) {
        printf("[CLEANUP] Removing session for account_id %d\n", account_id);
        remove_session(account_id);
    }
    
    // Free the client structure AFTER removing session
    free(c);
    printf("[CLEANUP] Cleanup complete for socket %d\n", client_socket);
}

void update_socket_state(int socket, socket_state_t new_state) {
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_map_mutex);
    HASH_FIND_INT(socket_map, &socket, info);
    if (info) {
        printf("[SOCKET_STATE] Socket %d: %d -> %d\n", socket, info->state, new_state);
        info->state = new_state;
        info->last_activity = time(NULL);
    }
    pthread_mutex_unlock(&socket_map_mutex);
}

// Debug function to dump all socket states
/*void dump_socket_states(void) {
    printf("[SOCKET_DUMP] Current socket states:\n");
    pthread_mutex_lock(&socket_map_mutex);
    socket_info_t *info, *tmp;
    HASH_ITER(hh, socket_map, info, tmp) {
        const char* state_str = (info->state == SOCKET_STATE_NEW) ? "NEW" :
                               (info->state == SOCKET_STATE_AUTHENTICATING) ? "AUTHENTICATING" :
                               (info->state == SOCKET_STATE_AUTHENTICATED) ? "AUTHENTICATED" : "UNKNOWN";
        printf("[SOCKET_DUMP]   Socket %d: state=%s, account_id=%d, last_activity=%ld\n", 
               info->socket, state_str, info->account_id, info->last_activity);
    }
    pthread_mutex_unlock(&socket_map_mutex);
}*/
// Function to find client by nickname - IMPROVED
client_t* find_client_by_nickname(const char* nickname) {
    client_t *c, *tmp, *result = NULL;
    
    pthread_mutex_lock(&clients_mutex);
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active && strcmp(c->nickname, nickname) == 0) {
            result = c;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return result;
}


// Function to remove a client - COMPLETELY REWRITTEN for thread safety

// Function to get list of connected clients - FIXED
void get_client_list(char* list_buffer, size_t buffer_size) {
    pthread_mutex_lock(&clients_mutex);
    
    snprintf(list_buffer, buffer_size, "Connected users (%d): ", client_count);
    int first = 1;
    client_t *c, *tmp;
    
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            if (!first) {
                strncat(list_buffer, ", ", buffer_size - strlen(list_buffer) - 1);
            }
            strncat(list_buffer, c->nickname, buffer_size - strlen(list_buffer) - 1);
            first = 0;
        }
    }
    strncat(list_buffer, "\n", buffer_size - strlen(list_buffer) - 1);
    
    pthread_mutex_unlock(&clients_mutex);
}


// Move socket from auth thread to command thread
void promote_to_authenticated(int socket, int account_id) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Starting promotion for socket %d\n", account_id, socket);
    FILE_LOG(log_message);
    
    // Create client structure
    client_t *new_client = malloc(sizeof(client_t));
    if (!new_client) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE-ID:%d] Failed to allocate client structure\n", account_id);
        FILE_LOG(log_message);
        return;
    }
    
    // Initialize client
    memset(new_client, 0, sizeof(client_t));
    new_client->socket = socket;
    new_client->account_id = account_id;
    new_client->active = 1;
    new_client->mode = CLIENT_MODE_CHAT;
    strncpy(new_client->cwd, default_cwd, sizeof(new_client->cwd) - 1);
    new_client->cwd[sizeof(new_client->cwd) - 1] = '\0';
    
    // Get user info for the client
    user_t *user = find_user(account_id);
    if (user) {
        strncpy(new_client->username, user->username, MAX_USERNAME_LEN - 1);
        strncpy(new_client->nickname, user->username, sizeof(new_client->nickname) - 1);
    }
    
    // Add to clients map
    pthread_mutex_lock(&clients_mutex);
    HASH_ADD_INT(clients_map, socket, new_client);
    client_count++;
    pthread_mutex_unlock(&clients_mutex);
    
    // Remove from auth epoll
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Removing socket %d from auth epoll\n", account_id, socket);
    FILE_LOG(log_message);
    if (epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_DEL, socket, NULL) == -1) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE-ID:%d] Failed to remove from auth epoll\n", account_id);
        FILE_LOG(log_message);
    }
    
    // Update socket state
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_map_mutex);
    HASH_FIND_INT(socket_map, &socket, info);
    if (info) {
        info->state = SOCKET_STATE_AUTHENTICATED;
        info->account_id = account_id;
        info->last_activity = time(NULL);
        snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Updated socket %d state to AUTHENTICATED\n", account_id, socket);
        FILE_LOG(log_message);
    }
    pthread_mutex_unlock(&socket_map_mutex);
    
    // Add to command thread epoll
    struct epoll_event event;
    event.events = EPOLLIN | EPOLLET;
    event.data.fd = socket;
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Adding socket %d to command thread epoll\n", account_id, socket);
    FILE_LOG(log_message);
    if (epoll_ctl(cmd_thread_ctx.epoll_fd, EPOLL_CTL_ADD, socket, &event) == -1) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE-ID:%d] Failed to add to command thread epoll\n", account_id);
        FILE_LOG(log_message);
        remove_client(socket);
        return;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Successfully added socket %d to command thread epoll\n", account_id, socket);
    FILE_LOG(log_message);
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "AUTH_SUCCESS:You are now fully authenticated.\n");
    send(socket, response, strlen(response), 0);
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE-ID:%d] Socket %d is fully authenticated\n", account_id, socket);
    FILE_LOG(log_message);
    // Announce new user
    char announcement[BUFFER_SIZE];
    snprintf(announcement, sizeof(announcement), "%s has joined the chat", new_client->nickname);
    broadcast_message(announcement, socket);

}


// Chat mode handler - IMPROVED with better error checking
void handle_chat_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    // Handle nickname change
    if (strncmp(buffer, "/nick ", 6) == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Handling /nick command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        char new_nick[32];
        memset(new_nick, 0, sizeof(new_nick));
        strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
        new_nick[sizeof(new_nick) - 1] = '\0';
        new_nick[strcspn(new_nick, "\r\n ")] = 0;

        if (strlen(new_nick) == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Invalid nickname. Usage: /nick <name>\n");
            ssize_t n_sent= send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            if(n_sent < 0){
                printf("Failed to send message to client %d\n", client_socket);
                if(errno == EPIPE){
                    printf("Client %d disconnected\n", client_socket);
                    remove_client(client_socket);
                }
                else{printf("Failed to send message to client %d\n", client_socket);}
            }
            return;
        }
        
        if (find_client_by_nickname(new_nick)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Nickname '%s' is already taken. Choose a different one.\n", new_nick);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        
        // Update nickname with proper synchronization
        pthread_mutex_lock(&clients_mutex);
        client_t *client = NULL;
        HASH_FIND_INT(clients_map, &client_socket, client);
        if (client && client->active) {
            char old_nick[32];
            strncpy(old_nick, client->nickname, sizeof(old_nick) - 1);
            old_nick[sizeof(old_nick) - 1] = '\0';
            
            strncpy(client->nickname, new_nick, sizeof(client->nickname) - 1);
            client->nickname[sizeof(client->nickname) - 1] = '\0';
            
            pthread_mutex_unlock(&clients_mutex);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Nickname changed to '%s'\n", new_nick);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s is now known as %s", old_nick, new_nick);
            broadcast_message(broadcast_msg, client_socket);
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Nickname changed to '%s' for socket %d\n", c->account_id, new_nick, client_socket);
            FILE_LOG(log_message);
        } else {
            pthread_mutex_unlock(&clients_mutex);
        }
        return;
    }
    
    // Handle list command
    if (strcmp(buffer, "/list") == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Handling /list command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        get_client_list(broadcast_msg, sizeof(broadcast_msg));
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Handle help command
    if (strcmp(buffer, "/help") == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Handling /help command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        snprintf(broadcast_msg, sizeof(broadcast_msg),
                 "Chat Commands:\n"
                 "  /nick <name> - Change your nickname\n"
                 "  /list - Show connected users\n"
                 "  /help - Show this help\n"
                 "  /file - Enter file mode\n"
                 "  /quit - Kill the overall program\n"
                 "Just type any message to chat with everyone!\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Handle file commands
    if (strncmp(buffer, "/file", 5) == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Handling /file command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        
        pthread_mutex_lock(&clients_mutex);
        // Use the client pointer that was already passed to this function
        if (c && c->active) {
            c->mode = CLIENT_MODE_FILE;
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Client %d mode changed to FILE\n", c->account_id, client_socket);
            FILE_LOG(log_message);
        } else {
            snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD-ID:%d] Client not found or inactive for socket %d\n", c->account_id, client_socket);
            FILE_LOG(log_message);
        }
        pthread_mutex_unlock(&clients_mutex);
        
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] File mode activated for socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File mode activated\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    
    // Handle unknown commands
    if (buffer[0] == '/') {
        snprintf(broadcast_msg, sizeof(broadcast_msg), 
                 "Unknown command. Type /help for available commands.\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Regular chat message - broadcast to everyone
    if (strlen(buffer) > 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), 
                 "%s: %s", c->nickname, buffer);
        broadcast_message(broadcast_msg, client_socket);
        
        // Log the message
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] CHAT [%s] %s: %s\n", c->account_id, c->username, c->nickname, buffer);
        FILE_LOG(log_message);
        return;
    }
}
}

// Authentication thread function
void* auth_thread_func(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    FILE_LOG("[INFO][AUTH_THREAD] Authentication thread started\n");
    
    while (ctx->running) {
        int nfds = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, 100);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD] epoll_wait in auth thread: %s\n", strerror(errno));
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds > 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] epoll_wait returned %d events\n",  nfds);
            FILE_LOG(log_message);
        }
        
        // Debug: dump socket states every few seconds when no events
        static time_t last_dump = 0;
        if (nfds == 0) {
            time_t now = time(NULL);
            if (now - last_dump > 5) {
                //dump_socket_states();
                last_dump = now;
            }
        }
        
        for (int i = 0; i < nfds; i++) {
            int client_socket = events[i].data.fd;
            socket_info_t *info = get_socket_info(client_socket);
            if (!info) continue;
            
            ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_read <= 0) {
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD-ID:%d] Socket %d disconnected (bytes_read=%zd)\n", info->account_id, client_socket, bytes_read);
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                close(client_socket);
                continue;
            }
            
            buffer[bytes_read] = '\0';
            buffer[strcspn(buffer, "\r\n")] = 0;
            
            // Process authentication messages
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Socket %d: received %zd bytes, state=%d, account_id=%d\n", 
                   info->account_id, client_socket, bytes_read, info->state, info->account_id);
            FILE_LOG(log_message);
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Socket %d: raw data: '%s'\n", 
                   info->account_id, client_socket, buffer);
            FILE_LOG(log_message);
            char response[BUFFER_SIZE];
            
            // Skip processing if this is a new connection (shouldn't happen anymore, but safety check)
            if (info->state == SOCKET_STATE_NEW) {
                snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD-ID:%d] WARNING: Socket %d in NEW state in epoll - should not occur\n", info->account_id, client_socket);
                FILE_LOG(log_message);
                continue;
            }
            
            // We need to determine account_id for process_auth_message
            // For initial auth, we might not have it yet, so we'll handle this step by step
            int account_id = info->account_id;
            
            // If we don't have account_id yet, try to extract from login command
            if (account_id <= 0 && strncmp(buffer, "/login", 6) == 0) {
                char username[MAX_USERNAME_LEN];
                if (sscanf(buffer, "/login %31s", username) == 1) {
                    username_t *uname_entry = find_username(username);
                    if (uname_entry) {
                        account_id = uname_entry->account_id;
                        // Update socket info with account_id
                        if (info) {
                            info->account_id = account_id;
                        }
                        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Set account_id %d for socket %d\n", info->account_id, account_id, client_socket);
                        FILE_LOG(log_message);
                    }
                }
            }
            
            int result = 0;
            if (account_id > 0) {
                // Check for lockout before processing any auth attempt
                if (check_and_handle_lockout(account_id, client_socket)) {
                    continue; // Skip processing if locked
                }
                if(strcmp(buffer, "/time") == 0){
                    check_and_handle_lockout(account_id, client_socket);
                    continue; 
                }
                result = process_auth_message(buffer, account_id, response, sizeof(response));
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] process_auth_message returned: %d\n", info->account_id, result);
                FILE_LOG(log_message);
            } 
            else {
                snprintf(response, sizeof(response), "Please use /login <username> <password> to authenticate\n");
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD-ID:NA] No account_id available for socket %d, sending login prompt\n", client_socket);
                FILE_LOG(log_message);
            }
            
            if (result == 1) { // Message processed successfully
                // Check if user is actually fully authenticated
                auth_flags_t auth_status = get_auth_status(account_id);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Socket %d: auth_status=%d\n", 
                       info->account_id, client_socket, auth_status);
                FILE_LOG(log_message);
                
                if (auth_status == AUTH_FULLY_AUTHENTICATED) {
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Authentication COMPLETE for socket %d, promoting to chat...\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                    promote_to_authenticated(client_socket, account_id);
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Promotion complete for socket %d\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                } else {
                    
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Authentication INCOMPLETE for socket %d, sending response\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                    send(client_socket, response, strlen(response), 0);
                }
            } 
            else {
                snprintf(log_message, 
                    sizeof(log_message), 
                    "[ERROR][AUTH_THREAD:%d] Message processing failed, sending response to socket %d: '%s'\n", 
                    account_id, client_socket, response);
                FILE_LOG(log_message);
                send(client_socket, response, strlen(response), 0);
            }
        }
    }
    
    printf("Authentication thread exiting\n");
    return NULL;
}

// Command handling thread function
void* cmd_thread_func(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    struct epoll_event events[MAX_EVENTS];
    char buffer[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];

    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] Command handler thread started\n");
    FILE_LOG(log_message);
    
    while (ctx->running) {
        int nfds = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, 100);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD] epoll_wait in cmd thread: %s\n", strerror(errno));
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds > 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] epoll_wait returned %d events\n", nfds);
            FILE_LOG(log_message);
        }
        
        for (int i = 0; i < nfds; i++) {
            int client_socket = events[i].data.fd;
            socket_info_t *info = get_socket_info(client_socket);
            printf("[CMD_THREAD] Processing event for socket %d, info=%p, state=%d\n", 
                   client_socket, info, info ? info->state : -1);
            if (!info || info->state != SOCKET_STATE_AUTHENTICATED) {
                printf("[CMD_THREAD] Skipping socket %d (no info or wrong state)\n", client_socket);
                continue;
            }
            
            ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_read <= 0) {
                snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD-ID:%d] Socket %d disconnected (bytes_read=%zd)\n", info->account_id, client_socket, bytes_read);
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                close(client_socket);
                continue;
            }
            
            buffer[bytes_read] = '\0';
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Socket %d: received %zd bytes, state=%d\n", 
                   info->account_id, client_socket, bytes_read, info->state);
            FILE_LOG(log_message);
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD-ID:%d] Socket %d: raw data: '%s'\n", 
                   info->account_id, client_socket, buffer);
            FILE_LOG(log_message);
            buffer[strcspn(buffer, "\r\n")] = 0;
            
            // Handle commands and messages using client mode
            printf("[CMD_THREAD] Processing message from socket %d: '%s'\n", client_socket, buffer);
            client_t *client = find_client_by_socket(client_socket);
            if (client) {
                printf("[CMD_THREAD] Found client for socket %d, mode=%d\n", client_socket, client->mode);
                
                // Skip empty messages
                if (strlen(buffer) == 0) {
                    continue;
                }
                
                // Handle quit command (universal quit command)
                if (strcmp(buffer, "/quit") == 0) {
                    char response[BUFFER_SIZE];
                    snprintf(response, sizeof(response), "Goodbye! You have left the chat.\n");
                    send(client_socket, response, strlen(response), 0);
                    remove_client(client_socket);
                    continue;
                }
                
                // Dispatch based on client mode
                if (client->mode == CLIENT_MODE_CHAT) {
                    printf("[CMD_THREAD] Processing CHAT mode for user %s\n", client->username);
                    handle_chat_mode(client, buffer, client_socket);
                } else if (client->mode == CLIENT_MODE_FILE) {
                    printf("[CMD_THREAD] Processing FILE mode for user %s\n", client->username);
                    handle_file_mode(client, buffer, client_socket);
                } else {
                    printf("[CMD_THREAD] Unknown client mode %d for socket %d\n", client->mode, client_socket);
                }
            } else {
                printf("[CMD_THREAD] ERROR: No client found for socket %d - this shouldn't happen for authenticated users\n", client_socket);
                // Try to find the client in the hash table for debugging
                pthread_mutex_lock(&clients_mutex);
                client_t *c, *tmp;
                HASH_ITER(hh, clients_map, c, tmp) {
                    printf("[CMD_THREAD] DEBUG: Client in map - socket=%d, active=%d, username=%s\n", 
                           c->socket, c->active, c->username);
                }
                pthread_mutex_unlock(&clients_mutex);
            }
        }
    }
    
    printf("Command handler thread exiting\n");
    return NULL;
}









// Make server_socket global for signal handler access
int server_socket = -1;
pthread_mutex_t server_socket_mutex = PTHREAD_MUTEX_INITIALIZER; // NEW: protect server socket

// Removed unused work queue functions and thread functions

// Signal handler for graceful shutdown
void signal_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server shutdown requested...\n");
    FILE_LOG(log_message);
    server_running = 0;
    
    // Close server socket to unblock accept() - with proper synchronization
    pthread_mutex_lock(&server_socket_mutex);
    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
    pthread_mutex_unlock(&server_socket_mutex);
}

// Function to add a new authenticated client - FIXED
void add_authenticated_client(client_t *new_client) {
    char log_message[BUFFER_SIZE];
    printf("[ADD_CLIENT] Adding authenticated client for user '%s' (socket %d)\n", 
           new_client->username, new_client->socket);
    
    pthread_mutex_lock(&clients_mutex);
    
    // Check if client already exists by socket (prevent duplicates)
    client_t *existing = NULL;
    HASH_FIND_INT(clients_map, &new_client->socket, existing);
    if (existing) {
        pthread_mutex_unlock(&clients_mutex);
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD-ID:%d] Warning: Client socket %d already exists in map\n", new_client->account_id, new_client->socket);
        FILE_LOG(log_message);
        return;
    }
    
    // Check for existing client with same username and remove it
    client_t *duplicate = NULL, *tmp = NULL;
    HASH_ITER(hh, clients_map, duplicate, tmp) {
        if (duplicate->active && strcmp(duplicate->username, new_client->username) == 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Removing existing client for user '%s' (socket %d)\n", 
                   duplicate->account_id, duplicate->username, duplicate->socket);
            FILE_LOG(log_message);
            HASH_DEL(clients_map, duplicate);
            client_count--;
            close(duplicate->socket);
            free(duplicate);
            break;
        }
    }
    
    HASH_ADD_INT(clients_map, socket, new_client);
    client_count++;
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Successfully added client for user '%s' (socket %d). Total clients: %d\n", 
           new_client->account_id, new_client->username, new_client->socket, client_count);
    FILE_LOG(log_message);
    
    pthread_mutex_unlock(&clients_mutex);
}





// Function to broadcast message to all authenticated clients except sender - FIXED



// Function to handle individual authenticated client - IMPROVED
void* handle_authenticated_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg); // Free the allocated memory for the socket
    
    char buffer[BUFFER_SIZE];
    client_t *c = find_client_by_socket(client_socket);
    char broadcast_msg[BUFFER_SIZE];
    
    if (!c) {
        printf("Error: No client found for socket %d in authenticated handler\n", client_socket);
        close(client_socket);
        return NULL;
    }
    
    // Send welcome message and instructions
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Welcome to %s!\n"
             "Commands:\n"
             "  /nick <name> - Change your nickname\n"
             "  /list - Show connected users\n"
             "  /help - Show this help\n"
             "  /quit - Leave the chat\n"
             "  /file - Enter file mode\n"
             "Type your messages to chat with everyone!\n\n", 
             PROGRAM_NAME);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    // Announce new user to everyone
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "%s joined the chat", c->nickname);
    broadcast_message(broadcast_msg, client_socket);
    
    // Main message handling loop
    while (server_running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            client_t *c = find_client_by_socket(client_socket);
            printf("Client %s disconnected\n", c ? c->nickname : "(unknown)");
            break;
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0; // Remove newlines
        
        // Skip empty messages
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Re-check if session is still valid
        c = find_client_by_socket(client_socket);
        if (!c || !c->active) {
            printf("Client %d not valid or inactive\n", client_socket);
            break;
        }
        
        if (!is_authenticated(c->account_id)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Session expired. Please reconnect and authenticate again.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Handle quit command (universal quit command)
        if (strcmp(buffer, "/quit") == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Goodbye! You have left the chat.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Dispatch based on mode - check client is still valid
        if (c->mode == CLIENT_MODE_CHAT) {
            handle_chat_mode(c, buffer, client_socket);
        } else if (c->mode == CLIENT_MODE_FILE) {
            handle_file_mode(c, buffer, client_socket);
        }
    }
    
    // Clean up session and remove client
    
    remove_client(client_socket);
    
    return NULL;
}



// Extract client certificate - IMPROVED error handling
X509* extract_client_cert(int client_socket) {
    uint32_t net_cert_len;
    char log_message[BUFFER_SIZE];
    client_t *c = find_client_by_socket(client_socket);
    // Read certificate length with retry logic
    unsigned long total_read = 0;
    while (total_read < sizeof(net_cert_len)) {
        int recvd = recv(client_socket, ((char*)&net_cert_len) + total_read, 
                        sizeof(net_cert_len) - total_read, 0);
        if (recvd <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec delay = {0, 100000000}; 
                nanosleep(&delay, NULL);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Failed to receive certificate length from client.\n", c->account_id);
            FILE_LOG(log_message);
            return NULL;
        }
        total_read += recvd;
    }
    
    uint32_t cert_len = ntohl(net_cert_len);
    if (cert_len == 0 || cert_len > 8192) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Invalid certificate length received: %u\n", c->account_id, cert_len);
        FILE_LOG(log_message);
        return NULL;
    }
    
    char* cert_buf = malloc(cert_len + 1);
    if (!cert_buf) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Memory allocation failed for certificate buffer.\n", c->account_id);
        FILE_LOG(log_message);
        return NULL;
    }
    
    // Read certificate data with retry logic
    total_read = 0;
    while (total_read < (unsigned long)cert_len) {
        int recvd = recv(client_socket, cert_buf + total_read, 
                        cert_len - total_read, 0);
        if (recvd <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct timespec delay = {0, 100000000}; 
                nanosleep(&delay, NULL);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Failed to receive certificate data from client.\n", c->account_id);
            FILE_LOG(log_message);
            free(cert_buf);
            return NULL;
        }
        total_read += recvd;
    }
    
    cert_buf[cert_len] = '\0';
    BIO* cert_bio = BIO_new_mem_buf(cert_buf, cert_len);
    X509* client_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    BIO_free(cert_bio);
    free(cert_buf);
    
    if (!client_cert) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Failed to parse client certificate.\n", c->account_id);
        FILE_LOG(log_message);
        return NULL;
    }
    return client_cert;
}

// implemennts initial connection setup for epoll architecture
int setup_initial_connection(int client_socket) {
    char log_message[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Setting up initial connection for %s:%d\n", 
           inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    FILE_LOG(log_message);

    // Temporarily set socket to blocking
    int flags = fcntl(client_socket, F_GETFL, 0);
    fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);

    // Extract certificate
    X509* client_cert = extract_client_cert(client_socket);

    // Restore non-blocking mode after certificate extraction
    fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

    if (!client_cert) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Client certificate extraction failed. Closing connection.\n");
        FILE_LOG(log_message);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    
    EVP_PKEY* client_pubkey = X509_get_pubkey(client_cert);
    if (!client_pubkey) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Failed to extract public key from client certificate.\n");
        FILE_LOG(log_message);
        X509_free(client_cert);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    
    // Print subject CN 
    X509_NAME* subj = X509_get_subject_name(client_cert);
    char cn[256];
    X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Received client certificate. Subject CN: %s\n", cn);
    FILE_LOG(log_message);

    // Receive username
    char username_buffer[BUFFER_SIZE];
    int name_bytes = recv(client_socket, username_buffer, BUFFER_SIZE - 1, 0);
    char username[MAX_USERNAME_LEN] = "";
    unsigned int account_id = 0;
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Socket %d: received %d bytes for username\n", client_socket, name_bytes);
    FILE_LOG(log_message);
    
    if (name_bytes <= 0) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Socket %d: client disconnected before sending username\n", client_socket);
        FILE_LOG(log_message);
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    
    username_buffer[name_bytes] = '\0';
    username_buffer[strcspn(username_buffer, "\r\n")] = 0;
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Socket %d: username data: '%s'\n", client_socket, username_buffer);
    FILE_LOG(log_message);

    if (strncmp(username_buffer, "USERNAME:", 9) == 0) {
        strncpy(username, username_buffer + 9, MAX_USERNAME_LEN - 1);
        username[MAX_USERNAME_LEN - 1] = '\0';
        
        username_t *uname_entry = find_username(username);
        if (!uname_entry) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Invalid username received: %s\n", username);
            FILE_LOG(log_message);
            snprintf(response, sizeof(response), "ERROR: Invalid username\n");
            send(client_socket, response, strlen(response), 0);
            
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        
        account_id = uname_entry->account_id;
        user_t *user = find_user(account_id);
        if (!user) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Invalid account_id received: %u\n", account_id);
            FILE_LOG(log_message);
            snprintf(response, sizeof(response), "[ERROR][AUTH_THREAD] Invalid account_id\n");
            send(client_socket, response, strlen(response), 0);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        if(get_auth_status(account_id) & AUTH_STATUS_LOCKED){
            if(get_remaining_lockout_time(account_id) > 0){
            snprintf(response, sizeof(response), "%s Account is locked for %d more seconds due to too many failed attempts.\n", 
                AUTH_LOCKED, get_remaining_lockout_time(account_id));
            send(client_socket, response, strlen(response), 0);
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Account is locked for %d more seconds due to too many failed attempts.\n", get_remaining_lockout_time(account_id));
            FILE_LOG(log_message);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
            }
            else if(get_remaining_lockout_time(account_id) <= 0){
                session_t *session = find_session(account_id);
                if(session){
                    session->auth_status = AUTH_NONE;
                }
                snprintf(response, sizeof(response), "%s Account is unlocked. Please login with: /login <username> <password>\n", 
                AUTH_STATUS_UNLOCKED);
                send(client_socket, response, strlen(response), 0);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Account is unlocked.\n", account_id);
                FILE_LOG(log_message);
            }
        }
        
        user->public_key = client_pubkey;
        client_pubkey = NULL; // Ownership transferred
        
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Valid username received: %s \n", account_id, username);
        FILE_LOG(log_message);
        
        // Create authentication session (chamber)
        if (!create_auth_session(account_id)) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Failed to create authentication session for %s\n", account_id, username);
            FILE_LOG(log_message);

            snprintf(response, sizeof(response), "ERROR: Failed to create session\n");
            send(client_socket, response, strlen(response), 0);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        
        // Update socket info with account_id
        socket_info_t *info = get_socket_info(client_socket);
        if (info) {
            pthread_mutex_lock(&socket_map_mutex);
            info->account_id = account_id;
            pthread_mutex_unlock(&socket_map_mutex);
        }
        else{
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Failed to get socket info for %s\n", account_id, username);
            FILE_LOG(log_message);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        if(check_and_handle_lockout(account_id, client_socket)){
            return -1;
        }
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Authentication chamber created for %s\n", account_id, username);
        FILE_LOG(log_message);
        
        // Generate RSA challenge
        if (is_rsa_system_initialized()) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Initiating automatic RSA challenge for %s\n", account_id, username);
            FILE_LOG(log_message);
            rsa_challenge_result_t rsa_result = start_rsa_challenge_for_client(account_id, user->public_key);
            
            if (rsa_result.success && rsa_result.encrypted_size > 0) {
                char hex_output[RSA_HEX_BUFFER_SIZE];
                snprintf(hex_output, sizeof(hex_output), "RSA_CHALLENGE:");
                char *hex_ptr = hex_output + strlen(hex_output);
                for (int i = 0; i < rsa_result.encrypted_size; i++) {
                    sprintf(hex_ptr + (i * 2), "%02x", rsa_result.encrypted_challenge[i]);
                }
                strcat(hex_output, "\n");
                send(client_socket, hex_output, strlen(hex_output), 0);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] RSA challenge sent to %s\n", account_id, username);
                FILE_LOG(log_message);
            } else {
                snprintf(log_message,sizeof(log_message),"[CRITICAL][AUTH_THREAD-ID:%d] Failed to generate/send RSA challenge for %s\n", account_id, username);
                FILE_LOG(log_message);
                EVP_PKEY_free(client_pubkey);
                X509_free(client_cert);
                remove_socket_info(client_socket);
                close(client_socket);
                return -1;
            }
        }
        
        // Send authentication prompt
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Sending authentication prompt to %s\n", account_id, username);
        FILE_LOG(log_message);
        snprintf(response, sizeof(response),
                 "%s - Authentication Required\n"
                 "========================================\n"
                 "Please authenticate to access the chat:\n"
                 "  /login <username> <password> - Login with existing account\n", PROGRAM_NAME);
                 // will be implemented later
                 //"  /register <username> <password> - Create new account\n\n", PROGRAM_NAME);
        send(client_socket, response, strlen(response), 0);
        
    } 
    else {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD-ID:%d] Invalid username format received\n", account_id);
        FILE_LOG(log_message);
        snprintf(response, sizeof(response), "ERROR: Invalid username format\n");
        send(client_socket, response, strlen(response), 0);
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    if (account_id > 0) {
        if (check_and_handle_lockout(account_id, client_socket)) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD-ID:%d] Connection rejected for account %u - locked out\n", account_id, account_id);
            FILE_LOG(log_message);
            EVP_PKEY_free(client_pubkey);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1; // Reject connection entirely
        }
    }
    if (client_pubkey) {
        EVP_PKEY_free(client_pubkey);
    }
    X509_free(client_cert);
    
    snprintf(log_message, sizeof(log_message),"[INFO][AUTH_THREAD-ID:%d] Initial connection setup completed for %s \n", account_id, username);
    FILE_LOG(log_message);
    return 0; // Success
}


// Function to broadcast shutdown message to all authenticated clients - IMPROVED
void broadcast_shutdown_message(void) {
    char shutdown_msg[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Broadcasting shutdown message to all authenticated clients\n");
    FILE_LOG(log_message);
    snprintf(shutdown_msg, sizeof(shutdown_msg), 
             "Server is shutting down. Goodbye!\n");
    
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            // Send without holding mutex to prevent deadlock
            int client_socket = c->socket;
            pthread_mutex_unlock(&clients_mutex);
            send(client_socket, shutdown_msg, strlen(shutdown_msg), 0);
            pthread_mutex_lock(&clients_mutex);
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Shutdown message broadcasted to all authenticated clients\n");
    FILE_LOG(log_message);
}

// Print usage information
void print_usage(const char *program_name) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Printing usage information\n");
    FILE_LOG(log_message);
    printf("%s - Secure Authenticated Chat Server\n", PROGRAM_NAME);
    printf("Requires encrypted user database to start\n\n");
    
    printf("USAGE:\n");
    printf("  %s <database_password>\n", program_name);
    printf("  %s --help\n", program_name);
    printf("  %s --version\n", program_name);
    
    printf("\nDESCRIPTION:\n");
    printf("  Starts a secure chat server that requires user authentication.\n");
    printf("  All clients must authenticate before accessing the chat.\n");
    printf("  Uses encrypted user database file: %s\n", DEFAULT_USER_FILE);
    
    printf("\nEXAMPLE:\n");
    printf("  %s myDatabasePassword\n", program_name);
    
    printf("\nSETUP:\n");
    printf("  1. Create a users.txt file with format: username:password_hash\n");
    printf("  2. Encrypt it: ./user_encryptor encrypt users.txt %s <password>\n", DEFAULT_USER_FILE);
    printf("  3. Start server: %s <password>\n", program_name);
    printf("  4. Clients connect and authenticate to join chat\n");
    
    printf("\nFEATURES:\n");
    printf("  - Mandatory user authentication\n");
    printf("  - Encrypted user database\n");
    printf("  - Multi-client chat with nicknames\n");
    printf("  - Session management and timeout\n");
    printf("  - Graceful shutdown with Ctrl+C\n");
}

// Print version information
void print_version(void) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Printing version information\n");
    FILE_LOG(log_message);
    printf("%s\n", PROGRAM_NAME);
    printf("Secure authenticated chat server with encrypted user database\n");
    FILE_LOG(log_message);
    printf("Built with OpenSSL encryption and POSIX threads\n");
    FILE_LOG(log_message);
}

// Cleanup function for graceful shutdown - COMPLETELY REWRITTEN
void cleanup_server(void) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Cleaning up server resources...\n");
    FILE_LOG(log_message);
    broadcast_shutdown_message();
    
    // Wait for clients to receive the shutdown message
    struct timespec delay = {0, 100000000}; 
    nanosleep(&delay, NULL);
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Closing all client sockets...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            close(c->socket); 
            c->active = 0;    
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Stopping worker threads...\n");
    FILE_LOG(log_message);
    auth_thread_ctx.running = 0;
    cmd_thread_ctx.running = 0;
    
    // Wait for threads to finish
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Waiting for auth thread...\n");
    FILE_LOG(log_message);
    pthread_join(auth_thread_ctx.thread_id, NULL);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Waiting for command thread...\n");
    FILE_LOG(log_message);
    pthread_join(cmd_thread_ctx.thread_id, NULL);
    
    // Close epoll fds
    close(auth_thread_ctx.epoll_fd);
    close(cmd_thread_ctx.epoll_fd);
    
    // Clean up socket map
    socket_info_t *current, *temp_socket;
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Cleaning up socket map...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&socket_map_mutex);
    HASH_ITER(hh, socket_map, current, temp_socket) {
        HASH_DEL(socket_map, current);
        close(current->socket);
        free(current);
    }
    pthread_mutex_unlock(&socket_map_mutex);
    
    // Now safely free all remaining clients
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Freeing remaining client map...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&clients_mutex);
    client_t *current_client, *temp_client;
    HASH_ITER(hh, clients_map, current_client, temp_client) {
        HASH_DEL(clients_map, current_client);
        free(current_client);
    }
    client_count = 0;
    pthread_mutex_unlock(&clients_mutex);
    
    // Destroy mutexes
    pthread_mutex_destroy(&clients_mutex);
    pthread_mutex_destroy(&thread_count_mutex);
    pthread_mutex_destroy(&server_socket_mutex);
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server cleanup complete\n");
    FILE_LOG(log_message);
}

int main(int argc, char *argv[]) {
    char log_message[BUFFER_SIZE];

    // Handle special arguments
    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            print_version();
            return 0;
        }
    }
    
    // Validate arguments
    if (argc != 2) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Database password was not entered\n\n");
        FILE_LOG(log_message);
        printf("DATABASE PASSWORD REQUIRED\n\n");
        print_usage(argv[0]);
        return 1;
    }

    signal(SIGPIPE, SIG_IGN);
    
    const char* database_password = argv[1];
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Starting %s by reading user base at %s\n", PROGRAM_NAME, user_file);
    FILE_LOG(log_message);

    
    // Initialize authentication system with encrypted database
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Decrypting user database...\n");
    FILE_LOG(log_message);
    if(!init_encrypted_auth_system(user_file, (char*)database_password)){
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to initialize authentication system\n");
        FILE_LOG(log_message);
        return 1;
    }
    printf("User Database succesfully loaded!\n");
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] User database loaded successfully!\n");
    FILE_LOG(log_message);
    
    // Initialize RSA authentication system
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Initializing RSA authentication...\n");
    if (!init_rsa_system("RSAkeys/server_private.pem", "RSAkeys/server_public.pem")) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Server RSA keys not found!\n");
        FILE_LOG(log_message);
        printf("ERROR: RSA authentication keys not found!\n");
        printf("This server requires RSA two-factor authentication.\n");
        printf("  1. Run: ./generate_rsa_keys server\n");
        printf("\nServer CANNOT start without this step.\n");
        return 1;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] RSA two-factor authentication enabled!\n");
    FILE_LOG(log_message);
    if(!init_email_system("userStatus.txt")){
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to initialize email system\n");
        FILE_LOG(log_message);
        return 1;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Email system initialized!\n");
    FILE_LOG(log_message);

    // Removed unused work queue initialization and thread creation

    // Set up signal handlers for graceful shutdown
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create server socket
    pthread_mutex_lock(&server_socket_mutex);
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        pthread_mutex_unlock(&server_socket_mutex);
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Socket creation failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] setsockopt failed\n");
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Bind failed on port %d\n", PORT);
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Listen failed\n");
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    pthread_mutex_unlock(&server_socket_mutex);
    
    printf("Server listening on port %d\n", PORT);
    printf("Maximum clients: %d\n", MAX_CLIENTS);
    printf("Server ready! Press Ctrl+C to exit\n");
    printf("========================================================================\n");
    
    // Set up epoll for main thread (accepting connections)
    int main_epoll_fd = epoll_create1(0);
    if (main_epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (main) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set up epoll for auth thread
    auth_thread_ctx.epoll_fd = epoll_create1(0);
    if (auth_thread_ctx.epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (auth) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set up epoll for command thread
    cmd_thread_ctx.epoll_fd = epoll_create1(0);
    if (cmd_thread_ctx.epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (cmd) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Add server socket to main epoll
    struct epoll_event server_event;
    server_event.events = EPOLLIN;
    server_event.data.ptr = NULL; // Server socket marker
    epoll_ctl(main_epoll_fd, EPOLL_CTL_ADD, server_socket, &server_event);
    
    // Start worker threads
    auth_thread_ctx.running = 1;
    cmd_thread_ctx.running = 1;
    
    if (pthread_create(&auth_thread_ctx.thread_id, NULL, auth_thread_func, &auth_thread_ctx) != 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to create auth thread\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    if (pthread_create(&cmd_thread_ctx.thread_id, NULL, cmd_thread_func, &cmd_thread_ctx) != 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to create command thread\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Main accept loop
    struct epoll_event events[MAX_EVENTS];
    while (server_running) {
        int nfds = epoll_wait(main_epoll_fd, events, MAX_EVENTS, 100);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_wait (main) failed\n");
            FILE_LOG(log_message);
            break;
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.ptr == NULL) {
                // New connection
                struct sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                
                int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
                if (client_socket < 0) {
                    if (server_running) {
                        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] accept failed\n");
                        FILE_LOG(log_message);
                    }
                    continue;
                }
                
                snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] New connection from %s:%d (socket=%d)\n", 
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_socket);
                FILE_LOG(log_message);
                // Set non-blocking
                int flags = fcntl(client_socket, F_GETFL, 0);
                fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
                
                // Initialize socket tracking
                add_socket_info(client_socket);
                
                // Set initial state
                socket_info_t *info = get_socket_info(client_socket);
                if (info) {
                    info->state = SOCKET_STATE_NEW;
                    info->last_activity = time(NULL);
                    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: initialized with state=NEW\n", client_socket);
                    FILE_LOG(log_message);
                    printf("[MAIN_EPOLL] Socket %d: initialized with state=NEW\n", client_socket);
                }
                
                // Handle initial connection setup BEFORE adding to epoll (certificate extraction, RSA challenge)
                snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: starting initial setup\n", client_socket);
                FILE_LOG(log_message);
                printf("[MAIN_EPOLL] Socket %d: starting initial setup\n", client_socket);
                
                int setup_result = setup_initial_connection(client_socket);
                if(setup_result != 0){
                    remove_client(client_socket);
                    close(client_socket);
                    continue;
                }
                if (setup_result == 0) {
                    // Setup successful, update socket state and add to epoll
                    socket_info_t *updated_info = get_socket_info(client_socket);
                    if (updated_info) {
                        updated_info->state = SOCKET_STATE_AUTHENTICATING;
                        printf("[MAIN_EPOLL] Socket %d: setup successful, state=AUTHENTICATING\n", client_socket);
                    }
                    
                    // Add to auth thread's epoll AFTER setup is complete
                    struct epoll_event client_event;
                    client_event.events = EPOLLIN | EPOLLET;
                    client_event.data.fd = client_socket;
                    if (epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_ADD, client_socket, &client_event) == -1) {
                        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_ctl (auth) failed\n");
                        FILE_LOG(log_message);
                        remove_socket_info(client_socket);
                        close(client_socket);
                        continue;
                    }
                    
                    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: added to auth thread epoll\n", client_socket);
                    FILE_LOG(log_message);
                    printf("[MAIN_EPOLL] Socket %d: added to auth thread epoll\n", client_socket);
                }
                else {
                    // Setup failed, socket is already cleaned up
                    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: intial setup failed\n", client_socket);
                    FILE_LOG(log_message);
                    continue;
                }
            }
        }
    }
    
    // Cleanup
    close(main_epoll_fd);
    
    // Cleanup and shutdown
    pthread_mutex_lock(&server_socket_mutex);
    if (server_socket != -1) {
        close(server_socket);
        server_socket = -1;
    }
    pthread_mutex_unlock(&server_socket_mutex);
    cleanup_server();
    
    // Add a small delay to ensure all threads have completely finished
    // before cleaning up the auth system to prevent deadlock
    struct timespec delay = {0, 500000000}; // 500ms in nanoseconds
    nanosleep(&delay, NULL);
    
    cleanup_auth_system(); // Clean up authentication system hashmaps
    OPENSSL_cleanup();
    pthread_mutex_destroy(&clients_mutex);
    pthread_mutex_destroy(&thread_count_mutex);
    pthread_mutex_destroy(&server_socket_mutex);
    printf("Server Cleanup Succesful!\n");
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] %s shutdown complete\n", PROGRAM_NAME);
    FILE_LOG(log_message);
    return 0;
}    