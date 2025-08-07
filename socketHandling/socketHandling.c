#include "socketHandling.h"
// Global socket state tracking
socket_info_t *socket_info_map = NULL;
pthread_mutex_t socket_info_map_mutex = PTHREAD_MUTEX_INITIALIZER;
// Global variables with proper mutex protection
client_t *clients_map = NULL; // Hashmap root
int client_count = 0;
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// Account ID to socket mapping
account_socket_t *account_socket_map = NULL;
pthread_mutex_t account_socket_map_mutex = PTHREAD_MUTEX_INITIALIZER;

int check_and_handle_lockout(unsigned int account_id, int client_socket) {
    // First check persistent lockout state
    int remaining_time = check_persistent_lockout(account_id);
    char log_message[BUFFER_SIZE];

    if (remaining_time > 0) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), 
                 "%s Account is locked for %d more seconds due to failed authentication attempts.\n"
                 "This lockout persists across connections. Please try again later.\n", 
                 AUTH_LOCKED, remaining_time);
        send(client_socket, response, strlen(response), 0);
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Account %d attempted connection while locked (%d sec remaining)\n", 
                 account_id, account_id, remaining_time);
        FILE_LOG(log_message);
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
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Account %d attempted connection while locked (%d sec remaining)\n", 
                     account_id, account_id, auth_remaining);
            FILE_LOG(log_message);
            return 1; // Account is locked
        } else {
            // Session lockout expired, send unlock message
            char response[BUFFER_SIZE];
            snprintf(response, sizeof(response), 
                     "%s Account lockout has expired. You may now login.\n", 
                     AUTH_STATUS_UNLOCKED);
            send(client_socket, response, strlen(response), 0);
            FILE_LOG(response);
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_SYSTEM][ID:%d] Account %d lockout expired\n", 
                     account_id, account_id);
            FILE_LOG(log_message);
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
    
    pthread_mutex_lock(&socket_info_map_mutex);
    HASH_ADD_INT(socket_info_map, socket, info);
    pthread_mutex_unlock(&socket_info_map_mutex);
}

// Socket management functions
socket_info_t* get_socket_info(int socket) {
    socket_info_t *info = NULL;
    HASH_FIND_INT(socket_info_map, &socket, info);
    return info;
}


// Function to find client by socket 
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

// Function to get client status by account ID
char* get_client_status_by_account_id(unsigned int account_id) {
    char *json = malloc(1024);
    if (!json) return strdup("{\"error\": \"Memory allocation failed\"}");
    
    // Find user
    user_t *user = find_user(account_id);
    if (!user) {
        snprintf(json, 1024, "{\"error\": \"User not found\", \"account_id\": %d}", account_id);
        return json;
    }
    
    // O(1) lookup: Find socket by account_id
    int socket = find_socket_by_account_id(account_id);
    
    if (socket != -1) {
        // User has an active socket - check if fully authenticated
        client_t *client = find_client_by_socket(socket);
        
        if (client && client->active) {
            // Client is fully authenticated and connected
            snprintf(json, 1024, 
                    "{\"account_id\": %d, \"username\": \"%s\", \"status\": \"connected\", "
                    "\"nickname\": \"%s\", \"socket\": %d, \"auth_level\": %d, "
                    "\"mode\": \"%s\", \"connect_time\": %ld}",
                    account_id, user->username, client->nickname, client->socket, 
                    client->authLevel, 
                    (client->mode == CLIENT_MODE_CHAT) ? "chat" : "file",
                    client->connect_time);
            return json;
        } else {
            // Socket exists but not in clients_map - still in authentication phase
            socket_info_t *socket_info = get_socket_info(socket);
            if (socket_info) {
                const char *state_str;
                switch (socket_info->state) {
                    case SOCKET_STATE_NEW:
                        state_str = "new_connection";
                        break;
                    case SOCKET_STATE_AUTHENTICATING:
                        state_str = "authenticating";
                        break;
                    case SOCKET_STATE_AUTHENTICATED:
                        state_str = "authenticated";
                        break;
                    default:
                        state_str = "unknown";
                        break;
                }
                
                snprintf(json, 1024, 
                        "{\"account_id\": %d, \"username\": \"%s\", \"status\": \"%s\", "
                        "\"socket\": %d, \"auth_level\": %d, \"last_activity\": %ld}",
                        account_id, user->username, state_str, socket_info->socket, 
                        user->authLevel, socket_info->last_activity);
                return json;
            }
        }
    }
    
    // Client is not connected at all
    snprintf(json, 1024, 
            "{\"account_id\": %d, \"username\": \"%s\", \"status\": \"disconnected\", "
            "\"auth_level\": %d}",
            account_id, user->username, user->authLevel);
    
    return json;
}

// Function to get client status by username
char* get_client_status_by_username(const char *username) {
    // Find user by username to get account_id
    username_t *username_entry = NULL;
    HASH_FIND_STR(username_map, username, username_entry);

    
    
    if (!username_entry) {
        char *json = malloc(1024);
        if (!json) return strdup("{\"error\": \"Memory allocation failed\"}");
        snprintf(json, 1024, "{\"error\": \"User not found\", \"username\": \"%s\"}", username);
        return json;
    }
    
    // Use the existing account_id function
    return get_client_status_by_account_id(username_entry->account_id);
}




void remove_socket_info(int socket) {
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_info_map_mutex);
    HASH_FIND_INT(socket_info_map, &socket, info);
    if (info) {
        HASH_DEL(socket_info_map, info);
        free(info);
    }
    pthread_mutex_unlock(&socket_info_map_mutex);
}



int find_socket_by_account_id(unsigned int account_id) {
    account_socket_t *mapping = NULL;
    int socket = -1;
    
    pthread_mutex_lock(&account_socket_map_mutex);
    HASH_FIND_INT(account_socket_map, &account_id, mapping);
    if (mapping) {
        socket = mapping->socket;
    }
    pthread_mutex_unlock(&account_socket_map_mutex);
    
    return socket;
}
void add_account_socket_mapping(unsigned int account_id, int socket) {
    account_socket_t *mapping = malloc(sizeof(account_socket_t));
    if (!mapping) return;
    
    mapping->account_id = account_id;
    mapping->socket = socket;
    
    pthread_mutex_lock(&account_socket_map_mutex);
    HASH_ADD_INT(account_socket_map, account_id, mapping);
    pthread_mutex_unlock(&account_socket_map_mutex);
}
void remove_account_socket_mapping(unsigned int account_id) {
    account_socket_t *mapping = NULL;
    
    pthread_mutex_lock(&account_socket_map_mutex);
    HASH_FIND_INT(account_socket_map, &account_id, mapping);
    if (mapping) {
        HASH_DEL(account_socket_map, mapping);
        free(mapping);
    }
    pthread_mutex_unlock(&account_socket_map_mutex);
}