#include "../hashmap/uthash.h"
#include "../auth_system.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>





// Client mode enumeration
typedef enum {
    CLIENT_MODE_CHAT,
    CLIENT_MODE_FILE
} client_mode_t;

// Complete client structure definition
typedef struct client {
    int socket;
    struct sockaddr_in addr;
    char nickname[32];
    char username[MAX_USERNAME_LEN];
    unsigned int account_id;
    int authLevel;
    int active;
    time_t connect_time;
    client_mode_t mode;
    char cwd[256]; // Current working directory for file mode
    UT_hash_handle hh; // For uthash
} client_t;



typedef enum {
    SOCKET_STATE_NEW,           // Just connected, needs auth
    SOCKET_STATE_AUTHENTICATING,// In authentication process
    SOCKET_STATE_AUTHENTICATED  // Fully authenticated
} socket_state_t;

typedef struct {
    int socket;
    socket_state_t state;
    time_t last_activity;
    unsigned int account_id;            // Set after successful auth
    UT_hash_handle hh;        // For hash table
} socket_info_t;

// Account ID to socket mapping structure
typedef struct {
    unsigned int account_id;
    int socket;
    UT_hash_handle hh;        // For hash table
} account_socket_t;

// Global variables
extern client_t* clients_map;
extern int client_count;
extern pthread_mutex_t clients_mutex;
extern socket_info_t* socket_info_map;
extern pthread_mutex_t socket_info_map_mutex;

// Account ID to socket mapping
extern account_socket_t* account_socket_map;
extern pthread_mutex_t account_socket_map_mutex;

int check_and_handle_lockout(unsigned int account_id, int client_socket);
void add_socket_info(int socket);
client_t* find_client_by_socket(int client_socket);
void remove_socket_info(int socket);
int find_socket_by_account_id(unsigned int account_id);
void add_account_socket_mapping(unsigned int account_id, int socket);
void remove_account_socket_mapping(unsigned int account_id);
socket_info_t* get_socket_info(int socket);


char* get_client_status_by_account_id(unsigned int account_id);
char* get_client_status_by_username(const char *username);

// Signal handler for broken pipes
void sigpipe_handler(int sig);
