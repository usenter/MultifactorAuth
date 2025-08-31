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

#define MAX_HISTORY_SIZE 100
#define MAX_LINE_LENGTH 1024

// Command history entry
typedef struct {
    char command[MAX_LINE_LENGTH];
    time_t timestamp;
} history_entry_t;

// Line editor state
typedef struct {
    char line[MAX_LINE_LENGTH];        // Current line being edited
    int cursor_pos;                    // Cursor position in line
    int line_length;                   // Current length of line
    int history_index;                 // Current position in history (-1 = current line)
    char saved_line[MAX_LINE_LENGTH];  // Saved line when browsing history
} line_editor_t;

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

    // Enhanced shell features
    history_entry_t command_history[MAX_HISTORY_SIZE];
    int history_count;                 // Number of commands in history
    int history_position;              // Current position for new commands
    line_editor_t line_editor;         // Line editing state
    int raw_mode;                      // Whether client is in raw mode
    
    // PTY shell for real shell interaction
    int pty_master_fd;                 // Master PTY file descriptor
    pid_t shell_pid;                   // Shell process ID
    pthread_t shell_thread;            // Thread handling shell I/O
    int shell_active;                  // Whether shell is running
    char command_buffer[1024];         // Buffer for command filtering
    int command_buffer_pos;            // Position in command buffer

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
