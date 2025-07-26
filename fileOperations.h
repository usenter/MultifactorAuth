#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

#include "auth_system.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>

// Buffer size for file operations
#define BUFFER_SIZE 1024



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

// File operation function declarations
void handle_file_mode(client_t *c, char *buffer, int client_socket);

// Utility functions
int isAccessible(client_t *c, char *folderName, char mode, int client_socket);

#endif // FILE_OPERATIONS_H 