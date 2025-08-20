#ifndef FILE_OPERATIONS_H
#define FILE_OPERATIONS_H

#include "../socketHandling_tools/socketHandlingOperations.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>


// Buffer size for file operations
#define MAX_DIRECTORIES 1000


// File operation function declarations
void handle_file_mode(client_t *c, char *buffer, int client_socket);
void handle_ls_command(client_t *c, int client_socket);
void handle_cd_command(client_t *c, char *buffer, int client_socket);
void handle_touch_command(client_t *c, char *buffer, int client_socket);
void handle_rm_command(client_t *c, char *buffer, int client_socket);
void handle_rmdir_command(client_t *c, char *buffer, int client_socket);
void handle_mkdir_command(client_t *c, char *buffer, int client_socket);
void handle_cat_command(client_t *c, char *buffer, int client_socket);
// Utility functions
int isAccessible(client_t *c, char *fullPath, char mode, int client_socket);

#endif // FILE_OPERATIONS_H 