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
#include <pty.h>
#include <termios.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>




// Buffer size for file operations
#define MAX_DIRECTORIES 1000
#define MAX_COMMAND_ARGS 20
#define MAX_ARG_LENGTH 256

// Command mapping structure
typedef struct {
    char *command_name;
    int (*handler)(client_t *c, int argc, char **argv, int client_socket);
    char *description;
    int requires_path_check; // Whether this command needs access control
    char access_mode; // 'r' for read, 'w' for write, 'x' for execute
} command_mapping_t;

// Function declarations
void handle_file_mode(client_t *c, char *buffer, int client_socket);
void handle_ls_command(client_t *c, int client_socket);
void handle_cd_command(client_t *c, char *buffer, int client_socket);
void handle_touch_command(client_t *c, char *buffer, int client_socket);
void handle_rm_command(client_t *c, char *buffer, int client_socket);
void handle_rmdir_command(client_t *c, char *buffer, int client_socket);
void handle_mkdir_command(client_t *c, char *buffer, int client_socket);
void handle_cat_command(client_t *c, char *buffer, int client_socket);

// New pseudo-shell functions
void init_pseudo_shell(void);
int parse_shell_command(client_t *c, char *command_line, int client_socket);
int execute_mapped_command(client_t *c, char *command, int argc, char **argv, int client_socket);

// Mapped command handlers (with proper signatures)
int shell_ls(client_t *c, int argc, char **argv, int client_socket);
int shell_cd(client_t *c, int argc, char **argv, int client_socket);
int shell_pwd(client_t *c, int argc, char **argv, int client_socket);
int shell_cat(client_t *c, int argc, char **argv, int client_socket);
int shell_touch(client_t *c, int argc, char **argv, int client_socket);
int shell_rm(client_t *c, int argc, char **argv, int client_socket);
int shell_mkdir(client_t *c, int argc, char **argv, int client_socket);
int shell_rmdir(client_t *c, int argc, char **argv, int client_socket);
int shell_help(client_t *c, int argc, char **argv, int client_socket);
int shell_clear(client_t *c, int argc, char **argv, int client_socket);
int shell_whoami(client_t *c, int argc, char **argv, int client_socket);
int shell_history(client_t *c, int argc, int client_socket);
int shell_enhanced(client_t *c, int argc, char **argv, int client_socket);
int shell_filtered(client_t *c, int argc, char **argv, int client_socket);

// Enhanced shell functions
void init_enhanced_shell(client_t *c);
void add_command_to_history(client_t *c, const char *command);
void enable_raw_mode(client_t *c);
void disable_raw_mode(client_t *c);
void force_terminal_reset(int client_socket);
int process_raw_input(client_t *c, char *input, int length);
void handle_arrow_key(client_t *c, int key);
void handle_tab_completion(client_t *c);
void refresh_line_display(client_t *c);
char* get_previous_command(client_t *c);
char* get_next_command(client_t *c);
void reset_line_editor(client_t *c);

// Utility functions
int isAccessible(client_t *c, char *fullPath, char mode, int client_socket);
void send_response(int client_socket, const char *message);
char** parse_arguments(char *line, int *argc);
void cleanup_client_shell(client_t *c);

// Filtered shell functions
int is_command_allowed(const char *command);
int is_command_forbidden(const char *command);
int execute_filtered_command(client_t *c, const char *command, int client_socket);
char* sanitize_command(const char *input);

// PTY shell functions
int start_pty_shell(client_t *c);
void stop_pty_shell(client_t *c);
void* pty_shell_thread(void *arg);
int process_shell_input(client_t *c, const char *input, int client_socket);
int filter_command_on_enter(client_t *c, const char *command);

#endif // FILE_OPERATIONS_H 