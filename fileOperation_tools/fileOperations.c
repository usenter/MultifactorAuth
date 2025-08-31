#include "fileOperations.h"
#include <sys/stat.h>


const char *auths[numAuths] = {
    "user", "admin", "superadmin", "business", "finance",
    "marketing", "sales", "engineering", "hr", "superAdmin"
};

// Whitelist of allowed shell commands with their descriptions
static const char* allowed_commands[] = {
    "ls", "ll", "la", "dir",                    // Directory listing
    "cd", "pwd",                                // Directory navigation
    "cat", "less", "more", "head", "tail",      // File viewing
    "grep", "find", "locate", "which", "whereis", // Search
    "file", "stat", "wc", "du", "df",           // File info
    "touch", "mkdir", "cp", "mv",               // Safe file operations
    "rm", "rmdir",                              // Deletion (with restrictions)
    "echo", "printf",                           // Output
    "date", "whoami", "id", "uptime",           // System info
    "ps", "top", "htop",                        // Process info (read-only)
    "clear", "reset",                           // Terminal control
    "history",                                  // Command history
    "tree",                                     // Directory tree
    "nano", "vim", "vi", "emacs",              // Editors (restricted)
    NULL // Sentinel
};

// Completely forbidden commands (security risks)
static const char* forbidden_commands[] = {
    "su", "sudo", "passwd", "chown", "chmod",   // Permission changes
    "mount", "umount", "fdisk", "mkfs",         // Filesystem operations
    "iptables", "netstat", "ss", "lsof",        // Network tools
    "kill", "killall", "pkill",                 // Process control
    "crontab", "at", "batch",                   // Job scheduling
    "wget", "curl", "ftp", "ssh", "scp",        // Network transfers
    "gcc", "make", "python", "perl", "bash",    // Compilers/interpreters
    "systemctl", "service", "chkconfig",        // Service control
    "useradd", "userdel", "usermod", "groupadd", // User management
    "reboot", "shutdown", "halt", "poweroff",   // System control
    NULL // Sentinel
};

// Global command mapping table (kept for backward compatibility)
static command_mapping_t command_map[] = {
    {"help", shell_help, "Show help information", 0, ' '},
    {"shell", shell_filtered, "Enable filtered real shell", 0, ' '},
    {"enhanced", shell_filtered, "Enable filtered real shell (alias)", 0, ' '},
    {NULL, NULL, NULL, 0, ' '} // Sentinel
};

static int command_map_initialized = 0;


void handle_file_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    printf("[DEBUG] File mode command received: %s\n", buffer);

    // Initialize pseudo-shell if not already done
    init_pseudo_shell();

    // Handle special mode-switching commands
    if(strncmp(buffer, "/chat", 5) == 0){
        // Always disable raw mode when switching modes
        if (c->raw_mode) {
            disable_raw_mode(c);
        }
        c->mode = CLIENT_MODE_CHAT;
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File mode ended, returning to chat mode\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    if(strncmp(buffer, "/quit", 5) == 0){
        if (c->raw_mode) {
            disable_raw_mode(c);
        }
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Shutting down server...\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        exit(0);
    }

    // Block chat mode commands in file mode
    if(strncmp(buffer, "/list", 5) == 0 || strncmp(buffer, "/nick", 5) == 0){
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Chat mode commands are not available in file mode\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }

    // Check if client is in PTY shell mode
    if (c->raw_mode && c->shell_active) {
        // Process input through PTY shell
        process_shell_input(c, buffer, client_socket);
    } else if (c->raw_mode) {
        // Raw mode but no shell - fallback to old behavior
        printf("[DEBUG] Raw mode without active shell, falling back\n");
        parse_shell_command(c, buffer, client_socket);
    } else {
        // Normal line-buffered mode
        parse_shell_command(c, buffer, client_socket);
    }
}



void handle_ls_command(client_t *c,  int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    printf("User %s is trying to list directory %s\n", c->username, c->cwd);
    
    // Extract the relative path from UserDirectory/ onwards
    char *relative_path = c->cwd;
    
    
    printf("Checking permissions for %s\n", relative_path);
    if(!isAccessible(c, relative_path, 'r', client_socket)){
        printf("User %s does not have permission to read directory %s\n", c->username, c->cwd);
        return;
    }
    DIR *dir = opendir(c->cwd);
    if (!dir) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Could not open directory: %s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    struct dirent *entry;
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Contents of %s:\n", c->cwd);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue; // skip hidden files
        snprintf(broadcast_msg, sizeof(broadcast_msg), "%s\n", entry->d_name);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    }
    closedir(dir);
    return;
    }

void handle_cd_command(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    char new_dir[256];
    // go up by one directory
    if(strncmp(buffer+3, "..", 2) == 0){
        //go up one directory
        char* lastSlash = strrchr(c->cwd, '/');
        if(lastSlash && lastSlash != c->cwd) {
            // Create the parent directory path by truncating at the last slash
            char parentDir[256];
            size_t parentLen = lastSlash - c->cwd;
            strncpy(parentDir, c->cwd, parentLen);
            parentDir[parentLen] = '\0';
            
            // Check if we're trying to go above UserDirectory
            if(strncmp(parentDir, "UserDirectory", 13) != 0) {
                snprintf(broadcast_msg, sizeof(broadcast_msg), "Cannot go up from root directory\n");
                send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
                return;
            }
            
            strncpy(c->cwd, parentDir, sizeof(c->cwd) - 1);
            c->cwd[sizeof(c->cwd) - 1] = '\0';
        } else {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Cannot go up from root directory\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Changed directory to %s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    // go to the root directory
    else if(strncmp(buffer+3, ".", 1) == 0){
        strncpy(c->cwd, "UserDirectory", sizeof(c->cwd) - 1);
        c->cwd[sizeof(c->cwd) - 1] = '\0';
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Changed directory to %s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    // go to the directory
    else{
        strncpy(new_dir, buffer+3, sizeof(new_dir) - 1);
    }
    // check if the directory exists
    snprintf(new_dir, sizeof(new_dir), "%s/%s", c->cwd, buffer+3);
    // Remove trailing slashes/newlines
    new_dir[strcspn(new_dir, "\r\n ")] = 0;
    DIR *dir = opendir(new_dir);
    if (!dir) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Directory does not exist: %s\n", new_dir);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    closedir(dir);
    
    // Extract the relative path from UserDirectory/ onwards
    
    
    // Check access using the relative path
    if(!isAccessible(c, new_dir, 'r', client_socket)) return;
    
    strncpy(c->cwd, new_dir, sizeof(c->cwd)-1);
    c->cwd[sizeof(c->cwd)-1] = '\0';
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Changed directory to %s\n", c->cwd);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);

}
    
void handle_touch_command(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    if(!isAccessible(c, c->cwd, 'w', client_socket)) return;
        char file_path[512];
        snprintf(file_path, sizeof(file_path), "%s/%s", c->cwd, buffer+6);
        // Remove trailing slashes/newlines
        file_path[strcspn(file_path, "\r\n ")] = 0;
        FILE *f = fopen(file_path, "w");
        if (!f) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to create file: %s\n", file_path);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        fclose(f);
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File created: %s\n", file_path);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;

}

void handle_rm_command(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
     // Check write permissions for the current directory
     if(!isAccessible(c, c->cwd, 'w', client_socket)) return;
    
     char filename[256];
     strncpy(filename, buffer + 3, sizeof(filename) - 1);
     filename[sizeof(filename) - 1] = '\0';
     // Remove trailing whitespace/newlines
     filename[strcspn(filename, "\r\n ")] = '\0';
     
     // Construct full file path
     char filepath[512];
     snprintf(filepath, sizeof(filepath), "%s/%s", c->cwd, filename);
     
     // Check if file exists and get its type
     struct stat file_stat;
     if(stat(filepath, &file_stat) != 0) {
         snprintf(broadcast_msg, sizeof(broadcast_msg), "File does not exist: %s\n", filename);
         send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
         return;
     }
     
     // Check if it's a directory
     if(S_ISDIR(file_stat.st_mode)) {
         snprintf(broadcast_msg, sizeof(broadcast_msg), "Cannot remove directory: %s (use rmdir for directories)\n", filename);
         send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
         return;
     }
     
     // Attempt to remove the file
     if(remove(filepath) == 0) {
         snprintf(broadcast_msg, sizeof(broadcast_msg), "File removed: %s\n", filename);
         send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
     } else {
         snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to remove file: %s\n", filename);
         send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
     }
}

//helper functions to remove a directory recursively
int removeRecursively(const char *dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        return -1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        
        struct stat file_stat;
        if (stat(fullpath, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                // Recursively remove subdirectory
                if (removeRecursively(fullpath) != 0) {
                    closedir(dir);
                    return -1;
                }
            } else {
                // Remove file
                if (remove(fullpath) != 0) {
                    closedir(dir);
                    return -1;
                }
            }
        }
    }
    
    closedir(dir);
    // Remove the now-empty directory
    return rmdir(dirpath);
}

int canRemoveRecursively(client_t *c, char *dirpath, int client_socket){
    DIR *dir = opendir(dirpath);
    if (!dir) {
        return 0; // Can't open directory
    }
    
    // Check if current directory is writable
    if (!isAccessible(c, dirpath, 'w', client_socket)) {
        closedir(dir);
        return 0;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        
        struct stat file_stat;
        if (stat(fullpath, &file_stat) == 0 && S_ISDIR(file_stat.st_mode)) {
            // Recursively check subdirectory
            if (!canRemoveRecursively(c, fullpath, client_socket)) {
                closedir(dir);
                return 0;
            }
        }
    }
    
    closedir(dir);
    return 1; // All directories are removable

}

void handle_rmdir_command(client_t *c, char *buffer, int client_socket){

    char broadcast_msg[BUFFER_SIZE];
    char *args = buffer + 3;
    int recursive = 0;
    char filename[256];
    
    // Check for -r flag
    if (strncmp(args, "-r ", 3) == 0) {
        if(!canRemoveRecursively(c, args + 3, client_socket)){
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Cannot remove directory: %s. Cannot remove certain files due to lack of permissions.\n", args + 3);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        recursive = 1;
        strncpy(filename, args + 3, sizeof(filename) - 1);
    }
    else{
        strncpy(filename, args, sizeof(filename) - 1);
    }
      
    filename[sizeof(filename) - 1] = '\0';
    filename[strcspn(filename, "\r\n ")] = '\0';
    
    // Construct full file path
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", c->cwd, filename);
    
    // Check if file/directory exists
    struct stat file_stat;
    if(stat(filepath, &file_stat) != 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File/directory does not exist: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    if(S_ISDIR(file_stat.st_mode)) {
        if (!recursive) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Cannot remove directory: %s (use rm -r for directories)\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        
        // Check permissions recursively before attempting removal
        if (!canRemoveRecursively(c, filepath, client_socket)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Permission denied: cannot remove directory %s or its contents\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        
        // All permissions checked, now remove recursively
        if (removeRecursively(filepath) == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Directory removed: %s\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        } else {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to remove directory: %s\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        }
    } else {
        // Regular file removal (same as before)
        if(!isAccessible(c, c->cwd, 'w', client_socket)) return;
        
        if(remove(filepath) == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "File removed: %s\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        } else {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to remove file: %s\n", filename);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        }
    }
    
}

void handle_mkdir_command(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    if(!isAccessible(c, c->cwd, 'w', client_socket)) return;
    char dirname[256];
    strncpy(dirname, buffer + 6, sizeof(dirname) - 1);
    dirname[sizeof(dirname) - 1] = '\0';
    dirname[strcspn(dirname, "\r\n ")] = '\0';
    if(mkdir(dirname, 0755) == 0){
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Directory created: %s\n", dirname);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    }
    else{
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to create directory: %s\n", dirname);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    }
}
void handle_cat_command(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    char *args = buffer + 4;
    char filename[256];
    strncpy(filename, args, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';
    filename[strcspn(filename, "\r\n ")] = '\0';  // Remove whitespace
    
    // Check read permissions for current directory
    if(!isAccessible(c, c->cwd, 'r', client_socket)) return;
    
    // Construct full file path
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", c->cwd, filename);
    
    struct stat file_stat;
    
    // Get file metadata
    if (stat(filepath, &file_stat) == -1) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File not found: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Check if it's a regular file
    if (!S_ISREG(file_stat.st_mode)) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Not a regular file: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    FILE* file = fopen(filepath, "r");
    if (!file) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to open file: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    char *tempStore = malloc(file_stat.st_size + 1);  // +1 for null terminator
    if(!tempStore){
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to allocate memory for file: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        fclose(file);
        return;
    }
    
    size_t bytes_read = fread(tempStore, 1, file_stat.st_size, file);
    fclose(file);
    
    if (bytes_read != (size_t)file_stat.st_size) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to read complete file: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        free(tempStore);
        return;
    }
    
    tempStore[file_stat.st_size] = '\0';  // Null terminate for text files
    
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Contents of %s:\n", filename);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    send(client_socket, tempStore, file_stat.st_size, 0);
    
    free(tempStore);
    return;
}
// Check if user has access to a folder/file
int isAccessible(client_t *c, char *fullPath, char mode, int client_socket) {
    char broadcast_msg[BUFFER_SIZE];
    char readPermLevel[numAuths+1];
    char writePermLevel[numAuths+1];
    
    char filePath[1024];
    char folderName[1024];
    
    // Extract relative path from full path
    char *relative_path = fullPath;
    if (strncmp(fullPath, "UserDirectory/", 14) == 0) {
        relative_path = fullPath + 14;  // Skip "UserDirectory/"
    } else if (strcmp(fullPath, "UserDirectory") == 0) {
        relative_path = ".";  // For root directory
    }
    
    strncpy(folderName, relative_path, 1024);
    folderName[strcspn(folderName, "/")] = 0;
    
    snprintf(filePath, 1024, "UserDirectory/%s/.perms", relative_path);
    FILE* permsFile = fopen(filePath, "r");
    if(permsFile == NULL){
        printf("Permissions file not found for %s\n", relative_path);
        return 0;
    }


    // Read the file line by line to handle variable spacing
    char line[256];
    int read_found = 0, write_found = 0;
    
    while (fgets(line, sizeof(line), permsFile) && (!read_found || !write_found)) {
        if (strncmp(line, "read:", 5) == 0) {
            char *perm_start = line + 5;
            while (*perm_start == ' ' || *perm_start == '\t') perm_start++;
            strncpy(readPermLevel, perm_start, numAuths);
            readPermLevel[numAuths] = '\0';
            read_found = 1;
        } else if (strncmp(line, "write:", 6) == 0) {
            char *perm_start = line + 6;
            while (*perm_start == ' ' || *perm_start == '\t') perm_start++;
            strncpy(writePermLevel, perm_start, numAuths);
            writePermLevel[numAuths] = '\0';
            write_found = 1;
        }
    }
    
    fclose(permsFile);
    
    
    if (mode == 'r') {
        char relevantBit = readPermLevel[c->authLevel];
        if (relevantBit == '1') {
            return 1;
        } else {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "You do not have permission to read this file/access this directory\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return 0;
        }
    } else if (mode == 'w') {
        char relevantBit = writePermLevel[c->authLevel];
        if (relevantBit == '1') {
            return 1;
        } else {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "You do not have permission to write to this file/directory\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return 0;
        }
    }
    return 0;
}

// ================= NEW PSEUDO-SHELL FUNCTIONS =================

void init_pseudo_shell(void) {
    if (command_map_initialized) return;

    // Initialize command map (if needed for future dynamic loading)
    command_map_initialized = 1;
    printf("[INFO] Pseudo-shell command mapping initialized\n");
}

void send_response(int client_socket, const char *message) {
    send(client_socket, message, strlen(message), 0);
}

char** parse_arguments(char *line, int *argc) {
    char **argv = malloc(MAX_COMMAND_ARGS * sizeof(char*));
    if (!argv) return NULL;

    *argc = 0;
    char *token = strtok(line, " \t\n\r");

    while (token && *argc < MAX_COMMAND_ARGS - 1) {
        argv[(*argc)++] = strdup(token);
        token = strtok(NULL, " \t\n\r");
    }
    argv[*argc] = NULL;

    return argv;
}

void free_arguments(char **argv, int argc) {
    if (!argv) return;
    for (int i = 0; i < argc; i++) {
        if (argv[i]) free(argv[i]);
    }
    free(argv);
}

void cleanup_client_shell(client_t *c) {
    if (!c) return;
    
    // Stop PTY shell if active
    if (c->shell_active) {
        printf("[INFO] Cleaning up PTY shell for disconnecting user %s\n", c->username);
        stop_pty_shell(c);
    }
    
    // If client is in shell mode, properly disable it
    if (c->raw_mode) {
        c->raw_mode = 0;
    }
    
    // Reset line editor state (for backward compatibility)
    reset_line_editor(c);
    
    printf("[INFO] Shell cleanup completed for user %s\n", c->username);
}

int parse_shell_command(client_t *c, char *command_line, int client_socket) {
    if (!command_line || strlen(command_line) == 0) {
        send_response(client_socket, "\n");
        return 1;
    }

    // Skip leading whitespace
    while (*command_line && (*command_line == ' ' || *command_line == '\t')) {
        command_line++;
    }

    if (!*command_line) {
        send_response(client_socket, "\n");
        return 1;
    }

    // Check for enhanced shell exit command
    if (strcmp(command_line, "exit") == 0) {
        if (c->raw_mode) {
            disable_raw_mode(c);
            send_response(client_socket, "Exited enhanced shell. Type 'enhanced' to re-enable.\n");
            return 1;
        } else {
            send_response(client_socket, "Not in enhanced shell mode. Use /chat to return to chat mode or /quit to exit.\n");
            return 1;
        }
    }

    // Parse command and arguments
    int argc;
    char **argv = parse_arguments(command_line, &argc);

    if (!argv || argc == 0) {
        send_response(client_socket, "Error parsing command\n");
        if (argv) free_arguments(argv, argc);
        return 0;
    }

    char *command = argv[0];
    int result = execute_mapped_command(c, command, argc, argv, client_socket);

    // Add successful commands to history (skip some internal commands)
    if (result && strcmp(command, "history") != 0 && strcmp(command, "clear") != 0) {
        add_command_to_history(c, command_line);
    }

    free_arguments(argv, argc);
    return result;
}

int execute_mapped_command(client_t *c, char *command, int argc, char **argv, int client_socket) {
    // Find command in mapping table
    for (int i = 0; command_map[i].command_name != NULL; i++) {
        if (strcmp(command, command_map[i].command_name) == 0) {
            // Execute the mapped command
            return command_map[i].handler(c, argc, argv, client_socket);
        }
    }

    // Command not found
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "Unknown command: %s\nType 'help' for available commands.\n", command);
    send_response(client_socket, response);
    return 0;
}

// ================= MAPPED COMMAND HANDLERS =================

int shell_ls(client_t *c, int argc, char **argv, int client_socket) {
    handle_ls_command(c, client_socket);
    return 1;
}

int shell_cd(client_t *c, int argc, char **argv, int client_socket) {
    if (argc < 2) {
        send_response(client_socket, "cd: missing directory argument\n");
        return 0;
    }

    char cd_command[BUFFER_SIZE];
    snprintf(cd_command, sizeof(cd_command), "cd %s", argv[1]);
    handle_cd_command(c, cd_command, client_socket);
    return 1;
}

int shell_pwd(client_t *c, int argc, char **argv, int client_socket) {
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "%s\n", c->cwd);
    send_response(client_socket, response);
    return 1;
}

int shell_cat(client_t *c, int argc, char **argv, int client_socket) {
    if (argc < 2) {
        send_response(client_socket, "cat: missing file argument\n");
        return 0;
    }

    char cat_command[BUFFER_SIZE];
    snprintf(cat_command, sizeof(cat_command), "cat %s", argv[1]);
    handle_cat_command(c, cat_command, client_socket);
    return 1;
}

int shell_touch(client_t *c, int argc, char **argv, int client_socket) {
    if (argc < 2) {
        send_response(client_socket, "touch: missing file argument\n");
        return 0;
    }

    char touch_command[BUFFER_SIZE];
    snprintf(touch_command, sizeof(touch_command), "touch %s", argv[1]);
    handle_touch_command(c, touch_command, client_socket);
    return 1;
}

int shell_rm(client_t *c, int argc, char **argv, int client_socket) {
    if (argc < 2) {
        send_response(client_socket, "rm: missing file argument\n");
        return 0;
    }

    char rm_command[BUFFER_SIZE];
    snprintf(rm_command, sizeof(rm_command), "rm %s", argv[1]);
    handle_rm_command(c, rm_command, client_socket);
    return 1;
}

int shell_mkdir(client_t *c, int argc, char **argv, int client_socket) {
    if (argc < 2) {
        send_response(client_socket, "mkdir: missing directory argument\n");
        return 0;
    }

    char mkdir_command[BUFFER_SIZE];
    snprintf(mkdir_command, sizeof(mkdir_command), "mkdir %s", argv[1]);
    handle_mkdir_command(c, mkdir_command, client_socket);
    return 1;
}

int shell_rmdir(client_t *c, int argc, char **argv, int client_socket) {
    char rmdir_command[BUFFER_SIZE];

    if (argc >= 3 && strcmp(argv[1], "-r") == 0) {
        snprintf(rmdir_command, sizeof(rmdir_command), "rmdir -r %s", argv[2]);
    } else if (argc >= 2) {
        snprintf(rmdir_command, sizeof(rmdir_command), "rmdir %s", argv[1]);
    } else {
        send_response(client_socket, "rmdir: missing directory argument\n");
        return 0;
    }

    handle_rmdir_command(c, rmdir_command, client_socket);
    return 1;
}

int shell_help(client_t *c, int argc, char **argv, int client_socket) {
    char response[BUFFER_SIZE * 4];
    char *ptr = response;
    int remaining = sizeof(response);

    if (c->raw_mode) {
        // In filtered shell mode, show allowed shell commands
        ptr += snprintf(ptr, remaining, "Filtered Shell - Allowed Commands:\n\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "Directory Operations:\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  ls, ll, la, dir  - List directory contents\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  cd, pwd          - Navigate directories\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  mkdir            - Create directories\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "\nFile Operations:\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  cat, less, more, head, tail - View files\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  touch, cp, mv    - Create and move files\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  rm, rmdir        - Remove files/directories\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "\nSearch & Info:\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  grep, find, locate, which - Search\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  file, stat, wc, du, df - File information\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "\nSystem Info:\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  date, whoami, id, uptime - System information\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  ps, top          - Process information\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "\nOther:\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  echo, printf     - Output text\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  clear, reset     - Clear screen\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  tree             - Directory tree\n");
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "  exit             - Exit filtered shell\n");
        remaining = sizeof(response) - (ptr - response);
        
        ptr += snprintf(ptr, remaining, "\nNote: Commands are executed in your current directory (%s)\n", c->cwd);
        remaining = sizeof(response) - (ptr - response);
        ptr += snprintf(ptr, remaining, "Access is restricted to UserDirectory and subdirectories.\n");
        
    } else {
        // Normal file mode commands
        ptr += snprintf(ptr, remaining, "Available file mode commands:\n");
        remaining = sizeof(response) - (ptr - response);

        for (int i = 0; command_map[i].command_name != NULL && remaining > 0; i++) {
            ptr += snprintf(ptr, remaining, "  %-10s - %s\n",
                           command_map[i].command_name,
                           command_map[i].description);
            remaining = sizeof(response) - (ptr - response);
        }
    }

    ptr += snprintf(ptr, remaining, "\nYour permissions: %s\n", auths[c->authLevel]);
    send_response(client_socket, response);
    return 1;
}

int shell_clear(client_t *c, int argc, char **argv, int client_socket) {
    send_response(client_socket, "\033[2J\033[1;1H"); // ANSI clear screen and home cursor
    return 1;
}

int shell_whoami(client_t *c, int argc, char **argv, int client_socket) {
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "user: %s\nlevel: %s (%d)\n",
             c->username, auths[c->authLevel], c->authLevel);
    send_response(client_socket, response);
    return 1;
}

int shell_history(client_t *c, int argc, int client_socket) {
    char response[BUFFER_SIZE * 4];
    char *ptr = response;
    int remaining = sizeof(response);

    ptr += snprintf(ptr, remaining, "Command History:\n");
    remaining -= (ptr - response);

    if (c->history_count == 0) {
        ptr += snprintf(ptr, remaining, "No commands in history.\n");
    } else {
        for (int i = 0; i < c->history_count && remaining > 100; i++) {
            int index = (c->history_position - c->history_count + i) % MAX_HISTORY_SIZE;
            ptr += snprintf(ptr, remaining, "%d: %s\n",
                           i + 1, c->command_history[index].command);
            remaining -= (ptr - response);
        }
    }

    send_response(client_socket, response);
    return 1;
}

int shell_enhanced(client_t *c, int argc, char **argv, int client_socket) {
    // Redirect to filtered shell
    return shell_filtered(c, argc, argv, client_socket);
}

int shell_filtered(client_t *c, int argc, char **argv, int client_socket) {
    // Start PTY shell
    if (start_pty_shell(c) != 0) {
        send_response(client_socket, "Failed to start interactive shell\n");
        return 0;
    }
    
    // Enable shell mode
    c->raw_mode = 1;
    
    char welcome_msg[] = "\nInteractive shell enabled! Features:\n"
                        "  • Real shell with tab completion and command history\n"
                        "  • Security filtering for dangerous commands\n"
                        "  • Full terminal features (colors, cursor movement)\n"
                        "  • Restricted to safe commands and your user directory\n"
                        "  • Type 'exit' to return to file mode\n\n";
    send_response(client_socket, welcome_msg);
    
    return 1;
}

// ================= ENHANCED SHELL FUNCTIONS =================

void init_enhanced_shell(client_t *c) {
    // Initialize command history
    memset(c->command_history, 0, sizeof(c->command_history));
    c->history_count = 0;
    c->history_position = 0;

    // Initialize line editor
    memset(&c->line_editor, 0, sizeof(line_editor_t));
    c->line_editor.history_index = -1; // -1 means not browsing history
    c->raw_mode = 0;

    printf("[INFO] Enhanced shell initialized for user %s\n", c->username);
}

void add_command_to_history(client_t *c, const char *command) {
    if (!command || strlen(command) == 0 || strlen(command) >= MAX_LINE_LENGTH) {
        return;
    }

    // Don't add duplicate consecutive commands
    if (c->history_count > 0) {
        int last_index = (c->history_position - 1 + MAX_HISTORY_SIZE) % MAX_HISTORY_SIZE;
        if (strcmp(c->command_history[last_index].command, command) == 0) {
            return;
        }
    }

    // Add command to history
    strcpy(c->command_history[c->history_position].command, command);
    c->command_history[c->history_position].timestamp = time(NULL);

    c->history_position = (c->history_position + 1) % MAX_HISTORY_SIZE;
    if (c->history_count < MAX_HISTORY_SIZE) {
        c->history_count++;
    }
}

void enable_raw_mode(client_t *c) {
    if (c->raw_mode) return;

    // Use minimal terminal modifications to avoid permanent changes
    // Avoid alternate screen buffer which can cause issues
    const char *setup_sequences[] = {
        "\033[2J",      // Clear entire screen
        "\033[1;1H",    // Move cursor to top-left
        "\r\n"          // New line
    };

    // Send setup sequences
    for (int i = 0; i < sizeof(setup_sequences) / sizeof(setup_sequences[0]); i++) {
        send(c->socket, setup_sequences[i], strlen(setup_sequences[i]), 0);
    }

    c->raw_mode = 1;
    reset_line_editor(c);

    // Send initial prompt
    char prompt[] = "\033[32m$\033[0m ";
    send(c->socket, prompt, strlen(prompt), 0);
}

void force_terminal_reset(int client_socket) {
    // Emergency terminal reset - minimal and safe
    // Only reset basic terminal attributes to avoid mouse wheel issues
    const char *emergency_reset[] = {
        "\033[0m",      // Reset all text attributes
        "\033[2J",      // Clear entire screen
        "\033[1;1H",    // Move cursor to top-left
        "\r\n"          // New line
    };

    // Send essential reset sequences only
    for (int i = 0; i < sizeof(emergency_reset) / sizeof(emergency_reset[0]); i++) {
        send(client_socket, emergency_reset[i], strlen(emergency_reset[i]), 0);
    }
}

void disable_raw_mode(client_t *c) {
    if (!c->raw_mode) return;

    // Send minimal reset sequences to restore normal terminal behavior
    // Only reset what we actually changed
    const char *cleanup_sequences[] = {
        "\033[0m",      // Reset all text attributes
        "\r\n"          // New line
    };

    // Send essential reset sequences only
    for (int i = 0; i < sizeof(cleanup_sequences) / sizeof(cleanup_sequences[0]); i++) {
        send(c->socket, cleanup_sequences[i], strlen(cleanup_sequences[i]), 0);
    }

    c->raw_mode = 0;
    printf("[INFO] Enhanced shell disabled for user %s - terminal restored\n", c->username);
}

void reset_line_editor(client_t *c) {
    memset(c->line_editor.line, 0, MAX_LINE_LENGTH);
    c->line_editor.cursor_pos = 0;
    c->line_editor.line_length = 0;
    c->line_editor.history_index = -1;
    memset(c->line_editor.saved_line, 0, MAX_LINE_LENGTH);
}

void refresh_line_display(client_t *c) {
    char refresh_cmd[BUFFER_SIZE];

    // Clear current line and move cursor to start, then show prompt and line
    snprintf(refresh_cmd, sizeof(refresh_cmd), "\r\033[K\033[32m$\033[0m %s", c->line_editor.line);

    // Position cursor correctly
    int cursor_offset = c->line_editor.cursor_pos + 3; // +3 for prompt "$ "
    if (cursor_offset > 3) {
        snprintf(refresh_cmd + strlen(refresh_cmd), sizeof(refresh_cmd) - strlen(refresh_cmd),
                "\033[%dG", cursor_offset);
    }

    send(c->socket, refresh_cmd, strlen(refresh_cmd), 0);
}

char* get_previous_command(client_t *c) {
    if (c->history_count == 0) return NULL;

    if (c->line_editor.history_index == -1) {
        // First time going back, save current line
        strcpy(c->line_editor.saved_line, c->line_editor.line);
        c->line_editor.history_index = c->history_count - 1;
    } else if (c->line_editor.history_index > 0) {
        c->line_editor.history_index--;
    }

    int index = (c->history_position - c->history_count + c->line_editor.history_index) % MAX_HISTORY_SIZE;
    return c->command_history[index].command;
}

char* get_next_command(client_t *c) {
    if (c->line_editor.history_index == -1) return NULL;

    if (c->line_editor.history_index >= c->history_count - 1) {
        // Reached end of history, restore original line
        c->line_editor.history_index = -1;
        return c->line_editor.saved_line;
    } else {
        c->line_editor.history_index++;
        int index = (c->history_position - c->history_count + c->line_editor.history_index) % MAX_HISTORY_SIZE;
        return c->command_history[index].command;
    }
}

void handle_arrow_key(client_t *c, int key) {
    char *history_command = NULL;

    if (key == 'A') { // Up arrow
        history_command = get_previous_command(c);
    } else if (key == 'B') { // Down arrow
        history_command = get_next_command(c);
    } else if (key == 'C') { // Right arrow
        if (c->line_editor.cursor_pos < c->line_editor.line_length) {
            c->line_editor.cursor_pos++;
        }
    } else if (key == 'D') { // Left arrow
        if (c->line_editor.cursor_pos > 0) {
            c->line_editor.cursor_pos--;
        }
    }

    if (history_command) {
        strcpy(c->line_editor.line, history_command);
        c->line_editor.line_length = strlen(history_command);
        c->line_editor.cursor_pos = c->line_editor.line_length;
    }

    refresh_line_display(c);
}

void handle_tab_completion(client_t *c) {
    // Simple tab completion - complete file/directory names and commands
    char *line = c->line_editor.line;
    int cursor = c->line_editor.cursor_pos;

    // Find the word being completed (from cursor backwards to whitespace)
    int word_start = cursor;
    while (word_start > 0 && line[word_start - 1] != ' ') {
        word_start--;
    }

    char partial_word[MAX_LINE_LENGTH];
    int partial_len = cursor - word_start;
    if (partial_len >= MAX_LINE_LENGTH || partial_len == 0) {
        // Just beep if nothing to complete
        send(c->socket, "\a", 1, 0);
        return;
    }

    strncpy(partial_word, line + word_start, partial_len);
    partial_word[partial_len] = '\0';

    // If we're at the beginning of the line, try command completion
    if (word_start == 0) {
        // Try to complete commands
        char *matches[MAX_COMMAND_ARGS];
        int match_count = 0;
        
        // Check built-in commands
        extern command_mapping_t command_map[];
        for (int i = 0; command_map[i].command_name != NULL && match_count < MAX_COMMAND_ARGS - 1; i++) {
            if (strncmp(command_map[i].command_name, partial_word, partial_len) == 0) {
                matches[match_count++] = command_map[i].command_name;
            }
        }
        
        if (match_count == 1) {
            // Single match - complete it
            int completion_len = strlen(matches[0]) - partial_len;
            if (c->line_editor.line_length + completion_len < MAX_LINE_LENGTH - 1) {
                // Insert completion
                memmove(&c->line_editor.line[cursor + completion_len],
                       &c->line_editor.line[cursor],
                       c->line_editor.line_length - cursor);
                memcpy(&c->line_editor.line[cursor], matches[0] + partial_len, completion_len);
                c->line_editor.cursor_pos += completion_len;
                c->line_editor.line_length += completion_len;
                c->line_editor.line[c->line_editor.line_length] = '\0';
                refresh_line_display(c);
            }
        } else if (match_count > 1) {
            // Multiple matches - show them
            send(c->socket, "\n\r", 2, 0);
            for (int i = 0; i < match_count; i++) {
                send(c->socket, matches[i], strlen(matches[i]), 0);
                send(c->socket, "  ", 2, 0);
            }
            send(c->socket, "\n\r", 2, 0);
            refresh_line_display(c);
        } else {
            // No matches
            send(c->socket, "\a", 1, 0);
        }
    } else {
        // Try to complete file/directory names
        DIR *dir = opendir(c->cwd);
        if (!dir) {
            send(c->socket, "\a", 1, 0);
            return;
        }

        char *matches[MAX_COMMAND_ARGS];
        int match_count = 0;
        struct dirent *entry;
        
        while ((entry = readdir(dir)) != NULL && match_count < MAX_COMMAND_ARGS - 1) {
            if (entry->d_name[0] == '.') continue; // Skip hidden files
            if (strncmp(entry->d_name, partial_word, partial_len) == 0) {
                matches[match_count] = malloc(strlen(entry->d_name) + 1);
                if (matches[match_count]) {
                    strcpy(matches[match_count], entry->d_name);
                    match_count++;
                }
            }
        }
        closedir(dir);

        if (match_count == 1) {
            // Single match - complete it
            int completion_len = strlen(matches[0]) - partial_len;
            if (c->line_editor.line_length + completion_len < MAX_LINE_LENGTH - 1) {
                // Insert completion
                memmove(&c->line_editor.line[cursor + completion_len],
                       &c->line_editor.line[cursor],
                       c->line_editor.line_length - cursor);
                memcpy(&c->line_editor.line[cursor], matches[0] + partial_len, completion_len);
                c->line_editor.cursor_pos += completion_len;
                c->line_editor.line_length += completion_len;
                c->line_editor.line[c->line_editor.line_length] = '\0';
                refresh_line_display(c);
            }
        } else if (match_count > 1) {
            // Multiple matches - show them
            send(c->socket, "\n\r", 2, 0);
            for (int i = 0; i < match_count; i++) {
                send(c->socket, matches[i], strlen(matches[i]), 0);
                send(c->socket, "  ", 2, 0);
            }
            send(c->socket, "\n\r", 2, 0);
            refresh_line_display(c);
        } else {
            // No matches
            send(c->socket, "\a", 1, 0);
        }

        // Free allocated memory
        for (int i = 0; i < match_count; i++) {
            free(matches[i]);
        }
    }
}

int process_raw_input(client_t *c, char *input, int length) {
    int i = 0;
    int command_ready = 0;
    
    while (i < length) {
        unsigned char ch = (unsigned char)input[i++];

        // Handle escape sequences
        if (ch == '\033' && i + 1 < length) {
            unsigned char next = (unsigned char)input[i++];
            if (next == '[' && i < length) {
                unsigned char third = (unsigned char)input[i++];
                // Handle arrow keys: [A (up), [B (down), [C (right), [D (left)
                if (third >= 'A' && third <= 'D') {
                    handle_arrow_key(c, third);
                } else {
                    // Handle other [ sequences - consume additional characters if needed
                    while (i < length && input[i] >= '0' && input[i] <= '9') i++; // Skip digits
                    if (i < length && (input[i] == '~' || input[i] == ';')) i++; // Skip terminator
                }
            } else if (next == 'O' && i < length) {
                // Function key sequences - skip the next character
                i++;
            }
            // Ignore other escape sequences
            continue;
        }

        // Handle control characters
        if (ch == '\t') { // Tab key
            handle_tab_completion(c);
            continue;
        }

        if (ch == '\r' || ch == '\n') { // Enter key
            command_ready = 1;
            break;
        }

        if (ch == '\b' || ch == 127) { // Backspace
            if (c->line_editor.cursor_pos > 0) {
                // Remove character before cursor
                memmove(&c->line_editor.line[c->line_editor.cursor_pos - 1],
                       &c->line_editor.line[c->line_editor.cursor_pos],
                       c->line_editor.line_length - c->line_editor.cursor_pos);
                c->line_editor.cursor_pos--;
                c->line_editor.line_length--;
                c->line_editor.line[c->line_editor.line_length] = '\0';
                refresh_line_display(c);
            }
            continue;
        }

        if (ch == 3) { // Ctrl+C
            // Reset current line
            reset_line_editor(c);
            send_response(c->socket, "\n\r^C\n\r");
            char prompt[] = "\033[32m$\033[0m ";
            send(c->socket, prompt, strlen(prompt), 0);
            continue;
        }

        if (ch == 4) { // Ctrl+D
            // Exit enhanced shell
            disable_raw_mode(c);
            send_response(c->socket, "\n\rExited enhanced shell (Ctrl+D). Type 'enhanced' to re-enable.\n");
            return 0;
        }

        // Handle printable characters
        if (ch >= 32 && ch <= 126 && c->line_editor.line_length < MAX_LINE_LENGTH - 1) {
            // Insert regular character at cursor position
            memmove(&c->line_editor.line[c->line_editor.cursor_pos + 1],
                   &c->line_editor.line[c->line_editor.cursor_pos],
                   c->line_editor.line_length - c->line_editor.cursor_pos);
            c->line_editor.line[c->line_editor.cursor_pos] = ch;
            c->line_editor.cursor_pos++;
            c->line_editor.line_length++;
            c->line_editor.line[c->line_editor.line_length] = '\0';
            refresh_line_display(c);
            continue;
        }

        // Ignore other characters (non-printable, etc.)
    }

    return command_ready;
}

// ================= FILTERED SHELL FUNCTIONS =================

int is_command_allowed(const char *command) {
    if (!command) return 0;
    
    for (int i = 0; allowed_commands[i] != NULL; i++) {
        if (strcmp(command, allowed_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

int is_command_forbidden(const char *command) {
    if (!command) return 1;
    
    for (int i = 0; forbidden_commands[i] != NULL; i++) {
        if (strcmp(command, forbidden_commands[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

char* sanitize_command(const char *input) {
    if (!input) return NULL;
    
    size_t len = strlen(input);
    char *sanitized = malloc(len + 1);
    if (!sanitized) return NULL;
    
    int j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        // Allow alphanumeric, spaces, basic punctuation, but block dangerous chars
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || 
            (c >= '0' && c <= '9') || c == ' ' || c == '-' || c == '_' || 
            c == '.' || c == '/' || c == '*' || c == '?' || c == '[' || 
            c == ']' || c == '=' || c == ':') {
            sanitized[j++] = c;
        }
        // Block dangerous characters like ;, |, &, $, `, etc.
    }
    sanitized[j] = '\0';
    
    return sanitized;
}

int execute_filtered_command(client_t *c, const char *command, int client_socket) {
    if (!command || strlen(command) == 0) {
        return 0;
    }
    
    printf("[DEBUG] Executing filtered command: '%s'\n", command);
    
    // Parse command to get the base command
    char *command_copy = strdup(command);
    if (!command_copy) {
        send_response(client_socket, "Memory allocation error\n");
        return 0;
    }
    
    char *first_word = strtok(command_copy, " \t");
    if (!first_word) {
        free(command_copy);
        return 0;
    }
    
    // Check if command is explicitly forbidden
    if (is_command_forbidden(first_word)) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "Command '%s' is not allowed for security reasons.\n", first_word);
        send_response(client_socket, response);
        free(command_copy);
        return 0;
    }
    
    // Check if command is in allowed list
    if (!is_command_allowed(first_word)) {
        char response[BUFFER_SIZE];
        snprintf(response, sizeof(response), "Command '%s' is not in the allowed list.\nType 'help' to see available commands.\n", first_word);
        send_response(client_socket, response);
        free(command_copy);
        return 0;
    }
    
    free(command_copy);
    
    // Sanitize the full command
    char *sanitized = sanitize_command(command);
    if (!sanitized) {
        send_response(client_socket, "Command sanitization failed\n");
        return 0;
    }
    
    // Handle cd command specially (need to track directory changes)
    if (strncmp(sanitized, "cd ", 3) == 0 || strcmp(sanitized, "cd") == 0) {
        // Extract target directory
        char *target_dir = NULL;
        if (strlen(sanitized) > 3) {
            target_dir = sanitized + 3;
            while (*target_dir == ' ') target_dir++; // Skip spaces
        }
        
        // Change to target directory or home if no argument
        char full_command[BUFFER_SIZE];
        if (!target_dir || strlen(target_dir) == 0) {
            snprintf(full_command, sizeof(full_command), "cd %s && pwd", c->cwd);
        } else {
            // Restrict to UserDirectory and subdirectories
            if (strstr(target_dir, "..") || target_dir[0] == '/' || strstr(target_dir, "~")) {
                send_response(client_socket, "Directory access restricted to UserDirectory and subdirectories\n");
                free(sanitized);
                return 0;
            }
            snprintf(full_command, sizeof(full_command), "cd %s && cd %s && pwd", c->cwd, target_dir);
        }
        
        // Execute cd command and capture new directory
        FILE *fp = popen(full_command, "r");
        if (fp) {
            char new_cwd[256];
            if (fgets(new_cwd, sizeof(new_cwd), fp)) {
                new_cwd[strcspn(new_cwd, "\r\n")] = 0;
                // Verify the new directory is still within UserDirectory
                if (strncmp(new_cwd, "UserDirectory", 13) == 0 || strstr(new_cwd, "/UserDirectory")) {
                    strncpy(c->cwd, new_cwd, sizeof(c->cwd) - 1);
                    c->cwd[sizeof(c->cwd) - 1] = '\0';
                    printf("[DEBUG] Changed directory to: %s\n", c->cwd);
                } else {
                    send_response(client_socket, "Directory change blocked - outside allowed area\n");
                }
            }
            pclose(fp);
        } else {
            send_response(client_socket, "Failed to change directory\n");
        }
        
        free(sanitized);
        return 1;
    }
    
    // For other commands, execute in current directory and capture output
    char full_command[BUFFER_SIZE * 2];
    snprintf(full_command, sizeof(full_command), "cd %s && %s 2>&1", c->cwd, sanitized);
    
    printf("[DEBUG] Executing: %s\n", full_command);
    
    FILE *fp = popen(full_command, "r");
    if (!fp) {
        send_response(client_socket, "Failed to execute command\n");
        free(sanitized);
        return 0;
    }
    
    // Read and send output
    char buffer[BUFFER_SIZE];
    int output_sent = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        send(client_socket, buffer, strlen(buffer), 0);
        output_sent = 1;
    }
    
    int exit_status = pclose(fp);
    
    // If no output was sent and command failed, send error message
    if (!output_sent && exit_status != 0) {
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "Command failed with exit status %d\n", exit_status);
        send_response(client_socket, error_msg);
    }
    
    free(sanitized);
    return 1;
}

// ================= PTY SHELL FUNCTIONS =================

int start_pty_shell(client_t *c) {
    if (c->shell_active) {
        printf("[DEBUG] Shell already active for user %s\n", c->username);
        return 0;
    }
    
    // Initialize shell state
    c->pty_master_fd = -1;
    c->shell_pid = -1;
    c->shell_active = 0;
    c->command_buffer_pos = 0;
    memset(c->command_buffer, 0, sizeof(c->command_buffer));
    
    // Create pseudo-terminal
    int slave_fd;
    if (openpty(&c->pty_master_fd, &slave_fd, NULL, NULL, NULL) == -1) {
        printf("[ERROR] Failed to create PTY for user %s: %s\n", c->username, strerror(errno));
        return -1;
    }
    
    // Set PTY to non-blocking
    int flags = fcntl(c->pty_master_fd, F_GETFL);
    if (flags == -1 || fcntl(c->pty_master_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        printf("[ERROR] Failed to set PTY non-blocking: %s\n", strerror(errno));
        close(c->pty_master_fd);
        close(slave_fd);
        return -1;
    }
    
    // Fork shell process
    c->shell_pid = fork();
    if (c->shell_pid == -1) {
        printf("[ERROR] Failed to fork shell process: %s\n", strerror(errno));
        close(c->pty_master_fd);
        close(slave_fd);
        return -1;
    }
    
    if (c->shell_pid == 0) {
        // Child process - become shell
        close(c->pty_master_fd);

        // Create new session and process group
        if (setsid() == -1) {
            perror("setsid");
            exit(1);
        }

        // Set up slave PTY as stdin/stdout/stderr
        if (dup2(slave_fd, STDIN_FILENO) == -1 ||
            dup2(slave_fd, STDOUT_FILENO) == -1 ||
            dup2(slave_fd, STDERR_FILENO) == -1) {
            exit(1);
        }
        close(slave_fd);

        // Make this process the controlling terminal
        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) == -1) {
            perror("TIOCSCTTY");
            // Continue anyway - not all systems support this
        }

        // Set proper terminal attributes for the slave PTY
        struct termios term_attrs;
        if (tcgetattr(STDIN_FILENO, &term_attrs) == 0) {
            // Enable canonical mode and echo
            term_attrs.c_lflag |= (ICANON | ECHO | ISIG);
            term_attrs.c_iflag |= (BRKINT | ICRNL | IUTF8);
            term_attrs.c_oflag |= (OPOST | ONLCR);
            term_attrs.c_cflag |= (CS8 | CREAD);
            tcsetattr(STDIN_FILENO, TCSANOW, &term_attrs);
        }

        // Set environment
        setenv("TERM", "xterm-256color", 1);
        setenv("PS1", "\\[\\033[32m\\]$\\[\\033[0m\\] ", 1);
        setenv("BASH_ENV", "", 1); // Prevent bashrc issues

        // Change to user directory
        if (chdir(c->cwd) != 0) {
            chdir("UserDirectory"); // Fallback
        }

        // Execute shell with proper options
        execl("/bin/bash", "bash", "--login", "-i", NULL);
        exit(1);
    }
    
    // Parent process
    close(slave_fd);
    c->shell_active = 1;
    
    // Create thread to handle shell I/O
    if (pthread_create(&c->shell_thread, NULL, pty_shell_thread, c) != 0) {
        printf("[ERROR] Failed to create shell thread: %s\n", strerror(errno));
        stop_pty_shell(c);
        return -1;
    }
    
    printf("[INFO] Started PTY shell for user %s (PID: %d)\n", c->username, c->shell_pid);
    return 0;
}

void stop_pty_shell(client_t *c) {
    if (!c->shell_active) {
        return;
    }
    
    printf("[INFO] Stopping PTY shell for user %s\n", c->username);
    
    c->shell_active = 0;
    
    // Close PTY master
    if (c->pty_master_fd != -1) {
        close(c->pty_master_fd);
        c->pty_master_fd = -1;
    }
    
    // Kill shell process
    if (c->shell_pid > 0) {
        kill(c->shell_pid, SIGTERM);
        
        // Wait for process to exit (with timeout)
        int status;
        for (int i = 0; i < 10; i++) {
            if (waitpid(c->shell_pid, &status, WNOHANG) == c->shell_pid) {
                break;
            }
            usleep(100000); // 100ms
        }
        
        // Force kill if still alive
        if (waitpid(c->shell_pid, &status, WNOHANG) == 0) {
            kill(c->shell_pid, SIGKILL);
            waitpid(c->shell_pid, &status, 0);
        }
        
        c->shell_pid = -1;
    }
    
    // Cancel and join thread
    if (c->shell_thread) {
        pthread_cancel(c->shell_thread);
        pthread_join(c->shell_thread, NULL);
        c->shell_thread = 0;
    }
    
    printf("[INFO] PTY shell stopped for user %s\n", c->username);
}

void* pty_shell_thread(void *arg) {
    client_t *c = (client_t*)arg;
    char buffer[1024];
    fd_set readfds;
    struct timeval timeout;
    
    printf("[INFO] Shell I/O thread started for user %s\n", c->username);
    
    while (c->shell_active && c->pty_master_fd != -1) {
        FD_ZERO(&readfds);
        FD_SET(c->pty_master_fd, &readfds);
        
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;
        
        int ready = select(c->pty_master_fd + 1, &readfds, NULL, NULL, &timeout);
        
        if (ready > 0 && FD_ISSET(c->pty_master_fd, &readfds)) {
            ssize_t bytes_read = read(c->pty_master_fd, buffer, sizeof(buffer) - 1);
            
            if (bytes_read > 0) {
                buffer[bytes_read] = '\0';
                
                // Send output directly to client
                send(c->socket, buffer, bytes_read, 0);
                
                printf("[DEBUG] Shell output (%zd bytes): %.*s\n", bytes_read, (int)bytes_read, buffer);
            } else if (bytes_read == 0) {
                // EOF - shell closed
                printf("[INFO] Shell closed for user %s\n", c->username);
                break;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                // Error
                printf("[ERROR] Shell read error for user %s: %s\n", c->username, strerror(errno));
                break;
            }
        } else if (ready == -1 && errno != EINTR) {
            printf("[ERROR] Shell select error for user %s: %s\n", c->username, strerror(errno));
            break;
        }
    }
    
    printf("[INFO] Shell I/O thread ending for user %s\n", c->username);
    c->shell_active = 0;
    return NULL;
}

int process_shell_input(client_t *c, const char *input, int client_socket) {
    if (!c->shell_active || c->pty_master_fd == -1) {
        return 0;
    }
    
    size_t input_len = strlen(input);
    printf("[DEBUG] Processing shell input (%zu bytes): %.*s\n", input_len, (int)input_len, input);
    
    // Check for exit command
    if (strncmp(input, "exit", 4) == 0 && (input_len == 4 || input[4] == '\n' || input[4] == '\r')) {
        stop_pty_shell(c);
        c->raw_mode = 0;
        send_response(client_socket, "\nExited interactive shell. Type 'shell' to re-enable.\n");
        return 1;
    }
    
    // Add input to command buffer for filtering
    for (size_t i = 0; i < input_len; i++) {
        char ch = input[i];
        
        if (ch == '\n' || ch == '\r') {
            // Command complete - check for dangerous commands
            c->command_buffer[c->command_buffer_pos] = '\0';
            
            if (filter_command_on_enter(c, c->command_buffer)) {
                // Command blocked - don't send to shell
                char warning[] = "\r\n\033[31mCommand blocked for security reasons\033[0m\r\n$ ";
                send(client_socket, warning, strlen(warning), 0);
                c->command_buffer_pos = 0;
                return 1;
            }
            
            // Reset buffer after processing
            c->command_buffer_pos = 0;
        } else if (c->command_buffer_pos < sizeof(c->command_buffer) - 1) {
            c->command_buffer[c->command_buffer_pos++] = ch;
        }
    }
    
    // Send input to shell
    ssize_t bytes_written = write(c->pty_master_fd, input, input_len);
    if (bytes_written == -1) {
        printf("[ERROR] Failed to write to shell PTY: %s\n", strerror(errno));
        return 0;
    }
    
    return 1;
}

int filter_command_on_enter(client_t *c, const char *command) {
    if (!command || strlen(command) == 0) {
        return 0; // Allow empty commands
    }
    
    // Parse first word of command
    char *command_copy = strdup(command);
    if (!command_copy) return 0;
    
    char *first_word = strtok(command_copy, " \t");
    if (!first_word) {
        free(command_copy);
        return 0;
    }
    
    // Check if command is forbidden
    int blocked = is_command_forbidden(first_word);
    
    printf("[DEBUG] Command filter: '%s' -> %s\n", first_word, blocked ? "BLOCKED" : "ALLOWED");
    
    free(command_copy);
    return blocked;
}
