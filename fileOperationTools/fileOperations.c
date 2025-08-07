#include "fileOperations.h"
#include <sys/stat.h>


const char *auths[numAuths] = {
    "user", "admin", "superadmin", "business", "finance",
    "marketing", "sales", "engineering", "hr", "superAdmin"
};


void handle_file_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    printf("[DEBUG] File mode command received: %s\n", buffer);
    if(strncmp(buffer, "/chat", 5) == 0){
        c->mode = CLIENT_MODE_CHAT;
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File mode ended, returning to chat mode\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    if(strncmp(buffer, "/help", 5) == 0){
        const char *userPermName = auths[c->authLevel];
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File mode commands work similar to a terminal. The following commands are available:\n"
                 "  ls - List files in the current directory\n"
                 "  cd <directory> - Change to a different directory\n"
                 "  pwd - Show the current working directory\n"
                 "  cat <file> - Display the contents of a file\n"
                 "  touch <file> - Create a new file\n"
                 "  rm <file> - Delete a file\n"
                 "  mkdir <directory> - Create a new directory\n"
                 "  rmdir <directory> - Delete a directory\n"
                 "  /help - Show this help\n"
                 "  /chat - End file mode and return to chat mode\n"
                 "  /quit - kill the overall program\n"
                "Note that the file mode is not a full terminal, so some commands may not work as expected.\n"
                "Additionally, access to files is limited by the user's permissions.\n"
                "Your permissions are: %s\n", userPermName);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    if(strncmp(buffer, "/list", 5) == 0 || strncmp(buffer, "/nick", 5) == 0 || strncmp(buffer, "/file", 5) == 0){
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Chat mode commands are not available in file mode\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        buffer = "\0"; //clear buffer
        return;
    }
    
    // ls command
    if(strncmp(buffer, "ls", 2) == 0) {
        handle_ls_command(c, client_socket);
        return;
    }
    // cd command
    if(strncmp(buffer, "cd ", 3) == 0) {
        handle_cd_command(c, buffer, client_socket);
        return;
    }
    // touch command
    if(strncmp(buffer, "touch ", 6) == 0) {
        handle_touch_command(c, buffer, client_socket);
        return;
    }
    // pwd command
    if(strncmp(buffer, "pwd", 3) == 0) {
        printf("User %s is trying to get the current working directory%s\n", c->username, c->cwd);
        snprintf(broadcast_msg, sizeof(broadcast_msg), "%s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    // rm command
    if(strncmp(buffer, "rm ", 3) == 0) {
        handle_rm_command(c, buffer, client_socket);
        return;
    }
    if(strncmp(buffer, "rmdir ", 6) == 0) {
        handle_rmdir_command(c, buffer, client_socket);
        return;
    }
    if(strncmp(buffer, "mkdir ", 6) == 0) {
        handle_mkdir_command(c, buffer, client_socket);
        return;
    }
    if(strncmp(buffer, "cat ", 4) == 0) {
        handle_cat_command(c, buffer, client_socket);
        return;
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
