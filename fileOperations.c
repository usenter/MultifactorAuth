#include "fileOperations.h"
#include "auth_system.h"


const char *auths[numAuths] = {
    "user", "admin", "superadmin", "business", "finance",
    "marketing", "sales", "engineering", "hr", "superAdmin"
};


void handle_file_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    if(strncmp(buffer, "/end", 5) == 0){
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
                 "  /end - End file mode and return to chat mode\n"
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
        printf("User %s is trying to list directory %s\n", c->username, c->cwd);
        
        // Extract the relative path from UserDirectory/ onwards
        char *relative_path = c->cwd;
        if (strncmp(c->cwd, "UserDirectory/", 14) == 0) {
            relative_path = c->cwd + 14;  // Skip "UserDirectory/"
        } else {
            relative_path = ".";  // For root directory (UserDirectory)
        }
        
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
    // cd command
    if(strncmp(buffer, "cd ", 3) == 0) {
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
        char *relative_path = new_dir;
        if (strncmp(new_dir, "UserDirectory/", 14) == 0) {
            relative_path = new_dir + 14;  // Skip "UserDirectory/"
        }
        
        // Check access using the relative path
        if(!isAccessible(c, relative_path, 'r', client_socket)) return;
        
        strncpy(c->cwd, new_dir, sizeof(c->cwd)-1);
        c->cwd[sizeof(c->cwd)-1] = '\0';
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Changed directory to %s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    // touch command
    if(strncmp(buffer, "touch ", 6) == 0) {
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
    // pwd command
    if(strncmp(buffer, "pwd", 3) == 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "%s\n", c->cwd);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
}





// Check if user has access to a folder/file
int isAccessible(client_t *c, char *fName, char mode, int client_socket) {
    char broadcast_msg[BUFFER_SIZE];
    char readPermLevel[numAuths+1];
    char writePermLevel[numAuths+1];
    

    char* filePath = malloc(1024);
    char* folderName = malloc(1024);
    strncpy(folderName, fName, 1024);
    folderName[strcspn(folderName, "\r\n ")] = 0;
    // For ls command, we want to check permissions for the current directory
    // For other commands, we want to check permissions for the target directory
    snprintf(filePath, 1024, "UserDirectory/%s/.perms", fName);
    FILE* permsFile = fopen(filePath, "r");
    if(permsFile == NULL){
        printf("Permissions file not found for %s\n", fName);
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
    free(filePath);
    
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