#include "fileOperations.h"
#include "auth_system.h"
#include <sys/stat.h>


const char *auths[numAuths] = {
    "user", "admin", "superadmin", "business", "finance",
    "marketing", "sales", "engineering", "hr", "superAdmin"
};


void handle_file_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
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
        handle_ls_command(c, buffer, client_socket);
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



void handle_ls_command(client_t *c, char *buffer, int client_socket){
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

 // encryption system to be integrated later
/*
// Global master password and salt
static char master_password[256] = {0};
static unsigned char master_salt[32];
static int encryption_initialized = 0;

// Structure to store encryption keys per directory
typedef struct {
    char directory_path[512];
    unsigned char key[32];  // 256-bit key for AES-256
    unsigned char iv[16];   // 128-bit IV for AES
    UT_hash_handle hh;
    //need to turn into hash;
} encryption_key_t;

// Global array to store encryption keys (in practice, you might load this from a secure file)
encryption_key_t *directoryKeys_map = NULL;
int num_keys = 0;

// Function to initialize encryption system with admin password
int initialize_encryption_system(char* inputMasterPassword) {
    if(encryption_initialized) return 0;
    
    if(!inputMasterPassword) {
        char* inputPassword = getpass("Enter master encryption password: ");
        if(!inputPassword) {
            printf("Failed to read password\n");
            return -1;
        }
        inputPassword[strcspn(inputPassword, "\n")] = '\0';
        hash_password(inputPassword, master_password);
        memset(inputPassword, 0, strlen(inputPassword));
    }
    else{
        hash_password(inputMasterPassword, master_password);
        memset(inputMasterPassword, 0, strlen(inputMasterPassword));
    }

    
    // Generate random salt for key derivation
    if (RAND_bytes(master_salt, sizeof(master_salt)) != 1) {
        printf("Failed to generate salt\n");
        return -1;
    }
    
    encryption_initialized = 1;
    printf("Encryption system initialized successfully!\n");
   
    
    
    return 1;
}

// Function to derive a directory-specific key from master password and directory path
int derive_directory_key(const char* directory_path, unsigned char* key_out, unsigned char* iv_out) {
    if (!encryption_initialized) {
        printf("Encryption system not initialized!\n");
        return -1;
    }
    
    // Create unique input by combining master password + directory path + salt
    char input_data[1024];
    snprintf(input_data, sizeof(input_data), "%s:%s", master_password, directory_path);
    
    // Use PBKDF2 to derive key
    if (PKCS5_PBKDF2_HMAC(input_data, strlen(input_data),
                          master_salt, sizeof(master_salt),
                          10000,  // 10,000 iterations
                          EVP_sha256(),
                          32, key_out) != 1) {
        return -1;
    }
    
    // Derive IV using different salt approach
    char iv_input[1024];
    snprintf(iv_input, sizeof(iv_input), "IV:%s:%s", master_password, directory_path);
    
    unsigned char iv_temp[32];
    if (PKCS5_PBKDF2_HMAC(iv_input, strlen(iv_input),
                          master_salt, sizeof(master_salt),
                          5000,   // 5,000 iterations for IV
                          EVP_sha256(),
                          32, iv_temp) != 1) {
        return -1;
    }
    
    // Use first 16 bytes as IV
    memcpy(iv_out, iv_temp, 16);
    
    // Clear sensitive data
    memset(input_data, 0, sizeof(input_data));
    memset(iv_input, 0, sizeof(iv_input));
    memset(iv_temp, 0, sizeof(iv_temp));
    
    return 0;
}
// Function to get encryption key for a directory
encryption_key_t* get_directory_key(const char* directory_path) {
    encryption_key_t *key;
    HASH_FIND(hh, directoryKeys_map, directory_path, strlen(directory_path), key);
    return key;
}

// Function to generate a new encryption key for a directory using master password
int generate_directory_key(const char* directory_path) {
    if (!encryption_initialized) return -1;
    
    encryption_key_t* new_key = malloc(sizeof(encryption_key_t));
    if(!new_key){
        printf("Failed to allocate memory for new key\n");
        return -1;
    }
    strncpy(new_key->directory_path, directory_path, sizeof(new_key->directory_path) - 1);
    new_key->directory_path[sizeof(new_key->directory_path) - 1] = '\0';
    HASH_ADD_KEYPTR(hh, directoryKeys_map, new_key->directory_path, strlen(new_key->directory_path), new_key);
    // Derive key and IV from master password and directory path
    if (derive_directory_key(directory_path, new_key->key, new_key->iv) != 0) {
        HASH_DEL(directoryKeys_map, new_key);
        free(new_key);
        return -1;
    }
    return 1;
}

// Admin function to change master password (re-encrypts all files)
int change_master_password() {
    if (!encryption_initialized) {
        printf("Encryption system not initialized!\n");
        return -1;
    }
    
    char old_password[256];
    char new_password[256];
    char confirm_password[256];
    
    printf("Enter current master password: ");
    if (!fgets(old_password, sizeof(old_password), stdin)) {
        return -1;
    }
    old_password[strcspn(old_password, "\n")] = 0;
    
    if (strcmp(old_password, master_password) != 0) {
        printf("Incorrect current password!\n");
        memset(old_password, 0, sizeof(old_password));
        return -1;
    }
    
    printf("Enter new master password: ");
    if (!fgets(new_password, sizeof(new_password), stdin)) {
        memset(old_password, 0, sizeof(old_password));
        return -1;
    }
    new_password[strcspn(new_password, "\n")] = 0;
    
    printf("Confirm new master password: ");
    if (!fgets(confirm_password, sizeof(confirm_password), stdin)) {
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        return -1;
    }
    confirm_password[strcspn(confirm_password, "\n")] = 0;
    
    if (strcmp(new_password, confirm_password) != 0) {
        printf("New passwords do not match!\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return -1;
    }
    
    if (strlen(new_password) < 8) {
        printf("New password must be at least 8 characters long!\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return -1;
    }
    
    printf("WARNING: This will re-encrypt ALL files with the new password.\n");
    printf("This may take some time. Continue? (y/N): ");
    
    char confirm[10];
    if (!fgets(confirm, sizeof(confirm), stdin) || 
        (confirm[0] != 'y' && confirm[0] != 'Y')) {
        printf("Password change cancelled.\n");
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirm_password, 0, sizeof(confirm_password));
        return -1;
    }
    
    // Store old password temporarily
    char temp_old_password[256];
    strcpy(temp_old_password, master_password);
    
    // Update to new password
    strncpy(master_password, new_password, sizeof(master_password) - 1);
    
    // Clear all cached keys (they'll be regenerated with new password)
    num_keys = 0;
    
    // Re-encrypt all files with new password
    printf("Re-encrypting all files with new password...\n");
    
    // First, we need to decrypt all files with old password, then encrypt with new
    // This is a complex operation - for brevity, showing the concept
    printf("Password changed successfully!\n");
    
    // Clear sensitive data
    memset(old_password, 0, sizeof(old_password));
    memset(new_password, 0, sizeof(new_password));
    memset(confirm_password, 0, sizeof(confirm_password));
    memset(temp_old_password, 0, sizeof(temp_old_password));
    
    return 0;
}

// Function to verify admin password for sensitive operations
int verify_admin_password() {
    if (!encryption_initialized) {
        printf("Encryption system not initialized!\n");
        return 0;
    }
    
    char password[256];
    printf("Enter admin password: ");
    
    if (!fgets(password, sizeof(password), stdin)) {
        return 0;
    }
    password[strcspn(password, "\n")] = 0;
    
    int result = (strcmp(password, master_password) == 0);
    memset(password, 0, sizeof(password));
    
    return result;
}

// Admin command to display encryption status
void show_encryption_status() {
    if (!verify_admin_password()) {
        printf("Access denied.\n");
        return;
    }
    
    printf("=== Encryption Status ===\n");
    printf("Encryption initialized: %s\n", encryption_initialized ? "Yes" : "No");
    printf("Number of directory keys cached: %d\n", HASH_COUNT(directoryKeys_map));
    printf("Master salt: ");
    for (int i = 0; i < 8; i++) {  // Show only first 8 bytes for security
        printf("%02x", master_salt[i]);
    }
    printf("...\n");
    
    printf("\nDirectory keys:\n");
    encryption_key_t *key, *temp  = NULL;
    HASH_ITER(hh, directoryKeys_map, key, temp) {
        printf("  - %s\n", key->directory_path);
    }
}

// Function to encrypt data
int encrypt_data(const unsigned char* plaintext, int plaintext_len, 
                const unsigned char* key, const unsigned char* iv,
                unsigned char* ciphertext, int* ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len = len;
    
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *ciphertext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Function to decrypt data
int decrypt_data(const unsigned char* ciphertext, int ciphertext_len,
                const unsigned char* key, const unsigned char* iv,
                unsigned char* plaintext, int* plaintext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    int len;
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len = len;
    
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    *plaintext_len += len;
    
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

// Modified touch command that creates encrypted files
void handle_touch_command_encrypted(client_t *c, char *buffer, int client_socket) {
    char broadcast_msg[BUFFER_SIZE];
    
    // Check write permissions
    if (!isAccessible(c, c->cwd, 'w', client_socket)) return;
    
    char filename[256];
    char *args = buffer + 6; // Skip "touch "
    strncpy(filename, args, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';
    filename[strcspn(filename, "\r\n ")] = '\0';
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", c->cwd, filename);
    
    // Get or create encryption key for this directory
    encryption_key_t* dir_key = get_directory_key(c->cwd);
    if (!dir_key) {
        if (generate_directory_key(c->cwd) != 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to generate encryption key\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        dir_key = get_directory_key(c->cwd);
    }
    
    // Create empty encrypted file
    const char* empty_content = "";
    unsigned char ciphertext[1024];
    int ciphertext_len;
    
    if (encrypt_data((const unsigned char*)empty_content, strlen(empty_content),
                     dir_key->key, dir_key->iv, ciphertext, &ciphertext_len) != 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Encryption failed\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    FILE *file = fopen(filepath, "wb");
    if (!file) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Failed to create file: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Write magic header, IV, then encrypted content
    fwrite("ENCRYPT1", 1, 8, file);  // Magic header
    fwrite(dir_key->iv, 1, 16, file); // IV
    fwrite(ciphertext, 1, ciphertext_len, file); // Encrypted content
    fclose(file);
    
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Encrypted file created: %s\n", filename);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
}

// Modified cat command that decrypts files
void handle_cat_command_encrypted(client_t *c, char *buffer, int client_socket) {
    char broadcast_msg[BUFFER_SIZE];
    
    // Check read permissions
    if (!isAccessible(c, c->cwd, 'r', client_socket)) return;
    
    char filename[256];
    char *args = buffer + 4; // Skip "cat "
    strncpy(filename, args, sizeof(filename) - 1);
    filename[sizeof(filename) - 1] = '\0';
    filename[strcspn(filename, "\r\n ")] = '\0';
    
    char filepath[512];
    snprintf(filepath, sizeof(filepath), "%s/%s", c->cwd, filename);
    
    // Check if file exists
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File not found: %s\n", filename);
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Get encryption key for this directory
    encryption_key_t* dir_key = get_directory_key(c->cwd);
    if (!dir_key) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "No encryption key found for directory\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        fclose(file);
        return;
    }
    
    // Read and verify magic header
    unsigned char magic[8];
    if (fread(magic, 1, 8, file) != 8 || memcmp(magic, "ENCRYPT1", 8) != 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File is not encrypted or corrupted\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        fclose(file);
        return;
    }
    
    // Read IV from file
    unsigned char file_iv[16];
    if (fread(file_iv, 1, 16, file) != 16) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Invalid encrypted file format\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        fclose(file);
        return;
    }
    
    // Read encrypted content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file) - 24; // Subtract magic header (8) + IV (16)
    fseek(file, 24, SEEK_SET); // Skip magic header + IV
    
    unsigned char *ciphertext = malloc(file_size);
    if (!ciphertext) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Memory allocation failed\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        fclose(file);
        return;
    }
    
    fread(ciphertext, 1, file_size, file);
    fclose(file);
    
    // Decrypt content
    unsigned char *plaintext = malloc(file_size + 16); // Extra space for padding
    int plaintext_len;
    
    if (decrypt_data(ciphertext, file_size, dir_key->key, file_iv,
                     plaintext, &plaintext_len) != 0) {
        snprintf(broadcast_msg, sizeof(broadcast_msg), "Decryption failed - access denied\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        free(ciphertext);
        free(plaintext);
        return;
    }
    
    // Null-terminate and send decrypted content
    plaintext[plaintext_len] = '\0';
    snprintf(broadcast_msg, sizeof(broadcast_msg), "Content of %s:\n%s\n", filename, plaintext);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    free(ciphertext);
    free(plaintext);
}

// Function to write encrypted content to file (for file editing)
int write_encrypted_file(const char* filepath, const char* content, const char* directory_path) {
    encryption_key_t* dir_key = get_directory_key(directory_path);
    if (!dir_key) return -1;
    
    unsigned char ciphertext[strlen(content) + 32]; // Extra space for padding
    int ciphertext_len;
    
    if (encrypt_data((const unsigned char*)content, strlen(content),
                     dir_key->key, dir_key->iv, ciphertext, &ciphertext_len) != 0) {
        return -1;
    }
    
    FILE *file = fopen(filepath, "wb");
    if (!file) return -1;
    
    // Write IV first, then encrypted content
    fwrite(dir_key->iv, 1, 16, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);
    
    return 0;
}

// Function to check if a file is already encrypted
int is_file_encrypted(const char* filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return 0;
    
    // Check if file size is at least 16 bytes (for IV)
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fclose(file);
    
    if (file_size < 16) return 0;
    
    // For a more robust check, we could try to decrypt and see if it fails
    // For now, we'll assume files >= 16 bytes might be encrypted
    // You could add a magic header to definitively identify encrypted files
    return 1;
}

// Function to encrypt a single file
int encrypt_existing_file(const char* filepath, const char* directory_path) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        printf("Failed to open file for encryption: %s\n", filepath);
        return -1;
    }
    
    // Read entire file content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char *content = malloc(file_size + 1);
    if (!content) {
        fclose(file);
        return -1;
    }
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);
    
    // Get or create encryption key for this directory
    encryption_key_t* dir_key = get_directory_key(directory_path);
    if (!dir_key) {
        if (generate_directory_key(directory_path) != 0) {
            free(content);
            return -1;
        }
        dir_key = get_directory_key(directory_path);
    }
    
    // Encrypt the content
    unsigned char *ciphertext = malloc(file_size + 32); // Extra space for padding
    int ciphertext_len;
    
    if (encrypt_data(content, file_size, dir_key->key, dir_key->iv, 
                     ciphertext, &ciphertext_len) != 0) {
        free(content);
        free(ciphertext);
        return -1;
    }
    
    // Write encrypted content back to file
    file = fopen(filepath, "wb");
    if (!file) {
        free(content);
        free(ciphertext);
        return -1;
    }
    
    // Write IV first, then encrypted content
    fwrite(dir_key->iv, 1, 16, file);
    fwrite(ciphertext, 1, ciphertext_len, file);
    fclose(file);
    
    free(content);
    free(ciphertext);
    
    printf("Encrypted file: %s\n", filepath);
    return 0;
}

// Recursive function to encrypt all files in a directory tree
int encrypt_directory_recursive(const char* dirpath) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        printf("Failed to open directory: %s\n", dirpath);
        return -1;
    }
    
    struct dirent *entry;
    int files_encrypted = 0;
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Skip .perms files (permission files shouldn't be encrypted)
        if (strcmp(entry->d_name, ".perms") == 0) {
            continue;
        }
        
        char fullpath[1024];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        
        struct stat file_stat;
        if (stat(fullpath, &file_stat) == 0) {
            if (S_ISDIR(file_stat.st_mode)) {
                // Recursively encrypt subdirectory
                int subdir_count = encrypt_directory_recursive(fullpath);
                if (subdir_count >= 0) {
                    files_encrypted += subdir_count;
                }
            } else if (S_ISREG(file_stat.st_mode)) {
                // Check if file is already encrypted
                if (!is_file_encrypted(fullpath)) {
                    if (encrypt_existing_file(fullpath, dirpath) == 0) {
                        files_encrypted++;
                    }
                } else {
                    printf("File already encrypted: %s\n", fullpath);
                }
            }
        }
    }
    
    closedir(dir);
    return files_encrypted;
}

// Main function to encrypt entire UserDirectory tree at startup
void encrypt_all_existing_files() {
    if (!encryption_initialized) {
        printf("Error: Encryption system not initialized!\n");
        printf("Please run server initialization first.\n");
        return;
    }
    
    printf("Starting encryption of existing files...\n");
    
    int total_encrypted = encrypt_directory_recursive("UserDirectory");
    
    if (total_encrypted >= 0) {
        printf("Encryption complete! %d files encrypted.\n", total_encrypted);
    } else {
        printf("Encryption failed!\n");
    }
}

// Enhanced function with magic header to definitively identify encrypted files
int is_file_encrypted_enhanced(const char* filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return 0;
    
    // Read first 8 bytes to check for magic header
    unsigned char magic[8];
    if (fread(magic, 1, 8, file) != 8) {
        fclose(file);
        return 0;
    }
    fclose(file);
    
    // Check for our custom magic header "ENCRYPT1"
    return (memcmp(magic, "ENCRYPT1", 8) == 0);
}

// Enhanced encryption function with magic header
int encrypt_existing_file_enhanced(const char* filepath, const char* directory_path) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        printf("Failed to open file for encryption: %s\n", filepath);
        return -1;
    }
    
    // Read entire file content
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    unsigned char *content = malloc(file_size + 1);
    if (!content) {
        fclose(file);
        return -1;
    }
    
    fread(content, 1, file_size, file);
    content[file_size] = '\0';
    fclose(file);
    
    // Get or create encryption key for this directory
    encryption_key_t* dir_key = get_directory_key(directory_path);
    if (!dir_key) {
        if (generate_directory_key(directory_path) != 0) {
            free(content);
            return -1;
        }
        dir_key = get_directory_key(directory_path);
    }
    
    // Encrypt the content
    unsigned char *ciphertext = malloc(file_size + 32);
    int ciphertext_len;
    
    if (encrypt_data(content, file_size, dir_key->key, dir_key->iv, 
                     ciphertext, &ciphertext_len) != 0) {
        free(content);
        free(ciphertext);
        return -1;
    }
    
    // Write encrypted content with magic header
    file = fopen(filepath, "wb");
    if (!file) {
        free(content);
        free(ciphertext);
        return -1;
    }
    
    // Write magic header, IV, then encrypted content
    fwrite("ENCRYPT1", 1, 8, file);  // Magic header
    fwrite(dir_key->iv, 1, 16, file); // IV
    fwrite(ciphertext, 1, ciphertext_len, file); // Encrypted content
    fclose(file);
    
    free(content);
    free(ciphertext);
    
    printf("Encrypted file: %s\n", filepath);
    return 0;
}*/