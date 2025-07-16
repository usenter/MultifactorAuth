#ifndef AUTH_SYSTEM_H
#define AUTH_SYSTEM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>

#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64
#define MAX_HASH_LEN 65  // SHA-256 hash is 64 chars + null terminator
#define MAX_USERS 100
#define AUTH_TIMEOUT 300  // 5 minutes in seconds

// User structure
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password_hash[MAX_HASH_LEN];
    int active;
} user_t;

// Session structure
typedef struct {
    char username[MAX_USERNAME_LEN];
    SOCKET client_socket;
    time_t login_time;
    int authenticated;
} session_t;

// Authentication commands
#define AUTH_LOGIN "AUTH_LOGIN"
#define AUTH_REGISTER "AUTH_REGISTER"
#define AUTH_SUCCESS "AUTH_SUCCESS"
#define AUTH_FAILED "AUTH_FAILED"
#define AUTH_LOGOUT "AUTH_LOGOUT"

// Function declarations
void init_auth_system(void);
int add_user(const char* username, const char* password);
int authenticate_user(const char* username, const char* password);
int create_session(const char* username, SOCKET client_socket);
void remove_session(SOCKET client_socket);
session_t* get_session(SOCKET client_socket);
int is_authenticated(SOCKET client_socket);
void cleanup_expired_sessions(void);
void hash_password(const char* password, char* hash);
int verify_password(const char* password, const char* hash);
void save_users_to_file(const char* filename);
void load_users_from_file(const char* filename);

#endif // AUTH_SYSTEM_H 