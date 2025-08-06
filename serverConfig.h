#ifndef SERVER_CONFIG_H
#define SERVER_CONFIG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

// Server configuration structure
typedef struct {
    int maxUsers;
    int maxEvents;
    int disableEmail;
    int disableRSA;
    int disablePassword;
    int initialized;
} server_config_t;

// Global server configuration
extern server_config_t server_config;

// Function declarations
int init_server_config(const char* config_file);
void cleanup_server_config(void);
int is_server_config_loaded(void);
int get_max_users(void);
int get_max_events(void);
int is_email_disabled(void);
int is_rsa_disabled(void);
int is_password_disabled(void);

#endif // SERVER_CONFIG_H 