#include "serverConfig.h"

// Global server configuration
server_config_t server_config = {0, 0, 0, 0, 0, 0};

int init_server_config(const char* config_file) {
    if (!config_file) {
        printf("[ERROR] Invalid config file path\n");
        return 0;
    }
    
    // Clean up any existing config
    cleanup_server_config();
    
    FILE *file = fopen(config_file, "rb");
    if (!file) {
        printf("[ERROR] Failed to open server config file: %s\n", config_file);
        return 0;
    }

    fseek(file, 0, SEEK_END);
    long flen = ftell(file);
    rewind(file);

    char *data = (char*)malloc(flen + 1);
    if (!data) { 
        fclose(file); 
        return 0; 
    }

    fread(data, 1, flen, file);
    data[flen] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) {
        printf("[ERROR] Failed to parse server config JSON\n");
        return 0;
    }

    // Parse configuration values with defaults
    const cJSON *js_maxUsers = cJSON_GetObjectItemCaseSensitive(json, "maxUsers");
    const cJSON *js_maxEvents = cJSON_GetObjectItemCaseSensitive(json, "maxEvents");
    const cJSON *js_disableEmail = cJSON_GetObjectItemCaseSensitive(json, "disableEmail");
    const cJSON *js_disableRSA = cJSON_GetObjectItemCaseSensitive(json, "disableRSA");
    const cJSON *js_disablePassword = cJSON_GetObjectItemCaseSensitive(json, "disablePassword");
    
    // Set values with defaults
    server_config.maxUsers = (js_maxUsers && cJSON_IsNumber(js_maxUsers)) ? js_maxUsers->valueint : 100;
    server_config.maxEvents = (js_maxEvents && cJSON_IsNumber(js_maxEvents)) ? js_maxEvents->valueint : 100;
    server_config.disableEmail = (js_disableEmail && cJSON_IsBool(js_disableEmail)) ? js_disableEmail->valueint : 0;
    server_config.disableRSA = (js_disableRSA && cJSON_IsBool(js_disableRSA)) ? js_disableRSA->valueint : 0;
    server_config.disablePassword = (js_disablePassword && cJSON_IsBool(js_disablePassword)) ? js_disablePassword->valueint : 0;
    server_config.initialized = 1;
    
    cJSON_Delete(json);
    
    printf("[INFO] Server configuration loaded successfully\n");
    printf("[INFO] Max Users: %d, Max Events: %d\n", server_config.maxUsers, server_config.maxEvents);
    printf("[INFO] Email: %s, RSA: %s, Password: %s\n", 
           server_config.disableEmail ? "DISABLED" : "ENABLED",
           server_config.disableRSA ? "DISABLED" : "ENABLED", 
           server_config.disablePassword ? "DISABLED" : "ENABLED");
    
    return 1;
}

void cleanup_server_config(void) {
    server_config.initialized = 0;
}

int is_server_config_loaded(void) {
    return server_config.initialized;
}

int get_max_users(void) {
    return server_config.initialized ? server_config.maxUsers : 100;
}

int get_max_events(void) {
    return server_config.initialized ? server_config.maxEvents : 100;
}

int is_email_disabled(void) {
    return server_config.initialized && server_config.disableEmail;
}

int is_rsa_disabled(void) {
    return server_config.initialized && server_config.disableRSA;
}

int is_password_disabled(void) {
    return server_config.initialized && server_config.disablePassword;
} 