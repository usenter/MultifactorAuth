#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>
#include "../configTools/serverConfig.h"

#define REST_SERVER_PORT 8080
#define BUFFER_SIZE 4096

// Function declarations
void print_response_in_chunks(const char *response, const char *prefix, int chunk_size);
int enhance_logging_by_username(const char *server_ip, const char *username);
int enhance_logging_by_account_id(const char *server_ip, int account_id);
int disable_enhanced_logging(const char *server_ip);
int get_enhanced_logging_status(const char *server_ip);

// Callback function for CURL to write response data
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response_ptr = (char **)userp;
    
    // Get current length of response
    size_t current_len = *response_ptr ? strlen(*response_ptr) : 0;
    
    // Reallocate to accommodate new data
    *response_ptr = realloc(*response_ptr, current_len + realsize + 1);
    if (*response_ptr == NULL) {
        printf("Error: Failed to allocate memory for response\n");
        return 0;
    }
    
    // Append new data to existing response
    memcpy(*response_ptr + current_len, contents, realsize);
    (*response_ptr)[current_len + realsize] = 0;
    
    return realsize;
}

// Function to query client status by account ID
int query_status_by_account_id(const char *server_ip, int account_id) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[256];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL
    snprintf(url, sizeof(url), "http://%s:%d/status?account_id=%d", 
             server_ip, REST_SERVER_PORT, account_id);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Response for Account ID %d:\n%s\n", account_id, response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    return 0;
}

// Function to query client status by username
int query_status_by_username(const char *server_ip, const char *username) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[512];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    // Build URL with URL-encoded username
    char *encoded_username = curl_easy_escape(curl, username, 0);
    snprintf(url, sizeof(url), "http://%s:%d/status?username=%s", 
             server_ip, REST_SERVER_PORT, encoded_username);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    printf("this is the curl request sent %s\n", url);
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        if (encoded_username) curl_free(encoded_username);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Response for Username '%s':\n%s\n", username, response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    if (encoded_username) curl_free(encoded_username);
    return 0;
}

// Function to query client logs by account ID with time filtering
int query_logs_by_account_id(const char *server_ip, int account_id, time_t start_time, time_t end_time) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[512];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL with command-line style query format
    char query[512];
    char *encoded_query;
    
    // Build the query string in the new format
    if (start_time > 0 && end_time > 0) {
        // FIX: Copy the struct tm values to avoid overwriting
        struct tm start_tm_copy;
        struct tm end_tm_copy;
        
        struct tm *temp_tm = localtime(&start_time);
        start_tm_copy = *temp_tm;  // Copy the struct
        
        temp_tm = localtime(&end_time);
        end_tm_copy = *temp_tm;    // Copy the struct
        
        snprintf(query, sizeof(query), "logs account_id %d start=\"%04d-%02d-%02d %02d:%02d\" end=\"%04d-%02d-%02d %02d:%02d\"",
                account_id,
                start_tm_copy.tm_year + 1900, start_tm_copy.tm_mon + 1, start_tm_copy.tm_mday, 
                start_tm_copy.tm_hour, start_tm_copy.tm_min,
                end_tm_copy.tm_year + 1900, end_tm_copy.tm_mon + 1, end_tm_copy.tm_mday, 
                end_tm_copy.tm_hour, end_tm_copy.tm_min);
    } else if (start_time > 0) {
        struct tm *start_tm = localtime(&start_time);
        snprintf(query, sizeof(query), "logs account_id %d start=\"%04d-%02d-%02d %02d:%02d\"",
                account_id,
                start_tm->tm_year + 1900, start_tm->tm_mon + 1, start_tm->tm_mday, 
                start_tm->tm_hour, start_tm->tm_min);
    } else if (end_time > 0) {
        struct tm *end_tm = localtime(&end_time);
        snprintf(query, sizeof(query), "logs account_id %d end=\"%04d-%02d-%02d %02d:%02d\"",
                account_id,
                end_tm->tm_year + 1900, end_tm->tm_mon + 1, end_tm->tm_mday, 
                end_tm->tm_hour, end_tm->tm_min);
    } else {
        snprintf(query, sizeof(query), "logs account_id %d", account_id);
    }
    
    // URL encode the query
    encoded_query = curl_easy_escape(curl, query, 0);
    snprintf(url, sizeof(url), "http://%s:%d/logs?q=%s", server_ip, REST_SERVER_PORT, encoded_query);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        if (encoded_query) curl_free(encoded_query);
        return -1;
    }
    
    // Print response in chunks if it's large
    if (response) {
        int response_len = strlen(response);
        if (response_len > 1000) {
            print_response_in_chunks(response, "Logs for Account ID", 1000);
        } else {
            printf("Logs for Account ID %d:\n%s\n", account_id, response);
        }
        free(response);
    }
    
    curl_easy_cleanup(curl);
    if (encoded_query) curl_free(encoded_query);
    return 0;
}


// Function to query client logs by username with time filtering
int query_logs_by_username(const char *server_ip, const char *username, time_t start_time, time_t end_time) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[512];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL with command-line style query format
    char query[512];
    char *encoded_query;
    
    // Build the query string in the new format
    if (start_time > 0 && end_time > 0) {
        // More robust approach: format each timestamp separately
        char start_str[32];
        char end_str[32];
        
        // Format start time
        struct tm *temp_tm = localtime(&start_time);
        snprintf(start_str, sizeof(start_str), "%04d-%02d-%02d %02d:%02d",
                temp_tm->tm_year + 1900, temp_tm->tm_mon + 1, temp_tm->tm_mday, 
                temp_tm->tm_hour, temp_tm->tm_min);
        
        // Format end time
        temp_tm = localtime(&end_time);
        snprintf(end_str, sizeof(end_str), "%04d-%02d-%02d %02d:%02d",
                temp_tm->tm_year + 1900, temp_tm->tm_mon + 1, temp_tm->tm_mday, 
                temp_tm->tm_hour, temp_tm->tm_min);
        
        // Debug output

        
        // Build final query using the pre-formatted strings
        snprintf(query, sizeof(query), "logs username %s start=\"%s\" end=\"%s\"",
                username, start_str, end_str);
                
    } else if (start_time > 0) {
        struct tm *start_tm = localtime(&start_time);
        snprintf(query, sizeof(query), "logs username %s start=\"%04d-%02d-%02d %02d:%02d\"",
                username,
                start_tm->tm_year + 1900, start_tm->tm_mon + 1, start_tm->tm_mday, 
                start_tm->tm_hour, start_tm->tm_min);
    } else if (end_time > 0) {
        struct tm *end_tm = localtime(&end_time);
        snprintf(query, sizeof(query), "logs username %s end=\"%04d-%02d-%02d %02d:%02d\"",
                username,
                end_tm->tm_year + 1900, end_tm->tm_mon + 1, end_tm->tm_mday, 
                end_tm->tm_hour, end_tm->tm_min);
    } else {
        snprintf(query, sizeof(query), "logs username %s", username);
    }
    
    
    // URL encode the query
    encoded_query = curl_easy_escape(curl, query, 0);
    snprintf(url, sizeof(url), "http://%s:%d/logs?q=%s", server_ip, REST_SERVER_PORT, encoded_query);
    printf("this is the curl request sent %s\n", url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        if (encoded_query) curl_free(encoded_query);
        return -1;
    }
    
    if (response) {
        int response_len = strlen(response);
        if (response_len > 1000) {
            print_response_in_chunks(response, "Logs for Username", 1000);
        } else {
            printf("Logs for Username '%s':\n%s\n", username, response);
        }
        free(response);
    }
    
    curl_easy_cleanup(curl);
    if (encoded_query) curl_free(encoded_query);
    return 0;
}

// Function to enhance logging for a specific username
int enhance_logging_by_username(const char *server_ip, const char *username) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[512];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL with URL-encoded username
    char *encoded_username = curl_easy_escape(curl, username, 0);
    snprintf(url, sizeof(url), "http://%s:%d/enhance?username=%s", 
             server_ip, REST_SERVER_PORT, encoded_username);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        if (encoded_username) curl_free(encoded_username);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Enhanced logging response for Username '%s':\n%s\n", username, response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    if (encoded_username) curl_free(encoded_username);
    return 0;
}

// Function to enhance logging for a specific account ID
int enhance_logging_by_account_id(const char *server_ip, int account_id) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[256];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL
    snprintf(url, sizeof(url), "http://%s:%d/enhance?account_id=%d", 
             server_ip, REST_SERVER_PORT, account_id);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Enhanced logging response for Account ID %d:\n%s\n", account_id, response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    return 0;
}

// Function to disable enhanced logging
int disable_enhanced_logging(const char *server_ip) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[256];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL
    snprintf(url, sizeof(url), "http://%s:%d/disable", server_ip, REST_SERVER_PORT);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Disable enhanced logging response:\n%s\n", response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    return 0;
}

// Function to get enhanced logging status
int get_enhanced_logging_status(const char *server_ip) {
    CURL *curl;
    CURLcode res;
    char *response = NULL;
    char url[256];
    
    // Initialize CURL
    curl = curl_easy_init();
    if (!curl) {
        printf("Error: Failed to initialize CURL\n");
        return -1;
    }
    
    // Build URL
    snprintf(url, sizeof(url), "http://%s:%d/status", server_ip, REST_SERVER_PORT);
    
    // Set up CURL options
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    // Perform the request
    res = curl_easy_perform(curl);
    
    if (res != CURLE_OK) {
        printf("Error: CURL request failed: %s\n", curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        if (response) free(response);
        return -1;
    }
    
    // Print response
    if (response) {
        printf("Enhanced logging status:\n%s\n", response);
        free(response);
    }
    
    curl_easy_cleanup(curl);
    return 0;
}

// Function to print large responses in chunks
void print_response_in_chunks(const char *response, const char *prefix, int chunk_size) {
    if (!response) return;
    
    int len = strlen(response);
    printf("%s (Total length: %d characters):\n", prefix, len);
    
    for (int i = 0; i < len; i += chunk_size) {
        int remaining = len - i;
        int current_chunk = (remaining < chunk_size) ? remaining : chunk_size;
        
        printf("--- Chunk %d-%d ---\n", i + 1, i + current_chunk);
        printf("%.*s\n", current_chunk, response + i);
        
        if (i + current_chunk < len) {
            printf("Press Enter to continue...");
            getchar();
        }
    }
    printf("--- End of response ---\n");
}

void print_help(void) {
    printf("\n=== Interactive REST Client ===\n");
    printf("Commands:\n");
    printf("  query username <username>  - Query status by username\n");
    printf("  query account <id>         - Query status by account ID\n");
    printf("  logs username <username> [time_params]  - Search logs by username\n");
    printf("  logs account <id> [time_params]        - Search logs by account ID\n");
    printf("  enhance username <username> - Enable enhanced logging for username\n");
    printf("  enhance account <id>        - Enable enhanced logging for account ID\n");
    printf("  disable                     - Disable enhanced logging\n");
    printf("  status                     - Show enhanced logging status\n");
    printf("  help                       - Show this help\n");
    printf("  quit                       - Exit the program\n");
    printf("  clear                      - Clear the screen\n");
    /*printf("\nExamples:\n");
    printf("  query username alice\n");
    printf("  query account 123\n");
    printf("  logs username alice\n");
    printf("  logs account 123\n");
    printf("  logs username sam start_time=1705331160\n");
    printf("  logs account 123 end_time=1705331400\n");
    printf("  logs username alice start_time=\"today 14:30\" end_time=\"today 15:30\"\n");
    printf("  logs username sam start_time=\"yesterday 18:06\"\n");
    printf("  logs account 123 end_time=\"2024-01-15 15:30\"\n");
    printf("  logs username john start_time=today\\ 18:06\n");
    printf("  logs account 456 end_time=1705331400\n");
    printf("\nTime Parameters:\n");
    printf("  start_time=<time>  - Get logs from this time to now\n");
    printf("  end_time=<time>    - Get logs from beginning to this time\n");
    printf("  Both parameters can be used together for a specific range\n");
    printf("\nTime Formats:\n");
    printf("  Human-readable: \"today 18:06\", \"yesterday 14:30\", \"2024-01-15 15:30\"\n");
    printf("  Unix timestamp: 1705331160 (numeric value)\n");
    printf("  Relative: \"2 hours ago\", \"1 day ago\", \"last week\"\n");
    printf("================================\n\n");*/
}

// Function to convert human-readable time to Unix timestamp
time_t parse_human_time(const char *time_str) {
    if (!time_str || strlen(time_str) == 0) {
        return 0;
    }
    
    // Trim whitespace
    while (*time_str == ' ' || *time_str == '\t') time_str++;
    char *end = (char*)time_str + strlen(time_str) - 1;
    while (end > time_str && (*end == ' ' || *end == '\t')) end--;
    *(end + 1) = '\0';
    
    // Check if it's already a Unix timestamp (numeric)
    if (strspn(time_str, "0123456789") == strlen(time_str)) {
        return (time_t)atol(time_str);
    }
    
    // Handle human-readable time strings
    char date_cmd[512];
    // Escape quotes and special characters for shell safety
    char escaped_time[256];
    unsigned int j = 0;
    for (int i = 0; time_str[i] && j < sizeof(escaped_time) - 1; i++) {
        if (time_str[i] == '"' || time_str[i] == '\\' || time_str[i] == '\'') {
            escaped_time[j++] = '\\';
        }
        escaped_time[j++] = time_str[i];
    }
    escaped_time[j] = '\0';
    
    // Try different date parsing approaches
    const char *date_formats[] = {
        "date -d '%s' +%%s 2>/dev/null",
        "date -d \"%s\" +%%s 2>/dev/null",
        NULL
    };
    
    for (int i = 0; date_formats[i] != NULL; i++) {
        snprintf(date_cmd, sizeof(date_cmd), date_formats[i], escaped_time);
        
        FILE *pipe = popen(date_cmd, "r");
        if (!pipe) {
            continue;
        }
        
        char result[64];
        if (fgets(result, sizeof(result), pipe) != NULL) {
            pclose(pipe);
            result[strcspn(result, "\n")] = 0;
            time_t timestamp = (time_t)atol(result);
            if (timestamp > 0) {
                return timestamp;
            }
        }
        
        pclose(pipe);
    }
    
    // If all parsing attempts failed, try some common patterns manually
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    
    if (strcmp(time_str, "now") == 0 || strcmp(time_str, "today") == 0) {
        return now;
    }
    
    if (strcmp(time_str, "yesterday") == 0) {
        return now - 86400; // 24 hours ago
    }
    
    // Try to parse "today HH:MM" or "yesterday HH:MM"
    int hour, minute;
    if (strncmp(time_str, "today ", 6) == 0) {
        if (sscanf(time_str + 6, "%d:%d", &hour, &minute) == 2) {
            struct tm tm_today = *tm_now;
            tm_today.tm_hour = hour;
            tm_today.tm_min = minute;
            tm_today.tm_sec = 0;
            return mktime(&tm_today);
        }
    }
    
    if (strncmp(time_str, "yesterday ", 10) == 0) {
        if (sscanf(time_str + 10, "%d:%d", &hour, &minute) == 2) {
            struct tm tm_yesterday = *tm_now;
            tm_yesterday.tm_mday -= 1;
            tm_yesterday.tm_hour = hour;
            tm_yesterday.tm_min = minute;
            tm_yesterday.tm_sec = 0;
            return mktime(&tm_yesterday);
        }
    }
    
    return 0;
}

// Function to convert Unix timestamp to human-readable form
char* format_human_time(time_t timestamp) {
    static char time_str[64];
    if (timestamp == 0) {
        strcpy(time_str, "beginning");
        return time_str;
    }
    
    struct tm *tm_info = localtime(&timestamp);
    if (!tm_info) {
        strcpy(time_str, "unknown");
        return time_str;
    }
    
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

// Function to parse time parameters from command
void parse_time_params(const char *time_str, time_t *start_time, time_t *end_time) {
    *start_time = 0;
    *end_time = 0;
    
    if (!time_str || strlen(time_str) == 0) {
        return;
    }
    
    // Parse start_time=value (use original string for finding)
    const char *start_token = strstr(time_str, "start=");
    if (start_token) {
        start_token += 6; // Skip "start="
        
        char start_value[128] = {0};
        
        // Handle quoted values
        if (*start_token == '"') {
            start_token++; // Skip opening quote
            const char *end_quote = strchr(start_token, '"');
            if (end_quote) {
                int len = end_quote - start_token;
                if (len < (int)sizeof(start_value)) {
                    strncpy(start_value, start_token, len);
                    start_value[len] = '\0';
                }
            }
        } else {
            // Handle unquoted values - find the end of the value
            const char *space = strchr(start_token, ' ');
            if (space) {
                int len = space - start_token;
                if (len < (int)sizeof(start_value)) {
                    strncpy(start_value, start_token, len);
                    start_value[len] = '\0';
                }
            } else {
                // No space found, use rest of string
                strncpy(start_value, start_token, sizeof(start_value) - 1);
            }
        }
        
        if (strlen(start_value) > 0) {
            *start_time = parse_human_time(start_value);
            if (*start_time > 0) {
                printf("DEBUG: Parsed start_time: %ld (%s)\n", *start_time, format_human_time(*start_time));
            } else {
                printf("DEBUG: Failed to parse start_time from '%s'\n", start_value);
            }
        }
    }
    
    // Parse end_time=value (use original string for finding)
    const char *end_token = strstr(time_str, "end=");
    if (end_token) {
        end_token += 4; // Skip "end="
        
        char end_value[128] = {0};
        
        // Handle quoted values
        if (*end_token == '"') {
            end_token++; // Skip opening quote
            const char *end_quote = strchr(end_token, '"');
            if (end_quote) {
                int len = end_quote - end_token;
                if (len < (int)sizeof(end_value)) {
                    strncpy(end_value, end_token, len);
                    end_value[len] = '\0';
                }
            }
        } else {
            // Handle unquoted values
            const char *space = strchr(end_token, ' ');
            if (space) {
                int len = space - end_token;
                if (len < (int)sizeof(end_value)) {
                    strncpy(end_value, end_token, len);
                    end_value[len] = '\0';
                }
            } else {
                // No space found, use rest of string
                strncpy(end_value, end_token, sizeof(end_value) - 1);
            }
        }
        
        if (strlen(end_value) > 0) {
            *end_time = parse_human_time(end_value);
            if (*end_time > 0) {
                printf("DEBUG: Parsed end_time: %ld (%s)\n", *end_time, format_human_time(*end_time));
            } else {
                printf("DEBUG: Failed to parse end_time from '%s'\n", end_value);
            }
        }
    }
}

void clear_screen(void) {
    printf("\033[2J\033[H");  // Clear screen and move cursor to top
}

void print_usage(const char *program_name) {
    printf("Usage: %s [config_file]\n", program_name);
    printf("  config_file: Optional server configuration file\n");
    printf("  Defaults to: configTools/serverConf.json\n");
    printf("  Fallback defaults: 127.0.0.1:8080\n\n");
    printf("Examples:\n");
    printf("  %s configTools/serverConf.json\n", program_name);
    printf("  %s\n", program_name);
}

int main(int argc, char *argv[]) {
    char *server_ip = "127.0.0.1";
    int rest_port = REST_SERVER_PORT;
    const char *config_file = "configTools/serverConf.json";
    
    // Check if config file is provided
    if (argc >= 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        config_file = argv[1];
    }
    
    // Try to load config file
    if (!init_server_config(config_file)) {
        printf("Failed to load config file: %s\n", config_file);
        printf("Using default values: %s:%d\n", server_ip, rest_port);
    } else {
        server_ip = get_server_ip();
        rest_port = get_rest_server_port();
        printf("Loaded config: Server %s:%d, REST %s:%d\n", 
               get_server_ip(), get_server_port(), server_ip, rest_port);
    }
    
    // Initialize CURL globally
    curl_global_init(CURL_GLOBAL_ALL);
    
    char input[512];
    char command[64];
    char query_type[32];
    char identifier[128];
    char time_params[256];
    
    print_help();
    
    printf("REST Client ready. Type 'help' for commands.\n");
    printf("Server: %s:%d\n\n", server_ip, rest_port);
    
    while (1) {
        printf("rest_client> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        // Parse command with optional time parameters (handle quotes properly)
        char *cmd_start = input;
        char *cmd_end = strchr(cmd_start, ' ');
        if (!cmd_end) {
            // Single command like "help" or "quit"
            strcpy(command, cmd_start);
            query_type[0] = '\0';
            identifier[0] = '\0';
            time_params[0] = '\0';
        } else {
            *cmd_end = '\0';
            strcpy(command, cmd_start);
            
            // Parse remaining arguments
            char *args = cmd_end + 1;
            char *arg1_end = strchr(args, ' ');
            if (arg1_end) {
                *arg1_end = '\0';
                strcpy(query_type, args);
                
                char *arg2_start = arg1_end + 1;
                char *arg2_end = strchr(arg2_start, ' ');
                if (arg2_end) {
                    *arg2_end = '\0';
                    strcpy(identifier, arg2_start);
                    strcpy(time_params, arg2_end + 1);
                } else {
                    strcpy(identifier, arg2_start);
                    time_params[0] = '\0';
                }
            } else {
                strcpy(query_type, args);
                identifier[0] = '\0';
                time_params[0] = '\0';
            }
        }
        
        if (strlen(command) > 0) {
            if (strcmp(command, "query") == 0) {
                if (strcmp(query_type, "username") == 0) {
                    if (strlen(identifier) > 0) {
                        printf("Querying username: %s\n", identifier);
                        query_status_by_username(server_ip, identifier);
                    } else {
                        printf("Error: Username not provided\n");
                    }
                } else if (strcmp(query_type, "account") == 0) {
                    int account_id = atoi(identifier);
                    if (account_id > 0) {
                        printf("Querying account ID: %d\n", account_id);
                        query_status_by_account_id(server_ip, account_id);
                    } else {
                        printf("Error: Invalid account ID '%s'\n", identifier);
                    }
                } else {
                    printf("Error: Invalid query type '%s'. Use 'username' or 'account'\n", query_type);
                }
            } else if (strcmp(command, "logs") == 0) {
                time_t start_time = 0, end_time = 0;
                parse_time_params(time_params, &start_time, &end_time);
                
                if (strcmp(query_type, "username") == 0) {
                    if (strlen(identifier) > 0) {
                        printf("Searching logs for username: %s", identifier);
                        if (start_time > 0) printf(" from %s", format_human_time(start_time));
                        if (end_time > 0) printf(" to %s", format_human_time(end_time));
                        if (start_time == 0 && end_time == 0) printf(" (all time)");
                        printf("\n");
                        query_logs_by_username(server_ip, identifier, start_time, end_time);
                    } else {
                        printf("Error: Username not provided for logs\n");
                    }
                } else if (strcmp(query_type, "account") == 0) {
                    int account_id = atoi(identifier);
                    if (account_id > 0) {
                        printf("Searching logs for account ID: %d", account_id);
                        if (start_time > 0) printf(" from %s", format_human_time(start_time));
                        if (end_time > 0) printf(" to %s", format_human_time(end_time));
                        if (start_time == 0 && end_time == 0) printf(" (all time)");
                        printf("\n");
                        query_logs_by_account_id(server_ip, account_id, start_time, end_time);
                    } else {
                        printf("Error: Invalid account ID '%s' for logs\n", identifier);
                    }
                } else {
                    printf("Error: Invalid query type '%s' for logs. Use 'username' or 'account'\n", query_type);
                }
            } else if (strcmp(command, "enhance") == 0) {
                if (strcmp(query_type, "username") == 0) {
                    if (strlen(identifier) > 0) {
                        printf("Enhancing logging for username: %s\n", identifier);
                        enhance_logging_by_username(server_ip, identifier);
                    } else {
                        printf("Error: Username not provided for enhance\n");
                    }
                } else if (strcmp(query_type, "account") == 0) {
                    int account_id = atoi(identifier);
                    if (account_id > 0) {
                        printf("Enhancing logging for account ID: %d\n", account_id);
                        enhance_logging_by_account_id(server_ip, account_id);
                    } else {
                        printf("Error: Invalid account ID '%s' for enhance\n", identifier);
                    }
                } else {
                    printf("Error: Invalid enhance type '%s'. Use 'username' or 'account'\n", query_type);
                }
            } else if (strcmp(command, "disable") == 0) {
                printf("Disabling enhanced logging...\n");
                disable_enhanced_logging(server_ip);
            } else if (strcmp(command, "status") == 0) {
                printf("Getting enhanced logging status...\n");
                get_enhanced_logging_status(server_ip);
            } else {
                printf("Error: Unknown command '%s'. Type 'help' for available commands.\n", command);
            }
        } else if (strcmp(input, "help") == 0) {
            print_help();
        } else if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
            printf("Goodbye!\n");
            break;
        } else if (strcmp(input, "clear") == 0) {
            clear_screen();
        } else if (strlen(input) == 0) {
            // Empty line, continue
            continue;
        } else {
            printf("Error: Invalid command. Type 'help' for available commands.\n");
        }
        
        printf("\n");
    }
    
    // Clean up CURL
    curl_global_cleanup();
    cleanup_server_config();
    
    return 0;
} 