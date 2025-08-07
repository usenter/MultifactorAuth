#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <microhttpd.h>

#include "../auth_system.h"
#include "../socketHandling/socketHandling.h"

// Function to parse human-readable timestamp
time_t parse_human_timestamp(const char *timestamp_str) {
    if (!timestamp_str || strlen(timestamp_str) == 0) {
        return 0;
    }
    
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    struct tm target_tm = *tm_now;
    
    // Parse "today HH:MM" format
    if (strncmp(timestamp_str, "today", 5) == 0) {
        int hour, minute;
        if (sscanf(timestamp_str + 5, " %d:%d", &hour, &minute) == 2) {
            target_tm.tm_hour = hour;
            target_tm.tm_min = minute;
            target_tm.tm_sec = 0;
            target_tm.tm_isdst = -1;
            return mktime(&target_tm);
        }
    }
    
    // Parse "yesterday HH:MM" format
    if (strncmp(timestamp_str, "yesterday", 9) == 0) {
        int hour, minute;
        if (sscanf(timestamp_str + 9, " %d:%d", &hour, &minute) == 2) {
            target_tm.tm_mday -= 1;
            target_tm.tm_hour = hour;
            target_tm.tm_min = minute;
            target_tm.tm_sec = 0;
            target_tm.tm_isdst = -1;
            return mktime(&target_tm);
        }
    }
    
    // Parse "now" format
    if (strcmp(timestamp_str, "now") == 0) {
        return now;
    }
    
    // Parse "YYYY-MM-DD HH:MM" format
    int year, month, day, hour, minute;
    if (sscanf(timestamp_str, "%d-%d-%d %d:%d", &year, &month, &day, &hour, &minute) == 5) {
        target_tm.tm_year = year - 1900;
        target_tm.tm_mon = month - 1;
        target_tm.tm_mday = day;
        target_tm.tm_hour = hour;
        target_tm.tm_min = minute;
        target_tm.tm_sec = 0;
        target_tm.tm_isdst = -1;
        time_t result = mktime(&target_tm);
        printf( "DEBUG: Parsed '%s' -> year=%d, month=%d, day=%d, hour=%d, min=%d -> timestamp=%ld\n", 
                timestamp_str, year, month, day, hour, minute, result);
        return result;
    }
    
    // Try to parse as Unix timestamp
    char *endptr;
    time_t timestamp = strtol(timestamp_str, &endptr, 10);
    if (*endptr == '\0') {
        return timestamp;
    }
    
    return 0;
}

// Function to format timestamp as human-readable string
char* format_human_time(time_t timestamp) {
    static char time_str[64];
    if (timestamp == 0) {
        strcpy(time_str, "never");
        return time_str;
    }
    
    struct tm *tm_info = localtime(&timestamp);
    if (!tm_info) {
        strcpy(time_str, "invalid");
        return time_str;
    }
    
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    return time_str;
}

// Function to parse timestamp from log line
time_t parse_log_timestamp(const char *line) {
    // Buffer to hold extracted timestamp string
    char timestamp_str[20]; // "YYYY-MM-DD HH:MM:SS" is 19 chars + null terminator
    
    // Extract timestamp from: [2025-08-06 23:30:11] [INFO][MAIN_THREAD] message
    const char *timestamp_start = strstr(line, "[");
    const char *timestamp_end = strstr(timestamp_start + 1, "]");
    
    if (!timestamp_start || !timestamp_end || (timestamp_end - timestamp_start - 1) != 19) {
        return (time_t)-1; // Return error code for invalid format
    }
    
    // Extract the timestamp string: "2025-08-06 23:30:11"
    strncpy(timestamp_str, timestamp_start + 1, 19);
    timestamp_str[19] = '\0'; // Null terminate the string
    
    // Parse using strptime
    struct tm tm_info = {0};
    if (strptime(timestamp_str, "%Y-%m-%d %H:%M:%S", &tm_info) == NULL) {
        return (time_t)-1; // Return error code for parsing failure
    }
    
    // Let mktime determine if DST applies
    tm_info.tm_isdst = -1;
    
    // Convert to Unix timestamp (already in system timezone)
    time_t result = mktime(&tm_info);
    return result;
}


// Function to check if log entry is within time range
int is_log_in_time_range(const char *line, time_t start_time, time_t end_time) {
    if (start_time == 0 && end_time == 0) {
        return 1;
    }
    time_t log_time = parse_log_timestamp(line);
    if (log_time == 0) {
        return 1; // If we can't parse timestamp, include it
    }
     // Add this error check!
     if (log_time == (time_t)-1) {
        printf( "ERROR: Failed to parse timestamp in line: %s\n", line);
        return 0; 
    }
    if (start_time > 0 && end_time > 0) {
        // Both times specified - check if log is in range
        int in_range = (log_time >= start_time && log_time <= end_time);
       
        return in_range;
    } else if (start_time > 0) {
        // Only start time specified - from start_time to now
        int in_range = (log_time >= start_time);
     
        return in_range;
    } else if (end_time > 0) {
        // Only end time specified - from beginning to end_time
        int in_range = (log_time <= end_time);
       
        return in_range;
    }
    return 1;
}

// Function to extract account_id from log line
int extract_account_id_from_line(const char *line) {
    const char *id_marker = strstr(line, "[ID:");
    if (!id_marker) return -1;
    
    const char *id_start = id_marker + 4; // Skip "[ID:"
    const char *id_end = strchr(id_start, ']');
    if (!id_end) return -1;
    
    return atoi(id_start);
}

// Function to search logs by account ID with time filtering
char* search_logs_by_account_id(unsigned int account_id, time_t start_time, time_t end_time) {
    FILE *log_file = fopen("server.log", "r");
    if (!log_file) {
        char *error = malloc(128);
        snprintf(error, 128, "{\"error\": \"Log file not found\", \"account_id\": %u}", account_id);
        return error;
    }
    
    char line[2048];
    int entry_count = 0;
    
    // Allocate buffer for JSON response
    char *json = malloc(1024*1024); // 1MB buffer
    if (!json) {
        fclose(log_file);
        return strdup("{\"error\": \"Memory allocation failed\"}");
    }
    
    // Start building JSON response
    int json_len = snprintf(json, 1024*1024, 
        "{\"account_id\": %u, \"log_entries\": [", account_id);
    printf( "DEBUG: Searching logs for account_id: %u, start_time: %ld, end_time: %ld\n", account_id, start_time, end_time);
    while (fgets(line, sizeof(line), log_file)) {
        int line_account_id = extract_account_id_from_line(line);
        if (line_account_id == (int)account_id) {
            if (is_log_in_time_range(line, start_time, end_time)) {
                line[strcspn(line, "\n")] = 0;
                char escaped_line[4096];
                unsigned int j = 0;
                for (int i = 0; line[i] && j < sizeof(escaped_line) - 1; i++) {
                    if (line[i] == '"' || line[i] == '\\') {
                        escaped_line[j++] = '\\';
                    }
                    escaped_line[j++] = line[i];
                }
                escaped_line[j] = '\0';
                
                if (entry_count > 0) {
                    json_len += snprintf(json + json_len, 1024*1024 - json_len, ",\n");
                }
                json_len += snprintf(json + json_len, 1024*1024 - json_len, "\"%s\"", escaped_line);
                entry_count++;
            }
        }
        
    }
    fclose(log_file);
    // Add time range info if specified
    // Add time range info if specified
    char time_info[256] = "";
    if (start_time > 0 || end_time > 0) {
        if (start_time > 0 && end_time > 0) {
            // Format each timestamp separately to avoid static buffer conflicts
            char start_str[32];
            char end_str[32];
            
            // Format start time
            struct tm *temp_tm = localtime(&start_time);
            snprintf(start_str, sizeof(start_str), "%04d-%02d-%02d %02d:%02d:%02d",
                    temp_tm->tm_year + 1900, temp_tm->tm_mon + 1, temp_tm->tm_mday,
                    temp_tm->tm_hour, temp_tm->tm_min, temp_tm->tm_sec);
            
            // Format end time
            temp_tm = localtime(&end_time);
            snprintf(end_str, sizeof(end_str), "%04d-%02d-%02d %02d:%02d:%02d",
                    temp_tm->tm_year + 1900, temp_tm->tm_mon + 1, temp_tm->tm_mday,
                    temp_tm->tm_hour, temp_tm->tm_min, temp_tm->tm_sec);
            
            snprintf(time_info, sizeof(time_info), 
                ", \"time_range\": {\"start\": \"%s\", \"end\": \"%s\"}", 
                start_str, end_str);
                
        } else if (start_time > 0) {
            struct tm *start_tm = localtime(&start_time);
            snprintf(time_info, sizeof(time_info), 
                ", \"time_range\": {\"start\": \"%04d-%02d-%02d %02d:%02d:%02d\", \"end\": \"now\"}",
                start_tm->tm_year + 1900, start_tm->tm_mon + 1, start_tm->tm_mday,
                start_tm->tm_hour, start_tm->tm_min, start_tm->tm_sec);
        } else if (end_time > 0) {
            struct tm *end_tm = localtime(&end_time);
            snprintf(time_info, sizeof(time_info), 
                ", \"time_range\": {\"start\": \"beginning\", \"end\": \"%04d-%02d-%02d %02d:%02d:%02d\"}",
                end_tm->tm_year + 1900, end_tm->tm_mon + 1, end_tm->tm_mday,
                end_tm->tm_hour, end_tm->tm_min, end_tm->tm_sec);
        }
    }

    
    snprintf(json + json_len, 1024*1024 - json_len, 
        "\n], \"entry_count\": %d%s}", entry_count, time_info);
    
    return json;
}

// Function to search logs by username with time filtering
char* search_logs_by_username(const char *username, time_t start_time, time_t end_time) {
    // First find the account_id for this username
    username_t *username_entry = NULL;
    pthread_mutex_lock(&user_map_mutex);
    HASH_FIND_STR(username_map, username, username_entry);
    pthread_mutex_unlock(&user_map_mutex);
    
    if (!username_entry) {
        char *error = malloc(128);
        snprintf(error, 128, "{\"error\": \"User not found\", \"username\": \"%s\"}", username);
        return error;
    }
    // Now search logs by account_id (more efficient)
    char *result = search_logs_by_account_id(username_entry->account_id, start_time, end_time);
    
    // Modify the JSON to include username info
    if (result && strstr(result, "\"account_id\":")) {
        // Find the account_id field and add username after it
        char *account_id_pos = strstr(result, "\"account_id\":");
        if (account_id_pos) {
            char *comma_pos = strchr(account_id_pos, ',');
            if (comma_pos) {
                // Calculate new size needed
                int username_addition_len = strlen(username) + 20; // ", \"username\": \"USERNAME\""
                char *new_result = malloc(strlen(result) + username_addition_len + 1);
                if (new_result) {
                    // Copy up to the comma after account_id
                    int prefix_len = comma_pos - result;
                    strncpy(new_result, result, prefix_len);
                    
                    // Add username field
                    snprintf(new_result + prefix_len, username_addition_len + 1, 
                            ", \"username\": \"%s\"", username);
                    
                    // Copy the rest
                    strcat(new_result, comma_pos);
                    
                    free(result);
                    result = new_result;
                }
            }
        }
    }
    
    return result;
}

// Function to convert auth_flags_t to human-readable status string
const char* get_auth_status_string(auth_flags_t auth_status) {
    if (auth_status == AUTH_NONE) {
        return "disconnected";
    } else if (auth_status == AUTH_FULLY_AUTHENTICATED) {
        return "fully_authenticated";
    } else if (auth_status & AUTH_STATUS_LOCKED) {
        return "locked_out";
    } else if (auth_status & AUTH_EMAIL) {
        return "email_verified";
    } else if (auth_status & AUTH_PASSWORD) {
        return "password_verified";
    } else if (auth_status & AUTH_RSA) {
        return "rsa_authenticated";
    } else {
        return "unknown";
    }
}

// Function to get user status as JSON string
char* get_user_status_json(unsigned int account_id, const char *username) {
    session_t *session = find_session(account_id);
    user_t *user = find_user(account_id);
    
    if (!user) {
        char *error = malloc(128);
        snprintf(error, 128, "{\"error\": \"User not found\", \"account_id\": %u}", account_id);
        return error;
    }
    
    auth_flags_t auth_status = session ? session->auth_status : AUTH_NONE;
    const char *status_str = get_auth_status_string(auth_status);
    
    char *json = malloc(512);
    if (!json) {
        return strdup("{\"error\": \"Memory allocation failed\"}");
    }
    
    if (username) {
        snprintf(json, 512, 
            "{\"username\": \"%s\", \"account_id\": %u, \"status\": \"%s\", \"last_seen\": \"%s\", \"auth_flags\": %d}", 
            username, account_id, status_str, 
            session ? format_human_time(session->login_time) : "never",
            auth_status);
    } else {
        snprintf(json, 512, 
            "{\"account_id\": %u, \"username\": \"%s\", \"status\": \"%s\", \"last_seen\": \"%s\", \"auth_flags\": %d}", 
            account_id, user->username, status_str,
            session ? format_human_time(session->login_time) : "never",
            auth_status);
    }
    
    return json;
}

// Function to parse command-line style query
typedef struct {
    char username[64];
    unsigned int account_id;
    time_t start_time;
    time_t end_time;
    int valid;
    int use_account_id; // 1 if account_id specified, 0 if username specified
} log_query_t;

// Helper function to skip whitespace
static char* skip_whitespace(char *str) {
    while (*str == ' ' || *str == '\t') str++;
    return str;
}

// Helper function to parse quoted values for timestamps
static char* parse_quoted_value(char *current_pos, time_t *time_result) {
    if (*current_pos == '"') {
        current_pos++; // Skip opening quote
        
        // Find the matching closing quote, being careful about the search
        char *end_quote = current_pos;
        while (*end_quote && *end_quote != '"') {
            end_quote++;
        }
        
        if (*end_quote == '"') {
            // Create a temporary buffer to hold the extracted string
            int len = end_quote - current_pos;
            char temp_buffer[256]; // Adjust size as needed
            
            if (len < sizeof(temp_buffer)) {
                strncpy(temp_buffer, current_pos, len);
                temp_buffer[len] = '\0';
                
                *time_result = parse_human_timestamp(temp_buffer);
            }
            
            current_pos = end_quote + 1; // Move past closing quote
        }
    } else {
        // Handle unquoted values (until space or end)
        char *end = current_pos;
        while (*end && *end != ' ') end++;
        
        if (end > current_pos) {
            int len = end - current_pos;
            char temp_buffer[256];
            
            if (len < sizeof(temp_buffer)) {
                strncpy(temp_buffer, current_pos, len);
                temp_buffer[len] = '\0';
                
                *time_result = parse_human_timestamp(temp_buffer);
            }
            
            current_pos = end;
        }
    }
    return current_pos;
}

log_query_t parse_log_query(const char *query) {
    log_query_t result = {0};
    
    if (!query) {
        return result;
    }
    printf("DEBUG: Parsing query: %s\n", query);
    char *query_copy = strdup(query);
    if (!query_copy) {
        return result; // Memory allocation failed
    }
    
    char *current_pos = query_copy;
    
    // Skip "logs" if present
    current_pos = skip_whitespace(current_pos);
    if (strncmp(current_pos, "logs", 4) == 0 && 
        (current_pos[4] == ' ' || current_pos[4] == '\0')) {
        current_pos += 4;
    }
    
    // Parse the entire query manually (no strtok)
    while (*current_pos) {
        current_pos = skip_whitespace(current_pos);
        if (!*current_pos) break;
        
        if (strncmp(current_pos, "username", 8) == 0 && 
            (current_pos[8] == ' ' || current_pos[8] == '\0')) {
            current_pos += 8;
            current_pos = skip_whitespace(current_pos);
            
            // Extract username (until next space or end)
            char *end = current_pos;
            while (*end && *end != ' ') end++;
            
            int len = end - current_pos;
            if (len > 0 && len < (int)sizeof(result.username)) {
                strncpy(result.username, current_pos, len);
                result.username[len] = '\0';
                result.valid = 1;
                result.use_account_id = 0;
            }
            current_pos = end;
            
        } else if (strncmp(current_pos, "account_id", 10) == 0 && 
                   (current_pos[10] == ' ' || current_pos[10] == '\0')) {
            current_pos += 10;
            current_pos = skip_whitespace(current_pos);
            
            // Extract account ID
            char *end = current_pos;
            while (*end && *end != ' ') end++;
            
            int len = end - current_pos;
            if (len > 0 && len < 32) {
                char idbuf[32] = {0};
                strncpy(idbuf, current_pos, len);
                result.account_id = atoi(idbuf);
                result.valid = 1;
                result.use_account_id = 1;
            }
            current_pos = end;
            
        } else if (strncmp(current_pos, "start=", 6) == 0) {
            current_pos += 6;
            current_pos = parse_quoted_value(current_pos, &result.start_time);
            current_pos = skip_whitespace(current_pos);
            
        } else if (strncmp(current_pos, "end=", 4) == 0) {
            current_pos += 4;
            current_pos = parse_quoted_value(current_pos, &result.end_time);
        } else {
            // Skip unknown token
            while (*current_pos && *current_pos != ' ') current_pos++;
        }
    }
    free(query_copy);
    return result;
}




// REST API request handler
static enum MHD_Result rest_request_handler(void *cls, struct MHD_Connection *connection,
                                          const char *url, const char *method,
                                          const char *version, const char *upload_data,
                                          size_t *upload_data_size, void **con_cls) {
    (void)cls; (void)version; (void)upload_data;
    static int dummy;
    struct MHD_Response *response;
    int ret;
    printf("DEBUG: REST API request handler called for URL: %s\n", url);
    if (&dummy != *con_cls) {
        *con_cls = &dummy;
        return MHD_YES;
    }
    
    if (0 != *upload_data_size)
        return MHD_NO;
    
    // Handle only GET requests
    if (strcmp(method, "GET") != 0) {
        const char *error_msg = "{\"error\": \"Method not allowed\"}";
        printf("DEBUG: Method not allowed\n");
        response = MHD_create_response_from_buffer(strlen(error_msg),
                                                 (void*)error_msg,
                                                 MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Content-Type", "application/json");
        ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
        MHD_destroy_response(response);
        return ret;
    }
    
    // Handle /status endpoint
    if (strncmp(url, "/status", 7) == 0) {
        printf("DEBUG: Handling /status endpoint\n");
        const char *account_id_param = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "account_id");
        const char *username_param = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "username");
        
        char *json_response = NULL;
        
        if (account_id_param) {
            unsigned int account_id = atoi(account_id_param);
            json_response = get_user_status_json(account_id, NULL);
        } else if (username_param) {
            // Find account_id for username and return status
            username_t *username_entry = NULL;
            pthread_mutex_lock(&user_map_mutex);
            HASH_FIND_STR(username_map, username_param, username_entry);
            pthread_mutex_unlock(&user_map_mutex);
            
            if (username_entry) {
                json_response = get_user_status_json(username_entry->account_id, username_param);
            } else {
                json_response = malloc(128);
                if (json_response) {
                    snprintf(json_response, 128, "{\"error\": \"User not found\", \"username\": \"%s\"}", username_param);
                }
            }
        } else {
            json_response = strdup("{\"error\": \"Missing parameter. Use account_id or username\"}");
        }
        
        if (json_response) {
            response = MHD_create_response_from_buffer(strlen(json_response),
                                                     (void*)json_response,
                                                     MHD_RESPMEM_MUST_FREE);
            MHD_add_response_header(response, "Content-Type", "application/json");
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            return ret;
        }
    }
    
    // Handle /logs endpoint with command-line style query
    if (strncmp(url, "/logs", 5) == 0) {
        const char *query_param = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "q");
        if (!query_param) {
            const char *help_msg = "{"
                "\"error\": \"Missing query parameter\","
                "\"usage\": \"GET /logs?q=QUERY_STRING\","
                "\"examples\": ["
                    "\"logs username sam start=\\\"today 19:30\\\" end=\\\"today 20:00\\\"\","
                    "\"logs account_id 19 start=\\\"yesterday 10:00\\\"\","
                    "\"logs username zoey\","
                    "\"logs account_id 20 end=\\\"now\\\"\""
                "],"
                "\"time_formats\": ["
                    "\"today HH:MM\","
                    "\"yesterday HH:MM\","
                    "\"YYYY-MM-DD HH:MM\","
                    "\"now\","
                    "\"unix_timestamp\""
                "]"
                "}";
            response = MHD_create_response_from_buffer(strlen(help_msg),
                                                     (void*)help_msg,
                                                     MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            return ret;
        }
        
        log_query_t query = parse_log_query(query_param);
        
     
        
        if (!query.valid || (query.use_account_id == 0 && strlen(query.username) == 0) || 
            (query.use_account_id == 1 && query.account_id == 0)) {
            const char *error_msg = "{\"error\": \"Invalid query format. Expected: logs [username USERNAME | account_id ID] [start=\\\"TIME\\\"] [end=\\\"TIME\\\"]\"}";
            response = MHD_create_response_from_buffer(strlen(error_msg),
                                                     (void*)error_msg,
                                                     MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header(response, "Content-Type", "application/json");
            ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
            MHD_destroy_response(response);
            return ret;
        }
        
        char *json_response = NULL;
        if (query.use_account_id) {
            json_response = search_logs_by_account_id(query.account_id, query.start_time, query.end_time);
        } else {
            json_response = search_logs_by_username(query.username, query.start_time, query.end_time);
        }
        
        if (json_response) {
            response = MHD_create_response_from_buffer(strlen(json_response),
                                                     (void*)json_response,
                                                     MHD_RESPMEM_MUST_FREE);
            MHD_add_response_header(response, "Content-Type", "application/json");
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
            ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);
            return ret;
        }
    }
    
    // 404 for unknown endpoints
    const char *error_msg = "{\"error\": \"Not found\", \"available_endpoints\": [\"/logs\"]}";
    response = MHD_create_response_from_buffer(strlen(error_msg),
                                             (void*)error_msg,
                                             MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(response, "Content-Type", "application/json");
    ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response(response);
    return ret;
}

// Function to start REST API server
struct MHD_Daemon* start_rest_server(int port) {
    printf("DEBUG: Starting REST API server on port %d\n", port);
    return MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL,
                           &rest_request_handler, NULL,
                           MHD_OPTION_END);
}