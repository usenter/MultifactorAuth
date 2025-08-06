#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <curl/curl.h>

#define REST_SERVER_PORT 8080
#define BUFFER_SIZE 4096

// Callback function for CURL to write response data
size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    char **response_ptr = (char **)userp;
    
    *response_ptr = realloc(*response_ptr, realsize + 1);
    if (*response_ptr == NULL) {
        printf("Error: Failed to allocate memory for response\n");
        return 0;
    }
    
    memcpy(*response_ptr, contents, realsize);
    (*response_ptr)[realsize] = 0;
    
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

void print_usage(const char *program_name) {
    printf("Usage: %s <server_ip> <query_type> <identifier>\n", program_name);
    printf("  server_ip: IP address of the server\n");
    printf("  query_type: 'account' or 'username'\n");
    printf("  identifier: account ID (if query_type is 'account') or username (if query_type is 'username')\n\n");
    printf("Examples:\n");
    printf("  %s 127.0.0.1 account 123\n", program_name);
    printf("  %s 127.0.0.1 username alice\n", program_name);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *server_ip = argv[1];
    const char *query_type = argv[2];
    const char *identifier = argv[3];
    
    // Initialize CURL globally
    curl_global_init(CURL_GLOBAL_ALL);
    
    int result = -1;
    
    if (strcmp(query_type, "account") == 0) {
        int account_id = atoi(identifier);
        if (account_id <= 0) {
            printf("Error: Invalid account ID '%s'\n", identifier);
            return 1;
        }
        result = query_status_by_account_id(server_ip, account_id);
    } else if (strcmp(query_type, "username") == 0) {
        result = query_status_by_username(server_ip, identifier);
    } else {
        printf("Error: Invalid query type '%s'. Use 'account' or 'username'\n", query_type);
        print_usage(argv[0]);
        return 1;
    }
    
    // Clean up CURL
    curl_global_cleanup();
    
    return result;
} 