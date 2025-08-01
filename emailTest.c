#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <time.h>
#include "emailTest.h"

int useJSON = 1;  // If this is not set to 1, you need to define the emailFrom variable
const char* emailConfigFile = "emailConfig.json";
const char* emailFrom = "noreply@example.com";
// Define all email lines
const char *payload_text[] = {
    "To: recipient@example.com\r\n",
    "From: your-email@gmail.com\r\n",
    "Subject: Test Email from C Program\r\n",
    "\r\n", // empty line header/body separator
    "This is a test email sent from a C program using libcurl!\r\n",
    NULL
};

char* format_email_content(emailContent_t* payload, const char* from_email) {
    if (!payload || !payload->TO || !payload->subject || !payload->body || !from_email) {
        printf("Invalid payload or missing required fields\n");
        return NULL;
    }
    
    // Calculate required buffer size
    size_t total_size = strlen("To: ") + strlen(payload->TO) + strlen("\r\n") +
                       strlen("From: ") + strlen(from_email) + strlen("\r\n") +
                       strlen("Subject: ") + strlen(payload->subject) + strlen("\r\n") +
                       strlen("\r\n") + // empty line separator
                       strlen(payload->body) + strlen("\r\n") + 1;
    
    char* content = (char*)malloc(total_size);
    if (!content) {
        printf("Failed to allocate memory for email content\n");
        return NULL;
    }
    
    // Format the email content
    snprintf(content, total_size, 
             "To: %s\r\n"
             "From: %s\r\n"
             "Subject: %s\r\n"
             "\r\n"
             "%s\r\n",
             payload->TO, from_email, payload->subject, payload->body);
    
    return content;
}

int read_credentials_json(const char *filename, emailContent_t* payload) {
    if (!payload) return 1;
    
    FILE *file = fopen(filename, "rb");
    if (!file) return 1;

    fseek(file, 0, SEEK_END);
    long flen = ftell(file);
    rewind(file);

    char *data = (char*)malloc(flen + 1);
    if (!data) { fclose(file); return 2; }

    fread(data, 1, flen, file);
    data[flen] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) return 3;

    const cJSON *js_receiver = cJSON_GetObjectItemCaseSensitive(json, "receiver");
    const cJSON *js_subject = cJSON_GetObjectItemCaseSensitive(json, "subject");
    const cJSON *js_body = cJSON_GetObjectItemCaseSensitive(json, "body");
   
    if (!cJSON_IsString(js_receiver)) {
        cJSON_Delete(json);
        return 4;
    }
    
    // Populate the emailContent_t struct with content fields
    payload->TO = strdup(js_receiver->valuestring);
    
    // Handle optional subject and body
    if (cJSON_IsString(js_subject)) {
        payload->subject = strdup(js_subject->valuestring);
    } else {
        payload->subject = strdup("No Subject");
    }
    
    if (cJSON_IsString(js_body)) {
        payload->body = strdup(js_body->valuestring);
    } else {
        payload->body = strdup("No body content");
    }
   
    cJSON_Delete(json);
    return 0;
}

int read_credentials_json_full(const char *filename, char** from_email, char** to_email, char** password) {
    if (!from_email || !to_email || !password) return 1;
    
    FILE *file = fopen(filename, "rb");
    if (!file) return 1;

    fseek(file, 0, SEEK_END);
    long flen = ftell(file);
    rewind(file);

    char *data = (char*)malloc(flen + 1);
    if (!data) { fclose(file); return 2; }

    fread(data, 1, flen, file);
    data[flen] = '\0';
    fclose(file);

    cJSON *json = cJSON_Parse(data);
    free(data);
    if (!json) return 3;

    const cJSON *js_sender = cJSON_GetObjectItemCaseSensitive(json, "sender");
    const cJSON *js_receiver = cJSON_GetObjectItemCaseSensitive(json, "receiver");
    const cJSON *js_password = cJSON_GetObjectItemCaseSensitive(json, "password");
   
    if (!cJSON_IsString(js_sender) || !cJSON_IsString(js_receiver) || !cJSON_IsString(js_password)) {
        cJSON_Delete(json);
        return 4;
    }
    
    // Populate the email credentials
    *from_email = strdup(js_sender->valuestring);
    *to_email = strdup(js_receiver->valuestring);
    *password = strdup(js_password->valuestring);
   
    cJSON_Delete(json);
    return 0;
}

void cleanup_email_content(emailContent_t* payload) {
    if (!payload) return;
    
    if (payload->TO) {
        free(payload->TO);
        payload->TO = NULL;
    }
    if (payload->subject) {
        free(payload->subject);
        payload->subject = NULL;
    }
    if (payload->body) {
        free(payload->body);
        payload->body = NULL;
    }
}

// Keep track of current position in email content
struct upload_status {
    char* email_content;
    size_t content_length;
    size_t bytes_sent;
};

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp) {
    struct upload_status *upload_ctx = (struct upload_status *)userp;
    
    if (upload_ctx->bytes_sent >= upload_ctx->content_length) {
        return 0; // no more data to send
    }
    
    size_t remaining = upload_ctx->content_length - upload_ctx->bytes_sent;
    size_t to_send = (remaining < size * nmemb) ? remaining : size * nmemb;
    
    memcpy(ptr, upload_ctx->email_content + upload_ctx->bytes_sent, to_send);
    upload_ctx->bytes_sent += to_send;
    
    return to_send;
}

void send_email(emailContent_t* payload) {
    if (!payload) {
        printf("Error: NULL payload provided to send_email\n");
        return;
    }

    // Validate that we have all required fields from the struct
    if (!payload->TO || !payload->subject || !payload->body) {
        printf("Error: Missing required email fields (TO, subject, or body)\n");
        return;
    }

    CURL *curl;
    CURLcode res;
    struct curl_slist *recipients = NULL;
    struct upload_status upload_ctx;

    // Internal variables for FROM and PASSWORD
    char* from_email = NULL;
    char* password = NULL;
    char* to_email = NULL;

    // Load credentials based on useJSON flag
    if (useJSON) {
        // Load FROM, TO, and PASSWORD from JSON file
        int result = read_credentials_json_full(emailConfigFile, &from_email, &to_email, &password);
        if (result != 0) {
            printf("Failed to read credentials from JSON (error code: %d)\n", result);
            return;
        }
        printf("Loaded credentials from JSON file\n");
    } else {
        // Use global emailFrom and load password from JSON, but use payload->TO
        from_email = strdup(emailFrom);
        to_email = strdup(payload->TO); // Use the TO from the struct
        int result = read_credentials_json_full(emailConfigFile, NULL, NULL, &password);
        if (result != 0) {
            printf("Failed to read password from JSON (error code: %d)\n", result);
            free(from_email);
            return;
        }
        printf("Using global FROM and struct TO\n");
    }

    // Format email content from the struct
    char* email_content = format_email_content(payload, from_email);
    if (!email_content) {
        printf("Failed to format email content\n");
        free(from_email);
        free(to_email);
        free(password);
        return;
    }

    // Initialize upload context
    upload_ctx.email_content = email_content;
    upload_ctx.content_length = strlen(email_content);
    upload_ctx.bytes_sent = 0;
   
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, from_email);
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from_email);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
       
        recipients = curl_slist_append(recipients, to_email);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);

        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));
        } else {
            printf("Email sent successfully!\n");
        }

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }

    // Clean up all allocated memory
    free(email_content);
    free(from_email);
    free(to_email);
    free(password);
}

// Email token authentication functions
int generate_email_token(char* token) {
    if (!token) return 0;
    
    // Generate a random 6-digit token
    srand(time(NULL));
    int code = rand() % 1000000;
    snprintf(token, 7, "%06d", code);
    return 1;
}

int send_email_token_to_user(const char* username, const char* email, const char* token) {
    if (!username || !email || !token) return 0;
    
    emailContent_t *email_payload = malloc(sizeof(emailContent_t));
    if (!email_payload) return 0;
    
    memset(email_payload, 0, sizeof(emailContent_t));
    email_payload->TO = strdup(email);
    email_payload->subject = strdup("Authentication Token");
    
    char body[1024];
    snprintf(body, sizeof(body), 
             "Hello %s,\n\nYour authentication token is: %s\n\n"
             "Please enter this token to complete your login.\n"
             "This token will expire in 10 minutes.\n\n"
             "If you did not request this token, please ignore this email.",
             username, token);
    
    email_payload->body = strdup(body);
    
    send_email(email_payload);
    cleanup_email_content(email_payload);
    free(email_payload);
    
    return 1;
}

/*
// Example usage for the new email system:

// For testing with single email (useJSON = 1):
// 1. Create emailConfig.json with:
//    {
//      "sender": "your_email@gmail.com",
//      "receiver": "your_email@gmail.com", 
//      "password": "your_app_password"
//    }
//
// 2. Use the email system:
emailContent_t email = {0};
email.subject = strdup("Test Subject");
email.body = strdup("Test email body");
send_email(&email);
cleanup_email_content(&email);

// For production with different recipient (useJSON = 0):
// 1. Set useJSON = 0
// 2. Set emailFrom global variable
// 3. Use the email system:
emailContent_t email = {0};
email.TO = strdup("recipient@example.com");
email.subject = strdup("Test Subject");
email.body = strdup("Test email body");
send_email(&email);
cleanup_email_content(&email);
*/

