#include <stdio.h>
#include <string.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdlib.h>
#include <time.h>
#include "emailHandlingOperations.h"

const char* emailFrom = "noreply@example.com";

// Global email configuration (loaded once and cached)
email_config_t email_config = {NULL, NULL, NULL, NULL, 465, 1, 600, 1, 0};
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

int read_credentials_json_full(const char *filename, char** from_email, char** password, int* useJSON, char** bcc, int* emailTokenExpiry, char** smtpServer, int* smtpPort, int* useSSL) {
    if (!from_email ||  !password) return 1;
    
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
    const cJSON *js_useJSON = cJSON_GetObjectItemCaseSensitive(json, "useJSON");
    const cJSON *js_bcc = cJSON_GetObjectItemCaseSensitive(json, "bcc");
    const cJSON *js_emailTokenExpiry = cJSON_GetObjectItemCaseSensitive(json, "emailTokenExpiry");
    const cJSON *js_smtpServer = cJSON_GetObjectItemCaseSensitive(json, "smtpServer");
    const cJSON *js_smtpPort = cJSON_GetObjectItemCaseSensitive(json, "smtpPort");
    const cJSON *js_useSSL = cJSON_GetObjectItemCaseSensitive(json, "useSSL");
    
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][EMAIL_FUNCTION] js_sender: %s\n", js_sender->valuestring);
    snprintf(log_message, sizeof(log_message), "[INFO][EMAIL_FUNCTION] js_receiver: %s\n", js_receiver->valuestring);
    snprintf(log_message, sizeof(log_message), "[INFO][EMAIL_FUNCTION] js_password: %s\n", js_password->valuestring);
    
    // Check required fields
    if (!cJSON_IsString(js_sender) || !cJSON_IsString(js_receiver) || !cJSON_IsString(js_password)) {
        cJSON_Delete(json);
        return 4;
    }
    
    // Populate the email credentials
    *from_email = strdup(js_sender->valuestring);
    *password = strdup(js_password->valuestring);
    
    // Handle useJSON setting (optional, defaults to 1)
    if (useJSON && cJSON_IsNumber(js_useJSON)) {
        *useJSON = js_useJSON->valueint;
    } else {
        *useJSON = 1; // Default to JSON mode
    }
    
    // Handle BCC setting (optional)
    if (bcc && cJSON_IsString(js_bcc)) {
        *bcc = strdup(js_bcc->valuestring);
    } else if (bcc) {
        *bcc = NULL; // No BCC if not specified
    }
    

    
    // Handle emailTokenExpiry setting (optional, defaults to 600 seconds)
    if (emailTokenExpiry && cJSON_IsNumber(js_emailTokenExpiry)) {
        *emailTokenExpiry = js_emailTokenExpiry->valueint;
    } else if (emailTokenExpiry) {
        *emailTokenExpiry = 600; // Default to 10 minutes
    }
    
    // Handle SMTP server setting (optional, defaults to smtp.gmail.com)
    if (smtpServer && cJSON_IsString(js_smtpServer)) {
        *smtpServer = strdup(js_smtpServer->valuestring);
    } else if (smtpServer) {
        *smtpServer = strdup("smtp.gmail.com"); // Default SMTP server
    }
    
    // Handle SMTP port setting (optional, defaults to 465)
    if (smtpPort && cJSON_IsNumber(js_smtpPort)) {
        *smtpPort = js_smtpPort->valueint;
    } else if (smtpPort) {
        *smtpPort = 465; // Default SMTP port
    }
    
    // Handle useSSL setting (optional, defaults to true)
    if (useSSL && cJSON_IsBool(js_useSSL)) {
        *useSSL = js_useSSL->valueint;
    } else if (useSSL) {
        *useSSL = 1; // Default to using SSL
    }
   
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

char* send_email(emailContent_t* payload) {
    if (!payload) {
        return ("[ERROR]NULL payload provided to send_email\n");
    }

    // Validate that we have all required fields from the struct
    if (!payload->TO || !payload->subject || !payload->body) {
        return ("[ERROR]Missing required email fields (TO, subject, or body)\n");
    }

    CURL *curl;
    CURLcode res;
    struct curl_slist *recipients = NULL;
    struct upload_status upload_ctx;

    // Check if email config is loaded
    if (!is_email_config_loaded()) {
        return ("[ERROR]Email config not loaded. Call init_email_config() first.\n");
    }

    // Use cached credentials based on useJSON setting
    char* from_email = NULL;
    char* password = strdup(email_config.password);
    
    if (email_config.useJSON) {
        // Use sender from config file
        from_email = strdup(email_config.from_email);
    } else {
        // Use hardcoded sender
        from_email = strdup(emailFrom);
    }

    // Format email content from the struct
    char* email_content = format_email_content(payload, from_email);
    if (!email_content) {
        free(from_email);
        free(password);
        return ("[ERROR]Failed to format email content\n");
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
        
        // Build SMTP URL based on config
        char smtp_url[256];
        if (email_config.useSSL) {
            snprintf(smtp_url, sizeof(smtp_url), "smtps://%s:%d", email_config.smtp_server, email_config.smtp_port);
        } else {
            snprintf(smtp_url, sizeof(smtp_url), "smtp://%s:%d", email_config.smtp_server, email_config.smtp_port);
        }
        curl_easy_setopt(curl, CURLOPT_URL, smtp_url);
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);
       
        recipients = curl_slist_append(recipients, payload->TO);
        
        // Add BCC recipient if configured
        if (email_config.bcc && strlen(email_config.bcc) > 0) {
            recipients = curl_slist_append(recipients, email_config.bcc);
        }
        
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);

        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            return ("[ERROR]curl_easy_perform() failed: %s\n");
        } 

        curl_slist_free_all(recipients);
        curl_easy_cleanup(curl);
    }

    // Clean up all allocated memory
    free(email_content);
    free(from_email);
    free(password);    
    return ("[INFO]Email sent successfully!\n");


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

// Email configuration management functions

int init_email_config() {
    if (!EMAIL_CONFIG_PATH) {
        printf("[ERROR] Invalid config file path\n");
        return 0;
    }
    
    // Clean up any existing config
    cleanup_email_config();
    
    // Load credentials from JSON file
    char* from_email = NULL;
    char* password = NULL;
    int useJSON_setting = 1;
    char* bcc_email = NULL;
    int emailTokenExpiry_setting = 600;
    char* smtpServer_setting = NULL;
    int smtpPort_setting = 465;
    int useSSL_setting = 1;
    
    int result = read_credentials_json_full(EMAIL_CONFIG_PATH, &from_email,  &password, &useJSON_setting, &bcc_email, &emailTokenExpiry_setting, &smtpServer_setting, &smtpPort_setting, &useSSL_setting);
    if (result != 0) {
        printf("[ERROR] Failed to load email config from %s\n", EMAIL_CONFIG_PATH);
        return 0;
    }
    
  
    
    // Store in global config
    email_config.from_email = from_email;
    email_config.password = password;
    email_config.bcc = bcc_email;
    email_config.smtp_server = smtpServer_setting;
    email_config.smtp_port = smtpPort_setting;
    email_config.useSSL = useSSL_setting;
    email_config.emailTokenExpiry = emailTokenExpiry_setting;
    email_config.useJSON = useJSON_setting;
    email_config.initialized = 1;
    
    return 1;
}

void cleanup_email_config(void) {
    if (email_config.from_email) {
        free(email_config.from_email);
        email_config.from_email = NULL;
    }
    if (email_config.password) {
        free(email_config.password);
        email_config.password = NULL;
    }
    if (email_config.bcc) {
        free(email_config.bcc);
        email_config.bcc = NULL;
    }
    if (email_config.smtp_server) {
        free(email_config.smtp_server);
        email_config.smtp_server = NULL;
    }
    email_config.initialized = 0;
}

int is_email_config_loaded(void) {
    return email_config.initialized && email_config.from_email && email_config.password;
}

int is_email_required(void) {
    // Check if email is disabled in server config
    extern int is_email_disabled(void);
    if (is_email_disabled()) {
        return 0;
    }
    return email_config.initialized;
}

int get_email_token_expiry(void) {
    return email_config.initialized ? email_config.emailTokenExpiry : 600; // Default 10 minutes
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

