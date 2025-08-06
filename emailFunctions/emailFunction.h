


#ifndef EMAIL_FUNCTION_H
#define EMAIL_FUNCTION_H

typedef struct {
    char* TO;        // Always set by caller
    char* subject;   // Always set by caller  
    char* body;      // Always set by caller
    // FROM and PASSWORD are loaded from JSON or global config, not by caller
} emailContent_t;

// Email configuration structure for caching
typedef struct {
    char* from_email;
    char* password;
    char* bcc;
    char* smtp_server;
    int smtp_port;
    int useSSL;
    int requireEmail;
    int emailTokenExpiry;
    int useJSON;
    int initialized;
} email_config_t;

// Global email configuration (loaded once)
extern email_config_t email_config;

// Function declarations
int read_credentials_json(const char* filename, emailContent_t* payload);
int read_credentials_json_full(const char* filename, char** from_email, char** to_email, char** password, int* useJSON, char** bcc, int* requireEmail, int* emailTokenExpiry, char** smtpServer, int* smtpPort, int* useSSL);
char* send_email(emailContent_t* payload);
void cleanup_email_content(emailContent_t* payload);

// Email config management functions
int init_email_config();
void cleanup_email_config(void);
int is_email_config_loaded(void);
int is_email_required(void);
int get_email_token_expiry(void);

#endif // EMAIL_FUNCTION_H
