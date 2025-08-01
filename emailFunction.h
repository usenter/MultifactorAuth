


typedef struct {
    char* TO;        // Always set by caller
    char* subject;   // Always set by caller  
    char* body;      // Always set by caller
    // FROM and PASSWORD are loaded from JSON or global config, not by caller
} emailContent_t;

int read_credentials_json(const char* filename, emailContent_t* payload);
int read_credentials_json_full(const char* filename, char** from_email, char** to_email, char** password);
void send_email(emailContent_t* payload);
void cleanup_email_content(emailContent_t* payload);
