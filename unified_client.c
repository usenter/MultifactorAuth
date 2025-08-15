#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <sys/utsname.h>
#define PORT 12345
#define BUFFER_SIZE 1024
#define MAX_MESSAGES 100
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 64
#define RSA_KEY_SIZE 2048
#define RSA_CHALLENGE_SIZE 32
#define MAX_RSA_ENCRYPTED_SIZE (RSA_KEY_SIZE/8)  // 256 bytes for 2048-bit key
#define RSA_DECRYPT_BUFFER_SIZE MAX_RSA_ENCRYPTED_SIZE
#define RSA_HEX_BUFFER_SIZE (MAX_RSA_ENCRYPTED_SIZE * 2 + 64)
#define MAX_FILE_PATH_LEN 512
#define PROGRAM_NAME "AuthenticatedChatClient"

volatile int running = 1;
int password_authenticated = 0;
int rsa_completed = 0;
int email_authenticated = 0;
int locked = 0;
static char g_username[MAX_USERNAME_LEN] = "";
static char g_last_shutdown_reason[128] = "normal";


// RSA keys for automatic authentication
EVP_PKEY* client_private_key = NULL;
EVP_PKEY* server_public_key = NULL;
char client_id[64] = "";  // Must be specified by user
unsigned int account_id = 0;  // Add account_id

// Authentication response checking
#define AUTH_SUCCESS "AUTH_SUCCESS"

// Function to cleanup client resources
void cleanup_client_resources(int client_socket);

// Global message storage
typedef struct {
    char message[BUFFER_SIZE];
    int valid;
} stored_message_t;

stored_message_t message_buffer[MAX_MESSAGES];
int message_count = 0;
pthread_mutex_t message_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to store a message
void store_message(const char* msg) {
    pthread_mutex_lock(&message_mutex);
    if (message_count < MAX_MESSAGES) {
        strncpy(message_buffer[message_count].message, msg, BUFFER_SIZE - 1);
        message_buffer[message_count].message[BUFFER_SIZE - 1] = '\0';
        message_buffer[message_count].valid = 1;
        message_count++;
    }
    pthread_mutex_unlock(&message_mutex);
}

// Function to get stored messages
int get_stored_messages(char messages[][BUFFER_SIZE], int max_count) {
    pthread_mutex_lock(&message_mutex);
    int count = (message_count < max_count) ? message_count : max_count;
    for (int i = 0; i < count; i++) {
        if (message_buffer[i].valid) {
            strcpy(messages[i], message_buffer[i].message);
        }
    }
    pthread_mutex_unlock(&message_mutex);
    return count;
}

// Ensure logs directory exists
static void ensure_logs_dir(void) {
    struct stat st;
    if (stat("logs", &st) == -1) {
        mkdir("logs", 0755);
    }
}

// Helper to append a shell command's output into a report
static void append_shell_section(FILE* fp, const char* title, const char* cmd) {
    if (!fp || !cmd) return;
    fprintf(fp, "\n[%s]\n$ %s\n", title ? title : "CMD", cmd);
    fflush(fp);
    FILE* pp = popen(cmd, "r");
    if (!pp) {
        fprintf(fp, "(failed to run)\n");
        return;
    }
    char line[512];
    int lines = 0;
    while (fgets(line, sizeof(line), pp) && lines < 2000) { // cap to prevent huge logs
        fputs(line, fp);
        lines++;
    }
    pclose(pp);
}

// Generate a client-side debug report
static void generate_client_debug_report(const char* reason, int client_socket, int last_errno) {
    ensure_logs_dir();
    time_t now = time(NULL);
    struct tm tm_now;
    localtime_r(&now, &tm_now);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y%m%d_%H%M%S", &tm_now);

    char filename[256];
    snprintf(filename, sizeof(filename), "logs/ClientDebug_%s_%s_%d.log",
             (g_username[0] ? g_username : "unknown"), ts, getpid());

    FILE* fp = fopen(filename, "w");
    if (!fp) return;

    fprintf(fp, "CLIENT DEBUG REPORT\n");
    fprintf(fp, "Timestamp: %s\n", ts);
    fprintf(fp, "Program: %s\n", PROGRAM_NAME);
    fprintf(fp, "PID: %d\n", getpid());
    fprintf(fp, "Username: %s\n", (g_username[0] ? g_username : "unknown"));
    fprintf(fp, "Reason: %s\n", reason ? reason : "unspecified");

    // System info
    struct utsname uts; if (uname(&uts) == 0) {
        fprintf(fp, "System: %s %s %s %s %s\n", uts.sysname, uts.nodename, uts.release, uts.version, uts.machine);
    }

    // Auth state
    fprintf(fp, "AuthState: password=%d rsa=%d email=%d locked=%d\n",
            password_authenticated, rsa_completed, email_authenticated, locked);

    // Socket info
    if (client_socket >= 0) {
        struct sockaddr_in peer; socklen_t plen = sizeof(peer);
        char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
        if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
            inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
            port = ntohs(peer.sin_port);
        }
        int soerr = 0; socklen_t slen = sizeof(soerr);
        getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
        fprintf(fp, "Socket: fd=%d peer=%s:%d last_errno=%d(%s) SO_ERROR=%d(%s)\n",
                client_socket, ip, port, last_errno, strerror(last_errno), soerr, strerror(soerr));

        struct tcp_info tcpi; socklen_t tlen = sizeof(tcpi);
        if (getsockopt(client_socket, IPPROTO_TCP, TCP_INFO, &tcpi, &tlen) == 0) {
            fprintf(fp, "TCP_INFO: state=%u rtt=%u rttvar=%u snd_cwnd=%u retrans=%u unacked=%u\n",
                    tcpi.tcpi_state, tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
                    tcpi.tcpi_snd_cwnd, tcpi.tcpi_retransmits, tcpi.tcpi_unacked);
        }
    }

    // Recent messages
    fprintf(fp, "\nRecentMessages:\n");
    char msgs[MAX_MESSAGES][BUFFER_SIZE];
    int cnt = get_stored_messages(msgs, MAX_MESSAGES);
    int start = (cnt > 20) ? (cnt - 20) : 0; // last 20
    for (int i = start; i < cnt; i++) {
        fprintf(fp, "- %s\n", msgs[i]);
    }

    // Local shell diagnostics (best-effort; may be unavailable)
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ss -tanpi | grep ':%d ' || ss -tanpi | head -n 100", PORT);
    append_shell_section(fp, "ss_port", cmd);
    snprintf(cmd, sizeof(cmd), "netstat -anp 2>/dev/null | grep ':%d' | head -n 100", PORT);
    append_shell_section(fp, "netstat_port", cmd);
    append_shell_section(fp, "ss_summary", "ss -s");
    append_shell_section(fp, "route", "ip route show");
    append_shell_section(fp, "ifconfig", "ip -br addr");
    // If running as root, include iptables snapshot and a small RST sniff
    if (geteuid() == 0) {
        append_shell_section(fp, "iptables_connlimit", "iptables -L INPUT -v -n --line-numbers | grep -E 'REJECT|SYN_FLOOD|connlimit' || true");
        snprintf(cmd, sizeof(cmd), "timeout 1 tcpdump -Q inout -ni any -vv -c 10 'tcp port %d and tcp[tcpflags] & tcp-rst != 0' 2>&1", PORT);
        append_shell_section(fp, "tcpdump_rst_1s", cmd);
    }

    fclose(fp);
}

// RSA Authentication Functions
// Load client's private key
int load_client_private_key(const char* username) {
    char key_file[MAX_FILE_PATH_LEN];
    snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", username);
    
    FILE* fp = fopen(key_file, "r");
    if (!fp) {
        printf("ERROR: Could not open client private key: %s\n", key_file);
        return 0;
    }
    
    client_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!client_private_key) {
        printf("ERROR: Could not read client private key from: %s\n", key_file);
        return 0;
    }
    

    return 1;
}

// Load server's public key
int load_server_public_key(void) {
    FILE* fp = fopen("RSAkeys/server_public.pem", "r");
    if (!fp) {
        printf("ERROR: Could not open server public key: RSAkeys/server_public.pem\n");
        return 0;
    }
    
    server_public_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!server_public_key) {
        printf("ERROR: Could not read server public key\n");
        return 0;
    }

    return 1;
}
int generate_self_signed_cert(const char* username);
// Handle RSA challenge automatically
int handle_rsa_challenge(int socket, const char* hex_challenge) {
    if (!client_private_key || !server_public_key) {
        printf("RSA keys not loaded - cannot handle RSA challenge!\n");
        return 0;
    }
    
    //printf("Authenticating with server...\n");
    
    // Convert hex challenge back to binary
    size_t challenge_len = strlen(hex_challenge) / 2;
    unsigned char encrypted_challenge[MAX_RSA_ENCRYPTED_SIZE];
    /*
    printf("DEBUG: Hex challenge length: %zu chars, Binary length: %zu bytes\n", 
           strlen(hex_challenge), challenge_len);
    printf("DEBUG: Expected encrypted size for 2048-bit RSA: %d bytes\n", MAX_RSA_ENCRYPTED_SIZE);
    */
    if (challenge_len != MAX_RSA_ENCRYPTED_SIZE) {
        printf("ERROR: Encrypted challenge length mismatch! Expected %d, got %zu\n", 
               MAX_RSA_ENCRYPTED_SIZE, challenge_len);
        return 0;
    }
    
    for (size_t i = 0; i < challenge_len; i++) {
        sscanf(hex_challenge + (i * 2), "%2hhx", &encrypted_challenge[i]);
    }
    
    // Decrypt challenge with client private key
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(client_private_key, NULL);
    if (!decrypt_ctx || EVP_PKEY_decrypt_init(decrypt_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (decrypt_ctx) EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to setup RSA decryption\n");
        return 0;
    }
    
    unsigned char decrypted_challenge[RSA_DECRYPT_BUFFER_SIZE];
    size_t decrypted_len = sizeof(decrypted_challenge);
    
    /*
    printf("DEBUG: About to decrypt %zu bytes of encrypted data\n", challenge_len);
    printf("DEBUG: Decryption buffer size: %zu bytes\n", decrypted_len);
    printf("DEBUG: Expected decrypted size: %d bytes\n", RSA_CHALLENGE_SIZE);
        */
    //decrypt the challenge using the client private key
    if (EVP_PKEY_decrypt(decrypt_ctx, decrypted_challenge, &decrypted_len, encrypted_challenge, challenge_len) <= 0) {
        ERR_print_errors_fp(stdout);
        PEM_write_PrivateKey(stdout, client_private_key, NULL, NULL, 0, NULL, NULL);
        EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to decrypt RSA challenge\n");
        return 0;
    }
    EVP_PKEY_CTX_free(decrypt_ctx);
    
    //printf("DEBUG: Successfully decrypted %zu bytes (expected %d bytes)\n", 
    //       decrypted_len, RSA_CHALLENGE_SIZE);
    
    if (decrypted_len != RSA_CHALLENGE_SIZE) {
        printf("WARNING: Decrypted length mismatch! Expected %d, got %zu\n", 
               RSA_CHALLENGE_SIZE, decrypted_len);
    }
    
    // Encrypt decrypted challenge with server public key
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(server_public_key, NULL);
    if (!encrypt_ctx || EVP_PKEY_encrypt_init(encrypt_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(encrypt_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (encrypt_ctx) EVP_PKEY_CTX_free(encrypt_ctx);
        printf("Failed to setup RSA encryption\n");
        return 0;
    }
    
    unsigned char encrypted_response[MAX_RSA_ENCRYPTED_SIZE];
    size_t encrypted_len = sizeof(encrypted_response);
    
    // Use RSA_CHALLENGE_SIZE instead of decrypted_len for consistency
    size_t input_len = RSA_CHALLENGE_SIZE;
    //printf("DEBUG: About to re-encrypt %zu bytes with server public key\n", input_len);
    //printf("DEBUG: Output buffer size: %zu bytes\n", encrypted_len);
    
    if (EVP_PKEY_encrypt(encrypt_ctx, encrypted_response, &encrypted_len, decrypted_challenge, input_len) <= 0) {
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(encrypt_ctx);
        printf("Failed to encrypt RSA response\n");
        return 0;
    }
    EVP_PKEY_CTX_free(encrypt_ctx);
    
    //printf("DEBUG: Successfully re-encrypted to %zu bytes (expected %d bytes)\n", 
    //      encrypted_len, MAX_RSA_ENCRYPTED_SIZE);
    
    if (encrypted_len != MAX_RSA_ENCRYPTED_SIZE) {
        printf("WARNING: Re-encrypted length mismatch! Expected %d, got %zu\n", 
               MAX_RSA_ENCRYPTED_SIZE, encrypted_len);
    }
    
    // Convert response to hex and send
    char hex_response[RSA_HEX_BUFFER_SIZE];
    snprintf(hex_response, sizeof(hex_response), "/rsa_response ");
    char* hex_ptr = hex_response + strlen(hex_response);
    
    for (size_t i = 0; i < encrypted_len; i++) {
        sprintf(hex_ptr + (i * 2), "%02x", encrypted_response[i]);
    }
    
    if (send(socket, hex_response, strlen(hex_response), 0) < 0) {
        printf("Failed to send RSA response\n");
        return 0;
    }
    
    //printf("RSA response sent successfully\n");
    
    // Clear sensitive data
    memset(decrypted_challenge, 0, sizeof(decrypted_challenge));
    memset(encrypted_response, 0, sizeof(encrypted_response));
    
    return 1;
}

// Cleanup RSA keys
void cleanup_rsa_keys(void) {
    if (client_private_key) {
        EVP_PKEY_free(client_private_key);
        client_private_key = NULL;
    }
    if (server_public_key) {
        EVP_PKEY_free(server_public_key);
        server_public_key = NULL;
    }
}

//function for file handling mode
int file_handling(const char* username){
    printf("File handling for user %s\n", username);
    return 1;

}

typedef enum {
    MSG_PROCESSED,    // Message handled, show prompt
    MSG_CONTINUE,     // Message handled, don't show prompt
    MSG_EXIT          // Exit the loop
} MessageResult;

MessageResult process_server_message(int client_socket, const char* buffer);
MessageResult handle_rsa_messages(int client_socket, const char* buffer);
MessageResult handle_server_shutdown(int client_socket, const char* buffer);
MessageResult handle_auth_state_messages(const char* buffer);
MessageResult handle_token_messages(const char* buffer);
MessageResult handle_auth_phase_messages(const char* buffer);
MessageResult handle_final_auth_success(const char* buffer);
static void show_appropriate_prompt(void);

// Function to receive messages from server (chat mode)
void* receive_messages(void* arg) {
    int client_socket = *(int*)arg;
    char buffer[BUFFER_SIZE];
    
    while (running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            int last_errno = errno;
            snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason),
                     "recv_failed bytes=%d errno=%d:%s", bytes_received, last_errno, strerror(last_errno));
            printf("\nServer disconnected or recv error (bytes_received=%d)\n", bytes_received);
            generate_client_debug_report(g_last_shutdown_reason, client_socket, last_errno);
            running = 0;
            break;
        }
        
        buffer[bytes_received] = '\0';
        
        // Process the message and determine if we should continue the loop
        MessageResult result = process_server_message(client_socket, buffer);
        
        if (result == MSG_EXIT) {
            snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason), "auth_or_rsa_exit");
            generate_client_debug_report(g_last_shutdown_reason, client_socket, 0);
            break;
        }
        
        if (result == MSG_PROCESSED) {
            show_appropriate_prompt();
        }
    }
    
    return NULL;
}



MessageResult process_server_message(int client_socket, const char* buffer) {
    // Store the message first
    store_message(buffer);
    
    // Handle RSA authentication
    MessageResult rsa_result = handle_rsa_messages(client_socket, buffer);
    if (rsa_result != MSG_PROCESSED) {
        return rsa_result;
    }
    
    // Handle server shutdown
    MessageResult shutdown_result = handle_server_shutdown(client_socket, buffer);
    if (shutdown_result != MSG_PROCESSED) {
        return shutdown_result;
    }
    
    // Handle authentication state changes
    MessageResult auth_result = handle_auth_state_messages(buffer);
    if (auth_result != MSG_PROCESSED) {
        return auth_result;
    }
    
    // Handle token-related messages  
    MessageResult token_result = handle_token_messages(buffer);
    if (token_result != MSG_PROCESSED) {
        return token_result;
    }
    
    // Handle authentication phase messages
    MessageResult phase_result = handle_auth_phase_messages(buffer);
    if (phase_result != MSG_PROCESSED) {
        return phase_result;
    }
    
    // Handle final authentication success
    if (handle_final_auth_success(buffer) == MSG_CONTINUE) {
        return MSG_CONTINUE;
    }
    
    // Default: show server message
    printf("%s\n", buffer);
    return MSG_PROCESSED;
}

MessageResult handle_rsa_messages(int client_socket, const char* buffer) {
    if (strstr(buffer, "RSA_CHALLENGE:") && !rsa_completed) {
        char* challenge_start = strstr(buffer, "RSA_CHALLENGE:") + 14;
        char* challenge_end = strchr(challenge_start, '\n');
        if (challenge_end) *challenge_end = '\0';
        
        printf("\n[RSA] Performing RSA mutual authentication...\n");
        if (handle_rsa_challenge(client_socket, challenge_start)) {
            rsa_completed = 1;
            printf("[RSA] SUCCESS: RSA mutual authentication completed!\n");
            printf("[RSA] Secure encrypted channel established between client and server.\n");
            printf("[RSA] You may now login with your username and password.\n\n");
        } else {
            printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
        }
        return MSG_EXIT;
    }
    
    if (strstr(buffer, "RSA_FAILED")) {
        printf("\nRSA authentication failed - connection may be terminated by server.\n");
        running = 0;
        return MSG_EXIT;
    }
    
    if (strstr(buffer, "SECURITY_ERROR")) {
        printf("\nSECURITY ERROR: RSA authentication is required but failed.\n");
        printf("Make sure you have the correct RSA keys for your client.\n");
        return MSG_EXIT;
    }
    
    if (strncmp(buffer, "RSA_AUTH_SUCCESS", 16) == 0) {
        rsa_completed = 1;
        return MSG_CONTINUE;
    }
    
    return MSG_PROCESSED;
}

MessageResult handle_server_shutdown(int client_socket, const char* buffer) {
    if (strstr(buffer, "Server is shutting down") || 
        strstr(buffer, "server disconnected") ||
        strstr(buffer, "Server disconnected")) {
        
        printf("\n%s", buffer);
        printf("Server is shutting down. Client exiting immediately...\n");
        running = 0;
        
        cleanup_client_resources(client_socket); 
        exit(0);
    }
    return MSG_PROCESSED;
}

MessageResult handle_auth_state_messages(const char* buffer) {
    if (strstr(buffer, "AUTH_LOCKED")) {
        printf("\n%s\n", buffer);
        locked = 1;
        return MSG_CONTINUE;
    }
    
    if (strstr(buffer, "AUTH_STATUS_UNLOCKED")) {
        locked = 0;
        password_authenticated = 0;
        email_authenticated = 0;
        return MSG_PROCESSED;
    }
    
    return MSG_PROCESSED;
}

MessageResult handle_token_messages(const char* buffer) {
    if (strstr(buffer, "AUTH_TOKEN_EXPIRED")) {
        printf("\nYour token has expired. Use /newToken to request a new one.\n");
        struct timespec delay = {0, 300000000}; 
        nanosleep(&delay, NULL);
        show_appropriate_prompt();

        return MSG_CONTINUE;
    }
    
    if (strstr(buffer, "AUTH_TOKEN_FAIL")) {
        const char* token_fail_message = buffer+ 16;
        printf("%s\n", token_fail_message);
        struct timespec delay = {0, 300000000}; 
        nanosleep(&delay, NULL);
        show_appropriate_prompt();
        return MSG_CONTINUE;
    }
    
    if (strstr(buffer, "AUTH_TOKEN_GEN_SUCCESS")) {
        printf("A new token has been sent to your email.\n");
        struct timespec delay = {0, 150000000}; 
        nanosleep(&delay, NULL);
        show_appropriate_prompt();
        return MSG_CONTINUE;
    }
    
    return MSG_PROCESSED;
}

MessageResult handle_auth_phase_messages(const char* buffer) {
    if (strncmp(buffer, "PHASE:EMAIL", 11) == 0) {
        if (strstr(buffer, "AUTH_SUCCESS") && strstr(buffer, "Email token verified successfully")) {
            printf("\nEmail verification successful! You are now fully authenticated.\n");
            printf("SERVER: %s\n", buffer);
            email_authenticated = 1;
            return MSG_CONTINUE;
        }
        if (strstr(buffer, "Password verified")) {
            password_authenticated = 1;
            printf("\nPassword verified. Please check your email for a 6-digit token.\n");
            printf("Use /token <code> to enter the token, or /newToken to request a new one.\n");
            struct timespec delay = {0, 150000000}; 
            nanosleep(&delay, NULL);
            show_appropriate_prompt();
            return MSG_CONTINUE;
        }
        
        printf("\n%s", buffer);
        return MSG_CONTINUE;
    }
    
    return MSG_PROCESSED;
}

MessageResult handle_final_auth_success(const char* buffer) {
    if (strstr(buffer, "AUTH_SUCCESS")) {
        printf("\n%s", buffer);
        email_authenticated = 1;
        password_authenticated = 1;
        rsa_completed = 1;
        locked = 0;
        struct timespec delay = {0, 150000000}; 
        nanosleep(&delay, NULL);
        show_appropriate_prompt();
        return MSG_CONTINUE;
    }
    
    return MSG_PROCESSED;
}

void show_appropriate_prompt(void) {
    if (password_authenticated && email_authenticated) {
        printf("> ");
    } else {
        printf("auth> ");
    }
    fflush(stdout);
}

// Function to cleanup client resources
void cleanup_client_resources(int client_socket) {
    printf("Cleaning up client resources...\n");
    
    // Close socket
    if (client_socket >= 0) {
        shutdown(client_socket, SHUT_RDWR);
        close(client_socket);
    }
    
    // Cleanup RSA keys
    cleanup_rsa_keys();
    
    // Cleanup message mutex
    pthread_mutex_destroy(&message_mutex);
    
    // Clear message buffer
    pthread_mutex_lock(&message_mutex);
    for (int i = 0; i < message_count; i++) {
        message_buffer[i].valid = 0;
        memset(message_buffer[i].message, 0, BUFFER_SIZE);
    }
    message_count = 0;
    pthread_mutex_unlock(&message_mutex);
    
    printf("Client cleanup complete\n");
}

// Function to handle secure chat client
int client_mode(int client_socket, const char* username) {
    char buffer[BUFFER_SIZE];
    pthread_t receive_thread;

    // Reset authentication state variables for fresh connection
    password_authenticated = 0;
    rsa_completed = 0;
    email_authenticated = 0;
    locked = 0;

    if (username) {
        strncpy(g_username, username, sizeof(g_username) - 1);
        g_username[sizeof(g_username) - 1] = '\0';
    }
    printf("Connected to secure MultiFactor Authentication chat server! Beginning RSA challenge-response authentication...\n");
    //printf("Starting RSA challenge-response authentication...\n");

    // Synchronously wait for and handle RSA challenge before starting receive thread
    int rsa_ok = 0;
    while (!rsa_ok && running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            return 0;
        }
        //printf("[CLIENT_DEBUG] Parsing server input...\n");
        buffer[bytes_received] = '\0';
        if (strstr(buffer, "RSA_CHALLENGE:") && !rsa_completed) {
            char* challenge_start = strstr(buffer, "RSA_CHALLENGE:") + 14;
            char* challenge_end = strchr(challenge_start, '\n');
            if (challenge_end) *challenge_end = '\0';
            //printf("[RSA] Performing RSA mutual authentication...\n");
            if (handle_rsa_challenge(client_socket, challenge_start)) {
                rsa_completed = 1;
                rsa_ok = 1;
                printf("[RSA] SUCCESS: RSA mutual authentication completed!\n");
                //printf("[RSA] You may now login with your username and password.\n");
            } 
            else {
                printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
                running = 0;
                return 0;
            }
        }
        else if (strstr(buffer, "RSA_FAILED")) {
            printf("\n[RSA] RSA authentication failed - connection may be terminated by server.\n");
            running = 0;
            return 0;
        } 
        else if (strstr(buffer, "SECURITY_ERROR")) {
            printf("\n[RSA] SECURITY ERROR: RSA authentication is required but failed.\n");
            printf("[RSA] Make sure you have the correct RSA keys for your client.\n");
            running = 0;
            return 0;
        } 
        else {
            // Check for immediate authentication success (when all auth methods disabled)
            if (strstr(buffer, "AUTH_SUCCESS")) {
                printf("%s", buffer);
                // Set all authentication flags
                email_authenticated = 1;
                password_authenticated = 1;
                rsa_completed = 1;
                locked = 0;
                rsa_ok = 1; // Exit the authentication loop
                printf("[AUTH] Auto-authentication successful! You are now fully authenticated.\n");
            }
            // Check for lockout status in initial messages
            else if (strstr(buffer, "AUTH_LOCKED")) {
                locked = 1;
                printf("\n[AUTH] You are currently locked out. Please wait before trying again.\n");
                running = 0;
                return 0;
            }
            else {
                // Print any other server message (e.g., banner, authentication prompt)
                printf("%s", buffer);
                
                // Show auth prompt after displaying server messages
                if (!rsa_completed) {
                    printf("auth> ");
                    fflush(stdout);
                }
            }
        }
        
    }
    //printf("[CLIENT_DEBUG] RSA challenge completed\n");
    // Now start the receive thread for chat and further messages
    if (pthread_create(&receive_thread, NULL, receive_messages, &client_socket) != 0) {
        printf("Failed to create receive thread\n");
        snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason), "pthread_create_failed");
        generate_client_debug_report(g_last_shutdown_reason, client_socket, errno);
        return 0;
    }
    //printf("[CLIENT_DEBUG] started receive thread\n");

    // Main loop to send messages
    while (running && fgets(buffer, BUFFER_SIZE, stdin)) {
        buffer[strcspn(buffer, "\r\n")] = 0;
        if (!running) break;
        if (strcmp(buffer, "/quit") == 0) {
            running = 0;
            break;
        }
        if (strlen(buffer) > 0) {
            if(locked){
                snprintf(buffer, sizeof(buffer), "/time");
                send(client_socket, buffer, strlen(buffer), 0);
                continue;
            }
            if (!password_authenticated) {
                if (strncmp(buffer, "/login", 6) == 0)  {
                    //printf("[CLIENT_DEBUG] Sending auth command to server: '%s'\n", buffer);
                    
                    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                    
                }
                else if (!locked) {
                    printf("Please authenticate first. Use: /login <username> <password> or /register <username> <password>\n");
                    printf("auth> ");
                    continue;
                }

            }
            else if(!email_authenticated) {
                if(strncmp(buffer, "/token", 6) == 0 || strncmp(buffer, "/newToken", 9) == 0){
                    //printf("[CLIENT_DEBUG] Sending token command to server: '%s'\n", buffer);
                    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                }
                else {
                    printf("Please authenticate first. Use: /token <code> or /newToken\n");
                    printf("auth> ");
                    continue;
                }
            } else {
                //printf("[CLIENT_DEBUG] Sending chat message to server: '%s'\n", buffer);
                if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
                    printf("Failed to send message\n");
                    running = 0;
                    break;
                }
            }
        }
        if (password_authenticated && email_authenticated) {
            if(strncmp(buffer, "/file", 5) == 0){
                file_handling(username);
            }
            else{
                printf(">");
            }
        } 
    }
    running = 0;
    shutdown(client_socket, SHUT_RDWR);
    pthread_join(receive_thread, NULL);
    printf("Disconnected from chat server\n");
    cleanup_client_resources(client_socket);
    if (g_last_shutdown_reason[0] == '\0') {
        snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason), "normal");
    }
    generate_client_debug_report(g_last_shutdown_reason, client_socket, 0);
    return 1; // cleaned up and returned successfully
}

// Helper function to generate a self-signed certificate
int generate_self_signed_cert(const char* username) {
    char privkey_path[MAX_FILE_PATH_LEN];
    char cert_path[MAX_FILE_PATH_LEN];
    snprintf(privkey_path, sizeof(privkey_path), "RSAkeys/client_%s_private.pem", username);
    snprintf(cert_path, sizeof(cert_path), "RSAkeys/client_%s_cert.pem", username);

    FILE* fp = fopen(privkey_path, "r");
    if (!fp) {
        printf("ERROR: Private key not found for certificate generation.\n");
        return 0;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!pkey) {
        printf("ERROR: Could not read private key for certificate generation.\n");
        return 0;
    }

    X509* x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        printf("ERROR: Could not allocate X509 certificate.\n");
        return 0;
    }
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)username, -1, -1, 0);
    X509_set_issuer_name(x509, name); // self-signed

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        printf("ERROR: Failed to sign certificate.\n");
        return 0;
    }

    FILE* cert_fp = fopen(cert_path, "w");
    if (!cert_fp) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        printf("ERROR: Could not open cert file for writing.\n");
        return 0;
    }
    PEM_write_X509(cert_fp, x509);
    fclose(cert_fp);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    printf("Self-signed certificate generated: %s\n", cert_path);
    return 1;
}

int main(int argc, char *argv[]) {
    
    struct sockaddr_in server_addr;
    
    // Parse command line arguments
    int skip_rsa = 0;
    const char* username = NULL;
    
    if (argc == 2) {
        username = argv[1];
    } else if (argc == 3 && strcmp(argv[1], "--no-rsa") == 0) {
        skip_rsa = 1;
        username = argv[2];
    } else {
        printf("Usage: %s [--no-rsa] <username>\n", argv[0]);
        printf("Examples:\n");
        printf("  %s alice                    # Normal mode (generate RSA keys)\n", argv[0]);
        printf("  %s --no-rsa alice           # Skip RSA key generation (for RSA-disabled servers)\n", argv[0]);
        return 1;
    }
    // Capture for debug report filename
    if (username) {
        strncpy(g_username, username, sizeof(g_username) - 1);
        g_username[sizeof(g_username) - 1] = '\0';
    }
    
    // Set global client_id for use in RSA functions
    strncpy(client_id, username, sizeof(client_id) - 1);
    client_id[sizeof(client_id) - 1] = '\0';
    
    if (!skip_rsa) {
        // Check if RSA keys exist, generate if needed
        char key_file[MAX_FILE_PATH_LEN];
        snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", username);
        FILE* fp = fopen(key_file, "r");
        if (!fp) {
            printf("Private key not found for user '%s'. Generating new RSA keys...\n", username);
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "./generate_rsa_keys client %s", username);
            int ret = system(cmd);
            if (ret != 0) {
                printf("Failed to generate RSA keys for user '%s'!\n", username);
                return 1;
            }
        } else {
            fclose(fp);
        }
        
        // Check for certificate, generate if needed
        char cert_file[MAX_FILE_PATH_LEN];
        snprintf(cert_file, sizeof(cert_file), "RSAkeys/client_%s_cert.pem", username);
        FILE* cert_fp = fopen(cert_file, "r");
        if (!cert_fp) {
            printf("Certificate not found for user '%s'. Generating self-signed certificate...\n", username);
            if (!generate_self_signed_cert(username)) {
                printf("Failed to generate self-signed certificate for user '%s'!\n", username);
                return 1;
            }
        } else {
            fclose(cert_fp);
        }
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    
    if (!skip_rsa) {
        // Load RSA keys
        if (!load_client_private_key(username) || !load_server_public_key()) {
            printf("Failed to load RSA keys\n");
            return 1;
        }
        printf("RSA keys loaded. Connecting to server...\n");
    } else {
        printf("Connecting to server... (RSA disabled)\n");
    }
    
    // Connect to server with retry logic
    int sock = -1;
    int connect_retries = 0;
    const int max_connect_retries = 3;
    const int connect_retry_delay = 1; // seconds
    
    while (connect_retries < max_connect_retries) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            return 1;
        }
        
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(PORT);
        server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            printf("Connection attempt %d/%d failed: %s\n", connect_retries + 1, max_connect_retries, strerror(errno));
            close(sock);
            sock = -1;
            
            connect_retries++;
            if (connect_retries < max_connect_retries) {
                printf("Retrying connection in %d second(s)...\n", connect_retry_delay);
                sleep(connect_retry_delay);
            } else {
                printf("All connection attempts failed. Giving up.\n");
                return 1;
            }
        } else {
            printf("Connection successful on attempt %d/%d\n", connect_retries + 1, max_connect_retries);
            break;
        }
    }
    //printf("Connected to server. Sending certificate...\n");
    
    // Clear any leftover data in the socket buffer
    char clear_buf[1024];
    while (recv(sock, clear_buf, sizeof(clear_buf), MSG_PEEK | MSG_DONTWAIT) > 0) {
        recv(sock, clear_buf, sizeof(clear_buf), 0);
    }
    
    if (!skip_rsa) {
        char cert_buf[8192];
        size_t cert_len = 0;
        
        // Send real certificate
        char cert_file[MAX_FILE_PATH_LEN];
        snprintf(cert_file, sizeof(cert_file), "RSAkeys/client_%s_cert.pem", username);
        FILE* cert_fp = fopen(cert_file, "r");
        if (!cert_fp) {
            printf("ERROR: Could not open certificate file for sending.\n");
            close(sock);
            return 1;
        }
        memset(cert_buf, 0, sizeof(cert_buf));
        cert_len = fread(cert_buf, 1, sizeof(cert_buf) - 1, cert_fp);
        fclose(cert_fp);
        cert_buf[cert_len] = '\0';
        
        // Send certificate length first (as 4-byte int, network order) with retry logic
        uint32_t net_cert_len = htonl(cert_len);
        int cert_retries = 0;
        const int max_cert_retries = 3;
        const int cert_retry_delay = 1; // seconds
        
        while (cert_retries < max_cert_retries) {
            if (send(sock, &net_cert_len, sizeof(net_cert_len), 0) != sizeof(net_cert_len)) {
                printf("ERROR: Failed to send certificate length (attempt %d/%d): %s\n", 
                       cert_retries + 1, max_cert_retries, strerror(errno));
                
                cert_retries++;
                if (cert_retries < max_cert_retries) {
                    printf("Retrying certificate length send in %d second(s)...\n", cert_retry_delay);
                    sleep(cert_retry_delay);
                } else {
                    printf("All certificate length send attempts failed. Giving up.\n");
                    close(sock);
                    return 1;
                }
            } else {
                break;
            }
        }
        
        // Send certificate data with retry logic
        cert_retries = 0;
        ssize_t sent_bytes = 0;
        
        while (cert_retries < max_cert_retries) {
            sent_bytes = send(sock, cert_buf, cert_len, 0);
            if (sent_bytes != (ssize_t)cert_len) {
                printf("ERROR: Failed to send certificate data (attempt %d/%d): Sent %zd of %zu bytes: %s\n", 
                       cert_retries + 1, max_cert_retries, sent_bytes, cert_len, strerror(errno));
                
                cert_retries++;
                if (cert_retries < max_cert_retries) {
                    printf("Retrying certificate data send in %d second(s)...\n", cert_retry_delay);
                    sleep(cert_retry_delay);
                } else {
                    printf("All certificate data send attempts failed. Giving up.\n");
                    close(sock);
                    return 1;
                }
            } else {
                break;
            }
        }
    }
    
    // Send username after certificate with retry logic
    char id_msg[BUFFER_SIZE];
    snprintf(id_msg, sizeof(id_msg), "USERNAME:%s\n", username);
    int user_retries = 0;
    const int max_user_retries = 3;
    const int user_retry_delay = 1; // seconds

    while (user_retries < max_user_retries) {
        if (send(sock, id_msg, strlen(id_msg), 0) < 0) {
            printf("ERROR: Failed to send username (attempt %d/%d): %s\n", 
                   user_retries + 1, max_user_retries, strerror(errno));
            
            user_retries++;
            if (user_retries < max_user_retries) {
                printf("Retrying username send in %d second(s)...\n", user_retry_delay);
                sleep(user_retry_delay);
            } else {
                printf("All username send attempts failed. Giving up.\n");
                close(sock);
                return 1;
            }
        } else {
            break;
        }
    }
    // Run secure chat client
    if(client_mode(sock, username)){
        close(sock);
        return 1;
    }
    
    // Cleanup
    cleanup_client_resources(sock);
    return 0;
} 