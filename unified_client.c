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
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <netinet/tcp.h>
#include <sys/utsname.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "JWT_tools/jwtOperations.h"
#define PORT 12345
#define BUFFER_SIZE 2048
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
static int ecdh_ready = 0;
static char g_username[MAX_USERNAME_LEN] = "";
static char g_last_shutdown_reason[128] = "normal";

// JWT token storage
static char g_stored_jwt_token[2048] = "";
static char g_jwt_token_file[MAX_FILE_PATH_LEN] = "";


// RSA keys for automatic authentication + ECDH session state
typedef struct {
    EVP_PKEY *client_private_key;      
    EVP_PKEY *server_public_key;  
    // ECDH (X25519) ephemeral keypair for this connection
    EVP_PKEY *ecdh_keypair;
    unsigned char ecdh_public_raw[64];
    size_t ecdh_public_len;
    // Peer (server) ephemeral public key (raw)
    unsigned char peer_public_raw[64];
    size_t peer_public_len;
    // Derived shared secret and session key
    unsigned char *shared_secret;   
    size_t shared_secret_len;
    unsigned char symmetric_key[32]; // Final 256-bit key
    unsigned char hkdf_salt[RSA_CHALLENGE_SIZE]; // Salt for HKDF
    size_t hkdf_salt_len;
} dh_session_t;

dh_session_t dh_session;

char client_id[64] = "";  // Must be specified by user
unsigned int account_id = 0;  // Add account_id

// Authentication response checking
#define AUTH_SUCCESS "AUTH_SUCCESS"

// Function to cleanup client resources
void cleanup_client_resources(int client_socket);

// JWT token management function declarations
int load_jwt_token(const char* username);
void save_jwt_token(const char* token);
void clear_jwt_token();
int is_jwt_token_expired(const char* token);

// Global message storage
typedef struct {
    char message[BUFFER_SIZE];
    int valid;
} stored_message_t;

int derive_shared_secret(dh_session_t *session) {
    EVP_PKEY_CTX *ctx = NULL;
    int result = 0;
    size_t secret_length = 0;

    if (session == NULL || session->ecdh_keypair == NULL || session->peer_public_len == 0) {
        printf("ERROR: ECDH keys not ready\n");
        return 0;
    }

    EVP_PKEY *peer_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                     session->peer_public_raw, session->peer_public_len);
    if (!peer_key) {
        printf("ERROR: Failed to load peer ECDH public key\n");
        return 0;
    }

    ctx = EVP_PKEY_CTX_new(session->ecdh_keypair, NULL);
    if (ctx == NULL) {
        printf("ERROR: Failed to create derivation context\n");
        EVP_PKEY_free(peer_key);
        return 0;
    }
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        printf("ERROR: Failed to initialize derivation\n");
        goto cleanup;
    }
    if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0) {
        printf("ERROR: Failed to set peer public key\n");
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, NULL, &secret_length) <= 0) {
        fprintf(stderr, "Failed to determine secret length\n");
        goto cleanup;
    }
    session->shared_secret = OPENSSL_malloc(secret_length);
    if (!session->shared_secret) {
        fprintf(stderr, "Failed to allocate memory for shared secret\n");
        goto cleanup;
    }
    if (EVP_PKEY_derive(ctx, session->shared_secret, &secret_length) <= 0) {
        fprintf(stderr, "Failed to derive shared secret\n");
        OPENSSL_free(session->shared_secret);
        session->shared_secret = NULL;
        goto cleanup;
    }
    session->shared_secret_len = secret_length;
    
    result = 1;

cleanup:
    if (ctx) EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return result;
}

int derive_session_key(dh_session_t *session) {
    if (session == NULL || session->shared_secret == NULL || session->shared_secret_len == 0) {
        return 0;
    }
    // Use HKDF-SHA256 with salt to derive a 32-byte session key
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!kctx) return 0;
    size_t outlen = sizeof(session->symmetric_key);
    const unsigned char* hkdf_salt = session->hkdf_salt;
    size_t hkdf_salt_len = session->hkdf_salt_len;
    int ok = EVP_PKEY_derive_init(kctx) == 1 &&
             EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_salt(kctx, hkdf_salt, hkdf_salt_len) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_key(kctx, session->shared_secret, (int)session->shared_secret_len) == 1 &&
             EVP_PKEY_CTX_add1_hkdf_info(kctx, (const unsigned char*)"MFADH", 5) == 1 &&
             EVP_PKEY_derive(kctx, session->symmetric_key, &outlen) == 1;
    EVP_PKEY_CTX_free(kctx);
    if (ok) {
        // Debug: Print first 8 bytes of derived key
        printf("[ECDH] Session key derived successfully. First 8 bytes: ");
        for (int i = 0; i < 8 && i < (int)sizeof(session->symmetric_key); i++) {
            printf("%02x", session->symmetric_key[i]);
        }
        printf("\n");
        return 1;
    }
    else{
        printf("[ECDH] Failed to derive session key\n");
    }
    return 0;
}




static int hex_encode(const unsigned char* in, size_t len, char* out, size_t outsz) {
    static const char* hex = "0123456789abcdef";
    if (outsz < (len * 2 + 1)) return 0;
    for (size_t i = 0; i < len; i++) {
        out[i*2] = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[len*2] = '\0';
    return 1;
}

static int hex_decode(const char* in, unsigned char* out, size_t outsz, size_t* written) {
    size_t inlen = strlen(in);
    if (inlen % 2 != 0) return 0;
    size_t need = inlen / 2;
    if (need > outsz) return 0;
    for (size_t i = 0; i < need; i++) {
        unsigned int byte;
        if (sscanf(in + i*2, "%2x", &byte) != 1) return 0;
        out[i] = (unsigned char)byte;
    }
    if (written) *written = need;
    return 1;
}

// Generate client ECDH (X25519) ephemeral keypair
static int generate_dh_keys(dh_session_t* session) {
    if (!session) return 0;
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!kctx) return 0;
    if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); return 0; }
    if (EVP_PKEY_keygen(kctx, &session->ecdh_keypair) <= 0) { EVP_PKEY_CTX_free(kctx); return 0; }
    EVP_PKEY_CTX_free(kctx);
    session->ecdh_public_len = sizeof(session->ecdh_public_raw);
    if (EVP_PKEY_get_raw_public_key(session->ecdh_keypair, session->ecdh_public_raw, &session->ecdh_public_len) != 1) {
        EVP_PKEY_free(session->ecdh_keypair);
        session->ecdh_keypair = NULL;
        return 0;
    }
    return 1;
}



static int aes_gcm_decrypt_hex(const unsigned char* key,
                               const char* in_hex,
                               unsigned char* out_plain, size_t out_plain_sz,
                               size_t* out_written) {
    size_t bin_len_est = strlen(in_hex) / 2;
    unsigned char* bin = malloc(bin_len_est);
    if (!bin) {
        printf("[DECRYPT_DEBUG] Failed to allocate memory for binary data\n");
        return 0;
    }
    size_t bin_len = 0;
    if (!hex_decode(in_hex, bin, bin_len_est, &bin_len)) { 
        printf("[DECRYPT_DEBUG] Hex decode failed - hex length: %zu (should be even)\n", strlen(in_hex));
        printf("[DECRYPT_DEBUG] Last 20 chars of hex: %.20s\n", in_hex + strlen(in_hex) - 20);
        free(bin); 
        return 0; 
    }
    if (bin_len < 12 + 16) { 
        printf("[DECRYPT_DEBUG] Binary length too short: %zu, need at least 28\n", bin_len);
        free(bin); 
        return 0; 
    }
    //printf("[DECRYPT_DEBUG] Binary length OK: %zu bytes, ciphertext will be %zu bytes\n", bin_len, bin_len - 28);
    unsigned char *iv = bin;
    unsigned char *tag = bin + bin_len - 16;
    unsigned char *ciphertext = bin + 12;
    size_t clen = bin_len - 12 - 16;
    //printf("[DECRYPT_DEBUG] IV first 4 bytes: %02x%02x%02x%02x, Tag first 4 bytes: %02x%02x%02x%02x\n", 
           //iv[0], iv[1], iv[2], iv[3], tag[0], tag[1], tag[2], tag[3]);
    if (clen > out_plain_sz) { 
        printf("[DECRYPT_DEBUG] Ciphertext too large: %zu > %zu\n", clen, out_plain_sz);
        free(bin); 
        return 0; 
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(bin); return 0; }
    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) == 1;
    if (!ok) { 
        printf("[DECRYPT_DEBUG] EVP_DecryptInit failed\n");
        EVP_CIPHER_CTX_free(ctx); 
        free(bin); 
        return 0; 
    }
    int outlen = 0, tmplen = 0;
    if (EVP_DecryptUpdate(ctx, out_plain, &outlen, ciphertext, (int)clen) != 1) { 
        printf("[DECRYPT_DEBUG] EVP_DecryptUpdate failed, clen=%zu\n", clen);
        EVP_CIPHER_CTX_free(ctx); 
        free(bin); 
        return 0; 
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1) { 
        printf("[DECRYPT_DEBUG] EVP_CIPHER_CTX_ctrl SET_TAG failed\n");
        EVP_CIPHER_CTX_free(ctx); 
        free(bin); 
        return 0; 
    }
    if (EVP_DecryptFinal_ex(ctx, out_plain + outlen, &tmplen) != 1) { 
        printf("[DECRYPT_DEBUG] EVP_DecryptFinal_ex failed - authentication tag verification failed\n");
        EVP_CIPHER_CTX_free(ctx); 
        free(bin); 
        return 0; 
    }
    outlen += tmplen;
    EVP_CIPHER_CTX_free(ctx);
    free(bin);
    if (out_written) *out_written = (size_t)outlen;
    return 1;
}

ssize_t send_secure(const int server_socket, const char* data, size_t len) {
   
    if (server_socket >= 0 && ecdh_ready) {
        unsigned char iv[12];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            return send(server_socket, data, len, 0);
        }
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        if (!ectx) return send(server_socket, data, len, 0);
        int ok = EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
                 EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) == 1 &&
                 EVP_EncryptInit_ex(ectx, NULL, NULL, dh_session.symmetric_key, iv) == 1;
        if (!ok) { EVP_CIPHER_CTX_free(ectx); return send(server_socket, data, len, 0); }
        unsigned char ct[4096]; int ctlen = 0, t = 0;
        if (EVP_EncryptUpdate(ectx, ct, &ctlen, (const unsigned char*)data, (int)len) != 1 ||
            EVP_EncryptFinal_ex(ectx, ct + ctlen, &t) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            printf("Failed to encrypt message: %s\n", data);
            return send(server_socket, data, len, 0);
        }
        ctlen += t;
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            printf("Failed to get tag: %s\n", data);
            return send(server_socket, data, len, 0);
        }
        EVP_CIPHER_CTX_free(ectx);
        unsigned char frame[12 + (size_t)ctlen + 16];
        memcpy(frame, iv, 12);
        memcpy(frame + 12, ct, ctlen);
        memcpy(frame + 12 + ctlen, tag, 16);
        char hexbuf[8192];
        if (!hex_encode(frame, sizeof(frame), hexbuf, sizeof(hexbuf))) {
            printf("Failed to hex-encode message: %s\n", data);
            return send(server_socket, data, len, 0);
        }
        char enc_frame[8300];
        int n = snprintf(enc_frame, sizeof(enc_frame), "ENC %s\n", hexbuf);
        if (n < 0) return -1;
        return send(server_socket, enc_frame, (size_t)n, 0);
    }
    printf(" message sent: %s\n", data);
    return send(server_socket, data, len, 0);
}


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
    printf("Generating client debug report...\n");
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


// Load client's private key
int load_client_private_key(const char* username) {
    char key_file[MAX_FILE_PATH_LEN];
    snprintf(key_file, sizeof(key_file), "RSAkeys/client_%s_private.pem", username);
    
    FILE* fp = fopen(key_file, "r");
    if (!fp) {
        printf("ERROR: Could not open client private key: %s\n", key_file);
        return 0;
    }
    
    dh_session.client_private_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!dh_session.client_private_key) {
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
    
    dh_session.server_public_key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    
    if (!dh_session.server_public_key) {
        printf("ERROR: Could not read server public key\n");
        return 0;
    }

    return 1;
}

// Handle RSA challenge automatically
int handle_rsa_challenge(int socket, const char* hex_challenge) {
    if (!dh_session.client_private_key || !dh_session.server_public_key) {
        printf("RSA keys not loaded - cannot handle RSA challenge!\n");
        return 0;
    }
    
   
    size_t challenge_len = strlen(hex_challenge) / 2;
    unsigned char encrypted_challenge[MAX_RSA_ENCRYPTED_SIZE];
    
    if (challenge_len != MAX_RSA_ENCRYPTED_SIZE) {
        printf("ERROR: Encrypted challenge length mismatch! Expected %d, got %zu\n", 
               MAX_RSA_ENCRYPTED_SIZE, challenge_len);
        return 0;
    }
    
    for (size_t i = 0; i < challenge_len; i++) {
        sscanf(hex_challenge + (i * 2), "%2hhx", &encrypted_challenge[i]);
    }
    
    // Decrypt challenge with client private key
    EVP_PKEY_CTX *decrypt_ctx = EVP_PKEY_CTX_new(dh_session.client_private_key, NULL);
    if (!decrypt_ctx || EVP_PKEY_decrypt_init(decrypt_ctx) <= 0 || 
        EVP_PKEY_CTX_set_rsa_padding(decrypt_ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        if (decrypt_ctx) EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to setup RSA decryption\n");
        return 0;
    }
    
    unsigned char decrypted_challenge[RSA_DECRYPT_BUFFER_SIZE];
    size_t decrypted_len = sizeof(decrypted_challenge);
    
    
    if (EVP_PKEY_decrypt(decrypt_ctx, decrypted_challenge, &decrypted_len, encrypted_challenge, challenge_len) <= 0) {
        ERR_print_errors_fp(stdout);
        PEM_write_PrivateKey(stdout, dh_session.client_private_key, NULL, NULL, 0, NULL, NULL);
        EVP_PKEY_CTX_free(decrypt_ctx);
        printf("Failed to decrypt RSA challenge\n");
        return 0;
    }
    if(decrypted_len >= RSA_CHALLENGE_SIZE){
        memcpy(dh_session.hkdf_salt, decrypted_challenge, RSA_CHALLENGE_SIZE);
        dh_session.hkdf_salt_len = RSA_CHALLENGE_SIZE;
    }else{
        dh_session.hkdf_salt_len = 0;
        dh_session.hkdf_salt[0] = 0;
    }
    EVP_PKEY_CTX_free(decrypt_ctx);
    
    
    
    if (decrypted_len != RSA_CHALLENGE_SIZE) {
        printf("WARNING: Decrypted length mismatch! Expected %d, got %zu\n", 
               RSA_CHALLENGE_SIZE, decrypted_len);
    }
    
    // Encrypt decrypted challenge with server public key
    EVP_PKEY_CTX *encrypt_ctx = EVP_PKEY_CTX_new(dh_session.server_public_key, NULL);
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
   
    
    if (EVP_PKEY_encrypt(encrypt_ctx, encrypted_response, &encrypted_len, decrypted_challenge, input_len) <= 0) {
        ERR_print_errors_fp(stdout);
        EVP_PKEY_CTX_free(encrypt_ctx);
        printf("Failed to encrypt RSA response\n");
        return 0;
    }
    EVP_PKEY_CTX_free(encrypt_ctx);
    
    
    
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
    
    
    // Clear sensitive data
    memset(decrypted_challenge, 0, sizeof(decrypted_challenge));
    memset(encrypted_response, 0, sizeof(encrypted_response));
    
    return 1;
}

// Cleanup RSA keys
void cleanup_rsa_keys(void) {
    if (dh_session.client_private_key) {
        EVP_PKEY_free(dh_session.client_private_key);
        dh_session.client_private_key = NULL;
    }
    if (dh_session.server_public_key) {
        EVP_PKEY_free(dh_session.server_public_key);
        dh_session.server_public_key = NULL;
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
MessageResult handle_ecdh_messages(int client_socket, const char* buffer);
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
        
        // If secure and message is encrypted, decrypt first and then process
        if (ecdh_ready && strncmp(buffer, "ENC ", 4) == 0) {
            // Handle multiple ENC messages in the buffer
            char* current_pos = buffer;
            while (current_pos && strncmp(current_pos, "ENC ", 4) == 0) {
                char* hex = current_pos + 4;
                
                // Find the end of this ENC message (look for next ENC or end of buffer)
                char* next_enc = strstr(hex, "\nENC ");
                char* msg_end = hex + strlen(hex);  // Default to end of buffer
                
                if (next_enc) {
                    msg_end = next_enc;  // End at the newline before next ENC
                    *msg_end = '\0';     // Temporarily null-terminate this message
                }
                
                //printf("[DEBUG] Processing ENC message, hex length before trim: %zu\n", strlen(hex));
                
                // Trim trailing newline/CR/whitespace from this hex payload
                char* end = hex + strlen(hex);
                while (end > hex && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) {
                    end--;
                }
                *end = '\0';
                
                //printf("[DEBUG] After trimming, hex length: %zu (should be even)\n", strlen(hex));
                if (strlen(hex) % 2 != 0) {
                    printf("[DEBUG] ODD hex length detected! Last char: '%c' (0x%02x)\n", 
                           hex[strlen(hex)-1], (unsigned char)hex[strlen(hex)-1]);
                }
                
                unsigned char plain[BUFFER_SIZE]; 
                size_t written = 0;
                if (aes_gcm_decrypt_hex(dh_session.symmetric_key, hex, plain, sizeof(plain)-1, &written)) {
                    plain[written] = '\0';
                    // Process decrypted plaintext as if received
                    MessageResult result = process_server_message(client_socket, (const char*)plain);
                    if (result == MSG_EXIT) {
                        snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason), "auth_or_rsa_exit");
                        generate_client_debug_report(g_last_shutdown_reason, client_socket, 0);
                        running = 0;
                        goto exit_receive_loop;
                    }
                    if (result == MSG_PROCESSED) {
                        show_appropriate_prompt();
                    }
                } else {
                    printf("[SECURE] Failed to decrypt ENC message\n");
                    printf("[DEBUG] Hex length: %zu, expected min: %d (12+16=28)\n", strlen(hex), 28);
                    printf("[DEBUG] First 32 chars of hex: %.32s\n", hex);
                    printf("[DEBUG] Key first 8 bytes: ");
                    for (int i = 0; i < 8; i++) {
                        printf("%02x", dh_session.symmetric_key[i]);
                    }
                    printf("\n");
                }
                
                // Move to next ENC message if there is one
                if (next_enc) {
                    current_pos = next_enc + 1;  // Skip the newline
                } else {
                    break;  // No more ENC messages
                }
            }
            continue;
        }
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
    
exit_receive_loop:
    return NULL;
}

MessageResult process_server_message(int client_socket, const char* buffer) {
    // Store the message first
    store_message(buffer);
    
    // Debug: Print all received messages
    //printf("[DEBUG] Client received: '%.100s%s'\n", buffer, strlen(buffer) > 100 ? "..." : "");
    
    // Handle RSA authentication
    MessageResult rsa_result = handle_rsa_messages(client_socket, buffer);
    if (rsa_result != MSG_PROCESSED) {
        return rsa_result;
    }
    // Handle ECDH exchange
    MessageResult ecdh_result = handle_ecdh_messages(client_socket, buffer);
    if (ecdh_result != MSG_PROCESSED) {
        return ecdh_result;
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
    
    // Handle JWT tokens
    if (strncmp(buffer, "JWT ", 4) == 0) {
        const char* token = buffer + 4;
        // Remove trailing newline if present
        char* newline = strchr(token, '\n');
        if (newline) *newline = '\0';
        
        printf("[JWT] Received new token from server (length: %zu)\n", strlen(token));
        printf("[JWT] Token preview: %.50s...\n", token);
        save_jwt_token(token);
        return MSG_PROCESSED;
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
            
            return MSG_CONTINUE;
        } else {
            printf("[RSA] FAILED: RSA authentication failed! Connection may be terminated.\n");
            return MSG_EXIT;
        }
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

// Handle ECDH messages
MessageResult handle_ecdh_messages(int client_socket, const char* buffer) {
    if (strncmp(buffer, "ECDH_SERVER_PUB", 15) == 0) {
        //printf("[ECDH] Received server public key\n");
        const char* hex = buffer + 16;
        const char* nl = strchr(hex, '\n');
        char hexbuf[256];
        if (nl) {
            size_t n = (size_t)(nl - hex);
            if (n >= sizeof(hexbuf)) n = sizeof(hexbuf) - 1;
            memcpy(hexbuf, hex, n);
            hexbuf[n] = '\0';
            hex = hexbuf;
        }
        size_t written = 0;
        if (!hex_decode(hex, dh_session.peer_public_raw, sizeof(dh_session.peer_public_raw), &written)) {
            printf("[ECDH] Failed to parse server ECDH public key\n");
            return MSG_PROCESSED;
        }
        dh_session.peer_public_len = written;
        if (!derive_shared_secret(&dh_session) || !derive_session_key(&dh_session)) {
            printf("[ECDH] Failed to derive session key\n");
            return MSG_PROCESSED;
        }
        //printf("[ECDH] Session keys derived, waiting for ECDH_OK to enable encryption\n");
        // Send our ECDH public key to server
        char hexpub[256];
        if (!hex_encode(dh_session.ecdh_public_raw, dh_session.ecdh_public_len, hexpub, sizeof(hexpub))) {
            return MSG_PROCESSED;
        }
        char msg[300];
        snprintf(msg, sizeof(msg), "ECDH_CLIENT_PUB %s\n", hexpub);
        send(client_socket, msg, strlen(msg), 0);
        //printf("[ECDH] Sent client public key, waiting for ECDH_OK\n");
        return MSG_CONTINUE;
    }
    if (strncmp(buffer, "ECDH_OK", 7) == 0) {
        ecdh_ready = 1; // Enable encryption after receiving ECDH_OK confirmation
        printf("[ECDH] ECDH_OK received - handshake complete, encryption now enabled\n");

        // After ECDH is ready, try to resume with JWT token
        if (strlen(g_stored_jwt_token) > 0) {
            // Check if token is expired before attempting to resume
            if (is_jwt_token_expired(g_stored_jwt_token)) {
                printf("[JWT] Stored token is expired, cleaning up...\n");
                clear_jwt_token();
            } else {
                printf("[JWT] ECDH handshake complete, attempting to resume session with stored token...\n");
                char resume_cmd[BUFFER_SIZE];
                snprintf(resume_cmd, sizeof(resume_cmd), "/resume %s", g_stored_jwt_token);

                if (send_secure(client_socket, resume_cmd, strlen(resume_cmd)) > 0) {
                    printf("[JWT] Resume command sent, waiting for server response...\n");
                    return MSG_CONTINUE;
                } else {
                    printf("[JWT] Failed to send resume command, proceeding with normal authentication...\n");
                }
            }
        }

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
    // Control message from server: request debug report on exit
    if (strncmp(buffer, "DEBUG_ON_EXIT ", 14) == 0) {
        strncpy(g_last_shutdown_reason, "debug_on_exit", sizeof(g_last_shutdown_reason)-1);
        g_last_shutdown_reason[sizeof(g_last_shutdown_reason)-1] = '\0';
        printf("[CTRL] Server requested client to generate debug report on exit.\n");
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

    if (strstr(buffer, "JWT_TOKEN_FAILED")) {
        printf("[JWT] Token verification failed, continuing with normal authentication flow...\n");
        printf("Please use /login <username> <password> to login\n");
        show_appropriate_prompt();
        clear_jwt_token(); 
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
            // Save the new JWT token that should be received after full authentication
            return MSG_CONTINUE;
        }
        if (strstr(buffer, "AUTH_SUCCESS") && strstr(buffer, "JWT")) {
            password_authenticated = 1;
            printf("\nPassword verified from JWT. Please check your email for a 6-digit token.\n");
            printf("Use /token <code> to enter the token, or /newToken to request a new one.\n");
            struct timespec delay = {0, 150000000};
            nanosleep(&delay, NULL);
            show_appropriate_prompt();
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

    // Cleanup ECDH ephemeral materials and reset state
    ecdh_ready = 0;
    if (dh_session.ecdh_keypair) {
        EVP_PKEY_free(dh_session.ecdh_keypair);
        dh_session.ecdh_keypair = NULL;
    }
    if (dh_session.shared_secret) {
        OPENSSL_cleanse(dh_session.shared_secret, dh_session.shared_secret_len);
        OPENSSL_free(dh_session.shared_secret);
        dh_session.shared_secret = NULL;
        dh_session.shared_secret_len = 0;
    }
    OPENSSL_cleanse(dh_session.symmetric_key, sizeof(dh_session.symmetric_key));
    OPENSSL_cleanse(dh_session.ecdh_public_raw, dh_session.ecdh_public_len);
    dh_session.ecdh_public_len = 0;
    OPENSSL_cleanse(dh_session.peer_public_raw, dh_session.peer_public_len);
    dh_session.peer_public_len = 0;
    
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

    // Ensure run loop is active for a fresh connection (in case prior session set it to 0)
    running = 1;

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

    // Try to resume with JWT token if available, but wait for server to be ready first
    if (strlen(g_stored_jwt_token) > 0) {
        printf("[JWT] Stored token found, will attempt resume after server initialization...\n");
    }

    // Synchronously wait for and handle RSA challenge and ECDH handshake before starting receive thread
    int rsa_auth_complete = 0;
    while (!rsa_auth_complete && running) {
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            printf("\nServer disconnected\n");
            running = 0;
            return 0;
        }

        buffer[bytes_received] = '\0';
        MessageResult result = process_server_message(client_socket, buffer);
        if (result == MSG_EXIT) {
            running = 0;
            return 0;
        }
        // If JWT resume was successful, skip to main loop
        if (result == MSG_CONTINUE && password_authenticated && email_authenticated) {
            printf("[JWT] Resuming to main chat loop...\n");
            rsa_auth_complete = 1;
            continue;
        }
        // If server indicates immediate success (no RSA/ECDH), finish bootstrap
        if (strstr(buffer, "AUTH_SUCCESS") && !strstr(buffer, "RSA_AUTH_SUCCESS")) {
            ecdh_ready = 1;
            rsa_auth_complete = 1;
            continue;
        }
        // When RSA and ECDH are both ready, we can proceed
        if (rsa_completed && ecdh_ready) {
            printf("[AUTH] RSA and ECDH authentication completed successfully!\n");
            printf("[AUTH] You may now login with your username and password. Use /login <username> <password> to login\n\n");
            rsa_auth_complete = 1;
        }
    }

    // Now start the receive thread for chat and further messages
    if (pthread_create(&receive_thread, NULL, receive_messages, &client_socket) != 0) {
        printf("Failed to create receive thread\n");
        snprintf(g_last_shutdown_reason, sizeof(g_last_shutdown_reason), "pthread_create_failed");
        generate_client_debug_report(g_last_shutdown_reason, client_socket, errno);
        return 0;
    }

    // Show appropriate prompt since authentication handshake is complete
    show_appropriate_prompt();

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
                send_secure(client_socket, buffer, strlen(buffer));
                continue;
            }
            if (!password_authenticated) {
                if (strncmp(buffer, "/login", 6) == 0)  {
                    
                    if (send_secure(client_socket, buffer, strlen(buffer)) < 0) {
                        printf("Failed to send message\n");
                        running = 0;
                        break;
                    }
                    
                }
                else if (!locked) {
                    printf("Please authenticate first. Use: /login <username> <password>\n");
                    printf("auth> ");
                    continue;
                }
                else{
                    printf("Please use /login <username> <password> to login\n");
                    show_appropriate_prompt();
                    continue;
                }

            }
            else if(!email_authenticated) {
                if(strncmp(buffer, "/token", 6) == 0 || strncmp(buffer, "/newToken", 9) == 0){
                    //printf("[CLIENT_DEBUG] Sending token command to server: '%s'\n", buffer);
                    if (send_secure(client_socket, buffer, strlen(buffer)) < 0) {
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
                // Use send_secure for all post-authentication messages
                if (send_secure(client_socket, buffer, strlen(buffer)) < 0) {
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
                show_appropriate_prompt();
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

// JWT token management functions
int load_jwt_token(const char* username) {
    if (!username) return 0;
    
    // Set JWT token file path
    snprintf(g_jwt_token_file, sizeof(g_jwt_token_file), "JWT_tokens/client_%s.jwt", username);
    
    // Create JWT_tokens directory if it doesn't exist
    char dir_path[MAX_FILE_PATH_LEN];
    snprintf(dir_path, sizeof(dir_path), "JWT_tokens");
    mkdir(dir_path, 0755);
    
    // Try to load existing token
    FILE* fp = fopen(g_jwt_token_file, "r");
    if (!fp) {
        printf("[JWT] No stored token found for user '%s'\n", username);
        return 0;
    }
    
    size_t bytes_read = fread(g_stored_jwt_token, 1, sizeof(g_stored_jwt_token) - 1, fp);
    fclose(fp);
    
    if (bytes_read > 0) {
        g_stored_jwt_token[bytes_read] = '\0';
        // Remove trailing newlines
        size_t len = strlen(g_stored_jwt_token);
        while (len > 0 && (g_stored_jwt_token[len-1] == '\n' || g_stored_jwt_token[len-1] == '\r')) {
            g_stored_jwt_token[--len] = '\0';
        }
        printf("[JWT] Loaded stored token for user '%s' (%zu bytes)\n", username, len);
        return 1;
    }
    
    return 0;
}

void save_jwt_token(const char* token) {
    if (!token || strlen(token) == 0) return;
    
    FILE* fp = fopen(g_jwt_token_file, "w");
    if (!fp) {
        printf("[JWT] Warning: Could not save token to file\n");
        return;
    }
    
    fwrite(token, 1, strlen(token), fp);
    fclose(fp);
    
    // Store in memory as well
    strncpy(g_stored_jwt_token, token, sizeof(g_stored_jwt_token) - 1);
    g_stored_jwt_token[sizeof(g_stored_jwt_token) - 1] = '\0';
    
    printf("[JWT] Token saved successfully\n");
}

void clear_jwt_token() {
    // Clear from memory
    memset(g_stored_jwt_token, 0, sizeof(g_stored_jwt_token));
    
    // Remove file if it exists
    if (strlen(g_jwt_token_file) > 0) {
        unlink(g_jwt_token_file);
        printf("[JWT] Token cleared and file removed\n");
    }
}

// Check if JWT token is expired
int is_jwt_token_expired(const char* token) {
    if (!token || strlen(token) == 0) return 1;
    
    // JWT format: header.payload.signature
    char* first_dot = strchr(token, '.');
    if (!first_dot) return 1;
    
    char* second_dot = strchr(first_dot + 1, '.');
    if (!second_dot) return 1;
    
    // Extract payload section
    size_t payload_len = second_dot - first_dot - 1;
    if (payload_len == 0) return 1;
    
    char* payload_encoded = (char*)malloc(payload_len + 1);
    if (!payload_encoded) return 1;
    
    memcpy(payload_encoded, first_dot + 1, payload_len);
    payload_encoded[payload_len] = '\0';
    
    // Base64 decode payload
    size_t decoded_len = (payload_len * 3) / 4; // Base64 decoding size estimate
    unsigned char* payload_decoded = (unsigned char*)malloc(decoded_len + 1);
    if (!payload_decoded) {
        free(payload_encoded);
        return 1;
    }
    
    if (!b64url_to_raw(payload_encoded, payload_decoded, decoded_len, &decoded_len)) {
        free(payload_encoded);
        free(payload_decoded);
        return 1;
    }
    
    payload_decoded[decoded_len] = '\0';
    free(payload_encoded);
    
    // Parse JSON payload to find "exp" field
    char* exp_pos = strstr((char*)payload_decoded, "\"exp\"");
    if (!exp_pos) {
        free(payload_decoded);
        return 1; // No expiration field found, assume expired
    }
    
    // Look for the expiration timestamp value
    char* colon_pos = strchr(exp_pos, ':');
    if (!colon_pos) {
        free(payload_decoded);
        return 1;
    }
    
    // Skip whitespace and find the number
    char* num_start = colon_pos + 1;
    while (*num_start == ' ' || *num_start == '\t' || *num_start == '\n' || *num_start == '\r') {
        num_start++;
    }
    
    // Extract the timestamp value
    char* num_end = num_start;
    while (*num_end >= '0' && *num_end <= '9') {
        num_end++;
    }
    
    if (num_end == num_start) {
        free(payload_decoded);
        return 1; // No valid number found
    }
    
    // Temporarily null-terminate for strtol
    char temp = *num_end;
    *num_end = '\0';
    long exp_timestamp = strtol(num_start, NULL, 10);
    *num_end = temp; // Restore original character
    
    free(payload_decoded);
    
    if (exp_timestamp <= 0) return 1;
    
    // Compare with current time
    time_t current_time = time(NULL);
    return (current_time >= exp_timestamp);
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
    
    // Load JWT token if available
    load_jwt_token(username);
    
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
        printf("RSA keys loaded. Generating ECDH keys... \n");
        if (!generate_dh_keys(&dh_session)) {
            printf("Failed to generate ECDH keys\n");
            return 1;
        }
        printf("ECDH keys ready. Connecting to server...\n");
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
    if(client_mode(sock, username)){
        close(sock);
        return 1;
    }
    
    // Cleanup
    cleanup_client_resources(sock);
    return 0;
} 