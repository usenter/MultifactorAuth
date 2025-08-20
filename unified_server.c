#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include "auth_system.h"
#include "hashmap/uthash.h"
#include "fileOperationTools/fileOperations.h" // File mode operations
#include "configTools/serverConfig.h"
#include "REST_tools/serverRest.h"
#include "IPTableFunctions/IPtableFunctions.h"

// Function to check client connection health
int check_client_health(int socket) {
    // Check if socket is still valid   
    if (fcntl(socket, F_GETFD) == -1) {
        return 0; // Socket is invalid
    }
    
    // Try to get socket error status
    int error = 0;
    socklen_t len = sizeof(error);
    if (getsockopt(socket, SOL_SOCKET, SO_ERROR, &error, &len) == -1) {
        return 0; // Socket error
    }
    
    if (error != 0) {
        return 0; // Socket has error
    }
    
    return 1; // Socket is healthy
}

// Optional: Apply basic iptables mitigation at server start and remove at shutdown
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

// Async-signal-safe shutdown signaling
static volatile sig_atomic_t shutdown_flag = 0;
static int shutdown_pipe[2] = { -1, -1 }; // [0]=read, [1]=write





int setup_initial_connection(int client_socket);
void* handle_authenticated_client(void* arg);

#define PORT 12345
#define REST_PORT 8080
#define DEFAULT_USER_FILE "encrypted_users.txt"
#define SERVER_CONFIG_PATH "configTools/serverConf.json"
#define PROGRAM_NAME "AuthenticatedChatServer"
char default_cwd[256] = "UserDirectory";
int server_socket = -1;
pthread_mutex_t server_socket_mutex = PTHREAD_MUTEX_INITIALIZER; // NEW: protect server socket


// Thread communication
typedef struct {
    int epoll_fd;            // epoll fd for this thread
    pthread_t thread_id;
    volatile int running;
} thread_context_t;

thread_context_t auth_thread_ctx;
thread_context_t cmd_thread_ctx;

// REST API server (now handled by serverRest.c)
struct MHD_Daemon *rest_daemon = NULL;

// External declarations for auth system
extern user_t *user_map;
extern pthread_mutex_t user_map_mutex;


volatile int server_running = 1;
char* user_file = DEFAULT_USER_FILE;
char* emailPassword = NULL; // Fill this in if you disable useJSON parameter in emailTest.c



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

// Send message securely if session key exists for this socket; otherwise plaintext
ssize_t send_secure(int client_socket, const char* data, size_t len) {
    socket_info_t *sinfo = get_socket_info(client_socket);
    session_t *sess = (sinfo && sinfo->account_id > 0) ? find_session(sinfo->account_id) : NULL;
    if (sess && sess->session_key[0] != 0) {
        unsigned char iv[12];
        if (RAND_bytes(iv, sizeof(iv)) != 1) {
            return send(client_socket, data, len, 0);
        }
        EVP_CIPHER_CTX* ectx = EVP_CIPHER_CTX_new();
        if (!ectx) return send(client_socket, data, len, 0);
        int ok = EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
                 EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(iv), NULL) == 1 &&
                 EVP_EncryptInit_ex(ectx, NULL, NULL, sess->session_key, iv) == 1;
        if (!ok) { EVP_CIPHER_CTX_free(ectx); return send(client_socket, data, len, 0); }
        unsigned char ct[4096]; int ctlen = 0, t = 0;
        if (EVP_EncryptUpdate(ectx, ct, &ctlen, (const unsigned char*)data, (int)len) != 1 ||
            EVP_EncryptFinal_ex(ectx, ct + ctlen, &t) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            return send(client_socket, data, len, 0);
        }
        ctlen += t;
        unsigned char tag[16];
        if (EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
            EVP_CIPHER_CTX_free(ectx);
            return send(client_socket, data, len, 0);
        }
        EVP_CIPHER_CTX_free(ectx);
        unsigned char frame[12 + (size_t)ctlen + 16];
        memcpy(frame, iv, 12);
        memcpy(frame + 12, ct, ctlen);
        memcpy(frame + 12 + ctlen, tag, 16);
        char hexbuf[8192];
        if (!hex_encode(frame, sizeof(frame), hexbuf, sizeof(hexbuf))) {
            return send(client_socket, data, len, 0);
        }
        char enc_frame[8300];
        int n = snprintf(enc_frame, sizeof(enc_frame), "ENC %s\n", hexbuf);
        if (n < 0) return -1;
        return send(client_socket, enc_frame, (size_t)n, 0);
    }
    return send(client_socket, data, len, 0);
}

// Decrypt ENC frame in-place if present and key available
static void decrypt_inplace_if_needed(int client_socket, char* buffer, size_t bufsize) {
    char log_message[BUFFER_SIZE];
    
    if (strncmp(buffer, "ENC ", 4) != 0) return;
    socket_info_t *sinfo = get_socket_info(client_socket);
    if (!sinfo || sinfo->account_id <= 0) {
        printf("[DECRYPT] No socket info or invalid account_id for socket %d\n", client_socket);
        return;
    }
    session_t *sess = find_session(sinfo->account_id);
    if (!sess || sess->session_key[0] == 0) {
        printf("[DECRYPT] No session or session keys for account_id %d\n", sinfo->account_id);
        return;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Decrypting message: %s\n", 
                         sinfo->account_id, buffer);
    FILE_LOG(log_message);
    const char* hex = buffer + 4;
    size_t hexlen = strlen(hex);
    size_t bin_need = hexlen / 2;
    unsigned char *tmp = malloc(bin_need);
    if (!tmp) return;
    size_t binw = 0;
    if (!hex_decode(hex, tmp, bin_need, &binw) || binw < 12 + 16) { free(tmp); return; }
    unsigned char *iv = tmp;
    unsigned char *tag = tmp + binw - 16;
    unsigned char *ct = tmp + 12;
    size_t ctlen = binw - 12 - 16;
    EVP_CIPHER_CTX* dctx = EVP_CIPHER_CTX_new();
    if (!dctx) { free(tmp); return; }
    int ok = EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(dctx, NULL, NULL, sess->session_key, iv) == 1;
    if (!ok) { EVP_CIPHER_CTX_free(dctx); free(tmp); return; }
    int outl = 0, t = 0;
    unsigned char out[BUFFER_SIZE];
    if (EVP_DecryptUpdate(dctx, out, &outl, ct, (int)ctlen) == 1 &&
        EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, 16, tag) == 1 &&
        EVP_DecryptFinal_ex(dctx, out + outl, &t) == 1) {
        size_t wrote = (size_t)(outl + t);
        if (wrote >= bufsize) wrote = bufsize - 1;
        memcpy(buffer, out, wrote);
        buffer[wrote] = '\0';
        printf("[DECRYPT] Successfully decrypted message for account_id %d: '%s'\n", sinfo->account_id, buffer);
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Successfully decrypted message for account_id %d: '%s'\n", 
                         sinfo->account_id, sinfo->account_id, buffer);
        FILE_LOG(log_message);
    } else {
        printf("[DECRYPT] Failed to decrypt message for account_id %d\n", sinfo->account_id);
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Failed to decrypt message for account_id %d\n", 
                         sinfo->account_id, sinfo->account_id);
        FILE_LOG(log_message);
    }
    EVP_CIPHER_CTX_free(dctx);
    free(tmp);
}

static int send_ecdh_server_pub(int client_socket, unsigned int account_id) {
    session_t *session = find_session(account_id);
    if (!session) return 0;
    if (!session->ecdh_keypair) {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
        if (!kctx) return 0;
        if (EVP_PKEY_keygen_init(kctx) <= 0) { EVP_PKEY_CTX_free(kctx); return 0; }
        if (EVP_PKEY_keygen(kctx, &session->ecdh_keypair) <= 0) { EVP_PKEY_CTX_free(kctx); return 0; }
        EVP_PKEY_CTX_free(kctx);
    }
    unsigned char pub[64]; size_t publen = sizeof(pub);
    if (EVP_PKEY_get_raw_public_key(session->ecdh_keypair, pub, &publen) != 1) return 0;
    char hexpub[256];
    if (!hex_encode(pub, publen, hexpub, sizeof(hexpub))) return 0;
    char msg[300];
    snprintf(msg, sizeof(msg), "ECDH_SERVER_PUB %s\n", hexpub);
    send(client_socket, msg, strlen(msg), 0);
    return 1;
}

static int handle_ecdh_client_pub(int client_socket, unsigned int account_id, const char* hex) {
    session_t *session = find_session(account_id);
    if (!session || !session->ecdh_keypair) return 0;
    size_t written = 0;
    if (!hex_decode(hex, session->ecdh_peer_pub, sizeof(session->ecdh_peer_pub), &written)) return 0;
    session->ecdh_peer_pub_len = written;

    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                 session->ecdh_peer_pub, session->ecdh_peer_pub_len);
    if (!peer) return 0;
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(session->ecdh_keypair, NULL);
    if (!dctx) { EVP_PKEY_free(peer); return 0; }
    if (EVP_PKEY_derive_init(dctx) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return 0; }
    if (EVP_PKEY_derive_set_peer(dctx, peer) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return 0; }
    size_t seclen = 0;
    if (EVP_PKEY_derive(dctx, NULL, &seclen) <= 0) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return 0; }
    unsigned char *sec = OPENSSL_malloc(seclen);
    if (!sec) { EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return 0; }
    if (EVP_PKEY_derive(dctx, sec, &seclen) <= 0) { OPENSSL_free(sec); EVP_PKEY_free(peer); EVP_PKEY_CTX_free(dctx); return 0; }
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(dctx);

    // HKDF-SHA256 to derive 32-byte session key
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    size_t outlen = sizeof(session->session_key);
    int ok = kctx && EVP_PKEY_derive_init(kctx) == 1 &&
             EVP_PKEY_CTX_set_hkdf_md(kctx, EVP_sha256()) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_salt(kctx, NULL, 0) == 1 &&
             EVP_PKEY_CTX_set1_hkdf_key(kctx, sec, (int)seclen) == 1 &&
             EVP_PKEY_CTX_add1_hkdf_info(kctx, (const unsigned char*)"MFADH", 5) == 1 &&
             EVP_PKEY_derive(kctx, session->session_key, &outlen) == 1;
    if (kctx) EVP_PKEY_CTX_free(kctx);
    OPENSSL_free(sec);
    if (!ok) return 0;
    printf("[ECDH] Sending ECDH_OK to client\n");
    send(client_socket, "ECDH_OK\n", 8, 0);
    return 1;
}

void broadcast_message(const char* message, int sender_socket, int overrideBroadcast) {
    char log_message[BUFFER_SIZE];

    if (!message) return;
    
    char* message_with_newline = malloc(strlen(message) + 2);
    if (!message_with_newline) {
        printf("Failed to allocate memory for broadcast message\n");
        return;
    }
    memset(message_with_newline, 0, strlen(message) + 2);
    
    strncpy(message_with_newline, message, strlen(message));
    strncat(message_with_newline, "\n", 1);
    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] Broadcasting message: %s", message_with_newline);
    FILE_LOG(log_message);
    
    pthread_mutex_lock(&clients_mutex);
    client_t *c, *tmp;
    HASH_ITER(hh, clients_map, c, tmp) {
        if ((c->active && c->socket != sender_socket) && 
            (c->mode == CLIENT_MODE_CHAT || overrideBroadcast)) {
            
            // Send with error checking but don't hold mutex during send
			int client_socket = c->socket;
			size_t mlen = strlen(message_with_newline);
			ssize_t sent = send_secure(client_socket, message_with_newline, mlen);
			if (sent < 0) {
				int send_errno = errno;
				struct sockaddr_in peer; socklen_t plen = sizeof(peer);
				char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
				if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
					inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
					port = ntohs(peer.sin_port);
				}
				int soerr = 0; socklen_t slen = sizeof(soerr);
				getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
				struct tcp_info tcpi; 
                socklen_t tlen = sizeof(tcpi);
				int have_tcpi = (getsockopt(client_socket, IPPROTO_TCP, TCP_INFO, &tcpi, &tlen) == 0);

				// If the non-blocking socket would block, do NOT mark inactive; skip and try later
				if (send_errno == EAGAIN || send_errno == EWOULDBLOCK) {
					const char *mode_str = (c->mode == CLIENT_MODE_CHAT) ? "chat" : "file";
					snprintf(log_message, sizeof(log_message),
						"[DEBUG][BROADCAST][ID:%u user:%s nick:%s mode:%s] send would block on socket %d peer=%s:%d; skipping for now (errno=%d:%s)\n",
						c->account_id, c->username, c->nickname, mode_str,
						client_socket, ip, port, send_errno, strerror(send_errno));
					FILE_LOG(log_message);
				} else {
					const char *mode_str = (c->mode == CLIENT_MODE_CHAT) ? "chat" : "file";
					snprintf(log_message, sizeof(log_message),
						"[WARN][BROADCAST][ID:%u user:%s nick:%s mode:%s] send to socket %d peer=%s:%d failed: errno=%d(%s) SO_ERROR=%d(%s)%s%s\n",
						c->account_id, c->username, c->nickname, mode_str,
						client_socket, ip, port, send_errno, strerror(send_errno), soerr, strerror(soerr),
						have_tcpi ? " TCP_STATE=" : "", have_tcpi ? "" : "");
					FILE_LOG(log_message);
					if (have_tcpi) {
						snprintf(log_message, sizeof(log_message),
							"[WARN][BROADCAST][ID:%u] tcp_info: state=%u rtt=%u rttvar=%u snd_cwnd=%u retrans=%u unacked=%u\n",
							c->account_id,
							tcpi.tcpi_state, tcpi.tcpi_rtt, tcpi.tcpi_rttvar,
							tcpi.tcpi_snd_cwnd, tcpi.tcpi_retransmits, tcpi.tcpi_unacked);
						FILE_LOG(log_message);
					}
					// Only mark inactive for real errors
					c->active = 0;
				}
			} else if ((size_t)sent < mlen) {
				const char *mode_str = (c->mode == CLIENT_MODE_CHAT) ? "chat" : "file";
				snprintf(log_message, sizeof(log_message),
					"[WARN][BROADCAST][ID:%u user:%s nick:%s mode:%s] partial send to socket %d: sent=%zd of %zu bytes\n",
					c->account_id, c->username, c->nickname, mode_str,
					client_socket, sent, mlen);
				FILE_LOG(log_message);
			}
            
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    free(message_with_newline);
}
void remove_client(int client_socket) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] Starting cleanup for socket %d\n", client_socket);
    FILE_LOG(log_message);
    
    client_t *c = NULL;
    
    // Acquire mutex first to prevent race conditions
    pthread_mutex_lock(&clients_mutex);
    HASH_FIND_INT(clients_map, &client_socket, c);
    if (!c) {
        pthread_mutex_unlock(&clients_mutex);
        snprintf(log_message, sizeof(log_message), "[WARN][CLEANUP] No client found for socket %d\n", client_socket);
        FILE_LOG(log_message);
        // Fallback cleanup for sockets that disconnected before promotion
        unsigned int fallback_account_id = 0;
        socket_info_t *sinfo = get_socket_info(client_socket);
        if (sinfo) {
            fallback_account_id = sinfo->account_id;
        }
        // Remove from socket tracking
        remove_socket_info(client_socket);
        // Remove from epolls
        int epoll_result = epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
        if (epoll_result < 0 && errno != ENOENT) {
            snprintf(log_message, sizeof(log_message), "[WARN][CLEANUP] Failed to remove socket %d from auth epoll: %s\n",
                    client_socket, strerror(errno));
            FILE_LOG(log_message);
        }
        epoll_result = epoll_ctl(cmd_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
        if (epoll_result < 0 && errno != ENOENT) {
            snprintf(log_message, sizeof(log_message), "[WARN][CLEANUP] Failed to remove socket %d from cmd epoll: %s\n",
                    client_socket, strerror(errno));
            FILE_LOG(log_message);
        }
        // Close socket
        close(client_socket);
        // Remove mapping and session if we know the account_id
        if (fallback_account_id != 0 && fallback_account_id != (unsigned int)-1) {
            remove_account_socket_mapping(fallback_account_id);
            snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] Removing session for account_id %d (fallback)\n", fallback_account_id);
            FILE_LOG(log_message);
            remove_session(fallback_account_id);
        }
        snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] Fallback cleanup complete for socket %d\n", client_socket);
        FILE_LOG(log_message);
        return; // Done with fallback cleanup
    }
    
    // Mark as inactive while holding mutex to prevent race conditions
    c->active = 0;
    
    // Copy necessary data for logging and broadcasting
    char username_copy[MAX_USERNAME_LEN];
    char nickname_copy[32];
    unsigned int account_id = c->account_id;
    
    strncpy(username_copy, c->username, sizeof(username_copy) - 1);
    username_copy[sizeof(username_copy) - 1] = '\0';
    strncpy(nickname_copy, c->nickname, sizeof(nickname_copy) - 1);
    nickname_copy[sizeof(nickname_copy) - 1] = '\0';
    
    // Remove from hash table while still holding mutex
    HASH_DEL(clients_map, c);
    client_count--;
    pthread_mutex_unlock(&clients_mutex);

    snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] User '%s' (%s) left the chat (Total clients: %d)\n", 
           username_copy, nickname_copy, client_count);
    FILE_LOG(log_message);
    
    // Remove from socket tracking
    remove_socket_info(client_socket);
    
    // Remove from epoll with proper error handling
    int epoll_result = epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
    if (epoll_result < 0 && errno != ENOENT) {
        snprintf(log_message, sizeof(log_message), "[WARN][CLEANUP] Failed to remove socket %d from auth epoll: %s\n", 
                client_socket, strerror(errno));
        FILE_LOG(log_message);
    }
    
    epoll_result = epoll_ctl(cmd_thread_ctx.epoll_fd, EPOLL_CTL_DEL, client_socket, NULL);
    if (epoll_result < 0 && errno != ENOENT) {
        snprintf(log_message, sizeof(log_message), "[WARN][CLEANUP] Failed to remove socket %d from cmd epoll: %s\n", 
                client_socket, strerror(errno));
        FILE_LOG(log_message);
    }
    
    // Close socket outside of mutex
    close(client_socket);
    
    // Broadcast departure message
    char departure_msg[BUFFER_SIZE];
    snprintf(departure_msg, sizeof(departure_msg), 
             "%s has left the chat", nickname_copy);
    
    broadcast_message(departure_msg, client_socket, 1);
    
    // Remove account_id to socket mapping
    if (account_id != 0) {
        remove_account_socket_mapping(account_id);
    }
    
    // Remove session BEFORE freeing the client structure
    if (account_id != 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] Removing session for account_id %d\n", account_id);
        FILE_LOG(log_message);
        remove_session(account_id);
    }
    
    // Free the client structure AFTER removing session
    free(c);
    snprintf(log_message, sizeof(log_message), "[INFO][CLEANUP] Cleanup complete for socket %d\n", client_socket);
    FILE_LOG(log_message);
}

void update_socket_state(int socket, socket_state_t new_state) {
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_info_map_mutex);
    HASH_FIND_INT(socket_info_map, &socket, info);
    if (info) {
        printf("[SOCKET_STATE] Socket %d: %d -> %d\n", socket, info->state, new_state);
        info->state = new_state;
        info->last_activity = time(NULL);
    }
    pthread_mutex_unlock(&socket_info_map_mutex);
}

client_t* find_client_by_nickname(const char* nickname) {
    client_t *c, *tmp, *result = NULL;
    
    pthread_mutex_lock(&clients_mutex);
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active && strcmp(c->nickname, nickname) == 0) {
            result = c;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    return result;
}

void get_client_list(char* list_buffer, size_t buffer_size) {
    snprintf(list_buffer, buffer_size, "Connected users (%d): ", client_count);
    int first = 1;
    client_t *c, *tmp;
    pthread_mutex_lock(&clients_mutex);

    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            if (!first) {
                strncat(list_buffer, ", ", buffer_size - strlen(list_buffer) - 1);
            }
            strncat(list_buffer, c->nickname, buffer_size - strlen(list_buffer) - 1);
            first = 0;
        }
    }
    pthread_mutex_unlock(&clients_mutex);
    strncat(list_buffer, "\n", buffer_size - strlen(list_buffer) - 1);
}

// Move socket from auth thread to command thread
void promote_to_authenticated(int socket, unsigned int account_id) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Starting promotion for socket %d\n", account_id, socket);
    FILE_LOG(log_message);
    // Get accurate client count to avoid race conditions
    pthread_mutex_lock(&clients_mutex);
    int current_count = client_count;
    pthread_mutex_unlock(&clients_mutex);
    
    printf("Added authenticated client %d to chat\n", account_id);
    printf("total clients: %d\n", current_count+1);
    // Create client structure
    client_t *new_client = malloc(sizeof(client_t));
    if (!new_client) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE][ID:%d] Failed to allocate client structure\n", account_id);
        FILE_LOG(log_message);
        return;
    }
    
    // Initialize client
    memset(new_client, 0, sizeof(client_t));
    new_client->socket = socket;
    new_client->account_id = account_id;
    new_client->active = 1;
    new_client->mode = CLIENT_MODE_CHAT;
    strncpy(new_client->cwd, default_cwd, sizeof(new_client->cwd) - 1);
    new_client->cwd[sizeof(new_client->cwd) - 1] = '\0';
    
    // Get user info for the client
    user_t *user = find_user(account_id);
    if (user) {
        strncpy(new_client->username, user->username, MAX_USERNAME_LEN - 1);
        strncpy(new_client->nickname, user->username, sizeof(new_client->nickname) - 1);
        new_client->authLevel = user->authLevel; // Copy the user's authority level
    }
    
    // Add to clients map
    pthread_mutex_lock(&clients_mutex);
    HASH_ADD_INT(clients_map, socket, new_client);
    client_count++;
    pthread_mutex_unlock(&clients_mutex);
    
    // Remove from auth epoll (only if it was added there)
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Removing socket %d from auth epoll\n", account_id, socket);
    FILE_LOG(log_message);
    if (epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_DEL, socket, NULL) == -1) {
        // This is expected for auto-authenticated sockets that were never added to auth epoll
        snprintf(log_message, sizeof(log_message), "[DEBUG][PROMOTE][ID:%d] Socket %d was not in auth epoll (likely auto-authenticated)\n", account_id, socket);
        FILE_LOG(log_message);
    } else {
        snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Successfully removed socket %d from auth epoll\n", account_id, socket);
        FILE_LOG(log_message);
    }
    
    // Update socket state
    socket_info_t *info = NULL;
    pthread_mutex_lock(&socket_info_map_mutex);
    HASH_FIND_INT(socket_info_map, &socket, info);
    if (info) {
        info->state = SOCKET_STATE_AUTHENTICATED;
        info->account_id = account_id;
        info->last_activity = time(NULL);
        add_account_socket_mapping(account_id, socket);
        snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Updated socket %d state to AUTHENTICATED\n", account_id, socket);
        FILE_LOG(log_message);
    }
    pthread_mutex_unlock(&socket_info_map_mutex);
    
    // Add to command thread epoll
    struct epoll_event event;
    event.data.fd = socket;
    event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP | EPOLLERR;
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Adding socket %d to command thread epoll\n", account_id, socket);
    FILE_LOG(log_message);
    if (epoll_ctl(cmd_thread_ctx.epoll_fd, EPOLL_CTL_ADD, socket, &event) == -1) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE][ID:%d] Failed to add to command thread epoll\n", account_id);
        FILE_LOG(log_message);
        remove_client(socket);
        return;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Successfully added socket %d to command thread epoll\n", account_id, socket);
    FILE_LOG(log_message);
    
    // Validate socket is still valid after epoll addition
    if (fcntl(socket, F_GETFD) == -1) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE][ID:%d] Socket %d became invalid after epoll addition\n", account_id, socket);
        FILE_LOG(log_message);
        remove_client(socket);
        return;
    }
    
    char response[BUFFER_SIZE];
    snprintf(response, sizeof(response), "AUTH_SUCCESS You are now fully authenticated.\n");
    
    // Send with error checking
    ssize_t sent = send(socket, response, strlen(response), 0);
    if (sent < 0) {
        snprintf(log_message, sizeof(log_message), "[ERROR][PROMOTE][ID:%d] Failed to send AUTH_SUCCESS to socket %d: %s\n", 
                 account_id, socket, strerror(errno));
        FILE_LOG(log_message);
        remove_client(socket);
        return;
    } else if (sent != (ssize_t)strlen(response)) {
        snprintf(log_message, sizeof(log_message), "[WARN][PROMOTE][ID:%d] Partial send to socket %d: %zd of %zu bytes\n", 
                 account_id, socket, sent, strlen(response));
        FILE_LOG(log_message);
    }
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][PROMOTE][ID:%d] SENDING to socket %d: '%s'\n", account_id, socket, response);
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Socket %d is fully authenticated\n", account_id, socket);
    FILE_LOG(log_message);
    // Announce new user
    char announcement[BUFFER_SIZE];
    snprintf(announcement, sizeof(announcement), "%s has joined the chat", new_client->nickname);
    broadcast_message(announcement, socket, 0);
    snprintf(response, sizeof(response),
                 "Chat Commands:\n"
                 "  /nick <name> - Change your nickname\n"
                 "  /list - Show connected users\n"
                 "  /help - Show this help\n"
                 "  /file - Enter file mode\n"
                 "  /quit - Kill the overall program\n"
                 "Just type any message to chat with everyone!\n");
    send(socket, response, strlen(response), 0);
}

void handle_chat_mode(client_t *c, char *buffer, int client_socket){
    char broadcast_msg[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    // Handle nickname change
    if (strncmp(buffer, "/nick ", 6) == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Handling /nick command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        char new_nick[32];
        memset(new_nick, 0, sizeof(new_nick));
        strncpy(new_nick, buffer + 6, sizeof(new_nick) - 1);
        new_nick[sizeof(new_nick) - 1] = '\0';
        new_nick[strcspn(new_nick, "\r\n ")] = 0;

        if (strlen(new_nick) == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Invalid nickname. Usage: /nick <name>\n");
            ssize_t n_sent= send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            if(n_sent < 0){
                printf("Failed to send message to client %d\n", client_socket);
                if(errno == EPIPE){
                    printf("Client %d disconnected\n", client_socket);
                    remove_client(client_socket);
                }
                else{printf("Failed to send message to client %d\n", client_socket);}
            }
            return;
        }
        
        if (find_client_by_nickname(new_nick)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Nickname '%s' is already taken. Choose a different one.\n", new_nick);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            return;
        }
        
        // Update nickname with proper synchronization
        client_t *client = NULL;
        HASH_FIND_INT(clients_map, &client_socket, client);
        if (client && client->active) {
            char old_nick[32];
            strncpy(old_nick, client->nickname, sizeof(old_nick) - 1);
            old_nick[sizeof(old_nick) - 1] = '\0';
            
            strncpy(client->nickname, new_nick, sizeof(client->nickname) - 1);
            client->nickname[sizeof(client->nickname) - 1] = '\0';
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Nickname changed to '%s'\n", new_nick);
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "%s is now known as %s", old_nick, new_nick);
            broadcast_message(broadcast_msg, client_socket, 0);
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Nickname changed to '%s' for socket %d\n", c->account_id, new_nick, client_socket);
            FILE_LOG(log_message);
        } 
        return;
    }

    // Handle list command
    if (strcmp(buffer, "/list") == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Handling /list command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        get_client_list(broadcast_msg, sizeof(broadcast_msg));
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Handle help command
    if (strcmp(buffer, "/help") == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Handling /help command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        snprintf(broadcast_msg, sizeof(broadcast_msg),
                 "Chat Commands:\n"
                 "  /nick <name> - Change your nickname\n"
                 "  /list - Show connected users\n"
                 "  /help - Show this help\n"
                 "  /file - Enter file mode\n"
                 "  /quit - Kill the overall program\n"
                 "Just type any message to chat with everyone!\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Handle file commands
    if (strncmp(buffer, "/file", 5) == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Handling /file command from socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        
        pthread_mutex_lock(&clients_mutex);
        // Use the client pointer that was already passed to this function
        if (c && c->active) {
            c->mode = CLIENT_MODE_FILE;
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Client %d mode changed to FILE\n", c->account_id, client_socket);
            FILE_LOG(log_message);
        } else {
            snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD][ID:%d] Client not found or inactive for socket %d\n", c->account_id, client_socket);
            FILE_LOG(log_message);
        }
        pthread_mutex_unlock(&clients_mutex);
        
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] File mode activated for socket %d\n", c->account_id, client_socket);
        FILE_LOG(log_message);
        snprintf(broadcast_msg, sizeof(broadcast_msg), "File mode activated\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    // Handle unknown commands
    if (buffer[0] == '/') {
        snprintf(broadcast_msg, sizeof(broadcast_msg), 
                 "Unknown command. Type /help for available commands.\n");
        send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
        return;
    }
    
    // Regular chat message - broadcast to everyone
    if (strlen(buffer) > 0) {
        decrypt_inplace_if_needed(client_socket, buffer, sizeof(buffer));
        snprintf(broadcast_msg, sizeof(broadcast_msg), 
                 "%s: %s", c->nickname, buffer);
        broadcast_message(broadcast_msg, client_socket, 0);
        
        // Log the message
        snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] CHAT [%s] %s: %s\n", c->account_id, c->username, c->nickname, buffer);
        FILE_LOG(log_message);
        return;
    }

}

void* auth_thread_func(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    int max_events = get_max_events();
    struct epoll_event events[max_events];
    char buffer[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    FILE_LOG("[INFO][AUTH_THREAD] Authentication thread started\n");
    
    while (ctx->running) {
        // Check running flag before each epoll_wait
        if (!ctx->running) {
            snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_THREAD] Running flag is 0, exiting main loop\n");
            FILE_LOG(log_message);
            break;
        }
        
        int nfds = epoll_wait(ctx->epoll_fd, events, max_events, 100);
        if (nfds == -1) {
            if (errno == EINTR) {
                snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_THREAD] epoll_wait interrupted by signal (EINTR), checking running flag\n");
                FILE_LOG(log_message);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD] epoll_wait in auth thread: %s\n", strerror(errno));
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds > 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] epoll_wait returned %d events\n",  nfds);
            FILE_LOG(log_message);
        }
        
        // Debug: dump socket states every few seconds when no events
        static time_t last_dump = 0;
        if (nfds == 0) {
            time_t now = time(NULL);
            if (now - last_dump > 5) {
                //dump_socket_states();
                last_dump = now;
            }
        }
        
        for (int i = 0; i < nfds; i++) {
            int client_socket = events[i].data.fd;
            socket_info_t *info = get_socket_info(client_socket);
            if (!info) continue;
    
            // NEW: handle hangup/error events up-front
            uint32_t ev = events[i].events;
            if (ev & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                char log_message[BUFFER_SIZE];
                struct sockaddr_in peer; socklen_t plen = sizeof(peer);
                char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
                if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
                    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
                    port = ntohs(peer.sin_port);
                }
                int soerr = 0; socklen_t slen = sizeof(soerr);
                getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                snprintf(log_message, sizeof(log_message),
                    "[ERROR][AUTH_THREAD][ID:%d] Socket %d event(s):%s%s%s peer=%s:%d SO_ERROR=%d:%s\n",
                    info->account_id, client_socket,
                    (ev & EPOLLRDHUP) ? " RDHUP" : "",
                    (ev & EPOLLHUP) ? " HUP" : "",
                    (ev & EPOLLERR) ? " ERR" : "",
                    ip, port, soerr, strerror(soerr));
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                remove_client(client_socket);
                continue;
            }
            
            ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_read <= 0) {
                if (bytes_read == 0) {
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Socket %d closed by peer (orderly shutdown)\n", info->account_id, client_socket);
                } else {
                    struct sockaddr_in peer; socklen_t plen = sizeof(peer);
                    char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
                    if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
                        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip)); port = ntohs(peer.sin_port);
                    }
                    int soerr = 0; socklen_t slen = sizeof(soerr);
                    getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                    snprintf(log_message, sizeof(log_message),
                    "[ERROR][AUTH_THREAD][ID:%d] Socket %d recv error (errno=%d:%s, SO_ERROR=%d:%s, peer=%s:%d)\n",
                    info->account_id, client_socket, errno, strerror(errno), soerr, strerror(soerr), ip, port);                }
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                remove_client(client_socket);
                continue;
            }
            
            buffer[bytes_read] = '\0';
            buffer[strcspn(buffer, "\r\n")] = 0;
            
            // If this socket is secure and message starts with ENC, decrypt first
            decrypt_inplace_if_needed(client_socket, buffer, sizeof(buffer));
            
            // ECDH client pub handling (only allowed after RSA)
            if (strncmp(buffer, "ECDH_CLIENT_PUB", 15) == 0) {
                printf("%s\n", buffer);
                if ((get_auth_status(info->account_id) & AUTH_RSA)) {
                    char* hex = buffer + 16;
                    // Trim trailing newline/CR/whitespace from the hex payload
                    char* end = hex + strlen(hex);
                    while (end > hex && (end[-1] == '\n' || end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t')) {
                        end--;
                    }
                    *end = '\0';
                    char resp_log[BUFFER_SIZE];
                    if (handle_ecdh_client_pub(client_socket, info->account_id, hex)) {
                        snprintf(resp_log, sizeof(resp_log), "[INFO][AUTH_THREAD][ID:%d] ECDH key established\n", info->account_id);
                    } else {
                        snprintf(resp_log, sizeof(resp_log), "[ERROR][AUTH_THREAD][ID:%d] ECDH key establishment failed\n", info->account_id);
                    }
                    FILE_LOG(resp_log);
                }
                continue;
            }

            // Process authentication messages
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Socket %d: received %zd bytes, state=%d, account_id=%d\n", 
                   info->account_id, client_socket, bytes_read, info->state, info->account_id);
            FILE_LOG(log_message);
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Socket %d: raw data: '%s'\n", 
                   info->account_id, client_socket, buffer);
            FILE_LOG(log_message);
            char response[BUFFER_SIZE];
            
            // Check for lockout expiration and send unlock message if needed
            if (info->account_id > 0 && check_and_send_unlock_message(info->account_id, response, sizeof(response))) {
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Sending unlock message to socket %d\n", info->account_id, client_socket);
                FILE_LOG(log_message);
                send(client_socket, response, strlen(response), 0);
                
                continue; // Skip further processing
            }
            
            // Skip processing if this is a new connection (shouldn't happen anymore, but safety check)
            if (info->state == SOCKET_STATE_NEW) {
                snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD][ID:%d] WARNING: Socket %d in NEW state in epoll - should not occur\n", info->account_id, client_socket);
                FILE_LOG(log_message);
                continue;
            }
            
            // We need to determine account_id for process_auth_message
            // For initial auth, we might not have it yet, so we'll handle this step by step
            unsigned int account_id = info->account_id;
            
            // If we don't have account_id yet, try to extract from login command
            if (account_id <= 0 && strncmp(buffer, "/login", 6) == 0) {
                char username[MAX_USERNAME_LEN];
                if (sscanf(buffer, "/login %31s", username) == 1) {
                    username_t *uname_entry = find_username(username);
                    if (uname_entry) {
                        account_id = uname_entry->account_id;
                        // Update socket info with account_id
                        if (info) {
                            info->account_id = account_id;
                        }
                        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Set account_id %d for socket %d\n", info->account_id, account_id, client_socket);
                        FILE_LOG(log_message);
                    }
                }
            }
            
                    // Enhanced logging for authentication attempts
        if (account_id > 0) {
            username_t *uname_entry = find_username_by_account_id(account_id);
            if (uname_entry) {
                // Enhanced logging will be handled automatically by FILE_LOG if enabled
                decrypt_inplace_if_needed(client_socket, buffer, sizeof(buffer));
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Authentication attempt - Socket: %d, Data: %s\n", 
                         account_id, client_socket, buffer);
                FILE_LOG(log_message);
            }
        }
            
            auth_result_t process_result;
            if (account_id > 0) {
                // Check for lockout before processing any auth attempt
                if (check_and_handle_lockout(account_id, client_socket)) {
                    continue; // Skip processing if locked
                }
                if(strcmp(buffer, "/time") == 0){
                    check_and_handle_lockout(account_id, client_socket);
                    continue; 
                }
                process_result = process_auth_message(buffer, account_id, response, sizeof(response));
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] process_auth_message returned: success=%d, authenticated=%d\n", 
                        info->account_id, process_result.success, process_result.authenticated);
                FILE_LOG(log_message);
                
                // Load the response from process_result into the response buffer
                snprintf(response, sizeof(response), "%s", process_result.response);
            } 
            else {
                snprintf(response, sizeof(response), "Please use /login <username> <password> to authenticate\n");
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD-ID:NA] No account_id available for socket %d, sending login prompt\n", client_socket);
                FILE_LOG(log_message);
            }
            
            if (process_result.success == 1) { // Message processed successfully
                // Check if user is actually fully authenticated
                auth_flags_t auth_status = get_auth_status(account_id);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Socket %d: auth_status=%d\n", 
                       info->account_id, client_socket, auth_status);
                FILE_LOG(log_message);
                
                if(auth_status & AUTH_STATUS_LOCKED){
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Account %d is locked, sending lockout message\n", info->account_id, account_id);
                    FILE_LOG(log_message);
                    snprintf(response, sizeof(response), "%s Account is locked for %d more seconds due to too many failed attempts.\n", AUTH_LOCKED, get_remaining_lockout_time(account_id));
                    send(client_socket, response, strlen(response), 0);
                    continue;
                }

                // After RSA succeeds, force a fresh ECDH handshake for this socket
                if ((auth_status & AUTH_RSA)) {
                    session_t *sess = find_session(account_id);
                    if (sess) {
                        reset_session_ecdh(account_id);
                        send_ecdh_server_pub(client_socket, account_id);
                        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] ECDH server pub sent to socket %d (reset)\n", info->account_id, client_socket);
                        FILE_LOG(log_message);
                    }
                }

                if (auth_status == AUTH_FULLY_AUTHENTICATED) {
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Authentication COMPLETE for socket %d, promoting to chat...\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                    
                    // Enhanced logging for successful authentication
                    username_t *uname_entry = find_username_by_account_id(account_id);
                    if (uname_entry) {
                        // Enhanced logging will be handled automatically by FILE_LOG if enabled
                        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Authentication COMPLETE - Socket: %d, Account: %d\n", 
                                 account_id, client_socket, account_id);
                        FILE_LOG(log_message);
                    }
                    
                    promote_to_authenticated(client_socket, account_id);
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Promotion complete for socket %d\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                } 
                else {
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Authentication INCOMPLETE for socket %d, sending response\n", info->account_id, client_socket);
                    FILE_LOG(log_message);
                    snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_THREAD][ID:%d] SENDING to socket %d: '%.100s'\n", info->account_id, client_socket, response);
                    FILE_LOG(log_message);
                    
                    // Sanity check: ensure socket matches the expected account_id
                    socket_info_t *verify_info = get_socket_info(client_socket);
                    if (!verify_info || verify_info->account_id != account_id) {
                        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] SOCKET MISMATCH! client_socket=%d, expected_account_id=%d, actual_account_id=%d\n", 
                                account_id, client_socket, account_id, verify_info ? verify_info->account_id : -1);
                        FILE_LOG(log_message);
                    }
                    
                    send(client_socket, response, strlen(response), 0);
                }
            } 
            else {
                snprintf(log_message, 
                    sizeof(log_message), 
                    "[ERROR][AUTH_THREAD:%d] Message processing failed, sending response to socket %d: '%s'\n", 
                    account_id, client_socket, response);
                FILE_LOG(log_message);
                snprintf(log_message, sizeof(log_message), "[DEBUG][AUTH_THREAD][ID:%d] SENDING to socket %d: '%.100s'\n", account_id, client_socket, response);
                FILE_LOG(log_message);
                
                // Sanity check: ensure socket matches the expected account_id
                socket_info_t *verify_info = get_socket_info(client_socket);
                if (!verify_info || verify_info->account_id != account_id) {
                    snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] SOCKET MISMATCH! client_socket=%d, expected_account_id=%d, actual_account_id=%d\n", 
                            account_id, client_socket, account_id, verify_info ? verify_info->account_id : -1);
                    FILE_LOG(log_message);
                }
                
                send(client_socket, response, strlen(response), 0);
            }
        }
    }
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Authentication thread exiting\n");
    FILE_LOG(log_message);
    return NULL;
}

void* cmd_thread_func(void *arg) {
    thread_context_t *ctx = (thread_context_t *)arg;
    int max_events = get_max_events();
    struct epoll_event events[max_events];
    char buffer[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];

    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] Command handler thread started\n");
    FILE_LOG(log_message);
    
    while (ctx->running) {
        // Check running flag before each epoll_wait
        if (!ctx->running) {
            snprintf(log_message, sizeof(log_message), "[DEBUG][CMD_THREAD] Running flag is 0, exiting main loop\n");
            FILE_LOG(log_message);
            break;
        }
        
        int nfds = epoll_wait(ctx->epoll_fd, events, max_events, 100);
        if (nfds == -1) {
            if (errno == EINTR) {
                snprintf(log_message, sizeof(log_message), "[DEBUG][CMD_THREAD] epoll_wait interrupted by signal (EINTR), checking running flag\n");
                FILE_LOG(log_message);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD] epoll_wait in cmd thread: %s\n", strerror(errno));
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds > 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] epoll_wait returned %d events\n", nfds);
            FILE_LOG(log_message);
        }
        
        for (int i = 0; i < nfds; i++) {
            int client_socket = events[i].data.fd;
            socket_info_t *info = get_socket_info(client_socket);
    
            if (!info || info->state != SOCKET_STATE_AUTHENTICATED) {
                continue;
            }
    
            // NEW: handle hangup/error events up-front
            uint32_t ev = events[i].events;
            if (ev & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                char log_message[BUFFER_SIZE];
                struct sockaddr_in peer; socklen_t plen = sizeof(peer);
                char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
                if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
                    inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip));
                    port = ntohs(peer.sin_port);
                }
                int soerr = 0; socklen_t slen = sizeof(soerr);
                getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                snprintf(log_message, sizeof(log_message),
                    "[ERROR][CMD_THREAD][ID:%d] Socket %d event(s):%s%s%s peer=%s:%d SO_ERROR=%d:%s\n",
                    info->account_id, client_socket,
                    (ev & EPOLLRDHUP) ? " RDHUP" : "",
                    (ev & EPOLLHUP) ? " HUP" : "",
                    (ev & EPOLLERR) ? " ERR" : "",
                    ip, port, soerr, strerror(soerr));
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                remove_client(client_socket);
                continue;
            }
            
            ssize_t bytes_read = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
            if (bytes_read <= 0) {
                if (bytes_read == 0) {
                    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Socket %d closed by peer (orderly shutdown)\n", info->account_id, client_socket);
                } else {
                    struct sockaddr_in peer; socklen_t plen = sizeof(peer);
                    char ip[INET_ADDRSTRLEN] = "UNKNOWN"; int port = -1;
                    if (getpeername(client_socket, (struct sockaddr*)&peer, &plen) == 0) {
                        inet_ntop(AF_INET, &peer.sin_addr, ip, sizeof(ip)); port = ntohs(peer.sin_port);
                    }
                    int soerr = 0; socklen_t slen = sizeof(soerr);
                    getsockopt(client_socket, SOL_SOCKET, SO_ERROR, &soerr, &slen);
                    snprintf(log_message, sizeof(log_message),
                    "[ERROR][CMD_THREAD][ID:%d] Socket %d recv error (errno=%d:%s, SO_ERROR=%d:%s, peer=%s:%d)\n",
                    info->account_id, client_socket, errno, strerror(errno), soerr, strerror(soerr), ip, port);                }
                FILE_LOG(log_message);
                remove_socket_info(client_socket);
                remove_client(client_socket);
                continue;
            }
            
            buffer[bytes_read] = '\0';
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Socket %d: received %zd bytes, state=%d\n", 
                   info->account_id, client_socket, bytes_read, info->state);
            FILE_LOG(log_message);
            snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD][ID:%d] Socket %d: raw data: '%s'\n", 
                   info->account_id, client_socket, buffer);
            FILE_LOG(log_message);
            
            // If this socket is secure and message starts with ENC, decrypt first
            decrypt_inplace_if_needed(client_socket, buffer, sizeof(buffer));
            snprintf(log_message, sizeof(log_message), "[INFO]Decrypted message: %s\n", buffer);
            FILE_LOG(log_message);
            
            buffer[strcspn(buffer, "\r\n")] = 0;
            
            // Handle commands and messages using client mode
            client_t *client = find_client_by_socket(client_socket);
            if (client) {
                
                // Skip empty messages
                if (strlen(buffer) == 0) {
                    continue;
                }
                
                // Handle quit command (universal quit command)
                if (strcmp(buffer, "/quit") == 0) {
                    char response[BUFFER_SIZE];
                    snprintf(response, sizeof(response), "Goodbye! You have left the chat.\n");
                    send(client_socket, response, strlen(response), 0);
                    remove_client(client_socket);
                    continue;
                }
                
                // Dispatch based on client mode
                if (client->mode == CLIENT_MODE_CHAT) {
                    handle_chat_mode(client, buffer, client_socket);
                } else if (client->mode == CLIENT_MODE_FILE) {
                    handle_file_mode(client, buffer, client_socket);
                } else {
                    snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD] Unknown client mode %d for socket %d\n", client->mode, client_socket);
                    FILE_LOG(log_message);
                }
            } else {
                snprintf(log_message, sizeof(log_message), "[ERROR][CMD_THREAD] No client found for socket %d - this shouldn't happen for authenticated users\n", client_socket);
                FILE_LOG(log_message);
                // Try to find the client in the hash table for debugging
                client_t *c, *tmp;
                HASH_ITER(hh, clients_map, c, tmp) {
                    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] Client in map - socket=%d, active=%d, username=%s\n", 
                           c->socket, c->active, c->username);
                    FILE_LOG(log_message);
                }
            }
        }
    }
    
    snprintf(log_message, sizeof(log_message), "[INFO][CMD_THREAD] Command handler thread exiting\n");
    FILE_LOG(log_message);
    return NULL;
}

void signal_handler(int sig) {
    (void)sig; // Suppress unused parameter warning
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Signal handler called with signal %d\n", sig);
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server shutdown requested...\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Setting shutdown_flag=1, server_running=0\n");
    FILE_LOG(log_message);
    shutdown_flag = 1;
    server_running = 0;
    
    // Best-effort wake any epoll_wait via self-pipe
    snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Attempting to wake epoll via shutdown pipe\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] shutdown_pipe[1]=%d, shutdown_pipe[0]=%d\n", shutdown_pipe[1], shutdown_pipe[0]);
    FILE_LOG(log_message);
    if (shutdown_pipe[1] != -1) {
        // Write multiple bytes to ensure the pipe is definitely readable
        const char bytes[] = "xxx";
        ssize_t written = write(shutdown_pipe[1], bytes, sizeof(bytes));
        snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Wrote %zd bytes to shutdown pipe (fd=%d)\n", written, shutdown_pipe[1]);
        FILE_LOG(log_message);
        
        if (written == -1) {
            snprintf(log_message, sizeof(log_message), "[ERROR][SIGNAL] Failed to write to shutdown pipe: %s (errno=%d)\n", strerror(errno), errno);
            FILE_LOG(log_message);
        }
        
        // Force a flush to ensure the write goes through
        fsync(shutdown_pipe[1]);
        snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Flushed shutdown pipe\n");
        FILE_LOG(log_message);
    } else {
        snprintf(log_message, sizeof(log_message), "[WARN][SIGNAL] Shutdown pipe write end is closed!\n");
        FILE_LOG(log_message);
    }
    snprintf(log_message, sizeof(log_message), "[DEBUG][SIGNAL] Signal handler completed\n");
    FILE_LOG(log_message);
}

void add_authenticated_client(client_t *new_client) {
    char log_message[BUFFER_SIZE];
    printf("[ADD_CLIENT] Adding authenticated client for user '%s' (socket %d)\n", 
           new_client->username, new_client->socket);
    
    pthread_mutex_lock(&clients_mutex);
    
    // Check if client already exists by socket (prevent duplicates)
    client_t *existing = NULL;
    HASH_FIND_INT(clients_map, &new_client->socket, existing);
    if (existing) {
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD][ID:%d] Warning: Client socket %d already exists in map\n", new_client->account_id, new_client->socket);
        FILE_LOG(log_message);
        pthread_mutex_unlock(&clients_mutex);
        return;
    }
    
    // Check for existing client with same username and remove it
    client_t *duplicate = NULL, *tmp = NULL;
    HASH_ITER(hh, clients_map, duplicate, tmp) {
        if (duplicate->active && strcmp(duplicate->username, new_client->username) == 0) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Removing existing client for user '%s' (socket %d)\n", 
                   duplicate->account_id, duplicate->username, duplicate->socket);
            FILE_LOG(log_message);
            HASH_DEL(clients_map, duplicate);
            client_count--;
            close(duplicate->socket);
            free(duplicate);
            break;
        }
    }
    
    HASH_ADD_INT(clients_map, socket, new_client);
    client_count++;
    pthread_mutex_unlock(&clients_mutex);
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Successfully added client for user '%s' (socket %d). Total clients: %d\n", 
           new_client->account_id, new_client->username, new_client->socket, client_count);
    FILE_LOG(log_message);
    
    
}

void* handle_authenticated_client(void* arg) {
    int client_socket = *(int*)arg;
    free(arg); // Free the allocated memory for the socket
    
    char buffer[BUFFER_SIZE];
    client_t *c = find_client_by_socket(client_socket);
    char broadcast_msg[BUFFER_SIZE];
    
    if (!c) {
        printf("Error: No client found for socket %d in authenticated handler\n", client_socket);
        close(client_socket);
        return NULL;
    }
    
    // Send welcome message and instructions
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "Welcome to %s!\n"
             "Commands:\n"
             "  /nick <name> - Change your nickname\n"
             "  /list - Show connected users\n"
             "  /help - Show this help\n"
             "  /quit - Leave the chat\n"
             "  /file - Enter file mode\n"
             "Type your messages to chat with everyone!\n\n", 
             PROGRAM_NAME);
    send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
    
    // Enhanced logging for authenticated client
    // Enhanced logging will be handled automatically by FILE_LOG if enabled
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][CHAT][ID:%d] Client authenticated and joined chat\n", c->account_id);
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][CHAT][ID:%d] Client socket: %d, Mode: %d\n", c->account_id, client_socket, c->account_id);
    FILE_LOG(log_message);
    
    // Announce new user to everyone
    snprintf(broadcast_msg, sizeof(broadcast_msg), 
             "%s joined the chat", c->nickname);
    broadcast_message(broadcast_msg, client_socket, 0);
    
    // Main message handling loop
    while (server_running) {
        // Check shutdown flag before each iteration
        if (!server_running) {
            printf("Shutdown requested, exiting client handler\n");
            break;
        }
        
        int bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, MSG_DONTWAIT);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                client_t *c = find_client_by_socket(client_socket);
                printf("Client %s disconnected\n", c ? c->nickname : "(unknown)");
                break;
            } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // No data available, check shutdown flag
                if (!server_running) {
                    printf("Shutdown requested, exiting client handler\n");
                    break;
                }
                // Small delay before retry
                struct timespec delay = {0, 10000000}; // 10ms
                nanosleep(&delay, NULL);
                continue;
            } else {
                // Real error
                client_t *c = find_client_by_socket(client_socket);
                printf("Client %s recv error\n", c ? c->nickname : "(unknown)");
                break;
            }
        }
        
        buffer[bytes_received] = '\0';
        buffer[strcspn(buffer, "\r\n")] = 0; // Remove newlines
        
        // Skip empty messages
        if (strlen(buffer) == 0) {
            continue;
        }
        
        // Enhanced logging for message received
        // Enhanced logging will be handled automatically by FILE_LOG if enabled
        snprintf(log_message, sizeof(log_message), "[INFO][CHAT][ID:%d] Message received: %s\n", c->account_id, buffer);
        FILE_LOG(log_message);
        
        // Re-check if session is still valid
        c = find_client_by_socket(client_socket);
        if (!c || !c->active) {
            printf("Client %d not valid or inactive\n", client_socket);
            break;
        }
        
        if (!is_authenticated(c->account_id)) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                     "Session expired. Please reconnect and authenticate again.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Handle quit command (universal quit command)
        if (strcmp(buffer, "/quit") == 0) {
            snprintf(broadcast_msg, sizeof(broadcast_msg), "Goodbye! You have left the chat.\n");
            send(client_socket, broadcast_msg, strlen(broadcast_msg), 0);
            break;
        }
        
        // Dispatch based on mode - check client is still valid
        if (c->mode == CLIENT_MODE_CHAT) {
            handle_chat_mode(c, buffer, client_socket);
        } else if (c->mode == CLIENT_MODE_FILE) {
            handle_file_mode(c, buffer, client_socket);
        }
    }
    
    // Clean up session and remove client
    
    remove_client(client_socket);
    
    return NULL;
}

X509* extract_client_cert(int client_socket) {
    uint32_t net_cert_len;
    char log_message[BUFFER_SIZE];
    socket_info_t *socket_info = get_socket_info(client_socket);
    
    // If socket_info is missing, this indicates an initialization failure
    // Add it on the spot to prevent crashes
    if (!socket_info) {
        snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Socket info missing for socket %d, creating it now\n", client_socket);
        FILE_LOG(log_message);
        add_socket_info(client_socket);
        socket_info = get_socket_info(client_socket);
        if (!socket_info) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Failed to create socket info for socket %d\n", client_socket);
            FILE_LOG(log_message);
            return NULL;
        }
    }
    
    // Read certificate length with retry logic
    unsigned long total_read = 0;
    int retry_count = 0;
    const int max_retries = 50; // 5 seconds total with 100ms delays
    
    while (total_read < sizeof(net_cert_len)) {
        int recvd = recv(client_socket, ((char*)&net_cert_len) + total_read, 
                        sizeof(net_cert_len) - total_read, MSG_DONTWAIT);
        if (recvd <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Check shutdown flag during certificate extraction
                if (!server_running) {
                    printf("[SHUTDOWN] Aborting certificate length extraction due to shutdown\n");
                    return NULL;
                }
                
                retry_count++;
                if (retry_count > max_retries) {
                    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD][ID:%d] Certificate length extraction timeout after %d retries for socket %d\n", 
                             socket_info->account_id, max_retries, client_socket);
                    FILE_LOG(log_message);
                    return NULL;
                }
                
                struct timespec delay = {0, 100000000}; // 100ms
                nanosleep(&delay, NULL);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Failed to receive certificate length from client socket %d.\n", socket_info->account_id, client_socket);
            FILE_LOG(log_message);
            return NULL;
        }
        total_read += recvd;
        retry_count = 0; // Reset retry count on successful read
    }
    
    uint32_t cert_len = ntohl(net_cert_len);
    if (cert_len == 0 || cert_len > 8192) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Invalid certificate length received: %u from socket %d\n", socket_info->account_id, cert_len, client_socket);
        FILE_LOG(log_message);
        
                    // Enhanced logging for certificate extraction issues
            if (socket_info->account_id > 0) {
                username_t *uname_entry = find_username_by_account_id(socket_info->account_id);
                if (uname_entry) {
                    // Enhanced logging will be handled automatically by FILE_LOG if enabled
                    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD][ID:%d] Certificate extraction FAILED - Invalid length: %u, Socket: %d\n",
                             socket_info->account_id, cert_len, client_socket);
                    FILE_LOG(log_message);
                }
            }
        
        return NULL;
    }
    
    char* cert_buf = malloc(cert_len + 1);
    if (!cert_buf) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Memory allocation failed for certificate buffer from socket %d.\n", socket_info->account_id, client_socket);
        FILE_LOG(log_message);
        return NULL;
    }
    
    // Read certificate data with retry logic
    total_read = 0;
    retry_count = 0; // Reuse retry counter for certificate data
    
    while (total_read < (unsigned long)cert_len) {
        int recvd = recv(client_socket, cert_buf + total_read, 
                        cert_len - total_read, MSG_DONTWAIT);
        if (recvd <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Check shutdown flag during certificate extraction
                if (!server_running) {
                    printf("[SHUTDOWN] Aborting certificate extraction due to shutdown\n");
                    free(cert_buf);
                    return NULL;
                }
                
                retry_count++;
                if (retry_count > max_retries) {
                    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD][ID:%d] Certificate data extraction timeout after %d retries for socket %d\n", 
                             socket_info->account_id, max_retries, client_socket);
                    FILE_LOG(log_message);
                    free(cert_buf);
                    return NULL;
                }
                
                if(errno == EAGAIN){
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] EAGAIN received for socket %d (retry %d/%d)\n", client_socket, retry_count, max_retries);
                    FILE_LOG(log_message);
                }
                else if(errno == EWOULDBLOCK){
                    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] EWOULDBLOCK received for socket %d (retry %d/%d)\n", client_socket, retry_count, max_retries);
                    FILE_LOG(log_message);
                }

                struct timespec delay = {0, 100000000}; // 100ms
                nanosleep(&delay, NULL);
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Failed to receive certificate data from client socket %d.\n", socket_info->account_id, client_socket);
            FILE_LOG(log_message);
            free(cert_buf);
            return NULL;
        }
        total_read += recvd;
        retry_count = 0; // Reset retry count on successful read
    }
    
    cert_buf[cert_len] = '\0';
    
    // Check if this is a placeholder certificate (when RSA is disabled)
    if (strcmp(cert_buf, "NO_RSA_CERTIFICATE") == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Client sent placeholder certificate (RSA disabled), skipping certificate parsing for socket %d.\n", socket_info->account_id, client_socket);
        FILE_LOG(log_message);
        free(cert_buf);
        return NULL; // This will be handled specially in setup_initial_connection
    }
    
    BIO* cert_bio = BIO_new_mem_buf(cert_buf, cert_len);
    X509* client_cert = PEM_read_bio_X509(cert_bio, NULL, 0, NULL);
    BIO_free(cert_bio);
    free(cert_buf);
    
    if (!client_cert) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Failed to parse client certificate from socket %d.\n", socket_info->account_id, client_socket);
        FILE_LOG(log_message);
        return NULL;
    }
    return client_cert;
}

int setup_initial_connection(int client_socket) {
    char log_message[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    int peer_result = getpeername(client_socket, (struct sockaddr*)&client_addr, &addr_len);
    if (peer_result == 0) {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Setting up initial connection for %s:%d\n", 
            inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    } else {
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Setting up initial connection for UNKNOWN_PEER (getpeername failed)\n");
    }
    FILE_LOG(log_message);

    // Decide whether to perform RSA certificate extraction
    extern int is_rsa_disabled(void);
    int rsa_disabled = is_rsa_disabled();

    X509* client_cert = NULL;
    EVP_PKEY* client_pubkey = NULL;

    if (!rsa_disabled) {
        // Temporarily set socket to blocking
        int flags = fcntl(client_socket, F_GETFL, 0);
        fcntl(client_socket, F_SETFL, flags & ~O_NONBLOCK);

        // Extract certificate
        client_cert = extract_client_cert(client_socket);

        // Restore non-blocking mode after certificate extraction
        fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);

        // Validate socket_info consistency after certificate extraction
        socket_info_t *cert_info = get_socket_info(client_socket);
        if (cert_info && cert_info->account_id > 0) {
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Socket %d: account_id already set to %d before username extraction\n", 
                     client_socket, cert_info->account_id);
            FILE_LOG(log_message);
        }

        if (!client_cert) {
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Certificate extraction failed for socket %d - client may have disconnected\n", client_socket);
            FILE_LOG(log_message);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }

        // We have a valid certificate, extract the public key
        client_pubkey = X509_get_pubkey(client_cert);
        if (!client_pubkey) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Failed to extract public key from client certificate.\n");
            FILE_LOG(log_message);
            X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        
        // Print subject CN 
        X509_NAME* subj = X509_get_subject_name(client_cert);
        char cn[256];
        X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn));
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][SOCKET-%d] Received client certificate. Subject CN: %s\n", client_socket, cn);
        FILE_LOG(log_message);
    } else {
        // RSA is disabled: skip certificate extraction entirely
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] No certificate required (RSA disabled). Proceeding without RSA authentication.\n");
        FILE_LOG(log_message);
        // Ensure any prior incorrect warning only triggers for real account ids
        socket_info_t *cert_info = get_socket_info(client_socket);
        if (cert_info && cert_info->account_id > 0) {
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Socket %d: account_id already set to %d before username extraction\n", 
                     client_socket, cert_info->account_id);
            FILE_LOG(log_message);
        }
    }

    // Receive username with retry logic
    char username_buffer[BUFFER_SIZE];
    int name_bytes = 0;
    int username_retry_count = 0;
    const int max_username_retries = 30; // 3 seconds total with 100ms delays
    
    // Try to read username with retries
    while (name_bytes <= 0 && username_retry_count < max_username_retries) {
        name_bytes = recv(client_socket, username_buffer, BUFFER_SIZE - 1, MSG_DONTWAIT);
        
        if (name_bytes <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                username_retry_count++;
                if (username_retry_count >= max_username_retries) {
                    snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD] Username extraction timeout after %d retries for socket %d\n", 
                             max_username_retries, client_socket);
                    FILE_LOG(log_message);
                    EVP_PKEY_free(client_pubkey);
                    X509_free(client_cert);
                    remove_socket_info(client_socket);
                    close(client_socket);
                    return -1;
                }
                
                struct timespec delay = {0, 100000000}; // 100ms
                nanosleep(&delay, NULL);
                continue;
            } else {
                // Real error, not just no data
                snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Socket %d: client disconnected before sending username (errno=%d: %s)\n", 
                         client_socket, errno, strerror(errno));
                FILE_LOG(log_message);
                EVP_PKEY_free(client_pubkey);
                X509_free(client_cert);
                remove_socket_info(client_socket);
                close(client_socket);
                return -1;
            }
        }
    }
    
    char username[MAX_USERNAME_LEN] = "";
    unsigned int account_id = 0;
    
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Socket %d: received %d bytes for username after %d retries\n", 
             client_socket, name_bytes, username_retry_count);
    FILE_LOG(log_message);
    
    // Final check that we actually got valid data
    if (name_bytes <= 0) {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Socket %d: failed to receive username after all retries\n", client_socket);
        FILE_LOG(log_message);
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    
    username_buffer[name_bytes] = '\0';
    username_buffer[strcspn(username_buffer, "\r\n")] = 0;
    snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Socket %d: username data: '%s'\n", client_socket, username_buffer);
    FILE_LOG(log_message);

    if (strncmp(username_buffer, "USERNAME:", 9) == 0) {
        strncpy(username, username_buffer + 9, MAX_USERNAME_LEN - 1);
        username[MAX_USERNAME_LEN - 1] = '\0';
        
        username_t *uname_entry = find_username(username);
        if (!uname_entry) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Invalid username received: %s\n", username);
            FILE_LOG(log_message);
            snprintf(response, sizeof(response), "ERROR: Invalid username\n");
            send(client_socket, response, strlen(response), 0);
            
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        
        account_id = uname_entry->account_id;
        
        // Update socket_info with the account_id
        socket_info_t *current_socket_info = get_socket_info(client_socket);
        if (current_socket_info) {
            current_socket_info->account_id = account_id;
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD] Socket %d: assigned account_id=%d for user '%s'\n", 
                     client_socket, account_id, username);
            FILE_LOG(log_message);
        }
        
        user_t *user = find_user(account_id);
        if (!user) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD] Invalid account_id received: %u\n", account_id);
            FILE_LOG(log_message);
            snprintf(response, sizeof(response), "[ERROR][AUTH_THREAD] Invalid account_id\n");
            send(client_socket, response, strlen(response), 0);
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        if(get_auth_status(account_id) & AUTH_STATUS_LOCKED){
            if(get_remaining_lockout_time(account_id) > 0){
            snprintf(response, sizeof(response), "%s Account is locked for %d more seconds due to too many failed attempts.\n", 
                AUTH_LOCKED, get_remaining_lockout_time(account_id));
            send(client_socket, response, strlen(response), 0);
            snprintf(log_message, sizeof(log_message), "[WARN][AUTH_THREAD] Account is locked for %d more seconds due to too many failed attempts.\n", get_remaining_lockout_time(account_id));
            FILE_LOG(log_message);
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
            }
            else if(get_remaining_lockout_time(account_id) <= 0){
                session_t *session = find_session(account_id);
                if(session){
                    session->auth_status = AUTH_NONE;
                }
                snprintf(response, sizeof(response), "%s Account is unlocked. Please login with: /login <username> <password>\n", 
                AUTH_STATUS_UNLOCKED);
                send(client_socket, response, strlen(response), 0);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Account is unlocked.\n", account_id);
                FILE_LOG(log_message);
            }
        }
        
        if (client_pubkey) {
            user->public_key = client_pubkey;
            client_pubkey = NULL; // Ownership transferred
        } else {
            user->public_key = NULL; // No RSA key when RSA is disabled
        }
        
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Valid username received: %s \n", account_id, username);
        FILE_LOG(log_message);
        
        // Create/reset authentication session (chamber) for fresh login
        if (!reset_auth_session(account_id)) {
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Failed to create authentication session for %s\n", account_id, username);
            FILE_LOG(log_message);

            snprintf(response, sizeof(response), "ERROR: Failed to create session\n");
            send(client_socket, response, strlen(response), 0);
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        
        // Update socket info with account_id
        socket_info_t *info = get_socket_info(client_socket);
        if (info) {
            info->account_id = account_id;
            add_account_socket_mapping(account_id, client_socket);
        }
        else{
            snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Failed to get socket info for %s\n", account_id, username);
            FILE_LOG(log_message);
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1;
        }
        if(check_and_handle_lockout(account_id, client_socket)){
            return -1;
        }
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Authentication chamber created for %s\n", account_id, username);
        FILE_LOG(log_message);
        
        // Generate RSA challenge
        extern int is_rsa_disabled(void);
        if (!is_rsa_disabled() && is_rsa_system_initialized()) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Initiating automatic RSA challenge for %s\n", account_id, username);
            FILE_LOG(log_message);
            rsa_challenge_result_t rsa_result = start_rsa_challenge_for_client(account_id, user->public_key);
            
            if (rsa_result.success && rsa_result.encrypted_size > 0) {
                char hex_output[RSA_HEX_BUFFER_SIZE];
                snprintf(hex_output, sizeof(hex_output), "RSA_CHALLENGE:");
                char *hex_ptr = hex_output + strlen(hex_output);
                for (int i = 0; i < rsa_result.encrypted_size; i++) {
                    sprintf(hex_ptr + (i * 2), "%02x", rsa_result.encrypted_challenge[i]);
                }
                strcat(hex_output, "\n");
                send(client_socket, hex_output, strlen(hex_output), 0);
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] RSA challenge sent to %s\n", account_id, username);
                FILE_LOG(log_message);
            } else {
                snprintf(log_message,sizeof(log_message),"[CRITICAL][AUTH_THREAD][ID:%d] Failed to generate/send RSA challenge for %s\n", account_id, username);
                FILE_LOG(log_message);
                EVP_PKEY_free(client_pubkey);
                X509_free(client_cert);
                remove_socket_info(client_socket);
                close(client_socket);
                return -1;
            }
        }
        
        // Check if all authentication methods are disabled
        extern int is_password_disabled(void);
        extern int is_email_disabled(void);
        if (is_rsa_disabled() && is_password_disabled() && is_email_disabled()) {
            // All authentication disabled - immediately authenticate and promote user
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] All authentication disabled - auto-authenticating %s\n", account_id, username);
            FILE_LOG(log_message);
            
            // Mark user as fully authenticated
            session_t *session = NULL;
            session = find_session(account_id);
            if (session) {
                session->auth_status = AUTH_PASSWORD | AUTH_RSA | AUTH_EMAIL; // Mark all as complete
                snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Auto-authentication complete for %s\n", account_id, username);
                FILE_LOG(log_message);
                
                // Promote to authenticated chat
                promote_to_authenticated(client_socket, account_id);
                
                EVP_PKEY_free(client_pubkey);
                X509_free(client_cert);
                return 0; // Success
            } else {
                snprintf(log_message, sizeof(log_message), "[ERROR][AUTH_THREAD][ID:%d] No session found for auto-authentication of %s\n", account_id, username);
                FILE_LOG(log_message);
            }
        }
        
        // Send authentication prompt
        snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Sending authentication prompt to %s\n", account_id, username);
        FILE_LOG(log_message);
        snprintf(response, sizeof(response),
                 "%s - LOGIN PHASE\n"
                 "========================================\n"
                 "Please authenticate to access the chat:\n"
                 "  /login <username> <password> - Login with existing account\n", PROGRAM_NAME);
        send(client_socket, response, strlen(response), 0);
        
    } 
    else {
        snprintf(log_message, sizeof(log_message), "[CRITICAL][AUTH_THREAD][ID:%d] Invalid username format received\n", account_id);
        FILE_LOG(log_message);
        snprintf(response, sizeof(response), "ERROR: Invalid username format\n");
        send(client_socket, response, strlen(response), 0);
        EVP_PKEY_free(client_pubkey);
        X509_free(client_cert);
        remove_socket_info(client_socket);
        close(client_socket);
        return -1;
    }
    if (account_id > 0) {
        if (check_and_handle_lockout(account_id, client_socket)) {
            snprintf(log_message, sizeof(log_message), "[INFO][AUTH_THREAD][ID:%d] Connection rejected for account %u - locked out\n", account_id, account_id);
            FILE_LOG(log_message);
            if (client_pubkey) EVP_PKEY_free(client_pubkey);
            if (client_cert) X509_free(client_cert);
            remove_socket_info(client_socket);
            close(client_socket);
            return -1; // Reject connection entirely
        }
    }
    if (client_pubkey) {
        EVP_PKEY_free(client_pubkey);
    }
    X509_free(client_cert);
    
    snprintf(log_message, sizeof(log_message),"[INFO][AUTH_THREAD][ID:%d] Initial connection setup completed for %s \n", account_id, username);
    FILE_LOG(log_message);
    return 0; // Success
}

void broadcast_shutdown_message(void) {
    char shutdown_msg[BUFFER_SIZE];
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Broadcasting shutdown message to all authenticated clients\n");
    FILE_LOG(log_message);
    snprintf(shutdown_msg, sizeof(shutdown_msg), 
             "Server is shutting down. Goodbye!\n");
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Acquiring clients_mutex for shutdown broadcast\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&clients_mutex);
    
    client_t *c, *tmp;
    int broadcast_count = 0;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            int client_socket = c->socket;
            snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Broadcasting shutdown to client socket %d (user: %s)\n", client_socket, c->username);
            FILE_LOG(log_message);
            ssize_t sent = send(client_socket, shutdown_msg, strlen(shutdown_msg), 0);
            snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Sent %zd bytes to socket %d\n", sent, client_socket);
            FILE_LOG(log_message);
            broadcast_count++;
        }
    }
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Broadcasted shutdown message to %d clients\n", broadcast_count);
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Releasing clients_mutex after shutdown broadcast\n");
    FILE_LOG(log_message);
    pthread_mutex_unlock(&clients_mutex);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Shutdown message broadcasted to all authenticated clients\n");
    FILE_LOG(log_message);
}

void print_usage(const char *program_name) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Printing usage information\n");
    FILE_LOG(log_message);
    printf("%s - Secure Authenticated Chat Server\n", PROGRAM_NAME);
    printf("Requires encrypted user database to start\n\n");
    
    printf("USAGE:\n");
    printf("  %s <database_password>\n", program_name);
    printf("  %s --help\n", program_name);
    printf("  %s --version\n", program_name);
    
    printf("\nDESCRIPTION:\n");
    printf("  Starts a secure chat server that requires user authentication.\n");
    printf("  All clients must authenticate before accessing the chat.\n");
    printf("  Uses encrypted user database file: %s\n", DEFAULT_USER_FILE);
    
    printf("\nEXAMPLE:\n");
    printf("  %s myDatabasePassword\n", program_name);
    
    printf("\nSETUP:\n");
    printf("  1. Create a users.txt file with format: username:password_hash\n");
    printf("  2. Encrypt it: ./user_encryptor encrypt users.txt %s <password>\n", DEFAULT_USER_FILE);
    printf("  3. Start server: %s <password>\n", program_name);
    printf("  4. Clients connect and authenticate to join chat\n");
    
    printf("\nFEATURES:\n");
    printf("  - Mandatory user authentication\n");
    printf("  - Encrypted user database\n");
    printf("  - Multi-client chat with nicknames\n");
    printf("  - Session management and timeout\n");
    printf("  - Graceful shutdown with Ctrl+C\n");
}

void print_version(void) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Printing version information\n");
    FILE_LOG(log_message);
    printf("%s\n", PROGRAM_NAME);
    printf("Secure authenticated chat server with encrypted user database\n");
    FILE_LOG(log_message);
    printf("Built with OpenSSL encryption and POSIX threads\n");
    FILE_LOG(log_message);
}

void cleanup_server(void) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Cleaning up server resources...\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 1: Broadcasting shutdown message to clients\n");
    FILE_LOG(log_message);
    broadcast_shutdown_message();
    
    // Wait for clients to receive the shutdown message
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 2: Waiting 100ms for clients to receive shutdown message\n");
    FILE_LOG(log_message);
    struct timespec delay = {0, 100000000}; 
    nanosleep(&delay, NULL);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 3: Closing all client sockets\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Closing all client sockets...\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Acquiring clients_mutex for socket cleanup\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&clients_mutex);
    
    client_t *c, *tmp;
    int closed_count = 0;
    HASH_ITER(hh, clients_map, c, tmp) {
        if (c->active) {
            snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Closing client socket %d (user: %s)\n", c->socket, c->username);
            FILE_LOG(log_message);
            close(c->socket); 
            c->active = 0;
            closed_count++;
        }
    }
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Closed %d client sockets\n", closed_count);
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Releasing clients_mutex after socket cleanup\n");
    FILE_LOG(log_message);
    pthread_mutex_unlock(&clients_mutex);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 4: Stopping worker threads\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Stopping worker threads...\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Setting auth_thread_ctx.running = 0\n");
    FILE_LOG(log_message);
    auth_thread_ctx.running = 0;
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Setting cmd_thread_ctx.running = 0\n");
    FILE_LOG(log_message);
    cmd_thread_ctx.running = 0;
    
    // Wait for threads to finish
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 5: Closing epoll fds to wake threads\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Closing thread epoll fds to wake them...\n");
    FILE_LOG(log_message);
    
    // Close epoll fds to wake threads from epoll_wait
    if (auth_thread_ctx.epoll_fd != -1) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Closing auth thread epoll fd %d\n", auth_thread_ctx.epoll_fd);
        FILE_LOG(log_message);
        close(auth_thread_ctx.epoll_fd);
        auth_thread_ctx.epoll_fd = -1;
    }
    
    if (cmd_thread_ctx.epoll_fd != -1) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Closing cmd thread epoll fd %d\n", cmd_thread_ctx.epoll_fd);
        FILE_LOG(log_message);
        close(cmd_thread_ctx.epoll_fd);
        cmd_thread_ctx.epoll_fd = -1;
    }
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 6: Waiting for auth thread to join\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Waiting for auth thread...\n");
    FILE_LOG(log_message);
    pthread_join(auth_thread_ctx.thread_id, NULL);
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Auth thread joined successfully\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Step 7: Waiting for command thread to join\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Waiting for command thread...\n");
    FILE_LOG(log_message);
    pthread_join(cmd_thread_ctx.thread_id, NULL);
    snprintf(log_message, sizeof(log_message), "[DEBUG][CLEANUP] Command thread joined successfully\n");
    FILE_LOG(log_message);
    
    // Clean up socket map
    socket_info_t *current, *temp_socket;
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Cleaning up socket map...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&socket_info_map_mutex);
    HASH_ITER(hh, socket_info_map, current, temp_socket) {
        HASH_DEL(socket_info_map, current);
        close(current->socket);
        free(current);
    }
    pthread_mutex_unlock(&socket_info_map_mutex);
    
    // Now safely free all remaining clients
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Freeing remaining client map...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&clients_mutex);
    client_t *current_client, *temp_client;
    HASH_ITER(hh, clients_map, current_client, temp_client) {
        HASH_DEL(clients_map, current_client);
        free(current_client);
    }
    client_count = 0;
    pthread_mutex_unlock(&clients_mutex);
    
    // Stop REST API server
    if (rest_daemon) {
        MHD_stop_daemon(rest_daemon);
        rest_daemon = NULL;
    }
    
    // Clean up account socket map
    account_socket_t *current_account, *temp_account;
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Cleaning up account socket map...\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&account_socket_map_mutex);
    HASH_ITER(hh, account_socket_map, current_account, temp_account) {
        HASH_DEL(account_socket_map, current_account);
        free(current_account);
    }
    pthread_mutex_unlock(&account_socket_map_mutex);
    
    // Destroy mutexes
    pthread_mutex_destroy(&clients_mutex);
    pthread_mutex_destroy(&server_socket_mutex);
    pthread_mutex_destroy(&socket_info_map_mutex);
    pthread_mutex_destroy(&account_socket_map_mutex);
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server cleanup complete\n");
    FILE_LOG(log_message);
}

int main(int argc, char *argv[]) {
    char log_message[BUFFER_SIZE];
    FILE* log_file = fopen(SERVER_LOG_FILE, "a");
    if (log_file) {
        fclose(log_file);
        snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server log file created\n");
        FILE_LOG(log_message);
    }

    // Handle special arguments
    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-v") == 0) {
            print_version();
            return 0;
        }
    }
    
    // Validate arguments
    if (argc != 2) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Database password was not entered\n\n");
        FILE_LOG(log_message);
        printf("DATABASE PASSWORD REQUIRED\n\n");
        print_usage(argv[0]);
        return 1;
    }

    
    const char* database_password = argv[1];
    
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Starting %s by reading user base at %s\n", PROGRAM_NAME, user_file);
    FILE_LOG(log_message);

    // Initialize server configuration
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Loading server configuration...\n");
    FILE_LOG(log_message);
    if (!init_server_config(SERVER_CONFIG_PATH)) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to initialize server configuration\n");
        FILE_LOG(log_message);
        return 1;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Server configuration loaded successfully!\n");
    FILE_LOG(log_message);
    
    // Initialize authentication system with encrypted database
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Decrypting user database...\n");
    FILE_LOG(log_message);
    if(!init_encrypted_auth_system(user_file, (char*)database_password)){
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to initialize authentication system\n");
        FILE_LOG(log_message);
        return 1;
    }
    printf("User Database succesfully loaded!\n");
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] User database loaded successfully!\n");
    FILE_LOG(log_message);
    
    // Initialize RSA authentication system (check if disabled)
    extern int is_rsa_disabled(void);
    if (!is_rsa_disabled()) {
        snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Initializing RSA authentication...\n");
        FILE_LOG(log_message);
        if (!init_rsa_system("RSAkeys/server_private.pem", "RSAkeys/server_public.pem")) {
            snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Server RSA keys not found!\n");
            FILE_LOG(log_message);
            printf("ERROR: RSA authentication keys not found!\n");
            printf("This server requires RSA two-factor authentication.\n");
            printf("  1. Run: ./generate_rsa_keys server\n");
            printf("\nServer CANNOT start without this step.\n");
            return 1;
        }
        snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] RSA two-factor authentication enabled!\n");
        FILE_LOG(log_message);
    } else {
        snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] RSA authentication disabled in server configuration\n");
        FILE_LOG(log_message);
    }
    
    // Initialize email system (check if disabled)
    if(!init_email_system("userStatus.txt")){
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to initialize email system\n");
        FILE_LOG(log_message);
        return 1;
    }
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Email system initialized!\n");
    FILE_LOG(log_message);

    // Removed unused work queue initialization and thread creation

    // Create server socket
    pthread_mutex_lock(&server_socket_mutex);
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        pthread_mutex_unlock(&server_socket_mutex);
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Socket creation failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set socket options for address reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] setsockopt failed\n");
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    // Configure server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Bind failed on port %d\n", PORT);
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 128) < 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Listen failed\n");
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
        pthread_mutex_unlock(&server_socket_mutex);
        return 1;
    }
    
    pthread_mutex_unlock(&server_socket_mutex);
    
    printf("Server listening on port %d\n", PORT);
    printf("Maximum clients: %d\n", get_max_users());

    // Apply iptables mitigation if possible (no-op if not root or script missing)
    // Note: IPtables protection may limit connections during testing
    apply_iptables_protection(PORT);
    
    // Start REST API server
    int rest_port = get_rest_server_port();
    rest_daemon = start_rest_server(rest_port);
    if (rest_daemon == NULL) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to start REST API server on port %d\n", rest_port);
        FILE_LOG(log_message);
        return 1;
    }
    printf("REST API server listening on port %d\n", rest_port);
    printf("Server ready! Press Ctrl+C to exit\n");
    printf("========================================================================\n");
    
    // Set up epoll for main thread (accepting connections)
    int main_epoll_fd = epoll_create1(0);
    if (main_epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (main) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set up epoll for auth thread
    auth_thread_ctx.epoll_fd = epoll_create1(0);
    if (auth_thread_ctx.epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (auth) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Set up epoll for command thread
    cmd_thread_ctx.epoll_fd = epoll_create1(0);
    if (cmd_thread_ctx.epoll_fd == -1) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_create1 (cmd) failed\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Add server socket to main epoll
    struct epoll_event server_event;
    server_event.events = EPOLLIN;
    server_event.data.fd = server_socket; // Store server socket fd
    epoll_ctl(main_epoll_fd, EPOLL_CTL_ADD, server_socket, &server_event);
    
    // Create self-pipe and add read end to epoll to wake on signals
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Creating shutdown pipe\n");
    FILE_LOG(log_message);
    if (pipe(shutdown_pipe) == 0) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Shutdown pipe created: read_fd=%d, write_fd=%d\n", shutdown_pipe[0], shutdown_pipe[1]);
        FILE_LOG(log_message);
        
        int flags_r = fcntl(shutdown_pipe[0], F_GETFL, 0);
        int flags_w = fcntl(shutdown_pipe[1], F_GETFL, 0);
        fcntl(shutdown_pipe[0], F_SETFL, flags_r | O_NONBLOCK);
        fcntl(shutdown_pipe[1], F_SETFL, flags_w | O_NONBLOCK);
        
        struct epoll_event pipe_event;
        pipe_event.events = EPOLLIN;
        pipe_event.data.fd = shutdown_pipe[0];  // Store fd directly instead of pointer
        int epoll_add_result = epoll_ctl(main_epoll_fd, EPOLL_CTL_ADD, shutdown_pipe[0], &pipe_event);
        if (epoll_add_result == -1) {
            snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to add shutdown pipe to epoll: %s (errno=%d)\n", strerror(errno), errno);
            FILE_LOG(log_message);
            close(shutdown_pipe[0]);
            close(shutdown_pipe[1]);
            shutdown_pipe[0] = -1;
            shutdown_pipe[1] = -1;
            return 1;
        }
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Added shutdown pipe to epoll, result: %d\n", epoll_add_result);
        FILE_LOG(log_message);
        
        // NOW set up signal handlers AFTER shutdown pipe is ready
        signal(SIGINT, signal_handler);
        signal(SIGTERM, signal_handler);
        signal(SIGPIPE, sigpipe_handler);

        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Signal handlers installed after shutdown pipe setup\n");
        FILE_LOG(log_message);
        
    } else {
        snprintf(log_message, sizeof(log_message), "[ERROR][MAIN_THREAD] Failed to create shutdown pipe: %s\n", strerror(errno));
        FILE_LOG(log_message);
    }
    
    // Block signals in all threads except main thread
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    
    // Start worker threads (they inherit the signal mask, so signals blocked)
    auth_thread_ctx.running = 1;
    cmd_thread_ctx.running = 1;
    
    if (pthread_create(&auth_thread_ctx.thread_id, NULL, auth_thread_func, &auth_thread_ctx) != 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to create auth thread\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    if (pthread_create(&cmd_thread_ctx.thread_id, NULL, cmd_thread_func, &cmd_thread_ctx) != 0) {
        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] Failed to create command thread\n");
        FILE_LOG(log_message);
        return 1;
    }
    
    // Main accept loop
    int max_events = get_max_events();
    struct epoll_event events[max_events];
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Entering main accept loop with server_running=%d\n", server_running);
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] About to enter main loop, shutdown_pipe[0]=%d, shutdown_pipe[1]=%d\n", shutdown_pipe[0], shutdown_pipe[1]);
    FILE_LOG(log_message);
    
    while (server_running) {
        
        // Check shutdown flag before epoll_wait
        if (!server_running) {
            snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] server_running is 0, exiting main loop\n");
            FILE_LOG(log_message);
            break;
        }
        
        // Use shorter timeout for more responsive shutdown
        int nfds = epoll_wait(main_epoll_fd, events, max_events, 100);
        
        // Check shutdown flag immediately after epoll_wait
        if (!server_running) {
            snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] server_running=0 detected after epoll_wait, exiting main loop\n");
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds == -1) {
            if (errno == EINTR) {
                // Check if we should exit due to signal
                if (!server_running) {
                    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] server_running=0 detected after EINTR, exiting main loop\n");
                    FILE_LOG(log_message);
                    break;
                }
                continue;
            }
            snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_wait (main) failed\n");
            FILE_LOG(log_message);
            break;
        }
        
        if (nfds == 0) {
            // Check shutdown flag on timeout as fallback
            if (!server_running) {
                snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Shutdown detected via flag during timeout\n");
                FILE_LOG(log_message);
                break;
            }
        } 
        
        // Check ALL events for shutdown pipe first (priority check)
        int shutdown_detected = 0;
       
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == shutdown_pipe[0]) {
                // Drain the pipe and break to exit loop
                snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] SHUTDOWN PIPE EVENT DETECTED! Processing shutdown...\n");
                FILE_LOG(log_message);
                char buf[16];
                int bytes_read = 0;
                while ((bytes_read = read(shutdown_pipe[0], buf, sizeof(buf))) > 0) {
                    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Drained %d bytes from shutdown pipe\n", bytes_read);
                    FILE_LOG(log_message);
                }
                snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Setting server_running=0 and breaking from main loop\n");
                FILE_LOG(log_message);
                server_running = 0;
                shutdown_detected = 1;
                break;
            }
        }
        
        // Exit immediately if shutdown was detected
        if (shutdown_detected) {
            break;
        }
        
        // Process other events only if not shutting down
        for (int i = 0; i < nfds; i++) {
            // Skip shutdown pipe events (already processed above)
            if (events[i].data.fd == shutdown_pipe[0]) {
                continue;
            }
            
            snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Event %d: data.fd=%d, shutdown_pipe[0]=%d\n", i, events[i].data.fd, shutdown_pipe[0]);
            FILE_LOG(log_message);
            
            if (events[i].data.fd == server_socket) {
                // New connection
                struct sockaddr_in client_addr;
                socklen_t client_addr_len = sizeof(client_addr);
                
                int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_addr_len);
                if (client_socket < 0) {
                    if (server_running) {
                        snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] accept failed\n");
                        FILE_LOG(log_message);
                    }
                    continue;
                }
                
                // Check if we've reached the maximum number of clients
                int max_clients = get_max_users();
                if (client_count >= max_clients) {
                    snprintf(log_message, sizeof(log_message), "[WARN][MAIN_THREAD] Maximum clients (%d) reached, rejecting connection from %s:%d\n", 
                           max_clients, inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
                    FILE_LOG(log_message);
                    send(client_socket, "Server is full, please try again later\n", 38, 0);
                    close(client_socket);
                    continue;
                }
                
                snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] New connection from %s:%d (socket=%d)\n", 
                       inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port), client_socket);
                FILE_LOG(log_message);
                // Set non-blocking
                int flags = fcntl(client_socket, F_GETFL, 0);
                fcntl(client_socket, F_SETFL, flags | O_NONBLOCK);
                
                // Initialize socket tracking
                add_socket_info(client_socket);
                
                // Set initial state
                socket_info_t *info = get_socket_info(client_socket);
                if (info) {
                    info->state = SOCKET_STATE_NEW;
                    info->last_activity = time(NULL);
                    info->account_id = -1;  // Ensure clean state
                    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: initialized with state=NEW, account_id=%d\n", 
                             client_socket, info->account_id);
                    FILE_LOG(log_message);
                }
                
                // Handle initial connection setup BEFORE adding to epoll (certificate extraction, RSA challenge)
                snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: starting initial setup\n", client_socket);
                FILE_LOG(log_message);
                
                int setup_result = setup_initial_connection(client_socket);
                if(setup_result != 0){
                    // setup_initial_connection already handles cleanup on failure
                    // But ensure socket_info is also cleaned up
                    socket_info_t *failed_info = get_socket_info(client_socket);
                    if (failed_info) {
                        snprintf(log_message, sizeof(log_message), "[WARN][MAIN_THREAD] Socket %d: setup failed, cleaning up socket_info\n", client_socket);
                        FILE_LOG(log_message);
                        remove_socket_info(client_socket);
                    }
                    // Don't call remove_client or close again - socket is already closed
                    continue;
                }
                if (setup_result == 0) {
                    // Setup successful, check socket state
                    socket_info_t *updated_info = get_socket_info(client_socket);
                    if (updated_info) {
                        if (updated_info->state == SOCKET_STATE_AUTHENTICATED) {
                            // Auto-authentication occurred during setup - socket is already promoted
                            snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: auto-authenticated during setup, skipping auth epoll\n", client_socket);
                            FILE_LOG(log_message);
                        } 
                        else {
                            // Normal authentication flow - set state and add to auth epoll
                            updated_info->state = SOCKET_STATE_AUTHENTICATING;
                            snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: setup successful, state=AUTHENTICATING\n", client_socket);
                            FILE_LOG(log_message);
                            
                            // Add to auth thread's epoll after setup is complete
                            struct epoll_event client_event;
                            client_event.data.fd = client_socket;
                            client_event.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLHUP | EPOLLERR;
                            snprintf(log_message, sizeof(log_message), "[INFO][PROMOTE][ID:%d] Adding socket %d to auth thread epoll\n", updated_info->account_id, client_socket);
                            if (epoll_ctl(auth_thread_ctx.epoll_fd, EPOLL_CTL_ADD, client_socket, &client_event) == -1) {
                                snprintf(log_message, sizeof(log_message), "[FATAL][MAIN_THREAD] epoll_ctl (auth) failed\n");
                                FILE_LOG(log_message);
                                remove_socket_info(client_socket);
                                close(client_socket);
                                continue;
                            }
                            
                            snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: added to auth thread epoll\n", client_socket);
                            FILE_LOG(log_message);
                        }
                    }
                }
                else {
                    // Setup failed, socket is already cleaned up
                    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Socket %d: intial setup failed\n", client_socket);
                    FILE_LOG(log_message);
                    continue;
                }
            }
        }
    }
    
    // We are exiting main accept loop
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Main accept loop exited, beginning cleanup\n");
    FILE_LOG(log_message);
    FILE_LOG("[INFO][MAIN_THREAD] Main accept loop exited\n");
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Closing main epoll and shutdown pipes\n");
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Closing main epoll fd...\n");
    FILE_LOG(log_message);
    // Cleanup
    close(main_epoll_fd);
    if (shutdown_pipe[0] != -1) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Closing shutdown_pipe[0]\n");
        FILE_LOG(log_message);
        close(shutdown_pipe[0]);
    }
    if (shutdown_pipe[1] != -1) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Closing shutdown_pipe[1]\n");
        FILE_LOG(log_message);
        close(shutdown_pipe[1]);
    }
    
    // Cleanup and shutdown
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Acquiring server_socket_mutex to close server socket\n");
    FILE_LOG(log_message);
    pthread_mutex_lock(&server_socket_mutex);
    if (server_socket != -1) {
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Closing server socket %d\n", server_socket);
        FILE_LOG(log_message);
        close(server_socket);
        server_socket = -1;
    }
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Releasing server_socket_mutex\n");
    FILE_LOG(log_message);
    pthread_mutex_unlock(&server_socket_mutex);

    // Remove iptables mitigation on shutdown
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Starting iptables mitigation removal\n");
    FILE_LOG(log_message);
    FILE_LOG("[INFO][MAIN_THREAD] Removing iptables mitigation...\n");
    remove_iptables_protection(PORT);
    FILE_LOG("[INFO][MAIN_THREAD] iptables mitigation removal complete\n");
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] About to call cleanup_server()\n");
    FILE_LOG(log_message);
    cleanup_server();
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] cleanup_server() completed\n");
    FILE_LOG(log_message);
    
    // Add a small delay to ensure all threads have completely finished
    // before cleaning up the auth system to prevent deadlock
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Waiting 500ms for threads to fully complete\n");
    FILE_LOG(log_message);
    struct timespec delay = {0, 500000000}; // 500ms in nanoseconds
    nanosleep(&delay, NULL);
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] 500ms delay completed\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Cleaning up authentication system\n");
    FILE_LOG(log_message);
    cleanup_auth_system(); // Clean up authentication system hashmaps
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Authentication system cleanup completed\n");
    FILE_LOG(log_message);
    
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Cleaning up OpenSSL\n");
    FILE_LOG(log_message);
    OPENSSL_cleanup();
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] OpenSSL cleanup completed\n");
    FILE_LOG(log_message);
    free(server_config.serverIPaddress);

    printf("Server Cleanup Succesful...\n");
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] %s shutdown complete\n", PROGRAM_NAME);
    FILE_LOG(log_message);
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] About to return 0 and exit\n");
    FILE_LOG(log_message);
    return 0;
}    

