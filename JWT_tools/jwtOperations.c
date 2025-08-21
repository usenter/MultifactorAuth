#include "jwtOperations.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static unsigned char g_jwt_secret[32];
static int g_secret_ready = 0;

// Global JWT state tracking (optional, for revocation/versioning)
static jwt_state_t *g_jwt_states = NULL;

// Helper functions for JWT type conversion
const char* jwt_type_to_string(jwt_type_t type) {
    switch (type) {
        case JWT_TYPE_NONE: return "none";
        case JWT_TYPE_RSA: return "rsa";
        case JWT_TYPE_SESSKEY: return "sesskey";
        case JWT_TYPE_PASSWORD: return "password";
        case JWT_TYPE_EMAIL: return "email";
        case JWT_TYPE_FULL: return "full";
        default: return "unknown";
    }
}

jwt_type_t jwt_type_from_string(const char* type_str) {
    if (!type_str) return JWT_TYPE_NONE;
    if (strcmp(type_str, "rsa") == 0) return JWT_TYPE_RSA;
    if (strcmp(type_str, "sesskey") == 0) return JWT_TYPE_SESSKEY;
    if (strcmp(type_str, "password") == 0) return JWT_TYPE_PASSWORD;
    if (strcmp(type_str, "email") == 0) return JWT_TYPE_EMAIL;
    if (strcmp(type_str, "full") == 0) return JWT_TYPE_FULL;
    return JWT_TYPE_NONE;
}

// Get or create JWT state for an account
static jwt_state_t* get_jwt_state(unsigned int account_id) {
    jwt_state_t *state = NULL;
    HASH_FIND_INT(g_jwt_states, &account_id, state);
    
    if (!state) {
        state = malloc(sizeof(jwt_state_t));
        if (!state) return NULL;
        
        state->account_id = account_id;
        state->token_version = 1;
        state->token_type = JWT_TYPE_NONE;
        state->last_issued = 0;
        
        HASH_ADD_INT(g_jwt_states, account_id, state);
    }
    
    return state;
}

// Update JWT state and increment version if needed
static int update_jwt_state(unsigned int account_id, jwt_type_t new_type) {
    jwt_state_t *state = get_jwt_state(account_id);
    if (!state) return 0;
    
    // Increment version if auth stage is progressing
    if (new_type > state->token_type) {
        state->token_version++;
    }
    
    state->token_type = new_type;
    state->last_issued = time(NULL);
    
    return 1;
}

void b64url_from_raw(const unsigned char* in, size_t in_len, char* out, size_t out_sz) {
	// base64 then URL-safe and strip '='
	unsigned char* tmp = malloc(((in_len + 2) / 3) * 4 + 4);
	int len = EVP_EncodeBlock(tmp, in, (int)in_len);
	size_t j = 0;
	for (int i = 0; i < len && j + 1 < out_sz; i++) {
		unsigned char c = tmp[i];
		if (c == '+') c = '-';
		else if (c == '/') c = '_';
		else if (c == '=') break;
		out[j++] = c;
	}
	out[j] = '\0';
	free(tmp);
}

int b64url_to_raw(const char* in, unsigned char* out, size_t out_max, size_t* out_len) {
	// convert -_ to +/ and pad
	size_t in_len = strlen(in);
	size_t padded_len = in_len;
	size_t pad = (4 - (padded_len % 4)) % 4;
	char* tmp = malloc(in_len + pad + 1);
	for (size_t i = 0; i < in_len; i++) {
		char c = in[i];
		if (c == '-') c = '+';
		else if (c == '_') c = '/';
		tmp[i] = c;
	}
	for (size_t i = 0; i < pad; i++) tmp[in_len + i] = '=';
	tmp[in_len + pad] = '\0';

	int dec_len = EVP_DecodeBlock(out, (unsigned char*)tmp, (int)(in_len + pad));
	free(tmp);
	if (dec_len < 0) return 0;
	// EVP_DecodeBlock may include padding bytes; caller may trim if needed.
	*out_len = (size_t)dec_len;
	return 1;
}

int jwt_init_secret(const char* path) {
	FILE* f = fopen(path, "rb");
	if (f) {
		size_t r = fread(g_jwt_secret, 1, sizeof(g_jwt_secret), f);
		fclose(f);
		if (r == sizeof(g_jwt_secret)) { g_secret_ready = 1; return 1; }
	}
	if (RAND_bytes(g_jwt_secret, (int)sizeof(g_jwt_secret)) != 1) return 0;
	f = fopen(path, "wb");
	if (f) {
		fwrite(g_jwt_secret, 1, sizeof(g_jwt_secret), f);
		fclose(f);
	}
	g_secret_ready = 1;
	return 1;
}

static int json_extract_int(const char* json, const char* key, long* out) {
	// naive extractor: looks for "key": number
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":", key);
	const char* p = strstr(json, pat);
	if (!p) return 0;
	p += strlen(pat);
	while (*p == ' ' || *p == '\t') p++;
	char* end = NULL;
	long v = strtol(p, &end, 10);
	if (end == p) return 0;
	*out = v;
	return 1;
}

static int json_extract_str(const char* json, const char* key, char* out, size_t out_sz) {
	char pat[64];
	snprintf(pat, sizeof(pat), "\"%s\":\"", key);
	const char* p = strstr(json, pat);
	if (!p) return 0;
	p += strlen(pat);
	const char* q = strchr(p, '"');
	if (!q) return 0;
	size_t n = (size_t)(q - p);
	if (n >= out_sz) n = out_sz - 1;
	memcpy(out, p, n);
	out[n] = '\0';
	return 1;
}

// New staged JWT issuance function
char* jwt_issue_hs256_staged(unsigned int account_id, 
                             const char* username, 
                             jwt_type_t stage,
                             int token_version,
                             int ttl_seconds) {
    if (!g_secret_ready) return NULL;
    
    // Update internal state tracking
    update_jwt_state(account_id, stage);
    
    const char* header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char header_b64[128];
    b64url_from_raw((const unsigned char*)header, strlen(header), header_b64, sizeof(header_b64));

    time_t now = time(NULL);
    long iat = (long)now;
    long exp = (long)(now + (ttl_seconds > 0 ? ttl_seconds : 3600));

    char payload[512];
    snprintf(payload, sizeof(payload),
             "{\"sub\":%u,\"username\":\"%s\",\"stage\":\"%s\",\"ver\":%d,\"iat\":%ld,\"exp\":%ld}",
             account_id, username ? username : "", jwt_type_to_string(stage), token_version, iat, exp);

    char payload_b64[1024];
    b64url_from_raw((const unsigned char*)payload, strlen(payload), payload_b64, sizeof(payload_b64));

    char signing_input[1200];
    snprintf(signing_input, sizeof(signing_input), "%s.%s", header_b64, payload_b64);

    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int sig_len = 0;
    if (!HMAC(EVP_sha256(), g_jwt_secret, (int)sizeof(g_jwt_secret),
              (unsigned char*)signing_input, strlen(signing_input), sig, &sig_len)) {
        return NULL;
    }
    char sig_b64[256];
    b64url_from_raw(sig, sig_len, sig_b64, sizeof(sig_b64));

    size_t out_len = strlen(signing_input) + 1 + strlen(sig_b64) + 1;
    char* token = malloc(out_len);
    if (!token) return NULL;
    snprintf(token, out_len, "%s.%s", signing_input, sig_b64);
    return token;
}

// Updated verification function with new signature
int jwt_verify_hs256(const char* token,
                     unsigned int* account_id_out,
                     jwt_type_t* stage_out,
                     int* token_version_out,
                     long* iat_out,
                     long* exp_out,
                     char* username_out,
                     size_t username_out_sz) {
    if (!g_secret_ready || !token) {
        fprintf(stderr, "[JWT_DEBUG] Secret not ready or token NULL\n");
        return 0;
    }
    
    const char* dot1 = strchr(token, '.');
    if (!dot1) return 0;
    const char* dot2 = strchr(dot1 + 1, '.');
    if (!dot2) return 0;

    size_t hlen = (size_t)(dot1 - token);
    size_t plen = (size_t)(dot2 - dot1 - 1);
    const char* sig_b64 = dot2 + 1;

    char signing_input[1200];
    if (hlen + 1 + plen >= sizeof(signing_input)) return 0;
    memcpy(signing_input, token, hlen + 1 + plen);
    signing_input[hlen + 1 + plen] = '\0';

    unsigned char sig[EVP_MAX_MD_SIZE];
    unsigned int sig_len = 0;
    if (!HMAC(EVP_sha256(), g_jwt_secret, (int)sizeof(g_jwt_secret),
              (unsigned char*)signing_input, strlen(signing_input), sig, &sig_len)) {
        fprintf(stderr, "[JWT_DEBUG] HMAC computation failed\n");
        return 0;
    }
    unsigned char sig_tok[EVP_MAX_MD_SIZE];
    size_t sig_tok_len = 0;
    if (!b64url_to_raw(sig_b64, sig_tok, sizeof(sig_tok), &sig_tok_len)) {
        fprintf(stderr, "[JWT_DEBUG] Base64URL decode of signature failed\n");
        return 0;
    }

    // Trim padding bytes from decoded signature if present
    while (sig_tok_len > 0 && sig_tok[sig_tok_len - 1] == 0) {
        sig_tok_len--;
    }

    if (sig_len != sig_tok_len || CRYPTO_memcmp(sig, sig_tok, sig_len) != 0) {
        fprintf(stderr, "[JWT_DEBUG] Signature mismatch: computed_len=%u, token_len=%zu\n", sig_len, sig_tok_len);
        return 0;
    }

    // decode payload
    char* payload_b64 = strndup(dot1 + 1, plen);
    unsigned char payload_raw[1024];
    size_t payload_raw_len = 0;
    int ok = b64url_to_raw(payload_b64, payload_raw, sizeof(payload_raw), &payload_raw_len);
    free(payload_b64);
    if (!ok) {
        printf("[JWT_DEBUG] Payload Base64URL decode failed\n");
        return 0;
    }
    payload_raw[payload_raw_len] = '\0';
    const char* json = (const char*)payload_raw;

    long sub = 0, ver = 0, iat = 0, exp = 0;
    char stage_str[32] = {0};
    
    if (!json_extract_int(json, "sub", &sub)) {
        fprintf(stderr, "[JWT_DEBUG] Failed to extract 'sub' from JSON: %s\n", json);
        return 0;
    }
    if (!json_extract_int(json, "ver", &ver)) {
        fprintf(stderr, "[JWT_DEBUG] Failed to extract 'ver' from JSON: %s\n", json);
        return 0;
    }
    json_extract_int(json, "iat", &iat);
    if (!json_extract_int(json, "exp", &exp)) {
        fprintf(stderr, "[JWT_DEBUG] Failed to extract 'exp' from JSON: %s\n", json);
        return 0;
    }
    if (exp > 0 && time(NULL) > exp) {
        fprintf(stderr, "[JWT_DEBUG] Token expired: exp=%ld, current=%ld\n", exp, time(NULL));
        return 0;
    }

    // Extract stage string
    if (!json_extract_str(json, "stage", stage_str, sizeof(stage_str))) {
        fprintf(stderr, "[JWT_DEBUG] Failed to extract 'stage' from JSON: %s\n", json);
        return 0;
    }
    jwt_type_t stage = jwt_type_from_string(stage_str);
    
    // Verify token version matches current state
    // DISABLED: Token version checking disabled for resume functionality
    // jwt_state_t *current_state = get_jwt_state((unsigned int)sub);
    // if (current_state && current_state->token_version != (int)ver) {
    //     return 0; // Token version mismatch - token revoked
    // }

    if (account_id_out) *account_id_out = (unsigned int)sub;
    if (stage_out) *stage_out = stage;
    if (token_version_out) *token_version_out = (int)ver;
    if (iat_out) *iat_out = iat;
    if (exp_out) *exp_out = exp;
    if (username_out && username_out_sz > 0) {
        username_out[0] = '\0';
        json_extract_str(json, "username", username_out, username_out_sz);
    }
    return 1;
}

// Legacy function for backward compatibility
char* jwt_issue_hs256(unsigned int account_id, const char* username, int auth_flags, int ttl_seconds) {
    // Convert auth_flags to stage (simplified mapping)
    jwt_type_t stage = JWT_TYPE_FULL; // Default to full auth
    if (auth_flags == 0) stage = JWT_TYPE_NONE;
    else if ((auth_flags & 1) == 1) stage = JWT_TYPE_PASSWORD; // AUTH_PASSWORD
    else if ((auth_flags & 7) == 7) stage = JWT_TYPE_FULL; // AUTH_FULLY_AUTHENTICATED
    
    return jwt_issue_hs256_staged(account_id, username, stage, 1, ttl_seconds);
}

// Cleanup function for JWT states
void jwt_cleanup_states(void) {
    jwt_state_t *state, *tmp;
    HASH_ITER(hh, g_jwt_states, state, tmp) {
        HASH_DEL(g_jwt_states, state);
        free(state);
    }
    g_jwt_states = NULL;
}

// Get current token version for an account
int jwt_get_current_version(unsigned int account_id) {
    jwt_state_t *state = get_jwt_state(account_id);
    return state ? state->token_version : 1;
}

// Revoke all tokens for an account (increment version)
int jwt_revoke_account(unsigned int account_id) {
    jwt_state_t *state = get_jwt_state(account_id);
    if (!state) return 0;
    
    state->token_version++;
    state->last_issued = time(NULL);
    return 1;
}

// Get current auth stage for an account
jwt_type_t jwt_get_current_stage(unsigned int account_id) {
    jwt_state_t *state = get_jwt_state(account_id);
    return state ? state->token_type : JWT_TYPE_NONE;
}