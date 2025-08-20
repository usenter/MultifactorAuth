#include "jwt.h"
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

static unsigned char g_jwt_secret[32];
static int g_secret_ready = 0;

static void b64url_from_raw(const unsigned char* in, size_t in_len, char* out, size_t out_sz) {
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

static int b64url_to_raw(const char* in, unsigned char* out, size_t out_max, size_t* out_len) {
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

char* jwt_issue_hs256(unsigned int account_id, const char* username, int auth_flags, int ttl_seconds) {
	if (!g_secret_ready) return NULL;
	const char* header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
	char header_b64[128];
	b64url_from_raw((const unsigned char*)header, strlen(header), header_b64, sizeof(header_b64));

	time_t now = time(NULL);
	long iat = (long)now;
	long exp = (long)(now + (ttl_seconds > 0 ? ttl_seconds : 3600));

	char payload[256];
	snprintf(payload, sizeof(payload),
	         "{\"sub\":%u,\"username\":\"%s\",\"auth\":%d,\"iat\":%ld,\"exp\":%ld}",
	         account_id, username ? username : "", auth_flags, iat, exp);

	char payload_b64[512];
	b64url_from_raw((const unsigned char*)payload, strlen(payload), payload_b64, sizeof(payload_b64));

	char signing_input[800];
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

int jwt_verify_hs256(const char* token,
                     unsigned int* account_id_out,
                     int* auth_flags_out,
                     long* iat_out, long* exp_out,
                     char* username_out, size_t username_out_sz) {
	if (!g_secret_ready || !token) return 0;
	const char* dot1 = strchr(token, '.');
	if (!dot1) return 0;
	const char* dot2 = strchr(dot1 + 1, '.');
	if (!dot2) return 0;

	size_t hlen = (size_t)(dot1 - token);
	size_t plen = (size_t)(dot2 - dot1 - 1);
	const char* sig_b64 = dot2 + 1;

	char signing_input[800];
	if (hlen + 1 + plen >= sizeof(signing_input)) return 0;
	memcpy(signing_input, token, hlen + 1 + plen);
	signing_input[hlen + 1 + plen] = '\0';

	unsigned char sig[EVP_MAX_MD_SIZE];
	unsigned int sig_len = 0;
	if (!HMAC(EVP_sha256(), g_jwt_secret, (int)sizeof(g_jwt_secret),
	          (unsigned char*)signing_input, strlen(signing_input), sig, &sig_len)) {
		return 0;
	}
	unsigned char sig_tok[EVP_MAX_MD_SIZE];
	size_t sig_tok_len = 0;
	if (!b64url_to_raw(sig_b64, sig_tok, sizeof(sig_tok), &sig_tok_len)) return 0;
	if (sig_len != sig_tok_len || CRYPTO_memcmp(sig, sig_tok, sig_len) != 0) return 0;

	// decode payload
	char* payload_b64 = strndup(dot1 + 1, plen);
	unsigned char payload_raw[512];
	size_t payload_raw_len = 0;
	int ok = b64url_to_raw(payload_b64, payload_raw, sizeof(payload_raw), &payload_raw_len);
	free(payload_b64);
	if (!ok) return 0;
	payload_raw[payload_raw_len] = '\0';
	const char* json = (const char*)payload_raw;

	long sub=0, auth=0, iat=0, exp=0;
	if (!json_extract_int(json, "sub", &sub)) return 0;
	if (!json_extract_int(json, "auth", &auth)) return 0;
	json_extract_int(json, "iat", &iat);
	if (!json_extract_int(json, "exp", &exp)) return 0;
	if (exp > 0 && time(NULL) > exp) return 0;

	if (account_id_out) *account_id_out = (unsigned int)sub;
	if (auth_flags_out) *auth_flags_out = (int)auth;
	if (iat_out) *iat_out = iat;
	if (exp_out) *exp_out = exp;
	if (username_out && username_out_sz > 0) {
		username_out[0] = '\0';
		json_extract_str(json, "username", username_out, username_out_sz);
	}
	return 1;
}