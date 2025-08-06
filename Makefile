# Simplified Makefile for TCP Server/Client Project (Linux)
CC = clang
CFLAGS = -Wall -Wextra -std=c17 -pthread -D_POSIX_C_SOURCE=200809L
LIBS = -lssl -lcrypto -lcurl -lcjson -lmicrohttpd

# Object files
OBJS = encryptionTools.o auth_system.o fileOperations.o emailFunction.o serverConfig.o

# Targets
all: unified_server unified_client encryptionTools_test user_encryptor generate_rsa_keys rest_client

# Object file rules with header dependencies
encryptionTools.o: decryptionFunctions/encryptionTools.c decryptionFunctions/encryptionTools.h
	$(CC) $(CFLAGS) -c $< -o $@

auth_system.o: auth_system.c
	$(CC) $(CFLAGS) -c $< -o $@

fileOperations.o: fileOperations.c fileOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# Email test executable
emailFunction.o: emailFunctions/emailFunction.c emailFunctions/emailFunction.h
	$(CC) $(CFLAGS) -c $< -o $@

# Server configuration
serverConfig.o: serverConfig.c serverConfig.h
	$(CC) $(CFLAGS) -c $< -o $@

# REST client program
rest_client: rest_client.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Standalone file encryption/decryption tool
user_encryptor: userEncryptionTools/user_encryptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Server with authentication (uses object files)
unified_server: unified_server.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

encryptionTools_test: decryptionFunctions/encryptionTools.c decryptionFunctions/encryptionTools.h
	$(CC) $(CFLAGS) -DTEST_MAIN -o $@ $< $(LIBS)

# Unified client with authentication support (includes RSA authentication)
unified_client: unified_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# RSA key generator utility
generate_rsa_keys: generate_rsa_keys.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Clean
clean:
	rm -f *.o unified_server unified_client encryptionTools_test user_encryptor generate_rsa_keys rest_client

.PHONY: all clean 