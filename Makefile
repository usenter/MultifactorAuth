# Simplified Makefile for TCP Server/Client Project (Linux)
CC = clang
CFLAGS = -Wall -Wextra -std=c17 -pthread -D_POSIX_C_SOURCE=200809L -D_GNU_SOURCE -g
LIBS = -lssl -lcrypto -lcurl -lcjson -lmicrohttpd 

# Object files
OBJS = encryptionOperations.o auth_system.o fileHandlingOperations.o emailHandlingOperations.o serverConfigOperations.o socketHandlingOperations.o serverRestOperations.o IPtableOperations.o jwtOperations.o

# Targets
all: unified_server unified_client encryptionOperations user_encryptor generate_rsa_keys rest_client

# Object file rules with header dependencies
encryptionOperations.o: encryption_tools/encryptionOperations.c encryption_tools/encryptionOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

auth_system.o: auth_system.c
	$(CC) $(CFLAGS) -c $< -o $@

fileHandlingOperations.o: fileOperation_tools/fileOperations.c fileOperation_tools/fileOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# Email test executable
emailHandlingOperations.o: emailHandling_tools/emailHandlingOperations.c emailHandling_tools/emailHandlingOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# Server configuration
serverConfigOperations.o: config_tools/serverConfigOperations.c config_tools/serverConfigOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# Socket handling
socketHandlingOperations.o: socketHandling_tools/socketHandlingOperations.c socketHandling_tools/socketHandlingOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# REST API handling
serverRestOperations.o: REST_tools/serverRestOperations.c REST_tools/serverRestOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# IP table functions
IPtableOperations.o: IPTable_tools/IPtableOperations.c IPTable_tools/IPtableOperations.h
	$(CC) $(CFLAGS) -c IPTable_tools/IPtableOperations.c -o $@

# JWT operations
jwtOperations.o: JWT_tools/jwtOperations.c JWT_tools/jwtOperations.h
	$(CC) $(CFLAGS) -c $< -o $@

# REST client program
rest_client: REST_tools/rest_client.c serverConfigOperations.o
	$(CC) $(CFLAGS) -o $@ $< serverConfigOperations.o $(LIBS)

# Standalone file encryption/decryption tool
user_encryptor: userDBencryption_tools/user_encryptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Server with authentication (uses object files)
unified_server: unified_server.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
encryptionOperations: encryption_tools/encryptionOperations.c encryption_tools/encryptionOperations.h
	$(CC) $(CFLAGS) -DTEST_MAIN -o $@ $< $(LIBS)

# Unified client with authentication support (includes RSA authentication)
unified_client: unified_client.c jwtOperations.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# RSA key generator utility
generate_rsa_keys: generate_rsa_keys.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Clean
clean:
	rm -f *.o unified_server unified_client encryptionOperations user_encryptor generate_rsa_keys rest_client

.PHONY: all clean 