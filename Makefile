# Simplified Makefile for TCP Server/Client Project (Linux)
CC = clang
CFLAGS = -Wall -Wextra -std=c17 -pthread -D_POSIX_C_SOURCE=200809L
LIBS = -lssl -lcrypto

# Object files
OBJS = encryptionTools.o auth_system.o hashmap/hashmap.o

# Targets
all: unified_server unified_client simple_test_client encryptionTools_test user_encryptor

# Object file rules with header dependencies
encryptionTools.o: encryptionTools.c encryptionTools.h
	$(CC) $(CFLAGS) -c $< -o $@

auth_system.o: auth_system.c
	$(CC) $(CFLAGS) -c $< -o $@

hashmap/hashmap.o: hashmap/hashmap.c
	$(CC) $(CFLAGS) -c $< -o $@

# Standalone encryption tools test executable
encryptionTools_test: encryptionTools.c encryptionTools.h
	$(CC) $(CFLAGS) -DTEST_MAIN -o $@ $< $(LIBS)

# Standalone file encryption/decryption tool
user_encryptor: userEncryptionTools/user_encryptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Server with authentication (uses object files)
unified_server: unified_server.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Unified client with authentication support
unified_client: unified_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Simple test client
simple_test_client: simple_test_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Clean
clean:
	rm -f unified_server unified_client simple_test_client encryptionTools_test user_encryptor $(OBJS)

# Run server in basic mode
run-server-basic: unified_server
	./unified_server basic

# Run server in chat mode
run-server-chat: unified_server
	./unified_server chat

# Run client in basic mode
run-client-basic: unified_client
	./unified_client basic

# Run client in chat mode
run-client-chat: unified_client
	./unified_client chat

# Run simple test client
run-test-client: simple_test_client
	./simple_test_client

.PHONY: all clean run-server-basic run-server-chat run-client-basic run-client-chat run-test-client 