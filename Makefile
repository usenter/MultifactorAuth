# Simplified Makefile for TCP Server/Client Project (Linux)
CC = clang
CFLAGS = -Wall -Wextra -std=c17 -pthread -D_POSIX_C_SOURCE=200809L
LIBS = 

# Targets
all: unified_server unified_client authenticated_client simple_test_client

# Server with authentication
unified_server: unified_server.c auth_system.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Original client (without authentication)
unified_client: unified_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# New authenticated client
authenticated_client: authenticated_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Simple test client
simple_test_client: simple_test_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Clean
clean:
	rm -f unified_server unified_client authenticated_client simple_test_client

# Run server in basic mode
run-server-basic: unified_server
	./unified_server basic

# Run server in chat mode
run-server-chat: unified_server
	./unified_server chat

# Run authenticated client in basic mode
run-auth-client-basic: authenticated_client
	./authenticated_client basic

# Run authenticated client in chat mode
run-auth-client-chat: authenticated_client
	./authenticated_client chat

# Run simple test client
run-test-client: simple_test_client
	./simple_test_client

.PHONY: all clean run-server-basic run-server-chat run-auth-client-basic run-auth-client-chat run-test-client 