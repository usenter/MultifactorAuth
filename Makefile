# Simplified Makefile for TCP Server/Client Project
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lws2_32

# Targets
all: unified_server.exe unified_client.exe authenticated_client.exe

# Server with authentication
unified_server.exe: unified_server.c auth_system.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Original client (without authentication)
unified_client.exe: unified_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# New authenticated client
authenticated_client.exe: authenticated_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Clean
clean:
	del *.exe

# Run server in basic mode
run-server-basic: unified_server.exe
	./unified_server.exe basic

# Run server in chat mode
run-server-chat: unified_server.exe
	./unified_server.exe chat

# Run authenticated client in basic mode
run-auth-client-basic: authenticated_client.exe
	./authenticated_client.exe basic

# Run authenticated client in chat mode
run-auth-client-chat: authenticated_client.exe
	./authenticated_client.exe chat

.PHONY: all clean run-server-basic run-server-chat run-auth-client-basic run-auth-client-chat 