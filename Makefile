# Simplified Makefile for TCP Server/Client Project
CC = gcc
CFLAGS = -Wall -Wextra -std=c99
LIBS = -lws2_32

# Targets
all: unified_server.exe unified_client.exe simple_test_client.exe

# Unified server (supports both basic and chat modes)
unified_server.exe: unified_server.c
	$(CC) $(CFLAGS) -o unified_server.exe unified_server.c $(LIBS)

# Unified client (supports both basic and chat modes)
unified_client.exe: unified_client.c
	$(CC) $(CFLAGS) -o unified_client.exe unified_client.c $(LIBS)

# Simple test client
simple_test_client.exe: simple_test_client.c
	$(CC) $(CFLAGS) -o simple_test_client.exe simple_test_client.c $(LIBS)

# Clean build files
clean:
	rm *.exe

# Run basic server
run-basic-server: unified_server.exe
	unified_server.exe basic

# Run chat server
run-chat-server: unified_server.exe
	unified_server.exe chat

# Run basic client
run-basic-client: unified_client.exe
	unified_client.exe basic

# Run chat client
run-chat-client: unified_client.exe
	unified_client.exe chat

# Run test client
run-test: simple_test_client.exe
	simple_test_client.exe

# Help
help:
	@echo "Available targets:"
	@echo "  all                    - Build all executables"
	@echo "  unified_server.exe     - Build unified server"
	@echo "  unified_client.exe     - Build unified client"
	@echo "  simple_test_client.exe - Build test client"
	@echo "  clean                  - Remove all executables"
	@echo "  run-basic-server       - Run server in basic mode"
	@echo "  run-chat-server        - Run server in chat mode"
	@echo "  run-basic-client       - Run client in basic mode"
	@echo "  run-chat-client        - Run client in chat mode"
	@echo "  run-test               - Run test client"
	@echo ""
	@echo "Usage examples:"
	@echo "  make run-chat-server   # Start chat server"
	@echo "  make run-chat-client   # Start chat client (in another terminal)"
	@echo "  make run-basic-server  # Start basic echo server"
	@echo "  make run-test          # Test the server"

.PHONY: all clean run-basic-server run-chat-server run-basic-client run-chat-client run-test help 