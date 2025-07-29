# Simplified Makefile for TCP Server/Client Project (Linux)
CC = clang
CFLAGS = -Wall -Wextra -std=c17 -pthread -D_POSIX_C_SOURCE=200809L
LIBS = -lssl -lcrypto -lcurl

# Object files
OBJS = encryptionTools.o auth_system.o fileOperations.o config_parser.o

# Targets
all: unified_server unified_client encryptionTools_test user_encryptor generate_rsa_keys email_config_manager emailTest

# Object file rules with header dependencies
encryptionTools.o: decryptionFunctions/encryptionTools.c decryptionFunctions/encryptionTools.h
	$(CC) $(CFLAGS) -c $< -o $@

auth_system.o: auth_system.c
	$(CC) $(CFLAGS) -c $< -o $@

fileOperations.o: fileOperations.c fileOperations.h
	$(CC) $(CFLAGS) -c $< -o $@



config_parser.o: config_parser.c config_parser.h
	$(CC) $(CFLAGS) -c $< -o $@



# Standalone encryption tools test executable
encryptionTools_test: decryptionFunctions/encryptionTools.c decryptionFunctions/encryptionTools.h
	$(CC) $(CFLAGS) -DTEST_MAIN -o $@ $< $(LIBS)

# Standalone file encryption/decryption tool
user_encryptor: userEncryptionTools/user_encryptor.c
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

# Server with authentication (uses object files)
unified_server: unified_server.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Unified client with authentication support (includes RSA authentication)
unified_client: unified_client.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# RSA key generator utility
generate_rsa_keys: generate_rsa_keys.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)



# Email configuration manager
email_config_manager: email_config_manager.c config_parser.o
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

# Email test
emailTest: emailTest.c
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)




# Clean
clean:
	rm -f unified_server unified_client encryptionTools_test user_encryptor generate_rsa_keys test_email_service email_config_manager $(OBJS) *.pem

.PHONY: all clean 