#!/bin/bash

# Simple Authentication Test Script
# Tests login for 20 users from decrypted_users.txt

SERVER_IP=${1:-127.0.0.1}
PORT=12345
USER_FILE="decrypted_users.txt"
LOG_FILE="auth_test_$(date +%Y%m%d_%H%M%S).log"
MAX_USERS=20

echo "=== Simple Authentication Test ==="
echo "Server: $SERVER_IP:$PORT"
echo "User file: $USER_FILE"
echo "Max users: $MAX_USERS"
echo "Log file: $LOG_FILE"
echo "=================================="

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to test connection for a user
test_user_connection() {
    local username="$1"
    local user_id="$2"
    
    log_message "Testing connection for user: $username (ID: $user_id)"
    
    # Generate RSA keys if they don't exist
    local key_file="RSAkeys/client_${username}_private.pem"
    local cert_file="RSAkeys/client_${username}_cert.pem"
    
    if [ ! -f "$key_file" ] || [ ! -f "$cert_file" ]; then
        log_message "Generating RSA keys for user: $username"
        ./generate_rsa_keys client "$username" >/dev/null 2>&1
        if [ $? -ne 0 ]; then
            log_message "ERROR: Failed to generate RSA keys for $username"
            return 1
        fi
    fi
    
    # Test basic connection (without full client interaction)
    timeout 10 bash -c "
        # Create a simple test connection
        exec 3<>/dev/tcp/$SERVER_IP/$PORT
        if [ \$? -eq 0 ]; then
            echo 'Connection established for $username'
            exec 3<&-
            exit 0
        else
            echo 'Connection failed for $username'
            exit 1
        fi
    " >/dev/null 2>&1
    
    local result=$?
    if [ $result -eq 0 ]; then
        log_message "SUCCESS: Connection test passed for $username"
        return 0
    else
        log_message "FAILED: Connection test failed for $username"
        return 1
    fi
}

# Check if server is running
log_message "Checking if server is running..."
if ! pgrep -f "unified_server" >/dev/null; then
    log_message "ERROR: Server is not running. Please start the server first."
    exit 1
fi

log_message "Server is running. Starting authentication test..."

# Read user file and extract users
if [ ! -f "$USER_FILE" ]; then
    log_message "ERROR: User file $USER_FILE not found"
    exit 1
fi

# Read first 20 users from the file
users=()
user_count=0

while IFS= read -r line && [ $user_count -lt $MAX_USERS ]; do
    if [[ "$line" =~ ^[0-9]+: ]]; then
        username=$(echo "$line" | cut -d':' -f2)
        user_id=$(echo "$line" | cut -d':' -f1)
        
        users+=("$username:$user_id")
        ((user_count++))
    fi
done < "$USER_FILE"

log_message "Found $user_count users to test"

# Test connection for each user
success_count=0
fail_count=0

for user_info in "${users[@]}"; do
    IFS=':' read -r username user_id <<< "$user_info"
    
    test_user_connection "$username" "$user_id"
    if [ $? -eq 0 ]; then
        ((success_count++))
    else
        ((fail_count++))
    fi
    
    # Small delay between tests
    sleep 0.2
done

# Generate summary report
log_message "=== AUTHENTICATION TEST SUMMARY ==="
log_message "Total users tested: $user_count"
log_message "Successful connections: $success_count"
log_message "Failed connections: $fail_count"
log_message "Success rate: $((success_count * 100 / user_count))%"

# Check server status after test
if pgrep -f "unified_server" >/dev/null; then
    log_message "Server is still running after test"
else
    log_message "WARNING: Server crashed during test!"
fi

# Check current connections
current_connections=$(netstat -an | grep ":$PORT" | wc -l)
log_message "Current connections to server: $current_connections"

echo ""
echo "=== Test Complete ==="
echo "Check $LOG_FILE for detailed results"
echo "Successful connections: $success_count/$user_count"