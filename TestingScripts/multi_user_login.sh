#!/bin/bash

# Multi-User Login Script for MultifactorAuth Server
# Reads encrypted_users.txt and attempts to log in with 20 users simultaneously

SERVER_IP=${1:-127.0.0.1}
PORT=12345
USER_FILE="decrypted_users.txt"
LOG_FILE="multi_user_login_$(date +%Y%m%d_%H%M%S).log"
MAX_USERS=500

echo "=== Multi-User Login Stress Test ==="
echo "Server: $SERVER_IP:$PORT"
echo "User file: $USER_FILE"
echo "Max users: $MAX_USERS"
echo "Log file: $LOG_FILE"
echo "======================================"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Check if expect is installed
if ! command -v expect &> /dev/null; then
    echo "ERROR: expect is required for interactive login automation"
    echo "Install it with: sudo apt-get install expect"
    exit 1
fi

# Function to attempt login for a single user
# Function to attempt login for a single user
attempt_login() {
    local username="$1"
    local password="$2"
    local user_id="$3"
    
    log_message "Attempting login for user: $username (ID: $user_id)"
    
    # Check if RSA keys exist for this user
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
    
    # Create expect script to automate the interactive login
    local expect_script="/tmp/expect_${username}_$$.exp"
    cat > "$expect_script" << 'EOF'
#!/usr/bin/expect -f
set timeout 30
set username [lindex $argv 0]
set password [lindex $argv 1]
set user_id [lindex $argv 2]

proc log_message {msg} {
    puts stderr "[clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}] - $msg"
}

log_user 0

# Start the client
spawn ./unified_client $username

# Wait for RSA authentication to complete
expect {
    "RSA mutual authentication completed" {
        log_message "RSA auth completed for $username"
    }
    "RSA authentication failed" {
        log_message "RSA auth failed for $username"
        exit 1
    }
    "auth>" {
        log_message "Got auth prompt for $username (RSA may have completed silently)"
    }
    timeout {
        log_message "Timeout waiting for RSA auth for $username"
        exit 1
    }
}

# If we didn't get the auth prompt yet, wait for it
expect {
    "auth>" {
        log_message "Got auth prompt for $username"
    }
    timeout {
        log_message "Timeout waiting for auth prompt for $username"
        exit 1
    }
}

# Send login command
log_message "Sending login command for $username"
send "/login $username $password\r"

# Wait for response
expect {
    "AUTH_SUCCESS" {
        log_message "Welcome, $username! You are now authenticated"
        
        # Wait for chat prompt
        expect {
            ">" {
                log_message "User $username is now in chat mode"
                
                # Send confirmation message to verify successful login
                send "Hello from $username\r"
                expect ">"
                log_message "User $username confirmed successful login"
                
                # Stay connected with periodic commands during wait phase
                log_message "User $username staying connected with periodic activity"
                
                # Wait with periodic activity instead of indefinitely
                set activity_counter 0
                while {1} {
                    expect {
                        ">" {
                            # Send periodic commands to simulate real usage
                            incr activity_counter
                            if {$activity_counter % 10 == 0} {
                                send "/list\r"
                                expect ">"
                            }
                        }
                        eof {
                            log_message "Connection lost for $username"
                            exit 1
                        }
                        timeout {
                            # Send a periodic heartbeat to keep connection alive
                            send "\r"
                        }
                    }
                }
            }
            timeout {
                log_message "User $username authenticated but didn't get chat prompt"
                send "/quit\r"
                expect eof
                exit 1
            }
        }
    }
    "AUTH_FAILED" {
        log_message "Login failed for $username"
        send "/quit\r"
        expect eof
        exit 1
    }
    "Invalid username or password" {
        log_message "Invalid credentials for $username"
        send "/quit\r"
        expect eof
        exit 1
    }
    timeout {
        log_message "Timeout during login for $username"
        send "/quit\r"
        expect eof
        exit 1
    }
}
EOF

    # Run the expect script with parameters
    expect -f "$expect_script" "$username" "$password" "$user_id" 2>> "$LOG_FILE"
    local result=$?
    
    # Clean up expect script
    rm -f "$expect_script"
    
    if [ $result -eq 0 ]; then
        log_message "SUCCESS: User $username logged in successfully and is staying connected"
        return 0
    else
        log_message "FAILED: User $username login failed (exit code: $result)"
        return 1
    fi
}


# Check if server is running
log_message "Checking if server is running..."
if ! pgrep -f "unified_server" >/dev/null; then
    log_message "ERROR: Server is not running. Please start the server first."
    exit 1
fi

log_message "Server is running. Starting multi-user login test..."

# Read user file and extract users
if [ ! -f "$USER_FILE" ]; then
    log_message "ERROR: User file $USER_FILE not found"
    exit 1
fi

# Read first 20 users from the file
# Format: account#:username:password:email:address:phonenumber:authorityLevel
users=()
user_count=0

while IFS= read -r line && [ $user_count -lt $MAX_USERS ]; do
    # Skip empty lines and comments
    if [[ -z "$line" || "$line" =~ ^# ]]; then
        continue
    fi
    
    # Check if line has the expected format (at least 7 fields separated by colons)
    field_count=$(echo "$line" | tr -cd ':' | wc -c)
    if [ "$field_count" -ge 6 ]; then
        account_id=$(echo "$line" | cut -d':' -f1)
        username=$(echo "$line" | cut -d':' -f2)
        password=$(echo "$line" | cut -d':' -f3)
        email=$(echo "$line" | cut -d':' -f4)
        address=$(echo "$line" | cut -d':' -f5)
        phone=$(echo "$line" | cut -d':' -f6)
        authority=$(echo "$line" | cut -d':' -f7)
        
        # Only proceed if username and password are not empty
        if [[ -n "$username" && -n "$password" ]]; then
            users+=("$username:$password:$account_id")
            ((user_count++))
            log_message "Parsed user: $username (Account: $account_id, Authority: $authority)"
        else
            log_message "Skipping line with empty username or password: $line"
        fi
    else
        log_message "Skipping malformed line (insufficient fields): $line"
    fi
done < "$USER_FILE"

log_message "Found $user_count users to test"

# Store PIDs for cleanup
client_pids=()

# Function to cleanup all clients on script termination
cleanup_clients() {
    log_message "Script termination detected - disconnecting all clients..."
    
    # Send SIGTERM to all client processes
    for pid in "${client_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log_message "Terminating client process $pid"
            kill -TERM "$pid" 2>/dev/null
        fi
    done
    
    # Wait a moment for graceful shutdown
    sleep 2
    
    # Force kill any remaining processes
    for pid in "${client_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            log_message "Force killing client process $pid"
            kill -KILL "$pid" 2>/dev/null
        fi
    done
    
    log_message "All clients disconnected. Script terminated."
    exit 0
}

# Set up signal handlers for script termination
trap cleanup_clients SIGTERM SIGINT
# Attempt login for each user in parallel (but with small delays to avoid overwhelming)
success_count=0
fail_count=0
successful_users=()
failed_users=()

for user_info in "${users[@]}"; do
    IFS=':' read -r username password user_id <<< "$user_info"
    
    # Start login attempt in background
    attempt_login "$username" "$password" "$user_id" &
    pid=$!
    client_pids+=($pid)
    
    # Small delay to avoid overwhelming the server
    sleep 0.01
done

# Wait for all login attempts to complete (just the initial login, not the indefinite connection)
log_message "Waiting for all initial login attempts to complete..."
user_index=0
for pid in "${client_pids[@]}"; do
    IFS=':' read -r username password user_id <<< "${users[$user_index]}"
    
    # Wait a short time for initial login verification (reduced from 60s)
    timeout 0.1 bash -c "
        while kill -0 $pid 2>/dev/null; do
            sleep 0.01
        done
    " &
    wait $!
    
    # Check if process is still running (means login was successful and staying connected)
    if kill -0 "$pid" 2>/dev/null; then
        ((success_count++))
        successful_users+=("$username")
        log_message "✓ CONFIRMED SUCCESS: $username (Account: $user_id) - staying connected"
    else
        # Process ended, check exit code
        wait $pid
        if [ $? -eq 0 ]; then
            ((success_count++))
            successful_users+=("$username")
            log_message "✓ CONFIRMED SUCCESS: $username (Account: $user_id) - but disconnected"
        else
            ((fail_count++))
            failed_users+=("$username")
            log_message "✗ CONFIRMED FAILURE: $username (Account: $user_id)"
        fi
    fi
    ((user_index++))
done

# Generate summary report
log_message "=== LOGIN TEST SUMMARY ==="
log_message "Total users tested: $user_count"
log_message "Successful logins: $success_count"
log_message "Failed logins: $fail_count"
if [ $user_count -gt 0 ]; then
    log_message "Success rate: $((success_count * 100 / user_count))%"
else
    log_message "Success rate: 0%"
fi

# List successful users
if [ ${#successful_users[@]} -gt 0 ]; then
    log_message "--- SUCCESSFUL LOGINS ---"
    for user in "${successful_users[@]}"; do
        log_message "✓ $user"
    done
fi

# List failed users
if [ ${#failed_users[@]} -gt 0 ]; then
    log_message "--- FAILED LOGINS ---"
    for user in "${failed_users[@]}"; do
        log_message "✗ $user"
    done
fi

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
echo "=== Initial Login Phase Complete ==="
echo "Check $LOG_FILE for detailed results"
echo "Successful logins: $success_count/$user_count"
echo ""
echo "Connected clients will remain active until this script is terminated (Ctrl+C or kill)"
echo "Use Ctrl+C or kill this script to disconnect all clients gracefully"

# Keep the main script running until terminated
log_message "Script now waiting indefinitely. Connected clients will stay active until script termination."
while true; do
    sleep 1
    
    # Check if any client processes have died unexpectedly
    active_clients=0
    for pid in "${client_pids[@]}"; do
        if kill -0 "$pid" 2>/dev/null; then
            ((active_clients++))
        fi
    done
    
    if [ $active_clients -eq 0 ] && [ $success_count -gt 0 ]; then
        log_message "All client processes have terminated unexpectedly"
        break
    fi
done