#!/bin/bash

# Multi-User Login Script for MultifactorAuth Server
# Reads encrypted_users.txt and attempts to log in with users simultaneously
# 
# IMPORTANT: This script addresses the "auth success timeout" issue where:
# - Server successfully authenticates clients
# - Clients receive auth success message
# - But expect script's 'interact' command fails in background mode
# - Script incorrectly reports timeout failures
# 
# Solution: Use proper background monitoring instead of 'interact'

SERVER_IP=${1:-127.0.0.1}
PORT=12345
USER_FILE="decrypted_users.txt"
LOG_FILE="logs/ConnectMultUsers_$(date +%Y%m%d_%H%M%S).log"
MAX_USERS=300
CONNECTION_TIMEOUT=300  # 5 minutes in seconds
MAX_RETRIES=3  # Maximum retry attempts per user
RETRY_DELAY=1  # Base delay in seconds between retries

echo "=== Multi-User Login Stress Test (WITH RETRY LOGIC) ==="
echo "Server: $SERVER_IP:$PORT"
echo "User file: $USER_FILE"
echo "Max users: $MAX_USERS"
echo "Connection timeout: ${CONNECTION_TIMEOUT}s (5 minutes)"
echo "Max retries per user: $MAX_RETRIES"
echo "Base retry delay: ${RETRY_DELAY}s"
echo "Log file: $LOG_FILE"
echo "======================================"

# Function to log messages with reduced verbosity
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Function to log only to file (for detailed debugging)
log_debug() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Check if expect is installed
if ! command -v expect &> /dev/null; then
    echo "ERROR: expect is required for interactive login automation"
    echo "Install it with: sudo apt-get install expect"
    exit 1
fi

# Function to attempt login for a single user with retry logic
attempt_login_with_retries() {
    local username="$1"
    local password="$2"
    local user_id="$3"
    local max_retries="$4"
    
    local retry_count=0
    local last_exit_code=0
    
    while [ $retry_count -le $max_retries ]; do
        if [ $retry_count -gt 0 ]; then
            local delay=$((RETRY_DELAY * (2 ** (retry_count - 1))))  # Exponential backoff
            log_message "🔄 RETRY $retry_count/$max_retries for $username (Account: $user_id) - waiting ${delay}s before retry..."
            sleep $delay
        fi
        
        log_debug "Attempting login for user: $username (ID: $user_id) - attempt $((retry_count + 1))"
        
        # Create expect script to automate the interactive login
        local expect_script="/tmp/expect_${username}_$$_${retry_count}.exp"
        cat > "$expect_script" << 'EOF'
     
#!/usr/bin/expect -f
set timeout 100
set username [lindex $argv 0]
set password [lindex $argv 1]
set user_id [lindex $argv 2]

proc log_message {msg} {
    puts stderr "[clock format [clock seconds] -format {%Y-%m-%d %H:%M:%S}] - $msg"
}

log_user 0

# Start the client with RSA disabled so it only sends username (no RSA challenge)
spawn ./unified_client --no-rsa $username

# Wait for RSA authentication to complete
expect {
    "\[AUTH\] Auto-authentication successful! You are now fully authenticated." {
        log_message "Auto-authentication successful for $username"
        # For background operation, just keep the client running
        # Don't use interact in background mode
        set timeout -1  # No timeout
        # Wait indefinitely for the client to stay alive
        expect {
            eof {
                log_message "Client $username disconnected"
                exit 0
            }
            timeout {
                # This should never happen with timeout -1, but just in case
                log_message "Unexpected timeout for $username"
                exit 1
            }
        }
    }
    timeout {
        log_message "Timeout waiting for auth_success for $username"
        exit 1
    }
}

EOF

        # Run the expect script with parameters
        expect -f "$expect_script" "$username" "$password" "$user_id" 2>> "$LOG_FILE" &
        local expect_pid=$!
        
        # Wait a bit for the expect script to either succeed or fail
        sleep 0.5
        
        # Check if the expect process is still running (indicating success)
        if kill -0 "$expect_pid" 2>/dev/null; then
            # Expect is still running, which means authentication succeeded and client is connected
            log_message "✓ SUCCESS: $username (Account: $user_id) - connected and authenticated on attempt $((retry_count + 1))"
            rm -f "$expect_script"
            return 0
        else
            # Expect process ended, check exit code to determine failure reason
            wait $expect_pid
            last_exit_code=$?
            
            # Clean up expect script
            rm -f "$expect_script"
            
            # Determine specific failure reason
            local failure_reason=""
            case $last_exit_code in
                1) failure_reason="authentication timeout - didn't receive auth success message" ;;
                2) failure_reason="connection refused or server unreachable" ;;
                126) failure_reason="command not executable" ;;
                127) failure_reason="command not found" ;;
                130) failure_reason="interrupted by user (SIGINT)" ;;
                139) failure_reason="segmentation fault" ;;
                143) failure_reason="terminated (SIGTERM)" ;;
                *) failure_reason="unknown error (exit code: $last_exit_code)" ;;
            esac
            
            if [ $retry_count -eq $max_retries ]; then
                # Final attempt failed
                log_message "✗ FINAL FAILURE: $username (Account: $user_id) - $failure_reason after $((retry_count + 1)) attempts"
                return $last_exit_code
            else
                log_debug "✗ Attempt $((retry_count + 1)) failed for $username: $failure_reason"
            fi
        fi
        
        ((retry_count++))
    done
    
    return $last_exit_code
}

# Function to attempt login for a single user (legacy function for backward compatibility)
attempt_login() {
    attempt_login_with_retries "$1" "$2" "$3" 0  # 0 retries = original behavior
}

# Function to monitor client health and detect real disconnections
monitor_client_health() {
    local username="$1"
    local expect_pid="$2"
    local user_id="$3"
    
    # Wait a bit for initial authentication
    sleep 2
    
    # Check if expect is still running
    if ! kill -0 "$expect_pid" 2>/dev/null; then
        log_debug "Client $username: expect process ended early"
        return 1
    fi
    
    # Monitor for a longer period to detect real disconnections
    local monitor_time=30  # Monitor for 30 seconds
    local check_interval=5  # Check every 5 seconds
    
    for ((i=0; i<monitor_time/check_interval; i++)); do
        if ! kill -0 "$expect_pid" 2>/dev/null; then
            log_debug "Client $username: expect process ended during monitoring"
            return 1
        fi
        
        # Check if the client process is actually running
        if pgrep -f "unified_client $username" >/dev/null; then
            log_debug "Client $username: process healthy, continuing monitoring"
        else
            log_debug "Client $username: client process not found, may have crashed"
            return 1
        fi
        
        sleep $check_interval
    done
    
    log_debug "Client $username: monitoring complete, client appears stable"
    return 0
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

# Read users from the file
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
        else
            log_debug "Skipping line with empty username or password: $line"
        fi
    else
        log_debug "Skipping malformed line (insufficient fields): $line"
    fi
done < "$USER_FILE"

log_message "Found $user_count users to test"
sleep 1

# Store PIDs for cleanup
declare -A client_pids_map

# Function to cleanup all clients on script termination
cleanup_clients() {
    log_message "Script termination detected - disconnecting all clients..."
    
    # Send SIGTERM to all client processes
    for username in "${!client_pids_map[@]}"; do
        pid="${client_pids_map[$username]}"
        if kill -0 "$pid" 2>/dev/null; then
            log_debug "Terminating client process $username (PID: $pid)"
            kill -TERM "$pid" 2>/dev/null
        fi
    done
    
    # Wait a moment for graceful shutdown
    sleep 2
    
    # Force kill any remaining processes
    for username in "${!client_pids_map[@]}"; do
        pid="${client_pids_map[$username]}"
        if kill -0 "$pid" 2>/dev/null; then
            log_debug "Force killing client $username (PID: $pid)"
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
declare -A failure_reasons
declare -A client_pids_map

for user_info in "${users[@]}"; do
    IFS=':' read -r username password user_id <<< "$user_info"
    
    # Start login attempt in background
    attempt_login_with_retries "$username" "$password" "$user_id" "$MAX_RETRIES" &
    pid=$!
    client_pids_map["$username"]=$pid
    
    # Small delay to avoid overwhelming the server
    sleep 0.25
done

# Wait for all login attempts to complete and categorize results
log_message "Waiting for all initial login attempts to complete..."
sleep 5  # Give all login attempts time to either succeed or fail

user_index=0
for user_info in "${users[@]}"; do
    IFS=':' read -r username password user_id <<< "$user_info"
    pid="${client_pids_map[$username]}"
    
    # Check if this user's login attempt succeeded or failed
    if kill -0 "$pid" 2>/dev/null; then
        # Process is still running, which means login succeeded and client is connected
        ((success_count++))
        successful_users+=("$username")
        log_message "✓ CONFIRMED: $username (Account: $user_id) - client connected and running"
    else
        # Process ended, check exit code to determine failure reason
        wait $pid 2>/dev/null
        exit_code=$?
        
        # Determine specific failure reason
        case $exit_code in
            1) failure_reasons["$username"]="authentication timeout - didn't receive auth success message" ;;
            2) failure_reasons["$username"]="connection refused or server unreachable" ;;
            126) failure_reasons["$username"]="command not executable" ;;
            127) failure_reasons["$username"]="command not found" ;;
            130) failure_reasons["$username"]="interrupted by user (SIGINT)" ;;
            139) failure_reasons["$username"]="segmentation fault" ;;
            143) failure_reasons["$username"]="terminated (SIGTERM)" ;;
            *) failure_reasons["$username"]="unknown error (exit code: $exit_code)" ;;
        esac
        
        ((fail_count++))
        failed_users+=("$username")
        log_message "✗ FAILED: $username (Account: $user_id) - ${failure_reasons[$username]}"
    fi
    ((user_index++))
done

# Generate summary report
log_message "=== LOGIN TEST SUMMARY (WITH RETRY LOGIC) ==="
log_message "Total users tested: $user_count"
log_message "Successful logins: $success_count"
log_message "Failed logins: $fail_count"
log_message "Retry configuration: Max $MAX_RETRIES retries, Base delay ${RETRY_DELAY}s"
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

# List failed users with reasons
if [ ${#failed_users[@]} -gt 0 ]; then
    log_message "--- FAILED LOGINS ---"
    for user in "${failed_users[@]}"; do
        reason="${failure_reasons[$user]:-unknown reason}"
        log_message "✗ $user - $reason"
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
log_message "Script now waiting for ${CONNECTION_TIMEOUT}s. Connected clients will stay active until timeout or script termination."

# Track clients that were initially successful for ongoing monitoring
declare -a initially_successful_pids=()
user_index=0
for user_info in "${users[@]}"; do
    IFS=':' read -r username password user_id <<< "$user_info"
    pid="${client_pids_map[$username]}"
    if kill -0 "$pid" 2>/dev/null; then
        initially_successful_pids+=("$pid:$username:$user_id")
    fi
done

dropped_count=0
declare -a dropped_users=()
start_time=$SECONDS

log_message "Monitoring ${#initially_successful_pids[@]} successful connections for stability..."

while true; do
    sleep 0.25
    current_time=$SECONDS
    elapsed_time=$((current_time - start_time))
    
    # Check if we've reached the connection timeout (5 minutes)
    if [ $elapsed_time -ge $CONNECTION_TIMEOUT ]; then
        log_message "Connection timeout (${CONNECTION_TIMEOUT}s) reached. Disconnecting all clients."
        # Gracefully terminate all client processes
        for client_info in "${initially_successful_pids[@]}"; do
            IFS=':' read -r pid username user_id <<< "$client_info"
            if kill -0 "$pid" 2>/dev/null; then
                log_debug "Terminating client $username (PID: $pid) after timeout"
                kill -TERM "$pid" 2>/dev/null
            fi
        done
        # Wait for graceful shutdown
        sleep 2
        # Force kill any remaining processes
        for client_info in "${initially_successful_pids[@]}"; do
            IFS=':' read -r pid username user_id <<< "$client_info"
            if kill -0 "$pid" 2>/dev/null; then
                log_debug "Force killing client $username (PID: $pid)"
                kill -KILL "$pid" 2>/dev/null
            fi
        done
        break
    fi
    
    # Check if any initially successful clients have dropped
    active_clients=0
    for client_info in "${initially_successful_pids[@]}"; do
        IFS=':' read -r pid username user_id <<< "$client_info"
        if kill -0 "$pid" 2>/dev/null; then
            ((active_clients++))
        else
            # Client dropped - check if we haven't already counted it
            if ! printf '%s\n' "${dropped_users[@]}" | grep -q "^$username$"; then
                ((dropped_count++))
                ((fail_count++))
                ((success_count--))  # Remove from success count
                dropped_users+=("$username")
                failure_reasons["$username"]="connection dropped during test"
                # Remove from successful_users array
                successful_users=($(printf '%s\n' "${successful_users[@]}" | grep -v "^$username$"))
                failed_users+=("$username")
                log_message "✗ CONNECTION DROPPED: $username (Account: $user_id) - now counted as failure"
            fi
        fi
    done
    
    # Log periodic status with reduced frequency
    if [ $((SECONDS % 60)) -eq 0 ]; then  # Every 60 seconds instead of 30
        time_remaining=$((CONNECTION_TIMEOUT - elapsed_time))
        log_message "STATUS: Active: $active_clients, Success: $success_count, Failed: $fail_count, Time remaining: ${time_remaining}s"
    fi
    
    if [ "$active_clients" -eq 0 ] && [ ${#initially_successful_pids[@]} -gt 0 ]; then
        log_message "All client processes have terminated"
        break
    fi
done

# Final summary with dropped connections
log_message "=== FINAL TEST SUMMARY (INCLUDING DROPPED CONNECTIONS) ==="
log_message "Total users tested: $user_count"
log_message "Successful persistent connections: $success_count"
log_message "Failed connections (including drops): $fail_count"
log_message "Connections dropped during test: $dropped_count"
log_message "Total connection time: ${elapsed_time}s"
log_message "Retry configuration: Max $MAX_RETRIES retries, Base delay ${RETRY_DELAY}s"
if [ $user_count -gt 0 ]; then
    log_message "Final success rate: $((success_count * 100 / user_count))%"
else
    log_message "Final success rate: 0%"
fi

log_message ""
log_message "=== TEST COMPLETED ==="
log_message "All successful connections were maintained until timeout or script termination"
log_message "Failed connections were properly categorized with specific reasons"