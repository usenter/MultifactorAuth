#!/bin/bash

# Real-time Stress Test Monitoring Script
# Usage: ./monitor_stress_test.sh [duration_seconds]

DURATION=${1:-60}
LOG_FILE="stress_test_$(date +%Y%m%d_%H%M%S).log"
SERVER_PID=$(pgrep unified_server)
PORT=12345

echo "=== Real-time Stress Test Monitoring ==="
echo "Duration: $DURATION seconds"
echo "Log file: $LOG_FILE"
echo "Server PID: $SERVER_PID"
echo "======================================"

# Function to log metrics
log_metric() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Start monitoring
log_metric "=== STRESS TEST MONITORING STARTED ==="

# Monitor for specified duration
for i in $(seq 1 $DURATION); do
    # Server status
    if [ -n "$SERVER_PID" ] && kill -0 $SERVER_PID 2>/dev/null; then
        SERVER_STATUS="RUNNING"
        CPU_USAGE=$(ps -p $SERVER_PID -o pcpu --no-headers 2>/dev/null || echo "0")
        MEMORY_USAGE=$(ps -p $SERVER_PID -o pmem --no-headers 2>/dev/null || echo "0")
        THREAD_COUNT=$(ls /proc/$SERVER_PID/task/ 2>/dev/null | wc -l || echo "0")
    else
        SERVER_STATUS="CRASHED"
        CPU_USAGE="0"
        MEMORY_USAGE="0"
        THREAD_COUNT="0"
    fi
    
    # Network connections
    CONNECTION_COUNT=$(netstat -an | grep ":$PORT" | wc -l)
    
    # System resources
    SYSTEM_CPU=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    SYSTEM_MEMORY=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
    
    # Log all metrics
    log_metric "SECOND $i - Server: $SERVER_STATUS, CPU: ${CPU_USAGE}%, MEM: ${MEMORY_USAGE}%, Threads: $THREAD_COUNT, Connections: $CONNECTION_COUNT, System CPU: ${SYSTEM_CPU}%, System MEM: ${SYSTEM_MEMORY}%"
    
    # Alert on critical conditions
    if [ "$SERVER_STATUS" = "CRASHED" ]; then
        log_metric "🚨 CRITICAL: Server crashed!"
    fi
    
    if (( $(echo "$CPU_USAGE > 90" | bc -l 2>/dev/null) )); then
        log_metric "⚠️  WARNING: High CPU usage: ${CPU_USAGE}%"
    fi
    
    if (( $(echo "$MEMORY_USAGE > 20" | bc -l 2>/dev/null) )); then
        log_metric "⚠️  WARNING: High memory usage: ${MEMORY_USAGE}%"
    fi
    
    if [ "$CONNECTION_COUNT" -gt 25 ]; then
        log_metric "⚠️  WARNING: High connection count: $CONNECTION_COUNT"
    fi
    
    sleep 1
done

log_metric "=== STRESS TEST MONITORING COMPLETED ==="

echo ""
echo "📊 Monitoring completed. Check $LOG_FILE for detailed metrics."
echo "Run ./evaluate_stress_test.sh for final analysis."