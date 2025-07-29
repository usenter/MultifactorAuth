#!/bin/bash

# Stress Test Evaluation Script
# Usage: ./evaluate_stress_test.sh [server_pid]

SERVER_PID=${1:-$(pgrep unified_server)}
PORT=12345

echo "=== Stress Test Evaluation Report ==="
echo "Server PID: $SERVER_PID"
echo "Port: $PORT"
echo "Timestamp: $(date)"
echo "====================================="

# 1. Server Process Analysis
echo ""
echo "1. SERVER PROCESS ANALYSIS"
echo "=========================="
if [ -n "$SERVER_PID" ]; then
    echo "Server Status: RUNNING (PID: $SERVER_PID)"
    echo "Process Info:"
    ps -p $SERVER_PID -o pid,ppid,cmd,pcpu,pmem,etime
else
    echo "Server Status: NOT RUNNING"
    echo "WARNING: Server may have crashed during stress test!"
fi

# 2. Memory Usage Analysis
echo ""
echo "2. MEMORY USAGE ANALYSIS"
echo "========================"
if [ -n "$SERVER_PID" ]; then
    echo "Current Memory Usage:"
    ps -p $SERVER_PID -o pid,vsz,rss,pmem --no-headers | awk '{print "Virtual Memory:", $2 " KB", "RSS:", $3 " KB", "Memory %:", $4 "%"}'
    
    # Check for memory leaks (if we have historical data)
    echo ""
    echo "Memory Trend (if available):"
    # This would need to be enhanced with actual monitoring data
    echo "Note: Install monitoring tools for detailed memory analysis"
fi

# 3. Network Connection Analysis
echo ""
echo "3. NETWORK CONNECTION ANALYSIS"
echo "=============================="
echo "Active connections to port $PORT:"
netstat -an | grep ":$PORT" | wc -l | awk '{print "Total connections:", $1}'

echo ""
echo "Connection states:"
netstat -an | grep ":$PORT" | awk '{print $6}' | sort | uniq -c

# 4. System Resource Analysis
echo ""
echo "4. SYSTEM RESOURCE ANALYSIS"
echo "==========================="
echo "CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print "CPU Load:", $2}'

echo ""
echo "Memory Usage:"
free -h | grep "Mem:" | awk '{print "Total:", $2, "Used:", $3, "Free:", $4}'

# 5. Error Analysis
echo ""
echo "5. ERROR ANALYSIS"
echo "================"
echo "Recent system errors:"
dmesg | tail -10 | grep -i error

echo ""
echo "Network errors:"
journalctl --since "5 minutes ago" | grep -i "network\|connection\|error" | tail -5

# 6. Performance Metrics
echo ""
echo "6. PERFORMANCE METRICS"
echo "======================"
if [ -n "$SERVER_PID" ]; then
    echo "Server uptime:"
    ps -p $SERVER_PID -o etime --no-headers
    
    echo ""
    echo "Thread count:"
    ls /proc/$SERVER_PID/task/ 2>/dev/null | wc -l | awk '{print "Active threads:", $1}'
fi

# 7. Recommendations
echo ""
echo "7. RECOMMENDATIONS"
echo "=================="
if [ -n "$SERVER_PID" ]; then
    MEMORY_USAGE=$(ps -p $SERVER_PID -o pmem --no-headers)
    if (( $(echo "$MEMORY_USAGE > 10" | bc -l) )); then
        echo "⚠️  HIGH MEMORY USAGE: Consider optimizing memory allocation"
    fi
    
    CPU_USAGE=$(ps -p $SERVER_PID -o pcpu --no-headers)
    if (( $(echo "$CPU_USAGE > 80" | bc -l) )); then
        echo "⚠️  HIGH CPU USAGE: Consider optimizing algorithms or adding more cores"
    fi
else
    echo "❌ SERVER CRASHED: Investigate crash logs and fix stability issues"
fi

echo ""
echo "✅ EVALUATION COMPLETE"
echo "======================"
echo "Check the above metrics to determine:"
echo "- Server stability under load"
echo "- Memory leak detection"
echo "- CPU performance bottlenecks"
echo "- Network handling capacity"
echo "- Authentication system robustness"