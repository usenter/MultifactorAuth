#include "IPtableFunctions.h"
#include "../socketHandling/socketHandling.h"

//default values
const char *syn_rate = "1000/second";   
const int syn_burst = 2000;      // make same as syn_rate        
const int per_ip_limit = 10000;           

static int run_shell_command(const char *cmd) {
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Running shell command: %s\n", cmd);
    FILE_LOG(log_message);
    int rc = system(cmd);
    if (rc == -1) {
        FILE_LOG("[ERROR][MAIN_THREAD] system() returned -1\n");
        return -1;
    }
    if (WIFEXITED(rc)) {
        int status = WEXITSTATUS(rc);
        snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Command exit status: %d\n", status);
        FILE_LOG(log_message);
        return status;
    }
    FILE_LOG("[ERROR][MAIN_THREAD] Command did not exit normally\n");
    return -1;
}

// Remove ALL iptables rules relevant to a specific service port to avoid stacking
static void clear_iptables_rules_for_port(int service_port) {
    if (geteuid() != 0) return;
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Clearing existing iptables rules for tcp/%d (avoid stacking)\n", service_port);
    FILE_LOG(log_message);

    char cmd[512];
    
    // Remove ALL connlimit rules for this port by numeric index (descending) - IMPROVED
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Removing connlimit rules for port %d\n", service_port);
    FILE_LOG(log_message);
    snprintf(cmd, sizeof(cmd),
             "bash -c \"for n in \\$(iptables -L INPUT -n --line-numbers | awk '/REJECT.*tcp.*dpt:%d.*conn.*src/ {print \\$1}' | sort -nr); do [ -n \\\"\\$n\\\" ] && echo \\\"Removing rule \\$n\\\" && iptables -w 2 -D INPUT \\$n; done\"",
             service_port);
    run_shell_command(cmd);
    
    // Also try removing by exact pattern matching for any remaining rules
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Attempting pattern-based connlimit removal for port %d\n", service_port);
    FILE_LOG(log_message);
    for (int limit = 50; limit <= 1000; limit += 50) {
        snprintf(cmd, sizeof(cmd),
                 "iptables -w 2 -D INPUT -p tcp --dport %d -m connlimit --connlimit-above %d --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null || true",
                 service_port, limit);
        run_shell_command(cmd);
    }

    // Detach all INPUT hooks to SYN_FLOOD for this port (repeat until none)
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Removing SYN_FLOOD hooks for port %d\n", service_port);
    FILE_LOG(log_message);
    snprintf(cmd, sizeof(cmd),
             "bash -lc 'while iptables -w 2 -C INPUT -p tcp --syn --dport %d -j SYN_FLOOD 2>/dev/null; do iptables -w 2 -D INPUT -p tcp --syn --dport %d -j SYN_FLOOD; done'",
             service_port, service_port);
    run_shell_command(cmd);

    // Flush and delete custom chain if present
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Cleaning up SYN_FLOOD chain\n");
    FILE_LOG(log_message);
    run_shell_command("iptables -w 2 -F SYN_FLOOD 2>/dev/null || true");
    run_shell_command("iptables -w 2 -X SYN_FLOOD 2>/dev/null || true");

    // Verify cleanup by listing remaining rules for this port
    snprintf(log_message, sizeof(log_message), "[DEBUG][MAIN_THREAD] Verifying cleanup - checking for remaining rules on port %d\n", service_port);
    FILE_LOG(log_message);
    snprintf(cmd, sizeof(cmd), "iptables -L INPUT -n --line-numbers | grep -E \"dpt:%d|SYN_FLOOD\" || echo \"No remaining rules found for port %d\"", service_port, service_port);
    run_shell_command(cmd);
    
    FILE_LOG("[INFO][MAIN_THREAD] iptables rules cleared for service port\n");
}

int apply_iptables_protection(int service_port) {
    char log_message[BUFFER_SIZE];
    if (geteuid() != 0) {
        snprintf(log_message, sizeof(log_message), "[WARN][MAIN_THREAD] Skipping iptables mitigation: server not running as root\n");
        FILE_LOG(log_message);
        return 0;
    }

    // Always begin from a clean state to avoid stacking rules
    clear_iptables_rules_for_port(service_port);

    
    // Kernel hardening
    run_shell_command("sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1");
    run_shell_command("sysctl -w net.ipv4.tcp_max_syn_backlog=4096 >/dev/null 2>&1");
    run_shell_command("sysctl -w net.ipv4.tcp_synack_retries=3 >/dev/null 2>&1");

    char cmd[512];
    // Create/flush chain (fail fast if xtables lock is held)
    run_shell_command("iptables -w 2 -N SYN_FLOOD 2>/dev/null || true");
    run_shell_command("iptables -w 2 -F SYN_FLOOD >/dev/null 2>&1");

    // Add hashlimit RETURN and then DROP
    snprintf(cmd, sizeof(cmd),
             "iptables -w 2 -A SYN_FLOOD -m hashlimit --hashlimit-name syn_%d --hashlimit-mode srcip --hashlimit-upto %s --hashlimit-burst %d -j RETURN",
             service_port, syn_rate, syn_burst);
    run_shell_command(cmd);
    run_shell_command("iptables -w 2 -A SYN_FLOOD -j DROP");

    // Hook for SYN packets to this port
    snprintf(cmd, sizeof(cmd),
             "iptables -w 2 -C INPUT -p tcp --syn --dport %d -j SYN_FLOOD 2>/dev/null || iptables -w 2 -A INPUT -p tcp --syn --dport %d -j SYN_FLOOD",
             service_port, service_port);
    run_shell_command(cmd);

    // Per-IP concurrent connection limit
    snprintf(cmd, sizeof(cmd),
             "iptables -w 2 -C INPUT -p tcp --dport %d -m connlimit --connlimit-above %d --connlimit-mask 32 -j REJECT --reject-with tcp-reset 2>/dev/null || iptables -w 2 -A INPUT -p tcp --dport %d -m connlimit --connlimit-above %d --connlimit-mask 32 -j REJECT --reject-with tcp-reset",
             service_port, per_ip_limit, service_port, per_ip_limit);
    run_shell_command(cmd);

    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] iptables mitigation applied for tcp/%d\n", service_port);
    FILE_LOG(log_message);
    return 0;
}

void remove_iptables_protection(int service_port) {
    if (geteuid() != 0) return;
    char log_message[BUFFER_SIZE];
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] Removing iptables mitigation for tcp/%d\n", service_port);
    FILE_LOG(log_message);
    clear_iptables_rules_for_port(service_port);
    snprintf(log_message, sizeof(log_message), "[INFO][MAIN_THREAD] iptables mitigation removal complete for tcp/%d\n", service_port);
    FILE_LOG(log_message);
}
