
/*
 * IP table functions public interface
 */
#ifndef IPTABLEOPERATIONS_H
#define IPTABLEOPERATIONS_H

#include <stdio.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * Only expose the functions that are used outside this module.
 * Helper functions remain with internal linkage in the .c file.
 */
int apply_iptables_protection(int service_port);
void remove_iptables_protection(int service_port);

#endif /* IPTABLEFUNCTIONS_H */
