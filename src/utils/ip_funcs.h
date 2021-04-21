#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_IP_FUNCS_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_IP_FUNCS_H_

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>


/**
 * Searches in `nodeport0` the `:` character (parsing correctly IPv6 addresses
 * if enclosed within `[` and `]`) and split it into two strings: the node and
 * the port. Calls `getaddrinfo()` with the splitted strings and the resulting
 * arguments.
 */
int getaddrinfo2(const char *nodeport0,
                 const struct addrinfo *hints,
                 struct addrinfo **res);

/**
 * Convert and IP address to a string
 */
char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);

struct in_addr
netAddrIpv4(int prefix, struct in_addr *addr);

struct in6_addr
netAddrIpv6(int prefix, struct in6_addr *addr);

bool ip_eq_prefix(const struct sockaddr *sa0, int prefix0, const struct sockaddr *sa1, int prefix1);

bool ip_eq(const struct sockaddr *sa0, const struct sockaddr *sa1);

struct sockaddr* sockaddr_copy(struct sockaddr* source);
void sockaddr_free(struct sockaddr* source);

#endif

