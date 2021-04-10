#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_IP_FUNCS_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_IP_FUNCS_H_

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>


/**
 * Searches in `nodeport0` the `:` character (parsing correctly IPv6 addresses
 * if enclosed within `[` and `]`) and split it into two strings: the node and
 * the port. Calls `getaddrinfo()` with the splitted strings and the resulting
 * arguments.
 */
static int getaddrinfo2(const char *nodeport0,
                       const struct addrinfo *hints,
                       struct addrinfo **res) {
    size_t len = strlen(nodeport0);
    char nodeport[len+1];
    strncpy(nodeport, nodeport0, len+1);

    char *node = nodeport, *service = nodeport;

    if(*nodeport == '['){
        char *c = strchr(nodeport, ']');
        if(c && *c) {
            *c = 0;
            node = nodeport + 1;
            service = c + 1;
        }
    }

    char *c = strchr(service, ':');
    if(c && *c) {
        *c = 0;
        service = c+1;
    } else {
        service = NULL;
    }

    return getaddrinfo(node, service, hints, res);
}

/**
 * Convert and IP address to a string
 */
static char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
#define sa4 ((struct sockaddr_in *)sa)
#define sa6 ((struct sockaddr_in6 *)sa)
    char addr[1024];

    if(!sa) {
        strncpy(s, "(null)", maxlen);
        return s;
    }

    switch(sa->sa_family) {
        case AF_INET: {
            inet_ntop(AF_INET, &(sa4->sin_addr), addr, sizeof(addr));
            snprintf(s, maxlen, "%s:%d", addr, ntohs(sa4->sin_port));
            break;
        }

        case AF_INET6:
            inet_ntop(AF_INET6, &(sa6->sin6_addr), addr, sizeof(addr));
            snprintf(s, maxlen, "[%s]:%d", addr, ntohs(sa6->sin6_port));
            break;

        default:
            return NULL;
    }

    return s;
#undef sa4
#undef sa6
}

static struct in_addr
netAddrIpv4(int prefix, struct in_addr *addr) {
    if(prefix < 0) prefix=32;
    in_addr_t netmask = 0;
    while(prefix--){
        netmask = (netmask << 1) | 1;
    }
    struct in_addr res = { .s_addr = netmask & addr->s_addr };
    return res;
}

static struct in6_addr
netAddrIpv6(int prefix, struct in6_addr *addr) {
    if(prefix < 0) prefix=128;
    struct in6_addr netmask;
    for (long i = prefix, j = 0; i > 0; i -= 8, ++j) {
        netmask.s6_addr[j] = (i >= 8) ?
            0xff :
            ( 0xffU << ( 8 - i ) ) & 0xffU;
    }
    struct in6_addr res = {};
    for(int i = 0; i < 16; i++) {
        res.s6_addr[i] = res.s6_addr[i] & netmask.s6_addr[i];
    }
    return netmask;
}

static bool ip_eq_prefix(const struct sockaddr *sa0, int prefix0, const struct sockaddr *sa1, int prefix1){
    //char straddr1[1024], straddr2[1024];
    //printf("ip_eq_prefix(%s, %d, %s, %d)\n",
    //    get_ip_str((struct sockaddr*) sa0, straddr1, 1024), prefix0,
    //    get_ip_str((struct sockaddr*) sa1, straddr2, 1024), prefix1);

    if(sa0->sa_family != sa1->sa_family) return false;

    switch(sa0->sa_family) {
        case AF_INET: {
            struct sockaddr_in *addr0 = (struct sockaddr_in *) sa0;
            struct sockaddr_in *addr1 = (struct sockaddr_in *) sa1;

            /* check port number */
            if (addr0->sin_port != addr1->sin_port) return false;

            /* check network IP */
            struct in_addr net_addr0 = netAddrIpv4(prefix0, &addr0->sin_addr);
            struct in_addr net_addr1 = netAddrIpv4(prefix1, &addr1->sin_addr);
            if (net_addr0.s_addr != net_addr1.s_addr) return false;

            return true;
        }

        case AF_INET6: {
            struct sockaddr_in6 *addr0 = (struct sockaddr_in6 *) sa0;
            struct sockaddr_in6 *addr1 = (struct sockaddr_in6 *) sa1;

            /* check port number */
            if (addr0->sin6_port != addr1->sin6_port) return false;

            /* check network IP */
            struct in6_addr net_addr0 = netAddrIpv6(prefix0, &addr0->sin6_addr);
            struct in6_addr net_addr1 = netAddrIpv6(prefix1, &addr1->sin6_addr);
            for(int i = 0; i < 16; ++i)
                if (net_addr0.s6_addr[i] != net_addr1.s6_addr[i]) return false;

            return true;
        }
    }
    return false;
}

static bool ip_eq(const struct sockaddr *sa0, const struct sockaddr *sa1){
    return ip_eq_prefix(sa0, -1, sa1, -1);
}

#endif

