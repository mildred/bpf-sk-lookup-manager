#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
//#include <linux/unix_diag.h> /* for unix sockets */
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */
#include <netinet/tcp.h>

#include <stdbool.h>

#include "./ip_funcs.h"
#include "./sock.h"

struct sk_lookup_manager_bpf;

typedef struct mapping {
  int              family;
  int              protocol;
  int              from_port;
  struct addrinfo *to_addr;
  ino_t            inode;
  pid_t            pid;
  int              pid_fd;
  int              fd;
  struct stat      fdstat;
  struct sk_lookup_manager_bpf *skel;
  struct bpf_link *link ;
  struct mapping  *next;
} mapping_t;

void mapping_free(mapping_t *map);


int mapping_parse_add_any(mapping_t **in_mapping, int family, int proto, const char *spec);

static inline int mapping_parse_add_tcp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_TCP, spec);
}

static inline int mapping_parse_add_udp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_UDP, spec);
}


int mapping_find_inodes(mapping_t *mapping);

#if 0
static mapping_t *mapping_parse(int *in_argc, char **in_argv[]){
#define argc (*in_args)
#define argv (*in_argv)
  while(argc > 0) {
    argv[ar]
    argc++
  }
#undef argc
#undef argv
}
#endif


#endif

