#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */
#include <netinet/tcp.h>

#include <stdbool.h>

#include "./ip_funcs.h"
#include "./sock.h"

struct sk_lookup_manager_bpf;

typedef struct mapping_preserve {
  struct sockaddr              *bind_addr;
  bool                          found;
  bool                          added;
  bool                          removed;
  struct mapping_preserve      *next;
} mapping_preserve_t;

typedef struct mapping {
  int                           family;
  int                           protocol;
  int                           from_port;
  struct addrinfo              *to_addr;
  ino_t                         inode;
  pid_t                         pid;
  int                           pid_fd;
  int                           fd;
  struct stat                   fdstat;
  mapping_preserve_t           *preserve;
  struct sk_lookup_manager_bpf *skel;
  int                           preserve4_size;
  int                           preserve6_size;
  struct bpf_link              *link;
  struct mapping               *next;
} mapping_t;

void mapping_free(mapping_t *map);
void mapping_preserve_free(mapping_preserve_t *map);
void mapping_preserve_mark_not_found(mapping_preserve_t *p);

// Remove all elements marked to be removed, mark all other elements to be
// removed next time and remove the added mark.
void mapping_preserve_mark_removed_and_remove(mapping_preserve_t **p);

// Get length of preserve map
int mapping_preserve_len(mapping_preserve_t *p, int *v4_len, int *v6_len);

// Add a preserve mapping and return true, or if already found, do nothing but
// mark it as found and return false.
bool mapping_preserve_add_or_find(mapping_preserve_t **p, struct sockaddr *addr);

// Remove not found mappings, keep the found mappings. Any remaining mapping is
// marked as not found. Return true the list was changed.
bool mapping_preserve_remove_not_found(mapping_preserve_t **p);

bool mapping_preserve_has_changes(mapping_preserve_t *p);


int mapping_parse_add_any(mapping_t **in_mapping, int family, int proto, const char *spec);

static inline int mapping_parse_add_tcp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_TCP, spec);
}

static inline int mapping_parse_add_udp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_UDP, spec);
}


int mapping_find_inodes(mapping_t *mapping);

#endif

