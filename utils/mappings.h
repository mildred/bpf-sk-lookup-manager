#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_MAPPINGS_H_

#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
//#include <linux/unix_diag.h> /* for unix sockets */
#include <linux/inet_diag.h> /* for IPv4 and IPv6 sockets */
#include <netinet/tcp.h>


#include "./ip_funcs.h"
#include "./sock.h"

typedef struct mapping {
  int              family;
  int              protocol;
  int              from_port;
  struct addrinfo *to_addr;
  ino_t            inode;
  pid_t            pid;
  int              pid_fd;
  int              fd;
  struct mapping  *next;
} mapping_t;

static void mapping_free(mapping_t *map) {
  while(map) {
    mapping_t *next_map = map->next;
    freeaddrinfo(map->to_addr);
    free(map);
    map = next_map;
  }
}

static int mapping_parse_add_any(mapping_t **in_mapping, int family, int proto, const char *spec) {
#define mapping (*in_mapping)
  int port = atoi(spec);
  const char *spec_to = strchr(spec, '=');
  if(!spec_to) return -EINVAL;
  spec_to++;

  //printf("mapping_parse_add_any port=%d, spec_to=%s, family=%d\n", port, spec_to, family);

  struct addrinfo hints = {
      .ai_flags = AI_PASSIVE,
      .ai_family = family,
      .ai_protocol = proto,
      .ai_socktype = (proto == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM
  };
  struct addrinfo *res;
  int err = getaddrinfo2(spec_to, &hints, &res);
  if(err) {
    fprintf(stderr, "getaddrinfo(%s) error: %s\n", spec_to, gai_strerror(err));
    return -EINVAL;
  }

  mapping_t *map = malloc(sizeof(mapping_t));
  if(!map) return -ENOMEM;
  bzero(map, sizeof(mapping_t));

  map->family = res->ai_family;
  map->protocol = proto;
  map->from_port = port;
  map->to_addr = res;
  map->next = mapping;
  mapping = map;

  return 0;
#undef mapping
}

static inline int mapping_parse_add_tcp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_TCP, spec);
}

static inline int mapping_parse_add_udp(mapping_t **in_mapping, int family, const char *spec) {
  return mapping_parse_add_any(in_mapping, family, IPPROTO_UDP, spec);
}


static const char* tcp_states_map[]={
    [TCP_ESTABLISHED] = "ESTABLISHED",
    [TCP_SYN_SENT] = "SYN-SENT",
    [TCP_SYN_RECV] = "SYN-RECV",
    [TCP_FIN_WAIT1] = "FIN-WAIT-1",
    [TCP_FIN_WAIT2] = "FIN-WAIT-2",
    [TCP_TIME_WAIT] = "TIME-WAIT",
    [TCP_CLOSE] = "CLOSE",
    [TCP_CLOSE_WAIT] = "CLOSE-WAIT",
    [TCP_LAST_ACK] = "LAST-ACK",
    [TCP_LISTEN] = "LISTEN",
    [TCP_CLOSING] = "CLOSING"
};

static int mapping_find_inodes(mapping_t *mapping) {
  int err = 0;
  int fd = 0;

  for(;mapping; mapping = mapping->next) {

    //printf("family=%d (%d,%d,%d), protocol=%d (%d,%d)\n", mapping->family, AF_UNSPEC, AF_INET, AF_INET6, mapping->protocol, IPPROTO_TCP, IPPROTO_UDP);

    long buf[8192 / sizeof(long)];
    struct sockaddr_nl nladdr = {
      .nl_family = AF_NETLINK
    };

    if(!fd) {
      fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_SOCK_DIAG);
      if (fd < 0) return -errno;
    }

    // Send query

    struct
    {
      struct nlmsghdr nlh;
      //struct inet_diag_req r;
      struct inet_diag_req_v2 idr;
    } req = {
      .nlh.nlmsg_len = sizeof(req),
      .nlh.nlmsg_type = SOCK_DIAG_BY_FAMILY,
      .nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,

      .idr.sdiag_family = mapping->family,
      .idr.sdiag_protocol = mapping->protocol,
      .idr.idiag_states = 1<<TCP_CLOSE | 1<<TCP_LISTEN,

      /*
      .idr = {
        .sdiag_family = mapping->family,
        .sdiag_protocol = mapping->protocol,
        .idiag_ext = 0,
        .pad = 0,
        .idiag_states = TCP_LISTEN,
        .id = { }
        //.id = {
        //  .idiag_sport = 0,
        //  .idiag_dport = 0,
        //  .idiag_src = {0, 0, 0, 0},
        //  .idiag_dst = {0, 0, 0, 0},
        //  .idiag_if = 0,
        //  .idiag_cookie = {-1, -1}
        //}
      }
      */
    };
    struct iovec iov_req = {
      .iov_base = &req,
      .iov_len = sizeof(req)
    };
    struct msghdr msg = {
      .msg_name = (void *) &nladdr,
      .msg_namelen = sizeof(nladdr),
      .msg_iov = &iov_req,
      .msg_iovlen = 1
    };

    do {
      err = sendmsg(fd, &msg, 0) < 0 ? errno : 0;
    } while(err == EINTR);

    if(err) goto cleanup;

    // Receive responses

    struct iovec iov_res = {
      .iov_base = buf,
      .iov_len = sizeof(buf)
    };

    bool continue_receive = true;

    while (continue_receive) {
      struct msghdr msg = {
        .msg_name = (void *) &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov_res,
        .msg_iovlen = 1
      };

      ssize_t ret = recvmsg(fd, &msg, 0);
      err = ret < 0 ? errno : 0;

      if(err == EINTR) continue;
      else if (err) goto cleanup;
      else if (ret == 0) break;

      const struct nlmsghdr *h = (struct nlmsghdr *) buf;
      if (!NLMSG_OK(h, ret)) {
        err = EPROTO;
        goto cleanup;
      }

      for (; NLMSG_OK(h, ret); h = NLMSG_NEXT(h, ret)) {
        if (h->nlmsg_type == NLMSG_DONE){
          continue_receive = false;
          break;
        }

        if (h->nlmsg_type == NLMSG_ERROR) {
          const struct nlmsgerr *error = NLMSG_DATA(h);

          if (h->nlmsg_len < NLMSG_LENGTH(sizeof(*error))) {
            fprintf(stderr, "Error from netlink\n");
            //fprintf(stderr, "Error from netlink: %s", error);
            err = EPROTO;
            goto cleanup;
          } else {
            fprintf(stderr, "Error from netlink: %s\n", strerror(-error->error));
            err = -error->error;
            goto cleanup;
          }
        }

        if (h->nlmsg_type != SOCK_DIAG_BY_FAMILY) {
          fprintf(stderr, "Unexpected nlmsg_type %u\n", (unsigned) h->nlmsg_type);
          err = EPROTO;
          goto cleanup;
        }

        // Parse response

        const struct inet_diag_msg *diag = NLMSG_DATA(h);
        unsigned int len = h->nlmsg_len;

        if (len < NLMSG_LENGTH(sizeof(*diag))) {
          fprintf(stderr, "short response\n");
          err = EPROTO;
          goto cleanup;
        }
        //if (diag->idiag_family != AF_UNIX) {
        //  fprintf(stderr, "unexpected family %u\n", diag->idiag_family);
        //  err = EPROTO;
        //  goto cleanup;
        //}

        struct rtattr *attr;
        unsigned int rta_len = len - NLMSG_LENGTH(sizeof(*diag));
        //unsigned int peer = 0;
        //size_t path_len = 0;
        struct tcp_info *tcpi;
        //char path[sizeof(((struct sockaddr_un *) 0)->sun_path) + 1];

        for (attr = (struct rtattr *) (diag + 1);
            RTA_OK(attr, rta_len); attr = RTA_NEXT(attr, rta_len)) {
          switch (attr->rta_type) {
            case INET_DIAG_INFO:
              //The payload of this attribute is a tcp_info-struct, so it is
              //ok to cast
              tcpi = (struct tcp_info*) RTA_DATA(attr);

              //Output some sample data
              fprintf(stdout, "\tState: %s RTT: %gms (var. %gms) "
                  "Recv. RTT: %gms Snd_cwnd: %u/%u\n",
                  tcp_states_map[tcpi->tcpi_state],
                  (double) tcpi->tcpi_rtt/1000,
                  (double) tcpi->tcpi_rttvar/1000,
                  (double) tcpi->tcpi_rcv_rtt/1000,
                  tcpi->tcpi_unacked,
                  tcpi->tcpi_snd_cwnd);
              break;

#if 0
            case UNIX_DIAG_NAME:
              if (!path_len) {
                path_len = RTA_PAYLOAD(attr);
                if (path_len > sizeof(path) - 1)
                  path_len = sizeof(path) - 1;
                memcpy(path, RTA_DATA(attr), path_len);
                path[path_len] = '\0';
              }
              break;

            case UNIX_DIAG_PEER:
              if (RTA_PAYLOAD(attr) >= sizeof(peer))
                peer = *(unsigned int *) RTA_DATA(attr);
              break;
#endif
          default:
              break;
          }
        }

        char addr1[1024], addr2[1024];

        mapping->inode = 0;

        switch(diag->idiag_family){
          case AF_INET: {
            struct sockaddr_in src = {
              .sin_family = diag->idiag_family,
              .sin_port   = diag->id.idiag_sport,
            };
            struct sockaddr_in dst = {
              .sin_family = diag->idiag_family,
              .sin_port   = diag->id.idiag_dport,
            };

            memcpy(&src.sin_addr, diag->id.idiag_src, 4);
            memcpy(&dst.sin_addr, diag->id.idiag_dst, 4);

            //printf("IPv4 %s -> %s inode=%d\n",
            //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
            //    get_ip_str((struct sockaddr*) &dst, addr2, 1024),
            //    diag->idiag_inode);
            //printf("ip_eq(%s, %s)\n",
            //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
            //    get_ip_str(mapping->to_addr->ai_addr, addr2, 1024));

            if(ip_eq((struct sockaddr*) &src, mapping->to_addr->ai_addr)) {
              printf("IPv4 %d -> %s == %s inode=%d\n",
                  mapping->from_port,
                  get_ip_str((struct sockaddr*) &src, addr1, 1024),
                  get_ip_str(mapping->to_addr->ai_addr, addr2, 1024),
                  diag->idiag_inode);
              mapping->inode = diag->idiag_inode;
            }
            break;
          }
          case AF_INET6: {
            struct sockaddr_in6 src = {
              .sin6_family = diag->idiag_family,
              .sin6_port   = diag->id.idiag_sport,
            };
            struct sockaddr_in6 dst = {
              .sin6_family = diag->idiag_family,
              .sin6_port   = diag->id.idiag_dport,
            };

            memcpy(&src.sin6_addr, diag->id.idiag_src, 16);
            memcpy(&dst.sin6_addr, diag->id.idiag_dst, 16);

            //printf("IPv6 %s -> %s inode=%d\n",
            //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
            //    get_ip_str((struct sockaddr*) &dst, addr2, 1024),
            //    diag->idiag_inode);
            //printf("ip_eq(%s, %s)\n",
            //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
            //    get_ip_str(mapping->to_addr->ai_addr, addr2, 1024));

            if(ip_eq((struct sockaddr*) &src, mapping->to_addr->ai_addr)) {
              printf("IPv6 %d -> %s == %s inode=%d\n",
                  mapping->from_port,
                  get_ip_str((struct sockaddr*) &src, addr1, 1024),
                  get_ip_str(mapping->to_addr->ai_addr, addr2, 1024),
                  diag->idiag_inode);
              mapping->inode = diag->idiag_inode;
            }
            break;
          }
          default:
            fprintf(stderr, "Unknown family %d\n", diag->idiag_family);
            err = EPROTO;
            goto cleanup;
        }

        if(mapping->inode) {
          if(mapping->fd) close(mapping->fd);
          mapping->fd = sock_pid_fd_from_inode(mapping->inode, &mapping->pid, &mapping->pid_fd);
          printf("Found in PID=%d, fd=%d -> %d\n", mapping->pid, mapping->pid_fd, mapping->fd);
          // TODO compare with fstat the old and new fd to see if it changed
        }

#if 0
        if (peer)
          printf(", peer=%u", peer);

        if (path_len)
          printf(", name=%s%s", *path ? "" : "@",
              *path ? path : path + 1);

        putchar('\n');
#endif
      }
    }
    err = 0;
  }

cleanup:
  if(fd) close(fd);
  return -err;
}

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

