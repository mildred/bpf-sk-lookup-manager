#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "mappings.h"

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

int mapping_parse_add_any(mapping_t **in_mapping, int family, int proto, const char *spec) {
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

int mapping_find_inodes(mapping_t *mapping) {
  int err = 0;
  int fd = 0;
  int newfd = 0;
  char addr[1024];

  for(;mapping; mapping = mapping->next) {

    mapping_preserve_mark_removed_and_remove(&mapping->preserve);

    //printf("family=%d (%d,%d,%d), protocol=%d (%d,%d)\n", mapping->family, AF_UNSPEC, AF_INET, AF_INET6, mapping->protocol, IPPROTO_TCP, IPPROTO_UDP);

    int v4_len = 0, v6_len = 0;

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

        struct rtattr *attr;
        unsigned int rta_len = len - NLMSG_LENGTH(sizeof(*diag));
        struct tcp_info *tcpi;

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

            if(!newfd && ip_eq((struct sockaddr*) &src, mapping->to_addr->ai_addr)) {
              //printf("IPv4 %d -> %s == %s inode=%d\n",
              //    mapping->from_port,
              //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
              //    get_ip_str(mapping->to_addr->ai_addr, addr2, 1024),
              //    diag->idiag_inode);
              mapping->inode = diag->idiag_inode;
              get_ip_str((struct sockaddr*) &src, addr1, 1024);
              get_ip_str(mapping->to_addr->ai_addr, addr2, 1024);
            } else if (ntohs(src.sin_port) == mapping->from_port) {
              if(mapping_preserve_add_or_find(&mapping->preserve, (struct sockaddr*) &src)) {
                printf("Preserve %s\n", get_ip_str((struct sockaddr*) &src, addr1, 1024));
              }
              v4_len++;
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

            if(!newfd && ip_eq((struct sockaddr*) &src, mapping->to_addr->ai_addr)) {
              //printf("IPv6 %d -> %s == %s inode=%d\n",
              //    mapping->from_port,
              //    get_ip_str((struct sockaddr*) &src, addr1, 1024),
              //    get_ip_str(mapping->to_addr->ai_addr, addr2, 1024),
              //    diag->idiag_inode);
              mapping->inode = diag->idiag_inode;
              get_ip_str((struct sockaddr*) &src, addr1, 1024);
              get_ip_str(mapping->to_addr->ai_addr, addr2, 1024);
            } else if (ntohs(src.sin6_port) == mapping->from_port) {
              if(mapping_preserve_add_or_find(&mapping->preserve, (struct sockaddr*) &src)) {
                printf("Preserve %s\n", get_ip_str((struct sockaddr*) &src, addr1, 1024));
              }
              v6_len++;
            }
            break;
          }
          default:
            fprintf(stderr, "Unknown family %d\n", diag->idiag_family);
            err = EPROTO;
            goto cleanup;
        }

        //printf("Found inode=%ld\n", mapping->inode);

        if(!newfd && mapping->inode) {
          memcpy(addr, addr1, 1024);
          newfd = sock_pid_fd_from_inode(mapping->inode, &mapping->pid, &mapping->pid_fd);
          if(newfd < 0) {
            fprintf(stderr, "Cannot fetch inode(%ld) for /proc/%d/fd/%d: %s (%s)\n",  mapping->inode, mapping->pid, mapping->pid_fd, strerror(-newfd), strerror(errno));
            err = (newfd == -EINVAL) ? EAGAIN : -newfd;
            goto cleanup;
          }
        }
      }
    }

    char addr0[1024];
    for(mapping_preserve_t *p = mapping->preserve; p; p = p->next){
      if(p->removed) {
        printf("Stop preserving %s\n", get_ip_str((struct sockaddr*) p->bind_addr, addr0, 1024));
      }
    }

    if(newfd) {
      //bool need_newfd = (mapping->family == AF_INET6) ? v6_len > mapping->preserve6_size :
      //                  (mapping->family == AF_INET)  ? v4_len > mapping->preserve4_size : false;

      // Compare with fstat the old and new fd to see if it changed
      struct stat st;
      if(fstat(newfd, &st) < 0) {
        fprintf(stderr, "Cannot fstat inode(%ld) fd %d: %s\n", mapping->inode, newfd, strerror(errno));
        err = errno;
        goto cleanup;
      }

      bool newfd_changed = mapping->fdstat.st_dev != st.st_dev || mapping->fdstat.st_ino != st.st_ino;

      if(newfd_changed || mapping_preserve_has_changes(mapping->preserve)) {
        if(mapping->fd) close(mapping->fd);
        mapping->fd = newfd;
        memcpy(&mapping->fdstat, &st, sizeof(struct stat));
        printf("[PID %d] :%d -> %s => /proc/%d/fd/%d -> socket:[%ld] [%ld:%ld]\n",
            mapping->pid, mapping->from_port, addr, mapping->pid, mapping->pid_fd, mapping->inode, mapping->fdstat.st_dev, mapping->fdstat.st_ino);
        //printf("Found in PID=%d, fd=%d -> %d (%ld:%ld))\n", mapping->pid, mapping->pid_fd, mapping->fd, mapping->fdstat.st_dev, mapping->fdstat.st_ino);
      } else {
        close(newfd);
      }
      newfd = 0;
    }

    err = 0;
  }

cleanup:
  if(newfd) close(newfd);
  if(fd) close(fd);
  return -err;
}

void mapping_free(mapping_t *map) {
  while(map) {
    mapping_t *next_map = map->next;
    freeaddrinfo(map->to_addr);
    mapping_preserve_free(map->preserve);
    free(map);
    map = next_map;
  }
}

void mapping_preserve_free(mapping_preserve_t *p) {
  while(p) {
    mapping_preserve_t *next = p->next;
    sockaddr_free(p->bind_addr);
    free(p);
    p = next;
  }
}

void mapping_preserve_mark_not_found(mapping_preserve_t *p) {
  while(p) {
    p->found = false;
    p = p->next;
  }
}

void mapping_preserve_mark_removed_and_remove(mapping_preserve_t **p) {
  while(*p) {
    if((*p)->removed) {
      mapping_preserve_t *next = (*p)->next;
      free(*p);
      *p = next;
    } else {
      (*p)->added   = false;
      (*p)->removed = true;
      (*p)->found   = false;
      p = &(*p)->next;
    }
  }
}

int mapping_preserve_len(mapping_preserve_t *p, int *v4_len, int *v6_len) {
  int res = 0;
  if(v4_len) *v4_len = 0;
  if(v6_len) *v6_len = 0;
  while(p) {
    res++;
    switch(p->bind_addr->sa_family){
      case AF_INET:
        if(v4_len) (*v4_len)++;
        break;
      case AF_INET6:
        if(v6_len) (*v6_len)++;
        break;
    }
    p = p->next;
  }
  return res;
}

bool mapping_preserve_add_or_find(mapping_preserve_t **p, struct sockaddr *addr) {
  while(*p) {
    if(ip_eq(addr, (*p)->bind_addr)) {
      (*p)->found = true;
      (*p)->removed = false;
      (*p)->added = false;
      return false;
    }
    p = &(*p)->next;
  }
  *p = malloc(sizeof(mapping_preserve_t));
  bzero(*p, sizeof(mapping_preserve_t));
  (*p)->found = true;
  (*p)->added = true;
  (*p)->bind_addr = sockaddr_copy(addr);
  return true;
}

bool mapping_preserve_remove_not_found(mapping_preserve_t **p) {
  bool res = false;
  while(*p) {
    if(! (*p)->found) {
      mapping_preserve_t *ptr = *p;
      *p = (*p)->next;
      free(ptr);
      res = true;
    } else {
      (*p)->found = false;
      p = &(*p)->next;
    }
  }
  return res;
}

bool mapping_preserve_has_changes(mapping_preserve_t *p) {
  //char addr[1024];
  while(p) {
    //if(p->added)   printf("+ %s preserved\n", get_ip_str((struct sockaddr*) p->bind_addr, addr, 1024));
    //if(p->removed) printf("- %s preserved\n", get_ip_str((struct sockaddr*) p->bind_addr, addr, 1024));
    if(p->added || p->removed) return true;
    p = p->next;
  }
  return false;
}
