#ifndef _BPF_SK_LOOKUP_MANAGER_UTILS_SOCK_H_
#define _BPF_SK_LOOKUP_MANAGER_UTILS_SOCK_H_

#include <unistd.h>
#include <sys/types.h>

int sock_pid_fd_from_inode(ino_t inode, pid_t *pid, int *fd);

#endif

