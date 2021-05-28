#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "sock.h"

static int pidfd_open(pid_t pid, int flags){
  return syscall(434, pid, flags);
}

static int pidfd_getfd(int pidfd, int fd, int flags){
  return syscall(438, pidfd, fd, flags);
}

static int get_pid_fd(pid_t pid, int fd){
  int pidfd = pidfd_open(pid, 0);
  if(pidfd < 0) return -errno;

  int res = pidfd_getfd(pidfd, fd, 0);
  if (res < 0) res = -errno;

  close(pidfd);

  return res;
}

static int is_proc_dir(const struct dirent *ent){
  return atoi(ent->d_name) && ent->d_type == DT_DIR;
}

static int sock_fd_from_inode_and_pid(ino_t inode, pid_t pid) {
  int err = 0;

  struct dirent **namelist = 0;
  int n = 0;

  char dirname[PATH_MAX], matchstr[PATH_MAX], linkname[PATH_MAX], linkdest[PATH_MAX];
  snprintf(dirname, PATH_MAX, "/proc/%d/fd", pid);
  snprintf(matchstr, PATH_MAX, "socket:[%ld]", inode);
  //printf("[%s] n = %d\n", dirname, n);

  n = scandir(dirname, &namelist, NULL, alphasort);
  //printf("[%s] n = %d err: %s\n", dirname, n, strerror(errno));
  if (n == -1) {
    err = errno;
    goto cleanup;
  }

  //printf("[%s] n = %d\n", dirname, n);

  for(int i = 0; i < n; i++) {
    if(namelist[i]->d_type != DT_LNK) continue;
    snprintf(linkname, PATH_MAX, "/proc/%d/fd/%s", pid, namelist[i]->d_name);
    int res = readlink(linkname, linkdest, PATH_MAX-1);
    if (res > 0) {
      linkdest[res] = 0;
      //printf("%s -> %s\n", linkname, linkdest);
      if(!strcmp(matchstr, linkdest)) {
        err = -atoi(namelist[i]->d_name);
        goto cleanup;
      }
    }
  }

cleanup:
  while (n > 0 && n--) {
    free(namelist[n]);
  }
  if(namelist) free(namelist);
  return -err;
}

int sock_pid_fd_from_inode(ino_t inode, pid_t *pid, int *fd) {
  int err = 0;

  struct dirent **namelist = 0;
  int n = 0;
  struct stat st, st_self;

  if(stat("/proc/self/ns/net", &st_self) < 0) {
    fprintf(stderr, "Cannot stat /proc/self/ns/net: %s\n", strerror(errno));
    err = errno;
    goto cleanup;
  }

  n = scandir("/proc", &namelist, is_proc_dir, alphasort);
  if (n == -1) {
    err = errno;
    goto cleanup;
  }
  //printf("n = %d\n", n);

  for(int i = 0; i < n; i++) {
    //puts(namelist[i]->d_name);
    *pid = atoi(namelist[i]->d_name);
    if(!*pid) continue;

    char ns_path[PATH_MAX];
    snprintf(ns_path, PATH_MAX, "/proc/%s/ns/net", namelist[i]->d_name);
    if(stat(ns_path, &st) < 0) {
      // defunct process can fail to have readable network namespace
      // fprintf(stderr, "Cannot stat %s: %s\n", ns_path, strerror(errno));
      continue;
    }

    if(st.st_ino != st_self.st_ino || st.st_dev != st_self.st_dev) {
      continue;
    }

    *fd = sock_fd_from_inode_and_pid(inode, *pid);
    if(*fd > 0) {
      err = -get_pid_fd(*pid, *fd);
      goto cleanup;
    }
  }

  err = EINVAL;

cleanup:
  while (n > 0 && n--) {
    free(namelist[n]);
  }
  if(namelist) free(namelist);
  return -err;
}
