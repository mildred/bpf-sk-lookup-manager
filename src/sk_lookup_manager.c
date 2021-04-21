#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <linux/bpf.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "utils/mappings.h"

typedef struct { __u32 addr[4]; } ipv6_t;

#include "sk_lookup_manager.skel.h"

static struct bpf_link *attach_lookup_prog(struct bpf_program *prog)
{
	struct bpf_link *link;
	int net_fd;

	net_fd = open("/proc/self/ns/net", O_RDONLY);
	if (net_fd < 0) {
		fprintf(stderr, "failed to open /proc/self/ns/net, %s\n",
				strerror(-net_fd));
		return NULL;
	}

	link = bpf_program__attach_netns(prog, net_fd);
	if (link < 0) {
		fprintf(stderr, "failed to attach program '%s' to netns, %s\n",
			bpf_program__name(prog),
			strerror(- (intptr_t) link));
		link = NULL;
	}

	close(net_fd);
	return link;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int resize_preserve_maps(mapping_t* map) {
	int err = 0;

	mapping_preserve_len(map->preserve, &map->preserve4_size, &map->preserve6_size);

	switch(map->family){
		case AF_INET:   map->preserve6_size = 0; break;
		case AF_INET6:  map->preserve4_size = 0; break;
	}

	err = -bpf_map__resize(map->skel->maps.preserve_ipv4_map, map->preserve4_size || 1);
	if(err) {
		fprintf(stderr, "Failed to resize preserve_ipv4_map to %d: %s\n", map->preserve4_size, strerror(err));
		goto cleanup;
	}
	err = -bpf_map__resize(map->skel->maps.preserve_ipv6_map, map->preserve6_size || 1);
	if(err) {
		fprintf(stderr, "Failed to resize preserve_ipv6_map to %d, %s\n", map->preserve6_size, strerror(err));
		goto cleanup;
	}

cleanup:
	return err;
}

static int fill_preserve_maps(mapping_t* map, bool is_new) {
	int err = 0;
	int fd4 = 0, fd6 = 0;
	mapping_preserve_t *preserve = 0;

	fd4 = bpf_map__fd(map->skel->maps.preserve_ipv4_map);
	if (fd4 < 0) {
		err = -fd4;
		fprintf(stderr, "Failed to get BPF preserve_ipv4_map file descriptor: %s\n", strerror(err));
		goto cleanup;
	}
	//if(map->family != AF_INET) {
	//	close(fd4);
	//	fd4 = 0;
	//}

	fd6 = bpf_map__fd(map->skel->maps.preserve_ipv6_map);
	if (fd6 < 0) {
		err = -fd6;
		fprintf(stderr, "Failed to get BPF preserve_ipv6_map file descriptor: %s\n", strerror(err));
		goto cleanup;
	}
	//if(map->family != AF_INET6) {
	//	close(fd6);
	//	fd6 = 0;
	//}

	for(preserve = map->preserve; !is_new && preserve; preserve = preserve->next) {
		if (preserve->bind_addr->sa_family != map->family) continue;
		if (!preserve->removed) continue;

		switch(preserve->bind_addr->sa_family) {
			case AF_INET: {
				__u32 map_index = ((struct sockaddr_in*) preserve->bind_addr)->sin_addr.s_addr;
				err = bpf_map_delete_elem(fd4, &map_index);
				break;
			}
			case AF_INET6: {
				ipv6_t map_index;
				memcpy(map_index.addr, ((struct sockaddr_in6*) preserve->bind_addr)->sin6_addr.s6_addr, 16);
				err = bpf_map_delete_elem(fd6, &map_index);
				break;
			}
		}
		if (err) {
			fprintf(stderr, "Failed to remove preserve IP from BPF map\n");
			goto cleanup;
		}
	}

	for(preserve = map->preserve; preserve; preserve = preserve->next) {
		if (preserve->bind_addr->sa_family != map->family) continue;
		if (!preserve->added) continue;

		__u8 map_value = 1;
		switch(preserve->bind_addr->sa_family) {
			case AF_INET: {
				__u32 map_index = ((struct sockaddr_in*) preserve->bind_addr)->sin_addr.s_addr;
				err = -bpf_map_update_elem(fd4, &map_index, &map_value, BPF_NOEXIST);
				if (err) {
					err = errno;
					fprintf(stderr, "Failed to put preserve IPv4 to BPF map %d: %s\n", fd4, strerror(err));
					goto cleanup;
				}
				break;
			}
			case AF_INET6: {
				ipv6_t map_index;
				memcpy(map_index.addr, ((struct sockaddr_in6*) preserve->bind_addr)->sin6_addr.s6_addr, 16);
				err = -bpf_map_update_elem(fd6, &map_index, &map_value, BPF_NOEXIST);
				if (err) {
					fprintf(stderr, "Failed to put preserve IPv6 to BPF map %d: %s\n", fd6, strerror(err));
					goto cleanup;
				}
				break;
			}
		}
	}


cleanup:
	//if(fd4 > 0) close(fd4);
	//if(fd6 > 0) close(fd6);
	return err;
}

static int install_sk_lookup(mapping_t *map) {
	int err;
	if (map->fd) {
		if(map->skel) {
			bpf_link__destroy(map->link);
			sk_lookup_manager_bpf__destroy(map->skel);
		}

		map->skel = sk_lookup_manager_bpf__open();
		if (!map->skel) {
			fprintf(stderr, "Failed to open skeleton\n");
			return 1;
		}

		err = resize_preserve_maps(map);
		if(err) {
			return err;
		}

		/* Load & verify BPF programs */
		err = sk_lookup_manager_bpf__load(map->skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			return err;
		}

		map->skel->bss->redirect_port = map->from_port;
		map->skel->bss->redirect_family = map->family;
		map->skel->bss->redirect_protocol = map->protocol;

		err = fill_preserve_maps(map, true);
		if(err) {
			return err;
		}

		int map_fd = bpf_map__fd(map->skel->maps.redir_map);
		if (map_fd < 0) {
			err = -map_fd;
			fprintf(stderr, "Failed to get BPF map file descriptor\n");
			return err;
		}
		uint64_t map_value = (uint64_t) map->fd;
		int map_index = 0;
		err = bpf_map_update_elem(map_fd, &map_index, &map_value, BPF_NOEXIST);
		if (err) {
			fprintf(stderr, "Failed to put file descriptor to BPF map\n");
			close(map_fd);
			return err;
		}

		// close map->fd to avoid holding it when not in use
		close(map->fd);
		map->fd = 0;
		map->preserve_changed = false;

		//close(map_fd);

		/* Attach program */
		map->link = attach_lookup_prog(map->skel->progs.redirect);
		if (!map->link) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			return 1;
		}
		char addr1[1024];
		get_ip_str(map->to_addr->ai_addr, addr1, 1024);
		printf("Attached :%d to %s /proc/%d/fd/%d [%ld:%ld]\n", map->from_port, addr1, map->pid, map->pid_fd, map->fdstat.st_dev, map->fdstat.st_ino);
	} else if (map->preserve_changed) {
		err = fill_preserve_maps(map, false);
		if(err) {
			return err;
		}

		map->preserve_changed = false;
	}

	return 0;
}

int main(int argc, char **argv){
	int verbose = 0;
	int err = 0;
	mapping_t *mapping = 0;

	for(int argi = 1; argi < argc; argi++) {
		if(!strcmp("-h", argv[argi]) || !strcmp("--help", argv[argi])) {
			//     "---------|---------|---------|---------|---------|---------|---------|-|-------|
			//     "------->------->------->------->------->------->------->------->-------|-------|
			printf("%s [OPTIONS]\n", argv[0]);
			printf("\n"
				"Manages the sk-lookup BPF programs on the system. Redirects incoming\n"
				"connections on some destination ports to specified sockets. Refresh\n"
				"every second the sockets in case services were restarted or stopped.\n"
				"\n"
				"OPTIONS:\n"
				"        -h, --help      this help\n"
#ifdef VERSION
				"        --version       version information\n"
#endif
				"        -v              verbose messages\n"
				"        -t PORT=ADDR    redirect TCP port to ADDR\n"
				"        -u PORT=ADDR    redirect UDP port to ADDR\n"
				"\n"
				"Examples:\n"
				"        -t 2222=0.0.0.0:22 -t 2222=[::]:22 redirects every incoming\n"
				"        connection on port 2222 to SSH server that is listening to\n"
				"        0.0.0.0:22 and [::]:22. Both families are listed to account for\n"
				"        IPv4 and IPv6 packets.\n"
				"\n"
				"Hints: Errors in BPF can appear in /sys/kernel/debug/tracing/trace_pipe\n");
#ifdef VERSION
			printf("\nVersion: %s\n", VERSION);
#endif
			return 0;
#ifdef VERSION
		} else if(!strcmp("--version", argv[argi])) {
			printf("%s version: %s\n", argv[0], VERSION);
			return 0;
#endif
		} else if(!strcmp("-v", argv[argi])) {
			verbose = 1;
		} else if(!strcmp("-t", argv[argi]) && argi + 1 < argc) {
			err = mapping_parse_add_tcp(&mapping, AF_UNSPEC, argv[argi+1]);
			if(err){
				fprintf(stderr, "Cannot parse -t %s: %s\n", argv[argi+1], strerror(-err));
				exit(EXIT_FAILURE);
			}
			argi++;

		} else if(!strcmp("-u", argv[argi]) && argi + 1 < argc) {
			err = mapping_parse_add_udp(&mapping, AF_UNSPEC, argv[argi+1]);
			argi++;
			if(err) {
				fprintf(stderr, "Cannot parse -u %s: %s\n", argv[argi+1], strerror(-err));
				exit(EXIT_FAILURE);
			}
		}
	}

	do {
		err = mapping_find_inodes(mapping);
	} while(-err == EAGAIN);
	if(err) {
		fprintf(stderr, "Cannot find inodes: %s\n", strerror(-err));
		exit(EXIT_FAILURE);
	}

	/* Set up libbpf errors and debug info callback */
	if(verbose) libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	for(mapping_t *map = mapping; map; map = map->next) {
		err = install_sk_lookup(map);
		if(err) goto cleanup;
	}

	for (;;) {
		/* trigger our BPF program */
		sleep(1);

		do {
			err = mapping_find_inodes(mapping);
		} while(err == -EAGAIN);
		if(err) {
			fprintf(stderr, "Cannot find inodes: %s\n", strerror(-err));
			exit(EXIT_FAILURE);
		}

		for(mapping_t *map = mapping; map; map = map->next) {
			err = install_sk_lookup(map);
			if(err) goto cleanup;
		}

	}

cleanup:
	for(mapping_t *map = mapping; map; map = map->next) {
		if(map->skel) {
			bpf_link__destroy(map->link);
			sk_lookup_manager_bpf__destroy(map->skel);
		}
	}
	return -err;
}
