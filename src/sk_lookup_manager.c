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

#include "sk_lookup_manager.skel.h"

#include "../utils/mappings.h"

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

		/* Load & verify BPF programs */
		err = sk_lookup_manager_bpf__load(map->skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			return err;
		}

		map->skel->bss->redirect_port = map->from_port;
		map->skel->bss->redirect_family = map->family;
		map->skel->bss->redirect_protocol = map->protocol;

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

		close(map_fd);

		/* Attach program */
		map->link = attach_lookup_prog(map->skel->progs.redirect);
		if (!map->link) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			return 1;
		}
		char addr1[1024];
		get_ip_str(map->to_addr->ai_addr, addr1, 1024);
		printf("Attached :%d to %s /proc/%d/fd/%d [%ld:%ld]\n", map->from_port, addr1, map->pid, map->pid_fd, map->fdstat.st_dev, map->fdstat.st_ino);
	}

	return 0;
}

int main(int argc, char **argv){
	int verbose = 0;
	int err = 0;
	mapping_t *mapping = 0;

	for(int argi = 1; argi < argc; argi++) {
		if(!strcmp("-v", argv[argi])) {
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
