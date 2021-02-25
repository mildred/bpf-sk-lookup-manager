#include <stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <linux/bpf.h>

#include <bpf/libbpf.h>

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

int main(int argc, char **argv){
	int err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	struct sk_lookup_manager_bpf *skel = sk_lookup_manager_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open skeleton\n");
		return 1;
	}

	/* Load & verify BPF programs */
	err = sk_lookup_manager_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach program */
	struct bpf_link *link = attach_lookup_prog(skel->progs.hello_world);
	if (!link) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	printf("Successfully started!\n");

	for (;;) {
		/* trigger our BPF program */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	sk_lookup_manager_bpf__destroy(skel);
	return -err;
}
