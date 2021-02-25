bpf-inet-lookup-manager
=======================

Goal: manage incoming connections using eBPF sk_lookup programs.

Use case: on a server with no split network namespaces, all daemons are running
in the root network namespace to avoid complex network setup such as NAT and
subnets. Each daemon is given a 127.0.0.0/8 IPv4 and ULA IPv6 address to listen
to and must not listen to INADDR_ANY. On incoming connection, the manager shall
redirect to the correct socket for the given port number using a configuration.

Operations:

- the manager is configured with a list of port number and destination address
  mapping
- upon receiving a new connection, the manager tries to find an already
  listening socket that matches, if so, it selects this socket
- upon failure, it looks up the destination port number and fetches the IP
  address (which might be provate) to select a socket suitable
- upon failure, it returns and the kernel will reject the packet as there is no
  matching socket listening

Requirement
-----------

- clang with bpf backend
- libbpf

Build
-----

    make -B

Run
---

Work in progress

    ./sk_lookup_manager

Check
-----

    dmesg

Documentation
-------------

- Cloudflare presentation: https://blog.cloudflare.com/its-crowded-in-here/
- eBPF sk_lookup: https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html
- Building: https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/
- Helpers: [bpf-helpers(7)](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- BPF System call: [bpf(2)](https://www.man7.org/linux/man-pages/man2/bpf.2.html)
- sk_lookup sample [tools/testing/selftests/bpf/prog_tests/sk_lookup.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/prog_tests/sk_lookup.c?h=v5.11)
