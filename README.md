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

TODO
----

bpf_sk_lookup_tcp and bpf_sk_lookup_udp and not accessible to sk_lookup BPF
programs, the kernel should be patched.

It seems that if calling bpf_sk_lookup_tcp from within a sk_lookup BPF program
would cause an infinite recursion if it was possible:

- `__inet_lookup_listener()` in `net/ipv4/inet_hashtables.c` will call the BPF program
- `bpf_sk_lookup_tcp()` is called within `net/core/filter.c`
- `bpf_sk_lookup()` is called
- `bpf_skc_lookup()` is the next function called, which is a wrapper around
- `__bpf_skc_lookup()`
- `sk_lookup()` is then called after namespace lookup (if needed)
- then depending on the protocol, it will call `__inet_lookup()` for TCP4 (or `__udp4_lib_lookup`, `__inet6_lookup` or `udp6_lib_lookup` function pointer)
- `__inet_lookup()` is back in `net/ipv4/inet_hashtables.c`, it will lookup connected sockets, and if not found
- `__inet_lookup_listener()` is called to find unconnected listening sockets
- which calls the BPF program again, looping

If so, perhaps some BPF wrapper could be added to directly lookup a listening
sockets from the inet/inet6 hashtables without looking up already connected
sockets nor calling recursively BPF code.

It seems rather simple: add a BPF wrapper code that would work much like the
already existing bpf_sk_lookup_tcp/udp but instead of calling
`__inet_lookup_listener()`, it would call directly the hashtable querying
functions (`ipv4_portaddr_hash`, `inet_lhash2_bucket` and `inet_lhash2_lookup`)
and return a result.

This way, BPF code could query sockets and choose if it wants to lookup sockets
from a specific listening address or `INADDR_ANY` or both. It would add
flexibility to BPF programs.

BPF helper functions are checked within `kernel/bpf/verifier.c` and an "unknown
func" error message is returned if the function is not allowed for the given
program type. The functions available for each program type is defined in
`sk_lookup_func_proto` (for the sk_lookup program type) in `net/core/filter.c`.

Each program type, for a given helper function name can associate a different
implementation. Here, we would want an implementation that would not cause
infinite loops.


Requirement
-----------

- clang with bpf backend
- [libbpf](https://github.com/libbpf/libbpf)

Build
-----

    make -B

Run
---

Work in progress

    src/sk_lookup_manager

Check
-----

    sudo cat /sys/kernel/debug/tracing/trace_pipe

Documentation
-------------

- Cloudflare presentation: https://blog.cloudflare.com/its-crowded-in-here/
- eBPF sk_lookup: https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html
- Building: https://qmonnet.github.io/whirl-offload/2020/04/12/llvm-ebpf-asm/
- BPF Helpers: [bpf-helpers(7)](https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html)
- BPF System call: [bpf(2)](https://www.man7.org/linux/man-pages/man2/bpf.2.html)
- sk_lookup sample [tools/testing/selftests/bpf/prog_tests/sk_lookup.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/prog_tests/sk_lookup.c?h=v5.11) for the C part and [tools/testing/selftests/bpf/progs/test_sk_lookup.c](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/testing/selftests/bpf/progs/test_sk_lookup.c?h=v5.11) for the eBPF part.
- [libbpf](https://github.com/libbpf/libbpf) with [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) and [blog post](https://nakryiko.com/posts/libbpf-bootstrap/)
- [BPF kernel development](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/bpf/bpf_devel_QA.rst)
- [Kernel Virtual Machine](https://linux-kernel-labs.github.io/refs/heads/master/info/vm.html)
