bpf-inet-lookup-manager
=======================

Goal: manage incoming connections using eBPF sk_lookup programs.

Requirement
-----------

[bcc](https://github.com/iovisor/bcc/)

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
