default: sk_lookup_manager
.PHONY: default

sk_lookup_manager: LIBS=-lbpf
sk_lookup_manager: sk_lookup_manager.o
	$(CC) $(LIBS) $+ -o $@

sk_lookup_manager.o: bpf_prog.skel.h

%.o: %.c
	$(CC) -c $< -o $@

%.bpf.o: %.bpf.c
	#clang -target bpf -Wall -O2 -c $< -o $@
	clang -O2 -emit-llvm -c $< -o - | llc -march=bpf -mcpu=probe -filetype=obj -o $@
	llvm-objdump -d $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@
