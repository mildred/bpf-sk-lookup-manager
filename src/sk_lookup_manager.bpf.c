// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <sys/socket.h>
#include <linux/in.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_SOCKS 1

struct {
	__uint(type, BPF_MAP_TYPE_SOCKMAP);
	__uint(max_entries, MAX_SOCKS);
	__type(key, __u32);
	__type(value, __u64);
} redir_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u8);
} preserve_ipv4_map SEC(".maps");

typedef struct { __u32 addr[4]; } ipv6_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, ipv6_t);
	__type(value, __u8);
} preserve_ipv6_map SEC(".maps");

int redirect_port = 0;
int redirect_family = 0;
int redirect_protocol = 0;

static const __u32 KEY0 = 0;

SEC("sk_lookup/redirect")
int redirect(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	if (ctx->local_port != redirect_port) return SK_PASS;
	if (ctx->family != redirect_family) return SK_PASS;
	if (ctx->protocol != redirect_protocol) return SK_PASS;

	switch(ctx->family){
		case AF_INET: {
			__u32 key = ctx->local_ip4;
			if(bpf_map_lookup_elem(&preserve_ipv4_map, &key)) {
				return SK_PASS;
			}
			break;
		}
		case AF_INET6: {
			ipv6_t key = {
				.addr = { ctx->local_ip6[0], ctx->local_ip6[1], ctx->local_ip6[2],  ctx->local_ip6[3] }
			};
			if(bpf_map_lookup_elem(&preserve_ipv6_map, &key)) {
				return SK_PASS;
			}
			break;
		}
		default:
			return SK_PASS;
	}

	sk = bpf_map_lookup_elem(&redir_map, &KEY0);
	if (!sk)
		return SK_PASS;

	err = bpf_sk_assign(ctx, sk, 0);
	if(err){
		bpf_printk("Redirect port %d error %d\n", redirect_port, err);
		bpf_printk("Redirect sk family %d packet family %d\n", sk->family, ctx->family);
	}
	bpf_sk_release(sk);
	return err ? SK_DROP : SK_PASS;

	return SK_PASS;
}

