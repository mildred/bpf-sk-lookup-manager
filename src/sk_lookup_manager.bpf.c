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

#if 0

SEC("sk_lookup/hello_world")
int hello_world(struct bpf_sk_lookup *ctx)
{
	struct bpf_sock *sk;
	int err;

	/* Accept any connection from port other than 9898 */
	if (ctx->local_port != 9898)
		return SK_PASS;

	bpf_printk("Hello World from port 9898\n");

	struct bpf_sock_tuple tuple;
	__u32 tuple_size;
	switch(ctx->family){
		case AF_INET:
			tuple.ipv4.saddr = ctx->remote_ip4;
			tuple.ipv4.daddr = ctx->local_ip4;
			tuple.ipv4.sport = ctx->remote_port;
			tuple.ipv4.dport = ctx->local_port;
			tuple_size = sizeof(tuple.ipv4);
			break;
		case AF_INET6:
			tuple.ipv6.saddr[0] = ctx->remote_ip6[0];
			tuple.ipv6.saddr[1] = ctx->remote_ip6[1];
			tuple.ipv6.saddr[2] = ctx->remote_ip6[2];
			tuple.ipv6.saddr[3] = ctx->remote_ip6[3];
			tuple.ipv6.daddr[0] = ctx->local_ip6[0];
			tuple.ipv6.daddr[1] = ctx->local_ip6[1];
			tuple.ipv6.daddr[2] = ctx->local_ip6[2];
			tuple.ipv6.daddr[3] = ctx->local_ip6[3];
			tuple.ipv6.sport = ctx->remote_port;
			tuple.ipv6.dport = ctx->local_port;
			tuple_size = sizeof(tuple.ipv6);
			break;
		default:
			return SK_PASS;
	}

	switch(ctx->protocol){
		case IPPROTO_TCP:
			sk = bpf_sk_lookup_tcp(ctx, &tuple, tuple_size, -1, 0);
			break;
		case IPPROTO_UDP:
			sk = bpf_sk_lookup_udp(ctx, &tuple, tuple_size, -1, 0);
			break;
		default:
			return SK_PASS;
	}

	if(!sk) return SK_PASS;

	err = bpf_sk_assign(ctx, sk, 0);
	bpf_sk_release(sk);
	return err ? SK_DROP : SK_PASS;
}

#endif
