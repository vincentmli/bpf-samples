#include <stdint.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>

/*
* Sample XDP/tc program, sets the TCP PSH flag on every RATIO packet.
* compile it with:
*      clang -O2 -emit-llvm -c tcp_ack.c -o - |llc -march=bpf -filetype=obj -o tcp_ack.o
 * attach it to a device with XDP as:
 * 	ip link set dev lo xdp object tcp_ack.o verbose
* attach it to a device with tc as:
*      tc qdisc add dev eth0 clsact
*      tc filter add dev eth0 egress matchall action bpf object-file tcp_ack.o
* replace the bpf with
*      tc filter replace dev eth0 egress matchall action bpf object-file tcp_ack.o
*/

#define SEC(NAME) __attribute__((section(NAME), used))
#define RATIO 4 

/* from bpf_helpers.h */

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
        (void *) BPF_FUNC_trace_printk;

static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *) BPF_FUNC_get_prandom_u32;

static int tcp_ack(void *data, void *data_end)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
	int tcplen;

	/* sanity check needed by the eBPF verifier */
	if ((void *)(tcphdr + 1) > data_end)
		return 0;

	/* skip non TCP packets */
	if (eth->h_proto != __constant_htons(ETH_P_IP) || iph->protocol != IPPROTO_TCP)
		return 0;

	/* incompatible flags, or PSH already set */
	if (tcphdr->syn || tcphdr->fin || tcphdr->rst || tcphdr->psh)
		return 0;

	if (tcphdr->ack) {

		tcplen = iph->tot_len - (tcphdr->doff*4 + iph->ihl*4); 
                char fmt[] = "XDP: tcplen=%d \n";
                bpf_trace_printk(fmt, sizeof(fmt), tcplen);

		if (bpf_get_prandom_u32() % RATIO == 0)
			return 1;
	}

	return 0;
}

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;

	if (tcp_ack(data, data_end))
		return XDP_DROP;

	return XDP_PASS;
}

SEC("action")
int tc_main(struct __sk_buff *skb)
{
	void *data = (void *)(uintptr_t)skb->data;
	void *data_end = (void *)(uintptr_t)skb->data_end;

	if (tcp_ack(data, data_end))
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
