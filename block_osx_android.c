#include <stdint.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

/*
 * Sample XDP to parse tcp option.
 * compile it with:
 * clang -Wall -O2 -emit-llvm -c block_osx_android.c -o - |llc -march=bpf -filetype=obj -o block_osx_android.o
 * attach it to a device with XDP as:
 * 	ip link set dev lo xdp object block_osx_android.o verbose
 */

#define SEC(NAME) __attribute__((section(NAME), used))

#define TCPOPT_EOL        0       /* End of options (1)              */
#define TCPOPT_NOP        1       /* No-op (1)                       */
#define TCPOPT_MAXSEG     2       /* Maximum segment size (4)        */
#define TCPOPT_WSCALE     3       /* Window scaling (3)              */
#define TCPOPT_SACKOK     4       /* Selective ACK permitted (2)     */
#define TCPOPT_SACK       5       /* Actual selective ACK (10-34)    */
#define TCPOPT_TSTAMP     8       /* Timestamp (10)                  */


/* from bpf_helpers.h */

static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
(void *) BPF_FUNC_trace_printk;


static int __always_inline block_osx_android(void *data, void *data_end)
{
	struct ethhdr *eth = (struct ethhdr *)data;
	struct iphdr *iph = (struct iphdr *)(eth + 1);
	struct tcphdr *tcphdr = (struct tcphdr *)(iph + 1);
	struct udphdr *udphdr = (struct udphdr *)(iph + 1);
	__u64 nh_off = sizeof(*eth);
	const __u8 *op;
        int i, optlen;

	/* skip non TCP packets */
    	if ((void *)(eth + 1) > data_end)
        	return 0;
	if (eth->h_proto != __constant_htons(ETH_P_IP))
		return 0;

    	if ((void *)(iph + 1) > data_end)
        	return 0;

	switch (iph->protocol) {
		case IPPROTO_TCP: 
			/* sanity check needed by the eBPF verifier */
			if ((void *)(tcphdr + 1)  > data_end)
				return 0;
			if (tcphdr->syn) {
				// OS X SYN TCP option pattern (tcp header size)
				if (tcphdr->doff*4 == 44 || tcphdr->doff*4 == 28) {
					char fmt[] = "XDP: tcp source : %d OS X data offset :%d\n";
					bpf_trace_printk(fmt, sizeof(fmt), (int)tcphdr->source, (int)tcphdr->doff*4);
					return 1;
				}
				// Android SYN TCP wscale 8
		                optlen = tcphdr->doff*4 - sizeof(*tcphdr);
                		op = (const __u8 *)(tcphdr + 1);
                		for (i = 0; i < optlen; ) {
                        		if ((void *)op + i + 3 > data_end)
                                		return 0;
                        		if (op[i] == TCPOPT_WSCALE && op[i+2] == 8 ) {
                                		char fmt[] = "XDP: tcp source : %d Android tcp wscale count: %d\n";
                                		bpf_trace_printk(fmt, sizeof(fmt), tcphdr->source, op[i+2]);
                                		return 1;
                        		}
                        		if (op[i] < 2)
                                		i++;
                        		else
                                		i += ((void *)op + 2 < data_end && op[i+1]) ? : 1;
                		}

			}
		case IPPROTO_UDP:
	        	/* sanity check needed by the eBPF verifier */
        		if ((void *)(udphdr + 1)  > data_end)
                		return 0;
	        	nh_off += sizeof(struct iphdr) + sizeof(struct udphdr);
        		if (data_end > data + nh_off + 5) {
            			op = data + nh_off;
            			if (op[0] == 0x04 && op[1] == 0x0 && op[2] == 0x0 && op[3] == 0x0) {
                    			char fmt[] = "XDP: udp source : %d UDP payload pattern\n";
                    			bpf_trace_printk(fmt, sizeof(fmt), (int)udphdr->source);
                    			return 1;
            			}
         		}
		default:
			return 0;
	}

	return 0;
}

SEC("prog")
int xdp_main(struct xdp_md *ctx)
{
	void *data_end = (void *)(uintptr_t)ctx->data_end;
	void *data = (void *)(uintptr_t)ctx->data;

	if (block_osx_android(data, data_end))
		return XDP_DROP;

	return XDP_PASS;
}


char _license[] SEC("license") = "GPL";
