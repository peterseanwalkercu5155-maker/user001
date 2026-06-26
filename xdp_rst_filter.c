#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef htons
#define htons(x) ((__u16)( \
        (((__u16)(x) & (__u16)0x00ffU) << 8) | \
        (((__u16)(x) & (__u16)0xff00U) >> 8) ))
#endif

SEC("xdp")
int xdp_rst_filter(struct xdp_md *ctx) {
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

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return XDP_PASS;

    // Drop SYN-ACK packets to prevent local Linux kernel from generating outbound RSTs
    // Pass SYN-ACK packets so user-space TCP stack (AF_XDP) can receive them
    if (tcph->syn && tcph->ack) {
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
