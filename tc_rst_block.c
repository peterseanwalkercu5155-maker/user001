#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

SEC("tc")
int tc_rst_block(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)eth + sizeof(*eth);
    if ((void *)iph + sizeof(*iph) > data_end)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    int ip_hdr_len = iph->ihl * 4;
    if (ip_hdr_len < sizeof(*iph))
        return TC_ACT_OK;

    struct tcphdr *tcph = (void *)iph + ip_hdr_len;
    if ((void *)tcph + sizeof(*tcph) > data_end)
        return TC_ACT_OK;

    // Chặn gói RST gửi đi
    if (tcph->rst) {
        return TC_ACT_SHOT; // Hủy gói tin
    }

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
