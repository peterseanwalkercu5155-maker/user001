#ifndef AF_XDP_H
#define AF_XDP_H

#include "network.h"
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/xsk.h>
#include <poll.h>

#define NUM_FRAMES 4096
#define FRAME_SIZE XSK_UMEM__DEFAULT_FRAME_SIZE
#define INVALID_UMEM_FRAME UINT64_MAX

struct xsk_umem_info {
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    struct xsk_umem *umem;
    void *buffer;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;
    int outstanding_tx;
    uint64_t tx_frame_idx;
};

struct xsk_socket_info *init_af_xdp_socket(const char *iface, int queue_id);
void cleanup_af_xdp_socket(struct xsk_socket_info *xsk_info);
int push_xdp_tx(struct xsk_socket_info *xsk, unsigned char *payload, int len);
void process_xdp_completion(struct xsk_socket_info *xsk);
void craft_af_xdp_tcp_packet(unsigned char *pkt, int *pkt_len, const char *payload_data, int payload_size, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, unsigned char *src_mac, unsigned char *dst_mac);
int poll_xdp_rx(struct xsk_socket_info *xsk, unsigned char *pkt_buf, int max_len);

#endif // AF_XDP_H
