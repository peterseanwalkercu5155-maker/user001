#ifndef NETWORK_H
#define NETWORK_H

#include "types.h"
#include <linux/if_packet.h>

long long get_ms();
void set_nonblocking(int fd);
int is_ipv4(const char *str);
void apply_optimizations();
int resolve_host(const char *host, char *ip_buf);
void auto_port_scan();
unsigned short calculate_checksum(unsigned short *addr, int count);
unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp);
int init_raw_socket();
int init_afpacket_socket(const char *iface);
void craft_tcp_syn(unsigned char *packet, int *packet_len, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack);
void craft_udp_packet(unsigned char *packet, int *packet_len, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char *payload, int payload_len);
unsigned int get_local_ip();
unsigned int get_subnet_mask(const char *iface);
int get_default_interface(char *interface_out, size_t len);
int load_xdp_filter(const char *interface, const char *bpf_obj);
int configure_xdp_target(const char *interface, const char *target_ip, int target_port, unsigned int src_ip_net);
int unload_xdp_filter(const char *interface);

void enable_rst_drop(const char *iface);
void disable_rst_drop(const char *iface);
unsigned long long get_net_drops(const char *iface);

#endif
