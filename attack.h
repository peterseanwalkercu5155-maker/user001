#ifndef ATTACK_H
#define ATTACK_H

#include "types.h"

#define MAX_STATES 65536

typedef struct {
    uint16_t src_port;
    uint32_t seq;
    uint32_t ack;
    volatile int active;
} ConnectionState;

extern ConnectionState established_pool[MAX_STATES];
extern volatile int established_count;

void generate_heavy_payloads();
void encrypt_payload(unsigned char *buffer, int len, unsigned char key);
void obfuscate_payload(unsigned char *buffer, int len);
void handle_connection_event(int epoll_fd, struct epoll_event *ev, int thread_id);
int spawn_connection(int epoll_fd, int thread_id);
void *worker_thread(void *arg);

#endif
