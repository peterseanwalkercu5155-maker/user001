#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <time.h>

/* ANSI Colors for terminal output */
#define COLOR_RESET   "\x1b[0m"
#define COLOR_INFO    "\x1b[32m" /* Green */
#define COLOR_WARN    "\x1b[33m" /* Yellow */
#define COLOR_ERR     "\x1b[31m" /* Red */

/* Helper macro for timestamp */
#define PRINT_TIMESTAMP() do { \
    time_t t = time(NULL); \
    struct tm *tm_info = localtime(&t); \
    char buffer[26]; \
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info); \
    printf("[%s] ", buffer); \
} while(0)

#define LOG_INFO(fmt, ...) do { \
    PRINT_TIMESTAMP(); \
    printf(COLOR_INFO "[INFO] " COLOR_RESET fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_WARN(fmt, ...) do { \
    PRINT_TIMESTAMP(); \
    printf(COLOR_WARN "[WARN] " COLOR_RESET fmt "\n", ##__VA_ARGS__); \
} while(0)

#define LOG_ERR(fmt, ...) do { \
    PRINT_TIMESTAMP(); \
    printf(COLOR_ERR "[ERROR] " COLOR_RESET fmt "\n", ##__VA_ARGS__); \
} while(0)

#endif
