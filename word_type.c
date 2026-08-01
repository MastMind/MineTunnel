#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "word_type.h"


static int is_word(const char* str);
static int is_string(const char* str);
static int is_number(const char* str);
static int is_ipaddr(const char* str);
static int is_ip6addr(const char* str);


/**
 * Check if string matches word type
 * @param str String to check
 * @param wt Word type to match
 * @return 1 if match, 0 otherwise
 */
int striswt(const char* str, word_type wt) {
    if (!str)
        return 0;

    switch (wt) {
        case IMPL_WORD:
            return is_word(str);
        case STRING:
            return is_string(str);
        case NUMBER:
            return is_number(str);
        case IPADDR:
            return is_ipaddr(str);
        case IP6ADDR:
            return is_ip6addr(str);
    }

    return 0;
}

static int is_word(const char* str) { //word can't contain spaces
    return (strcspn(str, " ") == strlen(str)) ? 1 : 0;
}

static int is_string(const char* str) { //any sequence can be string
    return 1;
}

static int is_number(const char* str) {
    if (*str == '-') {
        str++;
        if (!*str) {
            return 0;
        }
    }
 
    size_t digits = strspn(str, "0123456789");
    return (digits == strlen(str) && digits > 0) ? 1 : 0;
}


static int is_ipaddr(const char* str) {
    const char* p = str;
    int i, d_nums, val;
    char tmp[4];

    for (i = 0; i < 4; i++) {
        d_nums = (int)strspn(p, "0123456789");
        if (d_nums == 0 || d_nums > 3) {
            return 0;
        }

        if (d_nums > 1 && *p == '0') {
            return 0;
        }

        memset(tmp, 0, sizeof(tmp));
        memcpy(tmp, p, d_nums);
        val = atoi(tmp);
        if (val < 0 || val > 255) {
            return 0;
        }

        p += d_nums;

        if (i < 3) {
            if (*p != '.') {
                return 0;
            }
            p++;
        }
    }

    return (*p == '\0') ? 1 : 0;
}

static int is_ip6addr(const char* str) {
    const char *p = str;
    int groups = 0;
    int double_colon = 0;

    if (p[0] == ':' && p[1] == ':') {
        double_colon = 1;
        p += 2;
        if (*p == '\0') {
            return 1;
        }
    }

    while (*p) {
        int hex_len = (int)strspn(p, "0123456789abcdefABCDEF");
        if (hex_len == 0 || hex_len > 4) {
            return 0;
        }

        groups++;
        p += hex_len;

        if (*p == '\0') {
            break;
        }

        if (*p == ':') {
            p++;
            if (*p == ':') {
                if (double_colon) {
                    return 0;
                }

                double_colon = 1;
                p++;
                if (*p == '\0') {
                    break;
                }
            } else if (*p == '\0') {
                return 0;
            }
        } else {
            return 0;
        }
    }

    if (double_colon) {
        return (groups <= 7) ? 1 : 0;
    } else {
        return (groups == 8) ? 1 : 0;
    }
}
