#ifndef DEFINES_H
#define DEFINES_H


#include <limits.h>
#include <stdint.h>
#include <net/if.h>




#define PROG_NAME_LENGTH 256
#define DEFAULT_PID_FILE "/var/run/minetunnel.pid"
#define DEFAULT_CTL_PATH "/var/run/minetunnel_ctl"
#define DEFAULT_CONFIG_FILE "config.json"
#define MAX_ENCRYPTOR_NAME 128
#define MAX_DEV_NAME_LENGTH IFNAMSIZ+1
#define MAX_PROTO_LENGTH 8
#define MAX_TUNMODE_LENGTH 4
#define IPV4_ADDR_LENGTH 4
#define PORT_LENGTH 2
#define MAX_TUNNELS 256
#define EPOLL_TIMEOUT 5000

#define MAX_JSON_STR_LENGTH 8192
#define MAX_STR_LENGTH 8192

#define SOCKET_SIZE 262144
#define MAX_SIZE_OF_UDP_PACKET 65536

#define DEFAULT_ICMP_ID 1234

#define APP_NAME "MineTunnel"
#define DEFAULT_MINE_TUN_NAME "mine_tun%d"
#define DEFAULT_MINE_TAP_NAME "mine_tap%d"

//network types
typedef union {
    uint32_t value;
    uint8_t addr[4];
} ipv4_addr;

typedef enum tun_proto_e {
    PROTO_NONE = 0,
    // PROTO_TCP, //TODO for future usage
    PROTO_UDP,
    PROTO_ICMP
} tun_proto_t;

typedef enum tun_mode_e {
    MODE_UNKNOWN = 0,
    MODE_TUN,
    MODE_TAP
} tun_mode_t;

typedef enum encryptor_type_e {
    ENCRYPTOR_UNKNOWN = 0,
    ENCRYPTOR_SYMMETRIC,
    ENCRYPTOR_ASYMMETRIC //TODO for future usage
} encryptor_type_t;


#endif
