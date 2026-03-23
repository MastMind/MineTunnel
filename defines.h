#ifndef DEFINES_H
#define DEFINES_H


#include <limits.h>
#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#else
#include <net/if.h>
#endif
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif




#define PROG_NAME_LENGTH 256
#ifndef _WIN32
#define DEFAULT_PID_FILE "/var/run/minetunnel.pid"
#define DEFAULT_CTL_PATH "/var/run/minetunnel_ctl"
#endif
#define DEFAULT_CONFIG_FILE "config.json"
#define MAX_ENCRYPTOR_NAME 128
#define MAX_DEV_NAME_LENGTH IFNAMSIZ+1
#define MAX_PROTO_LENGTH 8
#define MAX_TUNMODE_LENGTH 4
#define IPV4_ADDR_LENGTH 4
#define IPV6_ADDR_LENGTH 16
#define MAC_ADDR_LENGTH 6
#define PORT_LENGTH 2
#ifdef _WIN32
#define MAX_TUNNELS 64
#define POLLING_TIMEOUT 1000
#else
#define MAX_TUNNELS 256
#define EPOLL_TIMEOUT 5000
#endif

#define MAX_JSON_STR_LENGTH 8192
#define MAX_STR_LENGTH 8192

#define SOCKET_SIZE 262144
#define MAX_SIZE_OF_UDP_PACKET 65536

#define DEFAULT_ICMP_ID 1234

#define APP_NAME "MineTunnel"
#define VERSION_STR "1.0.0"
#define DEFAULT_MINE_TUN_NAME "mine_tun%d"
#define DEFAULT_MINE_TAP_NAME "mine_tap%d"

//network types
typedef union {
    uint32_t value;
    uint8_t addr[IPV4_ADDR_LENGTH];
} ipv4_addr;

typedef union {
    uint8_t addr[IPV6_ADDR_LENGTH];
    uint32_t value[IPV6_ADDR_LENGTH / 4];
} ipv6_addr;

typedef union {
    uint64_t value;
    uint8_t addr[MAC_ADDR_LENGTH];
} mac_addr;

typedef struct tunnel_endpoint_s {
    ipv4_addr remote_endpoint;
    uint16_t remote_port;
    int      is_dynamic;
    int      ttl;
} tunnel_endpoint_t;

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
