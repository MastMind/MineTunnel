#ifndef TUNNEL_H
#define TUNNEL_H


#include <stdint.h>
#include <net/if.h>
#include <limits.h>

#include "task.h"
#include "hash_table.h"
#include "list.h"
#include "defines.h"




typedef struct opts_s {
    char prog_name[PROG_NAME_LENGTH];
    uint8_t daemonize;
    uint8_t verbose;
    char pidfile_path[PATH_MAX];
    char config_path[PATH_MAX];
} options_t;

typedef struct tun_intf_s {
    int raw_socket_in;
    int raw_socket_out;
    int tun_fd;
    char tun_name[IFNAMSIZ + 1];
    tun_proto_t proto;
    tun_mode_t mode;
} tun_intf_t;

typedef struct enc_entinty_s {
    char name[MAX_ENCRYPTOR_NAME];
    void* shared_library_handle;
    void (*encrypt)(char*, uint32_t);
    void (*decrypt)(char*, uint32_t);
    encryptor_type_t (*get_type)(void);
    int (*set_params)(const char*);
} enc_entinty_t;

typedef struct tunnel_endpoint_s {
    ipv4_addr remote_endpoint;
    uint16_t remote_port;
} tunnel_endpoint_t;

typedef struct tunnel_entity_s {
    ipv4_addr local_endpoint;
    uint16_t local_port;
    uint16_t icmp_identifier;
    hash_table_t* remote_endpoint_ht;
    bh_list_t* remote_endpoint_list;
    tun_intf_t tun_intf;
    char bringup_script[PATH_MAX];
    char shutdown_script[PATH_MAX];
    enc_entinty_t* encryptor;
} tunnel_entity_t;

typedef struct fd_tun_map_s {
    int fd;
    tunnel_entity_t* tun;
    worker_t* worker;
} fd_tun_map_t;

int tunnel_parse_opts(int argc, char** argv);
int tunnel_app_start();
void tunnel_app_stop();

int tunnel_app_getDaemonize();
int tunnel_app_getVerbosity();


#endif
