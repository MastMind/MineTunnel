#ifndef TUNNEL_H
#define TUNNEL_H


#include <stdint.h>
#ifdef _WIN32
#include <winsock2.h>
#include <devguid.h>
#else
#include <net/if.h>
#endif
#include <limits.h>

#include "task.h"
#include "hash_table.h"
#include "list.h"
#include "defines.h"




typedef struct opts_s {
    char prog_name[PROG_NAME_LENGTH];
    uint8_t daemonize;
    uint8_t verbose;
#ifndef _WIN32
    char pidfile_path[PATH_MAX];
#endif
    char config_path[PATH_MAX];
    uint16_t control_port;
} options_t;

typedef struct tun_intf_s {
#ifdef _WIN32
    SOCKET raw_socket_in;
    SOCKET raw_socket_out;
    HANDLE tun_fd;
    GUID   guidAdapter;
    void*  wintun_ctx;
#else
    int raw_socket_in;
    int raw_socket_out;
    int tun_fd;
#endif
    char tun_name[IFNAMSIZ + 1];
    tun_proto_t proto;
    tun_mode_t mode;
} tun_intf_t;

typedef struct enc_entinty_s {
    char name[MAX_ENCRYPTOR_NAME];
    void* shared_library_handle;
    uint32_t (*encrypt)(void*, char*, uint32_t);
    uint32_t (*decrypt)(void*, char*, uint32_t);
    encryptor_type_t (*get_type)(void);
    void* (*create_instance)(const char*);
    void (*destroy_instance)(void*);
} enc_entinty_t;

typedef struct tunnel_entity_s {
    ipv4_addr local_endpoint;
    uint16_t local_port;
    uint16_t icmp_identifier;
    hash_table_t* remote_endpoint_ht;
    bh_list_t* remote_endpoint_list;
    int dynamic_endpoints;
    tun_intf_t tun_intf;
    char bringup_script[PATH_MAX];
    char shutdown_script[PATH_MAX];
    char bringup_embed[EMBED_SCRIPT_PAYLOAD_MAX];
    char shutdown_embed[EMBED_SCRIPT_PAYLOAD_MAX];
    enc_entinty_t* encryptor;
    void* encryptor_instance;
    worker_t* worker;
} tunnel_entity_t;

typedef struct fd_tun_map_s {
    int fd;
    tunnel_entity_t* tun;
} fd_tun_map_t;

/**
 * Parse command line options
 * @param argc Number of command line arguments
 * @param argv Array of command line argument strings
 * @return 0 on success, non-zero on error
 */
int tunnel_parse_opts(int argc, char** argv);

/**
 * Start the tunnel application
 * @return 0 on success, non-zero on error
 */
int tunnel_app_start();

/**
 * Stop the tunnel application
 */
void tunnel_app_stop();

/**
 * Get daemonize flag value
 * @return 1 if daemon mode is enabled, 0 otherwise
 */
int tunnel_app_getDaemonize();

/**
 * Get verbosity flag value
 * @return 1 if verbose mode is enabled, 0 otherwise
 */
int tunnel_app_getVerbosity();

/**
 * Get control socket TCP port (from -l, or the default when unset)
 * @return TCP port number
 */
uint16_t tunnel_app_getControlPort();

/**
 * Collect pointers to all active tunnels into out[] (up to max_out).
 * The tunnel set is immutable after startup, so no locking is required.
 * @return number of tunnels written
 */
int tunnel_collect_all(tunnel_entity_t** out, int max_out);

/**
 * Find an active tunnel by its interface name.
 * @return tunnel pointer or NULL if not found
 */
tunnel_entity_t* tunnel_find_by_name(const char* name);

#ifdef _WIN32
/**
 * Write data asynchronously to TAP interface using IOCP
 * @param tun_fd TAP interface handle
 * @param buf Buffer containing data to write
 * @param size Size of data to write
 */
void iocp_tap_write_async(HANDLE tun_fd, const char* buf, DWORD size);

/**
 * Write data asynchronously to TUN interface
 * @param intf TUN interface structure
 * @param buf Buffer containing data to write
 * @param size Size of data to write
 */
void tun_write_async(tun_intf_t* intf, const char* buf, DWORD size);
#endif


#endif
