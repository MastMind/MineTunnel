#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "list.h"
#include "tunnel.h"
#include "task.h"
#include "utils.h"
#include "crc.h"




int Daemonize() {
    return daemon(1, 0);
}

int CheckRoot() {
    int uid = getuid();
    int euid = geteuid();

#ifdef DEBUG
    fprintf(stdout, "uid %d\n euid %d\n", uid, euid);
#endif

    if (uid < 0 || euid < 0) {
        return -1; //system error
    }
    
    if (uid > 0 || euid > 0) {
        return 1; //this is not root
    }

    return 0;
}

int IsFileExists(const char* filename) {
    return access(filename, F_OK) ? 0 : 1;
}

void ExecScript(const char* filename) {
    pid_t pid = fork();

    if (pid < 0) {
        PrintError("Script %s couldn't be executed. Internal error\n", filename);
        return;
    }

    if (pid) { //this is parent process and it must not execute something
        return;
    }

    char* argv[] = { "/bin/sh", (char*)filename, NULL };
    execv("/bin/sh", argv);

    exit(0);
}

int SetIngoreICMPEcho(int ignore) {
    FILE* f = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    char value[3] = "";

    if (!f) {
        return -1;
    }

    sprintf(value, "%d\n", ignore);
    fwrite(value, sizeof(value), 1, f);

    fclose(f);
#ifdef DEBUG
    fprintf(stdout, "Ingore ICMP Echo turned %s\n", ignore ? "on" : "off");
#endif

    return 0;
}

uint32_t tunnel_hash_func(void* data) {
    tunnel_entity_t* tun = (tunnel_entity_t*)data;

    unsigned char hash_str[IPV4_ADDR_LENGTH + PORT_LENGTH] = { 0 };

    memcpy(hash_str, &tun->local_endpoint.value, IPV4_ADDR_LENGTH);
    memcpy(hash_str + IPV4_ADDR_LENGTH, &tun->local_port, PORT_LENGTH);

    return crc32_calc(hash_str, IPV4_ADDR_LENGTH + PORT_LENGTH);
}

int tunnel_cmp_func(void* arg1, void* arg2) {
    tunnel_entity_t* tun1 = (tunnel_entity_t*)arg1;
    tunnel_entity_t* tun2 = (tunnel_entity_t*)arg2;

    return (tun1->local_endpoint.value == tun2->local_endpoint.value &&
        tun1->local_port == tun2->local_port) ? 0 : 1;
}

uint32_t endpoint_hash_func(void* data) {
    bh_list_t* list_node = (bh_list_t*)data;
    tunnel_endpoint_t* endpoint = (tunnel_endpoint_t*)list_node->data;

    unsigned char hash_str[IPV4_ADDR_LENGTH + PORT_LENGTH] = { 0 };

    memcpy(hash_str, &endpoint->remote_endpoint.value, IPV4_ADDR_LENGTH);
    memcpy(hash_str + IPV4_ADDR_LENGTH, &endpoint->remote_port, PORT_LENGTH);

    return crc32_calc(hash_str, IPV4_ADDR_LENGTH + PORT_LENGTH);
}

int endpoint_cmp_func(void* arg1, void* arg2) {
    bh_list_t* list_node1 = (bh_list_t*)arg1;
    bh_list_t* list_node2 = (bh_list_t*)arg2;
    tunnel_endpoint_t* endpoint1 = (tunnel_endpoint_t*)list_node1->data;
    tunnel_endpoint_t* endpoint2 = (tunnel_endpoint_t*)list_node2->data;

    return (endpoint1->remote_endpoint.value == endpoint2->remote_endpoint.value &&
        endpoint1->remote_port == endpoint2->remote_port) ? 0 : 1;
}

uint32_t tun_map_hash_func(void* data) {
    fd_tun_map_t* tun_map = (fd_tun_map_t*)data;

    return (uint32_t)tun_map->fd;
}

int tun_map_cmp_func(void* arg1, void* arg2) {
    fd_tun_map_t* tun_map_1 = (fd_tun_map_t*)arg1;
    fd_tun_map_t* tun_map_2 = (fd_tun_map_t*)arg2;

    return (tun_map_1->fd == tun_map_2->fd) ? 0 : 1;
}

uint32_t encryptor_hash_func(void* data) {
    enc_entinty_t* encryptor = (enc_entinty_t*)data;

    return crc32_calc((unsigned char*)encryptor->name, strlen(encryptor->name));
}

int encryptor_cmp_func(void* arg1, void* arg2) {
    enc_entinty_t* encryptor1 = (enc_entinty_t*)arg1;
    enc_entinty_t* encryptor2 = (enc_entinty_t*)arg2;

    return strncmp(encryptor1->name, encryptor2->name, MAX_ENCRYPTOR_NAME);
}

uint32_t tun_cache_hash_func(void* data) {
    tun_cache_t* tun_cache = (tun_cache_t*)data;
    unsigned char hash_str[IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH + IPV6_ADDR_LENGTH] = { 0 };

    memcpy(hash_str, &tun_cache->ip.value, IPV4_ADDR_LENGTH);
    memcpy(hash_str + IPV4_ADDR_LENGTH, tun_cache->mac.addr, MAC_ADDR_LENGTH);
    memcpy(hash_str + IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH, tun_cache->ip6.addr, IPV6_ADDR_LENGTH);

    return crc32_calc(hash_str, IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH + IPV6_ADDR_LENGTH);
}

int tun_cache_cmp_func(void* arg1, void* arg2) {
    tun_cache_t* tun_cache1 = (tun_cache_t*)arg1;
    tun_cache_t* tun_cache2 = (tun_cache_t*)arg2;

    return (tun_cache1->ip.value == tun_cache2->ip.value &&
        tun_cache1->mac.value == tun_cache2->mac.value &&
        !memcmp(tun_cache1->ip6.addr, tun_cache2->ip6.addr, IPV6_ADDR_LENGTH)) ? 0 : 1;
}
