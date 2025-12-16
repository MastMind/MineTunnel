#ifndef TASK_H
#define TASK_H


#include "hash_table.h"
#include "list.h"
#include "deque.h"
#include "defines.h"
#include "utils.h"


#define MAX_TASKS 1024
#define MAX_CACHE_TTL 60




typedef struct fd_tun_map_s fd_tun_map_t;

typedef struct task_s {
    fd_tun_map_t* tun_map;
    char buffer[SOCKET_SIZE];
    uint16_t size;
    int endpoint_flag;
    tunnel_endpoint_t endpoint;
} task_t;

typedef struct worker_s {
    pthread_t thr;
    pthread_attr_t attr;
    pthread_mutex_t mutex;
    pthread_t tun_cache_thr;
    pthread_attr_t tun_cache_attr;
    pthread_mutex_t tun_cache_mutex;
    pthread_cond_t cond_empty;
    task_t task_buf[MAX_TASKS];
    uint16_t new_task_idx;
    uint16_t cur_task_idx;
    hash_table_t* tun_cache_ht;
    bh_deque_t* tun_cache_list;
} worker_t;

typedef struct tun_cache_s {
    ipv4_addr ip;
    ipv6_addr ip6;
    mac_addr mac;
    bh_list_t* endpoint_list;
    uint16_t ttl;
} tun_cache_t;

void task_create_worker(worker_t* worker);
void task_get_new(worker_t* worker, task_t** task);
void task_add(worker_t* worker);
void task_destroy_all_workers();


#endif
