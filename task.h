#ifndef TASK_H
#define TASK_H


#ifdef _WIN32
#include <winsock2.h>   /* before windows.h */
#include <windows.h>
#else
#include <pthread.h>
#endif

#include "hash_table.h"
#include "list.h"
#include "deque.h"
#include "defines.h"
#include "utils.h"


#define MAX_TASKS 256
#define MAX_CACHE_TTL 600
#define MAX_DYNAMIC_ENDPOINT_TTL 900 //IMPORTANT: should be greater than MAX_CACHE_TTL

#ifdef _WIN32
#define WAIT_FOR_OBJECT_DELAY 500
#endif




typedef struct fd_tun_map_s fd_tun_map_t;

typedef struct task_s {
    fd_tun_map_t* tun_map;
    //char buffer[SOCKET_SIZE];
    char* buffer;
    uint16_t size;
    int endpoint_flag;
    tunnel_endpoint_t endpoint;
} task_t;

typedef struct worker_s {
#ifdef _WIN32
    HANDLE              thr;
    HANDLE              tun_cache_thr;
    CRITICAL_SECTION    mutex;
    CRITICAL_SECTION    tun_cache_mutex;
    CONDITION_VARIABLE  cond_empty;
#else
    pthread_t           thr;
    pthread_attr_t      attr;
    pthread_mutex_t     mutex;
    pthread_t           tun_cache_thr;
    pthread_attr_t      tun_cache_attr;
    pthread_mutex_t     tun_cache_mutex;
    pthread_cond_t      cond_empty;
#endif
    //task_t              task_buf[MAX_TASKS];
    task_t*              task_buf;
    uint16_t            new_task_idx;
    uint16_t            cur_task_idx;
    hash_table_t*       tun_cache_ht;
    bh_deque_t*         tun_cache_list;
    int                 dyn_endpoints_enabled;
    struct tunnel_entity_s* current_tun;  /* back-pointer for dyn_endpoints_thr */
#ifdef _WIN32
    HANDLE              dyn_endpoints_thr;
    CRITICAL_SECTION    dyn_endpoints_mutex;
#else
    pthread_t           dyn_endpoints_thr;
    pthread_attr_t      dyn_endpoints_attr;
    pthread_mutex_t     dyn_endpoints_mutex;
#endif
} worker_t;

typedef struct tun_cache_s {
    ipv4_addr ip;
    ipv6_addr ip6;
    mac_addr mac;
    bh_list_t* endpoint_list;
    uint16_t ttl;
} tun_cache_t;

void task_create_worker(worker_t* worker, struct tunnel_entity_s* tun);
void task_get_new(worker_t* worker, task_t** task);
void task_release(worker_t* worker);
void task_add(worker_t* worker);
void task_destroy_all_workers();


#endif
