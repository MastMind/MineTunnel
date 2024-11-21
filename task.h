#ifndef TASK_H
#define TASK_H


#include "tunnel.h"
#include "defines.h"


#define MAX_TASKS 1024




typedef struct fd_tun_map_s fd_tun_map_t;

typedef struct task_s {
    fd_tun_map_t* tun_map;
    char buffer[SOCKET_SIZE];
    uint16_t size;
} task_t;

typedef struct worker_s {
    pthread_t thr;
    pthread_attr_t attr;
    pthread_mutex_t mutex;
    pthread_cond_t cond_empty;
    task_t task_buf[MAX_TASKS];
    uint16_t new_task_idx;
    uint16_t cur_task_idx;
} worker_t;

void task_create_worker(worker_t* worker);
void task_get_new(worker_t* worker, task_t** task);
void task_add(worker_t* worker);
void task_destroy_all_workers();


#endif
