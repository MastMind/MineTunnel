#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "include/net_headers.h"
#else
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#endif
#include <sys/time.h>

#include "tunnel.h"
#include "task.h"
#include "crc.h"
#include "defines.h"
#include "utils.h"




#ifdef _WIN32
#ifndef ssize_t
typedef SSIZE_T ssize_t;
#endif
#endif


static worker_t* workers[MAX_TUNNELS];
static uint16_t size = 0;

#ifdef _WIN32
static DWORD WINAPI thread_func(LPVOID param);
static DWORD WINAPI tun_cache_thread_func(LPVOID param);
static DWORD WINAPI dyn_endpoints_thread_func(LPVOID param);
#else
static void *thread_func(void *param);
static void *tun_cache_thread_func(void *param);
static void *dyn_endpoints_thread_func(void *param);
#endif
static void update_remote_endpoints(worker_t* worker, const char* buf, uint16_t size,
                                    tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint);
static void free_remote_endpoint_from_ht(void* data);

static ssize_t prepare_udp(char* sendbuf, char* packet_buf, uint16_t packet_size,
                            ipv4_addr local_endpoint, uint16_t local_port,
                            ipv4_addr remote_endpoint, uint16_t remote_port);
static ssize_t prepare_icmp(char* sendbuf, char* packet_buf, uint16_t packet_size,
                             ipv4_addr local_endpoint, ipv4_addr remote_endpoint,
                             uint16_t id);

#ifdef _WIN32
static ssize_t send_udp(SOCKET raw_socket, char *sendbuf, uint16_t size);
static ssize_t recv_udp(tun_intf_t* intf, char* recvbuf, uint16_t size);
static ssize_t send_icmp(SOCKET raw_socket, char* sendbuf, uint16_t size);
static ssize_t recv_icmp(tun_intf_t* intf, char* recvbuf, uint16_t size,
                         ipv4_addr local_endpoint, uint16_t local_port);
#else
static ssize_t send_udp(int raw_socket, char *sendbuf, uint16_t size);
static ssize_t recv_udp(int tun_socket, char* recvbuf, uint16_t size);
static ssize_t send_icmp(int raw_socket, char* sendbuf, uint16_t size);
static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size,
                         ipv4_addr local_endpoint, uint16_t local_port);
#endif

static int search_cache(worker_t* worker, const char* buf, uint16_t size,
                        tunnel_entity_t* tun, tunnel_endpoint_t** endpoint);
static void update_cache(worker_t* worker, const char* buf, uint16_t size,
                         tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint);
static unsigned short checksum(void *b, int len);

#ifdef _WIN32
#define WORKER_MUTEX_LOCK(w) EnterCriticalSection(&(w)->mutex)
#define WORKER_MUTEX_UNLOCK(w) LeaveCriticalSection(&(w)->mutex)
#define WORKER_CACHE_LOCK(w) EnterCriticalSection(&(w)->tun_cache_mutex)
#define WORKER_CACHE_UNLOCK(w) LeaveCriticalSection(&(w)->tun_cache_mutex)
#define WORKER_COND_WAIT(w) SleepConditionVariableCS(&(w)->cond_empty, &(w)->mutex, INFINITE)
#define WORKER_COND_SIGNAL(w) WakeConditionVariable(&(w)->cond_empty)
#else
#define WORKER_MUTEX_LOCK(w) pthread_mutex_lock(&(w)->mutex)
#define WORKER_MUTEX_UNLOCK(w) pthread_mutex_unlock(&(w)->mutex)
#define WORKER_CACHE_LOCK(w) pthread_mutex_lock(&(w)->tun_cache_mutex)
#define WORKER_CACHE_UNLOCK(w) pthread_mutex_unlock(&(w)->tun_cache_mutex)
#define WORKER_COND_WAIT(w) pthread_cond_wait(&(w)->cond_empty, &(w)->mutex)
#define WORKER_COND_SIGNAL(w) pthread_cond_signal(&(w)->cond_empty)
#endif

#ifdef _WIN32
#define SLEEP_1S() Sleep(1000)
#else
#define SLEEP_1S() sleep(1)
#endif

#ifdef _WIN32
#define DYN_MUTEX_LOCK(w) EnterCriticalSection(&(w)->dyn_endpoints_mutex)
#define DYN_MUTEX_UNLOCK(w) LeaveCriticalSection(&(w)->dyn_endpoints_mutex)
#else
#define DYN_MUTEX_LOCK(w) pthread_mutex_lock(&(w)->dyn_endpoints_mutex)
#define DYN_MUTEX_UNLOCK(w) pthread_mutex_unlock(&(w)->dyn_endpoints_mutex)
#endif


void task_create_worker(worker_t* worker, tunnel_entity_t* tun) {
    if (!worker) {
        return;
    }

    worker->tun_cache_ht = NULL;
    worker->tun_cache_list = NULL;
    worker->new_task_idx = 0;
    worker->cur_task_idx = 0;
    worker->dyn_endpoints_enabled = 0;
    worker->current_tun = NULL;

    //memset(worker->task_buf, 0, sizeof(worker->task_buf));
    worker->task_buf = (task_t*)malloc(sizeof(task_t) * MAX_TASKS);

    for (int i = 0; i < MAX_TASKS; ++i) {
        worker->task_buf[i].buffer = (char*)malloc(SOCKET_SIZE);
        memset(worker->task_buf[i].buffer, 0, SOCKET_SIZE);
    }

#ifdef _WIN32
    InitializeCriticalSection(&worker->mutex);
    InitializeCriticalSection(&worker->tun_cache_mutex);
    InitializeConditionVariable(&worker->cond_empty);

    worker->tun_cache_thr = CreateThread(NULL, 0, tun_cache_thread_func, worker, 0, NULL);
    if (!worker->tun_cache_thr) {
        PrintError("task_create_worker: CreateThread (cache) failed. Code: %lu\n", GetLastError());
        return;
    }

    if (tun->dynamic_endpoints) {
        worker->dyn_endpoints_enabled = 1;
        worker->current_tun = tun;
        InitializeCriticalSection(&worker->dyn_endpoints_mutex);
        worker->dyn_endpoints_thr = CreateThread(NULL, 0, dyn_endpoints_thread_func, worker, 0, NULL);
        if (!worker->dyn_endpoints_thr) {
            PrintError("task_create_worker: CreateThread (dyn_endpoints) failed. Code: %lu\n", GetLastError());
            return;
        }
    }

    worker->thr = CreateThread(NULL, 0, thread_func, worker, 0, NULL);
    if (!worker->thr) {
        PrintError("task_create_worker: CreateThread (worker) failed. Code: %lu\n", GetLastError());
        return;
    }
#else
    pthread_mutex_init(&worker->tun_cache_mutex, NULL);
    pthread_attr_init(&worker->tun_cache_attr);
    pthread_create(&worker->tun_cache_thr, &worker->tun_cache_attr, tun_cache_thread_func, worker);

    if (tun->dynamic_endpoints) {
        worker->dyn_endpoints_enabled = 1;
        worker->current_tun = tun;
        pthread_mutex_init(&worker->dyn_endpoints_mutex, NULL);
        pthread_attr_init(&worker->dyn_endpoints_attr);
        pthread_create(&worker->dyn_endpoints_thr, &worker->dyn_endpoints_attr,
                       dyn_endpoints_thread_func, worker);
    }

    pthread_cond_init(&worker->cond_empty, NULL);
    pthread_mutex_init(&worker->mutex, NULL);
    pthread_attr_init(&worker->attr);
    pthread_create(&worker->thr, &worker->attr, thread_func, worker);
#endif

    workers[size] = worker;
    size++;
}

void task_get_new(worker_t* worker, task_t** task) {
    WORKER_MUTEX_LOCK(worker);
    *task = &worker->task_buf[worker->new_task_idx];
}

void task_add(worker_t* worker) {
    if (worker->new_task_idx == MAX_TASKS - 1) {
        worker->new_task_idx = 0;
    } else {
        ++worker->new_task_idx;
    }

    WORKER_COND_SIGNAL(worker);
    WORKER_MUTEX_UNLOCK(worker);
}

void task_destroy_all_workers() {
    for (uint16_t i = 0; i < size; i++) {
        worker_t* w = workers[i];
        for (uint16_t j = 0; j < MAX_TASKS; ++j) {
            free(w->task_buf[j].buffer);
        }
        free(w->task_buf);
#ifdef _WIN32
        WakeAllConditionVariable(&w->cond_empty);

        if (w->thr) {
            WaitForSingleObject(w->thr, WAIT_FOR_OBJECT_DELAY);
            TerminateThread(w->thr, 0);
            CloseHandle(w->thr);
        }

        if (w->tun_cache_thr) {
            WaitForSingleObject(w->tun_cache_thr, WAIT_FOR_OBJECT_DELAY);
            TerminateThread(w->tun_cache_thr, 0);
            CloseHandle(w->tun_cache_thr);
        }

        if (w->dyn_endpoints_enabled) {
            if (w->dyn_endpoints_thr) {
                WaitForSingleObject(w->dyn_endpoints_thr, WAIT_FOR_OBJECT_DELAY);
                TerminateThread(w->dyn_endpoints_thr, 0);
                CloseHandle(w->dyn_endpoints_thr);
            }
            DeleteCriticalSection(&w->dyn_endpoints_mutex);
        }

        DeleteCriticalSection(&w->mutex);
        DeleteCriticalSection(&w->tun_cache_mutex);
#else
        pthread_mutex_unlock(&w->mutex);

        pthread_cancel(w->thr);
        pthread_attr_destroy(&w->attr);
        pthread_cond_destroy(&w->cond_empty);
        pthread_mutex_destroy(&w->mutex);

        pthread_cancel(w->tun_cache_thr);
        pthread_attr_destroy(&w->tun_cache_attr);
        pthread_mutex_destroy(&w->tun_cache_mutex);

        if (w->dyn_endpoints_enabled) {
            pthread_cancel(w->dyn_endpoints_thr);
            pthread_join(w->dyn_endpoints_thr, NULL);
            pthread_attr_destroy(&w->dyn_endpoints_attr);
            pthread_mutex_destroy(&w->dyn_endpoints_mutex);
        }
#endif

        hash_table_clear(&w->tun_cache_ht, free);
        bhdeque_clear(w->tun_cache_list, NULL);
        free(w);
    }

    size = 0;
}

#ifdef _WIN32
static DWORD WINAPI thread_func(LPVOID param)
#else
static void *thread_func(void *param)
#endif
{
    worker_t* worker = (worker_t*)param;

    while (1) {
        WORKER_MUTEX_LOCK(worker);

        if (worker->cur_task_idx == worker->new_task_idx) {
#ifdef DEBUG
            fprintf(stdout, "Worker thread is idle\n");
#endif
            WORKER_COND_WAIT(worker);
#ifdef DEBUG
            fprintf(stdout, "Worker thread resumed\n");
#endif
            WORKER_MUTEX_UNLOCK(worker);
            continue;
        }

        task_t* current_task = &worker->task_buf[worker->cur_task_idx];
        fd_tun_map_t* current_tun_map = current_task->tun_map;
        tunnel_entity_t* current_tun = current_tun_map->tun;
        enc_entinty_t* current_encryptor = current_tun->encryptor;

#ifdef _WIN32
        int fd = current_tun_map->fd;
        int tun_fd_as_int = (int)(intptr_t)current_tun->tun_intf.tun_fd;
#else
        int fd = current_tun_map->fd;
        int tun_fd_as_int = current_tun->tun_intf.tun_fd;
#endif

        if (fd == tun_fd_as_int) { //this is accepted from tunnel socket (encapsulating)
            if (worker->dyn_endpoints_enabled) {
                DYN_MUTEX_LOCK(worker);
            }

            bh_list_t* current_endpoint_list = current_tun->remote_endpoint_list;
            tunnel_endpoint_t* current_endpoint = current_endpoint_list ?
                                                (tunnel_endpoint_t*)current_endpoint_list->data :
                                                NULL;
            char send_buf[SOCKET_SIZE];
            uint16_t send_size = 0;

            int cache_flag = search_cache(worker, current_task->buffer, current_task->size,
                                          current_tun, &current_endpoint);
#ifdef DEBUG
            if (current_endpoint) {
                fprintf(stdout, "search_cache %u current_endpoint->addr %u.%u.%u.%u:%u\n",
                        cache_flag,
                        current_endpoint->remote_endpoint.addr[0],
                        current_endpoint->remote_endpoint.addr[1],
                        current_endpoint->remote_endpoint.addr[2],
                        current_endpoint->remote_endpoint.addr[3],
                        current_endpoint->remote_port);
            }
#endif

            if (current_encryptor) {
                current_task->size = current_encryptor->encrypt(current_tun->encryptor_instance,
                                                                current_task->buffer,
                                                                current_task->size);
            }

            while (current_endpoint_list) {
                switch (current_tun->tun_intf.proto) {
                    case PROTO_UDP:
                        send_size = prepare_udp(send_buf, current_task->buffer, current_task->size,
                                                current_tun->local_endpoint, current_tun->local_port,
                                                current_endpoint->remote_endpoint, current_endpoint->remote_port);
                        send_udp(current_tun->tun_intf.raw_socket_out, send_buf, send_size);
                        break;
                    case PROTO_ICMP:
                        send_size = prepare_icmp(send_buf, current_task->buffer, current_task->size,
                                                 current_tun->local_endpoint, current_endpoint->remote_endpoint,
                                                 current_tun->icmp_identifier);
                        send_icmp(current_tun->tun_intf.raw_socket_out, send_buf, send_size);
                        break;
                    default:
                        break;
                }

                if (current_endpoint->is_dynamic) {
                    current_endpoint->ttl = MAX_DYNAMIC_ENDPOINT_TTL;
                }

                if (cache_flag) {
                    break;
                }

                current_endpoint_list = current_endpoint_list->next;
                if (current_endpoint_list) {
                    current_endpoint = (tunnel_endpoint_t*)current_endpoint_list->data;
                }
            }

            if (worker->dyn_endpoints_enabled) {
                DYN_MUTEX_UNLOCK(worker);
            }
        }

        if (fd == current_tun->tun_intf.raw_socket_in) { //this is accepted from underlay network (decapsulating)
            switch (current_tun->tun_intf.proto) {
                case PROTO_UDP:
                    if (current_encryptor) {
                        current_task->size = current_encryptor->decrypt(current_tun->encryptor_instance,
                                                                        current_task->buffer,
                                                                        current_task->size);
                    }
#ifdef _WIN32
                    if (!recv_udp(&current_tun->tun_intf, current_task->buffer, current_task->size))
#else
                    if (!recv_udp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size))
#endif
                    {
                        PrintError("Error in receiving UDP datagram\n");
                        break;
                    }

                    if (current_tun->dynamic_endpoints) {
                        update_remote_endpoints(worker, current_task->buffer, current_task->size,
                                                current_tun, &current_task->endpoint);
                    }

                    update_cache(worker, current_task->buffer, current_task->size,
                                 current_tun, &current_task->endpoint);
                    break;

                case PROTO_ICMP: {
                    if (current_encryptor) {
#ifdef _WIN32
                        current_task->size = current_encryptor->decrypt(
                            current_tun->encryptor_instance,
                            current_task->buffer + sizeof(ip_hdr_t) + sizeof(struct icmp),
                            current_task->size - (sizeof(ip_hdr_t) + sizeof(struct icmp)));
                        current_task->size += (uint16_t)(sizeof(ip_hdr_t) + sizeof(struct icmp));
#else
                        current_task->size = current_encryptor->decrypt(
                            current_tun->encryptor_instance,
                            current_task->buffer + sizeof(struct ip) + sizeof(struct icmp),
                            current_task->size - (sizeof(struct ip) + sizeof(struct icmp)));
                        current_task->size += (uint16_t)(sizeof(struct ip) + sizeof(struct icmp));
#endif
                    }

#ifdef _WIN32
                    if (!recv_icmp(&current_tun->tun_intf, current_task->buffer, current_task->size,
                              current_tun->local_endpoint, current_tun->icmp_identifier)) {
                        break;
                    }

                    ip_hdr_t* iphdr = (ip_hdr_t*)current_task->buffer;
                    struct icmp* icmphdr = (struct icmp*)(current_task->buffer + sizeof(ip_hdr_t));

                    current_task->endpoint_flag = 1;
                    current_task->endpoint.remote_endpoint.value = iphdr->ip_src;
                    current_task->endpoint.remote_port = icmphdr->icmp_id;

                    if (current_tun->dynamic_endpoints) {
                        update_remote_endpoints(worker, current_task->buffer, current_task->size,
                                                current_tun, &current_task->endpoint);
                    }

                    update_cache(worker,
                                 current_task->buffer + sizeof(ip_hdr_t) + sizeof(struct icmp),
                                 current_task->size - (uint16_t)(sizeof(ip_hdr_t) + sizeof(struct icmp)),
                                 current_tun, &current_task->endpoint);
#else
                    if (!recv_icmp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size,
                              current_tun->local_endpoint, current_tun->icmp_identifier)) {
                        PrintError("Error in receiving ICMP datagram\n");
                        break;
                    }

                    struct ip* iphdr = (struct ip*)current_task->buffer;
                    struct icmp* icmphdr = (struct icmp*)(current_task->buffer + sizeof(struct ip));

                    current_task->endpoint_flag = 1;
                    current_task->endpoint.remote_endpoint.value = iphdr->ip_src.s_addr;
                    current_task->endpoint.remote_port = icmphdr->icmp_id;

                    if (current_tun->dynamic_endpoints) {
                        update_remote_endpoints(worker, current_task->buffer, current_task->size,
                                                current_tun, &current_task->endpoint);
                    }

                    update_cache(worker,
                                 current_task->buffer + sizeof(struct ip) + sizeof(struct icmp),
                                 current_task->size - (uint16_t)(sizeof(struct ip) + sizeof(struct icmp)),
                                 current_tun, &current_task->endpoint);
#endif
                    break;
                }

                default:
                    break;
            }
        }

        if (worker->cur_task_idx == MAX_TASKS - 1) {
            worker->cur_task_idx = 0;
        } else {
            ++worker->cur_task_idx;
        }

        WORKER_MUTEX_UNLOCK(worker);
    }

#ifdef _WIN32
    return 0;
#else
    pthread_exit(0);
#endif
}

#ifdef _WIN32
static DWORD WINAPI tun_cache_thread_func(LPVOID param)
#else
static void *tun_cache_thread_func(void *param)
#endif
{
    worker_t* worker = (worker_t*)param;

    while (1) {
        time_t cur_timestamp = time(NULL);
        SLEEP_1S();

        WORKER_CACHE_LOCK(worker);
        bh_deque_t* cur_tun_cache_list = worker->tun_cache_list;

        while (cur_tun_cache_list) {
            hash_table_t* cur_hash_table = (hash_table_t*)cur_tun_cache_list->data;
            bh_list_t* internal_list = (bh_list_t*)cur_hash_table->data;
            bh_list_t* prev_internal_list = NULL;
            int del_flag = 0;

            while (internal_list) {
                tun_cache_t* cur_tun_cache = (tun_cache_t*)internal_list->data;

                time_t diff_time = time(NULL) - cur_timestamp;
                if (diff_time < 0) { //time overflow case
                    diff_time = 1;
                }

                if (diff_time >= cur_tun_cache->ttl) {
                    bh_list_t* next_internal_list = internal_list->next;

                    if (prev_internal_list) {
                        prev_internal_list->next = next_internal_list;
                    } else {
                        cur_hash_table->data = next_internal_list;
                    }

                    free(cur_tun_cache);
                    free(internal_list);
                    internal_list = next_internal_list;

                    if (!prev_internal_list && !internal_list) {
                        cur_hash_table->data = NULL;
                        if (cur_hash_table == worker->tun_cache_ht) {
                            hash_table_del(&worker->tun_cache_ht, NULL);
                        } else {
                            hash_table_del(&cur_hash_table, NULL);
                        }

                        if (cur_tun_cache_list == worker->tun_cache_list) {
                            bhdeque_erase(&worker->tun_cache_list, NULL);
                            cur_tun_cache_list = worker->tun_cache_list;
                        } else {
                            bhdeque_erase(&cur_tun_cache_list, NULL);
                        }

                        del_flag = 1;
                    }
                } else {
                    cur_tun_cache->ttl -= (uint16_t)diff_time;
                    prev_internal_list = internal_list;
                    internal_list = internal_list->next;
                }
            }

            if (cur_tun_cache_list && !del_flag) {
                cur_tun_cache_list = cur_tun_cache_list->next;
            }
        }

        WORKER_CACHE_UNLOCK(worker);
    }

#ifdef _WIN32
    return 0;
#else
    pthread_exit(0);
#endif
}

static ssize_t prepare_udp(char* sendbuf, char* packet_buf, uint16_t packet_size,
                            ipv4_addr local_endpoint, uint16_t local_port,
                            ipv4_addr remote_endpoint, uint16_t remote_port) {
    ssize_t tx_len = 0;

#ifdef _WIN32
    ip_hdr_t* iph = (ip_hdr_t*)sendbuf;
    tx_len += sizeof(ip_hdr_t);

    iph->ip_vhl = IP_VHL(4, 20);
    iph->ip_tos = 0;
    iph->ip_off = htons(IP_DF);
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_UDP;
    iph->ip_src = htonl(local_endpoint.value);
    iph->ip_dst = remote_endpoint.value;

    udp_hdr_t* udph = (udp_hdr_t*)(sendbuf + sizeof(ip_hdr_t));
    tx_len += sizeof(udp_hdr_t);

    udph->uh_sport = htons(local_port);
    udph->uh_dport = htons(remote_port);
    udph->uh_sum = 0;

    memcpy(sendbuf + tx_len, packet_buf, packet_size);
    tx_len += packet_size;

    udph->uh_ulen = htons((uint16_t)(tx_len - sizeof(ip_hdr_t)));
    iph->ip_len = htons((uint16_t)tx_len);
    iph->ip_sum = 0;
    iph->ip_sum = checksum(sendbuf, (int)tx_len);
#else
    struct iphdr* iph = (struct iphdr*)sendbuf;
    tx_len += sizeof(struct iphdr);

    iph->ihl = 0x5;
    iph->version = 0x4;
    iph->tos = 0;
    iph->frag_off = 0x40;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = htonl(local_endpoint.value);
    iph->daddr = remote_endpoint.value;

    struct udphdr* udph = (struct udphdr*)(sendbuf + sizeof(struct iphdr));
    tx_len += sizeof(struct udphdr);

    udph->source = htons(local_port);
    udph->dest = htons(remote_port);
    udph->check = 0;

    memcpy(sendbuf + tx_len, packet_buf, packet_size);
    tx_len += packet_size;

    udph->len = htons((uint16_t)(tx_len - sizeof(struct iphdr)));
    iph->tot_len = htons((uint16_t)tx_len);
    iph->check = checksum((unsigned short*)sendbuf, (int)tx_len);
#endif

    return tx_len;
}

static ssize_t prepare_icmp(char* sendbuf, char* packet_buf, uint16_t packet_size,
                             ipv4_addr local_endpoint, ipv4_addr remote_endpoint,
                             uint16_t id) {
    ssize_t tx_len = 0;

#ifdef _WIN32
    ip_hdr_t* iph = (ip_hdr_t*)sendbuf;
    tx_len += sizeof(ip_hdr_t);

    iph->ip_vhl = IP_VHL(4, 20);
    iph->ip_tos = 0;
    iph->ip_off = htons(IP_DF);
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_ICMP;
    iph->ip_src = htonl(local_endpoint.value);
    iph->ip_dst = remote_endpoint.value;

    struct icmp* icmph = (struct icmp*)(sendbuf + sizeof(ip_hdr_t));
    tx_len += sizeof(struct icmp);

    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    // icmph->icmp_id    = htons(id);
    icmph->icmp_id = id;
    icmph->icmp_seq = 0;
    icmph->icmp_cksum = 0;

    struct timeval* tmp_tv = (struct timeval*)icmph + sizeof(struct icmp);
    gettimeofday(tmp_tv, NULL);

    memcpy(sendbuf + tx_len, packet_buf, packet_size);
    tx_len += packet_size;

    iph->ip_len = htons((uint16_t)tx_len);
    iph->ip_sum = 0;
    iph->ip_sum = checksum(sendbuf, (int)tx_len);
    icmph->icmp_cksum = checksum((unsigned short*)icmph,
                                  (int)(tx_len - sizeof(ip_hdr_t)));
#else
    struct iphdr* iph = (struct iphdr*)sendbuf;
    tx_len += sizeof(struct iphdr);

    iph->ihl = 0x5;
    iph->version = 0x4;
    iph->tos = 0;
    iph->frag_off = 0x40;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr = htonl(local_endpoint.value);
    iph->daddr = remote_endpoint.value;

    struct icmp* icmph = (struct icmp*)(sendbuf + sizeof(struct iphdr));
    struct timeval* tmp_tv = (struct timeval*)icmph->icmp_data;
    gettimeofday(tmp_tv, NULL);

    tx_len += sizeof(struct icmp);

    icmph->icmp_type = 0x8;
    icmph->icmp_code = 0;
    icmph->icmp_id = id;
    icmph->icmp_cksum = 0;
    icmph->icmp_seq = 0;

    memcpy(sendbuf + tx_len, packet_buf, packet_size);
    tx_len += packet_size;

    iph->tot_len = htons((uint16_t)tx_len);
    iph->check = checksum((unsigned short*)sendbuf, (int)tx_len);
    icmph->icmp_cksum = checksum((unsigned short*)icmph,
                                  (int)(tx_len - sizeof(struct iphdr)));
#endif

    return tx_len;
}

#ifdef _WIN32
static ssize_t send_udp(SOCKET raw_socket, char *sendbuf, uint16_t size)
#else
static ssize_t send_udp(int raw_socket, char *sendbuf, uint16_t size)
#endif
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;

#ifdef _WIN32
    ip_hdr_t* ip = (ip_hdr_t*)sendbuf;
    udp_hdr_t* udph = (udp_hdr_t*)(sendbuf + sizeof(ip_hdr_t));

    sin.sin_port = udph->uh_dport;
    sin.sin_addr.s_addr = ip->ip_dst;

    sendbuf += sizeof(ip_hdr_t);
    return (ssize_t)sendto(raw_socket, sendbuf, size - (int)sizeof(ip_hdr_t),
                           0, (struct sockaddr*)&sin, sizeof(struct sockaddr));
#else
    struct ip* ip = (struct ip*)sendbuf;
    struct udphdr* udph = (struct udphdr*)(sendbuf + sizeof(struct ip));

    sin.sin_port = udph->dest;
    memcpy(&sin.sin_addr.s_addr, &ip->ip_dst.s_addr, sizeof(ip->ip_dst.s_addr));

    sendbuf += sizeof(struct ip);
    return sendto(raw_socket, sendbuf, size - sizeof(struct ip),
                  MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(struct sockaddr));
#endif
}

#ifdef _WIN32
static ssize_t recv_udp(tun_intf_t* intf, char* recvbuf, uint16_t size)
#else
static ssize_t recv_udp(int tun_socket, char* recvbuf, uint16_t size)
#endif
{
#ifdef _WIN32
    tun_write_async(intf, recvbuf, (DWORD)size);
    return (ssize_t)size;
#else
    return write(tun_socket, recvbuf, size);
#endif
}

#ifdef _WIN32
static ssize_t send_icmp(SOCKET raw_socket, char* sendbuf, uint16_t size)
#else
static ssize_t send_icmp(int raw_socket, char* sendbuf, uint16_t size)
#endif
{
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;

#ifdef _WIN32
    ip_hdr_t* ip = (ip_hdr_t*)sendbuf;
    sin.sin_addr.s_addr = ip->ip_dst;

    sendbuf += sizeof(ip_hdr_t);
    return sendto(raw_socket, sendbuf, size - sizeof(ip_hdr_t),
                           0, (struct sockaddr*)&sin, sizeof(struct sockaddr));
#else
    struct ip* ip = (struct ip*)sendbuf;
    memcpy(&sin.sin_addr.s_addr, &ip->ip_dst.s_addr, sizeof(ip->ip_dst.s_addr));

    sendbuf += sizeof(struct ip);
    return sendto(raw_socket, sendbuf, size - sizeof(struct ip),
                  MSG_DONTWAIT, (struct sockaddr*)&sin, sizeof(struct sockaddr));
#endif
}

#ifdef _WIN32
static ssize_t recv_icmp(tun_intf_t* intf, char* recvbuf, uint16_t size,
                         ipv4_addr local_endpoint, uint16_t local_port)
#else
static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size,
                         ipv4_addr local_endpoint, uint16_t local_port)
#endif
{
#ifdef _WIN32
    ip_hdr_t* iphdr = (ip_hdr_t*)recvbuf;
    struct icmp* icmphdr = (struct icmp*)(recvbuf + sizeof(ip_hdr_t));

    if (IP_VERSION(iphdr) != 4) {
        return 0;
    }

    if (iphdr->ip_p != IPPROTO_ICMP) {
        return 0;
    }

    if ((local_endpoint.value && local_endpoint.value != iphdr->ip_dst) ||
        local_port != icmphdr->icmp_id) {
        return 0;
    }

    char* payload = recvbuf + sizeof(ip_hdr_t) + sizeof(struct icmp);
    DWORD payload_size = size - (DWORD)(sizeof(ip_hdr_t) + sizeof(struct icmp));

    tun_write_async(intf, payload, payload_size);
    return (ssize_t)payload_size;
#else
    struct ip* iphdr = (struct ip*)recvbuf;
    struct icmp* icmphdr = (struct icmp*)(recvbuf + sizeof(struct ip));

    if (local_endpoint.value == iphdr->ip_dst.s_addr &&
        local_port == icmphdr->icmp_id) {
        return write(tun_socket,
                     recvbuf + sizeof(struct ip) + sizeof(struct icmp),
                     size - (sizeof(struct ip) + sizeof(struct icmp)));
    }
    return 0;
#endif
}

static int search_cache(worker_t* worker, const char* buf, uint16_t size,
                        tunnel_entity_t* tun, tunnel_endpoint_t** endpoint) {
    tun_intf_t* tun_intf = &tun->tun_intf;
    tun_cache_t cur_tun_cache;
    tun_cache_t* tun_cache = NULL;

#ifdef _WIN32
    ip_hdr_t* iph = (ip_hdr_t*)buf;
    ip6_hdr_t* ip6h = NULL;
    ether_hdr_t* eth = (ether_hdr_t*)buf;
#else
    struct iphdr* iph  = (struct iphdr*)buf;
    struct ip6_hdr* ip6h = NULL;
    struct ethhdr* eth  = (struct ethhdr*)buf;
#endif

    switch (tun_intf->mode) {
        case MODE_TUN:
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
#ifdef _WIN32
            if (IP_VERSION(iph) != 0x4) {
                if (IP_VERSION(iph) == 0x6) {
                    ip6h = (ip6_hdr_t*)buf;
                    memcpy(cur_tun_cache.ip6.addr,
                           endpoint ? &ip6h->ip6_dst : &ip6h->ip6_src,
                           IPV6_ADDR_LENGTH);
                } else {
                    return 0;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = endpoint ? iph->ip_dst : iph->ip_src;
            }
#else
            if (iph->version != 0x4) {
                if (iph->version == 0x6) {
                    ip6h = (struct ip6_hdr*)buf;
                    memcpy(cur_tun_cache.ip6.addr,
                           endpoint ? &ip6h->ip6_dst : &ip6h->ip6_src,
                           IPV6_ADDR_LENGTH);
                } else {
                    return 0;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = endpoint ? iph->daddr : iph->saddr;
            }
#endif
            cur_tun_cache.mac.value = 0;
            break;

        case MODE_TAP:
            cur_tun_cache.ip.value = 0;
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
#ifdef _WIN32
            memcpy(cur_tun_cache.mac.addr,
                   endpoint ? eth->ether_dhost : eth->ether_shost,
                   MAC_ADDR_LENGTH);
#else
            memcpy(cur_tun_cache.mac.addr,
                   endpoint ? eth->h_dest : eth->h_source,
                   MAC_ADDR_LENGTH);
#endif
            break;

        default:
            PrintInform("The current tun %s has mode which doesn't support caching of endpoints (search cache)",
                        tun_intf->tun_name);
            return 0;
    }

    WORKER_CACHE_LOCK(worker);
    tun_cache = hash_table_find(&worker->tun_cache_ht, &cur_tun_cache,
                                &tun_cache_hash_func, &tun_cache_cmp_func);
    if (tun_cache) {
        tun_cache->ttl = MAX_CACHE_TTL;
        if (endpoint) {
            *endpoint = (tunnel_endpoint_t*)tun_cache->endpoint_list->data;
        }
        WORKER_CACHE_UNLOCK(worker);
        return 1;
    }

    WORKER_CACHE_UNLOCK(worker);
    return 0;
}

static void update_cache(worker_t* worker, const char* buf, uint16_t size,
                         tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint) {
    tun_intf_t* tun_intf = &tun->tun_intf;
    tun_cache_t cur_tun_cache;
    tun_cache_t* tun_cache = NULL;
    bh_list_t* cur_endpoint_list = NULL;
    bh_list_t* found_endpoint_list = NULL;

#ifdef _WIN32
    ip_hdr_t* iph = (ip_hdr_t*)buf;
    ip6_hdr_t* ip6h = NULL;
    ether_hdr_t* eth = (ether_hdr_t*)buf;
#else
    struct iphdr* iph = (struct iphdr*)buf;
    struct ip6_hdr* ip6h = NULL;
    struct ethhdr* eth  = (struct ethhdr*)buf;
#endif

    switch (tun_intf->mode) {
        case MODE_TUN:
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
#ifdef _WIN32
            if (IP_VERSION(iph) != 0x4) {
                if (IP_VERSION(iph) == 0x6) {
                    ip6h = (ip6_hdr_t*)buf;
                    memcpy(cur_tun_cache.ip6.addr, &ip6h->ip6_src, IPV6_ADDR_LENGTH);
                } else {
                    return;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = iph->ip_src;
            }
#else
            if (iph->version != 0x4) {
                if (iph->version == 0x6) {
                    ip6h = (struct ip6_hdr*)buf;
                    memcpy(cur_tun_cache.ip6.addr, &ip6h->ip6_src, IPV6_ADDR_LENGTH);
                } else {
                    return;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = iph->saddr;
            }
#endif
            cur_tun_cache.mac.value = 0;
            break;

        case MODE_TAP:
            cur_tun_cache.ip.value = 0;
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
#ifdef _WIN32
            memcpy(cur_tun_cache.mac.addr, eth->ether_shost, MAC_ADDR_LENGTH);
#else
            memcpy(cur_tun_cache.mac.addr, eth->h_source, MAC_ADDR_LENGTH);
#endif
            break;

        default:
            PrintInform("The current tun %s has mode which doesn't support caching of endpoints (update cache)",
                        tun_intf->tun_name);
            return;
    }

#ifdef DEBUG
    fprintf(stdout, "update_cache: ip %u.%u.%u.%u\n",
            cur_tun_cache.ip.addr[0], cur_tun_cache.ip.addr[1],
            cur_tun_cache.ip.addr[2], cur_tun_cache.ip.addr[3]);
#endif

    if (search_cache(worker, buf, size, tun, NULL)) {
        return;
    }

    if (worker->dyn_endpoints_enabled) {
        DYN_MUTEX_LOCK(worker);
    }

    bhlist_push_front(&cur_endpoint_list, cur_endpoint);
    found_endpoint_list = hash_table_find(&tun->remote_endpoint_ht, cur_endpoint_list,
                                          &endpoint_hash_func, &endpoint_cmp_func);
    if (!found_endpoint_list) {
        PrintError("Can't find remote endpoint %u.%u.%u.%u port %u\n",
                   cur_endpoint->remote_endpoint.addr[0],
                   cur_endpoint->remote_endpoint.addr[1],
                   cur_endpoint->remote_endpoint.addr[2],
                   cur_endpoint->remote_endpoint.addr[3],
                   cur_endpoint->remote_port);
        bhlist_clear(cur_endpoint_list, NULL);
        if (worker->dyn_endpoints_enabled) {
            DYN_MUTEX_UNLOCK(worker);
        }
        return;
    }

    bhlist_clear(cur_endpoint_list, NULL);

    cur_tun_cache.endpoint_list = found_endpoint_list;
    cur_tun_cache.ttl = MAX_CACHE_TTL;

    if (worker->dyn_endpoints_enabled) {
        DYN_MUTEX_UNLOCK(worker);
    }

    tun_cache = (tun_cache_t*)malloc(sizeof(tun_cache_t));
    if (!tun_cache) {
        PrintError("Internal error. Can't allocate memory for new tun_cache record");
        return;
    }

    memcpy(tun_cache, &cur_tun_cache, sizeof(tun_cache_t));

    WORKER_CACHE_LOCK(worker);
    hash_table_t* cur_hash_table = hash_table_add_r(&worker->tun_cache_ht, tun_cache,
                                                     &tun_cache_hash_func);
    bhdeque_push_front(&worker->tun_cache_list, cur_hash_table);

#ifdef DEBUG
    fprintf(stdout, "update_cache: added ip %u.%u.%u.%u ttl %u\n",
            tun_cache->ip.addr[0], tun_cache->ip.addr[1],
            tun_cache->ip.addr[2], tun_cache->ip.addr[3],
            tun_cache->ttl);
#endif
    WORKER_CACHE_UNLOCK(worker);
}

static void free_remote_endpoint_from_ht(void* data) {
    bh_list_t* element = (bh_list_t*)data;
    if (element->data) {
        free(element->data);
    }
    free(element);
}

static void update_remote_endpoints(worker_t* worker, const char* buf, uint16_t size,
                                    tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint) {
    DYN_MUTEX_LOCK(worker);

    bh_list_t* cur_endpoint_list = NULL;
    bhlist_push_front(&cur_endpoint_list, cur_endpoint);
    bh_list_t* found_endpoint_list = hash_table_find(&tun->remote_endpoint_ht, cur_endpoint_list,
                                                     &endpoint_hash_func, &endpoint_cmp_func);
    bhlist_clear(cur_endpoint_list, NULL);
    cur_endpoint_list = NULL;

    if (found_endpoint_list) {
        tunnel_endpoint_t* found_endpoint = (tunnel_endpoint_t*)found_endpoint_list->data;
        if (found_endpoint->is_dynamic) {
#ifdef DEBUG
            PrintInform("update_remote_endpoints: updated ttl for %u.%u.%u.%u:%u\n",
                found_endpoint->remote_endpoint.addr[0], found_endpoint->remote_endpoint.addr[1],
                found_endpoint->remote_endpoint.addr[2], found_endpoint->remote_endpoint.addr[3],
                found_endpoint->remote_port);
#endif
            found_endpoint->ttl = MAX_DYNAMIC_ENDPOINT_TTL;
        } else {
            DYN_MUTEX_UNLOCK(worker);
            return;
        }
    } else {
        tunnel_endpoint_t* new_endpoint = (tunnel_endpoint_t*)malloc(sizeof(tunnel_endpoint_t));
        if (!new_endpoint) {
            PrintError("update_remote_endpoints: can't alloc memory for %u.%u.%u.%u:%u\n",
                cur_endpoint->remote_endpoint.addr[0], cur_endpoint->remote_endpoint.addr[1],
                cur_endpoint->remote_endpoint.addr[2], cur_endpoint->remote_endpoint.addr[3],
                cur_endpoint->remote_port);
            DYN_MUTEX_UNLOCK(worker);
            return;
        }

        memcpy(new_endpoint, cur_endpoint, sizeof(tunnel_endpoint_t));
        new_endpoint->is_dynamic = 1;
        new_endpoint->ttl = MAX_DYNAMIC_ENDPOINT_TTL;

        bhlist_push_front(&tun->remote_endpoint_list, new_endpoint);
        hash_table_add(&tun->remote_endpoint_ht, tun->remote_endpoint_list, &endpoint_hash_func);

        PrintInform("Registered new dynamic endpoint %u.%u.%u.%u:%u\n",
                    cur_endpoint->remote_endpoint.addr[0], cur_endpoint->remote_endpoint.addr[1],
                    cur_endpoint->remote_endpoint.addr[2], cur_endpoint->remote_endpoint.addr[3],
                    cur_endpoint->remote_port);

        WORKER_CACHE_LOCK(worker);
        hash_table_clear(&worker->tun_cache_ht, free);
        bhdeque_clear(worker->tun_cache_list, NULL);
        worker->tun_cache_ht = NULL;
        worker->tun_cache_list = NULL;
        WORKER_CACHE_UNLOCK(worker);
    }

    DYN_MUTEX_UNLOCK(worker);
}

#ifdef _WIN32
static DWORD WINAPI dyn_endpoints_thread_func(LPVOID param)
#else
static void *dyn_endpoints_thread_func(void *param)
#endif
{
    worker_t* worker = (worker_t*)param;
    tunnel_entity_t* tun = worker->current_tun;

    while (1) {
        time_t cur_timestamp = time(NULL);
        SLEEP_1S();

        DYN_MUTEX_LOCK(worker);
        bh_list_t* cur_remote_endpoint_list = tun->remote_endpoint_list;
        bh_list_t* prev_remote_endpoint_list = NULL;

        while (cur_remote_endpoint_list) {
            tunnel_endpoint_t* cur_remote_endpoint =
                (tunnel_endpoint_t*)cur_remote_endpoint_list->data;

            if (!cur_remote_endpoint->is_dynamic) {
                prev_remote_endpoint_list = cur_remote_endpoint_list;
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            time_t diff_time = time(NULL) - cur_timestamp;
            if (diff_time < 0) {
                diff_time = 1;
            }

            if (diff_time >= cur_remote_endpoint->ttl) {
                bh_list_t* tmp_next = cur_remote_endpoint_list->next;

                if (cur_remote_endpoint_list == tun->remote_endpoint_list) {
                    tun->remote_endpoint_list = tmp_next;
                }
                if (prev_remote_endpoint_list) {
                    prev_remote_endpoint_list->next = tmp_next;
                }

                PrintInform("Delete dynamic endpoint %u.%u.%u.%u:%u\n",
                    cur_remote_endpoint->remote_endpoint.addr[0],
                    cur_remote_endpoint->remote_endpoint.addr[1],
                    cur_remote_endpoint->remote_endpoint.addr[2],
                    cur_remote_endpoint->remote_endpoint.addr[3],
                    cur_remote_endpoint->remote_port);

                WORKER_CACHE_LOCK(worker);
                hash_table_clear(&worker->tun_cache_ht, free);
                bhdeque_clear(worker->tun_cache_list, NULL);
                worker->tun_cache_ht = NULL;
                worker->tun_cache_list = NULL;
                WORKER_CACHE_UNLOCK(worker);

                hash_table_del_element(&tun->remote_endpoint_ht, cur_remote_endpoint_list,
                                       &endpoint_hash_func, &endpoint_cmp_func,
                                       &free_remote_endpoint_from_ht);
                cur_remote_endpoint_list = tmp_next;
                continue;
            } else {
                cur_remote_endpoint->ttl -= (uint16_t)diff_time;
            }

            prev_remote_endpoint_list = cur_remote_endpoint_list;
            cur_remote_endpoint_list = cur_remote_endpoint_list->next;
        }

        DYN_MUTEX_UNLOCK(worker);
    }

#ifdef _WIN32
    return 0;
#else
    pthread_exit(0);
#endif
}

static unsigned short checksum(void *buf, int len) {
    unsigned short* p_buf = (unsigned short*)buf;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *p_buf++;
    }

    if (len == 1) {
        sum += *(unsigned char*)p_buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = (unsigned short)(~sum);

    return result;
}
