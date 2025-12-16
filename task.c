#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <sys/time.h>

#include "tunnel.h"
#include "task.h"
#include "crc.h"
#include "defines.h"
#include "utils.h"




static worker_t* workers[MAX_TUNNELS];
static uint16_t size = 0;

static void *thread_func(void *param);
static void *tun_cache_thread_func(void *param);
static ssize_t prepare_udp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, uint16_t local_port, ipv4_addr remote_endpoint, uint16_t remote_port);
static ssize_t send_udp(int raw_socket, char *sendbuf, uint16_t size);
static ssize_t recv_udp(int tun_socket, char* recvbuf, uint16_t size);
static ssize_t prepare_icmp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, ipv4_addr remote_endpoint, uint16_t id);
static ssize_t send_icmp(int raw_socket, char* sendbuf, uint16_t size);
static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size, ipv4_addr local_endpoint, uint16_t local_port);
static int search_cache(worker_t* worker, const char* buf, uint16_t size, tunnel_entity_t* tun, tunnel_endpoint_t** endpoint);
static void update_cache(worker_t* worker, const char* buf, uint16_t size, tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint);
static unsigned short checksum(void *b, int len);


void task_create_worker(worker_t* worker) {
    if (!worker) {
        return;
    }

    worker->tun_cache_ht = NULL;
    worker->tun_cache_list = NULL;
    pthread_mutex_init(&worker->tun_cache_mutex, NULL);
    pthread_attr_init(&worker->tun_cache_attr);
    pthread_create(&worker->tun_cache_thr, &worker->tun_cache_attr, tun_cache_thread_func, worker);

    worker->new_task_idx = 0;
    worker->cur_task_idx = 0;
    pthread_cond_init(&worker->cond_empty, NULL);

    pthread_mutex_init(&worker->mutex, NULL);

    //init task buf
    memset(worker->task_buf, 0, sizeof(worker->task_buf));

    pthread_attr_init(&worker->attr);
    pthread_create(&worker->thr, &worker->attr, thread_func, worker);

    workers[size] = worker;
    size++;
}

void task_get_new(worker_t* worker, task_t** task) {
    pthread_mutex_lock(&worker->mutex);

    *task = &worker->task_buf[worker->new_task_idx];

    pthread_mutex_unlock(&worker->mutex);
}

void task_add(worker_t* worker) {
    pthread_mutex_lock(&worker->mutex);

    if (worker->new_task_idx == MAX_TASKS - 1) {
        worker->new_task_idx = 0;
    } else {
        ++worker->new_task_idx;
    }

    pthread_cond_signal(&worker->cond_empty); 

    pthread_mutex_unlock(&worker->mutex);
}

void task_destroy_all_workers() {
    for (uint16_t i = 0; i < size; i++) {
        pthread_mutex_unlock(&workers[i]->mutex);

        pthread_cancel(workers[i]->thr);
        pthread_attr_destroy(&workers[i]->attr);

        pthread_cond_destroy(&workers[i]->cond_empty);
        pthread_mutex_destroy(&workers[i]->mutex);

        pthread_cancel(workers[i]->tun_cache_thr);
        pthread_attr_destroy(&workers[i]->tun_cache_attr);
        pthread_mutex_destroy(&workers[i]->tun_cache_mutex);

        hash_table_clear(&workers[i]->tun_cache_ht, free);
        bhdeque_clear(workers[i]->tun_cache_list, NULL);

        free(workers[i]);
    }

    size = 0;
}

static void *thread_func(void *param) {
    worker_t* worker = (worker_t*)param;

    while (1) {
        pthread_mutex_lock(&worker->mutex);

        if (worker->cur_task_idx == worker->new_task_idx) {
#ifdef DEBUG
            fprintf(stdout, "Thread %lu is stoped\n", pthread_self());
#endif
            pthread_cond_wait(&worker->cond_empty, &worker->mutex);
#ifdef DEBUG
            fprintf(stdout, "Thread %lu is resumed\n", pthread_self());
#endif
            pthread_mutex_unlock(&worker->mutex);
            continue;
        }

        //handle task in task_deque_last
        task_t* current_task = &worker->task_buf[worker->cur_task_idx];
        fd_tun_map_t* current_tun_map = current_task->tun_map;
        int fd = current_tun_map->fd;
        tunnel_entity_t* current_tun = current_tun_map->tun;

        if (fd == current_tun->tun_intf.tun_fd) { //this is accepted from tunnel socket (encapsulating)
            //prepare packet for sending via raw_socket_out for each endpoint
            bh_list_t* current_endpoint_list = current_tun->remote_endpoint_list;
            tunnel_endpoint_t* current_endpoint = (tunnel_endpoint_t*)current_endpoint_list->data;
            char send_buf[SOCKET_SIZE];
            uint16_t send_size = 0;

            //check cache by task buffer (search by dst ip or dst mac)
            int cache_flag = search_cache(worker, current_task->buffer, current_task->size, current_tun, &current_endpoint);
#ifdef DEBUG
            fprintf(stdout, "search_cache %u current_endpoint->addr %u.%u.%u.%u:%u\n", cache_flag,
                                                                                current_endpoint->remote_endpoint.addr[0],
                                                                                current_endpoint->remote_endpoint.addr[1],
                                                                                current_endpoint->remote_endpoint.addr[2],
                                                                                current_endpoint->remote_endpoint.addr[3],
                                                                                current_endpoint->remote_port);
#endif
            //encrypt packetbuf if it possible
            enc_entinty_t* current_encryptor = current_tun->encryptor;

            if (current_encryptor) {
                current_task->size = current_encryptor->encrypt(current_tun->encryptor_id, current_task->buffer, current_task->size);
            }

            while (current_endpoint_list) {
                //encapsulating depends of proto
                switch (current_tun->tun_intf.proto) {
                    case PROTO_UDP:
                        send_size = prepare_udp(send_buf, current_task->buffer, current_task->size, current_tun->local_endpoint, current_tun->local_port, current_endpoint->remote_endpoint, current_endpoint->remote_port);
                        send_udp(current_tun->tun_intf.raw_socket_out, send_buf, send_size);
                        break;
                    case PROTO_ICMP:
                        send_size = prepare_icmp(send_buf, current_task->buffer, current_task->size, current_tun->local_endpoint, current_endpoint->remote_endpoint, current_tun->icmp_identifier);
                        send_icmp(current_tun->tun_intf.raw_socket_out, send_buf, send_size);
                        break;
                    default:
                        break;
                }

                if (cache_flag) {
                    break;
                }

                current_endpoint_list = current_endpoint_list->next;
                if (current_endpoint_list) {
                    current_endpoint = (tunnel_endpoint_t*)current_endpoint_list->data;
                }
            }
        }

        if (fd == current_tun->tun_intf.raw_socket_in) { //this is accept from underlay network (decapsulating)
            //decrypt packetbuf if it possible
            enc_entinty_t* current_encryptor = current_tun->encryptor;

            switch (current_tun->tun_intf.proto) {
                case PROTO_UDP:
                    if (current_encryptor) {
                        current_task->size = current_encryptor->decrypt(current_tun->encryptor_id, current_task->buffer, current_task->size);
                    }

                    recv_udp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size);
                    update_cache(worker, current_task->buffer, current_task->size, current_tun, &current_task->endpoint);
                    break;
                case PROTO_ICMP:
                    if (current_encryptor) {
                        current_task->size = current_encryptor->decrypt(current_tun->encryptor_id, current_task->buffer + sizeof(struct ip) + sizeof(struct icmp),
                            current_task->size - (sizeof(struct ip) + sizeof(struct icmp)));
                        current_task->size += sizeof(struct ip) + sizeof(struct icmp);
                    }

                    recv_icmp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size, current_tun->local_endpoint, current_tun->icmp_identifier);
                    //getting endpoint from iph and icmphdr
                    struct ip* iphdr = (struct ip*)current_task->buffer;
                    struct icmp* icmphdr = (struct icmp *)(current_task->buffer + sizeof(struct ip));

                    current_task->endpoint_flag = 1;
                    current_task->endpoint.remote_endpoint.value = iphdr->ip_src.s_addr;
                    current_task->endpoint.remote_port = icmphdr->icmp_id; //id is equal to port in ICMP mode

                    update_cache(worker, current_task->buffer + sizeof(struct ip) + sizeof(struct icmp), current_task->size - (sizeof(struct ip) + sizeof(struct icmp)),
                        current_tun, &current_task->endpoint);
                    break;
                default:
                    break;
            }
        }

        if (worker->cur_task_idx == MAX_TASKS - 1) {
            worker->cur_task_idx = 0;
        } else {
            ++worker->cur_task_idx;
        }

        pthread_mutex_unlock(&worker->mutex);
    }

    pthread_exit(0);
}

static void *tun_cache_thread_func(void *param) {
    worker_t* worker = (worker_t*)param;

    while (1) {
        time_t cur_timestamp = time(NULL);
        sleep(1);

        pthread_mutex_lock(&worker->tun_cache_mutex);
        bh_deque_t* cur_tun_cache_list = worker->tun_cache_list;

        while (cur_tun_cache_list) {
            hash_table_t* cur_hash_table = (hash_table_t*)cur_tun_cache_list->data;
            bh_list_t* internal_list = (bh_list_t*)cur_hash_table->data;
            bh_list_t* prev_internal_list = NULL;
            int del_flag = 0;

            while (internal_list) {
                tun_cache_t* cur_tun_cache = (tun_cache_t*)internal_list->data;

                //current timestamp substraction
                time_t diff_time = time(NULL) - cur_timestamp;
                if (diff_time < 0) { //time overflow case
                    diff_time = 1;
                }

                if (diff_time >= cur_tun_cache->ttl) {
                    //delete this record
                    bh_list_t* next_internal_list = internal_list->next;

                    if (prev_internal_list) {
                        prev_internal_list->next = next_internal_list;
                    }

                    free(cur_tun_cache);
                    free(internal_list);
                    internal_list = next_internal_list;

                    if (!prev_internal_list && !internal_list) {
                        //this was the last record. Need to delete whole hash_table and cache_list record
                        cur_hash_table->data = NULL;
                        if (cur_hash_table == worker->tun_cache_ht) {
                            hash_table_del(&worker->tun_cache_ht, NULL);
                        } else {
                            hash_table_del(&cur_hash_table, NULL);
                        }

                        //delete the cache_list record
                        if (cur_tun_cache_list == worker->tun_cache_list) {
                            bhdeque_erase(&worker->tun_cache_list, NULL);
                            cur_tun_cache_list = worker->tun_cache_list;
                        } else {
                            bhdeque_erase(&cur_tun_cache_list, NULL);
                        }

                        del_flag = 1;
                    }
                } else {
                    cur_tun_cache->ttl -= diff_time;
                    prev_internal_list = internal_list;
                    internal_list = internal_list->next;
                }
            }

            if (cur_tun_cache_list && !del_flag) {
                cur_tun_cache_list = cur_tun_cache_list->next;
            }
        }

        pthread_mutex_unlock(&worker->tun_cache_mutex);
    }

    pthread_exit(0);
}

static ssize_t prepare_udp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, uint16_t local_port, ipv4_addr remote_endpoint, uint16_t remote_port) {
    ssize_t tx_len = 0;
    struct iphdr *iph = (struct iphdr *)sendbuf;
    
    tx_len += sizeof(struct iphdr);

    //fill the IP header:
    iph->ihl = 0x5;
    iph->version = 0x4;
    iph->tos = 0;

    iph->frag_off = 0x40; //Do not fragment
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;

    iph->saddr = htonl(local_endpoint.value);
    iph->daddr = remote_endpoint.value;

    //construct the UDP header:
    struct udphdr *udph = (struct udphdr *)(sendbuf + sizeof(struct iphdr));
    tx_len += sizeof(struct udphdr);

    udph->source = htons(local_port);
    udph->dest = htons(remote_port); 
    udph->check = 0;

    memcpy(sendbuf + tx_len, packet_buf, packet_size);

    tx_len += packet_size;

    udph->len = htons(tx_len - ((int)sizeof(struct iphdr)));
    iph->tot_len = htons(tx_len);
    iph->check = checksum((unsigned short *)sendbuf, tx_len);


    return tx_len;
}

static ssize_t send_udp(int raw_socket, char *sendbuf, uint16_t size) {
    struct sockaddr_in sin;
    struct ip *ip;
    struct udphdr *udph;

    ip = (struct ip *)sendbuf;
    udph = (struct udphdr *)sendbuf + sizeof(struct ip);
    ssize_t tx_len = 0;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = udph->dest;

    memcpy(&sin.sin_addr.s_addr, &ip->ip_dst.s_addr,
           sizeof(ip->ip_dst.s_addr));

    sendbuf += sizeof(struct ip);
    tx_len = sendto(raw_socket, sendbuf, size - sizeof(struct ip),  MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(struct sockaddr));
    
    return tx_len;
}

static ssize_t recv_udp(int tun_socket, char* recvbuf, uint16_t size) {
    return write(tun_socket, recvbuf, size);
}

static ssize_t prepare_icmp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, ipv4_addr remote_endpoint, uint16_t id) {
    ssize_t tx_len = 0;
    struct iphdr *iph = (struct iphdr *)sendbuf;
    
    tx_len += sizeof(struct iphdr);

    //fill the IP header:
    iph->ihl = 0x5;
    iph->version = 0x4;
    iph->tos = 0;

    iph->frag_off = 0x40; //Do not fragment
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;

    iph->saddr = htonl(local_endpoint.value);
    iph->daddr = remote_endpoint.value;

    //construct icmp hdr
    struct icmp *icmp = (struct icmp *)(sendbuf + sizeof(struct iphdr));
    struct timeval *tmp_tv = (struct timeval *)icmp->icmp_data;

    gettimeofday(tmp_tv, NULL);

    tx_len += sizeof(struct icmp);

    icmp->icmp_type = 0x8; // echo request type
    icmp->icmp_code = 0;
    icmp->icmp_id = id;
    icmp->icmp_cksum = 0; // zero field before computing checksum
    icmp->icmp_seq = 0;

    memcpy(sendbuf + tx_len, packet_buf, packet_size);

    tx_len += packet_size;

    iph->tot_len = htons(tx_len);
    iph->check = checksum((unsigned short *)sendbuf, tx_len);

    icmp->icmp_cksum = checksum((unsigned short *)icmp, tx_len - sizeof(struct iphdr));

    return tx_len;

}

static ssize_t send_icmp(int raw_socket, char* sendbuf, uint16_t size) {
    ssize_t tx_len = 0;
    struct sockaddr_in sin;
    struct ip *ip;

    ip = (struct ip *)sendbuf;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;

    memcpy(&sin.sin_addr.s_addr, &ip->ip_dst.s_addr,
           sizeof(ip->ip_dst.s_addr));

    sendbuf += sizeof(struct ip);
    tx_len = sendto(raw_socket, sendbuf, size - sizeof(struct ip),  MSG_DONTWAIT, (struct sockaddr *)&sin, sizeof(struct sockaddr));
    
    return tx_len;
}

static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size, ipv4_addr local_endpoint, uint16_t local_port) {
    struct ip* iphdr = (struct ip*)recvbuf;
    struct icmp* icmphdr = (struct icmp *)(recvbuf + sizeof(struct ip));
    ssize_t tx_len = 0;

    if (local_endpoint.value == iphdr->ip_dst.s_addr &&
        local_port == icmphdr->icmp_id) { //check if it is addresed to the local endpoint
        tx_len = write(tun_socket, recvbuf + sizeof(struct ip) + sizeof(struct icmp), size - (sizeof(struct ip) + sizeof(struct icmp)));
    }

    return tx_len;
}

static int search_cache(worker_t* worker, const char* buf, uint16_t size, tunnel_entity_t* tun, tunnel_endpoint_t** endpoint) {
    tun_intf_t* tun_intf = &tun->tun_intf;
    tun_cache_t cur_tun_cache;
    struct iphdr *iph = (struct iphdr *)buf;
    struct ethhdr *eth = (struct ethhdr *)buf;
    tun_cache_t* tun_cache = NULL;

    switch (tun_intf->mode) {
        case MODE_TUN:
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
            if (iph->version != 0x4) { // This is not IPv4 header
                if (iph->version == 0x6) { // This is IPv6 header
                    struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;

                    memcpy(cur_tun_cache.ip6.addr, endpoint ? &ip6h->ip6_dst : &ip6h->ip6_src, IPV6_ADDR_LENGTH);
                } else {
                    return 0;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = endpoint ? iph->daddr : iph->saddr;
            }

            cur_tun_cache.mac.value = 0;
            break;
        case MODE_TAP:
            cur_tun_cache.ip.value = 0;
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
            memcpy(&cur_tun_cache.mac.value, endpoint ? eth->h_dest : eth->h_source, MAC_ADDR_LENGTH);
            break;
        default:
            PrintInform("The current tun %s has mode which doesn't support caching of endpoints (search cache)", tun_intf->tun_name);
            return 0;
    }

    //search cache for duplicates
    pthread_mutex_lock(&worker->tun_cache_mutex);

    tun_cache = hash_table_find(&worker->tun_cache_ht, &cur_tun_cache, &tun_cache_hash_func, &tun_cache_cmp_func);

    if (tun_cache) {
        tun_cache->ttl = MAX_CACHE_TTL;

        if (endpoint) {
            *endpoint = (tunnel_endpoint_t*)tun_cache->endpoint_list->data;
        }

        pthread_mutex_unlock(&worker->tun_cache_mutex);

        return 1;
    }

    pthread_mutex_unlock(&worker->tun_cache_mutex);

    return 0;
}

static void update_cache(worker_t* worker, const char* buf, uint16_t size, tunnel_entity_t* tun, tunnel_endpoint_t* cur_endpoint) {
    tun_intf_t* tun_intf = &tun->tun_intf;
    tun_cache_t cur_tun_cache;
    struct iphdr *iph = (struct iphdr *)buf;
    struct ethhdr *eth = (struct ethhdr *)buf;
    tun_cache_t* tun_cache = NULL;
    bh_list_t* cur_endpoint_list = NULL;
    bh_list_t* found_endpoint_list = NULL;

    switch (tun_intf->mode) {
        case MODE_TUN:
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
            if (iph->version != 0x4) { // This is not IPv4 header
                if (iph->version == 0x6) { // This is IPv6 header
                    struct ip6_hdr *ip6h = (struct ip6_hdr *)buf;
                    memcpy(cur_tun_cache.ip6.addr, &ip6h->ip6_src, IPV6_ADDR_LENGTH);
                } else {
                    return;
                }
                cur_tun_cache.ip.value = 0;
            } else {
                cur_tun_cache.ip.value = iph->saddr;
            }

            cur_tun_cache.mac.value = 0;
            break;
        case MODE_TAP:
            cur_tun_cache.ip.value = 0;
            memset(cur_tun_cache.ip6.addr, 0, IPV6_ADDR_LENGTH);
            memcpy(&cur_tun_cache.mac.value, eth->h_source, MAC_ADDR_LENGTH);
            break;
        default:
            PrintInform("The current tun %s has mode which doesn't support caching of endpoints (update cache)", tun_intf->tun_name);
            return;
    }

#ifdef DEBUG
            fprintf(stdout, " cur_tun_cache.ip %u.%u.%u.%u\n", cur_tun_cache.ip.addr[0],
                                                                cur_tun_cache.ip.addr[1],
                                                                cur_tun_cache.ip.addr[2],
                                                                cur_tun_cache.ip.addr[3]);
#endif
    if (search_cache(worker, buf, size, tun, NULL)) {
        return;
    }
    //search list in tun list endpoint
    bhlist_push_front(&cur_endpoint_list, cur_endpoint);
    found_endpoint_list = hash_table_find(&tun->remote_endpoint_ht, cur_endpoint_list, &endpoint_hash_func, &endpoint_cmp_func);

    if (!found_endpoint_list) {
        //log internal error
        PrintError("Can't find remote endpoint %u.%u.%u.%u port %u\n", cur_endpoint->remote_endpoint.addr[0],
                                                                        cur_endpoint->remote_endpoint.addr[1],
                                                                        cur_endpoint->remote_endpoint.addr[2],
                                                                        cur_endpoint->remote_endpoint.addr[3],
                                                                        cur_endpoint->remote_port);
        //remove whole cur_endpoint_list
        bhlist_clear(cur_endpoint_list, NULL);
        return;
    }

    //remove whole cur_endpoint_list
    bhlist_clear(cur_endpoint_list, NULL);

    //add to cache
    cur_tun_cache.endpoint_list = found_endpoint_list;
    cur_tun_cache.ttl = MAX_CACHE_TTL;

    tun_cache = (tun_cache_t*)malloc(sizeof(tun_cache_t));
    if (!tun_cache) {
        PrintError("Internal error. Can't allocate memory for new tun_cache record");
        return;
    }

    memcpy(tun_cache, &cur_tun_cache, sizeof(tun_cache_t));

    pthread_mutex_lock(&worker->tun_cache_mutex);

    hash_table_t* cur_hash_table = hash_table_add_r(&worker->tun_cache_ht, tun_cache, &tun_cache_hash_func);
    bhdeque_push_front(&worker->tun_cache_list, cur_hash_table);
#ifdef DEBUG
    tun_cache_t* print_tun_cache = tun_cache;

    fprintf(stdout, "print_tun_cache->ip %u.%u.%u.%u\n", print_tun_cache->ip.addr[0],
                                                        print_tun_cache->ip.addr[1],
                                                        print_tun_cache->ip.addr[2],
                                                        print_tun_cache->ip.addr[3]);
    fprintf(stdout, "print_tun_cache->ttl %u\n", print_tun_cache->ttl);
#endif

    pthread_mutex_unlock(&worker->tun_cache_mutex);
}

static unsigned short checksum(void *buf, int len) {
    unsigned short *p_buf = buf;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2) {
        sum += *p_buf;
        ++p_buf;
    }

    if (len == 1) {
        sum += *(unsigned char *)p_buf;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;

    return result;
}
