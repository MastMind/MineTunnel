#include <pthread.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>

#include "tunnel.h"
#include "task.h"
#include "defines.h"
#include "utils.h"




static worker_t* workers[MAX_TUNNELS];
static uint16_t size = 0;

static void *thread_func(void *param);
static ssize_t prepare_udp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, uint16_t local_port, ipv4_addr remote_endpoint, uint16_t remote_port);
static ssize_t send_udp(int raw_socket, char *sendbuf, uint16_t size);
static ssize_t recv_udp(int tun_socket, char* recvbuf, uint16_t size);
static ssize_t prepare_icmp(char* sendbuf, char* packet_buf, uint16_t packet_size, ipv4_addr local_endpoint, ipv4_addr remote_endpoint, uint16_t id);
static ssize_t send_icmp(int raw_socket, char* sendbuf, uint16_t size);
static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size, ipv4_addr local_endpoint);
static unsigned short checksum(void *b, int len);


void task_create_worker(worker_t* worker) {
    if (!worker) {
        return;
    }

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
            bh_list_t* current_enpoint_list = current_tun->remote_endpoint_list;

            char send_buf[SOCKET_SIZE];
            uint16_t send_size = 0;

            //encrypt packetbuf if it possible
            enc_entinty_t* current_encryptor = current_tun->encryptor;

            if (current_encryptor) {
                current_task->size = current_encryptor->encrypt(current_tun->encryptor_id, current_task->buffer, current_task->size);
            }

            while (current_enpoint_list) {
                tunnel_endpoint_t* current_endpoint = (tunnel_endpoint_t*)current_enpoint_list->data;

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

                current_enpoint_list = current_enpoint_list->next;
            }
        }

        if (fd == current_tun->tun_intf.raw_socket_in) { //this is accept from overlay network (decapsulating)
            //encrypt packetbuf if it possible
            enc_entinty_t* current_encryptor = current_tun->encryptor;

            switch (current_tun->tun_intf.proto) {
                case PROTO_UDP:
                    if (current_encryptor) {
                        current_task->size = current_encryptor->decrypt(current_tun->encryptor_id, current_task->buffer, current_task->size);
                    }

                    recv_udp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size);
                    break;
                case PROTO_ICMP:
                    if (current_encryptor) {
                        current_task->size = current_encryptor->decrypt(current_tun->encryptor_id, current_task->buffer + sizeof(struct ip) + sizeof(struct icmp), current_task->size - (sizeof(struct ip) + sizeof(struct icmp)));
                        current_task->size += sizeof(struct ip) + sizeof(struct icmp);
                    }

                    recv_icmp(current_tun->tun_intf.tun_fd, current_task->buffer, current_task->size, current_tun->local_endpoint);
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

static ssize_t recv_icmp(int tun_socket, char* recvbuf, uint16_t size, ipv4_addr local_endpoint) {
    struct ip* iphdr = (struct ip*)recvbuf;
    ssize_t tx_len = 0;

    if (local_endpoint.value == iphdr->ip_dst.s_addr) { //check if it is addresed to the local endpoint
        tx_len = write(tun_socket, recvbuf + sizeof(struct ip) + sizeof(struct icmp), size - (sizeof(struct ip) + sizeof(struct icmp)));
    }

    return tx_len;
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
