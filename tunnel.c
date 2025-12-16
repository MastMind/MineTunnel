#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <sys/epoll.h>

#include <linux/if_tun.h>
#include <arpa/inet.h>

#include "config.h"
#include "tunnel.h"
#include "task.h"
#include "crc.h"
#include "defines.h"
#include "utils.h"




static options_t opts;
static int sig_close = 0;
static config_t cfg;
static hash_table_t* tunnels_ht = NULL;
static hash_table_t* sck_tun_ht = NULL;
static hash_table_t* encryptors_ht = NULL;
static int epoll_fd = 0;
struct epoll_event* evlist = NULL;
static uint32_t evlist_count = 0;

static int tun_idx = 0;
static int tap_idx = 0;

static void RegSignals();
static void SigHandler(int signo);
static void PrintHelp(char* app_name);
static int build_tunnels(config_t* cfg);
static int load_encryptors(config_t* cfg);
static int init_tun_intf(tunnel_entity_t* tun, tun_info_t* tun_info);
static int add_tun_map(int fd, tunnel_entity_t* tun);
static int tunnel_poll();
static void tunnel_stop(void* arg);
static void encryptor_release(void* arg);

#ifdef DEBUG
void PrintBuffer(unsigned char *buffer, uint32_t size);
#endif


int tunnel_parse_opts(int argc, char** argv) {
    const char* short_options = "hdvp:c:";

    const struct option long_options[] = {
        { "help", no_argument, NULL, 'h' },
        { "daemon", no_argument, NULL, 'd' },
        { "verbose", no_argument, NULL, 'v' },
        { "pid", required_argument, NULL, 'p' },
        { "config", required_argument, NULL, 'c' },
        { NULL, 0, NULL, 0 }
    };

    int res = 0;
    int option_index = 0;

    memset(&opts, 0, sizeof(opts));

    strncpy(opts.prog_name, argv[0], PROG_NAME_LENGTH);
    //fill default values in opts
    strncpy(opts.pidfile_path, DEFAULT_PID_FILE, PATH_MAX);
    strncpy(opts.config_path, DEFAULT_CONFIG_FILE, PATH_MAX);

    while (( res = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
        switch (res) {
            case 'h':
                PrintHelp(argv[0]);
                break;
            case 'd':
                opts.daemonize = 1;
                break;
            case 'v':
                opts.verbose = 1;
                break;
            case 'p':
                if (*optarg != '\0') {
                    strncpy(opts.pidfile_path, optarg, PATH_MAX);
                }
                break;
            case 'c':
                if (*optarg != '\0') {
                    strncpy(opts.config_path, optarg, PATH_MAX);
                }
                break;
            default:
                return -1;
        }
    }

    return 0;
}

int tunnel_app_start() {
    tun_idx = 0;
    tap_idx = 0;

    //need root
    if (CheckRoot()) {
        fprintf(stderr, "App must be run as the root\n");
        return -1;
    }

    //daemonize if it is required
    if (opts.daemonize) {
        //check pid
        if (IsFileExists(opts.pidfile_path)) {
            fprintf(stderr, "The another instance of service probably is running. Aborted.\n");
            return -2;
        }

        if (Daemonize()) {
            fprintf(stderr, "Can't daemonize process. Errno %d\n", errno);
            return -3;
        }

        //write pid
        FILE* f_pid_file = fopen(opts.pidfile_path, "w");
        if (!f_pid_file) {
            fprintf(stderr, "Can't write pid to %s. Errno %d\n", opts.pidfile_path, errno);
            return -4;
        }

        pid_t current_pid = getpid();
        char line[MAX_STR_LENGTH] = { 0 };

        sprintf(line, "%u", (uint32_t)current_pid);
        fwrite(line, strlen(line), 1, f_pid_file);
        fclose(f_pid_file);

        //syslog init and logfile writing
        openlog(APP_NAME, LOG_PID, LOG_USER);
    }

    memset(&cfg, 0, sizeof(config_t));

    RegSignals();

    if (parse_config(&cfg, opts.config_path)) {
        fprintf(stderr, "Error in config file %s\n", opts.config_path);
        return -5;
    }

    //load encryptors
    if (load_encryptors(&cfg)) {
        fprintf(stderr, "Can't load encryptors\n");
        return -6;
    }

    //build tunnels
    if (build_tunnels(&cfg)) {
        fprintf(stderr, "Can't start tunnels\n");
        return -7;
    }

    PrintInform("Tunnels are running!\n");

    //polling
    return tunnel_poll();
}

void tunnel_app_stop() {
    //exec global shutdown script here
    if (*cfg.global_shutdown_script != '\0') {
        ExecScript(cfg.global_shutdown_script);
    }

    task_destroy_all_workers();

    if (evlist) {
        free(evlist);
    }

    evlist = NULL;
    evlist_count = 0;

    close(epoll_fd);
    epoll_fd = 0;

    //close all sockets and all devices
    hash_table_clear(&sck_tun_ht, NULL);
    hash_table_clear(&tunnels_ht, &tunnel_stop);
    hash_table_clear(&encryptors_ht, &encryptor_release);

    //utils action
    SetIngoreICMPEcho(0);

    //free cfg
    if (cfg.tunnels) {
        free(cfg.tunnels);
    }

    if (cfg.encryptors) {
        free(cfg.encryptors);
    }

    PrintInform("Tunnels are stoped!\n");

    //delete daemon pid file if it necessary
    if (opts.daemonize) {
        unlink(opts.pidfile_path);
    }

    closelog();
}

int tunnel_app_getDaemonize() {
    return opts.daemonize;
}

int tunnel_app_getVerbosity() {
    return opts.verbose;
}

static void RegSignals() {
    sigset_t sig_set;
    struct sigaction sig_act;

    sigemptyset(&sig_set);
    sigaddset(&sig_set, SIGTERM);
    sigaddset(&sig_set, SIGINT);
    sigaddset(&sig_set, SIGQUIT);
    sigaddset(&sig_set, SIGCHLD);

    sig_act.sa_flags = 0;
    sig_act.sa_mask = sig_set;
    sig_act.sa_handler = &SigHandler;

    sigaction(SIGTERM, &sig_act, NULL);
    sigaction(SIGINT, &sig_act, NULL);
    sigaction(SIGQUIT, &sig_act, NULL);
    sigaction(SIGCHLD, &sig_act, NULL);
}

static void SigHandler(int signo) {
    if (signo == SIGCHLD) {
        int status = 0;

        while (!waitpid(-1, &status, WNOHANG));

        return;
    }

    sig_close = 1;
}

static void PrintHelp(char* app_name) {
    fprintf(stdout, "Usage: %s [options]\n", app_name);
    fprintf(stdout, "\t --daemon -d  : run in background mode\n");
    fprintf(stdout, "\t --verbose -v : switch on verbose output\n");
    fprintf(stdout, "\t --pid -p     : set path to pid file (for background mode only)\n");
    fprintf(stdout, "\t --config -c  : set config path (by default it is ./config.json)\n");
    exit(-1);
}

static int build_tunnels(config_t* cfg) {
    if (cfg->tunnels_count > MAX_TUNNELS) {
        PrintError("Tunnels in cfg more than %u\n", MAX_TUNNELS);
        return -5;
    }

    epoll_fd = epoll_create(1);

    if (epoll_fd < 0) {
        PrintError("epoll init failed\n");
        return -1;
    }

#ifdef DEBUG
    fprintf(stdout, "epoll_fd is %d\n", epoll_fd);
#endif

    for (uint16_t i = 0; i < cfg->tunnels_count; i++) {
        tunnel_entity_t tun;
        tunnel_entity_t* found_tun = NULL;
        tunnel_endpoint_t* new_endpoint = (tunnel_endpoint_t*)malloc(sizeof(tunnel_endpoint_t));
        tun_info_t* tun_info = cfg->tunnels + i;

        if (!new_endpoint) {
            PrintError("Internal error. Can't alloc memory for new tunnel endpoint\n");
            return -1;
        }

        memset(&tun, 0, sizeof(tunnel_entity_t));

        tun.local_endpoint.value = tun_info->local_endpoint.value;
        tun.local_port = tun_info->local_port;
        tun.icmp_identifier = tun_info->icmp_id;

        new_endpoint->remote_endpoint.value = tun_info->remote_endpoint.value;
        new_endpoint->remote_port = tun_info->remote_port;

        memset(&tun.tun_intf, 0, sizeof(tun_intf_t));

        strncpy(tun.tun_intf.tun_name, tun_info->dev_name, MAX_DEV_NAME_LENGTH);
        tun.tun_intf.proto = tun_info->proto;
        tun.tun_intf.mode = tun_info->mode;

        strncpy(tun.bringup_script, tun_info->bringup_script, PATH_MAX);
        strncpy(tun.shutdown_script, tun_info->shutdown_script, PATH_MAX);

        //search encryptor
        enc_entinty_t search_entity;

        if (*tun_info->encryptor_name != '\0') {
            memset(&search_entity, 0, sizeof(enc_entinty_t));
            strncpy(search_entity.name, tun_info->encryptor_name, MAX_ENCRYPTOR_NAME);

            enc_entinty_t* found_encryptor_entity = hash_table_find(&encryptors_ht, &search_entity, &encryptor_hash_func, &encryptor_cmp_func);

            if (!found_encryptor_entity) {
                PrintError("Can't find encryptor %s\n", search_entity.name);
            } else {
                int encryptor_id = found_encryptor_entity->set_params(tun_info->encryption_params);
                if (encryptor_id < 0) {
                    PrintError("Can't set encryption params for encryptor %s and for tunnel with local ip %u.%u.%u.%u and remote ip %u.%u.%u.%u\nError code: %d\n", search_entity.name,
                                                                                                                                                                    tun_info->local_endpoint.addr[0],
                                                                                                                                                                    tun_info->local_endpoint.addr[1],
                                                                                                                                                                    tun_info->local_endpoint.addr[2],
                                                                                                                                                                    tun_info->local_endpoint.addr[3],
                                                                                                                                                                    tun_info->remote_endpoint.addr[0],
                                                                                                                                                                    tun_info->remote_endpoint.addr[1],
                                                                                                                                                                    tun_info->remote_endpoint.addr[2],
                                                                                                                                                                    tun_info->remote_endpoint.addr[3],
                                                                                                                                                                    encryptor_id);
                } else {
                    tun.encryptor = found_encryptor_entity;
                    tun.encryptor_id = encryptor_id;
                }
            }
        }

        //search duplicate
        found_tun = (tunnel_entity_t*)hash_table_find(&tunnels_ht, &tun, &tunnel_hash_func, &tunnel_cmp_func);

        if (found_tun) {
            if (found_tun->tun_intf.proto != tun_info->proto ||
                found_tun->tun_intf.mode != tun_info->mode ||
                strncmp(found_tun->tun_intf.tun_name, tun_info->dev_name, MAX_DEV_NAME_LENGTH)) {
                PrintError("Bad duplicate tunnel with local ip %u.%u.%u.%u\nOptions proto, mode and name should be equal\n", tun_info->local_endpoint.addr[0],
                                                                                                                             tun_info->local_endpoint.addr[1],
                                                                                                                             tun_info->local_endpoint.addr[2],
                                                                                                                             tun_info->local_endpoint.addr[3]);
                free(new_endpoint);
                return -2;
            }

            bhlist_push_front(&found_tun->remote_endpoint_list, new_endpoint);
            hash_table_add(&found_tun->remote_endpoint_ht, found_tun->remote_endpoint_list, &endpoint_hash_func);
        } else {
            tunnel_entity_t* new_tun = (tunnel_entity_t*)malloc(sizeof(tunnel_entity_t));

            if (!new_tun) {
                PrintError("Internal error. Can't alloc memory for new tunnel entity\n");
                free(new_endpoint);
                return -3;
            }

            memcpy(new_tun, &tun, sizeof(tunnel_entity_t));

            bhlist_push_front(&new_tun->remote_endpoint_list, new_endpoint);
            hash_table_add(&new_tun->remote_endpoint_ht, new_tun->remote_endpoint_list, &endpoint_hash_func);

            //start tunnel in system here
            if (init_tun_intf(new_tun, tun_info)) {
                free(new_endpoint);
                free(new_tun);
                return -4;
            }

            //exec bringup script
            if (*new_tun->bringup_script != '\0') {
                ExecScript(new_tun->bringup_script);
            }

            hash_table_add(&tunnels_ht, new_tun, &tunnel_hash_func);
        }
    }

    //exec global bringup script
    if (*cfg->global_bringup_script != '\0') {
        ExecScript(cfg->global_bringup_script);
    }

    return 0;
}

static int load_encryptors(config_t* cfg) {
    int ret = 0;
    enc_entinty_t* encryptor = NULL;

    for (uint16_t i = 0; i < cfg->encryptors_count; i++) {
        tun_encryptor_t* tun_encryptor = cfg->encryptors + i;
        encryptor = (enc_entinty_t*)malloc(sizeof(enc_entinty_t));

        if (!encryptor) {
            ret = -1;
            goto err;
        }

        //load_encryptor
        memset(encryptor, 0, sizeof(enc_entinty_t));

        strncpy(encryptor->name, tun_encryptor->name, MAX_ENCRYPTOR_NAME);
        encryptor->shared_library_handle = dlopen(tun_encryptor->module_path, RTLD_NOW | RTLD_GLOBAL);

        if (!encryptor->shared_library_handle) {
            ret = -2;
            goto err;
        }

        encryptor->encrypt = dlsym(encryptor->shared_library_handle, "encrypt");
        if (!encryptor->encrypt) {
            ret = -3;
            goto err;
        }

        encryptor->decrypt = dlsym(encryptor->shared_library_handle, "decrypt");
        if (!encryptor->decrypt) {
            ret = -4;
            goto err;
        }

        encryptor->get_type = dlsym(encryptor->shared_library_handle, "get_type");
        if (!encryptor->get_type) {
            ret = -5;
            goto err;
        }

        encryptor->set_params = dlsym(encryptor->shared_library_handle, "set_params");
        if (!encryptor->set_params) {
            ret = -6;
            goto err;
        }

        hash_table_add(&encryptors_ht, encryptor, &encryptor_hash_func);
#ifdef DEBUG
        fprintf(stdout, "Encryptor %s successfully loaded\n", tun_encryptor->module_path);
#endif
    }

err:
    if (ret < 0) {
        if (encryptor) {
            if (encryptor->shared_library_handle) {
                dlclose(encryptor->shared_library_handle);
            }
            free(encryptor);
        }
    }

    return ret;
}
 
static int init_tun_intf(tunnel_entity_t* tun, tun_info_t* tun_info) {
    struct ifreq ifr;
    int err = 0;
    int fd = 0;
    tun_intf_t* intf = &tun->tun_intf;
    int zero = 0; 
    const int *val = &zero;
    uint32_t socketbuffsize = SOCKET_SIZE;

    struct sockaddr_in serveraddr;

    //init sockets
    switch (tun_info->proto) {
        case PROTO_UDP:
            // Init SOCK_RAW for output UDP packets:
            intf->raw_socket_out = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
            if (intf->raw_socket_out < 0) {
                intf->raw_socket_out = 0;
                PrintError("Can't create UDP output raw socket\n");
                err = -5;
                goto err_label;
            }

            // Init SOCK_DGRAM for input UDP packets (because we want to handle only specific input port packets):
            intf->raw_socket_in = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (intf->raw_socket_in < 0) {
                intf->raw_socket_in = 0;
                PrintError("Can't create UDP input raw socket\n");
                err = -6;
                goto err_label;
            }
            
            socketbuffsize = SOCKET_SIZE;
            if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF, &socketbuffsize, sizeof(socketbuffsize)) < 0) {
                PrintError("Can't set socket options for UDP output raw socket\n");
                err = -7;
                goto err_label;
            }

            if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_SNDBUF, &socketbuffsize, sizeof(socketbuffsize)) < 0) {
                PrintError("Can't set socket options for UDP input raw socket\n");
                err = -8;
                goto err_label;
            }
            
            // inform the kernel do not fill up the packet structure (need manual fragmentation if it require)
            if (setsockopt(intf->raw_socket_out, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) < 0) {
                PrintError("Can't set socket option IP_HDRINCL for UDP output raw socket\n");
                err = -9;
                goto err_label;
            }


            memset(&serveraddr, 0, sizeof(serveraddr));
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_addr.s_addr = htonl(INADDR_NONE); // Ignore all input packets, because this is out socket
            serveraddr.sin_port = 0;

            if (bind(intf->raw_socket_out, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
                PrintError("Can't bind for UDP output raw socket\n");
                err = -10;
                goto err_label;
            }

            memset(&serveraddr, 0, sizeof(serveraddr));

            serveraddr.sin_family = AF_INET;
            serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
            serveraddr.sin_port = htons(tun->local_port);

            if (bind(intf->raw_socket_in, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
                PrintError("Can't bind for UDP input raw socket\n");
                err = -11;
                goto err_label;
            }
            break;
        case PROTO_ICMP:
            // Init SOCK_RAW for output UDP packets:
            intf->raw_socket_out = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (intf->raw_socket_out < 0) {
                intf->raw_socket_out = 0;
                PrintError("Can't create ICMP output raw socket\n");
                err = -12;
                goto err_label;
            }

            // Init SOCK_DGRAM for input ICMP packets (because we want to handle only specific input port packets):
            intf->raw_socket_in = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (intf->raw_socket_in < 0) {
                intf->raw_socket_in = 0;
                PrintError("Can't create ICMP input raw socket\n");
                err = -13;
                goto err_label;
            }
            
            socketbuffsize = SOCKET_SIZE;
            if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF, &socketbuffsize, sizeof(socketbuffsize)) < 0) {
                PrintError("Can't set socket options for ICMP output raw socket\n");
                err = -14;
                goto err_label;
            }
            if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_SNDBUF, &socketbuffsize, sizeof(socketbuffsize)) < 0) {
                PrintError("Can't set socket options for ICMP input raw socket\n");
                err = -15;
                goto err_label;
            }
            
            // inform the kernel do not fill up the packet structure (need manual fragmentation if it require)
            if (setsockopt(intf->raw_socket_out, IPPROTO_IP, IP_HDRINCL, val, sizeof(zero)) < 0) {
                PrintError("Can't set socket option IP_HDRINCL for ICMP output raw socket\n");
                err = -16;
                goto err_label;
            }


            memset(&serveraddr, 0, sizeof(serveraddr));
            serveraddr.sin_family = AF_INET;
            serveraddr.sin_addr.s_addr = htonl(INADDR_NONE); // Ignore all input packets, because this is out socket
            serveraddr.sin_port = 0;

            if (bind(intf->raw_socket_out, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
                PrintError("Can't bind for ICMP output raw socket\n");
                err = -17;
                goto err_label;
            }

            memset(&serveraddr, 0, sizeof(serveraddr));

            serveraddr.sin_family = AF_INET;
            serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
            serveraddr.sin_port = htons(tun->local_port);

            if (bind(intf->raw_socket_in, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
                PrintError("Can't bind for ICMP input raw socket\n");
                err = -18;
                goto err_label;
            }

            //set icmp_echo_ignore_all
            if (SetIngoreICMPEcho(1)) {
                PrintError("Can't set ignore flag for icmp echo\n");
                err = -19;
                goto err_label;
            }

            break;
        default:
            break;
    }

    fd = open("/dev/net/tun", O_RDWR);

    if (fd < 0) {
        PrintError("Can't open /dev/net/tun device for creating virtual interface\n");
        err = -20;
        goto err_label;
    }

    memset(&ifr, 0, sizeof(ifr));

    switch (tun_info->mode) {
        case MODE_TUN:
            ifr.ifr_flags = IFF_TUN;

            if (*intf->tun_name == '\0') {
                snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TUN_NAME, tun_idx);
                tun_idx++;
            }
            break;
        case MODE_TAP:
            ifr.ifr_flags = IFF_TAP;

            if (*intf->tun_name == '\0') {
                snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TAP_NAME, tap_idx);
                tap_idx++;
            }
            break;
        default:
            PrintError("Bad tunnel mode with code %u\n", tun_info->mode);
            err = -21;
            goto err_label;
    }

    ifr.ifr_flags |= IFF_NO_PI;

    strncpy(ifr.ifr_name, intf->tun_name, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
        PrintError("ioctl TUNSETIFF error for interface %s\n", intf->tun_name);
        err = -22;
        goto err_label;
    }

    strcpy(intf->tun_name, ifr.ifr_name);
    intf->tun_fd = fd;

    //fill tun map (for fast searching socket and tunnel in select polling)
    if (intf->raw_socket_in) {
        if (add_tun_map(intf->raw_socket_in, tun)) {
            err = -23;
            goto err_label;
        }

        evlist = (struct epoll_event*)realloc(evlist, sizeof(struct epoll_event) * (evlist_count + 1));

        if (!evlist) {
            PrintError("Internal error. Can't realloc memory for epoll's evlist and register input socket\n");
            err = -24;
            goto err_label;
        }

        evlist[evlist_count].data.fd = intf->raw_socket_in;
        evlist[evlist_count].events = EPOLLIN;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, intf->raw_socket_in, &evlist[evlist_count]) < 0) {
            PrintError("Can't do EPOLL_CTL_ADD for input socket\n");
            err = -25;
            goto err_label;
        }

        evlist_count++;
    }

    if (intf->tun_fd) {
        if (add_tun_map(intf->tun_fd, tun)) {
            err = -26;
            goto err_label;
        }

        evlist = (struct epoll_event*)realloc(evlist, sizeof(struct epoll_event) * (evlist_count + 1));

        if (!evlist) {
            PrintError("Internal error. Can't realloc memory for epoll's evlist and register tunnel socket socket\n");
            err = -27;
            goto err_label;
        }

        evlist[evlist_count].data.fd = intf->tun_fd;
        evlist[evlist_count].events = EPOLLIN;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, intf->tun_fd, &evlist[evlist_count]) < 0) {
            PrintError("Can't do EPOLL_CTL_ADD for tunnel socket\n");
            err = -28;
            goto err_label;
        }

        evlist_count++;
    }

    //create worker on tunnel
    tun->worker = (worker_t*)malloc(sizeof(worker_t));

    if (!tun->worker) {
        PrintError("Internal error. Can't alloc memory for the worker of tunnel\n");
        err = -29;
        goto err_label;
    }

    task_create_worker(tun->worker);

    return 0;

err_label:
    if (intf->raw_socket_in) {
        close(intf->raw_socket_in);
    }

    if (intf->raw_socket_out) {
        close(intf->raw_socket_out);
    }

    if (intf->tun_fd) {
        close(intf->tun_fd);
    }

    return err;
}

static int add_tun_map(int fd, tunnel_entity_t* tun) {
    fd_tun_map_t* tun_map = (fd_tun_map_t*)malloc(sizeof(fd_tun_map_t));

    if (!tun_map) {
        PrintError("Internal error. Can't alloc memory for new tunnel map\n");
        return -1;
    }

    tun_map->fd = fd;
    tun_map->tun = tun;

    //search for duplicate
    if (hash_table_find(&sck_tun_ht, tun_map, &tun_map_hash_func, &tun_map_cmp_func)) {
        PrintError("Found duplicate for tunnel map: fd %d\n", fd);
        free(tun_map);
        return -3;
    }

    hash_table_add(&sck_tun_ht, tun_map, &tun_map_hash_func);

#ifdef DEBUG
    fprintf(stdout, "Added tunmap with fd %d and tun->tun_intf.tun_fd %d\n", tun_map->fd, tun->tun_intf.tun_fd);
#endif

    return 0;
}

static int tunnel_poll() {
    //create epoll from registered sockets
    while (!sig_close) {
#ifdef DEBUG
        fprintf(stdout, "epoll_wait polling...\n");
#endif
        int fds = epoll_wait(epoll_fd, evlist, evlist_count, EPOLL_TIMEOUT);

        if(fds < 0 && !sig_close) {
            if (errno == EINTR) {
#ifdef DEBUG
                fprintf(stderr, "epoll_wait timeout\n");
#endif
                continue;
            }

            fprintf(stderr, "epoll_wait error, exit\n errno %d\n", errno);
            return -1;
        }

        for(int i = 0; i < fds; ++i) {
#ifdef DEBUG
            fprintf(stdout, "evlist[%d].events: 0x%08X\n", i, evlist[i].events);
            fprintf(stdout, "evlist[%d].data.fd: %d\n", i, evlist[i].data.fd);
#endif
            if (evlist[i].events & EPOLLIN) {
                fd_tun_map_t tmp_tun;

                tmp_tun.fd = evlist[i].data.fd;
                fd_tun_map_t* found_tun_map = (fd_tun_map_t*)hash_table_find(&sck_tun_ht, &tmp_tun, &tun_map_hash_func, &tun_map_cmp_func);

                if (found_tun_map) {
                    //create task with socket i argument and tunnel entity
                    task_t* new_task = NULL;
                    tunnel_entity_t* current_tun = found_tun_map->tun;
                    struct sockaddr_in remote_addr;
                    socklen_t remote_len = sizeof(remote_addr);
                    ssize_t bytes = 0;
                    int remote_endpoint_flag = 0;

                    task_get_new(current_tun->worker, &new_task);  //get new task identity and fill it below
                    if (found_tun_map->fd == current_tun->tun_intf.raw_socket_in) { //read from underlay network
                        switch (current_tun->tun_intf.proto) {
                            case PROTO_UDP:
                                bytes = recvfrom(found_tun_map->fd, new_task->buffer, sizeof(new_task->buffer), 0,
                                    (struct sockaddr *)&remote_addr, &remote_len);
                                remote_endpoint_flag = 1;
                                break;
                            case PROTO_ICMP:
                                bytes = read(found_tun_map->fd, new_task->buffer, sizeof(new_task->buffer));
                                break;
                            default:
                                PrintError("Can't receive packet. Unknown tunnel proto.\n");
                                break;
                        }
                    } else {
                        bytes = read(found_tun_map->fd, new_task->buffer, sizeof(new_task->buffer));
                    }

                    if (bytes <= 0) {
                        PrintError("Something went wrong in the receiving packets\n");
                        continue;
                    }

                    new_task->tun_map = found_tun_map;
                    new_task->size = bytes;
                    new_task->endpoint_flag = remote_endpoint_flag;
#ifdef DEBUG
                    fprintf(stdout, "Accepted packet: \n");
                    PrintBuffer((unsigned char*)new_task->buffer, bytes);
#endif
                    //add endpoint addr info to task (if received from underlay network)
                    if (remote_endpoint_flag) {
                        new_task->endpoint.remote_endpoint.value = remote_addr.sin_addr.s_addr;
                        new_task->endpoint.remote_port = ntohs(remote_addr.sin_port);
                    }

                    task_add(current_tun->worker);
                }
            }
        }
    }

    return 0;
}

static void tunnel_stop(void* arg) {
    tunnel_entity_t* tun = (tunnel_entity_t*)arg;

    //exec shutdown script
    if (*tun->shutdown_script != '\0') {
        ExecScript(tun->shutdown_script);
    }

    bhlist_clear(tun->remote_endpoint_list, NULL);
    hash_table_clear(&tun->remote_endpoint_ht, NULL);

    if (tun->tun_intf.raw_socket_in) {
        close(tun->tun_intf.raw_socket_in);
    }

    if (tun->tun_intf.raw_socket_out) {
        close(tun->tun_intf.raw_socket_out);
    }

    if (tun->tun_intf.tun_fd) {
        close(tun->tun_intf.tun_fd);
    }
}

static void encryptor_release(void* arg) {
    enc_entinty_t* encryptor = (enc_entinty_t*)arg;

    if (encryptor->shared_library_handle) {
        dlclose(encryptor->shared_library_handle);
    }
}

#ifdef DEBUG

void PrintBuffer(unsigned char *buffer, uint32_t size) {
    uint32_t i = 0;

    fprintf(stdout, "\t");

    while (size) {
        fprintf(stdout, "0x%02X ", *buffer);

        ++i;
        if (i % 0x10 == 0) {
            i = 0;
            fprintf(stdout, "\n");
        }

        ++buffer;
        --size;
    }

    fprintf(stdout, "\n");
}

#endif
