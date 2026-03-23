#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#ifdef _WIN32
#include <winsock2.h>
#include <mswsock.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winioctl.h>
#include <wchar.h>
#include <objbase.h>
#include <setupapi.h>
#include <devguid.h>
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <dlfcn.h>
#endif
#include <getopt.h>

#include "config.h"
#include "tunnel.h"
#include "task.h"
#include "crc.h"
#include "defines.h"
#include "utils.h"
#ifdef _WIN32
#include "include/wintun.h"
#include "tapctl.h"
#include "tunctl.h"
#endif




static options_t opts;
static volatile int sig_close = 0;
static config_t cfg;
static hash_table_t* tunnels_ht = NULL;
static hash_table_t* sck_tun_ht = NULL;
static hash_table_t* encryptors_ht = NULL;

static int tun_idx = 0;
static int tap_idx = 0;
#ifndef _WIN32
static char localbuf[SOCKET_SIZE] = { 0 };
#endif

#ifdef _WIN32
#define LOAD_SYM(field, sym_name) \
        encryptor->field = (void*)GetProcAddress( \
            (HMODULE)encryptor->shared_library_handle, (sym_name)); \
        if (!encryptor->field) { \
            PrintError("Symbol '%s' not found in %s\n", (sym_name), tun_encryptor->module_path); \
            ret = -3; goto err; \
        }
#else
#define LOAD_SYM(field, sym_name) \
        encryptor->field = dlsym(encryptor->shared_library_handle, (sym_name)); \
        if (!encryptor->field) { \
            PrintError("Symbol '%s' not found in %s\n", (sym_name), tun_encryptor->module_path); \
            ret = -3; goto err; \
        }
#endif

#ifdef _WIN32

typedef enum {
    IOCP_OP_TAP_READ  = 1,
    IOCP_OP_SOCK_READ = 2,
    IOCP_OP_TAP_WRITE = 3,
} iocp_op_t;

typedef struct iocp_ctx_s {
    OVERLAPPED ov;
    iocp_op_t op;
    HANDLE hTap;
    SOCKET sock;
    int proto;
    fd_tun_map_t* tun_map;
    tunnel_entity_t* tun;
    char buf[SOCKET_SIZE];
    WSABUF wsabuf;
    struct sockaddr_in remote_addr;
    INT remote_addr_len;
    struct iocp_ctx_s* next_free;
} iocp_ctx_t;

typedef struct wintun_reader_ctx_s {
    wintun_ctx_t* wintun;
    fd_tun_map_t* tun_map;
    tunnel_entity_t* tun;
} wintun_reader_ctx_t;

//#define IOCP_WRITE_POOL_SIZE  256
#define IOCP_WRITE_POOL_SIZE 1024
#define REPOST_SOCK_ATTEMPTS 8
#define IOCP_KEY_STOP  ((ULONG_PTR)0xDEAD)

static iocp_ctx_t* iocp_write_pool_mem = NULL;
static iocp_ctx_t* iocp_write_free_list = NULL;
static CRITICAL_SECTION iocp_write_pool_cs;
static HANDLE iocp_write_sem = NULL;
static HANDLE iocp_handle = NULL;
static HANDLE iocp_thr = NULL;

static HANDLE wintun_reader_threads[MAX_TUNNELS];
static uint32_t wintun_reader_count = 0;
static volatile LONG wintun_fd_counter = 0;

static WSADATA wsa;

#else

static int epoll_fd = 0;
static struct epoll_event* evlist = NULL;
static uint32_t evlist_count = 0;

#endif

static void RegSignals(void);
static void SigHandler(int signo);
static void PrintHelp(char* app_name);
static void PrintVersion(void);
static int build_tunnels(config_t* cfg);
static int load_encryptors(config_t* cfg);
static int init_tun_intf(tunnel_entity_t* tun, tun_info_t* tun_info);
static int add_tun_map(int fd, tunnel_entity_t* tun);
static int tunnel_poll(void);
static void tunnel_stop(void* arg);
static void encryptor_release(void* arg);

#ifdef _WIN32
static void iocp_pool_init(void);
static void iocp_pool_destroy(void);
static iocp_ctx_t* iocp_ctx_write_alloc(void);
static void iocp_ctx_write_free(iocp_ctx_t* ctx);
static DWORD WINAPI wintun_reader_thread_func(LPVOID param);
static DWORD WINAPI iocp_thread_func(LPVOID param);
static void repost_tap_read(iocp_ctx_t* ctx);
static void repost_sock_read(iocp_ctx_t* ctx);
#endif

#ifdef DEBUG
void PrintBuffer(unsigned char* buffer, uint32_t size);
#endif


int tunnel_parse_opts(int argc, char** argv) {
#ifdef _WIN32
    const char* short_options = "hdvc:";
#else
    const char* short_options = "hdvp:c:";
#endif

    const struct option long_options[] = {
        { "help",    no_argument,       NULL, 'h' },
        { "daemon",  no_argument,       NULL, 'd' },
        { "verbose", no_argument,       NULL, 'v' },
#ifndef _WIN32
        { "pid",     required_argument, NULL, 'p' },
#endif
        { "config",  required_argument, NULL, 'c' },
        { "version", no_argument, NULL, 'V' },
        { NULL, 0, NULL, 0 }
    };

    int res = 0;
    int option_index = 0;

    memset(&opts, 0, sizeof(opts));
    strncpy(opts.prog_name, argv[0], PROG_NAME_LENGTH - 1);
#ifndef _WIN32
    strncpy(opts.pidfile_path, DEFAULT_PID_FILE, PATH_MAX - 1);
#endif
    strncpy(opts.config_path, DEFAULT_CONFIG_FILE, PATH_MAX - 1);

    while ((res = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1) {
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
#ifndef _WIN32
            case 'p':
                if (*optarg != '\0') {
                    strncpy(opts.pidfile_path, optarg, PATH_MAX - 1);
                }
                break;
#endif
            case 'c':
                if (*optarg != '\0') {
                    strncpy(opts.config_path, optarg, PATH_MAX - 1);
                }
                break;
            case 'V':
                PrintVersion();
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

    if (CheckRoot()) {
#ifdef _WIN32
        fprintf(stderr, "App must be run with Administrator privileges\n");
#else
        fprintf(stderr, "App must be run as root\n");
#endif
        return -1;
    }

    if (opts.daemonize) {
#ifdef _WIN32
        fprintf(stderr, "Daemon mode is not supported on Windows\n");
        return -2;
#else
        if (IsFileExists(opts.pidfile_path)) {
            fprintf(stderr, "Another instance is probably running. Aborted.\n");
            return -2;
        }
        if (Daemonize()) {
            fprintf(stderr, "Can't daemonize. Errno %d\n", errno);
            return -3;
        }

        FILE* f_pid = fopen(opts.pidfile_path, "w");
        if (!f_pid) {
            fprintf(stderr, "Can't write pid to %s. Errno %d\n", opts.pidfile_path, errno);
            return -4;
        }
        char line[MAX_STR_LENGTH] = { 0 };
        sprintf(line, "%u", (uint32_t)getpid());
        fwrite(line, strlen(line), 1, f_pid);
        fclose(f_pid);

        openlog(APP_NAME, LOG_PID, LOG_USER);
#endif
    }

    memset(&cfg, 0, sizeof(config_t));
    RegSignals();

    if (parse_config(&cfg, opts.config_path)) {
        fprintf(stderr, "Error in config file %s\n", opts.config_path);
        return -5;
    }

    if (load_encryptors(&cfg)) {
        fprintf(stderr, "Can't load encryptors\n");
        return -6;
    }

    if (build_tunnels(&cfg)) {
        fprintf(stderr, "Can't start tunnels\n");
        return -7;
    }

    PrintInform("Tunnels are running!\n");
    return tunnel_poll();
}

void tunnel_app_stop() {
    if (*cfg.global_shutdown_script != '\0') {
        ExecScript(cfg.global_shutdown_script);
    }

#ifdef _WIN32
    if (iocp_thr) {
        if (iocp_handle) {
            PostQueuedCompletionStatus(iocp_handle, 0, IOCP_KEY_STOP, NULL);
        }

        WaitForSingleObject(iocp_thr, POLLING_TIMEOUT);
        TerminateThread(iocp_thr, 0);
        CloseHandle(iocp_thr);
        iocp_thr = NULL;
    }

    //stopping wintun reader threads
    for (uint32_t i = 0; i < wintun_reader_count; i++) {
        if (wintun_reader_threads[i]) {
            WaitForSingleObject(wintun_reader_threads[i], POLLING_TIMEOUT);
            TerminateThread(wintun_reader_threads[i], 0);
            CloseHandle(wintun_reader_threads[i]);
            wintun_reader_threads[i] = NULL;
        }
    }
    wintun_reader_count = 0;
#endif

    task_destroy_all_workers();

#ifdef _WIN32
    if (iocp_handle) { 
        CloseHandle(iocp_handle);
        iocp_handle = NULL;
    }

    iocp_pool_destroy();
#else
    if (evlist) {
        free(evlist);
        evlist = NULL;
    }

    evlist_count = 0;
    close(epoll_fd);
    epoll_fd = 0;
#endif

    hash_table_clear(&sck_tun_ht, NULL);
    hash_table_clear(&tunnels_ht, &tunnel_stop);
    hash_table_clear(&encryptors_ht, &encryptor_release);

    // SetIngoreICMPEcho(0);

    if (cfg.tunnels) {
        free(cfg.tunnels);
    }

    if (cfg.encryptors) {
        free(cfg.encryptors);
    }
#ifdef _WIN32
    wintun_global_unload();
#endif
    PrintInform("Tunnels are stopped!\n");

#ifndef _WIN32
    if (opts.daemonize) {
        unlink(opts.pidfile_path);
        closelog();
    }
#endif
}

int tunnel_app_getDaemonize() {
    return opts.daemonize;
}

int tunnel_app_getVerbosity() {
    return opts.verbose;
}

#ifdef _WIN32

//Public API used by task.c to post an async WriteFile to the TAP HANDLE
void iocp_tap_write_async(HANDLE tun_fd, const char* buf, DWORD size) {
    iocp_ctx_t* ctx = iocp_ctx_write_alloc();
    ctx->hTap = tun_fd;

    memcpy(ctx->buf, buf, size);
    BOOL ok = WriteFile(tun_fd, ctx->buf, size, NULL, &ctx->ov);

    if (!ok && GetLastError() != ERROR_IO_PENDING) {
        if (!sig_close) {
            PrintError("iocp_tap_write_async: WriteFile failed. Code: %lu\n", GetLastError());
        }

        iocp_ctx_write_free(ctx);
    }
}

void tun_write_async(tun_intf_t* intf, const char* buf, DWORD size) {
    if (intf->wintun_ctx) {
        wintun_send_packet((wintun_ctx_t*)intf->wintun_ctx, buf, size);
    } else {
        iocp_tap_write_async(intf->tun_fd, buf, size);
    }
}

#endif

static void RegSignals(void) {
#ifdef _WIN32
    signal(SIGABRT, SigHandler);
    signal(SIGINT,  SigHandler);
    signal(SIGTERM, SigHandler);
#else
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
#endif
}

static void SigHandler(int signo) {
#ifndef _WIN32
    if (signo == SIGCHLD) {
        int status = 0;
        while (!waitpid(-1, &status, WNOHANG));
        return;
    }
#endif
    sig_close = 1;
}

static void PrintHelp(char* app_name) {
    fprintf(stdout, "Usage: %s [options]\n", app_name);
    fprintf(stdout, "\t --daemon  -d : run in background mode (Linux only)\n");
    fprintf(stdout, "\t --verbose -v : enable verbose output\n");
#ifndef _WIN32
    fprintf(stdout, "\t --pid     -p : path to pid file (background mode only)\n");
#endif
    fprintf(stdout, "\t --config  -c : config path (default: ./config.json)\n");
    fprintf(stdout, "\t --version    : print app's version\n");
    exit(-1);
}

static void PrintVersion(void) {
    fprintf(stdout, "%s\n", VERSION_STR);
    exit(-1);
}

static int add_tun_map(int fd, tunnel_entity_t* tun) {
    fd_tun_map_t* tun_map = (fd_tun_map_t*)malloc(sizeof(fd_tun_map_t));
    if (!tun_map) {
        PrintError("Internal error. Can't alloc memory for new tunnel map\n");
        return -1;
    }

    tun_map->fd = fd;
    tun_map->tun = tun;

    if (hash_table_find(&sck_tun_ht, tun_map, &tun_map_hash_func, &tun_map_cmp_func)) {
        PrintError("Found duplicate for tunnel map: fd %d\n", fd);
        free(tun_map);
        return -3;
    }

    hash_table_add(&sck_tun_ht, tun_map, &tun_map_hash_func);

#ifdef DEBUG
    fprintf(stdout, "Added tunmap with fd %d\n", fd);
#endif
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

        memset(encryptor, 0, sizeof(enc_entinty_t));
        strncpy(encryptor->name, tun_encryptor->name, MAX_ENCRYPTOR_NAME - 1);

#ifdef _WIN32
        encryptor->shared_library_handle = (void*)LoadLibraryA(tun_encryptor->module_path);
        if (!encryptor->shared_library_handle) {
            PrintError("Can't load module %s. Code: %lu\n",
                       tun_encryptor->module_path, GetLastError());
            ret = -2;
            goto err;
        }
#else
        encryptor->shared_library_handle = dlopen(tun_encryptor->module_path,
                                                   RTLD_NOW | RTLD_GLOBAL);
        if (!encryptor->shared_library_handle) {
            PrintError("Can't load module %s\n", tun_encryptor->module_path);
            ret = -2; goto err;
        }
#endif

        LOAD_SYM(encrypt, "encrypt")
        LOAD_SYM(decrypt, "decrypt")
        LOAD_SYM(get_type, "get_type")
        LOAD_SYM(create_instance, "create_instance")
        LOAD_SYM(destroy_instance, "destroy_instance")

        hash_table_add(&encryptors_ht, encryptor, &encryptor_hash_func);

#ifdef DEBUG
        fprintf(stdout, "Encryptor %s loaded successfully\n", tun_encryptor->module_path);
#endif
    }

err:
    if (ret < 0 && encryptor) {
        if (encryptor->shared_library_handle) {
#ifdef _WIN32
            FreeLibrary((HMODULE)encryptor->shared_library_handle);
#else
            dlclose(encryptor->shared_library_handle);
#endif
        }
        free(encryptor);
    }
    return ret;
}

static int init_tun_intf(tunnel_entity_t* tun, tun_info_t* tun_info) {
    int err  = 0;
    tun_intf_t* intf = &tun->tun_intf;
    int zero = 0;
    const int* val = &zero;
    uint32_t socketbuffsize = SOCKET_SIZE;
    struct sockaddr_in serveraddr;

#ifndef _WIN32
    struct ifreq ifr;
    int fd = 0;
#endif

#ifdef _WIN32
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        PrintError("WSAStartup failed. Code: %d\n", WSAGetLastError());
        return -1;
    }
#endif
    switch (tun_info->proto) {
    case PROTO_UDP:
#ifdef _WIN32
        intf->raw_socket_out = WSASocket(AF_INET, SOCK_RAW, IPPROTO_UDP,
                                         NULL, 0, WSA_FLAG_OVERLAPPED);
        if (intf->raw_socket_out == INVALID_SOCKET) {
            intf->raw_socket_out = 0;
            PrintError("Can't create UDP output socket. Code: %d\n", WSAGetLastError());
            err = -5;
            goto err_label;
        }

        intf->raw_socket_in = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                                        NULL, 0, WSA_FLAG_OVERLAPPED);
        if (intf->raw_socket_in == INVALID_SOCKET) {
            intf->raw_socket_in = 0;
            PrintError("Can't create UDP input socket. Code: %d\n", WSAGetLastError());
            err = -6;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF,
                       (const char*)&socketbuffsize, sizeof(socketbuffsize)) == SOCKET_ERROR) {
            PrintError("setsockopt SO_SNDBUF (UDP out) failed. Code: %d\n", WSAGetLastError());
            err = -7;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_RCVBUF,
                       (const char*)&socketbuffsize, sizeof(socketbuffsize)) == SOCKET_ERROR) {
            PrintError("setsockopt SO_RCVBUF (UDP in) failed. Code: %d\n", WSAGetLastError());
            err = -8;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = INADDR_ANY;
        serveraddr.sin_port = 0;
        if (bind(intf->raw_socket_out, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
            PrintError("bind (UDP out) failed. Code: %d\n", WSAGetLastError());
            err = -10;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
        serveraddr.sin_port = htons(tun->local_port);
        if (bind(intf->raw_socket_in, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
            PrintError("bind (UDP in) failed. Code: %d\n", WSAGetLastError());
            err = -11;
            goto err_label;
        }

        {
            BOOL bNewBehavior = FALSE;
            DWORD dwBytesReturned = 0;
            WSAIoctl(intf->raw_socket_in, SIO_UDP_CONNRESET,
                     &bNewBehavior, sizeof(bNewBehavior),
                     NULL, 0, &dwBytesReturned, NULL, NULL);
        }
#else
        intf->raw_socket_out = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_UDP);
        if (intf->raw_socket_out < 0) {
            intf->raw_socket_out = 0;
            PrintError("Can't create UDP output raw socket\n");
            err = -5;
            goto err_label;
        }

        intf->raw_socket_in = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
        if (intf->raw_socket_in < 0) {
            intf->raw_socket_in = 0;
            PrintError("Can't create UDP input socket\n");
            err = -6;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF,
                       &socketbuffsize, sizeof(socketbuffsize)) < 0) {
            PrintError("Can't set SO_SNDBUF for UDP output socket\n");
            err = -7;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_SNDBUF,
                       &socketbuffsize, sizeof(socketbuffsize)) < 0) {
            PrintError("Can't set SO_SNDBUF for UDP input socket\n");
            err = -8;
            goto err_label;
        }
        if (setsockopt(intf->raw_socket_out, IPPROTO_IP, IP_HDRINCL,
                       val, sizeof(zero)) < 0) {
            PrintError("Can't set IP_HDRINCL for UDP output socket\n");
            err = -9;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_NONE);
        serveraddr.sin_port = 0;
        if (bind(intf->raw_socket_out, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
            PrintError("bind (UDP out) failed\n");
            err = -10;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
        serveraddr.sin_port = htons(tun->local_port);
        if (bind(intf->raw_socket_in, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
            PrintError("bind (UDP in) failed\n");
            err = -11;
            goto err_label;
        }
#endif
        break;

    case PROTO_ICMP:
#ifdef _WIN32
        intf->raw_socket_out = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP,
                                         NULL, 0, WSA_FLAG_OVERLAPPED);
        if (intf->raw_socket_out == INVALID_SOCKET) {
            intf->raw_socket_out = 0;
            PrintError("Can't create ICMP output raw socket. Code: %d\n", WSAGetLastError());
            err = -12;
            goto err_label;
        }

        intf->raw_socket_in = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP,
                                        NULL, 0, WSA_FLAG_OVERLAPPED);
        if (intf->raw_socket_in == INVALID_SOCKET) {
            intf->raw_socket_in = 0;
            PrintError("Can't create ICMP input raw socket. Code: %d\n", WSAGetLastError());
            err = -13;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF,
                       (const char*)&socketbuffsize, sizeof(socketbuffsize)) == SOCKET_ERROR) {
            PrintError("setsockopt SO_SNDBUF (ICMP out) failed. Code: %d\n", WSAGetLastError());
            err = -14;
            goto err_label;
        }
        if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_RCVBUF,
                       (const char*)&socketbuffsize, sizeof(socketbuffsize)) == SOCKET_ERROR) {
            PrintError("setsockopt SO_RCVBUF (ICMP in) failed. Code: %d\n", WSAGetLastError());
            err = -15;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, IPPROTO_IP, IP_HDRINCL,
                       (const char*)val, sizeof(zero)) == SOCKET_ERROR) {
            PrintError("setsockopt IP_HDRINCL (ICMP out) failed. Code: %d\n", WSAGetLastError());
            err = -16;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
        serveraddr.sin_port = 0;

        if (bind(intf->raw_socket_in, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) == SOCKET_ERROR) {
            PrintError("bind (ICMP in) failed. Code: %d\n", WSAGetLastError());
            err = -17;
            goto err_label;
        }

        WORD rcvall = RCVALL_ON;
        DWORD bytes_ret = 0;
        if (WSAIoctl(intf->raw_socket_in, SIO_RCVALL,
                     &rcvall, sizeof(rcvall),
                     NULL, 0, &bytes_ret, NULL, NULL) == SOCKET_ERROR) {
            PrintError("[-] WSAIoctl(SIO_RCVALL) failed: %d\n", WSAGetLastError());
            err = -18;
            goto err_label;
        }
#else
        intf->raw_socket_out = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
        if (intf->raw_socket_out < 0) {
            intf->raw_socket_out = 0;
            PrintError("Can't create ICMP output raw socket\n");
            err = -12;
            goto err_label;
        }

        intf->raw_socket_in = socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_ICMP);
        if (intf->raw_socket_in < 0) {
            intf->raw_socket_in = 0;
            PrintError("Can't create ICMP input raw socket\n");
            err = -13;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, SOL_SOCKET, SO_SNDBUF,
                       &socketbuffsize, sizeof(socketbuffsize)) < 0) {
            PrintError("Can't set SO_SNDBUF for ICMP output socket\n");
            err = -14;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_in, SOL_SOCKET, SO_SNDBUF,
                       &socketbuffsize, sizeof(socketbuffsize)) < 0) {
            PrintError("Can't set SO_SNDBUF for ICMP input socket\n");
            err = -15;
            goto err_label;
        }

        if (setsockopt(intf->raw_socket_out, IPPROTO_IP, IP_HDRINCL,
                       val, sizeof(zero)) < 0) {
            PrintError("Can't set IP_HDRINCL for ICMP output socket\n");
            err = -16;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = htonl(INADDR_NONE);
        serveraddr.sin_port = 0;
        if (bind(intf->raw_socket_out, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
            PrintError("bind (ICMP out) failed\n");
            err = -17;
            goto err_label;
        }

        memset(&serveraddr, 0, sizeof(serveraddr));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_addr.s_addr = tun->local_endpoint.value;
        serveraddr.sin_port = htons(tun->local_port);

        if (bind(intf->raw_socket_in, (struct sockaddr*)&serveraddr, sizeof(serveraddr)) < 0) {
            PrintError("bind (ICMP in) failed\n");
            err = -18;
            goto err_label;
        }
#endif
        break;

    default:
        break;
    }

#ifdef _WIN32
    if (tun_info->mode == MODE_TUN) {
        if (*intf->tun_name == '\0') {
            snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TUN_NAME, tun_idx++);
        }

        wintun_ctx_t* wctx = (wintun_ctx_t*)malloc(sizeof(wintun_ctx_t));
        if (!wctx) {
            err = -20;
            goto err_label;
        }

        DWORD wret = wintun_create(wctx, intf->tun_name);
        if (wret != ERROR_SUCCESS) {
            free(wctx); err = -21;
            goto err_label;
        }

        wret = wintun_start_session(wctx, WINTUN_MIN_RING_CAPACITY * 32);
        if (wret != ERROR_SUCCESS) {
            wintun_destroy(wctx);
            free(wctx);
            err = -22;
            goto err_label;
        }

        intf->wintun_ctx = wctx;

        //wintun has no HANDLE for I/O. Assign an artificial unique integer
        intf->tun_fd = (HANDLE)(intptr_t)(0x10000 +
                       (int)InterlockedIncrement(&wintun_fd_counter));
    } else {
        GUID  guidAdapter;
        DWORD dwResult;

        dwResult = tap_create_adapter("MineTunnel TAP",
                                      "tap0901", &guidAdapter);
        if (dwResult != ERROR_SUCCESS) {
            PrintError("tap_create_adapter failed (0x%08lX)\n", dwResult);
            err = -20;
            goto err_label;
        }

        intf->guidAdapter = guidAdapter;
        intf->wintun_ctx = NULL;

        if (*intf->tun_name == '\0') {
            snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TAP_NAME, tap_idx++);
        }

        dwResult = tap_set_intf_name(&guidAdapter, intf->tun_name);
        if (dwResult != ERROR_SUCCESS) {
            PrintError("tap_set_intf_name failed (0x%08lX)\n", dwResult);
            err = -22;
            goto err_label;
        }

        HANDLE hTap = tap_open_handle(&guidAdapter, TRUE);
        if (!hTap || hTap == INVALID_HANDLE_VALUE) {
            PrintError("tap_open_handle failed for %s\n", intf->tun_name);
            err = -23;
            goto err_label;
        }

        intf->tun_fd = hTap;

        dwResult = tap_set_media_status(hTap, TRUE);
        if (dwResult != ERROR_SUCCESS) {
            PrintError("tap_set_media_status failed for %s (0x%08lX)\n",
                       intf->tun_name, dwResult);
            err = -25;
            goto err_label;
        }
    }
#else
    fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        PrintError("Can't open /dev/net/tun\n");
        err = -20;
        goto err_label;
    }

    memset(&ifr, 0, sizeof(ifr));
    switch (tun_info->mode) {
        case MODE_TUN:
            ifr.ifr_flags = IFF_TUN;
            if (*intf->tun_name == '\0') {
                snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TUN_NAME, tun_idx++);
            }
            break;
        case MODE_TAP:
            ifr.ifr_flags = IFF_TAP;
            if (*intf->tun_name == '\0') {
                snprintf(intf->tun_name, IFNAMSIZ, DEFAULT_MINE_TAP_NAME, tap_idx++);
            }
            break;
        default:
            PrintError("Unknown tunnel mode %u\n", tun_info->mode);
            err = -21;
            goto err_label;
    }

    ifr.ifr_flags |= IFF_NO_PI;
    strncpy(ifr.ifr_name, intf->tun_name, IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void*)&ifr)) < 0) {
        PrintError("ioctl TUNSETIFF failed for %s\n", intf->tun_name);
        err = -22;
        goto err_label;
    }

    strcpy(intf->tun_name, ifr.ifr_name);
    intf->tun_fd = fd;
#endif
    if (intf->raw_socket_in) {
        int sock_fd = (int)intf->raw_socket_in;

        if (add_tun_map(sock_fd, tun)) {
            err = -26;
            goto err_label;
        }

#ifdef _WIN32
        //Associate socket with IOCP and post initial overlapped recv
        if (CreateIoCompletionPort((HANDLE)intf->raw_socket_in,
                                   iocp_handle, 0, 0) == NULL) {
            PrintError("CreateIoCompletionPort (socket) failed. Code: %lu\n",
                       GetLastError());
            err = -27;
            goto err_label;
        }

        fd_tun_map_t key = {
            .fd = (int)intf->raw_socket_in,
            .tun = tun
        };

        fd_tun_map_t* map = (fd_tun_map_t*)hash_table_find(
            &sck_tun_ht, &key, &tun_map_hash_func, &tun_map_cmp_func);

        iocp_ctx_t* ctx = (iocp_ctx_t*)malloc(sizeof(iocp_ctx_t));
        if (!ctx) {
            err = -28;
            goto err_label;
        }

        memset(ctx, 0, sizeof(iocp_ctx_t));
        ctx->op = IOCP_OP_SOCK_READ;
        ctx->sock = intf->raw_socket_in;
        ctx->proto = (int)intf->proto;
        ctx->tun = tun;
        ctx->tun_map = map;
        repost_sock_read(ctx);
#else
        evlist = (struct epoll_event*)realloc(evlist,
                     sizeof(struct epoll_event) * (evlist_count + 1));
        if (!evlist) {
            PrintError("Can't realloc evlist for input socket\n");
            err = -27;
            goto err_label;
        }

        evlist[evlist_count].data.fd = sock_fd;
        evlist[evlist_count].events = EPOLLIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, &evlist[evlist_count]) < 0) {
            PrintError("epoll_ctl ADD failed for input socket\n");
            err = -28;
            goto err_label;
        }
        evlist_count++;
#endif
    }

    tun->worker = (worker_t*)malloc(sizeof(worker_t));
    if (!tun->worker) {
        PrintError("Can't alloc worker\n");
        err = -33;
        goto err_label;
    }

    task_create_worker(tun->worker, tun);
    if (intf->tun_fd) {
        int tun_fd_key = (int)((intptr_t)intf->tun_fd);

        if (add_tun_map(tun_fd_key, tun)) {
            err = -29;
            goto err_label;
        }

#ifdef _WIN32
        if (intf->wintun_ctx) {
            fd_tun_map_t  key = {
                .fd = tun_fd_key,
                .tun = tun
            };

            fd_tun_map_t* map = (fd_tun_map_t*)hash_table_find(
                &sck_tun_ht, &key, &tun_map_hash_func, &tun_map_cmp_func);

            wintun_reader_ctx_t* rctx =
                (wintun_reader_ctx_t*)malloc(sizeof(wintun_reader_ctx_t));

            if (!rctx) {
                err = -30;
                goto err_label;
            }

            rctx->wintun = (wintun_ctx_t*)intf->wintun_ctx;
            rctx->tun = tun;
            rctx->tun_map = map;

            HANDLE wthr = CreateThread(NULL, 0, wintun_reader_thread_func,
                                       rctx, 0, NULL);
            if (!wthr) {
                PrintError("CreateThread (wintun_reader) failed. Code: %lu\n",
                           GetLastError());
                free(rctx);
                err = -31;
                goto err_label;
            }

            if (wintun_reader_count < MAX_TUNNELS) {
                wintun_reader_threads[wintun_reader_count++] = wthr;
            } else {
                PrintError("wintun_reader_threads table full\n");
                TerminateThread(wthr, 0);
                CloseHandle(wthr);
                err = -32;
                goto err_label;
            }
        } else {
            if (CreateIoCompletionPort(intf->tun_fd, iocp_handle, 0, 0) == NULL) {
                PrintError("CreateIoCompletionPort (TAP) failed. Code: %lu\n",
                           GetLastError());
                err = -30;
                goto err_label;
            }

            fd_tun_map_t  key = {
                .fd = tun_fd_key,
                .tun = tun
            };

            fd_tun_map_t* map = (fd_tun_map_t*)hash_table_find(
                &sck_tun_ht, &key, &tun_map_hash_func, &tun_map_cmp_func);

            iocp_ctx_t* ctx = (iocp_ctx_t*)malloc(sizeof(iocp_ctx_t));
            if (!ctx) {
                err = -31;
                goto err_label;
            }

            memset(ctx, 0, sizeof(iocp_ctx_t));
            ctx->op = IOCP_OP_TAP_READ;
            ctx->hTap = intf->tun_fd;
            ctx->tun = tun;
            ctx->tun_map = map;
            repost_tap_read(ctx);
        }
#else
        evlist = (struct epoll_event*)realloc(evlist,
                     sizeof(struct epoll_event) * (evlist_count + 1));
        if (!evlist) {
            PrintError("Can't realloc evlist for tun fd\n");
            err = -30;
            goto err_label;
        }

        evlist[evlist_count].data.fd = tun_fd_key;
        evlist[evlist_count].events = EPOLLIN;
        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, tun_fd_key, &evlist[evlist_count]) < 0) {
            PrintError("epoll_ctl ADD failed for tun fd\n");
            err = -31;
            goto err_label;
        }

        evlist_count++;
#endif
    }

    return 0;

err_label:
#ifdef _WIN32
    if (intf->raw_socket_in && intf->raw_socket_in != INVALID_SOCKET) {
        closesocket(intf->raw_socket_in);
    }

    if (intf->raw_socket_out && intf->raw_socket_out != INVALID_SOCKET) {
        closesocket(intf->raw_socket_out);
    }

    if (intf->wintun_ctx) {
        wintun_destroy((wintun_ctx_t*)intf->wintun_ctx);
        free(intf->wintun_ctx);
        intf->wintun_ctx = NULL;
    } else if (intf->tun_fd && intf->tun_fd != INVALID_HANDLE_VALUE) {
        tap_destroy_adapter(&intf->guidAdapter);
        CloseHandle(intf->tun_fd);
    }
#else
    if (intf->raw_socket_in) {
        close(intf->raw_socket_in);
    }

    if (intf->raw_socket_out) {
        close(intf->raw_socket_out);
    }

    if (intf->tun_fd) {
        close(intf->tun_fd);
    }
#endif
    return err;
}

static int build_tunnels(config_t* cfg) {
    if (cfg->tunnels_count > MAX_TUNNELS) {
        PrintError("Tunnel count %u exceeds MAX_TUNNELS %u\n",
                   cfg->tunnels_count, MAX_TUNNELS);
        return -5;
    }

#ifdef _WIN32
    wintun_global_load();

    iocp_handle = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
    if (!iocp_handle) {
        PrintError("CreateIoCompletionPort failed. Code: %lu\n", GetLastError());
        return -1;
    }

    iocp_pool_init();
    iocp_thr = CreateThread(NULL, 0, iocp_thread_func, NULL, 0, NULL);
    if (!iocp_thr) {
        PrintError("CreateThread (iocp) failed. Code: %lu\n", GetLastError());
        return -2;
    }
#else
    epoll_fd = epoll_create(1);
    if (epoll_fd < 0) {
        PrintError("epoll_create failed\n");
        return -1;
    }
#ifdef DEBUG
    fprintf(stdout, "epoll_fd is %d\n", epoll_fd);
#endif
#endif

    for (uint16_t i = 0; i < cfg->tunnels_count; i++) {
        tunnel_entity_t tun;
        tunnel_entity_t* found_tun = NULL;
        tun_info_t* tun_info = cfg->tunnels + i;
        tunnel_endpoint_t* new_endpoint = (tunnel_endpoint_t*)malloc(sizeof(tunnel_endpoint_t));

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
        if (tun_info->proto == PROTO_ICMP)
            new_endpoint->remote_port = tun_info->icmp_id;

        if (new_endpoint->remote_endpoint.value == 0) {
            tun.dynamic_endpoints = 1;
        }

        memset(&tun.tun_intf, 0, sizeof(tun_intf_t));
        strncpy(tun.tun_intf.tun_name, tun_info->dev_name, MAX_DEV_NAME_LENGTH - 1);
        tun.tun_intf.proto = tun_info->proto;
        tun.tun_intf.mode = tun_info->mode;

        strncpy(tun.bringup_script, tun_info->bringup_script, PATH_MAX - 1);
        strncpy(tun.shutdown_script, tun_info->shutdown_script, PATH_MAX - 1);

        //optional encryptor
        if (*tun_info->encryptor_name != '\0') {
            enc_entinty_t search_entity;
            memset(&search_entity, 0, sizeof(enc_entinty_t));
            strncpy(search_entity.name, tun_info->encryptor_name, MAX_ENCRYPTOR_NAME - 1);

            enc_entinty_t* found_enc = (enc_entinty_t*)hash_table_find(
                &encryptors_ht, &search_entity, &encryptor_hash_func, &encryptor_cmp_func);

            if (!found_enc) {
                PrintError("Can't find encryptor %s\n", search_entity.name);
            } else {
                void* inst = found_enc->create_instance(tun_info->encryption_params);
                if (!inst) {
                    PrintError("Can't create encryptor instance for %s\n", search_entity.name);
                } else {
                    tun.encryptor = found_enc;
                    tun.encryptor_instance = inst;
                }
            }
        }

        found_tun = (tunnel_entity_t*)hash_table_find(
            &tunnels_ht, &tun, &tunnel_hash_func, &tunnel_cmp_func);

        if (found_tun) {
            if (found_tun->tun_intf.proto != tun_info->proto ||
                found_tun->tun_intf.mode != tun_info->mode  ||
                strncmp(found_tun->tun_intf.tun_name, tun_info->dev_name, MAX_DEV_NAME_LENGTH)) {
                PrintError("Bad duplicate tunnel %u.%u.%u.%u: proto/mode/name mismatch\n",
                           tun_info->local_endpoint.addr[0], tun_info->local_endpoint.addr[1],
                           tun_info->local_endpoint.addr[2], tun_info->local_endpoint.addr[3]);
                free(new_endpoint);
                return -2;
            }

            if (new_endpoint->remote_endpoint.value == 0) {
                found_tun->dynamic_endpoints = 1;
            } else {
                bhlist_push_front(&found_tun->remote_endpoint_list, new_endpoint);
                hash_table_add(&found_tun->remote_endpoint_ht,
                               found_tun->remote_endpoint_list, &endpoint_hash_func);
            }
        } else {
            tunnel_entity_t* new_tun = (tunnel_entity_t*)malloc(sizeof(tunnel_entity_t));
            if (!new_tun) {
                PrintError("Internal error. Can't alloc memory for new tunnel entity\n");
                free(new_endpoint);
                return -3;
            }

            memcpy(new_tun, &tun, sizeof(tunnel_entity_t));

            if (new_endpoint->remote_endpoint.value) {
                bhlist_push_front(&new_tun->remote_endpoint_list, new_endpoint);
                hash_table_add(&new_tun->remote_endpoint_ht,
                               new_tun->remote_endpoint_list, &endpoint_hash_func);
            }

            if (init_tun_intf(new_tun, tun_info)) {
                free(new_endpoint);
                free(new_tun);
                return -4;
            }

            if (*new_tun->bringup_script != '\0') {
                ExecScript(new_tun->bringup_script);
            }

            hash_table_add(&tunnels_ht, new_tun, &tunnel_hash_func);
        }
    }

    if (*cfg->global_bringup_script != '\0') {
        ExecScript(cfg->global_bringup_script);
    }

    return 0;
}

static int tunnel_poll(void) {
#ifdef _WIN32
    while (!sig_close) {
        Sleep(POLLING_TIMEOUT);
    }

    return 0;

#else

    while (!sig_close) {
#ifdef DEBUG
        fprintf(stdout, "epoll_wait polling...\n");
#endif
        int fds = epoll_wait(epoll_fd, evlist, (int)evlist_count, EPOLL_TIMEOUT);

        if (fds < 0 && !sig_close) {
            if (errno == EINTR) {
#ifdef DEBUG
                fprintf(stderr, "epoll_wait interrupted\n");
#endif
                continue;
            }
            fprintf(stderr, "epoll_wait error, exit. errno %d\n", errno);
            return -1;
        }

        for (int i = 0; i < fds; i++) {
#ifdef DEBUG
            fprintf(stdout, "evlist[%d].events: 0x%08X  fd: %d\n",
                    i, evlist[i].events, evlist[i].data.fd);
#endif
            if (!(evlist[i].events & EPOLLIN)) {
                continue;
            }

            fd_tun_map_t  tmp_tun = {
                .fd = evlist[i].data.fd
            };

            fd_tun_map_t* found_map = (fd_tun_map_t*)hash_table_find(
                &sck_tun_ht, &tmp_tun, &tun_map_hash_func, &tun_map_cmp_func);

            if (!found_map) {
                continue;
            }            

            task_t* new_task = NULL;
            tunnel_entity_t* current_tun = found_map->tun;
            struct sockaddr_in remote_addr;
            socklen_t remote_len = sizeof(remote_addr);
            ssize_t bytes = 0;
            int remote_endpoint_flag = 0;

            if (found_map->fd == current_tun->tun_intf.raw_socket_in) {
                switch (current_tun->tun_intf.proto) {
                    case PROTO_UDP:
                        bytes = recvfrom(found_map->fd, localbuf,
                                         SOCKET_SIZE, MSG_DONTWAIT,
                                         (struct sockaddr*)&remote_addr, &remote_len);
                        remote_endpoint_flag = 1;
                        break;
                    case PROTO_ICMP:
                        bytes = read(found_map->fd, localbuf,
                                     SOCKET_SIZE);
                        break;
                    default:
                        PrintError("Can't receive packet. Unknown tunnel proto.\n");
                        break;
                }
            } else {
                bytes = read(found_map->fd, localbuf, SOCKET_SIZE);
            }

            if (bytes <= 0) {
                PrintError("Something went wrong in the receiving packets\n");
                continue;
            }

            task_get_new(current_tun->worker, &new_task);
            memcpy(new_task->buffer, localbuf, bytes);
            new_task->tun_map = found_map;
            new_task->size = (uint16_t)bytes;
            new_task->endpoint_flag = remote_endpoint_flag;

#ifdef DEBUG
            fprintf(stdout, "Accepted packet:\n");
            PrintBuffer((unsigned char*)new_task->buffer, (uint32_t)bytes);
#endif

            if (remote_endpoint_flag) {
                new_task->endpoint.remote_endpoint.value = remote_addr.sin_addr.s_addr;
                new_task->endpoint.remote_port = ntohs(remote_addr.sin_port);
            }

            task_add(current_tun->worker);
        }
    }

    return 0;
#endif
}

static void tunnel_stop(void* arg) {
    tunnel_entity_t* tun = (tunnel_entity_t*)arg;

    if (*tun->shutdown_script != '\0') {
        ExecScript(tun->shutdown_script);
    }

    bhlist_clear(tun->remote_endpoint_list, NULL);
    hash_table_clear(&tun->remote_endpoint_ht, NULL);

#ifdef _WIN32
    if (tun->tun_intf.raw_socket_in  && tun->tun_intf.raw_socket_in  != INVALID_SOCKET) {
        closesocket(tun->tun_intf.raw_socket_in);
    }

    if (tun->tun_intf.raw_socket_out && tun->tun_intf.raw_socket_out != INVALID_SOCKET) {
        closesocket(tun->tun_intf.raw_socket_out);
    }

    if (tun->tun_intf.wintun_ctx) {
        wintun_destroy((wintun_ctx_t*)tun->tun_intf.wintun_ctx);
        free(tun->tun_intf.wintun_ctx);
        tun->tun_intf.wintun_ctx = NULL;
    } else if (tun->tun_intf.tun_fd &&
               tun->tun_intf.tun_fd != INVALID_HANDLE_VALUE) {
        tap_destroy_adapter(&tun->tun_intf.guidAdapter);
        CloseHandle(tun->tun_intf.tun_fd);
    }

    WSACleanup();
#else
    if (tun->tun_intf.raw_socket_in) {
        close(tun->tun_intf.raw_socket_in);
    }

    if (tun->tun_intf.raw_socket_out) {
        close(tun->tun_intf.raw_socket_out);
    }

    if (tun->tun_intf.tun_fd) {
        close(tun->tun_intf.tun_fd);
    }
#endif
    if (tun->encryptor && tun->encryptor_instance) {
        tun->encryptor->destroy_instance(tun->encryptor_instance);
    }
}

static void encryptor_release(void* arg) {
    enc_entinty_t* encryptor = (enc_entinty_t*)arg;

    if (encryptor->shared_library_handle) {
#ifdef _WIN32
        FreeLibrary((HMODULE)encryptor->shared_library_handle);
#else
        dlclose(encryptor->shared_library_handle);
#endif
    }
}

#ifdef _WIN32

static void iocp_pool_init(void) {
    InitializeCriticalSection(&iocp_write_pool_cs);
    iocp_write_sem = CreateSemaphore(NULL, IOCP_WRITE_POOL_SIZE,
                                     IOCP_WRITE_POOL_SIZE, NULL);
    iocp_write_pool_mem = (iocp_ctx_t*)malloc(sizeof(iocp_ctx_t) * IOCP_WRITE_POOL_SIZE);
    iocp_write_free_list = NULL;
    for (int i = 0; i < IOCP_WRITE_POOL_SIZE; i++) {
        memset(&iocp_write_pool_mem[i], 0, sizeof(iocp_ctx_t));
        iocp_write_pool_mem[i].op = IOCP_OP_TAP_WRITE;
        iocp_write_pool_mem[i].next_free = iocp_write_free_list;
        iocp_write_free_list = &iocp_write_pool_mem[i];
    }
}

static void iocp_pool_destroy(void) {
    if (iocp_write_sem) {
        CloseHandle(iocp_write_sem);
        iocp_write_sem = NULL;
    }

    if (iocp_write_pool_mem) {
        free(iocp_write_pool_mem);
        iocp_write_pool_mem = NULL;
    }

    iocp_write_free_list = NULL;
    DeleteCriticalSection(&iocp_write_pool_cs);
}

static iocp_ctx_t* iocp_ctx_write_alloc(void) {
    WaitForSingleObject(iocp_write_sem, INFINITE);
    EnterCriticalSection(&iocp_write_pool_cs);

    iocp_ctx_t* ctx = iocp_write_free_list;
    iocp_write_free_list = ctx->next_free;

    LeaveCriticalSection(&iocp_write_pool_cs);
    memset(&ctx->ov, 0, sizeof(OVERLAPPED));
    ctx->next_free = NULL;
    return ctx;
}

static void iocp_ctx_write_free(iocp_ctx_t* ctx) {
    EnterCriticalSection(&iocp_write_pool_cs);
    ctx->next_free = iocp_write_free_list;
    iocp_write_free_list = ctx;
    LeaveCriticalSection(&iocp_write_pool_cs);
    ReleaseSemaphore(iocp_write_sem, 1, NULL);
}

static DWORD WINAPI wintun_reader_thread_func(LPVOID param) {
    wintun_reader_ctx_t* ctx = (wintun_reader_ctx_t*)param;
    wintun_ctx_t* wctx = ctx->wintun;

    while (!sig_close) {
        DWORD pkt_size = 0;
        BYTE* pkt = wintun_receive_packet(wctx, &pkt_size);

        if (pkt) {
            if (pkt_size > 0) {
                task_t* new_task = NULL;
                task_get_new(ctx->tun->worker, &new_task);
                memcpy(new_task->buffer, pkt, pkt_size);
                new_task->tun_map = ctx->tun_map;
                new_task->size = (uint16_t)pkt_size;
                new_task->endpoint_flag = 0;
                task_add(ctx->tun->worker);
                wintun_release_packet(wctx, pkt);
            } else {
                wintun_release_packet(wctx, pkt);
            }
        } else {
            DWORD e = GetLastError();
            if (e == ERROR_NO_MORE_ITEMS) {
                WaitForSingleObject(wctx->read_wait_event, WAIT_FOR_OBJECT_DELAY);
            } else {
                if (!sig_close) {
                    PrintError("wintun_reader: receive error. Code: %lu\n", e);
                }
                break;
            }
        }
    }

    free(ctx);
    return 0;
}

static DWORD WINAPI iocp_thread_func(LPVOID param) {
    //(void)param;
    while (!sig_close) {
        DWORD bytes = 0;
        ULONG_PTR key = 0;
        OVERLAPPED* pov = NULL;

        BOOL ok = GetQueuedCompletionStatus(iocp_handle, &bytes, &key,
                                            &pov, POLLING_TIMEOUT);

        if (key == IOCP_KEY_STOP) {
            break;
        }

        if (!ok) {
            if (!pov) {
                continue;
            }

            iocp_ctx_t* ctx = (iocp_ctx_t*)pov;
            if (!sig_close) {
                PrintError("iocp_thread: I/O error on op %d. Code: %lu\n",
                           ctx->op, GetLastError());
            }

            switch (ctx->op) {
                case IOCP_OP_TAP_WRITE:
                    iocp_ctx_write_free(ctx);
                    break;
                case IOCP_OP_TAP_READ:
                    repost_tap_read(ctx);
                    break;
                case IOCP_OP_SOCK_READ:
                    repost_sock_read(ctx);
                    break;
            }
            continue;
        }

        iocp_ctx_t* ctx = (iocp_ctx_t*)pov;

        switch (ctx->op) {
            case IOCP_OP_TAP_READ: {
                if (bytes > 0) {
                    task_t* new_task = NULL;
                    task_get_new(ctx->tun->worker, &new_task);
                    memcpy(new_task->buffer, ctx->buf, bytes);
                    new_task->tun_map = ctx->tun_map;
                    new_task->size = (uint16_t)bytes;
                    new_task->endpoint_flag = 0;
                    task_add(ctx->tun->worker);
                }
                repost_tap_read(ctx);
                break;
            }

            case IOCP_OP_SOCK_READ: {
                if (bytes > 0) {
                    task_t* new_task = NULL;
                    task_get_new(ctx->tun->worker, &new_task);
                    memcpy(new_task->buffer, ctx->buf, bytes);
                    new_task->tun_map = ctx->tun_map;
                    new_task->size = (uint16_t)bytes;
                    if (ctx->proto == PROTO_UDP) {
                        new_task->endpoint_flag = 1;
                        new_task->endpoint.remote_endpoint.value =
                            ctx->remote_addr.sin_addr.s_addr;
                        new_task->endpoint.remote_port =
                            ntohs(ctx->remote_addr.sin_port);
                    } else {
                        new_task->endpoint_flag = 0;
                    }
                    task_add(ctx->tun->worker);
                }
                repost_sock_read(ctx);
                break;
            }

            case IOCP_OP_TAP_WRITE: {
                iocp_ctx_write_free(ctx);
                break;
            }

            default:
                PrintError("iocp_thread: unknown op %d\n", ctx->op);
                break;
        }
    }
    return 0;
}

static void repost_tap_read(iocp_ctx_t* ctx) {
    if (sig_close) {
        return;
    }

    memset(&ctx->ov, 0, sizeof(OVERLAPPED));
    DWORD bytes_read = 0;
    BOOL ok = ReadFile(ctx->hTap, ctx->buf, SOCKET_SIZE, &bytes_read, &ctx->ov);
    if (!ok && GetLastError() != ERROR_IO_PENDING && !sig_close) {
        PrintError("repost_tap_read: ReadFile failed. Code: %lu\n", GetLastError());
    }
}

static void repost_sock_read(iocp_ctx_t* ctx) {
    if (sig_close) {
        return;
    }

    for (int attempt = 0; attempt < REPOST_SOCK_ATTEMPTS; attempt++) {
        memset(&ctx->ov, 0, sizeof(OVERLAPPED));
        ctx->wsabuf.buf = ctx->buf;
        ctx->wsabuf.len = SOCKET_SIZE;
        DWORD flags = 0, bytes = 0;
        int ret;

        if (ctx->proto == PROTO_UDP) {
            ctx->remote_addr_len = sizeof(ctx->remote_addr);
            ret = WSARecvFrom(ctx->sock, &ctx->wsabuf, 1, &bytes, &flags,
                              (struct sockaddr*)&ctx->remote_addr,
                              &ctx->remote_addr_len, &ctx->ov, NULL);
        } else {
            ret = WSARecv(ctx->sock, &ctx->wsabuf, 1, &bytes, &flags,
                          &ctx->ov, NULL);
        }

        if (!ret || WSAGetLastError() == WSA_IO_PENDING) {
            return;
        }

        int e = WSAGetLastError();
        if (e == WSAECONNRESET || e == WSAENETRESET || e == WSAECONNABORTED) {
            if (!sig_close) {
                PrintError("repost_sock_read: transient error %d, retrying\n", e);
            }
            continue;
        }

        if (!sig_close) {
            PrintError("repost_sock_read: WSARecv failed. Code: %d\n", e);
        }
        return;
    }

    if (!sig_close) {
        PrintError("repost_sock_read: gave up after retries\n");
    }
}

#endif

#ifdef DEBUG
void PrintBuffer(unsigned char* buffer, uint32_t size) {
    uint32_t i = 0;
    fprintf(stdout, "\t");
    while (size) {
        fprintf(stdout, "0x%02X ", *buffer);
        if (++i % 0x10 == 0) { fprintf(stdout, "\n\t"); }
        ++buffer;
        --size;
    }
    fprintf(stdout, "\n");
}
#endif
