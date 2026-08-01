#include "control_socket.h"
#include "tunnel.h"
#include "task.h"
#include "json.h"
#include "utils.h"
#include "defines.h"
#include "hash_table.h"
#include "list.h"
#include "deque.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>

typedef SOCKET sock_t;

#define BAD_SOCK   INVALID_SOCKET
#define CLOSESOCK  closesocket
#define MTX_T      CRITICAL_SECTION
#define MTX_INIT(m)    InitializeCriticalSection(m)
#define MTX_LOCK(m)    EnterCriticalSection(m)
#define MTX_UNLOCK(m)  LeaveCriticalSection(m)
#define MTX_DESTROY(m) DeleteCriticalSection(m)
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <net/if.h>

typedef int sock_t;

#define BAD_SOCK   (-1)
#define CLOSESOCK  close
#define MTX_T      pthread_mutex_t
#define MTX_INIT(m)    pthread_mutex_init(m, NULL)
#define MTX_LOCK(m)    pthread_mutex_lock(m)
#define MTX_UNLOCK(m)  pthread_mutex_unlock(m)
#define MTX_DESTROY(m) pthread_mutex_destroy(m)
#endif

#define CTRL_MAX_CLIENTS      10
#define CTRL_MAX_CONNS        32
#define CTRL_SESSION_TIMEOUT  60
#define CTRL_RECV_CHUNK       4096
#define CTRL_LINE_MAX         8192
#define CTRL_JSON_BUF         65536

//One active client connection (registered or not).
typedef struct {
    int    in_use;
    sock_t sock;
    int    uid; //0 = connected but not yet registered
} ctrl_conn_t;

static ctrl_conn_t g_conns[CTRL_MAX_CONNS];
static int         g_next_uid   = 1;
static MTX_T       g_lock;
static sock_t      g_listen     = BAD_SOCK;
static volatile int g_running   = 0;

#ifdef _WIN32
static HANDLE      g_accept_thr = NULL;
#else
static pthread_t   g_accept_thr;
static int         g_accept_started = 0;
#endif




static void send_all(sock_t s, const char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        int n = send(s, buf + off, (int)(len - off), 0);
        if (n <= 0) {
            return;
        }
        off += (size_t)n;
    }
}

//Extract a STRING field from a JSON object, or NULL.
static const char* obj_str(json_object_t o, const char* key) {
    json_value_t v = json_object_get_element(o, key);
    if (v && v->type == STRING) {
        return (const char*)v->value;
    }
    return NULL;
}

static int addr_is_zero(const uint8_t* a, int len) {
    for (int i = 0; i < len; i++) {
        if (a[i]) {
            return 0;
        }
    }
    return 1;
}

static void fmt_ipv4(const ipv4_addr* ip, char* out, size_t n) {
    if (ip->value == 0) {
        snprintf(out, n, "0");
        return;
    }
    snprintf(out, n, "%u.%u.%u.%u",
             ip->addr[0], ip->addr[1], ip->addr[2], ip->addr[3]);
}

static void fmt_ipv6(const ipv6_addr* ip, char* out, size_t n) {
    if (addr_is_zero(ip->addr, IPV6_ADDR_LENGTH)) {
        snprintf(out, n, "0");
        return;
    }
#ifdef _WIN32
    struct in6_addr a6;
    memcpy(&a6, ip->addr, IPV6_ADDR_LENGTH);
    inet_ntop(AF_INET6, &a6, out, (socklen_t)n);
#else
    struct in6_addr a6;
    memcpy(&a6, ip->addr, IPV6_ADDR_LENGTH);
    if (!inet_ntop(AF_INET6, &a6, out, (socklen_t)n)) {
        snprintf(out, n, "0");
    }
#endif
}

static void fmt_mac(const mac_addr* m, char* out, size_t n) {
    if (m->value == 0) {
        snprintf(out, n, "0");
        return;
    }
    snprintf(out, n, "%02x:%02x:%02x:%02x:%02x:%02x",
             m->addr[0], m->addr[1], m->addr[2],
             m->addr[3], m->addr[4], m->addr[5]);
}

static void fmt_endpoint(const tunnel_endpoint_t* ep, char* out, size_t n) {
    snprintf(out, n, "%u.%u.%u.%u:%u",
             ep->remote_endpoint.addr[0], ep->remote_endpoint.addr[1],
             ep->remote_endpoint.addr[2], ep->remote_endpoint.addr[3],
             (unsigned)ep->remote_port);
}

static const char* proto_str(tun_proto_t p) {
    switch (p) {
        case PROTO_UDP:  return "udp";
        case PROTO_ICMP: return "icmp";
        default:         return "none";
    }
}

static const char* mode_str(tun_mode_t m) {
    switch (m) {
        case MODE_TUN: return "tun";
        case MODE_TAP: return "tap";
        default:       return "unknown";
    }
}

static void iface_addr(const char* ifname, char* out, size_t n) {
    snprintf(out, n, "0.0.0.0");
#ifdef _WIN32
    //Best-effort on Windows: match the adapter FriendlyName.
    ULONG bufsz = 15 * 1024;
    IP_ADAPTER_ADDRESSES* addrs = (IP_ADAPTER_ADDRESSES*)malloc(bufsz);

    if (!addrs) {
        return;
    }
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             NULL, addrs, &bufsz) == NO_ERROR) {
        for (IP_ADAPTER_ADDRESSES* a = addrs; a; a = a->Next) {
            char friendly[256] = {0};
            if (a->FriendlyName) {
                wcstombs(friendly, a->FriendlyName, sizeof(friendly) - 1);
            }
            if (strcmp(friendly, ifname) != 0) {
                continue;
            }
            for (IP_ADAPTER_UNICAST_ADDRESS* u = a->FirstUnicastAddress; u; u = u->Next) {
                if (u->Address.lpSockaddr->sa_family == AF_INET) {
                    struct sockaddr_in* si = (struct sockaddr_in*)u->Address.lpSockaddr;
                    inet_ntop(AF_INET, &si->sin_addr, out, (socklen_t)n);
                    free(addrs);
                    return;
                }
            }
        }
    }

    free(addrs);
#else
    struct ifaddrs* ifas = NULL;
    if (getifaddrs(&ifas) != 0) {
        return;
    }
    for (struct ifaddrs* ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET &&
            ifa->ifa_name && strcmp(ifa->ifa_name, ifname) == 0) {
            struct sockaddr_in* si = (struct sockaddr_in*)ifa->ifa_addr;
            inet_ntop(AF_INET, &si->sin_addr, out, (socklen_t)n);
            break;
        }
    }
    freeifaddrs(ifas);
#endif
}


static void endp_lock(worker_t* w) {
    if (w && w->dyn_endpoints_enabled) {
#ifdef _WIN32
        EnterCriticalSection(&w->dyn_endpoints_mutex);
#else
        pthread_mutex_lock(&w->dyn_endpoints_mutex);
#endif
    }
}
static void endp_unlock(worker_t* w) {
    if (w && w->dyn_endpoints_enabled) {
#ifdef _WIN32
        LeaveCriticalSection(&w->dyn_endpoints_mutex);
#else
        pthread_mutex_unlock(&w->dyn_endpoints_mutex);
#endif
    }
}
static void cache_lock(worker_t* w) {
#ifdef _WIN32
    EnterCriticalSection(&w->tun_cache_mutex);
#else
    pthread_mutex_lock(&w->tun_cache_mutex);
#endif
}
static void cache_unlock(worker_t* w) {
#ifdef _WIN32
    LeaveCriticalSection(&w->tun_cache_mutex);
#else
    pthread_mutex_unlock(&w->tun_cache_mutex);
#endif
}

static void send_envelope(sock_t s, int uid, const char* type,
                          const char* status, json_object_t data) {
    json_object_t root = json_object_create();
    if (!root) {
        if (data) {
            json_object_clear(data);
        }
        return;
    }

    char uidbuf[16];
    snprintf(uidbuf, sizeof(uidbuf), "%d", uid);
    json_object_add_string(root, "uid", uidbuf);
    json_object_add_string(root, "type", type);
    if (status) {
        json_object_add_string(root, "status", status);
    }
    if (!data) {
        data = json_object_create();
    }
    json_object_add_object(root, "data", data);

    char* buf = (char*)malloc(CTRL_JSON_BUF);
    if (buf) {
        buf[0] = '\0';
        if (json_object_to_str(root, buf) == 0) {
            size_t len = strlen(buf);
            if (len + 1 < CTRL_JSON_BUF) {
                buf[len++] = '\n';
                send_all(s, buf, len);
            }
        }
        free(buf);
    }

    json_object_clear(root);
}

static void send_ok(sock_t s, int uid, const char* type, json_object_t data) {
    send_envelope(s, uid, type, "OK", data);
}

static void send_fail(sock_t s, int uid, const char* type, const char* msg) {
    json_object_t data = json_object_create();
    json_object_add_string(data, "message", msg);
    send_envelope(s, uid, type, "fail", data);
}

static int session_count_locked(void) {
    int c = 0;
    for (int i = 0; i < CTRL_MAX_CONNS; i++) {
        if (g_conns[i].in_use && g_conns[i].uid > 0) {
            c++;
        }
    }
    return c;
}

//Register a connection: assign a uid. Returns uid, or -1 if full.
static int session_register(int conn_idx) {
    int uid = -1;
    MTX_LOCK(&g_lock);
    if (session_count_locked() < CTRL_MAX_CLIENTS) {
        uid = g_next_uid++;
        g_conns[conn_idx].uid = uid;
    }
    MTX_UNLOCK(&g_lock);
    return uid;
}

static void session_unregister(int conn_idx) {
    MTX_LOCK(&g_lock);
    g_conns[conn_idx].uid = 0;
    MTX_UNLOCK(&g_lock);
}

//Allocate a connection slot; returns index or -1 when full.
static int conn_alloc(sock_t s) {
    int idx = -1;
    MTX_LOCK(&g_lock);
    for (int i = 0; i < CTRL_MAX_CONNS; i++) {
        if (!g_conns[i].in_use) {
            g_conns[i].in_use = 1;
            g_conns[i].sock = s;
            g_conns[i].uid = 0;
            idx = i;
            break;
        }
    }
    MTX_UNLOCK(&g_lock);
    return idx;
}

static void conn_free(int idx) {
    MTX_LOCK(&g_lock);
    g_conns[idx].in_use = 0;
    g_conns[idx].uid = 0;
    g_conns[idx].sock = BAD_SOCK;
    MTX_UNLOCK(&g_lock);
}

static void cmd_get_tunnels(sock_t s, int uid) {
    tunnel_entity_t* all[MAX_TUNNELS];
    int n = tunnel_collect_all(all, MAX_TUNNELS);

    json_array_t tunnels = json_array_create();

    for (int i = 0; i < n; i++) {
        tunnel_entity_t* t = all[i];
        json_object_t to = json_object_create();

        char portbuf[16];
        snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)t->local_port);
        char localbuf[32];
        fmt_ipv4(&t->local_endpoint, localbuf, sizeof(localbuf));
        if (strcmp(localbuf, "0") == 0) {
            snprintf(localbuf, sizeof(localbuf), "0.0.0.0");
        }

        json_object_add_string(to, "device", t->tun_intf.tun_name);
        json_object_add_string(to, "proto", proto_str(t->tun_intf.proto));
        json_object_add_string(to, "mode", mode_str(t->tun_intf.mode));
        json_object_add_string(to, "local", localbuf);
        json_object_add_string(to, "port", portbuf);
        json_object_add_string(to, "encryption",
                               t->encryptor ? t->encryptor->name : "none");

        //Remote endpoints + link status (endpoints may be mutated by the
        //worker when dynamic endpoints are enabled -> lock).
        json_array_t remote = json_array_create();
        int have_ep = 0;

        endp_lock(t->worker);
        bh_list_t* it = t->remote_endpoint_list;
        while (it) {
            tunnel_endpoint_t* ep = (tunnel_endpoint_t*)it->data;
            if (ep) {
                char ipbuf[32];
                fmt_endpoint(ep, ipbuf, sizeof(ipbuf));
                json_object_t eo = json_object_create();
                json_object_add_string(eo, "ip", ipbuf);
                json_object_add_string(eo, "dynamic",
                                       ep->is_dynamic ? "true" : "false");
                json_array_add_object(remote, eo);
                have_ep = 1;
            }
            it = it->next;
        }
        endp_unlock(t->worker);

        json_object_add_string(to, "link", have_ep ? "up" : "down");
        json_object_add_array(to, "remote", remote);

        json_array_add_object(tunnels, to);
    }

    json_object_t data = json_object_create();
    json_object_add_array(data, "tunnels", tunnels);
    send_ok(s, uid, "tunnel_list", data);
}

//Read the "request".interfaces array; returns count and fills names[] (each
//pointer references memory owned by the parsed tree).
static int req_interfaces(json_object_t req, const char** names, int max) {
    int cnt = 0;
    json_value_t iv = json_object_get_element(req, "interfaces");
    if (iv && iv->type == JSON_ARRAY) {
        json_array_t arr = (json_array_t)iv->value;
        for (unsigned i = 0; i < arr->size && cnt < max; i++) {
            json_value_t e = json_array_get_element(arr, i);
            if (e && e->type == STRING) {
                names[cnt++] = (const char*)e->value;
            }
        }
    }
    return cnt;
}

static void cmd_get_tunnels_addr(sock_t s, int uid, json_object_t req) {
    const char* names[MAX_TUNNELS];
    int n = req_interfaces(req, names, MAX_TUNNELS);

    for (int i = 0; i < n; i++) {
        if (!tunnel_find_by_name(names[i])) {
            char msg[128];
            snprintf(msg, sizeof(msg), "interface %s not found", names[i]);
            send_fail(s, uid, "tunnel_addr", msg);
            return;
        }
    }

    json_array_t arr = json_array_create();
    for (int i = 0; i < n; i++) {
        char addr[64];
        iface_addr(names[i], addr, sizeof(addr));
        json_object_t o = json_object_create();
        json_object_add_string(o, "name", names[i]);
        json_object_add_string(o, "addr", addr);
        json_array_add_object(arr, o);
    }

    json_object_t data = json_object_create();
    json_object_add_array(data, "tunnel_addresses", arr);
    send_ok(s, uid, "tunnel_addr", data);
}

//Append the cache entries of a tunnel into the given array (locked).
static void collect_cache(tunnel_entity_t* t, json_array_t cache_arr) {
    worker_t* w = t->worker;
    if (!w) {
        return;
    }
    int is_tap = (t->tun_intf.mode == MODE_TAP);

    cache_lock(w);
    bh_deque_t* dq = w->tun_cache_list;
    while (dq) {
        hash_table_t* node = (hash_table_t*)dq->data;
        bh_list_t* il = node ? node->data : NULL;
        while (il) {
            tun_cache_t* c = (tun_cache_t*)il->data;
            if (c) {
                char ipv4[32], ipv6[64], mac[32], ttl[16];
                if (is_tap) {
                    snprintf(ipv4, sizeof(ipv4), "0");
                    snprintf(ipv6, sizeof(ipv6), "0");
                    fmt_mac(&c->mac, mac, sizeof(mac));
                } else {
                    fmt_ipv4(&c->ip, ipv4, sizeof(ipv4));
                    fmt_ipv6(&c->ip6, ipv6, sizeof(ipv6));
                    snprintf(mac, sizeof(mac), "0");
                }
                snprintf(ttl, sizeof(ttl), "%u", (unsigned)c->ttl);

                json_object_t co = json_object_create();
                json_object_add_string(co, "ipv4", ipv4);
                json_object_add_string(co, "ipv6", ipv6);
                json_object_add_string(co, "mac", mac);
                json_object_add_string(co, "ttl", ttl);
                json_array_add_object(cache_arr, co);
            }
            il = il->next;
        }
        dq = dq->next;
    }
    cache_unlock(w);
}

static void cmd_get_tunnel_cache(sock_t s, int uid, json_object_t req) {
    const char* names[MAX_TUNNELS];
    int n = req_interfaces(req, names, MAX_TUNNELS);

    for (int i = 0; i < n; i++) {
        if (!tunnel_find_by_name(names[i])) {
            char msg[128];
            snprintf(msg, sizeof(msg), "interface %s not found", names[i]);
            send_fail(s, uid, "tunnel_cache", msg);
            return;
        }
    }

    json_array_t caches = json_array_create();
    for (int i = 0; i < n; i++) {
        tunnel_entity_t* t = tunnel_find_by_name(names[i]);

        //representative VTEP: first known remote endpoint
        char vtep[32] = "0.0.0.0:0";
        endp_lock(t->worker);
        if (t->remote_endpoint_list) {
            tunnel_endpoint_t* ep = (tunnel_endpoint_t*)t->remote_endpoint_list->data;
            if (ep) {
                fmt_endpoint(ep, vtep, sizeof(vtep));
            }
        }
        endp_unlock(t->worker);

        json_array_t cache_arr = json_array_create();
        collect_cache(t, cache_arr);

        json_object_t o = json_object_create();
        json_object_add_string(o, "name", names[i]);
        json_object_add_string(o, "vtep", vtep);
        json_object_add_array(o, "cache", cache_arr);
        json_array_add_object(caches, o);
    }

    json_object_t data = json_object_create();
    json_object_add_array(data, "tunnel_caches", caches);
    send_ok(s, uid, "tunnel_cache", data);
}

static void clear_one_cache(tunnel_entity_t* t) {
    worker_t* w = t->worker;
    if (!w) {
        return;
    }
    cache_lock(w);
    hash_table_clear(&w->tun_cache_ht, free);
    bhdeque_clear(w->tun_cache_list, NULL);
    w->tun_cache_ht = NULL;
    w->tun_cache_list = NULL;
    cache_unlock(w);
}

static void cmd_clear_tunnel_cache(sock_t s, int uid, json_object_t req) {
    const char* names[MAX_TUNNELS];
    int n = req_interfaces(req, names, MAX_TUNNELS);

    for (int i = 0; i < n; i++) {
        if (!tunnel_find_by_name(names[i])) {
            char msg[128];
            snprintf(msg, sizeof(msg), "interface %s not found", names[i]);
            send_fail(s, uid, "cache_cleared", msg);
            return;
        }
    }

    json_array_t echo = json_array_create();
    for (int i = 0; i < n; i++) {
        clear_one_cache(tunnel_find_by_name(names[i]));
        json_array_add_string(echo, names[i]);
    }

    json_object_t data = json_object_create();
    json_object_add_array(data, "interfaces", echo);
    send_ok(s, uid, "cache_cleared", data);
}

static void cmd_clear_tunnel_cache_all(sock_t s, int uid) {
    tunnel_entity_t* all[MAX_TUNNELS];
    int n = tunnel_collect_all(all, MAX_TUNNELS);
    for (int i = 0; i < n; i++) {
        clear_one_cache(all[i]);
    }

    json_object_t data = json_object_create();
    json_object_add_string(data, "interfaces", "all");
    send_ok(s, uid, "cache_cleared", data);
}

//Dispatch one registered-session request. Returns 1 to keep the session
// open, 0 to close it (unregister / session close).
static int dispatch(sock_t s, int conn_idx, int uid, json_object_t root) {
    json_value_t reqv = json_object_get_element(root, "request");
    if (!reqv || reqv->type != JSON_OBJECT) {
        send_fail(s, uid, "error", "missing request");
        return 1;
    }
    json_object_t req = (json_object_t)reqv->value;
    const char* cmd = obj_str(req, "cmd");
    if (!cmd) {
        send_fail(s, uid, "error", "missing cmd");
        return 1;
    }

    //uid in the envelope must match the session uid
    const char* uid_s = obj_str(root, "uid");
    if (!uid_s || atoi(uid_s) != uid) {
        send_fail(s, uid, "error", "uid mismatch");
        return 1;
    }

    if (strcmp(cmd, "keep_alive") == 0) {
        send_ok(s, uid, "session_alive", NULL);
    } else if (strcmp(cmd, "unregister") == 0) {
        send_ok(s, uid, "session_close", NULL);
        session_unregister(conn_idx);
        return 0;
    } else if (strcmp(cmd, "get_tunnels") == 0) {
        cmd_get_tunnels(s, uid);
    } else if (strcmp(cmd, "get_tunnels_addr") == 0) {
        cmd_get_tunnels_addr(s, uid, req);
    } else if (strcmp(cmd, "get_tunnel_cache") == 0) {
        cmd_get_tunnel_cache(s, uid, req);
    } else if (strcmp(cmd, "clear_tunnel_cache") == 0) {
        cmd_clear_tunnel_cache(s, uid, req);
    } else if (strcmp(cmd, "clear_tunnel_cache_all") == 0) {
        cmd_clear_tunnel_cache_all(s, uid);
    } else {
        char msg[160];
        snprintf(msg, sizeof(msg), "unknown command: %s", cmd);
        send_fail(s, uid, "error", msg);
    }
    return 1;
}

// Handle a single JSON line. Returns 1 to continue, 0 to close connection.
static int handle_line(sock_t s, int conn_idx, const char* line) {
    int uid = g_conns[conn_idx].uid;

    json_value_t v = json_from_string(line);
    if (!v) {
        send_fail(s, uid, "error", "invalid JSON");
        return 1;
    }
    if (v->type != JSON_OBJECT) {
        json_object_clear((json_object_t)v->value);
        free(v);
        send_fail(s, uid, "error", "invalid request");
        return 1;
    }
    json_object_t root = (json_object_t)v->value;

    int keep = 1;
    if (uid == 0) {
        //not registered yet: only "register" is accepted
        json_value_t reqv = json_object_get_element(root, "request");
        const char* cmd = (reqv && reqv->type == JSON_OBJECT)
                          ? obj_str((json_object_t)reqv->value, "cmd") : NULL;
        if (cmd && strcmp(cmd, "register") == 0) {
            int new_uid = session_register(conn_idx);
            if (new_uid < 0) {
                send_fail(s, 0, "session_open", "max clients reached");
                keep = 0;
            } else {
                send_ok(s, new_uid, "session_open", NULL);
            }
        } else {
            send_fail(s, 0, "error", "expected register command first");
        }
    } else {
        const char* cmd = obj_str((json_object_t)json_object_get_element(root, "request")->value, "cmd");
        PrintInform("Control socket: client %d cmd='%s'\n", uid, cmd ? cmd : "(null)");
        keep = dispatch(s, conn_idx, uid, root);
    }

    json_object_clear(root);
    free(v);
    return keep;
}

static void handle_client(sock_t s) {
    int idx = conn_alloc(s);
    if (idx < 0) {
        CLOSESOCK(s);
        return;
    }

    PrintInform("Control socket: client connected (slot %d)\n", idx);

#ifdef _WIN32
    DWORD tmo = CTRL_SESSION_TIMEOUT * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tmo, sizeof(tmo));
#else
    struct timeval tv;
    tv.tv_sec = CTRL_SESSION_TIMEOUT;
    tv.tv_usec = 0;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    char* line = (char*)malloc(CTRL_LINE_MAX + 1);
    size_t linelen = 0;
    char chunk[CTRL_RECV_CHUNK];
    int keep = 1;

    while (keep && g_running && line) {
        int n = recv(s, chunk, sizeof(chunk), 0);
        if (n == 0) {
            break;
        }

        if (n < 0) {
#ifdef _WIN32
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT) {
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
#endif
                int uid = g_conns[idx].uid;
                json_object_t data = json_object_create();
                json_object_add_string(data, "message", "inactive for 60s");
                send_envelope(s, uid, "session_expired", NULL, data);
            }
            break;
        }

        for (int i = 0; i < n && keep; i++) {
            char ch = chunk[i];
            if (ch == '\n') {
                line[linelen] = '\0';
                if (linelen > 0) {
                    keep = handle_line(s, idx, line);
                }
                linelen = 0;
            } else if (ch != '\r') {
                if (linelen < CTRL_LINE_MAX) {
                    line[linelen++] = ch;
                } else {
                    linelen = 0;
                }
            }
        }
    }

    free(line);
    conn_free(idx);
    CLOSESOCK(s);
    PrintInform("Control socket: client disconnected (slot %d)\n", idx);
}

#ifdef _WIN32
static DWORD WINAPI client_thread(LPVOID param) {
    sock_t s = (sock_t)(SOCKET)(intptr_t)param;
    handle_client(s);
    return 0;
}
#else
static void* client_thread(void* param) {
    sock_t s = (int)(intptr_t)param;
    handle_client(s);
    return NULL;
}
#endif

static void accept_loop(void) {
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(g_listen, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 300000;

        int r = select((int)g_listen + 1, &rfds, NULL, NULL, &tv);
        if (r <= 0 || !FD_ISSET(g_listen, &rfds)) {
            continue;
        }

        struct sockaddr_in cli;
        socklen_t clilen = sizeof(cli);
        sock_t cs = accept(g_listen, (struct sockaddr*)&cli, &clilen);
        if (cs == BAD_SOCK) {
            continue;
        }

#ifdef _WIN32
        HANDLE th = CreateThread(NULL, 0, client_thread,
                                 (LPVOID)(intptr_t)cs, 0, NULL);
        if (th) {
            CloseHandle(th);
        } else {
            CLOSESOCK(cs);
        }
#else
        pthread_t th;
        if (pthread_create(&th, NULL, client_thread, (void*)(intptr_t)cs) == 0) {
            pthread_detach(th);
        } else {
            CLOSESOCK(cs);
        }
#endif
    }
}

#ifdef _WIN32
static DWORD WINAPI accept_thread(LPVOID param) {
    (void)param;
    accept_loop();
    return 0;
}
#else
static void* accept_thread(void* param) {
    (void)param;
    accept_loop();
    return NULL;
}
#endif

int control_socket_start(uint16_t port) {
    if (port == 0) {
        port = CONTROL_DEFAULT_PORT;
    }

    memset(g_conns, 0, sizeof(g_conns));
    for (int i = 0; i < CTRL_MAX_CONNS; i++) {
        g_conns[i].sock = BAD_SOCK;
    }
    g_next_uid = 1;
    MTX_INIT(&g_lock);

#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        PrintError("control_socket: WSAStartup failed\n");
        return -1;
    }
#endif

    g_listen = socket(AF_INET, SOCK_STREAM, 0);
    if (g_listen == BAD_SOCK) {
        PrintError("control_socket: socket() failed\n");
        return -1;
    }

    int yes = 1;
    setsockopt(g_listen, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(g_listen, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        PrintError("control_socket: bind(127.0.0.1:%u) failed\n", (unsigned)port);
        CLOSESOCK(g_listen);
        g_listen = BAD_SOCK;
        return -1;
    }
    if (listen(g_listen, 5) != 0) {
        PrintError("control_socket: listen() failed\n");
        CLOSESOCK(g_listen);
        g_listen = BAD_SOCK;
        return -1;
    }

    g_running = 1;

#ifdef _WIN32
    g_accept_thr = CreateThread(NULL, 0, accept_thread, NULL, 0, NULL);
    if (!g_accept_thr) {
        g_running = 0;
        CLOSESOCK(g_listen);
        g_listen = BAD_SOCK;
        return -1;
    }
#else
    if (pthread_create(&g_accept_thr, NULL, accept_thread, NULL) != 0) {
        g_running = 0;
        CLOSESOCK(g_listen);
        g_listen = BAD_SOCK;
        return -1;
    }
    g_accept_started = 1;
#endif

    PrintInform("control socket listening on 127.0.0.1:%u\n", (unsigned)port);
    return 0;
}

void control_socket_stop(void) {
    if (!g_running && g_listen == BAD_SOCK) {
        return;
    }
    g_running = 0;
    PrintInform("Control socket: stopping\n");
#ifdef _WIN32
    if (g_accept_thr) {
        WaitForSingleObject(g_accept_thr, INFINITE);
        CloseHandle(g_accept_thr);
        g_accept_thr = NULL;
    }
#else
    if (g_accept_started) {
        pthread_join(g_accept_thr, NULL);
        g_accept_started = 0;
    }
#endif

    if (g_listen != BAD_SOCK) {
        CLOSESOCK(g_listen);
        g_listen = BAD_SOCK;
    }

    MTX_LOCK(&g_lock);
    for (int i = 0; i < CTRL_MAX_CONNS; i++) {
        if (g_conns[i].in_use && g_conns[i].sock != BAD_SOCK) {
            CLOSESOCK(g_conns[i].sock);
        }
    }
    MTX_UNLOCK(&g_lock);

    for (int spins = 0; spins < 200; spins++) {
        int busy = 0;
        MTX_LOCK(&g_lock);
        for (int i = 0; i < CTRL_MAX_CONNS; i++) {
            if (g_conns[i].in_use) {
                busy = 1;
                break;
            }
        }
        MTX_UNLOCK(&g_lock);
        if (!busy) {
            break;
        }
#ifdef _WIN32
        Sleep(10);
#else
        usleep(10000);
#endif
    }

#ifdef _WIN32
    WSACleanup();
#endif
    MTX_DESTROY(&g_lock);
}
