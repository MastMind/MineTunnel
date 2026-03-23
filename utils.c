#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "list.h"
#include "tunnel.h"
#include "task.h"
#include "utils.h"
#include "crc.h"




#ifndef _WIN32
int Daemonize() {
    return daemon(1, 0);
}
#endif

int CheckRoot() {
#ifdef _WIN32
    HANDLE hToken    = NULL;
    TOKEN_ELEVATION elevation = { 0 };
    DWORD cbSize    = sizeof(TOKEN_ELEVATION);

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        return -1;
    }

    BOOL ok = GetTokenInformation(hToken, TokenElevation,
                                  &elevation, cbSize, &cbSize);
    CloseHandle(hToken);

    if (!ok) {
        return -1;
    }

    return elevation.TokenIsElevated ? 0 : 1;

#else
    int uid  = getuid();
    int euid = geteuid();

#ifdef DEBUG
    fprintf(stdout, "uid %d  euid %d\n", uid, euid);
#endif

    if (uid < 0 || euid < 0) {
        return -1;
    }

    if (uid > 0 || euid > 0) {
        return 1;
    }

    return 0;
#endif
}

int IsFileExists(const char* filename) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(filename);
    return (attr != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
#else
    return access(filename, F_OK) ? 0 : 1;
#endif
}

void ExecScript(const char* filename) {
#ifdef _WIN32
    char cmd[PATH_MAX + MAX_STR_LENGTH];
    snprintf(cmd, sizeof(cmd), "cmd.exe /C \"%s\"", filename);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        PrintError("Script %s couldn't be executed. Code: %lu\n",
                   filename, GetLastError());
        return;
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

#else
    pid_t pid = fork();
    if (pid < 0) {
        PrintError("Script %s couldn't be executed. Internal error\n", filename);
        return;
    }

    if (pid) {
        return;
    }

    char* argv[] = { "/bin/sh", (char*)filename, NULL };
    execv("/bin/sh", argv);
    exit(0);
#endif
}

uint32_t tunnel_hash_func(void* data) {
    tunnel_entity_t* tun = (tunnel_entity_t*)data;
    unsigned char hs[IPV4_ADDR_LENGTH + PORT_LENGTH] = { 0 };
    memcpy(hs, &tun->local_endpoint.value, IPV4_ADDR_LENGTH);
    memcpy(hs + IPV4_ADDR_LENGTH, &tun->local_port, PORT_LENGTH);
    return crc32_calc(hs, IPV4_ADDR_LENGTH + PORT_LENGTH);
}

int tunnel_cmp_func(void* arg1, void* arg2) {
    tunnel_entity_t* t1 = (tunnel_entity_t*)arg1;
    tunnel_entity_t* t2 = (tunnel_entity_t*)arg2;
    return (t1->local_endpoint.value == t2->local_endpoint.value &&
            t1->local_port == t2->local_port) ? 0 : 1;
}

uint32_t endpoint_hash_func(void* data) {
    bh_list_t* node = (bh_list_t*)data;
    tunnel_endpoint_t* ep  = (tunnel_endpoint_t*)node->data;
    unsigned char hs[IPV4_ADDR_LENGTH + PORT_LENGTH] = { 0 };
    memcpy(hs, &ep->remote_endpoint.value, IPV4_ADDR_LENGTH);
    memcpy(hs + IPV4_ADDR_LENGTH, &ep->remote_port, PORT_LENGTH);
    return crc32_calc(hs, IPV4_ADDR_LENGTH + PORT_LENGTH);
}

int endpoint_cmp_func(void* arg1, void* arg2) {
    tunnel_endpoint_t* e1 = (tunnel_endpoint_t*)((bh_list_t*)arg1)->data;
    tunnel_endpoint_t* e2 = (tunnel_endpoint_t*)((bh_list_t*)arg2)->data;
    return (e1->remote_endpoint.value == e2->remote_endpoint.value &&
            e1->remote_port == e2->remote_port) ? 0 : 1;
}

uint32_t tun_map_hash_func(void* data) {
    return (uint32_t)((fd_tun_map_t*)data)->fd;
}

int tun_map_cmp_func(void* arg1, void* arg2) {
    return (((fd_tun_map_t*)arg1)->fd == ((fd_tun_map_t*)arg2)->fd) ? 0 : 1;
}

uint32_t encryptor_hash_func(void* data) {
    enc_entinty_t* enc = (enc_entinty_t*)data;
    return crc32_calc((unsigned char*)enc->name, (uint32_t)strlen(enc->name));
}

int encryptor_cmp_func(void* arg1, void* arg2) {
    return strncmp(((enc_entinty_t*)arg1)->name,
                   ((enc_entinty_t*)arg2)->name, MAX_ENCRYPTOR_NAME);
}

uint32_t tun_cache_hash_func(void* data) {
    tun_cache_t* c = (tun_cache_t*)data;
    unsigned char hs[IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH + IPV6_ADDR_LENGTH] = { 0 };
    memcpy(hs, &c->ip.value, IPV4_ADDR_LENGTH);
    memcpy(hs + IPV4_ADDR_LENGTH, c->mac.addr, MAC_ADDR_LENGTH);
    memcpy(hs + IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH, c->ip6.addr, IPV6_ADDR_LENGTH);
    return crc32_calc(hs, IPV4_ADDR_LENGTH + MAC_ADDR_LENGTH + IPV6_ADDR_LENGTH);
}

int tun_cache_cmp_func(void* arg1, void* arg2) {
    tun_cache_t* c1 = (tun_cache_t*)arg1;
    tun_cache_t* c2 = (tun_cache_t*)arg2;
    return (c1->ip.value == c2->ip.value &&
            !memcmp(c1->mac.addr, c2->mac.addr, MAC_ADDR_LENGTH) &&
            !memcmp(c1->ip6.addr, c2->ip6.addr, IPV6_ADDR_LENGTH)) ? 0 : 1;
}
