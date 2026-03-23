#ifdef _WIN32

#ifndef TUNCTL_H
#define TUNCTL_H

#include <windows.h>
#include <stdint.h>
#include "defines.h"
#include "include/wintun.h"




typedef struct wintun_ctx_s {
    WINTUN_ADAPTER_HANDLE adapter;
    WINTUN_SESSION_HANDLE session;
    HANDLE read_wait_event;
} wintun_ctx_t;


DWORD wintun_global_load(void);
void  wintun_global_unload(void);
DWORD wintun_create(wintun_ctx_t* ctx, LPCSTR name);
void  wintun_destroy(wintun_ctx_t* ctx);
DWORD wintun_start_session(wintun_ctx_t* ctx, DWORD capacity);
BYTE* wintun_receive_packet(wintun_ctx_t* ctx, DWORD* size);
void  wintun_release_packet(wintun_ctx_t* ctx, const BYTE* packet);
DWORD wintun_send_packet(wintun_ctx_t* ctx, const char* buf, DWORD size);

#endif
#endif
