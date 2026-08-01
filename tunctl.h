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


/**
 * Load Wintun library globally
 * @return Error code
 */
DWORD wintun_global_load(void);

/**
 * Unload Wintun library globally
 */
void wintun_global_unload(void);

/**
 * Get the NET_LUID of the Wintun adapter (needed to configure the TUN
 * interface via the iphlpapi address/route/MTU APIs).
 * @param ctx Wintun context (must have a valid adapter handle)
 * @param luid Pointer to receive the adapter LUID
 * @return ERROR_SUCCESS on success, Win32 error code otherwise
 */
DWORD wintun_get_adapter_luid(wintun_ctx_t* ctx, NET_LUID* luid);

/**
 * Create Wintun adapter
 * @param ctx Wintun context
 * @param name Adapter name
 * @return Error code
 */
DWORD wintun_create(wintun_ctx_t* ctx, LPCSTR name);

/**
 * Destroy Wintun adapter
 * @param ctx Wintun context
 */
void wintun_destroy(wintun_ctx_t* ctx);

/**
 * Start Wintun session
 * @param ctx Wintun context
 * @param capacity Session capacity
 * @return Error code
 */
DWORD wintun_start_session(wintun_ctx_t* ctx, DWORD capacity);

/**
 * Receive packet from Wintun adapter
 * @param ctx Wintun context
 * @param size Pointer to store packet size
 * @return Pointer to packet data
 */
BYTE* wintun_receive_packet(wintun_ctx_t* ctx, DWORD* size);

/**
 * Release packet
 * @param ctx Wintun context
 * @param packet Packet to release
 */
void wintun_release_packet(wintun_ctx_t* ctx, const BYTE* packet);

/**
 * Send packet through Wintun adapter
 * @param ctx Wintun context
 * @param buf Packet data
 * @param size Packet size
 * @return Error code
 */
DWORD wintun_send_packet(wintun_ctx_t* ctx, const char* buf, DWORD size);

#endif
#endif
