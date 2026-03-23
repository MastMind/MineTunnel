#ifdef _WIN32

#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>

#include "tunctl.h"
#include "include/wintun.h"
#include "utils.h"




static HMODULE wintun_dll = NULL;
static WINTUN_CREATE_ADAPTER_FUNC* fn_CreateAdapter = NULL;
static WINTUN_CLOSE_ADAPTER_FUNC* fn_CloseAdapter = NULL;
static WINTUN_DELETE_DRIVER_FUNC* fn_DeleteDriver = NULL;
static WINTUN_START_SESSION_FUNC* fn_StartSession = NULL;
static WINTUN_END_SESSION_FUNC* fn_EndSession = NULL;
static WINTUN_GET_READ_WAIT_EVENT_FUNC* fn_GetReadWaitEvent = NULL;
static WINTUN_RECEIVE_PACKET_FUNC* fn_ReceivePacket = NULL;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* fn_ReleaseReceivePacket = NULL;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC* fn_AllocateSendPacket = NULL;
static WINTUN_SEND_PACKET_FUNC* fn_SendPacket = NULL;

#define LOAD_FN(var, type, name) \
    do { \
        void* _p = (void*)GetProcAddress(wintun_dll, (name)); \
        if (!_p) { \
            PrintError("tunctl: symbol '%s' not found in wintun.dll\n", (name)); \
            wintun_global_unload(); \
            return GetLastError() ? GetLastError() : ERROR_PROC_NOT_FOUND; \
        } \
        memcpy(&(var), &_p, sizeof(void*)); \
    } while (0)

DWORD wintun_global_load(void) {
    if (wintun_dll) return ERROR_SUCCESS;

    wintun_dll = LoadLibraryExA("wintun.dll", NULL,
                                LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                LOAD_LIBRARY_SEARCH_DEFAULT_DIRS);
    if (!wintun_dll) {
        DWORD err = GetLastError();
        PrintError("tunctl: failed to load wintun.dll. Code: %lu\n", err);
        return err;
    }

    LOAD_FN(fn_CreateAdapter, WINTUN_CREATE_ADAPTER_FUNC, "WintunCreateAdapter");
    LOAD_FN(fn_CloseAdapter, WINTUN_CLOSE_ADAPTER_FUNC, "WintunCloseAdapter");
    LOAD_FN(fn_DeleteDriver, WINTUN_DELETE_DRIVER_FUNC, "WintunDeleteDriver");
    LOAD_FN(fn_StartSession, WINTUN_START_SESSION_FUNC, "WintunStartSession");
    LOAD_FN(fn_EndSession, WINTUN_END_SESSION_FUNC, "WintunEndSession");
    LOAD_FN(fn_GetReadWaitEvent, WINTUN_GET_READ_WAIT_EVENT_FUNC, "WintunGetReadWaitEvent");
    LOAD_FN(fn_ReceivePacket, WINTUN_RECEIVE_PACKET_FUNC, "WintunReceivePacket");
    LOAD_FN(fn_ReleaseReceivePacket, WINTUN_RELEASE_RECEIVE_PACKET_FUNC, "WintunReleaseReceivePacket");
    LOAD_FN(fn_AllocateSendPacket, WINTUN_ALLOCATE_SEND_PACKET_FUNC, "WintunAllocateSendPacket");
    LOAD_FN(fn_SendPacket, WINTUN_SEND_PACKET_FUNC, "WintunSendPacket");

#ifdef DEBUG
    PrintInform("tunctl: wintun.dll loaded\n");
#endif
    return ERROR_SUCCESS;
}

void wintun_global_unload(void) {
    if (wintun_dll) {
        if (fn_DeleteDriver) fn_DeleteDriver();
        FreeLibrary(wintun_dll);
        wintun_dll = NULL;
    }

    fn_CreateAdapter = NULL;
    fn_CloseAdapter = NULL;
    fn_DeleteDriver = NULL;
    fn_StartSession = NULL;
    fn_EndSession = NULL;
    fn_GetReadWaitEvent = NULL;
    fn_ReceivePacket = NULL;
    fn_ReleaseReceivePacket = NULL;
    fn_AllocateSendPacket = NULL;
    fn_SendPacket = NULL;
}

DWORD wintun_create(wintun_ctx_t* ctx, LPCSTR name) {
    if (!ctx || !name) {
        return ERROR_BAD_ARGUMENTS;
    }

    if (!fn_CreateAdapter) {
        return ERROR_DLL_NOT_FOUND;
    }

    memset(ctx, 0, sizeof(wintun_ctx_t));

    WCHAR wname[MAX_DEV_NAME_LENGTH * 2];
    MultiByteToWideChar(CP_ACP, 0, name, -1, wname,
                        (int)(MAX_DEV_NAME_LENGTH * 2));

    ctx->adapter = fn_CreateAdapter(wname, L"MineTunnel TUN", NULL);
    if (!ctx->adapter) {
        DWORD err = GetLastError();
        PrintError("tunctl: WintunCreateAdapter('%s') failed. Code: %lu\n",
                   name, err);
        return err;
    }
#ifdef DEBUG
    PrintInform("tunctl: wintun adapter '%s' created\n", name);
#endif
    return ERROR_SUCCESS;
}

void wintun_destroy(wintun_ctx_t* ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->session) {
        fn_EndSession(ctx->session);
        ctx->session         = NULL;
        ctx->read_wait_event = NULL;
    }

    if (ctx->adapter) {
        fn_CloseAdapter(ctx->adapter);
        ctx->adapter = NULL;
    }
}

DWORD wintun_start_session(wintun_ctx_t* ctx, DWORD capacity) {
    if (!ctx || !ctx->adapter) {
        return ERROR_BAD_ARGUMENTS;
    }

    if (!fn_StartSession) {
        return ERROR_DLL_NOT_FOUND;
    }

    ctx->session = fn_StartSession(ctx->adapter, capacity);
    if (!ctx->session) {
        DWORD err = GetLastError();
        PrintError("tunctl: WintunStartSession failed. Code: %lu\n", err);
        return err;
    }

    ctx->read_wait_event = fn_GetReadWaitEvent(ctx->session);
    return ERROR_SUCCESS;
}

BYTE* wintun_receive_packet(wintun_ctx_t* ctx, DWORD* size) {
    if (!ctx || !ctx->session || !size) return NULL;
    return fn_ReceivePacket(ctx->session, size);
}

void wintun_release_packet(wintun_ctx_t* ctx, const BYTE* packet) {
    if (!ctx || !ctx->session || !packet) return;
    fn_ReleaseReceivePacket(ctx->session, packet);
}

DWORD wintun_send_packet(wintun_ctx_t* ctx, const char* buf, DWORD size) {
    if (!ctx || !ctx->session || !buf || size == 0) {
        return ERROR_BAD_ARGUMENTS;
    }

    BYTE* dst = fn_AllocateSendPacket(ctx->session, size);
    if (!dst) {
        DWORD err = GetLastError();
        if (err != ERROR_BUFFER_OVERFLOW && err != ERROR_HANDLE_EOF)
            PrintError("tunctl: WintunAllocateSendPacket failed. Code: %lu\n",
                       err);
        return err;
    }

    memcpy(dst, buf, size);
    fn_SendPacket(ctx->session, dst);
    return ERROR_SUCCESS;
}

#endif
