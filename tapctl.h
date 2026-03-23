#ifdef _WIN32

#ifndef TAPCTL_H
#define TAPCTL_H

#include <windows.h>
#include <stdint.h>

#include "defines.h"




typedef enum tap_operation_e {
    TAP_DELETE = 0,
    TAP_SET_NAME
} tap_operation_t;

typedef struct tap_op_params_s {
    union {
        struct {
            LPCWSTR szName;
        } set_name;

        struct {
            uint32_t local_ip;
            uint32_t remote_ip;
            uint32_t remote_mask;
        } tun;
    };
} tap_op_params_t;

DWORD tap_create_adapter(LPCSTR szDeviceDescription, LPCSTR szHwId, LPGUID pguidAdapter);
DWORD tap_destroy_adapter(LPGUID pguidAdapter);
DWORD tap_set_intf_name(LPGUID pguidAdapter, LPCSTR szName);
HANDLE tap_open_handle(LPCGUID pguidAdapter, BOOL bOverlapped);
DWORD tap_set_media_status(HANDLE hDevice, BOOL bUp);

#endif

#endif
