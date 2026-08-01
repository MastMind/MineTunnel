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

/**
 * Create TAP adapter
 * @param szDeviceDescription Device description
 * @param szHwId Hardware ID
 * @param pguidAdapter Pointer to store adapter GUID
 * @return Error code
 */
DWORD tap_create_adapter(LPCSTR szDeviceDescription, LPCSTR szHwId, LPGUID pguidAdapter);

/**
 * Destroy TAP adapter
 * @param pguidAdapter Adapter GUID
 * @return Error code
 */
DWORD tap_destroy_adapter(LPGUID pguidAdapter);

/**
 * Set TAP interface name
 * @param pguidAdapter Adapter GUID
 * @param szName New interface name
 * @return Error code
 */
DWORD tap_set_intf_name(LPGUID pguidAdapter, LPCSTR szName);

/**
 * Open TAP device handle
 * @param pguidAdapter Adapter GUID
 * @param bOverlapped Overlapped I/O flag
 * @return Device handle
 */
HANDLE tap_open_handle(LPCGUID pguidAdapter, BOOL bOverlapped);

/**
 * Set TAP media status
 * @param hDevice Device handle
 * @param bUp Media status (up/down)
 * @return Error code
 */
DWORD tap_set_media_status(HANDLE hDevice, BOOL bUp);

#endif

#endif
