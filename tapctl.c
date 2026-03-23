#ifdef _WIN32

#include <winsock2.h>
#include <iphlpapi.h>
#include <windows.h>
#include <winioctl.h>
#include <objbase.h>
#include <setupapi.h>
#include <devguid.h>
#include <wchar.h>
#include <stdio.h>
#include <stdint.h>

#include "tapctl.h"
#include "utils.h"




//Registry path to Connection\Name.
#define REG_CONNECTIONS_KEY \
    L"SYSTEM\\CurrentControlSet\\Control\\Network\\" \
    L"{4D36E972-E325-11CE-BFC1-08002BE10318}"


//IOCTL codes for tap0901 (from tap-windows.h)
#define TAP_WIN_IOCTL(n) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, (n), METHOD_BUFFERED, FILE_ANY_ACCESS)

#define TAP_IOCTL_SET_MEDIA_STATUS  TAP_WIN_IOCTL(0x06)
// #define TAP_IOCTL_CONFIG_TUN        TAP_WIN_IOCTL(0x0a)
// #define TAP_IOCTL_CONFIG_P2P        TAP_WIN_IOCTL(0x05)


static void *find_function(const WCHAR *libname, const char *funcname, HMODULE *m);
static DWORD get_net_adapter_guid(HDEVINFO hDeviceInfoSet, PSP_DEVINFO_DATA pDeviceInfoData,
                                int iNumAttempts, LPGUID pguidAdapter);
static DWORD get_reg_string(HKEY hKey, LPCWSTR szName, LPWSTR *pszValue);
static DWORD guid_to_wstr(LPCGUID pguid, LPWSTR szBuf, int cchBuf);
static DWORD execute_on_first_adapter(HWND hwndParent, LPGUID pguidAdapter,
                                    tap_operation_t tapOperation,
                                    const tap_op_params_t *pParams);


DWORD tap_create_adapter(LPCSTR szDeviceDescription, LPCSTR szHwId, LPGUID pguidAdapter) {
    DWORD dwResult = 0;
    HMODULE libnewdev = NULL;

    HDEVINFO hDevInfo = SetupDiCreateDeviceInfoList(NULL, NULL);
    if (hDevInfo == INVALID_HANDLE_VALUE) {
        dwResult = GetLastError();
        PrintError("Error in creating SetupDiCreateDeviceInfoList. Code: %lu\n", dwResult);
        return dwResult;
    }

    SP_DEVINFO_DATA deviceInfoData = { sizeof(SP_DEVINFO_DATA) };

    if (!SetupDiCreateDeviceInfo(hDevInfo,
                                "Net",
                                &GUID_DEVCLASS_NET,
                                szDeviceDescription,
                                NULL,
                                DICD_GENERATE_ID,
                                &deviceInfoData)) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: SetupDiCreateDeviceInfo failed. Code: %lu\n", dwResult);
        goto end;
    }

    if (!SetupDiSetSelectedDevice(hDevInfo, &deviceInfoData)) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: SetupDiSetSelectedDevice failed. Code: %lu\n", dwResult);
        goto end;
    }

    size_t cch = strlen(szHwId);
    size_t cbBuf = (cch + 2) * sizeof(char);
    LPSTR szHwIdMultiSz = (LPSTR)malloc(cbBuf);
    if (!szHwIdMultiSz) {
        dwResult = ERROR_OUTOFMEMORY;
        goto end;
    }
    memcpy(szHwIdMultiSz, szHwId, cch + 1);
    szHwIdMultiSz[cch + 1] = '\0';

    BOOL bOk = SetupDiSetDeviceRegistryProperty(hDevInfo,
                                                &deviceInfoData,
                                                SPDRP_HARDWAREID,
                                                (PBYTE)szHwIdMultiSz,
                                                (DWORD)cbBuf);
    free(szHwIdMultiSz);

    if (!bOk) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: SetupDiSetDeviceRegistryProperty failed. Code: %lu\n", dwResult);
        goto end;
    }

    if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, hDevInfo, &deviceInfoData)) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: DIF_REGISTERDEVICE failed. Code: %lu\n", dwResult);
        goto end;
    }

    typedef BOOL (WINAPI *DiInstallDeviceFn)(HWND, HDEVINFO, SP_DEVINFO_DATA *,
                                             SP_DRVINFO_DATA *, DWORD, BOOL *);
    DiInstallDeviceFn installfn = find_function(L"newdev.dll", "DiInstallDevice", &libnewdev);
    if (!installfn) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: DiInstallDevice not found. Code: %lu\n", dwResult);
        goto end;
    }

    if (!installfn(NULL, hDevInfo, &deviceInfoData, NULL, 0, NULL)) {
        dwResult = GetLastError();
        PrintError("tap_create_adapter: DiInstallDevice warning. Code: 0x%08lX\n", dwResult);
    }

    dwResult = get_net_adapter_guid(hDevInfo, &deviceInfoData, 30, pguidAdapter);

end:
    if (libnewdev) {
        FreeLibrary(libnewdev);
    }

    SetupDiDestroyDeviceInfoList(hDevInfo);
    return dwResult;
}

DWORD tap_destroy_adapter(LPGUID pguidAdapter) {
    if (!pguidAdapter) {
        return ERROR_BAD_ARGUMENTS;
    }

    return execute_on_first_adapter(NULL, pguidAdapter, TAP_DELETE, NULL);
}

DWORD tap_set_intf_name(LPGUID pguidAdapter, LPCSTR szName) {
    if (!pguidAdapter || !szName) {
        return ERROR_BAD_ARGUMENTS;
    }

    WCHAR szwName[2*IFNAMSIZ + 2] = {0};

    MultiByteToWideChar(CP_ACP, 0, szName, -1, szwName, 2*IFNAMSIZ + 2);
    tap_op_params_t params = {0};
    params.set_name.szName = szwName;
    return execute_on_first_adapter(NULL, pguidAdapter, TAP_SET_NAME, &params);
}

HANDLE tap_open_handle(LPCGUID pguidAdapter, BOOL bOverlapped) {
    if (!pguidAdapter) {
        return INVALID_HANDLE_VALUE;
    }

    WCHAR szGuid[64] = {0};
    if (StringFromGUID2(pguidAdapter, szGuid, _countof(szGuid)) == 0) {
        return INVALID_HANDLE_VALUE;
    }

    WCHAR szPath[128];
    _snwprintf(szPath, _countof(szPath), L"\\\\.\\Global\\%s.tap", szGuid);

    DWORD dwFlags = FILE_ATTRIBUTE_SYSTEM;
    if (bOverlapped) {
        dwFlags |= FILE_FLAG_OVERLAPPED;
    }

    HANDLE hDevice = CreateFileW(szPath,
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                NULL,
                                OPEN_EXISTING,
                                dwFlags,
                                NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        PrintError("tap_open_handle: CreateFileW failed for %ls. Code: %lu\n",
                   szPath, GetLastError());
    }

    return hDevice;
}

DWORD tap_set_media_status(HANDLE hDevice, BOOL bUp) {
    if (hDevice == INVALID_HANDLE_VALUE) {
        return ERROR_BAD_ARGUMENTS;
    }

    ULONG ulStatus = bUp ? 1UL : 0UL;
    DWORD dwLen = 0;
    if (!DeviceIoControl(hDevice,
                         TAP_IOCTL_SET_MEDIA_STATUS,
                         &ulStatus, sizeof(ulStatus),
                         &ulStatus, sizeof(ulStatus),
                         &dwLen, NULL)) {
        DWORD dwResult = GetLastError();
        PrintError("tap_set_media_status: DeviceIoControl failed. Code: %lu\n", dwResult);
        return dwResult;
    }
    return ERROR_SUCCESS;
}

static DWORD guid_to_wstr(LPCGUID pguid, LPWSTR szBuf, int cchBuf) {
    if (StringFromGUID2(pguid, szBuf, cchBuf) == 0) {
        PrintError("guid_to_wstr: buffer too small\n");
        return ERROR_INSUFFICIENT_BUFFER;
    }

    return ERROR_SUCCESS;
}

static void *find_function(const WCHAR *libname, const char *funcname, HMODULE *m)
{
    WCHAR libpath[MAX_PATH];
    void *fptr = NULL;

    //Make sure the dll is loaded from the system32 folder
    if (!GetSystemDirectoryW(libpath, _countof(libpath)))
    {
        return NULL;
    }

    const size_t path_length = wcslen(libpath) + 1 + wcslen(libname);
    if (path_length >= _countof(libpath))
    {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return NULL;
    }
    wcscat(libpath, L"\\");
    wcscat(libpath, libname);

    *m = LoadLibraryW(libpath);
    if (*m == NULL)
    {
        return NULL;
    }

    fptr = GetProcAddress(*m, funcname);
    if (!fptr)
    {
        FreeLibrary(*m);
        *m = NULL;
        return NULL;
    }

    return fptr;
}

static DWORD get_net_adapter_guid(HDEVINFO hDeviceInfoSet, PSP_DEVINFO_DATA pDeviceInfoData,
                                int iNumAttempts, LPGUID pguidAdapter)
{
    DWORD dwResult = ERROR_BAD_ARGUMENTS;

    if (pguidAdapter == NULL || iNumAttempts < 1)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    HKEY hKey = SetupDiOpenDevRegKey(hDeviceInfoSet, pDeviceInfoData, DICS_FLAG_GLOBAL, 0,
                                     DIREG_DRV, KEY_READ);
    if (hKey == INVALID_HANDLE_VALUE)
    {
        dwResult = GetLastError();
        PrintError("get_net_adapter_guid error: SetupDiOpenDevRegKey failed with result %lu\n", dwResult);
        return dwResult;
    }

    while (iNumAttempts > 0)
    {
        LPWSTR szCfgGuidString = NULL;
        dwResult = RegQueryValueExW(hKey, L"NetCfgInstanceId", NULL, NULL, NULL, NULL);
        if (dwResult != ERROR_SUCCESS)
        {
            if (dwResult == ERROR_FILE_NOT_FOUND && --iNumAttempts > 0)
            {
                Sleep(1000);
                continue;
            }

            SetLastError(dwResult);
            PrintError("get_net_adapter_guid error: querying \"NetCfgInstanceId\" registry value failed with result %lu\n", dwResult);
            break;
        }

        dwResult = get_reg_string(hKey, L"NetCfgInstanceId", &szCfgGuidString);
        if (dwResult != ERROR_SUCCESS)
        {
            break;
        }

        dwResult = SUCCEEDED(CLSIDFromString(szCfgGuidString, (LPCLSID)pguidAdapter))
                       ? ERROR_SUCCESS
                       : ERROR_INVALID_DATA;
        free(szCfgGuidString);
        break;
    }

    RegCloseKey(hKey);
    return dwResult;
}

static DWORD get_reg_string(HKEY hKey, LPCWSTR szName, LPWSTR *pszValue)
{
    if (pszValue == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    DWORD dwValueType = REG_NONE, dwSize = 0;
    DWORD dwResult = RegQueryValueExW(hKey, szName, NULL, &dwValueType, NULL, &dwSize);
    if (dwResult != ERROR_SUCCESS)
    {
        SetLastError(dwResult);
        PrintError("get_reg_string error: RegQueryValueExW failed with result %lu\n", dwResult);
        return dwResult;
    }

    switch (dwValueType)
    {
        case REG_SZ:
        case REG_EXPAND_SZ:
        {
            LPWSTR szValue = (LPWSTR)malloc(dwSize);
            if (szValue == NULL)
            {
                PrintError("get_reg_string error: malloc(%lu) failed with result %lu\n", dwSize, dwResult);
                return ERROR_OUTOFMEMORY;
            }

            dwResult = RegQueryValueExW(hKey, szName, NULL, NULL, (LPBYTE)szValue, &dwSize);
            if (dwResult != ERROR_SUCCESS)
            {
                SetLastError(dwResult);
                PrintError("get_reg_string error:  reading \"%ls\" registry value failed with result %lu\n", szName, dwResult);
                free(szValue);
                return dwResult;
            }

            if (dwValueType == REG_EXPAND_SZ)
            {
                DWORD
                dwSizeExp = dwSize * 2, dwCountExp =
#ifdef UNICODE
                                            dwSizeExp / sizeof(WCHAR);
#else
                                            dwSizeExp / sizeof(WCHAR) - 1;
#endif
                LPWSTR szValueExp = (LPWSTR)malloc(dwSizeExp);
                if (szValueExp == NULL)
                {
                    free(szValue);
                    PrintError("get_reg_string error: malloc(%lu) failed with result %lu\n", dwSizeExp, dwResult);
                    return ERROR_OUTOFMEMORY;
                }

                DWORD dwCountExpResult = ExpandEnvironmentStringsW(szValue, szValueExp, dwCountExp);
                if (dwCountExpResult == 0)
                {
                    PrintError("get_reg_string error: expanding \"%ls\" registry value failed with result %lu\n", szName, dwResult);
                    free(szValueExp);
                    free(szValue);
                    return dwResult;
                }
                else if (dwCountExpResult <= dwCountExp)
                {
                    free(szValue);
                    *pszValue = szValueExp;
                    return ERROR_SUCCESS;
                }
                else
                {
                    free(szValueExp);
#ifdef UNICODE
                    dwSizeExp = dwCountExpResult * sizeof(WCHAR);
#else
                    dwSizeExp = (dwCountExpResult + 1) * sizeof(WCHAR);
#endif
                    dwCountExp = dwCountExpResult;
                    szValueExp = (LPWSTR)malloc(dwSizeExp);
                    if (szValueExp == NULL)
                    {
                        free(szValue);
                        PrintError("get_reg_string error: malloc(%lu) failed with result %lu\n", dwSizeExp, dwResult);
                        return ERROR_OUTOFMEMORY;
                    }

                    dwCountExpResult = ExpandEnvironmentStringsW(szValue, szValueExp, dwCountExp);
                    free(szValue);
                    *pszValue = szValueExp;
                    return ERROR_SUCCESS;
                }
            }
            else
            {
                *pszValue = szValue;
                return ERROR_SUCCESS;
            }
        }

        default:
            PrintError("get_reg_string error: registry value is not string (type %lu)\n", dwValueType);
            return ERROR_UNSUPPORTED_TYPE;
    }
}

static DWORD
execute_on_first_adapter(
    HWND hwndParent,
    LPGUID pguidAdapter,
    tap_operation_t tapOperation,
    const tap_op_params_t *pParams)
{
    DWORD dwResult;
    if (pguidAdapter == NULL) {
        return ERROR_BAD_ARGUMENTS;
    }

    //Enumarate all existance network devices
    HDEVINFO hDevInfoList = SetupDiGetClassDevsEx(
        &GUID_DEVCLASS_NET,
        NULL,
        hwndParent,
        DIGCF_PRESENT,
        NULL, NULL, NULL);
    if (hDevInfoList == INVALID_HANDLE_VALUE) {
        dwResult = GetLastError();
        PrintError("execute_on_first_adapter: SetupDiGetClassDevsEx failed. Code: %lu\n", dwResult);
        return dwResult;
    }

    SP_DEVINFO_LIST_DETAIL_DATA devinfo_list_detail_data = {
        .cbSize = sizeof(SP_DEVINFO_LIST_DETAIL_DATA)
    };
    if (!SetupDiGetDeviceInfoListDetail(hDevInfoList, &devinfo_list_detail_data)) {
        dwResult = GetLastError();
        PrintError("execute_on_first_adapter: SetupDiGetDeviceInfoListDetail failed. Code: %lu\n", dwResult);
        goto cleanup_hDevInfoList;
    }

    dwResult = ERROR_FILE_NOT_FOUND;

    for (DWORD dwIndex = 0;; dwIndex++) {
        SP_DEVINFO_DATA devinfo_data = { .cbSize = sizeof(SP_DEVINFO_DATA) };
        if (!SetupDiEnumDeviceInfo(hDevInfoList, dwIndex, &devinfo_data)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                //Adapter with the current GUID not found
                WCHAR szId[64] = {0};
                guid_to_wstr(pguidAdapter, szId, _countof(szId));
                PrintError("execute_on_first_adapter: adapter %ls not found\n", szId);
                dwResult = ERROR_FILE_NOT_FOUND;
            } else {
                PrintError("execute_on_first_adapter: SetupDiEnumDeviceInfo(%lu) failed. Code: %lu\n",
                           dwIndex, GetLastError());
            }
            goto cleanup_hDevInfoList;
        }

        GUID guidCurrent;
        if (get_net_adapter_guid(hDevInfoList, &devinfo_data, 1, &guidCurrent) != ERROR_SUCCESS ||
            memcmp(pguidAdapter, &guidCurrent, sizeof(GUID))) {
            continue;
        }

        //Found required adapter
        switch (tapOperation) {
            case TAP_DELETE: {
                SP_REMOVEDEVICE_PARAMS removeParams = {
                    .ClassInstallHeader = {
                        .cbSize          = sizeof(SP_CLASSINSTALL_HEADER),
                        .InstallFunction = DIF_REMOVE
                    },
                    .Scope    = DI_REMOVEDEVICE_GLOBAL,
                    .HwProfile = 0
                };

                if (!SetupDiSetClassInstallParams(
                        hDevInfoList,
                        &devinfo_data,
                        &removeParams.ClassInstallHeader,
                        sizeof(removeParams))) {
                    dwResult = GetLastError();
                    PrintError("TAP_DELETE: SetupDiSetClassInstallParams failed. Code: %lu\n", dwResult);
                    break;
                }

                if (!SetupDiCallClassInstaller(DIF_REMOVE, hDevInfoList, &devinfo_data)) {
                    dwResult = GetLastError();
                    PrintError("TAP_DELETE: DIF_REMOVE failed. Code: %lu\n", dwResult);
                    break;
                }

                //Check and message if reboot is required
                SP_DEVINSTALL_PARAMS devInstallParams = { .cbSize = sizeof(SP_DEVINSTALL_PARAMS) };
                if (SetupDiGetDeviceInstallParams(hDevInfoList, &devinfo_data, &devInstallParams)) {
                    if (devInstallParams.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART)) {
                        PrintInform("TAP_DELETE: reboot required to complete removal\n");
                    }
                }

                dwResult = ERROR_SUCCESS;
                break;
            }

            case TAP_SET_NAME: {
                if (!pParams || !pParams->set_name.szName) {
                    dwResult = ERROR_BAD_ARGUMENTS;
                    break;
                }

                WCHAR szGuid[64] = {0};
                dwResult = guid_to_wstr(pguidAdapter, szGuid, _countof(szGuid));
                if (dwResult != ERROR_SUCCESS)
                    break;

                WCHAR szKeyPath[256];
                _snwprintf(szKeyPath, _countof(szKeyPath),
                           REG_CONNECTIONS_KEY L"\\%s\\Connection", szGuid);

                HKEY hKey;
                LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, szKeyPath,
                                          0, KEY_SET_VALUE, &hKey);
                if (lRes != ERROR_SUCCESS) {
                    dwResult = (DWORD)lRes;
                    PrintError("TAP_SET_NAME: RegOpenKeyExW failed for %ls. Code: %lu\n",
                               szKeyPath, dwResult);
                    break;
                }

                LPCWSTR szName = pParams->set_name.szName;
                DWORD cbName = (DWORD)((wcslen(szName) + 1) * sizeof(WCHAR));
                lRes = RegSetValueExW(hKey, L"Name", 0, REG_SZ,
                                      (const BYTE *)szName, cbName);
                RegCloseKey(hKey);

                if (lRes != ERROR_SUCCESS) {
                    dwResult = (DWORD)lRes;
                    PrintError("TAP_SET_NAME: RegSetValueExW failed. Code: %lu\n", dwResult);
                    break;
                }

                {
                    WCHAR szOldName[256] = {0};
                    ULONG ulSize = 0;
                    GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &ulSize);
                    IP_ADAPTER_ADDRESSES* pAddrs = (IP_ADAPTER_ADDRESSES*)malloc(ulSize);
                    if (pAddrs) {
                        if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddrs, &ulSize)
                                == ERROR_SUCCESS) {
                            WCHAR szGuidW[64] = {0};
                            guid_to_wstr(pguidAdapter, szGuidW, _countof(szGuidW));

                            for (IP_ADAPTER_ADDRESSES* p = pAddrs; p; p = p->Next) {
                                WCHAR szAdapterGuid[64] = {0};
                                MultiByteToWideChar(CP_ACP, 0, p->AdapterName, -1,
                                                    szAdapterGuid, _countof(szAdapterGuid));
                                if (wcsstr(szGuidW, szAdapterGuid) != NULL ||
                                    wcsstr(szAdapterGuid, szGuidW + 1) != NULL) {
                                    wcsncpy(szOldName, p->FriendlyName,
                                            _countof(szOldName) - 1);
                                    break;
                                }
                            }
                        }
                        free(pAddrs);
                    }

                    if (szOldName[0] != L'\0' &&
                        wcscmp(szOldName, szName) != 0) {
                        char cmdA[512];
                        char szOldNameA[256], szNewNameA[256];
                        WideCharToMultiByte(CP_ACP, 0, szOldName, -1,
                                            szOldNameA, sizeof(szOldNameA), NULL, NULL);
                        WideCharToMultiByte(CP_ACP, 0, szName, -1,
                                            szNewNameA, sizeof(szNewNameA), NULL, NULL);
                        snprintf(cmdA, sizeof(cmdA),
                                 "powershell -Command \"Rename-NetAdapter -Name '%s' -NewName '%s'\"",
                                 szOldNameA, szNewNameA);
                        system(cmdA);
                    }
                }

                dwResult = ERROR_SUCCESS;
                break;
            }

            default:
                dwResult = ERROR_CALL_NOT_IMPLEMENTED;
                PrintError("execute_on_first_adapter: wrong tapOperation with code %u\n", (uint32_t)tapOperation);
                break;
        }

        break;
    }

cleanup_hDevInfoList:
    SetupDiDestroyDeviceInfoList(hDevInfoList);
    return dwResult;
}

#endif
