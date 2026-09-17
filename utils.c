#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

#include "tunnel.h"
#include "embed_interpreter.h"
#include "task.h"
#include "utils.h"




#ifndef _WIN32
/**
 * Convert the process to a daemon
 * @return 0 on success, non-zero on error
 */
int Daemonize() {
    return daemon(1, 0);
}
#endif

/**
 * Check if the process has root privileges
 * @return 0 if root, non-zero otherwise
 */
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

/**
 * Check if a file exists
 * @param filename Path to file to check
 * @return 1 if file exists, 0 otherwise
 */
int IsFileExists(const char* filename) {
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(filename);
    return (attr != INVALID_FILE_ATTRIBUTES) ? 1 : 0;
#else
    return access(filename, F_OK) ? 0 : 1;
#endif
}

/**
 * Execute a shell script
 * @param filename Path to script to execute
 */
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

/**
 * Execute an embedded script
 * @param payload Script payload
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int ExecEmbed(const char* payload, tunnel_entity_t* tun) {
    char* delimiter = ";";
    char* payload_copy = strdup(payload);
    int ret = 0;
    if (!payload_copy) {
        PrintError("Can't allocate memory for payload");
        return -1;
    }

    char *token = strtok(payload_copy, delimiter);
    while (token != NULL) {
        if (embed_interpreter_exec(token, tun)) {
            PrintError("Can't exec line %s", token);
            ret = -2;
            goto end;
        }

        token = strtok(NULL, delimiter);
    }

end:
    free(payload_copy);
    return ret;
}

/**
 * Build the byte-array key (IP + port) used by the hash tables
 * @param ip IPv4 address value
 * @param port Port number
 * @param key Output buffer (at least IP_PORT_KEY_LEN bytes)
 */
void ip_port_key(uint32_t ip, uint16_t port, unsigned char* key) {
    memcpy(key, &ip, IPV4_ADDR_LENGTH);
    memcpy(key + IPV4_ADDR_LENGTH, &port, PORT_LENGTH);
}

/**
 * Strip whitespace from line
 * @param line Input line
 * @return Pointer to stripped line
 */
char* strip_line(const char* line) {
    const char* cset = " \t\b\n\r";

    if (!line) {
        return NULL;
    }

    char* ret = (char*)strdup(line + strspn(line, cset));
    if (!ret) {
        return NULL;
    }

    unsigned int str_length = strlen(ret);

    if (!str_length) {
        free(ret);
        return NULL;
    }

    for (int i = str_length - 1; i >= 0; i--) {
        if (!strchr(cset, ret[i])) {
            ret[i + 1] = '\0';
            break;
        }
    }

    return ret;
}
