#ifndef UTILS_H
#define UTILS_H


#ifndef _WIN32
#include <syslog.h>
#endif
#include <stdio.h>

#include "tunnel.h"




typedef struct tunnel_entity_s tunnel_entity_t;
//declare smart prints which depend of log and verbosity settings
//write to log if it's opened
#ifndef _WIN32
#define PrintInform(...) if (!tunnel_app_getDaemonize() && tunnel_app_getVerbosity()) { \
                            fprintf(stdout, __VA_ARGS__); \
                        } else if (tunnel_app_getDaemonize()) { \
                            syslog(LOG_INFO, __VA_ARGS__); \
                        }
#else
#define PrintInform(...) fprintf(stdout, __VA_ARGS__)
#endif

#ifndef _WIN32
#define PrintError(...) if (!tunnel_app_getDaemonize() && tunnel_app_getVerbosity()) { \
                            fprintf(stderr, __VA_ARGS__); \
                        } else if (tunnel_app_getDaemonize()) { \
                            syslog(LOG_ERR, __VA_ARGS__); \
                        }
#else
#define PrintError(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifdef _WIN32
#define MAX_CLASS_NAME_LEN 512

#ifndef _countof
#define _countof(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#endif

/**
 * Convert the process to a daemon
 * @return 0 on success, non-zero on error
 */
int Daemonize();

/**
 * Check if the process has root privileges
 * @return 0 if root, non-zero otherwise
 */
int CheckRoot();

/**
 * Check if a file exists
 * @param filename Path to file to check
 * @return 1 if file exists, 0 otherwise
 */
int IsFileExists(const char* filename);

/**
 * Execute a shell script
 * @param filename Path to script to execute
 */
void ExecScript(const char* filename);

/**
 * Execute an embedded script
 * @param payload Script payload
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int ExecEmbed(const char* payload, tunnel_entity_t* tun);

#define IP_PORT_KEY_LEN (IPV4_ADDR_LENGTH + PORT_LENGTH)

/**
 * Build the byte-array key (IP + port) used by the hash tables
 * @param ip IPv4 address value
 * @param port Port number
 * @param key Output buffer (at least IP_PORT_KEY_LEN bytes)
 */
void ip_port_key(uint32_t ip, uint16_t port, unsigned char* key);

/**
 * Strip whitespace from line
 * @param line Input line
 * @return Pointer to stripped line
 */
char* strip_line(const char* line);


#endif
