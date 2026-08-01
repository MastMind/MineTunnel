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

/**
 * Hash function for tunnel entities
 * @param data Tunnel entity data
 * @return Hash value
 */
uint32_t tunnel_hash_func(void* data);

/**
 * Comparison function for tunnel entities
 * @param arg1 First tunnel entity
 * @param arg2 Second tunnel entity
 * @return 0 if equal, non-zero otherwise
 */
int tunnel_cmp_func(void* arg1, void* arg2);

/**
 * Hash function for endpoints
 * @param data Endpoint data
 * @return Hash value
 */
uint32_t endpoint_hash_func(void* data);

/**
 * Comparison function for endpoints
 * @param arg1 First endpoint
 * @param arg2 Second endpoint
 * @return 0 if equal, non-zero otherwise
 */
int endpoint_cmp_func(void* arg1, void* arg2);

/**
 * Hash function for file descriptor to tunnel mappings
 * @param data Mapping data
 * @return Hash value
 */
uint32_t tun_map_hash_func(void* data);

/**
 * Comparison function for file descriptor to tunnel mappings
 * @param arg1 First mapping
 * @param arg2 Second mapping
 * @return 0 if equal, non-zero otherwise
 */
int tun_map_cmp_func(void* arg1, void* arg2);

/**
 * Hash function for encryptors
 * @param data Encryptor data
 * @return Hash value
 */
uint32_t encryptor_hash_func(void* data);

/**
 * Comparison function for encryptors
 * @param arg1 First encryptor
 * @param arg2 Second encryptor
 * @return 0 if equal, non-zero otherwise
 */
int encryptor_cmp_func(void* arg1, void* arg2);

/**
 * Hash function for tunnel cache entries
 * @param data Cache entry data
 * @return Hash value
 */
uint32_t tun_cache_hash_func(void* data);

/**
 * Comparison function for tunnel cache entries
 * @param arg1 First cache entry
 * @param arg2 Second cache entry
 * @return 0 if equal, non-zero otherwise
 */
int tun_cache_cmp_func(void* arg1, void* arg2);

/**
 * Strip whitespace from line
 * @param line Input line
 * @return Pointer to stripped line
 */
char* strip_line(const char* line);


#endif
