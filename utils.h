#ifndef UTILS_H
#define UTILS_H


#ifndef _WIN32
#include <syslog.h>
#endif

#include "tunnel.h"




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

int Daemonize();
int CheckRoot();
int IsFileExists(const char* filename);
void ExecScript(const char* filename);
uint32_t tunnel_hash_func(void* data);
int tunnel_cmp_func(void* arg1, void* arg2);
uint32_t endpoint_hash_func(void* data);
int endpoint_cmp_func(void* arg1, void* arg2);
uint32_t tun_map_hash_func(void* data);
int tun_map_cmp_func(void* arg1, void* arg2);
uint32_t encryptor_hash_func(void* data);
int encryptor_cmp_func(void* arg1, void* arg2);
uint32_t tun_cache_hash_func(void* data);
int tun_cache_cmp_func(void* arg1, void* arg2);


#endif
