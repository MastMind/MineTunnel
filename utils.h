#ifndef UTILS_H
#define UTILS_H


#include <syslog.h>

#include "tunnel.h"




//declare smart prints which depend of log and verbosity settings
//write to log if it's opened
#define PrintInform(...) if (!tunnel_app_getDaemonize() && tunnel_app_getVerbosity()) { \
                            fprintf(stdout, __VA_ARGS__); \
                        } else if (tunnel_app_getDaemonize()) { \
                            syslog(LOG_INFO, __VA_ARGS__); \
                        }

#define PrintError(...) if (!tunnel_app_getDaemonize() && tunnel_app_getVerbosity()) { \
                            fprintf(stderr, __VA_ARGS__); \
                        } else if (tunnel_app_getDaemonize()) { \
                            syslog(LOG_ERR, __VA_ARGS__); \
                        }

int Daemonize();
int CheckRoot();
int IsFileExists(const char* filename);
void ExecScript(const char* filename);
int SetIngoreICMPEcho(int ignore);


#endif
