#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include "utils.h"




int Daemonize() {
    return daemon(1, 0);
}

int CheckRoot() {
    int uid = getuid();
    int euid = geteuid();

#ifdef DEBUG
    fprintf(stdout, "uid %d\n euid %d\n", uid, euid);
#endif

    if (uid < 0 || euid < 0) {
        return -1; //system error
    }
    
    if (uid > 0 || euid > 0) {
        return 1; //this is not root
    }

    return 0;
}

int IsFileExists(const char* filename) {
    return access(filename, F_OK) ? 0 : 1;
}

void ExecScript(const char* filename) {
    pid_t pid = fork();

    if (pid < 0) {
        PrintError("Script %s couldn't be executed. Internal error\n", filename);
        return;
    }

    if (pid) { //this is parent process and it must not execute something
        return;
    }

    char* argv[] = { "/bin/sh", (char*)filename, NULL };
    execv("/bin/sh", argv);

    exit(0);
}

int SetIngoreICMPEcho(int ignore) {
    FILE* f = fopen("/proc/sys/net/ipv4/icmp_echo_ignore_all", "w");
    char value[3] = "";

    if (!f) {
        return -1;
    }

    sprintf(value, "%d\n", ignore);
    fwrite(value, sizeof(value), 1, f);

    fclose(f);
#ifdef DEBUG
    fprintf(stdout, "Ingore ICMP Echo turned %s\n", ignore ? "off" : "on");
#endif

    return 0;
}
