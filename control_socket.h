#ifndef CONTROL_SOCKET_H
#define CONTROL_SOCKET_H

#include <stdint.h>


#define CONTROL_DEFAULT_PORT 9880




int control_socket_start(uint16_t port);
void control_socket_stop(void);

#endif
