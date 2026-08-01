#ifndef EMBED_COMMANDS_IMPL_H
#define EMBED_COMMANDS_IMPL_H

#include "tunnel.h"
#include "defines.h"


#define CMD_ARGS char* func_name, tunnel_entity_t* tun




int cmd_interface_link(CMD_ARGS);
int cmd_interface_set_mtu(CMD_ARGS);
int cmd_interface_set_ipv4_addr(CMD_ARGS);
int cmd_interface_set_ipv6_addr(CMD_ARGS);
int cmd_route_ipv4_add(CMD_ARGS);
int cmd_route_ipv6_add(CMD_ARGS);
int cmd_route_ipv4_del(CMD_ARGS);
int cmd_route_ipv6_del(CMD_ARGS);
int cmd_dns_server_ipv4_add(CMD_ARGS);
int cmd_dns_server_ipv6_add(CMD_ARGS);
int cmd_dns_server_ipv4_del(CMD_ARGS);
int cmd_dns_server_ipv6_del(CMD_ARGS);


#endif
