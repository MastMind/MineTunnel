#include <stdlib.h>

#include "embed_commands.h"


const command shell_commands[] = {
    { "interface link up", cmd_interface_link },
    { "interface link down", cmd_interface_link },
    { "interface mtu \"num\"", cmd_interface_set_mtu },
    { "interface ipv4 addr \"ip\" mask \"num\"", cmd_interface_set_ipv4_addr },
    { "interface ipv6 addr \"ip\" mask \"num\"", cmd_interface_set_ipv6_addr },
    { "route add \"ip\" mask \"num\" via gateway \"ip\"", cmd_route_ipv4_add },
    { "route add \"ip\" mask \"num\" via gateway \"ip\" metric \"num\"", cmd_route_ipv4_add },
    { "route6 add \"ip6\" mask \"num\" via gateway \"ip\"", cmd_route_ipv6_add },
    { "route6 add \"ip6\" mask \"num\" via gateway \"ip\" metric \"num\"", cmd_route_ipv6_add },
    { "route del \"ip\" mask \"num\" via gateway \"ip\"", cmd_route_ipv4_del },
    { "route del \"ip\" mask \"num\" via gateway \"ip\" metric \"num\"", cmd_route_ipv4_del },
    { "route6 del \"ip6\" mask \"num\" via gateway \"ip\"", cmd_route_ipv6_del },
    { "route6 del \"ip6\" mask \"num\" via gateway \"ip\" metric \"num\"", cmd_route_ipv6_del },
    { "dns add \"ip\"", cmd_dns_server_ipv4_add },
    { "dns6 add \"ip6\"", cmd_dns_server_ipv6_add },
    { "", NULL } //terminal element
};
