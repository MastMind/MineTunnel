#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include "tunctl.h"
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/rtnetlink.h>
#include <linux/if_addr.h>
#include <arpa/inet.h>
#endif


#include "embed_commands_impl.h"
#include "defines.h"
#include "utils.h"




#ifdef _WIN32
static DWORD get_luid_from_tun(const tunnel_entity_t *tun, NET_LUID *luid);
static int win_pin_vtep_route(const ipv4_addr *vtep);
static int win_unpin_vtep_route(const ipv4_addr *vtep);
#else /* Linux */
static int create_netlink_socket();
static int netlink_send_recv(int sock, struct nlmsghdr *msg, size_t msg_len,
                            char *response, size_t response_len);
#endif

/**
 * Link interface command
 * @param func_name Command name
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_interface_link(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;
    int up = strstr(func_name, "down") != NULL ? 0 : 1;

#ifdef _WIN32
    /* Get interface index from the adapter LUID (works for both TAP via GUID
     * and TUN via the wintun adapter handle) — avoids if_nametoindex which may
     * be unreliable with wintun/tap connection names in some MinGW builds. */
    NET_LUID luid_link;
    if (get_luid_from_tun(tun, &luid_link) != NO_ERROR) {
        PrintError("Failed to resolve LUID for interface %s\n", ifname);
        return -1;
    }
    NET_IFINDEX idx_link = 0;
    if (ConvertInterfaceLuidToIndex(&luid_link, &idx_link) != NO_ERROR) {
        PrintError("ConvertInterfaceLuidToIndex failed for interface %s\n", ifname);
        return -1;
    }

    MIB_IFROW row;
    memset(&row, 0, sizeof(row));
    row.dwIndex = (DWORD)idx_link;
 
    if (GetIfEntry(&row) != NO_ERROR) {
        PrintError("GetIfEntry failed for %s\n", ifname);
        return -1;
    }
 
    row.dwAdminStatus = up ? MIB_IF_ADMIN_STATUS_UP : MIB_IF_ADMIN_STATUS_DOWN;
 
    DWORD r = SetIfEntry(&row);
    if (r != NO_ERROR) {
        PrintError("Failed to %s interface %s: error %lu\n",
                   up ? "bring up" : "bring down", ifname, r);
        return -1;
    }
 
    PrintInform("Interface %s %s successfully\n", ifname, up ? "brought up" : "brought down");
    return 0;
 
#else /* Linux */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        char buf[256];
    } request = {
        .nlh = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .nlmsg_type = RTM_SETLINK,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
            .nlmsg_seq = 1,
            .nlmsg_pid = getpid()
        },
        .ifm = {
            .ifi_family = AF_UNSPEC,
            .ifi_index = ifindex,
            .ifi_flags = up ? IFF_UP : 0,
            .ifi_change = IFF_UP
        }
    };

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to %s interface %s: %s\n",
                      up ? "bring up" : "bring down", ifname, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("Interface %s %s successfully\n", ifname, up ? "brought up" : "brought down");
    return 0;
#endif
}

/**
 * Set interface MTU command
 * @param func_name Command name with MTU value at the end
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_interface_set_mtu(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Extract MTU value from the end of func_name
    // Format: "interface mtu num"
    char *last_space = strrchr(func_name, ' ');
    char *mtu_str = last_space + 1;
    int mtu = atoi(mtu_str);
    if (mtu <= 0) {
        PrintError("Invalid MTU value: %s\n", mtu_str);
        return -1;
    }

#ifdef _WIN32
    NET_LUID luid;
    if (get_luid_from_tun(tun, &luid) != NO_ERROR) return -1;
 
    /* Set MTU for both IPv4 and IPv6 interface entries */
    int families[2] = { AF_INET, AF_INET6 };
    for (int i = 0; i < 2; i++) {
        MIB_IPINTERFACE_ROW row;
        InitializeIpInterfaceEntry(&row);
        row.Family        = families[i];
        row.InterfaceLuid = luid;
 
        DWORD r = GetIpInterfaceEntry(&row);
        if (r != NO_ERROR) continue; /* skip if family not configured */
 
        row.NlMtu            = (ULONG)mtu;
        row.SitePrefixLength = 0;    /* must be 0 when modifying MTU */
 
        r = SetIpInterfaceEntry(&row);
        if (r != NO_ERROR) {
            PrintError("Failed to set MTU %d on interface %s (family %d): error %lu\n",
                       mtu, ifname, families[i], r);
            return -1;
        }
    }
 
    PrintInform("MTU %d set successfully on interface %s\n", mtu, ifname);
    return 0;
 
#else /* Linux */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr nlh;
        struct ifinfomsg ifm;
        char buf[256];
    } request = {
        .nlh = {
            .nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
            .nlmsg_type = RTM_SETLINK,
            .nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK,
            .nlmsg_seq = 1,
            .nlmsg_pid = getpid()
        },
        .ifm = {
            .ifi_family = AF_UNSPEC,
            .ifi_index = ifindex,
            .ifi_flags = 0,
            .ifi_change = 0
        }
    };

    struct rtattr *rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_len  = RTA_LENGTH(4);
    rta->rta_type = IFLA_MTU;
    memcpy(RTA_DATA(rta), &mtu, 4);

    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to set MTU %d on interface %s: %s\n",
                      mtu, ifname, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("MTU %d set successfully on interface %s\n", mtu, ifname);
    return 0;
#endif
}

/**
 * Set interface IPv4 address command
 * @param func_name Command name with IPv4 address and netmask
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_interface_set_ipv4_addr(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Extract IPv4 address and netmask from func_name
    // Format: "interface ipv4 addr ip mask num"
    char *mask_ptr = strstr(func_name, " mask ");
    if (!mask_ptr) {
        PrintError("Invalid ipv4 addr command format\n");
        return -1;
    }
    char *mask_str = mask_ptr + 6;  // Skip " mask "
    int mask_len = atoi(mask_str);
    if (mask_len < 0 || mask_len > 32) {
        PrintError("Invalid mask value: %s\n", mask_str);
        return -1;
    }

    // Find the IP address (between "addr " and " mask ")
    char *addr_ptr = strstr(func_name, "addr ");
    if (!addr_ptr) {
        PrintError("Invalid ipv4 addr command format\n");
        return -1;
    }
    char *ip_str_start = addr_ptr + 5;  // Skip "addr "

    // Copy IP string, terminated at " mask "
    char ip_str[64];
    size_t ip_len = (size_t)(mask_ptr - ip_str_start);
    if (ip_len == 0 || ip_len >= sizeof(ip_str)) {
        PrintError("Invalid IP address in command\n");
        return -1;
    }
    strncpy(ip_str, ip_str_start, ip_len);
    ip_str[ip_len] = '\0';

#ifdef _WIN32
    NET_LUID luid;
    if (get_luid_from_tun(tun, &luid) != NO_ERROR) return -1;
 
    MIB_UNICASTIPADDRESS_ROW row;
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid                 = luid;
    row.Address.Ipv4.sin_family       = AF_INET;
    row.OnLinkPrefixLength            = (UINT8)mask_len;
    row.DadState                      = IpDadStatePreferred;
    row.SkipAsSource                  = FALSE;
 
    if (InetPtonA(AF_INET, ip_str, &row.Address.Ipv4.sin_addr) != 1) {
        PrintError("Invalid IPv4 address: %s\n", ip_str);
        return -1;
    }
 
    /* Delete existing address first to avoid duplicate error */
    DeleteUnicastIpAddressEntry(&row);
 
    DWORD r = CreateUnicastIpAddressEntry(&row);
    if (r != NO_ERROR) {
        PrintError("Failed to set IPv4 addr %s/%d on %s: error %lu\n",
                   ip_str, mask_len, ifname, r);
        return -1;
    }
 
    PrintInform("Set IPv4 %s/%d on interface %s\n", ip_str, mask_len, ifname);
    return 0;
 
#else /* Linux */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    // Parse IP address
    struct in_addr ip_addr;
    if (inet_pton(AF_INET, ip_str, &ip_addr) <= 0) {
        PrintError("Invalid IPv4 address: %s\n", ip_str);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
        char buf[256];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    request.nlh.nlmsg_type  = RTM_NEWADDR;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.ifa.ifa_family    = AF_INET;
    request.ifa.ifa_prefixlen = (uint8_t)mask_len;
    request.ifa.ifa_flags     = 0;
    request.ifa.ifa_scope     = RT_SCOPE_UNIVERSE;
    request.ifa.ifa_index     = (unsigned int)ifindex;

    // Add IFA_LOCAL attribute
    struct rtattr *rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &ip_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add IFA_ADDRESS attribute
    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len  = RTA_LENGTH(4);
    memcpy(RTA_DATA(rta), &ip_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to set IPv4 address %s/%d on interface %s: %s\n",
                      ip_str, mask_len, ifname, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("IPv4 address %s/%d set successfully on interface %s\n", ip_str, mask_len, ifname);
    return 0;
#endif
}

/**
 * Set interface IPv6 address command
 * @param func_name Command name with IPv6 address and netmask
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_interface_set_ipv6_addr(CMD_ARGS) {
#ifdef _WIN32
    //TODO implement this for Windows
    return 0;
#else
    const char *ifname = tun->tun_intf.tun_name;
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    // Extract IPv6 address and netmask from func_name
    // Format: "interface ipv6 addr "ip" mask "num""
    char *mask_ptr = strstr(func_name, " mask ");
    if (!mask_ptr) {
        PrintError("Invalid ipv6 addr command format\n");
        return -1;
    }
    char *mask_str = mask_ptr + 6;  // Skip " mask "
    int mask_len = atoi(mask_str);
    if (mask_len < 0 || mask_len > 128) {
        PrintError("Invalid mask value: %s\n", mask_str);
        return -1;
    }

    // Find the IP address (between "addr " and " mask ")
    char *addr_ptr = strstr(func_name, "addr ");
    if (!addr_ptr) {
        PrintError("Invalid ipv6 addr command format\n");
        return -1;
    }
    char *ip_str_start = addr_ptr + 5;  // Skip "addr "

    // Copy IP string, terminated at " mask "
    char ip_str[64];
    size_t ip_len = (size_t)(mask_ptr - ip_str_start);
    if (ip_len == 0 || ip_len >= sizeof(ip_str)) {
        PrintError("Invalid IP address in command\n");
        return -1;
    }
    strncpy(ip_str, ip_str_start, ip_len);
    ip_str[ip_len] = '\0';

    // Parse IPv6 address
    struct in6_addr ip_addr;
    if (inet_pton(AF_INET6, ip_str, &ip_addr) <= 0) {
        PrintError("Invalid IPv6 address: %s\n", ip_str);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr  nlh;
        struct ifaddrmsg ifa;
        char buf[256];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    request.nlh.nlmsg_type  = RTM_NEWADDR;
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.ifa.ifa_family    = AF_INET6;
    request.ifa.ifa_prefixlen = (uint8_t)mask_len;
    request.ifa.ifa_flags     = 0;
    request.ifa.ifa_scope     = RT_SCOPE_UNIVERSE;
    request.ifa.ifa_index     = (unsigned int)ifindex;

    // Add IFA_LOCAL attribute
    struct rtattr *rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = IFA_LOCAL;
    rta->rta_len  = RTA_LENGTH(16);
    memcpy(RTA_DATA(rta), &ip_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add IFA_ADDRESS attribute
    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = IFA_ADDRESS;
    rta->rta_len  = RTA_LENGTH(16);
    memcpy(RTA_DATA(rta), &ip_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to set IPv6 address %s/%d on interface %s: %s\n",
                      ip_str, mask_len, ifname, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("IPv6 address %s/%d set successfully on interface %s\n", ip_str, mask_len, ifname);
    return 0;
#endif
}

/**
 * Add IPv4 route command
 * @param func_name Command name with route parameters
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_route_ipv4_add(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: route add "ip" mask "num" via gateway "ip"
    // Extract destination IP
    char *dest_ptr = strstr(func_name, "add ");
    if (!dest_ptr) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    dest_ptr += 4;
    char *dest_end = strstr(dest_ptr, " mask ");
    if (!dest_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char dest_ip_str[64];
    strncpy(dest_ip_str, dest_ptr, dest_end - dest_ptr);
    dest_ip_str[dest_end - dest_ptr] = '\0';

    // Extract mask
    char *mask_ptr = dest_end + 6; // " mask "
    char *mask_end = strstr(mask_ptr, " via gateway ");
    if (!mask_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char mask_str[64];
    strncpy(mask_str, mask_ptr, mask_end - mask_ptr);
    mask_str[mask_end - mask_ptr] = '\0';
    int mask_len = atoi(mask_str);

    // Extract gateway IP and optional metric
    // Format: "...via gateway <ip>" or "...via gateway <ip> metric <num>"
    char *gateway_ptr = mask_end + 13; // " via gateway "
    int metric = 0;
    char gateway_ip_str[64];

    char *metric_ptr = strstr(gateway_ptr, " metric ");
    if (metric_ptr) {
        size_t gw_len = (size_t)(metric_ptr - gateway_ptr);
        if (gw_len == 0 || gw_len >= sizeof(gateway_ip_str)) {
            PrintError("Invalid gateway in route command\n");
            return -1;
        }
        strncpy(gateway_ip_str, gateway_ptr, gw_len);
        gateway_ip_str[gw_len] = '\0';
        metric = atoi(metric_ptr + 8); // skip " metric "
    } else {
        strncpy(gateway_ip_str, gateway_ptr, sizeof(gateway_ip_str) - 1);
        gateway_ip_str[sizeof(gateway_ip_str) - 1] = '\0';
    }

#ifdef _WIN32
    NET_LUID luid;
    if (get_luid_from_tun(tun, &luid) != NO_ERROR) return -1;

    (void)ifname;  /* on Windows routes are keyed by LUID, not by name */
    /* 1. Pin a host route to every VTEP via the CURRENT physical gateway,
     *    BEFORE installing the tunnel route, so that the encapsulated traffic
     *    addressed to the VTEP itself is not black-holed by the new route.
     *    Mirrors the Linux netlink logic (RTM_GETROUTE -> add <vtep>/32). */
    if (tun->remote_endpoint_list) {
        bh_list_t *ep_it = tun->remote_endpoint_list;
        while (ep_it) {
            tunnel_endpoint_t *ep = (tunnel_endpoint_t *)ep_it->data;
            if (ep && ep->remote_endpoint.value) {
                win_pin_vtep_route(&ep->remote_endpoint);
            }
            ep_it = ep_it->next;
        }
    }

    /* 2. Install the tunnel route specified in the command. */
    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid     = luid;
    row.ValidLifetime     = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.Metric            = (metric > 0) ? (ULONG)metric : 1;
    row.Protocol          = MIB_IPPROTO_NETMGMT;
    row.Origin            = NlroManual;

    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.PrefixLength = (UINT8)mask_len;
    if (inet_pton(AF_INET, dest_ip_str,
                  &row.DestinationPrefix.Prefix.Ipv4.sin_addr) != 1) {
        PrintError("Invalid destination address: %s\n", dest_ip_str);
        return -1;
    }

    row.NextHop.Ipv4.sin_family = AF_INET;
    if (inet_pton(AF_INET, gateway_ip_str,
                  &row.NextHop.Ipv4.sin_addr) != 1) {
        PrintError("Invalid gateway address: %s\n", gateway_ip_str);
        return -1;
    }

    DWORD r = CreateIpForwardEntry2(&row);
    if (r == ERROR_OBJECT_ALREADY_EXISTS) {
        r = SetIpForwardEntry2(&row);
    }
    if (r != NO_ERROR) {
        PrintError("Failed to add route %s/%d via %s: error %lu\n",
                   dest_ip_str, mask_len, gateway_ip_str, r);
        return -1;
    }

    PrintInform("Added route %s/%d via %s metric %d\n",
                dest_ip_str, mask_len, gateway_ip_str, metric);
    return 0;

#else /* Linux */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    // 1. Add routes to each VTEP from remote_endpoint_list
    if (tun->remote_endpoint_list) {
        bh_list_t* cur_remote_endpoint_list = tun->remote_endpoint_list;
        while (cur_remote_endpoint_list) {
            tunnel_endpoint_t* cur_remote_endpoint =
                (tunnel_endpoint_t*)cur_remote_endpoint_list->data;

            // Query existing route to find the gateway for this VTEP
            struct {
                struct nlmsghdr nlh;
                struct rtmsg    rtm;
                char buf[RTA_LENGTH(4)];
            } get_request;

            memset(&get_request, 0, sizeof(get_request));
            get_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
            get_request.nlh.nlmsg_flags = NLM_F_REQUEST;
            get_request.nlh.nlmsg_type  = RTM_GETROUTE;
            get_request.nlh.nlmsg_seq   = 1;
            get_request.nlh.nlmsg_pid   = getpid();

            get_request.rtm.rtm_family   = AF_INET;
            get_request.rtm.rtm_dst_len  = 32;
            get_request.rtm.rtm_src_len  = 0;
            get_request.rtm.rtm_tos      = 0;
            get_request.rtm.rtm_table    = RT_TABLE_MAIN;
            get_request.rtm.rtm_protocol = RTPROT_UNSPEC;
            get_request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
            get_request.rtm.rtm_type     = RTN_UNSPEC;

            // Add RTA_DST attribute (VTEP IP)
            struct rtattr *rta = (struct rtattr *)((char *)&get_request +
                                  NLMSG_ALIGN(get_request.nlh.nlmsg_len));
            rta->rta_type = RTA_DST;
            rta->rta_len  = RTA_LENGTH(4);
            memcpy(RTA_DATA(rta), &cur_remote_endpoint->remote_endpoint.value, 4);
            get_request.nlh.nlmsg_len = NLMSG_ALIGN(get_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            char response[4096];
            int ret = netlink_send_recv(sock, &get_request.nlh, get_request.nlh.nlmsg_len,
                                        response, sizeof(response));
            if (ret < 0) {
                PrintError("Failed to query route for VTEP %u.%u.%u.%u\n",
                          cur_remote_endpoint->remote_endpoint.addr[0],
                          cur_remote_endpoint->remote_endpoint.addr[1],
                          cur_remote_endpoint->remote_endpoint.addr[2],
                          cur_remote_endpoint->remote_endpoint.addr[3]);
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            // Parse response to find gateway
            uint32_t vtep_gateway = 0;
            struct nlmsghdr *resp = (struct nlmsghdr *)response;
            int resp_len = ret;
            for (; NLMSG_OK(resp, (unsigned int)resp_len);
                   resp = NLMSG_NEXT(resp, resp_len))
            {
                if (resp->nlmsg_type != RTM_NEWROUTE)
                    continue;

                struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(resp);
                if (rtm->rtm_family != AF_INET)
                    continue;

                struct rtattr *attr = RTM_RTA(rtm);
                int attr_len = RTM_PAYLOAD(resp);
                for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                    if (attr->rta_type == RTA_GATEWAY) {
                        vtep_gateway = *(uint32_t *)RTA_DATA(attr);
                    }
                }
            }

            if (vtep_gateway == 0) {
                PrintError("No route found for VTEP %u.%u.%u.%u\n",
                          cur_remote_endpoint->remote_endpoint.addr[0],
                          cur_remote_endpoint->remote_endpoint.addr[1],
                          cur_remote_endpoint->remote_endpoint.addr[2],
                          cur_remote_endpoint->remote_endpoint.addr[3]);
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            // Create route: ip route add <vtep_ip>/32 via <vtep_gateway>
            struct {
                struct nlmsghdr nlh;
                struct rtmsg    rtm;
                char buf[1024];
            } add_request;

            memset(&add_request, 0, sizeof(add_request));
            add_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
            add_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
            add_request.nlh.nlmsg_type  = RTM_NEWROUTE;
            add_request.nlh.nlmsg_seq   = 1;
            add_request.nlh.nlmsg_pid   = getpid();

            add_request.rtm.rtm_family   = AF_INET;
            add_request.rtm.rtm_dst_len  = 32;
            add_request.rtm.rtm_src_len  = 0;
            add_request.rtm.rtm_tos      = 0;
            add_request.rtm.rtm_table    = RT_TABLE_MAIN;
            add_request.rtm.rtm_protocol = RTPROT_STATIC;
            add_request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
            add_request.rtm.rtm_type     = RTN_UNICAST;
            add_request.rtm.rtm_flags    = 0;

            rta = (struct rtattr *)((char *)&add_request +
                   NLMSG_ALIGN(add_request.nlh.nlmsg_len));
            rta->rta_type = RTA_DST;
            rta->rta_len  = RTA_LENGTH(4);
            memcpy(RTA_DATA(rta), &cur_remote_endpoint->remote_endpoint.value, 4);
            add_request.nlh.nlmsg_len = NLMSG_ALIGN(add_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            rta = (struct rtattr *)((char *)&add_request +
                   NLMSG_ALIGN(add_request.nlh.nlmsg_len));
            rta->rta_type = RTA_GATEWAY;
            rta->rta_len  = RTA_LENGTH(4);
            memcpy(RTA_DATA(rta), &vtep_gateway, 4);
            add_request.nlh.nlmsg_len = NLMSG_ALIGN(add_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            char add_response[4096];
            ret = netlink_send_recv(sock, &add_request.nlh, add_request.nlh.nlmsg_len,
                                    add_response, sizeof(add_response));
            if (ret < 0) {
                PrintError("Failed to add route to VTEP %u.%u.%u.%u\n",
                          cur_remote_endpoint->remote_endpoint.addr[0],
                          cur_remote_endpoint->remote_endpoint.addr[1],
                          cur_remote_endpoint->remote_endpoint.addr[2],
                          cur_remote_endpoint->remote_endpoint.addr[3]);
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            struct nlmsghdr *add_resp = (struct nlmsghdr *)add_response;
            if (add_resp->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(add_resp);
                if (err->error) {
                    PrintError("Failed to add route to VTEP %u.%u.%u.%u: %s\n",
                              cur_remote_endpoint->remote_endpoint.addr[0],
                              cur_remote_endpoint->remote_endpoint.addr[1],
                              cur_remote_endpoint->remote_endpoint.addr[2],
                              cur_remote_endpoint->remote_endpoint.addr[3],
                              strerror(-err->error));
                    cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                    continue;
                }
            }

            PrintInform("Added route to VTEP %u.%u.%u.%u via %u.%u.%u.%u\n",
                        cur_remote_endpoint->remote_endpoint.addr[0],
                        cur_remote_endpoint->remote_endpoint.addr[1],
                        cur_remote_endpoint->remote_endpoint.addr[2],
                        cur_remote_endpoint->remote_endpoint.addr[3],
                        ((uint8_t *)&vtep_gateway)[0],
                        ((uint8_t *)&vtep_gateway)[1],
                        ((uint8_t *)&vtep_gateway)[2],
                        ((uint8_t *)&vtep_gateway)[3]);

            cur_remote_endpoint_list = cur_remote_endpoint_list->next;
        }
    }

    // 2. Add the main route specified in the command
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char buf[1024];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    request.nlh.nlmsg_type  = RTM_NEWROUTE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.rtm.rtm_family   = AF_INET;
    request.rtm.rtm_dst_len  = mask_len;
    request.rtm.rtm_src_len  = 0;
    request.rtm.rtm_tos      = 0;
    request.rtm.rtm_table    = RT_TABLE_MAIN;
    request.rtm.rtm_protocol = RTPROT_STATIC;
    request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
    request.rtm.rtm_type     = RTN_UNICAST;
    request.rtm.rtm_flags    = 0;

    // Add RTA_DST
    struct rtattr *rta = (struct rtattr *)((char *)&request +
                          NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(4);

    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_ip_str, &dest_addr) <= 0) {
        PrintError("Invalid destination IP address: %s\n", dest_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &dest_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_GATEWAY
    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len  = RTA_LENGTH(4);

    struct in_addr gw_addr;
    if (inet_pton(AF_INET, gateway_ip_str, &gw_addr) <= 0) {
        PrintError("Invalid gateway IP address: %s\n", gateway_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &gw_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_PRIORITY (metric) if specified
    if (metric > 0) {
        rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
        rta->rta_type = RTA_PRIORITY;
        rta->rta_len  = RTA_LENGTH(4);
        int metric_val = metric;
        memcpy(RTA_DATA(rta), &metric_val, 4);
        request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to add route %s/%d via %s: %s\n",
                      dest_ip_str, mask_len, gateway_ip_str, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("Added route %s/%d via %s metric %d\n",
                dest_ip_str, mask_len, gateway_ip_str, metric);
    return 0;
#endif
}

/**
 * Add IPv6 route command
 * @param func_name Command name with route parameters
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_route_ipv6_add(CMD_ARGS) {
#ifdef _WIN32
    return 0;
#else
    const char *ifname = tun->tun_intf.tun_name;
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    // Parse command: route6 add "ip6" mask "num" via gateway "ip"
    // Extract destination IPv6
    char *dest_ptr = strstr(func_name, "add ");
    if (!dest_ptr) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    dest_ptr += 4;
    char *dest_end = strstr(dest_ptr, " mask ");
    if (!dest_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char dest_ip_str[64];
    strncpy(dest_ip_str, dest_ptr, dest_end - dest_ptr);
    dest_ip_str[dest_end - dest_ptr] = '\0';

    // Extract mask
    char *mask_ptr = dest_end + 6; // " mask "
    char *mask_end = strstr(mask_ptr, " via gateway ");
    if (!mask_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char mask_str[64];
    strncpy(mask_str, mask_ptr, mask_end - mask_ptr);
    mask_str[mask_end - mask_ptr] = '\0';
    int mask_len = atoi(mask_str);

    // Extract gateway IPv6 and optional metric
    char *gateway_ptr = mask_end + 13; // " via gateway "
    int metric = 0;
    char gateway_ip_str[64];

    char *metric_ptr = strstr(gateway_ptr, " metric ");
    if (metric_ptr) {
        size_t gw_len = (size_t)(metric_ptr - gateway_ptr);
        if (gw_len == 0 || gw_len >= sizeof(gateway_ip_str)) {
            PrintError("Invalid gateway in route6 add command\n");
            return -1;
        }
        strncpy(gateway_ip_str, gateway_ptr, gw_len);
        gateway_ip_str[gw_len] = '\0';
        metric = atoi(metric_ptr + 8);
    } else {
        strncpy(gateway_ip_str, gateway_ptr, sizeof(gateway_ip_str) - 1);
        gateway_ip_str[sizeof(gateway_ip_str) - 1] = '\0';
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    // 1. Add routes to each VTEP from remote_endpoint_list
    if (tun->remote_endpoint_list) {
        bh_list_t* cur_remote_endpoint_list = tun->remote_endpoint_list;
        while (cur_remote_endpoint_list) {
            tunnel_endpoint_t* cur_remote_endpoint =
                (tunnel_endpoint_t*)cur_remote_endpoint_list->data;

            // Query existing route to find the gateway for this VTEP
            struct {
                struct nlmsghdr nlh;
                struct rtmsg    rtm;
                char buf[RTA_LENGTH(16)];
            } get_request;

            memset(&get_request, 0, sizeof(get_request));
            get_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
            get_request.nlh.nlmsg_flags = NLM_F_REQUEST;
            get_request.nlh.nlmsg_type  = RTM_GETROUTE;
            get_request.nlh.nlmsg_seq   = 1;
            get_request.nlh.nlmsg_pid   = getpid();

            get_request.rtm.rtm_family   = AF_INET6;
            get_request.rtm.rtm_dst_len  = 128;
            get_request.rtm.rtm_src_len  = 0;
            get_request.rtm.rtm_tos      = 0;
            get_request.rtm.rtm_table    = RT_TABLE_MAIN;
            get_request.rtm.rtm_protocol = RTPROT_UNSPEC;
            get_request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
            get_request.rtm.rtm_type     = RTN_UNSPEC;

            // Add RTA_DST attribute (VTEP IP)
            struct rtattr *rta = (struct rtattr *)((char *)&get_request +
                                  NLMSG_ALIGN(get_request.nlh.nlmsg_len));
            rta->rta_type = RTA_DST;
            rta->rta_len  = RTA_LENGTH(16);
            memcpy(RTA_DATA(rta), &cur_remote_endpoint->remote_endpoint.value, 16);
            get_request.nlh.nlmsg_len = NLMSG_ALIGN(get_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            char response[4096];
            int ret = netlink_send_recv(sock, &get_request.nlh, get_request.nlh.nlmsg_len,
                                        response, sizeof(response));
            if (ret < 0) {
                PrintError("Failed to query route for VTEP\n");
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            // Parse response to find gateway
            struct in6_addr vtep_gateway = {0};
            struct nlmsghdr *resp = (struct nlmsghdr *)response;
            int resp_len = ret;
            for (; NLMSG_OK(resp, (unsigned int)resp_len);
                   resp = NLMSG_NEXT(resp, resp_len))
            {
                if (resp->nlmsg_type != RTM_NEWROUTE)
                    continue;

                struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(resp);
                if (rtm->rtm_family != AF_INET6)
                    continue;

                struct rtattr *attr = RTM_RTA(rtm);
                int attr_len = RTM_PAYLOAD(resp);
                for (; RTA_OK(attr, attr_len); attr = RTA_NEXT(attr, attr_len)) {
                    if (attr->rta_type == RTA_GATEWAY) {
                        memcpy(&vtep_gateway, RTA_DATA(attr), 16);
                    }
                }
            }

            if (memcmp(&vtep_gateway, &((struct in6_addr){0}), 16) == 0) {
                PrintError("No route found for VTEP\n");
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            // Create route: ip6 route add <vtep_ip>/128 via <vtep_gateway>
            struct {
                struct nlmsghdr nlh;
                struct rtmsg    rtm;
                char buf[1024];
            } add_request;

            memset(&add_request, 0, sizeof(add_request));
            add_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
            add_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
            add_request.nlh.nlmsg_type  = RTM_NEWROUTE;
            add_request.nlh.nlmsg_seq   = 1;
            add_request.nlh.nlmsg_pid   = getpid();

            add_request.rtm.rtm_family   = AF_INET6;
            add_request.rtm.rtm_dst_len  = 128;
            add_request.rtm.rtm_src_len  = 0;
            add_request.rtm.rtm_tos      = 0;
            add_request.rtm.rtm_table    = RT_TABLE_MAIN;
            add_request.rtm.rtm_protocol = RTPROT_STATIC;
            add_request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
            add_request.rtm.rtm_type     = RTN_UNICAST;
            add_request.rtm.rtm_flags    = 0;

            rta = (struct rtattr *)((char *)&add_request +
                   NLMSG_ALIGN(add_request.nlh.nlmsg_len));
            rta->rta_type = RTA_DST;
            rta->rta_len  = RTA_LENGTH(16);
            memcpy(RTA_DATA(rta), &cur_remote_endpoint->remote_endpoint.value, 16);
            add_request.nlh.nlmsg_len = NLMSG_ALIGN(add_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            rta = (struct rtattr *)((char *)&add_request +
                   NLMSG_ALIGN(add_request.nlh.nlmsg_len));
            rta->rta_type = RTA_GATEWAY;
            rta->rta_len  = RTA_LENGTH(16);
            memcpy(RTA_DATA(rta), &vtep_gateway, 16);
            add_request.nlh.nlmsg_len = NLMSG_ALIGN(add_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(rta->rta_len);

            char add_response[4096];
            ret = netlink_send_recv(sock, &add_request.nlh, add_request.nlh.nlmsg_len,
                                    add_response, sizeof(add_response));
            if (ret < 0) {
                PrintError("Failed to add route to VTEP\n");
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            struct nlmsghdr *add_resp = (struct nlmsghdr *)add_response;
            if (add_resp->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(add_resp);
                if (err->error) {
                    PrintError("Failed to add route to VTEP: %s\n",
                              strerror(-err->error));
                    cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                    continue;
                }
            }

            PrintInform("Added route to VTEP via gateway\n");

            cur_remote_endpoint_list = cur_remote_endpoint_list->next;
        }
    }

    // 2. Add the main route specified in the command
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char buf[1024];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK;
    request.nlh.nlmsg_type  = RTM_NEWROUTE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.rtm.rtm_family   = AF_INET6;
    request.rtm.rtm_dst_len  = mask_len;
    request.rtm.rtm_src_len  = 0;
    request.rtm.rtm_tos      = 0;
    request.rtm.rtm_table    = RT_TABLE_MAIN;
    request.rtm.rtm_protocol = RTPROT_STATIC;
    request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
    request.rtm.rtm_type     = RTN_UNICAST;
    request.rtm.rtm_flags    = 0;

    // Add RTA_DST
    struct rtattr *rta = (struct rtattr *)((char *)&request +
                          NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(16);

    struct in6_addr dest_addr;
    if (inet_pton(AF_INET6, dest_ip_str, &dest_addr) <= 0) {
        PrintError("Invalid destination IPv6 address: %s\n", dest_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &dest_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_GATEWAY
    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len  = RTA_LENGTH(16);

    struct in6_addr gw_addr;
    if (inet_pton(AF_INET6, gateway_ip_str, &gw_addr) <= 0) {
        PrintError("Invalid gateway IPv6 address: %s\n", gateway_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &gw_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_PRIORITY (metric) if specified
    if (metric > 0) {
        rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
        rta->rta_type = RTA_PRIORITY;
        rta->rta_len  = RTA_LENGTH(4);
        int metric_val = metric;
        memcpy(RTA_DATA(rta), &metric_val, 4);
        request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to add route %s/%d via %s: %s\n",
                      dest_ip_str, mask_len, gateway_ip_str, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("Added route %s/%d via %s metric %d\n",
                dest_ip_str, mask_len, gateway_ip_str, metric);
    return 0;
#endif
}

/**
 * Delete IPv4 route command
 * @param func_name Command name with route parameters
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_route_ipv4_del(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: route del "ip" mask "num" via gateway "ip"
    char *dest_ptr = strstr(func_name, "del ");
    if (!dest_ptr) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    dest_ptr += 4;
    char *dest_end = strstr(dest_ptr, " mask ");
    if (!dest_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char dest_ip_str[64];
    strncpy(dest_ip_str, dest_ptr, dest_end - dest_ptr);
    dest_ip_str[dest_end - dest_ptr] = '\0';

    char *mask_ptr = dest_end + 6; // " mask "
    char *mask_end = strstr(mask_ptr, " via gateway ");
    if (!mask_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char mask_str[64];
    strncpy(mask_str, mask_ptr, mask_end - mask_ptr);
    mask_str[mask_end - mask_ptr] = '\0';
    int mask_len = atoi(mask_str);

    // Extract gateway IP and optional metric
    char *gateway_ptr = mask_end + 13; // " via gateway "
    int metric = 0;
    char gateway_ip_str[64];

    char *metric_ptr = strstr(gateway_ptr, " metric ");
    if (metric_ptr) {
        size_t gw_len = (size_t)(metric_ptr - gateway_ptr);
        if (gw_len == 0 || gw_len >= sizeof(gateway_ip_str)) {
            PrintError("Invalid gateway in route del command\n");
            return -1;
        }
        strncpy(gateway_ip_str, gateway_ptr, gw_len);
        gateway_ip_str[gw_len] = '\0';
        metric = atoi(metric_ptr + 8);
    } else {
        strncpy(gateway_ip_str, gateway_ptr, sizeof(gateway_ip_str) - 1);
        gateway_ip_str[sizeof(gateway_ip_str) - 1] = '\0';
    }

#ifdef _WIN32
    NET_LUID luid;
    if (get_luid_from_tun(tun, &luid) != NO_ERROR) return -1;

    (void)ifname;  /* on Windows routes are keyed by LUID, not by name */
    (void)metric;  /* metric is not part of the route key for deletion */

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);

    row.InterfaceLuid = luid;
    row.DestinationPrefix.Prefix.Ipv4.sin_family = AF_INET;
    row.DestinationPrefix.PrefixLength = (UINT8)mask_len;
    if (inet_pton(AF_INET, dest_ip_str,
                  &row.DestinationPrefix.Prefix.Ipv4.sin_addr) != 1) {
        PrintError("Invalid destination address: %s\n", dest_ip_str);
        return -1;
    }
    row.NextHop.Ipv4.sin_family = AF_INET;
    if (inet_pton(AF_INET, gateway_ip_str,
                  &row.NextHop.Ipv4.sin_addr) != 1) {
        PrintError("Invalid gateway address: %s\n", gateway_ip_str);
        return -1;
    }

    DWORD r = DeleteIpForwardEntry2(&row);
    if (r != NO_ERROR) {
        PrintError("Failed to delete route %s/%d via %s: error %lu\n",
                   dest_ip_str, mask_len, gateway_ip_str, r);
        return -1;
    }

    PrintInform("Deleted route %s/%d via %s\n",
                dest_ip_str, mask_len, gateway_ip_str);

    /* After tearing down the tunnel route, remove the per-VTEP helper routes
     * (reverse order of add: main route first, then the VTEP host routes).
     * Mirrors the Linux netlink logic. */
    if (tun->remote_endpoint_list) {
        bh_list_t *ep_it = tun->remote_endpoint_list;
        while (ep_it) {
            tunnel_endpoint_t *ep = (tunnel_endpoint_t *)ep_it->data;
            if (ep && ep->remote_endpoint.value) {
                win_unpin_vtep_route(&ep->remote_endpoint);
            }
            ep_it = ep_it->next;
        }
    }

    return 0;

#else /* Linux */
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    // 1. Delete the main route specified in the command
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char buf[1024];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nlh.nlmsg_type  = RTM_DELROUTE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.rtm.rtm_family   = AF_INET;
    request.rtm.rtm_dst_len  = mask_len;
    request.rtm.rtm_src_len  = 0;
    request.rtm.rtm_tos      = 0;
    request.rtm.rtm_table    = RT_TABLE_MAIN;
    request.rtm.rtm_protocol = RTPROT_STATIC;
    request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
    request.rtm.rtm_type     = RTN_UNICAST;
    request.rtm.rtm_flags    = 0;

    struct rtattr *rta = (struct rtattr *)((char *)&request +
                          NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(4);

    struct in_addr dest_addr;
    if (inet_pton(AF_INET, dest_ip_str, &dest_addr) <= 0) {
        PrintError("Invalid destination IP address: %s\n", dest_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &dest_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len  = RTA_LENGTH(4);

    struct in_addr gw_addr;
    if (inet_pton(AF_INET, gateway_ip_str, &gw_addr) <= 0) {
        PrintError("Invalid gateway IP address: %s\n", gateway_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &gw_addr.s_addr, 4);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_PRIORITY (metric) if specified
    if (metric > 0) {
        rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
        rta->rta_type = RTA_PRIORITY;
        rta->rta_len  = RTA_LENGTH(4);
        int metric_val = metric;
        memcpy(RTA_DATA(rta), &metric_val, 4);
        request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    if (ret < 0) {
        PrintError("Failed to delete route %s/%d via %s\n", dest_ip_str, mask_len, gateway_ip_str);
        close(sock);
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to delete route %s/%d via %s: %s\n",
                      dest_ip_str, mask_len, gateway_ip_str, strerror(-err->error));
            close(sock);
            return -1;
        }
    }

    PrintInform("Deleted route %s/%d via %s\n", dest_ip_str, mask_len, gateway_ip_str);

    // 2. Delete routes for each VTEP from remote_endpoint_list
    if (tun->remote_endpoint_list) {
        bh_list_t* cur_remote_endpoint_list = tun->remote_endpoint_list;
        while (cur_remote_endpoint_list) {
            tunnel_endpoint_t* cur_remote_endpoint =
                (tunnel_endpoint_t*)cur_remote_endpoint_list->data;

            struct {
                struct nlmsghdr nlh;
                struct rtmsg    rtm;
                char buf[1024];
            } del_request;

            memset(&del_request, 0, sizeof(del_request));
            del_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
            del_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            del_request.nlh.nlmsg_type  = RTM_DELROUTE;
            del_request.nlh.nlmsg_seq   = 1;
            del_request.nlh.nlmsg_pid   = getpid();

            del_request.rtm.rtm_family   = AF_INET;
            del_request.rtm.rtm_dst_len  = 32;
            del_request.rtm.rtm_src_len  = 0;
            del_request.rtm.rtm_tos      = 0;
            del_request.rtm.rtm_table    = RT_TABLE_MAIN;
            del_request.rtm.rtm_protocol = RTPROT_STATIC;
            del_request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
            del_request.rtm.rtm_type     = RTN_UNICAST;
            del_request.rtm.rtm_flags    = 0;

            struct rtattr *del_rta = (struct rtattr *)((char *)&del_request +
                                      NLMSG_ALIGN(del_request.nlh.nlmsg_len));
            del_rta->rta_type = RTA_DST;
            del_rta->rta_len  = RTA_LENGTH(4);
            memcpy(RTA_DATA(del_rta), &cur_remote_endpoint->remote_endpoint.value, 4);
            del_request.nlh.nlmsg_len = NLMSG_ALIGN(del_request.nlh.nlmsg_len) +
                                        RTA_ALIGN(del_rta->rta_len);

            char del_response[4096];
            ret = netlink_send_recv(sock, &del_request.nlh, del_request.nlh.nlmsg_len,
                                    del_response, sizeof(del_response));
            if (ret < 0) {
                PrintError("Failed to delete route for VTEP %u.%u.%u.%u\n",
                          cur_remote_endpoint->remote_endpoint.addr[0],
                          cur_remote_endpoint->remote_endpoint.addr[1],
                          cur_remote_endpoint->remote_endpoint.addr[2],
                          cur_remote_endpoint->remote_endpoint.addr[3]);
                cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                continue;
            }

            struct nlmsghdr *del_resp = (struct nlmsghdr *)del_response;
            if (del_resp->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(del_resp);
                if (err->error) {
                    PrintError("Failed to delete route for VTEP %u.%u.%u.%u: %s\n",
                              cur_remote_endpoint->remote_endpoint.addr[0],
                              cur_remote_endpoint->remote_endpoint.addr[1],
                              cur_remote_endpoint->remote_endpoint.addr[2],
                              cur_remote_endpoint->remote_endpoint.addr[3],
                              strerror(-err->error));
                    cur_remote_endpoint_list = cur_remote_endpoint_list->next;
                    continue;
                }
            }

            PrintInform("Deleted route for VTEP %u.%u.%u.%u\n",
                        cur_remote_endpoint->remote_endpoint.addr[0],
                        cur_remote_endpoint->remote_endpoint.addr[1],
                        cur_remote_endpoint->remote_endpoint.addr[2],
                        cur_remote_endpoint->remote_endpoint.addr[3]);

            cur_remote_endpoint_list = cur_remote_endpoint_list->next;
        }
    }

    close(sock);
    return 0;
#endif
}

/**
 * Delete IPv6 route command
 * @param func_name Command name with route parameters
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_route_ipv6_del(CMD_ARGS) {
#ifdef _WIN32
    return 0;
#else
    const char *ifname = tun->tun_intf.tun_name;
    int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        PrintError("Interface %s not found\n", ifname);
        return -1;
    }

    // Parse command: route6 del "ip6" mask "num" via gateway "ip"
    char *dest_ptr = strstr(func_name, "del ");
    if (!dest_ptr) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    dest_ptr += 4;
    char *dest_end = strstr(dest_ptr, " mask ");
    if (!dest_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char dest_ip_str[64];
    strncpy(dest_ip_str, dest_ptr, dest_end - dest_ptr);
    dest_ip_str[dest_end - dest_ptr] = '\0';

    char *mask_ptr = dest_end + 6; // " mask "
    char *mask_end = strstr(mask_ptr, " via gateway ");
    if (!mask_end) {
        PrintError("Invalid route command format\n");
        return -1;
    }
    char mask_str[64];
    strncpy(mask_str, mask_ptr, mask_end - mask_ptr);
    mask_str[mask_end - mask_ptr] = '\0';
    int mask_len = atoi(mask_str);

    // Extract gateway IPv6 and optional metric
    char *gateway_ptr = mask_end + 13; // " via gateway "
    int metric = 0;
    char gateway_ip_str[64];

    char *metric_ptr = strstr(gateway_ptr, " metric ");
    if (metric_ptr) {
        size_t gw_len = (size_t)(metric_ptr - gateway_ptr);
        if (gw_len == 0 || gw_len >= sizeof(gateway_ip_str)) {
            PrintError("Invalid gateway in route6 del command\n");
            return -1;
        }
        strncpy(gateway_ip_str, gateway_ptr, gw_len);
        gateway_ip_str[gw_len] = '\0';
        metric = atoi(metric_ptr + 8);
    } else {
        strncpy(gateway_ip_str, gateway_ptr, sizeof(gateway_ip_str) - 1);
        gateway_ip_str[sizeof(gateway_ip_str) - 1] = '\0';
    }

    (void)metric; /* metric not used for route deletion on IPv6 */

    int sock = create_netlink_socket();
    if (sock < 0) {
        return -1;
    }

    // 1. Delete the main route specified in the command
    struct {
        struct nlmsghdr nlh;
        struct rtmsg    rtm;
        char buf[1024];
    } request;

    memset(&request, 0, sizeof(request));
    request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nlh.nlmsg_type  = RTM_DELROUTE;
    request.nlh.nlmsg_seq   = 1;
    request.nlh.nlmsg_pid   = getpid();

    request.rtm.rtm_family   = AF_INET6;
    request.rtm.rtm_dst_len  = mask_len;
    request.rtm.rtm_src_len  = 0;
    request.rtm.rtm_tos      = 0;
    request.rtm.rtm_table    = RT_TABLE_MAIN;
    request.rtm.rtm_protocol = RTPROT_STATIC;
    request.rtm.rtm_scope    = RT_SCOPE_UNIVERSE;
    request.rtm.rtm_type     = RTN_UNICAST;
    request.rtm.rtm_flags    = 0;

    // Add RTA_DST
    struct rtattr *rta = (struct rtattr *)((char *)&request +
                NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len  = RTA_LENGTH(16);

    struct in6_addr dest_addr;
    if (inet_pton(AF_INET6, dest_ip_str, &dest_addr) < 0) {
        PrintError("Invalid destination IPv6 address: %s\n", dest_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &dest_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_GATEWAY
    rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len  = RTA_LENGTH(16);

    struct in6_addr gw_addr;
    if (inet_pton(AF_INET6, gateway_ip_str, &gw_addr) < 0) {
        PrintError("Invalid gateway IPv6 address: %s\n", gateway_ip_str);
        close(sock);
        return -1;
    }
    memcpy(RTA_DATA(rta), &gw_addr, 16);
    request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    // Add RTA_PRIORITY (metric) if specified
    if (metric > 0) {
        rta = (struct rtattr *)((char *)&request + NLMSG_ALIGN(request.nlh.nlmsg_len));
        rta->rta_type = RTA_PRIORITY;
        rta->rta_len  = RTA_LENGTH(4);
        int metric_val = metric;
        memcpy(RTA_DATA(rta), &metric_val, 4);
        request.nlh.nlmsg_len = NLMSG_ALIGN(request.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
    }

    char response[4096];
    int ret = netlink_send_recv(sock, &request.nlh, request.nlh.nlmsg_len, response, sizeof(response));
    close(sock);

    if (ret < 0) {
        return -1;
    }

    struct nlmsghdr *resp = (struct nlmsghdr *)response;
    if (resp->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
        if (err->error) {
            PrintError("Failed to delete route %s/%d via %s: %s\n",
                                            dest_ip_str, mask_len, gateway_ip_str, strerror(-err->error));
            return -1;
        }
    }

    PrintInform("Deleted route %s/%d via %s\n", dest_ip_str, mask_len, gateway_ip_str);
    return 0;
#endif
}

/**
 * Add IPv4 DNS server command
 * @param func_name Command name with DNS server IP
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_dns_server_ipv4_add(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: dns add "ip"
    char *ip_ptr = strstr(func_name, "add ");
    if (!ip_ptr) {
        PrintError("Invalid DNS command format\n");
        return -1;
    }
    ip_ptr += 4;

    char *ip_end = ip_ptr + strlen(ip_ptr);
    char dns_ip_str[64];
    size_t dns_ip_len = (size_t)(ip_end - ip_ptr);
    if (dns_ip_len == 0 || dns_ip_len >= sizeof(dns_ip_str)) {
        PrintError("Invalid DNS IP length\n");
        return -1;
    }
    strncpy(dns_ip_str, ip_ptr, dns_ip_len);
    dns_ip_str[dns_ip_len] = '\0';

    struct in_addr dns_addr;
    if (inet_pton(AF_INET, dns_ip_str, &dns_addr) <= 0) {
        PrintError("Invalid DNS server IP address: %s\n", dns_ip_str);
        return -1;
    }

#ifdef _WIN32
    /* netsh: most compatible DNS method on Windows (Vista+, no extra libs) */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 add dnsserver name=\"%s\" address=%s index=1 validate=no",
             ifname, dns_ip_str);
    if (system(cmd) != 0) {
        PrintError("Failed to add DNS server %s on interface %s via netsh\n", dns_ip_str, ifname);
        return -1;
    }
    PrintInform("Added DNS server %s on interface %s\n", dns_ip_str, ifname);
    return 0;

#else /* Linux */
    /* Try resolvconf first (checks binary existence before using it) */
    if (system("which resolvconf > /dev/null 2>&1") == 0) {
        char add_dns_cmd[512];
        snprintf(add_dns_cmd, sizeof(add_dns_cmd),
                 "echo 'nameserver %s' | resolvconf -a %s -f && resolvconf -u",
                 dns_ip_str, ifname);
        if (system(add_dns_cmd) == 0) {
            PrintInform("Added DNS server %s to interface %s via resolvconf\n", dns_ip_str, ifname);
            return 0;
        }
    }

    /* Fallback: append to /etc/resolv.conf */
    FILE *resolv_file = fopen("/etc/resolv.conf", "a");
    if (resolv_file) {
        fprintf(resolv_file, "nameserver %s\n", dns_ip_str);
        fclose(resolv_file);
        PrintInform("Added DNS server %s to /etc/resolv.conf\n", dns_ip_str);
        return 0;
    }

    PrintError("Failed to add DNS server %s\n", dns_ip_str);
    return -1;
#endif
}

/**
 * Add IPv6 DNS server command
 * @param func_name Command name
 * @param tun Tunnel entity for context
 * @return 0 on success, non-zero on error
 */
int cmd_dns_server_ipv6_add(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: dns6 add "ip6"
    char *ip_ptr = strstr(func_name, "add ");
    if (!ip_ptr) {
        PrintError("Invalid DNS command format\n");
        return -1;
    }
    ip_ptr += 4;

    char *ip_end = ip_ptr + strlen(ip_ptr);
    char dns_ip_str[64];
    size_t dns_ip_len = (size_t)(ip_end - ip_ptr);
    if (dns_ip_len == 0 || dns_ip_len >= sizeof(dns_ip_str)) {
        PrintError("Invalid DNS IP length\n");
        return -1;
    }
    strncpy(dns_ip_str, ip_ptr, dns_ip_len);
    dns_ip_str[dns_ip_len] = '\0';

    struct in6_addr dns_addr;
    if (inet_pton(AF_INET6, dns_ip_str, &dns_addr) <= 0) {
        PrintError("Invalid DNS server IPv6 address: %s\n", dns_ip_str);
        return -1;
    }

#ifdef _WIN32
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv6 add dnsserver name=\"%s\" address=%s index=1 validate=no",
             ifname, dns_ip_str);
    if (system(cmd) != 0) {
        PrintError("Failed to add DNS6 server %s on interface %s via netsh\n", dns_ip_str, ifname);
        return -1;
    }
    PrintInform("Added DNS6 server %s on interface %s\n", dns_ip_str, ifname);
    return 0;

#else /* Linux */
    if (system("which resolvconf > /dev/null 2>&1") == 0) {
        char add_dns_cmd[512];
        snprintf(add_dns_cmd, sizeof(add_dns_cmd),
                 "echo 'nameserver %s' | resolvconf -a %s -f && resolvconf -u",
                 dns_ip_str, ifname);
        if (system(add_dns_cmd) == 0) {
            PrintInform("Added DNS6 server %s to interface %s via resolvconf\n", dns_ip_str, ifname);
            return 0;
        }
    }

    FILE *resolv_file = fopen("/etc/resolv.conf", "a");
    if (resolv_file) {
        fprintf(resolv_file, "nameserver %s\n", dns_ip_str);
        fclose(resolv_file);
        PrintInform("Added DNS6 server %s to /etc/resolv.conf\n", dns_ip_str);
        return 0;
    }

    PrintError("Failed to add DNS6 server %s\n", dns_ip_str);
    return -1;
#endif
}

int cmd_dns_server_ipv4_del(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: dns del "ip"
    char *ip_ptr = strstr(func_name, "del ");
    if (!ip_ptr) {
        PrintError("Invalid DNS command format\n");
        return -1;
    }
    ip_ptr += 4;

    char *ip_end = ip_ptr + strlen(ip_ptr);
    char dns_ip_str[64];
    size_t dns_ip_len = (size_t)(ip_end - ip_ptr);
    if (dns_ip_len == 0 || dns_ip_len >= sizeof(dns_ip_str)) {
        PrintError("Invalid DNS IP length\n");
        return -1;
    }
    strncpy(dns_ip_str, ip_ptr, dns_ip_len);
    dns_ip_str[dns_ip_len] = '\0';

    struct in_addr dns_addr;
    if (inet_pton(AF_INET, dns_ip_str, &dns_addr) <= 0) {
        PrintError("Invalid DNS server IP address: %s\n", dns_ip_str);
        return -1;
    }

#ifdef _WIN32
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv4 delete dnsserver name=\"%s\" address=%s",
             ifname, dns_ip_str);
    if (system(cmd) != 0) {
        PrintError("Failed to remove DNS server %s on interface %s via netsh\n", dns_ip_str, ifname);
        return -1;
    }
    PrintInform("Removed DNS server %s on interface %s\n", dns_ip_str, ifname);
    return 0;

#else /* Linux */
    /* Try resolvconf first */
    if (system("which resolvconf > /dev/null 2>&1") == 0) {
        char cmd2[256];
        snprintf(cmd2, sizeof(cmd2), "resolvconf -d %s -f && resolvconf -u", ifname);
        if (system(cmd2) == 0) {
            PrintInform("Removed DNS server %s from interface %s via resolvconf\n", dns_ip_str, ifname);
            return 0;
        }
    }

    /* Fallback: rewrite /etc/resolv.conf filtering out the entry */
    FILE *resolv_file = fopen("/etc/resolv.conf", "r");
    if (!resolv_file) {
        PrintError("Failed to open /etc/resolv.conf for reading\n");
        return -1;
    }

    FILE *temp_file = fopen("/tmp/resolv.conf.tmp", "w");
    if (!temp_file) {
        fclose(resolv_file);
        PrintError("Failed to create temp file for resolv.conf\n");
        return -1;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), resolv_file)) {
        if (strstr(line, "nameserver") && strstr(line, dns_ip_str)) {
            found = 1;
            continue; /* skip this line */
        }
        fputs(line, temp_file);
    }
    fclose(resolv_file);
    fclose(temp_file);

    if (found) {
        rename("/tmp/resolv.conf.tmp", "/etc/resolv.conf");
        PrintInform("Removed DNS server %s from /etc/resolv.conf\n", dns_ip_str);
        return 0;
    }

    /* Entry not found — clean up temp file */
    remove("/tmp/resolv.conf.tmp");
    PrintError("DNS server %s not found in /etc/resolv.conf\n", dns_ip_str);
    return -1;
#endif
}

int cmd_dns_server_ipv6_del(CMD_ARGS) {
    const char *ifname = tun->tun_intf.tun_name;

    // Parse command: dns6 del "ip6"
    char *ip_ptr = strstr(func_name, "del ");
    if (!ip_ptr) {
        PrintError("Invalid DNS command format\n");
        return -1;
    }
    ip_ptr += 4;

    char *ip_end = ip_ptr + strlen(ip_ptr);
    char dns_ip_str[64];
    size_t dns_ip_len = (size_t)(ip_end - ip_ptr);
    if (dns_ip_len == 0 || dns_ip_len >= sizeof(dns_ip_str)) {
        PrintError("Invalid DNS IP length\n");
        return -1;
    }
    strncpy(dns_ip_str, ip_ptr, dns_ip_len);
    dns_ip_str[dns_ip_len] = '\0';

    struct in6_addr dns_addr;
    if (inet_pton(AF_INET6, dns_ip_str, &dns_addr) <= 0) {
        PrintError("Invalid DNS server IPv6 address: %s\n", dns_ip_str);
        return -1;
    }

#ifdef _WIN32
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
             "netsh interface ipv6 delete dnsserver name=\"%s\" address=%s",
             ifname, dns_ip_str);
    if (system(cmd) != 0) {
        PrintError("Failed to remove DNS6 server %s on interface %s via netsh\n", dns_ip_str, ifname);
        return -1;
    }
    PrintInform("Removed DNS6 server %s on interface %s\n", dns_ip_str, ifname);
    return 0;

#else /* Linux */
    if (system("which resolvconf > /dev/null 2>&1") == 0) {
        char cmd2[256];
        snprintf(cmd2, sizeof(cmd2), "resolvconf -d %s -f && resolvconf -u", ifname);
        if (system(cmd2) == 0) {
            PrintInform("Removed DNS6 server %s from interface %s via resolvconf\n", dns_ip_str, ifname);
            return 0;
        }
    }

    FILE *resolv_file = fopen("/etc/resolv.conf", "r");
    if (!resolv_file) {
        PrintError("Failed to open /etc/resolv.conf for reading\n");
        return -1;
    }

    FILE *temp_file = fopen("/tmp/resolv.conf.tmp", "w");
    if (!temp_file) {
        fclose(resolv_file);
        PrintError("Failed to create temp file for resolv.conf\n");
        return -1;
    }

    char line[256];
    int found = 0;
    while (fgets(line, sizeof(line), resolv_file)) {
        if (strstr(line, "nameserver") && strstr(line, dns_ip_str)) {
            found = 1;
            continue;
        }
        fputs(line, temp_file);
    }
    fclose(resolv_file);
    fclose(temp_file);

    if (found) {
        rename("/tmp/resolv.conf.tmp", "/etc/resolv.conf");
        PrintInform("Removed DNS6 server %s from /etc/resolv.conf\n", dns_ip_str);
        return 0;
    }

    remove("/tmp/resolv.conf.tmp");
    PrintError("DNS6 server %s not found in /etc/resolv.conf\n", dns_ip_str);
    return -1;
#endif
}

#ifdef _WIN32
/*
 * Get NET_LUID directly from the GUID stored in tun_intf.guidAdapter.
 * This avoids if_nametoindex and ConvertInterfaceIndexToLuid which may be
 * unavailable in some MinGW-w64 toolchain versions.
 */
static DWORD get_luid_from_tun(const tunnel_entity_t *tun, NET_LUID *luid) {
    /* TUN interfaces are backed by a wintun adapter whose GUID is NOT stored
     * in tun_intf.guidAdapter, so ConvertInterfaceGuidToLuid() can't be used.
     * The LUID must be obtained from the wintun adapter handle directly. */
    if (tun->tun_intf.wintun_ctx) {
        DWORD r = wintun_get_adapter_luid(
            (wintun_ctx_t *)tun->tun_intf.wintun_ctx, luid);
        if (r != ERROR_SUCCESS) {
            PrintError("wintun_get_adapter_luid failed: error %lu\n", r);
        }
        return r;
    }

    /* TAP interfaces (tap0901) store a valid adapter GUID in tun_intf. */
    DWORD r = ConvertInterfaceGuidToLuid(&tun->tun_intf.guidAdapter, luid);
    if (r != NO_ERROR) {
        PrintError("ConvertInterfaceGuidToLuid failed: error %lu\n", r);
    }
    return r;
}

/**
 * Pin a /32 host route to a VTEP through the CURRENT physical gateway.
 *
 * Before a tunnel route is installed (which may capture the path to the VTEP
 * itself), we resolve how the VTEP is reachable right now via GetBestRoute2()
 * and install an explicit host route over the same physical interface/gateway.
 * This keeps the encapsulated underlay traffic flowing and avoids a routing
 * loop / black hole. Equivalent to the Linux RTM_GETROUTE + add <vtep>/32 path.
 *
 * @param vtep VTEP address (network byte order in vtep->value)
 * @return 0 on success or when no helper is needed (on-link), -1 on error
 */
static int win_pin_vtep_route(const ipv4_addr *vtep) {
    SOCKADDR_INET dst;
    memset(&dst, 0, sizeof(dst));
    dst.Ipv4.sin_family      = AF_INET;
    dst.Ipv4.sin_addr.s_addr = vtep->value;

    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET best_src;
    DWORD r = GetBestRoute2(NULL, 0, NULL, &dst, 0, &best, &best_src);
    if (r != NO_ERROR) {
        PrintError("No route found for VTEP %u.%u.%u.%u (GetBestRoute2 error %lu)\n",
                   vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3], r);
        return -1;
    }

    /* Unspecified next hop => VTEP is on-link; no helper route required.
     * Matches the Linux behaviour of skipping when there is no RTA_GATEWAY. */
    if (best.NextHop.si_family != AF_INET ||
        best.NextHop.Ipv4.sin_addr.s_addr == 0) {
        PrintInform("VTEP %u.%u.%u.%u is on-link, no helper route needed\n",
                    vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3]);
        return 0;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid     = best.InterfaceLuid;   /* physical interface to VTEP */
    row.ValidLifetime     = 0xFFFFFFFF;
    row.PreferredLifetime = 0xFFFFFFFF;
    row.Metric            = best.Metric;
    row.Protocol          = MIB_IPPROTO_NETMGMT;
    row.Origin            = NlroManual;
    row.DestinationPrefix.Prefix.Ipv4.sin_family   = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = vtep->value;
    row.DestinationPrefix.PrefixLength             = 32;
    row.NextHop.Ipv4.sin_family       = AF_INET;
    row.NextHop.Ipv4.sin_addr.s_addr  = best.NextHop.Ipv4.sin_addr.s_addr;

    DWORD cr = CreateIpForwardEntry2(&row);
    if (cr == ERROR_OBJECT_ALREADY_EXISTS) {
        cr = SetIpForwardEntry2(&row);
    }
    if (cr != NO_ERROR) {
        PrintError("Failed to pin route to VTEP %u.%u.%u.%u: error %lu\n",
                   vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3], cr);
        return -1;
    }

    {
        const uint8_t *gw = (const uint8_t *)&best.NextHop.Ipv4.sin_addr.s_addr;
        PrintInform("Pinned route to VTEP %u.%u.%u.%u via %u.%u.%u.%u\n",
                    vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3],
                    gw[0], gw[1], gw[2], gw[3]);
    }
    return 0;
}

/**
 * Remove the /32 host route previously installed by win_pin_vtep_route().
 *
 * The pinned /32 is the most specific route to the VTEP, so GetBestRoute2()
 * resolves it back (giving us the exact interface + next hop needed to delete
 * the row). On-link / non-/32 results are left untouched to avoid removing a
 * system route we never created.
 *
 * @param vtep VTEP address (network byte order in vtep->value)
 * @return 0 on success or nothing-to-do, -1 on error
 */
static int win_unpin_vtep_route(const ipv4_addr *vtep) {
    SOCKADDR_INET dst;
    memset(&dst, 0, sizeof(dst));
    dst.Ipv4.sin_family      = AF_INET;
    dst.Ipv4.sin_addr.s_addr = vtep->value;

    MIB_IPFORWARD_ROW2 best;
    SOCKADDR_INET best_src;
    DWORD r = GetBestRoute2(NULL, 0, NULL, &dst, 0, &best, &best_src);
    if (r != NO_ERROR) {
        /* Nothing reachable / already gone — nothing to clean up. */
        return 0;
    }

    /* Only delete if this is exactly our pinned host route (a /32 via a real
     * gateway), never an on-link or aggregated system route. */
    if (best.DestinationPrefix.PrefixLength != 32 ||
        best.NextHop.si_family != AF_INET ||
        best.NextHop.Ipv4.sin_addr.s_addr == 0) {
        return 0;
    }

    MIB_IPFORWARD_ROW2 row;
    InitializeIpForwardEntry(&row);
    row.InterfaceLuid = best.InterfaceLuid;
    row.DestinationPrefix.Prefix.Ipv4.sin_family   = AF_INET;
    row.DestinationPrefix.Prefix.Ipv4.sin_addr.s_addr = vtep->value;
    row.DestinationPrefix.PrefixLength             = 32;
    row.NextHop.Ipv4.sin_family       = AF_INET;
    row.NextHop.Ipv4.sin_addr.s_addr  = best.NextHop.Ipv4.sin_addr.s_addr;

    DWORD dr = DeleteIpForwardEntry2(&row);
    if (dr != NO_ERROR && dr != ERROR_NOT_FOUND) {
        PrintError("Failed to delete pinned route to VTEP %u.%u.%u.%u: error %lu\n",
                   vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3], dr);
        return -1;
    }

    PrintInform("Removed pinned route to VTEP %u.%u.%u.%u\n",
                vtep->addr[0], vtep->addr[1], vtep->addr[2], vtep->addr[3]);
    return 0;
}

#else
/**
 * Create a netlink socket
 * @return File descriptor on success, -1 on error
 */
static int create_netlink_socket() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        PrintError("Failed to create netlink socket: %m\n");
        return -1;
    }

    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_groups = 0
    };

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PrintError("Failed to bind netlink socket: %m\n");
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * Send netlink message and receive response
 * @param sock Netlink socket
 * @param msg Netlink message to send
 * @param msg_len Length of message
 * @param response Buffer for response
 * @param response_len Maximum response length
 * @return Actual response length on success, -1 on error
 */
static int netlink_send_recv(int sock, struct nlmsghdr *msg, size_t msg_len,
                            char *response, size_t response_len) {
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK
    };

    if (sendto(sock, msg, msg_len, 0, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        PrintError("Failed to send netlink message: %m\n");
        return -1;
    }

    struct msghdr hdr = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = (struct iovec[]){{
            .iov_base = response,
            .iov_len = response_len
        }},
        .msg_iovlen = 1,
        .msg_control = NULL,
        .msg_controllen = 0,
        .msg_flags = 0
    };

    ssize_t ret = recvmsg(sock, &hdr, 0);
    if (ret < 0) {
        PrintError("Failed to receive netlink response: %m\n");
        return -1;
    }

    return (int)ret;
}

#endif
