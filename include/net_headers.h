#ifdef _WIN32

#ifndef NET_HEADERS_H
#define NET_HEADERS_H

/*
 * net_headers.h — replacement for Linux headers:
 *   netinet/ether.h   — Ethernet
 *   netinet/ip.h      — IPv4
 *   netinet/ip6.h     — IPv6
 *   netinet/udp.h     — UDP
 *   netinet/ip_icmp.h — ICMP / ICMPv6
 *
 * Compatible with Windows + MinGW (gcc).
 * Include AFTER <winsock2.h> or <windows.h>.
 */

#include <stdint.h>
#include <winsock2.h>   /* htons, htonl, ntohs, ntohl */
#include <ws2tcpip.h>   /* struct in6_addr             */

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Packing
 * All network structures must have no padding — fields are laid out
 * contiguously exactly as they appear in a real packet.
 * ====================================================================== */
#define NET_PACKED  __attribute__((packed))

/* =========================================================================
 * Common constants — EtherType
 * ====================================================================== */
#define ETHERTYPE_IP    0x0800  /* IPv4            */
#define ETHERTYPE_ARP   0x0806  /* ARP             */
#define ETHERTYPE_IPV6  0x86DD  /* IPv6            */
#define ETHERTYPE_VLAN  0x8100  /* 802.1Q VLAN tag */

/* =========================================================================
 * Common constants — IP protocols (protocol field in IPv4, next header in IPv6)
 * ====================================================================== */
#define IPPROTO_ICMP    1
#define IPPROTO_TCP     6
#define IPPROTO_UDP     17
#define IPPROTO_IPV6    41   /* IPv6-in-IPv4 (tunnel) */
#define IPPROTO_ICMPV6  58

/* =========================================================================
 * ETH — Ethernet II (netinet/ether.h)
 * ====================================================================== */
#define ETH_ALEN      6     /* MAC address length in bytes          */
#define ETH_HLEN      14    /* Ethernet header length               */
#define ETH_ZLEN      60    /* minimum frame size                   */
#define ETH_FRAME_LEN 1514  /* maximum frame size (without FCS)     */

typedef struct {
    uint8_t  ether_dhost[ETH_ALEN]; /* destination MAC address          */
    uint8_t  ether_shost[ETH_ALEN]; /* source MAC address               */
    uint16_t ether_type;            /* EtherType (network byte order)   */
} NET_PACKED ether_hdr_t;

/* 802.1Q VLAN tag — inserted between MAC addresses and EtherType */
typedef struct {
    uint8_t  ether_dhost[ETH_ALEN];
    uint8_t  ether_shost[ETH_ALEN];
    uint16_t tpid;       /* 0x8100                              */
    uint16_t tci;        /* PCP (3 bits) + DEI (1) + VID (12)  */
    uint16_t ether_type; /* actual EtherType                    */
} NET_PACKED ether_vlan_hdr_t;

/* Macros for VLAN TCI field */
#define VLAN_PCP(tci)  (((tci) >> 13) & 0x07)  /* Priority Code Point */
#define VLAN_DEI(tci)  (((tci) >> 12) & 0x01)  /* Drop Eligible       */
#define VLAN_VID(tci)  ((tci) & 0x0FFF)         /* VLAN ID             */

/* =========================================================================
 * IPv4 (netinet/ip.h)
 * ====================================================================== */
#define IP_HLEN     20   /* minimum header size (without options) */

/* Flags in the frag_off field */
#define IP_RF       0x8000  /* reserved                 */
#define IP_DF       0x4000  /* Don't Fragment           */
#define IP_MF       0x2000  /* More Fragments           */
#define IP_OFFMASK  0x1FFF  /* fragment offset mask     */

typedef struct {
    uint8_t  ip_vhl;       /* version (high 4 bits) + IHL (low 4 bits)         */
    uint8_t  ip_tos;       /* Type of Service / DSCP+ECN                        */
    uint16_t ip_len;       /* total packet length (header + data)               */
    uint16_t ip_id;        /* fragment identification                            */
    uint16_t ip_off;       /* flags (3 bits) + fragment offset (13 bits)        */
    uint8_t  ip_ttl;       /* Time To Live                                       */
    uint8_t  ip_p;         /* protocol (IPPROTO_*)                               */
    uint16_t ip_sum;       /* header checksum                                    */
    uint32_t ip_src;       /* source IP address      (network byte order)        */
    uint32_t ip_dst;       /* destination IP address (network byte order)        */
    /* IPv4 options — variable length, not included in the struct */
} NET_PACKED ip_hdr_t;

/* Macros for the ip_vhl field */
#define IP_VERSION(ip)   (((ip)->ip_vhl >> 4) & 0x0F)
#define IP_IHL(ip)       (((ip)->ip_vhl & 0x0F) << 2)  /* header length in bytes */
#define IP_VHL(ver, ihl) (((ver) << 4) | ((ihl) >> 2)) /* construct ip_vhl       */

/* Payload starts immediately after the header */
#define IP_DATA(ip)  ((uint8_t *)(ip) + IP_IHL(ip))

/* =========================================================================
 * IPv6 (netinet/ip6.h)
 * ====================================================================== */
#define IPV6_HLEN   40   /* fixed IPv6 header size */

typedef struct {
    uint32_t ip6_flow;       /* version (4) + traffic class (8) + flow label (20) */
    uint16_t ip6_plen;       /* payload length (excluding header)                  */
    uint8_t  ip6_nxt;        /* next header (IPPROTO_*)                            */
    uint8_t  ip6_hlim;       /* Hop Limit (equivalent of TTL)                      */
    struct in6_addr ip6_src; /* source address      (16 bytes)                     */
    struct in6_addr ip6_dst; /* destination address (16 bytes)                     */
} NET_PACKED ip6_hdr_t;

/* Macros for the ip6_flow field (values are in host byte order after ntohl) */
#define IP6_VERSION(ip6)      ((ntohl((ip6)->ip6_flow) >> 28) & 0x0F)
#define IP6_TCLASS(ip6)       ((ntohl((ip6)->ip6_flow) >> 20) & 0xFF)
#define IP6_FLOWLABEL(ip6)    (ntohl((ip6)->ip6_flow) & 0x000FFFFF)

/* Construct ip6_flow from components */
#define IP6_FLOW_MAKE(ver, tc, fl) \
    htonl(((uint32_t)(ver) << 28) | ((uint32_t)(tc) << 20) | ((fl) & 0x000FFFFF))

/* =========================================================================
 * UDP (netinet/udp.h)
 * ====================================================================== */
#define UDP_HLEN    8   /* fixed UDP header size */

typedef struct {
    uint16_t uh_sport; /* source port                              */
    uint16_t uh_dport; /* destination port                         */
    uint16_t uh_ulen;  /* length (header + data)                   */
    uint16_t uh_sum;   /* checksum (0 = not computed)              */
} NET_PACKED udp_hdr_t;

#define UDP_DATA(udp)  ((uint8_t *)(udp) + UDP_HLEN)

/* =========================================================================
 * ICMP (netinet/ip_icmp.h)
 * ====================================================================== */

/* ICMP message types */
#define ICMP_ECHOREPLY       0   /* Echo Reply                  */
#define ICMP_DEST_UNREACH    3   /* Destination Unreachable     */
#define ICMP_SOURCE_QUENCH   4   /* Source Quench (deprecated)  */
#define ICMP_REDIRECT        5   /* Redirect                    */
#define ICMP_ECHO            8   /* Echo Request                */
#define ICMP_TIME_EXCEEDED   11  /* Time Exceeded               */
#define ICMP_PARAMETERPROB   12  /* Parameter Problem           */
#define ICMP_TIMESTAMP       13  /* Timestamp Request           */
#define ICMP_TIMESTAMPREPLY  14  /* Timestamp Reply             */
#define ICMP_INFO_REQUEST    15  /* Information Request         */
#define ICMP_INFO_REPLY      16  /* Information Reply           */
#define ICMP_ADDRESS         17  /* Address Mask Request        */
#define ICMP_ADDRESSREPLY    18  /* Address Mask Reply          */

/* Codes for ICMP_DEST_UNREACH */
#define ICMP_NET_UNREACH     0   /* Network Unreachable         */
#define ICMP_HOST_UNREACH    1   /* Host Unreachable            */
#define ICMP_PROT_UNREACH    2   /* Protocol Unreachable        */
#define ICMP_PORT_UNREACH    3   /* Port Unreachable            */
#define ICMP_FRAG_NEEDED     4   /* Fragmentation Needed        */
#define ICMP_SR_FAILED       5   /* Source Route Failed         */

/* Codes for ICMP_REDIRECT */
#define ICMP_REDIR_NET       0   /* Redirect for Network        */
#define ICMP_REDIR_HOST      1   /* Redirect for Host           */
#define ICMP_REDIR_NETTOS    2   /* Redirect for TOS & Network  */
#define ICMP_REDIR_HOSTTOS   3   /* Redirect for TOS & Host     */

/* Codes for ICMP_TIME_EXCEEDED */
#define ICMP_EXC_TTL         0   /* TTL exceeded in transit     */
#define ICMP_EXC_FRAGTIME    1   /* Fragment reassembly timeout */

typedef struct {
    uint8_t  icmp_type;  /* message type (ICMP_*)             */
    uint8_t  icmp_code;  /* code (further specifies the type) */
    uint16_t icmp_cksum; /* checksum                          */

    union {
        /* Echo Request / Echo Reply (type 8 / type 0) */
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;

        /* Destination Unreachable / Time Exceeded (type 3 / type 11) */
        struct {
            uint16_t unused;
            uint16_t mtu;    /* Next-Hop MTU (for ICMP_FRAG_NEEDED) */
        } frag;

        /* Redirect (type 5) */
        uint32_t gateway;
        uint32_t raw;        /* access to the first 4 bytes as uint32_t */
    } icmp_hun;

    /* Data — for DEST_UNREACH/TIME_EXCEEDED contains the original IP header */
} NET_PACKED icmp_hdr_t;

/* Convenience aliases for echo fields */
// #define icmp_id   icmp_hun.echo.id
// #define icmp_seq  icmp_hun.echo.seq


// TODO Original Linux ICMP struct definition
struct icmp_ra_addr {
    uint32_t ira_addr;
    uint32_t ira_preference;
} NET_PACKED;

struct icmp {
    u_char  icmp_type;      /* type of message, see below */
    u_char  icmp_code;      /* type sub code */
    u_short icmp_cksum;     /* ones complement cksum of struct */
    union {
        u_char ih_pptr;         /* ICMP_PARAMPROB */
        struct in_addr ih_gwaddr;   /* ICMP_REDIRECT */
        struct ih_idseq {
            uint16_t    icd_id; /* network format */
            uint16_t    icd_seq; /* network format */
        } ih_idseq;
        int ih_void;

        /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
        struct ih_pmtu {
            uint16_t ipm_void;  /* network format */
            uint16_t ipm_nextmtu;   /* network format */
        } ih_pmtu;

        struct ih_rtradv {
            u_char irt_num_addrs;
            u_char irt_wpa;
            uint16_t irt_lifetime;
        } ih_rtradv;
    } icmp_hun;
#define icmp_pptr   icmp_hun.ih_pptr
#define icmp_gwaddr icmp_hun.ih_gwaddr
#define icmp_id     icmp_hun.ih_idseq.icd_id
#define icmp_seq    icmp_hun.ih_idseq.icd_seq
#define icmp_void   icmp_hun.ih_void
#define icmp_pmvoid icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa    icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
    union {
        struct id_ts {          /* ICMP Timestamp */
            /*
             * The next 3 fields are in network format,
             * milliseconds since 00:00 GMT
             */
            uint32_t its_otime; /* Originate */
            uint32_t its_rtime; /* Receive */
            uint32_t its_ttime; /* Transmit */
        } id_ts;
        struct id_ip  {
            ip_hdr_t idi_ip;
            /* options and then 64 bits of data */
        } id_ip;
        struct icmp_ra_addr id_radv;
        uint32_t id_mask;
        char    id_data[1];
    } icmp_dun;
#define icmp_otime  icmp_dun.id_ts.its_otime
#define icmp_rtime  icmp_dun.id_ts.its_rtime
#define icmp_ttime  icmp_dun.id_ts.its_ttime
#define icmp_ip     icmp_dun.id_ip.idi_ip
#define icmp_radv   icmp_dun.id_radv
#define icmp_mask   icmp_dun.id_mask
#define icmp_data   icmp_dun.id_data
} NET_PACKED;

/* =========================================================================
 * ICMPv6 (netinet/icmp6.h)
 * ====================================================================== */

/* ICMPv6 message types */
#define ICMP6_DST_UNREACH          1
#define ICMP6_PACKET_TOO_BIG       2
#define ICMP6_TIME_EXCEEDED        3
#define ICMP6_PARAM_PROB           4
#define ICMP6_ECHO_REQUEST         128
#define ICMP6_ECHO_REPLY           129
#define ICMP6_MEMBERSHIP_QUERY     130  /* MLD                  */
#define ICMP6_MEMBERSHIP_REPORT    131
#define ICMP6_MEMBERSHIP_REDUCTION 132
#define ND_ROUTER_SOLICIT          133  /* Neighbor Discovery   */
#define ND_ROUTER_ADVERT           134
#define ND_NEIGHBOR_SOLICIT        135
#define ND_NEIGHBOR_ADVERT         136
#define ND_REDIRECT                137

/* Codes for ICMP6_DST_UNREACH */
#define ICMP6_DST_UNREACH_NOROUTE     0
#define ICMP6_DST_UNREACH_ADMIN       1
#define ICMP6_DST_UNREACH_BEYONDSCOPE 2
#define ICMP6_DST_UNREACH_ADDR        3
#define ICMP6_DST_UNREACH_NOPORT      4

typedef struct {
    uint8_t  icmp6_type;
    uint8_t  icmp6_code;
    uint16_t icmp6_cksum;

    union {
        /* Echo Request / Reply (128 / 129) */
        struct {
            uint16_t id;
            uint16_t seq;
        } echo;

        /* Packet Too Big (2) */
        uint32_t mtu;

        /* all others — first 4 bytes of data */
        uint32_t raw;
    } icmp6_dataun;
} NET_PACKED icmp6_hdr_t;

#define icmp6_id   icmp6_dataun.echo.id
#define icmp6_seq  icmp6_dataun.echo.seq
#define icmp6_mtu  icmp6_dataun.mtu

/* =========================================================================
 * Utility functions — checksums
 * ====================================================================== */

/*
 * net_checksum — standard Internet checksum (RFC 1071).
 * Used for IPv4 header, ICMP, UDP (with pseudo-header).
 *
 * Example for an IP header:
 *   ip->ip_sum = 0;
 *   ip->ip_sum = net_checksum(ip, IP_IHL(ip));
 */
static inline uint16_t net_checksum(const void *data, size_t len) {
    const uint16_t *p = (const uint16_t *)data;
    uint32_t sum = 0;

    while (len > 1) {
        sum += *p++;
        len -= 2;
    }
    if (len == 1)
        sum += *(const uint8_t *)p;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

/*
 * udp_checksum — UDP checksum with IPv4 pseudo-header.
 *
 *   ip  : pointer to the IPv4 header
 *   udp : pointer to the UDP header
 */
static inline uint16_t udp_checksum(const ip_hdr_t *ip, const udp_hdr_t *udp) {
    /* Pseudo-header used for checksum calculation */
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t  zero;
        uint8_t  proto;
        uint16_t len;
    } NET_PACKED pseudo;

    pseudo.src   = ip->ip_src;
    pseudo.dst   = ip->ip_dst;
    pseudo.zero  = 0;
    pseudo.proto = IPPROTO_UDP;
    pseudo.len   = udp->uh_ulen;

    uint32_t sum = 0;
    const uint16_t *p;
    size_t len;

    /* Sum the pseudo-header */
    p = (const uint16_t *)&pseudo;
    len = sizeof(pseudo);
    while (len > 1) { sum += *p++; len -= 2; }

    /* Sum the UDP header + data */
    p = (const uint16_t *)udp;
    len = ntohs(udp->uh_ulen);
    while (len > 1) { sum += *p++; len -= 2; }
    if (len == 1) sum += *(const uint8_t *)p;

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

#ifdef __cplusplus
}
#endif

#endif /* NET_HEADERS_H */

#endif
