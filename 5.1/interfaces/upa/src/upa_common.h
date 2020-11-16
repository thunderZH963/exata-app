// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200 
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.
#ifndef UPA_COMMON_H
#define UPA_COMMON_H

#ifdef _WIN32
#include <ws2ipdef.h>
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#endif

#define IFNAME_SIZE 16
#define UPA_HDR_SIZE (sizeof(struct upa_hdr))

/* These number are random */
#define UPA_MAGIC16_1 0xAB78
#define UPA_MAGIC32_1 0x8912a9b5
#define UPA_MAGIC32_2 0x90714313
#define UPA_MAGIC32_3 0xbc7f63bb

enum {
    /* Connection Manager calls */
    UPA_MSG_CONNECTION_MANAGER = 1,
    UPA_MSG_CONNECTION_MANAGER_BEACON,
    UPA_MSG_AUTO_IPNE_REGISTER,
    UPA_MSG_AUTO_IPNE_UNREGISTER,
    UPA_MSG_SOLICIT_EXATA,
    UPA_MSG_SET_UPA_NODE,
    UPA_MSG_RESET_UPA_NODE,
    UPA_MSG_AUTO_IPNE_REGISTER_SUCCESS,
    UPA_MSG_AUTO_IPNE_REGISTER_UNSUCCESS,
    UPA_MSG_AUTO_IPNE_UNREGISTER_SUCCESS,
    UPA_MSG_AUTO_IPNE_UNREGISTER_UNSUCCESS,

    /* Socket calls */
    UPA_MSG_NEW_SOCKET = 100,
    UPA_MSG_REGISTER,
    UPA_MSG_BIND,
    UPA_MSG_LISTEN,
    UPA_MSG_CONNECT,
    UPA_MSG_ACCEPT,
    UPA_MSG_DATA_CONNECTED,
    UPA_MSG_DATA_UNCONNECTED,
    UPA_MSG_CLOSE,
    UPA_MSG_SHUTDOWN,

    /* Process calls */
    UPA_MSG_FORK,
    UPA_MSG_DUP,
    
    /* IOCTL Calls */
    UPA_MSG_GET_IF_INFO,
    UPA_MSG_UPDATE_RT,

    /* Linux proc/net calls*/
    UPA_MSG_GET_PROC_NET
};

union sockAddress {
    sockaddr_in ipv4;
    sockaddr_in6 ipv6;
};

struct sockAddrInfo{
    short   sin_family;
    sockAddress address;
};

struct upa_hdr {
    UInt16  msg_type;
    UInt16  port;
    UInt32  upa_node;
    UInt32  qualnet_fd;
    UInt32  address;
    UInt32  network_type;
    /*struct timeval tstamp; -- Maybe add later */
};

struct new_sock_msg_data {
    int family;
    int type;
    int protocol;
};

#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif
struct qualnet_if_info {
    char ifname[IFNAMSIZ];
    struct sockaddr_in ifaddr;
    struct sockaddr_in netmask;
    struct sockaddr_in bcastaddr;
    struct sockaddr phyaddr;
    short flags;
    int ifindex;
    int metric;
    int mtu;
};
    
// TODO: /proc/net stuff. Move to a separate header file.
enum {
    UPA_PROC_NET_DEV,
    UPA_PROC_NET_ROUTE,
    UPA_PROC_NET_UDP,
    UPA_PROC_NET_TCP,
    UPA_PROC_NET_SNMP
};


/* DEV:: /proc/net/dev  */
typedef struct {
    char ifname[IFNAMSIZ];
    long     rx_bytes;  
    long     rx_packets;
    int     rx_errors; // errors detected by device driver
    int     rx_drops;  // dropped by device driver
    int     rx_fifo;   // fifo buffer errors (overflow, locking)
    int     rx_frames; // packet framing errors
    int     rx_compressed; // not used
    int     rx_multicast;  
    long    tx_bytes;
    long     tx_packets;
    int        tx_errs;
    int     tx_drops;
    int        tx_fifo;
    int     tx_collisions; // collisions detected on interface
    int     tx_carrier;    // carrier losses detected by device driver
    int        tx_compressed; 
}SLDevInfo;

typedef struct {
    char ifname[IFNAMSIZ];
    struct sockaddr_in dest;
    struct sockaddr_in gateway;
    int flags;
    int metric;
    struct sockaddr_in netmask;
    int mtu;
#ifdef SL_INFO_COMPLETE
    int refcount;
    int use;
    int window;
    int irtt;
#endif
} SLRouteInfo;

typedef struct {

} SLUdpInfo;

typedef struct {

} SLTcpInfo;

typedef struct {
    long ip[19];
    long icmp[26];
    long tcp[14];
    long udp[4];
}SLSnmpInfo;

enum channelType
{
    DATA,
    MESSAGE,
};

void
SockaddrToAddress(sockaddr* sockAddress, Address* address);

int
AddressToSockaddr(sockaddr* sockAddress, Address* address);

unsigned short
GetPortFromSockaddr(sockaddr* address);

void
SetPortFromSockaddr(sockaddr* address,
                    unsigned short port,
                    UInt32* length = NULL);

int
GetSockaddrLength(sockaddr* address);
#endif
