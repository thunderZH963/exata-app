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
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

//
// Ported from FreeBSD 4.7
// This file contains functions for IPv6 routing
//

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//  This product includes software developed by the University of
//  California, Berkeley and its contributors.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//


// /**
// PACKAGE     :: Ipv6-Route
// DESCRIPTION :: Ipv6-Route inforamtion, storing, retriving, searching.
// **/


#ifndef _ROUTE_H_
#define _ROUTE_H_

#include "ipv6_radix.h"
#include "ipv6.h"

/*
 * These numbers are used by reliable protocols for determining
 * retransmission behavior and are included in the routing structure.
 */


// /**
// STRUCT      :: rt_metrics
// DESCRIPTION :: route related metic functions
// **/
typedef struct rt_metrics_struct {
    UInt32  rmx_mtu;        /* MTU for this path */
    UInt32  rmx_hopcount;   /* max hops expected */
    UInt32  rmx_expire;     /* lifetime for route, e.g. redirect */
    UInt32  rmx_recvpipe;   /* inbound delay-bandwith product */
    UInt32  rmx_sendpipe;   /* outbound delay-bandwith product */
    UInt32  rmx_ssthresh;   /* outbound gateway buffer limit */
    UInt32  rmx_rtt;        /* estimated round trip time */
    UInt32  rmx_rttvar;     /* estimated rtt variance */
    UInt32  rmx_pksent;     /* packets sent using this route */
} rt_metrics;

/*
 * rmx_rtt and rmx_rttvar are stored as microseconds;
 * RTTTOPRHZ(rtt) converts to a value suitable for use
 * by a protocol slowtimo counter.
 */



// /**
// CONSTANT    :: MAX_KEY_LENGTH : 32
// DESCRIPTION :: Maximum prefix length.
// **/
#define MAX_KEY_LENGTH 32


/*
 * We distinguish between routes to hosts and routes to networks,
 * preferring the former if available.  For each route we infer
 * the interface to use from the gateway address supplied when
 * the route was entered.  Routes that forward packets through
 * gateways are marked so that the output routines know to address the
 * gateway rather than the ultimate destination.
 */


// /**
// STRUCT      :: rtentry
// DESCRIPTION :: route entry structure
// **/
typedef struct rtentry_struct
{
    rn_leaf* rt_node;             /* tree glue, and other values */
    in6_addr* rt_gateway;  /* value */
    unsigned int rt_flags;        /* up/down?, host/net */
    clocktype rt_expire;          /* route expire time*/
    unsigned int rt_refcnt;       /* # held references */
    unsigned int rt_use;          /* raw # packets forwarded */
    int rt_ifp;                   /* the answer: interface to use */
    int rt_ifa;                   /* the answer: interface to use */
    rt_metrics rt_rmx;            /* metrics used by rx'ing protocols */
} rtentry;



// /**
// CONSTANT    :: RTF_UP : 0x1
// DESCRIPTION :: route usable
// **/
#define RTF_UP      0x1         // route usable

// /**
// CONSTANT    :: RTF_GATEWAY : 0x2
// DESCRIPTION :: destination is a gateway
// **/
#define RTF_GATEWAY 0x2         // destination is a gateway

// /**
// CONSTANT    :: RTF_HOST : 0x4
// DESCRIPTION :: host entry (net otherwise)
// **/
#define RTF_HOST    0x4         // host entry (net otherwise)

// /**
// CONSTANT    :: RTF_REJECT  : 0x8
// DESCRIPTION :: host or net unreachable
// **/
#define RTF_REJECT  0x8         // host or net unreachable

// /**
// CONSTANT    :: RTF_DYNAMIC : 0x10
// DESCRIPTION :: created dynamically (by redirect)
// **/
#define RTF_DYNAMIC 0x10        /* created dynamically (by redirect) */

// /**
// CONSTANT    :: RTF_MODIFIED : 0x20
// DESCRIPTION :: modified dynamically (by redirect)
// **/
#define RTF_MODIFIED    0x20    /* modified dynamically (by redirect) */

// /**
// CONSTANT    :: RTF_DONE  : 0x40
// DESCRIPTION :: message confirmed
// **/
#define RTF_DONE    0x40        /* message confirmed */

// /**
// CONSTANT    :: RTF_MASK : 0x80
// DESCRIPTION :: subnet mask present
// **/
#define RTF_MASK    0x80        /* subnet mask present */

// /**
// CONSTANT    :: RTF_STATIC : 0x800
// DESCRIPTION :: manually added
// **/
#define RTF_STATIC  0x800       /* manually added */

// /**
// CONSTANT    :: RTF_LOCAL : 0x200000
// DESCRIPTION :: route represents a local address
// **/
#define RTF_LOCAL   0x200000    /* route represents a local address */

// /**
// CONSTANT    :: RTF_BROADCAST : 0x400000
// DESCRIPTION :: route represents a bcast address
// **/
#define RTF_BROADCAST   0x400000    /* route represents a bcast address */

// /**
// CONSTANT    :: RTF_MULTICAST  : 0x800000
// DESCRIPTION :: route represents a mcast address
//                0x1000000 and up unassigned
// **/
#define RTF_MULTICAST   0x800000    /* route represents a mcast address */
                    /* 0x1000000 and up unassigned */

// /**
// CONSTANT    :: RTM_ADD : 0x1
// DESCRIPTION :: Add Route
// **/
#define RTM_ADD     0x1 /* Add Route */

// /**
// CONSTANT    :: RTM_DELETE : 0x2
// DESCRIPTION :: Delete Route
// **/
#define RTM_DELETE  0x2 /* Delete Route */

// /**
// CONSTANT    :: RTM_CHANGE : 0x3
// DESCRIPTION :: Change Metrics or flags
// **/
#define RTM_CHANGE  0x3 /* Change Metrics or flags */

// /**
// CONSTANT    :: RTM_REDIRECT : 0x6
// DESCRIPTION :: Told to use different route
// **/
#define RTM_REDIRECT    0x6 /* Told to use different route */

// /**
// CONSTANT    :: RTM_MISS : 0x7
// DESCRIPTION :: Lookup failed on this address
// **/
#define RTM_MISS    0x7 /* Lookup failed on this address */


// /**
// CONSTANT    :: RTM_RESOLVE : 0xb
// DESCRIPTION :: req to resolve dst to LL addr
// **/
#define RTM_RESOLVE 0xb /* req to resolve dst to LL addr */

// /**
// CONSTANT    :: RTM_NEWADDR : 0xc
// DESCRIPTION :: address being added to iface
// **/
#define RTM_NEWADDR 0xc /* address being added to iface */

// /**
// CONSTANT    :: RTM_DELADDR : 0xd
// DESCRIPTION :: address being removed from iface
// **/
#define RTM_DELADDR 0xd /* address being removed from iface */

// /**
// CONSTANT    :: RTM_IFINFO : 0xe
// DESCRIPTION :: iface going up/down etc.
// **/
#define RTM_IFINFO  0xe /* iface going up/down etc. */

// /**
// CONSTANT    :: RTM_NEWMADDR : 0xf
// DESCRIPTION :: mcast group membership being added to if
// **/
#define RTM_NEWMADDR    0xf /* mcast group membership being added to if */

// /**
// CONSTANT    :: RTM_DELMADDR : 0x10
// DESCRIPTION :: mcast group membership being deleted
// **/
#define RTM_DELMADDR    0x10    /* mcast group membership being deleted */

// /**
// CONSTANT    :: RTM_EXPIRE : 0x11
// DESCRIPTION :: Route has Expired
// **/
#define RTM_EXPIRE  0x11    /* Route has Expired */

// /**
// CONSTANT    :: RTM_RTLOST : 0x12
// DESCRIPTION :: Router has been Lost
// **/
#define RTM_RTLOST  0x12    /* Router has been Lost */


// /**
// CONSTANT    :: RTM_REACHHINT : 0x14
// DESCRIPTION :: upper layer says this is reachable
// **/
#define RTM_REACHHINT   0x14    /* upper layer says this is reachable */

// /**
// CONSTANT    :: RTV_HOPCOUNT : 0x2
// DESCRIPTION :: init or lock _hopcount
// **/
#define RTV_HOPCOUNT    0x2 /* init or lock _hopcount */

// /**
// CONSTANT    :: RTV_EXPIRE : 0x4
// DESCRIPTION :: init or lock _hopcount
// **/
#define RTV_EXPIRE  0x4 /* init or lock _hopcount */


/*
 * Bitmask values for rtm_addr.
 */

// /**
// CONSTANT    :: RTA_DST : 0x1
// DESCRIPTION :: destination sockaddr present
// **/
#define RTA_DST     0x1 /* destination sockaddr present */

// /**
// CONSTANT    :: RTA_GATEWAY : 0x2
// DESCRIPTION :: gateway sockaddr present
// **/
#define RTA_GATEWAY 0x2 /* gateway sockaddr present */

// /**
// CONSTANT    :: RTA_NETMASK : 0x4
// DESCRIPTION :: netmask sockaddr present
// **/
#define RTA_NETMASK 0x4 /* netmask sockaddr present */

// /**
// CONSTANT    :: RTA_GENMASK : 0x8
// DESCRIPTION :: cloning mask sockaddr present
// **/
#define RTA_GENMASK 0x8 /* cloning mask sockaddr present */

// /**
// CONSTANT    :: RTA_BRD : 0x80
// DESCRIPTION :: for NEWADDR, broadcast or p-p dest addr
// **/
#define RTA_BRD     0x80    /* for NEWADDR, broadcast or p-p dest addr */


// /**
// STRUCT      :: route
// DESCRIPTION :: A route consists of a destination address and a reference
// to a routing entry.  These are often held by protocols
// in their control blocks, e.g. inpcb.
// **/
typedef struct route_struct
{
    rtentry ro_rt;
    in6_addr ro_dst;
    UInt32 prefixLen;
} route;


//Prefix Holding pointers.

// /**
// STRUCT      :: prefixList
// DESCRIPTION :: Prefix Holding pointers.
// **/
typedef struct prefixListStruct
{
    rn_leaf* rnp;
    struct prefixListStruct* prev;
    struct prefixListStruct* next;
} prefixList;



// /**
// API                 :: route_init.
// LAYER               :: Network
// PURPOSE             :: Route initialization function
// PARAMETERS          ::
// + ipv6               : struct ipv6_data_struct* ipv6: IPv6 data pointer of
//                      :    node.
// RETURN              :: None
// **/
void
route_init(struct ipv6_data_struct *ipv6);



// /**
// API                 :: rtalloc
// LAYER               :: Network
// PURPOSE             :: route allocation function
// PARAMETERS          ::
// + node               : Node* node : pointer to node
// + ro                 : route* ro: Pointer to destination route.
// + llAddr             : unsigned int llAddr: Link layer address.
// RETURN              :: None
// **/
void rtalloc(Node* node, route* ro, MacHWAddress& llAddr);



// /**
// API                 :: rtalloc_ign
// LAYER               :: Network
// PURPOSE             :: Route ignition function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + ro                 : route* ro : Pointer to destination route.
// + ignore             : UInt32 ignore: Ignore flag
// + llAddr             : unsigned int llAddr: Link layer address.
// RETURN              :: None
// **/
void
rtalloc_ign(
    Node* node,
    route* ro,
    UInt32 ignore,
    MacHWAddress& llAddr);



// /**
// API                 :: rtalloc1
// LAYER               :: Network
// PURPOSE             :: Second level route allocation function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + rnh                : radix_node_head* rnh: Pointer to radix tree head.
/// + dst               : in6_addr* dst : IPv6 Destination Address
// + report             : int report: Report flag
// + ignflags           : UInt32 ignflags: Ignor flag
// + linkLayerAddr      : unsigned int linkLayerAddr: Link layer address.
// RETURN              :: rn_leaf*
// **/
rn_leaf*
rtalloc1(
    Node* node,
    radix_node_head* rnh,
    in6_addr* dst,
    int report,
    UInt32 ignflags,
    MacHWAddress& linkLayerAddr);



// /**
// API                 :: addPrefix
// LAYER               :: Network
// PURPOSE             :: Adds prefix in prefix list.
// PARAMETERS          ::
// + tail               : prefixList* tail: End pointer of prefix list
// + rn                 : rn_leaf* rn: Pointer to radix node.
// + noOfPrefix         : unsigned int* noOfPrefix: No of perfix in
//                      :        the prefix list
// RETURN              :: None
// **/
void
addPrefix(
    prefixList* tail,
    rn_leaf* rn,
    unsigned int* noOfPrefix);



// /**
// API                 :: RadixTreeLookUp
// LAYER               :: Network
// PURPOSE             :: Radix tree lookup function.
// PARAMETERS          ::
// +dst                 : in6_addr* dst: IPV6 Destination Address
// +rnh                 : radix_node_head* rnh: Radix tree head pointer
// RETURN              :: rn_leaf*
// **/
rn_leaf*
RadixTreeLookUp(Node* node, in6_addr* dst, radix_node_head* rnh);



// /**
// API                 :: FreeRoute
// LAYER               :: Network
// PURPOSE             :: frees allocated route.
// PARAMETERS          ::
// + ro                 : struct route_struct* ro: Pointer to ipv6 route.
// RETURN              :: None
// **/
void FreeRoute(struct route_struct* ro);



// /**
// API                 :: Route_Malloc
// LAYER               :: Network
// PURPOSE             :: route memory allocation function
// PARAMETERS          :: None
// RETURN              :: route*
// **/
route* Route_Malloc();

#endif
