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
// This file contains NDP (RFC 2461)
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

#ifndef _IF_NDP6_H_
#define _IF_NDP6_H_

#include "api.h"
#include "ipv6.h"

// used in the flag to identify different advertisement


// /**
// CONSTANT    :: ROUTER_ADV : 0x80000000
// DESCRIPTION :: router advertisement flag.
// **/
#define ROUTER_ADV      0x80000000


// /**
// CONSTANT    :: SOLICITED_ADV : 0x40000000
// DESCRIPTION :: solicited advertisement flag.
// **/
#define SOLICITED_ADV   0x40000000

// /**
// CONSTANT    :: OVERRIDE_ADV : 0x20000000
// DESCRIPTION :: overriding flag.
// **/
#define OVERRIDE_ADV    0x20000000


// /**
// CONSTANT    :: NO_LLA_ADV : 0x00000001
// DESCRIPTION :: no link layer flag.
// **/
#define NO_LLA_ADV      0x00000001


// /**
// CONSTANT    :: MASK_ADV : 0xf0000000
// DESCRIPTION :: Masked advertisement flag.
// **/
#define MASK_ADV        0xf0000000

// IPv6 Neighbor Discovery Protocol.
// See RFC xxxx for protocol description.



// STRUCT      :: rtentry_struct
// DESCRIPTION :: route entry structure.
// **/
struct rtentry_struct;



// /**
// CONSTANT    :: LLNDP6_UNREACHABLE : 0
// DESCRIPTION :: held very old/unreachable routes
// **/
#define LLNDP6_UNREACHABLE    0


// /**
// CONSTANT    :: LLNDP6_INCOMPLETE : 1
// DESCRIPTION :: no info yet
// **/
#define LLNDP6_INCOMPLETE   1   // no info yet


// /**
// CONSTANT    :: LLNDP6_PROBING : 2
// DESCRIPTION :: usable, NUD probes it
// **/
#define LLNDP6_PROBING      2   // usable, NUD probes it


// /**
// CONSTANT    :: LLNDP6_REACHABLE : 3
// DESCRIPTION :: valid
// **/
#define LLNDP6_REACHABLE    3   // valid


// /**
// CONSTANT    :: LLNDP6_BUILTIN : 4
// DESCRIPTION :: don't fall into probing
// **/
#define LLNDP6_BUILTIN      4   // don't fall into probing


// /**
// CONSTANT    :: M_NOPROBE : M_BCAST
// DESCRIPTION :: don't trigger NUD probes
// **/
#define M_NOPROBE           M_BCAST // don't trigger NUD probes

//---------------------------NDP Timers ----------------------------------//



// /**
// CONSTANT    :: NDPT_KEEP : 2 * MINUTE
// DESCRIPTION :: Route default lifetime (2 minutes)
// **/
#define NDPT_KEEP       2 * MINUTE  // Route default lifetime (2 minutes)


// /**
// CONSTANT    :: NDPT_REACHABLE : 30 * SECOND
// DESCRIPTION :: Route is reachable for 30 seconds
// **/
#define NDPT_REACHABLE  30 * SECOND


// /**
// CONSTANT    :: NDPT_RETRANS  : 2 * SECOND
// DESCRIPTION :: Retrans timer (2 seconds)
// **/
#define NDPT_RETRANS    2 * SECOND  // Retrans timer (2 seconds)


// /**
// CONSTANT    :: NDPT_PROBE : 5 * SECOND
// DESCRIPTION :: Delay first probe
// **/
#define NDPT_PROBE      5 * SECOND  // Delay first probe


// /**
// CONSTANT    :: NDPT_PROBE : 5 * SECOND
// DESCRIPTION :: Delay first probe
// **/
#define NDPT_UNREACHABLE      5 * SECOND  // Delay first probe

// /**
// CONSTANT    :: NDPT_DOWN : 3 * SECOND
// DESCRIPTION :: hold down timer (3 seconds)
// **/
#define NDPT_DOWN       3 * SECOND  // hold down timer (3 seconds)


// /**
// CONSTANT    :: NDP_UMAXTRIES  : 3
// DESCRIPTION :: Max unicast solicit (3)
// **/
#define NDP_UMAXTRIES   3           // Max unicast solicit (3)


// /**
// CONSTANT    :: NDP_MMAXTRIES : 3
// DESCRIPTION :: Max multicast solicit (3)
// **/
#define NDP_MMAXTRIES   3           // Max multicast solicit (3)

//---------------------------NDP Timers ----------------------------------//



// STRUCT      :: Ipv6NSolRetryMessage
// DESCRIPTION :: Neighbor Solicitation Message retry structure.
// **/
typedef struct Ipv6_NSol_RetryMessage_struct
{
    int retryCounter;
    int interfaceId;
    int packetSize;
    int otherDataLength;
    in6_addr dst;
}Ipv6NSolRetryMessage;

// STRUCT      :: Ipv6RouterAdverInfo
// DESCRIPTION :: Router Advertise Timer info structure.
// **/
typedef struct Ipv6_Rout_Adver_Info_struct
{
    int interfaceId;
}Ipv6RouterAdverInfo;

// STRUCT      :: Ipv6NeighAdverInfo
// DESCRIPTION :: Neighbor Advertise Timer info structure.
// **/
typedef struct Ipv6_Neigh_Adver_Info_struct
{
    int retryCounter;
    int interfaceId;
}Ipv6NeighAdverInfo;

// STRUCT      :: Ipv6RouterSolInfo
// DESCRIPTION :: Router Solicitation Timer info structure.
// **/
typedef struct Ipv6_Rout_Sol_Info_struct
{
    int retryCounter;
    int interfaceId;
}Ipv6RouterSolInfo;

//-----------------------------------------------------------------------//


// /**
// API                 :: ndplookup
// LAYER               :: Network
// PURPOSE             :: Neighbor Cache lookup function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +ifp                 : int* ifp : Pointer to interface index
// +rt                  : rtentry* rt :Pointer to route entry structure
// +msg                 : Message* msg : Pointer to the Message Structure
// +dst                 : in6_addr* dst : IPv6 Destination Address
// +desten              : NodeAddress* desten: Destination linklayer address
// RETURN              :: rn_leaf*
rn_leaf* ndplookup(
    Node* node,
    int interfaceId,
    in6_addr *addr,
    int report,
    MacHWAddress& linkLayerAddr);



// /**
// API                 :: updatePrefixList
// LAYER               :: Network
// PURPOSE             :: Prefix list updating function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +addr                : in6_addr* addr : IPv6 Address of destination
// +prefixLen           : UInt32         : Prefix Length
// +report              : int report: error report flag
// +linkLayerAddr       : NodeAddress linkLayerAddr: Link layer address
// +routeFlag           : int routeFlag: route Flag
// +routeType           : int routeType: Route type e.g. gatewayed/local.
// +gatewayAddr         : in6_addr gatewayAddr: Gateway's ipv6 address.
// RETURN              :: None
// **/
void updatePrefixList(
    Node* node,
    int interfaceId,
    in6_addr *addr,
    UInt32 prefixLen,
    int report,
    MacHWAddress& linkLayerAddr,
    int routeFlag,
    int routeType,
    in6_addr gatewayAddr);



// /**
// API                 :: ndadv6_input
// LAYER               :: Network
// PURPOSE             :: Neighbor advertising processing function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN              :: None
// **/
int
ndadv6_input(
    Node* node,
    Message* msg,
    int interfaceId);



// /**
// API                 :: ndp6_resolve
// LAYER               :: Network
// PURPOSE             :: Link layer address resolving function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +ifp                 : int *ifp : interface id
// +rt                  : rtentry* rt
// +msg                 : Message* msg : Pointer to the message structure
// +dst                 : in6_addr* dst : IPv6 Address
// RETURN              :: int
// **/
int
ndp6_resolve(
    Node* node,
    int incomingInterface,
    int *ifp,    // interface id
    rtentry* rt,
    Message* msg,
    in6_addr* dst);



// /**
// API                 :: ndsol6_output
// LAYER               :: Network
// PURPOSE             :: Neighbor Solicitation sending function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId   :Identification No. of the concerned interface
// +dst                 : in6_addr* dst     :IPv6 Destination Address
// +target              : in6_addr* target  :IPv6 Target Address
// +retry               : BOOL retry        : Will retry or not.
// RETURN              :: None
// **/
void ndsol6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target,
    BOOL retry);



// /**
// API                 :: prefixLookUp
// LAYER               :: Network
// PURPOSE             :: Prefix look up function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +addr                : in6_addr* addr : IPv6 Address pointer,
//                      :           IPv6 prefix to search in prefix table.
// +rn                  : rn_leaf** rn : Points to an radix-tree-leaf pointer
// RETURN              :: NONE
// **/
void prefixLookUp(Node* node, in6_addr* addr, rn_leaf**);


// /**
// API                 :: rtsol6_input
// LAYER               :: Network
// PURPOSE             :: Receive a Router Solicitation packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN              :: int
// **/
int
rtsol6_input(Node* node, Message* msg, int interfaceId);

// /**
// API                 :: ndsol6_input
// LAYER               :: Network
// PURPOSE             :: Receive a Neighbor Solicitation packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to message structure
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN              :: int
int
ndsol6_input(Node* node, Message* msg, int interfaceId);


// /**
// API                 :: Router Advertisement processing function.
// LAYER               :: Network
// PURPOSE             :: Receive a Router Advertisement packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to message structure
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN              :: int
// **/

int
rtadv6_input(Node* node, Message* msg, int interfaceId);


// /**
// API                 :: rtsol6_output
// LAYER               :: Network
// PURPOSE             :: Send a Router Solicitation packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +target              : in6_addr* target : IPv6 target address pointer
// RETURN              :: None
// **/

void rtsol6_output(
        Node* node,
        int interfaceId,
        in6_addr* target);

// /**
// API                 :: rtadv6_output
// LAYER               :: Network
// PURPOSE             :: Send a Router Advertisement packet.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +dst                 : in6_addr* dst : IPv6 Destination Address pointer
// +target              : in6_addr* target : IPv6 target address pointer
// RETURN              :: None
// **/
void
rtadv6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target);

//---------------------------------------------------------------------------
// FUNCTION             : ndadv6_output
// PURPOSE             :: Send a Neighbor Advertisement packet.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// +dst                 : in6_addr* dst : IPv6 destination address pointer.
// +target              : in6_addr* target : IPv6 target address pointer.
// +flags               : int flags: Type of advt.
// RETURN               : None
// NOTES                : Targeted Neighbor sends it's link layer address in
//                        response to Neighbor solicitation.
//---------------------------------------------------------------------------
void ndadv6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target,
    int flags);

// /**
// API                 :: CheckStaticRouteEntry
// LAYER               :: Network
// PURPOSE             :: To check user given static route entry.
// PARAMETERS          ::
// +ipv6Addr            : in6_addr ipv6Addr: IPv6 address for static entry.
// +hp                  : struct prefixListStruct* hp: Pointer to prefix list
//                      :   structure.
// +noOfPrefix          : int noOfPrefix: No of prefixes in the list.
// +interfaceId         : int interfaceId: Index of concerned interface
// +linkLayerAddr       : NodeAddress linkLayerAddr: link layer address.
// RETURN              :: None
// **/
void
CheckStaticRouteEntry(
    in6_addr ipv6Addr,
    struct prefixListStruct* hp,
    int noOfPrefix,
    int interfaceId,
    MacHWAddress& linkLayerAddr);



// /**
// API                 :: destinationLookUp
// LAYER               :: Network
// PURPOSE             :: It checks the destination cache.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +ipv6                : IPv6Data* ipv6: Pointer to node's IPv6 data.
// +dst                 : in6_addr* dst : IPv6 destination address,
//                      :           IPv6 destination address to search.
// RETURN              :: route*
// **/
route* destinationLookUp(Node* node, IPv6Data* ipv6, in6_addr* dst);

// /**
// FUNCTION         :: ndp_resolvellAddrandSendToMac
// LAYER            :: Network
// PURPOSE          :: Resolve Next-hop link-layer address and send to mac
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + outgoingInterface :  Int32      : Interface Index
// RETURN           :: void : NULL.
// **/
void
ndp_resolvellAddrandSendToMac(
    Node *node,
    Message *msg,
    in6_addr nextHopAddr,
    int outgoingInterface);

// /**
// FUNCTION         :: search_NDPentry
// LAYER            :: Network
// PURPOSE          :: Search for link layer address in ndp cache
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + outgoingInterface :  Int32      : Interface Index
// + ndp_cache_entry : rn_leaf**     : Pointer to pointer to NDP cache entry
// RETURN           :: BOOL : Found or not found flag.
// **/
static  BOOL search_NDPentry(Node* node,
                         Message* msg,
                         in6_addr nextHopAddr,
                         int outgoingInterface,
                         rn_leaf** ndp_cache_entry);

#endif
