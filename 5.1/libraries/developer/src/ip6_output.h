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

#ifndef IPV6_OUTPUT_H
#define IPV6_OUTPUT_H

#include "ip6_opts.h"
#include "ipv6_route.h"



// /**
// API                 :: ip6_output
// LAYER               :: Network
// PURPOSE             :: IPv6 Packet Sending function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +opts                : optionList* opts : Pointer to the Option List
// +ro                  : route* ro: Pointer to route for sending the packet.
// +flags               : int flags: Flag, type of route.
// +imo                 : ip_moptions *imo: Multicast Option Pointer.
// +interfaceID         : int interfaceID : Index of the concerned Interface
// RETURN              :: int
// **/

int
ip6_output(
    Node* node,
    Message* msg,
    optionList* opts,
    route* ro,
    int flags,
    ip_moptions *imo,
    int incomingInterface,
    int interfaceID);



// /**
// API                 :: Deliver ip6 packets to queue
// LAYER               :: Network
// PURPOSE             :: Deliver ip6 packets to queue
// PARAMETERS          ::
// +node                : Node* node : Pointer to Node
// +msg                 : Message* msg : Pointer to the Message structure
// +interfaceID         : int interfaceID : Incoming interface
// +oif                 : int oif : Outgoing interface
// +nextHopLinkAddr     : NodeAddress nextHopLinkAddr : Address of Next Hop
// RETURN              :: int
// **/

int ip6PacketDelivertoQueue(
        Node* node,
        Message* msg,
        int interfaceID,
        int oif,
        MacHWAddress& nextHopLinkAddress);

#endif
