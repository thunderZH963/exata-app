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

#ifndef IPV6_INPUT_H
#define IPV6_INPUT_H

#include "api.h"
#include "ip6_opts.h"
#include "ipv6.h"


// /**
// API                 :: ip6_input
// LAYER               :: Network
// PURPOSE             :: IPv6 Input processing function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +arg                 : int arg: Option argument
// +interfaceId         : int interfaceId : Index of the concerned Interface
// +lastHopAddress      : NodeAddress : last Hop Link Layer Address
// RETURN              :: None
// **/
void
ip6_input(
    Node* node,
    Message* msg,
    void* arg,
    int interfaceId,
    MacHWAddress* lastHopAddress);

// /**
// API                 :: ip6_deliver
// LAYER               :: Network
// PURPOSE             :: IPv6 packet deliver function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +opts                : optionList* opts : Pointer to the Option List
// +interfaceId         : int interfaceId : Id of the concerned interface
// +headerValue         : unsigned char: Value of ipv6 next header
// RETURN              :: None
// NOTES                : IPv6 packet deliver function
// **/

void ip6_deliver(
        Node* node,
        Message* msg,
        optionList* opts,
        int interfaceId,
        unsigned char headerValue);

#endif
