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

/*
 * PURPOSE:         MulticastStatic routing.
 */

#ifndef _MULTICAST_STATIC_H_
#define _MULTICAST_STATIC_H_


/*
 * NAME:        RoutingMulticastStaticLayer.
 *
 * PURPOSE:     Handles all messages sent to bellmandford.
 *
 * PARAMETERS:  node, node receiving message.
 *              msg, message for node to interpret.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */

void RoutingMulticastStaticLayer(Node *node, const Message *msg);


/*
 * NAME:        RoutingMulticastStaticInit.
 *
 * PURPOSE:     Handling all initializations needed by multicast static routing.
 *
 * PARAMETERS:  node, node doing the initialization.
 *              nodeInput, input from configuration file.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */

void RoutingMulticastStaticInit(Node *node, const NodeInput *nodeInput);


/*
 * NAME:        RoutingMulticastStaticFinalize.
 *
 * PURPOSE:     Handling all finalization needed by multicast static routing.
 *
 * PARAMETERS:  node, node doing the finalization.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */

void RoutingMulticastStaticFinalize(Node *node);


int RoutingMulticastStaticGetInterfaceIndex(Node *node, Address addr);


#endif /* _MULTICAST_STATIC_H_ */

