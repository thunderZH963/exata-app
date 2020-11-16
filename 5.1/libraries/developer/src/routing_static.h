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
 * PURPOSE:         Static routing.
 */

#ifndef _STATIC_ROUTING_H_
#define _STATIC_ROUTING_H_


/*
 * NAME:        RoutingStaticLayer.
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

void
RoutingStaticLayer(
    Node *node,
    const Message *msg);


/*
 * NAME:        RoutingStaticInit.
 *
 * PURPOSE:     Handling all initializations needed by static routing.
 *
 * PARAMETERS:  node, node doing the initialization.
 *              nodeInput, input from configuration file.
 *              type, either STATIC or DEFAULT routes.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */

void
RoutingStaticInit(
    Node *node,
    const NodeInput *nodeInput,
    NetworkRoutingProtocolType type);


/*
 * NAME:        RoutingStaticFinalize.
 *
 * PURPOSE:     Handling all finalization needed by static routing.
 *
 * PARAMETERS:  node, node doing the finalization.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */

void
RoutingStaticFinalize(
    Node *node);


#endif /* _STATIC_ROUTING_H_ */

