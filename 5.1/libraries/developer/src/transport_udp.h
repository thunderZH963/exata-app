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

#ifndef _UDP_H_
#define _UDP_H_

#include "dynamic.h"
#include "stats_transport.h"

typedef struct {  /* UDP header */
    unsigned short sourcePort;       /* source port */
    unsigned short destPort;         /* destination port */
    unsigned short length;           /* length of the packet */
    unsigned short checksum;         /* checksum */
} TransportUdpHeader;

struct TransportDataUdpStruct {
    BOOL udpStatsEnabled;            /* whether to collect stats */
    BOOL traceEnabled;

    STAT_TransportStatistics* newStats;

#ifdef ADDON_DB    
    MetaDataStruct* metaData;
#endif
};


/*
 * FUNCTION    TransportUdpInit
 * PURPOSE     Initialization function for UDP.
 *
 * Parameters:
 *     node:      node being initialized.
 *     nodeInput: structure containing contents of input file
 */
void TransportUdpInit(Node *node, const NodeInput *nodeInput);


/*
 * FUNCTION    TransportLayerUdp.
 * PURPOSE     Models the behaviour of UDP on receiving the
 *             message encapsulated in msgHdr
 *
 * Parameters:
 *     node:     node which received the message
 *     msg:   message received by the layer
 */
void TransportUdpLayer(Node *node, Message *msg);


/*
 * FUNCTION    TransportUdpFinalize
 * PURPOSE     Called at the end of simulation to collect the results of
 *             the simulation of the UDP protocol of Transport Layer.
 *
 * Parameter:
 *     node:     node for which results are to be collected.
 */
void TransportUdpFinalize(Node *node);


/*
 * FUNCTION    TransportUdpSendToApp
 * PURPOSE     Send data up to the application.
 *
 * Parameters:
 *     node:      node sending the data to the application.
 *     msg:       data to be sent to the application.
 */
void TransportUdpSendToApp(Node *node, Message *msg);


/*
 * FUNCTION    TransportUdpSendToNetwork
 * PURPOSE     Send data down to the network layer.
 *
 * Parameters:
 *     node:      node sending the data down to network layer.
 *     msg:       data to be sent down to network layer.
 */
void TransportUdpSendToNetwork(Node *node, Message *msg);


/*
 * FUNCTION    TransportUdpPrintTrace
 * PURPOSE     Print out packet trace information.
 *
 * Parameters:
 *     node:      node printing out the trace information.
 *     msg:       packet to be printed.
 */
void TransportUdpPrintTrace(Node *node, Message *msg);

/*
 * FUNCTION    Udp_HandleIcmpMessage
 * PURPOSE     Send the received ICMP Error Message to Application.
 * Parameters:
 *     node:      node sending the message to application layer
 *     msg:       message to be sent to application layer
 *     icmpType:  ICMP Message Type
 *     icmpCode:   ICMP Message Code
 */

void Udp_HandleIcmpMessage (Node *node,
                            Message *msg,
                            unsigned short icmpType,
                            unsigned short icmpCode);


#endif /* _UDP_H_ */

