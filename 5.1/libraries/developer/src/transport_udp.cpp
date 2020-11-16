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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "transport_udp.h"
#include "app_util.h"
#include "app_mdp.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

// /**
// FUNCTION   :: TransportUdpInitTrace
// LAYER      :: TRANSPORT
// PURPOSE    :: Determine what kind of packet trace we need to worry about
// PARAMETERS ::
// + node : Node* : Pointer to node, doing the packet trace
// + nodeInput    : const NodeInput* : pointer to configuration file
// RETURN ::  void : NULL
// **/

static
void TransportUdpInitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-UDP",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-UDP should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_TRANSPORT_LAYER])
        {
            trace = TRUE;
    }
}

    if (trace)
    {
        TRACE_EnableTraceXML(node, TRACE_UDP,
            "UDP", TransportUdpPrintTrace, writeMap);
    }
    else
    {
        TRACE_DisableTraceXML(node, TRACE_UDP, "UDP", writeMap);
    }
    writeMap = FALSE;
}

/*
 * FUNCTION    TransportUdpInit
 * PURPOSE     Initialization function for UDP.
 *
 * Parameters:
 *     node:      node being initialized.
 *     nodeInput: structure containing contents of input file
 */
void
TransportUdpInit(Node *node, const NodeInput *nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal = FALSE;
    BOOL readVal = FALSE;
    TransportDataUdp* udp =
       (TransportDataUdp*)MEM_malloc(sizeof(TransportDataUdp));

    node->transportData.udp = udp;

    TransportUdpInitTrace(node, nodeInput);

    IO_ReadBool(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "UDP-STATISTICS",
        &retVal,
        &readVal);

    if (retVal == FALSE || !readVal)
    {
        udp->udpStatsEnabled = FALSE;

    }
    else if (readVal)
    {
        udp->udpStatsEnabled = TRUE;
        udp->newStats = new STAT_TransportStatistics(node, "udp");
    }
    else
    {
        printf("TransportUdp unknown setting (%s) for UDP-STATISTICS.\n", buf);
        udp->udpStatsEnabled = FALSE;
    }

    if (udp->udpStatsEnabled == FALSE)
    {
#ifdef ADDON_DB
        if (node->partitionData->statsDb != NULL)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createTransAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB TRANSPORT_Aggregate table requires\n"
                    " UDP-STATISTICS to be set to YES\n");    
            }
            if (node->partitionData->statsDb->statsSummaryTable->createTransSummaryTable)
            {
        
                ERROR_ReportError(
                    "Invalid Configuration: Use of StatsDB TRANSPORT_Summary table requires\n"
                    " UDP-STATISTICS to be set to YES\n");    
            }
        }
#endif
    }
}

/*
 * FUNCTION    TransportUdpFinalize
 * PURPOSE     Called at the end of simulation to collect the results of
 *             the simulation of the UDP protocol of Transport Layer.
 *
 * Parameter:
 *     node:     node for which results are to be collected.
 */
void
TransportUdpFinalize(Node *node)
{
    char buf[MAX_STRING_LENGTH];
    TransportDataUdp* udp = node->transportData.udp;

    if (udp->udpStatsEnabled == TRUE) {
        udp->newStats->Print(
            node,
            "Transport",
            "UDP",
            ANY_ADDRESS,
            -1 /* instance id */);
    }
}

/*
 * FUNCTION    TransportUdpLayer.
 * PURPOSE     Models the behaviour of UDP on receiving the
 *             message encapsulated in msgHdr
 *
 * Parameters:
 *     node:     node which received the message
 *     msg:   message received by the layer
 */
void
TransportUdpLayer(Node *node,  Message *msg)
{
    /* Retrieve the pointer to the data portion which relates
       to the TCP protocol. */

    switch (msg->eventType)
    {
        case MSG_TRANSPORT_FromNetwork:
        {
            TransportUdpSendToApp(node, msg);
            break;
        }
        case MSG_TRANSPORT_FromAppSend:
        {
            TransportUdpSendToNetwork(node, msg);
            break;
        }
        default:
            assert(FALSE);
            abort();
    }
}



/*
 * FUNCTION    TransportUdpSendToApp
 * PURPOSE     Send data up to the application.
 *
 * Parameters:
 *     node:      node sending the data to the application.
 *     msg:       data to be sent to the application.
 */
void
TransportUdpSendToApp(Node *node, Message *msg)
{
    TransportDataUdp *udpLayer =
        (TransportDataUdp *) node->transportData.udp;
    TransportUdpHeader* udpHdr = (TransportUdpHeader *)
                                 MESSAGE_ReturnPacket(msg);

    UdpToAppRecv *info;
    Address sourceAddress;
    Address destinationAddress;
    NetworkToTransportInfo *infoPtr = (NetworkToTransportInfo *)
                                      MESSAGE_ReturnInfo(msg);
#ifdef ADDON_DB
    HandleTransportDBEvents(
        node,
        msg,
        infoPtr->incomingInterfaceIndex,          
        "UDPReceiveFromLower",        
        infoPtr->sourceAddr,
        infoPtr->destinationAddr,        
        udpHdr->sourcePort,
        udpHdr->destPort,  
        sizeof(TransportUdpHeader));
#endif
    int incomingInterfaceIndex = infoPtr->incomingInterfaceIndex;

    memcpy(&sourceAddress, &(infoPtr->sourceAddr), sizeof(Address));

    memcpy(&destinationAddress,
           &(infoPtr->destinationAddr),
           sizeof(Address));

    /* Set destination port. */
    // first check for external MDP packet
    if (MdpIsExataIncomingPort(node,udpHdr->destPort))
    {
        MESSAGE_SetLayer(msg, APP_LAYER, APP_MDP);
    }
    else
    {
        MESSAGE_SetLayer(msg, APP_LAYER, udpHdr->destPort);
    }

    MESSAGE_SetEvent(msg, MSG_APP_FromTransport);
    MESSAGE_SetInstanceId(msg, 0);

    /* Update info field (used by application layer). */

    TosType priority = infoPtr->priority;
    MESSAGE_InfoAlloc(node, msg, sizeof(UdpToAppRecv));
    info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);

    info->priority = priority;
    memcpy(&(info->sourceAddr), &sourceAddress, sizeof(Address));
    info->sourcePort = udpHdr->sourcePort;
    memcpy(&(info->destAddr), &destinationAddress, sizeof(Address));
    info->destPort = udpHdr->destPort;
    info->incomingInterfaceIndex = incomingInterfaceIndex;

    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                     msg,
                     TRACE_TRANSPORT_LAYER,
                     PACKET_IN,
                     &acnData);

    if (udpLayer->udpStatsEnabled)
    {
        int type = STAT_AddressToDestAddressType(node, info->destAddr);
        udpLayer->newStats->AddSentToUpperLayerDataPoints(
            node,
            msg,
            info->sourceAddr,
            info->destAddr,
            info->sourcePort,
            info->destPort);
        udpLayer->newStats->AddSegmentReceivedDataPoints(
            node,
            msg,
            type,
            0,
            MESSAGE_ReturnPacketSize(msg) - sizeof(TransportUdpHeader),
            sizeof(TransportUdpHeader),
            info->sourceAddr,
            info->destAddr,
            info->sourcePort,
            info->destPort);
    }
    /* Remove UDP header. */
    MESSAGE_RemoveHeader(node, msg, sizeof(TransportUdpHeader), TRACE_UDP);

#ifdef ADDON_DB
    HandleTransportDBEvents(
        node,
        msg,
        info->incomingInterfaceIndex,          
        "UDPSendToUpper",        
        info->sourceAddr,
        info->destAddr,        
        info->sourcePort,
        info->destPort,  
        0);
#endif
    /* Send packet to application layer. */
    MESSAGE_Send(node, msg, TRANSPORT_DELAY);
}


/*
 * FUNCTION    TransportUdpSendToNetwork
 * PURPOSE     Send data down to the network layer.
 *
 * Parameters:
 *     node:      node sending the data down to network layer.
 *     msg:       data to be sent down to network layer.
 */
void
TransportUdpSendToNetwork(Node *node, Message *msg)
{
    TransportDataUdp *udp = (TransportDataUdp *) node->transportData.udp;
    TransportUdpHeader *udpHdr;
    AppToUdpSend *info;
    unsigned char protocol = IPPROTO_UDP;

    info = (AppToUdpSend *) MESSAGE_ReturnInfo(msg);
#ifdef ADDON_DB
    HandleTransportDBEvents(
        node,
        msg,
        info->outgoingInterface,          
        "UDPReceiveFromUpper",        
        info->sourceAddr,
        info->destAddr,
        info->sourcePort,
        info->destPort,   
        0);
#endif

    MESSAGE_AddHeader(node, msg, sizeof(TransportUdpHeader), TRACE_UDP);

    udpHdr = (TransportUdpHeader *) msg->packet;
    

    udpHdr->sourcePort = info->sourcePort;
    udpHdr->destPort = info->destPort;
    udpHdr->length = (unsigned short) MESSAGE_ReturnPacketSize(msg);
    udpHdr->checksum = 0;  /* checksum not calculated */

    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                     msg,
                     TRACE_TRANSPORT_LAYER,
                     PACKET_OUT,
                     &acnData);

#ifdef ADDON_DB
    // Here we add the packet to the Network database.
    // Gather as much information we can for the database.  
    HandleTransportDBEvents(
        node,
        msg,
        info->outgoingInterface,          
        "UDPSendToLower",        
        info->sourceAddr,
        info->destAddr,
        info->sourcePort,
        info->destPort,   
        sizeof(TransportUdpHeader));

#endif
#ifdef ADDON_BOEINGFCS
    if (msg->originatingProtocol == TRACE_HSLS)          
    {
        protocol = IPPROTO_CES_HSLS;
    }
#endif
    if (udp->udpStatsEnabled)
    {
        int type = STAT_AddressToDestAddressType(node, info->destAddr);
        udp->newStats->AddReceiveFromUpperLayerDataPoints(node, msg);
        udp->newStats->AddSegmentSentDataPoints(
            node,
            msg,
            0,
            MESSAGE_ReturnPacketSize(msg) - sizeof(TransportUdpHeader),
            sizeof(TransportUdpHeader),
            info->sourceAddr,
            info->destAddr,
            info->sourcePort,
            info->destPort);
    }
    NetworkIpReceivePacketFromTransportLayer(
        node,
        msg,
        info->sourceAddr,
        info->destAddr,
        info->outgoingInterface,
        info->priority,
        protocol,
        FALSE,
        info->ttl);
}


// /**
// FUNCTION   :: TransportUdpPrintTrace
// LAYER      :: TRANSPORT
// PURPOSE    :: Print out packet trace information
// PARAMETERS ::
// + node   : Node*    : Pointer to node, doing the packet trace
// + msg    : Message* : Pointer to packet to be printed
// RETURN ::  void : NULL
// **/

void TransportUdpPrintTrace(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    TransportUdpHeader* udpHdr = (TransportUdpHeader *)
                                 MESSAGE_ReturnPacket(msg);

    sprintf(buf, "<udp>%hu %hu %hu %hu</udp>",
        udpHdr->sourcePort,
        udpHdr->destPort,
        udpHdr->length,
        udpHdr->checksum);
    TRACE_WriteToBufferXML(node, buf);
}

/*
 * FUNCTION    Udp_HandleIcmpMessage
 * PURPOSE     Send the received ICMP Error Message to Application.
 * Parameters:
 *     node:      node sending the message to application layer
 *     msg:       message to be sent to application layer
 *     icmpType:  ICMP Message Type
  *    icmpCode:  ICMP Message Code
 */
void Udp_HandleIcmpMessage(Node *node,
                           Message *msg,
                           unsigned short icmpType,
                           unsigned short icmpCode)
{

    TransportUdpHeader* udpHeader = (TransportUdpHeader*)
                                            MESSAGE_ReturnPacket(msg);

    // Note: Below code should be uncommneted if the message is to be
    //passed to application layer through API App_HandleIcmpMessage

    //MESSAGE_ShrinkPacket(node, msg, sizeof(TransportUdpHeader));

    App_HandleIcmpMessage(node,
                          udpHeader->sourcePort,
                          udpHeader->destPort,
                          icmpType,
                          icmpCode);
}
