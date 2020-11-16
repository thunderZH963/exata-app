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

// This is an abstract model of a wormhole network.  The model can be viewed
// as a set of point-to-multipoint (wormhole node to wormhole nodes) links.
// Each wormhole network is group into a subnet.  Each wormhole subnet has
// many distributed wormhole nodes.  When a wormhole node receives data
// from the environment, it broadcasts the data to all other wormhole
// nodes in the subnet.
// Finally, this model does not consider collisions within the wormhole subnet.
// It is well known that many physical methods are available to connect a few
// points with very high bandwidth and nearly zero latency, for example,
// via wires, directional antenna and LOS links like laser beams.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "mac_wormhole.h"
#include "mac_dot11.h"
#include "mac_tdma.h"
#include "network_ip.h"
#include "application.h"

#ifdef ENTERPRISE_LIB
#include "mpls.h"
#endif //ENTERPRISE_LIB

#undef DEBUG
#define DEBUG  0

// Name: MacWormholeInit
// Purpose: Initialize wormhole
// Parameter: node, node calling this function.
//            nodeInput, configuration file access.
//            interfaceIndex, interface to initialize.
//            interfaceAddress, interface's address
//            subnetList, list of nodes in the subnet.
//            nodesInSubnet, number of nodes in the subnet.
//            macProtocolName, the eavesdropping/replaying MAC
// Return: void.

void
MacWormholeInit(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    NodeAddress interfaceAddress,
    SubnetMemberData* subnetList,
    int nodesInSubnet,
    char *macProtocolName)
{
    MacWormholeData *wormhole=NULL;
    BOOL wasFound;
    char inputString[MAX_STRING_LENGTH];

#ifdef PARALLEL //Parallel
    int i;
    for (i = 0; i < nodesInSubnet; i++)
    {
        if (subnetList[i].node == NULL)
        {
            ERROR_ReportError
                ("WORMHOLE networks cannot be split across partitions.");
        }
    }

    // Not supporting lookahead
    PARALLEL_SetProtocolIsNotEOTCapable(node);
    PARALLEL_SetMinimumLookaheadForInterface(node, 0);
#endif //endParallel
    node->macData[interfaceIndex]->macProtocol = MAC_PROTOCOL_WORMHOLE;
    node->macData[interfaceIndex]->isWormhole = TRUE;

    wormhole = (MacWormholeData *)MEM_malloc(sizeof(MacWormholeData));

    memset(wormhole, 0, sizeof(MacWormholeData));

    wormhole->myMacData = node->macData[interfaceIndex];
    wormhole->myMacData->macVar = (void *) wormhole;

    wormhole->mode = NETIA_WORMHOLE_THRESHOLD;

    wormhole->nodeList = subnetList;
    wormhole->numNodesInSubnet = nodesInSubnet;

    //wormhole->stats.packetsReceived = 0;
    //wormhole->stats.packetsReceivedWithoutRecursion = 0;
    //wormhole->stats.packetsReplayed = 0;
    //wormhole->stats.packetsDiscarded = 0;

    // set wormhole->bandwidth, which is the link bandwidth
    // of the wormhole tunnel link.  This value should be
    // higher than the victim network's link bandwidth.
    IO_ReadInt64(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-LINK-BANDWIDTH",
        &wasFound,
        &wormhole->bandwidth); // wormhole tunnel link's bandwidth

    if (!wasFound)
    {
        char errorStr[MAX_STRING_LENGTH];
        char addressStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(interfaceAddress, addressStr);
        sprintf(errorStr, "Unable to read \"WORMHOLE-LINK-BANDWIDTH\" for "
                "interface address %s", addressStr);

        ERROR_ReportError(errorStr);
    }
    ERROR_Assert(wormhole->bandwidth > 0 &&
                 wormhole->bandwidth <= 1000000000000000LL,
                 "Invalid value for WORMHOLE-LINK-BANDWIDTH. "
                 "Accepted values are between minimal value 1 and "
                 "maximal value 1000000000000000.");

    // set wormhole->propDelay
    IO_ReadTime(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-PROPAGATION-DELAY",
        &wasFound,
        &wormhole->propDelay);

    if (!wasFound)
    {
        wormhole->userSpecifiedPropDelay = FALSE;
        wormhole->propDelay = CLOCKTYPE_MAX;
    }
    else
    {
        wormhole->userSpecifiedPropDelay = TRUE;
        ERROR_Assert(wormhole->propDelay > 0 &&
                     wormhole->propDelay <= 1000000000000000LL,
                     "Invalid value for WORMHOLE-PROPAGATION-DELAY. "
                     "Accepted values are between minimal value 1 and "
                     "maximal value 1000000000000000.");
    }

    // Determines the needed WORMHOLE-MODE
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-MODE",
        &wasFound,
        inputString); // one of "THRESHOLD", "ALLPASS" and "ALLDROP"

    if (wasFound)
    {
        // Options
        // 1. THRESHOLD: drop all packets > WORMHOLE-THRESHOLD bytes
        // 2. ALLPASS: do not drop any packet
        // 3. ALLDROP: do drop any packet
        if (strcmp(inputString, "THRESHOLD") == 0)
        {
            wormhole->mode = NETIA_WORMHOLE_THRESHOLD;
            //printf("WORMHOLE mode: THRESHOLD %d\n", wormhole->threshold);
        }
        else if (strcmp(inputString, "ALLPASS") == 0)
        {
            wormhole->mode = NETIA_WORMHOLE_ALLPASS;
            //printf("WORMHOLE mode: ALLPASS\n");
        }
        else if (strcmp(inputString, "ALLDROP") == 0)
        {
            wormhole->mode = NETIA_WORMHOLE_ALLDROP;
            //printf("WORMHOLE mode: ALLDROP\n");
        }
        else
        {
            ERROR_Assert(FALSE, "Invalid WORMHOLE mode\n");
        }
    }
    else
    {
        ERROR_Assert(wasFound, "WORMHOLE needs to specify WORMHOLE-MODE\n");
    }

    // set wormhole->threshold, which is used in THRESHOLD mode
    IO_ReadInt(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-THRESHOLD",
        &wasFound,
        &wormhole->threshold);
    if (wasFound)
    {
        if (wormhole->mode != NETIA_WORMHOLE_THRESHOLD)
        {
            ERROR_ReportError(
                "WORMHOLE-MODE and THRESHOLD PARAMETER mismatch. "
                "Please do not set THRESHOLD.");
        }
    }
    else
    {
        if (wormhole->mode == NETIA_WORMHOLE_ALLDROP)
        {
            wormhole->threshold = 0;    // packet size > 0, then drop
        }
        else
        {
            wormhole->threshold = WORMHOLE_DEFAULT_THRESHOLD;
        }
    }
    ERROR_Assert(wormhole->threshold >= 0 && wormhole->threshold <= 2147483647,
                 "Invalid value for WORMHOLE-THRESHOLD. "
                 "Accepted values are between minimal value 0 and "
                 "maximal value 2147483647.");

    // Once the replay end receives a tunneled packet from the other end,
    // it must use a replay MAC protocol to resend the packet.
    // Currently only a CSMA style replay MAC is supported.
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-REPLAY-MAC-PROTOCOL",
        &wasFound,
        macProtocolName);

    if (!wasFound)
    {
        ERROR_Assert(
            wasFound,
            "WORMHOLE needs to specify WORMHOLE-REPLAY-MAC-PROTOCOL\n");
    }
    // More types of replay MAC feasible in the future following research
    ERROR_Assert(strcmp(macProtocolName, "WORMHOLE-CSMA")==0,
                 "Incorrect WORMHOLE-REPLAY-MAC-PROTOCOL");

#if 0
    // This is for future use.
    // In the future, wormhole attack needs more optimization
    // against different victim MAC protocols
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WORMHOLE-VICTIM-MAC-PROTOCOL",
        &wasFound,
        macProtocolName);

    if (!wasFound) {
        wormhole->victimMacProtocol = MAC_PROTOCOL_802_11;
    }
    else {
        if (strcmp(macProtocolName, "MAC802.11") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_802_11;
        }
        else if (strcmp(macProtocolName, "CSMA") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_CSMA;
        }
        else if (strcmp(macProtocolName, "MACA") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_MACA;
        }
        else if (strcmp(macProtocolName, "TDMA") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_TDMA;
        }
        else if (strcmp(macProtocolName, "ALOHA") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_ALOHA;
        }
        else if (strcmp(macProtocolName, "MACDOT11") == 0 ||
                 strcmp(macProtocolName, "MACDOT11e") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_DOT11;
        }
#ifdef ADDON_DOT16
        else if (strcmp(macProtocolName, "MAC802.16") == 0 ||
                 strcmp(macProtocolName, "MAC802.16e") == 0) {
            wormhole->victimMacProtocol = MAC_PROTOCOL_DOT16;
        }
#endif // ADDON_DOT16
        else {
            char errorMessage[MAX_STRING_LENGTH];

            sprintf(errorMessage, "Unknown MAC protocol %s\n",
                    macProtocolName);
            ERROR_ReportError(errorMessage);

            //MAC_InitUserMacProtocol(
            //    node, nodeInput,
            //    macProtocolName,
            //    interfaceIndex);
        }//if//
    }
#endif

    //
    // The following code is for replaying
    //
    wormhole->timer.flag =
        WORMHOLEREPLAY_TIMER_OFF | WORMHOLEREPLAY_TIMER_UNDEFINED;
    wormhole->timer.seq = 0;

    wormhole->status = NETIA_WORMHOLEREPLAY_STATUS_PASSIVE;
    wormhole->BOmin = WORMHOLEREPLAY_BO_MIN;
    wormhole->BOmax = WORMHOLEREPLAY_BO_MAX;

    // The followings were redundant because of the previous memset to 0
    //wormhole->BOtimes = 0;
    //wormhole->firstInBuffer = 0;
    //wormhole->lastInBuffer = 0;
    //wormhole->numInBuffer = 0;

    RANDOM_SetSeed(wormhole->seed,
                   node->globalSeed,
                   node->nodeId,
                   MAC_PROTOCOL_WORMHOLE,
                   interfaceIndex);
}

// Name: MacWormholePrintStats
// Purpose: Print out stats for a particular interface.
// Parameter: node, node calling this function.
//            wormhole, WORMHOLE data structure.
//            interfaceIndex, interface associated with the stats.
// Return: None.

static
void MacWormholePrintStats(
    Node *node,
    MacWormholeData *wormhole,
    int interfaceIndex)
{
    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "Frames intercepted all = %d",
            wormhole->stats.packetsReceived);
    IO_PrintStat(node, "MAC", "Wormhole", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames dropped by wormhole = %d",
            wormhole->stats.packetsDropped);
    IO_PrintStat(node, "MAC", "Wormhole", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames tunneled = %d",
            wormhole->stats.packetsReceivedWithoutRecursion);
    IO_PrintStat(node, "MAC", "Wormhole", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames replayed = %d", wormhole->stats.packetsReplayed);
    IO_PrintStat(node, "MAC", "Wormhole", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames dropped by queue = %d",
            wormhole->stats.packetsDiscarded);
    IO_PrintStat(node, "MAC", "Wormhole", ANY_DEST, interfaceIndex, buf);
}



// Name: MacWormholeFinalize
// Purpose: Handle any finalization tasks.
// Parameter: node, node calling this function.
//            interfaceIndex, interface associated with the
//                            finalization tasks.
// Return: None.

void MacWormholeFinalize(Node *node, int interfaceIndex)
{
    MacData* macInterface = node->macData[interfaceIndex];
    if (macInterface->macStats == TRUE)
    {
        MacWormholePrintStats(
            node,
            (MacWormholeData *) node->macData[interfaceIndex]->macVar,
            interfaceIndex);
    }
    MEM_free(macInterface->macVar); // free the MacWormholeData
}


// Name: MacWormholeTunnelSend
// Purpose: Relay a frame from one wormhole node to another.
// Parameter: sourceNode, source wormhole node to relay frame from.
//            destNode, destination wormhole node to relay frame to.
//            interfaceIndex, interface to use to relay frame.
//            msgToSend, frame to relay to wormhole node.
// Return: None.

static
void MacWormholeTunnelSend(Node *sourceNode,
                           Node *destNode,
                           int interfaceIndex,
                           Message *msgToSend)
{
    MacWormholeData *wormhole=NULL;
    clocktype propDelay=0; // propagation delay of the wormhole tunnel link

    wormhole = (MacWormholeData*)destNode->macData[interfaceIndex]->macVar;

    // Though a wormhole is defined as a high-speed large-bandwidth link,
    // it cannot beat the physical law to exceed the speed of light.
    // We need to calculate its propagation delay if user hasn't specified one.
    if (wormhole->userSpecifiedPropDelay) {
        propDelay = wormhole->propDelay;
    }
    else
    {
        // If user doesn't specify propagation delay,
        // calculate it from sender's position and receiver's position.
        // Propagation delay = distance / signal propagation speed.
        Coordinates fromPosition;
        Coordinates toPosition;
        double distance;

        MOBILITY_ReturnCoordinates(sourceNode, &fromPosition);
        MOBILITY_ReturnCoordinates(destNode, &toPosition);

           COORD_CalcDistance(
            NODE_GetTerrainPtr(sourceNode)->getCoordinateSystem(),
               &fromPosition, &toPosition, &distance);

        propDelay = PROP_CalculatePropagationDelay(
                        distance,
                        SPEED_OF_LIGHT,
                        sourceNode->partitionData,
                        -1,
                        NODE_GetTerrainPtr(sourceNode)->getCoordinateSystem(),
                        &fromPosition,
                        &toPosition);
    }

    // Send to the specified wormhole terminal "destNode"
    MESSAGE_SetEvent(msgToSend, MSG_MAC_LinkToLink);
    MESSAGE_SetLayer(msgToSend, MAC_LAYER, 0);
    MESSAGE_SetInstanceId(msgToSend, (short)interfaceIndex);
    clocktype txDelay = (clocktype)
        (MESSAGE_ReturnPacketSize(msgToSend) * 8 * SECOND
         / wormhole->bandwidth);
    MESSAGE_Send(destNode, msgToSend, propDelay+txDelay);

    if (DEBUG)
    {
        printf("\tMacWormholeTunnelSend (to %d/%x)\n", destNode->nodeId,
               NetworkIpGetLinkLayerAddress(destNode, interfaceIndex));
    }
}


// Name: MacWormholeTunnelBroadcast
// Purpose: Broadcast the frame to the wormhole nodes (via relay).
// Parameter: node, wormhole node.
//        wormhole, WORMHOLE data structure.
//        fromAddr, wormhole node received frame from.
//        msgToSend, frame to relay to wormhole node (other than source node).
// Return: None.

static
void MacWormholeTunnelBroadcast(
    Node *node,
    MacWormholeData *wormhole,
    NodeAddress fromAddr,
    Message *msgToSend)
{
    int i=0;

    if (DEBUG)
    {
        printf("#%d: MacWormholeTunnelBroadcast(%d nodes)\n",
               node->nodeId, wormhole->numNodesInSubnet);
    }

//GuiStart
    if (node->guiOption == TRUE)
    {
        GUI_Broadcast(node->nodeId,
                      GUI_MAC_LAYER,
                      GUI_DEFAULT_DATA_TYPE,
                      wormhole->myMacData->interfaceIndex,
                      node->getNodeTime());
    }
//GuiEnd

    // Broadcast to all other wormhole nodes except for the wormhole node that
    // originated the frame.
    for (i = 0; i < wormhole->numNodesInSubnet; i++)
    {
       int interfaceIndex = wormhole->nodeList[i].interfaceIndex;
       Node* tempNode = wormhole->nodeList[i].node;

       NodeAddress tempaddr = MAC_VariableHWAddressToFourByteMacAddress(
                              tempNode,
                              &tempNode->macData[interfaceIndex]->macHWAddr);
        if (wormhole->nodeList[i].node->nodeId != node->nodeId &&
            tempaddr != fromAddr)
        {
            if (DEBUG)
            {
                printf("Wormhole node %u mac sends (control) packet of "
                       "size %u to node %u\n",
                       node->nodeId,
                       MESSAGE_ReturnPacketSize(msgToSend),
                       wormhole->nodeList[i].node->nodeId);
            }
            MacWormholeTunnelSend(node,
                                  wormhole->nodeList[i].node,
                                  wormhole->nodeList[i].interfaceIndex,
                                  MESSAGE_Duplicate(node, msgToSend));
        }
    }
}

// Name: MacWormholePrintPacket
// Purpose: Print the packet contents for debug purpose
// Parameter: node, the wormhole starting end.
//            interfaceIndex, interface received frame from.
//            msg, frame intercepted
// Return: None.

static void
wormholePrintPacket(Node *node, int interfaceIndex, Message *msg)
{
    MacData *thisMac = node->macData[interfaceIndex];
    MacWormholeData *wormhole = (MacWormholeData *)thisMac->macVar;
    char *packet = MESSAGE_ReturnPacket(msg);
    IpHeaderType *ipHeader=NULL;

    switch(wormhole->victimMacProtocol)
    {
        case MAC_PROTOCOL_CSMA:
        case MAC_PROTOCOL_802_11:
        case MAC_PROTOCOL_DOT11: {
            DOT11_FrameHdr *macHdr = (DOT11_FrameHdr *)packet;

            if (DEBUG)
            {
                char sourceAddr[24],destAddr[24],address3[24];
                MacDot11MacAddressToStr(sourceAddr, &macHdr->sourceAddr);
                MacDot11MacAddressToStr(destAddr, &macHdr->destAddr);
                MacDot11MacAddressToStr(address3, &macHdr->address3);
                printf("MAC header: frameType = 0x%02X, "
                       "frameFlags = 0x%02X (0x80 to DS, 0x40 from DS)\n\t"
                       // "padding = %02X%02X, duration = %u\n\t"
                       "SOURCE = %s, DEST = %s, address3 = %s\n"
                       ,
                       macHdr->frameType,
                       macHdr->frameFlags,
                       sourceAddr,
                       destAddr,
                       address3
                       );
            }

            ipHeader = (IpHeaderType *)(packet + DOT11_DATA_FRAME_HDR_SIZE);

            if (DEBUG && macHdr->frameType == DOT11_DATA)
            {
                printf("IP header: version = %u, header length = %u\n"
                       "\tToS = %u, total length = %u\n\t"
                       "TTL = %u, Protocol = %u, Checksum = 0x%X\n"
                       "\tSOURCE = 0x%08X, DEST = 0x%08X\n\n",
                       IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len),
                       ipHeader->ip_ttl,
                       ipHeader->ip_p,
                       ipHeader->ip_sum,
                       ipHeader->ip_src, ipHeader->ip_dst);
            }
            break;
        }
        case MAC_PROTOCOL_TDMA: {
            TdmaHeader *macHdr = (TdmaHeader *)packet;

            if (DEBUG)
            {
                printf("MAC header: SOURCE = ");
                MAC_PrintMacAddr(&macHdr->sourceAddr);
                printf(" DEST = ");
                MAC_PrintMacAddr(&macHdr->destAddr);
                printf("priority = %08X\n",macHdr->priority);
            }

            ipHeader = (IpHeaderType *)(packet + sizeof(TdmaHeader));

            if (DEBUG && (IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len) == 4))
            {
                printf("IP header: version = %u, header length = %u\n"
                       "\tToS = %u, total length = %u\n\t"
                       "TTL = %u, Protocol = %u, Checksum = 0x%X\n"
                       "\tSOURCE = 0x%08X, DEST = 0x%08X\n\n",
                       IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
                       IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len),
                       ipHeader->ip_ttl,
                       ipHeader->ip_p,
                       ipHeader->ip_sum,
                       ipHeader->ip_src, ipHeader->ip_dst
                       );
            }
            break;
        }
        default:
            break;
    }
}

// Name: MacWormholeTunneling
// Purpose: Add header and invoke tunnel broadcast
// Parameter: node, wormhole node.
//        wormhole, WORMHOLE data structure.
//        newMsg, frame to relay to wormhole node (other than source node).
// Return: None.

static void
MacWormholeTunneling(Node *node,
                     MacWormholeData *wormhole,
                     Message *newMsg)
{
    MacWormholeFrameHeader header;
    MacData *thisMac = wormhole->myMacData;
    int interfaceIndex = thisMac->interfaceIndex;

    if (MESSAGE_ReturnPacketSize(newMsg) > wormhole->threshold)
    {
        // If packet size is longer than the threhold,
        // the wormhole guesses this is a data packet, drop it.
        if (wormhole->mode != NETIA_WORMHOLE_ALLPASS)
        {
            if (DEBUG)
            {
                printf("Wormhole node %u mac drops (data) packet "
                       "with size %u\n",
                       node->nodeId, MESSAGE_ReturnPacketSize(newMsg));
            }
            wormhole->stats.packetsDropped++;
            return;
        }
        else
        {
            if (DEBUG)
            {
                printf("Wormhole node %u mac passes (data) packet "
                       "with size %u\n",
                       node->nodeId, MESSAGE_ReturnPacketSize(newMsg));
                wormholePrintPacket(node, interfaceIndex, newMsg);
            }
        }
    }
    else
    {
        // Otherwise, the wormhole guesses this is a control packet,
        // let the packet go through
        if (DEBUG)
        {
            printf("Wormhole node %u mac passes (control) packet "
                   "with size %u\n",
                   node->nodeId, MESSAGE_ReturnPacketSize(newMsg));
            wormholePrintPacket(node, interfaceIndex, newMsg);
        }
    }

    MESSAGE_AddHeader(node,
                      newMsg,
                      sizeof(MacWormholeFrameHeader),
                      TRACE_WORMHOLE);

    memset(&header,0,sizeof(MacWormholeFrameHeader));
    

    header.sourceAddr =
            MAC_VariableHWAddressToFourByteMacAddress(
                                  node,
                                  &node->macData[interfaceIndex]->macHWAddr);

    header.destAddr = ANY_DEST;

    memcpy(MESSAGE_ReturnPacket(newMsg),&header,
            sizeof(MacWormholeFrameHeader));
    // Forward to all other wormhole nodes
 

    MacWormholeTunnelBroadcast(
        node,
        wormhole,
        header.sourceAddr,
        newMsg);
}


#undef PARTICIPANT
// Caveats: PARTICIPANT mode means the wormhole node is an insider.
//      Compared to TRANSPARENT mode where the wormhole node is an
//      outsider, this insider case is unlikely true.
//      More importantly, this offers no advantage in regard to
//      wormhole attack in a network with non-uniform packet size
//      (though insiders can always distinguish control packets from
//       data packets in any network, including those networks using
//       a uniform packet size)
//      Thus in this implementation, only TRANSPARENT mode is realized.
//      We will implement PARTICIPANT mode for networks with uniform packet
//      (i.e., all packets are of the same size and encrypted).
#ifdef PARTICIPANT
// Name: MacWormholeNetworkLayerHasPacketToSend
// Purpose: Wormhole node has packets to send.
// Parameter: node, wormhole node.
//            wormhole, WORMHOLE data structure.
// Return: None.
void MacWormholeNetworkLayerHasPacketToSend(
    Node *node,
    MacWormholeData *wormhole)
{
    Message *newMsg = NULL;
    NodeAddress nextHopAddress = 0;
    int networkType = 0;
    TosType priority = 0;
    MacData *thisMac = wormhole->myMacData;
    int interfaceIndex = thisMac->interfaceIndex;

    MAC_OutputQueueDequeuePacket(node,
                                 interfaceIndex,
                                 &newMsg,
                                 &nextHopAddress,
                                 &networkType,
                                 &priority);

    assert(newMsg != NULL);
    wormhole->stats.packetsReceived++;
    MacWormholeTunneling(node, wormhole, newMsg); // tunnel the packet
}
#endif // PARTICIPANT

// Name: MacWormholeReceivePacketFromPhy
// Purpose: A wormhole terminal just picked up a packet from PHY layer
// Parameter: node, node calling this function.
//            wormhole, wormhole data structure.
//            msg, frame or timer.
// Return: None.

void MacWormholeReceivePacketFromPhy(Node* node,
                                     MacWormholeData* wormhole,
                                     Message* msg)
{
    // In emulation, to distinguish each packet, we do packet content match
    // char *packet = MESSAGE_ReturnPacket(msg);

    // But in simulation, to distinguish each packet, we do
    // packet originatingNodeId & sequenceNumber match,
    // as packet content match is infeasible.

    wormhole->stats.packetsReceived++;
    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Wormhole node %d at time (%s): "
               "intercepted a packet originated from node %d "
               "at creation time %15" TYPES_64BITFMT "d.\n",
               node->nodeId, clockStr, msg->originatingNodeId,
               msg->packetCreationTime);
    }

    // Packets received by me, and tunneled to other wormhole terminals.
    // However, for single-hop wormholes, a tunneled packet will be replayed
    // by other terminals and received by me again.
    // If I keep wormholing the packet, the recursive effect will cause
    // exponentially increasing communication events (a packet storm).
    // Thus a recursion-blocking buffer is implemented: most recently
    // tunneled packets are recorded.  If an intercepted packet is found
    // in the buffer, it is discarded rather than tunneled.
    if (wormhole->numInBuffer != 0)
    {
        unsigned int i=0;

        for (i = wormhole->firstInBuffer;
            i != wormhole->lastInBuffer;
            i = (i+1) % WORMHOLE_BUFFER_SIZE)
        {
            // At the intercepting end (the sending/tunnel beginning end),
            // do string comparison to see if the intercepted packet
            // is in my already-sent record.

            // The commented-out part is only feasible in emulation.
            //if (memcmp(wormhole->justTunneled[i],
            //packet,
            //WORMHOLE_INSPECT_BYTES) == 0)
            if (memcmp(wormhole->justTunneled[i],
                       &msg->originatingNodeId,
                       sizeof(NodeAddress)) == 0 &&
                memcmp(wormhole->justTunneled[i]+sizeof(NodeAddress),
                       &msg->sequenceNumber,
                       sizeof(int)) == 0)
            {
                // If yes, I already tunneled this packet recently,
                // and now it comes back to me again.  This is perhaps
                // because my wormhole partners are within 1-hop distance of
                // me, so discard the packet.
                if (DEBUG)
                {
                    char clockStr[20];
                    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                    printf("Wormhole node %d at time (%s): "
                           "Discard a packet tunneled before (originated "
                           "from node %d at creation time %15" 
                            TYPES_64BITFMT "d).\n",
                           node->nodeId, clockStr, msg->originatingNodeId,
                           msg->packetCreationTime);
                }
                return;
            }
        }
    }

    wormhole->stats.packetsReceivedWithoutRecursion++;

    wormhole->numInBuffer++;
    // The commented-out part is only feasible in emulation.
    //memcpy(wormhole->justTunneled[wormhole->lastInBuffer],
    //packet,
    //WORMHOLE_INSPECT_BYTES);
    memcpy(wormhole->justTunneled[wormhole->lastInBuffer],
           &msg->originatingNodeId,
           sizeof(NodeAddress));
    memcpy(wormhole->justTunneled[wormhole->lastInBuffer]+sizeof(NodeAddress),
           &msg->sequenceNumber,
           sizeof(int));
    wormhole->lastInBuffer =
        (wormhole->lastInBuffer+1) % WORMHOLE_BUFFER_SIZE;
    if (wormhole->firstInBuffer == wormhole->lastInBuffer)
    {
        // Buffer reaches the maximal capacity, stay in the full status
        wormhole->firstInBuffer =
            (wormhole->firstInBuffer+1) % WORMHOLE_BUFFER_SIZE;
        wormhole->numInBuffer--;
    }

    // Tunnel the packet to other wormhole terminals
    MacWormholeTunneling(node, wormhole, msg);
}

//
// Replay section
//

// Name: PhyStatus
// Purpose: PHY_GetStatus for the wormhole replay interface
// Parameter: node, node calling this function.
//            wormholeReplay, wormhole data structure.
// Return: the phy status.

static /*inline*/
PhyStatusType PhyStatus(Node* node, MacWormholeData* wormholeReplay)
{
    return PHY_GetStatus(node, wormholeReplay->myMacData->phyNumber);
}


/*
 * NAME:        MacWormholeReplayDataXmit.
 *
 * PURPOSE:     Sending data frames to destination.
 *
 * PARAMETERS:  node, node sending the data frame.
 *              wormholeReplay, wormhole data structure.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static
void MacWormholeReplayXmit(Node *node, MacWormholeData *wormholeReplay)
{
    Message *msg=NULL;
    TosType priority=0;

    assert(wormholeReplay->status == NETIA_WORMHOLEREPLAY_STATUS_XMIT);

    /*
     * Dequeue packet which was received from the
     * network layer.
     */
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    Scheduler *scheduler =
        ip->interfaceInfo[wormholeReplay->myMacData->interfaceIndex]
        ->scheduler;

    (*scheduler).retrieve(ALL_PRIORITIES, DEQUEUE_NEXT_PACKET, &msg,
                          &priority, DEQUEUE_PACKET, node->getNodeTime());

    if (msg == NULL)
    {
        ERROR_ReportError("WORMHOLEREPLAY: Queue should not be empty...\n");
    }

    wormholeReplay->status = NETIA_WORMHOLEREPLAY_STATUS_IN_XMITING;
    wormholeReplay->timer.flag =
        WORMHOLEREPLAY_TIMER_OFF | WORMHOLEREPLAY_TIMER_UNDEFINED;

    PHY_StartTransmittingSignal(
        node, wormholeReplay->myMacData->phyNumber,
        msg, FALSE, 0);

    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Wormhole node %d (time %s) replayed a packet of size %d "
               "originated from node %d at time %15" TYPES_64BITFMT "d\n",
               node->nodeId, clockStr, MESSAGE_ReturnPacketSize(msg),
               msg->originatingNodeId, msg->packetCreationTime);
    }
}


// Name: MacWormholeReplayFrame
// Purpose: Wormhole recipient nodes handling frame sent from sender.
// Parameter: node, the recipient wormhole node.
//            interfaceIndex, interface received frame from.
//            msg, frame received for replay.
// Return: None.

void
MacWormholeReplayFrame(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    MacData *macData = node->macData[interfaceIndex];
    MacWormholeData* wormhole = (MacWormholeData *)macData->macVar;

    MacWormholeFrameHeader header;
    memset(&header,0,sizeof(MacWormholeFrameHeader));
    memcpy(&header,MESSAGE_ReturnPacket(msg),sizeof(MacWormholeFrameHeader));
  

    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Wormhole node %d at time (%s): "
               "received a %x-tunneled packet of size %d "
               "originated from node %d at creation time %15" 
               TYPES_64BITFMT "d.\n",
               node->nodeId, clockStr, header.sourceAddr,
               MESSAGE_ReturnPacketSize(msg),
               msg->originatingNodeId, msg->packetCreationTime);
    }

    if (MAC_IsMyUnicastFrame(node, header.destAddr) ||
        header.destAddr == ANY_DEST)

    {
        // Actually in current wormhole implementation, ReplayFrame() only
        // receives the packets that are going to be replayed for sure.
        // Thus it's 100% to be here.
        MESSAGE_RemoveHeader(node,
                             msg,
                             sizeof(MacWormholeFrameHeader),
                             TRACE_WORMHOLE);

        // Multiple interfaces/channels:
        // Using WORMHOLEREPLAY protocol to replay the frame
        // in every WORMHOLE interface.
        for (interfaceIndex = 0;
            interfaceIndex < node->numberInterfaces &&
                node->macData[interfaceIndex]->isWormhole == TRUE;
            interfaceIndex++)
        {
            BOOL queueWasEmpty =
                NetworkIpOutputQueueIsEmpty(node, interfaceIndex);
            BOOL queueIsFull;
            Message* newmsg = MESSAGE_Duplicate(node, msg);

            // put into the interface's forwarding queue
            NetworkDataIp *ip = (NetworkDataIp *)
                node->networkData.networkVar;
            Scheduler *scheduler =
                ip->interfaceInfo[interfaceIndex]->scheduler;
            (*scheduler).insert(newmsg,
                                &queueIsFull,
                                0,
                                NULL, //const void* infoField,
                                node->getNodeTime());

            if (queueIsFull)
            {
                // Increment stat for number of to-be-replayed packets
                // discarded because of a lack of buffer space.
                wormhole->stats.packetsDiscarded++;
                MESSAGE_Free(node, newmsg);
                MESSAGE_Free(node, msg);
                return;
            }

            if (queueWasEmpty)
            {
#if 0
                if (MESSAGE_ReturnPacketSize(msg) <= WORMHOLE_DIRECT_THRESHOLD &&
                    wormhole->status == NETIA_WORMHOLEREPLAY_STATUS_PASSIVE)
                {
                    // Very short packets, e.g., 802.11 ACK packets,
                    // should be directly replayed immediately
                    wormhole->status = NETIA_WORMHOLEREPLAY_STATUS_XMIT;
                    MacWormholeReplayXmit(node, wormhole);
                }
                else
#endif
                    if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex))
                    {
                        MacWormholeReplayHasPacketToSend(
                            node,
                            (MacWormholeData *)
                            node->macData[interfaceIndex]->macVar);

                    }
            }
        }
        MESSAGE_Free(node, msg);

        wormhole->stats.packetsReplayed++;
    }
    else
    {
        // Actually in current wormhole implementation, ReplayFrame() only
        // receives the packets that are going to be replayed for sure.
        // Thus it's impossible to be here.
        MESSAGE_Free(node, msg);
    }
}

// Name: MacWormholeReplayTransmissionFinished
// Purpose: Wormhole node finished transmitting.
//          (for simulating transmission delay)
// Parameter: node, wormhole node.
//            interfaceIndex, interface used to sent last frame.
//            msg, timer telling us that the transmission is done.
// Return: None.
void MacWormholeReplayTransmissionFinished(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    MacWormholeData *wormhole =
        (MacWormholeData *)node->macData[interfaceIndex]->macVar;

    assert(wormhole != NULL);

    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Wormhole node %d at time (%s): "
               "finished transmitting a packet originated from node %d "
               "at creation time %15" TYPES_64BITFMT "d.\n",
               node->nodeId, clockStr,
               msg->originatingNodeId, msg->packetCreationTime);
    }

    if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE)
    {
        if (DEBUG)
        {
            printf("    there's more packets in the queue, "
                   "so try to send the next packet\n");
        }
        MacWormholeReplayHasPacketToSend(node, wormhole);
    }
    MESSAGE_Free(node, msg);
}


/*
 * NAME:        MacWormholeReplaySetTimer.
 *
 * PURPOSE:     Set a timer for node to expire at time timerValue.
 *
 * PARAMETERS:  node, node setting the timer.
 *              wormholeReplay, wormhole data structure.
 *              timerType, what type of timer is being set.
 *              delay, when timer is to expire.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static
void MacWormholeReplaySetTimer(Node *node,
                               MacWormholeData* wormholeReplay,
                               int timerType,
                               clocktype delay)
{
    Message      *newMsg=NULL;
    int         *timerSeq=NULL;

    if (delay == 0)
    {
        return;
    }
    wormholeReplay->timer.flag =
        (unsigned char)(WORMHOLEREPLAY_TIMER_ON | timerType);
    wormholeReplay->timer.seq++;

    assert((timerType == WORMHOLEREPLAY_TIMER_BACKOFF) ||
           (timerType == WORMHOLEREPLAY_TIMER_YIELD));

    newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0,
                           MSG_MAC_TimerExpired);
    MESSAGE_SetInstanceId(newMsg,
                          (short)wormholeReplay->myMacData->interfaceIndex);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(wormholeReplay->timer.seq));
    timerSeq  = (int *) MESSAGE_ReturnInfo(newMsg);
    *timerSeq = wormholeReplay->timer.seq;

    MESSAGE_Send(node, newMsg, delay); // CSMA delays
}


/*
 * NAME:        MacWormholeReplayYield.
 *
 * PURPOSE:     Yield so neighboring nodes can transmit or receive.
 *
 * PARAMETERS:  node, node that is yielding.
 *              wormholeReplay, wormhole data structure.
 *              holding, how int to yield for in CSMA.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static
void MacWormholeReplayYield(Node *node,
                            MacWormholeData *wormholeReplay,
                            clocktype holding)
{
    assert(wormholeReplay->status == NETIA_WORMHOLEREPLAY_STATUS_YIELD);
    MacWormholeReplaySetTimer(node,
                              wormholeReplay,
                              WORMHOLEREPLAY_TIMER_YIELD,
                              holding);
}


/*
 * NAME:        MacWormholeReplayBackoff.
 *
 * PURPOSE:     Backing off sending data at a later time.
 *
 * PARAMETERS:  node, node that is backing off.
 *              wormholeReplay, wormhole data structure.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static
void MacWormholeReplayBackoff(Node *node, MacWormholeData *wormhole)
{
    clocktype randTime=0;
    assert(wormhole->status == NETIA_WORMHOLEREPLAY_STATUS_BACKOFF);

    randTime = (RANDOM_nrand(wormhole->seed) % wormhole->BOmin)
        + DOT11_802_11a_SLOT_TIME;
    wormhole->BOmin = wormhole->BOmin * 2;

    if (wormhole->BOmin > wormhole->BOmax) {
        wormhole->BOmin = wormhole->BOmax;
    } // see CSMA code MacCsmaBackoff()

    wormhole->BOtimes++;
    MacWormholeReplaySetTimer(node,
                              wormhole,
                              WORMHOLEREPLAY_TIMER_BACKOFF,
                              randTime);
}


/*
 * NAME:        CheckPhyStatusAndSendOrBackoff
 *
 * PURPOSE:     Based on checked physical status, send the replay packet
 *              or backoff.
 *
 * PARAMETERS:  node, node that is in passive state.
 *              wormholeReplay, wormhole data structure.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static //inline//
void CheckPhyStatusAndSendOrBackoff(Node* node,
                                    MacWormholeData* wormholeReplay)
{
    /* Carrier sense response from phy. */

    if ((PhyStatus(node, wormholeReplay) == PHY_IDLE) &&
        (wormholeReplay->status != NETIA_WORMHOLEREPLAY_STATUS_IN_XMITING))
    {
        if (DEBUG)
        {
            char clockStr[20];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("Wormhole node %d transmits at time %s\n",
                   node->nodeId, clockStr);
        }
        wormholeReplay->status = NETIA_WORMHOLEREPLAY_STATUS_XMIT;
        MacWormholeReplayXmit(node, wormholeReplay);
    }
    else {
        if (!MAC_OutputQueueIsEmpty(
                node, wormholeReplay->myMacData->interfaceIndex))
        {
            if (DEBUG)
            {
                char clockStr[20];
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Wormhole node %d backoff at time %s\n",
                       node->nodeId, clockStr);
            }
            wormholeReplay->status = NETIA_WORMHOLEREPLAY_STATUS_BACKOFF;
            MacWormholeReplayBackoff(node, wormholeReplay);
        }
    }
}



/*
 * NAME:        MacWormholeReplayHasPacketToSend.
 *
 * PURPOSE:     In passive mode, start process to send data; else return;
 *
 * PARAMETERS:  node, node that is in passive state.
 *              wormholeReplay, wormhole data structure.
 *
 * RETURN:      None.
 *
 */

void MacWormholeReplayHasPacketToSend(
    Node *node,
    MacWormholeData *wormholeReplay)
{
    if (wormholeReplay->status == NETIA_WORMHOLEREPLAY_STATUS_PASSIVE)
    {
#undef WORMHOLE_DIRECT_REPLAY
#ifdef WORMHOLE_DIRECT_REPLAY
        wormholeReplay->status = NETIA_WORMHOLEREPLAY_STATUS_XMIT;
        MacWormholeReplayXmit(node, wormholeReplay);
#else // WORMHOLE_DIRECT_REPLAY
        CheckPhyStatusAndSendOrBackoff(node, wormholeReplay);
#endif // WORMHOLE_DIRECT_REPLAY
    } // see MacCsmaNetworkLayerHasPacketToSend()
}




/*
 * NAME:        MacWormholeReplayPassive.
 *
 * PURPOSE:     In passive mode, check whether there is a local packet.
 *              If YES, send data; else return;
 *
 * PARAMETERS:  node, node that is in passive state.
 *              wormholeReplay, wormhole data structure.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  node != NULL.
 */

static
void MacWormholeReplayPassive(Node *node, MacWormholeData *wormholeReplay)
{
    if ((wormholeReplay->status == NETIA_WORMHOLEREPLAY_STATUS_PASSIVE) &&
        (!MAC_OutputQueueIsEmpty(
             node,
             wormholeReplay->myMacData->interfaceIndex)))
    {
        MacWormholeReplayHasPacketToSend(node, wormholeReplay);
    } // see MacCsmaPassive()

}

// Name: MacWormholeReplayReceivePacketFromPhy
// Purpose: Do nothing. Only for protocol implementation conformation.
// Parameter: None.
// Return: None.

void MacWormholeReplayReceivePacketFromPhy(
    Node *node, MacWormholeData *wormhole, Message *msg)
{
    switch (wormhole->status)
    {
        case NETIA_WORMHOLEREPLAY_STATUS_PASSIVE:
        case NETIA_WORMHOLEREPLAY_STATUS_CARRIER_SENSE:
        case NETIA_WORMHOLEREPLAY_STATUS_BACKOFF:
        case NETIA_WORMHOLEREPLAY_STATUS_XMIT:
        case NETIA_WORMHOLEREPLAY_STATUS_IN_XMITING:
        case NETIA_WORMHOLEREPLAY_STATUS_YIELD:
        {
            MESSAGE_Free(node, msg);
            return;
        }
        default:
            ERROR_ReportError("Invalid replaying status.\n");
    }
}


// Name: MacWormholeReplayReceivePhyStatusChangeNotification
// Purpose: React to change in physical status of wormhole replay interface.
// Parameter: node, node that is handling the frame or timer.
//            wormholeReplay, wormhole data structure.
//            oldPhyStatus, physical status before the change.
//            newPhyStatus, physical status after the change.
// Return: None.

void MacWormholeReplayReceivePhyStatusChangeNotification(
    Node* node,
    MacWormholeData* wormholeReplay,
    PhyStatusType oldPhyStatus,
    PhyStatusType newPhyStatus)
{
#ifdef WORMHOLE_DIRECT_REPLAY
    // do nothing as the MAC is deactivated
    return;
#else // WORMHOLE_DIRECT_REPLAY
    // CSMA style reaction to PhyStatus Change
    if (oldPhyStatus == PHY_TRANSMITTING)
    {
        assert(newPhyStatus != PHY_TRANSMITTING);
        assert(wormholeReplay->status ==
               NETIA_WORMHOLEREPLAY_STATUS_IN_XMITING);

        wormholeReplay->BOmin = WORMHOLEREPLAY_BO_MIN;
        wormholeReplay->BOmax = WORMHOLEREPLAY_BO_MAX;
        wormholeReplay->BOtimes = 0;
        wormholeReplay->status = NETIA_WORMHOLEREPLAY_STATUS_YIELD;
        MacWormholeReplayYield(
            node,
            wormholeReplay,
            (clocktype)WORMHOLEREPLAY_TX_DATA_YIELD_TIME);
    }//if//
#endif // WORMHOLE_DIRECT_REPLAY
}


// Name: MacWormholeLayer
// Purpose: Handle frames and timers.
// Parameter: node, node that is handling the frame or timer.
//            interfaceIndex, interface associated with frame or timer.
//            msg, frame or timer.
// Return: None.

void
MacWormholeLayer(Node *node, int interfaceIndex, Message *msg)
{
    MacWormholeData *wormhole =
        (MacWormholeData *)node->macData[interfaceIndex]->macVar;

    if (!(node->macData[interfaceIndex]->interfaceIsEnabled) )
    {
        MESSAGE_Free(node, msg);
        return;
    }

    switch (msg->eventType) {
#ifdef PARTICIPANT
        // For future PARTICIPANT mode, i.e., wormhole nodes are
        // network members.
        case MSG_MAC_FromNetwork:
            if (DEBUG)
            {
                char clockStr[20];
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %ld received packet "
                       "to send from network layer at time %s\n",
                       node->nodeId, clockStr);
            }
            MacWormholeNetworkLayerHasPacketToSend(node, wormhole);
            break;
#endif // PARTICIPANT
        case MSG_MAC_LinkToLink:
            MacWormholeReplayFrame(node, interfaceIndex, msg);
            break;

        case MSG_MAC_TransmissionFinished:
            MacWormholeReplayTransmissionFinished(node, interfaceIndex, msg);
            break;

        default:
        {
            MacWormholeData *wormholeReplay = wormhole;
            int seq_num=0;

            if (msg->eventType != MSG_MAC_TimerExpired)
            {
                printf("at ""%15" TYPES_64BITFMT "d"
                       ", node %d executing wrong event %d on int %d\n",
                       node->getNodeTime(), node->nodeId, msg->eventType,
                       interfaceIndex);
                fflush(stdout);
            }
            assert(msg->eventType == MSG_MAC_TimerExpired);

            seq_num = *((int *) MESSAGE_ReturnInfo(msg));

            MESSAGE_Free(node, msg);

            // CSMA timer handling
            if ((seq_num < wormholeReplay->timer.seq) ||
                ((wormholeReplay->timer.flag & WORMHOLEREPLAY_TIMER_SWITCH)
                 == WORMHOLEREPLAY_TIMER_OFF))
            {
                return;
            }

            if (seq_num > wormholeReplay->timer.seq)
            {
                assert(FALSE);
            }

            assert(((wormholeReplay->timer.flag & WORMHOLEREPLAY_TIMER_TYPE)
                    == WORMHOLEREPLAY_TIMER_BACKOFF) ||
                   ((wormholeReplay->timer.flag & WORMHOLEREPLAY_TIMER_TYPE)
                    == WORMHOLEREPLAY_TIMER_YIELD));

            switch(wormholeReplay->timer.flag & WORMHOLEREPLAY_TIMER_TYPE)
            {
                case WORMHOLEREPLAY_TIMER_BACKOFF:
                {
                    wormholeReplay->timer.flag =
                        WORMHOLEREPLAY_TIMER_OFF |
                        WORMHOLEREPLAY_TIMER_UNDEFINED;
                    if (DEBUG)
                    {
                        char clockStr[20];
                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        printf("Wormhole node %d backoff finished at time %s\n",
                               node->nodeId, clockStr);
                    }
                    CheckPhyStatusAndSendOrBackoff(node, wormholeReplay);

                    break;
                }

                case WORMHOLEREPLAY_TIMER_YIELD:
                    wormholeReplay->timer.flag =
                        WORMHOLEREPLAY_TIMER_OFF |
                        WORMHOLEREPLAY_TIMER_UNDEFINED;
                    wormholeReplay->status =
                        NETIA_WORMHOLEREPLAY_STATUS_PASSIVE;
                    if (DEBUG)
                    {
                        char clockStr[20];
                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        printf("Wormhole node %d yield finished at time %s\n",
                               node->nodeId, clockStr);
                    }
                    MacWormholeReplayPassive(node, wormholeReplay);
                    break;

                default:
                    assert(FALSE); abort();
                    break;
            }/*switch*/
        }
    }
}
