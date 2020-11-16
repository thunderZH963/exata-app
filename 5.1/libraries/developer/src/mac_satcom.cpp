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

// This is an abstract model of a satellite network.  Each satellite
// network is group into subnets.  Each satellite subnet has
// exactly one satellite node and many ground nodes.  The
// ground nodes associated with a subnet always transmit to the
// designated subnet satellite node.  Thus, no handoffs are
// involved.  Also, satellite nodes are bent-pipe satellites
// (relay data only).  When the satellite node receives data
// from the ground nodes, it broadcasts the data to all other ground
// nodes in the subnet, but not to the ground node originating the data.
// Finally, this model does not consider collisions.  Therefore,
// the model can be viewed as a set of point-to-multipoint (ground
// node to ground nodes) links.


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "mac_satcom.h"
#include "network_ip.h"
#ifdef ENTERPRISE_LIB
#include "mpls.h"
#endif // ENTERPRISE_LIB

#ifdef ADDON_DB
#include "dbapi.h"
#endif

//#define DEBUG 0

static const clocktype DefaultMACPropagationDelay = (270 * MILLI_SECOND);
static const Int64 DefaultMACSatcomBandwidth = 1000000;
static const double DefaultMACSatcomBER = 0.000001;


// Name: MacSatComIsMySubnetBroadcastFrame
// Purpose: Check if IP address belongs to our subnet broadcast address.
// Parameter: node, node calling this function.
//            addr, IP address to check.
// Return: TRUE if address is one of ours, FALSE otherwise.

static
BOOL MacSatComIsMySubnetBroadcastFrame(Node *node, NodeAddress addr) {
    int i;

    for (i = 0; i < node->numberInterfaces; i++) {
        if (addr == NetworkIpGetInterfaceBroadcastAddress(node, i)) {
            return TRUE;
        }
    }

    return FALSE;
}


// Name: MacSatComGetSubnetParameters
// Purpose: Get the parameters for a subnet.
// Parameter: node, node calling this function.
//            address, subnet address to get parameters from.
//            nodeInput, configuration file access.
//            bandwidth, bandwidth of subnet.
//            userSpecifiedPropDelay, determines whether or not the user
//                                    specifies his/her own prop. delay.
//            uplinkDelay, uplink propagation delay of subnet.
//            downlinkDelay, downlink propagation delay of subnet.
// Return: Bandwidth, uplink and downlink propagation delay.

void
MacSatComGetSubnetParameters(
    Node* node,
    int interfaceIndex,
    Address* address,
    const NodeInput* nodeInput,
    Int64 *bandwidth,
    BOOL *userSpecifiedPropDelay,
    clocktype *uplinkDelay,
    clocktype *downlinkDelay)
{
    BOOL wasFound;
    clocktype propDelay;
    char addressStr[MAX_STRING_LENGTH];

    IO_ConvertIpAddressToString(address, addressStr);

    IO_ReadInt64(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "SATCOM-BANDWIDTH",
        &wasFound,
        bandwidth);

    if (!wasFound) {
        *bandwidth = DefaultMACSatcomBandwidth;
    }

    IO_ReadTime(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "SATCOM-PROPAGATION-DELAY",
        &wasFound,
        &propDelay);

    if (!wasFound) {
        *userSpecifiedPropDelay = FALSE;

       *uplinkDelay = DefaultMACPropagationDelay / 2;
        *downlinkDelay = DefaultMACPropagationDelay / 2;
    }
    else {
        *userSpecifiedPropDelay = TRUE;

        // Uplink delay is half the ground-to-ground propagation delay
        *uplinkDelay = propDelay / 2;

        // Downlink delay is half the ground-to-ground propagation delay
        *downlinkDelay = propDelay / 2;
    }
}


// Name: MacSatComHandlePromiscuousMode
// Purpose: Send remote packet to network layer.
// Parameter: node, node calling this function.
//            satCom, SATCOM data structure.
//            frame, frame to send to network layer.
// Return: None.

static
void MacSatComHandlePromiscuousMode(
    Node *node,
    MacSatComData *satCom,
    Message *frame,
    NodeAddress prevHop,
    NodeAddress destAddr)
{
    MESSAGE_RemoveHeader(
        node,
        frame,
        sizeof(MacSatComFrameHeader),
        TRACE_SATCOM);

    MAC_SneakPeekAtMacPacket(
        node,
        satCom->myMacData->interfaceIndex,
        frame,
        prevHop,
        destAddr);

    MESSAGE_AddHeader(
        node,
        frame,
        sizeof(MacSatComFrameHeader),
        TRACE_SATCOM);
}

// Name: MacSatComInit
// Purpose: Initialize SATCOM model.
// Parameter: node, node calling this function.
//            nodeInput, configuration file access.
//            interfaceIndex, interface to initialize.
//            address, subhet address to initialize.
//            interfaceAddress, interface address to initialize.
//            numHostBits, number of host bits for this subnet.
//            nodeList, list of nodes in the subnet.
//            numNodesInSubnet, number of nodes in the subnet.
//            userSpecifiedPropDelay, determines whether or not the user
//                                    specifies his/her own prop. delay.
//            downlinkDelay, downlink propagation delay of subnet.
//            uplinkDelay, uplink propagation delay of subnet.
//            subnetList, node list in subnet
// Return: FALSE if satellite node, TRUE otherwise (although will assert).

BOOL
MacSatComInit(
    Node *node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    int numNodesInSubnet,
    BOOL userSpecifiedPropDelay,
    clocktype uplinkDelay,
    clocktype downlinkDelay,
    const int subnetListIndex,
    SubnetMemberData* subnetList)
{
    int i;
    NodeAddress satelliteNodeId;
    MacSatComData *satCom;
    BOOL wasFound;
    char satType[MAX_STRING_LENGTH];

    satCom = (MacSatComData *)
          MEM_malloc(sizeof(MacSatComData));

    memset(satCom, 0, sizeof(MacSatComData));

    satCom->myMacData = node->macData[interfaceIndex];
    satCom->myMacData->macVar = (void *) satCom;
    satCom->myMacData->phyNumber = interfaceIndex;

    satCom->status = MAC_SATCOM_IDLE;
    satCom->type = MAC_SATCOM_UNKNOWN;

    satCom->nodeList = (SubnetMemberData*)subnetList;
    satCom->numNodesInSubnet = numNodesInSubnet;

    satCom->stats.packetsSent = 0;
    satCom->stats.packetsReceived = 0;
    satCom->stats.packetsRelayed = 0;

    satCom->userSpecifiedPropDelay = userSpecifiedPropDelay;
    satCom->uplinkDelay = uplinkDelay;
    satCom->downlinkDelay = downlinkDelay;

    IO_ReadInt(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "SATCOM-SATELLITE-NODE",
        &wasFound,
        (int *)&satelliteNodeId);

    ERROR_Assert(wasFound,
                 "SATCOM needs to specify SATCOM-SATELLITE-NODE\n");

    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "SATCOM-TYPE",
        &wasFound,
        satType);

    ERROR_Assert(wasFound, "SATCOM needs to specify SATCOM-TYPE\n");

    if (strcmp(satType, "BENT-PIPE") != 0) {
        ERROR_Assert(FALSE,
                     "SATCOM currently only supports BENT-PIPE type\n");
    }

#ifdef PARALLEL //Parallel
    PARALLEL_SetProtocolIsNotEOTCapable(node);
    PARALLEL_SetMinimumLookaheadForInterface(node,
                                                 (2*userSpecifiedPropDelay));
#endif //endParallel

#ifdef ADDON_DB
    // if interface is already enabled, don't trigger a DB update
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL && db->statsSummaryTable->createPhySummaryTable)
    {
        satCom->macOneHopData =
            new std::map<int,MacOneHopNeighborStats>();
    }
#endif

    // If we are ground node, then only keep track of the satellite node
    if (node->nodeId != satelliteNodeId) {
        satCom->type = MAC_SATCOM_GROUND;

        wasFound = FALSE;

        for (i = 0; i < numNodesInSubnet; i++) {
            // Look for the satellite node and keep a record of it.
            if (satCom->nodeList[i].nodeId == satelliteNodeId)
            {
                wasFound = TRUE;
                satCom->satNodeIndex = i;
                break;
            }
        }

        // If satellite node not found, then generate error.
        ERROR_Assert(wasFound, "Satellite node not found!\n");


        return TRUE;
    }
    // This is the satellite node...
    else {
        satCom->type = MAC_SATCOM_SATELLITE;
        satCom->satNodeIndex = -1;
        return FALSE;
   }
}


// Name: MacSatComPrintStats
// Purpose: Print out stats for a particular interface.
// Parameter: node, node calling this function.
//            satCom, SATCOM data structure.
//            interfaceIndex, interface associated with the stats.
// Return: None.

static
void MacSatComPrintStats(
    Node *node,
    MacSatComData *satCom,
    int interfaceIndex)
{
    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "Frames sent = %d", satCom->stats.packetsSent);
    IO_PrintStat(node, "MAC", "SatCom", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames received = %d", satCom->stats.packetsReceived);
    IO_PrintStat(node, "MAC", "SatCom", ANY_DEST, interfaceIndex, buf);

    sprintf(buf, "Frames relayed = %d", satCom->stats.packetsRelayed);
    IO_PrintStat(node, "MAC", "SatCom", ANY_DEST, interfaceIndex, buf);

#ifdef ADDON_DB
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL && db->statsSummaryTable->createPhySummaryTable)
    {
        delete(satCom->macOneHopData);
    }
#endif
}



// Name: MacSatComFinalize
// Purpose: Handle any finalization tasks.
// Parameter: node, node calling this function.
//            interfaceIndex, interface associated with the
//                            finalization tasks.
// Return: None.

void MacSatComFinalize(Node *node, int interfaceIndex) {
    if (node->macData[interfaceIndex]->macStats == TRUE) {
        MacSatComPrintStats(
            node,
            (MacSatComData *) node->macData[interfaceIndex]->macVar,
            interfaceIndex);
    }
}


// Name: MacSatComSend
// Purpose: Relay a frame from satellite to ground.
// Parameter: sourceNode, source node to relay frame from.
//            destNode, destination ground node to relay frame to.
//            interfaceIndex, interface to use to relay frame.
//            msgToSend, frame to relay to ground node.
// Return: None.

static
void MacSatComSend(
    Node *sourceNode,
    Node *destNode,
    int interfaceIndex,
    Message *msgToSend)
{

    MacSatComData *satCom;
    clocktype downlinkDelay;

    satCom = (MacSatComData*)destNode->macData[interfaceIndex]->macVar;

        downlinkDelay = satCom->downlinkDelay;

    MESSAGE_SetEvent(msgToSend, MSG_MAC_SatelliteToGround);
    MESSAGE_SetLayer(msgToSend, MAC_LAYER, 0);

    MESSAGE_SetInstanceId(msgToSend, (short)interfaceIndex);

    MESSAGE_Send(destNode, msgToSend, downlinkDelay);

#ifdef DEBUG
    char addrStr[MAX_STRING_LENGTH], src[MAX_STRING_LENGTH];
    IO_ConvertIpAddressToString(
              NetworkIpGetLinkLayerAddress(destNode, interfaceIndex), addrStr);
    IO_ConvertIpAddressToString( NetworkIpGetLinkLayerAddress(sourceNode, 0), src);
    printf("\tMacSatComSend (from %d/%s to %d/%s)\n", sourceNode->nodeId, src, destNode->nodeId, addrStr);
#endif

}


// Name: MacSatComBroadcast
// Purpose: Broadcast the frame to the ground nodes (via relay).
// Parameter: node, satellite node.
//            satCom, SATCOM data structure.
//            fromAddr, ground node received frame from.
//            msgToSend, frame to relay to ground node (other then source node).
// Return: None.

static
void MacSatComBroadcast(
    Node *node,
    MacSatComData *satCom,
    NodeAddress fromAddr,
    Message *msgToSend)
{
    int i;

//GuiStart
    if (node->guiOption == TRUE) {
        GUI_Broadcast(node->nodeId,
                      GUI_MAC_LAYER,
                      GUI_DEFAULT_DATA_TYPE,
                      satCom->myMacData->interfaceIndex,
                      node->getNodeTime());
    }
//GuiEnd

#ifdef DEBUG
    MacSatComFrameHeader *header =
                        (MacSatComFrameHeader *)msgToSend->packet;
    if (header->destAddr == -1)
    {
        printf("#%d: MacSatComBroadcast(%d nodes)\n",
                node->nodeId, satCom->numNodesInSubnet);
    }
    else
    {
        printf("#%d: MacSatComSend (1 node)\n",
               node->nodeId);
    }
#endif

//  printf("\n Message from node: %d\n", msgToSend->originatingNodeId);

    // Broadcast to all ground nodes except for ground node that
    // originated the frame.
    for (i = 0; i < satCom->numNodesInSubnet; i++) {
        //make sure we don't send packet to ourselves
        //for the originator, it will be dropped when received
        //to fix a issue in parallel mode
        if (satCom->nodeList[i].node && satCom->nodeList[i].nodeId != node->nodeId)
        {
           MacHWAddress myHWAddr = GetMacHWAddress(satCom->nodeList[i].node,
                            satCom->nodeList[i].interfaceIndex);
           MacSatComSend(
                    node,
                    satCom->nodeList[i].node,
                    satCom->nodeList[i].interfaceIndex,
                    MESSAGE_Duplicate(node, msgToSend));
        }
    }

#ifdef PARALLEL //Parallel
    MESSAGE_SetEvent(msgToSend, MSG_MAC_SatelliteToGround);
    MESSAGE_SetLayer(msgToSend, MAC_LAYER, 0);
    msgToSend->eventTime = node->getNodeTime() + satCom->downlinkDelay;
    MESSAGE_SetInstanceId(msgToSend, (short) satCom->myMacData->subnetIndex);
    msgToSend->relayNodeAddr = fromAddr;
//  printf("\n msgToSend->relayNodeAddr = %d", msgToSend->relayNodeAddr);
    PARALLEL_SendMessageToAllPartitions(msgToSend, node->partitionData);
#else //Parallel
    MESSAGE_Free(node, msgToSend);
#endif //Parallel
}


// Name: MacSatComHandleGroundToSatelliteFrame
// Purpose: Satellite handling frames received from ground node.
// Parameter: node, satellite node.
//            interfaceIndex, interface received frame from.
//            msg, frame to relay to ground node (other then source node).
// Return: None.

void MacSatComHandleGroundToSatelliteFrame(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    MacSatComData *satCom
        = (MacSatComData *)node->macData[interfaceIndex]->macVar;

    MacSatComFrameHeader *header = (MacSatComFrameHeader *)msg->packet;
    if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
    {
        return;
    }
#ifdef ADDON_DB
        clocktype recvTime = node->getNodeTime();
        StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);
        ERROR_Assert(delayInfo , "delayInfo not inserted by sender!");
        clocktype delay = recvTime - delayInfo -> sendTime; 
        HandleStatsDBPhySummaryUpdateForMacProtocols(
            node,
            interfaceIndex,
            MAPPING_GetNodeIdFromInterfaceAddress(node, header->sourceAddr),
            satCom->macOneHopData,
            delayInfo->txDelay,
            delay,
            FALSE);

        delayInfo -> txDelay = -1;
        delayInfo -> sendTime = node->getNodeTime();
#endif

#ifdef DEBUG
    {
        char addrStr[MAX_STRING_LENGTH];
        char clockStr[20];
        IO_ConvertIpAddressToString(header->sourceAddr, addrStr);
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("mac_satcom.cpp: Node %ld received packet from node %s at time %s\n",
                node->nodeId, addrStr, clockStr);
    }
    #endif

    ERROR_Assert(satCom->type == MAC_SATCOM_SATELLITE,
                 "SATCOM: Not a satellite node\n");

    ERROR_Assert(!MAC_IsMyUnicastFrame(node, header->destAddr),
                 "SATCOM: Satellite node cannot be a destination "
                 "of a frame\n");

    MacSatComBroadcast(
            node,
            satCom,
            header->sourceAddr,
            msg);

    satCom->stats.packetsRelayed++;
}



// Name: MacSatComHandleSatelliteToGroundFrame
// Purpose: Ground node handling frame sent from satellite.
// Parameter: node, ground node.
//            interfaceIndex, interface received frame from.
//            msg, frame received from satellite.
// Return: None.

void MacSatComHandleSatelliteToGroundFrame(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    char addrStr[MAX_STRING_LENGTH];
    MacSatComData *satCom
        = (MacSatComData *)node->macData[interfaceIndex]->macVar;

    MacSatComFrameHeader *header = (MacSatComFrameHeader *)msg->packet;
    IO_ConvertIpAddressToString(header->destAddr, addrStr);
    if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
    {
        return;
    }
#ifdef DEBUG
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        IO_ConvertIpAddressToString(header->sourceAddr, addrStr);
        printf("mac_satcom.cpp Node %ld received packet from node %s at time %s\n",
                node->nodeId, addrStr, clockStr);
        printf("    handing off packet to network layer\n");
        IO_ConvertIpAddressToString(header->destAddr, addrStr);
        printf(" DESTINATION %s\n", addrStr);
    }
    #endif

    ERROR_Assert(satCom->type == MAC_SATCOM_GROUND,
                 "SATCOM: Not a satellite node\n");

    MacHWAddress destHWAddr;
    MAC_FourByteMacAddressToVariableHWAddress(node, interfaceIndex,
                                             &destHWAddr,
                                            header->destAddr);

    if (header->sourceAddr == MAC_VariableHWAddressToFourByteMacAddress(node,
                                  &node->macData[interfaceIndex]->macHWAddr))
    {
        #ifdef DEBUG
        {
            char addrStr[MAX_STRING_LENGTH];
            char clockStr[20];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("mac_satcom.cpp Node %ld received packet from self at time %s\n",
                   node->nodeId, clockStr);
            printf("    dropping packet\n");
            IO_ConvertIpAddressToString(header->destAddr, addrStr);
            printf(" DESTINATION %s\n", addrStr);
        }
        #endif
        MESSAGE_Free(node, msg);
    }
    else if (MAC_IsMyAddress(node, &destHWAddr) ||
        MacSatComIsMySubnetBroadcastFrame(node, header->destAddr) ||
        header->destAddr == ANY_DEST)
    {
#ifdef ADDON_DB
        clocktype recvTime = node->getNodeTime();
        StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);
        ERROR_Assert(delayInfo , "delayInfo not inserted by sender!");
        clocktype delay = recvTime - delayInfo -> sendTime;
        HandleStatsDBPhySummaryUpdateForMacProtocols(
            node,
            interfaceIndex,
            satCom->nodeList[satCom->satNodeIndex].nodeId,
            satCom->macOneHopData,
            delayInfo->txDelay,
            delay,
            FALSE);
#endif
        MESSAGE_RemoveHeader(node,
                             msg,
                             sizeof(MacSatComFrameHeader),
                             TRACE_SATCOM);

        MAC_HandOffSuccessfullyReceivedPacket(
                node, interfaceIndex, msg, header->sourceAddr);

        satCom->stats.packetsReceived++;
    }
    else {
        if (satCom->myMacData->promiscuousMode == TRUE) {
            MacSatComHandlePromiscuousMode(node,
                                           satCom,
                                           msg,
                                           header->sourceAddr,
                                           header->destAddr);
            satCom->stats.packetsReceived++;

#ifdef ADDON_DB
        clocktype recvTime = node->getNodeTime();
        StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);
        ERROR_Assert(delayInfo , "delayInfo not inserted by sender!");
        clocktype delay = recvTime - delayInfo -> sendTime;
        HandleStatsDBPhySummaryUpdateForMacProtocols(
            node,
            interfaceIndex,
            satCom->nodeList[satCom->satNodeIndex].nodeId,
            satCom->macOneHopData,
            delayInfo->txDelay,
            delay,
            FALSE);
#endif
        }

        MESSAGE_Free(node, msg);
    }
}


// Name: MacSatComTransmissionFinished
// Purpose: Ground node finished transmitting.
// Parameter: node, ground node.
//            interfaceIndex, interface used to sent last frame.
//            msg, timer telling us that the transmission is done.
// Return: None.
void MacSatComTransmissionFinished(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    MacSatComData *satCom
        = (MacSatComData *)node->macData[interfaceIndex]->macVar;

    assert(satCom != NULL);
    satCom->stats.packetsSent++;

    satCom->status = MAC_SATCOM_IDLE;
    #ifdef DEBUG
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %ld finished transmitting packet at time %s\n",
                node->nodeId, clockStr);
    }
    #endif
    if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE) {
        #ifdef DEBUG
        {
            printf("    there's more packets in the queue, "
                   "so try to send the next packet\n");
        }
        #endif

        MacSatComNetworkLayerHasPacketToSend(node, satCom);
    }

    MESSAGE_Free(node, msg);
}


// Name: MacSatComNetworkLayerHasPacketToSend
// Purpose: Ground node has packets to send.
// Parameter: node, ground node.
//            satCom, SATCOM dataa structure.
// Return: None.

void MacSatComNetworkLayerHasPacketToSend(
    Node *node,
    MacSatComData *satCom)
{
    Message *newMsg = NULL;
    Message *txFinishedMsg;
    clocktype txDelay;
    NodeAddress nextHopAddress;
    int networkType;
    TosType priority;
    MacSatComFrameHeader *header;
    MacData *thisMac = satCom->myMacData;
    int interfaceIndex = thisMac->interfaceIndex;
    clocktype uplinkDelay;
    if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
    {
        return;
    }


    /*ERROR_Assert(satCom->type != MAC_SATCOM_SATELLITE,
                 "SATCOM: Satellite node cannot initiate data "
                 "transmissions\n");*/
    if(satCom->type == MAC_SATCOM_SATELLITE)
    {
        MAC_OutputQueueDequeuePacket(node,
                                     interfaceIndex,
                                     &newMsg,
                                     &nextHopAddress,
                                     &networkType, &priority);
        MESSAGE_Free(node , newMsg);
        return ;

    }
    //Changed by dualip team- start

    if (satCom->status == MAC_SATCOM_BUSY) {
        return;
    }

    assert(satCom->satNodeIndex != -1);
    assert(satCom->type == MAC_SATCOM_GROUND);
    assert(satCom->status == MAC_SATCOM_IDLE);

    MAC_OutputQueueDequeuePacket(node,
                                 interfaceIndex,
                                 &newMsg,
                                 &nextHopAddress,
                                 &networkType, &priority);

    assert(newMsg != NULL);

    MESSAGE_AddHeader(node,
                      newMsg,
                      sizeof(MacSatComFrameHeader),
                      TRACE_SATCOM);

    header = (MacSatComFrameHeader *)MESSAGE_ReturnPacket(newMsg);

    header->sourceAddr = MAC_VariableHWAddressToFourByteMacAddress(node,
                               &node->macData[interfaceIndex]->macHWAddr);
    header->destAddr = nextHopAddress;

    txDelay = (clocktype)(MESSAGE_ReturnPacketSize(newMsg) * 8 * SECOND
                          / thisMac->bandwidth);

    MESSAGE_SetEvent(newMsg, MSG_MAC_GroundToSatellite);
    MESSAGE_SetLayer(newMsg, MAC_LAYER, 0);

    // Send to satellite node.
    uplinkDelay = satCom->uplinkDelay;
#ifdef ADDON_DB

    StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( newMsg, INFO_TYPE_DelayInfo);

    if (delayInfo == NULL)
    {
        (StatsDBPhySummDelayInfo*) MESSAGE_AddInfo(node,
                                                   newMsg,
                                                   sizeof(StatsDBPhySummDelayInfo),
                                                   INFO_TYPE_DelayInfo);
        delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( newMsg, INFO_TYPE_DelayInfo);
    }
   
    delayInfo -> txDelay = txDelay;
    delayInfo -> sendTime = node->getNodeTime();
#endif

     //msg send if node is on our partition
    if (satCom->nodeList[satCom->satNodeIndex].node &&
        satCom->nodeList[satCom->satNodeIndex].node->partitionId == node->partitionId)
    {
        MESSAGE_SetInstanceId(newMsg,
             (short) satCom->nodeList[satCom->satNodeIndex].interfaceIndex);
        MESSAGE_Send(satCom->nodeList[satCom->satNodeIndex].node, newMsg, txDelay + uplinkDelay);
    }
    else
    {
        MESSAGE_SetInstanceId(newMsg,
            (short) satCom->myMacData->subnetIndex);
        int destNodeId = satCom->nodeList[satCom->satNodeIndex].nodeId;

            //node->partitionData->subnetData.subnetList[subnetIndex].memberList[satCom->satNodeIndex].nodeId;

        MESSAGE_RemoteSend(node, destNodeId, newMsg, txDelay + uplinkDelay);
    }

    satCom->status = MAC_SATCOM_BUSY;
    txFinishedMsg = MESSAGE_Alloc(node, MAC_LAYER, 0,
                                  MSG_MAC_TransmissionFinished);

    MESSAGE_SetInstanceId(txFinishedMsg, (short)interfaceIndex);
    MESSAGE_Send(node, txFinishedMsg, txDelay);

#ifdef DEBUG
   printf("#%d: MacSatComNetworkLayerHasPacketToSend(to %d)\n",
           node->nodeId,
           MAPPING_GetNodeIdFromInterfaceAddress(node, nextHopAddress));
#endif
}



// Name: MacSatComLayer
// Purpose: Handle frames and timers.
// Parameter: node, node that is handling the frame or timer.
//            interfaceIndex, interface associated with frame or timer.
//            msg, frame or timer.
// Return: None.
void MacSatComLayer(Node *node, int interfaceIndex, Message *msg) {
    MacSatComData *satCom =
        (MacSatComData *)node->macData[interfaceIndex]->macVar;

    switch (msg->eventType) {
        case MSG_MAC_FromNetwork: {
            #ifdef DEBUG
            {
                char clockStr[20];
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %ld received packet to send from network layer "
                       "at time %s\n",
                        node->nodeId, clockStr);
            }
            #endif
            MacSatComNetworkLayerHasPacketToSend(node, satCom);
            break;
        }
        case MSG_MAC_GroundToSatellite: {
            MacSatComHandleGroundToSatelliteFrame(node, interfaceIndex, msg);
            break;
        }
        case MSG_MAC_SatelliteToGround: {
            MacSatComHandleSatelliteToGroundFrame(node, interfaceIndex, msg);
            break;
        }
        case MSG_MAC_TransmissionFinished: {
            MacSatComTransmissionFinished(node, interfaceIndex, msg);
            break;
        }
        default: {
            assert(FALSE); abort();
        }
    }
}

