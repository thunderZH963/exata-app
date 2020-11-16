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
#include <math.h>

#include "api.h"
#include "partition.h"

#include "mac_link.h"
#include "mac.h"
#include "network_ip.h"

#include "mac_background_traffic.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#ifdef WIRELESS_LIB
#include "mac_link_microwave.h"
#include "mac_link_satellite.h"
#endif // WIRELESS_LIB

#ifdef PARALLEL //Parallel
#include "parallel.h"
#endif //endParallel

#ifdef ADDON_BOEINGFCS
#include "network_ces_inc.h"
#include "link_ces_sincgars_sip.h"
#include "mac_ces_eplrs.h"
#endif

#define DEBUG 0

#define DEFAULT_HEADER_SIZE_IN_BITS (28 * 8)


static
clocktype LinkGetPropDelayForWireless(Node *node,
                                      LinkData *link) {
    Coordinates nodePosition;
    Coordinates destPosition;
    double distance;

    MOBILITY_ReturnCoordinates(node, &nodePosition);
    MOBILITY_ReturnCoordinates(link->dest, &destPosition);

    COORD_CalcDistance(
        NODE_GetTerrainPtr(node)->getCoordinateSystem(),
        &nodePosition, &destPosition, &distance);

    return PROP_CalculatePropagationDelay(
               distance,
               link->propSpeed,
               node->partitionData,
               -1,
               NODE_GetTerrainPtr(node)->getCoordinateSystem(),
               &nodePosition,
               &destPosition);
}

void LinkSendFrame(Node*       node,
                   Message*    msg,
                   LinkData*   link,
                   int         interfaceIndex,
                   Mac802Address sourceAddress,
                   Mac802Address nextHopAddress,
                   BOOL        isFrameTagged,
                   TosType     priority,
                   Int64 effectiveBW) {

    clocktype        propDelay;
    clocktype        txDelay;
    LinkFrameHeader* header;
    MacData*         thisMac = link->myMacData;
    Message*         txFinishedMsg;


    txDelay = (clocktype)(((MESSAGE_ReturnPacketSize(msg) * 8)
        + link->headerSizeInBits) * SECOND / effectiveBW);

    // Calculate the delay of real traffic due to BG traffic.
    if ((thisMac->bgMainStruct) && (thisMac->bandwidth > effectiveBW))
    {
        BgMainStruct* bgMainStruct = (BgMainStruct*)thisMac->bgMainStruct;
        BgRealTrafficDelay* bgRealDelay = bgMainStruct->bgRealDelay;

        // Calculate packet transmission delay if BG traffic is not there.
        clocktype normalDelay =
                (clocktype)(((MESSAGE_ReturnPacketSize(msg) * 8) +
                    link->headerSizeInBits) * SECOND / thisMac->bandwidth);

        bgRealDelay[priority].delay += (txDelay - normalDelay);
        bgRealDelay[priority].occurrence ++;

        BgTraffic_SuppressByHigher(node, thisMac, priority, txDelay);
    }

    MESSAGE_AddHeader(node, msg, sizeof(LinkFrameHeader), TRACE_LINK);

    header = (LinkFrameHeader*) MESSAGE_ReturnPacket(msg);

    MAC_CopyMac802Address(&header->sourceAddr, &sourceAddress);
    MAC_CopyMac802Address(&header->destAddr, &nextHopAddress);
    header->vlanTag    = isFrameTagged;

#ifdef ADDON_DB
    HandleMacDBEvents(
            node,
            msg,
            node->macData[interfaceIndex]->phyNumber,
            interfaceIndex,
            MAC_SendToPhy,
            node->macData[interfaceIndex]->macProtocol);
#endif

    BOOL isMyFrame = FALSE;
    BOOL isAnyFrame = FALSE;
    STAT_DestAddressType type;

    MacLinkGetPacketProperty(node,
                             msg,
                             interfaceIndex,
                             type,
                             isMyFrame,
                             isAnyFrame);

    // Check for TRACE_LINK and TRACE_VLAN headers
    Int32 controlSize = 0;
    Int32 i;
    for (i = 0; i < msg->numberOfHeaders; i++)
    {
        if (msg->headerProtocols[i] == TRACE_LINK
            || msg->headerProtocols[i] == TRACE_VLAN)
        {
            controlSize += msg->headerSizes[i];
        }
    }

    if (node->macData[interfaceIndex]->macStats)
    {
        node->macData[interfaceIndex]->stats->AddFrameSentDataPoints(
            node,
            msg,
            type,
            controlSize,
            MESSAGE_ReturnPacketSize(msg) - controlSize,
            interfaceIndex,
            link->destNodeId);
    }
    MESSAGE_SetEvent(msg, MSG_MAC_LinkToLink);
    MESSAGE_SetLayer(msg, MAC_LAYER, 0);
    MESSAGE_SetInstanceId(msg, (short)link->destInterfaceIndex);

#ifdef ADDON_DB
    HandleMacDBConnectivity(node,
        interfaceIndex, msg, MAC_SendToPhy);
    //Add the delay info necessary for the phy summary table
    StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);

    if (delayInfo == NULL)
    {
        (StatsDBPhySummDelayInfo*) MESSAGE_AddInfo(node,
                                                   msg,
                                                   sizeof(StatsDBPhySummDelayInfo),
                                                   INFO_TYPE_DelayInfo);
        delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);
    }

    delayInfo -> txDelay = txDelay;
    delayInfo -> sendTime = node->getNodeTime();
#endif

    if (link->dest != NULL) { // same partition
        if (link->phyType == WIRELESS) {

            MESSAGE_InfoAlloc(node, msg, sizeof(WirelessLinkInfo));
            WirelessLinkInfo* linkInfo =
                   (WirelessLinkInfo*) MESSAGE_ReturnInfo(msg);

            propDelay = LinkGetPropDelayForWireless(node, link);

            linkInfo->propDelay = propDelay;
            MESSAGE_Send(link->dest, msg, txDelay + propDelay);
        }//WIRELESS

#ifdef WIRELESS_LIB
        else if (link->phyType == MICROWAVE) {

            Coordinates sourcePosition;
            WirelessLinkInfo* linkInfo;
            WirelessLinkParameters *linkvar =
                   (WirelessLinkParameters*)link->linkVar;

            MESSAGE_InfoAlloc(node, msg, sizeof(WirelessLinkInfo));
            linkInfo = (WirelessLinkInfo*) MESSAGE_ReturnInfo(msg);

            memcpy(&(linkInfo->sourcesiteparameters), &(linkvar->Tx),
                        sizeof(WirelessLinkSiteParameters));
            MOBILITY_ReturnCoordinates(node, &sourcePosition);

            linkInfo->sourcecoordinates = sourcePosition;
            propDelay = LinkGetPropDelayForWireless(node, link);
            linkInfo->propDelay = propDelay;

            MESSAGE_Send(link->dest, msg, txDelay + propDelay);

        }
        else if (link->phyType == SATELLITE) {

            Coordinates sourcePosition;
            SatelliteLinkInfo* linkInfo;

            SatelliteLinkParameters *linkvar =
                   (SatelliteLinkParameters*)link->linkVar;

            MESSAGE_InfoAlloc(node, msg, sizeof(SatelliteLinkInfo));
            linkInfo = (SatelliteLinkInfo*) MESSAGE_ReturnInfo(msg);

            memcpy(&(linkInfo->sourceSiteParameters), &(linkvar->txPara),
                    sizeof(WirelessLinkSiteParameters));

            MOBILITY_ReturnCoordinates(node, &sourcePosition);
            linkInfo->sourcecoordinates = sourcePosition;

            propDelay = LinkGetPropDelayForWireless(node, link);
            linkInfo->propDelay = propDelay;

            txDelay = (clocktype)(((MESSAGE_ReturnPacketSize(msg) * 8)
                    + link->headerSizeInBits) * SECOND / linkvar->dataRate);

            MESSAGE_Send(link->dest, msg, txDelay + propDelay);

        }
#endif // WIRELESS_LIB
        else {
            MESSAGE_Send(link->dest, msg, txDelay + thisMac->propDelay);

        }// WIRED
    }
    else {
#ifdef PARALLEL //Parallel
        if (link->partitionIndex != node->partitionData->partitionId) {

            if (DEBUG) {
                printf("node %d sending remote link message\n", node->nodeId);
                MESSAGE_PrintMessage(msg);
            }
#ifdef WIRELESS_LIB
            if (link->phyType == MICROWAVE) {

                WirelessLinkParameters *linkvar =
                       (WirelessLinkParameters*)link->linkVar;

                PARALLEL_SendRemoteLinkMessage(node, msg, link, txDelay, &(linkvar->Tx));
            }
            else if (link->phyType == SATELLITE) {

                WirelessLinkParameters *linkvar =
                       (WirelessLinkParameters*)link->linkVar;

                SatelliteLinkParameters *linkPar =
                   (SatelliteLinkParameters*)link->linkVar;

                txDelay = (clocktype)(((MESSAGE_ReturnPacketSize(msg) * 8)
                    + link->headerSizeInBits) * SECOND / linkPar->dataRate);

                PARALLEL_SendRemoteLinkMessage(node, msg, link, txDelay, &(linkvar->Tx));
            }
            else
#endif // WIRELESS_LIB
            {
                WirelessLinkSiteParameters params;
                params.propSpeed = link->propSpeed;
                PARALLEL_SendRemoteLinkMessage(node, msg, link, txDelay, &params);
            }
        }
        else {
            ERROR_ReportError("Destination of the link is not set\n");
        }
#else //elseParallel
        ERROR_ReportError("Destination of the link is not set\n");
#endif //endParallel
    }

    link->status               = LINK_IS_BUSY;
    link->stats.totalBusyTime += txDelay;

    txFinishedMsg = MESSAGE_Alloc(node,
                                  MAC_LAYER,
                                  0,
                                  MSG_MAC_TransmissionFinished);

    MESSAGE_SetInstanceId(txFinishedMsg, (short) interfaceIndex);
    MESSAGE_Send(node, txFinishedMsg, txDelay);
}

void LinkSendTaggedFrame(Node*       node,
                         Message*    msg,
                         LinkData*   link,
                         int         interfaceIndex,
                         Mac802Address sourceAddress,
                         Mac802Address nextHopAddress,
                         VlanId      vlanId,
                         TosType     priority,
                         Int64 effectiveBW) {

    // Outgoing frame header contains vlan tag.
    // So add vlan tag first

    MacHeaderVlanTag *tagHeader;

    MESSAGE_AddHeader(node, msg, sizeof(MacHeaderVlanTag), TRACE_VLAN);

    tagHeader = (MacHeaderVlanTag*) MESSAGE_ReturnPacket(msg);

    tagHeader->tagProtocolId            = 0x8100;
    tagHeader->canonicalFormatIndicator = 0;
    tagHeader->userPriority             = priority;
    tagHeader->vlanIdentifier           = vlanId;

    LinkSendFrame(node,
                  msg,
                  link,
                  interfaceIndex,
                  sourceAddress,
                  nextHopAddress,
                  TRUE,
                  priority,
                  effectiveBW);
}


void LinkNetworkLayerHasPacketToSend(
    Node *node,
    int interfaceIndex)
{
    Message *newMsg = NULL;
    MacHWAddress nextHopHWAddr;

    Mac802Address sourceAddr;
    Mac802Address macnextHopAddr;
    int networkType;
    TosType priority;
    Int64 effectiveBW = 0;

    LinkData *link = (LinkData *)node->macData[interfaceIndex]->macVar;
#ifdef ADDON_BOEINGFCS
    if (NetworkCesIncIsEnable(node, interfaceIndex)&&
       node->macData[interfaceIndex]->macProtocol == MAC_PROTOCOL_CES_EPLRS)
    {
        link = MacCesEplrsGetMacVarLink(node,
            node->macData[interfaceIndex]);
    }
#endif

    MacData *thisMac = link->myMacData;

    BOOL isSendingTaggedFrame =
        (thisMac->vlan != NULL && thisMac->vlan->sendTagged);

    if (link->status == LINK_IS_BUSY) {
        if (DEBUG) {
            printf("    channel is busy, so have to wait\n");
        }

        return;
    }

    assert(link->status == LINK_IS_IDLE);

    if (DEBUG) {
        printf("    channel is idle\n");
    }


    ConvertVariableHWAddressTo802Address(node,
                                   &node->macData[interfaceIndex]->macHWAddr,
                                    &sourceAddr);

    MAC_OutputQueueDequeuePacket(node,
                                 interfaceIndex,
                                 &newMsg,
                                 &nextHopHWAddr,
                                 &networkType,
                                 &priority);

    ConvertVariableHWAddressTo802Address(node,
                                    &nextHopHWAddr,
                                    &macnextHopAddr);

    assert(newMsg != NULL);

    // Check BG traffic is in this interface.
    if (thisMac->bgMainStruct)
    {
        // Calculate total BW used by the BG traffic.
        int bgUtilizeBW = BgTraffic_BWutilize(node,
                                              thisMac,
                                              priority);

        // Calculate the effective BW will be used by the real traffic.
        effectiveBW = thisMac->bandwidth - bgUtilizeBW;

        if (effectiveBW < 0)
        {
            effectiveBW = 0;
        }
    }
    else
    {
        effectiveBW = thisMac->bandwidth;
    }

    // Handle case when link bandwidth is 0.  Here, we just drop the frame.
    if (effectiveBW == 0)
    {
        if (DEBUG) {
            printf("    bandwidth is 0, so drop frame\n");
        }
#ifdef ADDON_DB
        HandleMacDBEvents(
                          node,
                          newMsg,
                          node->macData[interfaceIndex]->phyNumber,
                          interfaceIndex,
                          MAC_Drop,
                          node->macData[interfaceIndex]->macProtocol,
                          TRUE,
                          "No Effective Bandwidth");
#endif

        if (node->macData[interfaceIndex]->macStats)
        {
            node->macData[interfaceIndex]->stats->
                AddFrameDroppedSenderDataPoints(node,
                                         link->destNodeId,
                                         interfaceIndex,
                                         MESSAGE_ReturnPacketSize(newMsg));
        }

        MESSAGE_Free(node, newMsg);

        if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE) {
            if (DEBUG) {
                printf("    there's more packets in the queue, "
                       "so try to send the next packet\n");
            }

            (*link->myMacData->sendFrameFn)(node, interfaceIndex);
        }

        return;
    }

    if (isSendingTaggedFrame)
    {
        LinkSendTaggedFrame(node,
                            newMsg,
                            link,
                            interfaceIndex,
                            sourceAddr,
                            macnextHopAddr,
                            thisMac->vlan->vlanId,
                            priority,
                            effectiveBW);
    }
    else {
        LinkSendFrame(node,
                      newMsg,
                      link,
                      interfaceIndex,
                      sourceAddr,
                      macnextHopAddr,
                      FALSE,
                      priority,
                      effectiveBW);
    }
}


static
void LinkMessageArrived(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    LinkData *link = (LinkData*)node->macData[interfaceIndex]->macVar; //AJS important

    LinkFrameHeader *header = (LinkFrameHeader *) MESSAGE_ReturnPacket(msg);

#ifdef ADDON_DB
    HandleMacDBEvents(node,
                      msg,
                      node->macData[interfaceIndex]->phyNumber,
                      interfaceIndex,
                      MAC_ReceiveFromPhy,
                      node->macData[interfaceIndex]->macProtocol);
#endif

    Mac802Address sourceAddr;
    Mac802Address destAddr;
    BOOL isVlanTag = FALSE;
    MacHeaderVlanTag tagInfo;

    MAC_CopyMac802Address(&sourceAddr, &header->sourceAddr);
    MAC_CopyMac802Address(&destAddr, &header->destAddr);
    isVlanTag = header->vlanTag;

    STAT_DestAddressType type;
    BOOL isMyAddr = FALSE;
    BOOL isAnyFrame = FALSE;

    MacLinkGetPacketProperty(node,
                             msg,
                             interfaceIndex,
                             type,
                             isMyAddr,
                             isAnyFrame);

    MESSAGE_RemoveHeader(node, msg, sizeof(LinkFrameHeader), TRACE_LINK);
    Int32 controlSize = sizeof(LinkFrameHeader);

    memset(&tagInfo, 0, sizeof(MacHeaderVlanTag));


    if (isVlanTag)
    {
        // Vlan tag present in header.
        // Collect vlan information and remove header
        MacHeaderVlanTag *tagHeader = (MacHeaderVlanTag *)
                                      MESSAGE_ReturnPacket(msg);

        memcpy(&tagInfo, tagHeader, sizeof(MacHeaderVlanTag));

        MESSAGE_RemoveHeader(
            node, msg, sizeof(MacHeaderVlanTag), TRACE_VLAN);
        controlSize += sizeof(MacHeaderVlanTag);
    }

    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %d received packet from node ",node->nodeId);
        MAC_PrintMacAddr(&sourceAddr);
        printf(" at time %s\n", clockStr);
        printf("    handing off packet to network layer\n");
    }

    if (isMyAddr || isAnyFrame)
    {
        if (node->macData[interfaceIndex]->macStats)
        {
            node->macData[interfaceIndex]->
                stats->AddFrameReceivedDataPoints(
                                           node,
                                           msg,
                                           type,
                                           controlSize,
                                           MESSAGE_ReturnPacketSize(msg),
                                           interfaceIndex);
        }

        // Either broadcast frame or frame for this station
#ifdef ADDON_DB
        HandleMacDBConnectivity(node, interfaceIndex, msg, MAC_ReceiveFromPhy);
        clocktype recvTime = node->getNodeTime();
        //Extract the delay info needed for the phy summary table
        StatsDBPhySummDelayInfo *delayInfo = (StatsDBPhySummDelayInfo*)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_DelayInfo);
        ERROR_Assert(delayInfo , "delayInfo not inserted by sender!");
        clocktype delay = recvTime - delayInfo -> sendTime;
        HandleStatsDBPhySummaryUpdateForMacProtocols(
            node,
            interfaceIndex,
            link->destNodeId,
            link->macOneHopData,
            delayInfo->txDelay,
            delay,
            FALSE);
#endif
#ifdef ADDON_BOEINGFCS 

        //SIP NODE for INC, SINCGARS
        //message from INC to SINCGARS Radio
        if (CesSincgarsSipIsEnable(node))
        {
            CesSincgarsSipHandlePacketFromLink(node, interfaceIndex, msg);
        }
        else
#endif
        {
            MacHWAddress srcHWAddr;
            Convert802AddressToVariableHWAddress(node,
                                                 &srcHWAddr,
                                                 &sourceAddr);

            MAC_HandOffSuccessfullyReceivedPacket(node,
                interfaceIndex,
                msg,
                &srcHWAddr);
        }
    }
    else
    {
        MESSAGE_Free(node, msg);
    }
}


static
void MessageArrivedFromLink(
    Node *node,
    int interfaceIndex,
    Message *msg)
{
    LinkData *link = (LinkData*)node->macData[interfaceIndex]->macVar;
#ifdef ADDON_BOEINGFCS
    if (NetworkCesIncIsEnable(node, interfaceIndex)&&
       node->macData[interfaceIndex]->macProtocol == MAC_PROTOCOL_CES_EPLRS)
    {
        link = MacCesEplrsGetMacVarLink(node,
            node->macData[interfaceIndex]);
    }
#endif

    if (link->phyType == WIRELESS) {
        // receiving end of wireless link can calculate/store propDelay
        WirelessLinkInfo* wli = (WirelessLinkInfo*) MESSAGE_ReturnInfo(msg);
        link->myMacData->propDelay = wli->propDelay;
        LinkMessageArrived(node, interfaceIndex, msg);
    }
#ifdef WIRELESS_LIB
    else if (link->phyType == MICROWAVE) {

        WirelessLinkInfo* wli = (WirelessLinkInfo*) MESSAGE_ReturnInfo(msg);
        link->myMacData->propDelay = wli->propDelay;
        WirelessLinkMessageArrivedFromLink(node, interfaceIndex, msg);
    }
    else if (link->phyType == SATELLITE) {

        SatelliteLinkInfo* wli = (SatelliteLinkInfo*) MESSAGE_ReturnInfo(msg);
        link->myMacData->propDelay = wli->propDelay;
        SatelliteLinkMessageArrivedFromLink(node, interfaceIndex, msg);
    }
#endif // WIRELESS_LIB
    else if (link->phyType == WIRED) {
        LinkMessageArrived(node, interfaceIndex, msg);

    }
}


static
void TransmissionFinished(Node* node, int interfaceIndex, Message* msg) {

    LinkData *link = NULL;

#ifdef ADDON_BOEINGFCS
    if (MacCesEplrsChangeLinkAndMacStatus(node, interfaceIndex))
    {
        MESSAGE_Free(node, msg);
        return;
    }
#endif

    link = (LinkData *)node->macData[interfaceIndex]->macVar;

    assert(link != NULL);
    assert(link->status == LINK_IS_BUSY);

    link->status = LINK_IS_IDLE;

    if (DEBUG) {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %d finished transmitting packet at time %s\n",
                node->nodeId, clockStr);
    }

    if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE) {
        if (DEBUG) {
            printf("    there's more packets in the queue, "
                   "so try to send the next packet\n");
        }

        (*link->myMacData->sendFrameFn)(node, interfaceIndex);
    }
    MESSAGE_Free(node, msg);
}

static
void ReturnLinkParameters(
    Node* node,
    LinkData* link,
    const NodeInput   *nodeInput,
    Address* address,
    MacLinkType* phyType,
    int* headerSizeInBits,
    Int64* bandwidth,
    BOOL* macStats,
    clocktype* propDelay,
    double* propSpeed)
{
    BOOL wasFound;
    BOOL readValue = FALSE;
    char yesOrNo[MAX_STRING_LENGTH];
    char phyTypeString[MAX_STRING_LENGTH];
    char addrStr[MAX_STRING_LENGTH];
    Int32 interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(
                               node,
                               *address);

    IO_ConvertIpAddressToString(address, addrStr);

    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "LINK-PHY-TYPE",
        &wasFound,
        phyTypeString);

    if (!wasFound || strcmp(phyTypeString, "WIRED") == 0)
    {
        *phyType = WIRED;
    }
    else if (strcmp(phyTypeString, "WIRELESS") == 0)
    {
        *phyType = WIRELESS;
    }
    else if (strcmp(phyTypeString, "MICROWAVE") == 0)
    {
        *phyType = MICROWAVE;
    }
    else if (strcmp(phyTypeString, "SATELLITE") == 0)
    {
        *phyType = SATELLITE;
    }
    else
    {
        ERROR_ReportError("Unknown link type for LINK-PHY-TYPE\n");
    }

    IO_ReadInt(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "LINK-HEADER-SIZE-IN-BITS",
        &wasFound,
        headerSizeInBits);

    if (!wasFound)
    {
        *headerSizeInBits = DEFAULT_HEADER_SIZE_IN_BITS;
    }
    else if (*headerSizeInBits <= 0)
    {
        char errorStr[MAX_STRING_LENGTH];

        sprintf(errorStr,
                "LINK-HEADER-SIZE-IN-BITS for %s needs to be > 0.\n",
                addrStr);
        ERROR_ReportError(errorStr);
    }

    if (*phyType != SATELLITE)
    {
        IO_ReadInt64(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "LINK-BANDWIDTH",
            &wasFound,
            bandwidth);

        if (!wasFound)
        {
            char errorStr[MAX_STRING_LENGTH];

            sprintf(errorStr, "LINK-BANDWIDTH for %s was not specified.\n",
                    addrStr);
            ERROR_ReportError(errorStr);
        }
        else if (bandwidth < 0)
        {
            char errorStr[MAX_STRING_LENGTH];
            sprintf(errorStr, "LINK-BANDWIDTH for %s needs to be >= 0.\n",
                    addrStr);
            ERROR_ReportError(errorStr);
        }
    }

    IO_ReadBool(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "MAC-LAYER-STATISTICS",
        &wasFound,
        &readValue);

    if (!wasFound || !readValue)
    {
        *macStats = FALSE;
    }
    else if (readValue)
    {
        *macStats = TRUE;
    }
    else
    {
        ERROR_ReportError("Expecting YES or NO for MAC-LAYER-STATISTICS\n");
    }
#ifdef ADDON_DB
    if (*macStats == FALSE)
    {
        if (node->partitionData->statsDb)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createMacAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB MAC_Aggregate table requires\n"
                    " MAC-LAYER-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsSummaryTable->createMacSummaryTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB MAC_Summary table requires\n"
                    " MAC-LAYER-STATISTICS to be set to YES\n");
            }
        }
    }
#endif
    if (*phyType == WIRED)
    {
        IO_ReadTime(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "LINK-PROPAGATION-DELAY",
            &wasFound,
            propDelay);

        if (!wasFound)
        {
            char errorStr[MAX_STRING_LENGTH];

            sprintf(errorStr,
                    "LINK-PROPAGATION-DELAY for %s was not specified.\n",
                    addrStr);
            ERROR_ReportError(errorStr);

        }
        else if (*propDelay < 0)
        {
            char errorStr[MAX_STRING_LENGTH];

            sprintf(errorStr,
                    "LINK-PROPAGATION-DELAY for %s needs to be >= 0.\n",
                    addrStr);
            ERROR_ReportError(errorStr);
        }
    }
    else if (*phyType == WIRELESS || *phyType == MICROWAVE || *phyType == SATELLITE)
    {
        // Read the propagation speed if configured
        IO_ReadDouble(
             node,
             node->nodeId,
             interfaceIndex,
             nodeInput,
             "LINK-PROPAGATION-SPEED",
             &wasFound,
             propSpeed);

        if (!wasFound) {
           *propSpeed = SPEED_OF_LIGHT;
        }
        else if (*propSpeed <= 0)
        {
            char errorStr[MAX_STRING_LENGTH];

            sprintf(errorStr,
                    "LINK-PROPAGATION-SPEED for %s needs to be > 0.\n",
                    addrStr);
            ERROR_ReportError(errorStr);
        }

        link->propSpeed = *propSpeed;
    }

    if (*phyType == MICROWAVE)
    {
#ifdef WIRELESS_LIB
        WirelessLinkInitialize(node, link, address, nodeInput);
#else // WIRELESS_LIB
        ERROR_ReportMissingLibrary("MICROWAVE", "Wireless");
#endif // WIRELESS_LIB
    }

    if (*phyType == SATELLITE)
    {
 #ifdef WIRELESS_LIB
        SatelliteLinkInitialize(node, link, address, nodeInput);
 #else // WIRELESS_LIB
        ERROR_ReportMissingLibrary("SATELLITE", "Wireless");
 #endif // WIRELESS_LIB
    }
}

void LinkInit(
    Node*             node,
    const NodeInput*  nodeInput,
    Address*          address,
    int               interfaceIndex,
    int               remoteInterfaceIndex,
    const NodeId      nodeId1,
     Mac802Address linkAddress1,
    const NodeId      nodeId2,
     Mac802Address linkAddress2)
{
    BOOL        macStats;
    clocktype   propDelay;
    double      propSpeed = 0;
    int         headerSizeInBits;
    Int64       bandwidth;
    LinkData*   link = (LinkData*)MEM_malloc(sizeof(LinkData));
    MacData*    thisMac;
    MacLinkType phyType;

    NodeId      theOtherNode        = 0;
    Mac802Address myLinkAddress;
    Mac802Address theOtherLinkAddress;

    link->isPointToPointLink = TRUE;

    ReturnLinkParameters(node,
                         link,
                         nodeInput,
                         address,
                         &phyType,
                         &headerSizeInBits,
                         &bandwidth,
                         &macStats,
                         &propDelay,
                         &propSpeed);

    if (node->nodeId == nodeId1)
    {

        MAC_CopyMac802Address(&myLinkAddress,&linkAddress1);
        theOtherNode        = nodeId2;

        MAC_CopyMac802Address(&theOtherLinkAddress,&linkAddress2);
    }
    else if (node->nodeId == nodeId2)
    {

        MAC_CopyMac802Address(&myLinkAddress,&linkAddress2);
        theOtherNode        = nodeId1;

         MAC_CopyMac802Address(&theOtherLinkAddress,&linkAddress1);
    }
    else
    {
        ERROR_ReportError("Bad LinkInit() call\n");
    }

    assert(node->macData[interfaceIndex]->interfaceStatusHandlerList != NULL);

    thisMac = node->macData[interfaceIndex];

#ifdef ADDON_BOEINGFCS
    if (thisMac->macProtocol == MAC_PROTOCOL_CES_EPLRS)
    {
        thisMac->macVarLink      = (void*)link;
        thisMac->bandwidth       = bandwidth;
    }
    else
    {
#endif

        thisMac->macProtocol     = MAC_PROTOCOL_LINK;
        thisMac->interfaceIndex  = interfaceIndex;
        thisMac->macVar          = (void*)link;
        thisMac->mplsVar         = NULL;
        thisMac->promiscuousMode = FALSE;
        thisMac->bandwidth       = bandwidth;
        thisMac->macStats        = macStats;

#ifdef ADDON_BOEINGFCS
    }
#endif


#ifdef ADDON_DB
    // if interface is already enabled, don't trigger a DB update
    StatsDb* db = node->partitionData->statsDb;
    BOOL alreadyEnabled = NetworkIpInterfaceIsEnabled(node, interfaceIndex);
    if (db != NULL && db->statsSummaryTable->createPhySummaryTable)
    {
        link->macOneHopData =
            new std::map<int,MacOneHopNeighborStats>();
    }
#endif

    MAC_EnableInterface(node, interfaceIndex);

#ifdef ADDON_DB
    if (!alreadyEnabled)
    {
        // Record this in the interface status table
        STATSDB_HandleInterfaceStatusTableInsert(node, TRUE, interfaceIndex);
#if 0
        if (node->partitionData->statsDb->statsStatusTable->createInterfaceStatusTable)
        {
            StatsDBInterfaceStatus interfaceStatus;
            char interfaceAddrStr[100];
            NetworkIpGetInterfaceAddressString(node, interfaceIndex, interfaceAddrStr);
            interfaceStatus.m_triggeredUpdate = TRUE;
            interfaceStatus.m_address = interfaceAddrStr;
            interfaceStatus.m_interfaceEnabled =
                NetworkIpInterfaceIsEnabled(node, interfaceIndex);

            STATSDB_HandleInterfaceStatusTableInsert(node, interfaceStatus);
        }
#endif
    }
#endif

    link->myMacData             = thisMac;
    link->phyType               = phyType;
    link->propSpeed             = propSpeed;
    link->status                = LINK_IS_IDLE;
    link->stats.totalBusyTime   = 0;
    link->destNodeId            = theOtherNode;
    MAC_CopyMac802Address(&link->destLinkAddress,&theOtherLinkAddress);
    link->destInterfaceIndex    = remoteInterfaceIndex;
    link->headerSizeInBits      = headerSizeInBits;
    link->partitionIndex        = 0;
    
#ifdef ADDON_BOEINGFCS
    link->MessageSipBuffer = NULL;
    link->MessageSipTimer = NULL;
#endif

    if (phyType == WIRED) {
        thisMac->propDelay = propDelay;
#ifdef PARALLEL //Parallel
        PARALLEL_SetProtocolIsNotEOTCapable(node);
        PARALLEL_SetMinimumLookaheadForInterface
            (node, propDelay + (clocktype)
             (link->headerSizeInBits * SECOND / thisMac->bandwidth));
    }
    else {
        // There really is no minimum in this case, because there's
        // no way of knowing whether the nodes are mobile, so we
        // use the txDelay of the header.
        PARALLEL_SetProtocolIsNotEOTCapable(node);
        PARALLEL_SetMinimumLookaheadForInterface
            (node, (clocktype)
             (link->headerSizeInBits * SECOND / thisMac->bandwidth));
#endif //endParallel
    }

#ifdef PARALLEL //Parallel
    link->partitionIndex = PARALLEL_GetPartitionForNode(theOtherNode);
#endif //endParallel

    if (link->partitionIndex == node->partitionData->partitionId) {
        link->dest = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash,
                                                theOtherNode);
    }
    else {
        link->dest = NULL;
    }

    // Now that the bandwidth has been set, configure the output queue
    NetworkIpCreateQueues(node, nodeInput, interfaceIndex);

    // assign function pointers with send and receive functions
    link->myMacData->sendFrameFn    = &LinkNetworkLayerHasPacketToSend;
    link->myMacData->receiveFrameFn = &MessageArrivedFromLink;

}


void LinkLayer(Node *node, int interfaceIndex, Message *msg) {
    LinkData *link = (LinkData *)node->macData[interfaceIndex]->macVar;

#ifdef ADDON_BOEINGFCS
    if (NetworkCesIncIsEnable(node, interfaceIndex) &&
        node->macData[interfaceIndex]->macProtocol == MAC_PROTOCOL_CES_EPLRS)
    {
        link = MacCesEplrsGetMacVarLink(node,
            node->macData[interfaceIndex]);
    }
#endif

    switch (msg->eventType) {
        case MSG_MAC_FromNetwork: {
            if (DEBUG) {
                char clockStr[20];
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %d received packet to send from network layer "
                       "at time %s\n",
                        node->nodeId, clockStr);
            }

            (* link->myMacData->sendFrameFn)(node, interfaceIndex);
            break;
        }

        case MSG_MAC_LinkToLink: {
            (* link->myMacData->receiveFrameFn)(node, interfaceIndex, msg);
            break;
        }

        case MSG_MAC_TransmissionFinished: {
            TransmissionFinished(node, interfaceIndex, msg);
            break;
        }
#ifdef ADDON_BOEINGFCS
        case MSG_MAC_SipBufferTimer: {
            CesSincgarsSipBufferTimer(node, interfaceIndex, msg);
            break;
        }
#endif

        default: {
            assert(FALSE); abort();
        }
    }
}


void LinkFinalize(Node *node, int interfaceIndex) {
    LinkData* link = (LinkData*)node->macData[interfaceIndex]->macVar;
    double linkUtilization;
    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];

    if (node->macData[interfaceIndex]->macStats == FALSE) {
        return;
    }

    sprintf(buf, "Destination = %u", link->destNodeId);
    IO_PrintStat(node, "MAC", "Link", ANY_DEST, interfaceIndex, buf);

    if (node->getNodeTime() == 0) {
        linkUtilization = 0;
    }
    else {
        linkUtilization = (double) link->stats.totalBusyTime /
                          (double) node->getNodeTime();
    }

    sprintf(buf, "Link Utilization = %f", floor(linkUtilization * 1000000 + 0.5) / 1000000);
    IO_PrintStat(node, "MAC", "Link", ANY_DEST, interfaceIndex, buf);

    if (node->macData[interfaceIndex]->macStats)
    {
        node->macData[interfaceIndex]->stats->Print(node,
                                                    "MAC",
                                                    "Link",
                                                    ANY_DEST,
                                                    interfaceIndex);
    }

#ifdef ENTERPRISE_LIB
    // Release vlan info structure if allocated
    MacReleaseVlanInfoForThisInterface(node, interfaceIndex);
#endif // ENTERPRISE_LIB

#ifdef ADDON_DB
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL && db->statsSummaryTable->createPhySummaryTable)
    {
        delete(link->macOneHopData);
    }
#endif
}

//--------------------------------------------------------------------------
// FUNCTION   :: MacLinkGetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Return packet properties
// PARAMETERS :: Node* node
//                   Node which received the message.
//               Message* msg
//                   The sent message
//               Int32 interfaceIndex
//                   The interface index on which packet was received
//               STAT_DestAddressType& type
//                   Sets the traffic type
//               BOOL& isMyFrame
//                   Set TRUE if msg  is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void MacLinkGetPacketProperty(Node* node,
                              Message* msg,
                              Int32 interfaceIndex,
                              STAT_DestAddressType& type,
                              BOOL& isMyFrame,
                              BOOL& isAnyFrame)
{
    if (msg != NULL)
    {
        LinkFrameHeader* header =
                                (LinkFrameHeader*)MESSAGE_ReturnPacket(msg);

        MacHWAddress destHWAddr;
        Convert802AddressToVariableHWAddress(node,
                                             &destHWAddr,
                                             &header->destAddr);

        if (NetworkIpIsUnnumberedInterface(node, interfaceIndex))
        {
            isMyFrame = MAC_IsMyAddress(node, &destHWAddr);
        }
        else
        {
            MacHWAddress* myMacAddr = &node->macData[interfaceIndex]->
                                                                  macHWAddr;
            isMyFrame = MAC_IsIdenticalHWAddress(myMacAddr, &destHWAddr);
        }

        if (!isMyFrame)
        {
            isAnyFrame = MAC_IsBroadcastHWAddress(&destHWAddr);
        }

        if (isMyFrame || !isAnyFrame)
        {
            type = STAT_Unicast;
        }
        else
        {
            type = STAT_Broadcast;
        }
    }
}


#ifdef ADDON_DB
//--------------------------------------------------------------------------
// FUNCTION   :: MacLinkGetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Called by the API HandleMacDBEvents
// PARAMETERS :: Node* node
//                   Pointer to the node
//               Message* msg
//                   Pointer to the input message
//               Int32 interfaceIndex
//                   Interface index on which packet received
//               MacDBEventType eventType
//                   Receives the eventType
//               StatsDBMacEventParam& macParam
//                   Input StatDb event parameter
//               BOOL& isMyFrame
//                   set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void MacLinkGetPacketProperty(Node* node,
                              Message* msg,
                              Int32 interfaceIndex,
                              MacDBEventType eventType,
                              StatsDBMacEventParam& macParam,
                              BOOL& isMyFrame,
                              BOOL& isAnyFrame)
{
    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;

    char srcAdd[25];
    char destAdd[25];

    memset(srcAdd, 0, sizeof(char) * 25);
    memset(destAdd, 0, sizeof(char) * 25);

    Int32 controlSize = sizeof(LinkFrameHeader);
    BOOL isVlanTag = FALSE;
    BOOL isSwitchCtrlPacket = FALSE;

    if (msg != NULL)
    {
        LinkFrameHeader* header =
                              (LinkFrameHeader*)MESSAGE_ReturnPacket(msg);
        LinkData* link = (LinkData*) node->macData[interfaceIndex]->macVar;

        Convert802AddressToVariableHWAddress(node,
                                             &destHWAddr,
                                             &header->destAddr);
        Convert802AddressToVariableHWAddress(node,
                                             &srcHWAddr,
                                             &header->sourceAddr);

        if (NetworkIpIsUnnumberedInterface(node, interfaceIndex))
        {
            isMyFrame = MAC_IsMyAddress(node, &destHWAddr);
        }
        else
        {
            MacHWAddress* myMacAddr = &node->macData[interfaceIndex]->
                                                                  macHWAddr;
            isMyFrame = MAC_IsIdenticalHWAddress(myMacAddr, &destHWAddr);
        }

        if (!isMyFrame)
        {
            isAnyFrame = MAC_IsBroadcastHWAddress(&destHWAddr);
        }

        if (MAC_IsASwitch(node))
        {
            isMyFrame = TRUE;
            if (IsSwitchCtrlPacket(node, header->destAddr))
            {
                macParam.SetFrameType("CONTROL");
                macParam.SetHdrSize(0);
                isSwitchCtrlPacket = TRUE;
            }
        }

        if (!isSwitchCtrlPacket)
        {
            isVlanTag = header->vlanTag;
            if (isVlanTag)
            {
                controlSize += sizeof(MacHeaderVlanTag);
            }
            macParam.SetFrameType("DATA");
            macParam.SetHdrSize(controlSize);
        }

        Mac802AddressToStr(destAdd, &header->destAddr);
        macParam.SetDstAddr(destAdd);

        Mac802AddressToStr(srcAdd, &header->sourceAddr);
        macParam.SetSrcAddr(srcAdd);
    }
}
#endif

