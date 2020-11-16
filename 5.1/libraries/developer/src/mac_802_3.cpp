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
// PURPOSE: This model implements IEEE 802.3 which uses the CSMA/CD
// technique as the channel access technique.
//
// ASSUMPTIONS: 1. This implementation handles the backoff situatuion
//              using 'Truncated Binary Exponential Backoff' algorithm.
//              So under a heavy load, a station may capture the channel.
//              2. Frame will face same propagation delay for all the
//              destination stations. So distance is not a factor between
//              any pair of station.
//


#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "list.h"
#include "mac.h"
#include "mac_llc.h"
#include "mac_802_3.h"
#include "mac_arp.h"
#include "mac_background_traffic.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif
//--------------------------------------------------------------------------
//                   Mac 802.3 trace functions
//--------------------------------------------------------------------------

// Control comments output to the trace file
#define TraceComments 1

// Control self timer output to the trace file
#define TraceOwnTimer 0

// Debug option for full duplex
#define MAC_FULL_DUP_DEBUG 0

//  FUNCTION:  Mac802_3TraceReturnStationState
//  PURPOSE:   Gives state of a station
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//  RETURN TYPE: A single charecter to describe state.
//
static char Mac802_3TraceReturnStationState(
    Node* node,
    MacData802_3* mac802_3)
{
    switch (mac802_3->stationState)
    {
        case IDLE_STATE:
            return 'I';
        case TRANSMITTING_STATE:
            return 'T';
        case RECEIVING_STATE:
            return 'R';
        case YIELD_STATE:
            return 'Y';
        case BACKOFF_STATE:
            return 'B';
        default:
            return 'U';
    }
}


//  FUNCTION:  Mac802_3TraceWriteStationStatusHeader
//  PURPOSE:   Write portion of trace for station status.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               FILE* fp
//                  Pointer to trace file
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteStationStatusHeader(
    Node* node,
    MacData802_3* mac802_3,
    FILE* fp)
{
    fprintf(fp, " --- [%c : %2u: %4u]",
        Mac802_3TraceReturnStationState(node, mac802_3),
        mac802_3->collisionCounter,
        mac802_3->backoffWindow);
}




//  FUNCTION:  Mac802_3GetSrcAndDestMacAddrFromFrame
//  PURPOSE:   Gives source and destination Mac address of a frame.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               Message* msg
//                  Pointer to message
//               MacAddress* destMacAddr
//                  Pointer to collect destination Mac Address of frame
//                MacAddress* srcMacAddr
//                  Pointer to collect source Mac Address of frame
//  RETURN TYPE: None
//
static void Mac802_3GetSrcAndDestMacAddrFromFrame(
    Node* node,
    Message* msg,
    Mac802Address* destMacAddr,
    Mac802Address* srcMacAddr)
{
    unsigned char*  macEthernetFramePtr =
        (unsigned char *) MESSAGE_ReturnPacket(msg);

    ERROR_Assert(macEthernetFramePtr != NULL,
        "Mac802_3GetSrcAndDestMacAddrFromFrame: Frame not found\n");

    // Make the frame pointer to point to the destAddress part
    // 7 bytes for preamble and 1 byte for start frame delemeter
    macEthernetFramePtr += 8;

    // Collect destination Mac address
    memcpy(destMacAddr->byte, macEthernetFramePtr,
        MAC_ADDRESS_LENGTH_IN_BYTE);

    // Collect source Mac address
    macEthernetFramePtr += MAC_ADDRESS_LENGTH_IN_BYTE;
    memcpy(srcMacAddr->byte, macEthernetFramePtr,
        MAC_ADDRESS_LENGTH_IN_BYTE);
}


//  FUNCTION:  Mac802_3GetSrcAndDestAddrFromFrame
//  PURPOSE:   Gives source and destination IP address of a frame.
//              Its a overloaded function
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to MacData802_3
//               Message* msg
//                  Pointer to message
//                MacHWAddress* srcHwAddr
//                  Pointer to collect source Mac Address of frame
//                MacHWAddress* destHwAddr
//                  Pointer to collect destination Mac Address of frame
//  RETURN TYPE: None
//
void Mac802_3GetSrcAndDestAddrFromFrame(
    Node* node,
    Message* msg,
    MacHWAddress* srcHWAddr,
    MacHWAddress* destHWAddr)
{
    Mac802Address srcMacAddr;
    Mac802Address destMacAddr;

    // Collect source and destination mac address
    Mac802_3GetSrcAndDestMacAddrFromFrame(
                                node,
                                msg,
                                &destMacAddr,
                                &srcMacAddr);

    Convert802AddressToVariableHWAddress (
            node,
            srcHWAddr,
            &srcMacAddr);

    Convert802AddressToVariableHWAddress (
            node,
            destHWAddr,
            &destMacAddr);
    }


//  FUNCTION:  Mac802_3TraceWriteFileFormatDescription
//  PURPOSE:   The mac802_3.trace file may be optionally generated by
//             adding MAC-802.3-TRACE to the user configuration file.
//             It contains details of frame exchange and, additionally,
//             comments for exception  events.
//             The file uses an ad-hoc ascii format as described in
//             Mac802_3TraceWriteFileFormatDescription.
//             All trace calls are to Mac802_3Trace. Refer to that
//             function for  more details.
//             Write the header of the trace file describing output fields
//  PARAMETERS:  FILE* fp
//                  Pointer to trace file
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteFileFormatDescription(
    FILE* fp)
{
    fprintf(fp, "File: mac_802_3.trace\n"
                "\n"
                "Fields are space separated. The format of each line is:\n"
                "1.  Running serial number (for cross-reference)\n"
                "2.  Node ID at which trace is captured\n"
                "3.  Interface ID where trace is captured\n"
                "4.  Time in seconds\n"
                "5.  A character indicating S)end R)eceive or O)wnTimer\n"
                "6.  Status of transmission or received frame type\n"
                "    --- (separator)\n"
                "7.  [Station State : Num Collision : Collision Window]\n"
                "    Fields as necessary (depending on actions)\n");

    if (TraceOwnTimer)
    {
        fprintf(fp, "\n"
                    "Own Timer:\n"
                    "    Four fields describe current states\n"
                    "    Some additional comments describes the actions\n\n"
                    "    [Node Seq : Msg Seq : Flag : Timer]\n"
                    "    Node Seq -> Current Seq num maintained by node\n"
                    "    Msg Seq  -> Seq num carries by message\n"
                    "    Flag     -> Describes the backoff status\n"
                    "    Timer    -> Describes type of self timer\n");
    }

    if (TraceComments)
    {
        fprintf(fp, "\n"
                    "Additional comments are of the form:\n"
                    "    Node ID  Interface ID Current Time  "
                    "--- Free form comment\n");
    }
    fprintf(fp, "\n");
}


//  FUNCTION:  Mac802_3TraceWriteNodeAddrAsDotIP
//  PURPOSE:   Write the adress in dotted quad format
//  PARAMETERS:  NodeAddress address
//                  Addres of the node
//               FILE* fp
//                  Pointer to trace file
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteNodeAddrAsDotIP(
    NodeAddress address,
    FILE* fp)
{
    fprintf(fp, "[%02X.%02X.%02X.%02X]",
        (address & 0xff000000) >> 24,
        (address & 0xff0000) >> 16,
        (address & 0xff00) >> 8,
        (address & 0xff));
}



//  FUNCTION:  Mac802_3TraceWriteCommonHeader
//  PURPOSE:   Write portion of trace that is common to all packets
//  PARAMETERS:  NodeAddress address
//                  Addres of the node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               Message* msg
//                  Pointer to message
//               char *flag
//                  Flag
//               unsigned int serialNo
//                  Serial number
//               FILE* fp
//                  Pointer to trace file
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteCommonHeader(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    const char* flag,
    unsigned int serialNo,
    FILE* fp)
{
    char simTime[MAX_STRING_LENGTH];

    fprintf(fp, "%4u) ", serialNo);
    fprintf(fp, "%4u ", node->nodeId);
    fprintf(fp, "%3u  ", mac802_3->myMacData->interfaceIndex);

    TIME_PrintClockInSecond(node->getNodeTime(), simTime);
    fprintf(fp, "%s ", simTime);

    if (! strncmp(flag, "Collision", 9))
    {
        fprintf(fp, " %s", "Collision");
    }
    else
    {
        fprintf(fp, "%c ", *flag);
    }
}


//  FUNCTION:  Mac802_3TraceWriteStartTrHeader
//  PURPOSE:   Write portion of trace for start transmission message.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               Message* msg
//                  Pointer to message
//               FILE* fp
//                  Pointer to trace file
//               char *flag
//                  Flag
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteStartTrHeader(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    FILE* fp,
    const char* flag)
{
    if (!strcmp(flag, "S"))
    {
        fprintf(fp, "%8s", "Start");
        Mac802_3TraceWriteStationStatusHeader(node, mac802_3, fp);
    }
    else if (! strncmp(flag, "Collision", 9))
    {
        Mac802_3TraceWriteStationStatusHeader(node, mac802_3, fp);
        fprintf(fp, "%s", (flag + 10));
    }
}


//  FUNCTION:  Mac802_3TraceWriteEndTrHeader
//  PURPOSE:   Write portion of trace for end transmission message.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               Message* msg
//                  Pointer to message
//               FILE* fp
//                  Pointer to trace file
//               char *flag
//                  Flag
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteEndTrHeader(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    FILE* fp,
    const char* flag)
{

    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;

    if (!strcmp(flag, "S"))
    {
        fprintf(fp, "%8s", "End");
        Mac802_3TraceWriteStationStatusHeader(node, mac802_3, fp);
        return;
    }

    Mac802_3GetSrcAndDestAddrFromFrame(node, msg, &srcHWAddr, &destHWAddr);

    if (!MAC_IsBroadcastHWAddress(&destHWAddr))
    {
        fprintf(fp, "%8s", "Unicast");
        Mac802_3TraceWriteStationStatusHeader(node, mac802_3, fp);
        fprintf(fp, "  ");
        //Mac802_3TraceWriteNodeAddrAsDotIP(srcAddr, fp);
        for (int i = 0; i < srcHWAddr.hwLength -1; i++)
        {
            fprintf(fp,"%s-", decToHex(srcHWAddr.byte[i]));
        }
        fprintf(fp,"%s", decToHex(srcHWAddr.byte[srcHWAddr.hwLength - 1]));
        fprintf(fp, "%s", mac802_3->wasInBackoff ? "  back to BkOff" : "");
    }
    else
    {
        fprintf(fp, "%8s", "BrdCast");
        Mac802_3TraceWriteStationStatusHeader(node, mac802_3, fp);
        fprintf(fp, "%s", mac802_3->wasInBackoff ? "  back to BkOff" : "");
    }
}


//  FUNCTION:  Mac802_3TraceWriteSelfTimerHeader
//  PURPOSE:   Write portion of trace for self timers.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               Message* msg
//                  Pointer to message
//               FILE* fp
//                  Pointer to trace file
//               char *flag
//                  Flag
//  RETURN TYPE: None
//
static void Mac802_3TraceWriteSelfTimerHeader(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    FILE* fp,
    const char* flag)
{
    MAC802_3SelfTimer* info =
        (MAC802_3SelfTimer *) MESSAGE_ReturnInfo(msg);

    fprintf(fp, "%12s [%c : %3u: %4u][ %4d: %4d: %c: ",
            "---",
            Mac802_3TraceReturnStationState(node, mac802_3),
            mac802_3->collisionCounter,
            mac802_3->backoffWindow,
            mac802_3->seqNum, info->seqNum,
            mac802_3->wasInBackoff ? 'T' : 'F');

    switch (info->timerType)
    {
        case mac_802_3_TimerSendPacket:
            fprintf(fp, "%s] -- ", "SF");

            if (mac802_3->stationState == TRANSMITTING_STATE)
            {
                fprintf(fp, "%s ",
                    info->seqNum == mac802_3->seqNum ?
                    "Send Frm Achieved" : "Send Frm Cancled");
            }
            else if (mac802_3->stationState == RECEIVING_STATE)
            {
                fprintf(fp, "%s ", "Send Frm Cancled");
            }
            else if (mac802_3->stationState == IDLE_STATE)
            {
                fprintf(fp, "%s ", "Scheduled timer to send Frm");
            }
            break;

        case mac_802_3_ChannelIdle:
            fprintf(fp, "%s] -- ", "CI");

            if (mac802_3->stationState == IDLE_STATE)
            {
                fprintf(fp, "%s ",
                    mac802_3->msgBuffer == NULL ?
                    "Trying to Xmit" : "Trying to ReXmit");
            }
            else if (mac802_3->stationState == BACKOFF_STATE)
            {
                fprintf(fp, "%s ", "Trying to ReXmit");
            }
            else if (mac802_3->stationState == RECEIVING_STATE &&
                     mac802_3->wasInBackoff == TRUE)
            {
                fprintf(fp, "%s ", "Bkoff End in Recving");
            }
            else
            {
                fprintf(fp, "%s ", "Timer Cancled");
            }
            break;

        default:
            fprintf(fp, "%s ", "Unknown Timer");
            break;
    }
}


//  FUNCTION:  Mac802_3Trace
//  PURPOSE:   Common entry routine for trace.
//             Creates and writes to a file called "Mac802_3.trace".
//             Output is an internal ascii format with values of
//             interest described in
//             Mac802_3TraceWriteFileFormatDescription.
//             Besides frame specific fields, comments can be written
//             to trace by setting the flag parameter to any value
//             except "Send" or "Receive". In such cases, the message
//             parameter is ignored and can be NULL.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//               Message* msg
//                  Flag which is either "Send" or "Receive" or comment
//               FILE* fp
//                  File pointer
//  RETURN TYPE: None
//
static void Mac802_3Trace(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    const char* flag)
{
    static unsigned int count = 0;
    int eventType = MAC802_3_TRACE_UNKNOWN_EVENT;
    int interfaceIndex = mac802_3->myMacData->interfaceIndex;
    FILE* fp = NULL;

    if (! mac802_3->trace)
    {
        return;
    }

    if (msg != NULL)
    {
        eventType = msg->eventType;
    }

    if (eventType == MSG_MAC_TimerExpired && !TraceOwnTimer)
    {
        return;
    }

    if (count == 0)
    {
        fp = fopen("Mac802_3.trace", "w");
        ERROR_Assert(fp != NULL,
            "Mac_802_3_Trace: file initial open error.\n");
        Mac802_3TraceWriteFileFormatDescription(fp);
    }
    else
    {
        fp = fopen("Mac802_3.trace", "a");
        ERROR_Assert(fp != NULL,
            "Mac_802_3_Trace: file open error.\n");
    }

    if (!strncmp("802.3:", flag, 6))
    {
        if (TraceComments)
        {
            char simTime[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), simTime);

            fprintf(fp, "Node  %4d %3u  %s            --- %s\n",
                node->nodeId, interfaceIndex, simTime, (flag + 6));
        }
        fclose(fp);
        return;
    }

    count++;
    Mac802_3TraceWriteCommonHeader(
        node, mac802_3, msg, flag, count, fp);

    switch (eventType)
    {
        case MSG_MAC_StartTransmission:
            Mac802_3TraceWriteStartTrHeader(node, mac802_3, msg, fp, flag);
            break;

        case MSG_MAC_TransmissionFinished:
            Mac802_3TraceWriteEndTrHeader(node, mac802_3, msg, fp, flag);
            break;

        case MSG_MAC_TimerExpired:
            Mac802_3TraceWriteSelfTimerHeader(
                node, mac802_3, msg, fp, flag);
            break;

        default:
            break;
    } //switch

    fprintf(fp, "\n");
    fclose(fp);
}


//  FUNCTION:  Mac802_3TraceInit
//  PURPOSE:   Initialize trace setting from user configuration file
//  PARAMETERS:  Node* node
//                  Pointer to node
//               const NodeInput* nodeInput
//                  Pointer to node input
//              int interfaceIndex
//                  Particular interface of the node.
//               MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//  RETURN TYPE: None
//
static void Mac802_3TraceInit(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    MacData802_3* mac802_3)
{
    char yesOrNo[MAX_STRING_LENGTH];
    BOOL retVal = FALSE;

    // Initialize trace values for the node
    // <TraceType> is one of
    //      NO    the default if nothing is specified
    //      YES   an ascii format
    // Format is: MAC-802.3-TRACE  YES | NO
    //  Trace setting may be qualified for a node, interface or subnet
    //

    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "MAC-802.3-TRACE",
        &retVal,
        yesOrNo);

    if (retVal == TRUE)
    {
        if (!strcmp(yesOrNo, "NO"))
        {
            mac802_3->trace = FALSE;
        }
        else if (!strcmp(yesOrNo, "YES"))
        {
            mac802_3->trace = TRUE;
        }
        else
        {
            ERROR_Assert(FALSE,
                "Mac802_3TraceInit: "
                "Unknown value of MAC-802.3-TRACE in configuration file.\n"
                "Expecting YES or NO\n");
        }
    }
    else
    {
        mac802_3->trace = FALSE;
    }
}


//--------------------------------------------------------------------------
//                   Mac 802.3 utility functions
//--------------------------------------------------------------------------

// FUNCTION:  Mac802_3MaxValue
// PURPOSE:   Get maximum value from two integer.
// PARAMETERS:   int value1
//                  First integer
//              int value2
//                 Second integer
// RETURN TYPE: int
//
static int Mac802_3MaxValue(
    int value1,
    int value2)
{
    return value1 > value2 ? value1 : value2;
}


// FUNCTION:  Mac802_3MinValue
// PURPOSE:   Get miniimum value from two integer.
// PARAMETERS:   int value1
//                  First integer
//              int value2
//                 Second integer
// RETURN TYPE: int
//
static int Mac802_3MinValue(
    int value1,
    int value2)
{
    return value1 < value2 ? value1 : value2;
}


// FUNCTION:  Mac802_3SetSelfTimer
// PURPOSE:   Schedules Self Timers.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                 Pointer to 802.3 structure
//              MAC802_3TimerType timerType
//                  Type of timer going to schedule.
//              clocktype delay
//                  Amount of delay to be suffered by timer
// RETURN TYPE: NONE
//
static void Mac802_3SetSelfTimer(
    Node* node,
    MacData802_3* mac802_3,
    MAC802_3TimerType timerType,
    clocktype delay)
{
    Message* newMsg = NULL;
    MAC802_3SelfTimer* info = NULL;

    newMsg = MESSAGE_Alloc(node, MAC_LAYER, MAC_PROTOCOL_802_3,
                           MSG_MAC_TimerExpired);

    MESSAGE_SetInstanceId(
        newMsg, (short) mac802_3->myMacData->interfaceIndex);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(MAC802_3SelfTimer));
    info = (MAC802_3SelfTimer *) MESSAGE_ReturnInfo(newMsg);

    mac802_3->seqNum++;

    info->timerType = timerType;
    info->seqNum = mac802_3->seqNum;

    MESSAGE_Send(node, newMsg, delay);
}


// FUNCTION:  Mac802_3BroadcastMessage
// PURPOSE:   Places a message into transmission medium to broadcast.
//            This message will be received by all neighbor nodes.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//              int eventType
//                  Type of event to broadcast
// RETURN TYPE: NONE
//
static void Mac802_3BroadcastMessage(
    Node* node,
    Message* msg,
    MacData802_3* mac802_3,
    int eventType)
{
    Message* tempMsg = NULL;
    ListItem* tempListItem = NULL;
    SubnetMemberData* getNeighborInfo = NULL;

    // Set channel delay as propagation delay. If this is
    // a broadcast for jam transmission, add jam transmision
    // delay with it.

    clocktype channelDelay = mac802_3->myMacData->propDelay;

    if (eventType == MSG_MAC_JamSequence)
    {
        channelDelay += mac802_3->jamTrDelay;
    }


    // Send message to each neighbor

    ERROR_Assert(mac802_3->neighborList,
        "Mac802_3BroadcastMessage: Neighbor List not initialized");

    tempListItem = mac802_3->neighborList->first;

    if (tempListItem == NULL)
    {
        getNeighborInfo =
            (SubnetMemberData*)MEM_malloc(sizeof(SubnetMemberData));
        getNeighborInfo->node =NULL;
        getNeighborInfo->nodeId =  mac802_3->link->destNodeId;
        getNeighborInfo->interfaceIndex =
                mac802_3->link->destInterfaceIndex;
        getNeighborInfo->partitionIndex =
                mac802_3->link->partitionIndex;

        if (getNeighborInfo->partitionIndex != node->partitionData->partitionId) {

            if (MAC_FULL_DUP_DEBUG)
            {
                printf("%d: PARALLEL broadcast to %d\n", node->nodeId, mac802_3->link->destNodeId);
            }

            tempMsg = MESSAGE_Duplicate(node, msg);
            PARALLEL_SendRemoteLinkMessage(node, tempMsg,
                    mac802_3->link, channelDelay, NULL);
        }
        else {
            ERROR_ReportError("Destination of the link is not set\n");
        }
    }

#ifdef ADDON_DB
    if (eventType == MSG_MAC_TransmissionFinished)
    {
        HandleMacDBConnectivity(node,
            mac802_3->myMacData->interfaceIndex, msg, MAC_SendToPhy);
    }
#endif

    while (tempListItem)
    {
        // Get neighbor information
        getNeighborInfo = (SubnetMemberData *) tempListItem->data;

        // Duplicate frame stored in own buffer to send neighbors
        tempMsg = MESSAGE_Duplicate(node, msg);

        // Set Layer, Protocol, Event & InstanceId
        MESSAGE_SetLayer(tempMsg, MAC_LAYER, MAC_PROTOCOL_802_3);
        MESSAGE_SetEvent(tempMsg, (short)eventType);
        MESSAGE_SetInstanceId(
            tempMsg, (short) getNeighborInfo->interfaceIndex);

        // Send the message
        MESSAGE_Send(getNeighborInfo->node, tempMsg, channelDelay);

        // Get next neighbor
        tempListItem = tempListItem->next;
    }
}


// FUNCTION:  Mac802_3TryToSendNextFrame
// PURPOSE:   Tries to send next packet. This packet may present in
//            self queue of it dequeues a fresh packet from queue.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: NONE
//
static void Mac802_3TryToSendNextFrame(
    Node* node,
    MacData802_3* mac802_3)
{
    if (mac802_3->msgBuffer == NULL)
    {
        // Retrieve packet as own buffer is empty
        if (MAC_OutputQueueIsEmpty(
                node, mac802_3->myMacData->interfaceIndex) != TRUE)
        {
            (*mac802_3->myMacData->sendFrameFn)
                (node, mac802_3->myMacData->interfaceIndex);
        }
    }
    else
    {
        // Due to collision prevoius frame present in self queue.
        // But backoff timer expired earlier while this station is
        // receiving another frame. Try to retransmit it.
        Mac802_3SenseChannel(node, mac802_3);
    }
}


// FUNCTION:  Mac802_3SenseChannel
// PURPOSE:   Sense the channel. If idle it waits recovery period
//            before start to send any frame.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: NONE
//
void Mac802_3SenseChannel(
    Node* node,
    MacData802_3* mac802_3)
{
    if (mac802_3->stationState == IDLE_STATE)
    {
        mac802_3->stationState = YIELD_STATE;

        mac802_3->interFrameGapStartTime = node->getNodeTime();
        Mac802_3SetSelfTimer(
            node, mac802_3, mac_802_3_ChannelIdle,
            mac802_3->interframeGap);

        Mac802_3Trace(node, mac802_3, NULL,
                      "802.3: Channel Idle. Waiting for recovery time..");
    }
    else
    {
        // Channel is busy
        //Mac802_3Trace(node, mac802_3, NULL,
        //              "802.3: Sensing the Channel Busy");
    }
}


// FUNCTION:  Mac802_3GetInterframeDelay
// PURPOSE:   Returns the interframe delay
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: clocktype
//
static clocktype Mac802_3GetInterframeDelay(
    Node* node,
    MacData802_3* mac802_3)
{
    if (mac802_3->bwInMbps == MAC802_3_10BASE_ETHERNET)
    {
        // Interframe gap for 10 Mbps ethernet
        return (clocktype) MAC802_3_10BASE_ETHERNET_INTERFRAME_DELAY;
    }
    else if (mac802_3->bwInMbps == MAC802_3_100BASE_ETHERNET)
    {
        // Interframe gap for 100 Mbps ethernet
        return (clocktype) MAC802_3_100BASE_ETHERNET_INTERFRAME_DELAY;
    }
    else
    {
        // Interframe gap for gigabit ethernet
        return (clocktype) MAC802_3_1000BASE_ETHERNET_INTERFRAME_DELAY;
    }
}


// FUNCTION:  Mac802_3GetSlotTime
// PURPOSE:   Returns the Slot time
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: clocktype
//
static clocktype Mac802_3GetSlotTime(
    Node* node,
    MacData802_3* mac802_3)
{
    if (mac802_3->bwInMbps == MAC802_3_10BASE_ETHERNET)
    {
        // Slot time for 10 Mbps ethernet
        return (clocktype) MAC802_3_10BASE_ETHERNET_SLOT_TIME;
    }
    else if (mac802_3->bwInMbps == MAC802_3_100BASE_ETHERNET)
    {
        // Slot time for 100 Mbps ethernet
        return (clocktype) MAC802_3_100BASE_ETHERNET_SLOT_TIME;
    }
    else
    {
        // Slot time for gigabit ethernet
        return (clocktype) MAC802_3_1000BASE_ETHERNET_SLOT_TIME;
    }
}


// FUNCTION:  Mac802_3GetJamTrDelay
// PURPOSE:   Returns the Jam transmission time.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: clocktype
//
static clocktype Mac802_3GetJamTrDelay(
    Node* node,
    MacData802_3* mac802_3)
{
    return (clocktype)(8 * MAC802_3_LENGTH_OF_JAM_SEQUENCE * MICRO_SECOND /
                       mac802_3->bwInMbps);
}


//--------------------------------------------------------------------------
//                  Functions Process the outgoing frame
//--------------------------------------------------------------------------


// FUNCTION:  Mac802_3CreateFrame
// PURPOSE:   Creates frame from the retrieved packet from queue into
//            a temporary place.
// PARAMETERS:   Node* node
//                  Pointer to node
//              Message* msg
//                  Pointer to message
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//              MacAddress* nextHopAddress
//                  Mac Address of destination station
//              MacAddress* sourceAddr
//                  Mac Address of source station
//              TosType priority
//                  Priority of frame
// RETURN TYPE: NONE
//
void Mac802_3CreateFrame(
    Node* node,
    Message* msg,
    MacData802_3* mac802_3,
    unsigned short lengthOfData,
    Mac802Address* nextHopAddress,
    Mac802Address* sourceAddr,
    TosType priority)
{
    int lengthOfFrameExcludePad = 0;
    int padRequired = 0;

    unsigned char* frameHeader = NULL;
    int sizeOfFrameHeader = MAC802_3_SIZE_OF_HEADER;
    int padAndChecksumSize = 0;


    // Check whether padding is required or not.
    // If required then calculate size of pad.
    lengthOfFrameExcludePad =
        (lengthOfData + MAC802_3_SIZE_OF_HEADER + MAC802_3_SIZE_OF_TAILER
         - MAC802_3_SIZE_OF_PREAMBLE_AND_SF_DELIMITER);

    if (mac802_3->bwInMbps >= MAC802_3_1000BASE_ETHERNET)
    {
        // To make length of the frame 512 bytes for GB Ethernet
        padRequired = MAC802_3_MINIMUM_FRAME_LENGTH_GB_ETHERNET
                      - lengthOfFrameExcludePad;
    }
    else
    {
        // To make length of the frame 64 bytes
        padRequired =
            MAC802_3_MINIMUM_FRAME_LENGTH - lengthOfFrameExcludePad;
    }

    // Validate pad value
    padRequired = (padRequired <= 0) ? 0 : padRequired;

    padAndChecksumSize = MAC802_3_SIZE_OF_TAILER + padRequired;

    // If station sends tagged frame, modify header length
    if (mac802_3->myMacData->vlan != NULL
        && mac802_3->myMacData->vlan->sendTagged)
    {
        sizeOfFrameHeader += sizeof(MacHeaderVlanTag);

        // need to reduce the padAndChecksumSize with size of VlanTag?
    }


    // Convert IP datagram into Ethernet Frame. For this purpose header
    // and tailer is required to add with the IP datagram.
    // Note: But in this implementation, tailer &
    //       optional data padding will be added as virtual payload.
    //
    MESSAGE_AddHeader(
        node, msg, sizeOfFrameHeader, TRACE_802_3);

    // Get the packet
    frameHeader = (unsigned char *) MESSAGE_ReturnPacket(msg);

    // Assign 10101010... sequence to preamble part of frame header
    memset (frameHeader, 0xAA, 7);
    frameHeader = frameHeader + 7;

    // Assign Start Frame Delimeter
    memset (frameHeader, 0xAB, 1);
    frameHeader++;

    // Assign destAddr to the frame
    memcpy (frameHeader, nextHopAddress->byte, MAC_ADDRESS_LENGTH_IN_BYTE);
    frameHeader = frameHeader + MAC_ADDRESS_LENGTH_IN_BYTE;

    // Assign sourceAddr to the frame
    memcpy (frameHeader, sourceAddr->byte, MAC_ADDRESS_LENGTH_IN_BYTE);
    frameHeader = frameHeader + MAC_ADDRESS_LENGTH_IN_BYTE;

    // Check if vlan tagging required
    if (mac802_3->myMacData->vlan != NULL
        && mac802_3->myMacData->vlan->sendTagged)
    {
        MacHeaderVlanTag tagField;

        // Collect tag informations
        tagField.tagProtocolId = MAC802_3_VLAN_TAG_TYPE;
        tagField.canonicalFormatIndicator = 0;
        tagField.userPriority = priority;
        tagField.vlanIdentifier = mac802_3->myMacData->vlan->vlanId;

        // Assign vlan tag
        memcpy(frameHeader, &tagField, sizeof(MacHeaderVlanTag));
        frameHeader = frameHeader + sizeof(MacHeaderVlanTag);
    }

    // If the value of this field is greater than 1536, then this field
    // should contain the type of data. But as fragmentation is not active
    // this field always reflects the length of client data.
    memcpy (frameHeader, &lengthOfData, sizeof(unsigned short));
    frameHeader = frameHeader + sizeof(unsigned short);

    // Add pad & checksum to virtual payload
    MESSAGE_AddVirtualPayload(node, msg, padAndChecksumSize);
}


// FUNCTION:  Mac802_3RetrievePacketFromQIntoOwnBuffer
// PURPOSE:   Retrieve a packet from queue, convert it into frame
//            and store it into own buffer.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: TosType priority
// NOTE: this return type is used for full duplex.
//
static
TosType Mac802_3RetrievePacketFromQIntoOwnBuffer(
    Node* node,
    MacData802_3* mac802_3)
{
    int networkType;
    unsigned short lengthOfData;
    Message* msg = NULL;
    NodeAddress nextHopAddress;
    TosType priority = 0;
    Mac802Address srcMacAddr;
    Mac802Address destMacAddr;
    MacHWAddress destHWAddr;
    int packetType = 0;

    int interfaceIndex = mac802_3->myMacData->interfaceIndex;

    ConvertVariableHWAddressTo802Address(node,
                            &node->macData[interfaceIndex]->macHWAddr,
                            &srcMacAddr);

    BOOL flag = MAC_OutputQueueDequeuePacketForAPriority(
                    node,
                    interfaceIndex,
                    &priority,
                    &msg,
                    &nextHopAddress,
                    &destHWAddr,
                    &networkType,
                    &packetType);

    ConvertVariableHWAddressTo802Address(node,&destHWAddr,&destMacAddr);

    if (!flag && !packetType)
    {
        return priority;
    }

    if (!MAC_IsBroadcastHWAddress(&destHWAddr) &&
            MAC_IsMyAddress(node,interfaceIndex,&destHWAddr))

    {
        char errorBuf[MAX_STRING_LENGTH];
        sprintf(errorBuf,
            "Mac802_3RetrievePacketFromQIntoOwnBuffer: \n"
            "Node %d is trying to send packet to itself\n",
            node->nodeId);

        ERROR_Assert(FALSE, errorBuf);
    }


    if (packetType && !LlcIsEnabled(node, interfaceIndex))
    {
        lengthOfData = (unsigned short) PROTOCOL_TYPE_ARP;
        priority = IPTOS_PREC_INTERNETCONTROL;
    }
    else
    {
        lengthOfData = (unsigned short) MESSAGE_ReturnPacketSize(msg);
    }


    if (lengthOfData <= 0)
    {
        char errorBuf[MAX_STRING_LENGTH];

        sprintf(errorBuf,
            "Packet of length %d has come at Node %d\n",
            lengthOfData, node->nodeId);
        ERROR_ReportWarning(errorBuf);
        return priority;
    }

    // Create Frame using the retrieved packet
    Mac802_3CreateFrame(
        node, msg, mac802_3, lengthOfData,
        &destMacAddr, &srcMacAddr, priority);

    // Collect frame into own buffer

    MESSAGE_SetEvent(msg, MSG_MAC_TransmissionFinished);
    MESSAGE_SetLayer(msg, MAC_LAYER, MAC_PROTOCOL_802_3);
    MESSAGE_SetInstanceId(msg, (short) interfaceIndex);

    mac802_3->msgBuffer = msg;
    return priority;
}

// /**
// FUNCTION  ::  Mac802_3FullDupSend
// PURPOSE   ::  Sending frame to the other node in full duplex mode
// PARAMETERS::
//     +node : Node* :  Pointer to node
//     +interfaceIndex : int : Particular interface of the node.
//     +mac802_3 : MacData802_3* : Pointer to 802.3 structure.
//     +msg : Message* : Pointer to message.
//     +priority : TosType : Priority of frame.
//     +effectiveBW : Int64 : Effective bandwidth available
//     +frmType : MAC802_3FrameType : Type of the frame i.e Switch, ARP or Application packet
// RETURN TYPE:: void
// **/
void Mac802_3FullDupSend(Node* node,
                        int interfaceIndex,
                        MacData802_3* mac802_3,
                        Message* msg,
                        TosType priority,
                        Int64 effectiveBW,
                        MAC802_3FrameType frmType)
{
    Message*         txFinishedMsg = NULL;
    MacData*         thisMac = mac802_3->myMacData;

    if (mac802_3->stationState == TRANSMITTING_STATE)
    {
        // the channel is busy, so we return
        if (MAC_FULL_DUP_DEBUG)
        {
            printf("Node %u Interface index %d, channel busy so return"
                ". \n", node->nodeId, interfaceIndex);
        }
        return;
    }

    UInt64 frameSizeInBits = (UInt64)
            (8 * MESSAGE_ReturnPacketSize(msg));
    clocktype txDelay = (clocktype)
            (frameSizeInBits * MICRO_SECOND / mac802_3->bwInMbps);

    if (frmType == SWITCH || frmType == ARP)
    {
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

        // Handle case when link bandwidth is 0.Here, just drop the frame.
        if (effectiveBW == 0)
        {
            if (MAC_FULL_DUP_DEBUG)
            {
                printf("Switch node %u Interface index %d Bandwidth is 0,"
                    " so drop frame\n", node->nodeId, interfaceIndex);
            }
#ifdef ADDON_DB
            HandleMacDBEvents(
                node,
                msg,
                node->macData[interfaceIndex]->phyNumber,
                interfaceIndex,
                MAC_Drop,
                node->macData[interfaceIndex]->macProtocol,
                TRUE,
                "No Effective Bandwidth");
#endif
            Mac802Address srcAddr;
            Mac802Address destAddr;
            Mac802_3GetSrcAndDestMacAddrFromFrame(node,
                                                  msg,
                                                  &srcAddr,
                                                  &destAddr);
            Int32 destNodeId = GetNodeIdFromMacAddress(destAddr.byte);

            if (node->macData[mac802_3->myMacData->interfaceIndex]
                                                               ->macStats)
            {
                node->macData[mac802_3->myMacData->interfaceIndex]->stats->
                    AddFrameDroppedSenderDataPoints(
                        node,
                        destNodeId,
                        mac802_3->myMacData->interfaceIndex,
                        MESSAGE_ReturnPacketSize(msg));
            }

            mac802_3->fullDupStats->numBytesDropped +=
                                MESSAGE_ReturnPacketSize(msg);
            MESSAGE_Free(node, msg);
            mac802_3->fullDupStats->numFrameDropped++;
            return;
        }
    }

    if ((thisMac->bgMainStruct) && (thisMac->bandwidth > effectiveBW))
    {
        BgMainStruct* bgMainStruct = (BgMainStruct*)thisMac->bgMainStruct;
        BgRealTrafficDelay* bgRealDelay = bgMainStruct->bgRealDelay;

        // Calculate packet transmission delay if BG traffic is not there.
        clocktype normalDelay =(clocktype)
            (frameSizeInBits * MICRO_SECOND / thisMac->bandwidth);
        bgRealDelay[priority].delay += (txDelay - normalDelay);
        bgRealDelay[priority].occurrence ++;

        BgTraffic_SuppressByHigher(node, thisMac, priority, txDelay);
    }

    SubnetMemberData* getNeighborInfo;

    ListItem* tempListItem = mac802_3->neighborList->first;

    //if neighbor is on different partition
    if (tempListItem == NULL)
    {
        getNeighborInfo =
            (SubnetMemberData*)MEM_malloc(sizeof(SubnetMemberData));
        getNeighborInfo->node =NULL;
        getNeighborInfo->nodeId =  mac802_3->link->destNodeId;
        getNeighborInfo->interfaceIndex =
                mac802_3->link->destInterfaceIndex;
        getNeighborInfo->partitionIndex =
                mac802_3->link->partitionIndex;
    }
    else
    {
        getNeighborInfo = (SubnetMemberData *) tempListItem->data;
    }

    // set event type for parallel
    MESSAGE_SetEvent(msg, MSG_MAC_LinkToLink);
    MESSAGE_SetLayer(msg, MAC_LAYER, 0);
    MESSAGE_SetInstanceId(msg, (short) getNeighborInfo->interfaceIndex);

    Mac802_3UpdateStatsSend(node, msg, interfaceIndex);

    if (getNeighborInfo->node != NULL)
    {
        MESSAGE_Send(getNeighborInfo->node, msg,
            txDelay + thisMac->propDelay);

        if (MAC_FULL_DUP_DEBUG)
        {
            if (frmType == ARP)
            {
                printf("Node %u Interface index %d, ARP sending packet"
                ". \n", node->nodeId, interfaceIndex);
            }
            else
            {
                char clockStr[20];

                MacHWAddress srcHWAddr ;
                MacHWAddress destHWAddr ;

                Mac802_3GetSrcAndDestAddrFromFrame(node, msg,
                                                     &srcHWAddr,&destHWAddr);


                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u: Interface %d, Dest node %u, "
                    " interframe gap ""%" TYPES_64BITFMT "d"
                    " ns with a delay of ""%15" TYPES_64BITFMT "d"" ns",
                    node->nodeId, interfaceIndex,
                        getNeighborInfo->nodeId, mac802_3->interframeGap,
                    txDelay + thisMac->propDelay);
                printf(" time %s sec.\n", clockStr);
                printf("Full dup Frame contents:- Src:");
                MAC_PrintHWAddr(&srcHWAddr);
                printf(" Dest: ");
                MAC_PrintHWAddr(&destHWAddr);
                printf("\n");
            }
        }
    }
    else //different partition
    {
        if (getNeighborInfo->partitionIndex != node->partitionData->partitionId) {

            PARALLEL_SendRemoteLinkMessage(node, msg, mac802_3->link, txDelay, NULL);
            // Free neighbor info if it was alloc'd earlier in this function.
            if (tempListItem == NULL) {
                MEM_free(getNeighborInfo);
            }
        }
        else {
            ERROR_ReportError("Destination of the link is not set\n");
        }
    }

    // Change the state of the node
    mac802_3->stationState = TRANSMITTING_STATE;

#ifdef ADDON_DB
    HandleMacDBConnectivity(
        node,
        mac802_3->myMacData->interfaceIndex,
        msg,
        MAC_SendToPhy);

    HandleMacDBEvents(
        node,
        msg,
        node->macData[interfaceIndex]->phyNumber,
        interfaceIndex,
        MAC_SendToPhy,
        MAC_PROTOCOL_802_3);
#endif

    // Time the channel was busy
    mac802_3->fullDupStats->totalBusyTime += txDelay;

    txFinishedMsg = MESSAGE_Alloc(node,
                                  MAC_LAYER,
                                  0,
                                  MSG_MAC_TransmissionFinished);

    MESSAGE_SetInstanceId(txFinishedMsg, (short) interfaceIndex);

    MESSAGE_Send(node, txFinishedMsg, txDelay + mac802_3->interframeGap);

    if ((frmType == ARP) && MAC_FULL_DUP_DEBUG)
    {
        printf("Node %u Interface index %d, ARP setting timer"
                ". \n", node->nodeId, interfaceIndex);
    }
}

// /**
// FUNCTION::  Mac802_3FullDupNetworkLayerHasPacketToSend
// PURPOSE::   Dequeues packet from queue and process
//            to forward it for full duplex
// PARAMETERS::
//      +node : Node* : Pointer to node
//      +interfaceIndex : int : Interface Index
//
// RETURN TYPE:: void
// /**
// Note: Full duplex
//  stations do not defer to received traffic, nor abort transmission,
//  jam, backoff, and reschedule transmissions as part of Transmit Media
//  Access Management. Transmissions may be initiated whenever the station
//  has a frame queued.
static
void Mac802_3FullDupNetworkLayerHasPacketToSend(
    Node* node,
    int interfaceIndex)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;
    TosType priority;
    Int64 effectiveBW = 0;
    MacData *thisMac = mac802_3->myMacData;
    unsigned short lengthOfPacket;

    if (mac802_3->stationState == TRANSMITTING_STATE)
    {
        // the channel is busy, so we return
        if (MAC_FULL_DUP_DEBUG)
        {
            printf("Node %u Interface index %d, channel busy so return"
                ". \n", node->nodeId, interfaceIndex);
        }

        return;
    }

    priority = Mac802_3RetrievePacketFromQIntoOwnBuffer(node, mac802_3);

    if (!mac802_3->msgBuffer)
    {
        return;
    }

    lengthOfPacket = Mac802_3GetLengthOfPacket(mac802_3->msgBuffer);
    // The bandwidth allocated to this full duplex. Do we need to calculate
    //  the background traffic and the bandwidth loss for this.
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
        if (MAC_FULL_DUP_DEBUG)
        {
            printf("Node %u Interface index %d Bandwidth is 0, so drop "
                "frame\n", node->nodeId, interfaceIndex);
        }

        if (mac802_3->msgBuffer)
        {
#ifdef ADDON_DB
            HandleMacDBEvents(node,
                              mac802_3->msgBuffer,
                              node->macData[interfaceIndex]->phyNumber,
                              interfaceIndex,
                              MAC_Drop,
                              node->macData[interfaceIndex]->macProtocol,
                              TRUE,
                              "No Effective Bandwidth");
#endif
            Mac802Address srcAddr;
            Mac802Address destAddr;
            Mac802_3GetSrcAndDestMacAddrFromFrame(
                node,
                mac802_3->msgBuffer,
                &srcAddr,
                &destAddr);
            Int32 destNodeId = GetNodeIdFromMacAddress(destAddr.byte);

            if (node->macData[mac802_3->myMacData->interfaceIndex]
                                                             ->macStats)
            {
                node->macData[mac802_3->myMacData->interfaceIndex]->stats->
                    AddFrameDroppedSenderDataPoints(
                        node,
                        destNodeId,
                        mac802_3->myMacData->interfaceIndex,
                        MESSAGE_ReturnPacketSize(mac802_3->msgBuffer));
            }

            mac802_3->fullDupStats->numBytesDropped +=
                MESSAGE_ReturnPacketSize(mac802_3->msgBuffer);
            MESSAGE_Free(node, mac802_3->msgBuffer);
            mac802_3->msgBuffer = NULL;
            mac802_3->fullDupStats->numFrameDropped++;
        }

        if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE)
        {
            if (MAC_FULL_DUP_DEBUG)
            {
                printf("Node %u Interface index %d There's more packets "
                    "in the queue so try to send the next packet\n",
                    node->nodeId, interfaceIndex);
            }

            (mac802_3->myMacData->sendFrameFn)(node, interfaceIndex);
        }

        return;
    }

    if (lengthOfPacket == PROTOCOL_TYPE_ARP &&
        !LlcIsEnabled(node, interfaceIndex))
    {
        Mac802_3FullDupSend(node,
            interfaceIndex,
            mac802_3,
            mac802_3->msgBuffer,
            IPTOS_PREC_INTERNETCONTROL,
            0,
            ARP);
    }
    else
    {
        Mac802_3FullDupSend(node,
            interfaceIndex,
            mac802_3,
            mac802_3->msgBuffer,
            priority,
            effectiveBW,
            FULL_DUP);
    }
   mac802_3->msgBuffer = NULL;
}


// FUNCTION:  Mac802_3NetworkLayerHasPacketToSend
// PURPOSE:   Dequeues packet from queue and process to forward it
// PARAMETERS:   Node* node
//                  Pointer to node
//              int interfaceIndex
//                  Interface Index
// RETURN TYPE: NONE
//
static void Mac802_3NetworkLayerHasPacketToSend(
    Node* node,
    int interfaceIndex)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    if (mac802_3->isFullDuplex)
    {
        Mac802_3FullDupNetworkLayerHasPacketToSend(node,
            interfaceIndex);
        return;
    }

    if (mac802_3->stationState == IDLE_STATE)
    {
        // Check if there is any frame into own buffer
        if (mac802_3->msgBuffer != NULL)
        {
            // Frame present.
            // So no need to retrieve another.
            return;
        }

        // Retrieve the packet from queue into own buffer
        Mac802_3RetrievePacketFromQIntoOwnBuffer(node, mac802_3);

        // Sense the channel to transmit frame
        Mac802_3SenseChannel(node, mac802_3);
    }
}


// FUNCTION:  Mac802_3CompleteFrameTransmission
// PURPOSE:   Finishes to place frame into transmission medium.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: NONE
//
static void Mac802_3CompleteFrameTransmission(
    Node* node,
    MacData802_3* mac802_3)
{
    // Frame has already kept in own buffer by scheduling a self timer.
    // Now frame will be send to all neighbor by duplicating stored frame.

    ERROR_Assert(mac802_3->msgBuffer != NULL,
        "Mac802_3CompleteFrameTransmission: "
        "Trying to send frame from empty buffer.\n");

    Mac802_3UpdateStatsSend(
        node,
        mac802_3->msgBuffer,
        mac802_3->myMacData->interfaceIndex);

#ifdef ADDON_DB
    HandleMacDBEvents(
        node,
        mac802_3->msgBuffer,
        node->macData[mac802_3->myMacData->interfaceIndex]->phyNumber,
        mac802_3->myMacData->interfaceIndex,
        MAC_SendToPhy,
        MAC_PROTOCOL_802_3);
#endif

    // Send the message in the LAN, ie, to each neighbor
    Mac802_3BroadcastMessage(node,
                             mac802_3->msgBuffer,
                             mac802_3,
                             MSG_MAC_TransmissionFinished);


    // Station has sent the frame successfully.
    // Reset collision counter & Empty self buffer.

    // Reset collision counter and backoff window
    mac802_3->collisionCounter = 0;
    mac802_3->backoffWindow = MAC802_3_MIN_BACKOFF_WINDOW;

    Mac802_3Trace(node, mac802_3, mac802_3->msgBuffer, "S");

    // Empty the message buffer
    MESSAGE_Free(node, mac802_3->msgBuffer);
    mac802_3->msgBuffer = NULL;
}


// FUNCTION:  Mac802_3StartToSendFrame
// PURPOSE:   Starts to place the frame into transmission medium.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: NONE
//
static void Mac802_3StartToSendFrame(
    Node* node,
    MacData802_3* mac802_3)
{
    Message* startMsg = NULL;
    clocktype trDelay;
    UInt64 frameSizeInBits;
    char clockStr[MAX_STRING_LENGTH];
    char trcBuf[MAX_STRING_LENGTH];

    // Set state as Transmitting.
    mac802_3->stationState = TRANSMITTING_STATE;

    ERROR_Assert(mac802_3->msgBuffer != NULL,
        "Mac802_3StartToSendFrame: "
        "Trying to send frame from empty buffer.\n");

    // Broadcast a message of event MSG_MAC_StartTransmission. This
    // message is an indication of start frame for other stations.

    startMsg = MESSAGE_Alloc(node,
                             MAC_LAYER,
                             MAC_PROTOCOL_802_3,
                             MSG_MAC_StartTransmission);

    Mac802_3BroadcastMessage(
        node, startMsg, mac802_3, MSG_MAC_StartTransmission);

    Mac802_3Trace(node, mac802_3, startMsg, "S");

    // Free the startMsg
    MESSAGE_Free(node, startMsg);


    // Schedule a self-message of event MSG_MAC_TimerExpired with
    // timer mac_802_3_TimerSendPacket.
    // Delay of the timer is equal to transmission delay.

    frameSizeInBits = (UInt64)
            (8 * MESSAGE_ReturnPacketSize(mac802_3->msgBuffer));

    trDelay = (clocktype)
            (frameSizeInBits * MICRO_SECOND / mac802_3->bwInMbps);

    TIME_PrintClockInSecond(trDelay, clockStr);
    sprintf(trcBuf,
        "802.3: Frame Xmitting with Tr. Delay %s (s)",
        clockStr);
    Mac802_3Trace(node, mac802_3, NULL, trcBuf);

    Mac802_3SetSelfTimer(
        node, mac802_3, mac_802_3_TimerSendPacket, trDelay);
}


//--------------------------------------------------------------------------
//                 Functions Process the incoming frame
//--------------------------------------------------------------------------
// /**
// FUNCTION::  Mac802_3FullDuplexHandleReceivedFrame
// PURPOSE::   Processes on successfully received Frame. Forwards the
//            packet after retrieving it from frame if the frame is
//            intended for this node when the node is working in full duplex
//            mode.
// PARAMETERS::
//    +node : Node* : Pointer to node
//    +interfaceIndex : int :Interface Index
//    +msg : Message* : Pointer to message
// RETURN TYPE:: void
// **/
static
void Mac802_3FullDuplexHandleReceivedFrame(Node* node,
                                           int interfaceIndex,
                                           Message* msg)
{

    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;

    MacHeaderVlanTag tagInfo;
    unsigned short lengthOfPacket = 0;

#ifdef ADDON_DB
    HandleMacDBEvents(
        node,
        msg,
        node->macData[interfaceIndex]->phyNumber,
        interfaceIndex,
        MAC_ReceiveFromPhy,
        node->macData[interfaceIndex]->macProtocol);
#endif

    // Initialise tagInfo variable. It collects VLAN
        // information, if present in frame, for future use
    memset(&tagInfo, 0, sizeof(MacHeaderVlanTag));

    // Get destination and source address from the frame.
    Mac802_3GetSrcAndDestAddrFromFrame(node, msg, &srcHWAddr, &destHWAddr);


    // Get Length of data / type field.
    lengthOfPacket = Mac802_3GetLengthOfPacket(msg);
    BOOL isMyAddr = FALSE;

    if (NetworkIpIsUnnumberedInterface(node, interfaceIndex))
    {
        isMyAddr = (MAC_IsBroadcastHWAddress(&destHWAddr) ||
                        MAC_IsMyAddress(node, &destHWAddr));
    }
    else
    {
       isMyAddr = MAC_IsMyHWAddress(node, interfaceIndex, &destHWAddr);
    }
    // Checking whether the message is intended for this station
    if (isMyAddr)
    {
        Mac802_3ConvertFrameIntoPacket(node, interfaceIndex, msg, &tagInfo);

        // Check if Length of data / type field is ARP
        if (lengthOfPacket == PROTOCOL_TYPE_ARP &&
                    !LlcIsEnabled(node, interfaceIndex))
        {
            if (MAC_FULL_DUP_DEBUG)
            {
                char clockStr[20];
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u Interface index %d received ARP packet from"
                    " node :",node->nodeId,interfaceIndex);
                MAC_PrintHWAddr(&srcHWAddr);
                printf("at time %s  in full duplex mode\n", clockStr);
            }

            int arpPacket = 1;
            MAC_HandOffSuccessfullyReceivedPacket(
            node, interfaceIndex, msg, &srcHWAddr, arpPacket);

            return;
        }

        MAC_HandOffSuccessfullyReceivedPacket(
            node, interfaceIndex, msg, &srcHWAddr);


        if (MAC_FULL_DUP_DEBUG)
        {
            char clockStr[20];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("Node %u Interface index %d successfully received packet"
                "from node: ", node->nodeId, interfaceIndex);
            MAC_PrintHWAddr(&srcHWAddr);
                printf("at time %s  in full duplex mode\n", clockStr);
        }
    }
    // no need to handle promiscuous mode.
    else
    {
        if (MAC_FULL_DUP_DEBUG)
        {
            char clockStr[20];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("Node %u Interface index %d received packet from "
                "node:", node->nodeId, interfaceIndex);
             MAC_PrintHWAddr(&srcHWAddr);
            printf("at time %s dropped in full duplex mode\n", clockStr);
        }

        // Message for unknown destination. So ignore it.
        MESSAGE_Free(node, msg);
    }
}



// FUNCTION:  Mac802_3HandleReceivedFrame
// PURPOSE:   Processes on successfully received Frame. Forwards the
//            packet after retrieving it from frame if the frame is
//            intended for this node.
// PARAMETERS:   Node* node
//                  Pointer to node
//              int interfaceIndex
//                  Interface Index
//              Message* msg
//                  Pointer to message
// RETURN TYPE: NONE
//
static void Mac802_3HandleReceivedFrame(
    Node* node,
    int interfaceIndex,
    Message* msg)
{

    MacHeaderVlanTag tagInfo;
    unsigned short lengthOfPacket = 0;

#ifdef ADDON_DB
    HandleMacDBEvents(
        node,
        msg,
        node->macData[interfaceIndex]->phyNumber,
        interfaceIndex,
        MAC_ReceiveFromPhy,
        node->macData[interfaceIndex]->macProtocol);
#endif
    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    // Initialise tagInfo variable. It collects VLAN
    // information, if present in frame, for future use
    memset(&tagInfo, 0, sizeof(MacHeaderVlanTag));

    // Get destination and source address from the frame.
    Mac802_3GetSrcAndDestAddrFromFrame(node, msg, &srcHWAddr, &destHWAddr);


    // Get Length of data / type field.
    lengthOfPacket = Mac802_3GetLengthOfPacket(msg);
    BOOL isMyAddr = FALSE;

    if (NetworkIpIsUnnumberedInterface(node, interfaceIndex))
    {
        isMyAddr = (MAC_IsBroadcastHWAddress(&destHWAddr) ||
                        MAC_IsMyAddress(node, &destHWAddr));
    }
    else
    {
       isMyAddr = MAC_IsMyHWAddress(node, interfaceIndex, &destHWAddr);
    }
    // Checking whether the message is intended for this station
    if (isMyAddr)
    {
        Mac802_3UpdateStatsReceive(node, msg, interfaceIndex);

#ifdef ADDON_DB
        HandleMacDBConnectivity(node,
                                interfaceIndex,
                                msg,
                                MAC_ReceiveFromPhy);
#endif
        Mac802_3Trace(node, mac802_3, msg, "R");

        Mac802_3ConvertFrameIntoPacket(node, interfaceIndex, msg, &tagInfo);

        // Check if Length of data / type field is ARP
        if (lengthOfPacket == PROTOCOL_TYPE_ARP && !LlcIsEnabled(node, interfaceIndex))
        {

            Int32 arpPacket = 1;
            MAC_HandOffSuccessfullyReceivedPacket(
                node, interfaceIndex, msg, &srcHWAddr, arpPacket);
            return;
        }
        
        MAC_HandOffSuccessfullyReceivedPacket(
            node, interfaceIndex, msg, &srcHWAddr);

    }

    // If node is operating in promiscuous mode then let
    // Network layer sneak a peak at the packet
    else if (node->macData[interfaceIndex]->promiscuousMode)
    {
        Mac802_3UpdateStatsReceive(node, msg, interfaceIndex);

#ifdef ADDON_DB
        HandleMacDBConnectivity(node,
                                interfaceIndex,
                                msg,
                                MAC_ReceiveFromPhy);
#endif

        Mac802_3Trace(node, mac802_3, msg, "R");

        Mac802_3ConvertFrameIntoPacket(node, interfaceIndex, msg, &tagInfo);

        // Check if Length of data / type field is ARP
        if (lengthOfPacket == PROTOCOL_TYPE_ARP &&
            !LlcIsEnabled(node, interfaceIndex))
        {
            int arpPacket = PROTOCOL_TYPE_ARP;
            MAC_SneakPeekAtMacPacket(
                node, interfaceIndex, msg, srcHWAddr, destHWAddr, arpPacket);
           // ArpReceivePacket(node, msg, interfaceIndex);
            return;
        }
        MAC_SneakPeekAtMacPacket(
            node, interfaceIndex, msg, srcHWAddr, destHWAddr);

        MESSAGE_Free(node, msg);
    }
    else
    {
        // Message for unknown destination. So ignore it.
        MESSAGE_Free(node, msg);
    }
}


// FUNCTION:  Mac802_3GetLengthOfPacket
// PURPOSE:   Get Length of data / type field of the received frame .
// PARAMETERS: Message* msg
//                Pointer to message
// RETURN TYPE: unsigned short
//
unsigned short Mac802_3GetLengthOfPacket(Message *msg)
{
    unsigned short lengthOfPacket;
    unsigned char* frame = NULL;

    // Get frame size
    frame = (unsigned char *) MESSAGE_ReturnPacket(msg);
    frame = frame + (MAC802_3_SIZE_OF_HEADER - sizeof(unsigned short));

    memcpy(&lengthOfPacket, frame, sizeof(unsigned short));

    return lengthOfPacket;
}


// FUNCTION:  Mac802_3ConvertFrameIntoPacket
// PURPOSE:   Converts the received frame into packet.
// PARAMETERS:   Node* node
//                  Pointer to node
//              Message* msg
//                  Pointer to message
//              MacHeaderVlanTag* tagInfo
//                  Pointer to collect VLAN tag information
// RETURN TYPE: NONE
//
void Mac802_3ConvertFrameIntoPacket(
    Node* node,
    int interfaceIndex,
    Message* msg,
    MacHeaderVlanTag* tagInfo)
{
    unsigned short lengthOfFrame;
    unsigned short lengthOfPacket;
    unsigned char* frame = NULL;
    int headerSize = MAC802_3_SIZE_OF_HEADER;
    int padAndChecksumSize = 0;

    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    // Get frame size
    lengthOfFrame = (unsigned short) MESSAGE_ReturnPacketSize(msg);

    if (mac802_3->isFullDuplex)
    {
#ifdef ADDON_DB
        HandleMacDBConnectivity(node,
                                interfaceIndex,
                                msg,
                                MAC_ReceiveFromPhy);
#endif
        Mac802_3UpdateStatsReceive(node, msg, interfaceIndex);
    }

    // Get length of data present in frame
    frame = (unsigned char *) MESSAGE_ReturnPacket(msg);
    frame = frame + (MAC802_3_SIZE_OF_HEADER - sizeof(unsigned short));

    memcpy(&lengthOfPacket, frame, sizeof(unsigned short));

    if (lengthOfPacket == MAC802_3_VLAN_TAG_TYPE)
    {
        // Vlan tag present in frame header. So collect tag information
        // and move another 4 byte to get data length present in header.
        memcpy(tagInfo, frame, sizeof(MacHeaderVlanTag));
        headerSize += sizeof(MacHeaderVlanTag);

        frame = frame + sizeof(MacHeaderVlanTag);
        memcpy(&lengthOfPacket, frame, sizeof(unsigned short));
    }

    if (lengthOfPacket == PROTOCOL_TYPE_ARP && !LlcIsEnabled(node, interfaceIndex))
    {
        lengthOfPacket = sizeof(ArpPacket);
    }

    MESSAGE_RemoveHeader(node, msg, headerSize, TRACE_802_3);

    // Remove tailer and pad if any
    padAndChecksumSize = lengthOfFrame - headerSize - lengthOfPacket;
    ERROR_Assert(padAndChecksumSize >= 0, "Wrong length of checksum & pad!");
    msg->virtualPayloadSize -= padAndChecksumSize;
}


//--------------------------------------------------------------------------
//               Functions handle the collision situation
//--------------------------------------------------------------------------


// FUNCTION:  Mac802_3SendJamSequence
// PURPOSE:   Create and send Jam Sequence.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
// RETURN TYPE: NONE
//
static void Mac802_3SendJamSequence(
    Node* node,
    MacData802_3* mac802_3)
{
    // Create Jam sequence
    Message* jamMsg = MESSAGE_Alloc(node,
                                    MAC_LAYER,
                                    MAC_PROTOCOL_802_3,
                                    MSG_MAC_JamSequence);

    MESSAGE_PacketAlloc(
        node,
        jamMsg,
        MAC802_3_LENGTH_OF_JAM_SEQUENCE,
        TRACE_802_3);

    memset(MESSAGE_ReturnPacket(jamMsg),
           0,
           MAC802_3_LENGTH_OF_JAM_SEQUENCE);

    Mac802_3UpdateStatsSend(node,
                            jamMsg,
                            mac802_3->myMacData->interfaceIndex);

#ifdef ADDON_DB
    HandleMacDBEvents(
        node,
        jamMsg,
        node->macData[mac802_3->myMacData->interfaceIndex]->phyNumber,
        mac802_3->myMacData->interfaceIndex,
        MAC_SendToPhy,
        MAC_PROTOCOL_802_3);
#endif
    // Send this sequence to all neighbor
    Mac802_3BroadcastMessage(
        node, jamMsg, mac802_3, MSG_MAC_JamSequence);

    Mac802_3Trace(node, mac802_3, NULL,
                  "802.3: sending Jam Sequence");

    MESSAGE_Free(node, jamMsg);
}


// FUNCTION:  Mac802_3HandleBackoffSituation
// PURPOSE:   Checks collision counter and if excessive collision occures
//            it rejects frame stored in own buffer. Otherwise, it schedule
//            a message to retransmit it.
// PARAMETERS:   Node* node
//                  Pointer to node
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//              Message* msg
//                  Pointer to message
// RETURN TYPE: NONE
//
static void Mac802_3HandleBackoffSituation(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg)
{
    // Check whether excessive collision occured.
    // If so drop this frame and goto Idle state after sending Jam.

    if (mac802_3->collisionCounter >= MAC802_3_MAX_BACKOFF)
    {
        // Free the message stored in the buffer
#ifdef ADDON_DB
        HandleMacDBEvents(
            node,
            mac802_3->msgBuffer,
            node->macData[mac802_3->myMacData->interfaceIndex]->phyNumber,
            mac802_3->myMacData->interfaceIndex, 
            MAC_Drop,
            node->macData[mac802_3->myMacData->interfaceIndex]->macProtocol,
            TRUE,
            "Reach Max Backoff Attempts");
#endif
        Mac802Address srcAddr;
        Mac802Address destAddr;
        Mac802_3GetSrcAndDestMacAddrFromFrame(
            node,
            mac802_3->msgBuffer,
            &destAddr,
            &srcAddr);

        Int32 destNodeId = GetNodeIdFromMacAddress(destAddr.byte);

        if (node->macData[mac802_3->myMacData->interfaceIndex]->macStats)
        {
            node->macData[mac802_3->myMacData->interfaceIndex]->
                stats->AddFrameDroppedSenderDataPoints(
                                        node,
                                        destNodeId,
                                        mac802_3->myMacData->interfaceIndex,
                                        MESSAGE_ReturnPacketSize(
                                            mac802_3->msgBuffer));
        }

        MESSAGE_Free(node, mac802_3->msgBuffer);
        mac802_3->msgBuffer = NULL;

        // Frame is discarded due to excessive collision. So
        // increase the numFrameLossForCollision statistics
        mac802_3->stats.numFrameLossForCollision++;

        Mac802_3Trace(node, mac802_3, msg, "Collision   Frame Lost");

        // Reset collision counter, backoff window and wasInBackoff flag.
        mac802_3->collisionCounter = 0;
        mac802_3->backoffWindow = MAC802_3_MIN_BACKOFF_WINDOW;
        mac802_3->wasInBackoff = FALSE;

        // Change state.
        mac802_3->stationState = YIELD_STATE;

        // Goto Idle state.
        // Set self timer for this purpose with proper delay that
        // sufficient to send Jam sequence and recovery time.

        Mac802_3SetSelfTimer(
            node, mac802_3, mac_802_3_ChannelIdle,
            mac802_3->jamTrDelay);

        return;
    }

    // Maximum backoff limit yet to reach. Try to retransmit the frame.
    if (mac802_3->msgBuffer != NULL)
    {
        clocktype randSlotTime;
        int numSlotBackoffReqd;
        char trcBuf[MAX_STRING_LENGTH];
        char clockStr[MAX_STRING_LENGTH];

        // Determine random backoff slot.
        numSlotBackoffReqd = Mac802_3MaxValue(
            (RANDOM_nrand(mac802_3->seed) % mac802_3->backoffWindow), 1);

        randSlotTime = numSlotBackoffReqd * mac802_3->slotTime;

        // Collect trace information
        TIME_PrintClockInSecond(randSlotTime, clockStr);
        sprintf(trcBuf,
                "Collision   Bkoff %s", clockStr);
        Mac802_3Trace(node, mac802_3, msg, trcBuf);

        // Update backoff window
        mac802_3->backoffWindow = Mac802_3MinValue(
                ((mac802_3->backoffWindow + 1) * 2) - 1,
                MAC802_3_MAX_BACKOFF_WINDOW);

        // Schedule Backoff Timer
        Mac802_3SetSelfTimer(
            node, mac802_3, mac_802_3_ChannelIdle, randSlotTime);
    }
    else
    {
        char errorBuf[MAX_STRING_LENGTH];
        sprintf(errorBuf,
            "Mac802_3HandleBackoffSituation: "
            "While backoff message must be in message buffer\n");
        ERROR_Assert(FALSE, errorBuf);
    }
}

// /**
//  FUNCTION::  Mac802_3FullDupTransmissionFinished
//  PURPOSE::   Handling events in post transmission
//  PARAMETERS::
//      +node : Node* : Pointer to node
//      +interfaceIndex : int : Interface Index
//      +msg : Message* : Pointer to message
//  RETURN TYPE:: void
// **/
static
void Mac802_3FullDupTransmissionFinished(Node* node,
                                         int interfaceIndex,
                                         Message* msg)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    // We need to ascertain if the node is already in the transmission state
    if (mac802_3->stationState != TRANSMITTING_STATE)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf(errorString,
            "Node: %u, Interface index: %d, channel has not transmitted."
            "\n", node->nodeId, interfaceIndex);
        ERROR_ReportError(errorString);
    }

    // Lets change the state
    mac802_3->stationState = IDLE_STATE;

    if (MAC_OutputQueueIsEmpty(node, interfaceIndex) != TRUE)
    {
        if (MAC_FULL_DUP_DEBUG)
        {
            printf("Node: %u Interface index: %d There's more packets "
                   " in the queue, so try to send the next packet.\n",
                   node->nodeId, interfaceIndex);
        }

        (*mac802_3->myMacData->sendFrameFn)(node, interfaceIndex);
    }

    // freeing the message
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------------------------
//                         Layer related routine
//--------------------------------------------------------------------------
// /**
//  FUNCTION::  Mac802_3FullDuplexLayer
//  PURPOSE::   Models behavior of MAC layer for full duplex with
//             IEEE 802.3 standard on receiving message enclosed in msg.
//  PARAMETERS::
//      +node : Node* : Pointer to node
//      +interfaceIndex : int : Interface Index
//      +msg : Message* : Pointer to message
//  RETURN TYPE:: void
// **/
static
void Mac802_3FullDuplexLayer(
    Node* node,
    int interfaceIndex,
    Message* msg)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;
    switch (msg->eventType)
    {
        // receiving data from network layer
        case MSG_MAC_FromNetwork:
        {
            (*mac802_3->myMacData->sendFrameFn)(node, interfaceIndex);
            break;
        }

        // sending data to another full duplex node
        case MSG_MAC_FullDupToFullDup:
        {
            (*mac802_3->myMacData->receiveFrameFn)(node, interfaceIndex, msg);
            break;
        }

        // sending data to another fulle duplex node for parallel
        case MSG_MAC_LinkToLink: {
            (*mac802_3->myMacData->receiveFrameFn)(node, interfaceIndex, msg);
            break;
        }

        // do the post-transmission actions
        case MSG_MAC_TransmissionFinished:
        {
            Mac802_3FullDupTransmissionFinished(node, interfaceIndex, msg);
            break;
        }

        default:
        {
            char errorStr[MAX_STRING_LENGTH];
            sprintf(errorStr, "Node %u, Unknown message type trapped."
                    , node->nodeId);

            ERROR_ReportError(errorStr);
        }
    }
}


//  FUNCTION:  Mac802_3Layer
//  PURPOSE:   Models behavior of MAC layer with the CSMA/CD protocol with
//             IEEE 802.3 standard on receiving message enclosed in msg.
//  PARAMETERS:   Node* node
//                   Pointer to node
//               int interfaceIndex
//                   Interface Index
//               Message* msg
//                   Pointer to message
//  RETURN TYPE: NONE
//
void Mac802_3Layer(
    Node* node,
    int interfaceIndex,
    Message* msg)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    // If its a full duplex we divert from here and then return
    if (mac802_3->isFullDuplex)
    {
        Mac802_3FullDuplexLayer(node, interfaceIndex, msg);
        return;
    }

    switch (msg->eventType)
    {
        case MSG_MAC_StartTransmission:
        {
            // Indicates some node has started to send a frame
            if (mac802_3->stationState == YIELD_STATE ||
                mac802_3->stationState == IDLE_STATE  ||
                mac802_3->stationState == BACKOFF_STATE)
            {
                clocktype presentTime = node->getNodeTime();

                if (mac802_3->interFrameGapStartTime > 0  &&
                    mac802_3->stationState == YIELD_STATE &&
                    (presentTime - mac802_3->interFrameGapStartTime) >
                    ((2 * mac802_3->interframeGap) / 3))
                {
                    // ignore, in order to ensure fairness
                }
                else
                {
                    // Another node has started to transmit a frame.
                    // Set my status as Receiving to reflect channel busy.
                    mac802_3->stationState = RECEIVING_STATE;
                }
            }
            else if (mac802_3->stationState == TRANSMITTING_STATE)
            {
                // Collision occurred.
                // Another node has started to send frame along with me.
                // Go to Backoff state and send Jam Sequence.

                // Increase the collisionCounter
                mac802_3->collisionCounter++;
                mac802_3->stats.numBackoffFaced++;

                // Set status as backoff state
                mac802_3->stationState = BACKOFF_STATE;
                mac802_3->wasInBackoff = TRUE;

                // Handle backoff situation using 'Truncated Binary
                // Exponential Backoff' algorithm.
                Mac802_3HandleBackoffSituation(node, mac802_3, msg);

                // Send Jam sequence to keep channel busy.
                Mac802_3SendJamSequence(node, mac802_3);
            }

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_MAC_TransmissionFinished:
        {
            // Indicates a frame has come up to this node.

            if (mac802_3->stationState == RECEIVING_STATE)
            {
                // Frame received successfully.
                // Check the frame. If it is intended for this station
                // forward it to upper layer.
                (*mac802_3->myMacData->receiveFrameFn)(node,
                                                       interfaceIndex,
                                                       msg);

                if (mac802_3->wasInBackoff)
                {
                    // Previously, station was in Backoff state.
                    // So change station state as Backoff.

                    mac802_3->stationState = BACKOFF_STATE;
                }
                else
                {
                    // Station was Idle previously.
                    // Make station Idle and try to send next frame
                    // if available.

                    mac802_3->stationState = IDLE_STATE;
                    Mac802_3TryToSendNextFrame(node, mac802_3);
                }

                // Msg, containing the frame, will be freed properly later.
            }
            else
            {
                // Received a corrupted frame due to collision.
                // Discard this runt frame.
#ifdef ADDON_DB
                BOOL isMyAddr = FALSE;
                MacHWAddress srcHWAddr;
                MacHWAddress destHWAddr;


                // Get destination and source address from the frame.
                Mac802_3GetSrcAndDestAddrFromFrame(node, msg, &srcHWAddr,
                                                    &destHWAddr);

                if (NetworkIpIsUnnumberedInterface(node, interfaceIndex))
                {
                    isMyAddr = (MAC_IsBroadcastHWAddress(&destHWAddr) ||
                            MAC_IsMyAddress(node, &destHWAddr));
                }
                else
                {
                    isMyAddr = MAC_IsMyHWAddress(node, interfaceIndex,
                                                 &destHWAddr);
                } 
                if (isMyAddr)
                {
                    HandleMacDBEvents(        
                                      node, 
                                      msg,
                                  node->macData[interfaceIndex]->phyNumber,
                                      interfaceIndex, 
                                      MAC_Drop,
                                  node->macData[interfaceIndex]->macProtocol,
                                      TRUE,
                                      "Corrupted due to Collision");
                }
#endif
                MESSAGE_Free(node, msg);
            }
            break;
        }
        case MSG_MAC_JamSequence:
        {
            Mac802_3UpdateStatsReceive(node, msg, interfaceIndex);
#ifdef ADDON_DB
                HandleMacDBEvents(
                    node,
                    msg,
                    node->macData[interfaceIndex]->phyNumber,
                    interfaceIndex,
                    MAC_ReceiveFromPhy,
                    node->macData[interfaceIndex]->macProtocol);
#endif

            if (mac802_3->stationState == RECEIVING_STATE)
            {
                // Collision detected by receiving station.

                if (mac802_3->wasInBackoff)
                {
                    // Previously, station was in Backoff state.
                    // So change station state as Backoff.
                    mac802_3->stationState = BACKOFF_STATE;
                }
                else
                {
                    // Station was Idle previously.
                    // Make station Idle and try to send next frame
                    // if available.

                    mac802_3->stationState = IDLE_STATE;
                    Mac802_3TryToSendNextFrame(node, mac802_3);
                }
            }
            else if (mac802_3->stationState == TRANSMITTING_STATE)
            {
                // Increase the collisionCounter
                mac802_3->collisionCounter++;
                mac802_3->stats.numBackoffFaced++;

                // Set status as backoff state
                mac802_3->stationState = BACKOFF_STATE;
                mac802_3->wasInBackoff = TRUE;

                // Handle backoff situation using 'Truncated Binary
                // Exponential Backoff' algorithm.
                Mac802_3HandleBackoffSituation(node, mac802_3, msg);

                // Send Jam sequence to keep channel busy.
                Mac802_3SendJamSequence(node, mac802_3);
            }

            // Free the Jam sequence message.
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_MAC_TimerExpired:
        {
            MAC802_3TimerType timerType;
            MAC802_3SelfTimer* info = NULL;

            // Get info from message
            info = (MAC802_3SelfTimer *) MESSAGE_ReturnInfo(msg);
            timerType = info->timerType;

            switch (timerType)
            {
                case mac_802_3_TimerSendPacket:
                {
                    Mac802_3Trace(node, mac802_3, msg, "O");

                    if (mac802_3->stationState == TRANSMITTING_STATE)
                    {
                        // Check whether it is a latest timer
                        if (info->seqNum != mac802_3->seqNum)
                        {
                            break;
                        }

                        // Broadcast the frame to all node by the
                        // message MSG_MAC_TransmissionFinished.
                        Mac802_3CompleteFrameTransmission(node, mac802_3);

                        // Frame transmited successfully.
                        // Make station Idle and try to send next frame
                        // if available.

                        mac802_3->stationState = IDLE_STATE;
                        Mac802_3TryToSendNextFrame(node, mac802_3);
                    }
                    break;
                }
                case mac_802_3_ChannelIdle:
                {
                    if (mac802_3->stationState == YIELD_STATE)
                    {

                        // Reset the interframe delay start time to 0
                        // after it elapses

                        mac802_3->interFrameGapStartTime = 0;

                        // Set own state as Idle and try to
                        // transmit frame if there exists.

                        mac802_3->stationState = IDLE_STATE;

                        if (mac802_3->msgBuffer != NULL)
                        {
                            Mac802_3StartToSendFrame(node, mac802_3);
                        }
                        else
                        {
                            Mac802_3TryToSendNextFrame(node, mac802_3);
                        }
                    }
                    else if (mac802_3->stationState == BACKOFF_STATE)
                    {
                        Mac802_3Trace(node, mac802_3, msg, "O");

                        // Set state as Idle.
                        mac802_3->stationState = IDLE_STATE;

                        // Reset wasInBackoff flag.
                        mac802_3->wasInBackoff = FALSE;

                        // Sense channel to transmit frame again
                        Mac802_3SenseChannel(node, mac802_3);
                    }
                    else if (mac802_3->stationState == RECEIVING_STATE &&
                             mac802_3->wasInBackoff == TRUE)
                    {
                        // The backoff timer expired but the state is
                        // receiving a frame. So change wasInBackoff flag
                        // as FALSE. This station now can compete to
                        // retransmit after receiving that frame.

                        mac802_3->wasInBackoff = FALSE;
                        Mac802_3Trace(node, mac802_3, msg, "O");
                    }
                    break;
                }
                default:
                {
                    // Invalid timer log error
                    ERROR_Assert(FALSE,
                        "Mac802_3Layer: Self Message with bad timer\n");
                    break;
                }
            }

            // Free self message
            MESSAGE_Free(node, msg);
            break;
        }
        default:
        {
            char errBuf[MAX_STRING_LENGTH];

            // Shouldn't get here
            sprintf(errBuf,
                "Mac802_3Layer: "
                "Node %u received a message of unknown event\n",
                node->nodeId);
            ERROR_Assert(FALSE, errBuf);
            break;
        }
    }
}


//--------------------------------------------------------------------------
//                      Initialization Routine
//--------------------------------------------------------------------------

// FUNCTION:  Mac802_3GetSubnetParameters
// PURPOSE:   Collects the Bandwidth and Propagation Delay of the subnet
//            from the configuration file.
// PARAMETERS:   void* ipAddr
//                  Ip address of the Interface.
//              const NodeInput*   nodeInput
//                  Pointer to nodeInput file.
//              NetworkType networkType
//                  Interface network type
//              Int64*       subnetBandwidth
//                  Pointer to the variable which collects subnet bandwidth
//              clocktype* subnetPropDelay
//                  Pointer to the variable which collects subnet
//                  Propagation Delay
//              BOOL forLink
//                  Whether for Full Duplex Point to Point Link or Subnet.
// RETURN TYPE: NONE
//
void Mac802_3GetSubnetParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    Address* address,
    Int64* subnetBandwidth,
    clocktype* subnetPropDelay,
    BOOL forLink)
{
    BOOL wasFound = FALSE;

    Int64 bandwidthInMbps = 0;
    BOOL isPropDelayProper = TRUE;
    BOOL isWarningRequired = FALSE;
    char errorStr[MAX_STRING_LENGTH];
    char propStr[MAX_STRING_LENGTH];
    char addressStr[MAX_STRING_LENGTH];
    BOOL isFound = FALSE;

    IO_ConvertIpAddressToString(address, addressStr);

    // Initialize subnet datarate for the interface of a node.
    // Format is: SUBNET-DATA-RATE  <datarate>
    //            <datarate> = 10000000 | 100000000
    // Currently Gigabit Ethernet is not supported.
    // No default value is provided.
    //
    if (!forLink)
    {
        IO_ReadInt64(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "SUBNET-DATA-RATE",
            &wasFound,
            subnetBandwidth);
    }
    else
    {
        // This reading is for point-to-point full duplex
        IO_ReadInt64(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "LINK-BANDWIDTH",
            &isFound,
            subnetBandwidth);
    }

    if (!isFound && !wasFound)
    {
        sprintf(errorStr, "Unable to read"
                " \"SUBNET-DATA-RATE/LINK-BANDWIDTH\""
                       "for interface address %s", addressStr);

        ERROR_ReportError(errorStr);
    }

    // Check whether the bandwidth is properly given or not
    bandwidthInMbps = (*subnetBandwidth / 1000000);

    if (!(bandwidthInMbps == MAC802_3_10BASE_ETHERNET ||
          bandwidthInMbps == MAC802_3_100BASE_ETHERNET ||
          bandwidthInMbps == MAC802_3_1000BASE_ETHERNET ||
          bandwidthInMbps == MAC802_3_10000BASE_ETHERNET))
    {
        sprintf(errorStr, "Bandwidth of the interface %s must be "
                "10Mbps, 100Mbps, 1000Mbps, or 10000Mbps", addressStr);

        ERROR_ReportError(errorStr);
    }

    // Initialize subnet datarate for the interface of a node.
    // Format is: SUBNET-PROPAGATION-DELAY <delay_value>
    //            <delay_value> = a slot time long.
    // No default value is provided.
    //

    if (!forLink)
    {
        IO_ReadTime(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "SUBNET-PROPAGATION-DELAY",
            &wasFound,
            subnetPropDelay);
    }
    else
    {
        // This reading is for point-to-point full duplex
        IO_ReadTime(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "LINK-PROPAGATION-DELAY",
            &isFound,
            subnetPropDelay);
    }

    if (!isFound && !wasFound)
    {
        sprintf(errorStr, "Unable to read \"SUBNET-PROPAGATION-DELAY/\""
                          " LINK-PROPAGATION-DELAY\" for interface"
                          " address %s", addressStr);

        ERROR_ReportError(errorStr);
    }


    if ((isFound) || (wasFound))
    {
        if (*subnetPropDelay <= 0)
        {
            TIME_PrintClockInSecond(*subnetPropDelay, propStr);
            sprintf(errorStr,
                "SUBNET-PROPAGATION-DELAY/LINK-PROPAGATION-DELAY"
                "should have a positive value.\n"
                "Given delay at interface %s is %s seconds.\n",
                addressStr, propStr);
            ERROR_ReportError(errorStr);
        }
    }

    // Check whether the propagation delay is properly given or not
    if (bandwidthInMbps == MAC802_3_10BASE_ETHERNET)
    {
        if (*subnetPropDelay >= MAC802_3_10BASE_ETHERNET_SLOT_TIME)
        {
            isPropDelayProper = FALSE;
        }
        else if (*subnetPropDelay >=
                 (MAC802_3_10BASE_ETHERNET_SLOT_TIME / 2))
        {
            isWarningRequired = TRUE;
        }
    }
    else if (bandwidthInMbps == MAC802_3_100BASE_ETHERNET)
    {
        if (*subnetPropDelay >= MAC802_3_100BASE_ETHERNET_SLOT_TIME)
        {
            isPropDelayProper = FALSE;
        }
        else if (*subnetPropDelay >=
                 (MAC802_3_100BASE_ETHERNET_SLOT_TIME / 2))
        {
            isWarningRequired = TRUE;
        }
    }
    else
    {
        if (*subnetPropDelay >= MAC802_3_1000BASE_ETHERNET_SLOT_TIME)
        {
            isPropDelayProper = FALSE;
        }
        else if (*subnetPropDelay >=
                 (MAC802_3_1000BASE_ETHERNET_SLOT_TIME / 2))
        {
            isWarningRequired = TRUE;
        }
    }

    if (!isPropDelayProper || isWarningRequired)
    {
        char clockStr[MAX_STRING_LENGTH];

        memset(clockStr, 0, MAX_STRING_LENGTH);
        if (bandwidthInMbps == MAC802_3_10BASE_ETHERNET)
        {
            TIME_PrintClockInSecond(MAC802_3_10BASE_ETHERNET_SLOT_TIME,
                                    clockStr);
        }
        else if (bandwidthInMbps == MAC802_3_100BASE_ETHERNET)
        {
            TIME_PrintClockInSecond(MAC802_3_100BASE_ETHERNET_SLOT_TIME,
                                    clockStr);
        }
        else if (bandwidthInMbps == MAC802_3_1000BASE_ETHERNET)
        {
            TIME_PrintClockInSecond(MAC802_3_1000BASE_ETHERNET_SLOT_TIME,
                                    clockStr);
        }
        else if (bandwidthInMbps == MAC802_3_10000BASE_ETHERNET)
        {
            TIME_PrintClockInSecond(MAC802_3_1000BASE_ETHERNET_SLOT_TIME,
                                    clockStr);
        }

        if (!isPropDelayProper)
        {
            sprintf(errorStr,
               "\"SUBNET-PROPAGATION-DELAY/LINK-PROPAGATION-DELAY\" "
               "should be less than the slot time (%s second) for interface %s",
                clockStr, addressStr);
            ERROR_ReportError(errorStr);
        }
        else
        {
            sprintf(errorStr,
                "802.3: For proper collision detection, propagation delay"
                " should be less than half the slot time (%s second)"
                " for interface %s", clockStr, addressStr);
            ERROR_ReportWarning(errorStr);
        }
    }
}


// FUNCTION:  Mac802_3GetNeighborInfo
// PURPOSE:   Arranging the neighbor in a list for self purpose.
//  PARAMETERS:   Node* node
//                   Pointer to node
//               LinkedList* list
//                   Pointer to the list, where neighbor will be arranging.
//               SubnetMemberData* nodeList
//                   List of neighbors present in the subnet.
//               int numNodesInSubnet
//                   Number of neighbors present in the subnet.
//  RETURN TYPE: NONE
//
static
void Mac802_3GetNeighborInfo(
    Node* node,
    LinkedList* list,
    SubnetMemberData* nodeList,
    int numNodesInSubnet,
    LinkData *link)
{
    int count;
    SubnetMemberData* nodeListPtr;


    // Get base address of the node list array
    nodeListPtr = nodeList;

    for (count = 0; count < numNodesInSubnet; count++)
    {
        if (nodeListPtr->node == NULL) //node is on a different partition
        {
            //link->myMacData = ;
            link->phyType = WIRED;
            link->status = LINK_IS_IDLE;
            link->destNodeId = nodeListPtr->nodeId;
            link->destInterfaceIndex = nodeListPtr->interfaceIndex ;
            link->partitionIndex = nodeListPtr->partitionIndex;
            //link->myMacData->sendFrameFn    = &LinkNetworkLayerHasPacketToSend;
            //link->myMacData->receiveFrameFn = &MessageArrivedFromLink;
        }
        else if (node->nodeId != nodeListPtr->node->nodeId)
        {
            // Accept all nodes except this node
            ListInsert(node, list, 0,(void *) nodeListPtr);
        }

        nodeListPtr++;
    }
}

// /**
// FUNCTION::  Mac802_3FullDuplexInit
// PURPOSE::   Initialization function for the IEEE 802.3 full duplex
//            protocol of MAC layer.
// PARAMETERS::
//     +node : Node* : Pointer to node
//     +nodeInput : const NodeInput* : Pointer to nodeInput file.
//     +interfaceIndex : int : Particular interface of the node.
//     +linkLayerAddr : const NodeAddress : Link layer address
//                      of the Interface.
//     +nodeList : SubnetMemberData* : List of neighbors
//                              present in the subnet.
//     +numNodesInSubnet : int : Number of neighbors present in the subnet.
// RETURN TYPE:: void
// **/
static
void Mac802_3FullDuplexInit(
    Node* node,
    int interfaceIndex,
    MacData802_3* mac802_3)
{
    // Initialize Stat Variables
    mac802_3->fullDupStats = (MAC802_3FullDuplexStatistics*) MEM_malloc(
                                sizeof(MAC802_3FullDuplexStatistics));
    memset(mac802_3->fullDupStats, 0, sizeof(MAC802_3FullDuplexStatistics));
    mac802_3->isFullDuplex = TRUE;

    if (MAC_FULL_DUP_DEBUG)
    {
        ListItem* tempListItem = mac802_3->neighborList->first;
        SubnetMemberData* getNeighborInfo =
            (SubnetMemberData *) tempListItem->data;

        printf("Node %u, Interface index %d, for "
              "full duplex initialized.\n", node->nodeId, interfaceIndex);
        printf("Node: %u, Connected node: %u, Connected Interface:"
              " %d\n\n", node->nodeId, getNeighborInfo->node->nodeId,
              getNeighborInfo->interfaceIndex);
    }
}


// FUNCTION:  Mac802_3Init
// PURPOSE:   Initialization function for the IEEE 802.3 CSMA/CD
//            protocol of MAC layer.
// PARAMETERS:   Node* node
//                  Pointer to node
//              const NodeInput*   nodeInput
//                  Pointer to nodeInput file.
//              int interfaceIndex
//                  Particular interface of the node.
//              SubnetMemberData* nodeList
//                  List of neighbors present in the subnet.
//              int numNodesInSubnet
//                  Number of neighbors present in the subnet.
//              BOOL forLink
//                  Whether for Full Duplex Point to Point Link or Subnet.
// RETURN TYPE: NONE
//
void Mac802_3Init(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    SubnetMemberData* nodeList,
    int numNodesInSubnet,
    BOOL forLink)
{
    MacData802_3* mac802_3;
    BOOL modeFound = FALSE;
    BOOL isLinkFullDuplex = FALSE;
    char macProtocolMode[MAX_STRING_LENGTH];
    char linkMacString[MAX_STRING_LENGTH];

    mac802_3 = (MacData802_3 *) MEM_malloc(sizeof(MacData802_3));
    memset(mac802_3, 0, sizeof(MacData802_3));

    mac802_3->myMacData = node->macData[interfaceIndex];
    mac802_3->myMacData->macVar = (void *) mac802_3;

    RANDOM_SetSeed(mac802_3->seed,
                   node->globalSeed,
                   node->nodeId,
                   MAC_PROTOCOL_802_3,
                   interfaceIndex);

    // Get channel bandwidth
    mac802_3->bwInMbps = (int) (mac802_3->myMacData->bandwidth / 1000000);

    // Initialize slot time, interframe gap and Jam transmission time.
    mac802_3->slotTime = Mac802_3GetSlotTime(node, mac802_3);
    mac802_3->interframeGap = Mac802_3GetInterframeDelay(node, mac802_3);
    mac802_3->jamTrDelay = Mac802_3GetJamTrDelay(node, mac802_3);

    // Initially there is no packet in own buffer
    mac802_3->msgBuffer = NULL;

    // Initialize state, collision counter
    // Backoff Window & Backoff Flag for this interface
    mac802_3->stationState = IDLE_STATE;
    mac802_3->collisionCounter = 0;
    mac802_3->wasInBackoff = FALSE;
    mac802_3->backoffWindow = MAC802_3_MIN_BACKOFF_WINDOW;
    mac802_3->seqNum = 0;

    // Initialize Stat Variables
    mac802_3->stats.numBackoffFaced = 0;
    mac802_3->stats.numFrameLossForCollision = 0;

    // Initialize neighbor list for this station
    ListInit(node, &mac802_3->neighborList);

    mac802_3->link= (LinkData*)MEM_malloc(sizeof(LinkData));
    memset(mac802_3->link, 0, sizeof(LinkData));
    mac802_3->link->isPointToPointLink = TRUE;

    Mac802_3GetNeighborInfo(
        node,
        mac802_3->neighborList,
        nodeList,
        numNodesInSubnet,
        mac802_3->link);

    mac802_3->link->myMacData = mac802_3->myMacData;

    //Check for full duplex mode

    mac802_3->isFullDuplex = FALSE;

    // Reading the mode of the mac 802.3
    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "MAC802.3-MODE",
        &modeFound,
        macProtocolMode);

    if (!modeFound)
    {
        IO_ReadString(
            node,
            node->nodeId,
            interfaceIndex,
            nodeInput,
            "LINK-MAC-PROTOCOL",
            &isLinkFullDuplex,
            linkMacString);
    }

    if ((!modeFound) && (!isLinkFullDuplex))
    {
        // not found
        // The default mode is half duplex.
        mac802_3->isFullDuplex = FALSE;
    }
    else if (modeFound && !strcmp(macProtocolMode, "HALF-DUPLEX"))
    {
        mac802_3->isFullDuplex = FALSE;
    }
    else if ((modeFound && !strcmp(macProtocolMode, "FULL-DUPLEX")) ||
            (isLinkFullDuplex && !strcmp(linkMacString, "MAC802.3")))
    {
        // only two nodes can exist in the subnet, its a point to point
        // link
        if (numNodesInSubnet != 2)
        {
            char errorString[MAX_STRING_LENGTH];

            sprintf(errorString,
                "Node:%u, Interface index: %u\n"
                "Full duplex works only for point to point links.\n",
                node->nodeId, interfaceIndex);

            ERROR_ReportError(errorString);
        }

        if (nodeList[0].nodeId == node->nodeId)
        {
            mac802_3->link->destNodeId = nodeList[1].nodeId;
        }
        else if (nodeList[1].nodeId == node->nodeId)
        {
            mac802_3->link->destNodeId = nodeList[0].nodeId;
        }
        else
        {
            ERROR_ReportError("MAC802.3: Error in initialization");
        }

        mac802_3->isFullDuplex = TRUE;

        // Initializing the full duplex mac
        Mac802_3FullDuplexInit(node,interfaceIndex,mac802_3);
    }
    else
    {
        char errorString[MAX_STRING_LENGTH];

        sprintf(errorString,
            "Node:%u Unknown value of MAC802.3-MODE in configuration "
            "file for interface index %u.\n"
            "Expecting FULL-DUPLEX | HALF-DUPLEX.\n",
            node->nodeId, interfaceIndex);

        ERROR_ReportError(errorString);
    }

    if (mac802_3->isFullDuplex)
    {
        // Initialize send and receive function pointers for full duplex
        mac802_3->myMacData->sendFrameFn =
            Mac802_3FullDupNetworkLayerHasPacketToSend;
        mac802_3->myMacData->receiveFrameFn =
            Mac802_3FullDuplexHandleReceivedFrame;
    }
    else
    {
        // Initialize send and receive function pointers
        mac802_3->myMacData->sendFrameFn = Mac802_3NetworkLayerHasPacketToSend;
        mac802_3->myMacData->receiveFrameFn = Mac802_3HandleReceivedFrame;
    }

    // The trace doesnt support full duplex.
    Mac802_3TraceInit(node, nodeInput, interfaceIndex, mac802_3);

    #ifdef PARALLEL //Parallel

    if (forLink)
    {
        PARALLEL_SetProtocolIsNotEOTCapable(node);
        PARALLEL_SetMinimumLookaheadForInterface(node,
                                        mac802_3->myMacData->propDelay);
    }

    #endif //endParallel


}


//--------------------------------------------------------------------------
//                         Finalize Functions
//--------------------------------------------------------------------------

//  FUNCTION:  Mac802_3PrintStats
//  PURPOSE:   Prints Statistics at the end of simulation
//  PARAMETERS:   Node* node
//                   Pointer to node
//               MacData802_3* mac802_3
//                   Mac 802.3 layer structure of this interface.
//               int interfaceIndex
//                   Interface Index
//  RETURN TYPE: NONE
//
static void Mac802_3PrintStats(
    Node* node,
    MacData802_3* mac802_3,
    int interfaceIndex)
{

    if (!node->macData[mac802_3->myMacData->interfaceIndex]->macStats)
    {
        return;
    }

    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];

    node->macData[mac802_3->myMacData->interfaceIndex]->stats->Print(
                                                         node,
                                                         "MAC",
                                                         "802.3 Half Duplex",
                                                         ANY_DEST,
                                                         interfaceIndex);

    sprintf(buf, "Number of Retransmissions in Half Duplex = %d",
        mac802_3->stats.numBackoffFaced);
    IO_PrintStat(
        node,
        "MAC",
        "802.3",
        ANY_DEST,
        interfaceIndex,
        buf);

    ctoa(mac802_3->stats.numFrameLossForCollision, buf1);
    sprintf(buf, "Number of Frames Dropped in Half Duplex = %s", buf1);
    IO_PrintStat(
        node,
        "MAC",
        "802.3",
        ANY_DEST,
        interfaceIndex,
        buf);
}


//  FUNCTION:  Mac802_3Finalize
//  PURPOSE:   Prints Statistics at the end of simulation
//  PARAMETERS:   Node* node
//                   Pointer to node
//               int interfaceIndex
//                   Interface Index
//  RETURN TYPE: NONE
//
static
void Mac802_3FullDuplexFinalize(
    Node* node,
    MacData802_3* mac802_3,
    int interfaceIndex)
{
    if (!node->macData[mac802_3->myMacData->interfaceIndex]->macStats)
    {
        return;
    }

    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];
    double linkUtilization = 0;

    node->macData[mac802_3->myMacData->interfaceIndex]->stats->Print(
                                                         node,
                                                         "MAC",
                                                         "802.3 Full Duplex",
                                                         ANY_DEST,
                                                         -1);
    ctoa(mac802_3->fullDupStats->numFrameDropped, buf1);
    sprintf(buf, "Number of Frames Dropped in Full Duplex = %s", buf1);
    IO_PrintStat(node,
                 "MAC",
                 "802.3",
                 ANY_DEST,
                 interfaceIndex,
                 buf);

    ctoa(mac802_3->fullDupStats->numBytesDropped,buf1);
    sprintf(buf, "Number of Bytes Dropped in Full Duplex = %s",buf1);
    IO_PrintStat(node,
                 "MAC",
                 "802.3",
                 ANY_DEST,
                 interfaceIndex,
                 buf);

    if (node->getNodeTime() == 0)
    {
        linkUtilization = 0;
    }
    else
    {
        linkUtilization =
            (double) mac802_3->fullDupStats->totalBusyTime
                            / (double) node->getNodeTime();
    }

    sprintf(buf, "Channel Utilization by Full Duplex = %f", linkUtilization);
    IO_PrintStat(node, "MAC", "802.3", ANY_DEST, interfaceIndex, buf);

    MEM_free(mac802_3->fullDupStats);
}


//  FUNCTION:  Mac802_3Finalize
//  PURPOSE:   Prints Statistics at the end of simulation
//  PARAMETERS:   Node* node
//                   Pointer to node
//               int interfaceIndex
//                   Interface Index
//  RETURN TYPE: NONE
//
void Mac802_3Finalize(
    Node* node,
    int interfaceIndex)
{
    MacData802_3* mac802_3 = (MacData802_3 *)
                              node->macData[interfaceIndex]->macVar;

    if (node->macData[interfaceIndex]->macStats == TRUE)
    {
        // The mac can be either in full or half duplex mode
        // If its a full duplex, some extra statistics may be added
        if (mac802_3->isFullDuplex)
        {
            Mac802_3FullDuplexFinalize(node, mac802_3, interfaceIndex);
            // The existing 802.3 parameters may also be needed.
            //  If not needed then we may return from here.
        }
        else
        {
            Mac802_3PrintStats(node, mac802_3, interfaceIndex);
        }
    }

#ifdef ENTERPRISE_LIB
    // Release vlan info structure if allocated
    MacReleaseVlanInfoForThisInterface(node, interfaceIndex);
#endif // ENTERPRISE_LIB
}

//--------------------------------------------------------------------------
// FUNCTION   :: Mac802_3GetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Return packet properties
// PARAMETERS :: Node* node
//                   Node which received the message.
//               Message* msg
//                   The sent message
//               Int32 interfaceIndex
//                   The interface index on which packet was received
//               Int32& destNodeId
//                   Sets the destination nodeId
//               Int32& controlSize
//                   Sets the controlSize
//               BOOL& isMyFrame
//                   Set TRUE if msg  is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void Mac802_3GetPacketProperty(Node* node,
                               Message* msg,
                               Int32 interfaceIndex,
                               Int32& destNodeId,
                               Int32& controlSize,
                               BOOL& isMyFrame,
                               BOOL& isAnyFrame)
{
    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;
    Mac802Address destMacAddr;
    UInt32 lengthOfFrame = (UInt32)MESSAGE_ReturnPacketSize(msg);
    UInt32 lengthOfPacket = 0;
    UInt8* frame = NULL;
    BOOL isSwitchCtrlPacket = FALSE;
    Int32 padAndChecksumSize = 0;

    if (msg != NULL)
    {
        Mac802_3GetSrcAndDestAddrFromFrame(node,
                                           msg,
                                           &srcHWAddr,
                                           &destHWAddr);

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

        ConvertVariableHWAddressTo802Address(node,
                                             &destHWAddr,
                                             &destMacAddr);

        if (isMyFrame || !isAnyFrame)
        {
            if (MAC_IsASwitch(node) 
                && IsSwitchCtrlPacket(node, destMacAddr))
            {
                isSwitchCtrlPacket = TRUE;
                destNodeId = ANY_NODEID;
                controlSize = MESSAGE_ReturnPacketSize(msg);
            }
            else
            {
                destNodeId = GetNodeIdFromMacAddress(destMacAddr.byte);
            }
        }
        else
        {
            destNodeId = ANY_NODEID;
        }

        if (!isSwitchCtrlPacket)
        {
            frame = (UInt8*)MESSAGE_ReturnPacket(msg);
            frame = frame + (MAC802_3_SIZE_OF_HEADER - sizeof(UInt16));
            memcpy(&lengthOfPacket, frame, sizeof(UInt16));

            if (lengthOfPacket == MAC802_3_VLAN_TAG_TYPE)
            {
                controlSize += sizeof(MacHeaderVlanTag);
                frame = frame + sizeof(MacHeaderVlanTag);
                memcpy(&lengthOfPacket, frame, sizeof(UInt16));
            }

            if (lengthOfPacket == PROTOCOL_TYPE_ARP
                && !LlcIsEnabled(node, interfaceIndex))
            {
                lengthOfPacket = sizeof(ArpPacket);
            }

            padAndChecksumSize = lengthOfFrame - controlSize
                                 - lengthOfPacket;

            controlSize += padAndChecksumSize;
        }
                
    }
}

//--------------------------------------------------------------------------
// NAME         Mac802_3UpdateStatsSend
// PURPOSE      Update sending statistics
// PARAMETERS   Node* node
//                  Node which received the message.
//              Message* msg
//                  The sent message
//              Int32 interfaceIndex
//                  The interface index on which packet received
// RETURN       None
// NOTES        None
//--------------------------------------------------------------------------
void Mac802_3UpdateStatsSend(
    Node* node,
    Message* msg,
    Int32 interfaceIndex)
{
    if (!node->macData[interfaceIndex]->macStats)
    {
        return;
    }

    if (msg->eventType == MSG_MAC_JamSequence)
    {
        node->macData[interfaceIndex]->stats->
            AddFrameSentDataPoints(
                node,
                msg,
                STAT_Broadcast,
                MESSAGE_ReturnPacketSize(msg),
                0,
                interfaceIndex,
                ANY_NODEID);
        return;
    }

    MacData802_3* mac802_3 = (MacData802_3*)
                              node->macData[interfaceIndex]->macVar;
    Int32 destNodeId = ANY_NODEID;
    BOOL isMyFrame = FALSE;
    BOOL isAnyFrame = FALSE;
    Int32 controlSize = MAC802_3_SIZE_OF_HEADER;
   
    Mac802_3GetPacketProperty(
        node,
        msg,
        interfaceIndex,
        destNodeId,
        controlSize,
        isMyFrame,
        isAnyFrame);

    STAT_DestAddressType type;
    if (isMyFrame || !isAnyFrame)
    {
        type = STAT_Unicast;
    }
    else
    {
        type = STAT_Broadcast;
    }

    node->macData[interfaceIndex]->stats->AddFrameSentDataPoints(
                              node,
                              msg,
                              type,
                              controlSize,
                              MESSAGE_ReturnPacketSize(msg) - controlSize,
                              interfaceIndex,
                              destNodeId);

}

//--------------------------------------------------------------------------
// NAME         Mac802_3UpdateStatsReceive
// PURPOSE      Update receiving statistics
// PARAMETERS   Node* node
//                  Node which received the message.
//              Message* msg
//                  The sent message
//              Int32 interfaceIndex
//                  The interface index on which packet received
// RETURN       None
// NOTES        None
//--------------------------------------------------------------------------
void Mac802_3UpdateStatsReceive(
    Node* node,
    Message* msg,
    Int32 interfaceIndex)
{
    if (!node->macData[interfaceIndex]->macStats)
    {
        return;
    }

    if (msg->eventType == MSG_MAC_JamSequence)
    {
        node->macData[interfaceIndex]->stats->
            AddFrameReceivedDataPoints(
                node,
                msg,
                STAT_Broadcast,
                MESSAGE_ReturnPacketSize(msg),
                0,
                interfaceIndex);
        return;
    }

    Int32 destNodeId;
    BOOL isMyFrame = FALSE;
    BOOL isAnyFrame = FALSE;
    Int32 controlSize = MAC802_3_SIZE_OF_HEADER;
    BOOL isPromiscuousMode = node->macData[interfaceIndex]->promiscuousMode;
    Mac802_3GetPacketProperty(
        node,
        msg,
        interfaceIndex,
        destNodeId,
        controlSize,
        isMyFrame,
        isAnyFrame);

    if (!isPromiscuousMode
        && (!isMyFrame && !isAnyFrame && !MAC_IsASwitch(node)))
    {
        return;
    }

    STAT_DestAddressType type;
    if (isMyFrame || !isAnyFrame)
    {
        type = STAT_Unicast;
    }
    else
    {
        type = STAT_Broadcast;
    }

    node->macData[interfaceIndex]->stats->AddFrameReceivedDataPoints(
        node,
        msg,
        type,
        controlSize,
        MESSAGE_ReturnPacketSize(msg) - controlSize,
        interfaceIndex);
}

#ifdef ADDON_DB
//--------------------------------------------------------------------------
// FUNCTION   :: Mac802_3GetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Called by the Mac Events Stats DB
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
//                   Set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void Mac802_3GetPacketProperty(Node* node,
                               Message* msg,
                               Int32 interfaceIndex,
                               MacDBEventType eventType,
                               StatsDBMacEventParam& macParam,
                               BOOL& isMyFrame,
                               BOOL& isAnyFrame)
{
    MacHWAddress srcHWAddr;
    MacHWAddress destHWAddr;
    Mac802Address destMacAddr;
    Mac802Address srcMacAddr;

    char srcAdd[25];
    char destAdd[25];

    memset(srcAdd, 0, sizeof(char) * 25);
    memset(destAdd, 0, sizeof(char) * 25);
    Int32 headerSize = MAC802_3_SIZE_OF_HEADER;
    UInt32 lengthOfFrame = (UInt32)MESSAGE_ReturnPacketSize(msg);
    UInt32 lengthOfPacket = 0;
    UInt8* frame = NULL;
    BOOL isSwitchCtrlPacket = FALSE;
    Int32 padAndChecksumSize = 0;

    if (msg != NULL)
    {
        if (msg->eventType == MSG_MAC_JamSequence)
        {

            if (eventType == MAC_SendToPhy)
            {
                MacSetDefaultHWAddress(node->nodeId,
                                       &srcHWAddr,
                                       interfaceIndex);
                ConvertVariableHWAddressTo802Address(node,
                                                     &srcHWAddr,
                                                     &srcMacAddr);
                Mac802AddressToStr(srcAdd, &srcMacAddr);
                macParam.SetSrcAddr(srcAdd);
            }

            isAnyFrame = TRUE;
            destMacAddr = ANY_MAC802;
            macParam.SetFrameType("JAM_SEQ");
            macParam.SetHdrSize(0);
        }
        else
        {
            Mac802_3GetSrcAndDestAddrFromFrame(node,
                                               msg,
                                               &srcHWAddr,
                                               &destHWAddr);

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

            ConvertVariableHWAddressTo802Address(node,
                                                 &destHWAddr,
                                                 &destMacAddr);
            ConvertVariableHWAddressTo802Address(node,
                                                 &srcHWAddr,
                                                 &srcMacAddr);

            if (MAC_IsASwitch(node))
            {
                isMyFrame = TRUE;
                if (IsSwitchCtrlPacket(node, destMacAddr))
                {
                    macParam.SetFrameType("CONTROL");
                    macParam.SetHdrSize(0);
                    isSwitchCtrlPacket = TRUE;
                }
            }

            if (!isSwitchCtrlPacket)
            {
                // Get frame size
                frame = (UInt8*) MESSAGE_ReturnPacket(msg);
                frame = frame + (MAC802_3_SIZE_OF_HEADER
                                                - sizeof(UInt16));
                memcpy(&lengthOfPacket, frame, sizeof(UInt16));

                if (lengthOfPacket == MAC802_3_VLAN_TAG_TYPE)
                {
                    headerSize += sizeof(MacHeaderVlanTag);
                    frame = frame + sizeof(MacHeaderVlanTag);
                    memcpy(&lengthOfPacket, frame, sizeof(UInt16));
                }

                if (lengthOfPacket == PROTOCOL_TYPE_ARP
                                      && !LlcIsEnabled(node, interfaceIndex))
                {
                    lengthOfPacket = sizeof(ArpPacket);
                }

                padAndChecksumSize
                    = lengthOfFrame - headerSize - lengthOfPacket;

                headerSize += padAndChecksumSize;
                macParam.SetFrameType("DATA");
                macParam.SetHdrSize(headerSize);
            }

            Mac802AddressToStr(srcAdd, &srcMacAddr);
            macParam.SetSrcAddr(srcAdd);
        }

        Mac802AddressToStr(destAdd, &destMacAddr);
        macParam.SetDstAddr(destAdd);
    }
}
#endif




