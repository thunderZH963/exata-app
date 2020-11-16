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

// /**
// PACKAGE     :: BACKGROUND TRAFFIC
// DESCRIPTION ::
// **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "mac.h"
#include "mac_background_traffic.h"


//-----------------------------------------------------------------------
// NAME:        BgTraffic_PrintBgItem
// PURPOSE:     Print the item of Background Traffic information
// PARAMETERS:  node - in which node this item exist.
//              bgInfoItem - item of BG traffic information.
// RETRUN:      None
//------------------------------------------------------------------------
static
void BgTraffic_PrintBgItem(
    Node* node,
    BgTrafficInfo* bgInfoItem)
{
    char time[MAX_STRING_LENGTH];

    if (!bgInfoItem)
    {
        printf("LINK_BG_TRAFFIC_DEBUG: BgInfo item is Empty\n");
        return;
    }

    printf("\tFlow Id %d \n", bgInfoItem->flowId);
    TIME_PrintClockInSecond(bgInfoItem->startTm, time);
    printf("\tStart Time %s\n", time);
    TIME_PrintClockInSecond(bgInfoItem->duration, time);
    printf("\tEnd Time %s Sec.\n", time);
    printf("\tUtilized Bandwidth %d\n", bgInfoItem->utlBandwidth);
    printf("\tPriority %d\n", bgInfoItem->priority);

    TIME_PrintClockInSecond(bgInfoItem->hiDuration, time);
    printf("\tTime used by higher Priority real Traffic %s\n", time);
    printf("\n");
    printf("\n");
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_PrintSelfTimerMsgList
// PURPOSE:     Print the Background Traffic self timer list
// PARAMETERS:  node - in which node this list belongs.
//              interfaceIndex - at which interface.
//              head - pointer of the SelfTimerMsg List.
// RETRUN:      None
//------------------------------------------------------------------------
void BgTraffic_PrintSelfTimerMsgList(
    Node *node,
    int interfaceIndex,
    BgSelfTimerMsg* head)
{
    char time[MAX_STRING_LENGTH];

    printf("LINK_BG_TRAFFIC_DEBUG: In NODE %u at Interface %u "
        "Print SelfTimerMsgList\n", node->nodeId, interfaceIndex);

    if (!head)
    {
        printf("LINK_BG_TRAFFIC_DEBUG: SelfTimerMsgList is Empty\n");
        return;
    }

    while (head)
    {
        TIME_PrintClockInSecond(head->time, time);
        printf("\tTime to fire %s\n",time);

        if (head->bgMsgType == START_BG_TRAFFIC)
        {
            printf("\tMsg Type is START_BG_TRAFFIC\n");
        }
        else if (head->bgMsgType == END_BG_TRAFFIC)
        {
            printf("\tMsg Type is END_BG_TRAFFIC\n");
        }

        printf("BG INFO ITEM:-\n");
        BgTraffic_PrintBgItem(node, head->bgInfoPtr);
        head = head->next;
    }
    printf("\n");
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_PrintList
// PURPOSE:     Print the Background Traffic Information list
// PARAMETERS:  node - in which node this list belongs.
//              interfaceIndex - at which interface.
//              head - beginning pointer of the list.
// RETRUN:      None
//------------------------------------------------------------------------
static
void BgTraffic_PrintList(
    Node *node,
    int interfaceIndex,
    BgTrafficInfo* head)
{
    printf("LINK_BG_TRAFFIC_DEBUG: In NODE %u at Interface %u\n",
        node->nodeId, interfaceIndex);

    if (!head)
    {
        printf("LINK_BG_TRAFFIC_DEBUG: List is Empty\n");
        return;
    }
    while (head)
    {
        BgTraffic_PrintBgItem(node, head);
        head = head->next;
    }
    printf("\n");
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_GetNode
// PURPOSE:     Get the specific node pointer from IP address.
// PARAMETERS:  firstNode - first node pointer of partition data.
//              ipAddStr - for which IP address, searching the node.
//              interfaceIndex - for which interface.
// RETRUN:      Pointer of a specific node.
//              NULL if the node lives on a remote partition.
//------------------------------------------------------------------------
static
Node* BgTraffic_GetNode(
    Node* firstNode,
    char* ipAddStr,
    int* interfaceIndex)
{
    BOOL isNodeId;
    NodeAddress interfaceAddress;
    Node* bgNode = NULL;
    NodeAddress nodeId;

    //get the IP Address from ipAddStr
    IO_ParseNodeIdOrHostAddress(ipAddStr, &interfaceAddress, &isNodeId);

    if (isNodeId)
    {
        ERROR_ReportError("The entry must be an IP address");
    }

    //get node ID from specific IP Address
    nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
        firstNode,
        interfaceAddress);

    if (nodeId == INVALID_MAPPING)
    {
        ERROR_ReportError("The interface address specified is "
                          "not bound to any node");
    }

    // Get node pointer from node ID
    // Allow retrieving non-local nodes (function will return NULL)
    BOOL found = PARTITION_ReturnNodePointer(firstNode->partitionData,
        &bgNode,
        nodeId,
        TRUE);

    if (!found || bgNode == NULL)
    {
        ERROR_ReportError("Could not return node pointer");
    }

    // Check if the node lives on a remote partition
    if (bgNode->partitionId != firstNode->partitionData->partitionId)
    {
        return NULL;
    }

    //get interface index w.r.t. node and IP address
    *interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(
        bgNode,
        interfaceAddress);

    if (*interfaceIndex == -1)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "No interface exists with interface "
                "address: %s at node %u", ipAddStr,
                bgNode->nodeId);
        ERROR_ReportError(errStr);
    }

    return bgNode;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_ReturnPrecedence
// PURPOSE:     Return the precedence of a Background traffic from
//              the general TOS format input string.
// PARAMETERS:  node - for this particular node.
//              tosString - General TOS format input string.
// RETRUN:      Precedence value.
//------------------------------------------------------------------------
static
int BgTraffic_ReturnPrecedence(
    Node* node,
    char* tosString)
{
    char buf[MAX_STRING_LENGTH];
    int value = 0;

    sscanf(tosString, "%s %d", buf, &value);

    if (!strcmp(buf, "PRECEDENCE"))
    {
        if (value >= 0 && value <= 7)
        {
            return value;
        }
        else
        {
            // PRECEDENCE [range < 0 to 7 >]
            ERROR_ReportError("LINK-BACKGROUND-TRAFFIC: "
                "PRECEDENCE value range < 0 to 7 >");
        }
    }
    else if (!strcmp(buf, "DSCP"))
    {
        if (value >= 0 && value <= 63)
        {
            return (value >> 3);
        }
        else
        {
            // DSCP [range <0 to 63 >]
            ERROR_ReportError("LINK-BACKGROUND-TRAFFIC: "
                "DSCP value range < 0 to 63 >");
        }
    }
    else if (!strcmp(buf, "TOS"))
    {
        if (value >= 0 && value <= 255)
        {
            return (value >> 5);
        }
        else
        {
            // TOS [range <0 to 255 >]
            ERROR_ReportError("LINK-BACKGROUND-TRAFFIC: "
                "TOS value range < 0 to 255 >");
        }
    }
    ERROR_ReportError("LINK-BACKGROUND-TRAFFIC:Unknown TOS related string");
    return 0;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_ReadParam
// PURPOSE:     Read Background traffic information from input string.
// PARAMETERS:  bgNode - for which node this parameter will be taken.
//              tokenStr - input string for BG traffic item information.
//              flowId - BG traffic flow identification number.
// RETRUN:      Return BgTrafficInfo pointer.
//------------------------------------------------------------------------
static
BgTrafficInfo* BgTraffic_ReadParam(
    Node* bgNode,
    char* tokenStr,
    int flowId)
{
    int nToken;

    RandomDistribution<clocktype> randomClocktype;
    randomClocktype.setSeed(bgNode->globalSeed,
                            bgNode->nodeId,
                            MSG_MAC_StartBGTraffic,
                            flowId);

    BgTrafficInfo *bgInfoItem =
        (BgTrafficInfo*) MEM_malloc(sizeof(BgTrafficInfo));

    ERROR_Assert(bgInfoItem, "Insufficient memory space\n");

    memset(bgInfoItem, 0, sizeof(BgTrafficInfo));
    bgInfoItem->flowId = flowId;

    nToken = randomClocktype.setDistribution(tokenStr, "LINK-BACKGROUND-TRAFFIC", RANDOM_CLOCKTYPE);
    bgInfoItem->startTm = randomClocktype.getRandomNumber();

    tokenStr = IO_SkipToken(tokenStr, BG_TOKENSEP, nToken);

    nToken = randomClocktype.setDistribution(tokenStr, "LINK-BACKGROUND-TRAFFIC", RANDOM_CLOCKTYPE);
    bgInfoItem->duration = randomClocktype.getRandomNumber();

    tokenStr = IO_SkipToken(tokenStr, BG_TOKENSEP, nToken);

    nToken = randomClocktype.setDistribution(tokenStr, "LINK-BACKGROUND-TRAFFIC", RANDOM_INT);
    bgInfoItem->utlBandwidth = (int) randomClocktype.getRandomNumber();

    tokenStr = IO_SkipToken(tokenStr, BG_TOKENSEP, nToken);

    bgInfoItem->priority =
        (TosType)BgTraffic_ReturnPrecedence(bgNode, tokenStr);

    if (LINK_BG_TRAFFIC_DEBUG)
    {
        BgTraffic_PrintBgItem(bgNode, bgInfoItem);
    }
    return bgInfoItem ;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_InsertBgSelfTimerMsgItem
// PURPOSE:     Insert item into the self timer list as ascending order
//              w.r.t. start time.
// PARAMETERS:  node - for this specific node.
//              header - pointer of a pointer of the selfTimerMsg list.
//              item - which will be inserted into the list.
// RETRUN:      None.
//------------------------------------------------------------------------
static
void BgTraffic_InsertBgSelfTimerMsgItem(
    Node *node,
    BgSelfTimerMsg** header,
    BgSelfTimerMsg* item)
{
    BgSelfTimerMsg* temp = (*header);

    //this will be the first item of the list
    if ((!(*header)) ||
        (((BgSelfTimerMsg*)*header)->time > item->time))
    {
        item->next = *header;
        (*header) = item;
        return;
    }
    else    // not the first item of the list//
    {
        while (temp->next)
        {
            if (temp->next->time > item->time)
            {
                item->next = temp->next;
                temp->next = item;
                return;
            }
            temp = temp->next;
        }
        temp->next = item;
    }
    return;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_CheckUniqueFlowId
// PURPOSE:     Check flowId is unique or not.
// PARAMETERS:  node - at this node
//              head - pointer of bgSelfTimer list
//              flowId - check this flowId
// RETRUN:      if this flowId is unique return TRUE otherwise FALSE
//------------------------------------------------------------------------
static
BOOL BgTraffic_CheckUniqueFlowId(
    Node* node,
    BgSelfTimerMsg* head,
    int flowId)
{
    if (!head)
    {
        if (LINK_BG_TRAFFIC_DEBUG)
        {
            printf("LINK_BG_TRAFFIC_DEBUG: SelfTimerMsg List is Empty\n");
        }
        return TRUE;
    }

    while (head)
    {
        if (head->bgMsgType == START_BG_TRAFFIC)
        {
            if (head->bgInfoPtr->flowId == flowId)
            {
                if (LINK_BG_TRAFFIC_DEBUG)
                {
                    printf("LINK_BG_TRAFFIC_DEBUG: duplicate flowId\n");
                }
                return FALSE;
            }
        }
        head = head->next;
    }
    return TRUE;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_Init
// PURPOSE:     Initialization the Background traffic from input file
// PARAMETERS:  firstNode - first node of partition data.
//              currentLine - pointer to the input string.
// RETRUN:      None
//------------------------------------------------------------------------
void BgTraffic_Init(
    Node* firstNode,
    const char* currentLine)
{
    char qualifier[MAX_STRING_LENGTH];
    char parameterName[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];
    int qualifierLen;
    char* ipAddStr = NULL;
    char iotoken[MAX_STRING_LENGTH];
    const char* delim = " \t\n";
    char* aStr = strchr((char*)currentLine, ']');
    char* tokenStr = strchr(aStr + 1, ']');
    Node* bgNode = NULL;
    int interfaceIndex = -1;
    int flowId = 0;
    BgTrafficInfo* bgInfoItem = NULL;

    if (!aStr || !tokenStr)
    {
        sprintf(errStr, "LINK-BACKGROUND-TRAFFIC: "
                "Undeterminable qualifier:\n %s\n", currentLine);
        ERROR_ReportError(errStr);
    }

    qualifierLen = (int)(aStr - currentLine - 1);
    strncpy(qualifier, &currentLine[1], qualifierLen);
    qualifier[qualifierLen] = '\0';
    aStr++;
    sscanf(aStr, "%s", parameterName);

    if (!strstr(parameterName, "LINK-BACKGROUND-TRAFFIC"))
    {
        sprintf(errStr, "LINK-BACKGROUND-TRAFFIC: "
            "Undeterminable qualifier2:\n %s\n", currentLine);
        ERROR_ReportError(errStr);
    }

    if (!strchr(parameterName, '[') || (aStr = strchr(parameterName, ']')))
    {
        char flowStr[MAX_STRING_LENGTH];
        int flowLen = (int)(aStr - (parameterName + 24));
        strncpy(flowStr, parameterName + 24, flowLen);
        flowStr[flowLen] = '\0';

        if (!IO_IsStringNonNegativeInteger(flowStr))
        {
            ERROR_ReportError("FlowId must be Numeric\n");
        }
        flowId = atoi(flowStr);
    }
    else
    {
        sprintf(errStr, "LINK-BACKGROUND-TRAFFIC: "
            "undeterminable qualifier2:\n %s\n", currentLine);
        ERROR_ReportError(errStr);
    }

    tokenStr += 1;
    ipAddStr = IO_GetDelimitedToken(iotoken, qualifier, delim, &aStr);

    if (LINK_BG_TRAFFIC_DEBUG)
    {
        printf("WHEN READ CONFIGURATION FILE:\n");
    }

    //the above bgInfo item invoke to each specified node
    while (ipAddStr != NULL)
    {
        bgNode = BgTraffic_GetNode(firstNode, ipAddStr, &interfaceIndex);
        if (!bgNode)
        {
            // The node lives on a remote partition.  Ignore it.
            ipAddStr = IO_GetDelimitedToken(iotoken, aStr, delim, &aStr);
            continue;
        }

        // initialize the bgInfo item corresponding to the input parameter
        bgInfoItem = BgTraffic_ReadParam(
            bgNode,
            tokenStr,
            flowId);

        BgMainStruct* bgMainStruct = NULL;
        BgSelfTimerMsg* startTimerItem =
            (BgSelfTimerMsg*) MEM_malloc(sizeof(BgSelfTimerMsg));
        BgSelfTimerMsg* endTimerItem =
            (BgSelfTimerMsg*) MEM_malloc(sizeof(BgSelfTimerMsg));
        BgTrafficInfo* tempBgInfoItem =
            (BgTrafficInfo*) MEM_malloc(sizeof(BgTrafficInfo));

        memcpy(tempBgInfoItem, bgInfoItem, sizeof(BgTrafficInfo));
        memset(startTimerItem, 0, sizeof(BgSelfTimerMsg));
        memset(endTimerItem, 0, sizeof(BgSelfTimerMsg));

        if (!bgNode->macData[interfaceIndex]->bgMainStruct)
        {
            bgMainStruct = (BgMainStruct*) MEM_malloc(sizeof(BgMainStruct));
            memset(bgMainStruct, 0, sizeof(BgMainStruct));
            bgNode->macData[interfaceIndex]->bgMainStruct = bgMainStruct;
        }
        else
        {
            bgMainStruct =
               (BgMainStruct*)bgNode->macData[interfaceIndex]->bgMainStruct;
        }

        //check this flowId is unique or not
        if (!BgTraffic_CheckUniqueFlowId(
            bgNode,
            bgMainStruct->bgSelfTimerMsgList,
            flowId))
        {
            sprintf(errStr, "LINK-BACKGROUND-TRAFFIC: Duplicate flowId %d "
                    "for the node %u\n", flowId, bgNode->nodeId);
            ERROR_ReportError(errStr);
        }

        startTimerItem->time = tempBgInfoItem->startTm;
        startTimerItem->bgMsgType = START_BG_TRAFFIC;
        startTimerItem->bgInfoPtr = tempBgInfoItem;

        //insert into self timer list
        BgTraffic_InsertBgSelfTimerMsgItem(
            bgNode,
            &(bgMainStruct->bgSelfTimerMsgList),
            startTimerItem);

        endTimerItem->time =
            tempBgInfoItem->startTm + tempBgInfoItem->duration;
        endTimerItem->bgMsgType = END_BG_TRAFFIC;
        endTimerItem->bgInfoPtr = tempBgInfoItem;

        //insert into self timer list
        BgTraffic_InsertBgSelfTimerMsgItem(
            bgNode,
            &(bgMainStruct->bgSelfTimerMsgList),
            endTimerItem);

        ipAddStr = IO_GetDelimitedToken(iotoken, aStr, delim, &aStr);
    }
    MEM_free(bgInfoItem);
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_InvokeSelfMsgForFirstTimer
// PURPOSE:     Invoke the selfTimer message for first item from
//              selfTimerMsg list. this function will be called from mac.cpp
// PARAMETERS:  node - for which node this self message will be invoked.
//              interfaceIndex - for which interface.
// RETRUN:      None.
//------------------------------------------------------------------------
void BgTraffic_InvokeSelfMsgForFirstTimer(Node* node,
                                            int interfaceIndex)
{
    BgMsgInfo* bgMsgInfo;
    Message* bgSelfTimerMsg;
    BgMainStruct* bgMainStruct =
        (BgMainStruct*)node->macData[interfaceIndex]->bgMainStruct;
    BgSelfTimerMsg* temp = bgMainStruct->bgSelfTimerMsgList;

    if (temp->bgMsgType != START_BG_TRAFFIC)
    {
        ERROR_Assert(FALSE, "BACKGROUND TRAFFIC: "
            "First item type should be START_BG_TRAFFIC.\n");
    }

    bgSelfTimerMsg = MESSAGE_Alloc(
        node,
        MAC_LAYER,
        0,
        MSG_MAC_StartBGTraffic);

    MESSAGE_InfoAlloc(node, bgSelfTimerMsg, sizeof(BgMsgInfo));
    bgMsgInfo = (BgMsgInfo*) MESSAGE_ReturnInfo(bgSelfTimerMsg);
    bgMsgInfo->bgPtr = temp->bgInfoPtr;
    bgMsgInfo->interfaceIndex = interfaceIndex;
    MESSAGE_Send(node, bgSelfTimerMsg, temp->time);

    //free the top item
    temp = bgMainStruct->bgSelfTimerMsgList;
    bgMainStruct->bgSelfTimerMsgList = temp->next;
    MEM_free(temp);
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_BWutilize
// PURPOSE:     BW used by BG Traffic for a particular priority.
// PARAMETERS:  node - at this node.
//              thisMac - at this mac data.
//              dataPriority - for specific priority.
// RETRUN:      Return total BW used by a specific priority BG Traffic.
//------------------------------------------------------------------------
int BgTraffic_BWutilize(
    Node* node,
    MacData* thisMac,
    TosType dataPriority)
{
    BgMainStruct* bgMainStruct = (BgMainStruct*)thisMac->bgMainStruct;

    if (LINK_BG_TRAFFIC_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), time);
        printf("In NODE %u at TIME %s ereturn used BW= %d\n",
            node->nodeId,
            time,
            bgMainStruct->bgReductionBW[dataPriority].reductioinBW);
    }
    return bgMainStruct->bgReductionBW[dataPriority].reductioinBW;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_SuppressByHigher
// PURPOSE:     Calculate the time, BG Traffic suppress by higher priority
//              real traffic.
// PARAMETERS:  node - at this node.
//              thisMac - at this mac data.
//              dataPriority - for specific priority.
//              duration - time to be taken by the specific priority real
//                         data packet for transmission
// RETRUN:      None.
//------------------------------------------------------------------------
void BgTraffic_SuppressByHigher(
    Node* node,
    MacData* thisMac,
    TosType dataPriority,
    clocktype duration)
{
    BgMainStruct* bgMainStruct = (BgMainStruct*)thisMac->bgMainStruct;
    int i = 0;

    for (i = 0; i < dataPriority; i++)
    {
        bgMainStruct->bgReductionBW[i].hiDuration += duration;
    }
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_InsertBgInfoItemInstatBgInfo
// PURPOSE:     Insert item into statBgInfo list as ascending order
//              w.r.t. start time.
// PARAMETERS:  node - for this specific node.
//              header - beginning of the statBgInfo list.
//              item - which will be inserted into the list.
// RETRUN:      None.
//------------------------------------------------------------------------
static
void BgTraffic_InsertBgInfoItemInstatBgInfo(
    Node *node,
    BgTrafficInfo* bgInfoItem,
    int interfaceIndex)
{
    BgMainStruct* bgMainStruct =
        (BgMainStruct*) node->macData[interfaceIndex]->bgMainStruct;
    BgTrafficInfo** header = &(bgMainStruct->statBgInfoList);
    BgTrafficInfo* temp;

    //this will be the first item of the list
    if (!(*header) ||
        ((*header)->startTm > bgInfoItem->startTm))
    {
        bgInfoItem->next = (*header);
        (*header) = bgInfoItem;
        return;
    }
    else    // not the first item of the list//
    {
        temp = *header;

        while (temp->next)
        {
            if (temp->next->startTm > bgInfoItem->startTm)
            {
                bgInfoItem->next = temp->next;
                temp->next = bgInfoItem;
                return;
            }
            temp = temp->next;
        }
        temp->next = bgInfoItem;
    }
    return;
}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_ProcessEvent
// PURPOSE:     Handle different type of message event of BG traffic.
// PARAMETERS:  node - at this node.
//              msg - self timer message.
// RETRUN:      None.
//------------------------------------------------------------------------
void BgTraffic_ProcessEvent(Node *node, Message *msg)
{
    clocktype delay;
    BgSelfTimerMsg* temp;
    BgMsgInfo* bgMsgInfo = (BgMsgInfo*) MESSAGE_ReturnInfo(msg);
    int i;
    int interfaceIndex = bgMsgInfo->interfaceIndex;
    BgMainStruct* bgMainStruct =
        (BgMainStruct*)node->macData[interfaceIndex]->bgMainStruct;
    BgReductionBW* bgReductionBW = bgMainStruct->bgReductionBW;
    BgTrafficInfo*  bgPtr = bgMsgInfo->bgPtr;
    TosType priority = bgPtr->priority;

    if (MESSAGE_GetEvent(msg) == MSG_MAC_StartBGTraffic)
    {
        for (i = priority; i >= 0; i--)
        {
            bgReductionBW[i].reductioinBW += bgPtr->utlBandwidth;
        }
        bgPtr->hiDuration = bgReductionBW[bgPtr->priority].hiDuration;

        BgTraffic_InsertBgInfoItemInstatBgInfo(
                        node, bgMsgInfo->bgPtr, interfaceIndex);

        if (LINK_BG_TRAFFIC_DEBUG)
        {
            char time[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), time);
            BgTraffic_PrintBgItem(node, bgMsgInfo->bgPtr);
            printf("After insert this above Info into node %u at time %s\n",
                node->nodeId, time);
            BgTraffic_PrintList(
                node,
                interfaceIndex,
                bgMainStruct->statBgInfoList);
        }
    }
    else if (MESSAGE_GetEvent(msg) == MSG_MAC_EndBGTraffic)
    {
        BgTrafficInfo*  statList = bgMainStruct->statBgInfoList;

        for (i = priority; i >= 0; i--)
        {
            bgReductionBW[i].reductioinBW -= bgPtr->utlBandwidth;
        }

        while (statList)
        {
            if (statList->flowId == bgPtr->flowId)
            {
                statList->hiDuration =
                    bgReductionBW[priority].hiDuration
                    - statList->hiDuration;
                break;
            }
            statList = statList->next;
        }

        if (LINK_BG_TRAFFIC_DEBUG)
        {
            char time[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), time);
            BgTraffic_PrintBgItem(node, bgMsgInfo->bgPtr);
            printf("After delete this above Info into node %u at time %s "
                "the Stat List is\n", node->nodeId, time);
            BgTraffic_PrintList(
                node,
                interfaceIndex,
                bgMainStruct->statBgInfoList);
        }
    }
    else
    {
        ERROR_Assert(FALSE, "BACKGROUND TRAFFIC: Unknown Event type.\n");
    }

    if (bgMainStruct->bgSelfTimerMsgList)
    {
        temp = bgMainStruct->bgSelfTimerMsgList;
        bgMsgInfo->bgPtr = temp->bgInfoPtr;

        if (temp->bgMsgType == START_BG_TRAFFIC)
        {
            MESSAGE_SetEvent(msg, MSG_MAC_StartBGTraffic);
        }
        else if (temp->bgMsgType == END_BG_TRAFFIC)
        {
            MESSAGE_SetEvent(msg, MSG_MAC_EndBGTraffic);
        }
        else
        {
            ERROR_Assert(FALSE, "BACKGROUND TRAFFIC: "
                "Unknown Self Message type.\n");
        }
        delay = temp->time - node->getNodeTime();
        MESSAGE_Send(node, msg, delay);

        //free the top element
        temp = bgMainStruct->bgSelfTimerMsgList;
        bgMainStruct->bgSelfTimerMsgList = temp->next;
        MEM_free(temp);
    }
    else
    {
        MESSAGE_Free(node, msg);
    }

}


//-----------------------------------------------------------------------
// NAME:        BgTraffic_Finalize
// PURPOSE:     Print the statistics of Random link fault.
// PARAMETERS:  node - in which node
//              interfaceIndex - in which interface.
// RETRUN:      None
//------------------------------------------------------------------------
void BgTraffic_Finalize(Node *node, int interfaceIndex)
{
    char buf[100];
    char time[MAX_STRING_LENGTH];
    int i;

    int maxBwUsed = 0;
    int maxBwUsedFlow = 0;
    double avgBwUsed = 0.0;

    clocktype bwUsedByAll = 0;
    clocktype bwUsedByAny = 0;
    clocktype currentTime = node->getNodeTime();
    clocktype bwUsedByLink = node->macData[interfaceIndex]->bandwidth *
                                            currentTime / SECOND;
    clocktype actDurByAny = 0;
    clocktype actDurByAll = 0;
    clocktype actDurStartTime = 0;
    clocktype actDurEndTime = 0;

    BgMainStruct* bgMainStruct =
        (BgMainStruct*)node->macData[interfaceIndex]->bgMainStruct;
    BgRealTrafficDelay* bgRealDelay = bgMainStruct->bgRealDelay;
    BgTrafficInfo* statHead;
    BgSelfTimerMsg* bgSelfTimerMsgList =
                        bgMainStruct->bgSelfTimerMsgList;

    while (bgSelfTimerMsgList)
    {
        if (bgSelfTimerMsgList->bgMsgType == START_BG_TRAFFIC)
        {
            BgTraffic_InsertBgInfoItemInstatBgInfo(
                node,
                bgSelfTimerMsgList->bgInfoPtr,
                interfaceIndex);
        }
    }

    statHead = bgMainStruct->statBgInfoList;

    while (statHead)
    {
        actDurByAny = statHead->duration - statHead->hiDuration;

        if (statHead->startTm > actDurEndTime)
        {
            actDurByAll += (actDurEndTime - actDurStartTime);
            actDurStartTime = statHead->startTm;
            actDurEndTime = (statHead->startTm + statHead->duration);
        }
        else if ((statHead->startTm + statHead->duration) > actDurEndTime)
        {
            actDurEndTime = statHead->startTm + statHead->duration;
        }

        bwUsedByAny = actDurByAny * statHead->utlBandwidth / SECOND;
        bwUsedByAll += bwUsedByAny;
        avgBwUsed = (bwUsedByAny * 100.0) / bwUsedByLink;

        if (maxBwUsed < statHead->utlBandwidth)
        {
            maxBwUsed = statHead->utlBandwidth;
            maxBwUsedFlow = statHead->flowId;
        }

        sprintf(buf, "percentage of BW utilized by Flow [%d] "
            "throughout simulation = %f", statHead->flowId, avgBwUsed);
        IO_PrintStat(
            node,
            "MAC",
            "BG Traffic of Link",
            ANY_DEST,
            interfaceIndex,
            buf);

        TIME_PrintClockInSecond(actDurByAny, time);
        sprintf(buf, "Total active time(s) of Flow [%d] is %s",
            statHead->flowId, time);
        IO_PrintStat(
            node,
            "MAC",
            "BG Traffic of Link",
            ANY_DEST,
            interfaceIndex,
            buf);

        statHead = statHead->next;
    }

    sprintf(buf, "Flow [%d] is used maximum BW", maxBwUsedFlow);
    IO_PrintStat(
        node,
        "MAC",
        "BG Traffic of Link",
        ANY_DEST,
        interfaceIndex,
        buf);

    actDurByAll += (actDurEndTime - actDurStartTime);
    TIME_PrintClockInSecond(actDurByAll, time);
    sprintf(buf, "Total time all background traffic was active %s", time);
    IO_PrintStat(
        node,
        "MAC",
        "BG Traffic of Link",
        ANY_DEST,
        interfaceIndex,
        buf);

    avgBwUsed = (bwUsedByAll * 100.0) / bwUsedByLink;
    sprintf(buf, "percentage of BW utilized by all BG Traffic "
        "throughout simulation = %f", avgBwUsed);
    IO_PrintStat(
        node,
        "MAC",
        "BG Traffic of Link",
        ANY_DEST,
        interfaceIndex,
        buf);

    for (i = 0; i < BG_MAX_PRIORITY; i++)
    {
        if (bgRealDelay->delay)
        {
            double avg =
                (bgRealDelay->delay * 1.0 ) / bgRealDelay->occurrence;
            TIME_PrintClockInSecond((clocktype)avg, time);
            sprintf(buf, "Avg delay of Real Traffic class priority[%d] "
                "flow due to BG traffic  %s", i, time);
            IO_PrintStat(
                node,
                "MAC",
                "BG Traffic of Link",
                ANY_DEST,
                interfaceIndex,
                buf);
        }
        bgRealDelay += 1;
    }
}
