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

#ifndef BACKGROUND_TRAFFIC_H
#define BACKGROUND_TRAFFIC_H

#include "random.h"

#define LINK_BG_TRAFFIC_DEBUG 0
#define BG_MAX_PRIORITY 8
#define BG_TOKENSEP    " ,\t"

// Structure containing Back Ground Traffic information.
typedef struct struct_bg_traffic_info
{
    int         flowId;       //Flow Identification number
    TosType     priority;     //Priority of BG traffic
    clocktype   startTm;      //BW utilization start time
    clocktype   duration;     //Duration of the BG Traffic
    int         utlBandwidth; //Utilization BW In bytes
    clocktype   hiDuration;   //Duration of BW used by higher priority
    struct struct_bg_traffic_info*  next;   //link to the next BG Info
} BgTrafficInfo;

// Structure which store BG Traffic information into the self timer message.
typedef struct struct_bg_traffic_Massage_info
{
    int             interfaceIndex; //interface number
    BgTrafficInfo*  bgPtr;          //BG Info pointer
} BgMsgInfo;

// different types of self timer message.
typedef enum
{
    START_BG_TRAFFIC,
    END_BG_TRAFFIC
} BgMsgType;

// Structure of self timer message.
typedef struct struct_bg_self_timer_msg_item
{
    BgMsgType      bgMsgType;   //Type of the self timer message
    clocktype      time;        //Time, the message will be fired
    BgTrafficInfo* bgInfoPtr;   //Link to related background traffic info
    struct struct_bg_self_timer_msg_item*  next; //link to the next Item
} BgSelfTimerMsg;

// Structure for calculating avg. delay of per priority class
// real traffic flow due to BG traffic
typedef struct struct_bg_for_real_traffic_dealy_claculation_item
{
    clocktype   delay;      //Total delay
    int         occurrence; //Number of occurrence
} BgRealTrafficDelay;

// Structure for Bandwidth Reduction item
typedef struct struct_bg_for_BW_Reduction_item
{
    int         reductioinBW;  // BW Reduction on particular priority
    clocktype   hiDuration;    // Duration used by higher priority packet
} BgReductionBW;


// Main Structure of the Background Traffic which ptr is in the MacData.
// Here assume, MAC support only in between 0 to 7 data packet priority.
typedef struct struct_bg_main
{
    //Bandwidth Reduction array
    BgReductionBW bgReductionBW[BG_MAX_PRIORITY];
    //list of BG traffic item for print statistics.
    BgTrafficInfo* statBgInfoList;
    //list of Self timer message
    BgSelfTimerMsg* bgSelfTimerMsgList;
    //information of real traffic delay due to bg traffic.
    BgRealTrafficDelay bgRealDelay[BG_MAX_PRIORITY];
} BgMainStruct;


void BgTraffic_Init(
    Node* firstNode,
    const char* currentLine);

void BgTraffic_ProcessEvent(Node* node, Message* msg);

void BgTraffic_InvokeSelfMsgForFirstTimer(
    Node* node,
    int interfaceIndex);

int BgTraffic_BWutilize(
    Node* node,
    MacData* thisMac,
    TosType dataPriority);

void BgTraffic_SuppressByHigher(
    Node* node,
    MacData* thisMac,
    TosType dataPriority,
    clocktype duration);

void BgTraffic_Finalize(Node* node, int interfaceIndex);

void BgTraffic_PrintSelfTimerMsgList(
    Node* node,
    int interfaceIndex,
    BgSelfTimerMsg* head);

#endif /* BACKGROUND_TRAFFIC_H */
