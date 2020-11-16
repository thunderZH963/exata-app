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

#ifndef _VBR_APP_H_
#define _VBR_APP_H_

#include "stats_app.h"

#define VBR_INVALID_SOURCE_PORT -1
typedef struct struct_vbr_str VbrData;
typedef struct struct_vbr_msg_str VbrMsgData;

//UserCodeStart

//UserCodeEnd

typedef struct {
    int BytesSent;
    int BytesSentId;
    int BytesReceived;
    int BytesReceivedId;
} VbrStatsType;


enum {
    VBR_SERVERIDLE,
    VBR_CLIENTIDLE,
    VBR_FINAL_STATE,
    VBR_INITIAL_STATE,
    VBR_CLIENTTIMEREXPIRED,
    VBR_SERVERRECEIVESDATA,
    VBR_DEFAULT_STATE
};



struct struct_vbr_str
{
    int state;
    int       connectionId;
    int       uniqueId;
    short     sourcePort;
    int       protocol;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL      sessionIsClosed;
    NodeAddress clientAddr;
    NodeAddress serverAddr;
    int itemSize;
    clocktype meanInterval;
    clocktype startTime;
    clocktype endTime;
    unsigned tos;
    char type;
    VbrStatsType stats;
    RandomSeed seed;
    int initStats;
    int printStats;
    Int32 mdpUniqueId;
    BOOL isMdpEnabled;
    std::string* applicationName;
    STAT_AppStatistics* appStats;
};


struct struct_vbr_msg_str
{
    short     sourcePort;
    char type;
#if defined(ADVANCED_WIRELESS_LIB) || defined(UMTS_LIB) || defined(MUOS_LIB)
    Int32 pktSize;
    clocktype meanInterval;
#endif // ADVANCED_WIRELESS_LIB || UMTS_LIB || MUOS_LIB
};

void
VbrInit(Node* node,
        NodeAddress clientAddr,
        NodeAddress serverAddr,
        int itemSize,
        clocktype meanInterval,
        clocktype startTime,
        clocktype endTime,
        unsigned tos,
        char* appName,
        BOOL isMdpEnabled = FALSE,
        BOOL isProfileNameSet = FALSE,
        char* profileName = NULL,
        Int32 uniqueId = -1,
        const NodeInput* nodeInput = NULL);

void
VbrFinalize(Node* node, VbrData* dataPtr);


void
VbrProcessEvent(Node* node, Message* msg);


void VbrRunTimeStat(Node* node, VbrData* dataPtr);




#endif
