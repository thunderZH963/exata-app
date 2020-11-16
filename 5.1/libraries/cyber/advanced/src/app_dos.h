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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#ifndef APP_DOS_H_
#define APP_DOS_H_

#include "stats_app.h"

//DOS Msg types
enum
{
    //DOS Msg
    MSG_DOS_VictimInit,
    MSG_DOS_AttackerInit,
    MSG_DOS_StopVictim,
    MSG_DOS_StopAttacker
};

struct AppDOSVictim
{
    int instanceId;
    int uniqueId;
    int destPort;
    std::list<int> sourceIdList;
    NodeAddress myAddress;

    STAT_AppStatistics* stats;
};

struct AppDOSAttacker
{
    static const int ATTACK_BASIC = 1;
    static const int ATTACK_SYN = 2;
    static const int ATTACK_FRAG = 3;

    // My information
    Address myAddress;

    // Victim Information
    Address victimAddress;
    short victimPort;

    // Attack information
    int attackType;
    clocktype startTime;
    clocktype endTime;
    clocktype duration;
    clocktype packetInterval;
    unsigned int packetSize;
    unsigned int packetCount;

    // Internal information
    int uniqueId;
    int instanceId;
    int tcpSessionId;


    // Statistics
    long udpPacketsSent;
    long tcpSYNSent;
    long fragmentsSent;
    clocktype firstPacketAt;
    clocktype lastPacketAt;

    STAT_AppStatistics* stats;
};

 void DOS_Initialize(
     Node* srcNode,
     int attackType,
     NodeAddress sourceNodeId,
     Address victimAddr,
     int packetCount,
     int packetSize,
     clocktype packetInterval,
     clocktype startTime,
     clocktype endTime,
     int victimPort);


void DOS_Finalize(Node *node);

bool DOS_Drop(Node *node, Message *msg);

void DOS_ProcessEvent(Node* node, Message* msg);

void DOS_Stop(Node* node);

#define ERROR_SmartReportError(msg, shouldAbort) \
    ERROR_WriteError(shouldAbort ? ERROR_ERROR : ERROR_WARNING, \
            (const char*) 0, msg, __FILE__, __LINE__);


#endif /* APP_DOS_H_ */
