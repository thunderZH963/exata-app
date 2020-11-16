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

#ifndef MESSENGER_APP_H
#define MESSENGER_APP_H

#include "if_queue.h"

#define MAX_ADDITIONAL_DATA_SIZE 80


#define HLA_VOICE_PACKET_FREQUENCY          (250 * MILLI_SECOND)
#define HLA_VOICE_PACKET_BACKOFF_FACTOR     3
#define HLA_VOICE_PACKET_BACKOFF_TIME       (HLA_VOICE_PACKET_BACKOFF_FACTOR \
                                                * HLA_VOICE_PACKET_FREQUENCY)

// /**
// CONSTANT     :: BYTE_TO_BIT      8
// DESCRIPTION  ::
// **/
#define BYTE_TO_BIT                 8

// /**
// CONSTANT     :: BROADCAST_ADDR   0xffffffff
// DESCRIPTION  ::
// **/
#define BROADCAST_ADDR              0xffffffff

typedef enum {
    GENERAL,
    VOICE_PACKET
} MessengerAppType;

typedef void (*MessageResultFunctionType)(
                 Node *node,
                 Message* msg,
                 BOOL success);

struct MessengerPktHeader{
    NodeAddress srcAddr;
    NodeAddress destAddr;
    clocktype initialPrDelay;
    clocktype lifetime;
    clocktype timeStamp;
    clocktype freq;
    int msgId;
    MessengerAppType appType;
    short transportType;
    unsigned short numFrags;
    unsigned short pktNum;
    unsigned short numAdditionalDataFrags;
    unsigned short additionalDataFragId;
    unsigned short additionalDataSize;
    unsigned short destNPGId;
    unsigned int fragSize;
    MessageResultFunctionType messageResultFunc;
    MessengerPktHeader()
    {
        destNPGId = 0;
        numFrags = 0;
    }
} ;

typedef struct {
    MessengerPktHeader pktHdr;
    BOOL recordStats;
    BOOL sessionOpen;
    int connId;
    char additionalData[MAX_ADDITIONAL_DATA_SIZE];
    int dataFragIdToSend;
    BOOL dataFragRecvd[MAX_ADDITIONAL_DATA_SIZE];
    clocktype messageStartTime;
    clocktype endTime;
} MessengerMessageData;

// /**
// CONSTANT    :: STANDALONE_MESSENGER_APPLICATION
// DESCRIPTION :: For standalone messenger application
// **/
#define STANDALONE_MESSENGER_APPLICATION


#define TYPICAL_NUMBER_OF_PKTS_PER_MSG (16)
#define RECV_ENTRY_INCREMENT (16)
#define MAX_CONSECUTIVE_DROPS (0)
#define CACHE_LIFETIME (30 * SECOND)

typedef enum {
    INIT = 0,
    HEADER,
    ADDITIONAL_DATA,
    VIRTUAL_PAYLOAD
} MessengerReceiveState;

typedef struct {
    MessengerMessageData msgData;
    clocktype shortPktDelaysBuffer[TYPICAL_NUMBER_OF_PKTS_PER_MSG];
    clocktype *pktDelays;
    BOOL alreadyReturnedComplete;
    char receiveBuffer[MAX(sizeof(MessengerPktHeader),
                           MAX_ADDITIONAL_DATA_SIZE)];
    MessengerReceiveState receiveState;
    int receiveBytesRemaining;
} MessengerPktBufferEntry;


typedef struct messenger_app_state_struct {
    NodeAddress srcId;
    int         msgId;

    // Self buffer kept by Messenger
    Queue       *queue;

    clocktype   messageLastRecvTime;
    clocktype   messageLastSentTime;

    int         numCollisionDetected;
    clocktype   adjBackoffTime;
    clocktype   nextChannelSenseTime;

    MessageResultFunctionType messageResultFunc;

    MessengerPktBufferEntry *recvList;
    int numRecvList;
    int maxRecvList;

    MessengerMessageData *sendList;
    int numSendList;
    int maxSendList;

    RandomDistribution<clocktype> backoffDistribution;
} MessengerState;

void MessengerInit(Node *);
void MessengerLayer(Node *, Message *);
void MessengerFinalize(Node *, AppInfo* appInfo);

void MessengerRegisterResultFunction(
    Node *node,
    MessageResultFunctionType functionPtr);

void MessengerSendMessage(
    Node *node,
    MessengerPktHeader pktHdr,
    char *additionalData,
    int additionalDataSize,
    MessageResultFunctionType functionPtr);


#ifdef STANDALONE_MESSENGER_APPLICATION


// /**
// FUNCTION    :: MessengerClientInit
// LAYER       :: APPLICATION
// PURPOSE     :: It initializes the client messenger application when
//                the application is in standalone mode
// PARAMETERS  ::
// + node       : Node* : Pointer to the node running the messenger app.
// + srcAddr    : NodeAddress : Source address
// + destAddr   : NodeAddress : Destination address
// + t_type     : TransportType : Transport Type
// + app_type   : MessengerAppType : Application Type
// + lifeTime   : clocktype : Life Time
// + startTime  : clocktype : Start Time
// + interval   : clocktype : Interval
// + fragSize   : int : Fragmentation Size
// + fragNum    : int : Fragmentation Number
// + destNPGId  : unsigned short : Destination NPG index
// + filename   : char* : External file name
// RETURN      :: void : NULL
// **/
void MessengerClientInit(
    Node* node,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    TransportType t_type,
    MessengerAppType app_type,
    clocktype lifeTime,
    clocktype startTime,
    clocktype interval,
    int fragSize,
    int fragNum,
#ifdef  MILITARY_RADIOS_LIB
    unsigned short destNPGId,
#endif
    char* filename);


// /**
// FUNCTION    :: MessengerServerListen
// LAYER       :: APPLICATION
// PURPOSE     :: It initializes the Server into Listen state.
//                This function is called when the destination is unicast.
// PARAMETERS  ::
// + node       : Node* : Pointer to the node running the messenger app.
// RETURN      :: void : NULL
// **/
void MessengerServerListen(Node *node);

#endif
#endif
