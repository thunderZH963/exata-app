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
#include "transport_tcp.h"
#include "tcpapps.h"
#include "app_util.h"
#include "if_queue.h"
#include "if_scheduler.h"

#include "app_messenger.h"
#include "partition.h"
#include "external_util.h"

#ifdef MILITARY_RADIOS_LIB
#include "mac.h"
#include "tadil_util.h"
#endif //MILITARY_RADIOS_LIB

#define DEBUG (0)
// message related debugging output
#define DEBUG_MESSAGE (0)

// queue related debugging output
#define DEBUG_QUEUE (0)

#define DEBUG_STATE (0)

// activates a debugging test application that will send a UDP message
// and a TCP message
#define TEST_APP (0)

// Test voice application
#define TEST_VOICE_APP (0)


#ifdef TEST_VOICE_APP
static FILE* fp;
//fp = fopen("voice.trc", "a+");
#endif

// Status Message
struct AckStatus
{
    bool status;
    Int32 receiverNodeId;
};

// we can add functionality to use sender side timers and return more
// failure and success messages on the sender side.  Right now it's
// exclusively receiver side notification

static clocktype clocktypeabs(clocktype x)
{
    if (x < 0)
    {
        return -x;
    }

    return x;
}

static MessengerState *GetPointer(Node *node)
{
    AppInfo *appList = node->appData.appPtr;
    MessengerState *messenger;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_MESSENGER)
        {
            messenger = (MessengerState *) appList->appDetail;

            return messenger;
        }
    }

    return NULL;
}

static void SendTimerMsg(
    Node *node,
    const MessengerMessageData msgData,
    const int eventType,
    const clocktype delay)
{
    Message *timerMsg;

    ERROR_Assert((delay > 0),
                 "delay has to be > 0");

    timerMsg = MESSAGE_Alloc(node, APP_LAYER,
                   APP_MESSENGER, eventType);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(MessengerMessageData));

    memcpy(MESSAGE_ReturnInfo(timerMsg), &msgData,
           sizeof(MessengerMessageData));

    MESSAGE_Send(node, timerMsg, delay);
}

static void SendReminderMsg(
    Node *node,
    const MessengerMessageData msgData)
{
    if (msgData.pktHdr.lifetime > 0)
    {
        SendTimerMsg(
            node, msgData, MSG_APP_TimerExpired, msgData.pktHdr.lifetime);
    }
}

static void SendNextPacketMsg(
    Node *node,
    const MessengerMessageData msgData,
    const clocktype delay)
{
    SendTimerMsg(node, msgData, MSG_APP_SendNextPacket, delay);
}


static MessengerMessageData *ReturnSendEntry(
    const MessengerState *messenger,
    const NodeAddress destAddr,
    const int msgId,
    const clocktype currentTime)
{
    int i;

    if (DEBUG)
    {
        char destAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(destAddr, destAddrStr);

        printf("ReturnSendEntry(match destAddr %s / msgId %d)\n",
               destAddrStr, msgId);
    }

    for (i = 0; i < messenger->numSendList; i++)
    {
        if (DEBUG)
        {
            char destAddrStr[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(
                messenger->sendList[i].pktHdr.destAddr,
                destAddrStr);
            printf("\tentry[%d] destAddr %s / msgId %d\n", i,
                   destAddrStr,
                   messenger->sendList[i].pktHdr.msgId);
        }
        if ((messenger->sendList[i].pktHdr.destAddr == destAddr) &&
            (messenger->sendList[i].pktHdr.msgId == msgId))
        {
            return &(messenger->sendList[i]);
        }
    }

    return NULL;

}

static MessengerMessageData *ReturnSendEntryForConnId(
    MessengerState *messenger,
    const int connId,
    int *index)
{
    int i;

    if (DEBUG)
    {
        printf("ReturnSendEntry(match connId %d)\n", connId);
    }

    for (i = 0; i < messenger->numSendList; i++)
    {
        if (DEBUG)
        {
            char destAddrStr[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(
                messenger->sendList[i].pktHdr.destAddr,
                destAddrStr);

            printf("\tentry[%d] destAddr %s / msgId %d\n", i,
                   destAddrStr,
                   messenger->sendList[i].pktHdr.msgId);
        }
        if ((messenger->sendList[i].connId == connId) &&
            (messenger->sendList[i].sessionOpen))
        {
            if (index)
            {
                *index = i;
            }
            return &(messenger->sendList[i]);
        }
    }

    if (index)
    {
        *index = -1;
    }
    return NULL;
}

static void DeleteSendEntry(
    MessengerState *messenger,
    const int index)
{
    int i;

    messenger->numSendList--;
/*
    memmove(&(messenger->sendList[index]), &(messenger->sendList[index+1]),
            sizeof(MessengerMessageData)
            * (messenger->numSendList - index));
*/
    for (i = index; i < messenger->numSendList; i++)
    {
        messenger->sendList[i] = messenger->sendList[i+1];
    }
}

static MessengerMessageData *CreateSendEntry(
    Node *node,
    MessengerState *messenger,
    const MessengerMessageData msgData)
{
    MessengerMessageData *entry;

    if (DEBUG)
    {
        char destAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(msgData.pktHdr.destAddr, destAddrStr);

        printf("#%d: CreateSendEntry destAddr = %s / msgId == %d\n",
               node->nodeId, destAddrStr, msgData.pktHdr.msgId);
    }

    if (messenger->numSendList == messenger->maxSendList)
    {
        MessengerMessageData *newSendList;

        newSendList = (MessengerMessageData *)
                      MEM_malloc(
                          sizeof(MessengerMessageData) *
                          (messenger->maxSendList + RECV_ENTRY_INCREMENT));
        memcpy(newSendList, messenger->sendList,
               sizeof(MessengerMessageData) * messenger->maxSendList);

        MEM_free(messenger->sendList);
        messenger->sendList = newSendList;

        messenger->maxSendList += RECV_ENTRY_INCREMENT;
    }

    entry = &(messenger->sendList[messenger->numSendList]);

    memcpy(entry, &msgData, sizeof(MessengerMessageData));

    messenger->numSendList++;

    return entry;
}

static MessengerMessageData *CreateOrReturnSendEntry(
    Node *node,
    MessengerState *messenger,
    const MessengerMessageData msgData,
    const clocktype currentTime)
{
    MessengerMessageData *entry;

    entry = ReturnSendEntry(
                messenger,
                msgData.pktHdr.destAddr,
                msgData.pktHdr.msgId,
                currentTime);

    if (entry == NULL)
    {
        entry = CreateSendEntry(node, messenger, msgData);
    }

    return entry;
}

static MessengerPktBufferEntry *ReturnRecvEntry(
    MessengerState *messenger,
    const NodeAddress srcAddr,
    const int msgId,
    const clocktype currentTime)
{
    int i;
    char srcAddrStr[MAX_STRING_LENGTH];
    char time[MAX_STRING_LENGTH];

    if (DEBUG)
    {

        IO_ConvertIpAddressToString(srcAddr, srcAddrStr);

        printf("ReturnRecvEntry(match srcAddr %s / msgId %d)\n",
               srcAddrStr, msgId);
    }

    for (i = 0; i < messenger->numRecvList; i++)
    {
        if (DEBUG)
        {

            IO_ConvertIpAddressToString(
                messenger->recvList[i].msgData.pktHdr.srcAddr,
                srcAddrStr);

            TIME_PrintClockInSecond(
                messenger->recvList[i].msgData.pktHdr.timeStamp, time);

            printf("\tentry[%d] srcAddr %s / msgId %d / timeStamp = %s\n",
                   i,
                   srcAddrStr,
                   messenger->recvList[i].msgData.pktHdr.msgId,
                   time);
        }

        if (((messenger->recvList[i].msgData.pktHdr.timeStamp
              + messenger->recvList[i].msgData.pktHdr.lifetime
              + CACHE_LIFETIME)
             < currentTime) &&
            (messenger->recvList[i].msgData.pktHdr.transportType
             != TRANSPORT_TYPE_RELIABLE))
        {
            if (messenger->recvList[i].pktDelays
                != messenger->recvList[i].shortPktDelaysBuffer)
            {
                MEM_free(messenger->recvList[i].pktDelays);
            }
            messenger->numRecvList--;
/*
            memmove(&(messenger->recvList[i]), &(messenger->recvList[i+1]),
                    sizeof(MessengerPktBufferEntry)
                    * (messenger->numRecvList - i));
*/
            {
                int j;

                for (j = i; j < messenger->numRecvList; j++)
                {
                    messenger->recvList[j] = messenger->recvList[j + 1];

                    if (messenger->recvList[j+1].pktDelays
                        == messenger->recvList[j+1].shortPktDelaysBuffer)
                    {
                        messenger->recvList[j].pktDelays
                            = messenger->recvList[j].shortPktDelaysBuffer;
                        if (DEBUG)
                        {
                            printf("\tA Rewiring ""%" TYPES_64BITFMT "d"" to ""%" TYPES_64BITFMT "d""\n",
                                   *(messenger->recvList[j].pktDelays),
                                   *(messenger->recvList[j].shortPktDelaysBuffer));
                        }
                    }
                    else
                    {
                        if (DEBUG)
                        {
                            printf("\tA Large buffer contended. ""%" TYPES_64BITFMT "d""\n",
                                   *(messenger->recvList[j].pktDelays));
                        }
                    }
                }
            }
        }
        if ((messenger->recvList[i].msgData.pktHdr.srcAddr == srcAddr) &&
            (messenger->recvList[i].msgData.pktHdr.msgId == msgId))
        {
            return &(messenger->recvList[i]);
        }
    }

    return NULL;
}

static MessengerPktBufferEntry *ReturnRecvEntryForConnId(
    const MessengerState *messenger,
    const int connId,
    int *index)
{
    int i;

    if (DEBUG)
    {
        printf("ReturnRecvEntryForConnId(match connId %d)\n", connId);
    }

    for (i = 0; i < messenger->numRecvList; i++)
    {
        if (DEBUG)
        {
            char srcAddrStr[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(
                messenger->recvList[i].msgData.pktHdr.srcAddr,
                srcAddrStr);

            printf("\tentry[%d] srcAddr %s / msgId %d / connId %d\n",
                   i,
                   srcAddrStr,
                   messenger->recvList[i].msgData.pktHdr.msgId,
                   messenger->recvList[i].msgData.connId);
        }
        if ((messenger->recvList[i].msgData.connId == connId) &&
            (messenger->recvList[i].msgData.sessionOpen))
        {
            if (index)
            {
                *index = i;
            }
            return &(messenger->recvList[i]);
        }
    }

    if (index)
    {
        *index = -1;
    }
    return NULL;
}

static void DeleteRecvEntry(
    MessengerState *messenger,
    const int index)
{
    if (messenger->recvList[index].pktDelays
        != messenger->recvList[index].shortPktDelaysBuffer)
    {
        MEM_free(messenger->recvList[index].pktDelays);
    }

    messenger->numRecvList--;
/*
    if (messenger->numRecvList > (index + 1))
    {
        memmove(&(messenger->recvList[index]), &(messenger->recvList[index+1]),
                sizeof(MessengerPktBufferEntry)
                * (messenger->numRecvList - index));
    }
*/
    {
        int i;

        for (i = index; i < messenger->numRecvList; i++)
        {
            messenger->recvList[i] = messenger->recvList[i + 1];

            if (messenger->recvList[i+1].pktDelays
                == messenger->recvList[i+1].shortPktDelaysBuffer)
            {
                messenger->recvList[i].pktDelays
                    = messenger->recvList[i].shortPktDelaysBuffer;
                if (DEBUG)
                {
                    printf("\tA Rewiring ""%" TYPES_64BITFMT "d"" to ""%" TYPES_64BITFMT "d""\n",
                           *(messenger->recvList[i].pktDelays),
                           *(messenger->recvList[i].shortPktDelaysBuffer));
                }
            }
            else
            {
                if (DEBUG)
                {
                    printf("\tA Large buffer contended. ""%" TYPES_64BITFMT "d""\n",
                           *(messenger->recvList[i].pktDelays));
                }
            }
        }
    }
}

static MessengerPktBufferEntry *AllocateRecvEntrySpace(
    MessengerState *messenger)
{
    MessengerPktBufferEntry *entry;

    if (messenger->numRecvList == messenger->maxRecvList)
    {
        MessengerPktBufferEntry *newRecvList;
        int i;

        if (DEBUG)
        {
            printf("Overrun maxRecvList.  Reallocating.\n");
        }
        newRecvList = (MessengerPktBufferEntry *)
                      MEM_malloc(
                          sizeof(MessengerPktBufferEntry) *
                          (messenger->maxRecvList + RECV_ENTRY_INCREMENT));
        memcpy(newRecvList, messenger->recvList,
               sizeof(MessengerPktBufferEntry) * messenger->maxRecvList);

        for (i = 0; i < messenger->numRecvList; i++)
        {
            if (messenger->recvList[i].pktDelays
                == messenger->recvList[i].shortPktDelaysBuffer)
            {
                newRecvList[i].pktDelays
                    = newRecvList[i].shortPktDelaysBuffer;
                if (DEBUG)
                {
                    printf("\tRewiring ""%" TYPES_64BITFMT "d"" to ""%" TYPES_64BITFMT "d""\n",
                           *(newRecvList[i].pktDelays),
                           *(newRecvList[i].shortPktDelaysBuffer));
                }
            }
            else
            {
                if (DEBUG)
                {
                    printf("\tLarge buffer contended. ""%" TYPES_64BITFMT "d""\n",
                           *(messenger->recvList[i].pktDelays));
                }
            }
        }
        MEM_free(messenger->recvList);
        messenger->recvList = newRecvList;

        messenger->maxRecvList += RECV_ENTRY_INCREMENT;
    }

    entry = &(messenger->recvList[messenger->numRecvList]);
    memset(entry, 0, sizeof(MessengerPktBufferEntry));

    messenger->numRecvList++;

    return entry;
}

static void AllocateRecvBuffers(
    MessengerPktBufferEntry *entry,
    const int numFrags)
{
    if (numFrags <= TYPICAL_NUMBER_OF_PKTS_PER_MSG)
    {
        entry->pktDelays = entry->shortPktDelaysBuffer;
        if (DEBUG)
        {
            printf("Regular Recv Buffer ""%" TYPES_64BITFMT "d"" == ""%" TYPES_64BITFMT "d""\n",
                   *(entry->pktDelays),
                   *(entry->shortPktDelaysBuffer));
        }

        memset(entry->pktDelays, 0,
               sizeof(clocktype) * TYPICAL_NUMBER_OF_PKTS_PER_MSG);
    }
    else
    {
        entry->pktDelays = (clocktype *)
                               MEM_malloc(sizeof(clocktype) * numFrags);
        if (DEBUG)
        {
            printf("Large Recv Buffer ""%" TYPES_64BITFMT "d"" != ""%" TYPES_64BITFMT "d""\n",
                   *(entry->pktDelays),
                   *(entry->shortPktDelaysBuffer));
        }
        memset(entry->pktDelays, 0, sizeof(clocktype) * numFrags);
    }
}

static MessengerPktBufferEntry *CreateRecvEntry(
    Node *node,
    MessengerState *messenger,
    const MessengerPktHeader pktHdr)
{
    MessengerPktBufferEntry *entry;

    if (DEBUG)
    {
        char srcAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(pktHdr.srcAddr, srcAddrStr);

        printf("CreateRecvEntry srcAddr = %s / msgId == %d\n",
               srcAddrStr, pktHdr.msgId);
    }

    entry = AllocateRecvEntrySpace(messenger);

    memcpy(&(entry->msgData.pktHdr), &pktHdr,
           sizeof(MessengerPktHeader));

    AllocateRecvBuffers(entry, pktHdr.numFrags);

    return entry;
}

static MessengerPktBufferEntry *CreateIncompleteRecvEntry(
    MessengerState *messenger,
    const NodeAddress srcAddr,
    const int connId)
{
    MessengerPktBufferEntry *entry;

    if (DEBUG)
    {
        char srcAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(srcAddr, srcAddrStr);

        printf("CreateIncompleteRecvEntry srcAddr = %s / connId = %d\n",
               srcAddrStr, connId);
    }

    entry = AllocateRecvEntrySpace(messenger);

    entry->msgData.pktHdr.srcAddr = srcAddr;
    entry->msgData.connId = connId;
    entry->msgData.sessionOpen = TRUE;

    return entry;
}

static MessengerPktBufferEntry *CreateOrReturnRecvEntry(
    Node *node,
    MessengerState *messenger,
    const MessengerPktHeader pktHdr,
    const clocktype currentTime)
{
    MessengerPktBufferEntry *entry;

    entry = ReturnRecvEntry(
                messenger, pktHdr.srcAddr, pktHdr.msgId, currentTime);

    if (entry == NULL)
    {
        MessengerMessageData msgData;
        entry = CreateRecvEntry(node, messenger, pktHdr);

        msgData.pktHdr = pktHdr;
        SendReminderMsg(node, msgData);
    }

    return entry;
}

static void
MessengerSendChannelSenseTimer(
    Node* node,
    const int eventType,
    const clocktype delay)
{
    Message* timerMsg = NULL;
    timerMsg = MESSAGE_Alloc(node, APP_LAYER,
                 APP_MESSENGER, eventType);
    MESSAGE_Send(node, timerMsg, delay);
}

static void
MessengerSenseChannel(Node *node, MessengerState *messenger)
{
    // Predict Cannel Status for Messenger Application
    if ((messenger->messageLastRecvTime == 0) ||
        ((node->getNodeTime() - messenger->messageLastRecvTime)
            > HLA_VOICE_PACKET_BACKOFF_TIME))
    {
        MessengerSendChannelSenseTimer(node,
                                    MSG_APP_ChannelIsIdle,
                                    PROCESS_IMMEDIATELY);
    }
    else
    {
        MessengerSendChannelSenseTimer(node,
                                    MSG_APP_ChannelIsBusy,
                                    PROCESS_IMMEDIATELY);
    }
}

static void
MessengerDetectCollision(Node *node, MessengerState *messenger)
{
    messenger->messageLastRecvTime = node->getNodeTime();

    if (messenger->messageLastSentTime != 0)
    {
        if ((messenger->messageLastRecvTime - messenger->messageLastSentTime)
                < HLA_VOICE_PACKET_BACKOFF_TIME)
        {
            // Collision Detected.
            messenger->numCollisionDetected++;


            if (DEBUG_STATE)
            {
                char time[MAX_STRING_LENGTH] = {0};
                char adjTime[MAX_STRING_LENGTH] = {0};
                TIME_PrintClockInSecond(node->getNodeTime(), time);
                TIME_PrintClockInSecond(messenger->adjBackoffTime, adjTime);
                printf("#%d: \tSuspecting collition at %s Sec\n",
                    node->nodeId, time);
            }
        }
        else
        {
            if (messenger->numCollisionDetected)
            {
                // Recovery
                messenger->numCollisionDetected = 0;

                if (DEBUG_STATE)
                {
                    char time[MAX_STRING_LENGTH] = {0};
                    TIME_PrintClockInSecond(node->getNodeTime(), time);
                    printf("#%d: \tRecovery at %s Sec\n", node->nodeId, time);
                }
            }
            // Else No Collision
        }
    }
}

static void
MessengerOutputQueueInitialize(
    Node *node,
    MessengerState *messenger)
{
    Queue* queuePtr = NULL;

    // a single FIFO queue
    QUEUE_Setup(
        node,
        &queuePtr,
        "FIFO",
        DEFAULT_APP_QUEUE_SIZE,
        APP_MESSENGER, // this is used to set the random seed
        0,
        0, // infoFieldSize
        FALSE,
        FALSE,
        node->getNodeTime(),
        NULL);

    messenger->queue = queuePtr;
}

static void
MessengerSendAllFromOutputQueue(Node *node, MessengerState *messenger)
{
    Queue* queuePtr = messenger->queue;
    int packetIndex = 0;

    // Dequeue all the packets from the queue which are currently there.
    while (queuePtr->packetsInQueue())
    {
        Message *queueMsg = NULL;

        if (DEBUG_QUEUE)
        {
            char clockStr[MAX_CLOCK_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("#%d: Dequeue Request at %s\n", node->nodeId, clockStr);
        }

        queuePtr->retrieve(&queueMsg,
                           packetIndex,
                           DEQUEUE_PACKET,
                           node->getNodeTime());

        if (queueMsg != NULL)
        {
            if (DEBUG_QUEUE)
            {
                printf("\t\tDequeuing a packet from Queue\n");
            }

            if (TEST_VOICE_APP)
            {
                char SentAt[MAX_CLOCK_STRING_LENGTH];
                TIME_PrintClockInSecond(node->getNodeTime(), SentAt);

                // Transmitt Src SentAt
                fprintf(fp, "%d\t:Tx:\t%s\n", node->nodeId, SentAt);
            }

            messenger->messageLastSentTime = node->getNodeTime();

            // Send All Queued Messeges
            MESSAGE_Send(node, queueMsg, PROCESS_IMMEDIATELY);
        }
    }
}

#ifdef MILITARY_RADIOS_LIB
static void SendFragmentTadil(
    Node* node,
    const MessengerState* messenger,
    MessengerMessageData msgData)
{
    char buf[sizeof(MessengerPktHeader) + MAX_ADDITIONAL_DATA_SIZE];
    char* bufPtr = buf;
    int headerSize = sizeof(MessengerPktHeader);
    NodeAddress destNodeId = ANY_ID;

    ERROR_Assert((msgData.pktHdr.fragSize
                  >= (signed) sizeof(MessengerPktHeader)),
                 "fragment size is too small");

    ERROR_Assert((((msgData.pktHdr.fragSize - sizeof(MessengerPktHeader))
                  * msgData.pktHdr.numFrags)
                 >= msgData.pktHdr.additionalDataSize),
                 "no space for additional data");

    msgData.pktHdr.timeStamp = node->getNodeTime();
    msgData.pktHdr.additionalDataFragId = msgData.dataFragIdToSend;

    if (DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

        printf("#%u:\tSendFragmentTadil at %s\n", node->nodeId, clockStr);
    }

    memcpy(
        bufPtr, (char *) &(msgData.pktHdr), sizeof(MessengerPktHeader));

    bufPtr += sizeof(MessengerPktHeader);

    if (msgData.pktHdr.additionalDataSize > 0)
    {
        int usefulDataSize
            = MIN(msgData.pktHdr.fragSize - sizeof(MessengerPktHeader),
                  msgData.pktHdr.additionalDataSize);
        char* additionalDataPtr
            = ((char *) msgData.additionalData)
              + (usefulDataSize * msgData.dataFragIdToSend);

        memcpy(bufPtr, additionalDataPtr, usefulDataSize);
        msgData.dataFragIdToSend
            = (msgData.dataFragIdToSend + 1)
              % msgData.pktHdr.numAdditionalDataFrags;

        headerSize += usefulDataSize;
    }

    TADIL_AppSendVirtualData(
        node,
        APP_MESSENGER,
        buf,
        headerSize,
        msgData.pktHdr.fragSize - headerSize,
        msgData.pktHdr.srcAddr,
        messenger->msgId, // Source port is not required.
        destNodeId,
        msgData.pktHdr.destAddr,
        msgData.pktHdr.destNPGId,    // NGP destination is supported.
        TRACE_MESSENGER);

    // For update client side statistics.
    MessengerMessageData* sendEntry =
        ReturnSendEntry(messenger,
                        msgData.pktHdr.destAddr,
                        msgData.pktHdr.msgId,
                        node->getNodeTime());

    if (msgData.pktHdr.pktNum == 0)
    {
        sendEntry->messageStartTime = node->getNodeTime();
    }

    msgData.pktHdr.pktNum++;

    sendEntry->pktHdr.pktNum = msgData.pktHdr.pktNum;
    sendEntry->endTime = node->getNodeTime();

    if (msgData.pktHdr.numFrags > msgData.pktHdr.pktNum)
    {
        SendNextPacketMsg(node, msgData, msgData.pktHdr.freq);
    }
}
#endif // MILITARY_RADIOS_LIB

static void SendFragmentUdp(
    Node *node,
    const MessengerState *messenger,
    MessengerMessageData msgData)
{
    char buf[sizeof(MessengerPktHeader) + MAX_ADDITIONAL_DATA_SIZE];
    char *bufPtr = buf;
    int headerSize = sizeof(MessengerPktHeader);

    ERROR_Assert((msgData.pktHdr.fragSize
                  >= (signed) sizeof(MessengerPktHeader)),
                 "fragment size is too small");

    ERROR_Assert((((msgData.pktHdr.fragSize - sizeof(MessengerPktHeader))
                  * msgData.pktHdr.numFrags)
                 >= msgData.pktHdr.additionalDataSize),
                 "no space for additional data");

    msgData.pktHdr.timeStamp = node->getNodeTime();
    msgData.pktHdr.additionalDataFragId =
        (unsigned short) msgData.dataFragIdToSend;

    if (DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

        printf("#%u:\tSendFragmentUdp at %s\n", node->nodeId, clockStr);
    }

    memcpy(
        bufPtr, (char *) &(msgData.pktHdr), sizeof(MessengerPktHeader));

    bufPtr += sizeof(MessengerPktHeader);

    if (msgData.pktHdr.additionalDataSize > 0)
    {
        int usefulDataSize
            = MIN(msgData.pktHdr.fragSize - sizeof(MessengerPktHeader),
                  msgData.pktHdr.additionalDataSize);
        char *additionalDataPtr
            = ((char *) msgData.additionalData)
              + (usefulDataSize * msgData.dataFragIdToSend);

        memcpy(bufPtr, additionalDataPtr, usefulDataSize);
        msgData.dataFragIdToSend
            = (msgData.dataFragIdToSend + 1)
              % msgData.pktHdr.numAdditionalDataFrags;

        headerSize += usefulDataSize;
    }

    if (msgData.pktHdr.appType == VOICE_PACKET)
    {
        BOOL isQueueFull = FALSE;
        Message* msgFrags = NULL;

        msgFrags = APP_UdpCreateMessage(
            node,
            ANY_IP,
            APP_MESSENGER,
            msgData.pktHdr.destAddr,
            APP_MESSENGER,
            TRACE_MESSENGER);

        APP_AddHeader(node, msgFrags, buf, headerSize);

        APP_AddVirtualPayload(node, msgFrags, 
            msgData.pktHdr.fragSize - headerSize);

        // Insert the voice pkt in messenger queue
        messenger->queue->insert(msgFrags,
                                 NULL,
                                 &isQueueFull,
                                 node->getNodeTime());

        if (DEBUG_QUEUE)
        {
            char clockStr[MAX_CLOCK_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

            printf("#%d: Enqueue Request at %s\n", node->nodeId, clockStr);

            if (isQueueFull)
                printf("\t\tDropping a packet as no space in Queue\n");
            else
                printf("\t\tInserting a packet in Queue\n");
        }

        if (TEST_VOICE_APP)
        {
            char SpeakedAt[MAX_CLOCK_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), SpeakedAt);

            // Transmitt Src SpeakedAt
            fprintf(fp, "%d\t:Q :\t%s\n", node->nodeId, SpeakedAt);
        }

        MessengerSenseChannel(node, (MessengerState *) messenger);
    }
    else
    {
        Message *udpmsg = APP_UdpCreateMessage(
            node,
            ANY_IP,
            APP_MESSENGER,
            msgData.pktHdr.destAddr,
            APP_MESSENGER,
            TRACE_MESSENGER);

        APP_AddHeader(node, udpmsg, buf, headerSize);

        APP_AddVirtualPayload(node, udpmsg, 
            msgData.pktHdr.fragSize - headerSize);

        APP_UdpSend(node, udpmsg, PROCESS_IMMEDIATELY); 
    }

    // For update client side statistics.
    MessengerMessageData* sendEntry =
        ReturnSendEntry(messenger,
                        msgData.pktHdr.destAddr,
                        msgData.pktHdr.msgId,
                        node->getNodeTime());

    if (msgData.pktHdr.pktNum == 0)
    {
        sendEntry->messageStartTime = node->getNodeTime();
    }

    msgData.pktHdr.pktNum++;

    sendEntry->pktHdr.pktNum = msgData.pktHdr.pktNum;
    sendEntry->endTime = node->getNodeTime();

    if (msgData.pktHdr.numFrags > msgData.pktHdr.pktNum)
    {
        SendNextPacketMsg(node, msgData, msgData.pktHdr.freq);
    }
}

static void SendFragmentTcp(
    Node *node,
    MessengerState *messenger,
    MessengerMessageData msgData,
    const clocktype currentTime)
{
    MessengerMessageData *sendEntry;

    ERROR_Assert((msgData.pktHdr.fragSize
                 >= (signed) sizeof(MessengerPktHeader)),
                 "fragment size is too small");

    ERROR_Assert((((sizeof(MessengerPktHeader) - msgData.pktHdr.fragSize)
                  * msgData.pktHdr.numFrags)
                 > msgData.pktHdr.additionalDataSize),
                 "no space for additional data");

    if (DEBUG)
    {
        printf("#%u:\tSendFragmentTcp\n", node->nodeId);
    }

    sendEntry = ReturnSendEntry(
                    messenger,
                    msgData.pktHdr.destAddr,
                    msgData.pktHdr.msgId,
                    currentTime);

    if (sendEntry)
    {
        ERROR_Assert(((sendEntry->pktHdr.pktNum == 0) &&
                      (sendEntry->pktHdr.numFrags == 1)),
                     "only one fragment at a time");

        SendReminderMsg(node, msgData);

        APP_TcpOpenConnection(
            node,
            APP_MESSENGER,
            msgData.pktHdr.srcAddr,
            (short) APP_GetFreePort(node),
            msgData.pktHdr.destAddr,
            (short) APP_MESSENGER,
            msgData.pktHdr.msgId,
            PROCESS_IMMEDIATELY);
    }
    else
    {
        ERROR_ReportError("Entry is not found.\n");
    }
}

static void SendFragment(
    Node *node,
    MessengerState *messenger,
    const MessengerMessageData msgData)
{
    if (msgData.pktHdr.transportType == TRANSPORT_TYPE_UNRELIABLE)
    {
        SendFragmentUdp(node, messenger, msgData);
    }
    else if (msgData.pktHdr.transportType == TRANSPORT_TYPE_RELIABLE)
    {
        SendFragmentTcp(node, messenger, msgData, node->getNodeTime());
    }

#ifdef MILITARY_RADIOS_LIB
    else if (msgData.pktHdr.transportType == TRANSPORT_TYPE_MAC)
    {
        // ASSUMPTION: node has only one interface with TADIL mac protocol.
        SendFragmentTadil(node, messenger, msgData);
    }
#endif //MILITARY_RADIOS_LIB

    else
    {
        ERROR_ReportError("Invalid value of pktHdr.transportType");
    }
}

static BOOL AdditionalDataReassemblyComplete(
    MessengerPktBufferEntry *recvEntry)
{
    int i;

    if (recvEntry->msgData.pktHdr.additionalDataSize == 0)
    {
        return TRUE;
    }

    for (i = 0; i < recvEntry->msgData.pktHdr.numAdditionalDataFrags; i++)
    {
        if (recvEntry->msgData.dataFragRecvd[i] == FALSE)
        {
            ERROR_ReportWarning("Message still incomplete only because "
                "data reassembly incomplete.");

            return FALSE;
        }
    }

    return TRUE;
}

static BOOL MessageComplete(
    Node *node,
    MessengerState *messenger,
    const MessengerPktHeader pktHdr,
    BOOL *alreadyReturnedComplete,
    BOOL markResultComplete,
    const UdpToAppRecv *udpToApp)
{
    MessengerPktBufferEntry *recvEntry;
    int i;

    if (DEBUG)
    {
        printf("#%u:\tMessageComplete\n", node->nodeId);
    }

    recvEntry = ReturnRecvEntry(
                    messenger,
                    pktHdr.srcAddr,
                    pktHdr.msgId,
                    node->getNodeTime());

    if (!recvEntry)
    {
        *alreadyReturnedComplete = TRUE;
        return FALSE;
    }

    if (recvEntry->alreadyReturnedComplete)
    {
        *alreadyReturnedComplete = TRUE;
        return FALSE;
    }

    if (pktHdr.transportType == TRANSPORT_TYPE_UNRELIABLE ||
        pktHdr.transportType == TRANSPORT_TYPE_MAC)
    {
        int consecutiveDrops = 0;

        for (i = (pktHdr.numFrags - 1); i >= 0; i--)
        {
            if (recvEntry->pktDelays[i] == 0)
            {
                consecutiveDrops++;
                if (consecutiveDrops > MAX_CONSECUTIVE_DROPS)
                {
                    *alreadyReturnedComplete = FALSE;
                    if (markResultComplete)
                    {
                        recvEntry->alreadyReturnedComplete = TRUE;
                    }
                    return FALSE;
                }
            }
            else
            {
                consecutiveDrops = 0;
            }
        }

        if (AdditionalDataReassemblyComplete(recvEntry))
        {
            recvEntry->alreadyReturnedComplete = TRUE;
            *alreadyReturnedComplete = FALSE;
            return TRUE;
        }
        else
        {
            *alreadyReturnedComplete = FALSE;
            return FALSE;
        }
    }
    else // TRANSPORT_TYPE_RELIABLE
    {
        *alreadyReturnedComplete = FALSE;

        if (markResultComplete)
        {
            recvEntry->alreadyReturnedComplete = TRUE;
        }

        return FALSE;
    }
}

static void MarkPacketArrival(
    Node *node,
    MessengerState *messenger,
    const MessengerPktHeader pktHdr,
    char *additionalDataPtr,
    MessengerPktBufferEntry *recvEntry = NULL)
{
    if (!recvEntry)
    {
        recvEntry = CreateOrReturnRecvEntry(
                        node, messenger, pktHdr, node->getNodeTime());
    }
    recvEntry->pktDelays[pktHdr.pktNum]
        = node->getNodeTime() - pktHdr.timeStamp;

    if (pktHdr.pktNum == 0)
    {
        recvEntry->msgData.messageStartTime = pktHdr.timeStamp;
    }

    if ((additionalDataPtr) && pktHdr.additionalDataSize > 0)
    {
        int dataSize = MIN(pktHdr.fragSize - sizeof(MessengerPktHeader),
                           pktHdr.additionalDataSize);

        char *ptr = (char *) recvEntry->msgData.additionalData;

        ptr += (dataSize * pktHdr.additionalDataFragId);

        memcpy(ptr, additionalDataPtr, dataSize);
        recvEntry->msgData.dataFragRecvd[pktHdr.additionalDataFragId] = TRUE;
    }
}

static void MarkConnectionClosed(
    MessengerState *messenger,
    int connId)
{
    MessengerPktBufferEntry *recvEntry;
    int index;

    recvEntry = ReturnRecvEntryForConnId(messenger, connId, &index);

    if (recvEntry)
    {
        // DeleteRecvEntry(messenger, index);
        recvEntry->msgData.sessionOpen = FALSE;
    }
    else
    {
        MessengerMessageData *sendEntry;

        sendEntry = ReturnSendEntryForConnId(messenger, connId, &index);

        if (sendEntry)
        {
            // Only set the session to FALSE with out remove the sendEntry
            // for print the statistics at end of the simulation.

            // DeleteSendEntry(messenger, index);
            sendEntry->sessionOpen = FALSE;
        }
    }

}

static void MessengerWriteTransportType(
    Node *node,
    TransportType transportType,
    char* transportTypeStr)
{
    switch (transportType)
    {
        case TRANSPORT_TYPE_RELIABLE:
        {
            strcpy(transportTypeStr, "Reliable");
            break;
        }
        case TRANSPORT_TYPE_UNRELIABLE:
        {
            strcpy(transportTypeStr, "Unreliable");
            break;
        }
        case TRANSPORT_TYPE_MAC: // For LINK16 and LINK11
        {
            strcpy(transportTypeStr, "Mac");
            break;
        }
        default:
        {
            // invalid transport type
            char errString[MAX_STRING_LENGTH];
            sprintf(errString, "node :%u\nInvalid transport type.\n",
                node->nodeId);
            ERROR_ReportError(errString);
            break;
        }
    }
}

static void RecordStatistics(
    Node *node,
    MessengerState *messenger,
    MessengerPktHeader pktHdr,
    const clocktype currentTime,
    MessengerPktBufferEntry *recvEntry = NULL)
{
    int i;
    clocktype totalDelay = 0;
    clocktype totalJitters = 0;
    clocktype currentDelay = 0;
    clocktype lastDelay = 0;
    clocktype currentJitter = 0;
    clocktype lastJitter = 0;
    int throughput = 0;
    int numFragsRecvd = 0;
    NodeAddress srcId;
    char transportTypeStr[MAX_STRING_LENGTH];

    if (!recvEntry)
    {
        recvEntry = ReturnRecvEntry(
                        messenger, pktHdr.srcAddr, pktHdr.msgId, currentTime);
    }

    ERROR_Assert(recvEntry,
                 "Unable to locate recvEntry for RecordStatistics");

    if (recvEntry->alreadyReturnedComplete == FALSE)
    {
        return;
    }

    MessengerWriteTransportType(
        node,
        (TransportType) pktHdr.transportType,
        transportTypeStr);

    for (i = 0; i < pktHdr.numFrags; i++)
    {
        lastDelay = currentDelay;
        currentDelay = recvEntry->pktDelays[i];
        lastJitter = currentJitter;
        currentJitter = clocktypeabs((currentDelay - lastDelay));

        if (currentDelay > 0)
        {
            numFragsRecvd++;

            if (lastJitter > 0)
            {
                totalJitters += clocktypeabs((currentJitter - lastJitter));
            }
        }
    }

    totalDelay = currentTime - recvEntry->msgData.messageStartTime;
    srcId = MAPPING_GetNodeIdFromInterfaceAddress(node, pktHdr.srcAddr);

    IO_PrintStat(
        node,
        "Application",
        "Messenger",
        ANY_DEST,
        pktHdr.msgId,
        "FLOW %u:%d Transport = %s",
        srcId,
        pktHdr.msgId,
        transportTypeStr);

    if (totalDelay > 0)
    {
        throughput = (int) ((pktHdr.numFrags * pktHdr.fragSize * 8 * SECOND)
                            / totalDelay);

        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            pktHdr.msgId,
            "FLOW %u:%d Receiver Throughput = %d bps",
            srcId,
            pktHdr.msgId,
            throughput);

    }

    IO_PrintStat(
        node,
        "Application",
        "Messenger",
        ANY_DEST,
        pktHdr.msgId,
        "FLOW %u:%d number of fragments recvd/total = %d/%d",
        srcId,
        pktHdr.msgId,
        numFragsRecvd,
        pktHdr.numFrags);

    IO_PrintStat(
        node,
        "Application",
        "Messenger",
        ANY_DEST,
        pktHdr.msgId,
        "FLOW %u:%d Number of bytes recv = %d",
        srcId,
        pktHdr.msgId,
        pktHdr.numFrags * pktHdr.fragSize);

    IO_PrintStat(
        node,
        "Application",
        "Messenger",
        ANY_DEST,
        pktHdr.msgId,
        "FLOW %d:%d total end-to-end delay = %f",
        srcId,
        pktHdr.msgId,
        ((double) totalDelay) / SECOND);

    if (numFragsRecvd > 0)
    {
        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            pktHdr.msgId,
            "FLOW %d:%d average end-to-end delay = %f",
            srcId,
            pktHdr.msgId,
            ((double) (totalDelay / numFragsRecvd)) / SECOND);

        if (numFragsRecvd > 2)
        {
            IO_PrintStat(
                node,
                "Application",
                "Messenger",
                ANY_DEST,
                pktHdr.msgId,
                "FLOW %d:%d average jitter = %f",
                srcId,
                pktHdr.msgId,
                ((double) (totalJitters / (numFragsRecvd - 1))) / SECOND);
        }
    }
}

void MessengerRegisterResultFunction(
    Node *node,
    MessageResultFunctionType functionPtr)
{
    MessengerState *messenger = GetPointer(node);

    ERROR_Assert(messenger, "Messenger App not started");

    messenger->messageResultFunc = functionPtr;
}

void TestResultFunction(Node *node, Message *msg, BOOL success)
{
    if (DEBUG)
    {
        printf("#%u: TestResultFunction, %s.\n",
               node->nodeId,
               success ? "Message Received" : "Message NOT Received");
    }
    MESSAGE_Free(node, msg);
}

static void TestInitialize(Node *node, MessengerState *messenger)
{
    MessengerPktHeader pktHdr;
    char mydata[10] = "hello";
    char dstIpv4AddressString[] = "225.0.0.0";
    NodeAddress dstIpv4Address;
    int numHostBits;
    BOOL isNodeId;

    IO_ParseNodeIdHostOrNetworkAddress(
        dstIpv4AddressString,
        &dstIpv4Address,
        &numHostBits,
        &isNodeId);

    printf("dstIpv4Address = %8x hex\n", dstIpv4Address);

    MessengerRegisterResultFunction(node, &TestResultFunction);

    pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                         node, node->nodeId);
    pktHdr.destAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                          node, (node->nodeId % node->numNodes) + 1);
    //pktHdr.destAddr = dstIpv4Address;
    pktHdr.msgId = messenger->msgId;
    messenger->msgId++;
    pktHdr.appType = GENERAL;
    pktHdr.transportType = TRANSPORT_TYPE_UNRELIABLE;
    pktHdr.numFrags = 5;
    pktHdr.pktNum = 0;
    pktHdr.initialPrDelay = 0;
    pktHdr.lifetime = 4 * SECOND;
    pktHdr.freq = 500 * MILLI_SECOND;
    pktHdr.fragSize = 800;

    MessengerSendMessage(node, pktHdr, mydata, 10, &TestResultFunction);

    pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, node->nodeId);
    pktHdr.destAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                              node, ((node->nodeId + 1) % node->numNodes));
    pktHdr.msgId = messenger->msgId;
    messenger->msgId++;

    pktHdr.transportType = TRANSPORT_TYPE_UNRELIABLE;
    pktHdr.numFrags = 5;
    pktHdr.pktNum = 0;
    pktHdr.initialPrDelay = 31 * SECOND;
    pktHdr.lifetime = 4 * SECOND;
    pktHdr.freq = 500 * MILLI_SECOND;
    pktHdr.fragSize = 800;

    MessengerSendMessage(node, pktHdr, NULL, 0, &TestResultFunction);

    pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, node->nodeId);
    pktHdr.destAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                              node, ((node->nodeId + 1) % node->numNodes));
    pktHdr.msgId = messenger->msgId;
    messenger->msgId++;

    pktHdr.transportType = TRANSPORT_TYPE_RELIABLE;
    pktHdr.numFrags = 1;
    pktHdr.pktNum = 0;
    pktHdr.initialPrDelay = 1 * SECOND;
    pktHdr.lifetime = 10 * SECOND;
    pktHdr.fragSize = 80000;

    MessengerSendMessage(node, pktHdr, mydata, 10, &TestResultFunction);
}

static void
TestVoiceCommunicationInit(Node *node, MessengerState *messenger)
{
    MessengerPktHeader pktHdr;

    MessengerRegisterResultFunction(node, &TestResultFunction);

    // Voice Communication consist of 100 Fragments 1 -> ALL
    if (node->nodeId == 1)
    {
        pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, node->nodeId);
        pktHdr.destAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, 2);;
        pktHdr.msgId = messenger->msgId;
        pktHdr.appType = VOICE_PACKET;
        pktHdr.transportType = TRANSPORT_TYPE_UNRELIABLE;
        pktHdr.numFrags = 100;
        pktHdr.pktNum = 0;
        pktHdr.initialPrDelay = 1 * SECOND;
        pktHdr.lifetime = 30 * SECOND;
        pktHdr.freq = HLA_VOICE_PACKET_FREQUENCY;
        pktHdr.fragSize = 500;

        if (DEBUG)
        {
            char srcStr[MAX_STRING_LENGTH] = {0};
            char dstStr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(pktHdr.srcAddr, srcStr);
            IO_ConvertIpAddressToString(pktHdr.destAddr, dstStr);

            printf("---------------------------------------\n"
                "#%d \tUnreliable : fragment #%d of %d\n"
                "---------------------------------------\n"
                "Src %s \t\t\t Dst %s\n"
                "---------------------------------------\n",
                node->nodeId, pktHdr.pktNum + 1, pktHdr.numFrags,
                srcStr, dstStr);
        }

        MessengerSendMessage(node, pktHdr, NULL, 0, &TestResultFunction);
    }
    messenger->msgId++;

    // Voice Communication consist of 4 Fragments 2 -> ALL
    if (node->nodeId == 2)
    {
        pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, node->nodeId);
        pktHdr.destAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, 1);;
        pktHdr.msgId = messenger->msgId;
        pktHdr.appType = VOICE_PACKET;
        pktHdr.transportType = TRANSPORT_TYPE_UNRELIABLE;
        pktHdr.numFrags = 100;
        pktHdr.pktNum = 0;
        //pktHdr.initialPrDelay = 1.15 * SECOND;
        pktHdr.initialPrDelay = 1 * SECOND;
        pktHdr.lifetime = 75 * SECOND;
        pktHdr.freq = HLA_VOICE_PACKET_FREQUENCY;
        pktHdr.fragSize = 500;

        if (DEBUG)
        {
            char srcStr[MAX_STRING_LENGTH] = {0};
            char dstStr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(pktHdr.srcAddr, srcStr);
            IO_ConvertIpAddressToString(pktHdr.destAddr, dstStr);

            printf("---------------------------------------\n"
                "#%d \tUnreliable : fragment #%d of %d\n"
                "---------------------------------------\n"
                "Src %s \t\t\t Dst %s\n"
                "---------------------------------------\n",
                node->nodeId, pktHdr.pktNum + 1, pktHdr.numFrags,
                srcStr, dstStr);
        }

        MessengerSendMessage(node, pktHdr, NULL, 0, &TestResultFunction);
    }
    messenger->msgId++;

    // Voice Communication consist of 20 Fragments 1 -> ALL
    if (node->nodeId == 3)
    {
        pktHdr.srcAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                             node, node->nodeId);
        pktHdr.destAddr = 0xffffffff;

        pktHdr.msgId = messenger->msgId;
        pktHdr.appType = VOICE_PACKET;
        pktHdr.transportType = TRANSPORT_TYPE_UNRELIABLE;
        pktHdr.numFrags = 20;
        pktHdr.pktNum = 0;
        pktHdr.initialPrDelay = 8 * SECOND;
        pktHdr.lifetime = 80 * SECOND;
        pktHdr.freq = HLA_VOICE_PACKET_FREQUENCY;
        pktHdr.fragSize = 500;

        if (DEBUG)
        {
            char srcStr[MAX_STRING_LENGTH] = {0};
            char dstStr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(pktHdr.srcAddr, srcStr);
            IO_ConvertIpAddressToString(pktHdr.destAddr, dstStr);

            printf("---------------------------------------\n"
                "#%d \tUnreliable : fragment #%d of %d\n"
                "---------------------------------------\n"
                "Src %s \t\t\t Dst %s\n"
                "---------------------------------------\n",
                node->nodeId, pktHdr.pktNum + 1, pktHdr.numFrags,
                srcStr, dstStr);
        }

        MessengerSendMessage(node, pktHdr, NULL, 0, &TestResultFunction);
    }
    messenger->msgId++;
}

void MessengerInit(Node *node)
{
    MessengerState *messenger = GetPointer(node);

    if (!messenger)
    {
        messenger = (MessengerState *)
                    MEM_malloc(sizeof(MessengerState));

        memset(messenger, 0, sizeof(MessengerState));

        messenger->srcId = node->nodeId;

        MessengerOutputQueueInitialize(node, messenger);

        messenger->backoffDistribution.setSeed(node->globalSeed,
                                               node->nodeId,
                                               APP_MESSENGER);
        messenger->backoffDistribution.setDistributionUniform(
                    HLA_VOICE_PACKET_BACKOFF_TIME,
                    (2 * HLA_VOICE_PACKET_BACKOFF_TIME));
        messenger->adjBackoffTime = HLA_VOICE_PACKET_BACKOFF_TIME;

        if (DEBUG_STATE)
        {
            char time[MAX_STRING_LENGTH] = {0};
            TIME_PrintClockInSecond(messenger->adjBackoffTime, time);
            printf("#%d: \tInitial Backoff Time is %s Sec\n",
                node->nodeId, time);
        }

        messenger->recvList
            = (MessengerPktBufferEntry *)
              MEM_malloc(
                  sizeof(MessengerPktBufferEntry) * node->numNodes);
        messenger->maxRecvList = node->numNodes;

        APP_RegisterNewApp(node, APP_MESSENGER, messenger);

        APP_TcpServerListen(
            node,
            APP_MESSENGER,
            MAPPING_GetDefaultInterfaceAddressFromNodeId(
                node, node->nodeId),
            APP_MESSENGER);

        if (TEST_APP)
        {
            TestInitialize(node, messenger);
        }

        if (TEST_VOICE_APP)
        {
            TestVoiceCommunicationInit(node, messenger);
        }
    }
}

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
#ifdef MILITARY_RADIOS_LIB
    unsigned short destNPGId,
#endif
    char* filename)
{
    FILE* fp = NULL;
    char* buf = NULL;
    int size = 0;
    char time[MAX_STRING_LENGTH] = {0};
    MessengerPktHeader pktHdr;
    MessengerState* messenger = NULL;

    MessengerInit(node);

    messenger = GetPointer(node);

    MessengerRegisterResultFunction(node, &TestResultFunction);

    pktHdr.srcAddr = srcAddr;
    pktHdr.destAddr = destAddr;
    pktHdr.msgId = messenger->msgId++;
    pktHdr.appType = app_type;
    pktHdr.transportType = (short) t_type;
    pktHdr.numFrags = (unsigned short) fragNum;
    pktHdr.pktNum = 0;
    pktHdr.initialPrDelay = startTime;
    pktHdr.lifetime = lifeTime;
    pktHdr.freq = interval;
    pktHdr.fragSize = fragSize;
#ifdef MILITARY_RADIOS_LIB
    pktHdr.destNPGId = destNPGId;
#endif
    if (filename)
    {
        fp = fopen(filename, "rb");
        ERROR_Assert(fp, "MESSENGER: File does not exist\n");

        fseek( fp, 0L, SEEK_END);
        size = ftell(fp);

        if (size > MAX_ADDITIONAL_DATA_SIZE)
        {
            sprintf(time,
                "MESSENGER: Not support more than 80 bytes real data %u\n",
                node->nodeId);
            ERROR_ReportWarning(time);
            size = MAX_ADDITIONAL_DATA_SIZE;
        }

        buf = (char*) MEM_malloc(size);
        rewind( fp);

        if (fread( buf, sizeof(char), size, fp) != (unsigned int)size)
        {
           sprintf(time,"MESSENGER: Unable to read data of size %d"
                        "from file %s \n",size, filename);
           ERROR_ReportError(time);
        }
        fclose(fp);
    }
    MessengerSendMessage(node, pktHdr, buf, size, &TestResultFunction);
}

// /**
// FUNCTION    :: MessengerServerListen
// LAYER       :: APPLICATION
// PURPOSE     :: It initializes the Server into Listen state.
//                This function is called when the destination is unicast.
// PARAMETERS  ::
// + node       : Node* : Pointer to the node running the messenger app.
// RETURN      :: void : NULL
// **/
void MessengerServerListen(Node* node)
{
    APP_TcpServerListen(
        node,
        APP_MESSENGER,
        MAPPING_GetDefaultInterfaceAddressFromNodeId(node, node->nodeId),
        APP_MESSENGER);
}


// /**
// FUNCTION    :: MessengerServerInit
// LAYER       :: APPLICATION
// PURPOSE     :: It initializes the Server end. This function is called
//                when server receive packet for first time.
// PARAMETERS  ::
// + node       : Node* : Pointer to the node running the messenger app.
// RETURN      :: MessengerState* : pointer of MessengerState.
// **/
static
MessengerState* MessengerServerInit(Node* node)
{
    MessengerInit(node);
    return GetPointer(node);
}
#endif //STANDALONE_MESSENGER_APPLICATION

void MessengerSendMessage(
    Node *node,
    MessengerPktHeader pktHdr,
    char *additionalData,
    int additionalDataSize,
    MessageResultFunctionType functionPtr)
{
    char buf1[MAX_CLOCK_STRING_LENGTH];
    MessengerState *messenger = GetPointer(node);
    MessengerMessageData msgData;

    ERROR_Assert(messenger, "Messenger App not started");

    memset(&msgData, 0, sizeof(MessengerMessageData));

    if (DEBUG || DEBUG_MESSAGE)
    {
        char buf[MAX_CLOCK_STRING_LENGTH];
        char destAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(pktHdr.destAddr, destAddrStr);

        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("#%u: App got SendRequest (#%u:%d) at %s.\n",
               node->nodeId,
               node->nodeId,
               pktHdr.msgId,
               buf);
        TIME_PrintClockInSecond(pktHdr.freq, buf);

        printf("\t%s : %d fragments of size %d, "
               "frequency %s to %s\n",
               (pktHdr.transportType == TRANSPORT_TYPE_RELIABLE ?
               "Reliable" : pktHdr.transportType ==
               TRANSPORT_TYPE_UNRELIABLE ? "Unreliable" :
               "Tadil"),
               pktHdr.numFrags,
               pktHdr.fragSize,
               buf,
               destAddrStr);

        TIME_PrintClockInSecond(pktHdr.initialPrDelay, buf);
        TIME_PrintClockInSecond(pktHdr.lifetime, buf1);
        printf("\tsend after %s, lifetime %s\n", buf, buf1);
    }
    pktHdr.pktNum = 0;
    pktHdr.messageResultFunc = functionPtr;
    pktHdr.additionalDataSize = (unsigned short) additionalDataSize;

    if (additionalDataSize > 0)
    {
        memcpy(msgData.additionalData, additionalData, additionalDataSize);
        pktHdr.numAdditionalDataFrags
            = (unsigned short) (ceil((double) additionalDataSize
                     / (pktHdr.fragSize - sizeof(MessengerPktHeader))));

        if (DEBUG)
        {
            printf("additionalDataSize = %d %d pkts of %" 
                             TYPES_SIZEOFMFT "u bytes\n",
                   additionalDataSize,
                   pktHdr.numAdditionalDataFrags,
                   (pktHdr.fragSize - sizeof(MessengerPktHeader)));
        }
    }

    msgData.pktHdr = pktHdr;

    ERROR_Assert((pktHdr.numFrags
                 * (pktHdr.fragSize - sizeof(MessengerPktHeader))
                 >= (unsigned int) additionalDataSize),
                 "Not enough space to send the additional data");

    // Initialize sendEntry for client side statistics.
    MessengerMessageData* sendEntry =
        CreateSendEntry(node, messenger, msgData);

    if (pktHdr.initialPrDelay > 0)
    {
        SendNextPacketMsg(node, msgData, pktHdr.initialPrDelay);
    }
    else
    {   // send first fragment now

        SendFragment(node, messenger, msgData);
    }

    SendReminderMsg(node, msgData);
}

static void MessengerDoReassembly(
    Node *node,
    MessengerPktBufferEntry *recvEntry,
    char **pktPtr,
    int *packetBytesRemaining)
{
    MessengerState *messenger = GetPointer(node);

    if (DEBUG)
    {
        printf("MessengerDoReassembly(%d)\n", *packetBytesRemaining);
    }

    switch (recvEntry->receiveState)
    {
        case INIT:
        {
            if (DEBUG)
            {
                printf("TCP Reassembly: starting new message\n");
            }
            recvEntry->receiveBytesRemaining = sizeof(MessengerPktHeader);
            recvEntry->receiveState = HEADER;

            break;
        }

        case HEADER:
        {
            if (*packetBytesRemaining >= recvEntry->receiveBytesRemaining)
            {
                MessengerPktHeader *pktHdr;

                memcpy(&(recvEntry->receiveBuffer
                             [sizeof(MessengerPktHeader)
                              - recvEntry->receiveBytesRemaining]),
                       *pktPtr,
                       recvEntry->receiveBytesRemaining);

                pktHdr = (MessengerPktHeader *) recvEntry->receiveBuffer;

                memcpy(
                    &(recvEntry->msgData.pktHdr),
                    recvEntry->receiveBuffer,
                    sizeof(MessengerPktHeader));

                AllocateRecvBuffers(
                    recvEntry, recvEntry->msgData.pktHdr.numFrags);

                SendReminderMsg(node, recvEntry->msgData);

                *packetBytesRemaining -= recvEntry->receiveBytesRemaining;
                *pktPtr += recvEntry->receiveBytesRemaining;

                recvEntry->receiveBytesRemaining
                    = recvEntry->msgData.pktHdr.additionalDataSize;

                if (DEBUG)
                {
                    printf("TCP Reassembly: header received successfully\n");
                }
                recvEntry->receiveState = ADDITIONAL_DATA;
            }
            else
            {
                // incomplete packet
                memcpy(
                    &(recvEntry->receiveBuffer
                          [sizeof(MessengerPktHeader)
                           - recvEntry->receiveBytesRemaining]),
                       *pktPtr,
                       *packetBytesRemaining);

                recvEntry->receiveBytesRemaining -= *packetBytesRemaining;
                *pktPtr += *packetBytesRemaining;
                *packetBytesRemaining = 0;

            }

            break;
        } // case HEADER
        case ADDITIONAL_DATA:
        {
            if (*packetBytesRemaining >= recvEntry->receiveBytesRemaining)
            {
                memcpy(&(recvEntry->msgData.additionalData
                             [recvEntry->msgData.pktHdr.additionalDataSize
                              - recvEntry->receiveBytesRemaining]),
                       *pktPtr,
                       recvEntry->receiveBytesRemaining);


                *packetBytesRemaining -= recvEntry->receiveBytesRemaining;
                *pktPtr += recvEntry->receiveBytesRemaining;

                recvEntry->receiveBytesRemaining
                    = recvEntry->msgData.pktHdr.fragSize
                      - recvEntry->msgData.pktHdr.additionalDataSize
                      - sizeof(MessengerPktHeader);

                if (DEBUG)
                {
                    printf("TCP Reassembly: "
                           "additional data recvd successfully\n");
                }
                recvEntry->receiveState = VIRTUAL_PAYLOAD;

            }
            else
            {
                memcpy(
                    &(recvEntry->msgData.additionalData
                          [recvEntry->msgData.pktHdr.additionalDataSize
                           - recvEntry->receiveBytesRemaining]),
                       *pktPtr,
                       *packetBytesRemaining);

                recvEntry->receiveBytesRemaining -= *packetBytesRemaining;
                *pktPtr += *packetBytesRemaining;
                *packetBytesRemaining = 0;
            }
            break;
        }
        case VIRTUAL_PAYLOAD:
        {
            if (*packetBytesRemaining >= recvEntry->receiveBytesRemaining)
            {
                Message *resultMsg;

                if (DEBUG || DEBUG_MESSAGE)
                {
                    char buf[MAX_CLOCK_STRING_LENGTH];
                    TIME_PrintClockInSecond(node->getNodeTime(),buf);
                    printf("#%u: Reliable Message completion at %s\n",
                           node->nodeId, buf);
                }

                resultMsg = MESSAGE_Alloc(node, APP_LAYER,
                                  APP_MESSENGER, MSG_APP_SendResult);

                MESSAGE_InfoAlloc(
                    node, resultMsg, sizeof(MessengerPktHeader));

                memcpy(MESSAGE_ReturnInfo(resultMsg),
                       &(recvEntry->msgData.pktHdr),
                       sizeof(MessengerPktHeader));

                if (recvEntry->msgData.pktHdr.additionalDataSize > 0)
                {
                    MESSAGE_PacketAlloc(
                        node,
                        resultMsg,
                        recvEntry->msgData.pktHdr.additionalDataSize,
                        TRACE_MESSENGER);

                    memcpy(MESSAGE_ReturnPacket(resultMsg),
                           recvEntry->msgData.additionalData,
                           recvEntry->msgData.pktHdr.additionalDataSize);
                }

                MarkPacketArrival(
                    node,
                    messenger,
                    recvEntry->msgData.pktHdr,
                    NULL,
                    recvEntry);

                recvEntry->alreadyReturnedComplete = TRUE;

                recvEntry->msgData.endTime = node->getNodeTime();

                ERROR_Assert(recvEntry->msgData.pktHdr.messageResultFunc,
                             "Result Function Not Registered");

                // Set the Ack status and the receivers node Id in message info.
                AckStatus* info = (AckStatus*)MESSAGE_AddInfo(
                                              node,
                                              resultMsg,
                                              sizeof(AckStatus),
                                              INFO_TYPE_AppMessenger_Status);
                info->status = true;
                info->receiverNodeId = node->nodeId;
                int remoteNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                         node,
                                         recvEntry->msgData.pktHdr.srcAddr);

                // Check if the node exist on local partition or not.
                Node* senderNode = MAPPING_GetNodePtrFromHash(
                                        node->partitionData->nodeIdHash,
                                        remoteNodeId);
                if (!senderNode)
                {
                    senderNode = MAPPING_GetNodePtrFromHash(
                                       node->partitionData->remoteNodeIdHash,
                                       remoteNodeId);
                    EXTERNAL_MESSAGE_SendAnyNode(senderNode->partitionData,
                                                 senderNode,
                                                 resultMsg,
                                                 0,
                                                 EXTERNAL_SCHEDULE_LOOSELY); 
                }
                else
                {
                    recvEntry->msgData.pktHdr.messageResultFunc(node,
                                                                resultMsg,
                                                                TRUE);
                }

                RecordStatistics(
                    node,
                    messenger,
                    recvEntry->msgData.pktHdr,
                    node->getNodeTime(),
                    recvEntry);

                if (node->guiOption)
                {
                    GUI_Receive(
                        recvEntry->msgData.pktHdr.srcAddr,
                        node->nodeId,
                        GUI_APP_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        0,
                        0,
                        node->getNodeTime());
                }

                APP_TcpCloseConnection(node, recvEntry->msgData.connId);

                *packetBytesRemaining -= recvEntry->receiveBytesRemaining;
                *pktPtr += recvEntry->receiveBytesRemaining;
                recvEntry->receiveState = INIT;
                if (DEBUG)
                {
                    printf("TCP Reassembly: "
                           "virtual data recvd successfully\n");
                }
            }
            else
            {
                recvEntry->receiveBytesRemaining -= *packetBytesRemaining;
                *pktPtr += *packetBytesRemaining;
                *packetBytesRemaining = 0;
                if (DEBUG)
                {
                    printf("TCP Reassembly: %d virtual bytes to go\n",
                           recvEntry->receiveBytesRemaining);
                }
            }
            break;
        }
    } // switch
}

void MessengerLayer(Node *node, Message *msg)
{
    char buf[MAX_CLOCK_STRING_LENGTH];

    MessengerState *messenger = GetPointer(node);

#ifndef STANDALONE_MESSENGER_APPLICATION
    ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION

    if (DEBUG)
    {
        TIME_PrintClockInSecond(node->getNodeTime(), buf);

        printf("#%d: MessengerLayer at %s\n", node->nodeId, buf);
    }

    switch(msg->eventType) {

       case MSG_APP_SendResult: {

             // Get Ack Status and Reciever node Id form message info
             AckStatus* info = (AckStatus*)MESSAGE_ReturnInfo(
                                                msg,
                                                INFO_TYPE_AppMessenger_Status);
             MessengerPktHeader* pktHdr = (MessengerPktHeader*)MESSAGE_ReturnInfo(msg);
            
             // Get the recievers node pointer from nodeIdHash
             Node* destNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash,
                                                         info->receiverNodeId);
             if (!destNode)
             {
                 // Node doesn't lie in the local partition, get node pointer from remoteNodeIdHash
                 destNode = MAPPING_GetNodePtrFromHash(node->partitionData->remoteNodeIdHash, info->receiverNodeId);
             }

             // Invoke the result function using the registered callback using the respective status info.
             if (info->status)
             {
                 pktHdr->messageResultFunc(destNode , msg, true);
             }
             else
             {
                 pktHdr->messageResultFunc(destNode, msg, false);
             }
             break;
       }

       case MSG_APP_SendRequest: {
            MessengerPktHeader *pktHdr;

            pktHdr = (MessengerPktHeader *) MESSAGE_ReturnInfo(msg);

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION
            MessengerSendMessage(
                node, *pktHdr, NULL, 0, messenger->messageResultFunc);

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_SendNextPacket: {
            MessengerMessageData *msgData;
            MessengerPktHeader *pktHdr;

            msgData = (MessengerMessageData *) MESSAGE_ReturnInfo(msg);
            pktHdr = (MessengerPktHeader *) &(msgData->pktHdr);

            if (DEBUG)
            {
                char destAddrStr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(pktHdr->destAddr, destAddrStr);

                TIME_PrintClockInSecond(node->getNodeTime(), buf);
                printf("#%d: SendNextPacket %s : fragment #%d of %d, "
                       "size %d, frequency %f to %s\n",
                       node->nodeId,
                       (pktHdr->transportType == TRANSPORT_TYPE_RELIABLE ?
                       "Reliable" : pktHdr->transportType ==
                       TRANSPORT_TYPE_UNRELIABLE ? "Unreliable" :
                       "Tadil"),
                       pktHdr->pktNum + 1,
                       pktHdr->numFrags,
                       pktHdr->fragSize,
                       ((double) pktHdr->freq) / SECOND,
                       destAddrStr);
            }
            SendFragment(node, messenger, *msgData);

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_FromTransport:

#ifdef MILITARY_RADIOS_LIB
        case MSG_APP_FromMac:
#endif //MILITARY_RADIOS_LIB
            {
            MessengerPktHeader *pktHdr;
            NodeAddress sourceAddr = 0;
            char tranStr[MAX_CLOCK_STRING_LENGTH];
            BOOL alreadyReturnedComplete;

#ifdef STANDALONE_MESSENGER_APPLICATION
            if (!messenger)
            {
                messenger = MessengerServerInit(node);
            }
#endif //STANDALONE_MESSENGER_APPLICATION
            if (msg->eventType == MSG_APP_FromTransport)
            {
                UdpToAppRecv *info =
                    (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
                sourceAddr = MAPPING_GetNodeIdFromInterfaceAddress(
                            node, info->sourceAddr.interfaceAddr.ipv4);
                strcpy(tranStr, "UDP");
            }
#ifdef MILITARY_RADIOS_LIB
            else
            {
                sourceAddr = node->nodeId;
                strcpy(tranStr, "TADIL");
            }
#endif //MILITARY_RADIOS_LIB
            pktHdr = (MessengerPktHeader *) MESSAGE_ReturnPacket(msg);

            if (DEBUG)
            {
                char clockStr[MAX_CLOCK_STRING_LENGTH];

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

                TIME_PrintClockInSecond(
                    node->getNodeTime() - pktHdr->timeStamp, buf);

                printf("#%d: From %s size %d from %d at %s, delay %s\n",
                       node->nodeId,
                       tranStr,
                       MESSAGE_ReturnPacketSize(msg),
                       sourceAddr,
                       clockStr,
                       buf);
            }

            if (msg->eventType == MSG_APP_FromTransport)
            {
                if (pktHdr->appType == VOICE_PACKET)
                {
                    MessengerDetectCollision(node, messenger);

                    if (TEST_VOICE_APP)
                    {
                        char RecvAt[MAX_CLOCK_STRING_LENGTH];
                        char SentAt[MAX_CLOCK_STRING_LENGTH];
                        NodeAddress src =
                            MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                    pktHdr->srcAddr);
                        TIME_PrintClockInSecond(
                            node->getNodeTime(), RecvAt);

                        TIME_PrintClockInSecond(
                            pktHdr->timeStamp, SentAt);

                        // Receiver RecvAt { Src SentAt msgId PktNum }
                        fprintf(fp, "%d\t:Rx:\t%s\t{ %d\t\t%s%d\t%d }\n",
                           node->nodeId, RecvAt, src, SentAt, pktHdr->msgId,
                           pktHdr->pktNum);
                    }

                }
            }

            MarkPacketArrival(
                node,
                messenger,
                *pktHdr,
                MESSAGE_ReturnPacket(msg) + sizeof(MessengerPktHeader));

            if (MessageComplete(
                    node,
                    messenger,
                    *pktHdr,
                    &alreadyReturnedComplete,
                    FALSE,
                    NULL))
            {
                Message *resultMsg;

                if (!alreadyReturnedComplete)
                {
                    MessengerPktBufferEntry *recvEntry;

                    recvEntry = ReturnRecvEntry(
                                    messenger,
                                    pktHdr->srcAddr,
                                    pktHdr->msgId,
                                    node->getNodeTime());

                    if (recvEntry == NULL)
                    {
                        char errMsg[256];
                        snprintf(errMsg, sizeof(errMsg),
                                 "Can't find recvEntry for srcAddr %08x msgId "
                                 " %08x\n", pktHdr->srcAddr, pktHdr->msgId);
                        ERROR_ReportError(errMsg);
                    }

                    if (DEBUG || DEBUG_MESSAGE)
                    {
                        TIME_PrintClockInSecond(node->getNodeTime(),buf);
                        printf("#%d: Unreliable Message completion at %s\n",
                               node->nodeId, buf);
                    }
                    if (node->guiOption)
                    {
                        GUI_Receive(
                            sourceAddr, node->nodeId,
                            GUI_APP_LAYER,
                            GUI_DEFAULT_DATA_TYPE,
                            0,
                            0,
                            node->getNodeTime());
                    }
                    ERROR_Assert(pktHdr->messageResultFunc,
                                 "Result Function Not Registered");

                    resultMsg = MESSAGE_Alloc(node, APP_LAYER,
                                    APP_MESSENGER, MSG_APP_SendResult);

                    MESSAGE_InfoAlloc(
                        node, resultMsg, sizeof(MessengerPktHeader));

                    memcpy(MESSAGE_ReturnInfo(resultMsg), pktHdr,
                           sizeof(MessengerPktHeader));

                    if (recvEntry->msgData.pktHdr.additionalDataSize > 0)
                    {
                       MESSAGE_PacketAlloc(
                            node,
                            resultMsg,
                            recvEntry->msgData.pktHdr.additionalDataSize,
                            TRACE_MESSENGER);

                        memcpy(MESSAGE_ReturnPacket(resultMsg),
                               recvEntry->msgData.additionalData,
                               recvEntry->msgData.pktHdr.additionalDataSize);
                    }

                    recvEntry->msgData.endTime = node->getNodeTime();

                    // Set the Ack status and the node Id of the message reciever.
                    AckStatus* info = (AckStatus*)MESSAGE_AddInfo(
                                                     node,
                                                     resultMsg,
                                                     sizeof(AckStatus),
                                                     INFO_TYPE_AppMessenger_Status);
                    info->status = true;
                    info->receiverNodeId = node->nodeId;
                    int remoteNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                 node,
                                                 pktHdr->srcAddr);

                    // Check if node exist in local partition or not.
                    Node* senderNode = MAPPING_GetNodePtrFromHash(
                                          node->partitionData->nodeIdHash,
                                          remoteNodeId);
                    if (!senderNode)
                    {
                        senderNode = MAPPING_GetNodePtrFromHash(
                                         node->partitionData->remoteNodeIdHash,
                                         remoteNodeId); 
                        EXTERNAL_MESSAGE_SendAnyNode(senderNode->partitionData,
                                                     senderNode,
                                                     resultMsg,
                                                     0,
                                                     EXTERNAL_SCHEDULE_LOOSELY);
                    }
                    else
                    {
                        pktHdr->messageResultFunc(node, resultMsg, TRUE);
                    }
                }
            }

            MESSAGE_Free(node, msg);
            break;
        }

        case MSG_APP_TimerExpired: {
            MessengerMessageData* msgData =
                (MessengerMessageData *) MESSAGE_ReturnInfo(msg);
            MessengerPktHeader *pktHdr =
                (MessengerPktHeader *) &(msgData->pktHdr);

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION
            if (DEBUG)
            {
                printf("#%u: Received reminder message\n", node->nodeId);
            }

            if ((unsigned) MAPPING_GetInterfaceIndexFromInterfaceAddress(node,
                pktHdr->srcAddr) != INVALID_MAPPING)
            {
                // sender side timer
                // don't do anything with this now
                if (DEBUG)
                {
                    printf("#%d: sender side timer at %f\n",
                           node->nodeId,
                           ((double)node->getNodeTime()) / SECOND);
                }
                MESSAGE_Free(node, msg);
            }
            else
            {
                BOOL alreadyReturnedComplete;

                // receiver side timer
                if (MessageComplete(
                        node,
                        messenger,
                        *pktHdr,
                        &alreadyReturnedComplete,
                        TRUE,
                        NULL) == FALSE)
                {
                    if (!alreadyReturnedComplete)
                    {
                        if (DEBUG || DEBUG_MESSAGE)
                        {
                            printf("#%d: %s Message FAILURE at %f\n",
                                   node->nodeId,
                                   (pktHdr->transportType
                                    == TRANSPORT_TYPE_RELIABLE ?
                                    "Reliable" : "Unreliable"),
                                   ((double)node->getNodeTime()) / SECOND);
                        }
                        MESSAGE_SetEvent(msg, MSG_APP_SendResult);

                        ERROR_Assert(pktHdr->messageResultFunc,
                                     "Result Function Not Registered");

                        if (pktHdr->transportType == TRANSPORT_TYPE_RELIABLE)
                        {
                            MessengerPktBufferEntry *recvEntry;

                            recvEntry = ReturnRecvEntryForConnId(
                                messenger, msgData->connId, NULL);

                            if (recvEntry)
                            {
                                APP_TcpCloseConnection(node, msgData->connId);
                            }
                        }

                        // Set the Ack status and the node Id of the message reciever.
                        AckStatus* info = (AckStatus*)MESSAGE_AddInfo(
                                                       node,
                                                       msg,
                                                       sizeof(AckStatus),
                                                       INFO_TYPE_AppMessenger_Status);
                        info->status = false;
                        info->receiverNodeId = node->nodeId;
                        int remoteNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                       node,
                                                       pktHdr->srcAddr);

                        // Check if node exist in local partition or not.
                        Node* senderNode = MAPPING_GetNodePtrFromHash(
                                              node->partitionData->nodeIdHash,
                                              remoteNodeId);
                        if (!senderNode)
                        {
                            senderNode = MAPPING_GetNodePtrFromHash(
                                              node->partitionData->remoteNodeIdHash,
                                              remoteNodeId); 
                            EXTERNAL_MESSAGE_SendAnyNode(senderNode->partitionData,
                                                         senderNode,
                                                         msg,
                                                         0,
                                                         EXTERNAL_SCHEDULE_LOOSELY);
                        }
                        else
                        {
                            pktHdr->messageResultFunc(node, msg, FALSE);
                        }
                    }
                    else
                    {
                        MESSAGE_Free(node, msg);
                    }
                }
                else
                {
                    RecordStatistics(
                        node, messenger, *pktHdr, node->getNodeTime());
                    MESSAGE_Free(node, msg);
                }
            }
            break;
        }
        case MSG_APP_ChannelIsBusy: {

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION
            if (DEBUG_STATE)
            {
                char time[MAX_STRING_LENGTH] = {0};
                TIME_PrintClockInSecond(node->getNodeTime(), time);

                printf("#%d: \tChannel Busy at %s\n", node->nodeId, time);
            }


            if ((messenger->nextChannelSenseTime == 0) ||
                (messenger->nextChannelSenseTime <= node->getNodeTime()))
            {
                if (messenger->numCollisionDetected)
                {
                    // Adjust Backoff (wait) time to a ramdom value ranging
                    // from X - 2X to avoid another collision &
                    // thereby recover.
                    messenger->adjBackoffTime = messenger->backoffDistribution.getRandomNumber();
                }
                else
                {
                    // No Collision | Recovery, reset Backoff Time to X
                    messenger->adjBackoffTime = HLA_VOICE_PACKET_BACKOFF_TIME;
                }


                // Schedule a self event for Channel Sense
                MessengerSendChannelSenseTimer(node,
                        MSG_APP_ChannelInBackoff,
                        messenger->adjBackoffTime);

                messenger->nextChannelSenseTime = node->getNodeTime()
                                            + messenger->adjBackoffTime;
                if (DEBUG_STATE)
                {
                    char backoffStr[MAX_STRING_LENGTH] = {0};
                    char nextTime[MAX_STRING_LENGTH] = {0};
                    TIME_PrintClockInSecond(messenger->adjBackoffTime,
                                            backoffStr);
                    TIME_PrintClockInSecond(messenger->nextChannelSenseTime,
                                            nextTime);
                    printf("\t\tBackoff Time is %s Sec\n"
                        "\t\tSchedule Next Channel Sense at %s Sec\n",
                        backoffStr, nextTime);
                }
            }
            else
            {
                if (DEBUG_STATE)
                {
                    char nextTime[MAX_STRING_LENGTH] = {0};
                    TIME_PrintClockInSecond(messenger->nextChannelSenseTime,
                                            nextTime);
                    printf("\t\tNext Channel Sense scheduled at %s Sec\n",
                        nextTime);
                }
            }

            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_APP_ChannelInBackoff: {

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION

            MessengerSenseChannel(node, messenger);

            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_APP_ChannelIsIdle: {

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION

            if (DEBUG_STATE)
            {
                char time[MAX_STRING_LENGTH] = {0};
                TIME_PrintClockInSecond(node->getNodeTime(), time);
                printf("#%d: \tChannel Idle at %s\n", node->nodeId, time);
            }
            MessengerSendAllFromOutputQueue(node, messenger);

            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_APP_FromTransListenResult: {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);


            if (DEBUG)
            {
                printf("#%d MessengerApp at %f got ListenResult\n",
                       node->nodeId,
                       ((double)node->getNodeTime()) / SECOND);
            }

            if (listenResult->connectionId == -1)
            {
                ERROR_ReportError("Failed to listen on server port.");
                node->appData.numAppTcpFailure++;
            }

            MESSAGE_Free(node, msg);
            break;

        }
        case MSG_APP_FromTransOpenResult: {
            TransportToAppOpenResult *openResult;

            openResult = (TransportToAppOpenResult *) MESSAGE_ReturnInfo(msg);

            if (DEBUG)
            {
                char addrStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(&openResult->remoteAddr, addrStr);
                printf("Messenger App: Node %d at %f got %s "
                       "OpenResult(id %d / connId %d / remoteAddr %s)\n",
                       node->nodeId, ((double)node->getNodeTime()) / SECOND,
                       (openResult->type == TCP_CONN_PASSIVE_OPEN ?
                        "PASSIVE" : "ACTIVE"),
                       openResult->uniqueId, openResult->connectionId,
                       addrStr);
            }


            if (openResult->connectionId == -1)
            {
                if (DEBUG)
                {
                    ERROR_ReportWarning("Unable to open connection");
                }
                MESSAGE_Free(node, msg);

                break;
            }
            else if (openResult->type == TCP_CONN_PASSIVE_OPEN)
            {   // will be receiving data

#ifdef STANDALONE_MESSENGER_APPLICATION

                if (!messenger)
                {
                    messenger = MessengerServerInit(node);
                }
#endif //STANDALONE_MESSENGER_APPLICATION
                if (openResult->remoteAddr.networkType == NETWORK_IPV6)
                {
                    ERROR_ReportError(
                        "Presently, MESSENGER does not support IPv6.\n");
                }

                CreateIncompleteRecvEntry(
                    messenger,
                    GetIPv4Address(openResult->remoteAddr),
                    openResult->connectionId);
            }
            else
            {
                // will be sending data
                MessengerMessageData *sendEntry;
                char buf[sizeof(MessengerPktHeader)
                         + MAX_ADDITIONAL_DATA_SIZE];

#ifdef STANDALONE_MESSENGER_APPLICATION
                ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION

                if (openResult->remoteAddr.networkType == NETWORK_IPV6)
                {
                    ERROR_ReportError(
                        "Presently, MESSENGER does not support IPv6.\n");
                }

                sendEntry = ReturnSendEntry(
                                messenger,
                                GetIPv4Address(openResult->remoteAddr),
                                openResult->uniqueId,
                                node->getNodeTime());

                ERROR_Assert(sendEntry, "Unable to locate sendEntry");
                ERROR_Assert(sendEntry->pktHdr.additionalDataSize
                             < MAX_ADDITIONAL_DATA_SIZE,
                             "not enough room for the additional data");

                sendEntry->connId = openResult->connectionId;
                sendEntry->sessionOpen = TRUE;

                sendEntry->pktHdr.timeStamp = node->getNodeTime();

                memcpy(buf,
                       &(sendEntry->pktHdr),
                       sizeof(MessengerPktHeader));
                memcpy(buf + sizeof(MessengerPktHeader),
                       sendEntry->additionalData,
                       sendEntry->pktHdr.additionalDataSize);

                Message *tcpmsg = APP_TcpCreateMessage(
                    node,
                    openResult->connectionId,
                    TRACE_MESSENGER);

                APP_AddHeader(
                    node, 
                    tcpmsg, 
                    buf,
                    sizeof(MessengerPktHeader)
                        + sendEntry->pktHdr.additionalDataSize);

                APP_AddVirtualPayload(
                    node, 
                    tcpmsg,
                    sendEntry->pktHdr.fragSize
                        - sizeof(MessengerPktHeader)
                        - sendEntry->pktHdr.additionalDataSize);

                APP_TcpSend(node, tcpmsg);

                if (sendEntry->pktHdr.pktNum == 0)
                {
                    sendEntry->messageStartTime = node->getNodeTime();
                }

                sendEntry->pktHdr.pktNum++;
                sendEntry->endTime = node->getNodeTime();
            }

            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_APP_FromTransDataSent: {

            TransportToAppDataSent *dataSent =
                (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION
            if (DEBUG)
            {
                printf("Messenger App: Node %d at %f got DataSent\n",
                       node->nodeId, ((double)node->getNodeTime()) / SECOND);
            }

            APP_TcpCloseConnection(node, dataSent->connectionId);

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_FromTransDataReceived: {
            TransportToAppDataReceived *dataRecvd;
            MessengerPktBufferEntry *recvEntry;
            int packetBytesRemaining = MESSAGE_ReturnPacketSize(msg);
            char *msgPtr = MESSAGE_ReturnPacket(msg);

            dataRecvd = (TransportToAppDataReceived *)
                        MESSAGE_ReturnInfo(msg);

#ifdef STANDALONE_MESSENGER_APPLICATION
            ERROR_Assert(messenger, "Messenger App not started");
#endif //STANDALONE_MESSENGER_APPLICATION
            if (DEBUG)
            {
                printf("Messenger App: Node %d at %f got DataRecvd %d\n",
                       node->nodeId,
                       ((double)node->getNodeTime()) / SECOND,
                       packetBytesRemaining);
            }


            recvEntry = ReturnRecvEntryForConnId(
                            messenger, dataRecvd->connectionId, NULL);

            if (!recvEntry)
            {
                if (DEBUG)
                {
                    ERROR_ReportWarning(
                        "data received for conn that has already failed");
                }
                MESSAGE_Free(node, msg);
                break;
            }

            while (packetBytesRemaining)
            {
                MessengerDoReassembly(
                   node,
                   recvEntry,
                   &msgPtr,
                   &packetBytesRemaining);
            }

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_APP_FromTransCloseResult: {
            TransportToAppCloseResult* closeResult =
                (TransportToAppCloseResult *) MESSAGE_ReturnInfo(msg);

            if (DEBUG)
            {
                printf("Messenger App: Node %d at %f got %s "
                       "CloseResult(connId %d)\n",
                       node->nodeId,
                       ((double)node->getNodeTime()) / SECOND,
                       (closeResult->type == TCP_CONN_PASSIVE_CLOSE ?
                        "PASSIVE" : "ACTIVE"),
                       closeResult->connectionId);
            }

            MarkConnectionClosed(messenger, closeResult->connectionId);

            MESSAGE_Free(node, msg);
            break;
        }
        default:
            ERROR_ReportError("Different Message Type\n");
    }
}

static
void PrintRecvListStatistics(Node* node)
{
    MessengerState *messenger = GetPointer(node);
    int i = 0;

    for (i = 0; i < messenger->numRecvList; i++)
    {
        MessengerPktBufferEntry* recvEntry = &(messenger->recvList[i]);

        RecordStatistics(node,
                        messenger,
                        recvEntry->msgData.pktHdr,
                        recvEntry->msgData.endTime,
                        recvEntry);
    }
}

static
void PrintSendListStatistics(Node* node)
{
    MessengerState *messenger = GetPointer(node);
    int throughput = 0;
    int i = 0;
    char transportTypeStr[MAX_STRING_LENGTH];

    for (i = 0; i < messenger->numSendList; i++)
    {
        MessengerMessageData* sendList = &(messenger->sendList[i]);
        NodeAddress srcId =  MAPPING_GetNodeIdFromInterfaceAddress(
                                        node, sendList->pktHdr.srcAddr);

        MessengerWriteTransportType(
            node,
            (TransportType) sendList->pktHdr.transportType,
            transportTypeStr);

        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            sendList->pktHdr.msgId,
            "FLOW %u:%d Transport = %s",
            srcId,
            sendList->pktHdr.msgId,
            transportTypeStr);

        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            sendList->pktHdr.msgId,
            "FLOW %u:%d Number of fragments send/total = %d/%d",
            srcId,
            sendList->pktHdr.msgId,
            sendList->pktHdr.pktNum,
            sendList->pktHdr.numFrags);

        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            sendList->pktHdr.msgId,
            "FLOW %u:%d Number of bytes send = %d",
            srcId,
            sendList->pktHdr.msgId,
            sendList->pktHdr.pktNum * sendList->pktHdr.fragSize);

        clocktype totalDelay =
            sendList->endTime - sendList->messageStartTime;

        IO_PrintStat(
            node,
            "Application",
            "Messenger",
            ANY_DEST,
            sendList->pktHdr.msgId,
            "FLOW %d:%d total end-to-end delay = %f",
            srcId,
            sendList->pktHdr.msgId,
            ((double) totalDelay) / SECOND);

        if (totalDelay > 0)
        {
            throughput = (int) ((sendList->pktHdr.pktNum *
                    sendList->pktHdr.fragSize * BYTE_TO_BIT * SECOND)
                        / totalDelay);

            IO_PrintStat(
                node,
                "Application",
                "Messenger",
                ANY_DEST,
                sendList->pktHdr.msgId,
                "FLOW %u:%d Sender Throughput = %d bps",
                srcId,
                sendList->pktHdr.msgId,
                throughput);
        }
    }
}

void MessengerFinalize(Node *node, AppInfo* appInfo)
{
    PrintRecvListStatistics(node);
    PrintSendListStatistics(node);
}
