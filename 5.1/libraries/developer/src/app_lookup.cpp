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

#include "api.h"
#include "app_util.h"
#include "app_lookup.h"

#define noDEBUG


/*
 * NAME:        AppLookupClientGetLookupClient.
 * PURPOSE:     search for a lookup client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              sourcePort - source port of the lookup client.
 * RETURN:      the pointer to the lookup client data structure,
 *              NULL if nothing found.
 */
static AppDataLookupClient *
AppLookupClientGetLookupClient(
    Node *node,
    short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataLookupClient *lookupClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_LOOKUP_CLIENT)
        {
            lookupClient = (AppDataLookupClient *) appList->appDetail;

            if (lookupClient->sourcePort == sourcePort)
            {
                return lookupClient;
            }
        }
    }

    return NULL;
}


/*
 * NAME:        AppLookupClientNewLookupClient.
 * PURPOSE:     create a new lookup client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              localAddr - local address.
 *              remoteAddr - remote address.
 *              requestsToSend - number of lookup items to send in simulation.
 *              requestSize - size of each packet.
 *              interval - time between two packets.
 *              startTime - when the node will start sending.
 * RETURN:      the pointer to the created lookup client data structure,
 *              NULL if no data structure allocated.
 */
static AppDataLookupClient *
AppLookupClientNewLookupClient(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    Int32 requestsToSend,
    Int32 requestSize,
    Int32 replySize,
    clocktype requestInterval,
    clocktype replyDelay,
    clocktype startTime,
    clocktype endTime,
    TosType tos)
{
    AppDataLookupClient *lookupClient;

    lookupClient = (AppDataLookupClient *)
                   MEM_malloc(sizeof(AppDataLookupClient));

    /*
     * fill in lookup info.
     */
    lookupClient->localAddr = localAddr;
    lookupClient->remoteAddr = remoteAddr;
    lookupClient->requestInterval = requestInterval;
    lookupClient->replyDelay = replyDelay;
    lookupClient->sessionStart = node->getNodeTime() + startTime;
    lookupClient->sessionIsClosed = FALSE;
    lookupClient->sessionLastSent = node->getNodeTime();
    lookupClient->sessionLastReceived = node->getNodeTime();
    lookupClient->sessionFinish = node->getNodeTime();
    lookupClient->endTime = endTime;
    lookupClient->numBytesSent = 0;
    lookupClient->numBytesRecvd = 0;
    lookupClient->numPktsSent = 0;
    lookupClient->numPktsRecvd = 0;
    lookupClient->totalEndToEndDelay = 0;
    lookupClient->requestsToSend = requestsToSend;
    lookupClient->requestSize = requestSize;
    lookupClient->replySize = replySize;
    lookupClient->sourcePort = node->appData.nextPortNum++;
    lookupClient->uniqueId = node->appData.uniqueId++;
    lookupClient->seqNo = 0;
    lookupClient->tos = tos;

#ifdef DEBUG
    {
        char clockStr[24];
        printf("LOOKUP Client: Node %u created new lookup client "
               "structure\n", node->nodeId);
        printf("    localAddr = %ld\n", lookupClient->localAddr);
        printf("    remoteAddr = %ld\n", lookupClient->remoteAddr);
        ctoa(lookupClient->requestInterval, clockStr);
        printf("    request interval = %s\n", clockStr);
        ctoa(lookupClient->replyDelay, clockStr);
        printf("    reply delay = %s\n", clockStr);
        ctoa(lookupClient->sessionStart, clockStr);
        printf("    sessionStart = %s\n", clockStr);
        printf("    numBytesSent = %ld\n", lookupClient->numBytesSent);
        printf("    numPktsSent = %ld\n", lookupClient->numPktsSent);
        printf("    requestsToSend = %ld\n", lookupClient->requestsToSend);
        printf("    requestSize = %ld\n", lookupClient->requestSize);
        printf("    replySize = %ld\n", lookupClient->replySize);
        printf("    sourcePort = %ld\n", lookupClient->sourcePort);
        printf("    seqNo = %ld\n", lookupClient->seqNo);
        printf("    tos = %ld\n", lookupClient->tos);
    }
#endif /* DEBUG */

    APP_RegisterNewApp(node, APP_LOOKUP_CLIENT, lookupClient);

    return lookupClient;
}


/*
 * NAME:        AppLookupClientScheduleNextPkt.
 * PURPOSE:     schedule the next packet the client will send.  If next packet
 *              won't arrive until the finish deadline, schedule a close.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the lookup client data structure.
 * RETRUN:      none.
 */
static void
AppLookupClientScheduleNextPkt(
    Node *node,
    AppDataLookupClient *clientPtr)
{
    AppTimer *timer;
    Message *timerMsg;

    timerMsg = MESSAGE_Alloc(
                   node,
                   APP_LAYER,
                   APP_LOOKUP_CLIENT,
                   MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[24];
        printf("LOOKUP Client: Node %u scheduling next data packet\n",
               node->nodeId);
        printf("    timer type is %d\n", timer->type);
        ctoa(clientPtr->requestInterval, clockStr);
        printf("    interval is %s\n", clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, clientPtr->requestInterval);
}

/*
 * NAME:        AppLayerLookupClient.
 * PURPOSE:     Models the behaviour of LookupClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerLookupClient(
    Node *node,
    Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    char error[MAX_STRING_LENGTH];
    AppDataLookupClient *clientPtr;

#ifdef DEBUG
    ctoa(node->getNodeTime(), buf);
    printf("LOOKUP Client: Node %ld got a message at %s\n",
           node->nodeId, buf);
#endif /* DEBUG */

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            AppTimer *timer;

            timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("LOOKUP Client: Node %ld at %s got timer %d\n",
                   node->nodeId, buf, timer->type);
#endif /* DEBUG */

            clientPtr = AppLookupClientGetLookupClient(
                            node,
                            timer->sourcePort);

            if (clientPtr == NULL)
            {
                sprintf(error,
                        "LOOKUP Client: Node %d cannot find lookup client\n",
                        node->nodeId);

                ERROR_ReportError(error);
            }

            switch (timer->type)
            {
                case APP_TIMER_SEND_PKT:
                {
                    LookupData data;

#ifdef DEBUG
                    printf("LOOKUP Client: Node %u has %ld items left"
                           "to send\n",
                           node->nodeId,
                           clientPtr->requestsToSend);
#endif /* DEBUG */

                    if (((clientPtr->requestsToSend > 1) &&
                         (node->getNodeTime() + clientPtr->requestInterval
                             < clientPtr->endTime)) ||
                        ((clientPtr->requestsToSend == 0) &&
                         (node->getNodeTime() + clientPtr->requestInterval <
                                clientPtr->endTime)) ||
                        ((clientPtr->requestsToSend > 1) &&
                         (clientPtr->endTime == 0)) ||
                        ((clientPtr->requestsToSend == 0) &&
                         (clientPtr->endTime == 0)))
                    {
                        data.type = 'd';
                    }
                    else
                    {
                        data.type = 'c';
                        clientPtr->sessionIsClosed = TRUE;
                        clientPtr->sessionFinish = node->getNodeTime();
                    }

                    data.sourcePort = clientPtr->sourcePort;
                    data.txTime = node->getNodeTime();
                    data.seqNo = clientPtr->seqNo++;
                    data.replyDelay = clientPtr->replyDelay;
                    data.replySize = clientPtr->replySize;
                    data.tos = clientPtr->tos;
#ifdef DEBUG
                    {
                        char clockStr[24];
                        ctoa(node->getNodeTime(), clockStr);

                        printf("LOOKUP Client: node %ld sending data packet"
                               " at time %s to LOOKUP server %ld\n",
                               node->nodeId, clockStr, clientPtr->remoteAddr);
                        printf("    size of payload is %d\n",
                               clientPtr->requestSize);
                    }
#endif /* DEBUG */

                    Message *msg = APP_UdpCreateMessage(
                        node,
                        clientPtr->localAddr,
                        (short) clientPtr->sourcePort,
                        clientPtr->remoteAddr,
                        APP_LOOKUP_SERVER,
                        TRACE_LOOKUP,
                        clientPtr->tos);

                    APP_AddHeader(
                        node,
                        msg,
                        &data,
                        sizeof(data));

                    APP_AddVirtualPayload(
                        node,
                        msg,
                        clientPtr->requestSize - sizeof(data));

                    APP_UdpSend(node, msg);

                    if (clientPtr->stats->GetMessagesSent().GetValue(node->getNodeTime()) == 0)
                    {                         
                        clientPtr->stats->SessionStart(node);
                    }
                    clientPtr->stats->AddMessageSentDataPoints(
                        node,
                        msg,
                        0,
                        clientPtr->requestSize,
                        0,
                        STAT_Unicast);
                    clientPtr->stats->AddFragmentSentDataPoints(
                        node,
                        clientPtr->requestSize,
                        STAT_Unicast);                        

                    clientPtr->numBytesSent += clientPtr->requestSize;
                    clientPtr->numPktsSent++;
                    clientPtr->sessionLastSent = node->getNodeTime();

                    if (clientPtr->requestsToSend > 0)
                    {
                        clientPtr->requestsToSend--;
                    }

                    if (clientPtr->sessionIsClosed == FALSE)
                    {
                        AppLookupClientScheduleNextPkt(node, clientPtr);
                    }

                    break;
                }

                default:
                    assert(FALSE);
            }

            break;
        }
        case MSG_APP_FromTransport:
        {
            //UdpToAppRecv *info;
            LookupData data;

            //info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
            memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

#ifdef DEBUG
            {
                char clockStr[24];
                ctoa(data.txTime, clockStr);
                printf("LOOKUP Client %ld: initial request packet "
                       "transmitted at %s\n",
                       node->nodeId, clockStr);

                ctoa(node->getNodeTime(), clockStr);
                printf("    received at %s\n", clockStr);
                //printf("    client is %ld\n",
                //       GetIPv4Address(info->sourceAddr));
                printf("    connection Id is %d\n", data.sourcePort);
                printf("    seqNo is %d\n", data.seqNo);
            }
#endif /* DEBUG */

            clientPtr = AppLookupClientGetLookupClient(
                            node,
                            data.sourcePort);

            if (clientPtr == NULL)
            {
                sprintf(error,
                        "LOOKUP Client: Node %d cannot find lookup client\n",
                        node->nodeId);

#ifdef EXATA
                break;
#else
                ERROR_ReportError(error);
#endif
            }

            clientPtr->stats->AddFragmentReceivedDataPoints(
                node,
                msg,
                MESSAGE_ReturnPacketSize(msg),
                STAT_Unicast);

            clientPtr->stats->AddMessageReceivedDataPoints(
                node,
                msg,
                0,
                MESSAGE_ReturnPacketSize(msg),
                0,
                STAT_Unicast);      

            clientPtr->numBytesRecvd += MESSAGE_ReturnPacketSize(msg);
            clientPtr->numPktsRecvd++;
            clientPtr->sessionLastReceived = node->getNodeTime();
            clientPtr->totalEndToEndDelay += node->getNodeTime() - data.txTime;
            clientPtr->seqNo = data.seqNo + 1;

#ifdef DEBUG
            {
                char clockStr[24];
                ctoa(clientPtr->totalEndToEndDelay, clockStr);
                printf("    total end-to-end delay so far is %s\n",
                       clockStr);
            }
#endif /* DEBUG */

            break;
        }
        default:
           ctoa(node->getNodeTime(), buf);
           sprintf(error, "LOOKUP Client: at time %s, node %d "
                   "received message of unknown type"
                   " %d\n", buf, node->nodeId, msg->eventType);
           ERROR_ReportError(error);
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppLookupClientInit.
 * PURPOSE:     Initialize a LookupClient session.
 * PARAMETERS:  node - pointer to the node,
 *              serverAddr - address of the server,
 *              requestsToSend - number of items to send,
 *              requestSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts,
 *              endTime - time until the session ends,
 *              tos - the contents for the type of service field.
 * RETURN:      none.
 */
void
AppLookupClientInit(
    Node *node,
    NodeAddress clientAddr,
    NodeAddress serverAddr,
    Int32 requestsToSend,
    Int32 requestSize,
    Int32 replySize,
    clocktype requestInterval,
    clocktype replyDelay,
    clocktype startTime,
    clocktype endTime,
    unsigned tos)
{
    char error[MAX_STRING_LENGTH];
    AppTimer *timer;
    AppDataLookupClient *clientPtr;
    Message *timerMsg;

    /* Check to make sure the number of lookup items is a correct value. */
    if (requestsToSend < 0)
    {
        sprintf(error,
                "LOOKUP Client: Node %d item to sends needs to be >= 0\n",
                node->nodeId);

        ERROR_ReportError(error);
    }

    /* Make sure that packet is big enough to carry lookup data information. */
    if (requestSize < (signed) sizeof(LookupData))
    {
        sprintf(error,
                "LOOKUP Client: Node %d request size needs to be >= %"
                        TYPES_SIZEOFMFT "u \n",
                node->nodeId, sizeof(LookupData));
        ERROR_ReportError(error);
    }

    /* Make sure that packet is within max limit. */
    if (requestSize > APP_MAX_DATA_SIZE)
    {
        sprintf(error,
                "LOOKUP Client: Node %d request and reply sizes need "
                "to be <= %d.\n",
                node->nodeId, APP_MAX_DATA_SIZE);
        ERROR_ReportError(error);
    }

    /* Make sure interval is valid. */
    if (requestInterval <= 0)
    {
        sprintf(error,
                "LOOKUP Client: Node %d request interval needs to be > 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    if (replyDelay < 0)
    {
        sprintf(error,
                "LOOKUP Client: Node %d reply delay needs to be >= 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Make sure start time is valid. */
    if (startTime < 0)
    {
        sprintf(error,
                "LOOKUP Client: Node %d start time needs to be >= 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        sprintf(error,
                "LOOKUP Client: Node %d end time needs to be > start time "
                "or equal to 0.\n", node->nodeId);

        ERROR_ReportError(error);
    }

    if (/* (tos is unsigned) tos < 0 ||*/ tos > 255)
    {
        sprintf(error, "LOOKUP Client: Node %d should have tos value "
            "within the range 0 to 255.\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

    clientPtr = AppLookupClientNewLookupClient(
                    node,
                    clientAddr,
                    serverAddr,
                    requestsToSend,
                    requestSize,
                    replySize,
                    requestInterval,
                    replyDelay,
                    startTime,
                    endTime,
                    (TosType) tos);

    if (clientPtr == NULL)
    {
        sprintf(error,
                "LOOKUP Client: Node %d cannot allocate memory for "
                "new client\n",
                node->nodeId);

        ERROR_ReportError(error);
    }


    timerMsg = MESSAGE_Alloc(
                   node,
                   APP_LAYER,
                   APP_LOOKUP_CLIENT,
                   MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

    Address src;
    Address dest;
    SetIPv4AddressInfo(&src, clientAddr);
    SetIPv4AddressInfo(&dest, serverAddr);
    clientPtr->stats = new STAT_AppStatistics(
        node,
        "Lookup",
        STAT_Unicast,
        STAT_AppSender);
    clientPtr->stats->Initialize(
        node,
        src,
        dest,
        clientPtr->uniqueId,
        clientPtr->uniqueId);

#ifdef DEBUG
    {
        char clockStr[24];
        ctoa(startTime, clockStr);
        printf("LOOKUP Client: Node %ld starting client at %s\n",
               node->nodeId, clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, startTime);
}

/*
 * NAME:        AppLookupClientPrintStats.
 * PURPOSE:     Prints statistics of a LookupClient session.
 * PARAMETERS:  node - pointer to the this node.
 *              clientPtr - pointer to the lookup client data structure.
 * RETURN:      none.
 */
static void
AppLookupClientPrintStats(
    Node *node,
    AppDataLookupClient *clientPtr)
{
    clocktype throughput;

    char addrStr[MAX_STRING_LENGTH];
    char startStr[MAX_STRING_LENGTH];
    char closeStr[MAX_STRING_LENGTH];
    char delayStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];

    char buf[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(clientPtr->sessionStart, startStr);
    TIME_PrintClockInSecond(clientPtr->sessionLastSent, closeStr);

    if (clientPtr->sessionIsClosed == FALSE)
    {
        clientPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
    }
    else
    {
        sprintf(sessionStatusStr, "Closed");
    }

    if (clientPtr->sessionFinish <= clientPtr->sessionStart)
    {
        throughput = 0;
    }
    else
    {
        throughput = (clocktype)
                     ((clientPtr->numBytesSent * 8.0 * SECOND)
                      / (clientPtr->sessionFinish -
                       clientPtr->sessionStart));
    }

    if (clientPtr->numPktsRecvd == 0)
    {
        TIME_PrintClockInSecond(0, delayStr);
    }
    else
    {
        TIME_PrintClockInSecond(
            clientPtr->totalEndToEndDelay / clientPtr->numPktsRecvd,
            delayStr);
    }

    ctoa(throughput, throughputStr);

    IO_ConvertIpAddressToString(clientPtr->remoteAddr, addrStr);
    sprintf(buf, "Server Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "First Packet Sent at (s) = %s", startStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Last Packet Sent at (s) = %s", closeStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Total Bytes Sent = %d", clientPtr->numBytesSent);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Total Packets Sent = %d", clientPtr->numPktsSent);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Total Bytes Received = %d", clientPtr->numBytesRecvd);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Total Packets Received = %d", clientPtr->numPktsRecvd);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    // We probably don't care about throughput for lookup applications.
    //sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
    //IO_PrintStat(
    //    node,
    //    "Application",
    //    "LOOKUP Client",
    //    ANY_DEST,
    //    clientPtr->sourcePort,
    //    buf);

    sprintf(buf, "Average Roundtrip Delay (s) = %s", delayStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);
}

/*
 * NAME:        AppLookupClientFinalize.
 * PURPOSE:     Collect statistics of a LookupClient session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppLookupClientFinalize(
    Node *node,
    AppInfo* appInfo)
{
    AppDataLookupClient *clientPtr =
        (AppDataLookupClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppLookupClientPrintStats(node, clientPtr);
    }
}


/*
 * NAME:        AppLookupServerGetLookupServer.
 * PURPOSE:     search for a lookup server data structure.
 * PARAMETERS:  node - lookup server.
 *              remoteAddr - lookup client sending the data.
 *              sourcePort - sourcePort of lookup client/server pair.
 * RETURN:      the pointer to the lookup server data structure,
 *              NULL if nothing found.
 */
static AppDataLookupServer *
AppLookupServerGetLookupServer(
    Node *node,
    NodeAddress remoteAddr,
    short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataLookupServer *lookupServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_LOOKUP_SERVER)
        {
            lookupServer = (AppDataLookupServer *) appList->appDetail;

            if ((lookupServer->sourcePort == sourcePort) &&
                (lookupServer->remoteAddr == remoteAddr))
            {
                return lookupServer;
            }
       }
   }

    return NULL;
}


/*
 * NAME:        AppLookupServerNewLookupServer.
 * PURPOSE:     create a new lookup server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              localAddr - local address.
 *              remoteAddr - remote address.
 *              sourcePort - sourcePort of lookup client/server pair.
 * RETRUN:      the pointer to the created lookup server data structure,
 *              NULL if no data structure allocated.
 */
static AppDataLookupServer *
AppLookupServerNewLookupServer(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    short sourcePort)
{
    AppDataLookupServer *lookupServer;

    lookupServer = (AppDataLookupServer *)
                   MEM_malloc(sizeof(AppDataLookupServer));

    /*
     * Fill in lookup info.
     */
    lookupServer->localAddr = localAddr;
    lookupServer->remoteAddr = remoteAddr;
    lookupServer->sourcePort = sourcePort;
    lookupServer->sessionStart = node->getNodeTime();
    lookupServer->sessionFinish = node->getNodeTime();
    lookupServer->sessionLastReceived = node->getNodeTime();
    lookupServer->sessionIsClosed = FALSE;
    lookupServer->numBytesRecvd = 0;
    lookupServer->numPktsRecvd = 0;
    lookupServer->numBytesSent = 0;
    lookupServer->numPktsSent = 0;
    lookupServer->seqNo = 0;
    lookupServer->uniqueId = node->appData.uniqueId++;

    APP_RegisterNewApp(node, APP_LOOKUP_SERVER, lookupServer);

    return lookupServer;
}

/*
 * NAME:        AppLayerLookupServer.
 * PURPOSE:     Models the behaviour of LookupServer Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerLookupServer(
    Node *node,
    Message *msg)
{
    char error[MAX_STRING_LENGTH];
    AppDataLookupServer *serverPtr;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv *info;
            LookupData data;

            info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
            memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

#ifdef DEBUG
            {
                char clockStr[24];
                ctoa(data.txTime, clockStr);
                printf("LOOKUP Server %ld: packet transmitted at %s\n",
                       node->nodeId, clockStr);

                ctoa(node->getNodeTime(), clockStr);
                printf("    received at %s\n", clockStr);
                printf("    client is %ld\n",
                        GetIPv4Address(info->sourceAddr));
                printf("    connection Id is %d\n", data.sourcePort);
                printf("    seqNo is %d\n", data.seqNo);
            }
#endif /* DEBUG */

            serverPtr = AppLookupServerGetLookupServer(
                            node,
                            GetIPv4Address(info->sourceAddr),
                            data.sourcePort);

            /* New connection, so create new lookup server to handle client. */
            if (serverPtr == NULL)
            {
                serverPtr = AppLookupServerNewLookupServer(
                                node,
                                GetIPv4Address(info->destAddr),
                                GetIPv4Address(info->sourceAddr),
                                data.sourcePort);

                serverPtr->stats = new STAT_AppStatistics(
                    node,
                    "lookupServer",
                    STAT_Unicast,
                    STAT_AppReceiver,
                    "Lookup Server");
                serverPtr->stats->Initialize(
                    node,
                    info->sourceAddr,
                    info->destAddr,
                    STAT_AppStatistics::GetSessionId(msg),
                    serverPtr->uniqueId);
                serverPtr->stats->SessionStart(node);
            }

            if (serverPtr == NULL)
            {
                sprintf(error, "LOOKUP Server: Node %d unable to "
                        "allocation server\n", node->nodeId);

                ERROR_ReportError(error);
            }

            serverPtr->stats->AddFragmentReceivedDataPoints(
                node,
                msg,
                MESSAGE_ReturnPacketSize(msg),
                STAT_Unicast);

            serverPtr->stats->AddMessageReceivedDataPoints(
                node,
                msg,
                0,
                MESSAGE_ReturnPacketSize(msg),
                0,
                STAT_Unicast);            

            serverPtr->numBytesRecvd += MESSAGE_ReturnPacketSize(msg);
            serverPtr->numPktsRecvd++;
            serverPtr->sessionLastReceived = node->getNodeTime();
            serverPtr->seqNo = data.seqNo + 1;

#ifdef DEBUG
            {
                char clockStr[24];
                ctoa((node->getNodeTime() + data.replyDelay), clockStr);
                printf("    transmitting reply packet at %s\n", clockStr);
            }
#endif /* DEBUG */

            Message *msg = APP_UdpCreateMessage(
                node,
                ANY_IP,
                data.sourcePort,
                GetIPv4Address(info->sourceAddr),
                APP_LOOKUP_CLIENT,
                TRACE_LOOKUP,
                data.tos);

            APP_AddHeader(
                node,
                msg,
                &data,
                sizeof(data));

            APP_AddVirtualPayload(
                node,
                msg,
                data.replySize - sizeof(data));

            APP_UdpSend(node, msg, data.replyDelay);

            if (serverPtr->stats->IsSessionStarted(STAT_Unicast) == FALSE )
            {                         
                serverPtr->stats->SessionStart(node);
            }
            serverPtr->stats->AddMessageSentDataPoints(
                node,
                msg,
                0,
                data.replySize,
                0,
                STAT_Unicast);
            serverPtr->stats->AddFragmentSentDataPoints(
                node,
                data.replySize,
                STAT_Unicast);    
            
            serverPtr->numBytesSent += data.replySize;
            serverPtr->numPktsSent++;

            if (data.type == 'd')
            {
                /* Do nothing. */
            }
            else
            if (data.type == 'c')
            {
                serverPtr->sessionFinish = node->getNodeTime();
                serverPtr->sessionIsClosed = TRUE;
            }
            else
            {
                assert(FALSE);
            }

            break;
        }

        default:
        {
            char buf[MAX_STRING_LENGTH];

            ctoa(node->getNodeTime(), buf);
            sprintf(error, "LOOKUP Server: At time %s, node %d received "
                    "message of unknown type "
                    "%d\n", buf, node->nodeId, msg->eventType);
            ERROR_ReportError(error);
        }
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppLookupServerInit.
 * PURPOSE:     listen on LookupServer server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppLookupServerInit(
    Node *node)
{
}

/*
 * NAME:        AppLookupServerPrintStats.
 * PURPOSE:     Prints statistics of a LookupServer session.
 * PARAMETERS:  node - pointer to this node.
 *              serverPtr - pointer to the lookup server data structure.
 * RETURN:      none.
 */
static void
AppLookupServerPrintStats(
    Node *node,
    AppDataLookupServer *serverPtr)
{
    clocktype throughput;

    char addrStr[MAX_STRING_LENGTH];
    char startStr[MAX_STRING_LENGTH];
    char closeStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(serverPtr->sessionStart, startStr);
    TIME_PrintClockInSecond(serverPtr->sessionLastReceived, closeStr);

    if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
    }
    else
    {
        sprintf(sessionStatusStr, "Closed");
    }

    if (serverPtr->sessionFinish <= serverPtr->sessionStart)
    {
        throughput = 0;
    }
    else
    {
        throughput = (clocktype)
                     ((serverPtr->numBytesRecvd * 8.0 * SECOND)
                     / (serverPtr->sessionFinish - serverPtr->sessionStart));
    }

    ctoa(throughput, throughputStr);

    IO_ConvertIpAddressToString(serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "First Packet Received at (s) = %s", startStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Last Packet Received at (s) = %s", closeStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Total Bytes Received = %d", serverPtr->numBytesRecvd);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Total Packets Received = %d", serverPtr->numPktsRecvd);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Total Bytes Sent = %d", serverPtr->numBytesSent);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Total Packets Sent = %d", serverPtr->numPktsSent);
    IO_PrintStat(
        node,
        "Application",
        "LOOKUP Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    // We probably don't care about throughput for lookup applications.
    //sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
    //IO_PrintStat(
    //    node,
    //    "Application",
    //    "LOOKUP Server",
    //    ANY_DEST,
    //    serverPtr->sourcePort,
    //    buf);
}

/*
 * NAME:        AppLookupServerFinalize.
 * PURPOSE:     Collect statistics of a LookupServer session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppLookupServerFinalize(
    Node *node,
    AppInfo* appInfo)
{
    AppDataLookupServer *serverPtr = (AppDataLookupServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppLookupServerPrintStats(node, serverPtr);
    }
}
