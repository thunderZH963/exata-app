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

#ifndef LOOKUP_APP_H
#define LOOKUP_APP_H

#include "types.h"

/*
 * Data item structure used by lookup.
 */
typedef
struct struct_app_lookup_data
{
    short sourcePort;
    char type;
    Int32 seqNo;
    clocktype txTime;
    clocktype replyDelay;
    Int32 replySize;
    TosType tos;
}
LookupData;


/* Structure containing lookup client information. */

typedef
struct struct_app_lookup_client_str
{
    NodeAddress localAddr;
    NodeAddress remoteAddr;
    clocktype requestInterval;
    clocktype replyDelay;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastSent;
    clocktype sessionLastReceived;
    clocktype endTime;
    BOOL sessionIsClosed;
    Int32 numBytesSent;
    Int32 numPktsSent;
    Int32 numBytesRecvd;
    Int32 numPktsRecvd;
    clocktype totalEndToEndDelay;
    Int32 requestsToSend;
    Int32 requestSize;
    Int32 replySize;
    short sourcePort;
    int uniqueId;
    Int32 seqNo;
    TosType tos;

    STAT_AppStatistics* stats;
}
AppDataLookupClient;

/* Structure containing lookup related information. */

typedef
struct struct_app_lookup_server_str
{
    NodeAddress localAddr;
    NodeAddress remoteAddr;
    short sourcePort;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastReceived;
    BOOL sessionIsClosed;
    Int32 numBytesSent;
    Int32 numPktsSent;
    Int32 numBytesRecvd;
    Int32 numPktsRecvd;
    Int32 seqNo;
    int uniqueId;

    STAT_AppStatistics* stats;
}
AppDataLookupServer;

/*
 * NAME:        AppLayerLookupClient.
 * PURPOSE:     Models the behaviour of LookupClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerLookupClient(
    Node *nodePtr,
    Message *msg);

/*
 * NAME:        AppLookupClientInit.
 * PURPOSE:     Initialize a LookupClient session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts.
 *              endTime - time until the session end.
 *              tos - the contents for the type of service field.
 *              isRsvpTeEnabled - whether RSVP-TE is enabled
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
    unsigned tos);

/*
 * NAME:        AppLookupClientFinalize.
 * PURPOSE:     Collect statistics of a LookupClient session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppLookupClientFinalize(
    Node *nodePtr,
    AppInfo* appInfo);

/*
 * NAME:        AppLayerLookupServer.
 * PURPOSE:     Models the behaviour of LookupServer Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerLookupServer(
    Node *nodePtr,
    Message *msg);

/*
 * NAME:        AppLookupServerInit.
 * PURPOSE:     listen on LookupServer server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppLookupServerInit(
    Node *node);

/*
 * NAME:        AppLookupServerFinalize.
 * PURPOSE:     Collect statistics of a LookupServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppLookupServerFinalize(
    Node *nodePtr,
    AppInfo* appInfo);


#endif /* LOOKUP_APP_H */
