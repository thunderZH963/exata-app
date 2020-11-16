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

#ifndef _EHTTP_H_
#define _EHTTP_H_

#include "types.h"


#if 0
typedef
enum
{
    EHTTP_IDLE,
    EHTTP_XMIT_PRIMARY_REQUEST,
    EHTTP_XMIT_SECONDARY_REQUEST,
    EHTTP_WAIT_PRIMARY_RESPONSE,
    EHTTP_WAIT_SECONDARY_RESPONSE
}
EHttpClientState;
typedef
enum
{
    THINK_TIMER,
    WAIT_PRIMARY_REPLY_TIMER,
    WAIT_SECONDARY_REPLY_TIMER
}
HttpClientTimerType;

typedef
struct http_client_timer_str
{
    HttpClientTimerType timerType;
    Int32 clientId;
}
HttpClientTimer;

#endif 
typedef
struct ehttp_client_stats_str
{
    int itemRequestBytes;   // number of bytes this item
    int pageItems;          // number of items this page
}
EHttpClientStats;

typedef
struct struct_app_ehttp_client_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;         // start time of current session
    clocktype sessionFinish;        // end time of current session
    clocktype avgSessionLength;     // average session length
    Int32 numSessions;               // total number of sessions
    Int32 numPages;                  // total num of pages recvd
    Address *servers;
    Int32 num_servers;
    double Zipf_constant;
    clocktype threshhold;
    clocktype lastReceiveTime;
    EHttpClientStats stats;
    RandomSeed seed;
    //EHttpClientState state;
    BOOL sessionIsClosed;
    Int32 documentsOnCurrentServer;
    int itemSizeLeft;
    Int64 numBytesSent;
    Int64 numBytesRecvd;
    clocktype cumulativePageRequestTimes;
    clocktype primaryRequestSendTime;
    clocktype longestPageRequestTime;
    Int32 uniqueId;
}
AppDataEHttpClient;

typedef
struct struct_app_ehttp_server_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL sessionIsClosed;
    Int64 numBytesSent;
    Int64 numBytesRecvd;
    Int32 pagesSent;
    Int32 bytesRemaining;
    RandomSeed seed;
    char inBuffer[MAX_STRING_LENGTH*8];
    //char inBuffer[9648];
    int intLine;
    int methodReturn;
    int keepAlive;
    char reqMethod[MAX_STRING_LENGTH];
    char reqUri[MAX_STRING_LENGTH];
    char reqVersion[MAX_STRING_LENGTH];

}
AppDataEHttpServer;

#if 0
// An array of DoubleDistElements expresses the CDF of a distribution,
// sorted so we can access its quickly via binary search.  We do
// linear interpolation between the values in the array.

typedef struct DoubleDistElement_str {
    double value;
    double cdf;
} DoubleDistElement;

double DoubleDistEmpiricalIntegralInterpolate(
    double x1, double x2, double y1, double y2, double x);

double DoubleDistEmpiricalContinuousInterpolate(
    double x1, double x2, double y1, double y2, double x);

int DoubleDistFindIndex(const DoubleDistElement *array,
                                        const Int32 count, double value);
#endif 
/*
 * NAME:        AppLayerEHttpServer.
 * PURPOSE:     Models the behaviour of Http Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerEHttpServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppEHttpServerInit.
 * PURPOSE:     listen on Http server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppEHttpServerInit(Node* nodePtr, Address serverAddr, const char* baseDir);

/*
 * NAME:        AppEHttpServerPrintStats.
 * PURPOSE:     Prints statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the http server data structure.
 * RETURN:      none.
 */
void
AppEHttpServerPrintStats(Node *nodePtr, AppDataEHttpServer *serverPtr);

/*
 * NAME:        AppEHttpServerFinalize.
 * PURPOSE:     Collect statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppEHttpServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppEHttpServerGetEHttpServer.
 * PURPOSE:     search for a http server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the http server.
 * RETURN:      the pointer to the http server data structure,
 *              NULL if nothing found.
 */
AppDataEHttpServer *
AppEHttpServerGetEHttpServer(Node *nodePtr, int connId);

/*
 * NAME:        AppEHttpServerRemoveEHttpServer.
 * PURPOSE:     Remove an HTTP server process that corresponds to the
 *              given connectionId
 * PARAMETERS:  nodePtr - pointer to the node.
 *              closeRes - the close connection results from TCP
 * RETURN:      none.
 */
void
AppEHttpServerRemoveEHttpServer(
    Node *nodePtr,
    TransportToAppCloseResult *closeRes);

/*
 * NAME:        AppEHttpServerNewEHttpServer.
 * PURPOSE:     create a new http server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created http server data structure,
 *              NULL if no data structure allocated.
 */
AppDataEHttpServer *
AppEHttpServerNewEHttpServer(Node *nodePtr,
                           TransportToAppOpenResult *openResult);

/*
 * NAME:        AppEHttpServerSendCtrlPkt.
 * PURPOSE:     call AppHttpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppEHttpServerSendCtrlPkt(Node *nodePtr, AppDataEHttpServer *serverPtr);

/*
 * NAME:        AppHttpClientDeterminePrimaryReplyLength.
 * PURPOSE:     Return the number of bytes in the primary reply
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppEHttpServerDeterminePrimaryReplyLength(Node *node, AppDataEHttpServer *serverPtr);

/*
 * NAME:        AppHttpClientDetermineSecondaryReplyLength.
 * PURPOSE:     Return the number of bytes in the secondary reply
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppEHttpServerDetermineSecondaryReplyLength(Node *node, AppDataEHttpServer *serverPtr);

/*
 * NAME:        AppEHttpServerSendSecondaryReply.
 * PURPOSE:     Send the secondary reply to the client.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              secondaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void
AppEHttpServerSendSecondaryReply(
    Node *node,
    AppDataEHttpServer *serverPtr,
    Int32 secondaryReplyLength);

/*
 * NAME:        AppEHttpServerSendPrimaryReply.
 * PURPOSE:     Send the primary reply to the client.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              primaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void
AppEHttpServerSendPrimaryReply(
    Node *node,
    AppDataEHttpServer *serverPtr,
    Int32 primaryReplyLength);

void AppEHttpServerHandleRequest( Node *node, AppDataEHttpServer * serverPtr, char * request, int requestLen);
int AppEHttpServerMethodParsing(char * method);
void AppEHttpServerGetParameter(char * buf, char * method, char * uri, char * version);
void AppEHttpServerMessageToClient(Node* node, AppDataEHttpServer* serverPtr, const char* output, int length);
void AppEHttpServerTimeSend(Node * node, AppDataEHttpServer * serverPtr);

void AppEHttpServerHeaderSend(Node* node, AppDataEHttpServer* serverPtr, const char* filename, int keepAlive, int fileSize);


void AppEHttpServerIndexHtml(Node *node, AppDataEHttpServer * serverPtr);
void AppEHttpServerStatsHtml(Node *node, AppDataEHttpServer * serverPtr);
void AppEHttpServerFavIconHtml(Node *node, AppDataEHttpServer * serverPtr);
void AppEHttpServerNotFound(Node *node, AppDataEHttpServer * serverPtr);

int AppEHttpServerFileSend(Node* node, AppDataEHttpServer* serverPtr, const char* fileName, int fileSize);
int AppEHttpServerGetLine(char * inBuf, char * sLine, int *requestLen);

void AppEHttpServerHeaderSendForStats(Node * node, AppDataEHttpServer *serverPtr);
void AppEHttpServerErrorHandle(Node* node, AppDataEHttpServer* serverPtr, const char* path, int eIndex);

struct contentsList {
    char * fileName;
    void (* pfunc)(Node *node, AppDataEHttpServer *serverPtr);
};

#endif /* _EHTTP_H_ */


