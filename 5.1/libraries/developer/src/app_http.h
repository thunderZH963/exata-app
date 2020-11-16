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

#ifndef _HTTP_H_
#define _HTTP_H_

#include "types.h"
#include "stats_app.h"

typedef
enum
{
    IDLE,
    XMIT_PRIMARY_REQUEST,
    XMIT_SECONDARY_REQUEST,
    WAIT_PRIMARY_RESPONSE,
    WAIT_SECONDARY_RESPONSE
}
HttpClientState;

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

typedef
struct http_client_stats_str
{
    int itemRequestBytes;   // number of bytes this item
    int pageItems;          // number of items this page
}
HttpClientStats;

typedef
struct struct_app_http_client_str
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
    HttpClientStats stats;
    RandomSeed seed;
    HttpClientState state;
    BOOL sessionIsClosed;
    Int32 documentsOnCurrentServer;
    int itemSizeLeft;
    Int64 numBytesSent;
    Int64 numBytesRecvd;
    clocktype cumulativePageRequestTimes;
    clocktype primaryRequestSendTime;
    clocktype longestPageRequestTime;
    Int32 uniqueId;
    std::string* applicationName;
    STAT_AppStatistics* appStats;

    // Dynamic address Changes
    std::vector<std::string> serverUrls;
    NetworkType queryNetworktype;
    Int32 serverIndex;
    NodeAddress* serverNodeIds;
    Int16* serverInterfaceIndex;
    Int16 clientInterfaceIndex;
}
AppDataHttpClient;

typedef
struct struct_app_http_server_str
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
    int clientUniqueId;
    Int32 uniqueId;
    STAT_AppStatistics* appStats;

}
AppDataHttpServer;

// Dynamic Address Change
// This structure contains the list of AppDataHttpServer with the 
// interface index.
// The stucture is prepared on the basis of interface index
struct AppHttpServerList
{
    Int32 interfaceIndex;
    std::list<AppDataHttpServer*>* httpServerDataList;
};

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


/*
 * NAME:        AppLayerHttpClient.
 * PURPOSE:     Models the behaviour of Http Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerHttpClient(Node *nodePtr, Message *msg);

/*
 * NAME:        AppHttpClientInit.
 * PURPOSE:     Initialize a Http session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddrs - addresses of the servers to choose from,
 *              numServerAddrs - number of addresses in above array,
 *              startTime - the time to start the first connection
 *              thresh - maximum time before deciding the connection is done.
 *              appName - application alias name
 *              serverUrls - list of url address if server configured as url
 * RETURN:      none.
 */
void
AppHttpClientInit(
    Node *nodePtr,
    Address clientAddr,
    Address *serverAddrs,
    Int32 numServerAddrs,
    clocktype startTime,
    clocktype thresh,
    char* appName,
    std::vector<std::string> serverUrls);

/*
 * NAME:        AppHttpClientFinalize.
 * PURPOSE:     Collect statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */

void
AppHttpClientFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppHttpClientNewHttpClient.
 * PURPOSE:     create a new http client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      the pointer to the created http client data structure,
 *
 */
/*static AppDataHttpClient *
AppHttpClientNewHttpClient(Node *nodePtr);*/

/*
 * NAME:        AppHttpClientSendThinkTimer.
 * PURPOSE:     Send a Timeout to itself at the end of the determined
 *              thinking period.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              clientPtr - pointer to the client's data structure
 *              thinkTime - determined thinking period
 * RETURN:      none.
 */
void
AppHttpClientSendThinkTimer(
    Node *nodePtr,
    AppDataHttpClient *clientPtr,
    clocktype thinkTime);

/*
 * NAME:        AppHttpClientSendWaitReplyTimer.
 * PURPOSE:     Send a Timeout to itself just in case the server never replies
 *              to a page request.  Times out at the maximum think threshhold
 *              parameter.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              clientPtr - pointer to the client's data structure
 *              timerType - either WAIT_PRIMARY_RESPONSE or
 *                                 WAIT_SECONDARY_RESPONSE
 * RETURN:      none.
 */
void
AppHttpClientSendWaitReplyTimer(
    Node *nodePtr,
    AppDataHttpClient *clientPtr,
    HttpClientTimerType timerType);

/*
 * NAME:        AppHttpClientProcessDoneThinking.
 * PURPOSE:     After waiting the think period, either request the next
 *              document, or select a new http server and start over.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientPtr - pointer to the client's data structure
 * RETURN:      none.
 */
void
AppHttpClientProcessDoneThinking(Node *node,
                                 AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientProcessWaitReplyTimer.
 * PURPOSE:     Do nothing if the packet reception was successful,
 *              otherwise, check if the server has not responded within
 *              the allotted threshhold.  If not, request the next
 *              document.  If so, reset the timer.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientPtr - pointer to the client's data structure
 * RETURN:      none.
 */
void
AppHttpClientProcessWaitReplyTimer(Node *node,
                                   AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientProcessReplyPacket.
 * PURPOSE:     Process a Reply Packet from the server.  This packet is marked
 *              as the last one corresponding to a specific request.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientPtr - pointer to the client's data structure
 * RETURN:      none.
 */
void
AppHttpClientProcessReplyPacket(Node *node,
                                AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientConsecutiveDocumentRetrievals.
 * PURPOSE:     Return the number of consecutive document retrievals for the
 *              current server.
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of consecutive document retrievals.
 */
Int32
AppHttpClientConsecutiveDocumentRetrievals(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientSelectNewServer.
 * PURPOSE:     Return the address for the next selected server
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the server index for the next server to communicate with.
 */
Int32
AppHttpClientSelectNewServer(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientDetermineThinkTime.
 * PURPOSE:     Return the amount of time to think for, before the next
 *              request.
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the amount of time to wait.
 */
double
AppHttpClientDetermineThinkTime(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientDetermineItemCount.
 * PURPOSE:     Return the number of items on this particular page.
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of items.
 */
Int32
AppHttpClientDetermineItemCount(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientDetermineSecondaryRequestLength.
 * PURPOSE:     Return the number of bytes in the secondary request
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppHttpClientDetermineSecondaryRequestLength(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientDeterminePrimaryRequestLength.
 * PURPOSE:     Return the number of bytes in the primary request
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppHttpClientDeterminePrimaryRequestLength(AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientSendPrimaryRequest.
 * PURPOSE:     Send the primary request of the given size to the server.
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      none.
 */
void
AppHttpClientSendPrimaryRequest(
    Node *node,
    AppDataHttpClient *clientPtr,
    Int32 primaryRequestLength);

/*
 * NAME:        AppHttpClientSendSecondaryRequest.
 * PURPOSE:     Send the secondary request of the given size to the server.
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      none.
 */
void
AppHttpClientSendSecondaryRequest(
    Node *node,
    AppDataHttpClient *clientPtr,
    Int32 secondaryRequestLength);

/*
 * NAME:        AppHttpClientPrintStats.
 * PURPOSE:     Prints statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              clientPtr - pointer to the http client data structure.
 * RETURN:      none.
 */
void
AppHttpClientPrintStats(Node *nodePtr, AppDataHttpClient *clientPtr);

/*
 * NAME:        AppHttpClientGetHttpClient.
 * PURPOSE:     search for a http client data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              connId - connection ID of the http client.
 * RETURN:      the pointer to the http client data structure,
 *              NULL if nothing found.
 */
AppDataHttpClient *
AppHttpClientGetHttpClient(Node *nodePtr, int connId);

/*
 * NAME:        AppHttpClientUpdateHttpClient.
 * PURPOSE:     update existing http client data structure by including
 *              connection id.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created http client data structure,
 *              NULL if no data structure allocated.
 */
AppDataHttpClient *
AppHttpClientUpdateHttpClient(Node *nodePtr,
                              TransportToAppOpenResult *openResult);

/*
 * NAME:        AppHttpClientNewHttpClient.
 * PURPOSE:     create a new http client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appName - application alias name
 * RETURN:      the pointer to the created http client data structure,
 *
 */
AppDataHttpClient *
AppHttpClientNewHttpClient(Node *nodePtr, char* appName);



/*
 * NAME:        AppLayerHttpServer.
 * PURPOSE:     Models the behaviour of Http Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerHttpServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppHttpServerInit.
 * PURPOSE:     listen on Http server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppHttpServerInit(Node *nodePtr, Address serverAddr);

/*
 * NAME:        AppHttpServerPrintStats.
 * PURPOSE:     Prints statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the http server data structure.
 * RETURN:      none.
 */
void
AppHttpServerPrintStats(Node *nodePtr, AppDataHttpServer *serverPtr);

/*
 * NAME:        AppHttpServerFinalize.
 * PURPOSE:     Collect statistics of a Http session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppHttpServerFinalize(Node *nodePtr, AppInfo* appInfo);

//---------------------------------------------------------------------------
// FUNCTION     : AppHttpServerGetHttpServer.
// PURPOSE      : Get the http server data pointer for this connection Id.
// PARAMETERS   ::
// +node        : Node* : pointer to the node.
//+connId       : Int32 : connectionId for which http server data pointer 
//                        is required
// RETURN       :
// AppDataHttpServer*   : server pointer with this connectionId if found 
//                        else NULL
//---------------------------------------------------------------------------
AppDataHttpServer*
AppHttpServerGetHttpServer(Node *nodePtr, int connId);

/*
 * NAME:        AppHttpServerRemoveHttpServer.
 * PURPOSE:     Remove an HTTP server process that corresponds to the
 *              given connectionId
 * PARAMETERS:  nodePtr - pointer to the node.
 *              closeRes - the close connection results from TCP
 * RETURN:      none.
 */
void
AppHttpServerRemoveHttpServer(
    Node *nodePtr,
    TransportToAppCloseResult *closeRes);

/*
 * NAME:        AppHttpServerNewHttpServer.
 * PURPOSE:     create a new http server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created http server data structure,
 *              NULL if no data structure allocated.
 */
AppDataHttpServer *
AppHttpServerNewHttpServer(Node *nodePtr,
                           TransportToAppOpenResult *openResult);

/*
 * NAME:        AppHttpServerSendCtrlPkt.
 * PURPOSE:     call AppHttpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppHttpServerSendCtrlPkt(Node *nodePtr, AppDataHttpServer *serverPtr);

/*
 * NAME:        AppHttpClientDeterminePrimaryReplyLength.
 * PURPOSE:     Return the number of bytes in the primary reply
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppHttpServerDeterminePrimaryReplyLength(Node *node, AppDataHttpServer *serverPtr);

/*
 * NAME:        AppHttpClientDetermineSecondaryReplyLength.
 * PURPOSE:     Return the number of bytes in the secondary reply
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppHttpServerDetermineSecondaryReplyLength(Node *node, AppDataHttpServer *serverPtr);

/*
 * NAME:        AppHttpServerSendSecondaryReply.
 * PURPOSE:     Send the secondary reply to the client.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              secondaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void
AppHttpServerSendSecondaryReply(
    Node *node,
    AppDataHttpServer *serverPtr,
    Int32 secondaryReplyLength);

/*
 * NAME:        AppHttpServerSendPrimaryReply.
 * PURPOSE:     Send the primary reply to the client.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              primaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void
AppHttpServerSendPrimaryReply(
    Node *node,
    AppDataHttpServer *serverPtr,
    Int32 primaryReplyLength);

/*
 * NAME:        AppHttpClientCheckLatePacket.
 * PURPOSE:     check if a late packet from some earlier connection
 *              is received.
 * PARAMETERS:  node - pointer to the node.
 *              connId - connection ID of the http client.
 * BOOL:        TRUE: if late packet received
 *              FALSE: otherwise
 */
BOOL
AppHttpClientCheckLatePacket(Node *node, Int32 connId);

/*
 * NAME:        AppHttpServerGetExistingHttpServer.
 * PURPOSE:     Finds the existing httpServer data structure from AppMap
                whose remote address and clientUniqueId matches with
                the remoteAddress and clientUniqueId of openResult.
 * PARAMETERS:  node - Node* : pointer to the node.
 *              openResult - TransportToAppOpenResult* : result of the
                open request.
 * RETURN:      the pointer to the last http server data structure,
 *              NULL if no data structure allocated.
 */
AppDataHttpServer*
AppHttpServerGetExistingHttpServer(Node* node,
                                   TransportToAppOpenResult* openResult);

//--------------------------------------------------------------------------
// FUNCTION    :: AppHttpUrlSessionStartCallBack
// PURPOSE     :: To update the client when URL is resolved
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : unsigned short : source port
// + uniqueId   : Int32          : connection id
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo : information required to 
//                                                 send buffered application 
//                                                 packets in case of UDP 
//                                                 based applications; not
//                                                 used by HTTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//---------------------------------------------------------------------------
bool
AppHttpUrlSessionStartCallBack(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    struct AppUdpPacketSendingInfo* packetSendingInfo);

//--------------------------------------------------------------------------
// FUNCTION    :: AppHttpAddAddressInformation
// PURPOSE     :: To add address information in HTTP
// PARAMETERS   ::
// + node       : Node*                 : pointer to the node
// + clientPtr  : AppDataHttpClient*    : http client pointer
// RETURN       : NONE
//---------------------------------------------------------------------------
void
AppHttpAddAddressInformation(Node* node,
                            AppDataHttpClient* clientPtr);

//--------------------------------------------------------------------------
// FUNCTION    :: AppHttpClientGetHttpClientFromUniqueId
// PURPOSE     :: To retrieve HTTP client based on unique id
// PARAMETERS   ::
// + node       : Node* : pointer to the node
// + uniqueId   : Int32 : unique id
// RETURN       :
// AppDataHttpClient* : client pointer if found else NULL
//---------------------------------------------------------------------------
AppDataHttpClient*
AppHttpClientGetHttpClientFromUniqueId(Node *node, Int32 uniqueId);

//---------------------------------------------------------------------------
// FUNCTION : AppHttpServerGetServerForThisInterfaceIndex.
// PURPOSE  : Get the http server structure from the node’s app data list.
// PARAMETERS: 
// +node            : Node* : pointer to the node
// +interfaceIndex  : Int32 : interface index
// RETURN:
// AppHttpServerList*  : HttpServer list formed at this interface.
//---------------------------------------------------------------------------
AppHttpServerList*
AppHttpServerGetServerForThisInterfaceIndex (
                                Node *node,
                                Int32 interfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION : HttpServerHandleChangeAddressEvent.
// PURPOSE  : Handle the change address event of http server.
// PARAMETERS: 
// +node            : Node* : pointer to the node
// +interfaceIndex  : Int32 : interface index
// +oldAddress      : Address*  : old address
// +subnetMask      : subnet mask
// +networkType     : network type
// RETURN           : NONE
//---------------------------------------------------------------------------
void HttpServerHandleChangeAddressEvent(
    Node* node,
    Int32 interfaceIndex,
    Address* oldAddress,
    NodeAddress subnetMask,
    NetworkType networkType);
#endif /* _HTTP_H_ */

