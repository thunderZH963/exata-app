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

/*
 * This file contains initialization function, message processing
 * function, and finalize function used by each http application.
 * This code is adapted from the work published by Bruce Mah.
 *      B. Mah, "An Empirical Model of HTTP Network Traffic",
 *      Proceedings of INFOCOM '97, Kobe, Japan, April 1997.
 *      http://www.employees.org/~bmah/Papers/Http-Infocom.pdf
 *
 * Differences/Modifications to the above model:
 * 1) 0 length request/response packets are changed to 1-byte packets
 * 2) The addition of a threshhold parameter that limits the maximum
 *    "think time" between page requests
 * 3) The use of this maximum threshhold parameter to recover from
 *    disconnections- the http client will re-initiate page requests if
 *    it is waiting for a response from the server, and has not received
 *    an update in {maximum threshhold} time.
 */

#ifdef EXATA
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>


#include "api.h"
#include "transport_tcp.h"
#include "app_util.h"
#include "app_ehttp.h"

static const int HttpPrimaryReplyDistLength =  1133 ;
static const int HttpConsecutiveDocsDistLength =  21 ;
static const int HttpFilesPerDocumentDistLength =  27 ;
static const int HttpPrimaryRequestDistLength =  305 ;
static const int HttpSecondaryReplyDistLength =  1848 ;
static const int HttpSecondaryRequestDistLength =  286 ;
static const int HttpThinkTimeDistLength =  1649 ;

static const char * methodList[] = {"GET", "HEAD", "POST"};
static const char * filetype_list[] = {"html", "htm", "HTML", "HTM", "txt", "TXT", "", "",
                            "jpeg", "JPEG", "jpg", "JPG", "gif","GIF", "", "",
                            "pdf","PDF","",""};
static const char * filetype_result[] = {"text/html", "text/plain","image/jpeg", "image/gif",
                            "application/pdf","application/octet-stream"};

static std::string rootDirectory;
#define MAX_METHOD  3
#define MAX_FILETYPE    5

#define GET     0
#define HEAD    1
#define POST    2

/*
// for dynamic creation
static struct contentsList cList[] =
                        {{"/", AppEHttpServerIndexHtml},
                        {"/stats", AppEHttpServerStatsHtml},
                        {"/favicon.ico", AppEHttpServerFavIconHtml},
                        {NULL, AppEHttpServerNotFound}};
*/

const char * err_list[] = { "400 Bad Request", "404 Not Found",                           // 0:400 1:404
                      "500 Internal Server Error", "501 Method Not Implemented" };  // 2:500 3:501

/*
 * NAME:        AppLayerEHttpServer.
 * PURPOSE:     Models the behaviour of Http Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerEHttpServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    memset(buf , 0, sizeof(buf));
    AppDataEHttpServer *serverPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("HTTP Server: Node %ld at %s got listenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            if (listenResult->connectionId == -1)
            {
                node->appData.numAppTcpFailure++;
            }

            break;
        }

        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;
            openResult = (TransportToAppOpenResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("HTTP Server: Node %ld at %s got OpenResult connId:%d\n",
                    node->nodeId, buf,openResult->connectionId );
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_PASSIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure++;
            }
            else
            {
                AppDataEHttpServer *serverPtr;
                serverPtr = AppEHttpServerNewEHttpServer(node, openResult);
                assert(serverPtr != NULL);
            }

            break;
        }

        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;
            char *payload;
            Int32 sendSize;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("HTTP Server Node %ld at %s sent data %ld\n",
                    node->nodeId, buf, dataSent->length);
#endif /* DEBUG */

            serverPtr = AppEHttpServerGetEHttpServer(node,
                                     dataSent->connectionId);

            //assert(serverPtr != NULL);
            if (serverPtr == NULL)
            {
                 break;
            }

            serverPtr->numBytesSent += (clocktype) dataSent->length;

            if (serverPtr->bytesRemaining > 0)
            {

#ifdef DEBUG
                printf("#%d:   HTTPD - still %d bytes remaining...\n",
                       node->nodeId, serverPtr->bytesRemaining);
#endif /* DEBUG */

                sendSize = MIN(serverPtr->bytesRemaining, APP_MAX_DATA_SIZE);
                payload = (char *)MEM_malloc(sendSize);
                memset(payload,0,sendSize);
                serverPtr->bytesRemaining -= sendSize;

                if (serverPtr->bytesRemaining == 0)
                {
                    *(payload + sendSize - 1) = 'd';
                }

                if (!serverPtr->sessionIsClosed)
                {
                    Message *tcpmsg = 
                        APP_TcpCreateMessage(node, serverPtr->connectionId, TRACE_HTTP);
                    APP_AddPayload(node, tcpmsg, payload, sendSize);
                    APP_TcpSend(node, tcpmsg);
                }
                MEM_free(payload);
            }
            break;
        }

        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived *dataRecvd;
            char *packet;

            dataRecvd = (TransportToAppDataReceived *)
                            MESSAGE_ReturnInfo(msg);

            packet = MESSAGE_ReturnPacket(msg);

#ifdef DEBUG
            printf("HTTP Server: Node %ld at %s received data size %d\n",
                    node->nodeId, buf, MESSAGE_ReturnPacketSize(msg));
#endif /* DEBUG */

            serverPtr = AppEHttpServerGetEHttpServer(node,
                                                 dataRecvd->connectionId);

            //assert(serverPtr != NULL);
            if (serverPtr == NULL)
            {
                //server pointer can be NULL
                break;
            }
            assert(serverPtr->sessionIsClosed == FALSE);

            serverPtr->numBytesRecvd +=
                (clocktype) MESSAGE_ReturnPacketSize(msg);

            // parsing the parameters
            AppEHttpServerHandleRequest(node, serverPtr, msg->packet, msg->packetSize);

            break;
        }

        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("HTTP Server: Node %ld at %s got close result\n",
                    node->nodeId, buf);
#endif /* DEBUG */

            serverPtr = AppEHttpServerGetEHttpServer(node,
                                                 closeResult->connectionId);
            //assert(serverPtr != NULL);
            if (serverPtr == NULL)
            {
                //server pointer can be NULL
                break;
            }

            if (serverPtr->sessionIsClosed == FALSE)
            {
                serverPtr->sessionIsClosed = TRUE;
                serverPtr->sessionFinish = node->getNodeTime();
            }

            AppEHttpServerRemoveEHttpServer(node, closeResult);
            break;
        }

        default:
            ctoa(node->getNodeTime(), buf);
            printf("HTTP Server: Node %u at time %s received "
                   "message of unknown type"
                   " %d.\n", node->nodeId, buf, msg->eventType);
            assert(FALSE);
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppEHttpServerInit.
 * PURPOSE:     listen on Http server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppEHttpServerInit(Node* node, Address serverAddr, const char* baseDir)
{
    if (serverAddr.networkType != NETWORK_IPV4
        && serverAddr.networkType != NETWORK_IPV6)
    {
        return;
    }

    /* this is a static global variable */
    rootDirectory = baseDir; 


    APP_TcpServerListen(
        node,
        APP_EHTTP_SERVER,
        serverAddr,
        (short) APP_EHTTP_SERVER);

}

/*
 * NAME:        AppEHttpServerPrintStats.
 * PURPOSE:     Prints statistics of a Http session.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the http server data structure.
 * RETURN:      none.
 */
void //inline//
AppEHttpServerPrintStats(Node *node, AppDataEHttpServer *serverPtr)
{
    clocktype throughput;
    char timeStr[MAX_STRING_LENGTH];
    char numBytesSentStr[MAX_STRING_LENGTH];
    char numBytesRecvdStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];
    char addrStr[MAX_STRING_LENGTH];


    if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
    }

    TIME_PrintClockInSecond(
        (serverPtr->sessionFinish - serverPtr->sessionStart),
        timeStr);


    if (serverPtr->sessionFinish <= serverPtr->sessionStart)
    {
        throughput = 0;
    }
    else
    {
        throughput = (clocktype)
            (((serverPtr->numBytesRecvd + serverPtr->numBytesSent)
                * 8.0 * SECOND)
            / (serverPtr->sessionFinish - serverPtr->sessionStart));
    }

    ctoa(throughput, throughputStr);

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Connection Length (s) = %s", timeStr);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Pages Sent = %d", serverPtr->pagesSent);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesSent, numBytesSentStr);
    sprintf(buf, "Bytes Sent = %s", numBytesSentStr);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesRecvd, numBytesRecvdStr);
    sprintf(buf, "Bytes Received = %s", numBytesRecvdStr);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Throughput (bits/sec) = %s", throughputStr);
    IO_PrintStat(
        node,
        "Application",
        "WWW Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);
}

/*
 * NAME:        AppEHttpServerFinalize.
 * PURPOSE:     Collect statistics of a Http session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppEHttpServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataEHttpServer *serverPtr = (AppDataEHttpServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppEHttpServerPrintStats(node, serverPtr);
    }
}

/*
 * NAME:        AppEHttpServerGetEHttpServer.
 * PURPOSE:     search for a http server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the http server.
 * RETURN:      the pointer to the http server data structure,
 *              NULL if nothing found.
 */
AppDataEHttpServer * //inline//
AppEHttpServerGetEHttpServer(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataEHttpServer *httpServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_EHTTP_SERVER)
        {
            httpServer = (AppDataEHttpServer *) appList->appDetail;

            if (httpServer->connectionId == connId)
            {
                return httpServer;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppEHttpServerRemoveEHttpServer.
 * PURPOSE:     Remove an HTTP server process that corresponds to the
 *              given connectionId
 * PARAMETERS:  node - pointer to the node.
 *              closeRes - the close connection results from TCP
 * RETURN:      none.
 */
void //inline//
AppEHttpServerRemoveEHttpServer(Node *node,
                              TransportToAppCloseResult *closeRes)
{
    AppInfo *curApp = node->appData.appPtr;
    AppInfo *tempApp;
    AppDataEHttpServer *serverPtr;

    if (curApp == NULL)
        return;

    if (curApp->appType == APP_EHTTP_SERVER)
    {
        serverPtr = (AppDataEHttpServer *) curApp->appDetail;
        assert(serverPtr);
        if (serverPtr->connectionId == closeRes->connectionId)
        {
#ifdef DEBUG
            printf("  REMOVE 1st server.\n");
#endif /* DEBUG */

            MEM_free(serverPtr);
            tempApp = curApp->appNext;
            MEM_free(curApp);
            node->appData.appPtr = tempApp;
            return;
        }

    }

    tempApp = curApp;
    curApp = curApp->appNext;
    while (curApp != NULL)
    {
        if (curApp->appType == APP_EHTTP_SERVER)
        {
            serverPtr = (AppDataEHttpServer *) curApp->appDetail;
            assert(serverPtr);
            if (serverPtr->connectionId == closeRes->connectionId)
            {
#ifdef DEBUG
                printf("    REMOVE intermediate server.\n");
#endif /* DEBUG */

                MEM_free(serverPtr);
                tempApp->appNext = curApp->appNext;
                MEM_free(curApp);
                curApp = tempApp->appNext;
            }
            else
            {
                tempApp = curApp;
                curApp = curApp->appNext;
            }
        }
        else
        {
            tempApp = curApp;
            curApp = curApp->appNext;
    }
}
}

/*
 * NAME:        AppEHttpServerNewEHttpServer.
 * PURPOSE:     create a new http server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created http server data structure,
 *              NULL if no data structure allocated.
 */
AppDataEHttpServer * //inline//
AppEHttpServerNewEHttpServer(Node *node,
                           TransportToAppOpenResult *openResult)
{
    AppDataEHttpServer *httpServer;

    httpServer = (AppDataEHttpServer *)
                 MEM_malloc(sizeof(AppDataEHttpServer));

    /*
     * fill in connection id, etc.
     */
    httpServer->connectionId = openResult->connectionId;
    httpServer->localAddr = openResult->localAddr;
    httpServer->remoteAddr = openResult->remoteAddr;
    httpServer->sessionStart = node->getNodeTime();
    httpServer->sessionFinish = node->getNodeTime();
    httpServer->sessionIsClosed = FALSE;
    httpServer->numBytesSent = 0;
    httpServer->numBytesRecvd = 0;
    httpServer->pagesSent = 0;
    httpServer->bytesRemaining = 0;
    memset(httpServer->inBuffer, 0, MAX_STRING_LENGTH*8);
    memset(httpServer->reqUri, 0, MAX_STRING_LENGTH);
    memset(httpServer->reqMethod, 0, MAX_STRING_LENGTH);
    memset(httpServer->reqVersion, 0, MAX_STRING_LENGTH);

    RANDOM_SetSeed(httpServer->seed,
                   node->globalSeed,
                   node->nodeId,
                   APP_EHTTP_SERVER,
                   httpServer->connectionId); // this is not invariant

    APP_RegisterNewApp(node, APP_EHTTP_SERVER, httpServer);

    httpServer->intLine = 0;

    return httpServer;
}

#if 0
/*
 * NAME:        AppHttpClientDeterminePrimaryReplyLength.
 * PURPOSE:     Return the number of bytes in the primary reply
 * PARAMETERS:
 * RETURN:      the number of bytes.
 */
Int32
AppEHttpServerDeterminePrimaryReplyLength(Node *node, AppDataEHttpServer *serverPtr)
{
    extern const DoubleDistElement *HttpPrimaryReplyDistTable;
    double u = RANDOM_erand(serverPtr->seed);
    float value;
    int midpoint = DoubleDistFindIndex(
                       HttpPrimaryReplyDistTable,
                       HttpPrimaryReplyDistLength,
                       u);

#ifdef DEBUG
    printf("    u = %f\n", u);
    printf("AppHttpClientDeterminePrimaryReplyLength(of %d) = %d\n",
           HttpPrimaryReplyDistLength, midpoint);
#endif /* DEBUG */

    if (midpoint < 0)
    {
        value = (float) HttpPrimaryReplyDistTable[0].value;
    }
    else
    {
        value = (float)
                DoubleDistEmpiricalIntegralInterpolate(
                    HttpPrimaryReplyDistTable[midpoint].cdf,
                    HttpPrimaryReplyDistTable[midpoint + 1].cdf,
                    HttpPrimaryReplyDistTable[midpoint].value,
                    HttpPrimaryReplyDistTable[midpoint + 1].value,
                    u);
    }

#ifdef DEBUG
    printf("    midpoint = %d, value = %f\n", midpoint, value);
#endif /* DEBUG */

    return (Int32) value;
}

/*
 * NAME:        AppHttpClientDetermineSecondaryReplyLength.
 * PURPOSE:     Return the number of bytes in the secondary reply
 * PARAMETERS:  clientPtr - pointer to the client's data structure
 * RETURN:      the number of bytes.
 */
Int32
AppEHttpServerDetermineSecondaryReplyLength(Node *node, AppDataEHttpServer *serverPtr)
{
    extern const DoubleDistElement *HttpSecondaryReplyDistTable;
    double u = RANDOM_erand(serverPtr->seed);
    float value;
    int midpoint = DoubleDistFindIndex(HttpSecondaryReplyDistTable,
                                       HttpSecondaryReplyDistLength,
                                       u);

#ifdef DEBUG
    printf("    u = %f\n", u);
    printf("AppHttpClientDetermineSecondaryReplyLength(of %d) = %d\n",
           HttpSecondaryReplyDistLength, midpoint);
#endif /* DEBUG */

    if (midpoint < 0)
    {
        value = (float) HttpSecondaryReplyDistTable[0].value;
    }
    else
    {
        value = (float)
                DoubleDistEmpiricalIntegralInterpolate(
                    HttpSecondaryReplyDistTable[midpoint].cdf,
                    HttpSecondaryReplyDistTable[midpoint + 1].cdf,
                    HttpSecondaryReplyDistTable[midpoint].value,
                    HttpSecondaryReplyDistTable[midpoint + 1].value,
                    u);
    }

#ifdef DEBUG
    printf("    midpoint = %d, value = %f\n", midpoint, value);
#endif /* DEBUG */

    return (Int32) value;
}
/*
 * NAME:        AppEHttpServerSendPrimaryReply.
 * PURPOSE:     Send the primary reply to the client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              primaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void //inline//
AppEHttpServerSendPrimaryReply(
    Node *node,
    AppDataEHttpServer *serverPtr,
    Int32 primaryReplyLength)
{
    char *payload;
    Int32 sendSize;

/*  Julian: added this because 0 length packets break the sim */
    if (primaryReplyLength == 0)
        primaryReplyLength = 1;


    sendSize = MIN(primaryReplyLength, APP_MAX_DATA_SIZE);
    payload = (char *)MEM_malloc(sendSize);
    memset(payload,0,sendSize);
    primaryReplyLength -= sendSize;
    serverPtr->bytesRemaining = primaryReplyLength;

    if (primaryReplyLength == 0)
    {
        *(payload + sendSize - 1) = 'd';
    }

    if (!serverPtr->sessionIsClosed)
    {
        Message *tcpmsg = 
            APP_TcpCreateMessage(node, serverPtr->connectionId, TRACE_HTTP);
        APP_AddPayload(node, tcpmsg, payload, sendSize);
        APP_TcpSend(node, tcpmsg);
    }
    MEM_free(payload);
}

/*
 * NAME:        AppEHttpServerSendSecondaryReply.
 * PURPOSE:     Send the secondary reply to the client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              secondaryReplyLength - the length in bytes of the reply.
 * RETURN:      none.
 */
void //inline//
AppEHttpServerSendSecondaryReply(
    Node *node,
    AppDataEHttpServer *serverPtr,
    Int32 secondaryReplyLength)
{
    char *payload;
    Int32 sendSize;

/*  Julian: added this because 0 length packets break the sim */
    if (secondaryReplyLength == 0)
        secondaryReplyLength = 1;



    sendSize = MIN(secondaryReplyLength, APP_MAX_DATA_SIZE);
    payload = (char *)MEM_malloc(sendSize);
    memset(payload,0,sendSize);
    secondaryReplyLength -= sendSize;
    serverPtr->bytesRemaining = secondaryReplyLength;

    if (secondaryReplyLength == 0)
    {
        *(payload + sendSize - 1) = 'd';
    }

    if (!serverPtr->sessionIsClosed)
    {
        Message *tcpmsg = 
            APP_TcpCreateMessage(node, serverPtr->connectionId, TRACE_HTTP);
        APP_AddPayload(node, tcpmsg, payload, sendSize);
        APP_TcpSend(node, tcpmsg);
    }
    MEM_free(payload);
}

#endif 
/*
 * NAME:        AppEHttpServerErrorHandle.
 * PURPOSE:     Send the error webpage such as "404 file not found" error
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              path - file name including location.
                eIndex - error Index
 * RETURN:      none.
 */

void AppEHttpServerErrorHandle(Node* node, AppDataEHttpServer* serverPtr, const char* path, int eIndex)
{
    std::string buf;

    buf = "HTTP/1.1 ";
    buf += err_list[eIndex];
    buf += "\r\n";
    AppEHttpServerMessageToClient(node, serverPtr, buf.c_str(), buf.length());

    buf = "Server: My_Httpd\r\n";
    buf += "Content-Type: text/html\r\n";
    buf += "\r\n";
    AppEHttpServerMessageToClient(node, serverPtr, buf.c_str(), buf.length());
    buf = "<HEAD><TITLE>404 Not Found</TITLE></HEAD>\r\n";
    buf += "<BODY><H1>404 Not Found</H1>\r\n";
    buf += "The requested URL ";
    buf += path;
    buf += " was not found on this server.\r\n";
    buf += "</BODY>\r\n";
    AppEHttpServerMessageToClient(node, serverPtr, buf.c_str(), buf.length());

}

/*
 * NAME:        AppEHttpServerHandleRequest.
 * PURPOSE:     Handle HTTP request from the client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              request - file name from client.
                questLen - length of request.
 * RETURN:      none.
 */
void AppEHttpServerHandleRequest(Node * node, AppDataEHttpServer * serverPtr, char * request, int requestLen)
{

    char singleLine[MAX_STRING_LENGTH*8];
    std::string mBasedir;
    std::string path;
    struct stat fileStat;
    memset(singleLine, 0, MAX_STRING_LENGTH*8);

    // add request into the inBuffer
    memcpy(serverPtr->inBuffer+serverPtr->intLine, request, requestLen);
    serverPtr->intLine+=requestLen;

    // fetch single line (ending \r\n) from inBuffer
    while (strcmp("\r\n\0", singleLine))
    {
        if ((AppEHttpServerGetLine(serverPtr->inBuffer, singleLine, &serverPtr->intLine)) == -1) //no /r/n
        {
            //not a complete command
            return;
        }
        if (!strncmp(singleLine, "GET", 3))
        {
            AppEHttpServerGetParameter(singleLine, serverPtr->reqMethod, serverPtr->reqUri, serverPtr->reqVersion);
        }
        if (!strncmp(serverPtr->inBuffer, "Connection: Keep", 16)) {
            serverPtr->keepAlive = 1;
        }
    }

    mBasedir = rootDirectory;
    path = mBasedir + serverPtr->reqUri;

    if (!strcmp(serverPtr->reqUri, "/"))
    {
        path += "index.html";
    }
    else if (serverPtr->reqUri[strlen(serverPtr->reqUri)-1] == '/')
    {
        path[path.length()-1] = 0;
    }

    if ((stat(path.c_str(), &fileStat)!= 0) && (strcmp(serverPtr->reqUri, "/serverinfo.html")) )
    {
        AppEHttpServerErrorHandle(node, serverPtr, path.c_str(), 1);   // 404 Not found error
        // printf("[HTTP SERVER] 404: file not found error\n");
        return ;
    }

    switch (serverPtr->methodReturn) {
        case GET:   // GET method
            // dynamic creation
            if (strcmp(serverPtr->reqUri, "/serverinfo.html") == 0)
            {
                AppEHttpServerStatsHtml(node, serverPtr);
                APP_TcpCloseConnection(
                     node,
                     serverPtr->connectionId);
                serverPtr->sessionFinish = node->getNodeTime();
                serverPtr->sessionIsClosed = TRUE;

                break;
            }

            // send header
            //AppEHttpServerHeaderSend(node, serverPtr, path, serverPtr->keepAlive, fileStat.st_size);

            // send contents
            if (AppEHttpServerFileSend(node, serverPtr, path.c_str(), fileStat.st_size) == -1)
                printf("[ERROR] file send error\n");
            APP_TcpCloseConnection(
                    node,
                    serverPtr->connectionId);
            serverPtr->sessionFinish = node->getNodeTime();
            serverPtr->sessionIsClosed = TRUE;
            break;
        case HEAD:   // HEAD method
            AppEHttpServerHeaderSend(node, serverPtr, path.c_str(), serverPtr->keepAlive, fileStat.st_size);
            break;
        default:
            APP_TcpCloseConnection(
                    node,
                    serverPtr->connectionId);
            serverPtr->sessionFinish = node->getNodeTime();
            serverPtr->sessionIsClosed = TRUE;
    }
}

/*
 * NAME:        AppEHttpServerGetLine.
 * PURPOSE:     copy the command to trim out carrage return and line feed.
 * PARAMETERS:  inBuf - original command.
 *              sLine - buffer for the command after trimming out.
 *              intLen - length of string.
 * RETURN:      none.
 */
int AppEHttpServerGetLine(char * inBuf, char * sLine, int *intLen)
{
    int i, j;

    for (i=0 ; i < *intLen ; i++) {
        sLine[i] = inBuf[i];
        if ((inBuf[i]== '\r') && (inBuf[i+1]== '\n'))
        {
            sLine[i+1] = inBuf[i+1];
            sLine[i+2]='\0';
            for (j=(i+2); j<*intLen; j++)
            {
                inBuf[j-(i+2)]=inBuf[j];
            }
            *intLen = *intLen - (i+2);
            return 0;
        }
    }
    return -1;
}

/*
 * NAME:        AppEHttpServerFileSend.
 * PURPOSE:     open and transfer the requested file.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              toSend - file to send.
                fileSize - size of file to send.
 * RETURN:      int.
 */

int AppEHttpServerFileSend(Node* node, AppDataEHttpServer* serverPtr, const char* toSend, int fileSize)
{
    char *buffer;
    FILE * fp;

/*
    AppEHttpServerIndexHtml(node, serverPtr);
                APP_TcpCloseConnection(
                    node,
                    serverPtr->connectionId);
*/

    buffer = (char *)MEM_malloc(fileSize);
    //memset((char *)&buffer, 0, sizeof(buffer));
    if ((fp=fopen(toSend, "r")) == NULL ) {
        return -1;
    } else {
        size_t temp;
        temp = fread((void*)buffer, 1, fileSize, fp);
        AppEHttpServerMessageToClient(node, serverPtr, buffer, fileSize);

        free(buffer);
        fclose(fp);
        return 0;
    }
}

/*
//for dynamic creation
void AppEHttpServerIndexHtml(Node *node, AppDataEHttpServer * serverPtr)
{
    char buf[65535];
    //char buf[MAX_STRING_LENGTH];

    memset((char *)&buf, 0, sizeof(buf));

    sprintf(buf, "<html><head><title>IPNE WEB SERVER</title></head>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<body><p>WELCOME TO IPNE WEB SERVER</p>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<a href=\"stats\">1. Statistics</a>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "</body></html>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
}
*/


/*
 * NAME:        AppEHttpServerHeaderSendForStats.
 * PURPOSE:     transmit the header info for the status command.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 *              bytesToSend - content length
 * RETURN:      void.
 */
void AppEHttpServerHeaderSendForStats(Node * node, AppDataEHttpServer *serverPtr, unsigned int bytesToSend)
{
    char buf[MAX_STRING_LENGTH*8];
    char filetype[MAX_STRING_LENGTH];
    sprintf(filetype, "text/html");

    memset((char *)&buf, 0, sizeof(buf));
    memset((char *)&filetype, 0, sizeof(filetype));

//    check_type(filename, filetype);
    strcpy(buf, "HTTP/1.1 200 OK\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    AppEHttpServerTimeSend(node, serverPtr);

    sprintf(buf, "Server: My_Httpd/0.1\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "Content-Length: %d\r\n", bytesToSend);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "Content-Type: %s\r\n", filetype);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    //if (keepAlive) {
    //    sprintf(buf, "Connection: Keep-Alive\r\n");
    //} else {
        sprintf(buf, "Connection: Close\r\n");
    //}
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    strcpy(buf, "\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
}

/*
 * NAME:        AppEHttpServerStatsHtml.
 * PURPOSE:     handles status request.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 * RETURN:      void.
 */
void AppEHttpServerStatsHtml(Node *node, AppDataEHttpServer * serverPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char tempBuf[MAX_STRING_LENGTH];
    std::string buf;
    unsigned int bytesToSend; //for Content_Length in HTTP header

    memset(addrStr , 0, MAX_STRING_LENGTH);
    memset(statusStr , 0, MAX_STRING_LENGTH);

    memset((char *)&tempBuf, 0, sizeof(tempBuf));
    bytesToSend = 0;

    sprintf(tempBuf, "<HTML><HEAD><TITLE>Scalable Network Technologies: Creators of EXata</TITLE>");
    buf += tempBuf;
    sprintf(tempBuf, "</HEAD><BODY>");
    buf += tempBuf;
    if (serverPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
    }
    else
    {
        sprintf(statusStr, "Closed");
    }

    sprintf(tempBuf, "<p>Session Status = %s</p>", statusStr);
    //AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
    buf += tempBuf;
    
    IO_ConvertIpAddressToString(&serverPtr->localAddr, addrStr);
    sprintf(tempBuf, "<p>Server address = %s (node id:%d)</p>", addrStr, node->nodeId);
    //AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
    buf += tempBuf;
    
    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(tempBuf, "<p>Client address = %s</p>", addrStr);
    //AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
    buf += tempBuf;
    
    buf += "<p>Base directory  = " + rootDirectory + "</p>";
    //AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
    
    sprintf(tempBuf, "<H4 ALIGN=\"CENTER\"><font color=\"silver\"> Scalable Network Technologies, INC. Copyright (c) 2008</font></H4> </BODY> </HTML>");
    buf += tempBuf;
    bytesToSend = buf.length();

    AppEHttpServerHeaderSendForStats(node, serverPtr, bytesToSend);
    AppEHttpServerMessageToClient(node, serverPtr, buf.c_str(), buf.length());

}

#ifdef DERIUS
void AppEHttpServerStatsHtml(Node *node, AppDataEHttpServer * serverPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    AppEHttpServerHeaderSendForStats(node, serverPtr);

    memset(addrStr , 0, MAX_STRING_LENGTH);
    memset(statusStr , 0, MAX_STRING_LENGTH);
    memset((char *)&buf, 0, sizeof(buf));

    sprintf(buf, "<HTML><HEAD><TITLE>Scalable Network Technologies: Creators of QualNet Network Simulator Software</TITLE>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));


    sprintf(buf, "</HEAD><BODY> <TABLE id=headgfx cellSpacing=0 cellPadding=0 width=770 align=center border=0> <TBODY>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TR><TD width=10 background=tile_shdw_lt.jpg></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD><TABLE cellSpacing=0 cellPadding=0 width=%c100%c border=0><TBODY><TR>", 0x22, 0x22);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD align=right width=243 background=tile_head_grad03.jpg height=\"47\"><IMG src=\"header_logo.gif\" border=0></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD vAlign=\"middle\" align=\"center\" background=tile_head_grad03.jpg height=\"47\" width=\"316\"></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD vAlign=bottom align=left background=tile_head_grad03.jpg height=\"47\" width=\"191\"> </TD></TR></TBODY></TABLE></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD width=10 background=tile_shdw_rt.jpg></TD></TR></TBODY></TABLE>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TABLE cellSpacing=0 cellPadding=0 width=770 align=center border=0> <TBODY> <TR> <TD background=tile_shdw_lt.jpg rowSpan=2 width=10></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, " <TD vAlign=top align=left width=10>&nbsp;</td> <TD width=10 background=tile_shdw_rt.jpg rowSpan=2></TD></TR>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TR><TD><TABLE cellSpacing=0 cellPadding=0 width=750 border=0 id=\"index\"><TR>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<Th id=\"indexh1\" vAlign=center align=left width=10 background=tile_head_grad04.jpg>&nbsp;</Th>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<Th id=\"indexh1\" vAlign=center align=left background=tile_head_grad04.jpg height=20>&nbsp;</Th>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf,"<Th id=\"indexh1\" vAlign=center align=left width=10 background=tile_head_grad04.jpg>&nbsp;</Th> </TR> <TR> <td></td> <td>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    if (serverPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
    }
    else
    {
        sprintf(statusStr, "Closed");
    }

    sprintf(buf, "<p>Session Status = %s</p>", statusStr);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    IO_ConvertIpAddressToString(&serverPtr->localAddr, addrStr);
    sprintf(buf, "<p>Server address = %s (node id =%d)</p>", addrStr, node->nodeId);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "<p>Client address = %s</p>", addrStr);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<p>Base directory  = %s</p><p></p><p></p>", node->httpBaseDir);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "</td> <td></td> </TR> </TABLE></TD></TR></TABLE>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TABLE cellSpacing=0 cellPadding=0 width=770 align=center border=0> <TBODY>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TR> <TD width=10 background=tile_shdw_lt.jpg rowSpan=2></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf,"<TD background=tile_dots.jpg></TD> <TD width=10 background=tile_shdw_rt.jpg rowSpan=2></TD></TR>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, " <TR> <TD id=footer align=right><font color=\"silver\">");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "Scalable Network Technologies, Inc. Copyright (c) 2007</font></TD></TR>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf,"<TR> <TD vAlign=top align=right width=10 height=10><IMG height=10 src=\"tile_shdw_crnr_l.jpg\" width=10></TD>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<TD vAlign=top height=10><IMG height=10 src=\"tile_shdw_bottom.jpg\" width=%c100%c></TD>", 0x22, 0x22);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf,"<TD vAlign=top align=left width=10 height=10><IMG height=10 src=\"tile_shdw_crnr_r.jpg\" width=10></TD></TR></TBODY></TABLE> </BODY></HTML>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
}
#endif


/*
 * NAME:        AppEHttpServerNotFound.
 * PURPOSE:     handles "file not found" error.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 * RETURN:      void.
 */
void AppEHttpServerNotFound(Node *node, AppDataEHttpServer * serverPtr)
{

    printf("404 Not Found error\n");
    char buf[MAX_STRING_LENGTH];

    memset((char *)&buf, 0, sizeof(buf));

    sprintf(buf, "<html><head><title>EXATA WEB SERVER</title></head>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "<body><p>File not found</p>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "%s", serverPtr->reqUri);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "</body></html>");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));


}

/*
 * NAME:        AppEHttpServerGetParameter.
 * PURPOSE:     parse the request.
 * PARAMETERS:  buf - request input.
                method - method of request, e.g. GET and POST.
                uri - requested file including path.
                version - version of HTTP.
 * RETURN:      void.
 */
void AppEHttpServerGetParameter(char * buf, char * method, char * uri, char * version)
{
    unsigned int i, j, k;

    for (i=0; !isspace(buf[i]); i++) {
        method[i] = buf[i];
    }
    method[i] = '\0';

    while (isspace(buf[i]))
        i++;

    for (j=0; !isspace(buf[i]); j++, i++) {
        uri[j] = buf[i];
    }
    uri[j] = '\0';
    /* blank in URI handling */
    for (j=0; j<strlen(uri); j++) {
        if (uri[j] == '%' ) {
            uri[j] = ' ';
            for (k=j+1; k<strlen(uri); k++){
                uri[k] = uri[k+2];
            }
            j--;
        }
    }
    while (isspace(buf[i]))
        i++;
    for (j=0; !isspace(buf[i]); j++, i++) {
        version[j] = buf[i];
    }
    version[j] = '\0';
}

/*
 * NAME:        AppEHttpServerMethodParsing.
 * PURPOSE:     sanity check for the method.
 * PARAMETERS:  method - method of request, e.g. GET and POST.
 * RETURN:      int.
 */
int AppEHttpServerMethodParsing(char * method)
{
    int i;

    for (i=0; i<MAX_METHOD; i++) {
        if (!strcmp(method, methodList[i]))     return i;
    }
    return -1;
}

/*
 * NAME:        AppEHttpServerCheckType.
 * PURPOSE:     return the file type of the requested file.
 * PARAMETERS:  file - requested filename.
                filetype - file type of requested file.
 * RETURN:      none.
 */
void AppEHttpServerCheckType(const char * filename, char * filetype)
{
    int i, none;
    char seps[]   = ".";
    char * strPtr;
    char extension[10];
    char * next;
    char token[MAX_STRING_LENGTH];

    memset((char *)&extension, 0, sizeof(extension));
    strcpy(extension, &filename[strlen(filename)-6] );

    strPtr = IO_GetDelimitedToken(token, extension, seps, &next);
    strPtr = IO_GetDelimitedToken(token, next, seps, &next);

    none=1;
    for (i=0; i<MAX_FILETYPE * 4; i++) {
        if (!strcmp(strPtr, filetype_list[i])) {
             strcpy(filetype, filetype_result[i/4]);
             none = 0;
             break;
        }
    }
    if (none) {
        i++;
        strcpy(filetype, filetype_result[i/4]);
    }

}

/*
 * NAME:        AppEHttpServerHeaderSend.
 * PURPOSE:     send header file before content.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
                filename - file to send including the path.
                keepAlive - keepalive info.
                fileSize - size of file to send.
 * RETURN:      void.
 */
void AppEHttpServerHeaderSend(Node* node, AppDataEHttpServer* serverPtr, const char* filename, int keepAlive, int fileSize)
{
    char buf[MAX_STRING_LENGTH*8];
    char filetype[MAX_STRING_LENGTH];

    memset((char *)&buf, 0, sizeof(buf));
    memset((char *)&filetype, 0, sizeof(filetype));

    AppEHttpServerCheckType(filename, filetype);
    strcpy(buf, "HTTP/1.1 200 OK\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    AppEHttpServerTimeSend(node, serverPtr);

    sprintf(buf, "Server: My_Httpd/0.1\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "Content-Length: %d\r\n", fileSize);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    sprintf(buf, "Content-Type: %s\r\n", filetype);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    //if (keepAlive) {
    //    sprintf(buf, "Connection: Keep-Alive\r\n");
    //} else {
        sprintf(buf, "Connection: Close\r\n");
    //}
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));

    strcpy(buf, "\r\n");
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
}

/*
 * NAME:        AppEHttpServerMessageToClient.
 * PURPOSE:     transmit bytestream to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
                output - bytestream to transmit.
                length - length of bytestream to send.
 * RETURN:      void.
 */
void
AppEHttpServerMessageToClient(Node* node, AppDataEHttpServer* serverPtr, const char* output, int length)
{

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = 
            APP_TcpCreateMessage(node, serverPtr->connectionId, TRACE_HTTP);
        APP_AddPayload(node, tcpmsg, output, length);
        APP_TcpSend(node, tcpmsg);
    }
}


/*
 * NAME:        AppEHttpServerTimeSend.
 * PURPOSE:     transmit time infor to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the server's data structure.
 * RETURN:      void.
 */
void AppEHttpServerTimeSend(Node * node, AppDataEHttpServer * serverPtr)
{
    time_t  now;
    struct tm *newtime;
    char buf[1024];

    memset((char *)&buf, 0, sizeof(buf));
    time( &now ); // Get time as long integer
    newtime = localtime( &now ); // Convert to local time

//  sprintf(buf, "Date: %s, %02d %s %d %02d:%02d:%02d GMT\r\n", wday[newtime->tm_wday],
//          newtime->tm_mday,mon[newtime->tm_mon],newtime->tm_year + 1900,
//          newtime->tm_hour,newtime->tm_min,newtime->tm_sec);
    AppEHttpServerMessageToClient(node, serverPtr, buf, strlen(buf));
}

#if 0

/*-------------------------------------------------------
 * Distribution functions
 *-------------------------------------------------------*/

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

double DoubleDistEmpiricalIntegralInterpolate(
    double x1, double x2, double y1, double y2, double x)
{
    return ceil((y1 + ((y2 - y1) / (x2 - x1)) * (x - x1)));
}


double DoubleDistEmpiricalContinuousInterpolate(
    double x1, double x2, double y1, double y2, double x)
{
    return (y1 + ((y2 - y1) / (x2 - x1)) * (x - x1));
}


int DoubleDistFindIndex(const DoubleDistElement *array,
                                        const Int32 count, double value)
{
    int top = count - 1,
        bottom = 0,
        current;

#ifdef DEBUG
    printf(" findindex start value = %f ind0.val = %f\n",
           value, array[0].cdf);
#endif
    if (value < array[0].cdf)
        return -1;

    while (TRUE)
    {
        current = (top + bottom) / 2;
#ifdef DEBUG
        printf("    current = %d top = %d bottom = %d\n", current, top,
               bottom);
        printf("   value = %f cur1 = %f cur2 = %f\n", value,
               array[current].cdf, array[current + 1].cdf);
#endif

        if ((value >= array[current].cdf) &&
            (value < array[current + 1].cdf))
        {
#ifdef DEBUG
            printf("DONE\n");
#endif
            return current;
            break;
        }
        else if (value < array[current].cdf)
        {
            top = current - 1;
        }
        else if (value >= array[current + 1].cdf)
        {
            bottom = current + 1;
        }
        else
            assert(FALSE);
    }
    return -1; // shouldn't reach here, but needs to return a value
}


// HttpConsecutiveDocs.cc generated from HttpConsecutiveDocs.cdf
// on Wed Oct 27 00:28:20 PDT 1999 by gandy

static DoubleDistElement foo[] = {
{  1 ,  0.355731225296  }
, {  2 ,  0.549407114625  }
, {  3 ,  0.664031620553  }
, {  4 ,  0.747035573123  }
, {  5 ,  0.790513833992  }
, {  6 ,  0.814229249012  }
, {  7 ,  0.841897233202  }
, {  8 ,  0.881422924901  }
, {  9 ,  0.893280632411  }
, {  10 ,  0.901185770751  }
, {  11 ,  0.905138339921  }
, {  12 ,  0.909090909091  }
, {  13 ,  0.928853754941  }
, {  14 ,  0.944664031621  }
, {  15 ,  0.95652173913  }
, {  16 ,  0.96442687747  }
, {  17 ,  0.96837944664  }
, {  18 ,  0.97628458498  }
, {  19 ,  0.99209486166  }
, {  21 ,  0.99604743083  }
, {  37 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpConsecutiveDocsDistTable = foo;
// HttpFilesPerDocument.cc generated from HttpFilesPerDocument.cdf
// on Wed Oct 27 00:28:21 PDT 1999 by gandy


static DoubleDistElement foo1[] = {
{  1 ,  0.486376811594  }
, {  2 ,  0.691594202899  }
, {  3 ,  0.781449275362  }
, {  4 ,  0.826086956522  }
, {  5 ,  0.875362318841  }
, {  6 ,  0.904347826087  }
, {  7 ,  0.92347826087  }
, {  8 ,  0.939710144928  }
, {  9 ,  0.950724637681  }
, {  10 ,  0.96115942029  }
, {  11 ,  0.966376811594  }
, {  12 ,  0.972173913043  }
, {  13 ,  0.974492753623  }
, {  14 ,  0.977971014493  }
, {  15 ,  0.980289855072  }
, {  16 ,  0.987246376812  }
, {  17 ,  0.987826086957  }
, {  18 ,  0.989565217391  }
, {  19 ,  0.993043478261  }
, {  20 ,  0.995942028986  }
, {  21 ,  0.99652173913  }
, {  32 ,  0.997101449275  }
, {  33 ,  0.99768115942  }
, {  35 ,  0.998260869565  }
, {  37 ,  0.99884057971  }
, {  63 ,  0.999420289855  }
, {  65 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpFilesPerDocumentDistTable = foo1;
// HttpPrimaryReply.cc generated from HttpPrimaryReply.cdf
// on Wed Oct 27 00:28:23 PDT 1999 by gandy


static DoubleDistElement foo2[] = {
{  0 ,  0.00231749710313  }
, {  81 ,  0.0150637311703  }
, {  83 ,  0.0173812282735  }
, {  87 ,  0.0179606025492  }
, {  90 ,  0.018539976825  }
, {  102 ,  0.0220162224797  }
, {  103 ,  0.0295480880649  }
, {  104 ,  0.0428736964079  }
, {  110 ,  0.0440324449594  }
, {  195 ,  0.045191193511  }
, {  196 ,  0.0457705677868  }
, {  203 ,  0.0509849362688  }
, {  204 ,  0.0527230590962  }
, {  207 ,  0.053302433372  }
, {  210 ,  0.0538818076477  }
, {  211 ,  0.0544611819235  }
, {  219 ,  0.0573580533024  }
, {  225 ,  0.0579374275782  }
, {  231 ,  0.058516801854  }
, {  233 ,  0.0590961761298  }
, {  234 ,  0.0602549246813  }
, {  237 ,  0.0608342989571  }
, {  240 ,  0.0619930475087  }
, {  242 ,  0.063731170336  }
, {  244 ,  0.0643105446118  }
, {  246 ,  0.0654692931634  }
, {  247 ,  0.0660486674392  }
, {  249 ,  0.0666280417149  }
, {  250 ,  0.0677867902665  }
, {  252 ,  0.0683661645423  }
, {  253 ,  0.0689455388181  }
, {  254 ,  0.0706836616454  }
, {  258 ,  0.071842410197  }
, {  259 ,  0.0730011587486  }
, {  264 ,  0.0735805330243  }
, {  269 ,  0.0741599073001  }
, {  277 ,  0.0753186558517  }
, {  279 ,  0.0758980301275  }
, {  280 ,  0.077056778679  }
, {  281 ,  0.0776361529548  }
, {  284 ,  0.0787949015064  }
, {  285 ,  0.0793742757822  }
, {  286 ,  0.0811123986095  }
, {  287 ,  0.0828505214368  }
, {  288 ,  0.0834298957126  }
, {  291 ,  0.0840092699884  }
, {  293 ,  0.0845886442642  }
, {  295 ,  0.0857473928158  }
, {  296 ,  0.0874855156431  }
, {  297 ,  0.0886442641947  }
, {  298 ,  0.0892236384705  }
, {  300 ,  0.090382387022  }
, {  301 ,  0.0909617612978  }
, {  304 ,  0.0921205098494  }
, {  306 ,  0.0967555040556  }
, {  307 ,  0.0996523754345  }
, {  308 ,  0.101969872538  }
, {  310 ,  0.115295480881  }
, {  312 ,  0.118771726535  }
, {  314 ,  0.124565469293  }
, {  316 ,  0.130359212051  }
, {  318 ,  0.131517960603  }
, {  320 ,  0.132676709154  }
, {  322 ,  0.134994206257  }
, {  324 ,  0.136152954809  }
, {  326 ,  0.13731170336  }
, {  327 ,  0.137891077636  }
, {  328 ,  0.138470451912  }
, {  329 ,  0.139049826188  }
, {  330 ,  0.139629200463  }
, {  331 ,  0.140208574739  }
, {  332 ,  0.141367323291  }
, {  333 ,  0.143105446118  }
, {  334 ,  0.14426419467  }
, {  335 ,  0.145422943221  }
, {  336 ,  0.151216685979  }
, {  337 ,  0.151796060255  }
, {  338 ,  0.152375434531  }
, {  340 ,  0.152954808806  }
, {  342 ,  0.154113557358  }
, {  343 ,  0.15527230591  }
, {  344 ,  0.157589803013  }
, {  345 ,  0.158169177289  }
, {  350 ,  0.158748551564  }
, {  351 ,  0.15932792584  }
, {  356 ,  0.159907300116  }
, {  362 ,  0.162224797219  }
, {  364 ,  0.163962920046  }
, {  366 ,  0.164542294322  }
, {  368 ,  0.169177288528  }
, {  370 ,  0.171494785632  }
, {  372 ,  0.174971031286  }
, {  376 ,  0.178447276941  }
, {  383 ,  0.179026651217  }
, {  384 ,  0.179606025492  }
, {  385 ,  0.180185399768  }
, {  389 ,  0.181923522596  }
, {  400 ,  0.182502896871  }
, {  404 ,  0.183082271147  }
, {  405 ,  0.184241019699  }
, {  407 ,  0.184820393975  }
, {  409 ,  0.185979142526  }
, {  411 ,  0.186558516802  }
, {  416 ,  0.187137891078  }
, {  417 ,  0.187717265353  }
, {  418 ,  0.188296639629  }
, {  423 ,  0.190614136732  }
, {  428 ,  0.191193511008  }
, {  429 ,  0.191772885284  }
, {  435 ,  0.19235225956  }
, {  437 ,  0.192931633835  }
, {  438 ,  0.193511008111  }
, {  454 ,  0.194090382387  }
, {  455 ,  0.196987253766  }
, {  456 ,  0.199304750869  }
, {  459 ,  0.199884125145  }
, {  460 ,  0.200463499421  }
, {  463 ,  0.204519119351  }
, {  471 ,  0.205677867903  }
, {  472 ,  0.206257242178  }
, {  481 ,  0.207995365006  }
, {  483 ,  0.209154113557  }
, {  487 ,  0.209733487833  }
, {  499 ,  0.210312862109  }
, {  502 ,  0.210892236385  }
, {  507 ,  0.21147161066  }
, {  508 ,  0.213209733488  }
, {  520 ,  0.213789107764  }
, {  525 ,  0.214368482039  }
, {  529 ,  0.215527230591  }
, {  530 ,  0.216106604867  }
, {  531 ,  0.216685979143  }
, {  535 ,  0.217265353418  }
, {  536 ,  0.221900347625  }
, {  551 ,  0.2224797219  }
, {  553 ,  0.223059096176  }
, {  555 ,  0.223638470452  }
, {  560 ,  0.224217844728  }
, {  563 ,  0.225376593279  }
, {  574 ,  0.225955967555  }
, {  580 ,  0.227694090382  }
, {  581 ,  0.228852838934  }
, {  583 ,  0.22943221321  }
, {  584 ,  0.230590961761  }
, {  590 ,  0.231170336037  }
, {  592 ,  0.231749710313  }
, {  593 ,  0.232908458864  }
, {  604 ,  0.23348783314  }
, {  610 ,  0.234067207416  }
, {  615 ,  0.234646581692  }
, {  623 ,  0.235225955968  }
, {  628 ,  0.235805330243  }
, {  633 ,  0.236384704519  }
, {  635 ,  0.236964078795  }
, {  642 ,  0.238122827346  }
, {  643 ,  0.238702201622  }
, {  648 ,  0.239281575898  }
, {  655 ,  0.239860950174  }
, {  666 ,  0.241019698725  }
, {  678 ,  0.241599073001  }
, {  690 ,  0.242178447277  }
, {  692 ,  0.242757821553  }
, {  693 ,  0.243916570104  }
, {  695 ,  0.24449594438  }
, {  696 ,  0.245654692932  }
, {  703 ,  0.246234067207  }
, {  710 ,  0.246813441483  }
, {  712 ,  0.247392815759  }
, {  715 ,  0.247972190035  }
, {  716 ,  0.249130938586  }
, {  717 ,  0.249710312862  }
, {  723 ,  0.250289687138  }
, {  726 ,  0.250869061414  }
, {  731 ,  0.251448435689  }
, {  732 ,  0.253186558517  }
, {  734 ,  0.253765932793  }
, {  737 ,  0.254345307068  }
, {  748 ,  0.25550405562  }
, {  760 ,  0.256083429896  }
, {  761 ,  0.256662804171  }
, {  763 ,  0.257242178447  }
, {  769 ,  0.258400926999  }
, {  770 ,  0.258980301275  }
, {  771 ,  0.25955967555  }
, {  772 ,  0.260139049826  }
, {  773 ,  0.261877172654  }
, {  774 ,  0.262456546929  }
, {  775 ,  0.263615295481  }
, {  776 ,  0.265353418308  }
, {  777 ,  0.265932792584  }
, {  779 ,  0.267091541136  }
, {  781 ,  0.267670915411  }
, {  782 ,  0.268250289687  }
, {  786 ,  0.269409038239  }
, {  795 ,  0.269988412514  }
, {  803 ,  0.27056778679  }
, {  806 ,  0.271726535342  }
, {  807 ,  0.272305909618  }
, {  820 ,  0.272885283893  }
, {  822 ,  0.273464658169  }
, {  826 ,  0.274044032445  }
, {  828 ,  0.274623406721  }
, {  845 ,  0.275202780997  }
, {  851 ,  0.275782155272  }
, {  856 ,  0.276361529548  }
, {  857 ,  0.2775202781  }
, {  875 ,  0.278099652375  }
, {  888 ,  0.278679026651  }
, {  890 ,  0.279258400927  }
, {  893 ,  0.279837775203  }
, {  896 ,  0.280996523754  }
, {  898 ,  0.28157589803  }
, {  902 ,  0.283314020857  }
, {  907 ,  0.283893395133  }
, {  908 ,  0.284472769409  }
, {  912 ,  0.285052143685  }
, {  914 ,  0.286210892236  }
, {  919 ,  0.286790266512  }
, {  923 ,  0.287949015064  }
, {  930 ,  0.28852838934  }
, {  934 ,  0.289107763615  }
, {  935 ,  0.290845886443  }
, {  936 ,  0.294901506373  }
, {  937 ,  0.295480880649  }
, {  938 ,  0.300115874855  }
, {  939 ,  0.300695249131  }
, {  941 ,  0.301274623407  }
, {  949 ,  0.304750869061  }
, {  950 ,  0.305909617613  }
, {  955 ,  0.306488991889  }
, {  957 ,  0.307068366165  }
, {  969 ,  0.30764774044  }
, {  979 ,  0.308227114716  }
, {  988 ,  0.308806488992  }
, {  989 ,  0.311703360371  }
, {  990 ,  0.312862108922  }
, {  991 ,  0.316917728853  }
, {  992 ,  0.31865585168  }
, {  995 ,  0.319814600232  }
, {  1000 ,  0.321552723059  }
, {  1006 ,  0.322132097335  }
, {  1008 ,  0.322711471611  }
, {  1009 ,  0.323290845886  }
, {  1010 ,  0.323870220162  }
, {  1016 ,  0.324449594438  }
, {  1021 ,  0.32560834299  }
, {  1022 ,  0.326767091541  }
, {  1029 ,  0.327925840093  }
, {  1031 ,  0.328505214368  }
, {  1040 ,  0.329084588644  }
, {  1057 ,  0.32966396292  }
, {  1064 ,  0.330243337196  }
, {  1068 ,  0.330822711472  }
, {  1082 ,  0.331402085747  }
, {  1086 ,  0.332560834299  }
, {  1091 ,  0.336616454229  }
, {  1095 ,  0.337195828505  }
, {  1096 ,  0.338354577057  }
, {  1097 ,  0.338933951333  }
, {  1100 ,  0.339513325608  }
, {  1101 ,  0.340092699884  }
, {  1105 ,  0.341251448436  }
, {  1106 ,  0.341830822711  }
, {  1113 ,  0.342410196987  }
, {  1119 ,  0.342989571263  }
, {  1120 ,  0.344148319815  }
, {  1134 ,  0.34472769409  }
, {  1139 ,  0.345307068366  }
, {  1145 ,  0.346465816918  }
, {  1152 ,  0.347045191194  }
, {  1159 ,  0.347624565469  }
, {  1160 ,  0.348203939745  }
, {  1163 ,  0.349942062572  }
, {  1165 ,  0.350521436848  }
, {  1166 ,  0.351100811124  }
, {  1170 ,  0.3516801854  }
, {  1174 ,  0.352259559676  }
, {  1187 ,  0.352838933951  }
, {  1195 ,  0.353418308227  }
, {  1201 ,  0.353997682503  }
, {  1205 ,  0.354577056779  }
, {  1208 ,  0.355156431054  }
, {  1217 ,  0.356315179606  }
, {  1227 ,  0.356894553882  }
, {  1242 ,  0.357473928158  }
, {  1255 ,  0.358053302433  }
, {  1261 ,  0.358632676709  }
, {  1267 ,  0.359212050985  }
, {  1274 ,  0.359791425261  }
, {  1275 ,  0.360950173812  }
, {  1281 ,  0.366164542294  }
, {  1283 ,  0.36674391657  }
, {  1292 ,  0.367323290846  }
, {  1294 ,  0.371958285052  }
, {  1297 ,  0.373696407879  }
, {  1300 ,  0.374275782155  }
, {  1301 ,  0.374855156431  }
, {  1303 ,  0.375434530707  }
, {  1312 ,  0.376593279258  }
, {  1313 ,  0.377172653534  }
, {  1317 ,  0.37775202781  }
, {  1319 ,  0.378331402086  }
, {  1321 ,  0.380069524913  }
, {  1323 ,  0.380648899189  }
, {  1326 ,  0.381228273465  }
, {  1333 ,  0.38180764774  }
, {  1337 ,  0.382966396292  }
, {  1338 ,  0.383545770568  }
, {  1340 ,  0.384125144844  }
, {  1341 ,  0.384704519119  }
, {  1347 ,  0.385283893395  }
, {  1348 ,  0.385863267671  }
, {  1349 ,  0.386442641947  }
, {  1362 ,  0.387022016222  }
, {  1363 ,  0.387601390498  }
, {  1367 ,  0.388180764774  }
, {  1368 ,  0.389918887601  }
, {  1373 ,  0.390498261877  }
, {  1385 ,  0.391077636153  }
, {  1395 ,  0.391657010429  }
, {  1408 ,  0.392236384705  }
, {  1417 ,  0.39281575898  }
, {  1418 ,  0.393395133256  }
, {  1425 ,  0.393974507532  }
, {  1429 ,  0.394553881808  }
, {  1432 ,  0.395133256083  }
, {  1434 ,  0.396292004635  }
, {  1438 ,  0.396871378911  }
, {  1444 ,  0.398030127462  }
, {  1447 ,  0.398609501738  }
, {  1465 ,  0.39976825029  }
, {  1466 ,  0.401506373117  }
, {  1481 ,  0.402085747393  }
, {  1482 ,  0.402665121669  }
, {  1487 ,  0.403244495944  }
, {  1488 ,  0.40382387022  }
, {  1494 ,  0.404403244496  }
, {  1496 ,  0.404982618772  }
, {  1497 ,  0.405561993048  }
, {  1500 ,  0.407300115875  }
, {  1505 ,  0.407879490151  }
, {  1512 ,  0.408458864426  }
, {  1513 ,  0.409617612978  }
, {  1514 ,  0.411355735805  }
, {  1517 ,  0.411935110081  }
, {  1522 ,  0.412514484357  }
, {  1524 ,  0.413093858633  }
, {  1526 ,  0.413673232908  }
, {  1530 ,  0.414252607184  }
, {  1533 ,  0.41483198146  }
, {  1538 ,  0.415411355736  }
, {  1539 ,  0.415990730012  }
, {  1541 ,  0.416570104287  }
, {  1542 ,  0.417728852839  }
, {  1552 ,  0.418308227115  }
, {  1554 ,  0.41888760139  }
, {  1556 ,  0.419466975666  }
, {  1564 ,  0.420046349942  }
, {  1566 ,  0.420625724218  }
, {  1576 ,  0.421205098494  }
, {  1579 ,  0.421784472769  }
, {  1600 ,  0.422363847045  }
, {  1602 ,  0.422943221321  }
, {  1610 ,  0.423522595597  }
, {  1614 ,  0.424101969873  }
, {  1617 ,  0.424681344148  }
, {  1618 ,  0.425260718424  }
, {  1621 ,  0.4258400927  }
, {  1622 ,  0.426419466976  }
, {  1626 ,  0.426998841251  }
, {  1634 ,  0.427578215527  }
, {  1642 ,  0.428157589803  }
, {  1644 ,  0.428736964079  }
, {  1646 ,  0.429316338355  }
, {  1647 ,  0.431633835458  }
, {  1653 ,  0.432213209733  }
, {  1654 ,  0.433951332561  }
, {  1656 ,  0.434530706837  }
, {  1675 ,  0.436268829664  }
, {  1681 ,  0.43684820394  }
, {  1690 ,  0.437427578216  }
, {  1697 ,  0.438006952491  }
, {  1699 ,  0.440324449594  }
, {  1708 ,  0.441483198146  }
, {  1710 ,  0.442062572422  }
, {  1711 ,  0.442641946698  }
, {  1713 ,  0.443800695249  }
, {  1727 ,  0.444380069525  }
, {  1728 ,  0.446697566628  }
, {  1736 ,  0.447276940904  }
, {  1737 ,  0.44785631518  }
, {  1741 ,  0.448435689455  }
, {  1742 ,  0.449015063731  }
, {  1744 ,  0.449594438007  }
, {  1756 ,  0.450173812283  }
, {  1761 ,  0.450753186559  }
, {  1770 ,  0.451332560834  }
, {  1773 ,  0.45191193511  }
, {  1785 ,  0.452491309386  }
, {  1800 ,  0.453070683662  }
, {  1806 ,  0.453650057937  }
, {  1808 ,  0.454229432213  }
, {  1810 ,  0.455388180765  }
, {  1816 ,  0.455967555041  }
, {  1819 ,  0.456546929316  }
, {  1820 ,  0.457126303592  }
, {  1827 ,  0.457705677868  }
, {  1832 ,  0.458864426419  }
, {  1840 ,  0.460023174971  }
, {  1841 ,  0.460602549247  }
, {  1845 ,  0.461181923523  }
, {  1852 ,  0.461761297798  }
, {  1856 ,  0.462340672074  }
, {  1857 ,  0.46292004635  }
, {  1862 ,  0.463499420626  }
, {  1867 ,  0.464078794902  }
, {  1869 ,  0.464658169177  }
, {  1870 ,  0.465237543453  }
, {  1878 ,  0.465816917729  }
, {  1879 ,  0.466396292005  }
, {  1880 ,  0.46697566628  }
, {  1882 ,  0.467555040556  }
, {  1884 ,  0.468134414832  }
, {  1890 ,  0.469872537659  }
, {  1891 ,  0.472190034762  }
, {  1896 ,  0.472769409038  }
, {  1901 ,  0.473348783314  }
, {  1909 ,  0.47392815759  }
, {  1916 ,  0.474507531866  }
, {  1922 ,  0.475666280417  }
, {  1923 ,  0.476245654693  }
, {  1928 ,  0.476825028969  }
, {  1929 ,  0.477404403244  }
, {  1930 ,  0.47798377752  }
, {  1958 ,  0.478563151796  }
, {  1961 ,  0.479142526072  }
, {  1962 ,  0.480301274623  }
, {  1974 ,  0.480880648899  }
, {  1980 ,  0.481460023175  }
, {  1981 ,  0.482039397451  }
, {  1985 ,  0.482618771727  }
, {  1990 ,  0.483777520278  }
, {  1992 ,  0.484356894554  }
, {  1994 ,  0.48493626883  }
, {  1997 ,  0.485515643105  }
, {  2014 ,  0.486674391657  }
, {  2018 ,  0.487253765933  }
, {  2019 ,  0.487833140209  }
, {  2022 ,  0.488412514484  }
, {  2023 ,  0.489571263036  }
, {  2024 ,  0.490150637312  }
, {  2025 ,  0.492468134415  }
, {  2028 ,  0.493047508691  }
, {  2034 ,  0.493626882966  }
, {  2037 ,  0.494206257242  }
, {  2039 ,  0.494785631518  }
, {  2043 ,  0.495365005794  }
, {  2045 ,  0.496523754345  }
, {  2064 ,  0.497103128621  }
, {  2068 ,  0.497682502897  }
, {  2076 ,  0.498261877173  }
, {  2085 ,  0.498841251448  }
, {  2099 ,  0.501158748552  }
, {  2102 ,  0.501738122827  }
, {  2103 ,  0.502317497103  }
, {  2104 ,  0.503476245655  }
, {  2106 ,  0.509269988413  }
, {  2107 ,  0.509849362688  }
, {  2109 ,  0.513325608343  }
, {  2114 ,  0.513904982619  }
, {  2119 ,  0.51506373117  }
, {  2131 ,  0.515643105446  }
, {  2139 ,  0.516222479722  }
, {  2141 ,  0.516801853998  }
, {  2142 ,  0.517381228273  }
, {  2146 ,  0.517960602549  }
, {  2150 ,  0.518539976825  }
, {  2152 ,  0.519698725377  }
, {  2154 ,  0.520857473928  }
, {  2164 ,  0.521436848204  }
, {  2165 ,  0.522595596756  }
, {  2167 ,  0.523174971031  }
, {  2168 ,  0.524913093859  }
, {  2172 ,  0.525492468134  }
, {  2173 ,  0.52607184241  }
, {  2176 ,  0.526651216686  }
, {  2178 ,  0.527809965238  }
, {  2183 ,  0.528389339513  }
, {  2186 ,  0.530127462341  }
, {  2191 ,  0.530706836616  }
, {  2196 ,  0.531865585168  }
, {  2198 ,  0.532444959444  }
, {  2201 ,  0.53302433372  }
, {  2208 ,  0.533603707995  }
, {  2210 ,  0.535341830823  }
, {  2215 ,  0.535921205098  }
, {  2233 ,  0.536500579374  }
, {  2239 ,  0.53707995365  }
, {  2245 ,  0.537659327926  }
, {  2246 ,  0.538238702202  }
, {  2247 ,  0.538818076477  }
, {  2261 ,  0.539397450753  }
, {  2263 ,  0.539976825029  }
, {  2269 ,  0.540556199305  }
, {  2271 ,  0.541135573581  }
, {  2278 ,  0.542294322132  }
, {  2282 ,  0.542873696408  }
, {  2288 ,  0.544611819235  }
, {  2290 ,  0.545191193511  }
, {  2300 ,  0.545770567787  }
, {  2302 ,  0.546349942063  }
, {  2323 ,  0.547508690614  }
, {  2338 ,  0.54808806489  }
, {  2346 ,  0.548667439166  }
, {  2348 ,  0.549246813441  }
, {  2362 ,  0.549826187717  }
, {  2363 ,  0.550984936269  }
, {  2365 ,  0.551564310545  }
, {  2370 ,  0.55214368482  }
, {  2372 ,  0.552723059096  }
, {  2376 ,  0.553302433372  }
, {  2377 ,  0.556199304751  }
, {  2380 ,  0.556778679027  }
, {  2382 ,  0.557358053302  }
, {  2386 ,  0.557937427578  }
, {  2389 ,  0.558516801854  }
, {  2410 ,  0.55909617613  }
, {  2414 ,  0.559675550406  }
, {  2422 ,  0.560254924681  }
, {  2433 ,  0.560834298957  }
, {  2450 ,  0.561993047509  }
, {  2464 ,  0.562572421784  }
, {  2472 ,  0.56315179606  }
, {  2483 ,  0.563731170336  }
, {  2484 ,  0.564310544612  }
, {  2489 ,  0.564889918888  }
, {  2500 ,  0.565469293163  }
, {  2507 ,  0.566048667439  }
, {  2513 ,  0.566628041715  }
, {  2515 ,  0.567207415991  }
, {  2517 ,  0.567786790267  }
, {  2519 ,  0.568366164542  }
, {  2529 ,  0.569524913094  }
, {  2548 ,  0.57010428737  }
, {  2556 ,  0.570683661645  }
, {  2561 ,  0.571263035921  }
, {  2565 ,  0.571842410197  }
, {  2571 ,  0.572421784473  }
, {  2572 ,  0.573001158749  }
, {  2576 ,  0.573580533024  }
, {  2578 ,  0.5741599073  }
, {  2580 ,  0.575318655852  }
, {  2581 ,  0.575898030127  }
, {  2584 ,  0.576477404403  }
, {  2587 ,  0.577056778679  }
, {  2590 ,  0.577636152955  }
, {  2591 ,  0.578794901506  }
, {  2593 ,  0.579374275782  }
, {  2601 ,  0.580533024334  }
, {  2605 ,  0.58111239861  }
, {  2611 ,  0.581691772885  }
, {  2617 ,  0.582271147161  }
, {  2620 ,  0.582850521437  }
, {  2623 ,  0.584009269988  }
, {  2624 ,  0.588644264195  }
, {  2628 ,  0.589803012746  }
, {  2630 ,  0.590382387022  }
, {  2640 ,  0.590961761298  }
, {  2641 ,  0.592120509849  }
, {  2642 ,  0.592699884125  }
, {  2648 ,  0.593279258401  }
, {  2651 ,  0.593858632677  }
, {  2653 ,  0.594438006952  }
, {  2654 ,  0.595017381228  }
, {  2656 ,  0.595596755504  }
, {  2659 ,  0.59617612978  }
, {  2673 ,  0.597334878331  }
, {  2675 ,  0.599073001159  }
, {  2676 ,  0.599652375435  }
, {  2677 ,  0.60023174971  }
, {  2684 ,  0.601390498262  }
, {  2695 ,  0.602549246813  }
, {  2698 ,  0.603128621089  }
, {  2701 ,  0.603707995365  }
, {  2705 ,  0.604287369641  }
, {  2709 ,  0.604866743917  }
, {  2721 ,  0.606604866744  }
, {  2729 ,  0.60718424102  }
, {  2737 ,  0.607763615295  }
, {  2741 ,  0.608342989571  }
, {  2750 ,  0.608922363847  }
, {  2754 ,  0.609501738123  }
, {  2756 ,  0.610660486674  }
, {  2757 ,  0.61123986095  }
, {  2772 ,  0.611819235226  }
, {  2787 ,  0.612398609502  }
, {  2794 ,  0.613557358053  }
, {  2810 ,  0.614136732329  }
, {  2815 ,  0.614716106605  }
, {  2829 ,  0.615295480881  }
, {  2845 ,  0.615874855156  }
, {  2851 ,  0.616454229432  }
, {  2858 ,  0.617612977984  }
, {  2861 ,  0.61819235226  }
, {  2870 ,  0.619351100811  }
, {  2876 ,  0.619930475087  }
, {  2877 ,  0.621089223638  }
, {  2884 ,  0.621668597914  }
, {  2892 ,  0.62224797219  }
, {  2893 ,  0.623406720742  }
, {  2894 ,  0.625724217845  }
, {  2895 ,  0.626303592121  }
, {  2908 ,  0.626882966396  }
, {  2909 ,  0.628041714948  }
, {  2921 ,  0.628621089224  }
, {  2929 ,  0.629779837775  }
, {  2930 ,  0.630938586327  }
, {  2938 ,  0.631517960603  }
, {  2940 ,  0.632097334878  }
, {  2944 ,  0.632676709154  }
, {  2972 ,  0.63325608343  }
, {  2979 ,  0.633835457706  }
, {  3001 ,  0.634414831981  }
, {  3026 ,  0.634994206257  }
, {  3027 ,  0.635573580533  }
, {  3030 ,  0.636152954809  }
, {  3042 ,  0.636732329085  }
, {  3049 ,  0.63731170336  }
, {  3073 ,  0.637891077636  }
, {  3075 ,  0.638470451912  }
, {  3076 ,  0.639049826188  }
, {  3089 ,  0.640208574739  }
, {  3090 ,  0.640787949015  }
, {  3098 ,  0.641367323291  }
, {  3106 ,  0.641946697567  }
, {  3108 ,  0.642526071842  }
, {  3112 ,  0.643105446118  }
, {  3118 ,  0.643684820394  }
, {  3130 ,  0.644843568946  }
, {  3133 ,  0.645422943221  }
, {  3143 ,  0.646002317497  }
, {  3150 ,  0.646581691773  }
, {  3168 ,  0.647161066049  }
, {  3178 ,  0.647740440324  }
, {  3184 ,  0.6483198146  }
, {  3185 ,  0.648899188876  }
, {  3201 ,  0.649478563152  }
, {  3211 ,  0.650057937428  }
, {  3212 ,  0.651216685979  }
, {  3214 ,  0.651796060255  }
, {  3223 ,  0.652375434531  }
, {  3231 ,  0.654113557358  }
, {  3240 ,  0.654692931634  }
, {  3241 ,  0.65527230591  }
, {  3261 ,  0.655851680185  }
, {  3262 ,  0.657010428737  }
, {  3270 ,  0.657589803013  }
, {  3275 ,  0.658169177289  }
, {  3278 ,  0.658748551564  }
, {  3286 ,  0.65932792584  }
, {  3292 ,  0.660486674392  }
, {  3293 ,  0.663962920046  }
, {  3299 ,  0.664542294322  }
, {  3310 ,  0.665121668598  }
, {  3313 ,  0.666280417149  }
, {  3316 ,  0.666859791425  }
, {  3355 ,  0.668018539977  }
, {  3358 ,  0.668597914253  }
, {  3362 ,  0.669177288528  }
, {  3363 ,  0.669756662804  }
, {  3379 ,  0.670915411356  }
, {  3419 ,  0.671494785632  }
, {  3426 ,  0.672074159907  }
, {  3452 ,  0.672653534183  }
, {  3473 ,  0.673232908459  }
, {  3483 ,  0.673812282735  }
, {  3492 ,  0.675550405562  }
, {  3494 ,  0.676129779838  }
, {  3506 ,  0.676709154114  }
, {  3512 ,  0.677288528389  }
, {  3531 ,  0.677867902665  }
, {  3533 ,  0.678447276941  }
, {  3547 ,  0.679026651217  }
, {  3549 ,  0.680185399768  }
, {  3552 ,  0.680764774044  }
, {  3564 ,  0.681923522596  }
, {  3567 ,  0.682502896871  }
, {  3584 ,  0.683082271147  }
, {  3589 ,  0.683661645423  }
, {  3617 ,  0.684241019699  }
, {  3640 ,  0.684820393975  }
, {  3645 ,  0.68539976825  }
, {  3659 ,  0.685979142526  }
, {  3684 ,  0.686558516802  }
, {  3693 ,  0.687137891078  }
, {  3703 ,  0.687717265353  }
, {  3724 ,  0.688876013905  }
, {  3735 ,  0.689455388181  }
, {  3737 ,  0.690034762457  }
, {  3758 ,  0.690614136732  }
, {  3759 ,  0.691193511008  }
, {  3760 ,  0.69235225956  }
, {  3764 ,  0.694090382387  }
, {  3777 ,  0.694669756663  }
, {  3781 ,  0.695249130939  }
, {  3794 ,  0.695828505214  }
, {  3807 ,  0.69640787949  }
, {  3808 ,  0.696987253766  }
, {  3817 ,  0.697566628042  }
, {  3825 ,  0.698725376593  }
, {  3841 ,  0.699304750869  }
, {  3845 ,  0.699884125145  }
, {  3852 ,  0.700463499421  }
, {  3864 ,  0.701042873696  }
, {  3867 ,  0.702780996524  }
, {  3871 ,  0.7033603708  }
, {  3873 ,  0.703939745075  }
, {  3876 ,  0.704519119351  }
, {  3886 ,  0.705098493627  }
, {  3902 ,  0.706257242178  }
, {  3905 ,  0.706836616454  }
, {  3913 ,  0.707995365006  }
, {  3915 ,  0.710312862109  }
, {  3923 ,  0.710892236385  }
, {  3931 ,  0.71147161066  }
, {  3933 ,  0.712050984936  }
, {  3935 ,  0.712630359212  }
, {  3939 ,  0.713209733488  }
, {  3941 ,  0.713789107764  }
, {  3947 ,  0.714368482039  }
, {  3953 ,  0.715527230591  }
, {  3992 ,  0.716106604867  }
, {  3999 ,  0.719003476246  }
, {  4002 ,  0.719582850521  }
, {  4004 ,  0.720162224797  }
, {  4020 ,  0.720741599073  }
, {  4032 ,  0.721320973349  }
, {  4050 ,  0.721900347625  }
, {  4067 ,  0.7224797219  }
, {  4068 ,  0.723059096176  }
, {  4073 ,  0.723638470452  }
, {  4086 ,  0.724217844728  }
, {  4089 ,  0.725376593279  }
, {  4099 ,  0.726535341831  }
, {  4111 ,  0.727114716107  }
, {  4117 ,  0.727694090382  }
, {  4132 ,  0.728273464658  }
, {  4135 ,  0.728852838934  }
, {  4138 ,  0.72943221321  }
, {  4142 ,  0.730011587486  }
, {  4146 ,  0.730590961761  }
, {  4171 ,  0.731749710313  }
, {  4172 ,  0.732329084589  }
, {  4178 ,  0.732908458864  }
, {  4182 ,  0.73348783314  }
, {  4207 ,  0.734067207416  }
, {  4211 ,  0.734646581692  }
, {  4212 ,  0.735225955968  }
, {  4226 ,  0.736384704519  }
, {  4239 ,  0.736964078795  }
, {  4257 ,  0.737543453071  }
, {  4262 ,  0.738122827346  }
, {  4267 ,  0.739281575898  }
, {  4274 ,  0.739860950174  }
, {  4282 ,  0.74044032445  }
, {  4294 ,  0.741019698725  }
, {  4300 ,  0.741599073001  }
, {  4305 ,  0.742757821553  }
, {  4309 ,  0.743337195829  }
, {  4316 ,  0.743916570104  }
, {  4317 ,  0.74449594438  }
, {  4328 ,  0.745075318656  }
, {  4336 ,  0.745654692932  }
, {  4344 ,  0.746234067207  }
, {  4367 ,  0.747392815759  }
, {  4383 ,  0.747972190035  }
, {  4388 ,  0.748551564311  }
, {  4420 ,  0.749130938586  }
, {  4445 ,  0.749710312862  }
, {  4461 ,  0.750289687138  }
, {  4484 ,  0.751448435689  }
, {  4500 ,  0.752027809965  }
, {  4521 ,  0.752607184241  }
, {  4550 ,  0.753765932793  }
, {  4554 ,  0.754345307068  }
, {  4565 ,  0.754924681344  }
, {  4582 ,  0.757242178447  }
, {  4590 ,  0.758400926999  }
, {  4613 ,  0.758980301275  }
, {  4647 ,  0.75955967555  }
, {  4667 ,  0.760139049826  }
, {  4683 ,  0.760718424102  }
, {  4686 ,  0.761297798378  }
, {  4687 ,  0.761877172654  }
, {  4688 ,  0.762456546929  }
, {  4700 ,  0.763035921205  }
, {  4750 ,  0.763615295481  }
, {  4803 ,  0.764194669757  }
, {  4817 ,  0.765353418308  }
, {  4832 ,  0.765932792584  }
, {  4840 ,  0.76651216686  }
, {  4850 ,  0.767091541136  }
, {  4873 ,  0.767670915411  }
, {  4889 ,  0.768250289687  }
, {  4910 ,  0.768829663963  }
, {  4921 ,  0.769409038239  }
, {  4925 ,  0.769988412514  }
, {  4942 ,  0.77056778679  }
, {  4947 ,  0.771147161066  }
, {  4961 ,  0.771726535342  }
, {  4985 ,  0.772885283893  }
, {  4987 ,  0.773464658169  }
, {  4999 ,  0.774044032445  }
, {  5001 ,  0.774623406721  }
, {  5007 ,  0.775202780997  }
, {  5013 ,  0.775782155272  }
, {  5090 ,  0.776361529548  }
, {  5095 ,  0.776940903824  }
, {  5103 ,  0.7775202781  }
, {  5117 ,  0.778099652375  }
, {  5147 ,  0.778679026651  }
, {  5149 ,  0.779258400927  }
, {  5159 ,  0.780417149479  }
, {  5179 ,  0.780996523754  }
, {  5181 ,  0.782734646582  }
, {  5195 ,  0.783314020857  }
, {  5199 ,  0.784472769409  }
, {  5203 ,  0.785052143685  }
, {  5210 ,  0.785631517961  }
, {  5212 ,  0.786210892236  }
, {  5234 ,  0.786790266512  }
, {  5257 ,  0.787369640788  }
, {  5348 ,  0.787949015064  }
, {  5403 ,  0.78852838934  }
, {  5413 ,  0.789687137891  }
, {  5430 ,  0.790266512167  }
, {  5449 ,  0.791425260718  }
, {  5458 ,  0.792004634994  }
, {  5468 ,  0.79258400927  }
, {  5471 ,  0.793742757822  }
, {  5473 ,  0.796060254925  }
, {  5482 ,  0.7966396292  }
, {  5494 ,  0.797798377752  }
, {  5495 ,  0.798957126304  }
, {  5496 ,  0.800115874855  }
, {  5498 ,  0.801274623407  }
, {  5516 ,  0.801853997683  }
, {  5529 ,  0.802433371958  }
, {  5535 ,  0.80359212051  }
, {  5585 ,  0.804171494786  }
, {  5610 ,  0.804750869061  }
, {  5611 ,  0.805330243337  }
, {  5636 ,  0.80764774044  }
, {  5648 ,  0.808806488992  }
, {  5656 ,  0.809385863268  }
, {  5674 ,  0.809965237543  }
, {  5690 ,  0.810544611819  }
, {  5700 ,  0.811123986095  }
, {  5714 ,  0.811703360371  }
, {  5732 ,  0.812282734647  }
, {  5737 ,  0.813441483198  }
, {  5819 ,  0.814020857474  }
, {  5838 ,  0.81460023175  }
, {  5840 ,  0.815179606025  }
, {  5874 ,  0.815758980301  }
, {  5909 ,  0.816338354577  }
, {  5926 ,  0.816917728853  }
, {  5939 ,  0.81865585168  }
, {  5942 ,  0.819235225956  }
, {  5946 ,  0.819814600232  }
, {  5950 ,  0.820393974508  }
, {  5960 ,  0.820973348783  }
, {  5967 ,  0.823870220162  }
, {  5977 ,  0.824449594438  }
, {  6014 ,  0.825028968714  }
, {  6026 ,  0.82560834299  }
, {  6031 ,  0.826187717265  }
, {  6036 ,  0.826767091541  }
, {  6042 ,  0.827346465817  }
, {  6045 ,  0.829084588644  }
, {  6071 ,  0.82966396292  }
, {  6119 ,  0.830243337196  }
, {  6160 ,  0.830822711472  }
, {  6183 ,  0.831402085747  }
, {  6294 ,  0.831981460023  }
, {  6321 ,  0.832560834299  }
, {  6352 ,  0.833719582851  }
, {  6380 ,  0.834298957126  }
, {  6399 ,  0.834878331402  }
, {  6430 ,  0.835457705678  }
, {  6460 ,  0.836037079954  }
, {  6496 ,  0.836616454229  }
, {  6497 ,  0.837195828505  }
, {  6508 ,  0.837775202781  }
, {  6513 ,  0.838354577057  }
, {  6528 ,  0.838933951333  }
, {  6562 ,  0.839513325608  }
, {  6577 ,  0.840092699884  }
, {  6609 ,  0.84067207416  }
, {  6627 ,  0.841251448436  }
, {  6705 ,  0.841830822711  }
, {  6712 ,  0.842410196987  }
, {  6725 ,  0.842989571263  }
, {  6742 ,  0.845307068366  }
, {  6751 ,  0.845886442642  }
, {  6768 ,  0.846465816918  }
, {  6781 ,  0.847045191194  }
, {  6801 ,  0.847624565469  }
, {  6804 ,  0.848203939745  }
, {  6839 ,  0.848783314021  }
, {  6855 ,  0.849362688297  }
, {  6865 ,  0.849942062572  }
, {  6876 ,  0.850521436848  }
, {  6882 ,  0.851100811124  }
, {  6926 ,  0.8516801854  }
, {  7009 ,  0.852259559676  }
, {  7167 ,  0.852838933951  }
, {  7198 ,  0.853418308227  }
, {  7236 ,  0.853997682503  }
, {  7276 ,  0.854577056779  }
, {  7284 ,  0.855156431054  }
, {  7309 ,  0.85573580533  }
, {  7356 ,  0.856315179606  }
, {  7363 ,  0.856894553882  }
, {  7397 ,  0.857473928158  }
, {  7555 ,  0.858053302433  }
, {  7590 ,  0.858632676709  }
, {  7603 ,  0.859212050985  }
, {  7625 ,  0.860370799537  }
, {  7630 ,  0.860950173812  }
, {  7771 ,  0.861529548088  }
, {  7841 ,  0.862108922364  }
, {  7864 ,  0.86268829664  }
, {  7934 ,  0.863267670915  }
, {  7950 ,  0.864426419467  }
, {  7956 ,  0.865005793743  }
, {  7988 ,  0.865585168019  }
, {  7996 ,  0.866164542294  }
, {  8005 ,  0.86674391657  }
, {  8034 ,  0.867323290846  }
, {  8040 ,  0.867902665122  }
, {  8102 ,  0.868482039397  }
, {  8235 ,  0.869061413673  }
, {  8237 ,  0.869640787949  }
, {  8238 ,  0.870220162225  }
, {  8312 ,  0.872537659328  }
, {  8317 ,  0.873117033604  }
, {  8326 ,  0.873696407879  }
, {  8345 ,  0.874275782155  }
, {  8369 ,  0.874855156431  }
, {  8431 ,  0.875434530707  }
, {  8516 ,  0.876013904983  }
, {  8524 ,  0.876593279258  }
, {  8666 ,  0.877172653534  }
, {  8759 ,  0.87775202781  }
, {  8775 ,  0.878331402086  }
, {  8829 ,  0.879490150637  }
, {  8885 ,  0.880069524913  }
, {  8940 ,  0.880648899189  }
, {  9069 ,  0.881228273465  }
, {  9098 ,  0.88180764774  }
, {  9103 ,  0.882387022016  }
, {  9208 ,  0.882966396292  }
, {  9235 ,  0.883545770568  }
, {  9303 ,  0.884125144844  }
, {  9437 ,  0.884704519119  }
, {  9758 ,  0.886442641947  }
, {  9809 ,  0.887022016222  }
, {  9897 ,  0.887601390498  }
, {  9992 ,  0.888180764774  }
, {  10052 ,  0.88876013905  }
, {  10129 ,  0.889339513326  }
, {  10276 ,  0.889918887601  }
, {  10354 ,  0.890498261877  }
, {  10494 ,  0.891077636153  }
, {  10514 ,  0.891657010429  }
, {  10575 ,  0.892236384705  }
, {  10579 ,  0.89281575898  }
, {  10614 ,  0.893395133256  }
, {  10638 ,  0.893974507532  }
, {  10657 ,  0.894553881808  }
, {  10677 ,  0.895133256083  }
, {  10797 ,  0.895712630359  }
, {  10817 ,  0.896292004635  }
, {  10926 ,  0.896871378911  }
, {  11013 ,  0.897450753187  }
, {  11084 ,  0.898030127462  }
, {  11224 ,  0.898609501738  }
, {  11303 ,  0.899188876014  }
, {  11357 ,  0.89976825029  }
, {  11606 ,  0.900347624565  }
, {  11629 ,  0.900926998841  }
, {  11672 ,  0.901506373117  }
, {  11756 ,  0.902085747393  }
, {  11870 ,  0.902665121669  }
, {  12023 ,  0.903244495944  }
, {  12083 ,  0.90382387022  }
, {  12140 ,  0.904403244496  }
, {  12166 ,  0.904982618772  }
, {  12300 ,  0.906720741599  }
, {  12464 ,  0.907300115875  }
, {  12641 ,  0.908458864426  }
, {  13484 ,  0.909038238702  }
, {  13686 ,  0.910196987254  }
, {  13749 ,  0.91077636153  }
, {  13926 ,  0.911355735805  }
, {  13968 ,  0.911935110081  }
, {  14025 ,  0.912514484357  }
, {  14047 ,  0.913093858633  }
, {  14298 ,  0.913673232908  }
, {  14615 ,  0.914252607184  }
, {  14739 ,  0.91483198146  }
, {  14773 ,  0.917149478563  }
, {  14798 ,  0.917728852839  }
, {  14996 ,  0.918308227115  }
, {  15109 ,  0.91888760139  }
, {  15133 ,  0.919466975666  }
, {  15287 ,  0.920046349942  }
, {  15407 ,  0.920625724218  }
, {  15859 ,  0.921205098494  }
, {  15866 ,  0.921784472769  }
, {  15878 ,  0.922363847045  }
, {  16091 ,  0.922943221321  }
, {  16184 ,  0.923522595597  }
, {  16420 ,  0.924101969873  }
, {  16658 ,  0.924681344148  }
, {  17020 ,  0.925260718424  }
, {  17073 ,  0.926419466976  }
, {  17126 ,  0.926998841251  }
, {  17173 ,  0.927578215527  }
, {  17359 ,  0.928157589803  }
, {  17491 ,  0.928736964079  }
, {  17887 ,  0.929316338355  }
, {  18133 ,  0.92989571263  }
, {  18219 ,  0.930475086906  }
, {  18300 ,  0.931054461182  }
, {  18357 ,  0.931633835458  }
, {  18407 ,  0.932213209733  }
, {  18522 ,  0.932792584009  }
, {  18526 ,  0.933371958285  }
, {  18560 ,  0.933951332561  }
, {  18815 ,  0.934530706837  }
, {  18843 ,  0.935110081112  }
, {  18886 ,  0.935689455388  }
, {  19228 ,  0.936268829664  }
, {  19250 ,  0.93684820394  }
, {  19412 ,  0.938586326767  }
, {  19439 ,  0.939165701043  }
, {  20734 ,  0.939745075319  }
, {  20834 ,  0.940324449594  }
, {  20944 ,  0.94090382387  }
, {  21465 ,  0.941483198146  }
, {  21491 ,  0.942062572422  }
, {  22118 ,  0.942641946698  }
, {  22299 ,  0.944380069525  }
, {  22452 ,  0.944959443801  }
, {  22590 ,  0.945538818076  }
, {  22830 ,  0.946118192352  }
, {  23336 ,  0.946697566628  }
, {  23419 ,  0.947276940904  }
, {  23490 ,  0.94785631518  }
, {  24298 ,  0.948435689455  }
, {  26236 ,  0.949015063731  }
, {  26241 ,  0.950753186559  }
, {  26514 ,  0.951332560834  }
, {  26560 ,  0.952491309386  }
, {  28023 ,  0.953650057937  }
, {  28278 ,  0.954229432213  }
, {  28898 ,  0.954808806489  }
, {  29181 ,  0.955388180765  }
, {  29274 ,  0.955967555041  }
, {  29747 ,  0.956546929316  }
, {  30782 ,  0.957126303592  }
, {  30912 ,  0.957705677868  }
, {  35145 ,  0.958285052144  }
, {  35398 ,  0.958864426419  }
, {  37670 ,  0.959443800695  }
, {  39884 ,  0.960023174971  }
, {  41259 ,  0.960602549247  }
, {  43618 ,  0.961181923523  }
, {  45708 ,  0.961761297798  }
, {  45832 ,  0.962340672074  }
, {  45927 ,  0.964078794902  }
, {  49150 ,  0.964658169177  }
, {  49449 ,  0.965237543453  }
, {  51116 ,  0.965816917729  }
, {  51243 ,  0.966396292005  }
, {  51524 ,  0.96697566628  }
, {  51525 ,  0.967555040556  }
, {  53528 ,  0.968134414832  }
, {  53998 ,  0.968713789108  }
, {  54700 ,  0.969293163384  }
, {  54938 ,  0.970451911935  }
, {  55524 ,  0.971031286211  }
, {  59584 ,  0.971610660487  }
, {  61125 ,  0.972190034762  }
, {  66649 ,  0.972769409038  }
, {  66655 ,  0.973348783314  }
, {  71745 ,  0.97392815759  }
, {  76072 ,  0.974507531866  }
, {  76660 ,  0.975086906141  }
, {  77511 ,  0.975666280417  }
, {  77911 ,  0.976825028969  }
, {  79066 ,  0.977404403244  }
, {  80483 ,  0.97798377752  }
, {  83892 ,  0.978563151796  }
, {  84109 ,  0.979142526072  }
, {  84538 ,  0.979721900348  }
, {  85056 ,  0.980301274623  }
, {  95418 ,  0.981460023175  }
, {  98052 ,  0.982039397451  }
, {  111933 ,  0.982618771727  }
, {  116565 ,  0.983198146002  }
, {  118302 ,  0.984356894554  }
, {  123329 ,  0.98493626883  }
, {  125181 ,  0.985515643105  }
, {  153390 ,  0.986095017381  }
, {  168339 ,  0.986674391657  }
, {  197751 ,  0.988412514484  }
, {  197937 ,  0.98899188876  }
, {  237233 ,  0.989571263036  }
, {  286568 ,  0.990150637312  }
, {  290407 ,  0.990730011587  }
, {  310138 ,  0.991309385863  }
, {  322757 ,  0.991888760139  }
, {  522195 ,  0.992468134415  }
, {  544413 ,  0.993626882966  }
, {  649354 ,  0.99594438007  }
, {  694578 ,  0.996523754345  }
, {  1047903 ,  0.998261877173  }
, {  1634956 ,  0.998841251448  }
, {  1636039 ,  0.999420625724  }
, {  8146976 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpPrimaryReplyDistTable = foo2;
// HttpPrimaryRequest.cc generated from HttpPrimaryRequest.cdf
// on Wed Oct 27 00:28:25 PDT 1999 by gandy


static DoubleDistElement foo3[] = {
{  0 ,  0.00115874855156  }
, {  40 ,  0.00231749710313  }
, {  100 ,  0.00347624565469  }
, {  105 ,  0.00405561993048  }
, {  108 ,  0.00463499420626  }
, {  114 ,  0.00521436848204  }
, {  115 ,  0.00695249130939  }
, {  116 ,  0.00753186558517  }
, {  117 ,  0.00811123986095  }
, {  118 ,  0.0104287369641  }
, {  119 ,  0.0110081112399  }
, {  120 ,  0.0173812282735  }
, {  121 ,  0.0179606025492  }
, {  122 ,  0.018539976825  }
, {  126 ,  0.0196987253766  }
, {  128 ,  0.0220162224797  }
, {  130 ,  0.0254924681344  }
, {  131 ,  0.0260718424102  }
, {  132 ,  0.026651216686  }
, {  135 ,  0.0283893395133  }
, {  140 ,  0.031865585168  }
, {  142 ,  0.0330243337196  }
, {  143 ,  0.0336037079954  }
, {  148 ,  0.0388180764774  }
, {  150 ,  0.0405561993048  }
, {  152 ,  0.0422943221321  }
, {  153 ,  0.0434530706837  }
, {  155 ,  0.0538818076477  }
, {  156 ,  0.0556199304751  }
, {  157 ,  0.0614136732329  }
, {  158 ,  0.0625724217845  }
, {  159 ,  0.063731170336  }
, {  160 ,  0.0648899188876  }
, {  161 ,  0.0695249130939  }
, {  162 ,  0.0730011587486  }
, {  163 ,  0.0782155272306  }
, {  164 ,  0.0811123986095  }
, {  165 ,  0.0840092699884  }
, {  166 ,  0.0886442641947  }
, {  167 ,  0.0909617612978  }
, {  168 ,  0.0921205098494  }
, {  169 ,  0.0938586326767  }
, {  170 ,  0.0950173812283  }
, {  171 ,  0.0961761297798  }
, {  172 ,  0.0973348783314  }
, {  173 ,  0.0979142526072  }
, {  174 ,  0.0990730011587  }
, {  175 ,  0.101969872538  }
, {  176 ,  0.102549246813  }
, {  177 ,  0.104866743917  }
, {  178 ,  0.106604866744  }
, {  179 ,  0.108922363847  }
, {  180 ,  0.109501738123  }
, {  181 ,  0.111819235226  }
, {  183 ,  0.112977983778  }
, {  185 ,  0.115874855156  }
, {  188 ,  0.117033603708  }
, {  189 ,  0.117612977984  }
, {  190 ,  0.120509849363  }
, {  191 ,  0.123986095017  }
, {  192 ,  0.125144843569  }
, {  193 ,  0.128621089224  }
, {  194 ,  0.130938586327  }
, {  195 ,  0.135573580533  }
, {  196 ,  0.136732329085  }
, {  197 ,  0.139629200463  }
, {  198 ,  0.140787949015  }
, {  199 ,  0.147161066049  }
, {  200 ,  0.154113557358  }
, {  201 ,  0.15932792584  }
, {  202 ,  0.168018539977  }
, {  203 ,  0.172074159907  }
, {  204 ,  0.176129779838  }
, {  205 ,  0.184820393975  }
, {  206 ,  0.19640787949  }
, {  207 ,  0.2033603708  }
, {  208 ,  0.215527230591  }
, {  209 ,  0.226535341831  }
, {  210 ,  0.235805330243  }
, {  211 ,  0.245075318656  }
, {  212 ,  0.252607184241  }
, {  213 ,  0.263615295481  }
, {  214 ,  0.269988412514  }
, {  215 ,  0.28157589803  }
, {  216 ,  0.294322132097  }
, {  217 ,  0.300115874855  }
, {  218 ,  0.318076477404  }
, {  219 ,  0.32966396292  }
, {  220 ,  0.340092699884  }
, {  221 ,  0.350521436848  }
, {  222 ,  0.358053302433  }
, {  223 ,  0.371958285052  }
, {  224 ,  0.382966396292  }
, {  225 ,  0.393395133256  }
, {  226 ,  0.403244495944  }
, {  227 ,  0.409617612978  }
, {  228 ,  0.417149478563  }
, {  229 ,  0.42989571263  }
, {  230 ,  0.435110081112  }
, {  231 ,  0.444959443801  }
, {  232 ,  0.449015063731  }
, {  233 ,  0.460023174971  }
, {  234 ,  0.47798377752  }
, {  235 ,  0.485515643105  }
, {  236 ,  0.493047508691  }
, {  237 ,  0.497682502897  }
, {  238 ,  0.502317497103  }
, {  239 ,  0.509269988413  }
, {  240 ,  0.516222479722  }
, {  241 ,  0.527809965238  }
, {  242 ,  0.53302433372  }
, {  243 ,  0.534762456547  }
, {  244 ,  0.541135573581  }
, {  245 ,  0.545191193511  }
, {  246 ,  0.555619930475  }
, {  247 ,  0.55909617613  }
, {  248 ,  0.563731170336  }
, {  249 ,  0.569524913094  }
, {  250 ,  0.572421784473  }
, {  251 ,  0.576477404403  }
, {  252 ,  0.577636152955  }
, {  253 ,  0.579374275782  }
, {  254 ,  0.583429895713  }
, {  255 ,  0.58516801854  }
, {  256 ,  0.58922363847  }
, {  257 ,  0.598493626883  }
, {  258 ,  0.602549246813  }
, {  259 ,  0.615295480881  }
, {  260 ,  0.617612977984  }
, {  261 ,  0.619351100811  }
, {  262 ,  0.62224797219  }
, {  263 ,  0.626882966396  }
, {  264 ,  0.631517960603  }
, {  265 ,  0.636732329085  }
, {  266 ,  0.641367323291  }
, {  267 ,  0.644843568946  }
, {  268 ,  0.648899188876  }
, {  269 ,  0.65527230591  }
, {  270 ,  0.661645422943  }
, {  271 ,  0.666859791425  }
, {  272 ,  0.672653534183  }
, {  273 ,  0.674971031286  }
, {  274 ,  0.676129779838  }
, {  275 ,  0.679606025492  }
, {  276 ,  0.683661645423  }
, {  277 ,  0.687137891078  }
, {  278 ,  0.689455388181  }
, {  279 ,  0.691193511008  }
, {  280 ,  0.69235225956  }
, {  281 ,  0.698146002317  }
, {  282 ,  0.698725376593  }
, {  283 ,  0.702780996524  }
, {  284 ,  0.704519119351  }
, {  285 ,  0.715527230591  }
, {  286 ,  0.716685979143  }
, {  287 ,  0.717844727694  }
, {  288 ,  0.720162224797  }
, {  289 ,  0.730011587486  }
, {  290 ,  0.731749710313  }
, {  291 ,  0.73348783314  }
, {  292 ,  0.738122827346  }
, {  293 ,  0.749710312862  }
, {  294 ,  0.752607184241  }
, {  295 ,  0.754345307068  }
, {  299 ,  0.754924681344  }
, {  300 ,  0.75550405562  }
, {  301 ,  0.756083429896  }
, {  302 ,  0.756662804171  }
, {  303 ,  0.757242178447  }
, {  304 ,  0.75955967555  }
, {  305 ,  0.765353418308  }
, {  306 ,  0.765932792584  }
, {  307 ,  0.775782155272  }
, {  308 ,  0.786210892236  }
, {  309 ,  0.78852838934  }
, {  310 ,  0.789107763615  }
, {  311 ,  0.790845886443  }
, {  312 ,  0.792004634994  }
, {  313 ,  0.79258400927  }
, {  315 ,  0.793742757822  }
, {  316 ,  0.7966396292  }
, {  317 ,  0.797219003476  }
, {  318 ,  0.798957126304  }
, {  319 ,  0.800115874855  }
, {  321 ,  0.802433371958  }
, {  323 ,  0.803012746234  }
, {  325 ,  0.80359212051  }
, {  328 ,  0.804750869061  }
, {  329 ,  0.805330243337  }
, {  332 ,  0.805909617613  }
, {  339 ,  0.806488991889  }
, {  351 ,  0.807068366165  }
, {  364 ,  0.80764774044  }
, {  371 ,  0.808227114716  }
, {  373 ,  0.808806488992  }
, {  380 ,  0.809385863268  }
, {  389 ,  0.809965237543  }
, {  451 ,  0.810544611819  }
, {  496 ,  0.811123986095  }
, {  714 ,  0.811703360371  }
, {  1034 ,  0.813441483198  }
, {  1035 ,  0.819235225956  }
, {  1036 ,  0.820973348783  }
, {  1041 ,  0.827346465817  }
, {  1045 ,  0.827925840093  }
, {  1047 ,  0.828505214368  }
, {  1048 ,  0.834878331402  }
, {  1049 ,  0.836037079954  }
, {  1051 ,  0.837195828505  }
, {  1052 ,  0.837775202781  }
, {  1053 ,  0.838354577057  }
, {  1056 ,  0.840092699884  }
, {  1057 ,  0.84067207416  }
, {  1058 ,  0.841830822711  }
, {  1061 ,  0.842410196987  }
, {  1062 ,  0.846465816918  }
, {  1066 ,  0.847045191194  }
, {  1068 ,  0.847624565469  }
, {  1072 ,  0.848783314021  }
, {  1073 ,  0.849362688297  }
, {  1074 ,  0.850521436848  }
, {  1080 ,  0.851100811124  }
, {  1081 ,  0.8516801854  }
, {  1084 ,  0.852259559676  }
, {  1086 ,  0.852838933951  }
, {  1087 ,  0.853997682503  }
, {  1088 ,  0.85573580533  }
, {  1089 ,  0.857473928158  }
, {  1091 ,  0.858632676709  }
, {  1092 ,  0.859212050985  }
, {  1093 ,  0.860370799537  }
, {  1094 ,  0.863847045191  }
, {  1095 ,  0.864426419467  }
, {  1096 ,  0.865585168019  }
, {  1097 ,  0.867323290846  }
, {  1098 ,  0.868482039397  }
, {  1099 ,  0.870799536501  }
, {  1100 ,  0.873117033604  }
, {  1101 ,  0.875434530707  }
, {  1102 ,  0.876593279258  }
, {  1103 ,  0.879490150637  }
, {  1104 ,  0.882387022016  }
, {  1105 ,  0.884125144844  }
, {  1107 ,  0.884704519119  }
, {  1108 ,  0.887022016222  }
, {  1109 ,  0.888180764774  }
, {  1110 ,  0.889918887601  }
, {  1111 ,  0.891657010429  }
, {  1112 ,  0.894553881808  }
, {  1113 ,  0.897450753187  }
, {  1114 ,  0.906720741599  }
, {  1115 ,  0.907879490151  }
, {  1118 ,  0.909617612978  }
, {  1120 ,  0.912514484357  }
, {  1121 ,  0.917149478563  }
, {  1122 ,  0.91888760139  }
, {  1123 ,  0.921205098494  }
, {  1124 ,  0.927578215527  }
, {  1125 ,  0.92989571263  }
, {  1126 ,  0.931633835458  }
, {  1127 ,  0.932792584009  }
, {  1128 ,  0.933371958285  }
, {  1129 ,  0.934530706837  }
, {  1130 ,  0.935110081112  }
, {  1131 ,  0.940324449594  }
, {  1132 ,  0.944380069525  }
, {  1133 ,  0.951332560834  }
, {  1134 ,  0.957126303592  }
, {  1135 ,  0.958285052144  }
, {  1136 ,  0.960602549247  }
, {  1137 ,  0.961181923523  }
, {  1138 ,  0.962340672074  }
, {  1139 ,  0.96292004635  }
, {  1140 ,  0.963499420626  }
, {  1141 ,  0.966396292005  }
, {  1142 ,  0.968713789108  }
, {  1143 ,  0.969872537659  }
, {  1144 ,  0.973348783314  }
, {  1145 ,  0.976825028969  }
, {  1146 ,  0.97798377752  }
, {  1147 ,  0.981460023175  }
, {  1148 ,  0.983198146002  }
, {  1149 ,  0.98493626883  }
, {  1150 ,  0.986095017381  }
, {  1152 ,  0.986674391657  }
, {  1153 ,  0.987833140209  }
, {  1154 ,  0.988412514484  }
, {  1155 ,  0.98899188876  }
, {  1157 ,  0.989571263036  }
, {  1158 ,  0.990150637312  }
, {  1168 ,  0.990730011587  }
, {  1169 ,  0.991309385863  }
, {  1171 ,  0.991888760139  }
, {  1173 ,  0.992468134415  }
, {  1175 ,  0.993047508691  }
, {  1180 ,  0.993626882966  }
, {  1182 ,  0.994206257242  }
, {  1190 ,  0.994785631518  }
, {  1204 ,  0.99594438007  }
, {  1244 ,  0.996523754345  }
, {  1263 ,  0.997103128621  }
, {  1271 ,  0.998261877173  }
, {  1280 ,  0.998841251448  }
, {  1288 ,  0.999420625724  }
, {  1825 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpPrimaryRequestDistTable = foo3;
// HttpSecondaryReply.cc generated from HttpSecondaryReply.cdf
// on Wed Oct 27 00:28:27 PDT 1999 by gandy


static DoubleDistElement foo4[] = {
{  0 ,  0.00242130750605  }
, {  62 ,  0.00272397094431  }
, {  81 ,  0.0387409200969  }
, {  83 ,  0.057808716707  }
, {  90 ,  0.0611380145278  }
, {  102 ,  0.0653753026634  }
, {  103 ,  0.105024213075  }
, {  104 ,  0.146186440678  }
, {  109 ,  0.149818401937  }
, {  110 ,  0.155266343826  }
, {  113 ,  0.156779661017  }
, {  125 ,  0.157384987893  }
, {  181 ,  0.157687651332  }
, {  196 ,  0.15799031477  }
, {  199 ,  0.158595641646  }
, {  202 ,  0.158898305085  }
, {  203 ,  0.159200968523  }
, {  204 ,  0.160108958838  }
, {  210 ,  0.162227602906  }
, {  215 ,  0.162832929782  }
, {  218 ,  0.16313559322  }
, {  219 ,  0.164346246973  }
, {  223 ,  0.164648910412  }
, {  228 ,  0.166464891041  }
, {  234 ,  0.174334140436  }
, {  238 ,  0.175544794189  }
, {  240 ,  0.176150121065  }
, {  246 ,  0.176452784504  }
, {  252 ,  0.17705811138  }
, {  253 ,  0.177663438257  }
, {  254 ,  0.17887409201  }
, {  255 ,  0.179176755448  }
, {  256 ,  0.179479418886  }
, {  259 ,  0.180387409201  }
, {  260 ,  0.180992736077  }
, {  264 ,  0.181900726392  }
, {  265 ,  0.18401937046  }
, {  266 ,  0.18583535109  }
, {  267 ,  0.186138014528  }
, {  268 ,  0.186440677966  }
, {  273 ,  0.187046004843  }
, {  274 ,  0.188256658596  }
, {  275 ,  0.190072639225  }
, {  276 ,  0.190677966102  }
, {  277 ,  0.192191283293  }
, {  280 ,  0.192493946731  }
, {  283 ,  0.192796610169  }
, {  284 ,  0.194007263923  }
, {  286 ,  0.194309927361  }
, {  287 ,  0.194612590799  }
, {  289 ,  0.194915254237  }
, {  290 ,  0.195520581114  }
, {  292 ,  0.197033898305  }
, {  293 ,  0.197336561743  }
, {  294 ,  0.197639225182  }
, {  297 ,  0.19794188862  }
, {  298 ,  0.198244552058  }
, {  299 ,  0.198849878935  }
, {  300 ,  0.199152542373  }
, {  302 ,  0.199455205811  }
, {  303 ,  0.200060532688  }
, {  308 ,  0.201876513317  }
, {  309 ,  0.202179176755  }
, {  311 ,  0.202481840194  }
, {  312 ,  0.202784503632  }
, {  313 ,  0.20308716707  }
, {  315 ,  0.203389830508  }
, {  317 ,  0.203692493947  }
, {  322 ,  0.205205811138  }
, {  323 ,  0.205508474576  }
, {  324 ,  0.206416464891  }
, {  325 ,  0.207324455206  }
, {  326 ,  0.207929782082  }
, {  328 ,  0.210653753027  }
, {  329 ,  0.210956416465  }
, {  331 ,  0.211259079903  }
, {  332 ,  0.211561743341  }
, {  333 ,  0.212469733656  }
, {  334 ,  0.214285714286  }
, {  335 ,  0.216404358354  }
, {  337 ,  0.216707021792  }
, {  338 ,  0.21700968523  }
, {  341 ,  0.217615012107  }
, {  343 ,  0.217917675545  }
, {  344 ,  0.218523002421  }
, {  345 ,  0.21882566586  }
, {  346 ,  0.219733656174  }
, {  347 ,  0.220338983051  }
, {  348 ,  0.220641646489  }
, {  349 ,  0.220944309927  }
, {  350 ,  0.221246973366  }
, {  351 ,  0.221549636804  }
, {  352 ,  0.221852300242  }
, {  353 ,  0.222457627119  }
, {  354 ,  0.223365617433  }
, {  355 ,  0.223668280872  }
, {  356 ,  0.22397094431  }
, {  358 ,  0.224273607748  }
, {  364 ,  0.224576271186  }
, {  367 ,  0.225786924939  }
, {  368 ,  0.226694915254  }
, {  370 ,  0.226997578692  }
, {  373 ,  0.228208232446  }
, {  376 ,  0.22911622276  }
, {  381 ,  0.229418886199  }
, {  383 ,  0.230326876513  }
, {  385 ,  0.23093220339  }
, {  386 ,  0.231234866828  }
, {  387 ,  0.231840193705  }
, {  389 ,  0.232142857143  }
, {  390 ,  0.232748184019  }
, {  391 ,  0.233050847458  }
, {  392 ,  0.233353510896  }
, {  395 ,  0.234261501211  }
, {  397 ,  0.234564164649  }
, {  398 ,  0.235169491525  }
, {  399 ,  0.235472154964  }
, {  400 ,  0.236985472155  }
, {  401 ,  0.237288135593  }
, {  402 ,  0.23789346247  }
, {  403 ,  0.238498789346  }
, {  406 ,  0.239104116223  }
, {  407 ,  0.239709443099  }
, {  408 ,  0.240314769976  }
, {  409 ,  0.241525423729  }
, {  410 ,  0.242130750605  }
, {  411 ,  0.24303874092  }
, {  412 ,  0.244249394673  }
, {  413 ,  0.244552058111  }
, {  414 ,  0.245460048426  }
, {  415 ,  0.246065375303  }
, {  416 ,  0.246670702179  }
, {  419 ,  0.247578692494  }
, {  420 ,  0.249394673123  }
, {  421 ,  0.249697336562  }
, {  422 ,  0.250302663438  }
, {  424 ,  0.250605326877  }
, {  425 ,  0.250907990315  }
, {  426 ,  0.251210653753  }
, {  427 ,  0.252118644068  }
, {  428 ,  0.253631961259  }
, {  431 ,  0.253934624697  }
, {  432 ,  0.254539951574  }
, {  434 ,  0.255447941889  }
, {  435 ,  0.255750605327  }
, {  436 ,  0.256053268765  }
, {  438 ,  0.256355932203  }
, {  439 ,  0.25696125908  }
, {  440 ,  0.257263922518  }
, {  442 ,  0.257869249395  }
, {  443 ,  0.258474576271  }
, {  445 ,  0.258777239709  }
, {  451 ,  0.259079903148  }
, {  452 ,  0.259382566586  }
, {  454 ,  0.260290556901  }
, {  460 ,  0.260593220339  }
, {  461 ,  0.26210653753  }
, {  463 ,  0.265133171913  }
, {  466 ,  0.265435835351  }
, {  467 ,  0.265738498789  }
, {  468 ,  0.266343825666  }
, {  471 ,  0.267251815981  }
, {  474 ,  0.268462469734  }
, {  476 ,  0.26906779661  }
, {  477 ,  0.269370460048  }
, {  479 ,  0.269673123487  }
, {  481 ,  0.270581113801  }
, {  482 ,  0.27088377724  }
, {  483 ,  0.271186440678  }
, {  484 ,  0.271489104116  }
, {  485 ,  0.271791767554  }
, {  486 ,  0.272094430993  }
, {  489 ,  0.272397094431  }
, {  492 ,  0.273002421308  }
, {  494 ,  0.273305084746  }
, {  496 ,  0.273607748184  }
, {  497 ,  0.274515738499  }
, {  498 ,  0.275423728814  }
, {  499 ,  0.276331719128  }
, {  500 ,  0.279055690073  }
, {  502 ,  0.281476997579  }
, {  504 ,  0.282384987893  }
, {  505 ,  0.282687651332  }
, {  507 ,  0.28299031477  }
, {  508 ,  0.284200968523  }
, {  510 ,  0.285714285714  }
, {  515 ,  0.286016949153  }
, {  517 ,  0.286319612591  }
, {  519 ,  0.287530266344  }
, {  520 ,  0.288438256659  }
, {  522 ,  0.289346246973  }
, {  523 ,  0.290254237288  }
, {  524 ,  0.291162227603  }
, {  525 ,  0.292070217918  }
, {  529 ,  0.292372881356  }
, {  530 ,  0.292675544794  }
, {  532 ,  0.293280871671  }
, {  533 ,  0.2950968523  }
, {  535 ,  0.295399515738  }
, {  541 ,  0.295702179177  }
, {  542 ,  0.296004842615  }
, {  544 ,  0.296307506053  }
, {  546 ,  0.297215496368  }
, {  548 ,  0.297518159806  }
, {  549 ,  0.297820823245  }
, {  550 ,  0.298123486683  }
, {  551 ,  0.298426150121  }
, {  553 ,  0.299031476998  }
, {  555 ,  0.299636803874  }
, {  557 ,  0.299939467312  }
, {  558 ,  0.300242130751  }
, {  559 ,  0.300544794189  }
, {  560 ,  0.301452784504  }
, {  563 ,  0.301755447942  }
, {  566 ,  0.30205811138  }
, {  567 ,  0.302663438257  }
, {  568 ,  0.302966101695  }
, {  572 ,  0.303268765133  }
, {  574 ,  0.303571428571  }
, {  578 ,  0.30387409201  }
, {  582 ,  0.304176755448  }
, {  585 ,  0.304479418886  }
, {  586 ,  0.304782082324  }
, {  587 ,  0.305084745763  }
, {  588 ,  0.305387409201  }
, {  595 ,  0.305992736077  }
, {  596 ,  0.306295399516  }
, {  597 ,  0.306900726392  }
, {  598 ,  0.307203389831  }
, {  599 ,  0.307506053269  }
, {  607 ,  0.308111380145  }
, {  608 ,  0.308414043584  }
, {  609 ,  0.308716707022  }
, {  613 ,  0.30901937046  }
, {  614 ,  0.309322033898  }
, {  616 ,  0.309927360775  }
, {  617 ,  0.310230024213  }
, {  618 ,  0.310532687651  }
, {  622 ,  0.311440677966  }
, {  625 ,  0.311743341404  }
, {  626 ,  0.312046004843  }
, {  627 ,  0.312651331719  }
, {  628 ,  0.312953995157  }
, {  631 ,  0.313256658596  }
, {  636 ,  0.313559322034  }
, {  639 ,  0.313861985472  }
, {  644 ,  0.31416464891  }
, {  645 ,  0.314467312349  }
, {  648 ,  0.314769975787  }
, {  655 ,  0.315072639225  }
, {  656 ,  0.315375302663  }
, {  657 ,  0.315677966102  }
, {  658 ,  0.316585956416  }
, {  660 ,  0.316888619855  }
, {  661 ,  0.317191283293  }
, {  662 ,  0.317493946731  }
, {  663 ,  0.318099273608  }
, {  665 ,  0.318401937046  }
, {  666 ,  0.318704600484  }
, {  668 ,  0.319007263923  }
, {  669 ,  0.319915254237  }
, {  671 ,  0.320217917676  }
, {  672 ,  0.320520581114  }
, {  678 ,  0.320823244552  }
, {  679 ,  0.32112590799  }
, {  680 ,  0.321731234867  }
, {  683 ,  0.322336561743  }
, {  686 ,  0.323244552058  }
, {  690 ,  0.323849878935  }
, {  691 ,  0.324455205811  }
, {  694 ,  0.324757869249  }
, {  695 ,  0.326271186441  }
, {  698 ,  0.326573849879  }
, {  699 ,  0.326876513317  }
, {  702 ,  0.327481840194  }
, {  703 ,  0.32808716707  }
, {  704 ,  0.328389830508  }
, {  705 ,  0.328692493947  }
, {  706 ,  0.329600484262  }
, {  709 ,  0.330205811138  }
, {  714 ,  0.330508474576  }
, {  717 ,  0.330811138015  }
, {  720 ,  0.331113801453  }
, {  724 ,  0.331416464891  }
, {  725 ,  0.332021791768  }
, {  726 ,  0.332324455206  }
, {  728 ,  0.332627118644  }
, {  729 ,  0.332929782082  }
, {  732 ,  0.333837772397  }
, {  739 ,  0.334140435835  }
, {  740 ,  0.334745762712  }
, {  744 ,  0.33504842615  }
, {  745 ,  0.335351089588  }
, {  748 ,  0.335653753027  }
, {  750 ,  0.335956416465  }
, {  751 ,  0.336259079903  }
, {  767 ,  0.336561743341  }
, {  770 ,  0.33686440678  }
, {  773 ,  0.338075060533  }
, {  776 ,  0.339588377724  }
, {  777 ,  0.339891041162  }
, {  781 ,  0.340496368039  }
, {  782 ,  0.340799031477  }
, {  783 ,  0.341101694915  }
, {  790 ,  0.341404358354  }
, {  791 ,  0.34200968523  }
, {  794 ,  0.342312348668  }
, {  797 ,  0.34382566586  }
, {  801 ,  0.344128329298  }
, {  802 ,  0.344733656174  }
, {  803 ,  0.345338983051  }
, {  804 ,  0.345944309927  }
, {  808 ,  0.346246973366  }
, {  810 ,  0.346549636804  }
, {  813 ,  0.346852300242  }
, {  818 ,  0.34715496368  }
, {  819 ,  0.347457627119  }
, {  822 ,  0.348668280872  }
, {  824 ,  0.34897094431  }
, {  827 ,  0.349273607748  }
, {  829 ,  0.349576271186  }
, {  830 ,  0.349878934625  }
, {  831 ,  0.350181598063  }
, {  833 ,  0.350484261501  }
, {  835 ,  0.350786924939  }
, {  836 ,  0.351089588378  }
, {  845 ,  0.351392251816  }
, {  848 ,  0.351997578692  }
, {  851 ,  0.352300242131  }
, {  852 ,  0.354418886199  }
, {  853 ,  0.354721549637  }
, {  855 ,  0.355024213075  }
, {  856 ,  0.355326876513  }
, {  858 ,  0.355629539952  }
, {  861 ,  0.356234866828  }
, {  862 ,  0.356537530266  }
, {  864 ,  0.356840193705  }
, {  865 ,  0.357142857143  }
, {  866 ,  0.357748184019  }
, {  868 ,  0.358050847458  }
, {  869 ,  0.358353510896  }
, {  871 ,  0.358656174334  }
, {  874 ,  0.358958837772  }
, {  880 ,  0.359261501211  }
, {  885 ,  0.359564164649  }
, {  891 ,  0.359866828087  }
, {  896 ,  0.360169491525  }
, {  905 ,  0.360472154964  }
, {  907 ,  0.361985472155  }
, {  909 ,  0.362288135593  }
, {  910 ,  0.362590799031  }
, {  912 ,  0.36289346247  }
, {  915 ,  0.364406779661  }
, {  916 ,  0.364709443099  }
, {  920 ,  0.365012106538  }
, {  922 ,  0.365617433414  }
, {  923 ,  0.365920096852  }
, {  924 ,  0.366222760291  }
, {  925 ,  0.366525423729  }
, {  926 ,  0.366828087167  }
, {  929 ,  0.367130750605  }
, {  930 ,  0.367433414044  }
, {  932 ,  0.367736077482  }
, {  941 ,  0.370460048426  }
, {  942 ,  0.371065375303  }
, {  946 ,  0.371368038741  }
, {  952 ,  0.371670702179  }
, {  955 ,  0.372276029056  }
, {  956 ,  0.372578692494  }
, {  958 ,  0.372881355932  }
, {  965 ,  0.37318401937  }
, {  978 ,  0.373486682809  }
, {  979 ,  0.373789346247  }
, {  981 ,  0.374092009685  }
, {  984 ,  0.374394673123  }
, {  988 ,  0.374697336562  }
, {  990 ,  0.375  }
, {  991 ,  0.375302663438  }
, {  996 ,  0.375907990315  }
, {  997 ,  0.376210653753  }
, {  1001 ,  0.376513317191  }
, {  1003 ,  0.37681598063  }
, {  1007 ,  0.377723970944  }
, {  1011 ,  0.378026634383  }
, {  1019 ,  0.378631961259  }
, {  1021 ,  0.379237288136  }
, {  1023 ,  0.379539951574  }
, {  1024 ,  0.38014527845  }
, {  1025 ,  0.380447941889  }
, {  1026 ,  0.381355932203  }
, {  1028 ,  0.381658595642  }
, {  1032 ,  0.38196125908  }
, {  1038 ,  0.382566585956  }
, {  1039 ,  0.382869249395  }
, {  1040 ,  0.383474576271  }
, {  1041 ,  0.383777239709  }
, {  1043 ,  0.384079903148  }
, {  1053 ,  0.384382566586  }
, {  1054 ,  0.384685230024  }
, {  1061 ,  0.384987893462  }
, {  1064 ,  0.385593220339  }
, {  1066 ,  0.386198547215  }
, {  1070 ,  0.388014527845  }
, {  1073 ,  0.388619854722  }
, {  1076 ,  0.38892251816  }
, {  1078 ,  0.389225181598  }
, {  1079 ,  0.389527845036  }
, {  1080 ,  0.390133171913  }
, {  1083 ,  0.390435835351  }
, {  1084 ,  0.391041162228  }
, {  1086 ,  0.391646489104  }
, {  1087 ,  0.391949152542  }
, {  1089 ,  0.392554479419  }
, {  1091 ,  0.392857142857  }
, {  1095 ,  0.394370460048  }
, {  1096 ,  0.394975786925  }
, {  1097 ,  0.395278450363  }
, {  1098 ,  0.395581113801  }
, {  1100 ,  0.39588377724  }
, {  1101 ,  0.396489104116  }
, {  1111 ,  0.396791767554  }
, {  1116 ,  0.397094430993  }
, {  1117 ,  0.397397094431  }
, {  1119 ,  0.397699757869  }
, {  1121 ,  0.398002421308  }
, {  1122 ,  0.398305084746  }
, {  1125 ,  0.398607748184  }
, {  1129 ,  0.398910411622  }
, {  1134 ,  0.399515738499  }
, {  1135 ,  0.400423728814  }
, {  1140 ,  0.400726392252  }
, {  1142 ,  0.40102905569  }
, {  1145 ,  0.401634382567  }
, {  1156 ,  0.401937046005  }
, {  1160 ,  0.402239709443  }
, {  1162 ,  0.40284503632  }
, {  1163 ,  0.403147699758  }
, {  1164 ,  0.404055690073  }
, {  1165 ,  0.404661016949  }
, {  1171 ,  0.404963680387  }
, {  1172 ,  0.405266343826  }
, {  1178 ,  0.405569007264  }
, {  1179 ,  0.405871670702  }
, {  1180 ,  0.40617433414  }
, {  1185 ,  0.406476997579  }
, {  1187 ,  0.407384987893  }
, {  1188 ,  0.407687651332  }
, {  1191 ,  0.408292978208  }
, {  1192 ,  0.408898305085  }
, {  1196 ,  0.409200968523  }
, {  1197 ,  0.4098062954  }
, {  1200 ,  0.410714285714  }
, {  1201 ,  0.411016949153  }
, {  1202 ,  0.411319612591  }
, {  1204 ,  0.411622276029  }
, {  1210 ,  0.412227602906  }
, {  1216 ,  0.412530266344  }
, {  1217 ,  0.41313559322  }
, {  1218 ,  0.413438256659  }
, {  1219 ,  0.413740920097  }
, {  1220 ,  0.414043583535  }
, {  1226 ,  0.414346246973  }
, {  1229 ,  0.414648910412  }
, {  1230 ,  0.41495157385  }
, {  1232 ,  0.415254237288  }
, {  1237 ,  0.415556900726  }
, {  1238 ,  0.416162227603  }
, {  1240 ,  0.416767554479  }
, {  1241 ,  0.417675544794  }
, {  1242 ,  0.419188861985  }
, {  1243 ,  0.419491525424  }
, {  1244 ,  0.419794188862  }
, {  1245 ,  0.4200968523  }
, {  1261 ,  0.420702179177  }
, {  1267 ,  0.422215496368  }
, {  1268 ,  0.422518159806  }
, {  1269 ,  0.422820823245  }
, {  1272 ,  0.423426150121  }
, {  1280 ,  0.423728813559  }
, {  1282 ,  0.424636803874  }
, {  1283 ,  0.424939467312  }
, {  1284 ,  0.425242130751  }
, {  1292 ,  0.425544794189  }
, {  1300 ,  0.425847457627  }
, {  1303 ,  0.426150121065  }
, {  1310 ,  0.426452784504  }
, {  1311 ,  0.426755447942  }
, {  1312 ,  0.427663438257  }
, {  1313 ,  0.427966101695  }
, {  1314 ,  0.42887409201  }
, {  1317 ,  0.429479418886  }
, {  1321 ,  0.429782082324  }
, {  1329 ,  0.430084745763  }
, {  1330 ,  0.430387409201  }
, {  1331 ,  0.430690072639  }
, {  1332 ,  0.430992736077  }
, {  1334 ,  0.431295399516  }
, {  1336 ,  0.431598062954  }
, {  1337 ,  0.431900726392  }
, {  1339 ,  0.432203389831  }
, {  1344 ,  0.432506053269  }
, {  1345 ,  0.433111380145  }
, {  1369 ,  0.433716707022  }
, {  1372 ,  0.43401937046  }
, {  1375 ,  0.434322033898  }
, {  1376 ,  0.434624697337  }
, {  1380 ,  0.434927360775  }
, {  1381 ,  0.435230024213  }
, {  1388 ,  0.435532687651  }
, {  1392 ,  0.43583535109  }
, {  1393 ,  0.436138014528  }
, {  1394 ,  0.436440677966  }
, {  1395 ,  0.436743341404  }
, {  1410 ,  0.437348668281  }
, {  1413 ,  0.437651331719  }
, {  1415 ,  0.437953995157  }
, {  1416 ,  0.438256658596  }
, {  1419 ,  0.438559322034  }
, {  1420 ,  0.438861985472  }
, {  1432 ,  0.43916464891  }
, {  1433 ,  0.439467312349  }
, {  1435 ,  0.439769975787  }
, {  1438 ,  0.440072639225  }
, {  1439 ,  0.440677966102  }
, {  1440 ,  0.44098062954  }
, {  1442 ,  0.441585956416  }
, {  1443 ,  0.443401937046  }
, {  1444 ,  0.443704600484  }
, {  1445 ,  0.444007263923  }
, {  1446 ,  0.444309927361  }
, {  1451 ,  0.444612590799  }
, {  1454 ,  0.444915254237  }
, {  1464 ,  0.445217917676  }
, {  1470 ,  0.445520581114  }
, {  1471 ,  0.44612590799  }
, {  1473 ,  0.446731234867  }
, {  1475 ,  0.447336561743  }
, {  1476 ,  0.447639225182  }
, {  1479 ,  0.448244552058  }
, {  1484 ,  0.448547215496  }
, {  1486 ,  0.449152542373  }
, {  1489 ,  0.449757869249  }
, {  1496 ,  0.450363196126  }
, {  1498 ,  0.450665859564  }
, {  1502 ,  0.452481840194  }
, {  1504 ,  0.45308716707  }
, {  1507 ,  0.453389830508  }
, {  1509 ,  0.453692493947  }
, {  1515 ,  0.453995157385  }
, {  1517 ,  0.454600484262  }
, {  1518 ,  0.4549031477  }
, {  1519 ,  0.455205811138  }
, {  1522 ,  0.455508474576  }
, {  1539 ,  0.455811138015  }
, {  1547 ,  0.456113801453  }
, {  1550 ,  0.456416464891  }
, {  1559 ,  0.456719128329  }
, {  1566 ,  0.457021791768  }
, {  1567 ,  0.457627118644  }
, {  1568 ,  0.458837772397  }
, {  1569 ,  0.459140435835  }
, {  1570 ,  0.459745762712  }
, {  1571 ,  0.46004842615  }
, {  1572 ,  0.460351089588  }
, {  1607 ,  0.460653753027  }
, {  1611 ,  0.460956416465  }
, {  1613 ,  0.461561743341  }
, {  1617 ,  0.46186440678  }
, {  1618 ,  0.462167070218  }
, {  1620 ,  0.462469733656  }
, {  1625 ,  0.462772397094  }
, {  1634 ,  0.463075060533  }
, {  1638 ,  0.463377723971  }
, {  1640 ,  0.463983050847  }
, {  1645 ,  0.464285714286  }
, {  1646 ,  0.46700968523  }
, {  1650 ,  0.467312348668  }
, {  1656 ,  0.467615012107  }
, {  1660 ,  0.467917675545  }
, {  1662 ,  0.468220338983  }
, {  1664 ,  0.468523002421  }
, {  1666 ,  0.46882566586  }
, {  1668 ,  0.469128329298  }
, {  1670 ,  0.469430992736  }
, {  1675 ,  0.469733656174  }
, {  1678 ,  0.470036319613  }
, {  1687 ,  0.470338983051  }
, {  1688 ,  0.470641646489  }
, {  1703 ,  0.471549636804  }
, {  1710 ,  0.471852300242  }
, {  1713 ,  0.47215496368  }
, {  1714 ,  0.472457627119  }
, {  1720 ,  0.472760290557  }
, {  1721 ,  0.474576271186  }
, {  1728 ,  0.475484261501  }
, {  1739 ,  0.475786924939  }
, {  1741 ,  0.476089588378  }
, {  1746 ,  0.476392251816  }
, {  1757 ,  0.476694915254  }
, {  1759 ,  0.477300242131  }
, {  1767 ,  0.477602905569  }
, {  1772 ,  0.478208232446  }
, {  1775 ,  0.478510895884  }
, {  1779 ,  0.478813559322  }
, {  1786 ,  0.47911622276  }
, {  1787 ,  0.479721549637  }
, {  1790 ,  0.480024213075  }
, {  1800 ,  0.480326876513  }
, {  1802 ,  0.480629539952  }
, {  1808 ,  0.48093220339  }
, {  1810 ,  0.481234866828  }
, {  1815 ,  0.481537530266  }
, {  1819 ,  0.482142857143  }
, {  1823 ,  0.482445520581  }
, {  1829 ,  0.482748184019  }
, {  1831 ,  0.483353510896  }
, {  1832 ,  0.483656174334  }
, {  1836 ,  0.483958837772  }
, {  1846 ,  0.484261501211  }
, {  1848 ,  0.484564164649  }
, {  1851 ,  0.485774818402  }
, {  1860 ,  0.48607748184  }
, {  1863 ,  0.486380145278  }
, {  1872 ,  0.48789346247  }
, {  1879 ,  0.488196125908  }
, {  1887 ,  0.488498789346  }
, {  1891 ,  0.488801452785  }
, {  1896 ,  0.489104116223  }
, {  1897 ,  0.489406779661  }
, {  1898 ,  0.489709443099  }
, {  1905 ,  0.490314769976  }
, {  1908 ,  0.490617433414  }
, {  1910 ,  0.493946731235  }
, {  1913 ,  0.494249394673  }
, {  1928 ,  0.494552058111  }
, {  1936 ,  0.49485472155  }
, {  1937 ,  0.495157384988  }
, {  1945 ,  0.495460048426  }
, {  1948 ,  0.495762711864  }
, {  1953 ,  0.496065375303  }
, {  1954 ,  0.496670702179  }
, {  1957 ,  0.496973365617  }
, {  1958 ,  0.497276029056  }
, {  1962 ,  0.497578692494  }
, {  1963 ,  0.497881355932  }
, {  1968 ,  0.49818401937  }
, {  1974 ,  0.498486682809  }
, {  1975 ,  0.499092009685  }
, {  1976 ,  0.499394673123  }
, {  1979 ,  0.499697336562  }
, {  1981 ,  0.5  }
, {  1989 ,  0.500302663438  }
, {  1991 ,  0.500605326877  }
, {  1992 ,  0.500907990315  }
, {  1997 ,  0.501210653753  }
, {  1999 ,  0.501513317191  }
, {  2009 ,  0.50181598063  }
, {  2014 ,  0.502118644068  }
, {  2023 ,  0.502421307506  }
, {  2024 ,  0.502723970944  }
, {  2028 ,  0.503026634383  }
, {  2035 ,  0.503934624697  }
, {  2036 ,  0.504237288136  }
, {  2042 ,  0.504842615012  }
, {  2043 ,  0.50514527845  }
, {  2045 ,  0.505447941889  }
, {  2048 ,  0.507566585956  }
, {  2051 ,  0.507869249395  }
, {  2057 ,  0.508171912833  }
, {  2065 ,  0.508474576271  }
, {  2070 ,  0.508777239709  }
, {  2071 ,  0.509079903148  }
, {  2073 ,  0.509382566586  }
, {  2075 ,  0.509685230024  }
, {  2083 ,  0.510593220339  }
, {  2084 ,  0.510895883777  }
, {  2085 ,  0.511501210654  }
, {  2092 ,  0.511803874092  }
, {  2094 ,  0.51210653753  }
, {  2100 ,  0.512409200969  }
, {  2105 ,  0.513014527845  }
, {  2107 ,  0.513317191283  }
, {  2111 ,  0.51392251816  }
, {  2112 ,  0.514830508475  }
, {  2123 ,  0.515133171913  }
, {  2125 ,  0.515435835351  }
, {  2126 ,  0.517857142857  }
, {  2138 ,  0.518159806295  }
, {  2142 ,  0.518462469734  }
, {  2147 ,  0.518765133172  }
, {  2154 ,  0.51906779661  }
, {  2155 ,  0.519370460048  }
, {  2158 ,  0.519673123487  }
, {  2167 ,  0.519975786925  }
, {  2171 ,  0.520278450363  }
, {  2174 ,  0.520581113801  }
, {  2180 ,  0.521791767554  }
, {  2189 ,  0.522094430993  }
, {  2193 ,  0.522699757869  }
, {  2194 ,  0.523002421308  }
, {  2197 ,  0.523305084746  }
, {  2201 ,  0.523607748184  }
, {  2207 ,  0.523910411622  }
, {  2210 ,  0.524213075061  }
, {  2219 ,  0.524515738499  }
, {  2222 ,  0.524818401937  }
, {  2225 ,  0.525423728814  }
, {  2231 ,  0.525726392252  }
, {  2233 ,  0.52602905569  }
, {  2235 ,  0.526331719128  }
, {  2237 ,  0.526634382567  }
, {  2241 ,  0.526937046005  }
, {  2247 ,  0.527239709443  }
, {  2265 ,  0.527542372881  }
, {  2273 ,  0.52784503632  }
, {  2278 ,  0.528147699758  }
, {  2279 ,  0.528450363196  }
, {  2285 ,  0.528753026634  }
, {  2286 ,  0.529055690073  }
, {  2289 ,  0.529358353511  }
, {  2294 ,  0.529661016949  }
, {  2295 ,  0.530266343826  }
, {  2299 ,  0.530569007264  }
, {  2300 ,  0.530871670702  }
, {  2303 ,  0.531476997579  }
, {  2306 ,  0.531779661017  }
, {  2310 ,  0.532384987893  }
, {  2311 ,  0.532687651332  }
, {  2313 ,  0.533292978208  }
, {  2324 ,  0.533595641646  }
, {  2326 ,  0.533898305085  }
, {  2328 ,  0.534200968523  }
, {  2333 ,  0.534503631961  }
, {  2336 ,  0.5348062954  }
, {  2339 ,  0.535108958838  }
, {  2340 ,  0.535411622276  }
, {  2342 ,  0.535714285714  }
, {  2343 ,  0.536319612591  }
, {  2358 ,  0.536622276029  }
, {  2367 ,  0.537227602906  }
, {  2372 ,  0.537832929782  }
, {  2377 ,  0.53813559322  }
, {  2381 ,  0.539043583535  }
, {  2392 ,  0.539346246973  }
, {  2395 ,  0.539648910412  }
, {  2396 ,  0.53995157385  }
, {  2397 ,  0.540254237288  }
, {  2408 ,  0.540859564165  }
, {  2410 ,  0.541464891041  }
, {  2412 ,  0.541767554479  }
, {  2415 ,  0.542070217918  }
, {  2420 ,  0.542372881356  }
, {  2421 ,  0.542675544794  }
, {  2423 ,  0.542978208232  }
, {  2424 ,  0.543280871671  }
, {  2427 ,  0.543583535109  }
, {  2433 ,  0.543886198547  }
, {  2437 ,  0.544491525424  }
, {  2439 ,  0.544794188862  }
, {  2441 ,  0.5450968523  }
, {  2442 ,  0.545399515738  }
, {  2443 ,  0.545702179177  }
, {  2446 ,  0.546004842615  }
, {  2447 ,  0.546307506053  }
, {  2448 ,  0.54691283293  }
, {  2456 ,  0.547518159806  }
, {  2459 ,  0.547820823245  }
, {  2460 ,  0.548123486683  }
, {  2464 ,  0.549031476998  }
, {  2468 ,  0.549334140436  }
, {  2472 ,  0.549636803874  }
, {  2475 ,  0.549939467312  }
, {  2476 ,  0.550242130751  }
, {  2479 ,  0.550544794189  }
, {  2481 ,  0.551150121065  }
, {  2482 ,  0.551452784504  }
, {  2483 ,  0.551755447942  }
, {  2488 ,  0.55205811138  }
, {  2489 ,  0.552360774818  }
, {  2493 ,  0.552966101695  }
, {  2495 ,  0.553268765133  }
, {  2497 ,  0.554479418886  }
, {  2499 ,  0.555084745763  }
, {  2500 ,  0.555387409201  }
, {  2503 ,  0.555690072639  }
, {  2504 ,  0.556295399516  }
, {  2510 ,  0.556598062954  }
, {  2516 ,  0.556900726392  }
, {  2517 ,  0.557506053269  }
, {  2521 ,  0.558111380145  }
, {  2522 ,  0.559322033898  }
, {  2523 ,  0.559927360775  }
, {  2524 ,  0.560230024213  }
, {  2526 ,  0.56083535109  }
, {  2528 ,  0.561138014528  }
, {  2530 ,  0.561743341404  }
, {  2533 ,  0.562348668281  }
, {  2550 ,  0.562651331719  }
, {  2552 ,  0.563256658596  }
, {  2556 ,  0.563559322034  }
, {  2557 ,  0.563861985472  }
, {  2558 ,  0.56416464891  }
, {  2562 ,  0.564769975787  }
, {  2564 ,  0.565072639225  }
, {  2565 ,  0.565375302663  }
, {  2566 ,  0.565677966102  }
, {  2567 ,  0.566585956416  }
, {  2571 ,  0.567191283293  }
, {  2573 ,  0.567493946731  }
, {  2585 ,  0.568401937046  }
, {  2588 ,  0.569007263923  }
, {  2589 ,  0.569309927361  }
, {  2595 ,  0.569915254237  }
, {  2603 ,  0.570217917676  }
, {  2616 ,  0.570823244552  }
, {  2619 ,  0.572639225182  }
, {  2621 ,  0.57294188862  }
, {  2624 ,  0.573547215496  }
, {  2630 ,  0.574757869249  }
, {  2631 ,  0.575363196126  }
, {  2634 ,  0.575968523002  }
, {  2640 ,  0.576573849879  }
, {  2642 ,  0.577179176755  }
, {  2645 ,  0.578389830508  }
, {  2646 ,  0.578692493947  }
, {  2649 ,  0.578995157385  }
, {  2650 ,  0.5799031477  }
, {  2658 ,  0.580508474576  }
, {  2661 ,  0.581113801453  }
, {  2665 ,  0.581416464891  }
, {  2668 ,  0.581719128329  }
, {  2674 ,  0.582021791768  }
, {  2678 ,  0.582324455206  }
, {  2680 ,  0.582627118644  }
, {  2688 ,  0.582929782082  }
, {  2692 ,  0.583837772397  }
, {  2697 ,  0.584745762712  }
, {  2709 ,  0.58504842615  }
, {  2710 ,  0.585351089588  }
, {  2717 ,  0.585653753027  }
, {  2726 ,  0.585956416465  }
, {  2733 ,  0.586259079903  }
, {  2734 ,  0.586561743341  }
, {  2735 ,  0.58686440678  }
, {  2736 ,  0.587167070218  }
, {  2738 ,  0.587772397094  }
, {  2741 ,  0.588377723971  }
, {  2749 ,  0.588680387409  }
, {  2752 ,  0.588983050847  }
, {  2755 ,  0.589285714286  }
, {  2757 ,  0.589588377724  }
, {  2761 ,  0.5901937046  }
, {  2767 ,  0.591101694915  }
, {  2782 ,  0.591404358354  }
, {  2786 ,  0.591707021792  }
, {  2794 ,  0.59200968523  }
, {  2804 ,  0.592312348668  }
, {  2807 ,  0.592615012107  }
, {  2808 ,  0.592917675545  }
, {  2809 ,  0.593523002421  }
, {  2811 ,  0.594430992736  }
, {  2812 ,  0.594733656174  }
, {  2827 ,  0.595036319613  }
, {  2831 ,  0.595338983051  }
, {  2837 ,  0.595641646489  }
, {  2838 ,  0.595944309927  }
, {  2842 ,  0.596246973366  }
, {  2845 ,  0.596549636804  }
, {  2854 ,  0.59715496368  }
, {  2855 ,  0.597457627119  }
, {  2856 ,  0.597760290557  }
, {  2861 ,  0.598062953995  }
, {  2883 ,  0.598365617433  }
, {  2891 ,  0.598668280872  }
, {  2895 ,  0.59897094431  }
, {  2899 ,  0.599576271186  }
, {  2902 ,  0.599878934625  }
, {  2905 ,  0.600181598063  }
, {  2912 ,  0.601089588378  }
, {  2921 ,  0.601392251816  }
, {  2925 ,  0.601694915254  }
, {  2926 ,  0.601997578692  }
, {  2928 ,  0.602300242131  }
, {  2930 ,  0.602602905569  }
, {  2943 ,  0.602905569007  }
, {  2951 ,  0.603208232446  }
, {  2953 ,  0.603510895884  }
, {  2954 ,  0.604418886199  }
, {  2957 ,  0.604721549637  }
, {  2961 ,  0.607748184019  }
, {  2969 ,  0.608050847458  }
, {  2970 ,  0.608353510896  }
, {  2978 ,  0.608656174334  }
, {  2981 ,  0.608958837772  }
, {  2984 ,  0.609261501211  }
, {  2988 ,  0.610169491525  }
, {  2989 ,  0.610472154964  }
, {  2991 ,  0.610774818402  }
, {  2992 ,  0.611682808717  }
, {  2993 ,  0.611985472155  }
, {  2997 ,  0.612288135593  }
, {  2999 ,  0.61289346247  }
, {  3001 ,  0.613498789346  }
, {  3007 ,  0.613801452785  }
, {  3016 ,  0.614104116223  }
, {  3024 ,  0.614406779661  }
, {  3046 ,  0.615012106538  }
, {  3049 ,  0.615314769976  }
, {  3051 ,  0.615617433414  }
, {  3056 ,  0.615920096852  }
, {  3058 ,  0.616222760291  }
, {  3059 ,  0.616525423729  }
, {  3060 ,  0.617130750605  }
, {  3072 ,  0.617433414044  }
, {  3075 ,  0.61803874092  }
, {  3080 ,  0.618644067797  }
, {  3085 ,  0.619249394673  }
, {  3086 ,  0.619552058111  }
, {  3096 ,  0.620157384988  }
, {  3097 ,  0.620460048426  }
, {  3099 ,  0.621368038741  }
, {  3100 ,  0.622881355932  }
, {  3107 ,  0.623486682809  }
, {  3135 ,  0.624394673123  }
, {  3140 ,  0.624697336562  }
, {  3148 ,  0.625605326877  }
, {  3153 ,  0.625907990315  }
, {  3178 ,  0.626210653753  }
, {  3179 ,  0.62681598063  }
, {  3184 ,  0.627118644068  }
, {  3189 ,  0.627421307506  }
, {  3194 ,  0.628026634383  }
, {  3195 ,  0.628329297821  }
, {  3202 ,  0.628631961259  }
, {  3203 ,  0.628934624697  }
, {  3205 ,  0.629237288136  }
, {  3208 ,  0.629539951574  }
, {  3217 ,  0.629842615012  }
, {  3221 ,  0.63014527845  }
, {  3227 ,  0.630447941889  }
, {  3231 ,  0.630750605327  }
, {  3234 ,  0.631053268765  }
, {  3243 ,  0.631355932203  }
, {  3244 ,  0.631658595642  }
, {  3245 ,  0.63196125908  }
, {  3253 ,  0.632263922518  }
, {  3255 ,  0.632566585956  }
, {  3262 ,  0.632869249395  }
, {  3264 ,  0.633171912833  }
, {  3275 ,  0.633777239709  }
, {  3281 ,  0.634382566586  }
, {  3282 ,  0.634685230024  }
, {  3287 ,  0.634987893462  }
, {  3293 ,  0.635593220339  }
, {  3299 ,  0.635895883777  }
, {  3300 ,  0.636198547215  }
, {  3304 ,  0.636501210654  }
, {  3307 ,  0.637409200969  }
, {  3309 ,  0.638014527845  }
, {  3310 ,  0.638619854722  }
, {  3311 ,  0.63892251816  }
, {  3312 ,  0.639225181598  }
, {  3314 ,  0.639527845036  }
, {  3319 ,  0.640133171913  }
, {  3320 ,  0.640738498789  }
, {  3321 ,  0.641041162228  }
, {  3326 ,  0.641646489104  }
, {  3327 ,  0.641949152542  }
, {  3333 ,  0.642857142857  }
, {  3334 ,  0.643159806295  }
, {  3338 ,  0.643462469734  }
, {  3340 ,  0.64406779661  }
, {  3357 ,  0.644370460048  }
, {  3359 ,  0.645581113801  }
, {  3372 ,  0.64588377724  }
, {  3383 ,  0.646791767554  }
, {  3405 ,  0.647094430993  }
, {  3417 ,  0.647397094431  }
, {  3424 ,  0.647699757869  }
, {  3426 ,  0.651331719128  }
, {  3431 ,  0.651634382567  }
, {  3441 ,  0.651937046005  }
, {  3451 ,  0.652239709443  }
, {  3461 ,  0.652542372881  }
, {  3466 ,  0.65284503632  }
, {  3482 ,  0.653147699758  }
, {  3489 ,  0.653450363196  }
, {  3492 ,  0.653753026634  }
, {  3501 ,  0.654055690073  }
, {  3504 ,  0.654358353511  }
, {  3506 ,  0.654661016949  }
, {  3538 ,  0.654963680387  }
, {  3541 ,  0.655266343826  }
, {  3542 ,  0.655569007264  }
, {  3551 ,  0.65617433414  }
, {  3552 ,  0.657082324455  }
, {  3553 ,  0.657384987893  }
, {  3563 ,  0.657687651332  }
, {  3567 ,  0.65799031477  }
, {  3570 ,  0.658292978208  }
, {  3575 ,  0.658595641646  }
, {  3584 ,  0.659200968523  }
, {  3587 ,  0.660714285714  }
, {  3599 ,  0.661319612591  }
, {  3600 ,  0.661924939467  }
, {  3602 ,  0.663438256659  }
, {  3616 ,  0.663740920097  }
, {  3618 ,  0.664346246973  }
, {  3630 ,  0.664648910412  }
, {  3632 ,  0.665254237288  }
, {  3639 ,  0.666162227603  }
, {  3643 ,  0.666464891041  }
, {  3658 ,  0.667070217918  }
, {  3660 ,  0.667372881356  }
, {  3667 ,  0.667675544794  }
, {  3670 ,  0.667978208232  }
, {  3678 ,  0.668280871671  }
, {  3679 ,  0.668886198547  }
, {  3693 ,  0.669794188862  }
, {  3703 ,  0.6700968523  }
, {  3715 ,  0.671004842615  }
, {  3718 ,  0.671610169492  }
, {  3734 ,  0.67191283293  }
, {  3735 ,  0.672215496368  }
, {  3740 ,  0.672518159806  }
, {  3745 ,  0.672820823245  }
, {  3747 ,  0.673123486683  }
, {  3757 ,  0.673426150121  }
, {  3759 ,  0.673728813559  }
, {  3761 ,  0.674031476998  }
, {  3770 ,  0.674334140436  }
, {  3772 ,  0.674636803874  }
, {  3773 ,  0.674939467312  }
, {  3781 ,  0.675847457627  }
, {  3783 ,  0.676755447942  }
, {  3784 ,  0.67705811138  }
, {  3796 ,  0.677360774818  }
, {  3814 ,  0.678571428571  }
, {  3815 ,  0.67887409201  }
, {  3820 ,  0.679176755448  }
, {  3843 ,  0.679782082324  }
, {  3846 ,  0.680084745763  }
, {  3851 ,  0.680387409201  }
, {  3858 ,  0.680690072639  }
, {  3873 ,  0.681295399516  }
, {  3882 ,  0.681900726392  }
, {  3886 ,  0.682506053269  }
, {  3888 ,  0.683111380145  }
, {  3898 ,  0.683716707022  }
, {  3900 ,  0.68401937046  }
, {  3907 ,  0.684624697337  }
, {  3916 ,  0.685230024213  }
, {  3921 ,  0.685532687651  }
, {  3924 ,  0.68583535109  }
, {  3925 ,  0.687348668281  }
, {  3935 ,  0.687953995157  }
, {  3939 ,  0.688256658596  }
, {  3943 ,  0.688559322034  }
, {  3946 ,  0.689467312349  }
, {  3962 ,  0.690072639225  }
, {  3966 ,  0.690677966102  }
, {  3967 ,  0.69098062954  }
, {  3969 ,  0.691283292978  }
, {  3971 ,  0.691585956416  }
, {  3979 ,  0.692191283293  }
, {  3984 ,  0.692493946731  }
, {  3988 ,  0.692796610169  }
, {  3992 ,  0.693099273608  }
, {  3993 ,  0.693704600484  }
, {  3996 ,  0.694309927361  }
, {  4002 ,  0.694612590799  }
, {  4012 ,  0.694915254237  }
, {  4014 ,  0.695217917676  }
, {  4020 ,  0.695520581114  }
, {  4024 ,  0.695823244552  }
, {  4026 ,  0.69612590799  }
, {  4030 ,  0.697033898305  }
, {  4036 ,  0.697336561743  }
, {  4044 ,  0.697639225182  }
, {  4054 ,  0.69794188862  }
, {  4068 ,  0.698244552058  }
, {  4074 ,  0.698547215496  }
, {  4077 ,  0.699455205811  }
, {  4132 ,  0.699757869249  }
, {  4139 ,  0.700060532688  }
, {  4146 ,  0.700363196126  }
, {  4149 ,  0.700665859564  }
, {  4151 ,  0.700968523002  }
, {  4159 ,  0.701271186441  }
, {  4163 ,  0.701573849879  }
, {  4168 ,  0.701876513317  }
, {  4169 ,  0.702179176755  }
, {  4175 ,  0.702481840194  }
, {  4206 ,  0.702784503632  }
, {  4214 ,  0.70308716707  }
, {  4237 ,  0.703389830508  }
, {  4257 ,  0.703692493947  }
, {  4258 ,  0.704297820823  }
, {  4259 ,  0.704600484262  }
, {  4266 ,  0.7049031477  }
, {  4267 ,  0.705508474576  }
, {  4278 ,  0.705811138015  }
, {  4292 ,  0.706113801453  }
, {  4320 ,  0.706719128329  }
, {  4327 ,  0.707627118644  }
, {  4336 ,  0.707929782082  }
, {  4357 ,  0.708232445521  }
, {  4393 ,  0.708535108959  }
, {  4395 ,  0.708837772397  }
, {  4400 ,  0.709140435835  }
, {  4415 ,  0.709443099274  }
, {  4422 ,  0.709745762712  }
, {  4483 ,  0.71004842615  }
, {  4487 ,  0.710351089588  }
, {  4495 ,  0.710653753027  }
, {  4541 ,  0.711561743341  }
, {  4542 ,  0.71186440678  }
, {  4543 ,  0.712167070218  }
, {  4551 ,  0.712469733656  }
, {  4555 ,  0.712772397094  }
, {  4559 ,  0.713075060533  }
, {  4567 ,  0.713377723971  }
, {  4571 ,  0.713680387409  }
, {  4574 ,  0.714588377724  }
, {  4584 ,  0.715496368039  }
, {  4588 ,  0.715799031477  }
, {  4616 ,  0.71700968523  }
, {  4619 ,  0.717312348668  }
, {  4623 ,  0.717615012107  }
, {  4634 ,  0.717917675545  }
, {  4662 ,  0.719128329298  }
, {  4668 ,  0.720036319613  }
, {  4685 ,  0.720338983051  }
, {  4689 ,  0.720641646489  }
, {  4693 ,  0.720944309927  }
, {  4724 ,  0.721246973366  }
, {  4768 ,  0.721549636804  }
, {  4781 ,  0.721852300242  }
, {  4797 ,  0.72215496368  }
, {  4800 ,  0.722457627119  }
, {  4804 ,  0.722760290557  }
, {  4812 ,  0.723062953995  }
, {  4814 ,  0.723365617433  }
, {  4838 ,  0.723668280872  }
, {  4843 ,  0.724576271186  }
, {  4845 ,  0.724878934625  }
, {  4847 ,  0.725181598063  }
, {  4855 ,  0.725786924939  }
, {  4880 ,  0.726392251816  }
, {  4895 ,  0.726694915254  }
, {  4910 ,  0.727300242131  }
, {  4913 ,  0.727905569007  }
, {  4914 ,  0.728510895884  }
, {  4932 ,  0.728813559322  }
, {  4954 ,  0.72911622276  }
, {  4957 ,  0.729418886199  }
, {  4967 ,  0.729721549637  }
, {  4983 ,  0.730024213075  }
, {  4986 ,  0.730629539952  }
, {  5001 ,  0.73093220339  }
, {  5016 ,  0.731234866828  }
, {  5025 ,  0.731537530266  }
, {  5026 ,  0.731840193705  }
, {  5097 ,  0.732142857143  }
, {  5147 ,  0.732445520581  }
, {  5154 ,  0.732748184019  }
, {  5158 ,  0.733050847458  }
, {  5167 ,  0.733353510896  }
, {  5168 ,  0.733656174334  }
, {  5176 ,  0.733958837772  }
, {  5181 ,  0.734866828087  }
, {  5188 ,  0.735774818402  }
, {  5196 ,  0.73607748184  }
, {  5215 ,  0.736682808717  }
, {  5226 ,  0.736985472155  }
, {  5248 ,  0.737288135593  }
, {  5250 ,  0.737590799031  }
, {  5266 ,  0.738196125908  }
, {  5267 ,  0.738498789346  }
, {  5285 ,  0.738801452785  }
, {  5289 ,  0.739104116223  }
, {  5347 ,  0.739406779661  }
, {  5372 ,  0.739709443099  }
, {  5380 ,  0.740314769976  }
, {  5381 ,  0.740617433414  }
, {  5391 ,  0.740920096852  }
, {  5396 ,  0.742130750605  }
, {  5406 ,  0.742433414044  }
, {  5408 ,  0.742736077482  }
, {  5418 ,  0.74303874092  }
, {  5425 ,  0.743341404358  }
, {  5427 ,  0.743644067797  }
, {  5439 ,  0.743946731235  }
, {  5440 ,  0.744249394673  }
, {  5451 ,  0.744552058111  }
, {  5452 ,  0.74485472155  }
, {  5455 ,  0.745157384988  }
, {  5473 ,  0.745460048426  }
, {  5478 ,  0.745762711864  }
, {  5567 ,  0.746065375303  }
, {  5585 ,  0.746368038741  }
, {  5613 ,  0.746670702179  }
, {  5617 ,  0.746973365617  }
, {  5619 ,  0.749092009685  }
, {  5636 ,  0.749697336562  }
, {  5640 ,  0.75  }
, {  5667 ,  0.752118644068  }
, {  5673 ,  0.752421307506  }
, {  5692 ,  0.75514527845  }
, {  5693 ,  0.755447941889  }
, {  5699 ,  0.755750605327  }
, {  5719 ,  0.756053268765  }
, {  5737 ,  0.756355932203  }
, {  5753 ,  0.756658595642  }
, {  5769 ,  0.75696125908  }
, {  5776 ,  0.757263922518  }
, {  5803 ,  0.757566585956  }
, {  5813 ,  0.757869249395  }
, {  5816 ,  0.758171912833  }
, {  5818 ,  0.758474576271  }
, {  5827 ,  0.758777239709  }
, {  5828 ,  0.759079903148  }
, {  5835 ,  0.759382566586  }
, {  5845 ,  0.759685230024  }
, {  5926 ,  0.760593220339  }
, {  5938 ,  0.760895883777  }
, {  5960 ,  0.761501210654  }
, {  5973 ,  0.761803874092  }
, {  5979 ,  0.76210653753  }
, {  5981 ,  0.762409200969  }
, {  5985 ,  0.76392251816  }
, {  6062 ,  0.764225181598  }
, {  6076 ,  0.764527845036  }
, {  6090 ,  0.764830508475  }
, {  6097 ,  0.765133171913  }
, {  6119 ,  0.765738498789  }
, {  6160 ,  0.766041162228  }
, {  6161 ,  0.766343825666  }
, {  6163 ,  0.766949152542  }
, {  6168 ,  0.767251815981  }
, {  6189 ,  0.767554479419  }
, {  6208 ,  0.767857142857  }
, {  6216 ,  0.768159806295  }
, {  6237 ,  0.768765133172  }
, {  6259 ,  0.76906779661  }
, {  6315 ,  0.769673123487  }
, {  6320 ,  0.769975786925  }
, {  6330 ,  0.770581113801  }
, {  6345 ,  0.77088377724  }
, {  6360 ,  0.771186440678  }
, {  6368 ,  0.771489104116  }
, {  6369 ,  0.771791767554  }
, {  6393 ,  0.772094430993  }
, {  6397 ,  0.772397094431  }
, {  6413 ,  0.772699757869  }
, {  6462 ,  0.773002421308  }
, {  6483 ,  0.773305084746  }
, {  6498 ,  0.773607748184  }
, {  6504 ,  0.774213075061  }
, {  6535 ,  0.774515738499  }
, {  6543 ,  0.774818401937  }
, {  6544 ,  0.775121065375  }
, {  6570 ,  0.775423728814  }
, {  6576 ,  0.77602905569  }
, {  6594 ,  0.776331719128  }
, {  6595 ,  0.776634382567  }
, {  6604 ,  0.776937046005  }
, {  6620 ,  0.777239709443  }
, {  6638 ,  0.777542372881  }
, {  6654 ,  0.77784503632  }
, {  6665 ,  0.778147699758  }
, {  6667 ,  0.778450363196  }
, {  6677 ,  0.778753026634  }
, {  6712 ,  0.779055690073  }
, {  6716 ,  0.779358353511  }
, {  6721 ,  0.780266343826  }
, {  6730 ,  0.780569007264  }
, {  6743 ,  0.780871670702  }
, {  6773 ,  0.78117433414  }
, {  6792 ,  0.781476997579  }
, {  6801 ,  0.781779661017  }
, {  6824 ,  0.782082324455  }
, {  6836 ,  0.782687651332  }
, {  6846 ,  0.78299031477  }
, {  6852 ,  0.783292978208  }
, {  6882 ,  0.783595641646  }
, {  6885 ,  0.783898305085  }
, {  6906 ,  0.784200968523  }
, {  6907 ,  0.784503631961  }
, {  6941 ,  0.7848062954  }
, {  6969 ,  0.785108958838  }
, {  6976 ,  0.785714285714  }
, {  6977 ,  0.786016949153  }
, {  7020 ,  0.786319612591  }
, {  7026 ,  0.786622276029  }
, {  7033 ,  0.786924939467  }
, {  7050 ,  0.787832929782  }
, {  7072 ,  0.78813559322  }
, {  7086 ,  0.788438256659  }
, {  7119 ,  0.788740920097  }
, {  7137 ,  0.789043583535  }
, {  7189 ,  0.789346246973  }
, {  7200 ,  0.789648910412  }
, {  7227 ,  0.790254237288  }
, {  7228 ,  0.791767554479  }
, {  7232 ,  0.792070217918  }
, {  7236 ,  0.792978208232  }
, {  7257 ,  0.793280871671  }
, {  7276 ,  0.793583535109  }
, {  7284 ,  0.794188861985  }
, {  7309 ,  0.7950968523  }
, {  7313 ,  0.795399515738  }
, {  7363 ,  0.795702179177  }
, {  7405 ,  0.796610169492  }
, {  7412 ,  0.79691283293  }
, {  7423 ,  0.797215496368  }
, {  7429 ,  0.797518159806  }
, {  7444 ,  0.797820823245  }
, {  7474 ,  0.798123486683  }
, {  7486 ,  0.798426150121  }
, {  7522 ,  0.799031476998  }
, {  7541 ,  0.799334140436  }
, {  7567 ,  0.799636803874  }
, {  7585 ,  0.799939467312  }
, {  7586 ,  0.800242130751  }
, {  7590 ,  0.801452784504  }
, {  7606 ,  0.80205811138  }
, {  7636 ,  0.802360774818  }
, {  7652 ,  0.802663438257  }
, {  7699 ,  0.802966101695  }
, {  7737 ,  0.803268765133  }
, {  7775 ,  0.803571428571  }
, {  7793 ,  0.80387409201  }
, {  7810 ,  0.804479418886  }
, {  7833 ,  0.804782082324  }
, {  7835 ,  0.805084745763  }
, {  7918 ,  0.805387409201  }
, {  7941 ,  0.805690072639  }
, {  7943 ,  0.805992736077  }
, {  7966 ,  0.806295399516  }
, {  7970 ,  0.806598062954  }
, {  7982 ,  0.807506053269  }
, {  7993 ,  0.807808716707  }
, {  7996 ,  0.808111380145  }
, {  7998 ,  0.808414043584  }
, {  8009 ,  0.808716707022  }
, {  8060 ,  0.80901937046  }
, {  8063 ,  0.809624697337  }
, {  8072 ,  0.809927360775  }
, {  8092 ,  0.810230024213  }
, {  8094 ,  0.810532687651  }
, {  8102 ,  0.81083535109  }
, {  8105 ,  0.811138014528  }
, {  8109 ,  0.811440677966  }
, {  8121 ,  0.811743341404  }
, {  8129 ,  0.812046004843  }
, {  8133 ,  0.812348668281  }
, {  8138 ,  0.812651331719  }
, {  8188 ,  0.81416464891  }
, {  8218 ,  0.815375302663  }
, {  8231 ,  0.815677966102  }
, {  8240 ,  0.81598062954  }
, {  8279 ,  0.816283292978  }
, {  8296 ,  0.816585956416  }
, {  8318 ,  0.816888619855  }
, {  8326 ,  0.817191283293  }
, {  8334 ,  0.817493946731  }
, {  8342 ,  0.817796610169  }
, {  8344 ,  0.818099273608  }
, {  8355 ,  0.818401937046  }
, {  8360 ,  0.818704600484  }
, {  8369 ,  0.819309927361  }
, {  8370 ,  0.819612590799  }
, {  8373 ,  0.820217917676  }
, {  8376 ,  0.820520581114  }
, {  8378 ,  0.820823244552  }
, {  8410 ,  0.821428571429  }
, {  8446 ,  0.821731234867  }
, {  8451 ,  0.822033898305  }
, {  8453 ,  0.822639225182  }
, {  8484 ,  0.82294188862  }
, {  8502 ,  0.823244552058  }
, {  8524 ,  0.823547215496  }
, {  8538 ,  0.824455205811  }
, {  8655 ,  0.825363196126  }
, {  8671 ,  0.825665859564  }
, {  8721 ,  0.825968523002  }
, {  8751 ,  0.826271186441  }
, {  8770 ,  0.826573849879  }
, {  8782 ,  0.826876513317  }
, {  8827 ,  0.827179176755  }
, {  8853 ,  0.827481840194  }
, {  8880 ,  0.827784503632  }
, {  8924 ,  0.82808716707  }
, {  8958 ,  0.828389830508  }
, {  8975 ,  0.828692493947  }
, {  9012 ,  0.828995157385  }
, {  9034 ,  0.829297820823  }
, {  9063 ,  0.829600484262  }
, {  9084 ,  0.8299031477  }
, {  9128 ,  0.830205811138  }
, {  9141 ,  0.830508474576  }
, {  9172 ,  0.830811138015  }
, {  9191 ,  0.831113801453  }
, {  9250 ,  0.831719128329  }
, {  9258 ,  0.832021791768  }
, {  9259 ,  0.832324455206  }
, {  9269 ,  0.832627118644  }
, {  9302 ,  0.832929782082  }
, {  9317 ,  0.833232445521  }
, {  9380 ,  0.833535108959  }
, {  9410 ,  0.833837772397  }
, {  9435 ,  0.834140435835  }
, {  9561 ,  0.834443099274  }
, {  9596 ,  0.834745762712  }
, {  9687 ,  0.83504842615  }
, {  9740 ,  0.835351089588  }
, {  9790 ,  0.835653753027  }
, {  9829 ,  0.835956416465  }
, {  9840 ,  0.836259079903  }
, {  9843 ,  0.836561743341  }
, {  9854 ,  0.83686440678  }
, {  9871 ,  0.837167070218  }
, {  9895 ,  0.837469733656  }
, {  9925 ,  0.837772397094  }
, {  9928 ,  0.838075060533  }
, {  9965 ,  0.838983050847  }
, {  10006 ,  0.839285714286  }
, {  10010 ,  0.839588377724  }
, {  10020 ,  0.839891041162  }
, {  10075 ,  0.8401937046  }
, {  10119 ,  0.840496368039  }
, {  10185 ,  0.841101694915  }
, {  10265 ,  0.841707021792  }
, {  10316 ,  0.842917675545  }
, {  10326 ,  0.843220338983  }
, {  10371 ,  0.843523002421  }
, {  10379 ,  0.84382566586  }
, {  10425 ,  0.844733656174  }
, {  10468 ,  0.845036319613  }
, {  10476 ,  0.845338983051  }
, {  10522 ,  0.845641646489  }
, {  10614 ,  0.845944309927  }
, {  10633 ,  0.846246973366  }
, {  10643 ,  0.846549636804  }
, {  10679 ,  0.846852300242  }
, {  10700 ,  0.84715496368  }
, {  10753 ,  0.847457627119  }
, {  10790 ,  0.847760290557  }
, {  10806 ,  0.848062953995  }
, {  10839 ,  0.848365617433  }
, {  10947 ,  0.848668280872  }
, {  10960 ,  0.849273607748  }
, {  11021 ,  0.849576271186  }
, {  11052 ,  0.849878934625  }
, {  11054 ,  0.850181598063  }
, {  11184 ,  0.850484261501  }
, {  11214 ,  0.850786924939  }
, {  11305 ,  0.851089588378  }
, {  11309 ,  0.851694915254  }
, {  11331 ,  0.851997578692  }
, {  11352 ,  0.852300242131  }
, {  11353 ,  0.852602905569  }
, {  11357 ,  0.852905569007  }
, {  11484 ,  0.853510895884  }
, {  11508 ,  0.853813559322  }
, {  11561 ,  0.85411622276  }
, {  11581 ,  0.854721549637  }
, {  11595 ,  0.855024213075  }
, {  11621 ,  0.855326876513  }
, {  11700 ,  0.855629539952  }
, {  11735 ,  0.85593220339  }
, {  11752 ,  0.856234866828  }
, {  11756 ,  0.856537530266  }
, {  11826 ,  0.857445520581  }
, {  11888 ,  0.857748184019  }
, {  11953 ,  0.858353510896  }
, {  11984 ,  0.858656174334  }
, {  12027 ,  0.858958837772  }
, {  12033 ,  0.859261501211  }
, {  12062 ,  0.859564164649  }
, {  12076 ,  0.859866828087  }
, {  12086 ,  0.860169491525  }
, {  12224 ,  0.860472154964  }
, {  12247 ,  0.860774818402  }
, {  12434 ,  0.86107748184  }
, {  12478 ,  0.861380145278  }
, {  12581 ,  0.861682808717  }
, {  12748 ,  0.861985472155  }
, {  12861 ,  0.862288135593  }
, {  12885 ,  0.862590799031  }
, {  12904 ,  0.86289346247  }
, {  12922 ,  0.863196125908  }
, {  13044 ,  0.863498789346  }
, {  13096 ,  0.863801452785  }
, {  13114 ,  0.864104116223  }
, {  13229 ,  0.864406779661  }
, {  13252 ,  0.864709443099  }
, {  13301 ,  0.865617433414  }
, {  13304 ,  0.865920096852  }
, {  13330 ,  0.866222760291  }
, {  13331 ,  0.866828087167  }
, {  13393 ,  0.867736077482  }
, {  13419 ,  0.869552058111  }
, {  13489 ,  0.86985472155  }
, {  13507 ,  0.870157384988  }
, {  13525 ,  0.870460048426  }
, {  13557 ,  0.870762711864  }
, {  13579 ,  0.871065375303  }
, {  13609 ,  0.871368038741  }
, {  13654 ,  0.871670702179  }
, {  13682 ,  0.871973365617  }
, {  13743 ,  0.872276029056  }
, {  13754 ,  0.87318401937  }
, {  13789 ,  0.873486682809  }
, {  13894 ,  0.873789346247  }
, {  13914 ,  0.874092009685  }
, {  14001 ,  0.874394673123  }
, {  14049 ,  0.875302663438  }
, {  14095 ,  0.875605326877  }
, {  14096 ,  0.875907990315  }
, {  14134 ,  0.876210653753  }
, {  14156 ,  0.877118644068  }
, {  14158 ,  0.877421307506  }
, {  14181 ,  0.877723970944  }
, {  14231 ,  0.878026634383  }
, {  14458 ,  0.878329297821  }
, {  14482 ,  0.878631961259  }
, {  14550 ,  0.878934624697  }
, {  14572 ,  0.879842615012  }
, {  14576 ,  0.88014527845  }
, {  14632 ,  0.880447941889  }
, {  14669 ,  0.880750605327  }
, {  14763 ,  0.881053268765  }
, {  14773 ,  0.881355932203  }
, {  14803 ,  0.881658595642  }
, {  14804 ,  0.88196125908  }
, {  14817 ,  0.882263922518  }
, {  14828 ,  0.882566585956  }
, {  14829 ,  0.883474576271  }
, {  14842 ,  0.884079903148  }
, {  14893 ,  0.884382566586  }
, {  14930 ,  0.884685230024  }
, {  14938 ,  0.884987893462  }
, {  15019 ,  0.885290556901  }
, {  15022 ,  0.885593220339  }
, {  15124 ,  0.885895883777  }
, {  15134 ,  0.886198547215  }
, {  15135 ,  0.88710653753  }
, {  15150 ,  0.887409200969  }
, {  15228 ,  0.887711864407  }
, {  15230 ,  0.888014527845  }
, {  15251 ,  0.888317191283  }
, {  15263 ,  0.888619854722  }
, {  15269 ,  0.889225181598  }
, {  15285 ,  0.890133171913  }
, {  15294 ,  0.890435835351  }
, {  15320 ,  0.890738498789  }
, {  15341 ,  0.891041162228  }
, {  15342 ,  0.891343825666  }
, {  15431 ,  0.891646489104  }
, {  15503 ,  0.891949152542  }
, {  15568 ,  0.892554479419  }
, {  15569 ,  0.892857142857  }
, {  15786 ,  0.893159806295  }
, {  15805 ,  0.893462469734  }
, {  15834 ,  0.893765133172  }
, {  15995 ,  0.89406779661  }
, {  16046 ,  0.894370460048  }
, {  16142 ,  0.894975786925  }
, {  16247 ,  0.895278450363  }
, {  16266 ,  0.895581113801  }
, {  16272 ,  0.89588377724  }
, {  16300 ,  0.896186440678  }
, {  16310 ,  0.896489104116  }
, {  16328 ,  0.897397094431  }
, {  16352 ,  0.898002421308  }
, {  16491 ,  0.898305084746  }
, {  16541 ,  0.898607748184  }
, {  16614 ,  0.898910411622  }
, {  16664 ,  0.899213075061  }
, {  16687 ,  0.899515738499  }
, {  16765 ,  0.899818401937  }
, {  16918 ,  0.900121065375  }
, {  17017 ,  0.900423728814  }
, {  17035 ,  0.900726392252  }
, {  17209 ,  0.901937046005  }
, {  17313 ,  0.902239709443  }
, {  17431 ,  0.902542372881  }
, {  17482 ,  0.90284503632  }
, {  17562 ,  0.903450363196  }
, {  17622 ,  0.903753026634  }
, {  17633 ,  0.904055690073  }
, {  17737 ,  0.904358353511  }
, {  17791 ,  0.904661016949  }
, {  17962 ,  0.904963680387  }
, {  17978 ,  0.905266343826  }
, {  17981 ,  0.905569007264  }
, {  17996 ,  0.905871670702  }
, {  18068 ,  0.90617433414  }
, {  18133 ,  0.906779661017  }
, {  18270 ,  0.907082324455  }
, {  18345 ,  0.907384987893  }
, {  18358 ,  0.907687651332  }
, {  18404 ,  0.90799031477  }
, {  18456 ,  0.908292978208  }
, {  18548 ,  0.908595641646  }
, {  18581 ,  0.908898305085  }
, {  18604 ,  0.909200968523  }
, {  18634 ,  0.909503631961  }
, {  18643 ,  0.9098062954  }
, {  18644 ,  0.910714285714  }
, {  18718 ,  0.911016949153  }
, {  18728 ,  0.911319612591  }
, {  18849 ,  0.911622276029  }
, {  18854 ,  0.912227602906  }
, {  18858 ,  0.912832929782  }
, {  18916 ,  0.91313559322  }
, {  18938 ,  0.913438256659  }
, {  18963 ,  0.914346246973  }
, {  19006 ,  0.914648910412  }
, {  19040 ,  0.91495157385  }
, {  19064 ,  0.915556900726  }
, {  19068 ,  0.915859564165  }
, {  19182 ,  0.916162227603  }
, {  19227 ,  0.916464891041  }
, {  19228 ,  0.917070217918  }
, {  19311 ,  0.917372881356  }
, {  19456 ,  0.917675544794  }
, {  19664 ,  0.917978208232  }
, {  19673 ,  0.918280871671  }
, {  19678 ,  0.918583535109  }
, {  19799 ,  0.918886198547  }
, {  19917 ,  0.919188861985  }
, {  19957 ,  0.9200968523  }
, {  20059 ,  0.920399515738  }
, {  20176 ,  0.921004842615  }
, {  20316 ,  0.921307506053  }
, {  20344 ,  0.922215496368  }
, {  20348 ,  0.922518159806  }
, {  20505 ,  0.922820823245  }
, {  20561 ,  0.923123486683  }
, {  20593 ,  0.923426150121  }
, {  20615 ,  0.923728813559  }
, {  20735 ,  0.924031476998  }
, {  20871 ,  0.924334140436  }
, {  20944 ,  0.924636803874  }
, {  20957 ,  0.924939467312  }
, {  20990 ,  0.925242130751  }
, {  21238 ,  0.925544794189  }
, {  21241 ,  0.925847457627  }
, {  21273 ,  0.926150121065  }
, {  21292 ,  0.926452784504  }
, {  21305 ,  0.926755447942  }
, {  21440 ,  0.92705811138  }
, {  21453 ,  0.927663438257  }
, {  21491 ,  0.927966101695  }
, {  21513 ,  0.92887409201  }
, {  21733 ,  0.929176755448  }
, {  21741 ,  0.929479418886  }
, {  22117 ,  0.930084745763  }
, {  22118 ,  0.931598062954  }
, {  22125 ,  0.931900726392  }
, {  22459 ,  0.932203389831  }
, {  22530 ,  0.932506053269  }
, {  22566 ,  0.932808716707  }
, {  22597 ,  0.933111380145  }
, {  22865 ,  0.933414043584  }
, {  23044 ,  0.933716707022  }
, {  23071 ,  0.93401937046  }
, {  23285 ,  0.934322033898  }
, {  23332 ,  0.934624697337  }
, {  23380 ,  0.934927360775  }
, {  23438 ,  0.935230024213  }
, {  23451 ,  0.935532687651  }
, {  23525 ,  0.93583535109  }
, {  23732 ,  0.936138014528  }
, {  23821 ,  0.936743341404  }
, {  23883 ,  0.937046004843  }
, {  24070 ,  0.937348668281  }
, {  24251 ,  0.937953995157  }
, {  24343 ,  0.938256658596  }
, {  24389 ,  0.938559322034  }
, {  24498 ,  0.938861985472  }
, {  24558 ,  0.93916464891  }
, {  24597 ,  0.939467312349  }
, {  24832 ,  0.939769975787  }
, {  25389 ,  0.940072639225  }
, {  25394 ,  0.940375302663  }
, {  26106 ,  0.940677966102  }
, {  26206 ,  0.941585956416  }
, {  26241 ,  0.941888619855  }
, {  26275 ,  0.942191283293  }
, {  26283 ,  0.942796610169  }
, {  26472 ,  0.943099273608  }
, {  26514 ,  0.943401937046  }
, {  26560 ,  0.943704600484  }
, {  26718 ,  0.944007263923  }
, {  26791 ,  0.944309927361  }
, {  26901 ,  0.944612590799  }
, {  27504 ,  0.944915254237  }
, {  27618 ,  0.945217917676  }
, {  27957 ,  0.945520581114  }
, {  28007 ,  0.94612590799  }
, {  28023 ,  0.946428571429  }
, {  28278 ,  0.947033898305  }
, {  28452 ,  0.947336561743  }
, {  28821 ,  0.947639225182  }
, {  28864 ,  0.948244552058  }
, {  28894 ,  0.948849878935  }
, {  29092 ,  0.949152542373  }
, {  29260 ,  0.949757869249  }
, {  29336 ,  0.950665859564  }
, {  29767 ,  0.950968523002  }
, {  29833 ,  0.951573849879  }
, {  30122 ,  0.951876513317  }
, {  30246 ,  0.952179176755  }
, {  30303 ,  0.952784503632  }
, {  30449 ,  0.95308716707  }
, {  30481 ,  0.953389830508  }
, {  30527 ,  0.953692493947  }
, {  30620 ,  0.953995157385  }
, {  30997 ,  0.954297820823  }
, {  31313 ,  0.954600484262  }
, {  31341 ,  0.9549031477  }
, {  31355 ,  0.955205811138  }
, {  31405 ,  0.955508474576  }
, {  32087 ,  0.955811138015  }
, {  32110 ,  0.956113801453  }
, {  32177 ,  0.956416464891  }
, {  32254 ,  0.956719128329  }
, {  32280 ,  0.957021791768  }
, {  32368 ,  0.957324455206  }
, {  32534 ,  0.957627118644  }
, {  32564 ,  0.957929782082  }
, {  32591 ,  0.958232445521  }
, {  32836 ,  0.958535108959  }
, {  33128 ,  0.959443099274  }
, {  33537 ,  0.960351089588  }
, {  34013 ,  0.960653753027  }
, {  35288 ,  0.960956416465  }
, {  35312 ,  0.962167070218  }
, {  36532 ,  0.962469733656  }
, {  36606 ,  0.962772397094  }
, {  37138 ,  0.963377723971  }
, {  37356 ,  0.963983050847  }
, {  37490 ,  0.964891041162  }
, {  37832 ,  0.9651937046  }
, {  38294 ,  0.965496368039  }
, {  39450 ,  0.965799031477  }
, {  39493 ,  0.966101694915  }
, {  39500 ,  0.966404358354  }
, {  39610 ,  0.966707021792  }
, {  40087 ,  0.96700968523  }
, {  41616 ,  0.967312348668  }
, {  41819 ,  0.967615012107  }
, {  43111 ,  0.967917675545  }
, {  43643 ,  0.96882566586  }
, {  43652 ,  0.969128329298  }
, {  44001 ,  0.969430992736  }
, {  44056 ,  0.969733656174  }
, {  45090 ,  0.970036319613  }
, {  45137 ,  0.970338983051  }
, {  45140 ,  0.970641646489  }
, {  46086 ,  0.970944309927  }
, {  46437 ,  0.971246973366  }
, {  47441 ,  0.971549636804  }
, {  47540 ,  0.971852300242  }
, {  47742 ,  0.97215496368  }
, {  47758 ,  0.972457627119  }
, {  47945 ,  0.972760290557  }
, {  48264 ,  0.973062953995  }
, {  48519 ,  0.973365617433  }
, {  48731 ,  0.973668280872  }
, {  49047 ,  0.97397094431  }
, {  49142 ,  0.974273607748  }
, {  51810 ,  0.974576271186  }
, {  54242 ,  0.974878934625  }
, {  54582 ,  0.975181598063  }
, {  54667 ,  0.975484261501  }
, {  55104 ,  0.975786924939  }
, {  56622 ,  0.976089588378  }
, {  56940 ,  0.976392251816  }
, {  56989 ,  0.976694915254  }
, {  57301 ,  0.976997578692  }
, {  57590 ,  0.977300242131  }
, {  57745 ,  0.977602905569  }
, {  59179 ,  0.977905569007  }
, {  59893 ,  0.978208232446  }
, {  60083 ,  0.978510895884  }
, {  60344 ,  0.978813559322  }
, {  60355 ,  0.97911622276  }
, {  60356 ,  0.980024213075  }
, {  61015 ,  0.980326876513  }
, {  61023 ,  0.980629539952  }
, {  61026 ,  0.98093220339  }
, {  61027 ,  0.981234866828  }
, {  61035 ,  0.982142857143  }
, {  61975 ,  0.982445520581  }
, {  62069 ,  0.982748184019  }
, {  62080 ,  0.983050847458  }
, {  62081 ,  0.983958837772  }
, {  62915 ,  0.984261501211  }
, {  62926 ,  0.984564164649  }
, {  62927 ,  0.985472154964  }
, {  64932 ,  0.985774818402  }
, {  65205 ,  0.98607748184  }
, {  65216 ,  0.986380145278  }
, {  65217 ,  0.987288135593  }
, {  67379 ,  0.987590799031  }
, {  67396 ,  0.98789346247  }
, {  67825 ,  0.988196125908  }
, {  68633 ,  0.988498789346  }
, {  68877 ,  0.988801452785  }
, {  70210 ,  0.989406779661  }
, {  73217 ,  0.989709443099  }
, {  73490 ,  0.990012106538  }
, {  74513 ,  0.990314769976  }
, {  75151 ,  0.990617433414  }
, {  78256 ,  0.990920096852  }
, {  82057 ,  0.991222760291  }
, {  83648 ,  0.991525423729  }
, {  84500 ,  0.991828087167  }
, {  87630 ,  0.992130750605  }
, {  93582 ,  0.992433414044  }
, {  94943 ,  0.992736077482  }
, {  95418 ,  0.99303874092  }
, {  95641 ,  0.993341404358  }
, {  96505 ,  0.993644067797  }
, {  97671 ,  0.993946731235  }
, {  98163 ,  0.994249394673  }
, {  101866 ,  0.994552058111  }
, {  103200 ,  0.99485472155  }
, {  109775 ,  0.995157384988  }
, {  113422 ,  0.995460048426  }
, {  119362 ,  0.996065375303  }
, {  121593 ,  0.996368038741  }
, {  123329 ,  0.996670702179  }
, {  133400 ,  0.996973365617  }
, {  141820 ,  0.997276029056  }
, {  157435 ,  0.997578692494  }
, {  182861 ,  0.997881355932  }
, {  191112 ,  0.99818401937  }
, {  199785 ,  0.998486682809  }
, {  204121 ,  0.999092009685  }
, {  210795 ,  0.999394673123  }
, {  212542 ,  0.999697336562  }
, {  246212 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpSecondaryReplyDistTable = foo4;
// HttpSecondaryRequest.cc generated from HttpSecondaryRequest.cdf
// on Wed Oct 27 00:28:29 PDT 1999 by gandy


static DoubleDistElement foo5[] = {
{  0 ,  0.00272397094431  }
, {  106 ,  0.00302663438257  }
, {  115 ,  0.00332929782082  }
, {  116 ,  0.00544794188862  }
, {  117 ,  0.00665859564165  }
, {  118 ,  0.00938256658596  }
, {  119 ,  0.0115012106538  }
, {  120 ,  0.0145278450363  }
, {  121 ,  0.0172518159806  }
, {  123 ,  0.0181598062954  }
, {  124 ,  0.0193704600484  }
, {  125 ,  0.0199757869249  }
, {  126 ,  0.022397094431  }
, {  127 ,  0.0251210653753  }
, {  128 ,  0.0284503631961  }
, {  129 ,  0.0308716707022  }
, {  130 ,  0.034200968523  }
, {  131 ,  0.0366222760291  }
, {  132 ,  0.0411622276029  }
, {  133 ,  0.0420702179177  }
, {  134 ,  0.0438861985472  }
, {  135 ,  0.0517554479419  }
, {  136 ,  0.0544794188862  }
, {  137 ,  0.0811138014528  }
, {  138 ,  0.0826271186441  }
, {  139 ,  0.0995762711864  }
, {  141 ,  0.0998789346247  }
, {  142 ,  0.100484261501  }
, {  144 ,  0.100786924939  }
, {  145 ,  0.101392251816  }
, {  146 ,  0.101694915254  }
, {  148 ,  0.101997578692  }
, {  149 ,  0.102602905569  }
, {  153 ,  0.102905569007  }
, {  157 ,  0.10411622276  }
, {  158 ,  0.105629539952  }
, {  161 ,  0.10593220339  }
, {  162 ,  0.106234866828  }
, {  164 ,  0.107142857143  }
, {  167 ,  0.107445520581  }
, {  170 ,  0.107748184019  }
, {  172 ,  0.108050847458  }
, {  177 ,  0.109261501211  }
, {  178 ,  0.11107748184  }
, {  179 ,  0.111985472155  }
, {  180 ,  0.11289346247  }
, {  181 ,  0.115012106538  }
, {  182 ,  0.116828087167  }
, {  183 ,  0.118341404358  }
, {  184 ,  0.119552058111  }
, {  185 ,  0.122578692494  }
, {  186 ,  0.124394673123  }
, {  187 ,  0.127723970944  }
, {  188 ,  0.131355932203  }
, {  189 ,  0.133171912833  }
, {  190 ,  0.134079903148  }
, {  191 ,  0.137409200969  }
, {  192 ,  0.144975786925  }
, {  193 ,  0.150121065375  }
, {  194 ,  0.155871670702  }
, {  195 ,  0.164043583535  }
, {  196 ,  0.174636803874  }
, {  197 ,  0.181900726392  }
, {  198 ,  0.197033898305  }
, {  199 ,  0.210653753027  }
, {  200 ,  0.223365617433  }
, {  201 ,  0.231234866828  }
, {  202 ,  0.235774818402  }
, {  203 ,  0.24818401937  }
, {  204 ,  0.256355932203  }
, {  205 ,  0.269673123487  }
, {  206 ,  0.279661016949  }
, {  207 ,  0.289043583535  }
, {  208 ,  0.297820823245  }
, {  209 ,  0.308716707022  }
, {  210 ,  0.318099273608  }
, {  211 ,  0.327179176755  }
, {  212 ,  0.342312348668  }
, {  213 ,  0.356234866828  }
, {  214 ,  0.365012106538  }
, {  215 ,  0.375302663438  }
, {  216 ,  0.389830508475  }
, {  217 ,  0.399818401937  }
, {  218 ,  0.410411622276  }
, {  219 ,  0.421004842615  }
, {  220 ,  0.433111380145  }
, {  221 ,  0.444007263923  }
, {  222 ,  0.456416464891  }
, {  223 ,  0.466707021792  }
, {  224 ,  0.476392251816  }
, {  225 ,  0.485774818402  }
, {  226 ,  0.49818401937  }
, {  227 ,  0.511198547215  }
, {  228 ,  0.516041162228  }
, {  229 ,  0.525423728814  }
, {  230 ,  0.531476997579  }
, {  231 ,  0.537832929782  }
, {  232 ,  0.544188861985  }
, {  233 ,  0.548728813559  }
, {  234 ,  0.554176755448  }
, {  235 ,  0.558716707022  }
, {  236 ,  0.562651331719  }
, {  237 ,  0.569915254237  }
, {  238 ,  0.573849878935  }
, {  239 ,  0.581416464891  }
, {  240 ,  0.591101694915  }
, {  241 ,  0.594733656174  }
, {  242 ,  0.599878934625  }
, {  243 ,  0.603208232446  }
, {  244 ,  0.608353510896  }
, {  245 ,  0.611682808717  }
, {  246 ,  0.619249394673  }
, {  247 ,  0.628026634383  }
, {  248 ,  0.631658595642  }
, {  249 ,  0.634382566586  }
, {  250 ,  0.640738498789  }
, {  251 ,  0.644673123487  }
, {  252 ,  0.650423728814  }
, {  253 ,  0.653450363196  }
, {  254 ,  0.657687651332  }
, {  255 ,  0.661622276029  }
, {  256 ,  0.664648910412  }
, {  257 ,  0.671307506053  }
, {  258 ,  0.674939467312  }
, {  259 ,  0.679176755448  }
, {  260 ,  0.681900726392  }
, {  261 ,  0.687348668281  }
, {  262 ,  0.690072639225  }
, {  263 ,  0.696731234867  }
, {  264 ,  0.701271186441  }
, {  265 ,  0.708232445521  }
, {  266 ,  0.713377723971  }
, {  267 ,  0.7151937046  }
, {  268 ,  0.716707021792  }
, {  269 ,  0.719128329298  }
, {  270 ,  0.721852300242  }
, {  271 ,  0.724878934625  }
, {  272 ,  0.728510895884  }
, {  273 ,  0.731234866828  }
, {  274 ,  0.734866828087  }
, {  275 ,  0.739104116223  }
, {  276 ,  0.742130750605  }
, {  277 ,  0.749092009685  }
, {  278 ,  0.753631961259  }
, {  279 ,  0.759382566586  }
, {  280 ,  0.763014527845  }
, {  281 ,  0.766041162228  }
, {  282 ,  0.770581113801  }
, {  283 ,  0.773305084746  }
, {  284 ,  0.778147699758  }
, {  285 ,  0.779661016949  }
, {  286 ,  0.780266343826  }
, {  287 ,  0.790859564165  }
, {  288 ,  0.801452784504  }
, {  289 ,  0.808111380145  }
, {  290 ,  0.811440677966  }
, {  291 ,  0.817191283293  }
, {  292 ,  0.825060532688  }
, {  293 ,  0.83504842615  }
, {  294 ,  0.838983050847  }
, {  295 ,  0.844128329298  }
, {  296 ,  0.844733656174  }
, {  297 ,  0.846246973366  }
, {  298 ,  0.847760290557  }
, {  299 ,  0.849273607748  }
, {  300 ,  0.851089588378  }
, {  301 ,  0.852300242131  }
, {  302 ,  0.853510895884  }
, {  303 ,  0.854418886199  }
, {  304 ,  0.855326876513  }
, {  305 ,  0.855629539952  }
, {  306 ,  0.856537530266  }
, {  307 ,  0.857142857143  }
, {  308 ,  0.857748184019  }
, {  310 ,  0.858050847458  }
, {  311 ,  0.858958837772  }
, {  313 ,  0.860169491525  }
, {  314 ,  0.861380145278  }
, {  315 ,  0.86289346247  }
, {  317 ,  0.863196125908  }
, {  319 ,  0.864406779661  }
, {  320 ,  0.865314769976  }
, {  321 ,  0.866222760291  }
, {  324 ,  0.866525423729  }
, {  331 ,  0.866828087167  }
, {  347 ,  0.867130750605  }
, {  351 ,  0.867433414044  }
, {  1036 ,  0.870460048426  }
, {  1041 ,  0.870762711864  }
, {  1042 ,  0.871368038741  }
, {  1044 ,  0.871670702179  }
, {  1046 ,  0.872276029056  }
, {  1047 ,  0.875  }
, {  1048 ,  0.875605326877  }
, {  1049 ,  0.876513317191  }
, {  1050 ,  0.878026634383  }
, {  1051 ,  0.879237288136  }
, {  1052 ,  0.879842615012  }
, {  1053 ,  0.882263922518  }
, {  1054 ,  0.884987893462  }
, {  1055 ,  0.890435835351  }
, {  1056 ,  0.896489104116  }
, {  1057 ,  0.901937046005  }
, {  1058 ,  0.915556900726  }
, {  1059 ,  0.919188861985  }
, {  1060 ,  0.923123486683  }
, {  1061 ,  0.926150121065  }
, {  1062 ,  0.928268765133  }
, {  1063 ,  0.930992736077  }
, {  1064 ,  0.93401937046  }
, {  1065 ,  0.937348668281  }
, {  1066 ,  0.939467312349  }
, {  1067 ,  0.941283292978  }
, {  1068 ,  0.943099273608  }
, {  1069 ,  0.944915254237  }
, {  1070 ,  0.947639225182  }
, {  1071 ,  0.948547215496  }
, {  1072 ,  0.949455205811  }
, {  1073 ,  0.951573849879  }
, {  1074 ,  0.954600484262  }
, {  1075 ,  0.955205811138  }
, {  1076 ,  0.955508474576  }
, {  1077 ,  0.956113801453  }
, {  1078 ,  0.957627118644  }
, {  1079 ,  0.960653753027  }
, {  1080 ,  0.960956416465  }
, {  1081 ,  0.961259079903  }
, {  1082 ,  0.962167070218  }
, {  1083 ,  0.962772397094  }
, {  1084 ,  0.963075060533  }
, {  1086 ,  0.963983050847  }
, {  1090 ,  0.964285714286  }
, {  1091 ,  0.964588377724  }
, {  1099 ,  0.964891041162  }
, {  1100 ,  0.965799031477  }
, {  1101 ,  0.96700968523  }
, {  1103 ,  0.967917675545  }
, {  1104 ,  0.968523002421  }
, {  1118 ,  0.96882566586  }
, {  1121 ,  0.970036319613  }
, {  1122 ,  0.970641646489  }
, {  1123 ,  0.970944309927  }
, {  1125 ,  0.973365617433  }
, {  1126 ,  0.97397094431  }
, {  1127 ,  0.974576271186  }
, {  1128 ,  0.975786924939  }
, {  1129 ,  0.976694915254  }
, {  1130 ,  0.976997578692  }
, {  1132 ,  0.977602905569  }
, {  1133 ,  0.978208232446  }
, {  1134 ,  0.978813559322  }
, {  1135 ,  0.980024213075  }
, {  1138 ,  0.980326876513  }
, {  1139 ,  0.98093220339  }
, {  1140 ,  0.981234866828  }
, {  1142 ,  0.981537530266  }
, {  1143 ,  0.982142857143  }
, {  1144 ,  0.983050847458  }
, {  1145 ,  0.983656174334  }
, {  1146 ,  0.984564164649  }
, {  1147 ,  0.985774818402  }
, {  1148 ,  0.986380145278  }
, {  1149 ,  0.98789346247  }
, {  1150 ,  0.988196125908  }
, {  1151 ,  0.989104116223  }
, {  1152 ,  0.990012106538  }
, {  1154 ,  0.990314769976  }
, {  1157 ,  0.992433414044  }
, {  1158 ,  0.992736077482  }
, {  1160 ,  0.993341404358  }
, {  1164 ,  0.993644067797  }
, {  1165 ,  0.993946731235  }
, {  1168 ,  0.994552058111  }
, {  1169 ,  0.99485472155  }
, {  1170 ,  0.995762711864  }
, {  1171 ,  0.996065375303  }
, {  1172 ,  0.996368038741  }
, {  1173 ,  0.996670702179  }
, {  1176 ,  0.996973365617  }
, {  1177 ,  0.997881355932  }
, {  1178 ,  0.99818401937  }
, {  1179 ,  0.998486682809  }
, {  1182 ,  0.999092009685  }
, {  1280 ,  0.999394673123  }
, {  1281 ,  0.999697336562  }
, {  1288 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpSecondaryRequestDistTable = foo5;
// HttpThinkTime.cc generated from HttpThinkTime.cdf
// on Wed Oct 27 00:28:31 PDT 1999 by gandy


static DoubleDistElement foo6[] = {
{  1.005 ,  0.000595947556615  }
, {  1.010 ,  0.00119189511323  }
, {  1.022 ,  0.00178784266985  }
, {  1.024 ,  0.00238379022646  }
, {  1.037 ,  0.00357568533969  }
, {  1.038 ,  0.00417163289631  }
, {  1.040 ,  0.00476758045292  }
, {  1.065 ,  0.00536352800954  }
, {  1.066 ,  0.00595947556615  }
, {  1.075 ,  0.00655542312277  }
, {  1.078 ,  0.00715137067938  }
, {  1.089 ,  0.007747318236  }
, {  1.094 ,  0.00834326579261  }
, {  1.102 ,  0.00893921334923  }
, {  1.132 ,  0.0101311084625  }
, {  1.135 ,  0.0107270560191  }
, {  1.138 ,  0.0113230035757  }
, {  1.141 ,  0.0119189511323  }
, {  1.153 ,  0.0125148986889  }
, {  1.158 ,  0.0131108462455  }
, {  1.195 ,  0.0137067938021  }
, {  1.201 ,  0.0143027413588  }
, {  1.206 ,  0.0148986889154  }
, {  1.212 ,  0.0160905840286  }
, {  1.213 ,  0.0166865315852  }
, {  1.235 ,  0.0172824791418  }
, {  1.249 ,  0.0178784266985  }
, {  1.254 ,  0.0184743742551  }
, {  1.261 ,  0.0190703218117  }
, {  1.267 ,  0.0196662693683  }
, {  1.295 ,  0.0202622169249  }
, {  1.312 ,  0.0208581644815  }
, {  1.321 ,  0.0214541120381  }
, {  1.323 ,  0.0220500595948  }
, {  1.324 ,  0.0226460071514  }
, {  1.332 ,  0.023241954708  }
, {  1.340 ,  0.0238379022646  }
, {  1.349 ,  0.0244338498212  }
, {  1.354 ,  0.0250297973778  }
, {  1.375 ,  0.0256257449344  }
, {  1.376 ,  0.0262216924911  }
, {  1.381 ,  0.0268176400477  }
, {  1.393 ,  0.0274135876043  }
, {  1.401 ,  0.0280095351609  }
, {  1.413 ,  0.0286054827175  }
, {  1.421 ,  0.0292014302741  }
, {  1.425 ,  0.0297973778308  }
, {  1.429 ,  0.0303933253874  }
, {  1.434 ,  0.030989272944  }
, {  1.442 ,  0.0315852205006  }
, {  1.445 ,  0.0321811680572  }
, {  1.454 ,  0.0327771156138  }
, {  1.457 ,  0.0333730631704  }
, {  1.463 ,  0.0339690107271  }
, {  1.465 ,  0.0345649582837  }
, {  1.470 ,  0.0351609058403  }
, {  1.473 ,  0.0357568533969  }
, {  1.475 ,  0.0363528009535  }
, {  1.491 ,  0.0369487485101  }
, {  1.493 ,  0.0375446960667  }
, {  1.497 ,  0.03873659118  }
, {  1.500 ,  0.0393325387366  }
, {  1.501 ,  0.0405244338498  }
, {  1.505 ,  0.0411203814064  }
, {  1.506 ,  0.0423122765197  }
, {  1.511 ,  0.0429082240763  }
, {  1.515 ,  0.0435041716329  }
, {  1.531 ,  0.0441001191895  }
, {  1.534 ,  0.0446960667461  }
, {  1.536 ,  0.0452920143027  }
, {  1.550 ,  0.0458879618594  }
, {  1.554 ,  0.046483909416  }
, {  1.572 ,  0.0470798569726  }
, {  1.580 ,  0.0476758045292  }
, {  1.585 ,  0.0482717520858  }
, {  1.587 ,  0.0488676996424  }
, {  1.610 ,  0.049463647199  }
, {  1.615 ,  0.0500595947557  }
, {  1.616 ,  0.0506555423123  }
, {  1.620 ,  0.0512514898689  }
, {  1.634 ,  0.0524433849821  }
, {  1.637 ,  0.0530393325387  }
, {  1.650 ,  0.0536352800954  }
, {  1.663 ,  0.054231227652  }
, {  1.667 ,  0.0548271752086  }
, {  1.682 ,  0.0554231227652  }
, {  1.684 ,  0.0560190703218  }
, {  1.686 ,  0.0566150178784  }
, {  1.691 ,  0.057210965435  }
, {  1.713 ,  0.0578069129917  }
, {  1.721 ,  0.0584028605483  }
, {  1.726 ,  0.0589988081049  }
, {  1.730 ,  0.0595947556615  }
, {  1.737 ,  0.0601907032181  }
, {  1.752 ,  0.0607866507747  }
, {  1.753 ,  0.0613825983313  }
, {  1.783 ,  0.061978545888  }
, {  1.788 ,  0.0625744934446  }
, {  1.792 ,  0.0631704410012  }
, {  1.804 ,  0.0637663885578  }
, {  1.809 ,  0.0643623361144  }
, {  1.811 ,  0.064958283671  }
, {  1.817 ,  0.0655542312277  }
, {  1.828 ,  0.0661501787843  }
, {  1.836 ,  0.0667461263409  }
, {  1.839 ,  0.0673420738975  }
, {  1.845 ,  0.0679380214541  }
, {  1.871 ,  0.0685339690107  }
, {  1.876 ,  0.0691299165673  }
, {  1.884 ,  0.069725864124  }
, {  1.905 ,  0.0709177592372  }
, {  1.910 ,  0.0721096543504  }
, {  1.920 ,  0.072705601907  }
, {  1.935 ,  0.0733015494636  }
, {  1.957 ,  0.0738974970203  }
, {  1.961 ,  0.0744934445769  }
, {  1.963 ,  0.0750893921335  }
, {  1.967 ,  0.0756853396901  }
, {  1.990 ,  0.0762812872467  }
, {  1.997 ,  0.0768772348033  }
, {  2.001 ,  0.07747318236  }
, {  2.006 ,  0.0780691299166  }
, {  2.010 ,  0.0786650774732  }
, {  2.029 ,  0.0792610250298  }
, {  2.030 ,  0.0798569725864  }
, {  2.041 ,  0.080452920143  }
, {  2.050 ,  0.0810488676996  }
, {  2.072 ,  0.0822407628129  }
, {  2.075 ,  0.0828367103695  }
, {  2.105 ,  0.0834326579261  }
, {  2.109 ,  0.0846245530393  }
, {  2.117 ,  0.0852205005959  }
, {  2.136 ,  0.0858164481526  }
, {  2.138 ,  0.0864123957092  }
, {  2.151 ,  0.0870083432658  }
, {  2.170 ,  0.088200238379  }
, {  2.184 ,  0.0887961859356  }
, {  2.194 ,  0.0893921334923  }
, {  2.195 ,  0.0899880810489  }
, {  2.197 ,  0.0905840286055  }
, {  2.207 ,  0.0911799761621  }
, {  2.210 ,  0.0917759237187  }
, {  2.212 ,  0.0923718712753  }
, {  2.226 ,  0.0929678188319  }
, {  2.240 ,  0.0935637663886  }
, {  2.244 ,  0.0941597139452  }
, {  2.251 ,  0.0947556615018  }
, {  2.260 ,  0.0953516090584  }
, {  2.268 ,  0.095947556615  }
, {  2.277 ,  0.0965435041716  }
, {  2.296 ,  0.0971394517282  }
, {  2.307 ,  0.0977353992849  }
, {  2.332 ,  0.0983313468415  }
, {  2.337 ,  0.0995232419547  }
, {  2.355 ,  0.100119189511  }
, {  2.380 ,  0.100715137068  }
, {  2.383 ,  0.101311084625  }
, {  2.400 ,  0.101907032181  }
, {  2.401 ,  0.102502979738  }
, {  2.415 ,  0.103098927294  }
, {  2.424 ,  0.103694874851  }
, {  2.428 ,  0.104290822408  }
, {  2.440 ,  0.104886769964  }
, {  2.446 ,  0.105482717521  }
, {  2.466 ,  0.106078665077  }
, {  2.467 ,  0.106674612634  }
, {  2.472 ,  0.107270560191  }
, {  2.482 ,  0.107866507747  }
, {  2.492 ,  0.108462455304  }
, {  2.494 ,  0.109058402861  }
, {  2.503 ,  0.110250297974  }
, {  2.533 ,  0.11084624553  }
, {  2.549 ,  0.111442193087  }
, {  2.566 ,  0.112038140644  }
, {  2.600 ,  0.1126340882  }
, {  2.609 ,  0.113230035757  }
, {  2.610 ,  0.113825983313  }
, {  2.616 ,  0.11442193087  }
, {  2.620 ,  0.115017878427  }
, {  2.626 ,  0.115613825983  }
, {  2.631 ,  0.11620977354  }
, {  2.632 ,  0.116805721097  }
, {  2.655 ,  0.118593563766  }
, {  2.690 ,  0.119189511323  }
, {  2.697 ,  0.11978545888  }
, {  2.724 ,  0.120381406436  }
, {  2.726 ,  0.120977353993  }
, {  2.735 ,  0.121573301549  }
, {  2.737 ,  0.122765196663  }
, {  2.745 ,  0.123361144219  }
, {  2.750 ,  0.123957091776  }
, {  2.761 ,  0.124553039333  }
, {  2.770 ,  0.125148986889  }
, {  2.783 ,  0.125744934446  }
, {  2.790 ,  0.126340882002  }
, {  2.797 ,  0.126936829559  }
, {  2.834 ,  0.127532777116  }
, {  2.836 ,  0.128128724672  }
, {  2.874 ,  0.128724672229  }
, {  2.890 ,  0.129320619785  }
, {  2.903 ,  0.129916567342  }
, {  2.938 ,  0.130512514899  }
, {  2.948 ,  0.131108462455  }
, {  2.961 ,  0.131704410012  }
, {  2.975 ,  0.132300357569  }
, {  2.987 ,  0.132896305125  }
, {  2.988 ,  0.133492252682  }
, {  2.995 ,  0.134088200238  }
, {  2.998 ,  0.134684147795  }
, {  3.002 ,  0.135280095352  }
, {  3.005 ,  0.135876042908  }
, {  3.014 ,  0.136471990465  }
, {  3.039 ,  0.137067938021  }
, {  3.052 ,  0.137663885578  }
, {  3.055 ,  0.138259833135  }
, {  3.057 ,  0.138855780691  }
, {  3.067 ,  0.139451728248  }
, {  3.068 ,  0.140047675805  }
, {  3.097 ,  0.140643623361  }
, {  3.108 ,  0.141239570918  }
, {  3.148 ,  0.141835518474  }
, {  3.173 ,  0.142431466031  }
, {  3.205 ,  0.143027413588  }
, {  3.227 ,  0.143623361144  }
, {  3.233 ,  0.144219308701  }
, {  3.238 ,  0.144815256257  }
, {  3.242 ,  0.145411203814  }
, {  3.243 ,  0.146007151371  }
, {  3.244 ,  0.146603098927  }
, {  3.262 ,  0.147199046484  }
, {  3.283 ,  0.147794994041  }
, {  3.293 ,  0.148390941597  }
, {  3.306 ,  0.148986889154  }
, {  3.325 ,  0.14958283671  }
, {  3.364 ,  0.150178784267  }
, {  3.375 ,  0.150774731824  }
, {  3.404 ,  0.15137067938  }
, {  3.407 ,  0.151966626937  }
, {  3.419 ,  0.152562574493  }
, {  3.443 ,  0.15315852205  }
, {  3.445 ,  0.153754469607  }
, {  3.449 ,  0.154350417163  }
, {  3.483 ,  0.15494636472  }
, {  3.488 ,  0.155542312277  }
, {  3.492 ,  0.156138259833  }
, {  3.493 ,  0.15673420739  }
, {  3.497 ,  0.157330154946  }
, {  3.498 ,  0.157926102503  }
, {  3.501 ,  0.15852205006  }
, {  3.514 ,  0.159117997616  }
, {  3.517 ,  0.159713945173  }
, {  3.520 ,  0.160309892729  }
, {  3.522 ,  0.160905840286  }
, {  3.529 ,  0.161501787843  }
, {  3.536 ,  0.162097735399  }
, {  3.564 ,  0.162693682956  }
, {  3.566 ,  0.163289630513  }
, {  3.572 ,  0.163885578069  }
, {  3.574 ,  0.164481525626  }
, {  3.591 ,  0.165077473182  }
, {  3.596 ,  0.165673420739  }
, {  3.603 ,  0.166269368296  }
, {  3.614 ,  0.166865315852  }
, {  3.616 ,  0.167461263409  }
, {  3.625 ,  0.168057210965  }
, {  3.649 ,  0.168653158522  }
, {  3.658 ,  0.169249106079  }
, {  3.666 ,  0.169845053635  }
, {  3.669 ,  0.171036948749  }
, {  3.722 ,  0.171632896305  }
, {  3.723 ,  0.172228843862  }
, {  3.747 ,  0.172824791418  }
, {  3.751 ,  0.173420738975  }
, {  3.755 ,  0.174016686532  }
, {  3.816 ,  0.174612634088  }
, {  3.827 ,  0.175208581645  }
, {  3.843 ,  0.175804529201  }
, {  3.859 ,  0.176400476758  }
, {  3.872 ,  0.176996424315  }
, {  3.873 ,  0.177592371871  }
, {  3.891 ,  0.178188319428  }
, {  3.902 ,  0.178784266985  }
, {  3.920 ,  0.179380214541  }
, {  3.945 ,  0.179976162098  }
, {  3.959 ,  0.180572109654  }
, {  3.961 ,  0.181168057211  }
, {  3.976 ,  0.181764004768  }
, {  3.982 ,  0.182359952324  }
, {  3.984 ,  0.182955899881  }
, {  3.989 ,  0.183551847437  }
, {  3.992 ,  0.184147794994  }
, {  3.998 ,  0.184743742551  }
, {  4.005 ,  0.185339690107  }
, {  4.013 ,  0.185935637664  }
, {  4.017 ,  0.186531585221  }
, {  4.059 ,  0.187127532777  }
, {  4.085 ,  0.187723480334  }
, {  4.088 ,  0.18831942789  }
, {  4.092 ,  0.188915375447  }
, {  4.103 ,  0.189511323004  }
, {  4.112 ,  0.19010727056  }
, {  4.140 ,  0.190703218117  }
, {  4.151 ,  0.191299165673  }
, {  4.170 ,  0.19189511323  }
, {  4.176 ,  0.192491060787  }
, {  4.178 ,  0.193087008343  }
, {  4.183 ,  0.1936829559  }
, {  4.198 ,  0.194874851013  }
, {  4.203 ,  0.19547079857  }
, {  4.208 ,  0.196066746126  }
, {  4.237 ,  0.196662693683  }
, {  4.238 ,  0.19725864124  }
, {  4.239 ,  0.197854588796  }
, {  4.240 ,  0.198450536353  }
, {  4.243 ,  0.199046483909  }
, {  4.298 ,  0.199642431466  }
, {  4.307 ,  0.200238379023  }
, {  4.316 ,  0.200834326579  }
, {  4.326 ,  0.201430274136  }
, {  4.334 ,  0.202026221692  }
, {  4.337 ,  0.202622169249  }
, {  4.360 ,  0.203218116806  }
, {  4.375 ,  0.203814064362  }
, {  4.380 ,  0.204410011919  }
, {  4.384 ,  0.205005959476  }
, {  4.385 ,  0.205601907032  }
, {  4.388 ,  0.206197854589  }
, {  4.393 ,  0.206793802145  }
, {  4.402 ,  0.207389749702  }
, {  4.413 ,  0.207985697259  }
, {  4.420 ,  0.208581644815  }
, {  4.424 ,  0.209177592372  }
, {  4.427 ,  0.209773539928  }
, {  4.433 ,  0.210369487485  }
, {  4.446 ,  0.210965435042  }
, {  4.449 ,  0.211561382598  }
, {  4.454 ,  0.212157330155  }
, {  4.491 ,  0.212753277712  }
, {  4.519 ,  0.213349225268  }
, {  4.548 ,  0.213945172825  }
, {  4.551 ,  0.214541120381  }
, {  4.569 ,  0.215137067938  }
, {  4.586 ,  0.215733015495  }
, {  4.589 ,  0.216924910608  }
, {  4.594 ,  0.217520858164  }
, {  4.617 ,  0.218116805721  }
, {  4.624 ,  0.218712753278  }
, {  4.641 ,  0.219308700834  }
, {  4.666 ,  0.219904648391  }
, {  4.680 ,  0.220500595948  }
, {  4.694 ,  0.221096543504  }
, {  4.699 ,  0.221692491061  }
, {  4.712 ,  0.222288438617  }
, {  4.722 ,  0.222884386174  }
, {  4.730 ,  0.223480333731  }
, {  4.735 ,  0.224076281287  }
, {  4.747 ,  0.2252681764  }
, {  4.751 ,  0.225864123957  }
, {  4.755 ,  0.226460071514  }
, {  4.759 ,  0.22705601907  }
, {  4.771 ,  0.227651966627  }
, {  4.781 ,  0.228247914184  }
, {  4.791 ,  0.22884386174  }
, {  4.806 ,  0.229439809297  }
, {  4.809 ,  0.230035756853  }
, {  4.836 ,  0.23063170441  }
, {  4.841 ,  0.231227651967  }
, {  4.869 ,  0.231823599523  }
, {  4.888 ,  0.23241954708  }
, {  4.901 ,  0.233015494636  }
, {  4.931 ,  0.233611442193  }
, {  4.933 ,  0.23420738975  }
, {  4.935 ,  0.234803337306  }
, {  4.949 ,  0.235399284863  }
, {  4.963 ,  0.23599523242  }
, {  4.967 ,  0.236591179976  }
, {  4.976 ,  0.237187127533  }
, {  4.999 ,  0.237783075089  }
, {  5.007 ,  0.238379022646  }
, {  5.027 ,  0.238974970203  }
, {  5.035 ,  0.239570917759  }
, {  5.044 ,  0.240166865316  }
, {  5.055 ,  0.240762812872  }
, {  5.074 ,  0.241358760429  }
, {  5.080 ,  0.241954707986  }
, {  5.090 ,  0.242550655542  }
, {  5.114 ,  0.243146603099  }
, {  5.115 ,  0.243742550656  }
, {  5.122 ,  0.244338498212  }
, {  5.126 ,  0.244934445769  }
, {  5.133 ,  0.245530393325  }
, {  5.138 ,  0.246126340882  }
, {  5.163 ,  0.246722288439  }
, {  5.170 ,  0.247318235995  }
, {  5.171 ,  0.247914183552  }
, {  5.175 ,  0.248510131108  }
, {  5.186 ,  0.249106078665  }
, {  5.201 ,  0.249702026222  }
, {  5.230 ,  0.250297973778  }
, {  5.236 ,  0.250893921335  }
, {  5.286 ,  0.251489868892  }
, {  5.305 ,  0.252085816448  }
, {  5.310 ,  0.252681764005  }
, {  5.332 ,  0.253277711561  }
, {  5.346 ,  0.253873659118  }
, {  5.353 ,  0.254469606675  }
, {  5.399 ,  0.255065554231  }
, {  5.407 ,  0.255661501788  }
, {  5.414 ,  0.256257449344  }
, {  5.417 ,  0.256853396901  }
, {  5.423 ,  0.257449344458  }
, {  5.424 ,  0.258045292014  }
, {  5.436 ,  0.258641239571  }
, {  5.444 ,  0.259237187128  }
, {  5.455 ,  0.259833134684  }
, {  5.474 ,  0.260429082241  }
, {  5.478 ,  0.261025029797  }
, {  5.492 ,  0.261620977354  }
, {  5.511 ,  0.262216924911  }
, {  5.533 ,  0.262812872467  }
, {  5.540 ,  0.263408820024  }
, {  5.559 ,  0.26400476758  }
, {  5.560 ,  0.264600715137  }
, {  5.562 ,  0.265196662694  }
, {  5.563 ,  0.26579261025  }
, {  5.568 ,  0.266388557807  }
, {  5.582 ,  0.26758045292  }
, {  5.618 ,  0.268176400477  }
, {  5.652 ,  0.268772348033  }
, {  5.677 ,  0.26936829559  }
, {  5.694 ,  0.269964243147  }
, {  5.703 ,  0.270560190703  }
, {  5.733 ,  0.27115613826  }
, {  5.746 ,  0.271752085816  }
, {  5.836 ,  0.272348033373  }
, {  5.846 ,  0.27294398093  }
, {  5.852 ,  0.273539928486  }
, {  5.887 ,  0.274135876043  }
, {  5.906 ,  0.2747318236  }
, {  5.925 ,  0.275327771156  }
, {  5.933 ,  0.275923718713  }
, {  5.934 ,  0.276519666269  }
, {  5.964 ,  0.277115613826  }
, {  5.991 ,  0.277711561383  }
, {  6.001 ,  0.278307508939  }
, {  6.009 ,  0.278903456496  }
, {  6.028 ,  0.279499404052  }
, {  6.038 ,  0.280095351609  }
, {  6.053 ,  0.280691299166  }
, {  6.058 ,  0.281287246722  }
, {  6.060 ,  0.281883194279  }
, {  6.088 ,  0.282479141836  }
, {  6.102 ,  0.283075089392  }
, {  6.108 ,  0.283671036949  }
, {  6.109 ,  0.284266984505  }
, {  6.119 ,  0.284862932062  }
, {  6.152 ,  0.285458879619  }
, {  6.174 ,  0.286054827175  }
, {  6.203 ,  0.286650774732  }
, {  6.217 ,  0.287246722288  }
, {  6.233 ,  0.287842669845  }
, {  6.234 ,  0.289034564958  }
, {  6.237 ,  0.289630512515  }
, {  6.253 ,  0.290226460072  }
, {  6.278 ,  0.290822407628  }
, {  6.302 ,  0.291418355185  }
, {  6.314 ,  0.292014302741  }
, {  6.329 ,  0.292610250298  }
, {  6.361 ,  0.293206197855  }
, {  6.376 ,  0.293802145411  }
, {  6.394 ,  0.294398092968  }
, {  6.397 ,  0.294994040524  }
, {  6.423 ,  0.295589988081  }
, {  6.432 ,  0.296185935638  }
, {  6.437 ,  0.296781883194  }
, {  6.439 ,  0.297377830751  }
, {  6.451 ,  0.297973778308  }
, {  6.468 ,  0.298569725864  }
, {  6.474 ,  0.299165673421  }
, {  6.519 ,  0.299761620977  }
, {  6.526 ,  0.300357568534  }
, {  6.531 ,  0.300953516091  }
, {  6.532 ,  0.301549463647  }
, {  6.535 ,  0.302145411204  }
, {  6.595 ,  0.30274135876  }
, {  6.598 ,  0.303337306317  }
, {  6.622 ,  0.303933253874  }
, {  6.633 ,  0.30452920143  }
, {  6.634 ,  0.305125148987  }
, {  6.663 ,  0.305721096544  }
, {  6.682 ,  0.3063170441  }
, {  6.690 ,  0.306912991657  }
, {  6.701 ,  0.307508939213  }
, {  6.741 ,  0.30810488677  }
, {  6.745 ,  0.308700834327  }
, {  6.783 ,  0.309296781883  }
, {  6.788 ,  0.30989272944  }
, {  6.794 ,  0.310488676996  }
, {  6.815 ,  0.311084624553  }
, {  6.816 ,  0.31168057211  }
, {  6.821 ,  0.312276519666  }
, {  6.845 ,  0.312872467223  }
, {  6.868 ,  0.313468414779  }
, {  6.874 ,  0.314064362336  }
, {  6.878 ,  0.314660309893  }
, {  6.961 ,  0.315256257449  }
, {  7.019 ,  0.315852205006  }
, {  7.051 ,  0.316448152563  }
, {  7.061 ,  0.317044100119  }
, {  7.088 ,  0.317640047676  }
, {  7.111 ,  0.318235995232  }
, {  7.126 ,  0.318831942789  }
, {  7.155 ,  0.319427890346  }
, {  7.174 ,  0.320023837902  }
, {  7.181 ,  0.320619785459  }
, {  7.258 ,  0.321215733015  }
, {  7.278 ,  0.321811680572  }
, {  7.305 ,  0.322407628129  }
, {  7.308 ,  0.323003575685  }
, {  7.327 ,  0.323599523242  }
, {  7.361 ,  0.324195470799  }
, {  7.363 ,  0.324791418355  }
, {  7.389 ,  0.325387365912  }
, {  7.429 ,  0.325983313468  }
, {  7.441 ,  0.326579261025  }
, {  7.470 ,  0.327175208582  }
, {  7.473 ,  0.327771156138  }
, {  7.486 ,  0.328367103695  }
, {  7.520 ,  0.328963051251  }
, {  7.529 ,  0.329558998808  }
, {  7.552 ,  0.330154946365  }
, {  7.560 ,  0.330750893921  }
, {  7.582 ,  0.331346841478  }
, {  7.596 ,  0.331942789035  }
, {  7.604 ,  0.332538736591  }
, {  7.605 ,  0.333134684148  }
, {  7.651 ,  0.333730631704  }
, {  7.658 ,  0.334326579261  }
, {  7.691 ,  0.334922526818  }
, {  7.692 ,  0.335518474374  }
, {  7.705 ,  0.336114421931  }
, {  7.719 ,  0.336710369487  }
, {  7.731 ,  0.337306317044  }
, {  7.738 ,  0.337902264601  }
, {  7.739 ,  0.338498212157  }
, {  7.760 ,  0.339094159714  }
, {  7.786 ,  0.339690107271  }
, {  7.792 ,  0.340286054827  }
, {  7.795 ,  0.340882002384  }
, {  7.817 ,  0.34147794994  }
, {  7.821 ,  0.342073897497  }
, {  7.825 ,  0.342669845054  }
, {  7.827 ,  0.34326579261  }
, {  7.830 ,  0.343861740167  }
, {  7.839 ,  0.344457687723  }
, {  7.847 ,  0.34505363528  }
, {  7.867 ,  0.345649582837  }
, {  7.869 ,  0.346245530393  }
, {  7.870 ,  0.34684147795  }
, {  7.886 ,  0.347437425507  }
, {  7.949 ,  0.348033373063  }
, {  7.966 ,  0.34862932062  }
, {  7.971 ,  0.349225268176  }
, {  7.996 ,  0.349821215733  }
, {  8.000 ,  0.35041716329  }
, {  8.049 ,  0.351013110846  }
, {  8.062 ,  0.351609058403  }
, {  8.067 ,  0.352205005959  }
, {  8.070 ,  0.352800953516  }
, {  8.077 ,  0.353396901073  }
, {  8.081 ,  0.353992848629  }
, {  8.083 ,  0.354588796186  }
, {  8.126 ,  0.355184743743  }
, {  8.160 ,  0.355780691299  }
, {  8.175 ,  0.356376638856  }
, {  8.200 ,  0.356972586412  }
, {  8.217 ,  0.357568533969  }
, {  8.231 ,  0.358164481526  }
, {  8.257 ,  0.358760429082  }
, {  8.322 ,  0.359356376639  }
, {  8.323 ,  0.359952324195  }
, {  8.333 ,  0.360548271752  }
, {  8.335 ,  0.361144219309  }
, {  8.344 ,  0.361740166865  }
, {  8.359 ,  0.362336114422  }
, {  8.434 ,  0.362932061979  }
, {  8.453 ,  0.363528009535  }
, {  8.486 ,  0.364123957092  }
, {  8.496 ,  0.364719904648  }
, {  8.514 ,  0.365315852205  }
, {  8.519 ,  0.365911799762  }
, {  8.551 ,  0.366507747318  }
, {  8.644 ,  0.367103694875  }
, {  8.688 ,  0.367699642431  }
, {  8.709 ,  0.368295589988  }
, {  8.711 ,  0.368891537545  }
, {  8.749 ,  0.369487485101  }
, {  8.755 ,  0.370083432658  }
, {  8.810 ,  0.370679380215  }
, {  8.819 ,  0.371275327771  }
, {  8.830 ,  0.371871275328  }
, {  8.864 ,  0.372467222884  }
, {  8.875 ,  0.373063170441  }
, {  8.913 ,  0.373659117998  }
, {  8.932 ,  0.374255065554  }
, {  8.958 ,  0.374851013111  }
, {  8.993 ,  0.375446960667  }
, {  9.018 ,  0.376042908224  }
, {  9.021 ,  0.376638855781  }
, {  9.114 ,  0.377234803337  }
, {  9.127 ,  0.377830750894  }
, {  9.137 ,  0.378426698451  }
, {  9.161 ,  0.379022646007  }
, {  9.174 ,  0.379618593564  }
, {  9.192 ,  0.38021454112  }
, {  9.193 ,  0.380810488677  }
, {  9.215 ,  0.381406436234  }
, {  9.293 ,  0.38200238379  }
, {  9.307 ,  0.382598331347  }
, {  9.315 ,  0.383194278903  }
, {  9.323 ,  0.38379022646  }
, {  9.402 ,  0.384386174017  }
, {  9.418 ,  0.384982121573  }
, {  9.451 ,  0.38557806913  }
, {  9.487 ,  0.386174016687  }
, {  9.521 ,  0.386769964243  }
, {  9.588 ,  0.3873659118  }
, {  9.600 ,  0.387961859356  }
, {  9.607 ,  0.388557806913  }
, {  9.608 ,  0.38915375447  }
, {  9.656 ,  0.389749702026  }
, {  9.666 ,  0.390345649583  }
, {  9.727 ,  0.390941597139  }
, {  9.769 ,  0.391537544696  }
, {  9.794 ,  0.392133492253  }
, {  9.797 ,  0.392729439809  }
, {  9.807 ,  0.393325387366  }
, {  9.823 ,  0.393921334923  }
, {  9.844 ,  0.394517282479  }
, {  9.860 ,  0.395113230036  }
, {  9.864 ,  0.395709177592  }
, {  9.895 ,  0.396305125149  }
, {  9.915 ,  0.396901072706  }
, {  9.927 ,  0.397497020262  }
, {  9.929 ,  0.398092967819  }
, {  9.943 ,  0.398688915375  }
, {  9.982 ,  0.399284862932  }
, {  10.060 ,  0.399880810489  }
, {  10.091 ,  0.400476758045  }
, {  10.096 ,  0.401072705602  }
, {  10.104 ,  0.401668653159  }
, {  10.112 ,  0.402264600715  }
, {  10.120 ,  0.402860548272  }
, {  10.140 ,  0.403456495828  }
, {  10.146 ,  0.404052443385  }
, {  10.231 ,  0.404648390942  }
, {  10.309 ,  0.405244338498  }
, {  10.396 ,  0.405840286055  }
, {  10.401 ,  0.406436233611  }
, {  10.404 ,  0.407032181168  }
, {  10.454 ,  0.407628128725  }
, {  10.489 ,  0.408224076281  }
, {  10.505 ,  0.408820023838  }
, {  10.595 ,  0.409415971395  }
, {  10.603 ,  0.410011918951  }
, {  10.609 ,  0.410607866508  }
, {  10.627 ,  0.411203814064  }
, {  10.690 ,  0.411799761621  }
, {  10.749 ,  0.412395709178  }
, {  10.754 ,  0.412991656734  }
, {  10.793 ,  0.413587604291  }
, {  10.823 ,  0.414183551847  }
, {  10.838 ,  0.414779499404  }
, {  10.870 ,  0.415375446961  }
, {  10.887 ,  0.415971394517  }
, {  10.911 ,  0.416567342074  }
, {  10.931 ,  0.417163289631  }
, {  10.948 ,  0.417759237187  }
, {  10.955 ,  0.4189511323  }
, {  10.990 ,  0.419547079857  }
, {  11.016 ,  0.420143027414  }
, {  11.024 ,  0.42073897497  }
, {  11.026 ,  0.421334922527  }
, {  11.029 ,  0.421930870083  }
, {  11.040 ,  0.42252681764  }
, {  11.078 ,  0.423122765197  }
, {  11.091 ,  0.423718712753  }
, {  11.100 ,  0.42431466031  }
, {  11.120 ,  0.425506555423  }
, {  11.204 ,  0.42610250298  }
, {  11.226 ,  0.426698450536  }
, {  11.238 ,  0.427294398093  }
, {  11.241 ,  0.42789034565  }
, {  11.304 ,  0.428486293206  }
, {  11.312 ,  0.429082240763  }
, {  11.321 ,  0.429678188319  }
, {  11.349 ,  0.430274135876  }
, {  11.353 ,  0.430870083433  }
, {  11.357 ,  0.431466030989  }
, {  11.360 ,  0.432061978546  }
, {  11.414 ,  0.432657926103  }
, {  11.436 ,  0.433253873659  }
, {  11.441 ,  0.433849821216  }
, {  11.463 ,  0.434445768772  }
, {  11.469 ,  0.435041716329  }
, {  11.478 ,  0.435637663886  }
, {  11.482 ,  0.436233611442  }
, {  11.483 ,  0.436829558999  }
, {  11.484 ,  0.437425506555  }
, {  11.493 ,  0.438021454112  }
, {  11.500 ,  0.438617401669  }
, {  11.536 ,  0.439213349225  }
, {  11.681 ,  0.439809296782  }
, {  11.712 ,  0.440405244338  }
, {  11.721 ,  0.441001191895  }
, {  11.768 ,  0.441597139452  }
, {  11.787 ,  0.442193087008  }
, {  11.802 ,  0.442789034565  }
, {  11.866 ,  0.443384982122  }
, {  11.892 ,  0.443980929678  }
, {  11.983 ,  0.444576877235  }
, {  12.009 ,  0.445172824791  }
, {  12.025 ,  0.445768772348  }
, {  12.260 ,  0.446364719905  }
, {  12.268 ,  0.446960667461  }
, {  12.372 ,  0.447556615018  }
, {  12.377 ,  0.448152562574  }
, {  12.429 ,  0.448748510131  }
, {  12.433 ,  0.449344457688  }
, {  12.449 ,  0.449940405244  }
, {  12.495 ,  0.450536352801  }
, {  12.543 ,  0.451132300358  }
, {  12.568 ,  0.451728247914  }
, {  12.575 ,  0.452324195471  }
, {  12.584 ,  0.453516090584  }
, {  12.598 ,  0.454112038141  }
, {  12.613 ,  0.454707985697  }
, {  12.634 ,  0.455303933254  }
, {  12.648 ,  0.45589988081  }
, {  12.742 ,  0.456495828367  }
, {  12.753 ,  0.457091775924  }
, {  12.754 ,  0.45768772348  }
, {  12.785 ,  0.458283671037  }
, {  12.816 ,  0.458879618594  }
, {  12.823 ,  0.45947556615  }
, {  12.872 ,  0.460071513707  }
, {  12.904 ,  0.460667461263  }
, {  12.940 ,  0.46126340882  }
, {  12.957 ,  0.461859356377  }
, {  12.989 ,  0.462455303933  }
, {  12.998 ,  0.46305125149  }
, {  13.050 ,  0.463647199046  }
, {  13.067 ,  0.464243146603  }
, {  13.070 ,  0.46483909416  }
, {  13.088 ,  0.465435041716  }
, {  13.091 ,  0.466030989273  }
, {  13.095 ,  0.46662693683  }
, {  13.104 ,  0.467222884386  }
, {  13.177 ,  0.467818831943  }
, {  13.195 ,  0.468414779499  }
, {  13.290 ,  0.469010727056  }
, {  13.334 ,  0.469606674613  }
, {  13.342 ,  0.470202622169  }
, {  13.344 ,  0.470798569726  }
, {  13.346 ,  0.471394517282  }
, {  13.367 ,  0.471990464839  }
, {  13.371 ,  0.472586412396  }
, {  13.429 ,  0.473182359952  }
, {  13.453 ,  0.473778307509  }
, {  13.479 ,  0.474374255066  }
, {  13.495 ,  0.474970202622  }
, {  13.539 ,  0.475566150179  }
, {  13.563 ,  0.476162097735  }
, {  13.568 ,  0.476758045292  }
, {  13.577 ,  0.477353992849  }
, {  13.693 ,  0.477949940405  }
, {  13.764 ,  0.479141835518  }
, {  13.801 ,  0.479737783075  }
, {  13.846 ,  0.480333730632  }
, {  13.882 ,  0.480929678188  }
, {  13.940 ,  0.481525625745  }
, {  13.958 ,  0.482121573302  }
, {  14.028 ,  0.482717520858  }
, {  14.032 ,  0.483313468415  }
, {  14.144 ,  0.483909415971  }
, {  14.199 ,  0.484505363528  }
, {  14.205 ,  0.485101311085  }
, {  14.322 ,  0.485697258641  }
, {  14.383 ,  0.486293206198  }
, {  14.394 ,  0.486889153754  }
, {  14.459 ,  0.487485101311  }
, {  14.558 ,  0.488081048868  }
, {  14.578 ,  0.488676996424  }
, {  14.639 ,  0.489272943981  }
, {  14.696 ,  0.489868891538  }
, {  14.789 ,  0.490464839094  }
, {  14.792 ,  0.491060786651  }
, {  14.808 ,  0.491656734207  }
, {  14.849 ,  0.492252681764  }
, {  14.852 ,  0.492848629321  }
, {  14.853 ,  0.493444576877  }
, {  14.890 ,  0.494040524434  }
, {  14.937 ,  0.49463647199  }
, {  14.939 ,  0.495232419547  }
, {  14.954 ,  0.495828367104  }
, {  15.027 ,  0.49642431466  }
, {  15.041 ,  0.497020262217  }
, {  15.062 ,  0.497616209774  }
, {  15.171 ,  0.49821215733  }
, {  15.222 ,  0.498808104887  }
, {  15.315 ,  0.499404052443  }
, {  15.318 ,  0.5  }
, {  15.349 ,  0.500595947557  }
, {  15.350 ,  0.501191895113  }
, {  15.398 ,  0.50178784267  }
, {  15.429 ,  0.502383790226  }
, {  15.569 ,  0.502979737783  }
, {  15.624 ,  0.50357568534  }
, {  15.635 ,  0.504171632896  }
, {  15.661 ,  0.504767580453  }
, {  15.701 ,  0.50536352801  }
, {  15.718 ,  0.505959475566  }
, {  15.740 ,  0.506555423123  }
, {  15.780 ,  0.507747318236  }
, {  15.826 ,  0.508343265793  }
, {  15.844 ,  0.508939213349  }
, {  15.852 ,  0.509535160906  }
, {  15.869 ,  0.510131108462  }
, {  15.901 ,  0.510727056019  }
, {  16.055 ,  0.511323003576  }
, {  16.067 ,  0.511918951132  }
, {  16.084 ,  0.512514898689  }
, {  16.132 ,  0.513110846246  }
, {  16.192 ,  0.513706793802  }
, {  16.209 ,  0.514302741359  }
, {  16.242 ,  0.514898688915  }
, {  16.300 ,  0.515494636472  }
, {  16.310 ,  0.516090584029  }
, {  16.481 ,  0.516686531585  }
, {  16.600 ,  0.517282479142  }
, {  16.628 ,  0.517878426698  }
, {  16.651 ,  0.518474374255  }
, {  16.677 ,  0.519070321812  }
, {  16.705 ,  0.519666269368  }
, {  16.759 ,  0.520262216925  }
, {  16.864 ,  0.520858164482  }
, {  16.877 ,  0.521454112038  }
, {  16.908 ,  0.522050059595  }
, {  16.963 ,  0.522646007151  }
, {  16.968 ,  0.523241954708  }
, {  17.067 ,  0.523837902265  }
, {  17.102 ,  0.524433849821  }
, {  17.139 ,  0.525029797378  }
, {  17.157 ,  0.525625744934  }
, {  17.200 ,  0.526221692491  }
, {  17.232 ,  0.526817640048  }
, {  17.234 ,  0.527413587604  }
, {  17.276 ,  0.528009535161  }
, {  17.292 ,  0.528605482718  }
, {  17.319 ,  0.529201430274  }
, {  17.442 ,  0.529797377831  }
, {  17.526 ,  0.530393325387  }
, {  17.604 ,  0.530989272944  }
, {  17.657 ,  0.531585220501  }
, {  17.667 ,  0.532181168057  }
, {  17.769 ,  0.532777115614  }
, {  17.796 ,  0.53337306317  }
, {  17.813 ,  0.533969010727  }
, {  17.819 ,  0.534564958284  }
, {  17.936 ,  0.53516090584  }
, {  17.946 ,  0.535756853397  }
, {  17.971 ,  0.536352800954  }
, {  17.989 ,  0.53694874851  }
, {  18.002 ,  0.537544696067  }
, {  18.049 ,  0.538140643623  }
, {  18.054 ,  0.53873659118  }
, {  18.074 ,  0.539332538737  }
, {  18.093 ,  0.539928486293  }
, {  18.142 ,  0.54052443385  }
, {  18.342 ,  0.541120381406  }
, {  18.404 ,  0.541716328963  }
, {  18.479 ,  0.54231227652  }
, {  18.591 ,  0.542908224076  }
, {  18.832 ,  0.543504171633  }
, {  18.849 ,  0.54410011919  }
, {  18.872 ,  0.544696066746  }
, {  18.893 ,  0.545292014303  }
, {  19.033 ,  0.545887961859  }
, {  19.071 ,  0.546483909416  }
, {  19.138 ,  0.547079856973  }
, {  19.155 ,  0.547675804529  }
, {  19.177 ,  0.548271752086  }
, {  19.283 ,  0.548867699642  }
, {  19.326 ,  0.549463647199  }
, {  19.377 ,  0.550059594756  }
, {  19.462 ,  0.550655542312  }
, {  19.573 ,  0.551251489869  }
, {  19.577 ,  0.551847437426  }
, {  19.586 ,  0.552443384982  }
, {  19.593 ,  0.553039332539  }
, {  19.619 ,  0.553635280095  }
, {  19.704 ,  0.554231227652  }
, {  19.792 ,  0.554827175209  }
, {  19.821 ,  0.555423122765  }
, {  19.856 ,  0.556019070322  }
, {  19.956 ,  0.556615017878  }
, {  19.971 ,  0.557210965435  }
, {  20.009 ,  0.557806912992  }
, {  20.063 ,  0.558402860548  }
, {  20.194 ,  0.558998808105  }
, {  20.243 ,  0.559594755662  }
, {  20.258 ,  0.560190703218  }
, {  20.350 ,  0.560786650775  }
, {  20.360 ,  0.561382598331  }
, {  20.389 ,  0.561978545888  }
, {  20.502 ,  0.562574493445  }
, {  20.516 ,  0.563170441001  }
, {  20.530 ,  0.563766388558  }
, {  20.584 ,  0.564362336114  }
, {  20.609 ,  0.564958283671  }
, {  20.617 ,  0.565554231228  }
, {  20.785 ,  0.566150178784  }
, {  20.807 ,  0.566746126341  }
, {  20.832 ,  0.567342073897  }
, {  20.908 ,  0.567938021454  }
, {  20.914 ,  0.568533969011  }
, {  20.922 ,  0.569129916567  }
, {  20.985 ,  0.569725864124  }
, {  20.994 ,  0.570321811681  }
, {  21.008 ,  0.570917759237  }
, {  21.057 ,  0.571513706794  }
, {  21.188 ,  0.57210965435  }
, {  21.336 ,  0.572705601907  }
, {  21.380 ,  0.573301549464  }
, {  21.397 ,  0.57389749702  }
, {  21.400 ,  0.574493444577  }
, {  21.582 ,  0.575089392133  }
, {  21.624 ,  0.57568533969  }
, {  21.631 ,  0.576281287247  }
, {  21.645 ,  0.576877234803  }
, {  21.654 ,  0.57747318236  }
, {  21.710 ,  0.578069129917  }
, {  21.759 ,  0.578665077473  }
, {  21.847 ,  0.57926102503  }
, {  21.907 ,  0.579856972586  }
, {  21.914 ,  0.580452920143  }
, {  21.976 ,  0.5810488677  }
, {  21.981 ,  0.581644815256  }
, {  21.986 ,  0.582240762813  }
, {  22.000 ,  0.582836710369  }
, {  22.012 ,  0.583432657926  }
, {  22.019 ,  0.584028605483  }
, {  22.060 ,  0.584624553039  }
, {  22.076 ,  0.585220500596  }
, {  22.135 ,  0.585816448153  }
, {  22.298 ,  0.586412395709  }
, {  22.302 ,  0.587008343266  }
, {  22.311 ,  0.587604290822  }
, {  22.391 ,  0.588200238379  }
, {  22.569 ,  0.588796185936  }
, {  22.582 ,  0.589392133492  }
, {  22.618 ,  0.589988081049  }
, {  22.655 ,  0.590584028605  }
, {  22.684 ,  0.591179976162  }
, {  22.705 ,  0.591775923719  }
, {  22.723 ,  0.592371871275  }
, {  22.871 ,  0.592967818832  }
, {  23.032 ,  0.593563766389  }
, {  23.080 ,  0.594159713945  }
, {  23.099 ,  0.594755661502  }
, {  23.537 ,  0.595351609058  }
, {  23.640 ,  0.595947556615  }
, {  23.693 ,  0.596543504172  }
, {  23.702 ,  0.597139451728  }
, {  23.782 ,  0.597735399285  }
, {  23.951 ,  0.598331346841  }
, {  24.256 ,  0.598927294398  }
, {  24.304 ,  0.599523241955  }
, {  24.332 ,  0.600119189511  }
, {  24.405 ,  0.600715137068  }
, {  24.484 ,  0.601311084625  }
, {  24.527 ,  0.601907032181  }
, {  24.559 ,  0.602502979738  }
, {  24.666 ,  0.603098927294  }
, {  24.690 ,  0.603694874851  }
, {  24.737 ,  0.604290822408  }
, {  24.756 ,  0.604886769964  }
, {  24.763 ,  0.605482717521  }
, {  24.784 ,  0.606674612634  }
, {  24.790 ,  0.607270560191  }
, {  24.921 ,  0.607866507747  }
, {  24.929 ,  0.608462455304  }
, {  25.014 ,  0.609058402861  }
, {  25.046 ,  0.609654350417  }
, {  25.119 ,  0.610250297974  }
, {  25.307 ,  0.61084624553  }
, {  25.394 ,  0.611442193087  }
, {  25.664 ,  0.612038140644  }
, {  25.750 ,  0.6126340882  }
, {  25.852 ,  0.613230035757  }
, {  25.906 ,  0.613825983313  }
, {  25.912 ,  0.61442193087  }
, {  25.950 ,  0.615017878427  }
, {  26.060 ,  0.615613825983  }
, {  26.241 ,  0.61620977354  }
, {  26.405 ,  0.616805721097  }
, {  26.442 ,  0.617401668653  }
, {  26.462 ,  0.61799761621  }
, {  26.563 ,  0.618593563766  }
, {  26.653 ,  0.619189511323  }
, {  26.731 ,  0.61978545888  }
, {  26.838 ,  0.620381406436  }
, {  26.848 ,  0.620977353993  }
, {  26.868 ,  0.621573301549  }
, {  26.921 ,  0.622169249106  }
, {  26.993 ,  0.622765196663  }
, {  27.032 ,  0.623361144219  }
, {  27.141 ,  0.623957091776  }
, {  27.252 ,  0.624553039333  }
, {  27.440 ,  0.625148986889  }
, {  27.662 ,  0.625744934446  }
, {  27.713 ,  0.626340882002  }
, {  27.725 ,  0.626936829559  }
, {  27.873 ,  0.627532777116  }
, {  27.896 ,  0.628128724672  }
, {  27.921 ,  0.628724672229  }
, {  27.957 ,  0.629320619785  }
, {  27.977 ,  0.629916567342  }
, {  28.026 ,  0.630512514899  }
, {  28.061 ,  0.631108462455  }
, {  28.102 ,  0.631704410012  }
, {  28.412 ,  0.632300357569  }
, {  28.413 ,  0.632896305125  }
, {  28.415 ,  0.633492252682  }
, {  28.432 ,  0.634088200238  }
, {  28.506 ,  0.634684147795  }
, {  28.825 ,  0.635280095352  }
, {  28.942 ,  0.635876042908  }
, {  28.951 ,  0.636471990465  }
, {  28.994 ,  0.637067938021  }
, {  29.111 ,  0.637663885578  }
, {  29.169 ,  0.638259833135  }
, {  29.183 ,  0.638855780691  }
, {  29.202 ,  0.639451728248  }
, {  29.309 ,  0.640047675805  }
, {  29.380 ,  0.640643623361  }
, {  29.437 ,  0.641239570918  }
, {  29.546 ,  0.641835518474  }
, {  29.635 ,  0.642431466031  }
, {  29.986 ,  0.643027413588  }
, {  30.025 ,  0.643623361144  }
, {  30.069 ,  0.644219308701  }
, {  30.113 ,  0.644815256257  }
, {  30.241 ,  0.645411203814  }
, {  30.282 ,  0.646007151371  }
, {  30.390 ,  0.646603098927  }
, {  30.563 ,  0.647199046484  }
, {  30.624 ,  0.647794994041  }
, {  31.021 ,  0.648390941597  }
, {  31.192 ,  0.648986889154  }
, {  31.202 ,  0.64958283671  }
, {  31.309 ,  0.650178784267  }
, {  31.424 ,  0.650774731824  }
, {  31.642 ,  0.65137067938  }
, {  31.652 ,  0.651966626937  }
, {  31.736 ,  0.652562574493  }
, {  31.776 ,  0.65315852205  }
, {  31.801 ,  0.653754469607  }
, {  31.876 ,  0.654350417163  }
, {  32.106 ,  0.65494636472  }
, {  32.117 ,  0.655542312277  }
, {  32.347 ,  0.656138259833  }
, {  32.435 ,  0.65673420739  }
, {  32.550 ,  0.657330154946  }
, {  32.661 ,  0.657926102503  }
, {  32.683 ,  0.65852205006  }
, {  32.696 ,  0.659117997616  }
, {  32.717 ,  0.659713945173  }
, {  32.725 ,  0.660309892729  }
, {  32.815 ,  0.660905840286  }
, {  33.016 ,  0.661501787843  }
, {  33.142 ,  0.662097735399  }
, {  33.190 ,  0.662693682956  }
, {  33.248 ,  0.663289630513  }
, {  33.259 ,  0.663885578069  }
, {  33.295 ,  0.664481525626  }
, {  33.298 ,  0.665077473182  }
, {  33.777 ,  0.665673420739  }
, {  33.858 ,  0.666269368296  }
, {  33.969 ,  0.666865315852  }
, {  34.005 ,  0.667461263409  }
, {  34.041 ,  0.668057210965  }
, {  34.081 ,  0.668653158522  }
, {  34.252 ,  0.669249106079  }
, {  34.389 ,  0.669845053635  }
, {  34.403 ,  0.670441001192  }
, {  34.413 ,  0.671036948749  }
, {  34.429 ,  0.671632896305  }
, {  34.536 ,  0.672228843862  }
, {  34.634 ,  0.672824791418  }
, {  34.733 ,  0.673420738975  }
, {  34.894 ,  0.674016686532  }
, {  34.963 ,  0.674612634088  }
, {  35.067 ,  0.675208581645  }
, {  35.228 ,  0.675804529201  }
, {  35.251 ,  0.676400476758  }
, {  35.516 ,  0.676996424315  }
, {  35.559 ,  0.677592371871  }
, {  35.588 ,  0.678188319428  }
, {  35.645 ,  0.678784266985  }
, {  35.812 ,  0.679380214541  }
, {  36.324 ,  0.679976162098  }
, {  36.446 ,  0.680572109654  }
, {  36.687 ,  0.681168057211  }
, {  36.833 ,  0.681764004768  }
, {  36.898 ,  0.682359952324  }
, {  36.969 ,  0.682955899881  }
, {  37.396 ,  0.683551847437  }
, {  37.473 ,  0.684147794994  }
, {  37.638 ,  0.684743742551  }
, {  37.852 ,  0.685339690107  }
, {  37.909 ,  0.685935637664  }
, {  37.963 ,  0.686531585221  }
, {  38.204 ,  0.687127532777  }
, {  38.440 ,  0.687723480334  }
, {  38.444 ,  0.68831942789  }
, {  38.628 ,  0.688915375447  }
, {  38.722 ,  0.689511323004  }
, {  39.077 ,  0.69010727056  }
, {  39.139 ,  0.690703218117  }
, {  39.225 ,  0.691299165673  }
, {  39.282 ,  0.69189511323  }
, {  39.320 ,  0.692491060787  }
, {  39.467 ,  0.693087008343  }
, {  39.483 ,  0.6936829559  }
, {  39.561 ,  0.694278903456  }
, {  39.600 ,  0.694874851013  }
, {  39.870 ,  0.69547079857  }
, {  40.030 ,  0.696066746126  }
, {  40.350 ,  0.696662693683  }
, {  40.601 ,  0.69725864124  }
, {  40.634 ,  0.697854588796  }
, {  40.716 ,  0.698450536353  }
, {  40.981 ,  0.699046483909  }
, {  41.105 ,  0.699642431466  }
, {  41.165 ,  0.700238379023  }
, {  41.254 ,  0.700834326579  }
, {  41.454 ,  0.701430274136  }
, {  41.638 ,  0.702026221692  }
, {  41.741 ,  0.702622169249  }
, {  41.805 ,  0.703218116806  }
, {  41.993 ,  0.703814064362  }
, {  42.365 ,  0.704410011919  }
, {  42.672 ,  0.705005959476  }
, {  42.755 ,  0.705601907032  }
, {  42.814 ,  0.706197854589  }
, {  42.876 ,  0.706793802145  }
, {  42.937 ,  0.707389749702  }
, {  43.028 ,  0.707985697259  }
, {  43.308 ,  0.708581644815  }
, {  43.529 ,  0.709177592372  }
, {  43.735 ,  0.709773539928  }
, {  43.860 ,  0.710369487485  }
, {  43.874 ,  0.710965435042  }
, {  44.269 ,  0.711561382598  }
, {  44.573 ,  0.712157330155  }
, {  44.685 ,  0.712753277712  }
, {  44.937 ,  0.713349225268  }
, {  45.031 ,  0.713945172825  }
, {  45.066 ,  0.714541120381  }
, {  45.099 ,  0.715137067938  }
, {  45.167 ,  0.715733015495  }
, {  45.239 ,  0.716328963051  }
, {  45.670 ,  0.716924910608  }
, {  45.683 ,  0.717520858164  }
, {  45.820 ,  0.718116805721  }
, {  46.058 ,  0.718712753278  }
, {  46.109 ,  0.719308700834  }
, {  46.134 ,  0.719904648391  }
, {  46.189 ,  0.720500595948  }
, {  46.498 ,  0.721096543504  }
, {  46.686 ,  0.721692491061  }
, {  46.909 ,  0.722288438617  }
, {  47.013 ,  0.722884386174  }
, {  47.075 ,  0.723480333731  }
, {  47.104 ,  0.724076281287  }
, {  47.137 ,  0.724672228844  }
, {  47.358 ,  0.7252681764  }
, {  47.501 ,  0.725864123957  }
, {  47.902 ,  0.726460071514  }
, {  48.418 ,  0.72705601907  }
, {  48.609 ,  0.727651966627  }
, {  49.126 ,  0.728247914184  }
, {  49.571 ,  0.72884386174  }
, {  49.601 ,  0.729439809297  }
, {  49.667 ,  0.730035756853  }
, {  50.059 ,  0.73063170441  }
, {  50.167 ,  0.731227651967  }
, {  51.136 ,  0.731823599523  }
, {  51.371 ,  0.73241954708  }
, {  51.603 ,  0.733015494636  }
, {  52.075 ,  0.733611442193  }
, {  52.084 ,  0.73420738975  }
, {  52.590 ,  0.734803337306  }
, {  52.913 ,  0.735399284863  }
, {  53.234 ,  0.73599523242  }
, {  53.276 ,  0.736591179976  }
, {  53.328 ,  0.737187127533  }
, {  53.713 ,  0.737783075089  }
, {  54.148 ,  0.738379022646  }
, {  54.244 ,  0.738974970203  }
, {  54.471 ,  0.739570917759  }
, {  55.257 ,  0.740166865316  }
, {  55.361 ,  0.740762812872  }
, {  56.019 ,  0.741358760429  }
, {  56.192 ,  0.741954707986  }
, {  56.377 ,  0.742550655542  }
, {  56.639 ,  0.743146603099  }
, {  57.243 ,  0.743742550656  }
, {  58.009 ,  0.744338498212  }
, {  58.157 ,  0.744934445769  }
, {  58.232 ,  0.745530393325  }
, {  58.316 ,  0.746126340882  }
, {  58.459 ,  0.746722288439  }
, {  59.006 ,  0.747318235995  }
, {  59.100 ,  0.747914183552  }
, {  59.302 ,  0.748510131108  }
, {  59.896 ,  0.749106078665  }
, {  60.078 ,  0.749702026222  }
, {  60.245 ,  0.750297973778  }
, {  61.282 ,  0.750893921335  }
, {  61.341 ,  0.751489868892  }
, {  61.432 ,  0.752085816448  }
, {  61.612 ,  0.752681764005  }
, {  61.656 ,  0.753277711561  }
, {  61.698 ,  0.753873659118  }
, {  61.860 ,  0.754469606675  }
, {  63.497 ,  0.755065554231  }
, {  63.627 ,  0.755661501788  }
, {  63.796 ,  0.756257449344  }
, {  63.814 ,  0.756853396901  }
, {  63.816 ,  0.757449344458  }
, {  63.907 ,  0.758045292014  }
, {  63.919 ,  0.758641239571  }
, {  64.120 ,  0.759237187128  }
, {  64.382 ,  0.759833134684  }
, {  64.923 ,  0.760429082241  }
, {  65.235 ,  0.761025029797  }
, {  65.316 ,  0.761620977354  }
, {  65.322 ,  0.762216924911  }
, {  65.457 ,  0.762812872467  }
, {  65.877 ,  0.763408820024  }
, {  66.128 ,  0.76400476758  }
, {  66.813 ,  0.764600715137  }
, {  66.906 ,  0.765196662694  }
, {  67.477 ,  0.76579261025  }
, {  67.855 ,  0.766388557807  }
, {  67.860 ,  0.766984505364  }
, {  68.240 ,  0.76758045292  }
, {  68.527 ,  0.768176400477  }
, {  69.187 ,  0.768772348033  }
, {  69.462 ,  0.76936829559  }
, {  69.477 ,  0.769964243147  }
, {  69.552 ,  0.770560190703  }
, {  69.796 ,  0.77115613826  }
, {  70.049 ,  0.771752085816  }
, {  70.387 ,  0.772348033373  }
, {  71.107 ,  0.77294398093  }
, {  71.664 ,  0.773539928486  }
, {  71.856 ,  0.774135876043  }
, {  71.878 ,  0.7747318236  }
, {  72.095 ,  0.775327771156  }
, {  72.175 ,  0.775923718713  }
, {  72.524 ,  0.776519666269  }
, {  72.850 ,  0.777115613826  }
, {  72.921 ,  0.777711561383  }
, {  73.165 ,  0.778307508939  }
, {  73.549 ,  0.778903456496  }
, {  73.894 ,  0.779499404052  }
, {  74.419 ,  0.780095351609  }
, {  74.684 ,  0.780691299166  }
, {  75.711 ,  0.781287246722  }
, {  77.166 ,  0.781883194279  }
, {  77.293 ,  0.782479141836  }
, {  77.319 ,  0.783075089392  }
, {  77.729 ,  0.783671036949  }
, {  77.796 ,  0.784266984505  }
, {  77.825 ,  0.784862932062  }
, {  77.833 ,  0.785458879619  }
, {  78.150 ,  0.786054827175  }
, {  79.031 ,  0.786650774732  }
, {  80.676 ,  0.787246722288  }
, {  81.272 ,  0.787842669845  }
, {  81.282 ,  0.788438617402  }
, {  83.256 ,  0.789034564958  }
, {  83.969 ,  0.789630512515  }
, {  85.264 ,  0.790226460072  }
, {  85.324 ,  0.790822407628  }
, {  85.453 ,  0.791418355185  }
, {  85.573 ,  0.792014302741  }
, {  86.076 ,  0.792610250298  }
, {  86.950 ,  0.793206197855  }
, {  86.988 ,  0.793802145411  }
, {  87.239 ,  0.794398092968  }
, {  87.908 ,  0.794994040524  }
, {  88.172 ,  0.795589988081  }
, {  88.583 ,  0.796185935638  }
, {  88.857 ,  0.796781883194  }
, {  89.874 ,  0.797377830751  }
, {  91.236 ,  0.797973778308  }
, {  91.579 ,  0.798569725864  }
, {  93.930 ,  0.799165673421  }
, {  94.000 ,  0.799761620977  }
, {  94.160 ,  0.800357568534  }
, {  95.179 ,  0.800953516091  }
, {  95.368 ,  0.801549463647  }
, {  95.492 ,  0.802145411204  }
, {  96.921 ,  0.80274135876  }
, {  97.778 ,  0.803337306317  }
, {  98.426 ,  0.803933253874  }
, {  99.799 ,  0.80452920143  }
, {  99.802 ,  0.805125148987  }
, {  100.546 ,  0.805721096544  }
, {  100.904 ,  0.8063170441  }
, {  101.285 ,  0.806912991657  }
, {  101.486 ,  0.807508939213  }
, {  101.635 ,  0.80810488677  }
, {  102.845 ,  0.808700834327  }
, {  103.006 ,  0.809296781883  }
, {  103.188 ,  0.80989272944  }
, {  106.179 ,  0.810488676996  }
, {  106.904 ,  0.811084624553  }
, {  107.723 ,  0.81168057211  }
, {  109.080 ,  0.812276519666  }
, {  111.535 ,  0.812872467223  }
, {  111.809 ,  0.813468414779  }
, {  112.489 ,  0.814064362336  }
, {  113.916 ,  0.814660309893  }
, {  116.636 ,  0.815256257449  }
, {  117.343 ,  0.815852205006  }
, {  119.456 ,  0.816448152563  }
, {  120.144 ,  0.817044100119  }
, {  120.650 ,  0.817640047676  }
, {  120.885 ,  0.818235995232  }
, {  121.896 ,  0.818831942789  }
, {  125.109 ,  0.819427890346  }
, {  125.181 ,  0.820023837902  }
, {  125.565 ,  0.820619785459  }
, {  125.886 ,  0.821215733015  }
, {  126.001 ,  0.821811680572  }
, {  126.408 ,  0.822407628129  }
, {  128.273 ,  0.823003575685  }
, {  128.302 ,  0.823599523242  }
, {  129.838 ,  0.824195470799  }
, {  131.222 ,  0.824791418355  }
, {  131.675 ,  0.825387365912  }
, {  134.730 ,  0.825983313468  }
, {  134.764 ,  0.826579261025  }
, {  134.821 ,  0.827175208582  }
, {  134.909 ,  0.827771156138  }
, {  135.150 ,  0.828367103695  }
, {  135.732 ,  0.828963051251  }
, {  138.821 ,  0.829558998808  }
, {  140.275 ,  0.830154946365  }
, {  140.752 ,  0.830750893921  }
, {  143.452 ,  0.831346841478  }
, {  144.414 ,  0.831942789035  }
, {  144.462 ,  0.832538736591  }
, {  144.545 ,  0.833134684148  }
, {  147.902 ,  0.833730631704  }
, {  147.964 ,  0.834326579261  }
, {  147.998 ,  0.834922526818  }
, {  149.011 ,  0.835518474374  }
, {  149.949 ,  0.836114421931  }
, {  150.898 ,  0.836710369487  }
, {  151.581 ,  0.837306317044  }
, {  158.426 ,  0.837902264601  }
, {  160.997 ,  0.838498212157  }
, {  161.771 ,  0.839094159714  }
, {  161.912 ,  0.839690107271  }
, {  162.216 ,  0.840286054827  }
, {  162.404 ,  0.840882002384  }
, {  162.936 ,  0.84147794994  }
, {  163.116 ,  0.842073897497  }
, {  166.120 ,  0.842669845054  }
, {  168.526 ,  0.84326579261  }
, {  169.222 ,  0.843861740167  }
, {  170.829 ,  0.844457687723  }
, {  174.325 ,  0.84505363528  }
, {  175.409 ,  0.845649582837  }
, {  175.470 ,  0.846245530393  }
, {  176.796 ,  0.84684147795  }
, {  182.425 ,  0.847437425507  }
, {  185.990 ,  0.848033373063  }
, {  188.547 ,  0.84862932062  }
, {  190.978 ,  0.849225268176  }
, {  194.107 ,  0.849821215733  }
, {  194.375 ,  0.85041716329  }
, {  195.439 ,  0.851013110846  }
, {  196.741 ,  0.851609058403  }
, {  197.008 ,  0.852205005959  }
, {  199.015 ,  0.852800953516  }
, {  200.306 ,  0.853396901073  }
, {  200.423 ,  0.853992848629  }
, {  200.699 ,  0.854588796186  }
, {  201.540 ,  0.855184743743  }
, {  207.660 ,  0.855780691299  }
, {  208.578 ,  0.856376638856  }
, {  214.040 ,  0.856972586412  }
, {  216.928 ,  0.857568533969  }
, {  218.300 ,  0.858164481526  }
, {  219.243 ,  0.858760429082  }
, {  219.407 ,  0.859356376639  }
, {  219.737 ,  0.859952324195  }
, {  220.035 ,  0.860548271752  }
, {  220.843 ,  0.861144219309  }
, {  225.491 ,  0.861740166865  }
, {  234.283 ,  0.862336114422  }
, {  236.198 ,  0.862932061979  }
, {  247.486 ,  0.863528009535  }
, {  256.473 ,  0.864123957092  }
, {  258.052 ,  0.864719904648  }
, {  268.626 ,  0.865315852205  }
, {  275.025 ,  0.865911799762  }
, {  279.257 ,  0.866507747318  }
, {  298.407 ,  0.867103694875  }
, {  302.545 ,  0.867699642431  }
, {  307.267 ,  0.868295589988  }
, {  311.852 ,  0.868891537545  }
, {  319.049 ,  0.869487485101  }
, {  324.430 ,  0.870083432658  }
, {  332.217 ,  0.870679380215  }
, {  336.871 ,  0.871275327771  }
, {  339.291 ,  0.871871275328  }
, {  343.901 ,  0.872467222884  }
, {  356.425 ,  0.873063170441  }
, {  359.559 ,  0.873659117998  }
, {  359.826 ,  0.874255065554  }
, {  365.346 ,  0.874851013111  }
, {  369.924 ,  0.875446960667  }
, {  375.745 ,  0.876042908224  }
, {  379.771 ,  0.876638855781  }
, {  386.310 ,  0.877234803337  }
, {  386.482 ,  0.877830750894  }
, {  386.875 ,  0.878426698451  }
, {  391.477 ,  0.879022646007  }
, {  394.038 ,  0.879618593564  }
, {  399.782 ,  0.88021454112  }
, {  409.394 ,  0.880810488677  }
, {  409.836 ,  0.881406436234  }
, {  411.582 ,  0.88200238379  }
, {  414.448 ,  0.882598331347  }
, {  415.181 ,  0.883194278903  }
, {  417.474 ,  0.88379022646  }
, {  420.337 ,  0.884386174017  }
, {  429.775 ,  0.884982121573  }
, {  430.046 ,  0.88557806913  }
, {  433.367 ,  0.886174016687  }
, {  439.917 ,  0.886769964243  }
, {  444.843 ,  0.8873659118  }
, {  454.650 ,  0.887961859356  }
, {  455.642 ,  0.888557806913  }
, {  457.332 ,  0.88915375447  }
, {  464.615 ,  0.889749702026  }
, {  472.047 ,  0.890345649583  }
, {  472.913 ,  0.890941597139  }
, {  474.643 ,  0.891537544696  }
, {  475.461 ,  0.892133492253  }
, {  480.848 ,  0.892729439809  }
, {  481.448 ,  0.893325387366  }
, {  492.649 ,  0.893921334923  }
, {  506.030 ,  0.894517282479  }
, {  506.673 ,  0.895113230036  }
, {  510.040 ,  0.895709177592  }
, {  510.727 ,  0.896305125149  }
, {  522.892 ,  0.896901072706  }
, {  523.614 ,  0.897497020262  }
, {  525.162 ,  0.898092967819  }
, {  525.381 ,  0.898688915375  }
, {  526.559 ,  0.899284862932  }
, {  528.057 ,  0.899880810489  }
, {  538.093 ,  0.900476758045  }
, {  543.904 ,  0.901072705602  }
, {  549.961 ,  0.901668653159  }
, {  551.440 ,  0.902264600715  }
, {  557.837 ,  0.902860548272  }
, {  563.953 ,  0.903456495828  }
, {  566.444 ,  0.904052443385  }
, {  566.905 ,  0.904648390942  }
, {  629.128 ,  0.905244338498  }
, {  638.102 ,  0.905840286055  }
, {  638.172 ,  0.906436233611  }
, {  641.924 ,  0.907032181168  }
, {  676.286 ,  0.907628128725  }
, {  683.312 ,  0.908224076281  }
, {  695.578 ,  0.908820023838  }
, {  704.245 ,  0.909415971395  }
, {  724.676 ,  0.910011918951  }
, {  751.132 ,  0.910607866508  }
, {  763.651 ,  0.911203814064  }
, {  807.305 ,  0.911799761621  }
, {  811.234 ,  0.912395709178  }
, {  868.456 ,  0.912991656734  }
, {  882.812 ,  0.913587604291  }
, {  901.744 ,  0.914183551847  }
, {  932.548 ,  0.914779499404  }
, {  940.301 ,  0.915375446961  }
, {  954.825 ,  0.915971394517  }
, {  1002.998 ,  0.916567342074  }
, {  1012.693 ,  0.917163289631  }
, {  1038.212 ,  0.917759237187  }
, {  1105.723 ,  0.918355184744  }
, {  1134.833 ,  0.9189511323  }
, {  1171.934 ,  0.919547079857  }
, {  1197.936 ,  0.920143027414  }
, {  1231.970 ,  0.92073897497  }
, {  1254.049 ,  0.921334922527  }
, {  1287.271 ,  0.921930870083  }
, {  1292.881 ,  0.92252681764  }
, {  1329.739 ,  0.923122765197  }
, {  1340.446 ,  0.923718712753  }
, {  1388.699 ,  0.92431466031  }
, {  1498.211 ,  0.924910607867  }
, {  1500.084 ,  0.925506555423  }
, {  1501.186 ,  0.92610250298  }
, {  1525.962 ,  0.926698450536  }
, {  1530.416 ,  0.927294398093  }
, {  1542.618 ,  0.92789034565  }
, {  1618.348 ,  0.928486293206  }
, {  1649.950 ,  0.929082240763  }
, {  1655.644 ,  0.929678188319  }
, {  1658.788 ,  0.930274135876  }
, {  1753.192 ,  0.930870083433  }
, {  1857.215 ,  0.931466030989  }
, {  1886.367 ,  0.932061978546  }
, {  1932.921 ,  0.932657926103  }
, {  1963.054 ,  0.933253873659  }
, {  1969.943 ,  0.933849821216  }
, {  2008.889 ,  0.934445768772  }
, {  2071.757 ,  0.935041716329  }
, {  2086.576 ,  0.935637663886  }
, {  2133.312 ,  0.936233611442  }
, {  2198.468 ,  0.936829558999  }
, {  2277.407 ,  0.937425506555  }
, {  2277.740 ,  0.938021454112  }
, {  2330.024 ,  0.938617401669  }
, {  2370.961 ,  0.939213349225  }
, {  2399.380 ,  0.939809296782  }
, {  2494.597 ,  0.940405244338  }
, {  2503.314 ,  0.941001191895  }
, {  2754.408 ,  0.941597139452  }
, {  2767.265 ,  0.942193087008  }
, {  2825.967 ,  0.942789034565  }
, {  2856.912 ,  0.943384982122  }
, {  2858.710 ,  0.943980929678  }
, {  2861.233 ,  0.944576877235  }
, {  2930.043 ,  0.945172824791  }
, {  2977.419 ,  0.945768772348  }
, {  3079.200 ,  0.946364719905  }
, {  3120.266 ,  0.946960667461  }
, {  3586.420 ,  0.947556615018  }
, {  3701.108 ,  0.948152562574  }
, {  3777.320 ,  0.948748510131  }
, {  3846.408 ,  0.949344457688  }
, {  4029.417 ,  0.949940405244  }
, {  4038.538 ,  0.950536352801  }
, {  4159.443 ,  0.951132300358  }
, {  4197.646 ,  0.951728247914  }
, {  4375.387 ,  0.952324195471  }
, {  4530.996 ,  0.952920143027  }
, {  4575.401 ,  0.953516090584  }
, {  4692.591 ,  0.954112038141  }
, {  4832.765 ,  0.954707985697  }
, {  4839.955 ,  0.955303933254  }
, {  4970.075 ,  0.95589988081  }
, {  5280.023 ,  0.956495828367  }
, {  5476.239 ,  0.957091775924  }
, {  5485.151 ,  0.95768772348  }
, {  5600.177 ,  0.958283671037  }
, {  5791.909 ,  0.958879618594  }
, {  6014.229 ,  0.95947556615  }
, {  6083.311 ,  0.960071513707  }
, {  6249.294 ,  0.960667461263  }
, {  6530.980 ,  0.96126340882  }
, {  6675.949 ,  0.961859356377  }
, {  6840.707 ,  0.962455303933  }
, {  6907.789 ,  0.96305125149  }
, {  7071.396 ,  0.963647199046  }
, {  7141.474 ,  0.964243146603  }
, {  7351.750 ,  0.96483909416  }
, {  7547.162 ,  0.965435041716  }
, {  7974.115 ,  0.966030989273  }
, {  8090.970 ,  0.96662693683  }
, {  8240.089 ,  0.967222884386  }
, {  8329.244 ,  0.967818831943  }
, {  8563.239 ,  0.968414779499  }
, {  8779.892 ,  0.969010727056  }
, {  8912.522 ,  0.969606674613  }
, {  9115.377 ,  0.970202622169  }
, {  9612.008 ,  0.970798569726  }
, {  9743.292 ,  0.971394517282  }
, {  9753.185 ,  0.971990464839  }
, {  9800.786 ,  0.972586412396  }
, {  10001.220 ,  0.973182359952  }
, {  10273.240 ,  0.973778307509  }
, {  10354.384 ,  0.974374255066  }
, {  10797.105 ,  0.974970202622  }
, {  11560.890 ,  0.975566150179  }
, {  11670.381 ,  0.976162097735  }
, {  11714.205 ,  0.976758045292  }
, {  11809.110 ,  0.977353992849  }
, {  11958.338 ,  0.977949940405  }
, {  12537.117 ,  0.978545887962  }
, {  12799.527 ,  0.979141835518  }
, {  13374.598 ,  0.979737783075  }
, {  13889.928 ,  0.980333730632  }
, {  13967.928 ,  0.980929678188  }
, {  14879.242 ,  0.981525625745  }
, {  16024.275 ,  0.982121573302  }
, {  16288.390 ,  0.982717520858  }
, {  16950.393 ,  0.983313468415  }
, {  18013.639 ,  0.983909415971  }
, {  19333.438 ,  0.984505363528  }
, {  21596.407 ,  0.985101311085  }
, {  30485.574 ,  0.985697258641  }
, {  32293.403 ,  0.986293206198  }
, {  37232.086 ,  0.986889153754  }
, {  40837.624 ,  0.987485101311  }
, {  44907.533 ,  0.988081048868  }
, {  47682.548 ,  0.988676996424  }
, {  48163.354 ,  0.989272943981  }
, {  51423.703 ,  0.989868891538  }
, {  53173.234 ,  0.990464839094  }
, {  53529.671 ,  0.991060786651  }
, {  53783.839 ,  0.991656734207  }
, {  55730.739 ,  0.992252681764  }
, {  58454.460 ,  0.992848629321  }
, {  60538.834 ,  0.993444576877  }
, {  61568.396 ,  0.994040524434  }
, {  61998.009 ,  0.99463647199  }
, {  64196.583 ,  0.995232419547  }
, {  68308.521 ,  0.995828367104  }
, {  69261.188 ,  0.99642431466  }
, {  71747.823 ,  0.997020262217  }
, {  73348.352 ,  0.997616209774  }
, {  75130.868 ,  0.99821215733  }
, {  76980.142 ,  0.998808104887  }
, {  78116.122 ,  0.999404052443  }
, {  86394.941 ,  1  }
};

// Indirection is needed to fool damaged linker

const DoubleDistElement *HttpThinkTimeDistTable = foo6;
#endif 
#endif
