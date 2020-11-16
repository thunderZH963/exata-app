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

/*
 * This file contains initialization function, message processing
 * function, and finalize function used by generic ftp application.
 * The difference between FTP and FTP/GENERIC is that FTP uses
 * tcplib while FTP/GENERIC doesn't.  In FTP/GENERIC, the client
 * just sends data without control information and the server does
 * not respond to the client.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "transport_tcp.h"
#include "app_util.h"
#include "app_gen_ftp.h"

#include "ipv6.h"

// Pseudo traffic sender layer
#include "app_trafficSender.h"


#ifdef ADDON_DB
#include "dbapi.h"
#endif

// /**
// FUNCTION   :: AppGenFtpInitTrace
// LAYER      :: APPLCATION
// PURPOSE    :: FtpGen initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

void AppGenFtpInitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-GEN-FTP",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-GEN-FTP should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_APPLICATION_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
        if (node->appData.appStats)
        {
            TRACE_EnableTraceXML(node, TRACE_GEN_FTP,
                "GEN-FTP", AppGenFtpPrintTraceXML, writeMap);
        }
        else
        {
            ERROR_ReportError(
                "TRACE-GEN-FTP requires APPLICATION-STATISTICS to be set to YES");
        }
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_GEN_FTP,
                "GEN-FTP", writeMap);
    }
    writeMap = FALSE;
}

// /**
// FUNCTION   :: AppGenFtpPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void AppGenFtpPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];

    AppDataGenFtpServer *serverPtr = NULL;;
    AppDataGenFtpClient *clientPtr = NULL;
    AppInfo *appList = node->appData.appPtr;

    char clockStr[MAX_STRING_LENGTH];
    char srcAddr[MAX_STRING_LENGTH];
    char serverAddr[MAX_STRING_LENGTH];
    char clockStr1[MAX_STRING_LENGTH];
    char clockStr2[MAX_STRING_LENGTH];
    char clockStr3[MAX_STRING_LENGTH];

    sprintf(buf, "<ftp-genric>");
    TRACE_WriteToBufferXML(node, buf);
    switch (msg->eventType)
    {
       case MSG_TRANSPORT_FromAppSend:
         {
                clientPtr = (AppDataGenFtpClient *) appList->appDetail;
                AppToTcpSend *sendRequest =
                            (AppToTcpSend *) MESSAGE_ReturnInfo(msg);

                int pcktSize = MESSAGE_ReturnPacketSize(msg);
                sprintf(buf, "<msg_transport_from_appsend>");
                TRACE_WriteToBufferXML(node, buf);

                clientPtr = AppGenFtpClientGetGenFtpClient(node,
                                                sendRequest->connectionId);

                IO_ConvertIpAddressToString(&clientPtr->localAddr ,
                                            srcAddr);

                IO_ConvertIpAddressToString(&clientPtr->remoteAddr,
                                            serverAddr);

                clocktype now = node->getNodeTime();
                TIME_PrintClockInSecond(
                    clientPtr->stats->GetSessionStart().GetValueAsInt(now),
                    clockStr);
                TIME_PrintClockInSecond(
                    clientPtr->stats->GetSessionFinish().GetValueAsInt(now),
                                        clockStr1);
                TIME_PrintClockInSecond(clientPtr->endTime, clockStr2);
                TIME_PrintClockInSecond(
                    clientPtr->stats->GetLastFragmentSent().GetValueAsInt(now),
                    clockStr3);

                sprintf(buf,"%d %s %s %s %s %hu %d %d %s %s ",
                     clientPtr->connectionId,
                     srcAddr,
                     serverAddr,
                     clockStr,
                     clockStr1,
                     clientPtr->stats->IsSessionFinished(),
                     pcktSize,
                     clientPtr->itemsToSend,
                     clockStr2,
                     clockStr3
                );
                TRACE_WriteToBufferXML(node, buf);

                sprintf(buf, "</msg_transport_from_appsend>");
                TRACE_WriteToBufferXML(node, buf);
                break;
            }//end of case MSG_TRANSPORT_FromAppSend

          case MSG_APP_FromTransDataReceived:
          {
                sprintf(buf, "<msg_app_from_transport>");
                TRACE_WriteToBufferXML(node, buf);

                TransportToAppDataReceived *data;
                data =
                (TransportToAppDataReceived *) MESSAGE_ReturnInfo(msg);
                int pcktSize = MESSAGE_ReturnPacketSize(msg);

                serverPtr = AppGenFtpServerGetGenFtpServer(
                            node,
                            data->connectionId);

                clocktype now = node->getNodeTime();
                TIME_PrintClockInSecond(
                    serverPtr->stats->GetSessionStart().GetValueAsInt(now),
                    clockStr);
                TIME_PrintClockInSecond(
                    serverPtr->stats->GetSessionFinish().GetValueAsInt(now),
                                        clockStr1);
                TIME_PrintClockInSecond(
                    serverPtr->stats->GetLastFragmentReceived().GetValueAsInt(now),
                                        clockStr2);

                IO_ConvertIpAddressToString(&serverPtr->localAddr ,
                                            srcAddr);

                IO_ConvertIpAddressToString(&serverPtr->remoteAddr,
                                            serverAddr);

                sprintf(buf,"%d %s %s %s %s %hu %d %" TYPES_64BITFMT "d %s ",
                serverPtr->connectionId,
                srcAddr,
                serverAddr,
                clockStr,
                clockStr1,
                serverPtr->stats->IsSessionFinished(),
                pcktSize,
                serverPtr->stats->GetDataReceived().GetValueAsInt(now),
                clockStr2);

               TRACE_WriteToBufferXML(node, buf);

               sprintf(buf, "</msg_app_from_transport>");
               TRACE_WriteToBufferXML(node, buf);

               break;

         }//END OF CASE MSG_APP_FromTransport

    }//END OF Switch event type

    sprintf(buf, "</ftp-genric>");
    TRACE_WriteToBufferXML(node, buf);

}//END OF FUNCTION AppGenFtpPrintTraceXML



/*
 * NAME:        AppLayerGenFtpClient.
 * PURPOSE:     Models the behaviour of ftp client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerGenFtpClient(Node *node, Message *msg)
{
    AppDataGenFtpClient *clientPtr;
    char buf[MAX_STRING_LENGTH];

#ifdef DEBUG
    ctoa(node->getNodeTime(), buf);
#endif

    switch(msg->eventType)
    {
        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;
            AppDataGenFtpClient *clientPtr;

            openResult = (TransportToAppOpenResult *) MESSAGE_ReturnInfo(msg);

            #ifdef DEBUG
                printf("GENERIC FTP Client: Node %ld at %s got OpenResult\n",
                       node->nodeId, buf);
            #endif /* DEBUG */

            assert(openResult->type == TCP_CONN_ACTIVE_OPEN);

            clientPtr = AppGenFtpClientGetGenFtpClientWithUniqueId (node,openResult->uniqueId);

            if (openResult->connectionId < 0)
            {
                /* Keep trying until connection is established. */

                node->appData.appTrafficSender->appTcpOpenConnection(
                                node,
                                APP_GEN_FTP_CLIENT,
                                clientPtr->localAddr,
                                node->appData.nextPortNum++,
                                clientPtr->remoteAddr,
                                (UInt16) APP_GEN_FTP_SERVER,
                                clientPtr->uniqueId,
                                clientPtr->tos,
                                ANY_INTERFACE,
                                *clientPtr->serverUrl,
                                PROCESS_IMMEDIATELY,
                                clientPtr->destNodeId,
                                clientPtr->clientInterfaceIndex,
                                clientPtr->destInterfaceIndex);

#ifdef DEBUG
                printf("GENERIC FTP Client: Node %ld at %s connection "
                       "failed!  Retrying... \n",
                       node->nodeId, buf);
#endif /* DEBUG */

                node->appData.numAppTcpFailure ++;
            }
            else
            {

                clientPtr = AppGenFtpClientUpdateGenFtpClient(node,
                                                              openResult);

                assert(clientPtr != NULL);

#ifdef ADDON_DB
                STATSDB_HandleSessionDescTableInsert(node,
                    clientPtr->uniqueId,
                    openResult->localAddr, openResult->remoteAddr,
                    openResult->localPort, openResult->remotePort,
                    "FTP/GENERIC", "TCP");
#endif
                AppGenFtpClientSendNextItem(node, clientPtr);
            }

            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("GENERIC FTP Client: Node %ld at %s sent data %ld\n",
                   node->nodeId, buf, dataSent->length);
#endif /* DEBUG */

            clientPtr = AppGenFtpClientGetGenFtpClient(
                            node, dataSent->connectionId);

            if (clientPtr == NULL)
            {
                printf("GENERIC FTP Client: Node %d cannot find ftp client\n",
                        node->nodeId);

                assert(FALSE);
            }

            if (clientPtr->sessionIsClosed != TRUE)
            {
                AppGenFtpClientSendNextItem(node, clientPtr);
            }


            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("GENERIC FTP Client: Node %ld at %s got close result\n",
                    node->nodeId, buf);
#endif /* DEBUG */

            clientPtr = AppGenFtpClientGetGenFtpClient(
                            node, closeResult->connectionId);

            if (clientPtr == NULL)
            {
                printf("GENERIC FTP Client: Node %d cannot find ftp client\n",
                        node->nodeId);

                assert(FALSE);
            }

            if (clientPtr->sessionIsClosed == FALSE)
            {
                clientPtr->sessionIsClosed = TRUE;
                if (node->appData.appStats)
                {
                    clientPtr->stats->SessionFinish(node);
                }
            }

            break;
        }
        default:
            ctoa(node->getNodeTime(), buf);
            printf("GENERIC FTP Client: Node %d at %s received "
                   "message of unknown type"
                   " %d\n", node->nodeId, buf, msg->eventType);

            assert(FALSE);
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppGenFtpClientInit.
 * PURPOSE:     Initialize a ftp session.
 * PARAMETERS:  node - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each item.
 *              startTime - time until the session starts.
 *              endTime - time when session is over.
 *              tos - the contents for the type of service field
 *              appName - application alias name
 *              destString - destination string
 * RETURN:      none.
 */
void
AppGenFtpClientInit(
    Node *node,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype startTime,
    clocktype endTime,
    unsigned tos,
    char* appName,
    char* destString)
{
    AppDataGenFtpClient *clientPtr;

    /* Check to make sure the number of ftp items is a correct value. */
    if (itemsToSend < 0)
    {
        printf("GENERIC FTP Client: Node %d item to send needs to be >= 0\n",
               node->nodeId);

        exit(0);
    }

    /* Check to make sure the number of ftp item size is a correct value. */
    if (itemSize <= 0)
    {
        printf("GENERIC FTP Client: Node %d item size needs to be > 0\n",
               node->nodeId);

        exit(0);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        printf("GENERIC FTP Client: Node %d end time needs to be > start time "
               "or equal to 0.\n",
               node->nodeId);

        exit(0);
    }

    /* Check to make sure given TOS is a correct value. */
    if (/* (tos is unsigned) tos < 0 ||*/ tos > 255)
    {
        printf("GENERIC FTP Client: Node %d should have tos value "
            "within the range 0 to 255.\n",
            node->nodeId);
        exit(0);
    }

    clientPtr = AppGenFtpClientNewGenFtpClient(node,
                                               clientAddr,
                                               serverAddr,
                                               itemsToSend,
                                               itemSize,
                                               endTime,
                                               (TosType) tos,
                                               appName);

    if (clientPtr == NULL)
    {
        printf("GENERIC FTP Client: Node %d cannot allocate "
               "new ftp client\n", node->nodeId);

        assert(FALSE);
    }
     // dns
    // delay TCP connection untill
    // url is resolved , network type will be invalid
    // if server url is presentt
    if (serverAddr.networkType != NETWORK_INVALID)
    {
        if (node->appData.appStats)
        {
            std::string customName;
            if (clientPtr->applicationName->empty())
            {
                customName = "Gen FTP Client";
            }
            else
            {
                customName = *clientPtr->applicationName;
            }
            clientPtr->stats = new STAT_AppStatistics(
                                     node,
                                     "genFtpClient",
                                     STAT_Unicast,
                                     STAT_AppSender,
                                     customName.c_str());
            clientPtr->stats->EnableAutoRefragment();
            clientPtr->stats->Initialize(
                 node,
                 clientAddr,
                 serverAddr,
                 (STAT_SessionIdType)clientPtr->uniqueId,
                 clientPtr->uniqueId);
            clientPtr->stats->setTos(tos);
       }
    }
        // Dynamic Address
    // set the dns info in client pointer if server url is present
    // set the server url if it is not localhost
    if (serverAddr.networkType == NETWORK_INVALID && destString)
    {
        if (node->appData.appTrafficSender->ifUrlLocalHost(destString)
                                                                    == FALSE)
        {
            node->appData.appTrafficSender->appClientSetDnsInfo(
                                                    node,
                                                    (const char*)destString,
                                                    clientPtr->serverUrl);
        }
    }

    // Update the GEN FTP clientPtr with address information
    AppGenFtpClientAddAddressInformation(node, clientPtr);

    node->appData.appTrafficSender->appTcpOpenConnection(
                                node,
                                APP_GEN_FTP_CLIENT,
                                clientPtr->localAddr,
                                node->appData.nextPortNum++,
                                clientPtr->remoteAddr,
                                (UInt16) APP_GEN_FTP_SERVER,
                                clientPtr->uniqueId,
                                clientPtr->tos,
                                ANY_INTERFACE,
                                *clientPtr->serverUrl,
                                startTime,
                                clientPtr->destNodeId,
                                clientPtr->clientInterfaceIndex,
                                clientPtr->destInterfaceIndex);

}

/*
 * NAME:        AppGenFtpClientPrintStats.
 * PURPOSE:     Prints statistics of a ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              clientPtr - pointer to the ftp client data structure.
 * RETURN:      none.
 */
void //inline//
AppGenFtpClientPrintStats(Node *node, AppDataGenFtpClient *clientPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char closeStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (clientPtr->connectionId < 0)
    {
        sprintf(closeStr, "Failed");
    }
    else if (!clientPtr->stats->IsSessionFinished())
    {
        sprintf(closeStr, "Not closed");
        if (clientPtr->stats)
        {
            if (!clientPtr->stats->IsSessionFinished(STAT_Unicast))
            {
                clientPtr->stats->SessionFinish(node);
            }
        }
    }
    else
    {
        sprintf(closeStr, "Closed");
    }

    // dns
    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
    {
        IO_ConvertIpAddressToString(&clientPtr->remoteAddr, addrStr);
    }
    else
    {
        strcpy(addrStr, (char*)clientPtr->serverUrl->c_str());
    }
    sprintf(buf, "Server Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "Gen/FTP Client",
        ANY_DEST,
        clientPtr->connectionId,
        buf);

    sprintf(buf, "Session Status = %s", closeStr);
    IO_PrintStat(
        node,
        "Application",
        "Gen/FTP Client",
        ANY_DEST,
        clientPtr->connectionId,
        buf);
}

/*
 * NAME:        AppGenFtpClientFinalize.
 * PURPOSE:     Collect statistics of a ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppGenFtpClientFinalize(Node *node, AppInfo* appInfo)
{
    AppDataGenFtpClient *clientPtr =
        (AppDataGenFtpClient*) appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppGenFtpClientPrintStats(node, clientPtr);
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                node,
                "Application",
                "Gen/FTP Client",
                ANY_ADDRESS,
                clientPtr->connectionId);
        }
    }
    if (clientPtr->serverUrl)
    {
        delete (clientPtr->serverUrl);
        clientPtr->serverUrl = NULL;
    }
}

/*
 * NAME:        AppGenFtpClientGetGenFtpClientWithUniqueId.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              uniqueId - uniqueId of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpClient * //inline//
AppGenFtpClientGetGenFtpClientWithUniqueId(Node *node, Int32 uniqueId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataGenFtpClient *ftpClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_GEN_FTP_CLIENT)
        {
            ftpClient = (AppDataGenFtpClient *) appList->appDetail;

            if (ftpClient->uniqueId == uniqueId)
            {
                return ftpClient;
            }
        }
    }
    return NULL;
}


/*
 * NAME:        AppGenFtpClientGetGenFtpClient.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              connId - connection ID of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpClient * //inline//
AppGenFtpClientGetGenFtpClient(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataGenFtpClient *ftpClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_GEN_FTP_CLIENT)
        {
            ftpClient = (AppDataGenFtpClient *) appList->appDetail;

            if (ftpClient->connectionId == connId)
            {
                return ftpClient;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppGenFtpClientUpdateGenFtpClient.
 * PURPOSE:     update existing ftp client data structure by including
 *              connection id.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpClient * //inline//
AppGenFtpClientUpdateGenFtpClient(Node *node,
                                  TransportToAppOpenResult *openResult)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataGenFtpClient *tmpFtpClient = NULL;
    AppDataGenFtpClient *ftpClient = NULL;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_GEN_FTP_CLIENT)
        {
            tmpFtpClient = (AppDataGenFtpClient *) appList->appDetail;

#ifdef DEBUG
            printf("GENERIC FTP Client: Node %ld comparing uniqueId "
                   "%ld with %ld\n",
                   node->nodeId,
                   tmpFtpClient->uniqueId,
                   openResult->uniqueId);
#endif /* DEBUG */

            if (tmpFtpClient->uniqueId == openResult->uniqueId)
            {
                ftpClient = tmpFtpClient;
                break;
            }
        }
    }

    if (ftpClient == NULL)
    {
        assert(FALSE);
    }

    /*
     * fill in connection id, etc.
     */
    ftpClient->connectionId = openResult->connectionId;
    ftpClient->localAddr = openResult->localAddr;
    ftpClient->remoteAddr = openResult->remoteAddr;
    ftpClient->sessionIsClosed = FALSE;

#ifdef DEBUG
    {
        char clockStr[24];
        char addrStr[MAX_STRING_LENGTH];
        printf("GENERIC FTP Client: Node %ld updating ftp "
               "client struture\n", node->nodeId);
        printf("    connectionId = %d\n", ftpClient->connectionId);
        IO_ConvertIpAddressToString(&ftpClient->localAddr, addrStr);
        printf("    localAddr = %s\n", addrStr);
        IO_ConvertIpAddressToString(&ftpClient->remoteAddr, addrStr);
        printf("    remoteAddr = %s\n", addrStr);
        printf("    itemsToSend = %d\n", ftpClient->itemsToSend);
        printf("    itemSize = %d\n", ftpClient->itemSize);

        ctoa(ftpClient->endTime, clockStr);
        printf("    endTime = %s\n", clockStr);
    }
#endif /* DEBUG */

    return ftpClient;
}

/*
 * NAME:        AppGenFtpClientNewGenFtpClient.
 * PURPOSE:     create a new ftp client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              serverAddr - ftp server to this client.
 *              itemsToSend - number of ftp items to send in simulation.
 *              itemSize - size of each item.
 *              endTime - when simulation of ftp ends.
 *              tos - given priority value.
 *              appName - application alias name
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpClient * //inline//
AppGenFtpClientNewGenFtpClient(
    Node *node,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype endTime,
    TosType tos,
    char* appName)
{
    AppDataGenFtpClient *ftpClient;

    ftpClient = (AppDataGenFtpClient *)
                MEM_malloc(sizeof(AppDataGenFtpClient));

    memset(ftpClient, 0, sizeof(AppDataGenFtpClient));

    /*
     * fill in connection id, etc.
     */
    ftpClient->connectionId = -1;
    ftpClient->localAddr = clientAddr;
    ftpClient->remoteAddr = serverAddr;

    ftpClient->itemsToSend = itemsToSend;
    ftpClient->itemSize = itemSize;
    ftpClient->endTime = endTime;
    ftpClient->uniqueId = node->appData.uniqueId++;
    ftpClient->stats = NULL;

    if (appName)
    {
        ftpClient->applicationName = new std::string(appName);
    }
    else
    {
        ftpClient->applicationName = new std::string();
    }

    ftpClient->tos = tos;

    // Create statistics


#ifdef DEBUG
    {
        char clockStr[24];
        char addrStr[MAX_STRING_LENGTH];
        printf("GENERIC FTP Client: Node %ld creating new ftp "
               "client struture\n", node->nodeId);
        printf("    uniqueId = %d\n", ftpClient->uniqueId);
        printf("    connectionId = %d\n", ftpClient->connectionId);
        IO_ConvertIpAddressToString(&ftpClient->localAddr, addrStr);
        printf("    localAddr = %s\n", addrStr);
        IO_ConvertIpAddressToString(&ftpClient->remoteAddr, addrStr);
        printf("    remoteAddr = %s\n", addrStr);
        printf("    itemsToSend = %d\n", ftpClient->itemsToSend);
        printf("    itemSize = %d\n", ftpClient->itemSize);
        ctoa(ftpClient->endTime, clockStr);
        printf("    endTime = %s\n", clockStr);
    }
#endif /* DEBUG */

    // dynamic address
    ftpClient->destNodeId = ANY_NODEID;
    ftpClient->clientInterfaceIndex = ANY_INTERFACE;
    ftpClient->destInterfaceIndex = ANY_INTERFACE;
    ftpClient->serverUrl = new std::string();
    ftpClient->serverUrl->clear();
    APP_RegisterNewApp(node, APP_GEN_FTP_CLIENT, ftpClient);

    return ftpClient;
}

/*
 * NAME:        AppGenFtpClientSendNextItem.
 * PURPOSE:     Send the next item.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */

void //inline//
AppGenFtpClientSendNextItem(Node *node, AppDataGenFtpClient *clientPtr)
{

#ifdef DEBUG
    printf("GENERIC FTP Client: Node %ld has %ld items left to send\n",
           node->nodeId, clientPtr->itemsToSend);
#endif /* DEBUG */

    if (((clientPtr->itemsToSend > 1) &&
            (node->getNodeTime() < clientPtr->endTime)) ||
        ((clientPtr->itemsToSend == 0) &&
            (node->getNodeTime() < clientPtr->endTime)) ||
       ((clientPtr->itemsToSend > 1) && (clientPtr->endTime == 0)) ||
       ((clientPtr->itemsToSend == 0) && (clientPtr->endTime == 0)))
    {
        AppGenFtpClientSendPacket(node, clientPtr, FALSE);

        if (clientPtr->itemsToSend > 0)
        {
            clientPtr->itemsToSend--;
        }
    }
    else
    {
        if (((clientPtr->itemsToSend == 1) &&
             (node->getNodeTime() < clientPtr->endTime)) ||
            ((clientPtr->itemsToSend == 1) && (clientPtr->endTime == 0)))
        {
                AppGenFtpClientSendPacket(node, clientPtr, TRUE);
        }

        clientPtr->sessionIsClosed = TRUE;
        if (node->appData.appStats)
        {
            clientPtr->stats->SessionFinish(node);
        }

#ifdef DEBUG
        printf("GENERIC FTP Client: Node %ld closing connection %d\n",
               node->nodeId, clientPtr->connectionId);
#endif /* DEBUG */

        node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                clientPtr->connectionId);
    }
}

/*
 * NAME:        AppGenFtpClientSendPacket.
 * PURPOSE:     Send the remaining data.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 *              end - end of session.
 * RETRUN:      none.
 */
void //inline//
AppGenFtpClientSendPacket(Node *node,
                          AppDataGenFtpClient *clientPtr,
                          BOOL end)
{
#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];

        ctoa(node->getNodeTime(), clockStr);

        printf("GENERIC FTP Client: Node %ld sending pkt of size %d at %s\n",
               node->nodeId, clientPtr->itemSize, clockStr);
    }
#endif /* DEBUG */

    if (node->appData.appStats)
    {
        if (!clientPtr->stats->IsSessionStarted())
        {
            clientPtr->stats->SessionStart(node);
        }
    }
    Message *msg = APP_TcpCreateMessage(
        node,
        clientPtr->connectionId,
        TRACE_GEN_FTP);

    APP_AddVirtualPayload(node, msg, clientPtr->itemSize);

    node->appData.appTrafficSender->appTcpSend(node, msg);

    if (node->appData.appStats)
    {
        clientPtr->stats->AddMessageSentDataPoints(node, msg, 0, clientPtr->itemSize, 0);
        clientPtr->stats->AddFragmentSentDataPoints(node, clientPtr->itemSize);
    }
}



/*
 * NAME:        AppLayerGenFtpServer.
 * PURPOSE:     Models the behaviour of ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerGenFtpServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataGenFtpServer *serverPtr;

#ifdef DEBUG
    ctoa(node->getNodeTime(), buf);
#endif

    switch(msg->eventType)
    {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("GENERIC FTP Server: Node %ld at %s got ListenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            if (listenResult->connectionId == -1)
            {
#ifdef DEBUG
                printf("    Failed to listen on server port.\n");
#endif /* DEBUG */

                /* Removed second listen because none of the other TCP
                   app models do this (although this behavior is
                   otherwise okay).  The problem is we should not
                   bind to node->nodeId, but to the IP address
                   passed into AppGenFtpServerInit(). */

                node->appData.appTrafficSender->appTcpListen(
                                    node,
                                    APP_GEN_FTP_SERVER,
                                    listenResult->localAddr,
                                    (UInt16) APP_GEN_FTP_SERVER);
                node->appData.numAppTcpFailure++;
            }

            break;
        }
        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;
            openResult = (TransportToAppOpenResult *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("GENERIC FTP Server: Node %ld at %s got OpenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_PASSIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure++;
            }
            else
            {
                AppDataGenFtpServer *serverPtr;
                serverPtr = AppGenFtpServerNewGenFtpServer(node, openResult);
                if (serverPtr == NULL)
                {
                    printf("GENERIC FTP SERVER: Node %d cannot allocate "
                           "new ftp server\n", node->nodeId);

                    assert(FALSE);
                }

                if (node->appData.appStats)
                {
                    serverPtr->stats->Initialize(
                        node,
                        serverPtr->remoteAddr,
                        serverPtr->localAddr,
                        (STAT_SessionIdType)openResult->clientUniqueId,
                        serverPtr->uniqueId);
                    serverPtr->stats->SessionStart(node);
                }
#ifdef ADDON_DB
                // should be recorded at the receiver's side
                STATSDB_HandleAppConnCreation(node,
                    (const Address)serverPtr->remoteAddr,
                    (const Address)serverPtr->localAddr,
                    openResult->clientUniqueId);
#endif
            }

            break;
        }
        case MSG_APP_FromTransDataReceived:
        {
            int packetSize;
            TransportToAppDataReceived *dataRecvd;

            dataRecvd = (TransportToAppDataReceived *) MESSAGE_ReturnInfo(msg);

            packetSize = MESSAGE_ReturnPacketSize(msg);

#ifdef DEBUG
            printf("GENERIC FTP Server: Node %ld at %s received data %d\n",
                   node->nodeId, buf, packetSize);
#endif /* DEBUG */

            serverPtr = AppGenFtpServerGetGenFtpServer(
                            node, dataRecvd->connectionId);

            if (serverPtr == NULL)
            {
                printf("GENERIC FTP Server: Node %d cannot find ftp server\n",
                       node->nodeId);

                assert(FALSE);
            }

            if (serverPtr->sessionIsClosed == TRUE)
            {
                printf("GENERIC FTP Server: Node %d ftp server session "
                       "should not be closed\n", node->nodeId);

                assert(FALSE);
            }
            if (node->appData.appStats)
            {
                serverPtr->stats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    packetSize);
            }
            ActionData acnData;
            acnData.actionType = RECV;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node,
                            msg,
                            TRACE_APPLICATION_LAYER,
                            PACKET_IN,
                            &acnData);

            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("GENERIC FTP Server: Node %ld at %s got close result\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            serverPtr = AppGenFtpServerGetGenFtpServer(
                            node, closeResult->connectionId);

            if (serverPtr == NULL)
            {
                printf("GENERIC FTP Server: Node %d cannot find ftp server\n",
                       node->nodeId);

                assert(FALSE);
            }

            if (serverPtr->sessionIsClosed == FALSE)
            {
                serverPtr->sessionIsClosed = TRUE;
                if (node->appData.appStats)
                {
                    serverPtr->stats->SessionFinish(node);
                }
                node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                serverPtr->connectionId);
            }

            break;
        }
        // Dynamic addressing
        case MSG_APP_TimerExpired:
        {
            // now start listening at the updated address if
            // in valid address state
            Address serverAddress;
            if (AppTcpValidServerAddressState(node, msg, &serverAddress))
            {
                AppGenFtpServerInit(node, serverAddress);
            }
            break;
        }
        default:
        ctoa(node->getNodeTime(), buf);
        printf("GENERIC FTP Server: Node %d at %s received "
               "message of unknown type %d\n",
               node->nodeId, buf, msg->eventType);

        printf("    MSG_APP_TimerExpired = %d\n", MSG_APP_TimerExpired);

        assert(FALSE);
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppGenFtpServerInit.
 * PURPOSE:     listen on ftp server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppGenFtpServerInit(Node *node, Address serverAddr)
{
    node->appData.appTrafficSender->appTcpListen(
                                    node,
                                    APP_GEN_FTP_SERVER,
                                    serverAddr,
                                    (UInt16) APP_GEN_FTP_SERVER);
}

/*
 * NAME:        AppGenFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void //inline//
AppGenFtpServerPrintStats(Node *node, AppDataGenFtpServer *serverPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char closeStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (serverPtr->connectionId < 0)
    {
        sprintf(closeStr, "Failed");
    }
    else if (!serverPtr->stats->IsSessionFinished())
    {
        sprintf(closeStr, "Not closed");
        if (serverPtr->stats)
        {
            if (!serverPtr->stats->IsSessionFinished(STAT_Unicast))
            {
                serverPtr->stats->SessionFinish(node);
            }
        }
    }
    else
    {
        sprintf(closeStr, "Closed");
    }

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "Gen/FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Session Status = %s", closeStr);
    IO_PrintStat(
        node,
        "Application",
        "Gen/FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);
}

/*
 * NAME:        AppGenFtpServerFinalize.
 * PURPOSE:     Collect statistics of a ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppGenFtpServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataGenFtpServer *serverPtr = (AppDataGenFtpServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppGenFtpServerPrintStats(node, serverPtr);
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(
               node,
               "Application",
               "Gen/FTP Server",
                ANY_ADDRESS,
                serverPtr->connectionId);
        }
    }
}

/*
 * NAME:        AppGenFtpServerGetGenFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpServer * //inline//
AppGenFtpServerGetGenFtpServer(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataGenFtpServer *ftpServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_GEN_FTP_SERVER)
        {
            ftpServer = (AppDataGenFtpServer *) appList->appDetail;
            if (ftpServer->connectionId == connId)
            {
                return ftpServer;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppGenFtpServerNewGenFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpServer * //inline//
AppGenFtpServerNewGenFtpServer(Node *node,
                               TransportToAppOpenResult *openResult)
{
    AppDataGenFtpServer *ftpServer;

    ftpServer = (AppDataGenFtpServer *)
                MEM_malloc(sizeof(AppDataGenFtpServer));

    /*
     * fill in connection id, etc.
     */
    ftpServer->connectionId = openResult->connectionId;
    ftpServer->localAddr = openResult->localAddr;
    ftpServer->remoteAddr = openResult->remoteAddr;
    ftpServer->uniqueId = node->appData.uniqueId++;
    ftpServer->sessionIsClosed = FALSE;
    // Create statistics, enable auto-refragmentation
    if (node->appData.appStats)
    {
        ftpServer->stats = new STAT_AppStatistics(
            node,
            "genFtpServer",
            STAT_Unicast,
            STAT_AppReceiver,
            "Gen FTP Server");
        ftpServer->stats->EnableAutoRefragment();
    }
#ifdef DEBUG
    char addrStr[MAX_STRING_LENGTH];
    printf("GENERIC FTP Server: Node %ld creating new ftp "
           "server struture\n", node->nodeId);
    printf("    connectionId = %d\n", ftpServer->connectionId);
    IO_ConvertIpAddressToString(&ftpServer->localAddr, addrStr);
    printf("    localAddr = %s\n", addrStr);
    IO_ConvertIpAddressToString(&ftpServer->remoteAddr, addrStr);
    printf("    remoteAddr = %s\n", addrStr);
#endif /* DEBUG */

    APP_RegisterNewApp(node, APP_GEN_FTP_SERVER, ftpServer);

    return ftpServer;
}

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppGenFtpClientAddAddressInformation.
// PURPOSE              : store client interface index, destination 
//                        interface index destination node id to get the 
//                        correct address when application starts
// PARAMETERS:
// + node               : Node*                : pointer to the node
// + clientPtr          : AppDataGenFtpClient* : pointer to client data
// RETURN               : void
//---------------------------------------------------------------------------
void
AppGenFtpClientAddAddressInformation(
                                  Node* node,
                                  AppDataGenFtpClient* clientPtr)
{
    // Store the client and destination interface index such that we can get
    // the correct address when the application starts
    NodeId destNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                node,
                                                clientPtr->remoteAddr);

    if (destNodeId != INVALID_MAPPING)
    {
        clientPtr->destNodeId = destNodeId;
        clientPtr->destInterfaceIndex = 
            (Int16)MAPPING_GetInterfaceIdForDestAddress(
                                                node,
                                                destNodeId,
                                                clientPtr->remoteAddr);
    }
    // Handle loopback address in destination
    if (destNodeId == INVALID_MAPPING)
    {
        if (NetworkIpCheckIfAddressLoopBack(node, clientPtr->remoteAddr))
        {
            clientPtr->destNodeId = node->nodeId;
            clientPtr->destInterfaceIndex = DEFAULT_INTERFACE;
        }
    }
    clientPtr->clientInterfaceIndex = 
        (Int16)MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                            node,
                                            clientPtr->localAddr);
}
//---------------------------------------------------------------------------
// FUNCTION             : AppGenFtpClientGetClientPtr.
// PURPOSE              : get the FTP-GEN client pointer
// PARAMETERS:
// + node               : Node* : pointer to the node
// + uniqueId           : Int32*: unique id
// RETURN               
// AppDataGenFtpClient* : gen ftp client pointer
//---------------------------------------------------------------------------
AppDataGenFtpClient*
AppGenFtpClientGetClientPtr(Node* node, Int32 uniqueId)
{
    AppInfo* appList = node->appData.appPtr;
    AppDataGenFtpClient* genFtpClient = NULL;
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_GEN_FTP_CLIENT)
        {
            genFtpClient = (AppDataGenFtpClient*) appList->appDetail;

            if (genFtpClient->uniqueId == uniqueId)
            {
                return (genFtpClient);
            }
        }
    }
    return (NULL);
}
// dNS
//--------------------------------------------------------------------------
// FUNCTION    :: AppGenFtpUrlSessionStartCallBack
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
//                                                 used by GEN-FTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//---------------------------------------------------------------------------
bool
AppGenFtpUrlSessionStartCallBack(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    AppUdpPacketSendingInfo* packetSendingInfo)
{
    AppDataGenFtpClient* clientPtr = NULL;
    clientPtr = AppGenFtpClientGetClientPtr(
                                        node,
                                        uniqueId);
    if (clientPtr == NULL)
    {
           return (FALSE);
    }
    if (clientPtr->connectionId >= 0)
    {
#ifdef DEBUG

        printf("Session already started so ignore this response\n");

#endif
        return (FALSE);
    }

    if (serverAddr->networkType == NETWORK_IPV4)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV4)
        {
            ERROR_ReportErrorArgs("FTP/GENERIC Client: Node %d cannot "
                " find IPv4 ftp-gen client for ipv4 dest\n",
                node->nodeId);
        }
    }
    else if (serverAddr->networkType == NETWORK_IPV6)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV6)
        {
            ERROR_ReportErrorArgs("FTP/GENERIC Client: Node %d cannot "
                " find IPv6 ftp-gen client for ipv6 dest\n",
                               node->nodeId);
        }
    }
    if (node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "Gen FTP Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                                     node,
                                     "genFtpClient",
                                     STAT_Unicast,
                                     STAT_AppSender,
                                     customName.c_str());
        clientPtr->stats->EnableAutoRefragment();
        clientPtr->stats->Initialize(
                 node,
                 clientPtr->localAddr,
                 *serverAddr,
                 (STAT_SessionIdType)clientPtr->uniqueId,
                 clientPtr->uniqueId);
        clientPtr->stats->setTos(clientPtr->tos);
    }

    memcpy(
        &clientPtr->remoteAddr, 
        serverAddr,
        sizeof(Address));

    AppGenFtpClientAddAddressInformation(node, clientPtr);
    memset (packetSendingInfo, 0, sizeof(AppUdpPacketSendingInfo));
    return (FALSE);
}
