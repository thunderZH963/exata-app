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
 * function, and finalize function used by the ftp application.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "api.h"
#include "transport_tcp.h"
#include "tcpapps.h"
#include "app_util.h"
#include "app_ftp.h"

#include "ipv6.h"

// Pseudo traffic sender layer
#include "app_trafficSender.h"

/*
 * Static Functions
 */

/*
 * NAME:        AppFtpClientGetFtpClient.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              connId - connection ID of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataFtpClient *
AppFtpClientGetFtpClient(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataFtpClient *ftpClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FTP_CLIENT)
        {
            ftpClient = (AppDataFtpClient *) appList->appDetail;

            if (ftpClient->connectionId == connId)
            {
                return ftpClient;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppFtpClientUpdateFtpClient.
 * PURPOSE:     update existing ftp client data structure by including
 *              connection id.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpClient *
AppFtpClientUpdateFtpClient(Node *node,
                            TransportToAppOpenResult *openResult)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataFtpClient *tmpFtpClient = NULL;
    AppDataFtpClient *ftpClient = NULL;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FTP_CLIENT)
        {
            tmpFtpClient = (AppDataFtpClient *) appList->appDetail;

#ifdef DEBUG
            printf("FTP Client: Node %d comparing uniqueId "
                   "%d with %d\n",
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
    ftpClient->sessionStart = node->getNodeTime();
    if (node->appData.appStats)
    { 
        if (!ftpClient->stats->IsSessionStarted())
        {
            ftpClient->stats->SessionStart(node);
        }
    }
    ftpClient->sessionFinish = node->getNodeTime();
    ftpClient->lastTime = 0;
    ftpClient->sessionIsClosed = FALSE;
    ftpClient->bytesRecvdDuringThePeriod = 0;
#ifdef DEBUG
    char addrStr[MAX_STRING_LENGTH];
    printf("FTP Client: Node %d updating ftp client structure\n",
            node->nodeId);
    printf("    connectionId = %d\n", ftpClient->connectionId);
    IO_ConvertIpAddressToString(&ftpClient->localAddr, addrStr);
    printf("    localAddr = %s\n", addrStr);
    IO_ConvertIpAddressToString(&ftpClient->remoteAddr, addrStr);
    printf("    remoteAddr = %s\n", addrStr);
    printf("    itemsToSend = %d\n", ftpClient->itemsToSend);
#endif /* DEBUG */

    return ftpClient;
}

/*
 * NAME:        AppFtpClientNewFtpClient.
 * PURPOSE:     create a new ftp client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              clientAddr - address of this client.
 *              serverAddr - ftp server to this client.
 *              itemsToSend - number of ftp items to send in simulation.
 *              appName - user defined application alias name.
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpClient *
AppFtpClientNewFtpClient(Node *node,
                         Address clientAddr,
                         Address serverAddr,
                         int itemsToSend,
                         char* appName)
{
    AppDataFtpClient *ftpClient;

    ftpClient = (AppDataFtpClient *)
                MEM_malloc(sizeof(AppDataFtpClient));

    memset(ftpClient, 0, sizeof(AppDataFtpClient));

    /*
     * fill in connection id, etc.
     */
    ftpClient->connectionId = -1;
    ftpClient->uniqueId = node->appData.uniqueId++;

    ftpClient->localAddr = clientAddr;
    ftpClient->remoteAddr = serverAddr;

    // Make unique seed.
    RANDOM_SetSeed(ftpClient->seed,
                   node->globalSeed,
                   node->nodeId,
                   APP_FTP_CLIENT,
                   ftpClient->uniqueId);

    if (itemsToSend > 0)
    {
        ftpClient->itemsToSend = itemsToSend;
    }
    else
    {
        ftpClient->itemsToSend = AppFtpClientItemsToSend(ftpClient);
    }

    ftpClient->itemSizeLeft = 0;
    ftpClient->lastItemSent = 0;
    ftpClient->stats = NULL;
    if (appName)
    {
        ftpClient->applicationName = new std::string(appName);
    }
    else
    {
        ftpClient->applicationName = new std::string();
    }

#ifdef DEBUG
    char addrStr[MAX_STRING_LENGTH];
    printf("FTP Client: Node %d creating new ftp "
           "client structure\n", node->nodeId);
    printf("    connectionId = %d\n", ftpClient->connectionId);
    IO_ConvertIpAddressToString(&ftpClient->localAddr, addrStr);
    printf("    localAddr = %s\n", addrStr);
    IO_ConvertIpAddressToString(&ftpClient->remoteAddr, addrStr);
    printf("    remoteAddr = %s\n", addrStr);
    printf("    itemsToSend = %d\n", ftpClient->itemsToSend);
#endif /* DEBUG */

    #ifdef DEBUG_OUTPUT_FILE
    {
        char fileName[MAX_STRING_LENGTH];
        FILE *fp;
        char dataBuf[MAX_STRING_LENGTH];

        sprintf(fileName, "FTP_Throughput_%d", node->nodeId);

        /*
         * Open a data file to accumulate different statistics
         * informations of this node.
         */
        fp = fopen(fileName, "w");
        if (fp)
        {
            sprintf(dataBuf, "%s\n", "Simclock   Throughput(in Kbps) ");
            fwrite(dataBuf, strlen(dataBuf), 1, fp);
            fclose(fp);
        }
    }
    #endif

    // dynamic address
    ftpClient->destNodeId = ANY_NODEID;
    ftpClient->clientInterfaceIndex = ANY_INTERFACE;
    ftpClient->destInterfaceIndex = ANY_INTERFACE;
    ftpClient->serverUrl = new std::string();
    ftpClient->serverUrl->clear();
    APP_RegisterNewApp(node, APP_FTP_CLIENT, ftpClient);


    return ftpClient;
}

/*
 * NAME:        AppFtpClientSendNextItem.
 * PURPOSE:     Send the next item.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */
void
AppFtpClientSendNextItem(Node *node, AppDataFtpClient *clientPtr)
{
    assert(clientPtr->itemSizeLeft == 0);

    if (clientPtr->itemsToSend > 0)
    {
        clientPtr->itemSizeLeft = AppFtpClientItemSize(clientPtr);
        clientPtr->itemSizeLeft += AppFtpClientCtrlPktSize(clientPtr);

        AppFtpClientSendNextPacket(node, clientPtr);
        clientPtr->itemsToSend --;
    }
    else
    {
        if (!clientPtr->sessionIsClosed)
        {
            Message *msg = APP_TcpCreateMessage(
                node,
                clientPtr->connectionId,
                TRACE_FTP);

            APP_AddPayload(node, msg, "c", 1);

            node->appData.appTrafficSender->appTcpSend(node, msg);

            if (node->appData.appStats)
            { 
                clientPtr->stats->AddFragmentSentDataPoints(node,
                                                            1,
                                                            STAT_Unicast);
                clientPtr->stats->AddMessageSentDataPoints(node,
                                                           msg,
                                                           0,
                                                           1,
                                                           0,
                                                           STAT_Unicast);
            }
        }

        clientPtr->sessionIsClosed = TRUE;
        clientPtr->sessionFinish = node->getNodeTime();
        if (node->appData.appStats)
        { 
            if (!clientPtr->stats->IsSessionFinished())
            {
                clientPtr->stats->SessionFinish(node);
            }
        }
    }
}

/*
 * NAME:        AppFtpClientSendNextPacket.
 * PURPOSE:     Send the remaining data.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */
void
AppFtpClientSendNextPacket(Node *node, AppDataFtpClient *clientPtr)
{
    int itemSize;
    char *payload;

    /* Break packet down of larger than APP_MAX_DATA_SIZE. */
    if (clientPtr->itemSizeLeft > APP_MAX_DATA_SIZE)
    {
        itemSize = APP_MAX_DATA_SIZE;
        clientPtr->itemSizeLeft -= APP_MAX_DATA_SIZE;
        payload = (char *)MEM_malloc(itemSize);
        memset(payload,'d',itemSize);
    }
    else
    {
        itemSize = clientPtr->itemSizeLeft;
        payload = (char *)MEM_malloc(itemSize);
        memset(payload,'d',itemSize);

        /* Mark the end of the packet. */

         *(payload + itemSize - 1) = 'e';
          clientPtr->itemSizeLeft = 0;
    }

    if (!clientPtr->sessionIsClosed)
    {
        Message *msg = APP_TcpCreateMessage(
            node,
            clientPtr->connectionId,
            TRACE_FTP);

        APP_AddPayload(node, msg, payload, itemSize);

        node->appData.appTrafficSender->appTcpSend(node, msg);

        if (node->appData.appStats)
        {
            clientPtr->stats->AddFragmentSentDataPoints(node,
                                                        itemSize,
                                                        STAT_Unicast);
            clientPtr->stats->AddMessageSentDataPoints(node,
                                                       msg,
                                                       0,
                                                       itemSize,
                                                       0,
                                                       STAT_Unicast);
        }
    }
    MEM_free(payload);
}

/*
 * NAME:        AppFtpClientItemsToSend.
 * PURPOSE:     call tcplib function ftp_nitems() to get the
 *              number of items to send in an ftp session.
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      amount of items to send.
 */
int
AppFtpClientItemsToSend(AppDataFtpClient *clientPtr)
{
    int items;

    items = ftp_nitems(clientPtr->seed);

#ifdef DEBUG
    printf("FTP nitems = %d\n", items);
#endif /* DEBUG */

    return items;
}

/*
 * NAME:        AppFtpClientItemSize.
 * PURPOSE:     call tcplib function ftp_itemsize() to get the size
 *              of each item.
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      size of an item.
 */
int
AppFtpClientItemSize(AppDataFtpClient *clientPtr)
{
    int size;

    size = ftp_itemsize(clientPtr->seed);

#ifdef DEBUG
    printf("FTP item size = %d\n", size);
#endif /* DEBUG */

    return size;
}

/*
 * NAME:        AppFtpClientCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppFtpClientCtrlPktSize(AppDataFtpClient *clientPtr)
{
    int ctrlPktSize;
    ctrlPktSize = ftp_ctlsize(clientPtr->seed);

#ifdef DEBUG
    printf("FTP: Node %d ftp control pktsize = %d\n",
           ctrlPktSize);
#endif /* DEBUG */

    return (ctrlPktSize);
}

/*
 * NAME:        AppFtpServerGetFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataFtpServer *
AppFtpServerGetFtpServer(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataFtpServer *ftpServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FTP_SERVER)
        {
            ftpServer = (AppDataFtpServer *) appList->appDetail;

            if (ftpServer->connectionId == connId)
            {
                return ftpServer;
            }
        }
    }

    return NULL;
}


/*
 * NAME:        AppFtpServerNewFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpServer *
AppFtpServerNewFtpServer(Node *node,
                         TransportToAppOpenResult *openResult)
{
    AppDataFtpServer *ftpServer;

    ftpServer = (AppDataFtpServer *)
                MEM_malloc(sizeof(AppDataFtpServer));

    /*
     * fill in connection id, etc.
     */
    ftpServer->connectionId = openResult->connectionId;
    ftpServer->localAddr = openResult->localAddr;
    ftpServer->remoteAddr = openResult->remoteAddr;
    ftpServer->sessionStart = node->getNodeTime();
    ftpServer->sessionFinish = node->getNodeTime();
    ftpServer->lastTime = 0;
    ftpServer->sessionIsClosed = FALSE;
    ftpServer->bytesRecvdDuringThePeriod = 0;
    ftpServer->lastItemSent = 0;
    ftpServer->uniqueId = node->appData.uniqueId++;
    if (node->appData.appStats)
    {
        ftpServer->stats = new STAT_AppStatistics(
                                node,
                                "ftpServer",
                                STAT_Unicast,
                                STAT_AppSenderReceiver,
                                "FTP Server");
        ftpServer->stats->Initialize(
            node,
            openResult->remoteAddr,
            openResult->localAddr,
            (STAT_SessionIdType)openResult->clientUniqueId,
            ftpServer->uniqueId);
        ftpServer->stats->EnableAutoRefragment();
        ftpServer->stats->SessionStart(node);
    }
    RANDOM_SetSeed(ftpServer->seed,
                   node->globalSeed,
                   node->nodeId,
                   APP_FTP_SERVER,
                   ftpServer->connectionId);

    APP_RegisterNewApp(node, APP_FTP_SERVER, ftpServer);

    #ifdef DEBUG_OUTPUT_FILE
    {
        char fileName[MAX_STRING_LENGTH];
        FILE *fp;
        char dataBuf[MAX_STRING_LENGTH];

        sprintf(fileName, "FTP_Throughput_%d", node->nodeId);

        /*
         * Open a data file to accumulate different statistics
         * informations of this node.
         */
        fp = fopen(fileName, "w");
        if (fp)
        {
            sprintf(dataBuf, "%s\n", "Simclock   Throughput(in Kbps) ");
            fwrite(dataBuf, strlen(dataBuf), 1, fp);
            fclose(fp);
        }
    }
    #endif

    return ftpServer;
}

/*
 * NAME:        AppFtpServerSendCtrlPkt.
 * PURPOSE:     call AppFtpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  node - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppFtpServerSendCtrlPkt(Node *node, AppDataFtpServer *serverPtr)
{
    int pktSize;
    char *payload;

    pktSize = AppFtpServerCtrlPktSize(serverPtr);

    if (pktSize > APP_MAX_DATA_SIZE)
    {
        /*
         * Control packet size is larger than APP_MAX_DATA_SIZE,
         * set it to APP_MAX_DATA_SIZE. This should be rare.
         */
        pktSize = APP_MAX_DATA_SIZE;
    }
    payload = (char *)MEM_malloc(pktSize);
    memset(payload,'d',pktSize);
    if (!serverPtr->sessionIsClosed)
    {
        Message *msg = APP_TcpCreateMessage(
            node,
            serverPtr->connectionId,
            TRACE_FTP);

        APP_AddPayload(node, msg, payload, pktSize);

        node->appData.appTrafficSender->appTcpSend(node, msg);

        if (node->appData.appStats)
        {
            serverPtr->stats->AddFragmentSentDataPoints(node,
                                                        pktSize,
                                                        STAT_Unicast);
            serverPtr->stats->AddMessageSentDataPoints(node,
                                                       msg,
                                                       0,
                                                       pktSize,
                                                       0,
                                                       STAT_Unicast);
        }
    }
    MEM_free(payload);
}

/*
 * NAME:        AppFtpServerCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppFtpServerCtrlPktSize(AppDataFtpServer *serverPtr)
{
    int ctrlPktSize;
    ctrlPktSize = ftp_ctlsize(serverPtr->seed);

#ifdef DEBUG
    printf("FTP: Node ftp control pktsize = %d\n",
           ctrlPktSize);
#endif /* DEBUG */

    return (ctrlPktSize);
}

/*
 * Public Functions
 */

/*
 * NAME:        AppLayerFtpClient.
 * PURPOSE:     Models the behaviour of Ftp Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerFtpClient(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataFtpClient *clientPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;

            openResult = (TransportToAppOpenResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: FTP Client node %u got OpenResult\n", buf, node->nodeId);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_ACTIVE_OPEN);

            if (openResult->connectionId < 0)
            {
#ifdef DEBUG
                printf("%s: FTP Client node %u connection failed!\n",
                       buf, node->nodeId);
#endif /* DEBUG */

                node->appData.numAppTcpFailure ++;
            }
            else
            {
                AppDataFtpClient *clientPtr;

                clientPtr = AppFtpClientUpdateFtpClient(node, openResult);

                assert(clientPtr != NULL);

                AppFtpClientSendNextItem(node, clientPtr);
            }

            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: FTP Client node %u sent data %d\n",
                   buf, node->nodeId, dataSent->length);
#endif /* DEBUG */

            clientPtr = AppFtpClientGetFtpClient(node,
                                                 dataSent->connectionId);

            assert(clientPtr != NULL);

            clientPtr->lastItemSent = node->getNodeTime();

            /* Instant throughput is measured here after each 1 second */
            #ifdef DEBUG_OUTPUT_FILE
            {
                char fileName[MAX_STRING_LENGTH];
                FILE *fp;
                clocktype currentTime;

                clientPtr->bytesRecvdDuringThePeriod += dataSent->length;

                sprintf(fileName, "FTP_Throughput_%d", node->nodeId);

                fp = fopen(fileName, "a");
                if (fp)
                {
                    currentTime = node->getNodeTime();

                    if ((int)((currentTime -
                        clientPtr->lastTime)/SECOND) >= 1)
                    {
                        /* get throughput within this time window */
                        int throughput = (int)
                            ((clientPtr->bytesRecvdDuringThePeriod
                                * 8.0 * SECOND)
                            / (node->getNodeTime() - clientPtr->lastTime));

                        fprintf(fp, "%d\t\t%d\n", (int)(currentTime/SECOND),
                                (throughput/1000));

                        clientPtr->lastTime = currentTime;
                        clientPtr->bytesRecvdDuringThePeriod = 0;
                    }
                    fclose(fp);
                }
            }
            #endif

            if (clientPtr->itemSizeLeft > 0)
            {
                AppFtpClientSendNextPacket(node, clientPtr);
            }
            else if (clientPtr->itemsToSend == 0
                     && clientPtr->sessionIsClosed == TRUE)
            {
                node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                clientPtr->connectionId);
                // comments: apr 6 not needed, session should have already been closed
                if (node->appData.appStats)
                {
                    if (!clientPtr->stats->IsSessionFinished())
                    {
                        clientPtr->stats->SessionFinish(node);
                    }
                }
                // comments: apr 6 not needed
            }

            break;
        }
        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived *dataRecvd;

            dataRecvd = (TransportToAppDataReceived *)
                         MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: FTP Client node %u received data %d\n",
                   buf, node->nodeId, msg->packetSize);
#endif /* DEBUG */

            clientPtr = AppFtpClientGetFtpClient(node,
                                                 dataRecvd->connectionId);

            assert(clientPtr != NULL);

            if (node->appData.appStats)
            {
                clientPtr->stats->AddFragmentReceivedDataPoints(node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Unicast);
            }
            assert(msg->packet[msg->packetSize - 1] == 'd');

            if ((clientPtr->sessionIsClosed == FALSE) &&
                (clientPtr->itemSizeLeft == 0))
            {
                AppFtpClientSendNextItem(node, clientPtr);
            }

            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: FTP Client node %u got close result\n",
                   buf, node->nodeId);
#endif /* DEBUG */

            clientPtr = AppFtpClientGetFtpClient(node,
                                                 closeResult->connectionId);

            assert(clientPtr != NULL);
            if (node->appData.appStats)
            {
                if (!clientPtr->stats->IsSessionFinished())
                {
                    clientPtr->stats->SessionFinish(node);
                }
            }

            if (clientPtr->sessionIsClosed == FALSE)
            {
                clientPtr->sessionIsClosed = TRUE;
                clientPtr->sessionFinish = node->getNodeTime();
            }

            break;
        }
        default:
            ctoa(node->getNodeTime(), buf);
            printf("Time %s: FTP Client node %u received message of unknown"
                   " type %d.\n", buf, node->nodeId, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppFtpClientInit.
 * PURPOSE:     Initialize a Ftp session.
 * PARAMETERS:  node - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              waitTime - time until the session starts.
 *              appName - application alias name
 *              destString - destination string
 * RETURN:      none.
 */
void
AppFtpClientInit(
    Node *node,
    Address clientAddr,
    Address serverAddr,
    int itemsToSend,
    clocktype waitTime,
    char* appName,
    char* destString)
{
    AppDataFtpClient *clientPtr;

    /* Check to make sure the number of ftp items is a correct value. */

    if (itemsToSend < 0)
    {
        printf("FTP Client: Node %d items to send needs to be >= 0\n",
               node->nodeId);

        exit(0);
    }

    clientPtr = AppFtpClientNewFtpClient(node,
                                         clientAddr,
                                         serverAddr,
                                         itemsToSend,
                                         appName);

    if (clientPtr == NULL)
    {
        printf("FTP Client: Node %d cannot allocate "
               "new ftp client\n", node->nodeId);

        assert(FALSE);
    }
    // dns
    // delay TCP connection untill
    // url is resolved , network type will be invalid
    // if server url is present
    if (serverAddr.networkType != NETWORK_INVALID)
    {
        if (node->appData.appStats)
        {
            std::string customName;
            if (clientPtr->applicationName->empty())
            {
                customName = "FTP Client";
            }
            else
            {
                customName = *clientPtr->applicationName;
            }
            clientPtr->stats = new STAT_AppStatistics(
                                     node,
                                     "ftp",
                                     STAT_Unicast,
                                     STAT_AppSenderReceiver,
                                     customName.c_str());
            clientPtr->stats->EnableAutoRefragment();
            clientPtr->stats->Initialize(
                 node,
                 clientAddr,
                 serverAddr,
                 (STAT_SessionIdType)clientPtr->uniqueId,
                 clientPtr->uniqueId);
        }
    }
    if (serverAddr.networkType == NETWORK_INVALID && destString)
    {
        // set the dns info in client pointer if server url 
        // is present
        // set the server url if it is not localhost
        if (node->appData.appTrafficSender->ifUrlLocalHost(destString) 
                                                                    == FALSE)
        {
            node->appData.appTrafficSender->
                                appClientSetDnsInfo(
                                        node,
                                        (const char*)destString,
                                        clientPtr->serverUrl);
        }
    }

    // Update the FTP clientPtr with address information
    AppFtpClientAddAddressInformation(node, clientPtr);

    node->appData.appTrafficSender->appTcpOpenConnection(
                                node,
                                APP_FTP_CLIENT,
                                clientPtr->localAddr,
                                node->appData.nextPortNum++,
                                clientPtr->remoteAddr,
                                (UInt16) APP_FTP_SERVER,
                                clientPtr->uniqueId,
                                APP_DEFAULT_TOS,
                                ANY_INTERFACE,
                                *clientPtr->serverUrl,
                                waitTime,
                                clientPtr->destNodeId,
                                clientPtr->clientInterfaceIndex,
                                clientPtr->destInterfaceIndex);
}

/*
 * NAME:        AppFtpClientPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              clientPtr - pointer to the ftp client data structure.
 * RETURN:      none.
 */
void
AppFtpClientPrintStats(Node *node, AppDataFtpClient *clientPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (clientPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (clientPtr->sessionIsClosed == FALSE)
    {
        clientPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
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
        sprintf(statusStr, "Closed");
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

    sprintf(buf, "Server address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "FTP Client",
        ANY_DEST,
        clientPtr->connectionId,
        buf);

    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "FTP Client",
        ANY_DEST,
        clientPtr->connectionId,
        buf);
}

/*
 * NAME:        AppFtpClientFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppFtpClientFinalize(Node *node, AppInfo* appInfo)
{
    AppDataFtpClient *clientPtr = (AppDataFtpClient*)appInfo->appDetail;

    if ((node->appData.appStats == TRUE)
        && clientPtr->remoteAddr.networkType != NETWORK_INVALID)
    {
        AppFtpClientPrintStats(node, clientPtr);
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                node,
                "Application",
                "FTP Client",
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
 * NAME:        AppLayerFtpServer.
 * PURPOSE:     Models the behaviour of Ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerFtpServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataFtpServer *serverPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s got listenResult\n",
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
            printf("FTP Server: Node %ld at %s got OpenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_PASSIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure++;
            }
            else
            {
                AppDataFtpServer *serverPtr;
                serverPtr = AppFtpServerNewFtpServer(node, openResult);
                assert(serverPtr != NULL);
            }

            break;
        }

        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server Node %ld at %s sent data %ld\n",
                   node->nodeId, buf, dataSent->length);
#endif /* DEBUG */

            serverPtr = AppFtpServerGetFtpServer(node,
                                     dataSent->connectionId);

            assert(serverPtr != NULL);

            serverPtr->lastItemSent = node->getNodeTime();

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
            printf("FTP Server: Node %ld at %s received data size %d\n",
                   node->nodeId, buf, MESSAGE_ReturnPacketSize(msg));
#endif /* DEBUG */

            serverPtr = AppFtpServerGetFtpServer(node,
                                                 dataRecvd->connectionId);

            //assert(serverPtr != NULL);
            if (serverPtr == NULL)
            {
                // server pointer can be NULL due to the real-world apps
                break;

            }
            assert(serverPtr->sessionIsClosed == FALSE);

            if (node->appData.appStats)
            {
                serverPtr->stats->AddFragmentReceivedDataPoints(
                        node,
                        msg,
                        MESSAGE_ReturnPacketSize(msg),
                        STAT_Unicast);
            }

            /*
             * Test if the received data contains the last byte
             * of an item.  If so, send a response packet back.
             * If the data contains a 'c', close the connection.
             */
            if (packet[msg->packetSize - 1] == 'd')
            {
                /* Do nothing since item is not completely received yet. */
            }
            else if (packet[msg->packetSize - 1] == 'e')
            {
                /* Item completely received, now send control info. */

                AppFtpServerSendCtrlPkt(node, serverPtr);
            }
            else if (packet[msg->packetSize - 1] == 'c')
            {
                /*
                 * Client wants to close the session, so server also
                 * initiates a close.
                 */
                node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                serverPtr->connectionId);
                if (node->appData.appStats)
                {
                    if (!serverPtr->stats->IsSessionFinished())
                    {
                        serverPtr->stats->SessionFinish(node);
                    }
                }
                serverPtr->sessionFinish = node->getNodeTime();
                serverPtr->sessionIsClosed = TRUE;
            }
            else
            {
               assert(FALSE);
            }

            break;
        }

        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s got close result\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            serverPtr = AppFtpServerGetFtpServer(node,
                                                 closeResult->connectionId);
            assert(serverPtr != NULL);
            if (node->appData.appStats)
            {
                if (!serverPtr->stats->IsSessionFinished())
                {
                    serverPtr->stats->SessionFinish(node);
                }
            }
            if (serverPtr->sessionIsClosed == FALSE)
            {
                serverPtr->sessionIsClosed = TRUE;
                serverPtr->sessionFinish = node->getNodeTime();
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
                AppFtpServerInit(node, serverAddress);
            }
            break;
        }
        default:
            ctoa(node->getNodeTime(), buf);
            printf("FTP Server: Node %u at time %s received "
                   "message of unknown type"
                   " %d.\n", node->nodeId, buf, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppFtpServerInit.
 * PURPOSE:     listen on Ftp server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppFtpServerInit(Node *node, Address serverAddr)
{
    node->appData.appTrafficSender->appTcpListen(
                                    node,
                                    APP_FTP_SERVER,
                                    serverAddr,
                                    (UInt16) APP_FTP_SERVER);
}

/*
 * NAME:        AppFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppFtpServerPrintStats(Node *node, AppDataFtpServer *serverPtr)
{
    char addrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (serverPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
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
        sprintf(statusStr, "Closed");
    }



    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);


    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);


}

/*
 * NAME:        AppFtpServerFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppFtpServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataFtpServer *serverPtr = (AppDataFtpServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        // Print Stats unique to this Application
        AppFtpServerPrintStats(node, serverPtr);
        // Print stats in .stat file using Stat APIs
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(
                 node,
                "Application",
                "FTP Server",
                ANY_ADDRESS,
                serverPtr->connectionId);
        }
    }
}

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppFtpClientAddAddressInformation.
// PURPOSE              : store client interface index, destination 
//                        interface index destination node id to get the 
//                        correct address when application starts
// PARAMETERS:
// + node               : Node*             : pointer to the node
// + clientPtr          : AppDataFtpClient* : pointer to client data
// RETRUN               : NONE
//---------------------------------------------------------------------------
void
AppFtpClientAddAddressInformation(Node* node,
                                  AppDataFtpClient* clientPtr)
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
// FUNCTION             : AppFtpClientGetClientPtr.
// PURPOSE              : get the FTP client pointer
// PARAMETERS           ::
// + node               : Node* : pointer to the node
// + uniqueId           : Int32 : unique id
// RETURN               
// AppDataFtpClient*    : ftp client pointer
//---------------------------------------------------------------------------
AppDataFtpClient*
AppFtpClientGetClientPtr(
                        Node* node,
                        Int32 uniqueId)
{
    AppInfo* appList = node->appData.appPtr;
    AppDataFtpClient* ftpClient = NULL;
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FTP_CLIENT)
        {
            ftpClient = (AppDataFtpClient*) appList->appDetail;

            if (ftpClient->uniqueId == uniqueId)
            {
                return (ftpClient);
            }
        }
    }
    return (NULL);
}

// dns
//--------------------------------------------------------------------------
// FUNCTION    :: AppFtpUrlSessionStartCallBack
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
//                                                 used by FTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//--------------------------------------------------------------------------
bool
AppFtpUrlSessionStartCallBack(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    AppUdpPacketSendingInfo* packetSendingInfo)
{
    AppDataFtpClient* clientPtr = NULL;

    clientPtr = AppFtpClientGetClientPtr(
                                        node,
                                        uniqueId);
    if (clientPtr == NULL)
    {
           return (FALSE);
    }
    if (clientPtr->lastItemSent != 0)
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
            ERROR_ReportErrorArgs("FTP Client: Node %d cannot find IPv6 ftp"
                " client for ipv4 dest\n",
                node->nodeId);
        }
    }
    else if (serverAddr->networkType == NETWORK_IPV6)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV6)
        {
            ERROR_ReportErrorArgs("FTP Client: Node %d cannot find IPv4 ftp"
                " client for ipv6 dest\n",
                node->nodeId);
        }
    }
    if (node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
           customName = "FTP Client";
        }
        else
        {
           customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                                 node,
                                 "ftp",
                                 STAT_Unicast,
                                 STAT_AppSenderReceiver,
                                 customName.c_str());
        clientPtr->stats->EnableAutoRefragment();
        clientPtr->stats->Initialize(
                 node,
                 clientPtr->localAddr,
                 *serverAddr,
                 (STAT_SessionIdType)clientPtr->uniqueId,
                 clientPtr->uniqueId);
    }
    memcpy(
        &clientPtr->remoteAddr, 
        serverAddr,
        sizeof(Address));
    AppFtpClientAddAddressInformation(node, clientPtr);
    memset (packetSendingInfo, 0, sizeof(AppUdpPacketSendingInfo));
    return (FALSE);
}
