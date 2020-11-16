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
#include "app_mcbr.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#include "partition.h"
#endif

/*
 * NAME:        AppLayerMCbrClient.
 * PURPOSE:     Models the behaviour of MCbrClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerMCbrClient(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataMCbrClient *clientPtr;

    ctoa(node->getNodeTime()+getSimStartTime(node), buf);

#ifdef DEBUG
    printf("MCBR Client: Node %u got a message at %s\n",
           node->nodeId, buf);
#endif /* DEBUG */

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            AppTimer *timer;

            timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("MCBR Client: Node %u at %s got timer %d\n",
                   node->nodeId, buf, timer->type);
#endif /* DEBUG */

            clientPtr = AppMCbrClientGetMCbrClient(node, timer->sourcePort);
            Int32 itemSizeRead = clientPtr->itemSize;


           if (clientPtr == NULL)
            {
                printf("MCBR Client: Node %u cannot find mcbr client\n",
                       node->nodeId);

                assert(FALSE);
            }

            switch (timer->type)
            {
                case APP_TIMER_SEND_PKT:
                {
                    char *payload;
                    MCbrData data;
                    memset(&data, 0, sizeof(data));

                    payload = (char *)MEM_malloc(itemSizeRead);
                    memset(payload, 0, itemSizeRead);

#ifdef DEBUG
                    printf("MCBR Client: Node %u has %u items left"
                        "to send\n", node->nodeId, clientPtr->itemsToSend);
#endif /* DEBUG */

                    if (((clientPtr->itemsToSend > 1) &&
                         (node->getNodeTime() + clientPtr->interval
                         < clientPtr->endTime)) ||
                        ((clientPtr->itemsToSend == 0) &&
                         (node->getNodeTime() + clientPtr->interval
                          < clientPtr->endTime)) ||
                        ((clientPtr->itemsToSend > 1) &&
                         (clientPtr->endTime == 0)) ||
                        ((clientPtr->itemsToSend == 0) &&
                         (clientPtr->endTime == 0)))
                    {
                        data.type = 'd';
                    }
                    else
                    {
                        data.type = 'c';
                        clientPtr->sessionIsClosed = TRUE;
                        clientPtr->sessionFinish = node->getNodeTime();
                        if (node->appData.appStats)
                        {
                            clientPtr->stats->SessionFinish(node,
                                                        STAT_Multicast);
                        }
                    }

                    data.sourcePort = clientPtr->sourcePort;
                    data.txTime = node->getNodeTime();
                    data.seqNo = clientPtr->seqNo++;

                    data.isMdpEnabled = clientPtr->isMdpEnabled;

                    memcpy(payload, &data, sizeof(data));

#ifdef DEBUG
                    {
                        char clockStr[24];
                        ctoa(node->getNodeTime()+getSimStartTime(node),
                                                              clockStr);

                        printf("MCBR Client: node %u sending data packet"
                               " at time %s to MCBR server %u\n",
                               node->nodeId,
                               clockStr,
                               clientPtr->remoteAddr);
                        printf("    size of payload is %d\n",
                               clientPtr->itemSize);
                    }
#endif /* DEBUG */
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.m_SessionInitiator = node->nodeId;
    appParam.m_ReceiverId = clientPtr->receiverId;
    appParam.SetPriority(clientPtr->tos);
    appParam.SetFragNum(0);
    appParam.SetSessionId(clientPtr->uniqueId);
    appParam.SetAppType("MCBR");

    if (!clientPtr->applicationName->empty())
    {
        appParam.SetAppName(clientPtr->applicationName->c_str());
    }
    appParam.SetReceiverAddr(&clientPtr->remoteAddr);
    appParam.SetMsgSize(itemSizeRead);
    appParam.m_TotalMsgSize = itemSizeRead;
    appParam.m_fragEnabled = FALSE;
#endif

                    // Dynamic address
                    // Create and send a UDP msg with header and virtual 
                    // payload.
                    // if the client has not yet acquired a valid
                    // address then the application packets should not be 
                    // generated 
                    // check whether client is in valid address
                    // state
                    // if this is session start then packets will not be sent
                    // if in invalid address state and session will be closed
                    // ; if the session has already started and address 
                    // becomes invalid during application session then 
                    // packets will get generated but will be dropped at
                    //  network layer
                    if (AppMcbrClientGetSessionAddressState(node, clientPtr)
                            == ADDRESS_FOUND)
                    {
                        Message* msg = APP_UdpCreateMessage(
                                                    node,
                                                    clientPtr->localAddr,
                                                    clientPtr->sourcePort,
                                                    clientPtr->remoteAddr,
                                                    APP_MCBR_SERVER,
                                                    TRACE_MCBR,
                                                    clientPtr->tos);

                        if (clientPtr->isMdpEnabled)
                        {
                            APP_UdpSetMdpEnabled(
                                    msg, clientPtr->mdpUniqueId);
                        }

                        APP_AddPayload(
                            node,
                            msg,
                            payload,
                            clientPtr->itemSize);

#ifdef ADDON_DB
                        APP_UdpSend(node,
                                    msg,
                                    PROCESS_IMMEDIATELY,
                                    &appParam);
#else
                        APP_UdpSend(node, msg);
#endif

                        if (node->appData.appStats)
                        {
                            if (clientPtr->stats->GetMessagesSent(
                                STAT_Multicast).GetValue(node->getNodeTime()) 
                                                                == 0)
                            {
                                clientPtr->stats->SessionStart(
                                                    node,STAT_Multicast);
                            }
                            clientPtr->stats->AddFragmentSentDataPoints(node,
                                                        clientPtr->itemSize,
                                                        STAT_Multicast);
                            clientPtr->stats->AddMessageSentDataPoints(node,
                                                        msg,
                                                        0,
                                                        clientPtr->itemSize,
                                                        0,
                                                        STAT_Multicast);
                        }

                        clientPtr->sessionLastSent = node->getNodeTime();

                        if (clientPtr->itemsToSend > 0)
                        {
                            clientPtr->itemsToSend--;
                        }

                        if (clientPtr->sessionIsClosed == FALSE)
                        {
                            AppMCbrClientScheduleNextPkt(node, clientPtr);
                        }
                    }
                    else
                    {
                        clientPtr->sessionStart = 0;
                        clientPtr->sessionIsClosed = TRUE;
                    }

                    MEM_free(payload);
                    break;
                }

                default:
                {
#ifndef EXATA
                    assert(FALSE);
#endif
                }
            }

            break;
        }
        default:
           ctoa(node->getNodeTime()+getSimStartTime(node), buf);
           printf("MCBR Client: at time %s, node %u "
                  "received message of unknown type"
                  " %u.\n", buf, node->nodeId, msg->eventType);
#ifndef EXATA
           assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppMCbrClientInit.
 * PURPOSE:     Initialize a MCbrClient session.
 * PARAMETERS:  node - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts,
 *              endTime - time until the session ends,
 *              srcString - source name
 *              destString - destination name
 *              tos - the contents for the type of service field.
 *              isMdpEnabled - true if MDP is enabled by user.
 *              isProfileNameSet - true if profile name is provided by user.
 *              profileName - mdp profile name.
 *              uniqueId - mdp session unique id.
 *              nodeInput - nodeInput for config file.
 * RETURN:      none.
 */
void
AppMCbrClientInit(
    Node *node,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype interval,
    clocktype startTime,
    clocktype endTime,
    const char* srcString,
    const char* destString,
    unsigned tos,
    char* appName,
    BOOL isMdpEnabled,
    BOOL isProfileNameSet,
    char* profileName,
    Int32 uniqueId,
    const NodeInput* nodeInput)
{
    AppTimer *timer;
    AppDataMCbrClient *clientPtr;
    Message *timerMsg;
    int minSize;

    startTime -= getSimStartTime(node);
    endTime -= getSimStartTime(node);


    minSize = sizeof(MCbrData);

    /* Check to make sure the number of mcbr items is a correct value. */
    if (itemsToSend < 0)
    {
        printf("MCBR Client: Node %u item to sends needs to be >= 0\n",
               node->nodeId);

        exit(0);
    }

    /* Make sure that packet is big enough to carry mcbr data information. */
    if (itemSize < minSize)
    {
        printf("MCBR Client: Node %u item size needs to be >= %d.\n",
                node->nodeId, minSize);
        exit(0);
    }

    /* Make sure that packet is within max limit. */
    if (itemSize > APP_MAX_DATA_SIZE)
    {
        printf("MCBR Client: Node %u item size needs to be <= %d.\n",
                node->nodeId, APP_MAX_DATA_SIZE);
        exit(0);
    }

    /* Make sure interval is valid. */
    if (interval <= 0)
    {
        printf("MCBR Client: Node %u interval needs to be > 0.\n",
                node->nodeId);
        exit(0);
    }

    /* Make sure start time is valid. */
    if (startTime < 0)
    {
        printf("MCBR Client: Node %u start time needs to be >= 0.\n",
                node->nodeId);
        exit(0);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        printf("MCBR Client: Node %u end time needs to be > start time "
               "or equal to 0.\n", node->nodeId);

        exit(0);
    }

    // Validate the given tos for this application.
    if (tos > 255)
    {
        printf("MCBR Client: Node %u should have tos value "
            "within the range 0 to 255.\n",
            node->nodeId);
        exit(0);
    }

    clientPtr = AppMCbrClientNewMCbrClient(node,
                                         clientAddr,
                                         serverAddr,
                                         itemsToSend,
                                         itemSize,
                                         interval,
                                         startTime,
                                         endTime,
                                         tos,
                                         appName);
    if (clientPtr == NULL)
    {
        printf("MCBR Client: Node %u cannot allocate memory for"
               " new client\n", node->nodeId);

        assert(FALSE);
    }

    if (isMdpEnabled)
    {
    //client pointer initialization with respect to mdp
        clientPtr->isMdpEnabled = TRUE;
    clientPtr->mdpUniqueId = uniqueId;

    // MDP Layer Init
    MdpLayerInit(node,
                 clientAddr,
                 serverAddr,
                 clientPtr->sourcePort,
                 APP_MCBR_CLIENT,
                 isProfileNameSet,
                 profileName,
                 uniqueId,
                 nodeInput);
    }

    timerMsg = MESSAGE_Alloc(node,
                              APP_LAYER,
                              APP_MCBR_CLIENT,
                              MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

    timer->sourcePort = (short) clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

    if (node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "MCBR Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        // Create statistics
        clientPtr->stats = new STAT_AppStatistics(
                                        node,
                                        "mcbr",
                                        STAT_Multicast,
                                        STAT_AppSender,
                                        customName.c_str());
        clientPtr->stats->Initialize(
             node,
             clientAddr,
             serverAddr,
             (STAT_SessionIdType)clientPtr->uniqueId,
             clientPtr->uniqueId);

        // Create application hop by hop flow filter button
        if (GUI_IsAppHopByHopFlowEnabled())
        {
            GUI_CreateAppHopByHopFlowFilter(clientPtr->stats->GetSessionId(),
                node->nodeId, srcString, destString, "MCBR");
        }
        clientPtr->stats->setTos(tos);
    }


#ifdef DEBUG
    {
        char clockStr[24];
        ctoa(startTime+getSimStartTime(node), clockStr);
        printf("MCBR Client: Node %u starting client at %s\n",
               node->nodeId, clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, startTime);

#ifdef ADDON_NGCNMS

    clientPtr->lastTimer = timerMsg;

#endif
    
    // Dynamic Address
    // Update the MCBR clientPtr with address information
    AppMcbrClientAddAddressInformation(node, clientPtr);
}

/*
 * NAME:        AppMCbrClientPrintStats.
 * PURPOSE:     Prints statistics of a MCbrClient session.
 * PARAMETERS:  node - pointer to the this node.
 *              clientPtr - pointer to the mcbr client data structure.
 * RETURN:      none.
 */
void AppMCbrClientPrintStats(Node *node, AppDataMCbrClient *clientPtr) {

    char addrStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];

    char buf[MAX_STRING_LENGTH];

    if (clientPtr->sessionIsClosed == FALSE) {
        clientPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
        if (clientPtr->stats)
        {
            if (!clientPtr->stats->IsSessionFinished(STAT_Multicast))
            {
                clientPtr->stats->SessionFinish(node,STAT_Multicast);
            }
        }
    }
    else {
        sprintf(sessionStatusStr, "Closed");
    }

    IO_ConvertIpAddressToString(&clientPtr->remoteAddr, addrStr);

    sprintf(buf, "Server Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "MCBR Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "MCBR Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);
}

/*
 * NAME:        AppMCbrClientFinalize.
 * PURPOSE:     Collect statistics of a MCbrClient session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppMCbrClientFinalize(Node *node, AppInfo* appInfo)
{
    AppDataMCbrClient *clientPtr = (AppDataMCbrClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppMCbrClientPrintStats(node, clientPtr);
        // Print stats in .stat file using Stat APIs
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                node,
                "Application",
                "MCBR Client",
                ANY_ADDRESS,
                clientPtr->sourcePort);
        }
    }
}

/*
 * NAME:        AppMCbrClientGetMCbrClient.
 * PURPOSE:     search for a mcbr client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              sourcePort - connection ID of the mcbr client.
 * RETURN:      the pointer to the mcbr client data structure,
 *              NULL if nothing found.
 */
AppDataMCbrClient *
AppMCbrClientGetMCbrClient(Node *node, int sourcePort)
{
    // Get list of apps based on node id and sourcePort
    Address addr;
    SetIPv4AddressInfo(&addr, node->nodeId);
    AppInfo *appList = node->appData.appMap->getAppInfo(addr, sourcePort);

    AppDataMCbrClient *mcbrClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_MCBR_CLIENT)
        {
            mcbrClient = (AppDataMCbrClient *) appList->appDetail;

            if (mcbrClient->sourcePort == sourcePort)
            {
                return mcbrClient;
            }
        }
    }

    return NULL;
}

#ifdef ADDON_NGCNMS
// reset source address of application so that we
// can route packets correctly.
void
AppMCbrClientReInit(Node* node, Address sourceAddr)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataMCbrClient *mcbrClient;
    int i;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_MCBR_CLIENT)
        {
            mcbrClient = (AppDataMCbrClient *) appList->appDetail;

            for (i=0; i< node->numberInterfaces; i++)
            {
                // currently only support ipv4. May be better way to compare this.
                if (mcbrClient->localAddr.interfaceAddr.ipv4 == node->iface[i].oldIpAddress)
                {
                    memcpy(&(mcbrClient->localAddr), &sourceAddr, sizeof(Address));
                    //mcbrClient->localAddr = sourceAddr;
                }
            }
        }
    }

}
#endif

/*
 * NAME:        AppMCbrClientNewMCbrClient.
 * PURPOSE:     create a new mcbr client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              remoteAddr - remote address.
 *              itemsToSend - number of mcbr items to send in simulation.
 *              itemSize - size of each packet.
 *              interval - time between two packets.
 *              startTime - when the node will start sending.
 *              tos - the contents for the type of service field.
 * RETURN:      the pointer to the created mcbr client data structure,
 *              NULL if no data structure allocated.
 */
AppDataMCbrClient *
AppMCbrClientNewMCbrClient(Node *node,
                         Address localAddr,
                         Address remoteAddr,
                         Int32 itemsToSend,
                         Int32 itemSize,
                         clocktype interval,
                         clocktype startTime,
                         clocktype endTime,
                         TosType tos,
                         char* appName)
{
    AppDataMCbrClient *mcbrClient;

    mcbrClient = (AppDataMCbrClient *)
                MEM_malloc(sizeof(AppDataMCbrClient));

    /*
     * fill in mcbr info.
     */
    mcbrClient->localAddr = localAddr;
    mcbrClient->remoteAddr = remoteAddr;
    mcbrClient->interval = interval;
    mcbrClient->sessionStart = node->getNodeTime() + startTime;
    mcbrClient->sessionIsClosed = FALSE;
    mcbrClient->sessionLastSent = node->getNodeTime();
    mcbrClient->sessionFinish = node->getNodeTime();
    mcbrClient->endTime = endTime;
    mcbrClient->itemsToSend = itemsToSend;
    mcbrClient->itemSize = itemSize;
    mcbrClient->sourcePort = node->appData.nextPortNum++;
    mcbrClient->seqNo = 0;
    mcbrClient->tos = tos;

    //client pointer initialization with respect to mdp
    mcbrClient->isMdpEnabled = FALSE;
    mcbrClient->mdpUniqueId = -1;  //invalid value
    mcbrClient->uniqueId = node->appData.uniqueId++;
    mcbrClient->stats = NULL;

#ifdef ADDON_DB
    mcbrClient->sessionId = mcbrClient->uniqueId;
    if (Address_IsAnyAddress(&(mcbrClient->remoteAddr)) ||
        Address_IsMulticastAddress(&mcbrClient->remoteAddr))
    {
        mcbrClient->receiverId = 0;
    }
    else
    {
        mcbrClient->receiverId =
            MAPPING_GetNodeIdFromInterfaceAddress(node, remoteAddr);
    }
#endif

    if (appName != NULL)
    {
        mcbrClient->applicationName = new std::string(appName);
    }
    else
    {
#ifdef ADDON_DB
        char defaultAppName[MAX_STRING_LENGTH];
        sprintf(defaultAppName,
                "MCBR-%d-%d",
                node->nodeId,
                mcbrClient->sessionId);
        mcbrClient->applicationName = new std::string(defaultAppName);
#else
        mcbrClient->applicationName = new std::string();
#endif
    }

#ifdef DEBUG
    {
        char clockStr[24];
        printf("MCBR Client: Node %u created new mcbr client structure\n",
               node->nodeId);
        printf("    localAddr = %u\n", mcbrClient->localAddr);
        printf("    remoteAddr = %u\n", mcbrClient->remoteAddr);
        ctoa(mcbrClient->interval, clockStr);
        printf("    interval = %s\n", clockStr);
        ctoa(mcbrClient->sessionStart+getSimStartTime(node), clockStr);
        printf("    sessionStart = %s\n", clockStr);
        printf("    itemsToSend = %u\n", mcbrClient->itemsToSend);
        printf("    itemSize = %u\n", mcbrClient->itemSize);
        printf("    sourcePort = %u\n", mcbrClient->sourcePort);
        printf("    seqNo = %u\n", mcbrClient->seqNo);
    }
#endif /* DEBUG */

    // dynamic address
    mcbrClient->clientInterfaceIndex = ANY_INTERFACE;
    
    APP_RegisterNewApp(node, APP_MCBR_CLIENT, mcbrClient);

    // Save app based on node id and sourcePort
    Address addr;
    SetIPv4AddressInfo(&addr, node->nodeId);
    node->appData.appMap->pushDetail(addr, mcbrClient->sourcePort, APP_MCBR_CLIENT, mcbrClient);

    return mcbrClient;
}

/*
 * NAME:        AppMCbrClientScheduleNextPkt.
 * PURPOSE:     schedule the next packet the client will send.  If next packet
 *              won't arrive until the finish deadline, schedule a close.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the mcbr client data structure.
 * RETRUN:      none.
 */
void //inline//
AppMCbrClientScheduleNextPkt(Node *node, AppDataMCbrClient *clientPtr)
{
    AppTimer *timer;
    Message *timerMsg;

    timerMsg = MESSAGE_Alloc(node,
                              APP_LAYER,
                              APP_MCBR_CLIENT,
                              MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = (short)clientPtr->sourcePort;

    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[24];
        printf("MCBR Client: Node %u scheduling next data packet\n",
               node->nodeId);
        printf("    timer type is %d\n", timer->type);
        ctoa(clientPtr->interval, clockStr);
        printf("    interval is %s\n", clockStr);
    }
#endif /* DEBUG */

#ifdef ADDON_NGCNMS

    clientPtr->lastTimer = timerMsg;

#endif

    MESSAGE_Send(node, timerMsg, clientPtr->interval);
}


/*
 * NAME:        AppLayerMCbrServer.
 * PURPOSE:     Models the behaviour of MCbrServer Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerMCbrServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataMCbrServer *serverPtr;

    ctoa(node->getNodeTime()+getSimStartTime(node), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv *info;
            MCbrData data;
            clocktype tempJitter=0;
            clocktype delay=0;
#ifdef ADDON_DB
            AppMsgStatus msgStatus = APP_MSG_OLD;
#endif // ADDON_DB

            info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
            memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

#ifdef DEBUG
            {
                char clockStr[24];
                ctoa(data.txTime+getSimStartTime(node), clockStr);
                printf("MCBR Server %u: packet transmitted at %s\n",
                       node->nodeId, clockStr);

                ctoa(node->getNodeTime()+getSimStartTime(node), clockStr);
                printf("    received at %s\n", clockStr);
                IO_ConvertIpAddressToString(&info->sourceAddr, addrStr);
                printf("    client is %s\n", addrStr);
                printf("    connection Id is %d\n", data.sourcePort);
                printf("    seqNo is %d\n", data.seqNo);
            }
#endif /* DEBUG */

            serverPtr = AppMCbrServerGetMCbrServer(node,
                                                   info->sourceAddr,
                                                   data.sourcePort);

            /* New connection, so create new mcbr server to handle client. */
            if (serverPtr == NULL)
            {
                serverPtr = AppMCbrServerNewMCbrServer(node,
                                                       info->destAddr,
                                                       info->sourceAddr,
                                                       data.sourcePort);
                if (node->appData.appStats)
                {
                     // Create statistics
                    serverPtr->stats = new STAT_AppStatistics(
                        node,
                        "mcbrServer",
                        STAT_Multicast,
                        STAT_AppReceiver,
                        "MCBR Server");
                    serverPtr->stats->Initialize(
                        node,
                        info->sourceAddr,
                        info->destAddr,
                        STAT_AppStatistics::GetSessionId(msg),
                        serverPtr->uniqueId);
                    serverPtr->stats->SessionStart(node, STAT_Multicast);
                }
            }

            if (serverPtr == NULL)
            {
                printf("MCBR Server: Node %u unable to "
                       "allocation server\n", node->nodeId);

                assert(FALSE);
            }

            if (data.seqNo >= serverPtr->seqNo || data.isMdpEnabled)
            {
                if (node->appData.appStats)
                {
                    serverPtr->stats->AddFragmentReceivedDataPoints(
                        node,
                        msg,
                        MESSAGE_ReturnPacketSize(msg),
                        STAT_Multicast);
                    serverPtr->stats->AddMessageReceivedDataPoints(
                        node,
                        msg,
                        0,
                        MESSAGE_ReturnPacketSize(msg),
                        0,
                        STAT_Multicast);
#ifdef DEBUG
                    {
                        char clockStr[24];
                        ctoa(serverPtr->stats->GetTotalDelay(STAT_Multicast).GetValue(node->getNodeTime()), clockStr);
                        printf("    total end-to-end delay so far is %s\n",
                               clockStr);
                    }
#endif /* DEBUG */
                }

                serverPtr->seqNo = data.seqNo + 1;

#ifdef ADDON_DB
                msgStatus = APP_MSG_NEW;
#endif // ADDON_DB

                if (data.type == 'd')
                {
                    /* Do nothing. */
                }
                else if (data.type == 'c')
                {
                    serverPtr->sessionFinish = node->getNodeTime();
                    serverPtr->sessionIsClosed = TRUE;
                    if (node->appData.appStats)
                    {
                        serverPtr->stats->SessionFinish(node, STAT_Multicast);
                    }
                }
                else
                {
#ifndef EXATA
                    assert(FALSE);
#endif
                }
            }
#ifdef ADDON_DB
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL && node->appData.appStats)
            {
                StatsDBAppEventParam* appParamInfo = NULL;
                appParamInfo = (StatsDBAppEventParam*) MESSAGE_ReturnInfo(msg, INFO_TYPE_AppStatsDbContent);
                if (appParamInfo != NULL)
                {
                        serverPtr->sessionId = appParamInfo->m_SessionId;
                        serverPtr->sessionInitiator = appParamInfo->m_SessionInitiator;
                }

                delay = node->getNodeTime() - data.txTime;
                SequenceNumber::Status seqStatus =
                    APP_ReportStatsDbReceiveEvent(
                        node,
                        msg,
                        &(serverPtr->seqNumCache),
                        data.seqNo,
                        delay,
                        (clocktype)serverPtr->stats->
                            GetJitter(STAT_Multicast).
                            GetValue(node->getNodeTime()),
                        MESSAGE_ReturnPacketSize(msg),
                        (Int32)serverPtr->stats->
                            GetMessagesReceived(STAT_Multicast).
                            GetValue(node->getNodeTime()),
                        msgStatus);

                if (seqStatus == SequenceNumber::SEQ_NEW)
                {
                    StatsDBNetworkEventParam* ipParamInfo;
                    ipParamInfo = (StatsDBNetworkEventParam*)
                            MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

                    if (ipParamInfo == NULL)
                    {
                            printf ("ERROR: We should have Network Events Info");
                    }
                    else
                    {
                            serverPtr->hopCount += (int) ipParamInfo->m_HopCount;
                    }
                }
            }
#endif
            break;
        }

        default:
            ctoa(node->getNodeTime()+getSimStartTime(node), buf);
            printf("MCBR Server: At time %s, node %u received "
                   "message of unknown type "
                   "%u.\n", buf, node->nodeId, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppMCbrServerInit.
 * PURPOSE:     listen on MCbrServer server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppMCbrServerInit(Node *node)
{
}

/*
 * NAME:        AppMCbrServerPrintStats.
 * PURPOSE:     Prints statistics of a MCbrServer session.
 * PARAMETERS:  node - pointer to this node.
 *              serverPtr - pointer to the mcbr server data structure.
 * RETURN:      none.
 */
void
AppMCbrServerPrintStats(Node *node, AppDataMCbrServer *serverPtr) {

    char addrStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (serverPtr->sessionIsClosed == FALSE) {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
        if (serverPtr->stats)
        {
            if (!serverPtr->stats->IsSessionFinished(STAT_Multicast))
            {
                serverPtr->stats->SessionFinish(node,STAT_Multicast);
            }
        }
    }
    else {
        sprintf(sessionStatusStr, "Closed");
    }

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);

    sprintf(buf, "Client Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "MCBR Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "MCBR Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

}

/*
 * NAME:        AppMCbrServerFinalize.
 * PURPOSE:     Collect statistics of a MCbrServer session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppMCbrServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataMCbrServer *serverPtr = (AppDataMCbrServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppMCbrServerPrintStats(node, serverPtr);
        // Print stats in .stat file using Stat APIs
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(
                node,
                "Application",
                "MCBR Server",
                ANY_ADDRESS,
                serverPtr->sourcePort);
        }
    }

#ifdef ADDON_DB
    if (serverPtr->seqNumCache != NULL)
    {
        delete serverPtr->seqNumCache;
        serverPtr->seqNumCache = NULL;
    }
#endif // ADDON_DB
}

/*
 * NAME:        AppMCbrServerGetMCbrServer.
 * PURPOSE:     search for a mcbr server data structure.
 * PARAMETERS:  node - mcbr server.
 *              remoteAddr - mcbr client sending the data.
 *              sourcePort - sourcePort of mcbr client/server pair.
 * RETURN:      the pointer to the mcbr server data structure,
 *              NULL if nothing found.
 */
AppDataMCbrServer * //inline//
AppMCbrServerGetMCbrServer(Node *node, Address remoteAddr, int sourcePort)
{
    AppInfo *appList = node->appData.appMap->getAppInfo(remoteAddr, sourcePort);
    AppDataMCbrServer *mcbrServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_MCBR_SERVER)
        {
            mcbrServer = (AppDataMCbrServer *) appList->appDetail;

            if (mcbrServer->sourcePort == sourcePort
                && Address_IsSameAddress(&mcbrServer->remoteAddr, &remoteAddr))
            {
                return mcbrServer;
            }
       }
   }

    return NULL;
}

/*
 * NAME:        AppMCbrServerNewMCbrServer.
 * PURPOSE:     create a new mcbr server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              localAddr - local address.
 *              remoteAddr - remote address.
 *              sourcePort - sourcePort of mcbr client/server pair.
 * RETRUN:      the pointer to the created mcbr server data structure,
 *              NULL if no data structure allocated.
 */
AppDataMCbrServer * //inline//
AppMCbrServerNewMCbrServer(Node *node,
                           Address localAddr,
                           Address remoteAddr,
                           int sourcePort)
{
    AppDataMCbrServer *mcbrServer;

    mcbrServer = (AppDataMCbrServer *)
                MEM_malloc(sizeof(AppDataMCbrServer));

    /*
     * Fill in mcbr info.
     */
    memcpy(&(mcbrServer->localAddr), &localAddr, sizeof(Address));
    memcpy(&(mcbrServer->remoteAddr), &remoteAddr, sizeof(Address));
    mcbrServer->sourcePort = sourcePort;
    mcbrServer->sessionStart = node->getNodeTime();
    mcbrServer->sessionFinish = node->getNodeTime();
    mcbrServer->sessionLastReceived = node->getNodeTime();
    mcbrServer->sessionIsClosed = FALSE;
    mcbrServer->seqNo = 0;
    mcbrServer->uniqueId = node->appData.uniqueId++;
    mcbrServer->stats = NULL;

#ifdef ADDON_DB
    mcbrServer->hopCount=0;
    mcbrServer->seqNumCache = NULL;
#endif

    APP_RegisterNewApp(node, APP_MCBR_SERVER, mcbrServer);
    node->appData.appMap->pushDetail(remoteAddr, sourcePort, APP_MCBR_SERVER, mcbrServer);

    return mcbrServer;
}

#ifdef ADDON_NGCNMS

void AppMCbrReset(Node* node)
{

    if (node->disabled)
    {
        AppInfo *appList = node->appData.appPtr;
        AppDataMCbrClient *mcbrClient;

        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_MCBR_CLIENT)
            {
                mcbrClient = (AppDataMCbrClient *) appList->appDetail;
                MESSAGE_CancelSelfMsg(node, mcbrClient->lastTimer);
            }
        }
    }
}

#endif

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             :AppMcbrClientAddAddressInformation.
// PURPOSE              :store client interface index,to get the 
//                       correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataMCbrClient* : pointer to CBR client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppMcbrClientAddAddressInformation(Node* node,
                                  AppDataMCbrClient* clientPtr)
{
    clientPtr->clientInterfaceIndex = 
        (Int16)MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                            node,
                                            clientPtr->localAddr);
}

//---------------------------------------------------------------------------
// FUNCTION             :AppMcbrClientGetSessionAddressState.
// PURPOSE              :get the current address sate of client
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataMCbrClient* : pointer to CBR client data
// RETRUN:     
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if client is having valid address
//                        ADDRESS_INVALID : if client is in 
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppMcbrClientGetSessionAddressState(Node* node,
                                   AppDataMCbrClient* clientPtr)
{
    // variable to determine the client current address state
    Int32 clientAddressState = 0; 

    // Get the current client  address if the
    // session is starting
    // Address state is checked only at the session start; if this is not
    // starting of session then return FOUND_ADDRESS
    if (clientPtr->seqNo == 1)
    {
        clientAddressState =
            MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    node->nodeId,
                                    clientPtr->clientInterfaceIndex,
                                    clientPtr->localAddr.networkType,
                                    &(clientPtr->localAddr));
    }
    // if either client is not in valid address state
    // then mapping will return INVALID_MAPPING
    if (clientAddressState == INVALID_MAPPING)
    {
        return ADDRESS_INVALID;
    }
    return ADDRESS_FOUND;
}

