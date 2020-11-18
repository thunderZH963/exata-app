//
// Created by 张画 on 2020/11/14.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h" // EXATA_HOME/include/api.h
#include "app_util.h" // EXATA_HOME/include/app_util.h
#include "partition.h" // EXATA_HOME/include/partition.h
#include "app_newcbr.h"

/*
 * NAME:        AppLayerNewcbrClient.
 * PURPOSE:     Models the behaviour of NewcbrClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerNewcbrClient(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    char error[MAX_STRING_LENGTH];
    AppDataNewcbrClient *clientPtr;

#ifdef DEBUG
    TIME_PrintClockInSecond(node->getNodeTime(), buf);
    printf("NewCBR Client: Node %ld got a message at %sS\n",
           node->nodeId, buf);
#endif /* DEBUG */

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            AppTimer *timer;

            timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("NewcBR Client: Node %ld at %s got timer %d\n",
                   node->nodeId, buf, timer->type);
#endif /* DEBUG */

            clientPtr = AppNewCbrClientGetNewcbrClient(node, timer->sourcePort);

            if (clientPtr == NULL)
            {
                sprintf(error, "NewCBR Client: Node %d cannot find cbr"
                               " client\n", node->nodeId);

                ERROR_ReportError(error);
            }

            switch (timer->type)
            {
                // only support this
                case APP_TIMER_SEND_PKT:
                {
                    NewcbrData data;
                    char newcbrData[NEWCBR_HEADER_SIZE];

                    memset(&data, 0, sizeof(data));

                    ERROR_Assert(sizeof(data) <= NEWCBR_HEADER_SIZE,
                                 "NewCbrData size cant be greater than NEWCBR_HEADER_SIZE");

#ifdef DEBUG
                    printf("NEWCBR Client: Node %u has %u items left to"
                        " send\n", node->nodeId, clientPtr->itemsToSend);
#endif /* DEBUG */

                    // judge if close session
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
                        if (node->appData.appStats && clientPtr->stats)
                        {
                            clientPtr->stats->SessionFinish(node);
                        }
                    }

                    data.sourcePort = clientPtr->sourcePort;
                    data.txTime = node->getNodeTime();
                    data.seqNo = clientPtr->seqNo++;
                    data.isMdpEnabled = clientPtr->isMdpEnabled;
#if defined(ADVANCED_WIRELESS_LIB) || defined(UMTS_LIB) || defined(MUOS_LIB)
                    data.pktSize = clientPtr->itemSize;
                    data.interval = clientPtr->interval;
#endif // ADVANCED_WIRELESS_LIB || UMTS_LIB || MUOS_LIB


                    // Note: An overloaded Function
                    memset(newcbrData, 0, NEWCBR_HEADER_SIZE);
                    memcpy(newcbrData, (char *) &data, sizeof(data));

                    // Dynamic address
                    // Create and send a UDP msg with header and virtual
                    // payload.
                    // if the client has not yet acquired a valid
                    // address then the application packets should not be
                    // generated
                    // check whether client and server are in valid address
                    // state
                    // if this is session start then packets will not be sent
                    // if in invalid address state and session will be closed
                    // ; if the session has already started and address
                    // becomes invalid during application session then
                    // packets will get generated but will be dropped at
                    //  network layer
                    if (AppNewnewcbrClientGetSessionAddressState(node, clientPtr)
                        == ADDRESS_FOUND)
                    {
                        Message* sentMsg = APP_UdpCreateMessage(
                                node,
                                clientPtr->localAddr,
                                (short) clientPtr->sourcePort,
                                clientPtr->remoteAddr,
                                (short) APP_NEWCBR_SERVER,
                                TRACE_NEWCBR,
                                clientPtr->tos);

                        APP_AddHeader(
                                node,
                                sentMsg,
                                newcbrData,
                                NEWCBR_HEADER_SIZE);

                        int payloadSize =
                                clientPtr->itemSize - NEWCBR_HEADER_SIZE;

                        //modified in future
                        APP_AddVirtualPayload(
                                node,
                                sentMsg,
                                payloadSize);

                        // Add the virtual payload size as info
                        APP_AddInfo(
                                node,
                                sentMsg,
                                (char*) &payloadSize,
                                sizeof(int),
                                INFO_TYPE_DataSize);

                        // dns
                        AppUdpPacketSendingInfo packetSendingInfo;

                        packetSendingInfo.itemSize = clientPtr->itemSize;
                        packetSendingInfo.stats = clientPtr->stats;
                        packetSendingInfo.fragNo = NO_UDP_FRAG;
                        packetSendingInfo.fragSize = 0;

                        node->appData.appTrafficSender->appUdpSend(
                                node,
                                sentMsg,
                                *clientPtr->serverUrl,
                                clientPtr->localAddr,
                                APP_NEWCBR_CLIENT,
                                (short)clientPtr->sourcePort,
                                packetSendingInfo);
                        clientPtr->sessionLastSent = node->getNodeTime();

                        if (clientPtr->itemsToSend > 0)
                        {
                            clientPtr->itemsToSend--;
                        }

                        if (clientPtr->sessionIsClosed == FALSE)
                        {
                            AppNewnewcbrClientScheduleNextPkt(node, clientPtr);
                        }
                    }
                    else
                    {
                        clientPtr->sessionStart = 0;
                        clientPtr->sessionIsClosed = TRUE;
                    }

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
            TIME_PrintClockInSecond(node->getNodeTime(), buf, node);
            sprintf(error, "NEWCBR Client: at time %sS, node %d "
                           "received message of unknown type"
                           " %d\n", buf, node->nodeId, msg->eventType);
#ifndef EXATA
            ERROR_ReportError(error);
#endif
    }

    MESSAGE_Free(node, msg);
}

#ifdef ADDON_NGCNMS
// reset source address of application so that we
// can route packets correctly.
void
AppnewcbrClientReInit(Node* node, Address sourceAddr)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataNewcbrClient *newcbrClient;
    int i;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_NEWCBR_CLIENT)
        {
            newcbrClient = (AppDataNewcbrClient *) appList->appDetail;

            for (i=0; i< node->numberInterfaces; i++)
            {
                // currently only support ipv4. May be better way to compare this.
                if (newcbrClient->localAddr.interfaceAddr.ipv4 == node->iface[i].oldIpAddress)
                {
                    memcpy(&(newcbrClient->localAddr), &sourceAddr, sizeof(Address));
                }
            }
        }
    }

}
#endif

/*
 * NAME:        AppCbrClientInit.
 * PURPOSE:     Initialize a CbrClient session.
 * PARAMETERS:  node - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts,
 *              endTime - time until the session ends,
 *              tos - the contents for the type of service field.
 *              srcString - source name
 *              destString - destination name
 *              isRsvpTeEnabled - whether RSVP-TE is enabled
 *              appName - application alias name
 *              isMdpEnabled - true if MDP is enabled by user.
 *              isProfileNameSet - true if profile name is provided by user.
 *              profileName - mdp profile name.
 *              uniqueId - mdp session unique id.
 *              nodeInput - nodeInput for config file.
 * RETURN:      none.
 */
void
AppNewcbrClientInit(
        Node *node,
        Address clientAddr,
        Address serverAddr,
        Int32 itemsToSend,
        Int32 itemSize,
        clocktype interval,
        clocktype startTime,
        clocktype endTime,
        unsigned tos,
        const char* srcString,
        const char* destString,
        BOOL isRsvpTeEnabled,
        char* appName,
        BOOL isMdpEnabled,
        BOOL isProfileNameSet,
        char* profileName,
        Int32 uniqueId,
        const NodeInput* nodeInput)
{
    char error[MAX_STRING_LENGTH];
    AppTimer *timer;
    AppDataNewcbrClient  *clientPtr;
    Message *timerMsg;
    int minSize;
    startTime -= getSimStartTime(node);
    endTime -= getSimStartTime(node);

    ERROR_Assert(sizeof(newcbrData) <= NEWCBR_HEADER_SIZE,
                 "NewCbrData size cant be greater than CBR_HEADER_SIZE");
    minSize = NEWCBR_HEADER_SIZE;

    /* Check to make sure the number of cbr items is a correct value. */
    if (itemsToSend < 0)
    {
        sprintf(error, "NewCBR Client: Node %d item to sends needs"
                       " to be >= 0\n", node->nodeId);

        ERROR_ReportError(error);
    }

    /* Make sure that packet is big enough to carry cbr data information. */
    if (itemSize < minSize)
    {
        sprintf(error, "NewCBR Client: Node %d item size needs to be >= %d.\n",
                node->nodeId, minSize);
        ERROR_ReportError(error);
    }


    /* Make sure that packet is within max limit. */
    if (itemSize > APP_MAX_DATA_SIZE)
    {
        sprintf(error, "NewCBR Client: Node %d item size needs to be <= %d.\n",
                node->nodeId, APP_MAX_DATA_SIZE);
        ERROR_ReportError(error);
    }

    /* Make sure interval is valid. */
    if (interval <= 0)
    {
        sprintf(error, "NewCBR Client: Node %d interval needs to be > 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Make sure start time is valid. */
    if (startTime < 0)
    {
        sprintf(error, "NewCBR Client: Node %d start time needs to be >= 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        sprintf(error, "NewCBR Client: Node %d end time needs to be > "
                       "start time or equal to 0.\n", node->nodeId);

        ERROR_ReportError(error);
    }

    // Validate the given tos for this application.
    if (/*tos < 0 || */tos > 255)
    {
        sprintf(error, "NewCBR Client: Node %d should have tos value "
                       "within the range 0 to 255.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    clientPtr = AppNewcbrClientNewNewcbrClient(node,
                                         clientAddr,
                                         serverAddr,
                                         itemsToSend,
                                         itemSize,
                                         interval,
                                         origStart,
                                         endTime,
                                         (TosType) tos,
                                         appName);

    if (clientPtr == NULL)
    {
        sprintf(error,
                "NewCBR Client: Node %d cannot allocate memory for "
                "new client\n", node->nodeId);

        ERROR_ReportError(error);
    }
    // dns
    // Skipped if the server network type is not valid
    // it should happen only when the server address is given by a URL
    // statistics will be initialized when url is resolved by dns
    if (serverAddr.networkType != NETWORK_INVALID && node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "NEWCBR Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                node,
                "newcbr",
                STAT_Unicast,
                STAT_AppSender,
                customName.c_str());
        clientPtr->stats->Initialize(node,
                                     clientAddr,
                                     serverAddr,
                                     (STAT_SessionIdType)clientPtr->uniqueId,
                                     clientPtr->uniqueId);

        clientPtr->stats->setTos(tos);
        // Create application hop by hop flow filter button
        if (GUI_IsAppHopByHopFlowEnabled())
        {
            GUI_CreateAppHopByHopFlowFilter(clientPtr->stats->GetSessionId(),
                                            node->nodeId, srcString, destString, "NEWCBR");
        }
    }

    if (node->transportData.rsvpProtocol && isRsvpTeEnabled)
    {
        // Note: RSVP is enabled for Ipv4 networks only.
        Message *rsvpRegisterMsg;
        AppToRsvpSend *info;

        rsvpRegisterMsg = MESSAGE_Alloc(node,
                                        TRANSPORT_LAYER,
                                        TransportProtocol_RSVP,
                                        MSG_TRANSPORT_RSVP_InitApp);

        MESSAGE_InfoAlloc(node,
                          rsvpRegisterMsg,
                          sizeof(AppToRsvpSend));

        info = (AppToRsvpSend *) MESSAGE_ReturnInfo(rsvpRegisterMsg);

        info->sourceAddr = GetIPv4Address(clientAddr);
        info->destAddr = GetIPv4Address(serverAddr);

        info->upcallFunctionPtr = NULL;

        MESSAGE_Send(node, rsvpRegisterMsg, startTime);
    }


    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_NEWCBR_CLIENT,
                             MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(startTime, clockStr, node);
        printf("NEWCBR Client: Node %ld starting client at %sS\n",
               node->nodeId, clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, startTime);


    // Dynamic Address
    // update the client with url info if destination configured as URL
    if (serverAddr.networkType == NETWORK_INVALID && destString)
    {
        // set the dns info in client pointer if server url
        // is present
        // set the server url if it is not localhost
        if (node->appData.appTrafficSender->ifUrlLocalHost(destString)
            == FALSE)
        {
            node->appData.appTrafficSender->appClientSetDnsInfo(
                    node,
                    destString,
                    clientPtr->serverUrl);
        }
    }
    // Update the CBR clientPtr with address information
    AppNewcbrClientAddAddressInformation(node, clientPtr);
}

/*
 * NAME:        AppCbrClientPrintStats.
 * PURPOSE:     Prints statistics of a CbrClient session.
 * PARAMETERS:  node - pointer to the this node.
 *              clientPtr - pointer to the cbr client data structure.
 * RETURN:      none.
 */
void AppNewcbrClientPrintStats(Node *node, AppDataNewcbrClient *clientPtr) {

    char addrStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];

    char buf[MAX_STRING_LENGTH];

    if (clientPtr->sessionIsClosed == FALSE &&
        clientPtr->remoteAddr.networkType != NETWORK_INVALID) {
        clientPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
        if (!clientPtr->stats->IsSessionFinished(STAT_Unicast))
        {
            clientPtr->stats->SessionFinish(node);
        }
    }
    else {
        sprintf(sessionStatusStr, "Closed");
    }


    if (clientPtr->remoteAddr.networkType == NETWORK_ATM)
    {
        const LogicalSubnet* dstLogicalSubnet =
                AtmGetLogicalSubnetFromNodeId(
                        node,
                        clientPtr->remoteAddr.interfaceAddr.atm.ESI_pt1,
                        0);
        IO_ConvertIpAddressToString(
                dstLogicalSubnet->ipAddress,
                addrStr);
    }
    else
    {
        // dns
        if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
        {
            IO_ConvertIpAddressToString(&clientPtr->remoteAddr, addrStr);
        }
        else
        {
            strcpy(addrStr, (char*)clientPtr->serverUrl->c_str());
        }

    }

    sprintf(buf, "Server Address = %s", addrStr);
    IO_PrintStat(
            node,
            "Application",
            "NEWCBR Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);


    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
            node,
            "Application",
            "NEWCBR Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

}

/*
 * NAME:        AppCbrClientFinalize.
 * PURPOSE:     Collect statistics of a CbrClient session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppNewcbrClientFinalize(Node *node, AppInfo* appInfo)
{
    AppDataNewcbrClient *clientPtr = (AppDataNewcbrClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppNewcbrClientPrintStats(node, clientPtr);

        // Print stats in .stat file using Stat APIs
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                    node,
                    "Application",
                    "NEWCBR Client",
                    ANY_ADDRESS,
                    clientPtr->sourcePort);
        }
    }
    if (clientPtr->serverUrl)
    {
        delete (clientPtr->serverUrl);
        clientPtr->serverUrl = NULL;
    }
}

/*
 * NAME:        AppCbrClientGetCbrClient.
 * PURPOSE:     search for a cbr client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              sourcePort - source port of the cbr client.
 * RETURN:      the pointer to the cbr client data structure,
 *              NULL if nothing found.
 */
AppDataNewcbrClient *
AppNewcbrClientGetNewcbrClient(Node *node, short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataNewcbrClient *newcbrClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_NEWCBR_CLIENT)
        {
            newcbrClient = (AppDataNewcbrClient *) appList->appDetail;

            if (newcbrClient->sourcePort == sourcePort)
            {
                return newcbrClient;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppCbrClientNewCbrClient.
 * PURPOSE:     create a new cbr client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              remoteAddr - remote address.
 *              itemsToSend - number of cbr items to send in simulation.
 *              itemSize - size of each packet.
 *              interval - time between two packets.
 *              startTime - when the node will start sending.
 * RETURN:      the pointer to the created cbr client data structure,
 *              NULL if no data structure allocated.
 */
AppDataNewcbrClient *
AppNewcbrClientNewNewcbrClient(Node *node,
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
    AppDataNewcbrClient *newcbrClient;

    newcbrClient = (AppDataNewcbrClient *)
            MEM_malloc(sizeof(AppDataNewcbrClient));
    memset(newcbrClient, 0, sizeof(AppDataNewcbrClient));

    /*cbr
     * fill in  info.
     */
    memcpy(&(newcbrClient->localAddr), &localAddr, sizeof(Address));
    memcpy(&(newcbrClient->remoteAddr), &remoteAddr, sizeof(Address));
    newcbrClient->interval = interval;

    if (!NODE_IsDisabled(node))
    {
        newcbrClient->sessionStart = node->getNodeTime() + startTime;
    }
    else
    {
        // start time was already figured out in caller function.
        newcbrClient->sessionStart = startTime;
    }

    newcbrClient->sessionIsClosed = FALSE;
    newcbrClient->sessionLastSent = node->getNodeTime();
    newcbrClient->sessionFinish = node->getNodeTime();
    newcbrClient->endTime = endTime;
    newcbrClient->itemsToSend = itemsToSend;
    newcbrClient->itemSize = itemSize;
    newcbrClient->sourcePort = node->appData.nextPortNum++;
    newcbrClient->seqNo = 0;
    newcbrClient->tos = tos;
    newcbrClient->uniqueId = node->appData.uniqueId++;
    //client pointer initialization with respect to mdp

    newcbrClient->stats = NULL;
    // dns
    newcbrClient->serverUrl = new std::string();
    newcbrClient->serverUrl->clear();
    newcbrClient->destNodeId = ANY_NODEID;
    newcbrClient->clientInterfaceIndex = ANY_INTERFACE;
    newcbrClient->destInterfaceIndex = ANY_INTERFACE;
    if (appName)
    {
        newcbrClient->applicationName = new std::string(appName);
    }
    else
    {
        newcbrClient->applicationName = new std::string();
    }


    // Add CBR variables to hierarchy
    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateApplicationPath(
            node,                   // node
            "newcbrClient",            // protocol name
            newcbrClient->sourcePort,  // port
            "interval",             // object name
            path))                  // path (output)
    {
        h->AddObject(
                path,
                new D_ClocktypeObj(&newcbrClient->interval));
    }


#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];
        char localAddrStr[MAX_STRING_LENGTH];
        char remoteAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(&newcbrClient->localAddr, localAddrStr);
        IO_ConvertIpAddressToString(&newcbrClient->remoteAddr, remoteAddrStr);

        printf("newCBR Client: Node %u created new newcbr client structure\n",
               node->nodeId);
        printf("    localAddr = %s\n", localAddrStr);
        printf("    remoteAddr = %s\n", remoteAddrStr);
        TIME_PrintClockInSecond(newcbrClient->interval, clockStr);
        printf("    interval = %s\n", clockStr);
        TIME_PrintClockInSecond(newcbrClient->sessionStart, clockStr, node);
        printf("    sessionStart = %sS\n", clockStr);
        printf("    itemsToSend = %u\n", newcbrClient->itemsToSend);
        printf("    itemSize = %u\n", newcbrClient->itemSize);
        printf("    sourcePort = %ld\n", newcbrClient->sourcePort);
        printf("    seqNo = %ld\n", newcbrClient->seqNo);
    }
#endif /* DEBUG */

    APP_RegisterNewApp(node, APP_NEWCBR_CLIENT, newcbrClient);

    return newcbrClient;
}

/*
 * NAME:        AppCbrClientScheduleNextPkt.
 * PURPOSE:     schedule the next packet the client will send.  If next packet
 *              won't arrive until the finish deadline, schedule a close.
 * PARAMETERS:  node - pointer to the node,
 *              clientPtr - pointer to the cbr client data structure.
 * RETRUN:      none.
 */
void //inline//
AppNewcbrClientScheduleNextPkt(Node *node, AppDataNewcbrClient *clientPtr)
{
    AppTimer *timer;
    Message *timerMsg;

    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_NEWCBR_CLIENT,
                             MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[24];
        printf("NEWCBR Client: Node %u scheduling next data packet\n",
               node->nodeId);
        printf("    timer type is %d\n", timer->type);
        TIME_PrintClockInSecond(clientPtr->interval, clockStr);
        printf("    interval is %sS\n", clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, clientPtr->interval);
}

/*
 * NAME:        AppLayerCbrServer.
 * PURPOSE:     Models the behaviour of CbrServer Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerNewcbrServer(Node *node, Message *msg)
{
    char error[MAX_STRING_LENGTH];
    AppDataNewcbrServer *serverPtr;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv *info;
            NewcbrData data;


            ERROR_Assert(sizeof(data) <= NEWCBR_HEADER_SIZE,
                         "NewcbrData size cant be greater than NEWCBR_HEADER_SIZE");

            info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
            memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

            // trace recd pkt
            ActionData acnData;
            acnData.actionType = RECV;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_APPLICATION_LAYER,
                             PACKET_IN,
                             &acnData);

#ifdef DEBUG
            {
                char clockStr[MAX_STRING_LENGTH];
                char addrStr[MAX_STRING_LENGTH];
                TIME_PrintClockInSecond(data.txTime, clockStr, node);
                IO_ConvertIpAddressToString(&info->sourceAddr, addrStr);

                printf("NEWCBR Server %ld: packet transmitted at %sS\n",
                       node->nodeId, clockStr);
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
                printf("    received at %sS\n", clockStr);
                printf("    client is %s\n", addrStr);
                printf("    connection Id is %d\n", data.sourcePort);
                printf("    seqNo is %d\n", data.seqNo);
            }
#endif /* DEBUG */

            serverPtr = AppNewcbrServerGetNewcbrServer(node,
                                                 info->sourceAddr,
                                                 data.sourcePort);

            /* New connection, so create new newcbr server to handle client. */
            if (serverPtr == NULL)
            {
                serverPtr = AppNewcbrServerNewNewcbrServer(node,
                                                     info->destAddr,
                                                     info->sourceAddr,
                                                     data.sourcePort);

                // Create statistics
                if (node->appData.appStats)
                {
                    serverPtr->stats = new STAT_AppStatistics(
                            node,
                            "newcbrServer",
                            STAT_Unicast,
                            STAT_AppReceiver,
                            "NEWCBR Server");
                    serverPtr->stats->Initialize(
                            node,
                            info->sourceAddr,
                            info->destAddr,
                            STAT_AppStatistics::GetSessionId(msg),
                            serverPtr->uniqueId);
                    serverPtr->stats->SessionStart(node);
                }

            }

            if (serverPtr == NULL)
            {
                sprintf(error, "NEWCBR Server: Node %d unable to "
                               "allocation server\n", node->nodeId);

                ERROR_ReportError(error);
            }


            if (data.seqNo >= serverPtr->seqNo || data.isMdpEnabled)

            {

                if (node->appData.appStats)
                {
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
#ifdef DEBUG
                    {
                    char clockStr[24];
                    TIME_PrintClockInSecond(
                        serverPtr->stats->GetTotalDelay().GetValue(node->getNodeTime()), clockStr);
                    printf("    total end-to-end delay so far is %sS\n",
                           clockStr);
                }
#endif /* DEBUG */

                }
                serverPtr->seqNo = data.seqNo + 1;


                if (data.type == 'd')
                {
                    /* Do nothing. */
                }
                else if (data.type == 'c')
                {
                    serverPtr->sessionFinish = node->getNodeTime();
                    if (node->appData.appStats)
                    {
                        serverPtr->stats->SessionFinish(node);
                    }
                    serverPtr->sessionIsClosed = TRUE;
                }
                else
                {
                    assert(FALSE);
                }
            }

            break;
        }

        default:
        {
            char buf[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), buf, node);
            sprintf(error, "NEWCBR Server: At time %sS, node %d received "
                           "message of unknown type "
                           "%d\n", buf, node->nodeId, msg->eventType);
            ERROR_ReportError(error);
        }
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppCbrServerInit.
 * PURPOSE:     listen on CbrServer server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppNewcbrServerInit(Node *node)
{
    APP_InserInPortTable(node, APP_NEWCBR_SERVER, APP_NEWCBR_SERVER);
}

/*
 * NAME:        AppCbrServerPrintStats.
 * PURPOSE:     Prints statistics of a CbrServer session.
 * PARAMETERS:  node - pointer to this node.
 *              serverPtr - pointer to the cbr server data structure.
 * RETURN:      none.
 */
void
AppNewcbrServerPrintStats(Node *node, AppDataNewcbrServer *serverPtr) {

    char addrStr[MAX_STRING_LENGTH];
    char sessionStatusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (serverPtr->sessionIsClosed == FALSE) {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(sessionStatusStr, "Not closed");
        if (!serverPtr->stats->IsSessionFinished(STAT_Unicast))
        {
            serverPtr->stats->SessionFinish(node);
        }
    }
    else {
        sprintf(sessionStatusStr, "Closed");
    }

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);

    sprintf(buf, "Client address = %s", addrStr);
    IO_PrintStat(
            node,
            "Application",
            "NEWCBR Server",
            ANY_DEST,
            serverPtr->sourcePort,
            buf);


    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
            node,
            "Application",
            "NEWCBR Server",
            ANY_DEST,
            serverPtr->sourcePort,
            buf);


#ifdef LTE_LIB
    #ifdef LTE_LIB_LOG
#ifdef LTE_LIB_VALIDATION_LOG
    lte::LteLog::InfoFormat(node,-1,
            "APP",
            "%s,%s,%llu",
            "AppThroughput",
            addrStr,
            throughput);
#endif
#endif
#endif
}

/*
 * NAME:        AppCbrServerFinalize.
 * PURPOSE:     Collect statistics of a CbrServer session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppNewcbrServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataNewcbrServer *serverPtr = (AppDataNewcbrServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppNewcbrServerPrintStats(node, serverPtr);
        // Print stats in .stat file using Stat APIs
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(node,
                                    "Application",
                                    "NEWCBR Server",
                                    ANY_ADDRESS,
                                    serverPtr->sourcePort);
        }
    }

}

/*
 * NAME:        AppCbrServerGetCbrServer.
 * PURPOSE:     search for a cbr server data structure.
 * PARAMETERS:  node - cbr server.
 *              remoteAddr - cbr client sending the data.
 *              sourcePort - sourcePort of cbr client/server pair.
 * RETURN:      the pointer to the cbr server data structure,
 *              NULL if nothing found.
 */
AppDataCbrServer * //inline//
AppNewcbrServerGetNewcbrServer(
        Node *node, Address remoteAddr, short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataNewcbrServer *newcbrServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_NEWCBR_SERVER)
        {
            newcbrServer = (AppDataNewcbrServer *) appList->appDetail;

            if ((newcbrServer->sourcePort == sourcePort) &&
                IO_CheckIsSameAddress(
                        newcbrServer->remoteAddr, remoteAddr))
            {
                return newcbrServer;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppCbrServerNewCbrServer.
 * PURPOSE:     create a new cbr server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              localAddr - local address.
 *              remoteAddr - remote address.
 *              sourcePort - sourcePort of cbr client/server pair.
 * RETRUN:      the pointer to the created cbr server data structure,
 *              NULL if no data structure allocated.
 */
AppDataNewcbrServer * //inline//
AppNewcbrServerNewNewcbrServer(Node *node,
                         Address localAddr,
                         Address remoteAddr,
                         short sourcePort)
{
    AppDataNewcbrServer *newcbrServer;

    newcbrServer = (AppDataNewcbrServer *)
            MEM_malloc(sizeof(AppDataNewcbrServer));
    memset(newcbrServer, 0, sizeof(AppDataNewcbrServer));
    /*
     * Fill in cbr info.
     */
    memcpy(&(newcbrServer->localAddr), &localAddr, sizeof(Address));
    memcpy(&(newcbrServer->remoteAddr), &remoteAddr, sizeof(Address));
    newcbrServer->sourcePort = sourcePort;
    newcbrServer->sessionStart = node->getNodeTime();
    newcbrServer->sessionFinish = node->getNodeTime();
    newcbrServer->sessionIsClosed = FALSE;
    newcbrServer->seqNo = 0;
    newcbrServer->uniqueId = node->appData.uniqueId++;

    //    cbrServer->lastInterArrivalInterval = 0;
    //    cbrServer->lastPacketReceptionTime = 0;
    newcbrServer->stats = NULL;


    APP_RegisterNewApp(node, APP_NEWCBR_SERVER, newcbrServer);

    return newcbrServer;
}

#ifdef ADDON_NGCNMS

void AppNewcbrReset(Node* node)
{

    if (node->disabled)
    {
        AppInfo *appList = node->appData.appPtr;
        AppDataNewcbrClient *newcbrClient;

        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_NEWCBR_CLIENT)
            {
                newcbrClient = (AppDataNewcbrClient *) appList->appDetail;
                MESSAGE_CancelSelfMsg(node, newcbrClient->lastTimer);
            }
        }
    }
}

#endif
// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             :AppCbrClientAddAddressInformation.
// PURPOSE              :store client interface index, destination
//                       interface index destination node id to get the
//                       correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataCbrClient* : pointer to CBR client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppNewcbrClientAddAddressInformation(Node* node,
                                  AppDataNewcbrClient* clientPtr)
{
    // Store the client and destination interface index such that we can get
    // the correct address when the application starts
    NodeId destNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
            node,
            clientPtr->remoteAddr);
    if (destNodeId > 0)
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
// FUNCTION             :AppCbrClientGetSessionAddressState.
// PURPOSE              :get the current address sate of client and server
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataCbrClient* : pointer to CBR client data
// RETRUN:
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if both client and server
//                                        are having valid address
//                        ADDRESS_INVALID : if either of them are in
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppNewcbrClientGetSessionAddressState(Node* node,
                                   AppDataNewcbrClient* clientPtr)
{
    // variable to determine the server current address state
    Int32 serverAddresState = 0;
    // variable to determine the client current address state
    Int32 clientAddressState = 0;

    // Get the current client and destination address if the
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

        if (NetworkIpCheckIfAddressLoopBack(node, clientPtr->remoteAddr))
        {
            serverAddresState = clientAddressState;
        }
        else if (clientPtr->destNodeId != ANY_NODEID &&
                 clientPtr->destInterfaceIndex != ANY_INTERFACE)
        {
            serverAddresState =
                    MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                            node,
                            clientPtr->destNodeId,
                            clientPtr->destInterfaceIndex,
                            clientPtr->remoteAddr.networkType,
                            &(clientPtr->remoteAddr));
        }
    }
    // if either client or server are not in valid address state
    // then mapping will return INVALID_MAPPING
    if (clientAddressState == INVALID_MAPPING ||
        serverAddresState == INVALID_MAPPING)
    {
        return ADDRESS_INVALID;
    }
    return ADDRESS_FOUND;
}

// dns
//---------------------------------------------------------------------------
// NAME      : AppCbrUrlSessionStartCallback
// PURPOSE   : Process Received DNS info.
// PARAMETERS::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : unsigned short : source port
// + uniqueId   : Int32          : connection id; not used for CBR
// + interfaceId : Int16         : interface index,
// + serverUrl   : std::string   : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo : information required to
//                                                 send buffered application
//                                                 packets in case of UDP
//                                                 based applications
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as
//                this callback will initiate TCP Open request and not send
//                packet
//---------------------------------------------------------------------------
bool
AppNewcbrUrlSessionStartCallback(
        Node* node,
        Address* serverAddr,
        UInt16 sourcePort,
        Int32 uniqueId,
        Int16 interfaceId,
        std::string serverUrl,
        AppUdpPacketSendingInfo* packetSendingInfo)
{
    NewcbrData data;
    char newcbrData[NEWCBR_HEADER_SIZE];
    AppDataNewcbrClient* clientPtr = AppNewcbrClientGetNewcbrClient(node, sourcePort);

    if (clientPtr == NULL)
    {
        return (FALSE);
    }
    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
    {
#ifdef DEBUG
        printf("URL already resolved so ignore this response\n");
#endif
        return (FALSE);
    }
    if (serverAddr->networkType == NETWORK_IPV4)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV4)
        {
            ERROR_ReportErrorArgs("NEWCBR Client: Node %d cannot find IPv4"
                                  " newcbr client for ipv4 dest\n", node->nodeId);
        }
    }
    else if (serverAddr->networkType == NETWORK_IPV6)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV6)
        {
            ERROR_ReportErrorArgs("NEWCBR Client: Node %d cannot find IPv6"
                                  " newcbr client for ipv6 dest\n", node->nodeId);
        }
    }

    // Update client RemoteAddress field and session Start
    memcpy(&clientPtr->remoteAddr, serverAddr, sizeof(Address));

    // update the client address information
    AppNewcbrClientAddAddressInformation(node,
                                      clientPtr);


    if ((serverAddr->networkType != NETWORK_INVALID)
        && (node->appData.appStats))
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "NEWCBR Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                node,
                "newcbr",
                STAT_Unicast,
                STAT_AppSender,
                customName.c_str());
        clientPtr->stats->Initialize(node,
                                     clientPtr->localAddr,
                                     clientPtr->remoteAddr,
                                     (STAT_SessionIdType)clientPtr->uniqueId,
                                     clientPtr->uniqueId);

        clientPtr->stats->setTos(clientPtr->tos);
    }

    // First check if end time had already reached..
    if ((clientPtr->endTime != 0) &&
        ((clocktype)node->getNodeTime() > clientPtr->endTime))
    {
        if (node->appData.appStats)
        {
            clientPtr->stats->SessionFinish(node);
        }
        return (FALSE);
    }

    clientPtr->sessionStart = node->getNodeTime();
    // send the messages
    // Dynamic address
    // Create and send a UDP msg with header and virtual payload.
    // if the client has not yet acquired a valid address then the
    // application packets should not be generated check whether client
    // and server are in valid address state if this is session start
    // then packets will not be sent if in invalid address state and
    // session will be closed; if the session has already started and
    // address becomes invalid during application session then
    // packets will get generated but will be dropped at network layer
    if (AppNewcbrClientGetSessionAddressState(node, clientPtr)
        == ADDRESS_FOUND)
    {

        memset(
                &packetSendingInfo->appParam,
                NULL,
                sizeof(StatsDBAppEventParam));

        packetSendingInfo->stats = clientPtr->stats;
        return (TRUE);
    }
    else
    {
        clientPtr->sessionStart = 0;
        clientPtr->sessionIsClosed = TRUE;
    }
    return (FALSE);
}

