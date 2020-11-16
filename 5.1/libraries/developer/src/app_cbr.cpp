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
#include "partition.h"
#include "app_util.h"
#include "app_cbr.h"
#include "ipv6.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif // ADDON_DB

#ifdef LTE_LIB
#ifdef LTE_LIB_LOG
#include "log_lte.h"
#endif
#endif


// Pseudo traffic sender layer
#include "app_trafficSender.h"

// /**
// FUNCTION   :: AppLayerCbrInitTrace
// LAYER      :: APPLCATION
// PURPOSE    :: Cbr initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/


void AppLayerCbrInitTrace(Node* node, const NodeInput* nodeInput)
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
        "TRACE-CBR",
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
                "TRACE-CBR should be either \"YES\" or \"NO\".\n");
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
            TRACE_EnableTraceXML(node, TRACE_CBR,
                "CBR",  AppLayerCbrPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_CBR,
                "CBR", writeMap);
    }
    writeMap = FALSE;
}


//**
// FUNCTION   :: AppLayerCbrPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void AppLayerCbrPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];

    CbrData* data = (CbrData*) MESSAGE_ReturnPacket(msg);

    if (data == NULL) {
        return;
       }

    TIME_PrintClockInSecond(data->txTime, clockStr);

    sprintf(buf, "<cbr>%u %c %u %d %s</cbr>",
            data->sourcePort,
            data->type,
            data->seqNo,
                 (msg->packetSize + msg->virtualPayloadSize),
            clockStr);
    TRACE_WriteToBufferXML(node, buf);
}

/*
 * NOTE: CBR does not attempt to reorder packets.  Any out of order
 *       packets will be dropped.
 */

/*
 * NAME:        AppLayerCbrClient.
 * PURPOSE:     Models the behaviour of CbrClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerCbrClient(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    char error[MAX_STRING_LENGTH];
    AppDataCbrClient *clientPtr;

#ifdef DEBUG
    TIME_PrintClockInSecond(node->getNodeTime(), buf);
    printf("CBR Client: Node %ld got a message at %sS\n",
           node->nodeId, buf);
#endif /* DEBUG */

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            AppTimer *timer;

            timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("CBR Client: Node %ld at %s got timer %d\n",
                   node->nodeId, buf, timer->type);
#endif /* DEBUG */

            clientPtr = AppCbrClientGetCbrClient(node, timer->sourcePort);

            if (clientPtr == NULL)
            {
                sprintf(error, "CBR Client: Node %d cannot find cbr"
                    " client\n", node->nodeId);

                ERROR_ReportError(error);
            }

            switch (timer->type)
            {
                case APP_TIMER_SEND_PKT:
                {
                    CbrData data;
                    char cbrData[CBR_HEADER_SIZE];

                    memset(&data, 0, sizeof(data));

                    ERROR_Assert(sizeof(data) <= CBR_HEADER_SIZE,
                         "CbrData size cant be greater than CBR_HEADER_SIZE");

#ifdef DEBUG
                    printf("CBR Client: Node %u has %u items left to"
                        " send\n", node->nodeId, clientPtr->itemsToSend);
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

#ifdef DEBUG
                    {
                        char clockStr[MAX_STRING_LENGTH];
                        char addrStr[MAX_STRING_LENGTH];

                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
                        IO_ConvertIpAddressToString(
                            &clientPtr->remoteAddr, addrStr);

                        printf("CBR Client: node %ld sending data packet"
                               " at time %sS to CBR server %s\n",
                               node->nodeId, clockStr, addrStr);
                        printf("    size of payload is %d\n",
                               clientPtr->itemSize);
                    }
#endif /* DEBUG */
                    // Note: An overloaded Function
                    memset(cbrData, 0, CBR_HEADER_SIZE);
                    memcpy(cbrData, (char *) &data, sizeof(data));
#ifdef ADDON_DB
                    StatsDBAppEventParam appParam;
                    appParam.m_SessionInitiator = node->nodeId;
                    appParam.m_ReceiverId = clientPtr->receiverId;
                    appParam.SetAppType("CBR");
                    appParam.SetFragNum(0);

                    if (!clientPtr->applicationName->empty())
                    {
                        appParam.SetAppName(
                            clientPtr->applicationName->c_str());
                    }
                    // dns
                    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
                    {
                        appParam.SetReceiverAddr(&clientPtr->remoteAddr);
                    }
                    appParam.SetPriority(clientPtr->tos);
                    appParam.SetSessionId(clientPtr->sessionId);
                    appParam.SetMsgSize(clientPtr->itemSize);
                    appParam.m_TotalMsgSize = clientPtr->itemSize;
                    appParam.m_fragEnabled = FALSE;
#endif // ADDON_DB

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
                    if (AppCbrClientGetSessionAddressState(node, clientPtr)
                            == ADDRESS_FOUND)
                    {
                        Message* sentMsg = APP_UdpCreateMessage(
                                                node,
                                                clientPtr->localAddr,
                                                (short) clientPtr->sourcePort,
                                                clientPtr->remoteAddr,
                                                (short) APP_CBR_SERVER,
                                                TRACE_CBR,
                                                clientPtr->tos);

                        APP_AddHeader(
                                node,
                                sentMsg,
                                cbrData,
                                CBR_HEADER_SIZE);

                        int payloadSize =
                                clientPtr->itemSize - CBR_HEADER_SIZE;
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

                        if (clientPtr->isMdpEnabled)
                        {
                            APP_UdpSetMdpEnabled(sentMsg,
                                                     clientPtr->mdpUniqueId);
                        }

                        // dns
                        AppUdpPacketSendingInfo packetSendingInfo;
#ifdef ADDON_DB
                        packetSendingInfo.appParam = appParam;
#endif
                        packetSendingInfo.itemSize = clientPtr->itemSize;
                        packetSendingInfo.stats = clientPtr->stats;
                        packetSendingInfo.fragNo = NO_UDP_FRAG;
                        packetSendingInfo.fragSize = 0;

                        node->appData.appTrafficSender->appUdpSend(
                                                node,
                                                sentMsg,
                                                *clientPtr->serverUrl,
                                                clientPtr->localAddr,
                                                APP_CBR_CLIENT,
                                                (short)clientPtr->sourcePort,
                                                packetSendingInfo);
                        clientPtr->sessionLastSent = node->getNodeTime();

                        if (clientPtr->itemsToSend > 0)
                        {
                            clientPtr->itemsToSend--;
                        }

                        if (clientPtr->sessionIsClosed == FALSE)
                        {
                            AppCbrClientScheduleNextPkt(node, clientPtr);
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
           sprintf(error, "CBR Client: at time %sS, node %d "
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
AppCbrClientReInit(Node* node, Address sourceAddr)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataCbrClient *cbrClient;
    int i;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_CBR_CLIENT)
        {
            cbrClient = (AppDataCbrClient *) appList->appDetail;

            for (i=0; i< node->numberInterfaces; i++)
            {
                // currently only support ipv4. May be better way to compare this.
                if (cbrClient->localAddr.interfaceAddr.ipv4 == node->iface[i].oldIpAddress)
                {
                    memcpy(&(cbrClient->localAddr), &sourceAddr, sizeof(Address));
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
AppCbrClientInit(
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
    AppDataCbrClient *clientPtr;
    Message *timerMsg;
    int minSize;
    startTime -= getSimStartTime(node);
    endTime -= getSimStartTime(node);

    ERROR_Assert(sizeof(CbrData) <= CBR_HEADER_SIZE,
                 "CbrData size cant be greater than CBR_HEADER_SIZE");
    minSize = CBR_HEADER_SIZE;

    /* Check to make sure the number of cbr items is a correct value. */
    if (itemsToSend < 0)
    {
        sprintf(error, "CBR Client: Node %d item to sends needs"
            " to be >= 0\n", node->nodeId);

        ERROR_ReportError(error);
    }

    /* Make sure that packet is big enough to carry cbr data information. */
    if (itemSize < minSize)
    {
        sprintf(error, "CBR Client: Node %d item size needs to be >= %d.\n",
                node->nodeId, minSize);
        ERROR_ReportError(error);
    }


    /* Make sure that packet is within max limit. */
    if (itemSize > APP_MAX_DATA_SIZE)
    {
        sprintf(error, "CBR Client: Node %d item size needs to be <= %d.\n",
                node->nodeId, APP_MAX_DATA_SIZE);
        ERROR_ReportError(error);
    }

    /* Make sure interval is valid. */
    if (interval <= 0)
    {
        sprintf(error, "CBR Client: Node %d interval needs to be > 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Make sure start time is valid. */
    if (startTime < 0)
    {
        sprintf(error, "CBR Client: Node %d start time needs to be >= 0.\n",
                node->nodeId);
        ERROR_ReportError(error);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        sprintf(error, "CBR Client: Node %d end time needs to be > "
            "start time or equal to 0.\n", node->nodeId);

        ERROR_ReportError(error);
    }

    // Validate the given tos for this application.
    if (/*tos < 0 || */tos > 255)
    {
        sprintf(error, "CBR Client: Node %d should have tos value "
            "within the range 0 to 255.\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

#ifdef ADDON_NGCNMS
    clocktype origStart = startTime;

    // for restarts (node and interface).
    if (NODE_IsDisabled(node))
    {
        clocktype currTime = node->getNodeTime();
        if (endTime <= currTime)
        {
            // application already finished.
            return;
        }
        else if (startTime >= currTime)
        {
            // application hasnt started yet
            startTime -= currTime;
        }
        else
        {
            // application has already started,
            // so pick up where we left off.

            // try to determine the number of items already sent.
            if (itemsToSend != 0)
            {
                clocktype diffTime = currTime - startTime;
                int itemsSent = diffTime / interval;

                if (itemsToSend < itemsSent)
                {
                    return;
                }

                itemsToSend -= itemsSent;
            }

            // start right away.
            startTime = 0;

        }
    }
#endif

    clientPtr = AppCbrClientNewCbrClient(node,
                                         clientAddr,
                                         serverAddr,
                                         itemsToSend,
                                         itemSize,
                                         interval,
#ifndef ADDON_NGCNMS
                                         startTime,
#else
                                         origStart,
#endif
                                         endTime,
                                         (TosType) tos,
                                         appName);

    if (clientPtr == NULL)
    {
        sprintf(error,
                "CBR Client: Node %d cannot allocate memory for "
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
            customName = "CBR Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                                      node,
                                      "cbr",
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
                node->nodeId, srcString, destString, "CBR");
        }
    }
    // client pointer initialization with respect to mdp
    clientPtr->isMdpEnabled = isMdpEnabled;
    clientPtr->mdpUniqueId = uniqueId;

    if (isMdpEnabled)
    {
        // MDP Layer Init
        MdpLayerInit(node,
                     clientAddr,
                     serverAddr,
                     clientPtr->sourcePort,
                     APP_CBR_CLIENT,
                     isProfileNameSet,
                     profileName,
                     uniqueId,
                     nodeInput,
                     -1,
                     TRUE);
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
                              APP_CBR_CLIENT,
                              MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(startTime, clockStr, node);
        printf("CBR Client: Node %ld starting client at %sS\n",
               node->nodeId, clockStr);
    }
#endif /* DEBUG */

    MESSAGE_Send(node, timerMsg, startTime);

#ifdef ADDON_NGCNMS

    clientPtr->lastTimer = timerMsg;

#endif
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
    AppCbrClientAddAddressInformation(node, clientPtr);
}

/*
 * NAME:        AppCbrClientPrintStats.
 * PURPOSE:     Prints statistics of a CbrClient session.
 * PARAMETERS:  node - pointer to the this node.
 *              clientPtr - pointer to the cbr client data structure.
 * RETURN:      none.
 */
void AppCbrClientPrintStats(Node *node, AppDataCbrClient *clientPtr) {

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
        "CBR Client",
        ANY_DEST,
        clientPtr->sourcePort,
        buf);


    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "CBR Client",
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
AppCbrClientFinalize(Node *node, AppInfo* appInfo)
{
    AppDataCbrClient *clientPtr = (AppDataCbrClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppCbrClientPrintStats(node, clientPtr);

        // Print stats in .stat file using Stat APIs
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                node,
                "Application",
                "CBR Client",
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
AppDataCbrClient *
AppCbrClientGetCbrClient(Node *node, short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataCbrClient *cbrClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_CBR_CLIENT)
        {
            cbrClient = (AppDataCbrClient *) appList->appDetail;

            if (cbrClient->sourcePort == sourcePort)
            {
                return cbrClient;
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
AppDataCbrClient *
AppCbrClientNewCbrClient(Node *node,
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
    AppDataCbrClient *cbrClient;

    cbrClient = (AppDataCbrClient *)
                MEM_malloc(sizeof(AppDataCbrClient));
    memset(cbrClient, 0, sizeof(AppDataCbrClient));

    /*
     * fill in cbr info.
     */
    memcpy(&(cbrClient->localAddr), &localAddr, sizeof(Address));
    memcpy(&(cbrClient->remoteAddr), &remoteAddr, sizeof(Address));
    cbrClient->interval = interval;
#ifndef ADDON_NGCNMS
    cbrClient->sessionStart = node->getNodeTime() + startTime;
#else
    if (!NODE_IsDisabled(node))
    {
        cbrClient->sessionStart = node->getNodeTime() + startTime;
    }
    else
    {
        // start time was already figured out in caller function.
        cbrClient->sessionStart = startTime;
    }
#endif
    cbrClient->sessionIsClosed = FALSE;
    cbrClient->sessionLastSent = node->getNodeTime();
    cbrClient->sessionFinish = node->getNodeTime();
    cbrClient->endTime = endTime;
    cbrClient->itemsToSend = itemsToSend;
    cbrClient->itemSize = itemSize;
    cbrClient->sourcePort = node->appData.nextPortNum++;
    cbrClient->seqNo = 0;
    cbrClient->tos = tos;
    cbrClient->uniqueId = node->appData.uniqueId++;
    //client pointer initialization with respect to mdp
    cbrClient->isMdpEnabled = FALSE;
    cbrClient->mdpUniqueId = -1;  //invalid value
    cbrClient->stats = NULL;
    // dns
    cbrClient->serverUrl = new std::string();
    cbrClient->serverUrl->clear();
    cbrClient->destNodeId = ANY_NODEID;
    cbrClient->clientInterfaceIndex = ANY_INTERFACE;
    cbrClient->destInterfaceIndex = ANY_INTERFACE;
    if (appName)
    {
        cbrClient->applicationName = new std::string(appName);
    }
    else
    {
        cbrClient->applicationName = new std::string();
    }
#ifdef ADDON_DB
    cbrClient->sessionId = cbrClient->uniqueId;

    // dns
    // Skipped if the server network type is not valid
    // it should happen only when the server is given by a URL
    // receiverId will be initialized when url is resolved
    if (cbrClient->remoteAddr.networkType != NETWORK_INVALID)
    {
        if (Address_IsAnyAddress(&(cbrClient->remoteAddr)) ||
            Address_IsMulticastAddress(&cbrClient->remoteAddr))
        {
            cbrClient->receiverId = 0;
        }
        else
        {
            cbrClient->receiverId =
                MAPPING_GetNodeIdFromInterfaceAddress(node, remoteAddr);
        }
    }
#endif // ADDON_DB

    // Add CBR variables to hierarchy
    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateApplicationPath(
            node,                   // node
            "cbrClient",            // protocol name
            cbrClient->sourcePort,  // port
            "interval",             // object name
            path))                  // path (output)
    {
        h->AddObject(
            path,
            new D_ClocktypeObj(&cbrClient->interval));
    }

// The HUMAN_IN_THE_LOOP_DEMO is part of a gui user-defined command
// demo.
// The type of service value for this CBR application is added to
// the dynamic hierarchy so that the user-defined-command can change
// it during simulation.
#ifdef HUMAN_IN_THE_LOOP_DEMO
    if (h->CreateApplicationPath(
            node,
            "cbrClient",
            cbrClient->sourcePort,
            "tos",                  // object name
            path))                  // path (output)
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&cbrClient->tos));
    }
#endif

#ifdef DEBUG
    {
        char clockStr[MAX_STRING_LENGTH];
        char localAddrStr[MAX_STRING_LENGTH];
        char remoteAddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(&cbrClient->localAddr, localAddrStr);
        IO_ConvertIpAddressToString(&cbrClient->remoteAddr, remoteAddrStr);

        printf("CBR Client: Node %u created new cbr client structure\n",
               node->nodeId);
        printf("    localAddr = %s\n", localAddrStr);
        printf("    remoteAddr = %s\n", remoteAddrStr);
        TIME_PrintClockInSecond(cbrClient->interval, clockStr);
        printf("    interval = %s\n", clockStr);
        TIME_PrintClockInSecond(cbrClient->sessionStart, clockStr, node);
        printf("    sessionStart = %sS\n", clockStr);
        printf("    itemsToSend = %u\n", cbrClient->itemsToSend);
        printf("    itemSize = %u\n", cbrClient->itemSize);
        printf("    sourcePort = %ld\n", cbrClient->sourcePort);
        printf("    seqNo = %ld\n", cbrClient->seqNo);
    }
#endif /* DEBUG */

    APP_RegisterNewApp(node, APP_CBR_CLIENT, cbrClient);

    return cbrClient;
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
AppCbrClientScheduleNextPkt(Node *node, AppDataCbrClient *clientPtr)
{
    AppTimer *timer;
    Message *timerMsg;

    timerMsg = MESSAGE_Alloc(node,
                              APP_LAYER,
                              APP_CBR_CLIENT,
                              MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

#ifdef DEBUG
    {
        char clockStr[24];
        printf("CBR Client: Node %u scheduling next data packet\n",
               node->nodeId);
        printf("    timer type is %d\n", timer->type);
        TIME_PrintClockInSecond(clientPtr->interval, clockStr);
        printf("    interval is %sS\n", clockStr);
    }
#endif /* DEBUG */

#ifdef ADDON_NGCNMS

    clientPtr->lastTimer = timerMsg;

#endif

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
AppLayerCbrServer(Node *node, Message *msg)
{
    char error[MAX_STRING_LENGTH];
    AppDataCbrServer *serverPtr;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv *info;
            CbrData data;
#ifdef ADDON_DB
            AppMsgStatus msgStatus = APP_MSG_OLD;
#endif // ADDON_DB

            ERROR_Assert(sizeof(data) <= CBR_HEADER_SIZE,
                         "CbrData size cant be greater than CBR_HEADER_SIZE");

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

                printf("CBR Server %ld: packet transmitted at %sS\n",
                       node->nodeId, clockStr);
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
                printf("    received at %sS\n", clockStr);
                printf("    client is %s\n", addrStr);
                printf("    connection Id is %d\n", data.sourcePort);
                printf("    seqNo is %d\n", data.seqNo);
            }
#endif /* DEBUG */

            serverPtr = AppCbrServerGetCbrServer(node,
                                                 info->sourceAddr,
                                                 data.sourcePort);

            /* New connection, so create new cbr server to handle client. */
            if (serverPtr == NULL)
            {
                serverPtr = AppCbrServerNewCbrServer(node,
                                                     info->destAddr,
                                                     info->sourceAddr,
                                                     data.sourcePort);

                // Create statistics
                if (node->appData.appStats)
                {
                    serverPtr->stats = new STAT_AppStatistics(
                        node,
                        "cbrServer",
                        STAT_Unicast,
                        STAT_AppReceiver,
                        "CBR Server");
                    serverPtr->stats->Initialize(
                        node,
                        info->sourceAddr,
                        info->destAddr,
                        STAT_AppStatistics::GetSessionId(msg),
                        serverPtr->uniqueId);
                    serverPtr->stats->SessionStart(node);
                }
#ifdef ADDON_DB
                // cbr application, clientPort == serverPort
                STATSDB_HandleSessionDescTableInsert(node, msg,
                    info->sourceAddr, info->destAddr,
                    info->sourcePort, info->destPort,
                    "CBR", "UDP");

                StatsDBAppEventParam* appParamInfo = NULL;
                appParamInfo = (StatsDBAppEventParam*) MESSAGE_ReturnInfo(
                                   msg,
                                   INFO_TYPE_AppStatsDbContent);
                if (appParamInfo != NULL)
                {
                    STATSDB_HandleAppConnCreation(node, info->sourceAddr,
                        info->destAddr, appParamInfo->m_SessionId);
                }
#endif
            }

            if (serverPtr == NULL)
            {
                sprintf(error, "CBR Server: Node %d unable to "
                        "allocation server\n", node->nodeId);

                ERROR_ReportError(error);
            }

#ifdef ADDON_BOEINGFCS
            if ((serverPtr->useSeqNoCheck && data.seqNo >= serverPtr->seqNo) ||
                (serverPtr->useSeqNoCheck == FALSE))
#else
            if (data.seqNo >= serverPtr->seqNo || data.isMdpEnabled)
#endif
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

#ifdef LTE_LIB
#ifdef LTE_LIB_LOG
#ifdef LTE_LIB_VALIDATION_LOG
                static char addrStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
                lte::LteLog::InfoFormat(
                        node, -1, "APP", "%s,%s,%llu",
                        "AppPacketDelay", addrStr, delay);
#endif
#endif
#endif



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

#ifdef ADDON_DB
            msgStatus = APP_MSG_NEW;
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL)
            {
                clocktype delay = node->getNodeTime() - data.txTime;
                
                if (node->appData.appStats)
                {
                    if (serverPtr->stats->GetMessagesReceived().GetValue(node->getNodeTime()) == 1)
                    { // Only need this info once
                        StatsDBAppEventParam* appParamInfo = NULL;
                        appParamInfo = (StatsDBAppEventParam*) MESSAGE_ReturnInfo(msg, INFO_TYPE_AppStatsDbContent);
                        if (appParamInfo != NULL)
                        {
                            serverPtr->sessionId = appParamInfo->m_SessionId;
                            serverPtr->sessionInitiator = appParamInfo->m_SessionInitiator;
                        }
                    }

                    SequenceNumber::Status seqStatus =
                        APP_ReportStatsDbReceiveEvent(
                            node,
                            msg,
                            &(serverPtr->seqNumCache),
                            data.seqNo,
                            delay,
                            (clocktype)serverPtr->stats->
                                GetJitter().GetValue(node->getNodeTime()),
                            MESSAGE_ReturnPacketSize(msg),
                            (Int32)serverPtr->stats->
                                GetMessagesReceived().
                                GetValue(node->getNodeTime()),
                            msgStatus);

                    if (seqStatus == SequenceNumber::SEQ_NEW)
                    {
                        // get hop count
                        StatsDBNetworkEventParam* ipParamInfo;
                        ipParamInfo = (StatsDBNetworkEventParam*)
                            MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

                        if (ipParamInfo == NULL)
                        {
                            printf ("ERROR: We should have Network Events Info");
                        }
                        else
                        {
                            serverPtr->hopCount += (Int32) ipParamInfo->m_HopCount;
                        }
                    }
                }
            }
#endif // ADDON_DB
            break;
        }

        default:
        {
            char buf[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), buf, node);
            sprintf(error, "CBR Server: At time %sS, node %d received "
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
AppCbrServerInit(Node *node)
{
    APP_InserInPortTable(node, APP_CBR_SERVER, APP_CBR_SERVER);
}

/*
 * NAME:        AppCbrServerPrintStats.
 * PURPOSE:     Prints statistics of a CbrServer session.
 * PARAMETERS:  node - pointer to this node.
 *              serverPtr - pointer to the cbr server data structure.
 * RETURN:      none.
 */
void
AppCbrServerPrintStats(Node *node, AppDataCbrServer *serverPtr) {

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
        "CBR Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);


    sprintf(buf, "Session Status = %s", sessionStatusStr);
    IO_PrintStat(
        node,
        "Application",
        "CBR Server",
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
AppCbrServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataCbrServer *serverPtr = (AppDataCbrServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppCbrServerPrintStats(node, serverPtr);
        // Print stats in .stat file using Stat APIs
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(node,
                                    "Application",
                                    "CBR Server",
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
 * NAME:        AppCbrServerGetCbrServer.
 * PURPOSE:     search for a cbr server data structure.
 * PARAMETERS:  node - cbr server.
 *              remoteAddr - cbr client sending the data.
 *              sourcePort - sourcePort of cbr client/server pair.
 * RETURN:      the pointer to the cbr server data structure,
 *              NULL if nothing found.
 */
AppDataCbrServer * //inline//
AppCbrServerGetCbrServer(
    Node *node, Address remoteAddr, short sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataCbrServer *cbrServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_CBR_SERVER)
        {
            cbrServer = (AppDataCbrServer *) appList->appDetail;

            if ((cbrServer->sourcePort == sourcePort) &&
                IO_CheckIsSameAddress(
                    cbrServer->remoteAddr, remoteAddr))
            {
                return cbrServer;
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
AppDataCbrServer * //inline//
AppCbrServerNewCbrServer(Node *node,
                         Address localAddr,
                         Address remoteAddr,
                         short sourcePort)
{
    AppDataCbrServer *cbrServer;

    cbrServer = (AppDataCbrServer *)
                MEM_malloc(sizeof(AppDataCbrServer));
    memset(cbrServer, 0, sizeof(AppDataCbrServer));
    /*
     * Fill in cbr info.
     */
    memcpy(&(cbrServer->localAddr), &localAddr, sizeof(Address));
    memcpy(&(cbrServer->remoteAddr), &remoteAddr, sizeof(Address));
    cbrServer->sourcePort = sourcePort;
    cbrServer->sessionStart = node->getNodeTime();
    cbrServer->sessionFinish = node->getNodeTime();
    cbrServer->sessionIsClosed = FALSE;
    cbrServer->seqNo = 0;
    cbrServer->uniqueId = node->appData.uniqueId++;

    //    cbrServer->lastInterArrivalInterval = 0;
    //    cbrServer->lastPacketReceptionTime = 0;
    cbrServer->stats = NULL;
#ifdef ADDON_DB
    cbrServer->sessionId = -1;
    cbrServer->sessionInitiator = 0;
    cbrServer->hopCount = 0;
    cbrServer->seqNumCache = NULL;
#endif // ADDON_DB


#ifdef ADDON_BOEINGFCS
    BOOL retVal = FALSE;

    cbrServer->useSeqNoCheck = TRUE;

    IO_ReadBool(
        node->nodeId,
        ANY_ADDRESS,
        node->partitionData->nodeInput,
        "APP-CBR-USE-SEQUENCE-NUMBER-CHECK",
        &retVal,
        &cbrServer->useSeqNoCheck);

#endif

    APP_RegisterNewApp(node, APP_CBR_SERVER, cbrServer);

    return cbrServer;
}

#ifdef ADDON_NGCNMS

void AppCbrReset(Node* node)
{

    if (node->disabled)
    {
        AppInfo *appList = node->appData.appPtr;
        AppDataCbrClient *cbrClient;

        for (; appList != NULL; appList = appList->appNext)
        {
            if (appList->appType == APP_CBR_CLIENT)
            {
                cbrClient = (AppDataCbrClient *) appList->appDetail;
                MESSAGE_CancelSelfMsg(node, cbrClient->lastTimer);
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
AppCbrClientAddAddressInformation(Node* node,
                                  AppDataCbrClient* clientPtr)
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
AppCbrClientGetSessionAddressState(Node* node,
                                   AppDataCbrClient* clientPtr)
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
AppCbrUrlSessionStartCallback(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    AppUdpPacketSendingInfo* packetSendingInfo)
{
    CbrData data;
    char cbrData[CBR_HEADER_SIZE];
    AppDataCbrClient* clientPtr = AppCbrClientGetCbrClient(node, sourcePort);

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
            ERROR_ReportErrorArgs("CBR Client: Node %d cannot find IPv4"
                           " cbr client for ipv4 dest\n", node->nodeId);
        }
    }
    else if (serverAddr->networkType == NETWORK_IPV6)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV6)
        {
            ERROR_ReportErrorArgs("CBR Client: Node %d cannot find IPv6"
                           " cbr client for ipv6 dest\n", node->nodeId);
        }
    }

    // Update client RemoteAddress field and session Start
    memcpy(&clientPtr->remoteAddr, serverAddr, sizeof(Address));

    // update the client address information
    AppCbrClientAddAddressInformation(node,
                                      clientPtr);

#ifdef ADDON_DB

    // initialize receiverid

    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
    {
        if (Address_IsAnyAddress(&(clientPtr->remoteAddr)) ||
            Address_IsMulticastAddress(&clientPtr->remoteAddr))
        {
            clientPtr->receiverId = 0;
        }
        else
        {
            clientPtr->receiverId =
                MAPPING_GetNodeIdFromInterfaceAddress(node, *serverAddr);
        }
    }
#endif // ADDON_DB

    if ((serverAddr->networkType != NETWORK_INVALID)
        && (node->appData.appStats))
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "CBR Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        clientPtr->stats = new STAT_AppStatistics(
                                      node,
                                      "cbr",
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
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.m_SessionInitiator = node->nodeId;
    appParam.m_ReceiverId = clientPtr->receiverId;
    appParam.SetAppType("CBR");
    appParam.SetFragNum(0);

    if (!clientPtr->applicationName->empty())
    {
        appParam.SetAppName(
            clientPtr->applicationName->c_str());
    }
    appParam.SetReceiverAddr(&clientPtr->remoteAddr);
    appParam.SetPriority(clientPtr->tos);
    appParam.SetSessionId(clientPtr->sessionId);
    appParam.SetMsgSize(clientPtr->itemSize);
    appParam.m_TotalMsgSize = clientPtr->itemSize;
    appParam.m_fragEnabled = FALSE;
#endif // ADDON_DB
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
    if (AppCbrClientGetSessionAddressState(node, clientPtr)
                                                        == ADDRESS_FOUND)
    {
#ifdef ADDON_DB
        memcpy(
            &packetSendingInfo->appParam,
            &appParam,
            sizeof(StatsDBAppEventParam));
#else
        memset(
            &packetSendingInfo->appParam,
            NULL,
            sizeof(StatsDBAppEventParam));
#endif
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
