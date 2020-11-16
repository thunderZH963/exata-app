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
#include "tcpapps.h"
#include "transport_tcp.h"
#include "network_ip.h"
#include "app_vbr.h"

//UserCodeStartBodyData
#include "if_loopback.h"


//UserCodeEndBodyData

//Statistic Function Declarations
static void VbrInitStats(Node* node, VbrStatsType *stats);

//Utility Function Declarations
static void VbrClientScheduleNextPkt(Node* node,VbrData* dataPtr);

static VbrData* VbrServerSetDataPtr(Node* node, Message* msg) {
    UdpToAppRecv* info;
    VbrData* dataPtr;
    AppInfo* appList = node->appData.appPtr;

    info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
    for (; appList != NULL; appList = appList->appNext) {
        if (appList->appType == APP_VBR_SERVER) {
            dataPtr = (VbrData*) appList->appDetail;

            if (dataPtr->sourcePort == VBR_INVALID_SOURCE_PORT) {
                dataPtr->clientAddr   = GetIPv4Address(info->sourceAddr);
                dataPtr->serverAddr   = GetIPv4Address(info->destAddr);
                dataPtr->sourcePort   = info->sourcePort;
                dataPtr->connectionId = info->sourcePort;

                return dataPtr;
            }
        }
    }
    return NULL;
}

//State Function Declarations
static void enterVbrServerIdle(Node* node, VbrData* dataPtr, Message* msg);
static void enterVbrClientIdle(Node* node, VbrData* dataPtr, Message* msg);
static void enterVbrClientTimerExpired(Node* node, VbrData* dataPtr, Message* msg);
static void enterVbrServerReceivesData(Node* node, VbrData* dataPtr, Message* msg);

//Utility Function Definitions
//UserCodeStart
// FUNCTION VbrClientScheduleNextPkt
// PURPOSE *schedule the next packet the client will send.  If next packet*won't arrive until the finish deadline, schedule a close.*
// Parameters:
//  node: *pointer to the node*
//  dataPtr:  *pointer to the vbr client data structure*
static void VbrClientScheduleNextPkt(Node* node,VbrData* dataPtr) {
   AppTimer* timer;
   clocktype nextTime;
   clocktype currTime;
   Message* timerMsg ;

   timerMsg = MESSAGE_Alloc(node,
        APP_LAYER,
        APP_VBR_CLIENT,
        MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = dataPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

    timer->address = dataPtr->clientAddr;

    // VBR send data packet at variable rate which is a function of mean Interval
    nextTime = (clocktype)
        ((-log((double)(1.0-((double) RANDOM_erand(dataPtr->seed))))) *
        ((double)dataPtr->meanInterval));

    currTime = node->getNodeTime();
    if ((currTime + nextTime <= dataPtr->endTime))
    {
        MESSAGE_Send(node, timerMsg, nextTime);
        dataPtr->type = 'd';
    }
    else
    {
        dataPtr->type = 'c';
        dataPtr->sessionIsClosed = TRUE;
        if (node->appData.appStats)
        {
            dataPtr->appStats->SessionFinish(node);
        }
    }
}



//UserCodeEnd

//State Function Definitions
static void enterVbrServerIdle(Node* node,
                               VbrData* dataPtr,
                               Message *msg) {

    //UserCodeStartServerIdle

    //UserCodeEndServerIdle

}

static void enterVbrClientIdle(Node* node,
                               VbrData* dataPtr,
                               Message *msg) {

    //UserCodeStartClientIdle

    //UserCodeEndClientIdle

}

static void enterVbrClientTimerExpired(Node* node,
                                       VbrData* dataPtr,
                                       Message *msg) {

    //UserCodeStartClientTimerExpired
    // Variable Decleration
    clocktype currentTime = node->getNodeTime();
    VbrMsgData data;
    memset(&data, 0, sizeof(data));
    // update datPtr
    dataPtr->connectionId = dataPtr->sourcePort;

    // VbrMsgData: Set UDP Data sourcePort
    data.sourcePort = dataPtr->sourcePort;

    if (node->appData.appStats)
    {
        if (dataPtr->appStats->GetDataSent().GetValue(node->getNodeTime()) == 0)
        {
            dataPtr->appStats->SessionStart(node);
        }
    }

    // assuming session is not closed and going for scheduling nextPkt
    if (dataPtr->sessionIsClosed == FALSE)
    {
        // below call check whether to schedule timer for next packet or not
        // also update session status and dataPtr->type accordingly
        VbrClientScheduleNextPkt(node, dataPtr);
    }

    // VbrMsgData: Set packet type
    data.type = dataPtr->type;

#if defined(ADVANCED_WIRELESS_LIB) || defined(UMTS_LIB) || defined(MUOS_LIB)
    data.pktSize = dataPtr->itemSize;
    data.meanInterval = dataPtr->meanInterval;
#endif // ADVANCED_WIRELESS_LIB || UMTS_LIB || MUOS_LIB

    // send UDP data
    Message *msgVbr = APP_UdpCreateMessage(
        node,
        dataPtr->clientAddr,
        (short) dataPtr->sourcePort,
        dataPtr->serverAddr,
        (short) APP_VBR_SERVER,
        TRACE_VBR,
        dataPtr->tos);

    APP_AddPayload(
        node,
        msgVbr,
        &data,
        sizeof(data));

    APP_AddVirtualPayload(
        node,
        msgVbr,
        dataPtr->itemSize - sizeof(data));

    if (dataPtr->isMdpEnabled)
    {
        APP_UdpSetMdpEnabled(msgVbr, dataPtr->mdpUniqueId);
    }

    APP_UdpSend(node, msgVbr);

    dataPtr->stats.BytesSent += dataPtr->itemSize;
    dataPtr->sessionFinish = node->getNodeTime();

    // if session is not closed schedule for nextPkt
    if (node->appData.appStats)
    {
        dataPtr->appStats->AddFragmentSentDataPoints(node,
                                                     dataPtr->itemSize,
                                                     STAT_Unicast);
        dataPtr->appStats->AddMessageSentDataPoints(node,
                                                    msgVbr,
                                                    0,
                                                    dataPtr->itemSize,
                                                    0,
                                                    STAT_Unicast);
    }
    dataPtr->sessionFinish = node->getNodeTime();

    MESSAGE_Free(node, msg);

    //UserCodeEndClientTimerExpired
    dataPtr->state = VBR_CLIENTIDLE;
    enterVbrClientIdle(node, dataPtr, msg);
}

static void enterVbrServerReceivesData(Node* node,
                                       VbrData* dataPtr,
                                       Message *msg) {

    //UserCodeStartServerReceivesData
    // variable declaration & initialization
    UdpToAppRecv* info;
    VbrMsgData data;

    info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
    memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

    if (node->appData.appStats)
    {
        dataPtr->appStats->AddFragmentReceivedDataPoints(
            node,
            msg,
            MESSAGE_ReturnPacketSize(msg),
            STAT_Unicast);

        dataPtr->appStats->AddMessageReceivedDataPoints(
            node,
            msg,
            0,
            MESSAGE_ReturnPacketSize(msg),
            0,
            STAT_Unicast);
    }
    // VBR does not attempt to reorder packets.
    // After receiving each packet it simply updates dataPtr
    dataPtr->connectionId = data.sourcePort ;

    if (!dataPtr->sessionStart)
    {
        dataPtr->sessionStart = node->getNodeTime();
    }

    // Store session related information
     dataPtr->sessionFinish = node->getNodeTime();

    if (data.type == 'd')
    {
        /* Do nothing. */
    }
    else if (data.type == 'c')
    {
        dataPtr->sessionIsClosed = TRUE;
        if (node->appData.appStats)
        {
            dataPtr->appStats->SessionFinish(node);
        }
    }

    MESSAGE_Free(node, msg);


    //UserCodeEndServerReceivesData
    dataPtr->state = VBR_SERVERIDLE;
    enterVbrServerIdle(node, dataPtr, msg);
}


//Statistic Function Definitions
static void VbrInitStats(Node* node, VbrStatsType *stats) {
    if (node->guiOption) {
        stats->BytesSentId = GUI_DefineMetric("Total Bytes Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_INTEGER_TYPE,GUI_CUMULATIVE_METRIC);
        stats->BytesReceivedId = GUI_DefineMetric("Total Bytes Received", node->nodeId, GUI_APP_LAYER, 0, GUI_INTEGER_TYPE,GUI_CUMULATIVE_METRIC);
    }
}

void VbrRunTimeStat(Node* node, VbrData* dataPtr) {
    clocktype now = node->getNodeTime();

    if (node->appData.appStats)
    {
        if (node->guiOption) {
            GUI_SendIntegerData(node->nodeId,
                                dataPtr->stats.BytesSentId,
                                (Int32)dataPtr->appStats->
                                    GetDataSent().GetValue(now),
                                now);
            GUI_SendIntegerData(node->nodeId,
                                dataPtr->stats.BytesReceivedId,
                                (Int32)dataPtr->appStats->
                                    GetDataReceived().GetValue(now),
                                now);
        }
    }
}

void
VbrInit(Node* node,
        NodeAddress clientAddr,
        NodeAddress serverAddr,
        int itemSize,
        clocktype meanInterval,
        clocktype startTime,
        clocktype endTime,
        unsigned tos,
        char* appName,
        BOOL isMdpEnabled,
        BOOL isProfileNameSet,
        char* profileName,
        Int32 uniqueId,
        const NodeInput* nodeInput)
{
    VbrData *dataPtr = NULL;
    Message *msg = NULL;
    NetworkDataIp* ip = (NetworkDataIp *)node->networkData.networkVar;

    //UserCodeStartInit
    /****************INIT FUNCTION**************************/
    /***** INIT 1 FOLLOWS *****/
    AppTimer* timer;
    int minSize = sizeof(VbrMsgData);
    char error[MAX_STRING_LENGTH];

    /************************************************************/

    // Handle Loopback Address
    if (NetworkIpIsLoopbackInterfaceAddress(serverAddr) ||
        (MAPPING_GetNodeIdFromInterfaceAddress(node,clientAddr)
            == MAPPING_GetNodeIdFromInterfaceAddress(node,serverAddr)))
    {
        char errorStr[MAX_STRING_LENGTH] = {0};
        // Error
        sprintf(errorStr, "Application doesn't support "
            "Loopback Address!\n \n");

        ERROR_ReportWarning(errorStr);
        return;
    }

    /***** INIT 2 FOLLOWS *****/
    /* Make sure that packet is big enough to carry data information.
    */
    if (itemSize < minSize)
    {
        sprintf(error, "VBR Client: Node %u item size needs to be >= %d.\n",
            node->nodeId, minSize);
        ERROR_ReportError(error);
    }

    /* Make sure that packet is within max limit. */
    if (itemSize > APP_MAX_DATA_SIZE)
    {
        sprintf(error, "VBR Client: Node %u item size needs to be <= %d.\n",
            node->nodeId, APP_MAX_DATA_SIZE);
        ERROR_ReportError(error);
    }

    /* Make sure interval is valid. */
    if (meanInterval <= 0)
    {
        sprintf(error,"VBR Client: Node %u interval needs to be > 0.\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

    /* Make sure start time is valid. */
    if (startTime < 0)
    {
        sprintf(error, "VBR Client: Node %u start time needs to be >= 0.\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

    /* Check to make sure the end time is a correct value. */
    if (!((endTime > startTime) || (endTime == 0)))
    {
        sprintf(error, "VBR App: Node %u end time needs to be > start time "
            "or equal to 0.\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

    /***** INIT 3 FOLLOWS *****/
    // Perform common init functions for UDP & TCP
    BOOL correctClientAddr = FALSE;
    int ifid = 0;
    for (ifid = 0; ifid < node->numberInterfaces; ++ifid){
        if (ip->interfaceInfo[ifid]->ipAddress == clientAddr){
            correctClientAddr = TRUE;
            break;
        }
    }
    BOOL correctSvrAddr = FALSE;
    for (ifid = 0; ifid < node->numberInterfaces; ++ifid){
        if (ip->interfaceInfo[ifid]->ipAddress == serverAddr){
            correctSvrAddr = TRUE;
            break;
        }
    }

    if (correctSvrAddr || correctClientAddr) {
        dataPtr = (VbrData*) MEM_malloc(sizeof(VbrData));
        memset(dataPtr, 0, sizeof(VbrData));
    } else {
        sprintf(error, "VBR Client / Server is not define for Node Id %u\n",
            node->nodeId);
        ERROR_ReportError(error);
    }

    /***** INIT 4 FOLLOWS *****/
    if (correctSvrAddr)
    {
        //printf("NODE %u: APP_VBR_SERVER STARTING VBR PROTOCOL!\n",
        //    node->nodeId);

        dataPtr->protocol = APP_VBR_SERVER;
        //dataPtr->state = VBR_SERVERIDLE;
        dataPtr->sourcePort = VBR_INVALID_SOURCE_PORT;
        dataPtr->connectionId = dataPtr->sourcePort;
        dataPtr->isMdpEnabled = isMdpEnabled;
        dataPtr->mdpUniqueId  = uniqueId;
        dataPtr->uniqueId = node->appData.uniqueId++;
        dataPtr->applicationName = NULL;

        APP_RegisterNewApp(node, (AppType) dataPtr->protocol, dataPtr);
    }

    if (correctClientAddr)
    {
         //printf("NODE %u: APP_VBR_CLIENT STARTING VBR PROTOCOL!\n",
         //   node->nodeId);
        dataPtr->protocol = APP_VBR_CLIENT;
        //dataPtr->state = VBR_CLIENTIDLE;
        dataPtr->sourcePort = node->appData.nextPortNum++;

        //  Fill in vbr parameter info to this client dataPtr
        dataPtr->clientAddr   = clientAddr;
        dataPtr->serverAddr   = serverAddr;
        dataPtr->itemSize     = itemSize;
        dataPtr->meanInterval = meanInterval;
        dataPtr->startTime    = startTime;
        dataPtr->endTime      = endTime;
        dataPtr->connectionId = dataPtr->sourcePort;
        dataPtr->tos          = tos;
        dataPtr->isMdpEnabled = isMdpEnabled;
        dataPtr->mdpUniqueId  = uniqueId;
        dataPtr->uniqueId = node->appData.uniqueId++;
        if (appName)
        {
            dataPtr->applicationName = new std::string(appName);
        }
        else
        {
            dataPtr->applicationName = new std::string();
        }

        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, clientAddr);
        SetIPv4AddressInfo(&rAddr, serverAddr);

        if (node->appData.appStats)
        {
            std::string customName;
            if (dataPtr->applicationName->empty())
            {
                customName = "VBR Client";
            }
            else
            {
                customName = *dataPtr->applicationName;
            }
            dataPtr->appStats = new STAT_AppStatistics(
                                          node,
                                          "vbr",
                                          STAT_Unicast,
                                          STAT_AppSenderReceiver,
                                          customName.c_str());
            dataPtr->appStats->Initialize(
                 node,
                 lAddr,
                 rAddr,
                 (STAT_SessionIdType)dataPtr->uniqueId,
                 dataPtr->uniqueId);
            dataPtr->appStats->setTos(tos);
        }
        if (isMdpEnabled)
        {
            Address localAddr, remoteAddr;
            memset(&localAddr,0,sizeof(Address));
            memset(&remoteAddr,0,sizeof(Address));

            localAddr.networkType = NETWORK_IPV4;
            localAddr.interfaceAddr.ipv4 = clientAddr;
            remoteAddr.networkType = NETWORK_IPV4;
            remoteAddr.interfaceAddr.ipv4 = serverAddr;

            //MDP Layer Init
            MdpLayerInit(node,
                         localAddr,
                         remoteAddr,
                         dataPtr->sourcePort,
                         APP_VBR_CLIENT,
                         isProfileNameSet,
                         profileName,
                         uniqueId,
                         nodeInput,
                         -1,
                         TRUE);
        }

        // Make unique seed from node's initial seed value.
        RANDOM_SetSeed(dataPtr->seed,
                       node->globalSeed,
                       node->nodeId,
                       APP_VBR_CLIENT,
                       dataPtr->connectionId);//not sure connectionId is unique

        APP_RegisterNewApp(node, (AppType) dataPtr->protocol, dataPtr);

        //Set timer to intialise packet transfer at start time
        msg = MESSAGE_Alloc(node,
            APP_LAYER,
            APP_VBR_CLIENT,
            MSG_APP_TimerExpired);
        MESSAGE_InfoAlloc(node, msg, sizeof(AppTimer));

        timer = (AppTimer *)MESSAGE_ReturnInfo(msg);

        timer->sourcePort = dataPtr->sourcePort;
        timer->type = APP_TIMER_SEND_PKT;

        timer->address = dataPtr->clientAddr;

        dataPtr->sessionStart = node->getNodeTime() + startTime;
        MESSAGE_Send(node, msg, startTime);
    }
    /****************END OF INIT FUNCTION**************************/
    dataPtr->initStats = TRUE;


    //UserCodeEndInit
    if (dataPtr->initStats) {
        VbrInitStats(node, &(dataPtr->stats));
    }

    if (correctSvrAddr) {
        Message *msg = NULL;
        dataPtr->state = VBR_SERVERIDLE;
        enterVbrServerIdle(node, dataPtr, msg);
        return;
    }

    if (correctClientAddr) {
        Message *msg = NULL;
        dataPtr->state = VBR_CLIENTIDLE;
        enterVbrClientIdle(node, dataPtr, msg);
        return;
    }
}


void
VbrFinalize(Node* node, VbrData* dataPtr) {
    if (node->appData.appStats)
    {
        //UserCodeStartFinalize
        dataPtr->printStats = TRUE;
        char statProtocolName[MAX_STRING_LENGTH];
        strcpy(statProtocolName,"VBR");

        if (dataPtr->appStats
            && !dataPtr->appStats->IsSessionFinished(STAT_Unicast))
        {
            dataPtr->appStats->SessionFinish(node);
        }
    
        //UserCodeEndFinalize
        if (dataPtr->printStats)
        {
            if (dataPtr->protocol == APP_VBR_SERVER) {
                strcat(statProtocolName, " Server");
            }
            else
            {
                strcat(statProtocolName, " Client");
            }
            // Print stats in .stat file using Stat APIs
            if (dataPtr->appStats)
            {
                dataPtr->appStats->Print(
                    node,
                    "Application",
                    statProtocolName,
                    ANY_ADDRESS,
                    dataPtr->sourcePort);
            }
        }
    }
}


void
VbrProcessEvent(Node* node, Message* msg) {

    VbrData* dataPtr = NULL;

    int event;
    AppInfo* appList = node->appData.appPtr;
    int     id;
    int     tcpLocalPort = -1;
    NodeAddress     address = (NodeAddress) -1;
    short appType = APP_GetProtocolType(node,msg);
    BOOL tcpMode = TRUE;

    switch (msg->eventType) {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult* listenResult;
            listenResult = (TransportToAppListenResult*)
                           MESSAGE_ReturnInfo(msg);
            id         = -1;
            tcpLocalPort = listenResult->localPort;
            break;
        }
        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult* openResult;
            openResult = (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);
            id         = -1;
            tcpLocalPort = openResult->localPort;
            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent* dataSent;
            dataSent = (TransportToAppDataSent*) MESSAGE_ReturnInfo(msg);
            id         = dataSent->connectionId;
            break;
        }
        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived* dataReceived;
            dataReceived = (TransportToAppDataReceived*)
                           MESSAGE_ReturnInfo(msg);
            id         = dataReceived->connectionId;
            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult* closeResult;
            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);
            id         = closeResult->connectionId;
            break;
        }

        case MSG_APP_TimerExpired:
        {
            AppTimer* timer;
            timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

            if (timer->connectionId <= 0) {
                tcpMode = FALSE;
                id = timer->sourcePort;
                if (APP_GetProtocolType(node,msg) == APP_VBR_CLIENT) {
                    address = timer->address;
                } else {
                    address = timer->address;
                }
            } else {
                id = timer->connectionId;
            }
            break;
        }
        case MSG_APP_FromTransport:
        {
            UdpToAppRecv* info;
            info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
            tcpMode = FALSE;
            if (APP_GetProtocolType(node,msg) == APP_VBR_CLIENT) {
                id = info->destPort;
                address = GetIPv4Address(info->destAddr);
            } else {
                id = info->sourcePort;
                address = GetIPv4Address(info->sourceAddr);
            }
            break;
        }
        default:
            return;
    }

    for (; appList != NULL; appList = appList->appNext) {
        if (appList->appType == appType) {

            dataPtr = (VbrData*) appList->appDetail;
            if (tcpMode) {
                if (id == -1) {
                    if (APP_GetProtocolType(node,msg) == APP_VBR_CLIENT) {
                        if (dataPtr->sourcePort == tcpLocalPort) {
                            break;
                        }
                    } else {
                        if (dataPtr->connectionId == -1) {
                            break;
                        }
                    }
                } else if (dataPtr->connectionId == id) {
                    break;
                }
            } else {
                if ((dataPtr->clientAddr == address) &&
                    (dataPtr->sourcePort == id)) {

                    break;
                }
            }
            dataPtr = NULL;
        }
    }

    if (tcpMode ||
        (APP_GetProtocolType(node,msg) == APP_VBR_CLIENT))
    {
#ifdef EXATA
        if (dataPtr == NULL)
        {
            return;
        }
#else
        ERROR_Assert(dataPtr != NULL, "Data structure not found");
#endif
    }
    if (dataPtr == NULL)
    {
        Address localAddr;
        Address remoteAddr;

        dataPtr = VbrServerSetDataPtr(node, msg);

        // setting addresses
        SetIPv4AddressInfo(&localAddr, dataPtr->clientAddr);
        SetIPv4AddressInfo(&remoteAddr, dataPtr->serverAddr);

        // Create statistics
        if (node->appData.appStats)
        {
            dataPtr->appStats = new STAT_AppStatistics(
                node,
                "vbrServer",
                STAT_Unicast,
                STAT_AppSenderReceiver,
                "VBR Server");

            dataPtr->appStats->Initialize(
                node,
                localAddr,
                remoteAddr,
                STAT_AppStatistics::GetSessionId(msg),
                dataPtr->uniqueId);
            dataPtr->appStats->SessionStart(node);
        }
    }

#ifdef EXATA
        if (dataPtr == NULL)
        {
            return;
        }
#endif
    event = msg->eventType;
    switch (dataPtr->state) {
        case VBR_SERVERIDLE:
            switch (event) {
                case MSG_APP_FromTransport:
                    dataPtr->state = VBR_SERVERRECEIVESDATA;
                    enterVbrServerReceivesData(node, dataPtr, msg);
                    break;
                default:
                    assert(FALSE);
            }
            break;
        case VBR_CLIENTIDLE:
            switch (event) {
                case MSG_APP_TimerExpired:
                    dataPtr->state = VBR_CLIENTTIMEREXPIRED;
                    enterVbrClientTimerExpired(node, dataPtr, msg);
                    break;
                default:
                    assert(FALSE);
            }
            break;
        case VBR_CLIENTTIMEREXPIRED:
            assert(FALSE);
            break;
        case VBR_SERVERRECEIVESDATA:
            assert(FALSE);
            break;
        default:
            ERROR_ReportError("Illegal transition");
            break;
    }

}

