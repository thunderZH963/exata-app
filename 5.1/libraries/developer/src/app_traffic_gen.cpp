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
#include "app_traffic_gen.h"
#include "trace.h"

#include "ipv6.h"

// Pseudo traffic sender layer
#include "app_trafficSender.h"


#ifdef MILITARY_RADIOS_LIB
#include "mac.h"
#include "tadil_util.h"
#include "network_ip.h"
#endif //MILITARY_RADIOS_LIB

#define TRAFFIC_GEN_DEBUG      0
#define TRAFFIC_GEN_INIT_DEBUG 0
#define LINK16_GATEWAY_DEBUG   0

void TrafficGenPrintTraceXML(Node* node, Message* msg);

// /**
// FUNCTION   :: TrafficGenInitTrace
// LAYER      :: APPLIACTION
// PURPOSE    :: TrafficGen initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

void TrafficGenInitTrace(Node* node, const NodeInput* nodeInput)
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
        "TRACE-TRAFFIC-GEN",
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
                "TRACE-TRAFFIC-GEN should be either \"YES\" or \"NO\".\n");
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
            TRACE_EnableTraceXML(node, TRACE_TRAFFIC_GEN,
                "TRAFFIC-GEN", TrafficGenPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_TRAFFIC_GEN,
                "TRAFFIC-GEN", writeMap);
    }
    writeMap = FALSE;
}



static
TrafficGenServer* TrafficGenServerGetServer(
    Node* node,
    const Address& remoteAddr,
    int sourcePort);

// /**
// FUNCTION::       TrafficGenSendPacket
// LAYER::          Application
// PURPOSE::        Create an packet to send
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway IP interface
//                          that forwards fragment
//      +destAddr:          The IP destination address
//      +data:              The trafficgen header data
//      +payload:           The real packet payload
//      +realPayload:       The actual packet size
//      +sourcePort:        source port number
//      +virtualPayloadSize: virtual payload size
//      +priority:          packet priority
// RETURN:: NULL
// **/
void TrafficGenSendPacket(
    Node* node,
    const Address& srcAddr,
    const Address& destAddr,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    short sourcePort,
    int virtualPayloadSize,
    TosType priority,
    int dataSize,
    Message* origMsg,
    TrafficGenClient* clientPtr)
{
    Message* message = APP_UdpCreateMessage(
        node,
        srcAddr,
        sourcePort,
        destAddr,
        (short) APP_TRAFFIC_GEN_SERVER,
        TRACE_TRAFFIC_GEN,
        priority);

    ERROR_Assert(message, "TrafficGenSendPacket: Fail to"
        "create a packet.");

    APP_AddPayload(
        node,
        message,
        payload,
        realPayloadSize);

    APP_AddVirtualPayload(node, message, virtualPayloadSize);

    if (node->appData.appStats)
    {
        if (origMsg && MESSAGE_ReturnInfo(origMsg, INFO_TYPE_StatsTiming) != NULL)
        {
            // Copy stats timing info if it was found in the original message
            MESSAGE_AddInfo(
                    node,
                    message,
                    sizeof(STAT_Timing),
                    INFO_TYPE_StatsTiming);

            memcpy(
                MESSAGE_ReturnInfo(message, INFO_TYPE_StatsTiming),
                MESSAGE_ReturnInfo(origMsg, INFO_TYPE_StatsTiming),
                sizeof(STAT_Timing));
        }
        else if (clientPtr && clientPtr->stats)
        {
            // Packet was sent from a client
            if (Address_IsMulticastAddress(&clientPtr->remoteAddr))
            {
                clientPtr->stats->AddFragmentSentDataPoints(node,
                                                        dataSize,
                                                        STAT_Multicast);
                clientPtr->stats->AddMessageSentDataPoints(node,
                                                       message,
                                                       0,
                                                       dataSize,
                                                       0,
                                                       STAT_Multicast);
             }
            else
            {
                clientPtr->stats->AddFragmentSentDataPoints(node,
                                                        dataSize,
                                                        STAT_Unicast);
                clientPtr->stats->AddMessageSentDataPoints(node,
                                                       message,
                                                       0,
                                                       dataSize,
                                                       0,
                                                       STAT_Unicast);
            }
        }
    }
    MESSAGE_AddInfo(
            node,
            message,
            sizeof(TrafficGenData),
            INFO_TYPE_SuperAppUDPData);
    TrafficGenData* trafficGenData = (TrafficGenData*)
                                        MESSAGE_ReturnInfo(
                                            message,
                                            INFO_TYPE_SuperAppUDPData);

    ERROR_Assert(trafficGenData, "TrafficGenSendPacket: Fail to "
        "allocate an info field.");

    memcpy(trafficGenData, data, sizeof(TrafficGenData));
    trafficGenData->txTime = node->getNodeTime();

    // Note that in MILITARY_RADIOS lib,
    // don't set destNPGId here as it was already set properly

    if (data->isMdpEnabled)
    {
        APP_UdpSetMdpEnabled(message, data->mdpUniqueId);
    }

    // dns
    AppUdpPacketSendingInfo packetSendingInfo;
    std::string url;
    memset (&packetSendingInfo, 0, sizeof(AppUdpPacketSendingInfo));
    packetSendingInfo.itemSize = dataSize;
    if (clientPtr)
    {
        packetSendingInfo.stats = clientPtr->stats;
        url.append(*clientPtr->serverUrl);
    }
    else
    {
        packetSendingInfo.stats = NULL;
        url.clear();
    }
    packetSendingInfo.fragNo = NO_UDP_FRAG;
    packetSendingInfo.fragSize = 0;
    node->appData.appTrafficSender->appUdpSend(
                                            node,
                                            message,
                                            url,
                                            srcAddr,
                                            APP_TRAFFIC_GEN_CLIENT,
                                            sourcePort,
                                            packetSendingInfo);
}

#ifdef MILITARY_RADIOS_LIB
// /**
// FUNCTION::       TrafficGenServerGetNPGIdForRcvFrag
// LAYER::          Application
// PURPOSE::        Retrieve the NPGId stored in the traffic_gen data
// PARAMETERS::
//      +node:              Node pointer
//      +msg:     Message pointer of the received trafficgen packet
// RETURN:: NULL
// **/
static
unsigned short TrafficGenServerGetNPGIdForRcvFrag(
    Node* node,
    const Message* msg)
{
    ERROR_Assert(msg->eventType == MSG_APP_FromMac,
        "TrafficGenServerGetNPGIdForRcvFrag: "
        "Wrong message type.");

    TrafficGenData* data = (TrafficGenData*)
                                        MESSAGE_ReturnInfo(
                                            msg,
                                            INFO_TYPE_SuperAppUDPData);
    return data->destNPGId;
}

// /**
// FUNCTION::       TrafficGenSendPacketInTadilNet
// LAYER::          Application
// PURPOSE::        Create an packet to send in Tadil network
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway IP interface
//                          that forwards fragment
//      +destNPGId:         The NPG Id of destination tadil network
//      +data:              The trafficgen header data
//      +payload:           The real packet payload
//      +realPayload:       The actual packet size
//      +sourcePort:        source port number
//      +virtualPayloadSize: virtual payload size
// RETURN:: NULL
// **/
void TrafficGenSendPacketInTadilNet(
    Node* node,
    NodeAddress srcAddr,
    unsigned short destNPGId,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    short sourcePort,
    int virtualPayloadSize,
    Message* origMsg,
    TrafficGenClient* clientPtr)
{
    Message* message =  TADIL_AppCreateNewHeaderVirtualData(
                            node,
                            APP_TRAFFIC_GEN_SERVER,
                            payload,
                            realPayloadSize,
                            virtualPayloadSize,
                            srcAddr,
                            sourcePort,
                            ANY_ID,
                            ANY_DEST,
                            destNPGId,
                            TRACE_TRAFFIC_GEN);

    ERROR_Assert(message, "TrafficGenSendPacketInTadilNet: Fail to"
        "create a packet.");

    if (node->appData.appStats)
    {
        if (origMsg && MESSAGE_ReturnInfo(origMsg, INFO_TYPE_StatsTiming) != NULL)
        {
            // Copy stats timing info if it was found in the original message
            MESSAGE_AddInfo(
                    node,
                    message,
                    sizeof(STAT_Timing),
                    INFO_TYPE_StatsTiming);

            memcpy(
                MESSAGE_ReturnInfo(message, INFO_TYPE_StatsTiming),
                MESSAGE_ReturnInfo(origMsg, INFO_TYPE_StatsTiming),
                sizeof(STAT_Timing));
        }
        else if (clientPtr)
        {
            // Packet was sent from a client
            clientPtr->stats->AddFragmentSentDataPoints(node,
                                                        realPayloadSize + virtualPayloadSize,
                                                        STAT_Unicast);
            clientPtr->stats->AddMessageSentDataPoints(node,
                                                       message,
                                                       0,
                                                       realPayloadSize + virtualPayloadSize,
                                                       0,
                                                       STAT_Unicast);
        }
    }

    MESSAGE_AddInfo(
            node,
            message,
            sizeof(TrafficGenData),
            INFO_TYPE_SuperAppUDPData);
    TrafficGenData* trafficGenData = (TrafficGenData*)
                                        MESSAGE_ReturnInfo(
                                            message,
                                            INFO_TYPE_SuperAppUDPData);

    ERROR_Assert(trafficGenData, "TrafficGenSendPacketInTadilNet: Fail to "
        "allocate an info field.");

    memcpy(trafficGenData, data, sizeof(TrafficGenData));
    trafficGenData->txTime = node->getNodeTime();
    MESSAGE_Send(node, message, 0);
}

// /**
// FUNCTION::       TrafficGenGatewaySendFragToLink16
// LAYER::          Application
// PURPOSE::        Gateway calls this function to forward TrafficGen
//                  fragment to Link16 network
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway Link16 interface
//                          that forwards fragment
//      +destNPGId:         Destination NPG Id
//      +data:              The trafficgen header data
//      +payload:           the actual packet pointer
//      +realPayloadSize:   the actual packet size
//      +virtualPayloadSize: virtual payload size
// RETURN:: NULL
// **/
static
void TrafficGenGatewaySendFragToLink16(
    Node* node,
    NodeAddress srcAddr,
    unsigned short destNPGId,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    int virtualPayloadSize,
    Message* originalMsg)
{
    TrafficGenSendPacketInTadilNet(
        node,
        srcAddr,
        destNPGId,
        data,
        payload,
        realPayloadSize,
        data->sourcePort,
        virtualPayloadSize,
        originalMsg);

    if (node->appData.link16Gateway)
    {
        if (node->appData.link16Gateway->statsEnabled)
        {
            Link16GatewayStats* stats =
                &(node->appData.link16Gateway->statistics);
            stats->numBytesToLink16 +=
                (realPayloadSize+virtualPayloadSize);
        }
    }
}

// /**
// FUNCTION::       TrafficGenGatewaySendFragToIp
// LAYER::          Application
// PURPOSE::        Gateway calls this function to forward TrafficGen
//                  fragment to IP network
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway IP interface
//                          that forwards fragment
//      +destAddr:          The IP destination address
//      +data:              The trafficgen header data
//      +fragSize:          Fragment size
// RETURN:: NULL
// **/
static
void TrafficGenGatewaySendFragToIp(
    Node* node,
    const Address& srcAddr,
    const Address& destAddr,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    int virtualPayloadSize,
    Message* origMsg)
{
    TrafficGenSendPacket(
        node,
        srcAddr,
        destAddr,
        data,
        payload,
        realPayloadSize,
        data->sourcePort,
        virtualPayloadSize,
        APP_DEFAULT_TOS,
        0,
        origMsg);

    if (node->appData.link16Gateway)
    {
        if (node->appData.link16Gateway->statsEnabled)
        {
            Link16GatewayStats* stats =
                &(node->appData.link16Gateway->statistics);
            stats->numBytesToIp +=
                (realPayloadSize + virtualPayloadSize);
        }
    }
}

// /**
// FUNCTION::       TrafficGenGatewayForwardToLink16
// LAYER::          Application
// PURPOSE::        Gateway calls this function to forward TrafficGen
//                  fragment to IP network
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway IP interface
//                          that forwards fragment
//      +destAddr:          The IP destination address
//      +msg:               Message containing packet received from the IP network
// RETURN:: NULL
// **/
static
void TrafficGenGatewayForwardToLink16(
    Node* node,
    Address& sourceAddr,
    Address& destAddr,
    Message* msg)
{
    TrafficGenData* data = (TrafficGenData*)
                        MESSAGE_ReturnInfo(msg,
                                        INFO_TYPE_SuperAppUDPData);
    char* packet = MESSAGE_ReturnPacket(msg);
    int realPayloadSize = MESSAGE_ReturnActualPacketSize(msg);
    int virtualPayloadSize = MESSAGE_ReturnVirtualPacketSize(msg);
    char forwardMsgType = data->forwardMsgType;

    TrafficGenServer* serverPtr =
          TrafficGenServerGetServer(
                node,
                sourceAddr,
                data->sourcePort);

    TrafficGenData newData;

    ERROR_Assert(serverPtr, "Traffic-gen: Server must exist "
        "when do link16 forwarding ");

    unsigned short destNPGId;

    Link16GatewayData* link16Gateway = node->appData.link16Gateway;
    if (link16Gateway)
    {
        Link16GatewayForwardEntry* entr =
            link16Gateway->forwardTbHead;
        while (entr)
        {
            BOOL isMulticastAddr = FALSE;
            if (entr->ipNodeAddr.networkType == NETWORK_IPV4)
            {
                isMulticastAddr =
                    NetworkIpIsMulticastAddress(node, entr->ipNodeAddr.interfaceAddr.ipv4);
            }
            else
            {
                // Must be IPV6 here
                //
                // IPv6 multicast addresses are distinguished from unicast addresses
                // by the value of the high-order octet of the addresses:
                // a value of 0xFF (binary 11111111) identifies an address as a multicast
                // address; any other value identifies an address as a unicast address.
                isMulticastAddr = (entr->ipNodeAddr.interfaceAddr.ipv6.s6_addr8[0] == 0xff);
            }

            if (entr->tosType == forwardMsgType &&
                Address_IsSameAddress(&(entr->ipNodeAddr),
                                      isMulticastAddr? &destAddr : &sourceAddr) &&
                entr->appType == APP_TRAFFIC_GEN_CLIENT &&
                (data->destNPGId == (unsigned short)ANY_NPG ||
                 data->destNPGId == entr->NPGId))
            {
                destNPGId = entr->NPGId;
                NodeAddress srcAddr =
                Link16GatewayGetLink16IfaceAddrFromNPG(
                    node,
                    destNPGId);

                if (srcAddr == ANY_ADDRESS)
                {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr, "Link16-IP gateway %u: "
                        "cannot find an link16 interface to the "
                        "destination NPG %u in the gateway",
                        node->nodeId, destNPGId);
                }


                if (serverPtr->forwardSrcPort == -1)
                {
                    serverPtr->forwardSrcPort =
                        node->appData.nextPortNum++;
                }

                if (LINK16_GATEWAY_DEBUG)
                {
                    char currTime[MAX_STRING_LENGTH];
                    TIME_PrintClockInSecond(node->getNodeTime(), currTime);
                    printf("Link16-IP gateway node %d: time %s: "
                           "forward to NPG %d using addr %x\n",
                           node->nodeId, currTime, destNPGId, srcAddr);
                }

                memcpy(&newData, data, sizeof(TrafficGenData));
                newData.sourcePort = serverPtr->forwardSrcPort;
                newData.destNPGId = destNPGId;

                TrafficGenGatewaySendFragToLink16(
                    node,
                    srcAddr,
                    destNPGId,
                    &newData,
                    packet,
                    realPayloadSize,
                    virtualPayloadSize,
                    msg);
            }
            entr = entr->next;
        }
    }
}

// /**
// FUNCTION::       TrafficGenGatewayForwardToIp
// LAYER::          Application
// PURPOSE::        Gateway calls this function to forward TrafficGen
//                  fragment to IP network
// PARAMETERS::
//      +node:              Node pointer
//      +srcAddr:           The address of the gateway IP interface
//                          that forwards fragment
//      +msg:               Message containing the packet received from the Link16 network
// RETURN:: NULL
// **/
static
void TrafficGenGatewayForwardToIp(
    Node* node,
    const Address& sourceAddr,
    Message* msg)
{
    TrafficGenData* data = (TrafficGenData*)
                        MESSAGE_ReturnInfo(msg,
                                        INFO_TYPE_SuperAppUDPData);
    char* packet = MESSAGE_ReturnPacket(msg);
    int realPayloadSize = MESSAGE_ReturnActualPacketSize(msg);
    int virtualPayloadSize = MESSAGE_ReturnVirtualPacketSize(msg);
    char forwardMsgType = data->forwardMsgType;

    unsigned short srcNPGId =
        TrafficGenServerGetNPGIdForRcvFrag(node, msg);
    Address srcAddr;
    char errorMsg[MAX_STRING_LENGTH];

    TrafficGenServer* serverPtr =
          TrafficGenServerGetServer(
                node,
                sourceAddr,
                data->sourcePort);
    ERROR_Assert(serverPtr, "Traffic-gen: Server must exist "
        "when do link16 forwarding ");

    //create a new traffic gen header for forwarding
    TrafficGenData newdata;

    Link16GatewayData* link16Gateway = node->appData.link16Gateway;
    if (link16Gateway)
    {
        Link16GatewayForwardEntry* entr =
            link16Gateway->forwardTbHead;
        for (; entr; entr=entr->next)
        {
            if (entr->tosType == forwardMsgType &&
                entr->NPGId == srcNPGId &&
                entr->appType == APP_TRAFFIC_GEN_CLIENT)
            {
                if (Link16GatewayGetIpIfaceAddrFromDestNodeAddr(
                    node,
                    entr->ipNodeAddr,
                    srcAddr))
                {
                    if (Address_IsSameAddress(&(entr->ipNodeAddr), &srcAddr))
                    {
                        continue;
                    }
                    if (serverPtr->forwardSrcPort == -1)
                    {
                        serverPtr->forwardSrcPort =
                            node->appData.nextPortNum++;
                    }

                    //copy old trafficgen header into new header
                    memcpy(&newdata, data, sizeof(TrafficGenData));

                    //change the source port
                    newdata.sourcePort = serverPtr->forwardSrcPort;

                    TrafficGenGatewaySendFragToIp(
                        node,
                        srcAddr,
                        entr->ipNodeAddr,
                        &newdata,
                        packet,
                        realPayloadSize,
                        virtualPayloadSize,
                        msg);
                }
                else
                {
                    char addrStr[MAX_STRING_LENGTH];
                    if (entr->ipNodeAddr.networkType == NETWORK_IPV4)
                    {
                        IO_ConvertIpAddressToString(GetIPv4Address(entr->ipNodeAddr),
                                addrStr);
                    }
                    else
                    {
                        IO_ConvertIpAddressToString(&(entr->ipNodeAddr), addrStr);
                    }
                    sprintf(errorMsg, "Warning: Node: %u "
                        "Link16 gateway forward error: cannot "
                        "find an outgoing IP interface to node %s ",
                        node->nodeId, addrStr);
                    ERROR_ReportWarning(errorMsg);
                }

            }
        }
    }
}
#endif // MILITARY_RADIOS_LIB

//-----------------------------------------------
// NAME:        TrafficGenClientPrintUsageAndQuit
// PURPOSE:     print usage and quit
// PARAMETERS:  none
// RETRUN:      none
//-----------------------------------------------
static
void TrafficGenClientPrintUsageAndQuit(void)
{
    printf("TRAFFIC-GEN: Incorrect parameters.\n");
    printf("Usage: "TRAFFIC_GEN_USAGE);
    exit(0);
}

#ifdef MILITARY_RADIOS_LIB
//-----------------------------------------------
// NAME:        TrafficGenClientPrintNPGUsageAndQuit
// PURPOSE:     print usage and quit
// PARAMETERS:  none
// RETRUN:      none
//-----------------------------------------------
static
void TrafficGenClientPrintNPGUsageAndQuit(void)
{
    printf("TRAFFIC-GEN: Incorrect parameters.\n");
    printf("Usage: "TRAFFIC_GEN_NPG_USAGE);
    exit(0);
}
#endif

//---------------------------------------------------------
// NAME:        TrafficGenClientRequestNewConnectionSession
// PURPOSE:     print usage and quit
// PARAMETERS:  node - pointer to the node
//              clientPtr - pointer to the client
//              sendDelay - required delay
// RETRUN:      none
//---------------------------------------------------------
static
void TrafficGenClientRequestNewConnectionSession(
    Node* node,
    TrafficGenClient* clientPtr,
    clocktype sendDelay)
{
    AppQosToNetworkSend* info = NULL;
    Message* setupMsg = NULL;

    if (clientPtr->localAddr.networkType == NETWORK_IPV6 ||
            clientPtr->remoteAddr.networkType == NETWORK_IPV6)
    {
        ERROR_ReportError(
            "TrafficGenClientRequestConnectionSession "
            "QoS is not supported in Traffic-Gen IPv6.");
    }

    // Schedule a message for Q-OSPF to inform origination
    // of a new connection session of a TRAFFIC-GEN application.
    // Info field of this message contains Qos requirements and
    // identification of new connection.

    setupMsg = MESSAGE_Alloc(node,
                   NETWORK_LAYER,
                   ROUTING_PROTOCOL_OSPFv2,
                   MSG_ROUTING_QospfSetNewConnection);

    MESSAGE_InfoAlloc(node, setupMsg, sizeof(AppQosToNetworkSend));

    info = (AppQosToNetworkSend*) MESSAGE_ReturnInfo(setupMsg);

    info->clientType = APP_TRAFFIC_GEN_CLIENT;

    info->sourcePort = (short) clientPtr->sourcePort;
    info->destPort = APP_TRAFFIC_GEN_SERVER;
    info->sourceAddress = GetIPv4Address(clientPtr->localAddr);
    info->destAddress = GetIPv4Address(clientPtr->remoteAddr);

    info->priority = clientPtr->qosConstraints.priority;
    info->bandwidthRequirement = clientPtr->qosConstraints.bandwidth;
    info->delayRequirement = clientPtr->qosConstraints.delay;

    if (TRAFFIC_GEN_INIT_DEBUG)
    {
        char srcAddr[MAX_STRING_LENGTH];
        char destAddr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(
                GetIPv4Address(clientPtr->localAddr), srcAddr);
        IO_ConvertIpAddressToString(
                GetIPv4Address(clientPtr->remoteAddr), destAddr);

        printf("\n\n"
               "Connection request going from .......\n"
               "....Source Addr %s Dest Addr %s\n"
               "....Source port %d Dest port %d\n\n",
               srcAddr, destAddr,
               clientPtr->sourcePort, APP_TRAFFIC_GEN_SERVER);
    }
    MESSAGE_Send(node, setupMsg, sendDelay);
}


//-------------------------------------------------------------------
// NAME:        TrafficGenClientGetClient.
// PURPOSE:     search for a traffic gen client data structure.
// PARAMETERS:  node - pointer to the node.
//              sourcePort - connection Id of the traffic gen client.
// RETURN:      the pointer to the traffic gen client data structure.
//              If nothing found, assertion false occures giving
//              a proper error message.
//-------------------------------------------------------------------
static
TrafficGenClient* TrafficGenClientGetClient(
    Node* node,
    int sourcePort)
{
    AppInfo* appList = NULL;
    TrafficGenClient* clientPtr = NULL;
    char errorMsg[MAX_STRING_LENGTH];

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_GEN_CLIENT)
        {
            clientPtr = (TrafficGenClient*) appList->appDetail;

            if (clientPtr->sourcePort == sourcePort)
            {
                return clientPtr;
            }
        }
    }

    // Not found
    sprintf(errorMsg,
        "TRAFFIC-GEN Client: Node %d cannot find traffic gen client\n",
        node->nodeId);
    ERROR_Assert(FALSE, errorMsg);

    // Though unreachable code. But kept to eliminate warning msg.
    return NULL;
}

TrafficGenClient* TrafficGenClientGetClient(
    Node* node,
    NodeAddress destAddress)
{
    AppInfo* appList = NULL;
    TrafficGenClient* clientPtr = NULL;
    char errorMsg[MAX_STRING_LENGTH];

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_GEN_CLIENT)
        {
            clientPtr = (TrafficGenClient*) appList->appDetail;

            if (GetIPv4Address(clientPtr->remoteAddr) == destAddress)
            {
                return clientPtr;
            }
        }
    }

    // Not found
    sprintf(errorMsg,
        "TRAFFIC-GEN Client: Node %d cannot find traffic gen client\n",
        node->nodeId);
    ERROR_Assert(FALSE, errorMsg);

    // Though unreachable code. But kept to eliminate warning msg.
    return NULL;
}


//----------------------------------------------------------------------
// NAME:        TrafficGenClientNewClient.
// PURPOSE:     create a new traffic gen client data structure, place it
//              at the beginning of the application list.
// PARAMETERS:  node - pointer to the node.
// RETURN:      pointer to the created traffic gen client data structure,
//              NULL if no data structure allocated.
//----------------------------------------------------------------------
static
TrafficGenClient* TrafficGenClientNewClient(Node* node)
{
    TrafficGenClient* clientPtr = (TrafficGenClient*)
            MEM_malloc(sizeof(TrafficGenClient));

    // Initialize the client
    memset(&clientPtr->localAddr, 0, sizeof(Address));
    memset(&clientPtr->remoteAddr, 0, sizeof(Address));
    clientPtr->startTm = 0;
    clientPtr->endTm = 0;

    clientPtr->dataSizeDistribution.setDistributionNull();
    clientPtr->intervalDistribution.setDistributionNull();

    clientPtr->genProb = 0.0;

    DlbReset(&clientPtr->dlb, 0, 0, 0, node->getNodeTime());

    clientPtr->isDlbDrp = FALSE;
    clientPtr->delayedData = 0;
    clientPtr->delayedIntv = 0;
    clientPtr->dlbDrp = 0;
    clientPtr->trfType = TRAFFIC_GEN_TRF_TYPE_RND;
    clientPtr->lastSndTm = node->getNodeTime();
    clientPtr->totByteSent = 0;
    clientPtr->totDataSent = 0;

    MsTmWinInit(&clientPtr->sndThru,
                (clocktype) TRAFFIC_GEN_CLIENT_SSIZE,
                TRAFFIC_GEN_CLIENT_NSLOT,
                TRAFFIC_GEN_CLIENT_WEIGHT,
                node->getNodeTime());

    clientPtr->seqNo = 0;
    clientPtr->fragNo = 0;
    clientPtr->totFrag = 0;
    clientPtr->sourcePort = node->appData.nextPortNum++;
    clientPtr->isClosed = FALSE;

    // Quality of service related variables.
    clientPtr->isSessionAdmitted = FALSE;
    clientPtr->isQosEnabled = FALSE;
    clientPtr->qosConstraints.bandwidth = 0;
    clientPtr->qosConstraints.delay = 0;
    clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
    clientPtr->isRetryRequired = FALSE;
    clientPtr->connectionRetryInterval = 0;
    clientPtr->fragmentationSize = APP_MAX_DATA_SIZE;
    clientPtr->applicationName = NULL;
    clientPtr->uniqueId = node->appData.uniqueId++;
    clientPtr->stats = NULL;

    // dynamic address
    clientPtr->destNodeId = ANY_NODEID;
    clientPtr->clientInterfaceIndex = ANY_INTERFACE;
    clientPtr->destInterfaceIndex = ANY_INTERFACE;
    clientPtr->serverUrl = new std::string();
    clientPtr->serverUrl->clear();

    APP_RegisterNewApp(node, APP_TRAFFIC_GEN_CLIENT, clientPtr);

    return clientPtr;
}


//---------------------------------------------------------
// NAME:        TrafficGenClientSkipToken.
// PURPOSE:     skip the first n tokens.
// PARAMETERS:  token - pointer to the input string,
//              tokenSep - pointer to the token separators,
//              skip - number of skips.
// RETRUN:      pointer to the next token position.
//---------------------------------------------------------
static
char* TrafficGenClientSkipToken(char* token, const char* tokenSep, int skip)
{
    int idx;

    if (token == NULL)
    {
        return NULL;
    }

    // Eliminate preceding space
    idx = (int)strspn(token, tokenSep);
    token = (idx < (signed int)strlen(token)) ? token + idx : NULL;

    while (skip > 0 && token != NULL)
    {
        token = strpbrk(token, tokenSep);

        if (token != NULL)
        {
            idx = (int)strspn(token, tokenSep);
            token = (idx < (signed int)strlen(token)) ? token + idx : NULL;
        }
        skip--;
    }
    return token;
}


//-------------------------------------------------------------------------
// NAME:        TrafficGenClientScheduleNextPkt.
// PURPOSE:     Schedule next packet that will be sent.  If next packet
//              won't arrive until the finish deadline, schedule a close.
// PARAMETERS:  node - pointer to the node,
//              clientPtr - pointer to traffic gen client data structure.
// RETRUN:      none.
//--------------------------------------------------------------------------
static
void TrafficGenClientScheduleNextPkt(
    Node* node,
    TrafficGenClient* clientPtr,
    clocktype interval)
{
    AppTimer* timer = NULL;

    Message* timerMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_TRAFFIC_GEN_CLIENT,
                            MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

    MESSAGE_Send(node, timerMsg, interval);
}


//---------------------------------------------------------
// NAME:        TrafficGenClientSendData
// PURPOSE:     send out application data as scheduled
// PARAMETERS:  node - pointer to the node
//              clientPtr - pointer to the client
// RETRUN:      none
//---------------------------------------------------------
static
void TrafficGenClientSendData(
    Node* node,
    TrafficGenClient* clientPtr)
{
    BOOL isGen = FALSE;
    Int32 fragLen;
    Int32 dataLen = 0;
    clocktype dataIntv = 0;
    clocktype dlbDelay;
    TrafficGenData data;
    Int32 maxFragmentSize;

    //init the TrafficGenData
    memset(&data, 0, sizeof(data));

    dlbDelay = 0;

    if (clientPtr->delayedData)
    {
        isGen = TRUE;
        dataLen = clientPtr->delayedData;
        dataIntv = clientPtr->delayedIntv;
    }
    else
    {
        switch (clientPtr->trfType)
        {
            case TRAFFIC_GEN_TRF_TYPE_RND :
            {
                isGen = FALSE;

                // Determine whether or not generate data
                if (clientPtr->probabilityDistribution.getRandomNumber() < clientPtr->genProb) {

                    isGen = TRUE;
                    dataLen = clientPtr->dataSizeDistribution.getRandomNumber();
                    dataIntv = clientPtr->intervalDistribution.getRandomNumber();
                }
                break;
            }
            default :
            {
                ERROR_Assert(FALSE, "control reached an"
                    " unreachable block");
                break;
            }
        } // switch (clientPtr->trfType)
    } // end else

    if (isGen)
    {
        // Refine the data interval
        if (dataIntv == 0)
        {
            dataIntv = 1 * NANO_SECOND;
        }

        // Check with DLB
        dlbDelay = DlbUpdate(&clientPtr->dlb, dataLen, node->getNodeTime());

        if (dlbDelay)
        {
            isGen = FALSE;

            if (clientPtr->isDlbDrp)
            {
                clientPtr->delayedData = 0;
                clientPtr->delayedIntv = 0;
                clientPtr->dlbDrp++;
            }
            else
            {
                clientPtr->delayedData = dataLen;
                clientPtr->delayedIntv = dataIntv;
                dataIntv = dlbDelay;
            }
        }
        else
        {
            clientPtr->delayedData = 0;
            clientPtr->delayedIntv = 0;
        }

        if (clientPtr->isClosed == FALSE
            && (clientPtr->endTm != 0
                && (node->getNodeTime() + dataIntv > clientPtr->endTm)))
        {
            clientPtr->isClosed = TRUE;
            if (node->appData.appStats)
            {
                if (Address_IsMulticastAddress(&clientPtr->remoteAddr))
                {
                    clientPtr->stats->SessionFinish(node, STAT_Multicast);
                }
                else
                {
                    clientPtr->stats->SessionFinish(node, STAT_Unicast);
                }
            }
            data.type = 'c';
        }
        else
        {
            data.type = 'd';
        }

        if (isGen)
        {
            // Refine the data length
            //dataLen = ((unsigned) dataLen < sizeof (TrafficGenData)) ?
            //    sizeof (TrafficGenData) : dataLen;

            // Statistics update

            if (clientPtr->totByteSent == 0 && node->appData.appStats &&
                clientPtr->stats)
            {
                if (clientPtr->remoteAddr.networkType != NETWORK_INVALID 
                    && Address_IsMulticastAddress(&clientPtr->remoteAddr))
                {
                    clientPtr->stats->SessionStart(
                                                    node,
                                                    STAT_Multicast);
                }
                else
                {
                    clientPtr->stats->SessionStart(
                                                    node,
                                                    STAT_Unicast);
                }
            }
            clientPtr->totByteSent += dataLen;

            ERROR_Assert(
                clientPtr->totByteSent < TRAFFIC_GEN_MAX_DATABYTE_SEND,
                "Total bytes sent exceed maximum limit, current packet"
                " size should be reduced for proper statistics");

            clientPtr->totDataSent++;
            clientPtr->lastSndTm = node->getNodeTime();
            maxFragmentSize = clientPtr->fragmentationSize;

            MsTmWinNewData(&clientPtr->sndThru,
                           dataLen * 8.0,
                           node->getNodeTime());

            if (TRAFFIC_GEN_DEBUG)
            {
                FILE *fp;
                char fileName[MAX_STRING_LENGTH];
                char dataBuf[MAX_STRING_LENGTH];
                clocktype currentTime = node->getNodeTime();

                if (clientPtr->localAddr.networkType == NETWORK_IPV4)
                {
                    sprintf(fileName, "ClientGenFile_%d_%d_%d",
                        GetIPv4Address(clientPtr->localAddr),
                        GetIPv4Address(clientPtr->remoteAddr),
                        clientPtr->sourcePort);
                }
                else if (clientPtr->localAddr.networkType == NETWORK_IPV6)
                {
                    char localAddrStr[MAX_STRING_LENGTH];
                    char remoteAddrStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(&(clientPtr->localAddr),
                        localAddrStr);
                    IO_ConvertIpAddressToString(&(clientPtr->remoteAddr),
                        remoteAddrStr);
                    sprintf(fileName, "ClientGenFile_%s_%s_%d",
                        localAddrStr,
                        remoteAddrStr,
                        clientPtr->sourcePort);
                }

                fp = fopen(fileName, "a");

                if (fp)
                {
                    sprintf(dataBuf, "%.6f\t%d\t%.6f\t%.6f\n",
                        (currentTime / (double)SECOND),
                        clientPtr->sourcePort,
                        MsTmWinAvg(&clientPtr->sndThru, currentTime),
                        MsTmWinTotalAvg(&clientPtr->sndThru, currentTime));

                    if (fwrite(dataBuf, strlen(dataBuf), 1, fp)!= 1)
                    {
                       ERROR_ReportWarning("Unable to write in file \n");
                    }
                    fclose(fp);
                }

            }

            // Set up data
            data.sourcePort = clientPtr->sourcePort;
            data.txTime     = node->getNodeTime();
            data.seqNo      = clientPtr->seqNo++;
            data.totFrag    =
                (Int32) ceil((double)dataLen / (double)maxFragmentSize);
#ifdef MILITARY_RADIOS_LIB
            data.forwardMsgType = clientPtr->forwardMsgType;
            data.destNPGId = clientPtr->destNPGId;
#endif // MILITARY_RADIOS_LIB
            data.fragNo     = 0;

            data.isMdpEnabled = clientPtr->isMdpEnabled;
            data.mdpUniqueId = clientPtr->mdpUniqueId;

            // Fragmentation
            while (dataLen > 0)
            {
                fragLen = (dataLen > maxFragmentSize) ?
                          maxFragmentSize : dataLen;

                if (dataLen > fragLen
                    && dataLen - fragLen < (signed) sizeof(TrafficGenData))
                {
                    fragLen = dataLen - sizeof(TrafficGenData);
                }

#ifdef MILITARY_RADIOS_LIB
                int interfaceIndex =
                MAPPING_GetInterfaceIndexFromInterfaceAddress(
                    node, clientPtr->localAddr);

                if ((node->macData[interfaceIndex]->macProtocol
                    == MAC_PROTOCOL_TADIL_LINK16) ||
                    (node->macData[interfaceIndex]->macProtocol
                    == MAC_PROTOCOL_TADIL_LINK11))
                {
                    ERROR_Assert (
                        (clientPtr->localAddr.networkType == NETWORK_IPV4 &&
                        clientPtr->remoteAddr.networkType == NETWORK_IPV4),
                        "TrafficGenClientSendData: Local and remote addresses "
                        "must be IPv4 addresses in Tadil network.");

                    TrafficGenSendPacketInTadilNet(
                        node,
                        GetIPv4Address(clientPtr->localAddr),
                        clientPtr->destNPGId,
                        &data,
                        NULL,
                        0,
                        (short)clientPtr->sourcePort,
                        fragLen,
                        NULL,
                        clientPtr);
                }
                else
                {
#endif // MILITARY_RADIOS_LIB
                    // dns
                    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
                    {
                        ERROR_Assert(
                        (clientPtr->remoteAddr.networkType == NETWORK_IPV6 &&
                        clientPtr->localAddr.networkType == NETWORK_IPV6) ||
                        (clientPtr->remoteAddr.networkType == NETWORK_IPV4 &&
                        clientPtr->localAddr.networkType == NETWORK_IPV4),
                        "TrafficGenClientSendData: "
                        "Wrong network protocol configuration.");
                    }

                    TrafficGenSendPacket(
                        node,
                        clientPtr->localAddr,
                        clientPtr->remoteAddr,
                        &data,
                        NULL,
                        0,
                        (short) clientPtr->sourcePort,
                        fragLen,
                        (TosType) clientPtr->qosConstraints.priority,
                        dataLen,
                        NULL,
                        clientPtr);
#ifdef MILITARY_RADIOS_LIB
                }
#endif // MILITARY_RADIOS_LIB
                dataLen -= fragLen;
                data.fragNo++;
                clientPtr->fragNo++;
            } // end while (dataLen > 0)
        } // end  if (isGen)
    } // end  if (isGen)

    if (!clientPtr->isClosed)
    {
        TrafficGenClientScheduleNextPkt(node, clientPtr, dataIntv);
    }
}


//----------------------------------------------------------------------
// NAME:        TrafficGenClientLayerRoutine.
// PURPOSE:     Models the behaviour of Traffic Gen Client on receiving
//              message encapsulated in msg.
// PARAMETERS:  node - pointer to the node which received the message.
//              msg - message received by the layer
// RETURN:      none.
//----------------------------------------------------------------------
void TrafficGenClientLayerRoutine(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    TrafficGenClient* clientPtr = NULL;
    AppTimer* timer = NULL;

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            timer = (AppTimer*)MESSAGE_ReturnInfo(msg);
            clientPtr = TrafficGenClientGetClient(node, timer->sourcePort);
            ERROR_Assert(clientPtr, "TrafficGenClientLayerRoutine: "
                "clientPtr is null!\n");

            switch (timer->type)
            {
                case APP_TIMER_SEND_PKT:
                {
                    if (AppTrafficGenClientGetSessionAddressState(
                            node,
                            clientPtr) == ADDRESS_FOUND)
                    {
                        TrafficGenClientSendData(node, clientPtr);
                    }
                    else
                    {
                        clientPtr->startTm = 0;
                        clientPtr->endTm = 0;
                        clientPtr->isClosed = TRUE;
                    }
                    break;
                }
                default:
                {
                   ERROR_Assert(FALSE, "Unknown timer type");
                   break;
                }
            }
            break;
        }
        case MSG_APP_SessionStatus:
        {
            NetworkToAppQosConnectionStatus* info = NULL;

            info = (NetworkToAppQosConnectionStatus*)
                    MESSAGE_ReturnInfo(msg);

            clientPtr = TrafficGenClientGetClient(node, info->sourcePort);

            if (info->isSessionAdmitted)
            {
                // Session admitted. Modify start time and end time of
                // this session and schedule to send first packet.
                clientPtr->isSessionAdmitted = TRUE;

                clientPtr->endTm = (node->getNodeTime() +
                    (clientPtr->endTm - clientPtr->startTm));

                clientPtr->startTm = node->getNodeTime();

                TrafficGenClientScheduleNextPkt(node, clientPtr, 0);
            }
            else if (clientPtr->isRetryRequired)
            {
                // Retry to establish the connection.
                TrafficGenClientRequestNewConnectionSession(
                    node,
                    clientPtr,
                    clientPtr->connectionRetryInterval);
            }
            break;
        }
        default:
        {
            ctoa(node->getNodeTime(), buf);

            printf("TRAFFIC-GEN Client: At time %s, node %d "
                "received message of unknown type %d.\n",
                buf, node->nodeId, msg->eventType);

#ifndef EXATA
            ERROR_Assert(FALSE, "Code has reached an "
                "unrechable block");
#endif
        }
    } // end switch (msg->eventType)
    MESSAGE_Free(node, msg);
}


//----------------------------------------------------
// NAME:        TrafficGenClientInit.
// PURPOSE:     Initialize a TrafficGenClient session.
// PARAMETERS:  node - pointer to the node,
//              inputString - input string.
//              localAddr - client address.
//              remoteAddr - server address.
//              destType - flag to indicate destination type.
//              appName - application alias name.
//              destString, -  destination string
//              isMdpEnabled - true if MDP is enabled by user.
//              isProfileNameSet - true if profile name is provided by user.
//              profileName - mdp profile name.
//              uniqueId - mdp session unique id.
//              nodeInput - nodeInput for config file.
// RETURN:      NONE
//----------------------------------------------------
#define TOKENSEP    " ,\t"
void TrafficGenClientInit(
    Node* node,
    char* inputString,
    const Address&     localAddr,
    const Address&     remoteAddr,
    DestinationType destType,
    char* appName,
    char* destString,
    BOOL isMdpEnabled,
    BOOL isProfileNameSet,
    char* profileName,
    Int32 uniqueId,
    const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    TrafficGenClient* clientPtr = NULL;
    char* tokenStr = NULL;
    int nToken;
    RandomDistribution<clocktype> startEndTimeDistribution;
    Int32 bucketSize;
    Int32 tokenRate;
    Int32 peakRate;

    char delayStr[MAX_STRING_LENGTH];

    // dns
    // if destination is in form of URL then remote address is not valid at
    // initialization
    if (remoteAddr.networkType != NETWORK_INVALID)
    {
        if (!((localAddr.networkType == NETWORK_IPV6 &&
            remoteAddr.networkType == NETWORK_IPV6) ||
            (localAddr.networkType == NETWORK_IPV4 &&
            remoteAddr.networkType == NETWORK_IPV4)))
        {
            ERROR_ReportError("TrafficGen Initialization: "
            "Source and destination addresses must be the same network type!");
        }
    }
    // Create a new client
    clientPtr = TrafficGenClientNewClient(node);

    // Assign local and remote address.
    memcpy(&(clientPtr->localAddr), &localAddr, sizeof(Address));
    memcpy(&(clientPtr->remoteAddr), &remoteAddr, sizeof(Address));

#ifdef MILITARY_RADIOS_LIB
    // dns
    // if destination is in form of URL then remote address is not valid at
    // initialization. skipped here for URL case. This will be done when URL
    // is resolved
    if (remoteAddr.networkType != NETWORK_INVALID)
    {
        if (remoteAddr.networkType == NETWORK_IPV4 &&
            GetIPv4Address(remoteAddr) == ANY_DEST)
        {
            BOOL tadilIfaceFound = FALSE;
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if ((node->macData[i]->macProtocol == MAC_PROTOCOL_TADIL_LINK16)||
                    (node->macData[i]->macProtocol == MAC_PROTOCOL_TADIL_LINK11) )
                {
                    tadilIfaceFound = TRUE;
                    NodeAddress tadilIfaceAddress =
                        NetworkIpGetInterfaceAddress(node, i);
                    SetIPv4AddressInfo(
                        &(clientPtr->localAddr),
                        tadilIfaceAddress);
                    break;
                }
            }
            if (!tadilIfaceFound)
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Traffic-Gen: "
                    "Source must have a Link16 interface "
                    "if the destination is 255.255.255.255.\n");
                ERROR_ReportError(errorStr);
            }
        }
        else if (destType == DEST_TYPE_BROADCAST)
        {
            char errorStr[MAX_STRING_LENGTH];
            sprintf(errorStr, "Traffic-Gen: "
                "Destination cannot be IPv6 broadcast address \n");
            ERROR_ReportError(errorStr);
        }
        else
        {
            BOOL ipIfaceFound = FALSE;
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if ((node->macData[i]->macProtocol
                    != MAC_PROTOCOL_TADIL_LINK16) &&
                    (node->macData[i]->macProtocol
                    != MAC_PROTOCOL_TADIL_LINK11) )
                {
                    ipIfaceFound = TRUE;
                    Address ipIfaceAddr =
                        MAPPING_GetInterfaceAddressForInterface(
                               node,
                               node->nodeId,
                               remoteAddr.networkType,
                               i);
                    memcpy(&(clientPtr->localAddr),
                            &ipIfaceAddr, sizeof(Address));
                    break;
                }
            }
            if (!ipIfaceFound)
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Traffic-Gen: "
                    "Source must have an IP interface "
                    "if the destination is not 255.255.255.255.\n");
                ERROR_ReportError(errorStr);
            }

        }
        int interfaceIndex =
            MAPPING_GetInterfaceIndexFromInterfaceAddress(
                    node, clientPtr->localAddr);
        if (interfaceIndex == INVALID_MAPPING)
        {
            ERROR_ReportError("Traffic-gen: source address "
                "does not have a valid interface associated with it.");
        }
    }

#else //  MILITARY_RADIOS_LIB
    ERROR_Assert(destType != DEST_TYPE_BROADCAST,
                 //clientPtr->remoteAddr != ANY_DEST,
            "TRAFFIC-GEN does not support broadcast flow");
#endif //  MILITARY_RADIOS_LIB

    // Skip client properties
    tokenStr = inputString;
    tokenStr = TrafficGenClientSkipToken(
                   tokenStr, TOKENSEP, TRAFFIC_GEN_SKIP_SRC_AND_DEST);

    // Initialize each distribution with a different seed for independence.
    startEndTimeDistribution.setSeed(node->globalSeed,
                                     node->nodeId,
                                     APP_TRAFFIC_GEN_CLIENT,
                                     1);
    clientPtr->dataSizeDistribution.setSeed(node->globalSeed,
                                            node->nodeId,
                                            APP_TRAFFIC_GEN_CLIENT,
                                            2);
    clientPtr->intervalDistribution.setSeed(node->globalSeed,
                                            node->nodeId,
                                            APP_TRAFFIC_GEN_CLIENT,
                                            3);
    clientPtr->probabilityDistribution.setSeed(node->globalSeed,
                                               node->nodeId,
                                               APP_TRAFFIC_GEN_CLIENT,
                                               4);
    clientPtr->probabilityDistribution.setDistributionUniform(0.0, 1.0);

    nToken = startEndTimeDistribution.setDistribution(tokenStr,
                                                      "TrafficGen",
                                                      RANDOM_CLOCKTYPE);
    clientPtr->startTm = startEndTimeDistribution.getRandomNumber();

    tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

    nToken = startEndTimeDistribution.setDistribution(tokenStr,
                                                      "TrafficGen",
                                                      RANDOM_CLOCKTYPE);
    clientPtr->endTm = clientPtr->startTm
                       + startEndTimeDistribution.getRandomNumber();

    tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (tokenStr == NULL)
    {
        TrafficGenClientPrintUsageAndQuit();
    }
    nToken = sscanf(tokenStr, "%s", buf);

    if (nToken != 1)
    {
        TrafficGenClientPrintUsageAndQuit();
    }

    tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (strcmp(buf, "RND") == 0)
    {
        // Random distribution traffic
        clientPtr->trfType = TRAFFIC_GEN_TRF_TYPE_RND;

        nToken = clientPtr->dataSizeDistribution.setDistribution(tokenStr,
                                                                 "TrafficGen",
                                                                 RANDOM_INT);
        tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
        nToken = clientPtr->intervalDistribution.setDistribution(tokenStr,
                                                                 "TrafficGen",
                                                                 RANDOM_CLOCKTYPE);

        tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

        if (tokenStr == NULL)
        {
            TrafficGenClientPrintUsageAndQuit();
        }
        nToken = sscanf(tokenStr, "%lf", &clientPtr->genProb);

        if (nToken != 1)
        {
            TrafficGenClientPrintUsageAndQuit();
        }
        tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
    }
    else if (strcmp(buf, "TRC") == 0)
    {
        ERROR_ReportError("TRAFFIC-GEN : Unable to send "
            "traffics from any trace file\n");
    }
    else
    {
        TrafficGenClientPrintUsageAndQuit();
    }

    if (tokenStr == NULL)
    {
        TrafficGenClientPrintUsageAndQuit();
    }

    nToken = sscanf(tokenStr, "%s", buf);

    if (nToken != 1)
    {
        TrafficGenClientPrintUsageAndQuit();
    }

    tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (strcmp(buf, "NOLB") == 0)
    {
        // No shaper
        DlbReset(&clientPtr->dlb, 0, 0, 0, node->getNodeTime());
    }
    else
    {
        if (strcmp(buf, "LB") == 0)
        {
            // Shaper with LB
            if (tokenStr == NULL)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            nToken = sscanf(tokenStr, "%d %d", &bucketSize, &tokenRate);

            if (nToken != 2)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            tokenStr = TrafficGenClientSkipToken(
                           tokenStr, TOKENSEP, nToken);

            DlbReset(&clientPtr->dlb,
                     bucketSize,
                     tokenRate,
                     0,
                     node->getNodeTime());

        }
        else if (strcmp(buf, "DLB") == 0)
        {
            // Shaper with DLB
            if (tokenStr == NULL)
            {
                TrafficGenClientPrintUsageAndQuit();
            }
            nToken = sscanf(tokenStr, "%d %d %d",
                         &bucketSize, &tokenRate, &peakRate);
            if (nToken != 3)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            tokenStr = TrafficGenClientSkipToken(
                           tokenStr, TOKENSEP, nToken);

            DlbReset(&clientPtr->dlb,
                     bucketSize,
                     tokenRate,
                     peakRate,
                     node->getNodeTime());
        }
        else
        {
            TrafficGenClientPrintUsageAndQuit();
        }

        if (tokenStr == NULL)
        {
            TrafficGenClientPrintUsageAndQuit();
        }

        nToken = sscanf(tokenStr, "%s", buf);

        if (nToken != 1)
        {
            TrafficGenClientPrintUsageAndQuit();
        }

        tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

        if (strcmp(buf, "DROP") == 0)
        {
            clientPtr->isDlbDrp = TRUE;
        }
        else if (strcmp(buf, "DELAY") == 0)
        {
            clientPtr->isDlbDrp = FALSE;
        }
        else
        {
            TrafficGenClientPrintUsageAndQuit();
        }
    }


    // Add the new parameter <npg id> here
#ifdef MILITARY_RADIOS_LIB
    int numTokens = 0;
    clientPtr->forwardMsgType = LINK16_GATEWAY_TOS1;
    clientPtr->destNPGId = (unsigned short)ANY_NPG;
    while (tokenStr != NULL)
    {
        if (numTokens >= 4)
        {
            break;
        }
        nToken = sscanf(tokenStr, "%s", buf);
        if (nToken != 1)
        {
            TrafficGenClientPrintNPGUsageAndQuit();
        }

        if (strcmp(buf, "ForwardMsgType") == 0)
        {
            clientPtr->forwardMsgType = LINK16_GATEWAY_TOS3;
            tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
            numTokens++;
            nToken = sscanf(tokenStr, "%s", buf);
            if (nToken != 1)
            {
                ERROR_ReportError("Traffic_Gen forward message type configuration: "
                        "ForwardMsgType TOS1|TOS2|TOS3|TOS4|TOS5 \n");
            }

            if (strcmp(buf, "TOS1") == 0)
            {
                clientPtr->forwardMsgType = LINK16_GATEWAY_TOS1;
            }
            else if (strcmp(buf, "TOS2") == 0)
            {
                clientPtr->forwardMsgType = LINK16_GATEWAY_TOS2;
            }
            else if (strcmp(buf, "TOS3") == 0)
            {
                clientPtr->forwardMsgType = LINK16_GATEWAY_TOS3;
            }
            else if (strcmp(buf, "TOS4") == 0)
            {
                clientPtr->forwardMsgType = LINK16_GATEWAY_TOS4;
            }
            else if (strcmp(buf, "TOS5") == 0)
            {
                clientPtr->forwardMsgType = LINK16_GATEWAY_TOS5;
            }
            else
            {
                ERROR_ReportError("Traffic_Gen forward message type configuration: "
                        "ForwardMsgType TOS1|TOS2|TOS3|TOS4|TOS5 \n");
            }
            tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
            numTokens++;
        }
        else if (strcmp(buf, "NPG") == 0)
        {
            tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
            numTokens++;
            if (tokenStr != NULL)
            {
                nToken = sscanf(tokenStr, "%s", buf);
                if (nToken != 1)
                {
                    TrafficGenClientPrintNPGUsageAndQuit();
                }
                tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
                numTokens++;
            }

            if (strcmp(buf, "0") != 0)
            {
                unsigned short destNPGId;
                if (!(destNPGId = atoi(buf)) &&
                   destNPGId == (unsigned short)ANY_NPG)
                {
                    printf("TRAFFIC-GEN: Destination NPGId "
                            "is INVALID.\n");
                    TrafficGenClientPrintNPGUsageAndQuit();
                }
                // Set the destination NPG value in to the client pointer
                clientPtr->destNPGId = destNPGId;
            }
        }
        else {
            break;
        }
    }
#endif // MILITARY_RADIOS_LIB

    if (appName)
    {
        clientPtr->applicationName = new std::string(appName);
    }
    else
    {
        clientPtr->applicationName = new std::string();
    }

     // dns
    // Skipped if the server network type is not valid
    // it should happen only when the server address is given by a URL
    // statistics will be initialized when url is resolved by dns
    if (remoteAddr.networkType != NETWORK_INVALID && node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "Traffic Gen Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        if (Address_IsMulticastAddress((Address*)&remoteAddr))
        {
            clientPtr->stats = new STAT_AppStatistics(
                                        node,
                                        "trafficGen",
                                        STAT_Multicast,
                                        STAT_AppSender,
                                        customName.c_str());
        }
        else
        {
            clientPtr->stats = new STAT_AppStatistics(
                                        node,
                                        "trafficGen",
                                        STAT_Unicast,
                                        STAT_AppSender,
                                        customName.c_str());
        }
        
        clientPtr->stats->Initialize(
             node,
             localAddr,
             remoteAddr,
             (STAT_SessionIdType)clientPtr->uniqueId,
             clientPtr->uniqueId);
    }
    //client pointer initialization with respect to mdp
    clientPtr->isMdpEnabled = isMdpEnabled;
    clientPtr->mdpUniqueId = uniqueId;

    if (isMdpEnabled)
    {

        if (destType == DEST_TYPE_MULTICAST)
        {
            // MDP Layer Init
            MdpLayerInit(node,
                         localAddr,
                         remoteAddr,
                         clientPtr->sourcePort,
                         APP_TRAFFIC_GEN_CLIENT,
                         isProfileNameSet,
                         profileName,
                         uniqueId,
                         nodeInput);
        }
        else if (destType == DEST_TYPE_UNICAST)
        {
            // MDP Layer Init
            MdpLayerInit(node,
                         localAddr,
                         remoteAddr,
                         clientPtr->sourcePort,
                         APP_TRAFFIC_GEN_CLIENT,
                         isProfileNameSet,
                         profileName,
                         uniqueId,
                         nodeInput,
                         -1,
                         TRUE);
        }
        if (tokenStr)
        {
            nToken = sscanf(tokenStr, "%s", buf);
            if (strcmp(buf, "MDP-ENABLED") == 0)
            {
                tokenStr = TrafficGenClientSkipToken(tokenStr,
                                                     TOKENSEP,
                                                     nToken);
            }

            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", buf);
                if (strcmp(buf, "MDP-PROFILE") == 0)
                {
                    tokenStr = TrafficGenClientSkipToken(tokenStr,
                                                         TOKENSEP,
                                                         nToken+1);
                }
            }
        }
    }


    // This section is for Quality of Service purpose. If quality
    // of service is demanded by specifying different CONSTRAINT
    // values in configuration file Quality of Service will be
    // activated.
    if (tokenStr == NULL)
    {
        clientPtr->isSessionAdmitted = TRUE;
        clientPtr->isQosEnabled = FALSE;
        clientPtr->qosConstraints.bandwidth = 0;
        clientPtr->qosConstraints.delay = 0;
        clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
        clientPtr->isRetryRequired = FALSE;
        clientPtr->connectionRetryInterval = 0;
    }
    else
    {
        // If destination is not unicast address, Quality of
        // Service cannot be provided for this non unicast flow.
        if (destType != DEST_TYPE_UNICAST)
        {
            ERROR_ReportError(
                "Quality of Service cannot be provided for non "
                "unicast flow\n");
        }

        nToken = sscanf(tokenStr, "%s", buf);

        if (nToken != 1)
        {
            TrafficGenClientPrintUsageAndQuit();
        }

        tokenStr = TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

        if ((strcmp(buf, "CONSTRAINT") != 0)
            && (strcmp(buf, "FRAGMENT-SIZE") != 0))
        {
            TrafficGenClientPrintUsageAndQuit();
        }

        if (strcmp(buf,"FRAGMENT-SIZE") == 0)
        {
            if (tokenStr == NULL)
            {
                TrafficGenClientPrintUsageAndQuit();
            }
            nToken = sscanf(tokenStr, " %d %s",
                &clientPtr->fragmentationSize, buf);

            if ((clientPtr->fragmentationSize > APP_MAX_DATA_SIZE)
                || ((unsigned int)clientPtr->fragmentationSize <= 0))
                //2 * sizeof(TrafficGenData)))

            {
                char errorMsg[MAX_STRING_LENGTH];
                sprintf(errorMsg,
                        "Fragment Size should be <= %d and > %d\n",
                        APP_MAX_DATA_SIZE,
                        0);
                        //2 * sizeof(TrafficGenData));
                ERROR_ReportError(errorMsg);
            }

            tokenStr = TrafficGenClientSkipToken(tokenStr,
                TOKENSEP, nToken);
            if (tokenStr == NULL)
            {
                clientPtr->isSessionAdmitted = TRUE;
            }
        }

        if (tokenStr != NULL
            && (strcmp(buf, "CONSTRAINT") != 0))

        {
            ERROR_ReportWarning("Without Quality of Service, connection "
                "retry not required\n");
            TrafficGenClientPrintUsageAndQuit();
        }

        if (strcmp(buf, "CONSTRAINT") == 0)
        {
            char tosStr[MAX_STRING_LENGTH];
            char tosValueStr[MAX_STRING_LENGTH];
            unsigned priorityInInt = APP_DEFAULT_TOS;

            unsigned int dataLen = (unsigned int)
                clientPtr->dataSizeDistribution.getRandomNumber();

            if (remoteAddr.networkType == NETWORK_IPV6)
            {
                ERROR_ReportError("QoS is not supported in Traffic-gen IPv6.");
            }

            clocktype dataIntv;
            unsigned int sessionBwRequirement;

            dataIntv = clientPtr->intervalDistribution.getRandomNumber();

            sessionBwRequirement = (unsigned int)
                ((dataLen * 8) * (SECOND / dataIntv));

            clientPtr->isQosEnabled = TRUE;

            if (tokenStr == NULL)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            nToken = sscanf(tokenStr, "%d %s %s %s",
                        &clientPtr->qosConstraints.bandwidth,
                        delayStr,
                        tosStr,
                        tosValueStr);

            if (sessionBwRequirement >= (unsigned int)
                clientPtr->qosConstraints.bandwidth)
            {
                char errString[MAX_STRING_LENGTH * 2];

                sprintf(errString,
                    "Error in user application specification.\n"
                    "%s\n"
                    "Given constraint bandwidth is less than session"
                    " bandwidth requirement\n",
                    inputString);
                ERROR_ReportWarning(errString);
            }

            if (nToken < 2)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            clientPtr->qosConstraints.delay = (int) (
                TIME_ConvertToClock(delayStr)/MICRO_SECOND);

            if (clientPtr->qosConstraints.delay <= 0)
            {
                ERROR_ReportError("\nInvalid end-to-end delay constraint\n");
            }

            if (nToken == 2)
            {
                clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
            }

            if (nToken > 2)
            {
                if (!strcmp(tosStr, "RETRY-INTERVAL")
                    || !strcmp(tosStr, "MDP-ENABLED")
                    || !strcmp(tosStr, "MDP-PROFILE"))
                {
                    // qos_property: not contain [TOS] field
                    nToken = 2;
                }
                else
                {
                    if ((nToken == 4) &&
                        APP_AssignTos(tosStr, tosValueStr, &priorityInInt))
                    {
                        clientPtr->qosConstraints.priority =
                            (unsigned char)priorityInInt;
                        if (node->appData.appStats)
                        {
                            clientPtr->stats->setTos(clientPtr->qosConstraints.priority);
                        }
                    }
                    else
                    {
                        char errString[MAX_STRING_LENGTH * 2];
                        sprintf(errString,
                            "Error in user application specification.\n"
                            "%s\n"
                            "Format of qos property is\n  <qos_property> ::="
                            " CONSTRAINT <bandwidth> <delay>"
                            "[ TOS <tos-value> | DSCP <dscp-value>"
                            " | PRECEDENCE <precedence-value> ]\n",
                            inputString);
                        ERROR_ReportError(errString);
                    }
                }
            }

            tokenStr =
                TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);
        }

        if (tokenStr)
        {
            nToken = sscanf(tokenStr, "%s", buf);
            if (strcmp(buf, "MDP-ENABLED") == 0)
            {
                tokenStr = TrafficGenClientSkipToken(tokenStr,
                                                     TOKENSEP,
                                                     nToken);
            }

            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", buf);
                if (strcmp(buf, "MDP-PROFILE") == 0)
                {
                    tokenStr = TrafficGenClientSkipToken(tokenStr,
                                                         TOKENSEP,
                                                         nToken+1);
                }
            }
        }

        // Check whether connection retry required or not. If required
        // get the interval of retry timer
        if (tokenStr == NULL)
        {
            clientPtr->isRetryRequired = FALSE;
            clientPtr->connectionRetryInterval = 0;
        }
        else
        {
            nToken = sscanf(tokenStr, "%s", buf);

            if (nToken != 1)
            {
                TrafficGenClientPrintUsageAndQuit();
            }

            tokenStr =
                TrafficGenClientSkipToken(tokenStr, TOKENSEP, nToken);

            if (strcmp(buf, "RETRY-INTERVAL") == 0)
            {
                clientPtr->isRetryRequired = TRUE;

                if (tokenStr == NULL)
                {
                    TrafficGenClientPrintUsageAndQuit();
                }
                nToken = sscanf(tokenStr, "%s", buf);

                clientPtr->connectionRetryInterval =
                    TIME_ConvertToClock(buf);

                if (clientPtr->connectionRetryInterval <= 0)
                {
                    ERROR_ReportError("\nInvalid retry interval\n");
                }

                tokenStr = TrafficGenClientSkipToken(
                               tokenStr, TOKENSEP, nToken);
            }
            else
            {
                TrafficGenClientPrintUsageAndQuit();
            }
        }


        if (TRAFFIC_GEN_INIT_DEBUG)
        {
            char clockStr[MAX_STRING_LENGTH];

            ctoa((clientPtr->connectionRetryInterval / SECOND), clockStr);

            printf("\nTRAFFIC-GEN: %d, Qos Bandwidth: %d, Qos Delay: %d,"
                    " Given Priority: %d\n\n",
                    clientPtr->isQosEnabled,
                    clientPtr->qosConstraints.bandwidth,
                    clientPtr->qosConstraints.delay,
                    clientPtr->qosConstraints.priority);

            printf("Connection retry property: %d retry interval %sS\n\n",
                    clientPtr->isRetryRequired, clockStr);
        }
    }

    if (TRAFFIC_GEN_DEBUG)
    {
        FILE *fp;
        char fileName[MAX_STRING_LENGTH];
        if (clientPtr->localAddr.networkType == NETWORK_IPV4)
        {
            sprintf(fileName, "ClientGenFile_%d_%d_%d",
                GetIPv4Address(clientPtr->localAddr),
                GetIPv4Address(clientPtr->remoteAddr),
                clientPtr->sourcePort);
        }
        else
        {
            char localAddrStr[MAX_STRING_LENGTH];
            char remoteAddrStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&(clientPtr->localAddr),
                localAddrStr);
            IO_ConvertIpAddressToString(&(clientPtr->remoteAddr),
                remoteAddrStr);
            sprintf(fileName, "ClientGenFile_%s_%s_%d",
                localAddrStr,
                remoteAddrStr,
                clientPtr->sourcePort);
        }
        fp = fopen(fileName, "w");
        if (fp)
        {
            fclose(fp);
        }
    }

    // Issue a message for the first data. If Quality of Service is
    // requested, then send a connection setup message before issueing
    // the message for first data.
    // initaite the connection if destination is not in form of URL
    // if URL then connection will start when URL is resolved
    if (clientPtr->isQosEnabled &&
        clientPtr->remoteAddr.networkType != NETWORK_INVALID)
    {
        TrafficGenClientRequestNewConnectionSession(
            node,
            clientPtr,
            clientPtr->startTm);
    }
    else
    {
        TrafficGenClientScheduleNextPkt(node,
            clientPtr, clientPtr->startTm);
    }

    // dynamic address change
    if (remoteAddr.networkType == NETWORK_INVALID && destString)
    {
        // set the dns info in client pointer if server url is present
        // set the server url if it is not localhost
        if (node->appData.appTrafficSender->ifUrlLocalHost(destString)
                                                                    == FALSE)
        {
            node->appData.appTrafficSender->appClientSetDnsInfo(
                                        node,
                                        (const char*)destString,
                                        clientPtr->serverUrl);
        }
    }
    // Update the client address information
    AppTrafficGenClientAddAddressInformation(
                                        node,
                                        clientPtr);

    clientPtr->destType = destType;
}


//-------------------------------------------------------------------------
// NAME:        TrafficGenClientPrintStats.
// PURPOSE:     Prints statistics of a TrafficGenClient session.
// PARAMETERS:  node - pointer to the this node.
//              clientPtr - pointer to the traffic gen client data structure.
// RETURN:      none.
//-------------------------------------------------------------------------
void TrafficGenClientPrintStats(Node* node, TrafficGenClient* clientPtr)
{

    char remoteAddrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    if (clientPtr->isSessionAdmitted)
    {

        if (clientPtr->endTm != 0 && node->getNodeTime() >= clientPtr->endTm)
        {
            clientPtr->isClosed = TRUE;
            sprintf(statusStr, "Closed");
        }
        else
        {
            sprintf(statusStr, "Not closed");
            if (!clientPtr->stats->IsSessionFinished(STAT_Unicast))
            {
                clientPtr->stats->SessionFinish(node);
            }
            if (!clientPtr->stats->IsSessionFinished(STAT_Multicast))
            {
                clientPtr->stats->SessionFinish(node, STAT_Multicast);
            }
        }

        if (clientPtr->remoteAddr.networkType == NETWORK_IPV6)
        {
            IO_ConvertIpAddressToString(
                &(clientPtr->remoteAddr), remoteAddrStr);
        }
        else
        {
            // dns
            if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
            {
                IO_ConvertIpAddressToString(
                    GetIPv4Address(clientPtr->remoteAddr), remoteAddrStr);
            }
            else
            {
                strcpy(remoteAddrStr, (char*)clientPtr->serverUrl->c_str());
            }
        }
        sprintf(buf, "Server Address = %s", remoteAddrStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-GEN Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Session Status = %s", statusStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-GEN Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Total Data Units Dropped = %d", clientPtr->dlbDrp);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-GEN Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);
    }
    else
    {
        if (clientPtr->remoteAddr.networkType == NETWORK_IPV6)
        {
            IO_ConvertIpAddressToString(
                &(clientPtr->remoteAddr), remoteAddrStr);
        }
        else
        {
            IO_ConvertIpAddressToString(
                GetIPv4Address(clientPtr->remoteAddr), remoteAddrStr);
        }
        sprintf(buf, "Session Not Admitted For Server Address %s",
                remoteAddrStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-GEN Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);
    }
}


//-------------------------------------------------------------------------
// NAME:        TrafficGenClientFinalize.
// PURPOSE:     Collect statistics of a TrafficGenClient session.
// PARAMETERS:  node - pointer to the node.
//              appInfo - pointer to the application info data structure.
// RETURN:      none.
//-------------------------------------------------------------------------
void TrafficGenClientFinalize(Node* node, AppInfo* appInfo)
{
    TrafficGenClient* clientPtr = (TrafficGenClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        TrafficGenClientPrintStats(node, clientPtr);
        // Print stats in .stat file using Stat APIs
        if (clientPtr->stats)
        {
            clientPtr->stats->Print(
                node,
                "Application",
                "TRAFFIC-GEN Client",
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


//-----------------------------------------------------------------------
// NAME:        TrafficGenServerGetServer.
// PURPOSE:     search for a traffic gen server data structure.
// PARAMETERS:  node - traffic gen server.
//              remoteAddr - traffic gen client sending the data.
//              sourcePort - sourcePort of traffic gen client/server pair.
// RETURN:      the pointer to the traffic gen server data structure,
//              NULL if nothing found.
//-----------------------------------------------------------------------
static
TrafficGenServer* TrafficGenServerGetServer(
    Node* node,
    const Address& remoteAddr,
    int sourcePort)
{
    AppInfo* appList = NULL;
    TrafficGenServer*  serverPtr = NULL;

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_GEN_SERVER)
        {
            serverPtr = (TrafficGenServer*)  appList->appDetail;

            if ((serverPtr->sourcePort == sourcePort)
                && IO_CheckIsSameAddress(serverPtr->remoteAddr, remoteAddr))
            {
                return serverPtr;
            }
        }
    }
    return NULL;
}


//--------------------------------------------------------------------------
// NAME:        TrafficGenServerNewServer.
// PURPOSE:     create a new traffic gen server data structure, place it
//              at the beginning of the application list.
// PARAMETERS:  node - pointer to the node.
//              remoteAddr - remote address.
//              sourcePort - sourcePort of traffic gen client/server pair.
// RETRUN:      pointer to the created traffic gen server data structure,
//              NULL if no data structure allocated.
//--------------------------------------------------------------------------
static
TrafficGenServer* TrafficGenServerNewServer(
    Node* node,
    const Address& remoteAddr,
    const Address& localAddress,
    short sourcePort)
{
    TrafficGenServer*  serverPtr = (TrafficGenServer*)
            MEM_malloc(sizeof(TrafficGenServer));

    // Initialize
    memcpy(&(serverPtr->localAddr), &(localAddress), sizeof(Address));
    memcpy(&(serverPtr->remoteAddr), &(remoteAddr), sizeof(Address));
    serverPtr->sourcePort = sourcePort;

    serverPtr->startTm = node->getNodeTime();
    serverPtr->endTm = node->getNodeTime();
    serverPtr->lastRcvTm = 0;

    MsTmWinInit(&serverPtr->rcvThru,
                (clocktype) TRAFFIC_GEN_SERVER_SSIZE,
                TRAFFIC_GEN_SERVER_NSLOT,
                TRAFFIC_GEN_SERVER_WEIGHT,
                node->getNodeTime());

    serverPtr->seqNo = 0;
    serverPtr->fragNo = 0;
    serverPtr->totFrag = 0;
    serverPtr->fragByte = 0;
    serverPtr->fragTm = 0;
    serverPtr->isClosed = FALSE;

    serverPtr->lastInterArrivalInterval = 0;
    serverPtr->lastPacketReceptionTime = 0;
    serverPtr->totalJitter = 0;
    serverPtr->uniqueId = node->appData.uniqueId++;
    serverPtr->stats = NULL;

    APP_RegisterNewApp(node, APP_TRAFFIC_GEN_SERVER, serverPtr);

    if (TRAFFIC_GEN_DEBUG)
    {
        FILE *fp;
        char fileName[MAX_STRING_LENGTH];
        if (serverPtr->localAddr.networkType == NETWORK_IPV4)
        {
            sprintf(fileName, "ServerGenFile_%d_%d_%d",
                GetIPv4Address(serverPtr->remoteAddr),
                GetIPv4Address(serverPtr->localAddr),
                serverPtr->sourcePort);
        }
        else if (serverPtr->localAddr.networkType == NETWORK_IPV6)
        {
            char localAddrStr[MAX_STRING_LENGTH];
            char remoteAddrStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&(serverPtr->localAddr),
                localAddrStr);
            IO_ConvertIpAddressToString(&(serverPtr->remoteAddr),
                remoteAddrStr);
            sprintf(fileName, "ClientGenFile_%s_%s_%d",
                remoteAddrStr,
                localAddrStr,
                serverPtr->sourcePort);
        }

        fp = fopen(fileName, "w");
        if (fp)
        {
            fclose(fp);
        }
    }

#ifdef MILITARY_RADIOS_LIB
    serverPtr->forwardSrcPort = -1;  //Initialize this as an invalid port number
#endif

    return serverPtr;
}

// /**
// FUNCTION   :: TrafficGenPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void TrafficGenPrintTraceXML(Node* node, Message* msg)
{
     char buf[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];

    TrafficGenData* data = (TrafficGenData*) MESSAGE_ReturnInfo(msg,
                                              INFO_TYPE_SuperAppUDPData);

    if (data == NULL) {
        return;
    }

    TIME_PrintClockInSecond(data->txTime, clockStr);

    sprintf(buf, "<trafficgen>%u %u %u %d %s</trafficgen>",
                data->sourcePort,
                data->seqNo,
                data->fragNo,
                (msg->packetSize + msg->virtualPayloadSize),
                                                    clockStr);
    TRACE_WriteToBufferXML(node, buf);

}//END OF FUNCTION TrafficGenPrintTraceXML


//-----------------------------------------------------------------------
// NAME:        TrafficGenServerLayerRoutine.
// PURPOSE:     Models the behaviour of Traffic Gen Server on receiving
//              message encapsulated in msg.
// PARAMETERS:  node - pointer to the node which received the message.
//              msg - message received by the layer
// RETURN:      none.
//-----------------------------------------------------------------------
void TrafficGenServerLayerRoutine(Node* node, Message* msg)
{
    char clockStr[MAX_STRING_LENGTH];
    char errMsg[MAX_STRING_LENGTH];
    TrafficGenServer* serverPtr = NULL;
    TrafficGenData data;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:

#ifdef MILITARY_RADIOS_LIB
        case MSG_APP_FromMac:
#endif // MILITARY_RADIOS_LIB
        {
            Address sourceAddr;
            Address destAddr;

#ifdef MILITARY_RADIOS_LIB
            if (msg->eventType == MSG_APP_FromMac)
            {
                TadilToAppRecv *infotemp =
                    (TadilToAppRecv*)MESSAGE_ReturnInfo(msg);

                NodeAddress sourceId = infotemp->sourceId;

                // Any application can be identified by the four tuple.
                // But in case of LINK11 source node id is not available.
                // For that reason, originating node id is used.
                if (node->macData[MAC_DEFAULT_INTERFACE]->macProtocol
                    == MAC_PROTOCOL_TADIL_LINK11)
                {
                    sourceId = msg->originatingNodeId;
                }

                sourceAddr.networkType = NETWORK_IPV4;
                sourceAddr.interfaceAddr.ipv4 =
                    MAPPING_GetInterfaceAddressForInterface(
                                 node,
                                 sourceId,
                                 MAC_DEFAULT_INTERFACE);
                ERROR_Assert(sourceAddr.interfaceAddr.ipv4
                        != INVALID_MAPPING,
                             "TADIL: Invalid IP address");
                destAddr.networkType = NETWORK_IPV4;
                destAddr.interfaceAddr.ipv4 = ANY_DEST;

            }
            else
            {
                UdpToAppRecv* info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);

                memcpy(&sourceAddr, &(info->sourceAddr), sizeof(Address));
                memcpy(&destAddr, &(info->destAddr), sizeof(Address));
            }
#else // MILITARY_RADIOS_LIB
            UdpToAppRecv* info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);

            memcpy(&sourceAddr, &(info->sourceAddr), sizeof(Address));
            memcpy(&destAddr, &(info->destAddr), sizeof(Address));
#endif // MILITARY_RADIOS_LIB

            memcpy(&data,
                   MESSAGE_ReturnInfo(msg, INFO_TYPE_SuperAppUDPData),
                   sizeof(data));

            serverPtr = TrafficGenServerGetServer(
                            node,
                            sourceAddr,
                            data.sourcePort);

            // New connection.
            // Create new traffic gen server to handle client.
            if (serverPtr == NULL)
            {
                serverPtr = TrafficGenServerNewServer(
                    node, sourceAddr, destAddr, data.sourcePort);

                if (node->appData.appStats)
                {
                    // Create statistics
                    serverPtr->stats = new STAT_AppStatistics(
                        node,
                        "trafGenServer",
                        STAT_Unicast,
                        STAT_AppReceiver,
                        "Traffic Gen Server");

                    serverPtr->stats->Initialize(
                        node,
                        sourceAddr,
                        destAddr,
                        STAT_AppStatistics::GetSessionId(msg),
                        serverPtr->uniqueId);
                    serverPtr->stats->SessionStart(node);
                }
            }

            if ((data.seqNo == serverPtr->seqNo
                     && data.fragNo == serverPtr->fragNo)
                     || (data.seqNo > serverPtr->seqNo && data.fragNo == 0)
                     || (data.isMdpEnabled))
            {
#ifdef MILITARY_RADIOS_LIB
                //After received a fragment, the gateway needs
                //to update statistics and forward the fragment
                if (node->appData.link16Gateway)
                {
                    if (node->appData.link16Gateway->statsEnabled)
                    {
                        Link16GatewayStats* stats =
                            &(node->appData.link16Gateway->statistics);
                        int fragSize = MESSAGE_ReturnPacketSize(msg);
                        if (msg->eventType == MSG_APP_FromTransport)
                        {
                            stats->numBytesFromIp += fragSize;
                        }
                        else if (msg->eventType == MSG_APP_FromMac)
                        {
                            stats->numBytesFromLink16 += fragSize;
                        }
                    }

                    if (msg->eventType == MSG_APP_FromTransport)
                    {
                        TrafficGenGatewayForwardToLink16(
                            node,
                            sourceAddr,
                            destAddr,
                            msg);
                    }
                    else
                    {
                        TrafficGenGatewayForwardToIp(
                            node,
                            sourceAddr,
                            msg);
                    }
                }
#endif // MILITARY_RADIOS_LIB

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
                }
                if (data.fragNo == 0)
                {
                    serverPtr->fragByte = 0;
                    serverPtr->fragTm = data.txTime;
                }

                serverPtr->endTm = node->getNodeTime();
                serverPtr->lastRcvTm = node->getNodeTime();
                serverPtr->seqNo = data.seqNo;
                serverPtr->fragNo = data.fragNo;
                serverPtr->totFrag = data.totFrag;
                serverPtr->fragByte += MESSAGE_ReturnPacketSize(msg);

                if (serverPtr->fragNo == serverPtr->totFrag - 1)
                {
                    serverPtr->seqNo++;
                    serverPtr->fragNo = 0;

                    MsTmWinNewData(&serverPtr->rcvThru,
                                   serverPtr->fragByte * 8.0,
                                   node->getNodeTime());

                    if (TRAFFIC_GEN_DEBUG)
                    {
                        FILE *fp = NULL;
                        char fileName[MAX_STRING_LENGTH];
                        char dataBuf[MAX_STRING_LENGTH];
                        clocktype currentTime = node->getNodeTime();

                        if (serverPtr->localAddr.networkType == NETWORK_IPV4)
                        {
                            sprintf(fileName, "ServerGenFile_%d_%d_%d",
                                GetIPv4Address(serverPtr->remoteAddr),
                                GetIPv4Address(serverPtr->localAddr),
                                serverPtr->sourcePort);
                        }
                        else if (serverPtr->localAddr.networkType == NETWORK_IPV6)
                        {
                            char localAddrStr[MAX_STRING_LENGTH];
                            char remoteAddrStr[MAX_STRING_LENGTH];
                            IO_ConvertIpAddressToString(&(serverPtr->localAddr),
                                localAddrStr);
                            IO_ConvertIpAddressToString(&(serverPtr->remoteAddr),
                                remoteAddrStr);
                            sprintf(fileName, "ClientGenFile_%s_%s_%d",
                                remoteAddrStr,
                                localAddrStr,
                                serverPtr->sourcePort);
                        }

                        fp = fopen(fileName, "a");

                        if (fp)
                        {
                            sprintf(dataBuf, "%.6f\t%d\t%.6f\t%.6f\n",
                                (currentTime / (double)SECOND),
                                serverPtr->sourcePort,
                                MsTmWinAvg(&serverPtr->rcvThru,
                                           currentTime),
                                MsTmWinTotalAvg(&serverPtr->rcvThru,
                                                currentTime));

                            if (fwrite(dataBuf, strlen(dataBuf), 1, fp)!= 1)
                            {
                               ERROR_ReportWarning("Unable to write in file \n");
                            }

                            fclose(fp);
                        }
                    }
                }
                else
                {
                    serverPtr->fragNo++;
                }
            }

            ActionData acnData;
            acnData.actionType = RECV;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_APPLICATION_LAYER,
                             PACKET_IN,
                             &acnData);

            if (data.type == 'c')
            {
                if (node->appData.appStats)
                {
                    if (!serverPtr->stats->IsSessionFinished(STAT_Unicast))
                    {
                        serverPtr->stats->SessionFinish(node);
                    }
                }
            }
            else if (data.type != 'd')
            {
                ERROR_ReportError("Expected 'c' or 'd'");
            }

            break;
        }
        default:
        {
            ctoa(node->getNodeTime(), clockStr);

            sprintf(errMsg,
                "TRAFFIC-GEN Server: At time %s, node %d received "
                "message of unknown type %d.\n",
                clockStr, node->nodeId, msg->eventType);

            ERROR_Assert(FALSE, errMsg);
            break;
        }
    }
    MESSAGE_Free(node, msg);
}


//----------------------------------------------------
// NAME:        TrafficGenServerInit.
// PURPOSE:     listen on TrafficGenServer server port.
// PARAMETERS:  node - pointer to the node.
// RETURN:      none.
//----------------------------------------------------
void TrafficGenServerInit(Node* node)
{
}


//-------------------------------------------------------------------------
// NAME:        TrafficGenServerPrintStats.
// PURPOSE:     Prints statistics of a TrafficGenServer session.
// PARAMETERS:  node - pointer to this node.
//              serverPtr - pointer to the traffic gen server data structure.
// RETURN:      none.
//-------------------------------------------------------------------------
void TrafficGenServerPrintStats(
    Node* node,
    TrafficGenServer* serverPtr)
{
    char remoteAddrStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];


    if (serverPtr->endTm != 0 && node->getNodeTime() >= serverPtr->endTm)
    {
        serverPtr->isClosed = TRUE;
        if (!serverPtr->stats->IsSessionFinished(STAT_Unicast))
        {
            serverPtr->stats->SessionFinish(node);
        }
    }

    if (serverPtr->isClosed == FALSE)
    {
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

    if (serverPtr->remoteAddr.networkType == NETWORK_IPV6)
    {
        IO_ConvertIpAddressToString(
            &(serverPtr->remoteAddr), remoteAddrStr);
    }
    else
    {
        IO_ConvertIpAddressToString(
            GetIPv4Address(serverPtr->remoteAddr), remoteAddrStr);
    }
    sprintf(buf, "Client Address = %s", remoteAddrStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-GEN Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-GEN Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);
}


//-------------------------------------------------------------------------
// NAME:        TrafficGenServerFinalize.
// PURPOSE:     Collect statistics of a TrafficGenServer session.
// PARAMETERS:  node - pointer to the node.
//              appInfo - pointer to the application info data structure.
// RETURN:      none.
//-------------------------------------------------------------------------
void TrafficGenServerFinalize(Node* node, AppInfo* appInfo)
{
    TrafficGenServer* serverPtr = (TrafficGenServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        TrafficGenServerPrintStats(node, serverPtr);
        // Print stats in .stat file using Stat APIs
        if (serverPtr->stats)
        {
            serverPtr->stats->Print(
                node,
                "Application",
                "TRAFFIC-GEN Server",
                ANY_ADDRESS,
                serverPtr->sourcePort);
        }
    }
}

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppTrafficGenClientAddAddressInformation.
// PURPOSE              : store client interface index, destination
//                        interface index destination node id to get the
//                        correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : TrafficGenClient* : pointer to Traffic Gen
//                        client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppTrafficGenClientAddAddressInformation(Node* node,
                                  TrafficGenClient* clientPtr)
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

// DNS
//--------------------------------------------------------------------------
// NAME:        : AppTrafficGenUrlSessionStartCallback.
// PURPOSE:     : Process Received DNS info.
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : unsigned short : source port
// + uniqueId   : Int32          : connection id; not used for CBR
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo : information required to
//                                                 send buffered application
//                                                 packets in case of UDP
//                                                 based applications
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as
//                this callback will initiate TCP Open request and not send
//                packet
//--------------------------------------------------------------------------
bool
AppTrafficGenUrlSessionStartCallback(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    AppUdpPacketSendingInfo* packetSendingInfo)
{
    // TrafficGenData data;
    AppInfo* appList = NULL;
    TrafficGenClient* clientPtr = NULL;
    TrafficGenClient* dataPtr = NULL;

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_GEN_CLIENT)
        {
            dataPtr = (TrafficGenClient*) appList->appDetail;

            if (dataPtr->sourcePort == sourcePort)
            {
                clientPtr = dataPtr;
            }
        }
    }

    if (clientPtr == NULL)
    {
        return (FALSE);
    }
    if (clientPtr->remoteAddr.networkType != NETWORK_INVALID)
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
            ERROR_ReportErrorArgs("TRaffic Gen Client: Node %d cannot "
                    " find IPv4 Traffic Gen client for ipv4 dest\n",
                    node->nodeId);
        }
    }
    else if (serverAddr->networkType == NETWORK_IPV6)
    {
        if (clientPtr->localAddr.networkType != NETWORK_IPV6)
        {
             ERROR_ReportErrorArgs("CBR Client: Node %d cannot find IPv6 "
                    " Traffic Gen client for ipv6 dest\n",
                    node->nodeId);
        }
    }

    // Update client RemoteAddress field and session Start
    memcpy(&clientPtr->remoteAddr, serverAddr, sizeof(Address));

    // Update the client address information
    AppTrafficGenClientAddAddressInformation(node,
                                             clientPtr);

    if (!((clientPtr->localAddr.networkType == NETWORK_IPV6 &&
            clientPtr->remoteAddr.networkType == NETWORK_IPV6) ||
            (clientPtr->localAddr.networkType == NETWORK_IPV4 &&
            clientPtr->remoteAddr.networkType == NETWORK_IPV4)))
    {

        ERROR_ReportErrorArgs(
            "TrafficGenClientSendData: "
            "Wrong network protocol configuration.");
    }


#ifdef MILITARY_RADIOS_LIB
    // dns
    // if destination is in form of URL then remote address is not valid at
    // initialization. skipped here for URL case. This will be done when URL
    // is resolved
    if (serverAddr->networkType != NETWORK_INVALID)
    {
        if (serverAddr->networkType == NETWORK_IPV4 &&
            GetIPv4Address(*serverAddr) == ANY_DEST)
        {
            BOOL tadilIfaceFound = FALSE;
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if ((node->macData[i]->macProtocol == MAC_PROTOCOL_TADIL_LINK16)||
                    (node->macData[i]->macProtocol == MAC_PROTOCOL_TADIL_LINK11) )
                {
                    tadilIfaceFound = TRUE;
                    NodeAddress tadilIfaceAddress =
                        NetworkIpGetInterfaceAddress(node, i);
                    SetIPv4AddressInfo(
                        &(clientPtr->localAddr),
                        tadilIfaceAddress);
                    break;
                }
            }
            if (!tadilIfaceFound)
            {
                ERROR_ReportErrorArgs("Traffic-Gen: "
                    "Source must have a Link16 interface "
                    "if the destination is 255.255.255.255.\n");
            }
        }
        else if (clientPtr->destType == DEST_TYPE_BROADCAST)
        {
            ERROR_ReportErrorArgs( "Traffic-Gen: "
                    "Destination cannot be IPv6 broadcast address \n");
        }
        else
        {
            BOOL ipIfaceFound = FALSE;
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if ((node->macData[i]->macProtocol
                    != MAC_PROTOCOL_TADIL_LINK16) &&
                    (node->macData[i]->macProtocol
                    != MAC_PROTOCOL_TADIL_LINK11) )
                {
                    ipIfaceFound = TRUE;
                    Address ipIfaceAddr =
                        MAPPING_GetInterfaceAddressForInterface(
                               node,
                               node->nodeId,
                               serverAddr->networkType,
                               i);
                    memcpy(&(clientPtr->localAddr),
                            &ipIfaceAddr, sizeof(Address));
                    break;
                }
            }
            if (!ipIfaceFound)
            {
                ERROR_ReportErrorArgs("Traffic-Gen: "
                    "Source must have an IP interface "
                    "if the destination is not 255.255.255.255.\n");
            }

        }
        int interfaceIndex =
            MAPPING_GetInterfaceIndexFromInterfaceAddress(
                    node, clientPtr->localAddr);
        if (interfaceIndex == INVALID_MAPPING)
        {
            ERROR_ReportErrorArgs("Traffic-gen: source address "
                "does not have a valid interface associated with it.");
        }
    }
#endif //  MILITARY_RADIOS_LIB

    if (node->appData.appStats)
    {
        std::string customName;
        if (clientPtr->applicationName->empty())
        {
            customName = "Traffic Gen Client";
        }
        else
        {
            customName = *clientPtr->applicationName;
        }
        if (Address_IsMulticastAddress(&clientPtr->remoteAddr))
        {
            clientPtr->stats = new STAT_AppStatistics(
                                        node,
                                        "trafficGen",
                                        STAT_Multicast,
                                        STAT_AppSender,
                                        customName.c_str());
        }
        else
        {
            clientPtr->stats = new STAT_AppStatistics(
                                        node,
                                        "trafficGen",
                                        STAT_Unicast,
                                        STAT_AppSender,
                                        customName.c_str());
        }
        clientPtr->stats->Initialize(
             node,
             clientPtr->localAddr,
             clientPtr->remoteAddr,
             (STAT_SessionIdType)clientPtr->uniqueId,
             clientPtr->uniqueId);
    }

    // First check if end time had already reached..
    if ((clientPtr->endTm != 0) &&
        ((clocktype)node->getNodeTime() > clientPtr->endTm))
    {
        return (FALSE);
    }

    // Issue a message for the first data. If Quality of Service is
    // requested, then send a connection setup message before issueing
    // the message for first data.
    if (clientPtr->isQosEnabled)
    {
        TrafficGenClientRequestNewConnectionSession(
            node,
            clientPtr,
            clientPtr->startTm);
    }
    else
    {
        clientPtr->startTm = node->getNodeTime();
        if (clientPtr->totByteSent == 0 && node->appData.appStats)
        {
            clientPtr->stats->SessionStart(node, STAT_Unicast);
        }
        if (AppTrafficGenClientGetSessionAddressState(node, clientPtr)
                == ADDRESS_FOUND)
        {
            packetSendingInfo->stats = clientPtr->stats;
            // now send the bufffered packets
            return (TRUE);
        }
        else
        {
            clientPtr->startTm = 0;
            clientPtr->endTm = 0;
            clientPtr->isClosed = TRUE;
        }
    }
    return (FALSE);
}

//---------------------------------------------------------------------------
// FUNCTION             : AppTrafficGenClientGetSessionAddressState.
// PURPOSE              : get the current address sate of client and server
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : TrafficGenClient* : pointer to Traffic Gen
//                        client data
// RETRUN:
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if both client and server
//                                        are having valid address
//                        ADDRESS_INVALID : if either of them are in
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppTrafficGenClientGetSessionAddressState(Node* node,
                                   TrafficGenClient* clientPtr)
{
    // variable to determine the server current address state
    Int32 serverAddresState = 0;
    // variable to determine the client current address state
    Int32 clientAddressState = 0;

    // Get the current client and destination address if the
    // session is starting
    // Address state is checked only at the session start; if this is not
    // starting of session then return FOUND_ADDRESS
    if (clientPtr->seqNo == 0)
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
                 clientPtr->destInterfaceIndex != ANY_INTERFACE &&
                !NetworkIpIsMulticastAddress(
                    node, clientPtr->remoteAddr.interfaceAddr.ipv4))
        {
            serverAddresState =
                MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    clientPtr->destNodeId,
                                    clientPtr->destInterfaceIndex,
                                    clientPtr->remoteAddr.networkType,
                                    &(clientPtr->remoteAddr));
        }
        else if (NetworkIpIsMulticastAddress(
                    node, clientPtr->remoteAddr.interfaceAddr.ipv4))
        {
            serverAddresState = clientAddressState;
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


