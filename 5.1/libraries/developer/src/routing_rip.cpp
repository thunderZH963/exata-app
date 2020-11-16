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
#include "network_ip.h"
#include "app_util.h"
#include "routing_rip.h"
#include "network_dualip.h"
#include "external.h"
#include "external_socket.h"

// to activate debug define DEBUG
#define noDEBUG

//UserCodeStartBodyData
#define RIP_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED   4  // The route table starts with memory allocated for this many routes.
#define RIP_INFINITY   16  // RIP value for infinite distance
#define RIP_UPDATE_INTERVAL   (30 * SECOND)  // The delay between regular updates is: RIP_UPDATE_INTERVAL - [0, RIP_UPDATE_INTERVAL * RIP_UPDATE_JITTER) seconds. i.e., (25.5, 30] seconds.
#define RIP_UPDATE_JITTER   0.15
#define RIP_TRIGGER_DELAY   (5 * SECOND)  // The delay after triggered updates is: RIP_TRIGGER_DELAY - [0, RIP_TRIGGER_DELAY * RIP_TRIGGER_JITTER) seconds. i.e., (1, 5] seconds.
#define RIP_TRIGGER_JITTER   0.8
#define RIP_STARTUP_DELAY   (100 * MILLI_SECOND)  // The delay at startup before the first regular update is RIP_STARTUP_DELAY - [0, RIP_STARTUP_DELAY * RIP_STARTUP_JITTER) seconds i.e., (0, 100] milliseconds.
#define RIP_STARTUP_JITTER   1.0
#define RIP_TIMEOUT_DELAY   (180 * SECOND)  // Delay for route timed out
#define RIP_FLUSH_DELAY   (120 * SECOND)  // Delay to flush timed out route
#define RIP_HEADER_SIZE   4  // Header size of RIP
#define RIP_RTE_SIZE   20  // size of single route entry
#define RIP_MAX_RTE   25  // maxium route entry
#define RIP_MSG_SIZE   504  // size of response message


//UserCodeEndBodyData

//Statistic Function Declarations
static void RipInitStats(Node* node, RipStatsType* stats);
void RipPrintStats(Node* node);

//Utility Function Declarations
static void RipSendResponse(Node* node,
                            int interfaceIndex,
                            RipResponseType type,
                            Message* msg);
static void RipProcessResponse(Node* node,Message* msg);
static void RipScheduleTriggeredUpdate(Node* node);
static void RipSetRouteTimer(Node* node,
                             clocktype* timePtr,
                             NodeAddress destAddress,
                             clocktype delay,
                             RipRouteTimerType type);
static void RipHandleRouteTimeout(Node* node,RipRoute* routePtr);
static void RipInitRouteTable(Node* node);
static RipRoute* RipGetRoute(Node* node,NodeAddress destAddress);
static RipRoute* RipAddRoute(Node* node,
                             unsigned short routeTag,
                             NodeAddress destAddress,
                             NodeAddress subnetMask,
                             NodeAddress nextHop,
                             int metric,
                             int outgoingInterfaceIndex,
                             int learnedInterfaceIndex);
static void RipHandleRouteFlush(Node* node,RipRoute* routePtr);
static NodeAddress RipReturnMaskFromIPAddress(NodeAddress address);
static BOOL RipIsInADifferentMajorNetwork(NodeAddress nodeAddress1,
                                          NodeAddress nodeAddress2);
static void RipGetVersionAndSplitHorizon(Node* node,
                                         const NodeInput* nodeInput,
                                         int interfaceIndex,
                                         unsigned int* version,
                                         RipSplitHorizonType* splitHorizon);
static void RipClearChangedRouteFlags(Node* node);
static void RipInterfaceStatusHandler(Node* node,
                                      int interfaceIndex,
                                      MacInterfaceState state);
static void RipChangeToLowerCase(char* buf);

//State Function Declarations
static void enterRipIdle(Node* node, RipData* dataPtr, Message* msg);
static void enterRipHandleRegularUpdateAlarm(Node* node,
                                             RipData* dataPtr,
                                             Message* msg);
static void enterRipHandleTriggeredUpdateAlarm(Node* node,
                                               RipData* dataPtr,
                                               Message* msg);
static void enterRipHandleFromTransport(Node* node,
                                        RipData* dataPtr,
                                        Message* msg);
static void enterRipHandleRouteTimerAlarm(Node* node,
                                          RipData* dataPtr,
                                          Message* msg);

// FUNCTION RipPrintRouteTable
// PURPOSE  Prints to screen the local route table.
//
// Node *node
//     For current node.
// char *msg
//     To display a message
static void RipPrintRouteTable(Node* node, char* msg) {
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    int dataLen=dataPtr->numRoutes;
    int i;
    char cbuf[20];
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    printf("Rip: %s s, node %u, --- %s route table, "
           "(dest subnet nextHop dist)\n",
           cbuf,
           node->nodeId,
           msg);

    char address[MAX_STRING_LENGTH];
    for (i=0;i<dataLen;i++)
    {
        printf("Rip: %s s, node %u \t",cbuf,node->nodeId);
        IO_ConvertIpAddressToString(dataPtr->routeTable[i].destAddress,
                                    address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(dataPtr->routeTable[i].subnetMask,
                                    address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(dataPtr->routeTable[i].nextHop,
                                    address);
        printf("%s \t",address);
        printf("%d\n",dataPtr->routeTable[i].metric);
    }
}

//Utility Function Definitions
//UserCodeStart
// FUNCTION RipSendResponse
// PURPOSE  Sends a RIP Response message out the specified interface.
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  type:   ALL_ROUTES (regular) or CHANGED_ROUTES (triggered update)
//  msg:    Pointer to message with RIP event message.
static void RipSendResponse(Node* node,
                            int interfaceIndex,
                            RipResponseType type,
                            Message* msg)
{
//warning: Don't remove the opening and the closing brace
//add your code here:
#ifdef DEBUG
    char cbuf[20];
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    printf("Rip: %s s, node %u, Preparing to send on interface %d\n",
        cbuf,node->nodeId,interfaceIndex);
#endif
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    unsigned routeIndex;
    RipPacket response;
    NodeAddress ipAddress;
    NodeAddress subnetMask;
    unsigned metric;
    int i;
    response.command = RIP_RESPONSE;

    if ((dataPtr->version == RIP_VERSION_1) ||
        (type == RIP_REQUESTED_COMPATIBLE_ROUTES)||
        (dataPtr->ripCompatibility[interfaceIndex] == RIPv1_ONLY))
    {
        response.version = RIP_VERSION_1;
    }
    else
    {
        response.version = RIP_VERSION_2;
    }
    response.mustBeZero = 0;
    routeIndex = 0;

    while (routeIndex < dataPtr->numRoutes)
    {
        int rteIndex;

        // Loop until Response packet full, or all routes have been
        // examined.

        for (rteIndex = 0; routeIndex < dataPtr->numRoutes
                           && rteIndex < RIP_MAX_RTE; routeIndex++)
        {
#ifdef DEBUG
            char address[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(dataPtr->routeTable[routeIndex].
                                        destAddress,
                                        address);
            printf("Rip: %s s, node %u, route %s - ",
                cbuf,node->nodeId,address);
#endif

            if (dataPtr->routeTable[routeIndex].flushed == TRUE)
            {
                // Don't send flushed routes.
#ifdef DEBUG
                printf("Don't send flushed routes\n");
#endif
                continue;
            }
            if (interfaceIndex
                == dataPtr->routeTable[routeIndex].learnedInterfaceIndex)
            {
                // Split horizon only for wired networks.
                if (dataPtr->splitHorizon == RIP_SPLIT_HORIZON_SIMPLE
                    && (TunnelIsVirtualInterface(node, interfaceIndex) ||
                    MAC_IsWiredNetwork(node, interfaceIndex)))
                {
#ifdef DEBUG
                    printf("Split Horizon in action\n");
#endif
                    continue;
                }
            }
            if (type == RIP_CHANGED_ROUTES
                && dataPtr->routeTable[routeIndex].changed == FALSE)
            {
                // Triggered updates send only routes with the changed
                // flag.
#ifdef DEBUG
                printf("Triggered updates send "
                    "only routes with the changed flag\n");
#endif
                continue;
            }

#ifdef DEBUG
            printf("Taking this route, distance ");
#endif

            ipAddress = dataPtr->routeTable[routeIndex].destAddress;
            metric = dataPtr->routeTable[routeIndex].metric;
            subnetMask = dataPtr->routeTable[routeIndex].subnetMask;

            //added for route summarization
            //split horizon only for wired network

            if ((dataPtr->splitHorizon == RIP_SPLIT_HORIZON_OFF) ||
                    (!(MAC_IsWiredNetwork(node, interfaceIndex))))
            {
                //split horizon is off
                if (dataPtr->borderRouter == TRUE &&
                    dataPtr->routeSummary[interfaceIndex] == TRUE)
                {
                    if (RipIsInADifferentMajorNetwork(ipAddress,
                               NetworkIpGetInterfaceAddress(node,
                               interfaceIndex)))
                    {
                        int flag = 0;
                        for (i = 0; i < routeIndex; i++)
                        {
                            if (!RipIsInADifferentMajorNetwork(
                                ipAddress,
                                dataPtr->routeTable[i].destAddress) &&
                                (dataPtr->routeTable[i].flushed != TRUE))
                            {
                                flag = 1;// already added
                                break;
                            }
                        }
                        if (flag == 1)
                        {
                            // summarized route already added
                            continue;
                        }
                        metric = dataPtr->routeTable[routeIndex].metric;
                        for (i = routeIndex + 1;i < dataPtr->numRoutes;i++)
                        {
                            if (!RipIsInADifferentMajorNetwork(
                                dataPtr->routeTable[routeIndex].destAddress,
                                dataPtr->routeTable[i].destAddress))
                            {
                                if (metric > dataPtr->routeTable[i].metric)
                                {
                                    metric = dataPtr->routeTable[i].metric;
                                }
                            }
                        }
                        // Get network address
                        ipAddress = ipAddress &
                            RipReturnMaskFromIPAddress(ipAddress);
                        subnetMask = RipReturnMaskFromIPAddress(ipAddress);
                    }
                }
            }

            response.rtes[rteIndex].afi = 2;            // IP
            response.rtes[rteIndex].ipAddress = ipAddress;
            response.rtes[rteIndex].nextHop = 0;

            if ((dataPtr->version == RIP_VERSION_2) &&
                (response.version == RIP_VERSION_2))
            {
                response.rtes[rteIndex].routeTag =
                    dataPtr->routeTable[routeIndex].routeTag; 
                response.rtes[rteIndex].subnetMask = subnetMask;
                if (dataPtr->routeTable[routeIndex].outgoingInterfaceIndex
                    == interfaceIndex)
                {
                    response.rtes[rteIndex].nextHop =
                        dataPtr->routeTable[routeIndex].nextHop;
                }
            }
            else
            {
                response.rtes[rteIndex].routeTag = 0;
                response.rtes[rteIndex].subnetMask = 0;
            }
            if (interfaceIndex ==
                dataPtr->routeTable[routeIndex].learnedInterfaceIndex)
            {
                if (dataPtr->splitHorizon ==
                        RIP_SPLIT_HORIZON_POISONED_REVERSE
                    && (TunnelIsVirtualInterface(node, interfaceIndex) ||
                    MAC_IsWiredNetwork(node, interfaceIndex)))
                {
                    // Split Horizon with poisoned reverse
#ifdef DEBUG
                    printf("RIP_INFINITY Split Horizon "
                        "with poisoned reverse\n");
#endif
                    response.rtes[rteIndex].metric = RIP_INFINITY;
                }
                else
                {
                    // No Split-Horizon
#ifdef DEBUG
                    printf("MIN(%d,RIP_INFINITY) No Split-Horizon\n",
                        metric + 1);
#endif
                    response.rtes[rteIndex].metric =
                        MIN(metric + 1, RIP_INFINITY);
                }
            }
            else
            {

            // Increment metric here (at sending end).
#ifdef DEBUG
            printf("MIN(%d,RIP_INFINITY)\n",metric + 1);
#endif
            response.rtes[rteIndex].metric =
                MIN(metric + 1, RIP_INFINITY);
            }
            
#ifdef IPNE_INTERFACE
          //Convert response.rtes[rteIndex] to network byte order for IPNE

           RipRte* rte = &response.rtes[rteIndex];
           RipResponseSwapBytes(rte);
#endif


            rteIndex++;
        }//for//

        if (rteIndex != 0)
        {
            NodeAddress destAddress;
            if (type == RIP_REQUESTED_ROUTES ||
                type == RIP_REQUESTED_COMPATIBLE_ROUTES)
            {
                // Response to request is unicasted to requesting node
                UdpToAppRecv* info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
                destAddress = GetIPv4Address(info->sourceAddr);
            }
            else if (dataPtr->ripCompatibility[interfaceIndex] ==
                RIPv2_ONLY)
            {
                destAddress = RIP_MULTICAST_ADDRESS;
            }
            else if (NetworkIpIsWiredNetwork(node, interfaceIndex))
            {
                destAddress = NetworkIpGetInterfaceBroadcastAddress(
                                   node,
                                   interfaceIndex);
            }
#ifdef ADDON_BOEINGFCS
            else if (node->macData[interfaceIndex]->macProtocol ==
                MAC_PROTOCOL_CES_SRW_PORT)
            {
                destAddress =  RIP_MULTICAST_ADDRESS;
            }
#endif
            else
            {
                destAddress = ANY_DEST;
            }

            // Send Response message with CONTROL packet priority.
            // NetworkIpGetInterfaceBroadcastAddress() is used to ensure
            // that the packet is sent out the correct interface.
            // ANY_IP as the source IP address is interpreted at IP
            // to mean that IP will assign the source IP address
            // depending on the actual interface used.

#ifdef DEBUG
            char address1[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(destAddress,address1);
            printf("Rip: %s s, node %u, Sent packet to UDP, dst %s\n",
                cbuf,node->nodeId,address1);
#endif

            Message *msg = APP_UdpCreateMessage(
                node,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                (short) APP_ROUTING_RIP,
                destAddress,
                (short) APP_ROUTING_RIP,
                TRACE_RIP,
                IPTOS_PREC_INTERNETCONTROL);

            APP_UdpSetOutgoingInterface(msg, interfaceIndex);

            APP_AddPayload(
                node,
                msg,
                (char*) &response,
                RIP_HEADER_SIZE + RIP_RTE_SIZE * rteIndex);

            APP_UdpSend(
                node,
                msg,
                RANDOM_nrand(dataPtr->updateSeed)
                    % (clocktype) RIP_STARTUP_DELAY);

            if (type == RIP_CHANGED_ROUTES)
            {
                // Increment stat for number of triggered update Packets
                dataPtr->stats.numTriggeredPackets++;
            }
            else if (type == RIP_REQUESTED_ROUTES ||
                type == RIP_REQUESTED_COMPATIBLE_ROUTES)
            {
                // Increment stat for number of response packets sent 
                // for received request Packets

                dataPtr->stats.numResponseToRequestsSent++;
            }
            else
            {
                // Increment stat for number of regular update Packets
                dataPtr->stats.numRegularPackets++;
            }
        }
    }
}

// FUNCTION RipSendRequest
// PURPOSE  Sends a RIP Request message out the specified interface.
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  type:   ALL_ROUTES(inital request) or CHANGED_ROUTES(dignostic requests)
static void RipSendRequest(Node* node,
                           int interfaceIndex,
                           RipResponseType type) {

#ifdef DEBUG
        char cbuf[20];
        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
        printf("Rip: %s s, node %u, Preparing to send on interface %d\n",
            cbuf,node->nodeId,interfaceIndex);
#endif
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    unsigned routeIndex;
    RipPacket request;
    request.command = RIP_REQUEST;
    int rteIndex = 0;

    if ((dataPtr->version == RIP_VERSION_2) &&
        (dataPtr->ripCompatibility[interfaceIndex] != RIPv1_ONLY))
    {
        request.version = RIP_VERSION_2;
    }
    else
    {
        request.version = RIP_VERSION_1;
    }
    request.mustBeZero = 0;
    routeIndex = 0;
#ifdef DEBUG
        char address[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(
            dataPtr->routeTable[routeIndex].destAddress,address);
        printf("Rip: %s s, node %u, route %s - ",cbuf,node->nodeId,address);
#endif
    if (type == RIP_ALL_ROUTES) {
        request.rtes[rteIndex].afi = 0;
        request.rtes[rteIndex].ipAddress = 0;
        request.rtes[rteIndex].routeTag = 0;
        request.rtes[rteIndex].subnetMask = 0;
        request.rtes[rteIndex].nextHop = 0;
        request.rtes[rteIndex].metric = RIP_INFINITY;
#ifdef IPNE_INTERFACE

        //Convert response.rtes[rteIndex] to network byte order for IPNE
        RipRte* rte = &request.rtes[rteIndex];
        RipResponseSwapBytes(rte);
#endif
        NodeAddress destAddress;
        if (dataPtr->ripCompatibility[interfaceIndex] == RIPv2_ONLY)
        {
            destAddress = RIP_MULTICAST_ADDRESS;
        }
        else
        {
            if (NetworkIpIsWiredNetwork(node, interfaceIndex))
            {
                destAddress =
                    NetworkIpGetInterfaceBroadcastAddress(node,
                                                          interfaceIndex);
            }
            else
            {
                destAddress = ANY_DEST;
            }
        }
        // Send Response message with CONTROL packet priority.
        // NetworkIpGetInterfaceBroadcastAddress() is used to ensure
        // that the packet is sent out the correct interface.
        // ANY_IP as the source IP address is interpreted at IP
        // to mean that IP will assign the source IP address
        // depending on the actual interface used.

#ifdef DEBUG
        char address1[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(destAddress,address1);
        printf("Rip: %s s, node %u, Sent packet to UDP, dst %s\n",
               cbuf,node->nodeId,address1);
#endif
        Message *msg = APP_UdpCreateMessage(
            node,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            (short) APP_ROUTING_RIP,
            destAddress,
            (short) APP_ROUTING_RIP,
            TRACE_RIP,
            IPTOS_PREC_INTERNETCONTROL);

        APP_UdpSetOutgoingInterface(msg, interfaceIndex);

        APP_AddPayload(
            node,
            msg,
            (char*) &request,
            RIP_HEADER_SIZE + RIP_RTE_SIZE);

        APP_UdpSend(
            node,
            msg,
            RANDOM_nrand(dataPtr->updateSeed)
                % (clocktype) RIP_STARTUP_DELAY);

        // Increment stat for number of Request messages sent.
        dataPtr->stats.numRequestsSent++;
    }
}

// FUNCTION RipResponseSwapBytes
// PURPOSE  Swap Bytes of RIP RTE fields
// Parameters:
// rte:   Pointer to RTE data

void RipResponseSwapBytes(RipRte* rte)
{
    EXTERNAL_ntoh(&rte->afi,sizeof(rte->afi));
    EXTERNAL_ntoh(&rte->routeTag,sizeof(rte->routeTag));
    EXTERNAL_ntoh(&rte->ipAddress,sizeof(rte->ipAddress));
    EXTERNAL_ntoh(&rte->subnetMask,sizeof(rte->subnetMask));
    EXTERNAL_ntoh(&rte->nextHop,sizeof(rte->nextHop));
    EXTERNAL_ntoh(&rte->metric,sizeof(rte->metric));
}

// FUNCTION RipProcessRequest
// PURPOSE  Processes received RIP Request message.
// Parameters:
//  node:   Pointer to node
//  msg:    Pointer to message with RIP Request message.
static void RipProcessRequest(Node* node,Message* msg) 
{

    RipData* dataPtr = (RipData*) node->appData.routingVar;
    RipPacket* requestPtr = (RipPacket*) msg->packet;
    unsigned numRtes = (msg->packetSize - RIP_HEADER_SIZE) / RIP_RTE_SIZE;
    UdpToAppRecv* info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
    NodeAddress sourceAddress = GetIPv4Address(info->sourceAddr);
    NodeAddress destAddress = GetIPv4Address(info->destAddr);
    int incomingInterfaceIndex = info->incomingInterfaceIndex;
    unsigned metric = 0;

    if (NetworkIpIsMyIP(node, sourceAddress) &&
        destAddress == RIP_MULTICAST_ADDRESS &&
        incomingInterfaceIndex == CPU_INTERFACE)
    {
        // this packet was looped back to us by IP (i.e.
        // never left this node)... ignore these packets.
        return;
    }

    if (requestPtr->version == RIP_VERSION_1 && 
        dataPtr->ripCompatibility[incomingInterfaceIndex] == RIPv2_ONLY)
    {
        // For compatibility -
        //if RIP2 router receives RIP1 request it responds with RIP1 packet
        //If RIP2 router can send only RIP2 messages, then it does nothing
        // just increment uncompatible request received stats and return
        // If RIP1 router receive RIP2 request it does nothing
        // only increment uncompatible request received stats and return

        dataPtr->stats.numInvalidRipPacketsReceived++;
        return ;
    }

    ERROR_Assert(
        numRtes != 0 && numRtes <= RIP_MAX_RTE,
        "RIP Request message contains 0 or more than 25 RTEs");

    // Increment stat for number of Response messages received.
    dataPtr->stats.numRequestsReceived++;

#ifdef DEBUG
    char cbuf[20];
    unsigned i;
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    char address[MAX_STRING_LENGTH];
    IO_ConvertIpAddressToString(sourceAddress,address);
    printf("Rip: %s s, node %u, RCV Route broadcast, "
        "Received packet from UDP, src %s\n",cbuf,node->nodeId,address);

    // print the request packet payload
    printf("Rip: %s s, node %u, --- Update vector, "
        "(dest subnet nextHop dist)\n",cbuf,node->nodeId);
    for (i = 0; i < numRtes; i++)
    {
        RipRte* rtePtr = &requestPtr->rtes[i];
        printf("Rip: %s s, node %u, \t",cbuf,node->nodeId);
        IO_ConvertIpAddressToString(rtePtr->ipAddress,address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(rtePtr->subnetMask,address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(rtePtr->nextHop,address);
        printf("%s \t",address);
        printf("%d\n",rtePtr->metric);
      }
    // print the pre update routing table
    RipPrintRouteTable(node,"Pre Update");
#endif

    // whole table request
    // process route entry in table add it and then send response
    RipRte* rtePtr;
    rtePtr= &requestPtr->rtes[0];
#ifdef IPNE_INTERFACE
        // Swap RTEs from network to host here for IPNE.
        RipResponseSwapBytes(rtePtr);
#endif
    if (numRtes==1 && requestPtr->rtes[0].afi==0 &&
        requestPtr->rtes[0].metric == 16)
    {
        if (!NetworkIpIsWiredNetwork(node, incomingInterfaceIndex)) {

            // Response must be unicast to requesting node. In case of
            // Wireless subnet there won't be any default route available.
            // Update IP routing table with new route

            NetworkUpdateForwardingTable(
                node,
                sourceAddress,
                ANY_DEST,
                sourceAddress,
                incomingInterfaceIndex,
                metric,
                ROUTING_PROTOCOL_RIP);
        }
        if (dataPtr->version == RIP_VERSION_2 && 
            requestPtr->version == RIP_VERSION_1)
        {
            RipSendResponse(node,
                            incomingInterfaceIndex,
                            RIP_REQUESTED_COMPATIBLE_ROUTES,
                            msg);
        }
        else
        {
            RipSendResponse(node,
                            incomingInterfaceIndex,
                            RIP_REQUESTED_ROUTES,
                            msg);
        }
    }
    else
    {
        // dignostic request
        ERROR_ReportWarning(
            "RIP does not support Dignostic Request messages");
    }
}


// FUNCTION RipProcessResponse
// PURPOSE  Processes a received RIP Response message.
// Parameters:
//  node:   Pointer to node
//  msg:    Pointer to message with RIP Response message.
static void RipProcessResponse(Node* node,Message* msg)
{

    RipData* dataPtr = (RipData*) node->appData.routingVar;
    RipPacket* responsePtr = (RipPacket*) msg->packet;
    unsigned numRtes = (msg->packetSize - RIP_HEADER_SIZE) / RIP_RTE_SIZE;
    UdpToAppRecv* info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
    NodeAddress sourceAddress = GetIPv4Address(info->sourceAddr);
    NodeAddress destAddress = GetIPv4Address(info->destAddr);
    NodeAddress nextHopAddress = 0;
    int incomingInterfaceIndex = info->incomingInterfaceIndex;
    unsigned short routeTag = 0;
    unsigned i;

    if (NetworkIpIsMyIP(node, sourceAddress) &&
        destAddress == RIP_MULTICAST_ADDRESS &&
        incomingInterfaceIndex == CPU_INTERFACE)
    {
        // this packet was looped back to us by IP (i.e.
        // never left this node)... ignore these packets.
        return;
    }

    if (numRtes == 0 || numRtes > RIP_MAX_RTE)
    {
        dataPtr->stats.numInvalidRipPacketsReceived++;
        return;
    }

    // Checking for authentication route entry
    if (dataPtr->version == 2)
    {
        RipRte* authenticatePtr = &responsePtr->rtes[0];
        if (authenticatePtr->afi == RIP_AUTHENTICATION_IDENTIFIER)
        {
            // authentication type = routeTag
            // type = 1 means simple text authentication
            // type = 2 means MD5 Authentication
            // For RIPv2, Qualnet supports only unAuthenticated mode
            // So it will discard the received Authenticated Response

            dataPtr->stats.numInvalidRipPacketsReceived++;
            return;
        }
    }
    // Increment stat for number of Response messages received.
    dataPtr->stats.numResponsesReceived++;

#ifdef DEBUG
    char cbuf[20];
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    char address[MAX_STRING_LENGTH];
    IO_ConvertIpAddressToString(sourceAddress,address);
    printf("Rip: %s s, node %u, RCV Route broadcast, "
        "Received packet from UDP, src %s\n",cbuf,node->nodeId,address);

    // print the update packet payload
    printf("Rip: %s s, node %u, --- Update vector, "
        "(dest subnet nextHop dist)\n",cbuf,node->nodeId);
    for (i = 0; i < numRtes; i++)
    {
        RipRte* rtePtr = &responsePtr->rtes[i];
        printf("Rip: %s s, node %u, \t",cbuf,node->nodeId);
        IO_ConvertIpAddressToString(rtePtr->ipAddress,address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(rtePtr->subnetMask,address);
        printf("%s \t",address);
        IO_ConvertIpAddressToString(rtePtr->nextHop,address);
        printf("%s \t",address);
        printf("%d\n",rtePtr->metric);
    }

    // print the pre update routing table
    RipPrintRouteTable(node,"Pre Update");
#endif

    // Loop through all RTEs contained in Response packet
    for (i = 0; i < numRtes; i++)
    {
        RipRoute* routePtr;
        RipRte* rtePtr = &responsePtr->rtes[i];
        if (rtePtr->afi == RIP_AUTHENTICATION_IDENTIFIER)
        {
            // For RIP1 ignore entries starting with
            // AUTHENTICATION_IDENTIFIER

            continue;
        }

#ifdef IPNE_INTERFACE
        // Swap RTEs from network to host here for IPNE
        RipResponseSwapBytes(rtePtr);
#endif

  
        RipRoute* newRoutePtr;
        NodeAddress subnetMask = 8;

        ERROR_Assert(
            rtePtr->nextHop != (NodeAddress) NETWORK_UNREACHABLE,
            "RIP RTE next hop address should never be NETWORK_UNREACHABLE");
        if (NetworkIpIsMyIP(node, rtePtr->ipAddress))
        {
            // if it is to my attached netowrk
            continue;
        }
        if (rtePtr->nextHop && RipGetRoute(node, rtePtr->nextHop) &&
            !RipIsInADifferentMajorNetwork(rtePtr->nextHop,
            NetworkIpGetInterfaceAddress(node, incomingInterfaceIndex)) &&
            (NetworkIpIsWiredNetwork(node, incomingInterfaceIndex)))
        {
            nextHopAddress = rtePtr->nextHop;
        }
        else{
            nextHopAddress = sourceAddress;
        }

        if (dataPtr->version == RIP_VERSION_1 ||
            responsePtr->version == RIP_VERSION_1)
        {
            if (NetworkIpIsWiredNetwork(node, incomingInterfaceIndex))
            {
                subnetMask = RipReturnMaskFromIPAddress(rtePtr->ipAddress);
            }
            else
            {
                subnetMask = ANY_DEST;
            }
            routeTag = 0;
        }
        else
        {
            routeTag = rtePtr->routeTag;
            subnetMask = rtePtr->subnetMask;
        }
        // Attempt to obtain route from RIP route table using IP
        // address of the route destination.

        routePtr = RipGetRoute(node, rtePtr->ipAddress);

        bool found=false;
        if (!routePtr)
        {
            NodeAddress nwAddress;
            nwAddress=rtePtr->ipAddress & 
                RipReturnMaskFromIPAddress(rtePtr->ipAddress);
            if (nwAddress==rtePtr->ipAddress)
            {
                //ipAddress is a network address
                found = false;
                Int32 j = 0;
                for (j = 0; j < dataPtr->numRoutes; j++)
                {
                    //search for local address in route table with summarized
                    //route in response packet
                    if (!RipIsInADifferentMajorNetwork(rtePtr->ipAddress,
                        dataPtr->routeTable[j].destAddress))
                    {
                        // summarized route of packet found as local 
                        //address in route table
                        found =true;
                         break;
                    }
                }
                if (found==true)
                {
                    // ignore summarized route for internal network
                    continue;
                }
            }
        }
        if (!routePtr || (routePtr && routePtr->flushed == TRUE))
        {
            // Route does not exist in RIP route table, or does exist
            // but has been marked as flushed.
            if (rtePtr->metric == RIP_INFINITY)
            {
                // Ignore route with infinite distance if the route
                // does not exist in our own route table.
                // Continue to next RTE.
                continue;
            }

            // Route has non-infinite distance, so either add the route
            // to the route table or recover the flushed route.
            if (!routePtr)
            {
                // RipAddRoute() will flag the new route as changed (for
                // triggered updates).

                newRoutePtr = RipAddRoute(
                                  node,
                                  routeTag,
                                  rtePtr->ipAddress,
                                  subnetMask,
                                  nextHopAddress,
                                  rtePtr->metric,
                                  incomingInterfaceIndex,
                                  incomingInterfaceIndex);
            }
            else
            {
                // Recover flushed route.
                newRoutePtr = routePtr;
                newRoutePtr->nextHop = nextHopAddress;
                newRoutePtr->metric = rtePtr->metric;
                newRoutePtr->outgoingInterfaceIndex = incomingInterfaceIndex;
                newRoutePtr->learnedInterfaceIndex = incomingInterfaceIndex;
                newRoutePtr->changed = TRUE;   // Flag route as changed.
                newRoutePtr->flushed = FALSE;
            }

            // Update IP routing table with new route.
            NetworkUpdateForwardingTable(
                node,
                rtePtr->ipAddress,
                subnetMask,
                nextHopAddress,
                incomingInterfaceIndex,
                rtePtr->metric,
                ROUTING_PROTOCOL_RIP);

            if (newRoutePtr->flushTime != 0)
            {
                 routePtr->flushTime = 0;
            }
            // Start route-timeout timer.
            RipSetRouteTimer(
                node, &newRoutePtr->timeoutTime, newRoutePtr->destAddress,
                RIP_TIMEOUT_DELAY, RIP_TIMEOUT);

            // Schedule triggered update.
            RipScheduleTriggeredUpdate(node);

            // Continue to next RTE.
            continue;
        }

        // For the case of an existing, non-flushed route:  there are
        // three conditions where the route is considered changed, as
        // below.

        if ((routePtr->nextHop == sourceAddress
             && (rtePtr->metric != routePtr->metric
                 || routePtr->learnedInterfaceIndex
                    != incomingInterfaceIndex))
            ||
            (rtePtr->metric < routePtr->metric)
            ||
            (routePtr->timeoutTime != 0
             && routePtr->nextHop != nextHopAddress
             && rtePtr->metric != RIP_INFINITY
             && rtePtr->metric == routePtr->metric
             && node->getNodeTime() >= routePtr->timeoutTime - RIP_TIMEOUT_DELAY / 2))
        {
            BOOL updateForwardingTable = FALSE;

            // Update metric if necessary.
            if (routePtr->metric != rtePtr->metric)
            {
                routePtr->metric = rtePtr->metric;
                updateForwardingTable = TRUE;
            }

            // Update interface if necessary
            if (routePtr->learnedInterfaceIndex != incomingInterfaceIndex)
            {
                routePtr->learnedInterfaceIndex = incomingInterfaceIndex;
                routePtr->outgoingInterfaceIndex = incomingInterfaceIndex;
                updateForwardingTable = TRUE;
            }

            // Update next hop if necessary.
            if (routePtr->nextHop != nextHopAddress)
            {
                routePtr->nextHop = nextHopAddress;
                updateForwardingTable = TRUE;
            }

            // Changed next hop or interface, so update IP routing table.
            // If the route is to be marked invalid, the IP routing
            // table update is done later.
            if (updateForwardingTable)
            {
                if (routePtr->metric != RIP_INFINITY)
                {
                    NetworkUpdateForwardingTable(
                        node,
                        rtePtr->ipAddress,
                        subnetMask,
                        nextHopAddress,
                        incomingInterfaceIndex,
                        rtePtr->metric,
                        ROUTING_PROTOCOL_RIP);
                }
            }
            if (routePtr->metric == RIP_INFINITY)
            {
                // Mark route as invalid in the IP routing table.
                // (Route is retained in RIP route table.)

                NetworkUpdateForwardingTable(
                    node,
                    rtePtr->ipAddress,
                    subnetMask,
                    (NodeAddress) NETWORK_UNREACHABLE,
                    ANY_INTERFACE,
                    RIP_INFINITY,
                    ROUTING_PROTOCOL_RIP);

                // Cancel route-timeout timer.
                routePtr->timeoutTime = 0;

                // Start route-flush timer.
                RipSetRouteTimer(
                    node, &routePtr->flushTime, routePtr->destAddress,
                    RIP_FLUSH_DELAY, RIP_FLUSH);
            }
            else
            {
                // Cancel route-flush timer if active.
                routePtr->flushTime = 0;

                // Route was not marked invalid in the IP routing table,
                // so refresh the route.
                // Reinit route-timeout timer.

                RipSetRouteTimer(
                    node, &routePtr->timeoutTime, routePtr->destAddress,
                    RIP_TIMEOUT_DELAY, RIP_TIMEOUT);
            }
            // Flag route as changed if it isn't already.
            routePtr->changed = TRUE;

            // Schedule triggered update.
            RipScheduleTriggeredUpdate(node);

            // Continue to next RTE.
            continue;
        }//if//
        // Route is not considered changed, so just refresh route.
        if (routePtr->nextHop == sourceAddress && routePtr->flushTime == 0)
        {
            // Cancel route-flush timer if active.
            routePtr->flushTime = 0;
            // Reinit route-timeout timer.
            RipSetRouteTimer(
                node, &routePtr->timeoutTime, routePtr->destAddress,
                RIP_TIMEOUT_DELAY, RIP_TIMEOUT);
        }
        // Continue to next RTE.
    }//for//
#ifdef DEBUG
    // print the post update routing table
    RipPrintRouteTable(node,"Post Update");
#endif
}


// FUNCTION RipScheduleTriggeredUpdate
// PURPOSE  Schedules a triggered update if a regular update isn't
//          scheduled prior to it.
// Parameters:
//  node:   Pointer to node
static void RipScheduleTriggeredUpdate(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RipData* dataPtr = (RipData*) node->appData.routingVar;

    clocktype delay =
        RIP_TRIGGER_DELAY
        - (RANDOM_nrand(dataPtr->triggerSeed)
           % (clocktype) ((double) RIP_TRIGGER_DELAY * RIP_TRIGGER_JITTER));

    // Schedule a triggered update if both of the following are true:
    // a) A triggered update is not already scheduled for the node, and
    // b) Next regular update is not very soon.

    if (dataPtr->triggeredUpdateScheduled == FALSE
        && dataPtr->nextRegularUpdateTime > node->getNodeTime() + delay)
    {
        Message* newMsg;

        // Schedule triggered update.
        newMsg = MESSAGE_Alloc(node,
                                APP_LAYER,
                                APP_ROUTING_RIP,
                                MSG_APP_RIP_TriggeredUpdateAlarm);
        // Add some jitter.
        // delay == (1, 5] seconds.
        MESSAGE_Send(node, newMsg, delay);

        // Set flag indicating a triggered update has been scheduled.
        dataPtr->triggeredUpdateScheduled = TRUE;
    }
}


// FUNCTION RipSetRouteTimer
// PURPOSE  Sets a route-timeout or route-flush timer for a
//          particular route in the RIP route table.
// Parameters:
//  node:   Pointer to node
//  timePtr:    Storage for timer alarm time for route
//  destAddress:    IP address of route destination
//  delay:  Timer delay.
//  type:   ALL_ROUTES (regular) or CHANGED_ROUTES (triggered update)
static void RipSetRouteTimer(Node* node,
                             clocktype* timePtr,
                             NodeAddress destAddress,
                             clocktype delay,
                             RipRouteTimerType type) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    clocktype scheduledTime = node->getNodeTime() + delay;
    ERROR_Assert(
        delay != 0,
        "RIP SetRouteTimer() does not accept 0 delay");
    // Determine if a timer of the same type is already scheduled using
    // the value of *timePtr.
    if (*timePtr == 0)
    {
        // Timer of the same type is not running.
        Message* newMsg;
        RipRouteTimerMsgInfo* info;
        // Set QualNet event for appropriate time.
        newMsg = MESSAGE_Alloc(node,
                                APP_LAYER,
                                APP_ROUTING_RIP,
                                MSG_APP_RIP_RouteTimerAlarm);
        // Insert IP address of route destination, and timer type in
        // QualNet event.
        MESSAGE_InfoAlloc(node, newMsg, sizeof(RipRouteTimerMsgInfo));
        info = (RipRouteTimerMsgInfo*) MESSAGE_ReturnInfo(newMsg);
        info->type = type;
        info->destAddress = destAddress;
        MESSAGE_Send(node, newMsg, delay);
    }
    else
    {
        // Timer of the same type is currently running.
        // Don't schedule a new QualNet event.
        // Setting *timePtr to the new value is all that's required;
        // the scheduling of the new event is done

        ERROR_Assert(*timePtr >= node->getNodeTime(),
                     "RIP route timer in the past");
        ERROR_Assert(
            scheduledTime >= *timePtr,
            "RIP restarted route timer alarm time must be in the"
            " future of the old timer");

        if (*timePtr == scheduledTime)
        {
            // Return early if new alarm time and old alarm time are
            // equal.
            return;
        }
    }
    // Set alarm time for route in RIP route table.
    *timePtr = scheduledTime;
}


// FUNCTION RipHandleRouteTimeout
// PURPOSE  Processes a route timeout:  updates IP routing table,
//          sets RIP distance for route to infinity, schedules
// Parameters:
//  node:   Pointer to node.
//  routePtr:   Pointer to RIP route.
static void RipHandleRouteTimeout(Node* node,RipRoute* routePtr) {

//warning: Don't remove the opening and the closing brace
//add your code here:

    RipData* dataPtr = (RipData*) node->appData.routingVar;

    ERROR_Assert(
        routePtr->metric != RIP_INFINITY,
        "RIP timed out route should not already have infinite distance");

    ERROR_Assert(
        routePtr->flushTime == 0,
        "RIP timed out route should not have a flush timer active");

    // Increment stat for number of route-timeout events.
    dataPtr->stats.numRouteTimeouts++;

    // Mark route as invalid in IP routing table.
    // (Route is retained in RIP route table.)
    NetworkUpdateForwardingTable(
        node,
        routePtr->destAddress,
        routePtr->subnetMask,
        (NodeAddress) NETWORK_UNREACHABLE,
        ANY_INTERFACE,
        RIP_INFINITY,
        ROUTING_PROTOCOL_RIP);

    // Set distance for route to infinity.  Flag route as changed.
    routePtr->metric = RIP_INFINITY;
    routePtr->changed = TRUE;

    // Schedule triggered update.
    RipScheduleTriggeredUpdate(node);

   // Start flush timer.
    RipSetRouteTimer(
        node, &routePtr->flushTime, routePtr->destAddress,
        RIP_FLUSH_DELAY, RIP_FLUSH);
}


// FUNCTION RipInitRouteTable
// PURPOSE  Initializes a route table.
// Parameters:
//  node:   Pointer to node.
static void RipInitRouteTable(Node* node) {

//warning: Don't remove the opening and the closing brace
//add your code here:
    RipData* dataPtr = (RipData*) node->appData.routingVar;

    // Allocate initial space for route.  Record size.
    dataPtr->routeTable =
        (RipRoute*) MEM_malloc(RIP_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED
                             * sizeof(RipRoute));

    dataPtr->numRoutesAllocated =
        RIP_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED;

    // Initialize number of routes.
    dataPtr->numRoutes = 0;
}


// FUNCTION RipGetRoute
// PURPOSE  Finds a route in the RIP route table using the IP
//          address of the route destination.
// Parameters:
//  node:   Pointer to node.
//  destAddress:    IP address.
static RipRoute* RipGetRoute(Node* node,NodeAddress destAddress) {

//warning: Don't remove the opening and the closing brace
//add your code here:

    RipData* dataPtr = (RipData*) node->appData.routingVar;
    int top;
    int bottom;
    int middle;
    RipRoute* routePtr;

    // Return early if no routes.
    if (dataPtr->numRoutes == 0)
    {
        return NULL;
    }
    // Search route table.
    top = 0;
    bottom = dataPtr->numRoutes - 1;
    middle = (bottom + top) / 2;
    if (destAddress == dataPtr->routeTable[top].destAddress)
    {
        return &dataPtr->routeTable[top];
    }
    if (destAddress == dataPtr->routeTable[bottom].destAddress)
    {
        return &dataPtr->routeTable[bottom];
    }
    while (middle != top)
    {
        routePtr = &dataPtr->routeTable[middle];
        if (destAddress == routePtr->destAddress)
        {
            return routePtr;
        }
        else
        if (destAddress < routePtr->destAddress)
        {
            bottom = middle;
        }
        else
        {
            top = middle;
        }
        middle = (bottom + top) / 2;
    }
    // Could not find route.
    return NULL;
}


// FUNCTION RipAddRoute
// PURPOSE  Adds a route to the route table.  To modify an existing
//          route, use GetRoute() and modify the route directly.
// Parameters:
//  node:   Pointer to node.
//  destAddress:    IP address.
//  subnetMask: Subnet mask
//  nextHop:    Next hop IP address.
//  metric: Number of hops
//  outgoingInterfaceIndex: outgoing interface index
//  learnedInterfaceIndex:  interface  through which node learned the route
static RipRoute* RipAddRoute(Node* node,
                             unsigned short routeTag,
                             NodeAddress destAddress,
                             NodeAddress subnetMask,
                             NodeAddress nextHop,
                             int metric,
                             int outgoingInterfaceIndex,
                             int learnedInterfaceIndex) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    int index;
    // Have we used up all the allocated spaces for routes?
    if (dataPtr->numRoutes == dataPtr->numRoutesAllocated)
    {
        // Table filled, so reallocate double memory for route table.
        RipRoute* oldRouteTable;
        unsigned i;
        oldRouteTable = dataPtr->routeTable;
        dataPtr->routeTable =
            (RipRoute*)
            MEM_malloc(2 * dataPtr->numRoutesAllocated * sizeof(RipRoute));
            for (i = 0; i < dataPtr->numRoutes; i++)
        {
            dataPtr->routeTable[i] = oldRouteTable[i];
        }
        MEM_free(oldRouteTable);
        dataPtr->numRoutesAllocated *= 2;
    }
    // Insert route.
    index = dataPtr->numRoutes;
    dataPtr->numRoutes++;
    while (1)
    {
        RipRoute* routePtr;
        if (index != 0
            && destAddress <= dataPtr->routeTable[index - 1].destAddress)
        {
            if (destAddress == dataPtr->routeTable[index - 1].destAddress)
            {
                // Route already exists.
                ERROR_ReportError("Cannot add duplicate route");
            }
            dataPtr->routeTable[index] = dataPtr->routeTable[index - 1];
            index--;
            continue;
        }
        routePtr = &dataPtr->routeTable[index];
        routePtr->routeTag    = routeTag;
        routePtr->destAddress = destAddress;
        routePtr->subnetMask  = subnetMask;
        routePtr->nextHop     = nextHop;
        routePtr->metric      = metric;
        routePtr->outgoingInterfaceIndex = outgoingInterfaceIndex;
        routePtr->learnedInterfaceIndex  = learnedInterfaceIndex;
        routePtr->timeoutTime = 0;
        routePtr->flushTime   = 0;
        routePtr->changed     = TRUE;
        routePtr->flushed     = FALSE;
        return routePtr;
    }
    // Not reachable.
    ERROR_ReportError("Code not reachable");
    return NULL;
}


// FUNCTION RipHandleRouteFlush
// PURPOSE  Marks a route in the RIP route table as flushed.  For
//          efficiency, the route is not physically removed from the
//          RIP routing table.
// Parameters:
//  node:   Pointer to node
//  routePtr:   Pointer to RIP route
static void RipHandleRouteFlush(Node* node,RipRoute* routePtr) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    ERROR_Assert(
        routePtr->metric == RIP_INFINITY,
        "RIP route to be flushed should have inifinite distance");
    ERROR_Assert(
        routePtr->timeoutTime == 0,
        "RIP route to be flushed should not have an active timeout timer");
    // Mark route as flushed.
    routePtr->flushed = TRUE;
}


//--------------------------------------------------------------------------
// FUNCTION     : RipIsInADifferentMajorNetwork()
//
// PURPOSE      : Check if two addresses are attached with a different major
//                network
//
// PARAMETERS   : nodeAddress1 - first node ipaddress
//                nodeAddress2 - second node ipaddress
// RETURN VALUE : Returns true if attached to a different major network
//--------------------------------------------------------------------------
static
BOOL RipIsInADifferentMajorNetwork(
    NodeAddress nodeAddress1,
    NodeAddress nodeAddress2)
{
    BOOL differentNetworks = TRUE;
    NodeAddress networkAddress1;
    NodeAddress networkAddress2;
    networkAddress1=nodeAddress1 & RipReturnMaskFromIPAddress(nodeAddress1);
    networkAddress2=nodeAddress2 & RipReturnMaskFromIPAddress(nodeAddress2);
    if (networkAddress1 == networkAddress2)
    {
        differentNetworks = FALSE;
    }
    return differentNetworks;
}

// FUNCTION RipReturnMaskFromIPAddress
// PURPOSE  getting  mask form ip address
// Parameters:
//  address:    Ip address
static NodeAddress RipReturnMaskFromIPAddress(NodeAddress address) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    address = address >>24;
    if (address > 0 && address < 128)
    {
        return 0xFF000000;
    }
    else if (address > 127 && address < 192)
    {
        return 0xFFFF0000;
    }
    else if (address > 191 && address < 224 )
    {
        return 0xFFFFFF00;
    }
    else if (address > 223 && address < 240 )
    {
        return 0xFFFFFFFF;
    }
    else
    {
        return 0;
    }
}


// FUNCTION RipGetVersionAndSplitHorizon
// PURPOSE  Get version of Rip and check if Split-Horizon is enable
// Parameters:
//  node:   Pointer to node.
//  nodeInput:  Pointer to node input
//  interfaceIndex: index of interface
//  version:    Rip version
//  splitHorizon:   get the value of spliHorizon
static void RipGetVersionAndSplitHorizon(Node* node,
                                         const NodeInput* nodeInput,
                                         int interfaceIndex,
                                         unsigned int* version,
                                         RipSplitHorizonType* splitHorizon)
{
//warning: Don't remove the opening and the closing brace
//add your code here:

    BOOL retVal = 0;
    char buf[MAX_STRING_LENGTH];
    IO_ReadString(
        node->nodeId,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        nodeInput,
        "RIP-VERSION",
        &retVal,
        buf);
    if (retVal == TRUE)
    {
        if (strcmp(buf, "1") == 0)
        {
            *version = RIP_VERSION_1;
        }
        else
        {
            if (strcmp(buf, "2") == 0)
            {
                *version = RIP_VERSION_2;
            }
            else
            {
                ERROR_ReportError("RIP Version should be either 1 or 2");
            }
        }
    }
    else
    {
        *version = RIP_VERSION_2;  // By Default version is 2
    }
    IO_ReadString(
        node->nodeId,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        nodeInput,
        "SPLIT-HORIZON",
        &retVal,
        buf);
    if (retVal == TRUE)
    {
        if (strcmp(buf, "NO") == 0)
        {
            *splitHorizon = RIP_SPLIT_HORIZON_OFF;
        }
        else if (strcmp(buf, "SIMPLE") == 0)
        {
            *splitHorizon = RIP_SPLIT_HORIZON_SIMPLE;
        }
        else if (strcmp(buf, "POISONED-REVERSE") == 0)
        {
            *splitHorizon = RIP_SPLIT_HORIZON_POISONED_REVERSE;
        }
        else
        {
           ERROR_ReportError("Expecting NO/SIMPLE/POISONED-REVERSE");
        }
    }
        else
    {
        // By Default Split-Horizon is applied
        *splitHorizon = RIP_SPLIT_HORIZON_SIMPLE;
    }
}


// FUNCTION RipClearChangedRouteFlags
// PURPOSE  Reset 'changed-flag'  for all routing entry
// Parameters:
//  node:   Pointer to node
static void RipClearChangedRouteFlags(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    unsigned routeIndex = 0;
    for (routeIndex = 0; routeIndex < dataPtr->numRoutes; routeIndex++)
    {
        if (dataPtr->routeTable[routeIndex].changed == TRUE)
        {
            // Clear changed-route flags.
            dataPtr->routeTable[routeIndex].changed = FALSE;
        }
    }
}


// FUNCTION RipInterfaceStatusHandler
// PURPOSE  Handle interface fault
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  state:  state of interface
static void RipInterfaceStatusHandler(Node* node,
                                      int interfaceIndex,
                                      MacInterfaceState state)
{
//warning: Don't remove the opening and the closing brace
//add your code here:

    RipData* dataPtr = (RipData*) node->appData.routingVar;
    unsigned int routeIndex = 0;
    RipRoute* routePtr = NULL;
    NodeAddress networkAddress = 0;

    if (NetworkIpIsWiredNetwork(node, interfaceIndex))
    {
        networkAddress = NetworkIpGetInterfaceNetworkAddress(
                             node,
                             interfaceIndex);
    }
    else
    {
        networkAddress = NetworkIpGetInterfaceAddress(
                             node,
                             interfaceIndex);
    }
    if (state == MAC_INTERFACE_DISABLE)
    {
        for (routeIndex = 0; routeIndex < dataPtr->numRoutes; routeIndex++)
        {
            routePtr = &dataPtr->routeTable[routeIndex];
            if (routePtr->outgoingInterfaceIndex
                  == interfaceIndex)
            {
                // Set distance for route to infinity.
                // Flag route as changed.
                routePtr->metric = RIP_INFINITY;
                routePtr->changed = TRUE;

                NetworkUpdateForwardingTable(
                    node,
                    routePtr->destAddress,
                    routePtr->subnetMask,
                    (NodeAddress)NETWORK_UNREACHABLE,
                    routePtr->outgoingInterfaceIndex,
                    RIP_INFINITY,
                    ROUTING_PROTOCOL_RIP);

                // Cancel route-timeout timer.
                routePtr->timeoutTime = 0;

                // Start route-flush timer.
                RipSetRouteTimer(node,
                                 &routePtr->flushTime,
                                 routePtr->destAddress,
                                 RIP_FLUSH_DELAY,
                                 RIP_FLUSH);
            }
        }
    }
    else if (state == MAC_INTERFACE_ENABLE)
    {
        for (routeIndex = 0; routeIndex < dataPtr->numRoutes; routeIndex++)
        {
            routePtr = &dataPtr->routeTable[routeIndex];

            if (routePtr->destAddress == networkAddress)
            {
                routePtr->nextHop = NetworkIpGetInterfaceAddress(
                                        node,
                                        interfaceIndex);
                routePtr->outgoingInterfaceIndex = interfaceIndex;
                routePtr->learnedInterfaceIndex = interfaceIndex;
                routePtr->metric = 0;

                if (routePtr->changed != TRUE)
                {
                    routePtr->changed = TRUE;
                }
                if (routePtr->flushed != FALSE)
                {
                    // make entry alive
                    routePtr->flushed = FALSE;
                }
                if (routePtr->timeoutTime != 0)
                {
                    // Cancel route-timeout timer.
                    routePtr->timeoutTime = 0;
                }
                if (routePtr->flushTime != 0)
                {
                    // Cancel route-flush timer.
                    routePtr->flushTime = 0;
                }

                NetworkUpdateForwardingTable(
                        node,
                        routePtr->destAddress,
                        routePtr->subnetMask,
                        0,
                        routePtr->outgoingInterfaceIndex,
                        routePtr->metric,
                        ROUTING_PROTOCOL_RIP);
            }
        }
    }
    else
    {
       ERROR_Assert(FALSE, "Unknown MacInterfaceState\n");
    }
    // Schedule triggered update.
    RipScheduleTriggeredUpdate(node);
}


// FUNCTION RipChangeToLowerCase
// PURPOSE  Change any string to lowercase string
// Parameters:
//  buf:    Pointer to string
static void RipChangeToLowerCase(char* buf) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    int i = 0;
    int length = (int)strlen(buf);
    for (i = 0; i < length; i++)
    {
        if (buf[i] > 64 && buf[i] < 91)
        {
            buf[i] = buf[i] + 32;
        }
    }
}


// FUNCTION RipHookToRedistribute
// PURPOSE  Added for route redistribution
// Parameters:
//  node:
//  destAddress:
//  destAddressMask:
//  nextHopAddress:
//  interfaceIndex:
//  routeCost:
void RipHookToRedistribute(Node* node,
                           NodeAddress destAddress,
                           NodeAddress destAddressMask,
                           NodeAddress nextHopAddress,
                           int interfaceIndex,
                           void* routeCost) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RipRoute* routePtr = NULL;
    int cost =  *(int*) routeCost;

    unsigned short routeTag = 0;
    RipData* dataPtr = (RipData*) node->appData.routingVar;
    if (dataPtr->version == RIP_VERSION_2) {
        routeTag = 1; // for external routes routeTag is 1
    }
    else {
        routeTag = 0; // No routeTag
    }

    routePtr = RipGetRoute(
                    node,
                    destAddress);
    if (routePtr != NULL)
    {
        if (routePtr->metric > cost)
        {
            // it is possible routePt->metric is 16 when a new
            // external route is learned
            routePtr->metric = cost;
            routePtr->nextHop = nextHopAddress;
            routePtr->outgoingInterfaceIndex = interfaceIndex;
            routePtr->learnedInterfaceIndex = interfaceIndex;
            routePtr->changed = TRUE;
            // get new route, reset timeout and flushtime
            routePtr->timeoutTime = 0;
            routePtr->flushTime   = 0;
        }
        return;
    }

    routePtr = RipAddRoute(
                    node,
                    routeTag,
                    destAddress,
                    destAddressMask,
                    nextHopAddress,
                    (unsigned) cost,
                    interfaceIndex,
                    interfaceIndex);
    if (routePtr != NULL)
    {
        routePtr->changed = FALSE;
        routePtr->flushed = FALSE;
    }
}



//UserCodeEnd

//State Function Definitions
static void enterRipIdle(Node* node,
                         RipData* dataPtr,
                         Message* msg) {

    //UserCodeStartIdle
    if (msg != NULL)
    {
        MESSAGE_Free(node, msg);
    }

    //UserCodeEndIdle


}

static void enterRipHandleRegularUpdateAlarm(Node* node,
                                             RipData* dataPtr,
                                             Message* msg) {

    //UserCodeStartHandleRegularUpdateAlarm
    int i;
    Message* newMsg;
    clocktype delay;

#ifdef DEBUG
    char cbuf[20];
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    printf("Rip: %s s, node %u, ",cbuf,node->nodeId);
    printf("Handle Regular Update\n");
#endif

    // Increment stat for number of regular update events.
    dataPtr->stats.numRegularUpdateEvents++;

    // Send a response message to UDP on all eligible interfaces.

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (dataPtr->activeInterfaceIndexes[i]
            && NetworkIpInterfaceIsEnabled(node, i))
        {
             RipSendResponse(node, i, RIP_ALL_ROUTES, msg);
        }
    }
    // Schedule next regular update.
    newMsg = MESSAGE_Alloc(node,
                           APP_LAYER,
                           APP_ROUTING_RIP,
                           MSG_APP_RIP_RegularUpdateAlarm);

    // Add some jitter.
    // delay == (25.5, 30] seconds.
    delay = RIP_UPDATE_INTERVAL
            - (RANDOM_nrand(dataPtr->updateSeed)
               % (clocktype)
               ((double) RIP_UPDATE_INTERVAL * RIP_UPDATE_JITTER));

    MESSAGE_Send(node, newMsg, delay);

    // clear Changed-route Flags
    RipClearChangedRouteFlags(node);

    // Record scheduled time of regular update.
    // The triggered update process uses this information.

    dataPtr->nextRegularUpdateTime = node->getNodeTime() + delay;

    //UserCodeEndHandleRegularUpdateAlarm

    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);
}

static void enterRipHandleTriggeredUpdateAlarm(Node* node,
                                               RipData* dataPtr,
                                               Message* msg) {

    //UserCodeStartHandleTriggeredUpdateAlarm
    int i;
#ifdef DEBUG
    char cbuf[20];
    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
    printf("Rip: %s s, node %u, ",cbuf,node->nodeId);
    printf("Handle Triggered Update\n");
#endif

    // Increment stat for number of triggered update events.
     dataPtr->stats.numTriggeredUpdateEvents++;

    // Send changed routes to UDP on all eligible interfaces.
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (dataPtr->activeInterfaceIndexes[i]
            && NetworkIpInterfaceIsEnabled(node, i))
        {
             RipSendResponse(node, i, RIP_CHANGED_ROUTES, msg);
        }
    }

    // Clear changed-route flag
    RipClearChangedRouteFlags(node);

    // Clear triggered update flag.
    dataPtr->triggeredUpdateScheduled = FALSE;

    //UserCodeEndHandleTriggeredUpdateAlarm

    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);
}

// FUNCTION enterRipHandleRequestAlarm
// PURPOSE  Handles the timer event for sending request packet
// Parameters:
//  node:    Pointer to node
//  RipData: Pointer to RIP data structure
//  msg:     Pointer to timer message
static void enterRipHandleRequestAlarm(Node* node,
                                       RipData* dataPtr,
                                       Message* msg)
{
    int i = 0;
    Message* newMsg = NULL;
    clocktype delay = 0;

#ifdef DEBUG
        char cbuf[20];
        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
        printf("Rip: %s s, node %u, ",cbuf,node->nodeId);
        printf("Handle Request Message\n");
#endif

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (dataPtr->activeInterfaceIndexes[i]
            && NetworkIpInterfaceIsEnabled(node, i))
        {
             RipSendRequest(node, i, RIP_ALL_ROUTES);
        }
    }

    // Schedule regular update.
    newMsg = MESSAGE_Alloc(node,
                           APP_LAYER,
                           APP_ROUTING_RIP,
                           MSG_APP_RIP_RegularUpdateAlarm);

    // delay == (25.5, 30] seconds.
    delay = RIP_UPDATE_INTERVAL
            - (RANDOM_nrand(dataPtr->updateSeed)
               % (clocktype)
               ((double) RIP_UPDATE_INTERVAL * RIP_UPDATE_JITTER));
    MESSAGE_Send(node, newMsg, delay);
    dataPtr->nextRegularUpdateTime = node->getNodeTime() + delay;
    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);

}


static void enterRipHandleFromTransport(Node* node,
                                        RipData* dataPtr,
                                        Message* msg) {

    //UserCodeStartHandleFromTransport
    RipPacket* responsePtr = (RipPacket*) msg->packet;
    switch (responsePtr->command)
    {
        case 1:
        {
            RipProcessRequest(node, msg);
            break;
        }
        case 2:
        {
            RipProcessResponse(node, msg);
            break;
        }
        default:
            ERROR_ReportError("Invalid switch value");
    }
    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);

    //UserCodeEndHandleFromTransport
}

static void enterRipHandleRouteTimerAlarm(Node* node,
                                          RipData* dataPtr,
                                          Message* msg) {

    //UserCodeStartHandleRouteTimerAlarm
    RipRouteTimerMsgInfo* info =
        (RipRouteTimerMsgInfo*) MESSAGE_ReturnInfo(msg);
    RipRoute* routePtr;
    clocktype* timePtr;

    // Attempt to obtain route from RIP route table using IP address
    // of the route destination.

    routePtr = RipGetRoute(node, info->destAddress);

    ERROR_Assert(routePtr,
                 "RIP cannot retrieve route from timer information");

    // Obtain pointer to route alarm time.

    if (info->type == RIP_TIMEOUT)
    {
        timePtr = &routePtr->timeoutTime;
    }
    else
    {
        timePtr = &routePtr->flushTime;
    }

    if (*timePtr != 0)
    {
        ERROR_Assert(*timePtr >= node->getNodeTime(),
                     "RIP route timer in the past");

        if (*timePtr != node->getNodeTime())
        {
            // Timer event was postponed, so reschedule another timer event.

            Message* newMsg = MESSAGE_Duplicate(node, msg);

            MESSAGE_Send(node, newMsg, *timePtr - node->getNodeTime());
        }
       else
       {
            // node->getNodeTime() matches route alarm time,
            // so process timer event.

            switch (info->type)
            {
                case RIP_TIMEOUT:
                {
                    RipHandleRouteTimeout(node, routePtr);
                    break;
                }
                case RIP_FLUSH:
                {
                    RipHandleRouteFlush(node, routePtr);
                    break;
                }
                default:
                    ERROR_ReportError("Invalid switch value");
            }
            // Route timer is deactivated.
            *timePtr = 0;
        }
    }


    //UserCodeEndHandleRouteTimerAlarm

    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);
}

//Statistic Function Definitions
static void RipInitStats(Node* node, RipStatsType* stats) {
    if (node->guiOption) {
        stats->numRegularUpdateEventsId = 
            GUI_DefineMetric("RIP: Number of Regular Update Events",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numTriggeredUpdateEventsId = 
            GUI_DefineMetric("RIP: Number of Triggered Update Events",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numRouteTimeoutsId = 
            GUI_DefineMetric("RIP: Number of Route Timeout Events",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numRequestsSentId =
            GUI_DefineMetric("RIP: Number of Request Packets Sent",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numRequestsReceivedId =
            GUI_DefineMetric("RIP: Number of Request Packets Received",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numInvalidRipPacketsReceivedId =
            GUI_DefineMetric("RIP: Number of Invalid RIP "
                             "Packets received ",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numResponsesReceivedId = 
            GUI_DefineMetric("RIP: Number of Received Response Packets",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numRegularPacketsId = 
            GUI_DefineMetric("RIP: Number of Regular Update Packets Sent",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numTriggeredPacketsId = 
            GUI_DefineMetric("RIP: Number of Triggered Update Packets Sent",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
        stats->numResponseToRequestsSentId = 
            GUI_DefineMetric("RIP: Response Packets "
                             "Sent For Whole Table Request",
                             node->nodeId,
                             GUI_ROUTING_LAYER,
                             0,
                             GUI_UNSIGNED_TYPE,
                             GUI_CUMULATIVE_METRIC);
    }

    stats->numRegularUpdateEvents = 0;
    stats->numTriggeredUpdateEvents = 0;
    stats->numRouteTimeouts = 0;
    stats->numRequestsSent = 0;
    stats->numRequestsReceived = 0;
    stats->numInvalidRipPacketsReceived = 0;
    stats->numResponsesReceived = 0;
    stats->numRegularPackets = 0;
    stats->numTriggeredPackets = 0;
    stats->numResponseToRequestsSent = 0;
}

void RipPrintStats(Node* node) {
    RipStatsType* stats = &((RipData*) node->appData.routingVar)->stats;
    char buf[MAX_STRING_LENGTH];

    char statProtocolName[MAX_STRING_LENGTH];
    strcpy(statProtocolName,"RIP");
    sprintf(buf, "Regular Update Events = %u",
        stats->numRegularUpdateEvents);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Triggered Update Events = %u",
        stats->numTriggeredUpdateEvents);
    IO_PrintStat(node, "Application",statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Route Timeout Events = %u", stats->numRouteTimeouts);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Request Packets Sent = %u",
        stats->numRequestsSent);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Request Packets Received = %u",
        stats->numRequestsReceived);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Invalid RIP Packets Received = %u",
        stats->numInvalidRipPacketsReceived);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Response Packets Received = %u",
        stats->numResponsesReceived);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Regular Update Packets Sent = %u",
        stats->numRegularPackets);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Triggered Update Packets Sent = %u",
        stats->numTriggeredPackets);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "Response Packets Sent For Whole Table Request = %u",
        stats->numResponseToRequestsSent);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
}

void RipRunTimeStat(Node* node, RipData* dataPtr) {
    clocktype now = node->getNodeTime();

    if (node->guiOption) {
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numRegularUpdateEventsId,
                             dataPtr->stats.numRegularUpdateEvents,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numTriggeredUpdateEventsId,
                             dataPtr->stats.numTriggeredUpdateEvents,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numRouteTimeoutsId,
                             dataPtr->stats.numRouteTimeouts,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numRequestsSentId,
                             dataPtr->stats.numRequestsSent,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numRequestsReceivedId,
                             dataPtr->stats.numRequestsReceived,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.
                             numInvalidRipPacketsReceivedId,
                             dataPtr->stats.numInvalidRipPacketsReceived,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numResponsesReceivedId,
                             dataPtr->stats.numResponsesReceived,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numRegularPacketsId,
                             dataPtr->stats.numRegularPackets,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numTriggeredPacketsId,
                             dataPtr->stats.numTriggeredPackets,
                             now);
        GUI_SendUnsignedData(node->nodeId,
                             dataPtr->stats.numResponseToRequestsSentId,
                             dataPtr->stats.numResponseToRequestsSent,
                             now);
    }
}

void
RipInit(Node* node, const NodeInput* nodeInput, int interfaceIndex) {

    RipData* dataPtr = NULL;
    Message* msg = NULL;
    BOOL retVal = 0;
    char buf[MAX_STRING_LENGTH];

    // UserCodeStartInit
    // Make sure the dataPtr is either allocated or set
    // *before* the following auto-generated code

    unsigned int version = RIP_VERSION_2;
    RipSplitHorizonType splitHorizon = RIP_SPLIT_HORIZON_SIMPLE;

    // Set the interface handler function to be called when interface
    // faults occur.

    MAC_SetInterfaceStatusHandlerFunction(
        node,
        interfaceIndex,
        &RipInterfaceStatusHandler);

   // Read version of RIP and check if Split-Horizon is enable
    RipGetVersionAndSplitHorizon(
        node,
        nodeInput,
        interfaceIndex,
        &version,
        &splitHorizon);
    if (node->appData.routingVar == NULL)
    {
        // Nearly all initialization done when first eligible interface
        // enters this function.

        int i;
        Message* newMsg;
        clocktype delay;

        // Allocate and init state.

        dataPtr = (RipData*) MEM_malloc(sizeof(RipData));
        memset(dataPtr, 0, sizeof(RipData));
        dataPtr->initStats = TRUE;

        RANDOM_SetSeed(dataPtr->triggerSeed,
                       node->globalSeed,
                       node->nodeId,
                       APP_ROUTING_RIP,
                       interfaceIndex);
        RANDOM_SetSeed(dataPtr->updateSeed,
                       node->globalSeed,
                       node->nodeId,
                       APP_ROUTING_RIP,
                       interfaceIndex + 1);

        // Set pointer in node data structure to RIP state.

        node->appData.routingVar = (void*) dataPtr;

        // Allocate and initialize array tracking active RIP interfaces

        dataPtr->activeInterfaceIndexes =
            (unsigned char*) MEM_malloc(node->numberInterfaces);

        memset(dataPtr->activeInterfaceIndexes, 0, node->numberInterfaces);

        dataPtr->routeSummary = 
            (BOOL*)MEM_malloc(node->numberInterfaces * sizeof(BOOL));
        memset(dataPtr->routeSummary,
            0, node->numberInterfaces * sizeof(BOOL));
        dataPtr->ripCompatibility = (RipCompatibilityType*)
            MEM_malloc(node->numberInterfaces *
            sizeof(RipCompatibilityType));
        memset(dataPtr->ripCompatibility,
            0, node->numberInterfaces * sizeof(RipCompatibilityType));

        // Read if border router
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "RIP-BORDER-ROUTER",
            &retVal,
            buf);
        if (retVal == TRUE )
        {
            if (strcmp (buf, "NO") == 0)
            {
                dataPtr->borderRouter = FALSE;
            }
            else if (!strcmp (buf, "YES")) {
                dataPtr->borderRouter = TRUE;
            }
            else {
                ERROR_ReportError("Expecting YES/NO for BORDER ROUTER");
            }
        }
        else
        {
            dataPtr->borderRouter = FALSE;
        }
        // set the version field
        dataPtr->version = version;

        // set the Split Horizon field
        dataPtr->splitHorizon = splitHorizon;

        // Init route table.
        RipInitRouteTable(node);

        // Add directly connected networks (including wireless subnets
        // which the node has interfaces on) as permanent routes to the
        // route table.

        for (i = 0; i < node->numberInterfaces; i++)
        {
            RipRoute* routePtr;
            NodeAddress interfaceAddress =
                            NetworkIpGetInterfaceAddress(node, i);
            NodeAddress  subnetMask = 8;
            NodeAddress networkAddress =
                            NetworkIpGetInterfaceNetworkAddress(node, i);
            NetworkDataIp* ip = node->networkData.networkVar;
            IpInterfaceInfoType* interfaceInfo = 
                   ip->interfaceInfo[i];
            if (version == RIP_VERSION_1)
            {
                subnetMask = RipReturnMaskFromIPAddress(interfaceAddress);
                if (subnetMask == 0 &&
                    interfaceInfo->addressState  != INVALID)
                {
                    ERROR_ReportError("Node address is not valid IP address");
                }
            }
            else
            {
                subnetMask = NetworkIpGetInterfaceSubnetMask(node, i);
            }
            if (NetworkIpIsWiredNetwork(node, i))
            {
                if (!RipGetRoute(node, networkAddress))
                {

                    routePtr = RipAddRoute(
                           node,
                           0,
                           networkAddress,
                           subnetMask,
                           0, // to own attached network using 0,
                           0,
                           i,
                           i);
                    NetworkUpdateForwardingTable(
                           node,
                           networkAddress,
                           subnetMask,
                           0,
                           i,
                           0,
                           ROUTING_PROTOCOL_RIP);

                    // route not flagged as changed
                    routePtr->changed = FALSE;
                }
            }
            else
            {
                if (!RipGetRoute(node, networkAddress))
                {

                    routePtr = RipAddRoute(
                           node,
                           0,
                           interfaceAddress,
                           ANY_DEST,
                           interfaceAddress,
                           0,
                           i,
                           i);
                    NetworkUpdateForwardingTable(
                           node,
                           interfaceAddress,
                           ANY_DEST,
                           interfaceAddress,
                           i,
                           0,
                           ROUTING_PROTOCOL_RIP);

                    // route not flagged as changed
                    routePtr->changed = FALSE;
                }
            }
        }

        // Schedule Update Request
        newMsg = MESSAGE_Alloc(node,
                               APP_LAYER,
                               APP_ROUTING_RIP,
                               MSG_APP_RIP_RequestAlarm);

        // Add some jitter.
        // delay == (0, 100] milliseconds.
        RandomSeed startupSeed;
        RANDOM_SetSeed(startupSeed,
                       node->globalSeed,
                       node->nodeId,
                       APP_ROUTING_RIP);

        delay = RIP_STARTUP_DELAY
                - (RANDOM_nrand(startupSeed)
                % (clocktype)
                ((double) RIP_STARTUP_DELAY * RIP_STARTUP_JITTER));

        MESSAGE_Send(node, newMsg, delay);
    }
    else
    {
        // Little initialization for subsequent eligible interfaces.
        // Just retrieve RIP state from node data structure.

        dataPtr = (RipData*) node->appData.routingVar;
        ERROR_Assert(version == dataPtr->version, 
            "RIPv1 and RIPv2 can't run simultaneously at a node");
    }
    // Add interfaceIndex to array tracking active RIP interfaces.
    dataPtr->activeInterfaceIndexes[interfaceIndex] = 1;

    IO_ReadString(
        node->nodeId,
        NetworkIpGetInterfaceAddress(node, interfaceIndex),
        nodeInput,
        "RIP-AUTO-SUMMARY",
        &retVal,
        buf);
    if (retVal == TRUE){
        if (strcmp (buf, "NO") == 0){
            dataPtr->routeSummary[interfaceIndex] = FALSE;
        }
        else if (!strcmp(buf, "YES")){
            dataPtr->routeSummary[interfaceIndex] = TRUE;
        }
        else{
            ERROR_ReportError("Expecting YES/NO for AUTO SUMMARY");
        }
    }
    else{
        dataPtr->routeSummary[interfaceIndex] = FALSE;
    }

    if (dataPtr->version == RIP_VERSION_2){
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "RIP-COMPATIBILITY",
            &retVal,
            buf);
        if (retVal == TRUE) {
            if (strcmp (buf, "RIPv2-ONLY") == 0){
                dataPtr->ripCompatibility[interfaceIndex] = RIPv2_ONLY;
            }
            else if (!strcmp(buf, "RIPv1-ONLY")){
                dataPtr->ripCompatibility[interfaceIndex] = RIPv1_ONLY;
            }
            else if (!strcmp(buf, "RIPv1-COMPATIBLE")){
                dataPtr->ripCompatibility[interfaceIndex] =
                                                    RIPv1_COMPATIBLE;
            }
            else{
                ERROR_ReportError("Expecting RIPv2-ONLY/RIPv1-ONLY/"
                    "RIPv1-COMPATIBLE/NO_RIP for RIP-COMPATIBILITY");
            }
        }
        else {
            dataPtr->ripCompatibility[interfaceIndex] = RIPv2_ONLY;
        }
    }
    else {
        dataPtr->ripCompatibility[interfaceIndex] = RIPv1_ONLY;
    }
    if (dataPtr->version == RIP_VERSION_2) {
        NetworkIpAddToMulticastGroupList(node, RIP_MULTICAST_ADDRESS);
        NetworkUpdateMulticastForwardingTable(
            node,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            RIP_MULTICAST_ADDRESS,
            interfaceIndex);
    }
#ifdef ENTERPRISE_LIB

    // Set routing table update function for route redistribution
    RouteRedistributeSetRoutingTableUpdateFunction(
        node,
        &RipHookToRedistribute,
        interfaceIndex);
#endif // ENTERPRISE_LIB

#ifdef ADDON_BOEINGFCS
    // so that we can interact with waveform code.
    if (node->macData[interfaceIndex]->macProtocol ==
        MAC_PROTOCOL_CES_SRW_PORT && 
        (dataPtr->ripCompatibility[interfaceIndex] == RIPv1_ONLY ||
        dataPtr->ripCompatibility[interfaceIndex] ==
        RIPv1_COMPATIBLE))
    {
        NetworkIpAddToMulticastGroupList(node, RIP_MULTICAST_ADDRESS);
    }
#endif

    //UserCodeEndInit
    if (dataPtr->initStats) {
        RipInitStats(node, &(dataPtr->stats));
    }
    dataPtr->state = RIP_IDLE;
    enterRipIdle(node, dataPtr, msg);
    
    // registering RoutingRipHandleAddressChangeEvent function
    NetworkIpAddAddressChangedHandlerFunction(node,
                            &RoutingRipHandleChangeAddressEvent);
}


void
RipFinalize(Node* node, int interfaceIndex) {

    RipData* dataPtr = (RipData*) node->appData.routingVar;

    //UserCodeStartFinalize
    dataPtr->printStats = node->appData.routingStats
                          && (!dataPtr->printedStats);
    dataPtr->printedStats = TRUE;

    //UserCodeEndFinalize

    if (dataPtr->statsPrinted) {
        return;
    }

    if (dataPtr->printStats) {
        dataPtr->statsPrinted = TRUE;
        RipPrintStats(node);
    }
}


void
RipProcessEvent(Node* node, Message* msg) {

    RipData* dataPtr = NULL;
    int event;

    dataPtr = (RipData*) node->appData.routingVar;
    if (!dataPtr) {
        MESSAGE_Free(node, msg);
        return;
    }

    event = msg->eventType;
    switch (dataPtr->state) {
        case RIP_IDLE:
            switch (event) {
                case MSG_APP_RIP_RegularUpdateAlarm:
                    dataPtr->state = RIP_HANDLE_REGULAR_UPDATE_ALARM;
                    enterRipHandleRegularUpdateAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_RIP_TriggeredUpdateAlarm:
                    dataPtr->state = RIP_HANDLE_TRIGGERED_UPDATE_ALARM;
                    enterRipHandleTriggeredUpdateAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_RIP_RouteTimerAlarm:
                    dataPtr->state = RIP_HANDLE_ROUTE_TIMER_ALARM;
                    enterRipHandleRouteTimerAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_FromTransport:
                    dataPtr->state = RIP_HANDLE_FROM_TRANSPORT;
                    enterRipHandleFromTransport(node, dataPtr, msg);
                    break;
                case MSG_APP_RIP_RequestAlarm:
                    dataPtr->state = RIP_HANDLE_REQUEST_ALARM;
                    enterRipHandleRequestAlarm(node, dataPtr, msg);
                    break;
                default:
                    assert(FALSE);
            }
            break;
        case RIP_HANDLE_REGULAR_UPDATE_ALARM:
        case RIP_HANDLE_TRIGGERED_UPDATE_ALARM:
        case RIP_HANDLE_FROM_TRANSPORT:
        case RIP_HANDLE_ROUTE_TIMER_ALARM:
        case RIP_HANDLE_REQUEST_ALARM:
            ERROR_ReportError("Inconsistent RIP State");
            break;
        default:
            ERROR_ReportError("Illegal transition");
            break;
    }

}

//--------------------------------------------------------------------------
// FUNCTION   :: RoutingRipHandleChangeAddressEvent
// PURPOSE    :: Handles any change in the interface address
// PARAMETERS ::
// + node                    : Node*       : Pointer to Node structure
// + interfaceIndex          : Int32       : interface index
// + oldAddress              : Address*    : old address
// + subnetMask              : NodeAddress : subnetMask
// + NetworkType networkType : type of network protocol
// RETURN     ::             : void        : NULL
//--------------------------------------------------------------------------
void RoutingRipHandleChangeAddressEvent(
    Node* node,
    Int32 interfaceIndex,
    Address* oldAddress,
    NodeAddress subnetMask,
    NetworkType networkType)
{
    if (networkType == NETWORK_IPV6)
    {
        return;
    }
    NetworkDataIp* ip = node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = 
                   ip->interfaceInfo[interfaceIndex];
    if (interfaceInfo->addressState == INVALID)
    {
        return;
    }
    if (ip->interfaceInfo[interfaceIndex]->routingProtocolType !=
           ROUTING_PROTOCOL_RIP)
    {
        return;
    }

    RipRoute* routePtr = NULL;
    NodeAddress interfaceAddress = NetworkIpGetInterfaceAddress(node,
                                      interfaceIndex);

    if (!RipGetRoute(node, interfaceAddress))
    {
        if (NetworkIpIsWiredNetwork(node, interfaceIndex))
        {
            routePtr = RipAddRoute(
                node,
                0,
                interfaceAddress,
                subnetMask,
                interfaceAddress,
                1,
                interfaceIndex,
                interfaceIndex);
            NetworkUpdateForwardingTable(
                node,
                interfaceAddress,
                subnetMask,
                interfaceAddress,
                interfaceIndex,
                1,
                ROUTING_PROTOCOL_RIP);

            routePtr->changed = TRUE;  // route flagged as changed
        }
        else
        {
            routePtr = RipAddRoute(
                node,
                0,
                interfaceAddress,
                ANY_DEST,
                interfaceAddress,
                0,
                interfaceIndex,
                interfaceIndex);
            NetworkUpdateForwardingTable(
                node,
                interfaceAddress,
                ANY_DEST,
                interfaceAddress,
                interfaceIndex,
                0,
                ROUTING_PROTOCOL_RIP);

            routePtr->changed = TRUE;  // route flagged as changed
        }
    }

    RipScheduleTriggeredUpdate(node);
}
