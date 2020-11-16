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
#include "routing_ripng.h"

//UserCodeStartBodyData
#include "ipv6.h"
#include "network_dualip.h"
#include "transport_udp.h"

#define RIPNG_VERSION   1  // RIPng supports only version 1
#define RIPNG_INFINITY   16  // RIPng value for infinite distance
#define RIPNG_MUST_BE_ZERO   0
#define RIPNG_HEADER_SIZE   4  // Header size (bytes) of RIPng
#define RIPNG_RTE_SIZE   20  // A single RIPng-RTE size (bytes) in update packet
#define RIPNG_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED   4  // The route table starts with memory allocated for this many routes
#define RIPNG_REGULAR_UPDATE_INTERVAL   (30 * SECOND)  // Regular update interval
#define RIPNG_TRIGGER_UPDATE_INTERVAL   (5 * SECOND)  // Triggered update interval
#define RIPNG_ROUTE_TIMEOUT_INTERVAL   (180 * SECOND)  // Duration after which a route will be considered timed out
#define RIPNG_GARBAGE_COLLECTION_INTERVAL   (120 * SECOND)  // Upon expiration(after TIMEOUT) of the garbage-collection timer, the route is finally removed from the routing table
#define RIPNG_REGULAR_UPDATE_JITTER   0.15
#define RIPNG_TRIGGER_UPDATE_JITTER   0.8
#define RIPNG_STARTUP_JITTER   1.0
#define RIPNG_STARTUP_DELAY   (100 * MILLI_SECOND)  // The delay at startup before the first regular update is RIP_STARTUP_DELAY - [0, RIP_STARTUP_DELAY * RIP_STARTUP_JITTER) seconds i.e., (0, 100] milliseconds.
#define RIPNG_MAX_PREFIX_LEN   128  // Maximum destination prefix length
#define RIPNG_DEBUG   0  // For Debug Option


//UserCodeEndBodyData

//Statistic Function Declarations
static void RIPngInitStats(Node* node, RIPngStatsType *stats);
void RIPngPrintStats(Node *node);

//Utility Function Declarations
static void RIPngPrintRoutingTable(Node* node);
static void RIPngInitRouteTable(Node* node);
static void RIPngScheduleTriggeredUpdate(Node* node);
static void RIPngSetRouteTimer(Node* node,clocktype* timePtr,in6_addr destAddress,clocktype delay,RIPngRouteTimerType type);
static void RIPngInterfaceStatusHandler(Node* node,int interfaceIndex,MacInterfaceState state);
static void RIPngHandleRouteTimeout(Node* node,RIPngRtTable* routePtr);
static void RIPngHandleRouteFlush(Node* node,RIPngRtTable* routePtr);
static RIPngRtTable* RIPngGetRoute(Node* node,in6_addr destPrefix);
static RIPngRtTable* RIPngAddRoute(Node* node,in6_addr destPrefix,in6_addr nextHop,int metric,int outgoingInterfaceIndex,int learnedInterfaceIndex);
static void RIPngProcessResponse(Node* node,Message* msg);
static void RIPngClearChangedRouteFlags(Node* node);
static void RIPngSendResponse(Node* node,int interfaceIndex,RIPngResponseType type);
static void PrintRIPngResponsePacket(RIPngResponse& response,unsigned int numRtes);
static void GetAllNeighborRipRouterMulticastAddress(in6_addr* multicastAddress);

//State Function Declarations
static void enterRIPngHandleRegularUpdateAlarm(Node* node, RIPngData* dataPtr, Message* msg);
static void enterRIPngHandleTriggeredUpdateAlarm(Node* node, RIPngData* dataPtr, Message* msg);
static void enterRIPngHandleRouteTimerAlarm(Node* node, RIPngData* dataPtr, Message* msg);
static void enterRIPngIdle(Node* node, RIPngData* dataPtr, Message* msg);
static void enterRIPngHandleFromTransport(Node* node, RIPngData* dataPtr, Message* msg);

//Utility Function Definitions
//UserCodeStart
// FUNCTION RIPngPrintRoutingTable
// PURPOSE  Print the RIPng routing table
// Parameters:
//  node:   Pointer to current node
static void RIPngPrintRoutingTable(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
     RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
     RIPngRtTable* rtTable = dataPtr->routeTable;
     unsigned int i = 0;
     char buf[MAX_STRING_LENGTH];
     printf("\nRIPng Routing Table for Node =%u:\n", node->nodeId);
     printf("------------------------"
            "------------------------------------------"
            "-----------------------------------------------------\n");
     printf("              DestPrefix"
            "               NextHop  Metric    InfIndx "
                "timeOutTime        RtFlush  RtChange  flushTime\n");
     printf("------------------------"
            "------------------------------------------"
            "-----------------------------------------------------\n");
     for (i = 0; i < dataPtr->numRoutes; i++)
     {
         IO_ConvertIpAddressToString(&rtTable[i].destPrefix, buf);
         printf("%24s    ", buf);
         IO_ConvertIpAddressToString(&rtTable[i].nextHopAddress, buf);
         printf("    %14s    ", buf);
         TIME_PrintClockInSecond(rtTable[i].timeoutTime, buf);
         printf("%2d        %d     %-20s",rtTable[i].metric,
             rtTable[i].outgoingInterfaceIndex,
             buf);
         TIME_PrintClockInSecond(rtTable[i].flushTime, buf);
         printf("  %d        %d      %-20s\n",
             rtTable[i].flushed,
             rtTable[i].changed,
             buf);
     }
     printf("------------------------"
            "------------------------------------------"
            "-----------------------------------------------------\n");
}

// FUNCTION RIPngPrintTraceXML
// PURPOSE  Initializes the RIPng routing table
// Parameters:
// node:   Pointer to current node
// nodeInput : Pointer to node input structure

void RIPngPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    char prefixAddr[MAX_STRING_LENGTH];
    unsigned int i;
    unsigned numRtes = (msg->packetSize - RIPNG_HEADER_SIZE)
                        / RIPNG_RTE_SIZE;

    //UserCodeStartHandleFromTransport
    RIPngResponse response;

    memcpy(&response, msg->packet, RIPNG_HEADER_SIZE);
    response.rtes = (RIPngRte*)(msg->packet + RIPNG_HEADER_SIZE);

    sprintf(buf,"<ripng>%hu %hu %hu",
        response.command,
        response.version,
        0);
    TRACE_WriteToBufferXML(node, buf);

    for (i = 0; i < numRtes; i++)
    {
        IO_ConvertIpAddressToString(&response.rtes[i].prefix,prefixAddr);
        sprintf(buf, "<rteVer>%s %hu %hu %hu</rteVer>",
            prefixAddr,
            response.rtes[i].routeTag,
            response.rtes[i].prefixLen,
            response.rtes[i].metric);
       TRACE_WriteToBufferXML(node, buf);

    }

     sprintf(buf, "</ripng>");
    TRACE_WriteToBufferXML(node, buf);

}

// FUNCTION RIPngInitRouteTable
// PURPOSE  Initializes the RIPng routing table
// Parameters:
//  node:   Pointer to current node
static void RIPngInitRouteTable(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    // Allocate initial space for routes.
    dataPtr->routeTable =
              (RIPngRtTable*) MEM_malloc(
                             RIPNG_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED
                             * sizeof(RIPngRtTable));
    dataPtr->numRoutesAllocated =
         RIPNG_ROUTE_TABLE_NUM_INITIAL_ROUTES_ALLOCATED;
    // Initialize number of routes.
    dataPtr->numRoutes = 0;
}


// FUNCTION RIPngScheduleTriggeredUpdate
// PURPOSE  Schedule Triggered Update
// Parameters:
//  node:   Pointer to current node
static void RIPngScheduleTriggeredUpdate(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    clocktype delay = RIPNG_TRIGGER_UPDATE_INTERVAL
                 - (RANDOM_nrand(dataPtr->seed)
                    % (clocktype) ((double) RIPNG_TRIGGER_UPDATE_INTERVAL
                         * RIPNG_TRIGGER_UPDATE_JITTER));
    // Schedule a triggered update if both of the following are true:
    // a) A triggered update is not already scheduled for the node, and
    // b) Next regular update is not very soon.
    if (dataPtr->triggeredUpdateScheduled == FALSE
        && dataPtr->nextRegularUpdateTime > node->getNodeTime() + delay)
    {
        Message* newMsg;
        // Schedule triggered update.
        newMsg = MESSAGE_Alloc(
                    node,
                    APP_LAYER,
                    APP_ROUTING_RIPNG,
                    MSG_APP_RIPNG_TriggeredUpdateAlarm);
        MESSAGE_Send(node, newMsg, delay);
        // Set flag indicating a triggered update has been scheduled.
        dataPtr->triggeredUpdateScheduled = TRUE;
    }
}


// FUNCTION RIPngSetRouteTimer
// PURPOSE  Sets a route-timeout or route-flush timer for a particular route in the RIP route table.
// Parameters:
//  node:   Pointer to node
//  timePtr:    Storage for timer alarm time for route
//  destAddress:    IP address of route destination
//  delay:  Timer delay.
//  type:   ALL_ROUTES (regular) or CHANGED_ROUTES (triggered update)
static void RIPngSetRouteTimer(Node* node,clocktype* timePtr,in6_addr destAddress,clocktype delay,RIPngRouteTimerType type) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    clocktype scheduledTime = node->getNodeTime() + delay;
    ERROR_Assert(delay != 0, "RIPng SetRouteTimer() does not accept 0 "
        "delay");
    // Determine whether a timer of the same type is already scheduled using
    // the value of *timePtr.
    if (*timePtr == 0)
    {
        // Timer of the same type is not running.
        Message* newMsg;
        RIPngRouteTimerMsgInfo* info;
        // Set QualNet event for appropriate time.
        newMsg = MESSAGE_Alloc(node,
                     APP_LAYER,
                     APP_ROUTING_RIPNG,
                     MSG_APP_RIPNG_RouteTimerAlarm);
        // Insert IP address of route destination, and timer type in
        // QualNet event.
        MESSAGE_InfoAlloc(node, newMsg, sizeof(RIPngRouteTimerMsgInfo));
        info = (RIPngRouteTimerMsgInfo*) MESSAGE_ReturnInfo(newMsg);
        info->type = type;
        info->destPrefix = destAddress;
        MESSAGE_Send(node, newMsg, delay);
    }
    else
    {
        // Timer of the same type is currently running.
        // Don't schedule a new QualNet event.
        // Setting *timePtr to the new value is all that's required;
        // the scheduling of the new event is done
        ERROR_Assert(*timePtr >= node->getNodeTime(), "RIPng route timer in "
            "the past");
        ERROR_Assert(scheduledTime >= *timePtr, "RIPng restarted route "
            "timer alarm time must be in the future of the old timer");
        if (*timePtr == scheduledTime)
        {
            // Return early if new alarm time and old alarm time are equal.
            return;
        }
    }
    // Set alarm time for route in RIP route table.
    *timePtr = scheduledTime;
}


// FUNCTION RIPngInterfaceStatusHandler
// PURPOSE  Handle Interface fault
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  state:  state of interface
static void RIPngInterfaceStatusHandler(Node* node,int interfaceIndex,MacInterfaceState state) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    unsigned int routeIndex = 0;
    RIPngRtTable* routePtr = NULL;
    in6_addr networkAddress;
    if (NetworkIpIsWiredNetwork(node, interfaceIndex))
    {
        networkAddress = Ipv6GetPrefixFromInterfaceIndex(
                             node,
                             interfaceIndex);
    }
    else
    {
        Ipv6GetGlobalAggrAddress(
            node,
            interfaceIndex,
            &networkAddress);
    }
    if (state == MAC_INTERFACE_DISABLE)
    {
        dataPtr->activeInterfaceIndexes[interfaceIndex] = 0;
        if (RIPNG_DEBUG)
        {
            char buf[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), buf);
            printf("\nRIPngRoutingTable Before Handling "
                "Interface(%d) Failure at Node = %u at %s sec\n",
                interfaceIndex,
                node->nodeId,
                buf);
            RIPngPrintRoutingTable(node);
        }
        for (routeIndex = 0; routeIndex < dataPtr->numRoutes; routeIndex++)
        {
            routePtr = &dataPtr->routeTable[routeIndex];
            if (routePtr->outgoingInterfaceIndex == interfaceIndex)
            {
                // Set distance for route to infinity.
                // Flag route as changed.
                routePtr->metric = RIPNG_INFINITY;
                routePtr->changed = TRUE;
                // Get Global address of routePtr->nextHopAddress
                in6_addr nextHopGlobalAddress;
                nextHopGlobalAddress = Ipv6GetPrefixFromInterfaceIndex(
                                            node,
                                            interfaceIndex);
                nextHopGlobalAddress.s6_addr32[2] =
                    routePtr->nextHopAddress.s6_addr32[2];
                nextHopGlobalAddress.s6_addr32[3] =
                    routePtr->nextHopAddress.s6_addr32[3];
                // call IPv6 forwarding table update function
                Ipv6UpdateForwardingTable(
                    node,
                    routePtr->destPrefix,
                    routePtr->prefixLen,
                    nextHopGlobalAddress,
                    ANY_INTERFACE,
                    NETWORK_UNREACHABLE,
                    ROUTING_PROTOCOL_RIPNG);
                // Cancel route-timeout timer.
                routePtr->timeoutTime = 0;
                // Start route-flush timer.
                RIPngSetRouteTimer(
                    node,
                    &routePtr->flushTime,
                    routePtr->destPrefix,
                    RIPNG_GARBAGE_COLLECTION_INTERVAL,
                    RIPNG_GARBAGE);
              }
          }
          if (RIPNG_DEBUG)
          {
              char buf[MAX_STRING_LENGTH];
              TIME_PrintClockInSecond(node->getNodeTime(), buf);
              printf("\nRIPngRoutingTable After Handling "
                  "Interface(%d) Failure at Node = %u at %s sec\n",
                  interfaceIndex,
                  node->nodeId,
                  buf);
              RIPngPrintRoutingTable(node);
           }
      }
    else if (state == MAC_INTERFACE_ENABLE)
    {
        dataPtr->activeInterfaceIndexes[interfaceIndex]= 1;
        if (RIPNG_DEBUG)
        {
            char buf[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), buf);
            printf("\nRIPngRoutingTable Before Handling "
                "Interface(%d) Activation at Node = %u at %s sec\n",
                interfaceIndex,
                node->nodeId,
                buf);
            RIPngPrintRoutingTable(node);
        }
        for (routeIndex = 0; routeIndex < dataPtr->numRoutes; routeIndex++)
        {
            routePtr = &dataPtr->routeTable[routeIndex];
            //if (routePtr->destPrefix == networkAddress)
            if (0 == CMP_ADDR6(routePtr->destPrefix, networkAddress))
            {
                // Get the interface address from interface index and that
                // is the nexthop address
                Ipv6GetLinkLocalAddress(
                    node,
                    interfaceIndex,
                    &routePtr->nextHopAddress);
                routePtr->outgoingInterfaceIndex = interfaceIndex;
                routePtr->learnedInterfaceIndex =interfaceIndex;
                if (MAC_IsWiredNetwork(node, interfaceIndex))
                {
                    routePtr->metric = 1;
                }
                else
                {
                    routePtr->metric = 0;
                }
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
                // Get Global address of routePtr->nextHopAddress
                in6_addr nextHopGlobalAddress;
                nextHopGlobalAddress = Ipv6GetPrefixFromInterfaceIndex(
                                            node,
                                            interfaceIndex);
                nextHopGlobalAddress.s6_addr32[2] =
                    routePtr->nextHopAddress.s6_addr32[2];
                nextHopGlobalAddress.s6_addr32[3] =
                    routePtr->nextHopAddress.s6_addr32[3];
                // call IPv6 forwarding table update function
                Ipv6UpdateForwardingTable(
                    node,
                    routePtr->destPrefix,
                    routePtr->prefixLen,
                    nextHopGlobalAddress,
                    interfaceIndex,
                    routePtr->metric,
                    ROUTING_PROTOCOL_RIPNG);
            }
        }
        if (RIPNG_DEBUG)
        {
            char buf[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(node->getNodeTime(), buf);
            printf("\nRIPngRoutingTable After Handling "
                "Interface(%d) Activation at Node = %u at %s sec\n",
                interfaceIndex,
                node->nodeId,
                buf);
            RIPngPrintRoutingTable(node);
        }
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown MacInterfaceState\n");
    }
    // Schedule triggered update.
    RIPngScheduleTriggeredUpdate(node);
}


// FUNCTION RIPngHandleRouteTimeout
// PURPOSE  Processes a route timeout:  updates IP routing table,  sets RIPng distance for route to infinity, schedules flush timer
// Parameters:
//  node:   Pointer to node
//  routePtr:   Pointer to RIPng route
static void RIPngHandleRouteTimeout(Node* node,RIPngRtTable* routePtr) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    ERROR_Assert(routePtr->metric != RIPNG_INFINITY, "RIPng timed out "
        "route should not already have infinite distance");
    ERROR_Assert(routePtr->flushTime == 0, "RIPng timed out route should "
        "not have a flush timer active");
    // Increment stat for number of route-timeout events.
    dataPtr->stats.numRouteTimeouts++;
    // Get the Global address of routePtr->nextHopAddress
    in6_addr nextHopGlobalAddress = Ipv6GetPrefixFromInterfaceIndex(
                                        node,
                                        routePtr->outgoingInterfaceIndex);
    nextHopGlobalAddress.s6_addr32[2] =
        routePtr->nextHopAddress.s6_addr32[2];
    nextHopGlobalAddress.s6_addr32[3] =
        routePtr->nextHopAddress.s6_addr32[3];
    // Mark route as invalid in IP routing table.
    // (Route is retained in RIPng route table.)
    // Call the IPv6 forwarding table update function
    Ipv6UpdateForwardingTable(
        node,
        routePtr->destPrefix,
        routePtr->prefixLen,
        nextHopGlobalAddress,
        ANY_INTERFACE,
        NETWORK_UNREACHABLE,
        ROUTING_PROTOCOL_RIPNG);
    // Set distance for route to infinity.  Flag route as changed.
    routePtr->metric = RIPNG_INFINITY;
    routePtr->changed = TRUE;
    // Schedule triggered update.
    RIPngScheduleTriggeredUpdate(node);
    // Start flush timer.
    RIPngSetRouteTimer(
        node,
        &routePtr->flushTime,
        routePtr->destPrefix,
        RIPNG_GARBAGE_COLLECTION_INTERVAL,
        RIPNG_GARBAGE);
}


// FUNCTION RIPngHandleRouteFlush
// PURPOSE  Marks a route in the RIP route table as flush efficiency, the route is not physically removed from the RIP routing table.
// Parameters:
//  node:   Pointer to node
//  routePtr:   Pointer to RIPng Route Table Entry
static void RIPngHandleRouteFlush(Node* node,RIPngRtTable* routePtr) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    ERROR_Assert(routePtr->metric == RIPNG_INFINITY, "RIPng route to be "
        "flushed should have inifinite distance");
    ERROR_Assert(routePtr->timeoutTime == 0, "RIPng route to be flushed "
        "should not have an active timeout timer");
    // Mark route as flushed.
    routePtr->flushed = TRUE;
}


// FUNCTION RIPngGetRoute
// PURPOSE  Finds a route in the RIPng route table using the IPv6 address of the route destination.
// Parameters:
//  node:   Pointer to node
//  destPrefix: IPv6 address of destination
static RIPngRtTable* RIPngGetRoute(Node* node,in6_addr destPrefix) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    int top = 0;
    int bottom = 0;
    int middle = 0;
    RIPngRtTable* routePtr = NULL;
    // Return early if no routes.
    if (dataPtr->numRoutes == 0)
    {
        return(NULL);
    }
    // Search route table.
    top = 0;
    bottom = dataPtr->numRoutes - 1;
    middle = (bottom + top) / 2;
    int decide = 0;
    decide = CMP_ADDR6(
                destPrefix,
                dataPtr->routeTable[top].destPrefix);
    //if (destAddress == dataPtr->routeTable[top].destAddress)
    if (decide == 0)
    {
        return(&dataPtr->routeTable[top]);
    }
    decide = CMP_ADDR6(
                destPrefix,
                dataPtr->routeTable[bottom].destPrefix);
    //if (destAddress == dataPtr->routeTable[bottom].destAddress)
    if (decide == 0)
    {
        return(&dataPtr->routeTable[bottom]);
    }
    while (middle != top)
    {
        routePtr = &dataPtr->routeTable[middle];
        decide = CMP_ADDR6(
                    destPrefix,
                    routePtr->destPrefix);
        //if (destAddress == routePtr->destAddress)
        if (decide == 0)
        {
            return(routePtr);
        }
        else if (decide == -1)
        {
            //if (destAddress < routePtr->destAddress)
            bottom = middle;
        }
        else
        {
            top = middle;
        }
        middle = (bottom + top) / 2;
    }
    // Could not find route.
    return(NULL);
}


// FUNCTION RIPngAddRoute
// PURPOSE  Adds a route to the route table.  To modify an existing  route, use GetRoute() and modify the route directly.
// Parameters:
//  node:   Pointer to node
//  destPrefix: IPv6 address of destination
//  nextHop:    Next hop IPv6 address
//  metric: Number of hops
//  outgoingInterfaceIndex: outgoing interface index
//  learnedInterfaceIndex:  interface  through which node learned the route
static RIPngRtTable* RIPngAddRoute(Node* node,in6_addr destPrefix,in6_addr nextHop,int metric,int outgoingInterfaceIndex,int learnedInterfaceIndex) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    int index = 0;
    // Have we used up all the allocated spaces for routes?
    if (dataPtr->numRoutes == dataPtr->numRoutesAllocated)
    {
        // Table filled, so reallocate double memory for route table.
        RIPngRtTable* oldRouteTable;
        unsigned i = 0;
        oldRouteTable = dataPtr->routeTable;
        dataPtr->routeTable =
            (RIPngRtTable*) MEM_malloc(2 * dataPtr->numRoutesAllocated
                                         * sizeof(RIPngRtTable));
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
        RIPngRtTable* routePtr = NULL;
        int decide = 0;
        if (index !=0)
        {
            decide = CMP_ADDR6(
                        destPrefix,
                        dataPtr->routeTable[index - 1].destPrefix);
        }
        //if (index != 0
        //    && destPrefix <= dataPtr->routeTable[index - 1].destPrefix)
        if (index != 0 && decide <= 0)
        {
            //if (destPrefix == dataPtr->routeTable[index - 1].destPrefix)
            if (decide == 0)
            {
                // Route already exists.
                ERROR_ReportError("Cannot add duplicate route");
            }
            dataPtr->routeTable[index] = dataPtr->routeTable[index - 1];
            index--;
            continue;
        }
        routePtr = &dataPtr->routeTable[index];
        routePtr->destPrefix = destPrefix;
        routePtr->nextHopAddress = nextHop;
        routePtr->metric = (unsigned char) metric;
        routePtr->outgoingInterfaceIndex = outgoingInterfaceIndex;
        routePtr->learnedInterfaceIndex  = learnedInterfaceIndex;
        routePtr->timeoutTime = 0;
        routePtr->flushTime = 0;
        routePtr->changed = TRUE;
        routePtr->flushed = FALSE;
        return(routePtr);
    }
    // Not reachable.
    ERROR_ReportError("Code not reachable");
    return(NULL);
}


// FUNCTION RIPngProcessResponse
// PURPOSE  Process RIPng response packet
// Parameters:
//  node:   Pointer to node
//  msg:    Pointer to RIPng message
static void RIPngProcessResponse(Node* node,Message* msg) {

//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    RIPngResponse response;
    unsigned numRtes = (msg->packetSize - RIPNG_HEADER_SIZE)
                        / RIPNG_RTE_SIZE;
    UdpToAppRecv* info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
    in6_addr sourceAddress = GetIPv6Address(info->sourceAddr);
    in6_addr sourceGlobalAddress;
    char buf[MAX_STRING_LENGTH];
    int incomingInterfaceIndex = info->incomingInterfaceIndex;
    in6_addr incomingInterfacePrefix = Ipv6GetPrefixFromInterfaceIndex(
                                           node,
                                           incomingInterfaceIndex);
    unsigned rteIndex = 0;
    memcpy(&response, msg->packet, RIPNG_HEADER_SIZE);
    response.rtes = (RIPngRte*)(msg->packet + RIPNG_HEADER_SIZE);
    if (response.version != RIPNG_VERSION)
    {
        // do nothing
        return;
    }
    if (!NetworkIpIsWiredNetwork(node, incomingInterfaceIndex))
    {
        // DUAL-IP: the source address field of tunneled advertisement
        // contains global address instead of link-local address
        COPY_ADDR6(sourceAddress, sourceGlobalAddress);
    }
    else
    {
        // Get Global IPv6 address of the source
        // from which the advertisement has come
        COPY_ADDR6(sourceAddress, sourceGlobalAddress);
    }
    // Increment stat for number of Response messages received
    dataPtr->stats.numResponsesReceived++;
    if (RIPNG_DEBUG)
    {
        char TimeBuf[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), TimeBuf);
        IO_ConvertIpAddressToString(&sourceAddress, buf);
        printf("\nThe Node = %u receives RIPngUpdate packet\n"
        "via InfIndx = %d from %s (LinkLocalAddress),\n"
        "with a Message Seq.No = %u at time %s (Sec)\n",
            node->nodeId,
            incomingInterfaceIndex,
            buf,
            dataPtr->stats.numResponsesReceived,
            TimeBuf);
        PrintRIPngResponsePacket(response, numRtes);
        printf("\nRIPng Table Contents Before Processing the packet\n");
        RIPngPrintRoutingTable(node);
    }
    if (numRtes < 2 && numRtes > (unsigned)dataPtr->maxNumRte)
    {
        printf("Response message contains less than 2"
            "or greater than %d RTEs which is limited by MTU\n",
            dataPtr->maxNumRte);
        assert(FALSE);
    }
    // Loop through all RTEs and nextHop RTEs contained in Response packet
    rteIndex = 0;
    while (rteIndex < numRtes)
    {
        RIPngRtTable* routePtr = NULL;

        RIPngRte* rtePtr = &(response.rtes[rteIndex + 1]);
        rteIndex++;
        while (rtePtr->metric != 0xFF
              && rteIndex < numRtes)
        {
            RIPngRtTable* newRoutePtr = NULL;
            unsigned char dist_metric = 1;
            if (CMP_ADDR6(rtePtr->prefix, incomingInterfacePrefix) != 0)
            {
                // rtePtr->prefix i.e. the dest is not the source address
                dist_metric = MIN(rtePtr->metric + 1, RIPNG_INFINITY);
            }
            else
            {
                // rtePtr->prefix i.e. the dest itself
                // is the source address
                dist_metric = rtePtr->metric;
            }
            // validate the prefix of the RTE it should not be a link-local
            // address TBD [done]
            if (IS_LINKLADDR6(rtePtr->prefix) == TRUE)
            {
                // Destination prefix is a link-local address, but it should
                // not be.
                ERROR_Assert(NULL, "A link-local address should never be "
                    "present as a destination RTE.entry\n");
            }
            ERROR_Assert(rtePtr->prefixLen <= RIPNG_MAX_PREFIX_LEN,
                "Invalid Prefix Length in RTE.\n");
            // Validate next hop RTE
            // Attempt to obtain route from RIPng route table using IP
            // address of the route destination.
            routePtr = RIPngGetRoute(node, rtePtr->prefix);
            if ((routePtr == NULL)
                || (routePtr != NULL && routePtr->flushed == TRUE))
            {
                // Route does not exist in RIPng route table,
                // or exist but has been marked as flushed.
                if (dist_metric == RIPNG_INFINITY)
                {
                    // Ignore route with infinite distance if the route
                    // does not exist in our own route table.
                    // Continue to next RTE.
                    rteIndex++;
                    if (rteIndex < numRtes)
                    {
                        rtePtr = &(response.rtes[rteIndex]);
                    }
                    continue;
                }
                // Route has non-infinite distance, so either add the route
                // to the route table or recover the flushed route.
                if (!routePtr)
                {
                    // RIPngAddRoute() will flag the new route as changed
                    // (for triggered updates).
                    newRoutePtr = RIPngAddRoute(
                                      node,
                                      rtePtr->prefix,
                                      sourceAddress,
                                      dist_metric,
                                      incomingInterfaceIndex,
                                      incomingInterfaceIndex);

                    newRoutePtr->prefixLen = rtePtr->prefixLen;
                }
                else
                {
                    // Recover flushed route.
                    newRoutePtr = routePtr;
                    COPY_ADDR6(sourceAddress, newRoutePtr->nextHopAddress);
                    newRoutePtr->metric = dist_metric;
                    newRoutePtr->outgoingInterfaceIndex =
                        incomingInterfaceIndex;
                    newRoutePtr->learnedInterfaceIndex =
                        incomingInterfaceIndex;
                    // Flag route as changed
                    newRoutePtr->changed = TRUE;
                    newRoutePtr->flushed = FALSE;
                }
                // Update IP routing table with new route.
                Ipv6UpdateForwardingTable(
                    node,
                    rtePtr->prefix,
                    rtePtr->prefixLen,
                    sourceGlobalAddress,
                    incomingInterfaceIndex,
                    dist_metric,
                    ROUTING_PROTOCOL_RIPNG);
                if (newRoutePtr->flushTime != 0)
                {
                     routePtr->flushTime = 0;
                }
                // Start route-timeout timer.
                RIPngSetRouteTimer(
                    node,
                    &newRoutePtr->timeoutTime,
                    newRoutePtr->destPrefix,
                    RIPNG_ROUTE_TIMEOUT_INTERVAL,
                    RIPNG_TIMEOUT);
                // Schedule triggered update.
                RIPngScheduleTriggeredUpdate(node);
                // Continue to next RTE.
                rteIndex++;
                if (rteIndex < numRtes)
                {
                    rtePtr = &(response.rtes[rteIndex]);
                }
                continue;
            }
            int match = FALSE;
            // Compare the next hop address to the address of the router
            // from which the datagram came. If this datagram is from the
            // same router as the existing route, reinitialize the timeout
            if ((CMP_ADDR6(
                    routePtr->nextHopAddress,
                    sourceAddress) == 0)
                && (incomingInterfaceIndex
                    == routePtr->outgoingInterfaceIndex))
            {
               //nextHop == sourceAddress
               match = TRUE;
            }
            else
            {
                match = FALSE;
            }
            // For the case of an existing, non-flushed route:  there are
            // three conditions where the route is considered changed, as
            // below.
            if (
                (match == TRUE
                    && (dist_metric != routePtr->metric
                    || routePtr->learnedInterfaceIndex
                    != incomingInterfaceIndex))
                 || (dist_metric < routePtr->metric)
                 || (routePtr->timeoutTime != 0
                    //&& routePtr->nextHop != sourceAddress
                        && match == FALSE
                        && dist_metric != RIPNG_INFINITY
                        && dist_metric == routePtr->metric
                        && node->getNodeTime() >= routePtr->timeoutTime
                                              - RIPNG_ROUTE_TIMEOUT_INTERVAL
                                              / 2))
            {
                BOOL updateForwardingTable = FALSE;
                // Update metric if necessary.
                if (routePtr->metric != dist_metric)
                {
                    routePtr->metric = dist_metric;
                    updateForwardingTable = TRUE;
                }
                // Update interface if necessary
                if (routePtr->learnedInterfaceIndex !=
                        incomingInterfaceIndex)
                {
                    routePtr->learnedInterfaceIndex =
                        incomingInterfaceIndex;
                    routePtr->outgoingInterfaceIndex =
                        incomingInterfaceIndex;
                    updateForwardingTable = TRUE;
                }
                // Update next hop if necessary.
                //if (routePtr->nextHop != sourceAddress)
                if (match == FALSE)
                {
                    // COPY_ADDR6(from, to) // Ipv6 utility function
                    COPY_ADDR6(sourceAddress, routePtr->nextHopAddress);
                    updateForwardingTable = TRUE;
                }
                // Changed next hop or interface, so update IProuting table.
                // If the route is to be marked invalid, the IP routing
                // table update is done later.
                if (updateForwardingTable)
                {
                    if (routePtr->metric != RIPNG_INFINITY)
                    {
                        Ipv6UpdateForwardingTable(
                            node,
                            rtePtr->prefix,
                            rtePtr->prefixLen,
                            sourceGlobalAddress,
                            incomingInterfaceIndex,
                            dist_metric,
                            ROUTING_PROTOCOL_RIPNG);
                    }
                }
                if (routePtr->metric == RIPNG_INFINITY)
                {
                    // Mark route as invalid in the IP routing table.
                    // (Route is retained in RIPng route table.)
                    Ipv6UpdateForwardingTable(
                        node,
                        rtePtr->prefix,
                        rtePtr->prefixLen,
                        sourceGlobalAddress,
                        ANY_INTERFACE,
                        NETWORK_UNREACHABLE,
                        ROUTING_PROTOCOL_RIPNG);
                    // Cancel route-timeout timer.
                    routePtr->timeoutTime = 0;
                    // Start route-flush timer.
                    RIPngSetRouteTimer(
                        node,
                        &routePtr->flushTime,
                        routePtr->destPrefix,
                        RIPNG_GARBAGE_COLLECTION_INTERVAL,
                        RIPNG_GARBAGE);
                }
                else
                {
                    // Cancel route-flush timer if active.
                    routePtr->flushTime = 0;
                    // Route was not marked invalid in IP routing table,
                    // so refresh the route.
                    // Reinit route-timeout timer.
                    RIPngSetRouteTimer(
                        node,
                        &routePtr->timeoutTime,
                        routePtr->destPrefix,
                        RIPNG_ROUTE_TIMEOUT_INTERVAL,
                        RIPNG_TIMEOUT);
                }
                // Flag route as changed if it isn't already.
                routePtr->changed = TRUE;
                // Schedule triggered update.
                RIPngScheduleTriggeredUpdate(node);
                // Continue to next RTE.
                rteIndex++;
                if (rteIndex < numRtes)
                {
                    rtePtr = &(response.rtes[rteIndex]);
                }
                continue;
            }//if//
            // Route is not considered changed, so just refresh route.
            //if (routePtr->nextHop == sourceAddress
            //    && routePtr->flushTime == 0)
            if (match == TRUE && routePtr->flushTime == 0)
            {
                // Cancel route-flush timer if active.
                routePtr->flushTime = 0;
                // Reinit route-timeout timer.
                RIPngSetRouteTimer(
                    node,
                    &routePtr->timeoutTime,
                    routePtr->destPrefix,
                    RIPNG_ROUTE_TIMEOUT_INTERVAL,
                    RIPNG_TIMEOUT);
            }
            // Continue to next RTE.
            rteIndex++;
            if (rteIndex < numRtes)
            {
                rtePtr = &(response.rtes[rteIndex]);
            }
        }//end of while loop for each next//
    }
    if (RIPNG_DEBUG)
    {
        printf("\nRIPng Table Contents After Processing the packet\n");
        RIPngPrintRoutingTable(node);
    }
}


// FUNCTION RIPngClearChangedRouteFlags
// PURPOSE  Reset 'changed-flag' for all routing entry
// Parameters:
//  node:   Pointer to this node
static void RIPngClearChangedRouteFlags(Node* node) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
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


// FUNCTION RIPngSendResponse
// PURPOSE  Sends a RIPng Response message out the specified interface.
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  type:   Whether RIPNG_ALL_ROUTES (for regular update) or RIPNG_CHANGED_ROUTES (for triggered update)
static void RIPngSendResponse(Node* node,int interfaceIndex,RIPngResponseType type) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;
    unsigned routeIndex = 0;
    RIPngResponse response;
    in6_addr AllZeroIPv6Addr;
    in6_addr interfaceAddress;
    if (NetworkIpGetInterfaceType(node, interfaceIndex) == NETWORK_IPV4)
    {
        return;
    }
    // Allocate memory for response pkt rtes
    response.rtes = (RIPngRte*) MEM_malloc(RIPNG_RTE_SIZE
                                           * dataPtr->maxNumRte);
    memset(&AllZeroIPv6Addr, 0x00, sizeof(in6_addr));

    Ipv6GetGlobalAggrAddress(
        node,
        interfaceIndex,
        &interfaceAddress);

    // routeExaminedForPkt is used for creating
    // the response packet in RIPng format (i.e. nextHop oriented)
    unsigned char *routeExaminedForPkt =
                        (unsigned char *) MEM_malloc(dataPtr->numRoutes);
    memset(routeExaminedForPkt, 0x00, dataPtr->numRoutes);
    response.command = RIPNG_RESPONSE;  // Response message
    response.version = RIPNG_VERSION;   // for version 1
    response.mustBeZero = RIPNG_MUST_BE_ZERO;
    int rteIndex = 0;
    while (routeIndex < dataPtr->numRoutes)
    {
        // for all dataPtr->routeTable[routeIndex].nextHopAddress
        int rteDestEntry=0;
        unsigned i;
        for (i = routeIndex; i < dataPtr->numRoutes
                             && ((rteIndex + rteDestEntry + 1)
                                    < dataPtr->maxNumRte); i++)
        {
            if (routeExaminedForPkt[i] == 1
               ||
               ((CMP_ADDR6(
                    dataPtr->routeTable[routeIndex].nextHopAddress,
                    dataPtr->routeTable[i].nextHopAddress) != 0)
                 || (dataPtr->routeTable[routeIndex].
                        outgoingInterfaceIndex !=
                     dataPtr->routeTable[i].
                        outgoingInterfaceIndex)))
            {
                //for non-matched nextHopAddress
                continue;
            }
            // for matched nextHopAddress
            if (dataPtr->routeTable[i].flushed == TRUE)
            {
                // Don't send flushed routes.
                routeExaminedForPkt[i] = 1;
                continue;
            }
            if ((interfaceIndex ==
                    dataPtr->routeTable[i].learnedInterfaceIndex))
                 //&& (GetNumberOfTunnel(node, interfaceIndex) <= 1)) // Fix for DualIp
            {
                // Simple Split horizon only for wired networks.
                if (dataPtr->splitHorizon == RIPng_SPLIT_HORIZON_SIMPLE
                    && (TunnelIsVirtualInterface(node, interfaceIndex)||
                    MAC_IsWiredNetwork(node, interfaceIndex)))
                {
                    routeExaminedForPkt[i] = 1;
                    continue;
                }
             }
            if (type == RIPNG_CHANGED_ROUTES
                && dataPtr->routeTable[i].changed == FALSE)
            {
                // Triggered updates send only routes with the changed
                // flag.
                routeExaminedForPkt[i] = 1;
                continue;
            }
            // destAddress associated with current nextHop
            // found in i-th RIPng routeTable entry and it
            // will be considered for this pkt;
            // therefore advance rteDestEntry
            rteDestEntry++;
            // COPY_ADDR6(from, to) // Ipv6 utility function
            COPY_ADDR6(dataPtr->routeTable[i].destPrefix,
                response.rtes[rteIndex + rteDestEntry].prefix);
            // default value for route tag
            response.rtes[rteIndex + rteDestEntry].routeTag = 0;
            response.rtes[rteIndex + rteDestEntry].prefixLen =
                MAX_PREFIX_LEN;
            if ((interfaceIndex ==
                    dataPtr->routeTable[i].learnedInterfaceIndex))
                 //&& (GetNumberOfTunnel(node, interfaceIndex) <= 1)) // Fix for DualIp
            {
                if (dataPtr->splitHorizon ==
                        RIPng_SPLIT_HORIZON_POISONED_REVERSE
                    && (TunnelIsVirtualInterface(node, interfaceIndex)||
                    MAC_IsWiredNetwork(node, interfaceIndex)))
                {
                    // Split Horizon with poisoned reverse
                    response.rtes[rteIndex + rteDestEntry].metric =
                        RIPNG_INFINITY;
                }
                else
                {
                    // No Split-Horizon
                    response.rtes[rteIndex + rteDestEntry].metric =
                        dataPtr->routeTable[i].metric;
                }
            }
            else
            {
                response.rtes[rteIndex + rteDestEntry].metric =
                    dataPtr->routeTable[i].metric;
            }
            routeExaminedForPkt[i] = 1;
        }//end of for loop for the current next hop address
        // Next Hop RTE is created below
        if (rteDestEntry)
        {
            if ((CMP_ADDR6(
                    dataPtr->routeTable[routeIndex].nextHopAddress,
                    interfaceAddress) == 0)
                 && (dataPtr->routeTable[routeIndex].
                        outgoingInterfaceIndex
                     == interfaceIndex))
            {
                // Response pkt originator is itself next-hop address
                COPY_ADDR6(AllZeroIPv6Addr,
                    response.rtes[rteIndex].prefix);
            }
            else
            {
                COPY_ADDR6(
                    dataPtr->routeTable[routeIndex].nextHopAddress,
                    response.rtes[rteIndex].prefix);
            }
            response.rtes[rteIndex].routeTag = RIPNG_MUST_BE_ZERO;
            response.rtes[rteIndex].prefixLen = RIPNG_MUST_BE_ZERO;
            // denotes next hop RTE by assigning metric as 0xFF
            response.rtes[rteIndex].metric = 0xFF;
            rteIndex += rteDestEntry + 1;
        }
        if (i != dataPtr->numRoutes
             && rteIndex == dataPtr->maxNumRte)
        {
            // response pkt becomes full
            // but all the destAddresses for the current nextHop
            // are yet to be considered. Therefore donot advance
            // RIPng RouteTable index
        }
        else
        {
            // advance RIPng RouteTable index
            routeIndex++;
        }
        if ((rteIndex != 0 && routeIndex == dataPtr->numRoutes)
             || rteIndex == dataPtr->maxNumRte)
        {
            // send response pkt if either it is full or
            // when all the RIPng Route Table entries are examined
            // and there is atleast one entry in the pkt
            Address destAddress;
            Address sourceAddress;
            in6_addr multicastAddress;
            char buf[MAX_STRING_LENGTH];
            char* datagram;
            // response packet is muticast to the multicast
            // group FF02::9, the all-rip-routers multicast
            // group, on all connected networks that support
            // broadcasting or are point-to-point links.
            GetAllNeighborRipRouterMulticastAddress(&multicastAddress);
            SetIPv6AddressInfo(
                &destAddress,
                multicastAddress);
            SetIPv6AddressInfo(
                &sourceAddress,
                interfaceAddress);
            // allocate memory for datagram
            // and copy response pkt into datagram
            datagram = (char*) MEM_malloc(RIPNG_HEADER_SIZE
                                         + RIPNG_RTE_SIZE
                                         * rteIndex);
            memcpy(datagram, &response, RIPNG_HEADER_SIZE);
            memcpy(&datagram[RIPNG_HEADER_SIZE], response.rtes,
                RIPNG_RTE_SIZE * rteIndex);
            // Send datagram to UDP
            Message* msg = APP_UdpCreateMessage(
                node,
                sourceAddress,
                APP_ROUTING_RIPNG,
                destAddress,
                APP_ROUTING_RIPNG,
                TRACE_RIPNG,
                IPTOS_PREC_INTERNETCONTROL);

            APP_UdpSetOutgoingInterface(msg, interfaceIndex);

            APP_AddPayload(
                node,
                msg,
                (char*) datagram,
                RIPNG_HEADER_SIZE + RIPNG_RTE_SIZE * rteIndex);

            APP_UdpSend(node, msg, PROCESS_IMMEDIATELY);

            // free datagram here
            MEM_free(datagram);
            if (type == RIPNG_CHANGED_ROUTES)
            {
                // Increment stat for number of triggered update Packets
                dataPtr->stats.numTriggeredPacketSent++;
                if (RIPNG_DEBUG)
                {
                    char TimeBuf[MAX_STRING_LENGTH];
                    in6_addr destPrefix = Ipv6GetPrefixFromInterfaceIndex(
                                                            node,
                                                            interfaceIndex);
                    TIME_PrintClockInSecond(node->getNodeTime(), TimeBuf);
                    IO_ConvertIpAddressToString(&sourceAddress, buf);
                    printf("\nSending Triggered update from Node = %u, "
                        "at time %s (Sec), with Message Seq.No = %d;\n"
                        "Source = %s, InfIndx=%d\n",
                        node->nodeId,
                        TimeBuf,
                        dataPtr->stats.numTriggeredPacketSent,
                        buf,
                        interfaceIndex);
                    IO_ConvertIpAddressToString(&destPrefix, buf);
                    printf(", destAddr = %s\n",buf);
                    PrintRIPngResponsePacket(response, rteIndex);
                }
            }
            else if (type == RIPNG_ALL_ROUTES)
            {
                // Increment stat for number of regular update Packets
                dataPtr->stats.numRegularPacketSent++;
                if (RIPNG_DEBUG)
                {
                    char TimeBuf[MAX_STRING_LENGTH];
                    in6_addr destPrefix = Ipv6GetPrefixFromInterfaceIndex(
                                                            node,
                                                            interfaceIndex);
                    TIME_PrintClockInSecond(node->getNodeTime(), TimeBuf);
                    IO_ConvertIpAddressToString(&sourceAddress, buf);
                    printf("\nSending Regular update from Node = %u, "
                        "at time %s (Sec), with Message Seq.No = %d;\n"
                        "Source = %s, InfIndx=%d",
                        node->nodeId,
                        TimeBuf,
                        dataPtr->stats.numRegularPacketSent,
                        buf,
                        interfaceIndex);
                    IO_ConvertIpAddressToString(&destPrefix, buf);
                    printf(", destAddr = %s\n",buf);
                    PrintRIPngResponsePacket(response, rteIndex);
                }
            }
            else
            {
                ERROR_Assert(FALSE, "Unknown type !!!\n");
            }
            if (rteIndex == dataPtr->maxNumRte
                && routeIndex < dataPtr->numRoutes)
            {
                // response pkt becomes full but
                // not all the RIPng route table entries
                // are examined
                rteIndex = 0;
            }
        }
    } // end of while loop
    // Free response rtes
    MEM_free(response.rtes);
    // Free routeExaminedForPkt
    MEM_free(routeExaminedForPkt);
}


// FUNCTION PrintRIPngResponsePacket
// PURPOSE  Prints RIPng response packet contents
// Parameters:
//  response:   RIPng response packet
//  numRtes:    Number of routes in the response packet
static void PrintRIPngResponsePacket(RIPngResponse& response,unsigned int numRtes) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    char buf[MAX_STRING_LENGTH];
    printf("\nPrinting Response Packet\n");
    printf("========================"
        "================================\n");
    printf("\n              command=%u   version=%u"
        "   mustBeZero=%u\n",
        response.command,
        response.version,
        response.mustBeZero);
    unsigned int i = 0;
    printf("\n              destPrefix"
        "     routeTag  prefixLen  metric\n");
    for (i=0; i< numRtes; i++)
    {
        IO_ConvertIpAddressToString(&response.rtes[i].prefix,buf);
        printf("\n%24s        %u          %2u       %3u",
            buf,
            response.rtes[i].routeTag,
            response.rtes[i].prefixLen,
            response.rtes[i].metric);
    }
    printf("\n========================"
        "================================\n");
}


// FUNCTION GetAllNeighborRipRouterMulticastAddress
// PURPOSE  Get the all-rip-routers multicast group,  on all connected networks that support  broadcasting or are point-to-point links.
// Parameters:
//  multicastAddress:   Pointer to multicastAddress
static void GetAllNeighborRipRouterMulticastAddress(in6_addr* multicastAddress) {
//warning: Don't remove the opening and the closing brace
//add your code here:
    // response packet is muticast to the multicast
    // group FF02::9, the all-rip-routers multicast
    // group, on all connected networks that support
    // broadcasting or are point-to-point links.
    multicastAddress->s6_addr8[0] = 0xff;
    multicastAddress->s6_addr8[1] = 0x02;
    multicastAddress->s6_addr8[2] = 0x00;
    multicastAddress->s6_addr8[3] = 0x00;
    multicastAddress->s6_addr32[1] = 0;
    multicastAddress->s6_addr32[2] = 0;
    multicastAddress->s6_addr8[12] = 0x00;
    multicastAddress->s6_addr8[13] = 0x00;
    multicastAddress->s6_addr8[14] = 0x00;
    multicastAddress->s6_addr8[15] = 0x09;
}



//UserCodeEnd

//State Function Definitions
static void enterRIPngHandleRegularUpdateAlarm(Node* node,
                                               RIPngData* dataPtr,
                                               Message *msg) {

    //UserCodeStartHandleRegularUpdateAlarm
    int i = 0;
    Message* newMsg = NULL;
    clocktype delay = 0;
    dataPtr = (RIPngData*) node->appData.routingVar;

    // Increment stat for number of regular update events.
    dataPtr->stats.numRegularUpdateEvents++;

    // Send a response message to UDP on all eligible interfaces.
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (dataPtr->activeInterfaceIndexes[i]
            && NetworkIpInterfaceIsEnabled(node, i))
        {
             RIPngSendResponse(node, i, RIPNG_ALL_ROUTES);
        }
    }

    // Schedule next regular update.
    newMsg = MESSAGE_Alloc(
                node,
                APP_LAYER,
                APP_ROUTING_RIPNG,
                MSG_APP_RIPNG_RegularUpdateAlarm);


    // Add some jitter.
    // delay == (25.5, 30] seconds.
    delay = RIPNG_REGULAR_UPDATE_INTERVAL
            - (RANDOM_nrand(dataPtr->seed)
               % (clocktype) ((double) RIPNG_REGULAR_UPDATE_INTERVAL
                                       * RIPNG_REGULAR_UPDATE_JITTER));
    MESSAGE_Send(node, newMsg, delay);

    // clear Changed-route Flags
    RIPngClearChangedRouteFlags(node);

    // Record scheduled time of regular update.
    // The triggered update process uses this information.
    dataPtr->nextRegularUpdateTime = node->getNodeTime() + delay;

    //UserCodeEndHandleRegularUpdateAlarm

    dataPtr->state = RIPNG_IDLE;
    enterRIPngIdle(node, dataPtr, msg);
}

static void enterRIPngHandleTriggeredUpdateAlarm(Node* node,
                                                 RIPngData* dataPtr,
                                                 Message *msg) {

    //UserCodeStartHandleTriggeredUpdateAlarm
    dataPtr = (RIPngData*) node->appData.routingVar;
    int i = 0;

    // Increment stat for number of Triggered update events.
    dataPtr->stats.numTriggeredUpdateEvents++;

    // Send changed routes to UDP on all eligible interfaces.
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (dataPtr->activeInterfaceIndexes[i]
            && NetworkIpInterfaceIsEnabled(node, i))
        {
             RIPngSendResponse(node, i, RIPNG_CHANGED_ROUTES);
        }
    }

    // Clear changed-route flag
    RIPngClearChangedRouteFlags(node);

    // Clear triggered update flag.
    dataPtr->triggeredUpdateScheduled = FALSE;

    //UserCodeEndHandleTriggeredUpdateAlarm

    dataPtr->state = RIPNG_IDLE;
    enterRIPngIdle(node, dataPtr, msg);
}

static void enterRIPngHandleRouteTimerAlarm(Node* node,
                                            RIPngData* dataPtr,
                                            Message *msg) {

    //UserCodeStartHandleRouteTimerAlarm
    RIPngRouteTimerMsgInfo* info = (RIPngRouteTimerMsgInfo*)
                                    MESSAGE_ReturnInfo(msg);
    RIPngRtTable* routePtr = NULL;
    clocktype* timePtr = NULL;

    // Attempt to obtain route from RIP route table using IP address
    // of the route destination.
    routePtr = RIPngGetRoute(node, info->destPrefix);
    ERROR_Assert(routePtr, "RIPng cannot retrieve route from timer "
        "information");

    // Obtain pointer to route alarm time.
    if (info->type == RIPNG_TIMEOUT)
    {
        timePtr = &(routePtr->timeoutTime);
    }
    else
    {
        timePtr = &(routePtr->flushTime);
    }
    if (*timePtr != 0)
    {
        ERROR_Assert(*timePtr >= node->getNodeTime(), "RIPng route timer in "
            "the past");
        if (*timePtr != node->getNodeTime())
        {
            // Timer event was postponed, so reschedule another timer event
            Message* newMsg = MESSAGE_Duplicate(node, msg);

            MESSAGE_Send(node, newMsg, *timePtr - node->getNodeTime());

        }
       else
       {
            // node->getNodeTime() matches route alarm time,
            // so process timer event
            switch (info->type)
            {
                case RIPNG_TIMEOUT:
                {
                    if (RIPNG_DEBUG)
                    {
                        char TimeBuf[MAX_STRING_LENGTH];
                        TIME_PrintClockInSecond(*timePtr, TimeBuf);
                        printf("\nRIPngTimeOut occurs at %s sec\n", TimeBuf);
                    }
                    RIPngHandleRouteTimeout(node, routePtr);
                    break;
                }
                case RIPNG_GARBAGE:
                {
                    if (RIPNG_DEBUG)
                    {
                        char TimeBuf[MAX_STRING_LENGTH];
                        TIME_PrintClockInSecond(*timePtr, TimeBuf);
                        printf("\nRIPngRouteFlush occurs at %s sec\n", TimeBuf);
                    }
                    RIPngHandleRouteFlush(node, routePtr);
                    break;
                }
                default:
                    ERROR_ReportError("Invalid type of Timer !!!\n");
            }

            // Route timer is deactivated.
            *timePtr = 0;
        }
    }

    //UserCodeEndHandleRouteTimerAlarm

    dataPtr->state = RIPNG_IDLE;
    enterRIPngIdle(node, dataPtr, msg);
}

static void enterRIPngIdle(Node* node,
                           RIPngData* dataPtr,
                           Message *msg) {

    //UserCodeStartIdle
if (msg != NULL)
{
  MESSAGE_Free(node, msg);
}

    //UserCodeEndIdle


}

static void enterRIPngHandleFromTransport(Node* node,
                                          RIPngData* dataPtr,
                                          Message *msg) {

    //UserCodeStartHandleFromTransport
    RIPngResponse response;
    memcpy(&response, msg->packet, RIPNG_HEADER_SIZE);

    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_APPLICATION_LAYER,PACKET_IN, &acnData);

    switch (response.command)
    {
        case RIPNG_REQUEST:
        {
            ERROR_ReportError("RIPng does not support Request messages");
            break;
        }
        case RIPNG_RESPONSE:
        {
            RIPngProcessResponse(node, msg);
            break;
        }
        default:
            ERROR_ReportError("Invalid switch value");
    }


    //UserCodeEndHandleFromTransport

    dataPtr->state = RIPNG_IDLE;
    enterRIPngIdle(node, dataPtr, msg);
}


//Statistic Function Definitions
static void RIPngInitStats(Node* node, RIPngStatsType *stats) {
    if (node->guiOption) {
        stats->numRegularUpdateEventsId = GUI_DefineMetric("RIPng: Number of Regular Update Events", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numTriggeredUpdateEventsId = GUI_DefineMetric("RIPng: Number of Triggered Update Events", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRouteTimeoutsId = GUI_DefineMetric("RIPng: Number of Route Timeout Events", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numResponsesReceivedId = GUI_DefineMetric("RIPng: Number of Received Response Packets", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRegularPacketSentId = GUI_DefineMetric("RIPng: Number of Regular Update Packets Sent", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numTriggeredPacketSentId = GUI_DefineMetric("RIPng: Number of Triggered Update Packets Sent", node->nodeId, GUI_ROUTING_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
    }

    stats->numRegularUpdateEvents = 0;
    stats->numTriggeredUpdateEvents = 0;
    stats->numRouteTimeouts = 0;
    stats->numResponsesReceived = 0;
    stats->numRegularPacketSent = 0;
    stats->numTriggeredPacketSent = 0;
}

void RIPngPrintStats(Node* node) {
    RIPngStatsType *stats = &((RIPngData *) node->appData.routingVar)->stats;
    char buf[MAX_STRING_LENGTH];

    char statProtocolName[MAX_STRING_LENGTH];
    strcpy(statProtocolName,"RIPng");
    sprintf(buf, "RegularUpdateEvents = %u", stats->numRegularUpdateEvents);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "TriggeredUpdateEvents = %u", stats->numTriggeredUpdateEvents);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "RouteTimeouts = %u", stats->numRouteTimeouts);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "ResponsesReceived = %u", stats->numResponsesReceived);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "RegularPacketSent = %u", stats->numRegularPacketSent);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
    sprintf(buf, "TriggeredPacketSent = %u", stats->numTriggeredPacketSent);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, -1, buf);
}

void RIPngRunTimeStat(Node* node, RIPngData* dataPtr) {
    clocktype now = node->getNodeTime();

    if (node->guiOption) {
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRegularUpdateEventsId, dataPtr->stats.numRegularUpdateEvents, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numTriggeredUpdateEventsId, dataPtr->stats.numTriggeredUpdateEvents, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRouteTimeoutsId, dataPtr->stats.numRouteTimeouts, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numResponsesReceivedId, dataPtr->stats.numResponsesReceived, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRegularPacketSentId, dataPtr->stats.numRegularPacketSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numTriggeredPacketSentId, dataPtr->stats.numTriggeredPacketSent, now);
    }
}

// /**
// FUNCTION   :: RIPngInitTrace
// LAYER      :: APPLCATION
// PURPOSE    :: RIPng initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

static
void RIPngInitTrace(Node* node, const NodeInput* nodeInput)
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
        "TRACE-RIPNG",
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
                "TRACE-RIPNG should be either \"YES\" or \"NO\".\n");
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
            TRACE_EnableTraceXML(node, TRACE_RIPNG,
                "RIPNG", RIPngPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_RIPNG,
                "RIPNG", writeMap);
    }
    writeMap = FALSE;
}


void
RIPngInit(Node* node, const NodeInput* nodeInput, int interfaceIndex) {

    RIPngData *dataPtr = NULL;
    Message *msg = NULL;

    //UserCodeStartInit
    BOOL wasFound;
    char buf[MAX_STRING_LENGTH];

    if (node->networkData.networkProtocol == IPV4_ONLY)
    {
        char errorBuf[MAX_STRING_LENGTH];

        sprintf(errorBuf,
            "RIPng is IPv6 Network based routing protocol,"
            " it can not be run on Node %u\n", node->nodeId);
        ERROR_ReportError(errorBuf);
    }

    // Set the interface handler function to be called when interface
    // faults occur.

    MAC_SetInterfaceStatusHandlerFunction(
        node,
        interfaceIndex,
        &RIPngInterfaceStatusHandler); // TBD

    if (node->appData.routingVar == NULL)
    {
        // Nearly all initialization done when first eligible interface
        // enters this function.

        int i = 0;
        Message* newMsg;
        clocktype delay;

        // Allocate and init state.
        dataPtr = (RIPngData*) MEM_malloc(sizeof(RIPngData));
        memset(dataPtr,
            0,
            sizeof(RIPngData));

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "ROUTING-STATISTICS",
            &wasFound,
            buf);

        if ((wasFound == FALSE) || (strcmp(buf, "NO") == 0))
        {
            dataPtr->printStats = FALSE;
            dataPtr->initStats = FALSE;
        }
        else if (strcmp(buf, "YES") == 0)
        {
            dataPtr->printStats = TRUE;
            dataPtr->initStats = TRUE;
        }
        else
        {
            ERROR_ReportError("Need YES or NO for ROUTING-STATISTICS");
        }

        //dataPtr->initStats = TRUE;
        dataPtr->statsPrinted = FALSE;

        RANDOM_SetSeed(dataPtr->seed,
                       node->globalSeed,
                       node->nodeId,
                       APP_ROUTING_RIPNG,
                       interfaceIndex);

       // Set pointer in node data structure to RIPng state.
        node->appData.routingVar = (void*) dataPtr;

        // Allocate and initialize array tracking active RIPng interfaces.
        dataPtr->activeInterfaceIndexes =
            (unsigned char*) MEM_malloc(node->numberInterfaces);

        memset(dataPtr->activeInterfaceIndexes,
            0,
            node->numberInterfaces);

        // set the Split Horizon field
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node, interfaceIndex),
            nodeInput,
            "SPLIT-HORIZON",
            &wasFound,
            buf);
        if (wasFound == TRUE)
        {
            if (strcmp(buf, "NO") == 0)
            {
                dataPtr->splitHorizon = RIPng_SPLIT_HORIZON_OFF;
            }
            else if (strcmp(buf, "SIMPLE") == 0)
            {
                dataPtr->splitHorizon = RIPng_SPLIT_HORIZON_SIMPLE;
            }
            else if (strcmp(buf, "POISONED-REVERSE") == 0)
            {
                dataPtr->splitHorizon = RIPng_SPLIT_HORIZON_POISONED_REVERSE;
            }
            else
            {
                ERROR_ReportError("Expecting NO/SIMPLE/POISONED-REVERSE");
            }
        }
        else
        {
            // By Default Split-Horizon is applied
            dataPtr->splitHorizon = RIPng_SPLIT_HORIZON_SIMPLE;
        }
        // set maximum number of RTEs in an update packet
        dataPtr->maxNumRte = (int)((Ipv6GetMTU(node, interfaceIndex)
                                            - sizeof(ip6_hdr)
                                            - sizeof(TransportUdpHeader)
                                            - RIPNG_HEADER_SIZE)
                                        / (RIPNG_RTE_SIZE));
        // Init route table.
        RIPngInitRouteTable(node);

        // Add directly connected networks (including wireless subnets
        // which the node has interfaces on) as permanent routes to the
        // route table.

        for (i = 0; i < node->numberInterfaces; i++)
        {
            RIPngRtTable* routePtr = NULL;
            in6_addr interfaceAddress;
            in6_addr destAddress;
            int hopCount;

            if (NetworkIpGetInterfaceType(node, i) != NETWORK_IPV6
                && NetworkIpGetInterfaceType(node, i) != NETWORK_DUAL)
            {
                continue;
            }
            if (NetworkIpIsWiredNetwork(node, i))
            {
                // Get global interface address from the interface index
                Ipv6GetGlobalAggrAddress(
                    node,
                    i,
                    &interfaceAddress);

                // Get the destination prefix from the interface index
                destAddress = Ipv6GetPrefixFromInterfaceIndex(
                                  node,
                                  i);
                hopCount = 1;
            }
            else
            {
                // Get global interface address from the interface index
                Ipv6GetGlobalAggrAddress(
                    node,
                    i,
                    &interfaceAddress);
                destAddress = interfaceAddress;
                hopCount = 0;
            }

            if (!RIPngGetRoute(node, destAddress) &&
                !IS_LINKLADDR6(destAddress))
            {
                routePtr = RIPngAddRoute(
                               node,
                               destAddress,
                               interfaceAddress,
                               hopCount,
                               i,
                               i);

                routePtr->prefixLen =
                                (unsigned char) Ipv6GetPrefixLength(node, i);

                // route not flagged as changed
                routePtr->changed = FALSE;
            }
        }
        // Schedule first regular update.
        newMsg = MESSAGE_Alloc(
                    node,
                    APP_LAYER,
                    APP_ROUTING_RIPNG,
                    MSG_APP_RIPNG_RegularUpdateAlarm);

        // Add some jitter.
        // delay == (0, 100] milliseconds.

        delay = RIPNG_STARTUP_DELAY
                - (RANDOM_nrand(dataPtr->seed)
                   % (clocktype) ((double) RIPNG_STARTUP_DELAY
                                   * RIPNG_STARTUP_JITTER));

        MESSAGE_Send(node, newMsg, delay);

        // Record time of first regular update.
        // The triggered update process uses this information.

        dataPtr->nextRegularUpdateTime = node->getNodeTime() + delay;
    }
    else
    // This is already initialized
    {
        // Little initialization for subsequent eligible interfaces.
        // Just retrieve RIP state from node data structure.

         dataPtr = (RIPngData*) node->appData.routingVar;
    }
    dataPtr->activeInterfaceIndexes[interfaceIndex] = 1;
    // Make sure the dataPtr is either allocated or set
    // *before* the following auto-generated code

    //UserCodeEndInit
    if (dataPtr->initStats) {
        RIPngInitStats(node, &(dataPtr->stats));
    }
    dataPtr->state = RIPNG_IDLE;
    enterRIPngIdle(node, dataPtr, msg);

    // Intialize trace
    RIPngInitTrace(node, nodeInput);

    // registering RipngHandleAddressChangeEvent function
    Ipv6AddPrefixChangedHandlerFunction(
                                node,
                                &RipngHandleAddressChangeEvent);
}


void
RIPngFinalize(Node* node, int interfaceIndex) {

    RIPngData* dataPtr = (RIPngData*) node->appData.routingVar;

    //UserCodeStartFinalize
        //dataPtr->printStats = FALSE;
        if (RIPNG_DEBUG
            && !dataPtr->statsPrinted)
        {
            printf("\nRIPng Routing Tables At the End of Simulation\n");
            RIPngPrintRoutingTable(node);
        }


    //UserCodeEndFinalize

    if (dataPtr->statsPrinted) {
        return;
    }

    if (dataPtr->printStats) {
        dataPtr->statsPrinted = TRUE;
        RIPngPrintStats(node);
    }
}


void
RIPngProcessEvent(Node* node, Message* msg) {

    RIPngData* dataPtr;
    int event;

    dataPtr = (RIPngData*) node->appData.routingVar;
    if (!dataPtr) {
        MESSAGE_Free(node, msg);
        return;
    }

    event = msg->eventType;
    switch (dataPtr->state) {
        case RIPNG_HANDLE_REGULAR_UPDATE_ALARM:
            assert(FALSE);
            break;
        case RIPNG_HANDLE_TRIGGERED_UPDATE_ALARM:
            assert(FALSE);
            break;
        case RIPNG_HANDLE_ROUTE_TIMER_ALARM:
            assert(FALSE);
            break;
        case RIPNG_IDLE:
            switch (event) {
                case MSG_APP_RIPNG_RegularUpdateAlarm:
                    dataPtr->state = RIPNG_HANDLE_REGULAR_UPDATE_ALARM;
                    enterRIPngHandleRegularUpdateAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_RIPNG_TriggeredUpdateAlarm:
                    dataPtr->state = RIPNG_HANDLE_TRIGGERED_UPDATE_ALARM;
                    enterRIPngHandleTriggeredUpdateAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_RIPNG_RouteTimerAlarm:
                    dataPtr->state = RIPNG_HANDLE_ROUTE_TIMER_ALARM;
                    enterRIPngHandleRouteTimerAlarm(node, dataPtr, msg);
                    break;
                case MSG_APP_FromTransport:
                    dataPtr->state = RIPNG_HANDLE_FROM_TRANSPORT;
                    enterRIPngHandleFromTransport(node, dataPtr, msg);
                    break;
                default:
                    assert(FALSE);
            }
            break;
        case RIPNG_HANDLE_FROM_TRANSPORT:
            assert(FALSE);
            break;
        default:
            ERROR_ReportError("Illegal transition");
            break;
    }

}


//---------------------------------------------------------------------------
// FUNCTION             :  RipngHandleAddressChangeEvent
// PURPOSE              :: Handle Prefix change event,when a node enters
//                         in a new Network its prefix changes so this
//                         function send Trigger Update to neighboring
//                         routers that route is changed and send updated
//                         routing table.
// PARAMETERS           ::
// + node               : Node* : Pointer to Node structure
// + interfaceIndex     : Int : interface index
// + oldGlobalAddress   : in6_addr* old global address
// RETURN               : None
//---------------------------------------------------------------------------
void
RipngHandleAddressChangeEvent(Node* node,
                              int interfaceId,
                              in6_addr* oldGlobalAddress)
{
    IPv6Data* ipv6 = (IPv6Data *)node->networkData.networkVar->ipv6;

    IPv6InterfaceInfo* ipv6InterfaceInfo =
                     ipv6->ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    RIPngRtTable* routePtr = NULL;

    in6_addr oldPrefix;
    in6_addr interfaceAddress;
    in6_addr destAddress;
    int hopCount;

    // extracting old prefix
    if (NetworkIpIsWiredNetwork(node, interfaceId))
    {
        COPY_ADDR6(*oldGlobalAddress, oldPrefix);
    }
    else
    {
        Ipv6GetPrefix(
            oldGlobalAddress,
            &oldPrefix,
            ipv6InterfaceInfo->autoConfigParam.depGlobalAddrPrefixLen);
    }

    routePtr = RIPngGetRoute(node, oldPrefix);

    if (routePtr != NULL)
    {

        routePtr->metric = RIPNG_INFINITY;

        routePtr->changed = TRUE;

        routePtr->timeoutTime = 0;

        RIPngSetRouteTimer(node,
                           &routePtr->flushTime,
                           oldPrefix,
                           RIPNG_GARBAGE_COLLECTION_INTERVAL,
                           RIPNG_GARBAGE);
    }
    if (!IS_LINKLADDR6(ipv6InterfaceInfo->globalAddr))
    {
        routePtr = NULL;
        if (NetworkIpIsWiredNetwork(node, interfaceId))
        {
            // Get interface address from the interface index
            Ipv6GetGlobalAggrAddress(
                node,
                interfaceId,
                &interfaceAddress);

            // Get the destination prefix from the interface index
            destAddress = Ipv6GetPrefixFromInterfaceIndex(
                              node,
                              interfaceId);
            hopCount = 1;
        }
        else
        {
            // Get global interface address from the interface index
            Ipv6GetGlobalAggrAddress(
                node,
                interfaceId,
                &interfaceAddress);
            destAddress = interfaceAddress;
            hopCount = 0;
        }

        if (!RIPngGetRoute(node, destAddress))
        {
            routePtr = RIPngAddRoute(
                           node,
                           destAddress,
                           interfaceAddress,
                           hopCount,
                           interfaceId,
                           interfaceId);

            routePtr->prefixLen = Ipv6GetPrefixLength(node, interfaceId);

            // route not flagged as changed
            routePtr->changed = FALSE;
        }
    }
    RIPngScheduleTriggeredUpdate(node);
}
