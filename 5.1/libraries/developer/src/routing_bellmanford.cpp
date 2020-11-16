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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "network_ip.h"
#include "app_util.h"
#include "routing_bellmanford.h"


#define nDEBUG
#define nDEBUG_TABLE

//-----------------------------------------------------------------------------
// DEFINES
//-----------------------------------------------------------------------------

//
// The route table starts with memory allocated for this many routes.
//

#define NUM_INITIAL_ROUTES_ALLOCATED   4

//
// Bellman-Ford value for infinite distance.
//

#define BELLMANFORD_INFINITY   16

//
// Each node broadcasts its entire route table (a periodic update)
// at intervals of:
// PERIODIC_UPDATE_INTERVAL + [0, PERIODIC_UPDATE_JITTER) seconds.
//

#define PERIODIC_UPDATE_INTERVAL   (10 * SECOND)
#define PERIODIC_UPDATE_JITTER     (150 * MILLI_SECOND)

//
// Each node checks for timed-out routes at intervals of:
// CHECK_TIMEOUT_INTERVAL + [0, CHECK_TIMEOUT_JITTER) seconds.
//

#define CHECK_TIMEOUT_INTERVAL     (60 * SECOND)
#define CHECK_TIMEOUT_JITTER       (100 * MILLI_SECOND)

//
// Triggered updates are scheduled after a delay of:
// TRIGGERED_UPDATE_DELAY + [0, TRIGGERED_UPDATE_JITTER) seconds.
//

#define TRIGGERED_UPDATE_DELAY     (0 * SECOND)
#define TRIGGERED_UPDATE_JITTER    (150 * MILLI_SECOND)

//
// If a route is >= TIMEOUT_DELAY in age, it is considered timed out.
//

#define TIMEOUT_DELAY   (60 * SECOND)

//
// Each route-advertisement packet is limited to this many routes.
// If more routes need to be sent, multiple packets are sent.
//

#define MAX_ROUTES_PER_ROUTE_ADVERTISEMENT_PACKET   32



//-----------------------------------------------------------------------------
// STRUCTS, ENUMS, AND TYPEDEFS
//-----------------------------------------------------------------------------

//
// Route in a route table.
//

typedef struct
{
    NodeAddress destAddress;
    NodeAddress subnetMask;
    NodeAddress nextHop;
    int         incomingInterface;
    int         outgoingInterface;

    short       distance;
    BOOL        localRoute;

    clocktype   refreshTime;
    BOOL        changed;
    // This flag is set if its a re-distributed route
    BOOL        isPermanent;
} Route;

//
// Bellman-Ford state.
//

typedef struct
{
    // General state information.

    clocktype nextPeriodicUpdateTime;
    BOOL triggeredUpdateScheduled;

    // Route table.

    Route *routeTable;
    int numRoutesAllocated;
    int numRoutes;

    // Statistics.

    int numPeriodicUpdates;
    int numTriggeredUpdates;
    int numRouteTimeouts;
    int numRouteAdvertisementsReceived;
    RandomSeed periodicJitterSeed;
    RandomSeed checkTimeoutSeed;
    RandomSeed triggeredUpdateSeed;
    BOOL statsPrinted;
} Bellmanford;

//
// Header fields for route-advertisement packet.
//

typedef struct
{
    NodeAddress sourceAddress;  // source IP address
    NodeAddress destAddress;    // destination IP address
    int         payloadSize;    // size of payload in bytes
} RoutingBellmanfordHeader;

//
// Route in a route-advertisement packet.
//

typedef struct
{
    NodeAddress destAddress;
    NodeAddress subnetMask;
    NodeAddress nextHop;

    int         distance;
} AdvertisedRoute;

//
// enum for argument passed to SendRouteAdvertisement() to determine
// whether to execute in periodic or triggered update mode.
//

typedef enum
{
   ROUTING_BELLMANFORD_PERIODIC_UPDATE = 0,
   ROUTING_BELLMANFORD_TRIGGERED_UPDATE
} RouteAdvertisementType;

//
// enum for argument passed to PrintRouteTable() to vary what kind of
// output to print to screen.
//

typedef enum
{
    ROUTING_BELLMANFORD_PRE_UPDATE = 0,
    ROUTING_BELLMANFORD_POST_UPDATE
} PrintRouteTableType;



//-----------------------------------------------------------------------------
// PROTOTYPES FOR FUNCTIONS WITH INTERNAL LINKAGE
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Handler functions for Bellman-Ford internal messages
//-----------------------------------------------------------------------------

static void //inline//
HandlePeriodicUpdateAlarm(Node *node);

static void //inline//
HandleCheckRouteTimeoutAlarm(Node *node);

static void //inline//
HandleTriggeredUpdateAlarm(Node *node);

static void //inline//
SendRouteAdvertisement(
    Node *node, RouteAdvertisementType type);

static void //inline//
ScheduleTriggeredUpdate(Node *node);

//-----------------------------------------------------------------------------
// Handler functions for messages from the transport layer
//-----------------------------------------------------------------------------

static void //inline//
HandleFromTransport(Node *node, Message *msg);

static void //inline//
ProcessRouteAdvertisementPacket(
    Node *node,
    NodeAddress neighborAddr,
    int incomingInterfaceIndex,
    int numOfRTEntries,
    AdvertisedRoute *neighborRowPtr);

//-----------------------------------------------------------------------------
// Route table manipulation functions
//-----------------------------------------------------------------------------

static void //inline//
InitRouteTable(Bellmanford *bellmanford);

static Route * //inline//
FindRoute(
    Bellmanford *bellmanford,
    NodeAddress destAddress);

static Route * //inline//
AddRoute(
    Bellmanford *bellmanford,
    NodeAddress destAddress,
    NodeAddress subnetMask,
    NodeAddress nextHop,
    int incomingInterfaceIndex,
    int distance);

//-----------------------------------------------------------------------------
// Statistics
//-----------------------------------------------------------------------------

static void //inline//
PrintStats(Node *node);

//-----------------------------------------------------------------------------
// Debug output functions
//-----------------------------------------------------------------------------

static void //inline//
PrintRouteAdvertisementPacket(
    Node *node,
    AdvertisedRoute *neighborRowPtr,
    int numAdvertisedRoutes);

static void //inline//
PrintRouteTable(
    Node *node,
    PrintRouteTableType type);



//-----------------------------------------------------------------------------
// FUNCTIONS WITH EXTERNAL LINKAGE
//-----------------------------------------------------------------------------
// /**
// FUNCTION   :: RoutingBellmanfordInitTrace
// LAYER      :: APPLCATION
// PURPOSE    :: Bellmanford initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

void RoutingBellmanfordInitTrace(Node* node, const NodeInput* nodeInput)
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
        "TRACE-BELLMANFORD",
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
                "TRACE-BELLMANFORD should be either \"YES\" or \"NO\".\n");
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
            TRACE_EnableTraceXML(node, TRACE_BELLMANFORD,
                "BELLMANFORD", RoutingBellmanfordPrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_BELLMANFORD,
                "BELLMANFORD", writeMap);
    }
    writeMap = FALSE;
}
//-----------------------------------------------------------------------------
// Print TraceXML function
//-----------------------------------------------------------------------------


//-----------------------------------------------------------------------------
// FUNCTION   :: RoutingBellmanfordPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
//-----------------------------------------------------------------------------

void RoutingBellmanfordPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    char sourceAddr[MAX_STRING_LENGTH];
    char destinationAddr[MAX_STRING_LENGTH];
    char nexthopAddr[MAX_STRING_LENGTH];

    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;
    RoutingBellmanfordHeader *header;
    AdvertisedRoute *payload;
    int numAdvertisedRoutes;

    // If bellmanford is not configured here, then discard message.
    if (!bellmanford)
    {
        return;
    }
    // Obtain pointers to header, payload.

    header = (RoutingBellmanfordHeader *) msg->packet;
    payload = (AdvertisedRoute *)
              (msg->packet + sizeof(RoutingBellmanfordHeader));

    IO_ConvertIpAddressToString(header->sourceAddress, sourceAddr);
    IO_ConvertIpAddressToString(header->destAddress , destinationAddr);

     // Obtain number of rows in update.

    sprintf(buf, "<bellmanford>");
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf,"%s %s %d",
             sourceAddr,
             destinationAddr,
             header->payloadSize );
    TRACE_WriteToBufferXML(node, buf);

    numAdvertisedRoutes = header->payloadSize / sizeof(AdvertisedRoute);

    for (int i = 0; i < numAdvertisedRoutes; i++) {

    IO_ConvertIpAddressToString(payload->destAddress , destinationAddr);
    IO_ConvertIpAddressToString(payload->subnetMask, sourceAddr);
    IO_ConvertIpAddressToString(payload->nextHop, nexthopAddr);

    sprintf(buf,"<advertisedRoute>%s %s %s %d </advertisedRoute>",
                    destinationAddr,
                    sourceAddr,
                    nexthopAddr,
                    payload->distance);
    TRACE_WriteToBufferXML(node, buf);
    payload++;
    }

    sprintf(buf, "</bellmanford>");
    TRACE_WriteToBufferXML(node, buf);
}

//-----------------------------------------------------------------------------
// Init function
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     RoutingBellmanfordInit
// PURPOSE      Initializes the Bellman-Ford model.
//
// Parameters:
//
// Node *node
//     For current node
//
// Notes:
//
// This function is called once per node, for nodes which are running
// the Bellman-Ford model for routing.
//-----------------------------------------------------------------------------

void
RoutingBellmanfordInit(Node *node)
{
    Bellmanford *bellmanford;
    int i;
    clocktype randomDelay;

    Message *newMsg;

    if (node->networkData.networkProtocol == IPV6_ONLY)
    {
        // Bellmanford is an IPv4 Network based routing protocol,
        // it can not be run on this node

        return;
    }

    // Allocate Bellmanford struct.  Assign pointers.

    bellmanford = (Bellmanford *) MEM_malloc(sizeof(Bellmanford));
    node->appData.bellmanford = (void *) bellmanford;

    //Need for route redistribution
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    // Init stats.

    bellmanford->numPeriodicUpdates = 0;
    bellmanford->numRouteTimeouts = 0;
    bellmanford->numTriggeredUpdates = 0;
    bellmanford->numRouteAdvertisementsReceived = 0;
    bellmanford->statsPrinted = FALSE;

    // Init random seeds to each be different

    RANDOM_SetSeed(bellmanford->periodicJitterSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_BELLMANFORD,
                   1);
    RANDOM_SetSeed(bellmanford->checkTimeoutSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_BELLMANFORD,
                   2);
    RANDOM_SetSeed(bellmanford->triggeredUpdateSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_BELLMANFORD,
                   3);

    // Init Bellman-Ford route table.

    InitRouteTable(bellmanford);

    // Add 0-hop routes to local networks.  These are flagged as
    // local routes.
    //
    // Loop through all interfaces, since it's assumed that Bellman-Ford
    // is running on all interfaces on a node.

    for (i = 0; i < node->numberInterfaces; i++)
    {
        NodeAddress destAddress;
        NodeAddress subnetMask;
        Route *rowPtr;

        if (NetworkIpGetInterfaceType(node, i) != NETWORK_IPV4
            && NetworkIpGetInterfaceType(node, i) != NETWORK_DUAL)
        {
            continue;
        }

        if (NetworkIpIsWiredNetwork(node, i))
        {
            // This is a wiredlink interface.
            //
            // The destAddress is the network address for the interface,
            // and subnetMask is the subnet mask for the interface.

            destAddress = NetworkIpGetInterfaceNetworkAddress(node, i);
            subnetMask = NetworkIpGetInterfaceSubnetMask(node, i);
        }
        else
        {
            // This is a wireless interface.
            //
            // The destAddress is the IP address of the interface
            // itself, and subnetMask is 255.255.255.255 (ANY_DEST is
            // an all-one 32-bit value).
            //
            // This means that the route applies exactly to the host IP
            // address of the interface. (not to a network address)

            destAddress = NetworkIpGetInterfaceAddress(node, i);
            subnetMask = ANY_DEST;
        }

        if (!FindRoute(bellmanford, destAddress)
            // Dynamic address
            && ip->interfaceInfo[i]->addressState != INVALID)
        {
            rowPtr = AddRoute(bellmanford,
                         destAddress,
                         subnetMask,
                         NetworkIpGetInterfaceAddress(node, i),
                         i,
                         0);

            rowPtr->localRoute = TRUE;
        }

#ifdef ENTERPRISE_LIB
        if (ip->interfaceInfo[i]->routingProtocolType
            == ROUTING_PROTOCOL_BELLMANFORD)
        {

            RouteRedistributeSetRoutingTableUpdateFunction(
                node,
                &BellmanfordHookToRedistribute,
                i);
        }
#endif // ENTERPRISE_LIB
    }

    // Calculate jitter for first periodic update.

    randomDelay = RANDOM_nrand(bellmanford->periodicJitterSeed) % PERIODIC_UPDATE_JITTER;

    // Schedule first periodic update.

    newMsg = MESSAGE_Alloc(node,
                           APP_LAYER,
                           APP_ROUTING_BELLMANFORD,
                           MSG_APP_PeriodicUpdateAlarm);

    MESSAGE_Send(node, newMsg, 0);

    // Record time of periodic update in nextPeriodicUpdateTime.
    // (ScheduleTriggeredUpdate() uses this value.)

    bellmanford->nextPeriodicUpdateTime = node->getNodeTime() + randomDelay;

    // Calculate jitter for first route timeout check.

    randomDelay = RANDOM_nrand(bellmanford->checkTimeoutSeed) % CHECK_TIMEOUT_JITTER;

    // Schedule first route timeout.

    newMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_ROUTING_BELLMANFORD,
                            MSG_APP_CheckRouteTimeoutAlarm);
    MESSAGE_Send(node, newMsg, CHECK_TIMEOUT_INTERVAL + randomDelay);


    // Dynamic address
    // registering RoutingBellmanfordHandleAddressChangeEvent function
    NetworkIpAddAddressChangedHandlerFunction(node,
                            &RoutingBellmanfordHandleChangeAddressEvent);
}

//-----------------------------------------------------------------------------
// Layer function
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     RoutingBellmanfordLayer
// PURPOSE      Layer function for the Bellman-Ford model.
//
// Parameters:
//
// Node *node
//     For current node
// Message *msg
//     Message to be processed
//
// Notes:
//
// The MESSAGE_Free() on msg is called at the end of the function.
//-----------------------------------------------------------------------------

void
RoutingBellmanfordLayer(Node *node, Message *msg)
{
    if (node->networkData.networkProtocol == IPV6_ONLY)
    {
        // Bellmanford is an IPv4 Network based routing protocol,
        // it can not be run on this node

        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_INVALID_NETWORK_PROTOCOL;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_APPLICATION_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);

        return;
    }
    switch (msg->eventType)
    {
        // Messages sent within Bellman-Ford.

        case MSG_APP_PeriodicUpdateAlarm:
        {
            HandlePeriodicUpdateAlarm(node);
            break;
        }
        case MSG_APP_CheckRouteTimeoutAlarm:
        {
            HandleCheckRouteTimeoutAlarm(node);
            break;
        }
        case MSG_APP_TriggeredUpdateAlarm:
        {
            HandleTriggeredUpdateAlarm(node);
            break;
        }

        // Messages sent by UDP to Bellman-Ford.

        case MSG_APP_FromTransport:
        {
            HandleFromTransport(node, msg);
            break;
        }
        default:
            ERROR_ReportError("Invalid switch value");
    }

    // Done with the message, so free it.

    MESSAGE_Free(node, msg);
}

//-----------------------------------------------------------------------------
// Finalize function
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     RoutingBellmanfordFinalize
// PURPOSE      Finalize function for the Bellman-Ford model.
//
// Parameters:
//
// Node *node
//     For current node.
// int interfaceIndex
//     Interface index we are finalizing.
//
// Notes:
//
// Called once per node, per interface that is running Bellman-Ford.
// ...PrintStats() is called only for interfaceIndex 0.  See the
// ...PrintStats() function for more info.
//-----------------------------------------------------------------------------

void
RoutingBellmanfordFinalize(Node *node, int interfaceIndex)
{
    Bellmanford *bellmanford = (Bellmanford *)node->appData.bellmanford;

    if (node->networkData.networkProtocol == IPV6_ONLY)
    {
        // Bellmanford is an IPv4 Network based routing protocol,
        // it can not be run on this node

        return;
    }
    if (node->appData.routingStats == TRUE
        && bellmanford->statsPrinted == FALSE)
    {
        PrintStats(node);
        bellmanford->statsPrinted = TRUE;
    }
}



//-----------------------------------------------------------------------------
// FUNCTIONS WITH INTERNAL LINKAGE
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// Handler functions for Bellman-Ford internal messages
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     HandlePeriodicUpdateAlarm
// PURPOSE      Broadcasts a periodic update and schedules another.
//
// Parameters:
//
// Node *node
//     For current node.
//-----------------------------------------------------------------------------

static void //inline//
HandlePeriodicUpdateAlarm(Node *node)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    clocktype delay;
    Message *newMsg;

    // Send all routes to UDP.  Increment stat.

    SendRouteAdvertisement(
        node, ROUTING_BELLMANFORD_PERIODIC_UPDATE);

    // Schedule next periodic update. (node->getNodeTime() + 10 s + 0-100 ms)

    delay = PERIODIC_UPDATE_INTERVAL
            + (RANDOM_nrand(bellmanford->periodicJitterSeed) % PERIODIC_UPDATE_JITTER);

    newMsg = MESSAGE_Alloc(node,
                            APP_LAYER,
                            APP_ROUTING_BELLMANFORD,
                            MSG_APP_PeriodicUpdateAlarm);

    MESSAGE_Send(node, newMsg, delay);

    // Record time of next periodic update in nextPeriodicUpdateTime.
    // (ScheduleTriggeredUpdate() uses this value.)

    bellmanford->nextPeriodicUpdateTime = node->getNodeTime() + delay;
}

//-----------------------------------------------------------------------------
// FUNCTION     HandleCheckRouteTimeoutAlarm
// PURPOSE      Checks for route timeouts, schedules triggered update if
//              necessary.  Schedules next route timeout check.
//
// Parameters:
//
// Node *node
//     For current node.
//
// Notes:
//
// All routes (that aren't timed out already) are checked for staleness.
// Stale routes are marked unreachable and a triggered update is
// scheduled.
//-----------------------------------------------------------------------------

static void //inline//
HandleCheckRouteTimeoutAlarm(Node *node)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    int i;
    BOOL routeChanged;
    Message *newMsg;

#ifdef DEBUG
    {
        char cbuf[20];

        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

        printf("Bellmanford: %s s, node %u, --- Route timeout check\n",
               cbuf, node->nodeId);
    }
#endif // DEBUG

    // Look for stale routes in route table.

    routeChanged = FALSE;
    for (i = 0; i < bellmanford->numRoutes; i++)
    {

    // Added for redistribution. If its a redistributed route then we
    //  dont time out.
        if (bellmanford->routeTable[i].isPermanent == TRUE)
        {
          // move to the next route
             continue;
    }
        // Don't time out local routes, routes already marked unreachable.

        if (bellmanford->routeTable[i].localRoute == FALSE
            && bellmanford->routeTable[i].distance != BELLMANFORD_INFINITY
            && node->getNodeTime() - bellmanford->routeTable[i].refreshTime
               >= TIMEOUT_DELAY)
        {
            // Found new stale route.

#ifdef DEBUG_TABLE
            if (routeChanged == FALSE)
            {
                // We have a route change resulting from a route timeout,
                // and will be updating our route table.

                // Print pre-update route table.

                PrintRouteTable(
                    node,
                    ROUTING_BELLMANFORD_PRE_UPDATE);
            }
#endif // DEBUG_TABLE

            if (routeChanged == FALSE)
            {
                routeChanged = TRUE;
            }

            // Set nextHop is NETWORK_UNREACHABLE, distance is infinity,
            // routeChanged flag to TRUE.

            bellmanford->routeTable[i].nextHop     =
                (unsigned) NETWORK_UNREACHABLE;
            bellmanford->routeTable[i].distance    = BELLMANFORD_INFINITY;
            bellmanford->routeTable[i].refreshTime = node->getNodeTime();
            bellmanford->routeTable[i].changed     = TRUE;

            // Update forwarding table to indicate no route to
            // destAddress.

            NetworkUpdateForwardingTable(
                node,
                bellmanford->routeTable[i].destAddress,
                bellmanford->routeTable[i].subnetMask,
                (unsigned) NETWORK_UNREACHABLE,
                ANY_INTERFACE,
                bellmanford->routeTable[i].distance,
                ROUTING_PROTOCOL_BELLMANFORD);

            // Increment stat for a route timeout.
            // (If a route times out, becomes valid, and times out
            // again -- the second timeout also counts.)

            bellmanford->numRouteTimeouts++;

#ifdef DEBUG
#ifndef DEBUG_TABLE
            {
                char cbuf[20];

                TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

                printf("Bellmanford: %s s, node %u, --- Route timeout, dest"
                       " = %d\n",cbuf, node->nodeId, i);
            }
#endif // DEBUG_TABLE
#endif // DEBUG
        }
    }

    // If any route timed out, schedule a triggered update.

    if (routeChanged == TRUE)
    {
#ifdef DEBUG_TABLE
        // If the table was updated, print post-update route table.

        PrintRouteTable(
            node,
            ROUTING_BELLMANFORD_POST_UPDATE);
#endif // DEBUG_TABLE

        ScheduleTriggeredUpdate(node);
    }

    // Schedule next route timeout check.

    newMsg = MESSAGE_Alloc(node,
                           APP_LAYER,
                           APP_ROUTING_BELLMANFORD,
                           MSG_APP_CheckRouteTimeoutAlarm);

    MESSAGE_Send(node, newMsg,
                 CHECK_TIMEOUT_INTERVAL
                 + (RANDOM_nrand(bellmanford->checkTimeoutSeed) % CHECK_TIMEOUT_JITTER));
}

//-----------------------------------------------------------------------------
// FUNCTION     HandleTriggeredUpdateAlarm
// PURPOSE      Broadcasts a triggered update.
//
// Parameters:
//
// Node *node
//     For current node.
//
// Notes:
//
// This is called sometime after ScheduleTriggeredUpdate()
// schedules an update.  SendRouteAdvertisement() is
// called to broadcast the triggered update.
//-----------------------------------------------------------------------------

static void //inline//
HandleTriggeredUpdateAlarm(Node *node)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    // Send updated routes to UDP.

    SendRouteAdvertisement(node, ROUTING_BELLMANFORD_TRIGGERED_UPDATE);

    // Clear flag so that another triggered update can be scheduled if
    // it becomes necessary.

    bellmanford->triggeredUpdateScheduled = FALSE;
}

//-----------------------------------------------------------------------------
// FUNCTION     SendRouteAdvertisement
// PURPOSE      Broadcasts route-advertisement packets on all interfaces.
//
// Parameters:
//
// Node *node
//     For current node.
// RouteAdvertisementType type
//     ROUTING_BELLMANFORD_PERIODIC_UPDATE
//     or,
//     ROUTING_BELLMANFORD_TRIGGERED_UPDATE
//
// Notes:
//
// If type indicates periodic update, then all routes are advertised.
// If type indicates triggered update, then only flagged routes (routes
// which changed since the last update event) are advertised.
//-----------------------------------------------------------------------------

static void //inline//
SendRouteAdvertisement(
    Node *node, RouteAdvertisementType type)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    AdvertisedRoute payloadBuf[MAX_ROUTES_PER_ROUTE_ADVERTISEMENT_PACKET];
    int rowIndex;

    // In the while loop, send the current node's entire route table to
    // UDP, using multiple packets if necessary.

    rowIndex = 0;
    while (rowIndex < bellmanford->numRoutes)
    {
        // payloadBuf starts with zero rows copied into it.  Every time we
        // add a route into payloadBuf, we increment payloadRowIndex.  When
        // payloadBuf is full, we send payloadBuf out, set payloadRowIndex
        // to 0, and repeat the process -- until the node's entire route
        // table has been sent.

        int payloadRowIndex;
        int payloadSize;

        payloadRowIndex = 0;

        while (rowIndex < bellmanford->numRoutes
               && payloadRowIndex
                  < MAX_ROUTES_PER_ROUTE_ADVERTISEMENT_PACKET)
        {
            if (type == ROUTING_BELLMANFORD_PERIODIC_UPDATE
                ||
                (type == ROUTING_BELLMANFORD_TRIGGERED_UPDATE
                 && bellmanford->routeTable[rowIndex].changed == TRUE))
            {
                payloadBuf[payloadRowIndex].destAddress =
                    bellmanford->routeTable[rowIndex].destAddress;

                payloadBuf[payloadRowIndex].subnetMask =
                    bellmanford->routeTable[rowIndex].subnetMask;

                payloadBuf[payloadRowIndex].nextHop =
                    bellmanford->routeTable[rowIndex].nextHop;

                payloadBuf[payloadRowIndex].distance =
                    bellmanford->routeTable[rowIndex].distance;

                if (type == ROUTING_BELLMANFORD_TRIGGERED_UPDATE)
                {
                    // Reset routeChanged flag if this is a triggered
                    // update.

                    bellmanford->routeTable[rowIndex].changed = FALSE;
                }

                payloadRowIndex++;
            }
            rowIndex++;
        }

        payloadSize = sizeof(AdvertisedRoute)
                      * payloadRowIndex;

        if (payloadSize > 0)
        {
            int i;

            for (i = 0; i < node->numberInterfaces; i++)
            {
                NodeAddress destAddress;
                RoutingBellmanfordHeader header;

                if (NetworkIpGetUnicastRoutingProtocolType(node, i)
                    != ROUTING_PROTOCOL_BELLMANFORD)
                {
                    continue;
                }

                if (NetworkIpIsWiredNetwork(node, i))
                {
                    destAddress =
                        NetworkIpGetInterfaceBroadcastAddress(node, i);
                }
                else
                {
                    destAddress = ANY_DEST;
                }

                header.sourceAddress = ip->interfaceInfo[i]->ipAddress;
                header.destAddress   = destAddress;
                header.payloadSize   = payloadSize;

                Message* msg = APP_UdpCreateMessage(
                    node,
                    ip->interfaceInfo[i]->ipAddress,
                    (short) APP_ROUTING_BELLMANFORD,
                    // Dynamic Address
                    // we need to brodacast the packet as new address might
                    // make some nodes in subnet out of brodcast address 
                    // range
                    ANY_DEST,
                    (short) APP_ROUTING_BELLMANFORD,
                    TRACE_BELLMANFORD,
                    IPTOS_PREC_INTERNETCONTROL);

                APP_UdpSetOutgoingInterface(msg, i); 

                APP_AddPayload(
                    node,
                    msg,
                    payloadBuf,
                    payloadSize);

                APP_AddHeader(
                    node,
                    msg,
                    &header,
                    sizeof(RoutingBellmanfordHeader));

                APP_UdpSend(
                    node, 
                    msg,
                    RANDOM_nrand(bellmanford->periodicJitterSeed) % 
                        PERIODIC_UPDATE_JITTER);

                if (type == ROUTING_BELLMANFORD_PERIODIC_UPDATE)
                {
                    bellmanford->numPeriodicUpdates++;
                }
                else if (type == ROUTING_BELLMANFORD_TRIGGERED_UPDATE)
                {
                    bellmanford->numTriggeredUpdates++;
                }

#ifdef DEBUG
                {
                    char cbuf[20];
                    char *typeString;
                    char address[MAX_STRING_LENGTH];

                    if (type == ROUTING_BELLMANFORD_PERIODIC_UPDATE)
                    {
                        typeString = "Periodic";
                    }
                    else
                    {
                        typeString = "Triggered";
                    }

                    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
                    IO_ConvertIpAddressToString(destAddress, address);
                    printf("Bellmanford: %s s, node %u, "
                           "SND %s update, Sent packet to UDP, dst %s\n",
                            cbuf, node->nodeId, typeString, address);
                }
#endif // DEBUG
            }//for//
        }//if//
    }//while//
}

//-----------------------------------------------------------------------------
// FUNCTION     ScheduleTriggeredUpdate
// PURPOSE      Schedules a triggered update.  Checks if an update event
//              isn't already scheduled.
//
// Parameters:
//
// Node *node
//     For current node.
//-----------------------------------------------------------------------------

static void //inline//
ScheduleTriggeredUpdate(Node *node)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    // Schedule a triggered update only if
    // a) A triggered update is not already scheduled for the node, or
    // b) Next periodic update is far enough away.

    if (bellmanford->triggeredUpdateScheduled == FALSE
        && bellmanford->nextPeriodicUpdateTime
           > node->getNodeTime() + TRIGGERED_UPDATE_DELAY + TRIGGERED_UPDATE_JITTER)
    {
        Message *newMsg;

        // Schedule triggered update. (node->getNodeTime() + 0-100 ms)

        newMsg = MESSAGE_Alloc(node,
                                APP_LAYER,
                                APP_ROUTING_BELLMANFORD,
                                MSG_APP_TriggeredUpdateAlarm);

        MESSAGE_Send(node, newMsg,
                      TRIGGERED_UPDATE_DELAY
                      + RANDOM_nrand(bellmanford->triggeredUpdateSeed) % TRIGGERED_UPDATE_JITTER);

        // Set flag indicating a triggered update has been scheduled.

        bellmanford->triggeredUpdateScheduled = TRUE;
    }
}

//-----------------------------------------------------------------------------
// Handler functions for messages from the transport layer
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     HandleFromTransport
// PURPOSE      Processes a packet from UDP.
//
// Parameters:
//
// Node *node
//     For current node.
// Message *msg
//     Contains the UDP packet contents.
//
// Notes:
//
// Only route advertisement packets are receieved from UDP; there are no
// other types of Bellman-Ford messages sent over the network.
//
// This function will call ProcessRouteAdvertisementPacket().
//-----------------------------------------------------------------------------

static void //inline//
HandleFromTransport(Node *node, Message *msg)
{
    // Received a route-advertisement packet from UDP.  When received,
    // route advertisements from triggered and periodic updates are
    // treated the same way.

    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    RoutingBellmanfordHeader *header;
    AdvertisedRoute *payload;
    int numAdvertisedRoutes;
    UdpToAppRecv *info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
    int incomingInterfaceIndex = info->incomingInterfaceIndex;

    // If bellmanford is not configured here, then discard message.
    if (!bellmanford)
    {
        return;
    }

    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_APPLICATION_LAYER, PACKET_IN, &acnData);

    // Increment stat for number of route-advertisement packets
    // received.

    bellmanford->numRouteAdvertisementsReceived++;

    // Obtain pointers to header, payload.

    header = (RoutingBellmanfordHeader *) msg->packet;
    payload = (AdvertisedRoute *)
              (msg->packet + sizeof(RoutingBellmanfordHeader));

    // Obtain number of rows in update.

    numAdvertisedRoutes = header->payloadSize / sizeof(AdvertisedRoute);

#ifdef DEBUG
    {
        char cbuf[20];
        char address[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);
        IO_ConvertIpAddressToString(header->sourceAddress,address);
        printf("Bellmanford: %s s, node %u, RCV Route broadcast, "
               "Received packet from UDP, src %s\n",
               cbuf, node->nodeId, address);
    }
#endif // DEBUG

    // Process the route-advertisement packet.

    ProcessRouteAdvertisementPacket(
        node,
        header->sourceAddress,
        incomingInterfaceIndex,
        numAdvertisedRoutes,
        payload);
}

//-----------------------------------------------------------------------------
// FUNCTION     ProcessRouteAdvertisementPacket
// PURPOSE      Processes a route broadcast packet from UDP.
//
// Parameters:
//
// Node *node
//     For current node.
// NodeAddress neighborAddress
//     IP address of broadcasting node.
// int numAdvertisedRoutes
//     Number of rows in broadcasted route table.
// AdvertisedRoute *neighborRowPtr
//     Pointer to broadcasted route table.
//
// Notes:
//
// Each row in the broadcasted route table is looked at, and the
// local route table is updated appropriately.  The IP forwarding
// table is also updated, and a triggered update may be scheduled.
//-----------------------------------------------------------------------------

static void //inline//
ProcessRouteAdvertisementPacket(
    Node *node,
    NodeAddress neighborAddress,
    int incomingInterfaceIndex,
    int numAdvertisedRoutes,
    AdvertisedRoute *neighborRowPtr)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    int i;
    int j;
    BOOL routeChanged;
    NodeAddress destAddress;
    NodeAddress subnetMask;
    BOOL newRoute;

    // Dynamic Address
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    BOOL wasFound;

    routeChanged = FALSE;

#ifdef DEBUG

    // Print update vector from route broadcast.

    PrintRouteAdvertisementPacket(
         node,
         neighborRowPtr,
         numAdvertisedRoutes);

#endif // DEBUG

    for (i = 0; i < numAdvertisedRoutes; i++)
    {
        Route *rowPtr;

        destAddress = neighborRowPtr[i].destAddress;
        subnetMask = neighborRowPtr[i].subnetMask;

        // Skip routes that are for a directly connected network
        // (for point-to-point interfaces), or to oneself
        // (all other interface types).

        wasFound = FALSE;
        for (j = 0; j < node->numberInterfaces; j++)
        {
            if (NetworkIpIsWiredNetwork(node, j))
            {
                if (NetworkIpGetInterfaceNetworkAddress(node, j)
                        == destAddress
                    && NetworkIpGetInterfaceSubnetMask(node, j)
                        == subnetMask)
                {
                    // Skip this route.  Node doesn't need to update
                    // for directly connected network.

                    wasFound = TRUE;
                    break;
                }
            }
            else
            {
                if (NetworkIpGetInterfaceAddress(node, j) == destAddress)
                {
                    // Skip this route.  Node doesn't need to update
                    // route to self.

                    wasFound = TRUE;
                    break;
                }
            }
        }
        if (wasFound)
        {
            continue;
        }

        wasFound = FALSE;
        for (j = 0; j < node->numberInterfaces; j++)
        {
            if (NetworkIpGetInterfaceAddress(node, j)
                == neighborRowPtr[i].nextHop)
            {
                // Split horizon with poisoned reverse.

                neighborRowPtr[i].distance = BELLMANFORD_INFINITY;
                wasFound = TRUE;
                break;
            }
        }

        if (!wasFound)
        {
            // Increment hop count (one hop from neighbor to this node).

            if (neighborRowPtr[i].distance < BELLMANFORD_INFINITY)
            {
                neighborRowPtr[i].distance++;
            }
        }

        // Get route that goes to the same destAddress.

        newRoute = FALSE;
        rowPtr = FindRoute(bellmanford, destAddress);
        if (rowPtr == NULL)
        {
            // Route to destAddress not present in route table.
            // This is a new route.

            newRoute = TRUE;
        }

        // Update/refresh route in route table if this is a new route,
        // an advertised route has a better metric, or if the sending
        // node is a route's next hop.

        if (newRoute
            || neighborRowPtr[i].distance < rowPtr->distance
            || neighborAddress == rowPtr->nextHop 
            // Dynamic address
            && ip->interfaceInfo[incomingInterfaceIndex]->addressState
            != INVALID)
        {
            if (newRoute
                || neighborRowPtr[i].distance != rowPtr->distance
                || rowPtr->incomingInterface != incomingInterfaceIndex)
            {
#ifdef DEBUG_TABLE
                if (routeChanged == FALSE)
                {
                    // We have a route change resulting from this route
                    // broadcast, and will be updating our route table.

                    // Print update vector from route broadcast.

                    PrintRouteAdvertisementPacket(
                        node,
                        neighborRowPtr,
                        numAdvertisedRoutes);

                    // Print pre-update route table.

                    PrintRouteTable(
                        node,
                        ROUTING_BELLMANFORD_PRE_UPDATE);
                }
#endif // DEBUG_TABLE

                if (newRoute)
                {
                    rowPtr = AddRoute(
                        bellmanford,
                        destAddress,
                        subnetMask,
                        neighborAddress,
                        incomingInterfaceIndex,
                        neighborRowPtr[i].distance);
                }

                // Set new distance.

                rowPtr->distance = (short) neighborRowPtr[i].distance;

                // Set new interface
                rowPtr->incomingInterface = incomingInterfaceIndex;
                rowPtr->outgoingInterface = incomingInterfaceIndex;

                // Distance metric has changed (either increased or
                // decreased).  Set routeChanged flag for this route
                // so that the route is later sent on a triggered
                // update.

                rowPtr->changed = TRUE;
                if (routeChanged == FALSE)
                {
                    routeChanged = TRUE;
                }
            }//if//

            // Set nextHop to the sender of the route broadcast, unless
            // the distance advertised is infinity, in which case the
            // nextHop is NETWORK_UNREACHABLE.

            if (neighborRowPtr[i].distance == BELLMANFORD_INFINITY)
            {
                rowPtr->nextHop = (unsigned) NETWORK_UNREACHABLE;
            }
            else
            {
                rowPtr->nextHop = neighborAddress;
            }

            // Route is refreshed.

            rowPtr->refreshTime = node->getNodeTime();

            // Update forwarding table.

            NetworkUpdateForwardingTable(
                node,
                destAddress,
                subnetMask,
                rowPtr->nextHop,
                rowPtr->outgoingInterface,
                rowPtr->distance,
                ROUTING_PROTOCOL_BELLMANFORD);
        }//if//
    }//for//

    // If a route has changed, call function which determines whether
    // to schedule a triggered update.

    if (routeChanged == TRUE)
    {
#ifdef DEBUG
#ifndef DEBUG_TABLE
        char cbuf[20];

        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

        printf("Bellmanford: %s s, node %u, --- Route table updated\n",
               cbuf, node->nodeId);
#endif // DEBUG_TABLE
#endif // DEBUG
#ifdef DEBUG_TABLE
        // If the table was updated, print post-update route table.

        PrintRouteTable(
            node,
            ROUTING_BELLMANFORD_POST_UPDATE);
#endif // DEBUG_TABLE
        ScheduleTriggeredUpdate(node);
    }
#ifdef DEBUG
    else
    {
        char cbuf[20];

        TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

        printf("Bellmanford: %s s, node %u, --- Route table not changed\n",
               cbuf, node->nodeId);
#ifdef DEBUG_TABLE
        // If the table was updated, print post-update route table.

        PrintRouteTable(
            node,
            ROUTING_BELLMANFORD_POST_UPDATE);
#endif // DEBUG_TABLE
    }
#endif // DEBUG
}

//-----------------------------------------------------------------------------
// Route table manipulation functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     InitRouteTable
// PURPOSE      Initializes a route table.
//
// Parameters:
//
// Bellmanford *bellmanford
//     Pointer to Bellman-Ford state information.
//
// Notes:
//
// This function was designed to be run only once.
// (no re-initializing the route table!)
//-----------------------------------------------------------------------------

static void //inline//
InitRouteTable(
    Bellmanford *bellmanford)
{
    // Allocate route table.

    bellmanford->routeTable =
        (Route *) MEM_malloc(NUM_INITIAL_ROUTES_ALLOCATED * sizeof(Route));

    bellmanford->numRoutesAllocated = NUM_INITIAL_ROUTES_ALLOCATED;
    bellmanford->numRoutes = 0;

    bellmanford->nextPeriodicUpdateTime = 0;
    bellmanford->triggeredUpdateScheduled = FALSE;
}

//-----------------------------------------------------------------------------
// FUNCTION     FindRoute
// PURPOSE      Finds a route for an IP address.
//
// Parameters:
//
// Bellmanford *bellmanford
//     Pointer to Bellman-Ford state information.
// NodeAddress destAddress
//     IP address to find route for.
//
// Returns:
//
// A pointer to the row that matches destAddress.  If a row was not found,
// NULL is returned.
//-----------------------------------------------------------------------------

static Route * //inline//
FindRoute(
    Bellmanford *bellmanford,
    NodeAddress destAddress)
{
    int top;
    int bottom;
    int middle;
    Route *rowPtr;

    // Set row = NULL if cannot find row.
    // Otherwise set row to the matching one.

    if (bellmanford->numRoutes == 0)
    {
        return NULL;
    }

    top = 0;
    bottom = bellmanford->numRoutes - 1;
    middle = (bottom + top) / 2;

    if (destAddress == bellmanford->routeTable[top].destAddress)
    {
        return &bellmanford->routeTable[top];
    }
    if (destAddress == bellmanford->routeTable[bottom].destAddress)
    {
        return &bellmanford->routeTable[bottom];
    }

    while (middle != top)
    {
        rowPtr = &bellmanford->routeTable[middle];
        if (destAddress == rowPtr->destAddress)
        {
            return rowPtr;
        }
        else
        if (destAddress < rowPtr->destAddress)
        {
            bottom = middle;
        }
        else
        {
            top = middle;
        }

        middle = (bottom + top) / 2;
    }

    return NULL;
}

//-----------------------------------------------------------------------------
// FUNCTION     AddRoute
// PURPOSE      Adds a route to the route table.
//
// Parameters:
//
// Bellmanford *bellmanford
//     Pointer to Bellman-Ford state information.
// NodeAddress destAddress
//     IP address to add route for.
// NodeAddress subnetMask
//     Subnet mask for the route.
// NodeAddress nextHop
//     IP address of the next hop for the route.
// int distance
//     Distance metric (number of hops) for the route.
//
// Returns:
//
// Pointer to newly-added route.
//
// Notes:
//
// Adding a duplicate route will cause an assertion failure.  Two routes
// with the same destAddress but different subnetMasks is included in
// this limitation. -- Always check if a route exists with the
// ...FindRoute() first, unless it's known that the route doesn't exist.
//-----------------------------------------------------------------------------

static Route * //inline//
AddRoute(
    Bellmanford *bellmanford,
    NodeAddress destAddress,
    NodeAddress subnetMask,
    NodeAddress nextHop,
    int incomingInterfaceIndex,
    int distance)
{
    int index;

    // There should only be one row per unique destination address.

    // Check if the table has been filled.

    if (bellmanford->numRoutes == bellmanford->numRoutesAllocated)
    {
        Route *oldTable;
        int i;

        // Table filled:  Double route table size.

        oldTable = bellmanford->routeTable;
        bellmanford->routeTable = (Route *)
            MEM_malloc(2 * bellmanford->numRoutesAllocated
                              * sizeof(Route));
        for (i = 0; i < bellmanford->numRoutes; i++)
        {
            bellmanford->routeTable[i] = oldTable[i];
        }
        MEM_free(oldTable);
        bellmanford->numRoutesAllocated *= 2;
    }

    // Insert route.

    index = bellmanford->numRoutes;
    bellmanford->numRoutes++;
    while (1)
    {
        if (index != 0
            && destAddress <= bellmanford->routeTable[index - 1].destAddress)
        {
            if (destAddress == bellmanford->routeTable[index - 1].destAddress)
            {
                // Duplicate entry.

                ERROR_ReportError("Cannot add duplicate route");
            }

            bellmanford->routeTable[index] = bellmanford->routeTable[index - 1];
            index--;
            continue;
        }

        bellmanford->routeTable[index].destAddress = destAddress;
        bellmanford->routeTable[index].subnetMask  = subnetMask;
        bellmanford->routeTable[index].nextHop     = nextHop;
        bellmanford->routeTable[index].incomingInterface =
            incomingInterfaceIndex;
        bellmanford->routeTable[index].outgoingInterface =
            incomingInterfaceIndex;

        bellmanford->routeTable[index].distance    = (short) distance;
        bellmanford->routeTable[index].localRoute  = FALSE;

        bellmanford->routeTable[index].refreshTime = 0;
        bellmanford->routeTable[index].changed     = FALSE;
        bellmanford->routeTable[index].isPermanent =  FALSE;

        return &bellmanford->routeTable[index];
    }
}

//-----------------------------------------------------------------------------
// Statistics
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     PrintStats
// PURPOSE      Prints statistics for Bellman-Ford.
//
// Parameters:
//
// Node *node
//     For current node.
//
// Notes:
//
// Called by RoutingBellmanFordFinalize(), only for interfaceIndex 0.
//
// Note that when an update is sent, it is sent on all interfaces;
// this event is counted as a single periodic update, even though a
// packet is sent out on each interface.  Received updates, on the other
// hand, are counted once per packet received.)
//-----------------------------------------------------------------------------

static void //inline//
PrintStats(Node *node)
{
    Bellmanford *bellmanford = (Bellmanford *)node->appData.bellmanford;

    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "Number of periodic updates sent = %d",
            bellmanford->numPeriodicUpdates);
    IO_PrintStat(node, "Application", "Bellman-Ford", ANY_DEST, -1, buf);

    sprintf(buf, "Number of triggered updates sent = %d",
            bellmanford->numTriggeredUpdates);
    IO_PrintStat(node, "Application", "Bellman-Ford", ANY_DEST, -1, buf);

    sprintf(buf, "Number of route timeouts = %d",
            bellmanford->numRouteTimeouts);
    IO_PrintStat(node, "Application", "Bellman-Ford", ANY_DEST, -1, buf);

    sprintf(buf, "Number of update packets received = %d",
            bellmanford->numRouteAdvertisementsReceived);
    IO_PrintStat(node, "Application", "Bellman-Ford", ANY_DEST, -1, buf);
}

//-----------------------------------------------------------------------------
// Debug output functions
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     PrintRouteAdvertisementPacket
// PURPOSE      Prints to screen the contents of a route advertisement
//              packet (an "update vector").
//
// Parameters:
//
// Node *node
//     For current node.
// AdvertisedRoute *neighborRowPtr
//     Pointer to update vector.
// int numAdvertisedRoutes
//     Number of rows in update vector.
//-----------------------------------------------------------------------------

static void //inline//
PrintRouteAdvertisementPacket(
    Node *node,
    AdvertisedRoute *neighborRowPtr,
    int numAdvertisedRoutes)
{
    char cbuf[MAX_CLOCK_STRING_LENGTH];
    int i;

    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

    printf("Bellmanford: %s s, node %u, --- Update vector, "
           "(dest nextHop dist)\n",cbuf, node->nodeId);

    for (i = 0; i < numAdvertisedRoutes; i++)
    {

        char address[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(neighborRowPtr[i].destAddress, address);
        printf("Bellmanford:\t%s", address);

        if (neighborRowPtr[i].nextHop == (unsigned) NETWORK_UNREACHABLE)
        {
            printf("\t-");
        }
        else
        {
            IO_ConvertIpAddressToString(neighborRowPtr[i].nextHop, address);
            printf("\t%s", address);
        }

        printf("\t%d\n", neighborRowPtr[i].distance);
    }
}

//-----------------------------------------------------------------------
// FUNCTION     PrintRouteTable
// PURPOSE      Prints to screen the local route table.
//
// Parameters:
//
// Node *node
//     For current node.
// PrintRouteTableType type
//     ROUTING_BELLMANFORD_PRE_UPDATE
//     or,
//     ROUTING_BELLMANFORD_POST_UPDATE
//
// Notes:
//
// Prints the local route table.  The "pre" and "post" options are used
// to print to the screen whether the contents of the route table were
// before or after processing an update vector.
//------------------------------------------------------------------------

static void //inline//
PrintRouteTable(
    Node *node, PrintRouteTableType type)
{
    Bellmanford *bellmanford = (Bellmanford *) node->appData.bellmanford;

    int i;
    char cbuf[MAX_CLOCK_STRING_LENGTH];

    TIME_PrintClockInSecond(node->getNodeTime(), cbuf);

    printf("Bellmanford: %s s, node %u, ",
           cbuf, node->nodeId);

    if (type == ROUTING_BELLMANFORD_PRE_UPDATE)
    {
        printf("--- Pre-update route table, (dest nextHop dist)\n");
    }
    else
    if (type == ROUTING_BELLMANFORD_POST_UPDATE)
    {
        printf("--- Post-update route table, (dest nextHop dist)\n");
    }
    else
    {
        printf("--- Post-update Route table, (dest nextHop dist)\n");
    }

    for (i = 0; i < bellmanford->numRoutes; i++)
    {
        char address[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(bellmanford->routeTable[i].destAddress, address);
        printf("Bellmanford:\t%s",address);

        if (bellmanford->routeTable[i].nextHop
            == (unsigned) NETWORK_UNREACHABLE)
        {
            printf("\t-");
        }
        else
        {
            IO_ConvertIpAddressToString(bellmanford->routeTable[i].nextHop, address);
            printf("\t%s", address);
        }

        printf("\t%d\n", bellmanford->routeTable[i].distance);
    }
}
//-----------------------------------------------------------------------------
// FUNCTION BellmanfordHookToRedistribute
// PURPOSE      Update or add the redistributed
//              routes into Bellmanford routing table.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  IP address of destination network or host.
//              NodeAddress destAddressMask
//                  Netmask.
//              NodeAddress nextHopAddress
//                  Next hop IP address.
//              int interfaceIndex
//                    The specify the routing protocol
//              void* routeCost
//                  Metric associate with the route
// RETURN: None
//----------------------------------------------------------------------------
void
BellmanfordHookToRedistribute(
    Node* node,
    NodeAddress destAddress,
    NodeAddress destAddressMask,
    NodeAddress nextHopAddress,
    int interfaceIndex,
    void* routeCost)
{

    Route* routePtr = NULL;
    int cost =  *(int*) routeCost;

    Bellmanford* bellmanford = (Bellmanford*)node->appData.bellmanford;

    routePtr = FindRoute(
                   bellmanford,
                   destAddress);
    if (routePtr != NULL)
    {
        return;
    }

    routePtr = AddRoute(
                    bellmanford,
                    destAddress,
                    destAddressMask,
                    nextHopAddress,
                    interfaceIndex,
                    (unsigned) cost);

     if (routePtr != NULL)
     {
      // We set this flag so that the route doesnt get time out
         routePtr->isPermanent = TRUE;
     }
}

// Dynamic address

//---------------------------------------------------------------------------
// FUNCTION   :: RoutingBellmanfordHandleChangeAddressEvent
// PURPOSE    :: Handles any change in the interface address for Bellmanford
// PARAMETERS ::
// + node               : Node* : Pointer to Node structure
// + interfaceIndex     : Int32 : interface index
// + oldAddress         : Address* : current address
// + subnetMask         : NodeAddress : subnetMask
// + networkType        : NetworkType : type of network protocol
// RETURN :: void : NULL
//---------------------------------------------------------------------------

void RoutingBellmanfordHandleChangeAddressEvent(
    Node* node,
    Int32 interfaceIndex,
    Address* oldAddress,
    NodeAddress subnetMask,
    NetworkType networkType)
{
    // Get the Bellmanford data structure
    Bellmanford* bellmanford =
           (Bellmanford*)node->appData.bellmanford;

    NetworkDataIp* ip = node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo =
                      ip->interfaceInfo[interfaceIndex];

    // If Bellmanford is not configured on this interface, because
    // adress change handler function is registered at node level
    if (interfaceInfo->routingProtocolType != ROUTING_PROTOCOL_BELLMANFORD)
    {
        return;
    }

    // Bellmanford is only supported for IPv4
    if (networkType == NETWORK_IPV6 )
    {
        return;
    }
    // currently interface address state is invalid, hence no need to update
    // tables as no communication can occur from this interface while the 
    // interface is in invalid address state
    if (interfaceInfo->addressState  == INVALID )
    {
        return;
    }

    if (networkType == NETWORK_IPV4 || networkType == NETWORK_DUAL)
    {
        NodeAddress destAddress;
        NodeAddress subnetMask;
        Route* rowPtr;

        if (NetworkIpIsWiredNetwork(node, interfaceIndex))
        {
            // This is a wiredlink interface.
            // The destAddress is the current network
            // address for the interface,
            // and subnetMask is the current subnet mask for the interface.

            destAddress = NetworkIpGetInterfaceNetworkAddress(
                                                            node,
                                                            interfaceIndex);
            subnetMask = NetworkIpGetInterfaceSubnetMask(node,
                                                         interfaceIndex);
        }
        else
        {
            // This is a wireless interface.
            // The destAddress is the IP address of the interface
            // itself, and subnetMask is 255.255.255.255 (ANY_DEST is
            // an all-one 32-bit value).
            // This means that the route applies exactly to the host IP
            // address of the interface. (not to a network address)

            destAddress = NetworkIpGetInterfaceAddress(node, interfaceIndex);
            subnetMask = ANY_DEST;
        }

        // Update forwarding table to inclue new interface address
        NetworkUpdateForwardingTable(
                            node,
                            destAddress,
                            subnetMask,
                            0,
                            interfaceIndex,
                            1,
                            ROUTING_PROTOCOL_DEFAULT);

        // Update the routing table of bellmanford such that the
        // new address is advertised in updates
        if (!FindRoute(bellmanford, destAddress))
        {
            rowPtr = AddRoute(bellmanford,
                              destAddress,
                              subnetMask,
                              NetworkIpGetInterfaceAddress(node, 
                                                           interfaceIndex),
                              interfaceIndex,
                              0);

            rowPtr->localRoute = TRUE;
            rowPtr->changed = TRUE;
        }
    }
}
