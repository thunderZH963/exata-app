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

#ifndef _RIP_ROUTING_H_
#define _RIP_ROUTING_H_


typedef struct struct_rip_str RipData;

//UserCodeStart

typedef enum {
    RIP_ALL_ROUTES, // regular update
    RIP_CHANGED_ROUTES, // triggered update
    RIP_REQUESTED_ROUTES, // response to request packet
    RIP_REQUESTED_COMPATIBLE_ROUTES // response to RIP1 request packet with compatibility
} RipResponseType;


typedef enum {
    RIP_TIMEOUT, // route-timeout timer
    RIP_FLUSH // route-flush timer
} RipRouteTimerType;


typedef enum {
    RIP_VERSION_1 = 1, // Rip version 1
    RIP_VERSION_2 = 2 // Rip version 2
} RipVersion;


typedef enum {
    RIP_REQUEST = 1, // Request Message
    RIP_RESPONSE = 2 // Responce message
} RipMessageType;


typedef enum {
    RIP_SPLIT_HORIZON_OFF = 1,
    RIP_SPLIT_HORIZON_SIMPLE = 2,
    RIP_SPLIT_HORIZON_POISONED_REVERSE = 3
} RipSplitHorizonType;


typedef enum {
    RIPv2_ONLY = 0,
    RIPv1_ONLY,
    RIPv1_COMPATIBLE,
    NO_RIP
} RipCompatibilityType;

typedef struct {

    unsigned short routeTag; // route tag ( AS identifier )0 for rip routes, 1 for external routes
    NodeAddress destAddress; // IP address of route destination
    NodeAddress subnetMask; // subnet mask
    NodeAddress nextHop; // IP address of route next hop
    unsigned metric; // distance
    int outgoingInterfaceIndex; // index of outgoing interface
    int learnedInterfaceIndex; // index of interface on which route was learned
    clocktype timeoutTime; // alarm time of route-time out timer
    clocktype flushTime; // alarm time of route-flush timer
    BOOL changed; // flag indicating whether route has changed since last Response message was sent
    BOOL flushed; // flag indicating whether route is in the "flushed" state
} RipRoute;


typedef struct {
    unsigned short afi; // address family identifier(network-layerprotocol--IP)
    unsigned short routeTag; // route tag ( AS identifier )
    NodeAddress ipAddress; // IP addressof route destination
    NodeAddress subnetMask; // subnet mask
    NodeAddress nextHop; // IP address of route next hop
    unsigned metric; // distance
} RipRte;


typedef struct {
    RipRouteTimerType type; // route-timeoutor route-flush
    NodeAddress destAddress; // IP address of route destination
} RipRouteTimerMsgInfo;


typedef struct {
    unsigned char command;
    unsigned char version;
    short mustBeZero;
    RipRte rtes[25];
} RipPacket;



//UserCodeEnd

typedef struct {
    unsigned numRegularUpdateEvents;
    int numRegularUpdateEventsId;
    unsigned numTriggeredUpdateEvents;
    int numTriggeredUpdateEventsId;
    unsigned numRouteTimeouts;
    int numRouteTimeoutsId;
    unsigned numRequestsSent;
    int numRequestsSentId;
    unsigned numRequestsReceived;
    int numRequestsReceivedId;
    unsigned numInvalidRipPacketsReceived;
    int numInvalidRipPacketsReceivedId;
    unsigned numResponsesReceived;
    int numResponsesReceivedId;
    unsigned numRegularPackets;
    int numRegularPacketsId;
    unsigned numTriggeredPackets;
    int numTriggeredPacketsId;
    unsigned numResponseToRequestsSent;
    int numResponseToRequestsSentId;
} RipStatsType;


enum {
    RIP_FINAL_STATE,
    RIP_IDLE,
    RIP_HANDLE_REGULAR_UPDATE_ALARM,
    RIP_HANDLE_TRIGGERED_UPDATE_ALARM,
    RIP_HANDLE_FROM_TRANSPORT,
    RIP_HANDLE_ROUTE_TIMER_ALARM,
    RIP_HANDLE_REQUEST_ALARM,
    RIP_INITIAL_STATE,
    RIP_DEFAULT_STATE
};



struct struct_rip_str
{
    int state;

    unsigned char* activeInterfaceIndexes; // Tracking of indices of interfaces which RIP packets will be sent out on. (passive interface support)
    RipRoute* routeTable; // pointer to array of routing entry
    BOOL* routeSummary;
    RipCompatibilityType* ripCompatibility; 
    unsigned int numRoutes; // number of actual routes
    unsigned int numRoutesAllocated; // number of routes allowed before more memory needs to be allocated
    clocktype nextRegularUpdateTime; // Time of next regular update, used by the triggered update process
    BOOL triggeredUpdateScheduled; // Flag to prevent more than one triggered update from being scheduled.
    BOOL printedStats; // Used so that statistics are printed only once or the node
    unsigned int version; // RIP version
    RipSplitHorizonType splitHorizon; // Split-Horizon would be applied or not
    BOOL borderRouter; // Whether border router or not
    RipStatsType stats;
    RandomSeed triggerSeed; // Used for trigger interval
    RandomSeed updateSeed; // Used for update interval
    int initStats;
    int printStats;
    BOOL statsPrinted;
};

#define RIP_MULTICAST_ADDRESS    0xE0000009
#define RIP_AUTHENTICATION_IDENTIFIER    0xffff

void
RipInit(Node* node, const NodeInput* nodeInput, int interfaceIndex);


void
RipFinalize(Node* node, int interfaceIndex);


void
RipProcessEvent(Node* node, Message* msg);


void RipRunTimeStat(Node* node, RipData* dataPtr);

void
RipResponseSwapBytes(RipRte* rte);



//Interface Utility Functions


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
                           void* routeCost);


// FUNCTION enterRipHandleRequestAlarm
// PURPOSE  Handles the timer event for sending request packet
// Parameters:
//  node:    Pointer to node
//  RipData: Pointer to RIP data structure
//  msg:     Pointer to timer message
static void enterRipHandleRequestAlarm(Node* node,
                                       RipData* dataPtr,
                                       Message* msg);


// FUNCTION RipSendRequest
// PURPOSE  Sends a RIP Request message out the specified interface.
// Parameters:
//  node:   Pointer to node
//  interfaceIndex: Index of interface
//  type:   ALL_ROUTES(inital request) or CHANGED_ROUTES(dignostic requests)
static void RipSendRequest(Node* node,
                            int interfaceIndex,
                            RipResponseType type);


// FUNCTION RipProcessRequest
// PURPOSE  Processes received RIP Request message.
// Parameters:
//  node:   Pointer to node
//  msg:    Pointer to message with RIP Request message.
static void RipProcessRequest(Node* node,Message* msg);

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
    NetworkType networkType);
#endif
