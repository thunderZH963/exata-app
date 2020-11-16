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

#ifndef _RIPNG_ROUTING_H_
#define _RIPNG_ROUTING_H_


typedef struct struct_ripng_str RIPngData;

//UserCodeStart

typedef enum {
    RIPNG_REQUEST = 1, // Request Message
    RIPNG_RESPONSE = 2 // Response message
} RIPngMessageType;


typedef enum {
    RIPNG_ALL_ROUTES = 1, // For Regular update
    RIPNG_CHANGED_ROUTES = 2 // For Triggered update
} RIPngResponseType;


typedef enum {
    RIPNG_TIMEOUT = 1, // route-timeout timer
    RIPNG_GARBAGE = 2 // route-garbage-collection timer
} RIPngRouteTimerType;


typedef enum {
    RIPng_SPLIT_HORIZON_OFF = 1,
    RIPng_SPLIT_HORIZON_SIMPLE = 2,
    RIPng_SPLIT_HORIZON_POISONED_REVERSE = 3
} RIPngSplitHorizonType;



typedef struct ripng_timer_msg_info {
    RIPngRouteTimerType type; // route-timeout or route-flush
    in6_addr destPrefix; // IPv6 address of route destination
} RIPngRouteTimerMsgInfo;


typedef struct ripng_route_table_entry {
    in6_addr prefix; // in6_addr is analogous to unsigned char[16], defined for IPv6 addr
    unsigned short routeTag; // The intended use of the route tag is to provide a method of separating "internal" RIPng routes (routes for networks within the RIPng routing domain) from "external" RIPng routes, which may have been imported from an EGP or another IGP
    unsigned char prefixLen;
    unsigned char metric;
} RIPngRte;


typedef struct ripng_packet {
    unsigned char command;
    unsigned char version;
    short mustBeZero;
    RIPngRte* rtes;
} RIPngResponse;


//  Routing Table structure
typedef struct ripng_routing_table {
    in6_addr destPrefix; // Destination prefix
    unsigned char prefixLen;
    in6_addr nextHopAddress; // Next hop address
    BOOL changed; // To indicate that information about the route has changed recently.
    unsigned char metric; // Number of hops to be crossed to reach the destination
    int outgoingInterfaceIndex; // index of outgoing interface
    int learnedInterfaceIndex; // index of interface on which route was learned
    clocktype timeoutTime;
    clocktype flushTime;
    BOOL flushed;
} RIPngRtTable;



//UserCodeEnd

typedef struct {
    unsigned numRegularUpdateEvents;
    int numRegularUpdateEventsId;
    unsigned numTriggeredUpdateEvents;
    int numTriggeredUpdateEventsId;
    unsigned numRouteTimeouts;
    int numRouteTimeoutsId;
    unsigned numResponsesReceived;
    int numResponsesReceivedId;
    unsigned numRegularPacketSent;
    int numRegularPacketSentId;
    unsigned numTriggeredPacketSent;
    int numTriggeredPacketSentId;
} RIPngStatsType;


enum {
    RIPNG_FINAL_STATE,
    RIPNG_HANDLE_REGULAR_UPDATE_ALARM,
    RIPNG_HANDLE_TRIGGERED_UPDATE_ALARM,
    RIPNG_HANDLE_ROUTE_TIMER_ALARM,
    RIPNG_IDLE,
    RIPNG_INITIAL_STATE,
    RIPNG_HANDLE_FROM_TRANSPORT,
    RIPNG_DEFAULT_STATE
};



struct struct_ripng_str
{
    int state;

    unsigned char* activeInterfaceIndexes; // Tracking of indices of interfaces which RIPng packets will be sent out on. (passive interface support)
    unsigned int numRoutes; // Number of actual routes
    unsigned int numRoutesAllocated; // Number of routes allowed before anymore memory needs to  be further allocated
    clocktype nextRegularUpdateTime; // Time of next regular update
    BOOL triggeredUpdateScheduled; // Flag to prevent more than one triggered update from being scheduled.
    RIPngSplitHorizonType splitHorizon; // Split-Horizon-Type
    RIPngRtTable* routeTable;
    int maxNumRte; // Max number of RTEs including next-hop RTEs
    RIPngStatsType stats;
    RandomSeed seed;
    int initStats;
    int printStats;
    BOOL statsPrinted;
};


void
RIPngInit(Node* node, const NodeInput* nodeInput, int interfaceIndex);


void
RIPngFinalize(Node* node, int interfaceIndex);


void
RIPngProcessEvent(Node* node, Message* msg);


void RIPngRunTimeStat(Node* node, RIPngData* dataPtr);

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
                              in6_addr* oldGlobalAddress);


#endif
