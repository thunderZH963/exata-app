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

// General multi-end wormhole attack model.


#ifndef _WORMHOLE_H_
#define _WORMHOLE_H_

enum MacWormholeReplayStatus
{
    NETIA_WORMHOLEREPLAY_STATUS_PASSIVE,
    NETIA_WORMHOLEREPLAY_STATUS_CARRIER_SENSE,
    NETIA_WORMHOLEREPLAY_STATUS_BACKOFF,
    NETIA_WORMHOLEREPLAY_STATUS_XMIT,
    NETIA_WORMHOLEREPLAY_STATUS_IN_XMITING,
    NETIA_WORMHOLEREPLAY_STATUS_YIELD
};

#define WORMHOLEREPLAY_TX_DATA_YIELD_TIME         (1 * MICRO_SECOND)

/* Used to experiment with WORMHOLEREPLAY timers only. */
#define WORMHOLEREPLAY_LOCAL_DATA_YIELD_TIME      (0)
#define WORMHOLEREPLAY_REMOTE_DATA_YIELD_TIME     (0)

#define WORMHOLEREPLAY_BO_MIN          (1 * MILLI_SECOND)
#define WORMHOLEREPLAY_BO_MAX          (1 * WORMHOLEREPLAY_BO_MIN)

#define WORMHOLEREPLAY_TIMER_SWITCH    0x1  /* bit 0000 0001 is used for ON/OFF*/
#define WORMHOLEREPLAY_TIMER_ON        0x1
#define WORMHOLEREPLAY_TIMER_OFF       0x0

#define WORMHOLEREPLAY_TIMER_TYPE      0xE  /* bit 0000 1110 is used for Timer type */
#define WORMHOLEREPLAY_TIMER_BACKOFF   0x0
#define WORMHOLEREPLAY_TIMER_YIELD     0x2
#define WORMHOLEREPLAY_TIMER_UNDEFINED 0xE


typedef struct wormholeReplay_timer
{
    Int32 seq;
    unsigned char flag;
} WormholeReplayTimer;

#define WORMHOLE_DEFAULT_THRESHOLD      150
#define WORMHOLE_DIRECT_THRESHOLD       20

// Different modes of wormhole nodes
// 1. TRANSPARENT:
//    Any 0-1 signal received at one end will be replayed by the other end.
//    The wormhole devices do not need network addresses.
//    The existence of wormhole link is transparent to the network.
// 2. PARTICIPANT:
//    The wormhole devices have network addresses.  They participate in routing.
// 3. DONT_ATTACK:
//    Don't do attack.  All packets get through.
typedef enum
{
    NETIA_WORMHOLE_THRESHOLD,
    NETIA_WORMHOLE_ALLPASS,
    NETIA_WORMHOLE_ALLDROP
} MacWormholeMode;


//
// Multi-end wormhole nodes share an 802.3-like bus.
// If the adversary wants a switch-like wormhole network,
// should create pairwise wormholes instead.
//
// Wormhole packet header is similar to the 802.3 header, but is 28 bytes
// (2 bytes longer than the 802.3 header and no padding for short packets)
// This is based on switched ethernet (for future upgrade).
//
typedef struct {
    char      framePreamble[8];
    NodeAddress sourceAddr;
    char      sourceAddrPadding[6 - sizeof(NodeAddress)];
    NodeAddress destAddr;
    char      destAddrPadding[6 - sizeof(NodeAddress)];
    char      length[2];
    char      checksum[4];
} MacWormholeFrameHeader;


// Different statistics being collected
typedef struct {
    int packetsReceived;
    int packetsReceivedWithoutRecursion;
    int packetsReplayed;
    int packetsDiscarded;       // discarded because of queue overflow
    int packetsDropped;         // dropped as data (e.g., > threshold)
} WormholeStats;

#define REPLAY_QUEUE_SIZE 1000

typedef struct {
    MacData *myMacData;

    //
    // For debugging (if the eavesdropped packet is not encrypted)
    // 
    MAC_PROTOCOL victimMacProtocol;

    //
    // The following fields are for wormhole tunneling
    //
    int wormholeNodeIndex;
    SubnetMemberData *nodeList;
    int numNodesInSubnet;

    WormholeStats stats;

    MacWormholeMode mode;
    Int64 bandwidth;
    clocktype propDelay;
    BOOL userSpecifiedPropDelay;

    // The threshold determines passing or dropping.
    // Packet length <= this: pass as control packet;
    // Packet length >  this: drop as data packet.
    int threshold;

    //
    // The following fieds are for wormhole replay
    //
    enum MacWormholeReplayStatus status;
    Int32 BOmin;            /* minimum backoff */
    Int32 BOmax;            /* maximum backoff */
    Int32 BOtimes;          /* how many times has it backoff ? */

    WormholeReplayTimer timer;

    RandomSeed seed;        /* for setting backoff timer */

    // Packets received by me, and tunneled to other wormhole terminals.
    // This field is useful for single-hop wormholes, where a tunneled packet
    // will be replayed by other terminals and received by me again.  If I
    // keep wormholing the packet, the recursive effect will cause exponentially
    // increasing communication events.  Thus a recursion-blocking buffer is
    // implemented: recently tunneled packets are recorded here.  If an
    // intercepted packet is found in the buffer, it is discarded rather than tunneled.
#define WORMHOLE_BUFFER_SIZE    100
    // In simulation, use "NodeAddress originatingNodeId"
    // and "int sequenceNumber" in the message structure to
    // distinguish each individual packet.
    // Only in emulation can we do packet content match.
#define WORMHOLE_INSPECT_BYTES  (sizeof(NodeAddress)+sizeof(int))
    char justTunneled[WORMHOLE_BUFFER_SIZE][WORMHOLE_INSPECT_BYTES];
    unsigned int firstInBuffer, lastInBuffer, numInBuffer;
} MacWormholeData;


// Name: MacWormholeInit
// Purpose: Initialize wormhole
// Parameter: node, node calling this function.
//            nodeInput, configuration file access.
//            interfaceIndex, interface to initialize.
//            interfaceAddress, interface's Address
//            subnetList, list of nodes in the subnet.
//            nodesInSubnet, number of nodes in the subnet.
//            macProtocolName, the eavesdropping/replaying MAC
// Return: None

void
MacWormholeInit(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    NodeAddress interfaceAddress,
    SubnetMemberData* subnetList,
    int nodesInSubnet,
    char *macProtocolName);

#ifdef PARTICIPANT
// Name: MacWormholeNetworkLayerHasPacketToSend
// Purpose: Ground node has packets to send.
// Parameter: node, ground node.
//            wormhole, wormhole data structure.
// Return: None.

void
MacWormholeNetworkLayerHasPacketToSend(
    Node *node,
    MacWormholeData *wormhole);
#endif

// Name: MacWormholeLayer
// Purpose: Handle frames and timers.
// Parameter: node, node that is handling the frame or timer.
//            interfaceIndex, interface associated with frame or timer.
//            msg, frame or timer.
// Return: None.

void
MacWormholeLayer(
    Node *node,
    int interfaceIndex,
    Message *msg);


// Name: MacWormholeFinalize
// Purpose: Handle any finalization tasks.
// Parameter: node, node calling this function.
//            interfaceIndex, interface associated with the finalization tasks.
// Return: None.

void
MacWormholeFinalize(
    Node *node,
    int interfaceIndex);

// Name: MacWormholeReceivePacketFromPhy
// Purpose: A wormhole terminal just picked up a packet from PHY layer
// Parameter: node, node calling this function.
//            wormhole, wormhole data structure.
//            msg, frame or timer.
// Return: None.

void MacWormholeReceivePacketFromPhy(Node* node,
                                     MacWormholeData* wormhole,
                                     Message* msg);

// Name: MacWormholeReplayReceivePhyStatusChangeNotification
// Purpose: A wormhole terminal just picked up a PHY layer status change
// Parameter: node, node calling this function.
//            wormhole, wormhole data structure.
//            oldPhyStatus, newPhyStatus, old and new statuses
// Return: None.

void MacWormholeReplayReceivePhyStatusChangeNotification(
    Node* node,
    MacWormholeData* wormhole,
    PhyStatusType oldPhyStatus,
    PhyStatusType newPhyStatus);

/*
 * FUNCTION    MacWormholeReplayHasPacketToSend
 * PURPOSE     To tell WORMHOLEREPLAY there is a packet to send.
 */

void MacWormholeReplayHasPacketToSend(
    Node *node, MacWormholeData *wormholeReplay);

void MacWormholeReplayReceivePacketFromPhy(
    Node *node, MacWormholeData *wormhole, Message *msg);

#endif /* _WORMHOLE_H_ */

