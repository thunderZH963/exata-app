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

#ifndef LINK_H
#define LINK_H

#include "random.h"
//#include "mac_link_microwave.h"

#ifdef ADDON_DB
struct MacOneHopNeighborStats;
#endif

enum {
    LINK_IS_IDLE = 0,
    LINK_IS_BUSY = 1
};

typedef enum
{
    SATELLITE_NODE = 0,
    GROUND_STATION = 1
} nodeType;

//
// LinkFrameHeader
// It is similar to the 802.3 header, but is 28 bytes
// (2 bytes longer than the 802.3 header and no padding for short packets)
//

struct LinkFrameHeader {

    Mac802Address sourceAddr;
    Mac802Address destAddr;

    BOOL vlanTag;
    // MacHeaderVlanTag tag;  // This is an optional field.
                              // If station has vlanId, it sends
                              // frames with this tag field.
} ;

struct LinkStats {
    Int64 packetsSent;
    Int64 packetsReceived;
    Int64 bytesSent;
    Int64 bytesReceived;

    clocktype totalBusyTime;
};

struct LinkData {
    MacData* myMacData;

    MacLinkType phyType;
    int headerSizeInBits;
    double propSpeed;      // signal propagation speed for wireless link
    int status;
    Node* dest;
    NodeAddress destNodeId;
    Mac802Address destLinkAddress;
    int destInterfaceIndex;
    int partitionIndex;

    LinkStats stats;

    void* linkVar;
#ifdef ADDON_DB
    // For phy summary table
    std::map<int, MacOneHopNeighborStats>* macOneHopData;
#endif
#ifdef ADDON_BOEINGFCS
    Message *MessageSipBuffer; 
    Message *MessageSipTimer;
#endif
    BOOL isPointToPointLink;
};


struct WirelessLinkSiteParameters {
    double  AntennaDishDiameter;    //in meter
    double  AntennaHeight;          //in meter
    double  AntennaGain;            // in dB
    double  AntennaCableLoss;       // in dB
    int     polarization;           //itm
    double  Frequency;
    double  TxPower_dBm;
    double  propSpeed;              // in m/s
    nodeType nodetype;
    double noise_mW;
    double totalLossdB;
};


struct WirelessLinkInfo {
    clocktype propDelay;
    double distance;
    WirelessLinkSiteParameters sourcesiteparameters;
    Coordinates sourcecoordinates;
};


void LinkInit(
    Node*             node,
    const NodeInput*  nodeInput,
    Address*          address,
    int               interfaceIndex,
    int               remoteInterfaceIndex,
    const NodeId      nodeId1,
    Mac802Address linkAddress1,
    const NodeId      nodeId2,
    Mac802Address linkAddress2);


void LinkLayer(Node* node, int interfaceIndex, Message* msg);

void LinkFinalize(Node* node, int interfaceIndex);

void LinkSendFrame(Node*       node,
                   Message*    msg,
                   LinkData*   link,
                   int         interfaceIndex,
                   Mac802Address sourceAddress,
                   Mac802Address nextHopAddress,
                   BOOL        isFrameTagged,
                   TosType     priority,
                   Int64 effectiveBW);

void LinkSendTaggedFrame(Node*       node,
                         Message*    msg,
                         LinkData*   link,
                         int         interfaceIndex,
                         Mac802Address sourceAddress,
                         Mac802Address nextHopAddress,
                         VlanId      vlanId,
                         TosType     priority,
                         Int64 effectiveBW);

//--------------------------------------------------------------------------
// FUNCTION   :: MacLinkGetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Return packet properties
// PARAMETERS :: Node* node
//                   Node which received the message.
//               Message* msg
//                   The sent message
//               Int32 interfaceIndex
//                   The interface index on which packet was received
//               STAT_DestAddressType& type
//                   Sets the traffic type
//               BOOL& isMyFrame
//                   Set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void MacLinkGetPacketProperty(Node* node,
                              Message* msg,
                              Int32 interfaceIndex,
                              STAT_DestAddressType& type,
                              BOOL& isMyFrame,
                              BOOL& isAnyFrame);

#ifdef ADDON_DB
//--------------------------------------------------------------------------
// FUNCTION   :: MacLinkGetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Called by the API HandleMacDBEvents
// PARAMETERS :: Node* node
//                   Pointer to the node
//               Message* msg
//                   Pointer to the input message
//               Int32 interfaceIndex
//                   Interface index on which packet received
//               MacDBEventType eventType
//                   Receives the eventType
//               StatsDBMacEventParam& macParam
//                   Input StatDb event parameter
//               BOOL& isMyFrame
//                   set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void MacLinkGetPacketProperty(Node* node,
                              Message* msg,
                              Int32 interfaceIndex,
                              MacDBEventType eventType,
                              StatsDBMacEventParam& macParam,
                              BOOL& isMyFrame,
                              BOOL& isAnyFrame);
#endif

#endif /* LINK_H */

