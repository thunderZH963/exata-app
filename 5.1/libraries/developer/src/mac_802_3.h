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

//
// PURPOSE: This model implements IEEE 802.3 which uses the CSMA/CD
// technique as the channel access technique.
//

#ifndef MAC_802_3_H
#define MAC_802_3_H

#include "list.h"
#include "partition.h"

// /**
// CONSTANT    :: MAC802_3_MINIMUM_FRAME_LENGTH : 64
// DESCRIPTION :: Minimum frame length for ethernet.
// **/
#define MAC802_3_MINIMUM_FRAME_LENGTH               64

// /**
// CONSTANT    :: MAC802_3_MINIMUM_FRAME_LENGTH_GB_ETHERNET : 512
// DESCRIPTION :: Minimum frame length for GB ethernet.
// **/
#define MAC802_3_MINIMUM_FRAME_LENGTH_GB_ETHERNET   512

// /**
// CONSTANT    :: MAC802_3_SIZE_OF_HEADER : 22
// DESCRIPTION :: Size of ethernet frame header.
// **/
#define MAC802_3_SIZE_OF_HEADER                     22

// /**
// CONSTANT    :: MAC802_3_SIZE_OF_TAILER : 4
// DESCRIPTION :: Size of ethernet frame tailer.
// **/
#define MAC802_3_SIZE_OF_TAILER                     4

// /**
// CONSTANT    :: MAC802_3_SIZE_OF_PREAMBLE_AND_SF_DELIMITER : 8
// DESCRIPTION :: Size of ethernet preamble and start frame delimiter.
// **/
#define MAC802_3_SIZE_OF_PREAMBLE_AND_SF_DELIMITER  8

// /**
// CONSTANT    :: MAC802_3_VLAN_TAG_TYPE : 0x8100
// DESCRIPTION :: Value of 802.1Q Tag Type.
// **/
#define MAC802_3_VLAN_TAG_TYPE                      0x8100

// /**
// CONSTANT    :: MAC802_3_LENGTH_OF_JAM_SEQUENCE : 4
// DESCRIPTION :: Length of Jam Sequence in bytes.
// **/
#define MAC802_3_LENGTH_OF_JAM_SEQUENCE             4

// /**
// CONSTANT    :: MAC802_3_MAX_BACKOFF : 16
// DESCRIPTION :: Maximum limit for back off count.
// **/
#define MAC802_3_MAX_BACKOFF                        16

// /**
// CONSTANT    :: MAC802_3_MIN_BACKOFF_WINDOW : 1
// DESCRIPTION :: Minimum backoff window size.
// **/
#define MAC802_3_MIN_BACKOFF_WINDOW                 1

// /**
// CONSTANT    :: MAC802_3_MAX_BACKOFF_WINDOW : 1023
// DESCRIPTION :: Maximum backoff window size.
// **/
#define MAC802_3_MAX_BACKOFF_WINDOW                 1023

// /**
// CONSTANT    :: MAC802_3_10BASE_ETHERNET : 10
// DESCRIPTION :: Alternate ID of 10 base ethernet.
// **/
#define MAC802_3_10BASE_ETHERNET                    10

// /**
// CONSTANT    :: MAC802_3_100BASE_ETHERNET : 100
// DESCRIPTION :: Alternate ID of 100 base ethernet.
// **/
#define MAC802_3_100BASE_ETHERNET                   100

// /**
// CONSTANT    :: MAC802_3_1000BASE_ETHERNET : 1000
// DESCRIPTION :: Alternate ID of 1000 base ethernet.
// **/
#define MAC802_3_1000BASE_ETHERNET                  1000

// /**
// CONSTANT    :: MAC802_3_10000BASE_ETHERNET : 10000
// DESCRIPTION :: Alternate ID of 10000 base ethernet.
// **/
#define MAC802_3_10000BASE_ETHERNET                 10000

// /**
// CONSTANT    :: MAC802_3_10BASE_ETHERNET_SLOT_TIME : 51200 * NANO_SECOND
// DESCRIPTION :: Slot time for 10 base ethernet.
// **/
#define MAC802_3_10BASE_ETHERNET_SLOT_TIME          (51200 * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_100BASE_ETHERNET_SLOT_TIME : 5120 * NANO_SECOND
// DESCRIPTION :: Slot time for 100 base ethernet.
// **/
#define MAC802_3_100BASE_ETHERNET_SLOT_TIME         (5120  * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_1000BASE_ETHERNET_SLOT_TIME : 4096 * NANO_SECOND
// DESCRIPTION :: Slot time for 1000 base ethernet.
// **/
#define MAC802_3_1000BASE_ETHERNET_SLOT_TIME        (4096  * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_10BASE_ETHERNET_INTERFRAME_DELAY
//                                     : 9600 * NANO_SECOND
// DESCRIPTION :: Interframe delay for 10 base ethernet.
// **/
#define MAC802_3_10BASE_ETHERNET_INTERFRAME_DELAY   (9600 * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_100BASE_ETHERNET_INTERFRAME_DELAY
//                                       : 960 * NANO_SECOND
// DESCRIPTION :: Interframe delay for 100 base ethernet.
// **/
#define MAC802_3_100BASE_ETHERNET_INTERFRAME_DELAY  (960  * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_1000BASE_ETHERNET_INTERFRAME_DELAY
//                                        :  96 * NANO_SECOND
// DESCRIPTION :: Interframe delay for 1000 base ethernet.
// **/
#define MAC802_3_1000BASE_ETHERNET_INTERFRAME_DELAY (96   * NANO_SECOND)

// /**
// CONSTANT    :: MAC802_3_TRACE_UNKNOWN_EVENT : -1
// DESCRIPTION :: Unknown event ID at 802.3 trace.
// **/
#define MAC802_3_TRACE_UNKNOWN_EVENT                -1

//--------------------------------------------------------------------------
//              Ethernet specific constants
//
// The industry has adopted the name Ethernet to refer to all forms of the
// shared CSMA/CD (carrier sense multiple access/collision detection)
// networking scheme. The actual name for most implementations today is IEEE
// 802.3, but the name Ethernet has become so pervasive that it is hard to
// find a vendor or publication that does not refer to IEEE 802.3 as
// Ethernet. Ethernet 802.3 is often used to clarify this point.
//--------------------------------------------------------------------------

// /**
// CONSTANT     :: MAC802_3_HARDWARE_ADDR_SIZE : 6
// DESCRIPTION  :: Ethernet MAC address length
// **/
#define MAC802_3_HARDWARE_ADDR_SIZE     MAC_ADDRESS_LENGTH_IN_BYTE


// /**
// CONSTANT    :: MAC802_3_PROTOCOL_TYPE_IP : 0x0800
// DESCRIPTION :: Length Field value for protocol IP
// **/
#define MAC802_3_PROTOCOL_TYPE_IP                   0x0800


// /**
// CONSTANT    :: MAC802_3_PROTOCOL_TYPE_RARP : 0x08035
// DESCRIPTION :: Length Field value for protocol RARP
// **/
#define MAC802_3_PROTOCOL_TYPE_RARP                 0x08035

//--------------------------------------------------------------------------


// /**
// ENUM        :: MAC802_3StationState
// DESCRIPTION :: Different status types of a station.
//                This status changes according to status of channel.
// **/
typedef enum
{
    IDLE_STATE,         // Channel idle and any station can transmit frame.
    TRANSMITTING_STATE, // Channel is busy. A station is transmitting frame.
    RECEIVING_STATE,    // Channel is busy. Station is receiving frame
    YIELD_STATE,        // Station allows channel to recover itself.
    BACKOFF_STATE       // Collision has occured. Station pulled out itself
                        // before retransmission.
} MAC802_3StationState;

// /**
// ENUM       :: MAC802_3FrameType
// DESCRIPTION :: Different types of frames to be transferred to the
//                destination node. This is utilized only for Full Duplex
// **/
typedef enum
{
    FULL_DUP,
    ARP,
    SWITCH
} MAC802_3FrameType;

// /**
// ENUM       :: MAC802_3TimerType
// DESCRIPTION :: Ethernet self timer types.
// **/
typedef enum
{
    // The self-timer is used to pass frame transmission delay
    // before actually transmit frame.
    mac_802_3_TimerSendPacket,

    // Timer is used to changed state for a station.
    mac_802_3_ChannelIdle
} MAC802_3TimerType;


//--------------------------------------------------------------------------
//                       Structure of the frame
//--------------------------------------------------------------------------

// /**
// STRUCT      :: MAC802_3Header
// DESCRIPTION :: Elements of 802.3 frame header.
// **/
typedef struct MAC802_3_header
{
    // Contains a bit pattern for synchronization.
    unsigned char  preamble[7];

    // 1 byte bit pattern to signal start of frame.
    unsigned char startFrameDelimiter;

    // sourceAddr & destAddr : 6 byte Ethernet address each.
    Mac802Address destAddr;
    Mac802Address sourceAddr;

    // Length of data / type field.
    unsigned short lengthOfData;

    // Frame header optionally carry VLAN tag information.
    // In this case, lengthOfData field indicates the presence of
    // four bytes VLAN tag. Original length of data followed after
    // this tagged field.

} MAC802_3Header;


// /**
// STRUCT      :: MAC802_3Frame
// DESCRIPTION :: Elements of 802.3 frame.
// **/
typedef struct MAC802_3_frame
{
    // Header part of frame
    MAC802_3Header header;

    // Data field.
    // This field will be allocated dynamically. If data size falls
    // to satisfy minimum frame size it will be padded properly.

    // Tailer part,
    // This will also be added dynamically.
    // But in Qualnet this field will be unused.

    // NOTE : In Qualnet, tailer and pad field is added before the
    // data field. This helps to trace packet.
    // Actually all the fields are added dynamically. This structure
    // gives a mental picture of ethernet frame used.

} MAC802_3Frame;

//--------------------------------------------------------------------------

// /**
// STRUCT      :: MAC802_3SelfTimer
// DESCRIPTION :: Elements of a self timer.
// **/
typedef struct self_timer_information
{
    int seqNum;
    MAC802_3TimerType timerType;
} MAC802_3SelfTimer;

// /**
// STRUCT      :: MAC802_3Statistics
// DESCRIPTION :: Structure to keep statistics.
// **/
typedef struct struct_mac_802_3_stat
{
    Int32 numBackoffFaced;          // No of times backoff faced
    Int64 numFrameLossForCollision; // No of frame discarded due to collision
} MAC802_3Statistics;


// /**
// STRUCT      :: MAC802_3FullDuplexStatistics
// DESCRIPTION :: Structure to keep statistics for full duplex.
// **/
typedef struct struct_mac_802_3_full_duplex_stat
{
    Int64 numFrameDropped;          // No of frame discarded due to collision
    Int64 numBytesDropped;
    clocktype totalBusyTime;        // Time the channel is busy
} MAC802_3FullDuplexStatistics;


//--------------------------------------------------------------------------
//                       Layer structure
//--------------------------------------------------------------------------

// /**
// STRUCT      :: MacData802_3
// DESCRIPTION :: Layer structure of ethernet.
// **/
typedef struct struct_mac_802_3_str
{
    MacData* myMacData;
    
    /*Commented while differentiating between MacAddress and Ip Address*/
    //NodeAddress ownMacAddr;
    /*Comments End*/

    // Channel Bandwidth
    int bwInMbps;

    // Slot time, Interframe spacing and Jam transmission duration.
    clocktype slotTime;
    clocktype interframeGap;
    clocktype jamTrDelay;

    // Self buffer kept by 802.3
    Message* msgBuffer;

    // Station status, changes according to status of channel
    MAC802_3StationState stationState;

    // Different Collision related parameter.
    // Collision counter counts total collision faced by a frame.
    int backoffWindow;
    int collisionCounter;

    // This will be set if station goes to backoff. It is considered, a
    // station can receive a frame, changing it's state from BACKOFF to
    // RECEIVING,if it is in Backoff. This flag is used to change state
    // from RECEIVING to BACKOFF again.
    BOOL wasInBackoff;
    int seqNum;

    // Statistics collection
    MAC802_3Statistics stats;

    // Neighbors list, connected to this subnet, describes all neighbor
    // present in this subnet. Element of the list is SubnetMemberData
    LinkedList* neighborList;

    // Is it working in the full duplex mode, TRUE if it is
    BOOL isFullDuplex;

    // Statistics collection, if mode is fullduplex.
    MAC802_3FullDuplexStatistics* fullDupStats;

    BOOL trace;

    // record the time when the inter-frame gap delay starts
    clocktype interFrameGapStartTime;

    // seed for generating random backoff
    RandomSeed seed;

    // for point-to-point link to support parallel
    LinkData* link;

} MacData802_3;

//--------------------------------------------------------------------------

// /**
// FUNCTION   :: Mac802_3GetSubnetParameters
// LAYER      :: Mac
// PURPOSE    :: Get bandwidth and propagation delay for a given subnet.
// PARAMETERS ::
// + nodeInput       : const NodeInput*  : Pointer to node input.
// + address      : Address*    : Pointer to IpAddress Information.
// + subnetBandwidth : int*              : Get bandwidth for this subnet.
// + subnetPropDelay : clocktype*        : Get prop. delay for this subnet.
// + forLink : BOOL : Whether for Link (Full Duplex Point to Point Link) or
//                     Subnet.
// RETURN  :: None.
// **/
void Mac802_3GetSubnetParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    Address* address,
    Int64* subnetBandwidth,
    clocktype* subnetPropDelay,
    BOOL forLink);


// /**
// FUNCTION   :: Mac802_3Init
// LAYER      :: Mac
// PURPOSE    :: Initialize 802.3 protocol at a given interface.
// PARAMETERS ::
// + node             : Node*             : Pointer to node.
// + nodeInput        : const NodeInput*  : Pointer to node input.
// + interfaceIndex   : int               : Interface index
// + nodeList         : SubnetMemberData* : Pointer to subnet member list
// + numNodesInSubnet : int               : Member count in subnet.
// + forLink          : BOOL              : Whether for link or Subnet.
// RETURN  :: None.
// **/
void Mac802_3Init(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    SubnetMemberData* nodeList,
    int numNodesInSubnet,
    BOOL forLink);

// /**
// FUNCTION   :: Mac802_3Finalize
// LAYER      :: Mac
// PURPOSE    :: Finalize routine for 802.3 protocol.
// PARAMETERS ::
// + node             : Node*   : Pointer to node.
// + interfaceIndex   : int     : Interface index
// RETURN  :: None.
// **/
void Mac802_3Finalize(
    Node* node,
    int interfaceIndex);

// /**
// FUNCTION   :: Mac802_3Layer
// LAYER      :: Mac
// PURPOSE    :: Layer routine for 802.3 protocol.
// PARAMETERS ::
// + node             : Node*    : Pointer to node.
// + interfaceIndex   : int      : Interface index
// + msg              : Message* : Pointer to message.
// RETURN  :: None.
// **/
void Mac802_3Layer(
    Node* node,
    int interfaceIndex,
    Message* msg);

// /**
// FUNCTION   :: Mac802_3SenseChannel
// LAYER      :: Mac
// PURPOSE    :: This function is called by a station tosense channel.
// PARAMETERS ::
// + node       : Node*         : Pointer to node.
// + mac802_3   : MacData802_3* : Pointer to 802.3 data at an interface.
// RETURN  :: None.
// **/
void Mac802_3SenseChannel(
    Node* node,
    MacData802_3* mac802_3);

// /**
// FUNCTION   :: Mac802_3ConvertFrameIntoPacket
// LAYER      :: Mac
// PURPOSE    :: This function is called to convert a frame to packet.
// PARAMETERS ::
// + node        : Node*             : Pointer to node.
// + interfaceIndex : int            : Interface index
// + msg         : Message*          : Pointer to message.
// + tagInfo     : MacHeaderVlanTag* : Get VLAN info if present in  header.
// RETURN  :: void.
// **/
void Mac802_3ConvertFrameIntoPacket(
    Node* node,
    int interfaceIndex,
    Message* msg,
    MacHeaderVlanTag* tagInfo);


// FUNCTION:  Mac802_3CreateFrame
// PURPOSE:   Creates frame from the retrieved packet from queue into
//            a temporary place.
// PARAMETERS:   Node* node
//                  Pointer to node
//              Message* msg
//                  Pointer to message
//              MacData802_3* mac802_3
//                  Pointer to 802.3 structure
//              MacAddress nextHopAddress
//                  Mac Address of destination station
//              MacAddress sourceAddr
//                  Mac Address of source station
//              TosType priority
//                  Priority of frame
// RETURN TYPE: NONE
//
void Mac802_3CreateFrame(
    Node* node,
    Message* msg,
    MacData802_3* mac802_3,
    unsigned short lengthOfData,
    Mac802Address* nextHopAddress,
    Mac802Address* sourceAddr,
    TosType priority);



// FUNCTION:  Mac802_3GetLengthOfPacket
// PURPOSE:   return length of the frame
// PARAMETERS: Message* msg
//                Pointer to message
// RETURN TYPE: unsigned short
//
unsigned short Mac802_3GetLengthOfPacket(Message *msg);

//
//  FUNCTION:  Mac802_3GetSrcAndDestAddrFromFrame
//  PURPOSE:   Gives source and destination IP address of a frame.
//  PARAMETERS:  Node* node
//                  Pointer to node
//               MacData802_3* mac802_3
//                  Pointer to MacData802_3
//               Message* msg
//                  Pointer to message
//                MacHWAddress* srcHWAddr
//                  Pointer to collect source of frame
//               MacHWAddress* destHWAddr
//                  Pointer to collect destination of frame

//  RETURN TYPE: None
//
void Mac802_3GetSrcAndDestAddrFromFrame(
    Node* node,
    MacData802_3* mac802_3,
    Message* msg,
    MacHWAddress* srcHWAddr,
    MacHWAddress* destHWAddr);

// /**
// FUNCTION  ::  Mac802_3FullDupSend
// PURPOSE   ::  Sending frame to the other node in full duplex mode
// PARAMETERS::
//     +node : Node* :  Pointer to node
//     +interfaceIndex : int : Particular interface of the node.
//     +mac802_3 : MacData802_3* : Pointer to 802.3 structure.
//     +msg : Message* : Pointer to message.
//     +priority : TosType : Priority of frame.
//     +effectiveBW : Int64 : Effective bandwidth available
//     +frmType : MAC802_3FrameType : Type of the frame i.e Switch, ARP or Application packet
// RETURN TYPE:: void
// **/
void Mac802_3FullDupSend(Node* node,
                        int interfaceIndex,
                        MacData802_3* mac802_3,
                        Message* msg,
                        TosType priority,
                        Int64 effectiveBW,
                        MAC802_3FrameType frmType);

//--------------------------------------------------------------------------
// FUNCTION   :: Mac802_3GetPacketProperty
// LAYER      :: MAC
// PURPOSE    :: Return packet properties
// PARAMETERS :: Node* node
//                   Node which received the message.
//               Message* msg
//                   The sent message
//               Int32 interfaceIndex
//                   The interface index on which packet received
//               Int32& destNodeId
//                   Sets the destination nodeId
//               Int32& controlSize
//                   Sets the controlSize
//               BOOL& isMyFrame
//                   Set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void Mac802_3GetPacketProperty(
    Node* node,
    Message* msg, 
    Int32 interfaceIndex,
    Int32& destNodeId,
    Int32& controlSize,
    BOOL& isMyFrame,
    BOOL& isAnyFrame);

//--------------------------------------------------------------------------
// NAME         Mac802_3UpdateStatsSend
// PURPOSE      Update sending statistics
// PARAMETERS   Node* node
//                  Node which received the message.
//              Message* msg
//                  The sent message
//              Int32 interfaceIndex
//                  The interface index on which packet received
// RETURN       None
// NOTES        None
//--------------------------------------------------------------------------
void Mac802_3UpdateStatsSend(
    Node* node,
    Message* msg,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME         Mac802_3UpdateStatsReceive
// PURPOSE      Update receiving statistics
// PARAMETERS   Node* node
//                  Node which received the message.
//              Message* msg
//                  The sent message
//              Int32 interfaceIndex
//                  The interface index on which packet received
// RETURN       None
// NOTES        None
//--------------------------------------------------------------------------
void Mac802_3UpdateStatsReceive(
    Node* node,
    Message* msg,
    Int32 interfaceIndex);

#ifdef ADDON_DB
//--------------------------------------------------------------------------
// FUNCTION   :: Mac802_3GetPacketProperty
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
//                   Set TRUE if msg is unicast
//               BOOL& isAnyFrame
//                   Set TRUE if msg is broadcast
// RETURN     :: none
//--------------------------------------------------------------------------
void Mac802_3GetPacketProperty(Node* node,
                               Message* msg,
                               Int32 interfaceIndex,
                               MacDBEventType eventType,
                               StatsDBMacEventParam& macParam,
                               BOOL& isMyFrame,
                               BOOL& isAnyFrame);
#endif

#endif // MAC_802_3_H
