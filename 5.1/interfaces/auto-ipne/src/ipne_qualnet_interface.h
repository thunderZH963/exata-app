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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.
#ifndef IPNE_QUALNET_INTERFACE
#define IPNE_QUALNET_INTERFACE

enum {
    EXTERNAL_MESSAGE_IPNE_SetExternalInterface,
    EXTERNAL_MESSAGE_IPNE_ResetExternalInterface,
    EXTERNAL_MESSAGE_IPNE_EgressPacket,
    EXTERNAL_MESSAGE_IPNE_SetVirtualLanGateway
};

struct ForwardInfo
{
    NodeAddress nodeId;
    int interfaceIndex;
    NodeAddress previousHopAddress;
    NetworkType type;
};
// /**
// API       :: IPNE_ForwardFromNetworkLayer
// PURPOSE   :: Check if a packet should be forwarded to an operational host
//              and forward it if necessary.
//              Host byte order (QN definition)
// PARAMETERS::
// + node : Node* : The node processing the packet
// + interfaceIndex : int : Interface the packet was received on
// + msg : Message* : The packet
// RETURN    :: BOOL : TRUE if the packet was forwarded to an operational
//                     host, FALSE if not
// **/
/*BOOL AutoIPNE_ForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL eavesdrop);*/

// /**
// API       :: EmulateIpPacket
// PURPOSE   :: This is the default function used to inject a packet into
//              the QualNet simulation.  It will create a message from the
//              src to dst QualNet nodes.  It will call
//              EmulateIpPacketNatYes, EmulateIpPacketNatNo or
//              EmulateIpPacketTruEmulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + deviceIndex : int : Index of device that captured this packet
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: bool
// **/
bool AutoIPNEEmulateIpPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    int deviceIndex);

// /**
// API       :: AutoIPNEEmulateIpv6Packet
// PURPOSE   :: This is the default function used to inject a packet into
//              the QualNet simulation.  It will create a message from the
//              src to dst QualNet nodes.  It will call
//              EmulateIpPacketNatYes, EmulateIpPacketNatNo or
//              EmulateIpPacketTruEmulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : Int32 : The size of the packet
// + deviceIndex : Int32 : Index of device that captured this packet
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: bool
// **/
bool AutoIPNEEmulateIpv6Packet(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    Int32 packetSize,
    Int32 deviceIndex);


// /**
// API       :: ComputeTcpStyleChecksum
// PURPOSE   :: This function will compute a TCP checksum.  It may be used
//              for TCP type checksum, including UDP.  It assumes all
//              parameters are passed in network byte order.  The packet
//              pointer should point to the beginning of the tcp header,
//              with the packet data following.  The checksum field of the
//              TCP header should be 0.
// PARAMETERS::
// + srcAddress : UInt32 : The source IP address
// + dstAddress : UInt32 : The destination IP address
// + protocol : UInt8 : The protocol (in the IP header)
// + tcpLength : UInt16 : The length of the TCP header + packet data
// + packet : UInt8* : Pointer to the beginning of the packet
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeTcpStyleChecksum(
    UInt32 srcAddress,
    UInt32 dstAddress,
    UInt8 protocol,
    UInt16 tcpLength,
    UInt8* packet);

// /**
// API       :: AutoIPNEComputeTcpStyleChecksum
// PURPOSE   :: This function will compute a TCP checksum.  It may be used
//              for TCP type checksum, including UDP.  It assumes all
//              parameters are passed in network byte order.  The packet
//              pointer should point to the beginning of the tcp header,
//              with the packet data following.  The checksum field of the
//              TCP header should be 0. This overloaded function is for 
//              Ipv6.
// PARAMETERS::
// + srcAddress : UInt8* : Ponter to source IPv6 address
// + dstAddress : UInt8* : Ponter to destination IPv6 address
// + protocol : UInt8 : The protocol (in the IP header)
// + tcpLength : UInt32 : The length of the TCP header + packet data
// + packet : UInt8* : Pointer to the beginning of the packet
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeTcpStyleChecksum(
    UInt8* srcAddress,
    UInt8* dstAddress,
    UInt8 protocol,
    UInt32 tcpLength,
    UInt8* packet);


// /**
// API       :: ComputeIcmpStyleChecksum
// PURPOSE   :: Computes a checksum for the packet usable for ICMP
// PARAMETERS::
// + packet : UInt8* : Pointer to the beginning of the packet
// + length : UInt16 : Length of the packet in bytes (network byte order)
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeIcmpStyleChecksum(
    UInt8* packet,
    UInt16 length);

// /**
// API       :: AutoIPNEIncrementallyAdjustChecksum
// PURPOSE   :: This function will adjust an internet checksum if some part
//              of its packet data changes.  This can be used on the actual
//              packet data or on a virtual header.
// PARAMETERS::
// + sum : UInt16* : The checksum
// + oldData : UInt8* : The data that will be replaced
// + newData : UInt8* : The new data that will replace the old data
// + len : int : The length of the data that will be replaced
// + packetStart : UInt8* : The start of the packet.  NULL if it is part of
//                           the virtual header.  This parameter is
//                           necessary because the checksum covers 2 bytes
//                           of data and we need to know if the old data
//                           begins at an odd or even address relative to
//                           the start of the packet.
// RETURN    :: void
// **/
void AutoIPNEIncrementallyAdjustChecksum(
    UInt16* sum,
    UInt8* oldData,
    UInt8* newData,
    int len,
    UInt8* packetStart);


void AutoIPNEHandleExternalMessage(
    Node *node,
    Message *msg);

// /**
// API       :: ProcessOutgoingIPSecPacket
// PURPOSE   :: This functions processes an outgoing IPSec packet.
// PARAMETERS::
// + node " Node* : Pointer to the node structure
// + packet : UInt8* : Pointer to the beginning of the packet
// + msg : Message* : pointer to the msg structuredded.
// RETURN    :: void
// **/
void ProcessOutgoingIPSecPacket(
    Node* node,
    UInt8* packet,
    Message* msg);

struct AutoIPNE_NodeMapping;
AutoIPNE_NodeMapping* AutoIPNE_GetNodeMapping(EXTERNAL_Interface* ext, int deviceIndex, NodeAddress addr);

#define HITL_PORT 10000
#define OLSR_PORT 698
#endif
