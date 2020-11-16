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

#ifndef _TCP_INTERFACE_H_
#define _TCP_INTERFACE_H_

// /**
// API       :: TCPSwapBytes
// PURPOSE   :: Swap header bytes for a TCP packet
// PARAMETERS::
// + tcpHeader : UInt8* : Pointer to start of TCP header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: None
// **/
void TCPSwapBytes(
    UInt8* tcpHeader,
    BOOL in);

// /**
// API       :: PreProcessIpPacketTcp
// PURPOSE   :: This functions processes a TCP packet before adding
//              it to the simulation.  If NAT is enabled it will call
//              PreProcessIpPacketNatYes.  It will call any socket specific
//              functions.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + ip : struct libnet_ipv4_hdr* : Pointer to the IP header
// + sendPort : UInt16 : The sending port
// + destPort : UInt16 : The destination port
// + packet: UInt8* : Pointer to the beginning of the packet
// + size : int : The size of the packet in bytes
// + dataOffset : UInt8* : Pointer to the packet data (after UDP or TCP
//                          header)
// + checksum : UInt16* : Pointer to the checksum in the TCP or UDP header
// + func : QualnetPacketInjectFunction** : Function to use to inject the
//                                          packet.  May change depending on
//                                          socket function.
// RETURN    :: None
// **/
void PreProcessIpPacketTcp(
    EXTERNAL_Interface* iface,
    struct libnet_ipv4_hdr* ip,
    UInt16 sendPort,
    UInt16 destPort,
    UInt8* packet,
    int size,
    UInt8* dataOffset,
    UInt16* checksum,
    IPNE_EmulatePacketFunction** func);


// /**
// API       :: ProcessOutgoingIpPacketTcp
// PURPOSE   :: Process a TCP packet as it is leaving the simulation
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + udpHeader : UInt8* : Pointer to start of tcp header
// RETURN    :: None
// **/
void ProcessOutgoingIpPacketTcp(
    EXTERNAL_Interface* iface,
    //struct libnet_ipv4_hdr* ip,
IpHeaderType *ipHeader,
    UInt8* tcpHeader,
    UInt16* checksum);



#endif /* _TCP_INTERFACE_H_ */

