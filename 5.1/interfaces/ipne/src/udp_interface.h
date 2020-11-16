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

#ifndef _UDP_INTERFACE_H_
#define _UDP_INTERFACE_H_

#include "transport_udp.h"
#include "network_ip.h"

// /**
// API       :: UDPSwapBytes
// PURPOSE   :: Swap header bytes for a UDP packet
// PARAMETERS::
// + udpHeader : UInt8* : Pointer to start of UDP header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: None
// **/
void UDPSwapBytes(
    UInt8* udpHeader,
    BOOL in);

// /**
// API       :: PreProcessIpPacketUdp
// PURPOSE   :: Process a UDP packet as it is entering the simulation
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + packet : UInt8* : Pointer to start of packet
// + size : Int32 : Size of the packet in bytes
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// + func : IPNE_EmulatePacketFunction** : Function to use for packet
//          injection.  May be changed depending on port.
// RETURN    :: None
// **/
void PreProcessIpPacketUdp(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    Int32 size,
    IPNE_EmulatePacketFunction** func);

// /**
// API       :: ProcessOutgoingIpPacketUdp
// PURPOSE   :: Process a UDP packet as it is leaving the simulation
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + udpHeader : UInt8* : Pointer to start of udp header
// RETURN    :: None
// **/
void ProcessOutgoingIpPacketUdp(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8* udpHeader,
    //struct libnet_ipv4_hdr* ip,
    IpHeaderType  *ipHeader,
    BOOL * inject);
#endif /* _UDP_INTERFACE_H_ */
