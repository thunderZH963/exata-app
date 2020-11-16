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
#ifndef AUTO_IPNE_PACKET_INTERFACE
#define AUTO_IPNE_PACKET_INTERFACE



BOOL InitializePacketInterface(AutoIPNEData *data);

void PacketInterfaceReceive(EXTERNAL_Interface *iface);


void DetermineOperationHostMACAddress(
    AutoIPNEData *data,
    int address,
    char *macAddress,
    int *macAddressSize,
    int deviceIndex);

// /**
// API       :: InjectLinkPacket for ARP request
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme. This function is 
//                overloading function of InjectLinkPacket
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime,
    int    deviceIndex);


// API       :: InjectLinkPacket
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime);


#endif 

