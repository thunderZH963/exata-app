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
#ifndef AUTO_IPNE_CAPTURE_INTERFACE
#define AUTO_IPNE_CAPTURE_INTERFACE

#define WINVER_VISTA_ABOVE 6
#define DEFAULT_IPV6_PREFIX_LENGTH 64

// /**
// CONSTANT    :: ETYPE_IPV6 : 0x86dd
// DESCRIPTION :: Ether type for Ipv6 packets
// **/
#define ETYPE_IPV6 0x86dd

void AutoIPNEInitializeCaptureInterface(AutoIPNEData *data);

void AutoIPNECaptureInterface(EXTERNAL_Interface *iface);


bool DetermineOperationHostMACAddress(
    AutoIPNEData *data,
    int address,
    char *macAddress,
    int *macAddressSize,
    int deviceIndex);


BOOL DetermineOperationHostMACAddressIpv6(
    AutoIPNEData* data,
    in6_addr v6SrcAddress,
    UInt64 scopeId,
    in6_addr v6DstAddress,
    Int8* macAddress,
    Int32 *macAddressSize,
    Int32 deviceIndex);

// deviceIndex = -1 implies recompile all devices
void AutoIPNERecompileCaptureFilter(
    AutoIPNEData *data,
    int deviceIndex);

// /**
// API       :: AutoIPNEHandleCommonPacket
// PURPOSE   :: This function will handle the common headers in the incoming
//              packet received in IPNetworkEmulatorReceive or after
//              decrypting the packet in case of IPsec transport and tunnel
//              mode.
// PARAMETERS::
// + nextHeader : UInt8* : The header next to ip header
// + data : AutoIPNEData* : Pointer to the AutoIPNEData. This will be NULL
// +        when invoked from IPsec models.
// + size : int : The size of the sniffed packet, would be set to NULL when
// +        invoked from IPsec models.
// + ipHdr : IpHeaderType* : pointer to IpHeaderType.
// + proto : ip header protocol
// + pkt : UInt8* : packet pointer
// + payloadSize : int : size o fthe payload
// RETURN    :: bool
// **/
bool AutoIPNEHandleCommonPacket(
    UInt8* nextHeader,
    AutoIPNEData* data,
    int size,
    IpHeaderType* ipHdr,
    unsigned int    proto,
    UInt8* pkt,
    int payloadSize);

// /**
// API       :: AutoIPNEHandleIPv6CommonPacket
// PURPOSE   :: This function will handle the common headers in the incoming
//              IPv6 packet received in IPNetworkEmulatorReceive
// PARAMETERS::
// + nextHeader : UInt8* : The header next to ip header
// + data : AutoIPNEData* : Pointer to the AutoIPNEData. This will be NULL
// +        when invoked from IPsec models.
// + size : int : The size of the sniffed packet, would be set to NULL when
// +        invoked from IPsec models.
// + ipHdr : IpHeaderType* : pointer to libnet_ipv6_hdr type
// + proto : unsigned int : ip header protocol
// + pkt : UInt8* : packet pointer
// + payloadSize : int : size o fthe payload
// RETURN    :: bool
// **/
bool AutoIPNEHandleIPv6CommonPacket(
    UInt8* nextHeader,
    AutoIPNEData* data,
    int size,
    libnet_ipv6_hdr* ipHdr,
    unsigned int    proto,
    UInt8* pkt,
    int payloadSize);
#endif 

