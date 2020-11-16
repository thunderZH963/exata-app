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


#ifndef GATEWAY_PACKET_H
#define GATEWAY_PACKET_H

typedef enum {
    PACKET_FORMAT_NETWORK,
    PACKET_FORMAT_HOST
} PacketFormatType;
    
BOOL Ipv6ReadPacketAddressAndPort(
    char* packet,
    in6_addr* srcAddress,
    unsigned short* srcPort,
    in6_addr* destAddress,
    unsigned short* destPort,
    PacketFormatType formatType);

BOOL ReadPacketAddressAndPort(
    char *packet,
    NodeAddress *srcAddress,
    unsigned short *srcPort,
    NodeAddress *destAddress,
    unsigned short *destPort,
    PacketFormatType formatType = PACKET_FORMAT_HOST);

BOOL FormatPacketHeaders(
    char *packet,
    PacketFormatType formatType,
    BOOL isIpv6Pkt = FALSE);

BOOL UpdatePacketAddressAndPort(
    char *packet,
    NodeAddress srcAddress,
    unsigned short srcPort,
    NodeAddress destAddress,
    unsigned short destPort,
    PacketFormatType formatType);

void UpdateIpv6PacketAddressAndPort(
    char *packet,
    in6_addr* srcAddress,
    unsigned short srcPort,
    in6_addr* destAddress,
    unsigned short destPort,
    PacketFormatType formatType);

#endif
