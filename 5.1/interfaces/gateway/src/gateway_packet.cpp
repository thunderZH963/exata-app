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

#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif


#include "api.h"
#include "network_ip.h"
#include "gateway_packet.h"
#include "tcpiphdr.h"
#include "ipv6.h"
#include "ipne_qualnet_interface.h"


//---------------------------------------------------------------------------
// Helper routines
//    TODO: Move all of these to a library, to be shared between ipne, pas, this
//---------------------------------------------------------------------------

// /**
// API       :: ComputeIcmpStyleChecksum
// PURPOSE   :: Computes a checksum for the packet usable for ICMP
// PARAMETERS::
// + packet : UInt8* : Pointer to the beginning of the packet
// + length : UInt16 : Length of the packet in bytes (network byte order)
// RETURN    :: void
// **/
static UInt16 LIB_ComputeIcmpStyleChecksum(
    UInt8* packet,
    UInt16 length)
{
    bool odd;
    UInt16* paddedPacket;
    int sum;
    int i;
    int packetLength;

    packetLength = ntohs(length);
    odd = packetLength & 0x1;

    // If the packet is an odd length, pad it with a zero
    if (odd)
    {
        packetLength++;
        paddedPacket = (UInt16*) MEM_malloc(packetLength);
        paddedPacket[packetLength/2 - 1] = 0;
        memcpy(paddedPacket, packet, packetLength - 1);
    }
    else
    {
        paddedPacket = (UInt16*) packet;
    }

    // Compute the checksum
    // Assumes parameters are in network byte order

    sum = 0;
    for (i = 0; i < packetLength / 2; i++)
    {
        sum += paddedPacket[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    if (odd)
    {
        MEM_free(paddedPacket);
    }

    // Return the checksum
    return ~((UInt16) sum);
}

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
static UInt16 LIB_ComputeTcpStyleChecksum(
    UInt32 srcAddress,
    UInt32 dstAddress,
    UInt8 protocol,
    UInt16 tcpLength,
    UInt8* packet)
{
    UInt8 virtualHeader[12];
    UInt16* virtualHeaders = (UInt16*) virtualHeader;
    int sum;
    int i;

    // Compute the checksum
    // Assumes parameters are in network byte order
    memcpy(&virtualHeader[0], &srcAddress, sizeof(UInt32));
    memcpy(&virtualHeader[4], &dstAddress, sizeof(UInt32));
    virtualHeader[8] = 0;
    virtualHeader[9] = protocol;
    memcpy(&virtualHeader[10], &tcpLength, sizeof(UInt16));

    // The first part of the checksum is an ICMP style checksum over the
    // packet
    sum = (UInt16) ~LIB_ComputeIcmpStyleChecksum(packet, tcpLength);

    // The second part of the checksum is the virtual header
    for (i = 0; i < 12 / 2; i++)
    {
        sum += virtualHeaders[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Return the checksum
    return ~((UInt16) sum);
}

static BOOL Ipv6ReadNetworkPacketAddressAndPort(
    Int8* packet,
    in6_addr* srcAddress,
    UInt16* srcPort,
    in6_addr* destAddress,
    UInt16* destPort)
{
    struct tcphdr* thdr = NULL;
    struct udphdr* uhdr = NULL;
    UInt8 protocol = 0;
    UInt32 ipv6HeaderLen = 40;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    protocol = ipv6Header->ip6_nxt;

    *srcAddress = ipv6Header->ip6_src;
    *destAddress = ipv6Header->ip6_dst;

    switch (protocol)
    {
        case IP6_NHDR_FRAG:
        {
            ERROR_ReportWarning("Ipv6: Fragments of packet received. "
                "Dropping them");
            return FALSE;
        }
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipv6HeaderLen);
            *srcPort = ntohs(thdr->source);
            *destPort = ntohs(thdr->dest);
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipv6HeaderLen);
            *srcPort = ntohs(uhdr->source);
            *destPort = ntohs(uhdr->dest);
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}


static BOOL ReadNetworkPacketAddressAndPort(
    char *packet,
    NodeAddress *srcAddress,
    unsigned short *srcPort,
    NodeAddress *destAddress,
    unsigned short *destPort)
{
    struct iphdr *ip;
    struct tcphdr *thdr;
    struct udphdr *uhdr;
    int protocol, ipHeaderLen;


    ip = (struct iphdr *)packet;
    ipHeaderLen =  ip->ihl * 4;
    protocol = ip->protocol;

    *srcAddress     = ntohl(ip->saddr);
    *destAddress     = ntohl(ip->daddr);

    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipHeaderLen);
            *srcPort     = ntohs(thdr->source);
            *destPort    = ntohs(thdr->dest);
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipHeaderLen);
            *srcPort    = ntohs(uhdr->source);
            *destPort    = ntohs(uhdr->dest);
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL Ipv6ReadHostPacketAddressAndPort(
    Int8* packet,
    in6_addr* srcAddress,
    UInt16* srcPort,
    in6_addr* destAddress,
    UInt16* destPort)
{
    struct tcphdr* thdr = NULL;
    struct udphdr* uhdr = NULL;
    UInt8 protocol = 0;
    Int32 ipv6HeaderLen = 40;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    protocol = ipv6Header->ip6_nxt;

    *srcAddress = ipv6Header->ip6_src;
    *destAddress = ipv6Header->ip6_dst;

    switch (protocol)
    {
        case IP6_NHDR_FRAG:
        {
            ERROR_ReportWarning("Ipv6: Fragments of packet received. "
                "Dropping them");
            return FALSE;
        }
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipv6HeaderLen);
            *srcPort = thdr->source;
            *destPort = thdr->dest;
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipv6HeaderLen);
            *srcPort = uhdr->source;
            *destPort = uhdr->dest;
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}


static BOOL ReadHostPacketAddressAndPort(
    char *packet,
    NodeAddress *srcAddress,
    unsigned short *srcPort,
    NodeAddress *destAddress,
    unsigned short *destPort)
{
    struct iphdr *ip;
    struct tcphdr *thdr;
    struct udphdr *uhdr;
    int protocol, ipHeaderLen;
    IpHeaderType *ipHeader = (IpHeaderType *)packet;

    ipHeaderLen = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    ip = (struct iphdr *)packet;
    protocol = ip->protocol;

    *srcAddress     = ip->saddr;
    *destAddress     = ip->daddr;

    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipHeaderLen);
            *srcPort     = thdr->source;
            *destPort    = thdr->dest;
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipHeaderLen);
            *srcPort     = uhdr->source;
            *destPort    = uhdr->dest;
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

BOOL Ipv6ReadPacketAddressAndPort(
    Int8* packet,
    in6_addr* srcAddress,
    UInt16* srcPort,
    in6_addr* destAddress,
    UInt16* destPort,
    PacketFormatType formatType)
{
    if (formatType == PACKET_FORMAT_HOST)
    {
        return Ipv6ReadHostPacketAddressAndPort(packet,
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else if (formatType == PACKET_FORMAT_NETWORK)
    {
        return Ipv6ReadNetworkPacketAddressAndPort(packet,
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else
    {
        return FALSE;
    }
}

BOOL ReadPacketAddressAndPort(
    char *packet,
    NodeAddress *srcAddress,
    unsigned short *srcPort,
    NodeAddress *destAddress,
    unsigned short *destPort,
    PacketFormatType formatType)
{
    if (formatType == PACKET_FORMAT_HOST)
    {
        return ReadHostPacketAddressAndPort(packet, 
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else if (formatType == PACKET_FORMAT_NETWORK)
    {
        return ReadNetworkPacketAddressAndPort(packet, 
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else
    {
        return FALSE;
    }
}

static BOOL FormatOutgoingIpv6PacketHeaders(
    Int8* packet)
{
    struct udphdr* uhdr = NULL;
    struct tcphdr* thdr = NULL;
    Int32 protocol = 0;
    Int32 ipv6HeaderLen = 40;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    protocol = ipv6Header->ip6_nxt;
    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipv6HeaderLen);
            thdr->source = htons(thdr->source);
            thdr->dest = htons(thdr->dest);
            thdr->seq = htonl(thdr->seq);
            thdr->ack_seq = htonl(thdr->ack_seq);
            thdr->window = htons(thdr->window);
            thdr->urg_ptr = htons(thdr->urg_ptr);
            thdr->check = 0;

            UInt8* field = (UInt8 *)(packet + ipv6HeaderLen + 12);
            UInt8 lval = *field >> 4;
            UInt8 rval = *field & 0xFF;
            *field = (rval << 4) | lval;

            UInt8 *flags = (UInt8 *)(packet + ipv6HeaderLen + 13);

            // check the TCP options
#ifdef FORMAT_TCP_OPTIONS
            if (ipTotLen - ipv6HeaderLen - 20 /* Basic TCP header len */ > 0)
            {
                // There are tcp option
                unsigned char* options = (unsigned char *)(packet
                        + ipv6HeaderLen + 20);
                if (options[0] == 0x2) /* MAX SEGMENT SIZE option */
                {
                    unsigned char tmp = options[3];
                    options[3] = options[2];
                    options[2] = tmp;
                }
            }
#endif
             thdr->check = AutoIPNEComputeTcpStyleChecksum(
                    (UInt8*)&ipv6Header->ip6_src,
                    (UInt8*)&ipv6Header->ip6_dst,
                    ipv6Header->ip6_nxt,
                    (UInt32)ntohs(ipv6Header->ip6_plen),
                    (UInt8 *)thdr);
                break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipv6HeaderLen);
            uhdr->source = htons(uhdr->source);
            uhdr->dest = htons(uhdr->dest);
            uhdr->len = htons(uhdr->len);
            uhdr->check = 0;
            uhdr->check = AutoIPNEComputeTcpStyleChecksum(
                            (UInt8*)&ipv6Header->ip6_src,
                            (UInt8*)&ipv6Header->ip6_dst,
                            ipv6Header->ip6_nxt,
                            (UInt32)ntohs(ipv6Header->ip6_plen),
                            (UInt8 *)uhdr);
            break;
        }
        case IPPROTO_ICMP:
        {
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}


static BOOL FormatOutgoingPacketHeaders(
    char *packet)
{
    struct iphdr *ip;
    struct udphdr *uhdr;
    struct tcphdr *thdr;
    IpHeaderType *ipHeader = (IpHeaderType *)packet;
    int ipHeaderLen, ipTotLen;
    int protocol;

    ipHeaderLen = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;
    ipTotLen = IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len);
    
    // Let us first convert the first 4 bytes of the QualNet's IP header
    ipHeader->ip_v_hl_tos_len = htonl(ipHeader->ip_v_hl_tos_len);

    ip = (struct iphdr *)packet;
    
    ip->tot_len     = htons(ipTotLen);
    ip->id             = htons(ip->id);
#ifndef FORMAT_IP_FRAGMENT
    ip->frag_off     = htons(ip->frag_off);
#endif    
    ip->check        = 0;
    ip->saddr        = htonl(ip->saddr);
    ip->daddr        = htonl(ip->daddr);

    protocol = ip->protocol;
    
    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipHeaderLen);
            
            thdr->source     = htons(thdr->source);
            thdr->dest         = htons(thdr->dest);
            thdr->seq        = htonl(thdr->seq);
            thdr->ack_seq     = htonl(thdr->ack_seq);
            thdr->window    = htons(thdr->window);
            thdr->urg_ptr    = htons(thdr->urg_ptr);
            thdr->check        = 0;
            
            // Really not sure about this... 
            // why do we have to change the byte for data_off and reserved
            unsigned char *field = (unsigned char *)(packet + ipHeaderLen + 12);
            unsigned char lval = *field >> 4;
            unsigned char rval = *field & 0xFF;
            *field = (rval << 4) | lval;

            UInt8* flags = (unsigned char *)(packet + ipHeaderLen + 13);

            /* check the TCP options */
#ifdef FORMAT_TCP_OPTIONS
            if (ipTotLen - ipHeaderLen - 20 /* Basic TCP header len */ > 0)
            /* TODO */
            {
                // There are tcp option
                unsigned char *options = (unsigned char *)(packet + ipHeaderLen + 20);
                if (options[0] == 0x2) /* MAX SEGMENT SIZE option */
                {
                    unsigned char tmp = options[3];
                    options[3] = options[2];
                    options[2] = tmp;
                }
            }
#endif


            thdr->check = LIB_ComputeTcpStyleChecksum(
                            ip->saddr,
                            ip->daddr,
                            ip->protocol,
                            htons(ipTotLen - ipHeaderLen),
                            (UInt8 *)thdr);

                break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipHeaderLen);
            uhdr->source    = htons(uhdr->source);
            uhdr->dest         = htons(uhdr->dest);
            uhdr->len        = htons(uhdr->len);
            uhdr->check        = 0;
            break;
        }
        case IPPROTO_ICMP:
        {
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL FormatIncomingIpv6PacketHeaders(
    char* packet)
{
    struct udphdr* uhdr = NULL;
    struct tcphdr* thdr = NULL;
    UInt8 protocol = 0;
    Int32 ipv6HeaderLen = 40;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    protocol = ipv6Header->ip6_nxt;
    switch (protocol)
    {
        case IP6_NHDR_FRAG:
        {
            // This case will not get executed. Its already been handled
            break;
        }
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipv6HeaderLen);
            
            thdr->source = ntohs(thdr->source);
            thdr->dest = ntohs(thdr->dest);
            thdr->seq = ntohl(thdr->seq);
            thdr->ack_seq = ntohl(thdr->ack_seq);
            thdr->window = ntohs(thdr->window);
            thdr->urg_ptr = ntohs(thdr->urg_ptr);
            thdr->check = 0;
            
#ifdef FORMAT_TCP_OPTIONS
            if (thdr->doff > 5)
            {
                // There are tcp option
                unsigned char *options = (unsigned char *)(packet + 40 + 20);
                if (options[0] == 0x2) /* MAX SEGMENT SIZE option */
                {
                    unsigned char tmp = options[3];
                    options[3] = options[2];
                    options[2] = tmp;
                }
            }
#endif
            unsigned char *field = (unsigned char *)(packet + 40 + 12);
            unsigned char lval = *field >> 4;
            unsigned char rval = *field & 0xFF;
            *field = (rval << 4) | lval;

            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipv6HeaderLen);
            uhdr->source = ntohs(uhdr->source);
            uhdr->dest = ntohs(uhdr->dest);
            uhdr->len = ntohs(uhdr->len);
            uhdr->check = 0;
            break;
        }
        case IPPROTO_ICMP:
        {
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}


static BOOL FormatIncomingPacketHeaders(
    char *packet)
{
    struct iphdr *ip;
    struct udphdr *uhdr;
    struct tcphdr *thdr;
    IpHeaderType *ipHeader = (IpHeaderType *)packet;
    int ipHeaderLen, protocol;
    

    ip = (struct iphdr *)packet;
    ipHeaderLen = ip->ihl * 4;
    
    //ip->tot_len     = ntohs(ip->tot_len);
    ip->id             = ntohs(ip->id);
#ifdef FORMAT_IP_FRAGMENT
    ip->frag_off     = ntohs(ip->frag_off);
#endif
    ip->check        = 0;
    ip->saddr        = ntohl(ip->saddr);
    ip->daddr        = ntohl(ip->daddr);


    ipHeader->ip_v_hl_tos_len = ntohl(ipHeader->ip_v_hl_tos_len);

    protocol = ip->protocol;
    
    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipHeaderLen);
            
            thdr->source     = ntohs(thdr->source);
            thdr->dest         = ntohs(thdr->dest);
            thdr->seq        = ntohl(thdr->seq);
            thdr->ack_seq     = ntohl(thdr->ack_seq);
            thdr->window    = ntohs(thdr->window);
            thdr->urg_ptr    = ntohs(thdr->urg_ptr);
            thdr->check    = 0;
            
#ifdef FORMAT_TCP_OPTIONS
            if (thdr->doff > 5)
            {
                // There are tcp option
                unsigned char *options
                    = (unsigned char *)(packet + ipHeaderLen + 20);
                if (options[0] == 0x2) /* MAX SEGMENT SIZE option */
                {
                    unsigned char tmp = options[3];
                    options[3] = options[2];
                    options[2] = tmp;
                }
            }
#endif
                        
            unsigned char *field
                = (unsigned char *)(packet + ipHeaderLen + 12);
            unsigned char lval = *field >> 4;
            unsigned char rval = *field & 0xFF;
            *field = (rval << 4) | lval;

            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipHeaderLen);
            uhdr->source    = htons(uhdr->source);
            uhdr->dest         = htons(uhdr->dest);
            uhdr->len        = htons(uhdr->len);
            uhdr->check        = 0;
            break;
        }
        case IPPROTO_ICMP:
        {
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
} 

BOOL FormatPacketHeaders(
    char *packet,
    PacketFormatType formatType,
    BOOL isIpv6Pkt)
{
    if (isIpv6Pkt)
    {
        if (formatType == PACKET_FORMAT_NETWORK)
        {
            return FormatIncomingIpv6PacketHeaders(packet);
        }
        else if (formatType == PACKET_FORMAT_HOST)
        {
            return FormatOutgoingIpv6PacketHeaders(packet);
        }
    }
    else
    {
        if (formatType == PACKET_FORMAT_NETWORK)
        {
            return FormatIncomingPacketHeaders(packet);
        }
        else if (formatType == PACKET_FORMAT_HOST)
        {
            return FormatOutgoingPacketHeaders(packet);
        }
    }
    return FALSE;
}

static BOOL UpdateIpv6NetworkPacketAddressAndPort(
    Int8* packet,
    in6_addr* srcAddress,
    UInt16 srcPort,
    in6_addr* destAddress,
    UInt16 destPort)
{
    struct tcphdr* thdr = NULL;
    struct udphdr* uhdr = NULL;
    UInt8 protocol = 0;
    Int32 ipv6HeaderLen = 40;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    protocol = ipv6Header->ip6_nxt;

    if (srcAddress)
    {
        ipv6Header->ip6_src = *srcAddress;
    }

    if (destAddress)
    {
        ipv6Header->ip6_dst = *destAddress;
    }

    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipv6HeaderLen);
            if (srcPort)
            {
                thdr->source = srcPort;
            }

            if (destPort)
            {
                thdr->dest = destPort;
            }
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipv6HeaderLen);
            if (srcPort)
            {
                uhdr->source = srcPort;
            }

            if (destPort)
            {
                uhdr->dest = destPort;
            }
            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

static BOOL UpdateNetworkPacketAddressAndPort(
    char *packet,
    NodeAddress srcAddress,
    unsigned short srcPort,
    NodeAddress destAddress,
    unsigned short destPort)
{
    struct iphdr *ip;
    struct tcphdr *thdr;
    struct udphdr *uhdr;
    int protocol, ipHeaderLen;
    IpHeaderType *ipHeader = (IpHeaderType *)packet;

    ipHeaderLen = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    ip = (struct iphdr *)packet;
    protocol = ip->protocol;

    if (srcAddress)
        ip->saddr = srcAddress;
    
    if (destAddress)
        ip->daddr = destAddress;

    switch (protocol)
    {
        case IPPROTO_TCP:
        {
            thdr = (struct tcphdr *)(packet + ipHeaderLen);
            if (srcPort)
                thdr->source = srcPort;

            if (destPort)
                thdr->dest = destPort;
            break;
        }
        case IPPROTO_UDP:
        {
            uhdr = (struct udphdr *)(packet + ipHeaderLen);
            if (srcPort)
                uhdr->source = srcPort;

            if (destPort)
                uhdr->dest = destPort;

            break;
        }
        default:
        {
            return FALSE;
        }
    }

    return TRUE;
}

void UpdateIpv6PacketAddressAndPort(
    Int8* packet,
    in6_addr* srcAddress,
    UInt16 srcPort,
    in6_addr* destAddress,
    UInt16 destPort,
    PacketFormatType formatType)
{
    if (formatType == PACKET_FORMAT_NETWORK)
    {
        // not required to be called
    }
    else if (formatType == PACKET_FORMAT_HOST)
    {
        UpdateIpv6NetworkPacketAddressAndPort(
            packet,
            srcAddress,
            srcPort,
            destAddress,
            destPort);
    }
}


BOOL UpdatePacketAddressAndPort(
    char *packet,
    NodeAddress srcAddress,
    unsigned short srcPort,
    NodeAddress destAddress,
    unsigned short destPort,
    PacketFormatType formatType)
{
    if (formatType == PACKET_FORMAT_NETWORK)
    {
        return UpdateNetworkPacketAddressAndPort(
                        packet,
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else if (formatType == PACKET_FORMAT_HOST)
    {
        return UpdateNetworkPacketAddressAndPort(
                        packet,
                        srcAddress,
                        srcPort,
                        destAddress,
                        destPort);
    }
    else
        return FALSE;
}
