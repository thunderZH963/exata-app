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

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "ipnetworkemulator.h"
#include "external.h"
#include "external_socket.h"
#include "udp_interface.h"
#include "olsr_interface.h"
#include "transport_udp.h"
#include "network_ip.h"

#define DEBUG 0 

void UDPSwapBytes(
    UInt8* udpHeader,
    BOOL in)
{
    TransportUdpHeader *header;
    
    // Extract UDP  header
    header = (TransportUdpHeader*) udpHeader;

    // Byte-swap common header.  This is input from external network so put
    // it in host order.
    if (in)
    {
        EXTERNAL_ntoh(
            &header->sourcePort,
            sizeof(header->sourcePort));
        EXTERNAL_ntoh(
            &header->destPort,
            sizeof(header->destPort));
        EXTERNAL_ntoh(
            &header->length,
            sizeof(header->length));
        EXTERNAL_ntoh(
            &header->checksum,
            sizeof(header->checksum));
    }

    // Byte-swap common header.  This is output to network, so put it in 
    // network order.
    if (!in)
    {
        EXTERNAL_hton(
            &header->sourcePort,
            sizeof(header->sourcePort));
        EXTERNAL_hton(
            &header->destPort,
            sizeof(header->destPort));
        EXTERNAL_hton(
            &header->length,
            sizeof(header->length));
        EXTERNAL_hton(
            &header->checksum,
            sizeof(header->checksum));
    }
}

void PreProcessIpPacketUdp(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    Int32 size,
    IPNE_EmulatePacketFunction** func)
{
    struct libnet_ipv4_hdr *ip;
    u_long sendAddr;
    u_long destAddr;
    u_short sendPort;
    u_short destPort;
    u_short* checksum;
    IPSocket * s;
    IPNEData *data;
    int i;
    u_char *dataOffset; 
    struct libnet_udp_hdr *udp =  NULL;
    int ipHeaderLength;
    u_short fragOffset;
    NodeAddress ipDestAddr;

    data = (IPNEData*) iface->data;
    
    // Find the ip header
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;

    // Find the udp header and get a pointer to the checksum
    udp = (struct libnet_udp_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH
        + ipHeaderLength);
    checksum = &udp->uh_sum;
    fragOffset = ntohs(ip->ip_off) << 3;

    // If using NAT then pre-process the IP packet
    if (data->nat)
    {
        PreProcessIpPacketNatYes(iface, ip, checksum);
    }
    
    // Extract the addresses and ports.  Addresses must be in network byte
    // order, ports must be in host byte order.
    if (fragOffset ==0)
    {
        sendAddr = (u_long) ip->ip_src.s_addr;
        destAddr = (u_long) ip->ip_dst.s_addr;
        sendPort = ntohs(udp->uh_sport);
        destPort = ntohs(udp->uh_dport);
        dataOffset = ((u_char*) udp) + sizeof(struct libnet_udp_hdr);
    
        // Loop over all sockets
        for (i = 0; i < data->numSockets; i++)
        { 
            s = &data->sockets[i];

            // If the packet matches
            if (CompareIPSocket(
                sendAddr,
                sendPort,
                destAddr,
                destPort,
                s))
            {
                // Call the socket function
                (s->func)(iface, packet, dataOffset, size, checksum, func);
                break;
            }
        }
    }

     ipDestAddr=ntohl(ip->ip_dst.s_addr);

    if ((ipDestAddr > IP_MIN_MULTICAST_ADDRESS) && fragOffset ==0)
    {
         *checksum = 0;
    }

    // If true emulation, swap bytes from network byte order to host byte
    // order
    if (data->trueEmulation && fragOffset ==0)
    {
        UDPSwapBytes((UInt8*) udp, TRUE);
    }
}

void ProcessOutgoingIpPacketUdp(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8* udpHeader,
    IpHeaderType *ipHeader,
    //struct libnet_ipv4_hdr* ip,
    BOOL *inject)
{
    IPNEData *data = (IPNEData*) iface->data;

    if (data->trueEmulation)
    {
        unsigned short destPortNumber;
        TransportUdpHeader *udp;
        udp= (TransportUdpHeader *)udpHeader;
        destPortNumber=udp->destPort;
        int ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

        // Swap UDP bytes
        UDPSwapBytes(udpHeader, FALSE);
        
        if ((data->olsrEnabled) &&
                 (destPortNumber == APP_ROUTING_OLSR_INRIA))
        {
            for (int i=0; i < data->numOlsrNodes;i++)
            {
                if (myAddress == data->olsrNodeAddress[i])
                {
                    *inject=TRUE;
                    break;
                }
            }
            if (inject)
            {
                unsigned char *olsr= (unsigned char *) (
                        (unsigned char *) udp 
                        + sizeof(TransportUdpHeader));
                OLSRSwapBytes(olsr,FALSE);
            }

        }

        udp->checksum = ComputeTcpStyleChecksum(
            //htonl(LibnetIpAddressToULong(ip->ip_src)),
            htonl(ipHeader->ip_src),
            //htonl(LibnetIpAddressToULong(ip->ip_dst)),
            htonl(ipHeader->ip_dst),
            ipHeader->ip_p,
            htons((UInt16)IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength), udpHeader);

    }
}
