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

/**
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
    BOOL in)
{

    struct libnet_tcp_hdr* header = (struct libnet_tcp_hdr*) tcpHeader;

    // Byte-swap common header.  This is input from external network so put
    // it in host order.
    if (in)
    {
        EXTERNAL_ntoh(
            &header->th_sport,
            sizeof(header->th_sport));
        EXTERNAL_ntoh(
            &header->th_dport,
            sizeof(header->th_dport));
        EXTERNAL_ntoh(
            &header->th_seq,
            sizeof(header->th_seq));
        EXTERNAL_ntoh(
            &header->th_ack,
            sizeof(header->th_ack));
        EXTERNAL_ntoh(
            &header->th_sum,
            sizeof(header->th_sum));
        EXTERNAL_ntoh(
            &header->th_urp,
            sizeof(header->th_urp));

        unsigned int t;
        t=header->th_x2;  
        header->th_x2 =  header->th_off;
        header->th_off = t;

    }

    // Byte-swap common header.  This is output to network, so put it in
    // network order.
    if (!in)
    {
        EXTERNAL_hton(
            &header->th_sport,
            sizeof(header->th_sport));
        EXTERNAL_hton(
            &header->th_dport,
            sizeof(header->th_dport));
        EXTERNAL_hton(
            &header->th_seq,
            sizeof(header->th_seq));
        EXTERNAL_hton(
            &header->th_ack,
            sizeof(header->th_ack));
        EXTERNAL_hton(
            &header->th_sum,
            sizeof(header->th_sum));
        EXTERNAL_hton(
            &header->th_urp,
            sizeof(header->th_urp));

        unsigned int t;
        t=header->th_x2;  
        header->th_x2 =  header->th_off;
        header->th_off = t;
    }
}


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
    IPNE_EmulatePacketFunction** func)
{
    IPNEData* data;
    IPSocket* s;
    UInt32 sendAddr;
    UInt32 destAddr;
    int i;
    int ipHeaderLength;
    struct libnet_tcp_hdr *tcpHeader =  NULL;


    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    ipHeaderLength = ip->ip_hl * 4;

    // If using NAT
    if (data->nat)
    {
        PreProcessIpPacketNatYes(iface, ip, checksum);
    }

    // Find the tcp header and get a pointer to the checksum
    tcpHeader = (struct libnet_tcp_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH
        + ipHeaderLength);

    // Extract the addresses
    sendAddr = (UInt32) ip->ip_src.s_addr;
    destAddr = (UInt32) ip->ip_dst.s_addr;

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

    // If true emulation, swap bytes from network byte order to host byte
    // order
    if (data->trueEmulation)
    {
        TCPSwapBytes((UInt8*) tcpHeader, TRUE);
    }
}

void ProcessOutgoingIpPacketTcp(
    EXTERNAL_Interface* iface,
    //struct libnet_ipv4_hdr* ip,
    IpHeaderType *ipHeader,
    UInt8* tcpHeader,
    UInt16* checksum)
{
    int ipHeaderLength;
    UInt16 sum2;
    IPNEData *data = (IPNEData*) iface->data;

    if (data->trueEmulation)
    {
        // Swap TCP bytes
        TCPSwapBytes(tcpHeader, FALSE);

        //ipHeaderLength = ip->ip_hl * 4;
        ipHeaderLength =IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

        // First save, then zero out the checksum
        sum2 = *checksum;
        *checksum = 0;

        // Compute for TCP style
        *checksum = ComputeTcpStyleChecksum(
        //htonl(LibnetIpAddressToULong(ip->ip_src)),
        htonl(ipHeader->ip_src),
        //htonl(LibnetIpAddressToULong(ip->ip_dst)),
        htonl(ipHeader->ip_dst),
        ipHeader->ip_p,
        htons(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength), tcpHeader);

    }
}

