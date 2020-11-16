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
#include <errno.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "external_util.h"
#include "auto-ipnetworkemulator.h"
#include "capture_interface.h"
#include "ipne_qualnet_interface.h"
#include "arp_interface.h"
#include "olsr_interface.h"
#include "ospf_interface.h"
#include "pim_interface.h"
#include "esp_interface.h"
#include "transport_udp.h"
#include "capture_interface.h"
#ifdef EXATA
#include "mdp_interface.h"
#endif
#include "app_mdp.h"
#include "app_util.h"
// /**
// API       :: AutoIPNEHandleSniffedTunnelPacket
// PURPOSE   :: This function will handle an incoming ESP packet received
//            from outside Exata. Oncec the pcket is decrypted, this function
//            will be invoked from the ESP model to get the original packet.
//            this function works for the decrypted tunneled packet.
// PARAMETERS::
// + node : Node* : The node structure
// + msg : Message* : Pointer to the msg
// + packet : UInt8* : The pointer to the sniffed packet
// RETURN    :: void
// **/
void AutoIPNEHandleSniffedTunnelPacket(Node*     node,
                                       Message*  msg,
                                       UInt8*    packet)
{
    struct libnet_ipv4_hdr* ip;
    struct libnet_tcp_hdr* tcp;
    struct libnet_udp_hdr* udp;
    int ipHeaderLength;
    UInt8* payload;
    UInt8* nextHeader;
    UInt32 packetSize;

    // Extract IP header
    ip = (struct libnet_ipv4_hdr*) (packet);
    //ip->ip_hl specifies the length of the IP packet header in 32 bit words
    //so multiply with 4 to get the length in bytes.
    ipHeaderLength = ip->ip_hl * 4;

    // Update the packet size.  This will take care of the case where the
    // ethernet frame is padded.
    packetSize = ntohs(ip->ip_len);

    // Find where the payload begins
    payload = packet + ipHeaderLength;

    IpHeaderType *ipHeader = (IpHeaderType *)ip;
    ip->ip_id         = ntohs(ip->ip_id);
    ip->ip_off        = ntohs(ip->ip_off);
    ip->ip_sum        = ntohs(ip->ip_sum);
    ipHeader->ip_dst = ntohl(LibnetIpAddressToULong(ip->ip_dst));
    ipHeader->ip_src = ntohl(LibnetIpAddressToULong(ip->ip_src));

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.
    nextHeader = ((UInt8*) ip) + ipHeaderLength;

    int payloadSize = ntohs(ip->ip_len) - ipHeaderLength;
    AutoIPNEHandleCommonPacket(nextHeader,
                               NULL,
                               0,
                               ipHeader,
                               ip->ip_p,
                               (UInt8*) ip,
                               payloadSize);
    ipHeader->ip_v_hl_tos_len = ntohl(ipHeader->ip_v_hl_tos_len);
    return;
}
// /**
// API       :: AutoIPNEHandleSniffedESPPacket
// PURPOSE   :: This function will handle an incoming ESP packet received
//              from outside Exata. Once the packet is decrypted,this function
//              will be invoked from the ESP model to get the original packet
//              This function will not be invoked from the interface code
//              but instead will be called from the IPSEC model itself
//              once the packet has been decrypted.
// PARAMETERS::
// + node : Node* : The node structure
// + msg : Message* : Pointer to the msg structure
// + dat : char* : Pointer to the decrypted packet
// + ipHdr : IpHeaderType*: Ip header stucture
// + proto: The protocol depending on which the further functions will
//          be invoked
// RETURN    :: void
// **/
void AutoIPNEHandleSniffedESPPacket(Node*         node,
                                    Message*      msg,
                                    char*         dat,
                                    IpHeaderType* ipHdr,
                                    unsigned int  proto)
{
    UInt8* nextHeader;
    int hLen = IpHeaderSize(ipHdr);

    nextHeader = ((UInt8*) dat) + hLen;
    int payloadSize = IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len) - hLen;
    /* This is a tunnel mode data handling which is required for ESP data
     * only. If tunnel mode is handled then rest of the common packet need
     * not go through the swapping process*/
    if (proto == IPPROTO_IPIP)
    {
        AutoIPNEHandleSniffedTunnelPacket(node,
                                          msg,
                                          (UInt8*)dat);
        proto = ipHdr->ip_p;
        msg->headerProtocols[msg->numberOfHeaders] = TRACE_IP;
        msg->headerSizes[msg->numberOfHeaders] = IpHeaderSize(ipHdr);
        msg->numberOfHeaders++;
    }
    else
    {
        AutoIPNEHandleCommonPacket(nextHeader,
                                   NULL,
                                   0,
                                   ipHdr,
                                   proto,
                                   (UInt8*) dat,
                                   payloadSize);
    }
    /*Recreate the headers as they would have been lost
      if received from external entity.*/

    if (proto == IPPROTO_UDP)
    {
        MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
        msg->headerProtocols[msg->numberOfHeaders] = TRACE_UDP;
        msg->headerSizes[msg->numberOfHeaders] = sizeof(TransportUdpHeader);
        msg->numberOfHeaders++;
        MESSAGE_AddHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
    }
    else if (proto == IPPROTO_ICMP)
    {
        MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
        msg->headerProtocols[msg->numberOfHeaders] = TRACE_ICMP;
        msg->headerSizes[msg->numberOfHeaders] = sizeof(libnet_icmpv4_hdr);
        msg->numberOfHeaders++;
        MESSAGE_AddHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
    }
    else if (proto != IPPROTO_IP)
    {
        MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
        MESSAGE_AddHeader(node, msg, 0, TRACE_FORWARD);
        MESSAGE_AddHeader(node, msg, IpHeaderSize(ipHdr), TRACE_IP);
    }
    return;
}
