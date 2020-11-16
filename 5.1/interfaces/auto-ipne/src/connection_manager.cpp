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
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "auto-ipnetworkemulator.h"
#include "connection_manager.h"


void AutoIPNEHandleCMRequest(
    EXTERNAL_Interface *iface,
    UInt32 cmAddress,
    UInt16 cmPort,
    int deviceIndex)
{
    int  size, i;
    Node *node;
    NodeAddress address;

    size = 0;

    for(node = iface->partition->firstNode; node != NULL; node = node->nextNodeData)
    {
        printf("%d %s", node->nodeId, node->hostname);
        for(i = 0; i < node->numberInterfaces; i++)
        {
            address = MAPPING_GetInterfaceAddressForInterface(node, node->nodeId, i);
            printf(" %x", address);
        }
        printf("\n");
        fflush(stdout);

    }




    printf("Got request message from %x:%d\n", cmAddress, htons(cmPort));
    fflush(stdout);
}


// /**
// API       :: AutoIPNEHandleConnectionManager 
// PURPOSE   :: 
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet
// + size : int : The size of the sniffed packet
// + deviceIndex : int : the index of the network device receiving this packet
// RETURN    :: void
// **/
void AutoIPNEHandleConnectionManager(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    int deviceIndex)
{
    struct libnet_ipv4_hdr* ip;
    struct libnet_udp_hdr* udp;
    int ipHeaderLength;
    UInt8* payload;
    UInt8* nextHeader;
    ConnectionManagerHdr *message;

    // Extract IP header
    ip = (struct libnet_ipv4_hdr*) (packet + AutoIPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;

    // Find where the payload begins
    payload = packet + AutoIPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.
    nextHeader = ((UInt8*) ip) + ipHeaderLength;
    udp = (struct libnet_udp_hdr *)nextHeader;

    // Extract the payload
    message = (ConnectionManagerHdr *)(nextHeader + 8); /* 8 = size of UDP header */
    
    if(htonl(message->magicNumber) != AUTO_IPNE_MAGIC)
    {
        printf("Message from Connection manager has incorrect magic number: %x\n", htonl(message->magicNumber));
        return;
    }

    switch(htonl(message->msgType))
    {
        case AUTO_IPNE_CM_REQUEST:
        {
            AutoIPNEHandleCMRequest(iface, 
#ifdef _WIN32
                    ip->ip_src.S_un.S_addr,
#else
                    ip->ip_src.s_addr,
#endif
                    udp->uh_sport,
                    deviceIndex);
            break;
        }
        case AUTO_IPNE_CM_REGISTER:
        {
            break;
        }
        case AUTO_IPNE_CM_UNREGISTER:
        {
            break;
        }
        default:
        {
            printf("Unrecognized message from connection manager: %d\n", htonl(message->msgType));
        }
    }
}
