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
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "api.h"
#include "partition.h"
#include "internetgateway.h"
#include "gateway_osutils.h"
#include "gateway_packet.h"
#include "gateway_interface.h"
#include "gateway_nat.h"
#include "external_util.h"
#include "external_socket.h"
#include "network_ip.h"
#include "transport_tcp_hdr.h"
#include "auto-ipnetworkemulator.h"
#include "ipv6.h"


//#define GATEWAY_DEBUG


static void GATEWAY_ProcessIpv6CapturedPacket(
    EXTERNAL_Interface* iface,
    GatewayData* gwData,
    Int8* packet,
    Int32 packetSize)
{
    Address ipv6GatewayAddress;
    Address ipv6SrcAddress;
    in6_addr srcAddress, destAddress;
    UInt16 srcPort = 0, destPort = 0;
    AddressPortPair* pair = NULL;
    Int32 ipv6HeaderLen = 40;
    Int32 ethernetHeaderLen = 14;

    packet += ethernetHeaderLen; /* Skip the ethernet header */
    packetSize -= ethernetHeaderLen;

    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;

    Ipv6ReadPacketAddressAndPort(
        packet,
        &srcAddress,
        &srcPort,
        &destAddress,
        &destPort,
        PACKET_FORMAT_NETWORK);

    SetIPv6AddressInfo(&ipv6SrcAddress, srcAddress);
    SetIPv6AddressInfo(&ipv6GatewayAddress, gwData->ipv6InternetGateway);
    UInt8 ipv6Class =  ip6_hdrGetClass(ipv6Header->ipv6HdrVcf);

    pair = GatewayNatGetAddressPortPair(gwData, destPort);

    if (pair == NULL)
    {
        return;
    }

    FormatPacketHeaders(packet, PACKET_FORMAT_NETWORK, TRUE);

    UpdateIpv6PacketAddressAndPort(
        packet,
        NULL,
        0,
        &pair->srcAddress.interfaceAddr.ipv6,
        pair->srcPort,
        PACKET_FORMAT_HOST);

    EXTERNAL_SendIpv6DataNetworkLayer(
      iface,
      &ipv6GatewayAddress,
      &ipv6SrcAddress,
      &pair->srcAddress,
      ipv6Class,
      ipv6Header->ip6_nxt,
      ipv6Header->ip6_hlim,
      packet + ipv6HeaderLen,
      ntohs((u_short)ipv6Header->ip6_plen),
      EXTERNAL_QueryExternalTime(iface));
}


static void GATEWAY_ProcessCapturedPacket(
    EXTERNAL_Interface* iface,
    GatewayData* gwData,
    Int8* packet,
    Int32 packetSize)
{
    NodeAddress srcAddress, destAddress;
    unsigned short srcPort, destPort;
    AddressPortPair* pair = NULL;
    IpHeaderType* ipHeader = NULL;
    Int32 ipHeaderLen = 0;
    Int32 ipTotalLen = 0;
    Int32 ethernetHeaderLen = 14;

    packet += ethernetHeaderLen; /* Skip the ethernet header */
    packetSize -= ethernetHeaderLen;

    ReadPacketAddressAndPort(
        packet,
        &srcAddress, 
        &srcPort,
        &destAddress,
        &destPort,
        PACKET_FORMAT_NETWORK);
    
    pair = GatewayNatGetAddressPortPair(gwData, destPort);

    if (pair == NULL)
    {
#ifdef GATEWAY_DEBUG
    printf("Dropping packet %x:%d -> %x:%d (%d bytes)\n",
        srcAddress, srcPort, destAddress, destPort, packetSize - 14);
#endif

        return;
    }

    FormatPacketHeaders(packet, PACKET_FORMAT_NETWORK);

    UpdatePacketAddressAndPort(
        packet,
        0,
        0,
        pair->srcAddress.interfaceAddr.ipv4,
        pair->srcPort,
        PACKET_FORMAT_HOST);

    ipHeader = (IpHeaderType *)packet;
    // Handle fragmentation/offset if necessary 
    BOOL dontFragment = (ntohs(ipHeader->ipFragment) & 0x4000) != 0;
    BOOL moreFragments = (ntohs(ipHeader->ipFragment) & 0x2000) != 0;
    UInt16 fragmentOffset = ntohs(ipHeader->ipFragment) & 0x1FFF;
    unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    ipHeaderLen = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4; 
    ipTotalLen = IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len); 

#ifdef GATEWAY_DEBUG
    printf("Captured packet %x:%d -> %x:%d (%d bytes) [%d]\n", 
        srcAddress, srcPort, destAddress, destPort, packetSize - 14,
        ipHeader->ip_id);
#endif

    EXTERNAL_SendDataNetworkLayer(iface,
            gwData->internetGateway,
            srcAddress,
            pair->srcAddress.interfaceAddr.ipv4,
            ipHeader->ip_id,
            dontFragment,
            moreFragments,
            fragmentOffset,
            tos,
            ipHeader->ip_p,
            ipHeader->ip_ttl,
            packet + ipHeaderLen,
            ipTotalLen - ipHeaderLen,
            ipHeaderLen,
            NULL,
            EXTERNAL_QueryExternalTime(iface));
}


//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: GATEWAY_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              GATEWAYData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void GATEWAY_Initialize(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
}

// /**
// API       :: GATEWAY_InitializeNodes
// PURPOSE   :: This function is where the bulk of the IPNetworkEmulator
//              initialization is done.  It will:
//                  - Parse the interface configuration data
//                  - Create mappings between real <-> qualnet proxy
//                    addresses
//                  - Create instances of the FORWARD app on each node that
//                    is associated with a qualnet proxy address
//                  - Initialize the libpcap/libnet libraries using the
//                    configuration data
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void GATEWAY_InitializeNodes(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    GatewayData* gwData = NULL;
    int internetGatewayNodeId = 0;
    NodeAddress internetGateway = 0;
    Node* node = iface->partition->firstNode;
    BOOL wasFound = FALSE;
    BOOL IsGatewayIpv6Enable = FALSE;
    BOOL isGatewayIpv4Enable = FALSE;
    BOOL gatewayNodefound = FALSE;

    if (iface->partition->partitionId != 0)
        return;

    IO_ReadInt(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "INTERNET-GATEWAY",
            &wasFound,
            &internetGatewayNodeId);

    if (wasFound)
    {
        while (node)
        {
            if (node->nodeId == (UInt32)internetGatewayNodeId)
            {
                if (node->partitionId != 0)
                {
                    ERROR_ReportError("The Internet gateway node must be "
                        "on Partition 0\n");
                }
                gatewayNodefound = TRUE;
                break;
            }
            node = node->nextNodeData;
        }

        if (!gatewayNodefound)
        {
            ERROR_ReportError("Gateway node configured doesn't exists in "
                "the scenario. Please check the gateway configuration");
        }

        if (node->networkData.networkProtocol == IPV6_ONLY)
        {
             IsGatewayIpv6Enable = TRUE;
        }
        else if (node->networkData.networkProtocol == IPV4_ONLY)
        {
             isGatewayIpv4Enable = TRUE;
        }
        else if (node->networkData.networkProtocol == DUAL_IP)
        {
            IsGatewayIpv6Enable = TRUE;
            isGatewayIpv4Enable = TRUE;
        }
        else
        {
            ERROR_ReportError("Gateway functionality currently only "
                "supported for Ipv4 and Ipv6 network types. Please "
                "check your configuration");
        }

        if (IsGatewayIpv6Enable)
        {
            node = iface->partition->firstNode;
            Address ipv6Address
                = MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
                    node,
                    internetGatewayNodeId,
                    NETWORK_IPV6);

            if (ipv6Address.networkType != NETWORK_INVALID)
            {
                while (node)
                {
                    node->ipv6InternetGateway = ipv6Address;
                    node = node->nextNodeData;
                }
            }

            // Check if the internet gateway was assigned correctly
            node = iface->partition->firstNode;
            if (node->ipv6InternetGateway.networkType == NETWORK_INVALID)
            {
                ERROR_ReportError("Incorrect nodeId configured for "
                    "INTERNET-GATEWAY.\nUsage: INTERNET-GATEWAY "
                    "<node-id>");
            }
        }

        if (isGatewayIpv4Enable)
        {
            node = iface->partition->firstNode;
            internetGateway = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                    node,
                    internetGatewayNodeId);

            if (internetGateway != INVALID_MAPPING)
            {
                while (node)
                {
                    if (node->nodeId == (unsigned)internetGatewayNodeId)
                    {
                        if (node->partitionId != 0)
                            ERROR_ReportError("The Internet gateway node "
                            "must be on Partition 0\n");

                    }
                    node->internetGateway = internetGateway;
                    node = node->nextNodeData;
                }
            }

            // Check if the internet gateway was assigned correctly
            node = iface->partition->firstNode;
            if (node->internetGateway == INVALID_ADDRESS)
            {
                ERROR_ReportError("Incorrect nodeId configured for "
                   "INTERNET-GATEWAY.\nUsage: INTERNET-GATEWAY <node-id>\n");
            }
        }
    }

    // Allocate the local storage data structure for this interface
    gwData = (GatewayData *)MEM_malloc(sizeof(GatewayData));
    memset(gwData, 0, sizeof(GatewayData));
    if (gwData == NULL)
    {
        ERROR_ReportError("Cannot allocate memory for Gateway Interface.\n"
            "Aborting....\n");
    }

    if (isGatewayIpv4Enable)
    {
        gwData->internetGateway = internetGateway;
    }

    if (IsGatewayIpv6Enable)
    {
        gwData->ipv6InternetGateway
            = GetIPv6Address(node->ipv6InternetGateway);
    }

    gwData->lastNatPort = 23673;
    gwData->egressNATTable
        = new std::map<Int8 *, Int32, charStringCompareFunc>();
    gwData->ingressNATTable = new std::map<Int32, Int8*>();

    if ((gwData->egressNATTable == NULL) || (gwData->ingressNATTable == NULL))
    {
        printf("Cannot create NAT maps\n");
        return;
    }


    iface->data = (void *)gwData;

    /* Read the physical system's networking environment. This includes:
        a. The default internet gateway IP address
        b. The default interface to connect to internet */

    if (isGatewayIpv4Enable)
    {
        GatewayOSUtilsInitialize(gwData);

        /* Ask the AutoIPNE to close this interface */
        Address interfaceAddress;
        SetIPv4AddressInfo(&interfaceAddress, gwData->defaultInterfaceAddress);
        AutoIPNE_DisableInterface(iface->partition->firstNode, interfaceAddress);
        if (GatewayInterfaceInitialize(gwData) == FALSE)
        {
             ERROR_ReportError("Cannot initialize Ipv4 Gateway "
                "functionality");
        }
    }

    if (IsGatewayIpv6Enable)
    {
        GatewayOSUtilsIpv6Initialize(iface, gwData);
        Address interfaceAddress;
        SetIPv6AddressInfo(&interfaceAddress,
            gwData->defaultIpv6InterfaceAddress);
        AutoIPNE_DisableInterface(
            iface->partition->firstNode, interfaceAddress);
        if (GatewayInterfaceIpv6Initialize(gwData) == FALSE)
        {
            ERROR_ReportError("Cannot initialize Ipv6 Gateway "
                "functionality");
        }
    }
}

// /**
// API       :: GATEWAY_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void GATEWAY_Receive(EXTERNAL_Interface* iface)
{
    GatewayData* gwData = (GatewayData *)iface->data;
    Int8* packet = NULL;
    Int32 packetSize = 0;

    if (iface->partition->partitionId != 0)
    {
        return;
    }

    BOOL capturedIpv4Pkt = FALSE;
    BOOL capturedIpv6Pkt = FALSE;
    while (TRUE)
    {
        packet = GatewayInterfaceCapturePacket(gwData, &packetSize);
        if (packet != NULL)
        {
            capturedIpv4Pkt = TRUE;
            GATEWAY_ProcessCapturedPacket(iface, gwData, packet, packetSize);
        }
        else
        {
            capturedIpv4Pkt = FALSE;
        }
        packet = Ipv6GatewayInterfaceCapturePacket(gwData, &packetSize);
        if (packet != NULL)
        {
            capturedIpv6Pkt = TRUE;
            GATEWAY_ProcessIpv6CapturedPacket(iface,
                gwData, packet, packetSize);
        }
        else
        {
            capturedIpv6Pkt = FALSE;
        }

        if (!capturedIpv4Pkt && !capturedIpv6Pkt)
        {
            break;
        }
    }
}

// /**
// API       :: GATEWAY_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void GATEWAY_Forward(
    EXTERNAL_Interface* iface,
    Node* node,
    void* forwardData,
    Int32 forwardSize)
{
}

// /**
// API       :: GATEWAY_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void GATEWAY_Finalize(EXTERNAL_Interface* iface)
{
    GatewayData* gwData = (GatewayData *)iface->data;
    GatewayOSUtilsFinalize(gwData);
}

void GATEWAY_ForwardToIpv6InternetGateway(
    Node* node,
    Int32 interfaceIndex,
    Message* msg)
{
    EXTERNAL_Interface *iface;
    GatewayData* gwData = NULL;
    BOOL retVal = FALSE;
    AddressPortPair natKey;
    UInt16 natPort;

    // Retrieve the Internet-Gateway external interface
    iface = node->partitionData->interfaceTable[EXTERNAL_INTERNET_GATEWAY];
    if (iface == NULL)
    {
        MESSAGE_Free(node, msg);
        return;
    }

    gwData = (GatewayData *)iface->data;

    // Read the (address, port) pair for this packet
    retVal = Ipv6ReadPacketAddressAndPort(
                    (Int8 *)msg->packet, 
                    &natKey.srcAddress.interfaceAddr.ipv6,
                    &natKey.srcPort,
                    &natKey.destAddress.interfaceAddr.ipv6,
                    &natKey.destPort,
                    PACKET_FORMAT_HOST);

    if (!retVal)
    {
        return;
    }

    natPort = GatewayNatGetPortNumber(gwData, &natKey, TRUE);
    if (natPort <= 0)
    {
        printf("Cannot locate NAT key\n");
        return;
    }

    UpdateIpv6PacketAddressAndPort((char *)msg->packet,
            &gwData->defaultIpv6InterfaceAddress,
            natPort,
            NULL, /* do not change this field */
            0, /* do not change this field */ 
            PACKET_FORMAT_HOST);

    // Convert the packet form host format to network format
    retVal
        = FormatPacketHeaders((char *)msg->packet, PACKET_FORMAT_HOST, TRUE);

    if (!retVal)
    {
        printf("Cannot convert this packet from host format to "
            "network format\n");
        MESSAGE_Free(node, msg);
        return;
    }

    Ipv6GatewayInterfaceWritePacket(gwData,
            (UInt8 *)MESSAGE_ReturnPacket(msg),
            MESSAGE_ReturnPacketSize(msg));
    MESSAGE_Free(node, msg);
}


void GATEWAY_ForwardToInternetGateway(
    Node* node,
    int interfaceIndex,
    Message* msg)
{
    EXTERNAL_Interface* iface = NULL;
    GatewayData* gwData = NULL;
    BOOL retVal = FALSE;
    AddressPortPair natKey;
    UInt16 natPort = 0;

    // Retrieve the Internet-Gateway external interface 
    iface = node->partitionData->interfaceTable[EXTERNAL_INTERNET_GATEWAY];
    if (iface == NULL)
    {
        MESSAGE_Free(node, msg);
        return;
    }

    gwData = (GatewayData *)iface->data;

    // Read the (address, port) pair for this packet
    retVal = ReadPacketAddressAndPort(
                    (Int8 *)msg->packet,
                    &natKey.srcAddress.interfaceAddr.ipv4,
                    &natKey.srcPort,
                    &natKey.destAddress.interfaceAddr.ipv4,
                    &natKey.destPort,
                    PACKET_FORMAT_HOST);
    
    if (!retVal) return;

    natPort = GatewayNatGetPortNumber(gwData, &natKey);
    if (natPort <= 0)
    {
        printf("Cannot locate NAT key\n");
        return;
    }

    UpdatePacketAddressAndPort((Int8 *)msg->packet,
            gwData->defaultInterfaceAddress,
            natPort,
            0, /* do not change this field */
            0, /* do not change this field */ 
            PACKET_FORMAT_HOST);

    // Convert the packet form host format to network format
    retVal = FormatPacketHeaders((Int8 *)msg->packet, PACKET_FORMAT_HOST);

    if (!retVal)
    {
        printf("Cannot convert this packet from host format to network "
            "format\n");
        MESSAGE_Free(node, msg);
        return;
    }

    GatewayInterfaceWritePacket(gwData, 
            (UInt8 *)MESSAGE_ReturnPacket(msg),
            MESSAGE_ReturnPacketSize(msg));
    MESSAGE_Free(node, msg);
}

