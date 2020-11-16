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
#include "external.h"
#include "external_socket.h"
#include "ipnetworkemulator.h"
//MTree Fix start
#include "network_ip.h"
//MTree Fix end
#include "ospf_interface.h"
#include "routing_ospfv2.h"
#include "routing_qospf.h"
#include "auto-ipnetworkemulator.h"

// /**
// API       :: ComputeOspfChecksum
// PURPOSE   :: Computes the checksum for an entire OSPF packet
// PARAMETERS::
// + packet : UInt8* : The packet to compute the checksum for.  Assumes
//                     authentication data field and checksum field are 0
// + packetLength : int : The length of the packet
// RETURN :: UInt16 : The checksum
// **/
static UInt16 ComputeOspfChecksum(
    UInt8* packet,
    int packetLength)
{
    BOOL odd;
    UInt16* paddedPacket;
    int sum;
    int i;
    
    // If the packet is an odd length, pad it with a zero
    odd = packetLength & 0x1;
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
    sum = 0;
    for (i = 0; i < packetLength / 2; i++)
    {
        sum += paddedPacket[i];
    }

    // Carry the 1's
    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Free memory of padded packet
    if (odd)
    {
        MEM_free(paddedPacket);
    }

    // Return the checksum
    return ~((UInt16) sum);
}

// /**
// API       :: OspfSwapHello
// PURPOSE   :: Swap bytes for the hello packet
// PARAMETERS::
// + ospfCommon : Ospfv2CommonHeader* : The start of the common header
// **/
static void OspfSwapHello(Ospfv2CommonHeader* ospfCommon)
{
    Ospfv2HelloPacket* hello = (Ospfv2HelloPacket*) ospfCommon;
    int numNeighbors = (hello->commonHeader.packetLength
          - sizeof(Ospfv2HelloPacket)) / sizeof(NodeAddress);
    NodeAddress* neighbor = (NodeAddress*) (hello + 1);
    int i;

    // Byte-swap hello header
    EXTERNAL_ntoh(&hello->networkMask, sizeof(hello->networkMask));
    EXTERNAL_ntoh(&hello->helloInterval, sizeof(hello->helloInterval));
    EXTERNAL_ntoh(
        &hello->routerDeadInterval,
        sizeof(hello->routerDeadInterval));
    EXTERNAL_ntoh(&hello->designatedRouter, sizeof(hello->designatedRouter));
    EXTERNAL_ntoh(
        &hello->backupDesignatedRouter,
        sizeof(hello->backupDesignatedRouter));

    for (i = 0; i < numNeighbors; i++)
    {
        EXTERNAL_ntoh(neighbor, sizeof(NodeAddress));
        neighbor++;
    }
}

// /**
// API       :: OspfSwapDatabaseDescription
// PURPOSE   :: Swap bytes for the database description packet
// PARAMETERS::
// + ospfCommon : Ospfv2CommonHeader* : The start of the common header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if outgoing
// **/
static void OspfSwapDatabaseDescription(
    Ospfv2CommonHeader* ospfCommon,
    BOOL in)
{
    Ospfv2DatabaseDescriptionPacket* db =
        (Ospfv2DatabaseDescriptionPacket*) ospfCommon;
    int num = (db->commonHeader.packetLength
               - sizeof(Ospfv2DatabaseDescriptionPacket)) /
                   sizeof(Ospfv2LinkStateHeader);
    Ospfv2LinkStateHeader* lsh = (Ospfv2LinkStateHeader*) (db + 1);
    int i;

    EXTERNAL_ntoh(&db->interfaceMtu, sizeof(db->interfaceMtu));
    EXTERNAL_ntoh(&db->ddSequenceNumber, sizeof(db->ddSequenceNumber));

    for (i = 0; i < num; i++)
    {
        EXTERNAL_ntoh(&lsh->linkStateAge, sizeof(lsh->linkStateAge));
        EXTERNAL_ntoh(&lsh->linkStateID, sizeof(lsh->linkStateID));
        EXTERNAL_ntoh(
            &lsh->advertisingRouter,
            sizeof(lsh->advertisingRouter));
        EXTERNAL_ntoh(
            &lsh->linkStateSequenceNumber,
            sizeof(lsh->linkStateSequenceNumber));
        EXTERNAL_ntoh(&lsh->length, sizeof(lsh->length));

        // Swap checksum bytes.  Note that for outgoing packets the checksum
        // is calculated internally by OSPF.
        EXTERNAL_ntoh(
            &lsh->linkStateCheckSum,
            sizeof(lsh->linkStateCheckSum));

        lsh++;

    }
}

// /**
// API       :: OspfSwapLinkStateRequest
// PURPOSE   :: Swap bytes for the link state request packet
// PARAMETERS::
// + ospfCommon : Ospfv2CommonHeader* : The start of the common header
// **/
static void OspfSwapLinkStateRequestBytes(Ospfv2CommonHeader* ospfCommon)
{
    Ospfv2LinkStateRequestPacket* request =
        (Ospfv2LinkStateRequestPacket*) ospfCommon;
    Ospfv2LSRequestInfo* info = (Ospfv2LSRequestInfo*) (request + 1);
    int i;

    int numLSReqObject = (ospfCommon->packetLength
                 - sizeof(Ospfv2LinkStateRequestPacket))
                     / sizeof(Ospfv2LSRequestInfo);

    for (i = 0; i < numLSReqObject; i++)
    {
        EXTERNAL_ntoh(&info->linkStateType, sizeof(info->linkStateType));
        EXTERNAL_ntoh(&info->linkStateID, sizeof(info->linkStateID));
        EXTERNAL_ntoh(
            &info->advertisingRouter,
            sizeof(info->advertisingRouter));
        info++;
    }
}

// /**
// API       :: OspfSwapLinkStateBytes
// PURPOSE   :: Swap bytes for a link state header and its contents.
// PARAMETERS::
// + lsh : Ospfv2LinkStateHeader* : he start of the link state header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// + computeChecksum : BOOL : TRUE if the checksum should be computed.  Only
//                            used for outgoing packets.
// RETURN :: Ospfv2LinkStateHeader* : A pointer to the next link state
//     header (1 byte after the end of this link state header)
// **/
Ospfv2LinkStateHeader* OspfSwapLinkStateBytes(
    Ospfv2LinkStateHeader* lsh,
    BOOL in,
    BOOL computeChecksum)
{
    int i;
    int j;
    Ospfv2LinkStateHeader* newLsh;
    short int lsLength;

    EXTERNAL_ntoh(&lsh->linkStateAge, sizeof(lsh->linkStateAge));
    EXTERNAL_ntoh(&lsh->linkStateID, sizeof(lsh->linkStateID));
    EXTERNAL_ntoh(
        &lsh->advertisingRouter,
        sizeof(lsh->advertisingRouter));
    EXTERNAL_ntoh(
        &lsh->linkStateSequenceNumber,
        sizeof(lsh->linkStateSequenceNumber));

    if (in)
    {
        EXTERNAL_ntoh(&lsh->length, sizeof(lsh->length));
        lsLength = lsh->length;
    }
    else
    {
        lsLength = lsh->length;
        EXTERNAL_ntoh(&lsh->length, sizeof(lsh->length));
    }

    if (in)
    {
        EXTERNAL_ntoh(
            &lsh->linkStateCheckSum,
            sizeof(lsh->linkStateCheckSum));
    }

    switch (lsh->linkStateType)
    {
        case OSPFv2_ROUTER:
        {
            Ospfv2RouterLSA* router = (Ospfv2RouterLSA*) lsh;
            Ospfv2LinkInfo* links = (Ospfv2LinkInfo*) (router + 1);
            QospfPerLinkQoSMetricInfo* qos;

            // If this is an incoming packet then swap numLinks
            if (in)
            {
                EXTERNAL_ntoh(
                    &router->numLinks,
                    sizeof(router->numLinks));
            }

            for (i = 0; i < router->numLinks; i++)
            {
                // NOTE: only works for 1 metric!
                EXTERNAL_ntoh(&links->linkID, sizeof(links->linkID));
                EXTERNAL_ntoh(&links->linkData, sizeof(links->linkData));
                EXTERNAL_ntoh(&links->metric, sizeof(links->metric));

                qos = (QospfPerLinkQoSMetricInfo*)(links + 1);
                for (j = 0; j < links->numTOS; j++)
                {
                    // UNTESTED!!!
                    EXTERNAL_ntoh(
                        &qos->interfaceIndex + 1,
                        sizeof(UInt16));
                    qos++;
                }
                links = (Ospfv2LinkInfo*) qos;
            }

            // If this is not an incoming packet then swap numLinks
            if (!in)
            {
                EXTERNAL_ntoh(
                    &router->numLinks,
                    sizeof(router->numLinks));
            }

            newLsh = (Ospfv2LinkStateHeader*) links;
            break;
        }

        case OSPFv2_NETWORK:
        {
            Ospfv2NetworkLSA* network = (Ospfv2NetworkLSA*) lsh;
            int numAddrs;

            // Compute the number of addresses
            if (in)
            {
                numAddrs = (network->LSHeader.length
                    - sizeof(Ospfv2NetworkLSA))
                    / sizeof(NodeAddress);
            }
            else
            {
                numAddrs = (ntohs(network->LSHeader.length)
                    - sizeof(Ospfv2NetworkLSA))
                    / sizeof(NodeAddress);
            }
            NodeAddress* addr = ((NodeAddress*) (network + 1));

            for (i = 0; i < numAddrs; i++)
            {
                EXTERNAL_ntoh(addr, sizeof(NodeAddress));
                addr++;
            }


            newLsh = (Ospfv2LinkStateHeader*) addr;
            break;
        }

        case OSPFv2_NETWORK_SUMMARY:
        case OSPFv2_ROUTER_SUMMARY:
        {
            Ospfv2SummaryLSA* summary = (Ospfv2SummaryLSA*) lsh;
            NodeAddress* networkMask;
            UInt32* ospfMetric;
            networkMask = (NodeAddress*) (summary + 1);

            // swap netmask, metric
            EXTERNAL_ntoh(networkMask, sizeof(NodeAddress));
            ospfMetric = (UInt32 *)(networkMask + 1);
            EXTERNAL_ntoh(ospfMetric, sizeof(UInt32));

            newLsh = (Ospfv2LinkStateHeader*) (((char *)networkMask) +
                        (lsLength - sizeof(Ospfv2SummaryLSA)));
            break;
        }

        case OSPFv2_ROUTER_AS_EXTERNAL:
        {
            Ospfv2ASexternalLSA* external = (Ospfv2ASexternalLSA*) lsh;
            Ospfv2ExternalLinkInfo* info =
                (Ospfv2ExternalLinkInfo*) (external + 1);

            EXTERNAL_ntoh(&info->networkMask, sizeof(info->networkMask));
            EXTERNAL_ntoh(&info->ospfMetric, sizeof(UInt32));
            EXTERNAL_ntoh(
                &info->forwardingAddress,
                sizeof(info->forwardingAddress));
            EXTERNAL_ntoh(
                &info->externalRouterTag,
                sizeof(info->externalRouterTag));


            newLsh = (Ospfv2LinkStateHeader*) (info + 1);
            break;
        }

        case OSPFv2_GROUP_MEMBERSHIP:
            // Unsupported.  Report a warning and return the lsh.  This will
            // result in an incorrect checksum but won't crash QualNet.
            ERROR_ReportWarning("OSPF group membership not supported");
            return lsh;
            break;

        default:
            // Unsupported.  Report a warning and return the lsh.  This will
            // result in an incorrect checksum but won't crash QualNet.
            ERROR_ReportWarning("Unknown LSA type");
            return lsh;
            break;

    }

    // If this is an outgoing packet then create the checksum
    if (!in)
    {
        EXTERNAL_ntoh(
            &lsh->linkStateCheckSum,
            sizeof(lsh->linkStateCheckSum));
    }

    return newLsh;
}

// /**
// API       :: OspfSwapLinkStateUpdateBytes
// PURPOSE   :: Swap bytes for the link state update packet
// PARAMETERS::
// + ospfCommon : Ospfv2CommonHeader* : The start of the common header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if outgoing
// **/
static void OspfSwapLinkStateUpdateBytes(
    Ospfv2CommonHeader* ospfCommon,
    BOOL in)
{
    Ospfv2LinkStateUpdatePacket* update =
        (Ospfv2LinkStateUpdatePacket*) ospfCommon;
    Ospfv2LinkStateHeader* lsh = (Ospfv2LinkStateHeader*) (update + 1);
    int i;
    int numLSA;

    // Compute the number of LSAs and swap bytes
    if (in)
    {
        EXTERNAL_ntoh(&update->numLSA, sizeof(update->numLSA));
        numLSA = update->numLSA;
    }
    else
    {
        numLSA = update->numLSA;
        EXTERNAL_ntoh(&update->numLSA, sizeof(update->numLSA));
    }

    for (i = 0; i < numLSA; i++)
    {
        // Swap bytes for this link state advertisement.  Pass in as TRUE
        // to avoid calculating the checksum.  The checksum is computed by
        // ospf.
        lsh = OspfSwapLinkStateBytes(
            lsh,
            in,
            FALSE);
    }
}

// /**
// API       :: OspfSwapLinkStateAckBytes
// PURPOSE   :: Swap bytes for the link state ack packet
// PARAMETERS::
// + ospfCommon : Ospfv2CommonHeader* : The start of the common header
// + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if outgoing
// **/
static void OspfSwapLinkStateAckBytes(
    Ospfv2CommonHeader* ospfCommon,
    BOOL in)
{
    Ospfv2LinkStateAckPacket* ack = (Ospfv2LinkStateAckPacket*) ospfCommon;
    Ospfv2LinkStateHeader* lsh = (Ospfv2LinkStateHeader*) (ack + 1);
    int num = (ack->commonHeader.packetLength
        - sizeof(Ospfv2LinkStateAckPacket))
        / sizeof(Ospfv2LinkStateHeader);
    int i;

    for (i = 0; i < num; i++)
    {
        EXTERNAL_ntoh(&lsh->linkStateAge, sizeof(lsh->linkStateAge));
        EXTERNAL_ntoh(&lsh->linkStateID, sizeof(lsh->linkStateID));
        EXTERNAL_ntoh(
            &lsh->advertisingRouter,
            sizeof(lsh->advertisingRouter));
        EXTERNAL_ntoh(
            &lsh->linkStateSequenceNumber,
            sizeof(lsh->linkStateSequenceNumber));
        EXTERNAL_ntoh(&lsh->length, sizeof(lsh->length));

        if (in)
        {
            EXTERNAL_ntoh(
                &lsh->linkStateCheckSum,
                sizeof(lsh->linkStateCheckSum));
        }
        if (!in)
        {
            EXTERNAL_ntoh(
                &lsh->linkStateCheckSum,
                sizeof(lsh->linkStateCheckSum));
        }

        lsh++;
    }
}

void InitializeOspfInterface(EXTERNAL_Interface* iface)
{
    IPNEData* data;
    Node* node1;
    int i;
    NodeAddress qualnetNodeId;

    data = (IPNEData*) iface->data;

    // Create OSPF socket.  This is necessary to make the OS think it
    // can receive OSPF packets, so it won't send ICMP unsupported protocol
    // packets.
    data->ospfSocket = socket(AF_INET, SOCK_RAW, 0x59);
    ERROR_Assert(
        data->ospfSocket != -1,
        "IPNE error opening OSPF socket");

    // Add the OSPF nodes in the list  to the OSPF multicast groups
    for (i = 0; i < data->numOspfNodes; i++)
    {
        qualnetNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                            iface->partition->firstNode,
                            data->ospfNodeAddress[i]);

        node1 = MAPPING_GetNodePtrFromHash(
                iface->partition->nodeIdHash,
                qualnetNodeId);

        ERROR_Assert(
                    node1 != NULL,
                    "Invalid external OSPF node");

        NetworkIpAddToMulticastGroupList(node1, OSPFv2_ALL_SPF_ROUTERS);

        NetworkIpAddToMulticastGroupList(node1, OSPFv2_ALL_D_ROUTERS);
    }
}

void OspfSwapBytes(
    UInt8* ospfHeader,
    BOOL in)
{
    Ospfv2CommonHeader* ospfCommon;
    UInt8* next = ospfHeader;
    
    // Extract OSPF common header
    ospfCommon = (Ospfv2CommonHeader*) next;
    next += sizeof(Ospfv2CommonHeader);

    // Byte-swap common header.  This is input from external network so put
    // it in host order first.
    if (in)
    {
        EXTERNAL_ntoh(
            &ospfCommon->packetLength,
            sizeof(ospfCommon->packetLength));
        EXTERNAL_ntoh(
            &ospfCommon->routerID,
            sizeof(ospfCommon->routerID));
        EXTERNAL_ntoh(
            &ospfCommon->areaID,
            sizeof(ospfCommon->areaID));
        EXTERNAL_ntoh(
            &ospfCommon->checkSum,
            sizeof(ospfCommon->checkSum));
        EXTERNAL_ntoh(
            &ospfCommon->authenticationType,
            sizeof(ospfCommon->authenticationType));
        EXTERNAL_ntoh(
            &ospfCommon->authenticationData,
            sizeof(ospfCommon->authenticationData));
    }

    switch (ospfCommon->packetType)
    {
        case OSPFv2_HELLO:
            OspfSwapHello(ospfCommon);
            break;

        case OSPFv2_DATABASE_DESCRIPTION:
            OspfSwapDatabaseDescription(ospfCommon, in);
            break;

        case OSPFv2_LINK_STATE_REQUEST:
            OspfSwapLinkStateRequestBytes(ospfCommon);
            break;

        case OSPFv2_LINK_STATE_UPDATE:
            OspfSwapLinkStateUpdateBytes(ospfCommon, in);
            break;

        case OSPFv2_LINK_STATE_ACK:
            OspfSwapLinkStateAckBytes(ospfCommon, in);
            break;

        default:
            ERROR_ReportWarning("Unknown OSPF packet type");
            return;
            break;
    }

    // Byte-swap common header.  This is output to network, so put it in 
    // network order last.
    if (!in)
    {
        EXTERNAL_ntoh(
            &ospfCommon->packetLength,
            sizeof(ospfCommon->packetLength));
        EXTERNAL_ntoh(
            &ospfCommon->routerID,
            sizeof(ospfCommon->routerID));
        EXTERNAL_ntoh(&ospfCommon->areaID, sizeof(ospfCommon->areaID));
        ospfCommon->checkSum = 0;
        EXTERNAL_ntoh(
            &ospfCommon->authenticationType,
            sizeof(ospfCommon->authenticationType));
        EXTERNAL_ntoh(
             &ospfCommon->authenticationData,
             sizeof(ospfCommon->authenticationData));

        // Temporarily zero out authentication data for computing the
        // checksum
        char tempAuth[8];
        memcpy(tempAuth, ospfCommon->authenticationData, 8);
        memset(ospfCommon->authenticationData, 0, 8);
        memset(&ospfCommon->checkSum, 0, sizeof(ospfCommon->checkSum));

        ospfCommon->checkSum = ComputeOspfChecksum(
            ospfHeader,
            ntohs(ospfCommon->packetLength));

        // Re-set the authentication data
        memcpy(ospfCommon->authenticationData, tempAuth, 8);
    }

}

UInt16 CalculateLinkStateChecksum(
    Node* node,
    Ospfv2LinkStateHeader* lsh)
{
    static BOOL firstTime = TRUE;
    static BOOL computeChecksum = FALSE;

    // If this is the first time check if we need to compute the checksum
    if (firstTime)
    {
        EXTERNAL_Interface *ipne = NULL;
        //IPNEData *ipneData = NULL;
        AutoIPNEData *autoipneData = NULL;
        // Get IPNE external interface
        ipne = EXTERNAL_GetInterfaceByName(
            &node->partitionData->interfaceList,
            "IPNE");
        if (ipne == NULL)
        {
            // If not using IPNE, don't compute checksum
            computeChecksum = FALSE;
        }
        else
        {
            // If using IPNE, compute checksum if OSPF is enabled
            autoipneData = (AutoIPNEData*) ipne->data;
            firstTime = FALSE;
            computeChecksum = autoipneData->ospfEnabled;
        }

        firstTime = FALSE;
    }

    // Compute checksum if IPNE OSPF interface is enabled
    if (computeChecksum)
    {
        // First swap the bytes as if the packet is outgoing.  This will
        // compute the checksum.
        OspfSwapLinkStateBytes(
            lsh,
            FALSE,
            TRUE);

        // Finally swap the bytes back as if the packet is ingoing.  This
        // will leave the checksum intact in host byte order.
        OspfSwapLinkStateBytes(
            lsh,
            TRUE,
            FALSE);

        // Next return the checksum from the lsh header
        return lsh->linkStateCheckSum;
    }
    else
    {
        return 0;
    }
}

void PreProcessIpPacketOspf(
    EXTERNAL_Interface* iface,
    UInt8* packet)
{
    struct libnet_ipv4_hdr* ip;
    UInt8* next;

    // Find the ospf header
    next = packet + IPNE_ETHERNET_HEADER_LENGTH;
    ip = (struct libnet_ipv4_hdr*) next;
    next += ip->ip_hl * 4;

    // Swap bytes from network byte order to host byte order
    OspfSwapBytes(next, TRUE);

    // If this is a multicast packet then turn it into a broadcast packet.
    // Necessary, not sure why
    if (ip->ip_dst.s_addr == 0x050000e0)
    {
        ip->ip_dst.s_addr = 0xffffffff;
    }
}

void ProcessOutgoingIpPacketOspf(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8* packet,
    BOOL* inject)
{
    IPNEData* data;

    data = (IPNEData*) iface->data;

    // Check if myAddress is an OSPF address.  If it is then
    // inject the OSPF packet into the operational network.
    // For this, loop through the OSPF node list
    *inject = FALSE;
    for (int i = 0; i < data->numOspfNodes; i++)
    {
        if (myAddress == data->ospfNodeAddress[i])
        {
            *inject = TRUE;
            break;
        }
    }

    // If we are injecting the OSPF packet into the operational
    // network then swap the bytes
    if (inject)
    {
        OspfSwapBytes(
            packet,
            FALSE);
    }
}

void IgmpSwapBytes(UInt8* igmpHeader, BOOL in)
{
    // IGMP is not supported
}

void HandleIgmpInject(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int size)
{
    // IGMP is not supported
    ERROR_ReportWarning("IGMP not supported");
}
