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
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#endif

#include "api.h"
#include "external.h"
#include "partition.h"
#include "mac.h"
#include "phy.h"
#include "phy_802_11.h"
#include "mac_dot11.h"
#include "transport.h"
#include "transport_udp.h"
#include "transport_tcp.h"

#include "socketlayer.h"
#include "socketlayer_api.h"

#include "ControlMessages.h"
#include "qualnet_upa.h"
#include "upa_common.h"

//#define DEBUG

extern char upaGlobalData[UPA_DEV_MTU];

void UPA_HandleProcNetDev(
    Node *node,
    int qualnet_fd)
{
#if 0
    struct upa_hdr *uhdr;
    int thisInterface, numInterfaces;

    uhdr = (struct upa_hdr *)&upaGlobalData[0];
    SLDevInfo *dev = (SLDevInfo *)&upaGlobalData[UPA_HDR_SIZE];

    numInterfaces = node->numberInterfaces + 1;
    uhdr->address = numInterfaces;
    uhdr->port = 0;

    // First interface is lo. At this point all dev stats are 0
    memset(dev, 0, sizeof(SLDevInfo));
    sprintf(dev->ifname, "lo");

    for (thisInterface=1; thisInterface < numInterfaces; thisInterface++)
    {
        dev = (SLDevInfo *)&upaGlobalData[UPA_HDR_SIZE + 
            thisInterface * sizeof(SLDevInfo)];

        memset(dev, 0, sizeof(SLDevInfo));
        sprintf(dev->ifname, "qln%d", thisInterface - 1);

        switch(node->phyData[thisInterface - 1]->phyModel)
        {
            case PHY802_11a:
            case PHY802_11b:
            {
                PhyData802_11 *phy802_11 = (PhyData802_11 *)node->phyData[thisInterface - 1]->phyVar;
                dev->rx_errors = phy802_11->stats.totalSignalsWithErrors;
                break;
            }
            default:
                ERROR_ReportError("PHY Model node suported\n");
        }

        switch(node->macData[thisInterface - 1]->macProtocol)
        {
            case MAC_PROTOCOL_DOT11:
            {
                MacDataDot11 *dot11 = 
                    (MacDataDot11 *)node->macData[thisInterface - 1]->macVar;

                // Stats for DCF
                dev->tx_packets = dot11->unicastPacketsSentDcf + dot11->broadcastPacketsSentDcf;
                dev->rx_packets = dot11->unicastPacketsGotDcf + dot11->broadcastPacketsGotDcf;
                dev->tx_collisions = dot11->retxDueToCtsDcf + dot11->retxDueToAckDcf + dot11->retxAbortedRtsDcf;
                dev->tx_drops = dot11->pktsDroppedDcf;

                break;
            }
            default:
            {
                ERROR_ReportError("MAC protocol not supported by UPA\n");
            }
        }
    }

    UPA_SendPacket(node, 
            qualnet_fd, 
            upaGlobalData, 
            UPA_HDR_SIZE + numInterfaces * sizeof(SLDevInfo), 
            TRUE);
#endif
}


void UPA_HandleProcNetRoute(
    Node *node,
    int qualnet_fd)
{
#if 0
    struct upa_hdr *uhdr;
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->forwardTable;
    SLRouteInfo *info = (SLRouteInfo *)&upaGlobalData[UPA_HDR_SIZE];
    int route, rtEntryInUPAPacket, routeStart;

    uhdr = (struct upa_hdr *)&upaGlobalData[0];

    route = 0;
    rtEntryInUPAPacket = UPA_MTU / sizeof(SLRouteInfo);

    if (rt->size == 0)
    {
        uhdr->address = 0;
        uhdr->port = 0;
        UPA_SendPacket(node, qualnet_fd, upaGlobalData, UPA_HDR_SIZE, TRUE);
        return;
    }


    while (route < rt->size)
    {
        routeStart = route;
        uhdr = (struct upa_hdr *)&upaGlobalData[0];

        uhdr->address = (rt->size - route) > rtEntryInUPAPacket ?
            rtEntryInUPAPacket : (rt->size - route);
        uhdr->port = (rt->size - route) > rtEntryInUPAPacket ? 1 : 0;

        for (;route < routeStart + uhdr->address; route++)
        {
            info = (SLRouteInfo *)&upaGlobalData[UPA_HDR_SIZE + (route - routeStart) * sizeof(SLRouteInfo)];
            memset(info, 0, sizeof(SLRouteInfo));

            sprintf(info->ifname, "qln%d", rt->row[route].interfaceIndex);
            info->dest.sin_family = info->gateway.sin_family = info->netmask.sin_family = AF_INET;
            info->dest.sin_addr.s_addr = htonl(rt->row[route].destAddress);
            info->gateway.sin_addr.s_addr = htonl(rt->row[route].nextHopAddress);
            info->netmask.sin_addr.s_addr = htonl(rt->row[route].destAddressMask);
            info->flags = 1;
            info->metric = rt->row[route].cost;
        }

        UPA_SendPacket(node, qualnet_fd, upaGlobalData, uhdr->address * sizeof(SLRouteInfo) + UPA_HDR_SIZE, TRUE);
    }
#endif
}

void UPA_HandleProcNetSnmp(
    Node *node,
    int qualnet_fd)
{
#if 0
    struct upa_hdr *uhdr;
    SLSnmpInfo *info = (SLSnmpInfo *)&upaGlobalData[UPA_HDR_SIZE];
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;

    uhdr = (struct upa_hdr *)&upaGlobalData[0];

    // IP Fields:  Forwarding DefaultTTL InReceives InHdrErrors InAddrErrors ForwDatagrams 
    //        InUnknownProtos InDiscards InDelivers OutRequests OutDiscards OutNoRoutes 
    //        ReasmTimeout ReasmReqds ReasmOKs ReasmFails FragOKs FragFails FragCreates
    info->ip[0] = ip->ipForwardingEnabled ? 2 : 1;     /* Forwarding: 1=yes, 2=no */
    info->ip[1] = IPDEFTTL;                         /* DefaultTTL */
    info->ip[2] = ip->stats.ipInReceives;             /* InReceives */
    info->ip[3] = ip->stats.ipInHdrErrors;             /* InHdrErrors*/
    info->ip[4] = ip->stats.ipInAddrErrors;         /* InAddrErrors*/
    info->ip[5] = ip->stats.ipInForwardDatagrams;     /* ForwDatagrams*/
    info->ip[6] = 0;                                 /* InUnknownProtos*/ // XXX
    info->ip[7] = ip->stats.ipInDiscards;             /* InDiscards*/
    info->ip[8] = ip->stats.ipInDelivers;             /* InDelivers */
    info->ip[9] = ip->stats.ipOutRequests;             /* OutRequests*/
    info->ip[10] = ip->stats.ipOutDiscards;         /* OutDiscards*/
    info->ip[11] = ip->stats.ipOutNoRoutes;         /* OutNoRoutes*/
    info->ip[12] = 0;                                 /* ReasmTimeout*/ // XXX
    info->ip[13] = ip->stats.ipReasmReqds;             /* ReasmReqds */
    info->ip[14] = ip->stats.ipReasmOKs;             /* ReasmOKs */
    info->ip[15] = ip->stats.ipReasmFails;             /* ReasmFails */
    info->ip[16] = ip->stats.ipFragOKs;             /* FragOKs*/
    info->ip[17] = 0;                                 /* FragFils*/ // XXX
    info->ip[18] = ip->stats.ipFragsCreated;         /* FragsCreated*/
    

    // ICMP Fields: InMsgs InErrors InDestUnreachs InTimeExcds InParmProbs InSrcQuenchs 
    //         InRedirects InEchos InEchoReps InTimestamps InTimestampReps InAddrMasks 
    //        InAddrMaskReps OutMsgs OutErrors OutDestUnreachs OutTimeExcds OutParmProbs 
    //        OutSrcQuenchs OutRedirects OutEchos OutEchoReps OutTimestamps OutTimestampReps 
    //        OutAddrMasks OutAddrMaskReps
    

    // TCP Fields: [0] RtoAlgorithm, [1] RtoMin, [2] RtoMax, [3] MaxConn, [4] ActiveOpens 
    // [5] PassiveOpens, [6] AttemptFails, [7] EstabResets, [8] CurrEstab, [9] InSegs, [10] OutSegs 
    // [11] RetransSegs, [12] InErrs, [13] OutRsts
    info->tcp[0] = 0; /* RtoAlgorithm: 0: none, 1: constant, 3: mil-std-1778, 4: van jacobson, 5: rfc2988*/
    info->tcp[1] = 

    // UDP Fields: [0] InDatagrams, [1] NoPorts, [2] InErrors, [3] OutDatagrams
    DInt32 packetsReceivedAtTransport =
            node->transportData.udp->newStats->GetDataSegmentsReceived(STAT_Unicast).GetValue(node->getNodeTime()) +
            node->transportData.udp->newStats->GetDataSegmentsReceived(STAT_Broadcast).GetValue(node->getNodeTime()) +
            node->transportData.udp->newStats->GetDataSegmentsReceived(STAT_Multicast).GetValue(node->getNodeTime());

    DInt32 packetsSentFromTransport =
            node->transportData.udp->newStats->GetDataSegmentsSent(STAT_Unicast).GetValue(node->getNodeTime()) +
            node->transportData.udp->newStats->GetDataSegmentsSent(STAT_Broadcast).GetValue(node->getNodeTime()) +
            node->transportData.udp->newStats->GetDataSegmentsSent(STAT_Multicast).GetValue(node->getNodeTime());

    info->udp[0] = packetsReceivedAtTransport;     /* InDatagrams */
    info->udp[1] = 0; // XXX                                            /* NoPorts */
    info->udp[2] = 0; // XXX                                            /* InErrors */
    info->udp[3] = packetsSentFromTransport;    /* OutDatagrams */

#endif
}

void UPA_HandleProcNet(
    Node *node,
    int qualnet_fd,
    int proc_net_name)
{
#if 0
    switch(proc_net_name)
    {
        case UPA_PROC_NET_DEV:
        {
            UPA_HandleProcNetDev(node, qualnet_fd);
            break;
        }
        case UPA_PROC_NET_ROUTE:
        {
            UPA_HandleProcNetRoute(node, qualnet_fd);
            break;
        }
        case UPA_PROC_NET_SNMP:
        {
            UPA_HandleProcNetSnmp(node, qualnet_fd);
            break;
        }
        default:
        {
            assert(0);
        }
    }
#endif
}

