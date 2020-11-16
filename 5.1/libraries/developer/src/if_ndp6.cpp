//Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
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
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

//
//
// Ported from FreeBSD 4.7
// This file contains NDP (Neighbor Discovery Protocol - RFC 2461) for IPv6
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//  This product includes software developed by the University of
//  California, Berkeley and its contributors.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//

#include "api.h"
#include "if_ndp6.h"
#include "ipv6_route.h"
#include "ip6_icmp.h"
#include "ipv6.h"
#include "network_ip.h"
#include "ip6_output.h"
#include "network_dualip.h"
// IPv6 auto-config
#include "ipv6_auto_config.h"

#ifdef WIRELESS_LIB
#include "routing_dymo.h"
#endif // WIRELESS_LIB

#define DEBUG_IPV6 0

//---------------------------------------------------------------------------
// FUNCTION             : ndp6_NUDprocess
// PURPOSE             :: While processing neighbor unreachability
//                        detection(NUD), neighbor-solicitation is sent to a
//                        neighbor at every RetransTimer interval.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +rn_node             : rn_leaf* rn_node : Pointer to the leaf-node of the
//                                           routing table.
// +destination         : in6_addr* destination  : pkt's destination address
//----------------------------------------------------------------------------------

void ndp6_NUDprocess(Node* node, rn_leaf* rn_node, in6_addr* destination)
{
    IPv6Data* ipv6 = (IPv6Data *)node->networkData.networkVar->ipv6;
    rn_leaf* ln = NULL;
    rn_leaf keyNode;
    in6_addr solicitedNbrAddr;

    if (rn_node->rn_flags == RNF_IGNORE)
    {
        // virtually deleted route
        if (DEBUG_IPV6)
        {
            printf("\nNUD is requested for deleted route");
        }
        return;
    }

    if (rn_node->flags != RT_LOCAL)
    {
        // If it is a Gatewayed route send solicitation to the gateway.
        solicitedNbrAddr = rn_node->gateway;
        keyNode.key = rn_node->gateway;
    }
    else
    {
        solicitedNbrAddr = *destination;
        keyNode.key = *destination;
    }

    // search the keyNode in ndp_cache
    ln = (rn_leaf*)rn_search((void*)&keyNode, ipv6->ndp_cache);

    if (ln
        && node->getNodeTime() > ln->expire
        && ln->ln_state == LLNDP6_REACHABLE)
    {
        // change the state of the route into probing
        ln->ln_state = LLNDP6_PROBING;

        // Now send Neighbor Solicitation.
        ndsol6_output(
            node,
            ln->interfaceIndex,
            NULL,
            &solicitedNbrAddr,
            TRUE);

        if (DEBUG_IPV6)
        {
            char nexthopStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&solicitedNbrAddr, nexthopStr);
            printf("Node %u is sending neighbor-solicitation to %s"
                " for neighbor unreachability detection\n",
                node->nodeId, nexthopStr);
        }
    }
    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : ndp6_resolve
// PURPOSE             :: Resolve an IPv6 address into an ethernet address.
//                        If there is no entry in the ndp table,set one up and
//                        send a NS for the IPv6 address.Hold onto this
//                        buf and resend it once the address is finally
//                        resolved. A return value of 1 indicates that the
//                        packet is sent normally; a 0 return indicates
//                        that the packet has been taken over here, either now
//                        or for later transmission.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +ifp                 : int* ifp : Pointer to interface index
// +rt                  : rtentry* rt :Pointer to route entry structure
// +msg                 : Message* msg : Pointer to the Message Structure
// +dst                 : in6_addr* dst : IPv6 Destination Address
// RETURN               : int: status of resolve
// NOTES                : This function is called from Ipv6SendRawMessage()
//                        and ip6_forward() to resolve the linkLayer address.
//---------------------------------------------------------------------------
int
ndp6_resolve(
    Node* node,
    int incomingInterface,
    int* ifp,
    rtentry* rt,
    Message* msg,
    in6_addr* dst)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IPv6Data *ipv6 = ip->ipv6;

    rn_leaf* ln = NULL;

    MacHWAddress llAddr;
    route* ro = NULL;

    // multicast address is resolved here
    if (IS_MULTIADDR6(*dst))
    {
        route rte;

        COPY_ADDR6(*dst, rte.ro_dst);

        if (Ipv6IsReservedMulticastAddress(node, *dst))
        {
            ip6_output(
                node,
                msg,
                (optionList*)NULL,
                &rte,
                0,
                (ip_moptions*)NULL,
                incomingInterface,
                *ifp);
        }
        else
        {
            RouteThePacketUsingMulticastForwardingTable(
                node,
                msg,
                *ifp,
                NETWORK_IPV6);
        }

        // increment stats for number of IPv6 packets forwarded
        ipv6->ip6_stat.ip6s_forward++;

        return TRUE;
    }
#ifdef WIRELESS_LIB
 // For DYMO
    if (ipv6->isManetGateway){
        Address temp;
        SetIPv6AddressInfo(
            &temp,
            *dst);

        if (DymoIsPrefixMatch(
            &temp,
            &ipv6->manetPrefixAddr,
            ipv6->manetPrefixlength)){
            BOOL packetWasRouted = FALSE;

            ip6_hdr* ipv6Hdr = (ip6_hdr* )MESSAGE_ReturnPacket(msg);

            Dymo6RouterFunction(
                node,
                msg,
                ipv6Hdr->ip6_dst,
                ipv6->broadcastAddr,
                &packetWasRouted);

            if (packetWasRouted){
                return TRUE;
            }
        }
    }// end of if dymo check
#endif // WIRELESS_LIB

    // Check in the routing table first.
    if (DEBUG_IPV6)
    {
        printf("ndp_resolve: Checking Prefix lookup NodeId %u\n",
                node->nodeId);
    }

    // Check in the destination cache.
    ro = destinationLookUp(node, ipv6, dst);

    if (ro)
    {
        // route found and then retreive link address and
        // interface from route entry structure
        llAddr = ro->ro_rt.rt_node->linkLayerAddr;
        *ifp = ro->ro_rt.rt_node->interfaceIndex;

        if (*ifp >= 0)
        {
            // Increase the reachable time.
            ro->ro_rt.rt_expire = node->getNodeTime() + REACHABLE_TIME;

            ip6_output(
                node,
                msg,
                (optionList*)NULL,
                ro,
                0,
                (ip_moptions*)NULL,
                incomingInterface,
                *ifp);

            // increment stats for number of IPv6 packets forwarded
            ipv6->ip6_stat.ip6s_forward++;

            // request for neighbor unreachability detection
            ndp6_NUDprocess(node, ro->ro_rt.rt_node, dst);

            return TRUE;
        }
    }

    // If destination cache is empty then go for next hop determination.
    prefixLookUp(node, dst, &ln);

    // If found then check for gatewayed route.
    if (ln)
    {
        if (ln->interfaceIndex < 0)
        {
            // Get outgoing interface index from the ndp-cache
            rn_leaf keyNode;
            rn_leaf *ndp_cache_entry;

            keyNode.key = ln->gateway;

            // search for the gateway entry in ndp_cache
            ndp_cache_entry = (rn_leaf*)rn_search(
                                            (void*)&keyNode,
                                            ipv6->ndp_cache);
            if (ndp_cache_entry == NULL)
            {
                // ndp-cache lookup fails. So,
                // put the packet in the hold buffer.
                in6_addr nextHopNbrAddr;

                nextHopNbrAddr = ln->gateway;

                if (!Ipv6AddMessageInBuffer(
                        node,
                        msg,
                        &nextHopNbrAddr,
                        *ifp,
                        ndp_cache_entry))
                {
                    MESSAGE_Free(node, msg);
                    return FALSE;
                }
                return FALSE;
            }
            ln->interfaceIndex = ndp_cache_entry->interfaceIndex;
            ln->linkLayerAddr = ndp_cache_entry->linkLayerAddr;
        }
        // If it is a Gatewayed route forward to the gateway.
        if (ln->flags != RT_LOCAL)
        {
            // Get the Router link layer Address.
            if (DEBUG_IPV6)
            {
                printf("ndp_resolve: Gatewayed Route Node %u"
                " linklayer ",node->nodeId);
                MAC_PrintHWAddr(&ln->linkLayerAddr);
                printf("\n");
            }
        }// end of searching gatewayed route.
        else
        {
            // Local route check in the Neighbor cache.
            // Get the actual interface to do the next operation.
            *ifp = ln->interfaceIndex;

            if (DEBUG_IPV6)
            {
                printf("ndp_resolve: Local route NodeId %u\n",
                    node->nodeId);
            }

            BOOL found = search_NDPentry(node, msg, *dst, *ifp, &ln);

            if (!found)
            {
                return found;
            }
        } // end of neighbor cache lookup
    } // end getting information of matched prefix

    // IPv6 auto-config
    bool isDefaultRoute = FALSE;
    // Destination, prefix and neighbor lookup failed.
    // Now try to send using Default route.
    if (ln == NULL)
    {
        in6_addr defaultRoute;

        // For default route set all to zero.
        memset(&defaultRoute, 0, sizeof(in6_addr));

        prefixLookUp(node, &defaultRoute, &ln);
        if (ln == NULL ||
            ln->interfaceIndex < 0)
        {
            ipv6->ip6_stat.ip6s_noroute++;
            MESSAGE_Free(node, msg);
            return FALSE;
        }
        isDefaultRoute = TRUE;
    }

    // got a route and that has to be inserted in the destination cache
    // so that next packet for the same destination will get an entry there
    ro = Route_Malloc();
    if (!ro)
    {
        ERROR_ReportError("Unable to allocate route\n");
    }
    ro->ro_rt.rt_node = ln;
    llAddr = ln->linkLayerAddr;
    *ifp = ln->interfaceIndex;
    ro->prefixLen = 128;

    COPY_ADDR6(*dst, ro->ro_dst);
    rtalloc(node, ro, llAddr);

     // Add the routes but default routes are not added.
    if (isDefaultRoute == FALSE)
    {
        Ipv6AddDestination(node, ro);
    }

    ip6_output(
        node,
        msg,
        (optionList*)NULL,
        ro,
        0,
        (ip_moptions*)NULL,
        incomingInterface,
        *ifp);

    // increment stats for number of IPv6 packets forwarded
    ipv6->ip6_stat.ip6s_forward++;

    // request for neighbor unreachability detection
     ndp6_NUDprocess(node, ro->ro_rt.rt_node, dst);

    // if Default route then free it as it is not added.
     if ((ln->key.s6_addr32[0] == 0) &&
        (ln->key.s6_addr32[1] == 0) &&
        (ln->key.s6_addr32[2] == 0) &&
        (ln->key.s6_addr32[3] == 0))
    {
        FreeRoute(ro);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// FUNCTION             : ndsol6_output
// PURPOSE             :: Send a Neighbor Solicitation packet,
//                        asking who has address on interface.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// +dst                 : in6_addr* dst : IPv6 destination address pointer.
// +target              : in6_addr* target : IPv6 target address pointer.
// RETURN               : None
// NOTES                : Neighbor uses to get link layer address of the
//                        corroesponding ipv6 address.
//---------------------------------------------------------------------------
void ndsol6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target,
    BOOL retry)
{
    Message* msg = NULL;
    Message* retryMsg = NULL;
    Ipv6NSolRetryMessage* nsolRtMsg;
    int packetLength = 0;
    int otherLength = 0;
    ActionData acnData;


    char* payload = NULL;
    char* msgInfo = NULL;

    nd_neighbor_solicit *nsp;
    nd_opt_hdr* lp = NULL;
    ip_moptions* imo = NULL;
    int icmpLen = 0;
    int extraLen = 0;
    int optionLen = 0;
    in6_addr src_addr;
    in6_addr dst_addr;
    MacHWAddress llAddr;

    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;

    if (DEBUG_IPV6)
    {
        printf("Node %u Sending Neighbour Solicitation\n", node->nodeId);
    }
    // IPv6 auto-config
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                          ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    if (((dst == NULL) || IS_MULTIADDR6(*dst)) 
                && interfaceInfo->autoConfigParam.isDadEnable == FALSE)
    {
        imo = (ip_moptions*)MEM_malloc(sizeof(ip_moptions));
        imo->imo_multicast_interface = interfaceId;
        imo->imo_multicast_ttl = ND_DEFAULT_HOPLIM;
        imo->imo_multicast_loop = 0;
    }

    // Neighnor solicitation packet size
    icmpLen = sizeof(nd_neighbor_solicit);

    // If destination is multicast address
    if (imo)
    {

        llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
        extraLen = (llAddr.hwLength + 2) % ND_OPT_LINKADDR_LEN;

        if (extraLen != 0)
        {
            extraLen = ND_OPT_LINKADDR_LEN - extraLen;
        }
        icmpLen += llAddr.hwLength + 2 + extraLen;
        optionLen = (llAddr.hwLength + 2 + extraLen) >> 3;
    }

    // Source IP address
    // Ipv6 auto-config
    // Here assignment of source address to linklocal address takes place 
    // also here if DAD is in progress then src address is assigned to 
    // unspecified address.
    if (interfaceInfo->autoConfigParam.isDadEnable)
    {
        // This is setting the source address to unspecified address
        // all bits set to zero,This is the case when the interface is
        // undergoing DAD during stateless address autoconfiguration.
        CLR_ADDR6(src_addr);
        ipv6->autoConfigParameters.autoConfigStats.numOfNDSolForDadSent++;
    }
    else
    {
        Ipv6GetGlobalAggrAddress(node, interfaceId, &src_addr);
    }

    msg = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Icmp6_NeighSolicit);

    // Add icmpv6 header
    MESSAGE_PacketAlloc(node, msg, icmpLen, TRACE_ICMPV6);

    payload = MESSAGE_ReturnPacket(msg);
    memset(payload, 0, icmpLen);

    // Fill Up Neighbor Solicitation packet
    nsp = (nd_neighbor_solicit*) payload;

    if (imo)
    {
        // if multicast then add neighbor discovery option header
        lp = (nd_opt_hdr *)(nsp + 1);
        lp->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
        lp->nd_opt_len = (unsigned char)optionLen;

        memcpy(lp + 1, llAddr.byte, llAddr.hwLength);
    }

    // IP address of target of the solicitation.
    // MUST NOT be a multicast address
    COPY_ADDR6(*target, nsp->nd_ns_target);

    // ICMP header structure
    nsp->nd_ns_type = ND_NEIGHBOR_SOLICIT;
    // Ipv6 auto-config
    nsp->nd_ns_hdr.icmp6_data32[0] = node->getNodeTime() / MICRO_SECOND;
    interfaceInfo->autoConfigParam.nsTimeStamp = node->getNodeTime() / MICRO_SECOND;
    if (dst)
    {
        // unicast destination address
        COPY_ADDR6(*dst, dst_addr);
    }
    else
    {
        // solicitation multicast address: FF02:0:0:0:0:1:FFXX:XXXX
        // The solicited-node multicast address is formed by taking the
        // low-order 24 bits of the address and appending those bits to the
        // prefix FF02:0:0:0:0:1:FF00::/104
        Ipv6SolicitationMulticastAddress(&dst_addr, target);
     }

    // Trace sending packet for icmpv6
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
          PACKET_OUT, &acnData);

    // Add IPv6 header
    Ipv6AddIpv6Header(node, msg, icmpLen, src_addr, dst_addr,
                  IPTOS_PREC_INTERNETCONTROL,
                  IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);

    if (retry)
    {
        // Extra overhead for retry message if unable to resolved.
        retryMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_IPV6,
                               MSG_NETWORK_Ipv6_RetryNeighSolicit);

        // collect current message and store in the info field of the timer
        // that will avoid of creating this message again when timer expires.
        payload = MESSAGE_ReturnPacket(msg);
        packetLength = MESSAGE_ReturnPacketSize(msg);
        otherLength = 0;
        if (imo)
        {
            otherLength = sizeof(ip_moptions);
        }

        MESSAGE_InfoAlloc(
            node,
            retryMsg,
            sizeof(Ipv6NSolRetryMessage) + (unsigned int)(packetLength + otherLength));

        msgInfo = MESSAGE_ReturnInfo(retryMsg);
        nsolRtMsg = (Ipv6NSolRetryMessage*)msgInfo;
        nsolRtMsg->retryCounter = 1;
        nsolRtMsg->interfaceId = interfaceId;
        nsolRtMsg->packetSize = packetLength;
        nsolRtMsg->otherDataLength = otherLength;

        // copy the target because this will searched before retry.
        COPY_ADDR6(*target, nsolRtMsg->dst);

        msgInfo += sizeof(Ipv6NSolRetryMessage);

        memcpy(msgInfo, payload, packetLength);
        msgInfo += packetLength;

        if (imo)
        {
            memcpy(msgInfo, imo, sizeof(ip_moptions));
        }

        // Send  ICMP Packet.
        icmp6_send(node, msg, 0, imo, interfaceId, IP_ROUTETOIF);

        // now sending the timer
        MESSAGE_Send(node, retryMsg, RETRANS_TIMER);

    }
    else
    {
        // Send  ICMP Packet.
        icmp6_send(node, msg, 0, imo, interfaceId, IP_ROUTETOIF);
    }

    // Update Satatistics, free extra things
    if (imo != NULL)
    {
        MEM_free(imo);
    }
    icmp6->icmp6stat.icp6s_snd_ndsol++;
}


//---------------------------------------------------------------------------
// FUNCTION             : ndadv6_output
// PURPOSE             :: Send a Neighbor Advertisement packet.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// +dst                 : in6_addr* dst : IPv6 destination address pointer.
// +target              : in6_addr* target : IPv6 target address pointer.
// +flags               : int flags: Type of advt.
// RETURN               : None
// NOTES                : Targeted Neighbor sends it's link layer address in
//                        response to Neighbor solicitation.
//---------------------------------------------------------------------------
void ndadv6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target,
    int flags)
{
    Message* msg = NULL;
    char* payload = NULL;
    nd_neighbor_advert* nap = NULL;
    nd_opt_hdr* lp = NULL;
    ip_moptions* imo = NULL;
    int icmpLen;
    int extraLen = 0;
    int optionLen = 0;
    BOOL needlla = TRUE;
    in6_addr src_addr;
    MacHWAddress llAddr;

    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;

    if (DEBUG_IPV6)
    {
        printf("Node %u Sending Neighbor Advertisement\n", node->nodeId);
    }


    llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
    extraLen = (llAddr.hwLength + 2) % ND_OPT_LINKADDR_LEN;

    if (extraLen != 0)
    {
        extraLen = ND_OPT_LINKADDR_LEN - extraLen;
    }

    optionLen = (llAddr.hwLength + 2 + extraLen) >> 3;

    // Neighbor advertisement packet size
    icmpLen = sizeof(nd_neighbor_advert) + llAddr.hwLength + 2 + extraLen;

    // Source IP address.
    
    // Ipv6 auto-config
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                           ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    if (interfaceInfo->autoConfigParam.isAutoConfig == TRUE)
    {
        IPv6AutoConfigGetSrcAddrForNbrAdv(
                            node,
                            interfaceId,
                            &src_addr);
    }
    else
    {
        Ipv6GetGlobalAggrAddress(node, interfaceId, &src_addr);
    }

    msg = MESSAGE_Alloc(node,
                        NETWORK_LAYER,
                        NETWORK_PROTOCOL_IPV6,
                        MSG_NETWORK_Icmp6_NeighAdv);

    // Add icmpv6 header
    MESSAGE_PacketAlloc(node, msg, icmpLen, TRACE_ICMPV6);

    payload = MESSAGE_ReturnPacket(msg);
    memset(payload, 0, icmpLen);

    if (IS_MULTIADDR6(*dst))
    {
        imo = (ip_moptions*)MEM_malloc(sizeof(ip_moptions));
        imo->imo_multicast_interface = interfaceId;
        imo->imo_multicast_ttl = ND_DEFAULT_HOPLIM;
        imo->imo_multicast_loop = 0;
    }

    // Fill Neighbor Advertisement packet
    nap = (nd_neighbor_advert *)payload;

    if (needlla)
    {
        lp = (nd_opt_hdr *)(nap + 1);
        lp->nd_opt_type = ND_OPT_TARGET_LINKADDR;
        lp->nd_opt_len = (unsigned char)optionLen;

        memcpy(lp + 1, llAddr.byte, llAddr.hwLength);
    }

    COPY_ADDR6(*target, nap->nd_na_target);
    nap->nd_na_type = ND_NEIGHBOR_ADVERT;
    nap->nd_na_code = 0;
    nap->nd_na_flags_reserved = flags & MASK_ADV;

    // Trace sending packet for icmpv6
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
        PACKET_OUT, &acnData);

    // Add IPv6 header
    Ipv6AddIpv6Header(node, msg, icmpLen, src_addr, *dst,
                  IPTOS_PREC_INTERNETCONTROL,
                  IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);

    // Ipv6 auto-config
    if (flags & FORWARD_ADV)
    {
        ipv6->autoConfigParameters.autoConfigStats.numOfNDAdvForDadSent++;
    }
    // Send using ICMP6.
    icmp6_send(node, msg, 0, imo, interfaceId, flags);

    if (imo != NULL)
    {
        MEM_free(imo);
    }
    icmp6->icmp6stat.icp6s_snd_ndadv++;
}


//---------------------------------------------------------------------------
// FUNCTION             : ndsol6_input
// PURPOSE             :: Receive a Neighbor Solicitation packet.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : int : return status
// NOTES                : Neighbor Solicitation processing functions.
//---------------------------------------------------------------------------
int ndsol6_input(Node* node, Message* msg, int interfaceId)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;
    ActionData acnData;

    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);
    ip6_hdr *ipv6Header = (ip6_hdr*) payload;

    nd_neighbor_solicit* nsp = NULL;
    nd_opt_hdr* xp = NULL;

    int icmpLen = ipv6Header->ip6_plen - sizeof(nd_neighbor_solicit);
    in6_addr infAddr;

    rn_leaf* ln = NULL;

    in6_addr srcaddr;
    in6_addr dstaddr;
    in6_addr tgtaddr;

    unsigned char* lladdr = NULL;
    MacHWAddress linkLayerAddr;

    int extra = sizeof(ip6_hdr) + sizeof(nd_neighbor_solicit);
    int needed = ND_OPT_LINKADDR_LEN;
    int addrconfsol = 0;
    int haslladdr = 0;
    int forwardingFlag = 0;

    nsp = (nd_neighbor_solicit *) (ipv6Header + 1);

    COPY_ADDR6(ipv6Header->ip6_src, srcaddr);
    COPY_ADDR6(ipv6Header->ip6_dst, dstaddr);
    COPY_ADDR6(nsp->nd_ns_target, tgtaddr);

    // Code must be zero checking
    if (nsp->nd_ns_code != 0)
    {
        icmp6->icmp6stat.icp6s_rcv_badndsol++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }
    // If target message is multicast address
    if (IS_MULTIADDR6(tgtaddr))
    {
        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_TARGET_ADDR_MULTICAST;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }
    // IPv6 auto-config
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    if (IS_ANYADDR6(srcaddr))
    {
        // IPv6 auto-config
         if (nsp->nd_ns_hdr.icmp6_data32[0] == 
                interfaceInfo->autoConfigParam.nsTimeStamp)
        {
            // This is a looped back solicitation which has been received so
            // drop such a packet.
            MESSAGE_Free(node, msg);
            return TRUE;
        }
        ipv6->autoConfigParameters.autoConfigStats.numOfNDSolForDadRecv++;
        addrconfsol = 1;
    }
    if (icmpLen < 0)
    {
        icmp6->icmp6stat.icp6s_rcv_badndsol++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }
    if (!addrconfsol)
    {
        // Position pointer to option header
    retry:
        if (icmpLen < needed)
        {
            icmp6->icmp6stat.icp6s_rcv_badndsol++;

            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_OUT,
                             &acnData);
            MESSAGE_Free(node, msg);
            return FALSE;
        }

        if (packetLen >= extra + needed)
        {
            xp = (nd_opt_hdr*) (payload + extra);
        }
        else
        {
            extra = 0;
            xp = (nd_opt_hdr*) payload;
        }

        switch (xp->nd_opt_type)
        {
            case ND_OPT_SOURCE_LINKADDR:
            {
                // If Neighbor Solicitation has source linklayer address.
                if ((xp->nd_opt_len << 3) < ND_OPT_LINKADDR_LEN)
                {
                    icmp6->icmp6stat.icp6s_rcv_badndsol++;

                    //Trace drop
                    acnData.actionType = DROP;
                    acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
                    TRACE_PrintTrace(node,
                                     msg,
                                     TRACE_NETWORK_LAYER,
                                     PACKET_OUT,
                                     &acnData);
                    MESSAGE_Free(node, msg);
                    return FALSE;
                }
                haslladdr = 1;
                lladdr = (unsigned char*)MEM_malloc((xp->nd_opt_len << 3) - 2);
                memcpy(lladdr, xp + 1, (xp->nd_opt_len << 3) - 2);
                // fall down
            }
            default:
            {
                if (xp->nd_opt_len == 0)
                {
                    icmp6->icmp6stat.icp6s_rcv_badndsol++;

                    //Trace drop
                    acnData.actionType = DROP;
                    acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
                    TRACE_PrintTrace(node,
                                     msg,
                                     TRACE_NETWORK_LAYER,
                                     PACKET_OUT,
                                     &acnData);
                    MESSAGE_Free(node, msg);

                    if (lladdr)
                    {
                        MEM_free(lladdr);
                        lladdr = NULL;
                    }
                    return FALSE;
                }

                extra += xp->nd_opt_len << 3;
                icmpLen -= xp->nd_opt_len << 3;
                if (icmpLen > 0)
                {
                    goto retry;
                }
            }
        }//End option switching

        if ((haslladdr == 0) && (addrconfsol == 0) && IS_MULTIADDR6(dstaddr))
        {
            icmp6->icmp6stat.icp6s_rcv_badndsol++;

            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_OUT,
                             &acnData);
            MESSAGE_Free(node, msg);
            return FALSE;
        }
    }
    // Address auto configuration is now supported 
    // version.
    if (addrconfsol)
    {
        if (lladdr)
        {
            MEM_free(lladdr);
            lladdr = NULL;
        }
        if (Ipv6IsForwardingEnabled(ipv6) && in6_isanycast(node, &tgtaddr))
        {
            icmp6->icmp6stat.icp6s_rcv_badndsol++;

            //Trace drop
            acnData.actionType = DROP;
            acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_OUT,
                             &acnData);
            MESSAGE_Free(node, msg);
            return FALSE;
        }

        if (Ipv6IsForwardingEnabled(ipv6))
        {
            forwardingFlag = ROUTER_ADV;
        }
        // Ipv6 auto Config
        if (IPv6AutoConfigProcessNbrSolForDAD(
                node,
                interfaceId,
                nsp,
                linkLayerAddr,
                msg) == TRUE)
        {
            return TRUE;
        }
        // Ipv6 auto-config
        if (addrconfsol)
        {
            IPv6AutoConfigForwardNbrSolForDAD(
                node,
                interfaceId,
                tgtaddr,
                nsp,
                msg);
        }
        else
        {
            MESSAGE_Free(node, msg);
        }
        icmp6->icmp6stat.icp6s_rcv_ndsol++;
        return TRUE;
    }

    if (haslladdr != 0)
    {
        // Add an entry for the source in ndp table.

        linkLayerAddr = Ipv6ConvertStrLinkLayerToMacHWAddress(
            node, interfaceId, lladdr);
        // Check for static route entry first as it is given high priority
        // Update the static routes if any with proper linklayer and
        // interface index.
        CheckStaticRouteEntry(
                        srcaddr,
                        ipv6->prefixHead,
                        ipv6->noOfPrefix,
                        interfaceId,
                        linkLayerAddr);

        // Lookup in the ndp cache if the entry exists.
        ln = ndplookup(node, interfaceId, &srcaddr, 1, linkLayerAddr);

        ln->ln_state = LLNDP6_REACHABLE;
        ln->expire = node->getNodeTime() + NDPT_REACHABLE;
    }

    if (Ipv6IsForwardingEnabled(ipv6))
    {
        forwardingFlag = ROUTER_ADV;
    }

    // Check the target address with interface address if
    // target address matches with interface address then
    // Send the neighbor advertisement.
    Ipv6GetGlobalAggrAddress(node, interfaceId, &infAddr);

    if (SAME_ADDR6(tgtaddr, infAddr))
    {
        ndadv6_output(node, interfaceId, &srcaddr, &tgtaddr,
                forwardingFlag | SOLICITED_ADV | OVERRIDE_ADV);
    }

    // Trace for receive ICMPV6, remove ipv6 header first
    MESSAGE_RemoveHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);

    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);

    icmp6->icmp6stat.icp6s_rcv_ndsol++;
    MESSAGE_Free(node, msg);

    if (lladdr)
    {
        MEM_free(lladdr);
        lladdr = NULL;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION             : ndadv6_input
// PURPOSE             :: Receive a Neighbor Advertisement packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : int: returns status
// NOTES                : Neighbor advertisement processing function.
//---------------------------------------------------------------------------
int ndadv6_input(Node* node, Message* msg, int interfaceId)
{
    Message* msgNdpEvent;
    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);
    ActionData acnData;

    ip6_hdr *ip = (ip6_hdr*) payload;
    nd_neighbor_advert *nap = (nd_neighbor_advert *) (ip + 1);
    nd_opt_hdr *xp;

    int icmpLen = ip->ip6_plen - sizeof(nd_neighbor_advert);
    rn_leaf *ln = NULL;

    in6_addr srcaddr;
    in6_addr dstaddr;
    in6_addr tgtaddr;

    MacHWAddress linkLayerAddr;

    unsigned char* lladdr = NULL;
    int extra = sizeof(ip6_hdr) + sizeof(nd_neighbor_advert);
    int needed = ND_OPT_LINKADDR_LEN;

    int is_router = (nap->nd_na_flags_reserved & ROUTER_ADV) != 0;
    int is_solicited = (nap->nd_na_flags_reserved & SOLICITED_ADV) != 0;
    // Ipv6 auto-config
    NetworkDataIp* ip6 = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                     ip6->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    int is_adv_for_dad = (nap->nd_na_flags_reserved & FORWARD_ADV) != 0;
    if (is_adv_for_dad)
    {
        ip6->ipv6->autoConfigParameters.autoConfigStats.numOfNDAdvForDadRecv++;
    }

    int haslladdr = 0;

    COPY_ADDR6(ip->ip6_src, srcaddr);
    COPY_ADDR6(ip->ip6_dst, dstaddr);
    COPY_ADDR6(nap->nd_na_target, tgtaddr);

    if (nap->nd_na_code != 0)
    {

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_NEIGHBOR_ADVERTISEMENT;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }

    // IPv6 auto-config
    if (IS_MULTIADDR6(dstaddr) && is_solicited && !is_adv_for_dad)
    {
        MESSAGE_Free(node, msg);
        return FALSE;
    }

    if (IS_MULTIADDR6(tgtaddr))
    {

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_NEIGHBOR_ADVERTISEMENT;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }

    // position pointer to option header
retry:
    if (packetLen >= extra + needed)
    {
        xp = (nd_opt_hdr *) (payload + extra);
    }
    else
    {
        extra = 0;
        xp = (nd_opt_hdr*) payload;
    }

    switch (xp->nd_opt_type)
    {
        case ND_OPT_TARGET_LINKADDR:
        {
            if ((xp->nd_opt_len << 3) < ND_OPT_LINKADDR_LEN)
            {
                MESSAGE_Free(node, msg);
                return 0;
            }
            haslladdr = 1;
            lladdr = (unsigned char*)MEM_malloc((xp->nd_opt_len << 3) - 2);
            memcpy(lladdr, xp + 1, (xp->nd_opt_len << 3) - 2);
        }
        default:
        {
            if (xp->nd_opt_len == 0)
            {
                if (lladdr)
                {
                    MEM_free(lladdr);
                    lladdr = NULL;
                }
                MESSAGE_Free(node, msg);
                return 0;
            }
            extra += xp->nd_opt_len << 3;
            icmpLen -= xp->nd_opt_len << 3;
            if (icmpLen != 0)
            {
                goto retry;
            }
        }
    }

    if (haslladdr)
    {
        MacHWAddress llAddr;
        llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
        
        // IPv6 auto-config
        if (interfaceInfo->autoConfigParam.isDadEnable)
        {
            if (IPv6AutoConfigHandleNbrAdvForDAD(
                                    node,
                                    interfaceId,
                                    tgtaddr,
                                    linkLayerAddr,
                                    msg) == TRUE)
            {
                return TRUE;
            }
        }
        if ((!memcmp(lladdr, llAddr.byte, llAddr.hwLength))
            && interfaceInfo->autoConfigParam.addressState == PREFERRED)
        {
            MESSAGE_Free(node, msg);

            if (lladdr)
            {
                MEM_free(lladdr);
                lladdr = NULL;
            }

            return TRUE; // it should be from me, ignore it.
        }
    }


    linkLayerAddr = Ipv6ConvertStrLinkLayerToMacHWAddress(
            node, interfaceId, lladdr);

    if (lladdr)
    {
        MEM_free(lladdr);
        lladdr = NULL;
    }

    // Check for static route entry first as it is given high priority
    // Update the static routes if any with proper linklayer and
    // interface index.

    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    CheckStaticRouteEntry(
                    srcaddr,
                    ipv6->prefixHead,
                    ipv6->noOfPrefix,
                    interfaceId,
                    linkLayerAddr);

    ln = ndplookup(node, interfaceId, &srcaddr, 1, linkLayerAddr);

    if ((ln == NULL))
    {
        MESSAGE_Free(node, msg);
        return TRUE;
    }

    // Following code will be used in LinkFault
    //if (ln->flags && is_router == 0)
    //{
    //  ndp6_rtlost(node, rt, 1);
    //}

    ln->flags = (unsigned char)is_router;

    if ((haslladdr == 0) && (ln->ln_state < LLNDP6_PROBING))
    {
        MESSAGE_Free(node, msg);
        return TRUE;
    }

    ln->ln_state = LLNDP6_REACHABLE;
    ln->expire = node->getNodeTime();
    ln->expire += NDPT_REACHABLE;

    // Now Send Initial Messages.
    msgNdpEvent = MESSAGE_Alloc(node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_Ndadv6);

    MESSAGE_InfoAlloc(node, msgNdpEvent, sizeof(NadvEvent));
        ((NadvEvent*)MESSAGE_ReturnInfo(msgNdpEvent))->ln = ln;

    MESSAGE_Send(node, msgNdpEvent, NDP_DELAY);

    if (DEBUG_IPV6)
    {
        printf("Neighbor Advertising Processing Completed for Node %u\n",
            node->nodeId);
    }

    // IPv6 auto-config, forwarding of advertisement
    if (nap->nd_na_flags_reserved & FORWARD_ADV)
    {
        IPv6AutoConfigForwardNbrAdv(node, interfaceId, tgtaddr, msg);
    }
    else
    {
        // Trace for receive ICMPV6, remove ipv6 header first
         MESSAGE_RemoveHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);

        acnData.actionType = RECV;
        acnData.actionComment = NO_COMMENT;
        TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);


        MESSAGE_Free(node, msg);
    }
    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtsol6_output
// PURPOSE             :: Send a Router Solicitation packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +target              : in6_addr* target : IPv6 target address pointer
// RETURN               : None
// NOTES                : Neighbor Sends Router Solicitation to discover
//                        default routers.
//---------------------------------------------------------------------------
void
rtsol6_output(
    Node* node,
    int interfaceId,
    in6_addr* target)
{
    IPv6Data* ipv6 = (IPv6Data*) node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;

    Message* msg = NULL;
    char* payload;
    nd_router_solicit* rsp = NULL;
    nd_opt_hdr* lp = NULL;

    ip_moptions* imo = NULL;
    int icmpLen = 0;
    int extraLen = 0;
    int optionLen = 0;
    in6_addr src_addr;
    in6_addr dst_addr;

    MacHWAddress llAddr;

    if (DEBUG_IPV6)
    {
        printf("Sending Router Solicitation from Node %u InterfaceId %d\n",
            node->nodeId, interfaceId);
    }

    imo = (ip_moptions*)MEM_malloc(sizeof(ip_moptions));
    imo->imo_multicast_interface = interfaceId;
    imo->imo_multicast_ttl = ND_DEFAULT_HOPLIM;
    imo->imo_multicast_loop = 0;

    // Router solicitation packet size
    icmpLen = sizeof(nd_router_solicit);

    // Option considering source link layer address
    llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
    extraLen = (llAddr.hwLength + 2) % ND_OPT_LINKADDR_LEN;

    if (extraLen != 0)
    {
        extraLen = ND_OPT_LINKADDR_LEN - extraLen;
    }
    icmpLen += llAddr.hwLength + 2 + extraLen;
    optionLen = (llAddr.hwLength + 2 + extraLen) >> 3;

    // Source IP address
    Ipv6GetGlobalAggrAddress(node, interfaceId, &src_addr);

    msg = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Icmp6_RouterSolicit);

    // Add icmpv6 header
    MESSAGE_PacketAlloc(node, msg, icmpLen, TRACE_ICMPV6);

    payload = MESSAGE_ReturnPacket(msg);
    memset(payload, 0, icmpLen);

    // Fill Router Solicitation packet
    rsp = (nd_router_solicit *) payload;

    // Then add router discovery option header
    lp = (nd_opt_hdr *) (rsp + 1);
    lp->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    lp->nd_opt_len = (unsigned char)optionLen;

    memcpy(lp + 1, llAddr.byte, llAddr.hwLength);

    // ICMP header structure
    rsp->nd_rs_type = ND_ROUTER_SOLICIT;


    // The solicitation needs to be sent to all routers multicast address
    // FF02::2
       Ipv6AllRoutersMulticastAddress(&dst_addr);
    // Trace sending packet for icmpv6
     ActionData acnData;
      acnData.actionType = SEND;
      acnData.actionComment = NO_COMMENT;
      TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
          PACKET_OUT, &acnData);


    // Add IPv6 header
    Ipv6AddIpv6Header(node, msg, icmpLen, src_addr, dst_addr,
                  IPTOS_PREC_INTERNETCONTROL,
                  IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);

    // Send ICMPv6 Message.
    icmp6_send(node, msg, 0, imo, interfaceId, 0);
    if (imo != NULL)
    {
        MEM_free(imo);
    }
    icmp6->icmp6stat.icp6s_snd_rtsol++;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtadv6_output
// PURPOSE             :: Send a Router Advertisement packet.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +dst                 : in6_addr* dst : IPv6 Destination Address pointer
// +target              : in6_addr* target : IPv6 target address pointer
// RETURN               : None
// NOTES                : Router sends router advertisement periodically or
//                        in response to router solicitations.
//---------------------------------------------------------------------------
void
rtadv6_output(
    Node* node,
    int interfaceId,
    in6_addr* dst,
    in6_addr* target)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;
    IPv6InterfaceInfo* interfaceInfo = ip->interfaceInfo[interfaceId]->
                                                        ipv6InterfaceInfo;

    Message* msg = NULL;
    char* payload;
    ip_moptions* imo = NULL;
    int icmpLen = 0;
    int extraLen = 0;
    int optionLen = 0;

    MacHWAddress llAddr;

    int interfaceCount = 0;

    nd_router_advert* rap = NULL;
    nd_opt_hdr* lp = NULL;
    nd_opt_mtu* ndopt_mtu = NULL;
    nd_opt_prefix_info* ndopt_pi = NULL;

    in6_addr src_addr;
    in6_addr dst_addr;

    if (DEBUG_IPV6)
    {
        printf("Sending Router Advertisement from NodeId = %u\n",
            node->nodeId);
    }

    if (IS_MULTIADDR6(*dst))
    {
        imo = (ip_moptions*) MEM_malloc(sizeof(ip_moptions));
        imo->imo_multicast_interface = interfaceId;
        imo->imo_multicast_ttl = ND_DEFAULT_HOPLIM;
        imo->imo_multicast_loop = 0;
    }
    // Calculate total length
    icmpLen = sizeof(nd_router_advert);


    llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
    extraLen = (llAddr.hwLength + 2) % ND_OPT_LINKADDR_LEN;

    if (extraLen != 0)
    {
        extraLen = ND_OPT_LINKADDR_LEN - extraLen;
    }
    icmpLen += llAddr.hwLength + 2 + extraLen;
    optionLen = (llAddr.hwLength + 2 + extraLen) >> 3;

    int noOfIpv6Interfaces = 0;
    for (interfaceCount = 0; interfaceCount < node->numberInterfaces;
        interfaceCount++)
    {
        if ((ip->interfaceInfo[interfaceCount]->interfaceType
                                                           == NETWORK_IPV6 ||
              ip->interfaceInfo[interfaceCount]->interfaceType
                                                           == NETWORK_DUAL)
            && ip->interfaceInfo[interfaceCount]->isVirtualInterface == FALSE
            )
        {
            noOfIpv6Interfaces++;
        }
    }
    icmpLen += ((sizeof(nd_opt_prefix_info) * noOfIpv6Interfaces) +
               sizeof(nd_opt_mtu));

    msg = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Icmp6_RouterAdv);

    // Add icmpv6 header
    MESSAGE_PacketAlloc(node, msg, icmpLen, TRACE_ICMPV6);

    payload = MESSAGE_ReturnPacket(msg);
    memset(payload, 0, icmpLen);

    // Fill Router Advertisement packet
    rap = (nd_router_advert *)payload;

    // Construct the packet
    rap->nd_ra_type = ND_ROUTER_ADVERT;

    // cur hop limit
    rap->nd_ra_curhoplimit = CURR_HOP_LIMIT;

    // managed and other configuration assumed as not set
    // router lifetime, 0 for router which is not default

    // router life time is now not considered.

    // reachable and retransmit timer
    rap->nd_ra_reachable = NDPT_REACHABLE / MILLI_SECOND;
    rap->nd_ra_retransmit = NDPT_RETRANS / MILLI_SECOND;

    // now set option, first source link layer address
    lp = (nd_opt_hdr *) (rap + 1);
    lp->nd_opt_type = ND_OPT_SOURCE_LINKADDR;
    lp->nd_opt_len = (unsigned char)optionLen;

    memcpy(lp + 1, llAddr.byte, llAddr.hwLength);



    // Option MTU parameter
    ndopt_mtu = (nd_opt_mtu *)
        ((char*)(lp) + sizeof(nd_opt_hdr) + ETHER_ADDR_LEN);

    ndopt_mtu->nd_opt_mtu_type = ND_OPT_MTU;
    ndopt_mtu->nd_opt_mtu_len = 1;
    ndopt_mtu->nd_opt_mtu_mtu = Ipv6GetMTU(node, interfaceId);

    // Option prefix 1
    ndopt_pi = (nd_opt_prefix_info *) (ndopt_mtu + 1);

    // IPv6 auto-config
    if (interfaceInfo->autoConfigParam.isDelegatedRouter)
    {
        IPv6AutoConfigAttachPrefixesRouterAdv(node, ndopt_pi, interfaceId);
    }
    else
    {
        // Send all onlink prefixes
        for (interfaceCount = 0; interfaceCount < node->numberInterfaces;
            interfaceCount++)
        {
            if (!ip->interfaceInfo[interfaceCount])
            {
              break;
            }

            if ((ip->interfaceInfo[interfaceCount]->interfaceType
                                                        == NETWORK_IPV6 ||
                  ip->interfaceInfo[interfaceCount]->interfaceType
                                                        == NETWORK_DUAL)
                && ip->interfaceInfo[interfaceCount]->isVirtualInterface == FALSE
                )
            {
                in6_addr addr;

                if (!ndopt_pi)
                {
                    ERROR_ReportError("Space Not available\n");
                    break;
                }
                ndopt_pi->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
                ndopt_pi->nd_opt_pi_len = 4;
                ndopt_pi->nd_opt_pi_prefix_len =
                    (unsigned char)Ipv6GetPrefixLength(node, interfaceCount);

                //ndopt_pi->nd_opt_pi_valid_time =
                //  ipv6->routerLifeTime / SECOND;
                //ndopt_pi->nd_opt_pi_preferred_time =
                //  ipv6->routerLifeTime / SECOND;

                Ipv6GetGlobalAggrAddress(
                    node,
                    interfaceCount,
                    &addr);

                Ipv6GetPrefix(
                    &addr,
                    &(ndopt_pi->nd_opt_pi_prefix),
                    ip->interfaceInfo[interfaceCount]
                        ->ipv6InterfaceInfo->prefixLen);

                if (DEBUG_IPV6)
                {
                    char addressstr[80];
                    IO_ConvertIpAddressToString(&addr, addressstr);
                    printf("Router Advertisement %u %s Prefix Added %d\n",
                        node->nodeId, addressstr, interfaceCount);
                }

                ndopt_pi++;
            }

        }// End of entering all onlink prefixes.
    }


    // Source IP address should be link local address.
    // But to maintain proper mapping in QualNet which is used by some
    // MAC Layer protocols Global Address is sent.
    // So link local address in not used
    // Ipv6GetLinkLocalAddress(node, interfaceId, &src_addr);

    Ipv6GetGlobalAggrAddress(
        node,
        interfaceId,
        &src_addr);

    if (dst)
    {
        // Unicast destination address
        COPY_ADDR6(*dst, dst_addr);
    }
    else
    {
        // solicitation multicast address: FF02:0:0:0:0:1:FFXX:XXXX
        // The solicited-node multicast address is formed by taking the
        // low-order 24 bits of the address and appending those bits to the
        // prefix FF02:0:0:0:0:1:FF00::/104
        Ipv6SolicitationMulticastAddress(&dst_addr, target);
    }

    // Trace sending packet for ICMP
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
      PACKET_OUT, &acnData);

    // Add IPv6 header
    Ipv6AddIpv6Header(node, msg, icmpLen, src_addr, dst_addr,
                  IPTOS_PREC_INTERNETCONTROL,
                  IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);

    // Send ICMPv6 Message.
    icmp6_send(node, msg, 0, imo, interfaceId, 0);

    if (DEBUG_IPV6)
    {
        char ll_src_addr[ETHER_ADDR_LEN];
        memcpy(ll_src_addr, lp + 1, ETHER_ADDR_LEN);
        printf ("2. Router Advt Output Link layer address 0x %x%x%x%x\n",
                ll_src_addr[2],
                ll_src_addr[3],
                ll_src_addr[4],
                ll_src_addr[5]);
    }

    if (imo != NULL)
    {
        MEM_free(imo);
    }
    icmp6->icmp6stat.icp6s_snd_rtadv++;
    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtsol6_input
// PURPOSE             :: Receive a Router Solicitation packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN               : int: return status
// NOTES                : Router solicitation processing functions
//---------------------------------------------------------------------------
int rtsol6_input(Node* node, Message* msg, int interfaceId)
{

    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;
    ActionData acnData;

    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);
    ip6_hdr *ipv6Header = (ip6_hdr *) payload;

    MacHWAddress linkLayerAddr ;
    nd_router_solicit* rsp = NULL;
    nd_opt_hdr* xp = NULL;

    int icmpLen = ipv6Header->ip6_plen - sizeof(nd_router_solicit);

    in6_addr srcaddr;
    in6_addr dstaddr;

    unsigned char* lladdr = NULL;

    int extra = sizeof(ip6_hdr) + sizeof(nd_router_solicit);
    int needed = ND_OPT_LINKADDR_LEN;
    int haslladdr = 0;

    rsp = (nd_router_solicit *)(ipv6Header + 1);

    COPY_ADDR6(ipv6Header->ip6_src, srcaddr);
    COPY_ADDR6(ipv6Header->ip6_dst, dstaddr);

    if (rsp->nd_rs_code != 0)
    {
        icmp6->icmp6stat.icp6s_rcv_badrtsol++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_ROUTER_SOLICITATION;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }
    // Position pointer to option header
retry:
    if (packetLen >= extra + needed)
    {
        xp = (nd_opt_hdr *) (payload + extra);
    }
    else
    {
        extra = 0;
        xp = (nd_opt_hdr*) payload;
    }

    switch (xp->nd_opt_type)
    {
        case ND_OPT_SOURCE_LINKADDR:
        {
                if ((xp->nd_opt_len << 3) < ND_OPT_LINKADDR_LEN)
                {
                    icmp6->icmp6stat.icp6s_rcv_badrtsol++;

                    //Trace drop
                    acnData.actionType = DROP;
                    acnData.actionComment = DROP_BAD_ROUTER_SOLICITATION;
                    TRACE_PrintTrace(node,
                                     msg,
                                     TRACE_NETWORK_LAYER,
                                     PACKET_OUT,
                                     &acnData);
                    MESSAGE_Free(node, msg);
                    return FALSE;
                }
                haslladdr = 1;
                lladdr = (unsigned char*)MEM_malloc((xp->nd_opt_len << 3) - 2);
                memcpy(lladdr, xp + 1, (xp->nd_opt_len << 3) - 2);
        }
        default:
        {
                if (xp->nd_opt_len == 0)
                {
                    icmp6->icmp6stat.icp6s_rcv_badrtadv++;

                    //Trace drop
                    acnData.actionType = DROP;
                    acnData.actionComment = DROP_BAD_ROUTER_SOLICITATION;
                    TRACE_PrintTrace(node,
                                     msg,
                                     TRACE_NETWORK_LAYER,
                                     PACKET_OUT,
                                     &acnData);
                    MESSAGE_Free(node, msg);

                    if (lladdr)
                    {
                        MEM_free(lladdr);
                        lladdr = NULL;
                    }
                    return FALSE;
                }
                extra += xp->nd_opt_len << 3;
                icmpLen -= xp->nd_opt_len << 3;
                if (icmpLen > 0)
                {
                    goto retry;
                }
        }
    } // End of option switching

    if (haslladdr == 0)
    {
        icmp6->icmp6stat.icp6s_rcv_badrtsol++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_ROUTER_SOLICITATION;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return FALSE;
    }
    if (IS_ANYADDR6(srcaddr))
    {
        icmp6->icmp6stat.icp6s_rcv_badrtsol++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_BAD_ROUTER_SOLICITATION;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);

        if (lladdr)
        {
            MEM_free(lladdr);
            lladdr = NULL;
        }
        return FALSE;
    }


    linkLayerAddr = Ipv6ConvertStrLinkLayerToMacHWAddress(
            node, interfaceId, lladdr);
    // Check for static route entry first as it is given high priority
    // Update the static routes if any with proper linklayer and
    // interface index.
    CheckStaticRouteEntry(
                    srcaddr,
                    ipv6->prefixHead,
                    ipv6->noOfPrefix,
                    interfaceId,
                    linkLayerAddr);

    ndplookup(node, interfaceId, &srcaddr, 1, linkLayerAddr);

    if (DEBUG_IPV6)
    {
        printf("Router Solicitation Processing Complete\n");
    }

    // Trace for receive ICMPV6, remove ipv6 header first
    MESSAGE_RemoveHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);

    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);
    MESSAGE_Free(node, msg);

    if (lladdr)
    {
        MEM_free(lladdr);
        lladdr = NULL;
    }

    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtadv6_input
// PURPOSE             :: Receive a Router Advertisement packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : int: return status
// NOTES                : Router Advertisement processing function.
//---------------------------------------------------------------------------
int rtadv6_input(Node* node, Message* msg, int interfaceId)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IPv6Data *ipv6 = ip->ipv6;

    char* payload = MESSAGE_ReturnPacket(msg);

    ip6_hdr* ip6Header = (ip6_hdr*) payload;

    nd_router_advert* rap = NULL;

    in6_addr defaultAddr;
    memset(&defaultAddr, 0, sizeof(in6_addr));
    in6_addr src_addr;

    unsigned char* lladdr = NULL;
    MacHWAddress linkLayerAddr ;


    int haslladdr = 0;
    int mtu = 0;

    nd_opt_hdr* lp;
    nd_opt_mtu* ndopt_mtu;
    nd_opt_prefix_info* ndopt_pi;

    // Get Length.
    int icmpLen = ip6Header->ip6_plen;

    // Get Router Advertisement packet
    rap = (nd_router_advert *)(ip6Header + 1);
    icmpLen -= sizeof(nd_router_advert);

    COPY_ADDR6(ip6Header->ip6_src, src_addr);

    // Now Set option, first source link layer address.
    lp = (nd_opt_hdr *) (rap + 1);
    if (lp->nd_opt_type == ND_OPT_SOURCE_LINKADDR)
    {
        haslladdr = 1;
        lladdr = (unsigned char*)MEM_malloc((lp->nd_opt_len << 3) - 2);
        memset(lladdr, 0, (lp->nd_opt_len << 3) - 2);
        memcpy(lladdr, lp + 1, (lp->nd_opt_len << 3) - 2);

        if (DEBUG_IPV6)
        {
                printf ("Router Advt input Link layer addr 0x%x%x%x%x\n",
                    lladdr[2],
                    lladdr[3],
                    lladdr[4],
                    lladdr[5]);
        }
    }
    icmpLen -= sizeof(nd_opt_hdr);

    // Option MTU parameter
    ndopt_mtu = (nd_opt_mtu *) ((char*)(lp) + sizeof(nd_opt_hdr) +
        ETHER_ADDR_LEN);

    if (ndopt_mtu->nd_opt_mtu_type == ND_OPT_MTU)
    {
        mtu = ndopt_mtu->nd_opt_mtu_mtu;
        if (DEBUG_IPV6)
        {
            printf ("Router Advt input mtu %d\n",mtu);
        }
    }
    //
    icmpLen -= sizeof(nd_opt_mtu);



    linkLayerAddr = Ipv6ConvertStrLinkLayerToMacHWAddress(
            node, interfaceId, lladdr);

    // Check for static route entry first as it is given high priority
    // Update the static routes if any with proper linklayer and
    // interface index.
    CheckStaticRouteEntry(
                    src_addr,
                    ipv6->prefixHead,
                    ipv6->noOfPrefix,
                    interfaceId,
                    linkLayerAddr);

    ndplookup(node, interfaceId, &src_addr, 1, linkLayerAddr);

    // Option prefix 1
    ndopt_pi = (nd_opt_prefix_info *) (ndopt_mtu + 1);
    for (; ;)
    {
        if (!ndopt_pi)
        {
            break;
        }
        if (ndopt_pi->nd_opt_pi_type == ND_OPT_PREFIX_INFORMATION)
        {

            if (DEBUG_IPV6)
            {
                char addStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(
                    &ndopt_pi->nd_opt_pi_prefix,addStr);
                printf("Processing prefix option, Node %u %s ",node->nodeId,
                                                              addStr );
                MAC_PrintHWAddr(&linkLayerAddr);
                printf(" %d\n",icmpLen);
            }

            if (!Ipv6IsForwardingEnabled(ipv6))
            {
                updatePrefixList(node,
                                interfaceId,
                                &ndopt_pi->nd_opt_pi_prefix,
                                ndopt_pi->nd_opt_pi_prefix_len,
                                1,
                                linkLayerAddr,
                                RT_REMOTE,
                                AUTOCONF,
                                src_addr);
            }
            // Ipv6 auto-config
            IPv6AutoConfigProcessRouterAdv(
                            node,
                            interfaceId,
                            ndopt_pi,
                            src_addr);
        }

        ndopt_pi++;
        icmpLen -= sizeof(nd_opt_prefix_info);
        if (icmpLen < (signed) (sizeof(nd_opt_prefix_info)))
        {
            break;
        }
    }

    // Ipv6 auto-config
    IPv6InterfaceInfo* interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    newEligiblePrefix* returnAddr = NULL;
    if (interfaceInfo->autoConfigParam.isAutoConfig == TRUE)
    {
        returnAddr = (newEligiblePrefix*)
            IPv6AutoConfigValidateCurrentConfiguredPrefix(node, interfaceId);
    }
    // if auto-configurable interface 
    // and global address was set to link-local 
    if (interfaceInfo->autoConfigParam.isAutoConfig == TRUE
        && interfaceInfo->autoConfigParam.addressState == PREFERRED
        && IS_LINKLADDR6(interfaceInfo->globalAddr))
    {
        IPv6AutoConfigProcessRouterAdvForDAD(
                            node,
                            interfaceId,
                            returnAddr,
                            defaultAddr,
                            linkLayerAddr);
    }
    if (!interfaceInfo->autoConfigParam.isAutoConfig)
    {
        if (!Ipv6IsForwardingEnabled(ipv6))
        {
            memset(&defaultAddr, 0, sizeof(in6_addr));

            updatePrefixList(node,
                interfaceId,
                &defaultAddr,
                0,  // Prefix Length
                1,
                linkLayerAddr,
                RT_REMOTE,
                AUTOCONF,
                src_addr);
        }
    }

    if (lladdr)
    {
        MEM_free(lladdr);
        lladdr = NULL;
    }

    // Trace for receive ICMPV6, remove ipv6 header first
    MESSAGE_RemoveHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);

    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);

    MESSAGE_Free(node, msg);
    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION             : redirect6_output
// PURPOSE             :: Send a Redirect packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +msg                 : Message* msg : Pointer to message structure
// +rt                  : rtentry* rt : Pointer to router entry structure
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : None
// NOTES                : Redirect packet sending function.
// ASSUMTIONS           : This function calling is blocked as current version
//                        does not support link fault.
//---------------------------------------------------------------------------
void
redirect6_output(
    Node* node,
    Message* msg,
    rtentry* rt,
    int interfaceId)
{
    Message* rdMsg = NULL;

    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    IPv6Data* ipv6 = (IPv6Data*) node->networkData.networkVar->ipv6;
    Icmp6Data* icmp6 = ipv6->icmp6;

    char* rdPayload;
    int icmpLen;

    ip6_hdr *ip6Header;
    nd_redirect *rp;
    nd_opt_hdr *lp;

    nd_opt_rd_hdr *xp;
    in6_addr target;

    MacHWAddress llAddr;

    ip6Header = (ip6_hdr*) payload;

    if (rt->rt_flags & RTF_GATEWAY)
    {
        COPY_ADDR6(*rt->rt_gateway, target);
    }
    else
    {
        COPY_ADDR6(ip6Header->ip6_dst, target);
    }

    icmpLen = sizeof(nd_redirect) + sizeof(nd_opt_rd_hdr)
        + ND_OPT_LINKADDR_LEN;

    rdMsg = MESSAGE_Alloc(node,
                          NETWORK_LAYER,
                          NETWORK_PROTOCOL_IPV6,
                          MSG_NETWORK_Icmp6_Redirect);

    // Add ICMPV6 Header
    MESSAGE_PacketAlloc(node, rdMsg, icmpLen, TRACE_ICMPV6);

    rdPayload = MESSAGE_ReturnPacket(rdMsg);
    memset(rdPayload, 0, icmpLen);

    // fill Redirect packet
    rp = (nd_redirect*) rdPayload;

    lp = (nd_opt_hdr *)(rp + 1);

    xp = (nd_opt_rd_hdr *)(lp + ND_OPT_LINKADDR_LEN);

    xp->nd_opt_rh_type = ND_OPT_REDIRECTED_HEADER;
    xp->nd_opt_rh_len = (unsigned char) ((packetLen >> 3) + 1);

    lp->nd_opt_type = ND_OPT_TARGET_LINKADDR;
    lp->nd_opt_len = ND_OPT_LINKADDR_LEN >> 3;

    llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);
    memcpy(lp + 1, llAddr.byte, llAddr.hwLength);

    COPY_ADDR6(target, rp->nd_rd_target);
    COPY_ADDR6(ip6Header->ip6_dst, rp->nd_rd_dst);

    rp->nd_rd_type = ND_REDIRECT;

    // Trace sending packet for ICMPV6
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    // add IPv6 header
    Ipv6AddIpv6Header(node, rdMsg, icmpLen, ip6Header->ip6_dst,
                      ip6Header->ip6_src, IPTOS_PREC_INTERNETCONTROL,
                      IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);


    /* send */
    icmp6_send(node, rdMsg, 0, NULL, interfaceId, 0);
    icmp6->icmp6stat.icp6s_snd_redirect++;
    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : redirect6_input
// PURPOSE             :: Receive a Redirect packet
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to the message structure
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN               : int: status
// NOTES                : Redirect processing function
//---------------------------------------------------------------------------
int
redirect6_input(
    Node* node,
    Message* msg,
    int interfaceId)
{

    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    ip6_hdr *ip = (ip6_hdr*) payload;

    nd_redirect *rp;
    nd_opt_hdr *xp;

    int icmpLen = ip->ip6_plen - sizeof(nd_redirect);



    in6_addr srcaddr;
    in6_addr dstaddr;
    in6_addr tgtaddr;

    //unsigned
    unsigned char* lladdr = NULL;

    int extra = sizeof(ip6_hdr) + sizeof(nd_redirect);
    int needed = ND_OPT_LINKADDR_LEN;
    int haslladdr = 0;
    int is_router;

    rp = (nd_redirect *)(ip + 1);

    COPY_ADDR6(ip->ip6_src, srcaddr);
    COPY_ADDR6(ip->ip6_dst, dstaddr);
    COPY_ADDR6(rp->nd_rd_target, tgtaddr);

    is_router = !SAME_ADDR6(tgtaddr, rp->nd_rd_dst);

    if (rp->nd_rd_code != 0)
    {
        return 0;
    }

    if (!IS_LOCALADDR6(srcaddr))
    {
        return 0;
    }

    if (IS_MULTIADDR6(tgtaddr))
    {
        return 0;
    }

    // position pointer to option header
retry:
    if (packetLen >= extra + needed)
    {
        xp = (nd_opt_hdr *) (payload + extra);
    }
    else
    {
        extra = 0;
        xp = (nd_opt_hdr*) payload;
    }

    switch (xp->nd_opt_type)
    {
        case ND_OPT_REDIRECTED_HEADER:
            break;

        case ND_OPT_TARGET_LINKADDR:
            if ((xp->nd_opt_len << 3) < ND_OPT_LINKADDR_LEN)
            {
                return 0;
            }
            haslladdr = 1;
            lladdr = (unsigned char*)MEM_malloc((xp->nd_opt_len << 3) - 2);
            memcpy(lladdr, xp + 1, (xp->nd_opt_len << 3) - 2);

        default:
            if (xp->nd_opt_len == 0)
            {
                if (lladdr)
                {
                    MEM_free(lladdr);
                    lladdr = NULL;
                }
                return 0;
            }
            extra += xp->nd_opt_len << 3;
            icmpLen -= xp->nd_opt_len << 3;
            if (icmpLen != 0)
            {
                goto retry;
            }
    }
    if (lladdr)
    {
        MEM_free(lladdr);
        lladdr = NULL;
    }

    if (haslladdr == 0)
    {
        return 1;
    }
    return 1;
}

//---------------------------------------------------------------------------
// FUNCTION             : rn_leaf* ndplookup
// PURPOSE             :: Lookup or enter a new address in the ndp table
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// +addr                : in6_addr* addr : IPv6 address pointer,
//                              neighbor's v6 address to lookup in ndp table.
// +report              : int report: reporting flag
// +linkLayerAddr       : NodeAddress linkLayerAddr: Link Layer address of
//                              neighbor's linklayer address.
// RETURN               : rn_leaf*: returns pointer to radix leaf,
// NOTES                : Neighbor cache lookup function
//---------------------------------------------------------------------------
rn_leaf* ndplookup(
    Node* node,
    int interfaceId,
    in6_addr* addr,
    int report,
    MacHWAddress& linkLayerAddr)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    rn_leaf *rt = NULL;

    rt = rtalloc1(
            node,
            ipv6->ndp_cache,
            addr,
            report,
            0UL,
            linkLayerAddr);

    if (rt == NULL)
    {
        return NULL;
    }
    else
    {
        // If there is valid linklayer address then look out going interface.
        // if (linkLayerAddr != (unsigned) INVALID_LINK_ADDR)
        if (linkLayerAddr.hwType != HW_TYPE_UNKNOWN)
        {
            // If old mac-address is incompatible with new mac-address.
            if (rt->linkLayerAddr.hwLength != linkLayerAddr.hwLength)
            {
                rt->linkLayerAddr = INVALID_MAC_ADDRESS;
            }

            if (DEBUG_IPV6)
            {
                char addressStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(addr, addressStr);
                printf("nodeid %d Searching: %s linkLayer",
                node->nodeId,addressStr);
                MAC_PrintHWAddr(&linkLayerAddr);
                MAC_PrintHWAddr(&rt->linkLayerAddr);
                printf("\n");
            }

            rt->interfaceIndex = interfaceId;
            rt->linkLayerAddr = linkLayerAddr;
            rt->ln_state = LLNDP6_REACHABLE;
            rt->expire = node->getNodeTime() + NDPT_REACHABLE;

            rn_insert_reverse_lookup(node, rt);
        }
        else
        {
            // when invalid linklayer address then add the default interface.
            if (interfaceId >= 0)
            {
                rt->interfaceIndex = interfaceId;
                if (TunnelIsVirtualInterface(node, interfaceId))
                {
                    // As per RFC 2893, configured tunnels are assumed
                    // to NOT have a link-layer address, even though the
                    // link-layer (IPv4) does have address. So, we may
                    // set the state of the ndp entry as reachable only for
                    // IPv4-tunneled interface even if the link-layer address
                    // is invalid

                    rt->ln_state = LLNDP6_REACHABLE;
                }
            }
        }
        rt->flags = RT_LOCAL;
    }
    return rt;
}



// /**
// API                 :: updatePrefixList
// LAYER               :: Network
// PURPOSE             :: Prefix list updating function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +addr                : in6_addr* addr : IPv6 Address of destination
// +prefixLen           : UInt32         : Prefix Length
// +report              : int report: error report flag
// +linkLayerAddr       : NodeAddress linkLayerAddr: Link layer address
// +routeFlag           : int routeFlag: route Flag
// +routeType           : int routeType: Route type e.g. gatewayed/local.
// +gatewayAddr         : in6_addr gatewayAddr: Gateway's ipv6 address.
// RETURN              :: None
// **/
void updatePrefixList(
    Node* node,
    int interfaceId,
    in6_addr *addr,
    UInt32 prefixLen,
    int report,
    MacHWAddress& linkLayerAddr,
    int routeFlag,
    int routeType,
    in6_addr gatewayAddr)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    rn_leaf *rn = NULL;

    if (DEBUG_IPV6)
    {
        char addressStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(addr, addressStr);
        printf("\tSearching For :%s linkLayer",addressStr);
        MAC_PrintHWAddr(&linkLayerAddr);
    }
    rn = rtalloc1(
                node,
                ipv6->rt_tables,
                addr,
                report,
                0UL,
                linkLayerAddr);

    rn->keyPrefixLen = prefixLen;

    if (rn)
    {
        if (rn->flags != RT_LOCAL)
        {
            if (rn->rn_option == 1) // Means to add then.
            {
                rn->flags = (unsigned char) routeFlag;
                rn->interfaceIndex = interfaceId;
                rn->type = routeType;

                rn->gateway = gatewayAddr;

                rn->rn_option = RTM_REACHHINT; // Means Reachable.
                rn->ln_state = LLNDP6_REACHABLE;
                rn->expire = node->getNodeTime() + NDPT_KEEP;

                // Default router list entry.
                ipv6->defaultRouter = (defaultRouterList*)
                    MEM_malloc(sizeof(defaultRouterList));

                memset(ipv6->defaultRouter,0,sizeof(defaultRouterList));

                COPY_ADDR6(gatewayAddr, ipv6->defaultRouter->routerAddr);

                ipv6->defaultRouter->outgoingInterface = interfaceId;
                ipv6->defaultRouter->linkLayerAddr = linkLayerAddr;
                ipv6->defaultRouter->next = NULL;
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION             : prefixLookUp
// PURPOSE             :: Prefix cache look up function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +addr                : in6_addr* addr : IPv6 Address pointer,
//                                  IPv6 prevfix to search in prefix table.
// +rn                  : rn_leaf** rn : Points to radix-tree-leaf pointer
// RETURN               : None
// NOTES                : Prefix cache lookup and function.
//---------------------------------------------------------------------------
void prefixLookUp(Node* node, in6_addr* addr, rn_leaf **rn)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    *rn = RadixTreeLookUp(node, addr, ipv6->rt_tables);

    if (*rn == NULL)
    {
        int netInterface = Ipv6IpGetInterfaceIndexForNextHop(node, *addr);

        if (netInterface != -1)
        {
            in6_addr prefix;

            Ipv6GetPrefix(
                addr,
                &prefix,
                Ipv6GetPrefixLength(node, netInterface));
            *rn = RadixTreeLookUp(node, &prefix, ipv6->rt_tables);
        }
    }

    if (DEBUG_IPV6)
    {
        printf("prefixLookUp: NodeId %u\n", node->nodeId);
    }

    return;
}


//---------------------------------------------------------------------------
// FUNCTION             : destinationLookUp
// PURPOSE             :: Destination Cache lookup function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +ipv6                : IPv6Data* ipv6: Pointer to node's IPv6 data.
// +dst                 : in6_addr* dst : IPv6 destination address,
//                      :           IPv6 destination address to search.
// RETURN               : route*
// NOTES                : Destination Cache lookup function.
//---------------------------------------------------------------------------
route* destinationLookUp(Node* node, IPv6Data* ipv6, in6_addr* dst)
{
    DestinationCache* destCache = &(ipv6->destination_cache);
    DestinationRoute* temp = destCache->start;

    while (temp != NULL)
    {
        if (!temp->ro->ro_rt.rt_node)
        {
            temp = temp->nextRoute;
            continue;
        }

        if (SAME_ADDR6(*dst, temp->ro->ro_dst))
        {
            return temp->ro;
        }
        temp = temp->nextRoute;
    }
    return NULL;
}


//---------------------------------------------------------------------------
// FUNCTION             : CheckStaticRouteEntry
// PURPOSE             :: Check for static route entry
// PARAMETERS          ::
// +ipv6Addr            : in6_addr ipv6Addr: IPv6 address for static entry.
// +hp                  : struct prefixListStruct* hp: Pointer to prefix list
//                      :   structure.
// +noOfPrefix          : int noOfPrefix: No of prefixes in the list.
// +interfaceId         : int interfaceId: Index of concerned interface
// +linkLayerAddr       : NodeAddress linkLayerAddr: link layer address.
// RETURN               : None
// NOTES                : Static route entry checking function
//---------------------------------------------------------------------------
void CheckStaticRouteEntry(
            in6_addr ipv6Addr,
            struct prefixListStruct* hp,
            int noOfPrefix,
            int interfaceId,
            MacHWAddress& linkLayerAddr)
{
    int i = 0;
    in6_addr addr;
    rn_leaf* rnp = NULL;
    for (i = 0; i < noOfPrefix; i++)
    {
        rnp = hp->rnp;
        // local route.
        if (!rnp)
        {
            hp = hp->next;
            continue;
        }
        if (rnp->flags != RT_LOCAL)
        {
            addr = rnp->gateway;

            if (DEBUG_IPV6)
            {
                char tempStr[MAX_STRING_LENGTH];

                IO_ConvertIpAddressToString(&ipv6Addr, tempStr);
                printf("No of prefix %d Processing for static route %s",
                    noOfPrefix, tempStr);

                IO_ConvertIpAddressToString(&addr, tempStr);
                printf(" and gateway %s\n", tempStr);
            }

            if (SAME_ADDR6(addr, ipv6Addr))
            {
                // If old mac-address is incompatible with new mac-address.
                if (rnp->linkLayerAddr.hwLength != linkLayerAddr.hwLength)
                {
                    rnp->linkLayerAddr = INVALID_MAC_ADDRESS;
                }

                // Gateway is same as static route nexthop.
                rnp->linkLayerAddr = linkLayerAddr;
                rnp->interfaceIndex = interfaceId;
            }
        }
        hp = hp->next;
    } // end for Checking all prefix information.
}



//---------------------------------------------------------------------------
// FUNCTION             : ndsol6_retry
// PURPOSE             :: Neighbor solicitation retry function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to the message structure
// RETURN               : None
// NOTES                : Neighbor solicitation retry function.
//---------------------------------------------------------------------------
void ndsol6_retry(Node* node, Message* msg)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    // Check wether we have received the response.
    Ipv6NSolRetryMessage* nsolRtmsg = (Ipv6NSolRetryMessage*)
                                      MESSAGE_ReturnInfo(msg);
    int interfaceId = nsolRtmsg->interfaceId;
    MacHWAddress temHWAddr;
    rn_leaf* ln = ndplookup(
                    node,
                    nsolRtmsg->interfaceId,
                    &(nsolRtmsg->dst),
                    1,
                    temHWAddr//(unsigned) INVALID_LINK_ADDR
                    );
    if (DEBUG_IPV6)
    {
        char temp[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(&(nsolRtmsg->dst), temp);
        printf("Target Address %s\n",temp);
        printf ("node %d intf %d retry counter %d\n",
            node->nodeId, interfaceId, nsolRtmsg->retryCounter);

    }

    if (ln)
    {
        // Already got valid ndp information. so free the message.
        if (ln->ln_state == LLNDP6_REACHABLE)
        {
            MESSAGE_Free(node, msg);
            return;
        }
    }


    if (nsolRtmsg->retryCounter == MAX_UNICAST_SOLICIT)
    {
        // it has reached to maximum retry so free the same. update states.
        if (ln)
        {
            ln->ln_state = LLNDP6_INCOMPLETE;
            ln->expire = node->getNodeTime() + UNREACHABLE_TIME;
        }
        Ipv6DropMessageFromBuffer(node, nsolRtmsg->dst, NULL);

        // delete the entry for the neighbor from the neighbor-cache
        // since no reachability confirmation is received even after
        // sending MAX_UNICAST_SOLICIT solicitaions

        rn_delete_reverse_lookup(node, ln->linkLayerAddr);

        rn_delete((void *)ln,ipv6->ndp_cache);

        MESSAGE_Free(node, msg);
        return;
    }

    // Update the counter and fire event for next try.
    if (nsolRtmsg->retryCounter < MAX_UNICAST_SOLICIT)
    {
        nsolRtmsg->retryCounter++;
        ndsol6_output(node, interfaceId, NULL, &(nsolRtmsg->dst), FALSE);
        MESSAGE_Send(node, msg, RETRANS_TIMER);
    }
    else
    {
        MESSAGE_Free(node, msg);
    }
}

// /**
// FUNCTION         :: search_NDPentry
// LAYER            :: Network
// PURPOSE          :: Search for link layer address in ndp cache
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + outgoingInterface :  Int32      : Interface Index
// + ndp_cache_entry : rn_leaf**     : Pointer to pointer to NDP cache entry
// RETURN           :: BOOL : Found or not found flag.
// **/

static  BOOL search_NDPentry(Node* node,
                         Message* msg,
                         in6_addr nextHopAddr,
                         int outgoingInterface,
                         rn_leaf** ndp_cache_entry)
{
    MacHWAddress llAddr;

    *ndp_cache_entry =
        ndplookup(node, outgoingInterface, &nextHopAddr, 1, llAddr);

    if (ndp_cache_entry == NULL)
    {
        // While lookup fails Send Neighbor solicitation.
        // Put the packet in the hold buffer.
        // Put the Packet in the Queue and Set linklayer,
        // outgoing interface to invalid.
        if (!Ipv6AddMessageInBuffer(
                node,
                msg,
                &nextHopAddr,
                outgoingInterface,
                *ndp_cache_entry))
        {
            MESSAGE_Free(node, msg);
        }
        // Send the neighbor solicitation.
        ndsol6_output(node, outgoingInterface, NULL, &nextHopAddr, TRUE);
        return FALSE;
    }
    else
    {
        // Got the NDP cache entry.
        // Set properly state of the route.
        if ((*ndp_cache_entry)->ln_state >= LLNDP6_PROBING)
        {
            if ((*ndp_cache_entry)->ln_state == LLNDP6_PROBING)
            {
                if (!Ipv6AddMessageInBuffer(
                        node,
                        msg,
                        &nextHopAddr,
                        outgoingInterface,
                        *ndp_cache_entry))
                {
                    MESSAGE_Free(node, msg);
                }
                (*ndp_cache_entry)->expire = node->getNodeTime() + NDPT_PROBE;
                return FALSE;
            }
            else if ((*ndp_cache_entry)->ln_state == LLNDP6_REACHABLE)
            {
                if (node->getNodeTime() > (*ndp_cache_entry)->expire)
                {
                     (*ndp_cache_entry)->ln_state = LLNDP6_PROBING;

                    // Now send Neighbor Solicitation.
                    ndsol6_output(node, (*ndp_cache_entry)->interfaceIndex,
                       NULL, &nextHopAddr, TRUE);
                }
                 // if reachable set the timer again.
                (*ndp_cache_entry)->expire =
                                           node->getNodeTime() + NDPT_REACHABLE;
                 return TRUE;
            }

        }
        // If the state is not PROBING nor REACHABLE
        // try to resolve linklayer address.

        if ((*ndp_cache_entry)->ln_state == LLNDP6_INCOMPLETE)
        {
            // Put the packet in the hold buffer.
            // Put the Packet in the Queue and Set linklayer,
            // outgoing interface to invalid.
            if (!Ipv6AddMessageInBuffer(
                        node,
                        msg,
                        &nextHopAddr,
                        outgoingInterface,
                        (*ndp_cache_entry)))
            {
                    MESSAGE_Free(node, msg);
                    //return FALSE;
            }
            if (node->getNodeTime() > (*ndp_cache_entry)->expire)
            {
                (*ndp_cache_entry)->ln_state = LLNDP6_PROBING;

                // Now send Neighbor Solicitation.
                ndsol6_output(node, outgoingInterface,
                                NULL, &nextHopAddr, TRUE);
            }
        }
    }

    return FALSE;
}

// /**
// FUNCTION         :: ndp_resolvellAddrandSendToMac
// LAYER            :: Network
// PURPOSE          :: Resolve Next-hop link-layer address and send to mac
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + outgoingInterface :  Int32      : Interface Index
// RETURN           :: void : NULL.
// **/
void
ndp_resolvellAddrandSendToMac(
    Node *node,
    Message *msg,
    in6_addr nextHopAddr,
    int outgoingInterface)
{

    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    MacHWAddress llAddr;
    rn_leaf* ndp_cache_entry = NULL;
    route ro;
    COPY_ADDR6(nextHopAddr, ro.ro_dst);

    // multicast address is resolved here
    if (IS_MULTIADDR6(nextHopAddr))
    {

        if (Ipv6IsReservedMulticastAddress(node, nextHopAddr))
        {
            ip6_output(
                node,
                msg,
                (optionList*)NULL,
                &ro,
                0,
                (ip_moptions*)NULL,
                CPU_INTERFACE,
                outgoingInterface);
        }
        else
        {
            RouteThePacketUsingMulticastForwardingTable(
                node,
                msg,
                outgoingInterface,
                NETWORK_IPV6);
        }

        // increment stats for number of IPv6 packets forwarded
        ipv6->ip6_stat.ip6s_forward++;
        return;
    }

   BOOL found = search_NDPentry(node, msg, nextHopAddr,
                                outgoingInterface, &ndp_cache_entry);

   if (found)
   {
        ro.ro_rt.rt_node = ndp_cache_entry;

        ip6_output(
            node,
            msg,
            (optionList*)NULL,
            &ro,
            0,
            (ip_moptions*)NULL,
            CPU_INTERFACE,
            outgoingInterface);
        ipv6->ip6_stat.ip6s_forward++;
   }
}

