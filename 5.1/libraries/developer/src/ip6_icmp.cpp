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
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

//
// Ported from FreeBSD 4.7
// This file contains function for ICMPv6 (RFC 2463)
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


#include "ip6_icmp.h"
#include "if_ndp6.h"
#include "ipv6_route.h"
#include "ip6_opts.h"
#include "ip6_output.h"
#include "ip6_input.h"
#include "network_ip.h"

#define DEBUG_IPV6 0

void Icmp6PrintTraceXML(Node* node, Message* msg);


// /**
// FUNCTION   :: Icmp6PrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void Icmp6PrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];

    char* payload = MESSAGE_ReturnPacket(msg);
    icmp6_hdr* icmp = (icmp6_hdr*) payload;

    nd_opt_hdr* lp = NULL;

    sprintf(buf, "<icmpv6>");
    TRACE_WriteToBufferXML(node, buf);


    switch (icmp->icmp6_type)
    {
         case ND_NEIGHBOR_SOLICIT:
         {
            sprintf(buf, "<nd_neighbor_solicit>");
            TRACE_WriteToBufferXML(node, buf);
            nd_neighbor_solicit* nsp = NULL;
            nsp = (nd_neighbor_solicit *) icmp;

            sprintf(buf, "%hu %hu %hu ",
            nsp->nd_ns_type,
            nsp->nd_ns_code,
            nsp->nd_ns_cksum);
           TRACE_WriteToBufferXML(node, buf);

            lp = (nd_opt_hdr*)(nsp + 1);

            sprintf(buf, "%hu %hu ",
                lp->nd_opt_type,
                lp->nd_opt_len);
            TRACE_WriteToBufferXML(node, buf);

            sprintf(buf, "</nd_neighbor_solicit>");
            TRACE_WriteToBufferXML(node, buf);
            break;
         }
         case ND_ROUTER_SOLICIT:
        {
            sprintf(buf, "<nd_router_solicit>");
            TRACE_WriteToBufferXML(node, buf);
            nd_router_solicit * rsp = (nd_router_solicit *) icmp;

            sprintf(buf,"%hu %hu %hu ",
            rsp->nd_rs_type,
            rsp->nd_rs_code,
            rsp->nd_rs_cksum);

            TRACE_WriteToBufferXML(node, buf);

            // Then add router discovery option header
            lp = (nd_opt_hdr *) (rsp + 1);

            sprintf(buf,"%hu %hu",
            lp->nd_opt_type,
            lp->nd_opt_len);
            TRACE_WriteToBufferXML(node, buf);

            sprintf(buf, "</nd_router_solicit>");
            TRACE_WriteToBufferXML(node, buf);
            break;
        }
        case ND_ROUTER_ADVERT:
        {

            sprintf(buf, "<nd_router_advert>");
            TRACE_WriteToBufferXML(node, buf);

            nd_router_advert* rap = (nd_router_advert *) icmp;

            sprintf(buf,"%hu %hu %hu %d %d ",
            rap->nd_ra_type,
            rap->nd_ra_code,
            rap->nd_ra_cksum,
            rap->nd_ra_reachable,
            rap->nd_ra_retransmit);
            TRACE_WriteToBufferXML(node, buf);

            // Now Set option, first source link layer address.
            lp = (nd_opt_hdr *) (rap + 1);

            sprintf(buf," %hu %hu ",
            lp->nd_opt_type,
            lp->nd_opt_len);
            TRACE_WriteToBufferXML(node, buf);

            nd_opt_mtu* ndopt_mtu;

            // Option MTU parameter
            ndopt_mtu = (nd_opt_mtu *) ((char*)(lp) + sizeof(nd_opt_hdr) +
                                             ETHER_ADDR_LEN);
            sprintf(buf,"%hu %hu %d ",
            ndopt_mtu->nd_opt_mtu_type,
            ndopt_mtu->nd_opt_mtu_len,
            ndopt_mtu->nd_opt_mtu_mtu);

            TRACE_WriteToBufferXML(node, buf);

            // Option prefix 1
            nd_opt_prefix_info* ndopt_pi;
            ndopt_pi = (nd_opt_prefix_info *) (ndopt_mtu + 1);

            char addStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&ndopt_pi->nd_opt_pi_prefix,addStr);

            sprintf(buf,"%hu %hu %d %s %hu %hu %hu %hu ",
            ndopt_pi->nd_opt_pi_flags_reserved,
            ndopt_pi->nd_opt_pi_len,
            ndopt_pi->nd_opt_pi_preferred_time,
            addStr,
            ndopt_pi->nd_opt_pi_prefix_len,
            ndopt_pi->nd_opt_pi_reserved_site_plen,
            ndopt_pi->nd_opt_pi_type,
            ndopt_pi->nd_opt_pi_valid_time);

            TRACE_WriteToBufferXML(node, buf);

            sprintf(buf, "</nd_router_advert>");
            TRACE_WriteToBufferXML(node, buf);

            break;
        }
        case ND_NEIGHBOR_ADVERT:
       {
            sprintf(buf, "<nd_neighbor_advert>");
            TRACE_WriteToBufferXML(node, buf);

            nd_neighbor_advert *nap =
                (nd_neighbor_advert *) icmp;
            char targtAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&nap->nd_na_target,targtAddr);
            sprintf(buf,"%hu %hu %hu %d %s ",
            nap->nd_na_type,
            nap->nd_na_code,
            nap->nd_na_cksum,
            nap->nd_na_flags_reserved,
            targtAddr);
            TRACE_WriteToBufferXML(node, buf);

            // Now Set option, first source link layer address.
            lp = (nd_opt_hdr *) (nap + 1);

            sprintf(buf," %hu %hu ",
            lp->nd_opt_type,
            lp->nd_opt_len);
            TRACE_WriteToBufferXML(node, buf);

            sprintf(buf, "</nd_neighbor_advert>");
            TRACE_WriteToBufferXML(node, buf);

            break;
        }

   }
    sprintf(buf, "</icmpv6>");
    TRACE_WriteToBufferXML(node, buf);

}

//---------------------------------------------------------------------------
// FUNCTION             : AddICMP6Header
// PURPOSE             :: To add Icmpv6 Header to the message
// PARAMETERS          ::
// +node                : Node*         : Pointer to Node
// +msg                 : Message* msg  : Pointer to message structure.
// +type                : int type      : Type of Icmpv6 message.
// +code                : int code      : Icmpv6 code of message.
// +data                : char* data    : Icmpv6 message data.
// +dataLen             : int dataLen   : Icmpv6 message data length.
// RETURN               : None
// NOTES                : ICMPv6 Header adding function
//---------------------------------------------------------------------------
void
AddICMP6Header(
    Node* node,
    Message* msg,
    int type,
    int code,
    char* data,
    int dataLen)
{
    icmp6_hdr* icmpHdr = NULL;

    MESSAGE_AddHeader(node, msg, sizeof(icmp6_hdr), TRACE_ICMPV6);
    icmpHdr = (icmp6_hdr*) MESSAGE_ReturnPacket(msg);
    memset(icmpHdr, 0, sizeof(icmp6_hdr));
    icmpHdr->icmp6_type = (unsigned char)type;
    icmpHdr->icmp6_code = (unsigned char)code;
    icmpHdr->icmp6_cksum = 0;
    memset(icmpHdr->icmp6_dataun.icmp6_un_data8,0,dataLen);
    memcpy(icmpHdr->icmp6_dataun.icmp6_un_data8, data, dataLen);
    return;
}

// ICMP6 initialization
//---------------------------------------------------------------------------
// FUNCTION             : Icmp6Init
// PURPOSE             :: ICMP6 initialization
// PARAMETERS          ::
// +ipv6                : IPv6Data* ipv6: IPv6 data pointer of the node.
// RETURN               : None
//---------------------------------------------------------------------------
void Icmp6Init(IPv6Data* ipv6)
{
    ipv6->icmp6 = (Icmp6Data*) MEM_malloc(sizeof(Icmp6Data));

    //Statistic Variable Initializations.
    memset(&(ipv6->icmp6->icmp6stat), 0, sizeof(icmp6_stat));
}


//---------------------------------------------------------------------------
// FUNCTION             : icmp6_input
// PURPOSE             :: Process a received ICMPv6 message.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node.
// +msg                 : Message* msg  : Pointer to message structure.
// +oarg                : void*         : Option argument
// +interfaceId         : int interfaceId: Index to the concerned interface.
// RETURN               : None
// NOTES                : ICMPv6 received packet processing function
//---------------------------------------------------------------------------

void
icmp6_input(
    Node* node,
    Message* msg,
    void* oarg,
    int interfaceId)
{
    IPv6Data* ipv6 = (IPv6Data*)
                        ((NetworkDataIp*)node->networkData.networkVar)->ipv6;

    Icmp6Data* icmp6 = ipv6->icmp6;
    char* payload = MESSAGE_ReturnPacket(msg);
    ip6_hdr* ip = (ip6_hdr*)payload;
    int icmplen = ip->ip6_plen;
    icmp6_hdr* icp = NULL;
    int code = 0;

    optionList* opts = (optionList*) oarg;

    // Check at least minimum length.
    if (icmplen < (signed) (sizeof(icmp6_hdr)))
    {
        icmp6->icmp6stat.icp6s_tooshort++;
        goto freeit;
    }

    ip = (ip6_hdr*) payload;
    icp = (icmp6_hdr*) (ip + 1);

    if (DEBUG_IPV6)
    {
        // IPv6 Packet Printing Block.
        char addressStr[MAX_STRING_LENGTH];

        printf("\t IPv6 header when sending the packet through ICMP\n");
        printf("Version\t%d\n", ip6_hdrGetVersion(ip->ipv6HdrVcf));
        printf("Class\t%d\n", ip6_hdrGetClass(ip->ipv6HdrVcf));
        printf("Flow\t%d\n", ip6_hdrGetFlow(ip->ipv6HdrVcf));
        printf("length\t%d\n",ip->ip6_plen);
        printf("Next-Header\t%d\n",ip->ip6_nxt);
        printf("Hop-Limit\t%d\n",ip->ip6_hlim);

        IO_ConvertIpAddressToString(&ip->ip6_src, addressStr);
        printf("Ip-Source\t%s\n",addressStr);
        IO_ConvertIpAddressToString(&ip->ip6_dst, addressStr);
        printf("Ip-Destin\t%s\n",addressStr);

        printf("Icmp Code\t%d Type\t%d\n",icp->icmp6_code,icp->icmp6_type);
    }

    // Message type specific processing.
    code = icp->icmp6_code;

    if (IS_ANYADDR6(ip->ip6_src) &&
        (icp->icmp6_type != ND_NEIGHBOR_SOLICIT) &&
        (icp->icmp6_type != ND_ROUTER_SOLICIT))
    {
        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_UNKNOWN_MSG_TYPE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        goto freeit;
    }

    switch (icp->icmp6_type)
    {
        case ICMP6_DST_UNREACH:
        {
            switch (code)
            {
                case ICMP6_DST_UNREACH_NOROUTE:
                {
                    code = PRC_UNREACH_NET;
                    break;
                }
                case ICMP6_DST_UNREACH_ADMIN:
                {
                    code = PRC_UNREACH_HOST;
                    break;
                }
                case ICMP6_DST_UNREACH_BEYONDSCOPE:
                {
                    code = PRC_UNREACH_NET;
                    break;
                }
                case ICMP6_DST_UNREACH_ADDR:
                {
                    code = PRC_UNREACH_HOST;
                    icmp6->icmp6stat.icp6s_rcv_ur_addr++;
                    break;
                }
                case ICMP6_DST_UNREACH_NOPORT:
                {
                    code = PRC_UNREACH_PORT;
                    break;
                }
                default:
                    goto badcode;
            }
            goto deliver;
        }

        case ICMP6_PACKET_TOO_BIG:
        {
            /* Should be un commented when link fault is implemented.
            icmp6->icmp6stat.icp6s_rcv_pkttoobig++;
            code = PRC_MSGSIZE;
            if (rt == NULL)
            {
                goto deliver;
            }


            if ((rt->rt_mtu > Ipv6GetMTU(node, interfaceId)) ||
                (icp->icmp6_mtu > rt->rt_mtu) ||
                (icp->icmp6_mtu < IP6_MMTU))
            {
                goto freeit;
            }
            if ((rt->rt_flags & RTF_HOST) == 0)
            {
                    goto freeit;
            }


            if (icp->icmp6_mtu < rt->rt_mtu)
            {
                rt->rt_mtu = icp->icmp6_mtu;
            }
            goto deliver;
            */
            goto freeit;
        }

        case ICMP6_TIME_EXCEEDED:
        {
            if ((code != ICMP6_TIME_EXCEED_TRANSIT) &&
                (code != ICMP6_TIME_EXCEED_REASSEMBLY))
            {
                goto badcode;
            }
            code += PRC_TIMXCEED_INTRANS;
            goto deliver;
        }

        case ICMP6_PARAM_PROB:
        {
            if (code == ICMP6_PARAMPROB_NEXTHEADER)
            {
                code = PRC_UNREACH_PROTOCOL;
            }
            else
            {
                code = PRC_PARAMPROB;
            }
            goto deliver;
        }
        deliver:
             // Problem with datagram; advise higher level routines.
            if ((unsigned) icmplen < sizeof(ip6_hdr) + sizeof(icmp6_hdr) + 8)
            {
                goto freeit;
            }
            goto freeit;
        case ND_ROUTER_SOLICIT:
        {
            if (DEBUG_IPV6)
            {
                printf("Receive Router Solicitation in Node %u\n",
                    node->nodeId);
            }

            if (ip->ip6_hlim != ND_DEFAULT_HOPLIM)
            {
                icmp6->icmp6stat.icp6s_rcv_badrtsol++;
                goto freeit;
            }
            if (icmplen < (signed) (sizeof(nd_router_solicit)))
            {
                icmp6->icmp6stat.icp6s_badlen++;
                goto freeit;
            }

            if (!Ipv6IsForwardingEnabled(ipv6))
            {
                // IPv6 forwarding is not enabled
                icmp6->icmp6stat.icp6s_rcv_rtsol++;
                goto freeit;
            }

            in6_addr dst = ip->ip6_dst;

            if (!rtsol6_input(node, msg, interfaceId))
            {
                icmp6->icmp6stat.icp6s_rcv_badrtsol++;
                break;
            }

            // on receiving solicitation send router advertisement
            rtadv6_output(node,
                          interfaceId,
                          &dst,
                          &(ipv6->ip->interfaceInfo[interfaceId]->
                                    ipv6InterfaceInfo->globalAddr));

            icmp6->icmp6stat.icp6s_rcv_rtsol++;


            if (DEBUG_IPV6)
            {
            printf("Router Solicitation processing in Node %u complete\n",
                    node->nodeId);
            }
            break;
        }

        case ND_ROUTER_ADVERT:
        {
            if (DEBUG_IPV6)
            {
                printf("Received Router Advt. in Node %u interface %d\n",
                    node->nodeId, interfaceId);
            }

            if (ip->ip6_hlim != ND_DEFAULT_HOPLIM)
            {
                icmp6->icmp6stat.icp6s_rcv_badrtadv++;
                goto freeit;
            }
            if (icmplen < (signed) (sizeof(nd_router_advert)))
            {
                icmp6->icmp6stat.icp6s_badlen++;
                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_BAD_ICMP_LENGTH;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }

            if (!rtadv6_input(node, msg, interfaceId))
            {
               icmp6->icmp6stat.icp6s_rcv_badrtadv++;
               break;
            }
            if (DEBUG_IPV6)
            {
                printf("Received Router Advt. Processing Complete "
                    "in Node %u interface %d\n",
                    node->nodeId, interfaceId);
            }
            icmp6->icmp6stat.icp6s_rcv_rtadv++;
            break;
        }

        case ND_NEIGHBOR_SOLICIT:
        {
            // Neighbor solicitation received, in turn send
            // Neighbor advertisement.
            if (ip->ip6_hlim != ND_DEFAULT_HOPLIM)
            {
                icmp6->icmp6stat.icp6s_rcv_badndsol++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_BAD_NEIGHBOR_SOLICITATION;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }
            if (icmplen < (signed) (sizeof(nd_neighbor_solicit)))
            {
                icmp6->icmp6stat.icp6s_badlen++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_BAD_ICMP_LENGTH;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }

           if (!ndsol6_input(node, msg, interfaceId))
           {
               icmp6->icmp6stat.icp6s_rcv_badndsol++;
               break;
            }
            break;
        }

        case ND_NEIGHBOR_ADVERT:
        {
            if (ip->ip6_hlim != ND_DEFAULT_HOPLIM)
            {
                icmp6->icmp6stat.icp6s_rcv_badndadv++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_HOP_LIMIT_ZERO;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }
            if (icmplen < (signed) (sizeof(nd_neighbor_advert)))
            {
                icmp6->icmp6stat.icp6s_badlen++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_BAD_ICMP_LENGTH;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }

            if (!ndadv6_input(node, msg, interfaceId))
            {
               icmp6->icmp6stat.icp6s_rcv_badndadv++;
               break;
            }
            icmp6->icmp6stat.icp6s_rcv_ndadv++;
            break;
        }
        case ND_REDIRECT:
        {
            if (ip->ip6_hlim != ND_DEFAULT_HOPLIM)
            {
                icmp6->icmp6stat.icp6s_rcv_badredirect++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_HOP_LIMIT_ZERO;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }
            if (icmplen < (signed) (sizeof(nd_redirect)))
            {
                icmp6->icmp6stat.icp6s_badlen++;

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment = DROP_BAD_ICMP_LENGTH;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_OUT,
                                 &acnData);
                goto freeit;
            }
            // To be checked after redirect is implemented
            //if (!redirect6_input(node, msg, interfaceId))
            //  {
            //      icmp6->icmp6stat.icp6s_rcv_badredirect++;
            //     goto freeit;
            //  }
            //  icmp6->icmp6stat.icp6s_rcv_redirect++;
            goto freeit;

        badcode:
            icmp6->icmp6stat.icp6s_badcode++;
            goto freeit;
        }

        case ICMP6_ECHO_REQUEST:
        {
            in6_addr addr = ip->ip6_dst;
            ip->ip6_dst = ip->ip6_src;
            ip->ip6_src = addr;
            ip->ip6_hlim = CURR_HOP_LIMIT;
            icp->icmp6_type = ICMP6_ECHO_REPLY;
            Ipv6RouterFunctionType routerFunction = NULL;
            BOOL packetWasRouted = FALSE;
            routerFunction = Ipv6GetRouterFunction(node, interfaceId);
            if (routerFunction)
            {
                (*routerFunction)(
                    node,
                    msg,
                    ip->ip6_dst,
                    ipv6->broadcastAddr,
                    &packetWasRouted);
            }

            if (!packetWasRouted)
            {
                ndp6_resolve(
                    node,
                    CPU_INTERFACE,
                    &interfaceId,
                    NULL,
                    msg,
                    &ip->ip6_dst);
            }
            break;
        }

        case ICMP6_ECHO_REPLY:
        {
            // No Processing for the following;
            // just fall through to send to raw listener.
            goto freeit;
        }
        default:
        {
            if ((icp->icmp6_type & ICMP6_INFOMSG_MASK) != 0)
            {
                goto freeit;
            }
            goto freeit;
        }
    }
    return;

freeit:
    if (opts)
    {
        MEM_free(opts);
    }
    MESSAGE_Free(node, msg);
}

//---------------------------------------------------------------------------
// FUNCTION             : icmp6_send
// PURPOSE             :: Send an ICMPv6 packet after supplying a checksum.
//                      : in simulation checksum is kept zero as has no
//                      : chance of packet corruption.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Structure
// + opts               : void*         : Options
// +imo                 : ip_moptions* imo: Pointer to multicast options.
// +interfaceId         : int interfaceId : Index of the Interface
// +flags               : int flags: Flags for route type.
// RETURN               : None
// NOTES                : checksum is kept zero for simplicity
//---------------------------------------------------------------------------

void
icmp6_send(
    Node* node,
    Message* msg,
    void* opts,
    ip_moptions* imo,
    int interfaceId,
    int flags)
{
    IPv6Data* ipv6 = (IPv6Data*)
                        ((NetworkDataIp*)node->networkData.networkVar)->ipv6;
    char* payload = MESSAGE_ReturnPacket(msg);

    ip6_hdr* ip6Header = (ip6_hdr*)payload;
    icmp6_hdr* icp = (icmp6_hdr*) (ip6Header + 1);
    route* ro = NULL;

    if (DEBUG_IPV6)
    {

        if (imo)
        {
            switch (icp->icmp6_type)
            {
                case ND_NEIGHBOR_SOLICIT:
                {
                    nd_neighbor_solicit* nsp = NULL;
                    nsp = (nd_neighbor_solicit*)icp;

                    char addressStr[MAX_STRING_LENGTH];
                    nd_opt_hdr* lp = NULL;
                    char* ll_addr_str = NULL;

                    IO_ConvertIpAddressToString(
                        &nsp->nd_ns_target,
                        addressStr);
                    printf("TargerAddr\t%s\n",addressStr);

                    lp = (nd_opt_hdr*)(nsp + 1);
                    printf(" Neighbour Solicitation Information");
                    printf("Option-Type\t%d\n", lp->nd_opt_type);
                    printf("Option-Len\t%d\n", lp->nd_opt_len);
                    ll_addr_str = (char*)(lp + 1);
                    printf("Link-LayerAddr\t0x%x%x%x%x\n",
                        ll_addr_str[2],
                        ll_addr_str[3],
                        ll_addr_str[4],
                        ll_addr_str[5]);
                }
            }
        }
    }

    // Check sum not required for simulation.
    icp->icmp6_cksum = 0;

    if (IS_MULTIADDR6(ip6Header->ip6_dst))
    {
        route mro = {{0}};

        COPY_ADDR6(ip6Header->ip6_dst, mro.ro_dst);

        ip6_output(
            node,
            msg,
            (optionList*)opts,
            &mro,
            flags,
            imo,
            CPU_INTERFACE,
            interfaceId);

        return;
    }

    ro = destinationLookUp(node, ipv6, &ip6Header->ip6_dst);
    if (!ro)
    {
        ro = Route_Malloc();
        if (!ro)
        {
            ERROR_ReportError("Unable to allocate route\n");
        }
        COPY_ADDR6(ip6Header->ip6_dst, ro->ro_dst);
        ro->prefixLen = 128;
        ro->ro_rt.rt_node = NULL;

        //rtalloc(node, ro, 0);
        MacHWAddress tempHWAddress;
        rtalloc(node, ro,tempHWAddress);
        Ipv6AddDestination(node, ro);
    }

    ip6_output(
            node,
            msg,
            (optionList*)opts,
            ro,
            flags,
            imo,
            CPU_INTERFACE,
            interfaceId);



} // End of icmp send.



//---------------------------------------------------------------------------
// FUNCTION             : icmp6_error
// PURPOSE             :: Generate an error packet of type error
//                        in response to bad IPv6 packet.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Structure
// +type                : int type      : Icmpv6 type of message.
// +code                : int code      : Icmpv6 code of message.
// +arg                 : int arg       : Option argument.
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : None
// NOTES                : Icmpv6 Error message sending function
//---------------------------------------------------------------------------

void
icmp6_error(
    Node* node,
    Message* msg,
    int type,
    int code,
    int arg,
    int interfaceId)
{
    IPv6Data* ipv6 = (IPv6Data*)
                        ((NetworkDataIp*)node->networkData.networkVar)->ipv6;

    Icmp6Data* icmp6 = ipv6->icmp6;
    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    ip6_hdr* oip = (ip6_hdr*) payload;
    icmp6_hdr* icp;

    Message* icmpMsg;
    char* icmpPayload;

    icmp6->icmp6stat.icp6s_error++;

    // Don't send error in response to packet
    // without an identified source or a multicast
    // if it is not for path MTU discovery.

    if (IS_MULTIADDR6(oip->ip6_src) ||
        IS_ANYADDR6(oip->ip6_src) ||
        (in6_isanycast(node, &oip->ip6_src) == IP6ANY_ANYCAST))
    {

        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_UNIDENTIFIED_SOURCE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        return;
    }

    // Don't send error in response to multicasts if
    // it is not for path MTU discovery or multicast options
    if (IS_MULTIADDR6(oip->ip6_dst))
    {
        if (type != ICMP6_PACKET_TOO_BIG &&
            (type != ICMP6_PARAM_PROB || code != ICMP6_PARAMPROB_OPTION))
        {

            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_ICMP6_PACKET_TOO_BIG;
            TRACE_PrintTrace(node,msg,TRACE_NETWORK_LAYER,PACKET_IN, &acnData);

            MESSAGE_Free(node, msg);
            return;
        }
    }
    // Don't error if the old packet protocol was ICMPv6 error or redirect
    icp = (icmp6_hdr *) (oip + 1);

    if ((oip->ip6_nxt == IPPROTO_ICMPV6) &&
        ((oip->ip6_plen < sizeof(icmp6_hdr)) ||
         ((unsigned) packetLen < sizeof(ip6_hdr) + sizeof(char)) ||
         ((icp->icmp6_type & ICMP6_INFOMSG_MASK) == 0) ||
         (icp->icmp6_type == ND_REDIRECT)))
    {

        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_ICMP6_ERROR_OR_REDIRECT_MESSAGE;
        TRACE_PrintTrace(node,msg,TRACE_NETWORK_LAYER,PACKET_IN, &acnData);

        MESSAGE_Free(node, msg);
        return;
    }
    // First formulate ICMPv6 message
    packetLen = sizeof(icmp6_hdr) + packetLen;

    icmpMsg = MESSAGE_Alloc(node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_IPV6,
                            MSG_NETWORK_Icmp6_Error);

    MESSAGE_PacketAlloc(node, icmpMsg, packetLen, TRACE_ICMPV6);//TRACE_ICMPV6

    icmpPayload = MESSAGE_ReturnPacket(icmpMsg);

    memset(icmpPayload, 0, packetLen);

    icp = (icmp6_hdr*) icmpPayload;
    icp->icmp6_type = (unsigned char) type;

    switch (type)
    {
        case ICMP6_PACKET_TOO_BIG:
        {
            icp->icmp6_mtu = arg;
            break;
        }

        case ICMP6_PARAM_PROB:
        {
            icp->icmp6_pptr = arg;
            break;
        }

        case ICMP6_TIME_EXCEEDED:
        {
            icp->icmp6_mtu = 0;
            break;
        }

        case ICMP6_DST_UNREACH:
        {
            switch (code)
            {
                case ICMP6_DST_UNREACH_NOROUTE:
                    break;

                case ICMP6_DST_UNREACH_ADMIN:
                    break;

                case ICMP6_DST_UNREACH_BEYONDSCOPE:
                    break;

                case ICMP6_DST_UNREACH_ADDR:
                    break;

                case ICMP6_DST_UNREACH_NOPORT:
                    break;
            }
        }
        default:
        {
            icp->icmp6_mtu = 0;
            break;
        }
    }

    icp->icmp6_code = (unsigned char) code;


    // Trace sending packet for ICMPV6
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData);

    // Now, copy old IPv6 header in front of ICMPv6 message.
    Ipv6AddIpv6Header(node, icmpMsg, packetLen, oip->ip6_dst, oip->ip6_src,
          IPTOS_PREC_INTERNETCONTROL, IPPROTO_ICMPV6, ND_DEFAULT_HOPLIM);

    icmp6_reflect(node, icmpMsg, NULL, interfaceId);

    MESSAGE_Free(node, msg);

    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : icmp6_reflect
// PURPOSE             :: To reflect the IPv6 packet back to the source
// PARAMETERS          ::
// +node                : Node* node   : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message structure
// +opts                : unsigned char* opts: Option pointer.
// +interfaceId         : int interfaceId   : Index of the concerned Interface
// RETURN               :
// NOTES                : Sending message back to the source.
//---------------------------------------------------------------------------

void
icmp6_reflect(
    Node* node,
    Message* msg,
    unsigned char* opts,
    int interfaceId)
{

    char* payload = MESSAGE_ReturnPacket(msg);

    ip6_hdr* ip = (ip6_hdr*) payload;

    if (IS_ANYADDR6(ip->ip6_src) || IS_MULTIADDR6(ip->ip6_src))
    {
        // Bad address return.
        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_UNIDENTIFIED_SOURCE;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
        MESSAGE_Free(node, msg);
        goto done;
    }

    // Option Processing not done right now.

    Ipv6GetGlobalAggrAddress(node, interfaceId, &ip->ip6_src);
    ip->ip6_hlim = MAXTTL;
    icmp6_send(node, msg, opts, NULL, interfaceId, 0);

done:
    if (opts)
    {
        MEM_free(opts);
    }
}

//---------------------------------------------------------------------------
// FUNCTION             : Icmp6Finalize
// PURPOSE             :: Finalization
// PARAMETERS          ::
// +node                : Node* node    :   Pointer to the Node
// RETURN               : None
// NOTES                : Icmpv6 statistic printing function
//---------------------------------------------------------------------------

void Icmp6Finalize(Node* node)
{
    char buf[MAX_STRING_LENGTH];
    IPv6Data* ipv6 = (IPv6Data*)
                        ((NetworkDataIp*)node->networkData.networkVar)->ipv6;

    Icmp6Data* icmp6 = ipv6->icmp6;

    sprintf(buf, "Number of Router Solicitation Messages Sent = %d",
        icmp6->icmp6stat.icp6s_snd_rtsol);

    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

     sprintf(buf, "Number of Router Advertisement Messages Sent = %d",
                icmp6->icmp6stat.icp6s_snd_rtadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Neighbor Solicitation Messages Sent = %d",
                icmp6->icmp6stat.icp6s_snd_ndsol);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Neighbor Advertisement Messages Sent = %d",
                icmp6->icmp6stat.icp6s_snd_ndadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Redirect Messages Sent = %d",
                icmp6->icmp6stat.icp6s_snd_redirect);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    //--------------------------------------------------------------------//
    //                NDP Message Received Statistics.
    //--------------------------------------------------------------------//
    sprintf(buf, "Number of Router Solicitation Messages Received = %d",
                icmp6->icmp6stat.icp6s_rcv_rtsol);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Router Advertisement Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_rtadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Neighbor Solicitation Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_ndsol);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Neighbor Advertisement Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_ndadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);
    //--------------------------------------------------------------------//
    //                 ICMPv6 Error Related Statistics.
    //--------------------------------------------------------------------//

    sprintf(buf, "Number of Messages Received with Unknown Code = %u",
                icmp6->icmp6stat.icp6s_badcode);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Messages Received with Invalid Length = %u",
                icmp6->icmp6stat.icp6s_badlen);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Destination Unreachable Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_ur_addr);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Invalid Router Solicitation Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_badrtsol);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Invalid Router Advertisement Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_badrtadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Invalid Neighbor Solicitation Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_badndsol);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Invalid Neighbor Advertisement Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_badndadv);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);

    sprintf(buf, "Number of Invalid Redirect Messages Received = %u",
                icmp6->icmp6stat.icp6s_rcv_badredirect);
    IO_PrintStat(
        node,
        "Network",
        "ICMPv6",
        "",
        -1 , // instance Id
        buf);
}

