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
// This file contains functions for sending IPv6 packets
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
#include "partition.h"
#include "ip6_output.h"
#include "network_dualip.h"

#ifdef PAS_INTERFACE
#include "packet_analyzer.h"
#endif

#define DEBUG_IPV6 0

//------------------------------------------------------------------------//
//          IPv6 FRAGMENTATION IS END-TO-END ONLY.
//------------------------------------------------------------------------//

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6FragmentPacket
// PURPOSE             :: Fragment a Ipv6 packet
// PARAMETERS          ::
// +node                : Node* node: pointer to Node
// +msg                 : Message* msg: Pointer to Message Structure
// +mtu                 : int mtu: Maximum Transmission Unit of the circuit.
// +fragmentHead        : FragmetedMsg** fragmentHead: Fragmented message
//                                  list header.
// RETURN               : int : status of fragmentation.
// NOTES                : IPv6 fragmented packet processing function
//---------------------------------------------------------------------------

static int
Ipv6FragmentPacket(
    Node* node,
    Message* msg,
    int mtu,
    FragmetedMsg** fragmentHead)
{
    int off;
    int hlen;
    int unfragmentedLen;
    int fragmentedLen;

    ip6_hdr* originalIpv6Hdr = NULL;
    Message* tmpMsg = NULL;
    FragmetedMsg* fragmentChain = NULL;

    char* tempPayload = NULL;
    unsigned short offset;
    unsigned int curPayloadLen;

    char*  payload = MESSAGE_ReturnPacket(msg);
    int packetLen = 0;
    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    Address sourceAddress;
    Address destinationAddress;
    TosType trafficClass = ALL_PRIORITIES;
    unsigned char protocol;
    unsigned int hLim;

    // Calculate the Unfragmentable Part Length.
    // The Unfragmentable Part consists of the IPv6 header plus any
    // extension headers that must be processed by nodes in route to the
    // destination, that is, all headers up to and including the Routing
    // header if present, else the Hop-by-Hop Options header if present,
    // else no extension headers.
    unfragmentedLen = sizeof(ip6_hdr);
    hlen = sizeof(ip6_hdr) + sizeof(ipv6_fraghdr);


    // Now Calculate the fragmentedLen.
    // The Fragmentable Part of the original packet is divided into
    // fragments, each, except possibly the last one,
    // being an integer multiple of 8 octets long.

    fragmentedLen = ((int)(mtu - hlen) / 8) * 8;

    // originalIpv6Hdr = (ip6_hdr*) MESSAGE_ReturnPacket(msg);
    // Get the copy of the ipv6 header.
    originalIpv6Hdr = (ip6_hdr*) MEM_malloc(sizeof(ip6_hdr));

    memcpy(originalIpv6Hdr, payload, sizeof(ip6_hdr));

    // Remove the Ipv6 header from the original packet.
    Ipv6RemoveIpv6Header(
        node,
        msg,
        &sourceAddress,
        &destinationAddress,
        &trafficClass,
        &protocol,
        &hLim);

    // Get the new payload after removing the ipv6 header.
    packetLen = MESSAGE_ReturnPacketSize(msg);
    payload = MESSAGE_ReturnPacket(msg);


    // Make the first fragment Packet.
    tmpMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           NETWORK_PROTOCOL_IPV6,
                           MSG_NETWORK_Ipv6_Fragment);

    // allocate packet for fragmented part by taking care of original
    // packet and virtual packet.
    if (msg->packetSize >= fragmentedLen)
    {
        MESSAGE_PacketAlloc(
            node,
            tmpMsg,
            fragmentedLen ,
            TRACE_IPV6);
        // Now Make the fragmented Packet. with out virtual packet
        tempPayload = MESSAGE_ReturnPacket(tmpMsg);
        memcpy(tempPayload, payload, fragmentedLen);
    }
    else
    {
        MESSAGE_PacketAlloc(
            node,
            tmpMsg,
            msg->packetSize,
            TRACE_IPV6);
        tempPayload = MESSAGE_ReturnPacket(tmpMsg);
        memcpy(tempPayload, payload, msg->packetSize);
        // Now Make the fragmented Packet. with virtual packet.
        MESSAGE_AddVirtualPayload(
            node,
            tmpMsg,
            fragmentedLen - msg->packetSize);
    }

    //------------------------------------------------------------------------//
    // QULNET'S EXTRA OVERHEAD TO MANAGE BROKEN MESSAGE.
    //------------------------------------------------------------------------//
    tmpMsg->sequenceNumber = msg->sequenceNumber;
    tmpMsg->originatingProtocol = msg->originatingProtocol;
    tmpMsg->protocolType = msg->protocolType;
    tmpMsg->layerType = msg->layerType;
    tmpMsg->numberOfHeaders = msg->numberOfHeaders;
    tmpMsg->isEmulationPacket = msg->isEmulationPacket;

    for (int headerCounter = 0;
        headerCounter < msg->numberOfHeaders;
        headerCounter++)
    {
        tmpMsg->headerProtocols[headerCounter] =
            msg->headerProtocols[headerCounter];
        tmpMsg->headerSizes[headerCounter] = msg->headerSizes[headerCounter];

    }
    MESSAGE_CopyInfo(node, tmpMsg, msg);
    //------------------------------------------------------------------------//
    // END OF QUALNET SPECIFIC WORK.
    //------------------------------------------------------------------------//

    // unfragmented part added here first fragment header and then ipv6 header
    Ipv6AddFragmentHeader(node,
                          tmpMsg,
                          originalIpv6Hdr->ip6_nxt,
                          IP6F_MORE_FRAG ,
                          ipv6->ip6_id);

    // here IPv6 header is added
    Ipv6AddIpv6Header(
            node,
            tmpMsg,
            fragmentedLen + sizeof(ipv6_fraghdr), //hlen + fragmentedLen,
            originalIpv6Hdr->ip6_src,
            originalIpv6Hdr->ip6_dst,
            ip6_hdrGetClass(originalIpv6Hdr->ipv6HdrVcf),
            IP6_NHDR_FRAG,
            originalIpv6Hdr->ip6_hlim);

     ipv6->ip6_stat.ip6s_ofragments++;

     // Now put it into the fragmented list.
    (*fragmentHead) = (FragmetedMsg*) MEM_malloc(sizeof(FragmetedMsg));
    (*fragmentHead)->next = NULL;
    (*fragmentHead)->msg = tmpMsg;
    fragmentChain = (*fragmentHead);

    // Loop through length of segment after first fragment,
    // make new header and copy data of each part and link onto chain.
    for (off = /*unfragmentedLen + */fragmentedLen;
        off < packetLen; off += fragmentedLen)
    {
        tmpMsg = MESSAGE_Alloc(
                    node,
                    NETWORK_LAYER,
                    NETWORK_PROTOCOL_IPV6,
                    MSG_NETWORK_Ipv6_Fragment);


        offset = (unsigned short) off;
        if (packetLen < off + fragmentedLen)
        {
            curPayloadLen = hlen + packetLen - off;
        }
        else
        {
            offset |= IP6F_MORE_FRAG;
            curPayloadLen = hlen + fragmentedLen;
        }

        // packet to curPayloadLen - hlen, because fragment and V6 header
        // size are allocated later but it will allocated when there is
        // no virtual packet else 0 byte is allocated
        // virtual packet is added.
        if (msg->packetSize > off)
        {
            MESSAGE_PacketAlloc(node, tmpMsg,
                curPayloadLen - hlen ,
                TRACE_IPV6);
            // Now Make the fragmented Packet. with out virtual packet
            tempPayload = MESSAGE_ReturnPacket(tmpMsg);
            memcpy(tempPayload, payload + off, curPayloadLen - hlen);
        }
        else
        {
            MESSAGE_PacketAlloc(node, tmpMsg,
                0,
                TRACE_IPV6);
            // Now Make the fragmented Packet. with virtual packet.
            MESSAGE_AddVirtualPayload(node, tmpMsg, curPayloadLen - hlen);
        }

        MESSAGE_CopyInfo(node, tmpMsg, msg);

        // unfragmented part added here first fragment header and then ipv6 header
        Ipv6AddFragmentHeader(node,
                              tmpMsg,
                              originalIpv6Hdr->ip6_nxt,
                              offset,
                              ipv6->ip6_id);

        // Add IPv6 header
        Ipv6AddIpv6Header(
                node,
                tmpMsg,
                curPayloadLen - hlen + sizeof(ipv6_fraghdr),  //curPayloadLen,
                originalIpv6Hdr->ip6_src,
                originalIpv6Hdr->ip6_dst,
                ip6_hdrGetClass(originalIpv6Hdr->ipv6HdrVcf),
                IP6_NHDR_FRAG,
                originalIpv6Hdr->ip6_hlim);

        // Now put it in the fragment chain.
        fragmentChain->next = (FragmetedMsg*)
                                MEM_malloc(sizeof(FragmetedMsg));
        fragmentChain = fragmentChain->next;
        fragmentChain->msg = tmpMsg;
        fragmentChain->next = NULL;

        ipv6->ip6_stat.ip6s_ofragments++;
    } // end of creating all fragments
    MEM_free(originalIpv6Hdr);
    ipv6->ip6_id++;
    return TRUE;
} // end of fragmentation.



//---------------------------------------------------------------------------
// FUNCTION             : ip6PacketDelivertoQueue
// PURPOSE             :: Deliver a ipv6 packet to the queue
// PARAMETERS          ::
// +node                : Node* node : Pointer to Node
// +msg                 : Message* msg : Pointer to the Message structure
// +interfaceID         : int interfaceID : Incoming interface
// +oif                 : int oif : Outgoing interface
// +nextHopLinkAddr     : NodeAddress nextHopLinkAddr : Address of Next Hop
// RETURN               : int: Returns the status.
// NOTES                : Packet deliver to queue function
//---------------------------------------------------------------------------

int ip6PacketDelivertoQueue(
    Node* node,
    Message* msg,
    int interfaceID,
    int oif,
    MacHWAddress& nextHopLinkAddr)
{
    ip6_hdr *ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    if (Ipv6IsMyPacket(node, &(ipHeader->ip6_src)))
    {
        interfaceID = CPU_INTERFACE;
    }

    Ipv6SendPacketOnInterface(node, msg, interfaceID, oif, nextHopLinkAddr);

    return 1;
}


//---------------------------------------------------------------------------
// FUNCTION             : real_ip6_output
// PURPOSE             :: Send the packet in message to queue.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to the Message Structure
// +opts                : optionList* opts : Pointer to the Option List
// +ro                  : route* ro: Pointer to route by which the packet
//                                      will be send.
// +flags               : int flags: Falg, route type
// +imo                 : ip_moptions* imo: Multicast Option pointer
// +interfaceID         : int interfaceID : Index of the concerned interface
// RETURN               : int: Returns status of sending.
// NOTES                : Send the packet in message to queue.
//---------------------------------------------------------------------------

static int
real_ip6_output(
    Node* node,
    Message* msg,
    optionList* opts,
    route* ro,
    int flags,
    ip_moptions* imo,
    int incomingInterface,
    int interfaceID)
{
    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    char* payload = MESSAGE_ReturnPacket(msg);

    ip6_hdr* ip;
    int len;
    int mtu = 0;
    int error = 0;
    in6_addr* dst;
    int oif = interfaceID;
    MacHWAddress nextHopLinkAddr;

    QueuedPacketInfo* infoPtr;

    MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));

    infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

    /* Option header adding is not supported, except fragmentation header.
    if (opts)
    {
    again:
        switch (opts->headerType)
        {
            case IP6_NHDR_IPCP:
            case IP6_NHDR_DOPT:

                // ip6insertOption(msg, &opts, IP6_NHDR_DOPT);
                // falls into
            nextopt:
            default:
                // Option not yet supported:
                opts = opts->nextOption;
                if (opts)
                {
                    goto again;
                }
                break;

             case IP6_NHDR_RT:
                {
                    ipv6_rthdr* rhp;
                    // Update destination address
                    optAny = (opt6_any*)opts->optionPointer;
                    rhp  = (ipv6_rthdr*)(optAny + (sizeof(opt6_any) + 1));
                    // TBD
                }
                break;

            case IP6_NHDR_HOP:
                // fragment (if necessary) before
                break;
        }
    }
    */

    ip = (ip6_hdr*)payload;

#ifdef PAS_INTERFACE
    if (PAS_LayerCheck(node, interfaceID, PACKET_SNIFFER_ETHERNET))
    {
        PAS_IPv6(node, (UInt8 *)ip, NULL, interfaceID);
    }
#endif

    // DUAL-IP: Check whether outgoing interface is virtual Interface
    if (TunnelIsVirtualInterface(node, interfaceID))
    {
        // Encapsulate IPv6 pkt to tunnel it through the v4 tunnel
        return TunnelSendIPv6Pkt(node,
                  msg,
                  imo,
                  interfaceID);

    }
    else if (NetworkIpGetInterfaceType(node, interfaceID) == NETWORK_IPV4)
    {
        // Drop the pkt if the interface is not v4-tunneled and
        // also not connected with an IPv6 network.
        MESSAGE_Free(node, msg);
        return FALSE;
    }

    len = (unsigned int)ip->ip6_plen + sizeof(ip6_hdr);


    // Copy the destination address.
    dst = (in6_addr*)&ro->ro_dst;

    // If this is the source node
    if (flags & IP_ROUTETOIF)
    {
        // if destination is multicast then goto multicast section.
        if (IS_MULTIADDR6(ip->ip6_dst))
        {
            goto mcast;
        }
        oif = Ipv6GetInterfaceIndexFromAddress(node, &ip->ip6_src);

        // If invalid outgoing interface.
        if (oif == -1)
        {
            ipv6->ip6_stat.ip6s_noroute++;
            error = ENETUNREACH;
            MESSAGE_Free(node, msg);
            return (error);
        }
        ip->ip6_hlim = 1;
    }
    else
    {
        // when forwarding the packet
        oif = interfaceID;
    }

    // Multicast Sections.
    mcast:
    if (IS_MULTIADDR6(ip->ip6_dst))
    {
        // See if the caller provided any multicast options
        if (imo != NULL)
        {
            ip->ip6_hlim = (unsigned char) imo->imo_multicast_ttl;

            if (imo->imo_multicast_interface >= 0)
            {
                oif = imo->imo_multicast_interface;
            }
        }
        else
        {
            // else do nothing for now.. ospfv3_start
            // ip->ip6_hlim = IP_DEFAULT_MULTICAST_TTL;
        }

        // Multicasts with a time-to-live of zero may be looped-
        // back, above, but must not be transmitted on a network.
        // Also, multicasts addressed to the loopback interface
        // are not sent -- the above call to ip6_mloopback() will
        // loop back a copy if this host actually belongs to the
        // destination group on the loopback interface.
        if (ip->ip6_hlim == 0)
        {
            MESSAGE_Free(node, msg);
            return (error);
        }
    }

    // Get the linklayer address.
    // Now get the Link Layer Address to send it to mac.
    if (IS_MULTIADDR6(ip->ip6_dst))
    {

        nextHopLinkAddr = GetBroadCastAddress(node, interfaceID);

        COPY_ADDR6(ipv6->broadcastAddr, infoPtr->ipv6NextHopAddr);


    }
    else
    {
        // There is route get the link-layer address.
        if (ro && ro->ro_rt.rt_node)
        {
            nextHopLinkAddr = ro->ro_rt.rt_node->linkLayerAddr;

            infoPtr->ipv6NextHopAddr = ro->ro_rt.rt_node->gateway;

            if (node->guiOption == TRUE)
            {

                NodeAddress nextHopNodeId = 0;
                int interfaceIndex1 = 0;
                Address nextHopIpAddr;
                MAPPING_SetAddress(NETWORK_IPV6, &nextHopIpAddr,
                                                 &infoPtr->ipv6NextHopAddr);
                nextHopNodeId = MAPPING_GetNodeIdFromGlobalAddr(node,
                                               infoPtr->ipv6NextHopAddr);

                interfaceIndex1 =
                          MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                               node,
                                               nextHopIpAddr);
#ifdef EXATA
                if (msg->isEmulationPacket)
                {
                    GUI_Unicast(node->nodeId,
                                nextHopNodeId,
                                GUI_NETWORK_LAYER,
                                GUI_EMULATION_DATA_TYPE,
                                (int)interfaceID,
                                interfaceIndex1,
                                node->getNodeTime());

                }
                else
                {
                    GUI_Unicast(node->nodeId,
                                nextHopNodeId,
                                GUI_NETWORK_LAYER,
                                GUI_DEFAULT_DATA_TYPE,
                                (int)interfaceID,
                                interfaceIndex1,
                                node->getNodeTime());
                }
#else
                GUI_Unicast(node->nodeId,
                            nextHopNodeId,
                            GUI_NETWORK_LAYER,
                            GUI_DEFAULT_DATA_TYPE,
                            (int)interfaceID,
                            interfaceIndex1,
                            node->getNodeTime());
#endif
            }
        }
        else
        {
            ERROR_ReportError(
                "real_ip6_output: Unable to get Linklayer Address\n");
        }
    }

    mtu = Ipv6GetMTU(node, oif);

    // If small enough for interface, can just send directly.
    if (len <= mtu)
    {
        // Got the link-layer address deliver the packet to queue.
        error = ip6PacketDelivertoQueue(
                    node,
                    msg,
                    incomingInterface,
                    //interfaceID,
                    oif,
                    nextHopLinkAddr);
    }
    else
    {
        if (DEBUG_IPV6)
        {
            char srcAddrString[MAX_STRING_LENGTH];
            char destAddrString[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(&ip->ip6_src, srcAddrString);

            IO_ConvertIpAddressToString(&ip->ip6_dst, destAddrString);

            printf("Node %d Packet Size %d is greater than MTU value %d\n",
                node->nodeId,
                len,
                mtu);

            printf("Node %d fragmenting packet with source "
                    "%s destination %s\n",
                node->nodeId,
                srcAddrString,
                destAddrString);
        }

        // for fragmentation
        FragmetedMsg* fragHead = NULL;
        FragmetedMsg* tempFH = NULL;
        if (Ipv6FragmentPacket(node, msg, mtu, &fragHead))
        {
            while (fragHead)
            {
                 error = ip6PacketDelivertoQueue(
                            node,
                            fragHead->msg,
                            //interfaceID,
                            incomingInterface,
                            oif,
                            nextHopLinkAddr);

                tempFH = fragHead;
                fragHead = fragHead->next;
                MEM_free(tempFH);
            }
        }
        MESSAGE_Free(node, msg);
    }
    return error;
}


//-------------------------------------------------------------------------//
// Outgoing Packet Processing
//-------------------------------------------------------------------------//

//---------------------------------------------------------------------------
// FUNCTION             : ip6_output
// PURPOSE             :: IPv6 Packet sending function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +opts                : optionList* opts : Pointer to the Option List
// +ro                  : route* ro: Pointer to route for sending the packet.
// +flags               : int flags: Flag, type of route.
// +imo                 : ip_moptions *imo: Multicast Option Pointer.
// +interfaceID         : int interfaceID : Index of the concerned Interface
// RETURN               : int: Returns status of output.
// NOTES                : IPv6 Packet sending function
//---------------------------------------------------------------------------

int
ip6_output(
    Node* node,
    Message* msg,
    optionList* opts,
    route* ro,
    int flags,
    ip_moptions *imo,
    int incomingInterface,
    int interfaceID)
{
    char* payload = NULL;
    int packetLen;
    ip6_hdr* ip;
    in6_addr* dst;

    if (ro == NULL)
    {
        ERROR_ReportError("ip6_output: Unable to find route\n");
    }

    payload = MESSAGE_ReturnPacket(msg);
    packetLen = MESSAGE_ReturnPacketSize(msg);

    if ((flags & IP_FORWARDING))
    {
        return real_ip6_output(
                    node,
                    msg,
                    opts,
                    ro,
                    flags,
                    imo,
                    incomingInterface,
                    interfaceID);
    }

    ip = (ip6_hdr*) payload;
    dst = (in6_addr*) &ro->ro_dst;

    // Lookup the Route
    if (!SAME_ADDR6(*dst, ip->ip6_dst))
    {
        MESSAGE_Free(node, msg);
        return 0;
//        ERROR_ReportError("destination mismatch");
    }

    if (!IS_MULTIADDR6(ro->ro_dst))
    {
        MacHWAddress tempHWAddress;
        rtalloc(node, ro, tempHWAddress);
    }

    return real_ip6_output(node, msg, opts, ro, flags, imo, incomingInterface, interfaceID);
}


// Right now following function is not used, will be used during
// Hop by hop processing
// Header option processing on outgoing packets.

//---------------------------------------------------------------------------
// FUNCTION             : hd6_outoptions
// PURPOSE             :: Header Option Processing function
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to the Message Structure
// +cp                  : void* cp: Void pointer for header option.
// RETURN               : int: Returns the status.
// NOTES                : Header Option processing function
//---------------------------------------------------------------------------

static int
hd6_outoptions(Message* msg, void* cp)
{
    ipv6_h2hhdr* hp;
    opt6_any* op;
    int len;
    int olen;

    hp = (ipv6_h2hhdr *)cp;
    op = (opt6_any *)&hp->ih6_pad1;
    len = (hp->ih6_hlen + 1) * sizeof(ipv6_h2hhdr) -
            (2 * sizeof(unsigned char));

    while (len > 0)
    {
        if (olen < 0)
            return (1);
        if (olen > len)
            return (1);
        op = (opt6_any *)((char*)op + olen);
        len -= olen;
    }
    return 0;
}

