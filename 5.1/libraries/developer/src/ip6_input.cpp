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
// This file contains functions for receiving/handling different Ipv6 packets
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
#include "ipv6.h"
#include "ip6_input.h"
#include "ip6_icmp.h"
#include "if_ndp6.h"
#include "ip6_output.h"
#include "network_dualip.h"

#ifdef WIRELESS_LIB
#include "routing_aodv.h"
#include "routing_dymo.h"
#endif // WIRELESS_LIB

#ifdef ENTERPRISE_LIB
#include "routing_ospfv3.h"
#endif // ENTERPRISE_LIB

#ifdef ADVANCED_WIRELESS_LIB
#include "dot16_backbone.h"
#endif

#ifdef EXATA
#include "ipnetworkemulator.h"
#include "auto-ipnetworkemulator.h"
#include "record_replay.h"
#endif

#ifdef GATEWAY_INTERFACE
#include "internetgateway.h"
#endif

#ifdef PAS_INTERFACE
#include "packet_analyzer.h"
#endif

#define DEBUG_IPV6 0

//------------------------------------------------------------------------//
//                       OPTION HEADER PROCESSING
//------------------------------------------------------------------------//

//---------------------------------------------------------------------------
// FUNCTION             : ip6_reass
// PURPOSE             :: Take incoming datagram fragment and try to
//                        reassemble it into whole datagram.  If a chain for
//                        reassembly of this datagram already exists, then it
//                        is given as fp; otherwise have to make a chain.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Sturcture
// +fp                  : Ipv6FragQueue* fp: Pointer to fragmentation queue.
// RETURN               : Message*  : Pointer to the Message Structure
// NOTES                : Ressambling message function
//---------------------------------------------------------------------------

static Message*
ip6_reass(Node* node, Message* msg, Ipv6FragQueue* fp)
{
    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    char* payload = NULL;
    int packetLen = 0;
    char* lastPayload = MESSAGE_ReturnPacket(msg);

    int totalLength = 0;
    int totalVirtualPackeLength = 0;
    char* joinedPayload = NULL;
    int lengthToCopy = 0;
    int reassError = 0;
    int hLen = sizeof(ip6_hdr) + sizeof(ipv6_fraghdr);

    Ipv6FragData* tempFragData = NULL;
    Ipv6FragData* prevFragData = NULL;
    Message* joinedMsg = NULL;

    Address sourceAddress;
    Address destinationAddress;
    TosType trafficClass = ALL_PRIORITIES;
    unsigned char protocol;
    unsigned int hLim;

    // First calculate the total packet length to produce the large packet.

    tempFragData = fp->firstMsg;
    // Calculate the first fragment Information.
    payload = MESSAGE_ReturnPacket(tempFragData->msg);
    ip6_hdr* ip6Header = (ip6_hdr*)payload;
    ipv6_fraghdr* frgpHeader = (ipv6_fraghdr*)(ip6Header + 1);

    // Starting fragment offset should be zero.
    if ((frgpHeader->if6_off) != 0)
    {
        reassError = 1;
        //drop all the fragment packets and return
        tempFragData = fp->firstMsg;
        while (tempFragData)
        {
            prevFragData = tempFragData;
            tempFragData = tempFragData->nextMsg;
            ipv6->ip6_stat.ip6s_fragdropped++;
            MESSAGE_Free(node, prevFragData->msg);
            MEM_free(prevFragData);
        }
        ipv6->ip6_stat.ip6s_fragdropped++;
        MESSAGE_Free(node, msg);
        return NULL;
    }

    totalLength += tempFragData->msg->packetSize - sizeof(ip6_hdr) -
                            sizeof(ipv6_fraghdr);
    totalVirtualPackeLength += tempFragData->msg->virtualPayloadSize;
    tempFragData = tempFragData->nextMsg;

    // Then calculate packetsize rest of the fragmented packets.
    while (tempFragData)
    {
        payload = MESSAGE_ReturnPacket(tempFragData->msg);
        ip6Header = (ip6_hdr*)payload;
        frgpHeader = (ipv6_fraghdr*)(ip6Header + 1);
        int currentFragOff = frgpHeader->if6_off;

        // CHECK THE PROPER OFFSET
        if (currentFragOff != (totalLength + totalVirtualPackeLength))
        {
            reassError = 1;
            break;
        }

        totalLength += tempFragData->msg->packetSize - sizeof(ip6_hdr) -
                            sizeof(ipv6_fraghdr);

        totalVirtualPackeLength += tempFragData->msg->virtualPayloadSize;
        tempFragData = tempFragData->nextMsg;
    }

    // Now add the last packet and virtual packet length
    ip6Header = (ip6_hdr*)lastPayload;
    frgpHeader = (ipv6_fraghdr*)(ip6Header + 1);

    if ((int)frgpHeader->if6_off != totalLength + totalVirtualPackeLength)
    {
        reassError = 1;
    }

    totalLength += msg->packetSize - sizeof(ip6_hdr) - sizeof(ipv6_fraghdr);
    totalVirtualPackeLength += msg->virtualPayloadSize;

    if (reassError)
    {
        // Drop all the fragment packets and return
        tempFragData = fp->firstMsg;
        while (tempFragData)
        {
            prevFragData = tempFragData;
            tempFragData = tempFragData->nextMsg;
            ipv6->ip6_stat.ip6s_fragdropped++;
            MESSAGE_Free(node, prevFragData->msg);
            MEM_free(prevFragData);
        }
        ipv6->ip6_stat.ip6s_fragdropped++;
        MESSAGE_Free(node, msg);
        return NULL;
    }

    //Now allocate joined Message data;
    joinedMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           NETWORK_PROTOCOL_IPV6,
                           MSG_NETWORK_Ipv6_Fragment);

    MESSAGE_PacketAlloc(node, joinedMsg, totalLength, TRACE_IPV6);

    // Now Make the reassemble Packet. with virtual packet.
    MESSAGE_AddVirtualPayload(node, joinedMsg, totalVirtualPackeLength);

    joinedPayload = MESSAGE_ReturnPacket(joinedMsg);

    // Now copy all the messages.
    tempFragData = fp->firstMsg;

    // Remove Ipv6 header and Fragment header.
    Ipv6RemoveIpv6Header(
        node,
        tempFragData->msg,
        &sourceAddress,
        &destinationAddress,
        &trafficClass,
        &protocol,
        &hLim);

    MESSAGE_RemoveHeader(
        node,
        tempFragData->msg,
        sizeof(ipv6_fraghdr),
        TRACE_IPV6);
    // end of removing ipv6 and fragment header.

    payload = MESSAGE_ReturnPacket(tempFragData->msg);
    //packetLen = MESSAGE_ReturnPacketSize(tempFragData->msg);
    packetLen = tempFragData->msg->packetSize;

    lengthToCopy = packetLen;
    memcpy(joinedPayload, payload, lengthToCopy);
    ipv6->ip6_stat.ip6s_reassembled++;
//------------------------------------------------------------------------//
    // QULNET'S EXTRA OVERHEAD TO MANAGE TO JOIN MESSAGE.
//------------------------------------------------------------------------//
    joinedMsg->sequenceNumber = tempFragData->msg->sequenceNumber;
    joinedMsg->originatingProtocol = tempFragData->msg->originatingProtocol;
    joinedMsg->protocolType = tempFragData->msg->protocolType;
    joinedMsg->layerType = tempFragData->msg->layerType;
    joinedMsg->numberOfHeaders = tempFragData->msg->numberOfHeaders;
    joinedMsg->isEmulationPacket = tempFragData->msg->isEmulationPacket;

    for (int headerCounter = 0;
        headerCounter < msg->numberOfHeaders;
        headerCounter++)
    {
        joinedMsg->headerProtocols[headerCounter] =
            tempFragData->msg->headerProtocols[headerCounter];
        joinedMsg->headerSizes[headerCounter] =
            tempFragData->msg->headerSizes[headerCounter];

    }
    MESSAGE_CopyInfo(node, joinedMsg, tempFragData->msg);
//------------------------------------------------------------------------//
    // END OF QUALNET SPECIFIC WORK.
//------------------------------------------------------------------------//
    // Go for next processing.
    joinedPayload += lengthToCopy;
    prevFragData = tempFragData;
    tempFragData = tempFragData->nextMsg;
    MESSAGE_Free(node, prevFragData->msg);
    MEM_free(prevFragData);

    while (tempFragData)
    {
         payload = MESSAGE_ReturnPacket(tempFragData->msg);

         packetLen = tempFragData->msg->packetSize;
         lengthToCopy = packetLen - hLen;

         if (lengthToCopy > 0)
         {
             memcpy(joinedPayload, payload + hLen, lengthToCopy);
             joinedPayload += lengthToCopy;
         }
         ipv6->ip6_stat.ip6s_reassembled++;

         prevFragData = tempFragData;
         tempFragData = tempFragData->nextMsg;

         MESSAGE_Free(node, prevFragData->msg);
         MEM_free(prevFragData);
    }

    // Now add the last Message.
    lengthToCopy = msg->packetSize - hLen;

    if (lengthToCopy > 0)
    {
        memcpy(joinedPayload, lastPayload + hLen, lengthToCopy);
    }

    Ipv6AddIpv6Header(
        node,
        joinedMsg,
        totalLength + totalVirtualPackeLength,
        ip6Header->ip6_src,
        ip6Header->ip6_dst,
        ip6_hdrGetClass(ip6Header->ipv6HdrVcf),
        frgpHeader->if6_nh,
        ip6Header->ip6_hlim);

    MESSAGE_Free(node, msg);
    return joinedMsg;
}

//---------------------------------------------------------------------------
// FUNCTION             : frg6_delete
// PURPOSE             :: This function deletes all the fragmented packet.
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node
// +ipv6                : IPv6Data* ipv6: Ipv6 data pointer of node.
// +prevFp              : Ipv6FragQueue** prevFp: Pointer to the pointer of
//                                      previous fragment queue.
// +fp                  : Ipv6FragQueue** fp: Pointer to the pointer of
//                                      fragment queue.
// RETURN               : None
// NOTES                : fragmented header processing function
//---------------------------------------------------------------------------

static void
frag6_delete(
    Node* node,
    IPv6Data* ipv6,
    Ipv6FragQueue** prevFp,
    Ipv6FragQueue** fp)
{
    Ipv6FragQueue* tempFp = NULL;
    Ipv6FragData* tempFrg = (*fp)->firstMsg;
    Ipv6FragData* grbFrg = NULL;
    while (tempFrg)
    {
        grbFrg = tempFrg;
        tempFrg = tempFrg->nextMsg;
        MESSAGE_Free(node, grbFrg->msg);
        MEM_free(grbFrg);
        ipv6->ip6_stat.ip6s_fragtimeout++;
    }
    if ((*prevFp))
    {
        (*prevFp)->next = (*fp)->next;
    }
    else
    {
        ipv6->fragmentListFirst = (*fp)->next;
    }
    tempFp = (*fp);
    (*fp) = (*fp)->next;
    MEM_free(tempFp);
}
//---------------------------------------------------------------------------
// FUNCTION             : frg6_input
// PURPOSE             :: Fragment header input processing
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node
// +msg                 : Message* msg  : Pointer to Message Structure
// +opts                : optionList* opts : Pointer to Option List
// +interfaceId         : int interfaceId  : Value of the Interface index
// RETURN               : None
// NOTES                : fragmented header processing function
//---------------------------------------------------------------------------

static void
frg6_input(Node* node, Message* msg, optionList* opts, int interfaceId)
{
    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    ip6_hdr* ip = (ip6_hdr *) payload;
    ipv6_fraghdr* frgp = (ipv6_fraghdr*) (ip + 1);

    int mff;
    Ipv6FragQueue* prevFp = NULL;
    Ipv6FragQueue* fp = ipv6->fragmentListFirst;

    Message* joinedMsg = NULL;

    // Reassemble, first pullup headers.
    if ((unsigned) packetLen < sizeof(ip6_hdr) + sizeof(ipv6_fraghdr))
    {
        ipv6->ip6_stat.ip6s_toosmall++;
        MESSAGE_Free(node, msg);
        return;
    }

    // Make sure that fragments have a data length
    // that's a non-zero multiple of 8 bytes.
    if ((frgp->if6_off & IP6F_MORE_FRAG) &&
        ((ip->ip6_plen <= sizeof(ipv6_fraghdr)) ||
        ((ip->ip6_plen & 0x7) != 0)))
    {
         ipv6->ip6_stat.ip6s_toosmall++;
         MESSAGE_Free(node, msg);
         return;
    }

    while (fp)
    {
        // Look for queue of fragments of this datagram.
        if (frgp->if6_id == fp->ip6Frg_id &&
            SAME_ADDR6(ip->ip6_src, fp->ip6Frg_src) &&
            SAME_ADDR6(ip->ip6_dst, fp->ip6Frg_dst) &&
            frgp->if6_nh == fp->ip6Frg_nh)
        {
            break;
        }
        // Delete all the fragmented packets whose time has expired.
        if ((int)(node->getNodeTime() - fp->fragHoldTime) >= 0)
        {
            frag6_delete(node, ipv6, &prevFp, &fp);
           // printf("Fragment time expired Frag Id %u \n", fp->ip6Frg_id);
        }// end of deleting.
        else
        {
            prevFp = fp;
            fp = fp->next;
        }
    }

    // Adjust ip6_plen to not reflect header, if more fragments are
    // expected, set ip6_nxt to next header type.
    // ip->ip6_plen -= sizeof(ipv6_fraghdr);
    ip->ip6_nxt = frgp->if6_nh;

    unsigned char nextHdrType = ip->ip6_nxt;

    mff = frgp->if6_off & IP6F_MORE_FRAG;

    if (mff)
    {
        frgp->if6_off &= ~IP6F_MORE_FRAG;

        // check if the fragment is in bound.
        if ((int)(frgp->if6_off) + (int)ip->ip6_plen > IP_MAXPACKET)
        {
            ipv6->ip6_stat.ip6s_toosmall++;
            MESSAGE_Free(node, msg);
            return;
        }
    }

    // If datagram marked as having more fragments add it in the
    // fragment list.
    if (mff)
    {
        ipv6->ip6_stat.ip6s_fragments++;
        if (fp)
        {
            fp->lastMsg->nextMsg =
                (Ipv6FragData*) MEM_malloc(sizeof(Ipv6FragData));
            fp->lastMsg = fp->lastMsg->nextMsg;
        }
        else
        {
            if (!prevFp)
            {
                ipv6->fragmentListFirst =
                    (Ipv6FragQueue*) MEM_malloc(sizeof(Ipv6FragQueue));
                fp = ipv6->fragmentListFirst;
            }
            else
            {
                prevFp->next =
                    (Ipv6FragQueue*) MEM_malloc(sizeof(Ipv6FragQueue));
                fp = prevFp->next;
            }
            fp->firstMsg =
                (Ipv6FragData*) MEM_malloc(sizeof(Ipv6FragData));
            fp->lastMsg = fp->firstMsg;
            fp->ip6Frg_id = frgp->if6_id;
            COPY_ADDR6(ip->ip6_src, fp->ip6Frg_src);
            COPY_ADDR6(ip->ip6_dst, fp->ip6Frg_dst);
            fp->ip6Frg_nh = frgp->if6_nh;
            fp->fragHoldTime = node->getNodeTime() + ipv6->ipFragHoldTime;
            fp->next = NULL;
        }

        fp->lastMsg->nextMsg = NULL;
        fp->lastMsg->msg = msg;
        return ;
    }
    else // This is the last fragment packet so try to ressemble it.
    {
        if (fp)
        {
            // Join all the  fragmented packets then return.
            ipv6->ip6_stat.ip6s_fragments++;
            joinedMsg = ip6_reass(node, msg, fp);

            // Delete the fragment queue head
            if (ipv6->fragmentListFirst == fp)
            {
                ipv6->fragmentListFirst = fp->next;
            }
            else
            {
                prevFp->next = fp->next;
            }
            MEM_free(fp);
        }
        else
        {
            // Received but drop if as first packet not arrived.
            ipv6->ip6_stat.ip6s_fragments++;
            ipv6->ip6_stat.ip6s_fragdropped++;
            MESSAGE_Free(node, msg);
            return;
        }
    }

    // Now Process the reassemble message.
    if (joinedMsg)
    {
        ip6_deliver(node, joinedMsg, opts, interfaceId, nextHdrType);
    }
    return;
}


// May required during further option processing, right now not required
// Header option processing on incoming packets.

//---------------------------------------------------------------------------
// FUNCTION             : hd6_inoptions
// PURPOSE             :: Header processing of incoming packets
// PARAMETERS          ::
// +msg                 : Message* msg : Pointer to Message structure
// +opts                : optionList* opts : Pointer to Option List
// +alert               : int *alert: pointer to alerting message.
// RETURN               : int: return status.
// NOTES                : Header option processing function
//---------------------------------------------------------------------------

int
hd6_inoptions(Message* msg, optionList* opts, int *alert)
{
    ipv6_h2hhdr* hp;
    opt6_any* op;
    int len;
    int olen = 0;
    int errpptr = sizeof(ip6_hdr);

    hp = (ipv6_h2hhdr *)opts->optionPointer ;
    op = (opt6_any *)&hp->ih6_pad1;
    len = ((hp->ih6_hlen + 1) * sizeof(ipv6_h2hhdr)) -
        (2 * sizeof(unsigned char));

    while (len > 0)
    {
      /*if (olen < 0)
        {
            return (1);
        }*/
        if (olen > len)
        {
            errpptr += (int)((char*)&op->o6any_len - (char*)hp);
            // Insert Options.
            return (1);
        }
        op = (opt6_any *)((char*)op + olen);
        len -= olen;
    }
    return (0);
}


// Hop-by-Hop header input processing. Currently not implemented.

//---------------------------------------------------------------------------
// FUNCTION             : hop6_input
// PURPOSE             :: hop by hop option header processing function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : Pointer to Message Structure
// +arg                 : optionList* arg : Pointer to Option List
// +interfaceId         : int interfaceId : Index of the concerned interface
// RETURN               : None
// NOTES                : hop by hop processing function
//---------------------------------------------------------------------------

void
hop6_input(Node* node, Message* msg, optionList* arg, int interfaceId)
{
    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    optionList* opts = arg;
    ip6_hdr* ip = (ip6_hdr*)payload;
    ipv6_h2hhdr* hp = (ipv6_h2hhdr *) (ip + 1);

    int len  = (hp->ih6_hlen + 1) * sizeof(ipv6_h2hhdr);
    // int alert = 0;


    if ((unsigned) packetLen < sizeof(ip6_hdr) + sizeof(ipv6_h2hhdr))
    {
        ipv6->ip6_stat.ip6s_toosmall++;
        if (opts)
        {
            MEM_free(opts);
        }
        return;
    }

    if ((len > ip->ip6_plen) || (len + (signed)sizeof(ip6_hdr) > packetLen))
    {
        ipv6->ip6_stat.ip6s_toosmall++;
        if (opts)
        {
            MEM_free(opts);
        }
        MESSAGE_Free(node, msg);
        return;
    }

   /* ip->ip6_nxt = hp->ih6_nh;
    hp->ih6_nh = 0;
    ip->ip6_plen -= len;

    opts = ip6SaveOption(msg, &opts);

    if (opts && hd6_inoptions(msg, opts, &alert))
    {
        return;
    }

    ip = (ip6_hdr *)payload;

    // Switch out to protocol's input routine.
    if (ip->ip6_nxt == IP6_NHDR_HOP)
    {
        //icmp6_errparam(node, msg, opts);
        return;
    }

    //ip6_deliver(node, msg, opts, interfaceId);
    return;*/
}


//---------------------------------------------------------------------------
// FUNCTION             : ip6_forward
// PURPOSE             :: IPv6 packet forwarding function
// PARAMETERS          ::
// +node                : Node* node : Pointer to Node
// +msg                 : Message* msg : Pointer to Message Structure
// +opt                 : optionList* opt : Pointer to the Option List
// +interfaceId         : int interfaceId : Id of the concerned Interface
// + previousHopAddr....: MacHWAddress * previousHopAddr mac address of previous hop
// RETURN               : None
// NOTES                : IPv6 packet forwarding function
//---------------------------------------------------------------------------

static void
ip6_forward(
    Node* node,
    Message* msg,
    optionList* opt,
    int interfaceId,
    MacHWAddress* previousHopAddr)
{
    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    NetworkDataIp* ipPtr = (NetworkDataIp *) node->networkData.networkVar;
    char* payload = MESSAGE_ReturnPacket(msg);
    ip6_hdr *ip = (ip6_hdr *)payload;
    BOOL packetWasRouted = FALSE;
    Ipv6RouterFunctionType routerFunction = NULL;
    ActionData acnData;

    Message* mcopy = NULL;
    route ip6forward_rt;

    int error;
    // int type = 0;
    // int code = 0;
    // int mtu = 0;

    in6_addr dest;
    MacHWAddress desten;
    int incomingInterface = interfaceId;

    // Trace sending packet, when packet is forwarded.
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER,
              PACKET_OUT, &acnData, NETWORK_IPV6);


    //Check for multicast address.
    if (IS_MULTIADDR6(ip->ip6_dst) ||
        IS_ANYADDR6(ip->ip6_src))
    {
        ipv6->ip6_stat.ip6s_cantforward++;

        //Trace drop
        acnData.actionType = DROP;
        acnData.actionComment = DROP_UNREACHABLE_DEST;
        TRACE_PrintTrace(node,msg,TRACE_NETWORK_LAYER,PACKET_IN, &acnData);

        MESSAGE_Free(node, msg);
        return;
    }
    if (ip->ip6_hlim <= IPTTLDEC)
    {
        icmp6_error(node, msg, ICMP6_TIME_EXCEEDED,
                ICMP6_TIME_EXCEED_TRANSIT, 0, interfaceId);
        //MESSAGE_Free(node, msg);
        return;
    }

#ifdef EXATA
        if ((incomingInterface != CPU_INTERFACE)
            && (node->macData[incomingInterface])
            && (node->macData[incomingInterface]->isIpneInterface))
        {
            if ((NetworkIpGetUnicastRoutingProtocolType(node,
                                       incomingInterface,
                                       NETWORK_IPV6)
                                                  == ROUTING_PROTOCOL_NONE))
            {
                    if (AutoIPNE_ForwardFromNetworkLayer(node,
                                                         incomingInterface,
                                                         msg))
                    {
                        return;
                    }
            }
        }
        // this code will be called only if this node is not an ipne interface
        // i.e.replay mode is run without mapping this node as an external
        // node
        else if ((incomingInterface != CPU_INTERFACE)
                 && (incomingInterface != ANY_INTERFACE)
                 && (node->macData[incomingInterface])
                 && (node->macData[incomingInterface]->isReplayInterface))
        {

            if (node->partitionData->rrInterface->
                                         ReplayForwardFromNetworkLayer(node,
                                                          incomingInterface,
                                                          msg))
            {
                return;
            }
        }
#endif


    // Forward the packet.
    mcopy = msg;

    ip->ip6_hlim -= IPTTLDEC;

    COPY_ADDR6(ip->ip6_dst, dest);

    routerFunction = Ipv6GetRouterFunction(node, interfaceId);

    if (routerFunction && IS_MULTIADDR6(dest) == FALSE)
    {
        in6_addr ipv6PreviousHopAddr;
        memset(&ipv6PreviousHopAddr, 0 , sizeof(in6_addr));

        if (MAC_IsBroadcastHWAddress(previousHopAddr))
        {
            COPY_ADDR6(ipv6->broadcastAddr, ipv6PreviousHopAddr);
        }
        else
        {
            radix_GetNextHopFromLinkLayerAddress(
                    node,
                    &ipv6PreviousHopAddr,
                    previousHopAddr);
        }

        (*routerFunction)(
            node,
            msg,
            dest,
            ipv6PreviousHopAddr,
            &packetWasRouted);
    }

    if (!packetWasRouted)
    {
        error = ndp6_resolve(
                    node,
                    incomingInterface,
                    &interfaceId,
                    &ip6forward_rt.ro_rt,
                    msg,
                    &dest);
    }

    return;
   /*
    // Error checking will be done when tcp and link fault will be there
    // Check error status.
    if (error)
    {
        ipv6->ip6_stat.ip6s_cantforward++;
        ipv6->ip6_stat.ip6s_forward--;
    }
    else
    {
        if (!type)
        {
            return;
        }
    }
    // if message is freed no need to send error response.
    if (mcopy == NULL)
    {
        return;
    }

    switch (error)
    {
        case 0:
            {
                // Forwarded, but need redirect
                //if (type == ND_REDIRECT)
                //  redirect6_output(mcopy, rt);
                //return;
            }
        case ENETUNREACH:
        case EHOSTUNREACH:
        case ENETDOWN:
        case EHOSTDOWN:
        default:
            {
                type = ICMP6_DST_UNREACH;
                code = ICMP6_DST_UNREACH_ADDR;
                break;
            }
        case EMSGSIZE:
            {
                type = ICMP6_PACKET_TOO_BIG;
                ipv6->ip6_stat.ip6s_toobig++;
                if (mtu == 0)
                {
                    mtu = Ipv6GetMTU(node, interfaceId);
                }
                break;
            }
        case ENOBUFS:
            {
                MEM_free(mcopy);
                return;
            }
    } // end of switch checking error codes
    icmp6_error(node, mcopy, type, code, mtu, interfaceId);
    return;*/
}


//---------------------------------------------------------------------------
// FUNCTION             : ip6_deliver
// PURPOSE             :: IPv6 packet deliver function
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +opts                : optionList* opts : Pointer to the Option List
// +interfaceId         : int interfaceId : Id of the concerned interface
// +headerValue         : unsigned char: Value of ipv6 next header
// RETURN               : None
// NOTES                : IPv6 packet deliver function
//---------------------------------------------------------------------------

void ip6_deliver(
    Node* node,
    Message* msg,
    optionList* opts,
    int interfaceId,
    unsigned char headerValue)
{
    IPv6Data* ipv6 = (IPv6Data*) node->networkData.networkVar->ipv6;

    Address destAddress;
    in6_addr sourceAddress;
    TosType priority;
    unsigned char protocol;
    unsigned int hLim;
    int mappedInterfaceIndex = interfaceId;
    char* payload = MESSAGE_ReturnPacket(msg);
    ip6_hdr* ip = (ip6_hdr*)payload;

#ifdef EXATA
    // If the destination node in EXata has more than one interface and is
    // mapped to an operational host on one of its interfaces then
    // interfaceIndex,which is incomingInterface will not work.
    // The code below checks which interface has the destination IP address and
    // references that in the EXata code accordingly.

    if (node->numberInterfaces > 1)
    {
        if (IS_MULTIADDR6(ip->ip6_dst))
        {
            mappedInterfaceIndex = interfaceId;
        }
        else
        {
            mappedInterfaceIndex = Ipv6GetInterfaceIndexFromAddress(node,
                                                               &ip->ip6_dst);
        }
    }

    // If this is an external node then send the packet to the
    // operational network if we are doing true emulation

    if ((mappedInterfaceIndex != CPU_INTERFACE) &&
        (mappedInterfaceIndex != ANY_INTERFACE) &&
        (node->macData[mappedInterfaceIndex]) &&
        (node->macData[mappedInterfaceIndex]->isIpneInterface))
    {
#ifdef HITL_INTERFACE
        if ((node->isHitlNode == TRUE) 
            && (ipHeader->ip6_nxt !=  IPPROTO_OSPF)
            && (ipHeader->ip6_nxt !=  IPPROTO_PIM)
            && (ipHeader->ip6_nxt !=  IPPROTO_IGMP))
        {
            HITL_ForwardToHITL(node, mappedInterfaceIndex, msg);
            return;

        }
        else
#endif
        if (node->partitionData->isAutoIpne)
        {
            if (AutoIPNE_ForwardFromNetworkLayer(node,
                                                 mappedInterfaceIndex,
                                                 msg))
            {
                return;
            }
        }
    }
    // this code will be called only if this node is not an ipne interface
    // i.e.replay mode is run without mapping this node as an external
    // node
    else if ((mappedInterfaceIndex != CPU_INTERFACE) &&
            (mappedInterfaceIndex != ANY_INTERFACE) &&
            (node->macData[mappedInterfaceIndex]) &&
            (node->macData[mappedInterfaceIndex]->isReplayInterface))
    {

        if (node->partitionData->rrInterface->
                                        ReplayForwardFromNetworkLayer(node,
                                                       mappedInterfaceIndex,
                                                       msg))
        {
            return;
        }
    }
#endif
    switch (headerValue)
    {
        case IP6_NHDR_HOP:
        {
            // Hop-by-Hop option header not supported yet.
            break;
        }
        case IP6_NHDR_RT:
        {
            // Routing option header not checked yet.
            break;
        }
        case IP6_NHDR_FRAG:
        {
            // Fragment header processing.
            frg6_input(node, msg, opts, interfaceId);
            return;
        }
        case IP6_NHDR_DOPT:
        {
            // Destination Option Header not supported yet.
            break;
        }
        case IP6_NHDR_NONH:
        {
            break;
        }
        case IPPROTO_ICMPV6:
        {
            // ICMPv6 Message send it to ICMPv6 block.
            icmp6_input(node, msg, 0, interfaceId);
            break;
        }
        case IPPROTO_UDP:
        {
            // UDP Message Send it to UDP Block.
            Address sourceAddress;
            Address destinationAddress;
            TosType trafficClass = ALL_PRIORITIES;
            unsigned char protocol;
            unsigned int hLim;

            if (DEBUG_IPV6)
            {
                printf("Node: %d Received UDP packet\n", node->nodeId);
            }

            Ipv6RemoveIpv6Header(
                node,
                msg,
                &sourceAddress,
                &destinationAddress,
                &trafficClass,
                &protocol,
                &hLim);

            // Send to UDP
            Ipv6SendToUdp(node, msg, trafficClass, sourceAddress,
                destinationAddress, interfaceId);
            break;
        }
        case IPPROTO_TCP:
        {
            // TCP Message Send it to TCP Block.
            Address sourceAddress;
            Address destinationAddress;
            TosType trafficClass = 0;
            unsigned char protocol;
            unsigned int hLim;

            if (DEBUG_IPV6)
            {
                printf("Node: %d Received TCP packet\n", node->nodeId);
            }



            Ipv6RemoveIpv6Header(
                node,
                msg,
                &sourceAddress,
                &destinationAddress,
                &trafficClass,
                &protocol,
                &hLim);

            // Send to TCP
            Ipv6SendToTCP(node, msg, trafficClass, sourceAddress,
                destinationAddress, interfaceId);
            break;
        }
        case IPPROTO_IPV6:
        {
            // When a packet is received with this type of protocol,
            // it means an IPv6-tunneled IPv4 pkt is encapsulated within
            // the IPv6 pkt.

            if (node->networkData.networkProtocol == DUAL_IP)
            {
                TunnelHandleIPv4Pkt(node, msg, interfaceId);
            }
            else
            {
                // Since the node is not Dual-IP enabled, drop the packet.
                ipv6->ip6_stat.ip6s_noproto++;


            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_QUEUE_OVERFLOW;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_NETWORK_LAYER,
                             PACKET_OUT,
                             &acnData);
            MESSAGE_Free(node, msg);

            }

            break;
        }
#ifdef ENTERPRISE_LIB
        case IP6_NHDR_OSPF:
        {
            Address address;

            Ipv6RemoveIpv6Header(node,
                                msg,
                                &address,
                                &destAddress,
                                &priority,
                                &protocol,
                                &hLim);

            COPY_ADDR6(address.interfaceAddr.ipv6, sourceAddress);

            if (NetworkIpGetUnicastRoutingProtocolType(
                node,interfaceId, NETWORK_IPV6) == ROUTING_PROTOCOL_OSPFv3)
            {
                Ospfv3HandleRoutingProtocolPacket(node,
                                                  msg,
                                                  sourceAddress,
                                                  interfaceId);
            }
            else
            {
                MESSAGE_Free(node, msg);
            }
            break;
        }
#endif // ENTERPRISE_LIB
#ifdef WIRELESS_LIB
        case IPPROTO_AODV:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(
                node, interfaceId, NETWORK_IPV6) == ROUTING_PROTOCOL_AODV6)
            {
                Address srcAddress;

                Ipv6RemoveIpv6Header(
                    node,
                    msg,
                    &srcAddress,
                    &destAddress,
                    &priority,
                    &protocol,
                    &hLim);

                //hop-limit should not be decreased here
                //aodv would handle it
                AodvHandleProtocolPacket(
                    node,
                    msg,
                    srcAddress,
                    destAddress,
                    hLim,
                    interfaceId);
            }
            else
            {

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment =
                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData);
               MESSAGE_Free(node, msg);
            }
            break;
        }
        case IPPROTO_DYMO:
        {
            if (NetworkIpGetUnicastRoutingProtocolType(
                node, interfaceId, NETWORK_IPV6) == ROUTING_PROTOCOL_DYMO6)
            {
                Address srcAddress;

                Ipv6RemoveIpv6Header(
                    node,
                    msg,
                    &srcAddress,
                    &destAddress,
                    &priority,
                    &protocol,
                    &hLim);

                DymoHandleProtocolPacket(
                    node,
                    msg,
                    srcAddress,
                    destAddress,
                    interfaceId);

            }
             else
            {

                //Trace drop
                ActionData acnData;
                acnData.actionType = DROP;
                acnData.actionComment =
                    DROP_PROTOCOL_UNAVAILABLE_AT_INTERFACE;
                TRACE_PrintTrace(node,
                                 msg,
                                 TRACE_NETWORK_LAYER,
                                 PACKET_IN,
                                 &acnData);
            }
            MESSAGE_Free(node, msg);
            break;
        }
#endif // WIRELESS_LIB

#ifdef ADVANCED_WIRELESS_LIB
        case IPPROTO_DOT16:
        {
            Address sourceAddress;
            Address destinationAddress;
            TosType trafficClass = 0;
            unsigned char protocol;
            unsigned int hLim;

            if (DEBUG_IPV6)
            {
                printf("Node: %d Received DOT16 packet\n", node->nodeId);
            }

            Ipv6RemoveIpv6Header(
                node,
                msg,
                &sourceAddress,
                &destinationAddress,
                &trafficClass,
                &protocol,
                &hLim);
            Dot16BackboneReceivePacketOverIp(node, msg, sourceAddress);
             break;
        }
#endif
#ifdef GATEWAY_INTERFACE
        case IPPROTO_INTERNET_GATEWAY:
        {
            Address sourceAddress;
            Address destinationAddress;
            TosType trafficClass = 0;
            unsigned char protocol;
            unsigned int hLim;

            if (DEBUG_IPV6)
            {
                printf("Node: %d Received packet for gateway\n", node->nodeId);
            }

            Ipv6RemoveIpv6Header(
                node,
                msg,
                &sourceAddress,
                &destinationAddress,
                &trafficClass,
                &protocol,
                &hLim);
            GATEWAY_ForwardToIpv6InternetGateway(node, interfaceId, msg);
            break;
        }
#endif
    }
    return;
} // end of ip6_deliver function.


//---------------------------------------------------------------------------
// FUNCTION             : ip6_input
// PURPOSE             :: IPv6 input routine. If fragmented try to reassemble.
//                        Process options.  Pass to next level.
// PARAMETERS          ::
// +node                : Node* node : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message Structure
// +arg                 : void*        : Option argument
// +interfaceId         : int interfaceId : Index of the concerned Interface
// lastHopAddr
// RETURN               : None
// NOTES                : Ipv6 received packet processing function
//---------------------------------------------------------------------------

void
ip6_input(
    Node* node,
    Message* msg,
    void* arg,
    int interfaceId,
    MacHWAddress* lastHopAddr)
{
    IPv6Data* ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    char* payload = MESSAGE_ReturnPacket(msg);
    int packetLen = MESSAGE_ReturnPacketSize(msg);

    optionList* opts = (optionList*)arg;
    ip6_hdr* ip = (ip6_hdr *)payload;
    in6_addr ip6_addr;
    BOOL packetWasRouted = FALSE;
    Ipv6RouterFunctionType routerFunction = NULL;
    MacHWAddress tempHWAddress;

    // Option processing is not done in this version
    // except fragmentation.

    ipv6->ip6_stat.ip6s_total++;

    if (packetLen < (signed) (sizeof (ip6_hdr)))
    {
        ipv6->ip6_stat.ip6s_toosmall++;

        if (DEBUG_IPV6)
        {
            printf("ip6_input: packetLen < sizeof (ip6_hdr)\n");
        }
        return;
    }

    Ipv6GetGlobalAggrAddress(node, interfaceId, &ip6_addr);

    if (IS_ANYADDR6(ip6_addr) && !IS_MULTIADDR6(ip->ip6_dst))
    {

        if (DEBUG_IPV6)
        {
            printf("ip6_input:  (IS_ANYADDR6(ip6_addr) && "
                "!IS_MULTIADDR6(ip->ip6_dst))\n");
        }
        goto bad;
    }

    if (ip6_hdrGetVersion(ip->ipv6HdrVcf) != IPV6_VERSION)
    {
        ipv6->ip6_stat.ip6s_badvers++;

        if (DEBUG_IPV6)
        {
            printf("ip6_input: IP header version != IPV6_VERSION)\n");
        }
        goto bad;
    }

    // Check source address.
    if (IS_MULTIADDR6(ip->ip6_src) ||
        (in6_isanycast(node, &ip->ip6_src) == IP6ANY_ANYCAST))
    {
        ipv6->ip6_stat.ip6s_badsource++;

        if (DEBUG_IPV6)
        {
            printf("(IS_MULTIADDR6(ip->ip6_src) ||"
                "(in6_isanycast(node, &ip->ip6_src) == IP6ANY_ANYCAST))\n");
        }
        goto bad;
    }

    // Check unspecified destination
    if (IS_ANYADDR6(ip->ip6_dst))
    {
        ipv6->ip6_stat.ip6s_badsource++;

        if (DEBUG_IPV6)
        {
                printf("IS_ANYADDR6(ip->ip6_dst)\n");
        }

        goto bad;
    }

    // Check loopback addresses
    if (Ipv6IsLoopbackAddress(node, ip->ip6_src)
        || Ipv6IsLoopbackAddress(node, ip->ip6_dst))
    {
        ipv6->ip6_stat.ip6s_badsource++;

#ifdef  DEBUG_IPV6
        printf("ip6_input: IS_LOOPADDR6(ip->ip6_src) || "
            "IS_LOOPADDR6(ip->ip6_dst))\n");
#endif
        goto bad;
    }

    // Check buffer length and trim extra.
    if ((unsigned)packetLen < (sizeof(ip6_hdr) + ip->ip6_plen))
    {
        ipv6->ip6_stat.ip6s_tooshort++;

#ifdef  DEBUG_IPV6
        printf("ip6_input:packetLen < "
            "(sizeof(ip6_hdr) + ip->ip6_plen))\n");
#endif
        goto bad;
    }

    if ((ip->ip6_plen == 0) && (ip->ip6_nxt == IP6_NHDR_HOP))
    {
        ipv6->ip6_stat.ip6_invalidHeader++;
        if (DEBUG_IPV6)
        {
            printf("((ip->ip6_plen == 0) && "
                "(ip->ip6_nxt == IP6_NHDR_HOP))\n");
        }
        goto bad;
    }

#ifdef PAS_INTERFACE
    if (PAS_LayerCheck(node, interfaceId, PACKET_SNIFFER_ETHERNET))
    {
        PAS_IPv6(node, (UInt8 *)ip, lastHopAddr, interfaceId);
    }
#endif

    // Check my list of addresses, to see if the packet is for mine.
    if (Ipv6IsMyPacket(node, &ip->ip6_dst))
    {
        routerFunction = Ipv6GetRouterFunction(node, interfaceId);
        if (IS_MULTIADDR6(ip->ip6_dst) == FALSE
            && (routerFunction))
        {
            in6_addr dest;

            in6_addr ipv6PreviousHopAddr;

            COPY_ADDR6(ip->ip6_dst, dest);
            if (MAC_IsBroadcastHWAddress(lastHopAddr))
            {
                COPY_ADDR6(ipv6->broadcastAddr, ipv6PreviousHopAddr);
            }
            else if (!radix_GetNextHopFromLinkLayerAddress(
                        node,
                        &ipv6PreviousHopAddr,
                        lastHopAddr))
            {
                goto ours;
            }

            (*routerFunction)(
                node,
                msg,
                dest,
                ipv6PreviousHopAddr,
                &packetWasRouted);
        }

        if (!packetWasRouted)
        {
            goto ours;
        }
    }

    if (IS_MULTIADDR6(ip->ip6_dst))
    {
        RouteThePacketUsingMulticastForwardingTable(
            node,
            MESSAGE_Duplicate(node, msg),
            interfaceId,
            NETWORK_IPV6);

        ipv6->ip6_stat.ip6s_forward++;

        if (Ipv6IsPartOfMulticastGroup(node, ip->ip6_dst))
        {
            goto ours;
        }

        MESSAGE_Free(node, msg);

        return;
    }

    ip6_forward(node, msg, 0, interfaceId, lastHopAddr);
    return;

ours:
     // Switch out to protocol's input routine.
    ipv6->ip6_stat.ip6s_delivered++;
    Ipv6SendOnBackplane(
        node,
        msg,
        interfaceId,
        CPU_INTERFACE,
        tempHWAddress,   //0
        opts);
    return;

bad:
    ipv6->ip6_stat.ip6s_cantforward++;
    MESSAGE_Free(node, msg);
    return;
}

