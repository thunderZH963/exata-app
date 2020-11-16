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
// This file contains function handling routing of IPv6
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
#include "ipv6_route.h"
#include "ipv6_radix.h"
#include "network_ip.h"

#define DEBUG_IPV6 0

//---------------------------------------------------------------------------
// FUNCTION             : route_init
// PURPOSE             :: Route initialization function
// PARAMETERS          ::
// + ipv6               : struct ipv6_data_struct* ipv6: IPv6 data pointer of
//                      :    node.
// RETURN               : None
//---------------------------------------------------------------------------
void
route_init(struct ipv6_data_struct* ipv6)
{
    ipv6->rttrash = 0;
    ipv6->ndp_cache = NULL;

    // initialize all zeroes, all ones, mask table
    rn_init(ipv6);

    if (DEBUG_IPV6)
    {
        printf("   Routing Table Initialized Properly  \n");
    }
} // end of route initialization.


//---------------------------------------------------------------------------
// FUNCTION             : rtalloc
// PURPOSE             :: Route allocation function.
// PARAMETERS          ::
// + node               : Node* node : pointer to node
// + ro                 : route* ro: Pointer to destination route.
// + llAddr             : unsigned int llAddr: Link layer address.
// RETURN               : None
//---------------------------------------------------------------------------
void rtalloc(Node* node, route* ro, MacHWAddress& llAddr)
{
    rtalloc_ign(node, ro, 0, llAddr);

    if (DEBUG_IPV6)
    {
        printf("rtalloc: Returning from here\n");
    }
    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtalloc_ign
// PURPOSE             :: route ignition function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + ro                 : route* ro : Pointer to destination route.
// + ignore             : UInt32 : Ignore flag
// + llAddr             : unsigned int llAddr: Link layer address.
// RETURN               : None
//---------------------------------------------------------------------------
void
rtalloc_ign(
    Node* node,
    route* ro,
    UInt32 ignore,
    MacHWAddress& llAddr)
{
    IPv6Data* ipv6 = (IPv6Data *)node->networkData.networkVar->ipv6;

    // No route entry is found. So allocate memory.

    // if there is no route related information. try to get it.
    if (!ro->ro_rt.rt_node)
    {
        ro->ro_rt.rt_node =
            rtalloc1(node, ipv6->ndp_cache, &ro->ro_dst, 1, ignore, llAddr);
        ro->ro_rt.rt_flags |= RTF_UP;
    }
    return;
}

//---------------------------------------------------------------------------
// FUNCTION             : rtalloc1
// PURPOSE             :: second level route allocation function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + rnh                : radix_node_head* rnh: Pointer to radix tree head.
/// + dst               : in6_addr* dst : IPv6 Destination Address
// + report             : int report: Report flag
// + ignflags           : UInt32 : Ignore flag
// + linkLayerAddr      : unsigned Ignore linkLayerAddr: Link layer address.
// RETURN               : rn_leaf*
//---------------------------------------------------------------------------
rn_leaf*
rtalloc1(
    Node* node,
    radix_node_head* rnh,
    in6_addr* dst,
    int report,
    UInt32 ignflags,
    MacHWAddress& linkLayerAddr)
{
    IPv6Data* ipv6 = (IPv6Data *)node->networkData.networkVar->ipv6;
    rn_leaf* rn = NULL;
    rn_leaf* keyNode = NULL;

    // If no routing table is present.
    if (!rnh)
    {
        if (report)
        {
            // If required, report the failure to the supervising
            // Authorities.
        }
        return (NULL);
    }

    keyNode = Rn_LeafAlloc();

    keyNode->key = *dst;

    keyNode->keyPrefixLen = 128;

    // Search in the radix table
    rn = (rn_leaf*)rn_search((void*)keyNode, rnh);

    // if got the node and then return the information.
    if (rn != NULL)
    {
        if (DEBUG_IPV6)
        {
                char addressStr[80];
                IO_ConvertIpAddressToString(dst, addressStr);
                printf("rtalloc1: Found Address \t%s\n",addressStr);
        }

        MEM_free(keyNode);

        return rn;
    }
    else  // still haven't got the node, insert it.
    {
        // Multicast destination no need to add.
        if (dst->s6_addr8[0] == 0xff)
        {
            MEM_free(keyNode);

            return (NULL);
        }
        // Now add the information for the same.
        keyNode->key =  *dst;
        keyNode->linkLayerAddr = linkLayerAddr;
        keyNode->interfaceIndex = -3; // Put garbage value;

        // No linklayer adderss we need to add it as probing..
        if (linkLayerAddr.hwType == HW_TYPE_UNKNOWN)
        {
            keyNode->ln_state = 1; //LLNDP6_INCOMPLETE;
            keyNode->expire = 0;   // No expire time is set.
        }

        rn = (rn_leaf*) rn_insert(node, (void*)keyNode, rnh);
        if (rn)
        {
            // if the address is prefix then add to prefix list.
            if (keyNode->key.s6_addr32[2] == 0 && keyNode->key.s6_addr32[3] == 0)
            {
                if (!ipv6->prefixHead)
                {
                    ipv6->prefixHead = (prefixList*) MEM_malloc(
                                                        sizeof(prefixList));
                    ipv6->prefixTail = ipv6->prefixHead;
                    ipv6->prefixTail->next = NULL;
                    ipv6->prefixTail->prev = NULL;
                    ipv6->prefixTail->rnp = rn;
                    ipv6->noOfPrefix++;
                }
                else
                {
                    addPrefix((prefixList*) ipv6->prefixTail,
                        rn,
                        &(ipv6->noOfPrefix));
                    ipv6->prefixTail = ipv6->prefixTail->next;
                }
                if (DEBUG_IPV6)
                {
                    char addressStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(dst, addressStr);
                        printf("Node %u Added Prefix \t%s\n",
                            node->nodeId, addressStr);
                }
            } // end of prefix insertion
        }// end of successful insertion
        if (rn != keyNode)
        {
            if (keyNode->linkLayerAddr.byte)
            {
                MEM_free(keyNode->linkLayerAddr.byte);
            }
            MEM_free(keyNode);
            keyNode = NULL;
        }
    } // end of insertion.
    return (rn);
} // end of rtalloc1




//---------------------------------------------------------------------------
// FUNCTION             : addPrefix
// PURPOSE             :: Adds prefix in the prefix list.
// PARAMETERS          ::
// + tail               : prefixList* tail: End pointer of prefix list
// + rn                 : rn_leaf* rn: Pointer to radix node.
// + noOfPrefix         : unsigned int* noOfPrefix: No of prefix in
//                      :        prefix list
// RETURN               : None
//---------------------------------------------------------------------------
void addPrefix(
       prefixList* tail,
       rn_leaf* rn,
       unsigned int* noOfPrefix)
{
    tail->next = (prefixList*) MEM_malloc(sizeof(prefixList));
    tail->next->next = NULL;
    tail->next->prev = tail;
    tail->next->rnp = rn;
    (*noOfPrefix)++;
}

//---------------------------------------------------------------------------
// FUNCTION             : RadixTreeLookUp
// PURPOSE             :: Radix tree lookup function.
// PARAMETERS          ::
// +dst                 : in6_addr* dst: IPV6 Destination Address
// +rnh                 : radix_node_head* rnh: Radix tree head pointer
// RETURN              :: rn_leaf*
//---------------------------------------------------------------------------


rn_leaf* RadixTreeLookUp(
    Node* node,
    in6_addr* dst,
    radix_node_head* rnh)
{
    rn_leaf* rn = NULL;
    rn_leaf keyNode;

    keyNode.key = *dst;

    rn = (rn_leaf*)rn_match((void*)&keyNode, rnh, node);
    return rn;
}



//---------------------------------------------------------------------------
// FUNCTION             : FreeRoute
// PURPOSE             :: Frees a route
// PARAMETERS          ::
// + ro                 : struct route_struct* ro: Pointer to ipv6 route.
// RETURN               : None
//---------------------------------------------------------------------------
void FreeRoute(struct route_struct* ro)
{
    if (ro)
    {
        MEM_free(ro);
    }
}


//---------------------------------------------------------------------------
// FUNCTION             : Route_Malloc
// PURPOSE             :: Route memory allocation function.
// PARAMETERS          :: None
// RETURN               : route*
//---------------------------------------------------------------------------
route* Route_Malloc()
{
    route* ro = (route*) MEM_malloc(sizeof(route));

    ro->ro_rt.rt_node = NULL;
    return ro;
}

