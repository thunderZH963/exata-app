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

// Following is list of features implemented in this version.
// 1. IPv6 is implemented for mac protocols 802.3,802.11,CSMA,MACA & Switch
// 2. CBR, FTP/GENERIC, FTP, TELNET, HTTP/HTTPD ,TRAFFIC_GEN,SUPER-APPLICATION will be able
//    to use IPv6.
// 3. TCP & UDP support IPv6.
// 4. All types of IPv6 addressing is supported.
// 5. Neighbor Solicitation, Neighbor Advertisement, Router Solicitation,
//      Router Advertisement are supported.
// 6. IPv6 Routing Protocols supported are as below:
//      - Static Routing Protocol.
//      - Dynamic Routing Protocols:
//          1. RIPng
//          2. OSPFv3
//
// 7. ICMPv6 for IPv6 control packets sending is supported.
// 8. Fragmentation and Reassembly for large IPv6 packets is implemented.
// 9. Currently FIFO and priority scheduler support IPv6
// 10. dual ip is supported at node level.

// Listed features not implemented.
// 1. MLD is not supported in this version.
// 2. Router, Hop by Hop Option header, Destination Option header
//    processing is blocked due to non availability of other protocol or
//    control blocks.
// 3. dual ip is not supported at interface level.

// Assumptions taken to implement in QualNet simulation.
// 1. For Static Routing Global Aggreable address is taken, as site-local,
//    link-local addressing is confusing and also simulation
//    will have no effect if it is send by global/site/link level address.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "main.h"
#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "ipv6.h"

#include "if_queue.h"
#include "if_scheduler.h"
#include "queue_red.h"
#include "queue_wred_ecn.h"
#include "queue_rio_ecn.h"

#include "sch_graph.h"
#include "sch_strictprio.h"
#include "sch_wfq.h"
#include "sch_roundrobin.h"
#include "sch_scfq.h"
#include "sch_wrr.h"
#include "resource_manager_cbq.h"

#include "multicast_static.h"
#include "ipv6_radix.h"
#include "ipv6_route.h"
#include "if_ndp6.h"
#include "ip6_input.h"
#include "ip6_output.h"
#include "ip6_icmp.h"
#include "network_dualip.h"
#include "mac_llc.h"

#include "ipv6_auto_config.h"

#ifdef WIRELESS_LIB
#include "routing_aodv.h"
#include "routing_dymo.h"
#endif // WIRELESS_LIB

#ifdef ENTERPRISE_LIB
#include "mf_traffic_conditioner.h"
#include "sch_diffserv.h"
#include "routing_ospfv3.h"
#endif // ENTERPRISE_LIB

#define DEBUG_IPV6 0

#define IPV6_ROUTING_DISABLED_WARNING 0

//-------------------------------------------------------------------------//
// NAME         :IPv6InterfaceStatusHandler()
// PURPOSE      :Handle mac alert.
// ASSUMPTION   :None
// RETURN VALUE :None
//-------------------------------------------------------------------------//
void IPv6InterfaceStatusHandler(
    Node* node,
    int interfaceIndex,
    MacInterfaceState state);

void Ipv6PrintTraceXML(Node* node, Message* msg);

static
void Ipv6InitTrace(Node* node, const NodeInput* nodeInput);

void Icmp6PrintTraceXML(Node* node, Message* msg);
static
void Icmp6InitTrace(Node* node, const NodeInput* nodeInput);

// /**
// FUNCTION   :: Ipv6PrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void Ipv6PrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];

    ip6_hdr *ipv6_hdr = (ip6_hdr *) MESSAGE_ReturnPacket(msg);

    char addr1[50];
    char addr2[50];
    TosType priority;

    sprintf(buf, "<ipv6>");
    TRACE_WriteToBufferXML(node, buf);


    IO_ConvertIpAddressToString(&(ipv6_hdr->ip6_src), addr1, false);
    IO_ConvertIpAddressToString(&(ipv6_hdr->ip6_dst), addr2, false);


    priority = ip6_hdrGetClass(ipv6_hdr->ipv6HdrVcf);

    sprintf(buf, "%d %hu %u %hu %hu %hu %hu %s %s",
            ip6_hdrGetVersion(ipv6_hdr->ipv6HdrVcf),
            priority,
            ip6_hdrGetFlow(ipv6_hdr->ipv6HdrVcf),
            ipv6_hdr->ip6_plen,
            ipv6_hdr->ip6_nxt,
            ipv6_hdr->ip6_hlim,
            MESSAGE_ReturnPacketSize(msg),
            addr1,
            addr2);

    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, "</ipv6>");
    TRACE_WriteToBufferXML(node, buf);
}


// /**
// FUNCTION   :: Ipv6InitTrace
// LAYER      :: NETWORK
// PURPOSE    :: IP initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

static
void Ipv6InitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-IPV6",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-IPV6 should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_NETWORK_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
            TRACE_EnableTraceXML(node, TRACE_IPV6,
                "IPv6", Ipv6PrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_IPV6,
                "IPv6", writeMap);
    }
    writeMap = FALSE;
}

// /**
// FUNCTION   :: Icmp6InitTrace
// LAYER      :: NETWORK
// PURPOSE    :: IP initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

static
void Icmp6InitTrace(Node* node, const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-ICMPV6",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-ICMPV6 should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_NETWORK_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
            TRACE_EnableTraceXML(node, TRACE_ICMPV6,
                "ICMPV6", Icmp6PrintTraceXML, writeMap);
    }
    else
    {
            TRACE_DisableTraceXML(node, TRACE_ICMPV6,
                "ICMPV6", writeMap);
    }
    writeMap = FALSE;
}


void NetworkIpv6ParseAndSetRoutingProtocolType(
    Node* node,
    const NodeInput* nodeInput);

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6IsPacketForThisInterface
// PURPOSE             :: Checks a packet for this interface or not. Returns
//                        true if it is for this interface else false.
// PARAMETERS          ::
// + node               : Node* node         : Pointer to node
// + index              : int index          : Interface index
// + dst_addr           : in6_addr* dst_addr : IPv6 Destination Address
// RETURN               : BOOL
//---------------------------------------------------------------------------
static BOOL
Ipv6IsPacketForThisInterface(Node* node, int index, in6_addr* dst_addr)
{
    //Function to check packet is of this interface`
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    bool isDeprecated = SAME_ADDR6(ip->interfaceInfo[index]->
                          ipv6InterfaceInfo->autoConfigParam.depGlobalAddr,
                          *dst_addr);
    bool isValid = ip->interfaceInfo[index]->ipv6InterfaceInfo->
                        autoConfigParam.validLifetime > node->getNodeTime();

    //Now Check the address.
    if (SAME_ADDR6(ip->interfaceInfo[index]->ipv6InterfaceInfo->globalAddr,
        *dst_addr))
    {
        return TRUE;
    }
    else
        if (SAME_ADDR6(ip->interfaceInfo[index]->ipv6InterfaceInfo
        ->siteLocalAddr, *dst_addr))
        {
            return TRUE;
        }
        else
            if (SAME_ADDR6(ip->interfaceInfo[index]->ipv6InterfaceInfo
            ->linkLocalAddr, *dst_addr))
            {
                return TRUE;
            }
            else //Now check the multicast packet
                if (SAME_ADDR6(ip->interfaceInfo[index]->ipv6InterfaceInfo
                ->multicastAddr, *dst_addr))
                {
                    return TRUE;
                }
                else // check if the address is depricated and still valid
                    if (isDeprecated && isValid)
                    {
                        return TRUE;
                    }
                    else
                    {
                        return FALSE;
                    }
}//end of the function`


/******************************** IPV6 APIs ***************************/



//---------------------------------------------------------------------------
// FUNCTION             : Ipv6IsMyPacket
// PURPOSE             :: Function to check if the packet is for this node.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + dst_addr           : in6_addr* dst_addr    : IPv6 Destination Address
// RETURN               : BOOL
//---------------------------------------------------------------------------
BOOL Ipv6IsMyPacket(Node* node, in6_addr* dst_addr)
{
    int i;

    // Check Multicast
    if (IS_MULTIADDR6(*dst_addr))
    {
        if (Ipv6IsReservedMulticastAddress(node, *dst_addr))
        {
            return TRUE;
        }
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if ((NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
            && Ipv6IsPacketForThisInterface(node, i, dst_addr))
        {
            return TRUE;
        }
    }
    return FALSE;
} // end of the function;



//---------------------------------------------------------------------------
// FUNCTION             : in6_isanycast
// PURPOSE             :: Test if an address is an anycast address and
//                        returns flags.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + addr               : in6_addr *addr : IPv6 Address
// RETURN               : int: Returns true or false.
// NOTES                : currently any cast addressing is not supported.
//---------------------------------------------------------------------------
int
in6_isanycast(Node* node, in6_addr *addr)
{
    // currently any cast addressing is not supported.
    return (0);
}



//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetLinkLocalAddress
// PURPOSE             :: Gets the linklocal address of the interface
//                        specified interface Index.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId : Index of the concerned interface
// + addr               : in6_addr* addr    : IPv6 Address
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6GetLinkLocalAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->linkLocalAddr,
        *addr);
}




//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetSiteLocalAddress
// PURPOSE             :: Gets the Sitelocal address of the interface
//                        specified interface Index.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId : Index of the concerned interface
// + addr               : in6_addr* addr    : IPv6 address pointer,
//                              output sitelocal address.
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6GetSiteLocalAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->siteLocalAddr,
        *addr);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetGlobalAggrAddress
// PURPOSE             :: Gets the GlobalAggreable address of the interface
//                        specified interface Index.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId   : Index of the concerned interface
// + addr               : in6_addr* addr    : IPv6 address pointer,
//                              output global address.
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6GetGlobalAggrAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->globalAddr,
        *addr);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetMulticastAddress
// PURPOSE             :: Get a multicast address of the interface.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId : Index of the concerned interface
// + addr               : in6_addr* addr  : IPv6 address pointer,
//                              output multicast address.
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6GetMulticastAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->multicastAddr,
        *addr);
}



//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetAddressTypeFromString
// Purpose              : Returns NETWORK_IPV6 if string is IPv6 address
//                        NETWORK_IPV4 if string is IPv4 address
//                        NETWORK_INVALID otherwise
// PARAMETERS          ::
// + interfaceAddr      : char* interfaceAddr: String formated ip address
// RETURN               : NetworkType
//---------------------------------------------------------------------------
NetworkType Ipv6GetAddressTypeFromString(char* interfaceAddr)
{
    if (strchr(interfaceAddr, ':'))
    {
        return NETWORK_IPV6;
    }
    else if (strchr(interfaceAddr, '.'))
    {
        return NETWORK_IPV4;
    }
    return NETWORK_INVALID;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetMTU
// PURPOSE             :: Returs maximum transmission unit of an interface.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId : Index of the concerned interface
// RETURN               : int
//---------------------------------------------------------------------------
int Ipv6GetMTU(Node* node, int interfaceId)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->mtu);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetInterfaceIndexFromAddress
// PURPOSE             :: Function to find Interface Index
//                        from a given destinaion.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + dst                : in6_addr* dst : IPv6 address pointer,
//                              whose interface index is to be found.
// RETURN               : int: returns interface index or -1 if error.
//---------------------------------------------------------------------------
int Ipv6GetInterfaceIndexFromAddress(Node* node,in6_addr* dst)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i = 0;

    IPv6InterfaceInfo* ipv6InterfaceInfo;

    //Now start the searching ipv6 interface.
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
            || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            ipv6InterfaceInfo = ip->interfaceInfo[i]->ipv6InterfaceInfo;
            if (SAME_ADDR6(ipv6InterfaceInfo->globalAddr, *dst))
            {
                return i;
            }
            if (SAME_ADDR6(ipv6InterfaceInfo->siteLocalAddr, *dst))
            {
                return i;
            }
            if (SAME_ADDR6(ipv6InterfaceInfo->linkLocalAddr, *dst))
            {
                return i;
            }
        } //end of ipv6 enabled interface.
    }
    return -1;
}// end of interface index finding function.


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SolicitationMulticastAddress
// PURPOSE             :: Function to create solicitation multicast address.
// PARAMETERS          ::
// + dst                : in6_addr* dst     : IPv6 address pointer,
//                              output destination multicast address.
// + target             : in6_addr* target  : IPv6 Target Address pointer
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6SolicitationMulticastAddress(in6_addr* dst, in6_addr* target)
{
    // solicitation multicast address: FF02:0:0:0:0:1:FFXX:XXXX
    // The solicited-node multicast address is formed by taking the
    // low-order 24 bits of the address and appending those bits to the
    // prefix FF02:0:0:0:0:1:FF00::/104

    dst->s6_addr8[0] = 0xff;
    dst->s6_addr8[1] = 0x02;
    dst->s6_addr8[2] = 0x0;
    dst->s6_addr8[3] = 0x0;

    dst->s6_addr32[1] = 0;

    dst->s6_addr8[8] = 0x0;
    dst->s6_addr8[9] = 0x0;
    dst->s6_addr8[10] = 0x0;
    dst->s6_addr8[11] = 0x1;

    dst->s6_addr8[12] = 0xff;
    dst->s6_addr8[13] = target->s6_addr8[13];
    dst->s6_addr8[14] = target->s6_addr8[14];
    dst->s6_addr8[15] = target->s6_addr8[15];

} //End of function.


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AllRoutersMulticastAddress
// PURPOSE             :: Function to assign all routers multicast address.
// PARAMETERS          ::
// + dst                : in6_addr* dst     : IPv6 address pointer,
//                              output destination multicast address.
// RETURN               : None
//---------------------------------------------------------------------------

void Ipv6AllRoutersMulticastAddress(in6_addr* dst)
{
    dst->s6_addr8[0] = 0xff;
    dst->s6_addr8[1] = 0x02;
    dst->s6_addr8[2] = 0x0;
    dst->s6_addr8[3] = 0x0;

    dst->s6_addr32[1] = 0x0;
    dst->s6_addr32[2] = 0x0;

    dst->s6_addr8[12] = 0x0;
    dst->s6_addr8[13] = 0x0;
    dst->s6_addr8[14] = 0x0;
    dst->s6_addr8[15] = 0x2;

} //End of function.

//---------------------------------------------------------------------------
// /**
// FUNCTION         :: Ipv6GetInterfaceMulticastAddress
// LAYER            :: Network
// PURPOSE          :: Get multicast address of this interface
// PARAMETERS ::
// + node            : Node* : Node pointer
// + interfaceIndex  : int : interface for which multicast is required
// RETURN           :: IPv6 multicast address
// **/
//---------------------------------------------------------------------------
in6_addr
Ipv6GetInterfaceMulticastAddress(
    Node* node,
    int interfaceIndex)
{
    in6_addr interfaceAddress;
    in6_addr multicastAddress;

    Ipv6GetGlobalAggrAddress(
        node,
        interfaceIndex,
        &interfaceAddress);

    Ipv6SolicitationMulticastAddress(
        &multicastAddress,
        &interfaceAddress);

    return(multicastAddress);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6ConvertStrLinkLayerToMacHWAddress
// PURPOSE             :: Converts from character formatted link layer address
//                        to NodeAddress format.
// PARAMETERS          ::
// + llAddrStr          : char* llAddrStr : Link Layer Address String
// RETURN               : MacHWAddress: returns mac hardware address.
//---------------------------------------------------------------------------
MacHWAddress Ipv6ConvertStrLinkLayerToMacHWAddress(
    Node* node,
    int interfaceId,
    unsigned char* llAddrStr)
{
    //in case of v4-tunnels the llAddrStr contains the ipv4 address of tunnel
    // end-point.
    MacHWAddress llAddr = Ipv6GetLinkLayerAddress(node, interfaceId);

    memcpy(llAddr.byte, llAddrStr, llAddr.hwLength);

    return llAddr;
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetLinkLayerAddress
// PURPOSE             :: Returns link layer address of the interface
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId : Index of the concerned interface
// + ll_addr_str        : char* ll_addr_str: String formated linklayer address
// RETURN               : MacHWAddress
//---------------------------------------------------------------------------
MacHWAddress
Ipv6GetLinkLayerAddress(
    Node* node,
    int interfaceId)
{
    //in case of v4-tunnels the linklayer addresss should be the ipv4 address
    // of underlying interface
    if (TunnelIsVirtualInterface(node, interfaceId) == TRUE)
    {
        NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
        LinkedList* listptr =
            ip->interfaceInfo[interfaceId]->InterfacetunnelInfo;
        TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

        MacHWAddress macAddr;
        macAddr.hwLength = MAC_IPV4_LINKADDRESS_LENGTH;
        macAddr.hwType = IPV4_LINKADDRESS;
        macAddr.byte = (unsigned char*)MEM_malloc(macAddr.hwLength);
        memcpy(macAddr.byte,
            &tunneldata->tunnelStartAddress, MAC_IPV4_LINKADDRESS_LENGTH);
        return macAddr;
    }

    return node->macData[interfaceId]->macHWAddr;
}



//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetPrefix
// PURPOSE             :: Gets the prefix from the specified address.
// PARAMETERS          ::
// + addr               : in6_addr* addr    : IPv6 Address pointer,
//                              the prefix of which to found.
// + prefix             : in6_addr* prefix  : IPv6 Address pointer
//                              the output prefix.
// + length             : int length        : IPv6 prefix length
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6GetPrefix(
    const in6_addr* addr,
    in6_addr* prefix,
    unsigned int length)
{
    int counter;

    // prefix length in octet
    int prefixLength = length / 8;
    unsigned int extraBit = length - prefixLength * 8;

    memset(prefix, 0, sizeof(in6_addr));

    for (counter = 0; counter < prefixLength; counter++)
    {
        prefix->s6_addr8[counter] = addr->s6_addr8[counter];
    }

    if (extraBit)
    {
        unsigned char temp = addr->s6_addr8[counter];

        temp >>= (8 - extraBit);
        temp <<= (8 - extraBit);

        prefix->s6_addr8[counter] = temp;
    }
}


/*********************** IPV6 Header & Option Header *****************/



//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddIpv6Header
// PURPOSE             :: Adds Ipv6 header in the packet.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + payloadLen         : int payloadLen: Length of payload.
// + src_addr           : in6_addr src_addr     : IPv6 Source Address
// + dst_addr           : in6_addr dst_addr     : IPv6 Destination Address
// + priority           : TosType priority: Type of service type
// + protocol           : unsigned char protocol: Next protocol number.
// + hlim               : unsigned hlim: Maximum hop limit.
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6AddIpv6Header(
    Node *node,
    Message *msg,
    int payloadLen,
    in6_addr src_addr,
    in6_addr dst_addr,
    TosType priority,
    unsigned char protocol,
    unsigned hlim)
{
    ip6_hdr* ipv6_hdr = NULL;

    MESSAGE_AddHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);
    ipv6_hdr = (ip6_hdr*) MESSAGE_ReturnPacket(msg);
    memset(ipv6_hdr, 0, sizeof(ip6_hdr));

    // IPv6 header
    // version, class and flow
    ip6_hdrSetVersion(&(ipv6_hdr->ipv6HdrVcf), IPV6_VERSION);
    ip6_hdrSetClass(&(ipv6_hdr->ipv6HdrVcf), (unsigned char)priority);

    // Payload length in terms of octet
    ipv6_hdr->ip6_plen = (unsigned short) payloadLen;
    ipv6_hdr->ip6_nxt = protocol;
    ipv6_hdr->ip6_hlim = (unsigned char) hlim;

    // source and dest IP address
    COPY_ADDR6(src_addr, ipv6_hdr->ip6_src);
    COPY_ADDR6(dst_addr, ipv6_hdr->ip6_dst);

    //Trace sending packet
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                    msg,
                    TRACE_NETWORK_LAYER,
                    PACKET_OUT,
                    &acnData,
                    NETWORK_IPV6);

}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddFragmentHeader
// PURPOSE             :: Adds Fragment header in the packet
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + nextHeader         : unsigned char nextHeader: Next protocol number.
// + offset             : unsigned short offset: Fragmentation offset number.
// + id                 : unsigned int id: Fragment Identification no.
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6AddFragmentHeader(Node *node,
                      Message *msg,
                      unsigned char nextHeader,
                      unsigned short offset,
                      unsigned int id)
{
    ipv6_fraghdr* frgp = NULL;

    MESSAGE_AddHeader(node, msg, sizeof(ipv6_fraghdr), TRACE_IPV6);

    frgp =(ipv6_fraghdr*) MESSAGE_ReturnPacket(msg);

    frgp->if6_reserved = 0;
    frgp->if6_nh = nextHeader;
    frgp->if6_off = offset;
    frgp->if6_id = id;
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6RemoveIpv6Header
// PURPOSE             :: Removes Ipv6 header from the packet.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + sourceAddress      : Address* sourceAddress: Source Ip Address
// + destinationAddress : Address* destinationAddress: Destination Ip Address
// + priority           : TosType *priority: Type of service
// + protocol           : unsigned char *protocol: Next protocol no.
// + hLim               : unsigned *hLim: Maximum hop limit
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6RemoveIpv6Header(
    Node *node,
    Message *msg,
    Address* sourceAddress,
    Address* destinationAddress,
    TosType *priority,
    unsigned char *protocol,
    unsigned *hLim)
{
    ip6_hdr *ipv6Header = (ip6_hdr*) MESSAGE_ReturnPacket(msg);
    *priority = ip6_hdrGetClass(ipv6Header->ipv6HdrVcf);
    *hLim = ipv6Header->ip6_hlim;
    *protocol = ipv6Header->ip6_nxt;

    SetIPv6AddressInfo(sourceAddress, ipv6Header->ip6_src);
    SetIPv6AddressInfo(destinationAddress, ipv6Header->ip6_dst);

    MESSAGE_RemoveHeader(node, msg, sizeof(ip6_hdr), TRACE_IPV6);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddNewInterface
// PURPOSE             :: Adds new ipv6 interface to the node specified.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + globalAddr         : in6_addr* globalAddr  : IPv6 Address pointer,
//                          the global address to associate with the interface.
// + tla                : unsigned int tla: Top level aggregation
// + nla                : unsigned int nla: Next level aggregation
// + sla                : unsigned int sla: Site level aggregation
// + newInterfaceIndex  : int* newInterfaceIndex: Interface Index
// + nodeInput          : const NodeInput* nodeInput: Pointer to node input.
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6AddNewInterface(
    Node* node,
    in6_addr* globalAddr,
    in6_addr* subnetAddr,
    unsigned int subnetPrefixLen,
    int* newInterfaceIndex,
    const NodeInput* nodeInput,
    unsigned short siteCounter,
    BOOL isNewInterface)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    int interfaceIndex = -1;
    BOOL wasFound;
    IPv6InterfaceInfo* ipv6InterfaceInfo;

    if (isNewInterface)
    {
        interfaceIndex = node->numberInterfaces;
        node->numberInterfaces++;

        ip->interfaceInfo[interfaceIndex] =
            (IpInterfaceInfoType*) MEM_malloc(sizeof(IpInterfaceInfoType));
        memset(ip->interfaceInfo[interfaceIndex],
               0,
               sizeof(IpInterfaceInfoType));

        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV6;
    }
    else
    {
        interfaceIndex = node->numberInterfaces - 1;
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_DUAL;
    }

    *newInterfaceIndex = interfaceIndex;

    ERROR_Assert(
        (interfaceIndex >= 0) && (interfaceIndex < MAX_NUM_INTERFACES),
        "Number of interfaces has exceeded MAX_NUM_INTERFACES or is < 0");

    ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo =
        (IPv6InterfaceInfo*) MEM_malloc(sizeof(IPv6InterfaceInfo));

    ipv6InterfaceInfo = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    memset(ipv6InterfaceInfo, 0, sizeof(IPv6InterfaceInfo));

    ipv6InterfaceInfo->macLayerStatusEventHandlerFunction = NULL;

    COPY_ADDR6(*globalAddr, ipv6InterfaceInfo->globalAddr);

    ipv6InterfaceInfo->prefixLen = subnetPrefixLen;

    MAPPING_CreateIpv6SiteLocalAddr(
        globalAddr,
        &(ipv6InterfaceInfo->siteLocalAddr),
        siteCounter,
        subnetPrefixLen);


    MAPPING_CreateIpv6MulticastAddr(
        globalAddr, &(ipv6InterfaceInfo->multicastAddr));

    ipv6InterfaceInfo->multicastEnabled = TRUE;

    int ipFragUnit = MAX_NW_PKT_SIZE ;
    Address sourceAddress;
    sourceAddress.networkType = NETWORK_IPV6;
    Ipv6GetGlobalAggrAddress(node,
                    interfaceIndex,
                    &sourceAddress.interfaceAddr.ipv6);
    IO_ReadInt(node->nodeId,
               &sourceAddress,
               nodeInput,
               "IP-FRAGMENTATION-UNIT",
               &wasFound,
               &ipFragUnit);

    if (!wasFound)
    {
        ipFragUnit = MAX_NW_PKT_SIZE;
    }
    else if (ipFragUnit < MIN_IPv6_PKT_SIZE || ipFragUnit > MAX_NW_PKT_SIZE)
    {
        char errString[MAX_STRING_LENGTH];
        sprintf(errString, "IP fragmentation unit (%d) should not be less"
                " than MIN_IPv6_PKT_SIZE (%d) nor greater than"
                " MAX_NW_PKT_SIZE (%d)", ipFragUnit, MIN_IPv6_PKT_SIZE,
                MAX_NW_PKT_SIZE);
        
        ERROR_ReportError(errString);
    }

    ipv6InterfaceInfo->mtu = ipFragUnit;
    ip->interfaceInfo[interfaceIndex]->ipFragUnit = ipFragUnit;

    if (isNewInterface)
    {
        ip->interfaceInfo[interfaceIndex]
            ->macLayerStatusEventHandlerFunction = NULL;
        ip->interfaceInfo[interfaceIndex]->promiscuousMessagePeekFunction = NULL;
        ip->interfaceInfo[interfaceIndex]->macAckHandler = NULL;
    }

    ip->interfaceInfo[interfaceIndex]->hsrpEnabled = FALSE;

    sprintf(ip->interfaceInfo[interfaceIndex]->interfaceName,
            "interface%d", interfaceIndex);

    IO_ReadStringInstance(
            node->nodeId,
            globalAddr,
            nodeInput,
            "INTERFACE-NAME",
            interfaceIndex,
            FALSE,
            &wasFound,
            ip->interfaceInfo[interfaceIndex]->interfaceName);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6PreInit
// PURPOSE             :: Ipv6 PreInit function
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6PreInit(Node *node)
{
    // If IP has already initialized then don't go for initialization again.
    if (node->networkData.networkVar == NULL)
    {
        NetworkIpPreInit(node);
    }

    node->networkData.networkVar->ipv6 =
        (IPv6Data *) MEM_malloc(sizeof(IPv6Data));

    memset(node->networkData.networkVar->ipv6, 0, sizeof(IPv6Data));
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6InterfaceInit
// PURPOSE             :: Ipv6 interface Init function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceId        : int interfaceId           : Interface Index
// + nodeInput          : const NodeInput *nodeInput:Pointer to node input.
// + ip                 : NetworkDataIp* ip: Pointer to Ip data fo node.
// RETURN               : None
//---------------------------------------------------------------------------
static void
Ipv6InterfaceInit(
    Node* node,
    int interfaceId,
    const NodeInput *nodeInput,
    NetworkDataIp* ip)
{
    if (DEBUG_IPV6)
    {
        char addressString[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            &(ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo
            ->linkLocalAddr),
            addressString);

        printf("Node Id %u Interface %d = %s\n",
            node->nodeId,
            interfaceId,
            addressString);
    }

    ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->routerFunction = NULL;

    MAC_SetInterfaceStatusHandlerFunction(
                                        node,
                                        interfaceId,
                                        &IPv6InterfaceStatusHandler);
}// end of function.


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6StatInit
// PURPOSE             :: Statistic Initializations.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + ipv6               : IPv6Data* ipv6: Pointer to IPv6 data of node.
// RETURN               : None
//---------------------------------------------------------------------------
static void
Ipv6StatInit(Node* node, IPv6Data* ipv6)
{
    memset(&(ipv6->ip6_stat), 0, sizeof(ip6Stat));
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6HashTableInit
// PURPOSE             :: Hash table Initializations.
// PARAMETERS          ::
// + ipv6               : IPv6Data* ipv6: Pointer to IPv6 data of node.
// RETURN               : void
//---------------------------------------------------------------------------
static void
Ipv6HashTableInit(IPv6Data* ipv6)
{
    // Prefix initializations
    ipv6->hashTable = NULL;
    ipv6->prefixHead = NULL;
    ipv6->prefixTail = NULL;
    ipv6->noOfPrefix = 0;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddDefaultEntry
// PURPOSE             :: Ipv6 default entry adding function at the time of
//                          node initialization.
// PARAMETERS          ::
// + ip                 : NetworkDataIp* ip: : Pointer to IP data of node.
// + numberInterfaces   : int numberInterfaces: No of interfaces.
// RETURN               : None
//---------------------------------------------------------------------------
static void
Ipv6AddDefaultEntry(Node* node, NetworkDataIp* ip, int numberInterfaces)
{
    rn_leaf* keyNode;

    for (int i = 0; i < numberInterfaces; i++)
    {
        rn_leaf* rn;

        //Note: no default route should be added for virtual interface
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV4
            || TunnelIsVirtualInterface(node, i))
        {
            continue;
        }

        // Ipv6 auto-config
        if (ip->interfaceInfo[i]->ipv6InterfaceInfo->autoConfigParam.
                                                        isAutoConfig)
        {
            continue;
        }

        keyNode = (rn_leaf*) MEM_malloc(sizeof(rn_leaf));

        memset(keyNode, 0, sizeof(rn_leaf));

        Ipv6GetPrefix(
            &(ip->interfaceInfo[i]->ipv6InterfaceInfo->globalAddr),
            &keyNode->key,
            ip->interfaceInfo[i]->ipv6InterfaceInfo->prefixLen);

        keyNode->keyPrefixLen =
            ip->interfaceInfo[i]->ipv6InterfaceInfo->prefixLen;


        keyNode->linkLayerAddr = Ipv6GetLinkLayerAddress(node,i);

        keyNode->flags = RT_LOCAL;
        keyNode->type = 0;
        keyNode->interfaceIndex = i;
        keyNode->rn_option = RTM_REACHHINT; // Means Reachable

        // Insert into Radix Tree.
        rn = (rn_leaf*)rn_insert(node, (void*)keyNode, ip->ipv6->rt_tables);

        // Add Prefix in the prefix list
        if (!ip->ipv6->prefixHead)
        {
            ip->ipv6->prefixHead = (prefixList*)
                MEM_malloc(sizeof(prefixList));
            ip->ipv6->prefixTail = ip->ipv6->prefixHead;

            ip->ipv6->prefixTail->next = NULL;
            ip->ipv6->prefixTail->prev = NULL;

            ip->ipv6->prefixTail->rnp = rn;
            ip->ipv6->noOfPrefix++;
        }
        else
        {
            addPrefix(ip->ipv6->prefixTail, rn, &(ip->ipv6->noOfPrefix));
            ip->ipv6->prefixTail = ip->ipv6->prefixTail->next;
        }
    }// End adding default entries in routing tables.
}

//---------------------------------------------------------------------------
// FUNCTION     Ipv6ParseAndSetRoutingProtocolType()
// PURPOSE      Parse and set the Routing Prototocol
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//---------------------------------------------------------------------------

void Ipv6ParseAndSetRoutingProtocolType(
    Node* node,
    const NodeInput* nodeInput)
{
    BOOL retVal;
    char routingProtocolString[MAX_STRING_LENGTH];
    int i;

    NetworkRoutingProtocolType routingProtocolType;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {

            routingProtocolType = ROUTING_PROTOCOL_NONE;

            in6_addr address;

            Ipv6GetGlobalAggrAddress(node, i, &address);

            IO_ReadString(node->nodeId,
                &address,
                nodeInput,
                "ROUTING-PROTOCOL-IPv6",
                &retVal,
                routingProtocolString);

            if (!retVal)
            {
                IO_ReadString(node->nodeId,
                    &address,
                    nodeInput,
                    "ROUTING-PROTOCOL",
                    &retVal,
                    routingProtocolString);
            }

            if (retVal)
            {
                if (strcmp(routingProtocolString, "OSPFv3") == 0)
                {
#ifdef ENTERPRISE_LIB
                    routingProtocolType = ROUTING_PROTOCOL_OSPFv3;
#else //ENTERPRISE_LIB
                    ERROR_ReportMissingLibrary(
                                    routingProtocolString, "ENTERPRISE_LIB");
#endif // ENTERPRISE_LIB
                }
                else
#ifdef WIRELESS_LIB
                if (strcmp(routingProtocolString, "AODV") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_AODV6;
                }
                else
                if (strcmp(routingProtocolString, "DYMO") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_DYMO6;
                }
                else
                if (strcmp(routingProtocolString, "OLSR-INRIA") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OLSR_INRIA;
                }
                else if (strcmp(routingProtocolString, "OLSRv2-NIIGATA") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_OLSRv2_NIIGATA;
                }
#else // WIRELESS_LIB
                if ((strcmp(routingProtocolString, "AODV") == 0) ||
                    (strcmp(routingProtocolString, "DYMO") == 0) ||
                    (strcmp(routingProtocolString, "OLSR-INRIA") == 0) ||
                    (strcmp(routingProtocolString, "OLSRv2-NIIGATA") == 0))
                {
                   ERROR_ReportMissingLibrary(
                                        routingProtocolString, "Wireless");
                }
#endif // WIRELESS_LIB
                else if (strcmp(routingProtocolString, "RIPng") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_RIPNG;
                }
                else if (strcmp(routingProtocolString, "NONE") == 0)
                {
                    routingProtocolType = ROUTING_PROTOCOL_NONE;
                    // Allow a node to specify explicitly that routing
                    // protocols are not used.
                }
                else if (IPV6_ROUTING_DISABLED_WARNING)
                {
                    char buff[MAX_STRING_LENGTH];
                    sprintf(buff, "%s is not a valid IPv6 ROUTING-PROTOCOL"
                            " specified on interfaceIndex %d of node %d\n",
                            routingProtocolString, i, node->nodeId);
                    ERROR_ReportWarning(buff);
                }
            }
            else if (IPV6_ROUTING_DISABLED_WARNING)
            {
                char buff[MAX_STRING_LENGTH];
                sprintf(buff, "No IPv6 ROUTING-PROTOCOL is "
                "specified on interfaceIndex %d of node %d\n",
                i, node->nodeId);
                ERROR_ReportWarning(buff);
            }

            NetworkIpAddUnicastRoutingProtocolType(node,
                            routingProtocolType,
                            i,
                            NETWORK_IPV6);
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     IPv6RoutingInit()
// PURPOSE      Initialization function for network layer.
//              Initializes IP.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//---------------------------------------------------------------------------
void
IPv6RoutingInit(Node *node, const NodeInput *nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    BOOL retVal;

    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {
            switch (ip->interfaceInfo[i]->ipv6InterfaceInfo->
                    routingProtocolType)
            {
#ifdef ENTERPRISE_LIB
                case ROUTING_PROTOCOL_OSPFv3:
                {
                    MAC_SetInterfaceStatusHandlerFunction(
                                         node,
                                         i,
                                         &Ospfv3InterfaceStatusHandler);

                    if (!NetworkIpGetRoutingProtocol(node,
                                      ROUTING_PROTOCOL_OSPFv3, NETWORK_IPV6))
                    {

                        Ospfv3Init(node,
                            (Ospfv3Data **)
                            &ip->interfaceInfo[i]->ipv6InterfaceInfo
                            ->routingProtocol,
                            nodeInput,
                            i);
                    }
                    else
                    {
                      NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                                                    node,
                                                    ROUTING_PROTOCOL_OSPFv3,
                                                    i,
                                                    NETWORK_IPV6);
                    }
                    break;
                }
#endif // ENTERPRISE_LIB
#ifdef WIRELESS_LIB
                case ROUTING_PROTOCOL_AODV6:
                {
                    if (!NetworkIpGetRoutingProtocol(node,
                        ROUTING_PROTOCOL_AODV6, NETWORK_IPV6))
                    {
                        AodvInit(
                            node,
                            (AodvData**)&ip->interfaceInfo[i]
                                    ->ipv6InterfaceInfo->routingProtocol,
                            nodeInput,
                            i,
                            ROUTING_PROTOCOL_AODV6);
                    }
                    else
                    {
                      NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_AODV6,
                            i,
                            NETWORK_IPV6);
                    }
                    break;
                }// end of aodv
// start of dymo
                case ROUTING_PROTOCOL_DYMO6:
                {
                    if (!NetworkIpGetRoutingProtocol(node,
                        ROUTING_PROTOCOL_DYMO6, NETWORK_IPV6))
                    {
                        DymoInit(
                            node,
                            (DymoData**)&ip->interfaceInfo[i]
                                        ->ipv6InterfaceInfo->routingProtocol,
                            nodeInput,
                            i,
                            ROUTING_PROTOCOL_DYMO6);
                    }
                    else
                    {
                      NetworkIpUpdateUnicastRoutingProtocolAndRouterFunction(
                            node,
                            ROUTING_PROTOCOL_DYMO6,
                            i,
                            NETWORK_IPV6);
                    }
                    break;
                }// end of dymo
#endif // WIRELESS_LIB
                default:
                {
                    break;
                }
            }
        }
    }

    // Initializing Multicast static route
    char buf[MAX_STRING_LENGTH];
    IO_ReadString(
         node->nodeId,
         ANY_ADDRESS,
         nodeInput,
         "MULTICAST-STATIC-ROUTE",
         &retVal,
         buf);

    if (retVal == TRUE && strcmp(buf, "YES") == 0)
    {
        RoutingMulticastStaticInit(
                    node,
                    nodeInput);
    }

}

//---------------------------------------------------------------------------
// FUNCTION             : IPv6Init
// PURPOSE             :: Ipv6 Initializations.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + nodeInput          : const NodeInput *nodeInput: Pointer to nodeInput
// RETURN               : None
//---------------------------------------------------------------------------
void
IPv6Init(Node *node, const NodeInput *nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;

    Message* msg;
    BOOL retVal = FALSE;
    int i;
    clocktype ipFragHoldTime = 0;

    double throughput = 0.0;
    float rtPerformVar; // router performance variation
    char rtBackType[MAX_STRING_LENGTH]; //router backplane type
    char backplaneThroughput[MAX_STRING_LENGTH];

    Ipv6InitTrace(node, nodeInput);

    ip->backplaneType = BACKPLANE_TYPE_DISTRIBUTED;
    ip->backplaneStatus = NETWORK_IP_BACKPLANE_IDLE;

    ip->backplaneThroughputCapacity =
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT;

    if (DEBUG_IPV6)
    {
        printf("%u ip->backplaneThroughputCapacity = %u\n",
            retVal, (unsigned) ip->backplaneThroughputCapacity);
    }

// For Dymo init default value
   ipv6->isManetGateway = FALSE;
   ipv6->manetPrefixlength = 0;
// End for Dymo

    ip->dualIp = NULL; // set default value for dualIp

    // For Dual-IP enabled node, already the buffer for CPU gets
    // created during IPv4 initialization. So, skip it here.
    if (NetworkIpGetNetworkProtocolType(node, node->nodeId) != DUAL_IP)
    {
        char buf[MAX_STRING_LENGTH];

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "ROUTER-BACKPLANE-THROUGHPUT",
            &retVal,
            backplaneThroughput);

        char *p;

        if (retVal == FALSE ||
            strcmp(backplaneThroughput, "UNLIMITED") == 0 ||
            strcmp(backplaneThroughput, "0") == 0)
        {
            // If not specified, we assume infinite backplane throughput.
            ip->backplaneThroughputCapacity =
                        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT;
        }
        else if ((throughput = strtod(backplaneThroughput , &p)) > 0.0)
        {
            IO_ReadFloat(
                node->nodeId,
                ANY_ADDRESS,
                nodeInput,
                "ROUTER-PERFORMANCE-VARIATION",
                &retVal,
                &rtPerformVar);

            if (retVal)
            {
                throughput += ((throughput * rtPerformVar) / 100);
            }

            ip->backplaneThroughputCapacity = (clocktype)throughput;

            for (i = 0; i < node->numberInterfaces; i++)
            {
                ip->interfaceInfo[i]->disBackplaneCapacity =
                                            (clocktype)throughput;
            }

            IO_ReadString(
                node->nodeId,
                ANY_ADDRESS,
                nodeInput,
                "ROUTER-BACKPLANE-TYPE",
                &retVal,
                rtBackType);

            if (strcmp(rtBackType, "CENTRAL") == 0)
            {
                ip->backplaneType = BACKPLANE_TYPE_CENTRAL;
            }
            else if (strcmp(rtBackType, "DISTRIBUTED"))
            {
                ERROR_ReportError("ROUTER-BACKPLANE-TYPE should be "
                    "either \"CENTRAL\" or \"DISTRIBUTED\".\n");
            }
        }
        else
        {
            ERROR_ReportError("Wrong ROUTER-BACKPLANE-THROUGHPUT value.\n");
        }

        IO_ReadString(node->nodeId,
                 ANY_ADDRESS,
                 nodeInput,
                 "IP-FORWARDING",
                 &retVal,
                 buf);

        if (retVal)
        {
            if (strcmp(buf, "YES") == 0)
            {
                ip->ipForwardingEnabled = TRUE;
            }
            else if (strcmp(buf, "NO") == 0)
            {
                ip->ipForwardingEnabled = FALSE;
            }
            else
            {
                ERROR_ReportError("IP-FORWARDING should be either \"YES\" or \""
                                  "NO\".\n");
            }
        }
        else
        {
           ip->ipForwardingEnabled = TRUE;
        }

        // Do not need to clear fields
        // Read this node collect Diffserv statistics or not
        // The <variant> is one of YES | NO
        // Format is: DIFFSERV-EDGE-ROUTER-STATISTICS <variant>, for example
        //            DIFFSERV-EDGE-ROUTER-STATISTICS YES
        //            DIFFSERV-EDGE-ROUTER-STATISTICS NO
        // If not specified, default is NO

        IO_ReadString(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "DIFFSERV-EDGE-ROUTER-STATISTICS",
            &retVal,
            buf);

        if (retVal && strcmp(buf, "YES") == 0)
        {
            ip->mftcStatisticsEnabled = TRUE;
        }

        IO_ReadTime(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "IP-FRAGMENT-HOLD-TIME",
            &retVal,
            &ipFragHoldTime);

        if (!retVal)
        {
            ipv6->ipFragHoldTime = IP_FRAGMENT_HOLD_TIME;
        }
        else
        {
            ipv6->ipFragHoldTime = ipFragHoldTime;
        }

#ifdef ENTERPRISE_LIB

    // Read whether this node is Diffserv enabled Edge router or not
    // The <variant> is one of YES | NO
    // Format is: DIFFSERV-ENABLE-EDGE-ROUTER <variant>, for example
    //            DIFFSERV-ENABLE-EDGE-ROUTER YES
    //            DIFFSERV-ENABLE-EDGE-ROUTER NO
    //            [3 5]  DIFFSERV-ENABLE-EDGE-ROUTER YES
    // If not specified, default is NO

    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "DIFFSERV-ENABLE-EDGE-ROUTER",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            ip->isEdgeRouter = TRUE;
            DIFFSERV_MFTrafficConditionerInit(node, nodeInput);
        }
        else if (strcmp(buf, "NO") == 0)
        {
            ip->isEdgeRouter = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "DIFFSERV-ENABLE-EDGE-ROUTER: Unknown variant"
                " in configuration file.\n");
        }
    }
#endif // ENTERPRISE_LIB

        // Create buffer for CPU
        NetworkIpInitCpuQueueConfiguration(node, nodeInput);

    }

    // Perhop behavior initialization
    // But right now not used
    IpInitPerHopBehaviors(node, nodeInput);

    // Init Multicast Group List
    ListInit(node, &ipv6->multicastGroupList);

    // IPv6 auto-config
    // Parse IPv6 unicast routing Protocols
    Ipv6ParseAndSetRoutingProtocolType(node, nodeInput);

    // parse autoconfig parameters
    IPv6AutoConfigParseAutoConfig(node, nodeInput);

    BOOL autoConfigIntfacePresent = FALSE;

    //Now start the interface init
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i])
        {
            if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
                || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
            {
                IPv6InterfaceInfo* interfaceInfo =
                                    ip->interfaceInfo[i]->ipv6InterfaceInfo;

                bool isThisIntfaceAuto =
                    IPv6AutoConfigMakeInterfaceIdentifier(node, i);
                
                autoConfigIntfacePresent = autoConfigIntfacePresent ||
                                                isThisIntfaceAuto;

                Ipv6InterfaceInit(node, i, nodeInput, ip);

                // Ipv6 auto-config
                if (interfaceInfo->autoConfigParam.isDelegatedRouter)
                {
                    IPv6AutoConfigReadPrefValidLifeTime(
                        node,
                        i,
                        nodeInput);
                }
            }
        }
    }

    ipv6->max_keylen = MAX_KEY_LEN;

    Ipv6CreateBroadcastAddress(node, &ipv6->broadcastAddr);

    // Create loopback address
    CLR_ADDR6(ipv6->loopbackAddr);

    ipv6->loopbackAddr.s6_addr[15] = 0x01;

    //Initialize ICMP.
    Icmp6Init(ipv6);
    Icmp6InitTrace(node, nodeInput);

    ipv6->ip = ip; // For back Tracking;

    RANDOM_SetSeed(ipv6->jitterSeed,
                   node->globalSeed,
                   node->nodeId,
                   NETWORK_PROTOCOL_IPV6);

    route_init(ipv6);

    // Packet Hold buffer
    Ipv6HashTableInit(ipv6);

    // Adding Default Entries.
    Ipv6AddDefaultEntry(node, ip, node->numberInterfaces);

    // Set empty to destination cache.
    ipv6->destination_cache.start = NULL;
    ipv6->destination_cache.end = NULL;

    // Starting fragmentation id.
    ipv6->ip6_id = 1;
    ipv6->fragmentListFirst = NULL;
    // Statistics Initialize.
    Ipv6StatInit(node, ipv6);

    if (autoConfigIntfacePresent)
    {
        // Now Send Initial Messages.
        IPv6AutoConfigInit(node);
    }

    // Now Send Initial Messages.
    msg = MESSAGE_Alloc(node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_InitEvent);

    MESSAGE_Send(node, msg, RANDOM_nrand(ipv6->jitterSeed) % IPV6JITTER_RANGE);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6IsForwardingEnabled
// PURPOSE             :: Ipv6 forwarding enabled checking function
// PARAMETERS          ::
// + ipv6               : IPv6Data* ipv6:Pointer to IPv6 data of node.
// RETURN               : BOOL
//---------------------------------------------------------------------------
BOOL Ipv6IsForwardingEnabled(IPv6Data* ipv6)
{
    if (ipv6)
    {
        if (ipv6->ip)
        {
            return ipv6->ip->ipForwardingEnabled;
        }
        else
        {
            ERROR_ReportError("IsFowardingEnabled: ip Not Set Properly");
            return FALSE;
        }
    }
    else
    {
        return FALSE;
    }
}// End of forwarding checking


/******************** Timer Processing *****************************/

//--------------------------------------------------------------------------
// FUNCTION             : Ipv6InterfaceInitAdvt
// PURPOSE             :: This is an overloaded function to
//                        re-initialize advertisement by an interface
//                        that recovers from interface fault.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceindex     : int interfaceIndex : interface that recovers
//                        from interface fault
// RETURN               : None
//--------------------------------------------------------------------------
void
Ipv6InterfaceInitAdvt(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    in6_addr dstAddr;
    // IPv6 auto-config
    // Check if DAD enabled
    IPv6InterfaceInfo* interfaceInfo =
                        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    if (interfaceInfo->autoConfigParam.isDadEnable)
    {
        return;
    }
    //Check for Ipv6 interface type.
    if (ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_IPV6
        || ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_DUAL)
    {
        Ipv6SolicitationMulticastAddress(&dstAddr,
                &(ip->interfaceInfo[interfaceIndex]->
                    ipv6InterfaceInfo->globalAddr));

        if (!Ipv6IsForwardingEnabled(ip->ipv6))
        {
            //Send Router Solicitation for default router selection
            rtsol6_output(
                node,
                interfaceIndex,
                &(ip->interfaceInfo[interfaceIndex]->
                        ipv6InterfaceInfo->globalAddr));

            ndadv6_output(node, interfaceIndex, &dstAddr,
                    &(ip->interfaceInfo[interfaceIndex]->
                    ipv6InterfaceInfo->globalAddr),
                    OVERRIDE_ADV);
        }

        if (Ipv6IsForwardingEnabled(ip->ipv6))
        {
            // if router, then advertize its route
            rtadv6_output(
                node,
                interfaceIndex,
                &dstAddr,
                &(ip->interfaceInfo[interfaceIndex]->
                    ipv6InterfaceInfo->globalAddr));

            ndadv6_output(node, interfaceIndex, &dstAddr,
                    &(ip->interfaceInfo[interfaceIndex]->
                    ipv6InterfaceInfo->globalAddr),
                    ROUTER_ADV | OVERRIDE_ADV);
        }
    }

    // Now Send Periodic Advertisement
    if (Ipv6IsForwardingEnabled(ip->ipv6))
    {
        clocktype delayForAdv = 0;
        Message* msgRtAdv;

        msgRtAdv = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_Rdvt);

        MESSAGE_InfoAlloc(
            node,
            msgRtAdv,
            sizeof(Ipv6RouterAdverInfo));

        Ipv6RouterAdverInfo* info = (Ipv6RouterAdverInfo*)
                                          MESSAGE_ReturnInfo(msgRtAdv);

        info->interfaceId = interfaceIndex;
        if (ip->ipv6->icmp6->icmp6stat.icp6s_snd_rtadv <
                                         MAX_INITIAL_RTR_ADVERTISEMENTS)
        {
            // First few advertisement must not be longer than
            // MAX_INITIAL_RTR_ADVERT_INTERVAL
            delayForAdv = MAX_INITIAL_RTR_ADVERT_INTERVAL;
        }
        else
        {
            ip->ipv6->randomNum.setSeed(node->globalSeed,
                                        node->nodeId,
                                        NETWORK_PROTOCOL_IPV6,
                                        interfaceIndex);
            // Uniform between default values of MIN_RTR_ADVERT_INTERVAL
            // and MAX_RTR_ADVERT_INTERVAL
            ip->ipv6->randomNum.setDistributionUniform(
                        (clocktype)MIN_RTR_ADVERT_INTERVAL,
                        MAX_RTR_ADVERT_INTERVAL);
            delayForAdv = ip->ipv6->randomNum.getRandomNumber();
        }
        MESSAGE_Send(node, msgRtAdv, delayForAdv);
    }

        // Now Send Router Solicitation upto MAX_RTR_SOLICITATIONS times
    if (!Ipv6IsForwardingEnabled(ip->ipv6))
    {
        Message* msgRtSol;

        msgRtSol = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_RSol);

        MESSAGE_InfoAlloc(
            node,
            msgRtSol,
            sizeof(Ipv6RouterSolInfo));

        Ipv6RouterSolInfo* info = (Ipv6RouterSolInfo*)
                                          MESSAGE_ReturnInfo(msgRtSol);

        info->retryCounter =  1;
        info->interfaceId = interfaceIndex;

        MESSAGE_Send(node, msgRtSol, RTR_SOLICITATION_INTERVAL);
    }

    // Now Send Neighbor Advertisement upto MAX_NEIGHBOR_ADVERTISEMENT times
    Message* msgNdAdv;

    msgNdAdv = MESSAGE_Alloc(
        node,
        NETWORK_LAYER,
        NETWORK_PROTOCOL_IPV6,
        MSG_NETWORK_Ipv6_NdAdvt);

    MESSAGE_InfoAlloc(
        node,
        msgNdAdv,
        sizeof(Ipv6NeighAdverInfo));

    Ipv6NeighAdverInfo* info = (Ipv6NeighAdverInfo*)
                                      MESSAGE_ReturnInfo(msgNdAdv);

    info->retryCounter =  1;
    info->interfaceId = interfaceIndex;

    MESSAGE_Send(node, msgNdAdv, RETRANS_TIMER);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6InterfaceInitAdvt
// PURPOSE             :: Ipv6 interface initialization advertisement function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
static void
Ipv6InterfaceInitAdvt(Node* node)
{
    int i = 0;

    Message* msgNdpProcess;

    if (DEBUG_IPV6)
    {
        char buf[100];
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("Node %u: Got Init Timer at %ss\n", node->nodeId, buf);
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        // IPv6 auto-config
        // Check for Ipv6 interface type.
        NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
        if (ip->interfaceInfo[i]->interfaceType != NETWORK_IPV6
            && ip->interfaceInfo[i]->interfaceType != NETWORK_DUAL)
        {
            continue;
        }
        IPv6InterfaceInfo* interfaceInfo =
                                    ip->interfaceInfo[i]->ipv6InterfaceInfo;
        if (interfaceInfo->autoConfigParam.isDadConfigured)
        {
            IPv6AutoConfigInitiateDAD(node, i);
        }
        Ipv6InterfaceInitAdvt(node, i);
    }

    // after reachable time, node has to clear up its neighbor/dest cache
    msgNdpProcess = MESSAGE_Alloc(
        node,
        NETWORK_LAYER,
        NETWORK_PROTOCOL_IPV6,
        MSG_NETWORK_Ipv6_Ndp_Process);

    MESSAGE_Send(node, msgNdpProcess, REACHABLE_TIME);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6RetransRouterSolicit
// PURPOSE             :: Router Solicitation function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + msg                : Message* msg : Timer msg
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6RetransRouterSolicit(Node* node, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    Message* msgRtSol;

    Ipv6RouterSolInfo* msginfo =
                (Ipv6RouterSolInfo*)MESSAGE_ReturnInfo(msg);
    int interfaceId = msginfo->interfaceId;

    if (msginfo->retryCounter == MAX_RTR_SOLICITATIONS)
    {
        return;
    }

    if (DEBUG_IPV6)
    {
        char buf[100];
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("Node %u: Got Router Solicit Timer at %ss\n",
            node->nodeId, buf);
    }

    if (ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_IPV6
        || ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_DUAL)
    {
        if (!Ipv6IsForwardingEnabled(ip->ipv6))
        {
            //Send Router Solicitation for default router selection
            rtsol6_output(
                node,
                interfaceId,
                &(ip->interfaceInfo[interfaceId]->
                        ipv6InterfaceInfo->globalAddr));
        }
    }

    msgRtSol = MESSAGE_Alloc(
        node,
        NETWORK_LAYER,
        NETWORK_PROTOCOL_IPV6,
        MSG_NETWORK_Ipv6_RSol);

    MESSAGE_InfoAlloc(
        node,
        msgRtSol,
        sizeof(Ipv6RouterSolInfo));

    Ipv6RouterSolInfo* info = (Ipv6RouterSolInfo*)
                                      MESSAGE_ReturnInfo(msgRtSol);

    info->retryCounter = msginfo->retryCounter + 1;
    info->interfaceId = interfaceId;

    MESSAGE_Send(node, msgRtSol, RTR_SOLICITATION_INTERVAL);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6RetransNeighborAdvt
// PURPOSE             :: Neighbour advertisement functions
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + msg                : Message* msg : Timer msg
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6RetransNeighborAdvt(Node* node, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    in6_addr dstAddr;
    Message* msgNdAdv;

    Ipv6NeighAdverInfo* msginfo =
                (Ipv6NeighAdverInfo*)MESSAGE_ReturnInfo(msg);
    int interfaceId = msginfo->interfaceId;

    if (msginfo->retryCounter == MAX_NEIGHBOR_ADVERTISEMENT)
    {
        return;
    }

    if (DEBUG_IPV6)
    {
        char buf[100];
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("Node %u: Got Neigh Advt Timer at %ss\n",
            node->nodeId, buf);
    }

    if (ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_IPV6
        || ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_DUAL)
    {
        Ipv6SolicitationMulticastAddress(&dstAddr,
            &(ip->interfaceInfo[interfaceId]
                        ->ipv6InterfaceInfo->globalAddr));

        if (!Ipv6IsForwardingEnabled(ip->ipv6))
        {
            ndadv6_output(node, interfaceId, &dstAddr,
                &(ip->interfaceInfo[interfaceId]
                        ->ipv6InterfaceInfo->globalAddr), OVERRIDE_ADV);
        }

        if (Ipv6IsForwardingEnabled(ip->ipv6))
        {
            ndadv6_output(node, interfaceId, &dstAddr,
                &(ip->interfaceInfo[interfaceId]
                        ->ipv6InterfaceInfo->globalAddr),
                                ROUTER_ADV | OVERRIDE_ADV);
        }
    }

    msgNdAdv = MESSAGE_Alloc(
        node,
        NETWORK_LAYER,
        NETWORK_PROTOCOL_IPV6,
        MSG_NETWORK_Ipv6_NdAdvt);

    MESSAGE_InfoAlloc(
        node,
        msgNdAdv,
        sizeof(Ipv6NeighAdverInfo));

    Ipv6NeighAdverInfo* info = (Ipv6NeighAdverInfo*)
                                      MESSAGE_ReturnInfo(msgNdAdv);

    info->retryCounter = msginfo->retryCounter + 1;
    info->interfaceId = interfaceId;

    MESSAGE_Send(node, msgNdAdv, RETRANS_TIMER);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6RouterPeriodicAdvt
// PURPOSE             :: Router periodic advertisement functions
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6RouterPeriodicAdvt(Node* node, Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    in6_addr dstAddr;
    Message* msgRtAdv;

    Ipv6RouterAdverInfo* msginfo =
                (Ipv6RouterAdverInfo*)MESSAGE_ReturnInfo(msg);
    int interfaceId = msginfo->interfaceId;

    if (DEBUG_IPV6)
    {
        char buf[100];
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        printf("Node %u: Got Periodic Advt Timer at %ss\n",
            node->nodeId, buf);
    }

    if (ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_IPV6
        || ip->interfaceInfo[interfaceId]->interfaceType == NETWORK_DUAL)
    {
        // Ipv6 auto-config
        if (Ipv6IsForwardingEnabled(ip->ipv6) && 
            ip->ipv6->autoConfigParameters.eligiblePrefixList->size() != 0)
        {
            Ipv6SolicitationMulticastAddress(&dstAddr,
                &(ip->interfaceInfo[interfaceId]
                            ->ipv6InterfaceInfo->globalAddr));

            rtadv6_output(
                node,
                interfaceId,
                &dstAddr,
                &(ip->interfaceInfo[interfaceId]
                            ->ipv6InterfaceInfo->globalAddr));
        }
    }

    // Now Send Periodic Advertisement. to be made it to random.
    if (Ipv6IsForwardingEnabled(ip->ipv6))
    {
        clocktype delayForAdv = 0;
        msgRtAdv = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_Rdvt);

        MESSAGE_InfoAlloc(
            node,
            msgRtAdv,
            sizeof(Ipv6RouterAdverInfo));

        Ipv6RouterAdverInfo* info = (Ipv6RouterAdverInfo*)
                                          MESSAGE_ReturnInfo(msgRtAdv);

        info->interfaceId = interfaceId;
        if (ip->ipv6->icmp6->icmp6stat.icp6s_snd_rtadv <
                                         MAX_INITIAL_RTR_ADVERTISEMENTS)
        {
            // First few advertisement must not be longer than
            // MAX_INITIAL_RTR_ADVERT_INTERVAL
            delayForAdv = MAX_INITIAL_RTR_ADVERT_INTERVAL;
        }
        else
        {
            ip->ipv6->randomNum.setSeed(node->globalSeed,
                                        node->nodeId,
                                        NETWORK_PROTOCOL_IPV6,
                                        interfaceId);
            // Uniform between default values of MIN_RTR_ADVERT_INTERVAL
            // and MAX_RTR_ADVERT_INTERVAL
            ip->ipv6->randomNum.setDistributionUniform(
                        (clocktype)MIN_RTR_ADVERT_INTERVAL,
                        MAX_RTR_ADVERT_INTERVAL);
            delayForAdv = ip->ipv6->randomNum.getRandomNumber();
        }
        MESSAGE_Send(node, msgRtAdv, delayForAdv);
    }
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6NdpProcessing
// PURPOSE             :: Ipv6 Destination cache and neighbor cache
//                          processing function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6NdpProcessing(Node* node)
{
    // Delete destination routes whose time has expired,
    Message* msgNdpProcess;

    Ipv6DeleteDestination(node);

    // Go for next Ndp process.
    msgNdpProcess = MESSAGE_Alloc(
            node,
            NETWORK_LAYER,
            NETWORK_PROTOCOL_IPV6,
            MSG_NETWORK_Ipv6_Ndp_Process);

    MESSAGE_Send(node, msgNdpProcess, REACHABLE_TIME);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6Layer
// PURPOSE             :: IPv6 layer event notification function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + msg                : Message* msg : Pointer to message holding events
// RETURN               : void
//---------------------------------------------------------------------------
void
Ipv6Layer(Node* node, Message* msg)
{
    switch (msg->protocolType)
    {
#ifdef ENTERPRISE_LIB
        case ROUTING_PROTOCOL_OSPFv3:
        {

            Ospfv3HandleRoutingProtocolEvent(node, msg);

            return;
        }
#endif // ENTERPRISE_LIB
#ifdef WIRELESS_LIB
        case ROUTING_PROTOCOL_AODV6:
        {

            AodvHandleProtocolEvent(node, msg);

            return;
        }
        case ROUTING_PROTOCOL_DYMO6:
        {

            DymoHandleProtocolEvent(node, msg);

            return;
        }
#endif // WIRELESS_LIB

        default :
            break;
    }

    switch (MESSAGE_GetEvent(msg))
    {
        case MSG_NETWORK_Ipv6_InitEvent:
        {
            Ipv6InterfaceInitAdvt(node);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_Ipv6_Rdvt:
        {
            Ipv6RouterPeriodicAdvt(node, msg);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_Ipv6_NdAdvt:
        {
            Ipv6RetransNeighborAdvt(node, msg);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_Ipv6_RSol:
        {
            Ipv6RetransRouterSolicit(node, msg);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_Ipv6_Ndp_Process:
        {
            Ipv6NdpProcessing(node);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_Ipv6_RetryNeighSolicit:
        {
            ndsol6_retry(node,msg);
            break;
        }
        case MSG_NETWORK_Ipv6_Ndadv6:
        {
            rn_leaf* ln = ((NadvEvent*)MESSAGE_ReturnInfo(msg))->ln;
            in6_addr dst;

            dst = ln->key;

            Ipv6DeleteMessageInBuffer(node, dst, ln);
            MESSAGE_Free(node, msg);


            break;
        }
        case MSG_NETWORK_Backplane:
        {
            NetworkIpReceiveFromBackplane(node,msg);
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_NETWORK_JoinGroup:
        {
            in6_addr* mcastAddr = (in6_addr* ) MESSAGE_ReturnInfo(msg);

            Ipv6AddToMulticastGroupList(node, *mcastAddr);
            MESSAGE_Free(node, msg);

            break;
        }
        case MSG_NETWORK_LeaveGroup:
        {
            in6_addr* mcastAddr = (in6_addr* ) MESSAGE_ReturnInfo(msg);

            Ipv6RemoveFromMulticastGroupList(node, *mcastAddr);
            MESSAGE_Free(node, msg);

            break;
        }
        // IPV6 auto-config
        case MSG_NETWORK_Ipv6_AutoConfigInitEvent:
        {
            IPv6AutoConfigHandleInitEvent(node);
            break;
        }
        case MSG_NETWORK_Address_Deprecate_Event:
        {
            IPv6AutoConfigHandleAddressDeprecateEvent(node, msg);
            break;
        }
        case MSG_NETWORK_Ipv6_Wait_For_NDAdv:
        {
            IPv6AutoConfigHandleWaitNDAdvExpiry(node, msg);
            break;
        }
        case MSG_NETWORK_Address_Invalid_Event:
        {
            IPv6AutoConfigHandleAddressInvalidExpiry(node, msg);
            break;
        }
        case MSG_NETWORK_Forward_NSol_Event:
        {
            Int32* interfaceIdPtr = (Int32*) MESSAGE_ReturnInfo(msg);

            NetworkDataIp* ip = 
                (NetworkDataIp*) node->networkData.networkVar;

            IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[*interfaceIdPtr]->ipv6InterfaceInfo;
            if (interfaceInfo->autoConfigParam.forwardNSol)
            {
                ip->ipv6->autoConfigParameters.autoConfigStats.
                                                        numOfSolForwarded++;
                icmp6_send(
                    node,
                    interfaceInfo->autoConfigParam.forwardNSol,
                    0,
                    NULL,
                    *interfaceIdPtr,
                    IP_FORWARDING);
            }
            interfaceInfo->autoConfigParam.forwardNSol = NULL;
            break;
        }
        case MSG_NETWORK_Forward_NAdv_Event:
        {
            Int32* interfaceIdPtr = (Int32*) MESSAGE_ReturnInfo(msg);

            NetworkDataIp* ip = 
                            (NetworkDataIp*) node->networkData.networkVar;

            IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[*interfaceIdPtr]->ipv6InterfaceInfo;
            if (interfaceInfo->autoConfigParam.forwardNAdv)
            {
                ip->ipv6->autoConfigParameters.autoConfigStats.
                                                    numOfAdvertForwarded++;
                icmp6_send(
                    node,
                    interfaceInfo->autoConfigParam.forwardNAdv,
                    0,
                    NULL,
                    *interfaceIdPtr,
                    IP_FORWARDING);
            }
            interfaceInfo->autoConfigParam.forwardNAdv = NULL;
            break;
        }
        default :
        {
            MESSAGE_Free(node, msg);

            break;
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6PrintForwardingTable
// PURPOSE             :: IPv6 forwarding table printing function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6PrintForwardingTable(Node* node)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;

    if (!ipv6)
    {
        return;
    }

    printf("----------------------------------------------"
            "--------------------------------\n");
    printf(" Routing Table of Node Id %u ", node->nodeId);

    if (Ipv6IsForwardingEnabled(ip->ipv6))
    {
        printf(" Node Type: Router No of Prefix %u\n", ipv6->noOfPrefix);
    }
    else
    {
        printf(" Node Type: Host No of Prefix %u\n", ipv6->noOfPrefix);
    }

    printf("------------------------------------------------"
           "-------------------------------\n");
    printf("Type    \t\tPrefix\t     Index  LinkLayerAddr  Gateway\n");
    printf("-------------------------------------------------"
           "------------------------------\n");
    radix_traversal(node, ipv6->rt_tables->root, 1);
    printf("-------------------------------------------------"
           "------------------------------\n\n");

    // Print NDP Cache Entries.
    if (ipv6->ndp_cache->totalNodes > 0)
    {
        printf("\t\t\tNDP CACHE\n");
        printf("Type    \t\tAddress \tIndex  LinkLayerAddr\n");
        printf("----------------------------------------------"
               "---------------------------------\n");
        radix_traversal(node, ipv6->ndp_cache->root, 0);
        printf("----------------------------------------------"
               "---------------------------------\n\n");
    }
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6Finalize
// PURPOSE             :: Ipv6 Statistic printing function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6Finalize(Node* node)
{
    int i = 0;
    char buf[MAX_STRING_LENGTH];
    Scheduler *schedulerPtr = NULL;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;

    // Print the forwarding Table.
    if (DEBUG_IPV6)
    {
        Ipv6PrintForwardingTable(node);
    }

    if (node->networkData.networkStats == TRUE)
    {
        // IPv6 Statistic Outputs.
        sprintf(buf, "Total packets received = %u",
            ipv6->ip6_stat.ip6s_total);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packet too short = %u",
            ipv6->ip6_stat.ip6s_tooshort);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Not enough data = %u",
            ipv6->ip6_stat.ip6s_toosmall);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packets forwarded = %u", ipv6->ip6_stat.ip6s_forward);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packets recieved for unreachable destination = %u",
            ipv6->ip6_stat.ip6s_cantforward);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packets received from bad sources = %u",
            ipv6->ip6_stat.ip6s_badsource);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Datagrams delivered to upper level = %u",
            ipv6->ip6_stat.ip6s_delivered);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Total ipv6 packets generated = %u",
            ipv6->ip6_stat.ip6s_localout);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packets discarded due to no route = %u",
            ipv6->ip6_stat.ip6s_noroute);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);
        sprintf(buf, "Packets output discarded = %u",
            ipv6->ip6_stat.ip6s_outDiscarded);

        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Number of packets with improper version number = %u",
            ipv6->ip6_stat.ip6s_badvers);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Packets not forwarded because size greater than MTU = %u",
            ipv6->ip6_stat.ip6s_toobig);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Number of fragmented packets received = %u",
            ipv6->ip6_stat.ip6s_fragments);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);
        sprintf(buf, "Number of fragmented packets dropped = %u",
        ipv6->ip6_stat.ip6s_fragdropped);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Number of fragmented packets time out = %u",
        ipv6->ip6_stat.ip6s_fragtimeout);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

        sprintf(buf, "Number of Reassembled packets = %u",
            ipv6->ip6_stat.ip6s_reassembled);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);
        sprintf(buf, "Total output fragment created = %u",
            ipv6->ip6_stat.ip6s_ofragments);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);
        /*sprintf(buf, "Total MAC packet drop notifications received = %u",
            ipv6->ip6_stat.ip6s_macpacketdrop);
        IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);*/

        // End of IPv6 Statistic Output.

        // Now Print ICMP6 Statistics.
        Icmp6Finalize(node);

        // IPv6 auto-config
        IPv6AutoConfigFinalize(node);
    }
    if (!node->switchData )
    {
        for (i = 0; i < node->numberInterfaces; i++)
        {
            switch (NetworkIpGetUnicastRoutingProtocolType(node, i, NETWORK_IPV6))
            {
    #ifdef ENTERPRISE_LIB
                case ROUTING_PROTOCOL_OSPFv3:
                {

                    Ospfv3Finalize(node, i);

                    break;
                }
    #endif // ENTERPRISE_LIB
    #ifdef WIRELESS_LIB
                case ROUTING_PROTOCOL_AODV6:
                {

                    AodvFinalize(node, i, NETWORK_IPV6);

                    break;
                }
                case ROUTING_PROTOCOL_DYMO6:
                {

                    DymoFinalize(node, i, NETWORK_IPV6);

                    break;
                }
    #endif // WIRELESS_LIB

                default:
                {
                    // This routing protocol is not at the network layer
                    // (it does its finalization at its own layer), so just
                    // break.
                    break;
                }
            }
        }
    }

    // Then Queue Statistics.
    if (node->networkData.networkProtocol == DUAL_IP)
    {
        // Do not generate Queue Statistics here since
        // for Dual-IP enabled node, it will be generated at IPv4 layer
        return;
    }

#ifdef ENTERPRISE_LIB

    if (ip->isEdgeRouter == TRUE)
    {
        DIFFSERV_MFTrafficConditionerFinalize(node);
    }

#endif // ENTERPRISE_LIB

    for (i = 0; i < node->numberInterfaces; i++)
    {
        int j;
        schedulerPtr = ip->interfaceInfo[i]->scheduler;

        (*schedulerPtr).finalize(node, "Network", i);

        for (j = 0; j < (*schedulerPtr).numQueue(); j++)
        {
            (*schedulerPtr).invokeQueueFinalize(node, "Network", i, j);
        }

        if (ip->backplaneThroughputCapacity !=
            NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
        {
            Scheduler* inputSchedulerPtr =
                ip->interfaceInfo[i]->inputScheduler;

            inputSchedulerPtr->finalize(node, "Network", i, "IP", "Input");

            for (j = 0; j < inputSchedulerPtr->numQueue(); j++)
            {
                inputSchedulerPtr->invokeQueueFinalize(
                                    node, "Network", i, j, "IP", "Input");
            }
        }
    }

    if (ip->backplaneThroughputCapacity !=
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
    {
        Scheduler* cpuSchedulerPtr = ip->cpuScheduler;

        cpuSchedulerPtr->finalize(node, "Network", 0, "IP", "Cpu");

        cpuSchedulerPtr->invokeQueueFinalize(
                                node, "Network", 0, 0, "IP", "Cpu");
    }
}


//-----------------------------------------------------------------------------
// Ipv6 : Network-layer enqueueing
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// FUNCTION     Ipv6QueueInsert
// PURPOSE      Calls the packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface of input queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopLinkAddress
//                  Packet's next hop link address.
//              in6_addr destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
//---------------------------------------------------------------------------

static void
Ipv6QueueInsert(
    Node *node,
    Scheduler *scheduler,
    Message *msg,
    MacHWAddress& nextHopLinkAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull,
    int isOutputQueue = FALSE)
{
    ip6_hdr *ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);
    TosType trafficClass =
        (TosType) ip6_hdrGetClass(ipHeader->ipv6HdrVcf);
    int queueIndex = ALL_PRIORITIES;
    QueuedPacketInfo *infoPtr;

    // Tack on the nextHopAddress to the message using the insidious "info"
    // field.

    infoPtr = (QueuedPacketInfo*) MESSAGE_ReturnInfo(msg);

    memset(infoPtr->macAddress, 0, MAX_MACADDRESS_LENGTH);

    if (nextHopLinkAddress.hwType != HW_TYPE_UNKNOWN)
    {
        memcpy(infoPtr->macAddress, nextHopLinkAddress.byte,
                                                nextHopLinkAddress.hwLength);
    }
    infoPtr->hwLength = nextHopLinkAddress.hwLength;
    infoPtr->hwType = nextHopLinkAddress.hwType;

    COPY_ADDR6(destinationAddress,
               infoPtr->destinationAddress.ipv6DestAddr);

    infoPtr->outgoingInterface = outgoingInterface;
    infoPtr->networkType = networkType;
    infoPtr->userTos = trafficClass;

    if (isOutputQueue && (outgoingInterface != CPU_INTERFACE) &&
            LlcIsEnabled(node, outgoingInterface))
        LlcAddHeader(node,msg,PROTOCOL_TYPE_IP);

    // Call the "insertFunction" via function pointer.
    queueIndex = GenericPacketClassifier(scheduler,
        (int) ReturnPriorityForPHB(node, (TosType) trafficClass));



        //Trace dequeue
        ActionData acn;
        acn.actionType = ENQUEUE;
        acn.actionComment = NO_COMMENT;
        acn.pktQueue.interfaceID = (unsigned short)outgoingInterface;
        acn.pktQueue.queuePriority = (unsigned char) trafficClass;

        if (outgoingInterface != CPU_INTERFACE)
        {
            TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_OUT,
                        &acn,
                        NETWORK_IPV6);
        }
        else
        {
            TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acn,
                        NETWORK_IPV6);
        }

    (*scheduler).insert(
        msg,
        queueIsFull,
        queueIndex,
        NULL, //const void* infoField,
        node->getNodeTime());
}


//-----------------------------------------------------------------------------
// FUNCTION     Ipv6CpuQueueInsert
// PURPOSE      Calls the cpu packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopLinkAddress
//                  Packet's next hop link address.
//              in6_addr destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
//-----------------------------------------------------------------------------

void
Ipv6CpuQueueInsert(
    Node *node,
    Message *msg,
    MacHWAddress& nextHopLinkAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *cpuScheduler = ip->cpuScheduler;

    // NetworkIpQueueInsert
    Ipv6QueueInsert(
        node,
        cpuScheduler,
        msg,
        nextHopLinkAddress,
        destinationAddress,
        outgoingInterface,
        networkType,
        queueIsFull);
}


//-----------------------------------------------------------------------------
// FUNCTION     Ipv6InputQueueInsert
// PURPOSE      Calls the input packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int incomingInterface
//                  interface of input queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopLinkAddress
//                  Packet's next hop mac address.
//              in6_addr destinationAddress
//                  Packet's destination address.
//              int outgoingInterface
//                  Used to determine where packet should go after passing
//                  through the backplane.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
//-----------------------------------------------------------------------------

void
Ipv6InputQueueInsert(
    Node* node,
    int incomingInterface,
    Message* msg,
    MacHWAddress& nextHopLinkAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL* queueIsFull)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    Scheduler* inputScheduler = NULL;

    ERROR_Assert(
        incomingInterface >= 0 && incomingInterface < node->numberInterfaces,
        "Invalid incoming interface");

    inputScheduler = ip->interfaceInfo[incomingInterface]->inputScheduler;

    Ipv6QueueInsert(
        node,
        inputScheduler,
        msg,
        nextHopLinkAddress,
        destinationAddress,
        outgoingInterface,
        networkType,
        queueIsFull);
}


//-----------------------------------------------------------------------------
// FUNCTION     Ipv6OutputQueueInsert
// PURPOSE      Calls the output packet scheduler for an interface to retrieve
//              an IP packet from a queue associated with the interface.
//              The dequeued packet, since it's already been routed,
//              has an associated next-hop IP address.  The packet's
//              priority value is also returned.
// PARAMETERS   Node *node
//                  Pointer to node.
//              int outgoingInterface
//                  interface of output queue.
//              Message *msg
//                  Pointer to message with IP packet.
//              NodeAddress nextHopAddress
//                  Packet's next hop mac address.
//              in6_addr destinationAddress
//                  Packet's destination address.
//              int networkType
//                  Type of network packet is using (IP, Link-16, ...)
//              BOOL *queueIsFull
//                  Storage for boolean indicator.
//                  If TRUE, packet was not queued because scheduler
//                  reported queue was (or queues were) full.
// RETURN       None.
// NOTES        Called by QueueUpIpv6FragmentForMacLayer().
//-----------------------------------------------------------------------------

void
Ipv6OutputQueueInsert(
    Node* node,
    int outgoingInterface,
    Message* msg,
    MacHWAddress& nextHopAddress,
    in6_addr destinationAddress,
    int networkType,
    BOOL* queueIsFull)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    Scheduler* scheduler = NULL;

    ERROR_Assert(
        outgoingInterface >= 0 && outgoingInterface < node->numberInterfaces,
        "Invalid outgoing interface");

    scheduler = ip->interfaceInfo[outgoingInterface]->scheduler;

    Ipv6QueueInsert(
        node,
        scheduler,
        msg,
        nextHopAddress,
        destinationAddress,
        outgoingInterface,//ANY_INTERFACE, // Not used for output queue.
        networkType,
        queueIsFull,
        TRUE);
}

//---------------------------------------------------------------------------
// FUNCTION             : GetQueuePriorityFromUserTos
// PURPOSE             :: Returns the queue of the priority.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + userTos            : TosType userTos: Type of service.
// + numQueues          : int numQueues: no of Queues.
// RETURN               : unsigned integer
//---------------------------------------------------------------------------
static
unsigned GetQueuePriorityFromUserTos(
    Node *node,
    TosType userTos,
    int numQueues)
{
    int i = 0;

    int queuePriority = ReturnPriorityForPHB(node, userTos);

    for (i = numQueues - 1; i >= 0; i--)
    {
        if (i <= queuePriority)
        {
            // Return the queue in or from which
            // packet has been queued or dequeued
            return i;
        }
    }
    return IPTOS_PREC_ROUTINE;
}

//-----------------------------------------------------------------------------
// FUNCTION     QueueUpIpv6FragmentForMacLayer
// PURPOSE      Called by NetworkIpSendPacketOnInterface().  Checks if
//              the output queue(s) for the specified interface is empty
//              or full, and calls NetworkIpOutputQueueInsert() to queue
//              the IP packet.  Drops packet if the queue was full.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int interfaceIndex
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop address.
//
// NOTES        This is one of the places where
//              MAC_NetworkLayerHasPacketToSend() may be called,
//              which starts the MAC packet-sending process.  See the
//              comments for the necessary state.
//
//              MAC_NetworkLayerHasPacketToSend() is also called
//              in mpls.pc.
//-----------------------------------------------------------------------------

void
QueueUpIpv6FragmentForMacLayer(
    Node *node,
    Message *msg,
    int interfaceIndex,
    MacHWAddress& nextHop,
    int incomingInterface)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    Scheduler *scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

    ip6_hdr *ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);
    BOOL queueIsFull;
    BOOL queueWasEmpty;

#ifdef ENTERPRISE_LIB

    // If the Diffserv Multi-Field Traffic Conditioner is Enabled
    if (ip->isEdgeRouter == TRUE)
    {
        // Check whether or not the Diffserv Multi-Field Traffic Conditioner
        // will drop this packet
        DIFFSERV_TrafficConditionerProfilePacketAndMarkOrDrop(
            node,
            ip,
            msg,
            incomingInterface,
            //interfaceIndex,
            &queueIsFull);

        if (queueIsFull)
        {
            // DiffServ Multi-Field Traffic Conditioner dropped this packet
            // Free message and return early.

            // Increment stat for number of output IP packets discarded
            // because of a lack of buffer space.

            ip->ipv6->ip6_stat.ip6s_outDiscarded++;

            MESSAGE_Free(node, msg);

// GuiStart
            if (node->guiOption == TRUE)
            {
                TosType priority = GetQueuePriorityFromUserTos(
                                    node,
                                    (TosType)ip6_hdrGetClass(
                                    ipHeader->ipv6HdrVcf),
                                    scheduler->numQueue());

                GUI_QueueDropPacket(node->nodeId, GUI_NETWORK_LAYER,
                                    interfaceIndex, priority,
                                    node->getNodeTime());
            }
//GuiEnd

            return;
        }
    }

#endif // ENTERPRISE_LIB

    // Check the emptiness of the interface's output queue(s) before
    // attempting to queue packet.
        queueWasEmpty = NetworkIpOutputQueueIsEmpty(node, interfaceIndex);

    // Queue packet on output queue of interface.
    Ipv6OutputQueueInsert(node,
                           interfaceIndex,
                           msg,
                           nextHop,
                           ipHeader->ip6_dst,
                           NETWORK_PROTOCOL_IPV6,
                           &queueIsFull);

// GuiStart
    if (!queueIsFull && node->guiOption == TRUE)
    {
        TosType priority = GetQueuePriorityFromUserTos(
                               node,
                               (TosType)ip6_hdrGetClass(
                               ipHeader->ipv6HdrVcf),
                               scheduler->numQueue());

        GUI_QueueInsertPacket(node->nodeId, GUI_NETWORK_LAYER,
                              interfaceIndex, priority,
                              MESSAGE_ReturnPacketSize(msg),
                              node->getNodeTime());
    }
//GuiEnd

    if (queueIsFull)
    {
        // Increment stat for number of output IP packets discarded
        // because of a lack of buffer space.
        ip->ipv6->ip6_stat.ip6s_outDiscarded++;


        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_QUEUE_OVERFLOW;
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acnData,
                        NETWORK_IPV6);


// GuiStart
        if (node->guiOption == TRUE)
        {
            TosType priority = GetQueuePriorityFromUserTos(
                                node,
                                (TosType)ip6_hdrGetClass(
                                ipHeader->ipv6HdrVcf),
                                scheduler->numQueue());

            GUI_QueueDropPacket(node->nodeId, GUI_NETWORK_LAYER,
                                interfaceIndex, priority,
                                node->getNodeTime());
        }
//GuiEnd

        // Free message and return early.
        MESSAGE_Free(node, msg);
        return;
    }

    // Did not have to drop packet because of lack of buffer space.
    //
    // Start the MAC packet-sending process if the interface's output
    // queue(s) was empty, and after the insert attempt, now has a
    // packet to send.

    if (queueWasEmpty)
    {
        if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex))
        {
            MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
        }
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     Ipv6SendOnBackplane
// PURPOSE      Simulates packets going to the router backplane before
//              they are further processed.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packket.
//              int incomingInterface
//                  Index of interface from which packet was received.
//              int outgoingInterface
//                  Index of interface packet is to be sent to.
//              NodeAddress hopAddr
//                  mac address of the next hop node (for forwarding the packet)
//                  or the last hop node (for delivering the packet to upper
//                  layers.
//-----------------------------------------------------------------------------

void Ipv6SendOnBackplane(
     Node* node,
     Message* msg,
     int incomingInterface,
     int outgoingInterface,
     MacHWAddress& hopAddr,
     optionList* opts)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    ip6_hdr* ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    // If we assume unlimited backplane throughput,
    // then we skip the backplane overhead altogether.

    if (ip->backplaneThroughputCapacity ==
        NETWORK_IP_UNLIMITED_BACKPLANE_THROUGHPUT)
    {
        if (outgoingInterface == CPU_INTERFACE)
        {
             ip6_deliver(
                 node,
                 msg,
                 opts,
                 incomingInterface,
                 ipHeader->ip6_nxt);
        }
        else
        {
            QueueUpIpv6FragmentForMacLayer(node,
                                         msg,
                                         outgoingInterface,
                                         hopAddr,
                                         incomingInterface); // Link address
        }
    }
    else
    {
        BOOL queueIsFull = FALSE;

        if (incomingInterface == CPU_INTERFACE ||
            ip->backplaneType == BACKPLANE_TYPE_CENTRAL)
        {
            Ipv6CpuQueueInsert(node,
                               msg,
                               hopAddr, // Link address
                               ipHeader->ip6_dst,
                               outgoingInterface,
                               NETWORK_PROTOCOL_IPV6,
                               &queueIsFull);
        }
        else
        {
            Ipv6InputQueueInsert(node,
                               incomingInterface,
                               msg,
                               hopAddr, // Link address
                               ipHeader->ip6_dst,
                               outgoingInterface,
                               NETWORK_PROTOCOL_IPV6,
                               &queueIsFull);
        }

        // If queue is full, then just drop the packet.  No need to go
        // through the backplane.
        if (queueIsFull)
        {
           // Keep stats on how many packets are dropped due to
           // over backplane throughput limit.
           ip->stats.ipNumDroppedDueToBackplaneLimit++;

            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_QUEUE_OVERFLOW;
            TRACE_PrintTrace(node,
                            msg,
                            TRACE_NETWORK_LAYER,
                            PACKET_IN,
                            &acnData,
                            NETWORK_IPV6);

           // Backplane capacity has been reached, so drop packet.
           MESSAGE_Free(node, msg);
        }
        else
        {
            NetworkIpUseBackplaneIfPossible(node,
                                            incomingInterface);
        }
    }
}


//-----------------------------------------------------------------------------
// FUNCTION     NetworkIpSendPacketOnInterface
// PURPOSE      This function is called once the outgoing interface
//              index and next hop address to which to route an IP
//              packet are known.  This queues an IP packet for delivery
//              to the MAC layer.  This functions calls
//              QueueUpIpv6FragmentForMacLayer().
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              int incomingInterface
//                  Index of incoming interface.
//              int outgoingInterface
//                  Index of outgoing interface.
//              NodeAddress nextHop
//                  Next hop IP address.
// RETURN       None.
//
// NOTES        This function is used to initiate fragmentation if
//              required.
//-----------------------------------------------------------------------------

void
Ipv6SendPacketOnInterface(
    Node *node,
    Message *msg,
    int incomingInterface,
    int outgoingInterface,
    MacHWAddress& nextHopLinkAddr)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    ip6_hdr *ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    // Increment stat for total number of IP datagrams passed to IP for
    // transmission.  Does not include those counted in ipForwardDatagrams.

    ip->stats.ipOutRequests++;

    ERROR_Assert(ipHeader->ip6_plen <= Ipv6GetMTU(node, outgoingInterface),
                 "IPv6 datagram is too large, check NETWORK_IP_FRAG_UNIT in"
                 "include/main.h");

    Ipv6SendOnBackplane(node,
                         msg,
                         incomingInterface,
                         outgoingInterface,
                         nextHopLinkAddr,
                         NULL);

    // Add Fragmentation related codes here
}//Ipv6SendPacketOnInterface//


//-----------------------------------------------------------------------------
// FUNCTION     Ipv6ReceivePacketFromMacLayer
// PURPOSE      IP received IP packet from MAC layer.  Determine whether
//              the packet is to be delivered to this node, or needs to
//              be forwarded.
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to message with IP packet.
//              MacHWAddress* previousHopAddress
//                  nodeId of the previous hop.
//              int incomingInterface
//                  Index of interface on which packet arrived.
// RETURN       None.
//-----------------------------------------------------------------------------

void
Ipv6ReceivePacketFromMacLayer(
    Node* node,
    Message* msg,
    MacHWAddress* lastHopAddress,
    int interfaceIndex)
{
    if (DEBUG_IPV6)
    {
        printf("Ipv6: Received Packet Node=%u, Incoming Inf=%d,"
            "linklayer= ",
            node->nodeId,
            interfaceIndex);
        MAC_PrintHWAddr(lastHopAddress);
        printf("\n");
    }

    // Trace for receive packets.
    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
                    msg,
                    TRACE_NETWORK_LAYER,
                    PACKET_IN,
                    &acnData,
                    NETWORK_IPV6);

//GuiStart
    if (node->guiOption == TRUE)
    {
        in6_addr ipv6PreviousHopAddr;
        NodeAddress lastHopNodeId = 0;
        int interfaceIndex1 = 0;


        BOOL isFound = radix_GetNextHopFromLinkLayerAddress(node,
                                                        &ipv6PreviousHopAddr,
                                                        lastHopAddress);

        if (isFound)
        {
            Address lastHopIpAddr;
            MAPPING_SetAddress(NETWORK_IPV6, &lastHopIpAddr,
                                                       &ipv6PreviousHopAddr);
            lastHopNodeId = MAPPING_GetNodeIdFromGlobalAddr(node,
                                                       ipv6PreviousHopAddr);

            interfaceIndex1 = MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                                          node,
                                                          lastHopIpAddr);

            // Receive a packet from MAC, using VT to display.
            // last hop nodes interface index is found using the first byte
            // of lastHop link layer address.
#ifdef EXATA
            if (msg->isEmulationPacket)
            {
                GUI_Receive(lastHopNodeId,
                            node->nodeId,
                            GUI_NETWORK_LAYER,
                            GUI_EMULATION_DATA_TYPE,
                            interfaceIndex1,
                            interfaceIndex,
                            node->getNodeTime());
            }
            else
            {
                GUI_Receive(lastHopNodeId,
                            node->nodeId,
                            GUI_NETWORK_LAYER,
                            GUI_DEFAULT_DATA_TYPE,
                            interfaceIndex1,
                            interfaceIndex,
                            node->getNodeTime());
            }
#else
            GUI_Receive(lastHopNodeId,
                        node->nodeId,
                        GUI_NETWORK_LAYER,
                        GUI_DEFAULT_DATA_TYPE,
                        interfaceIndex1,
                        interfaceIndex,
                        node->getNodeTime());
#endif
        }
    }
//GuiEnd

    ip6_input(node, msg, 0, interfaceIndex, lastHopAddress);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SendRawMessage
// PURPOSE             :: Ipv6 packet sending function.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + sourceAddress      : in6_addr sourceAddress:
//                          IPv6 source address of packet
// + destinationAddress : in6_addr destinationAddress:
//                          IPv6 destination address of packet.
// + outgoingInterface  : int outgoingInterface
// + priority           : TosType priority: Type of service of packet.
// + protocol           : unsigned char protocol: Next protocol number.
// + ttl                : unsigned ttl: Time to live.
// RETURN               : None
//---------------------------------------------------------------------------

void
Ipv6SendRawMessage(
    Node *node,
    Message *msg,
    in6_addr sourceAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl)
{
    in6_addr newSourceAddress;
    int interfaceIndex = 0;
    MacHWAddress destEthAddr;
    BOOL packetWasRouted = FALSE;

    Ipv6RouterFunctionType routerFunction = NULL;

    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    if (ipv6 == NULL)
    {
        ERROR_ReportError("Trying to send IPv6 packet "
            "without Ipv6 Initialization."
            "Check NETWORK-PROTOCOL parameter in configuration file");
    }

    // check for application packets when
    // source address becomes invalid
    if (!IS_ANYADDR6(sourceAddress) && !Ipv6IsMyIp(node, &sourceAddress))
    {
        ipv6->autoConfigParameters.autoConfigStats.
            numOfPktDropDueToInvalidSrc++;
        MESSAGE_Free(node, msg);
        return;
    }

    // Check for loopback address
    if (Ipv6IsLoopbackAddress(node, destinationAddress)
        || Ipv6IsMyIp(node, &destinationAddress))
    {
        MacHWAddress tempHWAddr;
        Ipv6AddIpv6Header(
            node,
            msg,
            MESSAGE_ReturnPacketSize(msg),
            sourceAddress,
            destinationAddress,
            priority,
            protocol,
            ttl);

        Ipv6SendOnBackplane(
            node,
            msg,
            outgoingInterface,
            CPU_INTERFACE,
            tempHWAddr,
            NULL);

        return;
    }

    if (outgoingInterface == ANY_INTERFACE)
    {
        routerFunction = Ipv6GetRouterFunction(
                            node,
                            Ipv6GetFirstIPv6Interface(node));

        // Trying to figure the source address and outgoing interface to use
        if (!IS_ANYADDR6(sourceAddress))

        {
            interfaceIndex =
                   Ipv6GetInterfaceIndexFromAddress(node, &sourceAddress);
            COPY_ADDR6(sourceAddress, newSourceAddress);
        }
        else
        {
            rn_leaf* ln = NULL;
            prefixLookUp(node, &destinationAddress, &ln);

            if (ln)
            {
                interfaceIndex = ln->interfaceIndex;
            }

            Ipv6GetGlobalAggrAddress (
                node,
                interfaceIndex,
                &newSourceAddress);
        }
    }
    else
    {
        interfaceIndex = outgoingInterface;

        COPY_ADDR6(sourceAddress, newSourceAddress);

        routerFunction = Ipv6GetRouterFunction(node, outgoingInterface);
    }

    Ipv6AddIpv6Header(
        node,
        msg,
        MESSAGE_ReturnPacketSize(msg),
        newSourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);

    // For statistics update
    ipv6->ip6_stat.ip6s_localout++;

    if (TunnelIsVirtualInterface(node, outgoingInterface))
    {
        route ro;

        COPY_ADDR6(destinationAddress, ro.ro_dst);

        ro.ro_rt.rt_node = NULL;

        // Encapsulate IPv6 pkt to tunnel it through the v4 tunnel
        TunnelSendIPv6Pkt(
            node,
            msg,
            0,
            outgoingInterface);

        ipv6->ip6_stat.ip6s_forward++;

        return;
    }

    if (routerFunction && IS_MULTIADDR6(destinationAddress) == FALSE)
    {
        (*routerFunction)(
            node,
            msg,
            destinationAddress,
            ipv6->broadcastAddr,
            &packetWasRouted);
    }

    if (!packetWasRouted)
    {
        ndp6_resolve(
            node,
            CPU_INTERFACE,
            &interfaceIndex,
            NULL,
            msg,
            &destinationAddress);
    }
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SendToUdp
// PURPOSE             :: Ipv6 packet sending to Udp layer function
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message holding v6 packet
// + priority           : TosType priority: Type of Service of the packet.
// + sourceAddress      : Address sourceAddress: Packet's source ip address.
// + destinationAddress : Address destinationAddress: Packet's dest ip address.
// + incomingInterfaceIndex :int incomingInterfaceIndex:
//                          Incomming interface index.
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6SendToUdp(
    Node *node,
    Message *msg,
    TosType priority,
    Address sourceAddress,
    Address destinationAddress,
    int incomingInterfaceIndex)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, TransportProtocol_UDP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo*) MESSAGE_ReturnInfo(msg);

    memcpy(&infoPtr->sourceAddr, &sourceAddress, sizeof(Address));

    memcpy(&infoPtr->destinationAddr, &destinationAddress, sizeof(Address));

    infoPtr->priority = priority;
    infoPtr->incomingInterfaceIndex = incomingInterfaceIndex;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SendToTCP
// PURPOSE             :: Ipv6 packet sending to TCP layer function
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + priority           : TosType priority
// + sourceAddress      : Address sourceAddress
// + destinationAddress : Address destinationAddress
// + incomingInterfaceIndex :int incomingInterfaceIndex
// RETURN               : void
//---------------------------------------------------------------------------
void
Ipv6SendToTCP(
    Node *node,
    Message *msg,
    TosType priority,
    Address sourceAddress,
    Address destinationAddress,
    int incomingInterfaceIndex)
{
    NetworkToTransportInfo *infoPtr;

    MESSAGE_SetEvent(msg, MSG_TRANSPORT_FromNetwork);
    MESSAGE_SetLayer(msg, TRANSPORT_LAYER, TransportProtocol_TCP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(NetworkToTransportInfo));

    infoPtr = (NetworkToTransportInfo*) MESSAGE_ReturnInfo(msg);

    memcpy(&infoPtr->sourceAddr, &sourceAddress, sizeof(Address));

    memcpy(&infoPtr->destinationAddr, &destinationAddress, sizeof(Address));

    infoPtr->priority = priority;
    infoPtr->incomingInterfaceIndex = incomingInterfaceIndex;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}

//-------------------------------------------------------------------------//
//              HOLD BUFFER IMPLEMENTATION.
//-------------------------------------------------------------------------//

//------------------------------------------------------------------------//
//              HASH-TABLE FUNCTIONS.
//------------------------------------------------------------------------//


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6MovePacketsToQueue
// PURPOSE             :: Packets from hash table to queue sending function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + data               : void* data : void pointer to hash data.
// + ln                 : rn_leaf* ln: radix leaf node pointer,
//                              radix leaf associated with the packet's
//                              destination route.
// + destinationAddrPtr : in6_addr* :: Ipv6 destination address pointer
// RETURN               : None
//---------------------------------------------------------------------------
static void
Ipv6MovePacketsToQueue(
                       Node* node,
                       void* data, rn_leaf* ln ,
                       in6_addr* destinationAddrPtr)
{
    messageBuffer* pktData;
    MacHWAddress destEthAddr;
    QueuedPacketInfo *infoPtr;
    int incomingInterface;

    pktData = (messageBuffer*)data;


    if ((!ln) || (ln->linkLayerAddr.hwType == HW_TYPE_UNKNOWN))
    {
        MESSAGE_Free(node, pktData->msg);
        MEM_free(data);
        return;
    }

    MESSAGE_InfoAlloc(node, pktData->msg, sizeof(QueuedPacketInfo));

    infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(pktData->msg);

    // Set IPv6 next hop address
    infoPtr->ipv6NextHopAddr = ln->gateway;

    ip6_hdr* ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(pktData->msg);

    COPY_ADDR6(ipHeader->ip6_dst, *destinationAddrPtr);

    destEthAddr = ln->linkLayerAddr;

    incomingInterface = pktData->inComing;
    ndp6_resolve(
        node,
        incomingInterface,
        &pktData->inComing,
        NULL,
        pktData->msg,
        destinationAddrPtr);

    MEM_free(data);
    return;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6GetHashKey
// PURPOSE             :: Static function to return hash key.
// PARAMETERS          ::
// + ipAddr             : const in6_addr* ipAddr: Ipv6 address pointer,
//                          hash key is generated form the address
// RETURN               : unsigned int: Returns the hash key value.
//---------------------------------------------------------------------------
static unsigned int
Ipv6GetHashKey(const in6_addr* ipAddr)
{
    // Simple efficient hash implementation.
    unsigned int hostBit;
    unsigned int key;

    const UInt8* byte = &ipAddr->s6_addr8[12];

    hostBit = byte[0];
    hostBit <<= 8;
    hostBit |= byte[1];
    hostBit <<= 8;
    hostBit |= byte[2];
    hostBit <<= 8;
    hostBit |= byte[3];

    key = hostBit % MAX_HASHTABLE_SIZE;

    return key;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SearchHashTable
// PURPOSE             :: Static function to search key in the hash table.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + key                : const unsigned int key: Hash key value.
// + ipAddr             : const in6_addr* ipAddr: Ipv6 packet's destination
//                          address.
// RETURN               : Ipv6HashBlockData*: Pointer to hash block data
//---------------------------------------------------------------------------
static Ipv6HashBlockData*
Ipv6SearchHashTable(
        Node* node,
        const unsigned int key,
        const in6_addr* ipAddr)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    Ipv6HashTable* hTable = ipv6->hashTable;
    Ipv6HashBlock* hBlock = NULL;
    Ipv6HashBlockData* blockData = NULL;

    // Hash table is not created yet.
    if (!hTable)
    {
        return NULL;
    }

    // if any block is not created
    if (hTable->firstBlock == NULL)
    {
        return NULL;
    }

    // Search the hash table.
    hBlock = hTable->firstBlock;
    blockData = (Ipv6HashBlockData*) (hBlock->blockData);

    while (hBlock)
    {
        if ((blockData + key)->firstDataPtr == NULL)
        {
            // No data present hence no match found.
            return NULL;
        }
        else
        {
            if (SAME_ADDR6((blockData + key)->ipAddr, *ipAddr))
            {
                return (blockData + key);
            }
        }
        hBlock = hBlock->nextBlock;
    }
    return NULL;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6InsertInHashTable
// PURPOSE             :: Static function to insert packet in hash table.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + key                : const unsigned int key: Hash key value.
// + ipAddr             : const in6_addr* ipAddr    : IPv6 address pointer
// + data               : void* data: Void pointer to hash data.
// RETURN               : BOOL: Returns success or failure
//---------------------------------------------------------------------------
static BOOL
Ipv6InsertInHashTable(
    Node* node,
    const unsigned int key,
    const in6_addr* ipAddr,
    void* data)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    Ipv6HashTable* hTable = ipv6->hashTable;

    Ipv6HashBlock* prevHBlock = NULL;
    Ipv6HashBlock* hBlock = NULL;
    Ipv6HashBlockData* blockData = NULL;

    // Hash table is not created yet.
    if (!hTable)
    {
        ipv6->hashTable = (Ipv6HashTable*)MEM_malloc(sizeof(Ipv6HashTable));
        hTable = ipv6->hashTable;
        hTable->firstBlock = NULL;
    }

    // if any block is not created
    if (hTable->firstBlock == NULL)
    {
        hTable->firstBlock = (Ipv6HashBlock*)
            MEM_malloc(sizeof(Ipv6HashBlock));

        hBlock = hTable->firstBlock;
        hBlock->nextBlock = NULL;

        hBlock->blockData = (Ipv6HashBlockData*)
            MEM_malloc(sizeof(Ipv6HashBlockData) * MAX_HASHTABLE_SIZE);

        // Initialize the Block with default values.
        blockData = (Ipv6HashBlockData*) (hBlock->blockData);
        memset(blockData, 0, sizeof(Ipv6HashBlockData) * MAX_HASHTABLE_SIZE);

        // Create first entry.
        (blockData + key)->firstDataPtr =
            (Ipv6HashData*) MEM_malloc(sizeof(Ipv6HashData));

        (blockData + key)->lastDataPtr = (blockData + key)->firstDataPtr;
        (blockData + key)->lastDataPtr->nextDataPtr = NULL;

        memcpy(&((blockData + key)->ipAddr), ipAddr, sizeof(in6_addr));

        (blockData + key)->lastDataPtr->data = data;

        hBlock->totalDataElements = 1;

        return TRUE;
    }

    // Search Insertion positron in the hash table.
    hBlock = hTable->firstBlock;
    prevHBlock = hBlock;
    blockData = (Ipv6HashBlockData*)(hBlock->blockData);

    while (hBlock)
    {
        if ((blockData + key)->firstDataPtr == NULL)
        {
            // No data present hence Add the first entry..
            (blockData + key)->firstDataPtr =
                (Ipv6HashData*) MEM_malloc(sizeof(Ipv6HashData));

            (blockData + key)->lastDataPtr = (blockData + key)->firstDataPtr;
            (blockData + key)->lastDataPtr->nextDataPtr = NULL;

            memcpy(&((blockData + key)->ipAddr), ipAddr, sizeof(in6_addr));

            (blockData + key)->lastDataPtr->data = data;
            hBlock->totalDataElements++;

            return TRUE;
        }
        else
        {
            if (SAME_ADDR6((blockData + key)->ipAddr, *ipAddr))
            {
                (blockData + key)->lastDataPtr->nextDataPtr =
                    (Ipv6HashData*) MEM_malloc(sizeof(Ipv6HashData));

                (blockData + key)->lastDataPtr =
                    (blockData + key)->lastDataPtr->nextDataPtr;
                (blockData + key)->lastDataPtr->nextDataPtr = NULL;
                (blockData + key)->lastDataPtr->data = data;

                hBlock->totalDataElements++;

                return TRUE;
            }
        }
        prevHBlock = hBlock;
        hBlock = hBlock->nextBlock;
    } // All the blocks have been traversed but proper position not found.

    // Allocate the block to insert the data.
    hBlock = prevHBlock;
    hBlock->nextBlock = (Ipv6HashBlock*)
            MEM_malloc(sizeof(Ipv6HashBlock));

    hBlock = hBlock->nextBlock;
    hBlock->nextBlock = NULL;

    hBlock->blockData = (Ipv6HashBlockData*)
            MEM_malloc(sizeof(Ipv6HashBlockData) * MAX_HASHTABLE_SIZE);

    // Initialize the Block with default values.
    blockData = (Ipv6HashBlockData*)(hBlock->blockData);
    memset(blockData, 0, sizeof(Ipv6HashBlockData) * MAX_HASHTABLE_SIZE);

    // Create first entry in the newly created block.
    (blockData + key)->firstDataPtr = (Ipv6HashData*)
        MEM_malloc(sizeof(Ipv6HashData));

    (blockData + key)->lastDataPtr =
        (blockData + key)->firstDataPtr;
    (blockData + key)->lastDataPtr->nextDataPtr = NULL;

    memcpy(&((blockData + key)->ipAddr), ipAddr, sizeof(in6_addr));
    (blockData + key)->lastDataPtr->data = data;

    hBlock->totalDataElements = 1;
    return TRUE;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6DeleteDataFromHashTable
// PURPOSE             :: static function to delete from hash table.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + key                : const unsigned int key: Hash key value.
// + ipAddr             : const in6_addr* ipAddr    :IPv6 address pointer
// + ln                 : rn_leaf* ln: radix leaf node pointer, associated
//                          with hashed packet's destination route.
// RETURN               : BOOL: returns success or failure.
//---------------------------------------------------------------------------
static BOOL
Ipv6DeleteDataFromHashTable(
        Node* node,
        const unsigned int key,
        const in6_addr* ipAddr,
        rn_leaf* ln)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    Ipv6HashTable* hTable = ipv6->hashTable;
    Ipv6HashBlock* prevHBlock = NULL;
    Ipv6HashBlock* hBlock = NULL;
    Ipv6HashBlockData* blockData = NULL;

    // Hash table is not created yet.
    if (!hTable)
    {
        return FALSE;
    }

    // if first block is not created yet.
    if (hTable->firstBlock == NULL)
    {
        return FALSE;
    }

    // Search the hash table.
    hBlock = hTable->firstBlock;
    prevHBlock = hBlock;
    blockData = (Ipv6HashBlockData*)(hBlock->blockData);

    while (hBlock)
    {
        if ((blockData + key)->firstDataPtr == NULL)
        {
            if (hBlock->nextBlock == NULL)
            {
                // No data present hence no match found.
                return FALSE;
            }
        }
        else
        {
            if (SAME_ADDR6(
                (blockData + key)->ipAddr, *ipAddr))
            {
                Ipv6HashData* tempData = NULL;
                Ipv6HashData* hData =
                    (Ipv6HashData*)((blockData + key)->firstDataPtr);

                while (hData)
                {
                    // Send it other function or delete it.

                    if (ln == NULL)
                    {
                        messageBuffer* mbdPtr = (messageBuffer*)
                                                    hData->data;

                        ipv6->ip6_stat.ip6s_noroute++;
                        MESSAGE_Free(node, mbdPtr->msg);
                        MEM_free(mbdPtr);
                    }
                    else
                    {
                        Ipv6MovePacketsToQueue(
                            node,
                            hData->data,
                            ln,
                            (in6_addr*)ipAddr);
                    }
                    tempData = hData;
                    hData = hData->nextDataPtr;
                    MEM_free(tempData);
                    hBlock->totalDataElements--;
                }
                (blockData + key)->firstDataPtr = NULL;
                (blockData + key)->lastDataPtr = NULL;
                break;
            }
        }
        // if value doe snot match check the next block.
        prevHBlock = hBlock;
        hBlock = hBlock->nextBlock;
        if (hBlock)
        {
            blockData = (Ipv6HashBlockData*)(hBlock->blockData);
        }
    }

    if (!hBlock)
    {
        return FALSE;
    }
    else
    {
        if (hBlock->totalDataElements <= 0)
        {
            // it is not the first block.
            if (prevHBlock != hBlock)
            {
                prevHBlock->nextBlock = hBlock->nextBlock;
                if (hBlock->blockData)
                {
                    MEM_free(hBlock->blockData);
                }
                MEM_free(hBlock);
            }
            else // it is the first block.
            {
                // if there is no other block;
                if (hBlock->nextBlock == NULL)
                {
                    hTable->firstBlock = NULL;
                }
                else
                {
                    hTable->firstBlock = hBlock->nextBlock;
                }
                if (hBlock->blockData)
                {
                    MEM_free(hBlock->blockData);
                }
                MEM_free(hBlock);
            }
        }
    }
    return TRUE;
}


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddMessageInBuffer
// PURPOSE             :: Adds a ipv6 packet in the buffer.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + msg                : Message* msg : Pointer to message holding v6 packet.
// + nextHopAddr        : in6_addr* nextHopAddr :IPv6 address pointer,
//                              packet's destination address.
// + inComingInterface  : int inComingInterface: Incoming interface index.
// + rn                 : rn_leaf* rn: radix leaf node pointer, associated
//                          with packet's destination route.
// RETURN               : BOOL
//---------------------------------------------------------------------------
BOOL
Ipv6AddMessageInBuffer(
    Node* node,
    Message* msg,
    in6_addr* nextHopAddr,
    int inComingInterface,
    rn_leaf* rn)
{
    messageBuffer* bufData = NULL;
    bufData = (messageBuffer*) MEM_malloc(sizeof(messageBuffer));

    // Insert the values accordingly.
    bufData->msg = msg;
    bufData->inComing = inComingInterface; // Incoming interface
    bufData->rn = rn;

    if (!Ipv6InsertInHashTable(
            node,
            Ipv6GetHashKey(nextHopAddr),
            nextHopAddr,
            bufData))
    {
        MEM_free(bufData);
        return FALSE;
    }
    return TRUE;
}

// /**
// FUNCTION   :: Ipv6GetPrefixFromInterfaceIndex
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 prefix from address.
// PARAMETERS ::
// + node      : Node* : Node pointer
// + interfaceIndex : int : interface for which multicast is required
// RETURN     :: Prefix for this interface
// **/
in6_addr
Ipv6GetPrefixFromInterfaceIndex(
    Node* node,
    int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp* ) node->networkData.networkVar;
    IPv6InterfaceInfo* iface =
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    in6_addr interfaceAddress;
    in6_addr prefix;

    // Get interface address from the interface index
    Ipv6GetGlobalAggrAddress(
        node,
        interfaceIndex,
        &interfaceAddress);

    Ipv6GetPrefix(
        &interfaceAddress,
        &prefix,
        iface->prefixLen);

    return(prefix);
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6DeleteMessageInBuffer
// PURPOSE             :: Deletes ipv6 packets from buffer
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + nextHopAddr        : in6_addr nextHopAddr  : IPv6 Address
// + ln                 : rn_leaf* ln: radix leaf node pointer, associated
//                          with packet's destination route.
// RETURN               : BOOL: returns success or failure
//---------------------------------------------------------------------------
BOOL
Ipv6DeleteMessageInBuffer(
        Node* node,
        in6_addr nextHopAddr,
        rn_leaf* ln)
{
    if (Ipv6DeleteDataFromHashTable(
        node,
        Ipv6GetHashKey(&nextHopAddr),
        &nextHopAddr,
        ln))
    {
        return TRUE;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6DropMessageFromBuffer
// PURPOSE             :: Drops ipv6 packets from buffer
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + nextHopAddr        : in6_addr nextHopAddr: Next hop's Ipv6 address
// + ln                 : rn_leaf* ln: radix leaf node pointer, associated
//                          with packet's next hop route.
// RETURN               : BOOL: returns success or failure
//---------------------------------------------------------------------------
BOOL
Ipv6DropMessageFromBuffer(
        Node* node,
        in6_addr nextHopAddr,
        rn_leaf* ln)
{
    if (Ipv6DeleteDataFromHashTable(
        node,
        Ipv6GetHashKey(&nextHopAddr),
        &nextHopAddr,
        ln))
    {
        return TRUE;
    }
    return FALSE;
}

//-------------------------------------------------------------------------//
// Static Routing Code.
//-------------------------------------------------------------------------//

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6RoutingStaticEntry
// PURPOSE             :: Static routing route entry function
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + currentLine        : char currentLine[]: Static entry's current line.
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6RoutingStaticEntry(
    Node *node,
    char currentLine[])
{
    rn_leaf* keyNode;
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;

    char destAddressString[MAX_STRING_LENGTH];
    char nextHopString[MAX_STRING_LENGTH];

    NodeAddress sourceAddress;

    in6_addr ipAddress;
    unsigned int prefixLength = 0;
    in6_addr nextHopAddress;
    unsigned int nextHopPrefixLength = 0;

    BOOL isIpAddr = FALSE;
    NodeId nodeId = 0;
    rn_leaf* rn;

    // For IO_GetDelimitedToken
    char* next;
    char delims[] = {" \t\n"};
    char iotoken[MAX_STRING_LENGTH];
    char err[MAX_STRING_LENGTH];

    char* token = IO_GetDelimitedToken(iotoken, currentLine, delims, &next);

    if (!isdigit(*token))
    {
        sprintf(err, "Static Routing: First argument must be node id:\n"
            "%s", currentLine);
        ERROR_ReportError(err);
    }

    // Get source node.
    sourceAddress = atoi(token);

    if (sourceAddress != node->nodeId)
    {
        return;
    }

     // Retrieve next token.
    token = IO_GetDelimitedToken(iotoken, next, delims, &next);

    if (token == NULL)
    {
        sprintf(err,
            "Static Routing: Wrong arguments:\n %s",
            currentLine);
        ERROR_ReportError(err);
    }

    // Get destination address.
    strcpy(destAddressString, token);

    if (!strchr(destAddressString, ':'))
    {
        IO_ParseNodeIdHostOrNetworkAddress(
            destAddressString,
            &ipAddress,
            &isIpAddr,
            &nodeId);

        if (isIpAddr && !nodeId)
        {
            if (ipAddress.s6_addr32[2] != 0 &&
                ipAddress.s6_addr32[3] != 0)
            {
                sprintf(err, "Static Routing: destination must be a "
                    "network\n  %s\n", currentLine);
                ERROR_ReportError(err);
            }
        }
        else
        {
            if (!nodeId)
            {
                unsigned int tla = ipAddress.s6_addr32[0];
                unsigned int nla = ipAddress.s6_addr32[1];
                unsigned int sla = ipAddress.s6_addr32[2];

                // Check TLA, NLA, SLA range validity
                MAPPING_CreateIpv6GlobalUnicastAddr(
                    tla,
                    nla,
                    sla,
                    0, // To Create Network Address
                    &ipAddress);

                prefixLength = 64;
            }
            else
            {
                // Error Message
                sprintf(err, "Static Routing: destination must be a "
                    "network or host address\n  %s\n",
                    currentLine);
                ERROR_ReportError(err);
            }
        }
    }
    else
    {
        IO_ParseNodeIdHostOrNetworkAddress(
            destAddressString,
            &ipAddress,
            &isIpAddr,
            &nodeId,
            &prefixLength);

        if (nodeId)
        {
            // Error Message
            sprintf(err, "Static Routing: destination must be a "
                "network or host address\n  %s\n",
                currentLine);
            ERROR_ReportError(err);
        }
    }

    if (Ipv6GetFirstIPv6Interface(node) == -1)
    {
        sprintf(err,
                "Static Routing: Node %d is not an IPv6 node"
                " inside %s\n",
            node->nodeId,
            currentLine);
        ERROR_Assert(FALSE, err);
    }

    // Retrieve next token.
    token = IO_GetDelimitedToken(iotoken, next, delims, &next);
    if (token == NULL)
    {
        sprintf(err,
            "Static Routing: Wrong arguments:\n %s",
            currentLine);
        ERROR_ReportError(err);
    }

    // Get next hop address.
    strcpy(nextHopString, token);

    IO_ParseNodeIdHostOrNetworkAddress(
        nextHopString,
        &nextHopAddress,
        &isIpAddr,
        &nodeId,
        &nextHopPrefixLength);

    if ((node->networkData.networkProtocol != DUAL_IP)
        && Ipv6IpGetInterfaceIndexForNextHop(node, nextHopAddress) == -1)
    {
        sprintf(err,
                "Static Routing: Node %d is not connected to next hop %s"
                " inside %s\n",
            node->nodeId,
            nextHopString,
            currentLine);

        ERROR_Assert(FALSE, err);
    }

    if (!isIpAddr || nodeId)
    {
        sprintf(err, "Static Routing: Next hop address must be an "
                "interface address\n  %s\n",currentLine);

        ERROR_ReportError(err);
    }

    if (DEBUG_IPV6)
    {
        char tempStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(&nextHopAddress, tempStr);
        printf("Next Hop Address %s\n", tempStr);
    }

    // Now add the Static Routes.
    keyNode = (rn_leaf*) MEM_malloc(sizeof(rn_leaf));

    memset(keyNode, 0, sizeof(rn_leaf));

    keyNode->key = ipAddress;

    keyNode->keyPrefixLen = prefixLength;

    // Add Gateway or static routing next hop address.
    keyNode->gateway = nextHopAddress;


    keyNode->interfaceIndex = -1;
    keyNode->flags = RT_REMOTE;
    keyNode->type = 0;

    keyNode->rn_option = RTF_STATIC; // manually added.

    // Insert into Radix Tree.
    rn = (rn_leaf*) rn_insert(node,(void*) keyNode, ipv6->rt_tables);

    // Add Prefix in the prefix list
    if (!ipv6->prefixHead)
    {
        ipv6->prefixHead = (prefixList*) MEM_malloc(sizeof(prefixList));
        ipv6->prefixTail = ipv6->prefixHead;
        ipv6->prefixTail->next = NULL;
        ipv6->prefixTail->prev = NULL;
        ipv6->prefixTail->rnp = rn;
        ipv6->noOfPrefix++;
    }
    else
    {
        addPrefix(ipv6->prefixTail, rn, &(ipv6->noOfPrefix));
        ipv6->prefixTail = ipv6->prefixTail->next;
    }
} // end of function.


/****************** Destination Cache handling functions *****************/


//---------------------------------------------------------------------------
// FUNCTION             : Ipv6AddDestination
// PURPOSE             :: Adds destination in the destination cache.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + ro                 : route* ro: Pointer to destination route.
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6AddDestination(Node* node, route* ro)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    DestinationCache* destCache = &(ipv6->destination_cache);

    // No need to add default route in destination cache.
    if (ro)
    {
        rn_leaf* ln = ro->ro_rt.rt_node;
        if (ln)
        {
            if ((ln->key.s6_addr32[0] == 0) &&
                (ln->key.s6_addr32[1] == 0) &&
                (ln->key.s6_addr32[2] == 0) &&
                (ln->key.s6_addr32[3] == 0))
            {
                return;
            }

        }// end of not adding default route.
    }

    if (destCache->start == NULL)
    {
        destCache->start = (DestinationRoute*)
            MEM_malloc(sizeof(DestinationRoute));
        destCache->start->nextRoute = NULL;
        destCache->start->ro = ro;
        destCache->end = destCache->start;
    }
    else
    {
        destCache->end->nextRoute = (DestinationRoute*)
            MEM_malloc(sizeof(DestinationRoute));
        destCache->end->nextRoute->nextRoute = NULL;
        destCache->end = destCache->end->nextRoute;
        destCache->end->ro = ro;
    }
    ro->ro_rt.rt_expire = node->getNodeTime() + REACHABLE_TIME;
}

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6DeleteDestination
// PURPOSE             :: Deletes destination from the destination cache.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN               : None
//---------------------------------------------------------------------------
void Ipv6DeleteDestination(Node* node)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    DestinationCache* destCache = &(ipv6->destination_cache);
    DestinationRoute* temp = destCache->start;
    DestinationRoute* prev = temp;

    while (temp != NULL)
    {
        if (temp->ro->ro_rt.rt_node)
        {
            // Delete the route if time expired.
            if ((node->getNodeTime() - temp->ro->ro_rt.rt_expire) >= 0
                || temp->ro->ro_rt.rt_node->rn_flags == RNF_IGNORE)
            {
                // Deleting the starting route.
                if (temp == prev)
                {
                    // There is only one route.
                    if (destCache->start == destCache->end)
                    {
                        destCache->start = NULL;
                        destCache->end = NULL;
                        FreeRoute(temp->ro);
                        MEM_free(temp);
                        temp = NULL;
                    }
                    else
                    {
                        destCache->start = temp->nextRoute;
                        FreeRoute(temp->ro);
                        MEM_free(temp);
                        temp = destCache->start;
                        prev = destCache->start;
                    }
                }
                else
                {
                    if (temp == destCache->end)
                    {
                        destCache->end = prev;
                        prev->nextRoute = NULL;
                        FreeRoute(temp->ro);
                        MEM_free(temp);
                        temp = NULL;
                    }
                    else
                    {
                        prev->nextRoute = temp->nextRoute;
                        FreeRoute(temp->ro);
                        MEM_free(temp);
                        temp = prev->nextRoute;
                    }

                }
            } // end of deleting expired route.
            else
            {
                prev = temp;
                temp = temp->nextRoute;
            }
        }
        else // do no any operation the routes which are in use.
        {
            prev = temp;
            temp = temp->nextRoute;
        }
    } // end of deleting all expired routes loop.
}

// /**
// FUNCTION            :: Ipv6UpdateForwardingTable
// LAYER               :: Network
// PURPOSE             :: Updates Ipv6 Forwarding Table
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + destPrefix         : in6_addr destPrefix : IPv6 destination address
// + nextHopPrefix      : in6_addr nextHopPrefix: IPv6 next hop address for this destination
// + interfaceIndex     : int interfaceIndex
// + metric             : int metric : hop count between source and destination
// RETURN              :: None
// **/

void Ipv6UpdateForwardingTable(
    Node* node,
    in6_addr destPrefix,
    unsigned int destPrefixLen,
    in6_addr nextHopPrefix,
    int interfaceIndex,
    int metric,
    NetworkRoutingProtocolType type)
{
    rn_leaf* keyNode;
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    rn_leaf* rn;

    rn_leaf* ln = NULL;
    MacHWAddress llAddr;

    keyNode = (rn_leaf*) MEM_malloc(sizeof(rn_leaf));

    memset(keyNode, 0, sizeof(rn_leaf));

    keyNode->key = destPrefix;
    keyNode->gateway = nextHopPrefix;

    keyNode->flags = RT_REMOTE;
    keyNode->type = (int)type;
    keyNode->interfaceIndex = interfaceIndex;
    keyNode->metric = metric;
    keyNode->rn_option = RTF_DYNAMIC; // manually added.
    keyNode->rn_flags = RNF_ACTIVE;
    keyNode->keyPrefixLen = destPrefixLen;

    if (DEBUG_IPV6)
    {
        printf("Before update\n");
        Ipv6PrintForwardingTable(node);
    }
    if (metric == NETWORK_UNREACHABLE)
    {
        // delete the route from the routing table
        rn = (rn_leaf*) rn_delete((void*) keyNode, ipv6->rt_tables);

        MEM_free(keyNode);
    }
    else
    {
        // Insert new route into the routing table
        in6_addr networkAddress;

        if (NetworkIpIsWiredNetwork(node, interfaceIndex))
        {
            networkAddress = Ipv6GetPrefixFromInterfaceIndex(
                                 node,
                                 interfaceIndex);
        }
        else
        {
            Ipv6GetGlobalAggrAddress(
                node,
                interfaceIndex,
                &networkAddress);
        }

        if (0 == CMP_ADDR6(destPrefix, networkAddress))
        {
            // Destination network is directly connected
            keyNode->linkLayerAddr = Ipv6GetLinkLayerAddress(
                                        node,
                                        interfaceIndex);
            keyNode->flags = RT_LOCAL;

            // Insert the route into the routing table.
            rn = (rn_leaf*) rn_insert(node, (void*) keyNode, ipv6->rt_tables);
        }
        else
        {
            // Destination network is not directly connected.

            // Insert the route into the routing table.
            rn = (rn_leaf*) rn_insert(node, (void*) keyNode, ipv6->rt_tables);

            // Get the linklayer address of the gateway.
            ln = ndplookup(node, interfaceIndex, &nextHopPrefix, 1, llAddr);
            if (ln)
            {
                // Add Gateway or static routing next hop address.
                rn->gateway = nextHopPrefix;
                // If old mac-address is incompatible with new mac-address.
                if (rn->linkLayerAddr.hwLength != 0
                 && ln->linkLayerAddr.hwLength != 0
                 && rn->linkLayerAddr.hwLength != ln->linkLayerAddr.hwLength)
                {
                    rn->linkLayerAddr = INVALID_MAC_ADDRESS;
                }
                rn->linkLayerAddr = ln->linkLayerAddr;
                rn->interfaceIndex = ln->interfaceIndex;
                rn->flags = RT_REMOTE;
                rn->type = (int)type;
                rn->metric = metric;
                rn->rn_option = RTF_DYNAMIC; // manually added.
            }
        }

        if (rn != keyNode)
        {
            // route already exists so free the new allocation
            MEM_free(keyNode->linkLayerAddr.byte);
            MEM_free(keyNode);
        }
        else
        {
            // Add Prefix in the prefix list
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
                addPrefix(ipv6->prefixTail, rn, &(ipv6->noOfPrefix));
                ipv6->prefixTail = ipv6->prefixTail->next;
            }
        }

        route* ro = destinationLookUp(node, ipv6, &destPrefix);
        if (ro)
        {
            // update destination cache
            ro->ro_rt.rt_node->linkLayerAddr = rn->linkLayerAddr;
            ro->ro_rt.rt_node->interfaceIndex = interfaceIndex;
            ro->ro_rt.rt_node->gateway = nextHopPrefix;
        }
    }
    if (DEBUG_IPV6)
    {
        printf("After update\n");
        Ipv6PrintForwardingTable(node);
    }

    return;
}

// /**
// FUNCTION            :: Ipv6SetRouterFunction
// LAYER               :: Network
// PURPOSE             :: Sets the router function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + routerFunctionPtr  : Ipv6RouterFunctionType routerFunctionPtr: router
//                      : function pointer.
// + interfaceIndex     : int interfaceIndex : Interface index
// RETURN              :: void : NULL.
// **/
void Ipv6SetRouterFunction(Node *node,
                           Ipv6RouterFunctionType routerFunctionPtr,
                           int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_IPV6
        || ip->interfaceInfo[interfaceIndex]->interfaceType == NETWORK_DUAL)
    {
        IPv6InterfaceInfo *interfaceInfo;
        interfaceInfo = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

        ERROR_Assert(interfaceInfo->routerFunction ==
                 NULL,
                 "Router function already set");

        interfaceInfo->routerFunction = routerFunctionPtr;
    }
}

// /**
// FUNCTION     :: Ipv6InterfaceIndexFromSubnetAddress
// LAYER        :: Network
// PURPOSE      :: Get the interface index from an IPv6 subnet address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + address    :  in6_addr*     : Subnet Address
// RETURN       :: Interface index associated with specified subnet address.
// **/
int Ipv6InterfaceIndexFromSubnetAddress(
    Node *node,
    in6_addr address)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;
    in6_addr networkAddr, interfaceNetworkAddr;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
            || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            IPv6InterfaceInfo *interfaceInfo =
                ip->interfaceInfo[i]->ipv6InterfaceInfo;

            // Variable Subnet prefix length will be implemented Later
            Ipv6GetPrefix(&address, &networkAddr, interfaceInfo->prefixLen);

            Ipv6GetPrefix(
                &interfaceInfo->globalAddr,
                &interfaceNetworkAddr,
                interfaceInfo->prefixLen);

            if (CMP_ADDR6(networkAddr, interfaceNetworkAddr) == 0)
            {
                return i;
            }

            Ipv6GetPrefix(
                &interfaceInfo->siteLocalAddr,
                &interfaceNetworkAddr,
                MAX_PREFIX_LEN);

            if (CMP_ADDR6(networkAddr, interfaceNetworkAddr) == 0)
            {
                return i;
            }

            Ipv6GetPrefix(
                &interfaceInfo->linkLocalAddr,
                &interfaceNetworkAddr,
                MAX_PREFIX_LEN);

            if (CMP_ADDR6(networkAddr, interfaceNetworkAddr) == 0)
            {
                return i;
            }

        }
    }

    return -1;
}

// /**
// FUNCTION     :: Ipv6IpGetInterfaceIndexForNextHop
// LAYER        :: Network
// PURPOSE      :: This function looks at the network address of each of a
//                 node's network interfaces. When nextHopAddress is
//                 matched to a network, the interface index corresponding
//                 to the network is returned.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: Interface index associated with destination if found,
//                 -1 otherwise.
// **/
int Ipv6IpGetInterfaceIndexForNextHop(
    Node *node,
    in6_addr address)
{
    return Ipv6InterfaceIndexFromSubnetAddress(node, address);
}

// /**
// FUNCTION     :: Ipv6GetInterfaceAndNextHopFromForwardingTable
// LAYER        :: Network
// PURPOSE      :: Do a lookup on the routing table with a destination IPv6
//                 address to obtain an outgoing interface and a next hop
//                 Ipv6 address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// + interfaceIndex   :  int*    : Pointer to interface index
// + nextHopAddr   :  in6_addr*  : Next Hop Addr for destination.
// RETURN       :: void : NULL.
// **/
void Ipv6GetInterfaceAndNextHopFromForwardingTable(
    Node* node,
    in6_addr destAddr,
    int* interfaceIndex,
    in6_addr* nextHopAddress)
{
    rn_leaf* ln = NULL;

    *interfaceIndex = NETWORK_UNREACHABLE;

    prefixLookUp(node, &destAddr, &ln);

    if (ln)
    {
        *interfaceIndex = ln->interfaceIndex;
        if (ln->flags == RT_LOCAL)
            memset(nextHopAddress,0,sizeof(in6_addr));
        else
            (*nextHopAddress) = ln->gateway;
    }
}

// /**
// FUNCTION     :: Ipv6GetInterfaceIndexForDestAddress
// LAYER        :: Network
// PURPOSE      :: Get interface for the destination address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: Interface index associated with destination if found,
//                 -1 otherwise.
// **/
int Ipv6GetInterfaceIndexForDestAddress(
    Node* node,
    in6_addr destAddr)
{
    rn_leaf* ln = NULL;

    prefixLookUp(node, &destAddr, &ln);

    if (ln)
    {
        return ln->interfaceIndex;
    }
    return -1;
}

// /**
// FUNCTION     :: Ipv6GetMetricForDestAddress
// LAYER        :: Network
// PURPOSE      :: Get the cost metric for a destination from the
//                 forwarding table.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: Interface index associated with destination if found,
//                 -1 otherwise.
// **/
unsigned Ipv6GetMetricForDestAddress(
    Node* node,
    in6_addr destAddr)
{
    rn_leaf* ln = NULL;

    prefixLookUp(node, &destAddr, &ln);

    if (ln)
    {
        return ln->metric;
    }
    return (unsigned) NETWORK_UNREACHABLE;
}
// /**
// FUNCTION         :: Ipv6SendRawMessageToMac
// LAYER            :: Network
// PURPOSE          :: Use to send packet if IPv6 next hop address is known.
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + destAddr       :  in6_addr      : Destination Address
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + interfaceIndex :  Int32      : Interface Index
// RETURN           :: void : NULL.
// **/
void
Ipv6SendRawMessageToMac(
    Node *node,
    Message *msg,
    in6_addr sourceAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    in6_addr newSourceAddress;
    int interfaceIndex = 0;
    MacHWAddress destEthAddr;

    if (ipv6 == NULL)
    {
        ERROR_ReportError("Trying to send IPv6 packet "
            "without Ipv6 Initialization."
            "Check NETWORK-PROTOCOL parameter in configuration file");
    }
    if (outgoingInterface == ANY_INTERFACE)
    {
        // Trying to figure the source address and outgoing interface to use
        if (!IS_ANYADDR6(sourceAddress))

        {
            interfaceIndex =
                   Ipv6GetInterfaceIndexFromAddress(node, &sourceAddress);
            COPY_ADDR6(sourceAddress, newSourceAddress);
        }
        else
        {
            rn_leaf* ln = NULL;
            prefixLookUp(node, &destinationAddress, &ln);

            if (ln)
            {
                interfaceIndex = ln->interfaceIndex;
            }

            Ipv6GetGlobalAggrAddress (
                node,
                interfaceIndex,
                &newSourceAddress);
        }
    }
    else
    {
        interfaceIndex = outgoingInterface;

        COPY_ADDR6(sourceAddress, newSourceAddress);
    }

    Ipv6AddIpv6Header(
        node,
        msg,
        MESSAGE_ReturnPacketSize(msg),
        newSourceAddress,
        destinationAddress,
        priority,
        protocol,
        ttl);

    // For statistics update
    ipv6->ip6_stat.ip6s_localout++;

    if (TunnelIsVirtualInterface(node, outgoingInterface))
    {
        route ro;

        COPY_ADDR6(destinationAddress, ro.ro_dst);

        ro.ro_rt.rt_node = NULL;

        //MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));

        // Encapsulate IPv6 pkt to tunnel it through the v4 tunnel
        TunnelSendIPv6Pkt(
            node,
            msg,
            0,
            outgoingInterface);

        return;

    }

    ndp_resolvellAddrandSendToMac(
        node,
        msg,
        destinationAddress,
        outgoingInterface);

}


// /**
// API              :: Ipv6GetRouterFunction
// LAYER            :: Network
// PURPOSE          :: Get the router function pointer.
// PARAMETERS       ::
// + node           :  Node* : Pointer to node.
// + interfaceIndex :  int   : interface associated with router function
// RETURN           :: Ipv6RouterFunctionType : router function pointer.
// **/
Ipv6RouterFunctionType Ipv6GetRouterFunction(
    Node* node,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    IPv6InterfaceInfo *interfaceInfo =
                ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    if (interfaceInfo == NULL)
    {
        return NULL;
    }

    return interfaceInfo->routerFunction;
}

// /**
// API              :: Ipv6SetMulticastTimer
// LAYER            :: Network
// PURPOSE          :: Set timer to join and leave multicast groups.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to join or leave.
// + delay          :  clocktype    : delay.
// RETURN           :: void  : NULL.
// **/
void Ipv6SetMulticastTimer(
    Node* node,
    Int32 eventType,
    in6_addr mcastAddr,
    clocktype delay)

{
    Message* msg;
    in6_addr* info;

    msg = MESSAGE_Alloc(node,
                         NETWORK_LAYER,
                         NETWORK_PROTOCOL_IPV6,
                         eventType);

    MESSAGE_InfoAlloc(node, msg, sizeof(in6_addr));

    info = (in6_addr *) MESSAGE_ReturnInfo(msg);

    COPY_ADDR6(mcastAddr, *info);

    MESSAGE_Send(node, msg, delay);
}

// /**
// API              :: Ipv6JoinMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Join a multicast group.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to join.
// + delay          :  clocktype    : delay.
// RETURN           :: void  : NULL.
// **/
void Ipv6JoinMulticastGroup(
    Node* node,
    in6_addr mcastAddr,
    clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];

    if (IS_MULTIADDR6(mcastAddr) == FALSE
        || Ipv6IsReservedMulticastAddress(node, mcastAddr) == TRUE)
    {
        IO_ConvertIpAddressToString(&mcastAddr, grpStr);

        sprintf(errStr, "Node %u: Unable to set JoinTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {

        Ipv6SetMulticastTimer(node, MSG_NETWORK_JoinGroup, mcastAddr, delay);
    }
}

// /**
// API              :: Ipv6AddToMulticastGroupList
// LAYER            :: Network
// PURPOSE          :: Add group to multicast group list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + groupAddress   :  in6_addr     : Group to add to multicast group list.
// RETURN           :: void  : NULL.
// **/
void Ipv6AddToMulticastGroupList(Node* node, in6_addr groupAddress)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* list = ip->ipv6->multicastGroupList;
    ListItem* item = list->first;

    Ipv6MulticastGroupEntry* entry = NULL;

    // Go through the group list...
    while (item)
    {
        entry = (Ipv6MulticastGroupEntry* ) item->data;

        // Group already exists, so incrememt member count.
        if (CMP_ADDR6(entry->groupAddress, groupAddress) == 0)
        {
            entry->memberCount++;
            return;
        }

        item = item->next;
    }

    // Group doesn't exist, so add to multicast group list.
    entry = (Ipv6MulticastGroupEntry* )
            MEM_malloc(sizeof(Ipv6MulticastGroupEntry));

    COPY_ADDR6(groupAddress, entry->groupAddress);

    entry->memberCount = 1;

    ListInsert(node, list, node->getNodeTime(), entry);
}

// /**
// API              :: Ipv6LeaveMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Leave a multicast group.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + groupAddress   :  in6_addr     : Group to be removed from multicast
//                                    group list.
// + delay          :  clocktype    : delay.
// RETURN           :: void  : NULL.
// **/
void Ipv6LeaveMulticastGroup(
    Node *node,
    in6_addr mcastAddr,
    clocktype delay)
{
    char errStr[MAX_STRING_LENGTH];
    char grpStr[MAX_ADDRESS_STRING_LENGTH];

    if (IS_MULTIADDR6(mcastAddr) == FALSE
        || Ipv6IsReservedMulticastAddress(node, mcastAddr) == TRUE)
    {
        IO_ConvertIpAddressToString(&mcastAddr, grpStr);

        sprintf(errStr, "Node %u: Unable to set LeaveTimer\n"
            "    Group address %s is not a valid multicast address\n",
            node->nodeId, grpStr);

        ERROR_ReportError(errStr);
    }
    else
    {
        Ipv6SetMulticastTimer(
            node,
            MSG_NETWORK_LeaveGroup,
            mcastAddr,
            delay);
    }
}

// /**
// API              :: Ipv6RemoveFromMulticastGroupList
// LAYER            :: Network
// PURPOSE          :: Remove group from multicast group list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + groupAddress   :  in6_addr     : Group to be removed from multicast
//                                    group list.
// RETURN           :: void  : NULL.
// **/
void Ipv6RemoveFromMulticastGroupList(Node* node, in6_addr groupAddress)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* list = ip->ipv6->multicastGroupList;
    ListItem* item = list->first;

    Ipv6MulticastGroupEntry* entry = NULL;

    // Go through the multicast group list...
    while (item)
    {
        entry = (Ipv6MulticastGroupEntry* ) item->data;

        // Found it...
        if (CMP_ADDR6(entry->groupAddress, groupAddress) == 0)
        {
            // If only no one else belongs to the group, remove from group list.
            if (entry->memberCount == 1)
            {
                ListGet(node,
                        list,
                        item,
                        TRUE,
                        FALSE);
            }
            // Someone else also belongs to the group,
            // so decrement member count.
            else if (entry->memberCount > 1)
            {
                entry->memberCount--;
            }
            else
            {
                assert(FALSE);
            }

            return;
        }

        item = item->next;
    }
}

// /**
// API        :: Ipv6MacLayerStatusEventHandlerFunctionType
// LAYER      :: Network
// PURPOSE    :: Get the status event handler function pointer.
// PARAMETERS ::
// + node           : Node* : Pointer to node.
// + interfaceIndex : int   : interface associated with the status
//                            handler function.
// RETURN     :: MacLayerStatusEventHandlerFunctionType : Status event
//                                                        handler function.
// **/
Ipv6MacLayerStatusEventHandlerFunctionType
Ipv6GetMacLayerStatusEventHandlerFunction(
    Node* node,
    int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp* ) node->networkData.networkVar;
    IPv6InterfaceInfo* iface =
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    return iface->macLayerStatusEventHandlerFunction;
}

// /**
// API              :: Ipv6HandleSpecialMacLayerStatusEvents
// LAYER            :: Network
// PURPOSE          :: Give the routing protocol the messages that come from
//                     the MAC layer with packet drop notification.
//                     Used by the routing protocols for routing optimization.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + msg            :  Message*          : Pointer to message.
// + nextHopAddress :  const NodeAddress : Next Hop Address
// + interfaceIndex :  int               : Interface Index
// RETURN           :: void  : NULL.
// **/
static void
Ipv6HandleSpecialMacLayerStatusEvents(
    Node* node,
    Message* msg,
    MacHWAddress& nextHopAddress,
    int interfaceIndex)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;
    in6_addr ipv6PreviousHopAddr;

    Ipv6MacLayerStatusEventHandlerFunctionType pFuntion =
        Ipv6GetMacLayerStatusEventHandlerFunction(node, interfaceIndex);

    if (MAC_IsBroadcastHWAddress(&nextHopAddress))
    {
        COPY_ADDR6(ipv6->broadcastAddr, ipv6PreviousHopAddr);
    }
    else if (nextHopAddress.hwType == HW_TYPE_UNKNOWN)
    {
        //Drop notifiaction need to be added
        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_INVALID_LINK_ADDRESS;
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acnData,
                        NETWORK_IPV6);

        MESSAGE_Free(node, msg);

        return;
    }
    else if (!radix_GetNextHopFromLinkLayerAddress(
                    node,
                    &ipv6PreviousHopAddr,
                    &nextHopAddress))
    {
        MESSAGE_Free(node, msg);

        return;
    }

    if (pFuntion)
    {
        (pFuntion)(node, msg, ipv6PreviousHopAddr, interfaceIndex);
    }//if//

    MESSAGE_Free(node, msg);
}

// /**
// API              :: Ipv6NotificationOfPacketDrop
// LAYER            :: Network
// PURPOSE          :: Invoke callback functions when a packet is dropped.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + msg            :  Message*          : Pointer to message.
// + nextHopAddress :  const NodeAddress : Next Hop Address
// + interfaceIndex :  int               : Interface Index
// RETURN           :: void  : NULL.
// **/
void
Ipv6NotificationOfPacketDrop(
    Node* node,
    Message* msg,
    MacHWAddress& nextHopAddress,
    int interfaceIndex)
{
    IPv6Data *ipv6 = (IPv6Data *) node->networkData.networkVar->ipv6;

    ip6_hdr* ip6Header = (ip6_hdr *) MESSAGE_ReturnPacket(msg);

    ipv6->ip6_stat.ip6s_macpacketdrop++;

    if (ip6Header->ip6_nxt == IPPROTO_ICMPV6)
    {
        //Trace drop
        ActionData acnData;
        acnData.actionType = DROP;
        acnData.actionComment = DROP_INTERFACE_DOWN;
        TRACE_PrintTrace(node,
                        msg,
                        TRACE_NETWORK_LAYER,
                        PACKET_IN,
                        &acnData,
                        NETWORK_IPV6);

        MESSAGE_Free(node, msg);
        return;
    }

    MESSAGE_SetLayer(msg, NETWORK_LAYER, ROUTING_PROTOCOL_ALL);
    MESSAGE_SetEvent(msg, MSG_NETWORK_PacketDropped);
    MESSAGE_SetInstanceId(msg, 0);

    Ipv6HandleSpecialMacLayerStatusEvents(
        node,
        msg,
        nextHopAddress,
        interfaceIndex);
}

// /**
// API              :: Ipv6DeleteOutboundPacketsToANode
// LAYER            :: Network
// PURPOSE          :: Deletes all packets in the queue going to the
//                     specified next hop address. There is option to return
//                     all such packets back to the routing protocols.
// PARAMETERS       ::
// + node                           :  Node*          : Pointer to node.
// + nextHopAddress                 :  const in6_addr : Next Hop Address.
// + destinationAddress             :  const in6_addr : Destination Address
// + returnPacketsToRoutingProtocol :  const BOOL     : bool
// RETURN                           :: void  : NULL.
// **/
void Ipv6DeleteOutboundPacketsToANode(
    Node *node,
    in6_addr ipv6NextHopAddress,
    in6_addr destinationAddress,
    const BOOL returnPacketsToRoutingProtocol)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int interfaceIndex;

    for (interfaceIndex = 0;
         interfaceIndex < node->numberInterfaces;
         interfaceIndex++)
    {
        if (TunnelIsVirtualInterface(node, interfaceIndex))
        {
            continue;
        }
        int queueIndex = DEQUEUE_NEXT_PACKET;
        Scheduler* scheduler = NULL;
        QueuedPacketInfo* infoPtr;

        scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

        while (queueIndex < NetworkIpOutputQueueNumberInQueue(
                                node,
                                interfaceIndex,
                                FALSE,
                                ALL_PRIORITIES))
        {
            Message* msg = NULL;
            QueuePriorityType msgPriority = ALL_PRIORITIES;

            if (!scheduler->retrieve(
                    ALL_PRIORITIES,
                    queueIndex,
                    &msg,
                    &msgPriority,
                    PEEK_AT_NEXT_PACKET,
                    node->getNodeTime()))
            {
                ERROR_ReportError("Cannot retrieve packet");
            }

            infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

            if (((IS_MULTIADDR6(ipv6NextHopAddress))
                || (CMP_ADDR6(
                        infoPtr->ipv6NextHopAddr,
                        ipv6NextHopAddress) == 0))
                && ((IS_MULTIADDR6(destinationAddress)
                || !CMP_ADDR6(
                        infoPtr->destinationAddress.ipv6DestAddr,
                        destinationAddress) == 0)
                ))
            {
                if (!scheduler->retrieve(
                        ALL_PRIORITIES,
                        queueIndex,
                        &msg,
                        &msgPriority,
                        DROP_PACKET,
                        node->getNodeTime()))
                {
                    ERROR_ReportError("Cannot retrieve packet");
                }

                if (returnPacketsToRoutingProtocol)
                {
                    MacHWAddress destAddr;
                    destAddr.hwType = infoPtr->hwType;
                    destAddr.hwLength = infoPtr->hwLength;
                    destAddr.byte = (unsigned char*)
                                               MEM_malloc(destAddr.hwLength);
                    memcpy(destAddr.byte, infoPtr->macAddress,
                                                          destAddr.hwLength);

                    Ipv6HandleSpecialMacLayerStatusEvents(
                        node,
                        msg,
                        destAddr,
                        interfaceIndex);
                }
                else
                {
                    MESSAGE_Free(node, msg);
                }
            }
            else
            {
                queueIndex++;
            }
        }
    }
}

// /**
// API              :: Ipv6IsPartOfMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Check if destination is part of the multicast group.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + msg            :  Message*          : Pointer to message.
// + groupAddress   :  in6_addr          : Multicast Address
// RETURN           :: TRUE if node is part of multicast group,
//                     FALSE otherwise.
// **/
BOOL Ipv6IsPartOfMulticastGroup(Node* node, in6_addr groupAddress)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;

    ListItem* item = ipv6->multicastGroupList->first;

    Ipv6MulticastGroupEntry* entry;

    // Go through list and see if we belong to this multicast group.
    while (item)
    {
        entry = (Ipv6MulticastGroupEntry* ) item->data;

        // Found it!
        if (CMP_ADDR6(entry->groupAddress, groupAddress) == 0)
        {
            return TRUE;
        }

        item = item->next;
    }

    // Not part of multicast group...
    return FALSE;
}

// /**
// API              :: Ipv6IsReservedMulticastAddress
// LAYER            :: Network
// PURPOSE          :: Check if address is reserved multicast address.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to join.
// RETURN           :: TRUE if reserved multicast address, FALSE otherwise.
// **/
BOOL Ipv6IsReservedMulticastAddress(Node* node, in6_addr mcastAddr)
{
    if (!IS_MULTIADDR6(mcastAddr))
    {
        return FALSE;
    }
    else if (!(mcastAddr.s6_addr8[1] & IP6_T_FLAG))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

// /**
// API              :: Ipv6UpdateMulticastForwardingTable
// LAYER            :: Network
// PURPOSE          :: update entry with (sourceAddress,
//                     multicastGroupAddress) pair. search for the row with
//                     (sourceAddress, multicastGroupAddress) and update its
//                     interface.
// PARAMETERS       ::
// + node                   :  Node*        : Pointer to node.
// + sourceAddress          :  in6_addr     : Source Address.
// + multicastGroupAddress  :  in6_addr     : multicast group.
// RETURN           ::  void : NULL.
// **/
void Ipv6UpdateMulticastForwardingTable(
    Node* node,
    in6_addr sourceAddress,
    in6_addr multicastGroupAddress,
    int interfaceIndex)
{
    BOOL newInsert = FALSE;
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;

    Ipv6MulticastForwardingTable* multicastForwardingTable =
                                    &ipv6->multicastForwardingTable;

    const unsigned int intialTableRowSize = 8;

    int i;

    if (interfaceIndex < 0)
    {
        printf("Error node %u: invalid interface index %d is invalid.\n",
                node->nodeId, interfaceIndex);
        abort();
    }

    // See if there's a match in the table already and get the index
    // of the table where we want to update (match or new entry).
    for (i=0; i < multicastForwardingTable->size
            && (CMP_ADDR6(
                    multicastForwardingTable->row[i].sourceAddress,
                    sourceAddress)
            || CMP_ADDR6(
                    multicastForwardingTable->row[i].multicastGroupAddress,
                    multicastGroupAddress)); i++)
    {
        /* No match. */
    }

    // If where we are going to insert is at the end, make sure the
    // table is big enough.  If not, make it bigger.
    if (i == multicastForwardingTable->size)
    {
        multicastForwardingTable->size++;

        newInsert = TRUE;

        // Increase the table size if we ran out of space.
        if (multicastForwardingTable->size >
            multicastForwardingTable->allocatedSize)
        {
            if (multicastForwardingTable->allocatedSize == 0)
            {
                multicastForwardingTable->allocatedSize = intialTableRowSize;

                multicastForwardingTable->row =
                    (Ipv6MulticastForwardingTableRow* )MEM_malloc(
                            multicastForwardingTable->allocatedSize
                            * sizeof(Ipv6MulticastForwardingTableRow));
            }
            else
            {
                int newSize = (multicastForwardingTable->allocatedSize * 2);

                Ipv6MulticastForwardingTableRow* newTableRow =
                    (Ipv6MulticastForwardingTableRow*)MEM_malloc(
                          newSize
                          * sizeof(Ipv6MulticastForwardingTableRow));

                memcpy(
                    newTableRow,
                    multicastForwardingTable->row,
                    (multicastForwardingTable->allocatedSize
                    * sizeof(Ipv6MulticastForwardingTableRow)));

                MEM_free(multicastForwardingTable->row);

                multicastForwardingTable->row = newTableRow;
                multicastForwardingTable->allocatedSize = newSize;
            }//if//
        }//if//

        while (i > 0
                && (Ipv6CompareAddr6(
                        sourceAddress,
                        multicastForwardingTable->row[i - 1].sourceAddress)
                > 0))
        {
            multicastForwardingTable->row[i] =
                            multicastForwardingTable->row[i-1];

            i--;
        }//while//

    }//if//

    COPY_ADDR6(
        sourceAddress,
        multicastForwardingTable->row[i].sourceAddress);

    COPY_ADDR6(
        multicastGroupAddress,
        multicastForwardingTable->row[i].multicastGroupAddress);

    if (newInsert)
    {
        ListInit(node, &multicastForwardingTable->row[i].outInterfaceList);
    }

    // Only insert interface if interface not in the interface list already.
    if (!Ipv6InMulticastOutgoingInterface(
            node,
            multicastForwardingTable->row[i].outInterfaceList,
            interfaceIndex))
    {
        int* outInterfaceIndex = (int* ) MEM_malloc(sizeof(int));

        *outInterfaceIndex = interfaceIndex;

        ListInsert(
            node,
            multicastForwardingTable->row[i].outInterfaceList,
            node->getNodeTime(),
            outInterfaceIndex);
    }
}

// /**
// API              :: Ipv6InMulticastOutgoingInterface
// LAYER            :: Network
// PURPOSE          :: Determine if interface is in multicast outgoing
//                     interface list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + list           :  LinkedList*  : Pointer to Linked List.
// + interfaceIndex :  int          : Interface Index.
// RETURN           :: TRUE if interface is in multicast outgoing interface
//                     list, FALSE otherwise.
// **/
BOOL Ipv6InMulticastOutgoingInterface(
    Node* node,
    LinkedList* list,
    int interfaceIndex)
{
    ListItem* item = list->first;

    while (item)
    {
        int* outInterfaceIndex =  (int* )item->data;

        if (interfaceIndex == *outInterfaceIndex)
        {
            return TRUE;
        }

        item = item->next;
    }

    return FALSE;
}

// /**
// API              :: Ipv6GetOutgoingInterfaceFromMulticastTable
// LAYER            :: Network
// PURPOSE          :: get the interface List that lead to the (source,
//                     multicast group) pair.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + sourceAddress  :  in6_addr     : Source Address
// + groupAddress   :  in6_addr     : multicast group address
// RETURN           :: Interface List if match found, NULL otherwise.
// **/
LinkedList* Ipv6GetOutgoingInterfaceFromMulticastTable(
    Node* node,
    in6_addr sourceAddress,
    in6_addr groupAddress)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    Ipv6MulticastForwardingTable* multicastTable =
                                    &ipv6->multicastForwardingTable;
    int i;

    // Look for (source, group) pair.  If exist, use the indicated interface.
    // If not, return NETWORK_UNREACHABLE;
    for (i=0; i < multicastTable->size; i++) {

        if (!CMP_ADDR6(multicastTable->row[i].sourceAddress, sourceAddress)
            && !CMP_ADDR6(
                    multicastTable->row[i].multicastGroupAddress,
                    groupAddress))
        {
            return multicastTable->row[i].outInterfaceList;
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: Ipv6CreateBroadcastAddress
// LAYER      :: NETWORK
// PURPOSE    :: Create IPv6 Broadcast Address (ff02 followed by all one).
// PARAMETERS ::
//  +node           :  Node* : Pointer to Node.
//  +multicastAddr  : in6_addr* : Pointer to broadcast address.
// RETURN     :: void : NULL.
// **/
void
Ipv6CreateBroadcastAddress(Node* node, in6_addr* multicastAddr)
{
    multicastAddr->s6_addr[0] = 0xff;
    multicastAddr->s6_addr[1] = 0x02;
    multicastAddr->s6_addr[2] = 0xff;
    multicastAddr->s6_addr[3] = 0xff;
    multicastAddr->s6_addr32[1] = ANY_DEST;
    multicastAddr->s6_addr32[2] = ANY_DEST;
    multicastAddr->s6_addr32[3] = ANY_DEST;
}

// /**
// FUNCTION   :: Ipv6GetPrefixLength
// LAYER      :: NETWORK
// PURPOSE    :: Get prefix length of an interface.
// PARAMETERS ::
//  +node           : Node* : Pointer to Node.
//  +interfaceIndex : int   : Inetrafce Index.
// RETURN     :: Prefix Length.
// **/
UInt32
Ipv6GetPrefixLength(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    IPv6InterfaceInfo *pIfaceInfo = NULL;

    ERROR_Assert(
        interfaceIndex < node->numberInterfaces,
        "Invalid Interface Index");

    pIfaceInfo = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    return pIfaceInfo->prefixLen;
}

// /**
// FUNCTION   :: Ipv6GetFirstIPv6Interface
// LAYER      :: NETWORK
// PURPOSE    :: Return first IPv6 enabled interface.
// PARAMETERS ::
//  +node           : Node* : Pointer to Node.
// RETURN     :: Interface Index if found, -1 otherwise.
// **/
int Ipv6GetFirstIPv6Interface(Node* node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i = 0;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
            || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            return i;
        }
    }

    return -1;
}

// /**
// API              :: Ipv6SetMacLayerStatusEventHandlerFunction
// LAYER            :: Network
// PURPOSE          :: Allows the MAC layer to send status messages (e.g.,
//                     packet drop, link failure) to a network-layer routing
//                     protocol for routing optimization.
// PARAMETERS       ::
// + node                  :  Node*     : Pointer to node.
// + StatusEventHandlerPtr :  Ipv6MacLayerStatusEventHandlerFunctionType
//                                      : Function Pointer.
// + interfaceIndex        :  int       : Interface Index
// RETURN                  :: void      : NULL.
// **/
void
Ipv6SetMacLayerStatusEventHandlerFunction(
    Node *node,
    Ipv6MacLayerStatusEventHandlerFunctionType StatusEventHandlerPtr,
    int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

   IPv6InterfaceInfo *interfaceInfo =
                ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    ERROR_Assert(interfaceInfo->macLayerStatusEventHandlerFunction == NULL,
                 "IPv6-MAC-layer event handler function already set");

    interfaceInfo->macLayerStatusEventHandlerFunction =
                                            StatusEventHandlerPtr;
}

// /**
// API              :: Ipv6IsLoopbackAddress
// LAYER            :: Network
// PURPOSE          :: Check if address is self loopback address.
// PARAMETERS       ::
// + node            :  Node*     : Pointer to node.
// + address         :  in6_addr  : ipv6 address
// RETURN                  :: void      : NULL.
// **/
BOOL Ipv6IsLoopbackAddress(Node* node, in6_addr address)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    BOOL retVal = FALSE;

#ifdef CYBER_LIB
    if (ipv6 == NULL)
    {
        return FALSE;
    }
#endif // CYBER_LIB
    if (CMP_ADDR6(address, ipv6->loopbackAddr) == 0)
    {
        retVal = TRUE;
    }
    // Multicast Loopback
    else if (IS_MULTIADDR6(address)
            && (address.s6_addr8[1] & IP6_MULTI_INTERFACE_SCOPE))
    {
        retVal = TRUE;
    }

    return retVal;
}

// /**
// API              :: Ipv6IsMyIp
// LAYER            :: Network
// PURPOSE          :: Check if address is self loopback address.
// PARAMETERS       ::
// + node            :  Node*     : Pointer to node.
// + dst_addr        :  in6_addr* : Pointer to ipv6 address
// RETURN           :: TRUE if my Ip, FALSE otherwise.
// **/
BOOL Ipv6IsMyIp(Node* node, in6_addr* dst_addr)
{
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if ((NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
            && Ipv6IsPacketForThisInterface(node, i, dst_addr))
        {
            return TRUE;
        }
    }
    return FALSE;
} // end of the function;

// /**
// API              :: Ipv6IsValidGetMulticastScope
// LAYER            :: Network
// PURPOSE          :: Check if multicast address has valid scope.
// PARAMETERS       ::
// + node            :  Node*           : Pointer to node.
// + multiAddr       : in6_addr         : multicast address.
// RETURN           :: Scope value if valid multicast address, 0 otherwise.
// **/
int Ipv6IsValidGetMulticastScope(Node* node, in6_addr multiAddr)
{
    unsigned char scope = multiAddr.s6_addr8[1] & 0x0f;
    int retVal = 0;

    switch (scope)
    {
        case 0x00:
        case 0x03:
        case 0x0f:
        {
            ERROR_ReportWarning("MCBR: destination address scope belongs"
                                " to reserved range\n");
            break;
        }
        case 0x06:
        case 0x07:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
        {
            ERROR_ReportWarning("MCBR: destination address scope belongs"
                                " to unassigned range\n");
            break;
        }
        case IP6_MULTI_INTERFACE_SCOPE:
        case IP6_MULTI_LINK_SCOPE:
        case IP6_MULTI_ADMIN_SCOPE:
        case IP6_MULTI_SITE_SCOPE:
        case IP6_MULTI_ORG_SCOPE:
        case IP6_MULTI_GLOBAL_SCOPE:
        {
            retVal = scope;
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "Invalid Multicast Address");
        }
    }
    return retVal;
}

// /**
// FUNCTION         :: Ipv6SendPacketToMacLayer
// LAYER            :: Network
// PURPOSE          :: Use to send packet if IPv6 next hop address is known.
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + msg            :  Message*      : Pointer to Message
// + destAddr       :  in6_addr      : Destination Address
// + nextHopAddr    :  in6_addr      : Next Hop Address
// + interfaceIndex :  Int32      : Interface Index
// RETURN           :: void : NULL.
// **/
void Ipv6SendPacketToMacLayer(
    Node* node,
    Message* msg,
    in6_addr destAddr,
    in6_addr nextHopAddr,
    Int32 interfaceIndex)
{
    IPv6Data* ipv6  = (IPv6Data*) node->networkData.networkVar->ipv6;
    rn_leaf keyNode;
    rn_leaf* ndp_cache_entry;
    MacHWAddress destEthAddr;
    in6_addr localAddr;

    CLR_ADDR6(localAddr);

    if (TunnelIsVirtualInterface(node, interfaceIndex))
    {
        route ro;

        COPY_ADDR6(destAddr, ro.ro_dst);

        ro.ro_rt.rt_node = NULL;

        //MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));

        // Encapsulate IPv6 pkt to tunnel it through the v4 tunnel
        TunnelSendIPv6Pkt(
            node,
            msg,
            0,
            interfaceIndex);

        return;

    }

    if (CMP_ADDR6(localAddr, nextHopAddr) == 0)
    {
        keyNode.key = destAddr;
    }
    else
    {
        keyNode.key = nextHopAddr;
    }

    // search for the gateway entry in ndp_cache
    ndp_cache_entry = (rn_leaf*)rn_search((void*)&keyNode, ipv6->ndp_cache);

    if (ndp_cache_entry != NULL
        && ndp_cache_entry->linkLayerAddr.hwType != HW_TYPE_UNKNOWN)
    {
        route ro;

        COPY_ADDR6(destAddr, ro.ro_dst);

        ro.ro_rt.rt_node = ndp_cache_entry;

        ip6_output(
            node,
            msg,
            (optionList*)NULL,
            &ro,
            0,
            (ip_moptions*)NULL,
            CPU_INTERFACE,
            interfaceIndex);

        // increment stats for number of IPv6 packets forwarded
        ipv6->ip6_stat.ip6s_forward++;

    }
    else
    {
        ndp_resolvellAddrandSendToMac(
            node,
            msg,
            nextHopAddr,
            interfaceIndex);
    }
}

// /**
// API                 :: IsIPV6RoutingEnabledOnInterface
// LAYER               :: Network
// PURPOSE             :: To check if IPV6 Routing is enabled on interface?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL IsIPV6RoutingEnabledOnInterface(Node* node,
                                 int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    if (ip->interfaceInfo[interfaceIndex]
           ->ipv6InterfaceInfo->routingProtocolType != ROUTING_PROTOCOL_NONE)
    {
        return TRUE;
    }
    return FALSE;
}

//-------------------------------------------------------------------------//
// NAME         :IPv6InterfaceStatusHandler()
// PURPOSE      :Handle mac alert.
// ASSUMPTION   :None
// RETURN VALUE :None
//-------------------------------------------------------------------------//
void IPv6InterfaceStatusHandler(
    Node* node,
    int interfaceIndex,
    MacInterfaceState state)
{
    switch (state)
    {
        case MAC_INTERFACE_DISABLE:
        {
            //needs to cancle the periodic Timers
            break;
        }

        case MAC_INTERFACE_ENABLE:
        {
            Ipv6InterfaceInitAdvt(node, interfaceIndex);
            break;
        }

        default:
        {
            ERROR_Assert(FALSE, "Unknown MacInterfaceState\n");
        }
    }
}
