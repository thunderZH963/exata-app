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
#include <list>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "external.h"
#include "external_util.h"
#include "external_socket.h"
#include "network_ip.h"
#include "ipv6.h"
#include "transport_udp.h"

#include "auto-ipnetworkemulator.h"
#include "ipne_qualnet_interface.h"
#include "inject_interface.h"
#include "olsr_interface.h"
#include "ospf_interface.h"
#include "ipnetworkemulator.h"
#include "pim_interface.h"
#include "packet_validation.h"
#include "record_replay.h"
#include "igmpv3_interface.h"

// for mdp
#include "mdp_interface.h"
#include "app_mdp.h"
// For IPSec
#include "ipsec_interface.h"
#include "app_util.h"
//---------------------------------------------------------------------------
// Static Functions
//---------------------------------------------------------------------------
/*
 * FUNCTION:   BytesSwapHton
 * PURPOSE:    Swap the bytes of IP and UDP/TCP in ICMP message. This function is
                for the implementation of TRACEROUTE.  Traceroute request from operatioanal node
                is injected to simulator, and the ICMP message of 'time exceeded' and 'port unreachable'
                is transmitted back to operational node for TRACEROUTE. Bytes swapping is for the
                ICMP return packets.
 * RETURN:     NULL
 * PARAMETERS: msg,            message to be swapped (pointer from IP header)
 */

static void BytesSwapHton(UInt8* msg)
{
    //  Swap bytes for IP header
    IpHeaderType *ipHeader;
    int ipHeaderLength;
    UInt8* nextHeader;

    ipHeader = (IpHeaderType *) msg;

    ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;
    nextHeader = msg + ipHeaderLength;

    //unsigned int t;

    EXTERNAL_hton(
        &ipHeader->ip_v_hl_tos_len,
        sizeof(ipHeader->ip_v_hl_tos_len));
#ifdef BITF
    char t;
    t=ipHeader->ip_v;
    ipHeader->ip_v=ipHeader->ip_hl;
    ipHeader->ip_hl=t;

    ((((UInt16)(ipHeader->ip_len) & 0xff00) >> 8) | (((UInt16)(ipHeader->ip_len) & 0x00ff) << 8));
#endif

#ifdef BITF
    EXTERNAL_hton(
        &ipHeader->ip_ttl,
        sizeof(ipHeader->ip_ttl));
    EXTERNAL_hton(
        &ipHeader->ip_p,
        sizeof(ipHeader->ip_p));
    EXTERNAL_hton(
        &ipHeader->ip_src,
        sizeof(ipHeader->ip_src));
    EXTERNAL_hton(
        &ipHeader->ip_dst,
        sizeof(ipHeader->ip_dst));
#endif
    EXTERNAL_hton(
        &ipHeader->ip_ttl,
        sizeof(ipHeader->ip_ttl));
    EXTERNAL_hton(
        &ipHeader->ip_p,
        sizeof(ipHeader->ip_p));
    EXTERNAL_hton(
        &ipHeader->ip_id,
        sizeof(ipHeader->ip_id));
    EXTERNAL_hton(
        &ipHeader->ip_src,
        sizeof(ipHeader->ip_src));
    EXTERNAL_hton(
        &ipHeader->ip_dst,
        sizeof(ipHeader->ip_dst));

    EXTERNAL_hton(
        &ipHeader->ip_sum,
        sizeof(ipHeader->ip_sum));
    if (ipHeader->ip_p == IPPROTO_UDP)
    {
           //  Swap bytes for UDP header
        TransportUdpHeader *header;
        // Extract UDP  header
        header = (TransportUdpHeader*)nextHeader;

        EXTERNAL_hton(
            &header->sourcePort,
            sizeof(header->sourcePort));
        EXTERNAL_hton(
            &header->destPort,
            sizeof(header->destPort));
        EXTERNAL_hton(
            &header->length,
            sizeof(header->length));
        EXTERNAL_hton(
            &header->checksum,
            sizeof(header->checksum));
    }
    else if (ipHeader->ip_p == IPPROTO_TCP)
    {
        struct libnet_tcp_hdr* tcp;
        tcp = (struct libnet_tcp_hdr *)nextHeader;

        // Swap TCP header and call register port handlers
        tcp->th_sport = htons(tcp->th_sport);
        tcp->th_dport = htons(tcp->th_dport);
        tcp->th_seq   = htonl(tcp->th_seq);
        tcp->th_ack   = htonl(tcp->th_ack);
        tcp->th_win   = htons(tcp->th_win);
        tcp->th_sum   = 0;
        tcp->th_urp   = htons(tcp->th_urp);

//        tcp->th_x2 = tcp->th_off;
        tcp->th_off = tcp->th_x2;


/*
        unsigned char *field = (unsigned char *)(nextHeader + 12);
        unsigned char lval = *field >> 4;
        unsigned char rval = *field & 0xFF;
        *field = (rval << 4) | lval;
*/

        UInt16 *checksum = (UInt16 *)&tcp->th_sum;

/*
        *checksum = AutoIPNEComputeTcpStyleChecksum(
                htonl(ipHeader->ip_src),
                htonl(ipHeader->ip_dst),
                ipHeader->ip_p,
                htons(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength),
                (UInt8 *)tcp);
*/
        *checksum = AutoIPNEComputeTcpStyleChecksum(
                (ipHeader->ip_src),
                (ipHeader->ip_dst),
                ipHeader->ip_p,
                htons((UInt16)(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength)),
                (UInt8 *)tcp);
    }

}

// /**
// API        :: FindAnIpOptionField
// PURPOSE    :: Searches the IP header for the option field with option
//               code that matches optionKey, and returns a pointer to
//               the option field header.
// PARAMETERS ::
// + ipHeader  : const IpHeaderType*  : Pointer to an IP header.
// + optionKey : const int            : Option code for desired option field.
// + ipHeaderLength  : Length of IP Header
// RETURN     :: IpOptionsHeaderType* : to the header of the desired option
//                                      field. NULL if no option fields, or
//                                      the desired option field cannot be
//                                      found.
// **/
static IpOptionsHeaderType *
FindAnIpOptionField(
    const IpHeaderType *ipHeader,
    const int optionKey,
    int ipHeaderLength)
{
    IpOptionsHeaderType *currentOption;

    // If the passed in IP header is the minimum size, return NULL.
    // (no option in IP header)
    if (ipHeaderLength == sizeof(IpHeaderType))
    {
        return NULL;
    }

    // Move pointer over 20 bytes from start of IP header,
    // so currentOption points to first option.
    currentOption = (IpOptionsHeaderType *)
                    ((char *) ipHeader + sizeof(IpHeaderType));

    // Loop until an option code matches optionKey.
    while (currentOption->code != optionKey)
    {
        if (currentOption->code == IPOPT_NOP)
        {
            // Move pointer over 1 byte from start of options field, so
            // currentOption points to next option, if the current
            // option is a NOP.
            currentOption = (IpOptionsHeaderType *)
                            ((char *) currentOption + 1);
            continue;
        }
        // Options should never report their length as 0.
        if (currentOption->len == 0)
        {
            return NULL;
        }

        // Current option code doesn't match; move pointer over to next option.

        currentOption =
            (IpOptionsHeaderType *) ((char *) currentOption +
                                                        currentOption->len);

        // If we've run out of options, return NULL.
        if ((char *) currentOption
                >= (char *) ipHeader + IpHeaderSize(ipHeader)||
            *((char *) currentOption) == IPOPT_EOL)
        {
            return NULL;
        }
    }

    // Found option with code matching optionKey.  Return pointer to option.

    return currentOption;
}

// /**
// API        :: FindTraceRouteOption
// PURPOSE    :: Searches the IP header for the Traceroute option field ,
//               and returns a pointer to traceroute header.
// PARAMETERS ::
// + ipHeader  : const IpHeaderType*  : Pointer to an IP header.
// + ipHeaderLength  : Length of IP Header
// RETURN     :: ip_traceroute* : pointer to the header of the traceroute
//               option field. NULL if no option fields, or the desired
//               option field cannot be found.
// **/

static
ip_traceroute *FindTraceRouteOption(const IpHeaderType *ipHeader,
                                    int ipHeaderLength)
{
    IpOptionsHeaderType *currentOption;
    ip_traceroute *traceRouteOption;

    // If the passed in IP header is the minimum size, return NULL.
    // (no option in IP header)
    if (ipHeaderLength == sizeof(IpHeaderType))
    {
        return NULL;
    }

    // Move pointer over 20 bytes from start of IP header,
    // so currentOption points to first option.
    currentOption = (IpOptionsHeaderType *)
                    ((char *) ipHeader + sizeof(IpHeaderType));
    traceRouteOption = (ip_traceroute *)currentOption;

    // Loop until an option code matches optionKey.
    while (traceRouteOption->type != IPOPT_TRCRT)
    {
        // Options should never report their length as 0.
        if (currentOption->len == 0)
        {
            return NULL;
        }

        /* Current option code doesn't match;
           move pointer over to next option */
        currentOption =
            (IpOptionsHeaderType *) ((char *) currentOption +
                                                         currentOption->len);
        traceRouteOption = (ip_traceroute *)currentOption;

        // If we've run out of options, return NULL.
        if ((char *) currentOption
                >= (char *) ipHeader + IpHeaderSize(ipHeader)||
            *((char *) currentOption) == IPOPT_EOL)
        {
            return NULL;
        }
    }

    // Found tracerote option, Return pointer to option.

    return traceRouteOption;
}

// /**
// API       :: AutoIPNEComputeIcmpStyleChecksum
// PURPOSE   :: Computes a checksum for the packet usable for ICMP
// PARAMETERS::
// + packet : UInt8* : Pointer to the beginning of the packet
// + length : UInt16 : Length of the packet in bytes (network byte order)
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeIcmpStyleChecksum(
    UInt8* packet,
    UInt16 length)
{
    bool odd;
    UInt16* paddedPacket;
    int sum;
    int i;
    int packetLength;

    packetLength = ntohs(length);
    odd = packetLength & 0x1;

    // If the packet is an odd length, pad it with a zero
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
    // Assumes parameters are in network byte order

    sum = 0;
    for (i = 0; i < packetLength / 2; i++)
    {
        //printf("paddedpacket[%d]=%d\n",i,paddedPacket[i]);
       sum += paddedPacket[i];
    }
    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    if (odd)
    {
        MEM_free(paddedPacket);
    }

    // Return the checksum
    return ~((UInt16) sum);
}


// /**
// API       :: AutoIPNEComputeTcpStyleChecksum
// PURPOSE   :: This function will compute a TCP checksum.  It may be used
//              for TCP type checksum, including UDP.  It assumes all
//              parameters are passed in network byte order.  The packet
//              pointer should point to the beginning of the tcp header,
//              with the packet data following.  The checksum field of the
//              TCP header should be 0.
// PARAMETERS::
// + srcAddress : UInt32 : The source IP address
// + dstAddress : UInt32 : The destination IP address
// + protocol : UInt8 : The protocol (in the IP header)
// + tcpLength : UInt16 : The length of the TCP header + packet data
// + packet : UInt8* : Pointer to the beginning of the packet
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeTcpStyleChecksum(
    UInt32 srcAddress,
    UInt32 dstAddress,
    UInt8 protocol,
    UInt16 tcpLength,
    UInt8* packet)
{
    UInt8 virtualHeader[12];
    UInt16* virtualHeaders = (UInt16*) virtualHeader;
    int sum;
    int i;

    // Compute the checksum
    // Assumes parameters are in network byte order
    memcpy(&virtualHeader[0], &srcAddress, sizeof(UInt32));
    memcpy(&virtualHeader[4], &dstAddress, sizeof(UInt32));
    virtualHeader[8] = 0;
    virtualHeader[9] = protocol;
    memcpy(&virtualHeader[10], &tcpLength, sizeof(UInt16));

    // The first part of the checksum is an ICMP style checksum over the
    // packet
    sum = (UInt16) ~AutoIPNEComputeIcmpStyleChecksum(packet, tcpLength);

    // The second part of the checksum is the virtual header
    for (i = 0; i < 12 / 2; i++)
    {
        sum += virtualHeaders[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Return the checksum
    return ~((UInt16) sum);
}

// /**
// API       :: AutoIPNEComputeTcpStyleChecksum
// PURPOSE   :: This function will compute a TCP checksum.  It may be used
//              for TCP type checksum, including UDP.  It assumes all
//              parameters are passed in network byte order.  The packet
//              pointer should point to the beginning of the tcp header,
//              with the packet data following.  The checksum field of the
//              TCP header should be 0. This overloaded function is for 
//              Ipv6.
// PARAMETERS::
// + srcAddress : UInt8* : Ponter to source IPv6 address
// + dstAddress : UInt8* : Ponter to destination IPv6 address
// + protocol : UInt8 : The protocol (in the IP header)
// + tcpLength : UInt32 : The length of the TCP header + packet data
// + packet : UInt8* : Pointer to the beginning of the packet
// RETURN    :: void
// **/
UInt16 AutoIPNEComputeTcpStyleChecksum(
    UInt8* srcAddress,
    UInt8* dstAddress,
    UInt8 protocol,
    UInt32 tcpLength,
    UInt8* packet)
{
    UInt8 virtualHeader[40];
    UInt16* virtualHeaders = (UInt16*) virtualHeader;
    int sum = 0;
    int i = 0;

    // Compute the checksum
    // Assumes parameters are in network byte order

    memcpy(&virtualHeader[0], srcAddress, sizeof(in6_addr));
    memcpy(&virtualHeader[16], dstAddress, sizeof(in6_addr));
    memcpy(&virtualHeader[32], &tcpLength, sizeof(UInt32));
    virtualHeader[36] = 0;
    virtualHeader[37] = 0;
    virtualHeader[38] = 0;
    virtualHeader[39] = protocol;

    // The first part of the checksum is an ICMP style checksum over the
    // packet

    sum = (UInt16) ~AutoIPNEComputeIcmpStyleChecksum(packet,(UInt16)tcpLength);

    // The second part of the checksum is the virtual header
    for (i = 0; i < 40 / 2; i++)
    {
        sum += virtualHeaders[i];
    }

    while ((0xffff & (sum >> 16)) > 0)
    {
        sum = (sum & 0xFFFF) + ((sum >> 16) & 0xffff);
    }

    // Return the checksum
    return ~((UInt16) sum);
}


// /**
// API       :: AutoIPNEIncrementallyAdjustChecksum
// PURPOSE   :: This function will adjust an internet checksum if some part
//              of its packet data changes.  This can be used on the actual
//              packet data or on a virtual header.
// PARAMETERS::
// + sum : UInt16* : The checksum
// + oldData : UInt8* : The data that will be replaced
// + newData : UInt8* : The new data that will replace the old data
// + len : int : The length of the data that will be replaced
// + packetStart : UInt8* : The start of the packet.  NULL if it is part of
//                           the virtual header.  This parameter is
//                           necessary because the checksum covers 2 bytes
//                           of data and we need to know if the old data
//                           begins at an odd or even address relative to
//                           the start of the packet.
// RETURN    :: void
// **/
void AutoIPNEIncrementallyAdjustChecksum(
    UInt16* sum,
    UInt8* oldData,
    UInt8* newData,
    int len,
    UInt8* packetStart)
{
    UInt16* oval = (UInt16*) oldData;
    UInt16* nval = (UInt16*) newData;
    UInt16 sumVal;
    int sum2;
    int odd;

    // Determine if the old data begins at an odd address relative to the
    // start of the packet.  To handle this we swap the bytes of the checksum
    // before and after updating its value.  This makes it align properly
    // with the bytes of the old data.
    if (packetStart != NULL)
    {
        odd = (oldData - packetStart) & 0x1;
    }
    else
    {
        odd = FALSE;
    }

    if (odd)
    {
        sumVal = (*sum >> 8) | (*sum << 8);
    }
    else
    {
        sumVal = *sum;
    }

    // See RFCs 1141 and 1624. RFC 1071 is out of date.  Essentially we
    // update the checksum by subtracting the old value (~*oval) and
    // add the new value (*nval) in one's complement arithmetic.
    sum2 = (int) (~sumVal & 0xFFFF);
    while (len > 0)
    {
        sum2 += (~*oval & 0xFFFF) + (*nval & 0xFFFF);
        len -= 2;
        oval++;
        nval++;
    }

    while (sum2 >> 16)
    {
        sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    }

    // Swap the bytes back
    if (odd)
    {
        sumVal = (UInt16) (sum2 >> 8) | (sum2 << 8);
    }
    else
    {
        sumVal = (UInt16) sum2;
    }

    *sum = ~sumVal;
}

static int isBroadcast ( u_int8_t* addr, int len)
{
    int i;

    for (i=0; i<len; i++)
    {
        if (addr[i] == 0xff)
            continue;
        else
            return -1;
    }
    return 1;

}

AutoIPNE_NodeMapping* AutoIPNE_GetNodeMapping(EXTERNAL_Interface* ext, int deviceIndex, NodeAddress addr)
{
  int err;
  AutoIPNEData* data = (AutoIPNEData*) ext->data;
  assert(data != NULL);
  AutoIPNE_NodeMapping* mapping(NULL);
  int valueSize(0);

  EXTERNAL_ResolveMapping(ext, (char*)&addr, sizeof(NodeAddress), (char**)&mapping, &valueSize);

  if (valueSize != sizeof(AutoIPNE_NodeMapping))
  {
    return NULL;
  }
  
  return mapping;

  AutoIPNE_NodeMapping* potentialMapping = data->deviceArray[deviceIndex].mappingsList;

  for (;potentialMapping != NULL; potentialMapping = potentialMapping->next)
  {
    if (potentialMapping->isVirtualLan)
    {
      NodeAddress testAddr = htonl(addr);

      list<AutoIpneV4V6Address>::iterator it = data->deviceArray[deviceIndex].interfaceAddress->begin();
      for (; it != data->deviceArray[deviceIndex].
             interfaceAddress->end();
           ++it)
      {
        if ((it->address.interfaceAddr.ipv4 & it->u.subnetmask)
            == (testAddr & it->u.subnetmask))
        {
          return potentialMapping;
        }
      }
    }
  }

  return NULL;
}

// /**
// API       :: EmulateIpPacket
// PURPOSE   :: This is the default function used to inject a packet into
//              the QualNet simulation.  It will create a message from the
//              src to dst QualNet nodes.  It will call
//              EmulateIpPacketNatYes, EmulateIpPacketNatNo or
//              EmulateIpPacketTruEmulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + deviceIndex : int : The index of device that captured this packet
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: bool
// **/
bool AutoIPNEEmulateIpPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    int deviceIndex)
{
    AutoIPNEData* data;
    struct libnet_ipv4_hdr* ip;
    struct libnet_ethernet_hdr* ethernet;
    int ipHeaderLength;
    clocktype interfaceTime;
    char* payload;
    size_t payloadSize;
    AutoIPNE_NodeMapping* mapping;
    int valueSize;
    int error;
    char* ipOptions = NULL;

    // srcAddr is the IP address of the QualNet node that will forward the
    // message
    NodeAddress srcAddr;

    // ipSrcAddr is the IP address of the operational host that originated
    // this packet
    NodeAddress ipSrcAddr;

    // ipDestAddr is the IP address of the operational host that is the
    // destination of this packet
    NodeAddress ipDestAddr;

    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    // Compute current time if possible
    if (iface->timeFunction)
    {
        interfaceTime = iface->timeFunction(iface);
    }
    else
    {
        interfaceTime = 0;
    }

    // Extract IP header
    ip = (struct libnet_ipv4_hdr*) (packet + AutoIPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;

    if (ipHeaderLength > sizeof(IpHeaderType))
    {
        ipOptions = (char *)ip;
        ipOptions = ipOptions + sizeof(IpHeaderType);
        //EXTERNAL_ntoh(ipOptions, ipHeaderLength - sizeof(IpHeaderType));
        IpOptionsHeaderType *sourceRouteOption =
                                    FindAnIpOptionField((IpHeaderType *)ip,
                                                        IPOPT_SSRR,
                                                        ipHeaderLength);
        IpOptionsHeaderType *recordRouteOption =
                                    FindAnIpOptionField((IpHeaderType *)ip,
                                                        IPOPT_RR,
                                                        ipHeaderLength);
        IpOptionsHeaderType *timeStampOption =
                                    FindAnIpOptionField((IpHeaderType *)ip,
                                                        IPOPT_TS,
                                                        ipHeaderLength);
        ip_traceroute *tracert = FindTraceRouteOption((IpHeaderType *)ip,
                                                       ipHeaderLength);
        if (recordRouteOption)
        {
            char *currentAddress = (char *)recordRouteOption;
            currentAddress = currentAddress + sizeof(IpOptionsHeaderType);
            int check = sizeof(IpOptionsHeaderType);
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType) - IP_SOURCE_ROUTE_OPTION_PADDING)
            {
                *(UInt32 *)currentAddress = ntohl(*(UInt32 *)currentAddress);
                currentAddress += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (sourceRouteOption)
        {
            char *currentAddress = (char *)sourceRouteOption;
            currentAddress = currentAddress + sizeof(IpOptionsHeaderType);
            int check = sizeof(IpOptionsHeaderType);
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType) - IP_SOURCE_ROUTE_OPTION_PADDING)
            {
                *(UInt32 *)currentAddress = ntohl(*(UInt32 *)currentAddress);
                currentAddress += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (timeStampOption)
        {
            char *addOrTime = (char *)timeStampOption;
            addOrTime = addOrTime + 4;
            int check = 4;
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType))
            {
                *(UInt32 *)addOrTime = ntohl(*(UInt32 *)addOrTime);
                addOrTime += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (tracert)
        {
            char *pointer = (char *)tracert;
            pointer = pointer + 2;
            *(UInt16 *)pointer = ntohs(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt16 *)pointer = ntohs(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt16 *)pointer = ntohs(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt32 *)pointer = ntohl(*(UInt32 *)pointer);
        }
    }

#ifdef RETAIN_IP_HEADER
    // Precedence setting if any
    if (data->precEnabled)
    {
        for (int i=0; i<data->numPrecPairs; i++)
        {
            if (data->precSrcAddress[i] == htonl(LibnetIpAddressToULong(ip->ip_src)) &&
                (data->precDstAddress[i]== htonl(LibnetIpAddressToULong(ip->ip_dst))))
            {
                ip->ip_tos=data->precPriority<<5;
            }
        }
    }

    ipDestAddr = (LibnetIpAddressToULong(ip->ip_dst)); // dest address
    ipSrcAddr = (LibnetIpAddressToULong(ip->ip_src));  // src address
#else
    // Precedence setting if any
    if (data->precEnabled)
    {
        for (int i=0; i<data->numPrecPairs; i++)
        {
            if (data->precSrcAddress[i] == LibnetIpAddressToULong(ip->ip_src) &&
                (data->precDstAddress[i]==LibnetIpAddressToULong(ip->ip_dst)))
            {
                ip->ip_tos=data->precPriority<<5;
            }
        }
    }
    // Extract the IP src/dest addresses
    ipDestAddr = ntohl(LibnetIpAddressToULong(ip->ip_dst)); // dest address
    ipSrcAddr = ntohl(LibnetIpAddressToULong(ip->ip_src));  // src address
#endif

    // Inject the packet at the node that corresponds to the MAC address the
    // packet was sniffed on
    ethernet = (struct libnet_ethernet_hdr*) packet;
    
    //Mapping for macAddress
    //Key in the mapping table is not the macAddress alone but also the
    //corresponding device index. This is required to ensure that more than 1
    //physical interface with the same MAC address can be stored without any
    //collisions

    char macKey[10];
    BOOL success;
    int macKeySize = ETHER_ADDR_LEN + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,(char*)ethernet->ether_shost,deviceIndex);
    if (!success)
    {
        error = 1;
        ERROR_ReportWarning("No Memory to allocate. Cannot create a mapping\n");
    }
    else
    {
    error = EXTERNAL_ResolveMapping(
        iface,
           (char*) macKey,
            macKeySize,
        (char**) &mapping,
        &valueSize);
    }
    if (error)
    {
        error = EXTERNAL_ResolveMapping(
                iface,
                (char*) ethernet->ether_dhost,
                6,
                (char**) &mapping,
                &valueSize);

        if (error)
        {
            mapping = AutoIPNE_GetNodeMapping(iface, deviceIndex, htonl(ipSrcAddr));
            if (mapping == NULL)
            {
                if (data->debug)
                {
                    printf(
                        "EXata received packet for unknown mac address "
                        "%02x:%02x:%02x:%02x:%02x:%02x\n",
                        (UInt8) ethernet->ether_shost[0],
                        (UInt8) ethernet->ether_shost[1],
                        (UInt8) ethernet->ether_shost[2],
                        (UInt8) ethernet->ether_shost[3],
                        (UInt8) ethernet->ether_shost[4],
                        (UInt8) ethernet->ether_shost[5]);
                }
                // Return without adding the packet
                return false;
            }
        }

        // Return without adding the packet
        return false;
    }
    if (mapping->physicalAddress.networkType == NETWORK_IPV6)
    {
         return false; // we have IPv6 mapping but recieved a IPv4 packet
    }

    assert(valueSize == sizeof(AutoIPNE_NodeMapping));
    srcAddr = ntohl(mapping->virtualAddress.interfaceAddr.ipv4);

    // nextHopAddr is the IP adresss of the next hop host that this
    // packet should be forwarded to
    NodeAddress nextHopAddr = INVALID_ADDRESS;
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    const int posMultiplier = 0x0100;
    if (isBroadcast(ethernet->ether_dhost,6) == -1)
    {
        // get IP address from MAC address
        // for this, first extract the last 2 bytes of the mac address to
        // get the MI Id (in the context of JNE).
        UInt16 miId = (ethernet->ether_dhost[4] * posMultiplier) + ethernet->ether_dhost[5];
        // Now look up this id in the JNE mapping table to get the IP address
        MiQualnetNodeIdMapEntry* entry = AutoIPNE_FindEntryForMIId((AutoIPNEData*) iface->data, miId);
        if (entry)
        {
            nextHopAddr = entry->ipAddress;
        }
    }
#else
    if (isBroadcast(ethernet->ether_dhost,6) == -1)
    {
        // get IP address from MAC address
        if ((ethernet->ether_dhost[0] == 0xde) && ((ethernet->ether_dhost[1] == 0xad)))
        {
        memcpy(&nextHopAddr, ethernet->ether_dhost+2, 4);
        nextHopAddr = ntohl(nextHopAddr);
        }
    }
#endif
    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];

        printf(
            "<<< Received IP packet -------------------"
            "-------------------------------------\n");
        IO_ConvertIpAddressToString(ipSrcAddr, tempString);
        printf("    source: %20s    protocol: %5d    tos: 0x%0x\n",
                tempString, ip->ip_p, ip->ip_tos);
        IO_ConvertIpAddressToString(ipDestAddr, tempString);
        printf("    dest  : %20s    id      : %5d    ttl: %d\n",
                tempString, ip->ip_id, ip->ip_ttl);
        IO_ConvertIpAddressToString(srcAddr, tempString);
        printf("    via   : %20s    offset  : %5u    payload: %d\n",
            tempString,
            ntohs(ip->ip_off) & 0x1FFF,
            (UInt32)(packetSize - AutoIPNE_ETHERNET_HEADER_LENGTH - ipHeaderLength));
        printf(
            "------------------------------------------"
            "----------------------------------<<<\n");
        fflush(stdout);
    }

    /* If this the NAT case, then change the source address */
    if (mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
    {
        if (mapping->physicalAddress.interfaceAddr.ipv4
            != LibnetIpAddressToULong(ip->ip_src))
        {
            ERROR_ReportWarning("Received packet from Operational Host that is not configured correctly");
            return false;
        }
        else
        {
            ipSrcAddr = ntohl(mapping->virtualAddress.interfaceAddr.ipv4);
            // Checksum must be zeroed if udp
            if (ip->ip_p == IPPROTO_UDP)
            {
               ((struct libnet_udp_hdr *)(packet + 
                                         AutoIPNE_ETHERNET_HEADER_LENGTH + 
                                         ipHeaderLength))->uh_sum = 0;
            }
        }
    }
      
    /* if src and dst IP are the same, drop it */
    if (ipSrcAddr == ipDestAddr)
    {
        //printf("same src and dst IP address %x %x %d\n", ipSrcAddr, ipDestAddr, ip->ip_p);
        return false;
    }
#ifdef RETAIN_IP_HEADER
    payload = (char*) packet + AutoIPNE_ETHERNET_HEADER_LENGTH;
    payloadSize = packetSize - AutoIPNE_ETHERNET_HEADER_LENGTH;

    RoutePacketAndSendToMac(
        mapping->node,
        payload,
        CPU_INTERFACE,
        mapping->interfaceIndex,
        ANY_IP);

#else
    // The size of the qualnet packet will be the TCP header plus
    // the packet's data.  That is, the payload size minus the
    // ethernet and IP headers.
    payload = (char*) packet + AutoIPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;
    payloadSize = packetSize - AutoIPNE_ETHERNET_HEADER_LENGTH - ipHeaderLength;

    // Handle fragmentation/offset if necessary
    //BOOL dontFragment = (ntohs(ip->ip_off) & 0x4000) != 0;
    BOOL dontFragment = ((ip->ip_off) & (0x4000)) != 0;
    BOOL moreFragments = ((ip->ip_off) & 0x2000) != 0;
    UInt16 fragmentOffset = (ip->ip_off) & (0x1FFF);

    if ((ipDestAddr & 0xFF) == 0xFF) ipDestAddr = ANY_DEST;
//    printf("---> %x %d %d    %x\n", ntohs(ip->ip_off), dontFragment, moreFragments, fragmentOffset);

    // Send the packet through QualNet at the network layer
    //printf("Before calling SendDataNetworkLayer\n");

/*
    printf("Calling EXTERNAL_SendDataNetworkLayer(srcAddr=0x%x ipSrcAddr=0x%x ipDestAddr=0x%x\n",
           srcAddr, ipSrcAddr, ipDestAddr);
*/

    EXTERNAL_SendDataNetworkLayer(
        iface,
        srcAddr,
        ipSrcAddr,
        ipDestAddr,
        ntohs(ip->ip_id),
        dontFragment,
        moreFragments,
        fragmentOffset,
        ip->ip_tos,
        ip->ip_p,
        ip->ip_ttl,
        payload,
        payloadSize,
        ipHeaderLength,
        ipOptions,
        EXTERNAL_QuerySimulationTime(iface),
        //We want to send the packet as soon as we can. Specifically added for
        //Fixed comms feature.
        nextHopAddr);
#endif



    // Handle statistics
    AutoIPNE_HandleIPStatisticsReceivePacket(iface, packetSize, interfaceTime);

    return true;
}

// /**
// API       :: AutoIPNEEmulateIpv6Packet
// PURPOSE   :: This is the default function used to inject an IPv6 packet into
//              the QualNet simulation. It will create a message from the
//              src to dst QualNet nodes.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + deviceIndex : int : The index of device that captured this packet
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: bool
// **/
bool AutoIPNEEmulateIpv6Packet(EXTERNAL_Interface* iface,
                               UInt8* packet,
                               Int32 packetSize,
                               Int32 deviceIndex)
{
    AutoIPNEData* data = NULL;
    struct libnet_ipv6_hdr* ip = NULL;
    struct libnet_ethernet_hdr* ethernet = NULL;
    Int32 ipHeaderLength = 0;
    clocktype interfaceTime = 0;
    char* payload = NULL;
    AutoIPNE_NodeMapping* mapping = NULL;
    Int32 valueSize = 0;
    Int32 error;

    // srcAddr is the IPv6 address of the QualNet node that will forward the
    // message

    Address srcAddr;

    // ipSrcAddr is the IPv6 address of the operational host that originated
    // this packet

    Address ipSrcAddr;

    // ipDestAddr is the IPv6 address of the operational host that is the
    // destination of this packet

    Address ipDestAddr;

    data = (AutoIPNEData*) iface->data;
    ERROR_Assert(data != NULL,"Data should not be NULL");

    // Compute current time if possible
    if (iface->timeFunction)
    {
        interfaceTime = iface->timeFunction(iface);
    }
    else
    {
        interfaceTime = 0;
    }

    // Extract IPv6 header
    ip =
        (struct libnet_ipv6_hdr*)(packet + AutoIPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = IPV6_HEADER_LENGTH;

    // Extract the IPv6 src/dest addresses
    ipDestAddr.networkType = NETWORK_IPV6;
    ipSrcAddr.networkType = NETWORK_IPV6;
    for (int i = 0; i < 16; i++)
    {
        ipDestAddr.interfaceAddr.ipv6.s6_addr[i]
            = ip->ip_dst.libnet_s6_addr[i];
        ipSrcAddr.interfaceAddr.ipv6.s6_addr[i]
            = ip->ip_src.libnet_s6_addr[i];
    }

    // Inject the packet at the node that corresponds to the MAC address the
    // packet was sniffed on

    ethernet = (struct libnet_ethernet_hdr*) packet;

    // Mapping for macAddress
    // Key in the mapping table is not the macAddress alone but also the
    // corresponding device index. This is required to ensure that more than 1
    // physical interface with the same MAC address can be stored without any
    // collisions

    char macKey[10];
    BOOL success = FALSE;
    Int32 macKeySize = ETHER_ADDR_LEN + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,(char*)ethernet->ether_shost,deviceIndex);
    if (!success)
    {
        error = 1;
        ERROR_ReportWarning("No Memory to allocate. Cannot create a mapping\n");
    }
    else
    {
        error = EXTERNAL_ResolveMapping(iface,
                                        (char*) macKey,
                                        macKeySize,
                                        (char**) &mapping,
                                        &valueSize);
    }
    if (error)
    {
        error = EXTERNAL_ResolveMapping(iface,
                                        (char*) ethernet->ether_dhost,
                                        6,
                                        (char**) &mapping,
                                        &valueSize);

        if (error)
        {
            // See if this multicast packet from virtual LAN
            AutoIPNE_NodeMapping* potentialMapping;
            bool found = false;

            potentialMapping =
                data->deviceArray[deviceIndex].mappingsList;

            while (potentialMapping != 0)
            {
                if (found)
                {
                    break;
                }
                potentialMapping = potentialMapping->next;
            }
            if (!found)
            {
                if (data->debug)
                {
                    printf("EXata received packet for unknown mac address "
                            "%02x:%02x:%02x:%02x:%02x:%02x\n",
                            (UInt8) ethernet->ether_shost[0],
                            (UInt8) ethernet->ether_shost[1],
                            (UInt8) ethernet->ether_shost[2],
                            (UInt8) ethernet->ether_shost[3],
                            (UInt8) ethernet->ether_shost[4],
                            (UInt8) ethernet->ether_shost[5]);
                }
                // Return without adding the packet
                return false;
            }
        }
        // Return without adding the packet
        return false;
    }

    if (mapping->physicalAddress.networkType == NETWORK_IPV4)
    {
         return false; // we have IPv4 mapping but recieved a IPv6 packet
    }
    ERROR_Assert(valueSize == sizeof(AutoIPNE_NodeMapping),
                 "Invalid Mapping information");
    srcAddr.networkType = NETWORK_IPV6;

    // get source address from the mapping
    for (int j = 0; j < 16; j++)
    {
        srcAddr.interfaceAddr.ipv6.s6_addr[j]
            = mapping->virtualAddress.interfaceAddr.ipv6.s6_addr[j];
    }

    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];

        printf(
            "<<< Received IPv6 packet -------------------"
            "-------------------------------------\n");
        IO_ConvertIpAddressToString(&ipSrcAddr, tempString);
        printf("    source: %20s    protocol: %5d \n",
                tempString, ip->ip_nh);
        IO_ConvertIpAddressToString(&ipDestAddr, tempString);
        printf("    dest  : %20s    hop lim      : %5d\n",
                tempString, ip->ip_hl);
        IO_ConvertIpAddressToString(&srcAddr, tempString);
        printf("    via   : %20s    payload: %d\n",\
            tempString,
            ntohs(ip->ip_len));
        printf(
            "------------------------------------------"
            "----------------------------------<<<\n");
        fflush(stdout);
    }

    // If this the NAT case, then change the source address
    if (mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
    {
        if (memcmp(mapping->physicalAddress.interfaceAddr.ipv6.s6_addr,
                                ip->ip_src.libnet_s6_addr,sizeof(in6_addr)))
        {
            ERROR_ReportWarning("Received packet from Operational" 
                                "Host that is not configured correctly");
            return false;
        }
        else
        {
            for (int j = 0; j < 16; j++)
            {
                ipSrcAddr.interfaceAddr.ipv6.s6_addr[j] =
                      mapping->virtualAddress.interfaceAddr.ipv6.s6_addr[j];
            }
        }
    }
   
    // if src and dst IP are the same, drop it
    if (memcmp(ipSrcAddr.interfaceAddr.ipv6.s6_addr,
               ipDestAddr.interfaceAddr.ipv6.s6_addr,
               sizeof(in6_addr)) == 0)
    {
        printf("same src and dst IP address ");
        return false;
    }

    payload = (char*) packet +
              AutoIPNE_ETHERNET_HEADER_LENGTH +
              ipHeaderLength;
    UInt8* priority = (UInt8*)(ip->ip_flags + 1);

    // Send the packet through QualNet at the network layer
    EXTERNAL_SendIpv6DataNetworkLayer(iface,
                                      &srcAddr,
                                      &ipSrcAddr,
                                      &ipDestAddr,
                                      *priority,
                                      ip->ip_nh,
                                      ip->ip_hl,
                                      payload,
                                      ntohs((u_short)ip->ip_len),
                                      EXTERNAL_QuerySimulationTime(iface));

    // Handle statistics
    AutoIPNE_HandleIPStatisticsReceivePacket(iface, packetSize, interfaceTime);
    return true;
}

// /**
// API       :: ProcessOutgoingCommonPacket
// PURPOSE   :: This function separates out the common functionality that
//              is required in processing an IP/ESP packet before being
//              injected to the operational network
// PARAMETERS::
// + ipHeader : IpHeaderType* : The ip header
// + data : AutoIPNEData* : pointer to AutoIPNEData
// + packetSize : int : The size of the packet in bytes.
// + nextHeader:UInt8*:the next header field after the IP header
// + ipHeaderLength :int : ip header length
// RETURN    :: void
// **/
void ProcessOutgoingCommonPacket(
    IpHeaderType* ipHeader,
    AutoIPNEData* data,
    int packetSize,
    UInt8* nextHeader,
    int ipHeaderLength)
{
    if ((ipHeader->ip_p == IPPROTO_UDP) &&
        (IpHeaderGetIpFragOffset(ipHeader->ipFragment) == 0))
    {       
        struct libnet_udp_hdr* udp = (struct libnet_udp_hdr *) nextHeader;

        // Swap UDP header and call register port handlers

        udp->uh_sport = htons(udp->uh_sport);
        udp->uh_dport = htons(udp->uh_dport);
        udp->uh_ulen  = htons(udp->uh_ulen);
        
        // UDP protocol handler code:
        unsigned char* payload = (unsigned char *) ((unsigned char *)udp
                                 + sizeof(TransportUdpHeader));

        switch (ntohs(udp->uh_sport))
        {
            case OLSR_PORT:
            {
                OLSRPacketHandler::ReformatOutgoingPacket(payload);
                // The packet was modified, so the checksum must be zeroed
                udp->uh_sum = 0;
                break;
            }
            default:
            {
                if (data)
                {
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT] ++;
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES] += packetSize;
                }
                break;
            }
        }       
    }
    else if (ipHeader->ip_p == IPPROTO_TCP)
    {
        struct libnet_tcp_hdr* tcp;
        tcp = (struct libnet_tcp_hdr *) nextHeader;

        // Swap TCP header and call register port handlers
        tcp->th_sport = htons(tcp->th_sport);
        tcp->th_dport = htons(tcp->th_dport);
        tcp->th_seq   = htonl(tcp->th_seq);
        tcp->th_ack   = htonl(tcp->th_ack);
        tcp->th_win   = htons(tcp->th_win);
        tcp->th_sum   = 0;
        tcp->th_urp   = htons(tcp->th_urp);

        unsigned char* field = (unsigned char *) (nextHeader + 12);
        unsigned char lval = *field >> 4;
        unsigned char rval = *field & 0xFF;
        *field = (rval << 4) | lval;

        UInt16 *checksum = (UInt16 *)&tcp->th_sum;

        *checksum = AutoIPNEComputeTcpStyleChecksum(
                htonl(ipHeader->ip_src),
                htonl(ipHeader->ip_dst),
                ipHeader->ip_p,
                htons((UInt16)(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)
                - ipHeaderLength)),
                (UInt8 *)tcp);

        if (data)
        {
            data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT] ++;
            data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES] += packetSize;
        }
    }
    else if (ipHeader->ip_p == IPPROTO_OSPF)
    {
        OSPFPacketHandler::ReformatOutgoingPacket(nextHeader);
    }
    else if (ipHeader->ip_p == IPPROTO_PIM)
    {
        PIMPacketHandler::ReformatOutgoingPacket(
            nextHeader,
            IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength);
    }
    else if (ipHeader->ip_p == IPPROTO_IGMP)
    {
        if (packetSize - ipHeaderLength > IGMPV2_HEADER_SIZE)
        {
            IGMPv3PacketHandler::ReformatOutgoingPacket(nextHeader);
            UInt16 checkSum;
            checkSum = AutoIPNEComputeIcmpStyleChecksum(nextHeader,
                        htons(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)
                        - ipHeaderLength));
            UInt16* checkSumPtr;
            char* pkt = (char*)nextHeader;
            // forward data pointer 2 bytes
            pkt += sizeof(UInt8) + sizeof(UInt8);
            checkSumPtr = (UInt16*)pkt;
            *checkSumPtr = checkSum;
        }
        else
        {

            struct libnet_igmp_hdr* igmp;
            igmp = (struct libnet_igmp_hdr*) nextHeader;

            // First zero out checksum
            igmp->igmp_sum = 0;

            igmp->igmp_group.s_addr = htonl(igmp->igmp_group.s_addr);

            // Calculate the checksum - ICMP style
            igmp->igmp_sum = AutoIPNEComputeIcmpStyleChecksum(
                nextHeader,
                htons((UInt16)(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)
                               - ipHeaderLength)));
        }
    }
    else if ((ipHeader->ip_p == IPPROTO_ICMP) &&
        (IpHeaderGetIpFragOffset(ipHeader->ipFragment) == 0))
    {
        struct libnet_icmpv4_hdr* icmp;
        icmp = (struct libnet_icmpv4_hdr*) nextHeader;

        // First zero out checksum
        icmp->icmp_sum = 0;

        // if this is time-to-live exceed message, bytes swapping for
        // IP in ICMP message
        if (((icmp->icmp_type == ICMP_TIMXCEED)||
              (icmp->icmp_type == ICMP_UNREACH)||
              (icmp->icmp_type == ICMP_SOURCEQUENCH)||
              (icmp->icmp_type == ICMP_REDIRECT)||
              (icmp->icmp_type == ICMP_PARAMPROB)) )
        {
            BytesSwapHton((UInt8*)&(icmp->dun.ip.idi_ip));
        }

        // Compute for ICMP style
        icmp->icmp_sum = AutoIPNEComputeIcmpStyleChecksum(
            nextHeader,
            htons((UInt16)(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)
            - ipHeaderLength)));

    }
#ifdef CYBER_CORE
    else if (ipHeader->ip_p == IPPROTO_ESP)
    {
        ESPPacketHandler::ReformatOutgoingPacket(((UInt8*) nextHeader));
    }
    else if (ipHeader->ip_p == IPPROTO_AH)
    {
        AHPacketHandler::ReformatOutgoingPacket(((UInt8*) nextHeader));
    }
#endif //CYBER_CORE
    return;
}

// /**
// API       :: ProcessOutgoingCommonPacket
// PURPOSE   :: This function separates out the common functionality that
//              is required in processing an IP/ESP packet before being
//              injected to the operational network
// PARAMETERS::
// + ipHeader : ip6_hdr* : The ipv6 header
// + data : AutoIPNEData* : pointer to AutoIPNEData
// + packetSize : int : The size of the packet in bytes.
// + nextHeader: UInt8* : the next header field after the IPv6 header
// + ipHeaderLength :Int32 : ipv6 header length
// + proto :UInt8 : next header protocol type
// RETURN    :: void
// **/
void ProcessOutgoingCommonPacket(
    ip6_hdr* ipHeader,
    AutoIPNEData* data,
    Int32 packetSize,
    UInt8* nextHeader,
    Int32 ipHeaderLength,
    UInt8 proto)
{
    if (proto == IP6_NHDR_FRAG)
    {
        struct libnet_ipv6_frag_hdr* fragHeader
            = (struct libnet_ipv6_frag_hdr*)nextHeader;
        UInt8* nh = NULL;
        UInt16 offSet = fragHeader->ip_frag & 0xfff8;
        fragHeader->ip_frag = ntohs(fragHeader->ip_frag);
        fragHeader->ip_id = ntohl(fragHeader->ip_id);
        nh = nextHeader + sizeof(libnet_ipv6_frag_hdr);
        proto = fragHeader->ip_nh;
        if (offSet == 0)
        {
            ProcessOutgoingCommonPacket(ipHeader,
                                        data,
                                        packetSize,
                                        nh,
                                        ipHeaderLength,
                                        proto);
        }
    }
    else if (proto == IPPROTO_UDP)
    {
        struct libnet_udp_hdr* udp = (struct libnet_udp_hdr*) nextHeader;

        // Swap UDP header and call register port handlers
        udp->uh_sport = htons(udp->uh_sport);
        udp->uh_dport = htons(udp->uh_dport);
        udp->uh_ulen  = htons(udp->uh_ulen);
        udp->uh_sum = htons(udp->uh_sum);
        UInt16* checksum = (UInt16*)&udp->uh_sum;
        *checksum = 0;

        // udp checksum for ipv6
        *checksum = AutoIPNEComputeTcpStyleChecksum(
                    (UInt8*)&ipHeader->ip6_src,
                    (UInt8*)&ipHeader->ip6_dst,
                     proto,
                    (UInt32)ntohs(ipHeader->ipv6_plength),
                    (UInt8 *)udp);

        switch (ntohs(udp->uh_sport))
        {
            case OLSR_PORT:
            {
                ERROR_ReportWarning("OLSR currently not supported");
                break;
            }
            default:
            {
                if (data)
                {
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_PKT] ++;
                    data->stats[AUTO_IPNE_STATS_UDP_OUT_BYTES] += packetSize;
                }
                break;
            }
        }
    }
    else if (proto == IPPROTO_TCP)
    {
        struct libnet_tcp_hdr* tcp;
        tcp = (struct libnet_tcp_hdr*) nextHeader;

        // Swap TCP header and call register port handlers
        tcp->th_sport = htons(tcp->th_sport);
        tcp->th_dport = htons(tcp->th_dport);
        tcp->th_seq   = htonl(tcp->th_seq);
        tcp->th_ack   = htonl(tcp->th_ack);
        tcp->th_win   = htons(tcp->th_win);
        tcp->th_sum   = htons(tcp->th_sum);
        tcp->th_urp   = htons(tcp->th_urp);

        unsigned char* field = (unsigned char*) (nextHeader + 12);
        unsigned char lval = *field >> 4;
        unsigned char rval = *field & 0xFF;
        *field = (rval << 4) | lval;

        UInt16* checksum = &tcp->th_sum;
        *checksum = 0;

        *checksum = AutoIPNEComputeTcpStyleChecksum(
                    (UInt8*)&ipHeader->ip6_src,
                    (UInt8*)&ipHeader->ip6_dst,
                    proto,
                    (UInt32)ntohs(ipHeader->ipv6_plength),
                    (UInt8 *)tcp);

        if (data)
        {
            data->stats[AUTO_IPNE_STATS_TCP_OUT_PKT] ++;
            data->stats[AUTO_IPNE_STATS_TCP_OUT_BYTES] += packetSize;
        }
    }
    else if (proto == IPPROTO_ICMPV6)
    {
        struct libnet_icmpv6_hdr* icp = (struct libnet_icmpv6_hdr*)nextHeader;
        icp->id = htons(icp->id);
        icp->seq = htons(icp->seq);
        icp->icmp_sum = 0;
        icp->icmp_sum = AutoIPNEComputeTcpStyleChecksum(
                (UInt8*)&ipHeader->ip6_src,
                (UInt8*)&ipHeader->ip6_dst,
                 proto,
                (UInt32)ntohs(ipHeader->ipv6_plength),
                (UInt8*)icp);
    }
}

#ifdef CYBER_CORE
// /**
// API       :: ProcessOutgoingIPSecPacket
// PURPOSE   :: This functions processes an outgoing IPSec packet.
// PARAMETERS::
// + node " Node* : Pointer to the node structure
// + packet : UInt8* : Pointer to the beginning of the packet
// + msg : Message* : pointer to the msg structuredded.
// RETURN    :: void
// **/
void ProcessOutgoingIPSecPacket(
    Node* node,
    UInt8* packet,
    Message* msg)
{
    int ipHeaderLength;
    UInt8* nextHeader;

    BOOL is_tunnel_mode = FALSE;

    struct libnet_ipv4_hdr* ip;
    ip = (struct libnet_ipv4_hdr*) packet;
    IpHeaderType* ipHeader;
    IpHeaderType* ipHeader_inner = NULL;
    ipHeader = (IpHeaderType *) packet;

    // ip->ip_hl specifies the length of the IP packet header in 32 bit words
    // so multiply with 4 to get the length in bytes.

    ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;
    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.

    nextHeader = packet + ipHeaderLength;
    // before creating message, check for MDP packet

    MDPPacketHandler::CheckAndProcessOutgoingMdpPacket(node,
                                                       ipHeader,
                                                       ip,
                                                       msg,
                                                       ipHeaderLength);

    if (ipHeader->ip_p == IPPROTO_IPIP)
    {
        /* This is tunnel mode IPSEC*/
        /* First swap the IP payload and then the inner IP header*/ 

        ipHeader_inner = (IpHeaderType *) nextHeader;
        // ip->ip_hl specifies the length of the IP packet header in
        // 32 bit words so multiply with 4 to get the length in bytes.
        ipHeaderLength = IpHeaderGetHLen(ipHeader_inner->ip_v_hl_tos_len)
                        * 4;
        nextHeader = nextHeader + ipHeaderLength;
        ipHeader = ipHeader_inner;
        is_tunnel_mode = TRUE;
    }
    ProcessOutgoingCommonPacket(ipHeader,
                                NULL,
                                0,
                                nextHeader,
                                ipHeaderLength);
    int innerhLen = 0;
    if (is_tunnel_mode)
    {
        innerhLen  = (int) IpHeaderSize(ipHeader);
        // Now swap the inner IP header

        ipHeader->ip_id = ntohs(ipHeader->ip_id);
        ipHeader->ipFragment = ntohs(ipHeader->ipFragment);
        ipHeader->ip_sum = ntohs(ipHeader->ip_sum);
        ipHeader->ip_dst = ntohl(ipHeader->ip_dst);
        ipHeader->ip_src = ntohl(ipHeader->ip_src);
        ipHeader->ip_v_hl_tos_len = ntohl(ipHeader->ip_v_hl_tos_len);

        //Compute the chksum for the inner IP header

#ifdef OPENSSL_LIB
        NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
        struct libnet_ipv4_hdr* ipHdr = (struct libnet_ipv4_hdr*)ipHeader;
        if (ip->isIPsecOpenSSLEnabled)
        {
            ipHeader->ip_sum = 0;
            unsigned int inner_sum  = libnet_in_cksum((unsigned short*)ipHdr,
                                                      innerhLen);
            ipHdr->ip_sum = (unsigned short)LIBNET_CKSUM_CARRY(inner_sum);
        }
#endif
    }
    return;
}
#endif //CYBER_CORE
// /**
// API       :: ProcessOutgoingIpPacket
// PURPOSE   :: This functions processes an IP packet before being injected
//              to the operational network
//              IP header:QN definition
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + myAddress : NodeAddress : Node injecting the packet
// + packet: UInt8* : Pointer to the beginning of the IP packet
// + packetSize : int : The size of the packet in bytes.  May change if the
//                      ethernet frame was padded.
// RETURN    :: TRUE if the packet should be added to the network, FALSE
//              if it should not
static BOOL ProcessOutgoingIpPacket(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8* packet, //host byte order(QN definition)
    int packetSize)
{
    AutoIPNEData* data;
    int ipHeaderLength;
    UInt8* nextHeader;

    // By default assume we will inject the packet to the operational
    // network.  Depending on the protocol this packet might not be
    // injected.
    BOOL inject = TRUE;

    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    struct libnet_ipv4_hdr* ip;
    ip = (struct libnet_ipv4_hdr*) packet;
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) packet;

    // Swap the version and header length bytes.  Necessary on windows.
    // TODO: Do we have to swap these bytes?
#ifdef BITF
    unsigned int t;
    t = ip->ip_v;
    ip->ip_v = ip->ip_hl;
    ip->ip_hl = t;
#endif
    //ipHeaderLength = ip->ip_hl * 4;
    ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    if ((ipHeader->ip_dst >= IP_MIN_MULTICAST_ADDRESS) &&
            (ipHeader->ip_dst <= IP_MAX_MULTICAST_ADDRESS))
    {
        data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT] ++;
        data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES] += packetSize;
    }

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.

    nextHeader = packet + ipHeaderLength;
    ProcessOutgoingCommonPacket(ipHeader,
                                data,
                                packetSize,
                                nextHeader,
                                ipHeaderLength);
    return inject;
}

// /**
// API       :: ProcessOutgoingIpv6Packet
// PURPOSE   :: This functions processes an IPv6 packet before being injected
//              to the operational network
//              IP header:QN definition
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + packet: UInt8* : Pointer to the beginning of the IPv6 packet
// + packetSize : Int32 : The size of the packet in bytes.  May change if the
//                      ethernet frame was padded.
// RETURN    :: TRUE if the packet should be added to the network, FALSE
//              if it should not
static BOOL ProcessOutgoingIpv6Packet(
    EXTERNAL_Interface* iface,
    UInt8* packet, //host byte order(QN definition)
    Int32 packetSize)
{
    AutoIPNEData* data = NULL;
    Int32 ipHeaderLength = 0;
    UInt8* nextHeader = NULL;

    // By default assume we will inject the packet to the operational
    // network.  Depending on the protocol this packet might not be
    // injected.

    BOOL inject = TRUE;

    data = (AutoIPNEData*) iface->data;
    ERROR_Assert(data != NULL,"Data should not be NULL");
    UInt8 proto = 0;
    struct libnet_ipv6_hdr* ip = NULL;
    ip = (struct libnet_ipv6_hdr*) packet;
    ip6_hdr* ipHeader = NULL;
    ipHeader = (ip6_hdr*) packet;
    proto = ipHeader->ipv6_nhdr;

    ipHeaderLength = IPV6_HEADER_LENGTH;
    if (IS_MULTIADDR6(ipHeader->ip6_dst))
    {
        data->stats[AUTO_IPNE_STATS_MULTI_OUT_PKT] ++;
        data->stats[AUTO_IPNE_STATS_MULTI_OUT_BYTES] += packetSize;
    }

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.

    nextHeader = packet + ipHeaderLength;
    ProcessOutgoingCommonPacket(ipHeader,
                                data,
                                packetSize,
                                nextHeader,
                                ipHeaderLength,
                                proto);
    return inject;
}



// /**
// API       :: IPNE_ForwardFromNetworkLayer
// PURPOSE   :: Check if a packet should be forwarded to an operational host
//              and forward it if necessary.
//              Host byte order (QN definition)
// PARAMETERS::
// + node : Node* : The node processing the packet
// + interfaceIndex : int : Interface the packet was received on
// + msg : Message* : The packet
// RETURN    :: BOOL : TRUE if the packet was forwarded to an operational
//                     host, FALSE if not
// **/
BOOL AutoIPNE_ForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg,
    NodeAddress previousHopAddress,
    BOOL eavesdrop = FALSE)
{
    UInt16 offset;
    IpHeaderType *ipHeader;
    int ipHeaderLength;
    EXTERNAL_Interface *ipne = NULL;
    AutoIPNEData *ipneData = NULL;
    BOOL inject;
    char *ipOptions = NULL;
    char *ipOptionsHostOrder = NULL;


    // Get IPNE external interface
    ipne = node->partitionData->interfaceTable[EXTERNAL_IPNE];
    if (ipne == NULL)
    {
        ERROR_ReportError("EXata hardware-in-the-loop capability not present");
    }

    ipneData = (AutoIPNEData*) ipne->data;
    EXTERNAL_Interface *iface = ipne;

    if (!ipneData->isAutoIPNE)
    {
        return IPNE_ForwardFromNetworkLayer(node, interfaceIndex, msg);
    }

    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    // See if this is a virtual lan packet
    if (node->partitionData->partitionId == node->partitionId)
    {

        if (ipHeader->ip_p == IPPROTO_EXATA_VIRTUAL_LAN)
        {
            MESSAGE_RemoveHeader(node, msg, IpHeaderSize(ipHeader), TRACE_IP);
            ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
        }
        else
        {
            if (node->macData[interfaceIndex]->isVirtualLan) {
                return FALSE;
            }
        }
    }

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*) MESSAGE_ReturnPacket(msg);

    ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    if (ipHeaderLength > sizeof(IpHeaderType))
    {
        ipOptionsHostOrder = (char *)malloc(ipHeaderLength - sizeof(IpHeaderType));
        ipOptions = (char *)ipHeader;
        ipOptions = ipOptions + sizeof(IpHeaderType);
        memcpy(ipOptionsHostOrder, ipOptions, ipHeaderLength - sizeof(IpHeaderType));
        //EXTERNAL_ntoh(ipOptions, ipHeaderLength - sizeof(IpHeaderType));
        IpOptionsHeaderType *sourceRouteOption =
                                    FindAnIpOptionField(ipHeader,
                                                        IPOPT_SSRR,
                                                        ipHeaderLength);
        IpOptionsHeaderType *recordRouteOption =
                                    FindAnIpOptionField(ipHeader,
                                                        IPOPT_RR,
                                                        ipHeaderLength);
        IpOptionsHeaderType *timeStampOption =
                                    FindAnIpOptionField(ipHeader,
                                                        IPOPT_TS,
                                                        ipHeaderLength);
        ip_traceroute *tracert = FindTraceRouteOption(ipHeader,
                                                       ipHeaderLength);
        if (recordRouteOption)
        {
            char *currentAddress = (char *)recordRouteOption;
            currentAddress = currentAddress + sizeof(IpOptionsHeaderType);
            int check = sizeof(IpOptionsHeaderType);
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType) - IP_SOURCE_ROUTE_OPTION_PADDING)
            {
                *(UInt32 *)currentAddress = htonl(*(UInt32 *)currentAddress);
                currentAddress += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (sourceRouteOption)
        {
            char *currentAddress = (char *)sourceRouteOption;
            currentAddress = currentAddress + sizeof(IpOptionsHeaderType);
            int check = sizeof(IpOptionsHeaderType);
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType) - IP_SOURCE_ROUTE_OPTION_PADDING)
            {
                *(UInt32 *)currentAddress = htonl(*(UInt32 *)currentAddress);
                currentAddress += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (timeStampOption)
        {
            char *addOrTime = (char *)timeStampOption;
            addOrTime = addOrTime + 4;
            int check = 4;
            while ((unsigned)check < (unsigned)ipHeaderLength -
                   sizeof(IpHeaderType))
            {
                *(UInt32 *)addOrTime = htonl(*(UInt32 *)addOrTime);
                addOrTime += sizeof(NodeAddress);
                check += sizeof(NodeAddress);
            }
        }
        if (tracert)
        {
            char *pointer = (char *)tracert;
            pointer = pointer + 2;
            *(UInt16 *)pointer = htons(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt16 *)pointer = htons(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt16 *)pointer = htons(*(UInt16 *)pointer);
            pointer = pointer + 2;
            *(UInt32 *)pointer = htonl(*(UInt32 *)pointer);
        }
    }


    // Call the following code only when the node is running in context of its
    // native partition (required since node->networkData is invalid in other partitions)
    if ((node->partitionData->partitionId == node->partitionId) && !eavesdrop)
    {
        //Get IP proto no and Check if we need to inject this packet
        if (CheckNetworkRoutingProtocol(node,interfaceIndex,ip->ip_p))
        {
            //printf("inside the network routing protocol code\n");
            return FALSE;
        }

        UInt8* nextHeader;
        nextHeader = ((UInt8*) ip) + ipHeaderLength;

        // for UDP and TCP to check if we need to inject this packet
        if (ip->ip_p == IPPROTO_TCP|| (ip->ip_p == IPPROTO_UDP && (ip->ip_off&IP_OFFMASK)==0))
        {
            struct libnet_udp_hdr* udp;
            udp = (struct libnet_udp_hdr*) nextHeader;
            int port = udp->uh_dport;

            if (CheckApplicationRoutingProtocol(node,interfaceIndex,port))
            {
                //printf("inside the application routing protocol code\n");
                return FALSE;
            }
            if ((ip->ip_p == IPPROTO_UDP) && (udp->uh_dport == APP_MESSENGER))
            {
                return FALSE;
            }

        }
        // Trace sending packet
        ActionData acnData;
        acnData.actionType = SEND;
        acnData.actionComment = NO_COMMENT;
        TRACE_PrintTrace(
                node,
                msg,
                TRACE_NETWORK_LAYER,
                PACKET_OUT,
                &acnData);

    }

    if ((node->partitionId == node->partitionData->partitionId)
            && (node->macData[interfaceIndex]->promiscuousModeWithHeaderSwitch == TRUE))
    {
        //switching dest address of eavesdropped packet to that of the eavesdropping node's 
        //ip address. This feature cannot be used if the operational host acting as a 
        //eavesdropping node is a router
        ipHeader->ip_dst = MAPPING_GetInterfaceAddressForInterface(
                node,
                node->nodeId,
                interfaceIndex);
    }

    if (node->partitionData->partitionId != node->partitionData->masterPartitionForCluster)
    {
        // Give this message to the master partition for this cluster
        ForwardInfo* forward = NULL;
        MESSAGE_SetLayer(msg, EXTERNAL_LAYER, EXTERNAL_IPNE);
        MESSAGE_SetEvent(msg, EXTERNAL_MESSAGE_IPNE_EgressPacket);
        MESSAGE_AddInfo(iface->partition->firstNode, msg, sizeof(ForwardInfo), INFO_TYPE_ForwardInfo);
        forward = (ForwardInfo*)MESSAGE_ReturnInfo(msg, INFO_TYPE_ForwardInfo);
        forward->interfaceIndex = interfaceIndex;
        forward->nodeId = node->nodeId;
        forward->previousHopAddress = previousHopAddress;
        forward->type = NETWORK_IPV4;
        EXTERNAL_MESSAGE_RemoteSend(ipne, node->partitionData->masterPartitionForCluster, msg, 0, EXTERNAL_SCHEDULE_LOOSELY);
        return TRUE;
    }

    // Jeff
    {
    double rtr = msg->rtr(node);
    double drt = msg->deltaRealTime();
    double dst = msg->deltaSimTime(node);

    //printf("--> drt=%0.6f dst=%0.6f rtr=%0.6f\n", drt, dst, rtr);
    }

    // Figure out the outgoing address for this interface
    NodeAddress myAddress = MAPPING_GetInterfaceAddressForInterface(
            node,
            node->nodeId,
            interfaceIndex);

    // before creating message, check for MDP packet
    MDPPacketHandler::CheckAndProcessOutgoingMdpPacket(node,
                                               ipHeader,
                                               ip,
                                               msg,
                                               ipHeaderLength);

    //Need to record outgoing packets here, 
    //since everything in the recorded packets shouls be according to qualnet specifications 

    iface->partition->rrInterface->RecordOutgoingPacket(
        myAddress,  //this is the from address 
        0,
        ipHeader->ip_src,
        ipHeader->ip_dst,
        ipHeader->ip_id,
        IpHeaderGetIpDontFrag(ipHeader->ipFragment),
        IpHeaderGetIpMoreFrag(ipHeader->ipFragment),
        IpHeaderGetIpFragOffset(ipHeader->ipFragment),
        IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
        ipHeader->ip_p,
        ipHeader->ip_ttl,
        msg->packet + ipHeaderLength,
        msg->packetSize - ipHeaderLength,
        previousHopAddress,
        ipHeaderLength,
        ipOptionsHostOrder);
    free(ipOptionsHostOrder);

        // process outgoing packet
        inject = ProcessOutgoingIpPacket(
            ipne,
            myAddress,
            (UInt8*) ipHeader,
            MESSAGE_ReturnPacketSize(msg));

        // If the packet should be injected
        if (inject)
        {
            // Build offset
//BITF

            offset = IpHeaderGetIpFragOffset(ipHeader->ipFragment);
//BITF
            if (IpHeaderGetIpDontFrag(ipHeader->ipFragment))
            {
                offset |= 0x4000;
            }
//BITF
            if (IpHeaderGetIpMoreFrag(ipHeader->ipFragment))
            {
                offset |= 0x2000;
            }


            // Inject the packet to the operational network
            AutoIPNEInjectIpPacketAtLinkLayer(
                ipne,
                myAddress,
//BITF
                //ip->ip_tos,
                (UInt8)IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),

                ipHeader->ip_id,
                offset,
                ipHeader->ip_ttl,
                ipHeader->ip_p,
                ipHeader->ip_src,
                //LibnetIpAddressToULong(ip->ip_src),
                ipHeader->ip_dst,
                //LibnetIpAddressToULong(ip->ip_dst),
                (UInt8*) msg->packet + ipHeaderLength,
                IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - ipHeaderLength,
                EXTERNAL_QuerySimulationTime(ipne),
                ipOptions,
                ipHeaderLength);

           MESSAGE_Free(node,msg);
            return TRUE;
        }

        MESSAGE_Free(node,msg);
        return FALSE;
}

// /**
// API       :: AutoIPNE_ForwardFromNetworkLayer
// PURPOSE   :: Check if a packet should be forwarded to an operational host
//              and forward it if necessary.
//              Host byte order (QN definition)
// PARAMETERS::
// + node : Node* : The node processing the packet
// + interfaceIndex : Int32 : Interface the packet was received on
// + msg : Message* : The packet
// RETURN    :: BOOL : TRUE if the packet was forwarded to an operational
//                     host, FALSE if not
// **/
BOOL AutoIPNE_ForwardFromNetworkLayer(
    Node* node,
    Int32 interfaceIndex,
    Message* msg)
{
    ip6_hdr* ipHeader = NULL;
    Int32 ipHeaderLength = 0;
    EXTERNAL_Interface* ipne = NULL;
    AutoIPNEData* ipneData = NULL;
    BOOL inject = FALSE;

    // Get IPNE external interface
    ipne = node->partitionData->interfaceTable[EXTERNAL_IPNE];
    if (ipne == NULL)
    {
        ERROR_ReportError("EXata hardware-in-the-loop" 
                          "capability not present");
    }

    ipneData = (AutoIPNEData*) ipne->data;
    EXTERNAL_Interface* iface = ipne;

    ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    struct libnet_ipv6_hdr* ip
        = (struct libnet_ipv6_hdr*) MESSAGE_ReturnPacket(msg);

    ipHeaderLength = IPV6_HEADER_LENGTH;

    UInt8* nextHeader = NULL;
    nextHeader = ((UInt8*) ip) + ipHeaderLength;

    if (node->partitionData->partitionId == node->partitionId)
    {
        //Get IP proto no and Check if we need to inject this packet
        if (CheckNetworkRoutingProtocolIpv6(node,interfaceIndex,ip->ip_nh))
        {
            //printf("inside the network routing protocol code\n");
            return FALSE;
        }

        if (ip->ip_nh == IPPROTO_ICMPV6)
        {
             struct libnet_icmpv6_hdr* icp
                 = (struct libnet_icmpv6_hdr*) (ip + 1);
             if (icp->icmp_type != ICMP6_ECHO
                 && icp->icmp_type != ICMP6_ECHOREPLY)
             {
                 return FALSE;
             }
        }
        
        // for UDP and TCP to check if we need to inject this packet
        if (ip->ip_nh == IPPROTO_TCP|| ip->ip_nh == IPPROTO_UDP)
        {
            struct libnet_udp_hdr* udp = NULL;
            udp = (struct libnet_udp_hdr*) nextHeader;
            int port = udp->uh_dport;

            if (CheckApplicationRoutingProtocolIpv6(node,
                                                    interfaceIndex,
                                                    port))
            {
                return FALSE;
            }
            if ((ip->ip_nh == IPPROTO_UDP) && (udp->uh_dport == APP_MESSENGER))
            {
                return FALSE;
            }
        }

        // Trace sending packet
        ActionData acnData;
        acnData.actionType = SEND;
        acnData.actionComment = NO_COMMENT;
        TRACE_PrintTrace(node,
                         msg,
                         TRACE_NETWORK_LAYER,
                         PACKET_OUT,
                         &acnData);
    }

    if (node->partitionData->partitionId
            != node->partitionData->masterPartitionForCluster)
    {
        // Give this message to the master partition for this cluster
        ForwardInfo* forward = NULL;
        MESSAGE_SetLayer(msg, EXTERNAL_LAYER, EXTERNAL_IPNE);
        MESSAGE_SetEvent(msg, EXTERNAL_MESSAGE_IPNE_EgressPacket);
        MESSAGE_AddInfo(iface->partition->firstNode,
                        msg, sizeof(ForwardInfo),
                        INFO_TYPE_ForwardInfo);
        forward = (ForwardInfo*)MESSAGE_ReturnInfo(msg,
                                                   INFO_TYPE_ForwardInfo);
        forward->interfaceIndex = interfaceIndex;
        forward->nodeId = node->nodeId;
        forward->type = NETWORK_IPV6;
        EXTERNAL_MESSAGE_RemoteSend(ipne,
                              node->partitionData->masterPartitionForCluster,
                              msg,
                              0,
                              EXTERNAL_SCHEDULE_LOOSELY);
        return TRUE;
    }

    // Figure out the outgoing address for this interface
    Address myAddress = MAPPING_GetInterfaceAddressForInterface(node,
                                                            node->nodeId,
                                                            NETWORK_IPV6,
                                                            interfaceIndex);

    // process outgoing packet
    inject = ProcessOutgoingIpv6Packet(ipne,
                                       (UInt8*) ipHeader,
                                       MESSAGE_ReturnPacketSize(msg));

    // If the packet should be injected
    if (inject)
    {
        // Inject the packet to the operational network
        AutoIPNEInjectIpPacketAtLinkLayer(ipne,
                                      myAddress,
                                      ip6_hdrGetClass(ipHeader->ipv6HdrVcf),
                                      ip6_hdrGetFlow(ipHeader->ipv6HdrVcf),
                                      ipHeader->ipv6_plength,
                                      ipHeader->ipv6_nhdr,
                                      ipHeader->ipv6_hlim,
                                      ip->ip_src,
                                      ip->ip_dst,
                                      (UInt8*) msg->packet + ipHeaderLength,
                                      EXTERNAL_QuerySimulationTime(ipne));

        MESSAGE_Free(node,msg);
        return TRUE;
    }

    MESSAGE_Free(node,msg);
    return FALSE;
}

void AutoIPNEHandleExternalMessage(
    Node* node,
    Message* msg)
{
    switch (msg->eventType)
    {
        case EXTERNAL_MESSAGE_IPNE_SetExternalInterface:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            node->macData[interfaceIndex]->isIpneInterface = TRUE;

            node->macData[interfaceIndex]->isVirtualLan =
                (bool)*(int*)MESSAGE_ReturnPacket(msg);

            MESSAGE_Free(node, msg);
            break;
        }
        case EXTERNAL_MESSAGE_IPNE_ResetExternalInterface:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            node->macData[interfaceIndex]->isIpneInterface = FALSE;

            MESSAGE_Free(node, msg);
            break;
        }
        case EXTERNAL_MESSAGE_IPNE_EgressPacket:
        {
            ForwardInfo* forward = NULL;
            forward =
                (ForwardInfo*)MESSAGE_ReturnInfo(msg, INFO_TYPE_ForwardInfo);
            Node* remoteNode = NULL;

            remoteNode =
                MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash,
                                           forward->nodeId);
            if (remoteNode != NULL)
            {
                printf("Node Id %d should not be present in partition %d\n",
                        forward->nodeId,
                        remoteNode->partitionData->partitionId);
                assert(FALSE);
            }
            remoteNode =
                MAPPING_GetNodePtrFromHash(node->partitionData->remoteNodeIdHash,
                                           forward->nodeId);
            if (remoteNode == NULL)
            {
                printf("Node %d does not exist!\n", forward->nodeId);
                assert(FALSE);
            }
            if (forward->type == NETWORK_IPV4)
            {
                AutoIPNE_ForwardFromNetworkLayer(remoteNode,
                                             forward->interfaceIndex,
                                             msg,
                                             forward->previousHopAddress,
                                             FALSE);
            }
            else
            {
                AutoIPNE_ForwardFromNetworkLayer(remoteNode,
                                             forward->interfaceIndex,
                                             msg);
            }
            break;
        }
        case EXTERNAL_MESSAGE_IPNE_SetVirtualLanGateway:
        {
            int* packet = (int*)MESSAGE_ReturnPacket(msg);
            int subnetAddr, subnetMask;

            subnetAddr = *packet;
            subnetMask = *(packet + 1);
            printf("Partition %d %d node %d got virtual lan %x %x\n",
                    node->partitionData->partitionId,
                    node->partitionId,
                    node->nodeId,
                    subnetAddr, subnetMask);

            if (node->partitionData->virtualLanGateways->find(subnetAddr) ==
                    node->partitionData->virtualLanGateways->end())
            {
                printf("Adding\n");
                node->partitionData->virtualLanGateways->insert(
                        std::pair<int, int>(subnetAddr, subnetMask));
            }
            MESSAGE_Free(node, msg);
            break;
        }
        default:
        {
            printf("Unknown EXTERNAL_MESSAGE_IPNE type %d\n", msg->eventType);
            assert(FALSE);
        }
    }
}
