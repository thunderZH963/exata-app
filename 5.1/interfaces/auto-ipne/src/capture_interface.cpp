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

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/icmp6.h>
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include <winsock2.h>
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "external_util.h"
#include "auto-ipnetworkemulator.h"
#include "capture_interface.h"
#include "ipne_qualnet_interface.h"
#include "arp_interface.h"
#include "olsr_interface.h"
#include "ospf_interface.h"
#include "pim_interface.h"
#include "ipsec_interface.h"
#include "ipv6.h"
#include "product_info.h"
#include "igmpv3_interface.h"

#ifdef INTERFACE_JNE_C2ADAPTER
#include "c2adapter-api.h"
#endif /* INTERFACE_JNE_C2ADAPTER */

#ifdef INTERFACE_JNE_C3
#include "c3-api.h"
#endif /* INTERFACE_JNE_C3 */

#define FILTER_STRING_LENGTH (100 * MAX_STRING_LENGTH)
#ifdef INTERFACE_JNE_JREAP
#include "jreap-api.h"
#endif // JREAP
#define WORKING_BUFFER_SIZE 15000
// /**
// API       :: AutoIPNEHandleCommonPacket
// PURPOSE   :: This function will handle the common headers in the incoming
//              packet received in IPNetworkEmulatorReceive or after
//              decrypting the packet in case of IPsec transport and tunnel
//              mode.
// PARAMETERS::
// + nextHeader : UInt8* : The header next to ip header
// + data : AutoIPNEData* : Pointer to the AutoIPNEData. This will be NULL
// +        when invoked from IPsec models.
// + size : int : The size of the sniffed packet, would be set to NULL when
// +        invoked from IPsec models.
// + ipHdr : IpHeaderType* : pointer to IpHeaderType.
// + proto : ip header protocol
// + pkt : UInt8* : packet pointer
// + payloadSize : int : size o fthe payload
// + hitlPacket : bool : if the packet is for hitl
// RETURN    :: bool
// **/
bool AutoIPNEHandleCommonPacket(
    UInt8* nextHeader,
    AutoIPNEData* data,
    int size,
    IpHeaderType* ipHdr,
    unsigned int    proto,
    UInt8* pkt,
    int payloadSize)
{
    switch (proto)
    {
        case IPPROTO_TCP:
        {
            struct libnet_tcp_hdr * tcp =
                (struct libnet_tcp_hdr *)nextHeader;

            // Swap TCP header and call register port handlers
            tcp->th_sport = ntohs(tcp->th_sport);
            tcp->th_dport = ntohs(tcp->th_dport);
            tcp->th_seq   = ntohl(tcp->th_seq);
            tcp->th_ack   = ntohl(tcp->th_ack);
            tcp->th_win   = ntohs(tcp->th_win);
            tcp->th_sum   = 0;
            tcp->th_urp   = ntohs(tcp->th_urp);
            unsigned char *field = (unsigned char *)(nextHeader + 12);
            unsigned char lval = (unsigned char) (*field >> 4);
            unsigned char rval = (unsigned char) (*field & 0xFF);
            *field = (unsigned char) ((rval << 4) | lval);
            // TODO
            //   Call registered port number handlers
            if (data)
            {
                data->stats[AUTO_IPNE_STATS_TCP_IN_PKT] ++;
                data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES] += size;
            }
            break;
        }

        case IPPROTO_UDP:
        {
            if (IpHeaderGetIpFragOffset(ipHdr->ipFragment) == 0)
            {
                struct libnet_udp_hdr * udp =
                    (struct libnet_udp_hdr *)nextHeader;
                // Swap UDP header and call register port handlers
                udp->uh_sport = ntohs(udp->uh_sport);
                udp->uh_dport = ntohs(udp->uh_dport);
                udp->uh_ulen  = ntohs(udp->uh_ulen);
                
                //   Call registered port number handlers
                // UDP protocol handler code:
                unsigned char *payload = (unsigned char *)
                    ((unsigned char *)udp + 8);

                switch (udp->uh_sport)
                {
                    case OLSR_PORT:
                    {
                        OLSRPacketHandler::ReformatIncomingPacket(payload);
                        // The packet was modified, so the checksum must be zeroed
                        udp->uh_sum = 0;
                        break;
                    }
#ifdef HITL_INTERFACE
                    case HITL_PORT:
                        return false;
#endif
                    default:
                    {
                        if (data)
                        {
                            data->stats[AUTO_IPNE_STATS_UDP_IN_PKT] ++;
                            data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES] += size;
                        }
                        break;
                    }
                } 
            }

            break;
        }

        case IPPROTO_ICMP:
        {

            break;
        }
        case IPPROTO_IGMP:
        {
            if (payloadSize > IGMPV2_HEADER_SIZE)
            {
                IGMPv3PacketHandler::ReformatIncomingPacket(nextHeader);
            }
            else
            {
                struct libnet_igmp_hdr* igmp;
                igmp = (struct libnet_igmp_hdr*) nextHeader;
                igmp->igmp_group.s_addr =
                    ntohl(igmp->igmp_group.s_addr);
            }
            break;
        }
        case IPPROTO_OSPF:
        {
            OSPFPacketHandler::ReformatIncomingPacket(pkt);
            break;
        }
        case IPPROTO_PIM:
        {
            PIMPacketHandler::ReformatIncomingPacket(((UInt8*) nextHeader),
                payloadSize);
            break;
        }
#ifdef CYBER_CORE
        case IPPROTO_ESP:
        {
            ESPPacketHandler::ReformatIncomingPacket(((UInt8*) nextHeader));
            break;
        }
        case IPPROTO_AH:
        {
            AHPacketHandler::ReformatIncomingPacket(((UInt8*) nextHeader));
            break;
        }
#endif //CYBER_CORE
        default:
        {
            printf("Unknown IP packet: ip_p = %d\n", proto);
            break;
        }
    }
    return true;
}

// /**
// API       :: AutoIPNEHandleIPv6CommonPacket
// PURPOSE   :: This function will handle the common headers in the incoming
//              IPv6 packet received in IPNetworkEmulatorReceive
// PARAMETERS::
// + nextHeader : UInt8* : The header next to ip header
// + data : AutoIPNEData* : Pointer to the AutoIPNEData. This will be NULL
// +        when invoked from IPsec models.
// + size : int : The size of the sniffed packet, would be set to NULL when
// +        invoked from IPsec models.
// + ipHdr : IpHeaderType* : pointer to libnet_ipv6_hdr type
// + proto : unsigned int : ip header protocol
// + pkt : UInt8* : packet pointer
// + payloadSize : int : size o fthe payload
// RETURN    :: bool
// **/
bool AutoIPNEHandleIPv6CommonPacket(
    UInt8* nextHeader,
    AutoIPNEData* data,
    int size,
    libnet_ipv6_hdr* ipHdr,
    unsigned int proto,
    UInt8* pkt,
    int payloadSize)
{
    switch (proto)
    {
        case IP6_NHDR_FRAG:
        {
            UInt32 proto = 0;
            UInt8* nh_hdr = NULL;
            struct libnet_ipv6_frag_hdr* fragHeader
                = (struct libnet_ipv6_frag_hdr*)nextHeader;
            fragHeader->ip_frag = ntohs(fragHeader->ip_frag);
            fragHeader->ip_id = ntohl(fragHeader->ip_id);
            proto = fragHeader->ip_nh;
            nh_hdr = nextHeader + sizeof(libnet_ipv6_frag_hdr);
            UInt16 offSet = fragHeader->ip_frag & 0xfff8;

            if (offSet == 0)
            {
                AutoIPNEHandleIPv6CommonPacket(nh_hdr,
                                               data,
                                               size,
                                               ipHdr,
                                               proto,
                                               pkt,
                                               payloadSize);
            }
            break;
        }
        case IPPROTO_TCP:
        {
            struct libnet_tcp_hdr* tcp
                = (struct libnet_tcp_hdr*)nextHeader;

            // Swap TCP header and call register port handlers
            tcp->th_sport = ntohs(tcp->th_sport);
            tcp->th_dport = ntohs(tcp->th_dport);
            tcp->th_seq   = ntohl(tcp->th_seq);
            tcp->th_ack   = ntohl(tcp->th_ack);
            tcp->th_win   = ntohs(tcp->th_win);
            tcp->th_sum   = ntohs(tcp->th_sum);
            tcp->th_urp   = ntohs(tcp->th_urp);
            unsigned char* field = (unsigned char*)(nextHeader + 12);
            unsigned char lval = (unsigned char)(*field >> 4);
            unsigned char rval = (unsigned char)(*field & 0xFF);
            *field = (unsigned char) ((rval << 4) | lval);
            if (data)
            {
                data->stats[AUTO_IPNE_STATS_TCP_IN_PKT] ++;
                data->stats[AUTO_IPNE_STATS_TCP_IN_BYTES] += size;
            }
            break;
        }

        case IPPROTO_UDP:
        {
            struct libnet_udp_hdr* udp
                = (struct libnet_udp_hdr*)nextHeader;
            // Swap UDP header and call register port handlers
            udp->uh_sport = ntohs(udp->uh_sport);
            udp->uh_dport = ntohs(udp->uh_dport);
            udp->uh_ulen  = ntohs(udp->uh_ulen);
            udp->uh_sum  = udp->uh_sum;
            // Call registered port number handlers
            // UDP protocol handler code:
            switch (udp->uh_sport)
            {
                case OLSR_PORT:
                {
                    ERROR_ReportWarning("OLSR currently not supported");
                    break;
                }
#ifdef HITL_INTERFACE
                case HITL_PORT:
                    return false;
#endif
                default:
                {
                    if (data)
                    {
                        data->stats[AUTO_IPNE_STATS_UDP_IN_PKT] ++;
                        data->stats[AUTO_IPNE_STATS_UDP_IN_BYTES] += size;
                    }
                    break;
                }
            }
                break;
        }
        case IPPROTO_ICMPV6:
        {
            struct libnet_icmpv6_hdr* icp = (struct libnet_icmpv6_hdr*)nextHeader;
            icp->id = ntohs(icp->id);
            icp->seq = ntohs(icp->seq);
            break;
        }
        default:
        {
            printf("Unknown IP packet: ip_p = %d\n", proto);
            break;
        }
    }
    return true;
}

// /**
// API       :: AutoIPNEHandleSniffedPacket
// PURPOSE   :: This function will handle an incoming packet received in
//              IPNetworkEmulatorReceive.  It will inject the packet into the
//              QualNet simulation depending on which socket the packet came
//              through.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet
// + size : int : The size of the sniffed packet
// RETURN    :: bool
// **/
static bool AutoIPNEHandleSniffedPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int size,
    int deviceIndex)
{
    AutoIPNEData* data = NULL;
    struct libnet_ethernet_hdr* ethernet = NULL;
    UInt16 type = 0;
    IpHeaderType* ipHeader = NULL;

    data = (AutoIPNEData*) iface->data;

    // Pre-process depending on packet type
    ethernet = (struct libnet_ethernet_hdr*) (packet);
    type = ntohs(ethernet->ether_type);
    if (type == ETHERTYPE_ARP)
    {
        return AutoIPNE_ProcessArp(iface,
                                   packet + AutoIPNE_ETHERNET_HEADER_LENGTH,
                                   deviceIndex);
        // Process ARP, then return and do not process the packet further
    }
    else if (type == ETHERTYPE_IP)
    {
        struct libnet_ipv4_hdr* ip;

        int ipHeaderLength;
        UInt8* payload;
        UInt8* nextHeader;
        UInt32 packetSize;

        // Extract IP header
        ip = (struct libnet_ipv4_hdr*) (packet + AutoIPNE_ETHERNET_HEADER_LENGTH);
        ipHeaderLength = ip->ip_hl * 4;

        // Update the packet size.  This will take care of the case where the
        // ethernet frame is padded.
        packetSize = ntohs(ip->ip_len) + AutoIPNE_ETHERNET_HEADER_LENGTH;

        // Find where the payload begins
        payload = packet + AutoIPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;

#ifdef RETAIN_IP_HEADER
        ipHeader = (IpHeaderType *)ip;
        ip->ip_id         = ntohs(ip->ip_id);
#ifdef FORMAT_IP_FRAGMENT
        ip->ip_off     = ntohs(ip->ip_off);
#endif
        ip->ip_sum         = ntohs(ip->ip_sum);
        ip->ip_src        = ntohl(ip->ip_src);
        ip->ip_dst        = ntohl(ip->ip_dst);


        ipHeader->ip_v_hl_tos_len = ntohl(ipHeader->ip_v_hl_tos_len);
#endif

        if ((ntohl(ip->ip_dst.s_addr) >= IP_MIN_MULTICAST_ADDRESS) &&
                (ntohl(ip->ip_dst.s_addr) <= IP_MAX_MULTICAST_ADDRESS))
        {
            data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT] ++;
            data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES] += packetSize;
        }

        ip->ip_off     = ntohs(ip->ip_off);

        // Handle anything socket/protocol specific to this packet.
        // This possibly modify the packet as well as the packet injection
        // function.
        nextHeader = ((UInt8*) ip) + ipHeaderLength;
        ipHeader = (IpHeaderType *)ip;
        int payloadSize = ntohs(ip->ip_len) - ipHeaderLength;
        if (AutoIPNEHandleCommonPacket(nextHeader,
                                   data,
                                   size,
                                   ipHeader,
                                   ip->ip_p,
                                   (UInt8*) ip,
                                   payloadSize))

        {
            return AutoIPNEEmulateIpPacket(iface, packet, (int) packetSize, deviceIndex);
        }
        else
        {
            return false;
        }
    }
    else if (type == ETYPE_IPV6) // Received IPv6 packet
    {
        struct libnet_ipv6_hdr* ipv6 = NULL;

        int ipv6HeaderLength = 0;
        UInt8* payload = NULL;
        UInt8* nextHeader = NULL;
        UInt32 packetSize = 0;

        // Extract IPv6 header
        ipv6 = (struct libnet_ipv6_hdr*)
                                 (packet + AutoIPNE_ETHERNET_HEADER_LENGTH);
        ipv6HeaderLength = IPV6_HEADER_LENGTH;

        // Update the packet size.  This will take care of the case where the
        // ethernet frame is padded.
        packetSize = ntohs(ipv6->ip_len)
                     +IPV6_HEADER_LENGTH
                     + AutoIPNE_ETHERNET_HEADER_LENGTH;

        // Find where the payload begins
        payload = packet + AutoIPNE_ETHERNET_HEADER_LENGTH + ipv6HeaderLength;

        // Handle anything socket/protocol specific to this packet.
        nextHeader = ((UInt8*) ipv6) + ipv6HeaderLength;

        int payloadSize = ntohs(ipv6->ip_len);

        // Check for multicast packet
        if (ipv6->ip_dst.libnet_s6_addr[0] == 0xff)
        {
            if (!(ipv6->ip_dst.libnet_s6_addr[1] & IP6_T_FLAG))
            {
                // reserved multicast address
                // return wihtout adding packet to simulation
                return false;
            }
            data->stats[AUTO_IPNE_STATS_MULTI_IN_PKT] ++;
            data->stats[AUTO_IPNE_STATS_MULTI_IN_BYTES] += packetSize;
        }

        if (AutoIPNEHandleIPv6CommonPacket(nextHeader,
                                           data,
                                           size,
                                           ipv6,
                                           ipv6->ip_nh,
                                           (UInt8*) ipv6,
                                           payloadSize))
        {
            return AutoIPNEEmulateIpv6Packet(iface,
                                             packet,
                                             (int) packetSize,
                                             deviceIndex);
        }
        else
        {
            return false;
        }
    }
    else
    {
        // Unknown type, do not process
        if (data->debug)
        {
            printf(
                "IPNE received packet with unknown ethernet type: %d\n",
                ntohs(ethernet->ether_type));
        }
        return false;
    }
}

// /**
// API       :: DetermineIpAddressString
// PURPOSE   :: This function determines the device's IP address
//              in a string format from its device index
// PARAMETERS::
// + dev : pcap_if_t * : device detected by pcap
// + data : AutoIPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// RETURN    :: void
// **/

static void DetermineIpAddressString(
    pcap_if_t *dev,
    AutoIPNEData* data,
    int deviceIndex)
{
    struct pcap_addr *currAddr = dev->addresses;
    int interfaceAddress = 0, subnetMask = 0;
    while (currAddr != NULL)
    {
        if ((((struct sockaddr_in *)(currAddr->addr))->sin_family == AF_INET)
          && (((struct sockaddr_in *)(currAddr->netmask))->sin_family == AF_INET))
        {
            interfaceAddress = (int) (((struct sockaddr_in *)
                               (currAddr->addr))->sin_addr.s_addr);
            subnetMask = (int) (((struct sockaddr_in *)
                         (currAddr->netmask))->sin_addr.s_addr);
            if ((interfaceAddress != 0) && (subnetMask != 0))
            {
                AutoIpneV4V6Address v4Address;
                memset(&v4Address, 0, sizeof(AutoIpneV4V6Address));
                v4Address.address.networkType = NETWORK_IPV4;
                v4Address.address.interfaceAddr.ipv4 = interfaceAddress;
                v4Address.u.subnetmask = subnetMask;
                data->deviceArray[deviceIndex].interfaceAddress
                    ->push_back(v4Address);
            }
        }
        else  if (((struct sockaddr_in6*)(currAddr->addr))->sin6_family
            == AF_INET6)
        {
            sockaddr_in6* ipv6Addr = (sockaddr_in6*)currAddr->addr;
            AutoIpneV4V6Address v6Address;
            memset(&v6Address, 0, sizeof(AutoIpneV4V6Address));
            v6Address.address.networkType = NETWORK_IPV6;
            UInt8* itr = (UInt8*)(ipv6Addr->sin6_addr.s6_addr);
            for (UInt8 i = 0; i < 16; i++)
            {
                v6Address.address.interfaceAddr.ipv6.s6_addr[i] = *itr;
                itr++;
            }
            v6Address.u.ipv6.scopeId = ipv6Addr->sin6_scope_id;
            v6Address.u.ipv6.OnLinkPrefixLength = DEFAULT_IPV6_PREFIX_LENGTH;
            data->deviceArray[deviceIndex].interfaceAddress
                ->push_back(v6Address);
        }
        currAddr = currAddr->next;
    }
}

// /**
// API       :: DetermineMacAddress
// PURPOSE   :: This function determines the device's MAC address from
//              its device index
// PARAMETERS::
// + data : AutoIPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// + macAddress  : char * : 6 byte char array to store MAC address (output)
// RETURN    :: void
// **/
static bool DetermineMacAddress(
    AutoIPNEData* data,
    int deviceIndex,
    char* macAddress)
{
#ifdef __APPLE__
    char errbuf[PCAP_ERRBUF_SIZE];
    char errString[MAX_STRING_LENGTH];
    int deviceChoice;
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    struct sockaddr* addr;
    int i;

    // Get a list of all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        sprintf(errString,"Error in pcap_findalldevs: %s\n", errbuf);
        ERROR_ReportError(errString);
        return false;
    }
    if (alldevs == NULL)
    {
        ERROR_ReportError("pcap_findalldevs returned nothing");
        return false;
    }

    char* device = data->deviceArray[deviceIndex].device;
#ifdef DEBUG
    printf("getting MAC address for device %s\n", device);
#endif

    // Advance to the selected device
    dev = alldevs;
    while (dev != NULL)
    {
        if (dev->addresses->addr->sa_family == 18) // AF_LINK
        {
            char* addr = (char*) dev->addresses->addr;
            int nlen = addr[5]; // Length of name
            int alen = addr[6]; // Length of address

            if (alen == 6 && nlen == strlen(device) && strncmp(addr + 8, device, strlen(device)) == 0)
            {
                memcpy(macAddress, addr + 8 + nlen, 6);

#ifdef DEBUG
                printf("match, addr = ");
                printf("%02x", (UInt8) macAddress[0]);
                for (i = 1; i < 6; i++)
                {
                    printf(":%02x", (UInt8) macAddress[i]);
                }
#endif

                return true;
            }
        }

        dev = dev->next;
    }

    sprintf(errString, "Could not find MAC address for device %s", device);
    ERROR_ReportError(errString);
    return false;    // compiler doesn't know that ERROR_ReportError never returns

#else // __APPLE
#ifdef _WIN32  // windows
    DWORD retVal = 0;
    ULONG iteration = 0;
    ULONG family = AF_UNSPEC;
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    IP_ADAPTER_ADDRESSES* adaptersInfo = NULL;
    IP_ADAPTER_ADDRESSES* adaptersPtr = NULL;
    ULONG outBufLen = WORKING_BUFFER_SIZE;

    // get adapter settings, using default buffer size as 
    // WORKING_BUFFER_SIZE, in case of buffer over flow , re allocate
    // memory to required buffer size returned by the function 
    // GetAdaptersAddresses().
    do
    {
        adaptersInfo = (IP_ADAPTER_ADDRESSES*)MEM_malloc(outBufLen);
        retVal = GetAdaptersAddresses(family,
                                      flags,
                                      NULL,
                                      adaptersInfo,
                                      &outBufLen);

        if (retVal == ERROR_BUFFER_OVERFLOW)
        {
            MEM_free(adaptersInfo);
            adaptersInfo = NULL;
        }
        else
        {
            break;
        }

        iteration++;

    } while ((retVal == ERROR_BUFFER_OVERFLOW) && (iteration < 3));

    if (retVal == NO_ERROR)
    {
        adaptersPtr = adaptersInfo;
        while (adaptersPtr != NULL
           && (strstr(data->deviceArray[deviceIndex].device,
                          adaptersPtr->AdapterName) == NULL))
        {
            adaptersPtr = adaptersPtr->Next;
        }

        // Verify that an adapter was found
        if (adaptersPtr == NULL)
        {
            //ERROR_ReportWarning("Adapter not found");
            return false;
        }

        // Verify the address is the right size
        if (adaptersPtr->PhysicalAddressLength != ETHER_ADDR_LEN)
        {
            return false;
        }

        // Copy the address
        UInt8* u = (UInt8*) adaptersPtr->PhysicalAddress;
        memcpy(macAddress, u, ETHER_ADDR_LEN);
        MEM_free(adaptersInfo);
        return true;

    }
    else
    {
        ERROR_ReportError("Error getting adapters");
        return false;
    }

#else // unix/linux
    int err;
    int s;
    struct ifreq ifr;
    struct sockaddr_in*sin = (struct sockaddr_in*) &ifr.ifr_addr;
    UInt8* u = (UInt8*) ifr.ifr_addr.sa_data;

    // Get the socket for this device
    s = pcap_fileno(data->deviceArray[deviceIndex].pcapFrame);

    // Set the ifr struct to retrieve the mac address of the device name
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, data->deviceArray[deviceIndex].device);
    sin->sin_family = AF_INET;

    // Get the interface information
    err = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (err != 0)
    {
        ERROR_ReportWarning("Error calling ioctl on device");
        return false;
    }

    // Copy the address
    memcpy(macAddress, u, ETHER_ADDR_LEN);
    return true;
#endif // unix/linux
#endif // __APPLE__ not defined
}

// /**
// API       :: DetermineMacAddressString
// PURPOSE   :: This function determines the device's MAC address
//              in a string format from its device index
// PARAMETERS::
// + data : AutoIPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// + macAddressString  : char * : 18 byte char array to store MAC address
//                                string (output)
// RETURN    :: void
// **/
static bool DetermineMacAddressString(
    AutoIPNEData* data,
    int deviceIndex,
    char* macAddressString)
{
    char macAddress[ETHER_ADDR_LEN];

    // Call DetermineMacAddress and print to string
    bool foundAddr = DetermineMacAddress(data, deviceIndex, macAddress);
    if (!foundAddr)
    {
        return false;
    }

    sprintf(
        macAddressString,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        (UInt8) macAddress[0],
        (UInt8) macAddress[1],
        (UInt8) macAddress[2],
        (UInt8) macAddress[3],
        (UInt8) macAddress[4],
        (UInt8) macAddress[5]);

    return true;
}


void AutoIPNEInitializeCaptureInterface(
    AutoIPNEData *data)
{
    // Initialize pcap and libnet
    int i;
    char errString[MAX_STRING_LENGTH];
    char errbuf[PCAP_ERRBUF_SIZE];

    // pcap
    int err;
    pcap_if_t* alldevs;
    pcap_if_t* dev;
    int numDevices;
    // libnet

    /* Step 1: Find and open all network devices (for pcap) */
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        sprintf(errString,"Error in pcap_findalldevs: %s\n", errbuf);
        ERROR_ReportError(errString);
    }
    if (alldevs == NULL)
    {
        ERROR_ReportWarning("EXata cannot detect any networking device for emulation");
        return;
    }

    // Get the number of devices
    if (data->debug)
    {
        printf("Found Devices for capture:\n");
    }
    for (dev = alldevs, numDevices = 0; dev != NULL; dev = dev->next)
    {
        if (dev->flags & PCAP_IF_LOOPBACK)
            continue;

        if ((strcmp(dev->name, "any") == 0) || (strcmp(dev->name, "lo") == 0))
            continue;
        if (data->debug)
        {
            printf("Index=%d  %s %s\n", numDevices, dev->name, dev->description);
        }

        numDevices ++;
    }

    if (numDevices == 0)
    {
        ERROR_ReportError("This device has no network interface!");
    }

    // Allocate local storage for these devices
    data->numDevices = numDevices;
    data->deviceArray = (AutoIPNEDeviceData *)
                            MEM_malloc(sizeof(AutoIPNEDeviceData)*numDevices);
    memset((char *)data->deviceArray, 0, sizeof(AutoIPNEDeviceData)*numDevices);
    for (int k = 0; k < data->numDevices; k++)
    {
        data->deviceArray[k].interfaceAddress
            = new std::list<AutoIpneV4V6Address>;
    }

    i = 0;
    for (dev = alldevs; dev != NULL; dev = dev->next)
    {
        if (dev->flags & PCAP_IF_LOOPBACK)
            continue;

        if ((strcmp(dev->name, "any") == 0) || (strcmp(dev->name, "lo") == 0))
            continue;
        // If everything is ok, we set this flag to false
        data->deviceArray[i].disabled = TRUE;

        strcpy(data->deviceArray[i].device, dev->name);
        data->deviceArray[i].pcapFrame = pcap_open_live(
                dev->name,
                2048,
                1,
#ifdef __APPLE__
                1,
#else
                -1,
#endif
                errbuf);

        if (data->deviceArray[i].pcapFrame == NULL)
        {
            sprintf(
                    errString,
                    "\nError opening adapter: %s (Make sure EXata is running "
                    "with root access)\n",
                    errbuf);
            if (strstr(errString,"Operation not permitted")==NULL)
            {
                ERROR_ReportWarning(errString);
                i++;
                continue;
            }
            else
                ERROR_ReportError(errString);
        }


        // Set to non-blocking mode
        err = pcap_setnonblock(
                data->deviceArray[i].pcapFrame,
                TRUE,
                errbuf);

        if (err)
        {
            sprintf(errString, "\npcap_setnonblock : %s\n", errbuf);
            ERROR_ReportError(errString);
        }

        // If we cannot read MAC or IP address of this device, then
        // flag it as disabled, and close pcap on this device
        bool foundAddr
            = DetermineMacAddressString(data, i, data->deviceArray[i].macAddress);
        if (!foundAddr)
        {
            if (data->debug)
            {
                printf("Cannot read mac address of the device (index = %d). "
                       "Disabling this device.\n", i);
            }
            pcap_close(data->deviceArray[i].pcapFrame);
            i++;
            continue;
        }

        if (strcmp("00:00:00:00:00:00", data->deviceArray[i].macAddress) == 0)
        {
            sprintf(errString, "Network device %s does not have a valid MAC address "
                               "and cannot be used for emulation. Disabling this "
                               "device.\n", data->deviceArray[i].device);
            ERROR_ReportWarning(errString);
            pcap_close(data->deviceArray[i].pcapFrame);
            i++;
            continue;
        }

        DetermineIpAddressString(dev, data, i);

        if (data->deviceArray[i].interfaceAddress->empty())
        {
            if (data->debug)
            {
                printf("Cannot read ip address of the device (index = %d). "
                       "Disabling this device.\n", i);
            }
            pcap_close(data->deviceArray[i].pcapFrame);
            i++;
            continue;

        }
        data->deviceArray[i].disabled = FALSE;

        i++;
    }

    // Now set filters on all capture devices
    AutoIPNERecompileCaptureFilter(data, -1);
}


// /**
// API       :: PacketInterfaceReceive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void AutoIPNECaptureInterface(EXTERNAL_Interface* iface)
{
    AutoIPNEData* data;
    UInt8* packet;
    struct pcap_pkthdr header;
    char err[MAX_STRING_LENGTH];
    int i;
    bool success;
    char packetBuf[1500];

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
    assert(data != NULL);

    // Capture on all devices
    for (i = 0; i < data->numDevices; i++)
    {
        if (data->deviceArray[i].disabled)
            continue;

        // If pcap is not initialized don't do anything
        if (data->deviceArray[i].pcapFrame == NULL)
        {
            ERROR_ReportError("Invalid pcap frame");
        }

        // Keep getting packets
        packet = (UInt8*) pcap_next(
            data->deviceArray[i].pcapFrame,
            &header);

        while (packet != NULL)
        {
            if (header.caplen < header.len)
            {
                sprintf(err, "Sniffed packet only contains %u/%u bytes",
                            (UInt32) header.caplen, (UInt32) header.len);
                ERROR_ReportWarning(err);
            }

            if (data->incomingPacketLog)
            {
                memcpy(packetBuf,
                   packet,
                   MIN(header.caplen, (unsigned)data->packetLogCaptureSize));
            }


            bool success(false);

#if defined(INTERFACE_JNE_C3)
            if (success == false)
            {
              success = JNE::C3::process(iface, packet, header.caplen);
            }
#endif // C3

#if defined(INTERFACE_JNE_C2ADAPTER)
            if (success == false)
            {
              success = JNE::C2Adapter::process(iface, packet, header.caplen);
            }
#endif // C2ADAPTER

#ifdef INTERFACE_JNE_JREAP
            if (success == false)
            {
              success = JNE::JREAP::process(iface, i, packet, header.caplen);
            }
#endif // JREAP
            // chain further handlers here

            // default handler
            if (success == false)
            {
              success = AutoIPNEHandleSniffedPacket(iface, packet, header.caplen, i);
            }

            if (data->incomingPacketLog)
            {
                header.caplen = MIN(header.caplen,
                                   (unsigned)data->packetLogCaptureSize);
                if (success)
                {
                    pcap_dump((u_char *)data->incomingSuccessPacketLogger, &header, (const u_char *)packetBuf);
                }
                else
                {
                    pcap_dump((u_char *)data->incomingIgnoredPacketLogger, &header, (const u_char *)packetBuf);
                }
            }

            packet = (UInt8*) pcap_next(
                data->deviceArray[i].pcapFrame,
                &header);
        }
    }
}

#ifndef _WIN32
void PopulateARPTable(AutoIPNEData *data, int address, int deviceIndex)
{
    //create a packet to populate the arp table for the operational host
    int payloadSize = 1;
    UInt8* payload;
    payload = (UInt8 *) MEM_malloc(payloadSize);
    libnet_ptag_t t;
    NodeAddress srcAddr;
    int err;
    inet_aton(data->deviceArray[deviceIndex].ipAddress, (in_addr*) &srcAddr);

    // Pass IP header data based on the original packet
    t = libnet_build_ipv4(
            LIBNET_IPV4_H + payloadSize, // length
            0,                  // tos
            0,            // id
            0,           // fragmentation and offset
            1,              // ttl
            1,                    // protocol
            0,                           // checksum
            //*srcAddr,      // source address
            srcAddr,
            address,      // dest address
            NULL,                        // payload (already passed)
            0,                           // payload size
            data->deviceArray[deviceIndex].libnetFrame,
            0);
    if (t == -1)
    {
        ERROR_ReportWarning(
                  "Error while creating ipv4 packet for ARP population\n");
    }
    else
    {
       // Send the packet to the physical network
       err = libnet_write(data->deviceArray[deviceIndex].libnetFrame);
       if (err == -1)
       {
           ERROR_ReportWarning("Error while writing ARP population\n");
       }
    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetFrame);
}

// API       :: PopulateNDPTable
// PURPOSE   :: This function will send neighbor solicitation message to
//              operational host
// PARAMETERS::
// + data : AutoIPNEData* : Pointer to the AutoIPNEData.
// + src_add : in6_addr   : Source address,
// + dst_add : in6_addr*  : Destination to which neighbor solicitation message
//                          will be sent
// + deviceIndex : int    : Device index of exata server machine
// RETURN    :: void
void PopulateNDPTable(AutoIPNEData* data,
                      in6_addr src_add,
                      in6_addr dst_add,
                      int deviceIndex)
{
    //create a packet to populate the NDP table for the operational host
    UInt16 payloadSize;
    UInt8* payload = NULL;
    struct nd_neighbor_solicit* ns = NULL;
    char* option;
    UInt8 macAddr[6];
    in6_addr dstMulticastAddr;
    bool found = false;
    char errString[MAX_STRING_LENGTH];
    libnet_ptag_t t;
    libnet_in6_addr src;
    libnet_in6_addr dst;
    Int32 i,err;
    int counter = 0;
    payloadSize = sizeof(struct nd_neighbor_solicit)
                  + 2 * sizeof(char)
                  + ETHER_ADDR_LEN;
    payload = (UInt8*)MEM_malloc(payloadSize);
    memset(payload, 0, payloadSize);
    ns = (struct nd_neighbor_solicit*)payload;
    ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;
    ns->nd_ns_hdr.icmp6_code = 0;
    ns->nd_ns_hdr.icmp6_cksum = 0;
    ns->nd_ns_reserved = 0;
    ns->nd_ns_target = dst_add;

    dstMulticastAddr = dst_add;
    option = (char*)(ns+1);
    option[0] = 1;
    option[1] = 1;
    char srcMac[ETHER_ADDR_LEN];
    found = DetermineMacAddress(data, deviceIndex, srcMac);
    if (!found)
    {
          ERROR_ReportError("Can not determine source MAC address");
    }

    memcpy(option+2 , srcMac, ETHER_ADDR_LEN);
    // destination multicast address on which NS packet will be sent
    dstMulticastAddr.s6_addr[0] = 0xff;
    dstMulticastAddr.s6_addr[1] = 0x02;
    for (i=2; i < 11; i++)
    {
        dstMulticastAddr.s6_addr[i] = 0;
    }
    dstMulticastAddr.s6_addr[11] = 0x1;
    dstMulticastAddr.s6_addr[12] = 0xff;

    UInt16* checksum = (UInt16*)&ns->nd_ns_hdr.icmp6_cksum;
    *checksum = 0;
    //checksum for ipv6
   *checksum = AutoIPNEComputeTcpStyleChecksum((UInt8*)&src_add,
                                               (UInt8*)&dstMulticastAddr,
                                               IPPROTO_ICMPV6,
                                               (UInt32)ntohs(payloadSize),
                                               (UInt8*)payload);
    // Generic MAC for multicast
    macAddr[0] = 0x33;
    macAddr[1] = 0x33;
    macAddr[2] = dstMulticastAddr.s6_addr[12];
    macAddr[3] = dstMulticastAddr.s6_addr[13];
    macAddr[4] = dstMulticastAddr.s6_addr[14];
    macAddr[5] = dstMulticastAddr.s6_addr[15];

    for (i = 0; i < 16; i++)
    {
        src.libnet_s6_addr[i] = src_add.s6_addr[i];
        dst.libnet_s6_addr[i] = dstMulticastAddr.s6_addr[i];
    }

    t = libnet_build_data(payload,            // payload
                          payloadSize,        // payload size
                          data->deviceArray[deviceIndex].libnetLinkFrame,
                          0);
    if (t == -1)
    {
        sprintf(errString,
           "libnet error: %s",
           libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }
    else
    {
        // Pass IP header data based on the original packet
        t = libnet_build_ipv6(0, // traffic class
                              0, //flow level
                              payloadSize,
                              IPPROTO_ICMPV6,
                              ND_DEFAULT_HOPLIM,
                              src,
                              dst,
                              NULL, // payload (already passed)
                              0,    // payload size (already passed)
                              data->deviceArray[deviceIndex].libnetLinkFrame,
                              0);
        if (t == -1)
        {
            sprintf(errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
            ERROR_ReportWarning(errString);
        }
        else
        {
            // Build the ethernet header
            t = libnet_build_ethernet(
                macAddr,
                (UInt8*)(data->deviceArray[deviceIndex].macAddress),
                ETYPE_IPV6,
                0,
                0,
                data->deviceArray[deviceIndex].libnetLinkFrame,
                0);

            if (t == -1)
            {
                sprintf(
                    errString,
                    "libnet error: %s",
                    libnet_geterror(
                           data->deviceArray[deviceIndex].libnetLinkFrame));
                ERROR_ReportWarning(errString);
            }
            else
            {
                // Send the packet to the physical network
                err =libnet_write(
                            data->deviceArray[deviceIndex].libnetLinkFrame);
                if (err == -1)
                {
                    ERROR_ReportWarning(
                                    "Error while writing NDP population\n");
                }
            }
        }
    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}
#endif

bool DetermineOperationHostMACAddress(
    AutoIPNEData *data,
    int address,
    char *macAddress,
    int *macAddressSize,
    int deviceIndex)
{
#ifdef _WIN32
    ULONG size = 6;
    if (SendARP(address, INADDR_ANY, (PULONG)macAddress, &size) != NO_ERROR)
    {
        //char msg[MAX_STRING_LENGTH];
        //sprintf(msg, "Cannot find MAC address of the operational node %x", htonl(address));
        //ERROR_ReportWarning(msg);
        return false;
    }

    *macAddressSize = (int)size;
     return true;
#else
#ifdef __APPLE__
    ERROR_ReportError("MAC OSX is not supported.");
#else
    int err;
    int s;
    struct arpreq arpr;
    struct sockaddr_in* sin = (struct sockaddr_in*) &arpr.arp_pa;
    int retryCount;

    //create ICMP packet to make sure
    //the IP of the operational node is in ARP table
    PopulateARPTable(data, address, deviceIndex);

    // Get the socket for this device
    s = pcap_fileno(data->deviceArray[deviceIndex].pcapFrame);

    retryCount = 0;
    // Try upto retryCount times to look for the ARP entry
    while (retryCount < 3)
    {
        memset(&arpr, 0, sizeof(arpr));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = address;

        arpr.arp_ha.sa_family = 1;
        strcpy(arpr.arp_dev, data->deviceArray[deviceIndex].device);
        arpr.arp_flags = ATF_PUBL;

        // Get the arp information
        err = ioctl(s, SIOCGARP, (caddr_t)&arpr);
        if ((err == 0) && (memcmp(arpr.arp_ha.sa_data, "\0\0\0\0\0\0", 6)))
        {
            *macAddressSize = 6;
            memcpy(macAddress, arpr.arp_ha.sa_data, *macAddressSize);
            return true;
        }

        if (err != 0)
        {
            ERROR_ReportWarning("Error calling ioctl on device");
            return false;
        }

        EXTERNAL_Sleep((clocktype)(0.1 * SECOND));
        retryCount++;
    }

    //char buf[MAX_STRING_LENGTH];
    //sprintf(buf, "It appears that the device %s is not connected to this machine via the interface '%s'.\n"
    //"Disabling this operational host (traffic will not be received from the operational host).",
    //inet_ntoa(*(struct in_addr *)&address), data->deviceArray[deviceIndex].device);
    //ERROR_ReportWarning(buf);

    macAddress = NULL;
    macAddressSize = 0;
    return false;


#endif // __APPLE__
#endif
}

// API       :: DetermineOperationHostMACAddressIpv6
// PURPOSE   :: This function is used to determine the mac address of
//              IPv6 operational host
// PARAMETERS::
// + data : AutoIPNEData* : Pointer to the AutoIPNEData.
// + v6SrcAddress : ist<AutoIpneV4V6Address>::iterator   : Source address,
// + v6DstAddress : in6_addr  : Destination address (Operationla host's
//                              ipv6 addr)
// + macAddress : Int8*    : Array to store MAC address
// + macAddressSize : Int32* : Size of MAC address
// + deviceIndex : Int32 : device index of source
// RETURN    :: BOOL : True when successfully able to determine MAC addresss
//                     false otherwise
BOOL DetermineOperationHostMACAddressIpv6(
    AutoIPNEData* data,
    in6_addr v6SrcAddress,
    UInt64 scopeId,
    in6_addr v6DstAddress,
    Int8* macAddress,
    Int32* macAddressSize,
    Int32 deviceIndex)
{
#ifdef _WIN32
    if (Product::GetWindowsVersion() >= WINVER_VISTA_ABOVE)
    {
        typedef Int32 (WINAPI* importFunction)(PMIB_IPNET_ROW2,
                                               const SOCKADDR_INET*);
        HINSTANCE hDLL = LoadLibrary(TEXT("Iphlpapi.dll"));  // Handle to DLL
        importFunction GetMacAddrFunc;
        if (hDLL != NULL)
        {
            GetMacAddrFunc = (importFunction)GetProcAddress(
                                                      hDLL,
                                                      "ResolveIpNetEntry2");
            if (!GetMacAddrFunc)
            {
                ERROR_ReportError("ResolveIpNetEntry2 failed.");
                return FALSE;
            }
        }
        else
        {
            ERROR_ReportError("Error in dll loading.");
            return FALSE;
        }

        MIB_IPNET_ROW2 row2;
        memset(&row2, 0, sizeof(MIB_IPNET_ROW2));

        row2.Address.Ipv6.sin6_addr = v6DstAddress;
        row2.Address.Ipv6.sin6_family = AF_INET6;
        row2.Address.Ipv6.sin6_scope_id = scopeId;

        SOCKADDR_INET srcAddr;
        memset(&srcAddr,0,sizeof(SOCKADDR_INET));
        srcAddr.si_family = AF_INET6;
        srcAddr.Ipv6.sin6_addr = v6SrcAddress;
        srcAddr.Ipv6.sin6_scope_id = scopeId;

        UInt32 result = GetMacAddrFunc((PMIB_IPNET_ROW2)&row2, &srcAddr);
        if (result != NO_ERROR)
        {
            return FALSE;
        }

        *macAddressSize = (Int32)row2.PhysicalAddressLength;
        memcpy(macAddress, row2.PhysicalAddress, *macAddressSize);
        FreeLibrary(hDLL);
        return TRUE;
    }
    else
    {
        return FALSE;
    }
#else
#ifdef __APPLE__
    ERROR_ReportError("MAC OSX is not supported.");
    return false;
#else
    int err;
    int retryCount = 0;
    int ndp_sock;
    int error,addrlen,ifIndex,pkt_length,len;
    struct sockaddr_in6 srcAddr,dstAddr,dstMulticastAddr;
    struct nd_neighbor_advert* na = NULL;
    struct ifreq ifr;
    char src[MAX_STRING_LENGTH], dst[MAX_STRING_LENGTH];
    char* packet = NULL;
    clocktype initTime, endTime, duration;

    pkt_length = sizeof(struct nd_neighbor_advert)
                 + 2 * sizeof(char) // for opt_type and opt_len
                 + ETHER_ADDR_LEN; // target MAC address
    packet = (char*)MEM_malloc(pkt_length);
    memset(packet, 0, pkt_length);
    // create socket for NS packet
    if ((ndp_sock = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
    {
        ERROR_ReportError("Error in socket creation.");
        return FALSE;
    }

    memset(&ifr, 0, sizeof (ifr));
    memcpy(&ifr.ifr_name,
           data->deviceArray[deviceIndex].device,
           sizeof(ifr.ifr_name));
    if (setsockopt(ndp_sock,
                   SOL_SOCKET,
                   SO_BINDTODEVICE,
                   (void*)&ifr,
                   sizeof(ifr)) < 0)
    {
        ERROR_ReportError("SO_BINDTODEVICE failed");
        return false;
    }

    na = (struct nd_neighbor_advert*) packet;

    //put socket in non blocking mode
    if (fcntl(ndp_sock, F_SETFL, O_NONBLOCK) < 0 )
    {
        ERROR_ReportError("\nnon blocking failed");
        return false;
    }

    retryCount = 0;
    bool found = false;

    initTime = EXTERNAL_QueryRealTime();

    while ((na->nd_na_hdr.icmp6_type != ND_NEIGHBOR_ADVERT)
            || (memcmp(&na->nd_na_target,&v6DstAddress,sizeof(in6_addr))))
    {
        if (retryCount < 2)
        {
            PopulateNDPTable(data,
                             v6SrcAddress,
                             v6DstAddress,
                             deviceIndex);
             retryCount++;
        }
        // receive Neighbor advertisement packet on socket
        recv(ndp_sock, packet, pkt_length, 0);
        duration = EXTERNAL_QueryRealTime() - initTime;

        if ((duration) > (.3 * SECOND))
        {
            macAddress = NULL;
            macAddressSize = 0;
            return false;
        }
    }
    // retreive mac address from received packet from operational host
    unsigned char* pkt = (unsigned char*)packet;
    *macAddressSize = ETHER_ADDR_LEN;
    memcpy(macAddress,
          (Int8*)pkt + sizeof(struct nd_neighbor_advert) + 2 * sizeof(char),
          ETHER_ADDR_LEN);
    return true;
#endif
#endif
}

void AutoIPNERecompileCaptureFilter(
    AutoIPNEData *data,
    int deviceIndex)
{
    int err, size, dev;
    char errString[MAX_STRING_LENGTH];
    char pcapError[PCAP_ERRBUF_SIZE];
    char filterString[FILTER_STRING_LENGTH];
    struct bpf_program filter;
    bpf_u_int32 net;
    bpf_u_int32 mask;
    AutoIPNE_NodeMapping *mapping;

    for (dev = 0; dev < data->numDevices; dev++)
    {
        if (deviceIndex != -1) /* we are looking for one device only */
        {
            if (dev != deviceIndex)
                continue;
        }

        if (data->deviceArray[dev].disabled)
            continue;

        mapping = data->deviceArray[dev].mappingsList;

        if (mapping == NULL)
        {
            sprintf(filterString, "(ether proto 100)");
        }
        else
        {
            sprintf(filterString, "(ether src %s)", mapping->macAddressString);
            size = strlen(filterString);
            mapping = mapping->next;

            while (mapping != NULL)
            {
                sprintf(&filterString[size], " or (ether src %s)", mapping->macAddressString);
                size = strlen(filterString);
                if (size >= FILTER_STRING_LENGTH)
                {
                    ERROR_ReportError("Buffer overflow in creating filter string for pcap");
                }

                mapping = mapping->next;
            }
        }

        // look up net
        err = pcap_lookupnet(
                data->deviceArray[dev].device,
                &net,
                &mask,
                pcapError);

        #ifndef _WIN32
        if (strcmp(data->deviceArray[dev].device,"exata")!=0)
        {
        #endif
        if (err)
        {
            #ifndef _WIN32
            if (strcmp(data->deviceArray[dev].device,"exata")==0)
            #endif
            sprintf(errString, "\npcap_lookupnet : %s\n", pcapError);
            ERROR_ReportWarning(errString);

            pcap_close(data->deviceArray[dev].pcapFrame);
            data->deviceArray[dev].disabled = TRUE;
            continue;
        }
       #ifndef _WIN32
       }
       #endif

#if defined(INTERFACE_JNE_C2ADAPTER)
        {
        std::string substring1 = filterString;
        std::string substring2 = JNE::C2Adapter::subfilter(data->partitionData);

        std::string real_filter = "( "
          + substring1
          + " ) or ( " + substring2 + " )";

        if (substring2.size() > 0)
        {
          sprintf(filterString, "%s", real_filter.c_str());
        }
        }
#endif /* INTERFACE_JNE_C2ADAPTER */

#if defined(INTERFACE_JNE_C3)
        {
        std::string substring1 = filterString;
        std::string substring2 = JNE::C3::subfilter(data->partitionData);

        std::string real_filter = "( "
          + substring1
          + " ) or ( " + substring2 + " )";

        if (substring2.size() > 0)
        {
          sprintf(filterString, "%s", real_filter.c_str());
        }
        }
#endif /* INTERFACE_JNE_C3 */

#if defined(INTERFACE_JNE_JREAP)
        {
        std::string substring1 = filterString;
        std::string substring2 = JNE::JREAP::subfilter(data->partitionData);

        std::string real_filter = "( "
          + substring1
          + " ) or ( " + substring2 + " )";

        sprintf(filterString, "%s", real_filter.c_str());
        }
#endif /* INTERFACE_JNE_JREAP */

        // Compile the filter
        err = pcap_compile(
                data->deviceArray[dev].pcapFrame,
                &filter,
                filterString,
                0,
                net);

        if (err)
        {
            sprintf(
                    errString,
                    "\npcap_compile : %s\n",
                    pcap_geterr(data->deviceArray[dev].pcapFrame));
            ERROR_ReportWarning(errString);

            pcap_close(data->deviceArray[dev].pcapFrame);
            data->deviceArray[dev].disabled = TRUE;
            continue;
        }

        // Set the filter
        err = pcap_setfilter(data->deviceArray[dev].pcapFrame, &filter);
        if (err)
        {
            sprintf(
                    errString,
                    "\npcap_setfilter : %s\n",
                    pcap_geterr(data->deviceArray[dev].pcapFrame));
            ERROR_ReportWarning(errString);

            pcap_close(data->deviceArray[dev].pcapFrame);
            data->deviceArray[dev].disabled = TRUE;
            continue;
        }

        if (data->debug)
        {
            printf("NEW Filter = %s for device index %d\n", filterString, dev);
            fflush(stdout);
        }
    }
}
