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

#define _NETINET_IN_H_
#include "api.h"
#include "internetgateway.h"
#include "gateway_osutils.h"
#include "gateway_interface.h"
#include "qualnet_upa.h"
#include "ipv6.h"

void Ipv6gatewayInterfaceCreateFilterString(
    GatewayData* gwData,
    Int8* filterString)
{
    Int8 addr1[50];
    Address interfaceAddress;
    SetIPv6AddressInfo(&interfaceAddress,
        gwData->defaultIpv6InterfaceAddress);
    IO_ConvertIpAddressToString(&interfaceAddress, addr1);
    sprintf(filterString,
        "ip6 and (dst %s) and (not dst port %d) and "
        "(not dst port %d) and (not dst port %d) and (not dst port %d) "
        "and (not dst port %d)",
        addr1,
        UPA_CONTROL_PORT,
        UPA_DATA_PORT,
        UPA_CONTROL_PORT_IPV6,
        UPA_DATA_PORT_IPV6,
        UPA_MULTICAST_PORT_IPV6);
}

void GatewayInterfaceCreateFilterString(
    GatewayData *gwData,
    Int8* filterString)
{
    sprintf(filterString, "ip and (dst %d.%d.%d.%d) and (not dst port %d) "
        "and (not dst port %d) and (not dst port %d) and (not dst port %d) "
        "and (not dst port %d)",
        (gwData->defaultInterfaceAddress >> 24) & 0xFF,
        (gwData->defaultInterfaceAddress >> 16) & 0xFF,
        (gwData->defaultInterfaceAddress >> 8) & 0xFF,
        gwData->defaultInterfaceAddress & 0xFF,
        UPA_CONTROL_PORT,
        UPA_DATA_PORT,
        UPA_CONTROL_PORT_IPV6,
        UPA_DATA_PORT_IPV6,
        UPA_MULTICAST_PORT_IPV6);
}

void GatewayInterfaceUpdateFilters(
    GatewayData* gwData)
{
    pcap_t* handle = NULL;
    struct bpf_program fp;
    Int8 filterString[MAX_STRING_LENGTH];

    handle = (pcap_t *)gwData->pcapHandle;

    GatewayInterfaceCreateFilterString(gwData, &filterString[0]);
    printf("FILTER %s\n", filterString);

    if (pcap_compile(handle, &fp, filterString, 0,
        gwData->subnetAddress) == -1)
    {
        printf("Error: pcap_compile())\n");
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error: pcap_setfilter\n");
        return;
    }
}

BOOL GatewayInterfaceIpv6Initialize(
    GatewayData* gwData)
{
    Int8 errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    struct bpf_program fp;
    Int32 err = 0;
    Int8 filterString[MAX_STRING_LENGTH];

    // Initialize the pcap interface
    if (pcap_lookupnet(gwData->defaultIpv6InterfaceName,
                &gwData->subnetAddress,
                &gwData->subnetMask,
                errbuf) == -1)
    {
        printf("Cannot look up the netmask for the device [%s]: %s\n",
                gwData->defaultIpv6InterfaceName, errbuf);
        return FALSE;
    }

    handle = pcap_open_live(gwData->defaultIpv6InterfaceName,
                    2048,
                    1,
#ifdef __APPLE__
                    1,
#else
                    -1,
#endif
                    errbuf);
    
    if (handle == NULL)
    {
        printf("Cannot open device [%s] for capturing packets: %s\n",
                gwData->defaultIpv6InterfaceName, errbuf);
        return FALSE;
    }

    err = pcap_setnonblock(
                handle,
                TRUE,
                errbuf);

    if (err)
    {
        printf("Cannot set the capture device [%s] in non blocking "
            "mode: %s\n",
            gwData->defaultIpv6InterfaceName, errbuf);
        return FALSE;
    }

    Ipv6gatewayInterfaceCreateFilterString(gwData, &filterString[0]);

    if (pcap_compile(handle, &fp, filterString, 0,
        gwData->subnetAddress) == -1)
    {
        printf("Error: pcap_compile()): %s\n", pcap_geterr(handle));
        return FALSE;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error: pcap_setfilter\n");
        return FALSE;
    }

    gwData->ipv6PcapHandle = (void *)handle;

    // Initialize the libnet interface
    char libnetError[LIBNET_ERRBUF_SIZE];

#ifdef _WIN32
    gwData->ipv6LibnetHandle = (void *)libnet_init(LIBNET_LINK,
                                        gwData->defaultIpv6InterfaceName,
                                        libnetError);
#else
    gwData->ipv6LibnetHandle = (void *)libnet_init(LIBNET_RAW6,
                                        gwData->defaultIpv6InterfaceName,
                                        libnetError);
#endif

    if (gwData->ipv6LibnetHandle == NULL)
    {
        printf("Error: %s\n", libnetError);
        ERROR_ReportError("Cannot intialize libnet\n");
    }

    return TRUE;
}


BOOL GatewayInterfaceInitialize(
    GatewayData* gwData)
{
    Int8 errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    struct bpf_program fp;
    Int32 err = 0;
    Int8 filterString[MAX_STRING_LENGTH];

    // Initialize the pcap interface
    if (pcap_lookupnet(gwData->defaultInterfaceName,
                &gwData->subnetAddress, 
                &gwData->subnetMask, 
                errbuf) == -1)
    {
        printf("Cannot look up the netmask for the device [%s]: %s\n",
                gwData->defaultInterfaceName, errbuf);
        return FALSE;
    }


    handle = pcap_open_live(gwData->defaultInterfaceName,
                    2048,
                    1,
#ifdef __APPLE__
                    1,
#else
                    -1,
#endif
                    errbuf);
    
    if (handle == NULL)
    {
        printf("Cannot open device [%s] for capturing packets: %s\n",
                gwData->defaultInterfaceName, errbuf);
        return FALSE;
    }


    err = pcap_setnonblock(
                handle,
                TRUE,
                errbuf);

    if (err)
    {
        printf("Cannot set the capture device [%s] in non blocking "
            "mode: %s\n",
            gwData->defaultInterfaceName, errbuf);
        return FALSE;
    }

    GatewayInterfaceCreateFilterString(gwData, &filterString[0]);

    if (pcap_compile(handle, &fp, filterString, 0,
        gwData->subnetAddress) == -1)
    {
        printf("Error: pcap_compile())\n");
        return FALSE;
    }

    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Error: pcap_setfilter\n");
        return FALSE;
    }

    gwData->pcapHandle = (void *)handle;

    // Initialize the libnet interface
    Int8 libnetError[LIBNET_ERRBUF_SIZE];

#ifdef _WIN32
    gwData->libnetHandle = (void *)libnet_init(LIBNET_LINK,
                                        gwData->defaultInterfaceName,
                                        libnetError);
#else
    gwData->libnetHandle = (void *)libnet_init(LIBNET_RAW4,
                                        gwData->defaultInterfaceName,
                                        libnetError);
#endif
    
    if (gwData->libnetHandle == NULL)
    {
        printf("Error: %s\n", libnetError);
        ERROR_ReportError("Cannot intialize libnet\n");
    }

    return TRUE;
}


Int8* Ipv6GatewayInterfaceCapturePacket(
    GatewayData* gwData,
    Int32* packetSize)
{
    struct pcap_pkthdr header;
    Int8* packet = NULL;

    if (gwData->ipv6PcapHandle)
    {
        packet =
            (Int8 *)pcap_next((pcap_t *)gwData->ipv6PcapHandle, &header);
    }

    if (packet == NULL)
    {
        return NULL;
    }
    *packetSize = header.len;
    return packet;
}

Int8* GatewayInterfaceCapturePacket(
    GatewayData* gwData,
    Int32* packetSize)
{
    struct pcap_pkthdr header;
    Int8* packet = NULL;

    if (gwData->pcapHandle)
    {
        packet = (Int8 *)pcap_next((pcap_t *)gwData->pcapHandle, &header);
    }

    if (packet == NULL)
    {
        return NULL;
    }
    *packetSize = header.len;
    return packet;
}

Int32 Ipv6GatewayInterfaceWritePacket(
    GatewayData* gwData,
    UInt8* packet,
    Int32 packetSize)
{
    libnet_t* handle = (libnet_t*)gwData->ipv6LibnetHandle;
    struct ip6_hdr_struct* ipv6Header = (struct ip6_hdr_struct*)packet;
    struct libnet_ipv6_hdr* ipHeader = (struct libnet_ipv6_hdr*)packet;
    Int32 ipv6HeaderLen = 40;
    libnet_ptag_t tag;
    Int32 err = 0;

    tag = libnet_build_data(
            packet + ipv6HeaderLen,
            packetSize - ipv6HeaderLen,
            handle,
            0);

    tag = libnet_build_ipv6(
        ip6_hdrGetClass(ipv6Header->ipv6HdrVcf), // traffic class
        ip6_hdrGetFlow(ipv6Header->ipv6HdrVcf), //
        packetSize - ipv6HeaderLen,
        ipv6Header->ipv6_nhdr,
        ipv6Header->ipv6_hlim,
        ipHeader->ip_src,
        ipHeader->ip_dst,
        NULL, // payload (already passed)
        0,    // payload size (already passed)
        handle,
        0);

    if (tag == -1)
    {
        printf("Problem in creating libnet IP frame\n");
    }

#ifdef _WIN32
    tag = libnet_autobuild_ethernet(
            (u_int8_t *)&gwData->ipv6InternetRouterMacAddress[0],
            0x86dd,
            handle);

    if (tag == -1)
    {
        printf("Problem in creating libnet link frame\n");
    }
#endif

    err = libnet_write(handle);
    if (err == -1)
    {
        printf("Problem in writing libnet frame\n");
    }

    libnet_clear_packet(handle);
    return 0;
}

Int32 GatewayInterfaceWritePacket(
    GatewayData* gwData,
    UInt8* packet,
    Int32 packetSize)
{
    libnet_t* handle = (libnet_t *)gwData->libnetHandle;
    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr *)packet;
    Int32 ipHeaderLen = ip->ip_hl * 4;
    libnet_ptag_t tag;
    Int32 err = 0;

    tag = libnet_build_data(
            packet + ipHeaderLen,
            packetSize - ipHeaderLen,
            handle,
            0);

    tag = libnet_build_ipv4(
            packetSize,         // Length
            ip->ip_tos,            // tos
            ntohs(ip->ip_id),
            ntohs(ip->ip_off),
            ip->ip_ttl,
            ip->ip_p,
            0,
#ifdef _WIN32
            ip->ip_src.S_un.S_addr,
            ip->ip_dst.S_un.S_addr,
#else
            ip->ip_src.s_addr,
            ip->ip_dst.s_addr,
#endif
            NULL,
            0,
            handle,
            0);

    if (tag == -1)
    {
        printf("Problem in creating libnet IP frame\n");
    }

#ifdef _WIN32
    tag = libnet_autobuild_ethernet(
               (u_int8_t *)&gwData->internetRouterMacAddress[0],
                ETHERTYPE_IP,
                handle);
    
    if (tag == -1)
    {
        printf("Problem in creating libnet link frame\n");
    }
#endif


    err = libnet_write(handle);
    if (err == -1)
    {
        printf("Problem in writing libnet frame\n");
    }

    libnet_clear_packet(handle);

    return 0;
}

