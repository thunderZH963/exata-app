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

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_util.h"
#include "external_socket.h"
#include "ipnetworkemulator.h"
#include "network_ip.h"
#include "app_forward.h"

#include "udp_interface.h"
#include "voip_interface.h"
#include "arp_interface.h"
#include "ospf_interface.h"
#include "tcp_interface.h"
//Start OLSR interface
#include "olsr_interface.h"
//End OLSR interface

//---------------------------------------------------------------------------
// Static Functions
//---------------------------------------------------------------------------
/*
 * FUNCTION:   BytesSwapHton
 * PURPOSE:    Swap the bytes of IP and UDP in ICMP message. This function is
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
    ipHeader = (IpHeaderType *) msg;

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
        &ipHeader->ip_src,
        sizeof(ipHeader->ip_src));
    EXTERNAL_hton(
        &ipHeader->ip_dst,
        sizeof(ipHeader->ip_dst));

    //  Swap bytes for UDP header
    TransportUdpHeader *header;
    // Extract UDP  header
    header = (TransportUdpHeader*)(msg+20);

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


// /**
// API       :: isBroadcast
// PURPOSE   :: This function determines if address is broadcast
// PARAMETERS::
// + addr : unsigned int :address to check
// + len  : int : length to check
// RETURN    :: void
// **/

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

// /**
// API       :: DetermineMacAddress
// PURPOSE   :: This function determines the device's MAC address from
//              its device index
// PARAMETERS::
// + data : IPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// + macAddress  : char * : 6 byte char array to store MAC address (output)
// RETURN    :: void
// **/
static void DetermineMacAddress(
    IPNEData* data,
    int deviceIndex,
    char* macAddress)
{
#ifdef __APPLE__
    char errbuf[PCAP_ERRBUF_SIZE];
    char errString[MAX_STRING_LENGTH];
    int deviceChoice;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    struct sockaddr* addr;
    int i;

    // Get a list of all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        sprintf(errString,"Error in pcap_findalldevs: %s\n", errbuf);
        ERROR_ReportError(errString);
    }
    if (alldevs == NULL)
    {
        ERROR_ReportError("pcap_findalldevs returned nothing");
    }

    char* device = data->deviceArray[deviceIndex].device;
#ifdef DEBUG
    printf("getting MAC address for device %s\n", device);
#endif

    // Advance to the selected device
    d = alldevs;
    while (d != NULL)
    {
        if (d->addresses->addr->sa_family == 18) // AF_LINK
        {
            char* addr = (char*) d->addresses->addr;
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

                return;
            }
        }

        d = d->next;
    }

    sprintf(errString, "Could not find MAC address for device %s", device);
    ERROR_ReportError(errString);

#else
#ifdef _WIN32  // windows
    IP_ADAPTER_INFO adapter;
    PIP_ADAPTER_INFO adapterPtr;

    // Call GetAdaptersInfo once to get the buffer size.  After calling this
    // function, len will be the length of the buffer.
    DWORD len = sizeof(adapter);
    DWORD err = GetAdaptersInfo(
        &adapter,
        &len);
    if (err != ERROR_BUFFER_OVERFLOW && err != ERROR_SUCCESS)
    {
        ERROR_ReportError("Error getting length of adapter buffer");
    }

    // Allocate enough memory for all adapters
    adapterPtr = (PIP_ADAPTER_INFO) MEM_malloc(len);

    // Now get all of the adapters
    err  = GetAdaptersInfo(
        adapterPtr,
        &len);
    if (err != ERROR_SUCCESS)
    {
        ERROR_ReportError("Error getting adapters");
    }

    // Loop over all adapters.  Check if the adapter name matches the device
    // name.
    PIP_ADAPTER_INFO pAdapterInfo = adapterPtr;
    while (pAdapterInfo != NULL
           && (strstr(data->deviceArray[deviceIndex].device,
                          pAdapterInfo->AdapterName) == NULL))
    {
        pAdapterInfo = pAdapterInfo->Next;
    }

    // Verify that an adapter was found
    if (pAdapterInfo == NULL)
    {
        ERROR_ReportError("Adapter not found");
    }

    // Verify the address is the right size
    if (pAdapterInfo->AddressLength != ETHER_ADDR_LEN)
    {
        ERROR_ReportError("MAC address is not 6 bytes");
    }

    // Copy the address
    UInt8* u = (UInt8*) pAdapterInfo->Address;
    memcpy(macAddress, u, ETHER_ADDR_LEN);
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
        ERROR_ReportError("Error calling ioctl on device");
    }

    // Copy the address
    memcpy(macAddress, u, ETHER_ADDR_LEN);
#endif // unix/linux
#endif // __APPLE__ not defined
}

// /**
// API       :: DetermineMacAddressString
// PURPOSE   :: This function determines the device's MAC address
//              in a string format from its device index
// PARAMETERS::
// + data : IPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// + macAddressString  : char * : 18 byte char array to store MAC address
//                                string (output)
// RETURN    :: void
// **/
static void DetermineMacAddressString(
    IPNEData* data,
    int deviceIndex,
    char* macAddressString)
{
    char macAddress[ETHER_ADDR_LEN];

    // Call DetermineMacAddress and print to string
    DetermineMacAddress(data, deviceIndex, macAddress);
    sprintf(
        macAddressString,
        "%02x:%02x:%02x:%02x:%02x:%02x",
        (UInt8) macAddress[0],
        (UInt8) macAddress[1],
        (UInt8) macAddress[2],
        (UInt8) macAddress[3],
        (UInt8) macAddress[4],
        (UInt8) macAddress[5]);
}

// /**
// API       :: DetermineIpAddressString
// PURPOSE   :: This function determines the device's IP address
//              in a string format from its device index
// PARAMETERS::
// + data : IPNEData* : Pointer to IPNetworkEmulator data structure
// + deviceIndex : int : index of device
// + ipAddressString  : char * : 16 byte char array to store IP address
//                                string (output)
// RETURN    :: void
// **/
static void DetermineIpAddressString(
    IPNEData* data,
    int deviceIndex,
    char* ipAddressString)
{

#ifndef _WIN32 // unix/linux
    int err;
    int s;
    struct ifreq ifr;
    struct sockaddr_in*sin = (struct sockaddr_in*) &ifr.ifr_addr;
//    UInt8* u = (UInt8*) ifr.ifr_addr.sa_data;

    // Get the socket for this device
    s = pcap_fileno(data->deviceArray[deviceIndex].pcapFrame);

    // Set the ifr struct to retrieve the mac address of the device name
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, data->deviceArray[deviceIndex].device);
    sin->sin_family = AF_INET;

    // Get the interface information
    err = ioctl(s, SIOCGIFADDR, &ifr);
    if (err != 0)
    {
        ERROR_ReportError("Error calling ioctl on device");
    }

    sin = (sockaddr_in *)&ifr.ifr_addr;
    sprintf(ipAddressString, "%s",inet_ntoa(sin->sin_addr));
#else //windows
    IP_ADAPTER_INFO adapter;
    PIP_ADAPTER_INFO adapterPtr;

    // Call GetAdaptersInfo once to get the buffer size.  After calling this
    // function, len will be the length of the buffer.
    DWORD len = sizeof(adapter);
    DWORD err = GetAdaptersInfo(
        &adapter,
        &len);
    if (err != ERROR_BUFFER_OVERFLOW && err != ERROR_SUCCESS)
    {
        ERROR_ReportError("Error getting length of adapter buffer");
    }

    // Allocate enough memory for all adapters
    adapterPtr = (PIP_ADAPTER_INFO) MEM_malloc(len);

    // Now get all of the adapters
    err  = GetAdaptersInfo(
        adapterPtr,
        &len);
    if (err != ERROR_SUCCESS)
    {
        ERROR_ReportError("Error getting adapters");
    }

    // Loop over all adapters.  Check if the adapter name matches the device
    // name.
    PIP_ADAPTER_INFO pAdapterInfo = adapterPtr;
    while (pAdapterInfo != NULL
           && (strstr(data->deviceArray[deviceIndex].device, pAdapterInfo->AdapterName) == NULL))
    {
        pAdapterInfo = pAdapterInfo->Next;
    }

    // Verify that an adapter was found
    if (pAdapterInfo == NULL)
    {
        ERROR_ReportError("Adapter not found");
    }

#endif

}

// /**
// API       :: StringToAddress
// PURPOSE   :: This function converts an IP Address specified in
//              a string format to a NodeAddress
// PARAMETERS::
// + string : char * : Pointer to the string
// + address : NodeAddress * : Pointer to the NodeAddress struct
//                             where the address will be stored (otuput)
// RETURN    :: void
// **/
void StringToAddress(char* string, NodeAddress* address)
{
    char error[MAX_STRING_LENGTH];

#ifdef _WIN32 // windows
    // Convert to string using inet_addr
    // NOTE: won't work for 255.255.255.255
    
    *address = inet_addr(string);
        
    if (*address == INADDR_NONE)
    {
            sprintf(error, "Error calling inet_addr for \"%s\"", string);
        ERROR_ReportError(error);
    }
    
#else // unix/linux
    int err;
    // Convert to string using inet_aton
    err = inet_aton(string, (in_addr*) address);
    if (err == 0)
    {
        sprintf(error, "Error calling inet_aton for \"%s\"", string);
        ERROR_ReportError(error);
    }
#endif
}

// /**
// API       :: StringToWideString
// PURPOSE   :: This function will convert a string with 1 byte characters
//              to a string with 2 byte characters.
// PARAMETERS::
// + string : char* : The string with 1 byte characters
// + wideString : char* : The output string with 2 byte characters (output)
// RETURN    :: void
// **/
static void StringToWideString(char* string, char* wideString)
{
    int len = strlen(string) + 1;
    int i;
    char* ch;

    // Loop through all characters, copying them to wideString
    ch = wideString;
    for (i = 0; i < len; i++)
    {
        *ch++ = 0;
        *ch++ = string[i];
    }
}

// /**
// API       :: CreateFilterNatYes
// PURPOSE   :: This function will create a libpcap filter for use in
//              Nat-Yes mode
// PARAMETERS::
// + data : IPNEData* : Pointer to the IPNE data
// + deviceIndex : int : Which device in the IPNE data to use
// + numCorrespondences : int : The number of correspondences
// + qualnetAddresses : char** : The qualnet addresses, an array of strings
//                               one for each correspondence
// + realAddresses : char** : The real addresses, an array of strings
//                            one for each correspondence
// + multicastTransmitAddresses : char** : Array of multicast address
//                                         strings for multicast sniffing
// RETURN    :: Pointer to the filter.  Memory must be freed after calling.
// **/
static char* CreateFilterNatYes(
    IPNEData* data,
    int deviceIndex,
    int numCorrespondences,
    char** qualnetAddresses,
    char** realAddresses,
    char **multicastReceiveRealAddresses)
{
    char* filterString;
    unsigned int filterLength;
    int i;

    // It will look something like:
    //     ((ether dst 00:11:43:29:da:b7 and ether proto \ip) and
    //      (dst 192.168.0.92 or dst 192.168.0.94) and
    //      (src 192.168.0.92 or src 192.168.0.94))
    //
    // The maximum length is computed as follows:  (Note that each
    // correspondence has 2 ip addresses: One real, one qualnet)
    //     length "((ether dst 00:11:43:29:da:b7 and ether proto \ip) and " = 55
    //     length "src xxx.xxx.xxx.xxx" * 2 * num = 38 * num
    //     length " or " * 2 * (num - 1) = 8 * (num - 1)
    //     length "(" + ") and (" + "))" + 0 = 11
    //     total = 66 + 38 * num + 8 * (num - 1) = 96 + 46 * num
    //    + 10 * num ( for multicast)
    filterLength = 96 + 66 * numCorrespondences;
    filterString = (char*) MEM_malloc(filterLength * sizeof(char));

    sprintf(
        filterString,
        "((ether dst %s and ether proto \\ip) and "
        "(dst ",
        data->deviceArray[deviceIndex].macAddress);
    strcat(filterString, qualnetAddresses[0]);
    for (i = 1; i < numCorrespondences; i++)
    {
        strcat(filterString, " or dst ");
        strcat(filterString, qualnetAddresses[i]);
        strcat(filterString, "");
    }

    strcat(filterString, ") and (");

    strcat(filterString, "src ");
    strcat(filterString, realAddresses[0]);
    for (i = 1; i < numCorrespondences; i++)
    {
        strcat(filterString, " or src ");
        strcat(filterString, realAddresses[i]);
    }

    strcat(filterString, ")");

    //Add in multicast address here..SRD
    if (data->multicastEnabled)
    {
       strcat(filterString, " or (dst ");
       //and dst as mcast qualnet address
       strcat(filterString, multicastReceiveRealAddresses[0]);
       strcat(filterString, " and src ");
       strcat(filterString, realAddresses[0]);
       strcat(filterString, ")");

       for (i = 1; i < numCorrespondences; i++)
       {
          strcat(filterString, " or (dst ");
          //and dst as mcast qualnet address
          strcat(filterString, multicastReceiveRealAddresses[i]);
       strcat(filterString, " and src ");
       strcat(filterString, realAddresses[i]);
          strcat(filterString, ")");
       }

    }

    strcat(filterString, ")");


    if (strlen(filterString) + 1 > filterLength)
    {
        ERROR_ReportError("NatYes filter is too long");
    }

    return filterString;
}

// /**
// API       :: CreateFilterNatNo
// PURPOSE   :: This function will create a libpcap filter for use in
//              Nat-Yes mode
// PARAMETERS::
// + data : IPNEData* : Pointer to the IPNE data
// + deviceIndex : int : Which device in the IPNE data to use
// + numCorrespondences : int : The number of correspondences
// + realAddresses : char** : The real addresses, an array of strings
//                            one for each correspondence
// RETURN    :: Pointer to the filter.  Memory must be freed after calling.
// **/
static char* CreateFilterNatNo(
    IPNEData* data,
    int deviceIndex,
    int numCorrespondences,
    char** realAddresses)
{
    char* filterString;
    unsigned int filterLength;
    int i;

    // It will look something like:
    //     ((ether dst 00:11:43:29:da:b7 and ether proto \ip) and
    //      (dst 192.168.0.92 or dst 192.168.0.94) and
    //      (src 192.168.0.92 or src 192.168.0.94))
    //
    // The maximum length is computed as follows:  (Note that each
    // correspondence has 2 ip addresses: One real, one qualnet)
    //     length "((ether dst 00:11:43:29:da:b7 and ether proto \ip) and " = 55
    //     length "src xxx.xxx.xxx.xxx" * 2 * num = 38 * num
    //     length " or " * 2 * (num - 1) = 8 * (num - 1)
    //     length "(" + ") and (" + "))" + 0 = 11
    //     total = 66 + 38 * num + 8 * (num - 1) = 96 + 46 * num
    filterLength = 96 + 46 * numCorrespondences;
    filterString = (char*) MEM_malloc(filterLength * sizeof(char));

    sprintf(
        filterString,
        "((ether dst %s and ether proto \\ip) and "
        "(dst ",
        data->deviceArray[deviceIndex].macAddress);
    strcat(filterString, realAddresses[0]);
    for (i = 1; i < numCorrespondences; i++)
    {
        strcat(filterString, " or dst ");
        strcat(filterString, realAddresses[i]);
    }
    strcat(filterString, ") and (src ");

    strcat(filterString, realAddresses[0]);
    for (i = 1; i < numCorrespondences; i++)
    {
        strcat(filterString, " or src ");
        strcat(filterString, realAddresses[i]);

    }
    strcat(filterString, "))");

    if (strlen(filterString) + 1 > filterLength)
    {
        ERROR_ReportError("NatNo filter is too long");
    }

    return filterString;
}

// /**
// API       :: CreateFilterTrueEmulation
// PURPOSE   :: This function will create a libpcap filter for use in
//              True-Emulation mode
// PARAMETERS::
// + data : IPNEData* : Pointer to the IPNE data
// + deviceIndex : int : Which device in the IPNE data to use
// RETURN    :: Pointer to the filter.  Memory must be freed after calling.
// **/
static char* CreateFilterTrueEmulation(
    IPNEData* data,
    int deviceIndex,
    Node * node)
{
    char* filterString;
    char string[MAX_STRING_LENGTH];
    unsigned int filterLength;
    int i;

    // It will look something like:
    //     ((ether dst 00:11:43:29:da:b7 and ether proto \ip) or
    //      (ether proto \arp)
    //
    // The maximum length is 74

    // Due to the next-hop issue, this is modified. 
    // It looks like:
    //     ((ether[0:2] | 0x0000 = 0 and ether proto \ip) or 
    //      (ether proto \arp))
    // The maximum length became 71

    //
    // If ospf is being used there will be an additional
    //     " or (src xxx.xxx.xxx.xxx and (dst 224.0.0.5 or dst 244.0.0.6))"
    // for each node, which is 62 per string
    // 
    // If olsr is being used there will be an additional
    //     " or (src xxx.xxx.xxx.xxx and dst 255.255.255.255)"
    // for each node, which is 62 per string
    //
    // If rip is being used there will be an additional
    //     " or (src xxx.xxx.xxx.xxx and dst 255.255.255.255)"
    // for each node, which is 62 per string
    //

    if (data->macSpoofingEnabled)
        filterLength = 71;
    else
        filterLength = 74;

    //OSPF interface
    if (data->ospfEnabled)
    {
        filterLength += data->numOspfNodes * 62;
    }

    //OLSR interface
    if (data->olsrEnabled)
    {
        filterLength += data->numOlsrNodes * 50;
    }
     //Start Rip interface
    if (data->ripEnabled)
    {
        filterLength += data->numRipNodes * 50;
    }
    //End Rip interface
    

    filterString = (char*) MEM_malloc(filterLength * sizeof(char));

    if (data->macSpoofingEnabled)
        // filtering expression for MAC address staring with 0x0000 
        sprintf(
            filterString,
            "(( ether[0:2] = 0xaaaa and ether proto \\ip) or "
            "(ether proto \\arp))");
    else
        // filtering expression with QualNet machine MAC address
        sprintf(
            filterString,
            "((ether dst %s and ether proto \\ip) or "
            "(ether proto \\arp))",
            data->deviceArray[deviceIndex].macAddress);

    // Add filter for OSPF multicast packets
    if (data->ospfEnabled)
    {
        for (i = 0; i < data->numOspfNodes; i++)
        {
            sprintf(
                string,
                " or (src %s and (dst 224.0.0.5 or dst 244.0.0.6))",
                data->ospfNodeAddressString[i]);
            strcat(filterString, string);
        }
    }

    //Start OLSR interface
    // Add filter for OLSR broadcast packets
    if (data->olsrEnabled)
    {
        for (i = 0; i < data->numOlsrNodes; i++)
        {
            if (!data->olsrNetDirectedBroadcast)
            {
                sprintf(
                    string,
                    " or (src %s and dst 255.255.255.255)",
                    data->olsrNodeAddressString[i]);
            }
            else
            {
                char tmp[MAX_STRING_LENGTH];
                char pcapError[PCAP_ERRBUF_SIZE];
                unsigned int net;
                unsigned int mask;
                int err;
                char errString[MAX_STRING_LENGTH];
                unsigned int netDirectedBroadcast;
                NodeAddress olsrAddress;

                // Lookup network name/netmask
                err = pcap_lookupnet(
                    data->deviceArray[deviceIndex].device,
                    &net,
                    &mask,
                    pcapError);
                if (err)
                {
                    sprintf(errString, "\npcap_lookupnet : %s\n", pcapError);
                    ERROR_ReportError(errString);
                }
                StringToAddress(data->olsrNodeAddressString[i], &olsrAddress);
                netDirectedBroadcast = ((olsrAddress&mask) | ~mask);

                IO_ConvertIpAddressToString(
                    htonl(netDirectedBroadcast),
                    tmp);

                sprintf(
                    string,
                    " or (src %s and dst %s)",
                    data->olsrNodeAddressString[i], tmp);
                filterLength-= (15-strlen(tmp));
            } 
            strcat(filterString, string);
        }
    }
    //End OLSR interface
   
    //Start Rip interface
    // Add filter for Rip broadcast packets
    if (data->ripEnabled)
    {
        for (i = 0; i < data->numRipNodes; i++)
        {
            sprintf(
                string,
                " or (src %s and dst 255.255.255.255)",
                data->ripNodeAddressString[i]);
            strcat(filterString, string);
        }
    }
    
    //End Rip interface

    // Check that the filter string did not over-run the boundaries
    if (strlen(filterString) + 1 > filterLength)
    {
        ERROR_ReportError("TrueEmulation filter is too long");
    }

    return filterString;
}

// /**
// API       :: InitializeSnifferInjector
// PURPOSE   :: This function will set up the libpcap and libnet libraries
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + numCorrespondences : int : The number of correspondences between real
//                              and qualnet addresses
// + realAddresses : char** : Array of real address strings
// + qualnetAddresses : char** : Array of qualnet address strings
// + multicastTransmitAddresses : char** : Array of multicast address
//                                         strings for multicast sniffing
// + firstNode: Node* : The first node in partion
// RETURN    :: void
// **/
static void InitializeSnifferInjector(
    IPNEData* data,
    int numCorrespondences,
    char** realAddresses,
    char** qualnetAddresses,
    char **multicastReceiveRealAddresses,
    Node * firstNode)
{
    char* filterString;
    int i;
    char errString[MAX_STRING_LENGTH];

    // pcap
    struct bpf_program filter;
    char pcapError[PCAP_ERRBUF_SIZE];
    bpf_u_int32 net;
    bpf_u_int32 mask;
    int err;

    // libnet
    char libnetError[LIBNET_ERRBUF_SIZE];

    // Return if there are no correspondences between real and qualnet nodes
    if (numCorrespondences < 1)
    {
        ERROR_ReportWarning("No IPNE correspondences given!");
        return;
    }

    // Initialize each device for sniffing/injecting
    for (i = 0; i < data->numDevices; i++)
    {
        // Open a pcap physical device
        data->deviceArray[i].pcapFrame = pcap_open_live(
            data->deviceArray[i].device,
            2048,
            1,
#ifdef __APPLE__
            1,
#else
            -1,
#endif
            pcapError);
        if (data->deviceArray[i].pcapFrame == NULL)
        {
            sprintf(
                errString,
                "\nError opening adapter: %s (Make sure QualNet is running "
                "with root access)\n",
                pcapError);
            ERROR_ReportError(errString);
        }

        DetermineMacAddressString(data, i, data->deviceArray[i].macAddress);
        DetermineIpAddressString(data, i, data->deviceArray[i].ipAddress);
        // Set to non-blocking mode
        err = pcap_setnonblock(
            data->deviceArray[i].pcapFrame,
            TRUE,
            pcapError);
        if (err)
        {
            sprintf(errString, "\npcap_setnonblock : %s\n", pcapError);
            ERROR_ReportError(errString);
        }

        // Lookup network name/netmask
        err = pcap_lookupnet(
            data->deviceArray[i].device,
            &net,
            &mask,
            pcapError);
        if (err)
        {
            sprintf(errString, "\npcap_lookupnet : %s\n", pcapError);
            ERROR_ReportError(errString);
        }

        // Create the filter
        if (data->nat)
        {
            filterString = CreateFilterNatYes(
                data,
                i,
                numCorrespondences,
                qualnetAddresses,
                realAddresses,
                multicastReceiveRealAddresses);
        }
        else if (data->trueEmulation)
        {
            filterString = CreateFilterTrueEmulation(
                data,
                i,
                firstNode);
        }
        else
        {
            filterString = CreateFilterNatNo(
                data,
                i,
                numCorrespondences,
                qualnetAddresses);
        }

        if (data->debug)
        {
            printf("filter = \"%s\"\n", filterString);
            fflush(stdout);
        }

        // Compile the filter
        err = pcap_compile(
            data->deviceArray[i].pcapFrame,
            &filter,
            filterString,
            0,
            net);
        if (err)
        {
            sprintf(
                errString,
                "\npcap_compile : %s\n",
                pcap_geterr(data->deviceArray[i].pcapFrame));
            ERROR_ReportError(errString);
        }

        // Set the filter
        err = pcap_setfilter(data->deviceArray[i].pcapFrame, &filter);
        if (err)
        {
            sprintf(
                errString,
                "\npcap_setfilter : %s\n",
                pcap_geterr(data->deviceArray[i].pcapFrame));
            ERROR_ReportError(errString);
        }

        // Free memory for filter string
        MEM_free(filterString);

        // Initialize libnet library for network layer injection
        data->deviceArray[i].libnetFrame = libnet_init(
                LIBNET_RAW4,
                data->deviceArray[i].device,
                libnetError);
        if (data->deviceArray[i].libnetFrame == NULL)
        {
            sprintf(errString, "error in libnet_init: %s", libnetError);
            ERROR_ReportError(errString);
        }

        // Initialize libnet library for link layer injection
        data->deviceArray[i].libnetLinkFrame = libnet_init(
                LIBNET_LINK,
                data->deviceArray[i].device,
                libnetError);
        if (data->deviceArray[i].libnetLinkFrame == NULL)
        {
            sprintf(errString, "error in libnet_init: %s", libnetError);
            ERROR_ReportError(errString);
        }
    }
}

// /**
// API       :: RoutePacket
// PURPOSE   :: This function will directly route a packet to its
//              destination, bypassing the QualNet network.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet
// + packetSize : int : The size of the packet
// RETURN    :: void
// **/
static void RoutePacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize)
{
    IPNEData* data;
    libnet_ptag_t t;
    int err;
    char errString[MAX_STRING_LENGTH];

    UInt8* payload;
    int payloadSize;
    struct libnet_ipv4_hdr* ip =  NULL;
    int ipHeaderLength;
    int deviceIndex;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Go to the appropriate offsets for the IP header and payload
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;
    payload = packet + IPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;
    payloadSize = packetSize - IPNE_ETHERNET_HEADER_LENGTH - ipHeaderLength;

    // Determine which device to send the packet on.  If there is more than
    // on device, then determine the device based on the dest IP adddress.
    // If there is only one device then use that one device.
    IPNE_NodeMapping* mapping;
    int valueSize;

    // Determine the destination address
    UInt32 destAddress;
    destAddress = LibnetIpAddressToULong(ip->ip_dst);

    // Get the mapping for the destination address
    err = EXTERNAL_ResolveMapping(
            iface,
            (char*) &destAddress,
            sizeof(UInt32),
            (char**) &mapping,
            &valueSize);
    if (err)
    {
            ERROR_ReportError("Error resolving mapping");
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));

    if (data->numDevices > 1)
    {
        // Get the deviceIndex for the destination address
        deviceIndex = mapping->deviceIndex;
    }
    else
    {
        deviceIndex = 0;
    }

    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];

        printf(">>> ROUTING IP packet (not simulated) "
                "-----------------------------------------\n");

        IO_ConvertIpAddressToString(
            htonl(LibnetIpAddressToULong(ip->ip_src)),
            tempString);
        printf(
            "    source: %20s    protocol: %5d    tos: 0x%0x\n",
            tempString,
            ip->ip_p,
            ip->ip_tos);
        IO_ConvertIpAddressToString(
            htonl(LibnetIpAddressToULong(ip->ip_dst)),
            tempString);
        printf(
            "    dest  : %20s    id      : %5d    ttl: %d\n",
            tempString,
            ip->ip_id,
            ip->ip_ttl);
        // When routing packet via/dest are identical
        printf(
            "                                    offset  : %5d    "
            "payload: %d\n",
            ntohs(ip->ip_off) & 0x1FFF,
            payloadSize);
        printf("------------------------------------------"
                "---------------------------------->>>\n");
    }

    // Pass libnet the IP payload
    t = libnet_build_data(
            payload,            // payload
            payloadSize,        // payload size
            data->deviceArray[deviceIndex].libnetFrame,
            0);

    // Pass IP header data based on the original packet
    t = libnet_build_ipv4(
            LIBNET_IPV4_H + payloadSize, // length
            ip->ip_tos,                  // tos
            ntohs(ip->ip_id),            // id
            ntohs(ip->ip_off),           // fragmentation and offset
            ip->ip_ttl - 1,              // ttl
            ip->ip_p,                    // protocol
            0,                           // checksum
            LibnetIpAddressToULong(ip->ip_src),      // source address
            LibnetIpAddressToULong(ip->ip_dst),      // dest address
            NULL,                        // payload (already passed)
            0,                           // payload size
            data->deviceArray[deviceIndex].libnetFrame,
            0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetFrame));
        ERROR_ReportWarning(errString);
    }

    // Send the packet to the physical network
    err = libnet_write(data->deviceArray[deviceIndex].libnetFrame);
    if (err == -1)
    {
        sprintf(
            errString,
            "libnet error in route: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetFrame));
        ERROR_ReportWarning(errString);
    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetFrame);
}

// /**
// API       :: PreProcessIpPacketIcmp
// PURPOSE   :: This functions processes an ICMP packet before adding it to
//              the simulation.  If NAT is enabled it will call
//              PreProcessIpPacketNatYes.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + ip : struct libnet_ipv4_hdr* : Pointer to the IP header
// + packet: UInt8* : Pointer to the beginning of the packet
// + size : int : The size of the packet in bytes
// + dataOffset : UInt8* : Pointer to the packet data (after UDP or TCP
//                          header)
// + checksum : UInt16* : Pointer to the checksum in the TCP or UDP header
// RETURN    :: None
// **/
static void PreProcessIpPacketIcmp(
    EXTERNAL_Interface* iface,
    struct libnet_ipv4_hdr* ip,
    UInt8* packet,
    int size,
    UInt8* dataOffset,
    UInt16* checksum)
{
    IPNEData* data;
    int ipHeaderLength;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    ipHeaderLength = ip->ip_hl * 4;

    // If using NAT then pre-process the IP packet
    if (data->nat)
    {
        PreProcessIpPacketNatYes(iface, ip, checksum);
    }

#ifdef DERIUS
    // Check if we need to explicitly calculate the checksum
    if (data->explictlyCalculateChecksum)
    {
        UInt16 sum2 = *checksum;
        UInt8* headerStart;

        // First zero out checksum
        *checksum = 0;

        headerStart = ((UInt8*) ip) + ipHeaderLength;

        // Compute for ICMP style
        *checksum = ComputeIcmpStyleChecksum(
            headerStart, // TODO: was payload, check correct
            htons(ntohs(ip->ip_len) - ipHeaderLength));

        if (data->debug && sum2 != *checksum)
        {
            printf(
                "Computed checksums differ, proper = 0x%x "
                "incorrect = 0x%x\n",
                *checksum,
                sum2);
        }
    }
#endif
}

// /**
// API       :: PreProcessIpPacket
// PURPOSE   :: This functions processes an IP packet before adding
//              it to the simulation.  It will pass the packet to the
//              appropriate protocol-specific (function such as TCP, UDP,
//              OSPF) if necessary
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + packet: UInt8* : Pointer to the beginning of the packet
// + packetSize : int : The size of the packet in bytes.  May change if the
//                      ethernet frame was padded.
// + func : QualnetPacketInjectFunction** : Function to use to inject the
//                                          packet.  May change depending on
//                                          socket function.
// RETURN    :: -1 if the packet should not be added to the simulation, 0 if
//              it should
static int PreProcessIpPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int* packetSize,
    IPNE_EmulatePacketFunction** func)
{
    IPNEData* data;
    struct libnet_ipv4_hdr* ip;
    int ipHeaderLength;
    BOOL validProtocol;
    UInt8* payload;
    UInt8* nextHeader;
    UInt8* dataOffset;
    UInt16 port1;
    UInt16 port2;
    UInt16* sum;

    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Extract IP header
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;

    // Update the packet size.  This will take care of the case where the
    // ethernet frame is padded.
    *packetSize = ntohs(ip->ip_len) + IPNE_ETHERNET_HEADER_LENGTH;

    // Find where the payload begins
    payload = packet + IPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;

    // If using NAT
    if (data->nat)
    {
        // Check that the packet is TCP, UDP or ICMP.  If not, optionally
        // route the packet.
        validProtocol = FALSE;
        if (ip->ip_p == 0x01 || ip->ip_p == 0x06 || ip->ip_p == 0x11)
        {
            validProtocol = TRUE;
        }

        // If invalid protocol, route the packet (send it directly to the
        // destination without simulating it) if routing unknown protocols
        // is enabled and return -1, meaning do not process the packet
        // further.
        if (!validProtocol)
        {
            if (data->routeUnknownProtocols)
            {
                RoutePacket(iface, packet, *packetSize);

                if (data->debug)
                {
                    printf(
                        "Unknown transport protocol: %d (packet routed)\n",
                        ip->ip_p);
                }
            }
            else if (data->debug)
            {
                printf(
                    "Unknown transport protocol: %d (packet NOT routed)\n",
                    ip->ip_p);
            }

            return -1;
        }
    } // NAT

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.

    nextHeader = ((UInt8*) ip) + ipHeaderLength;

    // Pre-process packet depending on type
    if (ip->ip_p == IPPROTO_TCP)
    {
        struct libnet_tcp_hdr* tcp;

        // TCP: Get checksum, ports, where the data packet begins.  Call
        // PreProcessIpPacketTcp.  This will handle all udp/tcp
        // processing (such as specific protocols like OSPF)
        tcp = (struct libnet_tcp_hdr*) nextHeader;
        sum = &tcp->th_sum;
        port1 = ntohs(tcp->th_sport);
        port2 = ntohs(tcp->th_dport);
        dataOffset = ((UInt8*) tcp) + tcp->th_off * 4;

        PreProcessIpPacketTcp(
            iface,
            ip,
            port1,
            port2,
            packet,
            *packetSize,
            dataOffset,
            sum,
            func);
    }
    else if (ip->ip_p == IPPROTO_UDP)
    {
        PreProcessIpPacketUdp(
            iface,
            packet,
            *packetSize,
            func);
    }
    else if (ip->ip_p == IPPROTO_ICMP)
    {
        struct libnet_icmpv4_hdr* icmp;
        // ICMP: Get checksum, where the data packet begins.  Call
        // PreProcesIpPacketIcmp.
        icmp = (struct libnet_icmpv4_hdr*) nextHeader;
        sum = &icmp->icmp_sum;
        dataOffset = ((UInt8*) icmp) + sizeof(struct libnet_icmpv4_hdr);

        PreProcessIpPacketIcmp(
            iface,
            ip,
            packet,
            *packetSize,
            dataOffset,
            sum);
    }
    else if (data->ospfEnabled && ip->ip_p == IPPROTO_OSPF)
    {
        // OSPF: Call PreProcessIpPacketOspf only if OSPF is enabled
        PreProcessIpPacketOspf(
            iface,
            packet);
    }

    // Success
    return 0;
}

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
    IPNEData* data;
    int ipHeaderLength;
    UInt8* nextHeader;
    UInt16* sum;

    // By default assume we will inject the packet to the operational
    // network.  Depending on the protocol this packet might not be
    // injected.
    BOOL inject = TRUE;

    data = (IPNEData*) iface->data;
    assert(data != NULL);

    struct libnet_ipv4_hdr* ip;
    ip = (struct libnet_ipv4_hdr*) packet;
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) packet;
//    unsigned tos=IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    UInt32 tmp=ipHeader->ip_v_hl_tos_len;
//    ip->ip_hl=IpHeaderGetHLen(tmp);
//    ip->ip_v=IpHeaderGetVersion(tmp);
//    ip->ip_len=IpHeaderGetIpLength(tmp);
//    ip->ip_tos=IpHeaderGetTOS(tmp);

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

    // Handle anything socket/protocol specific to this packet.
    // This possibly modify the packet as well as the packet injection
    // function.

    nextHeader = packet + ipHeaderLength;


    // If this is OSPF then swap bytes
    // only for the non-fragmented or first fragmented packet

    //if (ip->ip_p == IPPROTO_UDP && (ip->ip_more_fragments==0) &&  (ip->ip_fragment_offset==0))
    if ((ipHeader->ip_p == IPPROTO_UDP) && 
        //(IpHeaderGetIpMoreFrag(ipHeader->ipFragment)==0) && 
        (IpHeaderGetIpFragOffset(ipHeader->ipFragment)==0))
    {
        ProcessOutgoingIpPacketUdp(
            iface,
            myAddress,
            nextHeader,
            ipHeader,
            &inject);
    }
    else if (ipHeader->ip_p == IPPROTO_TCP) 
    {
        struct libnet_tcp_hdr* tcp;

        // TCP: Get checksum, ports, where the data packet begins.  Call
        // PreProcessIpPacketTcp.  This will handle all udp/tcp
        // processing (such as specific protocols like OSPF)
        tcp = (struct libnet_tcp_hdr*) nextHeader;
        sum = &tcp->th_sum;

        ProcessOutgoingIpPacketTcp(
            iface,
            ipHeader,
            nextHeader,
            sum);
    }
    else if (data->ospfEnabled && (ipHeader->ip_p == IPPROTO_OSPF))
    {
        ProcessOutgoingIpPacketOspf(
            iface,
            myAddress,
            nextHeader,
            &inject);
    }
    else if (ipHeader->ip_p == IPPROTO_IGMP)
    {
        struct libnet_igmp_hdr* igmp;
        igmp = (struct libnet_igmp_hdr*) nextHeader;

        //First zero out checksum
        igmp->igmp_sum = 0;

        igmp->igmp_group.s_addr = htonl(igmp->igmp_group.s_addr);

        //Calculate the checksum - ICMP style
        igmp->igmp_sum = ComputeIcmpStyleChecksum(
            nextHeader,
            htons(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)- ipHeaderLength));
    }
    else if (ipHeader->ip_p == IPPROTO_ICMP && (IpHeaderGetIpMoreFrag(ipHeader->ip_v_hl_tos_len)==0))
    {
        struct libnet_icmpv4_hdr* icmp;
        // ICMP: Get checksum, where the data packet begins.  Call
        // PreProcesIpPacketIcmp.
        icmp = (struct libnet_icmpv4_hdr*) nextHeader;

        // First zero out checksum
        icmp->icmp_sum = 0;

        // if this is time-to-live exceed message, bytes swapping for IP in ICMP message
        if ((data->trueEmulation) && ((icmp->icmp_type == ICMP_TIMXCEED)||(icmp->icmp_type == ICMP_UNREACH)) )
        {
            BytesSwapHton((UInt8*)&(icmp->dun.ip.idi_ip));
            //BytesSwapHton(packet);
        }

        // Compute for ICMP style
        icmp->icmp_sum = ComputeIcmpStyleChecksum(
            nextHeader,
            htons(IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len)- ipHeaderLength));

    }
    return inject;
}

// /**
// API       :: PreProcessPacket
// PURPOSE   :: This function will verify that the given packet should be
//              included in the simulation (ie it is an IP packet) and does
//              NAT (Network Address Translation) if necessary
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet
// + packetSize : int* : The size of the packet.  Will be modified if the
//                       ethernet frame is padded.
// + func : QualnetPacketInjectFunction** : The function to use to inject
//                                          the packet into QualNet
// RETURN    :: void
// **/
static int PreProcessPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int* packetSize,
    IPNE_EmulatePacketFunction** func)
{
    IPNEData* data;
    struct libnet_ethernet_hdr* ethernet;
    UInt16 type;

    data = (IPNEData*) iface->data;

    // Pre-process depending on packet type
    ethernet = (struct libnet_ethernet_hdr*) (packet);
    type = ntohs(ethernet->ether_type);
    if (type == ETHERTYPE_ARP)
    {
        // Process ARP, then return and do not process the packet
        // further
        IPNE_ProcessArp(iface, packet + IPNE_ETHERNET_HEADER_LENGTH);
        return -1;
    }
    else if (type == ETHERTYPE_IP)
    {
        // Process IP packet and return result
        return PreProcessIpPacket(
            iface,
            packet,
            packetSize,
            func);
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

        return -1;
    }

    // Success, return 0 -- should not get here
    return 0;
}

// /**
// API       :: HandleSniffedIPPacket
// PURPOSE   :: This function will handle an incoming packet received in
//              IPNetworkEmulatorReceive.  It will inject the packet into the
//              QualNet simulation depending on which socket the packet came
//              through.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet
// + size : int : The size of the sniffed packet
// RETURN    :: void
// **/
static void HandleSniffedIPPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int size)
{
    int err;

//    struct libnet_ethernet_hdr* ethernet;
//   ethernet = (struct libnet_ethernet_hdr*) packet;

    // The default packet injection function is the generic
    // DefaultInjectIPPacket(). This function be changed later by a socket
    // or protocol specific function in PreProcessIpPacket().
    IPNE_EmulatePacketFunction* func = EmulateIpPacket;

    // Pre-process the packet.  This could cause a change to any part of the
    // packet.  The size parameter may also change if the ethernet frame is
    // padded.
    err = PreProcessPacket(
        iface,
        packet,
        &size,
        &func);
    if (err != 0)
    {
        // If an error was encountered while pre-processing the packet then
        // ignore the packet
        return;
    }

    // Call the packet injection function
    if (func != NULL)
    {
        (*func)(iface, packet, size);
    }
}

//---------------------------------------------------------------------------
// End of Static Functions
//---------------------------------------------------------------------------
// /**
// API       :: LibnetIpAddressToULong
// PURPOSE   :: Take a libnet IP address (which differs on unix/windows) and
//              convert it to an UInt32
// PARAMETERS::
// + addr : in_addr : The libnet IP address
// RETURN    :: The 4 byte IP address
// **/
UInt32 LibnetIpAddressToULong(in_addr addr)
{
    // Return address
#ifdef _WIN32
    return addr.S_un.S_addr;
#else
    return addr.s_addr;
#endif
}

// /**
// API       :: PreProcessIpNatYes
// PURPOSE   :: This functions will swap the IP addresses in the IP header
//              as well as update the given checksum.  Works for TCP, UDP,
//              ICMP checksums (ones-complement style).
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The IPNE interface
// + ip : struct libnet_ipv4_hdr* : Pointer to the IP header
// + checksum : UInt16* : Pointer to the checksum in the TCP or UDP header
// RETURN    :: None
// **/
void PreProcessIpPacketNatYes(
    EXTERNAL_Interface* iface,
    struct libnet_ipv4_hdr* ip,
    UInt16* checksum)
{
    char err[MAX_STRING_LENGTH];
    char tmp[MAX_STRING_LENGTH];

        
            
    // Swap the source address
    if (SwapAddress(
            iface,
            (UInt8*) &ip->ip_src,
            sizeof(UInt32),
            checksum,
            NULL))
    {
        IPAddressToString(&ip->ip_src, tmp);
        sprintf(err, "Address \"%s\" does not match what we are "
                        "sniffing for", tmp);
        ERROR_ReportWarning(err);
    }


    UInt32 destAddress;
    destAddress = ntohl(ip->ip_dst.s_addr);

    // Swap the destination address if unicast
    if (destAddress < IP_MIN_MULTICAST_ADDRESS)
    {
        if (SwapAddress(
                iface,
                (UInt8*) &ip->ip_dst,
                sizeof(UInt32),
                checksum,
                NULL))
        {
            IPAddressToString(&ip->ip_dst, tmp);
            sprintf(err, "Address \"%s\" does not match what we are "
                         "sniffing for", tmp);
            ERROR_ReportWarning(err);

        }
    }
}

// /**
// API       :: CompareIPSocket
// PURPOSE   :: This function will check if 2 sockets match.  It is
//              essentially a large, ugly comparison.  The size is necessary
//              because any 0 value is ignored, but a socket should not
//              match if the comparison is based entirely on 0 values.
// PARAMETERS::
// + addr1 : UInt32 : The address of the first end of the socket
// + port1 : UInt16 : The port of the first end of the socket
// + addr2 : UInt32 : The address of the second end of the socket
// + port2 : UInt16 : The port of the second end of the socket
// + s : IPSocket* : The socket to compare it with
// RETURN    :: void
// **/
int CompareIPSocket(
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    IPSocket* s)
{
    // return TRUE if addr1/port1 and addr2/port2 match the socket s,
    // ignore any values that are 0 -- but at the same time make sure
    // that the comparison isn't based entirely on 0 values

    return      (((addr1 == 0 || addr1 == s->addr1 || s->addr1 == 0)
                && (port1 == 0 || port1 == s->port1 || s->port1 == 0)
                && (addr2 == 0 || addr2 == s->addr2 || s->addr2 == 0)
                && (port2 == 0 || port2 == s->port2 || s->port2 == 0))
                && ((addr1 != 0 && s->addr1 != 0)
                    || (port1 != 0 && s->port1 != 0)
                    || (addr2 != 0 && s->addr2 != 0)
                    || (port2 != 0 && s->port2 != 0)))
            ||
                  ((addr1 == 0 || addr1 == s->addr2 || s->addr2 == 0)
                && (port1 == 0 || port1 == s->port2 || s->port2 == 0)
                && (addr2 == 0 || addr2 == s->addr1 || s->addr1 == 0)
                && (port2 == 0 || port2 == s->port1 || s->port1 == 0)
                && ((addr1 != 0 && s->addr2 != 0)
                    || (port1 != 0 && s->port2 != 0)
                    || (addr2 != 0 && s->addr1 != 0)
                    || (port2 != 0 && s->port1 != 0)));
}

// /**
// API       :: ComputeIcmpStyleChecksum
// PURPOSE   :: Computes a checksum for the packet usable for ICMP
// PARAMETERS::
// + packet : UInt8* : Pointer to the beginning of the packet
// + length : UInt16 : Length of the packet in bytes (network byte order)
// RETURN    :: void
// **/
UInt16 ComputeIcmpStyleChecksum(
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
// API       :: ComputeTcpStyleChecksum
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
UInt16 ComputeTcpStyleChecksum(
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
    sum = (UInt16) ~ComputeIcmpStyleChecksum(packet, tcpLength);

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
// API       :: IncrementallyAdjustChecksum
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
void IncrementallyAdjustChecksum(
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


// /**
// API       :: IPNECheckMulticastAndDoNAT
// PURPOSE   :: This function  checks if the destination is a multicast
//              address and initiates swapping of this destination addresses
// PARAMETERS::
// + node : Node * : Pointer to  Node data structure
// + iface : EXTERNAL_Interface * : Pointer to external interface
// + forwardData : void * : pointer to packet
// + forwardSize : int : size of the packet
// RETURN    :: void
// **/

void IPNECheckMulticastAndDoNAT(
        Node *node,
        EXTERNAL_Interface *iface,
        void *forwardData,
        int forwardSize)
{

    IPNEData *data;
    data = (IPNEData*) iface->data;
    UInt8 *packet;

    packet=(UInt8 *)forwardData;

    UInt32 destAddress;

    //check if NAT enabled, else exit
    if ((!data->nat)||(!data->multicastEnabled))
    {
        return;
    }

    struct libnet_ipv4_hdr *ip =  NULL;

    // Go to the appropriate offsets for the IP header and payload
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);

    //Assuming Linux only for now
    destAddress = ntohl(ip->ip_dst.s_addr);

    //check if Multicast destination in packet,else exit
    if (destAddress < IP_MIN_MULTICAST_ADDRESS)
    {
        return;
    }

    //Forward app doesn't keep track of interface on which
    //packet was received.
    //For Multicasting it means one node can have only one interface
    //in the mapping!!

    SwapMulticastAddress(
                node,
                iface,
                (UInt8*) &ip->ip_dst,
                sizeof(UInt32),
                NULL,
                NULL);


}


// /**
// API       :: SwapMulticastAddress
// PURPOSE   :: This function  swaps the destination multicast address
//              based on the mapping specified
// PARAMETERS::
// + node : Node * : Pointer to  Node data structure
// + iface : EXTERNAL_Interface * : Pointer to external interface
// + address : UInt8 * : Pointer to the address that needs to be swapped
// + addressSize: int: size of the address
// + sum : UInt16 * : Pointer to the checksum field
// + packetStart : UInt8 * : Pointer to start of packet
// RETURN    :: int :  return 0
// **/

int SwapMulticastAddress(
    Node *node,
    EXTERNAL_Interface *iface,
    UInt8 *address,
    int addressSize,
    UInt16 *sum,
    UInt8 *packetStart)
{

    UInt8 *newAddress = NULL;
    int valueSize = 0;
    int error = 0;
    int index = 0;
    IPNE_NodeMapping *mapping = NULL;
    NodeAddress myAddress;

    assert(iface != NULL);
    assert(address != NULL);

    //  Lookup current QualNet address mapping

    for (index=0;index < node->numberInterfaces;index++)
    {
        myAddress = MAPPING_GetInterfaceAddressForInterface(
                                             node,
                                             node->nodeId,
                                             index);

        myAddress = htonl(myAddress);

        error = EXTERNAL_ResolveMapping(
                iface,
                (char*) &myAddress,
                sizeof(NodeAddress),
                (char**) &mapping,
                &valueSize);

        if (!error)
        {
            break;
        }
    }


    ERROR_Assert(!error,
            "No match found for node");

    assert(valueSize == sizeof(IPNE_NodeMapping));

    //Get the associated multicast address from mapping
    //which is in the network order format

    newAddress = (UInt8*) &mapping->multicastReceiveRealAddress;

    // Adjust checksum, if one is given
    if (sum != NULL)
    {
        IncrementallyAdjustChecksum(
            sum,
            (UInt8*) address,
            newAddress,
            addressSize,
            packetStart);
    }

    

    // Set the old address to the new address
    memcpy(address, newAddress, sizeof(UInt32));

    return 0;

}



// /**
// API       :: SwapAddress
// PURPOSE   :: This function will swap a real IP address for a qualnet IP
//              address and vice versa.  It will also update a checksum
//              if provided.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The external interface
// + address : UInt8* : The address in network byte order
// + addressSize : int : The size of the address
// + sum : UInt16* : The checksum.  NULL if none.
// + packetStart : UInt8* : The start of the packet.  NULL if it is part of
//                           the virtual header.  See the function
//                           IncrementallyAdjustChecksum.
// RETURN    :: int : Returns 0 on success, non-zero on failure.
// **/
int SwapAddress(
    EXTERNAL_Interface* iface,
    UInt8* address,
    int addressSize,
    UInt16* sum,
    UInt8* packetStart)
{
    UInt8* newAddress;
    int valueSize;
    int error;
    IPNE_NodeMapping* mapping;
    char errString[MAX_STRING_LENGTH];

    assert(iface != NULL);
    assert(address != NULL);

    // Convert real <-> qualnet address (and vice versa)
    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) address,
        addressSize,
        (char**) &mapping,
        &valueSize);
    if (error)
    {
        return 1;
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));

    // Determine which address the mapping is for
    if (addressSize == mapping->realAddressSize
        && memcmp(address, &mapping->realAddress, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->proxyAddress;
        ERROR_Assert(mapping->proxyAddressSize == addressSize,
                     "Proxy/Real adddress sizes are different");
    }
    else if (addressSize == mapping->realAddressStringSize
        && memcmp(address, &mapping->realAddressString, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->proxyAddressString;
        ERROR_Assert(mapping->proxyAddressStringSize == addressSize,
                     "Proxy/Real adddress string sizes are different");
    }
    else if (addressSize == mapping->realAddressWideStringSize
        && memcmp(address, &mapping->realAddressWideString, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->proxyAddressWideString;
        ERROR_Assert(mapping->proxyAddressWideStringSize == addressSize,
                     "Proxy/Real adddress wide string sizes are different");
    }
    else if (addressSize == mapping->proxyAddressSize
        && memcmp(address, &mapping->proxyAddress, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->realAddress;
        ERROR_Assert(mapping->realAddressSize == addressSize,
                     "Proxy/Real adddress sizes are different");
    }
    else if (addressSize == mapping->proxyAddressStringSize
        && memcmp(address, &mapping->proxyAddressString, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->realAddressString;
        ERROR_Assert(mapping->realAddressStringSize == addressSize,
                     "Proxy/Real adddress string sizes are different");
    }
    else if (addressSize == mapping->proxyAddressWideStringSize
        && memcmp(address, &mapping->proxyAddressWideString, addressSize) == 0)
    {
        newAddress = (UInt8*) &mapping->realAddressWideString;
        ERROR_Assert(mapping->realAddressWideStringSize == addressSize,
                     "Proxy/Real adddress wide string sizes are different");
    }
    else
    {
        char tempString[MAX_STRING_LENGTH];
        IPAddressToString(address, tempString);
        sprintf(errString, "Address \"%s\"", tempString);
        printf("%s %d\n", errString, mapping->realAddressSize);
        IPAddressToString(&mapping->realAddress, tempString);
        sprintf(errString, "Address \"%s\"", tempString);
        ERROR_ReportError(errString);
    }

    // Adjust checksum, if one is given
    if (sum != NULL)
    {
        IncrementallyAdjustChecksum(
            sum,
            (UInt8*) address,
            newAddress,
            addressSize,
            packetStart);
    }

    // Set the old address to the new address
    memcpy(address, newAddress, addressSize);

    return 0;
}

// /**

// /**
// API       :: AutoConfMAC
// PURPOSE   :: This function will generate a ARP request to
//                resolve MAC address from IP address in configuration file 
//                with TrueEmulation mode.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void    AutoConfMAC(EXTERNAL_Interface* iface)
{
    IPNEData* data;
    IPNE_ArpPacketClass out;
    char macAddress[ETHER_ADDR_LEN+1];
    char bcast[ETHER_ADDR_LEN];
    int error;
    int i;
    IPNE_NodeMapping *mapping;
    int valueSize;

    // Fill in the outgoing packet
    // for all interfaces
    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    for (i=0 ; i < data->numArpReq; i++)
    {
        error = EXTERNAL_ResolveMapping(
            iface,
            (char*) &data->arpNodeAddress[i],
            sizeof(UInt32),
            (char**) &mapping,
            &valueSize);
        if (error)
        {
            ERROR_ReportError("Error resolving mapping");
        }
        assert(valueSize == sizeof(IPNE_NodeMapping));

#ifdef __APPLE__
        ERROR_ReportError("VIRTUAL-NODE MAC-ADDRESS is not explicitly specified");
#else
#ifndef _WIN32 // unix/linux
        int fd;
        struct ifreq ifrq;
        struct sockaddr_in *sin;

        //find local mac and ip address    
        UInt8* u = (UInt8*) ifrq.ifr_addr.sa_data;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        //strcpy(ifrq.ifr_name, deviceName);
        strcpy(ifrq.ifr_name, data->deviceArray[mapping->deviceIndex].device);
        if (ioctl(fd,SIOCGIFHWADDR, &ifrq) < 0)
        {
            printf("can't get MAC address\n");
        }

        memcpy(macAddress, u, ETHER_ADDR_LEN);

        if (ioctl(fd, SIOCGIFADDR, &ifrq) < 0)
        {
            printf("can't get IP address\n");
        }

        sin = (sockaddr_in *)&ifrq.ifr_addr;
        close(fd);

#else  // windows

        IP_ADAPTER_INFO adapter;
        PIP_ADAPTER_INFO adapterPtr;

        // Call GetAdaptersInfo once to get the buffer size.  After calling this
        // function, len will be the length of the buffer.
        DWORD len = sizeof(adapter);
        DWORD err = GetAdaptersInfo(
            &adapter,
            &len);
        if (err != ERROR_BUFFER_OVERFLOW && err != ERROR_SUCCESS)
        {
            ERROR_ReportError("Error getting length of adapter buffer");
        }

        // Allocate enough memory for all adapters
        adapterPtr = (PIP_ADAPTER_INFO) MEM_malloc(len);

        // Now get all of the adapters
        err  = GetAdaptersInfo(
            adapterPtr,
            &len);
        if (err != ERROR_SUCCESS)
        {
            ERROR_ReportError("Error getting adapters");
        }

        // Loop over all adapters.  Check if the adapter name matches the device
        // name.
        PIP_ADAPTER_INFO pAdapterInfo = adapterPtr;
        while (pAdapterInfo != NULL
           && (strstr(data->deviceArray[mapping->deviceIndex].device, pAdapterInfo->AdapterName) == NULL))
        {
            pAdapterInfo = pAdapterInfo->Next;
        }

        // Verify that an adapter was found
        if (pAdapterInfo == NULL)
        {
            ERROR_ReportError("Adapter not found");
        }

        //Get IP address -> support single IP address
        PIP_ADDR_STRING pAddressList = &(adapterPtr->IpAddressList);
    
        // Verify the MAC address is the right size
        if (pAdapterInfo->AddressLength != ETHER_ADDR_LEN)
        {
            ERROR_ReportError("MAC address is not 6 bytes");
        }

        // Copy the MAC address
        UInt8* u = (UInt8*) pAdapterInfo->Address;
        memcpy(macAddress, u, ETHER_ADDR_LEN);

#endif //#ifndef _WIN32 // unix/linux
#endif    //#ifdef __APPLE__

        //Create ARP Request packet
        out.hardwareType = htons(ARPHRD_ETHER);
        out.protocolType = htons(ETHERTYPE_IP);
        out.hardwareSize = ETHER_ADDR_LEN;
        out.protocolSize = 4;
        out.opcode = htons(ARPOP_REQUEST);

        bcast[0]=0xff;
        bcast[1]=0xff;
        bcast[2]=0xff;
        bcast[3]=0xff;
        bcast[4]=0xff;
        bcast[5]=0xff;

#ifdef __APPLE__
#else
#ifndef _WIN32 // unix/linux
        memcpy(out.senderProtocolAddress,(void *) &sin->sin_addr.s_addr, 4);
#else //windows
        NodeAddress localAddress;
        StringToAddress(pAddressList->IpAddress.String, &localAddress);
        memcpy(out.senderProtocolAddress, (void *)&localAddress, 4);
#endif //#ifndef _WIN32
#endif    //#ifdef __APPLE__

        memcpy(out.senderHardwareAddress, macAddress, ETHER_ADDR_LEN);
        memcpy(out.targetProtocolAddress, &data->arpNodeAddress[i], 4);
        memcpy(out.targetHardwareAddress, bcast, ETHER_ADDR_LEN);

        InjectLinkPacket(
                iface,
                out.targetHardwareAddress,
                    out.senderHardwareAddress,
                ETHERTYPE_ARP,
                    (UInt8*) &out,
                sizeof(out),
                0,
                mapping->deviceIndex);
    }
}

// /**
// API       :: IPAddressToString
// PURPOSE   :: This function will convert an IP address to a string.  IP
//              address should be in network byte order.
// PARAMETERS::
// addr : void* : Pointer to the address
// string : char* : The string.  The size should be at least 16 bytes.
// RETURN    :: void
// **/
void IPAddressToString(void* addr, char* string)
{
    UInt8* addr2 = (UInt8*) addr;

    // Convert addr to string
    sprintf(string, "%d.%d.%d.%d", addr2[0], addr2[1], addr2[2], addr2[3]);
}

// /**
// API       :: PrintIPAddress
// PURPOSE   :: This function will print an IP address to stdout.  IP
//              address should be in network byte order.
// PARAMETERS::
// addr : void* : Pointer to the address
// RETURN    :: void
// **/
void PrintIPAddress(void* addr)
{
    char str[16];

    // Convert to string, then print
    IPAddressToString((UInt8*) addr, str);
    printf("%s",str);
}

// /**
// API       :: InjectLinkPacket for ARP request
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme. This function is 
//                overloading function of InjectLinkPacket
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime,
    int    deviceIndex)
{
    IPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    //int deviceIndex;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Get current time
    if (iface->timeFunction)
    {
        now = iface->timeFunction(iface);
    }
    else
    {
        now = 0;
    }

    // Write packet to the device at this deviceIndex
    t = libnet_build_ethernet(
            dest,
            source,
            type,
            packet,
            packetSize,
            data->deviceArray[deviceIndex].libnetLinkFrame,
            0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Send the packet to the physical network
    err = libnet_write(data->deviceArray[deviceIndex].libnetLinkFrame);
    if (err == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Handle send statistics
    if (iface->timeFunction != NULL)
    {
        HandleIPStatisticsSendPacket(
            iface,
            receiveTime,
            now);
    }

    // Finalize the packet

    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}



// /**
// API       :: InjectLinkPacket
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime)
{
    IPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    int error;
    int deviceIndex;
    IPNE_NodeMapping* mapping;
    int valueSize;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Get current time
    if (iface->timeFunction)
    {
        now = iface->timeFunction(iface);
    }
    else
    {
        now = 0;
    }

    if (data->debug)
    {
        printf("Forwarding Link packet : ");
        printf("\n");
    }

    // Get the mapping for the destination address
    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) dest ,
        6,
        (char**) &mapping,
        &valueSize);
    if (error)
    {
        sprintf(errString, "Error resolving mapping for address");
        ERROR_ReportError(errString);
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));

    // Get the deviceIndex for the destination address
    deviceIndex = mapping->deviceIndex;

    // Write packet to the device at this deviceIndex
    t = libnet_build_ethernet(
            dest,
            source,
            type,
            packet,
            packetSize,
            data->deviceArray[deviceIndex].libnetLinkFrame,
            0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Send the packet to the physical network

    err = libnet_write(data->deviceArray[deviceIndex].libnetLinkFrame);
    if (err == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Handle send statistics
    if (iface->timeFunction != NULL)
    {
        HandleIPStatisticsSendPacket(
            iface,
            receiveTime,
            now);
    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}

// /**
// API       :: InjectIpPacketAtNetworkLayer
// PURPOSE   :: This function will forward an IP packet to the external
//              source.  This function will forward an entire IP packet to
//              the network, meaning that it should include the link and
//              network headers.  A new packet will be created from these
//              headers and the data in the packet will be forwarded to the
//              network.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet.  Includes link + network
//                      headers.
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectIpPacketAtNetworkLayer(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime)
{
    IPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    int deviceIndex;

    UInt8* payload;
    int payloadSize;
    struct libnet_ipv4_hdr* ip;
    int ipHeaderLength;

// for dynamic stat
    NodeAddress logVia;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Get current time
    if (iface->timeFunction)
    {
        now = iface->timeFunction(iface);
    }
    else
    {
        now = 0;
    }

    // Go to the appropriate offsets for the IP header and payload
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    //ipHeaderLength = ip->ip_hl * 4;
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    UInt8 tos =(UInt8)IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    ipHeaderLength = 20;
    payload = packet + IPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;
    payloadSize = packetSize - IPNE_ETHERNET_HEADER_LENGTH - ipHeaderLength;

    char tempString[MAX_STRING_LENGTH];

    logVia = LibnetIpAddressToULong(ip->ip_dst);

    // Determine the node address the injection is being done from
    if (data->nat)
    {
            IPNE_NodeMapping* logMapping;
            int valueSize;
            char tmp[MAX_STRING_LENGTH];

            // Determine the original IP source address pre-swap
            err = EXTERNAL_ResolveMapping(
                iface,
                (char*) &logVia,
                sizeof(NodeAddress),
                (char**) &logMapping,
                &valueSize);
            if (err)
            {
                IPAddressToString(&logVia, tmp);
                sprintf(errString, "Address \"%s\" does not match what we are sniffing "
                            "for", tmp);
                ERROR_ReportWarning(errString);
                return;
            }
            assert(valueSize == sizeof(IPNE_NodeMapping));
            logVia = logMapping->proxyAddress;
    }
    
    
    if (data->printPacketLog)
    {

        printf(
            ">>> Forwarding IP packet ----------------"
            "--------------------------------------\n");
        IO_ConvertIpAddressToString(
            htonl(LibnetIpAddressToULong(ip->ip_src)),
            tempString);
        printf(
            "    source: %20s    protocol: %5d    tos: 0x%0x\n",
            tempString,
            ip->ip_p,
            //ip->ip_tos
            tos);
        IO_ConvertIpAddressToString(
            htonl(LibnetIpAddressToULong(ip->ip_dst)),
            tempString);
        printf(
            "    dest  : %20s    id      : %5d    ttl: %d\n",
            tempString,
            ip->ip_id,
            ip->ip_ttl);
        IO_ConvertIpAddressToString(
            htonl(logVia),
            tempString);
        printf(
            "    via   : %20s    offset  : %5d    payload: %d\n",
            tempString,
            ntohs(ip->ip_off) & 0x1FFF,
            payloadSize);
        printf(
            "-----------------------------------------"
            "----------------------------------->>>\n");
    }

    // Determine which device to send the packet on.  If there is more than
    // one device, then determine the device based on the dest IP adddress.
    // If there is only one device then use that one device.

    if (data->numDevices > 1)
    {
        IPNE_NodeMapping* mapping;
        int valueSize;
        UInt32 destAddress;

        // Multiple devices, determine the destination address
        destAddress = LibnetIpAddressToULong(ip->ip_dst);

        // Get the mapping for the destination address
        err = EXTERNAL_ResolveMapping(
            iface,
            (char*) &destAddress,
            sizeof(UInt32),
            (char**) &mapping,
            &valueSize);
        if (err)
        {
        ERROR_ReportError("Error resolving mapping");
        }
        assert(valueSize == sizeof(IPNE_NodeMapping));

        // Get the deviceIndex for the destination address
        deviceIndex = mapping->deviceIndex;
    }
    else
    {
        // Only one device
        deviceIndex = 0;
    }

    // Pass libnet the IP payload
    t = libnet_build_data(
            payload,            // payload
            payloadSize,        // payload size
            data->deviceArray[deviceIndex].libnetFrame,
            0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet_build_data error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetFrame));
        ERROR_ReportWarning(errString);
    }

    // Pass IP header data based on the original packet
    t = libnet_build_ipv4(
        LIBNET_IPV4_H + payloadSize, // length
       // ip->ip_tos,                  // tos
       tos,
        ntohs(ip->ip_id),            // id
        ntohs(ip->ip_off),           // fragmentation and offset
        ip->ip_ttl - 1,              // ttl
        ip->ip_p,                    // protocol
        0,                           // checksum
        LibnetIpAddressToULong(ip->ip_src),  // source address
        LibnetIpAddressToULong(ip->ip_dst),  // dest address
        NULL,                        // payload (already passed)
        0,                           // payload size
        data->deviceArray[deviceIndex].libnetFrame,
        0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet_build_ipv4 error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetFrame));
        ERROR_ReportWarning(errString);
    }

    // Send the packet to the physical network
    err = libnet_write(data->deviceArray[deviceIndex].libnetFrame);
    if (err == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetFrame));
        ERROR_ReportWarning(errString);
    }

    // Handle send statistics
    if (iface->timeFunction != NULL)
    {
        HandleIPStatisticsSendPacket(
            iface,
            receiveTime,
            now);
    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetFrame);
}

// /**
// API       :: InjectIpPacketAtLinkLayer
// PURPOSE   :: This function will insert an IP packet directly at the link
//              layer destined for the next hop of the packet i.e. the  external
//              source.  This function will create the outgoing IP packet
//              based its arguments.  Only the data of the outgoing packet
//              should be passed in the "packet" parameter.  All arguments
//              should be in host byte order except for packet, which will
//              be forwarded as passed. The function creates an ethernet header
//              after looking up the ethernet destination address of the next
//              hop and the corresponding source ethernet address. This
//              function then writes the packet directly at the link layer
//              avoiding the use of the nodes kernel ip routing tables.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + myAddress : NodeAddress : The address of the node that is forwarding
//                             the IP packet.
// + tos : UInt8 : The TOS field of the outgoing IP packet
// + id : UInt16 : The id field
// + offset : UInt16 : The offset field
// + ttl : UInt8 : The TTL field
// + protocol : UInt8 : The protocol field
// + srcAddr : UInt32 : The source addr field
// + destAddr : UInt32 : The dest addr field
// + packet : UInt8* : Pointer to the packet.  ONLY the data portion
//                             of the packet.
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectIpPacketAtLinkLayer(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8 tos,
    UInt16 id,
    UInt16 offset,
    UInt8 ttl,
    UInt8 protocol,
    UInt32 srcAddr,
    UInt32 destAddr,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime)
{
    IPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    UInt8 dstMacAddress[6];
    UInt8 srcMacAddress[6];
    int srcMacAddressInt[6];
    IPNE_NodeMapping* mapping;
    int valueSize;

    // IP packet type
    UInt16 type = 0x0800;
    int deviceIndex;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Get current time
    if (iface->timeFunction)
    {
        now = iface->timeFunction(iface);
    }
    else
    {
        now = 0;
    }

    // Determine which device to send the packet on.  If there is more than
    // one device, then determine the device based on the outoing interface
    // IP address.

    myAddress = htonl(myAddress);

    // Get the mapping for the destination address
    err = EXTERNAL_ResolveMapping(
        iface,
        (char*) &myAddress,
        sizeof(NodeAddress),
        (char**) &mapping,
        &valueSize);
    if (err)
    {
        sprintf(
            errString,
            "Error resolving mapping for address 0x%x",
            ntohl(myAddress));
        ERROR_ReportError(errString);
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));


    // Get the deviceIndex for the destination address
    deviceIndex = mapping->deviceIndex;

    // If this is an OSPF packet, switch the broadcast address to
    // 224.0.0.5.  This is needed but I'm not sure why.
    if ((data->ospfEnabled) && (destAddr == 0xffffffff)
            && (protocol == IPPROTO_OSPF))
    {
        destAddr = 0xe0000005;
    }

//#ifdef DERIUS
    // If this is an OLSR packet, check broadcast address and set 
    if ((data->olsrEnabled) && (destAddr == 0xffffffff) && (data->olsrNetDirectedBroadcast))
    {
    //get net-directed broadcast address and assign to destAddr
        char pcapError[PCAP_ERRBUF_SIZE];
        unsigned int net;
        unsigned int mask;
        // Lookup network name/netmask
        err = pcap_lookupnet(
            data->deviceArray[deviceIndex].device,
            &net,
            &mask,
            pcapError);
        if (err)
        {
            sprintf(errString, "\npcap_lookupnet : %s\n", pcapError);
            ERROR_ReportError(errString);
        }

        unsigned int netDirectedBroadcast;
        netDirectedBroadcast = ((myAddress&mask) | ~mask); 
//        printf("%x\n", netDirectedBroadcast);
        destAddr = htonl(netDirectedBroadcast);
    }
//#endif

    srcAddr = htonl(srcAddr);
    destAddr = htonl(destAddr);

    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];

        printf(
            ">>> Forwarding IP packet at Link Layer -----------------"
            "-----------------------\n");
        IO_ConvertIpAddressToString(htonl(srcAddr), tempString);
        printf(
            "    source: %20s    protocol: %5d    tos: 0x%0x\n",
            tempString,
            protocol,
            tos);
        IO_ConvertIpAddressToString(htonl(destAddr), tempString);
        printf(
            "    dest  : %20s    id      : %5d    ttl: %d\n",
            tempString,
            id,
            ttl);
        IO_ConvertIpAddressToString(htonl(myAddress), tempString);
        printf(
            "    via   : %20s    offset  : %5d    payload: %d\n",
            tempString,
            offset,
            packetSize);
        printf(
            "------------------------------------------"
            "---------------------------------->>>\n");
    }

    // Now read the Outgoing MAC address for this mapping if not broadcast
    if (destAddr == htonl(0xe0000005))
    {
        dstMacAddress[0] = 0x01;
        dstMacAddress[1] = 0x00;
        dstMacAddress[2] = 0x5e;
        dstMacAddress[3] = 0x00;
        dstMacAddress[4] = 0x00;
        dstMacAddress[5] = 0x05;
    }
    else if (destAddr == 0xffffffff)
    {
        dstMacAddress[0] = 0xff;
        dstMacAddress[1] = 0xff;
        dstMacAddress[2] = 0xff;
        dstMacAddress[3] = 0xff;
        dstMacAddress[4] = 0xff;
        dstMacAddress[5] = 0xff;
    }
    else
    {
        memcpy(dstMacAddress, mapping->macAddress, 6);
    }

    // Also read the src MAC address through the device Index
    sscanf(
        data->deviceArray[deviceIndex].macAddress,
        "%x:%x:%x:%x:%x:%x",
        &srcMacAddressInt[0],&srcMacAddressInt[1],&srcMacAddressInt[2],
        &srcMacAddressInt[3],&srcMacAddressInt[4],&srcMacAddressInt[5]);
    srcMacAddress[0] = (UInt8)srcMacAddressInt[0];
    srcMacAddress[1] = (UInt8)srcMacAddressInt[1];
    srcMacAddress[2] = (UInt8)srcMacAddressInt[2];
    srcMacAddress[3] = (UInt8)srcMacAddressInt[3];
    srcMacAddress[4] = (UInt8)srcMacAddressInt[4];
    srcMacAddress[5] = (UInt8)srcMacAddressInt[5];

    // Now the dstMacAddress and srcMacAddress contain the correct
    // mac source and dst addresses

    // Pass libnet the IP pa-yload
    t = libnet_build_data(
        packet,            // payload
        packetSize,        // payload size
        data->deviceArray[deviceIndex].libnetLinkFrame,
        0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Pass IP header data based on the original packet
    t = libnet_build_ipv4(
        LIBNET_IPV4_H + packetSize, // length
        tos,
        id,
        offset,
        ttl,
        protocol,
        0,                          // checksum
        srcAddr,
        destAddr,
        NULL,                       // payload (already passed)
        0,                          // payload size (already passed)
        data->deviceArray[deviceIndex].libnetLinkFrame,
        0);
    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Build the ethernet header
    t = libnet_build_ethernet(
        dstMacAddress,
        srcMacAddress,
        type,
        0,
        0,
        data->deviceArray[deviceIndex].libnetLinkFrame,
        0);

    if (t == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Send the packet to the physical network at the network layer
    err = libnet_write(data->deviceArray[deviceIndex].libnetLinkFrame);
    if (err == -1)
    {
        sprintf(
            errString,
            "libnet error: %s",
            libnet_geterror(data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }

    // Handle send statistics
    if (iface->timeFunction != NULL)
    {
        HandleIPStatisticsSendPacket(
            iface,
            receiveTime,
            now);
    }

    // Finalize the packet-
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}

// /**
// API       :: EmualateIpPacketNatYes
// PURPOSE   :: This function will add a packet to the qualnet simulation
//              for use in Nat-Yes mode.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + ip : struct libnet_ipv4_hdr* : Pointer to the ip header
// + ipHeaderLength : int : Length of the IPh eader in bytes
// RETURN    :: void
// **/
void EmulateIpPacketNatYes(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    struct libnet_ipv4_hdr* ip,
    int ipHeaderLength)
{
    IPNEData* data;
    IPNE_NodeMapping* mapping;
    int valueSize;
    char err[MAX_STRING_LENGTH];
    int error;
    char tmp[16];

    // srcAddr is the IP address of the QualNet node that will forward the
    // message
    NodeAddress srcAddr;

    // ipSrcAddr is the IP address of the operational host that originated
    // this packet
    NodeAddress ipSrcAddr;

    // ipDestAddr is the IP address of the operational host that is the
    // destination of this packet
    NodeAddress ipDestAddr;

    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Extract the destination address from the packet.  This will be
    // the real address, so it must be converted back to a qualnet address.
    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) &ip->ip_dst,
        sizeof(UInt32),
        (char**) &mapping,
        &valueSize);
    if (error)
    {
        IPAddressToString(&ip->ip_dst, tmp);
        sprintf(err, "Address \"%s\" does not match what we are sniffing "
                    "for", tmp);
        ERROR_ReportWarning(err);
        return;
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));

    if (data->multicastEnabled)
    {
         //Assuming Linux
         ipDestAddr=ntohl(ip->ip_dst.s_addr);

         if (ipDestAddr > IP_MIN_MULTICAST_ADDRESS)
         {
            ipDestAddr = ntohl(mapping->multicastTransmitAddress);
         }
             else
         {
            ipDestAddr = ntohl(mapping->proxyAddress);
             }
    }
    else
    {
     ipDestAddr = ntohl(mapping->proxyAddress);
    }


    // Extract the source address.  Already swapped to QualNet proxy
    // address.
    // NOTE: ipSrcAddr should technically not be the proxy address
    ipSrcAddr = ntohl(ip->ip_src.s_addr);
    srcAddr = ipSrcAddr;

    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];
        NodeAddress logIpSrc;
        IPNE_NodeMapping* logMapping;

        // Determine the original IP source address pre-swap
        error = EXTERNAL_ResolveMapping(
            iface,
            (char*) &ip->ip_src,
            sizeof(UInt32),
            (char**) &logMapping,
            &valueSize);
        if (error)
        {
            IPAddressToString(&ip->ip_src, tmp);
            sprintf(err, "Address \"%s\" does not match what we are sniffing "
                        "for", tmp);
            ERROR_ReportWarning(err);
            return;
        }
        assert(valueSize == sizeof(IPNE_NodeMapping));

        logIpSrc = ntohl(logMapping->realAddress);

        printf(
            "<<< Received IP packet -------------------"
            "-------------------------------------\n");
        IO_ConvertIpAddressToString(logIpSrc, tempString);
        printf(
            "    source: %20s    protocol: %5d    tos: 0x%0x\n",
            tempString,
            ip->ip_p,
            ip->ip_tos);
        IO_ConvertIpAddressToString(ipDestAddr, tempString);
        printf(
            "    dest  : %20s    id      : %5d    ttl: %d\n",
            tempString,
            ip->ip_id,
            ip->ip_ttl);
        IO_ConvertIpAddressToString(srcAddr, tempString);
        printf(
            "    via   : %20s    offset  : %5d    payload: %u\n",
            tempString,
            ntohs(ip->ip_off) & 0x1FFF,
            (Int32)(packetSize - IPNE_ETHERNET_HEADER_LENGTH
                    - ipHeaderLength));
        printf("------------------------------------------"
                "----------------------------------<<<\n");
        fflush(stdout);
    }


//  DiffServ support
    TosType tos = ip->ip_tos;
//  DiffServ support

    // Send packet through QualNet using UDP
    EXTERNAL_SendDataAppLayerUDP(
        iface,                  // interface
        srcAddr,                // sending address
        ipDestAddr,             // destination address
        (char*) packet,         // payload
        packetSize,             // size
        EXTERNAL_QueryExternalTime(iface), //timestamp
        APP_FORWARD, // application type
        TRACE_FORWARD, // trace
        tos); // priority
}

// /**
// API       :: EmualateIpPacketNatNo
// PURPOSE   :: This function will add a packet to the qualnet simulation
//              for use in Nat-No mode.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + ip : struct libnet_ipv4_hdr* : Pointer to the ip header
// + ipHeaderLength : int : Length of the IPh eader in bytes
// RETURN    :: void
// **/
void EmulateIpPacketNatNo(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    struct libnet_ipv4_hdr* ip,
    int ipHeaderLength)
{
    IPNEData* data;

    // ipSrcAddr is the IP address of the operational host that originated
    // this packet.  For Nat-No this is also the ip address of the qualnet
    // node to send the packet from.
    NodeAddress ipSrcAddr;

    // ipDestAddr is the IP address of the operational host that is the
    // destination of this packet
    NodeAddress ipDestAddr;

    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Extract the IP src/dest addresses, convert to host byte order
    ipDestAddr = ntohl(LibnetIpAddressToULong(ip->ip_dst));
    ipSrcAddr = ntohl(LibnetIpAddressToULong(ip->ip_src));

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
        IO_ConvertIpAddressToString(ipSrcAddr, tempString);
        printf("    via   : %20s    offset  : %5d    payload: %u\n",\
            tempString,
            ntohs(ip->ip_off) & 0x1FFF,
            (Int32)(packetSize - IPNE_ETHERNET_HEADER_LENGTH
                    - ipHeaderLength));
        printf("------------------------------------------"
                "----------------------------------<<<\n");
        fflush(stdout);
    }

    TosType tos = ip->ip_tos;

    // This is not true emulation, so send the packet using UDP
    EXTERNAL_SendDataAppLayerUDP(
        iface,                  // interface
        ipSrcAddr,              // sending address
        ipDestAddr,             // destination address
        (char*) packet,         // payload
        packetSize,             // size
        EXTERNAL_QueryExternalTime(iface), // timestamp
        APP_FORWARD, // application type
        TRACE_FORWARD, // trace
        tos); // priority
}

// /**
// API       :: EmualateIpPacketTrueEmulation
// PURPOSE   :: This function will add a packet to the qualnet simulation
//              for use in True-Emulation mode.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// + ip : struct libnet_ipv4_hdr* : Pointer to the ip header
// + ipHeaderLength : int : Length of the IPh eader in bytes
// RETURN    :: void
// **/
void EmulateIpPacketTrueEmulation(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize,
    struct libnet_ipv4_hdr* ip,
    int ipHeaderLength)
{
    IPNEData* data;
    struct libnet_ethernet_hdr* ethernet;
    char* payload;
    size_t payloadSize;
    IPNE_NodeMapping* mapping;
    int valueSize;
    int error;

    // srcAddr is the IP address of the QualNet node that will forward the
    // message
    NodeAddress srcAddr;

    // ipSrcAddr is the IP address of the operational host that originated
    // this packet
    NodeAddress ipSrcAddr;

    // ipDestAddr is the IP address of the operational host that is the
    // destination of this packet
    NodeAddress ipDestAddr;

    data = (IPNEData*) iface->data;
    assert(data != NULL);


    // Extract the IP src/dest addresses
    ipDestAddr = ntohl(LibnetIpAddressToULong(ip->ip_dst)); // dest address
    ipSrcAddr = ntohl(LibnetIpAddressToULong(ip->ip_src));  // src address

    // Inject the packet at the node that corresponds to the MAC address the
    // packet was sniffed on
    ethernet = (struct libnet_ethernet_hdr*) packet;


    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) ethernet->ether_shost,
        6,
        (char**) &mapping,
        &valueSize);
    if (error)
    {
        if (data->debug)
        {
            printf(
                "IPNE received packet for unknown mac address "
                "%02x:%02x:%02x:%02x:%02x:%02x   %02x:%02x:%02x:%02x:%02x:%02x\n",
                (UInt8) ethernet->ether_shost[0],
                (UInt8) ethernet->ether_shost[1],
                (UInt8) ethernet->ether_shost[2],
                (UInt8) ethernet->ether_shost[3],
                (UInt8) ethernet->ether_shost[4],
                (UInt8) ethernet->ether_shost[5],
                (UInt8) ethernet->ether_dhost[0],
                (UInt8) ethernet->ether_dhost[1],
                (UInt8) ethernet->ether_dhost[2],
                (UInt8) ethernet->ether_dhost[3],
                (UInt8) ethernet->ether_dhost[4],
                (UInt8) ethernet->ether_dhost[5]);
        }

        // Return without adding the packet
        return;
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));
    srcAddr = ntohl(mapping->realAddress);

        // nextHopAddr is the IP adresss of the next hop host that this
        // packet should be forwarded to  
    NodeAddress nextHopAddr = INVALID_ADDRESS;

    if (data->macSpoofingEnabled)
    {
        if (isBroadcast(ethernet->ether_dhost,6) == -1) 
        {
            // get IP address from MAC address
            memcpy(&nextHopAddr, ethernet->ether_dhost+2, 4);
            nextHopAddr = ntohl(nextHopAddr);
            //printf("next hop addr = %x\n", nextHopAddr); 
            //printf("src hop addr = %x\n", srcAddr); 
    
            //get node   
            NodeAddress nodeId;
            Node* node;
            nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                iface->partition->firstNode,
                srcAddr);
            assert(nodeId != INVALID_MAPPING);
            node = MAPPING_GetNodePtrFromHash(
                iface->partition->nodeIdHash,
                nodeId);
            assert(node != NULL);
    
            //get interface index
            int interfaceIndex;
            interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(
                    node, srcAddr);
    
            //get subnet mask
            NodeAddress subnetMask;
            subnetMask = MAPPING_GetSubnetMaskForDestAddress( node, node->nodeId, nextHopAddr);
    
            // call NetworkUpdateForwardingTable up update routing table
            NetworkUpdateForwardingTable(
                 node,
                ipDestAddr,
                subnetMask,
                nextHopAddr,
                interfaceIndex,
                1,
                ROUTING_PROTOCOL_DEFAULT);
        }                                                                    
    }

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
        printf("    via   : %20s    offset  : %5d    payload: %u\n",\
            tempString,
            ntohs(ip->ip_off) & 0x1FFF,
            (Int32)(packetSize - IPNE_ETHERNET_HEADER_LENGTH
                    - ipHeaderLength));
        printf(
            "------------------------------------------"
            "----------------------------------<<<\n");
        fflush(stdout);
    }

    // The size of the qualnet packet will be the TCP header plus
    // the packet's data.  That is, the payload size minus the
    // ethernet and IP headers.
    payload = (char*) packet + IPNE_ETHERNET_HEADER_LENGTH + ipHeaderLength;
    payloadSize = packetSize - IPNE_ETHERNET_HEADER_LENGTH - ipHeaderLength;

    // Handle fragmentation/offset if necessary 
    BOOL dontFragment = (ntohs(ip->ip_off) & 0x4000) != 0;
    BOOL moreFragments = (ntohs(ip->ip_off) & 0x2000) != 0;
    UInt16 fragmentOffset = ntohs(ip->ip_off) & 0x1FFF;

    // Send the packet through QualNet at the network layer
    EXTERNAL_SendDataNetworkLayer(
        iface,
        srcAddr,
        ipSrcAddr,
        ipDestAddr,
        ip->ip_id,
        dontFragment,
        moreFragments,
        fragmentOffset,
        ip->ip_tos,
        ip->ip_p,
        ip->ip_ttl,
        payload,
        payloadSize,
        ipHeaderLength,
        NULL,
        EXTERNAL_QueryExternalTime(iface),
        nextHopAddr);

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
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: void
// **/
void EmulateIpPacket(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    int packetSize)
{
    IPNEData* data;
    struct libnet_ipv4_hdr* ip;
    int ipHeaderLength;
    clocktype interfaceTime;

    data = (IPNEData*) iface->data;
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
    ip = (struct libnet_ipv4_hdr*) (packet + IPNE_ETHERNET_HEADER_LENGTH);
    ipHeaderLength = ip->ip_hl * 4;

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

    // Emulate the packet in Nat-Yes, Nat-No or True emulation mode
    if (data->nat)
    {
        EmulateIpPacketNatYes(iface, packet, packetSize, ip, ipHeaderLength);
    }
    else if (data->trueEmulation)
    {
        EmulateIpPacketTrueEmulation(iface, packet, packetSize, ip, ipHeaderLength);
    }
    else
    {
        EmulateIpPacketNatNo(iface, packet, packetSize, ip, ipHeaderLength);
    }
    //MEM_free(packet);

    // Handle statistics
    HandleIPStatisticsReceivePacket(iface, interfaceTime);
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
BOOL IPNE_ForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg)
{
    UInt16 offset;
    IpHeaderType *ipHeader;
    int ipHeaderLength;
    static EXTERNAL_Interface *ipne = NULL;
    static IPNEData *ipneData = NULL;

    // Get IPNE external interface
    if (ipne == NULL)
    {
        ipne = EXTERNAL_GetInterfaceByName(
            &node->partitionData->interfaceList,
            "IPNE");
        ERROR_Assert(ipne != NULL, "IPNE not loaded");

        ipneData = (IPNEData*) ipne->data;
    }

    // Only forward from network layer if using true emulation
    if (ipneData->trueEmulation)
    {
        BOOL inject;
        ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

        struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*) MESSAGE_ReturnPacket(msg);

        ipHeaderLength =IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;
        //ipHeaderLength = ip->ip_hl * 4;

        // Figure out the outgoing address for this interface
        NodeAddress myAddress = MAPPING_GetInterfaceAddressForInterface(
            node,
            node->nodeId,
            interfaceIndex);

//======================



    // If this is an OLSR packet, check broadcast address and set 
    if ((ipneData->olsrEnabled) && (ipHeader->ip_dst == 0xffffffff) && (ipneData->olsrNetDirectedBroadcast))
    {
    //get net-directed broadcast address and assign to destAddr
        char pcapError[PCAP_ERRBUF_SIZE];
        unsigned int net;
        unsigned int mask;
        IPNE_NodeMapping* mapping; 
        int valueSize;
        char errString[MAX_STRING_LENGTH];
        int err;

    myAddress = htonl(myAddress);

    // Get the mapping for the destination address
    err = EXTERNAL_ResolveMapping(
        ipne,
        (char*) &myAddress,
        sizeof(NodeAddress),
        (char**) &mapping,
        &valueSize);
    if (err)
    {
        sprintf(
            errString,
            "Error resolving mapping for address 0x%x",
            ntohl(myAddress));
        ERROR_ReportError(errString);
    }
    assert(valueSize == sizeof(IPNE_NodeMapping));

        // Lookup network name/netmask
        err = pcap_lookupnet(
            ipneData->deviceArray[mapping->deviceIndex].device,
            &net,
            &mask,
            pcapError);
        if (err)
        {
            sprintf(errString, "\npcap_lookupnet : %s\n", pcapError);
            ERROR_ReportError(errString);
        }

        unsigned int netDirectedBroadcast;
        netDirectedBroadcast = ((myAddress&mask) | ~mask); 
        //printf("%x\n", newBroadcast);
        ipHeader->ip_dst = htonl(netDirectedBroadcast);
        myAddress = ntohl(myAddress);
    }
//======================


        // process outgoing packet
        inject = ProcessOutgoingIpPacket(
            ipne,
            myAddress,
            (UInt8*) ipHeader,
            MESSAGE_ReturnPacketSize(msg));

        // If the packet should be injected
        if (inject)
        {
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
            InjectIpPacketAtLinkLayer(
                ipne,
                myAddress,
//BITF
                //ip->ip_tos,
                IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),

                ipHeader->ip_id,
                offset,
                ipHeader->ip_ttl,
                ipHeader->ip_p,
                ipHeader->ip_src,
                //LibnetIpAddressToULong(ip->ip_src),
                ipHeader->ip_dst,
                //LibnetIpAddressToULong(ip->ip_dst),
                (UInt8*) msg->packet + ipHeaderLength,
                msg->packetSize - ipHeaderLength,
                EXTERNAL_QuerySimulationTime(ipne));

            // We're done.  Return TRUE: Don't process this message any more
            return TRUE;
        }
    }

    // Return FALSE: Packet was not sent to network via True-Emulation,
    return FALSE;
}

// /**
// API       :: HandleIPStatisticsReceivePacket
// PURPOSE   :: This function will compute statistics upon receiving info
//              from the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + now : clocktype : The current time
// RETURN    :: void
// **/
void HandleIPStatisticsReceivePacket(
    EXTERNAL_Interface* iface,
    clocktype now)
{
    IPNEData* data;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Increment number of received packets
    data->receivedPackets++;

    // TODO: check out why this is #if 0
#if 0
    // Update average/maximum interval if this is not the first packet
    if (data->lastReceiveTime != EXTERNAL_MAX_TIME)
    {
        interval = now - data->lastReceiveTime;
        data->avgInterval += (interval - data->avgInterval) / 32;
        if (interval > data->maxInterval)
        {
            data->maxInterval = interval;
        }
    }
    data->lastReceiveTime = now;
#endif
}

// /**
// API       :: HandleIPStatisticsSendPacket
// PURPOSE   :: This function will compute statistics upon injecting info
//              back into the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + receiveTime : clocktype : The time the packet was received.  This is
//                             the "now" value passed to
//                             HandleIPStatisticsReceive
// + now : clocktype : The current time
// RETURN    :: void
// **/
void HandleIPStatisticsSendPacket(
    EXTERNAL_Interface* iface,
    clocktype receiveTime,
    clocktype now)
{
    IPNEData* data;
    clocktype delay;
    clocktype D;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Increment number of sent packets
    data->sentPackets++;

    // Compute delay for this packet
    delay = now - receiveTime;

    // If we have a delay time for a previous packet then update jitter
    if (data->lastSendIntervalDelay != EXTERNAL_MAX_TIME)
    {
        // Compute abs(delay difference)
        if (delay > data->lastSendIntervalDelay)
        {
            D = delay - data->lastSendIntervalDelay;
        }
        else
        {
            D = data->lastSendIntervalDelay - delay;
        }

        // Update jitter
        data->jitter += (D - data->jitter) / 16;
    }

    // Set last delay time, used for next packet
    data->lastSendIntervalDelay = delay;
}

// /**
// API       :: AddIPSocketPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given port.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocketPort(
    IPNEData* data,
    UInt16 port,
    IPNE_SocketFunction func)
{
    if (data->debug)
    {
        printf("added port %d\n", port);
    }

    // Add a new socket based only on port by calling AddIPSocket
    AddIPSocket(
        data,
        0,
        port,
        0,
        0,
        func);
}

// /**
// API       :: AddIPSocketAddressPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given
//              address and port.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + addr : UInt32 : The address
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocketAddressPort(
    IPNEData* data,
    UInt32 addr,
    UInt16 port,
    IPNE_SocketFunction func)
{
    if (data->debug)
    {
        printf("added addr 0x%x port %d\n", addr, port);
    }

    // Add a new socket based on addr and port by calling AddIPSocket
    AddIPSocket(
        data,
        addr,
        port,
        0,
        0,
        func);
}

// /**
// API       :: AddIPSocket
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with addr1 and port1
//              and the other end with addr2 and port2.  Any address or port
//              value that is set to 0 will be ignored.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + addr1 : UInt32 : The first address
// + port1 : UInt16 : The first port
// + addr2 : UInt32 : The second address
// + port2 : UInt16 : The second port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocket(
    IPNEData* data,
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    IPNE_SocketFunction func)
{
    IPSocket* s;
    int i;
    char err[MAX_STRING_LENGTH];

    // Make sure the socket array is not full
    if (data->numSockets == IPNE_MAX_SOCKETS)
    {
        ERROR_ReportWarning("Max IP sockets reached");
        return;
    }

    // Check for duplicate socket
    for (i = 0; i < data->numSockets; i++)
    {
        if (CompareIPSocket(
                addr1,
                port1,
                addr2,
                port2,
                &data->sockets[i]))
        {
            sprintf(err, "Duplicate socket addr1 = 0x%x port1 = %d "
                         "addr2 = 0x%x port2 = %d",
                         addr1, port1, addr2, port2);
            ERROR_ReportWarning(err);
            return;
        }
    }

    // If no duplicate, add socket
    s = &data->sockets[data->numSockets];
    s->addr1 = addr1;
    s->port1 = port1;
    s->addr2 = addr2;
    s->port2 = port2;
    s->func = func;

    data->numSockets++;
}

//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: IPNE_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              IPNEData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void IPNE_Initialize(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    IPNEData* data;

    // Create new IPNEData
    data = (IPNEData*) MEM_malloc(sizeof(IPNEData));
    memset(data, 0, sizeof(IPNEData));
    iface->data = data;

    // Set default values
    data->isAutoIPNE = false;
    data->lastReceiveTime = EXTERNAL_MAX_TIME;
    data->lastSendIntervalDelay = EXTERNAL_MAX_TIME;
    data->nat = FALSE;
    data->trueEmulation = FALSE;
    data->numArpReq = 0;
    data->numArpReceived = 0;
    data->arpRetransmission = FALSE;
    data->arpSentTime = 0;
    data->multicastEnabled = FALSE;
    data->explictlyCalculateChecksum = FALSE;
    data->routeUnknownProtocols = FALSE;
    data->debug = FALSE;
    data->printPacketLog = FALSE;
    data->printStatistics = TRUE;
    data->lastStatisticsPrint = 0;
    data->numDevices = 0;
    data->deviceArray = NULL;

    // OSPF parameters
    data->numOspfNodes = 0;
    data->ospfEnabled = FALSE;
    data->ospfSocket = -1;
    data->ospfNodeAddress = NULL;
    data->ospfNodeAddressString = NULL;

    //Start OLSR interface
    //OLSR parameters
    data->olsrEnabled = FALSE;
    data->numOlsrNodes = 0;
    data->olsrNodeAddress = NULL;
    data->olsrNodeAddressString = NULL;
    data->olsrNetDirectedBroadcast = FALSE;
    //End OLSR interface

    //PRECEDENCE
    data->precEnabled = FALSE;
    //
     //Start Rip interface
    //Rip parameters
    data->ripEnabled = FALSE;
    data->numRipNodes = 0;
    data->ripNodeAddress = NULL;
    data->ripNodeAddressString = NULL;
    //End Rip interface

}

// /**
// API       :: ExtractNumberedDevice
// PURPOSE   :: This function will take a device in the form "DEVICE-3" and
//              determine its adapter name.  Reports an error if the
//              specified device does not exist.
// PARAMETERS::
// + deviceNumberString : char* : The "DEVICE-#" string
// + device : char* : The adapter name (output)
// RETURN    :: void
// **/
void ExtractNumberedDevice(char* deviceNumberString, char* device)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char errString[MAX_STRING_LENGTH];
    int deviceChoice;
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i;

    // Get a list of all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        sprintf(errString,"Error in pcap_findalldevs: %s\n", errbuf);
        ERROR_ReportError(errString);
    }
    if (alldevs == NULL)
    {
        ERROR_ReportError("pcap_findalldevs returned nothing");
    }

    // Extract the device number from the DEVICE-# string
    deviceChoice = atoi(&deviceNumberString[7]);
    if (deviceChoice < 1)
    {
        ERROR_ReportError("Invalid device choice (less than 1)");
    }

    // Advance to the selected device
    d = alldevs;
    for (i = 1; i < deviceChoice; i++)
    {
        d = d->next;

        if (d == NULL)
        {
            if (i == 1)
            {
                sprintf(
                    errString,
                    "Invalid device DEVICE-%d, there is only 1 device",
                    deviceChoice,
                    i);
            }
            else
            {
                sprintf(
                    errString,
                    "Invalid device DEVICE-%d, there are only %d devices",
                    deviceChoice,
                    i);
            }
            ERROR_ReportError(errString);
        }
    }

    // Make sure the user is not sniffing the "any" device or the loopback
    // device
    if ((strcmp(d->name, "any") == 0) || (strcmp(d->name, "lo") == 0))
    {
        sprintf(
            errbuf,
            "Invalid DEVICE \"%s\", must not use \"any\" or \"lo\" device",
            deviceNumberString);
        ERROR_ReportError(errbuf);
    }

    // Set the device name to this device
    strcpy(device, d->name);
}

// /**
// API       :: ReadDevice
// PURPOSE   :: This function will read a device string and compute the
//              adapter name.
// PARAMETERS::
// + input : char* : The device, either a "DEVICE-#" string or adapter name
// + device : char* : The adapter name (output)
// RETURN    :: void
// **/
void ReadDevice(
    char* input,
    char* device)
{
    // If the device is "DEVICE-#"
    if (strncmp(input, "DEVICE-", 7) == 0)
    {
        // Extract the numbered device (ie, DEVICE-0 could be eth0)
        ExtractNumberedDevice(input, device);
    }
    else
    {
        // User supplied the device, nothing to do
        strcpy(device, input);
    }
}

// /**
// API       :: PrintDevices
// PURPOSE   :: Print a list of all devices
// PARAMETERS:: none
// RETURN    :: void
// **/
void PrintDevices()
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char str[MAX_STRING_LENGTH];
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int numDevices;

    // Get a list of all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        ERROR_ReportErrorArgs("Error in pcap_findalldevs: %s\n", errbuf);
    }
    if (alldevs == NULL)
    {
        ERROR_ReportError("pcap_findalldevs returned nothing");
    }

    // Print table header
    printf("\n");
    printf("+-----------------------------------------------------------------------------+\n");
    printf("| Available devices for sniffing                      "
           "                        |\n");
    printf("| Use DEVICE-# to sniff on this device or use the name "
           "explicitly             |\n");
    printf("+-----------------------------------------------------------------------------+\n");

    // Print the list of devices
    numDevices = 0;
    for (d = alldevs; d != NULL; d = d->next)
    {
        // Print each device if it is not "any" or "lo"
        if ((strcmp(d->name, "any") != 0) && (strcmp(d->name, "lo") != 0))
        {
            numDevices++;
            sprintf(str, "%d. %s (", numDevices, d->name);
            if (d->description)
            {
                strcat(str,  d->description);
            }
            else
            {
                strcat(str, "No description available");
            }
            strcat(str, ")");
            printf("|   %-74s|\n", str);
        }
    }
    printf("+-----------------------------------------------------------------------------+\n");
    printf("\n");

    // Make sure some devices are available
    ERROR_Assert(
        numDevices > 0,
        "No interfaces found!");
}

// /**
// API       :: ReadVirtualNode
// PURPOSE   :: Read a VIRTUAL-NODE line of input.  All output strings are
//              empty if not specified.
// PARAMETERS::
// + input : char* : The input string, not including VIRTUAL-NODE
// + nat : BOOL : Whether Nat-Yes mode is being used
// + realAddress : char* : Real (operational) address (output)
// + proxyAddress : char* : Qualnet address (output)
// + device : char* : The adapter name for the virtual node, local to the
//                    qualnet machine (output)
// + macAddress : char* : The mac address corresponding to the realAddress,
//                        ie the mac address of the non-qualnet machine
//                        (output)
// + multicastTransmitAddress : char * : Pointer to the array storing multicast
//                                       Transmit addresses
// + multicastReceiveRealAddress : char * : Pointer to the array storing
//                                      multicast receive addresses
// RETURN    :: void
// **/
void ReadVirtualNode(
    char* input,
    BOOL nat,
    char* realAddress,
    char* proxyAddress,
    char* device,
    char* macAddress,
    char *multicastTransmitAddress,
    char *multicastReceiveRealAddress)
{
    char err[MAX_STRING_LENGTH];
    char iotoken[MAX_STRING_LENGTH];
    char* next;
    char* token;
    BOOL gotName = FALSE;
    BOOL inRealAddress = FALSE;
    BOOL inProxyAddress = FALSE;
    BOOL inDevice = FALSE;
    BOOL inMacAddress = FALSE;
    BOOL inMulticastTransmitAddress = FALSE;
    BOOL inMulticastReceiveRealAddress = FALSE;

    // Initialize strings
    realAddress[0] = 0;
    proxyAddress[0] = 0;
    device[0] = 0;
    macAddress[0] = 0;

    // Read all lines in the input string
    token = IO_GetToken(iotoken, input, &next);
    while (token != NULL)
    {
        // If the last token was REAL-ADDRESS, PROXY-ADDRESS, DEVICE or
        // MAC-ADDRESS
        if (gotName)
        {
            if (inRealAddress)
            {
                // Read REAL-ADDRESS
                strcpy(realAddress, token);
                inRealAddress = FALSE;
            }
            else if (inProxyAddress)
            {
                // Read PROXY-ADDRESS
                strcpy(proxyAddress, token);
                inProxyAddress = FALSE;
            }
            else if (inDevice)
            {
                // Read DEVICE
                ReadDevice(token, device);
                inDevice = FALSE;
            }
            else if (inMacAddress)
            {
                // Read MAC-ADDRESS
                strcpy(macAddress, token);
                inMacAddress = FALSE;
            }
            else if (inMulticastTransmitAddress)
            {
                // Read MULTICAST-TRANSMIT-ADDRESS
                strcpy(multicastTransmitAddress, token);
                inMulticastTransmitAddress = FALSE;
            }
            else if (inMulticastReceiveRealAddress)
            {
                // Read MULTICAST-RECEIVE-REAL-ADDRESS
                strcpy(multicastReceiveRealAddress, token);
                inMulticastReceiveRealAddress = FALSE;
            }

            gotName = FALSE;
        }
        else
        {
            // The last token was not REAL-ADDRESS, PROXY-ADDRESS or DEVICE
            // so expect to read the previous 3 tokens
            if (strcmp(token, "REAL-ADDRESS") == 0)
            {
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inRealAddress = TRUE;
            }
            else if (strcmp(token, "PROXY-ADDRESS") == 0)
            {
                ERROR_Assert(
                    nat == TRUE,
                    "PROXY-ADDRESS only used for NAT=YES");
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inProxyAddress = TRUE;
            }
            else if (strcmp(token, "DEVICE") == 0)
            {
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inDevice = TRUE;
            }
            else if (strcmp(token, "MAC-ADDRESS") == 0)
            {
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inMacAddress = TRUE;
            }
            else if (strcmp(token, "MULTICAST-TRANSMIT-ADDRESS") == 0)
            {
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inMulticastTransmitAddress = TRUE;

            }
            else if (strcmp(token, "MULTICAST-RECEIVE-REAL-ADDRESS") == 0)
            {
                ERROR_Assert(
                    gotName == FALSE,
                    "Badly specified IPNE VIRTUAL-NODE");
                inMulticastReceiveRealAddress = TRUE;
            }
            else
            {
                sprintf(
                    err,
                    "Unexpected string in IPNE VIRTUAL-NODE \"%s\"",
                    token);
                ERROR_ReportError(err);
            }

            gotName = TRUE;
        }

        token = IO_GetToken(iotoken, next, &next);
    }

    if (proxyAddress[0] == 0)
        ERROR_Assert(!nat,
            "No proxy address is configured with NatYes mode");
}

// /**
// API       :: IPNE_InitializeNodes
// PURPOSE   :: This function is where the bulk of the IPNetworkEmulator
//              initialization is done.  It will:
//                  - Parse the interface configuration data
//                  - Create mappings between real <-> qualnet proxy
//                    addresses
//                  - Create instances of the FORWARD app on each node that
//                    is associated with a qualnet proxy address
//                  - Initialize the libpcap/libnet libraries using the
//                    configuration data
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void IPNE_InitializeNodes(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    IPNEData* data;
    BOOL wasFound;
    char error[MAX_STRING_LENGTH];
    int i;
    int j;
    char buf[MAX_STRING_LENGTH];
    char iotoken[MAX_STRING_LENGTH];
    char* next;
    char* token;
    BOOL isNodeId;
    IdToNodePtrMap* nodeHash;
    NodeAddress qualnetNodeID;
    NodeAddress qualnetAddress;
    NodeAddress qualnetNodeID2;
    NodeAddress qualnetAddress2;
    Node* node1;
    clocktype receiveDelay = 0;
    clocktype ipneParallelLookahead = 0;
    BOOL printDevices = FALSE;
    int deviceIndex = 0;
    int ospfNodeIndex = 0;
    int arpNodeIndex = 0;
    //Start OLSR interface
    int olsrNodeIndex = 0;
    //End OLSR interface

    //Start Rip interface
    int ripNodeIndex = 0;
    //End Rip interface

    IPNE_NodeMapping* mapping;
    NodeInput ipneInput;
    BOOL gotNat = FALSE;
    BOOL gotDevices = FALSE;

    //PRECEDENCE
    int precNodeIndex = 0;

    // Interface parameters
    int numVirtualNodes = 0;
    int nodeIndex = 0;
    char** addressDevices = NULL;
    char** qualnetAddresses = NULL;
    char** realAddresses = NULL;
    char** macAddresses = NULL;
    char **multicastTransmitAddresses = NULL;
    char **multicastReceiveRealAddresses = NULL;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // all virtual nodes should be in partition 0
    if (iface->partition->partitionId != 0) 
        return;

    // Read in the IPNE-CONFIG-FILE
    IO_ReadCachedFile(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "IPNE-CONFIG-FILE",
        &wasFound,
        &ipneInput);
    ERROR_Assert(wasFound == TRUE, "IPNE-CONFIG-FILE not specified");

    // Read each of its lines
    for (i = 0; i < ipneInput.numLines; i++)
    {
        token = IO_GetToken(iotoken, ipneInput.inputStrings[i], &next);

        if (strcmp(token, "NAT") == 0)
        {
            // TODO: must make sure this is one of the first params

            // Handle NAT parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->nat = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->nat = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE NAT config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }

            gotNat = TRUE;
        }
        else if (strcmp(token, "TRUE-EMULATION") == 0)
        {
            // TODO: must make sure this is one of the first params

            // Handle TRUE-EMULATION parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->trueEmulation = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->trueEmulation = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE TRUE-EMULATION config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "MULTICAST") == 0)
        {
            // TODO: must make sure this is one of the first params
            //Multicast only works for NAT enabled mode
            if (data->nat == FALSE)
            {
                sprintf(
                    error,
                    "Please specify NAT enabled to TRUE before setting "
                    "this option\n");
                ERROR_ReportError(error);
            }


            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->multicastEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->multicastEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE multicast config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "RECEIVE-DELAY") == 0)
        {
            // Handle RECEIVE-DELAY parameter
            token = IO_GetToken(iotoken, next, &next);
            receiveDelay = TIME_ConvertToClock(token);
        }
        else if (strcmp(token, "PRINT-DEVICES") == 0)
        {
            // Handle PRINT-DEVICES parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                printDevices = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                printDevices = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE PRINT-DEVICES config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "NUM-DEVICES") == 0)
        {
            // Handle NUM-DEVICES parameter
            token = IO_GetToken(iotoken, next, &next);
            data->numDevices = atoi(token);

            // Allocate memory for devices
            data->deviceArray = (DeviceData*)
                MEM_malloc(sizeof(DeviceData) * data->numDevices);
        }
        else if (strcmp(token, "DEVICE") == 0)
        {
            // Handle DEVICE parameter
            ERROR_Assert(
                gotNat == TRUE,
                "IPNE NAT must be specifieid before DEVICE");
            ERROR_Assert(
                deviceIndex < data->numDevices,
                "Too many devices specified!  (NUM-DEVICES not specified "
                "properly, or too small)");

            token = IO_GetToken(iotoken, next, &next);

            ReadDevice(
                token,
                data->deviceArray[deviceIndex].device);

            deviceIndex++;
            if (deviceIndex == data->numDevices)
            {
                gotDevices = TRUE;
            }
        }
        else if (strcmp(token, "NUM-VIRTUAL-NODES") == 0)
        {
            // Handle NUM-VIRTUAL-NODES parameter
            token = IO_GetToken(iotoken, next, &next);
            numVirtualNodes = atoi(token);

            // Allocate memory for correspondence arrays.  In the case of NAT
            // the real/qualnet addresses will differ.  If no NAT, real and
            // qualnet addresses will be identical.
            addressDevices = (char**) MEM_malloc(
                numVirtualNodes * sizeof(char*));
            for (j = 0; j < numVirtualNodes; j++)
            {
                addressDevices[j] = (char*) MEM_malloc(
                    MAX_STRING_LENGTH * sizeof(char));
            }

            realAddresses = (char**) MEM_malloc(
                numVirtualNodes * sizeof(char*));
            for (j = 0; j < numVirtualNodes; j++)
            {
                realAddresses[j] = (char*) MEM_malloc(
                    MAX_STRING_LENGTH * sizeof(char));
            }

            macAddresses = (char**) MEM_malloc(
                numVirtualNodes * sizeof(char*));
            for (j = 0; j < numVirtualNodes; j++)
            {
                macAddresses[j] = (char*) MEM_malloc(
                    MAX_STRING_LENGTH * sizeof(char));
            }

            //Allocate mem for multicast transmit
            multicastTransmitAddresses = (char**) MEM_malloc(
                    numVirtualNodes * sizeof(char*));

            for (j = 0; j < numVirtualNodes; j++)
            {
                multicastTransmitAddresses[j] = (char*) MEM_malloc(
                        MAX_STRING_LENGTH * sizeof(char));
            }

            //Allocate mem for multicast receive
            multicastReceiveRealAddresses = (char**) MEM_malloc(
                    numVirtualNodes * sizeof(char*));
            for (j = 0; j < numVirtualNodes; j++)
            {
                multicastReceiveRealAddresses[j] = (char*) MEM_malloc(
                        MAX_STRING_LENGTH * sizeof(char));
            }

            // If Nat-Yes
            if (data->nat)
            {
                // Allocate mem for proxy
                qualnetAddresses = (char**) MEM_malloc(
                    numVirtualNodes * sizeof(char*));
                for (j = 0; j < numVirtualNodes; j++)
                {
                    qualnetAddresses[j] = (char*) MEM_malloc(
                        MAX_STRING_LENGTH * sizeof(char));
                }
            }
            else
            {
                qualnetAddresses = realAddresses;
            }
        }
        else if (strcmp(token, "VIRTUAL-NODE") == 0)
        {
            // Handle VIRTUAL-NODE parameter
            NodeAddress nodeIdForSanity;
            Node* nodeForSanity;
            NodeAddress addrForSanity;

            ERROR_Assert(
                (gotNat == TRUE) && (gotDevices == TRUE),
                "IPNE NAT and all DEVICE parameters must be specifieid "
                "before VIRTUAL-NODE");
            ERROR_Assert(
                nodeIndex < numVirtualNodes,
                "Too many devices specified!  (NUM-VIRTUAL-NODES not "
                "specified properly, or too small)");

            ReadVirtualNode(
                    next,
                    data->nat,
                    realAddresses[nodeIndex],
                    qualnetAddresses[nodeIndex],
                    addressDevices[nodeIndex],
                    macAddresses[nodeIndex],
                    multicastTransmitAddresses[nodeIndex],
                    multicastReceiveRealAddresses[nodeIndex]);

            // If no device was specified use the 0th device
            if (addressDevices[nodeIndex] == 0)
            {
                strcpy(
                    addressDevices[nodeIndex],
                    data->deviceArray[0].device);
            }

            //sanity check: all virtual nodes should be on partition 0
            //in case of NatYes, check qualnetAddresses (proxy address) 
            // other cases, check realAddress
            if (data->nat)
                StringToAddress(qualnetAddresses[nodeIndex], &addrForSanity);
            else     
                StringToAddress(realAddresses[nodeIndex], &addrForSanity);

            //get node
            nodeIdForSanity = MAPPING_GetNodeIdFromInterfaceAddress(
                iface->partition->firstNode,
                ntohl(addrForSanity));
            //assert(nodeIdForSanity != INVALID_MAPPING);
            if (nodeIdForSanity == INVALID_MAPPING)
            { 
                sprintf(
                    error,
                    "Fail to get Node ID from address: %s", qualnetAddresses[nodeIndex]);
                ERROR_ReportError(error);
            }

            nodeForSanity = MAPPING_GetNodePtrFromHash(
                iface->partition->nodeIdHash,
                nodeIdForSanity);
            if (nodeForSanity == NULL)
            { 
                sprintf(
                    error,
                    "Node: %d  -> all virtual nodes should be on parition 0", nodeIdForSanity);
                ERROR_ReportError(error);
            }

            nodeIndex++;
        }
        else if (strcmp(token, "EXPLICITLY-CALCULATE-CHECKSUM") == 0)
        {
            // Handle EXPLICITLY-CALCULATE-CHECKSUM parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->explictlyCalculateChecksum = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->explictlyCalculateChecksum = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE EXPLICITLY-CALCULATE-CHECKSUM config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "ROUTE-UNKNOWN-PROTOCOLS") == 0)
        {
            // Handle ROUTE-UNKNOWN-PROTOCOLS parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->routeUnknownProtocols = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->routeUnknownProtocols = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE ROUTE-UNKNOWN-PROTOCOLS config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "DEBUG") == 0)
        {
            // Handle DEBUG parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->debug = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->debug = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE DEBUG config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "PRINT-PACKET-LOG") == 0)
        {
            // Handle PRINT-PACKET-LOG parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->printPacketLog = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->printPacketLog = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE PRINT-PACKET-LOG config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "PRINT-STATISTICS") == 0)
        {
            // Handle PRINT-STATISTICS parameter
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->printStatistics = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->printStatistics = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE PRINT-STATISTICS config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "OSPF") == 0)
        {
            // Read if OSPF is enabled
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->ospfEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->ospfEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE OSPF config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "NUM-OSPF-NODES") == 0)
        {
            // Read in number of operational hosts running OSPF
            ERROR_Assert(
                data->ospfEnabled == TRUE,
                "OSPF should be enabled before specifying number "
                "of ospf nodes ");

            // Read in the number of OSPF nodes
            token = IO_GetToken(iotoken, next, &next);
            data->numOspfNodes = atoi(token);
            ERROR_Assert(
                data->numOspfNodes <= numVirtualNodes,
                "Number of operational hosts running ospf "
                "should be less than or equal to  number of virtual nodes ");

            // Now allocate memory for node addresses and strings
            data->ospfNodeAddress = (NodeAddress*)
                MEM_malloc(sizeof(NodeAddress) * data->numOspfNodes);
            memset(
                data->ospfNodeAddress,
                0,
                sizeof(NodeAddress) * data->numOspfNodes);

            data->ospfNodeAddressString = (char**)
                MEM_malloc(sizeof(char*) * data->numOspfNodes);
            for (j = 0; j < data->numOspfNodes; j++)
            {
                data->ospfNodeAddressString[j] = (char*)
                    MEM_malloc(sizeof(char) * 16);
                memset(
                    data->ospfNodeAddressString[j],
                    0,
                    sizeof(char) * 16);
            }
        }
        else if (strcmp(token, "OSPF-NODE-ADDRESS") == 0)
        {
            // Read in addresses of operational hosts running OSPF
            ERROR_Assert(
                data->ospfEnabled == TRUE,
                "OSPF should be enabled before specifying ospf nodes ");
            ERROR_Assert(
                ospfNodeIndex < data->numOspfNodes,
                "Too many OSPF nodes specified!");
            token = IO_GetToken(iotoken, next, &next);

            strcpy(data->ospfNodeAddressString[ospfNodeIndex], token);

            StringToAddress(token, &data->ospfNodeAddress[ospfNodeIndex]);

            EXTERNAL_ntoh(&data->ospfNodeAddress[ospfNodeIndex],
                    sizeof(NodeAddress));

            ospfNodeIndex++;
        }
        else if (strcmp(token, "OLSR") == 0)//Start OLSR interface
        {
            // Read if OSPF is enabled
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->olsrEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->olsrEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE OLSR config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "NUM-OLSR-NODES") == 0)
        {
            // Read in number of operational hosts running OLSR
            ERROR_Assert(
                data->olsrEnabled == TRUE,
                "OLSR should be enabled before specifying number "
                "of olsr nodes ");

            // Read in the number of OLSR nodes
            token = IO_GetToken(iotoken, next, &next);
            data->numOlsrNodes = atoi(token);
            ERROR_Assert(
                data->numOlsrNodes <= numVirtualNodes,
                "Number of operational hosts running olsr "
                "should be less than or equal to  number of virtual nodes ");

            // Now allocate memory for node addresses and strings
            data->olsrNodeAddress = (NodeAddress*)
                MEM_malloc(sizeof(NodeAddress) * data->numOlsrNodes);
            memset(
                data->olsrNodeAddress,
                0,
                sizeof(NodeAddress) * data->numOlsrNodes);

            data->olsrNodeAddressString = (char**)
                MEM_malloc(sizeof(char*) * data->numOlsrNodes);
            for (j = 0; j < data->numOlsrNodes; j++)
            {
                data->olsrNodeAddressString[j] = (char*)
                    MEM_malloc(sizeof(char) * 16);
                memset(
                    data->olsrNodeAddressString[j],
                    0,
                    sizeof(char) * 16);
            }
        }
        else if (strcmp(token, "OLSR-NODE-ADDRESS") == 0)
        {
            // Read in addresses of operational hosts running OLSR
            ERROR_Assert(
                data->olsrEnabled == TRUE,
                "OLSR should be enabled before specifying olsr nodes ");
            ERROR_Assert(
                olsrNodeIndex < data->numOlsrNodes,
                "Too many OLSR nodes specified!");
            token = IO_GetToken(iotoken, next, &next);

            strcpy(data->olsrNodeAddressString[olsrNodeIndex], token);

            StringToAddress(token, &data->olsrNodeAddress[olsrNodeIndex]);

            EXTERNAL_ntoh(&data->olsrNodeAddress[olsrNodeIndex],
                    sizeof(NodeAddress));

            olsrNodeIndex++;
        }
        else if (strcmp(token, "OLSR-NET-DIRECTED-BROADCAST") == 0)  //optional 
        {
            // Broadcast address for OLSR 
            ERROR_Assert(
                data->olsrEnabled == TRUE,
                "OLSR should be enabled before specifying olsr nodes ");
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->olsrNetDirectedBroadcast = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->olsrNetDirectedBroadcast = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE OLSR config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }

        }//End OLSR interface
        //Start Rip interface
        else if (strcmp(token, "RIP") == 0)
        {
            // Read if RIP is enabled
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->ripEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->ripEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE Rip config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else if (strcmp(token, "NUM-RIP-NODES") == 0)
        {
            // Read in number of operational hosts running RIP
            ERROR_Assert(
                data->ripEnabled == TRUE,
                "RIP should be enabled before specifying number "
                "of rip nodes ");

            // Read in the number of RIP nodes
            token = IO_GetToken(iotoken, next, &next);
            data->numRipNodes = atoi(token);
            ERROR_Assert(
                data->numRipNodes <= numVirtualNodes,
                "Number of operational hosts running rip "
                "should be less than or equal to  number of virtual nodes ");

            // Now allocate memory for node addresses and strings
            data->ripNodeAddress = (NodeAddress*)
                MEM_malloc(sizeof(NodeAddress) * data->numRipNodes);
            memset(
                data->ripNodeAddress,
                0,
                sizeof(NodeAddress) * data->numRipNodes);

            data->ripNodeAddressString = (char**)
                MEM_malloc(sizeof(char*) * data->numRipNodes);
            for (j = 0; j < data->numRipNodes; j++)
            {
                data->ripNodeAddressString[j] = (char*)
                    MEM_malloc(sizeof(char) * 16);
                memset(
                    data->ripNodeAddressString[j],
                    0,
                    sizeof(char) * 16);
            }
        }
        else if (strcmp(token, "RIP-NODE-ADDRESS") == 0)
        {
            // Read in addresses of operational hosts running RIP
            ERROR_Assert(
                data->ripEnabled == TRUE,
                "RIP should be enabled before specifying rip nodes ");
            ERROR_Assert(
                ripNodeIndex < data->numRipNodes,
                "Too many RIP nodes specified!");
            token = IO_GetToken(iotoken, next, &next);

            strcpy(data->ripNodeAddressString[ripNodeIndex], token);

            StringToAddress(token, &data->ripNodeAddress[ripNodeIndex]);

            EXTERNAL_ntoh(&data->ripNodeAddress[ripNodeIndex],
                    sizeof(NodeAddress));

            ripNodeIndex++;
        }
        //End RIP interface
        else if (strcmp(token, "PRECEDENCE") == 0)
        {
            // Read if PRECEDENCE is enabled
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->precEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->precEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE PRECEDENCE config parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }

        }
        else if (strcmp(token, "NUM-PRECEDENCE-PAIRS") == 0)
        {
            // Read in number of precedence pairs
            ERROR_Assert(
                data->precEnabled == TRUE,
                "PRECEDENCE should be enabled before specifying number "
                "of PRECEDENCE pairs ");

            // Read in the number of PRECEDENCE pairs
            token = IO_GetToken(iotoken, next, &next);
            data->numPrecPairs = atoi(token);

            // Now allocate memory for node addresses
            data->precSrcAddress = (NodeAddress*)
                    MEM_malloc(sizeof(NodeAddress) * data->numPrecPairs);
            memset( data->precSrcAddress, 0,
                sizeof(NodeAddress) * data->numPrecPairs);
            data->precDstAddress = (NodeAddress*)
                    MEM_malloc(sizeof(NodeAddress) * data->numPrecPairs);
            memset( data->precDstAddress, 0,
                sizeof(NodeAddress) * data->numPrecPairs);

        }
        else if (strcmp(token, "PRIORITY") == 0)
        {
            // Read in priority and src/dst pair
            ERROR_Assert(
                data->precEnabled == TRUE,
                "PRECEDENCE should be enabled before specifying priority");
            ERROR_Assert(
                data->numPrecPairs != 0,
                "Number of PRECEDENCE pairs should be specified");

            token = IO_GetToken(iotoken, next, &next);
            data->precPriority = (char)atoi(token);
            ERROR_Assert(
                (data->precPriority >= 0) && (data->precPriority <= 7),
                "PRECEDENCE should be 0 >= and <= 7 ");

            token = IO_GetToken(iotoken, next, &next);
            while (token != NULL)
            {
                if (strcmp(token, "SOURCE-ADDRESS") == 0)
                {
                    token = IO_GetToken(iotoken, next, &next);
                    //strcpy(data->precSrcAddressString[precNodeIndex], token);
                    StringToAddress(token, &data->precSrcAddress[precNodeIndex]);
                    EXTERNAL_ntoh(&data->precSrcAddress[precNodeIndex],
                            sizeof(NodeAddress));

                }
                else if (strcmp(token, "DESTINATION-ADDRESS") == 0)
                {
                    token = IO_GetToken(iotoken, next, &next);
                    //strcpy(data->precSrcAddressString[precNodeIndex], token);
                    StringToAddress(token, &data->precDstAddress[precNodeIndex]);
                    EXTERNAL_ntoh(&data->precSrcAddress[precNodeIndex],
                            sizeof(NodeAddress));
                }

                token = IO_GetToken(iotoken, next, &next);
            }


            ERROR_Assert(
                data->precSrcAddress[precNodeIndex] != 0 ,
                "No source address for Precedence configuration");

            ERROR_Assert(
                data->precDstAddress[precNodeIndex] != 0 ,
                "No desination address for Precedence configuration");

            precNodeIndex++;
        }
        else if (strcmp(token, "MAC-SPOOFING") == 0)
        {
            // Handle MAC-SPOOFING parameter
            // for next hop issue 
            token = IO_GetToken(iotoken, next, &next);
            if (strcmp(token, "YES") == 0)
            {
                data->macSpoofingEnabled = TRUE;
            }
            else if (strcmp(token, "NO") == 0)
            {
                data->macSpoofingEnabled = FALSE;
            }
            else
            {
                sprintf(
                    error,
                    "Unknown IPNE MAC-SPOOFING config "
                    " parameter \"%s\"",
                    token);
                ERROR_ReportError(error);
            }
        }
        else
        {
            sprintf(
                error,
                "Unknown IPNE parameter \"%s\"",
                token);
            ERROR_ReportWarning(error);
        }
    }
  
    if (data->debug)
        printf("number of precedence configuration = %d\n",  precNodeIndex);

    ERROR_Assert(
        precNodeIndex ==  data->numPrecPairs,
        "number of PRECEDENCE pair mismatch");


    ERROR_Assert(
        nodeIndex ==  numVirtualNodes,
        "Too many devices specified!  (NUM-VIRTUAL-NODES not "
        "specified properly, or too small)");

    if ((data->trueEmulation == TRUE) && (data->nat == TRUE))
    {
        ERROR_ReportError("TrueEmulation mode is enabled with NAT");
    }

    if (data->trueEmulation)
    {
        // Check if all the ospf node addresses are specified
        if (data->ospfEnabled)
        {
            ERROR_Assert(
                ospfNodeIndex == data->numOspfNodes,
                "Not all OSPF node addresses specified");
        }
        // Check if all the olsr node addresses are specified
        if (data->olsrEnabled)
        {
            ERROR_Assert(
                olsrNodeIndex == data->numOlsrNodes,
                "Not all OLSR node addresses specified");
        }

        // Check if all the rip node addresses are specified
        if (data->ripEnabled)
        {
            ERROR_Assert(
                ripNodeIndex == data->numRipNodes,
                "Not all RIP node addresses specified");
        }

    }

#ifdef DERIUS
    // If using true emulation, make sure all virtual nodes have a
    // mac address
    if (data->trueEmulation)
    {
        for (i = 0; i < numVirtualNodes; i++)
        {
            if (strlen(macAddresses[i]) == 0)
            {
                sprintf(
                    error,
                    "Must specify VIRTUAL-NODE MAC-ADDRESS when using true "
                    "emulation");
                ERROR_ReportError(error);
            }
        }
    }
#endif

    // Print sniffable devices if specified
    if (printDevices)
    {
        PrintDevices();
    }

    // Set the minimum delay between calls if specified
    if (receiveDelay > 0)
    {
        EXTERNAL_SetReceiveDelay(iface, receiveDelay);
    }

    // Set up each virtual node
    nodeHash = iface->partition->nodeIdHash;
    for (i = 0; i < numVirtualNodes; i++)
    {
        // Get the node pointer
        IO_AppParseSourceString(
            iface->partition->firstNode,
            buf,
            qualnetAddresses[i],
            &qualnetNodeID,
            &qualnetAddress);

        if (PARTITION_NodeExists(iface->partition, qualnetNodeID) == FALSE)
        {
            sprintf(
                error,
                "Unknown node \"%s\"", qualnetAddresses[i]);
            ERROR_ReportError(error);
        }
        node1 = MAPPING_GetNodePtrFromHash(nodeHash, qualnetNodeID);
        if (node1 == NULL)
        {
            // This node isn't in our partition.
            continue;
        }

        node1->isIpneNode = TRUE;
        int interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(node1, qualnetAddress);
        node1->macData[interfaceIndex]->isIpneInterface = TRUE;

        // If not running under true emulation then create a FORWARD app
        // between each pair of virtual nodes
        if (!data->trueEmulation)
        {
            for (j = 0; j < numVirtualNodes; j++)
            {
                if (i == j)
                {
                    continue;
                }

                IO_AppParseSourceString(
                        iface->partition->firstNode,
                        buf,
                        qualnetAddresses[j],
                        &qualnetNodeID2,
                        &qualnetAddress2);

                AppForwardInit(
                    node1,
                    "IPNE",
                    qualnetAddress,
                    qualnetAddress2,
                    TRUE);
            }


            if (data->multicastEnabled)
            {
                //Add another Init statement with
                //node->Mcast Transmit address
                NodeAddress multicastDestination;
                StringToAddress(multicastTransmitAddresses[i],
                        &multicastDestination);
                EXTERNAL_ntoh(&multicastDestination, sizeof(NodeAddress));

                AppForwardInit(
                        node1,
                        "IPNE",
                        qualnetAddress,
                        multicastDestination,
                        TRUE);

            }

        }
    //}

    // Create mappings for each correspondence
    //for (i = 0; i < numVirtualNodes; i++)
    //{
        mapping = (IPNE_NodeMapping*) MEM_malloc(
            sizeof(IPNE_NodeMapping));
        memset(mapping, 0, sizeof(IPNE_NodeMapping));

        // Lookup the device for this virtual node
        for (j = 0; j < data->numDevices; j++)
        {
            if (strcmp(addressDevices[i], data->deviceArray[j].device) == 0)
            {
                mapping->deviceIndex = j;
                break;
            }
        }

        // Make sure it was found
        if (j == data->numDevices)
        {
            sprintf(
                error,
                "Unknown device \"%s\" for VIRTUAL-NODE",
                addressDevices[i]);
            ERROR_ReportError(error);
        }

        // Create real address from string
        StringToAddress(realAddresses[i], &mapping->realAddress);
        mapping->realAddressSize = sizeof(NodeAddress);

        strcpy(mapping->realAddressString, realAddresses[i]);
        mapping->realAddressStringSize = strlen(realAddresses[i]);

        StringToWideString(realAddresses[i], mapping->realAddressWideString);
        mapping->realAddressWideStringSize = strlen(realAddresses[i]) * 2;

        // If using Nat-Yes
        if (data->nat)
        {
            // Parse qualnet address
            IO_ParseNodeIdOrHostAddress(
                qualnetAddresses[i],
                (NodeAddress*) &mapping->proxyAddress,
                &isNodeId);
            if (isNodeId)
            {
                sprintf(error, "Passed address 0x%x is a node id",
                                mapping->proxyAddress);
                ERROR_ReportError(error);
            }

            mapping->proxyAddress = htonl(mapping->proxyAddress);
            mapping->proxyAddressSize = sizeof(NodeAddress);

            strcpy(mapping->proxyAddressString, qualnetAddresses[i]);
            mapping->proxyAddressStringSize = strlen(qualnetAddresses[i]);

            StringToWideString(
                qualnetAddresses[i],
                mapping->proxyAddressWideString);
            mapping->proxyAddressWideStringSize =
                strlen(qualnetAddresses[i]) * 2;

            //Multicast address processing
            if (data->multicastEnabled)
            {
                //Saving mcast addresses in network byte order
                StringToAddress(multicastTransmitAddresses[i],
                        &mapping->multicastTransmitAddress);
                mapping->multicastTransmitAddressSize = sizeof(NodeAddress);
                strcpy(mapping->multicastTransmitAddressString,
                        multicastTransmitAddresses[i]);

                mapping->multicastTransmitAddressStringSize =
                    strlen(multicastTransmitAddresses[i]);


                StringToWideString(
                   multicastTransmitAddresses[i],
                   mapping->multicastTransmitAddressWideString);
                mapping->multicastTransmitAddressWideStringSize =
                   strlen(multicastTransmitAddresses[i]) * 2;


                StringToAddress(multicastReceiveRealAddresses[i],
                        &mapping->multicastReceiveRealAddress);

                mapping->multicastReceiveRealAddressSize = sizeof(NodeAddress);

                strcpy(mapping->multicastReceiveRealAddressString,
                        multicastReceiveRealAddresses[i]);

                mapping->multicastReceiveRealAddressStringSize =
                    strlen(multicastReceiveRealAddresses[i]);

                StringToWideString(
                    multicastReceiveRealAddresses[i],
                    mapping->multicastReceiveRealAddressWideString);
                mapping->multicastReceiveRealAddressWideStringSize =
                strlen(multicastReceiveRealAddresses[i]) * 2;
            }
        }

        // Set mac address if given
        if (strlen(macAddresses[i]) > 0)
        {
            int macAddressInt[6];
            strcpy(mapping->macAddressString, macAddresses[i]);
            mapping->macAddressStringSize = strlen(macAddresses[i]);

            sscanf(macAddresses[i],
                   "%x:%x:%x:%x:%x:%x",
                    &macAddressInt[0],
                    &macAddressInt[1],
                    &macAddressInt[2],
                    &macAddressInt[3],
                    &macAddressInt[4],
                    &macAddressInt[5]);
            mapping->macAddress[0] = (char)macAddressInt[0];
            mapping->macAddress[1] = (char)macAddressInt[1];
            mapping->macAddress[2] = (char)macAddressInt[2];
            mapping->macAddress[3] = (char)macAddressInt[3];
            mapping->macAddress[4] = (char)macAddressInt[4];
            mapping->macAddress[5] = (char)macAddressInt[5];
            mapping->macAddressSize = 6;
        }

        // Create mapping for realAddress
        EXTERNAL_CreateMapping(
            iface,
            (char*) &mapping->realAddress,
            mapping->realAddressSize,
            (char*) mapping,
            sizeof(IPNE_NodeMapping));

        // Create mapping for realAddressString
        EXTERNAL_CreateMapping(
            iface,
            (char*) &mapping->realAddressString,
            mapping->realAddressStringSize,
            (char*) mapping,
            sizeof(IPNE_NodeMapping));

        // Create mapping for realAddressWideString
        EXTERNAL_CreateMapping(
            iface,
            (char*) &mapping->realAddressWideString,
            mapping->realAddressWideStringSize,
            (char*) mapping,
            sizeof(IPNE_NodeMapping));

        // If using Nat-Yes
        if (data->nat)
        {
            // Create mapping for proxyAddress
            EXTERNAL_CreateMapping(
                iface,
                (char*) &mapping->proxyAddress,
                mapping->proxyAddressSize,
                (char*) mapping,
                sizeof(IPNE_NodeMapping));

            // Create mapping for proxyAddressString
            EXTERNAL_CreateMapping(
                iface,
                (char*) &mapping->proxyAddressString,
                mapping->proxyAddressStringSize,
                (char*) mapping,
                sizeof(IPNE_NodeMapping));

            // Create mapping for proxyAddressWideString
            EXTERNAL_CreateMapping(
                iface,
                (char*) &mapping->proxyAddressWideString,
                mapping->proxyAddressWideStringSize,
                (char*) mapping,
                sizeof(IPNE_NodeMapping));

            if (data->multicastEnabled)
            {
                // Create mapping for multicastTransmitAddress
                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastTransmitAddress,
                        mapping->multicastTransmitAddressSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

                // Create mapping for multicastTransmitAddressString
                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastTransmitAddressString,
                        mapping->multicastTransmitAddressStringSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

                // Create mapping for multicastTransmitAddressWideString

                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastTransmitAddressWideString,
                        mapping->multicastTransmitAddressWideStringSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

                // Create mapping for multicastReceiveRealAddress
                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastReceiveRealAddress,
                        mapping->multicastReceiveRealAddressSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

                // Create mapping for multicastReceiveRealAddressString
                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastReceiveRealAddressString,
                        mapping->multicastReceiveRealAddressStringSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

                // Create mapping for multicastReceiveRealAddressWideString

                EXTERNAL_CreateMapping(
                        iface,
                        (char*) &mapping->multicastReceiveRealAddressWideString,
                        mapping->multicastReceiveRealAddressWideStringSize,
                        (char*) mapping,
                        sizeof(IPNE_NodeMapping));

            }
        }

        // If mac address given then create mapping
        if (strlen(macAddresses[i]) > 0)
        {
            // Create mapping for macAddressString
            EXTERNAL_CreateMapping(
                iface,
                (char*) &mapping->macAddress,
                mapping->macAddressSize,
                (char*) mapping,
                sizeof(IPNE_NodeMapping));

            // Create mapping for macAddressString
            EXTERNAL_CreateMapping(
                iface,
                (char*) &mapping->macAddressString,
                mapping->macAddressStringSize,
                (char*) mapping,
                sizeof(IPNE_NodeMapping));
        }
    }

    // Initialize libpcap and libnet
    InitializeSnifferInjector(
        data,
        numVirtualNodes,
        realAddresses,
        qualnetAddresses,
        multicastReceiveRealAddresses,
        iface->partition->firstNode);
    
    // If using true emulation, make sure all virtual nodes have a
    // mac address
    if (data->trueEmulation)
    {
        // Check if all the ospf node addresses are specified
        if (data->ospfEnabled)
        {
            ERROR_Assert(
                ospfNodeIndex == data->numOspfNodes,
                "Not all OSPF node addresses specified");
        }

        // Count number of nodes for ARP
        // too many for loop
        // better to have user input??
        for (i = 0; i < numVirtualNodes; i++)
        {
            if (strlen(macAddresses[i]) == 0)
            {
                data->numArpReq++;
            }
        }

        // Now allocate memory for node address for ARP 
        data->arpNodeAddress = (NodeAddress*) MEM_malloc(sizeof(NodeAddress) * data->numArpReq);
        memset(data->arpNodeAddress, 0, sizeof(NodeAddress) * data->numArpReq);

        for (i = 0; i < numVirtualNodes; i++)
        {
            if (strlen(macAddresses[i]) == 0)
            {
                StringToAddress(realAddresses[i],
                        &data->arpNodeAddress[arpNodeIndex]);
                // ARP for MAC configuration 
                arpNodeIndex++;
            }
        }
        //AutoConfMAC(iface, addressDevices[i], realAddresses[i]);
        AutoConfMAC(iface);
    }


    // Free memory
    for (i = 0; i < numVirtualNodes; i++)
    {
        MEM_free(addressDevices[i]);
        MEM_free(realAddresses[i]);
        MEM_free(macAddresses[i]);
        MEM_free(multicastTransmitAddresses[i]);
        MEM_free(multicastReceiveRealAddresses[i]);

        // If NAT-Disabled, qualnetAddresses[i] == realAddresses[i]
        if (data->nat)
        {
            MEM_free(qualnetAddresses[i]);
        }
    }
    MEM_free(addressDevices);
    MEM_free(realAddresses);
    MEM_free(macAddresses);
    MEM_free(multicastTransmitAddresses);
    MEM_free(multicastReceiveRealAddresses);

    // If NAT-Disabled, qualnetAddresses == realAddresses so don't free
    // qualnetAddresses
    if (data->nat)
    {
        MEM_free(qualnetAddresses);
    }

    // Initialize VOIP interface
    InitializeVoipInterface(iface);

    // Initialize OSPF interface if enabled
    if (data->ospfEnabled)
    {
        InitializeOspfInterface(iface);
    }
    //Start OLSR interface
    // Initialize OLSR interface if enabled
    if (data->olsrEnabled)
    {
        InitializeOlsrInterface(iface);
    }
    //End OLSR interface
}

// /**
// API       :: IPNE_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void IPNE_Receive(EXTERNAL_Interface* iface)
{
    IPNEData* data;
    UInt8* packet;
    struct pcap_pkthdr header;
    char err[MAX_STRING_LENGTH];
    int i;

    if (iface->partition->partitionId != 0)
        return;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    // Update average/maximum interval if this is not the first packet
    clocktype now = EXTERNAL_QueryExternalTime(iface);
    if (data->lastReceiveTime != EXTERNAL_MAX_TIME)
    {
        clocktype interval;
        interval = now - data->lastReceiveTime;
        data->avgReceiveDelayInterval +=
            (interval - data->avgReceiveDelayInterval) / 32;
        if (interval > data->maxReceiveDelayInterval)
        {
            data->maxReceiveDelayInterval = interval;
        }
    }
    data->lastReceiveTime = now;

    // Capture on all devices
    for (i = 0; i < data->numDevices; i++)
    {
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

            // Handle packet injection by calling HandleSniffedIPPacket
            HandleSniffedIPPacket(iface, packet, header.caplen);

            packet = (UInt8*) pcap_next(
                data->deviceArray[i].pcapFrame,
                &header);
        }
    } 
    // Timer for ARP (3 secs + 3 secs for retransmission)
    // If no ARP response for 3 secs, halts.
    if ((data->trueEmulation) && (data->numArpReceived<data->numArpReq) )
    {
        if (now - data->arpSentTime > 3 * SECOND)
        {
            if (data->arpRetransmission) //if ARP retransmission
            { 
                // Check MAC addresses are completely resolved in case of TrueEmulation mode
                // Otherwise, print error and stop.  
                sprintf(
                    err,
                    "MAC address resolution timed out or VIRTUAL-NODE MAC-ADDRESS "
                    "is not explicitly specified");
                   ERROR_ReportError(err);
            }
            else 
            {
                if (data->debug)
                    printf("\nARP retransmission\n");

                // Retransmit ARP
                AutoConfMAC(iface);
                data->arpRetransmission=TRUE;
                data->arpSentTime = now;
                data->numArpReceived = 0;
            }
        }
    }

    if (data->printStatistics)
    {

        if (now - data->lastStatisticsPrint > 3 * SECOND)
        {
            printf("IPNE statistics\n");
            printf("    real time = %8fs   sim time = %fs\n",
                (double) now / SECOND,
                (double) EXTERNAL_QuerySimulationTime(iface) / SECOND);
            printf("    in      = %-8d      jitter  = %f ms\n",
                data->receivedPackets,
                (double) data->jitter / MILLI_SECOND);
            printf("    out     = %-8d      pps     = %-8.2f\n",
                data->sentPackets,
                (double) data->sentPackets * SECOND / (now - data->lastStatisticsPrint));
            printf("    max int = %8.3f ms   avg int = %8.3f ms\n",
                (double) data->maxReceiveDelayInterval / MILLI_SECOND,
                (double) data->avgReceiveDelayInterval / MILLI_SECOND);
            data->sentPackets = 0;
            data->receivedPackets = 0;
            data->maxReceiveDelayInterval = 0;
            data->lastStatisticsPrint = now;
        }
    }
}

// /**
// API       :: IPNE_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void IPNE_Forward(
    EXTERNAL_Interface* iface,
    Node *node,
    void* forwardData,
    int forwardSize)
{
    IPNEData* data;
    BOOL inject;

    // TODO: Make sure myAddress is properly set.  Currently this value is
    // used in ProcessOutgoingIpPacket by OSPF only.  Since OSPF IPNE is called
    // from IPNE_ForwardFromnetworkLayer this is currently okay.
    NodeAddress myAddress = 0xffffffff;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);
    
    //incomcing IP is network byte order 
    //so convert to QN definition
    IpHeaderType *ipHeader;
    ipHeader = (IpHeaderType *) ((UInt8*)forwardData + IPNE_ETHERNET_HEADER_LENGTH);

    EXTERNAL_ntoh(&ipHeader->ip_v_hl_tos_len, sizeof(ipHeader->ip_v_hl_tos_len));
    unsigned int tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    // process outging packet
    inject = ProcessOutgoingIpPacket(
        iface,
        myAddress,
        (UInt8*) ipHeader,
        forwardSize);

    // Inject the packet back into to the network by calling InjectIPPacket
    if (inject)
    {
        InjectIpPacketAtNetworkLayer(
            iface,
            (UInt8*) forwardData,
            forwardSize,
            EXTERNAL_QuerySimulationTime(iface));
    }
}

// /**
// API       :: IPNE_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void IPNE_Finalize(EXTERNAL_Interface* iface)
{
    int i;

    IPNEData* data;

    assert(iface != NULL);
    data = (IPNEData*) iface->data;
    assert(data != NULL);

    for (i = 0; i < data->numDevices; i++)
    {
        // Finalize libnet and libpcap
        if (data->deviceArray[i].libnetFrame)
        {
            libnet_destroy(data->deviceArray[i].libnetFrame);
        }
        if (data->deviceArray[i].libnetLinkFrame)
        {
            libnet_destroy(data->deviceArray[i].libnetLinkFrame);
        }
        if (data->deviceArray[i].pcapFrame)
        {
            pcap_close(data->deviceArray[i].pcapFrame);
        }
    }

    MEM_free(data->deviceArray);

    if (data->ospfSocket != -1)
    {
        close(data->ospfSocket);
    }
}
