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
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "external_util.h"
#include "auto-ipnetworkemulator.h"
#include "ipne_qualnet_interface.h"
#include "inject_interface.h"
#include "capture_interface.h"


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
void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime,
    int    deviceIndex)
{
    AutoIPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    int error;

    AutoIPNE_NodeMapping* mapping;
    int valueSize;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
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

    //Mapping for macAddress
    char macKey[10];
    BOOL success;
    int macKeySize = ETHER_ADDR_LEN + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,(char*)dest,deviceIndex);
    if (!success)
    {
        ERROR_ReportWarning("Cannot create a mapping\n");
    }
    else
    {
       error = EXTERNAL_ResolveMapping(
            iface,
            (char *)macKey,
            macKeySize,
            (char**) &mapping,
            &valueSize);
    }
    if (error)
    {
        sprintf(errString, "Error resolving mapping for address");
        ERROR_ReportError(errString);
    }
    assert(valueSize == sizeof(AutoIPNE_NodeMapping));
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

    if (data->outgoingPacketLog)
    {
        struct pcap_pkthdr header;
        unsigned char *libnetPacket;
        unsigned int libnetPacketSize;

        if (libnet_pblock_coalesce(data->deviceArray[deviceIndex].libnetLinkFrame,
            &libnetPacket,
            &libnetPacketSize))
        {
            header.len = header.caplen = libnetPacketSize;
            header.caplen = MIN(header.caplen,
                               (unsigned)data->packetLogCaptureSize);

            pcap_dump((u_char *)data->outgoingPacketLogger, &header, libnetPacket);
        }

    }

    // Handle send statistics
    if (iface->timeFunction != NULL)
    {
        AutoIPNE_HandleIPStatisticsSendPacket(
            iface,
            packetSize,
            receiveTime,
            now);
    }

    // Finalize the packet

    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}


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

int AutoIPNEDeviceIndex(EXTERNAL_Interface* ext, 
                        const std::string& devstr)
{
  assert(ext != NULL);
  AutoIPNEData* data = (AutoIPNEData*) ext->data;
  assert(data != NULL);

  for (int k(0); k < data->numDevices; k++)
  {
    AutoIPNEDeviceData* dev = &data->deviceArray[k];
    std::string entry(dev->device);

    if (entry == devstr)
    {
      return k;
    }
  }

  abort();
  return -1;
}

void AutoIPNEInterfaceSetComplement(EXTERNAL_Interface* ext,
                                    int except, 
                                    std::list<int>& exclusions)
{
  AutoIPNEData* data = (AutoIPNEData*) ext->data; 
  ERROR_Assert(data != NULL, "Cannot find the local AutoIPNEData structure");

  for (int k(0); k < data->numDevices; k++)
  {
    AutoIPNEDeviceData* dev = &data->deviceArray[k];
    if (k != except && dev->disabled == false)
    {                   
      exclusions.push_back(k);
    }
  }
} 

void AutoIPNESendRaw(EXTERNAL_Interface* ext,
                     const std::list<int>& send_list,
                     UInt8* buf,
                     int buf_size)
{
  std::list<int>::const_iterator pos = send_list.begin();

  for (; pos != send_list.end(); pos++)
  {
    int entry = *pos;
    AutoIPNEForceInject(ext, entry, buf, buf_size);
  }
}

void AutoIPNEForceInject(EXTERNAL_Interface* iface,
                         int ifdev,
                         UInt8* buf,
                         int buf_size)
{
  assert(iface != NULL);
  AutoIPNEData* data = (AutoIPNEData*) iface->data;
  assert(data != NULL);
  AutoIPNEDeviceData* dev = &data->deviceArray[ifdev];

  libnet_clear_packet(dev->libnetLinkFrame);

  int err = libnet_write_link(dev->libnetLinkFrame, buf, buf_size);

  if (err == -1)
  {
    char errString[MAX_STRING_LENGTH];

    sprintf(errString, "libnet error: %s",
            libnet_geterror(dev->libnetLinkFrame));
    ERROR_ReportWarning(errString);
  }

  libnet_clear_packet(dev->libnetLinkFrame);
}

void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime)
{
    AutoIPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    int error;
    int deviceIndex = 0;
    AutoIPNE_NodeMapping* mapping;
    int valueSize;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
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
    assert(valueSize == sizeof(AutoIPNE_NodeMapping));


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
        AutoIPNE_HandleIPStatisticsSendPacket(
            iface,
            packetSize,
            receiveTime,
            now);
    }

    if (data->outgoingPacketLog)
    {
        struct pcap_pkthdr header;
        unsigned char* libnetPacket;
        unsigned int libnetPacketSize;

        if (libnet_pblock_coalesce(data->deviceArray[deviceIndex].libnetLinkFrame,
            &libnetPacket,
            &libnetPacketSize))
        {
            header.len = header.caplen = libnetPacketSize;
            header.caplen = MIN(header.caplen, data->packetLogCaptureSize);

            pcap_dump((u_char *)data->outgoingPacketLogger, &header, libnetPacket);
        }

    }

    // Finalize the packet
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
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
void AutoIPNEInjectIpPacketAtLinkLayer(
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
    clocktype receiveTime,
    char *options,
    int ipHeaderLength)
{
    AutoIPNEData* data;
    libnet_ptag_t t;
    clocktype now;
    int err;
    char errString[MAX_STRING_LENGTH];
    UInt8 dstMacAddress[6];
    UInt8 srcMacAddress[6];
    int srcMacAddressInt[6];
    AutoIPNE_NodeMapping* mapping;
    int valueSize;

    // IP packet type
    UInt16 type = 0x0800;
    int deviceIndex;

    assert(iface != NULL);
    data = (AutoIPNEData*) iface->data;
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
        ERROR_ReportWarning(errString);
        return;
    }
    assert(valueSize == sizeof(AutoIPNE_NodeMapping));


    // Get the deviceIndex for the destination address
    deviceIndex = mapping->deviceIndex;

    // If this is an OSPF packet, switch the broadcast address to
    // 224.0.0.5.  This is needed but I'm not sure why.
    if ((protocol == IPPROTO_OSPF) && (destAddr == 0xffffffff))
    {
        destAddr = 0xe0000005;
    }


    srcAddr = htonl(srcAddr);
    destAddr = htonl(destAddr);


    // See if this is NAT Enabled mode. If so, change the destination
    // IP address except multicast packets

    if ((mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
        && (htonl(destAddr) < IP_MIN_MULTICAST_ADDRESS
        || htonl(destAddr) > IP_MAX_MULTICAST_ADDRESS))
    {
        // Recompute the checksum, if neccessary
        // In the below case, the packet is meant for me, even if I am an 
        // eavesdropping node so change the dest addr to my physical address,
        // if not then the packet is not meant for me, i am just a node
        // eavsdropping on othernodes' packets, so keep the destAddr as it is.

        if (destAddr == myAddress)
        {
            if (protocol == IPPROTO_TCP)
            {
                struct libnet_tcp_hdr* tcp;
                tcp = (struct libnet_tcp_hdr *)packet;

                UInt16* checksum = (UInt16 *)&tcp->th_sum;

                AutoIPNEIncrementallyAdjustChecksum(checksum,
                    (UInt8 *)&destAddr,
                    (UInt8 *)&(mapping->physicalAddress.interfaceAddr.ipv4),
                     sizeof(NodeAddress),
                    (UInt8 *)packet);
            }
            destAddr = mapping->physicalAddress.interfaceAddr.ipv4;
        }
    }

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
    else if (mapping->isVirtualLan)
    {
        StlMacAddress *stlMacAddr;

        std::map<int, StlMacAddress>::iterator it;
        it = mapping->virtualLanARP->find(destAddr);
        if (it == mapping->virtualLanARP->end())
        {
            char macAddress[6];
            int size;

            DetermineOperationHostMACAddress(data,
                    destAddr,
                    macAddress,
                    &size,
                    deviceIndex);

            if (macAddress == NULL)
            {
                return;
            }
    else
    {
                stlMacAddr = new StlMacAddress;
                memcpy(stlMacAddr->address, macAddress, 6);
                mapping->virtualLanARP->insert(
                    std::pair<int, StlMacAddress>(destAddr, *stlMacAddr));
            }
        }
        else
        {
            stlMacAddr= &it->second;
        }

        memcpy(dstMacAddress, stlMacAddr->address, 6);
    }
    else
    {
        // generic MAC address for Multicast packet
        if ((data->genericMulticastMac) &&
            (htonl(destAddr) >= IP_MIN_MULTICAST_ADDRESS &&
            htonl(destAddr) <= IP_MAX_MULTICAST_ADDRESS) )
        {
            //assign Multicast-Mapped MAC address (25 bits + 23 bits)
            // 00000001 00000000 01011110 0 + ...
            dstMacAddress[0] = 0x01;
            dstMacAddress[1] = 0x00;
            dstMacAddress[2] = 0x5e;

            dstMacAddress[5] = (destAddr >> 24)& 0xFF;
            dstMacAddress[4] = (destAddr >> 16) & 0xFF;
            dstMacAddress[3] = (destAddr >> 8) & 0xFF;
            dstMacAddress[3] &= 0x3F;
        }
        else
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
    else
    {
       //Pass libnet the IP options field if present
       if (ipHeaderLength > 20)
       {
           t = libnet_build_ipv4_options(
               (u_int8_t *)options,
               ipHeaderLength - 20,
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
       }


    // Pass IP header data based on the original packet
    t = libnet_build_ipv4(
        (u_int16_t)(ipHeaderLength + packetSize), // length
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
                libnet_geterror(
                           data->deviceArray[deviceIndex].libnetLinkFrame));
        ERROR_ReportWarning(errString);
    }
        else
        {
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
                    libnet_geterror(
                           data->deviceArray[deviceIndex].libnetLinkFrame));
                ERROR_ReportWarning(errString);
            }
            else
            {
                // Send the packet to the physical network at the network layer
                err = libnet_write(
                            data->deviceArray[deviceIndex].libnetLinkFrame);
                if (err == -1)
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
                    // Handle send statistics
                    if (iface->timeFunction != NULL)
                    {
                        AutoIPNE_HandleIPStatisticsSendPacket(
                            iface,
                            packetSize,
                            receiveTime,
                            now);
                    }

                    if (data->outgoingPacketLog)
                    {
                        struct pcap_pkthdr header;
                        unsigned char *libnetPacket;
                        unsigned int libnetPacketSize;

                        if (libnet_pblock_coalesce(
                          data->deviceArray[deviceIndex].libnetLinkFrame,
                            &libnetPacket,
                            &libnetPacketSize))
                        {
                            header.len = header.caplen = libnetPacketSize;
                            header.caplen
                                = MIN(header.caplen,
                                  (unsigned)data->packetLogCaptureSize);

                            pcap_dump((u_char *)data->outgoingPacketLogger,
                                      &header,
                                      libnetPacket);
                        }
                    }
                }
            }
        }
    }

    // Finalize the packet-
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}

// /**
// API       :: InjectIpPacketAtLinkLayer
// PURPOSE   :: This function will insert an IPv6 packet directly at the link
//              layer destined for the next hop of the packet i.e. the  external
//              source.  This function will create the outgoing IPv6 packet
//              based its arguments. Only the data of the outgoing packet
//              should be passed in the "packet" parameter.  All arguments
//              should be in host byte order except for packet, which will
//              be forwarded as passed. The function creates an ethernet header
//              after looking up the ethernet destination address of the next
//              hop and the corresponding source ethernet address. This
//              function then writes the packet directly at the link layer
//              avoiding the use of the nodes kernel ipv6 routing tables.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + myAddress : Address : The address of the node that is forwarding
//                             the IPv6 packet.
// + tc : UInt8 : The Traffic class
// + flow_label : UInt16 : Flow label
// + payload_length : UInt16 : Payload length
// + protocol : UInt8 : The protocol field
// + hop_lim : UInt8 : Hop limit
// + srcAddr : struct libnet_in6_addr : The source addr field
// + destAddr : struct libnet_in6_addr : The dest addr field
// + packet : UInt8* : Pointer to the packet.  ONLY the data portion
//                     of the packet.
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void AutoIPNEInjectIpPacketAtLinkLayer(
    EXTERNAL_Interface* iface,
    Address myAddress,
    UInt8 tc,
    UInt32 flow_label,
    UInt16 payload_length,
    UInt8 protocol,
    UInt8 hop_lim,
    struct libnet_in6_addr srcAddr,
    struct libnet_in6_addr destAddr,
    UInt8* packet,
    clocktype receiveTime)
{
    AutoIPNEData* data = NULL;
    libnet_ptag_t t;
    clocktype now = 0;
    Int32 err = 0;
    Int8 errString[MAX_STRING_LENGTH];
    UInt8 dstMacAddress[6];
    UInt8 srcMacAddress[6];
    Int32 srcMacAddressInt[6];
    AutoIPNE_NodeMapping* mapping;
    Int32 valueSize = 0;
    bool isInvalid = FALSE;

    Int32 deviceIndex = 0;

    ERROR_Assert(iface != NULL, "iface should not be NULL");
    data = (AutoIPNEData*)iface->data;
    ERROR_Assert(data != NULL, "data should not be NULL");

    // Get current time
    now = EXTERNAL_QueryExternalTime(iface);

    // Determine which device to send the packet on.  If there is more than
    // one device, then determine the device based on the outoing interface
    // IP address.
    // Get the mapping for the destination address
    err = EXTERNAL_ResolveMapping(iface,
                                  (char*)&myAddress.interfaceAddr.ipv6,
                                  sizeof(in6_addr),
                                  (char**)&mapping,
                                  &valueSize);
    if (err)
    {
        char tempString[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(&myAddress, tempString);
        sprintf(errString,
                "Error resolving mapping for address %s",
                 tempString);
        ERROR_ReportWarning(errString);
        return;
    }
    ERROR_Assert(valueSize == sizeof(AutoIPNE_NodeMapping),
                 "Invalid Mapping info");

    // Get the deviceIndex for the destination address
    deviceIndex = mapping->deviceIndex;

    // See if this is NAT Enabled mode. If so, change the destination
    // IP address

    if (mapping->ipneMode == AUTO_IPNE_MODE_NAT_ENABLED)
    {
        // Recompute the checksum, if neccessary
        if (memcmp(destAddr.libnet_s6_addr,
                   myAddress.interfaceAddr.ipv6.s6_addr,
                   sizeof(in6_addr)) == 0)
        {
            UInt16* checksum = NULL;
            if (protocol == IPPROTO_TCP)
            {
                struct libnet_tcp_hdr* tcp = NULL;
                tcp = (struct libnet_tcp_hdr*)packet;
                UInt16* tcp_cksum = (UInt16*)&tcp->th_sum;
                checksum = tcp_cksum ;
            }
            else if (protocol == IPPROTO_UDP)
            {
                struct libnet_udp_hdr* udp
                    = (struct libnet_udp_hdr*)packet;
                UInt16* udp_cksum = (UInt16*)&udp->uh_sum;
                checksum = udp_cksum;
            }
            else if (protocol == IPPROTO_ICMPV6)
            {
                struct libnet_icmpv6_hdr* icp =
                                          (struct libnet_icmpv6_hdr*)packet;
                UInt16* icmpv6_cksum = (UInt16*)&icp->icmp_sum;
                checksum = icmpv6_cksum;
            }
            else
            {
                isInvalid = TRUE;
                ERROR_ReportWarning("Invalid protocol packet");
            }

            if (!isInvalid)
            {
                AutoIPNEIncrementallyAdjustChecksum(checksum,
                       (UInt8*)&destAddr,
                       (UInt8*)&mapping->physicalAddress.interfaceAddr.ipv6,
                       sizeof(libnet_in6_addr),
                       (UInt8*)packet);
            }

            for (int j = 0; j < 16; j++)
            {
                destAddr.libnet_s6_addr[j] =
                 mapping->physicalAddress.interfaceAddr.ipv6.s6_addr[j];
            }
        }
    }

    if (data->printPacketLog)
    {
        char tempString[MAX_STRING_LENGTH];

        printf(
            ">>> Forwarding IP packet at Link Layer -----------------"
            "-----------------------\n");
        IO_ConvertIpAddressToString((char*)&srcAddr, tempString, false);
        printf(
            "    source: %20s    protocol: %5d    flow label: 0x%0x\n",
            tempString,
            protocol,
            flow_label);
        IO_ConvertIpAddressToString((char*)&destAddr, tempString, false);
        printf(
            "    dest  : %20s    hop lim      : %5d    \n",
            tempString,
            hop_lim);
        IO_ConvertIpAddressToString(&myAddress, tempString);
        printf(
            "    via   : %20s  payload: %d\n",
            tempString,
            payload_length);
        printf(
            "------------------------------------------"
            "---------------------------------->>>\n");
    }

    // get destination mac address from the mapping
    // check if it is a multicast packet
    if (destAddr.libnet_s6_addr[0] == 0xff)
    {
        // Generic MAC for multicast
        dstMacAddress[0] = 0x33;
        dstMacAddress[1] = 0x33;
        dstMacAddress[2] = destAddr.libnet_s6_addr[12];
        dstMacAddress[3] = destAddr.libnet_s6_addr[13];
        dstMacAddress[4] = destAddr.libnet_s6_addr[14];
        dstMacAddress[5] = destAddr.libnet_s6_addr[15];
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
    t = libnet_build_data(packet,            // payload
                          payload_length,        // payload size
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
        t = libnet_build_ipv6(tc, // traffic class
                             flow_label, //
                             payload_length,
                             protocol,
                             hop_lim,
                             srcAddr,
                             destAddr,
                             NULL, // payload (already passed)
                             0,    // payload size (already passed)
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
            // Build the ethernet header
            t = libnet_build_ethernet(
                dstMacAddress,
                srcMacAddress,
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
                // Send the packet to the physical network at the network layer
                err = libnet_write(data->deviceArray[deviceIndex].libnetLinkFrame);
                if (err == -1)
                {
                    sprintf(
                       errString,
                       "libnet error: %s",
                       libnet_geterror(
                           data->deviceArray[deviceIndex].libnetLinkFrame));
                    ERROR_ReportWarning(errString);
                }

                 // Handle send statistics
                if (iface->timeFunction != NULL)
                {
                    AutoIPNE_HandleIPStatisticsSendPacket(
                        iface,
                        payload_length,
                        receiveTime,
                        now);
                }
            }
        }

    }

    // Finalize the packet-
    libnet_clear_packet(data->deviceArray[deviceIndex].libnetLinkFrame);
}




void AutoIPNEInitializeInjectInterface(
    AutoIPNEData *data)
{
    /* AutoIPNEInitializeCaptureInterface must already have been called by now */

    // Initialize pcap and libnet
    int i;
    char errString[MAX_STRING_LENGTH];

    // libnet
    char libnetError[LIBNET_ERRBUF_SIZE];

    for (i=0; i < data->numDevices; i++)
    {
        if (data->deviceArray[i].disabled)
            continue;

        // Initialize libnet library for network layer injection
        data->deviceArray[i].libnetFrame = libnet_init(
                LIBNET_RAW4,
                data->deviceArray[i].device,
                libnetError);

        if (data->deviceArray[i].libnetFrame == NULL)
        {
            sprintf(errString, "Cannot use device %s for emulation. Error: %s",
                                     data->deviceArray[i].device, libnetError);
            ERROR_ReportWarning(errString);
            continue;
        }

        // Initialize libnet library for link layer injection
        data->deviceArray[i].libnetLinkFrame = libnet_init(
                LIBNET_LINK,
                data->deviceArray[i].device,
                libnetError);
        if (data->deviceArray[i].libnetLinkFrame == NULL)
        {
            sprintf(errString, "Cannot use device %s for emulation. Error: %s", data->deviceArray[i].device, libnetError);
            ERROR_ReportWarning(errString);
            continue;
        }
    }
}
