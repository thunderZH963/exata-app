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

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_util.h"
#include "external_socket.h"
#include "ipnetworkemulator.h"
#include "arp_interface.h"

void IPNE_ProcessArp(
    EXTERNAL_Interface *iface,
    UInt8* arp)
{
    IPNE_ArpPacketClass arpClass;
    char err[MAX_STRING_LENGTH];
    NodeAddress emulatedNodeId;
    NodeAddress target;
    NodeAddress arpSender;
    UInt8 dstHardwareAddress[6];
    IPNE_NodeMapping *mapping;
    int valueSize;
    int size;
    int error;
    int deviceIndex;
    IPNEData *data;
    char rAddr[16];
    struct sockaddr_in *sin;
    int i;

    arpClass.unpack(arp);

    data = (IPNEData*) iface->data;

    // Configuration for autoMAC configuration handling
    // ARP response for TrueEmulation mode
    if ((ntohs(arpClass.opcode) == ARPOP_REPLY) && (data->trueEmulation) )
    {
        if (data->debug)
        {
            printf("\nARP Response from: ");
            PrintIPAddress(arpClass.senderProtocolAddress);
            printf("\n");
        }

        // If all MAC address are resolved
        if ( (data->numArpReq == 0) ||
                (data->numArpReq == data->numArpReceived) )
            return;

        // Determine the mapping for ARP reply
        // If it's in mapping structure without MAC address, fill out
        // if it's not in mapping structure, ignore.

        // Determine the destination address
        memcpy(&target, arpClass.senderProtocolAddress, 4);

        // Get the mapping for the destination address
        error = EXTERNAL_ResolveMapping(
            iface,
            (char*) &target,
            sizeof(UInt32),
            (char**) &mapping,
            &valueSize);
        if (error)
        {
            ERROR_ReportError("Error resolving mapping");
        }
        assert(valueSize == sizeof(IPNE_NodeMapping));

        // Set mac address
        if (mapping->macAddressSize == 0)
        {
            memcpy(mapping->macAddress, arpClass.senderHardwareAddress, 6);
            mapping->macAddressSize = 6;
            mapping->macAddressStringSize = sizeof(arpClass.senderHardwareAddress);
            sprintf(mapping->macAddressString,
                    "%02x:%02x:%02x:%02x:%02x:%02x",
                    (UInt8)arpClass.senderHardwareAddress[0],
                    (UInt8)arpClass.senderHardwareAddress[1],
                    (UInt8)arpClass.senderHardwareAddress[2],
                    (UInt8)arpClass.senderHardwareAddress[3],
                    (UInt8)arpClass.senderHardwareAddress[4],
                    (UInt8)arpClass.senderHardwareAddress[5]);

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
        else
        {
            sprintf(err, "duplicate ARP response");
            ERROR_ReportWarning(err);
        }

        // Decrease the number of MAC resolve request
        data->numArpReceived++;

        return;
    }

    // ARP request: ignore if it's from local
    if (ntohs(arpClass.opcode) == ARPOP_REQUEST)
    {
        // Ignore ARP Request from local
        IPAddressToString(arpClass.senderProtocolAddress, rAddr);
        for (i=0 ; i<data->numDevices; i++)
        {
            if( strcmp( rAddr, data->deviceArray[i].ipAddress)==0 )
            {
                if (data->debug)
                    printf("Local ARQ Request\n");
                return;
            }
        }
    }

    // Verify ethernet
    if (ntohs(arpClass.hardwareType) != ARPHRD_ETHER)
    {
        sprintf(err, "Unknown hardware 0x%x", ntohs(arpClass.hardwareType));
        ERROR_ReportWarning(err);
        return;
    }

    // Verify IP
    if (ntohs(arpClass.protocolType) != ETHERTYPE_IP)
    {
        sprintf(err, "Unknown protocol 0x%x", ntohs(arpClass.protocolType));
        ERROR_ReportWarning(err);
        return;
    }

    // Verify mac address is 6 bytes
    if (arpClass.hardwareSize != ETHER_ADDR_LEN)
    {
        sprintf(err, "Unknown hardware size %d", arpClass.hardwareSize);
        ERROR_ReportWarning(err);
        assert(0);
        return;
    }

    // Verify IP address is 4 bytes
    if (arpClass.protocolSize != 4)
    {
        sprintf(err, "Unknown protocol size %d", arpClass.protocolSize);
        ERROR_ReportWarning(err);
        assert(0);
        return;
    }

    memcpy(&target, arpClass.targetProtocolAddress, 4);
    memcpy(
        &dstHardwareAddress,
        arpClass.senderHardwareAddress,
        ETHER_ADDR_LEN);

    // It was found.  Check if it is a virtual node (ie, the node exists in
    // the real network)
    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) &target,
        sizeof(NodeAddress),
        (char**) &mapping,
        &size);

    // If the node was found then it is a virtual node.  Some other host is
    // doing an ARP request for the virtual node -- ignore this request.
    // The virtual node will handle it.
    if (!error)
    {
        return;
    }

    //srd:lookup the mac address of the node sending the ARP request in the
    // mapping to obtain the device index of the interface
    error = EXTERNAL_ResolveMapping(
        iface,
        (char *)dstHardwareAddress,
        ETHER_ADDR_LEN,
        (char**) &mapping,
        &size);

    // If the mapping is not found then the host originating the ARP request
    // is not a virtual node, so ignore this ARP request.
    if (error)
    {
        return;
    }
    assert(size == sizeof(IPNE_NodeMapping));



    // MAC address of QualNet machine is not used anymore.
    // MAC address mapping is used. 

    // Determine which device the virtual node is running on
    deviceIndex = mapping->deviceIndex;

    // Lookup the device index in the data array to obtain the device to use
    UInt32 mymacInt[ETHER_ADDR_LEN];
    UInt8 mymac[ETHER_ADDR_LEN];
    assert(data->numDevices > deviceIndex);
    sscanf(
        data->deviceArray[deviceIndex].macAddress,
        "%x:%x:%x:%x:%x:%x",
        &mymacInt[0], &mymacInt[1], &mymacInt[2],
        &mymacInt[3], &mymacInt[4], &mymacInt[5]);
    mymac[0] = (UInt8)mymacInt[0];
    mymac[1] = (UInt8)mymacInt[1];
    mymac[2] = (UInt8)mymacInt[2];
    mymac[3] = (UInt8)mymacInt[3];
    mymac[4] = (UInt8)mymacInt[4];
    mymac[5] = (UInt8)mymacInt[5];

    if (data->debug)
    {
        printf(
            "    Using mac address %s\n",
            data->deviceArray[deviceIndex].macAddress);
    }

    // Check if this is the request to Emulated nodes 
    emulatedNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
        iface->partition->firstNode,
        ntohl(target));
    
    // Not found... return
    if (emulatedNodeId == ANY_DEST)
    {
        return;
    }

    if (data->debug)
    {
        printf("Got ARP request for 0x%x...\n", ntohl(target));
    }

    if (data->debug)
    {
        printf("    Maps to node id %d\n", emulatedNodeId);
    }

    UInt8 buffer[sizeof(IPNE_ArpPacketClass)];
    if(data->macSpoofingEnabled)
    {
    // MAC MAPPING
    // Create MAC address with emulated Node Address
    UInt8 myVirtualMac[ETHER_ADDR_LEN];
    myVirtualMac[0] = 0xaa;
    myVirtualMac[1] = 0xaa;
    memcpy(&myVirtualMac[2], &target, 4);

    //create ARP response 
    arpClass.pack(buffer, myVirtualMac);
    }
    else
    {
    arpClass.pack(buffer, mymac);
    }

    // get mapping based on IP for the Run time stat
    memcpy(&arpSender, arpClass.senderProtocolAddress, 4);
    error = EXTERNAL_ResolveMapping(
        iface,
        (char*) &arpSender,
        sizeof(NodeAddress),
        (char**) &mapping,
        &size);

    if (error)
    {
        return;
    }

    // Inject the packet to the operation network at the link layer
    InjectLinkPacket(
        iface,
        arpClass.senderHardwareAddress,
        //out.senderHardwareAddress,
        mymac,
        ETHERTYPE_ARP,
        buffer,
        sizeof(arpClass),
        0);
}

void
IPNE_ArpPacketClass::unpack(UInt8 * buffer)
{

    memcpy((void *)&hardwareType, (void *)buffer, 2);
    memcpy((void *)&protocolType, (void *)(buffer+2), 2);
    memcpy((void *)&hardwareSize, (void *)(buffer+4), 1);
    memcpy((void *)&protocolSize, (void *)(buffer+5), 1);
    memcpy((void *)&opcode, (void *)(buffer+6), 2);
    memcpy(senderHardwareAddress, (void *)(buffer+8), 6);
    memcpy(senderProtocolAddress, (void *)(buffer+14), 4);
    memcpy(targetHardwareAddress, (void *)(buffer+18), 6);
    memcpy(targetProtocolAddress, (void *)(buffer+24), 4);
}


void
IPNE_ArpPacketClass::pack(UInt8 * buffer, UInt8 * virtualMac)
{
    memcpy((void *)buffer, (void *)&hardwareType, 2);
    memcpy((void *)(buffer+2), (void *)&protocolType, 2);
    memcpy((void *)(buffer+4), (void *)&hardwareSize, 1);
    memcpy( (void *)(buffer+5), (void *)&protocolSize, 1);
    opcode = htons(ARPOP_REPLY);
    memcpy((void *)(buffer+6), (void *)&opcode, 2);
    memcpy((void *)(buffer+8), virtualMac, 6);
    memcpy((void *)(buffer+14), targetProtocolAddress, 4);
    memcpy((void *)(buffer+18), senderHardwareAddress, 6);
    memcpy((void *)(buffer+24), senderProtocolAddress, 4);
}
