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
#include "auto-ipnetworkemulator.h"
#include "arp_interface.h"
#include "inject_interface.h"

bool AutoIPNE_ProcessArp(
    EXTERNAL_Interface *iface,
    UInt8* arp,
    int deviceIndex)
{
    AutoIPNE_ArpPacketClass arpClass;
    char err[MAX_STRING_LENGTH];
    NodeAddress emulatedNodeId;
    NodeAddress target;
    NodeAddress arpSender;
    UInt8 dstHardwareAddress[6];
    AutoIPNE_NodeMapping *mapping;
    int size;
    int error;
    AutoIPNEData *data;
    char rAddr[16];
    struct sockaddr_in *sin;
    int i;

    arpClass.unpack(arp);

    data = (AutoIPNEData*) iface->data;


    // ARP request: ignore if it's from local
    if (ntohs(arpClass.opcode) == ARPOP_REQUEST)
    {
        // Ignore ARP Request from local
        IPAddressToString(arpClass.senderProtocolAddress, rAddr);
        for (i=0 ; i<data->numDevices; i++)
        {
            if (strcmp( rAddr, data->deviceArray[i].ipAddress)==0 )
            {
                ERROR_ReportWarning("Should not have got ARP request from non operational host");
                if (data->debug)
                    printf("Local ARQ Request\n");
                return false;
            }
        }
    }

    // Verify ethernet
    if (ntohs(arpClass.hardwareType) != ARPHRD_ETHER)
    {
        sprintf(err, "Unknown hardware 0x%x", ntohs(arpClass.hardwareType));
        ERROR_ReportWarning(err);
        return false;
    }

    // Verify IP
    if (ntohs(arpClass.protocolType) != ETHERTYPE_IP)
    {
        sprintf(err, "Unknown protocol 0x%x", ntohs(arpClass.protocolType));
        ERROR_ReportWarning(err);
        return false;
    }

    // Verify mac address is 6 bytes
    if (arpClass.hardwareSize != ETHER_ADDR_LEN)
    {
        sprintf(err, "Unknown hardware size %d", arpClass.hardwareSize);
        ERROR_ReportWarning(err);
        assert(0);
        return false;
    }

    // Verify IP address is 4 bytes
    if (arpClass.protocolSize != 4)
    {
        sprintf(err, "Unknown protocol size %d", arpClass.protocolSize);
        ERROR_ReportWarning(err);
        assert(0);
        return false;
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
        return false;
        //ERROR_ReportError("should not got ARP message initiated by physical node destinated for opertional node");
    }

    //lookup the mac address of the node sending the ARP request in the
    // mapping to obtain the device index of the interface
    
    char macKey[10];
    BOOL success;
    int* deviceIndexPtr = &deviceIndex;
    int macKeySize = ETHER_ADDR_LEN + sizeof(deviceIndex);
    success = AutoIPNE_CreateMacKey(macKey,(char*)dstHardwareAddress,deviceIndex);
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
            &size);
    }
    // If the mapping is not found then the host originating the ARP request
    // is not a virtual node, so ignore this ARP request.
    if (error)
    {
        //ERROR_ReportError("Should not have received ARP message from non-operation node");
        printf("Should not have received ARP message from non-operation node\n");
        return false;
    }
    assert(size == sizeof(AutoIPNE_NodeMapping));

    // MAC address of QualNet machine is not used anymore.
    // MAC address mapping is used. 

    // Determine which device the virtual node is running on

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


    // Check if this is the request to Emulated nodes 
    emulatedNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
        iface->partition->firstNode,
        ntohl(target));
    
    // Not found... return
    if (emulatedNodeId == ANY_DEST)
    {
        return false;
    }

    if (data->debug)
    {
        printf("Got ARP request for 0x%x...\n", ntohl(target));
    }

    if (data->debug)
    {
        printf("    Maps to node id %d\n", emulatedNodeId);
    }

    UInt8 buffer[sizeof(AutoIPNE_ArpPacketClass)];

    // MAC MAPPING
    UInt8 myVirtualMac[ETHER_ADDR_LEN];
    // Create MAC address with emulated Node Address
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    NodeId targetNodeId = MAPPING_GetNodeIdFromInterfaceAddress(iface->partition->firstNode, 
                                                                ntohl(target));
    int interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(iface->partition->firstNode, ntohl(target));
    MiQualnetNodeIdMapEntry* entry = AutoIPNE_FindEntryForQualNodeId((AutoIPNEData* ) iface->data, 
                                                       targetNodeId, interfaceIndex);
    if (!entry)
    {
        // no entry found in Qualnet node id map. virtual node only
        // target must be a simulated radio -> treat normally 
        myVirtualMac[0] = 0xde;
        myVirtualMac[1] = 0xad;
        memcpy(&myVirtualMac[2], &target, 4);
    }
    else
    {
        sscanf(entry->fakeMacAddressString,
           "%x:%x:%x:%x:%x:%x",
           &myVirtualMac[0], &myVirtualMac[1], &myVirtualMac[2],
           &myVirtualMac[3], &myVirtualMac[4], &myVirtualMac[5]);
    }
#else
    myVirtualMac[0] = 0xde;
    myVirtualMac[1] = 0xad;
    memcpy(&myVirtualMac[2], &target, 4);

#endif
    //create ARP response 
    arpClass.pack(buffer, myVirtualMac);
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
        return false;
    }

    // Inject the packet to the operation network at the link layer
    AutoIPNEInjectLinkPacket(
        iface,
        arpClass.senderHardwareAddress,
        //out.senderHardwareAddress,
        mymac,
        ETHERTYPE_ARP,
        buffer,
        sizeof(arpClass),
        0,
        deviceIndex);
    
    return true;
}

void
AutoIPNE_ArpPacketClass::unpack(UInt8 * buffer)
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
AutoIPNE_ArpPacketClass::pack(UInt8 * buffer, UInt8 * virtualMac)
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
