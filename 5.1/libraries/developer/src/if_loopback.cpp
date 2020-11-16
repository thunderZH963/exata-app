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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "network_ip.h"
#include "if_loopback.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif


#define DEBUG_LOOPBACK  (0)

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpIsLoopbackInterfaceAddress()
// PURPOSE      Checks for loopback host address,
//              127. 0. 0. 1 to  127. 255. 255. 254
// PARAMETERS   NodeAddress address
//                  IPv4 address.
// RETURN       (BOOL) TRUE for loopback address
//                     FALSE otherwise
//---------------------------------------------------------------------------

BOOL NetworkIpIsLoopbackInterfaceAddress(NodeAddress address)
{
    if ((address != IP_LOOPBACK_ADDRESS) &&
        ((address & IP_LOOPBACK_MASK) == IP_LOOPBACK_ADDRESS) &&
        ((address & 0xff) != 0xff))
    {
        return TRUE;
    }
    return FALSE;
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableReturnInterfaceAndNextHop()
// PURPOSE      Do a lookup on the routing table with a destination IP
//              address to obtain index of an outgoing interface
//              (= CPU_INTERFACE) and a next hop Ip address.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destinationAddress
//                  Destination IP address.
//              int *interfaceIndex
//                  Storage for index of outgoing interface.
//              NodeAddress *nextHopAddress
//                  Storage for next hop IP address.
//                  If no route can be found, *nextHopAddress will be
//                  set to NETWORK_UNREACHABLE.
// RETURN       BOOL.
//---------------------------------------------------------------------------

static
BOOL NetworkIpLoopbackForwardingTableReturnInterfaceAndNextHop(
    Node* node,
    NodeAddress destinationAddress,
    int* interfaceIndex,
    NodeAddress* nextHopAddress)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkForwardingTable* loopbackFwdTable = &(ip->loopbackFwdTable);
    int i;

    *interfaceIndex = NETWORK_UNREACHABLE;
    *nextHopAddress = (unsigned) NETWORK_UNREACHABLE;

    // NetworkIpLoopbackForwardingTableDisplay(node);

    for (i = 0; i < loopbackFwdTable->size; i++)
    {
        NodeAddress maskedDestinationAddress = MaskIpAddress(
                                destinationAddress,
                                loopbackFwdTable->row[i].destAddressMask);

        if ((loopbackFwdTable->row[i].destAddress
                == maskedDestinationAddress) &&
            (loopbackFwdTable->row[i].nextHopAddress
                != (unsigned) NETWORK_UNREACHABLE) &&
                (loopbackFwdTable->row[i].interfaceIsEnabled != FALSE))
        {
            *interfaceIndex = loopbackFwdTable->row[i].interfaceIndex;
            *nextHopAddress = loopbackFwdTable->row[i].nextHopAddress;
            return TRUE;
            break;
        }
    }
    return FALSE;
}



//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableAddEntry()
// PURPOSE      Add entry to IP Loopback Forwarding table.  Search the
//              routing table for an entry with an exact match for
//              destAddress, destAddressMask, if no matching
//              entry found, then add a new route.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeAddress destAddress
//                  IP address of destination network or host.
//              NodeAddress destAddressMask
//                  Netmask.
//              NodeAddress nextHopAddress
//                  Next hop IP address.
// RETURN       None.
//
// NOTES        The type field implies that the routing table can
//              simultaneously have entries with the same destination
//              addresses. This function sets the outgoing interface
//              to CPU_INTERFACE directly.
//---------------------------------------------------------------------------

static
void NetworkIpLoopbackForwardingTableAddEntry(
    Node* node,
    NodeAddress destAddress,
    NodeAddress destAddressMask,
    NodeAddress nextHopAddress)
{
    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkForwardingTable* loopbackFwdTable = &(ip->loopbackFwdTable);

    for (i = 0; i < loopbackFwdTable->size &&
            (loopbackFwdTable->row[i].destAddress != destAddress ||
            loopbackFwdTable->row[i].destAddressMask != destAddressMask);
            i++)
    {
        // Loop until match.
    }

    if (i == loopbackFwdTable->size)
    {
        // Need to add space to the array
        if (loopbackFwdTable->size == loopbackFwdTable->allocatedSize)
        {
            loopbackFwdTable->allocatedSize += IP_LOOPBACK_MAX_NUM_ENTRY;

            NetworkForwardingTableRow* newTableRow =
                (NetworkForwardingTableRow*) MEM_malloc(
                    loopbackFwdTable->allocatedSize
                    * sizeof(NetworkForwardingTableRow));

            if (loopbackFwdTable->row != NULL)
            {
                memcpy(newTableRow,
                       loopbackFwdTable->row,
                       loopbackFwdTable->size *
                       sizeof(NetworkForwardingTableRow));

                MEM_free(loopbackFwdTable->row);
            }

            loopbackFwdTable->row = newTableRow;

        }

        loopbackFwdTable->row[i].destAddress = destAddress;
        loopbackFwdTable->row[i].destAddressMask = destAddressMask;
        loopbackFwdTable->row[i].nextHopAddress = nextHopAddress;
        loopbackFwdTable->row[i].interfaceIndex = CPU_INTERFACE;
        loopbackFwdTable->row[i].protocolType = NETWORK_PROTOCOL_IP;
        loopbackFwdTable->row[i].interfaceIsEnabled = TRUE;
        loopbackFwdTable->row[i].adminDistance
                        = (NetworkRoutingAdminDistanceType) 0;
        loopbackFwdTable->row[i].cost = 1;
        loopbackFwdTable->size++;

    }
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableDisplay()
// PURPOSE      Display all entries in node's routing table for loopback.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackForwardingTableDisplay(Node *node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkForwardingTable *rt = &ip->loopbackFwdTable;

    int i = 0;
    char clockStr[MAX_CLOCK_STRING_LENGTH] = {0};

    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

    printf("Entries in node %u's routing table for loopback at %ss\n",
        node->nodeId, clockStr);
    printf("---------------------------------------------------------------"
        "--------------------\n");
    printf("          dest          mask        intf       nextHop"
        "    protocol    admin    Flag\n");
    printf("---------------------------------------------------------------"
        "--------------------\n");
    for (i = 0; i < rt->size; i++)
    {
        char address[20];
        IO_ConvertIpAddressToString(rt->row[i].destAddress, address);
        printf("%15s  ", address);
        IO_ConvertIpAddressToString(rt->row[i].destAddressMask, address);
        printf("%15s  ", address);
        printf("%5d", rt->row[i].interfaceIndex);
        IO_ConvertIpAddressToString(rt->row[i].nextHopAddress, address);
        printf("%15s   ", address);
        printf("%5u      ", rt->row[i].protocolType);
        printf("%5u", rt->row[i].adminDistance);

        if (rt->row[i].interfaceIsEnabled) {
            printf("       U\n");
        } else {
            printf("       D\n");
        }
    }

    printf ("\n");
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableInit()
// PURPOSE      Initialize the IP Loopback fowarding table.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackForwardingTableInit(Node *node)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    ip->loopbackFwdTable.size = 0;
    ip->loopbackFwdTable.allocatedSize = 0;
    ip->loopbackFwdTable.row = NULL;
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackInit()
// PURPOSE      The purpose of this function is Ip Loopback Interface
//              Configuration. By default loopback is enabled.
//              To disable this feature specify :
//
//              [node-id] IP-ENABLE-LOOPBACK   NO
//
//              If loopback is enabled, default loopback interface address
//              is IP_LOOPBACK_DEFAULT_INTERFACE, i.e., 127.0.0.1
//              If user want to configure default Loopback Interface Address,
//              the syntax is:
//
//              [node-id] IP-LOOPBACK-ADDRESS <loopback-interface-address>
//
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackInit(Node* node, const NodeInput* nodeInput)
{
    BOOL retVal = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IO_ReadString(
        node,
        node->nodeId,
        nodeInput,
        "IP-ENABLE-LOOPBACK",
        &retVal,
        buf);

    if (retVal && !strcmp(buf, "NO"))
    {
        ip->isLoopbackEnabled = FALSE;
        return;
    }

    if (ip->isLoopbackEnabled)
    {
        int i = 0;
        int numHostBits = 0;
        BOOL isNodeId = FALSE;
        NodeAddress loopbackAddr = 0;
        NodeAddress loopbackDefaultInterfaceAddr = 0;
        char loopbackAddrStr[MAX_STRING_LENGTH] = {0};
        char errorStr[MAX_STRING_LENGTH] = {0};

        retVal = FALSE;

        // Read Loopback interface address
        IO_ReadString(
            node->nodeId,
            ANY_IP,
            nodeInput,
            "IP-LOOPBACK-ADDRESS",
            &retVal,
            loopbackAddrStr);

        if (retVal)
        {
            IO_ParseNodeIdHostOrNetworkAddress(loopbackAddrStr,
                &loopbackAddr, &numHostBits, &isNodeId);

            if (isNodeId || (!NetworkIpIsLoopbackInterfaceAddress(
                                    loopbackAddr)))
            {
                // Error
                sprintf(errorStr,"IP Loopback: node %d\n\t"
                    "IP-LOOPBACK-ADDRESS  must be loopback interface"
                    " address", node->nodeId);

                ERROR_ReportError(errorStr);
            }

            loopbackDefaultInterfaceAddr = loopbackAddr;
        }
        else
        {
            loopbackDefaultInterfaceAddr = IP_LOOPBACK_DEFAULT_INTERFACE;
        }

        // Add default loopback interface
        NetworkIpLoopbackForwardingTableAddEntry(
            node,
            IP_LOOPBACK_ADDRESS,
            IP_LOOPBACK_MASK,
            loopbackDefaultInterfaceAddr);

        for (i = 0; i < node->numberInterfaces; i++)
        {
            NetworkIpLoopbackForwardingTableAddEntry(
                        node,
                        ip->interfaceInfo[i]->ipAddress,
                        ANY_IP, //Mask : 0xFFFFFFFF,
                        loopbackDefaultInterfaceAddr);
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackBroadcastAndMulticastToSender()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to msg
// RETURN       None.
//---------------------------------------------------------------------------

BOOL NetworkIpLoopbackLoopbackUnicastsToSender(
    Node* node,
    Message *msg)
{
    int outgoingInterface;
    NodeAddress nextHopAddress;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    if (NetworkIpLoopbackForwardingTableReturnInterfaceAndNextHop(
        node,
        ipHeader->ip_dst,
        &outgoingInterface,
        &nextHopAddress))
    {
        NetworkIpSendPacketOnInterface(node,
                              msg,
                              CPU_INTERFACE,
                              outgoingInterface,
                              ipHeader->ip_dst);
        // This was an loopback packet
        if (DEBUG_LOOPBACK)
        {
            char addrStr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(nextHopAddress, addrStr);
            printf("Node %u: Ip Datagram sent to loopback interface %s\n",
                node->nodeId, addrStr);
        }
        return TRUE;
    }
    // Not a loopback packet
    return FALSE;
}


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackBroadcastAndMulticastToSender()
// PURPOSE      Datagrams sent to a broadcast address or a multicast address
//              are copied to the loopback interface & sent out on Ethernet.
//              This is because the definition of broadcasting & multicasting
//              includes the sending host. - Ref [1]
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to msg
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackBroadcastAndMulticastToSender(
    Node* node,
    Message *msg)
{
    int outgoingInterface;
    NodeAddress nextHopAddress;
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;


    if (DEBUG_LOOPBACK)
    {
        printf("Node %u: Got Broadcast | Multicast Packet\n", node->nodeId);
    }

    if (NetworkIpLoopbackForwardingTableReturnInterfaceAndNextHop(
        node,
        ipHeader->ip_src,
        &outgoingInterface,
        &nextHopAddress))
    {

        if(NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
        {
            
            if(!NetworkIpIsPartOfMulticastGroup(node,
                ipHeader->ip_dst))
            {
                return ;
            }
#ifdef ADDON_DB
            else {
                    NetworkDataIp* ip = (NetworkDataIp *) 
                                        node->networkData.networkVar;
                    if (ip && ip->ipMulticastNetSummaryStats)
                    {
                        ip->ipMulticastNetSummaryStats->m_NumDataRecvd++;
                    }
                }
#endif
        }
        Message* copiedMsg = MESSAGE_Duplicate(node, msg);
        NetworkIpSendPacketOnInterface(node,
                                  copiedMsg,
                                  CPU_INTERFACE,
                                  outgoingInterface,
                                  ipHeader->ip_dst);

        if (DEBUG_LOOPBACK)
        {
            // Copy return successful
            char addrStr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(nextHopAddress, addrStr);
            printf("\tIp Datagram copied to loopback interface %s\n",
                addrStr);
        }
    }

    if (DEBUG_LOOPBACK)
    {
        // Copy return failed
        printf("\tIp Datagram not copied to the loopback interface\n");
    }
}

