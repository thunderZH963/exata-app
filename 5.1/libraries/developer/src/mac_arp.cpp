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

// /**
// PROTOCOL     :: Address Resolution Protocol
// LAYER        :: NETWORK
// REFERENCES   :: rfc 826
// COMMENTS     :: The present scheme supports only 802.3 mac protocol
//                 Other mac does not due to absent of hrdware address
// **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "list.h"

#include "network_ip.h"
#include "network_icmp.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#ifdef ENTERPRISE_LIB
#include "mpls.h"
#endif // ENTERPRISE_LIB
#include "mac.h"
#include "mac_link.h"
#include "mac_802_3.h"
#include "mac_arp.h"
#include "mac_llc.h"
#include "atm_logical_subnet.h"
// DHCP
#include "app_dhcp.h"


// ARP Debugs
#define ARP_DEBUG 0
#define ARPPROXY_DEBUG 0
#define ARPPROXY_PACKET_DEBUG 0
#define ARPGratuitous_DEBUG 0
#define ARPGratuitous_PACKET_DEBUG 0
#define ARP_PACKET_DEBUG 0
#define ARP_CACHE_DEBUG 0
#define STAT_TABLE_DEBUG 0
#define STAT_TABLE_INPUT_DEBUG 0
#define ARP_DATA_BUFFER 0

// use to print the ARP_DATA_Buffer related debugs
#define BUFFER 1
#define DISCARD 2


// /**
// ArpProtocolPacketFormat:
//
//  +--------+--------+--------+--------+
//  |   HardwareType  |  ProtocolType   |
//  +--------+--------+--------+--------+
//  |   HAL  |   PAL  |      OpCode     |
//  +--------+--------+--------+--------+
//  |      Source Hardware Address*     |
//  +--------+--------+--------+--------+
//  |      Source Protocol Address*     |
//  +--------+--------+--------+--------+
//  |      Target Hardware Address*     |
//  +--------+--------+--------+--------+
//  |      Target Protocol Address*     |
//  +--------+--------+--------+--------+
//
//  Note: The length of Address fields is determined by the corresponding
//        Address Length (HAL & PAL) fields. Current QualNet ARP
//        implementation only supports address resolution between
//        IP and Ethernet.
// **/

// /**
// FUNCTION    :: ArpPrintProtocolPacket
// LAYER       :: NETWORK
// PURPOSE     :: Prints ARP Request | Reply Packet
// PARAMETERS  ::
// + arpPacket  : ArpPacket* : The header of ARP
// RETURN      :: void : NULL
// **/
static
void ArpPrintProtocolPacket(ArpPacket* arpPacket)
{
    char srcstr[MAX_STRING_LENGTH] = {0};
    char dststr[MAX_STRING_LENGTH] = {0};
    MacHWAddress hwAddress;

    IO_ConvertIpAddressToString(arpPacket->s_IpAddr, srcstr);
    IO_ConvertIpAddressToString(arpPacket->d_IpAddr, dststr);
    printf("\n+--------+--------+--------+--------+\n"
        "|        %d        |       %d      |\n"
        "+--------+--------+--------+--------+\n"
        "|   %d    |   %d    |%16s |\n"
        "+--------+--------+--------+--------+\n|\t\t",
        arpPacket->hardType, arpPacket->protoType,
        arpPacket->hardSize, arpPacket->protoSize,
        (arpPacket->opCode == ARPOP_REQUEST) ?
            "ARPOP_REQUEST" : "ARPOP_REPLY");

    hwAddress.hwLength = (unsigned short)arpPacket->hardSize;
    hwAddress.byte =(unsigned char*)
                MEM_malloc(sizeof(unsigned char)* hwAddress.hwLength);
    memcpy(hwAddress.byte, arpPacket->s_macAddr, hwAddress.hwLength);
    MAC_PrintHWAddr(&hwAddress);


    printf("  |\n+--------+--------+--------+--------+\n|\t\t");
    printf("%s      \t|\n+--------+--------+--------+--------+\n|\t\t"
                                                                    ,srcstr);
    memcpy(hwAddress.byte, arpPacket->d_macAddr, hwAddress.hwLength);
    MAC_PrintHWAddr(&hwAddress);

    printf("   |\n+--------+--------+--------+--------+\n|\t\t");
    printf("%s        |\n+--------+--------+--------+--------+\n", dststr);
}

// /**
// FUNCTION    :: ArpPrintARPDataBufferDebug
// LAYER       :: NETWORK
// PURPOSE     :: Prints ARP Data Buffer Debug
// PARAMETERS  ::
// + node  : Node* : The Node Pointer
// + protocolAddress : NodeAddress
// + type : type of debug, buffer packet or discard packet
// RETURN      :: void : NULL
// **/
static
void ArpPrintARPDataBufferDebug(Node *node,
                                NodeAddress protocolAddress,
                                int type)
{

    switch (type)
    {
        case DISCARD:
        {
            char addrstr[MAX_STRING_LENGTH] = {0};
            char clockstr[MAX_STRING_LENGTH] = {0};
            clocktype curr_time = node->getNodeTime();
            IO_ConvertIpAddressToString(protocolAddress, addrstr);
            TIME_PrintClockInSecond(curr_time, clockstr);
            printf("Node %u Discarding data packet for IP Address %s at time"
                    " %s\n", node->nodeId, addrstr, clockstr);

            break;
        }

        case BUFFER:
        {
            char addrstr[MAX_STRING_LENGTH] = {0};
            char clockstr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(protocolAddress, addrstr);
            clocktype curr_time = node->getNodeTime();
            TIME_PrintClockInSecond(curr_time, clockstr);
            printf("Node %u Buffering the data packet for IP Address %s at"
                "time %s\n", node->nodeId, addrstr, clockstr);
            break;
        }
    }


}

// /**
// FUNCTION    :: ArpGetProtocolData
// LAYER       :: NETWORK
// PURPOSE     :: If thisinterface support ARP protocol, it return the
//                ArpData structure of this interface otherwise NULL
// PARAMETERS  ::
// + node      : Node* : Pointer to node.
// RETURN      :: ArpData* : ArpData structure pointer.
// **/
static
ArpData* ArpGetProtocolData(Node* node)
{
    NetworkData nwData = node->networkData;

    ERROR_Assert(nwData.isArpEnable,
                "ARP not enable in this interface\n");

    return((ArpData*)(nwData.arModule->arpData));
}

// /**
// FUNCTION    :: ArpIsEnable
// LAYER       :: NETWORK
// PURPOSE     :: The function is used for checking whether ARP is
//                enable or not.
// PARAMETERS  ::
// + node       : Node* :Pointer to node.
// RETURN      :: BOOL  : The boolean (either True or false) value
// **/
BOOL ArpIsEnable(Node* node)
{
    if (node->networkData.isArpEnable)
    {
        return TRUE;
    }

    return FALSE;
}

// /**
// FUNCTION    :: ArpIsEnable overloading
// LAYER       :: NETWORK
// PURPOSE     :: The function is used for checking whether ARP is
//                enable or not.
// PARAMETERS  ::
// + node      : Node* : Pointer to node.
// + int       : interface :Pointer to node.
// RETURN      :: BOOL  : The boolean (either True or false) value
// **/
BOOL ArpIsEnable(Node* node, int interfaceIndex)
{

    ArpData* arpData = (ArpData*)(node->networkData.arModule->arpData);

    if (arpData)
    {
        if (node->networkData.isArpEnable &&
                arpData->interfaceInfo[interfaceIndex].isEnable)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// /**
// FUNCTION    :: ArpPrintStatTable
// LAYER       :: NETWORK
// PURPOSE     :: Print ARP Table
// PARAMETERS  ::
// + node       : Node*  : Pointer to node.
// RETURN      :: void : NULL
// **/
static
void ArpPrintStatTable(Node* node)
{
    char clockStr[MAX_CLOCK_STRING_LENGTH] = {0};
    char protocolAddr[MAX_STRING_LENGTH] = {0};
    MacHWAddress hwAddress;
    ArpData* arpData = ArpGetProtocolData(node);
    ListItem* listItem = arpData->arpTTable->first;

    ctoa((node->getNodeTime() / SECOND), clockStr);


    printf("ARP Cache Table for node %u at time %s\n",
        node->nodeId, clockStr);
    printf("---------------------------------------------------------------"
        "--------------------\n");
    printf("ProtoType   ProtoAddr   RelativeInf ExpireTime"
           " EntryType   HwType  HwLength    HwAddr\n");
    printf("---------------------------------------------------------------"
        "--------------------\n");


    while (listItem != NULL)
    {
        ArpTTableElement* arpTTElement= (ArpTTableElement*)listItem->data;

       IO_ConvertIpAddressToString(arpTTElement->protocolAddr,protocolAddr);

        TIME_PrintClockInSecond(arpTTElement->expireTime, clockStr);

        printf("\t%hu\t\t%s\t\t\t%d\t\t%s\t\t%d\t\t%hu\t\t%hu\t",
            arpTTElement->protoType,
            protocolAddr,
            arpTTElement->interfaceIndex,
            clockStr,
            arpTTElement->entryType,
            arpTTElement->hwType,
            arpTTElement->hwLength);

        hwAddress.byte = arpTTElement->hwAddr;
        hwAddress.hwLength = arpTTElement->hwLength;
        MAC_PrintHWAddr(&hwAddress);
        hwAddress.byte = NULL;
        printf("\n");

        listItem = listItem->next;
    }
    printf("---------------------------------------------------------------"
        "--------------------\n");
}


// /**
// FUNCTION    :: ArpIsSupportedProtocol
// LAYER       :: NETWORK
// PURPOSE     :: This function check the suppoted protocol addr type
//                If satisfy then return TRUE otherwise FALSE.
// PARAMETERS  ::
// + prototype : unsigned short : protocol Type
// RETURN      :: BOOL : TRUE if the protocol is supported
// **/
static
BOOL ArpIsSupportedProtocol(unsigned short protoType)
{
    switch (protoType)
    {
        case PROTOCOL_TYPE_IP:
        {
            return TRUE;
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "Unknown Protocol Type\n");
            break;
        }
    }
    return FALSE; //Required to avoid warning issues
}

// /**
// FUNCTION    :: ArpCreatePacket
// LAYER       :: NETWORK
// PURPOSE     :: This function creates an ARP packet
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + arpData : ArpData* : arp main Data structure of this interface.
// + opCode : ArpOp : Type of operation i.e. Request or Reply.
// + destAddr : NodeAddress : request the Ethernet address for
//              this Ip address.
// + dstMacAddr : MacAddress : Device address
// + interfaceIndex : int : Interface of the node
// RETURN      :: Message* : Pointer to a Message structure
// **/
static
Message* ArpCreatePacket(
             Node* node,
             ArpData* arpData,
             ArpOp opCode,
             NodeAddress destAddr,
             MacHWAddress& dstMacAddr,
             int interfaceIndex)
{
    ArpPacket* arpPacket;
    unsigned short type;
    unsigned short length;
    unsigned char* hwString;

    // Last 3 three parameters are not used, MAC set its own protocol,
    // layer, event
    Message* arpMsg = MESSAGE_Alloc(node,
                                    NETWORK_LAYER,
                                    NETWORK_PROTOCOL_ARP,
                                    0);

    MESSAGE_PacketAlloc(node, arpMsg, sizeof(ArpPacket), TRACE_ARP);

    arpPacket = (ArpPacket*) arpMsg->packet;
    memset(arpPacket, 0, sizeof(ArpPacket));

    MacGetHardwareType(node, interfaceIndex, &type);
    arpPacket->hardType = type;
    MacGetHardwareLength(node, interfaceIndex, &length);
    arpPacket->hardSize = (unsigned char) length;

    memcpy(arpPacket->d_macAddr, dstMacAddr.byte, dstMacAddr.hwLength);
    hwString = (unsigned char *) MEM_malloc(sizeof(unsigned char)*length);
    memset(hwString, 0, sizeof(unsigned char)*length);
    MacGetHardwareAddressString(node, interfaceIndex, hwString);
    memcpy(arpPacket->s_macAddr, hwString, length);

    if (arpData->interfaceInfo[interfaceIndex].protoType ==
                                            PROTOCOL_TYPE_IP)
    {
        arpPacket->protoSize = ARP_PROTOCOL_ADDR_SIZE_IP;
        arpPacket->protoType = PROTOCOL_TYPE_IP;
        arpPacket->s_IpAddr =
                           NetworkIpGetInterfaceAddress(node,interfaceIndex);
        arpPacket->d_IpAddr = destAddr;
    }
    else
    {
        ERROR_Assert(FALSE, "Protocol suit not supported.\n");
    }

    arpPacket->opCode = (unsigned short)opCode;

    // ARP Debugs
    if (ARP_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        char addrstr[MAX_STRING_LENGTH] = {0};
        IO_ConvertIpAddressToString(destAddr, addrstr);

        if (arpPacket->s_IpAddr == arpPacket->d_IpAddr)
        {
            printf("ARP: Node %d sending a gratuitous packet at %s"
                   " Sec \n", node->nodeId, clockStr);
        }
        else
        {
        printf("ARP: Node %d sending a %s packet to %s at %s Sec \n",
            node->nodeId,
            (arpPacket->opCode == ARPOP_REQUEST) ? "REQUEST" : "REPLY",
            addrstr, clockStr);
        }
    }

    if (ARP_PACKET_DEBUG)
    {
        ArpPrintProtocolPacket(arpPacket);
    }
    //Trace sending pkt
    //ActionData acnData;
    //acnData.actionType = SEND;
    //acnData.actionComment = NO_COMMENT;
    //TRACE_PrintTrace(node, arpMsg, TRACE_NETWORK_LAYER,
    //                PACKET_OUT, &acnData);

    MEM_free(hwString);
    hwString = NULL;
    return(arpMsg);
}

// /**
// FUNCTION    :: EnqueueArpPacket
// LAYER       :: NETWORK
// PURPOSE     :: This function enqueues an ARP packet into the ARP Queue
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int : Interface of the node
// + msg:  Message* message to enqueue
// + arpData : ArpData* : arp main Data structure of this interface.
// + isFull : BOOL : Queue is Full or not
// + nextHop : NodeAddress : nextHop Ip address.
// + dstHWAddr : MacHWAddress& : destination hardware address address
// **/

void EnqueueArpPacket(Node* node,
                      int interfaceIndex,
                      Message *msg,
                      ArpData *arpData,
                      BOOL *isFull,
                      NodeAddress nextHop,
                      MacHWAddress& destHWAddr)
{
    QueuedPacketInfo *infoPtr = NULL;

    MESSAGE_InfoAlloc(node, msg, sizeof(QueuedPacketInfo));
    infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo(msg);

    infoPtr->nextHopAddress = nextHop;
    memcpy(infoPtr->macAddress, destHWAddr.byte, destHWAddr.hwLength);
    infoPtr->hwLength = destHWAddr.hwLength;
    infoPtr->hwType = destHWAddr.hwType;

    if (LlcIsEnabled(node, interfaceIndex))
    {
        LlcAddHeader(node, msg, PROTOCOL_TYPE_ARP);
    }

    arpData->interfaceInfo[interfaceIndex].requestQueue->insert(
                                        msg, NULL, isFull, 0, 0, 0);

}

// /**
// FUNCTION    :: DequeueArpPacket
// LAYER       :: NETWORK
// PURPOSE     :: This function dequeues an ARP packet from the ARP Queue
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int : Interface of the node
// + msg:  Message** variable for the mesaage dequeued
// + nextHop : NodeAddress : nextHop Ip address.
// + dstHWAddr : MacHWAddress& : destination hardware address address
// Return BOOL : True when message is successfully dequeued
// **/
BOOL DequeueArpPacket(Node *node,
                      int interfaceIndex,
                      Message **msg,
                      NodeAddress *nextHopAddr,
                      MacHWAddress *destMacAddr)
{
    ArpData* arpData = ArpGetProtocolData(node);
    QueuedPacketInfo *infoPtr;

    if (arpData->interfaceInfo[interfaceIndex].requestQueue->retrieve
                                                        (msg,
                                                         DEQUEUE_NEXT_PACKET,
                                                         DEQUEUE_PACKET,
                                                         0,
                                                         NULL))
    {

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));
        *nextHopAddr = infoPtr->nextHopAddress;
        destMacAddr->hwLength = infoPtr->hwLength;
        destMacAddr->hwType = infoPtr->hwType;
        if (destMacAddr->byte == NULL)
        {
            destMacAddr->byte = (unsigned char*) MEM_malloc(
                              sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(destMacAddr->byte, infoPtr->macAddress, infoPtr->hwLength);
        return TRUE;
    }

    return FALSE;
}


// /**
// FUNCTION    :: ArpQueueTopPacket
// LAYER       :: NETWORK
// PURPOSE     :: Peeks at the top packet in  ARP queue
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface for which request queue is checked
// + msg:  Message** variable for the mesaage
// + nextHop : NodeAddress : nextHop Ip address.
// + dstHWAddr : MacHWAddress& : destination hardware address address
// Return BOOL : True when message is successfully dequeued
//**/

BOOL ArpQueueTopPacket(
                  Node *node,
                  int interfaceIndex,
                  Message **msg,
                  NodeAddress *nextHopAddr,
                  MacHWAddress *destMacAddr)
{

    ArpData* arpData = ArpGetProtocolData(node);
    QueuedPacketInfo *infoPtr;

    if (arpData->interfaceInfo[interfaceIndex].requestQueue->retrieve
                                                        (msg,
                                                         DEQUEUE_NEXT_PACKET,
                                                         PEEK_AT_NEXT_PACKET,
                                                         0,
                                                         NULL))
    {

        infoPtr = (QueuedPacketInfo *) MESSAGE_ReturnInfo((*msg));
        *nextHopAddr = infoPtr->nextHopAddress;
        destMacAddr->hwLength = infoPtr->hwLength;
        destMacAddr->hwType = infoPtr->hwType;
        if (destMacAddr->byte == NULL)
        {
            destMacAddr->byte = (unsigned char*) MEM_malloc(
                              sizeof(unsigned char)*infoPtr->hwLength);
        }
        memcpy(destMacAddr->byte, infoPtr->macAddress, infoPtr->hwLength);
        return TRUE;
    }

    return FALSE;
}


// /**
// FUNCTION    :: ArpQueueIsEmpty
// LAYER       :: NETWORK
// PURPOSE     :: Checks if ARP queue is empty
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface for which request queue is checked
// RETURN: BOOL True when Queue is empty
//**/
BOOL ArpQueueIsEmpty(Node *node,
                     int interfaceIndex)
{
    ArpData* arpData = ArpGetProtocolData(node);
    return arpData->interfaceInfo[interfaceIndex].requestQueue->isEmpty();

}


// /**
// FUNCTION    :: ArpSendRequest
// LAYER       :: NETWORK
// PURPOSE     ::
//                The Address Resolution module fails to find a pair for Dst
//                Protocol Address of the packet transmitted by a higher
//                network layer. It generates an Ethernet packet with a type
//                field of ether_type$ADDRESS_RESOLUTION.
//                The Address Resolution module then sets
//                    - the ar$hrd field to ares_hrd$Ethernet,
//                    - ar$pro to the protocol type that is being resolved,
//                    - ar$hln to 6 (bytes in 48.bit Ethernet address),
//                    - ar$pln to the length of an address in that protocol,
//                    - ar$op to ares_op$REQUEST,
//                    - ar$sha with the 48.bit ethernet address of itself,
//                    - ar$spa with the protocol address of itself, and
//                    - ar$tpa with the protocol address of the machine that
//                             is trying to be accessed.
//                It does not set ar$tha to anything in particular,
//                because it
//                is this value that it is trying to determine.
//                It could set ar$tha to  broadcast address for the hardware
//                (all ones in the case of the 10Mbit Ethernet)
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + dstProtocolAddr : NodeAddress :
// + arpData : ArpData* : arp main Data structure of this interface.
// + interfaceIndex : int : in which interface this request shuld be
//                          broadcast.
// RETURN      :: void : NULL
// **/
static
void ArpSendRequest(
         Node* node,
         NodeAddress dstProtocolAddr,
         ArpData* arpData,
         int interfaceIndex)
{

    MacHWAddress destHWAddr;
    unsigned short hwLength = 0;
    unsigned short hwType = 0xffff;

    BOOL isFull = FALSE;
    BOOL wasArpQueueEmpty = ArpQueueIsEmpty(node, interfaceIndex);
    BOOL queueWasEmpty = NetworkIpOutputQueueIsEmpty(node, interfaceIndex);

    // if interface is disable do nothing
    if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
    {
        return;
    }

    MacGetHardwareLength(node, interfaceIndex, &hwLength);
    MacGetHardwareType(node, interfaceIndex, &hwType);

    destHWAddr.byte =
        (unsigned char*) MEM_malloc(sizeof(unsigned char)*hwLength);

    memset(destHWAddr.byte, 0xff, hwLength);
    destHWAddr.hwLength = hwLength;
    destHWAddr.hwType = hwType;

    // create ARP ppacket
    Message* arpRequestMsg = ArpCreatePacket(node,
                                             arpData,
                                             ARPOP_REQUEST,
                                             dstProtocolAddr,
                                             destHWAddr,
                                             interfaceIndex);

    arpData->interfaceInfo[interfaceIndex].stats.totalReqSend++;

    EnqueueArpPacket(node,
                     interfaceIndex,
                     arpRequestMsg,
                     arpData,
                     &isFull,
                     ANY_DEST,
                     destHWAddr);   //enqueue arp packet in network queue

    if (isFull)  //queue is full drop the request packet
    {
        arpData->interfaceInfo[interfaceIndex].stats.arppacketdropped++;
        MESSAGE_Free(node, arpRequestMsg);
        arpRequestMsg = NULL;

    }

    if (queueWasEmpty && wasArpQueueEmpty)
    {
         if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex) ||
             !ArpQueueIsEmpty(node, interfaceIndex))
         {
            MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
         }
    }
}


// /**
// FUNCTION    :: ArpTTableAddEntry
// LAYER       :: NETWORK
// PURPOSE     :: Overloading function used to add entry static and dynamic
//                entry
// PARAMETERS  ::
// + node : Node* : the node where the table has
// + ipAddress : NodeAddress : The interface address
// + intfIndex : int : Interface of the node
// + protocolType : unsigned short : Whether IP
// + macAddr : MacHwAddress* : mac address
// + timeOut : clocktype : Current time
// + entryType : BOOL : Static entry or dynamic entry
// RETURN      :: void : NULL
// **/
static
void ArpTTableAddEntry(
         Node* node,
         NodeAddress ipAddress,
         int intfIndex,
         unsigned short protocolType,
         MacHWAddress* macAddr,
         clocktype timeOut,
         BOOL entryType)
{
   ArpTTableElement* arpTTableElement = NULL;
   clocktype currentTime;
   ArpData* arpData = ArpGetProtocolData(node);

    // Add the entry
   arpTTableElement = (ArpTTableElement*)
                            MEM_malloc(sizeof(ArpTTableElement));
   memset(arpTTableElement, 0, sizeof(ArpTTableElement));

   ListInsert(node, arpData->arpTTable, 0, arpTTableElement);

   arpTTableElement->protocolAddr = ipAddress;
   arpTTableElement->protoType = protocolType;
   arpTTableElement->hwLength = macAddr->hwLength;

   if (entryType == ARP_ENTRY_TYPE_STATIC)
   {
        arpTTableElement->expireTime = timeOut;
        arpTTableElement->entryType = ARP_ENTRY_TYPE_STATIC;
   }

   else
   {
        arpTTableElement->entryType = ARP_ENTRY_TYPE_DYNAMIC;
        currentTime = node->getNodeTime();
        arpTTableElement->expireTime =
                                currentTime + arpData->arpExpireInterval;
   }

   memcpy(arpTTableElement->hwAddr, macAddr->byte, macAddr->hwLength);
   arpTTableElement->interfaceIndex = intfIndex;
   arpTTableElement->hwType = macAddr->hwType;

    // Update ARP Cache stats
   arpData->interfaceInfo[intfIndex].stats.totalCacheEntryCreated++;

   if (ARP_CACHE_DEBUG)
   {
        char clock[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(node->getNodeTime(), clock);
        printf("ARP Cache: Node %d Add Entry at %s Sec\n",
                                                node->nodeId, clock);
   }
}

// /**
// FUNCTION    :: ArpTTableUpdateEntry
// LAYER       :: NETWORK
// PURPOSE     :: This function updates an entry in the ArpTranslationTable
//                It update the sender hardware address field of the entry
//                with the new information in the packet and set
//                Merge_flag to true.
//                It also update the timestamp to reduce ARP flooding
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + arpData : ArpData* : ARP information
// + protoType : unsigned short : Type of the network
// + protocolAddress : NodeAddress  : The host
// + etherAddr : MacHWAddress*  : Hardware address
// + currentTime : clocktype  : The simulation time
// RETURN      :: BOOL : If success return TRUE
// **/
static
BOOL ArpTTableUpdateEntry(
         Node* node,
         ArpData* arpData,
         unsigned short protoType,
         NodeAddress protocolAddress,
         MacHWAddress* etherAddr,
         clocktype currentTime,
         int interfaceIndex)
{
    BOOL margeFlagVal = TRUE;

    // finds entry against protoType & protocolAddr.
    ArpTTableElement* arpTTableElement =
                      (ArpTTableElement*) FindItem(node,
                                                   arpData->arpTTable,
                                                   0,
                                                   (char*)&protocolAddress,
                                                   sizeof(NodeAddress));

    if (!arpTTableElement)
    {
        margeFlagVal = FALSE;
    }
    else
    {
        arpTTableElement->hwLength = etherAddr->hwLength;
        arpTTableElement->hwType = etherAddr->hwType;

        // Update the entry
        // To control ARP flooding, each entry is allowed to last for
        // 'arpExpireInterval' after it is last accessed
        arpTTableElement->expireTime =
                                currentTime + arpData->arpExpireInterval;

        memcpy(arpTTableElement->hwAddr, etherAddr->byte,
                                                        etherAddr->hwLength);

        arpData->interfaceInfo[interfaceIndex]
                              .stats.totalCacheEntryUpdated++;

        if (ARP_CACHE_DEBUG)
        {
            char clock[MAX_STRING_LENGTH] = {0};
            TIME_PrintClockInSecond(currentTime, clock);
            char addrstr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(protocolAddress, addrstr);
            printf("ARP Cache: Node %d Update Entry for IP address %s at %s"
                   " Sec\n",node->nodeId, addrstr, clock);
        }
    }

    return margeFlagVal;
}

// /**
// FUNCTION    :: ProcessArpReplyPacket
// LAYER       :: NETWORK
// PURPOSE     :: An ARP Reply packet is received, update the ARP cache table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : which will be process.
// + interfaceIndex : int  : incoming interface.
// RETURN      :: void : NULL
// **/

static void ProcessArpReplyPacket(
         Node* node,
         Message* msg,
         int interfaceIndex)
{

    ArpData* arpData = ArpGetProtocolData(node);
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    NetworkDataIcmp *icmp = (NetworkDataIcmp*) ip->icmpStruct;

    ListItem *requestListItem = NULL;

    // find if request is pendng for the IP address
    ArpRequestSentDb *db = (ArpRequestSentDb*)FindItem(
                               node,
                               arpData->interfaceInfo[interfaceIndex].arpDb,
                               0,
                               (char*)&packet->s_IpAddr,
                               sizeof(NodeAddress),
                               &requestListItem);

    //Request is still pending for the resolved mac address
   if (db)
   {
       //if arp data buffer is enable insert all packet in queue
       if ((db->arpBuffer) && (ListGetSize(node, db->arpBuffer) > 0))
       {
          NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

          BOOL queueWasEmpty = NetworkIpOutputQueueIsEmpty(
                                                     node, interfaceIndex);

          BOOL wasArpQueueEmpty = ArpQueueIsEmpty (node, interfaceIndex);

          //Insert all Buffered packet into network layer queue
          ListItem* listItem = db->arpBuffer->first;
          if (ARP_DEBUG)
          {
             printf("Node %u Inserting Buffer Packet into"
                        " Network Queue \n",node->nodeId);
          }

          while (listItem)
          {
                ArpBuffer* data = (ArpBuffer*) listItem->data;
                BOOL isFull = FALSE;

                ERROR_Assert(data != NULL,"Arp Buffer is Null");

                if (data->networkType == NETWORK_PROTOCOL_IP)
                {
                    // insert IP packet in network queue
                    IpHeaderType *ipHeader = (IpHeaderType *)
                                          MESSAGE_ReturnPacket(data->buffer);

                    NetworkIpOutputQueueInsert(node,
                                              data->interfaceIndex,
                                              data->buffer,
                                              data->nextHopAddr,
                                              ipHeader->ip_dst,
                                              data->networkType,
                                              &isFull);

                   if (isFull)
                   {
                        // Increment stat for number of output
                        // IP packets discarded because of a
                        // lack of buffer space.
                     ip->stats.ipOutDiscards++;

                     if (ip->isIcmpEnable && icmp->sourceQuenchEnable)
                     {
                         BOOL ICMPErrorMsgCreated =
                                   NetworkIcmpCreateErrorMessage(node,
                                                    data->buffer,
                                                    ipHeader->ip_src,
                                                    ANY_INTERFACE,
                                                    ICMP_SOURCE_QUENCH,
                                                    ICMP_SOURCE_QUENCH_CODE,
                                                    0,
                                                    0);
                         if (ICMPErrorMsgCreated)
                         {
                             (icmp->icmpErrorStat.icmpSrcQuenchSent)++;
                         }
                     }
                     MESSAGE_Free(node, data->buffer);
                   }
                }
#ifdef ENTERPRISE_LIB
                else if (data->networkType == PROTOCOL_TYPE_MPLS)
                {
                    // insert MPLS packet in MPLS queue
                     MplsData* mpls = (MplsData*)
                                      node->macData[interfaceIndex]->mplsVar;

                     MplsIpQueueInsert(node,
                                       mpls,
                                       data->buffer,
                                       data->interfaceIndex,
                                       data->nextHopAddr,
                                       MPLS_READY_TO_SEND,
                                       &data->priority,
                                       TRUE,
                                       &isFull);
                     if (isFull)
                     {
                        MESSAGE_Free(node, data->buffer);
                     }
                }
#endif // ENTERPRISE_LIB

                ListItem* templistItem = listItem->next;
                ListGet(node, db->arpBuffer, listItem, TRUE,FALSE);
                listItem = templistItem;
          } // end while loop

          if (queueWasEmpty && wasArpQueueEmpty)
          {
                if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex) ||
                    !ArpQueueIsEmpty(node, interfaceIndex))
                {
                   MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
                }
          }
       }// END IF arp data is enable
       if (db->arpBuffer)
       {
           MEM_free(db->arpBuffer);
           db->arpBuffer = NULL;
       }
       ListGet(node,
               arpData->interfaceInfo[interfaceIndex].arpDb,
               requestListItem,
               TRUE,
               FALSE);
   } // end if (db)

   arpData->interfaceInfo[interfaceIndex].stats.totalReplyRecvd++;
}

// /**
// FUNCTION    :: ProcessArpRequestPacket
// LAYER       :: NETWORK
// PURPOSE     :: An ARP Reply packet is received, update the ARP cache table
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : which will be process.
// + interfaceIndex : int  : incoming interface.
// + srcHWAddress : MacHWAddress&: source hardware address
// RETURN      :: void : NULL
// **/
static void ProcessArpRequestPacket(
         Node* node,
         Message* msg,
         int interfaceIndex,
         MacHWAddress& srcHWAddress)
{
    MacHWAddress destHWAddress;
    ArpData* arpData = ArpGetProtocolData(node);
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);

    BOOL isFull = FALSE;
    BOOL wasArpQueueEmpty = ArpQueueIsEmpty(node, interfaceIndex);

    BOOL queueWasEmpty = NetworkIpOutputQueueIsEmpty(node, interfaceIndex);

    // Create ARP reply packet
    Message* arpReplyMsg = ArpCreatePacket(node,
                                           arpData,
                                           ARPOP_REPLY,
                                           packet->s_IpAddr,
                                           srcHWAddress,
                                           interfaceIndex);

    ArpPacket* arpPacket = (ArpPacket*) arpReplyMsg->packet;

    destHWAddress.byte= (unsigned char*) MEM_malloc(packet->hardSize);

    memcpy(destHWAddress.byte, arpPacket->d_macAddr, arpPacket->hardSize);
    destHWAddress.hwLength = (unsigned short) arpPacket->hardSize;
    destHWAddress.hwType = arpPacket->hardType;

    EnqueueArpPacket(node,
                     interfaceIndex,
                     arpReplyMsg,
                     arpData,
                     &isFull,
                     arpPacket->d_IpAddr,
                     destHWAddress);  // enqueue arp reply message in  queue

    if (isFull)
    {
        arpData->interfaceInfo[interfaceIndex].stats.arppacketdropped++;
        MESSAGE_Free(node, arpReplyMsg);
        arpReplyMsg = NULL;
    }
    else
    {
        // Update ARP Cache stats
        arpData->interfaceInfo[interfaceIndex].stats.totalReplySend++;
    }

    arpData->interfaceInfo[interfaceIndex].stats.totalReqRecvd++;

    if (queueWasEmpty && wasArpQueueEmpty)
    {
        if (!NetworkIpOutputQueueIsEmpty(node, interfaceIndex)||
            !ArpQueueIsEmpty(node, interfaceIndex))
        {
            MAC_NetworkLayerHasPacketToSend(node, interfaceIndex);
        }
    }
}

// /**
// FUNCTION    :: ArpReceivePacket
// LAYER       :: NETWORK
// PURPOSE     :: An ARP packet is received by Address Resolution module
//                which
//                goes through an algorithm similar to the following.
//                (Negative conditionals indicate an end of processing and a
//                discarding of the packet.)
//                ?Do I have the hardware type in ar$hrd?
//                Yes: (almost definitely)
//                [optionally check the hardware length ar$hln]
//                ?Do I speak the protocol in ar$pro?
//                Yes:
//                [optionally check the protocol length ar$pln]
//                Merge_flag := false
//                If the pair <protocol type, sender protocol address> is
//                already in my translation table, update the sender
//                hardware address field of the entry with the new
//                information in the packet and set Merge_flag to true.
//                ?Am I the target protocol address?
//                Yes:
//                If Merge_flag is false, add the triplet <protocol type,
//                sender protocol address, sender hardware address>
//                to the translation table.
//                ?Is the opcode ares_op$REQUEST?  (look at the opcode!!)
//                Yes:
//                Swap hardware and protocol fields, putting the local
//                hardware and protocol addresses in sender fields.
//                Set the ar$op field to ares_op$REPLY
//                Send the packet to the (new) target hardware address on
//                the same hardware on which the request was
//                received.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : which will be process.
// + interfaceIndex : int  : incoming interface.
// RETURN      :: void : NULL
// **/
void ArpReceivePacket(
         Node* node,
         Message* msg,
         int interfaceIndex)
{
    BOOL margeFlag = FALSE;
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);
    ArpData* arpData = ArpGetProtocolData(node);

    unsigned short hwType = HW_TYPE_UNKNOWN;
    MacHWAddress srcHWAddress;
    MacHWAddress destHWAddress;
    MacGetHardwareType(node, interfaceIndex, &hwType);


    if (packet->hardType == hwType)
    {
        // skip: optional check on the hardware length ar$hln

        if (ArpIsSupportedProtocol(packet->protoType))
        {
            // skip: optional check the protocol length ar$pln
            clocktype currentTime = node->getNodeTime();
            margeFlag = FALSE;

            // If the pair <protocol type, sender protocol address> is
            // already in my translation table, update the sender
            // hardware address field of the entry with the new
            // information in the packet and set Merge_flag to true.

            srcHWAddress.byte= (unsigned char*) MEM_malloc(
                          sizeof(unsigned char)* packet->hardSize);

            memcpy(srcHWAddress.byte, packet->s_macAddr, packet->hardSize);
            srcHWAddress.hwLength = (unsigned short)packet->hardSize;
            srcHWAddress.hwType = packet->hardType;

            margeFlag = ArpTTableUpdateEntry(node,
                                             arpData,
                                             packet->protoType,
                                             packet->s_IpAddr,
                                             &srcHWAddress,
                                             currentTime,
                                             interfaceIndex);

            // Am I the target protocol address?
            if (NetworkIpGetInterfaceAddress(node, interfaceIndex)==
                                                      packet->d_IpAddr)
            {
                // If Merge_flag is false, add the triplet
                //<protocol type, sender protocol addr,
                // sender hardware addr>
                // to the translation table.
                if (!margeFlag)
                {
                    //Think about the "currentTime" parameter
                    ArpTTableAddEntry(node,
                                      packet->s_IpAddr,
                                      interfaceIndex,
                                      packet->protoType,
                                      &srcHWAddress,
                                      currentTime,
                                      ARP_ENTRY_TYPE_DYNAMIC);
                }

                switch (packet->opCode)
                {
                  case ARPOP_REQUEST: // receive request packet
                  {
                      ProcessArpRequestPacket(node,
                                              msg,
                                              interfaceIndex,
                                              srcHWAddress);
                      break;
                  }
                  case ARPOP_REPLY: // receive reply
                  {
                      // DHCP
                      if (packet->d_IpAddr == 0)
                      {
                          ListItem *requestListItem = NULL;
                          
                          ArpRequestSentDb *db = (ArpRequestSentDb*)FindItem(
                                       node,
                                       arpData->interfaceInfo[interfaceIndex].arpDb,
                                       0,
                                       (char*)&packet->s_IpAddr,
                                       sizeof(NodeAddress),
                                       &requestListItem);
                          if (db && db->isDHCP)
                          {
                            AppDHCPClientArpReply(
                                    node,
                                    interfaceIndex,
                                    FALSE);
                          }

                      }
                      
                      ProcessArpReplyPacket(node,
                                            msg,
                                            interfaceIndex);
                      break;
                  }

                  default:
                  {
                      ERROR_Assert(FALSE, "ARP Invalid Message Received\n");
                  }
                }
            } // end if
        } // end if protocol type is supported
     }

    MESSAGE_Free(node, msg);
}



// /**
// FUNCTION   ::  ArpSneakPacket
// PURPOSE:   ::  Sneak ARP packet, node is working in promiscous mode
// PARAMETERS ::
// + node : Node* Pointer to node.
// + msg :  Message pointer
// + interfaceIndex :incoming interface.
// RETURN      :: void : NULL
 //**/
void ArpSneakPacket(
         Node* node,
         Message* msg,
         int interfaceIndex)
{


    BOOL margeFlag = FALSE;
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);
    ArpData* arpData = ArpGetProtocolData(node);

    unsigned short hwType = HW_TYPE_UNKNOWN;
    MacHWAddress srcHWAddress;
    MacHWAddress destHWAddress;
    MacGetHardwareType(node, interfaceIndex, &hwType);


    if (packet->hardType == hwType)
    {
        // skip: optional check on the hardware length ar$hln

        if (ArpIsSupportedProtocol(packet->protoType))
        {
            // skip: optional check the protocol length ar$pln
            clocktype currentTime = node->getNodeTime();
            margeFlag = FALSE;

            // If the pair <protocol type, sender protocol address> is
            // already in my translation table, update the sender
            // hardware address field of the entry with the new
            // information in the packet and set Merge_flag to true.

            srcHWAddress.byte= (unsigned char*) MEM_malloc(
                          sizeof(unsigned char)* packet->hardSize);

            memcpy(srcHWAddress.byte, packet->s_macAddr, packet->hardSize);
            srcHWAddress.hwLength = (unsigned short)packet->hardSize;
            srcHWAddress.hwType = packet->hardType;

            margeFlag = ArpTTableUpdateEntry(node,
                                             arpData,
                                             packet->protoType,
                                             packet->s_IpAddr,
                                             &srcHWAddress,
                                             currentTime,
                                             interfaceIndex);
        }
    }
}



// /**
// FUNCTION    :: BufferPacket
// LAYER       :: NETWORK
// PURPOSE     :: This function buffer a data packet into ARP buffer
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// +  data : ArpBuffer*:: Pointer to Arp Buffer,
//                        to store details of the packet
// + interfaceIndex : int : Interface of the node
// + incomingInterface : int : Interface at which packet was arrived
// + nextHop : NodeAddress : nextHop Ip address.
// + priority:TosType  priority of packet
// + msg:  Message** variable for the mesaage dequeued
// + list  LinkedList*:: Pointer to list in which packet is buffered
// Return BOOL : True when message is successfully dequeued
// **/

static
void BufferPacket(
        Node* node,
        ArpBuffer* data,
        int interfaceIndex,
        int incomingInterface,
        NodeAddress nodeAddress,
        TosType priority,
        Message *msg,
        LinkedList* list,
        int networkType)
{
    data->interfaceIndex = interfaceIndex;
    data->incomingInterface = incomingInterface;
    data->nextHopAddr = nodeAddress;
    data->priority = priority;
    data->buffer = msg;
    data->networkType = networkType;
    ListInsert(node, list, 0, data);

    if (ARP_DATA_BUFFER)
    {
        ArpPrintARPDataBufferDebug(node, nodeAddress, BUFFER);
    }
}

// /**
// FUNCTION    :: ArpPreventFlooding
// LAYER       :: NETWORK
// PURPOSE     ::
// PARAMETERS  :: This function used to prevent ARP Flooding.
//                RFC 1122 recomends that there should be A mechanism to
//                prevent ARP flooding(repeatedly sending an ARP Request
//                for the same IP address, at a high rate) MUST be
//                included. The recommended maximum rate is 1 per
//                second per destination.
// + node : Node* : Pointer to node.
// + arpData : ArpData* : Pointer to ArpData
// + protocolAddress : NodeAddress : Ethernet address surch for
//                                   this Ip address.
// + currentTime : clocktype : Current Simulation Time
// RETURN      :: BOOL : TRUE or FALSE
// **/
static
BOOL ArpPreventFlooding(
         Node* node,
         Message *msg,
         ArpData* arpData,
         NodeAddress protocolAddress,
         clocktype currentTime,
         TosType priority,
         int interfaceIndex,
         int incomingInterface,
         int networkType,
         // DHCP
         bool isDhcp)
{
    BOOL preventFlooding = FALSE;
    ListItem* listItem = NULL;
    ArpRequestSentDb* db = (ArpRequestSentDb*) FindItem(
                                node,
                                arpData->interfaceInfo[interfaceIndex].arpDb,
                                0,
                                (char*)&protocolAddress,
                                sizeof(NodeAddress),
                                &listItem);


    if (db && ((currentTime - db->sentTime) >= (20 * SECOND)))
    {  //ARP request already sent and packet was sent 20 seconds before
       // delete the request 
        preventFlooding = FALSE;
        LinkedList* tempList = NULL;

        if ((db->arpBuffer) && (ListGetSize(node, db->arpBuffer) > 0))
        {
            ListItem* bufferItem = db->arpBuffer->first;
            ListInit(node, &tempList);

            while (bufferItem)
            {
                ListItem* nextbufferItem = bufferItem->next;
                ListInsert(node, tempList, 0, bufferItem->data);
                bufferItem->data = NULL;
                ListGet(node, db->arpBuffer, bufferItem, TRUE, FALSE);
                bufferItem = nextbufferItem;
            }
            MEM_free(db->arpBuffer);
            db->arpBuffer = NULL;
        }
        ListGet(node,
                arpData->interfaceInfo[interfaceIndex].arpDb,
                listItem,
                TRUE,
                FALSE);
        db = NULL;

        if (tempList)
        {
            ListItem* listIterator = tempList->first;
            while (listIterator)
            {
                arpData->interfaceInfo[interfaceIndex]
                                      .stats.numPktDiscarded++;
                ArpBuffer* bufferData = (ArpBuffer*)listIterator->data;
                // send notifications to network layer
                // DHCP
                if (bufferData->buffer)
                {
                    if (bufferData->networkType == PROTOCOL_TYPE_MPLS)
                    {
                        MplsNotificationOfPacketDrop(
                            node,
                            bufferData->buffer,
                            bufferData->nextHopAddr,
                            bufferData->interfaceIndex);
                    }
                    else
                    {
                        NetworkIpNotificationOfPacketDrop(
                            node,
                            bufferData->buffer,
                            bufferData->nextHopAddr,
                            bufferData->interfaceIndex);
                    }
                }

                ListItem* listItem = listIterator->next;
                ListGet(node, tempList, listIterator, TRUE, FALSE);
                listIterator = listItem;
            }
            ListFree(node, tempList, FALSE);
        }
    }
    else if (db)
    {
        //ARP request already sent
        preventFlooding = TRUE;
        if (arpData->interfaceInfo[interfaceIndex].isArpBufferEnable)
        {    // buffer the packet from IP

            if (ListGetSize(node, db->arpBuffer) ==
                 arpData->interfaceInfo[interfaceIndex].maxBufferSize)
            {
                // buffer is full discard oldest packet
                ListItem* bufferItem = db->arpBuffer->first;
                ArpBuffer* tempData = (ArpBuffer*) bufferItem->data;
                if (tempData->buffer != NULL)
                {
                    MESSAGE_Free(node, tempData->buffer);
                }

                ListGet(node, db->arpBuffer, bufferItem, TRUE, FALSE);
                arpData->interfaceInfo[interfaceIndex]
                                      .stats.numPktDiscarded++;

                if (ARP_DATA_BUFFER)
                {
                    ArpPrintARPDataBufferDebug(node, db->protocolAddr,
                                               DISCARD);
                }
            }

            ArpBuffer* data = (ArpBuffer*)MEM_malloc(sizeof(ArpBuffer));
            BufferPacket(node,
                         data,
                         interfaceIndex,
                         incomingInterface,
                         protocolAddress,
                         priority,
                         msg,
                         db->arpBuffer,
                         networkType);
            // DHCP
            if (isDhcp)
            {
                db->isDHCP = isDhcp;
            }

         }
         else             // buffer is not enable discard packet
         {
#ifdef ADDON_DB
         HandleNetworkDBEvents(
             node,
             msg,
             incomingInterface,
             "NetworkPacketDrop",
             "Arp Buffer Not Enabled",
             0,
             0,
             0,
             0);
#endif

             MESSAGE_Free(node, msg);
             arpData->interfaceInfo[interfaceIndex].stats.numPktDiscarded++;

             if (ARP_DATA_BUFFER)
             {
                 ArpPrintARPDataBufferDebug(node, protocolAddress, DISCARD);
             }
         }

        return preventFlooding;
    }// end elseif

    if (db == NULL) // Create new ARP request for protocolAddress
    {
        ArpRequestSentDb* newDb = (ArpRequestSentDb*)
                                       MEM_malloc(sizeof(ArpRequestSentDb));
        BOOL isAllqueueEmpty = TRUE;
        int i = 0;

        memset(newDb , 0, sizeof(ArpRequestSentDb));

        // check if ARP request retry event needs to be created
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ArpIsEnable (node, i) &&
               !ListIsEmpty(node,arpData->interfaceInfo[i].arpDb))
            {
               isAllqueueEmpty = FALSE;
               break;
            }
        }

        if (isAllqueueEmpty)
        {
             Message *retryMsg =MESSAGE_Alloc(node,
                                NETWORK_LAYER,
                                NETWORK_PROTOCOL_ARP,
                                MSG_NETWORK_ARPRetryTimer);

                MESSAGE_SetInstanceId(retryMsg, (short)interfaceIndex);
                MESSAGE_Send(node, retryMsg, SECOND);
        }

        //Insert new Request in ARP request Sent List
        ListInsert(node,
                   arpData->interfaceInfo[interfaceIndex].arpDb,
                   0,
                   newDb);

        newDb->protocolAddr = protocolAddress;
        newDb->sentTime = currentTime;
        newDb->RetryCount = arpData->maxRetryCount;
        // DHCP
        newDb->isDHCP = isDhcp;
        if (arpData->interfaceInfo[interfaceIndex].isArpBufferEnable)
        {
            // buffer is enable insert the data packet into buffer
            ListInit(node,&newDb->arpBuffer);
            ArpBuffer* buffer = (ArpBuffer*)MEM_malloc(sizeof(ArpBuffer));
            memset(buffer, 0, sizeof(ArpBuffer));
            BufferPacket(node,
                         buffer,
                         interfaceIndex,
                         incomingInterface,
                         protocolAddress,
                         priority,
                         msg,
                         newDb->arpBuffer,
                         networkType);
        }
        else
        {
            MESSAGE_Free(node, msg);
            arpData->interfaceInfo[interfaceIndex].stats.numPktDiscarded++;

            if (ARP_DATA_BUFFER)
            {
                ArpPrintARPDataBufferDebug(node, protocolAddress, DISCARD);
            }
        }
    }// end if (create new arp reqeuest packet)

    return preventFlooding;
}


// /**
// FUNCTION    :: ArpTTableLookup
// LAYER       :: NETWORK
// PURPOSE     :: This is the API function between IP and ARP.
//                This function search for the Ethernet address corresponding
//                to protocolAddress from ARP cache or Translation Table.
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int  : outgoing interface.
// + protoType : unsigned short  : Protocol Type
// + priority : TosType  :
// + protocolAddress : NodeAddress : Ethernet address surch for this Ip
//                                   address.
// + macAddr : MacHWAddress** : Ethernet address corresponding
//                            Ip address if exist.
// + msg : Message**  : Message pointer
// +  incomingInterface : int : Incoming Interface
// +  networkType : int : Network Type
// RETURN      :: BOOL : If success TRUE
// **/
BOOL ArpTTableLookup(
         Node* node,
         int interfaceIndex,
         unsigned short protoType,
         TosType priority,
         NodeAddress protocolAddress,
         MacHWAddress* macAddr,
         Message** msg,
         int incomingInterface,
         int networkType)
{
    ArpData* arpData = NULL;
    ArpTTableElement* arpTTableElement = NULL;
    ListItem *tableElementListItem = NULL;
    clocktype currentTime = node->getNodeTime();
    BOOL isFlooding = FALSE;

    unsigned short hwLength = 0;
    MacGetHardwareLength(node, interfaceIndex, &hwLength);

    (*macAddr).byte = (unsigned char*) MEM_malloc(
                          sizeof(unsigned char) * hwLength);

    // ARP Debug
    if (ARP_PACKET_DEBUG)
    {
        char clock[MAX_STRING_LENGTH] = {0};
        char addrstr[MAX_STRING_LENGTH] = {0};
        IO_ConvertIpAddressToString(protocolAddress, addrstr);
        TIME_PrintClockInSecond(currentTime, clock);
        printf("ARP: Node %u 's ARP Cache lookup for IP Address"
               " %s at %s Sec \n",node->nodeId, addrstr ,clock);
    }

    if (ARP_CACHE_DEBUG)
    {
        ArpPrintStatTable(node);
    }

    // ARP Handle Broadcast or Subnet Broadcast
    if ((protocolAddress == ANY_DEST) ||
        (protocolAddress == NetworkIpGetInterfaceBroadcastAddress(node,
                                                        interfaceIndex)))
    {
        if (ARP_DEBUG)
        {
            printf("ARP: Node %u returning MAC broadcast address "
                "[ff-ff-ff-ff-ff-ff] for Broadcast packet from network\n",
                node->nodeId);
        }

       *macAddr = GetBroadCastAddress(node,interfaceIndex);
        return TRUE;
    }

    if (MAC_IPv4addressIsMulticastAddress(protocolAddress))
    {
        MacGetHardwareLength(node, interfaceIndex, &hwLength);
        macAddr->hwLength = hwLength;
        MAC_TranslateMulticatIPv4AddressToMulticastMacAddress(
                                            protocolAddress, macAddr);
        return TRUE;
    }

    arpData = ArpGetProtocolData(node);

    arpTTableElement = (ArpTTableElement*) FindItem(node,
                                                    arpData->arpTTable,
                                                    0,
                                                    (char*)&protocolAddress,
                                                    sizeof(NodeAddress),
                                                    &tableElementListItem);

    if (arpTTableElement
          && (arpTTableElement->expireTime > ARP_STATICT_TIMEOUT)
          && (arpTTableElement->expireTime <= currentTime))
     {
         // arp entry exists but it is out of date
        if (ARP_CACHE_DEBUG)
        {
            char clk[MAX_STRING_LENGTH] = {0};
            TIME_PrintClockInSecond(currentTime, clk);
            ArpPrintStatTable(node);
            printf("ARP Cache: Entry deleted at %s Sec\n", clk);
        }

        ListGet(node,
                arpData ->arpTTable,
                tableElementListItem,
                TRUE,
                FALSE);

        arpTTableElement = NULL;

        // Update ARP cache stats
        arpData->interfaceInfo[interfaceIndex]
                              .stats.totalCacheEntryAgedout++;
        arpData->interfaceInfo[interfaceIndex]
                              .stats.totalCacheEntryDeleted++;
    }

    if (!MAC_InterfaceIsEnabled(node, interfaceIndex))
    {
        NetworkIpNotificationOfPacketDrop(node,
                                          *msg,
                                          protocolAddress,
                                          interfaceIndex);
        return FALSE;
    }



    if (!arpTTableElement) // arp entry does not exist
    {
        if (ARP_DEBUG)
        {
            char addrstr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(protocolAddress, addrstr);

            printf("ARP: Node %u 's ARP Cache does not contain any entry"
                " for %s\n", node->nodeId, addrstr);
        }

        isFlooding = ArpPreventFlooding(node,
                                        *msg,
                                        arpData,
                                        protocolAddress,
                                        currentTime,
                                        priority,
                                        interfaceIndex,
                                        incomingInterface,
                                        networkType,
                                        // DHCP
                                        FALSE);

        if (!isFlooding) // if not leading to flooding send arp request
        {
            ArpSendRequest(node,
                           protocolAddress,
                           arpData,
                           interfaceIndex);
        }

        return FALSE;
    }
    else if (arpTTableElement->protoType == protoType) // arp entry exists
    {
        if (ARP_DEBUG)
        {
            char addrstr[MAX_STRING_LENGTH] = {0};
            IO_ConvertIpAddressToString(protocolAddress, addrstr);
            printf("ARP: Node %u 's ARP Cache contain an entry for %s\n",
                node->nodeId, addrstr);
        }

        macAddr->hwLength = hwLength;
        macAddr->hwType = arpTTableElement->hwType;
        memcpy(macAddr->byte, arpTTableElement->hwAddr, macAddr->hwLength);
        return TRUE;
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown Protocol Type in ARP Cache Entry\n");
        return FALSE;
    }
}



// /**
// FUNCTION    :: ReverseArpTableLookUp
// LAYER       :: NETWORK
// PURPOSE     :: Finds IP address for a give Mac Address
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface of the node
// + macAddr : MacHWAddress* :hardware address
// Return NodeAddress : Ip address for a mac address
//**/
NodeAddress ReverseArpTableLookUp(
              Node* node,
              int interfaceIndex,
              MacHWAddress* macAddr)
{

    ArpData* arpData = ArpGetProtocolData(node);

    ArpTTableElement* arpTTableElement =
                        (ArpTTableElement*)FindItem(node,
                                                    arpData->arpTTable,
                                                    sizeof(NodeAddress),
                                                    (char*)macAddr->byte,
                                                    macAddr->hwLength);

    if (!arpTTableElement)
    {
            return 0;
    }
    else
    {
        return arpTTableElement->protocolAddr;
    }
}

// /**
// FUNCTION    :: ArpTTableFlushTable
// LAYER       :: NETWORK
// PURPOSE     :: This function may be call when interface is fault.
//                Remove the all entries from the ArpTranslationTable.
// PARAMETERS  ::
// + node       : Node* : Pointer to the Node
// + arpData    : ArpData* : Arp related information
// RETURN      :: void : NULL
// **/
static
void ArpTTableFlushTable(
         Node* node,
         ArpData* arpData,
         unsigned int interfaceIndex)
{
    ListItem* listItem = arpData ->arpTTable->first;

    while (listItem != NULL)
    {
        ListItem* nextListItem = listItem->next;
        ArpTTableElement* entry = (ArpTTableElement*)listItem->data;

        if (entry->interfaceIndex == interfaceIndex)
        {
            ListGet(node, arpData ->arpTTable, listItem, TRUE, FALSE);
            // Update ARP cache stats
            arpData->interfaceInfo[interfaceIndex]
                                  .stats.totalCacheEntryDeleted++;
        }
        listItem = nextListItem;
    }

    if (ARP_CACHE_DEBUG)
    {
        ArpPrintStatTable(node);
    }
}


// /**
// FUNCTION    :: ArpDbFlush
// LAYER       :: NETWORK
// PURPOSE     :: This function may be call when interface is fault.
//                Remove all entries from the ArpTranslationTable.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + arpData    : ArpData* :Pointer to ArpData for the particular interface.
// RETURN      :: void : NULL
// **/
static
void ArpDbFlush(
         Node* node,
         ArpData* arpData,
         int interfaceIndex)
{

   ListItem* listItem = arpData->interfaceInfo[interfaceIndex].arpDb->first;

    while (listItem != NULL)
    {
        ListItem* nextListItem = listItem->next;

        ListGet(node,
                arpData ->interfaceInfo[interfaceIndex].arpDb,
                listItem,
                TRUE,
                FALSE);

        listItem = nextListItem;
    }

    if (ARP_CACHE_DEBUG)
    {
        ArpPrintStatTable(node);
    }
}


// /**
// FUNCTION    :: ArpCreateStaticTable
// LAYER       :: NETWORK
// PURPOSE     :: Static ARP cache entry inserted into the main ARP table
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + arpStaticTableInput : NodeInput* : It is the input to the static
//                                      arp-table entry.
// RETURN      :: void : NULL
// **/
static
void ArpCreateStaticTable(Node* node, NodeInput* arpStaticTableInput)
{
    NodeAddress nodeId = 0;
    NodeAddress nodeIdForEntry = 0;
    NodeAddress ipAddress = 0;
    clocktype timeOut;
    MacHWAddress macAddr;
    BOOL isNodeId = FALSE;
    int lineCounter = 0;
    int item = 0;
    int intfIndex = -1;
    int intfIndexForEntry = -1;
    char nodeIdStr[MAX_STRING_LENGTH] = {0};
    char deviceTypeStr[MAX_STRING_LENGTH] = {0};
    char hwAddrStr[MAX_STRING_LENGTH] = {0};
    char protocolTypeStr[MAX_STRING_LENGTH] = {0};
    char ipAddressStr[MAX_STRING_LENGTH] = {0};
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    char clockInput[MAX_STRING_LENGTH];
    unsigned short hwType = ARP_HRD_UNKNOWN;
    unsigned short protocolType = 0;
    int numHostBits;

    for (;lineCounter <arpStaticTableInput->numLines; lineCounter++)
    {
        nodeId = 0;
        nodeIdForEntry = 0;
        // The static ARP cache has been read from the specific
        // input file. The format of the input file is as follows:
        // <node-id>
        //[<interface-index>] -optional field
        // <protocol-type i.e [IP]>
        // <protocol-address> | <node-interface>
        // <hardware-type [ETHRNET/ATM]>
        // <hardware-address>
        //<time-out in time format>

        item = sscanf(arpStaticTableInput->inputStrings[lineCounter],
                    "%s %s %s %s %s %s %s",
                    nodeIdStr, intfIndexStr,
                    protocolTypeStr, ipAddressStr,
                    deviceTypeStr, hwAddrStr,
                    clockInput);

        //Check the validity of the number of
        //attributes of each static entry
        if (item == ARP_STATIC_FILE_ATTRIBUTE - 1)
        {
            sscanf(arpStaticTableInput->inputStrings[lineCounter],
                      "%s %s %s %s %s %s",
                      nodeIdStr,
                      protocolTypeStr, ipAddressStr,
                      deviceTypeStr, hwAddrStr,
                      clockInput);
            memset(intfIndexStr, 0, MAX_STRING_LENGTH*sizeof(char));
        }
        //Checking the attribute must have
        //(ARP_STATIC_FILE_ATTRIBUTE -1) attribute or
        //(ARP_STATIC_FILE_ATTRIBUTE) attribue
        //If it , less than (ARP_STATIC_FILE_ATTRIBUTE-1)
        // programme will be asserted
        else if (item != ARP_STATIC_FILE_ATTRIBUTE)
        {
            ERROR_Assert(FALSE,
                        "Invalid number of entry in static arp file");
        }

        //For debuging the input read from the
        // file correctly or not
        if (STAT_TABLE_INPUT_DEBUG)
        {
            printf("\nAttribute in each entry of Static ARP File: \n");
            printf("----------------------------------");
            printf("\nitem: %d", item);
            printf("\nnodeId: %s", nodeIdStr);
            printf("\nintfIndexStr: %s", intfIndexStr);
            printf("\nprotocolTypeStr: %s",protocolTypeStr);
            printf("\nipAddressStr: %s", ipAddressStr);
            printf("\ndeviceTypeStr: %s", deviceTypeStr);
            printf("\nhwAddrStr: %s",hwAddrStr);
            printf("\nclockInput: %s\n",clockInput);
        }


        //Check the entry is for the specific node or for global one
        if (strcmp(nodeIdStr, "X") !=0 && strcmp(nodeIdStr, "x") !=0)
        {
            nodeId = (NodeAddress ) strtoul(nodeIdStr, NULL, 10);

            //check the validity of node-id
            if (nodeId <= 0)
            {
                ERROR_Assert(FALSE,"Invalid node-id");
            }

            if (node->nodeId != nodeId)
            {
                continue;
            }
        }

        timeOut = TIME_ConvertToClock(clockInput);


        //Currently the following two hardware types have been supported
        if (strcmp(deviceTypeStr,"ETHERNET") == 0)
        {
            hwType = ARP_HRD_ETHER;
        }
        else if (strcmp(deviceTypeStr, "ATM") == 0)
        {
            hwType = ARP_HRD_ATM;
        }
        else
        {
            ERROR_Assert(FALSE,
                "Invalid Hardware type or does not support the"
                " Current Version");
        }

        macAddr.hwType = hwType;
        MacValidateAndSetHWAddress(hwAddrStr, &macAddr);
        ERROR_Assert(macAddr.hwLength > 0,
                    "Hardware Length should be greater than 0");

        //Currently the IP protocol has been supported
        if (strcmp(protocolTypeStr,"IP") == 0)
        {
            protocolType = PROTOCOL_TYPE_IP;
        }
        else
        {
            ERROR_Assert(FALSE,"Invalid Protocol type");
        }

         //The static timeout value should be zero
         //It has kept as the user option for the future use
         //if (timeOut !=  ARP_STATICT_TIMEOUT)
         if (timeOut <  ARP_STATICT_TIMEOUT)
         {
              ERROR_Assert(FALSE,
                "Invalid time out for static ARP cache");
         }

        if (hwType == ARP_HRD_ETHER)
        {
            ArpSeperateNodeAndInterface(ipAddressStr, &nodeIdForEntry,
                &intfIndexForEntry, &isNodeId);

            if (isNodeId == TRUE)
            {
                ipAddress = MAPPING_GetInterfaceAddressForInterface(
                                node, nodeIdForEntry, intfIndexForEntry);

            }
            else
            {
                 IO_ParseNodeIdHostOrNetworkAddress(
                     ipAddressStr,
                     &ipAddress,
                     &numHostBits,
                     &isNodeId);
            }

        }

        else if (hwType == ARP_HRD_ATM)
        {
            ArpSeperateNodeAndInterface(ipAddressStr, &nodeIdForEntry,
                &intfIndexForEntry, &isNodeId);

            if (isNodeId == TRUE)
            {
               ipAddress = AtmGetLogicalIPAddressFromNodeId(
                               node, nodeIdForEntry, intfIndexForEntry);
            }
            else
            {
                ArpConvertStringAddressToNetworkAddress(
                    ipAddressStr, &ipAddress);
            }
        }

        else
        {
            ERROR_Assert(FALSE,"Invalid Protocol type");
        }

        if (item == ARP_STATIC_FILE_ATTRIBUTE)
        {
            intfIndex = (int) strtoul(intfIndexStr, NULL, 10);

        }
        else
        {
           //Find the interface through which the neighbour connected
           // If the node is not reachable, the default interface will  be 0
            ArpInterfaceChecking(node, ipAddress, &intfIndex);
        }

        if (intfIndex < 0)
        {
            ERROR_Assert(FALSE,"Invalid interface index");
        }
        ArpTTableAddEntry(node,
            ipAddress,
            intfIndex,
            protocolType,
            &macAddr,
            timeOut,
            ARP_ENTRY_TYPE_STATIC);

        if (STAT_TABLE_DEBUG)
        {
            ArpPrintStatTable(node);
        }
    }
}


// /**
// FUNCTION    :: ArpSeperateNodeAndInterface
// LAYER       :: NETWORK
// PURPOSE     :: It does check whether the ipAddressStr is either
//                nodeid-interface (nodeid-interface) or ip-address
//                if this is nodeid-interface, the values set into
//                nodeId and interface with the value and the BOOL set TRUE
//                Otherwise the BOOL value is FALSE
// PARAMETERS  ::
// + ipAddressStr[] : const char :
//                   Character string which has either nodeid-interface or
//                   ip-address string
//                   - the multicast protocol to get.
//                   interfaceId - specific interface index or ANY_INTERFACE
// + nodeId : NodeAddress* :The value to be set after extracting the
//                          nodeid from string
// + intfIndex : int* : The value to be set after extracting the interface
//                      from string
// + isNodeId : BOOL* : The value to be set TRUE if the string is
//                      nodeid-interface otherwise FALSE
// RETURN      :: void : NULL
// **/
void ArpSeperateNodeAndInterface(
         const char ipAddressStr[],
         NodeAddress* nodeId,
         int* intfIndex,
         BOOL* isNodeId)
{
    int stringLength = 0;
    int i = 0;
    int j = 0;
    char addressString[MAX_ADDRESS_STRING_LENGTH] = {0};

    *nodeId = 0;
    *intfIndex = -1;
    stringLength = (int)strlen(ipAddressStr);
    *isNodeId = FALSE;

    if (tolower(ipAddressStr[i]) == 'n')
    {
        return;
    }

    while (ipAddressStr[i] != '-' && i< stringLength)
    {
        addressString[j] = ipAddressStr[i];

        if (ipAddressStr[i] == '.')
        {
            return;
        }
        i++;
        j++;
    }

    if (IO_IsStringNonNegativeInteger(addressString))
    {
        *nodeId = (unsigned) strtoul(addressString, NULL, 10);
    }
    i++;
    j =0;
    memset(addressString, 0, MAX_ADDRESS_STRING_LENGTH);

    while (i < stringLength)
    {
        addressString[j] = ipAddressStr[i];

        i++;
        j++;
    }

    if (IO_IsStringNonNegativeInteger(addressString))
    {
        *intfIndex = (unsigned) strtoul(addressString, NULL, 10);
    }

    if (*nodeId > 0 && *intfIndex > -1)
    {
        *isNodeId = TRUE;
    }
}


// /**
// FUNCTION    :: ArpInterfaceChecking
// LAYER       :: NETWORK
// PURPOSE     :: This function is used to retrieve the interface through
//                which the neighbour has been connected to node
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + neighbourIp : NodeAddress : The ip-address which will is the static
//                               entry
// + nodeInterface : int* : The interface through which the neighbourIp
//                          has been connected
// RETURN      :: void : NULL
// **/
void ArpInterfaceChecking(
         Node* node,
         NodeAddress neighbourIp,
         int *nodeInterface)
{
    NodeAddress interfaceAddress = 0;
    NodeAddress subnetAddress = 0;
    NodeAddress interfaceNetworkAddress = 0;
    NodeAddress subnetMask = 0;
    int numHostBits = 0;
    int interfaceIndex = -1;
    int i;

    for (i = 0; i< node->numberInterfaces; i++)
    {
        MAPPING_GetInterfaceInfoForInterface(node, node->nodeId, i,
            &interfaceAddress, &subnetAddress, &subnetMask, &numHostBits);
        interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(node,
                            neighbourIp);

        interfaceNetworkAddress = MaskIpAddress(neighbourIp, subnetMask);

        if (interfaceNetworkAddress == subnetAddress)
        {
                *nodeInterface = i;
                return;
        }
    }
            *nodeInterface = DEFAULT_INTERFACE;
            return;
}


// /**
// FUNCTION    :: ArpHandleHWInterfaceFault
// LAYER       :: NETWORK
// PURPOSE     :: Handle Interface Fault Situations
// PARAMETERS  ::
// + node        : Node* : Pointer to node.
// + interfaceIndex : int : Interface Index
// + isInterfaceFaulty : BOOL : Denotes interface fault status.
// + newMacAddr : MacAddress : Current Interface Mac Address
// RETURN      :: void : NULL
// **/
void ArpHandleHWInterfaceFault(
         Node* node,
         int interfaceIndex,
         BOOL isInterfaceFaulty)
{
    ArpData* arpData = ArpGetProtocolData(node);

    if (isInterfaceFaulty)
    {
        // Flush ARP Cache
        ArpTTableFlushTable(node, arpData, interfaceIndex);

        // Clear ARP reference Database
        ArpDbFlush(node, arpData, interfaceIndex);
    }
    else
    {
        // When the network interface card in a system is changed,
        // the MAC address to its IP address mapping is changed.
        // In this case, when the host is rebooted, it will send an ARP
        // request packet for its own IP address. As this is a broadcast
        // packet, all the hosts in the network will receive and process
        // this packet. They will update their old mapping in the ARP cache
        // with this new mapping.
        arpData->interfaceInfo[interfaceIndex].stats.totalGratReqSend++;
        ArpSendRequest(node,
                       NetworkIpGetInterfaceAddress(node, interfaceIndex),
                       arpData,
                       interfaceIndex);
    }
}




// /**
// FUNCTION    :: ArpInit
// LAYER       :: NETWORK
// PURPOSE     :: Initialize ARP all data structure and configuration
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput* : Pointer to node input.
// RETURN      :: void : NULL
// **/
void ArpInit(
         Node* node,
         const NodeInput* nodeInput)
{

    int i = 0;
    NodeInput arpStaticTableInput;
    BOOL retVal = FALSE;
    Message* tickTimerMsg = NULL;
    char protocolString[MAX_STRING_LENGTH];
    NetworkData* nwData = (NetworkData*) &(node->networkData);

    ArpData* arpData = (ArpData*) MEM_malloc(sizeof(ArpData));
    AddressResolutionModule* addrResolnMod =
      (AddressResolutionModule*) MEM_malloc(sizeof(AddressResolutionModule));

    memset(addrResolnMod, 0, sizeof(AddressResolutionModule));
    memset(arpData, 0, sizeof(ArpData));
    memset(protocolString, 0, MAX_STRING_LENGTH);

    nwData->arModule = addrResolnMod;
    addrResolnMod->arpData = arpData;

    nwData->isArpEnable = FALSE;
    nwData->isRarpEnable = FALSE;

    IO_ReadString(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "ARP-ENABLED",
                  &retVal,
                  protocolString);

    if (retVal && strcmp(protocolString, "YES") == 0)
    {
        nwData->isArpEnable = TRUE;
    }

    IO_ReadString(node->nodeId,
                  ANY_ADDRESS,
                  nodeInput,
                  "ARP-STATISTICS",
                  &retVal,
                  protocolString);
    if (retVal && strcmp(protocolString, "YES") == 0)
    {
        for (i = 0; i < node->numberInterfaces; i++)
        {
            arpData->interfaceInfo[i].isArpStatEnable = TRUE;
        }
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        // NodeAddress ipAddr = NetworkIpGetInterfaceAddress(node, i);
        IO_ReadString(node,
                      node->nodeId,
                      i,
                      nodeInput,
                      "ARP-ENABLED",
                      &retVal,
                      protocolString);

        if (retVal && strcmp(protocolString, "YES") == 0)
        {
            arpData->interfaceInfo[i].isEnable = TRUE;
            nwData->isArpEnable = TRUE;
        }
        else
        {
            arpData->interfaceInfo[i].isEnable = FALSE;
        }

        if (arpData->interfaceInfo[i].isEnable)
        {
            arpData->interfaceInfo[i].protoType = PROTOCOL_TYPE_IP;
            arpData->interfaceInfo[i].requestQueue = new Queue;
            arpData->interfaceInfo[i].requestQueue->SetupQueue(node,
                                                               "FIFO",
                                                             ARP_QUEUE_SIZE);

            ListInit(node, &arpData->interfaceInfo[i].arpDb);

            tickTimerMsg = MESSAGE_Alloc(node,
                                         NETWORK_LAYER,
                                         NETWORK_PROTOCOL_ARP,
                                         MSG_NETWORK_ArpTickTimer);

            MESSAGE_SetInstanceId(tickTimerMsg, (short)i);
            MESSAGE_Send(node, tickTimerMsg, SECOND);


            arpData->interfaceInfo[i].maxBufferSize = ARP_BUFFER_SIZE;
            arpData->interfaceInfo[i].isArpBufferEnable = TRUE;

            IO_ReadInt(node,
                       node->nodeId,
                       i,
                       nodeInput,
                       "ARP-BUFFER-SIZE",
                       &retVal,
                       &arpData->interfaceInfo[i].maxBufferSize);

            if (arpData->interfaceInfo[i].maxBufferSize < 0)
            {
                ERROR_ReportWarning(
                    "Buffer Size Value in Config file is less than 0"
                    ", Using Default Value 1 \n");

                arpData->interfaceInfo[i].maxBufferSize = ARP_BUFFER_SIZE;
            }

            if (retVal && arpData->interfaceInfo[i].maxBufferSize)
            {
                arpData->interfaceInfo[i].isArpBufferEnable = TRUE;
            }
            else if (retVal && arpData->interfaceInfo[i].maxBufferSize == 0)
            {
                arpData->interfaceInfo[i].isArpBufferEnable = FALSE;
            }

            retVal = FALSE;
            memset(protocolString, 0, MAX_STRING_LENGTH);

            retVal = FALSE;
            memset(protocolString, 0, MAX_STRING_LENGTH);
            arpData->arpExpireInterval = ARP_DEFAULT_TIMEOUT_INTERVAL;

             IO_ReadTime(node,
                         node->nodeId,
                         i,
                         nodeInput,
                         "ARP-CACHE-EXPIRE-INTERVAL",
                         &retVal,
                         &arpData->arpExpireInterval);

             IO_ReadString(node,
                           node->nodeId,
                           i,
                           nodeInput,
                           "ARP-STATISTICS",
                           &retVal,
                           protocolString);
            if (retVal && strcmp(protocolString, "YES") == 0)
            {
                arpData->interfaceInfo[i].isArpStatEnable = TRUE;
            }
            else if (retVal && strcmp(protocolString, "NO") == 0)
            {
                arpData->interfaceInfo[i].isArpStatEnable = FALSE;
            }
            arpData->maxRetryCount = MAX_RETRY_COUNT;

            retVal = FALSE;

          }
    }

    if (ArpIsEnable(node))
    {
       // ARP Translation Table Initialization
       ListInit(node, &arpData->arpTTable);

       IO_ReadCachedFile(node->nodeId,
                        ANY_ADDRESS,
                        nodeInput,
                        "ARP-STATIC-CACHE-FILE",
                        &retVal,
                        &arpStaticTableInput);

       if (retVal)
       {
            //The Static ARP has been configured in the function
            ArpCreateStaticTable(node, &arpStaticTableInput);
       }

        if (STAT_TABLE_DEBUG)
        {
            ArpPrintStatTable(node);
        }
    }

#if 0
    ArpInitTrace(node, nodeInput);
#endif
}


// /**
// FUNCTION    :: ArpRetry
// LAYER       :: NETWORK
// PURPOSE     :: Retries ARP Request
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg  : Message* : Pointer to Message.
// RETURN      :: void : NULL
// **/
static
void ArpRetry(
         Node* node,
         Message* msg)
{

    BOOL need_retry = FALSE;
    ArpData* arpData = ArpGetProtocolData(node);
    clocktype currentTime = node->getNodeTime();
    int i = 0;

    for (; i < node->numberInterfaces; i++)
    {
        if (ArpIsEnable (node, i))
        {
            ListItem* listItem = arpData->interfaceInfo[i].arpDb->first;

            while (listItem)
            {
                ArpRequestSentDb* db = (ArpRequestSentDb*) listItem->data;

                if (db->RetryCount == 0 &&
                    (currentTime - db->sentTime) >= SECOND)
                {
                    // if all retries done delete the request
                    ListItem* nextListItem = listItem->next;
                    ListItem* bufferItem = NULL;
                    LinkedList* tempList = NULL;

                    if (db->arpBuffer
                        && (ListGetSize(node, db->arpBuffer) > 0))
                    {
                        bufferItem = db->arpBuffer->first;
                        ListInit(node, &tempList);
                    }

                    while (bufferItem)
                    {
                        ListItem* nextBufferItem = bufferItem->next;
                        ListInsert(node, tempList, 0, bufferItem->data);
                        bufferItem->data = NULL;
                        ListGet(node, db->arpBuffer, bufferItem,
                                TRUE, FALSE);
                        bufferItem = nextBufferItem;
                    }

                    if (tempList)
                    {
                        ListItem* listIterator = tempList->first;
                        while (listIterator)
                        {
                            arpData->interfaceInfo[i]
                                                  .stats.numPktDiscarded++;
                            ArpBuffer* bufferData = (ArpBuffer*)
                                                         listIterator->data;
                            // DHCP
                            if (bufferData->buffer)
                            {
                                //send notifications to network layer
                                if (bufferData->networkType == 
                                        PROTOCOL_TYPE_MPLS)
                                {
                                    MplsNotificationOfPacketDrop(node,
                                             bufferData->buffer,
                                             bufferData->nextHopAddr,
                                             bufferData->interfaceIndex);
                                }
                                else
                                {
                                    NetworkIpNotificationOfPacketDrop(node,
                                             bufferData->buffer,
                                             bufferData->nextHopAddr,
                                             bufferData->interfaceIndex);
                                }
                            }
                            ListItem* listItem = listIterator->next;
                            ListGet(node,
                                    tempList,
                                    listIterator,
                                    TRUE,
                                    FALSE);
                            listIterator = listItem;
                        }
                        ListFree(node, tempList, FALSE);
                    }

                    if (ARP_DEBUG)
                    {
                        char clockStr[MAX_STRING_LENGTH] = {0};
                        TIME_PrintClockInSecond(node->getNodeTime(),
                                                clockStr);
                        char addrstr[MAX_STRING_LENGTH] = {0};
                        IO_ConvertIpAddressToString(db->protocolAddr,
                                                    addrstr);
                        printf("ARP: Node %d ARP Reply not received from IP"
                               " address %s after %d Retry \n",
                               node->nodeId,addrstr,MAX_RETRY_COUNT);
                    }
                    // DHCP
                    if (db->isDHCP == TRUE)
                    {
                        AppDHCPClientArpReply(
                                    node,
                                    i,
                                    TRUE);
                    }
                    if (db->isDHCP == TRUE)
                    {
                        ListGet(node,
                                arpData->interfaceInfo[i].arpDb,
                                listItem,
                                TRUE,
                                FALSE);
                    }

                    listItem = nextListItem;
                }
               else if (db->RetryCount > 0 &&
                        (currentTime - db->sentTime) >= SECOND)
               {
                   // resend the ARP rqeuest as one second is complete
                   if (ARP_DEBUG)
                   {
                       char clockStr[MAX_STRING_LENGTH] = {0};
                       TIME_PrintClockInSecond(node->getNodeTime(),
                                                                   clockStr);
                       char addrstr[MAX_STRING_LENGTH] = {0};
                       IO_ConvertIpAddressToString(db->protocolAddr,addrstr);
                       printf("ARP: Node %d Re-send ARP Request packet to %s"
                            " at %s Sec\n", node->nodeId, addrstr, clockStr);
                   }

                   ArpSendRequest(node, db->protocolAddr, arpData, i);
                   db->RetryCount--;
                   db->sentTime = node->getNodeTime();
                   need_retry = TRUE;
                   listItem = listItem->next;
               }
               else
               {
                   need_retry = TRUE;
                   listItem = listItem->next;
               }
            }// end of while
        }
    }// end of for
    if (need_retry)
    {
        MESSAGE_Send(node, msg, SECOND);
    }
    else
    {
        MESSAGE_Free(node, msg);
    }
}


// /**
// FUNCTION    :: ArpLayer
// LAYER       :: NETWORK
// PURPOSE     :: Handle ARP events
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// RETURN      :: void : NULL
// **/
void ArpLayer(
         Node* node,
         Message* msg)
{
    ListItem* listItem = NULL;
    ArpData* arpData = ArpGetProtocolData(node);
    clocktype currentTime = node->getNodeTime();

    switch (msg->eventType)
    {
        //case MSG_MAC_ArpTickTimer:
        case MSG_NETWORK_ArpTickTimer:
        {
            // Delete out-of-date cache entries
            listItem = arpData ->arpTTable->first;

            while (listItem != NULL)
            {
                ArpTTableElement* arpTTableElement =
                                        (ArpTTableElement*) listItem->data;
                ListItem* nextListItem = listItem->next;

                if ((arpTTableElement->expireTime > ARP_STATICT_TIMEOUT) &&
                    (arpTTableElement->expireTime <= currentTime))
                {
                    if (ARP_CACHE_DEBUG)
                    {
                        char clk[MAX_STRING_LENGTH] = {0};
                        TIME_PrintClockInSecond(currentTime, clk);
                        ArpPrintStatTable(node);
                        printf("ARP Cache: Entry deleted at %s Sec\n", clk);
                    }

                    Int32 interfaceIndex = arpTTableElement->interfaceIndex;

                    ListGet(node,
                        arpData ->arpTTable,
                        listItem,
                        TRUE,
                        FALSE);

                    // Update ARP cache stats
                    arpData->interfaceInfo[interfaceIndex]
                                          .stats.totalCacheEntryAgedout++;
                    arpData->interfaceInfo[interfaceIndex]
                                          .stats.totalCacheEntryDeleted++;
                }
                listItem = nextListItem;
            }

            // Reuse and resend the tick message
            MESSAGE_Send(node, msg, SECOND);

            break;
        }
        case MSG_NETWORK_ARPRetryTimer:
        {
            ArpRetry(node,msg);
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "Invalid Event Type\n");
            break; // Unreachable
        }
    }
}

// /**
// FUNCTION    :: ArpFinalize
// LAYER       :: NETWORK
// PURPOSE     :: Finalize function for the ARP protocol.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN      :: void : NULL
// **/
void ArpFinalize(Node* node)
{
    char buf[MAX_STRING_LENGTH];
    ArpData* arpData = NULL;
    UInt32 i = 0;
    NodeAddress intfAddr;

    if (!ArpIsEnable(node))
    {
        return;
    }

    arpData = ArpGetProtocolData(node);

    if (ARP_CACHE_DEBUG)
    {
        ArpPrintStatTable(node);
    }

    if (node->numberInterfaces)
    {
        UInt32* tempCacheDeleted = new UInt32[node->numberInterfaces];
        // Clear all the ARP Cache
        for (i = 0; i < (UInt32) node->numberInterfaces; i++)
        {
            tempCacheDeleted[i] = 
                arpData->interfaceInfo[i].stats.totalCacheEntryDeleted;
        }

        for (i = 0; i < (UInt32) node->numberInterfaces; i++)
        {
            if (ArpIsEnable(node, i))
            {
                ArpTTableFlushTable(node, arpData, i);
                // Clear ARP reference Database
                ArpDbFlush(node, arpData, i);
            }
        }

        for (i = 0; i < (UInt32) node->numberInterfaces; i++)
        {
            arpData->interfaceInfo[i].stats.totalCacheEntryDeleted
                = tempCacheDeleted[i];
        }

        for (i = 0; i < (UInt32) node->numberInterfaces; i++)
        {
            intfAddr = NetworkIpGetInterfaceAddress(node, i);
            if (ArpIsEnable(node, i))
            {
                if (arpData->interfaceInfo[i].isArpStatEnable)
                {
                    sprintf(
                        buf,
                        "Request Sent = %u",
                        arpData->interfaceInfo[i].stats.totalReqSend);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Request Received = %u",
                        arpData->interfaceInfo[i].stats.totalReqRecvd);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Reply Sent = %u",
                        arpData->interfaceInfo[i].stats.totalReplySend);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Reply Received = %u",
                        arpData->interfaceInfo[i].stats.totalReplyRecvd);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Data Packet Discarded = %u",
                        arpData->interfaceInfo[i].stats.numPktDiscarded);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Entry Inserted = %u",
                        arpData
                           ->interfaceInfo[i].stats.totalCacheEntryCreated);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP Cache",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Entry Updated = %u",
                        arpData
                           ->interfaceInfo[i].stats.totalCacheEntryUpdated);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP Cache",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Entry Agedout = %u",
                        arpData
                           ->interfaceInfo[i].stats.totalCacheEntryAgedout);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP Cache",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                    sprintf(
                        buf,
                        "Entry Deleted = %u",
                        arpData
                           ->interfaceInfo[i].stats.totalCacheEntryDeleted);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP Cache",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);

                     sprintf(
                         buf,
                         "Gratuitous Request Sent = %u",
                         arpData->interfaceInfo[i].stats.totalGratReqSend);
                    IO_PrintStat(
                        node,
                        "Network",
                        "ARP",
                        intfAddr,
                        -1 /* instance Id */,
                        buf);
                }
            }
        }
        delete []tempCacheDeleted;
    }
}


// /**
// FUNCTION    :: ArpLookUpHarwareAddress
// LAYER       :: NETWORK
// PURPOSE     :: The function is used whenever required
//                to get the hardware address against the ip address
// PARAMETERS  ::
// + node       : Node*: Pointer to node whome require to know the
//                       hardware address
// + protocolAddress : NodeAddress  : The ip-address whose hardware
//                                     address is looking for.
// + interfaceIndex: int  : The interface number of the protocol address
// + hwType     : unsigned short :
// + hwAddr     : unsigned char  : The hardware address has been assigned
//                                 to the character pointer
// RETURN      :: BOOL : Return the boolean value
// **/
BOOL ArpLookUpHarwareAddress(
         Node* node,
         NodeAddress protocolAddress,
         int interfaceIndex,
         unsigned short hwType,
         unsigned char  *hwAddr)
{

    if (!ArpIsEnable(node, interfaceIndex))
    {
        return FALSE;
    }

    ArpData* arpData = ArpGetProtocolData(node);

    ArpTTableElement* arpTTableElement;
    arpTTableElement = (ArpTTableElement*) FindItem(
                           node,
                           arpData->arpTTable,
                           0,
                           (char*)&protocolAddress,
                           sizeof(NodeAddress));

    if (!arpTTableElement)
    {
        return FALSE;
    }
    else
    {
        if (arpTTableElement->hwType == ARP_HRD_ATM)
        {
            memcpy(hwAddr, arpTTableElement->hwAddr,
                   arpTTableElement->hwLength);
            return TRUE;
        }
        else
        {
            ERROR_Assert(FALSE, "ARP: No entry according to "
                "the logical IP address.\n");
            return FALSE;
       }
    }
}



// /**
// FUNCTION            :: ArpConvertStringAddressToNetworkAddress
// LAYER       :: NETWORK
// PURPOSE             :: Convert the input ip address in character
//                        format to NodeAddress
// PARAMETERS  ::
// + addressString      : const char : String which has ip-string
//                                     in character format
// + outputNodeAddress  : NodeAddress* : The string value converted
//                                       to NodeAddress value
// RETURN      :: void : NULL
// **/
void ArpConvertStringAddressToNetworkAddress(
         const char addressString[],
         NodeAddress* outputNodeAddress)
{
    NodeAddress nodeAddress;
    int i;
    BOOL isHex = FALSE;
    BOOL isReadingNumber = FALSE;
    int currentNumber;
    int stringLength = (int)strlen(addressString);

    ERROR_Assert(
        stringLength != 0 && stringLength < MAX_ADDRESS_STRING_LENGTH,
        "Invalid string length in IO_ParseNodeIdHostOrNetworkAddress()");

    nodeAddress = 0;
    currentNumber = 0;
    i = 0;

    if (tolower(addressString[0]) == 'n')
    {
        char aString[MAX_ADDRESS_STRING_LENGTH];
        int n;

        for (n = 1; n < stringLength && addressString[n] != '-'; n++)
        {
            aString[n - 1] = addressString[n];
        }

        aString[n - 1] = 0;

        if (n == stringLength)
        {
            char buf[MAX_STRING_LENGTH];

            sprintf(buf, "Bad subnet string: %s", addressString);
            ERROR_ReportError(buf);
        }

        //*numHostBits = atoi(aString);

        i = n + 1;
    }//if//

    while (i < stringLength)
    {
        if (!isReadingNumber)
        {
            if (addressString[i] == '0' && addressString[i + 1] == 'x')
            {
                isHex = TRUE;
                isReadingNumber = TRUE;
                currentNumber = 0;
                i = i + 2;
            }
            else
            if (isdigit((int)addressString[i]))
            {
                isHex = FALSE;
                isReadingNumber = TRUE;
                currentNumber = 0;
            }
            else
            {
                char buf[MAX_STRING_LENGTH];

                sprintf(buf, "Bad IP address string: %s", addressString);
                ERROR_ReportError(buf);
            }//if//
        }
        else
        {
            if (addressString[i] == ':')
            {
                isReadingNumber = FALSE;
                nodeAddress += currentNumber;
                nodeAddress = nodeAddress * 0x10000;
            }
            else
            if (addressString[i] == '.')
            {
                isReadingNumber = FALSE;
                nodeAddress += currentNumber;
                nodeAddress = nodeAddress * 0x100;
            }
            else
            if (isHex && isxdigit((int)addressString[i]))
            {
                char aString[2];
                int digit;
                aString[0] = addressString[i];
                aString[1] = 0;

                digit = strtoul(aString, NULL, 16);

                currentNumber = currentNumber * 0x10 + digit;
            }
            else
            if (!isHex && isdigit((int)addressString[i]))
            {
                int digit;
                char aString[2];
                aString[0] = addressString[i];
                aString[1] = 0;
                digit = strtoul(aString, NULL, 10);

                currentNumber = currentNumber * 10 + digit;
            }
            else
{
                char buf[MAX_STRING_LENGTH];

                sprintf(buf, "Bad IP address string: %s", addressString);
                ERROR_ReportError(buf);
            }

            i++;
        }//if//
    }//while//

    *outputNodeAddress = nodeAddress + currentNumber;
}

// /**
// FUNCTION            :: ARPNotificationOfPacketDrop
// LAYER       :: NETWORK
// PURPOSE             :: Notify for ARP Drop
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + msg : Message**  : Message pointer
// + nextHopAddress : NodeAddress : Ip address of node
// + interfaceIndex : int  : outgoing interface.
// RETURN      :: NULL
// **/
void ARPNotificationOfPacketDrop(Node *node,
                                 Message *msg,
                                 NodeAddress nextHopAddress,
                                 int interfaceIndex)
{
    //do nothing
    return;
}
// DHCP
//---------------------------------------------------------------------------
// FUNCTION            :: ArpCheckAddressForDhcp
// LAYER       :: NETWORK
// PURPOSE             :: Validate the Ipaddress for DHCP
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + Address : ipAddress  : Address to check
// + incomingInterface : int  : interface for broadcast
// RETURN      ::
// BOOL ......result
//---------------------------------------------------------------------------
void ArpCheckAddressForDhcp(
             Node* node,
             Address ipAddress,
             Int32 interfaceIndex)
{
    ArpData* arpData = NULL;
    arpData = ArpGetProtocolData(node);

    // Make the entry in ARP database
    BOOL isFlooding = ArpPreventFlooding(
                        node,
                        NULL,
                        arpData,
                        ipAddress.interfaceAddr.ipv4,
                        node->getNodeTime(),
                        APP_DEFAULT_TOS,
                        interfaceIndex,
                        interfaceIndex,
                        ipAddress.networkType,
                        TRUE);
    if (!isFlooding) // if not leading to flooding send arp request
    {
        ArpSendRequest(
                 node,
                 ipAddress.interfaceAddr.ipv4,
                 arpData,
                 interfaceIndex);
    }
    return;
}
#if 0

// /**
// FUNCTION    :: ArpProxy
// LAYER       :: NETWORK
// PURPOSE     :: This function is used for Proxy ARP reply.
//                It is special used by home agent or gateway to
//                to response in absence of host in home network.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : arp Request or Reply message
// + interfaceIndex : int  : Interface Index
// + proxyIp        : NodeAddress : The Ip address of the host
//                    whose proxy has been given.
// RETURN      :: void : NULL
// **/
void ArpProxy(
         Node* node,
         Message* msg,
         int interfaceIndex,
         NodeAddress proxyIp)
{
    BOOL margeFlag = FALSE;
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);
    ArpData* arpData = ArpGetProtocolData(node);
    MacHWAddress srcHWAddress;
    unsigned short hwType;
    MacGetHardwareType(node, interfaceIndex, &hwType);

    //whether it is required for Proxy ARP
    arpData->stats.totalPacketArrived += 1;

    if (packet->hardType == hwType)
    {
        // skip: optional check on the hardware length ar$hln

        if (ArpIsSupportedProtocol(packet->protoType))
        {
            // skip: optional check the protocol length ar$pln

            clocktype currentTime = node->getNodeTime();
            margeFlag = FALSE;

            // If the pair <protocol type, sender protocol address> is
            // already in my translation table, update the sender
            // hardware address field of the entry with the new
            // information in the packet and set Merge_flag to true.
            srcHWAddress.byte =  packet->s_macAddr;
            srcHWAddress.hwLength = (unsigned short) packet->hardSize;
            srcHWAddress.hwType = packet->hardType;

            margeFlag = ArpTTableUpdateEntry(
                            node,
                            arpData,
                            packet->protoType,
                            packet->s_IpAddr,
                            &srcHWAddress,
                            currentTime);

            // If Merge_flag is false, add the triplet
            //<protocol type, sender protocol addr, sender hardware addr>
            // to the translation table.
            if (!margeFlag)
            {
                //Think about the "currentTime" parameter
                ArpTTableAddEntry(
                    node,
                    packet->s_IpAddr,
                    interfaceIndex,
                    packet->protoType,
                    &srcHWAddress,
                    currentTime);
            }

            if (packet->opCode == ARPOP_REQUEST)
            {
                // Create proxy ARP reply packet
                Message* arpReplyMsg = ArpProxyCreatePacket(
                                            node,
                                            arpData,
                                            ARPOP_REPLY,
                                            proxyIp,
                                            packet->s_IpAddr,
                                            srcHWAddress,
                                            interfaceIndex);

                ArpPacket* arpPacket = (ArpPacket*) arpReplyMsg->packet;

                // Updare ARP Cache stats
                arpData->stats.totalReqRecvd += 1;
                arpData->stats.totalReplySend += 1;

                //statistics for proxy ARP
                arpData->stats.totalProxyReply += 1;

                if (LlcIsEnabled(node, interfaceIndex))
                {
                    LlcAddHeader(node, arpReplyMsg, PROTOCOL_TYPE_ARP);
                }
                MacHWAddress destHWAddr;
                MacHWAddress srcHWAddr;
                destHWAddr.byte = arpPacket->d_macAddr;
                destHWAddr.hwLength = (unsigned short) arpPacket->hardSize;
                srcHWAddr.byte = arpPacket->s_macAddr;
                srcHWAddr.hwLength = (unsigned short) arpPacket->hardSize;

                ArpSendProtocolPacketToMac(
                    node,
                    arpReplyMsg,
                    interfaceIndex,
                    &destHWAddr,
                    &srcHWAddr);
                    //&arpPacket->d_macAddr,
                    //&arpPacket->s_macAddr);
            }
            else
            {
                ERROR_Assert(FALSE, "ARP Invalid Message Received\n");
            }
        }
    }
    MESSAGE_Free(node, msg);
}


// /**
// FUNCTION      :: ArpProxyCreatePacket
// LAYER         :: NETWORK
// PURPOSE       :: This function creates an ARP reply packet
//                  for the node which is not in same home network.
// PARAMETERS    ::
// + node         : Node* : Pointer to node which indiates the host.
// + arpData      : ArpData* : arp main Data structure of this interface.
// + opCode       : ArpOp : Type of operation that is Reply in case of
//                          proxy arp.
// + proxyAddress : NodeAddress : used for proxy IP
// + destIPAddr   : NodeAddress :
// + dstMacAddr   : MacAddress  :
// + interfaceIndex: int        :
// RETURN      :: Message* : Pointer to a Message structure
// **/
Message* ArpProxyCreatePacket(
             Node* node,
             ArpData* arpData,
             ArpOp opCode,
             NodeAddress proxyAddress,
             NodeAddress destAddr,
             MacHWAddress dstMacAddr,
             int interfaceIndex)
{
    ArpPacket* arpPacket;
    unsigned short hwType;
    unsigned short hwLength;

    //ARP message has been allocated
    //The memory space has been assigned
    Message* arpMsg = MESSAGE_Alloc(node,
                                    NETWORK_LAYER,
                                    NETWORK_PROTOCOL_ARP,
                                    0);

    MESSAGE_PacketAlloc(node, arpMsg, sizeof(ArpPacket), TRACE_ARP);

    arpPacket = (ArpPacket*) arpMsg->packet;
    memset(arpPacket, 0, sizeof(ArpPacket));
    MacGetHardwareType(node, interfaceIndex, &hwType);
    arpPacket->hardType = hwType;
    MacGetHardwareLength(node, interfaceIndex, &hwLength);
    unsigned char* srcHWString;
    srcHWString = (unsigned char*)MEM_malloc(sizeof(unsigned char)*hwLength);
    MacGetHardwareAddressString(node, interfaceIndex, srcHWString);

    if (arpPacket->hardType == ARP_HRD_ETHER)
    {
        memcpy(arpPacket->d_macAddr,
               dstMacAddr.byte, dstMacAddr.hwLength);
        arpPacket->hardSize = (unsigned char) dstMacAddr.hwLength;
        //arpPacket->hardSize = MAC_ADDRESS_LENGTH_IN_BYTE;

        memcpy(
            arpPacket->s_macAddr,
            srcHWString,
            //arpData->interfaceInfo[interfaceIndex].hwAddr.byte,
            hwLength);
    }
    else
    {
        ERROR_Assert(FALSE, "Hardware type not supported.\n");
    }

    if (arpData->interfaceInfo[interfaceIndex].protoType ==
                                                PROTOCOL_TYPE_IP)
    {
        arpPacket->protoSize = ARP_PROTOCOL_ADDR_SIZE_IP;
        arpPacket->protoType = PROTOCOL_TYPE_IP;
        arpPacket->s_IpAddr =  proxyAddress; //The IP of the node whose
                                             //proxy has been given.
        arpPacket->d_IpAddr = destAddr;
    }
    else
    {
        ERROR_Assert(FALSE, "Protocol suit not supported.\n");
    }

    arpPacket->opCode = opCode;

    // Proxy ARP Debugs
    if (ARPPROXY_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("ARP: Node %d sending a Reply packet at %s Sec",
            node->nodeId, clockStr);
    }

    if (ARPPROXY_PACKET_DEBUG)
    {
        ArpPrintProtocolPacket(arpPacket);
    }

    //Trace sending pkt
    /*
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, arpMsg, TRACE_NETWORK_LAYER,
                    PACKET_OUT, &acnData);
    */
    return (arpMsg);
}


// /**
// FUNCTION    :: ArpGratuitous
// LAYER       :: NETWORK
// PURPOSE     :: This function is used for Gratuitous ARP reply.
//                It is special used by home agent or gateway to
//                to update the others ARP cache when the host
//                (which is responsible) came to know that the
//                host is not at home network. Gratuitous may be either
//                ARP request or ARP reply. Here ARP-request has been used
// PARAMETERS  ::
// + node      : Node* : Pointer to node that is host which
//                       is either gateway or home agent.
// + msg       : Message* : arp Request or Reply message
// + interfaceIndex : int : Interface Index
// + gratIPAddress  : NodeAddress : The Ip address of the host
//                                  whose mac address has beenupdated
//                                  in the ARP-cache table of other nodes.
// RETURN      :: void : NULL
// **/
void ArpGratuitous(
         Node* node,
         Message* msg,
         int interfaceIndex,
         NodeAddress gratIPAddress)
{
    MacHWAddress destMacAddr;
    ArpData* arpData = NULL; //We can passed this argument from the position
                             //where the function has been called
    unsigned short hwLength;
    unsigned short hwType;
    MacGetHardwareType(node, interfaceIndex, &hwType);
    MacGetHardwareLength(node, interfaceIndex, &hwLength);
    destMacAddr.hwLength = hwLength;
    destMacAddr.hwLength = hwType;

    memset(destMacAddr.byte, 0xff, destMacAddr.hwLength);
    ArpPacket* packet = (ArpPacket*) MESSAGE_ReturnPacket(msg);

    arpData = ArpGetProtocolData(node);
    Message* arpRequestMsg = ArpGratuitousCreatePacket(
                                node,
                                arpData,
                                ARPOP_REQUEST,
                                gratIPAddress,
                                packet->s_IpAddr,
                                destMacAddr,
                                interfaceIndex);

    ArpPacket* arpPacket = (ArpPacket*) arpRequestMsg->packet;

    arpData->stats.totalReqSend += 1;

    if (LlcIsEnabled(node, interfaceIndex))
    {
        LlcAddHeader(node, arpRequestMsg, PROTOCOL_TYPE_ARP);
    }
    //Statistics for gratuitous request
    arpData->stats.totalGratReqSend += 1;
    MacHWAddress srcHWAddress;
    MacHWAddress destHWAddress;
    destHWAddress.byte = destMacAddr.byte;
    destHWAddress.hwLength = MAC_ADDRESS_LENGTH_IN_BYTE;
    srcHWAddress.byte = arpPacket->s_macAddr;
    srcHWAddress.hwLength = (unsigned short)arpPacket->hardSize;
    ArpSendProtocolPacketToMac(
        node,
        arpRequestMsg,
        interfaceIndex,
        &destHWAddress,
        &srcHWAddress);
        //&destMacAddr,
        //&arpPacket->s_macAddr);
}


// /**
// FUNCTION      :: ArpGratuitousCreatePacket
// LAYER         :: NETWORK
// PURPOSE       :: This function creates an ARP reply packet
//                  for the node which is not in same home network.
// PARAMETERS    ::
// + node         : Node* : Pointer to node which indiates the host.
// + arpData      : ArpData* : arp main Data structure of this interface.
// + opCode       : ArpOp : The ARP message type
// + gratIPAddress: NodeAddress : The ip against whose the MAC addess
//                                 will be updated.
// + destIPAddr   : NodeAddress : The node who has send the ARP-request
// + dstMacAddr   : MacAddress  : The node who has send the ARP-request
// + interfaceIndex: int :
// RETURN      :: Message* : Pointer to a Message structure
// **/
Message* ArpGratuitousCreatePacket(
             Node* node,
             ArpData* arpData,
             ArpOp opCode,
             NodeAddress gratIPAddress,
             NodeAddress destIPAddr,
             MacHWAddress dstMacAddr,
             int interfaceIndex)
{
    ArpPacket* arpPacket;
    Message* arpMsg = MESSAGE_Alloc(
                        node,
                        NETWORK_LAYER,
                        NETWORK_PROTOCOL_ARP,
                        0);

    MESSAGE_PacketAlloc(node, arpMsg, sizeof(ArpPacket), TRACE_ARP);

    arpPacket = (ArpPacket*) arpMsg->packet;
    memset(arpPacket, 0, sizeof(ArpPacket));
    unsigned short hwType;
    MacGetHardwareType(node, interfaceIndex, &hwType);
    arpPacket->hardType = hwType;

    if (arpPacket->hardType == ARP_HRD_ETHER)
    {
        memcpy(arpPacket->d_macAddr,
               dstMacAddr.byte, dstMacAddr.hwLength);

        arpPacket->hardSize = (unsigned char)dstMacAddr.hwLength;
        MacGetHardwareAddressString(node, interfaceIndex, arpPacket->s_macAddr);
    }
    else
    {
        ERROR_Assert(FALSE, "Hardware type not supported.\n");
    }

    if (arpData->interfaceInfo[interfaceIndex].protoType ==
       PROTOCOL_TYPE_IP)
    {
        arpPacket->protoSize = ARP_PROTOCOL_ADDR_SIZE_IP;
        arpPacket->protoType = PROTOCOL_TYPE_IP;
        arpPacket->s_IpAddr = gratIPAddress; // The ip address of the
                                             // node which is not at
                                             // home-network
        arpPacket->d_IpAddr = destIPAddr;
    }
    else
    {
        ERROR_Assert(FALSE, "Protocol suit not supported.\n");
    }

    arpPacket->opCode = opCode;

    // ARP Debugs
    if (ARPGratuitous_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("ARP: Node %d sending a %s packet at %s Sec", node->nodeId,
            (arpPacket->opCode == ARPOP_REQUEST) ? "REQUEST" : "REPLY",
            clockStr);
    }

    if (ARPGratuitous_PACKET_DEBUG)
    {
        ArpPrintProtocolPacket(arpPacket);
    }

    //Trace sending pkt
    /* Note Commented after discussion with TRACE team
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, arpMsg, TRACE_NETWORK_LAYER,
                    PACKET_OUT, &acnData);
    */

    return(arpMsg);
}

// /**
// FUNCTION    :: ArpPrintTrace
// LAYER       :: NETWORK
// PURPOSE     :: Print out packet trace information.
// PARAMETERS  ::
// + node       : Node* : node printing out the trace information.
// + msg        : Message* : packet to be printed.
// RETURN      :: void : NULL
// **/
void ArpPrintTrace(Node *node, Message *msg)
{
/*
    char buf[MAX_STRING_LENGTH] = {0};
    ArpPacket* arpPacket = (ArpPacket*) MESSAGE_ReturnPacket(msg);

    sprintf(buf, "%d", arpPacket->hardType);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->protoType);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->hardSize);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->protoSize);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->opCode);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->s_macAddr);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%u", arpPacket->s_IpAddr);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%d", arpPacket->d_macAddr);
    TRACE_WriteToBuffer(node, buf);
    sprintf(buf, "%u", arpPacket->d_IpAddr);
    TRACE_WriteToBuffer(node, buf);
*/
    }


// /**
// FUNCTION    :: ArpInitTrace
// LAYER       :: NETWORK
// PURPOSE     :: Determine what kind of packet trace we need to worry about.
// PARAMETERS  ::
// + Node       : Node* : node doing the packet trace.
// + nodeInput : const NodeInput* : structure containing
//               contents of input file
// RETURN      :: void : NULL
//Note: The function has been commented after discussion with TRACE team
// **/
static
void ArpInitTrace(
         Node* node,
         const NodeInput* nodeInput)
{
/*
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll;

    traceAll = TRACE_IsTraceAll(node);

    IO_ReadString(node->nodeId,
        ANY_ADDRESS,
        nodeInput,
                  "TRACE-ARP",
        &retVal,
                  buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            if (!traceAll)
    {
                TRACE_EnableTrace(node, TRACE_ARP);
            }
    }
        else if (strcmp(buf, "NO") == 0)
        {
            if (traceAll)
    {
                TRACE_DisableTrace(node, TRACE_ARP);
            }
    }
        else
   {
            ERROR_ReportError("TRACE-ARP should be either \"YES\" or \""
                              "NO\".\n");
   }
    }
    else
    {
        TRACE_DisableTrace(node, TRACE_ARP);
    }
*/
}

#endif
