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
#include <stdlib.h>
#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>   /* for ip_mreq */
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include <netdb.h>
#endif

#include "api.h"
#include "fileio.h"
#include "external.h"
#include "external_util.h"
#include "partition.h"
#include "mac.h"
#include "phy.h"
#include "phy_802_11.h"
#include "mac_dot11.h"
#include "network_ip.h"

#include "socketlayer_api.h"
#include "socketlayer.h"

#include "ControlMessages.h"
#include "upa_common.h"
#include "qualnet_upa.h"
#include "upa_proc_net.h"

#ifdef AUTO_IPNE_INTERFACE
#include "auto-ipnetworkemulator.h"
#endif

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

//#define DEBUG
//#define DEBUG0

#ifndef _WIN32
typedef int SOCKET;
#endif

#define MAX_CONNECTION_MANAGERS 32

#define MAX_INTERFACE 100

/* TO be moved to private header file */
typedef struct upa_hash_node_str {
    int nodeId;
    int qualnet_fd;
    struct sockAddrInfo phyAddr;

    struct upa_hash_node_str* next;
    struct upa_hash_node_str* prev;
} UPAHashNode;

typedef struct {
    int controlChannel;
    int controlChannelIPv6;
    int dataChannel;
    int dataChannelIPv6;
    int ipv6MulticastChannel;
    int activeControlChannel[MAX_CONNECTION_MANAGERS];
    ipv6_mreq multicastRequest;
    int activeConnectionManagers;
    sockAddrInfo ConnectionManagers[MAX_CONNECTION_MANAGERS];
    BOOL firstMessage[MAX_CONNECTION_MANAGERS];
    clocktype nextCMBeaconAt;

    UPAHashNode* hashTable;
} UPAData;


struct InsertHashStr
{
    int qualnet_fd;
    int nodeId;
    struct sockAddrInfo addr;
};


/* We dont want to put this large buffer in the function stack.
    This buffer will be used by master partition only, so there is no need
    to lock it, or worry about concurrent access */
static char* g_payload;
static int g_payloadSize;

/************
 * 1. UPA_Initialize: read nodeInput for port number and other config inputs
 * 2. do something about char data[UPA_RECV_BUF_SIZE]
 *****************************************/

#define UPA_RECV_BUF_SIZE 8*1024
//char upaGlobalData[UPA_RECV_BUF_SIZE];


// API       :: SockaddrToAddress
// PURPOSE   :: This function is used to convert
//              standard address structure "sockaddr"
//              to Qualnet address structure "Address"
// PARAMETERS::
// + sockAddress :sockaddr*: (Input) pointer to struct sockaddr to be conveted,
// + address     :Address* : (Output) pointer to struct Address
// RETURN    :: void       : NULL
void SockaddrToAddress(sockaddr* sockAddress, Address* address)
{
    if (sockAddress->sa_family == AF_INET)
    {
        sockaddr_in* temp = (sockaddr_in*)sockAddress;
        address->networkType = NETWORK_IPV4;
        address->interfaceAddr.ipv4 = htonl(temp->sin_addr.s_addr);
    }
    else if (sockAddress->sa_family == WIN_AF_INET6
        || sockAddress->sa_family == UNIX_AF_INET6)
    {
        sockaddr_in6* temp = (sockaddr_in6*)sockAddress;
        address->networkType = NETWORK_IPV6;
        memcpy(&(address->interfaceAddr.ipv6),
               &(temp->sin6_addr.s6_addr),
               sizeof(temp->sin6_addr));
    }
}

// API       :: AddressToSockaddr
// PURPOSE   :: This function is used to convert
//              Qualnet address structure "Address" to
//              standard address structure "sockaddr"
// PARAMETERS::
// + sockAddress :sockaddr*: (Output) pointer to struct sockaddr
//                           NULL to get the size of sockaddr,
// + address     :Address* : (Input) pointer to struct Address to be conveted
// RETURN    :: int        : Size of sockaddr
int AddressToSockaddr(sockaddr* sockAddress, Address* address)
{
    Int32 size = 0;
    if (address->networkType == NETWORK_IPV4)
    {
        size = sizeof(sockaddr_in);
        if (sockAddress == NULL)
        {
            return size;
        }
        sockaddr_in* temp = (sockaddr_in*)sockAddress;
        memset(temp, 0, size);
        temp->sin_family = AF_INET;
        temp->sin_addr.s_addr = ntohl(address->interfaceAddr.ipv4);
    }
    else if (address->networkType == NETWORK_IPV6)
    {
        size = sizeof(sockaddr_in6);
        if (sockAddress == NULL)
        {
            return size;
        }
        sockaddr_in6* temp = (sockaddr_in6*)sockAddress;
        memset(temp, 0, size);
        temp->sin6_family = AF_INET6;
        memcpy(&(temp->sin6_addr.s6_addr),
               &(address->interfaceAddr.ipv6),
               sizeof(temp->sin6_addr));
    }
    return size;
}

unsigned short
GetPortFromSockaddr(sockaddr* address)
{
    unsigned short port;
    if (address->sa_family == AF_INET)
    {
        port = ((sockaddr_in*)address)->sin_port;
    }
    else
    {
        port = ((sockaddr_in6*)address)->sin6_port;
    }
    return port;
}

void
SetPortFromSockaddr(sockaddr* address, unsigned short port, UInt32* length)
{
    if (address->sa_family == AF_INET)
    {
        ((sockaddr_in*)address)->sin_port = port;
        if (length != NULL)
        {
            *length = sizeof(sockaddr_in);
        }
    }
    else
    {
        ((sockaddr_in6*)address)->sin6_port = port;
        if (length != NULL)
        {
            *length = sizeof(sockaddr_in6);
        }
    }
}

int
GetSockaddrLength(sockaddr* address)
{
    if (address->sa_family == AF_INET)
    {
        return sizeof(sockaddr_in);
    }
    else
    {
        return sizeof(sockaddr_in6);
    }
}

void
CopySockaddrToSockAddrInfo(sockaddr* address, sockAddrInfo* addrInfo)
{
#ifndef _WIN32
    if (address->sa_family == WIN_AF_INET6)
    {
        address->sa_family = UNIX_AF_INET6;
    }
#endif
    addrInfo->sin_family = address->sa_family;
    if (address->sa_family == AF_INET)
    {
        memcpy(&addrInfo->address.ipv4, address, sizeof(sockaddr_in));
    }
    else
    {
        memcpy(&addrInfo->address.ipv6, address, sizeof(sockaddr_in6));
    }
}

void UPA_InsertHash(
    EXTERNAL_Interface* iface,
    int nodeId,
    int qualnet_fd,
    sockaddr* phyAddr)
{
    UPAData* upaData = (UPAData*)(iface->data);
    UPAHashNode* hashNode;

    if (iface->partition->partitionId
        == iface->partition->masterPartitionForCluster)
    {
        hashNode  = (UPAHashNode*)MEM_malloc(sizeof(UPAHashNode));

        hashNode->nodeId = nodeId;
        hashNode->qualnet_fd = qualnet_fd;
        hashNode->phyAddr.sin_family = phyAddr->sa_family;
        CopySockaddrToSockAddrInfo(phyAddr, &hashNode->phyAddr);
        hashNode->next = upaData->hashTable;
        hashNode->prev = NULL;

        upaData->hashTable = hashNode;
    }
    else
    {
        Message* msg;
        msg = MESSAGE_Alloc(iface->partition->firstNode,
                    EXTERNAL_LAYER,
                    EXTERNAL_UPA,
                    EXTERNAL_MESSAGE_UPA_InsertHash);

        if (msg == NULL)
        {
            printf("Cannot allocate message %s %d\n", __FILE__, __LINE__);
            return;
        }

        InsertHashStr* hashStr = NULL;

        MESSAGE_PacketAlloc(iface->partition->firstNode,
                    msg,
                    sizeof(InsertHashStr),
                    TRACE_SOCKETLAYER);

        hashStr = (InsertHashStr*) MESSAGE_ReturnPacket(msg);

        hashStr->qualnet_fd = qualnet_fd;
        hashStr->nodeId = nodeId;
        CopySockaddrToSockAddrInfo(phyAddr, &hashStr->addr);

        EXTERNAL_MESSAGE_RemoteSend(iface,
                iface->partition->masterPartitionForCluster,
                msg,
                0,
                EXTERNAL_SCHEDULE_SAFE);
    }
}

int UPA_RetrieveHash(
    EXTERNAL_Interface* iface,
    int* nodeId,
    int* qualnet_fd,
    sockaddr* phyAddr)
{
    UPAData* upaData = (UPAData*)(iface->data);
    UPAHashNode* hashNode = upaData->hashTable;

    UInt32 phyAddrLength = GetSockaddrLength(phyAddr);
    while (hashNode)
    {
        if (!memcmp(&hashNode->phyAddr.address, phyAddr, phyAddrLength))
        {
            *nodeId = hashNode->nodeId;
            *qualnet_fd = hashNode->qualnet_fd;
            return 0;
        }

        hashNode = hashNode->next;
    }
    return -1;
}

void UpaPrepareSocketCloseMessage(
    upa_hdr* uhdr)
{
    uhdr->msg_type         = UPA_MSG_CLOSE;
    uhdr->port             = UPA_MAGIC16_1;
    uhdr->upa_node         = UPA_MAGIC32_1;
    uhdr->qualnet_fd    = UPA_MAGIC32_2;
    uhdr->address         = UPA_MAGIC32_3;
}

void UPA_TransmitPacket(
    EXTERNAL_Interface* iface,
    Node* node,
    char* data,
    int dataSize,
    sockaddr* phy_addr,
    UInt32 phy_addr_len)
{
    UPAData* upaData;
    int retVal;

    upaData = (UPAData*)(iface->data);
    int channel = 0;

    if (node->partitionData->partitionId
        == node->partitionData->masterPartitionForCluster)
    {
        if (phy_addr->sa_family == AF_INET)
        {
            channel = upaData->dataChannel;
        }
        else
        {
            channel = upaData->dataChannelIPv6;
        }
        do
        {
            retVal = sendto(channel,
                            data,
                            dataSize,
                            0,
                            phy_addr,
                            phy_addr_len);
#ifdef _WIN32
        }while (retVal < 0 && GetLastError() == WSAEWOULDBLOCK);
#else
        }while (retVal < 0 && errno == EWOULDBLOCK);
#endif

        if (retVal < 0)
        {
            Address phyAddr;
            SockaddrToAddress(phy_addr, &phyAddr);
            char strPhyAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&phyAddr, strPhyAddr);
            unsigned short phyAddrPort = GetPortFromSockaddr(phy_addr);
            printf("[UPA %d (%d %d)] Cannot send packet: %d %s to %s:%d\n",
                   node->nodeId,
                   node->partitionId,
                   node->partitionData->partitionId,
                   retVal,
                   strerror(errno),
                   strPhyAddr,
                   htons(phyAddrPort));
        }
    }
    else
    {
        Message* msg;
        msg = MESSAGE_Alloc(node,
                EXTERNAL_LAYER,
                EXTERNAL_UPA,
                EXTERNAL_MESSAGE_UPA_SendPacket);

        MESSAGE_PacketAlloc(node, msg, dataSize, TRACE_SOCKETLAYER);
        memcpy(MESSAGE_ReturnPacket(msg), data, dataSize);
        MESSAGE_AddHeader(node,
                          msg,
                          phy_addr_len,
                          TRACE_SOCKETLAYER);
        memcpy(MESSAGE_ReturnPacket(msg),
               (char*)phy_addr,
               phy_addr_len);

        EXTERNAL_MESSAGE_RemoteSend(iface,
                node->partitionData->masterPartitionForCluster,
                msg,
                0,
                EXTERNAL_SCHEDULE_SAFE);
    }
}

void UPA_SendPacket(
    Node* node,
    int fd,
    char* data,
    int dataSize,
    BOOL containsUpaHeader)
{
    EXTERNAL_Interface* iface;
    sockaddr* phy_addr;
    UInt32 phy_addr_len = 0;

    iface = node->partitionData->interfaceTable[EXTERNAL_UPA];
    if (!iface)
    {
        ERROR_ReportError("UPA Interface is not configured in EXata");
    }

    SL_ioctl(node,
             fd,
             CtrlMsg_UPA_GetPhysicalAddress,
             NULL,
             &phy_addr_len);

    phy_addr = (sockaddr*)MEM_malloc(phy_addr_len);

    SL_ioctl(node,
             fd,
             CtrlMsg_UPA_GetPhysicalAddress,
             phy_addr,
             &phy_addr_len);

#if 0
    if (containsUpaHeader)
    {
        struct upa_hdr* uhdr = (struct upa_hdr*)data;
        uhdr->msg_type     = htons(uhdr->msg_type);
        uhdr->port         = htons(uhdr->port);
        uhdr->upa_node    = htonl(uhdr->upa_node);
        uhdr->address    = htonl(uhdr->address);
        uhdr->qualnet_fd= htonl(uhdr->qualnet_fd);
    }
#endif

    UPA_TransmitPacket(iface, node, data, dataSize, phy_addr, phy_addr_len);
    MEM_free(phy_addr);
}





void UPA_CreateNewSocket(
    EXTERNAL_Interface* iface,
    Node* node,
    char* data,
    struct sockaddr* fromAddr,
    int addrLength)
{
    struct upa_hdr* uhdr = (struct upa_hdr*)&data[0];
    struct new_sock_msg_data* msg_data =
        (struct new_sock_msg_data*)&data[UPA_HDR_SIZE];
    struct sockaddr* local_addr;
    UInt32 addrLen = addrLength;
    unsigned short port = 0;

    int qualnet_fd, retVal;

#ifndef _WIN32
    if (ntohl(msg_data->family) == WIN_AF_INET6)
    {
        msg_data->family = htonl(UNIX_AF_INET6);
    }
#endif
    qualnet_fd = SL_socket(node,
                    ntohl(msg_data->family),
                    ntohl(msg_data->protocol),
                    ntohl(msg_data->type));
    if (qualnet_fd == -1)
    {
        printf("qualnet_fd == -1");
    }

    if (ntohl(msg_data->type) == SOCK_STREAM)
    {
        SocketLayerRegisterCallbacks(node,
                qualnet_fd,
                UPA_HandleEgressPacket,
                NULL,
                UPA_TcpListen,
                UPA_TcpAccept,
                UPA_TcpConnect,
                UPA_SendDone);
    }
    else if (ntohl(msg_data->type) == SOCK_DGRAM)
    {
        SocketLayerRegisterCallbacks(node,
                qualnet_fd,
                UPA_HandleEgressPacket,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL);
    }
    else
    {
        printf("Unexpected socket protocol type [%d]. Expecting %d or %d\n",
            ntohl(msg_data->protocol), SOCK_STREAM, SOCK_DGRAM);
        printf("Socket type is %d. Expected %d %d\n", ntohl(msg_data->type),
            IPPROTO_TCP, IPPROTO_UDP);
        assert(0);
    }
    retVal = SL_ioctl(node, qualnet_fd, CtrlMsg_UPA_SetUpaSocket, 0);

    retVal = SL_ioctl(node,
                      qualnet_fd,
                      CtrlMsg_UPA_SetPhysicalAddress,
                      fromAddr,
                      &addrLen);
    assert(retVal >= 0);

    retVal = SL_ioctl(node,
                      qualnet_fd,
                      CtrlMsg_MAC_GetInterfaceAddress,
                      NULL,
                      &addrLen);
    local_addr = (sockaddr*)malloc(addrLen);
    retVal = SL_ioctl(node,
                      qualnet_fd,
                      CtrlMsg_MAC_GetInterfaceAddress,
                      local_addr,
                      &addrLen);
    port = GetPortFromSockaddr(local_addr);
    assert(retVal >= 0);

    UPA_InsertHash(iface,
                   node->nodeId,
                   qualnet_fd,
                   fromAddr);

    uhdr->qualnet_fd = qualnet_fd;
    uhdr->address = addrLen;
    uhdr->port = htons(port);
    memcpy((char*)uhdr + UPA_HDR_SIZE, local_addr, addrLen);

#ifdef DEBUG
    Address debugAddr;
    Address localAddr;
    SockaddrToAddress(fromAddr, &debugAddr);
    SockaddrToAddress(local_addr, &localAddr);
    char strAddr[MAX_STRING_LENGTH];
    char strLocalAddr[MAX_STRING_LENGTH];
    IO_ConvertIpAddressToString(&debugAddr, strAddr);
    IO_ConvertIpAddressToString(&localAddr, strLocalAddr);
    int debugPort = GetPortFromSockaddr(fromAddr);
    printf("[UPA %d] New Socket request from Phy=<%s:%d> Virtual=<%s:%d>\n",
        node->nodeId,
        strAddr,
        htons(debugPort),
        strLocalAddr,
        htons(uhdr->port));
#endif

    UPA_SendPacket(node, qualnet_fd, data, UPA_HDR_SIZE + addrLen, TRUE);
}

void UPA_HandleIngressData(
    EXTERNAL_Interface* iface,
    struct sockaddr* fromAddr,
    char* data,
    int length)
{
    int nodeId, qualnet_fd;
    Node* node;
    unsigned short port = GetPortFromSockaddr(fromAddr);
    Address debugAddr;
    SockaddrToAddress(fromAddr, &debugAddr);
    char strAddr[MAX_STRING_LENGTH];
    IO_ConvertIpAddressToString(&debugAddr, strAddr);

#ifdef DEBUG0
    printf("[UPA] Got %d bytes data from %x:%d\n",
        length,
        strAddr,
        htons(port));
#endif

    if (UPA_RetrieveHash(iface,
                &nodeId,
                &qualnet_fd,
                fromAddr) < 0)
    {
        printf("Cannot find existing connection at hash table\n");
        printf("Address = %s:%d\n", strAddr, htons(port));
        return;
    }

    node = MAPPING_GetNodePtrFromHash(
                iface->partition->nodeIdHash,
                nodeId);

    if (node == NULL)
    {
        node = MAPPING_GetNodePtrFromHash(
                iface->partition->remoteNodeIdHash,
                nodeId);
        if (node == NULL)
        {
            printf("Cannot find valid node at hash table\n");
            return;
        }

        Message* msg;
        msg = MESSAGE_Alloc(node,
                EXTERNAL_LAYER,
                EXTERNAL_UPA,
                EXTERNAL_MESSAGE_UPA_HandleIngressData);

        MESSAGE_PacketAlloc(node, msg, length, TRACE_SOCKETLAYER);
        memcpy(MESSAGE_ReturnPacket(msg), data, length);
        MESSAGE_SetInstanceId(msg, qualnet_fd);
        EXTERNAL_MESSAGE_SendAnyNode(iface,
                                    node,
                                    msg,
                                    0,
                                    EXTERNAL_SCHEDULE_SAFE);
        return;

    }

#ifdef DEBUG
    printf("[%d] handling ingress data %d %d %d\n",
           node->nodeId,
           node->partitionId,
           node->partitionData->partitionId,
           iface->partition->partitionId);
#endif
#ifdef DEBUG0
    printf("Giving to node %d at fd = %d\n", node->nodeId, qualnet_fd);
#endif

    SL_send(node,
            qualnet_fd,
            data,
            length);
}

// API        :: StatsManager_HandleCommand
// PURPOSE    :: Handles connection manager commands.
// PARAMETERS ::
// + iface    : EXTERNAL_Interface  : external interface data
// + msg      : upa_hdr*            : message to be handled
// + fromAddr : fromAddr*           : address of the sender
// RETURN     :: void : NULL
int UPA_HandleConnectionManager(
    EXTERNAL_Interface* iface,
    struct upa_hdr* msg,
    struct sockaddr* fromAddr)
{
    UPAData* upaData = (UPAData*)iface->data;

    sockAddrInfo fromAddrInfo;
    fromAddrInfo.sin_family = fromAddr->sa_family;

    if (fromAddr->sa_family == AF_INET)
    {
        fromAddrInfo.address.ipv4 = *(sockaddr_in*)fromAddr;
    }
    else if (fromAddr->sa_family == AF_INET6)
    {
        fromAddrInfo.address.ipv6 = *(sockaddr_in6*)fromAddr;
    }

    switch (msg->msg_type)
    {
        case UPA_MSG_CONNECTION_MANAGER:
        {
            // If we cannot handle more CMs, just bail out
            if (upaData->activeConnectionManagers >= MAX_CONNECTION_MANAGERS)
            {
                return -1;
            }

            // Check if an entry for this CM exists
            for (int i = 0; i < upaData->activeConnectionManagers; i++)
            {
                if (!memcmp(&(upaData->ConnectionManagers[i].address),
                            &(fromAddrInfo.address),
                            sizeof(fromAddrInfo.address)))
                {
                    upaData->firstMessage[i] = true;
                    return 0;
                }
            }

            memcpy(&upaData->
                        ConnectionManagers[upaData->activeConnectionManagers],
                   &fromAddrInfo,
                   sizeof(sockAddrInfo));
            upaData->firstMessage[upaData->activeConnectionManagers] = true;

            if (fromAddr->sa_family == AF_INET)
            {
                upaData->
                    activeControlChannel[upaData->activeConnectionManagers] =
                    upaData->controlChannel;
            }
            else if (fromAddr->sa_family == AF_INET6)
            {
                upaData->
                    activeControlChannel[upaData->activeConnectionManagers] =
                    upaData->controlChannelIPv6;
            }

            upaData->activeConnectionManagers++;
            if (upaData->activeConnectionManagers == 1)
            {
                upaData->nextCMBeaconAt =
                    iface->partition->firstNode->getNodeTime();
            }
            break;
        }
//#ifdef AUTO_IPNE_INTERFACE
        case UPA_MSG_AUTO_IPNE_REGISTER:
        {
            EXTERNAL_Interface* ipne;
            Address virtualAddress, phyAddress;
            int i = 0;
            ipne = EXTERNAL_GetInterfaceByName(
                    &iface->partition->interfaceList,
                    "IPNE");
            ERROR_Assert(ipne != NULL, "IPNE not loaded");
            char* message = (char*)msg;
            sockaddr* virtualAddr = (sockaddr*)(message + UPA_HDR_SIZE);
            sockaddr* phyAddr =
                (sockaddr*)(message + UPA_HDR_SIZE + msg->upa_node);
            SockaddrToAddress(virtualAddr, &virtualAddress);
            SockaddrToAddress(phyAddr, &phyAddress);

            struct upa_hdr packet;
            int replyPacketSize =
                UPA_HDR_SIZE + msg->upa_node + msg->qualnet_fd;
            char* replyMessage = (char*)MEM_malloc(replyPacketSize);

            if (virtualAddress.networkType == phyAddress.networkType)
            {
                if (AutoIPNE_AddVirtualNode(
                        ipne,
                        phyAddress,
                        virtualAddress,
                        FALSE))
                {
                    packet.msg_type = UPA_MSG_AUTO_IPNE_REGISTER_SUCCESS;
                }
                else
                {
                    packet.msg_type = UPA_MSG_AUTO_IPNE_REGISTER_UNSUCCESS;
                }
            }
            else
            {
                packet.msg_type = UPA_MSG_AUTO_IPNE_REGISTER_UNSUCCESS;
            }
            packet.port = msg->port;
            packet.upa_node = msg->upa_node;
            packet.qualnet_fd = msg->qualnet_fd;
            memcpy(replyMessage, &packet, UPA_HDR_SIZE);
            memcpy(replyMessage + UPA_HDR_SIZE,
                   message + UPA_HDR_SIZE,
                   msg->upa_node + msg->qualnet_fd);
            for (i = 0; i < upaData->activeConnectionManagers; i++)
            {
                if (!memcmp(&(upaData->ConnectionManagers[i].address),
                            &(fromAddrInfo.address),
                            sizeof(fromAddrInfo.address)))
                {
                    break;
                }
            }
            sendto(upaData->activeControlChannel[i],
                    replyMessage,
                    replyPacketSize,
                    0,
                    fromAddr,
                    GetSockaddrLength(fromAddr));
            MEM_free(replyMessage);
            break;
        }
        case UPA_MSG_AUTO_IPNE_UNREGISTER:
        {
            EXTERNAL_Interface* ipne;
            Address virtualAddress, phyAddress;
            int i = 0;
            ipne = EXTERNAL_GetInterfaceByName(
                    &iface->partition->interfaceList,
                    "IPNE");
            ERROR_Assert(ipne != NULL, "IPNE not loaded");
            char* message = (char*)msg;
            sockaddr* virtualAddr = (sockaddr*)(message + UPA_HDR_SIZE);
            sockaddr* phyAddr =
                (sockaddr*)(message + UPA_HDR_SIZE + msg->upa_node);
            SockaddrToAddress(virtualAddr, &virtualAddress);
            SockaddrToAddress(phyAddr, &phyAddress);

            struct upa_hdr packet;
            int replyPacketSize =
                UPA_HDR_SIZE + msg->upa_node + msg->qualnet_fd;
            char* replyMessage = (char*)MEM_malloc(replyPacketSize);

            if (virtualAddress.networkType == phyAddress.networkType)
            {

                if (AutoIPNE_RemoveVirtualNode(
                        ipne,
                        phyAddress,
                        virtualAddress,
                        FALSE))
                {
                    packet.msg_type = UPA_MSG_AUTO_IPNE_UNREGISTER_SUCCESS;
                }
                else
                {
                    packet.msg_type = UPA_MSG_AUTO_IPNE_UNREGISTER_UNSUCCESS;
                }
            }
            else
            {
                packet.msg_type = UPA_MSG_AUTO_IPNE_UNREGISTER_UNSUCCESS;
            }
            packet.port = msg->port;
            packet.upa_node = msg->upa_node;
            packet.qualnet_fd = msg->qualnet_fd;
            memcpy(replyMessage, &packet, UPA_HDR_SIZE);
            memcpy(replyMessage + UPA_HDR_SIZE,
                   message + UPA_HDR_SIZE,
                   msg->upa_node + msg->qualnet_fd);
            for (i = 0; i < upaData->activeConnectionManagers; i++)
            {
                if (!memcmp(&(upaData->ConnectionManagers[i].address),
                            &(fromAddrInfo.address),
                            sizeof(fromAddrInfo.address)))
                {
                    break;
                }
            }
            sendto(upaData->activeControlChannel[i],
                    replyMessage,
                    replyPacketSize,
                    0,
                    fromAddr,
                    GetSockaddrLength(fromAddr));
            break;
        }
        case UPA_MSG_SOLICIT_EXATA:
        {
            NodePointerCollection* allNodes = iface->partition->allNodes;
            NodePointerCollectionIter iter;
            msg->network_type = NETWORK_INVALID;
            NetworkType type = NETWORK_INVALID;
            Node* node;
            int channel;
            sockaddr* sockAddr = NULL;
            int sockAddrLen;
            if (fromAddrInfo.sin_family == AF_INET)
            {
                fromAddrInfo.address.ipv4.sin_port = htons(msg->port);
                sockAddr = (sockaddr*)&fromAddrInfo.address.ipv4;
                sockAddrLen = sizeof (sockaddr_in);
                channel = upaData->controlChannel;
            }
            else if (fromAddrInfo.sin_family == AF_INET6)
            {
                fromAddrInfo.address.ipv6.sin6_port = htons(msg->port);
                sockAddr = (sockaddr*)&fromAddrInfo.address.ipv6;
                sockAddrLen = sizeof (sockaddr_in6);
                channel = upaData->ipv6MulticastChannel;
            }
            for (iter = allNodes->begin(); iter != allNodes->end(); iter++)
            {
                node = *iter;
                if (!iface->partition->partitionOnSameCluster[node->partitionId])
                {
                    continue;
                }
                for (int i=0; i < node->numberInterfaces; i++)
                {
                    type = MAPPING_GetNetworkTypeFromInterface(node, i);
                    if ((fromAddrInfo.sin_family == AF_INET && type == NETWORK_IPV4)
                        || (fromAddrInfo.sin_family == AF_INET6 && type == NETWORK_IPV6)
                        || type == NETWORK_DUAL)
                    {
                        msg->network_type = type;
                        break;
                    }
                }
                if (msg->network_type != NETWORK_INVALID)
                {
                    break;
                }
            }
            sendto(channel,
                   (char*)msg,
                   sizeof(struct upa_hdr),
                   0,
                   sockAddr,
                   sockAddrLen);
            break;
        }
//#endif
        case UPA_MSG_SET_UPA_NODE:
        {
            GUI_SetExternalNode(msg->upa_node,
                                3,
                                iface->partition->getGlobalTime());
            break;
        }
        case UPA_MSG_RESET_UPA_NODE:
        {
            GUI_ResetExternalNode(msg->upa_node,
                                  3,
                                  iface->partition->getGlobalTime());
            break;
        }
        default:
        {
            printf("Unknown message type: %d\n", msg->msg_type);
        }
    }
    return 0;
}

// API        :: UPA_HandleIngressMessage
// PURPOSE    :: Handles UPA Message.
// PARAMETERS ::
// + iface    : EXTERNAL_Interface  : external interface data
// + fromAddr : fromAddr*           : address of the sender
// + data     : char*               : message to be handled
// + length   : int                 : length of the message
// RETURN     :: void : NULL
void UPA_HandleIngressMessage(
    EXTERNAL_Interface* iface,
    struct sockaddr* fromAddr,
    char* data,
    int length)
{
    struct upa_hdr* uhdr;
    uhdr = (struct upa_hdr*)&data[0];

    UInt32 addressLength = GetSockaddrLength(fromAddr);
    // We do this before we attempt to find node*
    if (uhdr->msg_type < UPA_MSG_NEW_SOCKET)
    {
        UPA_HandleConnectionManager(iface, uhdr, fromAddr);
        return;
    }


    IdToNodePtrMap* nodeHash = iface->partition->nodeIdHash;

#if 0
    // Convert the upa header from network byte order to host order
    uhdr->msg_type     = ntohs(uhdr->msg_type);
    uhdr->port         = ntohs(uhdr->port);
    uhdr->upa_node    = ntohl(uhdr->upa_node);
    uhdr->address    = ntohl(uhdr->address);
    uhdr->qualnet_fd= ntohl(uhdr->qualnet_fd);
#endif

    Node* node = MAPPING_GetNodePtrFromHash(nodeHash, uhdr->upa_node);
    if (node == NULL)
    {
        Node* node =
            MAPPING_GetNodePtrFromHash(iface->partition->remoteNodeIdHash,
                    uhdr->upa_node);
        if (node == NULL)
        {
            printf("No node found for nodeId=%d msg=%d\n",
                   uhdr->upa_node,
                   uhdr->msg_type);
            assert(0); // TODO
        }
        Message* msg;
        msg = MESSAGE_Alloc(node,
                EXTERNAL_LAYER,
                EXTERNAL_UPA,
                EXTERNAL_MESSAGE_UPA_HandleIngressMessage);

        MESSAGE_PacketAlloc(node, msg, length, TRACE_SOCKETLAYER);
        memcpy(MESSAGE_ReturnPacket(msg), data, length);

        MESSAGE_AddHeader(node,
                          msg,
                          addressLength,
                          TRACE_SOCKETLAYER);
        memcpy(MESSAGE_ReturnPacket(msg),
               (char*)fromAddr,
               addressLength);

        EXTERNAL_MESSAGE_SendAnyNode(iface,
                                     node,
                                     msg,
                                     0,
                                     EXTERNAL_SCHEDULE_SAFE);
        return;
    }

    switch (uhdr->msg_type)
    {
        case UPA_MSG_NEW_SOCKET:
        {
            UPA_CreateNewSocket(iface, node, data, fromAddr, addressLength);
            break;
        }
        case UPA_MSG_REGISTER:
        {
            assert(FALSE);

#ifdef DEBUG
            Address debugAddr;
            SockaddrToAddress(fromAddr, &debugAddr);
            char strAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(&debugAddr, strAddr);
            int port = GetPortFromSockaddr(fromAddr);
            printf("[UPA %d] Register a new socket: <%s:%d> fd=%d\n",
                node->nodeId,
                strAddr,
                htons(port),
                uhdr->qualnet_fd);
#endif

            SL_ioctl(node,
                     uhdr->qualnet_fd,
                     CtrlMsg_UPA_SetPhysicalAddress,
                     fromAddr,
                     &addressLength);

            UPA_InsertHash(iface,
                           node->nodeId,
                           uhdr->qualnet_fd,
                           fromAddr);

            break;
        }
        case UPA_MSG_DATA_UNCONNECTED:
        {
            sockaddr_in destAddr;

#ifdef DEBUG0
            printf("[UPA %d] Asked to send packet to <%x:%d> fd=%d"
                   " (%d bytes)\n",
                   node->nodeId,
                   (uhdr->address),
                   htons(uhdr->port),
                   uhdr->qualnet_fd,
                   length - UPA_HDR_SIZE);
#endif

            destAddr.sin_addr.s_addr = htonl(uhdr->address);
            destAddr.sin_port = htons(uhdr->port);

            SL_sendto(node,
                    uhdr->qualnet_fd,
                    &data[UPA_HDR_SIZE],
                    length - UPA_HDR_SIZE,
                    (struct sockaddr*)&destAddr);

            break;
        }
        case UPA_MSG_DATA_CONNECTED:
        {
            assert(FALSE);
#ifdef DEBUG0
            printf("[UPA %d] Asked to send connected packet fd=%d"
                   " (%d bytes)\n",
                   node->nodeId,
                   uhdr->qualnet_fd,
                   length - UPA_HDR_SIZE);
#endif

            SL_send(node,
                    uhdr->qualnet_fd,
                    &data[UPA_HDR_SIZE],
                    length - UPA_HDR_SIZE);

            break;
        }
        case UPA_MSG_BIND:
        {
            sockaddr* addr;
            int addrlen;

            addr = (sockaddr*)&data[sizeof(upa_hdr)];

            SetPortFromSockaddr(addr, htons(uhdr->port));
#ifdef DEBUG
            Address debugAddr;
            char strAddr[MAX_STRING_LENGTH];
            SockaddrToAddress(addr, &debugAddr);
            IO_ConvertIpAddressToString(&debugAddr, strAddr);
            printf("[UPA %d] Bind to %s:%d\n",
                   node->nodeId,
                   strAddr,
                   ntohs(uhdr->port));
#endif
            SL_bind(node,
                    uhdr->qualnet_fd,
                    addr,
                    uhdr->address);

            SL_getsockname(node,
                           uhdr->qualnet_fd,
                           addr,
                           &addrlen);

            uhdr->port = htons(GetPortFromSockaddr(addr));

            UPA_SendPacket(node,
                uhdr->qualnet_fd,
                data,
                UPA_HDR_SIZE,
                TRUE);
            break;

        }
        case UPA_MSG_LISTEN:
        {
            SL_listen(node, uhdr->qualnet_fd, 0);
            break;
        }
        case UPA_MSG_CONNECT:
        {
            sockaddr* connect_addr = (sockaddr*)&data[sizeof(upa_hdr)];
            SetPortFromSockaddr(connect_addr, htons(uhdr->port));
#ifdef DEBUG
            Address debugAddr;
            Address connectAddr;
            char strAddr[MAX_STRING_LENGTH];
            char strConnectAddr[MAX_STRING_LENGTH];
            SockaddrToAddress(fromAddr, &debugAddr);
            SockaddrToAddress(connect_addr, &connectAddr);
            IO_ConvertIpAddressToString(&debugAddr, strAddr);
            IO_ConvertIpAddressToString(&connectAddr, strConnectAddr);
            printf("[UPA %d] Received connect message from <%s:%d> to=%s:%d"
                   " at %" TYPES_64BITFMT "d\n",
                   node->nodeId,
                   strAddr,
                   htons(GetPortFromSockaddr(fromAddr)),
                   strConnectAddr,
                   htons(uhdr->port),
                   iface->partition->getGlobalTime());
#endif

            SL_connect(node,
                       uhdr->qualnet_fd,
                       connect_addr,
                       uhdr->address);

            break;
        }
        case UPA_MSG_ACCEPT:
        {
            int length;
            char* recvData;

            SL_ioctl(node,
                uhdr->qualnet_fd,
                CtrlMsg_UPA_SetPhysicalAddress,
                fromAddr,
                &addressLength);

            UPA_InsertHash(iface,
                    node->nodeId,
                    uhdr->qualnet_fd,
                    fromAddr);

            UInt32 qualnet_fd = uhdr->qualnet_fd;
            while ((length =
                    SL_recv(node, qualnet_fd, (void**)&recvData, 0, 0))
                                                                        >= 0)
            {
                // This part of code has been commented because this technique
                // does not work with overlapped operations,
                // insted if a packet no data is sent,
                // it triggers close socket operation.

                //if (recvData == NULL)
                //{
                //    UpaPrepareSocketCloseMessage(uhdr);
                //    UPA_SendPacket(node,
                //                   qualnet_fd,
                //                   data,
                //                   UPA_HDR_SIZE,
                //                   TRUE);
                //}
                //else
                {
                    UPA_SendPacket(node,
                                   uhdr->qualnet_fd,
                                   recvData,
                                   length,
                                   FALSE);
                }
            }

            break;
        }
        case UPA_MSG_CLOSE:
        {
#ifdef DEBUG
            Address debugAddr;
            char strAddr[MAX_STRING_LENGTH];
            SockaddrToAddress(fromAddr, &debugAddr);
            IO_ConvertIpAddressToString(&debugAddr, strAddr);
            printf("[UPA %d] Received close message from <%s:%d> for fd:%d"
                   " at %" TYPES_64BITFMT "d\n",
                   node->nodeId,
                   strAddr,
                   htons(GetPortFromSockaddr(fromAddr)),
                   uhdr->qualnet_fd,
                   iface->partition->getGlobalTime());
#endif
            SL_close(node, uhdr->qualnet_fd);
            break;
        }
        case UPA_MSG_SHUTDOWN:
        {
#ifdef DEBUG
            Address debugAddr;
            char strAddr[MAX_STRING_LENGTH];
            SockaddrToAddress(fromAddr, &debugAddr);
            IO_ConvertIpAddressToString(&debugAddr, strAddr);
            printf("[UPA %d] Received shutdown message from <%s:%d> for fd:%d"
                   " at %" TYPES_64BITFMT "d\n",
                   node->nodeId,
                   strAddr,
                   htons(GetPortFromSockaddr(fromAddr)),
                   uhdr->qualnet_fd,
                   iface->partition->getGlobalTime());
#endif
            SL_shutdown(node, uhdr->qualnet_fd);
            break;
        }
        case UPA_MSG_FORK:
        {
            int i, numFds;

            numFds = uhdr->address;
            for (i=0; i<numFds; i++)
            {
                SL_fork(node, data[UPA_HDR_SIZE + i]);

            }

            break;
        }
        case UPA_MSG_DUP:
        {
            SL_fork(node, uhdr->qualnet_fd);
            break;
        }
        case UPA_MSG_GET_IF_INFO:
        {
            int qualnet_fd = uhdr->qualnet_fd;

            // YES, we are using 'address' field to return how many interfaces this node has.
            // +1 for the loopback interface
            uhdr->address = node->numberInterfaces + 1;

            UInt32 interfaceListLength = 0;
            SL_ioctl(node,
                     qualnet_fd,
                     CtrlMsg_MAC_GetInterfaceList,
                     data + UPA_HDR_SIZE,
                     &interfaceListLength);

            UPA_SendPacket(node,
                           qualnet_fd,
                           data,
                           interfaceListLength + UPA_HDR_SIZE,
                           TRUE);

            break;
        }
        case UPA_MSG_GET_PROC_NET:
        {
            int qualnet_fd = uhdr->qualnet_fd;
            int proc_net_name = uhdr->address;

            UPA_HandleProcNet(node, qualnet_fd, proc_net_name);
            break;
        }
        case UPA_MSG_UPDATE_RT:
        {
            SLRouteInfo* slRoute = (SLRouteInfo* )&data[UPA_HDR_SIZE];
            int interfaceIndex;

            if (slRoute->ifname[0] == '\0')
            {
                interfaceIndex = ANY_INTERFACE;
            }
            else
            {
                sscanf(slRoute->ifname, "qln%d", &interfaceIndex);
                // TODO validate interfaceIndex
            }

            NetworkUpdateForwardingTable(node,
                    htonl(slRoute->dest.sin_addr.s_addr),
                    htonl(slRoute->netmask.sin_addr.s_addr),
                    htonl(slRoute->gateway.sin_addr.s_addr),
                    interfaceIndex,
                    slRoute->metric,
                    ROUTING_PROTOCOL_DEFAULT);

            break;
        }
        default:
            printf("Invalid message type: %d\n", uhdr->msg_type);
            assert(0);
    }
}

void UPA_InitializeNodes(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{

}

// API        :: UPA_HandleIngressMessage
// PURPOSE    :: Handles UPA Message.
// PARAMETERS ::
// + iface    : EXTERNAL_Interface  : external interface data
// + s        : SOCKET              : Socket file descriptor
// + fromAddr : fromAddr*           : address of the sender
// + fromlen  : int/socklen_t*      : length of from address structure
// + type     : channelType         : Channel type DATA or MESSAGE
// RETURN     :: void : NULL
void 
ReadAndHandleChannel(EXTERNAL_Interface* iface,
                     SOCKET s,
                     sockaddr* from,
#ifdef _WIN32
                     int* fromlen,
#else
                     socklen_t* fromlen,
#endif
                     channelType type)
{
    int read;
    char buf[UPA_RECV_BUF_SIZE];
    if (s == 0)
    {
        return;
    }

    read = recvfrom(s, buf, UPA_RECV_BUF_SIZE, 0, from, fromlen);

    if (read > 0)
    {
        switch (type)
        {
            case DATA:
            {
                UPA_HandleIngressData(iface,
                                      from,
                                      buf,
                                      read);
                break;
            }
            case MESSAGE:
            {
                UPA_HandleIngressMessage(iface,
                                         from,
                                         buf,
                                         read);
                break;
            }
        }
    }
}

// API       :: UPA_Receive
// PURPOSE   :: This function is used to receive and handle UPA messages
// PARAMETERS::
// + iface    : EXTERNAL_Interface  : external interface data
// RETURN    :: void       : NULL
void UPA_Receive(EXTERNAL_Interface* iface)
{
    UPAData* upaData = (UPAData*)(iface->data);
    struct sockaddr_in fromAddr;
    struct sockaddr_in6 fromAddr6;

#ifdef _WIN32
    int length = sizeof(struct sockaddr);
    int length6 = sizeof(struct sockaddr_in6);
#else
    socklen_t length = sizeof(struct sockaddr);
    socklen_t length6 = sizeof(struct sockaddr_in6);
#endif

    if (iface->partition->partitionId
        != iface->partition->masterPartitionForCluster)
        return;

    ReadAndHandleChannel(iface,
                         upaData->dataChannel,
                         (struct sockaddr*)&fromAddr,
                         &length,
                         DATA);

    ReadAndHandleChannel(iface,
                         upaData->dataChannelIPv6,
                         (struct sockaddr*)&fromAddr6,
                         &length6,
                         DATA);

    ReadAndHandleChannel(iface,
                         upaData->controlChannel,
                         (struct sockaddr*)&fromAddr,
                         &length,
                         MESSAGE);

    ReadAndHandleChannel(iface,
                         upaData->ipv6MulticastChannel,
                         (struct sockaddr*)&fromAddr6,
                         &length6,
                         MESSAGE);

    ReadAndHandleChannel(iface,
                         upaData->controlChannelIPv6,
                         (struct sockaddr*)&fromAddr6,
                         &length6,
                         MESSAGE);

    if ((upaData->activeConnectionManagers > 0) &&
        (upaData->nextCMBeaconAt <= iface->timeFunction(iface)))
    {
        upaData->nextCMBeaconAt += 3*SECOND;
        for (int i = 0; i < upaData->activeConnectionManagers; i++)
        {
            if (upaData->firstMessage[i])
            {
                upaData->firstMessage[i] = false;

                if (g_payloadSize == 0)
                {
                    g_payloadSize = 4096;
                    g_payload = (char*)malloc(g_payloadSize);

                    char* strData;
                    struct upa_hdr* header;
                    int size;
                    Node* node;
                    //in_addr address;
                    Address address;
                    NetworkType type;

                    header = (struct upa_hdr*)&g_payload[0];
                    header->msg_type = UPA_MSG_CONNECTION_MANAGER;
                    header->upa_node = iface->partition->numNodes;

                    size = sizeof(struct upa_hdr);

                    strData = &g_payload[size];
                    size = 0;

                    NodePointerCollection* allNodes =
                        iface->partition->allNodes;
                    NodePointerCollectionIter iter;

                    for (iter = allNodes->begin(); iter != allNodes->end(); iter++)
                    {
                        node = *iter;
                        if (!iface->partition->
                                    partitionOnSameCluster[node->partitionId])
                        {
                            continue;
                        }
                        sprintf(&strData[size], "%d;%s",
                                node->nodeId,
                                node->hostname);
                        size=strlen(strData);

                        char* temp = g_payload;
                        NetworkType tempType = NETWORK_INVALID;
                        for (int i=0; i < node->numberInterfaces; i++)
                        {
                            type =
                                MAPPING_GetNetworkTypeFromInterface(node, i);
                            if (type == NETWORK_DUAL)
                            {
                                if (tempType == NETWORK_INVALID)
                                {
                                    tempType = NETWORK_IPV4;
                                }
                                else
                                {
                                    tempType = NETWORK_IPV6;
                                }
                            }
                            else
                            {
                                tempType = type;
                            }
                            if (tempType != NETWORK_INVALID)
                            {
                                address
                                    = MAPPING_GetInterfaceAddressForInterface(
                                        node,
                                        node->nodeId,
                                        tempType,
                                        i);

                                char addrString[MAX_STRING_LENGTH];
                                if (tempType == NETWORK_IPV4)
                                {
                                    int add = htonl(address.interfaceAddr.ipv4);
#ifdef _WIN32
                                    sockaddr_in addr_ipv4;
                                    memset(&addr_ipv4, 0, sizeof(sockaddr_in));
                                    DWORD srtLength = MAX_STRING_LENGTH;
                                    addr_ipv4.sin_family = AF_INET;
                                    memcpy(&addr_ipv4.sin_addr, &add, sizeof(IN_ADDR));
                                    WSAAddressToString((SOCKADDR*)&addr_ipv4,
                                                       sizeof(sockaddr_in),
                                                       NULL,
                                                       addrString,
                                                       &srtLength);
#else
                                    inet_ntop(AF_INET,
                                              &add,
                                              addrString,
                                              MAX_STRING_LENGTH);
#endif
                                }
                                else if (tempType == NETWORK_IPV6)
                                {
#ifdef _WIN32
                                    sockaddr_in6 addr_ipv6;
                                    memset(&addr_ipv6, 0, sizeof(sockaddr_in6));
                                    DWORD srtLength = MAX_STRING_LENGTH;
                                    addr_ipv6.sin6_family = WIN_AF_INET6;
                                    memcpy(&addr_ipv6.sin6_addr,
                                        &(address.interfaceAddr.ipv6),
                                        sizeof(IN6_ADDR));
                                    WSAAddressToString((SOCKADDR*)&addr_ipv6,
                                                       sizeof(sockaddr_in6),
                                                       NULL,
                                                       addrString,
                                                       &srtLength);
#else
                                    inet_ntop(AF_INET6,
                                              &address.interfaceAddr.ipv6,
                                              addrString,
                                              MAX_STRING_LENGTH);
#endif
                                }

                                sprintf(&strData[size],
                                        ";%d;%s",
                                        i,
                                        addrString);
                                size = strlen(strData);
                            }
                            if (type == NETWORK_DUAL
                                && tempType != NETWORK_IPV6)
                            {
                                i--;
                            }
                            else
                            {
                                tempType = NETWORK_INVALID;
                            }
                        }
                        sprintf(&strData[size], "\n");
                        size = strlen(strData);

                        if (size > (g_payloadSize - 100))
                        {
                            g_payload =
                                (char*)realloc(g_payload, g_payloadSize + 1024);
                            if (temp!=g_payload)
                            {
                                strData=&g_payload[sizeof(struct upa_hdr)];
                            }

                            g_payloadSize += 1024;
                            if (g_payload == NULL)
                                ERROR_ReportError("Cannot allocate memory!");
                        }
                    }
                    g_payloadSize = size + sizeof(struct upa_hdr);
                }
                printf("Sending %d bytes \n", g_payloadSize);
                fflush(stdout);

                sockaddr* addr =
                    (struct sockaddr*)&upaData->ConnectionManagers[i].address;

                sendto(upaData->activeControlChannel[i],
                        g_payload,
                        g_payloadSize,
                        0,
                        addr,
                        GetSockaddrLength(addr));
            }
            else
            {
                struct upa_hdr packet;
                packet.msg_type = UPA_MSG_CONNECTION_MANAGER_BEACON;
                sockaddr* sockAddr;
                int sockAddrLength;

                AutoIPNE_NodeMapping* mapping;
                int err, valueSize;
                Address physicalAddress;
                Address virtualAddress;
                sockaddr* temp =
                    (sockaddr*)&(upaData->ConnectionManagers[i].address);
                if (temp->sa_family == AF_INET)
                {
                    physicalAddress.networkType = NETWORK_IPV4;
                    memcpy(&physicalAddress.interfaceAddr.ipv4,
                        &(upaData->ConnectionManagers[i].address.ipv4.sin_addr),
                        sizeof(NodeAddress));
                }
                else if (temp->sa_family == AF_INET6)
                {
                    physicalAddress.networkType = NETWORK_IPV6;
                    memcpy(&physicalAddress.interfaceAddr.ipv6,
                        &(upaData->ConnectionManagers[i].address.ipv6.sin6_addr),
                        sizeof(in6_addr));
                }
                EXTERNAL_Interface* ipne;
                ipne = EXTERNAL_GetInterfaceByName(
                        &iface->partition->interfaceList,
                        "IPNE");
                ERROR_Assert(ipne != NULL, "IPNE not loaded");

                NodeAddress ipv4PhysicalAddress;
                in6_addr ipv6PhysicalAddress;
                packet.upa_node = 0;
                char* message;
                int messageLength = 0;
                if (physicalAddress.networkType == NETWORK_IPV4)
                {
                    ipv4PhysicalAddress = physicalAddress.interfaceAddr.ipv4;
                    err = EXTERNAL_ResolveMapping(
                            ipne,
                            (char*)&ipv4PhysicalAddress,
                            sizeof(NodeAddress),
                            (char**) &mapping,
                            &valueSize);
                    if (!err && mapping)
                    {
                        messageLength = UPA_HDR_SIZE + sizeof(sockaddr_in);
                        message = (char*)MEM_malloc(messageLength);
                        virtualAddress = mapping->virtualAddress;
                        sockaddr_in address;
                        address.sin_family = AF_INET;
                        address.sin_addr.s_addr =
                            virtualAddress.interfaceAddr.ipv4;
                        packet.qualnet_fd = sizeof(sockaddr_in);
                        memcpy(message, &packet, UPA_HDR_SIZE);
                        memcpy(message +  UPA_HDR_SIZE,
                               &address,
                               sizeof(sockaddr_in));
                    }
                }
                else if (physicalAddress.networkType == NETWORK_IPV6)
                {
                    ipv6PhysicalAddress = physicalAddress.interfaceAddr.ipv6;
                    err = EXTERNAL_ResolveMapping(
                            ipne,
                            (char*)&ipv6PhysicalAddress,
                            sizeof(in6_addr),
                            (char**) &mapping,
                            &valueSize);
                    if (!err && mapping)
                    {
                        messageLength = UPA_HDR_SIZE + sizeof(sockaddr_in6);
                        message = (char*)MEM_malloc(messageLength);
                        virtualAddress = mapping->virtualAddress;
                        in6_addr tempAddress =
                            virtualAddress.interfaceAddr.ipv6;
                        sockaddr_in6 address;
                        address.sin6_family = WIN_AF_INET6;
                        memcpy(&address.sin6_addr,
                            &tempAddress,
                            sizeof(in6_addr));
                        packet.qualnet_fd = sizeof(sockaddr_in6);
                        memcpy(message, &packet, UPA_HDR_SIZE);
                        memcpy(message +  UPA_HDR_SIZE,
                               &address,
                               sizeof(sockaddr_in6));
                    }
                }

                if (err)
                {
                    packet.qualnet_fd = 0;
                    messageLength = UPA_HDR_SIZE;
                    message = (char*)MEM_malloc(messageLength);
                    memcpy(message, &packet, UPA_HDR_SIZE);
                }

                if (upaData->ConnectionManagers[i].sin_family == AF_INET)
                {
                    sockAddr =
                        (sockaddr*)&upaData->ConnectionManagers[i].address.ipv4;
                    sockAddrLength = sizeof(struct sockaddr_in);
                }
                else if (upaData->ConnectionManagers[i].sin_family == AF_INET6)
                {
                    sockAddr =
                        (sockaddr*)&upaData->ConnectionManagers[i].address.ipv6;
                    sockAddrLength = sizeof(struct sockaddr_in6);
                }
                sendto(upaData->activeControlChannel[i],
                        message,
                        messageLength,
                        0,
                        sockAddr,
                        sockAddrLength);
                MEM_free(message);
            }
        }

    }
}

void UPA_Forward(
    EXTERNAL_Interface* iface,
    Node* node,
    void* forwardData,
    int forwardSize)
{

}

void UPA_Finalize(EXTERNAL_Interface* iface)
{

}

#ifdef _WIN32
void GetIPv6ScopeIds(DWORD* scopeId, int* maxLength)
{
    IP_ADAPTER_ADDRESSES* adaptersInfo = NULL;
    IP_ADAPTER_ADDRESSES* adapter = NULL;
    ULONG outBufLen = WORKING_BUFFER_SIZE;
    DWORD dwRetVal = 0;
    ULONG Iterations = 0;

    ULONG family = AF_INET6;

    // Set the flags to pass to GetAdaptersAddresses
    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

    // get adapter settings, using default buffer size as WORKING_BUFFER_SIZE,
    // in case of over flow, re allocate memory to the required buffer size
    // returend by the function GetAdaptersAddresses().
    do {
        adaptersInfo = (IP_ADAPTER_ADDRESSES*) MEM_malloc(outBufLen);
        if (adaptersInfo == NULL) {
            exit(1);
        }
        dwRetVal =
            GetAdaptersAddresses(family,
                                 flags,
                                 NULL,
                                 adaptersInfo,
                                 &outBufLen);
        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            MEM_free(adaptersInfo);
            adaptersInfo = NULL;
        } else {
            break;
        }
        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW)
             && (Iterations < MAX_TRIES));

    int i = 0;
    if (adaptersInfo != NULL)
    {
        for (adapter = adaptersInfo; adapter; adapter = adapter->Next)
        {
            if (adapter->Ipv6IfIndex != 0)
            {
                if (scopeId != NULL)
                {
                    scopeId[i] = adapter->Ipv6IfIndex;
                }
                i++;
            }
        }
    }
    MEM_free(adaptersInfo);
    *maxLength = i;
}
#endif

// API       :: UPA_Initialize
// PURPOSE   :: This function initialize UPA sockets to receive and send data
// PARAMETERS::
// + iface      : EXTERNAL_Interface    : external interface data
// + nodeInput  : const NodeInput*      : Pointer to NodeInput
// RETURN    :: void       : NULL
void UPA_Initialize(
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput)
{
    int controlChannel = 0;
    int dataChannel = 0;
    int multicastChannel = 0;
    int controlChannelIPv6 = 0;
    int dataChannelIPv6 = 0;
    struct ipv6_mreq multicastRequest6;  /* Multicast address join structure */

    struct sockaddr_in readerAddr;
    struct sockaddr_in6 readerAddr6;

    UPAData* upaData;
    int retVal;
#ifdef _WIN32
    ADDRINFO*  multicastAddr  = NULL;   /* Multicast Address */
    ADDRINFO*  localAddr      = NULL;   /* Local address to bind to */
    ADDRINFO   hints          = { 0 };  /* Hints for name lookup */
#else
    struct addrinfo*    multicastAddr = NULL; /* Multicast Address */
    struct addrinfo*    localAddr     = NULL; /* Local address to bind to */
    struct addrinfo    hints          = { 0 };/* Hints for name lookup */
#endif

    char multicastIP[] = "FF02::1";   /* First arg:  Multicast IP address */
    char multicastPort[] = "3134";    /* Second arg: Multicast port */
    bool ipv6Enabled = true;

    if (iface->partition->partitionId
        != iface->partition->masterPartitionForCluster)
    {
        return;
    }

#ifdef _WIN32
    WSADATA data;
    if (WSAStartup(MAKEWORD(2,2), &data) < 0)
    {
        ERROR_ReportError("Cannot start the windows networking service\n");
    }
#endif
    /* Set up the reader and writer sockets */
    controlChannel = socket(AF_INET, SOCK_DGRAM, 0);
    dataChannel = socket(AF_INET, SOCK_DGRAM, 0);
    controlChannelIPv6 = socket(AF_INET6, SOCK_DGRAM, 0);
    dataChannelIPv6 = socket(AF_INET6, SOCK_DGRAM, 0);

    /* Resolve the multicast group address */
    hints.ai_family = PF_UNSPEC;
    hints.ai_flags  = AI_NUMERICHOST;
    if (getaddrinfo(multicastIP, NULL, &hints, &multicastAddr) != 0)
    {
        ERROR_ReportError("getaddrinfo() failed");
    }

    /* Get a local address with the same family (IPv4 or IPv6)
     * as our multicast group
     */
    hints.ai_family   = multicastAddr->ai_family;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags    = AI_PASSIVE;
    /* Return an address we can bind to */
    if (getaddrinfo(NULL, multicastPort, &hints, &localAddr) != 0)
    {
        ERROR_ReportError("getaddrinfo() failed");
    }

    /* Create socket for receiving datagrams */
    multicastChannel = socket(localAddr->ai_family, localAddr->ai_socktype, 0);

#ifdef _WIN32
    if (controlChannel == INVALID_SOCKET
        || dataChannel == INVALID_SOCKET
        || multicastChannel == INVALID_SOCKET)
    {
        ERROR_ReportError("Cannot open sockets for UPA layer");
    }
#else
    if (!controlChannel || !dataChannel)
        ERROR_ReportError("Cannot open sockets for UPA Layer");
#endif

    readerAddr.sin_family = AF_INET;
    readerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    readerAddr.sin_port = htons(UPA_CONTROL_PORT);

    // The ::bind disambiguates it for the MSVC10 compiler
    // due to confusion between the socket bind defined in
    // the global namespace (and used here) and bind template
    // defined in the std namespace.
    retVal = ::bind(controlChannel,
                    (struct sockaddr*)&readerAddr,
                    sizeof(readerAddr));
#ifdef _WIN32
    if (retVal != 0)
#else
    if (retVal < 0)
#endif
    {
        printf("Error: %s\n", strerror(errno));
        ERROR_ReportError("It appears that another instance of EXata is"
            " currently running. Close the other instance of EXata first,"
            " before launching this one.");
    }

    readerAddr.sin_family = AF_INET;
    readerAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    readerAddr.sin_port = htons(UPA_DATA_PORT);

    // The ::bind disambiguates it for the MSVC10 compiler
    // due to confusion between the socket bind defined in
    // the global namespace (and used here) and bind template
    // defined in the std namespace.
    retVal = ::bind(dataChannel,
                    (struct sockaddr*)&readerAddr,
                    sizeof(readerAddr));
#ifdef _WIN32
    if (retVal != 0)
#else
    if (retVal < 0)
#endif
    {
        printf("Error: %s\n", strerror(errno));
        ERROR_ReportError("It appears that another instance of EXata"
            " is currently running. Close the other instance of EXata first,"
            " before launching this one.");
    }

    memset(&readerAddr6, 0, sizeof(readerAddr6));
    readerAddr6.sin6_family = AF_INET6;
    readerAddr6.sin6_port = htons(UPA_CONTROL_PORT_IPV6);

    retVal = ::bind(controlChannelIPv6,
                    (struct sockaddr*)&readerAddr6,
                    sizeof(readerAddr6));
#ifdef _WIN32
    if (retVal != 0)
#else
    if (retVal < 0)
#endif
    {
        printf("Error: %s\n", strerror(errno));
        if (errno == EINVAL)
        {
            ERROR_ReportError("It appears that another instance of EXata"
                " is currently running. Close the other instance of EXata first,"
                " before launching this one.");
        }
        else
        {
            ipv6Enabled = false;
            ERROR_ReportWarning("It appears that IPv6 is disabled on the system.");
        }
    }

    memset(&readerAddr6, 0, sizeof(readerAddr6));
    readerAddr6.sin6_family = AF_INET6;
    readerAddr6.sin6_port = htons(UPA_DATA_PORT_IPV6);

    if (ipv6Enabled == true)
    {
        retVal = ::bind(dataChannelIPv6,
                        (struct sockaddr*)&readerAddr6,
                        sizeof(readerAddr6));
#ifdef _WIN32
        if (retVal != 0)
#else
        if (retVal < 0)
#endif
        {
            printf("Error: %s\n", strerror(errno));
            ERROR_ReportError("It appears that another instance of EXata"
                " is currently running. Close the other instance of EXata first,"
                " before launching this one.");
        }

        /* Bind to the multicast port */
        if (bind(multicastChannel, localAddr->ai_addr, localAddr->ai_addrlen)
                                                            != 0 )
        {
            ERROR_ReportError("bind() failed");
        }

        /* Join the multicast group. We do this seperately depending on whether we
         * are using IPv4 or IPv6. WSAJoinLeaf is supposed to be IP version agnostic
         * but it looks more complex than just duplicating the required code. */

        /* Specify the multicast group */
        memcpy(&multicastRequest6.ipv6mr_multiaddr,
               &((struct sockaddr_in6*)(multicastAddr->ai_addr))->sin6_addr,
               sizeof(multicastRequest6.ipv6mr_multiaddr));

#ifdef _WIN32
        DWORD scopeIds[MAX_INTERFACE];
        int numScopeIds = 0;
        // get number of valid scopeIds
        GetIPv6ScopeIds(scopeIds, &numScopeIds);

        for (int i = 0; i < numScopeIds; i++)
        {
            multicastRequest6.ipv6mr_interface = scopeIds[i];

            /* Join the multicast address */
            if (setsockopt(multicastChannel,
                           IPPROTO_IPV6,
                           IPV6_ADD_MEMBERSHIP,
                           (char*) &multicastRequest6,
                           sizeof(multicastRequest6)) != 0)
            {
                char error[MAX_STRING_LENGTH];
                sprintf(error, "IPV6_ADD_MEMBERSHIP failed for interface index:%d",
                        multicastRequest6.ipv6mr_interface);
                ERROR_ReportWarning(error);
            }
        }
#else
        multicastRequest6.ipv6mr_interface = 0;
        /* Join the multicast address */
        if (setsockopt(multicastChannel,
                       IPPROTO_IPV6,
                       IPV6_ADD_MEMBERSHIP,
                       (char*) &multicastRequest6,
                       sizeof(multicastRequest6)) != 0)
        {
            ERROR_ReportError("setsockopt() failed");
        }
#endif
    }
    else
    {
        controlChannelIPv6 = 0;
        dataChannelIPv6 = 0;
        multicastChannel = 0;
    }

    freeaddrinfo(localAddr);
    freeaddrinfo(multicastAddr);

#ifdef _WIN32
    u_long arg = 1;

    if (ioctlsocket(controlChannel, FIONBIO, &arg))
    {
        ERROR_ReportError("Cannot set the reader socket as non-blocking");
    }
    if (ioctlsocket(dataChannel, FIONBIO, &arg))
    {
        ERROR_ReportError("Cannot set the reader socket as non-blocking");
    }
    if (ipv6Enabled == TRUE)
    {
        if (ioctlsocket(multicastChannel, FIONBIO, &arg))
        {
            ERROR_ReportError("Cannot set the reader socket as non-blocking");
        }
        if (ioctlsocket(controlChannelIPv6, FIONBIO, &arg))
        {
            ERROR_ReportError("Cannot set the reader socket as non-blocking");
        }
        if (ioctlsocket(dataChannelIPv6, FIONBIO, &arg))
        {
            ERROR_ReportError("Cannot set the reader socket as non-blocking");
        }
    }
#else
    if (fcntl(controlChannel, F_SETFL, O_NONBLOCK) < 0)
    {
        ERROR_ReportError("Cannot set the reader socket as non-blocking");
    }
    if (fcntl(dataChannel, F_SETFL, O_NONBLOCK) < 0)
    {
        ERROR_ReportError("Cannot set the writer socket as non-blocking");
    }
    if (ipv6Enabled == TRUE)
    {
        if (fcntl(multicastChannel, F_SETFL, O_NONBLOCK) < 0)
        {
            ERROR_ReportError("Cannot set the writer socket as non-blocking");
        }
        if (fcntl(controlChannelIPv6, F_SETFL, O_NONBLOCK) < 0)
        {
            ERROR_ReportError("Cannot set the writer socket as non-blocking");
        }
        if (fcntl(dataChannelIPv6, F_SETFL, O_NONBLOCK) < 0)
        {
            ERROR_ReportError("Cannot set the writer socket as non-blocking");
        }
    }
#endif

    upaData = (UPAData*)MEM_malloc(sizeof(UPAData));
    upaData->controlChannel = controlChannel;
    upaData->controlChannelIPv6 = controlChannelIPv6;
    upaData->dataChannel = dataChannel;
    upaData->dataChannelIPv6 = dataChannelIPv6;
    upaData->ipv6MulticastChannel = multicastChannel;
    upaData->multicastRequest = multicastRequest6;
    upaData->hashTable = NULL;
    upaData->activeConnectionManagers = 0;

    iface->data = upaData;

#if 0
#ifndef _WIN32
    EXTERNAL_AddFileDescForListening(iface, controlChannel);
#endif
#endif

    // Prepare the nodeinfo list that is sent to the CM
    g_payloadSize = 0;
    g_payload = NULL;
}

#if 0
void UPA_ProcessEvent(
    Node* node,
    void* arg)
{
    int controlChannel = (int)arg;
    struct sockaddr_in upaClientAddr;
    int addrLen;
    int n, dataAvailable;
    fd_set set;
    struct timeval timeout;
    assert(0);

    timeout.tv_usec = timeout.tv_sec = 0;

    FD_SET(controlChannel, &set);

    dataAvailable = select(controlChannel + 1, &set, NULL, NULL, &timeout);

    if (dataAvailable > 0)
    {
        //UPA_HandleIngressPacket(node, controlChannel);
    }
    else if (dataAvailable < 0)
    {
        ERROR_ReportError("Error with select in UPA");
    }
}
#endif

void UPA_HandleEgressPacket(
    Node* node,
    int qualnet_fd,
    char* data,
    int dataSize,
    struct sockaddr* fromAddr)
{
    char upaGlobalData[1500];
    struct upa_hdr* uhdr = (struct upa_hdr*)&upaGlobalData[0];
    int length;

    // This part of code has been commented because this technique
    // does not work with overlapped operations, insted if a packet
    // with no data is sent, it triggers close socket operation.

    //if (data == NULL) /* Connection closed */
    //{
    //    UpaPrepareSocketCloseMessage(uhdr);
    //    UPA_SendPacket(node, qualnet_fd, upaGlobalData, UPA_HDR_SIZE, TRUE);
    //    return;
    //}

    if (fromAddr == NULL)
    {
        UPA_SendPacket(node, qualnet_fd, data, dataSize, FALSE);
        return;
    }

    uhdr->upa_node = node->nodeId;
    uhdr->qualnet_fd = qualnet_fd;
    uhdr->address = length = GetSockaddrLength(fromAddr);
    uhdr->port = htons(GetPortFromSockaddr(fromAddr));

    int msgLength = UPA_HDR_SIZE + length + dataSize;

    if (msgLength > UPA_RECV_BUF_SIZE)
    {
        printf("TOO MUCH DATA %d+%" TYPES_SIZEOFMFT "u+%d\n",
               dataSize,
               UPA_HDR_SIZE,
               length);
        return;
    }

    char* msg = (char*)MEM_malloc(msgLength);
    memcpy(msg, (char*)uhdr, UPA_HDR_SIZE);
    memcpy(msg + UPA_HDR_SIZE, fromAddr, length);

    if (dataSize > 0)
        memcpy(msg+ UPA_HDR_SIZE + length, data, dataSize);

    UPA_SendPacket(node,
                   qualnet_fd,
                   msg,
                   msgLength,
                   TRUE);
}


void UPA_TcpListen(
    Node* node,
    int qualnet_fd)
{
    struct upa_hdr uhdr;

    uhdr.msg_type = UPA_MSG_LISTEN;
    // Do not need rest of the fields

    UPA_SendPacket(node, qualnet_fd, (char*)&uhdr, UPA_HDR_SIZE, TRUE);
}

void UPA_TcpConnect(
    Node* node,
    int qualnet_fd,
    sockaddr* remoteAddr)
{
    struct upa_hdr uhdr;
    int length = 0;
    int msgLength = UPA_HDR_SIZE;

    memset(&uhdr, 0, sizeof(upa_hdr));
    uhdr.msg_type = UPA_MSG_CONNECT;
    if (remoteAddr != NULL)
    {
        uhdr.address = length = GetSockaddrLength(remoteAddr);
        uhdr.port = htons(GetPortFromSockaddr(remoteAddr));
        msgLength += length;
    }

    char* msg = (char*)MEM_malloc(msgLength);
    memcpy(msg, (char*)&uhdr, UPA_HDR_SIZE);
    memcpy(msg + UPA_HDR_SIZE, remoteAddr, length);

    UPA_SendPacket(node, qualnet_fd, msg, msgLength, TRUE);
}

void UPA_SendDone(
    Node* node,
    int qualnet_fd,
    int length)
{
#ifdef TCP_BLOCKING_SEND
    struct upa_hdr* uhdr = (struct upa_hdr*)&upaGlobalData[0];

    uhdr->address = length;

    UPA_SendPacket(node, qualnet_fd, upaGlobalData, UPA_HDR_SIZE, TRUE);
#endif
}

void UPA_TcpAccept(
    Node* node,
    int qualnet_fd)
{
    int new_qualnet_fd;
    struct upa_hdr uhdr;
    sockaddr* remoteAddr = NULL;
    int length;
    SL_accept(node,
              qualnet_fd,
              NULL,
              &length);
    remoteAddr = (sockaddr*)MEM_malloc(length);
    new_qualnet_fd = SL_accept(node,
                               qualnet_fd,
                               remoteAddr,
                               &length);

    assert(new_qualnet_fd >= 0);
    SL_ioctl(node, new_qualnet_fd, CtrlMsg_UPA_SetUpaSocket, 0);

    uhdr.msg_type   = UPA_MSG_ACCEPT;
    uhdr.qualnet_fd = new_qualnet_fd;
    uhdr.address    = length;
    uhdr.port       = htons(GetPortFromSockaddr(remoteAddr));

    int msgLength = UPA_HDR_SIZE + length;
    char* msg = (char*)MEM_malloc(msgLength);
    memcpy(msg, (char*)&uhdr, UPA_HDR_SIZE);
    memcpy(msg + UPA_HDR_SIZE, remoteAddr, length);

    UPA_SendPacket(node, qualnet_fd, msg, msgLength, TRUE);
}


void UPA_HandleExternalMessage(
    Node* node,
    Message* msg)
{
    EXTERNAL_Interface* iface;

    iface = node->partitionData->interfaceTable[EXTERNAL_UPA];
    if (!iface)
    {
        ERROR_ReportError("UPA Interface is not configured in EXata");
    }

    switch (msg->eventType)
    {
        case EXTERNAL_MESSAGE_UPA_HandleIngressMessage:
        {
            sockaddr_in addr;
            sockaddr_in6 addr6;
            sockaddr* tempaddr = (sockaddr*)MESSAGE_ReturnPacket(msg);
            if (tempaddr->sa_family == AF_INET)
            {
                memcpy(&addr, tempaddr, sizeof(struct sockaddr_in));
                MESSAGE_RemoveHeader(node,
                                     msg,
                                     sizeof(struct sockaddr_in),
                                     TRACE_SOCKETLAYER);
                UPA_HandleIngressMessage(iface,
                                (sockaddr*)&addr,
                                MESSAGE_ReturnPacket(msg),
                                MESSAGE_ReturnPacketSize(msg));
            }
            else if (tempaddr->sa_family == AF_INET6)
            {
                memcpy(&addr6, tempaddr, sizeof(struct sockaddr_in6));
                MESSAGE_RemoveHeader(node,
                                     msg,
                                     sizeof(struct sockaddr_in6),
                                     TRACE_SOCKETLAYER);
                UPA_HandleIngressMessage(iface,
                                (sockaddr*)&addr6,
                                MESSAGE_ReturnPacket(msg),
                                MESSAGE_ReturnPacketSize(msg));
            }
            break;
        }
        case EXTERNAL_MESSAGE_UPA_HandleIngressData:
        {
            int qualnet_fd = MESSAGE_GetInstanceId(msg);

            SL_send(node,
                    qualnet_fd,
                    MESSAGE_ReturnPacket(msg),
                    MESSAGE_ReturnPacketSize(msg));
            break;
        }
        case EXTERNAL_MESSAGE_UPA_InsertHash:
        {
            InsertHashStr hashStr;
            memcpy((char*)&hashStr,
                   (char*)MESSAGE_ReturnPacket(msg),
                   sizeof(InsertHashStr));
            MESSAGE_RemoveHeader(node,
                                 msg,
                                 sizeof(InsertHashStr),
                                 TRACE_SOCKETLAYER);

            UPA_InsertHash(iface,
                    hashStr.nodeId,
                    hashStr.qualnet_fd,
                    (sockaddr*)&hashStr.addr.address);

            break;
        }
        case EXTERNAL_MESSAGE_UPA_SendPacket:
        {
            sockaddr* addr = (sockaddr*)MESSAGE_ReturnPacket(msg);
            UInt32 addrLen = GetSockaddrLength(addr);

            MESSAGE_RemoveHeader(node,
                                 msg,
                                 addrLen,
                                 TRACE_SOCKETLAYER);

            UPA_TransmitPacket(iface,
                    node,
                    MESSAGE_ReturnPacket(msg),
                    MESSAGE_ReturnPacketSize(msg),
                    addr,
                    addrLen);
            break;
        }
        default:
        {
            ;
        }
    }
    MESSAGE_Free(node, msg);

}
