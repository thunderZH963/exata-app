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

#include "api.h"
#include "network_ip.h"
#include "network_icmp.h"
#include "transport_udp.h"
#include "app_util.h"
#include "attack_sequence.h"

#define MAX_ATTACK_TYPES 4
#define ATTACK_INTERVAL 2 * SECOND

static void AttackNetworkIcmpSetIcmpHeader(Node *node,
                                     Message *msg,
                                     Message *icmpPacket,
                                     unsigned short icmpType,
                                     unsigned short icmpCode,
                                     unsigned int seqOrGatOrPoin);

struct AttackTimerHeader {
    NodeAddress address;
    int attackType;
};

void ATTACK_InitiateAttack(
    Node* node,
    NodeAddress victimAddress)
{
    Message* msg = MESSAGE_Alloc(node,
                    NETWORK_LAYER,
                    NETWORK_PROTOCOL_ATTACK,
                    0);

    MESSAGE_InfoAlloc(node, msg, sizeof(AttackTimerHeader));
    AttackTimerHeader* header = (AttackTimerHeader*)MESSAGE_ReturnInfo(msg);
    header->address = victimAddress;
    header->attackType = 0;

    MESSAGE_Send(node, msg, 0);

    //ATTACK_PortScan(node, victimAddress);
    //ATTACK_DeepThroat(node, victimAddress);
}

void ATTACK_PortScan(
    Node* node,
    NodeAddress victimAddress)
{

}

void ATTACK_CyberKit(
    Node* node,
    NodeAddress victimAddress)
{
    Message *newMsg;
    IcmpHeader *icmpHeader;
    char* data;

    newMsg = MESSAGE_Alloc(node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_ICMP,
                            MSG_NETWORK_IcmpData);
    MESSAGE_PacketAlloc(node, newMsg, 64, TRACE_ICMP);
    data = newMsg->packet;
    for (int i = 0; i < 64; i ++)
    {
        data[i] = 0xAA;
    }

    MESSAGE_AddHeader(node, newMsg, sizeof(IcmpHeader), TRACE_ICMP);
    icmpHeader = (IcmpHeader*) newMsg->packet;
    memset(icmpHeader, 0, sizeof(IcmpHeader));

    AttackNetworkIcmpSetIcmpHeader(node, NULL, newMsg, 8, 0, 0);

    NodeAddress sourceAddress =
                    NetworkIpGetInterfaceAddress(node, 0);

    NetworkIpSendRawMessage(node,
                            newMsg,
                            sourceAddress,
                            victimAddress,
                            ANY_INTERFACE,
                            0,
                            IPPROTO_ICMP,
                            IPDEFTTL);
}

void ATTACK_Backdoor(
    Node* node,
    NodeAddress victimAddress)
{
    char payload[] = "00";

    NodeAddress myAddress = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                                            node, node->nodeId);
    Message *msg = APP_UdpCreateMessage(
        node,
        myAddress,
        (short) 59,
        victimAddress,
        (short) 2140,
        TRACE_UDP);

    APP_AddPayload(node, msg, payload, strlen(payload) + 1);

    APP_UdpSend(node, msg, PROCESS_IMMEDIATELY);
}

void ATTACK_Cybercop(
    Node* node,
    NodeAddress victimAddress)
{
    char payload[] = "cybercop";

    NodeAddress myAddress = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                                            node, node->nodeId);
    Message *msg = APP_UdpCreateMessage(
        node,
        myAddress,
        (short) 59,
        victimAddress,
        (short) 7,
        TRACE_UDP);

    APP_AddPayload(node, msg, payload, strlen(payload) + 1);

    APP_UdpSend(node, msg, PROCESS_IMMEDIATELY);
}

void ATTACK_Ddos(
    Node* node,
    NodeAddress victimAddress)
{
    char payload[] = "newserver";

    NodeAddress myAddress = MAPPING_GetDefaultInterfaceAddressFromNodeId(
                                            node, node->nodeId);
    Message *msg = APP_UdpCreateMessage(
        node,
        myAddress,
        (short) 59,
        victimAddress,
        (short) 6838,
        TRACE_UDP);

    APP_AddPayload(node, msg, payload, strlen(payload) + 1);

    APP_UdpSend(node, msg, PROCESS_IMMEDIATELY);
}

void ATTACK_ProcessEvent(
    Node* node,
    Message* msg)
{

    AttackTimerHeader* header = (AttackTimerHeader*)MESSAGE_ReturnInfo(msg);
    printf("%d attacking %x with type %d\n", node->nodeId, header->address, header->attackType);

    switch(header->attackType)
    {
        case 0:
        {
            ATTACK_CyberKit(node, header->address);
            break;
        }
        case 1:
        {
            ATTACK_Ddos(node, header->address);
            break;
        }
        case 2:
        {
            ATTACK_Backdoor(node, header->address);
            break;
        }
        case 3:
        {
            ATTACK_Cybercop(node, header->address);
            break;
        }
        default:
        {
        }

    }

    header->attackType = (header->attackType + 1) % MAX_ATTACK_TYPES;
    MESSAGE_Send(node, msg, ATTACK_INTERVAL);
}



static unsigned short AttackNetworkIcmpChecksumCalculation(unsigned short * buf,
                                                      unsigned int nwords)
{
    unsigned int checksum;

    for (checksum = 0; nwords > 0; nwords--)
    {
         checksum += *buf++;

    } //End for

    checksum = (checksum>>16) + (checksum & 0xffff);
    checksum += (checksum>>16);

    return ((short) ~checksum);
}

static void AttackNetworkIcmpSetIcmpHeader(Node *node,
                                     Message *msg,
                                     Message *icmpPacket,
                                     unsigned short icmpType,
                                     unsigned short icmpCode,
                                     unsigned int seqOrGatOrPoin)
{
    NetworkDataIp *ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    IcmpHeader *icmpHeader;
    unsigned int nwords;
    unsigned short *buf;
    icmpHeader = (IcmpHeader*)(icmpPacket->packet);
    nwords = MESSAGE_ReturnActualPacketSize(icmpPacket);
    nwords = (nwords>>1);
    buf = (unsigned short*)icmpHeader;
    icmpHeader->icmpMessageType = (unsigned char) icmpType;
    icmpHeader->icmpCode = (unsigned char) icmpCode;


    icmpHeader->icmpCheckSum = AttackNetworkIcmpChecksumCalculation(buf, nwords);
}

