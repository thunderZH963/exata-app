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
// PROTOCOL :: Secure Neighbor Authentication (SNAuth)
// LAYER :: Network Layer
// REFERENCES ::
//  [HuPJ02] Yih-Chun Hu, Adrian Perrig, David B. Johnson,
//      Ariadne: A Secure On-demand Routing Protocol for Ad Hoc Networks,
//      pp.12-23, in Proceedings of The Eighth Annual International
//      Conference on Mobile Computing and Networking (MOBICOM),
//      September 23-28, 2002. Atlanta, Georgia, USA.
//  [HuPJ03b] Yi-Chun Hu, Adrian Perrig, David B. Johnson,
//      Rushing Attacks and Defense in Wireless Ad Hoc Network Routing
//      Protocols, pp.30-40, ACM Wireless Security (WiSe'03),
//      September 19, 2003.  San Diego, California, USA.
//
// COMMENTS :: We implement two variants in HELLO initiating.
//        If with the sender's certificate attached, it is CERTIFIED-HELLO.
//        Otherwise, it is simply HELLO.
// **/

// Note: This scheme could be used with ISAKMP together.
// In the could-be case, a (mobile) wireless node only distributes its
// certificate to its (k-hop, currently 1-hop) neighbors via a
// HELLO broadcast. Upon reception of the certificate, its neighbors
// will initiate ISAKMP exchange with the node.

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "buffer.h"

#include "certificate_wtls.h"
#include "network_secure_neighbor.h"

// DEBUG options
#define  DEBUG  0
#define  DEBUG_SECURENEIGHBOR_TRACE 0

//---------------------------------------------------------------
// FUNCTION     :SecureneighborPrintTrace()
// PURPOSE      :Trace printing function to call for Secureneighbor packet.
// ASSUMPTION   :None
// PARAMETERS :: node : Node* : the node
//               msg : Message* : the traced message
//               sendOrReceive: char : a flag indicating send or receive
// RETURN VALUE :None
//---------------------------------------------------------------
static
void SecureneighborPrintTrace(
         Node* node,
         Message* msg,
         char sendOrReceive)
{
    byte* pktPtr = (byte *) MESSAGE_ReturnPacket(msg);
    char clockStr[MAX_STRING_LENGTH];
    FILE* fp = fopen("secureneighbor.trace", "a");

    if (!fp)
    {
        ERROR_ReportError("Can't open secureneighbor.trace\n");
    }

    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

    // print packet ID
    fprintf(fp, "%u, %d; %s; %u %c; ",
        msg->originatingNodeId,
        msg->sequenceNumber,
        clockStr,
        node->nodeId,
        sendOrReceive);

    switch(*pktPtr)
    {
        case SND_HELLO:
        {
            fprintf(fp, "SND_HELLO");
            break;
        }
        case SND_CERTIFIED_HELLO:
        {
            fprintf(fp, "SND_CERTIFIED_HELLO");
            break;
        }
        case SND_CHALLENGE:
        {
            fprintf(fp, "SND_CHALLENGE");
            break;
        }
        case SND_CERTIFIED_CHALLENGE:
        {
            fprintf(fp, "SND_CERTIFIED_CHALLENGE");
            break;
        }
        case SND_RESPONSE1:
        {
            fprintf(fp, "SND_RESPONSE1");
            break;
        }
        case SND_RESPONSE2:
        {
            fprintf(fp, "SND_RESPONSE2");
            break;
        }
        default: {
            ERROR_Assert(FALSE, "Secureneighbor: Unknown packet type!\n");
            break;
        }
    }

    fprintf(fp, "\n");
    fclose(fp);
}

//-------------------------------------------------------------------------
// FUNCTION     :SecureneighborInitTrace()
// PURPOSE      :Enabling Secureneighbor trace.
//              :The output will go in file secureneighbor.trace
// PARAMETERS :: none.
// ASSUMPTION   :None
// RETURN VALUE :None
//-------------------------------------------------------------------------
static
void SecureneighborInitTrace(void)
{
    if (DEBUG_SECURENEIGHBOR_TRACE)
    {
        // Empty or create a file named secureneighbor.trace
        // to print the packet contents
        FILE* fp = fopen("secureneighbor.trace", "w");
        fclose(fp);
    }
}

//-----------------------------------------------------------------------
// FUNCTION : SecureneighborPrintNeighborTable
// PURPOSE  : Printing the different fields of the neighbor table
// ARGUMENTS: node, The node printing the neighbor table
//            neighborTable, Secureneighbor neighbor table
// RETURN   : None
//-----------------------------------------------------------------------
static
void SecureneighborPrintNeighborTable(Node *node,
                                      SecureneighborTable* neighborTable)
{
    SecureneighborEntry* current = NULL;
    char neighborAddr[MAX_STRING_LENGTH] = {0};

    printf("Node %u's Neighbor Table is:\n", node->nodeId);

    // Just do a sequential scan over the neighbor table
    for (current = neighborTable->head;
         current != NULL;
         current = current->next)
    {
        IO_ConvertIpAddressToString(current->neighborAddr, neighborAddr);
        printf("\tneighbor = %s", neighborAddr);
    }
    printf("\n\n\n");
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborIsInNeighborTable
// PURPOSE:  Detect if `neighborAddr' is in the neighbor table
// ARGUMENTS: neighborTable, The current neighbor table
//            neighborAddr, the operand
// RETURN:    the matching entry
//--------------------------------------------------------------------
static
SecureneighborEntry* SecureneighborIsInNeighborTable(
    SecureneighborTable* neighborTable,
    NodeAddress neighborAddr)
{
    SecureneighborEntry* current = NULL;

    // Just do a sequential scan over the neighbor list
    for (current = neighborTable->head;
         current != NULL;
         current = current->next)
    {
        if (current->neighborAddr == neighborAddr)
        {
            return current;
        }
    }
    return NULL;
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborReplaceInsertNeighborTable
// PURPOSE : Insert/Update an entry into the secure neighbor table
// ARGUMENTS: node,       current node.
//            neighborTable, the neighbor list
//            neighborAddr,   neighbor's Address
//            interfaceIndex, The incoming HELLO's interface
//            ttl, to be used in multiple-hop neighbor authentication
//            expireTime,   Life time of the entry
// RETURN   : The entry just modified or created
//--------------------------------------------------------------------
static
SecureneighborEntry* SecureneighborReplaceInsertNeighborTable(
    Node *node,
    SecureneighborTable* neighborTable,
    NodeAddress neighborAddr,
    byte *cert,
    length_t certLength,
    int interfaceIndex,
    int ttl,
    clocktype expireTime)
{
    int i = 0;
    SecureneighborEntry* current = NULL;

    // Just do a sequential scan over the neighbor list
    for (current = neighborTable->head;
         current != NULL;
         current = current->next)
    {
        i++;

        if (current->neighborAddr == neighborAddr)
        {
            break;
        }
    }

    if (current == NULL)
    {
        if (i != neighborTable->size)
        {
            char buffer[MAX_STRING_LENGTH];
            sprintf(buffer,
                    "Node %u has inconsistent neighbor list "
                    "(item count = %u, but size = %u\n",
                    node->nodeId, i, neighborTable->size);
            ERROR_ReportError(buffer);
        }

        // Insert at head
        (neighborTable->size)++;
        current = (SecureneighborEntry*)
            MEM_malloc(sizeof(SecureneighborEntry));
        memset(current, 0, sizeof(SecureneighborEntry));

        current->next = neighborTable->head;
        neighborTable->head = current;
    }

    // Now set the values
    current->neighborAddr = neighborAddr;
    if (cert != NULL)
    {
        memcpy(current->certificate,
               cert,
               certLength);
    }
    current->intf = interfaceIndex;
    current->expireTime = expireTime;
    if (DEBUG)
    {
        SecureneighborPrintNeighborTable(node,
                                         neighborTable);
    }
    return current;
}


//--------------------------------------------------------------------
// FUNCTION: SecureneighborBroadcastHelloMessage
// PURPOSE:  Send out the HELLO
// ARGUMENTS: node, The node sending the HELLO msg
//            certifiedMode, if 1, then do certified HELLO; 0, plain HELLO
// RETURN:    None
//--------------------------------------------------------------------
static
void SecureNeighborBroadcastHelloMessage(Node* node, BOOL certifiedMode)
{
    Message* newMsg = NULL;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    SecureneighborData* secureneighbor = ip->neighborData;
    SecureneighborHelloPacket* helloPkt = {0};
    SecureneighborCertifiedHelloPacket* certHelloPkt = {0};

    if (DEBUG > 1)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(node->getNodeTime(), time);
        printf("Node %u is sending Hello packet at %s\n",
               node->nodeId, time);
    }

    newMsg = MESSAGE_Alloc(
                 node,
                 MAC_LAYER,
                 0,
                 MSG_MAC_FromNetwork);

    if (certifiedMode)
    {
        MESSAGE_PacketAlloc(
            node,
            newMsg,
            sizeof(SecureneighborCertifiedHelloPacket),
            TRACE_SECURENEIGHBOR);

        certHelloPkt = (SecureneighborCertifiedHelloPacket *)
            MESSAGE_ReturnPacket(newMsg);
        certHelloPkt->type = SND_CERTIFIED_HELLO;
        certHelloPkt->nextPayload = 0;
        certHelloPkt->reserved = 0;
        certHelloPkt->certEncoding = 0;
        secureneighbor->stats.numHelloSentByte +=
            sizeof(SecureneighborCertifiedHelloPacket) +
            sizeof(IpHeaderType);
    }
    else
    {
        MESSAGE_PacketAlloc(
            node,
            newMsg,
            sizeof(SecureneighborHelloPacket),
            TRACE_SECURENEIGHBOR);
        helloPkt = (SecureneighborHelloPacket *)MESSAGE_ReturnPacket(newMsg);
        helloPkt->type = SND_HELLO;
        secureneighbor->stats.numHelloSentByte +=
            sizeof(SecureneighborHelloPacket) +
            sizeof(IpHeaderType);
    }

    for (int i = 0; i < node->numberInterfaces; i++)
    {
        IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];

        clocktype delay = (clocktype) (RANDOM_erand(secureneighbor->seed) *
            SECURENEIGHBOR_BROADCAST_JITTER * MILLI_SECOND);

        if (certifiedMode && intfInfo->certificate != NULL)
        {
            certHelloPkt->payloadLength = (short)intfInfo->certificateLength;
            memcpy(certHelloPkt->certificateData,
                   intfInfo->certificate,
                   certHelloPkt->payloadLength);
        }
        NetworkIpSendRawMessageToMacLayerWithDelay(
            node,
            MESSAGE_Duplicate(node, newMsg),
            intfInfo->ipAddress,
            ANY_DEST,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_SECURE_NEIGHBOR,
            1,
            i,
            ANY_DEST,
            delay);
    }
    MESSAGE_Free(node, newMsg);

    secureneighbor->stats.numHelloSent++;
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborUnicastChallengeResponse
// PURPOSE:  Send out the unicast CHALLENGE/RESPONSE
// ARGUMENTS: node, The node sending the msg
//            packetType, CHALLENGE/CERTIFIED_CHALLENGE/RESPONSE1/RESPONSE2
// RETURN:    None
//--------------------------------------------------------------------
static
void SecureNeighborUnicastChallengeResponse(
    Node* node,
    char packetType,
    NodeAddress neighborAddr,
    int interfaceIndex)
{
    Message* newMsg = NULL;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    SecureneighborData* secureneighbor = ip->neighborData;
    SecureneighborChallengePacket* challengePkt = {0};
    SecureneighborCertifiedChallengePacket* certChallengePkt = {0};
    SecureneighborResponse1Packet* response1Pkt = {0};
    SecureneighborResponse2Packet* response2Pkt = {0};
    clocktype delay = (clocktype) 0;

    newMsg = MESSAGE_Alloc(
                 node,
                 MAC_LAYER,
                 0,
                 MSG_MAC_FromNetwork);
    switch (packetType)
    {
        case SND_CHALLENGE:
            MESSAGE_PacketAlloc(
                node,
                newMsg,
                sizeof(SecureneighborChallengePacket),
                TRACE_SECURENEIGHBOR);
            challengePkt = (SecureneighborChallengePacket *)
                MESSAGE_ReturnPacket(newMsg);
            challengePkt->type = SND_CHALLENGE;
            delay = (clocktype)
                (RANDOM_erand(secureneighbor->seed) *
                 SECURENEIGHBOR_BROADCAST_JITTER * MILLI_SECOND);
            secureneighbor->stats.numChallengeSent++;
            secureneighbor->stats.numChallengeSentByte +=
                sizeof(SecureneighborChallengePacket) +
                sizeof(IpHeaderType);
            break;
        case SND_CERTIFIED_CHALLENGE:
            MESSAGE_PacketAlloc(
                node,
                newMsg,
                sizeof(SecureneighborCertifiedChallengePacket),
                TRACE_SECURENEIGHBOR);
            certChallengePkt = (SecureneighborCertifiedChallengePacket *)
                MESSAGE_ReturnPacket(newMsg);
            certChallengePkt->type = SND_CERTIFIED_CHALLENGE;
            delay = (clocktype)
                (RANDOM_erand(secureneighbor->seed) *
                 SECURENEIGHBOR_BROADCAST_JITTER * MILLI_SECOND);
            secureneighbor->stats.numChallengeSent++;
            secureneighbor->stats.numChallengeSentByte +=
                sizeof(SecureneighborCertifiedChallengePacket) +
                sizeof(IpHeaderType);
            break;
        case SND_RESPONSE1:
            MESSAGE_PacketAlloc(
                node,
                newMsg,
                sizeof(SecureneighborResponse1Packet),
                TRACE_SECURENEIGHBOR);
            response1Pkt = (SecureneighborResponse1Packet *)
                MESSAGE_ReturnPacket(newMsg);
            response1Pkt->type = SND_RESPONSE1;
            secureneighbor->stats.numResponse1SentByte +=
                sizeof(SecureneighborResponse1Packet) +
                sizeof(IpHeaderType);
            secureneighbor->stats.numResponse1Sent++;
            break;
        case SND_RESPONSE2:
            MESSAGE_PacketAlloc(
                node,
                newMsg,
                sizeof(SecureneighborResponse2Packet),
                TRACE_SECURENEIGHBOR);
            response2Pkt = (SecureneighborResponse2Packet *)
                MESSAGE_ReturnPacket(newMsg);
            response2Pkt->type = SND_RESPONSE2;
            secureneighbor->stats.numResponse2Sent++;
            secureneighbor->stats.numResponse2SentByte +=
                sizeof(SecureneighborResponse2Packet) +
                sizeof(IpHeaderType);
            break;
        default:
            ERROR_Assert(FALSE, "Impossible to be here.\n");
            break;
    }

    if (DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        char jitter[MAX_STRING_LENGTH];
        char address[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(neighborAddr, address);
        TIME_PrintClockInSecond(node->getNodeTime(), time);
        TIME_PrintClockInSecond(delay, jitter);
        printf(
            "Node %u sends SND_%s packet to %s at time %s with jitter %s\n",
            node->nodeId,
            (packetType == SND_CHALLENGE? "CHALLENGE" :
             (packetType == SND_CERTIFIED_CHALLENGE? "CERTIFIED_CHALLENGE" :
              (packetType == SND_RESPONSE1? "RESPONSE1" :
               (packetType == SND_RESPONSE2? "RESPONSE2" : "Impossible")))),
            address, time, jitter);
    }

    IpInterfaceInfoType* intfInfo = ip->interfaceInfo[interfaceIndex];
    NetworkIpSendRawMessageToMacLayerWithDelay(
        node,
        newMsg,
        intfInfo->ipAddress,
        neighborAddr,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_SECURE_NEIGHBOR,
        1,
        interfaceIndex,
        neighborAddr,
        delay);
}

//-----------------------------------------------------------------------
// FUNCTION : SecureneighborCryptoOverhead
// PURPOSE  : Send message with estimate crypto processing delay
// ARGUMENTS: node, The node which is scheduling an event
//            msg, The event type of the message
//            packetType,type of ANODr packet ex,ANODR_RREQ
//            srcAddr, the source Addr of the msg
//            incomingInterface,the interface from which the packet has come
//            ttl,time to live
//-----------------------------------------------------------------------
static
void SecureneighborCryptoOverhead(Node *node,
                                  Message *msg,
                                  char packetType,
                                  NodeAddress srcAddr,
                                  int incomingInterface,
                                  int ttl)
{
    // Send message with estimate processing delay
    MESSAGE_InfoAlloc(node, msg, sizeof(SecureneighborCryptoOverheadType));
    SecureneighborCryptoOverheadType *info =
        (SecureneighborCryptoOverheadType *)MESSAGE_ReturnInfo(msg);

    info->packetType = packetType;
    info->srcAddr = srcAddr;
    info->interfaceIndex = incomingInterface;
    //the ttl should be decreased before forwarding the packet
    info->ttl = ttl - IP_TTL_DEC;

    clocktype delay = AES_DEFAULT_DELAY;
    if (packetType == SND_CERTIFIED_HELLO)
    {
        delay = ECC_DEFAULT_DELAY;
    }

    MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_SECURENEIGHBOR);
    MESSAGE_SetEvent(msg, MSG_CRYPTO_Overhead);

    MESSAGE_Send(node, msg, delay);
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborPrintHandshakingList
// PURPOSE:  Print handshaking list for debugging
// ARGUMENTS: node: the node
//            head: The current handshaking list
// RETURN:    NONE
//--------------------------------------------------------------------
static
void SecureneighborPrintHandshakingList(
    Node *node,
    SecureneighborHandshakingList *head)
{
    char neighborAddr[MAX_STRING_LENGTH] = {0};
    char clockStr[MAX_STRING_LENGTH];
    char address[MAX_STRING_LENGTH];

    printf("Node %u's Handshaking List is:\n", node->nodeId);

    for (SecureneighborHandshakingList *current = head;
         current != NULL;
         current = current->next)
    {
        IO_ConvertIpAddressToString(current->neighborAddr, neighborAddr);
        IO_ConvertIpAddressToString(current->myAddr, address);
        TIME_PrintClockInSecond(current->startTime, clockStr);
        printf("\t(neighbor %s, myaddr %s, startTime %s)\n",
               neighborAddr, address, clockStr);
    }
    printf("\n\n\n");
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborIsInHandshaking
// PURPOSE:  Detect if there is an entry with "neighborAddr" in handshaking
// ARGUMENTS: head: The current handshaking list
//            myAddr: my address (in case of multiple interfaces)
//            neighborAddr: Handshaking with the node begins
//            now: if 0, timeout is ignored; otherwise, treat it as now time
//            timeout: if a handshake is too long and exceeds the `timeout'
//                   then it is restarted (the existing state is overrided).
// RETURN:    the matching entry
//--------------------------------------------------------------------
static
SecureneighborHandshakingList *SecureneighborIsInHandshaking(
    SecureneighborHandshakingList *head,
    NodeAddress myAddr,
    NodeAddress neighborAddr,
    clocktype now,
    clocktype timeout)
{
    if (head != NULL)
    {
        for (SecureneighborHandshakingList *current = head;
             current != NULL;
             current = current->next)
        {
            if (current->neighborAddr == neighborAddr &&
                current->myAddr == myAddr)
            {
                // Already in handshaking process with the HELLO's sender.

                // Timeout?
                if (now &&
                    (now - current->startTime) > timeout)
                {
                    // Don't drop, but update the start time
                    current->startTime = now;
                    return NULL;
                }
                return current;
            }
        }
    }
    return NULL;
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborInsertReplaceHandshaking
// PURPOSE:  Insert or replace the entry with "neighborAddr"
// ARGUMENTS: head: The current handshaking list
//            myAddr: my address (in case of multiple interfaces)
//            neighborAddr: Handshaking with the node begins
//            startTime: Handshaking start time
//            state: 0-CHALLENGE already sent; 1-RESPONSE1 already sent
//            flag: TRUE if 2-way handshaking, FALSE if 3-way
// RETURN:    None
//--------------------------------------------------------------------
static
void SecureneighborInsertReplaceHandshaking(
    SecureneighborHandshakingList **head,
    NodeAddress myAddr,
    NodeAddress neighborAddr,
    clocktype startTime,
    int state,
    BOOL flag)
{
    SecureneighborHandshakingList *current = *head;

    while (current != NULL)
    {
        if (current->neighborAddr == neighborAddr &&
            current->myAddr == myAddr)
        {
            // Replace it
            current->startTime = startTime;
            current->state = state;
            current->withoutResponse2 = flag;
            return;
        }
        current = current->next;
    }

    // Otherwise, insert at head
    current = (SecureneighborHandshakingList *)
        MEM_malloc(sizeof(SecureneighborHandshakingList));
    current->myAddr = myAddr;
    current->neighborAddr = neighborAddr;
    current->startTime = startTime;
    current->state = state;
    current->withoutResponse2 = flag;
    current->next = *head;
    *head = current;
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborDeleteHandshaking
// PURPOSE:  Delete the entry with matching "neighborAddr" from
//           the current handshaking list
// ARGUMENTS: head The current handshaking list
//            neighborAddr, Handshaking with the node is finished
// RETURN:    TRUE if there is matching and deletion; otherwise FALSE
//--------------------------------------------------------------------
static
BOOL SecureneighborDeleteHandshaking(
    SecureneighborHandshakingList **head,
    NodeAddress neighborAddr)
{
    SecureneighborHandshakingList *current = *head,
        *prev = NULL;

    while (current != NULL)
    {
        if (current->neighborAddr == neighborAddr)
        {
            // Delete it
            if (current == *head)
            {
                *head = current->next;
            }
            else
            {
                prev->next = current->next;
            }
            MEM_free(current);
            return TRUE;
        }
        prev = current;
        current = current->next;
    }
    return FALSE;
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborHandleHello
// PURPOSE:  Processing procedure when HELLO is received
// ARGUMENTS: node, The node which has received the HELLO msg
//            ttl,  to be used in multiple-hop neighbor authentication
//            interfaceIndex, The interface index through which
//                            the HELLO has been received.
// RETURN:    None
//--------------------------------------------------------------------
static
void SecureneighborHandleHello(
         Node* node,
         Message* msg,
         NodeAddress neighborAddr,
         int ttl,
         int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    SecureneighborData* secureneighbor = ip->neighborData;
    secureneighbor->stats.numHelloRecved++;

    if (DEBUG)
    {
        SecureneighborPrintHandshakingList(node,
                                           secureneighbor->handshaking);
    }
    // Already handshaking with `neighborAddr'?
    if (SecureneighborIsInHandshaking(
            secureneighbor->handshaking,
            ip->interfaceInfo[interfaceIndex]->ipAddress,
            neighborAddr,
            node->getNodeTime(),
            secureneighbor->neighborTimeout))
    {
        // Already in handshaking with the HELLO's sender, ignore it
        if (DEBUG)
        {
            char clockStr[MAX_STRING_LENGTH];
            char address[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(neighborAddr, address);
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
            printf("Node %u ignores hello from %s at time %s\n",
                   node->nodeId, address, clockStr);
        }
        return;
    }

    SecureneighborHelloPacket* helloPkt
        = (SecureneighborHelloPacket *) MESSAGE_ReturnPacket(msg);

    switch (helloPkt->type)
    {
        case SND_HELLO:
        {
            secureneighbor->stats.numHelloRecvedByte +=
                sizeof(SecureneighborHelloPacket) +
                sizeof(IpHeaderType);
            // Send back CHALLENGE
            SecureNeighborUnicastChallengeResponse(node,
                                                   SND_CHALLENGE,
                                                   neighborAddr,
                                                   interfaceIndex);

            // Record the handshaking
            SecureneighborInsertReplaceHandshaking(
                &secureneighbor->handshaking,
                ip->interfaceInfo[interfaceIndex]->ipAddress,
                neighborAddr,
                node->getNodeTime(),
                0,
                FALSE);

            break;
        }
        case SND_CERTIFIED_HELLO:
        {
            secureneighbor->stats.numHelloRecvedByte +=
                sizeof(SecureneighborCertifiedHelloPacket) +
                sizeof(IpHeaderType);

            // Send back CERTIFIED-CHALLENGE
            SecureneighborCertifiedHelloPacket* certHelloPkt =
                (SecureneighborCertifiedHelloPacket *)helloPkt;

            ERROR_Assert(
                certHelloPkt->nextPayload == 0 &&
                certHelloPkt->reserved == 0 &&
                certHelloPkt->certEncoding == 0,
                "Invalid secure neighbor CERTIFIED_HELLO packet.\n");

#if 1
            SecureNeighborUnicastChallengeResponse(node,
                                                   SND_CERTIFIED_CHALLENGE,
                                                   neighborAddr,
                                                   interfaceIndex);
#else
            // The current ISAKMP is node-based,
            // will be changed to IP-based later.
            // This code section will be uncommented once the change is done.
            BOOL status = IsISAKMPSAPresent(
                node,
                ip->interfaceInfo[interfaceIndex]->ipAddress,
                neighborAddr);
            SecureneighborTable* neighborTable = &secureneighbor->neighbors;

            if (status == FALSE)
            {
                ISAKMPSetUp_Negotiation(
                    node, NULL, NULL,
                    ip->interfaceInfo[interfaceIndex]->ipAddress,
                    neighborAddr,
                    INITIATOR, PHASE_1);
            }
            // The current ISAKMP is node-based,
            // will be changed to IP-based later
            SecureneighborReplaceInsertNeighborTable(
                node,
                neighborTable,
                neighborAddr,
                certHelloPkt->certificateData,
                certHelloPkt->payloadLength,
                interfaceIndex,
                ttl,
                node->getNodeTime() + SECURENEIGHBOR_TIMEOUT);
#endif

            // Record the handshaking
            SecureneighborInsertReplaceHandshaking(
                &secureneighbor->handshaking,
                ip->interfaceInfo[interfaceIndex]->ipAddress,
                neighborAddr,
                node->getNodeTime(),
                0,
                TRUE);

            break;
        }
        default:
            ERROR_Assert(FALSE, "Impossible to be here.\n");
            break;
    }
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborHandleChallengeResponse
// PURPOSE:  Processing procedure when CHALLENGE/RESPONSE is received
// ARGUMENTS: node, The node which has received the msg
//            msg, the incoming message
//            neighborAddr, The neighbor I'm talking to
//            ttl,  The ttl of the message
//            interfaceIndex, The interface index through which
//                            the message has been received.
// RETURN:    None
//--------------------------------------------------------------------

static
void SecureneighborHandleChallengeResponse(
         Node* node,
         Message* msg,
         NodeAddress neighborAddr,
         int ttl,
         int interfaceIndex)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    SecureneighborData* secureneighbor = ip->neighborData;
    SecureneighborTable* neighborTable = &secureneighbor->neighbors;
    char *packet = (char *) MESSAGE_ReturnPacket(msg);

    if (DEBUG)
    {
        SecureneighborPrintHandshakingList(node,
                                           secureneighbor->handshaking);
    }
    // Already handshaking with `neighborAddr'?
    SecureneighborHandshakingList *shaking =
        SecureneighborIsInHandshaking(
            secureneighbor->handshaking,
            ip->interfaceInfo[interfaceIndex]->ipAddress,
            neighborAddr,
            0,
            secureneighbor->neighborTimeout);

    switch (*packet)
    {
        case SND_CHALLENGE:
        case SND_CERTIFIED_CHALLENGE:
        {
            secureneighbor->stats.numChallengeRecved++;

            if (*packet == SND_CHALLENGE)
            {
                secureneighbor->stats.numChallengeRecvedByte +=
                    sizeof(SecureneighborChallengePacket) +
                    sizeof(IpHeaderType);
            }
            else
            {
                secureneighbor->stats.numChallengeRecvedByte +=
                    sizeof(SecureneighborCertifiedChallengePacket) +
                    sizeof(IpHeaderType);
            }

            if (shaking != NULL)
            {
                if (DEBUG)
                {
                    char clockStr[MAX_STRING_LENGTH];
                    char address[MAX_STRING_LENGTH];

                    IO_ConvertIpAddressToString(neighborAddr, address);
                    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                    printf("Node %u already handshaking with %s "
                           "at time %s\n",
                           node->nodeId, address, clockStr);
                }

                // Tricky: if X and Y exchange HELLOs, and then exchange
                // CHALLENGEs nearly at same time (i.e., one's CHALLENGE
                // is sent out before the other receives it.  The
                // transmission diagram is a crossover X), we must exactly
                // ignore one of the 2 CHALLENGEs, otherwise key agreement
                // is infeasible.
                //
                // For other already-in-handshaking cases, CHALLENGEs
                // should be ignored for optimization purpose.
                if (shaking->state == 0)
                {
                    NodeAddress myAddr =
                        ip->interfaceInfo[interfaceIndex]->ipAddress;
                    if (myAddr > neighborAddr)
                    {
                        if (DEBUG)
                        {
                            char clockStr[MAX_STRING_LENGTH];
                            char address[MAX_STRING_LENGTH];

                            IO_ConvertIpAddressToString(neighborAddr,
                                                        address);
                            TIME_PrintClockInSecond(node->getNodeTime(),
                                                    clockStr);
                            printf("Node %u ignores CHALLENGE from %s "
                                   "at time %s\n",
                                   node->nodeId, address, clockStr);
                        }
                        return;
                    }
                    // else myAddr < neighborAddr, let it get through
                }
                else if (shaking->state == 1)
                {
                    if (DEBUG)
                    {
                        char clockStr[MAX_STRING_LENGTH];
                        char address[MAX_STRING_LENGTH];

                        IO_ConvertIpAddressToString(neighborAddr, address);
                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        printf("Node %u ignores CHALLENGE from %s "
                               "at time %s\n",
                               node->nodeId, address, clockStr);
                    }
                    return;
                }
                else
                {
                    ERROR_ReportError("SecureNeighbor: Impossible.");
                }
            }
            // Send back RESPONSE1
            SecureNeighborUnicastChallengeResponse(node,
                                                   SND_RESPONSE1,
                                                   neighborAddr,
                                                   interfaceIndex);

            if (*packet == SND_CHALLENGE)
            {
                // Record the handshaking.  It is needed in 3-way handshake
                SecureneighborInsertReplaceHandshaking(
                    &secureneighbor->handshaking,
                    ip->interfaceInfo[interfaceIndex]->ipAddress,
                    neighborAddr,
                    node->getNodeTime(),
                    1,
                    TRUE);
            }
            else
            {
                // We don't record the handshaking at the receiver of
                // CERTIFIED-CHALLENGE because it is not needed
                // in 2-way handshake

                // In 2-way handshake, CERTIFIED_CHALLENGE receiver done
                SecureneighborReplaceInsertNeighborTable(
                    node,
                    neighborTable,
                    neighborAddr,
                    NULL,
                    0,
                    interfaceIndex,
                    ttl,
                    node->getNodeTime() + SECURENEIGHBOR_TIMEOUT);
            }

            break;
        }
        case SND_RESPONSE1:
        {
            secureneighbor->stats.numResponse1Recved++;
            secureneighbor->stats.numResponse1RecvedByte +=
                sizeof(SecureneighborResponse1Packet) +
                sizeof(IpHeaderType);

            if (shaking != NULL)
            {
                // In the handshaking list

                if (shaking->withoutResponse2 == FALSE)
                {
                    // 3-way handshake
                    SecureNeighborUnicastChallengeResponse(node,
                                                           SND_RESPONSE2,
                                                           neighborAddr,
                                                           interfaceIndex);
                }

                // In both 2-way handshake and 3-way handshake,
                // RESPONSE1 receiver done
                if (SecureneighborDeleteHandshaking(
                        &secureneighbor->handshaking,
                        neighborAddr)
                    == FALSE)
                {
                    ERROR_ReportError("SecureNeighbor: RESPONSE1 from "
                                      "a non-existent neighbor.");
                }
                else
                {
                    if (DEBUG)
                    {
                        char temp[MAX_STRING_LENGTH] = {0};
                        IO_ConvertIpAddressToString(neighborAddr, temp);
                        printf("Neighbor %s deleted from Node %d's "
                               "handshaking list\n",
                               temp, node->nodeId);
                    }
                }
                SecureneighborReplaceInsertNeighborTable(
                    node,
                    neighborTable,
                    neighborAddr,
                    NULL,
                    0,
                    interfaceIndex,
                    ttl,
                    node->getNodeTime() + SECURENEIGHBOR_TIMEOUT);
            }
            else
            {
                // Not in the handshaking list

                if (SecureneighborIsInNeighborTable(neighborTable,
                                                    neighborAddr))
                {
                    // This could be caused by multiple interfaces,
                    // where an interface S1 on node S handshakes with
                    // more than one interfaces on node R (say R1 and R2).
                    // W/o loss of generality, suppose R1's handshake
                    // ends earlier than R2's.   R will delete S1 from
                    // its handshaking list because of R1, then R2 will
                    // arrive at here.
                }
                else
                {
                    ERROR_ReportWarning("SecureNeighbor: RESPONSE1 from "
                                        "a non-existent neighbor.");
                }
            }
            break;
        }
        case SND_RESPONSE2:
        {
            secureneighbor->stats.numResponse2Recved++;
            secureneighbor->stats.numResponse2RecvedByte +=
                sizeof(SecureneighborResponse2Packet) +
                sizeof(IpHeaderType);

            // This is only for 3-way handshake, everything is done
            if (!shaking ||
                SecureneighborDeleteHandshaking(
                    &secureneighbor->handshaking,
                    neighborAddr)
                == FALSE)
            {
                // Not in the handshaking list

                if (SecureneighborIsInNeighborTable(neighborTable,
                                                    neighborAddr))
                {
                    // This could be caused by multiple interfaces,
                    // where an interface S1 on node S handshakes with
                    // more than one interfaces on node R (say R1 and R2).
                    // W/o loss of generality, suppose R1's handshake
                    // ends earlier than R2's.   R will delete S1 from
                    // its handshaking list because of R1, then R2 will
                    // arrive at here.
                }
                else
                {
                    ERROR_ReportWarning("SecureNeighbor: RESPONSE2 from "
                                        "a non-existent neighbor.");
                }
            }
            else
            {
                // In the handshaking list

                if (DEBUG)
                {
                    char temp[MAX_STRING_LENGTH] = {0};
                    IO_ConvertIpAddressToString(neighborAddr, temp);
                    printf("Neighbor %s deleted from Node %d's "
                           "handshaking list\n",
                           temp, node->nodeId);
                }
            }
            SecureneighborReplaceInsertNeighborTable(
                node,
                neighborTable,
                neighborAddr,
                NULL,
                0,
                interfaceIndex,
                ttl,
                node->getNodeTime() + SECURENEIGHBOR_TIMEOUT);
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "Impossible to be here.\n");
            break;
        }
    }
}

//--------------------------------------------------------------------
// FUNCTION: SecureneighborInitializeConfigurableParameters
// PURPOSE: To initialize the user configurable parameters or initialize
//          the corresponding variables
// PARAMETERS: node, the node pointer, which runs secureneighbor protocol
//             secureneighbor, secureneighbor internal structure
//             interfaceIndex the interface for which it is initializing
// RETURN:  Null
// ASSUMPTION: None
//--------------------------------------------------------------------
static
void SecureneighborInitializeConfigurableParameters(
         Node* node,
         const NodeInput* nodeInput,
         SecureneighborData* secureneighbor)
{
    BOOL wasFound;
    char buf[MAX_STRING_LENGTH];

    IO_ReadTime(
        node->nodeId,
        ANY_ADDRESS,  // per node based parameter, any addr
        nodeInput,
        "SECURE-NEIGHBOR-TIMEOUT",
        &wasFound,
        &secureneighbor->neighborTimeout);

    if (!wasFound)
    {
        secureneighbor->neighborTimeout =
            SECURENEIGHBOR_DEFAULT_TIMEOUT * MILLI_SECOND;
    }
    else
    {
        ERROR_Assert(secureneighbor->neighborTimeout > 0 &&
                     secureneighbor->neighborTimeout <= 1000000000000000LL,
                     "Invalid value for SECURENEIGHBOR-TIMEOUT. "
                     "Accepted values are between minimal value 1 and "
                     "maximal value 1000000000000000.");
    }

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SECURE-NEIGHBOR-CERTIFIED-HELLO",
        &wasFound,
        buf);

    if (!wasFound || !strcmp(buf, "NO"))
    {
        secureneighbor->doCertifiedHello = FALSE;
    }
    else if (!strcmp(buf, "YES"))
    {
        secureneighbor->doCertifiedHello = TRUE;
    }
    else
    {
        ERROR_ReportError("SECURE-NEIGHBOR-CERTIFIED-HELLO "
                          "expects YES or NO");
    }

#if 1
    // Currently only 1-hop
    secureneighbor->ttlMax = 1;
#else
    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SECURENEIGHBOR-TTL-MAX",
        &wasFound,
        &secureneighbor->ttlMax);

    if (wasFound == FALSE)
    {
        secureneighbor->ttlMax = SECURENEIGHBOR_DEFAULT_TTL_MAX;
    }

    ERROR_Assert(secureneighbor->ttlMax>0,
                 "SECURENEIGHBOR_TTL_MAX should be > 0");
#endif
}


//--------------------------------------------------------------------
// FUNCTION: SecureneighborInit
// PURPOSE:  Initialization function for SECURENEIGHBOR protocol
// ARGUMENTS: node, Secureneighbor node which is initializing itself
//            nodeInput,  The configuration file
// RETURN:    None
//--------------------------------------------------------------------
void SecureneighborInit(Node* node,
                        const NodeInput* nodeInput)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    BOOL retVal;
    char buf[MAX_STRING_LENGTH];

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SECURE-NEIGHBOR-ENABLED",
        &retVal,
        buf);

    if (!retVal || !strcmp(buf, "NO"))
    {
        ip->isSecureneighborEnabled = FALSE;
    }
    else if (!strcmp(buf, "YES"))
    {
        SecureneighborData* secureneighbor =
            (SecureneighborData *) MEM_malloc(sizeof(SecureneighborData));

        memset(secureneighbor, 0, sizeof(SecureneighborData));
        ip->neighborData = secureneighbor;

        // Initialize statistical variables
        memset(&(secureneighbor->stats), 0, sizeof(SecureneighborStats));

        SecureneighborInitTrace();

        // Read user configurable parameters from the configuration file or
        // initialize them with the default value.
        SecureneighborInitializeConfigurableParameters(
            node,
            nodeInput,
            secureneighbor);

        // Initialize secure neighbor table
        secureneighbor->neighbors.head = NULL;
        secureneighbor->neighbors.size = 0;

        RANDOM_SetSeed(secureneighbor->seed,
                       node->globalSeed,
                       node->nodeId,
                       NETWORK_PROTOCOL_SECURENEIGHBOR);

        // Initiate the timer
        Message *newMsg = MESSAGE_Alloc(node,
                                        NETWORK_LAYER,
                                        NETWORK_PROTOCOL_SECURENEIGHBOR,
                                        MSG_NETWORK_CheckNeighborTimeout);
        MESSAGE_Send(
            node,
            newMsg,
            secureneighbor->neighborTimeout +
            ((int)(RANDOM_erand(secureneighbor->seed)
                   * SECURENEIGHBOR_BROADCAST_JITTER)) * MILLI_SECOND);

        ip->isSecureneighborEnabled = TRUE;
    }
    else
    {
        ERROR_ReportError("SECURE-NEIGHBOR-ENABLED expects YES or NO");
    }
}


//--------------------------------------------------------------------
// FUNCTION: SecureneighborFinalize
// PURPOSE:  Called at the end of the simulation to collect the results
// ARGUMENTS: node, The node for which the statistics are to be printed
// RETURN:    None
//--------------------------------------------------------------------
void SecureneighborFinalize(Node* node)
{
    SecureneighborData* secureneighbor
        = node->networkData.networkVar->neighborData;
    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "Number of HELLO packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numHelloSent);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of HELLO packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numHelloSentByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of HELLO packets Received = %u",
            (unsigned short) secureneighbor->stats.numHelloRecved);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of HELLO packets Received = %u",
            (unsigned short) secureneighbor->stats.numHelloRecvedByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of CHALLENGE packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numChallengeSent);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of CHALLENGE packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numChallengeSentByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of CHALLENGE packets Received = %u",
            (unsigned short) secureneighbor->stats.numChallengeRecved);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of CHALLENGE packets Received = %u",
            (unsigned short) secureneighbor->stats.numChallengeRecvedByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of RESPONSE1 packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numResponse1Sent);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of RESPONSE1 packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numResponse1SentByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of RESPONSE1 packets Received = %u",
            (unsigned short) secureneighbor->stats.numResponse1Recved);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of RESPONSE1 packets Received = %u",
            (unsigned short) secureneighbor->stats.numResponse1RecvedByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of RESPONSE2 packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numResponse2Sent);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of RESPONSE2 packets Initiated = %u",
            (unsigned short) secureneighbor->stats.numResponse2SentByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    sprintf(buf, "Number of RESPONSE2 packets Received = %u",
            (unsigned short) secureneighbor->stats.numResponse2Recved);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);
    sprintf(buf, "Number of bytes of RESPONSE2 packets Received = %u",
            (unsigned short) secureneighbor->stats.numResponse2RecvedByte);
    IO_PrintStat(
        node,
        "Network",
        "SECURENEIGHBOR",
        ANY_DEST,
        -1,
        buf);

    if (DEBUG)
    {
        SecureneighborPrintNeighborTable(node,
                                         &secureneighbor->neighbors);
    }

    // Do sequential deletions
    {
        SecureneighborEntry *next = NULL,
            *current = secureneighbor->neighbors.head;
        while (current != NULL)
        {
            next = current->next;
            MEM_free(current);
            current = next;
        }
    }
    {
        SecureneighborHandshakingList *next = NULL,
            *current = secureneighbor->handshaking;
        while (current != NULL)
        {
            next = current->next;
            MEM_free(current);
            current = next;
        }
    }
}


//--------------------------------------------------------------------
// FUNCTION : SecureneighborHandleProtocolPacket
// PURPOSE  : Called when Secureneighbor packet is received from MAC,
//            the packets may be of following types, HELLO, CERTIFIED_HELLO,
//            CHALLENGE, CERTIFIED_CHALLENGE, RESPONSE1, RESPONSE2
// ARGUMENTS: node,     The node received message
//            msg,      The message received
//            srcAddr,  Source Address of the message
//            destAddr, Destination Address of the message
//            ttl,      time to leave
//            interfaceIndex, receiving interface
// RETURN   : None
//--------------------------------------------------------------------
void SecureneighborHandleProtocolPacket(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    int ttl,
    int interfaceIndex)
{
    char* packetType = MESSAGE_ReturnPacket(msg);

    if (DEBUG_SECURENEIGHBOR_TRACE)
    {
        SecureneighborPrintTrace(node, msg, 'R');
    }

    if (DEBUG >= 4)
    {
        char clockStr[MAX_STRING_LENGTH];
        char address[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u got SECURENEIGHBOR packet at time %s\n",
               node->nodeId, clockStr);

        IO_ConvertIpAddressToString(srcAddr, address);
        printf("\tsource: %s\n", address);

        IO_ConvertIpAddressToString(destAddr, address);
        printf("\tdestination: %s\n", address);
    }

    switch (*packetType)
    {
        case SND_HELLO:
        case SND_CERTIFIED_HELLO:
        case SND_CHALLENGE:
        case SND_CERTIFIED_CHALLENGE:
        case SND_RESPONSE1:
        case SND_RESPONSE2:
        {
            NetworkDataIp *ip = (NetworkDataIp *)
                node->networkData.networkVar;
            for (int i=0; i<node->numberInterfaces; i++)
            {
                if (srcAddr == ip->interfaceInfo[i]->ipAddress)
                {
                    // The node doesn't do handshaking between its own
                    // multiple interfaces
                    if (DEBUG)
                    {
                        printf("Self transmission.\n");
                    }
                    MESSAGE_Free(node, msg);
                    return;
                }
            }
            if (DEBUG)
            {
                char clockStr[MAX_STRING_LENGTH] = {0};
                char address[MAX_STRING_LENGTH] = {0};

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got SND_%s packet at time %s\n",
                       node->nodeId,
                       (*packetType == SND_HELLO? "HELLO" :
                        (*packetType == SND_CERTIFIED_HELLO?
                         "CERTIFIED_HELLO" :
                         (*packetType == SND_CHALLENGE? "CHALLENGE" :
                          (*packetType == SND_CERTIFIED_CHALLENGE?
                           "CERTIFIED_CHALLENGE" :
                           (*packetType == SND_RESPONSE1? "RESPONSE1" :
                            (*packetType == SND_RESPONSE2? "RESPONSE2" :
                             "Impossible")))))),
                       clockStr);

                IO_ConvertIpAddressToString(srcAddr, address);
                printf("\tsource: %s\n", address);

                IO_ConvertIpAddressToString(destAddr, address);
                printf("\tdestination: %s\n", address);
            }

            SecureneighborCryptoOverhead(node,
                                         msg,
                                         *packetType,
                                         srcAddr,
                                         interfaceIndex,
                                         ttl);
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "Secureneighbor: Unknown packet type!\n");
            break;
        }
    }
}


//--------------------------------------------------------------------
// FUNCTION: SecureneighborHandleProtocolEvent
// PURPOSE: Handles all the protocol events
// ARGUMENTS: node, the node received the event
//            msg,  msg containing the event type
//--------------------------------------------------------------------
void SecureneighborHandleProtocolEvent(
    Node* node,
    Message* msg)
{
    NetworkDataIp* ip = node->networkData.networkVar;
    SecureneighborData* secureneighbor = ip->neighborData;
    SecureneighborTable* neighborTable = &secureneighbor->neighbors;

    switch (MESSAGE_GetEvent(msg))
    {
        case MSG_NETWORK_CheckNeighborTimeout:
        {
            if (DEBUG)
            {
                char clockStr[MAX_STRING_LENGTH] = {0};
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Periodic printout (simTime=%s):\n", clockStr);
                SecureneighborPrintNeighborTable(node, neighborTable);
            }

            // Remove the expired neighbors.
            // Just do a sequential scan over the secure neighbor table
            SecureneighborEntry *current = neighborTable->head,
                *prev = NULL;
            while (current != NULL)
            {
                if (current->expireTime < node->getNodeTime())
                {
                    // expired route entry, delete it
                    if (current == neighborTable->head)
                    {
                        neighborTable->head = current->next;
                    }
                    else
                    {
                        prev->next = current->next;
                    }
                    SecureneighborEntry *tmp = current; // prev unchanged
                    current = current->next;
                    MEM_free(tmp);
                    --(neighborTable->size);
                }
                else
                {
                    prev = current;
                    current = current->next;
                }
            }

            // Reestablish the neighborhood.
            // Send HELLO
            if (secureneighbor->doCertifiedHello)
            {
                SecureNeighborBroadcastHelloMessage(
                    node,
                    TRUE);
            }
            else
            {
                SecureNeighborBroadcastHelloMessage(
                    node,
                    FALSE);
            }

            // Renew the timer
            MESSAGE_Send(
                node,
                msg,
                secureneighbor->neighborTimeout +
                ((int)(RANDOM_erand(secureneighbor->seed)
                       * SECURENEIGHBOR_BROADCAST_JITTER)) * MILLI_SECOND);
            break;
        }

        case MSG_CRYPTO_Overhead:
        {
            if (DEBUG >= 4)
            {
                char clockStr[MAX_STRING_LENGTH];

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u finishes SECURENEIGHBOR crypto operations "
                       "at time %s\n", node->nodeId, clockStr);
            }

            SecureneighborCryptoOverheadType infoType;

            memcpy(&infoType,
                   MESSAGE_ReturnInfo(msg),
                   sizeof(SecureneighborCryptoOverheadType));

            switch (infoType.packetType)
            {
                case SND_HELLO:
                case SND_CERTIFIED_HELLO:
                {
                    SecureneighborHandleHello(node,
                                              msg,
                                              infoType.srcAddr,
                                              infoType.ttl,
                                              infoType.interfaceIndex);
                    break;
                }
                case SND_CHALLENGE:
                case SND_CERTIFIED_CHALLENGE:
                case SND_RESPONSE1:
                case SND_RESPONSE2:
                {
                    SecureneighborHandleChallengeResponse(
                        node,
                        msg,
                        infoType.srcAddr,
                        infoType.ttl,
                        infoType.interfaceIndex);
                    break;
                }
                default: {
                    ERROR_Assert(FALSE, "Secureneighbor: "
                                 "Unknown crypto overhead type!\n");
                    break;
                }
            }
            MESSAGE_Free(node, msg);
            break;
        }

        default: {
            ERROR_Assert(FALSE, "Secureneighbor: Unknown MSG type!\n");
            break;
        }
    }
}
