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
#include <stdlib.h>
#include <string.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#include <sys/time.h>
#ifdef __APPLE__
#include <ifaddrs.h>
#include <net/if_dl.h>
#endif
#else // windows
#include "iphlpapi.h"
#include <sys/timeb.h>
#endif

#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
//#define DELTA_EPOCH_IN_MICROSECS  11644300800000000
#else
  #define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif

#include "api.h"
#include "partition.h"
#include "ipv6.h"
#include "external.h"
#include "external_util.h"
#include "qualnet_error.h"
#include "record_replay.h"
#include "packet_validation.h"
#include "packet_analyzer.h"
#include "WallClock.h"

#include "gui.h"


RecordReplayInterface::RecordReplayInterface ()
{
   recordMode = FALSE;
   replayMode = FALSE;
   recordFile = NULL;
   replayFile = NULL;
   partition = NULL;
}

RecordReplayInterface::~RecordReplayInterface ()
{
    if (recordFile)
    {
        fclose(recordFile);
    }

    if (replayFile)
    {
        fclose(replayFile);
    }
}

void RecordReplayInterface::Initialize(PartitionData* partitionData)
{
    char buf[MAX_STRING_LENGTH];
    BOOL wasFound;

    this->partition = partitionData;
    
    // Read the record parameter value from the config file
    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        partitionData->nodeInput,
        "EXATA-RECORD",
        &wasFound,
        buf);

     if (wasFound)
     {
        if (strcmp(buf, "YES") == 0)
        {
            recordMode = TRUE;
        }
        else if (strcmp(buf, "NO") != 0)
        {
            ERROR_ReportError("Invalid Value for RECORD Parameter."
                "Should be YES or NO.\n");
        }
     }

    // Read the record parameter value from the config file
    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        partitionData->nodeInput,
        "EXATA-REPLAY",
        &wasFound,
        buf);

     if (wasFound)
     {
        if (strcmp(buf, "YES") == 0)
        {
            replayMode = TRUE;
        }
        else if (strcmp(buf, "NO") != 0)
        {
            ERROR_ReportError("Invalid Value for REPLAY Parameter."
                "Should be YES or NO.\n");
        }

     }

     if (partition->partitionId != partition->masterPartitionForCluster)
     {
        return;
     }

     if (recordMode)
     {
         InitializeRecordInterface(partitionData->nodeInput);
     }

     if (replayMode)
     {
         InitializeReplayInterface(partitionData->nodeInput);
     }

}

void RecordReplayInterface::InitializeReplayInterface(
    const NodeInput* nodeInput)
{
    Message* msg = NULL;
    size_t amt_read;
    char buf[BIG_STRING_LENGTH];
    BOOL retVal;
    char verStr[21];
    if (!replayMode)
    {
        return;
    }

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "EXATA-REPLAY-FILE",
        &retVal,
        buf);

    ERROR_Assert(retVal, "REPLAY-FILE not specified "
        "while running in replay mode.");

    replayFile = fopen (buf, "rb");

    if (replayFile == NULL) 
    {
        perror ("Error opening dump file to read\n");
        return;
    }
    amt_read = fread(verStr, 21, 1, replayFile);
    if (strcmp(verStr,"EXATA-RECORD-FILE-V1")==0)
    {
        version = REPLAY_FILE_VERSION_V1;
    }
    else
    {
        version = REPLAY_FILE_VERSION_V0;
        rewind(replayFile);
    }
    SendTimerMsg(msg);
}

void RecordReplayInterface::SendTimerMsg(Message *replayInfoMsg)
{
    size_t amt_read;
    char type;
    char* finalpayload = NULL;

    ERROR_Assert(replayFile != NULL, "Replay file should not be null");
    if (version == REPLAY_FILE_VERSION_V1)
    {
        amt_read = fread(&type, 1, sizeof(UInt8), replayFile);
    }
    else
    {
        type = IPVERSION4;
    }
    if (type == IPVERSION4)
    {
        RecordFileHeader hdr;
        char* ipOptions = NULL;
        ReplayInfo* replayInfo;
        amt_read = fread((char*)&hdr, 1, sizeof(hdr), replayFile);

        if (amt_read != sizeof(hdr))
        {
            //either error occured or end of file was reached
            if (ferror (replayFile))
            {
                 perror ("Error reading from dump file\n");
                 return;
            }
            else if (feof(replayFile))
            {
                 //end of file has been reached
                MESSAGE_Free(partition->firstNode, replayInfoMsg);
                return;
            }
        }


        if (hdr.eventType == MSG_NodeJoin || hdr.eventType == MSG_NodeLeave)
        {
            // There is no payload for these events.
        }
        else if (hdr.eventType == MSG_PacketIn)
        {
            if (hdr.ipHeaderLength > sizeof(IpHeaderType))
            {
                ipOptions =
                   (char*)malloc(hdr.ipHeaderLength - sizeof(IpHeaderType));
                amt_read = fread((char*)ipOptions,
                                 1,
                                 hdr.ipHeaderLength - sizeof(IpHeaderType),
                                 replayFile);
                if (amt_read != (hdr.ipHeaderLength - sizeof(IpHeaderType)))
                {
                    perror ("Error reading from dump file\n");
                    return;
                }
            }
            finalpayload = (char*)malloc(hdr.payloadSize);
            amt_read = fread((char*)finalpayload,
                             1,
                             hdr.payloadSize,
                             replayFile);
            if (amt_read != hdr.payloadSize)
            {
                perror ("Error reading from dump file\n");
                return;
            }
        }
        else if (hdr.eventType == MSG_PacketOut)
        {
            //No need to send a timer for this kind of message,
            //so just set the timer for the next packet and return
            if (hdr.ipHeaderLength > sizeof(IpHeaderType))
            {
                ipOptions =
                   (char*)malloc(hdr.ipHeaderLength - sizeof(IpHeaderType));
                amt_read = fread((char*)ipOptions,
                                 1,
                                 hdr.ipHeaderLength - sizeof(IpHeaderType),
                                 replayFile);
                if (amt_read != (hdr.ipHeaderLength - sizeof(IpHeaderType)))
                {
                    perror ("Error reading from dump file\n");
                    return;
                }
            }
            finalpayload = (char*)malloc(hdr.payloadSize);
            amt_read = fread((char*)finalpayload,
                             1,
                             hdr.payloadSize,
                             replayFile);
            if (amt_read != hdr.payloadSize)
            {
                perror ("Error reading from dump file\n");
                return;
            }
            SendTimerMsg(replayInfoMsg);

            return;
        }
        else
        {
            ERROR_ReportError("Corrupted replay file. Aborting");
        }

        //Send the timer msg
        if (replayInfoMsg == NULL)
        {
            replayInfoMsg = MESSAGE_Alloc(partition->firstNode,
                                          EXTERNAL_LAYER,
                                          EXTERNAL_RECORD_REPLAY,
                                          hdr.eventType);

            replayInfo = (ReplayInfo*)MESSAGE_InfoAlloc(
                                   partition->firstNode,
                                   replayInfoMsg,
                                   sizeof(ReplayInfo));
        }

        replayInfoMsg->eventType = (short)hdr.eventType;
        replayInfo = (ReplayInfo*)MESSAGE_ReturnInfo(replayInfoMsg);

        memset(replayInfo, 0 , sizeof(ReplayInfo));
        replayInfo->interfaceAddress = hdr.interfaceAddress; 
        replayInfo->delay = hdr.delay;
        replayInfo->srcAddr = hdr.srcAddr;
        replayInfo->destAddr = hdr.destAddr;
        replayInfo->identification = hdr.identification;
        replayInfo->dontFragment = hdr.dontFragment;
        replayInfo->moreFragments = hdr.moreFragments;
        replayInfo->fragmentOffset = hdr.fragmentOffset;
        replayInfo->tos = hdr.tos;
        replayInfo->protocol = hdr.protocol;
        replayInfo->ttl = hdr.ttl;
        replayInfo->payloadSize = hdr.payloadSize;
        replayInfo->ipHeaderLength = hdr.ipHeaderLength;
        replayInfo->nextHopAddr = hdr.nextHopAddr;
        replayInfo->payload = (char*)MEM_malloc(hdr.payloadSize);
        memset(replayInfo->payload, 0, hdr.payloadSize);
        if (hdr.payloadSize != 0 && replayInfo->payload == NULL)
        {
            ERROR_ReportError("Sufficient memory could not be allocated");
        }

        if (finalpayload != NULL)
        {
            memcpy(replayInfo->payload, finalpayload, hdr.payloadSize);
            free(finalpayload);
        }

        if (hdr.ipHeaderLength > sizeof(IpHeaderType))
        {
            replayInfo->ipOptions = (char*)realloc(replayInfo->ipOptions,
                                        hdr.ipHeaderLength - sizeof(IpHeaderType));
            if (replayInfo->ipOptions == NULL)
            {
                ERROR_ReportError("Sufficient memory could not be allocated");
            }
            memcpy(replayInfo->ipOptions,
                   ipOptions,
                   hdr.ipHeaderLength - sizeof(IpHeaderType));
            free(ipOptions);
        }
        else
        {
            if (replayInfo->ipOptions != NULL)
            {
                free(replayInfo->ipOptions);
                replayInfo->ipOptions = NULL;
            }
        }
        EXTERNAL_MESSAGE_SendAnyNode(partition,
                           partition->firstNode,
                           replayInfoMsg,
                           hdr.timestamp - partition->firstNode->getNodeTime(),
                           EXTERNAL_SCHEDULE_LOOSELY);
    }
    else
    {
        RecordIPv6FileHeader hdr;
        IPv6ReplayInfo* replayInfo = NULL;
        amt_read = fread((char*)&hdr, 1, sizeof(hdr), replayFile);

        if (amt_read != sizeof(hdr))
        {
            //either error occured or end of file was reached
            if (ferror (replayFile))
            {
                 perror ("Error reading from dump file\n");
                return;
            }
            else if (feof(replayFile))
            {
                 //end of file has been reached
                MESSAGE_Free(partition->firstNode, replayInfoMsg);
                return;
            }
        }


        if (hdr.eventType == MSG_IPv6NodeJoin
            || hdr.eventType == MSG_IPv6NodeLeave)
        {
            // There is no payload for these events.
        }
        else if (hdr.eventType == MSG_IPv6PacketIn)
        {
            finalpayload = (char*)malloc(hdr.payloadSize);
            amt_read = fread((char*)finalpayload,
                             1,
                             hdr.payloadSize,
                             replayFile);
            if (amt_read != hdr.payloadSize)
            {
                perror ("Error reading from dump file\n");
                return;
            }
        }
        else if (hdr.eventType == MSG_PacketOut)
        {
            //No need to send a timer for this kind of message,
            //so just set the timer for the next packet and return
            finalpayload = (char*)malloc(hdr.payloadSize);
            amt_read = fread((char*)finalpayload,
                             1,
                             hdr.payloadSize,
                             replayFile);
            if (amt_read != hdr.payloadSize)
            {
                perror ("Error reading from dump file\n");
                return;
            }
            SendTimerMsg(replayInfoMsg);

            return;
        }
        else
        {
            ERROR_ReportError("Corrupted replay file. Aborting");
        }

        //Send the timer msg
        if (replayInfoMsg == NULL)
        {
            replayInfoMsg = MESSAGE_Alloc(partition->firstNode,
                EXTERNAL_LAYER,
                EXTERNAL_RECORD_REPLAY,
                hdr.eventType);

            replayInfo = (IPv6ReplayInfo*)MESSAGE_InfoAlloc(
                partition->firstNode,
                replayInfoMsg,
                sizeof(IPv6ReplayInfo));
        }
        replayInfoMsg->eventType = (short)hdr.eventType;
        replayInfo = (IPv6ReplayInfo*)MESSAGE_ReturnInfo(replayInfoMsg);

        memset(replayInfo, 0 , sizeof(IPv6ReplayInfo));
        replayInfo->interfaceAddress = hdr.interfaceAddress; 
        replayInfo->delay = hdr.delay;
        replayInfo->srcAddr = hdr.srcAddr;
        replayInfo->destAddr = hdr.destAddr;
        replayInfo->tos = hdr.tos;
        replayInfo->protocol = hdr.protocol;
        replayInfo->hlim = hdr.hlim;
        replayInfo->payloadSize = hdr.payloadSize;
        replayInfo->payload = (char*)MEM_malloc(hdr.payloadSize);
        memset(replayInfo->payload, 0, hdr.payloadSize);
        if (hdr.payloadSize != 0 && replayInfo->payload == NULL)
        {
            ERROR_ReportError("Sufficient memory could not be allocated");
        }

        if (finalpayload != NULL)
        {
            memcpy(replayInfo->payload, finalpayload, hdr.payloadSize);
            free(finalpayload);
        }

        EXTERNAL_MESSAGE_SendAnyNode(
        partition,
        partition->firstNode,
        replayInfoMsg,
        hdr.timestamp - partition->firstNode->getNodeTime(),
        EXTERNAL_SCHEDULE_LOOSELY);
    }

    //Once this timer expires, call sendtimermsg again
}

void RecordReplayInterface::ReplayProcessTimerEvent(Node* node, Message* msg)
{
    switch(msg->eventType)
    {
        case MSG_PacketIn:
        {
            ReplayInfo* replayInfo;
            replayInfo = (ReplayInfo*)MESSAGE_ReturnInfo(msg);
            NodeAddress nodeId;
            Node* virtualNode;
            Message* sendMessage;
            EXTERNAL_NetworkLayerPacket* truePacket;

            // Get source node
            nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                partition->firstNode,
                replayInfo->interfaceAddress);
            assert(nodeId != INVALID_MAPPING);
            virtualNode = MAPPING_GetNodePtrFromHash(
                partition->nodeIdHash,
                nodeId);
#ifdef PARALLEL //Parallel
            if (virtualNode == NULL)
            {
                // The source is on a remote partition.
                virtualNode = MAPPING_GetNodePtrFromHash(
                    partition->remoteNodeIdHash,
                    nodeId);
            }
#endif //Parallel
            assert(virtualNode != NULL);

/*#ifdef EXATA
    //Itroduce packet drop probability
    if (partition->dropProbExt !=-1)
    {
        RandomSeed seed;
        RANDOM_SetSeed(seed,
            partition->firstNode->globalSeed,
            partition->firstNode->nodeId,
            0, (unsigned int)time(NULL));

        if (EXTERNAL_CheckDrop(partition->dropProbExt, seed))
        {
            return;
        }
    }
#endif*/
            sendMessage = MESSAGE_Alloc(
                partition->firstNode,
                EXTERNAL_LAYER,
                0,
                MSG_EXTERNAL_SendPacket);
            sendMessage->isEmulationPacket = true;

            // Add EXTERNAL_NetworkLayerPacket info to send message
            truePacket = (EXTERNAL_NetworkLayerPacket*) MESSAGE_AddInfo(
                                        partition->firstNode,
                                        sendMessage,
                                        sizeof(EXTERNAL_NetworkLayerPacket),
                                        INFO_TYPE_ExternalData);

            truePacket->srcAddr.networkType = NETWORK_IPV4;

            // Handling the case when the source of the packet is not a node
            // in QualNet
            if (replayInfo->interfaceAddress)
            {
                truePacket->srcAddr.interfaceAddr.ipv4
                                             = replayInfo->interfaceAddress;
            }
            else
            {
                truePacket->srcAddr.interfaceAddr.ipv4 = replayInfo->srcAddr;
            }
            // Create the data portion of the packet.  If the payload is NULL
            // then send 0's.
            if (replayInfo->protocol == IPPROTO_UDP)
            {
                MESSAGE_PacketAlloc(
                        partition->firstNode,
                        sendMessage,
                        replayInfo->payloadSize,
                        TRACE_UDP);
                 if (NetworkIpIsMulticastAddress(partition->firstNode,
                                                 replayInfo->destAddr))
                 {
                    sendMessage->originatingProtocol = TRACE_MCBR;
                 }
            }
            else if (replayInfo->protocol == IPPROTO_ICMP)
            {
                MESSAGE_PacketAlloc(
                        partition->firstNode,
                        sendMessage,
                        replayInfo->payloadSize,
                        TRACE_ICMP);
            }
            else
            {
                MESSAGE_PacketAlloc(
                        partition->firstNode,
                        sendMessage,
                        replayInfo->payloadSize,
                        TRACE_FORWARD);
            }


            memcpy(MESSAGE_ReturnPacket(sendMessage),
                   replayInfo->payload,
                   replayInfo->payloadSize);

            if (replayInfo->ipHeaderLength > sizeof(IpHeaderType))
            {
                NetworkIpAddHeaderWithOptions(
                        partition->firstNode,
                        sendMessage,
                        replayInfo->srcAddr,
                        replayInfo->destAddr,
                        replayInfo->tos,
                        replayInfo->protocol,
                        replayInfo->ttl,
                        replayInfo->ipHeaderLength,
                        replayInfo->ipOptions);
            }
            else
            {
                // Create the IP header
                NetworkIpAddHeader(
                        partition->firstNode,
                        sendMessage,
                        replayInfo->srcAddr,
                        replayInfo->destAddr,
                        replayInfo->tos,
                        replayInfo->protocol,
                        replayInfo->ttl);
            }

            // Set additional ip parameters
            IpHeaderType* qualnetIp =
                          (IpHeaderType*) MESSAGE_ReturnPacket(sendMessage);
            qualnetIp->ip_id = replayInfo->identification;

            // Handle fragmentation/offset if necessary
            IpHeaderSetIpDontFrag(&(qualnetIp->ipFragment),
                                  replayInfo->dontFragment);
            IpHeaderSetIpMoreFrag(&(qualnetIp->ipFragment),
                                  replayInfo->moreFragments);
            IpHeaderSetIpFragOffset(&(qualnetIp->ipFragment),
                                     replayInfo->fragmentOffset);
#ifdef EXATA
            if (replayInfo->nextHopAddr != INVALID_ADDRESS)
            {
                NodeAddress* headers;
                MESSAGE_AddHeader(virtualNode, sendMessage, sizeof(NodeAddress) * 3, TRACE_IP);
                headers = (NodeAddress *)MESSAGE_ReturnPacket(sendMessage);
                headers[0] = replayInfo->interfaceAddress;
                headers[1] = replayInfo->destAddr;
                headers[2] = replayInfo->nextHopAddr;
            }
#endif

            EXTERNAL_MESSAGE_SendAnyNode(
                partition,
                virtualNode,
                sendMessage,
                replayInfo->delay,
                EXTERNAL_SCHEDULE_LOOSELY);
            /*if (!EXTERNAL_IsInWarmup(partition))
            {
                // Send the message.  Will be processed by IPNESendTrueEmulationPacket.
                EXTERNAL_MESSAGE_SendAnyNode(
                    partition,
                    node,
                    sendMessage,
                    delay,
                    EXTERNAL_SCHEDULE_LOOSELY);
            }
            else
            {
                BOOL wasPktDropped;
                EXTERNAL_SendDataDuringWarmup (iface, node, 
                    MESSAGE_Duplicate(node, sendMessage), &wasPktDropped);
                if (wasPktDropped)
                {
                    MESSAGE_Free(node, sendMessage);
                }
            }*/

            SendTimerMsg(msg);
            break;
        }
        case MSG_IPv6PacketIn:
        {
            IPv6ReplayInfo* replayInfo = NULL;
            replayInfo = (IPv6ReplayInfo*)MESSAGE_ReturnInfo(msg);
            NodeAddress nodeId;
            Node* virtualNode;
            Message* sendMessage = NULL;
            EXTERNAL_NetworkLayerPacket* truePacket = NULL;
            bool found = false;

            // Get source node
            nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                partition->firstNode,
                replayInfo->interfaceAddress);
            ERROR_Assert(nodeId != INVALID_MAPPING, "Invalid Mapping");

            found = PARTITION_ReturnNodePointer(partition,
                                                &virtualNode,
                                                nodeId,
                                                TRUE);
            ERROR_Assert(virtualNode != NULL ,
                         "Virtual node should not be null");

            sendMessage = MESSAGE_Alloc(partition->firstNode,
                                        EXTERNAL_LAYER,
                                        0,
                                        MSG_EXTERNAL_SendPacket);
            sendMessage->isEmulationPacket = true;

            // Add EXTERNAL_NetworkLayerPacket info to send message
            truePacket = (EXTERNAL_NetworkLayerPacket*) MESSAGE_AddInfo(
                                        partition->firstNode,
                                        sendMessage,
                                        sizeof(EXTERNAL_NetworkLayerPacket),
                                        INFO_TYPE_ExternalData);

            if (replayInfo->interfaceAddress.interfaceAddr.ipv6.s6_addr)
            {
                truePacket->srcAddr = replayInfo->interfaceAddress;
            }
            else
            {
                truePacket->srcAddr = replayInfo->srcAddr;
            }

            // Create the data portion of the packet.  If the payload is NULL
            // then send 0's.

            if (replayInfo->protocol == IPPROTO_UDP)
            {
                MESSAGE_PacketAlloc(partition->firstNode,
                                    sendMessage,
                                    replayInfo->payloadSize,
                                    TRACE_UDP);
                if (IS_MULTIADDR6(replayInfo->destAddr.interfaceAddr.ipv6))
                {
                    sendMessage->originatingProtocol= TRACE_MCBR;
                }
            }
            else if (replayInfo->protocol == IPPROTO_ICMPV6)
            {
                MESSAGE_PacketAlloc(partition->firstNode,
                                    sendMessage,
                                    replayInfo->payloadSize,
                                    TRACE_ICMPV6);
            }
            else
            {
                MESSAGE_PacketAlloc(partition->firstNode,
                                    sendMessage,
                                    replayInfo->payloadSize,
                                    TRACE_FORWARD);
            }


            memcpy(MESSAGE_ReturnPacket(sendMessage),
                                        replayInfo->payload,
                                        replayInfo->payloadSize);

            EXTERNAL_AddHdr(partition->firstNode,
                   sendMessage,
                   replayInfo->payloadSize,
                   replayInfo->srcAddr.interfaceAddr.ipv6.s6_addr,
                   replayInfo->destAddr.interfaceAddr.ipv6.s6_addr,
                   replayInfo->tos,
                   replayInfo->protocol,
                   replayInfo->hlim);

            EXTERNAL_MESSAGE_SendAnyNode(partition,
                                         virtualNode,
                                         sendMessage,
                                         replayInfo->delay,
                                         EXTERNAL_SCHEDULE_LOOSELY);

            SendTimerMsg(msg);

            break;
        }
        case MSG_NodeJoin:
        {
             ReplayInfo* replayInfo;
             replayInfo = (ReplayInfo*)MESSAGE_ReturnInfo(msg);
             NodeAddress nodeId;
             Node* virtualNode;
             int interfaceIndex;
             nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                partition->firstNode,
                                replayInfo->interfaceAddress);
             if (nodeId == INVALID_ADDRESS)
             {
                 char errMsg[MAX_STRING_LENGTH];
                 sprintf(errMsg,
                         "Invalid virtual node address: %x\n",
                         replayInfo->interfaceAddress);
                 ERROR_ReportWarning(errMsg);
                 return;
             }

             virtualNode = MAPPING_GetNodePtrFromHash(partition->nodeIdHash,
                                                      nodeId);
             if (virtualNode == NULL)
             {
                 virtualNode =
                     MAPPING_GetNodePtrFromHash(partition->remoteNodeIdHash,
                                                                    nodeId);
                 if (virtualNode == NULL)
                 {
                     char errMsg[MAX_STRING_LENGTH];
                     sprintf(errMsg,
                         "Invalid virtual node address: %x or nodeId: %d\n",
                         replayInfo->interfaceAddress, nodeId);
                     ERROR_ReportWarning(errMsg);
                     return;
                 }
             }

             interfaceIndex =
                 MAPPING_GetInterfaceIndexFromInterfaceAddress(virtualNode,
                                              replayInfo->interfaceAddress);

             if (virtualNode->partitionId !=
                                    virtualNode->partitionData->partitionId)
             {
                 Message* setInterfaceMsg = MESSAGE_Alloc(virtualNode,
                                              EXTERNAL_LAYER,
                                              EXTERNAL_RECORD_REPLAY,
                                              MSG_SetReplayInterface);
                 MESSAGE_SetInstanceId(setInterfaceMsg, interfaceIndex);
                 EXTERNAL_MESSAGE_SendAnyNode(partition,
                                              virtualNode,
                                              setInterfaceMsg,
                                              0,
                                              EXTERNAL_SCHEDULE_SAFE);
             }
             else
             {
                 virtualNode->macData[interfaceIndex]->isReplayInterface =
                                                                       TRUE;
             }
             
             SendTimerMsg(msg);
             break;
        }
        case MSG_IPv6NodeJoin:
        {
             IPv6ReplayInfo* replayInfo;
             replayInfo = (IPv6ReplayInfo*)MESSAGE_ReturnInfo(msg);
             NodeAddress nodeId;
             Node* virtualNode;
             int interfaceIndex;
             nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                              partition->firstNode,
                                              replayInfo->interfaceAddress);
             if (nodeId == INVALID_ADDRESS)
             {
                 char errMsg[MAX_STRING_LENGTH];
                 char addrStr[MAX_STRING_LENGTH];
                 IO_ConvertIpAddressToString(&replayInfo->interfaceAddress,
                                             addrStr);
                 sprintf(errMsg,
                         "Invalid virtual node address: %s\n",
                         addrStr);
                 ERROR_ReportWarning(errMsg);
                 return;
             }

             virtualNode = MAPPING_GetNodePtrFromHash(partition->nodeIdHash,
                                                      nodeId);
             if (virtualNode == NULL)
             {
                 virtualNode =
                     MAPPING_GetNodePtrFromHash(partition->remoteNodeIdHash,
                                                nodeId);
                 if (virtualNode == NULL)
                 {
                     char errMsg[MAX_STRING_LENGTH];
                     char addrStr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(
                                             &replayInfo->interfaceAddress,
                                             addrStr);
                     sprintf(errMsg,
                         "Invalid virtual node address: %s or nodeId: %d\n",
                         addrStr,
                         nodeId);
                     ERROR_ReportWarning(errMsg);
                     return;
                 }
             }

             interfaceIndex =
                  MAPPING_GetInterfaceIndexFromInterfaceAddress(virtualNode,
                                              replayInfo->interfaceAddress);

             if (virtualNode->partitionId !=
                                    virtualNode->partitionData->partitionId)
             {
                 Message *setInterfaceMsg = MESSAGE_Alloc(virtualNode,
                                                    EXTERNAL_LAYER,
                                                    EXTERNAL_RECORD_REPLAY,
                                                    MSG_SetReplayInterface);
                 MESSAGE_SetInstanceId(setInterfaceMsg, interfaceIndex);
                 EXTERNAL_MESSAGE_SendAnyNode(partition,
                     virtualNode, setInterfaceMsg, 0, EXTERNAL_SCHEDULE_SAFE);
             }
             else
             {
                 virtualNode->macData[interfaceIndex]->isReplayInterface =
                                                                       TRUE;
             }
             
             SendTimerMsg(msg);
             break;
        }
        case MSG_NodeLeave:
        {
             ReplayInfo* replayInfo;
             replayInfo = (ReplayInfo*)MESSAGE_ReturnInfo(msg);
             NodeAddress nodeId;
             Node* virtualNode;
             int interfaceIndex;
             nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                              partition->firstNode,
                                              replayInfo->interfaceAddress);
             if (nodeId == INVALID_ADDRESS)
             {
                 char errMsg[MAX_STRING_LENGTH];
                 sprintf(errMsg,
                         "Invalid virtual node address: %x\n",
                         replayInfo->interfaceAddress);
                 ERROR_ReportWarning(errMsg);
                 return;
             }

             virtualNode = MAPPING_GetNodePtrFromHash(partition->nodeIdHash,
                                                      nodeId);
             if (virtualNode == NULL)
             {
                 virtualNode =
                     MAPPING_GetNodePtrFromHash(partition->remoteNodeIdHash,
                                                nodeId);
                 if (virtualNode == NULL)
                 {
                     char errMsg[MAX_STRING_LENGTH];
                     sprintf(errMsg,
                             "Invalid virtual node address: %x or nodeId: %d\n",
                             replayInfo->interfaceAddress, nodeId);
                     ERROR_ReportWarning(errMsg);
                     return;
                 }
             }

             interfaceIndex =
                 MAPPING_GetInterfaceIndexFromInterfaceAddress(virtualNode,
                                             replayInfo->interfaceAddress);

             if (virtualNode->partitionId !=
                                    virtualNode->partitionData->partitionId)
             {
                 Message* resetInterfaceMsg = MESSAGE_Alloc(virtualNode,
                                              EXTERNAL_LAYER,
                                              EXTERNAL_RECORD_REPLAY,
                                              MSG_ResetReplayInterface);
                 MESSAGE_SetInstanceId(resetInterfaceMsg,
                                       interfaceIndex);
                 EXTERNAL_MESSAGE_SendAnyNode(partition,
                                              virtualNode,
                                              resetInterfaceMsg,
                                              0,
                                              EXTERNAL_SCHEDULE_SAFE);
             }
             else
             {
                 virtualNode->macData[interfaceIndex]->isReplayInterface =
                                                                      FALSE;
             }
             SendTimerMsg(msg);
             break;
        }
        case MSG_IPv6NodeLeave:
        {
             IPv6ReplayInfo* replayInfo;
             replayInfo = (IPv6ReplayInfo*)MESSAGE_ReturnInfo(msg);
             NodeAddress nodeId;
             Node* virtualNode;
             int interfaceIndex;
             nodeId =
                 MAPPING_GetNodeIdFromInterfaceAddress(partition->firstNode,
                                              replayInfo->interfaceAddress);
             if (nodeId == INVALID_ADDRESS)
             {
                 char errMsg[MAX_STRING_LENGTH];
                 char addrStr[MAX_STRING_LENGTH];
                 IO_ConvertIpAddressToString(&replayInfo->interfaceAddress,
                                             addrStr);
                 sprintf(errMsg,
                         "Invalid virtual node address: %s\n",
                         addrStr);
                 ERROR_ReportWarning(errMsg);
                 return;
             }

             virtualNode = MAPPING_GetNodePtrFromHash(partition->nodeIdHash,
                                                      nodeId);
             if (virtualNode == NULL)
             {
                 virtualNode =
                     MAPPING_GetNodePtrFromHash(partition->remoteNodeIdHash,
                                                nodeId);
                 if (virtualNode == NULL)
                 {
                     char errMsg[MAX_STRING_LENGTH];
                     char addrStr[MAX_STRING_LENGTH];
                     IO_ConvertIpAddressToString(
                                             &replayInfo->interfaceAddress,
                                             addrStr);
                     sprintf(errMsg,
                         "Invalid virtual node address: %s or nodeId: %d\n",
                         addrStr,
                         nodeId);
                     ERROR_ReportWarning(errMsg);
                     return;
                 }
             }

             interfaceIndex =
                 MAPPING_GetInterfaceIndexFromInterfaceAddress(virtualNode,
                                             replayInfo->interfaceAddress);

             if (virtualNode->partitionId !=
                                    virtualNode->partitionData->partitionId)
             {
                 Message* resetInterfaceMsg = MESSAGE_Alloc(virtualNode,
                                                  EXTERNAL_LAYER,
                                                  EXTERNAL_RECORD_REPLAY,
                                                  MSG_ResetReplayInterface);
                 MESSAGE_SetInstanceId(resetInterfaceMsg, interfaceIndex);
                 EXTERNAL_MESSAGE_SendAnyNode(partition,
                                              virtualNode,
                                              resetInterfaceMsg,
                                              0,
                                              EXTERNAL_SCHEDULE_SAFE);
             }
             else
             {
                 virtualNode->macData[interfaceIndex]->isReplayInterface =
                                                                      FALSE;
             }
             SendTimerMsg(msg);
             break;
        }
        case MSG_SetReplayInterface:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            node->macData[interfaceIndex]->isReplayInterface = TRUE;

            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_ResetReplayInterface:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            node->macData[interfaceIndex]->isReplayInterface = FALSE;

            MESSAGE_Free(node, msg);
            break;
        }

        default:
        {
            printf("Unknown record replay message type %d\n", msg->eventType);
            break;
            //assert(FALSE);
        }
    }

}

string RecordReplayInterface::IntToString(int num)
{
        ostringstream myStream;
        myStream << num << flush;
        return myStream.str();
}

bool IsBoeing()
{
#ifdef ADDON_BOEINGFCS
    return true;
#else
    return false;
#endif
}

void RecordReplayInterface::InitializeRecordInterface(const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    std::string dumpFileName = "";
    BOOL retVal;
    struct stat buffer;
    int status;
    time_t now;
    int x = 1;
    char verStr[21] = "EXATA-RECORD-FILE-V1";

    if (!recordMode)
    {
        return;
    }

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "EXPERIMENT-NAME",
        &retVal,
        buf);
    
    if (retVal)
    {
        dumpFileName += buf;
        dumpFileName += "_dump.bin";

    }
    else 
    {
        if (IsBoeing())
        {
            strcpy(buf, "ces");
        }
        else
        {
#ifdef EXATA
            strcpy(buf, "exata");
#else
            strcpy(buf, "qualnet");
#endif // EXATA
        }
        dumpFileName += buf;
        dumpFileName += "_dump.bin";
    }

    status = stat(dumpFileName.c_str(), &buffer);

    while (status == 0)
    {
        dumpFileName = buf;
        dumpFileName += "_dump_" + IntToString(x) + ".bin";
        status = stat(dumpFileName.c_str(), &buffer);
        x++;
    }

    recordFile = fopen (dumpFileName.c_str(), "wb");

    if (recordFile == NULL) 
    {
        perror ("Error opening dump file to write\n");
        return;
    }
    fwrite(verStr, 21, 1, recordFile);
}

#ifdef _WIN32

int RecordReplayInterface::getTimeOfDayWin(TimeValue *tv, TimeZone *tz)
{
  FILETIME ft;
  unsigned __int64 tmpres = 0;
  static int tzflag;
 
  if (NULL != tv)
  {
    GetSystemTimeAsFileTime(&ft);
 
    tmpres |= ft.dwHighDateTime;
    tmpres <<= 32;
    tmpres |= ft.dwLowDateTime;
 
    tmpres /= 10;  //convert into microseconds
    //converting file time to unix epoch
    tmpres -= DELTA_EPOCH_IN_MICROSECS; 
    
    tv->tv_sec = (tmpres / 1000000);
    tv->tv_usec = (tmpres % 1000000);
  }
 
  if (NULL != tz)
  {
    if (!tzflag)
    {
      _tzset();
      tzflag++;
    }
    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }
 
  return 0;
}
#endif

void RecordReplayInterface::RecordAddVirtualHost(NodeAddress virtualNodeAddress)
{
    RecordFileHeader header = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    UInt8 type = IPVERSION4;

    if (this->partition->partitionId != this->partition->masterPartitionForCluster)
    {
        return;
    }
    if (!recordMode)
    {
        return;
    }
    fwrite(&type, sizeof(UInt8), 1, recordFile);
    header.eventType = MSG_NodeJoin;
    header.timestamp = partition->firstNode->getNodeTime();
    header.interfaceAddress = virtualNodeAddress;
    ERROR_Assert(recordFile != NULL, "Record file can not be null");
    fwrite(&header, sizeof(header), 1, recordFile);
    fflush(recordFile);
}

// /**
// API       :: RecordAddIPv6VirtualHost
// PURPOSE   :: This function records information when an ipv6 host is mapped
//              to an physical address
// PARAMETERS::
// + virtualNodeAddress : Address : IPv6 address of virtual host
// RETURN    :: void
// **/
void RecordReplayInterface::RecordAddIPv6VirtualHost(
                                                 Address virtualNodeAddress)
{
    RecordIPv6FileHeader header;
    memset(&header, 0, sizeof(RecordIPv6FileHeader));
    UInt8 type = IPV6_VERSION;

    if (this->partition->partitionId !=
                                 this->partition->masterPartitionForCluster)
    {
        return;
    }
    if (!recordMode)
    {
        return;
    }
    fwrite(&type, sizeof(UInt8), 1, recordFile);
    header.eventType = MSG_IPv6NodeJoin;
    header.timestamp = partition->firstNode->getNodeTime();
    header.interfaceAddress = virtualNodeAddress;
    ERROR_Assert(recordFile != NULL, "Record file can not be null");
    fwrite(&header, sizeof(header), 1, recordFile);
    fflush(recordFile);
}

void RecordReplayInterface::RecordRemoveVirtualHost(NodeAddress virtualNodeAddress)
{
    
    RecordFileHeader header = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    UInt8 type = IPVERSION4;
    if (this->partition->partitionId != this->partition->masterPartitionForCluster)
    {
        return;
    }
    if (!recordMode)
    {
        return;
    }
    fwrite(&type, sizeof(UInt8), 1, recordFile);
    header.eventType = MSG_NodeLeave;
    header.timestamp = partition->firstNode->getNodeTime();
    header.interfaceAddress = virtualNodeAddress;
    ERROR_Assert(recordFile != NULL, "Record file can not be null");
    fwrite(&header, sizeof(header), 1, recordFile);
    fflush(recordFile);
}
// /**
// API       :: RecordRemoveIPv6VirtualHost
// PURPOSE   :: This function records information when an ipv6 host mapping
//              is removed
// PARAMETERS::
// + virtualNodeAddress : Address : IPv6 address of virtual host
// RETURN    :: void
// **/
void RecordReplayInterface::RecordRemoveIPv6VirtualHost(
                                                 Address virtualNodeAddress)
{
    RecordIPv6FileHeader header;
    memset(&header, 0, sizeof(RecordIPv6FileHeader));
    UInt8 type = IPV6_VERSION;
    if (this->partition->partitionId !=
                                 this->partition->masterPartitionForCluster)
    {
        return;
    }
    if (!recordMode)
    {
        return;
    }
    fwrite(&type, sizeof(UInt8), 1, recordFile);
    header.eventType = MSG_IPv6NodeLeave;
    header.timestamp = partition->firstNode->getNodeTime();
    header.interfaceAddress = virtualNodeAddress;
    ERROR_Assert(recordFile != NULL, "Record file can not be null");
    fwrite(&header, sizeof(header), 1, recordFile);
    fflush(recordFile);
}

void RecordReplayInterface::RecordHandleSniffedPacket(
        NodeAddress interfaceAddress,  //this is the from address 
        clocktype delay,
        NodeAddress srcAddr,
        NodeAddress destAddr,
        unsigned short identification,
        BOOL dontFragment,
        BOOL moreFragments,
        unsigned short fragmentOffset,
        TosType tos,
        unsigned char protocol,
        unsigned int ttl,
        char *payload,
        int payloadSize,
        NodeAddress nextHopAddr,
        int ipHeaderLength,
        char *ipOptions)
    {
        RecordFileHeader header;
        RealTimeHdr pcapheader;
        UInt8 type = IPVERSION4;
        if (this->partition->partitionId != this->partition->masterPartitionForCluster)
        {
            return;
        }
        if (!recordMode)
        {
            return;
        }
#ifdef _WIN32
        TimeValue gettimeofdayValue;
        getTimeOfDayWin(&gettimeofdayValue, NULL);
        pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
        pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#else 
        timeval gettimeofdayValue;
        gettimeofday(&gettimeofdayValue, NULL);
        pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
        pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#endif 
        fwrite(&type, sizeof(UInt8), 1, recordFile);
        pcapheader.caplen = payloadSize + LIBNET_ETH_H + LIBNET_IPV4_H;
        pcapheader.len = pcapheader.caplen;
        header.eventType = MSG_PacketIn;
        header.timestamp = partition->firstNode->getNodeTime();
        header.interfaceAddress = interfaceAddress;
        header.delay = delay;
        header.destAddr = destAddr;
        header.srcAddr = srcAddr;
        header.dontFragment = dontFragment;
        header.fragmentOffset = fragmentOffset;
        header.identification = identification;
        header.moreFragments = moreFragments;
        header.nextHopAddr = nextHopAddr;
        header.protocol = protocol;
        header.ttl = ttl;
        header.tos = tos;
        header.payloadSize = payloadSize;
        header.ipHeaderLength = ipHeaderLength;
        header.pcapheader = pcapheader;
    ERROR_Assert(recordFile != NULL, "Record file can not be null");
        fwrite(&header, sizeof(header), 1, recordFile);
        if (ipHeaderLength > sizeof(IpHeaderType))
        {
            fwrite(ipOptions, ipHeaderLength - sizeof(IpHeaderType), 1, recordFile);
        }

        fwrite(payload, payloadSize, 1, recordFile);
        fflush(recordFile);
    }

// /**
// API       :: RecordHandleIPv6SniffedPacket
// PURPOSE   :: This function records information when an packet in injected
//              into virtual node
// PARAMETERS::
// + interfaceAddress : Address : Source address
// + delay : clocktype : delay
// + srcAddr : Address : Source of the packet
// + destAddr : Address : Destination packets
// + tos : TosType : priority of packet
// + protocol : unsigned char : underlying protocol
// + hlim : unsigned : hop limit
// + payload : char* : packet payload
// + payloadsize : Int32 : size of payload
// RETURN    :: void
// **/
void RecordReplayInterface::RecordHandleIPv6SniffedPacket(
                      Address interfaceAddress,  //this is the from address 
                      clocktype delay,
                      Address srcAddr,
                      Address destAddr,
                      TosType tos,
                      unsigned char protocol,
                      unsigned hlim,
                      char* payload,
                      Int32 payloadSize)
    {
        RecordIPv6FileHeader header;
        RealTimeHdr pcapheader;
        memset(&header, 0, sizeof(RecordIPv6FileHeader));
        memset(&pcapheader, 0, sizeof(RealTimeHdr));
        UInt8 type = IPV6_VERSION;
        if (this->partition->partitionId != this->partition->masterPartitionForCluster)
        {
            return;
        }
        if (!recordMode)
        {
            return;
        }
#ifdef _WIN32
        TimeValue gettimeofdayValue;
        getTimeOfDayWin(&gettimeofdayValue, NULL);
        pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
        pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#else 
        timeval gettimeofdayValue;
        gettimeofday(&gettimeofdayValue, NULL);
        pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
        pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#endif 

        fwrite(&type, sizeof(UInt8), 1, recordFile);
        pcapheader.caplen = payloadSize + LIBNET_ETH_H + LIBNET_IPV6_H;
        pcapheader.len = pcapheader.caplen;
        header.eventType = MSG_IPv6PacketIn;
        header.timestamp = partition->firstNode->getNodeTime();
        header.interfaceAddress = interfaceAddress;
        header.delay = delay;
        header.destAddr = destAddr;
        header.srcAddr = srcAddr;
        header.protocol = protocol;
        header.hlim = hlim;
        header.tos = tos;
        header.payloadSize = payloadSize;
        header.pcapheader = pcapheader;
        ERROR_Assert(recordFile != NULL, "Record file can not be null");
        fwrite(&header, sizeof(header), 1, recordFile);

        fwrite(payload, payloadSize, 1, recordFile);
        fflush(recordFile);
    }

void RecordReplayInterface::RecordOutgoingPacket(
        NodeAddress interfaceAddress,  //this is the from address 
        clocktype delay,
        NodeAddress srcAddr,
        NodeAddress destAddr,
        unsigned short identification,
        BOOL dontFragment,
        BOOL moreFragments,
        unsigned short fragmentOffset,
        TosType tos,
        unsigned char protocol,
        unsigned int ttl,
        char * payload,
        int payloadSize,
        NodeAddress prevHopAddr,
        int ipHeaderLength,
        char *ipOptions)
    {
        RecordFileHeader header;
        RealTimeHdr pcapheader;
        UInt8 type = IPVERSION4;


        if (this->partition->partitionId != this->partition->masterPartitionForCluster)
        {
            return;
        }
        if (!recordMode)
        {
            return;
        }

#ifdef _WIN32
    TimeValue gettimeofdayValue;
    getTimeOfDayWin(&gettimeofdayValue, NULL);
    pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
    pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#else 
    timeval gettimeofdayValue;
    gettimeofday(&gettimeofdayValue, NULL);
    pcapheader.ts.tv_sec = (time_t) gettimeofdayValue.tv_sec;
    pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#endif 
        fwrite(&type, sizeof(UInt8), 1, recordFile);
        pcapheader.caplen = payloadSize + LIBNET_ETH_H + LIBNET_IPV4_H;
        pcapheader.len = pcapheader.caplen;

        header.eventType = MSG_PacketOut;
        header.timestamp = partition->firstNode->getNodeTime();
        header.interfaceAddress = interfaceAddress;
        header.delay = delay;
        header.destAddr = destAddr;
        header.srcAddr = srcAddr;
        header.dontFragment = dontFragment;
        header.fragmentOffset = fragmentOffset;
        header.identification = identification;
        header.moreFragments = moreFragments;
        header.nextHopAddr = prevHopAddr;
        header.protocol = protocol;
        header.ttl = ttl;
        header.tos = tos;
        header.payloadSize = payloadSize;
        header.ipHeaderLength = ipHeaderLength;
        header.pcapheader = pcapheader;
        ERROR_Assert(recordFile != NULL, "Record file can not be null");
        fwrite(&header, sizeof(header), 1, recordFile);
        if (ipHeaderLength > sizeof(IpHeaderType))
        {
            fwrite(ipOptions, ipHeaderLength - sizeof(IpHeaderType), 1, recordFile);
        }
        fwrite(payload, payloadSize, 1, recordFile);
        fflush(recordFile);
    }

// /**
// API       :: RecordOutgoingIPv6Packet
// PURPOSE   :: This function records information when an packet is sent 
//              to physical host
// PARAMETERS::
// + interfaceAddress : Address : Source address
// + delay : clocktype : delay
// + srcAddr : Address : Source of the packet
// + destAddr : Address : Destination packets
// + tos : TosType : priority of packet
// + protocol : unsigned char : underlying protocol
// + hlim : unsigned : hop limit
// + payload : char* : packet payload
// + payloadsize : Int32 : size of payload
// RETURN    :: void
// **/
void RecordReplayInterface::RecordOutgoingIPv6Packet(
                      Address interfaceAddress,  //this is the from address 
                      clocktype delay,
                      Address srcAddr,
                      Address destAddr,
                      TosType tos,
                      unsigned char protocol,
                      unsigned hlim,
                      char* payload,
                      Int32 payloadSize)
{
    RecordIPv6FileHeader header;
    RealTimeHdr pcapheader;
    UInt8 type = IPV6_VERSION;


    if (this->partition->partitionId != this->partition->masterPartitionForCluster)
    {
     return;
    }
    if (!recordMode)
    {
        return;
    }

#ifdef _WIN32
    TimeValue gettimeofdayValue;
    getTimeOfDayWin(&gettimeofdayValue, NULL);
    pcapheader.ts.tv_sec = gettimeofdayValue.tv_sec;
    pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#else 
    timeval gettimeofdayValue;
    gettimeofday(&gettimeofdayValue, NULL);
    pcapheader.ts.tv_sec = (time_t) gettimeofdayValue.tv_sec;
    pcapheader.ts.tv_usec = gettimeofdayValue.tv_usec;
#endif
        fwrite(&type, sizeof(UInt8), 1, recordFile);
        pcapheader.caplen = payloadSize + LIBNET_ETH_H + LIBNET_IPV6_H;
        pcapheader.len = pcapheader.caplen;

        header.eventType = MSG_PacketOut;
        header.timestamp = partition->firstNode->getNodeTime();
        header.interfaceAddress = interfaceAddress;
        header.delay = delay;
        header.destAddr = destAddr;
        header.srcAddr = srcAddr;
        header.protocol = protocol;
        header.hlim = hlim;
        header.tos = tos;
        header.payloadSize = payloadSize;

    ERROR_Assert(recordFile != NULL, "Record file can not be null");
        fwrite(&header, sizeof(header), 1, recordFile);

        fwrite(payload, payloadSize, 1, recordFile);
        fflush(recordFile);
}


BOOL RecordReplayInterface::
ReplayForwardFromNetworkLayer(Node* node,
                              int interfaceIndex,
                              Message* msg,
                              BOOL skipCheck)
{
    UInt16 offset;
    IpHeaderType *ipHeader;
    int ipHeaderLength;

    if (!replayMode)
    {
        return FALSE;
    }
    
    ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    struct libnet_ipv4_hdr* ip = (struct libnet_ipv4_hdr*) MESSAGE_ReturnPacket(msg);

    ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;

    // Call the following code only when the node is running in context of its 
    // native partition (required since node->networkData is invalid in other partitions)
    if (node->partitionData->partitionId == node->partitionId && !skipCheck)
    {
        //Get IP proto no and Check if we need to inject this packet 
        if (CheckNetworkRoutingProtocol(node,interfaceIndex,ip->ip_p))
        {
            //printf("inside the network routing protocol code\n");
            return FALSE;
        }

        UInt8* nextHeader;
        nextHeader = ((UInt8*) ip) + ipHeaderLength;

        if (ip->ip_p == IPPROTO_TCP|| ip->ip_p == IPPROTO_UDP)
        {
            struct libnet_udp_hdr* udp;
            udp = (struct libnet_udp_hdr*) nextHeader;
            int port = udp->uh_dport;

            if (CheckApplicationRoutingProtocol(node,interfaceIndex,port))
            {
                //printf("inside the application routing protocol code\n");
                return FALSE;
            }
            if ((ip->ip_p == IPPROTO_UDP) && (udp->uh_dport == APP_MESSENGER))
            {
                return FALSE;
            }

        }
    }

    MESSAGE_Free(node,msg);
    return TRUE;

}

// /**
// API       :: ReplayForwardFromNetworkLayer
// PURPOSE   :: This function replays the behavior as if the packet is sent
//              to physical host
// PARAMETERS::
// + interfaceAddress : Address : Source address
// + delay : clocktype : delay
// + srcAddr : Address : Source of the packet
// RETURN    :: BOOL False : if packet is routing or internal control packet
//                   True : otherwise
// **/
BOOL RecordReplayInterface::
        ReplayForwardFromNetworkLayer(Node* node,
                                      int interfaceIndex,
                                      Message* msg)
{
    ip6_hdr* ipHeader = NULL;
    int ipHeaderLength = IPV6_HEADER_LENGTH;

    if (!replayMode)
    {
        return FALSE;
    }
    ipHeader = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    struct libnet_ipv6_hdr* ip =
                         (struct libnet_ipv6_hdr*)MESSAGE_ReturnPacket(msg);


    // Call the following code only when the node is running in context of its 
    // native partition (required since node->networkData is invalid in other partitions)

    UInt8* nextHeader;
    nextHeader = ((UInt8*)ip) + ipHeaderLength;

    if (node->partitionData->partitionId == node->partitionId)
    {
        //Get IP proto no and Check if we need to inject this packet
        if (CheckNetworkRoutingProtocolIpv6(node,interfaceIndex,ip->ip_nh))
        {
            //printf("inside the network routing protocol code\n");
            return FALSE;
        }

        if (ip->ip_nh == IPPROTO_ICMPV6)
        {
             struct libnet_icmpv6_hdr* icp
                 = (struct libnet_icmpv6_hdr*) (ip + 1);
             if (icp->icmp_type != ICMP6_ECHO
                 && icp->icmp_type != ICMP6_ECHOREPLY)
             {
                 return FALSE;
             }
        }
        
        // for UDP and TCP to check if we need to inject this packet
        if (ip->ip_nh == IPPROTO_TCP|| ip->ip_nh == IPPROTO_UDP)
        {
            struct libnet_udp_hdr* udp = NULL;
            udp = (struct libnet_udp_hdr*) nextHeader;
            int port = udp->uh_dport;

            if (CheckApplicationRoutingProtocolIpv6(node,
                                                    interfaceIndex,
                                                    port))
            {
                return FALSE;
            }
            if ((ip->ip_nh == IPPROTO_UDP) && (udp->uh_dport == APP_MESSENGER))
            {
                return FALSE;
            }
        }

    }

    MESSAGE_Free(node,msg);
    return TRUE;
}
