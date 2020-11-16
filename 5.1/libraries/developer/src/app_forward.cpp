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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "transport_tcp.h"
#include "tcpapps.h"
#include "app_util.h"
#include "app_forward.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif

#ifdef SOCKET_INTERFACE
#include "socket-interface.h"
#endif
#include "external_util.h"

//#define DEBUG
#define DEFAULT_UDP_TIMEOUT 15 * 60 * SECOND // 15minutes

static void HandlePacketPriorityStats(
    AppDataForward* forward,
    BOOL packetSent,
    int priority)
{
    forward->tosStats[priority]->type = priority;
    if (packetSent)
    {
        forward->tosStats[priority]->numPriorityPacketSent++;
    }
    else
    {
        forward->tosStats[priority]->numPriorityPacketReceived++;
    }
}

#ifdef ADDON_DB
// STATS DB CODE
static void UpdateStatsDb(
    Node* node,
    AppDataForward* forward,
    Message* msg,
    int msgSize,
    BOOL isTcp,
    BOOL isCompleteMsg)
{
    clocktype delay = 0;

    StatsDb* db = node->partitionData->statsDb;

    StatsDBAppEventParam* appParamInfo =
        (StatsDBAppEventParam*) MESSAGE_ReturnInfo(msg, INFO_TYPE_AppStatsDbContent);
    ERROR_Assert(appParamInfo != NULL, "Info content not found !\n");

    if (forward->isServer)
    {
        forward->clientSessionId = appParamInfo->m_SessionId;
    }
    else
    {
        forward->serverSessionId = appParamInfo->m_SessionId;
    }
    strcpy(forward->applicationName, appParamInfo->m_ApplicationName);
    forward->sessionInitiator = appParamInfo->m_SessionInitiator;

    if (!isTcp)
    {
        FORWARD_UdpFragmentData* udpFragData =
            (FORWARD_UdpFragmentData*) MESSAGE_ReturnInfo(msg, INFO_TYPE_UdpFragData);
        if (udpFragData == NULL)
        {
            ERROR_ReportWarning("Forward: Unable to find UDP Info field\n");
            return;
        }

        // this delay is same for fragment and whole message
        delay = node->getNodeTime() - udpFragData->packetCreationTime;

        if (isCompleteMsg && !node->partitionData->statsDb->statsAppEvents->recordFragment)
        {
            APP_ReportStatsDbReceiveEvent(
                node,
                msg,
                &(forward->messageIdCache),
                udpFragData->messageId,
                delay,
                forward->udpStats->actUdpJitter,
                msgSize,
                forward->udpStats->numUdpPacketsReceived);
        }
        else if (!isCompleteMsg && node->partitionData->statsDb->statsAppEvents->recordFragment)
        {
            APP_ReportStatsDbReceiveEvent(
                node,
                msg,
                &(forward->fragNoCache),
                udpFragData->uniqueFragNo,
                delay,
                forward->udpStats->actUdpFragsJitter,
                msgSize,
                forward->udpStats->numUdpFragsReceived);
        }
    }
    else
    {
        // Transmission via TCP has no issues about duplicate, out of order,
        // fragmentation etc.
        FORWARD_TcpHeaderInfo* tcpHeader =
            (FORWARD_TcpHeaderInfo*) MESSAGE_ReturnInfo(msg, INFO_TYPE_ForwardTcpHeader);
        if (tcpHeader == NULL)
        {
            ERROR_ReportWarning("Forward: Unable to find TCP Header Info field\n");
            return;
        }
        // Perform the TCP delay calculations.
        delay = node->getNodeTime() - tcpHeader->packetCreationTime;

        APP_ReportStatsDbReceiveEvent(
            node,
            msg,
            NULL,
            0,
            delay,
            forward->tcpStats->actTcpJitter,
            msgSize,
            forward->tcpStats->numTcpMsgRecd);
    }
}
#endif

// /**
// FUNCTION   :: UpdateUdpStats
// PURPOSE    :: Updates the UDP related stats for
//               forward application. The function is
//               called when a complete UDP packet is
//               received.
// PARAMETERS ::
// + node : Pointer to the node.
// + forward : Pointer to the forward application.
// + msg : Message received pointer
// RETURN     ::  Void : NULL.
// **/
static void UpdateUdpStats(
    Node* node,
    AppDataForward* forward,
    Message* msg,
    BOOL packetReceived)

{
    clocktype D = 0;
    clocktype delay = 0;
    FORWARD_UdpFragmentData* udpFragData =
        (FORWARD_UdpFragmentData*) MESSAGE_ReturnInfo(msg, INFO_TYPE_UdpFragData);
    if (udpFragData == NULL)
    {
        ERROR_ReportWarning("Forward: Unable to find UDP Info field\n");
        return;
    }
    delay = node->getNodeTime() - udpFragData->packetCreationTime;

#ifdef ADDON_DB

    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL && !packetReceived)
    {
        // Hop count data.
        StatsDBNetworkEventParam* ipParamInfo;
        ipParamInfo = (StatsDBNetworkEventParam*)
            MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

        if (ipParamInfo == NULL)
        {
            printf ("ERROR: Forward Application no Network Events Info\n");
        }
        else
        {
            forward->udpStats->hopCount += (int)ipParamInfo->m_HopCount;
            if (forward->localAddr == ANY_ADDRESS)
            {
                //TODO: Get Broadcast Hop count
            }
            else if (NetworkIpIsMulticastAddress(node, forward->localAddr))
            {
                forward->udpStats->udpMulticastHopCount +=
                    (int)ipParamInfo->m_HopCount;
            }
            else
            {
                forward->udpStats->udpUnicastHopCount +=
                    (int)ipParamInfo->m_HopCount;
            }
        }
    }
#endif
    if (packetReceived)
    {
        // Create statistics
        if (node->appData.appStats)
        {
            forward->udpStats->udpAppStats->AddMessageReceivedDataPoints(
                    node,
                    msg,
                    0,
                    udpFragData->messageSize, // unfragmented UDP msg size
                    0,
                    STAT_NodeAddressToDestAddressType(node, forward->localAddr));
        }
        forward->udpStats->numUdpPacketsReceived++;
        forward->numPacketsReceived++;
        if (forward->udpStats->lastDelayTime != EXTERNAL_MAX_TIME)
        {
            if (forward->udpStats->numUdpPacketsReceived > 1)
            {
                // Compute abs(delay difference)
                if (delay > forward->udpStats->lastDelayTime)
                {
                    D = delay - forward->udpStats->lastDelayTime;
                }
                else
                {
                    D = forward->udpStats->lastDelayTime - delay;
                }

                // Update jitter
                if (forward->udpStats->numUdpPacketsReceived == 2)
                {
                    forward->udpStats->actUdpJitter = D;
                }
                else
                {
                    forward->udpStats->actUdpJitter += (D - forward->udpStats->actUdpJitter) / 16;
                }
                if (forward->numPacketsReceived == 2)
                {
                    forward->actJitter = D;
                }
                else
                {
                    forward->actJitter += (D - forward->actJitter) / 16;
                }

                forward->jitter += forward->actJitter;
                forward->udpStats->udpJitter += forward->udpStats->actUdpJitter;
            }
        }

        // Set last delay time, used for next packet
        forward->udpStats->lastDelayTime = delay;
        forward->udpStats->udpEndtoEndDelay += delay;

        if (forward->localAddr == ANY_ADDRESS)
        {
            forward->udpStats->numUdpBroadcastPacketsReceived++;
        }
        else if (NetworkIpIsMulticastAddress(node, forward->localAddr))
        {
            forward->udpStats->numUdpMulticastPacketsReceived++;
            forward->udpStats->udpMulticastDelay += delay;
            if (forward->udpStats->numUdpMulticastPacketsReceived > 1)
            {
                if (forward->udpStats->numUdpMulticastPacketsReceived == 2)
                {
                    forward->udpStats->actUdpMulticastJitter = D;
                }
                else
                {
                    forward->udpStats->actUdpMulticastJitter += (D - forward->udpStats->actUdpMulticastJitter) / 16;
                }
                forward->udpStats->udpMulticastJitter += forward->udpStats->actUdpMulticastJitter;
            }

        }
        else
        {
            forward->udpStats->numUdpUnicastPacketsReceived++;
            forward->udpStats->udpUnicastDelay += delay;
            if (forward->udpStats->numUdpUnicastPacketsReceived > 1)
            {
                if (forward->udpStats->numUdpUnicastPacketsReceived == 2)
                {
                    forward->udpStats->actUdpUnicastJitter = D;
                }
                else
                {
                    forward->udpStats->actUdpUnicastJitter += (D - forward->udpStats->actUdpUnicastJitter) / 16;
                }
                forward->udpStats->udpUnicastJitter += forward->udpStats->actUdpUnicastJitter;
            }
        }

#ifdef DEBUG
        printf("FORWARD UDP data received (%d bytes)\n",
            msg->packetSize);
#endif
    }
#ifdef ADDON_DB
    else
    {
        // Update stats for fragments, please note, this function will be
        // called for the fragment first. And then duplicated calls for
        // for completed packets. Thus, update to fragment related stats
        // shall be only put where when  packetReceived is FALSE to avoid
        // counting one fragments twice.

        // calculate jitter for fragments
        if (forward->udpStats->numUdpFragsReceived > 1)
        {
            // Compute abs(delay difference)
            if (delay > forward->udpStats->lastFragDelayTime)
            {
                D = delay - forward->udpStats->lastFragDelayTime;
            }
            else
            {
                D = forward->udpStats->lastFragDelayTime - delay;
            }

            // Update jitter
            if (forward->udpStats->numUdpFragsReceived == 2)
            {
                forward->udpStats->actUdpFragsJitter = D;
            }
            else
            {
                forward->udpStats->actUdpFragsJitter +=
                    (D - forward->udpStats->actUdpFragsJitter) / 16;
            }
        }

        forward->udpStats->lastFragDelayTime = delay;
    }
#endif // ADDON_DB

}

static void UpdateTcpStats(
    Node* node,
    AppDataForward* forward,
    Message* msg,
    BOOL packetReceived)
{
    clocktype D;
    clocktype delay = 0;

    FORWARD_TcpHeaderInfo* tcpHeader =
        (FORWARD_TcpHeaderInfo*) MESSAGE_ReturnInfo(msg, INFO_TYPE_ForwardTcpHeader);
    if (tcpHeader == NULL)
    {
        ERROR_ReportWarning("Forward: Unable to find TCP Header Info field\n");
        return;
    }
    // Perform the TCP delay calculations.
    delay = node->getNodeTime() - tcpHeader->packetCreationTime;

#ifdef ADDON_DB
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL && !packetReceived)
    {
        // Hop count data.
        StatsDBNetworkEventParam* ipParamInfo;
        ipParamInfo = (StatsDBNetworkEventParam*)
            MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

        if (ipParamInfo == NULL)
        {
            ERROR_ReportWarning ("ERROR: Forward Application no Network Events Info\n");
            return;
        }
        else
        {
            forward->tcpStats->fragHopCount += (int)ipParamInfo->m_HopCount;
        }
    }
#endif
    if (packetReceived)
    {
        forward->numPacketsReceived++;
        forward->tcpStats->numTcpMsgRecd++;
        if (forward->tcpStats->lastDelayTime != EXTERNAL_MAX_TIME)
        {
            if (forward->tcpStats->numTcpMsgRecd > 1)
            {
                // Compute abs(delay difference)
                if (delay > forward->tcpStats->lastDelayTime)
                {
                    D = delay - forward->tcpStats->lastDelayTime;
                }
                else
                {
                    D = forward->tcpStats->lastDelayTime - delay;
                }

                // Update jitter
                if (forward->tcpStats->numTcpMsgRecd == 2)
                {
                    forward->tcpStats->actTcpJitter = D;
                }
                else
                {
                    forward->tcpStats->actTcpJitter += (D - forward->tcpStats->actTcpJitter) / 16;
                }
                if (forward->numPacketsReceived == 2)
                {
                    forward->actJitter = D;
                }
                else
                {
                    forward->actJitter += (D - forward->actJitter) / 16;
                }

                forward->tcpStats->tcpJitter += forward->tcpStats->actTcpJitter;
                forward->jitter += forward->actJitter;
            }
        }
        // Set last delay time, used for next packet
        forward->tcpStats->lastDelayTime = delay;
        forward->tcpStats->tcpEndtoEndDelay += delay;

        // Avg packet hop count is equal to fragment hop count.  Can update this to
        // be weighted by messages received instead.
        forward->tcpStats->packetHopCount =
            (double) forward->tcpStats->fragHopCount / forward->tcpStats->numTcpFragRecd
            * forward->tcpStats->numTcpMsgRecd;
    }
}

// /**
// FUNCTION   :: TimeOutComp
// PURPOSE    :: Required for heap construction for the
//               UDP timeout functionality
// PARAMETERS ::
// + a : Pointer to the FORWARD_UdpTimeOutInfo.
// + b : Pointer to the FORWARD_UdpTimeOutInfo.
// RETURN     ::  bool :
// **/
bool TimeOutComp(FORWARD_UdpTimeOutInfo*& a, FORWARD_UdpTimeOutInfo*& b)
{
    return a->timeout > b->timeout;
}


// /**
// FUNCTION   :: ForwardReceiveUdpChunk
// PURPOSE    :: Handles UDP packet reconstruction
// PARAMETERS ::
// + node : Pointer to the node.
// + forward : Pointer to the forward application.
// + msg : Message received pointer
// RETURN     ::  Void : NULL.
// **/
static void ForwardReceiveUdpChunk(
    Node* node,
    AppDataForward* forward,
    Message* msg)
{
    // Now check to see if we are expecting multiple fragments.
    // So check the number of fragments.
    clocktype udpFailureTimeout;
    char* chunk = MESSAGE_ReturnPacket(msg);
    int chunkSize = MESSAGE_ReturnPacketSize(msg);
    int actualSize = MESSAGE_ReturnActualPacketSize(msg);
    int placeChunk = 0;

    FORWARD_UdpFragmentData* udpFragData;
    FORWARD_UdpPacketRecon* reconsData;
    FORWARD_UdpPacketRecon* tempData;
    udpFragData =
        (FORWARD_UdpFragmentData*) MESSAGE_ReturnInfo(msg, INFO_TYPE_UdpFragData);
    udpFailureTimeout = udpFragData->udpTimeout;

    // Check for the timeout first.
    std::vector<Int32>::iterator it;
    std::vector<FORWARD_UdpTimeOutInfo*>::iterator timeOutIt;
    for (unsigned int i = 0; i < forward->timeOutInfo.size(); i++)
    {
        // if ((*timeOutIt)->timeout < node->getNodeTime())
        if (forward->timeOutInfo.at(i)->timeout < node->getNodeTime())
        {
            // retireve the data.
            if (forward->udpHashRequest.UdpCheckAndRetrieveRequest(forward->timeOutInfo.at(i)->messageId, &tempData))
            {
                // remove the element from the hash, and the messageId vector.
                timeOutIt = forward->timeOutInfo.begin();
                forward->timeOutInfo.erase(timeOutIt);
                forward->udpHashRequest.UdpRemoveRequest(tempData->messageId);

                // Check if the new chunk belongs to this message.
                if (tempData->messageId == udpFragData->messageId)
                {
                    tempData = NULL;
                    return;
                }
                // new chunk does not belong to the message. Check the other messages.
                // Let the loop continue. Free up tempData.
                MEM_free(tempData);

            }
        }
        else
        {
            // We are done. No other packets have timeout.
            break;
        }
    }

    if (!forward->udpStats->udpAppStats && node->appData.appStats)
    {
        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, forward->localAddr);
        SetIPv4AddressInfo(&rAddr, forward->remoteAddr);
        forward->udpStats->udpAppStats = new STAT_AppStatistics(
            node,
            "forward-udp",
            STAT_NodeAddressToDestAddressType(node, forward->localAddr),
            STAT_AppSenderReceiver,
            "Forward UDP");

        forward->udpStats->udpAppStats->Initialize(
             node,
             rAddr,
             lAddr,
             (STAT_SessionIdType)forward->uniqueId,
             forward->uniqueId);
        forward->udpStats->udpAppStats->setTos(forward->tos);
        forward->udpStats->udpAppStats->SessionStart(node);
    }

    if (udpFragData->uniqueFragNo > forward->udpUniqueFragNoRcvd)
    {
        // Update UDP stats
        if (forward->localAddr == ANY_ADDRESS)
        {
            forward->udpStats->numUdpBroadcastFragsRecv++;
            forward->udpStats->numUdpBroadcastBytesReceived +=
                MESSAGE_ReturnPacketSize(msg);
            if (node->appData.appStats)
            {
                forward->udpStats->udpAppStats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Broadcast);
            }
        }
        else if (NetworkIpIsMulticastAddress(node, forward->localAddr))
        {
            // Multicast Packets.
            forward->udpStats->numUdpMulticastFragsRecv++;
            forward->udpStats->numUdpMulticastBytesReceived +=
                                            MESSAGE_ReturnPacketSize(msg);
            if (node->appData.appStats)
            {
                forward->udpStats->udpAppStats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Multicast);
            }
        }
        else
        {
            forward->udpStats->numUdpUnicastFragsRecv++;
            forward->udpStats->numUdpUnicastBytesReceived +=
                                            MESSAGE_ReturnPacketSize(msg);
            if (node->appData.appStats)
            {
                forward->udpStats->udpAppStats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Unicast);
            }
        }
        forward->udpStats->numUdpFragsReceived++;
        if (forward->udpStats->numUdpFragsReceived == 1)
        {
            forward->udpStats->udpServerSessionStart = node->getNodeTime();
        }

        forward->udpStats->udpServerSessionFinish = node->getNodeTime();
        // New code.
        forward->tosStats[udpFragData->tos]->totalPriorityDelay += node->getNodeTime() - msg->packetCreationTime;
        forward->numFragsReceived++;
        forward->udpStats->numUdpBytesReceived += MESSAGE_ReturnPacketSize(msg);
        forward->tosStats[udpFragData->tos]->numPriorityFragsRcvd++;
        forward->tosStats[udpFragData->tos]->numPriorityBytesRcvd += MESSAGE_ReturnPacketSize(msg);

        UpdateUdpStats(node, forward, msg, FALSE);
    }

#ifdef ADDON_DB
    // report stats DB for fragment
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL)
    {
        UpdateStatsDb(node,
            forward,
            msg,
            MESSAGE_ReturnPacketSize(msg),
            FALSE,
            FALSE);
    }
#endif // ADDON_DB

    if (udpFragData->numberFrags == 1)
    {
        if (udpFragData->uniqueFragNo > forward->udpUniqueFragNoRcvd)
        {
            // We have no frags to wait for
            // Extract SockIf_PktHdr from info field to be passed into EXT_FwdData()
            char* sockIf_PktHdr_Info = MESSAGE_ReturnInfo(msg, INFO_TYPE_SocketInterfacePktHdr);
            int sockIf_PktHdr_Size = MESSAGE_ReturnInfoSize(msg, INFO_TYPE_SocketInterfacePktHdr);
            EXTERNAL_ForwardData(
                forward->iface,
                node,
                sockIf_PktHdr_Info,
                sockIf_PktHdr_Size);
            //printf ("NodeId %d, packetSize %d\n", node->nodeId, msg->packetSize);

            // Need to Handle the statistics.
            UpdateUdpStats(node, forward, msg, TRUE);

            // Update the TOS stats.
            HandlePacketPriorityStats(forward, FALSE, udpFragData->tos);

            forward->udpUniqueFragNoRcvd = udpFragData->uniqueFragNo;
        }

#ifdef ADDON_DB
        // STATS DB CODE
        StatsDb* db = node->partitionData->statsDb;
        if (db != NULL)
        {
            UpdateStatsDb(node,
                forward,
                msg,
                MESSAGE_ReturnPacketSize(msg),
                FALSE,
                TRUE);
        }
#endif
        return;
    }
    if (udpFragData->uniqueFragNo <= forward->udpUniqueFragNoRcvd)
    {
        return;
    }
    forward->udpUniqueFragNoRcvd = udpFragData->uniqueFragNo;


    // We have fragmented packet. So check if we already have the fragment
    if (forward->udpHashRequest.UdpCheckAndRetrieveRequest(udpFragData->messageId, &reconsData))
    {
        ERROR_Assert(reconsData->messageId == udpFragData->messageId,
                     "Invalid UDP packet message Id");

        // We already have the data in storage.
        reconsData->remainingFragments--;

        // There is a possiblity that we did not receive the first
        // fragment that has the header, hence check for it.

        // past the first fragment.  Need to handle here.
        if (!reconsData->isVirtual)
        {
            // Now to place the chunk in its correct location.
            placeChunk = udpFragData->seqNum * FORWARD_UDP_FRAGMENT_SIZE;
            memcpy(reconsData->packet + placeChunk, chunk, chunkSize);
        }
        else if (reconsData->isVirtual && actualSize > 0)
        {
            // We have some actual data with virtual data.
            placeChunk = udpFragData->seqNum * FORWARD_UDP_FRAGMENT_SIZE;
            memcpy(reconsData->packet + placeChunk, chunk, actualSize);
        }

#ifdef DEBUG
        if (placeChunk + chunkSize > reconsData->messageSize)
        {
            printf (" Place Chunk is %d \n", placeChunk);
            printf (" Sequence Number is %d \n", udpFragData->seqNum);
            printf (" Message size is %d \n", reconsData->messageSize);
        }
#endif
        reconsData->receivedSize += chunkSize;

        if (reconsData->remainingFragments == 0 &&
                reconsData->receivedSize == reconsData->messageSize)
        {
            // we have received the entire packet.
            // Extract SockIf_PktHdr from info field to be passed into EXT_FwdData()
            char* sockIf_PktHdr_Info = MESSAGE_ReturnInfo(msg, INFO_TYPE_SocketInterfacePktHdr);
            int sockIf_PktHdr_Size = MESSAGE_ReturnInfoSize(msg, INFO_TYPE_SocketInterfacePktHdr);
            EXTERNAL_ForwardData(
                forward->iface,
                node,
                sockIf_PktHdr_Info,
                sockIf_PktHdr_Size);
            //printf ("NodeId %d, packetSize %d\n", node->nodeId,  reconsData->messageSize);


            // Update the UDP statistics.
            UpdateUdpStats(node, forward, msg, TRUE);
#ifdef ADDON_DB
            // STATS DB CODE
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL)
            {
                UpdateStatsDb(node,
                    forward,
                    msg,
                    reconsData->messageSize, // we need whole msg size
                    // MESSAGE_ReturnPacketSize(msg), this is frag size
                    FALSE,
                    TRUE);
            }
#endif

            // Update the TOS stats.
            HandlePacketPriorityStats(forward,
                                      FALSE,
                                      reconsData->tos);

            std::vector<FORWARD_UdpTimeOutInfo*>::iterator it;
            for (it = forward->timeOutInfo.begin();
                    it != forward->timeOutInfo.end();
                    it++)
            {
                if ((*it)->messageId == reconsData->messageId)
                {
                    forward->timeOutInfo.erase(it);
                    break;
                }
            }
            forward->udpHashRequest.UdpRemoveRequest(reconsData->messageId);
            // packet pointer is indeterminate due to no actual data and all virtual
            //MEM_free(reconsData->packet);
            MEM_free(reconsData);
        }
        else if ((reconsData->remainingFragments == 0 &&
                  reconsData->receivedSize != reconsData->messageSize) ||
                 (reconsData->remainingFragments != 0 &&
                  reconsData->receivedSize == reconsData->messageSize))
        {
            // We have a problem. This case should never happen.
            return;
        }
    }
    else
    {
        // Message does not exist in storage.
        // Save the message and move on.
        FORWARD_UdpPacketRecon* newData;
        newData = (FORWARD_UdpPacketRecon*) MEM_malloc(sizeof(FORWARD_UdpPacketRecon));

        // Save the header only if it is the first fragment.
        if (udpFragData->seqNum == 0)
        {
            newData->packetCreateTime = msg->packetCreationTime;
        }

        newData->messageSize = udpFragData->messageSize;
        newData->isVirtual = udpFragData->isVirtual;
        newData->messageId = udpFragData->messageId;
        newData->receivedSize = chunkSize;
        newData->remainingFragments = udpFragData->numberFrags - 1;
        newData->timeOut = udpFragData->udpTimeout;
        newData->tos = udpFragData->tos;

        // past the first fragment.  Need to handle here.
        // If the data is not virtual then save the entire chunk.
        if (!newData->isVirtual)
        {
            newData->packet = (char*) MEM_malloc(newData->messageSize);
            memset(newData->packet, 0, newData->messageSize);
            placeChunk = udpFragData->seqNum * FORWARD_UDP_FRAGMENT_SIZE;

            // Check the sequence number and place the chunk accordingly.
            memcpy(newData->packet + placeChunk, chunk, chunkSize);
        }
        else if (newData->isVirtual && actualSize > 0)
        {
            // data is actual as well as virtual
            newData->packet = (char*) MEM_malloc(newData->messageSize);
            memset(newData->packet, 0, newData->messageSize);
            placeChunk = udpFragData->seqNum * FORWARD_UDP_FRAGMENT_SIZE;
            memcpy(newData->packet + placeChunk, chunk, actualSize);
        }
#ifdef DEBUG
        if (placeChunk + chunkSize > newData->messageSize)
        {
            printf(" FIRST Place Chunk is %d \n", placeChunk);
            printf(" FIRST Sequence Number is %d \n", udpFragData->seqNum);
            printf(" FIRST Message size is %d \n", newData->messageSize);
        }
#endif

        // Save newData
        forward->udpHashRequest.UdpHashRequest(newData, newData->messageId);

        // Save the timeout info.
        FORWARD_UdpTimeOutInfo* timeOutInfo =
            (FORWARD_UdpTimeOutInfo*) MEM_malloc(sizeof(FORWARD_UdpTimeOutInfo));
        timeOutInfo->messageId = newData->messageId;
        timeOutInfo->timeout = newData->timeOut;
        forward->timeOutInfo.push_back(timeOutInfo);
        make_heap(forward->timeOutInfo.begin(), forward->timeOutInfo.end(), TimeOutComp);
    }
}

// /**
// FUNCTION   :: ForwardReceiveTcpChunk
// PURPOSE    :: Handles TCP packet reconstruction
// PARAMETERS ::
// + node : Pointer to the node.
// + forward : Pointer to the forward application.
// + msg : Message received pointer
// RETURN     ::  Void : NULL.
// **/
static void ForwardReceiveTcpChunk(
    Node *node,
    AppDataForward* forward,
    Message* msg)
{
    // There are three states:
    //     1) receivingMessage == FALSE
    //            We are not receiving a message.  This chunk is the
    //            beginning of a new message.  Receive up to the size of the
    //            Forward TCP Header and go to state 2.
    //     2) receivingMessage == TRUE && knowMessageSize == FALSE
    //            We are receiving a message, but we have not received
    //            the entire Forward TCP header.  If we have received the
    //            entire TCP header then extract the message
    //            size and go to state 3.  Otherwise extract what data is
    //            there and remain in state 2.
    //     3) receivingMessage == TRUE && knowMessageSize == TRUE
    //            We are receiving a message and know the message size.
    //            First receive all actual data, then receive all of the
    //            virtual data.  Once we have received the entire message
    //            then send it back to the external interface message and go
    //            to state 1.  Otherwise continue extracting the message and
    //            remain in state 3.

    int remaining;

    // Initialize this chunk
    char* chunk = MESSAGE_ReturnPacket(msg);
    int chunkSize = MESSAGE_ReturnPacketSize(msg);
#ifdef DEBUG
    int actualSize = MESSAGE_ReturnActualPacketSize(msg);
    int virtualSize = MESSAGE_ReturnVirtualPacketSize(msg);
#endif

    FORWARD_TcpHeaderInfo* tcpHeader;
    // Continue processing this chunk until there is nothing left.  Each
    // time through the loop, some data or all of the data will be extracted
    // from the chunk.

    // update the number of Frags received.
    forward->numFragsReceived++;

    // extrac the info field.
    int numFrags = 0;
    int lowerLimit = 0;
    int upperLimit = 0;
    numFrags = MESSAGE_ReturnNumFrags(msg);
    forward->tcpStats->numTcpFragRecd++;
    forward->tcpStats->tcpBytesRecd += chunkSize;
    if (node->appData.appStats)
    {
        if (!forward->tcpStats->tcpAppStats)
        {
            Address lAddr;
            Address rAddr;
            // setting addresses
            SetIPv4AddressInfo(&lAddr, forward->localAddr);
            SetIPv4AddressInfo(&rAddr, forward->remoteAddr);

            forward->tcpStats->tcpAppStats = new STAT_AppStatistics(
                                              node,
                                              "forward-tcp",
                                              STAT_Unicast,
                                              STAT_AppSenderReceiver,
                                              "Forward TCP");

            // will check msg boundaries and automatically call AddMessageReceivedDataPoints() 
            //    to update msg stats (rcvd msg and data size) when entire msg is rcvd
            forward->tcpStats->tcpAppStats->EnableAutoRefragment();

            forward->tcpStats->tcpAppStats->Initialize(
                                     node,
                                     rAddr,
                                     lAddr,
                                     STAT_AppStatistics::GetSessionId(msg),
                                     forward->uniqueId);
            forward->tcpStats->tcpAppStats->setTos(forward->tos);
            forward->tcpStats->tcpAppStats->SessionStart(node);
        }

        forward->tcpStats->tcpAppStats->AddFragmentReceivedDataPoints(
            node,
            msg,
            MESSAGE_ReturnPacketSize(msg),
            STAT_Unicast);
    }
    UpdateTcpStats(node, forward, msg, FALSE);
    if (forward->tcpStats->numTcpFragRecd == 1)
    {
        forward->tcpStats->firstTcpFragRecdTime = node->getNodeTime();
    }

    forward->tcpStats->lastTcpFragRecdTime = node->getNodeTime();

    int countInfo = 0;
    while (chunkSize > 0)
    {
        if (!forward->receivingMessage)
        {
            // STATE 1
            // This is the first chunk of a new message.  Receive up to the
            // size of the Forward TCP Header.

            ERROR_Assert(forward->bufferSize == 0, "buffer should be empty");
            ERROR_Assert(forward->receivedSize == 0, "should have received nthing");

            forward->receivingMessage = TRUE;

            // Extract message size
            tcpHeader = (FORWARD_TcpHeaderInfo*) MESSAGE_ReturnInfo(
                msg,
                INFO_TYPE_ForwardTcpHeader,
                countInfo);
            ERROR_Assert(tcpHeader != NULL, "No forward TCP header for this fragment");
            forward->messageSize = tcpHeader->packetSize;
            forward->actualSize = tcpHeader->packetSize - tcpHeader->virtualSize;
            forward->virtualSize = tcpHeader->virtualSize;

            // Resize buffer if necessary
            if (forward->actualSize > forward->bufferMaxSize)
            {
                MEM_free(forward->buffer);
                forward->buffer = (char*) MEM_malloc(forward->actualSize);
                forward->bufferMaxSize = forward->actualSize;
            }
            
            // Get the info field details for this fragment
            if (countInfo < (int)msg->infoBookKeeping.size())
            {
                lowerLimit = msg->infoBookKeeping.at(countInfo).infoLowerLimit;
                upperLimit = msg->infoBookKeeping.at(countInfo).infoUpperLimit;

                forward->upperLimit.push_back(upperLimit - lowerLimit);
                for (int k = lowerLimit; k < upperLimit; k++)
                {
                    MessageInfoHeader infoHdr;
                    infoHdr.infoSize = msg->infoArray.at(k).infoSize;
                    infoHdr.infoType = msg->infoArray.at(k).infoType;
                    infoHdr.info = (char*) MEM_malloc(infoHdr.infoSize);
                    memcpy(infoHdr.info, msg->infoArray.at(k).info, infoHdr.infoSize);
                    forward->tcpInfoField.push_back(infoHdr);
                }
            }

            // Continue processing message
            // Goes to STATE 2.
        }
        else // receivingMessage == TRUE
        {
            // Receive data

            if (forward->receivedSize < forward->actualSize)
            {
                // STATE 3
                // Continue receiving rest of actual data

                remaining = MIN(chunkSize, forward->actualSize - forward->bufferSize);

                memcpy(
                    forward->buffer + forward->bufferSize,
                    chunk,
                    remaining);

                forward->bufferSize += remaining;
                forward->receivedSize += remaining;
                chunk += remaining;
                chunkSize -= remaining;

                // Remains in STATE 3
            }
            else if (forward->receivedSize < forward->messageSize)
            {
                // STATE 3
                // All actual data is received.  Receive rest of virtual data.

                remaining = MIN(chunkSize, forward->messageSize - forward->receivedSize);

                forward->receivedSize += remaining;
                chunk += remaining;
                chunkSize -= remaining;

                // Remains in STATE 3
            }

            // Check if full packet is received
            if (forward->receivedSize == forward->messageSize)
            {
                // Extract SockIf_PktHdr from info field to be passed into EXT_FwdData()
                char* sockIf_PktHdr_Info = NULL;
                int sockIf_PktHdr_Size = 0;
                if (!forward->upperLimit.empty())
                {
                    for (unsigned int i = 0; i < (UInt32)forward->upperLimit.front(); i++)
                    {
                        MessageInfoHeader infoHdr = forward->tcpInfoField.at(i);
                        if (infoHdr.infoType == INFO_TYPE_SocketInterfacePktHdr)
                        {
                            sockIf_PktHdr_Info = infoHdr.info;
                            sockIf_PktHdr_Size = infoHdr.infoSize;
                            break;
                        }
                    }
                }

                // Process message - The request is complete so it
                // is forwarded back to the CES running on the partition that
                // initiated it. That partition will determine if it timed out.
                EXTERNAL_ForwardData(
                    forward->iface,
                    node,
                    sockIf_PktHdr_Info,
                    sockIf_PktHdr_Size);

                // Create a duplicate message.
                Message* newMsg;
                newMsg = MESSAGE_Duplicate(node, msg);

                // clean up the info field from the new message.
                for (unsigned int i = 0; i < newMsg->infoArray.size(); i++)
                {
                    MessageInfoHeader* hdr = &(newMsg->infoArray[i]);
                    MESSAGE_InfoFieldFree(node, hdr);
                    hdr->infoSize = 0;
                    hdr->info = NULL;
                    hdr->infoType = INFO_TYPE_UNDEFINED;
                }

                newMsg->infoArray.clear();
                if (!forward->upperLimit.empty())
                {
                    for (unsigned int i = 0;
                         i < (UInt32)forward->upperLimit.front(); i++)
                    {
                        MessageInfoHeader infoHdr;
                        char* info;
                        infoHdr = forward->tcpInfoField.at(i);
                        info = MESSAGE_AddInfo(
                                   node,
                                   newMsg,
                                   infoHdr.infoSize,
                                   infoHdr.infoType);
                        memcpy(info, infoHdr.info, infoHdr.infoSize);
                    }

                    // Clean up the info.
                    for (unsigned int i = 0;
                        i < (unsigned)forward->upperLimit.front(); i++)
                    {
                        if (i >= forward->tcpInfoField.size())
                        {
                            ERROR_ReportWarning("TCP Info field has less Infos that specified in BookKeeping\n");
                            break;
                        }
                        MessageInfoHeader* hdr = &(forward->tcpInfoField[i]);
                        if (hdr->infoSize > 0)
                        {
                            MEM_free(hdr->info);
                            hdr->infoSize = 0;
                            hdr->info = NULL;
                            hdr->infoType = INFO_TYPE_UNDEFINED;
                        }
                    }
                    if (!forward->tcpInfoField.empty())
                    {
                        forward->tcpInfoField.erase(forward->tcpInfoField.begin(),
                                                    forward->tcpInfoField.begin() + forward->upperLimit.front());
                    }

                    forward->upperLimit.pop_front();
                }
                //forward->tcpDelay.pop_front();
                UpdateTcpStats(node, forward, newMsg, TRUE);


#ifdef ADDON_DB
                StatsDb* db = node->partitionData->statsDb;
                if (db != NULL)
                {
                    UpdateStatsDb(node,
                        forward,
                        newMsg,
                        forward->messageSize,
                        TRUE,
                        TRUE);
                }
#endif
                // This message is finished.  Prepare for next message.
                forward->bufferSize = 0;
                forward->receivedSize = 0;
                forward->receivingMessage = FALSE;
                countInfo++;
                // Goes to STATE 1

                // Get rid of the new message.
                MESSAGE_Free(node, newMsg);
            }
        }
    }
}

// /**
// FUNCTION   :: AttemptToSendBufferedRequest
// PURPOSE    :: Sends buffered TCP data
// PARAMETERS ::
// + node : Pointer to the node.
// + forward : Pointer to the forward application.
// RETURN     ::  Void : NULL.
// **/
static void AttemptToSendBufferedRequest(
    Node *node,
    AppDataForward *forward)
{
    FORWARD_BufferedRequest *bufferedRequest;
    // Trying to send buffered requests
    if (forward->requestBuffer != NULL
            && forward->tcpState == FORWARD_TcpConnected
            && !forward->waitingForDataSent)
    {
        bufferedRequest = forward->requestBuffer;
#ifdef DEBUG
        // Count only mts data (virtual data size),
        // excluding SockIf_PktHdr STILL stored in pkt
        printf("FORWARD TCP queued packet sent (size = %d)\n",
               bufferedRequest->virtualSize);
#endif

        // remove from the request buffer
        forward->requestBuffer = bufferedRequest->next;
        if (forward->requestBuffer == NULL)
        {
            forward->lastRequest = NULL;
        }

        // TCP Stats
        forward->tcpStats->numTcpMsgSent++;
        forward->tcpStats->numTcpFragSent++;
        // Count only mts data (virtual data size), excluding sockif_pkthdr
        // STILL stored in real pkt--to be moved to info field before transmission
        forward->tcpStats->tcpBytesSent +=
            bufferedRequest->virtualSize;

        if (forward->tcpStats->numTcpMsgSent == 1)
        {
            // first Packet
            forward->tcpStats->firstTcpPacketSendTime = node->getNodeTime();
        }
        forward->tcpStats->lastTcpPacketSendTime = node->getNodeTime();
        // STATS DB CODE
#ifdef ADDON_DB
        StatsDBAppEventParam appParam;
        appParam.SetAppType("FORWARD-APPLICATION");
        appParam.SetAppName(forward->applicationName);
        appParam.m_ReceiverId = forward->receiverId;
        appParam.SetReceiverAddr(forward->remoteAddr);
        appParam.SetFragNum(0);
        appParam.m_fragEnabled = FALSE;
        appParam.SetPriority(forward->tos);
        // Count only mts data (virtual data size), excluding sockif_pkthdr
        appParam.m_TotalMsgSize = bufferedRequest->virtualSize;
        appParam.SetMsgSize(bufferedRequest->virtualSize);
        //appParam.SetSessionId(forward->uniqueId);
        if (forward->isServer)
        {
            appParam.SetSessionId(forward->serverSessionId);
        }
        else
        {
            appParam.SetSessionId(forward->clientSessionId);
        }

        appParam.m_SessionInitiator = node->nodeId ;

#ifdef SOCKET_INTERFACE
        // Handle qualnet socket msgId1 and msgId2
        if (forward->iface->type == EXTERNAL_SOCKET)
        {
            UInt64 msgId1 = 0;
            UInt64 msgId2 = 0;

            SocketInterface_GetMessageIds(bufferedRequest->messageData,
                               bufferedRequest->realDataSize,
                               &msgId1,
                               &msgId2);
            appParam.SetSocketInterfaceMsgId(msgId1, msgId2);
        }
#endif // SOCKET_INTERFACE
#endif
        Message *tempMsg = NULL;
        if (bufferedRequest->virtualSize > 0)
        {
            tempMsg = ForwardTcpSendNewHeaderVirtualData(
                node,
                forward->connectionId,
                bufferedRequest->messageData, // SockIf_PktHdr stored in real pkt to be moved to info field for tx
                bufferedRequest->realDataSize,
                bufferedRequest->virtualSize, // mts data size
                TRACE_FORWARD
#ifdef ADDON_DB
                ,
                &appParam,
                forward->ttl);
#else
                ,forward->ttl);
#endif
        }
        else
        {
            tempMsg = ForwardTcpSendData(
                node,
                forward->connectionId,
                bufferedRequest->messageData,
                bufferedRequest->realDataSize,
                TRACE_FORWARD
#ifdef ADDON_DB
                ,
                &appParam,
                forward->ttl);
#else
                ,forward->ttl);
#endif
        }
        if (node->appData.appStats)
        {
            // count only mts data size (virtual data size), excluding
            // SockIf_PktHdr in real pkt--to be moved to info before tx
            int bytesSent = bufferedRequest->virtualSize;
            forward->tcpStats->tcpAppStats->AddMessageSentDataPoints(
                node,
                tempMsg,
                0,
                bytesSent,
                0,
                STAT_Unicast);
        }

        forward->numPacketsSent++;
        forward->waitingForDataSent = TRUE;

        MEM_free(bufferedRequest);
    }
}

// /**
// FUNCTION   :: SendForwardUdpFragment
// PURPOSE    :: Sends UDP data transport layer. It takes
//               virtual and actual data.
// PARAMETERS ::
// + srcNode : Pointer to the node.
// + sendUdpDataMsg : Pointer to the UDP data.
// + iface : Pointer to the external interface.
// + realDataSize : size of the UDP header data.
// + virtualSize : size of virtual UDP data.
// + headerData : header data location
// + sequenceNum : UDP fragment sequence number
// + numFrags : Number of UDP fragments created from the UDP packet.
// + messageId : Uniques identifier for UDP packet.
// + totalMessageSize : Size of the UDP packet (not fragmented).
// RETURN     ::  Void : NULL.
// **/
static Message* SendForwardUdpFragment(
    Node* srcNode,
    EXTERNAL_ForwardSendUdpData* sendUdpDataMsg,
    EXTERNAL_Interface* iface,
    Int32 realDataSize,
    Int32 virtualSize,
    char* headerData,
    Int32 sequenceNum,
    Int32 uniqueFragNo,
#ifdef ADDON_DB
    StatsDBAppEventParam* appParam,
#endif // ADDON_DB
    Int32 numFrags,
    Int32 messageId,
    Int32 totalMessageSize,
    Int32 sessionId,
    Int32 forwardUniqueId,
    BOOL isMdpEnabled = FALSE,
    BOOL isServer = FALSE,
    BOOL isUdpMulticast = FALSE)
{
    Message *msg;
    AppToUdpSend *info;

    assert(iface != NULL);

    // Allocate memory for the message and data packet
    msg = MESSAGE_Alloc(
              srcNode,
              TRANSPORT_LAYER,
              TransportProtocol_UDP,
              MSG_TRANSPORT_FromAppSend);

    // Store SockIf_PktHdr NOT in pkt BUT in info field of comm msg to tx.
    // Assume no real data to send in pkt, ie, the only payload is MTS data (virtual data).
    // Thus MTS data size can be arbitrary, including less than sizeof(SockIf_PktHdr) = 32B.
    if (realDataSize > 0)
    {
        MESSAGE_AddInfo(srcNode, msg, realDataSize, 
                        INFO_TYPE_SocketInterfacePktHdr);
        memcpy(MESSAGE_ReturnInfo(msg, INFO_TYPE_SocketInterfacePktHdr), 
               headerData, realDataSize);
    }
    // Must call MSG_PktAlloc() even when real pkt size is 0, because MSG_PayloadAlloc() 
    // is called inside the PktAlloc() to allocate space for lower layer headers (TCP, IP, ...)
    MESSAGE_PacketAlloc(srcNode, msg, 0, TRACE_FORWARD);

    // Add virtual data if present
    if (virtualSize > 0)
    {
        MESSAGE_AddVirtualPayload(srcNode, msg, virtualSize);
    }

    // Create info for the transport protocol
    MESSAGE_InfoAlloc(
        srcNode,
        msg,
        sizeof(AppToUdpSend));
    info = (AppToUdpSend *) MESSAGE_ReturnInfo(msg);

    SetIPv4AddressInfo(&info->sourceAddr, sendUdpDataMsg->localAddress);

    // Set source port to be unique interface id
    info->sourcePort = (short)iface->interfaceId;

    SetIPv4AddressInfo(&info->destAddr, sendUdpDataMsg->remoteAddress);
    info->destPort = APP_FORWARD;

    info->priority = sendUdpDataMsg->priority;
    info->ttl = sendUdpDataMsg->ttl;
    info->outgoingInterface = ANY_INTERFACE;

    FORWARD_UdpFragmentData* udpFragInfo;

    // Fill in fragmentation info so packet can be reassembled
    udpFragInfo = (FORWARD_UdpFragmentData*) MESSAGE_AddInfo(
                      srcNode,
                      msg,
                      sizeof(FORWARD_UdpFragmentData),
                      INFO_TYPE_UdpFragData);
    ERROR_Assert(udpFragInfo != NULL, "Unable to add an info field!");
    udpFragInfo->seqNum = sequenceNum;
    udpFragInfo->numberFrags = numFrags;
    udpFragInfo->udpTimeout = srcNode->getNodeTime() + DEFAULT_UDP_TIMEOUT;
    udpFragInfo->messageId = messageId;
    udpFragInfo->messageSize = totalMessageSize;
    udpFragInfo->isVirtual = virtualSize > 0;
    udpFragInfo->tos = sendUdpDataMsg->priority;
    udpFragInfo->sessionId = sessionId;
    udpFragInfo->packetCreationTime = srcNode->getNodeTime();
    udpFragInfo->uniqueFragNo = uniqueFragNo;

    // STATS DB CODE
#ifdef ADDON_DB   

    HandleStatsDBAppSendEventsInsertion(srcNode,
                                        msg,
                                        virtualSize, // only mts virtual data and no real data are sent
                                        appParam);
#endif
    // Send with a delay of 1 nanosecond.  This will get past any problem
    // with an instantiate that has not been received.

    if (isMdpEnabled && isServer && isUdpMulticast)
    {
        Address localAddr, remoteAddr;

        memset(&localAddr,0,sizeof(Address));
        memset(&remoteAddr,0,sizeof(Address));

        localAddr.networkType = NETWORK_IPV4;
        localAddr.interfaceAddr.ipv4 = sendUdpDataMsg->localAddress;

        remoteAddr.networkType = NETWORK_IPV4;
        remoteAddr.interfaceAddr.ipv4 = sendUdpDataMsg->remoteAddress;

        // The udp frag to tx includes no real data but all virtual data,
        // and SockIf_PktHdr is stored in the info field

        //char* newPayload = (char*) MEM_malloc(realDataSize);
        //memcpy(newPayload, headerData, realDataSize);
        MdpQueueDataObject(srcNode,
                           localAddr,
                           remoteAddr,
                           forwardUniqueId,
                           0, //realDataSize,
                           NULL, //newPayload,
                           virtualSize,
                           msg,
                           TRUE,
                           (UInt16)info->sourcePort);
    }
    else
    {
        EXTERNAL_MESSAGE_SendAnyNode(
            iface->partition,
            srcNode,
            msg,
            1,
            EXTERNAL_SCHEDULE_LOOSELY);
    }
    return msg;

}

// /**
// FUNCTION   :: AppLayerForwardSendUdpData
// PURPOSE    :: Fragments the UDP data packet and send the
//               UDP fragments to layers below. This function
//               breaks UDP packets greater than 10,000 bytes into
//               10000 byte chunks. Header is only sent with the
//               first chunk.
// PARAMETERS ::
// + srcNode : Pointer to the node.
// + sendUdpDataMsg : Pointer to the UDP data.
// + iface : Pointer to the external interface.
// + forward : Pointer to forward application.
// + actualMsgSize : size of actual payload of UDP message data.
// + virtualMsgSize : size of virtual payload of UDP message data
// + data : UDP data location, store SockIf_PktHdr
// RETURN     ::  Void : NULL.
// **/
static Message* AppLayerForwardSendUdpData(
    Node* srcNode,
    EXTERNAL_ForwardSendUdpData* sendUdpDataMsg,
    EXTERNAL_Interface* iface,
    AppDataForward* forward,
    Int32 actualMsgSize,
    Int32 virtualMsgSize,
    char* data,
    int numNodesInMulticastGroup)
{
    // lets figure out the number of fragments.
    Int32 udpFragmentSize = 0;
    Int32 sequenceNum = 0;
    Int32 numFrags = 0;
    Int32 messageSize = virtualMsgSize; // msg to tx includes only virtual data
    Int32 totalMessageSize = messageSize;
    numFrags = (Int32) ceil((double)messageSize / FORWARD_UDP_FRAGMENT_SIZE);
    Message *tempMsg = NULL;

    int sessionId = -1;
    forward->udpMessageId++;

    if (forward->isServer)
    {
        sessionId = forward->serverSessionId;
    }
    else
    {
        sessionId = forward->clientSessionId;
    }

#ifdef DEBUG
    printf (" Node %d, server %d sent DATA client session ID = %d, server Session Id = %d\n\n",
        srcNode->nodeId,
        forward->isServer,
        forward->clientSessionId,
        forward->serverSessionId);
#endif
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;

    appParam.SetPriority(sendUdpDataMsg->priority);
    appParam.SetSessionId(sessionId);

    appParam.m_SessionInitiator = srcNode->nodeId ;
    appParam.m_TotalMsgSize = totalMessageSize;
    appParam.SetAppType("FORWARD-APPLICATION");
    appParam.SetAppName(forward->applicationName);
    appParam.m_ReceiverId = forward->receiverId;
    appParam.SetReceiverAddr(forward->remoteAddr);
    if (totalMessageSize > FORWARD_UDP_FRAGMENT_SIZE)
    {
       appParam.m_fragEnabled = TRUE;
    }

    // Handle special case for Fragmentation. In case of fragmentation
    // we would insert an entry for non-fragmented message and then
    // entries for the fragmented messages.

#ifdef SOCKET_INTERFACE
    // Handle ces socket msgId1 and msgId2
    if (iface->type == EXTERNAL_SOCKET)
    {
        UInt64 msgId1 = 0;
        UInt64 msgId2 = 0;

        // Get Ids from SockIf_PktHdr
        SocketInterface_GetMessageIds(data, actualMsgSize, &msgId1, &msgId2);
        appParam.SetSocketInterfaceMsgId(msgId1, msgId2);
    }
#endif // SOCKET_INTERFACE

#endif

    while (messageSize > 0)
    {
        if (messageSize < FORWARD_UDP_FRAGMENT_SIZE)
        {
            // Last packet to be sent
            udpFragmentSize = messageSize;
        }
        else
        {
            udpFragmentSize = FORWARD_UDP_FRAGMENT_SIZE;
        }
#ifdef ADDON_DB
        appParam.m_IsFragmentation = FALSE;
        if (totalMessageSize > FORWARD_UDP_FRAGMENT_SIZE &&
            sequenceNum == 0)
        {
            appParam.m_IsFragmentation = TRUE;
        }
        appParam.SetFragNum(sequenceNum);
#endif

        // Add sockif_pktHdr info field to all fragments
        // ---will extract the info from the last fragment.
        tempMsg = SendForwardUdpFragment(
            srcNode,
            sendUdpDataMsg,
            iface,
            actualMsgSize,
            udpFragmentSize,
            data,
            sequenceNum,
            forward->udpUniqueFragNo ++,
#ifdef ADDON_DB
            &appParam,
#endif // ADDON_DB
            numFrags,
            forward->udpMessageId,
            totalMessageSize,
            sessionId,
            forward->uniqueId,
            forward->isMdpEnabled,
            forward->isServer,
            forward->isUdpMulticast);

        sequenceNum++;
        messageSize -= udpFragmentSize;
        forward->udpStats->numUdpFragsSent ++;
        forward->tosStats[sendUdpDataMsg->priority]->numPriorityFragsSent ++;

        // Update fwd app udp stats
        if (srcNode->appData.appStats)
        {
            // Add timing info for each udp frag sent EXCEPT for the last one---the last frag 
            // will be added timing when AddMsgSentDataPts (but using unfragmented udp msg size)
            if (messageSize > 0)
            {
                forward->udpStats->udpAppStats->AddTiming(srcNode, tempMsg, udpFragmentSize, 0);
            }

            // update frag sent app stats whenever a frag is sent
            STAT_DestAddressType addrType =
                STAT_NodeAddressToDestAddressType(srcNode, forward->remoteAddr);
            forward->udpStats->udpAppStats->AddFragmentSentDataPoints(
                srcNode,
                udpFragmentSize, 
                addrType);
        }

        // Update the number of frags sent stats.
        if (sendUdpDataMsg->remoteAddress == ANY_ADDRESS)
        {
            forward->udpStats->numUdpBroadcastFragsSent++;
        }
        else if (NetworkIpIsMulticastAddress(srcNode,
            sendUdpDataMsg->remoteAddress))
        {
            forward->udpStats->numUdpMulticastFragsSent++;
        }
        else
        {
            forward->udpStats->numUdpUnicastFragsSent++;
        }
    }
    return tempMsg;
}

// /**
// API       :: QueueTCPData
// PURPOSE   :: This function will queue data for sending to the TCP
//              protocol in the future.  This is typically called when data
//              needs to be sent, but the connection has not been created.
//              The queued data will be sent to TCP in receive-order when
//              the connection is established.
// PARAMETERS::
// + node : Node* : The node where the data is being queued on
// + forward : AppDataForward* : The forward app that will send the data
// + messageData : char* : The data to sent
// + messageSize : int : The size of the data
// + virtualSize : int : The amount of virtual data to send with this packet
// RETURN    :: void
// **/
static void QueueTCPData(
    Node *node,
    AppDataForward *forward,
    char *messageData,
    int realDataSize,
    int virtualSize)
{
    FORWARD_BufferedRequest *newRequest;

#ifdef DEBUG
    printf("FORWARD TCP request queued (size = %d)\n",
           messageSize);
#endif

    // Allocate a buffered request and fill it in
    newRequest = (FORWARD_BufferedRequest*)
                 MEM_malloc(sizeof(FORWARD_BufferedRequest));
    newRequest->messageData = (char*) MEM_malloc(realDataSize);
    memcpy(newRequest->messageData, messageData, realDataSize);
    newRequest->realDataSize = realDataSize;
    newRequest->virtualSize = virtualSize;
    newRequest->next = NULL;

    // Add it to the end of the list
    if (forward->requestBuffer == NULL)
    {
        forward->requestBuffer = newRequest;
        forward->lastRequest = newRequest;
    }
    else
    {
        forward->lastRequest->next = newRequest;
        forward->lastRequest = newRequest;
    }
}

// /**
// FUNCTION   :: AppLayerForwardInstantiatePair
// PURPOSE    :: The function is used to instantiate
//               a node pair when some application is sent
//               from a node to the other. The function
//               initializes the source node and then sends an
//               initialization message to the destination node.
// PARAMETERS ::
// + srcNode : Pointer to the source node.
// + destNode : Pointer to the destination node.
// + from : Source node address.
// + to : Destination node address.
// + interfaceId : interface index .
// + interfaceName : Name of the external Interface being used.
// RETURN     ::  Void : NULL.
// **/
void AppLayerForwardInstantiatePair(
    Node* srcNode,
    Node* destNode,
    NodeAddress from,
    NodeAddress to,
    int interfaceId,
    char* interfaceName)
{
    char err[MAX_STRING_LENGTH];
    AppDataForward *forward;
    Message* instantiateMessage;
    EXTERNAL_ForwardInstantiate *instantiate;

    BOOL isServer;
    isServer = srcNode->nodeId < destNode->nodeId;

    AppForwardInit(
        srcNode,
        interfaceName,
        from,
        to,
        isServer);

    // Get the forward app now that it has been initialized.  This app
    // is used later in this function.
    forward = AppLayerGetForward(
                  srcNode,
                  from,
                  to,
                  interfaceId);
    sprintf(err, "Forward not initialized for interface %s %d", interfaceName, interfaceId);
    ERROR_Assert(forward != NULL, err);

    // Create an instantiate message
    instantiateMessage = MESSAGE_Alloc(
                             destNode,
                             APP_LAYER,
                             APP_FORWARD,
                             MSG_EXTERNAL_ForwardInstantiate);

#ifdef DEBUG
    printf(
        "Instantiate message sent to node id %d\n",
        destNode->nodeId);
#endif

    // Fill in info field with enough information to create a forward
    // app
    MESSAGE_InfoAlloc(
        destNode,
        instantiateMessage,
        sizeof(EXTERNAL_ForwardInstantiate));
    instantiate = (EXTERNAL_ForwardInstantiate*) MESSAGE_ReturnInfo(instantiateMessage);
    instantiate->localAddress = to;
    instantiate->remoteAddress = from;
    instantiate->interfaceId = interfaceId;
    strcpy(instantiate->interfaceName, interfaceName);
    instantiate->isServer = !isServer;

    // Send the instantiate message with no delay to the destination node.
    EXTERNAL_MESSAGE_SendAnyNode(destNode->partitionData, destNode,
                                 instantiateMessage, 0, EXTERNAL_SCHEDULE_LOOSELY);
}
// /**
// FUNCTION   :: AppLayerForwardSendTcpData
// PURPOSE    :: The function handles the TCP based application
//               The function maintains the TCP states, and instantiates
//               the node pairs. The originating node must be local
//               to this partition
// PARAMETERS ::
// + nodeA : Pointer to the source node.
// + nodeIdA : Source node id.
// + nodeB : Pointer to the destination node.
// + nodeIdB : Destination node id.
// + header : header data location
// + realDataSize : size of the UDP header data.
// + virtualDataSize : size of virtual UDP data.
// + SendTcpDataMsg : Pointer to TCP data.
// RETURN     ::  Void : NULL.
// **/
void AppLayerForwardSendTcpData(
    Node* nodeA,
    NodeAddress nodeIdA,
    Node* nodeB,
    NodeAddress nodeIdB,
    char* header,
    int realDataSize,
    int virtualDataSize,
    EXTERNAL_ForwardSendTcpData* sendTcpDataMsg)
{
    AppDataForward* forward;
    NodeAddress tempAddress;
    Node* srcNode;
    Node* tempNode;

    assert(nodeA != NULL);
    srcNode = nodeA;
    assert(nodeB != NULL);

    // Get the forward app on the source node.  If not found create one and
    // send a message to the dest node to instantiate a forward app.
    forward = AppLayerGetForward(
                  nodeA,
                  sendTcpDataMsg->fromAddress,
                  sendTcpDataMsg->toAddress,
                  sendTcpDataMsg->interfaceId);
    if (forward == NULL)
    {
        AppLayerForwardInstantiatePair(
            nodeA,
            nodeB,
            sendTcpDataMsg->fromAddress,
            sendTcpDataMsg->toAddress,
            sendTcpDataMsg->interfaceId,
            sendTcpDataMsg->interfaceName);

        forward = AppLayerGetForward(
                      nodeA,
                      sendTcpDataMsg->fromAddress,
                      sendTcpDataMsg->toAddress,
                      sendTcpDataMsg->interfaceId);
        assert(forward != NULL);
    }
    if (!forward->tcpStats->tcpAppStats && nodeA->appData.appStats)
    {
        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, forward->localAddr);
        SetIPv4AddressInfo(&rAddr, forward->remoteAddr);

        forward->tcpStats->tcpAppStats = new STAT_AppStatistics(
                                          nodeA,
                                          "forward-tcp",
                                          STAT_Unicast,
                                          STAT_AppSenderReceiver,
                                          "Forward TCP");
        forward->tcpStats->tcpAppStats->Initialize(
             nodeA,
             lAddr,
             rAddr,
             (STAT_SessionIdType)forward->uniqueId,
             forward->uniqueId);
        forward->tcpStats->tcpAppStats->setTos(forward->tos);
        forward->tcpStats->tcpAppStats->SessionStart(nodeA);
    }

    // Switch based on the TCP state of the source forward app
    switch (forward->tcpState)
    {
        // TCP has not been intialized
    case FORWARD_TcpUninitialized:
    {
        Message* listenMessage;
        Message* connectMessage;
        EXTERNAL_ForwardIdentifier* id;

        // Swap nodes so that the lowest ID is node A
        if (nodeIdA > nodeIdB)
        {
            tempAddress = nodeIdA;
            nodeIdA = nodeIdB;
            nodeIdB = tempAddress;

            tempNode = nodeA;
            nodeA = nodeB;
            nodeB = tempNode;

            tempAddress = sendTcpDataMsg->fromAddress;
            sendTcpDataMsg->fromAddress = sendTcpDataMsg->toAddress;
            sendTcpDataMsg->toAddress = tempAddress;
        }

        // Send a listen message to Node A (lowest ID).  This will
        // ensure that in the same pair of nodes the lowest one is
        // always listening.
        listenMessage = MESSAGE_Alloc(
                            nodeA,
                            APP_LAYER,
                            APP_FORWARD,
                            MSG_EXTERNAL_ForwardTcpListen);

        // Add in unique identifying information
        MESSAGE_InfoAlloc(
            nodeA,
            listenMessage,
            sizeof(EXTERNAL_ForwardIdentifier));
        id = (EXTERNAL_ForwardIdentifier*) MESSAGE_ReturnInfo(listenMessage);
        id->local = sendTcpDataMsg->fromAddress;
        id->remote = sendTcpDataMsg->toAddress;
        strcpy(id->interfaceName, sendTcpDataMsg->interfaceName);

        // Send the listen message with a delay of 1.  This will make
        // sure the app is instantiated on the dest before the listen
        // message is received.
        EXTERNAL_MESSAGE_SendAnyNode (nodeA->partitionData, nodeA,
                                      listenMessage, 1, EXTERNAL_SCHEDULE_LOOSELY);

        // Send a connect message to Node B (highest ID).  This will
        // ensure that in the same pair of nodes the lowest one is
        // always listening.
        connectMessage = MESSAGE_Alloc(
                             nodeB,
                             APP_LAYER,
                             APP_FORWARD,
                             MSG_EXTERNAL_ForwardTcpConnect);

        // Add in unique identifying information
        MESSAGE_InfoAlloc(
            nodeB,
            connectMessage,
            sizeof(EXTERNAL_ForwardIdentifier));
        id = (EXTERNAL_ForwardIdentifier*) MESSAGE_ReturnInfo(connectMessage);
        id->local = sendTcpDataMsg->toAddress;
        id->remote = sendTcpDataMsg->fromAddress;
        id->ttl = sendTcpDataMsg->ttl;
        forward->ttl = sendTcpDataMsg->ttl;
        strcpy(id->interfaceName, sendTcpDataMsg->interfaceName);

        // Send the connect message with a delay of 1.  This will make
        // sure the app is instantiated before the connect message is
        // received.
        EXTERNAL_MESSAGE_SendAnyNode(nodeB->partitionData, nodeB,
                                     connectMessage, 1, EXTERNAL_SCHEDULE_LOOSELY);

        // Queue data to be sent on source node
        if (nodeB == srcNode)
        {
            QueueTCPData(
                nodeB,
                forward,
                header,
                realDataSize,
                virtualDataSize);
        }
        else
        {
            QueueTCPData(
                nodeA,
                forward,
                header,
                realDataSize,
                virtualDataSize);
        }
        break;
    }

    // TCP is listening for a connection
    case FORWARD_TcpListening:
        forward->ttl = sendTcpDataMsg->ttl;
        // Queue the data to be sent when connected
        QueueTCPData(
            nodeA,
            forward,
            header,
            realDataSize,
            virtualDataSize);
        break;

        // TCP is attempting to connect
    case FORWARD_TcpConnecting:
        forward->ttl = sendTcpDataMsg->ttl;
        // Queue the data to be sent when connected
        QueueTCPData(
            nodeA,
            forward,
            header,
            realDataSize,
            virtualDataSize);
        break;

        // TCP is connected
    case FORWARD_TcpConnected:
        // If waiting for data to be sent then add it to the end of the
        // queue.  Otherwise just send it.
        if (forward->waitingForDataSent)
        {
            forward->ttl = sendTcpDataMsg->ttl;
            QueueTCPData(
                nodeA,
                forward,
                header,
                realDataSize,
                virtualDataSize);
        }
        else
        {
#ifdef DEBUG
            printf("FORWARD TCP new packet sent (size = %d)\n",
                   // The virtual data are mts data. The real data are SockIf_PktHdr,
                   // and will be moved from pkt to info field before tx to dst node
                   virtualDataSize);
#endif
            // STATS DB CODE
#ifdef ADDON_DB
            StatsDBAppEventParam appParam;
            appParam.SetAppType("FORWARD-APPLICATION");
            appParam.SetAppName(forward->applicationName);
            appParam.m_ReceiverId = forward->receiverId;
            appParam.SetReceiverAddr(forward->remoteAddr);
            appParam.SetFragNum(0);
            appParam.m_fragEnabled = FALSE;
            appParam.SetPriority(forward->tos);
            appParam.m_SessionInitiator = nodeA->nodeId;
            if (forward->isServer)
            {
                appParam.SetSessionId(forward->serverSessionId);
            }
            else
            {
                appParam.SetSessionId(forward->clientSessionId);
            }
            // data to send are all virtual
            appParam.m_TotalMsgSize = virtualDataSize;
            appParam.SetMsgSize(virtualDataSize);

#ifdef SOCKET_INTERFACE
            // Handle ces socket msgId1 and msgId2
            if (forward->iface->type == EXTERNAL_SOCKET)
            {
                UInt64 msgId1 = 0;
                UInt64 msgId2 = 0;

                SocketInterface_GetMessageIds(header,
                                   realDataSize,
                                   &msgId1,
                                   &msgId2);
                appParam.SetSocketInterfaceMsgId(msgId1, msgId2);
            }
#endif // SOCKET_INTERFACE
#endif
            Message * tempMsg = NULL;
            if (virtualDataSize > 0)
            {
                tempMsg = ForwardTcpSendNewHeaderVirtualData(
                    nodeA,
                    forward->connectionId,
                    header, // SockIf_PktHdr stored in real pkt to be moved to info field for tx
                    realDataSize,
                    virtualDataSize, // mts data size
                    TRACE_FORWARD
#ifdef ADDON_DB
                    ,
                    &appParam,
                    sendTcpDataMsg->ttl);
#else
                    ,sendTcpDataMsg->ttl);
#endif
            }
            else
            {
                tempMsg = ForwardTcpSendData(
                    nodeA,
                    forward->connectionId,
                    header,
                    realDataSize,
                    TRACE_FORWARD
#ifdef ADDON_DB
                    ,
                    &appParam,
                    sendTcpDataMsg->ttl);
#else
                    ,sendTcpDataMsg->ttl);
#endif
            }

            // TCP Stats
            // Count only mts data (virtual), not the SockIf_PktHdr
            int bytesSent = virtualDataSize;
            if (nodeA->appData.appStats)
           {
                forward->tcpStats->tcpAppStats->AddMessageSentDataPoints(
                    nodeA,
                    tempMsg,
                    0,
                    bytesSent,
                    0,
                    STAT_Unicast);
            }        
            forward->tcpStats->numTcpMsgSent++;
            forward->tcpStats->numTcpFragSent++;
            // Count only mts data (virtual), not the SockIf_PktHdr
            forward->tcpStats->tcpBytesSent += virtualDataSize;
            if (forward->tcpStats->numTcpMsgSent == 1)
            {
                // first Packet
                forward->tcpStats->firstTcpPacketSendTime = nodeA->getNodeTime();
            }
            forward->tcpStats->lastTcpPacketSendTime = nodeA->getNodeTime();

            forward->numPacketsSent++;
            forward->waitingForDataSent = TRUE;
        }
        break;
    }
}


// /**
// FUNCTION   :: AppForwardMessageTypeToStr
// PURPOSE    :: The function converts the message type to string.
// PARAMETERS ::
// + eventType : Message event identifier.
// RETURN     ::  String :
// **/
static const char *
AppForwardMessageTypeToStr(int eventType)
{
    switch (eventType)
    {
        // An external interface has requested sending TCP
        // data.
    case MSG_EXTERNAL_ForwardInstantiate:
        return ("MSG_EXTERNAL_ForwardInstantiate");
    case MSG_EXTERNAL_ForwardSendTcpData:
        return ("MSG_EXTERNAL_ForwardSendTcpData");
    case MSG_EXTERNAL_ForwardTcpListen:
        return ("MSG_EXTERNAL_ForwardTcpListen:");
    case MSG_EXTERNAL_ForwardTcpConnect:
        return (" MSG_EXTERNAL_ForwardTcpConnect:");
    case MSG_APP_FromTransport:
        return (" MSG_APP_FromTransport:");
    case MSG_APP_FromTransListenResult:
        return (" MSG_APP_FromTransListenResult: ");
    case MSG_APP_FromTransOpenResult:
        return (" MSG_APP_FromTransOpenResult: ");
    case MSG_APP_FromTransCloseResult:
        return (" MSG_APP_FromTransCloseResult: ");
    case MSG_APP_FromTransDataSent:
        return (" MSG_APP_FromTransDataSent: ");
    case MSG_APP_FromTransDataReceived:
        return (" MSG_APP_FromTransDataReceived: ");
    default:
        return (" unknown message type ");
    }
}

// /**
// FUNCTION   :: AppLayerForward
// PURPOSE    :: Models the behaviour of Forward on receiving the
//               message encapsulated in msg.
// PARAMETERS ::
// + node : Pointer to the node which received the message.
// + msg : message received by the layer.
// RETURN     ::  Void : NULL
// **/
void
AppLayerForward(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    char error[MAX_STRING_LENGTH];
    AppDataForward *forward;

#ifdef DEBUG
    TIME_PrintClockInSecond(node->getNodeTime(), buf);
    printf("FORWARD : Node %ld got a message at %sS of type %s\n",
           node->nodeId, buf, AppForwardMessageTypeToStr(msg->eventType));
#endif /* DEBUG */

    switch (msg->eventType)
    {
        // Instantiate a new forward app
    case MSG_EXTERNAL_ForwardInstantiate:
    {
#ifdef DEBUG
        printf("FORWARD : Node %u received MSG_EXTERNAL_ForwardInstantiate \n",
               node->nodeId);
        printf("          at = %lld\n", node->getNodeTime());
#endif /* DEBUG */
        EXTERNAL_ForwardInstantiate *instantiate =
            (EXTERNAL_ForwardInstantiate*) MESSAGE_ReturnInfo(msg);
        EXTERNAL_Interface *iface;
        D_Hierarchy* h;
        h = &node->partitionData->dynamicHierarchy;
        std::string path;
        NodeAddress destId;

        // Lookup the interface
        iface = EXTERNAL_GetInterfaceByName(
                    &node->partitionData->interfaceList,
                    instantiate->interfaceName);
        if (iface == NULL)
        {
            sprintf(error, "Unknown interface %s",
                    instantiate->interfaceName);
            ERROR_ReportError(error);
        }

        // Check if there is already a forward app.  If not then create one.
        forward = AppLayerGetForwardByNameAndServer(
                      node,
                      instantiate->localAddress,
                      instantiate->remoteAddress,
                      instantiate->interfaceName,
                      instantiate->isServer);
        if (forward == NULL)
        {
            AppForwardInit(
                node,
                instantiate->interfaceName,
                instantiate->localAddress,
                instantiate->remoteAddress,
                instantiate->isServer);

            // Get forward app.
            forward = AppLayerGetForwardByNameAndServer(
                          node,
                          instantiate->localAddress,
                          instantiate->remoteAddress,
                          instantiate->interfaceName,
                          instantiate->isServer);
            assert(forward != NULL);

            destId = MAPPING_GetNodeIdFromInterfaceAddress(
                         node->partitionData->firstNode,
                         forward->remoteAddr);
            assert(destId != INVALID_MAPPING);
            char nodeId[MAX_STRING_LENGTH];
            sprintf (nodeId, "destNode/%d", destId);
            if (h->IsEnabled())
            {
               h->CreateApplicationPath(
                    node,
                    "Forward",
                    (int)forward->sourcePort,
                    nodeId,
                    path);
            }

        }
        break;
    }

    case MSG_EXTERNAL_ForwardSendUdpData:
    {
#ifdef DEBUG
        printf("FORWARD : Node %u received MSG_EXTERNAL_ForwardSendUdpData \n",
               node->nodeId);
        printf("          at = %lld\n", node->getNodeTime());
#endif /* DEBUG */

        EXTERNAL_ForwardSendUdpData *sendData =
            (EXTERNAL_ForwardSendUdpData*) MESSAGE_ReturnInfo(msg);
        Node* destNode;
        NodeAddress destId;
        D_Hierarchy* h;
        h = &node->partitionData->dynamicHierarchy;
        std::string path;

        int numNodesInMulticastGroup = 0;

        if (sendData->remoteAddress == ANY_ADDRESS
            || NetworkIpIsMulticastAddress(node, sendData->remoteAddress))
        {
            // Check initialization for multicast/broadcast
            // Check if there is a forward app for one-to-many.  If not,
            // instantiate one.
            forward = AppLayerGetForward(
                          node,
                          sendData->localAddress,
                          sendData->remoteAddress,
                          sendData->interfaceId);
            if (forward == NULL)
            {
                // Instantiate forward app.  We are always the server.
                // Don't instantiate app on remote node because we don't
                // know the receiver nodes.
                AppForwardInit(
                    node,
                    sendData->interfaceName,
                    sendData->localAddress,
                    sendData->remoteAddress,
                    TRUE,
                    TRUE);

                forward = AppLayerGetForward(
                              node,
                              sendData->localAddress,
                              sendData->remoteAddress,
                              sendData->interfaceId);
                assert(forward != NULL);
            }
        }
        else
        {
            // Check initialization for unicast
            // Check if there is already a forward app.  If not instantiate
            // a forward app on this node, and send an instantiate message
            // to the remote node.
            forward = AppLayerGetForward(
                          node,
                          sendData->localAddress,
                          sendData->remoteAddress,
                          sendData->interfaceId);
            if (forward == NULL)
            {
                // Get destination node
                destId = MAPPING_GetNodeIdFromInterfaceAddress(
                             node->partitionData->firstNode,
                             sendData->remoteAddress);
                assert(destId != INVALID_MAPPING);
                destNode = MAPPING_GetNodePtrFromHash(
                               node->partitionData->nodeIdHash,
                               destId);
#ifdef PARALLEL //Parallel
                if (destNode == NULL)
                {
                    // Destination can be a node on a remote partition.
                    destNode = MAPPING_GetNodePtrFromHash(
                                   node->partitionData->remoteNodeIdHash, destId);
                }
#endif //Parallel
                assert(destNode != NULL);
                char nodeId[MAX_STRING_LENGTH];

                // Instantiate forward apps
                AppLayerForwardInstantiatePair(
                    node,
                    destNode,
                    sendData->localAddress,
                    sendData->remoteAddress,
                    sendData->interfaceId,
                    sendData->interfaceName);

                forward = AppLayerGetForward(
                              node,
                              sendData->localAddress,
                              sendData->remoteAddress,
                              sendData->interfaceId);
                assert(forward != NULL);

                sprintf (nodeId, "destNode/%d", destNode->nodeId);
                if (h->IsEnabled())
                {
                    h->CreateApplicationPath(
                        node,
                        "Forward",
                        (int)forward->sourcePort,
                        nodeId,
                        path);
                }
            }
        }

        STAT_DestAddressType addrType =
            STAT_NodeAddressToDestAddressType(node, forward->remoteAddr);
        
        // Initialize stats if not yet created
        if (!forward->udpStats->udpAppStats && node->appData.appStats)
        {
            // Set addresses
            Address lAddr;
            Address rAddr;
            SetIPv4AddressInfo(&lAddr, forward->localAddr);
            SetIPv4AddressInfo(&rAddr, forward->remoteAddr);

            forward->udpStats->udpAppStats = new STAT_AppStatistics(
                  node,
                  "forward-udp",
                  addrType,
                  STAT_AppSenderReceiver,
                  "Forward UDP");
            forward->udpStats->udpAppStats->Initialize(
                 node,
                 lAddr,
                 rAddr,
                 (STAT_SessionIdType) forward->uniqueId,
                 forward->uniqueId);
            forward->udpStats->udpAppStats->setTos(forward->tos);
            forward->udpStats->udpAppStats->SessionStart(node, addrType);
        }
        
        // Send UDP data
        Message * tempMsg = AppLayerForwardSendUdpData(
            node,
            sendData,
            forward->iface,
            forward,
            MESSAGE_ReturnActualPacketSize(msg),
            MESSAGE_ReturnVirtualPacketSize(msg),
            MESSAGE_ReturnPacket(msg),
            numNodesInMulticastGroup);

        // Update statistics
        forward->numPacketsSent++;

        // Count only mts data (virtual), excluding SockIf_PktHdr stored in the pkt
        int udpBytesSent = MESSAGE_ReturnVirtualPacketSize(msg);
        // Handle packet priority type.
        forward->tosStats[sendData->priority]->numPriorityBytesSent += udpBytesSent;
        HandlePacketPriorityStats(forward, TRUE, sendData->priority);

        if (node->appData.appStats)
        {
            forward->udpStats->udpAppStats->AddMessageSentDataPoints(
                node,
                tempMsg, // this is the last frag of the UDP msg
                0,
                udpBytesSent, // total data (virtual) of unfragmented UDP msg
                0,
                addrType);
        }
        break;
    }

    // UDP data received
    case MSG_APP_FromTransport:
    {
        UdpToAppRecv *info;
        NodeAddress srcAddr;
        NodeAddress destAddr;

        info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);

        srcAddr = GetIPv4Address(info->sourceAddr);
        destAddr = GetIPv4Address(info->destAddr);
        forward = AppLayerGetForward(
                      node,
                      destAddr,
                      srcAddr,
                      info->sourcePort);
        if (forward == NULL)
        {
            EXTERNAL_Interface* iface;
            NodeAddress srcNodeId;
            BOOL isServer;

            // Initialize forward app based on sending node interface
            // id (the udp source port) and source address
            iface = EXTERNAL_GetInterfaceByUniqueId(
                        &node->partitionData->interfaceList,
                        info->sourcePort);

            if (destAddr == ANY_ADDRESS
                || NetworkIpIsMulticastAddress(node, destAddr))
            {
                // Receiver is never server for multicast
                isServer = FALSE;
            }
            else
            {
                srcNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                node,
                                srcAddr);
                isServer = node->nodeId < srcNodeId;
            }

            // Create a new forward app
            AppForwardInit(
                node,
                iface->name,
                destAddr,
                srcAddr,
                isServer,
                TRUE);

            forward = AppLayerGetForward(
                          node,
                          destAddr,
                          srcAddr,
                          info->sourcePort);
            assert(forward != NULL);
        }

        // Now we have to handle the UDP packet
        // reconstruction.
        ForwardReceiveUdpChunk(node, forward, msg);
        break;
    }

    // An external interface has requested sending TCP
    // data.
    case MSG_EXTERNAL_ForwardSendTcpData:
    {
#ifdef DEBUG
        printf("FORWARD : Node %u received MSG_EXTERNAL_ForwardSendTcpData \n",
               node->nodeId);
        printf("          at = %lld\n", node->getNodeTime());
#endif /* DEBUG */

        NodeAddress to;
        NodeAddress nodeIdB;
        Node*       nodeB;

        EXTERNAL_ForwardSendTcpData* sendInfo =
            (EXTERNAL_ForwardSendTcpData*) MESSAGE_ReturnInfo(msg);

        // Get the destination node
        to = sendInfo->toAddress;
        nodeIdB = MAPPING_GetNodeIdFromInterfaceAddress(
                      node->partitionData->firstNode,
                      to);
        assert(nodeIdB != INVALID_MAPPING);
        nodeB = MAPPING_GetNodePtrFromHash(
                    node->partitionData->nodeIdHash,
                    nodeIdB);

#ifdef PARALLEL //Parallel
        if (nodeB == NULL)
        {
            // Destination can be a node on a remote partition.
            nodeB = MAPPING_GetNodePtrFromHash(
                        node->partitionData->remoteNodeIdHash, nodeIdB);
        }
#endif //Parallel
        assert(nodeB != NULL);
        // This will result in creation of a forward application if
        // needed on our node, and an instantiate message sent to the
        // destination node.
        AppLayerForwardSendTcpData(
            node, node->nodeId, nodeB, nodeIdB, MESSAGE_ReturnPacket(msg),
            msg->packetSize, msg->virtualPayloadSize,
            sendInfo);
        break;
    }

    case MSG_EXTERNAL_ForwardTcpListen:
    {
        // Get unique identifying information
        EXTERNAL_ForwardIdentifier* id;
        id = (EXTERNAL_ForwardIdentifier*) MESSAGE_ReturnInfo(msg);

        // Get forward app server
        forward = AppLayerGetForwardByNameAndServer(
                      node,
                      id->local,
                      id->remote,
                      id->interfaceName,
                      TRUE);
        if (forward == NULL)
        {
            ERROR_ReportWarning("Invalid forward app for tcp listen");
        }
        else
        {
            // Listen it is not already listening
            APP_TcpServerListen(
                node,
                APP_FORWARD,
                forward->localAddr,
                    (short)(APP_FORWARD + forward->interfaceId));
            forward->tcpState = FORWARD_TcpListening;
        }

#ifdef DEBUG
        printf(
            "Node %d TCP LISTEN uniqueId %d\n",
            node->nodeId,
            forward->uniqueId);
#endif

        break;
    }

    case MSG_EXTERNAL_ForwardTcpConnect:
    {
        // Get unique identifying information
        EXTERNAL_ForwardIdentifier* id;
        id = (EXTERNAL_ForwardIdentifier*) MESSAGE_ReturnInfo(msg);

        // Get forward app client
        forward = AppLayerGetForwardByNameAndServer(
                      node,
                      id->local,
                      id->remote,
                      id->interfaceName,
                      FALSE);
        if (forward == NULL)
        {
            ERROR_ReportWarning("Invalid forward app for tcp connect");
        }
        else if (forward->tcpState == FORWARD_TcpUninitialized)
        {
            // Connect if not already connecting
            APP_TcpOpenConnection(
                node,
                APP_FORWARD,
                forward->localAddr,
                forward->sourcePort,
                forward->remoteAddr,
                (short)(APP_FORWARD + forward->interfaceId),
                forward->uniqueId,
                PROCESS_IMMEDIATELY);
            forward->tcpState = FORWARD_TcpConnecting;
        }

#ifdef DEBUG
        printf(
            "Node %d TCP CONNECT uniqueId %d\n",
            node->nodeId,
            forward->uniqueId);
#endif
        break;
    }

    // Return message from TCP listen
    case MSG_APP_FromTransListenResult:
    {
        TransportToAppListenResult *listenResult;

        listenResult = (TransportToAppListenResult*)
                       MESSAGE_ReturnInfo(msg);
        if (listenResult->connectionId == -1)
        {
#ifdef DEBUG
            printf("FORWARD TCP server listen failed\n");
#endif
            node->appData.numAppTcpFailure++;
        }
        break;
    }

    // Return message from TCP open
    case MSG_APP_FromTransOpenResult:
    {
        TransportToAppOpenResult *openResult;

        openResult = (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);

        // Connection opened client side
        // Determine interfaceId based on listening port
        int interfaceId;
        if (openResult->type == TCP_CONN_ACTIVE_OPEN)
        {
            interfaceId = openResult->remotePort - APP_FORWARD;
        }
        else
        {
            interfaceId = openResult->localPort - APP_FORWARD;
        }
        NodeAddress remote = GetIPv4Address(openResult->remoteAddr);
        BOOL isServer;
        isServer = openResult->type == TCP_CONN_PASSIVE_OPEN;

#ifdef DEBUG
        printf(
            "Node %d TCP OPEN uniqueId %d connectionId %d interfaceId %d remote 0x%0x\n",
            node->nodeId,
            openResult->uniqueId,
            openResult->connectionId,
            interfaceId,
            remote);
#endif

        forward = AppLayerGetForwardByRemoteAndInterfaceIdAndServer(
                      node,
                      remote,
                      interfaceId,
                      isServer);
        if (forward == NULL)
        {
            sprintf(error, "Error looking up forward app for client "
                    "TCP connection open");
            ERROR_ReportError(error);
        }

        if (forward->tcpState == FORWARD_TcpConnected)
        {
            ERROR_ReportError("TCP is already connected");
        }

        // Check for error connecting.
        if (openResult->connectionId < 0)
        {
#ifdef DEBUG
            printf("FORWARD TCP server Open failed\n");
#endif
            node->appData.numAppTcpFailure++;
            forward->tcpState = FORWARD_TcpUninitialized;

            // STATS DB CODE - for message sent failure
#ifdef ADDON_DB
            if (forward->requestBuffer)
            {
                StatsDBAppEventParam appParam;
                appParam.SetAppType("Forward");
                appParam.SetFragNum(0);
                appParam.m_fragEnabled = FALSE;
                appParam.SetPriority(forward->tos);
                appParam.SetMsgSize(forward->requestBuffer->virtualSize);
                appParam.m_TotalMsgSize = forward->requestBuffer->virtualSize;
                appParam.SetMessageFailure((char*) "TCP Connection Failure");

                if (forward->isServer)
                {
                     appParam.SetSessionId(forward->serverSessionId);
                }
                else
                {
                    appParam.SetSessionId(forward->clientSessionId);

                }
                appParam.m_SessionInitiator = node->nodeId ;

#ifdef SOCKET_INTERFACE
                // Handle ces socket msgId1 and msgId2
                if (forward->iface->type == EXTERNAL_SOCKET)
                {
                    UInt64 msgId1 = 0;
                    UInt64 msgId2 = 0;

                    SocketInterface_GetMessageIds(forward->requestBuffer->messageData,
                                       forward->requestBuffer->realDataSize,
                                       &msgId1,
                                       &msgId2);
                    appParam.SetSocketInterfaceMsgId(msgId1, msgId2);
                }
#endif // SOCKET_INTERFACE

                Message *dummy_msg = MESSAGE_Alloc(
                    node,
                    TRANSPORT_LAYER,
                    TransportProtocol_TCP,
                    MSG_TRANSPORT_FromAppSend);

                HandleStatsDBAppSendEventsInsertion(
                    node,
                    dummy_msg,
                    forward->requestBuffer->virtualSize,
                    &appParam);
                MESSAGE_Free(node, dummy_msg);
            }
#endif
            break;
        }

        if (openResult->type == TCP_CONN_ACTIVE_OPEN)
        {
            forward->connectionId = openResult->connectionId;
            forward->tcpState = FORWARD_TcpConnected;
        }
        else if (openResult->type == TCP_CONN_PASSIVE_OPEN)
        {
            forward->connectionId = openResult->connectionId;
            forward->tcpState = FORWARD_TcpConnected;
        }
        else
        {
            ERROR_ReportError("Unknown TCP openResult type");
        }

        // Try sending buffered requests
        AttemptToSendBufferedRequest(node, forward);
        break;
    }

    // TCP connection closed
    case MSG_APP_FromTransCloseResult:
    {
        TransportToAppCloseResult *closeResult;

        closeResult = (TransportToAppCloseResult *)
                      MESSAGE_ReturnInfo(msg);

        forward = AppLayerGetForwardByConnectionId(
                      node,
                      closeResult->connectionId);
        if (forward == NULL)
        {
            sprintf(error, "Unknown connection Id \"%d\"",
                    closeResult->connectionId);
            ERROR_ReportError(error);
        }

        forward->tcpState = FORWARD_TcpUninitialized;
        forward->connectionId = -1;
        forward->uniqueId = -1;

        // Clean the buffers.
        forward->bufferSize = 0;
        forward->receivedSize = 0;
        forward->receivingMessage = FALSE;

        for (unsigned int i = 0; i < forward->tcpInfoField.size(); i++)
        {
            MessageInfoHeader* hdr = &(forward->tcpInfoField[i]);
            if (hdr->infoSize > 0)
            {
                MEM_free(hdr->info);
                hdr->infoSize = 0;
                hdr->info = NULL;
                hdr->infoType = INFO_TYPE_UNDEFINED;
            }
        }
        forward->tcpInfoField.clear();
        forward->upperLimit.clear();
        break;
    }

    // Return message from TCP send
    case MSG_APP_FromTransDataSent:
    {
        TransportToAppDataSent *dataSent;

        // Retrieve the corresponding forward app, and set the
        // waitingForDataSent flag to FALSE
        dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
        printf("FORWARD data sent (length = %d)\n",
               dataSent->length);
#endif

        forward = AppLayerGetForwardByConnectionId(
                      node,
                      dataSent->connectionId);
        if (forward == NULL)
        {
            sprintf(error, "Unknown connection Id \"%d\"",
                    dataSent->connectionId);
            ERROR_ReportError(error);
        }

        // update #frag sent stats for fwd TCP
        if (node->appData.appStats)
        {
            forward->tcpStats->tcpAppStats->AddFragmentSentDataPoints(node,
                                                           dataSent->length,
                                                           STAT_Unicast);
        }
        forward->waitingForDataSent = FALSE;

        // Try sending buffered requests
        AttemptToSendBufferedRequest(node, forward);
        break;
    }

    // TCP data received
    case MSG_APP_FromTransDataReceived:
    {
        TransportToAppDataReceived *dataReceived;

#ifdef DEBUG
        printf("FORWARD received TCP packet (length = %d)\n",
               MESSAGE_ReturnPacketSize(msg));
#endif

        // Determine which CES app received the data
        dataReceived = (TransportToAppDataReceived*)
                       MESSAGE_ReturnInfo(msg);
        forward = AppLayerGetForwardByConnectionId(
                      node,
                      dataReceived->connectionId);
        if (forward == NULL)
        {
            sprintf(error, "Unknown connection Id \"%d\"",
                    dataReceived->connectionId);
            ERROR_ReportError(error);
        }

        ForwardReceiveTcpChunk(node, forward, msg);
        break;
    }

    default:
        TIME_PrintClockInSecond(node->getNodeTime(), buf);
        sprintf(
            error,
            "FORWARD : at time %sS, node %lu "
            "received message of unknown type %d.",
            buf,
            (unsigned long) node->nodeId,
            msg->eventType);
        ERROR_ReportError(error);
    }

    MESSAGE_Free(node, msg);
}

// /**
// FUNCTION   :: AppForwardInit
// PURPOSE    :: Initialize a Forward session.
// PARAMETERS ::
// + node : Pointer to the node .
// + externalInterfaceName : the name of the external interface
//                           to use for packet forwarding.
// + localAddr : The node's address
// + remoteAddr : address of the remote node
// RETURN     ::  Void : NULL
// **/
void
AppForwardInit(
    Node *node,
    const char *externalInterfaceName,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    BOOL isServer,
    BOOL isUdp)
{
    char error[MAX_STRING_LENGTH];
    AppDataForward *forward;
    EXTERNAL_Interface *iface;
    std::string path;
    char name[MAX_STRING_LENGTH];
    BOOL createPath = FALSE;
    D_Hierarchy* h;
    h = &node->partitionData->dynamicHierarchy;

    // lookup interface name
    iface = EXTERNAL_GetInterfaceByName(
                &node->partitionData->interfaceList,
                externalInterfaceName);
    if (iface == NULL)
    {
        sprintf(error, "Interface \"%s\" not found", externalInterfaceName);
        ERROR_ReportError(error);
    }

    // create the app
    forward = new AppDataForward;
    forward->udpStats = new FORWARD_UdpStatsInfo;
    forward->tcpStats = new FORWARD_TcpStatsInfo;

    // fill in forward info
    forward->iface = iface;
    forward->interfaceId = iface->interfaceId;
    forward->localAddr = localAddr;
    forward->remoteAddr = remoteAddr;
    forward->isServer = isServer;
    forward->isMdpEnabled = FALSE;
    forward->isUdpMulticast = FALSE;

    // tcp info
    forward->tcpState = FORWARD_TcpUninitialized;
    forward->connectionId = -1;
    forward->uniqueId = node->appData.uniqueId++;

    if (isServer)
    {
        forward->serverSessionId = forward->uniqueId;
        forward->clientSessionId = -1;
    }
    else
    {
        forward->clientSessionId = forward->uniqueId;
        forward->serverSessionId = -1;
    }
#ifdef ADDON_DB
    forward->sessionInitiator = 0; // seems useless
    forward->messageIdCache = NULL;
    forward->fragNoCache = NULL;

    if (forward->remoteAddr == ANY_ADDRESS ||
        NetworkIpIsMulticastAddress(node, forward->remoteAddr))
    {
        forward->receiverId = 0;
    }
    else
    {
        forward->receiverId =
            MAPPING_GetNodeIdFromInterfaceAddress(node, remoteAddr);
    }

    if (isServer)
    {
        sprintf(forward->applicationName, "ForwardApplication-%d-%d",
                node->nodeId,
                forward->serverSessionId);
    }
    else
    {
        sprintf(forward->applicationName, "ForwardApplication-%d-%d",
                node->nodeId,
                forward->clientSessionId);
    }
#endif

    // udp info
    forward->sourcePort = node->appData.nextPortNum++;
    forward->udpMessageId = 0;
    forward->udpUniqueFragNo = 0;
    forward->udpUniqueFragNoRcvd = -1;

    // Initializing all the other parameters
    forward->beginStatsPeriod = 0;
    forward->bufferMaxSize = 0;
    forward->bufferSize = 0;
    forward->jitter = 0;
    forward->actJitter = 0;
    forward->jitterId = 0;
    forward->messageSize = 0;
    forward->numPacketsSent = 0;
    forward->numPacketsReceived = 0;
    forward->receivedSize = 0;
    forward->receivingMessage = 0;
    forward->tos = 0;
    forward->waitingForDataSent = 0;
    forward->numFragsReceived = 0;
    forward->numPacketsSentToNode = 0;
    forward->udpStats->numUdpFragsSent = 0;
    forward->udpStats->numUdpFragsReceived = 0;
    forward->udpStats->numUdpPacketsReceived = 0;
    forward->udpStats->numUdpBytesReceived = 0;
    forward->udpStats->udpEndtoEndDelay = 0;
    forward->udpStats->udpServerSessionStart = 0;
    forward->udpStats->udpServerSessionFinish = 0;
    forward->udpStats->numUdpMulticastPacketsReceived = 0;
    forward->udpStats->numUdpUnicastPacketsReceived = 0;
    forward->udpStats->numUdpMulticastFragsRecv = 0;
    forward->udpStats->numUdpMulticastFragsSent = 0;
    forward->udpStats->numUdpUnicastFragsRecv = 0;
    forward->udpStats->numUdpUnicastFragsSent = 0;
    forward->udpStats->numUdpMulticastBytesReceived = 0;
    forward->udpStats->numUdpUnicastBytesReceived = 0;
    forward->udpStats->udpSendPktTput = 0;
    forward->udpStats->udpRcvdPktTput = 0;
    forward->udpStats->hopCount = 0;
    forward->udpStats->udpJitter = 0;
    forward->udpStats->udpMulticastJitter = 0;
    forward->udpStats->udpUnicastJitter = 0;
    forward->udpStats->actUdpJitter = 0;
    forward->udpStats->actUdpMulticastJitter = 0;
    forward->udpStats->actUdpUnicastJitter = 0;
    forward->udpStats->udpUnicastDelay = 0;
    forward->udpStats->udpMulticastDelay = 0;
    forward->udpStats->lastDelayTime = EXTERNAL_MAX_TIME;
    forward->udpStats->udpUnicastHopCount = 0;
    forward->udpStats->udpMulticastHopCount = 0;
    forward->udpStats->numUdpBroadcastPacketsReceived = 0;
    forward->udpStats->numUdpBroadcastBytesReceived = 0;
    forward->udpStats->numUdpBroadcastFragsSent = 0;
    forward->udpStats->numUdpBroadcastFragsRecv = 0;
    forward->udpStats->udpAppStats = NULL;
#ifdef ADDON_DB
    forward->udpStats->actUdpFragsJitter = 0;
    forward->udpStats->lastFragDelayTime = EXTERNAL_MAX_TIME;
#endif // ADDON_DB

    // TCP Stats Initialization
    forward->tcpStats->firstTcpPacketSendTime = 0;
    forward->tcpStats->lastTcpPacketSendTime = 0;
    forward->tcpStats->numTcpFragRecd = 0;
    forward->tcpStats->numTcpFragSent = 0;
    forward->tcpStats->numTcpMsgRecd = 0;
    forward->tcpStats->numTcpMsgSent = 0;
    forward->tcpStats->tcpBytesRecd = 0;
    forward->tcpStats->tcpBytesSent = 0;
    forward->tcpStats->firstTcpFragRecdTime = 0;
    forward->tcpStats->lastTcpFragRecdTime = 0;
    forward->tcpStats->fragHopCount = 0;
    forward->tcpStats->packetHopCount = 0;
    forward->tcpStats->tcpEndtoEndDelay = 0;
    forward->tcpStats->tcpJitter = 0;
    forward->tcpStats->actTcpJitter = 0;
    forward->tcpStats->lastDelayTime = EXTERNAL_MAX_TIME;
    forward->tcpStats->tcpAppStats = NULL;

    for (int i = 0; i < MAX_TOS_BITS; i++)
    {
        forward->tosStats[i] = new FORWARD_PacketTosStats;
        forward->tosStats[i]->type = i;
        forward->tosStats[i]->numPriorityPacketReceived = 0;
        forward->tosStats[i]->numPriorityPacketSent = 0;
        forward->tosStats[i]->totalPriorityDelay = 0;
        forward->tosStats[i]->numPriorityFragsRcvd = 0;
        forward->tosStats[i]->numPriorityFragsSent = 0;
        forward->tosStats[i]->numPriorityBytesSent = 0;
        forward->tosStats[i]->numPriorityBytesRcvd = 0;

        // Add to the hierarchy
        sprintf (name, "%d/NumPacketSentWithPriority", i);
        if (h->IsEnabled())
        {
            createPath = h->CreateApplicationPath(
                             node,
                             "Forward",
                             (int)forward->sourcePort,
                             name,
                             path);
            if (createPath)
            {
                h->AddObject(path,
                             new D_UInt32Obj(&forward->tosStats[i]->numPriorityPacketSent));
            }

            sprintf (name, "%d/NumPacketsReceivedWithPriority", i);
            createPath = h->CreateApplicationPath(
                             node,
                             "Forward",
                             (int)forward->sourcePort,
                             name,
                             path);
            if (createPath)
            {
                h->AddObject(path,
                             new D_UInt32Obj(&forward->tosStats[i]->numPriorityPacketReceived));
            }
        }
    }

    forward->buffer = NULL;
    forward->lastRequest = NULL;
    forward->requestBuffer = NULL;

#ifdef HUMAN_IN_THE_LOOP_DEMO
    char path[MAX_STRING_LENGTH];

    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateApplicationPath(
                node,                   // node
                "appForward",            // protocol name
                forward->sourcePort,  // port
                "tos",             // object name
                path))                  // path (output)
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&forward->tos));
    }
#endif


#ifdef DEBUG
    printf("FORWARD : Node %u created new forward client structure\n",
           node->nodeId);
    printf("          sourcePort = %ld\n", forward->sourcePort);
#endif /* DEBUG */

    APP_RegisterNewApp(node, APP_FORWARD, forward);

    if (node->guiOption)
    {
        forward->jitterId = GUI_DefineMetric("External Jitter (ns)", node->nodeId, GUI_APP_LAYER, 0, GUI_INTEGER_TYPE,GUI_CUMULATIVE_METRIC);
    }
    forward->lastDelayTime = EXTERNAL_MAX_TIME;

    if (isServer && isUdp && node->appData.mdp != NULL)
    {

        Address clientAddr, destAddr;

        memset(&clientAddr,0,sizeof(Address));
        memset(&destAddr,0,sizeof(Address));

        clientAddr.networkType = NETWORK_IPV4;
        clientAddr.interfaceAddr.ipv4 = localAddr;

        destAddr.networkType = NETWORK_IPV4;
        destAddr.interfaceAddr.ipv4 = remoteAddr;


        // MDP layer Init
        MdpLayerInit(node,
                     clientAddr,
                     destAddr,
                     iface->interfaceId,
                     APP_FORWARD,
                     FALSE,
                     NULL,
                     forward->uniqueId);
        forward->isMdpEnabled = TRUE;
        forward->isUdpMulticast = TRUE;
    }

#ifdef DEBUG
    printf("FORWARD initialized on node %u\n", node->nodeId);
#endif
}

static void AppForwardPrintTosStats(
    Node* node,
    AppDataForward* forward,
    char* path,
    char* port)
{
    char buf[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];

    clocktype avgPriorityDelay = 0;
    int currPort = 0;

    currPort = atoi(port);

    if (currPort != forward->sourcePort)
    {
        return;
    }
    for (int i = 0; i < MAX_TOS_BITS; i++)
    {
        // Print the average delay for each priority packet.
        if (forward->tosStats[i]->numPriorityPacketReceived > 0)
        {
            sprintf(buf,
                    "Number Packets Sent with Priority %d = %d",
                    forward->tosStats[i]->type,
                    (UInt32) forward->tosStats[i]->numPriorityPacketSent);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);
            sprintf(buf,
                    "Number Packets Received with Priority %d = %d",
                    forward->tosStats[i]->type,
                    (UInt32) forward->tosStats[i]->numPriorityPacketReceived);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);

            sprintf(buf,
                    "Number Fragments Sent with Priority %d = %d",
                    forward->tosStats[i]->type,
                    forward->tosStats[i]->numPriorityFragsSent);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);
            sprintf(buf,
                    "Number Fragments Received with Priority %d = %d",
                    forward->tosStats[i]->type,
                    forward->tosStats[i]->numPriorityFragsRcvd);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);

            sprintf(buf,
                    "Number Bytes Sent with Priority %d = %d",
                    forward->tosStats[i]->type,
                    forward->tosStats[i]->numPriorityBytesSent);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);
            sprintf(buf,
                    "Number Bytes Received with Priority %d = %d",
                    forward->tosStats[i]->type,
                    forward->tosStats[i]->numPriorityBytesRcvd);
            IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);

            TIME_PrintClockInSecond(forward->tosStats[i]->totalPriorityDelay, clockStr);
            sprintf(buf,
                    "Total end-to-end delay with packet priority %d = %s",
                    forward->tosStats[i]->type,
                    clockStr);
            IO_PrintStat(node,
                         "Application",
                         "FORWARD",
                         ANY_DEST,
                         forward->sourcePort,
                         buf);

            avgPriorityDelay = forward->tosStats[i]->totalPriorityDelay /
                               (clocktype) forward->tosStats[i]->numPriorityFragsRcvd;
            TIME_PrintClockInSecond(avgPriorityDelay, clockStr);
            sprintf(buf,
                    "Average end-to-end delay with packet priority %d = %s",
                    forward->tosStats[i]->type,
                    clockStr);
            IO_PrintStat(node,
                         "Application",
                         "FORWARD",
                         ANY_DEST,
                         forward->sourcePort,
                         buf);
        }
    }
}

// /**
// FUNCTION   :: AppForwardPrintStats
// PURPOSE    :: Prints statistics of a Forward session.
// PARAMETERS ::
// + node : Pointer to the node .
// + forward : Pointer to the forward client data structure.
// RETURN     ::  Void : NULL
// **/
void AppForwardPrintStats(Node *node, AppDataForward *forward)
{
    char addrStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];

    clocktype avgDelay;
    double udpSentPacketThroughput = 0;
    double udpRecvPacketThroughput = 0;
    int numPacketSent = 0;

    D_Hierarchy* h;
    h = &node->partitionData->dynamicHierarchy;
    char path[MAX_STRING_LENGTH];
    std::string result;
    char child[MAX_STRING_LENGTH];
    char childPath[MAX_STRING_LENGTH];
    char portPath[MAX_STRING_LENGTH];
    char fullPortPath[MAX_STRING_LENGTH];
    char port[MAX_STRING_LENGTH];
    char destNodePath[MAX_STRING_LENGTH];
    int numChildren;
    double mcr = 0;

    IO_ConvertIpAddressToString(forward->localAddr, addrStr);
    sprintf(buf, "Forward Local Address = %s", addrStr);
    IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);

    IO_ConvertIpAddressToString(forward->remoteAddr, addrStr);
    sprintf(buf, "Forward Remote Address = %s", addrStr);
    IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);

    sprintf(path, "/node/%d/Forward/%d/destNode", node->nodeId, forward->sourcePort);
    if (h->IsEnabled() && h->IsValidPath(path))
    {
        numChildren = h->GetNumChildren(path);
        for (int i = 0; i < numChildren; i++)
        {
            strcpy(child, h->GetChildName(path, i).c_str());
            //printf ("Children are %s\n", child);
            sprintf (portPath,
                     "/node/%s/Forward",
                     child);
            // Get the port on which data was sent.
            if (!h->IsValidPath(portPath))
            {
                break;
            }

            for (int k = 0; k < h->GetNumChildren(portPath); k++)
            {
                strcpy(port, h->GetChildName(portPath, k).c_str());

                // Check if the port is the one used to send the node.
                sprintf(destNodePath,
                        "/node/%s/Forward/%s/destNode/%d",
                        child,
                        port,
                        node->nodeId);
                if (!h->IsValidPath(destNodePath))
                {
                    continue;
                }

                strcpy (fullPortPath, portPath);
                strcat(fullPortPath, "/");
                strcat(fullPortPath, port);

                // Get the number of packets sent to the node.
                sprintf(childPath,
                        "/node/%s/Forward/%s/NumPacketsSent",
                        child,
                        port);
                AppForwardPrintTosStats(node, forward, fullPortPath, port);
                if (h->IsValidPath(childPath))
                {
                    h->ReadAsString(childPath, result);
                    numPacketSent = atoi(result.c_str());
                    break;
                }
            }
        }
    }
    if (numPacketSent > 0)
    {
        mcr = ((double)(forward->numPacketsReceived * 100) / numPacketSent);
    }

    sprintf(buf, "Message Completion Rate (in Percent) = %f", mcr);
    IO_PrintStat(node, "Application", "FORWARD", ANY_DEST, forward->sourcePort, buf);
}

// /**
// FUNCTION   :: ForwardRunTimeStat
// PURPOSE    :: Prints GUI run time statistics of a Forward session.
// PARAMETERS ::
// + node : Pointer to the node .
// + forwardPtr : Pointer to the forward client data structure.
// RETURN     ::  Void : NULL
// **/
void ForwardRunTimeStat(Node *node, AppDataForward *forwardPtr)
{
    printf("jitter ""%" TYPES_64BITFMT "d""\n",
           forwardPtr->jitter);
    if (node->guiOption)
    {
        clocktype now = node->getNodeTime();

        GUI_SendIntegerData(
            node->nodeId,
            forwardPtr->jitterId,
            (int) forwardPtr->jitter,
            now);
    }
}

// /**
// FUNCTION   :: AppForwardFinalize
// PURPOSE    :: Collect statistics of a Forward session.
// PARAMETERS ::
// + node : Pointer to the node .
// + appInfo : Pointer to the application info data structure.
// RETURN     ::  Void : NULL
// **/
void
AppForwardFinalize(Node *node, AppInfo* appInfo)
{
    AppDataForward *clientPtr = (AppDataForward*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppForwardPrintStats(node, clientPtr);

        if (clientPtr->udpStats->udpAppStats)
        {
            if (!clientPtr->udpStats->udpAppStats->IsSessionFinished(STAT_Unicast))
            {
                clientPtr->udpStats->udpAppStats->SessionFinish(node, STAT_Unicast);
            }
            if (!clientPtr->udpStats->udpAppStats->IsSessionFinished(STAT_Multicast))
            {
                clientPtr->udpStats->udpAppStats->SessionFinish(node, STAT_Multicast);
            }
            clientPtr->udpStats->udpAppStats->Print(node,
                    "Application",
                    "Forward UDP",
                    ANY_ADDRESS,
                    clientPtr->sourcePort);
        }
        if (clientPtr->tcpStats->tcpAppStats)
        {
            if (!clientPtr->tcpStats->tcpAppStats->IsSessionFinished(STAT_Unicast))
            {
                clientPtr->tcpStats->tcpAppStats->SessionFinish(node, STAT_Unicast);
            }
            if (!clientPtr->tcpStats->tcpAppStats->IsSessionFinished(STAT_Multicast))
            {
                clientPtr->tcpStats->tcpAppStats->SessionFinish(node, STAT_Multicast);
            }
            clientPtr->tcpStats->tcpAppStats->Print(node,
                    "Application",
                    "Forward TCP",
                    ANY_ADDRESS,
                    clientPtr->sourcePort);
        }
    }

#ifdef ADDON_DB
    if (clientPtr->messageIdCache != NULL)
    {
        delete clientPtr->messageIdCache;
        clientPtr->messageIdCache = NULL;
    }

    if (clientPtr->fragNoCache != NULL)
    {
        delete clientPtr->fragNoCache;
        clientPtr->fragNoCache = NULL;
    }

    /*/ STATS DB CODE (TESTING ONLY)
    STATSDB_PrintTable(node->partitionData, node, STATSDB_EVENTS_TABLE);
    printf("PRINT IS DONE\n");*/
#endif
}

// /**
// FUNCTION   :: AppForwardGetForward.
// PURPOSE    :: search for a forward data structure.
// PARAMETERS ::
// + node : Pointer to the node .
// + localAddr : the local node address
// + remoteAddr : the address of the remote node
// + interfaceId : the interface to find
// RETURN     ::  The pointer to the forward data structure,
//                NULL if not found
// **/
AppDataForward* AppLayerGetForward(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    int interfaceId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataForward *forward;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FORWARD)
        {
            forward = (AppDataForward *) appList->appDetail;

            if ((forward->localAddr == localAddr)
                    && (forward->remoteAddr == remoteAddr)
                    && (forward->interfaceId == interfaceId))
            {
                return forward;
            }
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: AppForwardGetForwardByNameAndServer.
// PURPOSE    :: search for a forward data structure.
// PARAMETERS ::
// + node : Pointer to the node .
// + localAddr : the local node address
// + remoteAddr : the address of the remote node
// + interfaceName : the name of the interface to find
// + isServer : whether to get the server or client
// RETURN     ::  The pointer to the forward data structure,
//                NULL if not found
// **/
AppDataForward* AppLayerGetForwardByNameAndServer(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    char* interfaceName,
    BOOL isServer)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataForward *forward;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FORWARD)
        {
            forward = (AppDataForward *) appList->appDetail;

            if ((forward->localAddr == localAddr)
                    && (forward->remoteAddr == remoteAddr)
                    && (strcmp(forward->iface->name, interfaceName) == 0)
                    && (forward->isServer == isServer))
            {
                return forward;
            }
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: AppForwardGetForwardByConnectionId.
// PURPOSE    :: search for a forward data structure.
// PARAMETERS ::
// + node : Pointer to the node .
// + connectionId : the connection to search for
// RETURN     ::  The pointer to the forward data structure,
//                NULL if not found
// **/
AppDataForward* AppLayerGetForwardByConnectionId(
    Node *node,
    int connectionId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataForward *forward;

    // Return NULL if no connection specified
    if (connectionId == -1)
    {
        return NULL;
    }

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FORWARD)
        {
            forward = (AppDataForward *) appList->appDetail;

            if (forward->connectionId == connectionId)
            {
                return forward;
            }
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: AppLayerGetForwardByRemoteAndInterfaceIdAndServer.
// PURPOSE    :: search for a forward data structure.
// PARAMETERS ::
// + node : Pointer to the node .
// + remoteAddr : the address of the remote node
// + interfaceId : the interface to find
// + isServer : TRUE if we are server
// RETURN     ::  The pointer to the forward data structure,
//                NULL if not found
// **/
AppDataForward* AppLayerGetForwardByRemoteAndInterfaceIdAndServer(
    Node *node,
    NodeAddress remoteAddr,
    int interfaceId,
    BOOL isServer)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataForward *forward;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FORWARD)
        {
            forward = (AppDataForward *) appList->appDetail;

            if (forward->remoteAddr == remoteAddr
                    && forward->interfaceId == interfaceId
                    && forward->isServer == isServer)
            {
                return forward;
            }
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: AppLayerGetForwardBySourcePort.
// PURPOSE    :: search for a forward data structure.
// PARAMETERS ::
// + node : Pointer to the node .
// + sourcePort : get forward app with this source port
// RETURN     ::  The pointer to the forward data structure,
//                NULL if not found
// **/
AppDataForward* AppLayerGetForwardBySourcePort(
    Node *node,
    int sourcePort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataForward *forward;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_FORWARD)
        {
            forward = (AppDataForward *) appList->appDetail;

            if (forward->sourcePort == sourcePort)
            {
                return forward;
            }
        }
    }

    return NULL;
}

// /**
// FUNCTION   :: UdpHashRequest.
// PURPOSE    :: Stores the fragmented UDP packet in a
//               hash table. This function is called by UDP
//               packet reconstruction code.
// PARAMETERS ::
// + udpFragData : Pointer to the UDP packet reconstruction data
// + messageId : Unique UDP messageId.
// RETURN     ::  Void : NULL
// **/
void FORWARD_UdpRequestHash::UdpHashRequest(
    FORWARD_UdpPacketRecon* udpFragData,
    Int32 messageId)
{
    Int32 udpRequestId = messageId + 1;
    int index = udpRequestId % FORWARD_UDP_HASH_SIZE;

    udpHash[index][udpRequestId] = udpFragData;
}

// /**
// FUNCTION   :: UdpRemoveRequest.
// PURPOSE    :: Removes the UDP packet information from the
//               hash table. It removes the information based on
//               messageId.
// PARAMETERS ::
// + messageId : the UDP packet messageId.
// RETURN     ::  Void : NULL
// **/
void FORWARD_UdpRequestHash::UdpRemoveRequest(Int32 messageId)
{
    Int32 udpRequestId = messageId + 1;
    int index = udpRequestId % FORWARD_UDP_HASH_SIZE;
    std::map<Int32, FORWARD_UdpPacketRecon*>::iterator it;

    it = udpHash[index].find(udpRequestId);

    if (it != udpHash[index].end())
    {
        //Remove it
        //data = it->second;
        udpHash[index].erase(it);
    }
}

// /**
// FUNCTION   :: UdpCheckAndRetrieveRequest.
// PURPOSE    :: Checks and retrievs the UDP Fragment data
//               information from the hash table. The UDP
//               Fragment data is stored in data pointer and
//               TRUE is returned.
// PARAMETERS ::
// + messageId : the UDP packet messageId.
// + data : UDP packet information storing pointer
// RETURN     ::  Bool : TRUE if data found, FALSE otherwise.
// **/
BOOL FORWARD_UdpRequestHash::UdpCheckAndRetrieveRequest(
    Int32 messageId,
    FORWARD_UdpPacketRecon** data)
{
    Int32 udpRequestId = messageId + 1;
    int index = udpRequestId % FORWARD_UDP_HASH_SIZE;
    std::map<Int32, FORWARD_UdpPacketRecon*>::iterator it;
    //FORWARD_UdpPacketRecon* data;

    it = udpHash[index].find(udpRequestId);

    if (it == udpHash[index].end())
    {
        return FALSE;
    }
    else
    {
        // Remove it and return
        *data = it->second;
        //udpHash[index].erase(it);
        return TRUE;
    }
}

Message * ForwardTcpSendNewHeaderVirtualData(
    Node *node,
    int connId,
    char *header,
    int headerLength,
    int payloadSize,
    TraceProtocolType traceProtocol
#ifdef ADDON_DB
    ,
    StatsDBAppEventParam* appParam
#endif
    ,UInt8 ttl)
{
    Message *msg;
    AppToTcpSend *sendRequest;

    msg = MESSAGE_Alloc(
              node,
              TRANSPORT_LAYER,
              TransportProtocol_TCP,
              MSG_TRANSPORT_FromAppSend);

    MESSAGE_InfoAlloc(node, msg, sizeof(AppToTcpSend));
    sendRequest = (AppToTcpSend *) MESSAGE_ReturnInfo(msg);
    sendRequest->connectionId = connId;
    sendRequest->ttl = ttl;

    // Store SockIf_PktHdr header NOT in pkt BUT in info field of comm msg to tx.
    // Assume no real data to send in pkt, ie, the only payload is MTS data (virtual data).
    // Thus MTS data size can be arbitrary, including less than sizeof(SockIf_PktHdr) = 32B.
    if (headerLength > 0)
    {
        MESSAGE_AddInfo(node, msg, headerLength, 
                        INFO_TYPE_SocketInterfacePktHdr);
        memcpy(MESSAGE_ReturnInfo(msg, INFO_TYPE_SocketInterfacePktHdr), 
               header, headerLength);
    }
    // Must call MSG_PktAlloc() even when real pkt size is 0, because MSG_PayloadAlloc() 
    // is called inside the PktAlloc() to allocate space for lower layer headers (TCP, IP, ...)
    MESSAGE_PacketAlloc(node, msg, 0, traceProtocol);

    MESSAGE_AddVirtualPayload(node, msg, payloadSize);

    // Trace for sending packet
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_APPLICATION_LAYER,
              PACKET_OUT, &acnData);

    // Add the TCP Header Info Field
    FORWARD_TcpHeaderInfo* tcpHeaderInfo = NULL;

    // Fill in fragmentation info so packet can be reassembled
    tcpHeaderInfo = (FORWARD_TcpHeaderInfo*) MESSAGE_AddInfo(
                      node,
                      msg,
                      sizeof(FORWARD_TcpHeaderInfo),
                      INFO_TYPE_ForwardTcpHeader);
    ERROR_Assert(tcpHeaderInfo != NULL, "Unable to add an info field!");
    tcpHeaderInfo->packetCreationTime = msg->packetCreationTime;
    tcpHeaderInfo->packetSize = MESSAGE_ReturnPacketSize(msg);
    tcpHeaderInfo->virtualSize = payloadSize;

#ifdef ADDON_DB
    if (appParam != NULL)
    {
        appParam->SetPacketCreateTime(msg->packetCreationTime);
        HandleStatsDBAppSendEventsInsertion(
            node,
            msg,
            tcpHeaderInfo->packetSize,
            appParam);
    }
#endif

    MESSAGE_Send(node, msg, 0);
    return msg;
}


Message* ForwardTcpSendData(
    Node *node,
    int connId,
    char *payload,
    int length,
    TraceProtocolType traceProtocol
#ifdef ADDON_DB
    , StatsDBAppEventParam* appParam
#endif
    ,UInt8 ttl)

{
    Message *msg;
    AppToTcpSend *sendRequest;
    ActionData acnData;

    msg = MESSAGE_Alloc(
              node,
              TRANSPORT_LAYER,
              TransportProtocol_TCP,
              MSG_TRANSPORT_FromAppSend);

    MESSAGE_InfoAlloc(node, msg, sizeof(AppToTcpSend));
    sendRequest = (AppToTcpSend *) MESSAGE_ReturnInfo(msg);
    sendRequest->connectionId = connId;
    sendRequest->ttl = ttl;
    MESSAGE_PacketAlloc(node, msg, length, traceProtocol);
    memcpy(MESSAGE_ReturnPacket(msg), payload, length);

    //Trace Information
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_APPLICATION_LAYER,
        PACKET_OUT, &acnData);

    // Add the TCP Header Info Field
    FORWARD_TcpHeaderInfo* tcpHeaderInfo = NULL;

    // Fill in fragmentation info so packet can be reassembled
    tcpHeaderInfo = (FORWARD_TcpHeaderInfo*) MESSAGE_AddInfo(
                      node,
                      msg,
                      sizeof(FORWARD_TcpHeaderInfo),
                      INFO_TYPE_ForwardTcpHeader);

    ERROR_Assert(tcpHeaderInfo != NULL, "Unable to add an info field!");
    tcpHeaderInfo->packetCreationTime = node->getNodeTime();
    tcpHeaderInfo->packetSize = MESSAGE_ReturnPacketSize(msg);
    tcpHeaderInfo->virtualSize = 0;

#ifdef ADDON_DB
    if (appParam != NULL)
    {
        HandleStatsDBAppSendEventsInsertion(node, msg, length, appParam);
    }
#endif
    MESSAGE_Send(node, msg, 0);
    return msg;
}
