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
// PROTOCOL     :: Queue-Scheduler
// LAYER        ::
// REFERENCES   ::
// Simulate RED as described in:
// + Sally Floyd and Van Jacobson,
//  "Random Early Detection For Congestion Avoidance",
//  IEEE/ACM Transactions on Networking, August 1993.
// COMMENTS     :: None
//
// NOTES:    This implementation only drops packets, it does mark them
//           when ECN is enabled
//
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <map>

#include "api.h"
#include "network_ip.h"
#include "ipv6.h"
#ifdef ENTERPRISE_LIB
// This has been added as part of IP-MPLS Task
#include "mpls_shim.h"
#endif // ENTERPRISE_LIB

#include "if_queue.h"
#include "queue_red.h"
#include "queue_red_ecn.h"
#include "queue_wred_ecn.h"

//--------------------------------------------------------------------------
// Start: Utility Functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: EcnRedQueue::GetTosFromMsgHeader
// LAYER      ::
// PURPOSE    :: Returns TOS | T_CLASS from Message ip Header.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// RETURN     :: int : Integer
// **/

int EcnRedQueue::GetTosFromMsgHeader(Message* msg)
{

    IpHeaderType* ipHeader = NULL;
    char *payload = (char*) MESSAGE_ReturnPacket(msg);

    if (msg->headerProtocols[msg->numberOfHeaders - 1] == TRACE_LLC)
    {
        LlcHeader* llcHeader = (LlcHeader*) payload;
        if (llcHeader->etherType == PROTOCOL_TYPE_ARP)
        {
            return IPTOS_PREC_INTERNETCONTROL;
        }

        payload = payload + sizeof(LlcHeader);

#ifdef ENTERPRISE_LIB
        if (llcHeader->etherType == PROTOCOL_TYPE_MPLS)
        {
            payload = payload + sizeof(Mpls_Shim_LabelStackEntry);
        }
#endif // ENTERPRISE_LIB
    }

    ipHeader = (IpHeaderType*) payload;

    if (IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len) == IPVERSION4)
    {
        return IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    }
    else // IPv6
    {
        ip6_hdr* ipv6Header = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

        return ip6_hdrGetClass(ipv6Header->ipv6HdrVcf);
    }
    // Unreachable code, may be used in future
    //return IPTOS_PREC_ROUTINE; // Defaulted to best effort
}

// /**
// FUNCTION   :: EcnRedQueue::SetCeBitInMsgHeader
// LAYER      ::
// PURPOSE    :: Returns TOS | T_CLASS from Message ip Header.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// RETURN     :: void : Null
// **/

void EcnRedQueue::SetCeBitInMsgHeader(Message* msg)
{
    IpHeaderType* ipHeader = NULL;
    char *payload = (char*) MESSAGE_ReturnPacket(msg);

    if (msg->headerProtocols[msg->numberOfHeaders - 1] == TRACE_LLC)
    {
        LlcHeader* llcHeader = (LlcHeader*) payload;
        if (llcHeader->etherType == PROTOCOL_TYPE_ARP)
        {
            return;
        }

        payload = payload + sizeof(LlcHeader);

#ifdef ENTERPRISE_LIB
        if (llcHeader->etherType == PROTOCOL_TYPE_MPLS)
        {
            payload = payload + sizeof(Mpls_Shim_LabelStackEntry);
        }
#endif // ENTERPRISE_LIB
    }

    ipHeader = (IpHeaderType*) payload;

    if (IpHeaderGetVersion(ipHeader->ip_v_hl_tos_len) == IPVERSION4)
    {
        IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len),
            (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) | IPTOS_CE));
    }
    else // IPv6
    {
        ip6_hdr* ipv6Header = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

        ip6_hdrSetClass(&(ipv6Header->ipv6HdrVcf),
            (ip6_hdrGetClass(ipv6Header->ipv6HdrVcf) | IPTOS_CE));
    }
}


// /**
// FUNCTION   :: EcnRedQueue::ReturnPhbForDs
// LAYER      ::
// PURPOSE    :: Returns phb parameters for RED reading
//               either from file or *.config.
// PARAMETERS ::
// + red : const RedEcnParameters* : The pointer to Red Queue structure
//              unsigned char ds; The dscp or IP TOS field of the packet
// + ds : const unsigned int : ds value
// + wasFound : BOOL* : Status of found of phb parameter.
// RETURN     :: PhbParameters* : PhbParameters
// **/

PhbParameters* EcnRedQueue::ReturnPhbForDs(
    const RedEcnParameters* red,
    const unsigned int ds,
    BOOL* wasFound)
{
    int i;

    for (i = 1; i < red->numPhbParams; i++)
    {
        if (red->phbParams[i].ds == ds)
        {
            *wasFound = TRUE;
            return &(red->phbParams[i]);
        }
    }

    *wasFound = FALSE;
    return &(red->phbParams[0]);
}


// /**
// FUNCTION   :: EcnRedQueue::MarkThePacket
// LAYER      ::
// PURPOSE    :: Determines the probability of dropping or marking
// PARAMETERS ::
// + phbParam : PhbParameters* : pointer to PhbParameters structure
// + averageQueueSize : double : Average queue size.
// + packetCount : int* : Number of packets marked as ECN
// + isBetweenMinthMaxth : BOOL* : Status of mark or drop the packet
// + isECTset : BOOL : Status of ECT bit setting
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL EcnRedQueue::MarkThePacket(
    PhbParameters* phbParam,
    double averageQueueSize,
    int* packetCount,
    BOOL* isBetweenMinthMaxth,
    BOOL isECTset)
{
    double pbresult;             // probability
    double paresult;             // current packet marking probability
    double tmpNo;                // temporary Random number

    // if Average queue size is between min and max threshold then
    // calculate probability and mark/drop the packet based on
    // probability

    if ((averageQueueSize >= phbParam->minThreshold) &&
        (averageQueueSize < phbParam->maxThreshold))
    {
        // Increase the Counter
        (*packetCount)++;

        // Calculate the probability
        pbresult = phbParam->maxProbability
            * (averageQueueSize - phbParam->minThreshold)
            / (phbParam->maxThreshold - phbParam->minThreshold);

        if ((*packetCount * pbresult) >= 1.0)
        {
            paresult = 1.0;
        }
        else
        {
            paresult = pbresult / (1 - (*packetCount * pbresult));
        }

        // A random number is generated and compared to the probability of
        // marking the packet.  If the random number is less than the
        // probability value, then the packet is marked.

        tmpNo = RANDOM_erand(randomDropSeed);

        if (tmpNo <= paresult)
        {
            // Mark or drop the packet
            if (isECTset)
            {
                *isBetweenMinthMaxth = TRUE;
            }
            else
            {
                *isBetweenMinthMaxth = FALSE;
            }

            *packetCount = 0;
            return TRUE;
        }
        else
        {
            // Allow the packet in the queue
            return FALSE;
        }
    }
    else
    if ((averageQueueSize >= phbParam->maxThreshold))
    {
         // Drop the packet
        *packetCount = 0;
        *isBetweenMinthMaxth = FALSE;
        return TRUE;
    }
    else
    {
        // Allow the packet in the queue
        *packetCount = -1;
        return FALSE;
    }
}


// /**
// FUNCTION   :: EcnRedQueue::RedEcnQueueFinalize
// LAYER      ::
// PURPOSE    :: Prints status for RED and its variants
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + intfIndexStr : const char* : the intfIndexStr parameter
// + instanceId : const int : Instance Ids
// + stats : const RedEcnStats* : The pointer to RedEcnStats
// + redVariantString : const char* : Acessing the string "RED" or
//                                    "RIO" or "WRED".
// + profileString : const char* : Acessing profileString
// RETURN     :: void : Null
// **/

void EcnRedQueue::RedEcnQueueFinalize(
    Node* node,
    const char* layer,
    const char* intfIndexStr,
    const int instanceId,
    const RedEcnStats* stats,
    const char* redVariantString,
    const char* profileString)
{
    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "(%s) Packets Queued = %d",
            profileString, stats->numPacketsQueued);
    IO_PrintStat(
        node,
        layer,
        redVariantString,
        intfIndexStr,
        instanceId,
        buf);

    sprintf(buf, "(%s) Packets Dequeued = %d",
            profileString, stats->numPacketsDequeued);
    IO_PrintStat(
        node,
        layer,
        redVariantString,
        intfIndexStr,
        instanceId,
        buf);

    sprintf(buf, "(%s) Packets Marked ECN = %d",
            profileString, stats->numPacketsECNMarked);
    IO_PrintStat(
        node,
        layer,
        redVariantString,
        intfIndexStr,
        instanceId,
        buf);

    sprintf(buf, "(%s) Packets Dropped = %d",
            profileString, stats->numPacketsDropped);
    IO_PrintStat(
        node,
        layer,
        redVariantString,
        intfIndexStr,
        instanceId,
        buf);
}
//--------------------------------------------------------------------------
// End: Utility Functions
//--------------------------------------------------------------------------

//--------------------------------------------------------------------------
// Start: Public Interface functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: EcnRedQueue::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to insert
//               a message into it.  The infoField parameter has a specified
//               size infoFieldSize, which is set at Initialization, and
//               points to the structure that should be stored along
//               with the Message.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + infoField : const void* : The infoField parameter(NOTE :The infoField
//                             parameter is not yet handled)
// + QueueIsFull : BOOL* : returns Queue occupancy status
// + currentTime : const clocktype : current Simulation time
// + serviceTag : const double : serviceTag
// RETURN     :: void : Null
// **/

void EcnRedQueue::insert(
    Message* msg,
    const void* infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    const double serviceTag)
{
    insert(msg, infoField, QueueIsFull, currentTime, NULL, serviceTag);
}
void EcnRedQueue::insert(
    Message* msg,
    const void* infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    TosType* tos,
    const double serviceTag
    )
{
    BOOL notUsed = FALSE;
    BOOL isBetweenMinthMaxth = FALSE;
    BOOL isECTset = FALSE;
    BOOL wasEcnMarked = FALSE;

    int ip_tos;

    if (tos == NULL)
    {
        ip_tos = GetTosFromMsgHeader(msg);
    }
    else
    {
       ip_tos = (int) *tos;
    }

    PhbParameters* phbParam = ReturnPhbForDs(redEcnParams,
                                             ip_tos >> 2,
                                             &notUsed);

    if (ip_tos & IPTOS_CE)
    {
        wasEcnMarked = TRUE;
    }

    if (ip_tos & IPTOS_ECT)
    {
        isECTset = TRUE;
    }

    if (!(MESSAGE_ReturnPacketSize(msg) <= (queueSizeInBytes - bytesUsed)))
    {
        // No space for this item in the queue
        *QueueIsFull = TRUE;

        if (isCollectStats)
        {
            Queue::stats->DropPacket(msg, bytesUsed, currentTime);
        }
#ifdef ADDON_BOEINGFCS
        if (collectDscpStats)
        {
            QueuePerDscpStats *statsEntry = NULL;
            statsEntry = QueueGetPerDscpStatEntry(msg, dscpStats);
            statsEntry->numPacketsDropped++;
        }
#endif

        if (isCollectStats)
        {
            RedEcnStats *stats = phbParam->stats;
            stats->numPacketsDropped++;
            stats->numBytesDropped += MESSAGE_ReturnPacketSize(msg);
        }
        return;
    }

    // Update Average Queue Size.
    UpdateAverageQueueSize(
        isEmpty(),
        packetsInQueue(),
        redEcnParams->queueWeight,
        redEcnParams->typicalSmallPacketTransmissionTime,
        startIdleTime,
        &averageQueueSize,
        currentTime);

    if (MarkThePacket(
            phbParam,
            averageQueueSize,
            &packetCount,
            &isBetweenMinthMaxth,
            isECTset))
    {
        // When a router has decided from its active queue management
        // mechanism, to drop or mark a packet, it checks the IP-ECT bit in the
        // packet header. It sets the CE bit in the IP header if the IP-ECT bit
        //  is set.

        if (redEcnParams->isEcn && isECTset && isBetweenMinthMaxth)
        {
            if (tos == NULL)
            {
                SetCeBitInMsgHeader(msg);
                ip_tos = GetTosFromMsgHeader(msg);
            }
            else
            {
                *tos |= IPTOS_CE ;
                ip_tos = (int) *tos ;
            }
        }
        else
        {
            *QueueIsFull = TRUE;
            if (isCollectStats)
            {
                Queue::stats->DropPacket(msg, bytesUsed, currentTime);
            }
#ifdef ADDON_BOEINGFCS
            if (collectDscpStats)
            {
                QueuePerDscpStats *statsEntry = NULL;
                statsEntry = QueueGetPerDscpStatEntry(msg, dscpStats);
                statsEntry->numPacketsDropped++;
            }
#endif

            if (isCollectStats)
            {
                RedEcnStats *stats = phbParam->stats;

                stats->numPacketsDropped++;
                stats->numBytesDropped += MESSAGE_ReturnPacketSize(msg);
            }
            return;
        }
    }

    int dscp = ip_tos >> 2;
    UInt64 key = (*msg).originatingNodeId;
    key <<= 32;
    key |= (*msg).sequenceNumber;
    queue_profile[key] = dscp;

    // Inserting a packet in the queue

    Queue::insert(msg,
                  infoField,
                  QueueIsFull,
                  currentTime,
                  serviceTag);

    if (isCollectStats)
    {
        // Update statistical variables.
        RedEcnStats *stats = phbParam->stats;

        if ((!wasEcnMarked) && (ip_tos & IPTOS_CE))
        {
            stats->numPacketsECNMarked++;
            numPacketsECNMarked++;
        }

        if (*QueueIsFull)
        {
            stats->numPacketsDropped++;
            stats->numBytesDropped += MESSAGE_ReturnPacketSize(msg);
        }
        else
        {
            stats->numPacketsQueued++;
#ifdef ADDON_BOEINGFCS
            if (collectDscpStats)
            {
                QueuePerDscpStats *statsEntry = NULL;
                statsEntry = QueueGetPerDscpStatEntry(msg, dscpStats);
                statsEntry->numPacketsQueued++;
            }
#endif
            stats->numBytesQueued += MESSAGE_ReturnPacketSize(msg);
        }
    }
}


// /**
// FUNCTION   :: EcnRedQueue::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to dequeue,
//               peek at, or drop a message in its array of stored messages.
//               It now includes the "DropFunction" functionality as well.
// PARAMETERS ::
// + msg : Message** : The retrieved msg
// + index : const int : The position of the packet in the queue
// + operation : const QueueOperation : the retrieval mode
// + currentTime : const clocktype : current Simulation time
// + serviceTag : double* : serviceTag
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL EcnRedQueue::retrieve(
    Message** msg,
    const int index,
    const QueueOperation operation,
    const clocktype currentTime,
    double* serviceTag)
{
    BOOL isPacketRetrieve = FALSE;
    // Dequeueing a packet from the queue
    isPacketRetrieve = Queue::retrieve(msg,
                                        index,
                                        operation,
                                        currentTime,
                                        serviceTag);

    if ((operation == DEQUEUE_PACKET) || (operation == DISCARD_PACKET))
    {
        if (isEmpty())
        {
            // Start of queue idle time
            startIdleTime = currentTime;
        }

        UInt64 key = (**msg).originatingNodeId;
        key <<= 32;
        key |= (**msg).sequenceNumber;
        int dscp = queue_profile[key];
        queue_profile.erase(key);

        if (isCollectStats)
        {
            // Update statistical variables
            BOOL notUsed = FALSE;

            PhbParameters *phbParam = ReturnPhbForDs(redEcnParams,
                                                   dscp,&notUsed);
            RedEcnStats *stats = phbParam->stats;

            if (operation == DEQUEUE_PACKET)
            {
                stats->numPacketsDequeued++;
#ifdef ADDON_BOEINGFCS
                if (collectDscpStats)
                {
                    QueuePerDscpStats *statsEntry = NULL;
                    statsEntry = QueueGetPerDscpStatEntry((*msg), dscpStats);
                    statsEntry->numPacketsDequeued++;
                }
#endif
                stats->numBytesDequeued += MESSAGE_ReturnPacketSize((*msg));
            }

            if (operation == DISCARD_PACKET)
            {
                stats->numPacketsDropped++;
                stats->numBytesDropped += MESSAGE_ReturnPacketSize((*msg));
            }
        }
    }

    return isPacketRetrieve;
}


// /**
// FUNCTION   :: EcnRedQueue::replicate
// LAYER      ::
// PURPOSE    :: This function is proposed to replicate the state of the
//               queue, as if it had been the operative queue all along.
//               If there are packets in the existing queue, they are
//               transferred one-by-one into the new queue. This can result
//               in additional drops of packets that had previously been
//               stored. This function returns the number of additional
//               drops
// PARAMETERS ::
// + oldQueue : Queue* : old packetArray
// RETURN     :: int : Interger
// **/

int EcnRedQueue::replicate(Queue* oldQueue)
{
    int numExtraDrop = 0;
    numExtraDrop = Queue::replicate(oldQueue);

    // Replicate RED specific enties
    if (isCollectStats)
    {
        // Assuming that all statistics in old Queue belongs
        // to default PHB only

        RedEcnStats* stats = redEcnParams->phbParams[0].stats;

        stats->numPacketsQueued = (int)Queue::stats->GetPacketsEnqueued().GetValue(node->getNodeTime());
        stats->numPacketsDequeued = (int)Queue::stats->GetPacketsDequeued().GetValue(node->getNodeTime());
        stats->numPacketsDropped = (int)Queue::stats->GetPacketsDropped().GetValue(node->getNodeTime());
        stats->numBytesQueued = (int)Queue::stats->GetBytesEnqueued().GetValue(node->getNodeTime());
        stats->numBytesDequeued = (int)Queue::stats->GetBytesDequeued().GetValue(node->getNodeTime());;
        stats->numBytesDropped = (int)Queue::stats->GetBytesDropped().GetValue(node->getNodeTime());;
    }

    return numExtraDrop;
}


// /**
// FUNCTION   :: EcnRedQueue::finalize
// LAYER      ::
// PURPOSE    :: This function prototype outputs the final statistics for
//               this queue. The layer, protocol, interfaceAddress, and
//               instanceId parameters are given to IO_PrintStat with each
//               of the queue's statistics.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + interfaceIndex : const int : Interface index
// + instanceId : const int : Instance Ids
// + invokingProtocol : const char* : The protocol string
// RETURN     :: void : Null
// **/

void EcnRedQueue::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const int instanceId,
    const char* invokingProtocol,
    const char* splStatStr)
{
    int i;
    PhbParameters* phbParam = NULL;
    RedEcnStats* stats = NULL;
    char buf[MAX_STRING_LENGTH];
    char queueType[MAX_STRING_LENGTH] = { "RED" };
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    if (!isCollectStats)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP") == 0)
    {
        // IP queue finalization
        NetworkIpGetInterfaceAddressString(node,
                                           interfaceIndex,
                                           intfIndexStr);
    }
    else
    {
        memset(queueType, 0, MAX_STRING_LENGTH);
        sprintf(queueType, "%s RED", invokingProtocol);
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    if (redEcnParams->numPhbParams > 1)
    {
        for (i = 0; i < redEcnParams->numPhbParams; i++)
        {
            phbParam = &redEcnParams->phbParams[i];
            stats = phbParam->stats;

            sprintf(buf, "DSCP %d", (unsigned char) phbParam->ds);

            // Print DSCP specific stats
            RedEcnQueueFinalize(node,
                            layer,
                            intfIndexStr,
                            instanceId,
                            stats,
                            queueType,
                            buf);
        }
    }

    // Calling GenericQueueFinalize Function
    FinalizeQueue(node,
                  layer,
                  queueType,
                  interfaceIndex,
                  instanceId,
                  invokingProtocol);

    // Printing ECN statistic for each queue.
    sprintf(buf, "Packets Marked ECN = %d", numPacketsECNMarked);
    IO_PrintStat(
        node,
        layer,
        queueType,
        intfIndexStr,
        instanceId, //priority,
        buf);
}


// /**
// FUNCTION   :: EcnRedQueue::SetupQueue
// LAYER      ::
// PURPOSE    :: This function is proposed for RED queue initialization
// PARAMETERS ::
// + node : Node* : node
// + queueTypeString[] : const char : queue type string
// + queueSize : const int : queue size
// + interfaceIndex : const int : used for setting random seed
// + queueNumber : const int : used for setting random seed
// + infoFieldSize : const int : infoFieldSize
// + enableQueueStat : const BOOL : queue statistics
// + showQueueInGui : const BOOL : If want to show this Queue in GUI
//                                 Default value is false;
// + currentTime : const clocktype : Current simulation time
// + configInfo : const void* : pointer to a structure that contains
//                              configuration parameters for a Queue Type.
//                              This is not required for FIFO. Is it is
//                              found NULL for any other Queue Type the
//                              default setting will be applied for that
//                              queue Type. Default value is NULL
// RETURN     :: void : Null
// **/

void EcnRedQueue::SetupQueue(
    Node* node,
    const char queueTypeString[],
    const int queueSize,
    const int interfaceIndex,
    const int queueNumber,
    const int infoFieldSize,
    const BOOL enableQueueStat,
    const BOOL showQueueInGui,
    const clocktype currentTime,
    const void* configInfo
#ifdef ADDON_DB
    ,const char* queuePosition
#endif
    , const clocktype maxPktAge
#ifdef ADDON_BOEINGFCS
    ,const BOOL enablePerDscpStat
    ,Scheduler* repSched
    ,Queue* repQueue
#endif
    )
{
    Queue::SetupQueue(node,
                      queueTypeString,
                      queueSize,
                      interfaceIndex,
                      queueNumber,
                      infoFieldSize,
                      enableQueueStat,
                      showQueueInGui
#ifdef ADDON_DB
                      ,0, NULL, queuePosition
#else
                      ,currentTime, configInfo
#endif
                      , maxPktAge
#ifdef ADDON_BOEINGFCS
                      ,enablePerDscpStat
                      ,repSched
                      ,repQueue
#endif
                      );

    // Initialization of Red queue variables
    RANDOM_SetSeed(randomDropSeed,
                   node->globalSeed,
                   node->nodeId,
                   interfaceIndex,
                   queueNumber);

    averageQueueSize = 0.0;
    packetCount = -1;

    startIdleTime = currentTime;

    numPacketsECNMarked = 0;

    if (configInfo == NULL)
    {
        int i = 0;
        redEcnParams = (RedEcnParameters*)
            MEM_malloc(sizeof (RedEcnParameters));
        memset(redEcnParams, 0, sizeof (RedEcnParameters));

        if (DEBUG_PLUG_N_PLAY)
        {
            printf ("RED: Initiate Pulg-n-Play\n");
        }

        // Initiate Pulg-n-Play by assigning default values
        redEcnParams->isEcn = TRUE;

        redEcnParams->numPhbParams = 1;
        redEcnParams->maxPhbParams = redEcnParams->numPhbParams;

        redEcnParams->queueWeight = DEFAULT_RED_QUEUE_WEIGHT;
        redEcnParams->typicalSmallPacketTransmissionTime
                    = DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME;

        redEcnParams->phbParams = (PhbParameters*)
            MEM_malloc(sizeof(PhbParameters) * redEcnParams->numPhbParams);

        for (i = 0; i < redEcnParams->numPhbParams; i++)
        {
            redEcnParams->phbParams[i].minThreshold
                                = DEFAULT_RED_MIN_THRESHOLD;
            redEcnParams->phbParams[i].maxThreshold
                                = DEFAULT_RED_MAX_THRESHOLD;
            redEcnParams->phbParams[i].maxProbability
                                = DEFAULT_RED_MAX_PROBABILITY;
            redEcnParams->phbParams[i].stats = (RedEcnStats*)
                                    MEM_malloc(sizeof (RedEcnStats));

            if (DEBUG_PLUG_N_PLAY)
            {
                fprintf(stdout, "\n\n$ RED Plug-n-Play enabled\n"
                    ".................................................\n"
                    "RED-MIN-THRESHOLD     5\n"
                    "RED-MAX-THRESHOLD     15\n"
                    "RED-MAX-PROBABILITY   0.02\n"
                    "RED-QUEUE-WEIGHT      0.002\n"
                    "RED-SMALL-PACKET-TRANSMISSION-TIME   10MS\n"
                    ".................................................\n");
            }
        }
    }
    else
    {
        // Reading Red parameters from configuration files.
        this->redEcnParams = (RedEcnParameters*) configInfo;
    }
}

#ifdef ADDON_BOEINGFCS
void EcnRedQueue::signalCongestion(Node* node,
                                   int interfaceIndex,
                                   Message* msg)
{
}
#endif

//--------------------------------------------------------------------------
// End: Public Interface functions
//--------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Start: Read and configure RedEcnParameters
// -------------------------------------------------------------------------

// /**
// FUNCTION   :: InitializeRedEcnStats
// LAYER      ::
// PURPOSE    :: Allocate memory for, and initialize statistics
// PARAMETERS ::
// + stats : RedEcnStats** : The pointer to Red Statistics structure
// RETURN     :: void : Null
// **/

void InitializeRedEcnStats(RedEcnStats** stats)
{
    *stats = (RedEcnStats*) MEM_malloc(sizeof(RedEcnStats));

    memset(*stats, 0, sizeof(RedEcnStats));
}


// /**
// FUNCTION   :: RedReturnPhbForDs
// LAYER      ::
// PURPOSE    :: Returns phb parameters for RED reading
// PARAMETERS ::
// + red : const RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// + ds : const unsigned char : The dscp or IP TOS field of the packet
// + wasFound : BOOL* : Status of the parameter found
// RETURN     :: PhbParameters* : pointer to PhbParameters structure
// **/

static
PhbParameters* RedReturnPhbForDs(
    const RedEcnParameters* red,
    const unsigned char ds,
    BOOL* wasFound)
{
    int i;

    for (i = 1; i < red->numPhbParams; i++)
    {
        if (red->phbParams[i].ds == ds)
        {
            *wasFound = TRUE;
            return &(red->phbParams[i]);
        }
    }

    *wasFound = FALSE;
    return &(red->phbParams[0]);
}


// /**
// FUNCTION   :: RedAddPhbForDs
// LAYER      ::
// PURPOSE    :: Allocates memory for and returns Phb parameters
// PARAMETERS ::
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// + ds : const unsigned char : The dscp or IP TOS field of the packet
// + isCollectStats : const BOOL : Returns status of statistic collection
// RETURN     :: PhbParameters* : pointer to PhbParameters structure
// **/

static
PhbParameters* RedAddPhbForDs(
    RedEcnParameters* red,
    const unsigned char ds,
    const BOOL isCollectStats)
{
    int numParams = red->numPhbParams;

    if (numParams == red->maxPhbParams)
    {
        PhbParameters *nextPhbParams =
            (PhbParameters *) MEM_malloc(
                sizeof(PhbParameters) *
                    (numParams + INITIAL_NUM_PHB_ENTRIES));

        memcpy(nextPhbParams, red->phbParams,
               sizeof(PhbParameters) * numParams);

        MEM_free(red->phbParams);

        red->phbParams = nextPhbParams;
        red->maxPhbParams += INITIAL_NUM_PHB_ENTRIES;
    }

    red->phbParams[numParams].ds = ds;
    red->phbParams[numParams].minThreshold = red->phbParams[0].minThreshold;
    red->phbParams[numParams].maxThreshold = red->phbParams[0].maxThreshold;
    red->phbParams[numParams].maxProbability
                                        = red->phbParams[0].maxProbability;

    if (isCollectStats)
    {
        InitializeRedEcnStats(&(red->phbParams[numParams].stats));
    }

    red->numPhbParams++;

    return &(red->phbParams[numParams]);
}

// /**
// FUNCTION   :: RedAddMinThresholdToPhb
// LAYER      ::
// PURPOSE    :: Returns MinThreshold parameters
// PARAMETERS ::
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// + ds : const unsigned char : The dscp or IP TOS field of the packet
// + value : const double : Accessing the (int) value of minth
// + isCollectStats : const BOOL : Returns status of statistic collection
// RETURN     :: void : Null
// **/
static
void RedAddMinThresholdToPhb(
    RedEcnParameters* red,
    const unsigned char ds,
    const double value,
    const BOOL isCollectStats)
{
    BOOL wasFound;
    PhbParameters* phbParam = RedReturnPhbForDs(red, ds, &wasFound);

    if (!wasFound)
    {
        phbParam = RedAddPhbForDs(red, ds, isCollectStats);
    }

    phbParam->minThreshold = (int) value;
}


// /**
// FUNCTION   :: RedAddMaxThresholdToPhb
// LAYER      ::
// PURPOSE    :: Returns MaxThreshold parameters
// PARAMETERS ::
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// + ds : const unsigned char : The dscp or IP TOS field of the packet
// + value : const double : Accessing the (int) value of minth
// + isCollectStats : const BOOL : Returns status of statistic collection
// RETURN     :: void : Null
// **/
static
void RedAddMaxThresholdToPhb(
    RedEcnParameters* red,
    const unsigned char ds,
    const double value,
    const BOOL isCollectStats)
{
    BOOL wasFound = FALSE;
    PhbParameters* phbParam = RedReturnPhbForDs(red, ds, &wasFound);

    if (!wasFound)
    {
        phbParam = RedAddPhbForDs(red, ds, isCollectStats);
    }

    phbParam->maxThreshold = (int) value;
}


// /**
// FUNCTION   :: RedAddMaxProbabilityToPhb
// LAYER      ::
// PURPOSE    :: Returns MaxProbability parameters
// PARAMETERS ::
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// + ds : const unsigned char : The dscp or IP TOS field of the packet
// + value : const double : Accessing the (int) value of minth
// + isCollectStats : const BOOL : Returns status of statistic collection
// RETURN     :: void : Null
// **/
static
void RedAddMaxProbabilityToPhb(
    RedEcnParameters* red,
    const unsigned char ds,
    const double value,
    const BOOL isCollectStats)
{
    BOOL wasFound = FALSE;
    PhbParameters* phbParam = RedReturnPhbForDs(red, ds, &wasFound);

    if (!wasFound)
    {
        phbParam = RedAddPhbForDs(red, ds, isCollectStats);

    }

    phbParam->maxProbability = value;
}


// /**
// FUNCTION   :: ReadRed_EcnCommonConfigurationParams
// LAYER      ::
// PURPOSE    :: This function reads configuration parameters from
//               QualNet .config file.[NOTE : This Function have layer
//               dependency (arg: interfaceAddress)]
//               because of existing QualNet IO's.]
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN     :: void : Null
// **/

void ReadRed_EcnCommonConfigurationParams(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters* red)
{
    BOOL retVal = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};
    int nodeId = node->nodeId;

    IO_ReadString(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "ECN",
        &retVal,
        buf);

    if (retVal && (!strcmp(buf, "YES")))
    {
        red->isEcn = TRUE;
    }
    else
    {
        red->isEcn = FALSE;
    }

    IO_ReadTimeInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-SMALL-PACKET-TRANSMISSION-TIME",
        queueIndex,  // parameterInstanceNumber
        TRUE,      // fallbackIfNoInstanceMatch
        &retVal,
        &(red->typicalSmallPacketTransmissionTime));

    if (!retVal)
    {
        red->typicalSmallPacketTransmissionTime =
            DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME;
    }

    IO_ReadDoubleInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-QUEUE-WEIGHT",
        queueIndex,  // parameterInstanceNumber
        TRUE,      // fallbackIfNoInstanceMatch
        &retVal,
        &(red->queueWeight));

    if (!retVal)
    {
        red->queueWeight = DEFAULT_RED_QUEUE_WEIGHT;
    }
}


// /**
// FUNCTION   :: ReadRed_EcnConfigurationThParameters
// LAYER      ::
// PURPOSE    :: This function reads configuration parameters from
//               QualNet .config file[NOTE : This Function have layer
//               dependency for existing QualNet IO's.].
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN     :: void : Null
// **/
static
void ReadRed_EcnConfigurationThParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters* red)
{
    BOOL retVal = FALSE;
    int nodeId = node->nodeId;

    ReadRed_EcnCommonConfigurationParams(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    queueIndex,
                                    red);

    // Read Red Thresholds
    red->numPhbParams = 1;
    red->phbParams = (PhbParameters *) MEM_malloc(sizeof(PhbParameters));
    memset(red->phbParams, 0, sizeof(PhbParameters));
    InitializeRedEcnStats(&red->phbParams->stats);

    IO_ReadIntInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-MIN-THRESHOLD",
        queueIndex,   // parameterInstanceNumber
        TRUE,       // fallbackIfNoInstanceMatch
        &retVal,
        &(red->phbParams->minThreshold));

    if (retVal == FALSE)
    {
        red->phbParams->minThreshold = DEFAULT_RED_MIN_THRESHOLD;
    }
    else
    {
       ERROR_Assert(red->phbParams->minThreshold > 0.0,
                "RED minThreshold should be > 0.0\n");
    }


    IO_ReadIntInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-MAX-THRESHOLD",
        queueIndex,  // parameterInstanceNumber
        TRUE,      // fallbackIfNoInstanceMatch
        &retVal,
        &(red->phbParams->maxThreshold));

    if (retVal == FALSE)
    {
        red->phbParams->maxThreshold = DEFAULT_RED_MAX_THRESHOLD;
    }
    else
    {
       ERROR_Assert(red->phbParams->maxThreshold > 0.0,
                "RED maxThreshold should be > 0.0\n");
    }

    ERROR_Assert(red->phbParams->minThreshold <
        red->phbParams->maxThreshold,
        "RED maxThreshold should be greater than minThreshold\n");

    IO_ReadDoubleInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-MAX-PROBABILITY",
        queueIndex,  // parameterInstanceNumber
        TRUE,                // fallbackIfNoInstanceMatch
        &retVal,
        &(red->phbParams->maxProbability));

    if (retVal == FALSE)
    {
    red->phbParams->maxProbability = DEFAULT_RED_MAX_PROBABILITY;
    }

    else
    {

    ERROR_Assert(red->phbParams->maxProbability < 1.0 &&
        red->phbParams->maxProbability > 0.0,
        "Red maxProbability should be <= 1.0 and should be > 0.0\n");
    }
}


// /**
// FUNCTION   :: ReadRed_EcnConfigurationParameters
// LAYER      ::
// PURPOSE    :: This function reads Multilevel, ECN enabled RED
//               configuration parameters from QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + redEcnParams : RedEcnParameters** : Pointer of pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN     :: void : Null
// **/
void ReadRed_EcnConfigurationParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters** redEcnParams)
{
    NodeInput phbInput;
    BOOL retVal = FALSE;
    RedEcnParameters* red = NULL;
    int nodeId = node->nodeId;

    red = (RedEcnParameters*) MEM_malloc(sizeof(RedEcnParameters));
    memset(red, 0, sizeof(RedEcnParameters));

    ReadRed_EcnConfigurationThParameters(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    queueIndex,
                                    red);

    IO_ReadCachedFile(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "PER-HOP-BEHAVIOR-FILE",
        &retVal,
        &phbInput);

    if (retVal)
    {
        int i;
        PhbParameters* nextPhbParams
            = (PhbParameters *) MEM_malloc(sizeof(PhbParameters)
            * (red->numPhbParams + INITIAL_NUM_PHB_ENTRIES));

        memcpy(nextPhbParams, red->phbParams, sizeof(PhbParameters));
        MEM_free(red->phbParams);

        red->phbParams = nextPhbParams;
        red->maxPhbParams = INITIAL_NUM_PHB_ENTRIES;

        for (i = 0; i < phbInput.numLines; i++)

        {
            char identifier[MAX_STRING_LENGTH];

            sscanf(phbInput.inputStrings[i], "%s", identifier);

            if (strcmp(identifier, "RED") == 0)
            {
                int items;
                char parameterName[MAX_STRING_LENGTH];
                int ds;
                double value;

                items = sscanf(phbInput.inputStrings[i], "%*s %d %s %lf",
                       &ds, parameterName, &value);

                ERROR_Assert(items == 3, "PHB Mapping File: RED entries"
                        "expect <ds> <parameter> <value>\n");

                if (strcmp(parameterName, "RED-MIN-THRESHOLD") == 0)
                {
                    RedAddMinThresholdToPhb(
                        red,
                        (unsigned char) ds,
                        value,
                        enableQueueStat);
                }
                else
                if (strcmp(parameterName, "RED-MAX-THRESHOLD") == 0)
                {
                    RedAddMaxThresholdToPhb(
                        red,
                        (unsigned char) ds,
                        value,
                        enableQueueStat);
                }
                else
                if (strcmp(parameterName, "RED-MAX-PROBABILITY") == 0)
                {
                    RedAddMaxProbabilityToPhb(
                        red,
                        (unsigned char) ds,
                        value,
                        enableQueueStat);
                }
                else
                {
                    ERROR_ReportError("PHB Mapping File RED parameters are "
                            "RED-MIN-THRESHOLD, RED-MAX-THRESHOLD, and\n"
                            "RED-MAX-PROBABILITY\n");
                }
            }
        }
    }

    // Report warnings for wrong Configurations
    if (red->numPhbParams > 1)
    {
        int i = 0;
        PhbParameters* phbParam = NULL;

        for (i = 0; i < red->numPhbParams; i++)
        {
            phbParam = &red->phbParams[i];

            if (phbParam->minThreshold > phbParam->maxThreshold)
            {
                ERROR_ReportWarning("PHB Mapping File: RED-MAX-THRESHOLD is"
                " specified less than RED-MIN-THRESHOLD\n");
            }

            if (phbParam->maxProbability > 1.0)
            {
                ERROR_ReportWarning("PHB Mapping File: RED-MAX-PROBABILITY"
                    " is specified greater than 1\n");
            }
        }
    }
    else
    {
        if (red->phbParams[0].minThreshold > red->phbParams[0].maxThreshold)
        {
            ERROR_ReportWarning("RED: RED-MAX-THRESHOLD is"
                " specified less than RED-MIN-THRESHOLD\n");
        }

        if (red->phbParams[0].maxProbability > 1.0)
        {
            ERROR_ReportWarning("RED: RED-MAX-PROBABILITY is"
                            " specified greater than 1\n");
        }
    }

    // Attch Info
    *redEcnParams = red;
}

// -------------------------------------------------------------------------
// End: Read and configure RedEcnParameters
// -------------------------------------------------------------------------

