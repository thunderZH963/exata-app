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
// + www.sce.carleton.ca/faculty/lambadaris/recent-papers/162.pdf
// + http://www.cisco.com/warp/public/732/Tech/red/
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <map>

#include "api.h"
#include "network_ip.h"

#include "if_queue.h"
#include "queue_red.h"
#include "queue_red_ecn.h"
#include "queue_rio_ecn.h"
#include "queue_wred_ecn.h"


//-------------------------------------------------------------------------
// Start: Utility Functions
//-------------------------------------------------------------------------

// /**
// FUNCTION   :: EcnWredQueue::MredReturnPacketProfile
// LAYER      ::
// PURPOSE    :: Checks the packet profile by looking the dscp.It is assumed
//               that the dscp for actually marked Assured Forwarding
//               packets is consist of 6 bit calld ds field in Diffserv. For
//               now we are accessing 8 bit TOS field of IP header for DSCP.
//               To count this the value of these masks DSCP_FOURTH_BIT and
//               DSCP_FIFTH_BIT are taken to be 8 and 16. It should be
//               modified iff we are to deal with 6bit DS-field as dscp.
// PARAMETERS ::
// + dscp : const int : Accessing DSCP field of IP header
// RETURN     :: int : Integer
// **/

int EcnWredQueue::MredReturnPacketProfile(
    const int dscp)
{

    if (!(dscp & DSCP_FOURTH_BIT))
    {
        // The packet is green profile packet with lowest drop probability
        return GREEN_PROFILE;
    }
    else if ((dscp & DSCP_FOURTH_BIT) && !(dscp & DSCP_FIFTH_BIT))
    {
        // The packet is yellow profile packet with medium drop probability
        return YELLOW_PROFILE;
    }
    else //if ((dscp & DSCP_FOURTH_BIT) && (dscp & DSCP_FIFTH_BIT))
    {
        // The packet is Red profile packet with highest drop probability
        return RED_PROFILE;
    }
}


// /**
// FUNCTION   :: EcnWredQueue::MredReturnPhbForDs
// LAYER      ::
// PURPOSE    :: Returns PHB for In/Out profile packet. It is assumed that
//               The Assertion is now kept commented as because for now
//               there are packets with those bit fields "0".When there will
//               be packets of Assured forwarding only, this assertion
//               should be there in uncommented state.
// PARAMETERS ::
// + mred : const RedEcnParameters* : The pointer to RedEcnParameters
//                                    structure
// + dscp : const int : Accessing DSCP field of IP header
// RETURN     :: PhbParameters* : The pointer to PhbParameters
// **/

PhbParameters* EcnWredQueue::MredReturnPhbForDs(
    const RedEcnParameters* mred,
    const int dscp)
{
    if (MredReturnPacketProfile(dscp) == GREEN_PROFILE)
    {
        // Returning PHB for green packet
        return GREEN_PROFILE_PHB(mred);
    }
    else if (MredReturnPacketProfile(dscp) == YELLOW_PROFILE)
    {
        // Returning PHB for yellow packet
        return YELLOW_PROFILE_PHB(mred);
    }
    else //if (MredReturnPacketProfile(dscp) == RED_PROFILE)
    {
        // Returning PHB for Red packet
        return RED_PROFILE_PHB(mred);
    }
}

//-------------------------------------------------------------------------
// End: Utility Functions
//-------------------------------------------------------------------------


//-------------------------------------------------------------------------
// Start: Public Interface functions
//-------------------------------------------------------------------------

// /**
// FUNCTION   :: EcnWredQueue::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to insert
//               a message into it.  The infoField parameter has a specified
//               size infoFieldSize, which is set at Initialization, and
//               points to the structure that should be stored along
//               with the Message.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + infoField : const void* : The infoField parameter
// + QueueIsFull : BOOL* : returns Queue occupancy status
// + currentTime : const clocktype : current Simulation time
// + serviceTag : const double : The serviceTag parameter
// RETURN     :: void : Null
// **/

void EcnWredQueue::insert(
    Message* msg,
    const void* infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    const double serviceTag)
{
    insert(msg, infoField, QueueIsFull, currentTime, NULL, serviceTag);
}

void EcnWredQueue::insert(
    Message* msg,
    const void *infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    TosType* tos,
    const double serviceTag
    )
{
    BOOL isECTset = FALSE;
    BOOL wasEcnMarked = FALSE;
    BOOL isBetweenMinthMaxth = FALSE;


    ERROR_Assert(MESSAGE_ReturnPacketSize(msg) > 0,
        "Queue Error: Attempted to queue a packet of 0 length");



    int ip_tos;

    if (tos == NULL)
    {
        ip_tos = GetTosFromMsgHeader(msg);
    }
    else
    {
       ip_tos = (int) *tos;
    }

    PhbParameters *phbParam = MredReturnPhbForDs(this->redEcnParams,
                                                    ip_tos >> 2);

    if (WRED_DEBUG)
    {
        printf("WRED: Trying to Insert a Packet with"
            " DSCP(%u) in queue\n", ip_tos >> 2);
    }

    if (ip_tos & IPTOS_CE)
    {
        wasEcnMarked = TRUE;
    }

    if (ip_tos & IPTOS_ECT)
    {
        isECTset = TRUE;
    }

    // Check if there is space in the queue for this packet
    if (MESSAGE_ReturnPacketSize(msg) > (queueSizeInBytes - bytesUsed))
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

        // Update PHB Specific stats
        if (isCollectStats)
        {
            RedEcnStats *stats = phbParam->stats;

            stats->numPacketsDropped++;
            stats->numBytesDropped += MESSAGE_ReturnPacketSize(msg);
        }

        if (WRED_DEBUG)
        {
            printf("\t\t\tWRED: No space In the queue;"
            " Just dropping the packet(%u)\n", ip_tos >> 2);
        }

        // No space for this item in the queue
        return;
    }

    // Weighted RED calculates a single average queue that includes arriving
    // packets of all colors. For an arrival or departure of green ,
    // yellow or red packets, WRED updates a single average queue based on
    // total  number of packets of green, yellow or red color. However,
    // multiple RED threshold parameters are maintained - one for each color

    UpdateAverageQueueSize(
        isEmpty(),
        packetsInQueue(),
        redEcnParams->queueWeight,
        redEcnParams->typicalSmallPacketTransmissionTime,
        startIdleTime,
        &averageQueueSize,
        currentTime);

    if (WRED_DEBUG)
    {
        printf("\t\t\tWRED: Average Queue Size: %f"
                " Minth: %u Maxth: %u\n", averageQueueSize,
                phbParam->minThreshold, phbParam->maxThreshold);
    }

    // Check whether packet will be dropped or marked
    if (MarkThePacket(
            phbParam,
            averageQueueSize,
            &packetCount,
            &isBetweenMinthMaxth,
            isECTset))
    {
        // When a router has decided from its active queue management
        // mechanism, to drop or mark a packet, it checks the IP-ECT
        // bit in the packet header. It sets the CE bit in the IP header
        // if the IP-ECT bit is set.

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

            if (WRED_DEBUG)
            {
                printf("\t\t\tWRED: Random drop; Dropping Packet"
                    " with DSCP(%u)\n", ip_tos >> 2);
            }
            return;
        }
    }

    if (WRED_DEBUG)
    {
        printf("\t\t\tWRED: Inserting the Packet with"
            " DSCP(%u)\n", ip_tos >> 2);
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

    // Update variables and statistics
    if (isCollectStats)
    {
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
// FUNCTION   :: EcnWredQueue::retrieve
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
// + serviceTag : double* : The serviceTag parameter.
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL EcnWredQueue::retrieve(
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
            PhbParameters *phbParam = MredReturnPhbForDs(redEcnParams,
                                                        dscp);

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

        if (WRED_DEBUG)
        {
            printf("WRED: Dequeueing Packet with dscp(%d)\n", dscp);
        }
    }

    return isPacketRetrieve;
}


// /**
// FUNCTION   :: EcnWredQueue::finalize
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

void EcnWredQueue::finalize(
    Node *node,
    const char *layer,
    const int interfaceIndex,
    const int instanceId,
    const char* invokingProtocol,
    const char* splStatStr)
{
    char buf[MAX_STRING_LENGTH] = {0};
    char queueType[MAX_STRING_LENGTH] = { "WRED" };
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
        sprintf(queueType, "%s WRED", invokingProtocol);
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    RedEcnQueueFinalize(
        node,
        layer,
        intfIndexStr,
        instanceId,
        GREEN_PROFILE_PHB(redEcnParams)->stats,
        queueType,
        "GREEN");

    RedEcnQueueFinalize(
        node,
        layer,
        intfIndexStr,
        instanceId,
        YELLOW_PROFILE_PHB(redEcnParams)->stats,
        queueType,
        "YELLOW");

    RedEcnQueueFinalize(
        node,
        layer,
        intfIndexStr,
        instanceId,
        RED_PROFILE_PHB(redEcnParams)->stats,
        queueType,
        "RED");

    FinalizeQueue(node,
                  layer,
                  queueType,
                  interfaceIndex,
                  instanceId,
                  invokingProtocol);

    sprintf(buf, "Packets Marked ECN = %d", numPacketsECNMarked);
    IO_PrintStat(
        node,
        layer,
        queueType,
        intfIndexStr,
        instanceId,
        buf);
}


// /**
// FUNCTION   :: EcnWredQueue::SetupQueue
// LAYER      ::
// PURPOSE    :: This function is proposed for RED queue initialization
// PARAMETERS ::
// + node : Node* : node
// + queueTypeString[] : const char : Queue type string
// + queueSize : const int : queue size in bytes
// + interfaceIndex : const int : used for setting random seed
// + queueNumber : const int : used for setting random seed
// + infoFieldSize : const int : The infoFieldSize parameter
// + enableQueueStat : const BOOL : Status of queue statistics.
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

void EcnWredQueue::SetupQueue(
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
    , const BOOL enablePerDscpStat
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
                      ,0, NULL,queuePosition    
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

        // Initiate Plug-n-Play by assigning default values
        redEcnParams->numPhbParams = MRED_NUM_PHB;
        redEcnParams->queueWeight = DEFAULT_RED_QUEUE_WEIGHT;
        redEcnParams->typicalSmallPacketTransmissionTime
                    = DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME;

        redEcnParams->phbParams = (PhbParameters*)
            MEM_malloc(sizeof(PhbParameters) * redEcnParams->numPhbParams);

        redEcnParams->phbParams[GREEN_PROFILE].minThreshold
                                = DEFAULT_GREEN_PROFILE_MIN_THRESHOLD;
        redEcnParams->phbParams[GREEN_PROFILE].maxThreshold
                                = DEFAULT_GREEN_PROFILE_MAX_THRESHOLD;
        redEcnParams->phbParams[GREEN_PROFILE].maxProbability
                                        = DEFAULT_RED_MAX_PROBABILITY;
        redEcnParams->phbParams[YELLOW_PROFILE].minThreshold
                                = DEFAULT_YELLOW_PROFILE_MIN_THRESHOLD;
        redEcnParams->phbParams[YELLOW_PROFILE].maxThreshold
                                = DEFAULT_YELLOW_PROFILE_MAX_THRESHOLD;
        redEcnParams->phbParams[YELLOW_PROFILE].maxProbability
                                        = DEFAULT_RED_MAX_PROBABILITY;
        redEcnParams->phbParams[RED_PROFILE].minThreshold
                                    = DEFAULT_RED_PROFILE_MIN_THRESHOLD;
        redEcnParams->phbParams[RED_PROFILE].maxThreshold
                                    = DEFAULT_RED_PROFILE_MAX_THRESHOLD;
        redEcnParams->phbParams[RED_PROFILE].maxProbability
                                        = DEFAULT_RED_MAX_PROBABILITY;

        for (i = 0; i < redEcnParams->numPhbParams; i++)
        {
            redEcnParams->phbParams[i].stats
                = (RedEcnStats*) MEM_malloc(sizeof(RedEcnStats));

            memset(redEcnParams->phbParams[i].stats, 0,
                                            sizeof(RedEcnStats));
        }

        if (DEBUG_PLUG_N_PLAY)
        {
            fprintf(stdout, "\n\n$ WRED Plug-n-Play enabled\n"
                "......................................................\n"
                "GREEN-PROFILE-MIN-THRESHOLD        10\n"
                "GREEN-PROFILE-MAX-THRESHOLD        20\n"
                "GREEN-PROFILE-MAX-PROBABILITY      0.02\n"
                "YELLOW-PROFILE-MIN-THRESHOLD       5\n"
                "YELLOW-PROFILE-MAX-THRESHOLD       10\n"
                "YELLOW-PROFILE-MAX-PROBABILITY     0.02\n"
                "RED-PROFILE-MIN-THRESHOLD          2\n"
                "RED-PROFILE-MAX-THRESHOLD          5\n"
                "RED-PROFILE-MAX-PROBABILITY        0.02\n"
                "RED-QUEUE-WEIGHT      0.002\n"
                "RED-SMALL-PACKET-TRANSMISSION-TIME   10MS\n"
                "......................................................\n");
        }
    }
    else
    {
        // Reading Red parameters from configuration files.
        redEcnParams = ((RedEcnParameters*) configInfo);
    }
}

//-------------------------------------------------------------------------
// End: Public Interface functions
//-------------------------------------------------------------------------

// /**
// FUNCTION   :: ReadWred_EcnConfigurationThParameters
// LAYER      ::
// PURPOSE    :: This function reads Three color, ECN enabled WRED
//               configuration parameters from QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + wred : RedEcnParameters** : Pointer of pointer to RedEcnParameters
//                               Structure that keeps all configurable
//                               entries for Three color, ECN enabled WRED
//                               Queue.
// RETURN     :: void : Null
// **/

void ReadWred_EcnConfigurationThParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput *nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters** wred)
{
    RedEcnParameters* mred = NULL;

    mred = (RedEcnParameters*) MEM_malloc(sizeof (RedEcnParameters));
    memset(mred, 0, sizeof (RedEcnParameters));

    // Read queue weight and small pkt transmission time
    ReadRed_EcnCommonConfigurationParams(node,
                                         interfaceIndex,
                                         nodeInput,
                                         enableQueueStat,
                                         queueIndex,
                                         mred);
    // Read Mred Thresholds
    mred->numPhbParams = MRED_NUM_PHB;
    mred->phbParams = (PhbParameters*) MEM_malloc(sizeof(PhbParameters)
                                                  * MRED_NUM_PHB);
    memset(mred->phbParams, 0, sizeof(PhbParameters) * MRED_NUM_PHB);

    ReadThreeColorMredPhbParameters(node,
                                    interfaceIndex,
                                    nodeInput,
                                    enableQueueStat,
                                    queueIndex,
                                    mred);
    // Attach Info
    *wred = mred;
}

// -------------------------------------------------------------------------
// Start: Read and configure WRED
// -------------------------------------------------------------------------
