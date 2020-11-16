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
// REFERENCES   ::Simulate RED as described in:
// + Sally Floyd and Van Jacobson,
//   "Random Early Detection For Congestion Avoidance",
//   IEEE/ACM Transactions on Networking, August 1993.
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "network_ip.h"
#include "if_queue.h"
#include "queue_red.h"
#include "queue_rio_ecn.h"

#ifdef ADDON_BOEINGFCS
#include "routing_ces_malsr.h"
#endif

// #define TRACE_RED

//--------------------------------------------------------------------------
// Start: Utility Functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: RedQueue::UpdateAverageQueueSize
// LAYER      ::
// PURPOSE    :: Update the average queue size variable
// PARAMETERS ::
// + queueIsEmpty : const BOOL : If queue empty it returns TRUE elae FALSE.
// + numPackets : const int : Number of packets in queue
// + queueWeight : const double : Weight of that perticular queue
// + smallPktTxTime : const clocktype : Packet transmission time
// + startIdleTime : const clocktype :  Queue idle time
// + avgQueueSize : double* : Average queue size
// + theTime : const clocktype : Current simulation time
// RETURN     :: void : Null
// **/

void RedQueue::UpdateAverageQueueSize(
    const BOOL queueIsEmpty,
    const int numPackets,
    const double queueWeight,
    const clocktype smallPktTxTime,
    const clocktype startIdleTime,
    double* avgQueueSize,
    const clocktype theTime)
{
    // Calculating Average queue size
    if (!queueIsEmpty)
    {
        // Calculating the averageQueueSize
        *avgQueueSize = (((1.0 - queueWeight) * (*avgQueueSize))
                      + (queueWeight * numPackets));
    }
    else // The queue has been idle for some period
    {
        double mresult;
        mresult = (double) (theTime - startIdleTime) / smallPktTxTime;

        *avgQueueSize = pow((double) (1.0 - queueWeight), mresult)
                      * (*avgQueueSize);
    }
}


// /**
// FUNCTION   :: RedQueue::RedDropThePacket
// LAYER      ::
// PURPOSE    :: Determines the probability of dropping or marking
// PARAMETERS ::
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL RedQueue::RedDropThePacket()
{
    double pbresult;             // probability
    double paresult;             // current packet marking probability
    double tmpNo;                // temporary Random number

    // if Average queue size is between min and max threshold then
    // calculate probability and mark/drop the packet based on
    // probability

    if ((averageQueueSize >= redParams->minThreshold) &&
        (averageQueueSize < redParams->maxThreshold))
    {
        // Increase the Counter
        packetCount++;

        // Calculate the probability
        pbresult = redParams->maxProbability
            * (averageQueueSize - redParams->minThreshold)
            / (redParams->maxThreshold - redParams->minThreshold);

        if ((packetCount * pbresult) >= 1.0)
        {
            paresult = 1.0;
        }
        else
        {
            paresult = pbresult / (1 - (packetCount * pbresult));
        }

        // A random number is generated and compared to the probability of
        // marking the packet.  If the random number is less than the
        // probability value, then the packet is marked.

        tmpNo = RANDOM_erand(randomDropSeed);

        if (tmpNo <= paresult)
        {
            // Drop the packet
            packetCount = 0;
            return TRUE;
        }
        else
        {
            // Allow the packet in the queue
            return FALSE;
        }
    }
    else
    if ((averageQueueSize >= redParams->maxThreshold))
    {
         // Drop the packet
        packetCount = 0;
        return TRUE;
    }
    else
    {
        // Allow the packet in the queue
        packetCount = -1;
        return FALSE;
    }
}


//--------------------------------------------------------------------------
// End: Utility Functions
//--------------------------------------------------------------------------


//--------------------------------------------------------------------------
// Start: Public Interface functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: RedQueue::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to insert
//               a message into it.  The infoField parameter has a specified
//               size infoFieldSize, which is set at Initialization, and
//               points to the structure that should be stored along
//               with the Message
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + infoField : const void* : Default value 0
// + QueueIsFull : BOOL* : returns Queue occupancy status
// + currentTime : const clocktype : Current simulation time
// + serviceTag : const double : ServiceTag
// RETURN     :: void : Null
// **/

void RedQueue::insert(
    Message* msg,
    const void* infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    const double serviceTag)
{
    insert(msg, infoField, QueueIsFull, currentTime, NULL, serviceTag);
}

void RedQueue::insert(
    Message* msg,
    const void* infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    TosType* tos,
    const double serviceTag
    )
{
#ifdef TRACE_RED
printf ("at %I64d: inserting packet of size %d\n", currentTime, MESSAGE_ReturnPacketSize (msg));
#endif
    if (!(MESSAGE_ReturnPacketSize(msg) <= (queueSizeInBytes - bytesUsed)))
    {
        // No space for this item in the queue
        *QueueIsFull = TRUE;

        if (isCollectStats)
        {
            Queue::stats->DropPacket(msg,
                bytesUsed,
                currentTime);
        }
#ifdef ADDON_BOEINGFCS
        if (collectDscpStats)
        {
            QueuePerDscpStats *statsEntry = NULL;
            statsEntry = QueueGetPerDscpStatEntry(msg, dscpStats);
            statsEntry->numPacketsDropped++;
        }
#endif

        return;
    }

    // Update Average Queue Size.
    UpdateAverageQueueSize(
        isEmpty(),
        packetsInQueue(),
        redParams->queueWeight,
        redParams->typicalSmallPacketTransmissionTime,
        startIdleTime,
        &averageQueueSize,
        currentTime);

    if (RedDropThePacket())
    {
#ifdef TRACE_RED
printf ("at %I64d: dropping packet of size %d\n", currentTime, MESSAGE_ReturnPacketSize (msg));
#endif
        // A router has decided from its active queue management
        // mechanism, to drop a packet.
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
        return;
    }

    // Inserting a packet in the queue
     Queue::insert(msg,
                  infoField,
                  QueueIsFull,
                  currentTime,
                  serviceTag);
}


// /**
// FUNCTION   :: RedQueue::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to dequeue,
//               peek at, or drop a message in its array of stored messages.
//               It now includes the "DropFunction" functionality as well.
// PARAMETERS ::
// + msg : Message** : The retrieved message
// + index : const int : The position of the packet in the queue
// + operation : const QueueOperation : The retrieval mode
// + currentTime : const clocktype : Current simulation time
// + serviceTag : double* : ServiceTag
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL RedQueue::retrieve(
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
    }

    return isPacketRetrieve;
}


// /**
// FUNCTION   :: RedQueue::finalize
// LAYER      ::
// PURPOSE    :: This function prototype outputs the final statistics for
//               this queue. The layer, protocol, interfaceAddress, and
//               instanceId parameters are given to IO_PrintStat with each
//               of the queue's statistics.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + interfaceIndex : const int : The interface index
// + instanceId : const int : Instance Ids
// + invokingProtocol : const char* : The protocol string
// + splStatStr : const char* Special string for stat print
// RETURN     :: void : Null
// **/

void RedQueue::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const int instanceId,
    const char* invokingProtocol,
    const char* splStatStr)
{
    char queueType[MAX_STRING_LENGTH] = { "RED" };

    if (!isCollectStats)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP"))
    {
        memset(queueType, 0, MAX_STRING_LENGTH);
        sprintf(queueType, "%s RED", invokingProtocol);
    }
    // Calling GenericQueueFinalize Function
    FinalizeQueue(node,
                  layer,
                  queueType,
                  interfaceIndex,
                  instanceId,
                  invokingProtocol);
}


// /**
// FUNCTION   :: RedQueue::SetupQueue
// LAYER      ::
// PURPOSE    :: This function runs queue initialization routine. Any
//               algorithm specific configurable parameters will be kept in
//               a structure and after feeding that structure the structure
//               pointer will be sent to this function via that void pointer
//               configInfo. Some parameters includes default values, to
//               prevent breaking existing models. [Uses: vide Pseudo code]
// PARAMETERS :: None
// + queueTypeString[] : const char : Queue type string
// + queueSize : const int : Queue size in bytes
// + randomSeed[] : const unsigned short : randomSeed[]; Node seed[] value
// + infoFieldSize : const int : Default infoFieldSize = 0
// + enableQueueStat : const BOOL : Default enableQueueStat = false
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

void RedQueue::SetupQueue(
    Node* node,
    const char queueTypeString[],
    const int queueSize,
    const int interfaceInde,
    const int queueNumber,
    const int infoFieldSize,
    const BOOL enableQueueStat,
    const BOOL showQueueInGui,
    const clocktype currentTime,
    const void* configInfo
#ifdef ADDON_DB
    ,const char*queuePosition
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
                      interfaceInde,
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

    RANDOM_SetSeed(randomDropSeed,
                   node->globalSeed,
                   node->nodeId,
                   interfaceInde,
                   queueNumber);

    averageQueueSize = 0.0;
    packetCount = -1;

    startIdleTime = currentTime;

    if (configInfo == NULL)
    {
        redParams = (RedParameters*) MEM_malloc(sizeof (RedParameters));
        memset(redParams, 0, sizeof (RedParameters));

        // Initiate Plug-n-Play by assigning default values
        redParams->minThreshold = DEFAULT_RED_MIN_THRESHOLD;
        redParams->maxThreshold = DEFAULT_RED_MAX_THRESHOLD;
        redParams->maxProbability = DEFAULT_RED_MAX_PROBABILITY;
        redParams->queueWeight = DEFAULT_RED_QUEUE_WEIGHT;
        redParams->typicalSmallPacketTransmissionTime
                = DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME;

        if (DEBUG_PLUG_N_PLAY)
        {
            fprintf(stdout, "\n\n$ RED Plug-n-Play enabled\n"
                "......................................................\n"
                "RED-MIN-THRESHOLD     5\n"
                "RED-MAX-THRESHOLD     15\n"
                "RED-MAX-PROBABILITY   0.02\n"
                "RED-QUEUE-WEIGHT      0.002\n"
                "RED-SMALL-PACKET-TRANSMISSION-TIME   10MS\n"
                "......................................................\n");
        }
    }
    else
    {
        // Reading Red parameters from configuration files.
        redParams = (RedParameters*) configInfo;
    }
}

#ifdef ADDON_BOEINGFCS
void RedQueue::signalCongestion(Node* node,
                                int interfaceIndex,
                                Message* msg)
{
    RoutingCesMalsrSignalQueueCongestion(node,
                                         interfaceIndex,
                                         msg,
                                         redParams->minThreshold,
                                         averageQueueSize);
}
#endif

//--------------------------------------------------------------------------
// End: Public Interface functions
//--------------------------------------------------------------------------

// -------------------------------------------------------------------------
// Start: Read and configure RedParameters
// -------------------------------------------------------------------------

// /**
// FUNCTION   :: ReadRedConfigurationParameters
// LAYER      ::
// PURPOSE    :: This function reads RED configuration parameters from
//               QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + redConfigParams : RedParameters** : Pointer of pointer to
//                                       RedParameters Structure that keeps
//                                       all configurable entries for RED
//                                       Queue.
// RETURN     :: void : Null
// **/

void ReadRedConfigurationParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedParameters** redConfigParams)
{
    BOOL retVal = FALSE;
    RedParameters* red = NULL;
    int nodeId = node->nodeId;

    red = (RedParameters*) MEM_malloc(sizeof(RedParameters));
    memset(red, 0, sizeof(RedParameters));

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

    // Read Red Thresholds
    IO_ReadIntInstance(
        node,
        nodeId,
        interfaceIndex,
        nodeInput,
        "RED-MIN-THRESHOLD",
        queueIndex,   // parameterInstanceNumber
        TRUE,       // fallbackIfNoInstanceMatch
        &retVal,
        &(red->minThreshold));

    if (retVal == FALSE)
    {
        red->minThreshold = DEFAULT_RED_MIN_THRESHOLD;
    }
    else
    {
       ERROR_Assert(red->minThreshold > 0.0,
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
        &(red->maxThreshold));

    if (retVal == FALSE)
    {
        red->maxThreshold = DEFAULT_RED_MAX_THRESHOLD;
    }
    else
    {
       ERROR_Assert(red->maxThreshold > 0.0,
                "RED maxThreshold should be > 0.0\n");
    }

    ERROR_Assert(red->minThreshold <
        red->maxThreshold,
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
        &(red->maxProbability));

    if (retVal == FALSE)
    {
    red->maxProbability = DEFAULT_RED_MAX_PROBABILITY;
    }

    else
    {
    // Report an error for wrong Configurations

    ERROR_Assert(red->maxProbability < 1.0 && red->maxProbability > 0.0,
        "Red maxProbability should be <= 1.0 and should be > 0.0\n");

    }

    // Attch Info
    *redConfigParams = red;
}

// -------------------------------------------------------------------------
// End: Read and configure RedParameters
// -------------------------------------------------------------------------
