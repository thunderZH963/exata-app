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
// PROTOCOL     :: ATM_QUEUE.
// LAYER        :: ATM_LAYER2.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// PURPOSE:  Simulate RED as described in:
//           Sally Floyd and Van Jacobson,
//           "Random Early Detection For Congestion Avoidance",
//           IEEE/ACM Transactions on Networking, August 1993.
//
// NOTES:    This implementation only drops packets, it does not mark them
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "atm_layer2.h"
#include "atm_queue.h"

// /**
// FUNCTION   :: ReadRedConfigurationParameters
// LAYER      :: ATM Layer2
// PURPOSE    :: This function reads RED configuration parameters from
//               QualNet .config file
// PARAMETERS ::
// + node            : Node* : The node Pointer
// + address         : const Address : Interface Address
// + nodeInput       : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : enableQueueStat :Tag for enabling Queue
//                                             Statistics
// + queueIndex      : int : Queue Index
// +redConfigParams  : RedParameters** : Pointer of pointer to
//                      RedParameters Structure that keeps all configurable
//                      entries for RED Queue.
// RETURN     :: None
// NOTE:        This Function have layer dependency
//              because of existing QualNet IO's.
// **/
void ReadRedConfigurationParameters(Node* node,
                                    const Address address,
                                    const NodeInput* nodeInput,
                                    BOOL enableQueueStat,
                                    int queueIndex,
                                    RedParameters** redConfigParams)
{
    BOOL retVal = FALSE;
    char errorStr[MAX_STRING_LENGTH] = {0};
    RedParameters* red = NULL;

    red = (RedParameters*) MEM_malloc(sizeof(RedParameters));
    memset(red, 0, sizeof(RedParameters));

    IO_ReadTimeInstance(
        node->nodeId,
        &address,
        nodeInput,
        "ATM-RED-SMALL-PACKET-TRANSMISSION-TIME",
        queueIndex,  // parameterInstanceNumber
        TRUE,      // fallbackIfNoInstanceMatch
        &retVal,
        &(red->typicalSmallPacketTransmissionTime));

    if (!retVal)
    {
        red->typicalSmallPacketTransmissionTime = 10 * MILLI_SECOND;
    }

    red->queueWeight = 0;

    // Read Red Thresholds
    IO_ReadIntInstance(
        node->nodeId,
        &address,
        nodeInput,
        "ATM-RED-MIN-THRESHOLD",
        queueIndex,   // parameterInstanceNumber
        TRUE,       // fallbackIfNoInstanceMatch
        &retVal,
        &(red->minThreshold));

    if (!retVal)
    {
        red->minThreshold = 5;
    }
    else if (red->minThreshold < 0)
    {
        memset(errorStr, 0, MAX_STRING_LENGTH);
        sprintf(errorStr, "Node: %d Queue: %d\t"
            " ATM-RED-MIN-THRESHOLD specification.is negative.",
            node->nodeId, queueIndex);
        ERROR_ReportError(errorStr);
    }

    IO_ReadIntInstance(
        node->nodeId,
        &address,
        nodeInput,
        "ATM-RED-MAX-THRESHOLD",
        queueIndex,  // parameterInstanceNumber
        TRUE,      // fallbackIfNoInstanceMatch
        &retVal,
        &(red->maxThreshold));

    if (!retVal)
    {
        red->maxThreshold = 15;
    }
    else if (red->maxThreshold < 0)
    {
        memset(errorStr, 0, MAX_STRING_LENGTH);
        sprintf(errorStr, "Node: %d Queue: %d\t"
            " ATM-RED-MAX-THRESHOLD specification.is negative.",
            node->nodeId, queueIndex);
        ERROR_ReportError(errorStr);
    }

    IO_ReadDoubleInstance(
        node->nodeId,
        &address,
        nodeInput,
        "ATM-RED-MAX-PROBABILITY",
        queueIndex,  // parameterInstanceNumber
        TRUE,                // fallbackIfNoInstanceMatch
        &retVal,
        &(red->maxProbability));

    if (retVal == FALSE)
    {
        red->maxProbability = 0.02;
    }
    else if (red->maxProbability < 0)
    {
        memset(errorStr, 0, MAX_STRING_LENGTH);
        sprintf(errorStr, "Node: %d Queue: %d\t"
            "Missing ATM-RED-MAX-PROBABILITY specification.is negative.",
            node->nodeId, queueIndex);
        ERROR_ReportError(errorStr);
    }

    // Report warnings for wrong Configurations
    {
        if (red->minThreshold > red->maxThreshold)
        {
            ERROR_ReportWarning("ATM-RED: ATM-RED-MAX-THRESHOLD is"
                " specified less than ATM-RED-MIN-THRESHOLD\n");
        }

        if (red->maxProbability > 1.0)
        {
            ERROR_ReportWarning("ATM-RED: ATM-RED-MAX-PROBABILITY is"
                            " specified greater than 1\n");
        }
    }
    // Attch Info
    *redConfigParams = red;
}

// /**
// FUNCTION   :: UpdateAverageQueueSize
// LAYER      :: ATM Layer2
// PURPOSE    :: Update the average queue size variable
// PARAMETERS ::
// + queueIsEmpty  : const BOOL  : Checking for Queue is empty
// + numPackets    : const int : Number of Packets
// + queueWeight   : const double : Queue Weight
// + smallPktTxTime: const clocktype : Small packet Transmission Time
// + startIdleTime : const clocktype : Start Idle time
// + avgQueueSize  : double* : Avg Queue Size
// + theTime       : const clocktype : Current time
// RETURN     :: void : None
// **/
void AtmRedQueue::UpdateAverageQueueSize(const BOOL queueIsEmpty,
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
// FUNCTION   :: RedMarkThePacket
// LAYER      :: ATM Layer2
// PURPOSE    :: Determines the probability of dropping or marking
// PARAMETERS ::
// + isBetweenMinthMaxth : BOOL* : Is between Min and Max value
// RETURN     ::  BOOL
// **/
BOOL AtmRedQueue::RedMarkThePacket(BOOL* isBetweenMinthMaxth)
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
        *isBetweenMinthMaxth = true;

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
            return true;
        }
        else
        {
            // Allow the packet in the queue
            return false;
        }
    }
    else
    if ((averageQueueSize >= redParams->maxThreshold))
    {
         // Drop the packet
        packetCount = 0;
        *isBetweenMinthMaxth = false;
        return true;
    }
    else
    {
        // Allow the packet in the queue
        packetCount = -1;
        return false;
    }
}

// /**
// FUNCTION   :: SetupQueue
// LAYER      :: ATM Layer2
// PURPOSE    :: This function is proposed for ATM-RED queue initialization
// PARAMETERS ::
// + node            : Node* : pointer to node
// + queueTypeString : const char : Queue Type String
// + queueSize       : const int :Queue Size
// + interfaceIndex  : const int : used to set Random seed
// + queueNumber     : const int : used to set Random seed
// + infoFieldSize   : const int : Info Field Size
// + enableQueueStat : const BOOL : Enable Queue Stat
// + showQueueInGui  : const BOOL :Show Queue in GUI
// + currentTime     : const clocktype : Current Simulation Time.
// + configInfo :    : const void*  Configuration Info
// RETURN     ::  Void
// **/
void AtmRedQueue::SetupQueue(Node* node,
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
                              ,const char *queuePosition
#endif
                             , const clocktype maxPktAge
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

    // Reading Red parameters from configuration files.
    redParams = (RedParameters*) configInfo;
}


// /**
// FUNCTION   :: insert
// LAYER      :: ATM Layer2
// PURPOSE    ::This function prototype determines the arguments that need
//              to be passed to a queue data structure in order to insert
//              a message into it.  The infoField parameter has a specified
//              size infoFieldSize, which is set at Initialization, and
//              points to the structure that should be stored along
//              with the Message.
// PARAMETERS  ::
// + msg        : Pointer to msg structure.
// + infoField  :  const void* : The infoField parameter
// + QueueIsFull:  BOOL*  :returns Queue occupancy status
// + currentTime : const clocktype : current Simulation time
// RETURN     ::  Void
// **/
void AtmRedQueue::insert(Message* msg,
                         const void* infoField,
                         BOOL* QueueIsFull,
                         const clocktype currentTime)
{
    BOOL isBetweenMinthMaxth = false;

    if (!(MESSAGE_ReturnPacketSize(msg) <= (queueSizeInBytes - bytesUsed)))
    {
        // No space for this item in the queue
        *QueueIsFull = true;
        if (isCollectStats)
        {
            Queue::stats->DropPacket(msg, bytesUsed, currentTime);
        }
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

    if (RedMarkThePacket(&isBetweenMinthMaxth))
    {
        // Drop the packet.
        if (!isBetweenMinthMaxth)
        {
            *QueueIsFull = true;
            if (isCollectStats)
            {
                Queue::stats->DropPacket(msg, bytesUsed, currentTime);
            }
            return;
        }
        else
        {
            // Atm frame fill congested path, it mark it into the frame
            Atm_Layer2CongestionExperienced(msg);
        }
    }

    // Inserting a packet in the queue
    Queue::insert(msg,
                  infoField,
                  QueueIsFull,
                  currentTime);

}

// /**
// FUNCTION   :: retrieve
// LAYER      :: ATM Layer2
// PURPOSE    ::This function prototype determines the arguments that need
//              to be passed to a queue data structure in order to dequeue,
//              peek at, or drop a message in its array of stored messages.
//              It now includes the "DropFunction" functionality as well.
// PARAMETERS  ::
// + msg        : Message** : The retrieved msg
// + index      : const int : The packet index
// + operation  : const QueueOperation : the retrieval mode
// + currentTime: const clocktype : current Simulation time
// RETURN     ::  BOOL : AtmRedQueue :Red Queue structure
// **/
BOOL AtmRedQueue::retrieve(Message** msg,
                           const int index,
                           const QueueOperation operation,
                           const clocktype currentTime)
{
    BOOL isPacketRetrieve = false;
    // Dequeueing a packet from the queue
    isPacketRetrieve = Queue::retrieve(msg,
                                        index,
                                        operation,
                                        currentTime);

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
// FUNCTION   :: finalize
// LAYER      :: ATM Layer2
// PURPOSE    :: This function prototype outputs the final statistics for
//               this queue. The layer, protocol, interfaceAddress, and
//               instanceId parameters are given to IO_PrintStat with each
//               of the queue's statistics.
// PARAMETERS  ::
// + node        : The retrieved msg
// + layer       :  const char*  : Layer
// + interfaceIndex : const int  : Interface Index
// + instanceId     : const int  : Instance Id
// + invokingProtocol  :  const char*  : The invoking Protocol
// RETURN     ::  Void
// **/
void AtmRedQueue::finalize(Node* node,
                           const char* layer,
                           const int interfaceIndex,
                           const int instanceId,
                           const char* invokingProtocol,
                           const char* specialStatString)
{
    char queueType[MAX_STRING_LENGTH] = "ATM-RED";

    if (!isCollectStats)
    {
        return;
    }

    // Calling GenericQueueFinalize Function
    FinalizeQueue(node,
                layer,
                queueType,
                interfaceIndex,
                instanceId,
                invokingProtocol);
}
