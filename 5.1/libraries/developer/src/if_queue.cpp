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
// REFERENCES   :: None
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "if_queue.h"
#include "queue_red.h"
#include "queue_red_ecn.h"
#include "queue_wred_ecn.h"
#include "queue_rio_ecn.h"
#include "network_ip.h"

#include "atm_queue.h"
#include "stats_global.h"

#ifdef CYBER_LIB
#include "os_resource_manager.h"
#endif // CYBER_LIB

#ifdef ADDON_BOEINGFCS
#include "routing_ces_malsr.h"
#endif

//#ifdef ADDON_BOEINGFCS
char* Queue::getQueueType()
{
    return queueType;
}
//#endif

#ifdef ADDON_DB
#include "partition.h"
#include "db.h"
#include "dbapi.h"
#endif

BOOL Queue::getQueueStats()
{
    return isCollectStats;
}

void* Queue::getConfigParams()
{
    return NULL;
}
//--------------------------------------------------------------------------
// Start: Private Utility functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: Queue::RetriveArrayIndex
// LAYER      ::
// PURPOSE    :: Returns the positon of a packet
// PARAMETERS ::
// + index : int : The position of the packet in the queue
// RETURN     :: int : Integer value
// **/

inline int Queue::RetriveArrayIndex(int index)
{
    return ((headIndex + index) % maxPackets);
}

// /**
// FUNCTION   :: Queue::UpdateQueueDelayStats
// LAYER      ::
// PURPOSE    :: Calculates the queue delay
// PARAMETERS ::
// + packetArrayIndex : int : The position of the packet Info field
// + currentTime : const clocktype : Current Simulation time
// RETURN     :: void : Null
// **/

inline void Queue::UpdateQueueDelayStats(
    int packetArrayIndex,
    const clocktype currentTime)
{
    clocktype delay = currentTime - packetArray[packetArrayIndex].insertTime;

    if (isCollectStats)
    {
        stats->DelayDetected(delay);
    }
    // the current queue delay is stored at each queue label. It is
    // found by the following exponential average mechanism

    qDelay = (int) ((delayAveragingWeight * (float) (delay/MICRO_SECOND)) +
        ((1.0 - delayAveragingWeight) * (float) qDelay));
}


// /**
// FUNCTION   :: Queue::FinalizeQueue
// LAYER      ::
// PURPOSE    :: Helps in Printing Final Queue Statistics
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + protocol : const char* : The protocol string
// + interfaceIndex : const int : The interface index
// + instanceId : const int : Instance Ids
// + invokingProtocol : const char* : Protocol invoking finalize
// RETURN     :: void : Null
// **/

void Queue::FinalizeQueue(Node *node,
                      const char *layer,
                      const char *protocol,
                      const int interfaceIndex,
                      const int instanceId,
                      const char *invokingProtocol)
{
    char buf[MAX_STRING_LENGTH] = {0};
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    if (strcmp(invokingProtocol, "IP") == 0)
    {
        // IP queue finalization
        NetworkIpGetInterfaceAddressString(node,
                                           interfaceIndex,
                                           intfIndexStr);
    }
    else
    {
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    clocktype endTime = node->getNodeTime();
    lastChange = endTime;

    if (isCollectStats)
    {
        stats->FinalizeQueue(endTime, bytesInQueue());
        
        stats->Print(node,
            layer,
            protocol,
            intfIndexStr,
            instanceId);

        if (stats->GetPacketsDequeued().GetValue(endTime) > 0 ||
            stats->GetPacketsDroppedForcefully().GetValue(endTime) > 0 ||
            stats->GetPacketsDroppedForcefullyFromAging().GetValue(endTime) > 0)
        {
            sprintf(
                buf,
                "Average Time In Queue = %0.9lf",
                (double)
                (stats->GetTotalDelays().GetValue(endTime) /
                    (stats->GetPacketsDequeued().GetValue(endTime) +
                    stats->GetPacketsDroppedForcefully().GetValue(endTime) +
                    stats->GetPacketsDroppedForcefullyFromAging().GetValue(endTime))));
            IO_PrintStat(
                node,
                layer,
                protocol,
                intfIndexStr,
                instanceId,
                buf);
        }
    }
}

//--------------------------------------------------------------------------
// End: Private Utility functions
//--------------------------------------------------------------------------


//--------------------------------------------------------------------------
// Start: Public Interface functions
//--------------------------------------------------------------------------

// /**
// FUNCTION   :: Queue::insert
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
// + currentTime : const clocktype : Current Simulation time
// + serviceTag : const double : ServiceTag
// RETURN     :: void : Null
// **/

void Queue::insert(
    Message* msg,
    const void *infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    const double serviceTag)
{
    ERROR_Assert(MESSAGE_ReturnPacketSize(msg) > 0,
        "Queue Error: Attempted to queue a packet of 0 length");

#ifdef ADDON_BOEINGFCS
    ERROR_Assert(((representedSched == NULL) && (representedQueue == NULL)),
        "Queue Error: Attempted to queue a packet into a representative queue");
#endif 

    // if there is enough space in queue to fit the incoming packet
    if (MESSAGE_ReturnPacketSize(msg) > (queueSizeInBytes - bytesUsed))
    {
        *QueueIsFull = TRUE;

        if (isCollectStats)
        {
            stats->DropPacket(msg,
                bytesInQueue(),
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

        // No space for this item in the queue
        return;
    }

    // Need to add space to the array
    if (numPackets == maxPackets)
    {
        int i;
        PacketArrayEntry* newPacketArray = (PacketArrayEntry*)
            MEM_malloc(sizeof(PacketArrayEntry) * maxPackets * 2);
        memset(newPacketArray, 0,
            sizeof(PacketArrayEntry) * maxPackets * 2);

        i = maxPackets - headIndex;

        // Step One: Copy the queue over the headIndex to the end
        memcpy(newPacketArray, &packetArray[headIndex],
               sizeof(PacketArrayEntry) * i);

        // Step Two: Copy the remaining packets in the queue at the end
        memcpy(&newPacketArray[i], packetArray,
               sizeof(PacketArrayEntry) * (maxPackets - i));

        MEM_free(packetArray);
        packetArray = newPacketArray;
        tailIndex = maxPackets - 1;
        headIndex = 0;
        maxPackets *= 2;
    }

    // Add the Message* msg to the queue
    ERROR_Assert(((tailIndex >= 0) && (tailIndex < maxPackets)),
        "Queue Error: The tailIndex has become corrupted");

    lastChange = currentTime;
    //needs to be called before bytes are incremented, so averageQueueLength is correct
    if (isCollectStats)
    {
        stats->EnqueuePacket(msg, bytesUsed, currentTime);
    }
    numPackets++;
    bytesUsed += MESSAGE_ReturnPacketSize(msg);

    tailIndex++;

    if (tailIndex == maxPackets)
    {
        tailIndex = 0;
    }

    packetArray[tailIndex].msg = msg;
    packetArray[tailIndex].insertTime = currentTime;
    packetArray[tailIndex].serviceTag = serviceTag;


    *QueueIsFull = FALSE;

#ifdef ADDON_BOEINGFCS
    if (collectDscpStats)
    {
        QueuePerDscpStats *statsEntry = NULL;
        statsEntry = QueueGetPerDscpStatEntry(msg, dscpStats);
        statsEntry->numPacketsQueued++;
    }
#endif

#ifdef CYBER_LIB
    if (node->resourceManager)
    {
        node->resourceManager->packetAllocated(msg);
    }
#endif
}

void Queue::insert(
    Message* msg,
    const void *infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    TosType* tos,
    const double serviceTag
    )
{
    insert(msg, infoField, QueueIsFull, currentTime, serviceTag);
}

void Queue::insert(
    Node* node,
    int interfaceIndex,
    int priority,
    Message* msg,
    const void *infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    TosType* tos,
    const double serviceTag
    )
{
#ifdef ADDON_BOEINGFCS
    char* miInfo = (char*) MESSAGE_ReturnInfo(msg, INFO_TYPE_MIQoSAgePacket);
#endif

    insert(msg, infoField, QueueIsFull, currentTime, serviceTag);

    if ((!(*QueueIsFull)) && maxPktAge != CLOCKTYPE_MAX)
    {
        // create timer message, with info of msgIndex in queue
        // packet always inserted at tailIndex
        Message* timerMsg = NULL;
       
#ifdef ADDON_BOEINGFCS
        if (miInfo != NULL)
        {
            timerMsg = MESSAGE_Alloc(node,
                                     NETWORK_LAYER,
                                     NETWORK_PROTOCOL_IP,
                                     MSG_NETWORK_CES_MI_QueueAgingTimer);
        }
        else
#endif
        {
            timerMsg = MESSAGE_Alloc(node,
                                     NETWORK_LAYER,
                                     NETWORK_PROTOCOL_IP,
                                     MSG_NETWORK_Ip_QueueAgingTimer);
        }

        MESSAGE_InfoAlloc(node, timerMsg, sizeof(QueueAgeInfo));
        QueueAgeInfo* qInfo = (QueueAgeInfo*)
                               MESSAGE_ReturnInfo(timerMsg);

        // these 4 things should uniquely identify a message.
#ifdef ADDON_BOEINGFCS
        if (miInfo != NULL)
        {
            // contains the true packet priority to be used later...
            qInfo->qNumber = (int)*miInfo;
        }
        else
        {
            qInfo->qNumber = priority;
        }
#else
        qInfo->qNumber = priority;
#endif
        qInfo->msgPtr = msg; 
        qInfo->sequenceNumber = msg->sequenceNumber;
        qInfo->originatingNodeId = msg->originatingNodeId;

        MESSAGE_SetInstanceId(timerMsg, interfaceIndex);

        MESSAGE_Send(node, timerMsg, maxPktAge);

    }

#ifdef ADDON_BOEINGFCS
    if (*QueueIsFull)
    {
        signalCongestion(node, interfaceIndex, msg);
    }

    if (miInfo != NULL)
    {
        // no need to carry this info any more...
        MESSAGE_RemoveInfo(node, msg, INFO_TYPE_MIQoSAgePacket);
    }
#endif

}

void Queue::insert(
    Node* node,
    int interfaceIndex,
    int priority,
    Message* msg,
    const void *infoField,
    BOOL* QueueIsFull,
    const clocktype currentTime,
    const double serviceTag
    )
{
    insert(node, interfaceIndex, priority, msg, infoField, QueueIsFull, currentTime, NULL, serviceTag);
}

// /**
// FUNCTION   :: Queue::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a queue data structure in order to dequeue,
//               peek at, or drop a message in its array of stored messages.
//               It now includes the "DropFunction" functionality as well.
// PARAMETERS ::
// + msg : Message** : The retrieved msg
// + index : const int : The position of the packet in the queue
// + operation : const QueueOperation : The retrieval mode
// + currentTime : const clocktype : Current Simulation time
// + serviceTag : double* : ServiceTag = NULL
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL Queue::retrieve(
    Message** msg,
    const int index,
    const QueueOperation operation,
    const clocktype currentTime,
    double* serviceTag)
{
    int arrayIndex = -1;
    *msg = NULL;
#ifdef ADDON_BOEINGFCS
    // Retrieve packet directly from represented scheduler or queue
    if (queueSuspended != SUSPEND)
    {
        if (representedSched != NULL)
        {
            int msgPriority;
            return representedSched->retrieve(ALL_PRIORITIES,
                                              index,
                                              msg,
                                              &msgPriority,
                                              operation,
                                              currentTime);
        }
        else if (representedQueue != NULL)
        {
            return representedQueue->retrieve(msg,
                                              index,
                                              operation,
                                              currentTime,
                                              serviceTag);
        }
    }
#endif

    if ((numPackets == 0) || !(numPackets > index)
        || (queueSuspended == SUSPEND))
    {
        // Attempting to retrieve a packet that does not exist
        return FALSE;
    }

    switch (operation)
    {
        case DROP_PACKET:
        case DEQUEUE_PACKET:
        case DISCARD_PACKET:
        case DROP_AGED_PACKET:
        {
            ERROR_Assert(((headIndex >= 0) && (headIndex < maxPackets)),
                "Queue Error: The headIndex has become corrupted");

            if (index > 0)
            {
                arrayIndex = RetriveArrayIndex(index);

                *msg = packetArray[arrayIndex].msg;

                if (tailIndex == arrayIndex)
                {
                    tailIndex--;

                    if (tailIndex == -1)
                    {
                        tailIndex = maxPackets - 1;
                    }
                }
                else if (tailIndex > arrayIndex)
                {
                    int numToMove = tailIndex - arrayIndex;

                    memmove(&(packetArray[arrayIndex]),
                            &(packetArray[arrayIndex + 1]),
                            numToMove * sizeof(PacketArrayEntry));

                    tailIndex--;

                    if (tailIndex == -1)
                    {
                        tailIndex = maxPackets - 1;
                    }
                }
                else //(tailIndex < arrayIndex)
                {
                    // Step One: Move the end of the queue over ArrayIndex
                    memmove(&(packetArray[arrayIndex]),
                            &(packetArray[arrayIndex + 1]),
                            (maxPackets - arrayIndex - 1)
                            * sizeof(PacketArrayEntry));

                    // Step Two: Move the first entry over to the end of the array
                    memmove(&(packetArray[maxPackets-1]),
                            &(packetArray[0]),
                            sizeof(PacketArrayEntry));

                    if (tailIndex == 0)
                    {
                        tailIndex = maxPackets - 1;
                    }
                    else
                    {
                        // Step Three: Move the tail entries towards the front
                        //             of the array.
                        memmove(&(packetArray[0]),
                                &(packetArray[1]),
                                tailIndex * sizeof(PacketArrayEntry));

                        tailIndex--;
                    }
                }
            }
            else
            {
                arrayIndex = headIndex;
                *msg = packetArray[headIndex].msg;
                headIndex++;
                if (headIndex == maxPackets)
                {
                    headIndex = 0;
                }
            }

            lastChange = currentTime;

            numPackets--;
            int bytesBeforeOperation = bytesUsed;
            bytesUsed -= MESSAGE_ReturnPacketSize((*msg));

            if (operation == DEQUEUE_PACKET)
            {
                if (isCollectStats)
                {
                    stats->DequeuePacket(*msg, bytesBeforeOperation, currentTime);
                }
#ifdef ADDON_BOEINGFCS
                if (collectDscpStats)
                {
                    QueuePerDscpStats *statsEntry = NULL;
                    statsEntry = QueueGetPerDscpStatEntry((*msg), dscpStats);
                    statsEntry->numPacketsDequeued++;
                }
#endif
                UpdateQueueDelayStats(arrayIndex, currentTime);

                // Update Qos Stats
                totalTransmission += MESSAGE_ReturnPacketSize((*msg));
            }
            else if (operation == DISCARD_PACKET)
            {
                if (isCollectStats)
                {
                    stats->DropPacket(*msg, bytesBeforeOperation, currentTime);
                }
            }
            else if (operation == DROP_PACKET)
            {
                if (isCollectStats)
                {
                    stats->DropPacketForcefully(*msg, bytesBeforeOperation, currentTime);
                }
                UpdateQueueDelayStats(arrayIndex, currentTime);
            }
            else if (operation == DROP_AGED_PACKET)
            {
                if (isCollectStats)
                {
                    stats->DropPacketForcefully(*msg, bytesBeforeOperation, currentTime, true);
                }
                UpdateQueueDelayStats(arrayIndex, currentTime);
            }

            if ((serviceTag != NULL) && (numPackets > 0))
            {
                // Return Service Tag of the packet present at queue Top
                // after this dequeue.
                *serviceTag = packetArray[headIndex].serviceTag;
            }
#ifdef CYBER_LIB
            if (node->resourceManager)
            {
                node->resourceManager->packetFree(*msg);
            }
#endif
            return TRUE;
        }
        case PEEK_AT_NEXT_PACKET:
        {
            // Handles false dequeue functionality
            arrayIndex = RetriveArrayIndex(index);

            ERROR_Assert(((headIndex >= 0) && (headIndex < maxPackets)),
                "Queue Error: The headIndent has become corrupted");

            *msg = packetArray[arrayIndex].msg;

            if (serviceTag != NULL)
            {
                // Return Service Tag of the packet we are looking into
                *serviceTag = packetArray[arrayIndex].serviceTag;
            }
            return TRUE;
        }
        default:
        {
            // Error: Unknown Queue Operation
            ERROR_Assert(FALSE, "Queue Error: Unknown Queue Operation");
            return FALSE; // Not reachable.
        }
    }
}


// /**
// FUNCTION   :: Queue::isEmpty
// LAYER      ::
// PURPOSE    :: This function prototype returns a Boolean value of true
//               if the array of stored messages is empty, false otherwise.
// PARAMETERS :: None
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL Queue::isEmpty(BOOL checkPredecessor)
{
    if (queueSuspended == RESUME)
    {
#ifdef ADDON_BOEINGFCS
    // Choose to check represented scheduler or queue
    if (checkPredecessor == TRUE)
    {
        if (representedSched != NULL)
        {
            return BOOL((numPackets + representedSched->numberInQueue(ALL_PRIORITIES)) == 0);
        }
        else if (representedQueue != NULL)
        {
            return BOOL((numPackets + representedQueue->packetsInQueue()) == 0);
        }
    }
#endif        
        return (BOOL)(numPackets == 0);
    }
    return (BOOL)queueSuspended;
}


// /**
// FUNCTION   :: Queue::bytesInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the number of bytes stored
//               in the array.
// PARAMETERS :: None
// RETURN     :: int : Integer
// **/

int Queue::bytesInQueue(BOOL checkPredecessor)
{
#ifdef ADDON_BOEINGFCS
    // Choose to check represented scheduler or queue
    if (checkPredecessor == TRUE)
    {
        if (representedSched != NULL)
        {
            return (bytesUsed + representedSched->bytesInQueue(ALL_PRIORITIES));
        }
        else if (representedQueue != NULL)
        {
            return (bytesUsed + representedQueue->bytesInQueue());
        }
    }
#endif
    // Returns total bytes in queue.
    return bytesUsed;
}


// /**
// FUNCTION   :: Queue::freeSpaceInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns free space in number of
//               bytes in the queue.
// PARAMETERS ::
// RETURN     :: int: number of bytes free.
// **/
int Queue::freeSpaceInQueue()
{
    return(queueSizeInBytes - bytesUsed);
}


// /**
// FUNCTION   :: Queue::packetsInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the number of Messages
//               stored in the packetArray.
// PARAMETERS :: None
// RETURN     :: int : Integer
// **/

int Queue::packetsInQueue(BOOL checkPredecessor)
{
#ifdef ADDON_BOEINGFCS
    // Choose to check represented scheduler or queue
    if (checkPredecessor == TRUE)
    {
        if (representedSched != NULL)
        {
            return (numPackets + representedSched->numberInQueue(ALL_PRIORITIES));
        }
        else if (representedQueue != NULL)
        {
            return (numPackets + representedQueue->packetsInQueue());
        }
    }
#endif
    // Returns the number of packets in queue.
    return numPackets;
}


// /**
// FUNCTION   :: Queue::sizeOfQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the size of the Queue
// PARAMETERS :: None
// RETURN     :: int : Integer
// **/

int Queue::sizeOfQueue()
{
    // Returns the size of the Queue
    return queueSizeInBytes;
}


// /**
// FUNCTION   :: Queue::setServiceTag
// LAYER      ::
// PURPOSE    :: Set the service tag of the queue
// PARAMETERS ::
// + serviceTag : double : the value of the service tag
// RETURN     :: void : NULL
// **/

void Queue::setServiceTag(double serviceTag)
{
    packetArray[tailIndex].serviceTag = serviceTag;
}


// /**
// FUNCTION   :: Queue::replicate
// LAYER      ::
// PURPOSE    :: This function is proposed to replicate the state of the
//               queue, as if it had been the operative queue all along.
//               If there are packets in the existing queue, they are
//               transferred one-by-one into the new queue. This can result
//               in additional drops of packets that had previously been
//               stored. This function returns the number of additional
//               drops.
// PARAMETERS ::
// + oldQueue : Queue* : Old queue pointer
// RETURN     :: int : Old packetArray
// **/

int Queue::replicate(Queue* oldQueue)
{
    Message* msg = NULL;
    BOOL isRetreived = FALSE;
    BOOL QueueIsFull = FALSE;
    int numExtraDrop = 0;

    for (int i = 0; i < oldQueue->numPackets; i++)
    {
        isRetreived = oldQueue->retrieve(&msg,
                                    i,
                                    PEEK_AT_NEXT_PACKET,
                                    oldQueue->packetArray[i].insertTime);

        ERROR_Assert(msg,
            "Queue Error: Msg in Old Queue has become corrupted");

        insert(msg,
               oldQueue->packetArray[i].infoField,
               &QueueIsFull,
               oldQueue->packetArray[i].insertTime,
               oldQueue->packetArray[i].serviceTag);

        if (QueueIsFull)
        {
            numExtraDrop++;
        }
    }

    MEM_free(oldQueue->packetArray);
    oldQueue->numPackets = 0;
    oldQueue->packetArray = NULL;
#ifdef ADDON_BOEINGFCS
    representedSched = oldQueue->representedSched;
    representedQueue = oldQueue->representedQueue;
#endif
    return numExtraDrop;
}


// /**
// FUNCTION   :: Queue::setQueueBehavior
// LAYER      ::
// PURPOSE    :: This function is proposed to identify and tag misbehaved
//               queue at the interface, so that they can be punished.
// PARAMETERS ::
// + suspend : BOOL : The queue status
// RETURN     :: void : Null
// **/

void Queue::setQueueBehavior(BOOL suspend)
{
    queueSuspended = suspend;
}

// /**
// FUNCTION   :: Queue::getQueueBehavior
// LAYER      ::
// PURPOSE    :: This function return the current queue behavior
// PARAMETERS ::
// RETURN     :: BOOL : The queue status
// **/
BOOL Queue::getQueueBehavior()
{
    return queueSuspended;
}// end of getQueueBehavior

// /**
// FUNCTION   :: Queue::qosQueueInformationUpdate
// LAYER      ::
// PURPOSE    :: This function is proposed for qos information update
//               for Qos Routings like Qospf.
// PARAMETERS ::
// + qDelayVal : int* : Returning qDelay value
// + totalTransmissionVal : int* : Returning totalTransmission value
// + currentTime : const clocktype : Current simulation time
// + isResetTotalTransmissionVal : BOOL : Default false
// RETURN     :: void : Null
// **/
void Queue::qosQueueInformationUpdate(
    int* qDelayVal,
    int* totalTransmissionVal,
    const clocktype currentTime,
    BOOL isResetTotalTransmissionVal)
{
    *qDelayVal = qDelay;
    *totalTransmissionVal = totalTransmission;

    // Ref: ../network/qospf.cpp
    // Modification of average queuing delay, stored in
    // Queue->qDelay, occurs during queueing of a packet.
    // But for a long time if the queue has no packet to de queue,
    // this delay will not be modified. This checking is introduced
    // to modify the value to zero if the queue is inactive during
    // last flooding period.

    if ((currentTime - lastChange) > qosMonitorInterval)
    {
        qDelay = 0;
    }

    if (isResetTotalTransmissionVal)
    {
        totalTransmission = 0;
    }
}


// /**
// FUNCTION   :: Queue::byteDequeuedInPeriod
// LAYER      ::
// PURPOSE    :: This function prototype returns the number of bytes dequeued,
//               not dropped, during a given period.  This period starts at
//               the beginning of the simulation, and restarts whenever the
//               Queue resetPeriod function is called.
// PARAMETERS :: None
// RETURN     :: int : Integer
// **/
inline int Queue::byteDequeuedInPeriod()
{
    // Returns the number of packets in queue.
    return bytesDequeuedInPeriod;
}


// /**
// FUNCTION   :: Queue::utilizationInPeriod
// LAYER      ::
// PURPOSE    :: This function prototype returns the queue utilization, or
//               the amount of time that the queue is nonempty, during a
//               given period. This period starts at the beginning of the
//               simulation, and restarts whenever the queue resetPeriod
//               function is called.
// PARAMETERS :: None
// RETURN     :: clocktype : Utilize Time.
// **/
inline clocktype Queue::utilizationInPeriod()
{
    return utilizedTime;
}


// /**
// FUNCTION   :: Queue::averageTimeInQueue
// LAYER      ::
// PURPOSE    :: This function prototype returns the average time a packet
//               spends in the queue, during a given period.  This period
//               starts at the beginning of the simulation, and restarts
//               whenever the QueueResetPeriodFunctionType function is called.
// PARAMETERS :: None
// RETURN     :: clocktype : Queue Delays.
// **/
inline clocktype Queue::averageTimeInQueue()
{
    return queueDelaysDuringPeriod;
}


// /**
// FUNCTION   :: Queue::resetPeriod
// LAYER      ::
// PURPOSE    :: This function prototype resets the current period statistics
//               variables, and sets the currentPeriodStartTime to the
//               currentTime.
// PARAMETERS ::
// + currentTime : clocktype : Current simulation time.
// RETURN     :: void : Null
// **/

inline void Queue::resetPeriod (clocktype currentTime)
{
    currentStateStartTime = 0;
    utilizedTime = 0;
    stateIsIdle = TRUE;
    bytesDequeuedInPeriod = 0;
    packetsDequeuedInPeriod = 0;
    currentPeriodStartTime = currentTime;
    queueDelaysDuringPeriod = 0;
}


// /**
// FUNCTION   :: Queue::periodStartTime
// LAYER      ::
// PURPOSE    :: This function prototype returns the currentPeriodStartTime.
// PARAMETERS ::
// RETURN     :: clocktype : Current period start time.
// **/

inline clocktype Queue::periodStartTime()
{
    return currentPeriodStartTime;
}


// /**
// FUNCTION   :: Queue::finalize
// LAYER      ::
// PURPOSE    :: This function prototype outputs the final statistics for
//               this queue.  The layer, protocol, interfaceAddress, and
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

void Queue::finalize(
    Node *node,
    const char *layer,
    const int interfaceIndex,
    const int instanceId,
    const char* invokingProtocol,
    const char* splStatStr)
{
    char tempQueueType[MAX_STRING_LENGTH] = {0};
    char queueType[MAX_STRING_LENGTH] = {0};


    if (!isCollectStats)
    {
        return;
    }

    if (splStatStr)
    {
        sprintf(tempQueueType, "FIFO %s", splStatStr);
    }
    else
    {
        sprintf(tempQueueType, "FIFO");
    }

    if (strcmp(invokingProtocol, "IP"))
    {
        sprintf(queueType, "%s %s", invokingProtocol, tempQueueType);
    }
    else
    {
        sprintf(queueType, "%s", tempQueueType);
    }

    FinalizeQueue(node,
                  layer,
                  queueType,
                  interfaceIndex,
                  instanceId,
                  invokingProtocol);
}

clocktype Queue::getPacketInsertTime(int pktIndex)
{
    int arrayIndex;

    if (numPackets == 0)
    {
        return 0;
    }

    arrayIndex = RetriveArrayIndex(pktIndex);
    return packetArray[arrayIndex].insertTime;
}

// /**
// FUNCTION   :: Queue::SetupQueue
// LAYER      ::
// PURPOSE    :: This function runs queue initialization routine. Any
//               algorithm specific configurable parameters will be kept in
//               a structure and after feeding that structure the structure
//               pointer will be sent to this function via that void pointer
//               configInfo. Some parameters includes default values, to
//               prevent breaking existing models. [Uses: vide Pseudo code]
// PARAMETERS ::
// + node : Node* : node
// + queueTypeString[] : const char : Queue type string
// + queueSize : const int : Queue size in bytes
// + interfaceIndex : const int : used to generate random seed
// + qNumber : const int : used to generate random seed
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

void Queue::SetupQueue(
    Node* node,
    const char queueTypeString[],
    const int queueSize,
    const int interfaceIndex,
    const int qNumber,
    const int infoFieldSize,
    const BOOL enableQueueStat,
    const BOOL showQueueInGui,
    const clocktype currentTime,
    const void* configInfo
#ifdef ADDON_DB
    ,const char* queuePosition
#endif
    , const clocktype pktMaxAge
#ifdef ADDON_BOEINGFCS
    , const BOOL enablePerDscpStat
    ,Scheduler* repSched
    ,Queue* repQueue
#endif

    )
{

//#ifdef ADDON_BOEINGFCS
    memset(queueType, 0, MAX_STRING_LENGTH);
    memcpy(queueType, queueTypeString, strlen(queueTypeString));
//#endif

    // sanity check sinec pktMaxAge can be set to CLOCKTYPE_MAX
    // and if SetupQueue configured improperly, value may be 
    // assigned to currentTime, which will cause incorrect 
    // statistics.
    if (currentTime == CLOCKTYPE_MAX)
    {
        ERROR_ReportError("Queue Creation Time Cannot be CLOCKTYPE_MAX!!");
    }

#ifdef ADDON_DB    
    queueDBHookPtr = NULL;

    StatsDb* db = node->partitionData->statsDb;

    if (db && db->statsEventsTable->createQueueEventsTable)
    {
        queueDBHookPtr = new StatsQueueDB::StatsQueueEventHook(
            queueTypeString, node, interfaceIndex, this, (char *)queuePosition);
    }
    if (db && db->statsDescTable->createQueueDescTable) 
    {
        meta_data = new MetaDataStruct;
        meta_data->AddQueueMetaData(node,
                                   node->partitionData,
                                   node->partitionData->nodeInput);
    }
#endif

#ifdef ADDON_BOEINGFCS
    dscpStats = new QueuePerDscpMap;
    dscpStats->set_empty_key ((int)-3);
    dscpStats->set_deleted_key ((int)-2);
#endif

    queueSizeInBytes = queueSize;
    qDelay = 0;
    totalTransmission = 0;
    // Note: might be a QualNet Configurable parameter
    qosMonitorInterval = QOS_DEFAULT_INTERFACE_OBSERVATION_INTERVAL;

    queueCreationTime = currentTime;
    queueSuspended = FALSE;

    maxPackets = (int) MAX(ceil((double)queueSizeInBytes
        / DEFAULT_ETHERNET_MTU), 2);

    // The maxPackets value should be greater than or equal to 1
    ERROR_Assert(maxPackets >= 1,
        "Queue Error: Maximum number of packet must be >=1");

    packetArray = (PacketArrayEntry*)
        MEM_malloc(sizeof(PacketArrayEntry) * maxPackets);
    memset(packetArray, 0, sizeof(PacketArrayEntry) * maxPackets);

    numPackets = 0;
    bytesUsed = 0;
    headIndex = 1;
    tailIndex = 0;

    delayAveragingWeight = (float)DEFAULT_QUEUE_DELAY_WEIGHT_FACTOR;

    lastChange = 0;

    maxPktAge = pktMaxAge;
    queueNumber = qNumber;

    isCollectStats = enableQueueStat;

    this->node = node;

#ifdef ADDON_BOEINGFCS
    collectDscpStats = enablePerDscpStat;
    ERROR_Assert((repSched == NULL ||  repQueue == NULL),
        "Queue cannot represent both another scheduler and another queue at the same time");
    representedSched = repSched;
    representedQueue = repQueue;
#endif

#ifdef ADDON_DB
    if (queuePosition == NULL)
    {
        queuePosition = "";
    }
#endif
    if (!enableQueueStat)
    {
#ifdef ADDON_DB
        if (node->partitionData->statsDb != NULL)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createQueueAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Aggregate table requires\n"
                    " QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsSummaryTable->createQueueSummaryTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Summary table requires\n"
                    " QUEUE-STATISTICS to be set to YES\n");
            }
            if (node->partitionData->statsDb->statsStatusTable->createQueueStatusTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration settings: Use of StatsDB QUEUE_Status table requires\n"
                    " QUEUE-STATISTICS to be set to YES\n");
            }
        }
#endif
    }
    else
    {
        stats = new STAT_QueueStatistics(node,
    #ifdef ADDON_DB
            queuePosition,
    #else
            "",
    #endif
            interfaceIndex,
            queueTypeString,
            queueSize,
            queueNumber,
            currentTime);
    }
}

// /**
// FUNCTION   :: Queue::~Queue
// LAYER      ::
// PURPOSE    :: This function will free the memory in the queue
// PARAMETERS ::
// RETURN     :: void : Null
// **/
Queue::~Queue()
{
    if (packetArray != NULL)
    {
        while (numPackets)
        {
#ifdef ADDON_DB
        using namespace StatsQueueDB;
        if (queueDBHookPtr)
        {
            queueDBHookPtr->eventHook(packetArray[headIndex].msg,                 
                TRUE, 0, // queue priority
                STATS_QUEUE_DROP_PACKET,
                packetArray[headIndex].insertTime) ;
        }
#endif
            if (isCollectStats)
            {
                stats->DropPacket(packetArray[headIndex].msg, bytesUsed, node->getNodeTime());
            }
#ifdef ADDON_BOEINGFCS
            if (collectDscpStats)
            {
                QueuePerDscpStats *statsEntry = NULL;
                statsEntry = QueueGetPerDscpStatEntry(packetArray[headIndex].msg, dscpStats);
                statsEntry->numPacketsDropped++;
            }
#endif

            bytesUsed -= MESSAGE_ReturnPacketSize(packetArray[headIndex].msg);
            MESSAGE_Free((PartitionData*) NULL, packetArray[headIndex].msg);

            numPackets --;
            headIndex ++;
            if (headIndex == maxPackets)
            {
                headIndex = 0;
            }
        }

        MEM_free(packetArray);
        packetArray = NULL;
        tailIndex = 0;
        headIndex = 0;
    }

#ifdef ADDON_DB
    delete meta_data;
    if (queueDBHookPtr)
    {
        delete queueDBHookPtr;
    }

    if (isCollectStats)
    {
        //Add the old stats to the global inactive queue list
        node->partitionData->stats->global.inactiveQueues.push_back(stats);
    }
#endif
}

//--------------------------------------------------------------------------
// End: Public Interface functions
//--------------------------------------------------------------------------

#ifdef ADDON_BOEINGFCS
clocktype Queue::getTopPacketInsertTime()
{
    int arrayIndex;

    if (numPackets == 0)
    {
        return 0;
    }

    arrayIndex = RetriveArrayIndex(0);
    return packetArray[arrayIndex].insertTime;
}

void Queue::signalCongestion(Node* node,
                             int interfaceIndex,
                             Message* msg)
{
}
#endif

// /**
// FUNCTION   :: QUEUE_Setup
// LAYER      ::
// PURPOSE    :: This function runs the generic and then the
//               algorithm-specific queue initialization routine.
// PARAMETERS ::
// + node : Node* : node
// + queue : Queue** : Pointer of pointer to Queue class
// + queueTypeString[] : const char : Queue Type as specified in config file
// + queueSize : const int : Queue Size
// + interfaceIndex : const int : used for setting random seed
// + queueNumber : const int : used for setting random seed
// + infoFieldSize : const int : Default value 0;
// + enableQueueStat : const BOOL : Default value false
// + showQueueInGui : const BOOL : To show this Queue in GUI
// + currentTime : const clocktype : Current simulation time.
// + configInfo : const void* : Pointer to a structure that contains
//                              configuration parameters for a Queue Type
//                              This is not required for FIFO. Is it is
//                              found NULL for any other Queue Type the
//                              default setting will be applied for that
//                              queue Type. Default is NULL.

// RETURN     :: void : Null
// **/

void QUEUE_Setup(
    Node* node,
    Queue** queue,
    const char queueTypeString[],
    const int queueSize,
    const int interfaceIndex,
    const int qNumber,
    const int infoFieldSize,
    const BOOL enableQueueStat,
    const BOOL showQueueInGui,
    const clocktype currentTime,
    const void* configInfo,
    const clocktype maxPktAge
#ifdef ADDON_DB
    ,const char *queuePosition
#endif
#ifdef ADDON_BOEINGFCS
    ,const BOOL enablePerDscpStat
    ,Scheduler* repSched
    ,Queue* repQueue
#endif

    )
{
    if (!strcmp(queueTypeString, "FIFO"))
    {
        *queue = new Queue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
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
                             , enablePerDscpStat
                             ,repSched
                             ,repQueue
#endif
                             );
    }
    else if (!strcmp(queueTypeString, "RED"))
    {
        *queue = new RedQueue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
                             infoFieldSize,
                             enableQueueStat,
                             showQueueInGui,
                             currentTime,
                             configInfo
#ifdef ADDON_DB
                             ,queuePosition
#endif
                             , maxPktAge        
#ifdef ADDON_BOEINGFCS
                             , enablePerDscpStat
                             ,repSched
                             ,repQueue
#endif
                             );
    }
    else if (!strcmp(queueTypeString, "RED-ECN"))
    {
        // In any case this implementation includes ip.h | ipv6.h
        // to access TOS | TCLASS field of ipHeader

        *queue = new EcnRedQueue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
                             infoFieldSize,
                             enableQueueStat,
                             showQueueInGui,
                             currentTime,
                             configInfo
#ifdef ADDON_DB
                             ,queuePosition
#endif
                             , maxPktAge        
#ifdef ADDON_BOEINGFCS
                             ,enablePerDscpStat
                             ,repSched
                             ,repQueue
#endif
                             );
    }
    else if (!strcmp(queueTypeString, "WRED"))
    {
        // In any case this implementation includes ip.h | ipv6.h
        // to access TOS | TCLASS field of ipHeader

        *queue = new EcnWredQueue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
                             infoFieldSize,
                             enableQueueStat,
                             showQueueInGui,
                             currentTime,
                             configInfo
#ifdef ADDON_DB
                             ,queuePosition
#endif
                             , maxPktAge        
#ifdef ADDON_BOEINGFCS
                             ,enablePerDscpStat
                             ,repSched
                             ,repQueue
#endif
                             );
    }
    else if (!strcmp(queueTypeString, "RIO"))
    {
        // In any case this implementation includes ip.h | ipv6.h
        // to access TOS | TCLASS field of ipHeader

        *queue = new EcnRioQueue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
                             infoFieldSize,
                             enableQueueStat,
                             showQueueInGui,
                             currentTime,
                             configInfo
#ifdef ADDON_DB
                             ,queuePosition
#endif
                             , maxPktAge        
#ifdef ADDON_BOEINGFCS
                             , enablePerDscpStat
                             ,repSched
                             ,repQueue
#endif
                             );
    }
    else if (!strcmp(queueTypeString, "ATM-RED"))
    {
        *queue = new AtmRedQueue;
        (*queue)->SetupQueue(node,
                             queueTypeString,
                             queueSize,
                             interfaceIndex,
                             qNumber,
                             infoFieldSize,
                             enableQueueStat,
                             showQueueInGui,
                             currentTime,
                             configInfo
#ifdef ADDON_DB
                             ,queuePosition
#endif
                             , maxPktAge        
#ifdef ADDON_BOEINGFCS
                             , enablePerDscpStat
#endif
                             );
    }
    else
    {
        char errStr[MAX_STRING_LENGTH] = {0};
        sprintf(errStr, "Queue Error:"
            " Unknown Queue Type Specified: %s", queueTypeString);
        ERROR_Assert(FALSE, errStr);
    }

    if (queue == NULL)
    {
        // Error: No Queue exits with such priority value
        char errStr[MAX_STRING_LENGTH] = {0};
        sprintf(errStr, "Queue Error:"
            " Failed to assign memory for  %s", queueTypeString);
        ERROR_Assert(FALSE, errStr);
    }
}


void QUEUE_HandleEvent(Node* node, Message* msg)
{
    int interfaceIndex = MESSAGE_GetInstanceId(msg);
    switch (msg->eventType)
    {
        case MSG_NETWORK_Ip_QueueAgingTimer:
        {
            NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
            Message* tmpMsg = NULL;
            QueueAgeInfo* qInfo = (QueueAgeInfo*)
                                    MESSAGE_ReturnInfo(msg);
            QueuePriorityType queuePriority = ALL_PRIORITIES;

            Scheduler *scheduler = NULL;
            scheduler = ip->interfaceInfo[interfaceIndex]->scheduler;

            int qIndex = 0;
            int qSize = (*scheduler).numberInQueue(qInfo->qNumber);

            while (qIndex < qSize)
            {
                if ((*scheduler).retrieve(qInfo->qNumber,
                                          qIndex,
                                          &tmpMsg,
                                          &queuePriority, 
                                          PEEK_AT_NEXT_PACKET,
                                          node->getNodeTime()))
                {
                    ERROR_Assert(qInfo->qNumber == queuePriority,
                                 "Packet from wrong priority queue!!");

                    ERROR_Assert(tmpMsg, "Message should not be NULL!!");

                    if (tmpMsg->sequenceNumber == qInfo->sequenceNumber &&
                        tmpMsg->originatingNodeId == qInfo->originatingNodeId &&
                        tmpMsg == qInfo->msgPtr)
                    {
                        //char clockStr[MAX_STRING_LENGTH];
                        //char pktStr[MAX_STRING_LENGTH];
                        //TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        //TIME_PrintClockInSecond((*scheduler).getPacketInsertTime(qInfo->qNumber, qIndex), pktStr);

                        BOOL haveMsg = FALSE;
                        haveMsg = (*scheduler).retrieve(qInfo->qNumber,
                                                        qIndex,
                                                        &tmpMsg,
                                                        &queuePriority, 
                                                        DROP_AGED_PACKET,
                                                        node->getNodeTime());

                        ERROR_Assert(qInfo->qNumber == queuePriority,
                                     "Packet from wrong priority queue!!");

                        ERROR_Assert(haveMsg, "Queue retrieve problem!");

                        /*printf("[%s] Node %d DROPPING Message %d originatingNodeId %d msgPtr %ld from Queue %d inserTime %s\n",
                               clockStr, node->nodeId, tmpMsg->sequenceNumber, tmpMsg->originatingNodeId, tmpMsg, queuePriority, pktStr);*/
#ifdef ADDON_DB
                        
                        HandleNetworkDBEvents(
                            node,
                            tmpMsg,
                            interfaceIndex,        
                            "NetworkPacketDrop",
                            "Packet Aged in Queue",
                            0,
                            0,
                            0,
                            0);
#endif
                        MESSAGE_Free(node, tmpMsg);
                        break;
                    }
                    // else, its not the same packet this timer was created for
                }

                qIndex++;
            }
            break;
        }
#ifdef ADDON_BOEINGFCS
        case MSG_NETWORK_CES_MI_QueueAgingTimer:
        {
            QueueAgeInfo* qInfo = (QueueAgeInfo*)MESSAGE_ReturnInfo(msg);

            if (MICesQosGetAgedPacket(node,
                                      interfaceIndex,
                                      qInfo->qNumber,
                                      qInfo->sequenceNumber,
                                      qInfo->originatingNodeId,
                                      qInfo->msgPtr))
            {
#ifdef ADDON_DB
                        
                    HandleNetworkDBEvents(
                        node,
                        qInfo->msgPtr,
                        interfaceIndex,        
                        "NetworkPacketDrop",
                        "Packet Aged in MI Queue",
                        0,
                        0,
                        0,
                        0);
#endif
                MESSAGE_Free(node, qInfo->msgPtr);
            }

            break;
        }
#endif
        default:
        {
            ERROR_ReportError("Queue Event not supported!");
        }
    }

    MESSAGE_Free(node, msg);

}
// /**
// FUNCTION   :: Queue::getQueueNumber
// LAYER      ::
// PURPOSE    :: This function prototype returns the number/index of the Queue
// PARAMETERS :: None
// RETURN     :: int : Integer
// **/

int Queue::getQueueNumber()
{
    // Returns the number/index of the Queue
    return queueNumber;
}
