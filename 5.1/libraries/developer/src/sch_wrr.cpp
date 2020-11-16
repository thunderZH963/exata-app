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
// + A Methodology for Study of Network Processing Architectures.
//   SURYANARAYANAN, DEEPAK.(Under the direction of Dr.Gregory T Byrd.)
//   http://www.lib.ncsu.edu/etd/public/etd-45401520610152001/etd.pdf
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"

#include "sch_wrr.h"

#include "sch_graph.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

//--------------------------------------------------------------------------
// Start: Utility Functions
//--------------------------------------------------------------------------

//**
// FUNCTION   :: WrrScheduler::CalculateGreatestCommonDivisor
// LAYER      ::
// PURPOSE    :: Returns Greatest Common Divisor of two integer.
// PARAMETERS ::
// + a : int : Integer Value
// + b : int : Integer Value
// RETURN     :: int : Integer
// **/

int WrrScheduler::CalculateGreatestCommonDivisor(int a, int b)
{
    int max, min, rem;

    max = MAX(a, b);
    min = MIN(a, b);

    while (max % min)
    {
        rem = max;
        max = min;
        min = rem % min;
    }
    return min;
}


//**
// FUNCTION   :: WrrScheduler::ReassignQueueWeightCounter
// LAYER      ::
// PURPOSE    :: Calculates The weightCounter value for WRR packet scheduler
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void WrrScheduler::ReassignQueueWeightCounter()
{
    int i = 0;

    for (i = 0; i < numQueues; i++)
    {
        queueInfo[i].weightCounter =
            (int)((queueData[i].weight * WRR_WEIGHT_MULTIPLIER)  + 0.5) / gcdInfo;
    }

    // Calculate WRR serviceRound
    for (i = 0; i < numQueues; i++)
    {
        serviceRound +=  queueInfo[i].weightCounter;
    }

    if (WRR_DEBUG)
    {
        for (i = 0; i < numQueues; i++)
        {
            printf("\t\t\tweightCounter[%d] = %d \n",
                queueData[i].priority, queueInfo[i].weightCounter);
        }
        printf("\n\t\t\tTotal serviceRound = %u,\n", serviceRound);
        printf("\t\t ----------------Complete---------------\n\n");
    }
}


//**
// FUNCTION   :: WrrScheduler::AssignQueueWeightCounter
// LAYER      ::
// PURPOSE    :: Calculates the final gcd value to evaluate weightCounter
//               for WRR packet scheduler.
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void WrrScheduler::AssignQueueWeightCounter()
{
    int i = 0;
    int gcd = 0;

    gcd = (int)((queueData[0].weight * WRR_WEIGHT_MULTIPLIER) + 0.5);

    for (i = 0; i < numQueues - 1; i++)
    {
        gcd = CalculateGreatestCommonDivisor (gcd,
            (int)((queueData[i + 1].weight * WRR_WEIGHT_MULTIPLIER) + 0.5));
    }

    gcdInfo = gcd;

    if (WRR_DEBUG)
    {
        printf("\n\t\t -------Weight Counter Assignment-------\n");
    }

    ReassignQueueWeightCounter();
}


//**
// FUNCTION   :: WrrScheduler::AutoWeightAssignment
// LAYER      ::
// PURPOSE    :: Assigns queue weights
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void WrrScheduler::AutoWeightAssignment()
{
    int i;
    unsigned int sumQueuePriority = 0;  // Sum of (priority + 1)

    // Calculate Sum of all Active Queues (Priority + 1)
    for (i = 0; i < numQueues; i++)
    {
        sumQueuePriority += (queueData[i].priority + 1);
    }

    // Assign weight to each active queue
    if (WRR_DEBUG_WEIGHT)
    {
        printf("Calculating Queue Weight .......\n");
    }

    for (i = 0; i < numQueues; i++)
    {
        queueData[i].weight = (queueData[i].priority + 1)
                                / (float) sumQueuePriority;

        if (WRR_DEBUG_WEIGHT)
        {
            printf("\t\tweight[%d] = %0.9lf\n",
                queueData[i].priority, queueData[i].weight);
        }
    }
}


//**
// FUNCTION   :: WrrScheduler::IsResetServiceRound
// LAYER      ::
// PURPOSE    :: Checks if need to resets all weightCounter for all queues
//               at the interface when the weightCounters belongig to all
//               the active queue equals zero.
// PARAMETERS :: None
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL WrrScheduler::IsResetServiceRound()
{
    int j;
    int numActiveQueue = 0;       // Number of Active queues at interface
    int numZeroWeightCounter = 0; // Number of Active queues with zero
                                  // weightCounter on this interface

    for (j = 0; j < numQueues; j++)
    {
        // Find the number of active queues with zero weightCounter
        if ((!queueData[j].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                          TRUE
#endif
                                          )) &&
            (queueInfo[j].weightCounter == 0))
        {
            numZeroWeightCounter += 1;
        }

        // Find the number of active queues
        if (!queueData[j].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                         TRUE
#endif
                                         ))
        {
            numActiveQueue += 1;
        }

        if (WRR_DEBUG_WEIGHT)
        {
            printf("\t\t Number of packets in queue[%d] = %d\n",
                j, queueData[j].queue->packetsInQueue());
            printf("\t\t WeightCounter for queue[%d] = %d\n",
                j, queueInfo[j].weightCounter);
        }
    }

    if (numActiveQueue == numZeroWeightCounter)
    {
        // All active queue weightCounters equal zero
        // reset the serviceRound and weightCounters

        return TRUE;
    }
    return FALSE;
}


//**
// FUNCTION   :: WrrScheduler::WrrSelectNextQueue
// LAYER      ::
// PURPOSE    :: Schedules for a queueIndex And packetIndex to be dequeued
// PARAMETERS ::
// + index : int : The position of the packet in the queue
// + queueIndex : int* : Queue index
// + packetIndex : int* : Packet's index
// RETURN     :: void : Null
// **/

void WrrScheduler::WrrSelectNextQueue(
    int index,
    int* queueIndex,
    int* packetIndex)
{
    int i = 0;
    int numOfQueuesChecked = 1;  // The number of queues checked

    *packetIndex = 0; // The position of the packet in the selected queue
    *queueIndex = queueIndexInfo;

    if (WRR_DEBUG)
    {
         printf("\t\t Last dequeued queue = %d\n\n", *queueIndex);
         printf("\t -------------WRR Selection Procedure-------------\n\n");
         printf("\t\t Got index = %d \n", index);
    }

    while (TRUE)
    {
        if (serviceRound != 0)
        {
            // Resetting serviceRound by force as all active queue
            // weightCounters equal zero

            if (IsResetServiceRound())
            {
                serviceRound = 0;

                if (WRR_DEBUG)
                {
                    printf("\t\t Resetting serviceRound by force...\n");
                    printf("\n\t\t --------------Reset"
                        " Start--------------\n");
                }

                // Reassign all the weightCounter
                ReassignQueueWeightCounter();
            }
        }
        else // serviceRound finished.
        {
            if (WRR_DEBUG)
            {
                printf("\t\t Service Round Finished..."
                    "so Reassign WeightCounter\n");
                printf("\n\t\t --------------Reset Start--------------\n");
            }

            // Reassign all the weightCounter
            ReassignQueueWeightCounter();
        }

        if (*queueIndex == numQueues - 1)
        {
            *queueIndex = 0;
        }
        else
        {
            *queueIndex += 1;
        }

        if (WRR_DEBUG)
        {
            printf("\t\t Dequeue request for queue = %d\n", *queueIndex);
            printf("\t\t Scarching for the packet...\n");
            printf("\t\t Value of WeightCounter = %d\n",
                queueInfo[*queueIndex].weightCounter);
            printf("\t\t Number of packets in queue = %d\n",
                queueData[*queueIndex].queue->packetsInQueue());
        }

        // Checking whether the queue is active and its weightCounter is
        // not finished

        if ((!queueData[*queueIndex].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                                    TRUE
#endif
                                                    )) &&
            (queueData[*queueIndex].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                          TRUE
#endif
                                                          )
                > *packetIndex) &&
            (queueInfo[*queueIndex].weightCounter != 0))
        {
            if (i == index)
            {
                ERROR_Assert(queueInfo[*queueIndex].weightCounter >= 0,
                    "WRR : Weight Counter can never be negative\n");

                if (WRR_DEBUG)
                {
                    printf("\t\t Got the packet in this queue\n");
                }

                // Return the selected Queue
                return;
            }
            else
            {
                // queue active so incrementing i;the packet position at
                // the interface

                i++;
            }
        }

        if (WRR_DEBUG)
        {
            printf("\t\t Not selected; switch to next queue\n");
        }

        if (numOfQueuesChecked % numQueues == 0)
        {
            // Update packetIndex
            *packetIndex += 1;

            if (*packetIndex > index)
            {
                // Reset All
                i = 0;
                // The number of queues checked
                // N.B. Making numOfQueuesChecked equals zero here
                numOfQueuesChecked = 0;
                // The position of the packetin the selected queue
                *packetIndex = 0;
                // Reset queueIndex value
                *queueIndex = queueIndexInfo;
                // Reset all weight counters
                ReassignQueueWeightCounter();
            }
        }

        // The number of active queues checked
        numOfQueuesChecked++;
    }
}


//--------------------------------------------------------------------------
// End: Utility Functions
//--------------------------------------------------------------------------

//**
// FUNCTION   :: WrrScheduler::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a scheduler data structure in order to
//               insert a message into it. The scheduler is responsible for
//               routing this packet to an appropriate queue that it
//               controls, and returning whether or not the procedure was
//               successful. The changes here are the replacement of the
//               dscp parameter with the infoField pointer.  The size of
//               this infoField is stored in infoFieldSize.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + QueueIsFull : BOOL* : Queue is full or not
// + queueIndex : const int : Queue Index
// + infoField : const void* : Info field
// + currentTime : const clocktype : Current simulation time
// RETURN     :: void : Null
// **/

void WrrScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void WrrScheduler::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void WrrScheduler::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}


void WrrScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos)
{
    QueueData* qData = NULL;
    int queueIndex;
    int i;

    queueIndex = numQueues;
    for (i = 0; i < numQueues; i ++)
    {
        if (queueData[i].priority == priority)
        {
            queueIndex = i;
            break;
        }
    }

    ERROR_Assert((queueIndex >= 0) && (queueIndex < numQueues),
        "Queue does not exist!!!\n");

    // The priority queue in which incoming packet will be inserted
    qData = &queueData[queueIndex];

    if (WRR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("\nWrr : Simtime %s got packet to enqueue\n", time);
    }

    if (tos == NULL)
    {
       qData->queue->insert(msg, infoField, QueueIsFull, currentTime);
    }
    else
    {
        qData->queue->insert(msg, infoField, QueueIsFull, currentTime, tos);
    }
    if (!*QueueIsFull)
    {
        if (WRR_DEBUG)
        {
            printf("\t  Inserting packet in Queue with priority %u \n\n",
                qData->priority);
        }

        // Update packet enqueue status
        stats[queueIndex].packetQueued++;
    }
    else
    {
        if (WRR_DEBUG)
        {
            printf("\t  Dropping a packet as no space in Queue"
                " with priority %u \n\n", qData->priority);
        }

        // Update packet dequeue status
        stats[queueIndex].packetDropped++;
    }
#ifdef ADDON_DB
    using namespace StatsQueueDB;
    if (qData->queue->returnQueueDBHook())
    {        
        qData->queue->returnQueueDBHook()->eventHook(msg, *QueueIsFull,
            priority,  STATS_INSERT_PACKET);        
    }
#endif
}


//**
// FUNCTION   :: WrrScheduler::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a scheduler data structure in order to
//               dequeue or peek at a message in its array of stored
//               messages. I've reordered the arguments slightly, and
//               incorporated the "DropFunction" functionality as well.
// PARAMETERS ::
// + priority : const int : Priority of the queue
// + index : const int : The position of the packet in the queue
// + msg : Message** : The retrieved msg
// + msgPriority : int* : Msg priority
// + operation : const QueueOperation : The retrieval mode
// + currentTime : const clocktype : Current simulation time
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL WrrScheduler::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime)
{
    int i = 0;
    int j = 0;
    int queueIndex = ALL_PRIORITIES; //-1;
    int packetIndex = 0;

    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;
    *msg = NULL;

    // Check weight Assignments before Running WRR Scheduling
    if (!isAssigned)
    {
        AutoWeightAssignment();
        isAssigned = TRUE;

        if (WRR_DEBUG_WEIGHT)
        {
            for (i = 0; i < numQueues; i++)
            {
                printf("Queue[%d] Weight = %f\n", i, queueData[i].weight);
            }
        }
    }

    if (gcdInfo == 0)
    {
        AssignQueueWeightCounter();
    }

    if (WRR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Wrr : Simtime %s got request to dequeue\n", time);
    }

    if (!(index < numberInQueue(priority
#ifdef ADDON_BOEINGFCS
                                ,TRUE
#endif
        )) || (index < 0))
    {
        if (WRR_DEBUG)
        {
            printf("Wrr: Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    if (priority == ALL_PRIORITIES)
    {
        // Find the queue for dequeuing a packet
        WrrSelectNextQueue(index, &queueIndex, &packetIndex);

        // The queue selected for dequeuing a packet
        qData = &queueData[queueIndex];
    }
    else // if (specificPriorityOnly)
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);

        packetIndex = index;

        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority == qData->priority)
            {
                queueIndex = i;
                break;
            }
        }
    }

    if (WRR_DEBUG)
    {
        printf("\t\t This queue selected for dequeue = %d \n",
            queueIndex);
        printf("\t\t Position of packet in the queue = %d\n", packetIndex);

        printf("\t ------------------------------------------------\n\n");
    }

    // Update the statistical variables for dequeueing
    if (operation == DEQUEUE_PACKET)
    {
        for (j = 0; j < numQueues; j++)
        {
            if (!queueData[j].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                             TRUE
#endif
                                             ))
            {
                // Total number of dequeue requests while queues active
                stats[j].totalDequeueRequest++;
            }
        }
    }

    clocktype insertTime = qData->queue->getPacketInsertTime(packetIndex);

    // Calling Queue retrive function
    isMsgRetrieved = qData->queue->retrieve(msg,
                                            packetIndex,
                                            operation,
                                            currentTime);
    *msgPriority = qData->priority;

    //  If the message is dequeued ,Update related variables
    if (isMsgRetrieved)
    {
        if (operation == DEQUEUE_PACKET)
        {
            // Update WRR related variables
            queueInfo[queueIndex].weightCounter -= 1;
            serviceRound -= 1;

            // Update Dequeue Status
            stats[queueIndex].packetDequeued++;

            // Update queueIndex value
            queueIndexInfo = queueIndex;
        }

        if (operation == DISCARD_PACKET || operation == DROP_PACKET)
        {
            // Update Drop Status
            stats[queueIndex].packetDropped++;
            // Update queueIndex value
            queueIndexInfo = ALL_PRIORITIES; // -1
        }
#ifdef ADDON_DB
        using namespace StatsQueueDB;
        if (qData->queue->returnQueueDBHook() &&
           (operation != PEEK_AT_NEXT_PACKET))
        {
            qData->queue->returnQueueDBHook()->eventHook(*msg, 
                isMsgRetrieved, *msgPriority,  
                (StatsQueueEventType)operation,
                insertTime);
        }
#endif
    }


    if (WRR_DEBUG)
    {
        printf("\t  Retrieved Packet from queue %u\n", qData->priority);
    }

    return isMsgRetrieved;
}


//**
// FUNCTION   :: WrrScheduler::addQueue
// LAYER      ::
// PURPOSE    :: This function adds a queue to a scheduler.
//               This can be called either at the beginning of the
//               simulation (most likely), or during the simulation (in
//               response to QoS situations).  In either case, the
//               scheduling algorithm must accommodate the new queue, and
//               behave appropriately (recalculate turns, order, priorities)
//               immediately. This queue must have been previously setup
//               using QUEUE_Setup. Notice that the default value for
//               priority is the ALL_PRIORITIES constant, which implies that
//               the scheduler should assign the next appropriate value to
//               the queue.  This could be an error condition, if it is not
//               immediately apparent what the next appropriate value would
//               be, given the scheduling algorithm running.
// PARAMETERS ::
// + queue : Queue* : Pointer of Queue class
// + priority : const int : Priority of the queue
// + weight : const double : Weight of the queue
// RETURN     :: int : Integer
// **/

int WrrScheduler::addQueue(
    Queue *queue,
    const int priority,
    const double weight)
{

    if ((weight <= 0.0) || (weight > 1.0))
    {
        // Considering  1.0 as this is the default value
        ERROR_ReportError(
            "WRR: QUEUE-WEIGHT value must stay between <0.0 - 1.0>\n");
    }

    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        WrrStat* newStats
            = new WrrStat[maxQueues + DEFAULT_QUEUE_COUNT];

        WrrPerQueueInfo* newQueueInfo
            = new WrrPerQueueInfo[maxQueues + DEFAULT_QUEUE_COUNT];

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete[] queueData;

            memcpy(newStats, stats, sizeof(WrrStat) * maxQueues);
            delete[] stats;

            memcpy(newQueueInfo, queueInfo,
                sizeof(WrrPerQueueInfo) * maxQueues);
            delete[] queueInfo;
        }

        queueData = newQueueData;
        stats = newStats;
        queueInfo = newQueueInfo;

        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0, "Scheduler addQueue function maxQueues <= 0");

    if (weight < 1.0)
    {
       isAssigned = TRUE;
    }

    if (priority == ALL_PRIORITIES)
    {
        int newPriority;
        int index = numQueues;

        if (numQueues > 0)
        {
            newPriority = queueData[index-1].priority + 1;
        }
        else
        {
            newPriority = 0;
        }

        queueData[index].priority = newPriority;
        queueData[index].weight = (float) weight;
        queueData[index].queue = queue;

        memset(&stats[index], 0, sizeof(WrrStat));
        memset(&queueInfo[index], 0, sizeof(WrrPerQueueInfo));

        numQueues++;
        return queueData[index].priority;
    }
    else //manualPrioritySelection
    {
        int i;
        for (i = 0; i < numQueues; i++)
        {
            ERROR_Assert(queueData[i].priority != priority,
                "Priority queue already exists");
        }

        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority > priority)
            {
                int afterEntries = numQueues - i;
                QueueData* newQueueData = new QueueData[afterEntries];
                WrrStat* newStats = new WrrStat[afterEntries];
                WrrPerQueueInfo* newQueueInfo = new WrrPerQueueInfo[afterEntries];

                memcpy(newQueueData, &queueData[i],
                       sizeof(QueueData) * afterEntries);
                memcpy(&queueData[i+1], newQueueData,
                       sizeof(QueueData) * afterEntries);
                queueData[i].priority = priority;
                queueData[i].weight = (float) weight;
                queueData[i].queue = queue;

                memcpy(newStats, &stats[i],
                       sizeof(WrrStat) * afterEntries);
                memcpy(&stats[i+1], newStats,
                       sizeof(WrrStat) * afterEntries);
                memset(&stats[i], 0, sizeof(WrrStat));

                memcpy(newQueueInfo, &queueInfo[i],
                       sizeof(WrrPerQueueInfo) * afterEntries);
                memcpy(&queueInfo[i+1], newQueueInfo,
                       sizeof(WrrPerQueueInfo) * afterEntries);
                memset(&queueInfo[i], 0, sizeof(WrrPerQueueInfo));

                numQueues++;
                delete[] newQueueData;
                delete[] newQueueInfo;
                delete[] newStats;
                return queueData[i].priority;
            }
        }

        i = numQueues;

        queueData[i].priority = priority;
        queueData[i].weight = (float) weight;
        queueData[i].queue = queue;

        memset(&stats[i], 0, sizeof(WrrStat));
        memset(&queueInfo[i], 0, sizeof(WrrPerQueueInfo));

        numQueues++;
        return queueData[i].priority;
    }
}


//**
// FUNCTION   :: WrrScheduler::removeQueue
// LAYER      ::
// PURPOSE    :: This function removes a queue from the scheduler.
//               This function does not automatically finalize the queue,
//               so if the protocol modeler would like the queue to print
//               statistics before exiting, it must be explicitly finalized.
// PARAMETERS ::
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void WrrScheduler::removeQueue(const int priority)
{
    int i;

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == priority)
        {
            int afterEntries = numQueues - (i + 1);

            if (afterEntries > 0)
            {
                delete queueData[i].queue;
                memmove(&queueData[i], &queueData[i+1],
                    sizeof(QueueData) * afterEntries);

                memmove(&stats[i], &stats[i+1],
                    sizeof(WrrStat) * afterEntries);

                memmove(&queueInfo[i], &queueInfo[i+1],
                    sizeof(WrrPerQueueInfo) * afterEntries);
            }
            else
            {
                delete queueData[i].queue;
            }
            numQueues--;
            return;
        }
    }
}


//**
// FUNCTION   :: WrrScheduler::swapQueue
// LAYER      ::
// PURPOSE    :: This function substitutes the newly initialized queue
//               passed into this function, for the existing queue in
//               the scheduler, of type priority.  If there are packets
//               in the existing queue, they are transferred one-by-one
//               into the new queue.  This is done to attempt to replicate
//               the state of the queue, as if it had been the operative
//               queue all along.  This can result in additional drops of
//               packets that had previously been stored, and for
//               which there may be physical space in the queue.
//               If there is no such queue, it is added.
// PARAMETERS ::
// + queue : Queue* : Pointer of the Queue class
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void WrrScheduler::swapQueue(
    Queue* queue,
    const int priority)
{
    int i = 0;
    int numExtraDrops = 0;

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == priority)
        {
            Queue* oldQueue = queueData[i].queue;
            queueData[i].queue = queue;

            if (!oldQueue->isEmpty())
            {
                // If there are packets in the existing queue,
                // they are transferred one-by-one
                // into the new queue.

                numExtraDrops = queueData[i].queue->replicate(oldQueue);
            }

            // Update Enqueue, Dequeue and Drop Scheduler Stats for this Queue.
            stats[i].packetQueued -= numExtraDrops;
            stats[i].packetDropped += numExtraDrops;

            delete oldQueue;
            return;
        }
    }

    // If there is no such queue, it is added.
    addQueue(queue, priority);
}


//**
// FUNCTION   :: WrrScheduler::finalize
// LAYER      ::
// PURPOSE    :: This function prototype outputs the final statistics for
//               this scheduler. The layer, protocol, interfaceAddress, and
//               instanceId parameters are given to IO_PrintStat with each
//               of the queue's statistics.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + interfaceIndex : const int : Interface index
// + invokingProtocol : const char* : The protocol string
// + splStatStr : const char* Special string for stat print
// RETURN     :: void : Null
// **/

void WrrScheduler::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char *invokingProtocol,
    const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};
    char schedType[MAX_STRING_LENGTH] = "WRR";

    if (schedulerStatEnabled == FALSE)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP") == 0)
    {
        // IP scheduling finalization
        NetworkIpGetInterfaceAddressString(node,
                                           interfaceIndex,
                                           intfIndexStr);
    }
    else
    {
        memset(schedType, 0, MAX_STRING_LENGTH);
        sprintf(schedType, "%s WRR", invokingProtocol);
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    for (i = 0; i < numQueues; i++)
    {
        sprintf(buf, "Packets Queued = %u", stats[i].packetQueued);
        IO_PrintStat(
            node,
            layer,
            schedType,
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dequeued = %u", stats[i].packetDequeued);
        IO_PrintStat(
            node,
            layer,
            schedType,
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dropped = %u", stats[i].packetDropped);
        IO_PrintStat(
            node,
            layer,
            schedType,
            intfIndexStr,
            queueData[i].priority,
            buf);


        if (stats[i].totalDequeueRequest)
        {
            sprintf(buf, "Service Ratio = %0.9lf",
                (double) stats[i].packetDequeued
                    / stats[i].totalDequeueRequest);
        }
        else
        {
            double serviceRatio = 0.0;
            sprintf(buf, "Service Ratio = %0.9lf", serviceRatio);
        }

        IO_PrintStat(
            node,
            layer,
            schedType,
            intfIndexStr,
            queueData[i].priority,
            buf);
    }
}


//--------------------------------------------------------------------------
// Weighted Round Robin (WRR) Scheduler Class Constructor
//--------------------------------------------------------------------------

//**
// FUNCTION   :: WrrScheduler::WrrScheduler
// LAYER      ::
// PURPOSE    :: Constractor of WrrScheduler class to initialize
//               its own data members
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Status of scheduler stat enable or not
// + graphDataStr : const char : Graph data string
// RETURN     ::
// **/

WrrScheduler::WrrScheduler(
    BOOL enableSchedulerStat,
    const char graphDataStr[])
{
    queueData = NULL;
    numQueues = 0;
    maxQueues = 0;
    infoFieldSize = 0;
    packetsLostToOverflow = 0;
    schedulerStatEnabled = enableSchedulerStat;

    // Initialize WRR Scheduler specific info.
    isAssigned = FALSE;
    queueInfo = NULL;
    queueIndexInfo = -1;    // Queue selected for last dequeue
    serviceRound = 0;
    gcdInfo = 0;            // GreatestCommonDivisor for WRR
    stats = NULL;
    schedGraphStatPtr = NULL;

    // Initialize graphdata collection module
    if (strcmp(graphDataStr, "NA"))
    {
        SchedGraphStat* graphPtr = new SchedGraphStat(graphDataStr);
        schedGraphStatPtr = (SchedGraphStat*) graphPtr;

        if (schedGraphStatPtr == NULL)
        {
            printf("Memory allocation failed\n");
        }
    }
}

// /**
// FUNCTION   :: WrrScheduler::~WrrScheduler
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               WrrScheduler
// PARAMETERS ::
// RETURN     :: void : Null
// **/
WrrScheduler::~WrrScheduler()
{
    delete []queueData;
    delete []stats;
    delete []queueInfo;
}
