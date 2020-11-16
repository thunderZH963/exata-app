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
#include "sch_roundrobin.h"

#include "sch_graph.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define RR_DEBUG    0


//**
// FUNCTION   :: RoundRobinScheduler::RoundRobinSelectNextQueue
// LAYER      ::
// PURPOSE    :: Schedules for a queueIndex And packetIndex to be dequeued
// PARAMETERS ::
// + index : int : The position of the packet in the queue
// + queueIndex : int* : Queue Index
// + packetIndex : int* : Packet Index
// RETURN     :: void : Null
// **/

void RoundRobinScheduler::RoundRobinSelectNextQueue(
    int index,
    int* queueIndex,
    int* packetIndex)
{
    int i = 0;
    int numOfQueuesChecked = 1; // The number of queues checked

    *packetIndex = 0; // The position of the packet in the selected queue
    *queueIndex = queueIndexInfo;

    if (RR_DEBUG)
    {
        printf("\t\t\tLast dequeued queue = %d\n\n", *queueIndex);
        printf("\t\t\t---------RoundRobin Selection Procedure---------\n\n");
        printf("\t\t\t\tGot index = %d \n", index);
    }

    while (TRUE)
    {
        if (*queueIndex == numQueues - 1)
        {
            *queueIndex = 0;
        }
        else
        {
            *queueIndex += 1;
        }

        if (RR_DEBUG)
        {
            printf("\t\t\t\tDequeue request for queue = %d\n", *queueIndex);
            printf("\t\t\t\tScarching for the packet...\n");
        }

        // Checking whether the queue is active and contains the packet
        if (!queueData[*queueIndex].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                                   TRUE
#endif
                                                   ) &&
            ((queueData[*queueIndex].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                           TRUE
#endif               
                                                           )
                - *packetIndex) > 0))
        {
            if (i == index)
            {
                if (RR_DEBUG)
                {
                    printf("\t\t\t\tGot the packet in this queue\n");
                }

                return;
            }
            else
            {
                // queue active so incrementing i;the packet position at
                // the interface
                i++;
            }
        }

        if (RR_DEBUG)
        {
            printf("\t\t\t\tPacket not found; switch to next queue\n");
        }

        if (numOfQueuesChecked % numQueues == 0)
        {
            // Update packetIndex
            *packetIndex += 1;

            if (RR_DEBUG)
            {
                printf("\t\t\t\t* Repeat Search.....\n");
            }
        }

        // The number of active queues checked
        numOfQueuesChecked++;
    }
}


//**
// FUNCTION   :: RoundRobinScheduler::insert
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

void RoundRobinScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void RoundRobinScheduler::insert(
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

void RoundRobinScheduler::insert(
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


void RoundRobinScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos
    )
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

    if (RR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("\nRoundRobin: Simtime %s got packet to enqueue\n", time);
    }

    // Insert the packet in the queue
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
        if (RR_DEBUG)
        {
            printf("\t\t\tInserting a packet in Queue %u \n\n",
                qData->priority);
        }

        // Update packet enqueue status
        stats[queueIndex].packetQueued++;
    }
    else
    {
        if (RR_DEBUG)
        {
            printf("\t\t\tDropping a packet as no space in Queue %u \n\n",
                qData->priority);
        }

        // Update packet dequeue status
        stats[queueIndex].packetDropped++;
    }

#ifdef ADDON_DB
    using namespace StatsQueueDB;
    if (qData->queue->returnQueueDBHook())
    {        
        qData->queue->returnQueueDBHook()->eventHook(msg, 
            *QueueIsFull, priority, 
            STATS_INSERT_PACKET);        
    }
#endif
}

//**
// FUNCTION   :: RoundRobinScheduler::retrieve
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

BOOL RoundRobinScheduler::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime)
{
    int j;
    int queueIndex = ALL_PRIORITIES;// -1
    int packetIndex = 0;
    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;
    *msg = NULL;

    if (RR_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("\nRoundRobin: Simtime %s got request to dequeue\n\n",
            time);
    }

    if (!(index < numberInQueue(priority
#ifdef ADDON_BOEINGFCS
                                ,TRUE
#endif          
                                )) || (index < 0))
    {
        if (RR_DEBUG)
        {
            printf("RoundRobin: Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    if (priority == ALL_PRIORITIES)
    {
        // Find the queue for dequeuing a packet
        RoundRobinSelectNextQueue(
            index,
            &queueIndex,
            &packetIndex);

        // The queue selected for dequeuing a packet
        qData = &queueData[queueIndex];
    }
    else // if (specificPriorityOnly)
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);

        for (int i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority == qData->priority)
            {
                queueIndex = i;
                break;
            }
        }
        packetIndex = index;
    }

    if (RR_DEBUG)
    {
        printf("\t\t\t\tThis queue selected for dequeue = %d \n",
            queueIndex);
        printf("\t\t\t\tPosition of packet in the queue = %d\n",
            packetIndex);

        printf("\t\t\t-----------------------------------------------\n\n");
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

        if (RR_DEBUG)
        {
            printf("\t\t\tRetrieved Packet from queue %u\n",
                    qData->priority);
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
    return isMsgRetrieved;
}


//**
// FUNCTION   :: RoundRobinScheduler::addQueue
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

int RoundRobinScheduler::addQueue(
    Queue *queue,
    const int priority,
    const double weight)
{
    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        RoundRobinStat* newStats
            = new RoundRobinStat[maxQueues + DEFAULT_QUEUE_COUNT];

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete[] queueData;

            memcpy(newStats, stats, sizeof(RoundRobinStat) * maxQueues);
            delete[] stats;
        }

        queueData = newQueueData;
        stats = newStats;

        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0,
        "Scheduler addQueue function maxQueues <= 0");

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
        queueData[index].weight = (float)weight;
        queueData[index].queue = queue;

        memset(&stats[index], 0, sizeof(RoundRobinStat));

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
                RoundRobinStat* newStats = new RoundRobinStat[afterEntries];

                memcpy(newQueueData, &queueData[i],
                       sizeof(QueueData) * afterEntries);

                memcpy(&queueData[i+1], newQueueData,
                       sizeof(QueueData) * afterEntries);

                queueData[i].priority = priority;
                queueData[i].weight = (float)weight;
                queueData[i].queue = queue;

                // Handle Specific stats
                memcpy(newStats, &stats[i],
                        sizeof(RoundRobinStat) * afterEntries);

                memcpy(&stats[i+1], newStats,
                        sizeof(RoundRobinStat) * afterEntries);

                memset(&stats[i], 0, sizeof(RoundRobinStat));

                numQueues++;

                delete[] newQueueData;
                delete[] newStats;
                return queueData[i].priority;
            }
        }

        i = numQueues;

        queueData[i].priority = priority;
        queueData[i].weight = (float)weight;
        queueData[i].queue = queue;

        memset(&stats[i], 0, sizeof(RoundRobinStat));

        numQueues++;
        return queueData[i].priority;
    }
}


//**
// FUNCTION   :: RoundRobinScheduler::removeQueue
// LAYER      ::
// PURPOSE    :: This function removes a queue from the scheduler.
//               This function does not automatically finalize the queue,
//               so if the protocol modeler would like the queue to print
//               statistics before exiting, it must be explicitly finalized.
// PARAMETERS ::
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void RoundRobinScheduler::removeQueue(const int priority)
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
                    sizeof(RoundRobinStat) * afterEntries);
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
// FUNCTION   :: RoundRobinScheduler::swapQueue
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

void RoundRobinScheduler::swapQueue(
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
// FUNCTION   :: RoundRobinScheduler::finalize
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

void RoundRobinScheduler::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* invokingProtocol,
    const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};
    char schedType[MAX_STRING_LENGTH] = "RoundRobin";

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
        sprintf(schedType, "%s RoundRobin", invokingProtocol);
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
// RoundRobinScheduler Class Constructor
//--------------------------------------------------------------------------

//**
// FUNCTION   :: RoundRobinScheduler::RoundRobinScheduler
// LAYER      ::
// PURPOSE    :: Constractor of RoundRobinScheduler class to initialize its
//               own data members
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Status of scheduler stat enable or not
// + graphDataStr : const char : Graph data string
// RETURN     ::
// **/

RoundRobinScheduler::RoundRobinScheduler(
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
    queueIndexInfo = -1; // Queue selected for last dequeue
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
// FUNCTION   :: RoundRobinScheduler::~RoundRobinScheduler
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               RoundRobinScheduler
// PARAMETERS ::
// RETURN     :: void : Null
// **/
RoundRobinScheduler::~RoundRobinScheduler()
{
    delete []queueData;
    delete []stats;
}
