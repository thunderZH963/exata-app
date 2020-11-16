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
#include "sch_strictprio.h"

#include "sch_graph.h"

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif

//**
// FUNCTION   :: StrictPriorityScheduler::insert
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that
//               need to be passed to a scheduler data structure in order to
//               insert a message into it. The scheduler is responsible for
//               routing this packet to an appropriate queue that it
//               controls, and returning whether or not the procedure was
//               successful. The changes here are the replacement of the
//               dscp parameter with the infoField pointer.  The size of
//               this infoField is stored in infoFieldSize.
// PARAMETERS ::
// + msg : Message* : Pointer to Message structure
// + QueueIsFull : BOOL* : Status of queue
// + queueIndex : const int : Queue index
// + infoField : const void* : Info field
// + currentTime : const clocktype : Current simulation time
// RETURN     :: void : Null
// **/

void StrictPriorityScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void StrictPriorityScheduler::insert(
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


    if (SCH_PRIO_DEBUG)
    {
        char clock[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(currentTime, clock);
        printf("Enqueue Request at %s\n", clock);
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
        if (SCH_PRIO_DEBUG)
        {
            printf("\t\tInserting a packet in Queue with priority %u \n",
                qData->priority);
        }

        // Update packet enqueue status
        stats[queueIndex].packetQueued++;
    }
    else
    {
        if (SCH_PRIO_DEBUG)
        {
            printf("\t\tDropping a packet as no space in Queue"
                " with priority %u \n", qData->priority);
        }
        // Update packet dequeue status
        stats[queueIndex].packetDropped++;
    }
#ifdef ADDON_DB
    using namespace StatsQueueDB;
    if (qData->queue->returnQueueDBHook())
    {
        qData->queue->returnQueueDBHook()->eventHook(msg, 
            *QueueIsFull, priority,  STATS_INSERT_PACKET);
    }
#endif
}

void StrictPriorityScheduler::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(node, interfaceIndex, msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void StrictPriorityScheduler::insert(
    Node* node,
    int interfaceIndex,
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


    if (SCH_PRIO_DEBUG)
    {
        char clock[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(currentTime, clock);
        printf("Enqueue Request at %s priority %d\n", clock, priority);
    }

    // Insert the packet in the queue
    if (tos == NULL)
    {
        qData->queue->insert(node, interfaceIndex, priority, msg, infoField, QueueIsFull, currentTime);
    }
    else
    {
        qData->queue->insert(node, interfaceIndex, priority, msg, infoField, QueueIsFull, currentTime, tos);
    }

    if (!*QueueIsFull)
    {
        if (SCH_PRIO_DEBUG)
        {
            printf("\t\tInserting a packet in Queue with priority %u \n",
                qData->priority);
        }

        // Update packet enqueue status
        stats[queueIndex].packetQueued++;
    }
    else
    {
        if (SCH_PRIO_DEBUG)
        {
            printf("\t\tDropping a packet as no space in Queue"
                " with priority %u \n", qData->priority);
        }
        // Update packet dequeue status
        stats[queueIndex].packetDropped++;
    }
#ifdef ADDON_DB
    using namespace StatsQueueDB;
    if (qData->queue->returnQueueDBHook())
    {
        qData->queue->returnQueueDBHook()->eventHook(msg, 
            *QueueIsFull, priority,  STATS_INSERT_PACKET);
    }
#endif
}



//**
// FUNCTION   :: StrictPriorityScheduler::retrieve
// LAYER      ::
// PURPOSE    :: This function prototype determines the arguments that need
//               to be passed to a scheduler data structure in order to
//               dequeue or peek at a message in its array of stored messages
//               I've reordered the arguments slightly, and incorporated
//               the "DropFunction" functionality as well.
// PARAMETERS ::
// + priority : const int : Priority of queue
// + index : const int : The position of the packet in the queue
// + msg : Message** : The retrieved msg
// + msgPriority : int* : Msg priority
// + operation : const QueueOperation : The retrieval mode
// + currentTime : const clocktype : Current simulation time
// RETURN     :: BOOL : TRUE or FALSE
// **/

BOOL StrictPriorityScheduler::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime)
{
    int i;
    int queueInternalId = -1;
    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;
    *msg = NULL;
    clocktype insertTime = 0;

    if (SCH_PRIO_DEBUG)
    {
        char clock[MAX_STRING_LENGTH] = {0};
        TIME_PrintClockInSecond(currentTime, clock);
        printf("Dequeue Request at %s for priority %d index %d\n", 
               clock, priority, index);
    }

    if (!(index < numberInQueue(priority
#ifdef ADDON_BOEINGFCS
                                ,TRUE
#endif           
        
                                )) || (index < 0))
    {
        if (SCH_PRIO_DEBUG)
        {
            printf("Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    if (priority == ALL_PRIORITIES)
    {
        int queueInternalIndex = 0;
        int remainingIndex = index;

        for (i = numQueues - 1; i >= 0; i--)
        {
            if (!queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                             TRUE
#endif
                                             ))
            {
                if (remainingIndex >= queueData[i].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                                         TRUE
#endif                                                                   
                                                                         ))
                {
                    remainingIndex -= queueData[i].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                                         TRUE
#endif   
                                                                         );
                }
                else
                {
                    // The packet is in this queue
                    queueInternalId = i;
                    queueInternalIndex = remainingIndex;
                    break;
                }
            }
        }

        ERROR_Assert(queueInternalId >= 0,
            "Queue with negative InternalId does not exist\n");

        qData = &queueData[queueInternalId];
        insertTime = qData->queue->getPacketInsertTime(queueInternalIndex);
        isMsgRetrieved = qData->queue->retrieve(msg,
                                                queueInternalIndex,
                                                operation,
                                                currentTime);
    }
    else
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);

        insertTime = qData->queue->getPacketInsertTime(index);
        isMsgRetrieved = qData->queue->retrieve(msg,
                                                index,
                                                operation,
                                                currentTime);
        for (i = numQueues - 1; i >= 0; i--)
        {
            if (queueData[i].priority == priority)
            {
                queueInternalId = i;
                break;
            }
        }
    }

    *msgPriority = qData->priority;

    // Update Dequeue/Drop Status
    if (isMsgRetrieved)
    {
        if (operation == DEQUEUE_PACKET)
        {
            stats[queueInternalId].packetDequeued++;
        }

        if (operation == DISCARD_PACKET || operation == DROP_PACKET)
        {
            stats[queueInternalId].packetDropped++;
        }

        if (operation == DROP_AGED_PACKET)
        {
            stats[queueInternalId].packetDroppedAging++;
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

    if (SCH_PRIO_DEBUG)
    {
        printf("\t\tA packet with priority %u retrieved\n", qData->priority);
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

int StrictPriorityScheduler::addQueue(
    Queue *queue,
    const int priority,
    const double weight)
{
    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        StrictPriorityStat* newStats
            = new StrictPriorityStat[maxQueues + DEFAULT_QUEUE_COUNT];

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete []queueData;

            memcpy(newStats, stats, sizeof(StrictPriorityStat) * maxQueues);
            delete []stats;
        }

        queueData = newQueueData;
        stats = newStats;

        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0, "Scheduler addQueue function maxQueues <= 0");

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

        memset(&stats[index], 0, sizeof(StrictPriorityStat));

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
                StrictPriorityStat* newStats
                                = new StrictPriorityStat[afterEntries];

                memcpy(newQueueData, &queueData[i],
                       sizeof(QueueData) * afterEntries);

                memcpy(&queueData[i+1], newQueueData,
                       sizeof(QueueData) * afterEntries);

                queueData[i].priority = priority;
                queueData[i].weight = (float)weight;
                queueData[i].queue = queue;

                // Handle Specific stats
                memcpy(newStats, &stats[i],
                        sizeof(StrictPriorityStat) * afterEntries);

                memcpy(&stats[i+1], newStats,
                        sizeof(StrictPriorityStat) * afterEntries);

                memset(&stats[i], 0, sizeof(StrictPriorityStat));

                numQueues++;

                delete []newQueueData;
                delete []newStats;
                return queueData[i].priority;
            }
        }

        i = numQueues;

        queueData[i].priority = priority;
        queueData[i].weight = (float)weight;
        queueData[i].queue = queue;

        memset(&stats[i], 0, sizeof(StrictPriorityStat));

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

void StrictPriorityScheduler::removeQueue(const int priority)
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
                    sizeof(StrictPriorityStat) * afterEntries);
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

void StrictPriorityScheduler::swapQueue(
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

void StrictPriorityScheduler::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* invokingProtocol,
    const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};
    char schedType[MAX_STRING_LENGTH] = "StrictPrio";

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
        sprintf(schedType, "%s StrictPrio", invokingProtocol);
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    if (splStatStr)
    {
        sprintf(schedType, "  StrictPrio %s", splStatStr);
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

        if (stats[i].packetDroppedAging > 0)
        {
            sprintf(buf, "Packets Dropped due to Aging = %u", 
                stats[i].packetDroppedAging);
            IO_PrintStat(
                node,
                layer,
                schedType,
                intfIndexStr,
                queueData[i].priority,
                buf);
        }

    }
}

//---------------------------------------------------------------------------
// StrictPriorityScheduler Class Constructor
//---------------------------------------------------------------------------

//**
// FUNCTION   :: StrictPriorityScheduler::StrictPriorityScheduler
// LAYER      ::
// PURPOSE    :: Constractor of StrictPriorityScheduler class to initialize
//               its own data members
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Status of scheduler stat enable or not
// + graphDataStr : const char : Graph data string
// RETURN     ::
// **/

StrictPriorityScheduler::StrictPriorityScheduler(
    BOOL enableSchedulerStat,
    const char graphDataStr[])
{
    queueData = NULL;
    numQueues = 0;
    maxQueues = 0;
    infoFieldSize = 0;
    packetsLostToOverflow = 0;
    stats = NULL;
    schedulerStatEnabled = enableSchedulerStat;
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
// FUNCTION   :: StrictPriorityScheduler::~StrictPriorityScheduler
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               StrictPriorityScheduler
// PARAMETERS ::
// RETURN     :: void : Null
// **/
StrictPriorityScheduler::~StrictPriorityScheduler()
{
    delete []queueData;
    delete []stats;
}
