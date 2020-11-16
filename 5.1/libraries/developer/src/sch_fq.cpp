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
// REFERENCES   :: Same as scfq and wfq scheduler
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "if_queue.h"
#include "if_scheduler.h"
#include "sch_fq.h"


//---------------------------------------------------------------------------
// Start: Utility Functions
//---------------------------------------------------------------------------

//**
// FUNCTION   :: FQScheduler::AutoWeightAssignment
// LAYER      ::
// PURPOSE    :: Assigns queue weights
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void FQScheduler::AutoWeightAssignment()
{
    int i;
    unsigned int sumQueuePriority = 0;  // Sum of (priority + 1)

    // Calculate Sum of all Active Queues (Priority + 1)
    for (i = 0; i < numQueues; i++)
    {
        sumQueuePriority += (queueData[i].priority + 1);
    }

    // Assign weight to each active queue
    if (FQ_DEBUG_WEIGHT)
    {
        printf("Calculating Queue Weight .......\n");
    }

    for (i = 0; i < numQueues; i++)
    {
        queueData[i].weight = (queueData[i].priority + 1)
                                / (float) sumQueuePriority;

        if (FQ_DEBUG_WEIGHT)
        {
            printf("\t\tweight[%d] = %0.9lf\n",
                queueData[i].priority, queueData[i].weight);
        }
    }
}


//**
// FUNCTION   :: FQScheduler::FairQueueInsertionSort
// LAYER      ::
// PURPOSE    :: Sorts the active queues
//               in assending order based on finish number
// PARAMETERS :: None
// RETURN     :: void : Null
// **/

void FQScheduler::FairQueueInsertionSort()
{
    int i;
    int pos = 0;

    //  For each position i > 0 in the list
    for (i = 1; i < numActiveQueueInfo; i++)
    {
        //  Insert the member in position i into the sorted sublist
        SortQueueInfo item = sortQueueInfo[i];

        for (pos = i - 1; pos >= 0 &&
            sortQueueInfo[pos].sortedQueueFinishNum
                > item.sortedQueueFinishNum;
            pos--)
        {
            sortQueueInfo[pos + 1] = sortQueueInfo[pos];
        }
        sortQueueInfo[pos + 1] = item;
    }
    return;
}


//**
// FUNCTION   :: FQScheduler::FairQueueSchedulerSelectNextQueue
// LAYER      ::
// PURPOSE    :: Returns the next queue and index to be serviced
// PARAMETERS ::
// + index : int : The position of the packet in the queue
// + returnIndex : int* : Next queue Index
// RETURN     :: QueueData* : Return queue pointer
// **/

QueueData* FQScheduler::FairQueueSchedulerSelectNextQueue(
    int index,
    int* returnIndex)
{
    int i = 0;
    int n = 0;
    int packetIndex = -1;
    int skipAtBoundary = -1;
    QueueData* retVal = NULL;
    QueueData** sortedQueueData;

    if(numActiveQueueInfo == 0)
    {
        return NULL;
    }
    // Allocate memory for array of shorted queue and queue finish number
    sortQueueInfo = (SortQueueInfo*)
        MEM_malloc(sizeof(SortQueueInfo) * numActiveQueueInfo);
    memset(sortQueueInfo, 0, sizeof(SortQueueInfo) * numActiveQueueInfo);
    sortedQueueData = (QueueData**)
        MEM_malloc(sizeof(QueueData*) * numActiveQueueInfo);
    memset(sortedQueueData, 0, sizeof(QueueData*) * numActiveQueueInfo);

    // Sort the queue finish numbers in an array in ascending order
    // Insertion sort algorithm is applied here to sort the queues
    // Insert the queue finish numbers in the array
    // Maintain queue priority information for mapping in future.

    for (i = 0; i < numQueues; i++)
    {
        if (!queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                         TRUE
#endif                   
                                         ))
        {
            sortQueueInfo[n].internalIndex = 0;
            sortQueueInfo[n].sortedQueuePriority = queueData[i].priority;
            sortQueueInfo[n].sortedQueueFinishNum
                                            = queueInfo[i].queueFinishNum;
            n++;
        }
    }

    while (index > packetIndex)
    {
        if (FQ_DEBUG_SORT)
        {
            printf("\t: Printing sorting statistics:\n");
            printf("\t  Before Sorting SortedQueueFinishNum[] content:\n");
            for (n = 0; n < numActiveQueueInfo; n++)
            {
                printf("\t\tSortedQueueFinishNumber[%u] = %f\n",
                       n, sortQueueInfo[n].sortedQueueFinishNum);
            }
        }

        // Sort the list
        FairQueueInsertionSort();

        if (FQ_DEBUG_SORT)
        {
            printf("\tAfter Sorting SortedQueueFinishNum[] content:\n");
            for (n = 0; n < numActiveQueueInfo; n++)
            {
                printf("\t\tSortedQueueFinishNumber[%u] = %lf\n",
                       n, sortQueueInfo[n].sortedQueueFinishNum);
            }
        }

        // Sorted queue array
        for (n = 0; n < numActiveQueueInfo; n++)
        {
            for (i = 0; i < numQueues; i++)
            {
                if ((!queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                                  TRUE
#endif                   
                                                  )) &&
                    (queueData[i].priority
                        == sortQueueInfo[n].sortedQueuePriority))
                {
                    sortedQueueData[n] = &queueData[i];
                    break;
                }
            }
        }

        if (FQ_DEBUG_SORT)
        {
            for (n = 0; n < numActiveQueueInfo; n++)
            {
                printf("\t\tSortedQueue[%u] = %d\n",
                    n, sortedQueueData[n]->priority);
            }
        }

        packetIndex++;
        n = 0; // This is an important initialization
        if (index == packetIndex)
        {
            if ((index > 0) && (skipAtBoundary != -1))
            {
                for (n = 0; n < numActiveQueueInfo; n++)
                {
                    if (!sortQueueInfo[n].skip)
                    {
                        // Got the queue
                        *returnIndex = sortQueueInfo[n].internalIndex;
                        retVal = sortedQueueData[n];
                        break;
                    }
                    // Skip this Queue;
                }

                if (n == numActiveQueueInfo)
                {
                    for (n = 0; n < numActiveQueueInfo; n++)
                    {
                        if (sortQueueInfo[n].sortedQueuePriority
                            == skipAtBoundary)
                        {
                            // Get the queue last skipped
                            *returnIndex = sortQueueInfo[n].internalIndex;
                            retVal = sortedQueueData[n];
                            break;
                        }
                    }
                }
            }
            else
            {
                *returnIndex = sortQueueInfo[n].internalIndex;
                retVal = sortedQueueData[n];
            }

            if (FQ_DEBUG_TRACE)
            {
                printf("%lf\n", sortQueueInfo[n].sortedQueueFinishNum);
            }

            // Free momory before return
            MEM_free(sortedQueueData);
            MEM_free(sortQueueInfo);

            return retVal;
        }
        else
        {
            Message* peakMsg = NULL;
            // Continue search in the Queue with smallest FN
            for (n = 0; n < numActiveQueueInfo; n++)
            {
                if (sortedQueueData[n]->queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                              TRUE
#endif                   
                                                              )
                    > (sortQueueInfo[n].internalIndex + 1))
                {
                    break;
                }
                skipAtBoundary = sortQueueInfo[n].sortedQueuePriority;
                sortQueueInfo[n].skip = true;
            }

            if (n < numActiveQueueInfo)
            {
                sortQueueInfo[n].internalIndex++;
                sortedQueueData[n]->queue->retrieve(&peakMsg,
                            sortQueueInfo[n].internalIndex,
                            PEEK_AT_NEXT_PACKET,
                            0, //currentTime
                            &sortQueueInfo[n].sortedQueueFinishNum);
            }
        }
    }
    return NULL;
}


//**
// FUNCTION   :: FQScheduler::FairQueueFinalize
// LAYER      ::
// PURPOSE    :: Help function for printing final statistics
//               for Fair Schedulers
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + layer : const char* : The layer string
// + interfaceIndex : const int : Interface index
// + schedulerTypeString : const char* : Scheduler type string
// + invokingProtocol : const char* : The protocol string
// RETURN     :: void : Null
// **/

void FQScheduler::FairQueueFinalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* schedulerTypeString,
    const char* invokingProtocol,
    const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    if (strcmp(invokingProtocol, "IP") == 0)
    {
        // IP scheduling finalization
        NetworkIpGetInterfaceAddressString(node,
                                           interfaceIndex,
                                           intfIndexStr);
    }
    else
    {
        sprintf(intfIndexStr, "%d", interfaceIndex);
    }

    for (i = 0; i < numQueues; i++)
    {
#ifdef ADDON_BOEINGFCS
        char bufRsvnId[MAX_STRING_LENGTH] = {0};
        sprintf(bufRsvnId, "MI %s", splStatStr);

        Queue* myQueue = (Queue*) queueData[i].queue;
        myQueue->finalize(node,
                          "MI",
                          interfaceIndex,
                          queueData[i].priority,
                          bufRsvnId);
#endif

        sprintf(buf, "Packets Queued = %u", stats[i].totalPktEnqueued);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dequeued = %u", stats[i].totalPktDequeued);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);


        sprintf(buf, "Packets Dropped = %u", stats[i].packetDropPerQueue);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Dequeue Requests While "
                "Queue Active = %d", stats[i].numDequeueReq);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);


        sprintf(buf, "Dequeue Requests Serviced = %u",
                stats[i].numDequeueReq - stats[i].numMissedService);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);

        if (stats[i].numDequeueReq > 0)
        {
            sprintf(buf, "Service Ratio received = %0.9lf",
                (double)(stats[i].numDequeueReq - stats[i].numMissedService)
                    / stats[i].numDequeueReq);
        }
        else
        {
            double serviceRatio = 0.0;
            sprintf(buf, "Service Ratio received = = %0.9lf",serviceRatio);
        }

        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Total Service Received(Bytes) = %u",
                stats[i].totalServiceReceived);
        IO_PrintStat(
            node,
            layer,
            schedulerTypeString,
            intfIndexStr,
            queueData[i].priority,
            buf);
    }
}


//--------------------------------------------------------------------------
// End: Utility Functions
//--------------------------------------------------------------------------

//**
// FUNCTION   :: FQScheduler::addQueue
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

int FQScheduler::addQueue(
    Queue *queue,
    const int priority,
    const double weight)
{

    if ((weight <= 0.0) || (weight > 1.0))
    {
        // Considering  1.0 as this is the default value
        ERROR_ReportError(
            "FQ: QUEUE-WEIGHT value must stay between <0.0 - 1.0>\n");
    }

    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        FairQueueSchStat* newStats
            = new FairQueueSchStat[maxQueues + DEFAULT_QUEUE_COUNT];

        FairQueueInfo* newQueueInfo
            = new FairQueueInfo[maxQueues + DEFAULT_QUEUE_COUNT];

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete []queueData;

            memcpy(newStats, stats, sizeof(FairQueueSchStat) * maxQueues);
            delete []stats;

            memcpy(newQueueInfo, queueInfo,
                sizeof(FairQueueInfo) * maxQueues);
            delete []queueInfo;
        }

        queueData = newQueueData;
        stats = newStats;
        queueInfo = newQueueInfo;

        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0,
        "Scheduler addQueue function maxQueues <= 0");

    if (weight < 1.0)
    {
       isAssigned = true;
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
        queueData[index].weight = (float)weight;
        queueData[index].queue = queue;

        memset(&stats[index], 0, sizeof(FairQueueSchStat));
        memset(&queueInfo[index], 0, sizeof(FairQueueInfo));

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
                FairQueueSchStat* newStats = new FairQueueSchStat[afterEntries];
                FairQueueInfo* newQueueInfo = new FairQueueInfo[afterEntries];

                memcpy(newQueueData, &queueData[i],
                       sizeof(QueueData) * afterEntries);

                memcpy(&queueData[i+1], newQueueData,
                       sizeof(QueueData) * afterEntries);

                queueData[i].priority = priority;
                queueData[i].weight = (float)weight;
                queueData[i].queue = queue;

                // Handle Specific stats
                memcpy(newStats, &stats[i],
                        sizeof(FairQueueSchStat) * afterEntries);
                memcpy(&stats[i+1], newStats,
                        sizeof(FairQueueSchStat) * afterEntries);
                memset(&stats[i], 0, sizeof(FairQueueSchStat));

                // Handle specific queue info
                memcpy(newQueueInfo, &queueInfo[i],
                        sizeof(FairQueueInfo) * afterEntries);
                memcpy(&queueInfo[i+1], newQueueInfo,
                        sizeof(FairQueueInfo) * afterEntries);
                memset(&queueInfo[i], 0, sizeof(FairQueueInfo));

                numQueues++;
                delete []newQueueData;
                delete []newQueueInfo;
                delete []newStats;

                return queueData[i].priority;
            }
        }

        i = numQueues;

        queueData[i].priority = priority;
        queueData[i].weight = (float)weight;
        queueData[i].queue = queue;

        memset(&stats[i], 0, sizeof(FairQueueSchStat));
        memset(&queueInfo[i], 0, sizeof(FairQueueInfo));

        numQueues++;
        return queueData[i].priority;
    }
}


//**
// FUNCTION   :: FQScheduler::removeQueue
// LAYER      ::
// PURPOSE    :: This function removes a queue from the scheduler.
//               This function does not automatically finalize the queue,
//               so if the protocol modeler would like the queue to print
//               statistics before exiting, it must be explicitly finalized.
// PARAMETERS ::
// + priority : const int : Priority of the queue
// RETURN     :: void : Null
// **/

void FQScheduler::removeQueue(const int priority)
{
    int i;

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == priority)
        {
            int afterEntries = numQueues - (i + 1);

            // for dynamic queue remove operaiton
            // it is possible a non empty queue is removed
            if (!queueData[i].queue->isEmpty())
            {
                numActiveQueueInfo --;
            }

            if (afterEntries > 0)
            {
                delete queueData[i].queue;
                memmove(&queueData[i], &queueData[i+1],
                    sizeof(QueueData) * afterEntries);

                memmove(&stats[i], &stats[i+1],
                    sizeof(FairQueueSchStat) * afterEntries);

                memmove(&queueInfo[i], &queueInfo[i+1],
                    sizeof(FairQueueInfo) * afterEntries);
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
// FUNCTION   :: FQScheduler::swapQueue
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

void FQScheduler::swapQueue(
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
            stats[i].totalPktEnqueued -= numExtraDrops;
            stats[i].packetDropPerQueue += numExtraDrops;

            delete oldQueue;
            return;
        }
    }

    // If there is no such queue, it is added.
    addQueue(queue, priority);
}

// /**
// FUNCTION   :: FQScheduler::~FQScheduler
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               FQScheduler
// PARAMETERS ::
// RETURN     :: void : Null
// **/
FQScheduler::~FQScheduler()
{
    delete []queueData;
    delete []stats;
    delete []queueInfo;
}
