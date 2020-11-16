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
// + http://www.cisco.com/warp/public/732/Tech/wfq/
// + www.cs.ucla.edu/classes/fall99/cs219/lectures/lecture991102.PDF
// + www.rennes.enst-bretagne.fr/~toutain/G6Recherche/Papier-LBSCFQ-lamti.PDF
// + www.cs.virginia.edu/~cs757/slidespdf/fairqueuing.pdf
// + http://www4.ncsu.edu:8030/~dsuryan/ece633/scheduler.html
// + http://teal.gmu.edu/~bmark/ece742/lslides_00/lect13.pdf
// **/


#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"

#include "sch_fq.h"
#include "sch_scfq.h"

#include "sch_graph.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define SCFQ_DEBUG      0

//**
// FUNCTION   :: ScfqScheduler::insert
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

void ScfqScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void ScfqScheduler::insert(
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

void ScfqScheduler::insert(
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


void ScfqScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos
    )
{
    int i;
    BOOL queueWasEmpty = FALSE;
    QueueData* qData = NULL;
    double queueServiceFinishTag = 0.0;
    int queueIndex;

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

    // Check weight Assignments before Running FQ Scheduling
    if (!isAssigned)
    {
        AutoWeightAssignment();
        isAssigned = TRUE;

        if (SCFQ_DEBUG_WEIGHT)
        {
            for (i = 0; i < numQueues; i++)
            {
                printf("Queue[%d] Weight = %f\n", i, queueData[i].weight);
            }
        }
    }

    if (SCFQ_DEBUG)
    {
        char time[20];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Scfq: Simtime %s got packet to enqueue \n", time);
        printf("\tQueue Service Finish Tag = %lf\n",
                    queueInfo[queueIndex].queueServiceTag);
        printf("\tWeight of the queue %u = %.5f\n", queueIndex,
               queueData[queueIndex].weight);
        printf("\tCF value is %lf\n", CF);
        printf("\tCompare & select the max to update queueServiceTag\n");
    }

    // The priority queue in which incoming packet will be inserted
    qData = &queueData[queueIndex];

    // Check if the queue is empty and insert
    if (qData->queue->isEmpty())
    {
        queueWasEmpty = TRUE;
    }

    // Find WfqFinishNumber using round number if round number is greater
    // than the queue Finish number, else find it using its queue finish
    // number stored previously in it


   queueServiceFinishTag = MAX(CF,
                            queueInfo[queueIndex].queueServiceTag)
                        + (MESSAGE_ReturnPacketSize(msg)
                        / (double) queueData[queueIndex].weight);


    if (tos == NULL)
    {
        qData->queue->insert(msg, infoField, QueueIsFull, currentTime,
                        queueServiceFinishTag);
    }
    else
    {
        qData->queue->insert(msg, infoField, QueueIsFull, currentTime,
                        tos, queueServiceFinishTag);
    }


    if (queueWasEmpty && !(qData->queue->isEmpty()))
    {
        // If the queue is empty and the first packet is going to be inserted
        // in the queue increase the numActiveQueue accordingly

        numActiveQueueInfo++;

        // Update Queue Finish number with Top Packet Finish Number
        queueInfo[queueIndex].queueFinishNum = queueServiceFinishTag;
    }

    // If the queue in which the packet is to be inserted is not yet full
    // Find WfqFinishNumber, else drop the packet

    if (!*QueueIsFull)
    {
        // Update Statistical Variables
        stats[queueIndex].totalPktEnqueued++;

        // Update the Service Finish Tag for queues
        queueInfo[queueIndex].queueServiceTag = queueServiceFinishTag;

        if (SCFQ_DEBUG)
        {
            printf("\tQueue Service Finish Tag = %lf\n",
                queueInfo[queueIndex].queueServiceTag);
            printf("\tQueue Top packet Finish Number = %lf\n",
                queueInfo[queueIndex].queueFinishNum);
        }
    }
    else
    {
        stats[queueIndex].packetDropPerQueue++;

        if (SCFQ_DEBUG)
        {
            char time[20];
            TIME_PrintClockInSecond(currentTime, time);
            printf("Scfq: Simtime %s got packet to drop\n", time);
            printf("\tThe queue is full so unable to enqueue\n");
        }
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
// FUNCTION   :: ScfqScheduler::retrieve
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

BOOL ScfqScheduler::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime)
{
    int i;
    int returnIndex = ALL_PRIORITIES;
    int queueInternalId = ALL_PRIORITIES;
    double pktServiceTag = 0.0;
    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;

    *msg = NULL;

    if (SCFQ_DEBUG)
    {
        char clock[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, clock);
        printf("SCFQ: Simtime %s got request to dequeue\n", clock);
        printf("\tNum of Active queue before dequeuing is %u\n",
               numActiveQueueInfo);
    }

    if (!(index < numberInQueue(priority)) || (index < 0))
    {
        if (SCFQ_DEBUG)
        {
           printf("SCFQ: Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    if (priority == ALL_PRIORITIES)
    {
        // Find the queue for dequeuing a packet
        qData = FairQueueSchedulerSelectNextQueue(index, &returnIndex);
    }
    else // if (specificPriorityOnly)
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);
        returnIndex = index;
    }

    if (SCFQ_DEBUG)
    {
        printf("\tThe value of returnIndex passed for dequeue = %d\n",
               returnIndex);
    }

    // Update the statistical variables for dequeueing
    if (operation == DEQUEUE_PACKET)
    {
        // Update the statistical variables for dequeueing
        for (i = 0; i < numQueues; i++)
        {
            if (!queueData[i].queue->isEmpty())
            {
                stats[i].numDequeueReq++;
                if (&queueData[i] != qData)
                {
                    stats[i].numMissedService++;
                }
            }
        }
    }

    clocktype insertTime = qData->queue->getPacketInsertTime(index);

    // Calling Queue retrive function
    isMsgRetrieved = qData->queue->retrieve(msg,
                                            returnIndex,
                                            operation,
                                            currentTime,
                                            &pktServiceTag);

    *msgPriority = qData->priority;

    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == qData->priority)
        {
            queueInternalId = i;
            break;
        }
    }

    if (isMsgRetrieved)
    {
        if (operation == DEQUEUE_PACKET)
        {
            // Update the statistical variables for dequeueing
            stats[queueInternalId].totalServiceReceived
                    += MESSAGE_ReturnPacketSize((*msg));

            stats[queueInternalId].totalPktDequeued++;

            if (SCFQ_DEBUG)
            {
                printf("\tCF before dequeuing is %lf\n", CF);
                printf("\tQueue Finish Number before dequeuing is = %.5f\n",
                       queueInfo[queueInternalId].queueFinishNum);
            }

            if (SCFQ_DEBUG)
            {
                printf("\tNum of Active queue after dequeuing is %u\n",
                       numActiveQueueInfo);
                printf("\tCF after dequeuing is %lf\n",
                       queueInfo[queueInternalId].queueFinishNum);
                printf("\tNum of packet in the queue after dequeue is %u\n",
                       numberInQueue(qData->priority));
            }
        }

        if (operation == DISCARD_PACKET || operation == DROP_PACKET)
        {
            // Update Drop Status
            stats[queueInternalId].packetDropPerQueue++;

            if (SCFQ_DEBUG)
            {
                printf("\t\tDropping a packet from Queue %u \n",
                    queueInternalId);
            }
        }

        // Update CF with the finish time of the packet
        // presently receiving service
        CF = queueInfo[queueInternalId].queueFinishNum;

        // Update the finish number with top packet finish number
        queueInfo[queueInternalId].queueFinishNum = pktServiceTag;

        // Check if the queue is empty and deactivate
        if (qData->queue->isEmpty())
        {
            numActiveQueueInfo--;
        }

        if (numActiveQueueInfo == 0)
        {
            CF = 0.0;
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
    else
    {
        if (SCFQ_DEBUG)
        {
            char clock[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(currentTime, clock);
            printf("SCFQ: Simtime %s got request to view top with"
                   "priority %u\n", clock, priority);
        }
    }

    if (SCFQ_DEBUG)
    {
        printf("\tRetrieved Packet from priority queue %u\n",
            qData->priority);
    }
   return isMsgRetrieved;
}


//**
// FUNCTION   :: ScfqScheduler::finalize
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

void ScfqScheduler::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* invokingProtocol,
    const char* splStatStr)
{
    char schedType[MAX_STRING_LENGTH] = "SCFQ";

    if (schedulerStatEnabled == FALSE)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP"))
    {
        memset(schedType, 0, MAX_STRING_LENGTH);
        sprintf(schedType, "%s SCFQ", invokingProtocol);
    }

    FairQueueFinalize(node,
                      layer,
                      interfaceIndex,
                      schedType,
                      invokingProtocol,
                      splStatStr);
}


//--------------------------------------------------------------------------
// SCFQ Scheduler Class Constructor
//--------------------------------------------------------------------------

//**
// FUNCTION   :: ScfqScheduler::ScfqScheduler
// LAYER      ::
// PURPOSE    :: Constractor of ScfqScheduler class to initialize its
//               own data members
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Status of scheduler stat enable or not
// + graphDataStr : const char : Graph data string
// RETURN     ::
// **/

ScfqScheduler::ScfqScheduler(
    BOOL enableSchedulerStat,
    const char graphDataStr[])
{
    queueData = NULL;
    numQueues = 0;
    maxQueues = 0;
    infoFieldSize = 0;
    packetsLostToOverflow = 0;
    schedulerStatEnabled = enableSchedulerStat;

    // Initialize FQ Scheduler specific info.
    isAssigned = FALSE;
    numActiveQueueInfo = 0;
    queueInfo = NULL;
    sortQueueInfo = NULL;
    stats = NULL;

    // Initialize SCFQ Scheduler specific info.
    CF = 0.0;
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

