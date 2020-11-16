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
// + Computer Networking by Jame F. Kurose, Keith W. Ross [page - 530]
// + http://www.cs.berkeley.edu/~kfall/EE122/wfq-notes/index.htm
// + Wfq from Cisco http://www.cisco.com/warp/public/732/Tech/wfq/
// + Wfq implementation http://www.sics.se/~ianm/WFQ/wfq_descrip/node21.html
// + www.cs.ucla.edu/classes/fall99/cs219/lectures/lecture991102.PDF
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>

#include "api.h"
#include "sch_fq.h"
#include "sch_wfq.h"

#include "sch_graph.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

//**
// FUNCTION   :: WfqScheduler::setQueueBehavior
// LAYER      ::
// PURPOSE    :: Set the queue behavior
// PARAMETERS ::
// + priority : const int : Priority of a queue
// + suspend : BOOL : The queue status
// RETURN :: void
// **/
void WfqScheduler::setQueueBehavior(const int priority, QueueBehavior suspend)
{
    int i = 0;

    if (priority == ALL_PRIORITIES)
    {
        for (i = 0; i < numQueues; i++)
        {

            if ((suspend == SUSPEND)
                && (queueData[i].queue->getQueueBehavior() == RESUME)
                && (queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                                TRUE
#endif
                                                ) == FALSE))
            {
                numActiveQueueInfo--;
            }
            if ((suspend == RESUME)
                && (queueData[i].queue->getQueueBehavior() == SUSPEND)
                && (queueData[i].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                       TRUE
#endif                    
                                                      ) > 0))
            {
                numActiveQueueInfo++;
            }
            queueData[i].queue->setQueueBehavior((BOOL)suspend);
        }
    }
    else
    {
        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority == priority)
            {
                if ((suspend == SUSPEND)
                    && (queueData[i].queue->getQueueBehavior() == RESUME)
                    && (queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                                    TRUE
#endif
                                                    ) == FALSE))
                {
                    numActiveQueueInfo--;
                }
                if ((suspend == RESUME)
                    && (queueData[i].queue->getQueueBehavior() == SUSPEND)
                    && (queueData[i].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                           TRUE
#endif                       
                                                           ) > 0))
                {
                    numActiveQueueInfo++;
                }

                queueData[i].queue->setQueueBehavior((BOOL)suspend);
                break;
            }
        }
    }
    return;
}// end of setQueueBehavior


//**
// FUNCTION   :: WfqScheduler::getQueueBehavior
// LAYER      ::
// PURPOSE    :: Returns a Boolean value of TRUE if the queue is suspended
// PARAMETERS ::
// + priority : const int : Priority of a queue
// RETURN :: BOOL : TRUE or FALSE
//       If return TRUE mean queueBehavior is suspended
// **/
/*
QueueBehavior WfqScheduler::getQueueBehavior(const int priority)
{
    int i = 0;

    if (priority == ALL_PRIORITIES)
    {
        for (i = 0; i < numQueues; i++)
        {
            if (!queueData[i].queue->getQueueBehavior())
            {
                return RESUME;
            }
        }
    }
    else
    {
        for (i = 0; i < numQueues; i++)
        {
            if (queueData[i].priority == priority)
            {
                return (QueueBehavior)queueData[i].queue->getQueueBehavior();
            }
        }
    }
    return SUSPEND;
}//end of getQueueBehavior
*/



//**
// FUNCTION   :: WfqScheduler::insert
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
// + queueIndex : const int : priority of the queue
// + infoField : const void* : Info field
// + currentTime : const clocktype : Current simulation time
// RETURN     :: void : Null
// **/

void WfqScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void WfqScheduler::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime)
{
    insert(node, interfaceIndex,msg,QueueIsFull,priority,infoField,currentTime,NULL);
}

void WfqScheduler::insert(
    Node* node,
    int interfaceIndex,
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos)
{
    int i;
    double roundRate = 0.0;
    double queueServiceFinishTag = 0.0;
    double sumActiveWeight = 0.0;
    BOOL queueWasEmpty = FALSE;
    QueueData* qData = NULL;
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

        if (WFQ_DEBUG_WEIGHT)
        {
            for (i = 0; i < numQueues; i++)
            {
                printf("Queue[%d] Weight = %f\n", i, queueData[i].weight);
            }
        }
    }

    if (WFQ_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Wfq: Simtime %s got packet to enqueue with"
            " priority %u\n", time, queueData[queueIndex].priority);
        printf("\tQueue Service Finish Tag = %lf\n",
            queueInfo[queueIndex].queueServiceTag);
        printf("\tWeight of the queue %u = %.5f\n", queueIndex,
               queueData[queueIndex].weight);
        printf("\tRound Number before enqueuing is %lf\n",
               roundNumber);
    }

    // The priority queue in which incoming packet will be inserted
    qData = &queueData[queueIndex];

    if (qData->queue->isEmpty())
    {
        queueWasEmpty = TRUE;
    }

    if (tos == NULL)
    {
       qData->queue->insert(node, interfaceIndex, priority,
                            msg, infoField, QueueIsFull,
                            currentTime, queueServiceFinishTag);
    }
    else
    {
        qData->queue->insert(node, interfaceIndex, priority,
                             msg, infoField, QueueIsFull,
                             currentTime, tos, queueServiceFinishTag);
    }

    // Check if the queue is empty and insert
    if (queueWasEmpty && !(qData->queue->isEmpty()))
    {
        // If the queue is empty and the first packet is going to be inserted
        // in the queue increase the numActiveQueue accordingly

        numActiveQueueInfo++;
    }

    // If the queue in which the packet is to be inserted is not yet full
    // Find WfqFinishNumber, else drop the packet

    if (!*QueueIsFull)
    {
        // Update Round Number which is a virtual clock which progress
        // in round rate interval, where
        // round rate = 1 / (sum ActiveWeight)

        for (i = 0; i < numQueues; i++)
        {
            if (!queueData[i].queue->isEmpty())
            {
                sumActiveWeight += queueData[i].weight;
            }
        }

        roundRate = (double)(1.0 / sumActiveWeight);

        // Update Statistical Variables
        stats[queueIndex].totalPktEnqueued++;

        // Update the roundNumber & Service Finish Tag for queues
        roundNumber += roundRate;

        // Find WfqFinishNumber using round number if round number is
        // greater than the queue Finish number, else find it using its
        // queue finish number stored previously in it

        queueServiceFinishTag = MAX(roundNumber,
                            queueInfo[queueIndex].queueServiceTag)
                            + (MESSAGE_ReturnPacketSize(msg)
                            / queueData[queueIndex].weight);

        qData->queue->setServiceTag(queueServiceFinishTag);

        if (queueWasEmpty && !(qData->queue->isEmpty()))
        {
            // Update Queue Top Packets Finish Number
            queueInfo[queueIndex].queueFinishNum = queueServiceFinishTag;
        }

        queueInfo[queueIndex].queueServiceTag = queueServiceFinishTag;

        if (WFQ_DEBUG)
        {
            printf("\tRound Number after enqueuing is %lf\n", roundNumber);
            printf("\tQueue Top packet Finish Number = %lf\n",
                queueInfo[queueIndex].queueFinishNum);
        }
    }
    else
    {
        stats[queueIndex].packetDropPerQueue++;

        if (WFQ_DEBUG)
        {
            char time[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(currentTime, time);
            printf("Wfq: Simtime %s got packet to drop \n", time);
            printf("\tThe queue is full so unable to enqueue\n");
        }
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


void WfqScheduler::insert(
    Message* msg,
    BOOL* QueueIsFull,
    const int priority,
    const void *infoField,
    const clocktype currentTime,
    TosType* tos
    )
{
    int i;
    double roundRate = 0.0;
    double queueServiceFinishTag = 0.0;
    double sumActiveWeight = 0.0;
    BOOL queueWasEmpty = FALSE;
    QueueData* qData = NULL;
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

        if (WFQ_DEBUG_WEIGHT)
        {
            for (i = 0; i < numQueues; i++)
            {
                printf("Queue[%d] Weight = %f\n", i, queueData[i].weight);
            }
        }
    }

    if (WFQ_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Wfq: Simtime %s got packet to enqueue with"
            " priority %u\n", time, queueData[queueIndex].priority);
        printf("\tQueue Service Finish Tag = %lf\n",
            queueInfo[queueIndex].queueServiceTag);
        printf("\tWeight of the queue %u = %.5f\n", queueIndex,
               queueData[queueIndex].weight);
        printf("\tRound Number before enqueuing is %lf\n",
               roundNumber);
    }

    // The priority queue in which incoming packet will be inserted
    qData = &queueData[queueIndex];

    if (qData->queue->isEmpty())
    {
        queueWasEmpty = TRUE;
    }

    if (tos == NULL)
    {
       qData->queue->insert(msg, infoField, QueueIsFull,
                         currentTime, queueServiceFinishTag);
    }
    else
    {
        qData->queue->insert(msg, infoField, QueueIsFull,
                         currentTime, tos, queueServiceFinishTag);
    }

    // Check if the queue is empty and insert
    if (queueWasEmpty && !(qData->queue->isEmpty()))
    {
        // If the queue is empty and the first packet is going to be inserted
        // in the queue increase the numActiveQueue accordingly

        numActiveQueueInfo++;
    }

    // If the queue in which the packet is to be inserted is not yet full
    // Find WfqFinishNumber, else drop the packet

    if (!*QueueIsFull)
    {
        // Update Round Number which is a virtual clock which progress
        // in round rate interval, where
        // round rate = 1 / (sum ActiveWeight)

        for (i = 0; i < numQueues; i++)
        {
            if (!queueData[i].queue->isEmpty())
            {
                sumActiveWeight += queueData[i].weight;
            }
        }

        roundRate = (double)(1.0 / sumActiveWeight);

        // Update Statistical Variables
        stats[queueIndex].totalPktEnqueued++;

        // Update the roundNumber & Service Finish Tag for queues
        roundNumber += roundRate;

        // Find WfqFinishNumber using round number if round number is
        // greater than the queue Finish number, else find it using its
        // queue finish number stored previously in it

        queueServiceFinishTag = MAX(roundNumber,
                            queueInfo[queueIndex].queueServiceTag)
                            + (MESSAGE_ReturnPacketSize(msg)
                            / queueData[queueIndex].weight);

        qData->queue->setServiceTag(queueServiceFinishTag);

        if (queueWasEmpty && !(qData->queue->isEmpty()))
        {
            // Update Queue Top Packets Finish Number
            queueInfo[queueIndex].queueFinishNum = queueServiceFinishTag;
        }

        queueInfo[queueIndex].queueServiceTag = queueServiceFinishTag;

        if (WFQ_DEBUG)
        {
            printf("\tRound Number after enqueuing is %lf\n", roundNumber);
            printf("\tQueue Top packet Finish Number = %lf\n",
                queueInfo[queueIndex].queueFinishNum);
        }
    }
    else
    {
        stats[queueIndex].packetDropPerQueue++;

        if (WFQ_DEBUG)
        {
            char time[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(currentTime, time);
            printf("Wfq: Simtime %s got packet to drop \n", time);
            printf("\tThe queue is full so unable to enqueue\n");
        }
    }
#ifdef ADDON_DB
    using namespace StatsQueueDB;
    if (qData->queue->returnQueueDBHook())
    {
        qData->queue->returnQueueDBHook()->eventHook(msg, 
            *QueueIsFull, priority, STATS_INSERT_PACKET);
    }
#endif
}


//**
// FUNCTION   :: WfqScheduler::retrieve
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

BOOL WfqScheduler::retrieve(
    const int priority,
    const int index,
    Message** msg,
    int* msgPriority,
    const QueueOperation operation,
    const clocktype currentTime)
{
    int i;
    int queueIndex = ALL_PRIORITIES;
    int returnIndex = ALL_PRIORITIES;
    double pktServiceTag = 0.0;
    QueueData* qData = NULL;
    BOOL isMsgRetrieved = FALSE;
    *msg = NULL;

    if (WFQ_DEBUG)
    {
        int k = 0;
        char clock[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(currentTime, clock);
        printf("WFQ: Simtime %s got request to dequeue\n", clock);
        printf("\tNum of Active queue before dequeuing is %u\n",
               numActiveQueueInfo);

        printf("\tNum Packet at the interface %d\n", 
               numberInQueue(priority
#ifdef ADDON_BOEINGFCS
                            ,TRUE
#endif               
                            ));

        for (k = 0; k < numQueue(); k++)
        {
            printf("Num Packet at %d = %d\n", queueData[k].priority,
                queueData[k].queue->packetsInQueue(
#ifdef ADDON_BOEINGFCS
                                                   TRUE
#endif                   
                                                   ));
        }
    }

    if (!(index < numberInQueue(priority
#ifdef ADDON_BOEINGFCS
                                ,TRUE
#endif           
                                 )) || (index < 0))
    {
        if (WFQ_DEBUG)
        {
            printf("WFQ: Attempting to retrieve a packet that"
                " does not exist\n");
        }
        return isMsgRetrieved;
    }

    if (priority == ALL_PRIORITIES)
    {
        qData = FairQueueSchedulerSelectNextQueue(index, &returnIndex);
    }
    else // if (specificPriorityOnly)
    {
        // Dequeue a packet from the specified priority queue
        qData = SelectSpecificPriorityQueue(priority);
        returnIndex = index;
    }

    if (qData == NULL)
    {
        return isMsgRetrieved;
    }
    // Get the Queue Index
    for (i = 0; i < numQueues; i++)
    {
        if (queueData[i].priority == qData->priority)
        {
            queueIndex = i;
            break;
        }
    }

    if (operation == DEQUEUE_PACKET)
    {
        // Update the statistical variables for dequeueing
        for (i = 0; i < numQueues; i++)
        {
            if (!queueData[i].queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                             TRUE
#endif
                                             ))
            {
                stats[i].numDequeueReq++;
                if (&queueData[i] != qData)
                {
                    stats[i].numMissedService++;
                }
            }
        }
    }

    if (WFQ_DEBUG)
    {
        printf("\tThe value of returnIndex passed for dequeue = %d\n",
               returnIndex);
    }

    clocktype insertTime = qData->queue->getPacketInsertTime(returnIndex);

    // Calling Queue retrive function
    isMsgRetrieved = qData->queue->retrieve(msg,
                                            returnIndex,
                                            operation,
                                            currentTime,
                                            &pktServiceTag);
    *msgPriority = qData->priority;

    if (isMsgRetrieved) // dequeue & discard
    {
        if (operation == DEQUEUE_PACKET)
        {
            // Update the statistical variables for dequeueing
            stats[queueIndex].totalServiceReceived
                += MESSAGE_ReturnPacketSize((*msg));
            stats[queueIndex].totalPktDequeued++;
        }

        if (operation == DISCARD_PACKET || operation == DROP_PACKET)
        {
            // Update Drop Status
            stats[queueIndex].packetDropPerQueue++;
        }

        if (operation == DROP_AGED_PACKET)
        {
            // Update Drop Status
            stats[queueIndex].packetDropPerQueueAging++;
        }

        // Update Queue Top Packet service Tag or Finish Number
        queueInfo[queueIndex].queueFinishNum = pktServiceTag;

        // Check if the queue is empty and deactivate
        if (qData->queue->isEmpty(
#ifdef ADDON_BOEINGFCS
                                  TRUE
#endif
                                  ))
        {
            numActiveQueueInfo--;
        }

        if (WFQ_DEBUG)
        {
            printf("\tRetrieved Packet from queue %u\n", qData->priority);
            printf("\tNum of Active queue after retrival is %u\n",
                   numActiveQueueInfo);
            printf("\tQueue Service Finish Tag = %lf\n",
                queueInfo[queueIndex].queueServiceTag);
            printf("\tQueue Top packet Finish Number = %lf\n",
                queueInfo[queueIndex].queueFinishNum);
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
    else // Top packet
    {
        if (WFQ_DEBUG)
        {
            char clock[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(currentTime, clock);
            printf("WFQ: Simtime %s got request to view top with"
                   "priority %u\n", clock, priority);
        }
    }
    return isMsgRetrieved;
}


//**
// FUNCTION   :: WfqScheduler::finalize
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

void WfqScheduler::finalize(
    Node* node,
    const char* layer,
    const int interfaceIndex,
    const char* invokingProtocol,
    const char* splStatStr)
{
    char schedType[MAX_STRING_LENGTH] = "WFQ";

    if (schedulerStatEnabled == FALSE)
    {
        return;
    }

    if (strcmp(invokingProtocol, "IP"))
    {
        memset(schedType, 0, MAX_STRING_LENGTH);
        sprintf(schedType, "%s %s WFQ", splStatStr, invokingProtocol);
    }

    FairQueueFinalize(node,
                    layer,
                    interfaceIndex,
                    schedType,
                    invokingProtocol,
                    splStatStr);
}


//---------------------------------------------------------------------------
// WFQ Scheduler Class Constructor
//---------------------------------------------------------------------------

//**
// FUNCTION   :: WfqScheduler::WfqScheduler
// LAYER      ::
// PURPOSE    :: Constractor of WfqScheduler class to initialize
//               its own data members
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Status of scheduler stat enable or not
// + graphDataStr : const char : Graph data string
// RETURN     ::
// **/

WfqScheduler::WfqScheduler(
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

    roundNumber = 0.0;

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



