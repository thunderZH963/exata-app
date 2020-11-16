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
// PROTOCOL     :: ATM_Scheduler.
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

#include "sch_atm.h"
#include "atm_layer2.h"

// /**
// CONSTANT    ::   ATM_DEBUG   : 0
// DESCRIPTION ::   Denotes for debuging ATM.
// **/

#define ATM_DEBUG 0


// /**
// FUNCTION   :: CalGCD
// LAYER      :: ATM Layer2
// PURPOSE    :: Returns Greatest Common Divisor of two integer.
// PARAMETERS ::
// + a : int
// + b : int
// RETURN     :: int
// **/
int AtmScheduler::CalGCD(int a, int b)
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

// /**
// FUNCTION   :: AtmUpdateQueueSpecificBW
// LAYER      :: ATM Layer2
// PURPOSE    :: Allocate or deallocate bandwidth for a specific queue
// PARAMETERS ::
// + queueIndex : int : Queue Index
// + bandwidth  : int : bandwidth
// + isAdd      : BOOL : Is add
// RETURN     :: BOOL : If operation successful then return TRUE
//                      otherwise FALSE
// **/
BOOL AtmScheduler::AtmUpdateQueueSpecificBW(int queueIndex,
                                            int bandwidth,
                                            BOOL isAdd)
{
    int i;
    int sumActiveBW = 0;
    AtmPerQueueInfo* atmPerQueueInfo = NULL;

    // Sum of all Active bandwidth
    for (i = 0; i < numQueues; i++)
    {
        atmPerQueueInfo = (AtmPerQueueInfo*) queueData[i].infoField;
        sumActiveBW += atmPerQueueInfo->activeBW;
    }
    atmPerQueueInfo = (AtmPerQueueInfo*) queueData[queueIndex].infoField;

    if (ATM_DEBUG)
    {
        printf("    TotalBW %d and ActiveBW %d \n", totalBW, sumActiveBW);
    }

    if (isAdd)
    {
        if ((sumActiveBW + bandwidth) > totalBW)
        {
            if (ATM_DEBUG)
            {
                printf("    Not support allocation\n");
            }
            return FALSE;
        }
        atmPerQueueInfo->activeBW += bandwidth;

        if (ATM_DEBUG)
        {
            printf("    Support allocation\n");
        }
    }
    else
    {
        if (atmPerQueueInfo->activeBW < (unsigned int)bandwidth)
        {
            if (ATM_DEBUG)
            {
                printf("    Not possible to deallocation\n");
            }
            return FALSE;
        }
        atmPerQueueInfo->activeBW -= bandwidth;

        if (ATM_DEBUG)
        {
            printf("    Deallocation\n");
        }
    }
    return TRUE;
}

// /**
// FUNCTION   :: IsResetServiceRound
// LAYER      :: ATM Layer2
// PURPOSE    :: Checks if need to resets all weightCounter for all queues
//               at the interface when the weightCounters belongig to all
//               the active queue equals zero.
// PARAMETERS ::
// RETURN     :: BOOL
// **/
BOOL AtmScheduler::IsResetServiceRound()
{
    int j;
    int numActiveQueue = 0;       // Number of Active queues at interface
    int numZeroWeightCounter = 0; // Number of Active queues with zero
                                  // weightCounter on this interface

    // It is not required for ZERO th queue.
    for (j = 1; j < numQueues; j++)
    {
        AtmPerQueueInfo* atmPerQueueInfo =
            (AtmPerQueueInfo*) queueData[j].infoField;

        // Find the number of active queues with zero weightCounter
        if (!queueData[j].queue->isEmpty())
        {
            // Find the number of active queues
            numActiveQueue += 1;

            if (atmPerQueueInfo->weightCounter == 0)
            {
                numZeroWeightCounter += 1;
            }
        }
        if (ATM_DEBUG)
        {
            printf("\t\t Number of packets in queue[%d] = %d\n",
                j, queueData[j].queue->packetsInQueue());
            printf("\t\t WeightCounter for queue[%d] = %d\n",
                j, atmPerQueueInfo->weightCounter);
        }
    }

    if (numActiveQueue == numZeroWeightCounter)
    {
        // All active queue weightCounters equal zero
        // reset the serviceRound and weightCounters
        return true;
    }
    return false;
}

// /**
// FUNCTION   :: WeightAssignment
// LAYER      :: ATM Layer2
// PURPOSE    :: Assigns queue weights
// PARAMETERS ::
// RETURN     :: void : None
// **/
void AtmScheduler::WeightAssignment()
{
    int i;
    int sumActiveBW = 0;
    AtmPerQueueInfo* atmPerQueueInfo = NULL;
    queueIndexInfo = 1;    // Queue selected for last dequeue

    // Sum of all Active bandwidth.It is not required for ZERO th queue.
    for (i = 1; i < numQueues; i++)
    {
        atmPerQueueInfo = (AtmPerQueueInfo*) queueData[i].infoField;
        sumActiveBW += atmPerQueueInfo->activeBW;
    }

    // Assign weight to each active queue
    if (ATM_DEBUG)
    {
        printf("Calculating Queue Weight .......\n");
    }

    // It is not required for ZERO th queue.
    for (i = 1; i < numQueues; i++)
    {
        atmPerQueueInfo = (AtmPerQueueInfo*) queueData[i].infoField;

        if (atmPerQueueInfo->activeBW > 0)
        {
            queueData[i].weight =
                atmPerQueueInfo->activeBW / (float) sumActiveBW;
            atmPerQueueInfo->weightCounter = (unsigned int)
                ((queueData[i].weight * totalBW) / (ATM_CELL_LENGTH * 8));
            gcdInfo = atmPerQueueInfo->weightCounter;
            break;
        }
    }

    for (; i < numQueues; i++)
    {
        atmPerQueueInfo = (AtmPerQueueInfo*) queueData[i].infoField;

        if (atmPerQueueInfo->activeBW > 0)
        {
            queueData[i].weight =
                atmPerQueueInfo->activeBW / (float) sumActiveBW;
            atmPerQueueInfo->weightCounter = (unsigned int)
                ((queueData[i].weight * totalBW) / (ATM_CELL_LENGTH * 8));
            gcdInfo = CalGCD(gcdInfo, atmPerQueueInfo->weightCounter);
        }
    }

    if (gcdInfo == 0)
    {
        if (ATM_DEBUG)
        {
            printf("ATM Scheduler: Link have no reserve bandwidth");
        }
        return;
    }

    for (i = 1; i < numQueues; i++)
    {
        atmPerQueueInfo = (AtmPerQueueInfo*) queueData[i].infoField;
        atmPerQueueInfo->weightCounter /= gcdInfo;
        numCellInRound += atmPerQueueInfo->weightCounter;

        if (ATM_DEBUG)
        {
            printf("\t\tWeight[%d] = %0.9lf and Count = %d\n",
                i, queueData[i].weight, atmPerQueueInfo->weightCounter);
        }
    }
    isWeightAssigned = true;
}

// /**
// FUNCTION   :: AtmSchedulerSelectNextQueue
// LAYER      :: ATM Layer2
// PURPOSE    :: Schedules for a queueIndex And packetIndex to be dequeued
// PARAMETERS ::
// + index : int : Index
// + queueIndex : int* : Queue Index
// RETURN     :: void : None
// **/
void AtmScheduler::AtmSchedulerSelectNextQueue(int index,
                                               int* queueIndex)
{
    AtmPerQueueInfo* atmPerQueueInfo = NULL;
    int numOfQueuesChecked = 1;  // The number of queues checked

    *queueIndex = queueIndexInfo;

    if (ATM_DEBUG)
    {
        printf("\t\t\tLast dequeued queue = %d\n\n", *queueIndex);
        printf("\t\t\t---------ATM Scheduler Procedure---------\n\n");
        printf("\t\t\t\tGot index = %d \n", index);
    }

    while (TRUE)
    {
        if (numCellInRound)
        {
            if (IsResetServiceRound())
            {
                numCellInRound = 0;

                if (ATM_DEBUG)
                {
                    printf("\t\t Resetting serviceRound by force...\n");
                    printf("\n\t\t --------------Reset"
                        " Start--------------\n");
                }
                // Reassign all the weightCounter
                WeightAssignment();
                *queueIndex = queueIndexInfo;
            }
        }
        else
        {
            WeightAssignment();
            *queueIndex = queueIndexInfo;
        }

        if (ATM_DEBUG)
        {
            printf("\t\t\t\tDequeue request for queue = %d\n", *queueIndex);
            printf("\t\t\t\tScarching for the packet...\n");
        }

        if (*queueIndex == numQueues)
        {
            *queueIndex = 1;
        }

        atmPerQueueInfo =
            (AtmPerQueueInfo*) queueData[*queueIndex].infoField;

        // Checking whether the queue is not empty
        // and weight counter is not ZERO
        if (!queueData[*queueIndex].queue->isEmpty() &&
            atmPerQueueInfo->weightCounter)
        {
            if (ATM_DEBUG)
            {
                printf("\t\t\t\tGot the packet in this queue\n");
            }
            return;
        }

        if (ATM_DEBUG)
        {
            printf("\t\t\t\tPacket not found; switch to next queue\n");
        }

        if (numOfQueuesChecked == numQueues)
        {
            isWeightAssigned = false;
            *queueIndex = ALL_PRIORITIES;
            return;
        }
        *queueIndex += 1;
        numOfQueuesChecked ++;  // The number of queues checked
    }
}
// /**
// FUNCTION   :: insert
// LAYER      :: ATM Layer2
// PURPOSE    :: Inserts a packet in the queue
// PARAMETERS ::
// + msg : Message* : Message Pointer
// + QueueIsFull : BOOL* : Checkinh for Queue is full
// + queueIndex  : const int : Queue Index
// + infoField   : const void* : Pointer to Info field
// + currentTime : const clocktype : Current Simulation Time
// RETURN     :: BOOL
// NOTE       This function prototype determines the arguments that need
//            to be passed to a scheduler data structure in order to insert
//            a message into it. The scheduler is responsible for routing
//            this packet to an appropriate queue that it controls, and
//            returning whether or not the procedure was successful.  The
//            changes here are the replacement of the dscp parameter
//            with the infoField pointer.  The size of this infoField is
//            stored in infoFieldSize.
// **/
void AtmScheduler::insert(Node* node,
                          int interfaceIndex,
                          Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime)
{
    insert(msg, QueueIsFull, queueIndex, infoField, currentTime);
}

void AtmScheduler::insert(Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime)
{
    ERROR_Assert(queueIndex >= 0,
        "Queue with negetive InternalId does not exit\n");

    // The priority queue in which incoming packet will be inserted
    QueueData* qData = &queueData[queueIndex];

    if (ATM_SCH_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("\nAtm Scheduler: Simtime %s got packet to enqueue\n", time);
    }

    // Insert the packet in the queue
    qData->queue->insert(msg, NULL, QueueIsFull, currentTime);

    if (!*QueueIsFull)
    {
        if (ATM_SCH_DEBUG)
        {
            printf("\t\t\tInserting a packet in Queue %u \n\n",
                qData->priority);
        }

        // Update packet enqueue status
        stats[queueIndex].packetQueued++;
    }
    else
    {
        if (ATM_SCH_DEBUG)
        {
            printf("\t\t\tDropping a packet as no space in Queue %u \n\n",
                qData->priority);
        }

        // Update packet dequeue status
        stats[queueIndex].packetDropped++;
    }
}

// /**
// FUNCTION   :: retrieve
// LAYER      :: ATM Layer2
// PURPOSE    :: Dequeues a packet from the queue
// PARAMETERS ::
// + priority   : const int : Queue Pririty
// + index      : const int:  Index
// + msg           : Message** : Pointer to Message
// + msgPriority   : int* : message Priority
// + operation     : const QueueOperation : next header field
// + currentTime   : const clocktype : Current Simulation Time
// RETURN     :: BOOL
// NOTE       This function prototype determines the arguments that need
//            to be passed to a scheduler data structure in order to dequeue
//            or peek at a message in its array of stored messages.
//            I've reordered the arguments slightly, and incorporated
//            the "DropFunction" functionality as well.
// **/
BOOL AtmScheduler::retrieve(const int priority,
                            const int index,
                            Message** msg,
                            int* msgPriority,
                            const QueueOperation operation,
                            const clocktype currentTime)
{
    int j = 0;
    int queueIndex = ALL_PRIORITIES; //-1;
    int packetIndex = 0; // always dequeue the top packet.
    AtmPerQueueInfo* atmPerQueueInfo = NULL;
    QueueData* qData = NULL;
    BOOL isMsgRetrieved = false;

    *msg = NULL;

    if (ATM_DEBUG)
    {
        char time[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(currentTime, time);
        printf("Atm : Simtime %s got request to dequeue\n", time);
    }

    if (priority == ALL_PRIORITIES)
    {
        // If ZERO th queue has cell to send then serve it first.
        if (!queueData[0].queue->isEmpty())
        {
            queueIndex = 0;
        }
        else        // Find the queue for dequeuing a packet
        {
            AtmSchedulerSelectNextQueue(index, &queueIndex);
        }

        if (queueIndex != ALL_PRIORITIES)
        {
            // The queue selected for dequeuing a packet
            qData = &queueData[queueIndex];

            // Calling Queue retrive function
            isMsgRetrieved = qData->queue->retrieve(msg,
                                                    packetIndex,
                                                    operation,
                                                    currentTime);
            *msgPriority = qData->priority;

            if (ATM_DEBUG)
            {
                printf("\t  Retrieved Packet from queue %u\n",
                    qData->priority);
            }
        }
    }

    if (ATM_DEBUG)
    {
        printf("\t\t This queue selected for dequeue = %d \n",
            queueIndex);
        printf("\t\t Position of packet in the queue = %d\n", packetIndex);

        printf("\t ------------------------------------------------\n\n");
    }

    //  If the message is dequeued ,Update related variables
    if (isMsgRetrieved)
    {
        if (operation == DEQUEUE_PACKET)
        {
            // Update the statistical variables for dequeueing
            stats[queueIndex].packetDequeued++;

            for (j = 0; j < numQueues; j++)
            {
                if (!queueData[j].queue->isEmpty())
                {
                    // Total number of dequeue requests while queues active
                    stats[j].totalDequeueRequest++;
                }
            }

            if (queueIndex != 0)
            {
                ERROR_Assert(gcdInfo != 0, "No bandwidth is allocated\n");
                // Update ATM scheduler related variables
                atmPerQueueInfo =
                    (AtmPerQueueInfo*) queueData[queueIndex].infoField;
                atmPerQueueInfo->weightCounter -= 1;
                numCellInRound -= 1;

                // Update queueIndex value
                queueIndexInfo = queueIndex;
            }
        }
        else
        {
            ERROR_Assert(FALSE, "Atm Scheduler not support any "
                "operation other than DEQUEUE_PACKET\n");
        }
    }
    return isMsgRetrieved;
}


// /**
// FUNCTION   :: addQueue
// LAYER      :: ATM Layer2
// PURPOSE    :: Addes a Queue to the Scheduler
// PARAMETERS ::
// + queue     : Queue*    :   Queue
// + priority  : const int :   Priority of the Queue
// + weight    : const double :  Weight of the Queue
// RETURN     :: int : Priority
// NOTE         This function adds a queue to a scheduler.
//              This can be called either at the beginning of the simulation
//              (most likely), or during the simulation (in response to QoS
//              situations).  In either case, the scheduling algorithm
//              must accommodate the new queue, and behave appropriately
//              (recalculate turns, order, priorities) immediately.
//              This queue must have been previously setup using QUEUE_Setup.
//              Notice that the default value for priority is the
//               ALL_PRIORITIES constant, which implies that the scheduler
//               should assign the next appropriate value to the queue.
//              This could be an error condition, if it is not immediately
//              apparent what the next appropriate value would be, given the
//              scheduling algorithm running.
// **/
int AtmScheduler::addQueue(Queue *queue,
                           const int priority,
                           const double weight)
                           // Here weight carries BW of a particular queue.
{
    int i;
    if ((numQueues == 0) || (numQueues == maxQueues))
    {
        QueueData* newQueueData
            = new QueueData[maxQueues + DEFAULT_QUEUE_COUNT];

        AtmSchStat* newStats
            = new AtmSchStat[maxQueues + DEFAULT_QUEUE_COUNT];

        ERROR_Assert(newQueueData && newStats, "Insufficient memory space");

        if (queueData != NULL)
        {
            memcpy(newQueueData, queueData, sizeof(QueueData) * maxQueues);
            delete[] queueData;

            memcpy(newStats, stats, sizeof(AtmSchStat) * maxQueues);
            delete[] stats;
        }

        queueData = newQueueData;
        stats = newStats;
        maxQueues += DEFAULT_QUEUE_COUNT;
    }

    ERROR_Assert(maxQueues > 0,
        "Scheduler addQueue function maxQueues <= 0");

    AtmPerQueueInfo* atmPerQueueInfo = new AtmPerQueueInfo;
    memset(atmPerQueueInfo, 0, sizeof(AtmPerQueueInfo));
    atmPerQueueInfo->activeBW = (int)weight;

    for (i = 0; i < numQueues; i++)
    {
        ERROR_Assert(queueData[i].priority != priority,
            "Priority queue already exists");

        if (queueData[i].priority > priority)
        {
            int afterEntries = numQueues - i;
            QueueData* newQueueData = new QueueData[afterEntries];
            AtmSchStat* newStats = new AtmSchStat[afterEntries];

            memcpy(newQueueData, &queueData[i],
                   sizeof(QueueData) * afterEntries);
            memcpy(&queueData[i+1], newQueueData,
                   sizeof(QueueData) * afterEntries);

            memcpy(newStats, &stats[i],
                   sizeof(AtmSchStat) * afterEntries);
            memcpy(&stats[i+1], newStats,
                   sizeof(AtmSchStat) * afterEntries);

            delete[] newQueueData;
            delete[] newStats;
            break;
        }
    }

    queueData[i].priority = priority;
    queueData[i].weight = 0;
    queueData[i].queue = queue;
    queueData[i].infoField = (char*) atmPerQueueInfo;
    memset(&stats[i], 0, sizeof(AtmSchStat));
    numQueues++;
    return queueData[i].priority;
}

// /**
// FUNCTION   :: removeQueue
// LAYER      :: ATM Layer2
// PURPOSE    :: Removes a Queue from the Scheduler
//               this is pure virtual function in scheduler.h
// PARAMETERS ::
// + priority      : const int    : Priority
// RETURN     :: void : None
// NOTE         This function removes a queue from the scheduler.
//              This function does not automatically finalize the queue,
//              so if the protocol modeler would like the queue to print
//              statistics before exiting, it must be explicitly finalized.
// **/
void AtmScheduler::removeQueue(const int priority)
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
                delete queueData[i].infoField;

                memmove(&queueData[i], &queueData[i+1],
                    sizeof(QueueData) * afterEntries);

                memmove(&stats[i], &stats[i+1],
                    sizeof(AtmSchStat) * afterEntries);
            }
            else
            {
                delete queueData[i].queue;
                delete queueData[i].infoField;
            }
            numQueues--;
            return;
        }
    }
    ERROR_Assert(FALSE, "Specific Queue is not found for remove");
}

// /**
// FUNCTION   :: swapQueue
// LAYER      :: ATM Layer2
// PURPOSE    :: Only define this function because
//               this is pure virtual function in scheduler.h
// PARAMETERS ::
// + queue         : Queue*    : The Queue Pointer
// + priority      : const int : Priority
// RETURN     ::  void : None
// **/
void AtmScheduler::swapQueue(Queue* queue, const int priority)
{
    ERROR_Assert(FALSE, "ATM Scheduler not use this function");
    return;
}

// /**
// FUNCTION   :: finalize
// LAYER      :: ATM Layer2
// PURPOSE    :: This function prototype outputs the final statistics for
//              this scheduler. The layer, protocol, interfaceAddress, and
//              instanceId parameters are given to IO_PrintStat with each
//              of the queue's statistics.
// PARAMETERS ::
// + node     : Node*    : The node
// + layer      : const char* : The Layer
// + interfaceIndex    :  const int : Interface Index
// + invokingProtocol   : const char* : Invoking Protocol
// RETURN     ::  void : None
// **/
void AtmScheduler::finalize(Node* node,
                            const char* layer,
                            const int interfaceIndex,
                            const char *invokingProtocol,
                            const char* splStatStr)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char intfIndexStr[MAX_STRING_LENGTH] = {0};

    if (schedulerStatEnabled == false)
    {
        return;
    }

    sprintf(intfIndexStr, "%d", interfaceIndex);

    for (i = 0; i < numQueues; i++)
    {
        sprintf(buf, "Packets Queued = %u", stats[i].packetQueued);
        IO_PrintStat(
            node,
            layer,
            "ATM LAYER2",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dequeued = %u", stats[i].packetDequeued);
        IO_PrintStat(
            node,
            layer,
            "ATM LAYER2",
            intfIndexStr,
            queueData[i].priority,
            buf);

        sprintf(buf, "Packets Dropped = %u", stats[i].packetDropped);
        IO_PrintStat(
            node,
            layer,
            "ATM LAYER2",
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
            "ATM LAYER2",
            intfIndexStr,
            queueData[i].priority,
            buf);
    }
}

// /**
// FUNCTION   :: AtmScheduler
// LAYER      :: ATM Layer2
// PURPOSE    :: Class Constructor
// PARAMETERS ::
// + enableSchedulerStat : BOOL : Enable Scduler Stat
// RETURN     :: None : constructer
// **/

AtmScheduler::AtmScheduler(BOOL enableSchedulerStat)
{
    queueData = NULL;
    numQueues = 0;
    maxQueues = 0;
    infoFieldSize = 0;
    packetsLostToOverflow = 0;
    totalBW = 0;
    schedulerStatEnabled = enableSchedulerStat;

    // Initialize WRR Scheduler specific info.
    isWeightAssigned = false;
    queueIndexInfo = -1;    // Queue selected for last dequeue
    numCellInRound = 0;
    gcdInfo = 0;            // GreatestCommonDivisor for WRR
    stats = NULL;
}

// /**
// FUNCTION   :: PrintNumAtmCellEachQueque
// LAYER      :: ATM Layer2
// PURPOSE    :: for debug purpose
// PARAMETERS ::       :
// RETURN     :: void : NULL
// **/

void AtmScheduler::PrintNumAtmCellEachQueque()
{
    int j;

    printf("\n Number of Atm Cell into each Queue:-");

    for (j = 0; j < numQueues; j++)
    {
        printf("\t queue[%d]= %d", j, queueData[j].queue->packetsInQueue());
    }
    printf("\n");
}


// /**
// FUNCTION   :: AtmScheduler::~AtmScheduler
// LAYER      ::
// PURPOSE    :: This function will free the memory in the
//               AtmScheduler
// PARAMETERS ::
// RETURN     :: void : Null
// **/
AtmScheduler::~AtmScheduler() 
{
    delete []queueData;
    delete []stats;
}
