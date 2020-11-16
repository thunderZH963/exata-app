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
// PROTOCOL :: Queue-Scheduler
//
// SUMMARY  :: Strict Priority Scheduling is one of the first approaches
// used to provide different services. Traffic is inserted into different
// queues that are served according to their priority. Highest priority
// queue (queue with priority 0) are served as soon as they have packets in
// there. Thus with strict priority  scheduling, the queue with highest
// priority  served first, and continues to be served until it is empty
// which lead to starvation of queues with lower priority.
//
// LAYER ::
//
// STATISTICS::
// + packetQueued : Total number of packets queued
// + packetDequeued : Total number of packets dequeued
// + packetDropped : Total number of packets drop
//
// CONFIG_PARAM :: None
//
// VALIDATION :: None
//
// IMPLEMENTED_FEATURES :: Highest priority queue (queue with priority 0)
// are served as soon as they have packets in there. Thus with strict
// priority  scheduling, the queue with highest priority  served first, and
// continues to be served until it is empty which lead to starvation of
// queues with lower priority.
//
// OMITTED_FEATURES :: None
//
// ASSUMPTIONS :: None
//
// STANDARD :: None
//
// RELATED :: N.A.
// **/

#ifndef SCH_STRICT_PRIO_H
#define SCH_STRICT_PRIO_H

#include "if_scheduler.h"

#define SCH_PRIO_DEBUG 0

//--------------------------------------------------------------------------
// StrictPriorityScheduler API
//--------------------------------------------------------------------------

// /**
// STRUCT      :: StrictPriorityStat
// DESCRIPTION :: This structure contains statistics for this scheduler
// **/

typedef struct
{
    unsigned int packetQueued;      // Total packet queued
    unsigned int packetDequeued;    // Total packet dequeued
    unsigned int packetDropped;     // Total packet dropped
    unsigned int packetDroppedAging;     // Total packet dropped aging
}StrictPriorityStat;


// /**
// CLASS       :: StrictPriorityScheduler
// DESCRIPTION :: StrictPriority Scheduler Class
// **/

class StrictPriorityScheduler : public Scheduler
{
    protected:
      StrictPriorityStat* stats;

    public:
      StrictPriorityScheduler(BOOL enableSchedulerStat,
                            const char graphDataStr[]);

      virtual ~StrictPriorityScheduler();

      virtual void insert(Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime);

      virtual void insert(Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime,
                          TosType* tos);

      virtual void insert(Node* node,
                          int interfaceIndex,
                          Message* msg,
                          BOOL* QueueIsFull,
                          const int priority,
                          const void *infoField,
                          const clocktype currentTime,
                          TosType* tos);

      virtual void insert(Node* node,
                          int interfaceIndex,
                          Message* msg,
                          BOOL* QueueIsFull,
                          const int priority,
                          const void *infoField,
                          const clocktype currentTime);

      virtual BOOL retrieve(const int priority,
                            const int index,
                            Message** msg,
                            int* msgPriority,
                            const QueueOperation operation,
                            const clocktype currentTime);

      virtual int addQueue(Queue* queue,
                          const int priority = ALL_PRIORITIES,
                          const double weight = 1.0);

      virtual void removeQueue(const int priority);

      virtual void swapQueue(Queue* queue, const int priority);

      virtual void finalize(Node* node,
                          const char* layer,
                          const int interfaceIndex,
                          const char* invokingProtocol = "IP",
                          const char* splStatStr = NULL);
};


#endif // SCH_STRICT_PRIO_H
