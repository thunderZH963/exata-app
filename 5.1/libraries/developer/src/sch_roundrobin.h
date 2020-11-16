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
// SUMMARY  :: Round Robin Scheduling is proposed to avoid starvation of
// queues with lower priority. A Round Robin Scheduler alternates the
// service among the classes. For example, if there are three types of
// priority packets 0, 1, 2 respectively, a class 0 packet (highest priority
// packet) is transmitted first, followed by a class 1 packet, followed by a
// class 2 packet and then again a class 0 packet and so on. Thus Round
// Robin Scheduling avoids starvation of some queues and ensures that
// traffic gets fair share of bandwidth. But with this type of scheduling
// services can't be prioritized.
//
// LAYER ::
//
// STATISTICS::
// + packetQueued : Total packets queued
// + packetDequeued : Total packets dequeued
// + packetDropped : Total packets drop
// + totalDequeueRequest : Total dequeue request
//
// CONFIG_PARAM :: None
//
// VALIDATION :: None
//
// IMPLEMENTED_FEATURES :: if there are three types of priority packets 0,
// 1, 2 respectively, a class 0 packet (highest priority packet) is
// transmitted first, followed by a class 1 packet, followed by a class 2
// packet and then again a class 0 packet and so on. Thus Round Robin
// Scheduling avoids starvation of some queues and ensures that traffic gets
// fair share of bandwidth. But with this type of scheduling services can't
// be prioritized.
//
// OMITTED_FEATURES :: None
//
// ASSUMPTIONS :: None
//
// STANDARD :: None
//
// RELATED :: None
// **/

#ifndef SCH_ROUND_ROBIN_H
#define SCH_ROUND_ROBIN_H

#include "if_scheduler.h"


#define RR_DEBUG 0


//---------------------------------------------------------------------------
// RoundRobin Scheduler API
//---------------------------------------------------------------------------

// /**
// STRUCT      :: RoundRobinStat
// DESCRIPTION :: This structure contains statistics for this scheduler
// **/

typedef struct
{
    unsigned int packetQueued; // Total packet queued
    unsigned int packetDequeued; // Total packet dequeued
    unsigned int packetDropped; // Total packet dropped
    unsigned int totalDequeueRequest; // Total dequeue request at
                                      // the interface when
                                      // this queue is active
} RoundRobinStat;


// /**
// CLASS       :: RoundRobinScheduler
// DESCRIPTION :: RoundRobin Scheduler Class
// **/

class RoundRobinScheduler : public Scheduler
{
    protected:
      int             queueIndexInfo;
      RoundRobinStat* stats;

      void RoundRobinSelectNextQueue(int index,
                                    int* queueIndex,
                                    int* packetIndex);

    public:
      RoundRobinScheduler(BOOL enableSchedulerStat,
                        const char graphDataStr[]);

      virtual ~RoundRobinScheduler();

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
                          TosType* tos
                          );

      virtual void insert(Node* node,
                          int interfaceIndex,
                          Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime);

      virtual void insert(Node* node,
                          int interfaceIndex,
                          Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField,
                          const clocktype currentTime,
                          TosType* tos
                          );


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


#endif // SCH_ROUND_ROBIN_H
