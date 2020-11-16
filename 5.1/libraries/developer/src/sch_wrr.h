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
// SUMMARY  :: Weighted Round Robin (WRR) is a variant of the simple Round
// Robin (RR) scheduling algorithm. WRR Scheduling can prioritize service so
// that different traffic may be serviced differently. Each queue has a
// weight that reflects their allocated bandwidth and allows sending certain
// amount of data in one service round before going to the next service
// round Thus, Weighted Round Robin improves performances of Round Robin by
// inserting service prioritization and ensures traffic to get fair share of
// allocated bandwidth.
//
// LAYER    ::
//
// STATISTICS::
// + packetQueued : Total packet queued
// + packetDequeued : Total packet dequeued
// + packetDropped : Total packet dropped
// + totalDequeueRequest : Total dequeue request
//
// CONFIG_PARAM ::
//
// VALIDATION ::
//
// IMPLEMENTED_FEATURES ::
// Each queue has a weight that reflects their allocated bandwidth and
// allows sending certain amount of data in one service round before going
// to the next service round Thus, Weighted Round Robin improves
// performances of Round  Robin by inserting service prioritization and
// ensures traffic to get fair share of llocated bandwidth.
//
// OMITTED_FEATURES ::
//
// ASSUMPTIONS ::
// + User can specifies a weight for each queue but it should be >0 and <1.
// + If there is no weight specification for queues, weights to each queue
//   will be assigned internally in proportion to their priority.
//
// STANDARD ::
// A Methodology for Study of Network Processing Architectures.
// SURYANARAYANAN, DEEPAK.(Under the direction of Dr.Gregory T Byrd.)
// http://www.lib.ncsu.edu/etd/public/etd-45401520610152001/etd.pdf
//
// RELATED ::
// **/


#ifndef SCH_WEIGHTED_ROUND_ROBIN_H
#define SCH_WEIGHTED_ROUND_ROBIN_H

#include "if_scheduler.h"


#define WRR_DEBUG 0
#define WRR_DEBUG_WEIGHT 0

//--------------------------------------------------------------------------
// Weighted Round Robin (WRR) Scheduler API
//--------------------------------------------------------------------------

// /**
// CONSTANT    :: WRR_WEIGHT_MULTIPLIER : 100
// DESCRIPTION :: Weight multipier for service count calculation
// **/

#define WRR_WEIGHT_MULTIPLIER 100


// /**
// STRUCT      :: WrrStat
// DESCRIPTION :: This structure contains statistics for the scheduler
// **/

typedef struct
{
    unsigned int packetQueued;      // Total packet queued
    unsigned int packetDequeued;    // Total packet dequeued
    unsigned int packetDropped;     // Total packet dropped
    unsigned int totalDequeueRequest;
} WrrStat;


// /**
// STRUCT      :: WrrPerQueueInfo
// DESCRIPTION :: This structure contains service count information
//                for for Queues under this scheduler
// **/

typedef struct Wrr_ipqueue_info_str
{
    unsigned int weightCounter;  // weight Counter for WRR

} WrrPerQueueInfo;


// /**
// CLASS       :: WrrScheduler
// DESCRIPTION :: Weighted Round Robin Scheduler Class
// **/

class WrrScheduler : public Scheduler
{
    protected:
      BOOL              isAssigned;
      int               gcdInfo;         // GreatestCommonDivisor Info
      unsigned int      serviceRound;
      int               queueIndexInfo;  // Queue selected for last dequeue
      WrrPerQueueInfo*  queueInfo;
      WrrStat*          stats;

      int CalculateGreatestCommonDivisor(int a, int b);
      void ReassignQueueWeightCounter();
      void AssignQueueWeightCounter();

      BOOL IsResetServiceRound();

      void WrrSelectNextQueue(int index,
                            int* queueIndex,
                            int* packetIndex);

    public:
      WrrScheduler(BOOL enableSchedulerStat,
                   const char graphDataStr[]);

      virtual ~WrrScheduler();

      void AutoWeightAssignment();

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
                          TosType* tos);



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

#endif // SCH_WEIGHTED_ROUND_ROBIN_H
