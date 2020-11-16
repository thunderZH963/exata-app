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
// SUMMARY  :: Common Fair Queue Scheduler Functionalities
//
// LAYER ::
//
// STATISTICS:: Same as wfq and scfq scheduler
//
// CONFIG_PARAM :: N.A.
//
// VALIDATION :: N.A.
//
// IMPLEMENTED_FEATURES :: Commmon features of scfq and wfq scheduler
// function
//
// OMITTED_FEATURES :: Same as scfq and wfq scheduler
//
// ASSUMPTIONS :: Same as scfq and wfq scheduler
//
// STANDARD :: Same as scfq and wfq scheduler
//
// RELATED :: None
// **/

#ifndef SCH_FAIR_QUEUE_H
#define SCH_FAIR_QUEUE_H


#include "if_scheduler.h"


#define FQ_DEBUG_DROP 0
#define FQ_DEBUG_WEIGHT 0
#define FQ_DEBUG_SORT 0

#define FQ_DEBUG_TRACE 0

//--------------------------------------------------------------------------
// Generic Fair Queue (FQ) API
//--------------------------------------------------------------------------

// /**
// STRUCT      :: FairQueueSchStat
// DESCRIPTION :: This structure contains statistics for Fair schedulers
// **/

typedef struct generic_fq_stat_str
{
    // Generic fq Enqueue Stat
    UInt32        totalPktEnqueued;

    // Generic fq Drop Stat
    UInt32        packetDropPerQueue;

    UInt32        packetDropPerQueueAging;

    // Generic fq Dequeue Stat
    UInt32        totalPktDequeued;
    UInt32        numDequeueReq;
    UInt32        numMissedService;
    UInt32        totalServiceReceived; // Total bytes dequeued
} FairQueueSchStat;


// /**
// STRUCT      :: FairQueueInfo
// DESCRIPTION :: This structure contains the Queue finish number
//                for each queue under the selected Fair scheduler
// **/

typedef struct generic_fq_queue_info_str
{
    double queueFinishNum; // Queue Top packet Finish Number
    double queueServiceTag; // Queue Service Finish Tag
} FairQueueInfo;


// /**
// STRUCT      :: SortQueueInfo
// DESCRIPTION :: This structure helps to sort Queue finish number
// **/

typedef struct sorted_Queue_Info_str
{
    double  sortedQueueFinishNum;
    int     sortedQueuePriority;
    int     internalIndex; // Internal Packet Index
    BOOL    skip; // Need to skip this queue at boundary
} SortQueueInfo;


// /**
// CLASS       :: FQScheduler
// DESCRIPTION :: The base class for Fair Schedulers, e.g., WFQ, SCFQ
// **/

class FQScheduler : public Scheduler
{
    protected:
      BOOL              isAssigned;
      int               numActiveQueueInfo;

      FairQueueInfo*    queueInfo;
      FairQueueSchStat* stats;

      SortQueueInfo*    sortQueueInfo;

      void FairQueueInsertionSort();

      QueueData* FairQueueSchedulerSelectNextQueue(int index,
                                    int* returnIndex);

      void FairQueueFinalize(Node* node,
                      const char* layer,
                      const int interfaceIndex,
                      const char* schedulerTypeString,
                      const char* invokingProtocol,
                      const char* splStatStr);

    public:
      virtual ~FQScheduler();
      void AutoWeightAssignment();

      virtual int addQueue(Queue* queue,
                          const int priority = ALL_PRIORITIES,
                          const double weight = 1.0);

      virtual void removeQueue(const int priority);

      virtual void swapQueue(Queue* queue, const int priority);
};


#endif // SCH_FAIR_QUEUE_H

