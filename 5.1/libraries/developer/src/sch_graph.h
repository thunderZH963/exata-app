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
// SUMMARY  :: A performance study tool for QualNet schedulers.
//
// LAYER ::
//
// STATISTICS:: N.A.
//
// CONFIG_PARAM :: None
//
// VALIDATION :: None
//
// IMPLEMENTED_FEATURES :: A performance study tool for QualNet schedulers
//
// OMITTED_FEATURES :: None
//
// ASSUMPTIONS :: This implementation assumes queue index & priority value
// are same
//
// STANDARD :: None
//
// RELATED :: None
// **/

#ifndef _SCH_GRAPH_H_
#define _SCH_GRAPH_H_

#include "if_scheduler.h"

// /**
// STRUCTURE   :: SchedQueueInfo
// DESCRIPTION :: Scheduler queue information structure
// **/

typedef struct sched__queue_info_type
{
    int numByteDequeuePerInterval;
    int numPktDequeuePerInterval;
} SchedQueueInfo;


// /**
// CLASS       :: SchedGraphStat
// DESCRIPTION :: Scheduler graph statistics class
// **/

class SchedGraphStat
{
    protected:
      clocktype intervalForCollectGraphStat;
      int totalNumDequeRequestPerInterval;
      clocktype lastStorageTimeForCollectGraphStat;

      SchedQueueInfo*     schedQueueInfo;

      // File descriptor
      FILE*   thruputFd;        // thruput statistics
      FILE*   serviceRatioFd;   // statistics into certain interval.
      FILE*   queueSizePktsFd;  // QueueSize vs Time
      FILE*   queueSizeBytesFd; // Average Queue Size

      void openFilePointer(const char graphFileName[],
                            char locationInfoStr[],
                            FILE** graphFileFd);

      void writeSeriesTags(int numQueues);

    public:
      SchedGraphStat(const char graphDataStr[]);

      void collectStatisticsForGraph(Scheduler* scheduler,
                                    const int numQueues,
                                    const int priority,
                                    const int pktSize,
                                    const clocktype currentTime);
      ~SchedGraphStat();
};


#endif
