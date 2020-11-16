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


#ifndef SCH_RED_H
#define SCH_RED_H

#include "if_scheduler.h"

#define SCH_RED_DEBUG 0

#define DEFAULT_RED_SCHEDULER_SMOOTHING_FACTOR 0.125

#define DEFAULT_RED_SCHEDULER_MAX_LENGTH 5000000

#define DEFAULT_RED_SCHEDULER_MIN_LENGTH 4000000

//--------------------------------------------------------------------------
// REDScheduler API
//--------------------------------------------------------------------------

// /**
// STRUCT      :: REDStat
// DESCRIPTION :: This structure contains statistics for this scheduler
// **/

typedef struct
{
    unsigned int packetQueued;      // Total packet queued
    unsigned int packetDequeued;    // Total packet dequeued
    unsigned int packetDropped;     // Total packet dropped
    unsigned int packetDroppedAging;     // Total packet dropped aging
}REDStat;

typedef struct
{
      int maxLength;
      int minLength;
      double smoothingFactor;
}REDParams;

// /**
// CLASS       :: REDScheduler
// DESCRIPTION :: RED limited StrictPriority Scheduler Class
// **/

class REDScheduler : public Scheduler
{
    protected:
      REDStat* stats;
      int averageLength;
      int clim;
      REDParams* params;
      virtual void updateAverageLength(int newLength);

    public:
      REDScheduler(BOOL enableSchedulerStat,
                   const char graphDataStr[],
                   REDParams *rParams);

      virtual ~REDScheduler();

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


#endif // SCH_RED_H
