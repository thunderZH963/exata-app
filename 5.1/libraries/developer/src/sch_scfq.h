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
// SUMMARY  ::  Self Clocked Fair Queuing is an IP packet scheduling
// discipline. In Packet-Switched Networks, the packets belonging to various
// network flows are multiplexed together and queued for transmission at the
// output buffers associated with a link. The manner in which queued packets
// are selected for transmission on the link is known as the link scheduling
// discipline. IP packets arriving to the output interface are classified
// according to its priority. Each priority class typically has its own
// waiting area (queue). Similar to WFQ, for SCFQ, there are many queues in
// each output interface. SCFQ ensures that queues do not starve for
// bandwidth, and that traffic gets predictable service. In contrast, with
// priority queues, the queue with highest priority gets serviced first, and
// continues to be served until it is empty. This can lead to starvation of
// queues with lower priority. Weights are assigned to each queue, to
// reflect their allocated bandwidth. Self Clocked Fair Queuing tries to
// schedule multiple queues such that each of them gets a fair share of the
// total bandwidth. This will prevent starvation of any flow and allow
// traffic to get predictable service.
//
// LAYER ::
//
// STATISTICS::Same as wrr scheduler
//
// CONFIG_PARAM ::Same as wrr scheduler
//
// VALIDATION :: $QUALNET_HOME/verification/scheduler/scfq
//
// IMPLEMENTED_FEATURES :: SCFQ ensures that queues do not starve for
// bandwidth, and that traffic gets predictable service. In contrast, with
// priority queues, the queue with highest priority gets serviced first, and
// continues to be served until it is empty. This can lead to starvation of
// queues with lower priority. Weights are assigned to each queue, to
// reflect their allocated bandwidth. Self Clocked Fair Queuing tries to
// schedule multiple queues such that each of them gets a fair share of the
// total bandwidth. This will prevent starvation of any flow and allow
// traffic to get predictable service.
//
// OMITTED_FEATURES :: Same as bellow
//
// ASSUMPTIONS :: The weight of a queue is assigned as,
// weight(i) = (( priority + 1) - i) / Sum_priority. Where Sum_priority is
// the sum of (priority + 1) of all queues. If there present 8 queues then
// "0" is assigned lowest priority and "7" is highest.
//
// STANDARD ::
// + http://www.cisco.com/warp/public/732/Tech/wfq/
// + www.cs.ucla.edu/classes/fall99/cs219/lectures/lecture991102.PDF
// + www.rennes.enst-bretagne.fr/~toutain/G6Recherche/Papier-LBSCFQ-lamti.PDF
// + www.cs.virginia.edu/~cs757/slidespdf/fairqueuing.pdf
// + http://www4.ncsu.edu:8030/~dsuryan/ece633/scheduler.html
// + http://teal.gmu.edu/~bmark/ece742/lslides_00/lect13.pdf
//
// RELATED :: N.A.
// **/


#ifndef SCH_SELF_CLOCKED_FAIR_H
#define SCH_SELF_CLOCKED_FAIR_H


#include "sch_fq.h"


#define SCFQ_DEBUG 0
#define SCFQ_DEBUG_WEIGHT 0


//---------------------------------------------------------------------------
// Self Clocked Fair Queue (SCFQ) Scheduler API
//---------------------------------------------------------------------------

// /**
// CLASS       :: ScfqScheduler
// DESCRIPTION :: Self Clocked Fair Queue (SCFQ) Scheduler Class
// **/

class ScfqScheduler : public FQScheduler
{
    protected:
        double CF;

    public:
      ScfqScheduler(BOOL enableSchedulerStat,
                   const char graphDataStr[]);

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

      virtual void finalize(Node* node,
                          const char* layer,
                          const int interfaceIndex,
                          const char* invokingProtocol = "IP",
                          const char* splStatStr = NULL);
};


#endif // SCH_SELF_CLOCKED_FAIR_H
