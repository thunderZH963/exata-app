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
// SUMMARY  ::  RED, Random Early Detection is an Active Queue Management
// (AQM) technique that detects incipient congestion and provides feedback
// to end hosts by dropping the packets. The motivation behind RED is to
// keep the queue size small, reduce burstiness and solve the problem of
// global synchronization. RED drops packets before the actual physical
// queue is full. It operates based on an average queue length that is
// calculated using an exponential weighted average of the instantaneous
// queue length. RED drops packets with certain probability depending on the
// average length of the queue. The drop probability increases from 0 to
// maximum drop probability (maxp) as average queue size increases from
// minimum threshold (minth) to maximum threshold (maxth). If average queue
// size goes above maxth, all packets are dropped.
//
// LAYER ::
//
// STATISTICS::
//
// CONFIG_PARAM ::
// + minThreshold : Mimimum threshold value
// + maxThreshold : Maximum threshold value
// + maxProbability : Maximum probability for dropping packets
// + queueWeight : Queue weight
// + typicalSmallPacketTransmissionTime : Small packet transmission time
//
// VALIDATION :: $QUALNET_HOME/verification/red
//
// IMPLEMENTED_FEATURES :: RED drops packets before the actual physical
// queue is full. It operates based on an average queue length that is
// calculated using an exponential weighted average of the instantaneous
// queue length. RED drops packets with certain probability depending on the
// average length of the queue. The drop probability increases from 0 to
// maximum drop probability (maxp) as average queue size increases from
// minimum threshold (minth) to maximum threshold (maxth). If average queue
// size goes above maxth, all packets are dropped.
//
// OMITTED_FEATURES :: None
//
// ASSUMPTIONS :: None
//
// STANDARD :: Simulate RED as described in:
// + Sally Floyd and Van Jacobson,
//   "Random Early Detection For Congestion Avoidance",
//   IEEE/ACM Transactions on Networking, August 1993.
//
// RELATED :: N.A.
// NOTES:    This implementation only drops packets, it does not mark them.
// **/

#ifndef QUEUE_RED_H
#define QUEUE_RED_H

#include "if_queue.h"


#define DEBUG_PLUG_N_PLAY   0
// /**
// CONSTANT    :: DEFAULT_RED_MIN_THRESHOLD : 5
// DESCRIPTION :: Denotes the default number of packets in the queue that
//                represents the lower bound at which packets can be
//                randomly dropped.
// **/

#define DEFAULT_RED_MIN_THRESHOLD     5
// /**
// CONSTANT    :: DEFAULT_RED_MAX_THRESHOLD : 15
// DESCRIPTION :: Denotes the default number of packets in the queue that
//                represents the upper bound at which packets can be
//                randomly dropped.
// **/

#define DEFAULT_RED_MAX_THRESHOLD     15
// /**
// CONSTANT    :: DEFAULT_RED_MAX_PROBABILITY : 0.02
// DESCRIPTION :: Default maximum probability (0...1) value at which a
//                packet can be dropped (before the queue is completely
//                full, of course).
// **/

#define DEFAULT_RED_MAX_PROBABILITY   0.02
// /**
// CONSTANT    :: DEFAULT_RED_QUEUE_WEIGHT : 0.002
// DESCRIPTION :: Default queue weight value used to determine the bias
//                towards recent or historical queue lengths in
//                calculating the average.
// **/

#define DEFAULT_RED_QUEUE_WEIGHT      0.002
// /**
// CONSTANT    :: DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME : 10ms
// DESCRIPTION :: Default sample amount of time to transmit a small packet.
//                Used to estimate the queue average during idle periods.
// **/

#define DEFAULT_RED_SMALL_PACKET_TRANSMISSION_TIME   (10 * MILLI_SECOND)

// /**
// STRUCT      :: RedParameters
// DESCRIPTION :: Structure used to keep all configurable
//                entries for RED Queue.
// **/
typedef struct
{
    int             minThreshold;
    int             maxThreshold;
    double          maxProbability;

    double          queueWeight;
    clocktype       typicalSmallPacketTransmissionTime;
} RedParameters;


// /**
// CLASS       :: RedQueue
// DESCRIPTION :: This class is derived from Queue to Simulate RED Queue
// **/
class RedQueue:public Queue
{
    protected:
      clocktype         startIdleTime; // Start of idle time
      double            averageQueueSize;

      RedParameters*    redParams;

      int               packetCount; // packet since last marked packet
      RandomSeed        randomDropSeed; // A random seed

      // Utility Functions
      void UpdateAverageQueueSize(const BOOL queueIsEmpty,
                                  const int numPackets,
                                  const double queueWeight,
                                  const clocktype smallPktTxTime,
                                  const clocktype startIdleTime,
                                  double* avgQueueSize,
                                  const clocktype theTime);

      BOOL RedDropThePacket();

    public:
      virtual void SetupQueue(Node* node,
                              const char queueTypeString[],
                              const int queueSize,
                              const int interfaceIndex,
                              const int queueNumber,
                              const int infoFieldSize = 0,
                              const BOOL enableQueueStat = FALSE,
                              const BOOL showQueueInGui = FALSE,
                              const clocktype currentTime = 0,
                              const void* configInfo = NULL
#ifdef ADDON_DB
                              ,const char* queuePosition = NULL
#endif
                              , const clocktype maxPktAge = CLOCKTYPE_MAX
#ifdef ADDON_BOEINGFCS
                              , const BOOL enablePerDscpStat = FALSE
                              ,Scheduler* repSched = NULL
                              ,Queue* repQueue = NULL
#endif
                              );

      virtual void insert(Message* msg,
                          const void* infoField,
                          BOOL* QueueIsFull,
                          const clocktype currentTime,
                          const double serviceTag = 0.0);

      virtual void insert(Message* msg,
                          const void* infoField,
                          BOOL* QueueIsFull,
                          const clocktype currentTime,
                          TosType* tos,
                          const double serviceTag = 0.0);


      virtual BOOL retrieve(Message** msg,
                            const int index,
                            const QueueOperation operation,
                            const clocktype currentTime,
                            double* serviceTag = NULL);

      virtual void finalize(Node* node,
                            const char* layer,
                            const int interfaceIndex,
                            const int instanceId,
                            const char* invokingProtocol = "IP",
                            const char* splStatStr = NULL);

#ifdef ADDON_BOEINGFCS
      virtual void signalCongestion(Node* node,
                                    int interfaceIndex,
                                    Message* msg);
#endif
};


// -------------------------------------------------------------------------
// Read and configure RedParameters
// -------------------------------------------------------------------------

//**
// FUNCTION   :: ReadRedConfigurationParameters
// LAYER      ::
// PURPOSE    :: This function reads RED configuration parameters from
//               QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + redConfigParams : RedParameters** : Pointer of pointer to
//                                       RedParameters Structure that keeps
//                                       all configurable entries for RED
//                                       Queue.
// RETURN     :: void : Null
// **/
void ReadRedConfigurationParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedParameters** redConfigParams);

#endif // QUEUE_RED_H

