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
// SUMMARY  :: RED, Random Early Detection is an Active Queue Management
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
// STATISTICS:: Same as red queue
//
// CONFIG_PARAM :: Same as red queue
//
// VALIDATION :: None
//
// IMPLEMENTED_FEATURES ::  This implementation only drops packets, it does
// mark them when ECN is enabled.
//
// OMITTED_FEATURES :: Same as red queue
//
// ASSUMPTIONS :: Same as red queue
//
// STANDARD :: Simulate RED as described in:
// + Sally Floyd and Van Jacobson,
//  "Random Early Detection For Congestion Avoidance",
//  IEEE/ACM Transactions on Networking, August 1993.
//
// RELATED ::
//
// NOTES:    This implementation only drops packets, it does mark them
//           when ECN is enabled
// **/

#ifndef QUEUE_RED_ECN_H
#define QUEUE_RED_ECN_H

#include "queue_red.h"

#include <map>

// /**
// CONSTANT    ::   INITIAL_NUM_PHB_ENTRIES : 3
// DESCRIPTION ::   This macro is used to specify number of initial
//                  phb for any block memmory allocation
// **/
#define INITIAL_NUM_PHB_ENTRIES 3


// /**
// STRUCT      :: RedStats
// DESCRIPTION :: Structure used to keep track of all phb specific
//                stats for RED variants.
// **/
typedef struct
{
    int numPacketsQueued;
    int numPacketsDequeued;
    int numPacketsDropped;
    int numBytesQueued;
    int numBytesDequeued;
    int numBytesDropped;

    // Number of IP datagrams that have been marked by ECN
    int numPacketsECNMarked;
} RedEcnStats;


// /**
// STRUCT      :: PhbParameters
// DESCRIPTION :: Structure used to keep track of all phb specific
//                entries for RED variants.
// **/
typedef struct
{
    unsigned int    ds;
    int             minThreshold;
    int             maxThreshold;
    double          maxProbability;

    // Statistics
    RedEcnStats*    stats;
} PhbParameters;


// /**
// STRUCT      :: RedParameters
// DESCRIPTION :: Structure used to keep all configurable
//                entries for RED variants.
// **/
typedef struct
{
    BOOL              isEcn;

    int               numPhbParams;
    int               maxPhbParams;
    PhbParameters*    phbParams;

    double            queueWeight;
    clocktype         typicalSmallPacketTransmissionTime;
} RedEcnParameters;


// /**
// CLASS       ::   EcnRedQueue
// DESCRIPTION ::   This class is derived from RedQueue to Simulate RED
//                  with ECN support.
// **/
class EcnRedQueue:public RedQueue
{
    private:
        std::map<UInt64, int> queue_profile;

    protected:
      int               numPacketsECNMarked;
      RedEcnParameters* redEcnParams;


      int GetTosFromMsgHeader(Message* msg);

      void SetCeBitInMsgHeader(Message* msg);

      PhbParameters* ReturnPhbForDs(const RedEcnParameters* red,
                                    const unsigned int ds,
                                    BOOL* wasFound);

      BOOL MarkThePacket(PhbParameters* phbParam,
                            double averageQueueSize,
                            int* packetCount,
                            BOOL* isBetweenMinthMaxth,
                            BOOL isECTset);

      void RedEcnQueueFinalize(Node* node,
                               const char* layer,
                               const char* intfIndexStr,
                               const int instanceId,
                               const RedEcnStats* stats,
                               const char* redVariantString,
                               const char* profileString);

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

      virtual int replicate(Queue* newQueue);

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
// Start: Read and configure Red
// -------------------------------------------------------------------------

//**
// FUNCTION   :: InitializeRedEcnStats
// LAYER      ::
// PURPOSE    :: Allocate memory for, and initialize statistics
// PARAMETERS ::
// + stats : RedEcnStats** : The pointer to Red Statistics structure
// RETURN :: void : Null
// **/

void InitializeRedEcnStats(RedEcnStats** stats);


//**
// FUNCTION   :: ReadRed_EcnCommonConfigurationParams
// LAYER      ::
// PURPOSE    :: This function reads configuration parameters from
//               QualNet .config file.[NOTE : This Function have layer
//               dependency (arg: interfaceAddress)]
//               because of existing QualNet IO's.]
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + red : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN :: void : Null
// **/
void ReadRed_EcnCommonConfigurationParams(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters* red);


//**
// FUNCTION   :: ReadRed_EcnConfigurationParameters
// LAYER      ::
// PURPOSE    :: This function reads Multilevel, ECN enabled RED
//               configuration parameters from QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + redEcnParams : RedEcnParameters** : Pointer of pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN :: void : Null
// **/
void ReadRed_EcnConfigurationParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RedEcnParameters** redEcnParams);

// -------------------------------------------------------------------------
// End: Read and configure Red
// -------------------------------------------------------------------------



#endif // QUEUE_RED_ECN_H

