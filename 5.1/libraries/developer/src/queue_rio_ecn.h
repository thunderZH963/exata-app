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
// SUMMARY  :: The IETF Differentiated Services Working Group has
// standardized the Assured Forwarding (AF) Per Hop Behavior (PHB). RFC
// 2597 recommends that an Active Queue Management (AQM) technique be used
// to realize the multiple levels of drop precedence required in the AF PHB.
// The most widely used AQM scheme is RE (Random Early Detection). RED
// variants are classified into 4 Categories SAST is simply plain RED.
// RED provides fairness by dropping packets according to the connection's
// share of the bandwidth. However, RED suffers from some fairness problem
// - it can't identify any preferentially or it cannot punish misbehaving
// users. There are several ways to extend RED to a Multilevel RED (MRED)
// algorithm suitable for the AF PHB that can identify any preferentially
// and can punish misbehaving users. SAMT and MAMT are different ways of
// implementing MRED. The value of the MAST variant of MRED is not as
// intuitive as SAMT or MAMT. SAMT is better known in the Internet community
// by the name WRED (Weighted RED). Two simple approaches to the MAMT
// variant of MRED are RIO-C (RED with In/Out and Coupled average Queues)
// and RIO-DC (RED with In/Out and Decoupled average Queues).
//
// LAYER ::
//
// STATISTICS:: Same as red queue
//
// CONFIG_PARAM :: Same as red queue
//
// VALIDATION :: N.A.
//
// IMPLEMENTED_FEATURES :: RED suffers from some fairness problem
// - it can't identify any preferentially or it cannot punish misbehaving
// users. There are several ways to extend RED to a Multilevel RED (MRED)
// algorithm suitable for the AF PHB that can identify any preferentially
// and can punish misbehaving users. SAMT and MAMT are different ways of
// implementing MRED. The value of the MAST variant of MRED is not as
// intuitive as SAMT or MAMT. SAMT is better known in the Internet community
// by the name WRED (Weighted RED). Two simple approaches to the MAMT
// variant of MRED are RIO-C (RED with In/Out and Coupled average Queues)
// and RIO-DC (RED with In/Out and Decoupled average Queues).
//
// OMITTED_FEATURES :: None
//
// ASSUMPTIONS :: None
//
// STANDARD ::
// + "EMPIRICAL STUDY OF BUFFER MANAGEMENT SCHEMES FOR
//   DIFFSERV ASSURED FORWARDING PHB"
// + www.sce.carleton.ca/faculty/lambadaris/recent-papers/162.pdf
//
// RELATED :: None
// **/


#ifndef QUEUE_RIO_ECN_H
#define QUEUE_RIO_ECN_H

#include "queue_wred_ecn.h"

#include <map>


#define RIO_DEBUG 0

// /**
// ENUM   :: RioCountingModeType
// DESCRIPTION :: Enum describing Counting Mode for RIO
// **/

typedef enum
{
    RIO_COUPLED, // RIO with Coupled virtual queue
    RIO_DECOUPLED // RIO with Decoupled virtual queue
} RioCountingModeType;


// /**
// ENUM     :: RioMarkingModeType
// DESCRIPTION :: Enum describing Color Marking Mode for RIO
// **/

typedef enum
{
    TWO_COLOR, // Two color marking
    THREE_COLOR // Three color marking
} RioMarkingModeType;


// /**
// STRUCT      :: RioParameters
// DESCRIPTION :: Structure used to keep all configurable
//                entries for RIO variants.
// **/

typedef struct
{
    RedEcnParameters* redEcnParams;

    // Coupled or Decoupled
    RioCountingModeType rioCountingType;

    // Two Color or Three Color
    RioMarkingModeType rioMarkerType;
} RioParameters;

// /**
// CLASS       :: EcnRioQueue
// DESCRIPTION :: This class is derived from RedQueue to Simulate RED
//                with ECN support.
// **/

class EcnRioQueue;


// /**
// FUNCTION POINTER  : RioReturnAvgQueueSizePtr
// PURPOSE           : Returns AverageQueueSize And PacketCountPtr.
// **/

typedef void (EcnRioQueue::*RioReturnAvgQueueSizePtr)(
                                  double* avgQueueSize,
                                  int** packetCount,
                                  const int dscp,
                                  const clocktype currentTime);
// /**
// FUNCTION POINTER  : RioUpdateEnqueueVar
// PURPOSE           : Update internal variables for enqueue
// **/

typedef void (EcnRioQueue::*RioUpdateEnqueueVar)(const int dscp);


// /**
// FUNCTION POINTER  : RioUpdateDequeueVar
// PURPOSE           : Update internal variables for dequeue
// **/

typedef void (EcnRioQueue::*RioUpdateDequeueVar)(
                            const int dscp,
                            const clocktype currentTime);



//
// EcnRioQueue Class
//
class EcnRioQueue:public EcnWredQueue
{
    private:
     std::map<UInt64, int> queue_profile;

    protected:
      RioParameters* rio;

      // Green profile variables
      unsigned int numGreenPackets;
      double averageGreenQueueSize;
      int    packetGreenCount;
      clocktype startGreenIdleTime;

      // Yellow profile variables
      unsigned int numYellowPackets;
      double averageYellowQueueSize;
      int packetYellowCount;
      clocktype startYellowIdleTime;

      // Red profile variables
      unsigned int numRedPackets;
      double averageRedQueueSize;
      int packetRedCount;
      clocktype startRedIdleTime;

      // Utility Functions for RIO-COUPLED
      void RioCoupledTCReturnAvgQSizePktCountPtr(double* avgQueueSize,
                                            int** packetCountPtr,
                                            const int dscp,
                                            const clocktype currentTime);

      void RioCoupledTCUpdIntVarForEnqueue(const int dscp);

      void RioCoupledTCUpdIntVarForDequeue(const int dscp,
                                        const clocktype currentTime);

      void RioCoupledThCReturnAvgQSizePktCountPtr(double* avgQueueSize,
                                            int** packetCountPtr,
                                            const int dscp,
                                            const clocktype currentTime);

      void RioCoupledThCUpdIntVarForEnqueue(const int dscp);

      void RioCoupledThCUpdIntVarForDequeue(const int dscp,
                                            const clocktype currentTime);

      // Utility Functions for RIO-DECOUPLED
      void RioDecoupledTCReturnAvgQSizePktCountPtr(double* avgQueueSize,
                                            int** packetCountPtr,
                                            const int dscp,
                                            const clocktype currentTime);

      void RioDecoupledTCUpdIntVarForEnqueue(const int dscp);

      void RioDecoupledTCUpdIntVarForDequeue(const int dscp,
                                            const clocktype currentTime);

      void RioDecoupledThCReturnAvgQSizePktCountPtr(double* avgQueueSize,
                                            int** packetCountPtr,
                                            const int dscp,
                                            const clocktype currentTime);

      void RioDecoupledThCUpdIntVarForEnqueue(const int dscp);

      void RioDecoupledThCUpdIntVarForDequeue(const int dscp,
                                            const clocktype currentTime);


      // Function pointers
      RioReturnAvgQueueSizePtr  rioReturnAvgQueueSizePtr;
      RioUpdateEnqueueVar       rioUpdateEnqueueVar;
      RioUpdateDequeueVar       rioUpdateDequeueVar;

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
                              ,const char *queuePosition = NULL
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

      virtual void finalize(Node *node,
                            const char* layer,
                            const int interfaceIndex,
                            const int instanceId,
                            const char* invokingProtocol = "IP",
                            const char* splStatStr = NULL);
};


// -------------------------------------------------------------------------
// Start: Read and configure RIO
// -------------------------------------------------------------------------

//**
// FUNCTION   :: ReadThreeColorMredPhbParameters
// LAYER      ::
// PURPOSE    :: Reads Three color MRED Threshold parameters from config
//               file
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int: Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + isCollectStats : const BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + mred : RedEcnParameters* : Pointer to
//                RedEcnParameters Structure that keeps all configurable
//                entries for ECN enabled Multilevel RED Queue.
// RETURN     :: void : Null
// **/

void ReadThreeColorMredPhbParameters(
        Node* node,
        int interfaceIndex,
        const NodeInput* nodeInput,
        const BOOL isCollectStats,
        int queueIndex,
        RedEcnParameters* mred);


//**
// FUNCTION   :: ReadRio_EcnConfigurationThParameters
// LAYER      ::
// PURPOSE    :: This function reads Two | Three color, ECN enabled RIO
//               configuration parameters from QualNet .config file.
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceIndex : int : Interface Index
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Queue Index
// + rioParams : RioParameters** : Pointer of pointer to
//                RioParameters Structure that keeps all configurable
//                entries for Two | Three color, ECN enabled RIO Queue.
// RETURN     :: void : Null
// **/
void ReadRio_EcnConfigurationThParameters(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    BOOL enableQueueStat,
    int queueIndex,
    RioParameters** rioParams);

// -------------------------------------------------------------------------
// End: Read and configure RIO
// -------------------------------------------------------------------------

#endif // QUEUE_RIO_ECN_H
