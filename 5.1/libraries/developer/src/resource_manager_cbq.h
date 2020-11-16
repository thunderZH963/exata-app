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
// SUMMARY  :: Class Based Queue (CBQ) scheduling mechanism aims to provide
// link sharing between agencies that are using the same physical link & a
// framework to differentiate traffic that has different priorities. The
// main blocks for CBQ mechanism is: Classifier, Link-Sharing Scheduler,
// Packet Scheduler, Estimator. Each class has its own queue and is assigned
// its share of bandwidth. A child class can borrow bandwidth from its
// parent class as long as excess bandwidth is available.
//
// LAYER ::
//
// STATISTICS::
// + totalPkt : Total number packets queued
// + numDequeueReq : Total number of packets dequeue request
// + numDequeue : Total number of packets dequeued
// + numGPSDequeue : Total number of GPS dequeued
// + numLSSDequeue : Total number of LSS dequeued
// + numSuspended : Number of times Punished
// + maxExtradelay : Max Extradelay
// + totalExtradelay : Avgerage Extradelay
//
// CONFIG_PARAM ::
//
// VALIDATION :: None
//
// IMPLEMENTED_FEATURES :: Each class has its own queue and is assigned
// its share of bandwidth. A child class can borrow bandwidth from its
// parent class as long as excess bandwidth is available.
//
// OMITTED_FEATURES :: Same as bellow
//
// ASSUMPTIONS ::
// + We make the following assumptions about the link-sharing structure: the
//   root class is allocated 100% of the link bandwidth, and for each
//   non-leaf class, the sum of the bandwidth shares allocated to child
//   classes equals the bandwidth allocated to the class itself.Again we
//   assume that the agencies just below the ROOT must consist of all
//   non-leaf agencies.
// + The implementation of packet scheduler in CBQ is slightly different
//   from that described in the reference. This is because in the reference
//   there could be more than one queue with same priority value, but in
//   qualnet there could be only one queue with a priority value
//+ Leaf Classes or Agencies are leveled "1", if the TOP-LEVEL specified is
//  greater than maximum level in the link sharing structure, then it will
//  automatically search up to the ROOT level.
//
// STANDARD ::
// + 1."Link-sharing and Resource Management Models for Packet Networks"
//   by Sally Floyd and Van Jacobson. This paper appeared in IEEE/ACM
//   Transactions on Networking, Vol. 3 No. 4, August 1995
//   http://www-nrg.ee.lbl.gov/papers/link.pdf
// + 2."Quality of Service on Packet Switched Networks"
//   http://www.polito.it/~Risso/pubs/thesis.pdf
//
// RELATED ::
// **/

#ifndef RESOURCE_MANAGER_H
#define RESOURCE_MANAGER_H

#include "buffer.h"
#include "if_scheduler.h"


#define CBQ_DEBUG_LINK 0
#define CBQ_DEBUG      0


// /**
// CONSTANT    :: RM_FILTER_GAIN : 4
// DESCRIPTION :: Filter gain
// **/

#define RM_FILTER_GAIN 4

// /**
// CONSTANT    :: MAX_IDLE : 2.5
// DESCRIPTION :: The maximum avgidle value for the queue
// **/

#define MAX_IDLE 2.5

// /**
// CONSTANT    :: MIN_IDLE : 0
// DESCRIPTION :: The minimum avgidle value for the queue
// **/

#define MIN_IDLE 0

// /**
// STRUCT      :: ResourceManagerStat
// DESCRIPTION :: Structure for Statistics Collection
// **/

typedef struct Resource_manager_stat_str
{
    unsigned int    totalPkt;
    unsigned int    numDequeueReq;
    unsigned int    numDequeue;
    unsigned int    numGPSDequeue;
    unsigned int    numLSSDequeue;
    unsigned int    numSuspended;
    double          maxExtradelay;
    double          totalExtradelay;
} ResourceManagerStat;


// /**
// STRUCT      :: ResourceEstimator
// DESCRIPTION :: Structure for Agency behavior estimation
// **/

typedef struct resource_estimator_str
{
    clocktype lastServiceTime; // The time when the agency was last served
    double   timeToSend;      // The time when the queue will send a packet

    BOOL     isActive;        // Whether the agency is Active

    double   avgIdle;         // Average idle value for the queue
    double   prevAvgIdle;     // Prev average idle value
    double   maxAvgIdle;      // maximum average idle value for the agency

    unsigned int numPktToTransmit; // Number of packet to be transmitted
                                   // before suspension
    BOOL          suspend;      // Denotes the queue suspension
} ResourceEstimator;


// /**
// STRUCT      :: ResourceSharingNode
// DESCRIPTION :: Structure for an Agency in resource sharing structure
// **/

typedef struct resource_sharing_node_str
{
    BOOL     isAgency;        // Whether the node is an agency
    char*    agency;         // Name of the Agency
    float    weight;          // Weight for the Agency
    int      priority;    // Priority of the agency

    // CBQ Agencies can be deployed either as a non-work-conserving or
    // work-conserving.
    //
    // Non-work-conserving mode: a class (agency) that is currently exceeding
    //                           its rate is suspended for a certain amount
    //                           of time, even if the output link is idle
    //
    // Work-conserving mode    : when the parameter "BORROW" is set, the
    //                           specified agency is allowed to "BORROW"
    //                           bandwidth from its parent according to the
    //                           link sharing configuration.
    //
    // However there are some situations where this is not enough to
    // guarantee work conserving behaviour, basically because of the limit of
    // approximation of the link sharing guidelines. In this case the keyword
    // "EFFICIENT" triggers the departure of a packet from the first class
    // allowed to borrow even if it is overlimit. [2]

    BOOL            borrow;     // Is the agency is allowed to borrow
    BOOL            efficient;  // Is the agency is efficient
    DataBuffer      descendent; // Decendents of this agency

    ResourceEstimator*  estimator;

    struct resource_sharing_node_str* ancestor; // ancestor of this node
} ResourceSharingNode;


// /**
// CLASS  : CBQResourceManager
// PURPOSE: Class Based Queue (CBQ) Resource Manager Class
// **/

class CBQResourceManager : public Scheduler
{
    protected:
      Node*           nodeInfo;             // Node running cbq
      int             interfaceIndexInfo;   // Interface running cbq
      int             layerInfo;
      double          interfaceBW;          // The link BW at the interface
      double          weightFactor;         // Required for EWMA
      int             guideLineLevel;

      ResourceSharingNode* root;            // Link sharing sheduler graph

      DataBuffer      listAgency;           // List of agencies
      DataBuffer      listApplication;// List of end applications, basically
                                      // this is pointer to the leaf nodes
                                      // of the link sharing scheduler graph
                                      // which are distiguishable by the
                                      // queue they use for their priority
      Scheduler*      pktScheduler;

      BOOL                      statsCollected;
      ResourceManagerStat*      stats;

      // Utility Functions
      void ReadResourceSharingStr(const NodeInput lsrmInput);

      void DeleteResourceSharingGraph();

      void ActivateAgency(ResourceSharingNode* agency);

      void DeactivateAgency(ResourceSharingNode* agency);

      ResourceSharingNode* GetCurrentAgency(DataBuffer* agencyArray,
                                            char identity[]);

      ResourceSharingNode* GetApplicationByPriority(int priority);

      double FindFractionalBandWidth(ResourceSharingNode* agency);

      BOOL ResourceSharingEstimator(unsigned int pktSize,
                            ResourceSharingNode* cbqApplication,
                            const clocktype currentTime);

      BOOL AncestorOnlyGuideline(ResourceSharingNode* agencyInfo,
                                    const clocktype currentTime);

      BOOL TopLevelGuideline(ResourceSharingNode* agencyInfo,
                                    const clocktype currentTime);
      // Function Pointer
      typedef BOOL (CBQResourceManager::*ResourceSharingGuidelineType)(
                                        ResourceSharingNode* agency,
                                        const clocktype currentTime);

      ResourceSharingGuidelineType  resourceSharingGuidelineType;

    public:
      virtual ~CBQResourceManager();
      void Setup_ResourceManager(
                        Node* node,
                        NodeInput rsInput,
                        const int interfaceIndex,
                        const int layer,
                        const int interfaceBandwidth,
                        const char resrcMngrGuideLine[],
                        const int resrcMngrGuideLineLevel,
                        const char pktSchedulerTypeString[],
                        BOOL enablePktSchedulerStat,
                        BOOL enableStat,
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

      virtual BOOL isEmpty(const int priority);

      virtual int bytesInQueue(const int priority);

      virtual int numberInQueue(const int priority);

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

      void HandleProtocolEvent(int queueIndex);
};


// /**
// STRUCT      :: CBQResourceManagerInfo
// DESCRIPTION ::
// **/

typedef struct cbq_resource_manager_info_str
{
    CBQResourceManager* schPtr;
    unsigned int        index;
} CBQResourceManagerInfo;

//**
// FUNCTION   :: ReadCBQResourceManagerConfiguration
// LAYER      ::
// PURPOSE    :: Reads CBQ configuration parameters from .config file
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + interfaceAddress : const Address* : Interface Address
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + lsrmInput : NodeInput* : Resource sharing input
// + resrcMngrGuideLine : char* : Resource sharing guideline
// + resrcMngrGuideLineLevel : int* : Top-level limit
// + pktSchedulerString : char* : Packet scheduler Module
// RETURN     :: void : Null
// **/
void ReadCBQResourceManagerConfiguration(
    Node* node,
    int interfaceIndex,
    const NodeInput* nodeInput,
    NodeInput* lsrmInput,
    char* resrcMngrGuideLine,
    int* resrcMngrGuideLineLevel,
    char* pktSchedulerString);


//**
// FUNCTION   :: RESOURCE_MANAGER_Setup
// LAYER      ::
// PURPOSE    :: This function runs Resource Manager initialization routine
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + rsInput : NodeInput : Resource sharing structure input
// + interfaceIndex : const int : Interface index
// + layer : const int : The layer string
// + interfaceBandwidth : const int : Interface bandwidth
// + resrcMngr : CBQResourceManager** : Pointer of pointer to
//                                      CBQResourceManager structure
// + resrcMngrGuideLine[] : const char : String for resource manager
//                                       guideline
// + resrcMngrGuideLineLevel : const int : Resource manager guideline label
// + pktSchedulerTypeString[] : const char : Scheduler type string
// + enablePktSchedulerStat : BOOL : Packet scheduler statistics
// + enableStat : BOOL : Scheduler statistics
// + graphDataStr : const char* : Graph data string
// RETURN     :: void : Null
// **/
void RESOURCE_MANAGER_Setup(
    Node* node,
    NodeInput rsInput,
    const int interfaceIndex,
    const int layer,
    const int interfaceBandwidth,
    CBQResourceManager** resrcMngr,
    const char resrcMngrGuideLine[],
    const int resrcMngrGuideLineLevel,
    const char pktSchedulerTypeString[],
    BOOL enablePktSchedulerStat = FALSE,
    BOOL enableStat = FALSE,
    const char* graphDataStr = "NA");


//**
// FUNCTION   :: CBQResourceManagerHandleProtocolEvent
// LAYER      ::
// PURPOSE    :: Removes the suspension of queue and trigger dequeue request
//               Currently this function is called from ip.cpp
// PARAMETERS ::
// + node : Node* : Pointer to Node structure
// + msg : Message* : Pointer to Message structure
// RETURN     :: void : Null
// **/
void CBQResourceManagerHandleProtocolEvent(
    Node* node,
    Message* msg);

#endif // RESOURCE_MANAGER_H
