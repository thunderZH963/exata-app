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
// PROTOCOL :: ATM
//
// SUMMARY  :: Atm Scheduler Functionalities.
//
// LAYER :: ATM_Layer2.
//
// STATISTICS ::

// + atmCellReceive : Total number of Atm Cell received at
//                    this interfaces.
// + atmCellInHdrError : Total number of Atm Cell discarded
//                       due to header error.
// + atmCellAddrError : Total number of Atm Cell discarded due
//                      to incorrect destination address.
// + atmCellForward : Total number of Atm Cell for which an
//                    attempt was made to forward
// + atmCellNoRoutes : Total number of Atm Cell discarded
//                     because no route could be found.
// + numControlCell : Total number of Control Cell received
// + numAtmCellInDelivers : Total number of Atm Cell delivered
//                          to upper layer.

// CONFIG_PARAM ::
// + ATM-SCHEDULER-STATISTICS : string : Print scheduler statistics.
//
// VALIDATION :: $QUALNET_HOME/verification/atm-ip.
//
// IMPLEMENTED_FEATURES ::
// + PACKET TYPE : Only Signaling and Unicast data payload are implemented.
// + NETWORK TYPE : Point to point ATM link are supported.
// + LINK TYPE : Wired.
// + FUNCTIONALITY : IP Protocol Data Units are carried over the ATM cloud
//                   through the Gateways.
//                 : Logical Subnet concept is introduced. At present,
//                   single Logical IP subnet is supported within ATM cloud,
//                 : Routing within the ATM clouds is done statically. Static
//                   route file is provided externally during configuration.
//                 : Virtual path setup process for each application is done
//                   dynamically, Various signaling messages are exchanged
//                   for setup virtual paths.
//                 : BW are reserved for each application.

//
// OMITTED_FEATURES ::
// +PACKET TYPE : Broadcast and multicast packets are not implemented.
// +ROUTE TYPE : Only static route within ATM cloud is implemented.
// + PNNI Routing is not implemented within ATM.
// + PVC is not implemented.

// ASSUMPTIONS ::
// + ATM is working as a backbone cloud to transfer the traffic i.e. all the
// IP clouds are connected to backbone ATM cloud & have a DEFAULT-GATEWAY,
//.acting as an entry/exit point to/from the ATM cloud.
// + all application requires a fixed BW, described as SAAL_DEFAULT_BW
// parameter.
// + All nodes in a single ATM cloud are part of the same Logical Subnet.
// + Every ATM end-system should have at least one interface connected to IP.

//
// STANDARD/RFC ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000

// **/


#ifndef SCH_ATM_H
#define SCH_ATM_H

#include "if_scheduler.h"


// /**
// CONSTANT    ::   ATM_SCH_DEBUG   : 0
// DESCRIPTION ::   Denotes for debuging ATM Scheduler.
// **/

#define ATM_SCH_DEBUG 0


// /**
// ATM Scheduler (Statistical Multiplexing) API
// **/


// /**
// STRUCT      :: AtmSchStat
// DESCRIPTION :: This structure contains statistics for this scheduler
// **/

typedef struct struct_atm_sch_stat
{
    unsigned int packetQueued; // Total packet queued
    unsigned int packetDequeued; // Total packet dequeued
    unsigned int packetDropped; // Total packet dropped
    unsigned int totalDequeueRequest;
} AtmSchStat;


// /**
// STRUCT      :: AtmPerQueueInfo
// DESCRIPTION :: This structure contains service count information
//                for for Queues under this scheduler
// **/

typedef struct struct_atm_info_str
{
    unsigned int    activeBW;       // active bandwidth for a queue (bits)
    unsigned int    weightCounter;  // weight Counter for a queue

} AtmPerQueueInfo;


// /**
// CLASS       :: AtmScheduler
// DESCRIPTION :: Atm Scheduler Class
// **/

class AtmScheduler : public Scheduler
{
    protected:
      int               totalBW;
      BOOL              isWeightAssigned;
      int               gcdInfo;         // GreatestCommonDivisor Info
      unsigned int      numCellInRound;
      int               queueIndexInfo;  // Queue selected for last dequeue
      AtmSchStat* stats;

      int CalGCD(int a, int b);

      void WeightAssignment();

      BOOL IsResetServiceRound();


      void AtmSchedulerSelectNextQueue(int index,
                                        int* queueIndex);

    public:
      AtmScheduler(BOOL enableSchedulerStat);
      virtual ~AtmScheduler();
      void AtmSetTotalBW(int bandwidth)
      {
          totalBW = bandwidth;
      }

      void PrintNumAtmCellEachQueque();
      BOOL AtmUpdateQueueSpecificBW(int queueIndex,
                                    int bandwidth,
                                    BOOL isAdd);

      virtual void insert(Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField, // Here it's NULL
                          const clocktype currentTime);

      virtual void insert(Message* msg,
                          BOOL* QueueIsFull,
                          const int queueIndex,
                          const void* infoField, // Here it's NULL
                          const clocktype currentTime,
                          TosType* tos)
      {
        //Tos is not reqd in ATM queue.Hence it is made a dummy function.
      };

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
                          TosType* tos)
      {
        //Tos is not reqd in ATM queue.Hence it is made a dummy function.
      };


      virtual BOOL retrieve(const int priority,
                            const int index,
                            Message** msg,
                            int* msgPriority,
                            const QueueOperation operation,
                            const clocktype currentTime);

      virtual int addQueue(Queue *queue,
                            const int priority,
                            const double weight);
      // Here weight carries BW of a particular queue.

      virtual void removeQueue(const int priority);

      virtual void swapQueue(Queue* queue, const int priority);

      virtual void finalize(Node* node,
                          const char* layer,
                          const int interfaceIndex,
                          const char *invokingProtocol = "ATM-LAYER2",
                          const char* splStatStr = NULL);

};

#endif // SCH_ATM_H

