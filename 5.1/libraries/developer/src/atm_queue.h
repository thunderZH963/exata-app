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
// SUMMARY  :: Simulate RED as described in:
//             Sally Floyd and Van Jacobson,
//             "Random Early Detection For Congestion Avoidance",
//             IEEE/ACM Transactions on Networking, August 1993.
//
// NOTES    : This implementation only drops packets, it does not mark them.
//
//
// LAYER :: ATM_Layer2.
//
// STATISTICS :: Satistics are all printed w.r.t. Scheduler.
//
// CONFIG_PARAM ::
// + ATM-RED-MIN-THRESHOLD : int : The number of packets in the queue that
//                                 represents the lower bound at which
//                                 packets can be randomly dropped.
// + ATM-RED-MAX-THRESHOLD : int : The number of packets in the queue that
//                                 represents the upper bound at which
//                                 packets can be randomly dropped.
// + ATM-RED-MAX-PROBABILITY : double : The maximum probability (0...1) at
//                                 which a packet can be dropped (before
//                                 the queue is completely full, of course).
// + ATM-RED-SMALL-PACKET-TRANSMISSION-TIME: time : A sample amount of time
//                                 that it would take to transmit a small
//                                 packet - used to estimate the queue
//                                 average during idle periods..
//
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

// /**
// FILENAME: atm_queue.h
//
// PURPOSE:  Simulate RED as described in:
//           Sally Floyd and Van Jacobson,
//           "Random Early Detection For Congestion Avoidance",
//           IEEE/ACM Transactions on Networking, August 1993.
//
// NOTES:    This implementation only drops packets, it does not mark them.
// **/


#ifndef ATM_QUEUE_RED_H
#define ATM_QUEUE_RED_H

#include "if_queue.h"
#include "queue_red.h"


// /**
// CLASS       :: RedQueue
// DESCRIPTION :: This class is derived from Queue to Simulate RED Queue
// **/

class AtmRedQueue:public Queue
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

      BOOL RedMarkThePacket(BOOL* isBetweenMinthMaxth);

    public:

      virtual void SetupQueue(Node* node,
                              const char queueTypeString[],
                              const int queueSize,
                              const int interfaceIndex,
                              const int queueNumber,
                              const int infoFieldSize = 0,
                              const BOOL enableQueueStat = false,
                              const BOOL showQueueInGui = false,
                              const clocktype currentTime = 0,
                              const void* configInfo = NULL
#ifdef ADDON_DB
                              ,const char *queuePosition = NULL
#endif
                              , const clocktype maxPktAge = CLOCKTYPE_MAX
                              );

      virtual BOOL retrieve(Message** msg,
                            const int index,
                            const QueueOperation operation,
                            const clocktype currentTime);

      virtual void insert(Message* msg,
                          const void* infoField,
                          BOOL* QueueIsFull,
                          const clocktype currentTime);

      virtual void finalize(Node* node,
                            const char* layer,
                            const int interfaceIndex,
                            const int instanceId,
                            const char *invokingProtocol = "ATM-LAYER2",
                            const char* splStatStr = NULL);
};


// /**
// FUNCTION   :: ReadRedConfigurationParameters
// LAYER      :: ATM LAYER2
// PURPOSE    :: This function reads RED configuration parameters from
//               QualNet .config file
// PARAMETERS ::
// + node      :  Node* : The node Pointer
// + address   : const Address : Interface Address
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + enableQueueStat : BOOL : Tag for enabling Queue Statistics
// + queueIndex : int : Index of queue
// + redConfigParams :  Pointer of pointer to
//                      RedParameters Structure that keeps all configurable
//                      entries for RED Queue.
// RETURN     :: void : NULL
// NOTE:        This Function have layer dependency
//              because of existing QualNet IO's.
// **/

void ReadRedConfigurationParameters(Node* node,
                                    const Address address,
                                    const NodeInput* nodeInput,
                                    BOOL enableQueueStat,
                                    int queueIndex,
                                    RedParameters** redConfigParams);

#endif // ATM_QUEUE_RED_H

