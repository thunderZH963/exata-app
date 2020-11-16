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


#ifndef TRAFFIC_GEN_H
#define TRAFFIC_GEN_H

#include "random.h"
#include "util_dlb.h"
#include "sliding_win.h"

#include "types.h"
#include "stats_app.h"

#define TRAFFIC_GEN_SKIP_SRC_AND_DEST   3

#ifdef MILITARY_RADIOS_LIB
#define TRAFFIC_GEN_NPG_USAGE   "traffic_gen_application ::= node_addr1\n" \
    "                                   node_addr2\n" \
    "                                   session_property\n" \
    "                                   traffic_property\n" \
    "                                   leaky_bucket_property\n" \
    "                                   ForwardMsgType <msgType>\n" \
    "                                   NPG <npgId>\n" \
    "                                   [FRAGMENT-SIZE]\n" \
    "                                   [ qos_property " \
    "[session_retry_property]]\n"
#endif

#define TRAFFIC_GEN_USAGE   "traffic_gen_application ::= node_addr1\n" \
    "                                   node_addr2\n" \
    "                                   session_property\n" \
    "                                   traffic_property\n" \
    "                                   leaky_bucket_property\n" \
    "                                   [FRAGMENT-SIZE]\n" \
    "                                   [ qos_property " \
    "[session_retry_property]]\n" \
    "                                   [MDP-ENABLED " \
    "[MDP-PROFILE <profile name>] ]\n"


#define TRAFFIC_GEN_CLIENT_SSIZE        (0.01 * SECOND)
#define TRAFFIC_GEN_CLIENT_NSLOT        (100)
#define TRAFFIC_GEN_CLIENT_WEIGHT       (0)

#define TRAFFIC_GEN_SERVER_SSIZE        (0.01 * SECOND)
#define TRAFFIC_GEN_SERVER_NSLOT        (100)
#define TRAFFIC_GEN_SERVER_WEIGHT       (0)
#define TRAFFIC_GEN_MAX_DATABYTE_SEND   TYPES_ToInt64(0x7fffffffffffffff)

//
// Data item structure used by Traffic Gen
//
typedef
struct struct_traffic_gen_data
{
    short       sourcePort;
    Int32       seqNo;
    Int32       fragNo;
    Int32       totFrag;
    clocktype   txTime;
    Int32       externalInterface; // -1 if none

    Int32       mdpUniqueId;
    BOOL        isMdpEnabled;

#ifdef MILITARY_RADIOS_LIB
    char            forwardMsgType;      //for gateway forwarding
    unsigned int    destNPGId;
#endif // MILITARY_RADIOS_LIB
    char type;
} TrafficGenData;


// Traffic types
typedef enum struct_traffic_gen_trf_type
{
    TRAFFIC_GEN_TRF_TYPE_RND
} TrafficGenTrfType;


// Constraint factors for Quality of service
typedef struct struct_traffic_gen_qos_fact
{
    int bandwidth;   // Required QoS bandwidth
    int delay;       // Required QoS end-to-end delay
    TosType priority;
} TrafficGenQosFact;


// Structure containing traffic gen client information.
typedef struct struct_traffic_gen_client
{
    // Two end nodes
    Address     localAddr;
    Address     remoteAddr;

    // Connection properties
    clocktype       startTm;        // Connection start time
    clocktype       endTm;          // Connection end time

    // Random dist. traffic properties
    RandomDistribution<UInt32>    dataSizeDistribution;    // Data length traffic gen dist.
    RandomDistribution<clocktype> intervalDistribution;    // Data interval traffic gen dist.
    RandomDistribution<double>    probabilityDistribution; // general probability distribution.
    double          genProb;        // Data generation probability

    // Dual leaky bucket parameters
    Dlb             dlb;            // Dual leaky bucket
    BOOL            isDlbDrp;       // is drop allowed by DLB?
    Int32           delayedData;    // Delayed data length
    clocktype       delayedIntv;    // Delayed interval
    Int32           dlbDrp;         // Number of data dropped by DLB

    // Quality of Service property parameters
    BOOL                isQosEnabled;       // is session demanded QoS
    TrafficGenQosFact   qosConstraints;     // different constraints

    // Specifies connection retrying interval
    BOOL            isSessionAdmitted;       // is session request admitted
    BOOL            isRetryRequired;         // is session retry required
    clocktype       connectionRetryInterval; // retry interval

    // Add the new parameter <npg id> here
#ifdef MILITARY_RADIOS_LIB
    unsigned short destNPGId;
    char        forwardMsgType;
#endif // MILITARY_RADIOS_LIB

    // Statistics
    TrafficGenTrfType      trfType;     // Traffic type
    clocktype              lastSndTm;   // Last send time
    Int64                  totByteSent; // Total bytes sent
    Int32                  totDataSent; // Total number of data units sent
    MsTmWin                sndThru;     // Send throughput
    Int32                  seqNo;       // Data sequence number
    Int32                  fragNo;      // Fragmentation number
    Int32                  totFrag;     // Total fragment
    short                  sourcePort;  // Connection unique ID
    BOOL                   isClosed;    // Is connection closed?
    Int32                  fragmentationSize; // per fragment size

    Int32                  mdpUniqueId;
    BOOL                   isMdpEnabled;
    std::string*           applicationName;
    Int32                  uniqueId;
    STAT_AppStatistics*    stats;

    // Dynamic Address
    NodeId destNodeId; // destination node id for this app session 
    Int16 clientInterfaceIndex; // client interface index for this app 
                                // session
    Int16 destInterfaceIndex; // destination interface index for this app
                              // session
    std::string* serverUrl;

    DestinationType destType;

} TrafficGenClient;

// Structure containing traffic gen related information.
typedef struct struct_traffic_gen_server
{
    // Two end nodes
    Address     localAddr;
    Address     remoteAddr;

    // Connection properties
    clocktype       startTm;
    clocktype       endTm;

    // Statistics
    clocktype       lastRcvTm;
    MsTmWin         rcvThru;
    Int32           seqNo;
    Int32           fragNo;
    Int32           totFrag;
    Int32           fragByte;
    clocktype       fragTm;
    short           sourcePort;
    BOOL            isClosed;

    clocktype       lastInterArrivalInterval;
    clocktype       lastPacketReceptionTime;
    clocktype       totalJitter;
#ifdef MILITARY_RADIOS_LIB
    short  forwardSrcPort;
#endif // MILITARY_RADIOS_LIB
    Int32           uniqueId; 
    STAT_AppStatistics* stats;
} TrafficGenServer;


void TrafficGenClientLayerRoutine(Node* nodePtr, Message* msg);

void TrafficGenClientInit(
    Node* nodePtr,
    char* inputString,
    const Address& localAddr,
    const Address& remoteAddr,
    DestinationType destType,
    char* appName,
    // dynamic address change
    char* destString,
    BOOL isMdpEnabled = FALSE,
    BOOL isProfileNameSet = FALSE,
    char* profileName = NULL,
    Int32 uniqueId = -1,
    const NodeInput* nodeInput = NULL);


void TrafficGenClientFinalize(Node* nodePtr, AppInfo* appInfo);

void TrafficGenInitTrace(Node* node, const NodeInput* nodeInput);

void TrafficGenPrintTraceXML(Node* node, Message* msg);

void TrafficGenServerLayerRoutine(Node* nodePtr, Message* msg);

void TrafficGenServerInit(Node* nodePtr);

void TrafficGenServerFinalize(Node* nodePtr, AppInfo* appInfo);

TrafficGenClient* TrafficGenClientGetClient(
    Node* node,
    NodeAddress destAddress);

void TrafficGenSendPacketInTadilNet(
    Node* node,
    NodeAddress srcAddr,
    unsigned short destNPGId,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    short sourcePort,
    int virtualPayloadSize,
    Message* origMsg = NULL,
    TrafficGenClient* clientPtr = NULL);

void TrafficGenSendPacket(
    Node* node,
    const Address& srcAddr,
    const Address& destAddr,
    const TrafficGenData* data,
    const char* payload,
    int realPayloadSize,
    short sourcePort,
    int virtualPayloadSize,
    TosType priority,
    int dataSize = 0,
    Message* origMsg = NULL,
    TrafficGenClient* clientPtr = NULL);

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppTrafficGenClientAddAddressInformation.
// PURPOSE              : store client interface index, destination 
//                        interface index destination node id to get the 
//                        correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : TrafficGenClient* : pointer to Traffic Gen
//                        client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppTrafficGenClientAddAddressInformation(Node* node,
                                  TrafficGenClient* clientPtr);

//---------------------------------------------------------------------------
// FUNCTION             : AppTrafficGenClientGetSessionAddressState.
// PURPOSE              : get the current address sate of client and server 
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : TrafficGenClient* : pointer to Traffic Gen
//                        client data
// RETRUN:
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if both client and server
//                                        are having valid address
//                        ADDRESS_INVALID : if either of them are in 
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppTrafficGenClientGetSessionAddressState(Node* node,
                                   TrafficGenClient* clientPtr);

// DNS
//--------------------------------------------------------------------------
// NAME:        : AppTrafficGenUrlSessionStartCallback.
// PURPOSE:     : Process Received DNS info.
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : unsigned short : source port
// + uniqueId   : Int32          : connection id; not used for CBR
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo : information required to 
//                                                 send buffered application 
//                                                 packets in case of UDP 
//                                                 based applications
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//--------------------------------------------------------------------------
bool
AppTrafficGenUrlSessionStartCallback(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    struct AppUdpPacketSendingInfo* packetSendingInfo);




#endif /* TRAFFIC_GEN_H */
