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

#ifndef TRAFFIC_TRACE_H
#define TRAFFIC_TRACE_H

#include "random.h"
#include "util_dlb.h"
#include "sliding_win.h"

#include "types.h"

#define TRAFFIC_TRACE_SKIP_SRC_AND_DEST   3

#define TRAFFIC_TRACE_USAGE "traffic_trace_application ::= node_addr1\n" \
    "                                     node_addr2\n" \
    "                                     session_property\n" \
    "                                     traffic_property\n" \
    "                                     leaky_bucket_property\n" \
    "                                     [ qos_property " \
    "[session_retry_property]]\n" \
    "                                     [MDP-ENABLED " \
    "[MDP-PROFILE <profile name>] ]\n"


#define TRAFFIC_TRACE_CLIENT_SSIZE        (0.01 * SECOND)
#define TRAFFIC_TRACE_CLIENT_NSLOT        (100)
#define TRAFFIC_TRACE_CLIENT_WEIGHT       (0)

#define TRAFFIC_TRACE_SERVER_SSIZE        (0.01 * SECOND)
#define TRAFFIC_TRACE_SERVER_NSLOT        (100)
#define TRAFFIC_TRACE_SERVER_WEIGHT       (0)

#define TRAFFIC_TRACE_MAX_DATABYTE_SEND   0xFFFFFFFF

//#define TRAFFIC_TRACE_MAX_DATA_BLOCK_TO_READ 256
#define TRAFFIC_TRACE_MAX_DATA_BLOCK_TO_READ 16


// Data item structure
typedef
struct struct_traffic_trace_data
{
    clocktype   startTm;
    clocktype   endTm;
    short       sourcePort;
    Int32       seqNo;
    Int32       fragNo;
    Int32       totFrag;
    clocktype   txTime;
    Int32       mdpUniqueId;
    BOOL        isMdpEnabled;
} TrafficTraceData;


// Traffic types
typedef enum struct_traffic_trace_trf_type
{
    TRAFFIC_TRACE_TRF_TYPE_RND,
    TRAFFIC_TRACE_TRF_TYPE_TRC
} TrafficTraceTrfType;


// Structure for to collect some record from trace file
typedef struct struct_traffic_trace_trc_rec
{
    clocktype       interval;       // Interval for the next data
    clocktype       dataLen;        // Data length: the reason why the
                                    // type is
                                    // clocktype is to use the same random
                                    // distribution functions for the
                                    // interarrival time.
} TrafficTraceTrcRec;


typedef struct struct_traffic_trace_get_data_block
{
    TrafficTraceTrcRec*  trcRec;        // Traffic trace
    unsigned int         trcIdx;        // Trace index
    Int32                trcLen;        // Traffic trace length

    char   fileName[MAX_STRING_LENGTH];   // Trace file name
    Int32  lastFilePosition;              // Last position read
    UInt32 numElementRead;       // Traffic trace length
    BOOL   isNextScanedRequired;

} TrafficTraceGetDataBlock;


// Constraint factors for Quality of service
typedef struct struct_traffic_trace_qos_fact
{
    int bandwidth;   // Required QoS bandwidth
    int delay;       // Required QoS end-to-end delay
    TosType priority; // Priority given to a session
} TrafficTraceQosFact;


// Structure containing traffic trace client information.
typedef struct struct_traffic_trace_client_str
{
    // Two end nodes
    NodeAddress     localAddr;
    NodeAddress     remoteAddr;

    // Connection properties
    clocktype       startTm;        // Connection start time
    clocktype       endTm;          // Connection end time

    // Trace-based traffic properties
    TrafficTraceGetDataBlock dataBlock;

    // Dual leaky bucket parameters
    Dlb             dlb;            // Dual leaky bucket
    BOOL            isDlbDrp;       // is drop allowed by DLB?
    Int32           delayedData;    // Delayed data length
    clocktype       delayedIntv;    // Delayed interval
    Int32           dlbDrp;         // Number of data dropped by DLB

    // Qos property parameters
    BOOL                        isQosEnabled;    // is session demanded QoS
    TrafficTraceQosFact         qosConstraints;  // different constraints

    // Specifies connection retrying interval
    BOOL            isSessionAdmitted;        // is session request admitted
    BOOL            isRetryRequired;          // is session retry required
    clocktype       connectionRetryInterval;  // retry interval

    // Statistics
    TrafficTraceTrfType  trfType;        // Traffic type
    clocktype            lastSndTm;      // Last send time
    Int64                totByteSent;    // Total bytes sent
    Int32                totDataSent;    // Total number of data units sent
    MsTmWin              sndThru;        // Send throughput
    Int32                seqNo;          // Data sequence number
    Int32                fragNo;         // Fragmentation number
    Int32                totFrag;        // Total fragment
    short                sourcePort;     // Connection unique ID
    BOOL                 isClosed;       // Is connection closed?
    Int32                  mdpUniqueId;
    BOOL                   isMdpEnabled;
} TrafficTraceClient;


// Structure containing traffic trace related information.
typedef struct struct_traffic_trace_server_str
{
    // Two end nodes
    NodeAddress     localAddr;
    NodeAddress     remoteAddr;

    // Connection properties
    clocktype       startTm;
    clocktype       endTm;

    // Statistics
    clocktype       lastRcvTm;
    Int64           totByteRcvd;
    Int32           totDataRcvd;
    MsTmWin         rcvThru;
    clocktype       totDelay;
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
} TrafficTraceServer;


void TrafficTraceClientLayerRoutine(Node* nodePtr, Message* msg);

void TrafficTraceClientInit(
    Node* nodePtr,
    char* inputString,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    BOOL isDestMulticast,
    BOOL isMdpEnabled = FALSE,
    BOOL isProfileNameSet = FALSE,
    char* profileName = NULL,
    Int32 uniqueId = -1,
    const NodeInput* nodeInput = NULL);

void TrafficTraceClientFinalize(Node* nodePtr, AppInfo* appInfo);

void TrafficTraceServerLayerRoutine(Node* nodePtr, Message* msg);

void TrafficTraceServerInit(Node* nodePtr);

void TrafficTraceServerFinalize(Node* nodePtr, AppInfo* appInfo);

#endif /* TRAFFIC_TRACE_H */
