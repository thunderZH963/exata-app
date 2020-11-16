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

// This file contains simulation related definitions for Abstract TCP.

#ifndef ABSTRACT_TCP_H
#define ABSTRACT_TCP_H

#include "transport_abstract_tcp_hdr.h"

// Connection opening and closing status, used in messages
// sent to application.
#define TCP_CONN_ACTIVE_OPEN            0
#define TCP_CONN_PASSIVE_OPEN           1
#define TCP_CONN_ACTIVE_CLOSE           0
#define TCP_CONN_PASSIVE_CLOSE          1


// Typedef TransportDataAbstractTcp;
struct TransportDataAbstractTcpStruct {
    struct abs_tcpcb* head;          // head of queue of active tcpcb's
    tcp_seq tcpIss;             // initial sequence number
    UInt32 tcpNow;              // current time in ticks, 1 tick = 500 ms
    BOOL tcpIsStarted;          // whether TCP timers are going
    BOOL tcpStatsEnabled;       // whether to collect stats
    struct tcpstat* tcpStat;    // statistics

    struct abs_tcpcb* tp;       // to keep track of which tcpcb to use once
                                // tcp_output() is called after data is passed
                                // to the application layer
                                //

    BOOL tcpUseKeepAliveProbes; // Keepalive option
                                // If TRUE, always send probes when keepalive
                                // timer times out.if FALSE, remain silent
                                // Default value is TRUE
                                //
    BOOL tcpUseRfc1323;         // Whether to include TCP Options defined
                                // in RFC 1323: window scaling and timestamp.
                                // If TRUE, include these options in tcp header
                                // If FALSE, do not include these options.
                                // Default value is FALSE
                                //
    BOOL tcpUseNagleAlgorithm;  // Nagle algorithm: delay send to coalesce
                                // packets. If TRUE, enable Nagle.
                                // If FALSE, disable Nagle.
                                // Default value is TRUE
                                //
    BOOL tcpUseOptions;         // Use TCP option.
                                // If FALSE, shouldn't include options in TCP
                                // header. If TRUE, options are allowed.
                                // Default value is TRUE
                                //
    BOOL tcpUsePush;            // Whether to add PUSH to last buffer blocks
                                // Does not apply to a FIN segment
                                // If FALSE, PUSH bit is not added
                                // If TRUE,  PUSH bit is used
                                // Default value is TRUE
                                //
    BOOL tcpDelayShortPackets;  // If FALSE, do not delay ACK if the received
                                // packet is a short packet.
                                // If TRUE, delay ACK for short packets.
                                // Default value is FALSE
                                //
    BOOL tcpDelayAcks;          // Whether to delay ACK
                                // If FALSE, do not delay ACK.
                                // If TRUE, delay ACK
                                // Default value is TRUE
                                //
    unsigned int tcpMss;        // Maximum segment size
    UInt32 tcpSendBuffer;       // Send buffer size
    UInt32 tcpRecvBuffer;       // Receive buffer size
    BOOL nodeUseEcn;            // Whether Node ECN capable or not
    int con_id;

    //Trace
    BOOL trace;                 // TCPDUMP-ASCII
    int traceDirection;         // INPUT | OUTPUT | BOTH
    double tcpRandomDropPercent;// percent of packets to drop randomly

    int verificationDropCount;  // Drop count for verification scenarios
    RandomSeed seed;            // Really should have more than one.
                                // Used for timers and jitter.
};

// For trace, Type of Tcp Trace Direction
typedef enum
{
    ABS_TCP_TRACE_DIRECTION_BOTH,       // trace segments in both directions
    ABS_TCP_TRACE_DIRECTION_OUTPUT,     // trace segments output to network
    ABS_TCP_TRACE_DIRECTION_INPUT       // trace segments input from network
} AbsTcpTraceDirectionType;



//-------------------------------------------------------------------------
// FUNCTION     TransportAbstractTcpTrace
// PURPOSE      Create a tcpdump compatible ascii trace output
//              This is created when user input is ABSTRACT-TCP-TRACE-ASCII
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------
void TransportAbstractTcpTrace(Node* node,
                               struct abs_tcpcb* tp,
                               struct abstract_tcphdr* ti,
                               int len);


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpInit
// PURPOSE     Initialization function for AbstractTCP.
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------
void TransportAbstractTcpInit(Node* node,
                              const NodeInput* nodeInput);


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpLayer.
// PURPOSE     Models the behaviour of AbstractTCP on receiving the
//             message encapsulated in msgHdr
// Parameters:
//     node:     node which received the message
//     msgHdr:   message received by the layer
//-------------------------------------------------------------------------
void TransportAbstractTcpLayer(Node* node,
                               Message* msg);


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpFinalize
// PURPOSE     Called at the end of simulation to collect the results of
//             the simulation of the AbstractTCP protocol of Transport Layer.
// Parameter:
//     node:     node for which results are to be collected.
//-------------------------------------------------------------------------
void TransportAbstractTcpFinalize(Node* node);

#endif // ABSTRACT_TCP_H
