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

// This file contains simulation related definitions for TCP.

#ifndef _TCP_H_
#define _TCP_H_

#include "transport_tcp_hdr.h"
#include "transport_in_pcb.h"
#include "stats_transport.h"

// Connection opening and closing status, used in messages
// sent to application.
#define TCP_CONN_ACTIVE_OPEN            0
#define TCP_CONN_PASSIVE_OPEN           1
#define TCP_CONN_ACTIVE_CLOSE           0
#define TCP_CONN_PASSIVE_CLOSE          1

// Type of Tcp Variant //
typedef enum
{
    TCP_VARIANT_TAHOE,
    TCP_VARIANT_RENO,
    TCP_VARIANT_LITE,
    TCP_VARIANT_SACK,
    TCP_VARIANT_NEWRENO
} TcpVariantType;

// Type of Tcp Trace //
typedef enum
{
    TCP_TRACE_NONE,                 // no trace generated
    TCP_TRACE_PEEK,                 // deprecated, tcppeek
    TCP_TRACE_DEBUG,                // trace file format for internal use
    TCP_TRACE_DUMP,                 // tcpdump compatible binary format
    TCP_TRACE_DUMP_ASCII            // tcpdump compatible ascii format
} TcpTraceType;

// Type of Tcp Trace Direction //
typedef enum
{
    TCP_TRACE_DIRECTION_BOTH,       // trace segments in both directions
    TCP_TRACE_DIRECTION_OUTPUT,     // trace segments output to network
    TCP_TRACE_DIRECTION_INPUT       // trace segments input from network
} TcpTraceDirectionType;

// Don't push last block of write.
// If 1, do not push.
// If 0, push.
// moved here from tcp_config.h
#define TCP_NOPUSH  0

// Typedef TransportDataTcp;
struct TransportDataTcpStruct {
    struct inpcb head;          // head of queue of active inpcb's
    tcp_seq tcpIss;             // initial sequence number
    UInt32 tcpNow;       // current time in ticks, 1 tick = 500 ms
    BOOL tcpIsStarted;          // whether TCP timers are going
    BOOL tcpStatsEnabled;       // whether to collect stats
    struct tcpstat *tcpStat;    // statistics

    struct tcpcb *tp;           // to keep track of which tcpcb to use once
                                // tcp_output() is called after data is passed
                                // to the application layer
                                //

    TcpVariantType tcpVariant;  // TAHOE | RENO | LITE | SACK | NEWRENO
    TcpTraceType tcpTrace;      // NONE|TCPDUMP|TCPDUMP-ASCII
    TcpTraceDirectionType tcpTraceDirection;    // INPUT | OUTPUT | BOTH
    double tcpRandomDropPercent;// percent of packets to drop randomly

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
    UInt32 tcpSendBuffer;// Send buffer size
    UInt32 tcpRecvBuffer;// Receive buffer size
    BOOL nodeUseEcn;            // Whether Node ECN capable or not

    int verificationDropCount;  // Drop count for verification scenarios
    RandomSeed seed;            // Should be more than one.
                                // Used for jitter, timers, etc.

    STAT_TransportStatistics* newStats;
};

// Type of Tcp //
typedef enum
{
    TCP_REGULAR,
    TCP_ABSTRACT
} TcpType;

// /**
// FUNCTION   :: TransportTcpPrintTraceXML
// LAYER      :: TRANSPORT
// PURPOSE    :: Print out packet trace information in XML format
// PARAMETERS ::
// + node : Node* : Pointer to node, doing the packet trace
// + msg    : Message* : Pointer to tcp header to be printed
// RETURN ::  void : NULL
// **/

void TransportTcpPrintTraceXML(
    Node* node,
    Message* msg);


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpInit
// PURPOSE     Initialization function for TCP.
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------//
void TransportTcpInit(
    Node* node,
    const NodeInput* nodeInput);


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpLayer.
// PURPOSE     Models the behaviour of TCP on receiving the
//             message encapsulated in msgHdr
// Parameters:
//     node:     node which received the message
//     msgHdr:   message received by the layer
//-------------------------------------------------------------------------//
void TransportTcpLayer(
    Node *node,
    Message *msg);


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpFinalize
// PURPOSE     Called at the end of simulation to collect the results of
//             the simulation of the TCP protocol of Transport Layer.
// Parameter:
//     node:     node for which results are to be collected.
//-------------------------------------------------------------------------//
void TransportTcpFinalize(Node *node);

/*
 * FUNCTION    Tcp_HandleIcmpMessage
 * PURPOSE     Send the received ICMP Error Message to Application.
 * Parameters:
 *     node:      node sending the message to application layer
 *     msg:       message to be sent to application layer
 *     icmpType:  ICMP Message Type
 *     icmpCode:  ICMP Message Code
 */

void Tcp_HandleIcmpMessage (Node *node,
                            Message *msg,
                            unsigned short icmpType,
                            unsigned short icmpCode);


#endif // _TCP_H_ //


