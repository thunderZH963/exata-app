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

// This file contains message processing for TCP.
// TCP follows Internet RFC 793.

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "network_ip.h"
#include "trace.h"
#include "transport_tcp.h"
#include "transport_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_tcp_var.h"
#include "transport_tcpip.h"
#include "transport_tcp_proto.h"
#include "transport_abstract_tcp.h"
#include "network_icmp.h"
#include "app_util.h"
#include "partition.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define TCP_TIMER_JITTER (1 * MILLI_SECOND)
#define TCP_FAST_TIMER_INTERVAL (200 * MILLI_SECOND)
#define TCP_SLOW_TIMER_INTERVAL (500 * MILLI_SECOND)

#define TCP_DEFAULT_MSS 512
#define TCP_DEFAULT_SEND_BUFFER 16384
#define TCP_DEFAULT_RECV_BUFFER 16384

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpUserConfigInit
// PURPOSE      Initialize user configuration variables
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
// RETURN       None
// ASSUMPTIONS: None
// NOTE         These variables were #defines in config.h
//-------------------------------------------------------------------------//
static
void TransportTcpUserConfigInit(
    Node *node,
    const NodeInput *nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    int anInt = 0;
    TransportDataTcp *tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;

    //
    // Initialize tcpDelayAcks for the node
    // Format is: TCP-DELAY-ACKS  YES | NO
    // If not specified, default is YES
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-DELAY-ACKS",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpDelayAcks = FALSE;
        }
           else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpDelayAcks = TRUE;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-DELAY-ACKS: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpDelayAcks = TRUE;
    }

    //
    // Initialize tcpDelayShortPackets for the node
    // Format is: TCP-DELAY-SHORT-PACKETS-ACKS  NO | YES
    // If not specified, default is NO
    // Was TCP_ACK_HACK in config.h
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-DELAY-SHORT-PACKETS-ACKS",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpDelayShortPackets = FALSE;
        }
           else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpDelayShortPackets = TRUE;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-DELAY-SHORT-PACKETS-ACKS: Unknown "
                "value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpDelayShortPackets = FALSE;
    }

    //
    // Initialize tcpUseNagleAlgorithm for the node
    // Format is: TCP-USE-NAGLE-ALGORITHM  YES | NO
    // If not specified, default is YES
    // Was TCP_NODELAY in config.h
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-USE-NAGLE-ALGORITHM",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpUseNagleAlgorithm = FALSE;
        }
           else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpUseNagleAlgorithm = TRUE;
        }
        else {
            ERROR_Assert(FALSE,
                 "TCP-USE-NAGLE-ALGORITHM: Unknown "
                 "value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpUseNagleAlgorithm = TRUE;
    }

    //
    // Initialize tcpUseKeepAliveProbes for the node
    // Format is: TCP-USE-KEEPALIVE-PROBES  YES | NO
    // If not specified, default is YES
    // Was TCP_ALWAYS_KEEPALIVE in config.h
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-USE-KEEPALIVE-PROBES",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpUseKeepAliveProbes = FALSE;
        }
           else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpUseKeepAliveProbes = TRUE;
        }
        else {
            ERROR_Assert(FALSE, "TCP-USE-KEEPALIVE-PROBES: "
                "Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpUseKeepAliveProbes = TRUE;
    }

    //
    // Initialize tcpUseOption for the node
    // Format is: TCP-USE-OPTIONS  YES | NO
    // If not specified, default is YES
    // Was TCP_NOOPT in config.h
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-USE-OPTIONS",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpUseOptions = FALSE;
        }
        else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpUseOptions = TRUE;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-USE-OPTIONS: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpUseOptions = TRUE;
    }

    //
    // Initialize tcpUsePush for the node
    // Format is: TCP-USE-PUSH  YES | NO
    // If not specified, default is YES
    // TCP_NOPUSH, specified in config.h, is ** NOT ** the same
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-USE-PUSH",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NO") == 0) {
            tcpLayer->tcpUsePush = FALSE;
        }
        else if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpUsePush = TRUE;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-USE-PUSH: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpUsePush = TRUE;
    }

    //
    // Initialize tcpSendBuffer for the node
    // Format is: TCP-SEND-BUFFER <value>
    // If not specified, default is 16384
    // NOTE: Actually data type of this variable is unsigned long but Qualnet
    //       has no kernal function to read long value from input file.
    // Was TCP_SENDSPACE in config.h
    //
    anInt = 0;
    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-SEND-BUFFER",
        &retVal,
        &anInt);

    if (retVal == TRUE && (anInt > 0)) {
        tcpLayer->tcpSendBuffer = (UInt32) anInt;
    }
    else {
        tcpLayer->tcpSendBuffer = TCP_DEFAULT_SEND_BUFFER;
    }

    //
    // Initialize tcpRecvBuffer for the node
    // Format is: TCP-RECEIVE-BUFFER <value>
    // If not specified, default is 16384
    // NOTE: Actually data type of this variable is unsigned long but Qualnet
    //       has no kernal function to read long value from input file.
    // Was TCP_RCVSPACE in config.h
    //
    anInt = 0;
    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-RECEIVE-BUFFER",
        &retVal,
        &anInt);

    if (retVal == TRUE && (anInt > 0)) {
        tcpLayer->tcpRecvBuffer = (UInt32) anInt;
    }
    else {
        tcpLayer->tcpRecvBuffer = TCP_DEFAULT_RECV_BUFFER;
    }

    //
    // Initialize tcpMss for the node
    // Format is: TCP-MSS <value>
    // If not specified, default is 512
    // Was TCP_MSS in config.h
    //
    anInt = 0;

    if (tcpLayer->tcpUseOptions == TRUE) {
        IO_ReadInt(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "TCP-MSS",
            &retVal,
            &anInt);

        if (retVal == TRUE && (anInt > 0)) {
            tcpLayer->tcpMss = (unsigned int) anInt;
        }
        else {
            tcpLayer->tcpMss = TCP_DEFAULT_MSS;
        }
    }
    else {
        tcpLayer->tcpMss = TCP_DEFAULT_MSS;
    }

    ERROR_Assert(
        tcpLayer->tcpMss >= TCP_MIN_MSS,
         "TCP-MSS: Value below minimum of 64.\n");

    ERROR_Assert(
        tcpLayer->tcpSendBuffer >= tcpLayer->tcpMss,
         "TCP-SEND-BUFFER: Value below MSS.\n");

    if (tcpLayer->tcpUseRfc1323)
    {
        ERROR_Assert(
            tcpLayer->tcpRecvBuffer <= (TCP_MAXWIN << TCP_MAX_WINSHIFT),
             "TCP-RECEIVE-BUFFER: "
             "Value exceeds what is permitted by RFC 1323.\n");
    }
    else
    {
        ERROR_Assert(
            tcpLayer->tcpRecvBuffer <= TCP_MAXWIN,
             "TCP-RECEIVE-BUFFER: Value exceeds permitted window size.\n");
    }
}


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpTraceInit
// PURPOSE     Initialized Trace variables for TCP.
// RETURN       None
// ASSUMPTIONS: None
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------//
static
void TransportTcpTraceInit(
    Node *node,
    const NodeInput *nodeInput)
{
    TransportDataTcp* tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    double aDropPercent;            // for random packet drops
    int aDropCount = 0;             // drop count for verification scenarios.

    //
    // Initialize trace values for the node
    // <TraceType> is one of
    //      NONE    the default if nothing is specified
    //      TCPDUMP a tcpdump compatible binary format
    //      TCPDUMP-ASCII a tcpdump compatible ascii format
    // Format is: TCP-TRACE  <TraceType>, for example
    //            TCP-TRACE TCPDUMP
    //            [4 thru 7] TCP-TRACE NONE
    // The additional DEBUG type is only for internal use.
    // Only one trace type can be used at a time during the entire simulation.
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-TRACE",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "NONE") == 0) {
            tcpLayer->tcpTrace = TCP_TRACE_NONE;
        }
        else if (strcmp(buf, "DEBUG") == 0) {
            tcpLayer->tcpTrace = TCP_TRACE_DEBUG;
        }
        else if (strcmp(buf, "TCPPEEK") == 0) {
            //tcpLayer->tcpTrace = TCP_TRACE_PEEK;
            ERROR_ReportError(
                "TCP-TRACE: TCPPEEK trace is deprecated.\n");
        }
        else if (strcmp(buf, "TCPDUMP") == 0) {
            tcpLayer->tcpTrace = TCP_TRACE_DUMP;
        }
        else if (strcmp(buf, "TCPDUMP-ASCII") == 0) {
            tcpLayer->tcpTrace = TCP_TRACE_DUMP_ASCII;
        }
        else {
            ERROR_ReportError(
                "TCP-TRACE: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpTrace = TCP_TRACE_NONE;
    }

    //
    // Initialize tcpTraceDirectionType values for the node
    // <TraceDirectionType> is one of
    //  BOTH      store both input & output packets in trace file
    //  OUTPUT    store only segments output to the network
    //  INPUT     trace only packets received from the network
    // Format is: TCP-TRACE-DIRECTION  BOTH | OUTPUT | INPUT
    // Default value is BOTH
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-TRACE-DIRECTION",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "OUTPUT") == 0) {
            tcpLayer->tcpTraceDirection = TCP_TRACE_DIRECTION_OUTPUT;
        }
        else if (strcmp(buf, "INPUT") == 0) {
            tcpLayer->tcpTraceDirection = TCP_TRACE_DIRECTION_INPUT;
        }
        else if (strcmp(buf, "BOTH") == 0) {
            tcpLayer->tcpTraceDirection = TCP_TRACE_DIRECTION_BOTH;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-TRACE-DIRECTION: Unknown value "
                "in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpTraceDirection = TCP_TRACE_DIRECTION_BOTH;
    }

    //
    // Initialize random drop percent for the node
    // Format is: TCP-RANDOM-DROP-PERCENT  <value>, for example
    //            [3]  TCP-RANDOM-DROP-PERCENT 10
    //            [1]  TCP-RANDOM-DROP-PERCENT 5
    // For an FTP transfer from node 1 to 3, this would drop
    //      10% data packets at node 3 and 5% acks at node 1
    // This option is for internal use
    //
    IO_ReadDouble(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-RANDOM-DROP-PERCENT",
        &retVal,
        &aDropPercent);

    if (retVal == TRUE) {
        if (aDropPercent >= 0.0 && aDropPercent <= 100.0) {
            tcpLayer->tcpRandomDropPercent = aDropPercent;
        }
        else {
            ERROR_Assert(FALSE,
                "TCP-RANDOM-DROP-PERCENT: "
                "Out of range value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpRandomDropPercent = 0.0;
    }

    //
    // Read drop count
    // Format is: TCP-VERIFICATION-DROP-COUNT  <value>
    // This option is for use with TCP verification scenarios
    // that test variant behavior with 0 to 4 drops.
    // Range for <value> is 0 to 4, default is 0

    tcpLayer->verificationDropCount = 0;
    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-VERIFICATION-DROP-COUNT",
        &retVal,
        &aDropCount);

    if (retVal == TRUE) {
        if (aDropCount >= 0 && aDropCount <= 4) {
            tcpLayer->verificationDropCount = aDropCount;
        }
        else {
            ERROR_ReportError(
                "TCP-VERIFICATION-DROP-COUNT: "
                "Valid range is 0 to 4.\n");
        }
    }

}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpEcnInit
// PURPOSE      Initialize ECN for TCP
// RETURN       None
// ASSUMPTIONS: None
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------//
static
void TransportTcpEcnInit(
    Node *node,
    const NodeInput *nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    TransportDataTcp *tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;

    //
    // Initialize ECN for the node
    // Format is: ECN  YES | NO, for example
    //            ECN YES
    //            [7 thru 10] ECN YES
    //            [11 13 15]  ECN NO
    // If not specified, default is NO
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ECN",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "YES") == 0) {
            tcpLayer->nodeUseEcn = TRUE;
        }
        else if (strcmp(buf, "NO") == 0) {
            tcpLayer->nodeUseEcn = FALSE;
        }
        else {
            ERROR_Assert(FALSE,
                "ECN: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->nodeUseEcn = FALSE;
    }

    if (tcpLayer->nodeUseEcn
        && node->networkData.networkProtocol == IPV6_ONLY)
    {
        ERROR_ReportError(
            "TransportTcpEcnInit: ECN not supported for IPv6.\n");
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     StartTimer
// PURPOSE      Called by any function when try to start a timer.
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------//
static //inline//
void StartTimer(
    Node* node,
    Message* reusedMsg,
    int timerType,
    clocktype timerDelay)
{
    clocktype ExtraJitterDelay;
    Message* msg = reusedMsg;
    TransportDataTcp* tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;

    if (msg == NULL) {
       msg = MESSAGE_Alloc(node,
           TRANSPORT_LAYER, TransportProtocol_TCP, timerType);
    }//if//

    ExtraJitterDelay  =
                (clocktype) (RANDOM_erand(tcpLayer->seed) * TCP_TIMER_JITTER);

    MESSAGE_Send(node, msg,  (timerDelay + ExtraJitterDelay));
}


//-------------------------------------------------------------------------//
// FUNCTION     StartTcpFastTimer
// PURPOSE      This Timer is called by TransportTcpLayer every 200 ms.
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------//
static //inline//
void StartTcpFastTimer(
    Node* node,
    Message* reusedMsg)
{
    StartTimer(
        node,
        reusedMsg,
        MSG_TRANSPORT_TCP_TIMER_FAST,
        TCP_FAST_TIMER_INTERVAL);
}


//-------------------------------------------------------------------------//
// FUNCTION     StartTcpSlowTimer
// PURPOSE      This Timer is called by TransportTcpLayer every 500 ms.
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------//
static //inline//
void StartTcpSlowTimer(
    Node* node,
    Message* reusedMsg)
{
    StartTimer(
        node,
        reusedMsg,
        MSG_TRANSPORT_TCP_TIMER_SLOW,
        TCP_SLOW_TIMER_INTERVAL);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpStart
// PURPOSE      Called the first time a simulation actually uses the TCP
//              model to start TCPSlowTimer and TCPFistTimer for first time.
// RETURN       None
// ASSUMPTIONS: None
// Parameter:
//     node:     node for which results are to be collected.
//-------------------------------------------------------------------------//
static
void TransportTcpStart(Node* node)
{
    TransportDataTcp* tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;
    tcpLayer->tcpIsStarted = TRUE;

    //
    // Initialize system timeouts.
    //
    StartTimer(
        node,
        NULL,
        MSG_TRANSPORT_TCP_TIMER_FAST,
        (clocktype)(TCP_FAST_TIMER_INTERVAL * RANDOM_erand(tcpLayer->seed)));

    StartTimer(
        node,
        NULL,
        MSG_TRANSPORT_TCP_TIMER_SLOW,
        (clocktype)(TCP_SLOW_TIMER_INTERVAL * RANDOM_erand(tcpLayer->seed)));
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackInit
// PURPOSE      Initializate sack variables
//              Called after tcpcb has been initialized for a connection
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
void TransportTcpSackInit(struct tcpcb *tp)
{
    tp->isSackFastRextOn = FALSE;
    tp->sackNextRext = tp->snd_una;
    tp->sackRcvHead = NULL;
    tp->sackSndHead = NULL;
    tp->sackRightEdgeMax = tp->snd_una;
    tp->sackFastRextSentry = tp->snd_una;
    tp->sackFastRextLimit = tp->snd_una;
    tp->sackFastRextWindow = 0;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackFreeSndList
// PURPOSE      Free memory used by list for saving information
//              that receiver has selectively acked
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpSackFreeSndList(struct tcpcb *tp)
{
    TcpSackItem *anItem = tp->sackSndHead;

    while (anItem != NULL) {
        tp->sackSndHead = anItem->next;
        MEM_free(anItem);
        anItem = tp->sackSndHead;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackFreeRcvList
// PURPOSE      Free memory used by receiver for saving information
//              about segments received out of order
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpSackFreeRcvList(struct tcpcb *tp)
{
    TcpSackItem *anItem = tp->sackRcvHead;

    while (anItem != NULL) {
        tp->sackRcvHead = anItem->next;
        MEM_free(anItem);
        anItem = tp->sackRcvHead;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackFreeLists
// PURPOSE      Free memory used by lists to save sack information
//              Called from tcp_close() when closing a connection
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
void TransportTcpSackFreeLists(struct tcpcb *tp)
{
    TransportTcpSackFreeSndList(tp);
    TransportTcpSackFreeRcvList(tp);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackBlockTotal
// PURPOSE      Utility function to determine total selective acks in list
// RETURN       The cumulative sum of acknowledged segments in the sack list
// ASSUMPTIONS  None.
// NOTE:        the sum is in bytes
//-------------------------------------------------------------------------//
static
int TransportTcpSackBlockTotal(struct tcpcb *tp)
{
    int aCount = 0;
    TcpSackItem *anItem = tp->sackSndHead;

    while (anItem != NULL) {
        aCount += anItem->rightEdge - anItem->leftEdge;
        anItem = anItem->next;
    }
    return aCount;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackReadOptions
// PURPOSE      Read TCPOPT_SACK related values from the options area of a
//              TCP header of an incoming segment. Forward each pair of
//              left edge/ right edge values for list addition
// RETURN       None
// ASSUMPTIONS  read values are sane wrt snd_una, etc
//-------------------------------------------------------------------------//
void TransportTcpSackReadOptions(
    struct tcpcb *tp,
    unsigned char *cp,
    int optlen)
{
    tcp_seq aLeftEdge;
    tcp_seq aRightEdge;
    int aCtr;

    ERROR_Assert(optlen % (2 * (sizeof(tcp_seq))) == 2,
                "TCPSackReadOption: Option not on even boundary.\n");

    //
    // Traverse option list backwards since first block in list will be first
    // block in the SndList -- it would not have mattered if the send list
    // were in ascending order
    //
    for (aCtr = optlen - 8; aCtr >= 2; aCtr -= 8) {
        memcpy(&aLeftEdge, &cp[aCtr], 4);
        memcpy(&aRightEdge, &cp[aCtr + 4], 4);
        TransportTcpSackAddToSndList(tp, aLeftEdge, aRightEdge);
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackAddToSndList
// PURPOSE      Add the left / right edge value to SndList.
//              The value is (one of) the selective ack by the receiver.
//              It could also be a segment that is retransmitted.
// RETURN       None
// ASSUMPTIONS  None
// NOTE:        The SndList is not in ascending order. The decision on
//              the optimal way waits for more tests and sack
//              behavior observations
//-------------------------------------------------------------------------//
void TransportTcpSackAddToSndList(
    struct tcpcb *tp,
    tcp_seq theLeftEdge,
    tcp_seq theRightEdge)
{
    TcpSackItem *aNewItem = NULL;
    TcpSackItem *anItem = NULL;
    TcpSackItem *aPrevItem = NULL;

    ERROR_Assert(SEQ_LT(theLeftEdge, theRightEdge),
        "TcpSackAddToSndList: left edge not less than right edge.\n");

    if (SEQ_LT(theLeftEdge, tp->snd_una)) {
        theLeftEdge = tp->snd_una;
    }

    if (SEQ_GT(theRightEdge, tp->snd_max)) {
        theRightEdge = tp->snd_max;
    }

    if (SEQ_GEQ(theLeftEdge, theRightEdge)) {
        return;
    }

    // add the new block to the head of the list
    aNewItem = (TcpSackItem *)MEM_malloc(sizeof(TcpSackItem));
    aNewItem->leftEdge = theLeftEdge;
    aNewItem->rightEdge = theRightEdge;
    aNewItem->next = tp->sackSndHead;
    tp->sackSndHead = aNewItem;

    if (SEQ_GT(theRightEdge, tp->sackRightEdgeMax)) {
        tp->sackRightEdgeMax = theRightEdge;
        tp->sackFastRextSentry = tp->sackRightEdgeMax;
    }

    // deflate the list to merge continguous/overlapping blocks
    aPrevItem = aNewItem;
    anItem = aPrevItem->next;

    while (anItem != NULL) {

        if (!( SEQ_LT(anItem->rightEdge, aNewItem->leftEdge)
                || SEQ_GT(anItem->leftEdge, aNewItem->rightEdge) )) {

            // anItem and aNewItem are not disjoint
            if (SEQ_LT(anItem->leftEdge, aNewItem->leftEdge)) {
                aNewItem->leftEdge = anItem->leftEdge;
            }
            if (SEQ_GT(anItem->rightEdge, aNewItem->rightEdge)) {
                aNewItem->rightEdge = anItem->rightEdge;
            }
            aPrevItem->next = anItem->next;
            MEM_free(anItem);
        }
        else {
            aPrevItem = anItem;
        }
        anItem = aPrevItem->next;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackUpdateNewSndUna
// PURPOSE      Update SndLst when snd_una moves.
//              Remove items blocks that are entirely to the left of snd_una.
// RETURN       None
// ASSUMPTIONS  None
// NOTE         It happens (should not though except when receiver reneges)
//              that snd_una falls in the middle of a previous sacked block.
//              In this case, shift edge of block to the una value;
//              retransmit will handle the anamoly
//-------------------------------------------------------------------------//
void TransportTcpSackUpdateNewSndUna(
    struct tcpcb *tp,
    tcp_seq theSndUna)
{
    TcpSackItem *anItem = NULL;
    TcpSackItem *aPrevItem = NULL;

    if (SEQ_GT(theSndUna, tp->sackRightEdgeMax)) {
        tp->sackRightEdgeMax = theSndUna;
        tp->sackFastRextSentry = theSndUna;
    }

    anItem = tp->sackSndHead;

    while (anItem != NULL) {
        if (SEQ_LEQ(anItem->rightEdge, theSndUna)) {
            if (tp->sackSndHead == anItem) {
                tp->sackSndHead = anItem->next;
                MEM_free(anItem);
                anItem = tp->sackSndHead;
            }
            else {
                aPrevItem->next = anItem->next;
                MEM_free(anItem);
                anItem = aPrevItem->next;
            }
        }
        else {
            if (SEQ_LEQ(anItem->leftEdge, theSndUna)) {
                anItem->leftEdge = theSndUna;
            }
            aPrevItem = anItem;
            anItem = anItem->next;
        }
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackNextRext
// PURPOSE      Look through SndLst for next item to retransmit
//              The SndLst contains items, in any order, of sacked data
//              Sets the left and right edges of theRextItem to the
//              closest hole to the right of sackNextRext
// PARAMETER    theRextItem : will hold left/right edge of rext on return
//              from the function
// RETURNS      TRUE if theRextItem has useful values (is to the left of the
//                  highest sacked block)
//              FALSE if SndList is empty, or retransmit is at or beyond
//                  the right of the highest sacked block
// ASSUMPTIONS  highest right edge for retransmit is snd_max
//-------------------------------------------------------------------------//
BOOL TransportTcpSackNextRext(
    struct tcpcb *tp,
    TcpSackItem *theRextItem)
{
    BOOL isAdjusted = FALSE;
    TcpSackItem *anItem = NULL;

    if (tp->sackSndHead == NULL) {
        return FALSE;
    }
    if (SEQ_GEQ(tp->sackNextRext, tp->sackRightEdgeMax)) {
        return FALSE;
    }

    // set sackNextRext to the right edge in case it is within a block
    anItem = tp->sackSndHead;

    while (anItem != NULL) {
        if (SEQ_GEQ(tp->sackNextRext, anItem->leftEdge)
                && SEQ_LT(tp->sackNextRext, anItem->rightEdge)) {
            tp->sackNextRext = anItem->rightEdge;
            break;
        }
        anItem = anItem->next;
    }

    if (SEQ_GEQ(tp->sackNextRext, tp->sackFastRextSentry)) {
        return isAdjusted;
    }
    theRextItem->leftEdge = tp->sackNextRext;

    // set right edge to the end of gap assuming snd_max is largest
    theRextItem->rightEdge = tp->snd_max;
    anItem = tp->sackSndHead;

    while (anItem != NULL) {
        if (SEQ_LT(tp->sackNextRext, anItem->leftEdge)) {
            if (SEQ_LEQ(anItem->rightEdge, theRextItem->rightEdge)) {
                theRextItem->rightEdge = anItem->leftEdge;
                isAdjusted = TRUE;
            }
        }
        anItem = anItem->next;
    }

    if (isAdjusted) {
        ERROR_Assert(SEQ_LT(theRextItem->leftEdge, tp->sackFastRextSentry)
            && SEQ_LT(theRextItem->rightEdge, tp->sackFastRextSentry),
            "SackNextRext: Wrong values in RextItem.\n");
    }
    return isAdjusted;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackRextTimeoutInit
// PURPOSE      Reinitialize sack variables during retransmit timeout
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
void TransportTcpSackRextTimeoutInit(struct tcpcb *tp)
{
    tp->isSackFastRextOn = FALSE;
    tp->sackNextRext = tp->snd_una;
    tp->sackRightEdgeMax = tp->snd_una;
    tp->sackFastRextSentry = tp->snd_una;
    tp->sackFastRextLimit = tp->snd_una;
    tp->sackFastRextWindow = 0;
    TransportTcpSackFreeSndList(tp);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackFastRextInit
// PURPOSE      Initialize sack variables at onset of fast retransmit
//              Differentiate (for flexibility) 3 values
//                  - the right edge of the highest sack block
//                  - the sentry point to which rext should occur
//                  - the sequence number whose ack marks end of fast rext
// RETURN       None
// ASSUMPTIONS  The point at which fast rext ends can be treated in many ways,
//              and the markers could be static or change
//              Currently, the sackRightEdgeMax and Sentry are dynamic and
//              follow new sack info in received acks after the onset of
//              of fast retransmit. The limit is the right edge of the
//              window at onset of fast rext
//-------------------------------------------------------------------------//
void TransportTcpSackFastRextInit(struct tcpcb *tp)
{
    ERROR_Assert(!tp->isSackFastRextOn,
        "TcpSackFastRextInit: called with fast rext on.\n");

    tp->isSackFastRextOn = TRUE;
    tp->sackFastRextSentry = tp->sackRightEdgeMax;
    tp->sackFastRextLimit = tp->snd_max;
    tp->sackFastRextWindow = tp->snd_max - tp->snd_una
                                - TransportTcpSackBlockTotal(tp);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackFastRextEnd
// PURPOSE      Reset sack variables at the end of fast retransmit
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
void TransportTcpSackFastRextEnd(struct tcpcb *tp)
{
    UInt32 anIncrement = tp->t_maxseg;

    ERROR_Assert(tp->isSackFastRextOn,
        "TcpSackFastRextEnd: called when fast rext is off.\n");

    tp->isSackFastRextOn = FALSE;
    tp->t_dupacks = 0;

    if (SEQ_LT(tp->snd_nxt, tp->sackFastRextLimit)) {
        tp->snd_nxt = tp->sackFastRextLimit;
    }
    tp->snd_cwnd = MIN(tp->snd_cwnd, tp->snd_ssthresh);

    if (tp->snd_cwnd > tp->snd_ssthresh) {
        anIncrement = anIncrement * anIncrement / tp->snd_cwnd;
    }
    tp->snd_cwnd = MIN(tp->snd_cwnd + anIncrement,
                        (UInt32)TCP_MAXWIN << tp->snd_scale);
    tp->sackFastRextWindow = 0;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackWriteOptions
// PURPOSE      Write sack values in the option field of the TCP header
//              of the segment being sent
// RETURN VALUE On return, cp contains the stuffed values, optlen in
//              incremented by the bytes added.
//              If the RcvList is empty, cp and optlen are unchanged
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
void TransportTcpSackWriteOptions(
    struct tcpcb *tp,
    unsigned char *cp,
    unsigned int *optlenPtr)
{
    TcpSackItem *anItem = NULL;
    tcp_seq aLeftEdge;
    tcp_seq aRightEdge;
    unsigned int anOptLen;
    unsigned int aPosition;
    unsigned int aCtr;
    unsigned int aMaxCount;

    if (tp->sackRcvHead == NULL) {
        return;
    }

    anOptLen = *optlenPtr;

    while (anOptLen % 4 != 2) {
        cp[anOptLen] = TCPOPT_NOP;
        anOptLen++;
    }

    cp[anOptLen] = TCPOPT_SACK;

    anItem = tp->sackRcvHead;
    aCtr = 0;
    aPosition = 2; // first block is initially two bytes ahead of anOptLen
    aMaxCount = (TCP_MAXOLEN - anOptLen - aPosition) / 8;

    while (aCtr < aMaxCount && anItem != NULL) {
        aLeftEdge = anItem->leftEdge;
        memcpy(cp + aPosition + anOptLen, &aLeftEdge, 4);
        aPosition += 4;
        aRightEdge = anItem->rightEdge;
        memcpy(cp + aPosition  + anOptLen, &aRightEdge, 4);
        aPosition += 4;
        aCtr++;
        anItem = anItem->next;
    }
    cp[anOptLen + 1] = (unsigned char) aPosition;
    anOptLen += aPosition;
    *optlenPtr = anOptLen;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackAddToRcvList
// PURPOSE      Add the left & right edges of the received segment to RcvList
//              if it is out of sequence
//              The newly block will always be at the head of the list.
//              The list is deflated to merge overlapping items
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
void TransportTcpSackAddToRcvList(
    struct tcpcb *tp,
    tcp_seq theLeftEdge,
    tcp_seq theRightEdge)
{
    TcpSackItem *aNewItem = NULL;
    TcpSackItem *anItem = NULL;
    TcpSackItem *aPrevItem = NULL;

    ERROR_Assert(tp->t_state >= TCPS_ESTABLISHED,
        "TcpSackAddToRcvList: called without connection established.\n");

    if (SEQ_GEQ(theLeftEdge, theRightEdge)) {
        return;
    }

    // add a new block to the head of the list
    aNewItem = (TcpSackItem *)MEM_malloc(sizeof(TcpSackItem));
    aNewItem->leftEdge = theLeftEdge;
    aNewItem->rightEdge = theRightEdge;
    aNewItem->next = tp->sackRcvHead;
    tp->sackRcvHead = aNewItem;

    // deflate the list to merge continguous/overlapping blocks
    aPrevItem = aNewItem;
    anItem = aPrevItem->next;

    while (anItem != NULL) {
        if (!( SEQ_LT(anItem->rightEdge, aNewItem->leftEdge)
                || SEQ_GT(anItem->leftEdge, aNewItem->rightEdge) )) {
            if (SEQ_LT(anItem->leftEdge, aNewItem->leftEdge)) {
                aNewItem->leftEdge = anItem->leftEdge;
            }
            if (SEQ_GT(anItem->rightEdge, aNewItem->rightEdge)) {
                aNewItem->rightEdge = anItem->rightEdge;
            }
            aPrevItem->next = anItem->next;
            MEM_free(anItem);
        }
        else {
            aPrevItem = anItem;
        }
        anItem = aPrevItem->next;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSackUpdateNewRcvNxt
// PURPOSE      Update RcvList when rcv_nxt moves.
//              Remove items blocks that are entirely to the left of rcv_nxt
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
void TransportTcpSackUpdateNewRcvNxt(
    struct tcpcb *tp,
    tcp_seq theRcvNxt)
{
    TcpSackItem *anItem = NULL;
    TcpSackItem *aPrevItem = NULL;

    ERROR_Assert(tp->t_state >= TCPS_ESTABLISHED,
        "TcpSackUpdateNewRcvNxt: called without connection established.\n");

    anItem = tp->sackRcvHead;

    while (anItem != NULL) {
        if (SEQ_LEQ(anItem->rightEdge, theRcvNxt)) {
            if ((anItem == tp->sackRcvHead)) {
                tp->sackRcvHead = anItem->next;
                MEM_free(anItem);
                anItem = tp->sackRcvHead;
            }
            else {
                aPrevItem->next = anItem->next;
                MEM_free(anItem);
                anItem = aPrevItem->next;
            }
        }
        else {
            if (SEQ_LEQ(anItem->leftEdge, theRcvNxt)) {
                anItem->leftEdge = theRcvNxt;
            }
            aPrevItem = anItem;
            anItem = anItem->next;
        }
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceCheckDirection
// PURPOSE      Compare between theMsg and the user specification, which is
//              store in tcpTraceDirection variable in tcp structure.
// RETURN       BOOL
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
BOOL TransportTcpTraceCheckDirection(
    Node *node,
    const char *theMsg)
{
    TcpTraceDirectionType atcpTraceDirection = ((TransportDataTcp *)
                              node->transportData.tcp)->tcpTraceDirection;

    if (!strcmp(theMsg, "input")) {
        if (atcpTraceDirection == TCP_TRACE_DIRECTION_BOTH
                || atcpTraceDirection == TCP_TRACE_DIRECTION_INPUT) {
            return TRUE;
        }
    }

    if (!strcmp(theMsg, "output")) {
        if (atcpTraceDirection == TCP_TRACE_DIRECTION_BOTH
                || atcpTraceDirection == TCP_TRACE_DIRECTION_OUTPUT) {
            return TRUE;
        }
    }
    return FALSE;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugIpHeader
// PURPOSE      Write IP pseudo header to the debug trace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugIpHeader(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    char anAddrStr[MAX_STRING_LENGTH];

    fprintf(fp,"+===============+===============+\n");
    IO_ConvertIpAddressToString(&ti->ti_src, anAddrStr);
    fprintf(fp,"      %s\n", anAddrStr);
    fprintf(fp,"+---------------+---------------+\n");
    IO_ConvertIpAddressToString(&ti->ti_dst, anAddrStr);
    fprintf(fp,"      %s\n", anAddrStr);
    fprintf(fp,"+-------+-------+---------------+\n");
    fprintf(fp,"        ");
    fprintf(fp," %7u ",ti->ti_pr);
    fprintf(fp,"%15u\n",ti->ti_len);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugTcpHeader
// PURPOSE      Write the TCP header to the debug trace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugTcpHeader(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    fprintf(fp,"+===============+===============+\n");
    fprintf(fp," %15u %15u\n",ti->ti_sport,ti->ti_dport);
    fprintf(fp,"+---------------+---------------+\n");
    fprintf(fp,"           %10u\n",ti->ti_seq);
    fprintf(fp,"+-------------------------------+\n");
    fprintf(fp,"           %10u\n",ti->ti_ack);
    fprintf(fp,"+---+-----+-----+---------------+\n");
    fprintf(fp," %-2u ",tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off) << 2);
    fprintf(fp,"      ");
    fprintf(fp,"%u",(unsigned char)ti->ti_flags
                    & (unsigned char)TH_CWR ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_ECE ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_URG ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_ACK ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_PUSH ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_RST ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_SYN ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_FIN ? 1 : 0);
    fprintf(fp," %15u\n",ti->ti_win);
    fprintf(fp,"+---------------+---------------+\n");
    fprintf(fp," %15u %15u\n",ti->ti_sum,ti->ti_urp);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugOptions
// PURPOSE      Write options field to the debug trace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugOptions(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    int optionLength;
    unsigned char *optionPtr = NULL;
    int anOpt, anOptLen, aCtr;
    tcp_seq anEdge;
    unsigned short anMss;
    UInt32 aTimeStamp;

    optionLength = ((int)tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off) << 2)
        - sizeof(struct tcphdr);

    if (optionLength == 0) {
        return;
    }
    optionPtr = (unsigned char *)ti + sizeof(struct tcpiphdr);

    aCtr = 0;

    while (aCtr < optionLength)
    {
        if (aCtr % 4 == 0) {
            fprintf(fp,"+:::::::+:::::::+:::::::+:::::::+\n");
        }

        anOpt = optionPtr[aCtr];

        switch (anOpt) {

        case TCPOPT_EOL:
            aCtr += 1;
            fprintf(fp,"%8u", anOpt);
            if (aCtr % 4 == 0) {
                fprintf(fp,"\n");
            }
            break;

        case TCPOPT_NOP:
            fprintf(fp,"%8u", anOpt);
            aCtr += 1;
            if (aCtr % 4 == 0) {
                fprintf(fp,"\n");
            }
            break;

        case TCPOPT_SACK_PERMITTED:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp,"%8u%8u", anOpt, anOptLen);
            aCtr += 2;
            if (aCtr % 4 == 0) {
                fprintf(fp,"\n");
            }
            break;

        case TCPOPT_SACK:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp,"%8u%8u\n", anOpt, anOptLen); //assume right edge
            aCtr += 2;
            anOptLen -=2;
            while (anOptLen) {
                memcpy(&anEdge, optionPtr + aCtr, 4);
                fprintf(fp,"%31u\n", anEdge);
                anOptLen -= 4;
                aCtr += 4;
            }
            break;

        case TCPOPT_MAXSEG:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp, "%8u%8u", anOpt, anOptLen);
            aCtr += 2;
            if (aCtr % 4 == 0) {
                fprintf(fp, "\n");
            }
            memcpy(&anMss, optionPtr + aCtr, 2);
            fprintf(fp, "%16u", anMss);
            aCtr += 2;
            if (aCtr % 4 == 0) {
                fprintf(fp, "\n");
            }
            break;

        case TCPOPT_WINDOW:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp, "%8u%8u", anOpt, anOptLen);
            aCtr += 2;
            if (aCtr % 4 == 0) {
                fprintf(fp, "\n");
            }
            fprintf(fp, "%8u", optionPtr[aCtr]);
            aCtr++;
            if (aCtr % 4 == 0) {
                fprintf(fp, "\n");
            }
            break;

        case TCPOPT_TIMESTAMP:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp, "%8u%8u", anOpt, anOptLen);
            aCtr += 2;
            if (aCtr % 4 == 0) {
                fprintf(fp, "\n");
            }
            memcpy(&aTimeStamp, optionPtr + aCtr, 4);
            fprintf(fp, "%32u", aTimeStamp);
            aCtr += 4;
            fprintf(fp, "\n");
            memcpy(&aTimeStamp, optionPtr + aCtr, 4);
            fprintf(fp, "%32u", aTimeStamp);
            fprintf(fp, "\n");
            aCtr += 4;
            break;
        default:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp, "Unknown option\n");
            aCtr += anOptLen;
        }
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugTcpcb
// PURPOSE      Write some variables of interest to debug trace file
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugTcpcb(Node *node, struct tcpcb *tp, FILE *fp)
{
    fprintf(fp,"+...............................+\n");
    fprintf(fp,"+  send sequence variables      +\n");
    fprintf(fp,"+  snd_una = %15u    +\n",tp->snd_una);
    fprintf(fp,"+  snd_nxt = %15u    +\n",tp->snd_nxt);
    fprintf(fp,"+  snd_max = %15u    +\n",tp->snd_max);
//    fprintf(fp,"+  snd_up  = %15u    +\n",tp->snd_up);
//    fprintf(fp,"+  snd_w11 = %15u    +\n",tp->snd_wl1);
//    fprintf(fp,"+  snd_w12 = %15u    +\n",tp->snd_wl2);
//    fprintf(fp,"+  iss     = %15u    +\n",tp->iss);
//    fprintf(fp,"+  snd_wnd = %15u    +\n",tp->snd_wnd);
//    fprintf(fp,"+  nxtRext = %15u    +\n",tp->sackNextRext);
    fprintf(fp,"+...............................+\n");
    fprintf(fp,"+  receive sequence variables   +\n");
    fprintf(fp,"+  rcv_nxt = %15u    +\n",tp->rcv_nxt);
//    fprintf(fp,"+  rcv_wnd = %15u    +\n",tp->rcv_wnd);
//    fprintf(fp,"+  rcv_up  = %15u    +\n",tp->rcv_up);
//    fprintf(fp,"+  irs     = %15u    +\n",tp->irs);
    fprintf(fp,"+...............................+\n");
    fprintf(fp,"+  congestion control           +\n");
    fprintf(fp,"+  snd_cwnd= %15u    +\n",tp->snd_cwnd);
    fprintf(fp,"+  snd_ssthresh= %11u    +\n",tp->snd_ssthresh);
    fprintf(fp,"+  t_rtt   = %15u    +\n",tp->t_rtt);
    fprintf(fp,"+  t_rxtcur= %15u    +\n",tp->t_rxtcur);
//    fprintf(fp,"+  t_rxtshift= %13u    +\n",tp->t_rxtshift);
    fprintf(fp,"+  t_timer[xt]= %12u    +\n",tp->t_timer[TCPT_REXMT]);
    fprintf(fp,"+  t_dupacks= %14u    +\n",tp->t_dupacks);
//    fprintf(fp,"+  t_tcpVariant= %11u    +\n",tp->tcpVariant);
    fprintf(fp,"+...............................+\n");
    fprintf(fp,"+  isConnectionEcnCapable= %u    +\n",
                                                tp->t_ecnFlags & TF_ECN);
    fprintf(fp,"+...............................+\n");
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugRcvList
// PURPOSE      Print RcvList for debug purposes
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugRcvList(struct tcpcb *tp, FILE *fp)
{
    TcpSackItem *anItem = tp->sackRcvHead;

    while (anItem != NULL) {
        fprintf(fp, "left=%8u    right=%8u\n", anItem->leftEdge,
                anItem->rightEdge);
        anItem = anItem->next;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugSndList
// PURPOSE      Print SndList for debug purposes
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugSndList(struct tcpcb *tp, FILE *fp)
{
    TcpSackItem *anItem = tp->sackSndHead;

    while (anItem != NULL) {
        fprintf(fp, "left=%8u -- right=%8u\n", anItem->leftEdge,
                anItem->rightEdge);
        anItem = anItem->next;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebugNextRext
// PURPOSE      Print select set of variables during retransmit to debug trace
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebugNextRext(
    Node *node,
    struct tcpcb *tp,
    FILE *fp)
{
    fprintf(fp,"+...............................+\n");
    fprintf(fp,"+  retransmit variables         +\n");
    fprintf(fp,"+  snd_una = %15u    +\n",tp->snd_una);
    fprintf(fp,"+  snd_nxt = %15u    +\n",tp->snd_nxt);
    fprintf(fp,"+  snd_max = %15u    +\n",tp->snd_max);
    fprintf(fp,"+  nxtRext = %15u    +\n",tp->sackNextRext);
    fprintf(fp,"+...............................+\n");
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDebug
// PURPOSE      Single function called to write to the trace file tcptrace.out
//              Can be tweaked to print one or more of the pseudo-header,
//                  TCP header, options, data, state variables, control flow
//                  message
//              Currently, prints all of the segment header if theMsg
//                  parameter is "input" or "output"
//              By default, prints theMsg as is, if it anything else.
//              In this case, the tp/ti parameters can be 0
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDebug(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg)
{
    static UInt32 aCount=0;
    FILE *fp = NULL;
    char clockStr[MAX_STRING_LENGTH];

    if (aCount == 0) {
        fp = fopen("tcptrace.out", "w");
        ERROR_Assert(fp != NULL,
            "TcpTraceDebug: file open error.\n");
        fclose(fp);
    }

    fp = fopen("tcptrace.out", "a");
    ERROR_Assert(fp != NULL,
        "TcpTraceDebug: file open error.\n");

    aCount++;

    // change this to use TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
//    ctoa(node->getNodeTime(), clockStr);
    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

    if (TransportTcpTraceCheckDirection(node, theMsg)) {
            fprintf(fp, "\n");
            fprintf(fp, "Serial# [ %12u ]\n", aCount);
            fprintf(fp, "Time    [ %12s ]\n", clockStr);
            fprintf(fp, "Node    [ %5u ] %s\n", node->nodeId, theMsg);
            TransportTcpTraceDebugIpHeader(node, ti, fp);
            TransportTcpTraceDebugTcpHeader(node, ti, fp);
            TransportTcpTraceDebugOptions(node, ti, fp);

            if (ti->ti_len > (short)
                (tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off) << 2))
            {
                fprintf(fp,"+-------+-------+-------+-------+\n");
                fprintf(fp,"data...\n");
            }
            fprintf(fp,"+===============+===============+\n\n");
    }
    else if (!strcmp(theMsg, "random drop")) {
        // when testing of sack by dropping of random segments
        fprintf(fp, "\nA segment was dropped randomly at %d\n",
                                                        node->nodeId);
        aCount--;
    }
    else if (!strcmp(theMsg, "packet drop for ECN")) {
        // when testing of sack by dropping of random segments
        fprintf(fp, "\nA segment was dropped for ECN testing at %d\n",
            node->nodeId);
        aCount--;
    }
    else if (!strcmp(theMsg, "EcnEcho")) {
        // when testing of ecn checks EcnEcho bit is set or not
        fprintf(fp, "\n## EcnEcho bit is set at %d\n", node->nodeId);
        aCount--;
    }
    else if (!strcmp(theMsg, "CWR")) {
        // when testing of ecn checks CWR bit is set or not
        fprintf(fp, "\n** CWR bit is set at %d\n", node->nodeId);
        aCount--;
    }
    else if (!strcmp(theMsg, "CwndReduced")) {
        // when testing of ecn checks CWR bit is set or not
        fprintf(fp, "\nCC Congestion Window Reduced and it set at"
            " node = %d and snd_cwnd = %d\n", node->nodeId, tp->snd_cwnd);
        aCount--;
    }
    else if (!strcmp(theMsg, "ssthreshReduced")) {
        // when testing of ecn checks CWR bit is set or not
        fprintf(fp, "\nSS ssthresh Reduced and it set at"
            " node = %d and snd_ssthresh = %d\n",
            node->nodeId, tp->snd_ssthresh);
        aCount--;
    }
    else if (!strcmp(theMsg, "ECT")) {
        // when testing of ecn checks CWR bit is set or not
        fprintf(fp, "\n ECT bit is set inside ipHeader\n");
        aCount--;
    }

/*
    else if (!strcmp(theMsg, "sndList")
            && tp->t_state >= TCPS_ESTABLISHED
            && TCP_VARIANT_IS_SACK(tp)) {
        // debug print of the SndList
        TransportTcpTraceDebugSndList(tp, fp);
        aCount--;
    }

    else if (!strcmp(theMsg, "rcvList")
            && tp->t_state >= TCPS_ESTABLISHED
            && TCP_VARIANT_IS_SACK(tp)) {
        // debug print of the RcvList
        TransportTcpTraceDebugRcvList(tp, fp);
        aCount--;
    }

    else if (!strcmp(theMsg, "sackLeftEdge")) {
        // when sack has adjusted snd_nxt
        fprintf(fp, "Sack: snd_nxt moved right\n");
        aCount--;
    }

    else if (!strcmp(theMsg, "sackRightEdge")) {
        // when sack may adjust rext length
        fprintf(fp, "Sack: length may adjust\n");
        aCount--;
    }

    else if (!strcmp(theMsg, "NextRext")) {
        // debug print of the NextRext
        TransportTcpTraceDebugNextRext(node, tp, fp);
        aCount--;
    }
*/
    else if (!strcmp(theMsg, "variables")) {
        // debug print of the selected variables related to
        // snd, rcv, congestion, rtt, timers
        TransportTcpTraceDebugTcpcb(node, tp, fp);
        aCount--;
    }
/*
    else {
        // to print as-is any other message passed
        fprintf(fp, "%s\n", theMsg);
        aCount--;
    }
*/
    else {
        aCount--;
    }
    fclose(fp);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTracePeekIpHeader
// PURPOSE      Write IP pseudo header to the TcpPeek trace file
// ASSUMPTIONS  None.
// NOTES        TcpPeek is deprecated.
//-------------------------------------------------------------------------//
/*
static
void TransportTcpTracePeekIpHeader(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    fprintf(fp,"%ld,",ti->ti_src);
    fprintf(fp,"%ld,",ti->ti_dst);
    fprintf(fp,"%u,",ti->ti_pr);
    fprintf(fp,"%u,",ti->ti_len);
}
*/

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTracePeekTcpHeader
// PURPOSE      Write the TCP header to the TcpPeek trace file
// ASSUMPTIONS  None.
// NOTES        TcpPeek is deprecated.
//-------------------------------------------------------------------------//
/*
static
void TransportTcpTracePeekTcpHeader(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    fprintf(fp,"%u,%u,",ti->ti_sport,ti->ti_dport);
    fprintf(fp,"%lu,",ti->ti_seq);
    fprintf(fp,"%lu,",ti->ti_ack);
    fprintf(fp,"%u,",ti->ti_off << 2);
    fprintf(fp,"%u",ti->ti_flags & TH_URG ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_ACK ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_PUSH ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_RST ? 1 : 0);
    fprintf(fp,"%u",ti->ti_flags & TH_SYN ? 1 : 0);
    fprintf(fp,"%u,",ti->ti_flags & TH_FIN ? 1 : 0);
    fprintf(fp,"%u,",ti->ti_win);
    fprintf(fp,"%u,%u,",ti->ti_sum,ti->ti_urp);
}
*/

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTracePeekOptions
// PURPOSE      Write TCP options field to the Java dump trace file
// ASSUMPTIONS  None.
// NOTES        TcpPeek is deprecated.
//-------------------------------------------------------------------------//
/*
static
void TransportTcpTracePeekOptions(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    unsigned char *optionPtr = NULL;
    int aCtr;
    int optionLength = ((int)(ti->ti_off) << 2) - sizeof(struct tcphdr);

    if (optionLength == 0) {
        return;
    }
    optionPtr = (unsigned char *)ti + sizeof(struct tcpiphdr);

    for (aCtr = 0; aCtr < optionLength; aCtr++) {
        fprintf(fp, "%u,", *(optionPtr + aCtr));
    }
}
*/

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTracePeekData
// PURPOSE      Write the TCP data to the TcpPeek trace file
// ASSUMPTIONS  None.
// NOTES        TcpPeek is deprecated.
//-------------------------------------------------------------------------//
/*
static
void TransportTcpTracePeekData(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    int aDataLength;
    unsigned char *aDataPtr = NULL;
    int aCtr = (int)((ti->ti_off) << 2);

    aDataLength = ti->ti_len - aCtr;
    aDataPtr = (unsigned char *)ti + aCtr;

    for (aCtr = 0; aCtr < aDataLength; aCtr++) {
        fprintf(fp,"%x%x",((((*(aDataPtr + aCtr)) & 255) >> 4)),
                                      ((*(aDataPtr + aCtr)) & 15));
    }
}
*/

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTracePeek
// PURPOSE      Create a trace output called tcptrace.out suitable for
//                  use with TcpPeek
//              This is created when user input is TCP-TRACE YES
// RETURN       None
// ASSUMPTIONS  None.
// NOTES        TcpPeek is deprecated.
//-------------------------------------------------------------------------//
/*
static
void TransportTcpTracePeek(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    char *theMsg)
{
    static UInt32 aCount=0;
    FILE *fp= NULL;
    char clockStr[MAX_STRING_LENGTH];

    TcpTraceWithDataType aTraceWithDataType = ((TransportDataTcp *)
                             node->transportData.tcp)->tcpTraceWithData;

    if (aCount == 0) {
        fp = fopen("tcptrace.out", "w");
        ERROR_Assert(fp != NULL,
            "TcpTracePeek: file open error.\n");
        fclose(fp);
    }
    fp = fopen("tcptrace.out", "a");
    ERROR_Assert(fp != NULL,
        "TcpTracePeek: file open error.\n");

    aCount++;
    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
    fprintf(fp, "%lu,", aCount);
    fprintf(fp, "%s,", clockStr);
    fprintf(fp, "%u,", node->nodeId);
    TransportTcpTracePeekIpHeader(node, ti, fp);
    TransportTcpTracePeekTcpHeader(node, ti, fp);
    TransportTcpTracePeekOptions(node, ti, fp);

    if (aTraceWithDataType) {
        TransportTcpTracePeekData(node, ti, fp);
    }
    fprintf(fp, "\n");
    fclose(fp);
}
*/

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceConvertTimeToHMS
// PURPOSE      Convert string of sceond to H:M:S format
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceConvertTimeToHMS(
    char *timeString,
    FILE *fp)
{
    int anIndex = 0;
    int aNum = 0;
    int secStr = 0;
    int minStr = 0;
    int hrStr = 0;
    char aChar = timeString[anIndex++];

    while (aChar != '.') {
         aNum *= 10;
         aNum = aNum + (aChar - '0');
         aChar = timeString[anIndex++];
    }
    secStr = aNum % 60;
    aNum = aNum / 60;
    minStr = aNum % 60;
    hrStr = aNum / 60;
    fprintf(fp,"%d:%d:%d",hrStr,minStr,secStr);
    fprintf(fp,"%s ",(timeString + anIndex - 1));
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceConvertIntIPToDotIP
// PURPOSE      Convert decimal IP address to dot IP address
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceConvertIntIPToDotIP(
    UInt32 anIPAddress,
    FILE *fp)
{
    fprintf(fp, "%d.%d.%d.%d",
        (anIPAddress & 0xff000000) >> 24,
        (anIPAddress & 0xff0000) >> 16,
        (anIPAddress & 0xff00) >> 8,
        (anIPAddress & 0xff));
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpaIpTcpHeader
// PURPOSE      Write IP pseudo header and Tcp Header to tcpTrace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDumpaIpTcpHeader(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    char anAddrStr[MAX_STRING_LENGTH];
    int aFlag = 0;
    int aLen = ti->ti_len -
        (tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off) << 2);

    IO_ConvertIpAddressToString(&ti->ti_src, anAddrStr);
    fprintf(fp, "%s", anAddrStr);
    fprintf(fp,".");
    fprintf(fp,"%u > ",ti->ti_sport);
    IO_ConvertIpAddressToString(&ti->ti_dst, anAddrStr);
    fprintf(fp, "%s", anAddrStr);
    fprintf(fp,".");
    fprintf(fp,"%u: ",ti->ti_dport);

    if (ti->ti_flags & TH_SYN) {
        fprintf(fp,"S");
        aFlag = 1;
    }
    if (ti->ti_flags & TH_FIN) {
        fprintf(fp,"F");
        aFlag = 1;
    }
    if (ti->ti_flags & TH_PUSH) {
        fprintf(fp,"P");
        aFlag = 1;
    }
    if (ti->ti_flags & TH_RST) {
        fprintf(fp,"R");
        aFlag = 1;
    }
    if (!aFlag) {
        fprintf(fp,".");
    }
    fprintf(fp," ");

    if (aLen) {
        fprintf(fp,"%u:",ti->ti_seq);
        fprintf(fp,"%u",(ti->ti_seq + aLen));
        fprintf(fp,"(%u) ",aLen);
    }
    if (ti->ti_flags & TH_ACK) {
        fprintf(fp,"ack ");
        fprintf(fp,"%u ",ti->ti_ack);
    }
    fprintf(fp,"win %u ",ti->ti_win);
    if (ti->ti_flags & TH_URG) {
        fprintf(fp,"urg %u ", ti->ti_urp);
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpaOptions
// PURPOSE      Write TCP options field to the TcpDump ASCII trace file
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDumpaOptions(
    Node *node,
    struct tcpiphdr *ti,
    FILE *fp)
{
    int anOpt;
    int anOptLen;
    int aCtr = 0;
    int aFlag = 0;
    unsigned char *optionPtr = NULL;
    tcp_seq anEdge;
    unsigned short *aMss = NULL;
    UInt32 *aValue = NULL;
    int optionLength = ((int)
        (tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off)) << 2)
        - sizeof(struct tcphdr);

    if (optionLength == 0) {
        return;
    }
    optionPtr = (unsigned char *)ti + sizeof(struct tcpiphdr);
    fprintf(fp,"<");

    while (aCtr < optionLength)
    {
        anOpt = optionPtr[aCtr];

        if (aCtr != 0 && aFlag) {
            fprintf(fp,",");
        }
        aFlag = 1;

        switch (anOpt) {

        case TCPOPT_NOP:
            aCtr += 1;
            fprintf(fp, "nop");
            break;

        case TCPOPT_MAXSEG:
            aCtr += 2;
            aMss = (unsigned short *)(optionPtr + aCtr);
            fprintf(fp, "mss %d", *aMss);
            aCtr += 2;
            break;

        case TCPOPT_WINDOW:
            aCtr += 2;
            fprintf(fp,"wscale %d", optionPtr[aCtr]);
            aCtr += 1;
            break;

        case TCPOPT_TIMESTAMP:
            aCtr += 2;
            aValue = (UInt32 *) (optionPtr + aCtr);
            fprintf(fp,"timestamp %u ", *aValue++);
            fprintf(fp,"%u", *aValue);
            aCtr += 8;
            break;

        case TCPOPT_SACK_PERMITTED:
            fprintf(fp,"sackOK");
            aCtr += 2;
            break;

        case TCPOPT_SACK:
            anOptLen = optionPtr[aCtr+1];
            fprintf(fp,"sack"); //assume right edge
            aCtr += 2;
            anOptLen -= 2;
            while (anOptLen) {
                memcpy(&anEdge, optionPtr + aCtr, 4);
                fprintf(fp," %u", anEdge);
                anOptLen -= 4;
                aCtr += 4;
            }
            break;

        default:
            aCtr += 1;
            aFlag = 0;
        }
    }
    fprintf(fp,">");
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpAscii
// PURPOSE      Create a tcpdump compatible ascii trace output
//              This is created when user input is TCP-TRACE TCPDUMP-ASCII
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDumpAscii(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg)
{
    static UInt32 aCount=0;
    FILE *fp = NULL;
    char clockStr[MAX_STRING_LENGTH];

    if (aCount == 0) {
        fp = fopen("tcptrace.asc", "w");
        ERROR_Assert(fp != NULL,
            "TcpTraceDumpAscii: file open error.\n");
        fclose(fp);
    }
    fp = fopen("tcptrace.asc", "a");
    ERROR_Assert(fp != NULL,
        "TcpTraceDumpAscii: file open error.\n");

    aCount++;
    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
    TransportTcpTraceConvertTimeToHMS(clockStr, fp);
    TransportTcpTraceDumpaIpTcpHeader(node, ti, fp);
    TransportTcpTraceDumpaOptions(node, ti, fp);
    fprintf(fp, "\n");
    fclose(fp);
    return;
}


//-------------------------------------------------------------------------//
// FUNCTION     qn_htons and qn_htonl
// PURPOSE      A q&d substitute for htons and htonl
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//

static
unsigned short qn_htons(unsigned short theValue)
{
    unsigned short aResult = theValue;
#ifdef LITTLE_ENDIAN
    aResult = (unsigned short) (((aResult & 0x00ff) << 8) | ((aResult & 0xff00) >> 8));
#endif
    return aResult;
}

static
unsigned int qn_htoni(unsigned int theValue)
{
    unsigned int aResult = theValue;
#ifdef LITTLE_ENDIAN
    aResult =
        ((unsigned int)qn_htons(
            (unsigned short)(aResult & 0x0000ffff)) << 16)
        | (unsigned int)qn_htons(
            (unsigned short)((aResult & 0xffff0000) >> 16));
#endif
    return aResult;
}

static
UInt32 qn_htonl(UInt32 theValue)
{
    UInt32 aResult = theValue;
#ifdef LITTLE_ENDIAN
    aResult = ((UInt32)qn_htons(
            (unsigned short)(aResult & 0x0000ffff)) << 16)
        | (UInt32)qn_htons(
            (unsigned short)((aResult & 0xffff0000) >> 16));
#endif
    return aResult;
}


#define MAC_HEADER_LEN          14
#define IPv4_HEADER_LEN         20
#define IPv6_HEADER_LEN         40
#define IPv4_TCPDUMP_LENGTH_MAX 94
#define IPv6_TCPDUMP_LENGTH_MAX 114

static
time_t TransportTcpTraceGetMidnightTime(void)
{
    time_t aTimeInSec = 0;
    struct tm aLocalTm;

    // Set time to midnight, 17 August, 2004
    aLocalTm.tm_year = 2004 - 1900;
    aLocalTm.tm_mon  = 7;
    aLocalTm.tm_mday = 17;
    aLocalTm.tm_hour = 0;
    aLocalTm.tm_min = 0;
    aLocalTm.tm_sec = 0;
    aLocalTm.tm_isdst = 0; // assume no DST

    // Convert to time_t
    aTimeInSec = mktime(&aLocalTm);

    return aTimeInSec;
}

/* oringinal tcpdump binary code
    replaced with htonx usage.
static
time_t TransportTcpTraceGetMidnightTime(void)
{
    time_t aTimeInSec;
    struct tm *aLocalTm = NULL;

    aTimeInSec = time(NULL);
    aLocalTm = localtime(&aTimeInSec);
    aTimeInSec -= aLocalTm->tm_sec
                    + 60 * (aLocalTm->tm_min + 60 * aLocalTm->tm_hour);

    return aTimeInSec;
}
*/


//-------------------------------------------------------------------------//
// A sample tcpdump header structure
// We hard code it here
//-------------------------------------------------------------------------//
//#define TCPDUMP_MAGIC 0xA1B2C3D4
//typedef struct tcpdumpHeaderStr {
//  unsigned int magic;             // as defined above 0xa1b2c3d4
//  unsigned short versionMajor;    // default 2
//  unsigned short versionMinor;    // default 4
//  int timezone;                   // gmt to local correction, default 0
//  unsigned int significantDigits; // accuracy of timestamps, default 6
//  unsigned int snapshotLengthMax; // max length of saved portion of pkt,
//                                  //   default 94 (IPv4) or 114 (IPv6)
//  unsigned int datalinkType;      // data link type, default 1 (Ethernet)
//} TcpDumpHeaderType;


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpbFileHeader
// PURPOSE      Write the file header for tcpdump binary trace output
//
// ASSUMPTIONS  Lots:
//              Version 2.4
//              timezone as 0 GMT
//              time precision, default 6 microsecond
//              max length as 12+2+20+20+40 for MAC,2?,IP,TCP with options
//                  (or 12+2+40+20+40 for IPv6)
//              link type as Ethernet, 01
//-------------------------------------------------------------------------//
static
BOOL TransportTcpTraceDumpbFileHeader(FILE *fp, struct tcpiphdr aTcpIpHdr)
{
    unsigned short aShort;
    unsigned int anInt = 0xA1B2C3D4;             // magic number

    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    aShort = 2;                                 // version major
    if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
    {
        return(FALSE);
    }

    aShort = 4;                                 // version minor
    if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
    {
        return(FALSE);
    }

    anInt = 0;                                  // gmt offset
    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    anInt = 0;                                  // usec significant digits
    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    if (aTcpIpHdr.ti_src.networkType == NETWORK_IPV4) {
        anInt = IPv4_TCPDUMP_LENGTH_MAX;         // snapshot length
    } else {
        anInt = IPv6_TCPDUMP_LENGTH_MAX;         // snapshot length
    }

    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    anInt = 1;                                   // data link type
    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    return(TRUE);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpConvertIpToString
// PURPOSE      Convert IP header values to dot IP address format
// ASSUMPTIONS  IPv4 address.
//-------------------------------------------------------------------------//
static
void TransportTcpConvertIpToString(
    UInt32 theIpAddress,
    unsigned char *theString)
{
    int anIndex = 3;

    while (anIndex >= 0)
    {
        theString[anIndex] = (char)(theIpAddress % 256);
        theIpAddress = theIpAddress / 256;
        anIndex--;
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpConvertHdrToNetworkOrder
// PURPOSE      Convert TCPIP header values to network order
// RETURN       tcpiphdr structure
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
struct tcpiphdr TransportTcpConvertHdrToNetworkOrder(struct tcpiphdr *ti)
{
    struct tcpiphdr aHdr;

    memcpy(&aHdr, ti, sizeof(struct tcpiphdr));

#ifdef LITTLE_ENDIAN
#else
    #ifdef BIG_ENDIAN
    #else
        ERROR_Assert(FALSE, "TCPDUMP requires the machine type"
                    " (little or big endian) to be defined.\n"
                    "Please define using #define BIG_ENDIAN or"
                    " #define LITTLE_ENDIAN.\n");
    #endif
#endif

#ifdef LITTLE_ENDIAN
    aHdr.ti_len = qn_htons(aHdr.ti_len);
    if (aHdr.ti_src.networkType == NETWORK_IPV4)
    {
        aHdr.ti_src.interfaceAddr.ipv4 =
            qn_htonl(aHdr.ti_src.interfaceAddr.ipv4);
        aHdr.ti_dst.interfaceAddr.ipv4 =
             qn_htonl(aHdr.ti_dst.interfaceAddr.ipv4);
    }
    aHdr.ti_sport = qn_htons(aHdr.ti_sport);
    aHdr.ti_dport = qn_htons(aHdr.ti_dport);
    aHdr.ti_seq = qn_htonl(aHdr.ti_seq);
    aHdr.ti_ack = qn_htonl(aHdr.ti_ack);
    aHdr.ti_win = qn_htons((unsigned short)(aHdr.ti_win));
    aHdr.ti_sum = qn_htons(aHdr.ti_sum);
    aHdr.ti_urp = qn_htons(aHdr.ti_urp);
#else
    {
        unsigned int anInt;
        anInt = aHdr.ti_off;
        aHdr.ti_off = aHdr.ti_x2;
        aHdr.ti_x2 = anInt;
    }
#endif

    return (aHdr);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpbOptions
// PURPOSE      Write TCP options field to the binary Tcpdump dump file.
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
BOOL TransportTcpTraceDumpbOptions(
    struct tcpiphdr *ti,
    FILE *fp)
{
    unsigned char *optionPtr = NULL;
    int anOpt, anOptLen, aCtr;
    unsigned short aShort;
    UInt32 aLong;
    int anOptionLength = ((int)
        (tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off))<< 2)
        - sizeof(struct tcphdr);

    if (anOptionLength == 0) {
        return(TRUE);
    }
    optionPtr = (unsigned char *)ti + sizeof(struct tcpiphdr);
    aCtr = 0;

    while (aCtr < anOptionLength)
    {
        anOpt = optionPtr[aCtr];

        switch (anOpt) {

        case TCPOPT_NOP:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           break;

        case TCPOPT_MAXSEG:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           memcpy(&aShort, optionPtr + aCtr, sizeof(unsigned short));
           aShort = qn_htons(aShort);
           if (fwrite(&aShort, sizeof(unsigned short), 1 ,fp) != 1)
           {
              return(FALSE);
           }
           aCtr += 2;
           break;

        case TCPOPT_WINDOW:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           break;

        case TCPOPT_TIMESTAMP:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           memcpy(&aLong, optionPtr + aCtr, sizeof(UInt32));
           aLong = qn_htonl(aLong);
           if (fwrite(&aLong, sizeof(UInt32), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           memcpy(&aLong, optionPtr + aCtr + 4, sizeof(UInt32));
           aLong = qn_htonl(aLong);
           if (fwrite(&aLong, sizeof(UInt32), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 8;
           break;

        case TCPOPT_SACK_PERMITTED:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           break;

        case TCPOPT_SACK:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           anOptLen = optionPtr[aCtr];
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
           anOptLen -=2;
           while (anOptLen) {
               memcpy(&aLong, optionPtr + aCtr, sizeof(UInt32));
               aLong = qn_htonl(aLong);
               if (fwrite(&aLong, sizeof(UInt32), 1 ,fp) != 1)
               {
                   return(FALSE);
               }
               anOptLen -= 4;
               aCtr += 4;
           }
           break;

        default:
           if (fwrite((optionPtr + aCtr), sizeof(unsigned char), 1 ,fp) != 1)
           {
               return(FALSE);
           }
           aCtr += 1;
        }
    }
    return(TRUE);
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpBinaryData
// PURPOSE      Create a tcpdump compatible binary trace output
//              This is created when user input is TCP-TRACE TCPDUMP
//
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
BOOL TransportTcpTraceDumpBinaryData(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg,
    FILE *fp,
    UInt32 aCount)
{
    struct tcpiphdr aTcpIpHdr = TransportTcpConvertHdrToNetworkOrder(ti);
    clocktype aSimTime = 0;
    static time_t aMidnightTime  = TransportTcpTraceGetMidnightTime();
    unsigned int aPacketLength;
    unsigned int anOptionLength;
    unsigned int aDataLength;
    unsigned char *aDataPtr = NULL;
    unsigned short aShort;
    unsigned int anInt;
    UInt32 aLong;
    unsigned char aString[MAX_STRING_LENGTH];

    aSimTime = node->getNodeTime();
    anInt = (unsigned int)(aSimTime / SECOND + aMidnightTime);

    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }
    anInt = (unsigned int)(aSimTime % SECOND / MICRO_SECOND);

    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    anOptionLength = ((int)
        (tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off)) << 2)
        - sizeof(struct tcphdr);
    aDataLength = ti->ti_len - anOptionLength - sizeof(struct tcphdr);

    if (aTcpIpHdr.ti_src.networkType == NETWORK_IPV4) {
        aPacketLength = MAC_HEADER_LEN + IPv4_HEADER_LEN + ti->ti_len;
        anInt = aPacketLength;                  // capture length

        if (anInt > IPv4_TCPDUMP_LENGTH_MAX) {
            anInt = IPv4_TCPDUMP_LENGTH_MAX;
            aDataLength = IPv4_TCPDUMP_LENGTH_MAX - MAC_HEADER_LEN
                - IPv4_HEADER_LEN - sizeof(struct tcphdr) - anOptionLength;
        }
    } else {
        aPacketLength = MAC_HEADER_LEN + IPv6_HEADER_LEN + ti->ti_len;
        anInt = aPacketLength;                  // capture length

        if (anInt > IPv6_TCPDUMP_LENGTH_MAX) {
            anInt = IPv6_TCPDUMP_LENGTH_MAX;
            aDataLength = IPv6_TCPDUMP_LENGTH_MAX - MAC_HEADER_LEN
                - IPv6_HEADER_LEN - sizeof(struct tcphdr) - anOptionLength;
        }
    }

    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }
    anInt = aPacketLength;                  // packet length
    if (fwrite(&anInt, sizeof(unsigned int), 1, fp) != 1)
    {
        return(FALSE);
    }

    // Write Mac values as IP + padding
    if (aTcpIpHdr.ti_dst.networkType == NETWORK_IPV4)
    {
        aLong = GetIPv4Address(aTcpIpHdr.ti_dst);
        TransportTcpConvertIpToString(aLong, aString);
        aString[4] = aString[2];
        aString[5] = aString[3];
    }
    else
    {
        aLong = aTcpIpHdr.ti_dst.interfaceAddr.ipv6.s6_addr32[3];
        TransportTcpConvertIpToString(aLong, aString);
        aString[4] = aTcpIpHdr.ti_dst.interfaceAddr.ipv6.s6_addr[7];
        aString[5] = aTcpIpHdr.ti_dst.interfaceAddr.ipv6.s6_addr[5];
    }
    if (fwrite(aString, sizeof(unsigned char), 6, fp) != 6)
    {
        return(FALSE);
    }

    if (aTcpIpHdr.ti_src.networkType == NETWORK_IPV4)
    {
        aLong = GetIPv4Address(aTcpIpHdr.ti_src);
        TransportTcpConvertIpToString(aLong, aString);
        aString[4] = aString[2];
        aString[5] = aString[3];
    }
    else
    {
        aLong = aTcpIpHdr.ti_src.interfaceAddr.ipv6.s6_addr32[3];
        TransportTcpConvertIpToString(aLong, aString);
        aString[4] = aTcpIpHdr.ti_src.interfaceAddr.ipv6.s6_addr[7];
        aString[5] = aTcpIpHdr.ti_src.interfaceAddr.ipv6.s6_addr[5];
    }
    if (fwrite(aString, sizeof(unsigned char), 6, fp) != 6)
    {
       return(FALSE);
    }

    aString[0] = 0x08;                      // IP identifier
    aString[1] = 0x00;

    if (fwrite(aString, sizeof(unsigned char), 2, fp) != 2)
    {
        return(FALSE);
    }

    // Write IP header
    if (aTcpIpHdr.ti_src.networkType == NETWORK_IPV4)
    {
        aString[0] = 0x45;                      // Ip version + header length

        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        aString[0] = 0x00;                      // Type of service
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        aShort = qn_htons((unsigned short)(ti->ti_len + IPv4_HEADER_LEN));
                                                // total length byte

        if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
        {
            return(FALSE);
        }
        aShort = qn_htons((unsigned short)aCount);  // identification

        if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
        {
            return(FALSE);
        }
        aShort = qn_htons(0x4000);              // flag + offset
        if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
        {
            return(FALSE);
        }
        aString[0] = 0x80;                      // ttl
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        aString[0] = aTcpIpHdr.ti_pr;           // protocol
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        aShort = qn_htons(0x0000);              // checksum
        if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
        {
            return(FALSE);
        }
        aLong = GetIPv4Address(aTcpIpHdr.ti_src);   // source ip
        if (fwrite(&aLong, sizeof(UInt32), 1, fp) != 1)
        {
            return(FALSE);
        }
        aLong = GetIPv4Address(aTcpIpHdr.ti_dst);   // destination ip
        if (fwrite(&aLong, sizeof(UInt32), 1, fp) != 1)
        {
            return(FALSE);
        }
    }
    else
    {
        aString[0] = 0x60;                   // Ip version + Priority
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        // Flow label
        aString[0] = 0x00;
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }

        aString[0] = 0x00;
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        aString[0] = 0x00;
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }

        // Payload length byte
        aShort = qn_htons((unsigned short)ti->ti_len);
        if (fwrite(&aShort, sizeof(unsigned short), 1, fp) != 1)
        {
            return(FALSE);
        }
        // Next Header
        aString[0] = 0x06;
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        // Hop Count
        aString[0] = 0x01;
        if (fwrite(aString, sizeof(unsigned char), 1, fp) != 1)
        {
            return(FALSE);
        }
        // source ip
        in6_addr anAddr = GetIPv6Address(aTcpIpHdr.ti_src);
        if (fwrite(&anAddr, sizeof(in6_addr), 1, fp) != 1)
        {
          return(FALSE);
        }
        // destination ip
        anAddr = GetIPv6Address(aTcpIpHdr.ti_dst);
        if (fwrite(&anAddr, sizeof(in6_addr), 1, fp) != 1)
        {
            return(FALSE);
        }
    }

    // Write TCP header
    unsigned char lval = (aTcpIpHdr.ti_t.tcpHdr_x_off) >> 4;
    unsigned char rval = (aTcpIpHdr.ti_t.tcpHdr_x_off) & 0xFF;
    aTcpIpHdr.ti_t.tcpHdr_x_off = (rval << 4) | lval;

    if (fwrite(&aTcpIpHdr.ti_t, sizeof(struct tcphdr), 1, fp) != 1)
    {
        return(FALSE);
    }

    aTcpIpHdr.ti_t.tcpHdr_x_off = (lval << 4) | rval;

    // Write TCP options
    if (TransportTcpTraceDumpbOptions(ti, fp) ==  FALSE)
    {
        return(FALSE);
    }

    if (aDataLength) {
        aDataPtr = (unsigned char *)ti + anOptionLength
                                     + sizeof(struct tcpiphdr);
        memset(aString, 0xf0, aDataLength);
        if (fwrite(&aString, sizeof(unsigned char), aDataLength, fp)
                         != aDataLength)
        {
            return(FALSE);
        }
        //fwrite(aDataPtr, sizeof(unsigned char), aDataLength, fp);
    }

    return(TRUE);
}



//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTraceDumpBinary
// PURPOSE      Create a tcpdump compatible binary trace output
//              This is created when user input is TCP-TRACE TCPDUMP
//
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------//
static
void TransportTcpTraceDumpBinary(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg)
{
    FILE *fp = NULL;
    static UInt32 aCount = 0;
    struct tcpiphdr aTcpIpHdr = TransportTcpConvertHdrToNetworkOrder(ti);
    char errorString[MAX_STRING_LENGTH];

    if (aCount == 0) {
        fp = fopen("tcptrace.dmp", "wb");
        ERROR_Assert(fp != NULL,
            "TcpTraceDumpBinary: file open error.\n");
        if (TransportTcpTraceDumpbFileHeader(fp, aTcpIpHdr) == FALSE)
        {
            sprintf(errorString,
                    "TRANSPORT-TCP: Unable to write trace information"
                     "in tcptrace.dmp file");
           ERROR_ReportWarning(errorString);
        }
        fclose(fp);
    }

    fp = fopen("tcptrace.dmp", "ab");
    ERROR_Assert(fp != NULL,
        "TcpTraceDumpBinary: file open error.\n");

    aCount++;

    if (TransportTcpTraceDumpBinaryData(node, tp, ti, theMsg, fp, aCount) == FALSE)
    {
        sprintf(errorString,
            "TRANSPORT-TCP: Unable to write trace information in"
            "tcptrace.dmp file");
        ERROR_ReportWarning(errorString);
    }
    fclose(fp);
}



//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpTrace
// PURPOSE      Single function called to write to the trace file tcptrace.out
//              Can be tweaked to print one or more of the pseudo-header,
//                  TCP header, options, data, state variables, control flow
//                  message
//              Currently, prints all of the segment header if theMsg
//                  parameter is "input" or "output"
//              By default, prints theMsg as is, if it anything else.
//              In this case, the tp/ti parameters can be 0
// RETURN       None
// ASSUMPTIONS None.
//-------------------------------------------------------------------------//
void TransportTcpTrace(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg)
{
    TcpTraceType aTraceType = ((TransportDataTcp *)
                                    node->transportData.tcp)->tcpTrace;

    if (aTraceType == TCP_TRACE_NONE) {
        return;
    }

    // XXX this is a hack
    // tcp_input() reduces ti->ti_len by (ti->ti_off << 2) before we get here
    //
    if (!strcmp(theMsg, "input")) {
        ti->ti_len = (short) (ti->ti_len +
            ((tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off)) << 2));
    }

    if (TransportTcpTraceCheckDirection(node, theMsg)) {
        if (aTraceType == TCP_TRACE_PEEK) {
            // TCP-PEEK configuration is no more supported.
            ;//TransportTcpTracePeek(node, tp, ti, theMsg);
        }
        else if (aTraceType == TCP_TRACE_DUMP_ASCII) {
            TransportTcpTraceDumpAscii(node, tp, ti, theMsg);
        }
        else if (aTraceType == TCP_TRACE_DUMP) {
            TransportTcpTraceDumpBinary(node, tp, ti, theMsg);
        }
        else if (aTraceType == TCP_TRACE_DEBUG) {
            TransportTcpTraceDebug(node, tp, ti, theMsg);
        }
    }
    else if ((aTraceType == TCP_TRACE_DEBUG) &&
            strcmp("input", theMsg) && strcmp("output", theMsg)) {
        TransportTcpTraceDebug(node, tp, ti, theMsg);
    }

    if (!strcmp(theMsg, "input")) {
        ti->ti_len = (short) (ti->ti_len -
            ((tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off)) << 2));     //XXX
    }
    return;
}


// /**
// FUNCTION   :: TransportTcpInitTrace
// LAYER      :: TRANSPORT
// PURPOSE    :: Determine what kind of packet trace we need to worry about
// PARAMETERS ::
// + node : Node* : Pointer to node, doing the packet trace
// + nodeInput    : NodeInput* : Pointer to Message : structure containing
//                          contents of input file
// RETURN ::  void : NULL
// **/

static
void TransportTcpInitTrace(
    Node* node,
    const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-TCP",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-TCP should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_TRANSPORT_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
        TRACE_EnableTraceXML(node, TRACE_TCP,
            "TCP", TransportTcpPrintTraceXML, writeMap);
    }
    else
    {
        TRACE_DisableTraceXML(node, TRACE_TCP,
            "TCP", writeMap);
    }
    writeMap = FALSE;
}

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
    Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    struct tcphdr* ti = (struct tcphdr *) MESSAGE_ReturnPacket(msg);

    sprintf(buf, "<tcp>");
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, "%u %u %u %u %u",
            ti->th_sport,
            ti->th_dport,
            ti->th_seq,
            ti->th_ack,
            (tcphdrGetDataOffset(ti->tcpHdr_x_off)));
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, " <flags>%d %d %d %d %d %d %d %d %d</flags>",
        (tcphdrGetTh_x2(ti->tcpHdr_x_off)),
        (unsigned char)ti->th_flags & (unsigned char)TH_CWR ? 1 : 0,
        ti->th_flags & TH_ECE ? 1 : 0,
        ti->th_flags & TH_URG ? 1 : 0,
        ti->th_flags & TH_ACK ? 1 : 0,
        ti->th_flags & TH_PUSH ? 1 : 0,
        ti->th_flags & TH_RST ? 1 : 0,
        ti->th_flags & TH_SYN ? 1 : 0,
        ti->th_flags & TH_FIN ? 1 : 0);
    TRACE_WriteToBufferXML(node, buf);

    sprintf(buf, " %u %u %u",
        ti->th_win,
        ti->th_sum,
        ti->th_urp);
    TRACE_WriteToBufferXML(node, buf);


    int anOptionLength = ((int)(tcphdrGetDataOffset(ti->tcpHdr_x_off)) << 2)
        - sizeof(struct tcphdr);

    if (anOptionLength > 0)
    {
        unsigned char* optionPtr =
                    (unsigned char *)ti + sizeof(struct tcphdr);
        int aCtr = 0;
        int anOpt;
        int anOptLen;

        sprintf(buf, "<options>");
        TRACE_WriteToBufferXML(node, buf);

        while (aCtr < anOptionLength)
        {
            anOpt = optionPtr[aCtr];
            switch (anOpt)
            {

            case TCPOPT_NOP:
                sprintf(buf, "<nop>%u</nop>",
                    optionPtr[aCtr]);
                TRACE_WriteToBufferXML(node, buf);

                aCtr += 1;
                break;

            case TCPOPT_MAXSEG:
                sprintf(buf, "<mss>%u %u %u</mss>",
                    optionPtr[aCtr],
                    optionPtr[aCtr + 1],
                    *(unsigned short*)(optionPtr + aCtr + 2));
                TRACE_WriteToBufferXML(node, buf);

                aCtr += TCPOLEN_MAXSEG;
                break;

            case TCPOPT_WINDOW:
                sprintf(buf, "<scale>%u %u %u</scale>",
                    optionPtr[aCtr],
                    optionPtr[aCtr + 1],
                    optionPtr[aCtr + 2]);
                TRACE_WriteToBufferXML(node, buf);

                aCtr += TCPOLEN_WINDOW;
                break;

            case TCPOPT_TIMESTAMP:
                sprintf(buf, "<ts>%u %u %u %u</ts>",
                    optionPtr[aCtr],
                    optionPtr[aCtr + 1],
                    *(UInt32*)(optionPtr + aCtr + 2),
                    *(UInt32*)(optionPtr + aCtr + 6));
                TRACE_WriteToBufferXML(node, buf);

                aCtr += 10;
                break;

            case TCPOPT_SACK_PERMITTED:
                sprintf(buf, "<sackPermitted>%u %u</sackPermitted>",
                    optionPtr[aCtr],
                    optionPtr[aCtr + 1]);
                TRACE_WriteToBufferXML(node, buf);

                aCtr += TCPOLEN_SACK_PERMITTED;
                break;

            case TCPOPT_SACK:
                sprintf(buf, "<sack>%u %u",
                    optionPtr[aCtr],
                    optionPtr[aCtr + 1]);
                TRACE_WriteToBufferXML(node, buf);

                anOptLen = optionPtr[aCtr + 1];
                aCtr += 2;
                anOptLen -=2;

                sprintf(buf, "<lrEdge>");
                TRACE_WriteToBufferXML(node, buf);
                while (anOptLen)
                {
                    sprintf(buf, " %u",
                            *(UInt32*)(optionPtr + aCtr));
                    TRACE_WriteToBufferXML(node, buf);

                    anOptLen -= 4;
                    aCtr += 4;
                }
                sprintf(buf, "</lrEdge></sack>");
                TRACE_WriteToBufferXML(node, buf);

                break;

            default:
                sprintf(buf, "<eop>%u</eop>",
                    optionPtr[aCtr]);
                TRACE_WriteToBufferXML(node, buf);

                aCtr += 1;
                break;
            }
        }
        sprintf(buf, "</options>");
        TRACE_WriteToBufferXML(node, buf);
    }

    sprintf(buf, "</tcp>");
    TRACE_WriteToBufferXML(node, buf);
}

//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpInit
// PURPOSE     Initialization function for TCP.
//
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------//
void
TransportTcpInit(Node *node, const NodeInput *nodeInput)
{
    TransportDataTcp* tcpLayer;
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    char varBuf[MAX_STRING_LENGTH];
    BOOL varRetVal;
    //int hdrSize = sizeof(IpHeaderType);


    //
    // Initialize TCP Variant for the node
    // The <variant> is one of TAHOE | RENO | LITE | SACK | NEWRENO
    // It may be define ABSTRACT-TCP for initialize AbstractTCP.
    // Format is: TCP  <variant>, for example
    //            TCP  LITE
    //            [7 thru 10] TCP SACK
    //            [11 13 15]  TCP RENO
    // If not specified, default is LITE
    //
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP",
        &varRetVal,
        varBuf);

    // Initialize AbstractTCP.
    if (varRetVal == TRUE && (strcmp(varBuf, "ABSTRACT-TCP") == 0))
    {
        if (node->networkData.networkProtocol == IPV6_ONLY)
        {
            ERROR_ReportError(
                "Presently, ABSTRACT TCP does not support IPv6.\n");
        }
        node->transportData.tcpType = TCP_ABSTRACT;
        TransportAbstractTcpInit(node, nodeInput);
        return;
    }

    tcpLayer = (TransportDataTcp*)MEM_malloc(sizeof(TransportDataTcp));
    memset(tcpLayer, 0, sizeof(TransportDataTcp));
    // IPv6 support; cannot assume header size.
    //int hdrSize = sizeof(IpHeaderType);
    //assert(hdrSize == sizeof(struct ipovly));

    RANDOM_SetSeed(tcpLayer->seed,
                   node->globalSeed,
                   node->nodeId,
                   TransportProtocol_TCP);

    TransportTcpInitTrace(node, nodeInput);

    node->transportData.tcp = tcpLayer;

    // Initialize fast/slow timers status.
    tcpLayer->tcpIsStarted = FALSE;

    // Initialize head.
    tcpLayer->head.inp_next = &(tcpLayer->head);
    tcpLayer->head.inp_prev = &(tcpLayer->head);
    tcpLayer->head.inp_head = &(tcpLayer->head);
    tcpLayer->head.con_id = 0;
    tcpLayer->head.ttl = TTL_NOT_SET;

    // Initialize tcpIss and tcpNow.
    tcpLayer->tcpIss = 1;
    tcpLayer->tcpNow = 0;

    // Initialize TCP variant
    tcpLayer->tcpVariant = TCP_VARIANT_LITE;

    if (varRetVal == TRUE) {
        if (strcmp(varBuf, "TAHOE") == 0) {
            tcpLayer->tcpVariant = TCP_VARIANT_TAHOE;
        }
        else if (strcmp(varBuf, "RENO") == 0) {
            tcpLayer->tcpVariant = TCP_VARIANT_RENO;
        }
        else if (strcmp(varBuf, "LITE") == 0) {
            tcpLayer->tcpVariant = TCP_VARIANT_LITE;
        }
        else if (strcmp(varBuf, "SACK") == 0) {
            tcpLayer->tcpVariant = TCP_VARIANT_SACK;
        }
        else if (strcmp(varBuf, "NEWRENO") == 0) {
            tcpLayer->tcpVariant = TCP_VARIANT_NEWRENO;
        }
        else {
            // Preferably rewrite this this as
            // char aMsg[MAX_STRING_LENGTH];
            // sprintf(aMsg,
            //         "TCP: Unknown variant (%s) in configuration file.\n");
            // ERROR_Assert(FALSE, aMsg);
            // Or suggest it as a library function
            //
            ERROR_Assert(FALSE,
                "TCP: Unknown variant in configuration file.\n");
        }
    }
    // Initialize tcpStatsEnabled and tcpStat.
    IO_ReadBool(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-STATISTICS",
        &retVal,
        &varRetVal);

    // Allocate a tcpstat structure (WILL ALWAYS COLLECT STATISTICS!).
    tcpLayer->tcpStat =
        (struct tcpstat *)MEM_malloc(sizeof(struct tcpstat));
    memset ((char *) tcpLayer->tcpStat, 0, sizeof(struct tcpstat));

    if (retVal == FALSE || !varRetVal) {
        tcpLayer->tcpStatsEnabled = FALSE;
        tcpLayer->tcpStat = NULL;
    }
    else if (varRetVal) {
        tcpLayer->tcpStatsEnabled = TRUE;
        tcpLayer->newStats = new STAT_TransportStatistics(node, "tcp");
    }
    else {
        printf("TCP: Unknown value (%s) for TCP-STATISTICS in config file\n",
               buf);
        tcpLayer->tcpStatsEnabled = FALSE;
    }
    if (tcpLayer->tcpStatsEnabled == FALSE)
    {
#ifdef ADDON_DB
        if (node->partitionData->statsDb != NULL)
        {
            if (node->partitionData->statsDb->statsAggregateTable->createTransAggregateTable)
            {
                ERROR_ReportError(
                    "Invalid Configuration setting: Use of StatsDB TRANSPORT_Aggregate table requires\n"
                    " TCP-STATISTICS to be set to YES\n");    
            }
            if (node->partitionData->statsDb->statsSummaryTable->createTransSummaryTable)
            {
        
                ERROR_ReportError(
                    "Invalid Configuration setting: Use of StatsDB TRANSPORT_Summary table requires\n"
                    " TCP-STATISTICS to be set to YES\n");    
            }
        }
#endif
    }
    //
    // Initialize tcpUseRfc1323 for the node
    // Format is: TCP-USE-RFC1323  NO | YES
    // If not specified, default is NO
    // Was TCP_DO_RFC1323 in config.h
    //
    tcpLayer->tcpUseRfc1323 = FALSE;

    if (tcpLayer->tcpVariant == TCP_VARIANT_LITE
        || tcpLayer->tcpVariant == TCP_VARIANT_SACK
        || tcpLayer->tcpVariant == TCP_VARIANT_NEWRENO)
    {
        IO_ReadString(
                     node->nodeId,
                     ANY_ADDRESS,
                     nodeInput,
                     "TCP-USE-RFC1323",
                     &retVal,
                     buf);

        if (retVal == TRUE) {
            if (strcmp(buf, "NO") == 0) {
                tcpLayer->tcpUseRfc1323 = FALSE;
            }
               else if (strcmp(buf, "YES") == 0) {
                tcpLayer->tcpUseRfc1323 = TRUE;
            }
            else {
                ERROR_Assert(FALSE,
                "TCP-USE-RFC1323: Unknown value in configuration file.\n");
            }
        }
    }

    TransportTcpUserConfigInit(node, nodeInput);

    TransportTcpTraceInit(node, nodeInput);

    TransportTcpEcnInit(node, nodeInput);
}


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpLayer.
// PURPOSE     Models the behaviour of TCP on receiving the
//             message encapsulated in msgHdr
//
// Parameters:
//     node:     node which received the message
//     msg:   message received by the layer
//-------------------------------------------------------------------------//
void TransportTcpLayer(
    Node *node,
    Message *msg)
{
    // Call AbstractTCP layer function.
    if (node->transportData.tcpType == TCP_ABSTRACT)
    {
        TransportAbstractTcpLayer(node, msg);
        return;
    }
    //
    // Retrieve the pointer to the data portion which relates
    // to the TCP protocol.
    //
    TransportDataTcp* tcpLayer = (TransportDataTcp*)
                                    node->transportData.tcp;

    if (!tcpLayer->tcpIsStarted) {
       TransportTcpStart(node);
    }//if//

    switch (msg->eventType) {
    case MSG_TRANSPORT_FromNetwork: {
        struct ipovly* ipPseudoheader = NULL;
        NetworkToTransportInfo *info =
            (NetworkToTransportInfo *) MESSAGE_ReturnInfo(msg);

        TosType priority = info->priority;
        BOOL aCongestionExperienced = info->isCongestionExperienced;

        //Trace Receiving packet. We don't trace the IP pseudo header
        ActionData acnData;
        acnData.actionType = RECV;
        acnData.actionComment = NO_COMMENT;
        TRACE_PrintTrace(node, msg, TRACE_TRANSPORT_LAYER,
                        PACKET_IN, &acnData);

        //
        // QualNet: Put the conceptual IP pseudo header back
        // on the packet so that it can be used as a linked list cell
        // header by the NetBSD code and call tcp_input() to
        // process the packet.
        //
        //

        MESSAGE_AddHeader(node, msg, sizeof(struct ipovly), TRACE_TCP);

        ipPseudoheader = (struct ipovly*)msg->packet;
        ipPseudoheader->ih_len = (short) MESSAGE_ReturnPacketSize(msg);
        ipPseudoheader->ih_src = info->sourceAddr;
        ipPseudoheader->ih_dst = info->destinationAddr;
        ipPseudoheader->ih_x1 &= ~TI_ECE;

        if (aCongestionExperienced) {
            ipPseudoheader->ih_x1 |= TI_ECE;
        }

        tcp_input(
            node,
            (unsigned char *) MESSAGE_ReturnPacket(msg),
            MESSAGE_ReturnActualPacketSize(msg),
            MESSAGE_ReturnVirtualPacketSize(msg),
            priority,
            &(tcpLayer->head),
            &(tcpLayer->tcpIss),
            tcpLayer->tcpNow,
            tcpLayer->tcpStat,
            msg);

        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppListen: {
        AppToTcpListen *appListen;

        //
        // Call tcp_listen() to listen on the specified interface and port.
        //
        appListen = (AppToTcpListen *) MESSAGE_ReturnInfo(msg);

        tcp_listen(node, &(tcpLayer->head), appListen->appType,
                   &appListen->localAddr, appListen->localPort,
                   appListen->priority);

        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppOpen: {
        AppToTcpOpen *appOpen;

        //
        // Call tcp_connect() to set up a connection.
        //
        appOpen = (AppToTcpOpen *) MESSAGE_ReturnInfo(msg);

        tcp_connect(node, &(tcpLayer->head), appOpen->appType,
                    &appOpen->localAddr, appOpen->localPort,
                    &appOpen->remoteAddr, appOpen->remotePort,
                    tcpLayer->tcpNow, &(tcpLayer->tcpIss),
                    tcpLayer->tcpStat, appOpen->uniqueId,
                    appOpen->priority, appOpen->outgoingInterface);

        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppSend: {
        AppToTcpSend *appSend;

        //
        // Call tcp_send() to put the data in send buffer and
        // possibly send some data.
        // set tcp ttl from app layer
        //
        appSend = (AppToTcpSend *) MESSAGE_ReturnInfo(msg);

        if (tcpLayer->tcpStatsEnabled)
        {
            tcpLayer->newStats->AddReceiveFromUpperLayerDataPoints(node, msg);
        }
        if ((appSend->ttl != 0) &&
            (tcpLayer->head.ttl == TTL_NOT_SET))
        {
            tcpLayer->head.ttl = appSend->ttl;
        }

        tcp_send(node, &(tcpLayer->head), appSend->connectionId,
                 (unsigned char *) MESSAGE_ReturnPacket(msg),
                 MESSAGE_ReturnActualPacketSize(msg),
                 MESSAGE_ReturnVirtualPacketSize(msg),
                 tcpLayer->tcpNow, tcpLayer->tcpStat,
                 msg);

        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppClose: {
        AppToTcpClose *appClose;

        //
        // Call tcp_disconnect() to close the connection.
        //
        appClose = (AppToTcpClose *) MESSAGE_ReturnInfo(msg);
        tcp_disconnect(node, &(tcpLayer->head), appClose->connectionId,
                       tcpLayer->tcpNow, tcpLayer->tcpStat);
        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_TCP_TIMER_FAST:
        // fast timeout //
        tcp_fasttimo(node, &(tcpLayer->head), tcpLayer->tcpNow,
                     tcpLayer->tcpStat);

        StartTcpFastTimer(node, msg);
        break;

    case MSG_TRANSPORT_TCP_TIMER_SLOW:
        // slow timeout //
        tcp_slowtimo(node, &(tcpLayer->head), &(tcpLayer->tcpIss),
                     &(tcpLayer->tcpNow), tcpLayer->tcpStat);

        StartTcpSlowTimer(node, msg);
        break;

    case MSG_TRANSPORT_Tcp_CheckTcpOutputTimer:
        tcp_output(node, tcpLayer->tp, tcpLayer->tcpNow, tcpLayer->tcpStat);

        MESSAGE_Free(node, msg);
        break;

    default: {
        char clockStr[MAX_STRING_LENGTH];
        ctoa(node->getNodeTime(), clockStr);
        Int16 eventType = msg->eventType;

        MESSAGE_Free(node, msg);
        ERROR_ReportErrorArgs("Time %s: Node %u received message of "
                              "unknown type %d.\n",
                              clockStr,
                              node->nodeId,
                              eventType);
    }
    }//switch
}


//-------------------------------------------------------------------------//
// FUNCTION    TransportTcpFinalize
// PURPOSE     Called at the end of simulation to collect the results of
//             the simulation of the TCP protocol of Transport Layer.
// Parameter:
//     node:     node for which results are to be collected.
// RETURN       None
// ASSUMTION    None
//-------------------------------------------------------------------------//
void TransportTcpFinalize(Node *node)
{
    // Call AbstractTCP finalize function.
    if (node->transportData.tcpType == TCP_ABSTRACT)
    {
        TransportAbstractTcpFinalize(node);
        return;
    }

    TransportDataTcp *tcpLayer = (TransportDataTcp *)
                                    node->transportData.tcp;
    struct tcpstat *statPtr = NULL;
    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];

    if (tcpLayer->tcpStatsEnabled == FALSE) {
        return;
    }
    statPtr = tcpLayer->tcpStat;

    ctoa(statPtr->tcps_sndpack, buf1);
    sprintf(buf, "Data Packets in Sequence = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndrexmitpack, buf1);
    sprintf(buf, "Data Packets Retransmitted = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndfastrexmitpack, buf1);
    sprintf(buf, "Data Packets Fast Retransmitted = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndacks, buf1);
    sprintf(buf, "ACK-only Packets Sent = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndctrl, buf1);
    sprintf(buf, "Pure Control (SYN|FIN|RST) Packets Sent = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndwinup, buf1);
    sprintf(buf, "Window Update-Only Packets Sent = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndprobe, buf1);
    sprintf(buf, "Window Probes Sent = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvackpack, buf1);
    sprintf(buf, "In Sequence ACK Packets Received = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvdupack, buf1);
    sprintf(buf, "Duplicate ACK Packets Received = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvctrl, buf1);
    sprintf(buf, "Pure Control (SYN|FIN|RST) Packets Received = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvwinupd, buf1);
    sprintf(buf, "Window Update-Only Packets Received = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvwinprobe, buf1);
    sprintf(buf, "Window Probes Received = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);


    // Print packet error information.
    ctoa(statPtr->tcps_rcvbadsum + statPtr->tcps_rcvbadoff + statPtr->tcps_rcvshort, buf1);
    sprintf(buf, "Total Packets with Errors = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvbadsum, buf1);
    sprintf(buf, "Packets Received with Checksum Errors = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvbadoff, buf1);
    sprintf(buf, "Packets Received with Bad Offset = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvshort, buf1);
    sprintf(buf, "Packets Received that are Too Short = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    tcpLayer->newStats->Print(
        node,
        "Transport",
        "TCP",
        ANY_ADDRESS,
        -1 /* instance id */);

    // More data can be printed here.
    MEM_free(statPtr);
    MEM_free(tcpLayer);
}

/*
 * FUNCTION    Tcp_HandleIcmpMessage
 * PURPOSE     Send the received ICMP Error Message to Application.
 * Parameters:
 *     node:      node sending the message to application layer
 *     msg:       message to be sent to application layer
 *     icmpType:  ICMP Message Type
 *     icmpCode:  ICMP Message Code
 */

void Tcp_HandleIcmpMessage(
    Node *node,
    Message *msg,
    unsigned short icmpType,
    unsigned short icmpCode)
{

    tcphdr* tcpHeader = (tcphdr*)MESSAGE_ReturnPacket(msg);

    // Note: Below code should be uncommneted if the message is to be
    //passed to application layer through API App_HandleIcmpMessage

    //if (msg->packetSize >= sizeof(tcphdr))
    //{
    //    MESSAGE_ShrinkPacket(node, msg, sizeof(tcphdr));
    //}
    //else
    //{
    //    MESSAGE_ShrinkPacket(node, msg, msg->packetSize);
    //}

    App_HandleIcmpMessage(
            node,
            tcpHeader->th_sport,
            tcpHeader->th_dport,
            icmpType,
            icmpCode);
}
