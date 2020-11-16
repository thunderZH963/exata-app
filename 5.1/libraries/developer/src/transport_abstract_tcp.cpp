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

// This file contains message processing for Abstrct TCP.
//
// Basic components of ABSTRACT TCP are:
//
// RTT measurement: Whenever an ACK comes in, a sender sets the average
//                  RTT = 7/8 * average RTT + 1/8 * new RTT.
//                  This RTT measurement scheme is copied into Abstract
//                  TCP from TCP implementation in QualNet.
//
// Window management: Following TCP RENO specification.  Instead of
//                    allocating actual memory to cache sent packets,
//                    Abstract TCP rather use only parameters to keep track
//                    of sends packets. The parameters are cwnd (current
//                    window size - assume fixed packet size, thus it counts
//                    the packet number), start_wnd (sequence # of starting
//                    packet at current window), max_wnd (= start_wnd+cwnd),
//                    ssthresh, awnd (advertised window size), seq_una (the
//                    smallest sequence number of unacked packets).
//
// Timer management: Abstract TCP remove all other timers except for
//                   "retransmission timer". TCP checks the expiration
//                   of retransmission timer every 500 msec.
//
// Packet caching/reordering: Abstract TCP use an array of packet instate
//                            of byte stream. It maintain array with two
//                            variables (start_index, start_seq).  So,
//                            upon receiving a packet with sequence number
//                            recv_seq, TCP sets RECV_CACHE[i] = 1 w.r.t.
//                            i = ((recv_seq - start_seq) + start_index) %
//                            recvBufferSize. We omit reassembling packets
//                            but keeping reordering.
//
// TCP packet functions: We divide tcp_ouput to TransportTcpTransmitData,
//                       TransportTcpRetransmitData, TransportTcpTransmitAck
//                       based on the packet type and tcp_input to
//                       TransportTcpRecvData and TransportTcpRecvAck based
//                       on received packet type.
//
// Connection setup: Three-hand shaking is omitted. Sender retransmits the
//                   first data packet till it receives an ACK from receiver
//                   (sender and receiver initiate session upon
//                   receiving/sending the first ACK). The sender stops
//                   transmitting to close the session. Since mobility can
//                   temporarily disconnect the session, a receiver resumes
//                   the session if it receives a new data packet even after
//                   it closed the session. (Note that the same sender can
//                   start another session (after it closes the previous one)
//                   with the same receiver by sending the first packet with
//                   sequence number = 1. However, in the current version,
//                   one node can start only one session to each receiver in
//                   one simulation run).


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "api.h"
#include "network_ip.h"
#include "trace.h"
#include "transport_abstract_tcp.h"
#include "transport_abstract_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_abstract_tcp_var.h"
#include "transport_abstract_tcp_proto.h"

#define TCP_TIMER_JITTER (1 * MILLI_SECOND)
#define TCP_SLOW_TIMER_INTERVAL (500 * MILLI_SECOND)

#define TCP_DEFAULT_MSS 1024
#define TCP_DEFAULT_SEND_BUFFER 16 * 1024
#define TCP_DEFAULT_RECV_BUFFER 16 * 1024

//-------------------------------------------------------------------------
//                       START FUNCTION FOR DEBUGGING
//-------------------------------------------------------------------------

//-------------------------------------------------------------------------
// FUNCTION     TransportAbstractTcpTraceConvertTimeToHMS
// PURPOSE      Convert string of sceond to H:M:S format
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------
static
void TransportAbstractTcpTraceConvertTimeToHMS(char* timeString,
                                               FILE* fp)
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


//-------------------------------------------------------------------------
// FUNCTION     TransportAbstractTcpTraceHeader
// PURPOSE      Write message Header to tcpTrace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------
static
void TransportAbstractTcpTraceHeader(Node* node,
                                     struct abstract_tcphdr* ti,
                                     int len,
                                     FILE* fp)
{
    fprintf(fp, "%u.%d.%d.%d",
        (ti->th_src & 0xff000000) >> 24,
        (ti->th_src & 0xff0000) >> 16,
        (ti->th_src & 0xff00) >> 8,
        (ti->th_src & 0xff));
    fprintf(fp,".");
    fprintf(fp,"%-4u > ",ti->th_sport);
    fprintf(fp, "%u.%d.%d.%d",
        (ti->th_dst & 0xff000000) >> 24,
        (ti->th_dst & 0xff0000) >> 16,
        (ti->th_dst & 0xff00) >> 8,
        (ti->th_dst & 0xff));
    fprintf(fp,".");
    fprintf(fp,"%-4u:  ",ti->th_dport);

    if (len)
    {
        fprintf(fp,"%u:",ti->th_seq);
        fprintf(fp,"%u",(ti->th_seq + len));
        fprintf(fp,"(%u) ",len);
    }
    if (ti->th_ack)
    {
        fprintf(fp,"ack ");
        fprintf(fp,"%u ",ti->th_ack);
    }
    fprintf(fp,"win %u ",ti->th_win);
}


//-------------------------------------------------------------------------
// FUNCTION     TransportAbstractTcpTraceTcpcb
// PURPOSE      Write message Header to tcpTrace file
// RETURN       None
// ASSUMPTIONS  None.
//-------------------------------------------------------------------------
static
void TransportAbstractTcpTraceTcpcb(Node* node,
                                    struct abs_tcpcb* tp,
                                    FILE* fp)
{
    fprintf(fp,"cwnd:%u ssthresh:%u una:%u nxt:%u max:%u",
        tp->snd_cwnd, tp->snd_ssthresh,
        tp->snd_una, tp->snd_nxt, tp->snd_max);
}

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
                               int len)
{
    static FILE* abs_tcp_fp = NULL;
    char clockStr[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

    if (abs_tcp_fp == NULL) {
        abs_tcp_fp = fopen("tcptrace_abs.asc", "w");

        ERROR_Assert(abs_tcp_fp != NULL,
            "AbstractTcpTraceAscii: File open error.\n");
    }
    else {
        abs_tcp_fp = fopen("tcptrace_abs.asc", "a");

        ERROR_Assert(abs_tcp_fp != NULL,
            "AbstractTcpTraceAscii: File open error.\n");
    }

    TransportAbstractTcpTraceConvertTimeToHMS(clockStr, abs_tcp_fp);
    TransportAbstractTcpTraceHeader(node, ti, len, abs_tcp_fp);
    TransportAbstractTcpTraceTcpcb(node, tp, abs_tcp_fp);
    fprintf(abs_tcp_fp, "\n");
    fclose(abs_tcp_fp);
}


//-------------------------------------------------------------------------
//                       END FUNCTION FOR DEBUGGING
//-------------------------------------------------------------------------


//-------------------------------------------------------------------------
// FUNCTION     TransportTcpUserConfigInit
// PURPOSE      Initialize user configuration variables
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------
static
void TransportTcpUserConfigInit(Node* node,
                                const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    int anInt = 0;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;


    //NO KEEP ALIVE
    tcpLayer->tcpUseKeepAliveProbes = FALSE;

    //
    // Initialize tcpDelayAcks for the node
    // Format is: TCP-DELAY-ACKS  YES | NO
    // If not specified, default is NO
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
            ERROR_ReportError(
                "TCP-DELAY-ACKS: Unknown value in configuration file.\n");
        }
    }
    else {
        tcpLayer->tcpDelayAcks = FALSE;
    }

    //
    // Initialize tcpSendBuffer for the node
    // Format is: TCP-SEND-BUFFER <value>
    // If not specified, default is 16384
    // NOTE:Actually data type of this variable is unsigned long but Qualnet
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
    // NOTE:Actually data type of this variable is unsigned long but Qualnet
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

    if (tcpLayer->tcpMss < TCP_MIN_MSS) {
        ERROR_ReportError("TCP-MSS: Value below minimum of 64.\n");
    }

    if (tcpLayer->tcpSendBuffer < tcpLayer->tcpMss) {
        ERROR_ReportError("TCP-SEND-BUFFER: Value below MSS.\n");
    }

    if (tcpLayer->tcpRecvBuffer > TCP_MAXWIN) {
        ERROR_ReportError(
            "TCP-RECEIVE-BUFFER: Value exceeds permitted window size.\n");
    }
}


//-------------------------------------------------------------------------
// FUNCTION     TransportTcpEcnInit
// PURPOSE      Initialize ECN for TCP
// RETURN       None
// ASSUMPTIONS: None
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------
static
void TransportTcpEcnInit(Node* node,
                         const NodeInput* nodeInput)
{
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    tcpLayer->nodeUseEcn = FALSE;
}


//-------------------------------------------------------------------------
// FUNCTION     StartTimer
// PURPOSE      Called by any function when try to start a timer.
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------
static //inline
void StartTimer(Node* node,
                Message* reusedMsg,
                int timerType,
                clocktype timerDelay)
{
    clocktype ExtraJitterDelay;
    Message* msg = reusedMsg;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    if (msg == NULL) {
        msg = MESSAGE_Alloc(node,
            TRANSPORT_LAYER, TransportProtocol_TCP, timerType);
    }//if//

    ExtraJitterDelay  =
        (clocktype) (RANDOM_erand(tcpLayer->seed) * TCP_TIMER_JITTER);

    MESSAGE_Send(node, msg,  (timerDelay + ExtraJitterDelay));
}


//-------------------------------------------------------------------------
// FUNCTION     StartTcpSlowTimer
// PURPOSE      This Timer is called by TransportTcpLayer every 500 ms.
// RETURN       None
// ASSUMPTIONS: None
//-------------------------------------------------------------------------
static //inline
void StartTcpSlowTimer(Node* node,
                       Message* reusedMsg)
{
    StartTimer(
        node,
        reusedMsg,
        MSG_TRANSPORT_TCP_TIMER_SLOW,
        TCP_SLOW_TIMER_INTERVAL);
}


//-------------------------------------------------------------------------
// FUNCTION     TransportTcpStart
// PURPOSE      Called the first time a simulation actually uses the TCP
//              model to start TCPSlowTimer and TCPFistTimer for first time.
// RETURN       None
// ASSUMPTIONS: None
// Parameter:
//     node:     node for which results are to be collected.
//-------------------------------------------------------------------------
static
void TransportTcpStart(Node* node)
{
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;
    tcpLayer->tcpIsStarted = TRUE;

    //
    // Initialize system timeouts.
    //
    StartTimer(
        node,
        NULL,
        MSG_TRANSPORT_TCP_TIMER_SLOW,
        (clocktype)(TCP_SLOW_TIMER_INTERVAL * RANDOM_erand(tcpLayer->seed)));
}


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpInit
// PURPOSE     Initialization function for TCP.
//
// Parameters:
//     node:      node being initialized.
//     nodeInput: structure containing contents of input file
//-------------------------------------------------------------------------
void
TransportAbstractTcpInit(Node* node,
                         const NodeInput* nodeInput)
{
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                            MEM_malloc(sizeof(TransportDataAbstractTcp));
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    double aDropPercent;            // for random packet drops
    int aDropCount = 0;             // drop count for verification scenarios.

    node->transportData.tcp = tcpLayer;

    RANDOM_SetSeed(tcpLayer->seed,
                   node->globalSeed,
                   node->nodeId);

    // Initialize fast/slow timers status.
    tcpLayer->tcpIsStarted = FALSE;

    // Initialize head.
    tcpLayer->head = NULL;

    // Initialize tcpIss and tcpNow.
    tcpLayer->tcpIss = 1;
    tcpLayer->tcpNow = 0;
    tcpLayer->con_id = 0;

    // Initialize tcpStatsEnabled and tcpStat.
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-STATISTICS",
        &retVal,
        buf);

    tcpLayer->tcpStatsEnabled = FALSE;
    //tcpLayer->tcpStat = NULL;    
    // Allocate a tcpstat structure (WILL ALWAYS COLLECT STATISTICS!).
    tcpLayer->tcpStat =
                (struct tcpstat*)MEM_malloc(sizeof(struct tcpstat));
    memset ((char*) tcpLayer->tcpStat, 0, sizeof(struct tcpstat));

    if (retVal) {
        if (strcmp(buf, "YES") == 0) {
            tcpLayer->tcpStatsEnabled = TRUE;
        }
        else if (strcmp(buf, "NO") != 0) {
            ERROR_ReportError(
                "TCP-STATISTICS should be either YES or NO\n");
        }
    }
    //
    // Initialize trace values for the node
    // <TraceType> is one of
    //      NONE    the default if nothing is specified
    //      TCPDUMP-ASCII a tcpdump compatible ascii format
    // Format is: TCP-TRACE  <TraceType>, for example
    //            TCP-TRACE TCPDUMP-ASCII
    //            [4 thru 7] TCP-TRACE NONE
    //
    tcpLayer->trace = FALSE;
    tcpLayer->traceDirection = ABS_TCP_TRACE_DIRECTION_BOTH;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TCP-TRACE",
        &retVal,
        buf);

    if (retVal == TRUE) {
        if (strcmp(buf, "TCPDUMP-ASCII") == 0) {
            tcpLayer->trace = TRUE;

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
                    tcpLayer->traceDirection =
                        ABS_TCP_TRACE_DIRECTION_OUTPUT;
                }
                else if (strcmp(buf, "INPUT") == 0) {
                    tcpLayer->traceDirection =
                        ABS_TCP_TRACE_DIRECTION_INPUT;
                }
                else if (strcmp(buf, "BOTH") == 0) {
                    tcpLayer->traceDirection =
                        ABS_TCP_TRACE_DIRECTION_BOTH;
                }
                else {
                    ERROR_ReportError("TCP-TRACE-DIRECTION: "
                        "Unknown value in configuration file.\n");
                }
            }
        }
        else
        {
            ERROR_ReportError(
                "TCP-TRACE: AbstractTcp only support TCPDUMP-ASCII.\n");
        }
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

    // RFC 1323 not support
    tcpLayer->tcpUseRfc1323 = FALSE;

    TransportTcpUserConfigInit(node, nodeInput);

    TransportTcpEcnInit(node, nodeInput);
}


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpLayer.
// PURPOSE     Models the behaviour of TCP on receiving the
//             message encapsulated in msgHdr
//
// Parameters:
//     node:     node which received the message
//     msg:   message received by the layer
//-------------------------------------------------------------------------
void TransportAbstractTcpLayer(Node* node,
                               Message* msg)
{
    //
    // Retrieve the pointer to the data portion which relates
    // to the TCP protocol.
    //
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    // This "if" block is always checked when layer function is called.
    // But Timer will be started when the first tp block is created for
    // a particular node. So place this poriton into the switch cases
    // events MSG_TRANSPORT_FromAppOpen and MSG_TRANSPORT_FromAppListen.

    //if (!tcpLayer->tcpIsStarted) {
    //  TransportTcpStart(node);
    //}//if//

    switch (msg->eventType) {
    case MSG_TRANSPORT_FromNetwork:{
        TosType priority =
            ((NetworkToTransportInfo*)MESSAGE_ReturnInfo(msg))->priority;

        //TRACE_PrintTrace(node, msg, TRACE_TRANSPORT_LAYER);

        tcp_input(node,
                  msg,
                  priority);
        break;
    }
    case MSG_TRANSPORT_FromAppOpen: {
        //Call tcp_connect() to set up a connection.
        AppToTcpOpen* appOpen = (AppToTcpOpen*) MESSAGE_ReturnInfo(msg);

        if (!tcpLayer->tcpIsStarted) {
            TransportTcpStart(node);
        }

        tcp_connect(node,
                    (tcpLayer->head),
                    appOpen->appType,
                    &appOpen->localAddr,
                    appOpen->localPort,
                    &appOpen->remoteAddr,
                    appOpen->remotePort,
                    tcpLayer->tcpNow,
                    &(tcpLayer->tcpIss),
                    tcpLayer->tcpStat,
                    appOpen->uniqueId,
                    appOpen->priority,
                    appOpen->outgoingInterface);
        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppSend: {
        //
        // Call tcp_send() to put the data in send buffer and
        // possibly send some data.
        //
        AppToTcpSend* appSend = (AppToTcpSend*) MESSAGE_ReturnInfo(msg);

        tcp_send(node,
            (tcpLayer->head),
            appSend->connectionId,
            msg,
            MESSAGE_ReturnActualPacketSize(msg),
            MESSAGE_ReturnVirtualPacketSize(msg),
            tcpLayer->tcpNow,
            tcpLayer->tcpStat);
        break;
    }
    case MSG_TRANSPORT_FromAppClose: {
        // Call tcp_disconnect() to close the connection.
        AppToTcpClose* appClose = (AppToTcpClose*) MESSAGE_ReturnInfo(msg);

        tcp_close(node,
                  &(tcpLayer->head),
                  appClose->connectionId,
                  tcpLayer->tcpStat);
        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_TCP_TIMER_SLOW: {
        // slow timeout //
        tcp_slowtimo(node,
                     tcpLayer->head,
                     &(tcpLayer->tcpIss),
                     &(tcpLayer->tcpNow),
                     tcpLayer->tcpStat);

        StartTcpSlowTimer(node, msg);
        break;
    }
    case MSG_TRANSPORT_Tcp_CheckTcpOutputTimer: {
        tcp_output(node,
                   tcpLayer->tp,
                   tcpLayer->tcpNow,
                   tcpLayer->tcpStat);

        MESSAGE_Free(node, msg);
        break;
    }
    case MSG_TRANSPORT_FromAppListen:{
        // Call tcp_listen() to listen on the specified interface and port.
        AppToTcpListen* appListen = (AppToTcpListen*) MESSAGE_ReturnInfo(msg);

        if (!tcpLayer->tcpIsStarted) {
            TransportTcpStart(node);
        }

        tcp_listen(node,
                   tcpLayer->head,
                   appListen->appType,
                   &appListen->localAddr,
                   appListen->localPort,
                   appListen->priority);

        MESSAGE_Free(node, msg);
        break;
    }
    default: {
        char clockStr[MAX_STRING_LENGTH];
        char buf[MAX_STRING_LENGTH];
        ctoa(node->getNodeTime(), clockStr);
        sprintf(buf, "ABSTRACT-TCP: Time %s: Node %u received message of "
            "unknown type %d.\n", clockStr, node->nodeId, msg->eventType);
        MESSAGE_Free(node, msg);
        ERROR_Assert(FALSE, buf);
        break;
    }
    }//switch
}


//-------------------------------------------------------------------------
// FUNCTION    TransportAbstractTcpFinalize
// PURPOSE     Called at the end of simulation to collect the results of
//             the simulation of the TCP protocol of Transport Layer.
// Parameter:
//     node:     node for which results are to be collected.
// RETURN       None
// ASSUMTION    None
//-------------------------------------------------------------------------
void TransportAbstractTcpFinalize(Node* node)
{
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                            node->transportData.tcp;
    struct tcpstat* statPtr = NULL;
    char buf[MAX_STRING_LENGTH] = {0};
    char buf1[MAX_STRING_LENGTH] = {0};

    if (tcpLayer->tcpStatsEnabled == FALSE) {
        return;
    }

    statPtr = tcpLayer->tcpStat;

    // Print number of packets sent to and received from network.
    ctoa(statPtr->tcps_sndtotal, buf1);
    sprintf(buf, "Packets Sent to Network Layer = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_sndpack + statPtr->tcps_sndrexmitpack, buf1);
    sprintf(buf, "Data Packets Sent = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

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

//    sprintf(buf, "Pure Control (SYN|FIN|RST) Packets Sent = %lu",
//        statPtr->tcps_sndctrl);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Window Update-Only Packets Sent = %lu",
//        statPtr->tcps_sndwinup);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Window Probes Sent = %lu", statPtr->tcps_sndprobe);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

    ctoa(statPtr->tcps_rcvtotal, buf1);
    sprintf(buf, "Total Packets Received From Network Layer = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    ctoa(statPtr->tcps_rcvpack, buf1);
    sprintf(buf, "Data Packets Received = %s", buf1);
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

//    sprintf(buf, "Pure Control (SYN|FIN|RST) Packets Received = %lu",
//        statPtr->tcps_rcvctrl);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Window Update-Only Packets Received = %lu",
//        statPtr->tcps_rcvwinupd);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Window Probes Received = %lu",
//        statPtr->tcps_rcvwinprobe);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);


    // Print packet error information.
//    sprintf(buf, "Total Packets with Errors = %lu", statPtr->tcps_rcvbadsum
//        + statPtr->tcps_rcvbadoff + statPtr->tcps_rcvshort);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Packets Received with Checksum Errors = %lu",
//        statPtr->tcps_rcvbadsum);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

//    sprintf(buf, "Packets Received with Bad Offset = %lu",
//        statPtr->tcps_rcvbadoff);
//    IO_PrintStat(
//        node,
//        "Transport",
//        "TCP",
//        ANY_DEST,
//        -1, // instance Id
//        buf);

    ctoa(statPtr->tcps_rcvshort, buf1);
    sprintf(buf, "Packets Received that are Too Short = %s", buf1);
    IO_PrintStat(
        node,
        "Transport",
        "TCP",
        ANY_DEST,
        -1, // instance Id
        buf);

    // More data can be printed here.
    MEM_free(statPtr);
    MEM_free(tcpLayer);
}
