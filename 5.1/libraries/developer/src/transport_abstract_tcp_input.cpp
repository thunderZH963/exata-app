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

//
// This file contains Abstract TCP input routine.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "transport_abstract_tcp.h"
#include "transport_abstract_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_abstract_tcp_var.h"
#include "transport_abstract_tcp_proto.h"

// Limit of continuous dup ACK for fast retransmit.
#define ABS_TCP_REXMT_THRESH 3

#define DEBUG 0

//-------------------------------------------------------------------------
// Collect new round-trip time estimate
// and update averages and current timeout.
//-------------------------------------------------------------------------
static
void tcp_xmit_timer(struct abs_tcpcb* tp,
                    int rtt,
                    struct tcpstat* tcp_stat)
{
    int delta;

    tp->t_rttupdated++;

    if (tp->t_srtt != 0) {
        //
        // srtt is stored as fixed point with 5 bits after the
        // binary point (i.e., scaled by 8).  The following magic
        // is equivalent to the smoothing algorithm in rfc793 with
        // an alpha of .875 (srtt = rtt/8 + srtt*7/8 in fixed
        // point).  Adjust rtt to origin 0.
        //
        delta = ((rtt - 1) << TCP_DELTA_SHIFT)
            - (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

        if ((tp->t_srtt += delta) <= 0)
            tp->t_srtt = 1;

        //
        // We accumulate a smoothed rtt variance (actually, a
        // smoothed mean difference), then set the retransmit
        // timer to smoothed rtt + 4 times the smoothed variance.
        // rttvar is stored as fixed point with 4 bits after the
        // binary point (scaled by 16).  The following is
        // equivalent to rfc793 smoothing with an alpha of .75
        // (rttvar = rttvar*3/4 + |delta| / 4).  This replaces
        // rfc793's wired-in beta.
        //
        if (delta < 0)
            delta = -delta;
        delta -= tp->t_rttvar >> (TCP_RTTVAR_SHIFT - TCP_DELTA_SHIFT);
        if ((tp->t_rttvar += delta) <= 0)
            tp->t_rttvar = 1;
    } else {
        //
        // No rtt measurement yet - use the unsmoothed rtt.
        // Set the variance to half the rtt (so our first
        // retransmit happens at 3*rtt).
        //
        tp->t_srtt = rtt << TCP_RTT_SHIFT;
        tp->t_rttvar = rtt << (TCP_RTTVAR_SHIFT - 1);
    }
    tp->t_rtt = 0;
    tp->t_rxtshift = 0;

    //
    // the retransmit should happen at rtt + 4 * rttvar.
    // Because of the way we do the smoothing, srtt and rttvar
    // will each average +1/2 tick of bias.  When we compute
    // the retransmit timer, we want 1/2 tick of rounding and
    // 1 extra tick because of +-1/2 tick uncertainty in the
    // firing of the timer.  The bias will give us exactly the
    // 1.5 tick we need.  But, because the bias is
    // statistical, we have to test that we don't drop below
    // the minimum feasible timer (which is 2 ticks).
    //
    TCPT_RANGESET(tp->t_rxtcur, TCP_REXMTVAL(tp),
        MAX(tp->t_rttmin, (unsigned int) (rtt + 2)), TCPTV_REXMTMAX);

//    if (tcp_stat)
//        tcp_stat->tcps_rttupdated++;
}


//-------------------------------------------------------------------------
// Deliver data to application.
//-------------------------------------------------------------------------
static
void TransportTcpSendToApp(Node* node,
                           AppType app_type,
                           int conn_id,
                           int total_length,
                           Message* msg)
{
    TransportToAppDataReceived* tcpDataReceived;

    if (total_length > 0) {
        MESSAGE_SetLayer(msg, APP_LAYER, (short) app_type);
        MESSAGE_SetInstanceId(msg, 0);
        msg->eventType = MSG_APP_FromTransDataReceived;
        MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppDataReceived));
        tcpDataReceived = (TransportToAppDataReceived*)
                          MESSAGE_ReturnInfo(msg);
        tcpDataReceived->connectionId = conn_id;
        MESSAGE_Send(node, msg, TRANSPORT_DELAY);
    }
    else {
        MESSAGE_Free(node, msg);
    }
}


//-------------------------------------------------------------------------
// Reassemble received packets.
// Deliver data to application if in sequence.
//-------------------------------------------------------------------------
static
int tcp_reass(Node* node,
              struct abs_tcpcb* tp,
              struct abstract_tcphdr* ti,
              struct tcpstat* tcp_stat)
{
    int flags = 0;
    tcp_seq start_seq;
    int index = 0;
    int aggregated = 0;

     // Find a segment which begins after this one does.
    for (start_seq = tp->start_recv_seq; start_seq <= tp->last_recv_seq;) {
        index = start_seq - tp->start_recv_seq + tp->startRecvBufferIndex;
        index %= tp->recvBufferSize;

        if (DEBUG) {
            printf("CHECKING ORDER :%d %d :%d %d \n",
                tp->rcv_nxt, tp->startRecvBufferIndex, start_seq, index);
        }

        if(tp->recvBuffer[index]) {
            Message* msg = tp->recvBuffer[index];
            tp->recvBuffer[index] = NULL;
            aggregated+= (short)MESSAGE_ReturnPacketSize(msg);
            start_seq += (short)MESSAGE_ReturnPacketSize(msg);

            TransportTcpSendToApp(node,
                                  tp->app_type,
                                  tp->con_id,
                                  (short)MESSAGE_ReturnPacketSize(msg),
                                  msg);
        }
        else {
            break;
        }
    }

    if(aggregated != 0) { //aggregation is succeeded
        tp->startRecvBufferIndex += aggregated;
        tp->startRecvBufferIndex %= tp->recvBufferSize;
        tp->start_recv_seq += aggregated;
        tp->rcv_nxt += aggregated;
        tp->rcv_adv+= aggregated;
        if(tp->last_recv_seq < tp->rcv_nxt) {
            tp->last_recv_seq = tp->rcv_nxt;
        }
    }
    return (flags);
}


//-------------------------------------------------------------------------
// TCP input routine.
//-------------------------------------------------------------------------
void tcp_input(Node* node,
               Message* msg,
               TosType priority)
{
    struct abstract_tcphdr* ti;

    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    int total_len = MESSAGE_ReturnPacketSize(msg);

    struct tcpstat* tcp_stat;
    BOOL free = FALSE;

    tcp_stat = tcpLayer->tcpStat;

    if (tcp_stat) {
        tcp_stat->tcps_rcvtotal++;
    }

    // Get IP and TCP header together. Assume ip options have been stripped.
    // Note: IP leaves IP header in tcp_seg.
    //
    ti = (struct abstract_tcphdr*)(msg->packet); //TCP Header

    //short message than tcp/ip header
    if (total_len < (int) sizeof(struct abstract_tcphdr)) {
        if (tcp_stat)
            tcp_stat->tcps_rcvshort++;

        MESSAGE_Free(node, msg);
        return;
    }

    if (tcp_stat) {
        if (total_len > (int) sizeof(struct abstract_tcphdr)) {
            tcp_stat->tcps_rcvpack ++;
//            tcp_stat->tcps_rcvbyte += (MESSAGE_ReturnPacketSize(msg) -
//                                        sizeof(struct abstract_tcphdr));
        }
    }

    if (DEBUG) {
        printf("RECEIVE DATA :%d %d :%d :%d %f\n", ti->th_src, ti->th_dst,
            ti->th_seq, ti->th_ack, (double)node->getNodeTime());
    }

    if(ti->th_ack != 0 && ti->th_seq == 0 && ti->th_ack != TCPS_CLOSE_WAIT){

        TransportTcpHandleAck(node,msg);
        free = TRUE;
    }

    if(ti->th_seq != 0 || ti->th_ack == TCPS_CLOSE_WAIT) {

        tcp_seq dropValues[] = { 14001, 28001, 26001, 24001};
        static int dropFlag[] = {1, 1, 1, 1};

        // Drop some data packets (for testing)
        // This section works if TCP-RANDOM-DROP-PERCENT is used in user input
        {
            double aDropPercent = tcpLayer->tcpRandomDropPercent;
            if (aDropPercent > 0) {
                if (RANDOM_erand(tcpLayer->seed) < aDropPercent/100) {
                    if (tcp_stat)
                    {
                        tcp_stat->tcps_rcvtotal--;
                    }
                    MESSAGE_Free(node, msg);
                    return;
                }
            }
        }

        // Drop some specific data packets (for testing)
        // The values to drop are set in the verification .config files
        if (tcpLayer->verificationDropCount) {
            for (int counter = 0;
                counter < tcpLayer->verificationDropCount;
                counter++)
            {
                if (ti->th_seq == dropValues[counter] && dropFlag[counter]) {
                    if (tcp_stat)
                    {
                        tcp_stat->tcps_rcvtotal--;
                    }
                    dropFlag[counter]--;
                    MESSAGE_Free(node, msg);
                    return;
                }
            }
        }

        /* Uncomment this if custom drops are required.
        // Drop some specific data packets (for testing)
        // The values to drop are set at the top of this routine
        {
            static int dropSeq = 4;
            static int dropCount = 4;

            if (dropCount) {
                int counter;
                for (counter = 0; counter < dropSeq; counter++) {
                    if (ti->th_seq == dropValues[counter] &&
                            dropFlag[counter]) {
                        tcp_stat->tcps_rcvtotal--;
                        dropFlag[counter]--;
                        dropCount--;
                        MESSAGE_Free(node, msg);
                        return;
                    }
                }
            }
        }
        */

        free = FALSE;

        free = TransportTcpHandleData(node, msg, priority);
    }

    if(free) {
        MESSAGE_Free(node, msg);
    }
    return;
}


//-------------------------------------------------------------------------
// HANDLE ACK PKT: ack packet and data packet is never aggregated or
// combined to be sent. If two end nodes send packets to each other,
// it use "data packet" to send data and "ack packet" to send an ack.
//-------------------------------------------------------------------------
void TransportTcpHandleAck(Node* node, Message* msg)
{
    struct abstract_tcphdr* ti = (struct abstract_tcphdr*)(msg->packet);
    struct abs_tcpcb* tp;
    const int tcprexmtthresh = ABS_TCP_REXMT_THRESH;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;
    struct tcpstat* tcp_stat = tcpLayer->tcpStat;
    int acked;
    int win;
    Address srcAdd;
    Address dstAdd;

    SetIPv4AddressInfo(&srcAdd, ti->th_src);
    SetIPv4AddressInfo(&dstAdd, ti->th_dst);

    tp = tcpcblookup(tcpLayer->head,
                     &dstAdd,
                     ti->th_dport,
                     &srcAdd,
                     ti->th_sport,
                     TCPCB_NO_WILDCARD);

    ERROR_Assert(tp!= NULL, "ABSTRACT-TCP: Can't find the connection\n");

    //Trace
    if (tcpLayer->trace &&
        (tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_BOTH ||
            tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_INPUT))
        TransportAbstractTcpTrace(node, tp, ti,
        (MESSAGE_ReturnPacketSize(msg) - sizeof(struct abstract_tcphdr)));

    if (SEQ_LEQ(ti->th_ack, tp->snd_una)) {
        if (tcp_stat) {
            tcp_stat->tcps_rcvdupack++;
        }
        //
        // Dup acks mean that packets have left the
        // network (they're now cached at the receiver)
        // so bump cwnd by the amount in the receiver
        // to keep a constant cwnd packets in the
        // network.
        //
        if (tp->t_timer[TCPT_REXMT] == 0 || ti->th_ack != tp->snd_una) {
            tp->t_dupacks = 0;
        }//THREE DUPLICATE ACKS
        else if (++tp->t_dupacks == tcprexmtthresh) {
        // RFC 2001 says When the third duplicate ACK in a row is received,
        // set ssthresh to one-half the current congestion window, cwnd,
        // but no less than two segments.  Retransmit the missing segment.
        // Set cwnd to ssthresh plus 3 times the segment size. This inflates
        // the congestion window by the number of segments that have left
        // the network and which the other end has cached.

            //tcp_seq onxt = tp->snd_nxt;
            unsigned int win = tp->snd_cwnd / 2 /tp->t_maxseg;

            if (win < 2)
                win = 2;

            tp->snd_ssthresh = win * tp->t_maxseg;
            tp->t_rtt = 0;

            if (tcp_stat) {
                tcp_stat->tcps_sndfastrexmitpack++;
                tcp_stat->tcps_sndrexmitpack++;
            }

            tp->t_ecnFlags |= TF_REXT_PACKET;
            tp->t_ecnFlags |= TF_CWND_REDUCED;
             //retransmission
            TransportTcpSendPacket(node, tp, ti->th_ack,
                tp->sendBuffer[tp->startSendBufferIndex%
                tp->sendBufferSize]);
            tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

            // Set cwnd to ssthresh plus 3 times the segment size.
            tp->snd_cwnd = tp->snd_ssthresh + tp->t_dupacks * tp->t_maxseg;

            if(tp->snd_cwnd < tp->sendBufferSize)
                tp->snd_max =
                    MAX(tp->snd_nxt, (tp->snd_cwnd + tp->snd_una));

            //if (SEQ_GT(onxt, tp->snd_nxt)) tp->snd_nxt = onxt;
            //return;
        }
        else if (tp->t_dupacks > tcprexmtthresh) {
            tp->snd_cwnd += tp->t_maxseg;
            if(tp->snd_cwnd < tp->sendBufferSize)
                tp->snd_max =
                    MAX(tp->snd_nxt, (tp->snd_cwnd + tp->snd_una));
            tcp_output(node, tp,tcpLayer->tcpNow, tcp_stat);
        }
        tp->rcv_adv = ti->th_win;
        //ACK is duplicate or obsolete
        return;
    }
    //
    // If the congestion window was inflated to account
    // for the other side's cached packets, retract it.
    //
    //After lost packet is recovered and new ack comes in
    //
    if (tp->t_dupacks >= tcprexmtthresh &&
        tp->snd_cwnd > tp->snd_ssthresh) {
        tp->snd_cwnd = tp->snd_ssthresh;
    }
    tp->t_dupacks = 0;

    if (SEQ_GT(ti->th_ack, tp->snd_wnd + tp->snd_una)) {
//        if (tcp_stat)
//            tcp_stat->tcps_rcvacktoomuch++;
        return;
    }

    acked = ti->th_ack - tp->snd_una;
    if (tcp_stat) {
        tcp_stat->tcps_rcvackpack++;
//        tcp_stat->tcps_rcvackbyte += acked;
    }

    {
        int ack_int = 0;
        int packetSizeSum = 0;
        UInt32 i =0;
        Int32 ackLen = 0;

        //FREE sender buffer
        for (i = tp->startSendBufferIndex;
            i < tp->startSendBufferIndex + tp->sendBufferSize; i++) {
            if (tp->sendBuffer[i%tp->sendBufferSize]){
                packetSizeSum += MESSAGE_ReturnPacketSize(
                    tp->sendBuffer[i % tp->sendBufferSize]);
                ack_int++;
                MESSAGE_Free(node, tp->sendBuffer[i % tp->sendBufferSize]);
                tp->sendBuffer[i%tp->sendBufferSize] = NULL;
                if( packetSizeSum >= acked) break;
            }
            else{
                break;
            }
        }

        if(tp->cached > (tp->sendBufferSize - tp->t_maxseg)){
            ackLen = tp->last_buf_pkt_size;
        }

        tp->startSendBufferIndex += (ack_int);

        if(tp->lastSendBufferIndex < tp->startSendBufferIndex) {
            //tp->lastSendBufferIndex = tp->startSendBufferIndex +1;
            tp->lastSendBufferIndex = tp->startSendBufferIndex;
        }
        tp->cached -= acked;

        //Application cannot send a packet to TCP which is larger
        //than t_maxseg(segment size of TCP)
        if(tp->cached <= (tp->sendBufferSize - tp->t_maxseg)) {
            Message* newMsg;
            TransportToAppDataSent* dataSent;

            newMsg = MESSAGE_Alloc(
                node, APP_LAYER, tp->app_type, MSG_APP_FromTransDataSent);
            MESSAGE_InfoAlloc(node, newMsg, sizeof(TransportToAppDataSent));
            dataSent = (TransportToAppDataSent*) MESSAGE_ReturnInfo(newMsg);
            dataSent->connectionId = tp->con_id;
            dataSent->length = ackLen;
            MESSAGE_Send(node, newMsg, TRANSPORT_DELAY);
        }
    }

    //
    // If we have a timestamp reply, update smoothed
    // round trip time.  If no timestamp is present but
    // transmit timer is running and timed sequence
    // number was acked, update smoothed round trip time.
    // Since we now have an rtt measurement, cancel the
    // timer backoff (cf., Phil Karn's retransmit alg.).
    // Recompute the initial retransmit timer.
    //
    if (tp->t_rtt && SEQ_GT(ti->th_ack, tp->t_rtseq)) {
        tcp_xmit_timer(tp,tp->t_rtt, tcp_stat);
    }
    tp->snd_wnd -= acked;

    //
    // If all outstanding data is acked, stop retransmit
    // timer and remember to restart (more output or persist).
    // If there is more data to be acked, restart retransmit
    // timer, using current (possibly backed-off) value.
    //
    if (tp->snd_wnd == 0) {
        tp->t_timer[TCPT_REXMT] = 0;
    }
    else {
        tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
    }

    {//update windows
        unsigned int cw = tp->snd_cwnd;
        unsigned int incr = tp->t_maxseg;

        if (cw > tp->snd_ssthresh) {
            incr = incr * incr / cw;
        }
        tp->snd_cwnd = MIN(cw + incr, (unsigned int) (tp->sendBufferSize));
        tp->rcv_adv = ti->th_win;
    }

    if(SEQ_GT(ti->th_ack, tp->snd_una))
        tp->snd_una = ti->th_ack;

    if (SEQ_LT(tp->snd_nxt, tp->snd_una))
        tp->snd_nxt = tp->snd_una;

    win = MIN(tp->snd_cwnd, tp->rcv_adv);
    tp->snd_max = MAX(tp->snd_nxt, (tp->snd_una + win));

    //if (tp->cached == 0 && tp->t_state == TCPS_CLOSE_WAIT) {
    if (tp->cached == 0 && tp->t_state == TCPS_FIN_WAIT_1) {
        tcp_close(node, &(tcpLayer->head), tp->con_id, tcpLayer->tcpStat);
    }
    else {
        tcp_output(node, tp, tcpLayer->tcpNow, tcp_stat);
    }
    return;
}


//-------------------------------------------------------------------------
// add pkt into receive list.
//-------------------------------------------------------------------------
void TransportTcpAddToRcvList(struct abs_tcpcb* tp,
                              tcp_seq seq,
                              Message* msg,
                              int len)
{
    tcp_seq index = tp->startRecvBufferIndex + (seq - tp->start_recv_seq);

    index %= tp->recvBufferSize;

    if (!tp->recvBuffer[index]) {
        tp->recvBuffer[index] = msg;
    }
    if (tp->last_recv_seq < seq) {
        tp->last_recv_seq = seq;
    }
    tp->rcv_adv -= (short)MESSAGE_ReturnPacketSize(msg);
}


//-------------------------------------------------------------------------
// process data pkt.
//-------------------------------------------------------------------------
BOOL TransportTcpHandleData(Node* node,
                            Message* msg,
                            TosType priority)
{
    //
    // Process the segment text, merging it into the retransmit list
    // and arranging for acknowledgment of receipt if necessary.
    // This process logically involves adjusting tp->rcv_wnd as data
    // is presented to the user.
    //
    BOOL free = FALSE;
    Address srcAdd;
    Address dstAdd;

    struct abstract_tcphdr* ti = (struct abstract_tcphdr*) msg->packet;
    struct abs_tcpcb* tp;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;
    struct tcpstat* tcp_stat= tcpLayer->tcpStat;

    int len = MESSAGE_ReturnPacketSize(msg) -
                sizeof(struct abstract_tcphdr);

    SetIPv4AddressInfo(&srcAdd, ti->th_src);
    SetIPv4AddressInfo(&dstAdd, ti->th_dst);


    //
    //th_ack includes app type if it's initial packet
    //since there is no explicit connection setup, information is handed
    // over using unused fields in tcp header
    //

    if (DEBUG) {
        printf("RECEIVE DATA HANDLING :%d %d %d %d\n",
            ti->th_dst, ti->th_src, ti->th_seq,
            MESSAGE_ReturnPacketSize(msg));
    }

    tp = tcpcblookup(tcpLayer->head,
                     &dstAdd,
                     ti->th_dport,
                     &srcAdd,
                     ti->th_sport,
                     TCPCB_NO_WILDCARD);


    //when a receiver receives a close message
    // -- there is no explicit close function
    if(tp && tp->t_state != TCPS_CLOSED && ti->th_seq == TCPS_CLOSE_WAIT &&
        ti->th_ack == TCPS_CLOSE_WAIT && ti->th_seq > 1) { //close pkt
        free = TRUE;
        tcp_close (node, &(tcpLayer->head), tp->con_id, tcp_stat);
        return free;
    }

    if(tp && tp->t_state == TCPS_CLOSED) {
        free = TRUE;
        return free;
    }
    if ((ti->th_seq == 1) && (tp == NULL)) {//initial, start clients (tp)
        tp = tcpcblookup(tcpLayer->head,
                         &dstAdd,
                         ti->th_dport,
                         &srcAdd,
                         ti->th_sport,
                         TCPCB_WILDCARD);

        if (tp == NULL) {//not listen
            ERROR_ReportWarning("Unidentified Application\n");
            free = TRUE;
            return free;
        }

        tp  = tcp_attach(node,
                         tcpLayer->head,
                         tp->app_type,
                         &dstAdd,
                         ti->th_dport,
                         &srcAdd,
                         ti->th_sport,
                         -1,
                         priority);

        TransportToAppOpenResult* tcpOpenResult;
        Message* newmsg = MESSAGE_Alloc(node, APP_LAYER,
            tp->app_type, MSG_APP_FromTransOpenResult);

        MESSAGE_InfoAlloc(node, newmsg, sizeof(TransportToAppOpenResult));
        tcpOpenResult = (TransportToAppOpenResult*)
                        MESSAGE_ReturnInfo(newmsg);
        tcpOpenResult->type = TCP_CONN_PASSIVE_OPEN;
        tcpOpenResult->localAddr = tp->local_addr;
        tcpOpenResult->localPort = tp->local_port;
        tcpOpenResult->remoteAddr = tp->remote_addr;
        tcpOpenResult->remotePort = tp->remote_port;
        tcpOpenResult->connectionId = tp->con_id;
        tcpOpenResult->uniqueId = tp->unique_id;
        MESSAGE_Send(node, newmsg, TRANSPORT_DELAY);
        tp->t_state = TCPS_ESTABLISHED;
        //tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_IDLE;
        tp->t_timer[TCPT_KEEP] = 0;

        abstract_tcp_sendseqinit(tp);
        tp->snd_wnd = 0;

        //Trace
        if (tcpLayer->trace &&
            (tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_BOTH ||
                tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_INPUT))
            TransportAbstractTcpTrace(node, tp, ti, len);

        MESSAGE_RemoveHeader(
            node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);
        TransportTcpSendToApp(node, tp->app_type, tp->con_id, len, msg);
        tp->last_recv_seq += len;
        tp->start_recv_seq = tp->last_recv_seq;
        tp->rcv_nxt = ti->th_seq + len;
        TransportTcpTransmitAck(node, tp, tcp_stat);
    }
    else {
        ERROR_Assert(tp!= NULL,
            "ABSTRACT-TCP: Can't find the connection\n");

        //Trace
        if (tcpLayer->trace &&
            (tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_BOTH ||
                tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_INPUT))
            TransportAbstractTcpTrace(node, tp, ti, len);

        if((ti->th_seq == 1) && (tp->rcv_nxt <= ti->th_seq)) {
            MESSAGE_RemoveHeader(
                node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);
            TransportTcpSendToApp(node, tp->app_type, tp->con_id, len, msg);
            tp->last_recv_seq += len;
            tp->start_recv_seq = tp->last_recv_seq;
            tp->rcv_nxt = ti->th_seq + len;
            TransportTcpTransmitAck(node, tp, tcp_stat);
        }
        else if (ti->th_seq == tp->rcv_nxt &&
            (ti->th_seq == (tp->last_recv_seq))) {
            MESSAGE_RemoveHeader(
                node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);
            TransportTcpSendToApp(node, tp->app_type, tp->con_id, len, msg);
            tp->rcv_nxt += len;
            tp->last_recv_seq += len;
            tp->start_recv_seq = tp->rcv_nxt;
            tp->t_dupacks = 0;
            //TEST -- acks
            //            TransportTcpTrace(node, tp, 0,
            //              "AddToRcvList, step6: delayed ack 0");

            // Delayed ACK is not properly implemented. RFC says "The
            // delayed ACK algorithm should be used by a TCP receiver,
            // but it must not excessively delay ACKs. Specifically,
            // an ACK should be generated for at least every second
            // full-sized segment (2*RMSS), and must be generated within
            // 200ms of the arrival of the first unacked packet."
            // But FAST Timer is not implemented into ABSTRACT TCP.
            if (tcpLayer->tcpDelayAcks) {
                if(((ti->th_seq -1)/tp->t_maxseg) % 2 == 0)
                    TransportTcpTransmitAck(node, tp, tcp_stat);
            }
            else {
                TransportTcpTransmitAck(node, tp, tcp_stat);
            }
        }
        else if (ti->th_seq >= tp->rcv_nxt) {
            if( (ti->th_seq - tp->start_recv_seq +
                    (short)MESSAGE_ReturnPacketSize(msg)) >
                        tp->recvBufferSize) {

                if (DEBUG) {
                    printf("too large seqNo \n");
                }

                free= TRUE;
            }
            else {
                MESSAGE_RemoveHeader(
                    node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);
                TransportTcpAddToRcvList(tp, ti->th_seq, msg, len);
                tcp_reass(node, tp, ti, tcp_stat);
                tp->t_dupacks = 0;
                TransportTcpTransmitAck(node, tp, tcp_stat);
            }
        }
        else {
            tp->t_dupacks++;
            TransportTcpTransmitAck(node, tp, tcp_stat);
            free = TRUE;
        }
    }
    return free;
}
