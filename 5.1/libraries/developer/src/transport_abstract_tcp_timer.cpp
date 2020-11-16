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
// This file contains Abstract TCP timer management routines.
//

#include <stdio.h>
#include <stdlib.h>

#include "api.h"
#include "network_ip.h"
#include "transport_abstract_tcp.h"
#include "transport_abstract_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_abstract_tcp_var.h"
#include "transport_abstract_tcp_proto.h"

#define DEBUG 0

//-------------------------------------------------------------------------
// TCP timer processing.
//-------------------------------------------------------------------------
static
struct abs_tcpcb* tcp_timers(Node* node,
                              struct abs_tcpcb* tp,
                              int timer,
                              UInt32 tcp_now,
                              struct tcpstat* tcp_stat)
{
    Message* msg;
    TransportToAppOpenResult* tcpOpenResult;
    int rexmt;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    switch (timer) {
    //
    // Retransmission timer went off.  Message has not
    // been acked within retransmit interval.  Back off
    // to a longer retransmit interval and retransmit one segment.
    //
    case TCPT_REXMT:
        if (++tp->t_rxtshift > TCP_MAXRXTSHIFT) {
            tp->t_rxtshift = TCP_MAXRXTSHIFT;
//            if (tcp_stat)
//                tcp_stat->tcps_timeoutdrop++;
            //tp = tcp_drop(node, tp, tcp_now, tcp_stat);
            break;
        }
//        if (tcp_stat)
//            tcp_stat->tcps_rexmttimeo++;
        rexmt = TCP_REXMTVAL(tp) * tcp_backoff[tp->t_rxtshift];

        if (DEBUG) {
            printf("1 TO REXMT TIMEOUT :%d %d %d %d %d\n",
                tp->t_rxtcur, tp->t_rttmin,
                tp->t_rtt, tp->t_srtt, tp->t_rttvar);
        }

        TCPT_RANGESET(tp->t_rxtcur, rexmt,
                      tp->t_rttmin, TCPTV_REXMTMAX);

        if (DEBUG) {
            printf("TO REXMT TIMEOUT :%d %d %d %d %d\n",
                tp->t_rxtcur, tp->t_rttmin, tp->t_rtt,
                tp->t_srtt, tp->t_rttvar);
        }

        tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

        //
        // If we backed off this far,
        // our srtt estimate is probably bogus.  Clobber it
        // so we'll take the next rtt measurement as our srtt;
        // move the current srtt into rttvar to keep the current
        // retransmit times until then.
        //
        if (tp->t_rxtshift > TCP_MAXRXTSHIFT / 4) {

            tp->t_rttvar +=
                (tp->t_srtt >> (TCP_RTT_SHIFT - TCP_DELTA_SHIFT));

            tp->t_srtt = 0;
        }

        // If timing a segment in this window, stop the timer.
        // The retransmitted segment shouldn't be timed.
        tp->t_rtt = 0;

        //
        // Close the congestion window down to one segment
        // (we'll open it by one segment for each ack we get).
        // Since we probably have a window's worth of unacked
        // data accumulated, this "slow start" keeps us from
        // dumping all that data as back-to-back packets (which
        // might overwhelm an intermediate gateway).
        //
        // There are two phases to the opening: Initially we
        // open by one mss on each ack.  This makes the window
        // size increase exponentially with time.  If the
        // window is larger than the path can handle, this
        // exponential growth results in dropped packet(s)
        // almost immediately.  To get more time between
        // drops but still "push" the network to take advantage
        // of improving conditions, we switch from exponential
        // to linear window opening at some threshhold size.
        // For a threshhold, we use half the current window
        // size, truncated to a multiple of the mss.
        //
        // (the minimum cwnd that will give us exponential
        // growth is 2 mss.  We don't allow the threshhold
        // to go below this.)
        //
        {
            unsigned int win;
            win = MIN(tp->snd_wnd, tp->snd_cwnd) / 2 / tp->t_maxseg;
            if (win < 2)
                win = 2;
            tp->snd_cwnd = tp->t_maxseg;

            tp->snd_ssthresh = win * tp->t_maxseg;
            tp->t_dupacks = 0;
        }

        if(tp->snd_nxt > tp->snd_una)
            tp->snd_nxt = tp->snd_una;

        tp->snd_max = tp->snd_nxt + tp->t_maxseg;

        //tp->lastSendBufferIndex = (tp->startSendBufferIndex +1);
        tp->lastSendBufferIndex = tp->startSendBufferIndex;

        tp->t_ecnFlags |= TF_CWND_REDUCED;
        //TransportTcpTrace(node, 0, 0, "Rext: timeout");

        if (DEBUG) {
            printf("REXMT TO :%d :%f :%d \n",
                node->nodeId, (double)node->getNodeTime(), tp->snd_una);
        }

        if(tp->t_state != TCPS_CLOSED) {
            if (tp->sendBuffer[tp->startSendBufferIndex %
                    tp->sendBufferSize])
            TransportTcpSendPacket(node, tp, tp->snd_una,
                tp->sendBuffer[tp->startSendBufferIndex %
                    tp->sendBufferSize]);

            if(tcpLayer->tcpStat)
                tcpLayer->tcpStat->tcps_sndrexmitpack++;
        }
        break;

    //
    // drop connection if it is not possible to establish the connection
    // within initial connect keep alive (TCPTV_KEEP_INIT)
    //
    case TCPT_KEEP:
//        if (tcp_stat)
//            tcp_stat->tcps_keeptimeo++;

        if (tp->snd_una == 1) {
            msg = MESSAGE_Alloc(node, APP_LAYER,
                    tp->app_type, MSG_APP_FromTransOpenResult);
            MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppOpenResult));
            tcpOpenResult = (TransportToAppOpenResult*)
                            MESSAGE_ReturnInfo(msg);
            tcpOpenResult->type = TCP_CONN_ACTIVE_OPEN;
            tcpOpenResult->localAddr = tp->local_addr;
            tcpOpenResult->localPort = tp->local_port;
            tcpOpenResult->remoteAddr = tp->remote_addr;
            tcpOpenResult->remotePort = tp->remote_port;
            tcpOpenResult->connectionId = -1;
            tcpOpenResult->uniqueId = tp->unique_id;

            MESSAGE_Send(node, msg, TRANSPORT_DELAY);
            tcp_canceltimers(tp);
        }
        break;

    default:
        break;
    }
    return (tp);
}

//-------------------------------------------------------------------------
// Tcp protocol timeout routine called every 500 ms.
// Updates the timers in all active tcb's and
// causes finite state machine actions if timers expire.
//-------------------------------------------------------------------------
void tcp_slowtimo(Node* node,
                  struct abs_tcpcb* head,
                  tcp_seq* tcp_iss,
                  UInt32* tcp_now,
                  struct tcpstat* tcp_stat)
{
    struct abs_tcpcb* tp;
    int i;

    tp = head;
    if (tp == NULL) {
        return;
    }

    // Search through tcpcb's and update active timers.
    for (; tp !=NULL; tp = tp->next) {
        for (i = 0; i < TCPT_NTIMERS; i++) {
            if (tp->t_timer[i] && --tp->t_timer[i] == 0) {
                (void) tcp_timers(node, tp, i,
                                  *tcp_now, tcp_stat);
            }
        }
        tp->t_idle++;
        tp->t_duration++;
        if (tp->t_rtt)
            tp->t_rtt++;
    }
    // iss value of every tpc connection will be start with 1.
    // so this increment is not required.
//    *tcp_iss += TCP_ISSINCR/PR_SLOWHZ; // increment iss for timestamps
//    (*tcp_now) ++;
}


//-------------------------------------------------------------------------
// Cancel all timers for TCP tp.
//-------------------------------------------------------------------------
void tcp_canceltimers(struct abs_tcpcb* tp)
{
    int i;

    for (i = 0; i < TCPT_NTIMERS; i++) {
        tp->t_timer[i] = 0;
    }
}
