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

// Ported from FreeBSD 2.2.2.
// This file contains TCP input routine, follows pages 65-76 of RFC 793.

// Copyright (c) 1982, 1986, 1988, 1990, 1993, 1994, 1995
// The Regents of the University of California.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. All advertising materials mentioning features or use of this software
//    must display the following acknowledgement:
//  This product includes software developed by the University of
//  California, Berkeley and its contributors.
// 4. Neither the name of the University nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.
//
//  @(#)tcp_input.c 8.12 (Berkeley) 5/24/95

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "transport_tcp.h"
#include "transport_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_tcp_var.h"
#include "transport_tcpip.h"
#include "transport_tcp_proto.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define bcopy4(d, s) \
       ((((unsigned char *)d)[0] = ((unsigned char *)s)[0]), \
        (((unsigned char *)d)[1] = ((unsigned char *)s)[1]), \
        (((unsigned char *)d)[2] = ((unsigned char *)s)[2]), \
        (((unsigned char *)d)[3] = ((unsigned char *)s)[3]))

#define NoDEBUG

// Setting TCP_TEST_PKT_DROP and recompiling is no more required.
// The drop count is set via the configuration file.
// Change this value to the number of drops required (range 1 to 4)
// e.g. #define TCP_TEST_PKT_DROP 3 for 3 drops
// The value should be 0 (zero) for no drops
// #define TCP_TEST_PKT_DROP 0

#define NoECN_DEBUG_TEST


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpEcnRttEnd
// PURPOSE      TCP should not react to congestion indications more than once
//              every window of data (or more loosely, more than once every
//              round-trip time). That is, the TCP sender's congestion window
//              should be reduced only once in response to a series of dropped
//              and/or CE packets from a single window of data.
//              In addition, the TCP source should not decrease the slow-start
//              threshold, ssthresh, if it has been decreased within the last
//              round trip time.
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpEcnRttEnd(struct tcpcb *tp)
{
    tp->t_ecnFlags &= ~TF_CWND_REDUCED;

    if (tp->t_ecnFlags & TF_SSTH_REDUCED) {
        tp->t_ecnFlags |= TF_SSTH_REDUCED_PRTT;
    }
    else {
        tp->t_ecnFlags &= ~TF_SSTH_REDUCED_PRTT;
    }
    tp->t_ecnFlags &= ~TF_SSTH_REDUCED;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpRespondEcnEcho
// PURPOSE      Receiver set the TF_MUST_ECHO bit, checking the condition.
//              Sender take the action if it is require to reduce the
//              congestion window.
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpRespondEcnEcho(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    BOOL *aCongestionExperienced)
{
    // After a TCP receiver sends an ACK packet with the ECN-Echo bit
    // set, that TCP receiver continues to set the ECN-Echo flag in
    // ACK packets until it receives a CWR packet.
    //
    if (tp->t_ecnFlags & TF_ECN) {
        if ((unsigned char)ti->ti_flags & (unsigned char)TH_CWR) {
            tp->t_ecnFlags &= ~TF_MUST_ECHO;
        }
        if (*aCongestionExperienced) {
            tp->t_ecnFlags |= TF_MUST_ECHO;
            *aCongestionExperienced = FALSE;
        }
    }

    //
    // TCP does not react to congestion indications more than once every
    // window of data (or more loosely, more than once every round-trip time)
    // That is, the TCP sender's congestion window should be reduced only
    // once in response to a series of dropped and/or CE packets from
    // a single window of data.
    // So when the source TCP reacts to an ECN-Echo ACK packet by
    // reducing its congestion window.  The source TCP notes the packets
    // that are outstanding at that time (i.e., packets that have not yet
    // been acknowledged). Until all these packets are acknowledged, the
    // source TCP does not react to another ECN indication of congestion.
    //
    if (tp->t_ecnFlags & TF_ECN
        && SEQ_GEQ(tp->snd_una, tp->ecnMaxSeq)) {
        tp->t_ecnFlags &= ~TF_ECN_STATE;
    }

    if ((tp->t_ecnFlags & TF_ECN)
            && (ti->ti_flags & TH_ECE)
            && ((ti->ti_flags & TH_SYN) == 0)
            && ((tp->t_ecnFlags & TF_ECN_STATE) == 0)) {
        if ((tp->t_ecnFlags & TF_CWND_REDUCED) == 0) {
            tp->snd_cwnd = tp->snd_cwnd / 2;
            if (tp->snd_cwnd < tp->t_maxseg) {
                tp->snd_cwnd = tp->t_maxseg;
                tp->t_timer[TCPT_REXMT] = 0;
            }
            tp->ecnMaxSeq = tp->snd_max;
            tp->t_ecnFlags |= TF_CWND_REDUCED;
            tp->t_ecnFlags |= TF_CWR_NOW;
            tp->t_ecnFlags |= TF_ECN_STATE;
#ifdef ECN_DEBUG_TEST
            printf ("\nCwndReduced due to ECN\n\n");
#endif // ECN_DEBUG_TEST
            TransportTcpTrace(node, tp, 0, "CwndReduced");
        }
        if (((tp->t_ecnFlags & TF_SSTH_REDUCED) == 0)
            && ((tp->t_ecnFlags & TF_SSTH_REDUCED_PRTT) == 0)) {

            if (tp->snd_cwnd < tp->snd_ssthresh) {
                tp->snd_ssthresh = tp->snd_cwnd;
                tp->snd_ssthresh = MAX(tp->snd_ssthresh, 2 * tp->t_maxseg);
                tp->t_ecnFlags |= TF_SSTH_REDUCED;
                TransportTcpTrace(node, tp, 0, "ssthreshReduced");
            }
        }
    }
}


//-------------------------------------------------------------------------//
// Timer function used to simply call tcp_output() once
// data is passed to the application layer.
//-------------------------------------------------------------------------//
static
void TransportTcpSetTimerForOutput(Node *node)
{
    Message *newMsg = MESSAGE_Alloc(
        node, TRANSPORT_LAYER, TransportProtocol_TCP,
                            MSG_TRANSPORT_Tcp_CheckTcpOutputTimer);

    MESSAGE_Send(node, newMsg, 0);
}


//-------------------------------------------------------------------------//
// Collect new round-trip time estimate
// and update averages and current timeout.
//-------------------------------------------------------------------------//
static
void tcp_xmit_timer(
    struct tcpcb *tp,
    int rtt,
    struct tcpstat *tcp_stat)
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

    TransportTcpEcnRttEnd(tp);

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

    //
    // We received an ack for a packet that wasn't retransmitted;
    // it is probably safe to discard any error indications we've
    // received recently.  This isn't quite right, but close enough
    // for now (a route might have failed after we sent a segment,
    // and the return path might not be symmetrical).
    //
    tp->t_softerror = 0;

    //if (tcp_stat)
    //    tcp_stat->tcps_rttupdated++;
}


//-------------------------------------------------------------------------//
// Remove len bytes of data from a tcp segment.
//-------------------------------------------------------------------------//
static
void data_adj(
    struct tcpiphdr *ti,
    int len)
{
    unsigned char *old_start, *new_start;

    if (len < ti->ti_len){
        old_start = (unsigned char *) (ti + 1) ;
        new_start = old_start + len;
        memmove(old_start, new_start, ti->ti_len - len);
    }
}


//-------------------------------------------------------------------------//
// Deliver data to application.
//-------------------------------------------------------------------------//
static
void submit_data(
    Node *node,
    AppType app_type,
    int conn_id,
    unsigned char *datap,
    struct tcpiphdr* ti,
    int virtual_length,
    struct tcpcb *tp)
{
    Message *msg;
    TransportToAppDataReceived *tcpDataReceived;
    TransportDataTcp *tcpLayer =
        (TransportDataTcp *) node->transportData.tcp;

    int total_length = ti->ti_len;
    Message* origMsg = ti->msg;

    if (total_length > 0)
    {
        msg = MESSAGE_Alloc(
            node,
            APP_LAYER,
            app_type,
            MSG_APP_FromTransDataReceived);

        // Copy info field of the original message.
        if (origMsg != NULL)
        {
            if (origMsg->infoArray.size() > 0)
            {
                // Copy the info fields.
                MESSAGE_CopyInfo(node, msg, origMsg);
            }
        }
        MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppDataReceived));
        tcpDataReceived = (TransportToAppDataReceived *)
                          MESSAGE_ReturnInfo(msg);
        tcpDataReceived->connectionId = conn_id;

        if (total_length < virtual_length)
        {
            MESSAGE_PacketAlloc(node, msg, total_length, TRACE_UNDEFINED);
            memcpy(msg->packet, datap, total_length);
        }
        else
        {
            int actual_length = total_length - virtual_length;

            if (app_type == APP_SUPERAPPLICATION_SERVER)
            {
                MESSAGE_PacketAlloc(
                    node,
                    msg,
                    actual_length,
                    TRACE_SUPERAPPLICATION);
            }
            else
            {
                MESSAGE_PacketAlloc(node,
                                    msg,
                                    actual_length,
                                    TRACE_UNDEFINED);
            }

            if (actual_length > 0)
            {
                memcpy(MESSAGE_ReturnPacket(msg), datap, actual_length);
            }
            if (virtual_length > 0)
            {
                MESSAGE_AddVirtualPayload(node, msg, virtual_length);
            }

            if (tcpLayer->tcpStatsEnabled)
            {
                tcpLayer->newStats->AddSentToUpperLayerDataPoints(
                    node,
                    msg,
                    ti->ti_src,
                    ti->ti_dst,
                    ti->ti_sport,
                    ti->ti_dport);
            }

            MESSAGE_Free(node, origMsg);
            MESSAGE_Send(node, msg, TRANSPORT_DELAY);
        }
    }
    else
    {
        MESSAGE_Free(node, origMsg);
    }
}


//-------------------------------------------------------------------------//
// Reassemble received packets.
// Deliver data to application if in sequence.
//-------------------------------------------------------------------------//
static
int tcp_reass(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    struct tcpstat *tcp_stat,
    int virtual_len,
    Message* origMsg)
{
    struct tcpiphdr *q, *ti1, *q1;
    int flags;
    struct inpcb *inp = tp->t_inpcb;

    // Call with ti==0 after become established to
    // force pre-ESTABLISHED data up to user

    if (ti == 0)
        goto present;

     // Find a segment which begins after this one does.
    for (q = tp->seg_next; q != (struct tcpiphdr *)tp;
        q = (struct tcpiphdr *)q->ti_next)
        if (SEQ_GT(q->ti_seq, ti->ti_seq))
            break;

     // If there is a preceding segment, it may provide some of
     // our data already.  If so, drop the data from the incoming
     // segment.  If it provides all of our data, drop us.

    if ((struct tcpiphdr *)q->ti_prev != (struct tcpiphdr *)tp) {
        int i;
        q = (struct tcpiphdr *)q->ti_prev;
        // conversion to int (in i) handles seq wraparound
        i = q->ti_seq + q->ti_len - ti->ti_seq;

        if (i > 0) {
            if (i >= ti->ti_len) {
                //if (tcp_stat) {
                    //tcp_stat->tcps_rcvduppack++;
                    //tcp_stat->tcps_rcvdupbyte += ti->ti_len;
                //}
                //
                // Try to present any queued data
                // at the left window edge to the user.
                // This is needed after the 3-WHS
                // completes.
                //
                MEM_free(ti);
                goto present;
            }
            data_adj(ti, i);
            ti->ti_len = (short) (ti->ti_len - i);
            ti->ti_seq += i;
        }
        q = (struct tcpiphdr *)(q->ti_next);
    }
    //if (tcp_stat) {
        //tcp_stat->tcps_rcvoopack++;
        //tcp_stat->tcps_rcvoobyte += ti->ti_len;
    //}

    // While we overlap succeeding segments trim them or,
    // if they are completely covered, dequeue them.

    while (q != (struct tcpiphdr *)tp) {
        int i = (ti->ti_seq + ti->ti_len) - q->ti_seq;
        if (i <= 0)
            break;
        if (i < q->ti_len) {
            data_adj(q, i);
            q->ti_len = (short) (q->ti_len - i);
            q->ti_seq += i;
            break;
        }
        q1 = q;
        q = (struct tcpiphdr *)q->ti_next;
        remque_ti((struct tcpiphdr *)q->ti_prev);
        MEM_free(q1);
    }

    // Stick new segment in its place.
    insque_ti(ti, (struct tcpiphdr *)q->ti_prev);

present:

    // Present data to user, advancing rcv_nxt through
    // completed sequence space.

    if (!TCPS_HAVEESTABLISHED(tp->t_state))
        return (0);
    ti = tp->seg_next;
    if (ti == (struct tcpiphdr *)tp || ti->ti_seq != tp->rcv_nxt)
        return (0);
    do {
        tp->rcv_nxt += ti->ti_len;
        flags = ti->ti_flags & TH_FIN;

        remque_ti(ti);

        submit_data(node, inp->app_proto_type, inp->con_id,
                    (unsigned char *)(ti + 1), ti, ti->ti_vlen, tp);
        ti1 = ti;
        ti = (struct tcpiphdr *)ti->ti_next;
        MEM_free(ti1);
    } while (ti != (struct tcpiphdr *)tp && ti->ti_seq == tp->rcv_nxt);

    if (TCP_VARIANT_IS_SACK(tp)) {
        TransportTcpSackUpdateNewRcvNxt(tp, tp->rcv_nxt);
        TransportTcpTrace(node, 0, 0, "NewRcvNxt: from tcp_reass");
    }
    return (flags);
}


//-------------------------------------------------------------------------//
//  Determine a reasonable value for maxseg size.
//  If the route is known, check route for mtu.
//  If none, use an mss that can be handled on the outgoing
//  interface without forcing IP to fragment; if bigger than
//  an mbuf cluster (MCLBYTES), round down to nearest multiple of MCLBYTES
//  to utilize large mbufs.  If no route is found, route has no mtu,
//  or the destination isn't local, use a default, hopefully conservative
//  size (usually 512 or the default IP max size, but no more than the mtu
//  of the interface), as we can't discover anything about intervening
//  gateways or networks.  We also initialize the congestion/slow start
//  window to be a single segment if the destination isn't local.
//  While looking at the routing entry, we also initialize other path-dependent
//  parameters from pre-set or cached values in the routing entry.
//
//  Also take into account the space needed for options that we
//  send regularly.  Make maxseg shorter by that amount to assure
//  that we can send maxseg amount of data even when the options
//  are present.  Store the upper limit of the length of options plus
//  data in maxopd.
//
//  NOTE that this routine is only called when we process an incoming
//  segment, for outgoing segments only tcp_mssopt is called.
//
//-------------------------------------------------------------------------//
static
void tcp_mss(
    struct tcpcb *tp,
    int offer,
    struct tcpstat *tcp_stat)
{
    int mss;
    UInt32 bufsize;
    struct inpcb *inp = tp->t_inpcb;

     // Offer == 0 means that there was no MSS on the SYN segment,
     // in this case we use default or user input value TCP-MSS.

    if (offer == 0)
        offer = tp->mss;
    else
         // Sanity check: make sure that maxopd will be large
         // enough to allow some data on segments even is the
         // all the option space is used (40bytes).  Otherwise
         // funny things may happen in tcp_output.
        offer = MAX(offer, TCP_MIN_MSS);

    mss = MIN(tp->t_maxseg, (unsigned int) offer);

    // If there's a pipesize, change the socket buffer to that size.
    // if the mss is larger than the buffer size, derease the mss.

    bufsize = InpSendBufGetSize(&inp->inp_snd);

    if (bufsize < (UInt32) mss)
        mss = bufsize;

     // maxopd stores the maximum length of data AND options
     // in a segment; maxseg is the amount of data in a normal
     // segment.  We need to store this value (maxopd) apart
     // from maxseg, because now every segment carries options
     // and thus we normally have somewhat less data in segments.

    tp->t_maxopd = mss;

    if (!TCP_VARIANT_IS_RENO(tp)) {
        if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
             (tp->t_flags & TF_RCVD_TSTMP) == TF_RCVD_TSTMP)
            mss -= TCPOLEN_TSTAMP_APPA;
    }
    tp->t_maxseg = mss;
    tp->snd_cwnd = mss;

}


//-------------------------------------------------------------------------//
//  This function processes the Seven TCP options supported by Qualnet.
//  the Seven options are EOL, NOP, MSS, Window scale, Timestamp,
//  Sack permitted and Sack options.
//-------------------------------------------------------------------------//
static
void tcp_dooptions(
    struct tcpcb *tp,
    unsigned char *cp,
    int cnt,
    struct tcpiphdr *ti,
    struct tcpopt *topt,
    UInt32 tcp_now,
    struct tcpstat *tcp_stat)
{
    unsigned short mss = 0;
    int opt, optlen;
    unsigned char *optp = cp;
    unsigned char *datap = cp + cnt;

    for (; cnt > 0; cnt -= optlen, cp += optlen) {
        opt = cp[0];
        if (opt == TCPOPT_EOL) {
            break;
        }
        if (opt == TCPOPT_NOP) {
            optlen = 1;
        } else {
            optlen = cp[1];
            if (optlen <= 0)
                break;
        }

        switch (opt) {

        default:
            continue;

        case TCPOPT_MAXSEG:
            if (optlen != TCPOLEN_MAXSEG)
                continue;
            if (!(ti->ti_flags & TH_SYN))
                continue;
            memcpy((char *) &mss, (char *) cp + 2, sizeof(mss));
            break;

        case TCPOPT_WINDOW:
            if (TCP_VARIANT_IS_RENO(tp)) {
                break;
            }
            if (optlen != TCPOLEN_WINDOW)
                continue;
            if (!(ti->ti_flags & TH_SYN))
                continue;
            tp->t_flags |= TF_RCVD_SCALE;
            tp->requested_s_scale = (unsigned char) (MIN(cp[2], TCP_MAX_WINSHIFT));
            break;

        case TCPOPT_TIMESTAMP:
            if (TCP_VARIANT_IS_RENO(tp)) {
                break;
            }
            if (optlen != TCPOLEN_TIMESTAMP)
                continue;
            topt->to_flag |= TOF_TS;
            bcopy4(((char *)&topt->to_tsval), ((char *)cp + 2));
            bcopy4(((char *)&topt->to_tsecr), ((char *)cp + 6));

            // A timestamp received in a SYN makes
            // it ok to send timestamp requests and replies.

            if (ti->ti_flags & TH_SYN) {
                tp->t_flags |= TF_RCVD_TSTMP;
                tp->ts_recent = topt->to_tsval;
                tp->ts_recent_age = tcp_now;
            }
            break;

        case TCPOPT_SACK_PERMITTED:
            if (optlen != TCPOLEN_SACK_PERMITTED) {
                continue;
            }
            if (ti->ti_flags & TH_SYN) {
                tp->tcpVariant = TCP_VARIANT_SACK;
            }
            continue;

        case TCPOPT_SACK:
            if (TCP_VARIANT_IS_SACK(tp)) {
                TransportTcpSackReadOptions(tp, cp, optlen);
            }
            continue;
        }
    }

    if (ti->ti_flags & TH_SYN) {
        tcp_mss(tp, mss, tcp_stat); // sets t_maxseg
    }
    // remove options //
    memmove(optp, datap, ti->ti_len);
}


//-------------------------------------------------------------------------//
// TCP input routine, follows pages 65-76 of the
// protocol specification dated September, 1981 very closely.
//-------------------------------------------------------------------------//
void tcp_input(
    Node *node,
    unsigned char *payload,
    int actual_len,
    int virtual_len,
    TosType priority,
    struct inpcb *p_head,
    tcp_seq *tcp_iss,
    UInt32 tcp_now,
    struct tcpstat *tcp_stat,
    Message* origMsg)
{
    struct tcpiphdr *ti;
    struct inpcb *inp;
    struct tcpcb *tp = NULL;

    char *tcp_seg;
    const int tcprexmtthresh = 3;

    unsigned char *optp = NULL;
    unsigned char *datap = NULL;

    int optlen = 0;
    int len, tlen, off;
    int tiflags;

    int total_len = actual_len + virtual_len + sizeof(struct tcpiphdr) -
        (sizeof(struct tcphdr) + sizeof(struct ipovly));

    int todrop, acked, ourfinisacked, needoutput = 0;
    int iss = 0;
    struct tcpopt topt;
    UInt32 tiwin;
    int to_accept = 0;
    unsigned int flag;
    UInt32 aBufReadCount;
    BOOL aCongestionExperienced = FALSE;
    BOOL dropped_packet = FALSE;

    TransportDataTcp *tcpLayer = (TransportDataTcp *)
                                 node->transportData.tcp;

    //int dropCount = TCP_TEST_PKT_DROP;    // now, a user input
    tcp_seq dropValues[] = { 14002, 28002, 26002, 24002};
    static int dropFlag[] = { 1, 1, 1, 1};

    tcp_seg = MESSAGE_PayloadAlloc(node, total_len);
    assert(tcp_seg != NULL);

    ti = (struct tcpiphdr *)tcp_seg;

    memcpy (
        &ti->ti_i,
        payload,
        sizeof (struct ipovly));

    memcpy (
        &ti->ti_t,
        payload + sizeof (struct ipovly),
        sizeof (struct tcphdr));

    memcpy (
        ti + 1,
        payload + (sizeof (struct tcphdr) + sizeof (struct ipovly)),
        actual_len - (sizeof (struct tcphdr) + sizeof (struct ipovly)));

    // Copy the message.
    ti->msg = MESSAGE_Duplicate(node, origMsg);
    memset((char *)&topt, 0, sizeof(topt));

    if (tcp_stat) {
        tcp_stat->tcps_rcvtotal++;
    }

    // Get IP and TCP header together. Assume ip options have been stripped.
    // Note: IP leaves IP header in tcp_seg.
    //

    if (total_len <
        (signed) (sizeof (struct tcphdr) + sizeof (struct ipovly))) {
        int hdrSize = sizeof(struct tcpiphdr);

        if (tcp_stat)
            tcp_stat->tcps_rcvshort++;

        ERROR_Assert(hdrSize < MAX_CACHED_PAYLOAD_SIZE,
                     "MAX_CACHED_PAYLOAD_SIZE is too small.");
        // Free the message.
        MESSAGE_Free(node, ti->msg);
        MESSAGE_PayloadFree(node, tcp_seg, total_len);
        return;
    }

    //
    // Checksum extended TCP header and data.
    // Note here assumes ip hasn't subtracted ip header
    // length from ip_len (different from original code).
    // Assuming here that the source and destination IP address
    // fields and the packet length field have been correctly
    // set.
    //
    len = ti->ti_len;

    if (ti->ti_x1 & TI_ECE) {
        aCongestionExperienced = TRUE;
    }

    tlen = len - sizeof(struct ipovly);
    ti->ti_len = (short) tlen;
    ti->ti_vlen = virtual_len;

    // Zero and set this stuff in the "Extended pseudoheader"
    // for the checksum

    ti->ti_prev = 0;
    ti->ti_next = 0;
    ti->ti_x1 = 0;
    ti->ti_pr = IPPROTO_TCP;

    /* Checksum commented out because QualNet currently does not
       model bit errors
       If used, requires modification to the pseudoheader
       as per RFC 1883, section 8.1.
    ti->ti_sum = in_cksum( (unsigned short *) tcp_seg, len);
    if (ti->ti_sum) {
        if (tcp_stat)
            tcp_stat->tcps_rcvbadsum++;
        goto drop;
    }
    */

    // Check that TCP offset makes sense,
    // pull out TCP options and adjust length.      XXX

    off = tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off) << 2;

#ifdef ADDON_DB
             HandleTransportDBEvents(
                 node,
                 origMsg, //origMsg,
                 -1,
                 "TCPReceiveFromLower",
                 ti->ti_sport,
                 ti->ti_dport,
                 off,
                 tlen);
             // msgSize = tcp_hdr_size + optlen + payload
#endif
    if (off < (signed) (sizeof (struct tcphdr)) || off > tlen) {
        if (tcp_stat)
            tcp_stat->tcps_rcvbadoff++;
        goto drop;
    }
    tlen -= off;  // data length //
    ti->ti_len = (short) tlen;
    optlen = off - sizeof (struct tcphdr);
    optp = (unsigned char *) tcp_seg + sizeof(struct tcpiphdr);
    datap = optp + optlen;
    tiflags = ti->ti_flags;

    #ifdef DEBUG
        {
            char clockStr[100];
            char ipAddrStr[MAX_STRING_LENGTH];
            ctoa(node->getNodeTime(), clockStr);

            IO_ConvertIpAddressToString(&ti->ti_src, ipAddrStr);
            printf("Node %ld got segment from node %s at time %s\n",
                   node->nodeId,
                   ipAddrStr,
                   clockStr);
            printf("    size = %d\n", total_len);
            printf("    seqno = %d\n", ti->ti_seq);
            printf("    ack = %d\n", ti->ti_ack);
            printf("    type =");
        }

        if (tiflags & TH_FIN)
        {
            printf(" FIN |");
        }

        if (tiflags & TH_SYN)
        {
            printf(" SYN |");
        }

        if (tiflags & TH_RST)
        {
            printf(" RST |");
        }

        if (tiflags & TH_PUSH)
        {
            printf(" PUSH |");
        }

        if (tiflags & TH_ACK)
        {
            printf(" ACK |");
        }

        if (tiflags & TH_URG)
        {
            printf(" URG |");
        }
        printf("\n");
    #endif

    // Drop some data packets (for testing)
    // This section works if TCP-RANDOM-DROP-PERCENT is used in user input

    {
        double aDropPercent = tcpLayer->tcpRandomDropPercent;
        if (aDropPercent > 0 && !(tiflags & (TH_FIN | TH_SYN | TH_RST))) {
            if (RANDOM_erand(tcpLayer->seed) < aDropPercent/100) {
                TransportTcpTrace(node, 0, 0, "random drop");
                if (tcp_stat)
                {
                    tcp_stat->tcps_rcvtotal--;  // this was incremented above
                }
                goto drop;
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
            if (ti->ti_seq == dropValues[counter] && dropFlag[counter]) {
                tcp_stat->tcps_rcvtotal--;  // this was incremented above
                TransportTcpTrace(node, 0, 0, "specific packet drop");
                dropFlag[counter]--;
                goto drop;
            }
        }
    }

    /* Uncomment this if custom drops are required.
    // Drop some specific data packets (for testing)
    // The values to drop are set at the top of this routine
    if (dropCount) {
        int counter;
        for (counter = 0; counter < dropCount; counter++) {
            if (ti->ti_seq == dropValues[counter] && dropFlag[counter]) {
                tcp_stat->tcps_rcvtotal--;  // this was incremented above
                TransportTcpTrace(node, 0, 0, "specific packet drop");
                dropFlag[counter]--;
                goto drop;
            }
        }
    }
    */

    if (tcp_stat) {
        if (tlen > 0){
            tcp_stat->tcps_rcvpack ++;
            //tcp_stat->tcps_rcvbyte += ti->ti_len;
        }
        else if (tiflags & (TH_SYN|TH_FIN|TH_RST))
            tcp_stat->tcps_rcvctrl ++;
    }

    // Locate pcb for segment.

findpcb:

    inp = in_pcblookup(p_head, &ti->ti_dst, ti->ti_dport,
                       &ti->ti_src, ti->ti_sport, INPCB_NO_WILDCARD);

    //
    // PCB doesn't exist, check if it's a connection request.
    // If so, prepare to accept the connection.  Otherwise, drop
    // the packet.
    //
    if (inp == p_head){
        inp = in_pcblookup(p_head, &ti->ti_dst, ti->ti_dport,
                           &ti->ti_src, ti->ti_sport, INPCB_WILDCARD);
        if (inp != p_head) {
            to_accept = 1;
        } else {
            goto dropwithreset;
        }
    }

    tp = intotcpcb(inp);

    TransportTcpTrace(node, tp, ti, "input");

    // Here this function is called by Receiver.
    TransportTcpRespondEcnEcho(node, tp, ti, &aCongestionExperienced);

#ifdef ADDON_DB
    // insert here

    // Here we add the packet to the Network database.
    // Gather as much information we can for the database.

    /*HandleTransportDBEvents(
        node,
        ti->msg, //origMsg,
        tp->outgoingInterface,
        "TCPSendToUpper",
        ti->ti_sport,
        ti->ti_dport,
        sizeof (struct tcphdr) + optlen,
        sizeof (struct tcphdr) + optlen + tlen);
        // msgSize = tcp_hdr_size + optlen + payload*/

    HandleTransportDBSummary(
        node,
        ti->msg, //origMsg,
        tp->outgoingInterface,
        "TCPReceive",
        ti->ti_src,
        ti->ti_dst,
        ti->ti_sport,
        ti->ti_dport,
        sizeof (struct tcphdr) + optlen + tlen);

    HandleTransportDBAggregate(
        node,
        ti->msg, //origMsg,
        tp->outgoingInterface,
        "TCPReceive",
        sizeof (struct tcphdr) + optlen + tlen);
#endif

    // Data packet
    if (tcpLayer->tcpStatsEnabled)
    {
        tcpLayer->newStats->AddSegmentReceivedDataPoints(
            node,
            ti->msg,
            STAT_Unicast,
            0,
            tlen,
            sizeof(struct tcphdr) + optlen,
            ti->ti_src,
            ti->ti_dst,
            ti->ti_sport,
            ti->ti_dport);
    }
    if (tp->t_state == TCPS_CLOSED) {
        goto drop;
    }

    // Unscale the window into a 32-bit value. //
    if (!TCP_VARIANT_IS_RENO(tp) && (tiflags & TH_SYN) == 0) {
        tiwin = ti->ti_win << tp->snd_scale;
    } else {
        tiwin = ti->ti_win;
    }

    if (to_accept) {
        to_accept = 0;
        if ((tiflags & (TH_RST|TH_ACK|TH_SYN)) != TH_SYN) {

            // Note: dropwithreset makes sure we don't
            // send a RST in response to a RST.

            if (tiflags & TH_ACK) {
                //if (tcp_stat)
                    //tcp_stat->tcps_badsyn++;
                goto dropwithreset;
            }
            goto drop;
        }

        inp = (struct inpcb *)tcp_attach(node, p_head, inp->app_proto_type,
                                         &ti->ti_dst,  ti->ti_dport,
                                         &ti->ti_src, ti->ti_sport,
                                         -1, priority);

        if (inp == 0) {
            goto drop;
        }
        tp = intotcpcb(inp);
        tp->t_state = TCPS_LISTEN;
        if (!TCP_VARIANT_IS_RENO(tp)) {
            // Compute proper scaling value from buffer space //
            while (tp->request_r_scale < TCP_MAX_WINSHIFT &&
               (UInt32) (TCP_MAXWIN << tp->request_r_scale) <
                    inp->inp_rcv_hiwat)
                tp->request_r_scale++;
        }
    }

    // Segment received on connection.
    // Reset idle time and keep-alive timer.

    tp->t_idle = 0;
    if (TCPS_HAVEESTABLISHED(tp->t_state)) {
        tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_IDLE;
    }

    // Process options if not in LISTEN state,
    // else do it below (after getting remote address).

    if (tp->t_state != TCPS_LISTEN){
        tcp_dooptions(tp, optp, optlen, ti, &topt, tcp_now, tcp_stat);
        datap = optp;
    }

    //
    // Header prediction: check for the two common cases
    // of a uni-directional data xfer.  If the packet has
    // no control flags, is in-sequence, the window didn't
    // change and we're not retransmitting, it's a
    // candidate.  If the length is zero and the ack moved
    // forward, we're the sender side of the xfer.  Just
    // free the data acked & wake any higher level process
    // that was blocked waiting for space.  If the length
    // is non-zero and the ack didn't move, we're the
    // receiver side.  If we're getting packets in-order
    // (the reassembly queue is empty), add the data to
    // the socket buffer and note that we need a delayed ack.
    // Make sure that the hidden state-flags are also off.
    // Since we check for TCPS_ESTABLISHED above, it can only
    // be TH_NEEDSYN.
    //
    if (tp->t_state == TCPS_ESTABLISHED &&
        (tiflags & (TH_SYN|TH_FIN|TH_RST|TH_ACK)) == TH_ACK &&
        ((tp->t_flags & (TF_NEEDSYN|TF_NEEDFIN)) == 0) &&
        ((topt.to_flag & TOF_TS) == 0 ||
         TSTMP_GEQ(topt.to_tsval, tp->ts_recent)) &&
        ti->ti_seq == tp->rcv_nxt &&
        tiwin && tiwin == tp->snd_wnd &&
        tp->snd_nxt == tp->snd_max) {

         // If last ACK falls within this segment's sequence numbers,
         // record the timestamp.
         // NOTE that the test is modified according to the latest
         // proposal of the tcplw@cray.com list (Braden 1993/04/26).

        if (!TCP_VARIANT_IS_RENO(tp)) {
            if ((topt.to_flag & TOF_TS) != 0 &&
               SEQ_LEQ(ti->ti_seq, tp->last_ack_sent)) {
                tp->ts_recent_age = tcp_now;
                tp->ts_recent = topt.to_tsval;
            }
        }

        if (ti->ti_len == 0) {
            if (SEQ_GT(ti->ti_ack, tp->snd_una) &&
                    SEQ_LEQ(ti->ti_ack, tp->snd_max) &&
                tp->snd_cwnd >= tp->snd_wnd &&
                tp->t_dupacks < tcprexmtthresh) {

                 // this is a pure ack for outstanding data.

                //if (tcp_stat)
                //    ++tcp_stat->tcps_predack;
                if (!TCP_VARIANT_IS_RENO(tp) &&
                        (topt.to_flag & TOF_TS) != 0) {
                    tcp_xmit_timer(
                        tp, tcp_now - topt.to_tsecr + 1, tcp_stat);
                }
                else if (tp->t_rtt && SEQ_GT(ti->ti_ack, tp->t_rtseq)) {
                    tcp_xmit_timer(tp, tp->t_rtt, tcp_stat);
                }
                acked = ti->ti_ack - tp->snd_una;
                inp->info_buf->pktAcked += acked;
                if (tcp_stat) {
                    tcp_stat->tcps_rcvackpack++;
                    //tcp_stat->tcps_rcvackbyte += acked;
                }
                del_buf(node, inp, acked, ti->ti_ack);
                tp->snd_una = ti->ti_ack;

                if (TCP_VARIANT_IS_SACK(tp)) {
                    TransportTcpSackUpdateNewSndUna(tp, tp->snd_una);
                    TransportTcpTrace(
                        node, 0,0, "NewSndUna: hdr prediction");
                }

                 // If all outstanding data are acked, stop
                 // retransmit timer, otherwise restart timer
                 // using current (possibly backed-off) value.
                 // If process is waiting for space,
                 // wakeup/selwakeup/signal.  If data
                 // are ready to send, let tcp_output
                 // decide between more output or persist.

                if (tp->snd_una == tp->snd_max)
                    tp->t_timer[TCPT_REXMT] = 0;
                else if (tp->t_timer[TCPT_PERSIST] == 0)
                    tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;

                if (InpSendBufGetCount(&inp->inp_snd, BUF_READ))
                    tcp_output(node, tp, tcp_now, tcp_stat);

                // Free the message.
                MESSAGE_Free(node, ti->msg);
                MESSAGE_PayloadFree(node, tcp_seg, total_len);
                return;
            }
        } else if (ti->ti_ack == tp->snd_una &&
            tp->seg_next == (struct tcpiphdr *)tp &&
            (UInt32) ti->ti_len <= sbspace(inp)) {

             // this is a pure, in-sequence data packet
             // with nothing on the reassembly queue and
             // we have enough buffer space to take it.

            tp->rcv_nxt += ti->ti_len;
            //if (tcp_stat)
                //++tcp_stat->tcps_preddat;

            if (TCP_VARIANT_IS_SACK(tp)) {
                TransportTcpSackUpdateNewRcvNxt(tp, tp->rcv_nxt);
                TransportTcpTrace(node, 0, 0, "NewRcvNxt: hdr prediction");
            }

            if (!tcpLayer->tcpDelayShortPackets) {

                 //  If this is a short packet, then ACK now - with Nagel
                 //   congestion avoidance sender won't send more until
                 //   he gets an ACK.

                if (tiflags & TH_PUSH) {
                    tp->t_flags |= TF_ACKNOW;
                    TransportTcpTrace(node, 0, 0, "short path, ACK now");
                    tcp_output(node, tp, tcp_now, tcp_stat);
                } else if (!tcpLayer->tcpDelayAcks) {
                    tp->t_flags |= TF_ACKNOW;
                } else {
                    tp->t_flags |= TF_DELACK;
                }
            }
            else if (!tcpLayer->tcpDelayAcks) {
                    tp->t_flags |= TF_ACKNOW;
            }
            else {
                tp->t_flags |= TF_DELACK;
            }

#ifdef ADDON_DB
             HandleTransportDBEvents(
        node,
        ti->msg, //origMsg,
        tp->outgoingInterface,
        "TCPSendToUpper",
        ti->ti_sport,
        ti->ti_dport,
        optlen,
        optlen + tlen);
        // msgSize = tcp_hdr_size + optlen + payload
#endif
            // submit data to application.
            submit_data(node, inp->app_proto_type, inp->con_id,
                        datap, ti, virtual_len, tp);

            //
            // Call tcp_output() immediately after sending data
            // to application.  This is to simulate what actually happens in
            // real systems where once the user process grabs data from the
            // receiver's buffer, the user process then calls tcp_output()
            // to determine whether or not to reply with an ACK.  This is
            // used to handle the delay ACK feature.
            //
            tcpLayer->tp = tp;
            TransportTcpSetTimerForOutput(node);

            // Free the message.
            //MESSAGE_Free(node, ti->msg);
            MESSAGE_PayloadFree(node, tcp_seg, total_len);
            return;
        }
    }

    //
    // Calculate amount of space in receive window,
    // and then do TCP input processing.
    // Receive window is amount of space in rcv queue,
    // but not less than advertised window.
    //
    {
        int win;

        win = sbspace(inp);
        if (win < 0)
            win = 0;
        tp->rcv_wnd = MAX(win, (int)(tp->rcv_adv - tp->rcv_nxt));
    }

    switch (tp->t_state) {
    //
    // If the state is LISTEN then ignore segment if it contains an RST.
    // If the segment contains an ACK then it is bad and send a RST.
    // If it does not contain a SYN then it is not interesting; drop it.
    // Don't bother responding if the destination was a broadcast.
    // Otherwise initialize tp->rcv_nxt, and tp->irs, select an initial
    // tp->iss, and send a segment:
    //     <SEQ=ISS><ACK=RCV_NXT><CTL=SYN,ACK>
    // Also initialize tp->snd_nxt to tp->iss+1 and tp->snd_una to tp->iss.
    // Fill in remote peer address fields if not previously specified.
    // Enter SYN_RECEIVED state, and process any other fields of this
    // segment in this state.
    //
    case TCPS_LISTEN:

        if (tiflags & TH_RST)
            goto drop;
        if (tiflags & TH_ACK)
            goto dropwithreset;
        if (tiflags & TH_FIN)
            goto dropwithreset;
        if ((tiflags & TH_SYN) == 0)
            goto drop;
        tp->t_template = (struct tcpiphdr *) tcp_template(tp);
        if (tp->t_template == 0) {
            tp = (struct tcpcb *)tcp_drop(node, tp, tcp_now, tcp_stat);
            goto drop;
        }
        if (TCP_VARIANT_IS_SACK(tp)) {
            tp->tcpVariant = TCP_VARIANT_LITE;
        }

        // Receiving SYN, set the ECN bit of the Recever side connection.

        if ((tcpLayer->nodeUseEcn) &&
            (tiflags & TH_ECE) &&
            ((unsigned char)tiflags & (unsigned char)TH_CWR)) {
            tp->t_ecnFlags |= TF_ECN;
        }

        tcp_dooptions(tp, optp, optlen, ti, &topt, tcp_now, tcp_stat);
        datap = optp;

        if (iss)
            tp->iss = iss;
        else
            tp->iss = *tcp_iss;

        *tcp_iss += TCP_ISSINCR/4;
        tp->irs = ti->ti_seq;
        tcp_sendseqinit(tp);
        tcp_rcvseqinit(tp);

        // Initialization of the tcpcb for transaction;
        //   set SND.WND = SEG.WND,
        tp->snd_wnd = tiwin;    // initial send-window

        //    do a standard 3-way handshake.

        tp->t_flags |= TF_ACKNOW;
        tp->t_state = TCPS_SYN_RECEIVED;
        tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;

        // reset TCP Variant if sack is not applicable
        if (tcpLayer->tcpVariant != TCP_VARIANT_SACK
                && TCP_VARIANT_IS_SACK(tp)) {
            tp->tcpVariant = tcpLayer->tcpVariant;
        }

        if (tcp_stat)
            tcp_stat->tcps_accepts++;

        goto trimthenstep6;


    //
    // If the state is SYN_RECEIVED:
    //  do just the ack and RST checks from SYN_SENT state.
    // If the state is SYN_SENT:
    //  if seg contains an ACK, but not for our SYN, drop the input.
    //  if seg contains a RST, then drop the connection.
    //  if seg does not contain SYN, then drop it.
    // Otherwise this is an acceptable SYN segment
    //  initialize tp->rcv_nxt and tp->irs
    //  if seg contains ack then advance tp->snd_una
    //  if SYN has been acked change to ESTABLISHED else SYN_RCVD state
    //  arrange for segment to be acked (eventually)
    //  continue processing rest of data/controls, beginning with URG
    //
    case TCPS_SYN_RECEIVED:
    case TCPS_SYN_SENT:
        if (tiflags & TH_RST) {
            if (tiflags & TH_ACK)
            {
                tp->t_state = TCPS_CLOSED;
                tp = tcp_drop(node, tp, tcp_now, tcp_stat);
            }
            goto drop;
        }
        if ((tiflags & TH_ACK) &&
            (SEQ_LEQ(ti->ti_ack, tp->iss) ||
            SEQ_GT(ti->ti_ack, tp->snd_max))) {
            goto dropwithreset;
        }
        if (tp->t_state == TCPS_SYN_RECEIVED) {
            break;
        }
        if ((tiflags & TH_SYN) == 0) {
            goto drop;
        }
        tp->snd_wnd = ti->ti_win;   //  initial send window

        tp->irs = ti->ti_seq;
        tcp_rcvseqinit(tp);
        if (tiflags & TH_ACK) {
            if (tcp_stat)
                tcp_stat->tcps_connects++;
            //  Do window scaling on this connection?
            if (!TCP_VARIANT_IS_RENO(tp)) {
                if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
                    (TF_RCVD_SCALE|TF_REQ_SCALE)) {
                    tp->snd_scale = tp->requested_s_scale;
                    tp->rcv_scale = tp->request_r_scale;
                }
            }

            tp->rcv_adv += tp->rcv_wnd;
            tp->snd_una++;      //  SYN is acked

            // Reset connection's TCP variant value if peer echoed
            // a sack permitted option when we did not send one
            // (error condition)

            if (tcpLayer->tcpVariant != TCP_VARIANT_SACK
                    && TCP_VARIANT_IS_SACK(tp)) {
                tp->tcpVariant = tcpLayer->tcpVariant;
                TransportTcpTrace(
                    node, 0, 0, "Sack: variant reset to Lite!!");
            }

            //  Receiving SYN ACK, set the ECN bit of the Sender side
            //  connection.

            if (tcpLayer->nodeUseEcn && (tiflags & TH_ECE)) {
                tp->t_ecnFlags |= TF_ECN;
            }

            // If there's data, delay ACK; if there's also a FIN
            // ACKNOW will be turned on later.

            if (ti->ti_len != 0) {
                tp->t_flags |= TF_DELACK;
            } else {
                tp->t_flags |= TF_ACKNOW;
            }

            //  Received <SYN,ACK> in SYN_SENT[*] state.
            //  Transitions:
            //   SYN_SENT  --> ESTABLISHED
            //   SYN_SENT* --> FIN_WAIT_1

            if (tp->t_flags & TF_NEEDFIN) {
                tp->t_state = TCPS_FIN_WAIT_1;
                tp->t_flags &= ~TF_NEEDFIN;
                tiflags &= ~TH_SYN;
            } else {
                Message *msg;
                TransportToAppOpenResult *tcpOpenResult;

                if (inp->usrreq == INPCB_USRREQ_OPEN) {
                    flag = TCP_CONN_ACTIVE_OPEN;
                } else {
                    flag = TCP_CONN_PASSIVE_OPEN;
                }

                msg = MESSAGE_Alloc(node, APP_LAYER,
                                     inp->app_proto_type,
                                     MSG_APP_FromTransOpenResult);
                MESSAGE_InfoAlloc(
                    node, msg, sizeof(TransportToAppOpenResult));
                tcpOpenResult = (TransportToAppOpenResult *)
                                MESSAGE_ReturnInfo(msg);
                tcpOpenResult->type = flag;
                tcpOpenResult->localAddr = inp->inp_local_addr;
                tcpOpenResult->localPort = inp->inp_local_port;
                tcpOpenResult->remoteAddr = inp->inp_remote_addr;
                tcpOpenResult->remotePort = inp->inp_remote_port;
                tcpOpenResult->connectionId = inp->con_id;
                tcpOpenResult->uniqueId = inp->unique_id;

                MESSAGE_Send(node, msg, TRANSPORT_DELAY);

                inp->usrreq = INPCB_USRREQ_CONNECTED;
                tp->t_state = TCPS_ESTABLISHED;
                tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_IDLE;
#ifdef ADDON_DB
                STATSDB_HandleConnectionDescTableInsert(
                    node, /*inp->unique_id,*/ inp->inp_local_addr,
                    inp->inp_remote_addr, inp->inp_local_port,
                    inp->inp_remote_port, "TCP");
#endif
            }
        } else {

            //  Received initial SYN in SYN-SENT[*] state => simul-
            //  taneous open.

            tp->t_flags |= TF_ACKNOW;
            tp->t_timer[TCPT_REXMT] = 0;
            tp->t_state = TCPS_SYN_RECEIVED;

            // Reset connection's TCP variant value if peer did not echo
            // our sack permitted option

            if (tcpLayer->tcpVariant != TCP_VARIANT_SACK
                    && TCP_VARIANT_IS_SACK(tp)) {
                tp->tcpVariant = tcpLayer->tcpVariant;
            }
        }

trimthenstep6:

        // Advance ti->ti_seq to correspond to first data byte.
        // If data, trim to stay within window,
        // dropping FIN if necessary.

        ti->ti_seq++;
        if ((UInt32) ti->ti_len > tp->rcv_wnd) {
            todrop = ti->ti_len - tp->rcv_wnd;
            ti->ti_len = (short) tp->rcv_wnd;
            tiflags &= ~TH_FIN;
            //if (tcp_stat) {
                //tcp_stat->tcps_rcvpackafterwin++;
                //tcp_stat->tcps_rcvbyteafterwin += todrop;
            //}
        }
        tp->snd_wl1 = ti->ti_seq - 1;
        tp->rcv_up = ti->ti_seq;
        if (tiflags & TH_ACK) {
            goto process_ACK;
        }

        goto step6;

    case TCPS_LAST_ACK:
    case TCPS_CLOSING:
    case TCPS_TIME_WAIT:
        break;  // continue normal processing
    }

    //
    // States other than LISTEN or SYN_SENT.
    // First check timestamp, if present.
    // Then check the connection count, if present.
    // Then check that at least some bytes of segment are within
    // receive window.  If segment begins before rcv_nxt,
    // drop leading data (and SYN); if nothing left, just ack.
    //
    // RFC 1323 PAWS: If we have a timestamp reply on this segment
    // and it's less than ts_recent, drop it.
    //
    if (!TCP_VARIANT_IS_RENO(tp)) {
        if ((topt.to_flag & TOF_TS) != 0 && (tiflags & TH_RST) == 0 &&
            tp->ts_recent && TSTMP_LT(topt.to_tsval, tp->ts_recent)) {

            // Check to see if ts_recent is over 24 days old.
            if ((int)(tcp_now - tp->ts_recent_age) > TCP_PAWS_IDLE) {
                //
                // Invalidate ts_recent.  If this segment updates
                // ts_recent, the age will be reset later and ts_recent
                // will get a valid value.  If it does not, setting
                // ts_recent to zero will at least satisfy the
                // requirement that zero be placed in the timestamp
                // echo reply when ts_recent isn't valid.  The
                // age isn't reset until we get a valid ts_recent
                // because we don't want out-of-order segments to be
                // dropped when ts_recent is old.
                //
                tp->ts_recent = 0;
            } else {
                //if (tcp_stat) {
                    //tcp_stat->tcps_rcvduppack++;
                    //tcp_stat->tcps_rcvdupbyte += ti->ti_len;
                    //tcp_stat->tcps_pawsdrop++;
                //}
                goto dropafterack;
            }
        }
    }

    todrop = tp->rcv_nxt - ti->ti_seq;
    if (todrop > 0) {
        if (tiflags & TH_SYN) {
            tiflags &= ~TH_SYN;
            ti->ti_seq++;
            if (ti->ti_urp > 1)
                ti->ti_urp --;
            else
                tiflags &= ~TH_URG;
            todrop--;
        }

        // Following if statement from Stevens, vol. 2, p. 960.
        if (todrop > ti->ti_len
            || (todrop == ti->ti_len && (tiflags & TH_FIN) == 0)) {

            // Any valid FIN must be to the left of the window.
            // At this point the FIN must be a duplicate or out
            // of sequence; drop it.

            tiflags &= ~TH_FIN;

            //
            // Send an ACK to resynchronize and drop any data.
            // But keep on processing for RST or ACK.
            //
            tp->t_flags |= TF_ACKNOW;
            todrop = ti->ti_len;
            //if (tcp_stat) {
                //tcp_stat->tcps_rcvduppack++;
                //tcp_stat->tcps_rcvdupbyte += todrop;
            //}
        } else {
            //if (tcp_stat) {
                //tcp_stat->tcps_rcvpartduppack++;
                //tcp_stat->tcps_rcvpartdupbyte += todrop;
            //}
        }
        data_adj(ti, todrop);
        ti->ti_seq += todrop;
        ti->ti_len = (short) (ti->ti_len - todrop);
        if (ti->ti_len == 0)
        {
            dropped_packet = TRUE;
        }
        if (ti->ti_urp > todrop)
            ti->ti_urp = (unsigned short) (ti->ti_urp - todrop);
        else {
            tiflags &= ~TH_URG;
            ti->ti_urp = 0;
        }
    }

    //
    // If new data are received on a connection after the
    // user processes are gone, then RST the other end.
    //

    if (tp->t_state > TCPS_CLOSE_WAIT && ti->ti_len) {
        tp = tcp_close(node, tp, tcp_stat);
        //if (tcp_stat)
            //tcp_stat->tcps_rcvafterclose++;
        goto dropwithreset;
    }

    //
    // If segment ends after window, drop trailing data
    // (and PUSH and FIN); if nothing left, just ACK.
    //
    todrop = (ti->ti_seq+ti->ti_len) - (tp->rcv_nxt+tp->rcv_wnd);
    if (todrop > 0) {
        //if (tcp_stat)
            //tcp_stat->tcps_rcvpackafterwin++;
        if (todrop >= ti->ti_len) {
            //if (tcp_stat)
                //tcp_stat->tcps_rcvbyteafterwin += ti->ti_len;
            //
            // If a new connection request is received
            // while in TIME_WAIT, drop the old connection
            // and start over if the sequence numbers
            // are above the previous ones.
            //
            if (tiflags & TH_SYN &&
                tp->t_state == TCPS_TIME_WAIT &&
                SEQ_GT(ti->ti_seq, tp->rcv_nxt)) {
                iss = tp->rcv_nxt + TCP_ISSINCR;
                tp = tcp_close(node, tp, tcp_stat);
                goto findpcb;
            }
            //
            // If window is closed can only take segments at
            // window edge, and have to drop data and PUSH from
            // incoming segments.  Continue processing, but
            // remember to ack.  Otherwise, drop segment
            // and ack.
            //
            if (tp->rcv_wnd == 0 && ti->ti_seq == tp->rcv_nxt) {
                tp->t_flags |= TF_ACKNOW;
                if (tcp_stat)
                    tcp_stat->tcps_rcvwinprobe++;
            } else
                goto dropafterack;
        } else{
            //if (tcp_stat)
                //tcp_stat->tcps_rcvbyteafterwin += todrop;
        }
        ti->ti_len = (short) (ti->ti_len - todrop);
        tiflags &= ~(TH_PUSH|TH_FIN);
    }

    //
    // If last ACK falls within this segment's sequence numbers,
    // record its timestamp.
    // NOTE that the test is modified according to the latest
    // proposal of the tcplw@cray.com list (Braden 1993/04/26).
    //
    if (!TCP_VARIANT_IS_RENO(tp)) {
        if ((topt.to_flag & TOF_TS) != 0 &&
            SEQ_LEQ(ti->ti_seq, tp->last_ack_sent)) {
            tp->ts_recent_age = tcp_now;
            tp->ts_recent = topt.to_tsval;
        }
    }

    //
    // If the RST bit is set examine the state:
    //    SYN_RECEIVED STATE:
    //  If passive open, return to LISTEN state.
    //  If active open, inform user that connection was refused.
    //    ESTABLISHED, FIN_WAIT_1, FIN_WAIT2, CLOSE_WAIT STATES:
    //  Inform user that connection was reset, and close tcb.
    //    CLOSING, LAST_ACK, TIME_WAIT STATES
    //  Close the tcb.
    //
    if (tiflags&TH_RST) {
        switch (tp->t_state) {

        case TCPS_SYN_RECEIVED:
        case TCPS_ESTABLISHED:
        case TCPS_FIN_WAIT_1:
        case TCPS_FIN_WAIT_2:
        case TCPS_CLOSE_WAIT:
            tp->t_state = TCPS_CLOSED;
            //if (tcp_stat)
                //tcp_stat->tcps_drops++;
            tp = tcp_close(node, tp, tcp_stat);
            goto drop;

        case TCPS_CLOSING:
        case TCPS_LAST_ACK:
        case TCPS_TIME_WAIT:
            tp = tcp_close(node, tp, tcp_stat);
            goto drop;
        }
    }
    //
    // If a SYN is in the window, then this is an
    // error and we send an RST and drop the connection.
    //
    if (tiflags & TH_SYN) {
        tp = tcp_drop(node, tp, tcp_now, tcp_stat);
        goto dropwithreset;
    }

    //
    // If the ACK bit is off:  if in SYN-RECEIVED state or SENDSYN
    // flag is on (half-synchronized state), then queue data for
    // later processing; else drop segment and return.
    //
    if ((tiflags & TH_ACK) == 0) {
        if (tp->t_state == TCPS_SYN_RECEIVED ||
            (tp->t_flags & TF_NEEDSYN))
            goto step6;
        else
            goto drop;
    }

    //
    // Ack processing.
    //
    switch (tp->t_state) {

    //
    // In SYN_RECEIVED state if the ack ACKs our SYN then enter
    // ESTABLISHED state and continue processing, otherwise
    // send an RST.
    //
    case TCPS_SYN_RECEIVED:
        if (SEQ_GT(tp->snd_una, ti->ti_ack) ||
            SEQ_GT(ti->ti_ack, tp->snd_max))
            goto dropwithreset;
        if (tcp_stat)
            tcp_stat->tcps_connects++;
        // Do window scaling? //
        if (!TCP_VARIANT_IS_RENO(tp)) {
            if ((tp->t_flags & (TF_RCVD_SCALE|TF_REQ_SCALE)) ==
                (TF_RCVD_SCALE|TF_REQ_SCALE)) {
                tp->snd_scale = tp->requested_s_scale;
                tp->rcv_scale = tp->request_r_scale;
            }
        }

        //
        // Make transitions:
        //      SYN-RECEIVED  -> ESTABLISHED
        //      SYN-RECEIVED* -> FIN-WAIT-1
        //
        if (tp->t_flags & TF_NEEDFIN) {
            tp->t_state = TCPS_FIN_WAIT_1;
            tp->t_flags &= ~TF_NEEDFIN;
        } else {
            Message *msg;
            TransportToAppOpenResult *tcpOpenResult;

            if (inp->usrreq == INPCB_USRREQ_OPEN) {
                flag = TCP_CONN_ACTIVE_OPEN;
            } else {
                flag = TCP_CONN_PASSIVE_OPEN;
            }

            msg = MESSAGE_Alloc(node, APP_LAYER,
                                 inp->app_proto_type,
                                 MSG_APP_FromTransOpenResult);
            MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppOpenResult));
            tcpOpenResult = (TransportToAppOpenResult *)
                            MESSAGE_ReturnInfo(msg);
            tcpOpenResult->type = flag;
            tcpOpenResult->localAddr = inp->inp_local_addr;
            tcpOpenResult->localPort = inp->inp_local_port;
            tcpOpenResult->remoteAddr = inp->inp_remote_addr;
            tcpOpenResult->remotePort = inp->inp_remote_port;
            tcpOpenResult->connectionId = inp->con_id;

            tcpOpenResult->uniqueId = inp->unique_id;
            int * sessionIdInfo =  (int *)
                MESSAGE_ReturnInfo( origMsg, INFO_TYPE_StatsDbAppSessionId);
            if (sessionIdInfo != NULL)
            {
                if (sessionIdInfo || inp->remote_unique_id == -1)
                {
                    inp->remote_unique_id = *sessionIdInfo;
                }
                tcpOpenResult->clientUniqueId = inp->remote_unique_id;
            }

#ifdef ADDON_DB
            if (sessionIdInfo != NULL)
            {
                STATSDB_HandleTransConnCreation(node,
                    tcpOpenResult->remoteAddr, tcpOpenResult->remotePort,
                    tcpOpenResult->localAddr, tcpOpenResult->localPort);
            }
#endif

            MESSAGE_Send(node, msg, TRANSPORT_DELAY);

            inp->usrreq = INPCB_USRREQ_CONNECTED;
            tp->t_state = TCPS_ESTABLISHED;
            tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_IDLE;
        }
        //
        // If segment contains data or ACK, will call tcp_reass()
        // later; if not, do so now to pass queued data to user.
        //
        if (ti->ti_len == 0 && (tiflags & TH_FIN) == 0)
            (void) tcp_reass(node, tp, (struct tcpiphdr *)0,
                             tcp_stat, virtual_len, origMsg);
        tp->snd_wl1 = ti->ti_seq - 1;
        // fall into ...

    //
    // In ESTABLISHED state: drop duplicate ACKs; ACK out of range
    // ACKs.  If the ack is in the range
    //  tp->snd_una < ti->ti_ack <= tp->snd_max
    // then advance tp->snd_una to ti->ti_ack and drop
    // data from the retransmission queue.  If this ACK reflects
    // more up to date window information we update our window information.
    //
    case TCPS_ESTABLISHED:
    case TCPS_FIN_WAIT_1:
    case TCPS_FIN_WAIT_2:
    case TCPS_CLOSE_WAIT:
    case TCPS_CLOSING:
    case TCPS_LAST_ACK:
    case TCPS_TIME_WAIT:

        if (SEQ_LEQ(ti->ti_ack, tp->snd_una)) {
            if (ti->ti_len == 0 && tiwin == tp->snd_wnd) {
                if (tcp_stat) {
                    if (!(ti->ti_flags & (TH_FIN|TH_SYN|TH_RST)))
                        //tcp_stat->tcps_rcvdupack++;
                    {
                        if (dropped_packet == FALSE)
                        {
                            tcp_stat->tcps_rcvdupack++;
                        }
                    }
                }
                //
                // If we have outstanding data (other than
                // a window probe), this is a completely
                // duplicate ack (ie, window info didn't
                // change), the ack is the biggest we've
                // seen and we've seen exactly our rexmt
                // threshhold of them, assume a packet
                // has been dropped and retransmit it.
                // Kludge snd_nxt & the congestion
                // window so we send only this one
                // packet.
                //
                // We know we're losing at the current
                // window size so do congestion avoidance
                // (set ssthresh to half the current window
                // and pull our congestion window back to
                // the new ssthresh).
                //
                // Dup acks mean that packets have left the
                // network (they're now cached at the receiver)
                // so bump cwnd by the amount in the receiver
                // to keep a constant cwnd packets in the
                // network.
                //
                if (tp->t_timer[TCPT_REXMT] == 0 ||
                        ti->ti_ack != tp->snd_una) {

                    if (!TCP_SACK_REXT(tp)) {
                        tp->t_dupacks = 0;
                        TransportTcpTrace(node, 0, 0,
                            "Normal: Faxt ends : 1");
                    }
                }
                else if (++tp->t_dupacks == tcprexmtthresh) {
                    tcp_seq onxt = tp->snd_nxt;
                    unsigned int win =
                        MIN(tp->snd_wnd, tp->snd_cwnd) / 2 /
                        tp->t_maxseg;

                    if (win < 2)
                        win = 2;

                    // When the third duplicate ACK is received and the
                    // sender is not already in the Fast Recovery procedure,
                    // set ssthresh to no more than the value given in
                    //
                    //       ssthresh = max (FlightSize / 2, 2*MSS)
                    //
                    // where FLIGHT SIZE:The amount of data that has been
                    // sent but not yet acknowledged.
                    //
                    // Record the highest sequence number transmitted in
                    // the variable "recover".
                    //
                    if (TCP_VARIANT_IS_NEWRENO(tp)) {
                        tcp_seq flightSize;

                        if (SEQ_GEQ(ti->ti_ack, tp->send_high) &&
                                tp->t_partialacks < 0) {
                            flightSize = tp->snd_max - tp->snd_una;
                            tp->recover = tp->snd_max;
                            tp->t_partialacks = 0;
                            if ((tp->t_ecnFlags & TF_ECN_STATE) == 0) {
                                tp->snd_ssthresh = MAX(flightSize / 2 /
                                            tp->t_maxseg, 2) * tp->t_maxseg;
                            }
                        }
                        else {
                            tp->t_dupacks = 0;
                            goto drop;
                        }
                    }
                    else {
                        if ((tp->t_ecnFlags & TF_ECN_STATE) == 0) {
                            tp->snd_ssthresh = win * tp->t_maxseg;
                        }
                    }
                    tp->t_timer[TCPT_REXMT] = 0;
                    tp->t_rtt = 0;

                    if (TCP_VARIANT_IS_SACK(tp)) {
                        TransportTcpSackFastRextInit(tp);
                        TransportTcpTrace(node, 0, 0, "Sack: faxt starts");
                    }
                    else {
                        TransportTcpTrace(node, 0, 0, "Normal: faxt starts");
                    }

                    tp->snd_nxt = ti->ti_ack;
                    tp->snd_cwnd = tp->t_maxseg;

                    if (tcp_stat) {
                        tcp_stat->tcps_sndfastrexmitpack++;
                    }

                    tp->t_ecnFlags |= TF_REXT_PACKET;
                    tp->t_ecnFlags |= TF_CWND_REDUCED;

                    tcp_output(node, tp, tcp_now, tcp_stat);

                    if (!TCP_VARIANT_IS_TAHOE(tp)) {
                        tp->snd_cwnd = tp->snd_ssthresh +
                                       tp->t_maxseg * tp->t_dupacks;

                        if (!TCP_VARIANT_IS_SACK(tp)) {
                            if (SEQ_GT(onxt, tp->snd_nxt))
                                tp->snd_nxt = onxt;
                        }
                    }
                    goto drop;
                } else if (tp->t_dupacks > tcprexmtthresh) {
                    TransportTcpTrace(node, 0, 0, "Faxt: continues");
                    if (!TCP_VARIANT_IS_TAHOE(tp)) {
                        tp->snd_cwnd += tp->t_maxseg;
                        tcp_output(node, tp, tcp_now, tcp_stat);
                    }
                    goto drop;
                }
            } else {
                if (!TCP_VARIANT_IS_SACK(tp) && !TCP_VARIANT_IS_NEWRENO(tp)) {
                    tp->t_dupacks = 0;
                    TransportTcpTrace(node, 0, 0, "Normal: Faxt ends : 2");
                }
            }
            break;
        }
        //
        // If the congestion window was inflated to account
        // for the other side's cached packets, retract it.
        //
        if (TCP_VARIANT_IS_NEWRENO(tp)) {
            if (tp->t_partialacks < 0) {
                //
                // We were not in fast recovery.  Reset the duplicate ack
                // counter.
                //
                tp->t_dupacks = 0;
            } else if (SEQ_LT(ti->ti_ack, tp->recover)) {
                //
                // This is a partial ack.  Retransmit the first unacknowledged
                // segment and deflate the congestion window by the amount of
                // acknowledged data.  Do not exit fast recovery.
                //
                tcp_seq onxt = tp->snd_nxt;
                UInt32 ocwnd = tp->snd_cwnd;

                //
                // snd_una has not yet been updated and the send
                // buffer has not yet drained off the ACK'd data, so we
                // have to leave snd_una as it was to get the correct data
                // offset in tcp_output().
                //
                if (++tp->t_partialacks == 1){
                    tp->t_timer[TCPT_REXMT] = 0;
                }

                tp->t_rtt = 0;
                tp->snd_nxt = ti->ti_ack;
                //
                // Set snd_cwnd to one segment beyond ACK'd offset.  snd_una
                // is not yet updated when we're called.
                //
                tp->snd_cwnd = tp->t_maxseg + (ti->ti_ack - tp->snd_una);
                tcp_output(node, tp, tcp_now, tcp_stat);
                tp->snd_cwnd = ocwnd;

                if (SEQ_GT(onxt, tp->snd_nxt)) {
                    tp->snd_nxt = onxt;
                }
                //
                // Partial window deflation.  Relies on fact that tp->snd_una
                // not updated yet.
                //
                tp->snd_cwnd -= (ti->ti_ack - tp->snd_una - tp->t_maxseg);
            } else {
                //
                // Complete ack.  Inflate the congestion window to ssthresh
                // and exit fast recovery.
                //
                // Window inflation should have left us with approx.
                // snd_ssthresh outstanding data.  But in case we
                // would be inclined to send a burst, better to do
                // it via the slow start mechanism.
                //
                if (SEQ_SUB(tp->snd_max, ti->ti_ack) <
                    (int) tp->snd_ssthresh) {
                    tp->snd_cwnd = SEQ_SUB(tp->snd_max, ti->ti_ack)
                        + tp->t_maxseg;
                }
                else {
                    tp->snd_cwnd = tp->snd_ssthresh;
                }

                tp->t_partialacks = -1;
                tp->t_dupacks = 0;
            }
        }
        else{
            if (!TCP_VARIANT_IS_SACK(tp)) {
                if (!TCP_VARIANT_IS_TAHOE(tp)) {
                    if (tp->t_dupacks >= tcprexmtthresh &&
                        tp->snd_cwnd > tp->snd_ssthresh) {
                        tp->snd_cwnd = tp->snd_ssthresh;
                        TransportTcpTrace(node, 0, 0, "recovery end");
                    }
                }
                tp->t_dupacks = 0;
                TransportTcpTrace(node, 0, 0, "Normal: Faxt ends : 3");
            }
        }

        if (SEQ_GT(ti->ti_ack, tp->snd_max)) {
            //if (tcp_stat)
                //tcp_stat->tcps_rcvacktoomuch++;
            goto dropafterack;
        }


process_ACK:
        acked = ti->ti_ack - tp->snd_una;
        inp->info_buf->pktAcked += acked;
        if (tcp_stat) {
            if ((tlen == 0)&&(!(ti->ti_flags & (TH_SYN|TH_RST|TH_FIN)))) {
                tcp_stat->tcps_rcvackpack++;
            }
            //tcp_stat->tcps_rcvackbyte += acked;
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
        if (!TCP_VARIANT_IS_RENO(tp) && topt.to_flag & TOF_TS) {
            tcp_xmit_timer(tp, tcp_now - topt.to_tsecr + 1, tcp_stat);
        } else {
            if (tp->t_rtt && SEQ_GT(ti->ti_ack, tp->t_rtseq)) {
                tcp_xmit_timer(tp,tp->t_rtt, tcp_stat);
            }
        }

        //
        // If all outstanding data is acked, stop retransmit
        // timer and remember to restart (more output or persist).
        // If there is more data to be acked, restart retransmit
        // timer, using current (possibly backed-off) value.
        //
        if (ti->ti_ack == tp->snd_max) {
            tp->t_timer[TCPT_REXMT] = 0;
            needoutput = 1;
        } else {
            if (tp->t_timer[TCPT_PERSIST] == 0) {
                if (!TCP_VARIANT_IS_NEWRENO(tp) || tp->t_partialacks <= 1) {
                    tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
                }
            }
        }

        //
        // If no data (only SYN) was ACK'd,
        //    skip rest of ACK processing.
        //
        if (acked == 0) {
            goto step6;
        }

        //
        // When new data is acked, open the congestion window.
        // If the window gives us less than ssthresh packets
        // in flight, open exponentially (maxseg per packet).
        // Otherwise open linearly: maxseg per window
        // (maxseg^2 / cwnd per packet).
        //
       if (!TCP_SACK_REXT(tp) && (tp->t_partialacks < 0))
       {
            unsigned int cw = tp->snd_cwnd;
            unsigned int incr = tp->t_maxseg;

            if (cw > tp->snd_ssthresh) {
                incr = incr * incr / cw;
            }
            tp->snd_cwnd = MIN(cw + incr,
                (unsigned int) (TCP_MAXWIN<<tp->snd_scale));
        }

        aBufReadCount = InpSendBufGetCount(&inp->inp_snd, BUF_READ);
        if (acked > (int)aBufReadCount) {
            tp->snd_wnd -= aBufReadCount;
            //inp->info_buf->pktAcked += (int)aBufReadCount;
            del_buf(node, inp, (int)aBufReadCount, ti->ti_ack);
            ourfinisacked = 1;
        } else {
            tp->snd_wnd -= acked;
            //inp->info_buf->pktAcked += acked;
            del_buf(node, inp, acked, ti->ti_ack);
            ourfinisacked = 0;
        }
        tp->snd_una = ti->ti_ack;

        if (SEQ_LT(tp->snd_nxt, tp->snd_una))
            tp->snd_nxt = tp->snd_una;

        if (TCP_VARIANT_IS_SACK(tp)) {
            TransportTcpSackUpdateNewSndUna(tp, tp->snd_una);
            TransportTcpTrace(node, 0, 0, "NewSndUna: from process_ACK:");
        }

        if (TCP_SACK_REXT(tp)) {
            if (SEQ_GEQ(tp->snd_una, tp->sackFastRextLimit)) {
                TransportTcpSackFastRextEnd(tp);
                TransportTcpTrace(node, 0, 0, "Sack: faxt ends, 3a");
            }
            else {
                tp->snd_cwnd -= acked - 2 * tp->t_maxseg;
                TransportTcpTrace(node, 0, 0, "Sack: partial ack");
                tcp_output(node, tp, tcp_now, tcp_stat);
            }
        }

        switch (tp->t_state) {

        //
        // In FIN_WAIT_1 STATE in addition to the processing
        // for the ESTABLISHED state if our FIN is now acknowledged
        // then enter FIN_WAIT_2.
        //
        case TCPS_FIN_WAIT_1:
            if (ourfinisacked) {
                //
                // If we can't receive any more
                // data, then closing user can proceed.
                // Starting the timer is contrary to the
                // specification, but if we don't get a FIN
                // we'll hang forever.
                //
                tp->t_state = TCPS_FIN_WAIT_2;
                tp->t_timer[TCPT_2MSL] = TCPTV_MAXIDLE;
            }
            break;

        //
        // In CLOSING STATE in addition to the processing for
        // the ESTABLISHED state if the ACK acknowledges our FIN
        // then enter the TIME-WAIT state, otherwise ignore
        // the segment.
        //
        case TCPS_CLOSING:
            if (ourfinisacked) {
                tp->t_state = TCPS_TIME_WAIT;
                tcp_canceltimers(tp);
                tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
            }
            break;

        //
        // In LAST_ACK, we may still be waiting for data to drain
        // and/or to be acked, as well as for the ack of our FIN
        // If our FIN is now acknowledged, delete the TCB,
        // enter the closed state and return.
        //
        case TCPS_LAST_ACK:
            if (ourfinisacked) {
                tp = tcp_close(node, tp, tcp_stat);
                goto drop;
            }
            break;

        //
        // In TIME_WAIT state the only thing that should arrive
        // is a retransmission of the remote FIN.  Acknowledge
        // it and restart the finack timer.
        //
        case TCPS_TIME_WAIT:
            tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
            goto dropafterack;
        }
    }


step6:
    //
    // Update window information.
    // Don't look at window if no ACK: TAC's send garbage on first SYN.
    //
    if ((tiflags & TH_ACK) &&
        (SEQ_LT(tp->snd_wl1, ti->ti_seq) ||
        (tp->snd_wl1 == ti->ti_seq && (SEQ_LT(tp->snd_wl2, ti->ti_ack) ||
         (tp->snd_wl2 == ti->ti_ack && tiwin > tp->snd_wnd))))) {

        // keep track of pure window updates
        if (tcp_stat) {
            if (ti->ti_len == 0 &&
                tp->snd_wl2 == ti->ti_ack && tiwin > tp->snd_wnd) {
                tcp_stat->tcps_rcvwinupd++;
            }
        }
        tp->snd_wnd = tiwin;
        tp->snd_wl1 = ti->ti_seq;
        tp->snd_wl2 = ti->ti_ack;

        if (tp->snd_wnd > tp->max_sndwnd) {
            tp->max_sndwnd = tp->snd_wnd;
        }
        needoutput = 1;
    }
    //
    // Pull receive urgent pointer along
    // with the receive window.
    //
    if (SEQ_GT(tp->rcv_nxt, tp->rcv_up)) {
        tp->rcv_up = tp->rcv_nxt;
    }
    //
    // Process the segment text, merging it into the TCP sequencing queue,
    // and arranging for acknowledgment of receipt if necessary.
    // This process logically involves adjusting tp->rcv_wnd as data
    // is presented to the user (this happens in tcp_usrreq.c,
    // case PRU_RCVD).  If a FIN has already been received on this
    // connection then we just ignore the text.
    //
    if ((ti->ti_len || (tiflags & TH_FIN)) &&
        TCPS_HAVERCVDFIN(tp->t_state) == 0) {

        if (!tcpLayer->tcpDelayShortPackets) {
            if (ti->ti_seq == tp->rcv_nxt &&
                tp->seg_next == (struct tcpiphdr *)tp &&
                tp->t_state == TCPS_ESTABLISHED) {
                if (ti->ti_flags & TH_PUSH)
                    tp->t_flags |= TF_ACKNOW;
                else if (!tcpLayer->tcpDelayAcks)
                    tp->t_flags |= TF_ACKNOW;
                else
                    tp->t_flags |= TF_DELACK;
                tp->rcv_nxt += ti->ti_len;
                tiflags = ti->ti_flags & TH_FIN;

                if (TCP_VARIANT_IS_SACK(tp)) {
                    TransportTcpSackUpdateNewRcvNxt(tp, tp->rcv_nxt);
                    TransportTcpTrace(node, 0, 0,
                             "NewRcvNxt, step 6: delayed ack 1");
                }

                submit_data(node, inp->app_proto_type, inp->con_id,
                            (unsigned char *)(ti + 1), ti,
                            virtual_len, tp);

                //
                // Call tcp_output() immediately after sending data
                // to application. This is to simulate what actually happens in
                // real systems where once the user process grabs data from the
                // receiver's buffer, the user process then calls tcp_output()
                // to determine whether or not to reply with an ACK.  This is
                // used to handle the delay ACK feature.
                //
                tcpLayer->tp = tp;
                TransportTcpSetTimerForOutput(node);
                // Free the message.
                //MESSAGE_Free(node, ti->msg);
                MESSAGE_PayloadFree(node, tcp_seg, total_len);

            } else {
                TransportTcpTrace(node, tp, 0,
                           "AddToRcvList, step6: delayed ack 0");
                if (TCP_VARIANT_IS_SACK(tp)) {
                    TransportTcpSackAddToRcvList(tp, ti->ti_seq,
                                             ti->ti_seq + ti->ti_len);
                }

                tiflags = tcp_reass(node, tp, ti, tcp_stat, virtual_len, origMsg);
                tp->t_flags |= TF_ACKNOW;
            }
        } else {
            if (ti->ti_seq == tp->rcv_nxt &&
                tp->seg_next == (struct tcpiphdr *)tp &&
                tp->t_state == TCPS_ESTABLISHED) {
                if (!tcpLayer->tcpDelayAcks) {
                    tp->t_flags |= TF_ACKNOW;
                }
                else {
                    tp->t_flags |= TF_DELACK;
                }
                (tp)->rcv_nxt += (ti)->ti_len;
                tiflags = (ti)->ti_flags & TH_FIN;

                if (TCP_VARIANT_IS_SACK(tp)) {
                    TransportTcpSackUpdateNewRcvNxt(tp, tp->rcv_nxt);
                    TransportTcpTrace(node, 0, 0,
                            "NewRcvNxt, step 6: delayed ack else 1");
                }

                submit_data(node, inp->app_proto_type, inp->con_id,
                            datap, ti, virtual_len, tp);

                //
                // Call tcp_output() immediately after sending data
                // to application. This is to simulate what actually happens in
                // real systems where once the user process grabs data from the
                // receiver's buffer, the user process then calls tcp_output()
                // to determine whether or not to reply with an ACK.  This is
                // used to handle the delay ACK feature.
                //
                tcpLayer->tp = tp;
                TransportTcpSetTimerForOutput(node);

                // Free the message.
                //MESSAGE_Free(node, ti->msg);
                MESSAGE_PayloadFree(node, tcp_seg, total_len);

            } else {
                if (TCP_VARIANT_IS_SACK(tp)) {
                    TransportTcpSackAddToRcvList(tp, ti->ti_seq,
                                                 ti->ti_seq + ti->ti_len);
                    TransportTcpTrace(node, tp, 0,
                                "AddToRcvList, step6: delayedack else 0");
                }

                tiflags = tcp_reass(node, tp, ti, tcp_stat, virtual_len, origMsg);
                tp->t_flags |= TF_ACKNOW;
            }
        }

        //
        // Note the amount of data that peer has sent into
        // our window, in order to estimate the sender's
        // buffer size.
        //
        len = inp->inp_rcv_hiwat - (tp->rcv_adv - tp->rcv_nxt);
    } else {
        // Free the message.
        MESSAGE_Free(node, ti->msg);
        MESSAGE_PayloadFree(node, tcp_seg, total_len);

        tiflags &= ~TH_FIN;
    }

    //
    // If FIN is received ACK the FIN and let the user know
    // that the connection is closing.
    //
    if (tiflags & TH_FIN) {
        if (TCPS_HAVERCVDFIN(tp->t_state) == 0) {
            //
            //  If connection is half-synchronized
            //  (ie NEEDSYN flag on) then delay ACK,
            //  so it may be piggybacked when SYN is sent.
            //  Otherwise, since we received a FIN then no
            //  more input can be expected, send ACK now.
            //
            if (tp->t_flags & TF_NEEDSYN)
                tp->t_flags |= TF_DELACK;
            else
                tp->t_flags |= TF_ACKNOW;
            tp->rcv_nxt++;
        }
        switch (tp->t_state) {

        //
        // In SYN_RECEIVED and ESTABLISHED STATES
        // enter the CLOSE_WAIT state.
        //
        case TCPS_SYN_RECEIVED:
        case TCPS_ESTABLISHED:
        {
            TransportToAppCloseResult *tcpCloseResult;
            Message *msg;

            tp->t_state = TCPS_CLOSE_WAIT;

            // Inform application of passive close.

            msg = MESSAGE_Alloc(node, APP_LAYER,
                    inp->app_proto_type, MSG_APP_FromTransCloseResult);
            MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppCloseResult));

            tcpCloseResult = (TransportToAppCloseResult *)
                             MESSAGE_ReturnInfo(msg);
            tcpCloseResult->type = TCP_CONN_PASSIVE_CLOSE;
            tcpCloseResult->connectionId = inp->con_id;

            MESSAGE_Send(node, msg, TRANSPORT_DELAY);

            break;
        }

        //
        // If still in FIN_WAIT_1 STATE FIN has not been acked so
        // enter the CLOSING state.
        //
        case TCPS_FIN_WAIT_1:
            tp->t_state = TCPS_CLOSING;
            break;

        //
        // In FIN_WAIT_2 state enter the TIME_WAIT state,
        // starting the time-wait timer, turning off the other
        // standard timers.
        //
        case TCPS_FIN_WAIT_2:
            tp->t_state = TCPS_TIME_WAIT;
            tcp_canceltimers(tp);
            tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
            break;

        //
        // In TIME_WAIT state restart the 2 MSL time_wait timer.
        //
        case TCPS_TIME_WAIT:
            tp->t_timer[TCPT_2MSL] = 2 * TCPTV_MSL;
            break;
        }
    }

    //
    // Return any desired output.
    //
    if (needoutput || (tp->t_flags & TF_ACKNOW)) {
        tcp_output(node, tp, tcp_now, tcp_stat);
    }
    return;

dropafterack:
    //
    // Generate an ACK dropping incoming segment if it occupies
    // sequence space, where the ACK reflects our state.
    //
    if (tiflags & TH_RST)
        goto drop;
    tp->t_flags |= TF_ACKNOW;
    // Free the message.
    MESSAGE_Free(node, ti->msg);
    MESSAGE_PayloadFree(node, tcp_seg, total_len);

    tcp_output(node, tp, tcp_now, tcp_stat);
    return;

dropwithreset:


    //
    // Problem occurs when server already closes connection
    // while client is still sending or vice versa.  If this happens,
    // tp == NULL.  Just do nothing and return in this case.
    //
    if (tp == NULL)
    {
        tcp_respond(node, NULL, ti,
                    1, (tcp_seq)0, ti->ti_ack,
                    TH_RST | TH_ACK, tcp_stat);
        // Free the message.
        MESSAGE_Free(node, ti->msg);
        MESSAGE_PayloadFree(node, tcp_seg, total_len);
        return;
    }

    //
    // Generate a RST, dropping incoming segment.
    // Make ACK acceptable to originator of segment.
    // Don't bother to respond if destination was broadcast/multicast.
    //
    if (tiflags & TH_RST)
        goto drop;

    if (tiflags & TH_ACK){
        tcp_respond(node, tp, ti,
                    1, (tcp_seq)0, ti->ti_ack,
                    TH_RST, tcp_stat);
    }
    else {
        if (tiflags & TH_SYN)
            ti->ti_len++;
        tcp_respond(node, tp, ti,
                    1, ti->ti_seq+ti->ti_len, (tcp_seq)0,
                    TH_RST|TH_ACK, tcp_stat);
    }
    // Free the message.
    MESSAGE_Free(node, ti->msg);
    MESSAGE_PayloadFree(node, tcp_seg, total_len);
    return;
drop:

    //
    // Drop space held by incoming segment and return.
    //
    // Free the message.
    MESSAGE_Free(node, ti->msg);
    MESSAGE_PayloadFree(node, tcp_seg, total_len);
    return;

}


//-------------------------------------------------------------------------//
// Determine the MSS option to send on an outgoing SYN.
//-------------------------------------------------------------------------//
int tcp_mssopt(struct tcpcb *tp)
{
    return tp->mss;
}

