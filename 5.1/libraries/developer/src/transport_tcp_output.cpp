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
//
// Ported from FreeBSD 2.2.2.
// This file contains TCP output routine and ancillary functions.
//

//
// Copyright (c) 1982, 1986, 1988, 1990, 1993, 1995
//  The Regents of the University of California.  All rights reserved.
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
//  @(#)tcp_output.c    8.4 (Berkeley) 5/24/95
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "partition.h"
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

#define NoDEBUG
#define NoECN_DEBUG_TEST
//
// Change this value to the number of drops required
// e.g. #define ECN_TEST_PKT_DROP 3 for 3 drops
// The value should be 0 (zero) for no drops
//
#define ECN_TEST_PKT_DROP 0


static void MergeInfoField(
    Node* node,
    Message* dstMsg,
    infofield_array* info,
    int length,
    int retransmitting)
{
    // Add the book Keeping information
    MessageInfoBookKeeping bookKeeping;
    bookKeeping.msgSeqNum = info->msgSeqNum;

    bookKeeping.fragSize = length;
    bookKeeping.infoLowerLimit = (int)dstMsg->infoArray.size();

    // Add the info field content.
    MESSAGE_AppendInfo(node, dstMsg, info->infoArray);

    // Get the messageId first. Only if the database is on
#ifdef ADDON_DB
    StatsDb* db = node->partitionData->statsDb;

    if (db != NULL && db->statsEventsTable->createAppEventsTable)
    {
        StatsDBAppEventParam* appInfo = NULL;
        //appInfo = (StatsDBAppEventParam*) MESSAGE_ReturnInfo(dstMsg, INFO_TYPE_AppStatsDbContent);
        //ERROR_Assert(appInfo != NULL, "Unable to find the info field\n");

        // Get the application Info from the info fields.
        for (unsigned int i = 0; i < info->infoArray.size(); i++)
        {
            if (info->infoArray[i].infoType == INFO_TYPE_AppStatsDbContent)
            {
                appInfo = (StatsDBAppEventParam*)info->infoArray[i].info;
                break;
            }
        }
    }
#endif
    bookKeeping.infoUpperLimit = (int)dstMsg->infoArray.size();
    dstMsg->infoBookKeeping.push_back(bookKeeping);
}


static void TransmitData(
    Node* node,
    infoField_buf* info_buf,
    Message* msg,
    int len,
    int bytesSent,
    int tcpSeqNum)
{
    BOOL morePackets = FALSE;
    // Figure out what to send out agian.
    int packetSize = 0;
    int fragmentSize = 0;
    if (bytesSent < 0)
    {
        // Send from the start.
        bytesSent = 0;
    }
    std::list<infofield_array*>::iterator iter;
    iter = info_buf->info.begin();
    while (iter != info_buf->info.end())
    {
        infofield_array* firstInfo = *iter;
        morePackets = FALSE;
        packetSize += firstInfo->packetSize;
        if (packetSize <= bytesSent)
        {
            iter++;
            continue;
        }
        else
        {
            fragmentSize = packetSize - bytesSent;
            if (len < fragmentSize)
            {
                // So we only have a single packet in this TCP packet.
                MergeInfoField(node, msg, firstInfo, len, 1);
            }
            else
            {
                // We have more than one packet in the TCP packet
                morePackets = TRUE;
                MergeInfoField(node, msg, firstInfo, fragmentSize, 1);
                if (firstInfo->remPktSize != 0)
                {
                    firstInfo->remPktSize = 0;
                }
            }
            break;
        }
    }

     // Now to continue until done with length
    if (morePackets)
    {
        iter++;
        while (fragmentSize < len &&
               iter != info_buf->info.end())
        {
            infofield_array* firstInfo = *iter;
            if ((unsigned)(len - fragmentSize) >= firstInfo->packetSize)
            {
                MergeInfoField(node, msg, firstInfo, firstInfo->packetSize, 1);
                fragmentSize += firstInfo->packetSize;
            }
            else
            {
                MergeInfoField(node, msg, firstInfo, len - fragmentSize, 1);
                fragmentSize += (len - fragmentSize);
            }
            iter++;
        }
    }
}

//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpNegotiatingEcnCapability
// PURPOSE      Set ECE and CWR bits into SYN packet where as
//              ECE bit into SYN + ACK packet.
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpNegotiatingEcnCapability(
    Node *node,
    struct tcpcb *tp,
    int *flags)
{
    TransportDataTcp* tcpLayer =
        (TransportDataTcp*) node->transportData.tcp;

    //
    // In the connection setup phase, the source and destination TCPs
    // have to exchange information about their desire and/or capability to
    // use ECN. This is done by setting both the ECN-Echo flag and the CWR
    // flag in the SYN packet of the initial connection phase by the sender;
    // on receipt of this SYN packet, the receiver will set the ECN-Echo
    // flag in the SYN-ACK response.
    //
    if (tcpLayer->nodeUseEcn) {
        if (tp->t_ecnFlags & TF_ECN) {
            *flags |= TH_ECE;
        }
        else if (!(*flags & TH_ACK)) {
            *flags |= TH_ECE | TH_CWR;
        }
    }
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSetEcnCapablePacket
// PURPOSE      Take a decision that the ECT bit is set into the packet or not.
// RETURN       BOOL
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
BOOL TransportTcpSetEcnCapablePacket(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti)
{
    if (tp->t_ecnFlags & TF_ECN) {

        // The ECT bit is set on all packets other than pure ACK's.
        if ((!(ti->ti_flags & ~TH_ACK))
                && (ti->ti_len <=
                (short)((tcphdrGetDataOffset(ti->ti_t.tcpHdr_x_off))
                << 2)))
        {
            return FALSE;
        }

        // The ECT bit SHOULD NOT be set on retransmitted data packets.
        else if (tp->t_ecnFlags & TF_REXT_PACKET) {
            return FALSE;
        }

        //
        // When a TCP host enters TIME-WAIT or CLOSED state,
        // it should ignore any previous state about the negotiation of ECN
        // for that connection.
        //
        else if (tp->t_state == TCPS_CLOSED
                 || tp->t_state == TCPS_TIME_WAIT) {
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}


//-------------------------------------------------------------------------//
// FUNCTION     TransportTcpSetEcnEchoAndCWR
// PURPOSE      Receiver responds by setting the ECN-Echo flag in the next
//              outgoing ACK packet if congestion occur in the path.
//              Sender reduces its congestion window for any reason, it sets
//              a CWR bit in the TCP header of the next data packet.
// RETURN       None
// ASSUMPTIONS  None
//-------------------------------------------------------------------------//
static
void TransportTcpSetEcnEchoAndCWR(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti)
{

    // When a packet with CE bit set (in the IP header) reaches the receiver,
    // the receiver responds by setting the ECN-Echo flag (in the TCP header)
    // in the next outgoing ACK for the flow.

    if (tp->t_ecnFlags & TF_ECN
            && tp->t_ecnFlags & TF_MUST_ECHO
            && ti->ti_flags & TH_ACK) {
        ti->ti_flags |= TH_ECE;
        TransportTcpTrace(node, 0, 0, "EcnEcho");
    }

    // When TCP host reduces its congestion window for any reason,
    // it sets a Congestion Window Reduced (CWR) bit in the TCP header
    // of the next data packet.

    if ((tp->t_ecnFlags & (TF_ECN|TF_CWR_NOW)) == (TF_ECN|TF_CWR_NOW)
            && (tp->t_ecnFlags & TF_REXT_PACKET) == 0) {
        ti->ti_flags |= TH_CWR;
        tp->t_ecnFlags &= ~TF_CWR_NOW;
        TransportTcpTrace(node, 0, 0, "CWR");
    }
}


//-------------------------------------------------------------------------//
// Tcp output routine: figure out what should be sent and send it.
//-------------------------------------------------------------------------//
void tcp_output(
    Node *node,
    struct tcpcb *tp,
    UInt32 tcp_now,
    struct tcpstat *tcp_stat)
{
    Int32 len, win;
    int off, flags;
    struct tcpiphdr *ti;
    unsigned char opt[TCP_MAXOLEN];
    unsigned int optlen, hdrlen;
    int idle, sendalot;
    struct inpcb *inp = tp->t_inpcb;
    Message *msg;
    TosType priority = inp->priority;

    TransportDataTcp* tcpLayer =
        (TransportDataTcp*) node->transportData.tcp;

    TcpSackItem sackRextItem;
    int sackGapLength = 0;          // if 0, has no valid value
    UInt32 aBufReadCount;

    aBufReadCount = InpSendBufGetCount(&inp->inp_snd, BUF_READ);

    // Determine length of data that should be transmitted,
    // and flags that will be used.
    // If there is some data or critical controls (SYN, RST)
    // to send, then transmit; otherwise, investigate further.

    idle = (tp->snd_max == tp->snd_una);

    if (idle && tp->t_idle >= (unsigned int) tp->t_rxtcur){

        // We have been idle for "a while" and no acks are
        // expected to clock out any data we send --
        // slow start to get ack "clock" running again.
        tp->snd_cwnd = tp->t_maxseg;
    }

again:
    sendalot = 0;

    // Set sack variables active in case we are in a retransmission
    if (TCP_SACK_REXT(tp)
            && tp->snd_nxt != tp->snd_una) {
        tp->sackNextRext = tp->snd_una;
        off = tp->snd_max - tp->snd_una;
        win = MIN(tp->snd_wnd, tp->snd_cwnd);
        if (off < win && TransportTcpSackNextRext(tp, &sackRextItem)) {
            tp->snd_nxt = sackRextItem.leftEdge;
            sackGapLength = sackRextItem.rightEdge - tp->snd_nxt;
        }
        else {
            tp->snd_nxt = tp->snd_max;
            sackGapLength = 0;
        }
    }

    off = tp->snd_nxt - tp->snd_una;

    win = MIN(tp->snd_wnd, tp->snd_cwnd);


    flags = tcp_outflags[tp->t_state];

    // Get standard flags, and add SYN or FIN if requested by 'hidden'
    // state flags.
    if (tp->t_flags & TF_NEEDFIN) {
        flags |= TH_FIN;
    }
    if (tp->t_flags & TF_NEEDSYN) {
        flags |= TH_SYN;
    }

    // If in persist timeout with window of 0, send 1 byte.
    // Otherwise, if window is small but nonzero
    // and timer expired, we will send what we can
    // and go to transmit state.

    if (tp->t_force) {
        if (win == 0) {
            //
            // If we still have some data to send, then
            // clear the FIN bit.  Usually this would
            // happen below when it realizes that we
            // aren't sending all the data.  However,
            // if we have exactly 1 byte of unset data,
            // then it won't clear the FIN bit below,
            // and if we are in persist state, we wind
            // up sending the packet without recording
            // that we sent the FIN bit.
            //
            // We can't just blindly clear the FIN bit,
            // because if we don't have any more data
            // to send then the probe will be the FIN
            // itself.
            //
            if ((UInt32) off < aBufReadCount)
                flags &= ~TH_FIN;
            win = 1;
        } else {
            tp->t_timer[TCPT_PERSIST] = 0;
            tp->t_rxtshift = 0;
        }
    }

    len = MIN(aBufReadCount, (UInt32) win) - off;

    // Adjust length to right edge of gap, if applicable
    if (TCP_SACK_REXT(tp) && sackGapLength) {
        len = MIN(len, sackGapLength);
    }

    // Lop off SYN bit if it has already been sent.  However, if this
    // is SYN-SENT state and if segment contains data, suppress sending
    // segment.

    if ((flags & TH_SYN) && SEQ_GT(tp->snd_nxt, tp->snd_una)) {
        flags &= ~TH_SYN;
        off--, len++;
        if (len > 0 && tp->t_state == TCPS_SYN_SENT)
            return;
    }

    // Be careful not to send data and/or FIN on SYN segments
    // in cases when no CC option will be sent.
    // This measure is needed to prevent interoperability problems
    // with not fully conformant TCP implementations.

    if ((flags & TH_SYN) && (tp->t_flags & TF_NOOPT)){
        len = 0;
        flags &= ~TH_FIN;
    }

    if (len < 0) {

        // If FIN has been sent but not acked,
        // but we haven't been called to retransmit,
        // len will be -1.  Otherwise, window shrank
        // after we sent into it.  If window shrank to 0,
        // cancel pending retransmit, pull snd_nxt back
        // to (closed) window, and set the persist timer
        // if it isn't already going.  If the window didn't
        // close completely, just wait for an ACK.
        len = 0;

        flags &= ~TH_FIN;

        if (win == 0) {
            tp->t_timer[TCPT_REXMT] = 0;
            tp->t_rxtshift = 0;
            tp->snd_nxt = tp->snd_una;
            if (tp->t_timer[TCPT_PERSIST] == 0)
                tcp_setpersist(tp);
        }
    }
    if (len > (Int32) tp->t_maxseg) {
        len = tp->t_maxseg;
        sendalot = 1;
    }

    // For a retransmit, a sack block's left edge may limit
    // the length to a smaller value than the congestion
    // window permits

    if (TCP_SACK_REXT(tp) && !sendalot && len
            && (tp->snd_cwnd > tp->t_maxseg)    //not onset of retransmit
            && SEQ_LT(tp->snd_nxt, tp->sackFastRextSentry)) {
        sendalot = 1;
        TransportTcpTrace(node, 0, 0, "Rext: sendalot set to 1");
    }

    if (SEQ_LT(tp->snd_nxt + len,
               tp->snd_una + aBufReadCount + get_block_pkt_count(inp))) {
        flags &= ~TH_FIN;
    }
    win = sbspace(inp);

    //
    // Sender silly window avoidance.  If connection is idle
    // and can send all data, a maximum segment,
    // at least a maximum default-size segment do it,
    // or are forced, do it; otherwise don't bother.
    // If peer's buffer is tiny, then send
    // when window is at least half open.
    // If retransmitting (possibly after persist timer forced us
    // to send into a small window), then must resend.
    //
    if (len) {
        if (len == (Int32) tp->t_maxseg)
            goto send0;
        if ((idle || tp->t_flags & TF_NODELAY) &&
                (tp->t_flags & TF_NOPUSH) == 0 &&
                (UInt32) (len + off) >= aBufReadCount)
            goto send0;
        if (tp->t_force)
            goto send0;
        if ((UInt32) len >= tp->max_sndwnd / 2 && tp->max_sndwnd > 0)
            goto send0;
        if (SEQ_LT(tp->snd_nxt, tp->snd_max))
            goto send0;
    }

    //
    // Compare available window to amount of window
    // known to peer (as advertised window less
    // next expected input).  If the difference is at least two
    // max size segments, or at least 50% of the maximum possible
    // window, then want to send a window update to peer.
    //
    if (win > 0) {
        //
        // "adv" is the amount we can increase the window,
        // taking into account that we are limited by
        // TCP_MAXWIN << tp->rcv_scale.
        //
        Int32 adv = MIN(win, (Int32)TCP_MAXWIN << tp->rcv_scale) -
                    (tp->rcv_adv - tp->rcv_nxt);

        if (adv >= (Int32) (2 * tp->t_maxseg)) {
            goto send0;
        }
        if (2 * adv >= (Int32) inp->inp_rcv_hiwat) {
            goto send0;
        }
    }

    // Send if we owe peer an ACK.
    if (tp->t_flags & TF_ACKNOW) {
        goto send0;
    }

    if (flags & (TH_SYN|TH_FIN|TH_RST)) {
        goto send0;
    }

    if (SEQ_GT(tp->snd_up, tp->snd_una)) {
        goto send0;
    }

    // If our state indicates that FIN should be sent
    // and we have not yet done so, or we're retransmitting the FIN,
    // then we need to send.

    if (flags & TH_FIN && ((tp->t_flags & TF_SENTFIN) == 0 ||
                           SEQ_LT(tp->snd_nxt, tp->snd_max)))
        goto send0;

    //
    // TCP window updates are not reliable, rather a polling protocol
    // using ``persist'' packets is used to insure receipt of window
    // updates.  The three ``states'' for the output side are:
    //  idle            not doing retransmits or persists
    //  persisting      to move a small or zero window
    //  (re)transmitting    and thereby not persisting
    //
    // tp->t_timer[TCPT_PERSIST]
    //  is set when we are in persist state.
    // tp->t_force
    //  is set when we are called to send a persist packet.
    // tp->t_timer[TCPT_REXMT]
    //  is set when we are retransmitting
    // The output side is idle when both timers are zero.
    //
    // If send window is too small, there is data to transmit, and no
    // retransmit or persist is pending, then go to persist state.
    // If nothing happens soon, send when timer expires:
    // if window is nonzero, transmit what we can,
    // otherwise force out a byte.
    //
    if (aBufReadCount && tp->t_timer[TCPT_REXMT] == 0 &&
            tp->t_timer[TCPT_PERSIST] == 0) {
        tp->t_rxtshift = 0;
        tcp_setpersist(tp);
    }

    // No reason to send a segment, just return.
    TransportTcpTrace(node, 0, 0, "No output");
    return;

send0:

    // Before ESTABLISHED, force sending of initial options
    // unless TCP set not to do any options.
    // NOTE: we assume that the IP/TCP header plus TCP options
    // always fit in a single mbuf, leaving room for a maximum
    // link header, i.e.
    // max_linkhdr + sizeof (struct tcpiphdr) + optlen <= MHLEN

    optlen = 0;
    hdrlen = sizeof (struct tcphdr) + sizeof (struct ipovly);
    if (flags & TH_SYN) {

        TransportTcpNegotiatingEcnCapability(node, tp, &flags);

        tp->snd_nxt = tp->iss;
        if ((tp->t_flags & TF_NOOPT) == 0) {
            unsigned short mss;

            opt[0] = TCPOPT_MAXSEG;
            opt[1] = TCPOLEN_MAXSEG;
            mss = (unsigned short) tcp_mssopt(tp);
            (void)memcpy(opt + 2, &mss, sizeof(mss));
            optlen = TCPOLEN_MAXSEG;

            // Send sack permitted option during handshake
            // For an active open, check if this node's TCP is sack capable.
            // For a passive open, check tp variable which would have been
            //      set on receipt of the first handshake

            if (TCP_VARIANT_IS_SACK(tp)) {
                opt[optlen] = TCPOPT_SACK_PERMITTED;
                opt[optlen+1] = TCPOLEN_SACK_PERMITTED;
                optlen += 2;
                // since cannot see code to ensure 4 octet right edge
                opt[optlen] = TCPOPT_NOP;
                opt[optlen+1] = TCPOPT_NOP;
                optlen += 2;
            }

            if (!TCP_VARIANT_IS_RENO(tp)) {
                if ((tp->t_flags & TF_REQ_SCALE) &&
                        ((flags & TH_ACK) == 0 ||
                         (tp->t_flags & TF_RCVD_SCALE))) {
                    ///((UInt32 *) (opt + optlen)) = (
                    //    TCPOPT_NOP << 24 |
                    //    TCPOPT_WINDOW << 16 |
                    //    TCPOLEN_WINDOW << 8 |
                    //    tp->request_r_scale);

                    (opt + optlen)[0] = TCPOPT_NOP;
                    (opt + optlen)[1] = TCPOPT_WINDOW;
                    (opt + optlen)[2] = TCPOLEN_WINDOW;
                    (opt + optlen)[3] = tp->request_r_scale;

                    optlen += 4;
                }
            }
        }
    }

    // Send a timestamp and echo-reply if this is a SYN and our side
    // wants to use timestamps (TF_REQ_TSTMP is set) or both our side
    // and our peer have sent timestamps in our SYN's.

    if (!TCP_VARIANT_IS_RENO(tp)) {
        if ((tp->t_flags & (TF_REQ_TSTMP|TF_NOOPT)) == TF_REQ_TSTMP &&
                (flags & TH_RST) == 0 &&
                ((flags & TH_ACK) == 0 ||
                 (tp->t_flags & TF_RCVD_TSTMP))) {
            UInt32 *lp = (UInt32 *)(opt + optlen);

            // Form timestamp option as shown in appendix A of RFC 1323.
            //*lp++ = TCPOPT_TSTAMP_HDR;

            // Current BSD code converts rvalue above with htonl(), but
            // code below should be equivalent.

            (opt + optlen)[0] = TCPOPT_NOP;
            (opt + optlen)[1] = TCPOPT_NOP;
            (opt + optlen)[2] = TCPOPT_TIMESTAMP;
            (opt + optlen)[3] = TCPOLEN_TIMESTAMP;
            *lp++;

            *lp++ = tcp_now;
            *lp   = tp->ts_recent;
            optlen += TCPOLEN_TSTAMP_APPA;
        }
    }

    // Fill in Sack options in case of dropped segments
    // Ensure that this is the last coded option, so that as much
    // of balance space in available option field header can be used

    if (TCP_VARIANT_IS_SACK(tp)
            && tp->t_state == TCPS_ESTABLISHED
            && ((tp->t_flags & TF_NOOPT) == 0) ) {
        TransportTcpSackWriteOptions(tp, opt, &optlen);
    }

    hdrlen += optlen;

    //
    // Adjust data length if insertion of options will
    // bump the packet length beyond the t_maxseg length.
    // Clear the FIN bit because we cut off the tail of
    // the segment.
    //
    if (len + optlen > tp->t_maxopd) {

        // If there is still more to send, don't close the connection.
        flags &= ~TH_FIN;
        len = tp->t_maxopd - optlen;
        sendalot = 1;
    }


    // Create a TCP segment, attaching a copy of data to
    // be transmitted, and initialize the header from
    // the template for sends on this connection.

    // allocate the space for a tcp segment and copy data
    msg = MESSAGE_Alloc(node, 0, 0, 0);
    (unsigned char *) prepare_outgoing_packet(
        node,
        msg,
        &(inp->inp_snd),
        len,
        hdrlen,
        off);

    if (len) {
        if (tcp_stat) {
            if (tp->t_force && len == 1) {
                tcp_stat->tcps_sndprobe++;
            } else if (SEQ_LT(tp->snd_nxt, tp->snd_max)) {
                tcp_stat->tcps_sndrexmitpack++;
                //tcp_stat->tcps_sndrexmitbyte += len;
            } else {
                tcp_stat->tcps_sndpack++;
                //tcp_stat->tcps_sndbyte += len;
            }
        }

        //
        // If we're sending everything we've got, set PUSH.
        // (This will keep happy those implementations which only
        // give data to the user when a buffer fills or
        // a PUSH comes in.)
        //
        if ((UInt32) (off + len) == aBufReadCount) {
            if (flags & TH_FIN ) {
                flags |= TH_PUSH; // if FIN bit on, PUSH bit also on
            } else if (tcpLayer->tcpUsePush) {
                flags |= TH_PUSH; // if user specify TCP-PUSH YES
            }
        }

    } else {                              // len == 0
        if (tcp_stat) {
            if (flags & (TH_SYN|TH_FIN|TH_RST))
            {
                tcp_stat->tcps_sndctrl++;
                   if (flags & TH_RST)
                    tcp_stat->tcps_sndrst++;
            }
            else if (tp->t_flags & TF_ACKNOW)
                tcp_stat->tcps_sndacks++;
            else if (SEQ_GT(tp->snd_up, tp->snd_una))
                ;//tcp_stat->tcps_sndurg++;
            else
                tcp_stat->tcps_sndwinup++;
        }
    }

    ti = (tcpiphdr*) MEM_malloc((sizeof(tcpiphdr) + optlen));

    assert(tp->t_template != 0);
    (void)memcpy(ti, tp->t_template, sizeof (struct tcpiphdr));

    // Fill in fields, remembering maximum advertised
    // window for use in delaying messages about window sizes.
    // If resending a FIN, be sure not to use a new sequence number.

    //
    // If we are doing retransmissions, then snd_nxt will
    // not reflect the first unsent octet.  For ACK only
    // packets, we do not want the sequence number of the
    // retransmitted packet, we want the sequence number
    // of the next unsent octet.  So, if there is no data
    // (and no SYN or FIN), use snd_max instead of snd_nxt
    // when filling in ti_seq.  But if we are in persist
    // state, snd_max might reflect one byte beyond the
    // right edge of the window, so use snd_nxt in that
    // case, since we know we aren't doing a retransmission.
    // (retransmit and persist are mutually exclusive...)
    //
    if (len || (flags & (TH_SYN|TH_FIN)) || tp->t_timer[TCPT_PERSIST]) {
        ti->ti_seq = tp->snd_nxt;
    } else {
        ti->ti_seq = tp->snd_max;
    }
    ti->ti_ack = tp->rcv_nxt;
    if (optlen) {
        memcpy(ti + 1, opt, optlen);
        tcphdrSetDataOffset(&(ti->ti_t.tcpHdr_x_off),
            ((sizeof (struct tcphdr) + optlen) >> 2));
    }
    ti->ti_flags = (unsigned char)flags;

    // Calculate receive window.  Don't shrink window,
    // but avoid silly window syndrome.
    if (win < (Int32)(inp->inp_rcv_hiwat / 4) && win < (Int32)tp->t_maxseg)
        win = 0;
    if (!TCP_VARIANT_IS_RENO(tp)) {
        if (win > (Int32)TCP_MAXWIN << tp->rcv_scale)
            win = (Int32)TCP_MAXWIN << tp->rcv_scale;
    }
    if (win < (Int32)(tp->rcv_adv - tp->rcv_nxt))
        win = (Int32)(tp->rcv_adv - tp->rcv_nxt);
    if (!TCP_VARIANT_IS_RENO(tp)) {
        ti->ti_win = (unsigned short) (win>>tp->rcv_scale);
    }
    else {
        ti->ti_win = (unsigned short) win;
    }

    if (SEQ_GT(tp->snd_up, tp->snd_nxt)) {
        ti->ti_urp = (unsigned short)(tp->snd_up - tp->snd_nxt);
        ti->ti_flags |= TH_URG;
    } else {

        // If no urgent pointer to send, then we pull
        // the urgent pointer to the left edge of the send window
        // so that it doesn't drift into the send window on sequence
        // number wraparound.

        tp->snd_up = tp->snd_una;       // drag it along
    }

    // Put TCP length in extended header, and then
    // checksum extended header and data.
    if (len + optlen) {
        ti->ti_len = (unsigned short)(sizeof (struct tcphdr) + optlen + len);
    }

    /* Checksum commented out because QualNet currently does not
       model bit errors
    ti->ti_sum = in_cksum((unsigned short *)tcpseg, (int)(hdrlen + len));
    */

    // In transmit state, time the transmission and arrange for
    // the retransmit.  In persist state, just set snd_max.

    if (tp->t_force == 0 || tp->t_timer[TCPT_PERSIST] == 0) {
        tcp_seq startseq = tp->snd_nxt;

        // Advance snd_nxt over sequence space of this segment.
        if (flags & (TH_SYN|TH_FIN)) {
            if (flags & TH_SYN) {
                tp->snd_nxt++;
            }
            if (flags & TH_FIN) {
                tp->snd_nxt++;
                tp->t_flags |= TF_SENTFIN;
            }
        }

        if (TCP_SACK_REXT(tp)
                &&  SEQ_LT(tp->snd_nxt, tp->sackFastRextSentry)) {
            TransportTcpSackAddToSndList(tp,
                                         tp->snd_nxt, tp->snd_nxt + len);
            tp->snd_cwnd -= tp->t_maxseg;
            TransportTcpTrace(node, tp, 0, "sndList");
        }

        tp->snd_nxt += len;

        if (SEQ_GT(tp->snd_nxt, tp->snd_max)) {
            tp->snd_max = tp->snd_nxt;

            // Time this transmission if not a retransmission and
            // not currently timing anything.
            if (tp->t_rtt == 0) {
                tp->t_rtt = 1;
                tp->t_rtseq = startseq;
                //if (tcp_stat)
                //tcp_stat->tcps_segstimed++;
            }
        }

        //
        // Set retransmit timer if not currently set,
        // and not doing an ack or a keep-alive probe.
        // Initial value for retransmit timer is smoothed
        // round-trip time + 2 * round-trip time variance.
        // Initialize shift counter which is used for backoff
        // of retransmit time.
        //
        if (tp->t_timer[TCPT_REXMT] == 0 &&
                tp->snd_nxt != tp->snd_una) {
            tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
            if (tp->t_timer[TCPT_PERSIST]) {
                tp->t_timer[TCPT_PERSIST] = 0;
                tp->t_rxtshift = 0;
            }
        }
    } else {
        if (SEQ_GT(tp->snd_nxt + len, tp->snd_max)) {
            tp->snd_max = tp->snd_nxt + len;
        }
    }

    // Now to attach the info field to the message.
    int pktRetransmit = 0;
#ifdef DEBUG
    BOOL updateRetransmitList = FALSE;
#endif

    pktRetransmit = inp->info_buf->pktSizeRemovedFromBuffer;

    if (len > 0)
    {
        if (!inp->info_buf->setTcpSeqNum)
        {
            inp->info_buf->initTcpSeqNum = ti->ti_seq;
            inp->info_buf->setTcpSeqNum = TRUE;
        }
        int bytesSent = ti->ti_seq - inp->info_buf->initTcpSeqNum;

        TransmitData(node,
            inp->info_buf,
            msg,
            len,
            bytesSent,
            ti->ti_seq);
    }

    // Send the packet to the IP model.
    // Remove the ipovly pseudo-header beforehand.
    {
        Address destinationAddress = ti->ti_dst;
        BOOL anEcnCapablePacket;
#ifdef ECN_DEBUG_TEST
        int dropCount = ECN_TEST_PKT_DROP;
        tcp_seq dropValues[] = { 13002};
        static int dropFlag[] = { 1};
#endif // ECN_DEBUG_TEST

#ifdef DEBUG
        {
            char clockStr[100];
            char ipAddrStr[MAX_STRING_LENGTH];

            ctoa(node->getNodeTime(), clockStr);
            IO_ConvertIpAddressToString(&ti->ti_src, ipAddrStr);

            printf("Node %u sending segment to ip_dst %s at time %s\n",
                   node->nodeId, ipAddrStr, clockStr);

            printf("    size = %d\n", msg->packetSize);
            printf("    seqno = %d\n", ti->ti_seq);
            printf("    ack = %d\n", ti->ti_ack);
            printf("    type =");

            if (flags & TH_FIN)
            {
                printf(" FIN |");
            }
            if (flags & TH_SYN)
            {
                printf(" SYN |");
            }
            if (flags & TH_RST)
            {
                printf(" RST |");
            }
            if (flags & TH_PUSH)
            {
                printf(" PUSH |");
            }
            if (flags & TH_ACK)
            {
                printf(" ACK |");
            }
            if (flags & TH_URG)
            {
                printf(" URG |");
            }

            printf("\n");
        }
#endif // DEBUG

        anEcnCapablePacket = TransportTcpSetEcnCapablePacket(node, tp, ti);
        TransportTcpSetEcnEchoAndCWR(node, tp, ti);

        TransportTcpTrace(node, tp, ti, "output");
        if (anEcnCapablePacket) {
            TransportTcpTrace(node, 0, 0, "ECT");
        }
        TransportTcpTrace(node, tp, ti, "variables");

        MESSAGE_RemoveHeader(node, msg, sizeof(struct ipovly), TRACE_TCP);

        memcpy(
            MESSAGE_ReturnPacket(msg),
            &ti->ti_t,
            sizeof (struct tcphdr));

        memcpy(
            MESSAGE_ReturnPacket(msg) + sizeof (struct tcphdr),
            (ti + 1), optlen);

        // Hack solution for TCP trace.
        msg->headerSizes[msg->numberOfHeaders] -= sizeof(struct ipovly);
        msg->numberOfHeaders++;

        // Trace sending packet. We don't trace the IP pseudo header
        ActionData acnData;
        acnData.actionType = SEND;
        acnData.actionComment = NO_COMMENT;
        TRACE_PrintTrace(node, msg, TRACE_TRANSPORT_LAYER, PACKET_OUT, &acnData);

#ifdef ADDON_DB

    // Here we add the packet to the Network database.
    // Gather as much information we can for the database.      
        
    HandleTransportDBEvents(
        node,
        msg,
        tp->outgoingInterface,          
        "TCPSendToLower",        
        ti->ti_sport,
        ti->ti_dport,
        sizeof (struct tcphdr) + optlen,
        ti->ti_len);      

    HandleTransportDBSummary(
        node,
        msg,
        tp->outgoingInterface,  
        "TCPSend",        
        ti->ti_src,
        ti->ti_dst,
        ti->ti_sport,
        ti->ti_dport,        
        ti->ti_len);      

    HandleTransportDBAggregate(
        node,
        msg,
        tp->outgoingInterface,          
        "TCPSend", ti->ti_len);
#endif
    int * sessionIdInfo =  (int *)
        MESSAGE_ReturnInfo( msg, INFO_TYPE_StatsDbAppSessionId);        
    if (sessionIdInfo == NULL)
    {            
        sessionIdInfo = (int*) MESSAGE_AddInfo(
            node, msg, sizeof(int), INFO_TYPE_StatsDbAppSessionId);        
        *sessionIdInfo = inp->unique_id;
    }         

        TransportDataTcp *tcpLayer = (TransportDataTcp *) node->transportData.tcp;
        if (tcpLayer->tcpStatsEnabled)
        {
            int headerSize = ti->ti_t.tcpHdr_x_off * 4;
            if (headerSize < ti->ti_len)
            {
                // Data packet
                tcpLayer->newStats->AddSegmentSentDataPoints(
                    node,
                    msg,
                    0,
                    ti->ti_len - headerSize,
                    headerSize,
                    ti->ti_src,
                    ti->ti_dst,
                    ti->ti_sport,
                    ti->ti_dport);
            }
            else
            {
                // Control packet
                tcpLayer->newStats->AddSegmentSentDataPoints(
                    node,
                    msg,
                    ti->ti_len,
                    0,
                    0,
                    ti->ti_src,
                    ti->ti_dst,
                    ti->ti_sport,
                    ti->ti_dport);
            }
        }
#ifdef ECN_DEBUG_TEST

        // Drop some specific data packets (for testing)
        if (dropCount) {
            int counter;
            for (counter = 0; counter < dropCount; counter++) {
                if (ti->ti_seq == dropValues[counter] && dropFlag[counter]){
                    TransportTcpTrace(node, 0, 0, "packet drop for ECN");
                    printf ("\nSequence number of drop packet (for testing)"
                            " %u\n\n", ti->ti_seq);
                    dropFlag[counter]--;
                }
                else {
                    NetworkIpReceivePacketFromTransportLayer(
                        node,
                        msg,
                        ti->ti_src,
                        destinationAddress,
                        tp->outgoingInterface,
                        priority,
                        IPPROTO_TCP,
                        anEcnCapablePacket);
                }
            }
        }
        else {
            NetworkIpReceivePacketFromTransportLayer(
                node,
                msg,
                ti->ti_src,
                destinationAddress,
                tp->outgoingInterface,
                priority,
                IPPROTO_TCP,
                anEcnCapablePacket);
        }
#else
        NetworkIpReceivePacketFromTransportLayer(
            node,
            msg,
            ti->ti_src,
            destinationAddress,
            tp->outgoingInterface,
            priority,
            IPPROTO_TCP,
            anEcnCapablePacket,
            inp->ttl);
#endif // ECN_DEBUG_TEST

        tp->t_ecnFlags &= ~TF_REXT_PACKET;
    }

    if (tcp_stat)
    {
        tcp_stat->tcps_sndtotal++;
    }

    // Data sent (as far as we can tell).
    // If this advertises a larger window than any other segment,
    // then remember the size of the advertised window.
    // Any pending ACK has now been sent.

    if (win > 0 && SEQ_GT(tp->rcv_nxt+win, tp->rcv_adv))
    {
        tp->rcv_adv = tp->rcv_nxt + win;
    }

    tp->last_ack_sent = tp->rcv_nxt;
    tp->t_flags &= ~(TF_ACKNOW|TF_DELACK);

    MEM_free(ti);

    if (sendalot)
    {
        goto again;
    }
}


//-------------------------------------------------------------------------//
// tcp_setpersist routine: set the persist timer.
//-------------------------------------------------------------------------//
void tcp_setpersist(struct tcpcb *tp)
{
    int t = ((tp->t_srtt >> 2) + tp->t_rttvar) >> 1;

    assert(tp->t_timer[TCPT_REXMT] == 0);

    // Start/restart persistance timer.
    TCPT_RANGESET(
        tp->t_timer[TCPT_PERSIST],
        t * tcp_backoff[tp->t_rxtshift],
        TCPTV_PERSMIN, TCPTV_PERSMAX);
    if (tp->t_rxtshift < TCP_MAXRXTSHIFT)
    {
        tp->t_rxtshift++;
    }
}
