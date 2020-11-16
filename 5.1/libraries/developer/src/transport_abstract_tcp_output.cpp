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
// This file contains Abstract TCP output routine and ancillary functions.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "network_ip.h"
#include "transport_abstract_tcp.h"
#include "transport_abstract_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_abstract_tcp_var.h"
#include "transport_abstract_tcp_proto.h"

#define DEBUG 0

//
// Change this value to the number of drops required
// e.g. #define ECN_TEST_PKT_DROP 3 for 3 drops
// The value should be 0 (zero) for no drops
//
//-------------------------------------------------------------------------
// Tcp sent ACK.
//-------------------------------------------------------------------------
void TransportTcpTransmitAck(Node* node,
                             struct abs_tcpcb* tp,
                             struct tcpstat* tcp_stat)
{
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;
    Message* msg = MESSAGE_Alloc(node, 0, 0, 0);
    struct abstract_tcphdr* ti;

    MESSAGE_PacketAlloc(
        node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);


    if (tcp_stat) {
        tcp_stat->tcps_sndacks++;
    }

    ti = (struct abstract_tcphdr*)(msg->packet);

    // Fill in fields, remembering maximum advertised
    // window for use in delaying messages about window sizes.

    ti->th_src = GetIPv4Address(tp->local_addr);
    ti->th_sport = tp->local_port;
    ti->th_dst = GetIPv4Address(tp->remote_addr);
    ti->th_dport = tp->remote_port;
    ti->th_seq = 0;
    ti->th_ack = tp->rcv_nxt;

    // Calculate receive window.  Don't shrink window,
    // but avoid silly window syndrome.
    // Calculate advertised window -- need to modify
    ti->th_win = (unsigned short)tp->rcv_adv;

    // Send the packet to the IP model.
    {
        NodeAddress destinationAddress = ti->th_dst;

        if (DEBUG) {
            char clockStr[100];

            ctoa(node->getNodeTime(), clockStr);

            printf("Node %u sending segment to ip_dst %u at time %s\n",
                   node->nodeId, destinationAddress, clockStr);

            printf("    size = %d\n", msg->packetSize);
            printf("    seqno = %d\n", ti->th_seq);
            printf("    ack = %d\n", ti->th_ack);
            printf("    type =");

            printf("\n");
        }

    //Trace
    if (tcpLayer->trace &&
        (tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_BOTH ||
            tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_OUTPUT))
        TransportAbstractTcpTrace(node, tp, ti, 0);

        //TRACE_PrintTrace(node, msg, TRACE_TRANSPORT_LAYER);

        NetworkIpReceivePacketFromTransportLayer(node,
                                                 msg,
                                                 ti->th_src,
                                                 destinationAddress,
                                                 tp->outgoingInterface,
                                                 tp->priority,
                                                 IPPROTO_TCP,
                                                 FALSE);

        tp->t_ecnFlags &= ~TF_REXT_PACKET;
    }

    if (tcp_stat) {
        tcp_stat->tcps_sndtotal++;
    }

    // Data sent (as far as we can tell).
    // If this advertises a larger window than any other segment,
    // then remember the size of the advertised window.
    // Any pending ACK has now been sent.
    tp->last_ack_sent = tp->rcv_nxt;
}


//-------------------------------------------------------------------------
// Tcp output routine: figure out what should be sent and send it.
//-------------------------------------------------------------------------
void tcp_output(Node* node,
                struct abs_tcpcb* tp,
                UInt32 tcp_now,
                struct tcpstat* tcp_stat)
{
    int send = 0;

    if (tp->cached == 0) {
        if(tp->t_state == TCPS_CLOSED) {
            return;
        }
        return;
    }

    if ((tp->snd_una == 1) && (tp->snd_nxt > tp->snd_una))
        return;

    while (SEQ_GT (tp->snd_max, tp->snd_nxt)) {
        //need to transmitData
        if (tp->sendBuffer[tp->lastSendBufferIndex%tp->sendBufferSize] ) {
            int packetSize = (short)MESSAGE_ReturnPacketSize
            (tp->sendBuffer[tp->lastSendBufferIndex%tp->sendBufferSize]);

            //if (tcp_stat)
            //{
            //    tcp_stat->tcps_sndpack++;
            //    tcp_stat->tcps_sndbyte += packetSize;
            //}

            if( tp->snd_nxt + packetSize <= tp->snd_max) {
                if (tcp_stat) {
                    tcp_stat->tcps_sndpack++;
                }
                TransportTcpSendPacket(node, tp, tp->snd_nxt,
                tp->sendBuffer[tp->lastSendBufferIndex%tp->sendBufferSize]);
                tp->snd_wnd += packetSize;
                tp->snd_nxt += packetSize;
                tp->lastSendBufferIndex = (tp->lastSendBufferIndex+1);
                send++;
            }
            else {
                break;
            }
        }
        else {
            break;
        }

        if(tp->t_timer[TCPT_REXMT] == 0 &&
            tp->snd_nxt != tp->snd_una) {
            tp->t_timer[TCPT_REXMT] = tp->t_rxtcur;
        }
    }
}


//-------------------------------------------------------------------------
// Tcp sent data.
//-------------------------------------------------------------------------
void TransportTcpSendPacket(Node* node,
                            struct abs_tcpcb* tp,
                            tcp_seq seq,
                            Message* old)
{
    struct abstract_tcphdr* ti;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    Message* msg = MESSAGE_Duplicate(node, old);

    MESSAGE_AddHeader(node, msg, sizeof(struct abstract_tcphdr), TRACE_TCP);
    memset(msg->packet, 0, sizeof(struct abstract_tcphdr));
    ti = (struct abstract_tcphdr*)(msg->packet);
    ti->th_dst = GetIPv4Address(tp->remote_addr);
    ti->th_src = GetIPv4Address(tp->local_addr);
    ti->th_dport = tp->remote_port;
    ti->th_sport = tp->local_port;
    ti->th_seq = seq;
    ti->th_ack = 0;

    if(tp->t_state == TCPS_CLOSED && tp->cached <= tp->t_maxseg)
    { //closed pkt
        ti->th_seq = TCPS_CLOSE_WAIT;
        ti->th_ack = TCPS_CLOSE_WAIT;
    }

   //TRACE_PrintTrace(node, msg, TRACE_TRANSPORT_LAYER);

    //Trace
    if (tcpLayer->trace &&
        (tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_BOTH ||
            tcpLayer->traceDirection == ABS_TCP_TRACE_DIRECTION_OUTPUT))
        TransportAbstractTcpTrace(node, tp, ti,
          (MESSAGE_ReturnPacketSize(msg) - sizeof(struct abstract_tcphdr)));

   //RTT initiate
   if(tp->t_rtt == 0) {
      tp->t_rtt = 1;
      tp->t_rtseq = seq;
//      if(tcpLayer->tcpStat)
//        tcpLayer->tcpStat->tcps_segstimed++;
   }

   if(tcpLayer->tcpStat) {
        tcpLayer->tcpStat->tcps_sndtotal++;

//            tcpLayer->tcpStat->tcps_sndrexmitbyte +=
//                MESSAGE_ReturnPacketSize(old);
   }

   NetworkIpReceivePacketFromTransportLayer(
            node,
            msg,
            ti->th_src,
            ti->th_dst,
            tp->outgoingInterface,
            tp->priority,
            IPPROTO_TCP,
            FALSE);
}
