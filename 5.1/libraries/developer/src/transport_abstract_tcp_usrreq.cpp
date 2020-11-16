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
// This file contains Abstract TCP functions that process
// application requests.
//

#include <stdio.h>
#include <stdlib.h>

#include "api.h"

#include "transport_abstract_tcp.h"
#include "transport_abstract_tcp_seq.h"
#include "transport_tcp_timer.h"
#include "transport_abstract_tcp_var.h"
#include "transport_abstract_tcp_proto.h"

#define DEBUG 0

//-------------------------------------------------------------------------
// Do a send by putting data in output queue and
// possibly send more data.
//-------------------------------------------------------------------------
void tcp_send(Node* node,
              struct abs_tcpcb* phead,
              int conn_id,
              Message* msg,
              int actualLength,
              int virtualLength,
              UInt32 tcp_now,
              struct tcpstat* tcp_stat)
{
    struct abs_tcpcb* tp = tcpcbsearch(phead, conn_id);

    if (tp ==NULL) {
        char buf[MAX_STRING_LENGTH];
        // can't find the tcpcb block for this connection
        sprintf(buf, "TCP: can't find (id=%u,conn=%d)\n", node->nodeId,
            conn_id);
        ERROR_Assert(FALSE, buf);
        return;
    }

    unsigned int packetSize = MESSAGE_ReturnPacketSize(msg);

    if ((tp->cached + packetSize) <= tp->sendBufferSize) {
        if (packetSize <= tp->t_maxseg) {
            tp->sendBuffer[tp->cacheIndex] = msg;
            tp->cacheIndex++;
            tp->cacheIndex %= (tp->sendBufferSize);
            tp->cached += (short)MESSAGE_ReturnPacketSize(msg);
            tp->last_buf_pkt_size = MESSAGE_ReturnPacketSize(msg);
        }
        else {
            ERROR_ReportWarningArgs("IT should not be happend : "
                                    "pkt is too big %d\n",
                                    node->nodeId);
            MESSAGE_Free(node,msg);
        }

        if (tp->cached <= (tp->sendBufferSize - tp->t_maxseg)) {
            Message* newMsg;
            TransportToAppDataSent* dataSent;

            newMsg = MESSAGE_Alloc(
                node, APP_LAYER, tp->app_type, MSG_APP_FromTransDataSent);
            MESSAGE_InfoAlloc(node, newMsg, sizeof(TransportToAppDataSent));
            dataSent = (TransportToAppDataSent*) MESSAGE_ReturnInfo(newMsg);
            dataSent->connectionId = tp->con_id;
            dataSent->length = tp->last_buf_pkt_size;
            MESSAGE_Send(node, newMsg, TRANSPORT_DELAY);
        }
    }
    else {
        ERROR_ReportWarningArgs("IT should not be happend : available space "
                                "is not sufficent for this pkt in node %d \n",
                                node->nodeId);
        MESSAGE_Free(node, msg);
    }

    if (tp->cached > 0) {
        tcp_output(node, tp, tcp_now, tcp_stat);
    }
}


//-------------------------------------------------------------------------
// Common subroutine to open a TCP connection to remote host specified
// by remote_addr.
//-------------------------------------------------------------------------
void tcp_connect(Node* node,
                 struct abs_tcpcb* phead,
                 AppType app_type,
                 Address* local_addr,
                 short local_port,
                 Address* remote_addr,
                 short remote_port,
                 UInt32 tcp_now,
                 tcp_seq* tcp_iss,
                 struct tcpstat* tcp_stat,
                 Int32 unique_id,
                 TosType priority,
                 int outgoingInterface)
{
    struct abs_tcpcb* tp;
    int result = 0;
    Message* msg;
    TransportToAppOpenResult* tcpOpenResult;

    // check whether this connection already exists
    tp = (struct abs_tcpcb*) tcpcblookup(phead,
                                         local_addr,
                                         local_port,
                                         remote_addr,
                                         remote_port,
                                         TCPCB_NO_WILDCARD);

    if (tp != NULL) {
        // connection already exists
        result = -1;
    } else {

        // create tcpcb for this connection
        tp  = tcp_attach(node,
                         phead,
                         app_type,
                         local_addr,
                         local_port,
                         remote_addr,
                         remote_port,
                         unique_id,
                         priority);
    }

    if (result == -1) {

        // report failure to application and stop processing this message
        msg = MESSAGE_Alloc(node, APP_LAYER,
            app_type, MSG_APP_FromTransOpenResult);
        MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppOpenResult));
        tcpOpenResult = (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);
        tcpOpenResult->type = TCP_CONN_ACTIVE_OPEN;
        tcpOpenResult->localAddr = tp->local_addr;
        tcpOpenResult->localPort = tp->local_port;
        tcpOpenResult->remoteAddr = tp->remote_addr;
        tcpOpenResult->remotePort = tp->remote_port;
        tcpOpenResult->connectionId = result;

        tcpOpenResult->uniqueId = tp->unique_id;

        MESSAGE_Send(node, msg, TRANSPORT_DELAY);
        return;
    }

    //
    // Set receiving window scale.
    // Enter ESTABLISHED state.
    // Start keepalive timer and seed output sequence space.
    // Send initial segment on connection.
    //
    tp->t_state = TCPS_ESTABLISHED;
    tp->t_timer[TCPT_KEEP] = TCPTV_KEEP_INIT;
    tp->outgoingInterface = outgoingInterface;

//    if (tcp_stat)
//        tcp_stat->tcps_connattempt++;

    abstract_tcp_sendseqinit(tp);
    tp->snd_wnd = 0;

    msg = MESSAGE_Alloc(node, APP_LAYER,
        app_type, MSG_APP_FromTransOpenResult);
    MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppOpenResult));
    tcpOpenResult = (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);
    tcpOpenResult->type = TCP_CONN_ACTIVE_OPEN;
    tcpOpenResult->localAddr = tp->local_addr;
    tcpOpenResult->localPort = tp->local_port;
    tcpOpenResult->remoteAddr = tp->remote_addr;
    tcpOpenResult->remotePort = tp->remote_port;
    tcpOpenResult->connectionId = tp->con_id;
    tcpOpenResult->uniqueId = unique_id;

    MESSAGE_Send(node, msg, TRANSPORT_DELAY);
}


//-------------------------------------------------------------------------
// Prepare to accept connections.
//-------------------------------------------------------------------------
void tcp_listen(Node* node,
                struct abs_tcpcb* head,
                AppType app_type,
                Address* local_addr,
                short local_port,
                TosType priority)
{
    int result;
    struct abs_tcpcb* tp;
    Message* msg;
    TransportToAppListenResult* tcpListenResult;

    tp = tcpcblookup(head, local_addr, local_port, 0, 0, TCPCB_WILDCARD);

    if (tp != NULL) {
        result = -2;      // listen failed, server already set up
    }
    else {
        Address anAddress;
        Address_SetToAnyAddress(&anAddress, local_addr);

        tp = tcp_attach(node,
                        head,
                        app_type,
                        local_addr,
                        local_port,
                        &anAddress,
                        -1,
                        -1,
                        priority);

        if (tp == NULL) {
            result = -1;  // listen failed
        }
        else {
            abstract_tcp_sendseqinit(tp);
            result = tp->con_id; // listen succeeded
        }
    }

    // report status to application
    // result = -2, server port already set up
    // result = -1, failed to set up the server port
    // result >= 0, succeeded
    //
    msg = MESSAGE_Alloc(node, APP_LAYER, app_type,
                        MSG_APP_FromTransListenResult);
    MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppListenResult));
    tcpListenResult = (TransportToAppListenResult*) MESSAGE_ReturnInfo(msg);
    tcpListenResult->localAddr = *local_addr;
    tcpListenResult->localPort = local_port;
    tcpListenResult->connectionId = result;
    MESSAGE_Send(node, msg, TRANSPORT_DELAY);
}


//-------------------------------------------------------------------------
// Attach TCP protocol, allocating
// internet protocol control block, tcp control block,
// buffer space, initialize connection state to CLOSED.
//-------------------------------------------------------------------------
struct abs_tcpcb* tcp_attach(Node* node,
                             struct abs_tcpcb* head,
                             AppType app_type,
                             Address* local_addr,
                             short local_port,
                             Address* remote_addr,
                             short remote_port,
                             Int32 unique_id,
                             TosType priority)
{
    struct abs_tcpcb* tp;
    TransportDataAbstractTcp* tcpLayer = (TransportDataAbstractTcp*)
                                                node->transportData.tcp;

    // tcpcb for connections
    tp = tcpcballoc(tcpLayer->tcpSendBuffer, tcpLayer->tcpRecvBuffer);

    if (tp == NULL)
        return (tp);

    tp->next = NULL;

    if (tcpLayer->tcpRecvBuffer > 0) {
        tp->recvBuffer = (Message**)
            MEM_malloc(tcpLayer->tcpRecvBuffer * sizeof(Message*));
        ERROR_Assert(tp->recvBuffer != NULL,
            "ABSTRACT-TCP: Receive buffer is not allocated.\n");

        tp->recvBufferSize = tcpLayer->tcpRecvBuffer;
        memset(tp->recvBuffer, 0,
            (tcpLayer->tcpRecvBuffer * sizeof(Message*)));
    }

    if (tcpLayer->tcpSendBuffer > 0) {
        tp->sendBuffer = (Message**)
            MEM_malloc(tcpLayer->tcpSendBuffer * sizeof(Message*));
        ERROR_Assert(tp->sendBuffer != NULL,
            "ABSTRACT-TCP: Send buffer is not allocated.\n");

        tp->sendBufferSize = tcpLayer->tcpSendBuffer;
        memset(tp->sendBuffer, 0,
            (tcpLayer->tcpSendBuffer * sizeof(Message*)));
    }

    if (tcpLayer->head == NULL) {//new entry
        tcpLayer->head = tp;
    }
    else {
        tp->next = tcpLayer->head;
        tcpLayer->head = tp;
    }

    tp->mss = tp->t_maxseg = tp->t_maxopd = tcpLayer->tcpMss;
    tp->iss = 1;
    tp->t_srtt = TCPTV_SRTTBASE;
    tp->t_rttvar = ((TCPTV_RTOBASE-TCPTV_SRTTBASE) << TCP_RTTVAR_SHIFT);
    tp->t_rttmin = TCPTV_MIN;
    tp->t_rxtcur = TCPTV_RTOBASE*2;
    tp->snd_cwnd = tp->t_maxseg;
    tp->snd_ssthresh = TCP_MAXWIN;
    tp->app_type = app_type;
    tp->local_addr = *local_addr;
    tp->local_port = local_port;
    tp->remote_addr = *remote_addr;
    tp->remote_port = remote_port;
    tp->con_id = ++tcpLayer->con_id;

    tp->unique_id = unique_id;
    tp->priority = priority;

    tp->t_state = TCPS_ESTABLISHED;
    tp->snd_nxt = tp->snd_una = tp->iss;
    tp->recvBufferSize = tcpLayer->tcpRecvBuffer;
    tp->sendBufferSize = tcpLayer->tcpSendBuffer;
    tp->snd_scale = TCP_MAX_WINSHIFT;
    tp->rcv_adv = tcpLayer->tcpRecvBuffer;

    tp->startRecvBufferIndex = tp->lastRecvBufferIndex = 0;
    tp->startSendBufferIndex = tp->lastSendBufferIndex = tp->cacheIndex = 0;
    tp->start_recv_seq = tp->last_recv_seq = tp->iss;
    tp->cached = 0;

    return (tp);
}


//-------------------------------------------------------------------------
// Allocate a abs_tcpcb structure.
//-------------------------------------------------------------------------
struct abs_tcpcb* tcpcballoc(int snd_bufsize,
                             int rcv_bufsize)
{
    struct abs_tcpcb* tp;

    tp = (struct abs_tcpcb*)MEM_malloc(sizeof(struct abs_tcpcb));

    ERROR_Assert(tp != NULL,
        "ABSTRACT-TCP: tp block is not allocated.\n");

    memset((char*)tp, 0, sizeof(struct abs_tcpcb));
    return tp;
}

//-------------------------------------------------------------------------
// Look for a pcb in a queue using 4-tuple.
//-------------------------------------------------------------------------
struct abs_tcpcb* tcpcblookup(struct abs_tcpcb* head,
                              Address* local_addr,
                              short local_port,
                              Address* remote_addr,
                              short remote_port,
                              BOOL flag)
{
    struct abs_tcpcb* tp;

    for (tp = head; tp != NULL; tp = tp->next) {
        if (tp->local_port != local_port) continue;
        if (!Address_IsSameAddress(&tp->local_addr, local_addr)) continue;
        if (tp->remote_port == -1 && Address_IsAnyAddress(&tp->remote_addr)
            && flag == TCPCB_WILDCARD)
            return tp;
        if (tp->remote_port != remote_port) continue;
        if (!Address_IsSameAddress(&tp->remote_addr, remote_addr)) continue;
        break;
    }
    return tp;
}



//-------------------------------------------------------------------------
// Search a pcb in a queue using connection id.
//-------------------------------------------------------------------------
struct abs_tcpcb* tcpcbsearch(struct abs_tcpcb* head,
                              int con_id)
{
    struct abs_tcpcb* tp;

    for (tp = head; tp != NULL; tp = tp->next) {
        if (DEBUG) {
            printf("SEARCH :%d %d \n",
                tp->con_id, con_id);
        }

        if (tp->con_id == con_id) return tp;
    }
    return NULL;
}

//-------------------------------------------------------------------------
// Close a TCP control block:
//      discard all space held by the tcp
//      discard internet protocol block
//      wake up any sleepers
//-------------------------------------------------------------------------
void tcp_close(Node* node,
               struct abs_tcpcb** head,
               unsigned int con_id,
               struct tcpstat* tcp_stat)
{
    Message* msg;
    TransportToAppCloseResult* tcpCloseResult;

    struct abs_tcpcb* tp  = tcpcbsearch(*head, con_id);

    ERROR_Assert(tp != NULL, "ABSTRACT-TCP: tp block is not exist.\n");

    if (tp->cached != 0) {
        //tp->t_state = TCPS_CLOSE_WAIT;
        tp->t_state = TCPS_FIN_WAIT_1;
        return;
    }

    if (tp->t_state != TCPS_CLOSED) {

        tp->t_state = TCPS_CLOSED;

        msg = MESSAGE_Alloc(node, APP_LAYER,
            tp->app_type, MSG_APP_FromTransCloseResult);
        MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppCloseResult));
        tcpCloseResult = (TransportToAppCloseResult*) MESSAGE_ReturnInfo(msg);
        tcpCloseResult->type = TCP_CONN_PASSIVE_CLOSE;
        tcpCloseResult->connectionId = tp->con_id;
        MESSAGE_Send(node, msg, TRANSPORT_DELAY);

        if (tp->app_type == APP_GEN_FTP_CLIENT) {
            tcp_drop(node, head, con_id);
        }
    }
}

//-------------------------------------------------------------------------
// DROP a TCP control block after connection is closed.
//-------------------------------------------------------------------------
void tcp_drop(Node* node,
               struct abs_tcpcb** head,
               unsigned int con_id)
{
    BOOL flag = FALSE;
    struct abs_tcpcb* temp = *head;
    struct abs_tcpcb* tp  = tcpcbsearch(*head, con_id);

    if (tp ==NULL) {
        char buf[MAX_STRING_LENGTH];
        // can't find the tcpcb block for this connection
        sprintf(buf, "TCP: can't find (id=%u,conn=%d)\n", node->nodeId,
            con_id);
        ERROR_Assert(FALSE, buf);
        return;
    }

    if (*head == tp) {
        *head = temp->next;
        flag = TRUE;
    }
    else {
        while (temp->next) {
            if (temp->next == tp) {
                temp->next = tp->next;
                flag = TRUE;
                break;
            }
            temp = temp->next;
        }
    }
    ERROR_Assert(flag, "ABSTRACT-TCP: Can't find the connection\n");

    MEM_free(tp->recvBuffer);
    MEM_free(tp->sendBuffer);
    MEM_free(tp);
}
