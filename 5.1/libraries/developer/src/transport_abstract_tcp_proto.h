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

// This file contains Abstract TCP function prototypes.

#ifndef ABSTRACT_TCP_PROTO_H
#define ABSTRACT_TCP_PROTO_H

#include "transport_tcp_fsm.h"

#define TCPCB_WILDCARD     0
#define TCPCB_NO_WILDCARD  1

extern struct abs_tcpcb* tcp_attach(Node* node,
                                    struct abs_tcpcb*,
                                    AppType,
                                    Address*,
                                    short,
                                    Address*,
                                    short,
                                    Int32,
                                    TosType);

extern void tcp_canceltimers(struct abs_tcpcb*);

extern void tcp_close(Node*,
                      struct abs_tcpcb**,
                      unsigned int,
                      struct tcpstat*);

extern void tcp_input(Node*,
                      Message*,
                      TosType);

extern void tcp_output(Node*,
                       struct abs_tcpcb*,
                       UInt32,
                       struct tcpstat*);

extern void tcp_send(Node*,
                     struct abs_tcpcb*,
                     int,
                     Message* ,
                     int,
                     int,
                     UInt32,
                     struct tcpstat*);

extern void tcp_slowtimo(Node*,
                         struct abs_tcpcb*,
                         tcp_seq*,
                         UInt32*,
                         struct tcpstat*);

void TransportTcpSendPacket(Node* node,
                            struct abs_tcpcb* tp,
                            tcp_seq seq,
                            Message* msg);

struct abs_tcpcb* tcpcblookup(struct abs_tcpcb* head,
                              Address* local_addr,
                              short local_port,
                              Address* remote_addr,
                              short remote_port,
                              BOOL flag);

struct abs_tcpcb* tcpcbsearch(struct abs_tcpcb* head,
                              int con_id);

struct abs_tcpcb* tcpcballoc(int snd_bufsize,
                             int rcv_bufsize);

void TransportTcpHandleAck(Node* node,
                           Message* msg);

BOOL TransportTcpHandleData(Node* node,
                            Message* msg,
                            TosType priority);

void TransportTcpTransmitAck(Node* node,
                             struct abs_tcpcb* tp,
                             struct tcpstat* tcp_stat);

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
                 int outgoingInterface);

void tcp_listen(Node* node,
                struct abs_tcpcb*,
                AppType,
                Address*,
                short, TosType);

void tcp_drop(Node* node,
              struct abs_tcpcb** head,
              unsigned int con_id);

#endif // ABSTRACT_TCP_PROTO_H
