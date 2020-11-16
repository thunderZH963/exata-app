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
// This file contains TCP function prototypes.

#ifndef _TCP_PROTO_H_
#define _TCP_PROTO_H_


extern int get_conid(struct inpcb *);

extern void insque_ti(struct tcpiphdr *, struct tcpiphdr *);

extern int in_cksum(unsigned short *, int);

extern int myrand(int, int, unsigned short *);

extern void remque_ti(struct tcpiphdr *);

extern struct inpcb *tcp_attach(Node *node, struct inpcb *,
            AppType, Address*, short, Address*, short, Int32, TosType);

extern void tcp_canceltimers(struct tcpcb *);

extern struct tcpcb *tcp_close(Node *, struct tcpcb *, struct tcpstat *);

extern void tcp_connect(Node *, struct inpcb *, AppType,
                        Address*, short, Address*, short,
                        UInt32, tcp_seq *, struct tcpstat *,
                        Int32, TosType, int outgoingInterface);

extern void tcp_disconnect(Node *, struct inpcb *, int,
                           UInt32, struct tcpstat *);

extern struct tcpcb *tcp_drop(Node *, struct tcpcb *, UInt32,
                              struct tcpstat *);

extern void tcp_fasttimo(Node *, struct inpcb *, UInt32,
                         struct tcpstat *);

extern void tcp_input(Node *, unsigned char *, int, int,
                      TosType, struct inpcb *,
                      tcp_seq *, UInt32, struct tcpstat *,
                      Message* msg);

extern void tcp_listen(Node *, struct inpcb *, AppType, Address*,
                       short, TosType);

extern int tcp_mssopt(struct tcpcb *tp);

extern struct tcpcb *tcp_newtcpcb(Node *node, struct inpcb *);

extern void tcp_output(Node *, struct tcpcb *, UInt32,
                       struct tcpstat *);

extern void tcp_respond(Node *, struct tcpcb *, struct tcpiphdr *,
                        int, tcp_seq, tcp_seq,
                        int, struct tcpstat *);

extern void tcp_send(Node *, struct inpcb *, int,
                     unsigned char *, int, int, UInt32,
                     struct tcpstat *, Message*);

extern void tcp_setpersist(struct tcpcb *);

extern void tcp_slowtimo(Node *, struct inpcb *, tcp_seq *,
                         UInt32 *, struct tcpstat *);

extern struct tcpiphdr * tcp_template(struct tcpcb *);


// TCP Sack related prototypes

#include "transport_tcp_fsm.h"

void
TransportTcpSackInit(
    struct tcpcb *tp);

void
TransportTcpSackFreeLists(
    struct tcpcb *tp);

int
TransportTcpSackTotal(
    struct tcpcb *tp);

void
TransportTcpSackReadOptions(
    struct tcpcb *tp,
    unsigned char *cp,
    int optlen);

void
TransportTcpSackUpdateNewSndUna(
    struct tcpcb *tp,
    tcp_seq theSndUna);

BOOL
TransportTcpSackNextRext(
    struct tcpcb *tp,
    TcpSackItem *theRextItem);

void
TransportTcpSackRextTimeoutInit(
    struct tcpcb *tp);

void
TransportTcpSackFastRextInit(
    struct tcpcb *tp);

void
TransportTcpSackFastRextEnd(
    struct tcpcb *tp);

void TransportTcpSackWriteOptions(
    struct tcpcb *tp,
    unsigned char *cp,
    unsigned int *optlenPtr);

void
TransportTcpSackUpdateNewRcvNxt(
    struct tcpcb *tp,
    tcp_seq theRcvNxt);

void
TransportTcpSackAddToSndList(
    struct tcpcb *tp,
    tcp_seq theLeftEdge,
    tcp_seq theRightEdge);

void
TransportTcpSackAddToRcvList(
    struct tcpcb *tp,
    tcp_seq LeftEdge,
    tcp_seq theRightEdge);

// TCP trace prototype
void
TransportTcpTrace(
    Node *node,
    struct tcpcb *tp,
    struct tcpiphdr *ti,
    const char *theMsg);

#endif // _TCP_PROTO_H_

