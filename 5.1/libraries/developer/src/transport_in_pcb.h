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

/*
 *
 * Ported from FreeBSD 2.2.2.
 * This file contains common pcb structure for internet protocol
 * implementation.
 */

#ifndef _IN_PCB_H_
#define _IN_PCB_H_

/*
 * Copyright (c) 1982, 1986, 1990, 1993
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  @(#)in_pcb.h    8.1 (Berkeley) 6/10/93
 */

#include <iostream>
#include <vector>
#include <list>
using namespace std;
#define INPCB_WILDCARD     0
#define INPCB_NO_WILDCARD  1

#define sbspace(inp) ((inp)->inp_rcv_hiwat)

#define INPCB_DATATYPE_ACTUAL 0
#define INPCB_DATATYPE_VIRTUAL 1

#define IPDEFTTL 64

struct inp_buf_entry {
    int start_char;
    int end_char;
    int dataType;
};

typedef enum
{
    BUF_READ,
    BUF_WRITE
} BufAction;

typedef enum
{
    BUF_NOWRAP,
    BUF_READWRAP,
    BUF_WRITEWRAP
} BufWrap;

struct inp_buf {
    UInt32 start;           /* start of read position */
    UInt32 end;             /* start if write position */
    BufWrap wrap;                  /* whether positions have wrapped */
    UInt32 hiwat;           /* max actual char count */

    struct inp_buf_entry *entries; /* pointer to data type list */
    int numEntries;
    int maxEntries;
    int headIndex;
    int tailIndex;

    unsigned char *buffer;         /* buffer content */

};

/*
 * Data structure for info field
 */
struct infofield_array
{
    UInt32 msgSeqNum;
    UInt32 remPktSize;
    UInt32 packetSize;
    UInt32 virtualSize;
    BOOL retransmission;
    UInt32 fragId;
    BOOL isInfoFieldSent;
    UInt32 retransSize;
    UInt32 tcpSeqNum;
    //MessageInfoHeader infoArray[MAX_INFO_FIELDS];
    std::vector<MessageInfoHeader> infoArray;
    double smallInfoSpace[SMALL_INFO_SPACE_SIZE / sizeof(double)];
};

struct infoField_buf
{
    UInt32 connId;
    UInt32 tcpSeqNum;
    UInt32 initTcpSeqNum;
    BOOL setTcpSeqNum;
    UInt32 pktAcked;
    UInt32 pktSentSize;
    UInt32 pktSizeRemovedFromBuffer;
    //std::vector<infofield_array *> info;
    std::list<infofield_array *> info;
};



/*
 * Data structure for blocked user data.
 */
struct pending_buf{
    UInt32 cc;              /* number of bytes moved to send buffer */
    UInt32 hiwat;           /* length of the payload */
    Int32 virtualLength;            /* length of the virtual payload */
    UInt32 bufCapacity;     /* capacity of the buffer (below) */
    unsigned char *buffer;         /* payload of the blocked packet */
};



struct inpcb {
    struct inpcb *inp_next, *inp_prev; /* doubly linked list of inpcb */
    struct inpcb *inp_head;            /* pointer back to chain of inpcb's
                                              for this protocol */
    AppType app_proto_type;           /* app this connection belongs to */
    /* four-tuple used to identify a connection */
    Address inp_remote_addr;           /* remote address    */
    short     inp_remote_port;           /* remote port       */
    Address inp_local_addr;            /* local address     */
    short     inp_local_port;            /* local port        */

    char    *inp_ppcb;                 /* pointer to per protocol PCB */
    int     con_id;                    /* connection id #    */
    UInt32 inp_rcv_hiwat;       /* receive buffer size */
    struct inp_buf inp_snd;            /* send buffer */
    struct pending_buf blocked_pkt;    /* data blocked to send */
    int     usrreq;                    /* user request */

    struct infoField_buf* info_buf; /* info field buffer */
    Int32 unique_id;
    TosType priority;
    UInt8 ttl;                      /* ttl field for ip */
                                    /* Set once per tcp connection */
                                    /* Incoming Packet TTL ignored once set*/

    Int32 remote_unique_id; /* added for stats db app conn table */

};

/*
 * Possible values of usrreq.
 */
#define INPCB_USRREQ_NONE         0
#define INPCB_USRREQ_OPEN         1
#define INPCB_USRREQ_CONNECTED    2
#define INPCB_USRREQ_CLOSE        3

extern int get_block_pkt_count(struct inpcb *inp);

extern int append_buf(Node *, struct inpcb *, unsigned char *,
                          int, int, Message*);
extern void del_buf(Node *, struct inpcb *, int,  int);
extern struct inpcb *in_pcballoc(struct inpcb *, int, int);
extern void in_pcbdetach(struct inpcb *);
extern struct inpcb *in_pcblookup(struct inpcb *, Address*, short,
                                                  Address*, short, int);
extern struct inpcb *in_pcbsearch(struct inpcb *, int);

char *
prepare_outgoing_packet(
    Node *node,
    Message *msg,
    struct inp_buf *buf,
    int len,
    int hdrlen,
    int off);

/* Circular send buffer routines */
extern UInt32 InpSendBufGetCount(struct inp_buf *theBuf,
                                     BufAction theAction);
extern void InpSendBufRead(struct inp_buf *theBuf,
                               unsigned char *theData, UInt32 theLength);
extern UInt32 InpSendBufGetSize(struct inp_buf *theBuf);


#endif /* _IN_PCB_H_ */

