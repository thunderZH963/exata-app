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
// This file contains TCP Finite State Machine definitions.

#ifndef _TCP_FSM_H_
#define _TCP_FSM_H_

//
// Copyright (c) 1982, 1986, 1993
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
//  @(#)tcp_fsm.h   8.1 (Berkeley) 6/10/93
//

// TCP FSM state definitions.
// Per RFC793, September, 1981.

#define TCP_NSTATES 11

#define TCPS_CLOSED         0   // closed
#define TCPS_LISTEN         1   // listening for connection
#define TCPS_SYN_SENT       2   // active, have sent syn
#define TCPS_SYN_RECEIVED   3   // have sent and received syn
// states < TCPS_ESTABLISHED are those where connections not established
#define TCPS_ESTABLISHED    4   // established
#define TCPS_CLOSE_WAIT     5   // rcvd fin, waiting for close
// states > TCPS_CLOSE_WAIT are those where user has closed
#define TCPS_FIN_WAIT_1     6   // have closed, sent fin
#define TCPS_CLOSING        7   // closed xchd FIN; await FIN ACK
#define TCPS_LAST_ACK       8   // had fin and close; await FIN ACK
// states > TCPS_CLOSE_WAIT && < TCPS_FIN_WAIT_2 await ACK of FIN
#define TCPS_FIN_WAIT_2     9   // have closed, fin is acked
#define TCPS_TIME_WAIT      10  // in 2*msl quiet wait after close

#define TCPS_HAVERCVDSYN(s) ((s) >= TCPS_SYN_RECEIVED)
#define TCPS_HAVEESTABLISHED(s) ((s) >= TCPS_ESTABLISHED)
#define TCPS_HAVERCVDFIN(s) ((s) >= TCPS_TIME_WAIT)

//
// Flags used when sending segments in tcp_output.
// Basic flags (TH_RST,TH_ACK,TH_SYN,TH_FIN) are totally
// determined by state, with the proviso that TH_FIN is sent only
// if all data queued for output is included in the segment.
//
const static unsigned char   tcp_outflags[TCP_NSTATES] = {
    TH_RST|TH_ACK, 0, TH_SYN, TH_SYN|TH_ACK,
    TH_ACK, TH_ACK,
    TH_FIN|TH_ACK, TH_FIN|TH_ACK, TH_FIN|TH_ACK, TH_ACK, TH_ACK,
};

#endif // _TCP_FSM_H_
