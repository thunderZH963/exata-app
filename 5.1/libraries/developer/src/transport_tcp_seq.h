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
// This file contains macros & constants for operating TCP sequence numbers.

#ifndef _TCP_SEQ_H_
#define _TCP_SEQ_H_

//
// Copyright (c) 1982, 1986, 1993, 1995
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
//  @(#)tcp_seq.h   8.3 (Berkeley) 6/21/95
//

// TCP sequence numbers are 32 bit integers operated
// on with modular arithmetic.  These macros can be
// used to compare such integers.

#define SEQ_LT(a,b)     ((int)((a)-(b)) < 0)
#define SEQ_LEQ(a,b)    ((int)((a)-(b)) <= 0)
#define SEQ_GT(a,b)     ((int)((a)-(b)) > 0)
#define SEQ_GEQ(a,b)    ((int)((a)-(b)) >= 0)
#define SEQ_SUB(a,b)    ((long)((a)-(b)))

// for modulo comparisons of timestamps
#define TSTMP_LT(a,b)   ((int)((a)-(b)) < 0)
#define TSTMP_GEQ(a,b)  ((int)((a)-(b)) >= 0)

// TCP connection counts are 32 bit integers operated
// on with modular arithmetic.  These macros can be
// used to compare such integers.

#define CC_LT(a,b)  ((int)((a)-(b)) < 0)
#define CC_LEQ(a,b) ((int)((a)-(b)) <= 0)
#define CC_GT(a,b)  ((int)((a)-(b)) > 0)
#define CC_GEQ(a,b) ((int)((a)-(b)) >= 0)

// Macro to increment a CC: skip 0 which has a special meaning
#define CC_INC(c)   (++(c) == 0 ? ++(c) : (c))

// Macros to initialize tcp sequence numbers for
// send and receive from initial send and receive
// sequence numbers.
#define tcp_rcvseqinit(tp) \
    (tp)->rcv_adv = (tp)->rcv_nxt = (tp)->irs + 1

#define tcp_sendseqinit(tp) \
    (tp)->snd_una = (tp)->snd_nxt = (tp)->snd_max = (tp)->snd_up = \
        (tp)->iss

#define TCP_PAWS_IDLE   (24 * 24 * 60 * 60 * PR_SLOWHZ)
                    // timestamp wrap-around time //

// Increment for tcp_iss each second.
// This is designed to increment at the standard 250 KB/s,
// We also increment tcp_iss by a quarter of this amount
// each time we use the value for a new connection.

#define TCP_ISSINCR (250*1024)  // increment for tcp_iss each second

#endif // _TCP_SEQ_H_
