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
// This file contains TCP plus IP header structure after ip options removed.

#ifndef _TCPIP_H_
#define _TCPIP_H_

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
//  @(#)tcpip.h 8.1 (Berkeley) 6/10/93
//

// Overlay for ip header used by other protocols (tcp, udp).
struct ipovly {
    char *ih_next, *ih_prev;     // for protocol sequence q's
    unsigned char  ih_x1;        // (0x01 bit for ECN)
#define TI_ECE 0x01
    unsigned char  ih_pr;        // protocol
    short    ih_len;             // protocol length
    unsigned int ih_v_len;       // virtual length
    Address     ih_src;             // source internet address
    Address     ih_dst;             // destination internet address
};


// Tcp+ip header, after ip options removed.
struct tcpiphdr {
    struct  ipovly ti_i;        // overlaid ip structure
    struct  tcphdr ti_t;        // tcp header
    Message* msg;               // message attached with the packet.
};
#define ti_next     ti_i.ih_next
#define ti_prev     ti_i.ih_prev
#define ti_x1       ti_i.ih_x1
#define ti_pr       ti_i.ih_pr
#define ti_len      ti_i.ih_len
#define ti_vlen     ti_i.ih_v_len
#define ti_src      ti_i.ih_src
#define ti_dst      ti_i.ih_dst
#define ti_sport    ti_t.th_sport
#define ti_dport    ti_t.th_dport
#define ti_seq      ti_t.th_seq
#define ti_ack      ti_t.th_ack
//#define ti_x2       ti_t.th_x2
//#define ti_off      ti_t.th_off
#define ti_flags    ti_t.th_flags
#define ti_win      ti_t.th_win
#define ti_sum      ti_t.th_sum
#define ti_urp      ti_t.th_urp

#endif // _TCPIP_H_ //

