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
// This file contains TCP header structure definition.

#ifndef _TCP_HDR_H_
#define _TCP_HDR_H_

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
//  @(#)tcp.h   8.1 (Berkeley) 6/10/93
//

typedef UInt32  tcp_seq;

//
// TCP header.
// Per RFC 793, September, 1981.
//
struct tcphdr {
    unsigned short th_sport;       // source port
    unsigned short th_dport;       // destination port
    tcp_seq th_seq;                // sequence number
    tcp_seq th_ack;                // acknowledgement number
    unsigned char  tcpHdr_x_off;
                    //th_x2:4,         // (unused)
                   //th_off:4;        // data offset
    unsigned char  th_flags;
    UInt16  th_win;       // window
    unsigned short th_sum;         // checksum
    unsigned short th_urp;         // urgent pointer
};

//-------------------------------------------------------------------------
// FUNCTION       tcphdrSetTh_x2()
// PURPOSE        Set the value of th_x2 for tcphdr
// PARAMETERS:
//   tcpHdr_x_off : The variable containing the value of th_x2 and th_off
//   th_x2        : Input value for set operation
// RETURN         void
// ASSUMPTION     None
//-------------------------------------------------------------------------
static void tcphdrSetTh_x2(unsigned char* tcpHdr_x_off, unsigned char th_x2)
{
    //masks th_x2 within boundry range
    th_x2 = th_x2 & maskChar(5, 8);

    //clears the first 4 bits
    *tcpHdr_x_off = *tcpHdr_x_off & maskChar(5, 8);

    //setting the value of th_x2 in tcpHdr_x_off
    *tcpHdr_x_off = *tcpHdr_x_off | LshiftChar(th_x2, 4);
}


//-------------------------------------------------------------------------
// FUNCTION       tcphdrSetDataOffset()
// PURPOSE        Set the value of data offset for tcphdr
// PARAMETERS:
//   tcpHdr_x_off : The variable containing the value of th_x2 and th_off
//   th_off       : Input value for set operation
// RETURN         void
// ASSUMPTION     None
//-------------------------------------------------------------------------
static void tcphdrSetDataOffset(unsigned char* tcpHdr_x_off,
                                unsigned int th_off)
{
    unsigned char th_off_char= (unsigned char) th_off;

    //masks th_off within boundry range
    th_off_char = th_off_char & maskChar(5, 8);

    //clears the last 4 bits
    *tcpHdr_x_off = *tcpHdr_x_off & maskChar(1, 4);

    //setting the value of th_off in tcpHdr_x_off
    *tcpHdr_x_off = *tcpHdr_x_off | th_off_char;
}


//-------------------------------------------------------------------------
// FUNCTION       tcphdrGetTh_x2()
// PURPOSE        Returns the value of sequenceNumber for tcphdr
// PARAMETERS:
//   tcpHdr_x_off : The variable containing the value of th_x2 and th_off
// RETURN         unsigned char
// ASSUMPTION     None
//-------------------------------------------------------------------------
static unsigned char tcphdrGetTh_x2(unsigned char tcpHdr_x_off)
{
    unsigned char x = tcpHdr_x_off;

    //clears the last 4 bits
    x = x & maskChar(1, 4);

    //right shifts 4 bits
    x = RshiftChar(x, 4);

    return x;
}



//-------------------------------------------------------------------------
// FUNCTION       tcphdrGetDataOffset()
// PURPOSE        Returns the value of data offset for tcphdr
// PARAMETERS:
//   tcpHdr_x_off : The variable containing the value of th_x2 and th_off
// RETURN VALUE   unsigned char
// ASSUMPTION     None
//-------------------------------------------------------------------------
static unsigned char tcphdrGetDataOffset(unsigned char tcpHdr_x_off)
{
    unsigned char offset = tcpHdr_x_off;

    //clears the first 4 bits
    offset  = offset & maskChar(5, 8);

    return  offset;
}



// value of th_flags
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

// Bit 9 in the reserved field of theTCP header is designated as
// the ECN-Echo (ECE) flag and Bit 8 is designated as the
// Congestion Window Reduced (CWR) flag.

#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)


// value of TCP options and length of the options

#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOLEN_MAXSEG          4
#define TCPOPT_WINDOW           3
#define TCPOLEN_WINDOW          3
#define TCPOPT_SACK_PERMITTED   4       // Experimental
#define TCPOLEN_SACK_PERMITTED  2
#define TCPOPT_SACK             5       // Experimental
#define TCPOPT_TIMESTAMP        8
#define TCPOLEN_TIMESTAMP       10
#define TCPOLEN_TSTAMP_APPA     (TCPOLEN_TIMESTAMP+2) // appendix A
#define TCPOPT_TSTAMP_HDR       \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|TCPOPT_TIMESTAMP<<8|TCPOLEN_TIMESTAMP)

#define TCPOPT_CC               11      // CC options: RFC-1644
#define TCPOPT_CCNEW            12
#define TCPOPT_CCECHO           13
#define TCPOLEN_CC              6
#define TCPOLEN_CC_APPA         (TCPOLEN_CC+2)
#define TCPOPT_CC_HDR(ccopt)    \
    (TCPOPT_NOP<<24|TCPOPT_NOP<<16|(ccopt)<<8|TCPOLEN_CC)

#define TCP_MAXWIN 65535            // largest value for (unscaled) window
#define TTCP_CLIENT_SND_WND 4096    // dflt send window for T/TCP client

#define TCP_MAX_WINSHIFT 14         // maximum window shift

#define TCP_MAXHLEN (0xf<<2)        // max length of header in bytes
#define TCP_MAXOLEN (TCP_MAXHLEN - sizeof(struct tcphdr))
                                    // max space left for options

//64 was hardcoded should this be 68 (www.nmt.edu/~val/tcpip.html)
#define TCP_MIN_MSS 64              // min segment size
#define TCP_MAX_MSS \
    (MAX_NW_PKT_SIZE - sizeof(IpHeaderType) - sizeof(struct tcphdr))

#endif // _TCP_HDR_H_

