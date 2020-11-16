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
// This file contains Abstract TCP header structure definition.
//

#ifndef ABSTRACT_TCP_HDR_H
#define ABSTRACT_TCP_HDR_H

#include "transport_tcp_hdr.h"

//
// ABSTRCT TCP header.
//
struct abstract_tcphdr {
    Int32 th_src;
    Int32 th_dst;
    unsigned short th_sport;       // source port
    unsigned short th_dport;       // destination port
    tcp_seq th_seq;                // sequence number
    tcp_seq th_ack;                // acknowledgement number
    unsigned char  a_TcpHdr_x2_off;
                   //th_x2:4,         // (unused)
                   //th_off:4;        // data offset
    unsigned char th_flags;
    unsigned short th_win;       // window
//    unsigned short th_sum;         // checksum
//    unsigned short th_urp;         // urgent pointer
};

//-------------------------------------------------------------------------
// FUNCTION       abstract_tcphdrSetTh_x2()
// PURPOSE        Set the value of th_x2 for abstract_tcphdr
// PARAMETERS:
//   a_TcpHdr_x2_off : The variable containing the value of th_x2 and th_off
//   th_x2           : Input value for set operation
// RETURN         void
// ASSUMPTION     None
//-------------------------------------------------------------------------
static void abstract_tcphdrSetTh_x2(unsigned char* a_TcpHdr_x2_off,
unsigned char th_x2)
{
    //masks th_x2 within boundry range
    th_x2 = th_x2 & maskChar(5, 8);

    //clears the first 4 bits
    *a_TcpHdr_x2_off = *a_TcpHdr_x2_off & maskChar(5,8);

    //setting the value of th_x2 in a_TcpHdr_x2_off
    *a_TcpHdr_x2_off = *a_TcpHdr_x2_off | LshiftChar(th_x2,4);
}


//-------------------------------------------------------------------------
// FUNCTION       abstract_tcphdrSetDataOffset()
// PURPOSE        Set the value of data offset for abstract_tcphdr
// PARAMETERS:
//   a_TcpHdr_x2_off : The variable containing the value of th_x2 and th_off
//   th_off          : Input value for set operation
// RETURN         void
// ASSUMPTION     None
//-------------------------------------------------------------------------
static void abstract_tcphdrSetDataOffset(unsigned char* a_TcpHdr_x2_off,
unsigned char th_off)
{
    //masks th_off within boundry range
    th_off = th_off & maskChar(5, 8);

    //clears the last 4 bits
    *a_TcpHdr_x2_off = *a_TcpHdr_x2_off & maskChar(1,4);

    //setting the value of th_off in a_TcpHdr_x2_off
    *a_TcpHdr_x2_off = *a_TcpHdr_x2_off | th_off;
}


//-------------------------------------------------------------------------
// FUNCTION       abstract_tcphdrGetTh_x2()
// PURPOSE        Returns the value of th_x2 for abstract_tcphdr
// PARAMETERS:
//   a_TcpHdr_x2_off : The variable containing the value of th_x2 and th_off
// RETURN VALUE   unsigned char
// ASSUMPTION     None
//-------------------------------------------------------------------------
static unsigned char abstract_tcphdrGetTh_x2(unsigned char a_TcpHdr_x2_off)
{
    unsigned char x = a_TcpHdr_x2_off;

    //clears the last 4 bits
    x = x & maskChar(1,4);

    //right shifts 8 bits
    x = RshiftChar(x,4);

    return x;
}


//-------------------------------------------------------------------------
// FUNCTION       abstract_tcphdrGetDataOffset()
// PURPOSE        Returns the value of data offset for abstract_tcphdr
// PARAMETERS:
//   a_TcpHdr_x2_off : The variable containing the value of th_x2 and th_off
// RETURN         unsigned char
// ASSUMPTION     None
//-------------------------------------------------------------------------
static unsigned char abstract_tcphdrGetDataOffset(
    unsigned char a_TcpHdr_x2_off)
{
    unsigned char offset = a_TcpHdr_x2_off;

    //clears the first 4 bits
    offset  = offset & maskChar(5,8);

    return  offset;
}


#endif // ABSTRACT_TCP_HDR_H
