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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.
#ifndef TCPIP_HDR_H
#define TCPIP_HDR_H

#ifdef unix
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#else

#define __LITTLE_ENDIAN_BITFIELD__

struct iphdr {
#ifdef __LITTLE_ENDIAN_BITFIELD__
    UInt8     ihl:4,
            version:4;
#else
    UInt8     version:4,
            ihl:4;
#endif
    UInt8    tos;
    UInt16    tot_len;
    UInt16    id;
    UInt16    frag_off;
    UInt8    ttl;
    UInt8    protocol;
    UInt16    check;
    UInt32    saddr;
    UInt32    daddr;
};


struct tcphdr {
    UInt16    source;
    UInt16    dest;
    UInt32    seq;
    UInt32    ack_seq;
    UInt16    flags_and_offset; // NOT used by our code
    UInt16    window;
    UInt16    check;
    UInt16    urg_ptr;
};

struct udphdr {
    UInt16    source;
    UInt16    dest;
    UInt16    len;
    UInt16    check;
};

#endif

#endif
