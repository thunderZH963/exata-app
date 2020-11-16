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

// This file contains configurable options and constants.
// Users can set these values for their particular needs.

#ifndef _TCP_CONFIG_H_
#define _TCP_CONFIG_H_


// keepalive option
// if 1, always send probes when keepalive timer times out.
// if 0, remain silent
// Originally always_keepalive in tcp_timer.c
#define TCP_ALWAYS_KEEPALIVE 1

// Whether to include TCP Options defined in RFC 1323:
// window scaling and timestamp
// if 1, include these options in tcp header
// if 0, do not include these options
// Originally tcp_do_rfc1232 in tcp_subr.c.
#define TCP_DO_RFC1323 0

// Nagle algorithm: delay send to coalesce packets.
// If 1, disable Nagle. If 0, enable Nagle (default).
#define TCP_NODELAY 0

// Don't use TCP option.
// If 1, shouldn't include options in TCP header.
// If 0, options are allowed.
#define TCP_NOOPT   0

// Don't push last block of write.
// If 1, do not push.
// If 0, push.
#define TCP_NOPUSH  0

// Whether to delay ACK
// If 1, do not delay ACK if the received packet is a short packet.
// If 0, delay ACK of all packets.
#define TCP_ACK_HACK 1

// Default maximum segment size for TCP.
// With an IP MSS of 576, this is 536,
// but 512 is probably more convenient.
// This should be defined as MIN(512, IP_MSS - sizeof (struct tcpiphdr)).
// Originally defined in tcp.h
#define TCP_MSS 512

// TCP_SENDSPACE and TCP_RECVSPACE are the default send and
// receiver buffer size.
// Both of them should be defined as 1024*16.
// Originally tcp_sendspace and tcp_recvspace in tcp_usrreq.c.
#define TCP_SENDSPACE 1024*16
#define TCP_RECVSPACE 1024*16

#endif // _TCP_CONFIG_H_ //
