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
// Ported from FreeBSD 4.7
// This file contains ICMPv6 (RFC 2463) implementation
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

#ifndef _ICMP6_H_
#define _ICMP6_H_

#include "api.h"
#include "ipv6.h"

// /**
// CONSTANT    :: PRC_MSGSIZE : 5
// DESCRIPTION :: message size forced drop
// **/
#define PRC_MSGSIZE         5   /* message size forced drop */

// /**
// CONSTANT    :: PRC_UNREACH_NET : 8
// DESCRIPTION :: no route to network
// **/
#define PRC_UNREACH_NET     8   /* no route to network */


// /**
// CONSTANT    :: PRC_UNREACH_HOST : 9
// DESCRIPTION :: no route to host
// **/
#define PRC_UNREACH_HOST    9   /* no route to host */

// /**
// CONSTANT    :: PRC_UNREACH_PROTOCOL : 10
// DESCRIPTION :: dst says bad protocol
// **/
#define PRC_UNREACH_PROTOCOL    10  /* dst says bad protocol */

// /**
// CONSTANT    :: PRC_UNREACH_PORT : 11
// DESCRIPTION :: bad port #
// **/
#define PRC_UNREACH_PORT    11  /* bad port # */

// /**
// CONSTANT    :: PRC_REDIRECT_HOST : 15
// DESCRIPTION :: host routing redirect
// **/
#define PRC_REDIRECT_HOST   15  /* host routing redirect */

// /**
// CONSTANT    :: PRC_TIMXCEED_INTRANS : 18
// DESCRIPTION :: packet lifetime expired in transit
// **/
#define PRC_TIMXCEED_INTRANS    18  /* packet lifetime expired in transit */

// /**
// CONSTANT    :: PRC_PARAMPROB : 20
// DESCRIPTION :: header incorrect
// **/
#define PRC_PARAMPROB       20  /* header incorrect */




// STRUCT      :: icmp6_hdr
// DESCRIPTION :: Icmp6 Header Structure
// **/

typedef struct icmp6_hdr_struct
{
    unsigned char  icmp6_type;  /* type field */
    unsigned char  icmp6_code;  /* code field */
    unsigned short icmp6_cksum; /* checksum field */
    union
    {
        unsigned int   icmp6_un_data32[1];  /* type-specific field */
        unsigned short icmp6_un_data16[2];  /* type-specific field */
        unsigned char  icmp6_un_data8[4];   /* type-specific field */
    } icmp6_dataun;
} icmp6_hdr;


// /**
// MACRO       :: icmp6_data32 : icmp6_dataun.icmp6_un_data32
// DESCRIPTION :: shortcut to icmp6 data
// **/
#define icmp6_data32 icmp6_dataun.icmp6_un_data32

// /**
// MACRO       :: icmp6_data16 : icmp6_dataun.icmp6_un_data16
// DESCRIPTION :: shortcut to icmp6 data
// **/
#define icmp6_data16 icmp6_dataun.icmp6_un_data16

// /**
// MACRO       :: icmp6_data8 : icmp6_dataun.icmp6_un_data8
// DESCRIPTION :: shortcut to icmp6 data
// **/
#define icmp6_data8  icmp6_dataun.icmp6_un_data8

// /**
// CONSTANT    :: icmp6_pptr : icmp6_data32[0]
// DESCRIPTION :: parameter prob
// **/
#define icmp6_pptr   icmp6_data32[0]    // parameter prob

// /**
// CONSTANT    :: icmp6_mtu : icmp6_data32[0]
// DESCRIPTION :: packet too big
// **/
#define icmp6_mtu    icmp6_data32[0]    // packet too big

// /**
// CONSTANT    :: icmp6_id : icmp6_data16[0]
// DESCRIPTION :: echo request/reply
// **/
#define icmp6_id     icmp6_data16[0]    // echo request/reply

// /**
// CONSTANT    :: icmp6_seq : icmp6_data16[1]
// DESCRIPTION :: echo request/reply
// **/
#define icmp6_seq    icmp6_data16[1]    // echo request/reply

// /**
// CONSTANT    :: icmp6_maxdelay : icmp6_data16[0]
// DESCRIPTION :: mcast group membership
// **/
#define icmp6_maxdelay  icmp6_data16[0] // mcast group membership

// /**
// CONSTANT    :: ICMP6_DST_UNREACH       1
// DESCRIPTION :: Destination unreachable
// **/
#define ICMP6_DST_UNREACH       1

// /**
// CONSTANT    :: ICMP6_PACKET_TOO_BIG : 2
// DESCRIPTION :: Packet size bigger than acceptance level
// **/
#define ICMP6_PACKET_TOO_BIG    2

// /**
// CONSTANT    :: ICMP6_TIME_EXCEEDED : 3
// DESCRIPTION :: Time Exceeded
// **/
#define ICMP6_TIME_EXCEEDED     3

// /**
// CONSTANT    :: ICMP6_PARAM_PROB : 4
// DESCRIPTION :: ICMP6 probing parameter.
// **/
#define ICMP6_PARAM_PROB        4


// /**
// CONSTANT    :: ICMP6_INFOMSG_MASK : 0x80
// DESCRIPTION :: all information messages
// **/
#define ICMP6_INFOMSG_MASK      0x80    // all information messages


// /**
// CONSTANT    :: ICMP6_ECHO_REQUEST      128
// DESCRIPTION :: Echo Request
// **/
#define ICMP6_ECHO_REQUEST      128

// /**
// CONSTANT    :: ICMP6_ECHO_REPLY : 129
// DESCRIPTION :: Echo Reply
// **/
#define ICMP6_ECHO_REPLY        129

// /**
// CONSTANT    :: ICMP6_MEMBERSHIP_QUERY : 130
// DESCRIPTION :: Icmp6 member query
// **/
#define ICMP6_MEMBERSHIP_QUERY      130



// /**
// CONSTANT    :: ICMP6_ROUTER_RENUMBERING : 138
// DESCRIPTION :: TBD
// **/
#define ICMP6_ROUTER_RENUMBERING    138


// /**
// CONSTANT    :: ICMP6_DST_UNREACH_NOROUTE : 0
// DESCRIPTION :: Destination is unreachable with no available route
// **/
#define ICMP6_DST_UNREACH_NOROUTE   0

// /**
// CONSTANT    :: ICMP6_DST_UNREACH_ADMIN : 1
// DESCRIPTION :: destination unreachable by admin
// **/
#define ICMP6_DST_UNREACH_ADMIN     1

// /**
// CONSTANT    :: ICMP6_DST_UNREACH_NOTNEIGHBOR : 2
// DESCRIPTION :: Destination unreachaable
// **/
#define ICMP6_DST_UNREACH_NOTNEIGHBOR   2

// /**
// CONSTANT    :: ICMP6_DST_UNREACH_BEYONDSCOPE : 2
// DESCRIPTION :: Destination beyond scope
// **/
#define ICMP6_DST_UNREACH_BEYONDSCOPE   2

// /**
// CONSTANT    :: ICMP6_DST_UNREACH_ADDR : 3
// DESCRIPTION :: Address unreachable.
// **/
#define ICMP6_DST_UNREACH_ADDR      3

// /**
// CONSTANT    :: ICMP6_DST_UNREACH_NOPORT : 4
// DESCRIPTION :: Destination unreachable due to no port
// **/
#define ICMP6_DST_UNREACH_NOPORT    4


// /**
// CONSTANT    :: ICMP6_TIME_EXCEED_TRANSIT  : 0
// DESCRIPTION :: Time expired.
// **/
#define ICMP6_TIME_EXCEED_TRANSIT   0

// /**
// CONSTANT    :: ICMP6_TIME_EXCEED_REASSEMBLY : 1
// DESCRIPTION :: Reassembly time expired
// **/
#define ICMP6_TIME_EXCEED_REASSEMBLY    1


// /**
// CONSTANT    :: ICMP6_PARAMPROB_HEADER : 0
// DESCRIPTION :: Parameter problem header
// **/
#define ICMP6_PARAMPROB_HEADER      0

// /**
// CONSTANT    :: ICMP6_PARAMPROB_NEXTHEADER  : 1
// DESCRIPTION :: Parameter problem next header.
// **/
#define ICMP6_PARAMPROB_NEXTHEADER  1

// /**
// CONSTANT    :: ICMP6_PARAMPROB_OPTION : 2
// DESCRIPTION :: Parameter option header
// **/
#define ICMP6_PARAMPROB_OPTION      2


// Multicast Listener Discovery

// /**
// CONSTANT    :: MLD6_LISTENER_QUERY : 130
// DESCRIPTION :: multicast listener query
// **/
#define MLD6_LISTENER_QUERY     130 // multicast listener query

// /**
// CONSTANT    :: MLD6_LISTENER_REPORT : 131
// DESCRIPTION :: multicast listener report
// **/
#define MLD6_LISTENER_REPORT    131 // multicast listener report

// /**
// CONSTANT    :: MLD6_LISTENER_DONE : 132
// DESCRIPTION :: multicast listener done
// **/
#define MLD6_LISTENER_DONE      132 // multicast listener done

// /**
// STRUCT      :: mld6_hdr
// DESCRIPTION :: Structure of mld6 header
// **/
typedef struct mld6_hdr_struct
{
    icmp6_hdr   mld6_hdr;
    in6_addr    mld6_addr;  // multicast address
} mld6_hdr;


// /**
// CONSTANT    :: mld6_type : mld6_hdr.icmp6_type
// DESCRIPTION :: TBD
// **/
#define mld6_type   mld6_hdr.icmp6_type

// /**
// MACRO       :: mld6_code : mld6_hdr.icmp6_code
// DESCRIPTION :: Shortcut to mld6 code
// **/
#define mld6_code   mld6_hdr.icmp6_code

// /**
// MACRO       :: mld6_cksum : mld6_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to mld6 checksum
// **/
#define mld6_cksum  mld6_hdr.icmp6_cksum

// /**
// MACRO       :: mld6_maxdelay : mld6_hdr.icmp6_data16[0]
// DESCRIPTION :: Shortcut to mld6 maxdelay
// **/
#define mld6_maxdelay   mld6_hdr.icmp6_data16[0]

// /**
// MACRO       :: mld6_reserved : mld6_hdr.icmp6_data16[1]
// DESCRIPTION :: Shortcut to mld6 reserved
// **/
#define mld6_reserved   mld6_hdr.icmp6_data16[1]

// Neighbor Discovery

// /**
// CONSTANT    :: ND_ROUTER_SOLICIT : 133
// DESCRIPTION :: Router Solicitation flag
// **/
#define ND_ROUTER_SOLICIT       133

// /**
// CONSTANT    :: ND_ROUTER_ADVERT : 134
// DESCRIPTION :: Router Advertisement flag
// **/
#define ND_ROUTER_ADVERT        134

// /**
// CONSTANT    :: ND_NEIGHBOR_SOLICIT : 135
// DESCRIPTION :: Neighbor Solicitation flag.
// **/
#define ND_NEIGHBOR_SOLICIT     135

// /**
// CONSTANT    :: ND_NEIGHBOR_ADVERT : 136
// DESCRIPTION :: Neighbor Advertisement flag
// **/
#define ND_NEIGHBOR_ADVERT      136

// /**
// CONSTANT    :: ND_REDIRECT : 137
// DESCRIPTION :: Redirect Flag
// **/
#define ND_REDIRECT             137

 // router solicitation

// /**
// STRUCT      :: nd_router_solicit
// DESCRIPTION :: router solicitation structure.
// **/
typedef struct nd_router_solicit_struct
{
    icmp6_hdr   nd_rs_hdr;
} nd_router_solicit;


// /**
// MACRO       :: nd_rs_type : nd_rs_hdr.icmp6_type
// DESCRIPTION :: Shortcut to router solicitation type.
// **/
#define nd_rs_type  nd_rs_hdr.icmp6_type

// /**
// MACRO       :: nd_rs_code : nd_rs_hdr.icmp6_code
// DESCRIPTION :: Shortcut to router solicitation code.
// **/
#define nd_rs_code  nd_rs_hdr.icmp6_code

// /**
// MACRO       :: nd_rs_cksum : nd_rs_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to router solicitation check sum.
// **/
#define nd_rs_cksum nd_rs_hdr.icmp6_cksum

// /**
// MACRO       :: nd_rs_reserved : nd_rs_hdr.icmp6_data32[0]
// DESCRIPTION :: Shortcut to router solicitation reserved data.
// **/
#define nd_rs_reserved  nd_rs_hdr.icmp6_data32[0]

// router advertisement

// /**
// STRUCT      :: nd_router_advert
// DESCRIPTION :: router advertisement structure.
// **/
typedef struct nd_router_advert_struct
{
    icmp6_hdr    nd_ra_hdr;
    unsigned int nd_ra_reachable;   // reachable time
    unsigned int nd_ra_retransmit;  // retransmit timer
} nd_router_advert;


// /**
// MACRO       :: nd_ra_type : nd_ra_hdr.icmp6_type
// DESCRIPTION :: Shortcut to router advertisement type.
// **/
#define nd_ra_type      nd_ra_hdr.icmp6_type

// /**
// MACRO    :: nd_ra_code : nd_ra_hdr.icmp6_code
// DESCRIPTION :: Shortcut to router advertisement code.
// **/
#define nd_ra_code      nd_ra_hdr.icmp6_code

// /**
// MACRO       :: nd_ra_cksum : nd_ra_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to router advertisement checksum.
// **/
#define nd_ra_cksum     nd_ra_hdr.icmp6_cksum

// /**
// MACRO    :: nd_ra_curhoplimit : nd_ra_hdr.icmp6_data8[0]
// DESCRIPTION :: Shortcut to router advertisement hoplimit.
// **/
#define nd_ra_curhoplimit   nd_ra_hdr.icmp6_data8[0]

// /**
// MACRO       :: nd_ra_flags_reserved : nd_ra_hdr.icmp6_data8[1]
// DESCRIPTION :: Shortcut to router advertisement flags.
// **/
#define nd_ra_flags_reserved    nd_ra_hdr.icmp6_data8[1]


// /**
// CONSTANT    :: ND_RA_FLAG_MANAGED  : 0x80
// DESCRIPTION :: Managed flag
// **/
#define ND_RA_FLAG_MANAGED  0x80

// /**
// CONSTANT    :: ND_RA_FLAG_OTHER  : 0x40
// DESCRIPTION :: other flag
// **/
#define ND_RA_FLAG_OTHER    0x40


// /**
// MACRO       :: nd_ra_router_lifetime : nd_ra_hdr.icmp6_data16[1]
// DESCRIPTION :: Shortcut to router advertisement lifetime.
// **/
#define nd_ra_router_lifetime   nd_ra_hdr.icmp6_data16[1]

// neighbor solicitation
// /**
// STRUCT      :: nd_neighbor_solicit
// DESCRIPTION :: neighbor solicitation structure
// **/
typedef struct nd_neighbor_solicit_struct
{
    icmp6_hdr   nd_ns_hdr;
    in6_addr    nd_ns_target;   // target address
} nd_neighbor_solicit ;


// /**
// MACRO       :: nd_ns_type : nd_ns_hdr.icmp6_type
// DESCRIPTION :: Shortcut to neighbor solicitation icmpv6 type
// **/
#define nd_ns_type  nd_ns_hdr.icmp6_type

// /**
// MACRO    :: nd_ns_code : nd_ns_hdr.icmp6_code
// DESCRIPTION :: Shortcut to icmpv6 code
// **/
#define nd_ns_code  nd_ns_hdr.icmp6_code

// /**
// MACRO       :: nd_ns_cksum : nd_ns_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to neighbor solicitation icmpv6 checksum
// **/
#define nd_ns_cksum nd_ns_hdr.icmp6_cksum

// /**
// MACRO       :: nd_ns_reserved : nd_ns_hdr.icmp6_data32[0]
// DESCRIPTION :: Shortcut to neighbor solicitation icmpv6 data
// **/
#define nd_ns_reserved  nd_ns_hdr.icmp6_data32[0]

// neighbor advertisement
// /**
// STRUCT      :: nd_neighbor_advert
// DESCRIPTION :: Neighbor advertisement structure
// **/
typedef struct nd_neighbor_advert_struct
{
    icmp6_hdr   nd_na_hdr;
    in6_addr    nd_na_target;   /* target address */
} nd_neighbor_advert;


// /**
// MACRO       :: nd_na_type : nd_na_hdr.icmp6_type
// DESCRIPTION :: Shortcut to neighbor advertisement icmpv6 type
// **/
#define nd_na_type      nd_na_hdr.icmp6_type

// /**
// MACRO       :: nd_na_code : nd_na_hdr.icmp6_code
// DESCRIPTION :: Shortcut to neighbor advertisement icmpv6 code
// **/
#define nd_na_code      nd_na_hdr.icmp6_code

// /**
// MACRO       :: nd_na_cksum : nd_na_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to neighbor advertisement icmpv6 checksum
// **/
#define nd_na_cksum     nd_na_hdr.icmp6_cksum

// /**
// MACRO       :: nd_na_flags_reserved : nd_na_hdr.icmp6_data32[0]
// DESCRIPTION :: Shortcut to neighbor advertisement icmpv6 data
// **/
#define nd_na_flags_reserved    nd_na_hdr.icmp6_data32[0]

#if BYTE_ORDER == BIG_ENDIAN


// /**
// CONSTANT    :: ND_NA_FLAG_ROUTER  : 0x80000000
// DESCRIPTION :: Neighbor Advertisement flag
// **/
#define ND_NA_FLAG_ROUTER   0x80000000

// /**
// CONSTANT    :: ND_NA_FLAG_SOLICITED : 0x40000000
// DESCRIPTION :: Neighbor Solicitation flag
// **/
#define ND_NA_FLAG_SOLICITED    0x40000000

// /**
// CONSTANT    :: ND_NA_FLAG_OVERRIDE : 0x20000000
// DESCRIPTION :: Over riding flag
// **/
#define ND_NA_FLAG_OVERRIDE 0x20000000

#else // BYTE_ORDER == LITTLE_ENDIAN

// /**
// CONSTANT    :: ND_NA_FLAG_ROUTER : 0x00000080
// DESCRIPTION :: Neighbor Advertisement flag
// **/
#define ND_NA_FLAG_ROUTER   0x00000080

// /**
// CONSTANT    :: ND_NA_FLAG_SOLICITED : 0x00000040
// DESCRIPTION :: Neighbor Solicitation flag
// **/
#define ND_NA_FLAG_SOLICITED    0x00000040

// /**
// CONSTANT    :: ND_NA_FLAG_OVERRIDE : 0x00000020
// DESCRIPTION :: Overriding flag
// **/
#define ND_NA_FLAG_OVERRIDE 0x00000020
#endif

// redirect
// /**
// STRUCT      :: nd_redirect
// DESCRIPTION :: redirect message structure
// **/
typedef struct nd_redirect_struct
{   // redirect
    icmp6_hdr   nd_rd_hdr;
    in6_addr    nd_rd_target;   // target address
    in6_addr    nd_rd_dst;      // destination address
} nd_redirect;


// /**
// MACRO       :: nd_rd_type  : nd_rd_hdr.icmp6_type
// DESCRIPTION :: Shortcut to router advertisement icmpv6 type
// **/
#define nd_rd_type  nd_rd_hdr.icmp6_type

// /**
// MACRO       :: nd_rd_code : nd_rd_hdr.icmp6_code
// DESCRIPTION :: Shortcut to router advertisement icmpv6 code
// **/
#define nd_rd_code  nd_rd_hdr.icmp6_code

// /**
// MACRO       :: nd_rd_cksum : nd_rd_hdr.icmp6_cksum
// DESCRIPTION :: Shortcut to router advertisement icmpv6 checksum
// **/
#define nd_rd_cksum nd_rd_hdr.icmp6_cksum

// /**
// MACRO    :: nd_rd_reserved : nd_rd_hdr.icmp6_data32[0]
// DESCRIPTION :: Shortcut to router advertisement icmpv6 data
// **/
#define nd_rd_reserved  nd_rd_hdr.icmp6_data32[0]

// Neighbor discovery option header
// /**
// STRUCT      :: nd_opt_hdr
// DESCRIPTION :: Option header structure
// **/
typedef struct nd_opt_hdr_struct
{
    unsigned char nd_opt_type;
    unsigned char nd_opt_len;   // in units of 8 octets
} nd_opt_hdr;


// /**
// CONSTANT    :: ND_OPT_SOURCE_LINKADDR  : 1
// DESCRIPTION :: Option has source link layer address flag
// **/
#define ND_OPT_SOURCE_LINKADDR      1

// /**
// CONSTANT    :: ND_OPT_TARGET_LINKADDR : 2
// DESCRIPTION :: Option has target link layer address flag
// **/
#define ND_OPT_TARGET_LINKADDR      2

// /**
// CONSTANT    :: ND_OPT_PREFIX_INFORMATION : 3
// DESCRIPTION :: Option has prefix information flag
// **/
#define ND_OPT_PREFIX_INFORMATION   3

// /**
// CONSTANT    :: ND_OPT_REDIRECTED_HEADER : 4
// DESCRIPTION :: Option has redirect header
// **/
#define ND_OPT_REDIRECTED_HEADER    4

// /**
// CONSTANT    :: ND_OPT_MTU : 5
// DESCRIPTION :: Option has mtu
// **/
#define ND_OPT_MTU          5

// /**
// CONSTANT    :: ND_OPT_SHORTCUT_LIMIT : 6
// DESCRIPTION :: Option limit
// **/
#define ND_OPT_SHORTCUT_LIMIT       6

// /**
// CONSTANT    :: ND_OPT_MOB_ADVERT_INTERVAL : 7
// DESCRIPTION :: Mobile advertisement interval
// **/
#define ND_OPT_MOB_ADVERT_INTERVAL  7

// /**
// CONSTANT    :: ND_OPT_MOB_AGENT_INFORMATION : 8
// DESCRIPTION :: Mobile Agent Information
// **/
#define ND_OPT_MOB_AGENT_INFORMATION    8


// /**
// CONSTANT    :: ND_OPT_LINKADDR_LEN : 8
// DESCRIPTION :: Link layer address length.
// **/
#define ND_OPT_LINKADDR_LEN     8


// /**
// CONSTANT    :: ETHER_ADDR_LEN : 6
// DESCRIPTION :: Ethernet address length
// **/
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN          6
#endif

// prefix information
// /**
// STRUCT      :: nd_opt_prefix_info
// DESCRIPTION :: prefix information structure.
// **/
typedef struct nd_opt_prefix_info_struct
{
    unsigned char nd_opt_pi_type;
    unsigned char nd_opt_pi_len;
    unsigned char nd_opt_pi_prefix_len;
    unsigned char nd_opt_pi_flags_reserved;
    unsigned int  nd_opt_pi_valid_time;
    unsigned int  nd_opt_pi_preferred_time;
    unsigned int  nd_opt_pi_reserved_site_plen;
    in6_addr      nd_opt_pi_prefix;
} nd_opt_prefix_info;


// /**
// CONSTANT    :: ND_OPT_PI_FLAG_ONLINK : 0x80
// DESCRIPTION :: Onlink flag
// **/
#define ND_OPT_PI_FLAG_ONLINK   0x80

// /**
// CONSTANT    :: ND_OPT_PI_FLAG_AUTO : 0x40
// DESCRIPTION :: Auto configuration flag
// **/
#define ND_OPT_PI_FLAG_AUTO     0x40

// /**
// CONSTANT    :: ND_OPT_PI_FLAG_RTADDR : 0x20
// DESCRIPTION :: Router Advertisement flag
// **/
#define ND_OPT_PI_FLAG_RTADDR   0x20

// /**
// CONSTANT    :: ND_OPT_PI_FLAG_SITE : 0x10
// DESCRIPTION :: Site local flag
// **/
#define ND_OPT_PI_FLAG_SITE     0x10

// redirected header
// /**
// STRUCT      :: nd_opt_rd_hdr
// DESCRIPTION ::
// **/
typedef struct nd_opt_rd_hdr_struct
{
    unsigned char  nd_opt_rh_type;
    unsigned char  nd_opt_rh_len;
    unsigned short nd_opt_rh_reserved1;
    unsigned int   nd_opt_rh_reserved2;
} nd_opt_rd_hdr;

// MTU option

// /**
// STRUCT      :: nd_opt_mtu
// DESCRIPTION :: Maximum transmission unit option
// **/
typedef struct nd_opt_mtu_struct
{
    unsigned char  nd_opt_mtu_type;
    unsigned char  nd_opt_mtu_len;
    unsigned short nd_opt_mtu_reserved;
    unsigned int   nd_opt_mtu_mtu;
} nd_opt_mtu;

/* Shortcut Limit (NBMA) */

// /**
// STRUCT      :: nd_opt_sclim
// DESCRIPTION :: shortcut limit structure
// **/
typedef struct nd_opt_sclim_struct {
    unsigned char  nd_opt_scl_type;
    unsigned char  nd_opt_scl_len;
    unsigned char  nd_opt_scl_scl;
    unsigned char  nd_opt_scl_reserved1;
    unsigned int   nd_opt_scl_reserved2;
} nd_opt_sclim;

/* Advertisement Interval (Mobility) */
// /**
// STRUCT      :: nd_opt_advit
// DESCRIPTION :: Mobility advertisement structure
// **/
typedef struct nd_opt_advit_struct {
    unsigned char  nd_opt_ait_type;
    unsigned char  nd_opt_ait_len;
    unsigned short nd_opt_ait_reserved;
    unsigned int   nd_opt_ait_it;
} nd_opt_advit;

/* Home-Agent Information (Mobility) */

// /**
// STRUCT      :: nd_opt_agti
// DESCRIPTION :: Home Agent Mobility structure
// **/
typedef struct nd_opt_agti_struct
{
    unsigned char  nd_opt_hai_type;
    unsigned char  nd_opt_hai_len;
    unsigned short nd_opt_hai_reserved;
    short          nd_opt_hai_pref;
    unsigned short nd_opt_hai_life;
} nd_opt_agti;

// Router Renumbering

// /**
// CONSTANT    :: ICMP6_RT_RENUM_COMMAND : 0
// DESCRIPTION :: Router renumber command
// **/
#define ICMP6_RT_RENUM_COMMAND      0

// /**
// CONSTANT    :: ICMP6_RT_RENUM_RESULT : 1
// DESCRIPTION :: Icmp6 router renumber result
// **/
#define ICMP6_RT_RENUM_RESULT       1

// /**
// CONSTANT    :: ICMP6_RT_RENUM_SEQNUM_RESET : 255
// DESCRIPTION :: Icmp6 router renumber sequence request.
// **/
#define ICMP6_RT_RENUM_SEQNUM_RESET 255

// router renumbering header
// /**
// STRUCT      :: icmp6_router_renum
// DESCRIPTION :: router renumbering structure
// **/
typedef struct icmp6_router_renum_struct
{
    icmp6_hdr      rr_hdr;
    unsigned char  rr_segnum;
    unsigned char  rr_flags;
    unsigned short rr_maxdelay;
    unsigned int   rr_reserved;
} icmp6_router_renum;


// /**
// MACRO       :: rr_type : rr_hdr.icmp6_type
// DESCRIPTION :: routing header icmpv6 type
// **/
#define rr_type         rr_hdr.icmp6_type

// /**
// MACRO       :: rr_code : rr_hdr.icmp6_code
// DESCRIPTION :: routing header icmpv6 code
// **/
#define rr_code         rr_hdr.icmp6_code

// /**
// MACRO       :: rr_cksum : rr_hdr.icmp6_cksum
// DESCRIPTION :: routing header icmpv6 checksum
// **/
#define rr_cksum        rr_hdr.icmp6_cksum

// /**
// MACRO       :: rr_seqnum : rr_hdr.icmp6_data32[0]
// DESCRIPTION :: routing header icmpv6 data
// **/
#define rr_seqnum       rr_hdr.icmp6_data32[0]


// /**
// MACRO       :: ICMP6_RR_FLAGS_TEST  : 0x80
// DESCRIPTION :: router flag reset
// **/
#define ICMP6_RR_FLAGS_TEST     0x80

// /**
// MACRO       :: ICMP6_RR_FLAGS_REQRESULT : 0x40
// DESCRIPTION :: icmpv6 request reset flag
// **/
#define ICMP6_RR_FLAGS_REQRESULT    0x40

// /**
// MACRO      :: ICMP6_RR_FLAGS_FORCEAPPLY : 0x20
// DESCRIPTION :: icmpv6 force apply flag
// **/
#define ICMP6_RR_FLAGS_FORCEAPPLY   0x20

// /**
// MACRO       :: ICMP6_RR_FLAGS_SPECSITE : 0x10
// DESCRIPTION :: icmpv6 flag
// **/
#define ICMP6_RR_FLAGS_SPECSITE     0x10

// /**
// MACRO       :: ICMP6_RR_FLAGS_PREVDONE : 0x08
// DESCRIPTION :: icmpv6 flag
// **/
#define ICMP6_RR_FLAGS_PREVDONE     0x08

// prefix control operation: match-prefix part
// /**

// STRUCT      :: rr_pco_match
// DESCRIPTION :: rpm structure
// **/
typedef struct rr_pco_match_struct
{
    unsigned char       rpm_code;
    unsigned char       rpm_len;
    unsigned char       rpm_ordinal;
    unsigned char       rpm_matchlen;
    unsigned char       rpm_minlen;
    unsigned char       rpm_maxlen;
    unsigned short      rpm_reserved;
    in6_addr    rpm_prefix;
} rr_pco_match;


// /**
// CONSTANT    :: RPM_PCO_ADD : 1
// DESCRIPTION :: rpm add
// **/
#define RPM_PCO_ADD     1

// /**
// CONSTANT    :: RPM_PCO_CHANGE : 2
// DESCRIPTION :: rpm change
// **/
#define RPM_PCO_CHANGE      2

// /**
// CONSTANT    :: RPM_PCO_SETGLOBAL : 3
// DESCRIPTION :: rpm set global flag.
// **/
#define RPM_PCO_SETGLOBAL   3

/* prefix control operation: use-prefix part */
// /**
// STRUCT      :: rr_pco_use
// DESCRIPTION :: rpu structure
// **/
typedef struct rr_pco_use_struct
{
    unsigned char       rpu_uselen;
    unsigned char       rpu_keeplen;
    unsigned char       rpu_ramask;
    unsigned char       rpu_raflags;
    unsigned int        rpu_vltime;
    unsigned int        rpu_pltime;
    unsigned int        rpu_flags;
    in6_addr rpu_prefix;
} rr_pco_use;


// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_RAFLAGS_ONLINK : 0x20
// DESCRIPTION :: on link flag
// **/
#define ICMP6_RR_PCOUSE_RAFLAGS_ONLINK  0x20

// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_RAFLAGS_AUTO : 0x10
// DESCRIPTION :: Auto con flag
// **/
#define ICMP6_RR_PCOUSE_RAFLAGS_AUTO    0x10

#if BYTE_ORDER == BIG_ENDIAN


// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME  : 0x80000000
// DESCRIPTION :: Pico use flag
// **/
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME    0x80000000

// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME : 0x40000000
// DESCRIPTION :: Pico use flag
// **/
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME    0x40000000

#else /* BYTE_ORDER == LITTLE_ENDIAN */

// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME : 0x00000080
// DESCRIPTION :: Pico use flag
// **/
#define ICMP6_RR_PCOUSE_FLAGS_DECRVLTIME    0x00000080

// /**
// CONSTANT    :: ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME : 0x00000040
// DESCRIPTION :: pco use flag
// **/
#define ICMP6_RR_PCOUSE_FLAGS_DECRPLTIME    0x00000040
#endif

/* message body: result message */
// /**
// STRUCT      :: rr_result
// DESCRIPTION :: result message structure
// **/
typedef struct rr_result_struct
{
    unsigned short  rrr_flags;
    unsigned char   rrr_ordinal;
    unsigned char   rrr_matchedlen;
    unsigned int    rrr_ifid;
    in6_addr        rrr_prefix;
} rr_result;

#if BYTE_ORDER == BIG_ENDIAN

// /**
// CONSTANT    :: ICMP6_RR_RESULT_FLAGS_OOB : 0x0002
// DESCRIPTION :: result flag
// **/
#define ICMP6_RR_RESULT_FLAGS_OOB       0x0002

// /**
// CONSTANT    :: ICMP6_RR_RESULT_FLAGS_FORBIDDEN : 0x0001
// DESCRIPTION :: result flag
// **/
#define ICMP6_RR_RESULT_FLAGS_FORBIDDEN     0x0001
#else /* BYTE_ORDER == LITTLE_ENDIAN */

// /**
// CONSTANT    :: ICMP6_RR_RESULT_FLAGS_OOB : 0x0200
// DESCRIPTION :: result flag
// **/
#define ICMP6_RR_RESULT_FLAGS_OOB       0x0200

// /**
// CONSTANT    :: ICMP6_RR_RESULT_FLAGS_FORBIDDEN :0x0100
// DESCRIPTION :: result flag
// **/
#define ICMP6_RR_RESULT_FLAGS_FORBIDDEN     0x0100
#endif

/*
 * Home Agent Address Discovery
 */

/* home agent address discovery request */
// /**
// STRUCT      :: haad_request
// DESCRIPTION :: home agent address discovery structure
// **/
typedef struct haad_request_struct
{
    icmp6_hdr   haad_req_hdr;
    in6_addr    haad_req_ha;
} haad_request;


// /**
// MACRO       :: haad_req_type : haad_req_hdr.icmp6_type
// DESCRIPTION :: home agent icmp6 type
// **/
#define haad_req_type   haad_req_hdr.icmp6_type

// /**
// MACRO       :: haad_req_code : haad_req_hdr.icmp6_code
// DESCRIPTION :: home agent icmp6 code
// **/
#define haad_req_code   haad_req_hdr.icmp6_code

// /**
// MACRO       :: haad_req_cksum  : haad_req_hdr.icmp6_cksum
// DESCRIPTION :: home agent icmp6 checksum
// **/
#define haad_req_cksum  haad_req_hdr.icmp6_cksum

// /**
// MACRO       :: haad_req_id : haad_req_hdr.icmp6_data8[0]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_req_id haad_req_hdr.icmp6_data8[0]

// /**
// MACRO    :: haad_req_res1 : haad_req_hdr.icmp6_data8[1]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_req_res1   haad_req_hdr.icmp6_data8[1]

// /**
// MACRO       :: haad_req_res2 : haad_req_hdr.icmp6_data16[1]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_req_res2   haad_req_hdr.icmp6_data16[1]

/* home agent address discovery reply */
// /**
// STRUCT      :: haad_reply
// DESCRIPTION :: reply structure
// **/
typedef struct haad_reply_struct
{
    icmp6_hdr   haad_rep_hdr;
    in6_addr    haad_rep_agtaddrs[1];   /* ??? */
} haad_reply;


// /**
// MACRO       :: haad_rep_type : haad_rep_hdr.icmp6_type
// DESCRIPTION :: home agent icmp6 type
// **/
#define haad_rep_type   haad_rep_hdr.icmp6_type

// /**
// MACRO       :: haad_rep_code : haad_rep_hdr.icmp6_code
// DESCRIPTION :: home agent icmp6 code
// **/
#define haad_rep_code   haad_rep_hdr.icmp6_code

// /**
// MACRO       :: haad_rep_cksum : haad_rep_hdr.icmp6_cksum
// DESCRIPTION :: home agent icmp6 checksum
// **/
#define haad_rep_cksum  haad_rep_hdr.icmp6_cksum

// /**
// MACRO       :: haad_rep_id : haad_rep_hdr.icmp6_data8[0]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_rep_id haad_rep_hdr.icmp6_data8[0]

// /**
// MACRO       :: haad_rep_res1 : haad_rep_hdr.icmp6_data8[1]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_rep_res1   haad_rep_hdr.icmp6_data8[1]

// /**
// MACRO       :: haad_rep_res2 : haad_rep_hdr.icmp6_data16[1]
// DESCRIPTION :: home agent icmp6 data
// **/
#define haad_rep_res2   haad_rep_hdr.icmp6_data16[1]

/* IPSec flags */


// /**
// CONSTANT    :: ICMP6SEC_ERRORS : 1
// DESCRIPTION :: auth error types
// **/
#define ICMP6SEC_ERRORS     1   /* auth error types */

// /**
// CONSTANT    :: ICMP6SEC_REQUESTS : 2
// DESCRIPTION :: auth echo requests
// **/
#define ICMP6SEC_REQUESTS   2   /* auth echo requests */

// /**
// CONSTANT    :: ICMP6SEC_GROUPS : 4
// DESCRIPTION :: auth group management
// **/
#define ICMP6SEC_GROUPS     4   /* auth group management */

// /**
// CONSTANT    :: ICMP6SEC_NEIGHBORS : 8
// DESCRIPTION :: auth neighbor management
// **/
#define ICMP6SEC_NEIGHBORS  8   /* auth neighbor management */

// Error Codes

// /**
// CONSTANT    :: EMSGSIZE  : 40
// DESCRIPTION :: Message too long
// **/
#ifndef EMSGSIZE
#define EMSGSIZE        40      // Message too long
#endif

// /**
// CONSTANT    :: EPROTOTYPE : 41
// DESCRIPTION :: Protocol wrong type for socket
// **/
#ifndef EPROTOTYPE
#define EPROTOTYPE      41      // Protocol wrong type for socket
#endif

// /**
// CONSTANT    :: ENOPROTOOPT : 42
// DESCRIPTION :: Protocol not available
// **/
#ifndef ENOPROTOOPT
#define ENOPROTOOPT     42      // Protocol not available
#endif

// /**
// CONSTANT    :: EPROTONOSUPPORT  : 43
// DESCRIPTION :: Protocol not supported
// **/
#ifndef EPROTONOSUPPORT
#define EPROTONOSUPPORT 43      // Protocol not supported
#endif


// /**
// CONSTANT    :: ENETDOWN : 50
// DESCRIPTION :: Network is down
// **/
#ifndef ENETDOWN
#define ENETDOWN        50      // Network is down
#endif

// /**
// CONSTANT    :: ENETRESET : 52
// DESCRIPTION :: Network dropped connection on reset
// **/
#ifndef ENETRESET
#define ENETRESET       52      // Network dropped connection on reset
#endif

// /**
// CONSTANT    :: ECONNABORTED  : 53
// DESCRIPTION :: Software caused connection abort
// **/
#ifndef ECONNABORTED
#define ECONNABORTED    53      // Software caused connection abort
#endif

// /**
// CONSTANT    :: ECONNRESET : 54
// DESCRIPTION :: Connection reset by peer
// **/
#ifndef ECONNRESET
#define ECONNRESET      54      // Connection reset by peer
#endif

// /**
// CONSTANT    :: ENOBUFS : 55
// DESCRIPTION :: No buffer space available
// **/
#ifndef ENOBUFS
#define ENOBUFS         55      // No buffer space available
#endif

// /**
// CONSTANT    :: EISCONN : 56
// DESCRIPTION :: Socket is already connected
// **/
#ifndef EISCONN
#define EISCONN         56      // Socket is already connected
#endif

// /**
// CONSTANT    :: ENOTCONN : 57
// DESCRIPTION :: Socket is not connected
// **/
#ifndef ENOTCONN
#define ENOTCONN        57      // Socket is not connected
#endif

// /**
// CONSTANT    :: ESHUTDOWN : 58
// DESCRIPTION :: Can't send after socket shutdown
// **/
#ifndef ESHUTDOWN
#define ESHUTDOWN       58      // Can't send after socket shutdown
#endif

// /**
// CONSTANT    :: ETOOMANYREFS : 59
// DESCRIPTION :: Too many references: can't splice
// **/
#ifndef ETOOMANYREFS
#define ETOOMANYREFS    59      // Too many references: can't splice
#endif

// /**
// CONSTANT    :: ETIMEDOUT : 60
// DESCRIPTION :: Operation timed out
// **/
#ifndef ETIMEDOUT
#define ETIMEDOUT       60      // Operation timed out
#endif

// /**
// CONSTANT    :: ECONNREFUSED : 61
// DESCRIPTION :: Connection refused
// **/
#ifndef ECONNREFUSED
#define ECONNREFUSED    61      // Connection refused
#endif


// /**
// CONSTANT    :: EHOSTDOWN : 64
// DESCRIPTION :: Host is down
// **/
#ifndef EHOSTDOWN
#define EHOSTDOWN       64      // Host is down
#endif



// Variables related to this implementation
// of the IPv6 control message protocol.
// /**
// STRUCT      :: icmp6_stat
// DESCRIPTION :: Structure holding all the icmp6 statistics
// **/
typedef struct  icmp6stat_struct
{
// statistics related to IPV6 icmp packets generated
    int icp6s_badlen;       /* calculated bound mismatch */
    int icp6s_badcode;      /* icmp6_code out of range */
    int icp6s_tooshort; /* packet < ICMP6_MINLEN */
    int icp6s_error;        /* icmp6 error occured */
    int icp6s_snd_ndsol;    /* # of sent neighbor solicitations */
    int icp6s_snd_ndadv;    /* # of sent neighbor advertisements */
    int icp6s_snd_rtsol;    /* # of sent router solicitations */
    int icp6s_snd_rtadv;    /* # of sent router advertisements */
    int icp6s_snd_redirect; /* # of sent redirects */

    int icp6s_rcv_ndsol;    /* # of rcvd neighbor solicitations */
    int icp6s_rcv_ndadv;    /* # of rcvd neighbor advertisements */
    int icp6s_rcv_rtsol;    /* # of rcvd router solicitations */
    int icp6s_rcv_rtadv;    /* # of rcvd router advertisements */
    int icp6s_rcv_redirect; /* # of rcvd redirects */

    int icp6s_rcv_ur_addr;  /* # of rcvd unreach address */
    int icp6s_rcv_badrtsol; /* # of rcvd bad router sol. */
    int icp6s_rcv_badrtadv; /* # of rcvd bad router adv. */
    int icp6s_rcv_badndsol; /* # of rcvd bad neighbor sol. */
    int icp6s_rcv_badndadv; /* # of rcvd bad neighbor adv. */
    int icp6s_rcv_badredirect;  /* # of rcvd bad redirects */
} icmp6_stat;


// /**
// STRUCT      :: Icmp6Data
// DESCRIPTION :: Icmpv6 statistic structure
// **/
typedef
struct network_icmpv6_struct
{
    icmp6_stat icmp6stat;
} Icmp6Data;

// All Function declaration


// /**
// API                 :: Initialization function
// LAYER               :: Network
// PURPOSE             :: Initialize Icmp6
// PARAMETERS          ::
// +ipv6                : IPv6Data* ipv6: IPv6 data pointer of the node.
// RETURN              :: void
// **/
void
Icmp6Init(IPv6Data* ipv6);


// /**
// API                 :: Adding ICMPv6 Header
// LAYER               :: Network
// PURPOSE             :: Adding ICMPv6 Header
// PARAMETERS          ::
// +node                : Node*         : Pointer to Node
// +msg                 : Message* msg  : Pointer to message structure.
// +type                : int type      : Type of Icmpv6 message.
// +code                : int code      : Icmpv6 code of message.
// +data                : char* data    : Icmpv6 message data.
// +dataLen             : int dataLen   : Icmpv6 message data length.
// RETURN              :: void
// **/
void
AddICMP6Header(
    Node* node,
    Message* msg,
    int type,
    int code,
    char* data,
    int dataLen);



// /**
// API                 :: ICMPv6 Input routine.
// LAYER               :: Network
// PURPOSE             :: Add Icmp6 header to a packet
// PARAMETERS          ::
// +node                : Node* node    : Pointer to node.
// +msg                 : Message* msg  : Pointer to message structure.
// +oarg                : int oarg      : Option argument
// +interfaceId         : int interfaceId: Index to the concerned interface.
// RETURN              :: void
// **/
void icmp6_input(
    Node* node,
    Message* msg,
    void *oarg,
    int interfaceId);



// /**
// API                 :: ICMPv6 packet sending function
// LAYER               :: Network
// PURPOSE             :: ICMPv6 packet sending function
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Structure
// + opts               : int opts: Options
// +imo                 : ip_moptions* imo: Pointer to multicast options.
// +interfaceId         : int interfaceId : Index of the Interface
// +flags               : int flags: Flags for route type.
// RETURN              :: void
// **/
void
icmp6_send(
    Node* node,
    Message* msg,
    void* opts,
    ip_moptions* imo,
    int interfaceId,
    int flags);



// /**
// API                 :: ICMPv6 error message sending function
// LAYER               :: Network
// PURPOSE             :: ICMPv6 error message sending function
// PARAMETERS          ::
// +node                : Node* node    : Pointer to Node
// +msg                 : Message* msg  : Pointer to Message Structure
// +type                : int type      : Icmpv6 type of message.
// +code                : int code      : Icmpv6 code of message.
// +arg                 : int arg       : Option argument.
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN              :: void
// **/
void
icmp6_error(
    Node* node,
    Message* msg,
    int type,
    int code,
    int arg,
    int interfaceId);



// /**
// API                 :: ICMPv6 reflecting packet to source function
// LAYER               :: Network
// PURPOSE             :: ICMPv6 reflecting packet to source function
// PARAMETERS          ::
// +node                : Node* node   : Pointer to the Node
// +msg                 : Message* msg : Pointer to the Message structure
// +opts                : unsigned char* opts: Option pointer.
// +interfaceId         : int interfaceId   : Index of the concerned Interface
// RETURN              :: void
// **/
void
icmp6_reflect(
    Node* node,
    Message* msg,
    unsigned char* opts,
    int interfaceId);



// /**
// API                 :: ICMPv6 statistic printing function
// LAYER               :: Network
// PURPOSE             :: ICMPv6 statistic printing function
// PARAMETERS          ::
// +node                : Node* node : pointer to the node
// RETURN              :: void
// **/
void Icmp6Finalize(Node* node);

#endif
