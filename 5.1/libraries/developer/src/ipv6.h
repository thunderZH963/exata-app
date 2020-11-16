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

// /**
// PACKAGE     :: IPv6
// DESCRIPTION :: Data structures and parameters used in network layer
//                are defined here.
// **/

// Objective: Header file for IPv6 (Internet Protocol version 6)
// Reference: RFC 2460, RFC 2461

#ifndef IPV6_H
#define IPV6_H

#include "api.h"
#include "ipv6_route.h"
#include "ip6_opts.h"
#include "network_ip.h"
#include "ip6_input.h"
#include "ipv6_auto_config.h"

// /**
// CONSTANT    :: MAX_KEY_LEN : 128
// DESCRIPTION :: Maximum Key length of ipv6 address.
// **/
#define MAX_KEY_LEN 128

// /**
// CONSTANT    :: MAX_PREFIX_LEN : 64
// DESCRIPTION :: Maximum Prefix length of ipv6 address.
// **/
#define MAX_PREFIX_LEN 64

// /**
// CONSTANT    :: CURR_HOP_LIMIT : 255
// DESCRIPTION :: Current Hop limit a packet will traverse.
// **/
#define CURR_HOP_LIMIT  255

// /**
// CONSTANT    :: IPV6_ADDR_LEN : 16
// DESCRIPTION :: Ipv6 Address Lenght.
// **/
#define IPV6_ADDR_LEN       16

// /**
// CONSTANT    :: IP6_NHDR_HOP : 0
// DESCRIPTION :: Hop-by_hop IPv6 Next header field value.
// **/
#define IP6_NHDR_HOP    0

// /**
// CONSTANT    :: IP6_NHDR_RT : 43
// DESCRIPTION :: Routing IPv6 Next header field value.
// **/
#define IP6_NHDR_RT     43

// /**
// CONSTANT    :: IP6_NHDR_FRAG : 44
// DESCRIPTION :: Fragment IPv6 Next header field value.
// **/
#define IP6_NHDR_FRAG   44

// /**
// CONSTANT    :: IP6_NHDR_AUTH : 51
// DESCRIPTION :: Authentication IPv6 Next header field value.
// **/
#define IP6_NHDR_AUTH   51

// /**
// CONSTANT    :: IP6_NHDR_ESP : 50
// DESCRIPTION :: Encryption IPv6 Next header field value.
// **/
#define IP6_NHDR_ESP    50

// /**
// CONSTANT    :: IP6_NHDR_IPCP : 108
// DESCRIPTION :: Compression IPv6 Next header field value.
// **/
#define IP6_NHDR_IPCP   108

// /**
// CONSTANT    :: IP6_NHDR_OSPF : 89
// DESCRIPTION :: Compression IPv6 Next header field value.
// **/
#define IP6_NHDR_OSPF   89

// /**
// CONSTANT    :: IP6_NHDR_DOPT : 60
// DESCRIPTION :: Destination IPv6 Next header field value.
// **/
#define IP6_NHDR_DOPT   60  // destination options IPv6 header

// /**
// CONSTANT    :: IP6_NHDR_NONH : 59
// DESCRIPTION :: No next header IPv6 Next header field value.
// **/
#define IP6_NHDR_NONH   59

// /**
// CONSTANT    :: IPV6_FLOWINFO_VERSION : 0x000000f0
// DESCRIPTION :: Flow infromation version.
// **/
#define IPV6_FLOWINFO_VERSION   0x0000000f

// /**
// CONSTANT    :: IPV6_VERSION :  6
// DESCRIPTION :: IPv6 version no.
// **/
#define IPV6_VERSION            6

// /**
// CONSTANT    :: IP6_MMTU : 1280
// DESCRIPTION :: Minimal MTU and reassembly.
// **/
#define IP6_MMTU            1280

// If not Using Linux version of ipv6
#ifndef _NETINET_IN_H

// /**
// CONSTANT    :: IPPROTO_ICMPV6 : 58
// DESCRIPTION :: ICMPv6 protocol no.
// **/
#define IPPROTO_ICMPV6      58
#endif

// /**
// CONSTANT    :: IP6ANY_ANYCAST : 3
// DESCRIPTION :: IPv6 anycast.
// **/
#define IP6ANY_ANYCAST      3

// /**
// CONSTANT    :: ND_DEFAULT_HOPLIM : 255
// DESCRIPTION :: Node Discovery hop count.
// **/
#define ND_DEFAULT_HOPLIM       255

// /**
// MACRO    :: ND_DEFAULT_CLASS(0xe0)
// DESCRIPTION :: Node Discovery sets class.
// **/
#define ND_DEFAULT_CLASS        IPV6_SET_CLASS(0xe0)

// /**
// CONSTANT    :: IP6_INSOPT_NOALLOC : 1
// DESCRIPTION :: IPv6 insert option with no allocation.
// **/
#define IP6_INSOPT_NOALLOC  1

// /**
// CONSTANT    :: IP6_INSOPT_RAW : 2
// DESCRIPTION :: IPv6 insert raw option.
// **/
#define IP6_INSOPT_RAW      2

// /**
// CONSTANT    :: IP_FORWARDING : 1
// DESCRIPTION :: IPv6 forwarding flag.
// **/
#define IP_FORWARDING       1

// /**
// CONSTANT    :: IP6F_RESERVED_MASK : 0x0600
// DESCRIPTION :: Reserved fragment flag.
// **/
#define IP6F_RESERVED_MASK 0x0600

// /**
// CONSTANT    :: IP_DF : 0x4000
// DESCRIPTION :: Don't fragment flag.
// **/
#define IP_DF 0x4000

// /**
// CONSTANT    :: IP6F_MORE_FRAG : 0x01
// DESCRIPTION :: More fragments flag.
// **/
#define IP6F_MORE_FRAG 0x01

// /**
// CONSTANT    :: IP6F_OFF_MASK : 0xf8ff
// DESCRIPTION :: Mask for fragmenting bits.
// **/
#define IP6F_OFF_MASK 0xf8ff

// /**
// CONSTANT    :: IP6_FRAGTTL : 120
// DESCRIPTION :: Time to live for frags.
// **/
#define IP6_FRAGTTL 120

// Multicast Related Constants.
// /**
// CONSTANT    :: IP6_T_FLAG : 0x10
// DESCRIPTION :: T Flag if set indicates transient multicast address.
// **/
#define IP6_T_FLAG 0x10

// /**
// CONSTANT    :: Multicast Address Scope Related constants.
// **/
#define IP6_MULTI_INTERFACE_SCOPE 0x01
#define IP6_MULTI_LINK_SCOPE 0x02
#define IP6_MULTI_ADMIN_SCOPE 0x04
#define IP6_MULTI_SITE_SCOPE 0x05
#define IP6_MULTI_ORG_SCOPE 0x08
#define IP6_MULTI_GLOBAL_SCOPE 0x0e

// /**
// CONSTANT    :: IP_FRAGMENT_HOLD_TIME : 60 * SECOND
// DESCRIPTION :: IP Fragment hold time.
// **/
#define IP_FRAGMENT_HOLD_TIME  60 * SECOND

// /**
// CONSTANT    :: IP_ROUTETOIF : 4
// DESCRIPTION :: IPv6 route to interface.
// **/
#define IP_ROUTETOIF        4

// /**
// CONSTANT    :: IP_DEFAULT_MULTICAST_TTL : 255
// DESCRIPTION :: IPv6 route to interface.
// **/
#ifndef IP_DEFAULT_MULTICAST_TTL
#define IP_DEFAULT_MULTICAST_TTL 255
#endif


// /**
// CONSTANT    :: IPTTLDEC : 1
// DESCRIPTION :: TTL decrement.
// **/
#define IPTTLDEC 1


// /**
// CONSTANT    :: ENETUNREACH : 1
// DESCRIPTION :: Network unreachable.
// **/
#ifndef ENETUNREACH
#define ENETUNREACH         1
#endif

// /**
// CONSTANT    :: EHOSTUNREACH : 2
// DESCRIPTION :: Host unreachable.
// **/
#ifndef EHOSTUNREACH
#define EHOSTUNREACH        2
#endif

// /**
// CONSTANT    :: MAX_INITIAL_RTR_ADVERT_INTERVAL  : 16 * SECOND
// DESCRIPTION :: Router Advertisement timer.
// **/
#define MAX_INITIAL_RTR_ADVERT_INTERVAL  16 * SECOND

// /**
// CONSTANT    :: MAX_INITIAL_RTR_ADVERTISEMENTS  : 3
// DESCRIPTION :: Maximum Router Advertisement.
// **/
#define MAX_INITIAL_RTR_ADVERTISEMENTS  3

// /**
// CONSTANT    :: MAX_RTR_ADVERT_INTERVAL  : 600 * SECOND
// DESCRIPTION :: Maximum Router Advertisement timer.
// **/
#define MAX_RTR_ADVERT_INTERVAL  (600 * SECOND)

// /**
// CONSTANT    :: MIN_RTR_ADVERT_INTERVAL  : MAX_RTR_ADVERT_INTERVAL * 0.33
// DESCRIPTION :: Minimum Router Advertisement timer.
// **/
#define MIN_RTR_ADVERT_INTERVAL  (MAX_RTR_ADVERT_INTERVAL * 0.33)

// /**
// CONSTANT    :: RTR_SOLICITATION_INTERVAL  : 4 * SECOND
// DESCRIPTION :: Router Solicitation timer.
// **/
#define RTR_SOLICITATION_INTERVAL  4 * SECOND

// /**
// CONSTANT    :: REACHABLE_TIME : (30 * SECOND)
// DESCRIPTION :: reachable time
// **/
#define REACHABLE_TIME          (30 * SECOND)

// /**
// CONSTANT    :: UNREACHABLE_TIME : (30 * SECOND)
// DESCRIPTION :: unreachable time
// **/
#define UNREACHABLE_TIME          (30 * SECOND)

// /**
// CONSTANT    :: RETRANS_TIMER : (2 * SECOND)
// DESCRIPTION :: retransmission timer
// **/
#define RETRANS_TIMER           (2 * SECOND)

// /**
// CONSTANT    :: MAX_NEIGHBOR_ADVERTISEMENT : 3
// DESCRIPTION :: maximum neighbor advertisement
// **/
#define MAX_NEIGHBOR_ADVERTISEMENT    3

// /**
// CONSTANT    :: MAX_RTR_SOLICITATIONS : 1
// DESCRIPTION :: maximum Router Solicitations
// NOTE         : Sending only one Solicitation; modify it once
//                autoconfiguration supported.
// **/
#define MAX_RTR_SOLICITATIONS    1

// /**
// CONSTANT    :: MAX_MULTICAST_SOLICIT : 3
// DESCRIPTION :: maximum multicast solicitation
// **/
#define MAX_MULTICAST_SOLICIT    3

// /**
// CONSTANT    :: MAX_UNICAST_SOLICIT : 3
// DESCRIPTION :: maximum unicast solicitation
// **/
#define MAX_UNICAST_SOLICIT    3

// /**
// CONSTANT    :: PKT_EXPIRE_DURATION : (3 * SECOND)
// DESCRIPTION :: Packet expiration interval
// **/
#define PKT_EXPIRE_DURATION  (MAX_MULTICAST_SOLICIT * RETRANS_TIMER)

// /**
// CONSTANT    :: INVALID_LINK_ADDR : -3
// DESCRIPTION :: Invalid Link Layer Address
// **/
#define INVALID_LINK_ADDR   -3



// /**
// CONSTANT    :: MAX_HASHTABLE_SIZE : 4
// DESCRIPTION :: Maximum size of Hash-Table
// **/
//#define MAX_HASHTABLE_SIZE       4
#define MAX_HASHTABLE_SIZE       20

// /**
// CONSTANT    :: MAX_REVLOOKUP_SIZE : 100
// DESCRIPTION :: Maximum Rev Look up hash table size
// **/
#define MAX_REVLOOKUP_SIZE 100

// /**
// CONSTANT    :: IPV6_HEADER_LENGTH : 40
// DESCRIPTION :: Length of IPv6 header
// **/
#define IPV6_HEADER_LENGTH  40


// /**
// STRUCT      :: ip6_hdr_struct
// DESCRIPTION :: QualNet typedefs struct ip6_hdr_struct to ip6_hdr.
//                struct ip6_hdr_struct is 40 bytes,
//                just like in the BSD code.
// **/
typedef struct ip6_hdr_struct
{
    UInt32 ipv6HdrVcf;//ip6_v:4,        // version first, must be 6
                 //ip6_class:8,    // traffic class
                 //ip6_flow:20;    // flow label
#ifndef ip6_plen
    unsigned short ip6_plen;     // payload length
#else
    unsigned short ip6_plength;
#endif

#ifndef ip6_nxt
    unsigned char  ip6_nxt;      // next header
#else
    unsigned char ip6_next;
#endif

#ifndef ip6_hlim
    unsigned char  ip6_hlim;     // hop limit
#else
    unsigned char ip6_hoplim;
#endif

    in6_addr ip6_src;            // source address
    in6_addr ip6_dst;            // destination address
} ip6_hdr;

#ifdef _WIN32
#define ipv6_plength ip6_plength
#define ipv6_nhdr    ip6_next
#define ipv6_hlim    ip6_hoplim
#else
#define ipv6_plength ip6_plen
#define ipv6_nhdr    ip6_nxt
#define ipv6_hlim    ip6_hlim
#endif



// /**
// API                 :: ip6_hdrSetVersion()
// LAYER               :: Network
// PURPOSE             :: Set the value of version for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : UInt32 : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// + version           : UInt32 : Input value for set operation
// RETURN              :: void  : NULL.
// **/
static void ip6_hdrSetVersion(UInt32 *ipv6HdrVcf, UInt32 version)
{
    //masks ip6_v within boundry range
    version = version & maskInt(29, 32);

    //clears the first four bits of ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf & maskInt(5, 32);

    //Setting the value of version in ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf | LshiftInt(version, 4);
}


// /**
// API                 :: ip6_hdrSetClass()
// LAYER               :: Network
// PURPOSE             :: Set the value of class for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : UInt32 : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// + ipv6Class         : unsigned char : Input value for set operation
// RETURN              :: void  : NULL.
// **/
static void ip6_hdrSetClass(UInt32 *ipv6HdrVcf, unsigned char ipv6Class)
{
    unsigned int ipv6Class_int = (unsigned int)ipv6Class;

    //masks ip6_class within boundry range
    ipv6Class_int = ipv6Class_int & maskInt(25, 32);

    //clears the 5-12 bits of ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf & (~(maskInt(5, 12)));

    //Setting the value of class in ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf | LshiftInt(ipv6Class_int, 12);
}


// /**
// API                 :: ip6_hdrSetFlow()
// LAYER               :: Network
// PURPOSE             :: Set the value of flow for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : UInt32 : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// + flow              : UInt32 : Input value for set operation
// RETURN              :: void  : NULL.
// **/
static void ip6_hdrSetFlow(UInt32 *ipv6HdrVcf, UInt32 flow)
{
    //masks ip6_flow within boundry range
    flow = flow & maskInt(13, 32);

    //clears the last 20 bits of ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf & maskInt(1, 12);

    //Setting the value of flow in ipv6HdrVcf
    *ipv6HdrVcf = *ipv6HdrVcf | flow;
}


// /**
// API                 :: ip6_hdrGetVersion()
// LAYER               :: Network
// PURPOSE             :: Returns the value of version for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : unsigned int : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// RETURN              ::UInt32
// **/
static unsigned int ip6_hdrGetVersion(unsigned int ipv6HdrVcf)
{
    unsigned int version = ipv6HdrVcf;

    //clears the first 4 bits
    version = version & maskInt(1, 4);

    //right shifts so that last four bits represent version
    version = RshiftInt(version, 4);

    return version;
}

// /**
// API                 :: ip6_hdrGetClass()
// LAYER               :: Network
// PURPOSE             :: Returns the value of ip6_class for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : unsigned int : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// RETURN              ::UInt32
// **/
static unsigned char ip6_hdrGetClass(unsigned int ipv6HdrVcf)
{
    unsigned int ipv6Class = ipv6HdrVcf;

    //clears all the bits except 5-12
    ipv6Class = ipv6Class & maskInt(5, 12);

    //right shifts so that last 8 bits represent class
    ipv6Class = RshiftInt(ipv6Class, 12);

    return (unsigned char)ipv6Class;
}


// /**
// API                 :: ip6_hdrGetFlow()
// LAYER               :: Network
// PURPOSE             :: Returns the value of ip6_flow for ip6_hdr
// PARAMETERS          ::
// + ipv6HdrVcf        : unsigned int : The variable containing the value of ip6_v,ip6_class
//                       and ip6_flow
// RETURN              ::UInt32
// **/
static unsigned int ip6_hdrGetFlow(unsigned int ipv6HdrVcf)
{
    unsigned int ipv6_flow = ipv6HdrVcf;

    //clears the 1-12 bits
    ipv6_flow = ipv6_flow & maskInt(13, 32);

    return ipv6_flow;
}


// /**
// STRUCT      :: in6_multi_struct
// DESCRIPTION :: QualNet typedefs struct in6_multi_struct to in6_multi.
//                struct in6_multi_struct is just like in the BSD code.
// **/
struct in6_multi_struct         //Taken from in6_var.h-new
{
    int mop;
    in6_addr inm6_addr;         // IPv6 multicast address
    int inm6_ifIndex;           // back pointer to ifIndex
    NodeAddress inm6_ifma;      // back pointer to ifmultiaddr
    unsigned int inm6_timer;    // ICMPv6 membership report timer
    unsigned int inm6_state;    // state of the membership
};
typedef struct in6_multi_struct in6_multi;

// /**
// STRUCT      :: ipv6_h2hhdr_struct
// DESCRIPTION :: QualNet typedefs struct ipv6_h2hhdr_struct to ipv6_h2hhdr.
//                struct ipv6_h2hhdr_struct is hop-by-Hop Options Header of
//                14 bytes, just like in the BSD code.
// **/
typedef struct ipv6_h2hhdr_struct
{
    unsigned char  ih6_nh;   // next header
    unsigned char  ih6_hlen; // header extension length
    unsigned short ih6_pad1; // to 4 byte length
    unsigned int   ih6_pad2; // to 8 byte length
} ipv6_h2hhdr;

// Routing Header.


// /**
// CONSTANT    :: IP6_LSRRT : 0
// DESCRIPTION :: type 0: loose source route
// **/
#define IP6_LSRRT   0   // type 0: loose source route


// /**
// CONSTANT    :: IP6_NIMRT : 1
// DESCRIPTION :: type 1: Nimrod
// **/
#define IP6_NIMRT   1   // type 1: Nimrod

// /**
// STRUCT      :: ipv6_rthdr_struct
// DESCRIPTION :: QualNet typedefs struct ipv6_rthdr_struct to ipv6_rthdr.
//                struct ipv6_h2hhdr_struct is routing options header of
//                8 bytes, just like in the BSD code.
// **/
typedef struct ipv6_rthdr_struct
{
    unsigned char  ir6_nh;    // next header
    unsigned char  ir6_hlen;  // header extension length
    unsigned char  ir6_type;  // routing type
    unsigned char  ir6_sglt;  // index of next address
    unsigned int   ir6_slmsk; // was strict/loose bit mask
} ipv6_rthdr;

// /**
// CONSTANT    :: IP6_RT_MAX : 3
// DESCRIPTION :: Maximum number of addresses.
// **/
#define IP6_RT_MAX  23

// /**
// STRUCT      :: ipv6_rthdr_struct
// DESCRIPTION :: QualNet typedefs struct ipv6_rthdr_struct to ipv6_rthdr.
//                struct ipv6_h2hhdr_struct is destination options header
//                of 8 bytes, just like in the BSD code.
// **/
typedef struct ipv6_dopthdr_struct
{
    unsigned char  io6_nh;      // next header
    unsigned char  io6_hlen;    // header extension length
    unsigned short io6_pad1;    // to 4 byte length
    unsigned int   io6_pad2;    // to 8 byte length
} ipv6_dopthdr;

// /**
// STRUCT      :: ip_moptions_struct
// DESCRIPTION :: QualNet typedefs struct ip_moptions_struct to ip_moptions.
//                struct ip_moptions_struct is multicast option structure,
//                just like in the BSD code.
// **/
struct ip_moptions_struct
{
    char* moptions;
    int imo_multicast_interface;
    int imo_multicast_ttl;
    int imo_multicast_loop;
};
typedef struct ip_moptions_struct ip_moptions;

// /**
// STRUCT      :: ip6_frag_struct
// DESCRIPTION :: QualNet typedefs struct ip6_frag_struct to ipv6_fraghdr.
//                struct ip6_frag_struct is fragmentation header structure.
// **/
typedef struct ip6_frag_struct
{
    unsigned char  if6_nh;       // next header
    unsigned char  if6_reserved; // reserved field
    unsigned short if6_off;      // offset, reserved, and flag
    unsigned int if6_id;         // identification
} ipv6_fraghdr;

// /**
// STRUCT      :: ip6Stat_struct
// DESCRIPTION :: QualNet typedefs struct ip6stat_struct to ip6Stat.
//                struct ip6stat_struct is statistic information structure.
// **/
typedef struct  ip6stat_struct
{
    unsigned int ip6_invalidHeader;
    unsigned int ip6s_noproto;      // unknown or unsupported protocol
    unsigned int ip6s_total;        // total packets received
    unsigned int ip6s_delivered;    // datagrams delivered to upper level
    unsigned int ip6s_forward;      // packets forwarded
    unsigned int ip6s_localout;     // total ipv6 packets generated here
    unsigned int ip6s_cantforward;  // packets rcvd for unreachable dest
    unsigned int ip6s_noroute;      // packets discarded due to no route
    unsigned int ip6s_outDiscarded; // packet output discarded.
    unsigned int ip6s_badvers;      // ipv6 version != 6
    unsigned int ip6s_badsource;    // packets rcvd from bad sources
    unsigned int ip6s_toobig;       // not forwarded because size > MTU
    unsigned int ip6s_toosmall;     // not enough data
    unsigned int ip6s_tooshort;     // packet too short
    unsigned int ip6s_fragmented;   // datagrams successfully fragmented
    unsigned int ip6s_ofragments;   // output fragments created
    unsigned int ip6s_fragments;    // fragments received
    unsigned int ip6s_fragdropped;  // fragments dropped
    unsigned int ip6s_fragtimeout;  // fragments timed out
    unsigned int ip6s_reassembled;  // total packets reassembled ok
    unsigned int ip6s_macpacketdrop;// MAC Packet Drop Notifications Received.
} ip6Stat;

// /**
// Function Pointer Type. Instance of this type is used to register
// Router Function.
// **/
typedef
void (*Ipv6RouterFunctionType)(
    Node *node,
    Message *msg,
    in6_addr destAddr,
    in6_addr previousHopAddress,
    BOOL *PacketWasRouted);

// Function Pointer Type. Instance of this type is used to register
// Router Function.
// **/
typedef
void (*Ipv6MacLayerStatusEventHandlerFunctionType)(
    Node* node,
    const Message* msg,
    const in6_addr nextHop,
    const int interfaceIndex);

// /**
// STRUCT      :: Ipv6MulticastForwardingTableRow
// DESCRIPTION :: Structure of an entity of multicast forwarding table.
// **/
typedef
struct
{
    in6_addr sourceAddress;
    unsigned char srcAddrPrefixLength;        // Not used
    in6_addr multicastGroupAddress;
    LinkedList *outInterfaceList;
} Ipv6MulticastForwardingTableRow;

// /**
// STRUCT      :: Ipv6MulticastForwardingTable
// DESCRIPTION :: Structure of multicast forwarding table
// **/
typedef
struct
{
    int size;
    int allocatedSize;
    Ipv6MulticastForwardingTableRow *row;
} Ipv6MulticastForwardingTable;

// /**
// STRUCT      :: Ipv6MulticastGroupEntry
// DESCRIPTION :: Structure for Multicast Group Entry
// **/
typedef struct
{
    in6_addr groupAddress;
    int memberCount;// Not used presently

    // Not used.
    int interfaceIndex;

} Ipv6MulticastGroupEntry;

// /**
// STRUCT      :: IPv6InterfaceInfo
// DESCRIPTION :: QualNet typedefs struct ipv6_interface_struct to
//                IPv6InterfaceInfo. struct ipv6_interface_struct is
//                interface information structure.
// **/
typedef struct ipv6_interface_struct
{
    // Different IP addresses
    in6_addr linkLocalAddr;
    in6_addr siteLocalAddr;
    in6_addr globalAddr;
    unsigned int prefixLen;

    // multicast address
    BOOL multicastEnabled;
    in6_addr multicastAddr;

    BOOL is6to4Enabled;
    char interfaceName[10];

    // Maximum transmission unit through this interface
    int mtu;

    // Routing related information

    Ipv6RouterFunctionType     routerFunction;

    NetworkRoutingProtocolType routingProtocolType;
    void*                      routingProtocol;

    Ipv6MacLayerStatusEventHandlerFunctionType
        macLayerStatusEventHandlerFunction;

    // IPv6 auto-config
    Ipv6AutoConfigInterfaceParam autoConfigParam;
} IPv6InterfaceInfo;

// /**
// STRUCT      :: messageBuffer
// DESCRIPTION :: QualNet typedefs struct messageBufferStruct to
//                messageBuffer. struct messageBufferStruct is the
//                buffer to hold messages when neighbour discovery
//                is not done.
// **/
struct messageBufferStruct
{
    Message* msg;
    in6_addr* dst;
    int inComing;
    rn_leaf* rn;
};
typedef struct messageBufferStruct messageBuffer;

// /**
// STRUCT      :: ip6q
// DESCRIPTION :: QualNet typedefs struct ip6q_struct to
//                ip6q. struct ip6q is a simple queue to hold
//                fragmented packets.
// **/
typedef struct frag_data
{
    Message* msg;
    struct frag_data* nextMsg;
}Ipv6FragData;



// /**
// STRUCT      :: Ipv6FragQueue
// DESCRIPTION :: Ipv6 fragment queue structure.
// **/
typedef struct ip6_frag_q_struct
{
    unsigned int ip6Frg_id;
    in6_addr ip6Frg_src;
    in6_addr ip6Frg_dst;
    unsigned int ip6Frg_nh;
    clocktype fragHoldTime;
    Ipv6FragData* firstMsg;
    Ipv6FragData* lastMsg;
    struct ip6_frag_q_struct* next;
}Ipv6FragQueue;

typedef struct ip6q_struct ip6q;

// /**
// STRUCT      :: FragmetedMsg
// DESCRIPTION :: QualNet typedefs struct fragmeted_msg_struct to
//                ip6q. struct fragmeted_msg_struct is a simple
//                fragmented packets msg hold structure.
// **/
struct fragmeted_msg_struct
{
    Message* msg;
    struct fragmeted_msg_struct* next;
};

typedef struct fragmeted_msg_struct FragmetedMsg;



// /**
// STRUCT      :: defaultRouterList
// DESCRIPTION :: default router list structure.
// **/
struct default_router_list
{
    in6_addr routerAddr;
    int outgoingInterface;
    MacHWAddress linkLayerAddr;
    struct default_router_list* next;
};
typedef struct default_router_list defaultRouterList;

// /**
// STRUCT      :: destination_route_struct
// DESCRIPTION :: QualNet typedefs struct destination_route_struct to
//                destinationRoute. struct destination_route_struct is
//                destination information structure of a node.
// **/
struct route_struct;

struct destination_route_struct
{
    struct route_struct* ro;
    unsigned char inUse;
    struct destination_route_struct* nextRoute;
};

typedef struct destination_route_struct DestinationRoute;



// /**
// STRUCT      :: DestinationCache
// DESCRIPTION :: Destination cache entry structure
// **/
typedef struct destination_cache_struct
{
    DestinationRoute* start;
    DestinationRoute* end;
} DestinationCache;

// Hash data structure.


// /**
// STRUCT      :: Ipv6HashData
// DESCRIPTION :: Ipv6 hash data structure.
// **/
struct ipv6_hash_data_struct
{
    void* data;
    struct ipv6_hash_data_struct* nextDataPtr;
};
typedef struct ipv6_hash_data_struct Ipv6HashData;



// /**
// STRUCT      :: Ipv6HashBlockData
// DESCRIPTION :: Ipv6 hash block-data structure.
// **/
typedef struct ipv6_hash_blockdata_struct
{
    Ipv6HashData* firstDataPtr;
    Ipv6HashData* lastDataPtr;
    in6_addr ipAddr;
}Ipv6HashBlockData;



// /**
// STRUCT      :: Ipv6HashBlock
// DESCRIPTION :: Ipv6 hash block structure.
// **/
struct ipv6_hash_block_struct
{
    unsigned int totalDataElements;
    Ipv6HashBlockData* blockData;
    struct ipv6_hash_block_struct* nextBlock;
};
typedef struct ipv6_hash_block_struct Ipv6HashBlock;



// /**
// STRUCT      :: Ipv6HashTable
// DESCRIPTION :: Ipv6 hash table structure
// **/
typedef struct ipv6_hash_table_struct
{
    Ipv6HashBlock* firstBlock;
}Ipv6HashTable;

// /**
// STRUCT      :: IPv6Data
// DESCRIPTION :: QualNet typedefs struct ipv6_data_struct to
//                IPv6Data. struct ipv6_data_struct is
//                ipv6 information structure of a node.
// **/
typedef struct ipv6_data_struct
{

    // Route table related Informations
    int max_keylen;
    radix_node_head* rt_tables;
    unsigned int noOfPrefix;
    struct prefixListStruct* prefixHead;
    struct prefixListStruct* prefixTail;
    struct default_router_list* defaultRouter;
    // Routes not in table but not freed
    int rttrash;

    // NDP Cache
    radix_node_head* ndp_cache;

    // Hash for reverse NDP cache
    rn_rev_ndplookup* reverse_ndp_cache[MAX_REVLOOKUP_SIZE];

    // Destination cache.
    DestinationCache destination_cache;

    // Packet hold Structure before neighbor discovery.
    Ipv6HashTable* hashTable;

    // Multicast
    LinkedList* multicastGroupList;
    Ipv6MulticastForwardingTable multicastForwardingTable;

    // Fragmentation List.
    Ipv6FragQueue* fragmentListFirst;
    unsigned int ip6_id;

    char* addmask_key;
    char* rn_zeros;
    char* rn_ones;

    RandomSeed jitterSeed;

    // Ipv6 Statistics
    ip6Stat ip6_stat;

    // icmp6 related data structure pointer.
    struct network_icmpv6_struct* icmp6;

    // Back Pointer to Ip data for reverse traversal.
    NetworkDataIp* ip;

    in6_addr broadcastAddr;

    in6_addr loopbackAddr;
//Flag for default route entry
    BOOL defaultRouteFlag;
// For Dymo
    BOOL isManetGateway;
    UInt8 manetPrefixlength;
    Address manetPrefixAddr;
// End for Dymo
// For frag hold time
    clocktype ipFragHoldTime;
// End for frag hold time
    RandomDistribution<clocktype> randomNum;

    // Ipv6 auto-config
    Ipv6AutoConfigParam autoConfigParameters;
} IPv6Data;

// /**
// STRUCT      :: ndpNadvEvent
// DESCRIPTION :: QualNet typedefs struct ndp_event_struct to
//                IPv6Data. struct ndp_event_struct is
//                neighbor advertisement information structure.
// **/
typedef struct ndp_event_struct
{
    rn_leaf* ln;
}NadvEvent;

// /**
// MACRO    :: NDP_DELAY
// DESCRIPTION :: NDP neighbor advertisement delay.
// **/
#define NDP_DELAY 1 * MICRO_SECOND

// /**
// MACRO    :: IPV6JITTER_RANGE
// DESCRIPTION :: IPv6 jitter timer.
// **/
#define IPV6JITTER_RANGE   (1000 * MILLI_SECOND)


// /**
// MACRO    :: IPV6_SET_CLASS(hdr, priority)
// DESCRIPTION :: Sets the flow class.
// **/
//#define IPV6_SET_CLASS(hdr, priority)       ((hdr)->ip6_tos = priority)

// /**
// MACRO    :: IPV6_GET_CLASS(hdr)
// DESCRIPTION :: Gets the flow class.
// **/
//#define IPV6_GET_CLASS(hdr)   ((hdr)->ip6_class)

// /**
// CONSTANT    :: IP6ANY_HOST_PROXY : 1
// DESCRIPTION :: proxy (host)
// **/
#define IP6ANY_HOST_PROXY   1       // proxy (host)


// /**
// CONSTANT    :: IP6ANY_ROUTER_PROXY : 2
// DESCRIPTION :: proxy (router)
// **/
#define IP6ANY_ROUTER_PROXY 2       // proxy (router)


// /**
// API                 :: in6_isanycast
// LAYER               :: Network
// PURPOSE             :: Checks whether the address is anycast address
//                        of the node.
// PARAMETERS          ::
// + node               : Node*      : Pointer to node structure.
// + addr               : in6_addr   : ipv6 address.
// RETURN              :: int :
// **/
int
in6_isanycast(Node* node, in6_addr* addr);

//----------------------------------------------------------
// IPv6 header
//----------------------------------------------------------

// /**
// API                 :: Ipv6AddIpv6Header
// LAYER               :: Network
// PURPOSE             :: Add an IPv6 packet header to a message.
//                        Just calls AddIpHeader.
// PARAMETERS          ::
// + node               : Node*         : Pointer to node.
// + msg                : Message*      : Pointer to message.
// + srcaddr           : in6_addr      : Source IPv6 address.
// + dst_addr           : in6_addr      : Destination IPv6 address.
// + priority           : TosType : Current type of service
//                        (values are not standard for "IPv6 type of
//                         service field" but has correct function)
// + protocol           : unsigned char : IPv6 protocol number.
// + hlim               : unsigned      : Hop limit.
// RETURN              :: None
// **/
void
Ipv6AddIpv6Header(
    Node *node,
    Message *msg,
    int payloadLen,
    in6_addr src_addr,
    in6_addr dst_addr,
    TosType priority,
    unsigned char protocol,
    unsigned hlim);




// /**
// API                 :: Ipv6AddFragmentHeader
// LAYER               :: Network
// PURPOSE             :: Adds fragment header
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to Message
// + nextHeader         : unsigned char : nextHeader
// + offset             : unsigned short : offset
// + id                 : unsigned int : id
// RETURN              :: None
// **/
void
Ipv6AddFragmentHeader(
    Node *node,
    Message *msg,
    unsigned char nextHeader,
    unsigned short offset,
    unsigned int id);



// /**
// API                 :: Ipv6RemoveIpv6Header
// LAYER               :: Network
// PURPOSE             :: Removes Ipv6 header
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + sourceAddress      : Address* : Poineter Source address
// + destinationAddress : Address* destinationAddress : Destination address
// + priority           : TosType *priority : Priority
// + protocol           : unsigned char *protocol : protocol
// + hLim               : unsigned *hLim : hLim
// RETURN              :: None
// **/
void
Ipv6RemoveIpv6Header(
    Node *node,
    Message *msg,
    Address* sourceAddress,
    Address* destinationAddress,
    TosType *priority,
    unsigned char *protocol,
    unsigned *hLim);


// /**
// API                 :: Ipv6PreInit
// LAYER               :: Network
// PURPOSE             :: IPv6 Pre Initialization.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// RETURN              :: None
// **/
void
Ipv6PreInit(Node* node);

// /**
// API                 :: IPv6Init
// LAYER               :: Network
// PURPOSE             :: IPv6 Initialization.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + nodeInput          : const NodeInput* : Node input.
// RETURN              :: None
// **/
void
IPv6Init(Node *node, const NodeInput* nodeInput);

// /**
// API                 :: Ipv6IsMyPacket
// LAYER               :: Network
// PURPOSE             :: Checks whether the packet is the nodes packet.
//                        if the packet is of the node then returns TRUE,
//                        otherwise FALSE.
// PARAMETERS          ::
// + node               : Node*      : Pointer to node structure.
// + dst_addr           : in6_addr*  : ipv6 packet destination address.
// RETURN              :: BOOL :
// **/
BOOL Ipv6IsMyPacket(Node* node, in6_addr* dst_addr);

// /**
// API                 :: Ipv6IsAddressInNetwork
// LAYER               :: Network
// PURPOSE             :: Checks whether the address is in the same network.
//                      : if in the same network then returns TRUE,
//                        otherwise FALSE.
// PARAMETERS          ::
// + globalAddr         : const in6_addr* : Pointer to ipv6 address.
// + tla                : unsigned int    : Top level ipv6 address.
// + vla                : unsigned int    : Next level ipv6 address.
// + sla                : unsigned int    : Site local ipv6 address.
// RETURN              :: BOOL :
// **/
BOOL
Ipv6IsAddressInNetwork(
    const in6_addr* globalAddr,
    unsigned int tla,
    unsigned int nla,
    unsigned int sla);


// /**
// API                 :: Ipv6GetLinkLayerAddress
// LAYER               :: Network
// PURPOSE             :: Returns 32 bit link layer address of the interface.
// PARAMETERS          ::
// + node               : Node*           : Pointer to node structure.
// + interfaceId        : int             : Interface Id.
// + ll_addr_str        : char*           : Pointer to character link layer
//                                          address.
// RETURN              :: NodeAddress :
// **/
MacHWAddress
Ipv6GetLinkLayerAddress(
    Node* node,
    int interfaceId);

// /**
// API                 :: Ipv6AddNewInterface
// LAYER               :: Network
// PURPOSE             :: Adds an ipv6 interface to the node.
// PARAMETERS          ::
// + node               : Node*           : Pointer to node structure.
// + globalAddr         : in6_addr*       : Global ipv6 address pointer.
// + tla                : unsigned int    : Top level id.
// + nla                : unsigned int    : Next level id.
// + sla                : unsigned int    : Site level id.
// + newinterfaceIndex  : int*            : Pointer to new interface index.
// + nodeInput          : const NodeInput*: Node Input.
// RETURN              :: None
// **/
void Ipv6AddNewInterface(
    Node* node,
    in6_addr* globalAddr,
    in6_addr* subnetAddr,
    unsigned int subnetPrefixLen,
    int* newinterfaceIndex,
    const NodeInput* nodeInput,
    unsigned short siteCounter,
    BOOL isNewInterface);


// /**
// API                 :: Ipv6IsForwardingEnabled
// LAYER               :: Network
// PURPOSE             :: Checks whether the node is forwarding enabled.
// PARAMETERS          ::
// + ipv6               : IPv6Data*   : Pointer to ipv6 data structure.
// RETURN              :: BOOL :
// **/
BOOL Ipv6IsForwardingEnabled(IPv6Data* ipv6);

// /**
// FUNCTION   :: Ipv6Layer
// LAYER      :: Network
// PURPOSE    :: Handle IPv6 layer events, incoming messages and messages
//               sent to itself (timers, etc.).
// PARAMETERS ::
// + node      : Node*    : Pointer to node.
// + msg       : Message* : Pointer to message.
// RETURN     :: None
// **/
void
Ipv6Layer(Node* node, Message* msg);

// /**
// FUNCTION   :: Ipv6Finalize
// LAYER      :: Network
// PURPOSE    :: Finalize function for the IPv6 model.  Finalize functions
//               for all network-layer IPv6 protocols are called here.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// RETURN     :: None
// **/
void
Ipv6Finalize(Node* node);

// /**
// FUNCTION   :: Ipv6GetMTU
// LAYER      :: Network
// PURPOSE    :: Returns the maximum transmission unit of the interface.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + interfaceId : int : Interface Id.
// RETURN     :: int
// **/
int Ipv6GetMTU(Node* node, int interfaceId);

// /**
// FUNCTION   :: Ipv6GetInterfaceIndexFromAddress
// LAYER      :: Network
// PURPOSE    :: Returns interface index of the specified address.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + dst       : in6_addr* : IPv6 address.
// RETURN     :: int
// **/
int Ipv6GetInterfaceIndexFromAddress(Node* node, in6_addr* dst);

//-----------------------------------------------------------------------//
// A wrapper function for general use
//----------------------------------------------------------------------//

// /**
// API        :: Ipv6CpuQueueInsert
// LAYER      :: Network
// PURPOSE    :: Calls the cpu packet scheduler for an interface to retrieve
//               an IPv6 packet from a queue associated with the interface.
//               The dequeued packet, since it's already been routed,
//               has an associated next-hop IPv6 address.  The packet's
//               priority value is also returned.
// PARAMETERS ::
// + node               : Node*    : Pointer to node.
// + msg                : Message* : Pointer to message with IPv6 packet.
// + nextHopAddress     : NodeAddress : Packet's next hop link layer address.
// + destinationAddress : in6_addr    : Packet's destination address.
// + outgoingInterface  : int         : Used to determine where packet
//                                      should go after passing through
//                                      the backplane.
// + networkType        : int   : Type of network packet is using (IPv6,
//                                Link-16, ...)
// + queueIsFull        : BOOL* : Storage for boolean indicator.
//                                If TRUE, packet was not queued because
//                                scheduler reported queue was
//                                (or queues were) full.
// RETURN     :: None
// **/
void
Ipv6CpuQueueInsert(
    Node *node,
    Message *msg,
    NodeAddress nextHopLinkAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL *queueIsFull);

// /**
// API        :: Ipv6InputQueueInsert
// LAYER      :: Network
// PURPOSE    :: Calls input packet scheduler for an interface to retrieve
//               an IP packet from a queue associated with the interface.
//               The dequeued packet, since it's already been routed,
//               has an associated next-hop IPv6 address.  The packet's
//               priority value is also returned.
// PARAMETERS ::
// + node               : Node*    : Pointer to node.
// + incomingInterface  : int      : interface of input queue.
// + msg                : Message* : Pointer to message with IPv6 packet.
// + nextHopAddress     : NodeAddress : Packet's next hop link layer address.
// + destinationAddress : in6_addr    : Packet's destination address.
// + outgoingInterface  : int         : Used to determine where packet
//                                      should go after passing through
//                                      the backplane.
// + networkType        : int   : Type of network packet is using (IPv6,
//                                Link-16, ...)
// + queueIsFull        : BOOL* : Storage for boolean indicator.
//                                If TRUE, packet was not queued because
//                                scheduler reported queue was
//                                (or queues were) full.
// RETURN     :: None
// **/
void
Ipv6InputQueueInsert(
    Node* node,
    int incomingInterface,
    Message* msg,
    NodeAddress nextHopLinkAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    int networkType,
    BOOL* queueIsFull);

// /**
// API        :: Ipv6OutputQueueInsert
// LAYER      :: Network
// PURPOSE    :: Calls output packet scheduler for an interface to retrieve
//               an IP packet from a queue associated with the interface.
//               The dequeued packet, since it's already been routed,
//               has an associated next-hop IPv6 address.  The packet's
//               priority value is also returned.
//               Called by QueueUpIpFragmentForMacLayer().
// PARAMETERS ::
// + node               : Node*    : Pointer to node.
// + interfaceIndex     : int      : interface of input queue.
// + msg                : Message* : Pointer to message with IPv6 packet.
// + nextHopAddress     : NodeAddress : Packet's next link layer hop address.
// + destinationAddress : NodeAddress : Packet's destination address.
// + networkType        : int   : Type of network packet is using (IPv6,
//                                Link-16, ...)
// + queueIsFull        : BOOL* : Storage for boolean indicator.
//                                If TRUE, packet was not queued because
//                                scheduler reported queue was
//                                (or queues were) full.
// RETURN     :: None
// **/
void
Ipv6OutputQueueInsert(
    Node* node,
    int outgoingInterface,
    Message* msg,
    MacHWAddress& nextHopAddress,
    in6_addr destinationAddress,
    int networkType,
    BOOL* queueIsFull);

// /**
// API        :: QueueUpIpv6FragmentForMacLayer
// LAYER      :: Network
// PURPOSE    :: Calls output packet scheduler for an interface to retrieve
//               an IP packet from a queue associated with the interface.
//               The dequeued packet, since it's already been routed,
//               has an associated next-hop IPv6 address.  The packet's
//               priority value is also returned.
//               Called by QueueUpIpFragmentForMacLayer().
// PARAMETERS ::
// + node               : Node*    : Pointer to node.
// + interfaceIndex     : int      : interface of input queue.
// + msg                : Message* : Pointer to message with IPv6 packet.
// + nextHopAddress     : NodeAddress : Packet's next hop address.
// + destinationAddress : NodeAddress : Packet's destination address.
// + networkType        : int   : Type of network packet is using (IPv6,
//                                Link-16, ...)
// + queueIsFull        : BOOL* : Storage for boolean indicator.
//                                If TRUE, packet was not queued because
//                                scheduler reported queue was
//                                (or queues were) full.
// RETURN     :: None
// **/
void
QueueUpIpv6FragmentForMacLayer(
    Node *node,
    Message *msg,
    int interfaceIndex,
    //NodeAddress nextHop);
    MacHWAddress& nextHop,
    int incomingInterface);

// /**
// API        :: Ipv6SendPacketOnInterface
// LAYER      :: Network
// PURPOSE    :: This function is called once the outgoing interface
//               index and next hop address to which to route an IPv6
//               packet are known.  This queues an IPv6 packet for delivery
//               to the MAC layer.  This functions calls
//               QueueUpIpFragmentForMacLayer().
//               This function is used to initiate fragmentation if
//               required,before calling the next function.
// PARAMETERS          ::
// + node               : Node*       : Pointer to node.
// + msg                : Message*    : Pointer to message with ip packet.
// + incommingInterface : int         : Index of incoming interface.
// + outgoingInterface  : int         : Index of outgoing interface.
// + nextHop            : NodeAddress : Next hop link layer address.
// RETURN     :: None
// **/
void
Ipv6SendPacketOnInterface(
    Node* node,
    Message* msg,
    int incomingInterface,
    int outgoingInterface,
    MacHWAddress& nextHopLinkAddr);

// /**
// API        :: Ipv6SendOnBackplane
// LAYER      :: Network
// PURPOSE    :: This function is called when the packet delivered through
//               backplane delay.
//               required,before calling the next function.
// PARAMETERS          ::
// + node               : Node*       : Pointer to node.
// + msg                : Message*    : Pointer to message with ip packet.
// + incommingInterface : int         : Index of incomming interface.
// + outgoingInterface  : int         : Index of outgoing interface.
// + hopAddr            : NodeAddress : Next hop link layer address.
// RETURN     :: None
// **/
void Ipv6SendOnBackplane(
     Node* node,
     Message* msg,
     int incomingInterface,
     int outgoingInterface,
     MacHWAddress& hopAddr,
     optionList* opts);

// /**
// API        :: Ipv6SendRawMessage
// LAYER      :: Network
// PURPOSE    :: Called by NetworkIpReceivePacketFromTransportLayer() to
//               send to send UDP datagrams using IPv6.
//               This function adds an IPv6 header and calls
//               RoutePacketAndSendToMac().
// PARAMETERS ::
// + node               : Node*        : Pointer to node.
// + msg                : Message*     : Pointer to message with payload data
//                                       for IP packet.(IP header needs to
//                                       be added)
// + sourceAddress      : in6_addr     : Source IPv6 address.
//                        If sourceAddress is ANY_IP, lets IPv6 assign the
//                        source  address (depends on the route).
// + destinationAddress : in6_addr     : Destination IPv6 address.
// + outgoingInterface  : int          : outgoing interface to use to
//                                       transmit packet.
// + priority           : TosType : Priority of packet.
// + protocol           : unsigned char : IPv6 protocol number.
// + ttl                : unsigned      : Time to live.
//                                     See AddIpHeader() for special values.
// RETURN              :: None
// **/
void
Ipv6SendRawMessage(
    Node* node,
    Message* msg,
    in6_addr sourceAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl = IPDEFTTL);

// /**
// API        :: Ipv6SendToUdp
// LAYER      :: Network
// PURPOSE    :: Sends a UDP packet to UDP in the transport layer.
//               The source IPv6 address, destination IPv6 address, and
//               priority of the packet are also sent.
// PARAMETERS ::
// + node                   : Node*    : Pointer to node.
// + msg                    : Message* : Pointer to message with UDP packet.
// + priority               : TosType : Priority of UDP
//                                                          packet.
// + sourceAddress          : Address : Source IP address info.
// + destinationAddress     : Address : Destination IP address info.
// + incomingInterfaceIndex : int        :interface that received the packet
// RETURN     :: None
// **/
void
Ipv6SendToUdp(
    Node* node,
    Message* msg,
    TosType priority,
    Address sourceAddress,
    Address destinationAddress,
    int incomingInterfaceIndex);

// /**
// API        :: Ipv6SendToTCP
// LAYER      :: Network
// PURPOSE    :: Sends a TCP packet to UDP in the transport layer.
//               The source IPv6 address, destination IPv6 address, and
//               priority of the packet are also sent.
// PARAMETERS ::
// + node                   : Node*    : Pointer to node.
// + msg                    : Message* : Pointer to message with UDP packet.
// + priority               : TosType : Priority of TCP
//                                                          packet.
// + sourceAddress          : Address : Source IP address info.
// + destinationAddress     : Address : Destination IP address info.
// + incomingInterfaceIndex : int        :interface that received the packet
// RETURN     :: None
// **/
void
Ipv6SendToTCP(
    Node* node,
    Message* msg,
    TosType priority,
    Address sourceAddress,
    Address destinationAddress,
    int incomingInterfaceIndex);

// /**
// API        :: Ipv6ReceivePacketFromMacLayer
// LAYER      :: Network
// PURPOSE    :: IPv6 received IPv6 packet from MAC layer.  Determine whether
//               the packet is to be delivered to this node, or needs to
//               be forwarded.
// PARAMETERS ::
// + node              : Node*        : Pointer to node.
// + msg               : Message*     : Pointer to message with ip packet.
// + previousHopNodeId : NodeAddress  : nodeId of the previous hop.
// + interfaceIndex    : int : Index of interface on which packet arrived.
// RETURN     :: None
// **/
void
Ipv6ReceivePacketFromMacLayer(
    Node* node,
    Message* msg,
    MacHWAddress* lastHopAddress,
    int interfaceIndex);

//------------------------------------------------------------------------//
// Hold Buffer Functions.
//------------------------------------------------------------------------//

// /**
// API        :: Ipv6AddMessageInBuffer
// LAYER      :: Network
// PURPOSE    :: Adds an ipv6 packet in message in the hold buffer
// PARAMETERS ::
// + node              : Node*        : Pointer to node structure.
// + msg               : Message*     : Pointer to message with ip packet.
// + nextHopAddr       : in6_addr*    : Source IPv6 address.
// + inCommingInterface: int          : Incoming interface
// RETURN     :: BOOL
// **/
BOOL
Ipv6AddMessageInBuffer(
    Node* node,
    Message* msg,
    in6_addr* nextHopAddr,
    int inComingInterface,
    rn_leaf* rn);


// /**
// API        :: Ipv6DeleteMessageInBuffer
// LAYER      :: Network
// PURPOSE    :: Delets an ipv6 packet in the hold buffer
// PARAMETERS ::
// + node              : Node*        : Pointer to node structure.
// + mBuf              : messageBuffer* : Pointer to messageBuffer tail.
// RETURN     :: BOOL
// **/
BOOL
Ipv6DeleteMessageInBuffer(
        Node* node,
        in6_addr nextHopAddr,
        rn_leaf* ln);

// /**
// API        :: Ipv6DropMessageFromBuffer
// LAYER      :: Network
// PURPOSE    :: Drops an ipv6 packet from the hold buffer
// PARAMETERS ::
// + node              : Node*        : Pointer to node structure.
// + mBuf              : messageBuffer* : Pointer to messageBuffer tail.
// RETURN     :: void
// **/
BOOL
Ipv6DropMessageFromBuffer(
        Node* node,
        in6_addr nextHopAddr,
        rn_leaf* ln);


//-----------------------------------------------------------------------//
// Utility Functions
//------------------------------------------------------------------------//

// /**
// FUNCTION   :: Ipv6GetAddressTypeFromString
// LAYER      :: Network
// PURPOSE    :: Returns network type from string ip address.
// PARAMETERS ::
// + interfaceAddr  : char* : Character Pointer to ip address.
// RETURN     :: NetworkType
// **/
NetworkType
Ipv6GetAddressTypeFromString(char* interfaceAddr);

// /**
// FUNCTION   :: Ipv6GetInterfaceMulticastAddress
// LAYER      :: Network
// PURPOSE    :: Get multicast address of this interface
// PARAMETERS ::
// + node      : Node* : Node pointer
// + interfaceIndex : int : interface for which multicast is required
// RETURN     :: IPv6 multicast address
// **/
in6_addr
Ipv6GetInterfaceMulticastAddress(Node* node, int interfaceIndex);

// /**
// FUNCTION   :: Ipv6SolicitationMulticastAddress
// LAYER      :: Network
// PURPOSE    :: Copies multicast solicitation address.
// PARAMETERS ::
// + dst_addr  : in6_addr* : ipv6 address pointer.
// + target    : in6_addr* : ipv6 multicast address pointer.
// RETURN     :: None
// **/
void
Ipv6SolicitationMulticastAddress(
    in6_addr* dst_addr,
    in6_addr* target);

// /**
// FUNCTION             : Ipv6AllRoutersMulticastAddress
// PURPOSE             :: Function to assign all routers multicast address.
// PARAMETERS          ::
// + dst                : in6_addr* dst     : IPv6 address pointer,
//                              output destination multicast address.
// RETURN               : None
// **/

void
Ipv6AllRoutersMulticastAddress(
       in6_addr* dst);

// /**
// FUNCTION   :: IPv6GetLinkLocalAddress
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 link local address of the interface in
//               output parameter addr.
// PARAMETERS ::
// + node      :           : Pointer to the node structure.
// + interface : int       : interface Index.
// + addr      : in6_addr* : ipv6 address pointer.
// RETURN     :: None
// **/
void
Ipv6GetLinkLocalAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr);

// /**
// FUNCTION   :: IPv6GetSiteLocalAddress
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 site local address of the interface in
//               output parameter addr.
// PARAMETERS ::
// + node      :           : Pointer to the node structure.
// + interface : int       : interface Index.
// + addr      : in6_addr* : ipv6 address pointer.
// RETURN     :: None
// **/
void
Ipv6GetSiteLocalAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr);

// /**
// FUNCTION   :: IPv6GetSiteLocalAddress
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 global agreeable address of the interface in
//               output parameter addr.
// PARAMETERS ::
// + node      :           : Pointer to the node structure.
// + interface : int       : interface Index.
// + addr      : in6_addr* : ipv6 address pointer.
// RETURN     :: None
// **/
void
Ipv6GetGlobalAggrAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr);

// /**
// FUNCTION   :: Ipv6GetPrefix
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 prefix from address.
// PARAMETERS ::
// + addr      : in6_addr* : ipv6 address pointer.
// + prefix    : in6_addr* : ipv6 prefix pointer.
// RETURN     :: None
// **/
void
Ipv6GetPrefix(
    const in6_addr* addr,
    in6_addr* prefix,
    unsigned int length);

// /**
// FUNCTION   :: Ipv6GetPrefixFromInterfaceIndex
// LAYER      :: Network
// PURPOSE    :: Gets ipv6 prefix from address.
// PARAMETERS ::
// + node      : Node* : Node pointer
// + interfaceIndex : int : interface for which multicast is required
// RETURN     :: Prefix for this interface
// **/
in6_addr
Ipv6GetPrefixFromInterfaceIndex(
    Node* node,
    int interfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6ConvertStrLinkLayerToMacHWAddress
// PURPOSE             :: Converts from character formatted link layer address
//                        to NodeAddress format.
// PARAMETERS ::
// + llAddrStr          : char* llAddrStr : Link Layer Address String
// RETURN               : MacHWAddress: returns mac hardware address.
//---------------------------------------------------------------------------
MacHWAddress Ipv6ConvertStrLinkLayerToMacHWAddress(
    Node* node,
    int interfaceId,
    unsigned char* llAddrStr);

// /**
// FUNCTION            :: Ipv6OutputQueueIsEmpty
// LAYER               :: Network
// PURPOSE             :: Check weather output queue is empty
// PARAMETERS          ::
// + node               : Node *node : Pointer to Node
// + interfaceIndex     : int : interfaceIndex
// RETURN              :: BOOL
// **/
BOOL
Ipv6OutputQueueIsEmpty(Node *node, int interfaceIndex);


// /**
// FUNCTION            :: Ipv6RoutingStaticInit
// LAYER               :: Network
// PURPOSE             :: Ipv6 Static routing initialization function.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + nodeInput          : const NodeInput : *nodeInput
// + type               : NetworkRoutingProtocolType : type
// RETURN              :: None
// **/
void
Ipv6RoutingStaticInit(
    Node *node,
    const NodeInput *nodeInput,
    NetworkRoutingProtocolType type);


// /**
// FUNCTION            :: Ipv6RoutingStaticEntry
// LAYER               :: Network
// PURPOSE             :: Static routing route entry function
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + currentLine        : char currentLine[]: Static entry's current line.
// RETURN              :: None
// **/
void
Ipv6RoutingStaticEntry(
    Node *node,
    char currentLine[]);



// /**
// FUNCTION            :: Ipv6AddDestination
// LAYER               :: Network
// PURPOSE             :: Adds destination in the destination cache.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + ro                 : route* ro: Pointer to destination route.
// RETURN              :: None
// **/
void
Ipv6AddDestination(
   Node* node,
   struct route_struct* ro);



// /**
// FUNCTION            :: Ipv6DeleteDestination
// LAYER               :: Network
// PURPOSE             :: Deletes destination from the destination cache.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN              :: None
// **/
void
Ipv6DeleteDestination(Node* node);



// /**
// FUNCTION            :: Ipv6CheckForValidPacket
// LAYER               :: Network
// PURPOSE             :: Checks the packet's validity
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + scheduler          : SchedulerType* scheduler: pointer to scheduler
// + pIndex             : unsigned int* pIndex: packet index
// RETURN              :: int
// **/
int
Ipv6CheckForValidPacket(
    Node* node,
    Scheduler* scheduler,
    unsigned int* pIndex);



// /**
// FUNCTION            :: Ipv6NdpProcessing
// LAYER               :: Network
// PURPOSE             :: Ipv6 Destination cache and neighbor cache
//                      :   processing function
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN              :: None
// **/
void
Ipv6NdpProcessing(Node* node);

void ndsol6_retry(Node* node, Message* msg);

// /**
// FUNCTION            :: Ipv6UpdateForwardingTable
// LAYER               :: Network
// PURPOSE             :: Updates Ipv6 Forwarding Table
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + destPrefix         : in6_addr destPrefix : IPv6 destination address
// + nextHopPrefix      : in6_addr nextHopPrefix: IPv6 next hop address for this destination
// + interfaceIndex     : int : interfaceIndex
// + metric             : int metric : hop count between source and destination
// RETURN              :: None
// **/

void Ipv6UpdateForwardingTable(
    Node* node,
    in6_addr destPrefix,
    unsigned int destPrefixLen,
    in6_addr nextHopPrefix,
    int interfaceIndex,
    int metric,
    NetworkRoutingProtocolType type);

// /**
// FUNCTION            :: Ipv6EmptyForwardingTable
// LAYER               :: Network
// PURPOSE             :: Empties Ipv6 Forwarding Table for a particular
//                        routing protocol entry
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + type               : NetworkRoutingProtocolType type : Routing protocol type
// RETURN              :: None
// **/
void Ipv6EmptyForwardingTable(Node *node,
                              NetworkRoutingProtocolType type);

// /**
// FUNCTION            :: Ipv6PrintForwardingTable
// LAYER               :: Network
// PURPOSE             :: Prints the forwarding table.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// RETURN              :: None
// **/
void Ipv6PrintForwardingTable(Node *node);


// FUNCTION            :: Ipv6SetRouterFunction
// LAYER               :: Network
// PURPOSE             :: Sets the router function.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + routerFunctionPtr  : Ipv6RouterFunctionType routerFunctionPtr: router
//                      : function pointer.
// + interfaceIndex     : int interfaceIndex : Interface index
// RETURN              :: None
// **/
void Ipv6SetRouterFunction(Node *node,
                           Ipv6RouterFunctionType routerFunctionPtr,
                           int interfaceIndex);

// FUNCTION            :: Ipv6GetRoutingProtocolType
// LAYER               :: Network
// PURPOSE             :: Return The routing Protocol Type.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceIndex     : int interfaceIndex : Interface index
// RETURN              :: Routing Protocol Type
// **/
NetworkRoutingProtocolType Ipv6GetRoutingProtocolType(Node *node,
                                                int interfaceIndex);

// /**
// FUNCTION     :: Ipv6InterfaceIndexFromSubnetAddress
// LAYER        :: Network
// PURPOSE      :: Get the interface index from an IPv6 subnet address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + address    :  in6_addr*     : Subnet Address
// RETURN       :: Interface index associated with specified subnet address.
// **/
int Ipv6InterfaceIndexFromSubnetAddress(
    Node *node,
    in6_addr address);

// /**
// FUNCTION     :: Ipv6GetInterfaceAndNextHopFromForwardingTable
// LAYER        :: Network
// PURPOSE      :: Do a lookup on the routing table with a destination IPv6
//                 address to obtain an outgoing interface and a next hop
//                 Ipv6 address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// + interfaceIndex   :  int*    : Pointer to interface index
// + nextHopAddr   :  in6_addr*  : Next Hop Addr for destination.
// RETURN       :: void : NULL.
// **/
void Ipv6GetInterfaceAndNextHopFromForwardingTable(
    Node* node,
    in6_addr destAddr,
    int* interfaceIndex,
    in6_addr* nextHopAddress);

// /**
// FUNCTION     :: Ipv6GetInterfaceIndexForDestAddress
// LAYER        :: Network
// PURPOSE      :: Get interface for the destination address.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: interface index associated with destination.
// **/
int Ipv6GetInterfaceIndexForDestAddress(
    Node* node,
    in6_addr destAddr);

// /**
// FUNCTION     :: Ipv6GetMetricForDestAddress
// LAYER        :: Network
// PURPOSE      :: Get the cost metric for a destination from the
//                 forwarding table.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: interface index associated with destination.
// **/
unsigned Ipv6GetMetricForDestAddress(
    Node* node,
    in6_addr destAddr);

// /**
// FUNCTION     :: Ipv6IpGetInterfaceIndexForNextHop
// LAYER        :: Network
// PURPOSE      :: This function looks at the network address of each of a
//                 node's network interfaces. When nextHopAddress is
//                 matched to a network, the interface index corresponding
//                 to the network is returned.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + destAddr   :  in6_addr      : Destination Address
// RETURN       :: Interface index associated with destination if found,
//                 -1 otherwise.
// **/
int Ipv6IpGetInterfaceIndexForNextHop(
    Node *node,
    in6_addr address);

// /**
// API        :: Ipv6GetRouterFunction
// LAYER      :: Network
// PURPOSE    :: Get the router function pointer.
// PARAMETERS ::
// + node           : Node* : Pointer to node.
// + interfaceIndex : int   : interface associated with router function
// RETURN     :: Ipv6RouterFunctionType : router function pointer.
// **/
Ipv6RouterFunctionType Ipv6GetRouterFunction(
    Node* node,
    int interfaceIndex);

// /**
// FUNCTION     :: Ipv6SendPacketToMacLayer
// LAYER        :: Network
// PURPOSE      :: Used if IPv6 next hop address and outgoing interface is
//                 known.
// PARAMETERS   ::
// + node       :  Node* node    : Pointer to node
// + msg        :  Message*      : Pointer to message
// + destAddr   :  in6_addr      : Destination Address
// + nextHopAddr   :  in6_addr*  : Next Hop Addr for destination.
// + interfaceIndex   :  int*    : Pointer to interface index
// RETURN       :: void : NULL.
// **/
void Ipv6SendPacketToMacLayer(
    Node* node,
    Message* msg,
    in6_addr destAddr,
    in6_addr nextHopAddr,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION             : Ipv6SendRawMessageToMac
// PURPOSE             :: Ipv6 packet sending function.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + msg                : Message *msg : Pointer to message
// + sourceAddress      : in6_addr sourceAddress:
//                          IPv6 source address of packet
// + destinationAddress : in6_addr destinationAddress:
//                          IPv6 destination address of packet.
// + outgoingInterface  : int outgoingInterface
// + priority           : TosType priority: Type of service of packet.
// + protocol           : unsigned char protocol: Next protocol number.
// + ttl                : unsigned ttl: Time to live.
// RETURN               : None
//---------------------------------------------------------------------------
void
Ipv6SendRawMessageToMac(
    Node *node,
    Message *msg,
    in6_addr sourceAddress,
    in6_addr destinationAddress,
    int outgoingInterface,
    TosType priority,
    unsigned char protocol,
    unsigned ttl);

// /**
// API              :: Ipv6JoinMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Join a multicast group.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to join.
// + delay          :  clocktype    : delay.
// RETURN           :: void  : NULL.
// **/
void Ipv6JoinMulticastGroup(
    Node* node,
    in6_addr mcastAddr,
    clocktype delay);

// /**
// API              :: Ipv6AddToMulticastGroupList
// LAYER            :: Network
// PURPOSE          :: Add group to multicast group list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + groupAddress   :  in6_addr     : Group to add to multicast group list.
// RETURN           :: void  : NULL.
// **/
void Ipv6AddToMulticastGroupList(Node* node, in6_addr groupAddress);

// /**
// API              :: Ipv6LeaveMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Leave a multicast group.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to leave.
// RETURN           :: void  : NULL.
// **/
void Ipv6LeaveMulticastGroup(
    Node* node,
    in6_addr mcastAddr,
    clocktype delay);

// /**
// API              :: Ipv6RemoveFromMulticastGroupList
// LAYER            :: Network
// PURPOSE          :: Remove group from multicast group list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + groupAddress   :  in6_addr     : Group to be removed from multicast
//                                    group list.
// RETURN           :: void  : NULL.
// **/
void Ipv6RemoveFromMulticastGroupList(Node* node, in6_addr groupAddress);

// /**
// API              :: Ipv6NotificationOfPacketDrop
// LAYER            :: Network
// PURPOSE          :: Invoke callback functions when a packet is dropped.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + msg            :  Message*          : Pointer to message.
// + nextHopAddress :  const NodeAddress : Next Hop Address
// + interfaceIndex :  int               : Interface Index
// RETURN           :: void  : NULL.
// **/
void
Ipv6NotificationOfPacketDrop(
    Node* node,
    Message* msg,
    MacHWAddress& nextHopAddress,
    int interfaceIndex);

// /**
// API              :: Ipv6IsPartOfMulticastGroup
// LAYER            :: Network
// PURPOSE          :: Check if destination is part of the multicast group.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + msg            :  Message*          : Pointer to message.
// + groupAddress   :  in6_addr          : Multicast Address
// RETURN           :: TRUE if node is part of multicast group,
//                     FALSE otherwise.
// **/
BOOL Ipv6IsPartOfMulticastGroup(Node *node, in6_addr groupAddress);

// /**
// API              :: Ipv6IsReservedMulticastAddress
// LAYER            :: Network
// PURPOSE          :: Check if address is reserved multicast address.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + mcastAddr      :  in6_addr     : multicast group to join.
// RETURN           :: TRUE if reserved multicast address, FALSE otherwise.
// **/
BOOL Ipv6IsReservedMulticastAddress(Node* node, in6_addr mcastAddr);

// /**
// API              :: Ipv6InMulticastOutgoingInterface
// LAYER            :: Network
// PURPOSE          :: Determine if interface is in multicast outgoing
//                     interface list.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + list           :  LinkedList*  : Pointer to Linked List.
// + interfaceIndex :  int          : Interface Index.
// RETURN           :: TRUE if interface is in multicast outgoing interface
//                     list, FALSE otherwise.
// **/
BOOL Ipv6InMulticastOutgoingInterface(
    Node* node,
    LinkedList* list,
    int interfaceIndex);

// /**
// API              :: Ipv6UpdateMulticastForwardingTable
// LAYER            :: Network
// PURPOSE          :: update entry with (sourceAddress,
//                     multicastGroupAddress) pair. search for the row with
//                     (sourceAddress, multicastGroupAddress) and update its
//                     interface.
// PARAMETERS       ::
// + node                   :  Node*        : Pointer to node.
// + sourceAddress          :  in6_addr     : Source Address.
// + multicastGroupAddress  :  in6_addr     : multicast group.
// RETURN                   ::  void : NULL.
// **/
void Ipv6UpdateMulticastForwardingTable(
    Node* node,
    in6_addr sourceAddress,
    in6_addr multicastGroupAddress,
    int interfaceIndex);

// /**
// API              :: Ipv6GetOutgoingInterfaceFromMulticastTable
// LAYER            :: Network
// PURPOSE          :: get the interface List that lead to the (source,
//                     multicast group) pair.
// PARAMETERS       ::
// + node           :  Node*        : Pointer to node.
// + sourceAddress  :  in6_addr     : Source Address
// + groupAddress   :  in6_addr     : multicast group address
// RETURN           :: Interface List if match found, NULL otherwise.
// **/
LinkedList* Ipv6GetOutgoingInterfaceFromMulticastTable(
    Node* node,
    in6_addr sourceAddress,
    in6_addr groupAddress);

// /**
// FUNCTION   :: Ipv6CreateBroadcastAddress
// LAYER      :: NETWORK
// PURPOSE    :: Create IPv6 Broadcast Address (ff02 followed by all one).
// PARAMETERS ::
//  +node:  Node* : Pointer to Node.
//  +multicastAddr: in6_addr* : Pointer to broadcast address.
// RETURN     :: void : NULL.
// **/
void
Ipv6CreateBroadcastAddress(Node* node, in6_addr* multicastAddr);

// /**
// FUNCTION   :: Ipv6GetPrefixLength
// LAYER      :: NETWORK
// PURPOSE    :: Get prefix length of an interface.
// PARAMETERS ::
//  +node           : Node* : Pointer to Node.
//  +interfaceIndex : int   : Inetrafce Index.
// RETURN     :: Prefix Length.
// **/
UInt32
Ipv6GetPrefixLength(Node* node, int interfaceIndex);

// /**
// API              :: Ipv6SetMacLayerStatusEventHandlerFunction
// LAYER            :: Network
// PURPOSE          :: Allows the MAC layer to send status messages (e.g.,
//                     packet drop, link failure) to a network-layer routing
//                     protocol for routing optimization.
// PARAMETERS       ::
// + node                  :  Node*     : Pointer to node.
// + StatusEventHandlerPtr :  Ipv6MacLayerStatusEventHandlerFunctionType : Function Pointer
// + interfaceIndex        :  int       : Interface Index
// RETURN                  :: void      : NULL.
// **/
void
Ipv6SetMacLayerStatusEventHandlerFunction(
    Node *node,
    Ipv6MacLayerStatusEventHandlerFunctionType StatusEventHandlerPtr,
    int interfaceIndex);

// /**
// API              :: Ipv6DeleteOutboundPacketsToANode
// LAYER            :: Network
// PURPOSE          :: Deletes all packets in the queue going to the
//                     specified next hop address. There is option to return
//                     all such packets back to the routing protocols.
// PARAMETERS       ::
// + node                           :  Node*          : Pointer to node.
// + nextHopAddress                 :  const in6_addr : Next Hop Address.
// + destinationAddress             :  const in6_addr : Destination Address
// + returnPacketsToRoutingProtocol :  const BOOL     : bool
// RETURN                           :: void  : NULL.
// **/
void
Ipv6DeleteOutboundPacketsToANode(
    Node *node,
    in6_addr ipv6NextHopAddress,
    in6_addr destinationAddress,
    const BOOL returnPacketsToRoutingProtocol);

int Ipv6GetFirstIPv6Interface(Node* node);

// /**
// API              :: Ipv6IsLoopbackAddress
// LAYER            :: Network
// PURPOSE          :: Check if address is self loopback address.
// PARAMETERS       ::
// + node            :  Node*     : Pointer to node.
// + address         :  in6_addr  : ipv6 address
// RETURN                  :: void      : NULL.
// **/
BOOL Ipv6IsLoopbackAddress(Node* node, in6_addr address);

// /**
// API              :: Ipv6IsMyIp
// LAYER            :: Network
// PURPOSE          :: Check if address is self loopback address.
// PARAMETERS       ::
// + node            :  Node*     : Pointer to node.
// + dst_addr        :  in6_addr* : Pointer to ipv6 address
// RETURN           :: TRUE if my Ip, FALSE otherwise.
// **/
BOOL Ipv6IsMyIp(Node* node, in6_addr* dst_addr);

// /**
// API              :: Ipv6IsValidGetMulticastScope
// LAYER            :: Network
// PURPOSE          :: Check if multicast address has valid scope.
// PARAMETERS       ::
// + node            :  Node*           : Pointer to node.
// + multiAddr       : in6_addr         : multicast address.
// RETURN           :: Scope value if valid multicast address, 0 otherwise.
// **/
int Ipv6IsValidGetMulticastScope(Node* node, in6_addr multiAddr);

//------------------------------------------------------------------------
// FUNCTION     IPv6RoutingInit()
// PURPOSE      Initialization function for network layer.
//              Initializes IP.
// PARAMETERS   Node *node
//                  Pointer to node.
//              const NodeInput *nodeInput
//                  Pointer to node input.
//-----------------------------------------------------------------------
void
IPv6RoutingInit(Node *node, const NodeInput *nodeInput);

// /**
// API                 :: IsIPV6RoutingEnabledOnInterface
// LAYER               :: Network
// PURPOSE             :: To check if IPV6 Routing is enabled on interface?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL IsIPV6RoutingEnabledOnInterface(Node* node,
                                 int interfaceIndex);

//--------------------------------------------------------------------------
// FUNCTION             : Ipv6InterfaceInitAdvt
// PURPOSE             :: This is an overloaded function to
//                        re-initialize advertisement by an interface
//                        that recovers from interface fault.
// PARAMETERS          ::
// + node               : Node* node : Pointer to node
// + interfaceindex     : int interfaceIndex : interface that recovers
//                        from interface fault
// RETURN               : None
//--------------------------------------------------------------------------
void
Ipv6InterfaceInitAdvt(Node* node, int interfaceIndex);
#endif // IPV6_H


