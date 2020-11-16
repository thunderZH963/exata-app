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
 * Name: icmp.h
 * Purpose: To simulate INTERNET CONTROL MESSAGE PROTOCOL (ICMP)
 *          following RFC 792, RFC 1256., RFC 1122, RFC 1812
 */

#ifndef _ICMP_H_
#define _ICMP_H_

#define ICMP_DEFAULT_HOST_ROUTERLIST_SIZE     5


// ROUTER SPECIFICATION(For Router discovery message)

// Should be multicast address 224.0.0.1
#define ICMP_AD_ADDRESS              ANY_DEST

// Advertisement constants
#define ICMP_AD_MAX_INTERVAL         (600 * SECOND)
#define ICMP_AD_MIN_INTERVAL         (ICMP_AD_MAX_INTERVAL * 0.75)
#define ICMP_AD_LIFE_TIME            (ICMP_AD_MAX_INTERVAL * 3)

#define ICMP_REDIRECT_CACHE_TIME     (1 * SECOND);
#define ICMP_AD_PREFERNCE_LEVEL      0
#define ICMP_AD_ADDRESS_ENTRY_SIZE   2
#define ICMP_AD_NUMBER_OF_IP_ADDRESS_IN_INTERFACE 1

// Default priority of different type of ICMP messages.
#define ICMP_ERROR_MSG_PRIORITY        IPTOS_PREC_ROUTINE
#define ICMP_REQUEST_MSG_PRIO_DEFAULT  IPTOS_PREC_INTERNETCONTROL
#define ICMP_REPLY_MSG_PRIO_DEFAULT    ICMP_REQUEST_MSG_PRIO_DEFAULT


// ROUTER CONSTANTS (For Router discovery message)

#define ICMP_MAX_INITIAL_ADVERTISEMENTS       3
#define ICMP_MAX_INITIAL_ADVERT_INTERVAL      (16 * SECOND)
#define ICMP_MAX_RESPONSE_DELAY               (2 * SECOND)

// HOST SPECIFICATION(For Router discovery message)

// Should be multicast address 224.0.0.2
#define ICMP_SOLI_ADDRESS                     ANY_DEST


// HOST CONSTANTS(For Router discovery message)

#define ICMP_MAX_SOLICITATION_DELAY           (1 * SECOND)
#define ICMP_SOLICITATION_INTERVAL            (3 * SECOND)
#define ICMP_MAX_SOLICITATIONS                3

// Maximum packet size for the ICMP Error messages
#define ICMP_MAX_ERROR_MESSAGE_SIZE           96




/* this enum is use for initialized different types of Icmp Message */

typedef enum
{
    ICMP_ECHO_REPLY = 0,                          //This message has type 0
    ICMP_DESTINATION_UNREACHABLE = 3,             //This error has type  3
    ICMP_SOURCE_QUENCH,
    ICMP_REDIRECT,
    ICMP_ECHO = 8,                                //This message has type  8
    ICMP_ROUTER_ADVERTISEMENT,
    ICMP_ROUTER_SOLICITATION,
    ICMP_TIME_EXCEEDED,
    ICMP_PARAMETER_PROBLEM,
    ICMP_TIME_STAMP,
    ICMP_TIME_STAMP_REPLY,
    ICMP_INFORMATION_REQUEST,                   //obsolete
    ICMP_INFORMATION_REPLY,                      //obsolete
    ICMP_TRACEROUTE = 30,
    ICMP_SECURITY_FAILURES = 40
} IcmpMessage;

/* this enum is use for initialized different ICMP error code */
typedef enum
{
    ICMP_NETWORK_UNREACHABLE = 0,
    ICMP_HOST_UNREACHABLE,
    ICMP_PROTOCOL_UNREACHABLE,
    ICMP_PORT_UNREACHABLE,
    ICMP_DGRAM_TOO_BIG,
    ICMP_SOURCE_ROUTE_FAILED,
    ICMP_DESTINATION_NETWORK_UNKNOWN,
    ICMP_DESTINATION_HOST_UNKNOWN,
    ICMP_SOURCE_HOST_ISOLATED,                  //obsolete
    ICMP_DESTINATION_NETWORK_PROHIBITED,
    ICMP_DESTINATION_HOST_PROHIBITED,
    ICMP_NETWORK_UNREACHABLE_TOS,
    ICMP_HOST_UNREACHABLE_TOS,
    ICMP_COMMUNICATION_PROHIBITED,
    ICMP_HOST_PRECEDENCE_VIOLATION,
    ICMP_PRECEDENCE_CUTOFF
} IcmpDestinationUnreachableCode;

typedef  enum
{
    ICMP_ROUTER_ADVERTISEMENT_codeValue
} IcmpRouterAdvertisementCode;


typedef enum
{
    ICMP_ROUTER_SOLICITATION_codeValue
} IcmpRouterSolicitationCode;

typedef  enum
{
    ICMP_TTL_EXPIRED_IN_TRANSIT,
    ICMP_FRAGMENT_REASSEMBLY_TIME_EXCEEDED
} IcmpTimeExceededCode;

typedef  enum
{
    ICMP_SOURCE_QUENCH_CODE
} IcmpSourceQuenchCode;

typedef  enum
{
    ICMP_PARAMETER_PROBLEM_CODE
} IcmpParameterProblemCode;

typedef  enum
{
    PROBLEM_IN_HEADER_LENGTH = 0,
    PROBLEM_IN_TOTAL_LENGTH = 2,
    PROBLEM_IN_FLAGS_OR_FRAGOFFSET = 6,
    PROBLEM_IN_PROTOCOL = 9,
    PROBLEM_IN_OPTION = 20
} IpHeaderCheck;

typedef  enum
{
    ICMP_BAD_SPI,
    ICMP_AUTHENICATION_FAILED,
    ICMP_DECOMPRESSION_FAILED,
    ICMP_DECRYPTION_FAILED,
    ICMP_NEED_AUTHENTICATION,
    ICMP_NEED_AUTHORIZATION
} IcmpSecurityFailureCode;

typedef  enum
{
    ICMP_OUTBOUND_PACKET_SUCCESSFULLY_FORWARDED,
    ICMP_NO_ROUTE_FOR_OUTBOUND_PACKET
} IcmpTracerouteCode;

typedef struct
{
    unsigned int icmpNetworkUnreacableSent;
    unsigned int icmpNetworkUnreacableRecd;

    unsigned int icmpHostUnreacableSent;
    unsigned int icmpHostUnreacableRecd;

    unsigned int icmpProtocolUnreacableSent;
    unsigned int icmpProtocolUnreacableRecd;


    unsigned int icmpPortUnreacableSent;
    unsigned int icmpPortUnreacableRecd;

    unsigned int icmpSourceRouteFailedSent;
    unsigned int icmpSourceRouteFailedRecd;

    unsigned int icmpFragNeededSent;
    unsigned int icmpFragNeededRecd;

    unsigned int icmpDestinationNetworkUnknownRecd;
    unsigned int icmpDestinationHostUnknownRecd;
    unsigned int icmpNetworkAdminProhibitedRecd;
    unsigned int icmpHostAdminProhibitedRecd;
    unsigned int icmpNetworkUnreachableForTOSRecd;
    unsigned int icmpHostUnreachableForTOSRecd;
    unsigned int icmpCommAdminProhibitedRecd;
    unsigned int icmpHostPrecedenceViolationRecd;
    unsigned int icmpPrecedenceCutoffInEffectRecd;

    unsigned int icmpRedirctGenerate;
    unsigned int icmpRedirectReceive;


    unsigned int icmpSrcQuenchSent;
    unsigned int icmpSrcQuenchRecd;

    unsigned int icmpTTLExceededSent;
    unsigned int icmpTTLExceededRecd;

    unsigned int icmpFragReassemblySent;
    unsigned int icmpFragmReassemblyRecd;

    unsigned int icmpParameterProblemSent;
    unsigned int icmpParameterProblemRecd;

    unsigned int icmpSecurityFailedSent;
    unsigned int icmpSecurityFailedRecd;


} IcmpErrorStat;

/* Used for collect the statistics of Icmp module */

typedef struct
{
    unsigned short icmpAdvertisementGenerate;
    unsigned short icmpAdvertisementReceive;

    unsigned short icmpSolicitationGenerate;
    unsigned short icmpSolicitationReceive;

    unsigned short icmpEchoReceived;
    unsigned short icmpEchoReplyGenerated;

    unsigned short icmpTimestampReceived;
    unsigned short icmpTimestampReplyGenerated;

    unsigned short icmpTracerouteGenerated;


} IcmpStat;

// some parameters
typedef struct
{
    clocktype maxAdverInterval;
    clocktype minAdverInterval;
    clocktype adverLifeTime;
    clocktype redirectRertyTimeout;
    int maxNumSolicits;
    BOOL redirectOverrideRoutingProtocol;
} IcmpParameter;

/*
 * If the node is Router then it's each interface will be hold this type of
 * interface structure
 */

typedef struct
{
    BOOL              advertise;
    BOOL              solicitationFlag;
    BOOL              advertiseFlag;
    unsigned int      advertisementNumber;
    unsigned int      preferenceLevel;
} RouterInterfaceStructure;

/*
 * If the node is Host then it's interface will be hold this type of
 * interface structure
 */

typedef struct
{
    BOOL               alreadyGotRouterSolicitationMessage;
    BOOL               performRouterDiscovery;
    unsigned int       solicitationNumber;
} HostInterfaceStructure;


/* This is the structure of host's Router List */

typedef struct
{
    BOOL                systemConfiguration;
    BOOL                validRow;
    int                 count;
    int                 interfaceIndex;
    NodeAddress         routerAddr;
    unsigned int        preferenceLevel;
    clocktype           timeToLife;
} HostRouterList;

/* This is Icmp Redirect Message Cache */

typedef struct redirect_Cache
{
    NodeAddress ipSource;
    NodeAddress destination;
    redirect_Cache* next;
} RedirectCacheInfo;


/* This is Icmp Module structure */

typedef struct
{
    BOOL               router;
    BOOL               collectStatistics;
    BOOL               collectErrorStatistics;
    BOOL               networkUnreachableEnable;
    BOOL               hostUnreachableEnable;
    BOOL               protocolUnreachableEnable;
    BOOL               portUnreachableEnable;
    BOOL               fragmentationNeededEnable;
    BOOL               sourceRouteFailedEnable;
    BOOL               sourceQuenchEnable;
    BOOL               TTLExceededEnable;
    BOOL               fragmentsReassemblyTimeoutEnable;
    BOOL               parameterProblemEnable;
    BOOL               redirectEnable;
    BOOL               securityFailureEnable;
    void               *interfaceStruct[MAX_NUM_INTERFACES];
    HostRouterList     hostRouterList[ICMP_DEFAULT_HOST_ROUTERLIST_SIZE];
    RedirectCacheInfo* redirectCacheInfo;
    RedirectCacheInfo* redirectCacheInfoTail;
    IcmpStat           icmpStat;
    IcmpErrorStat      icmpErrorStat;
    IcmpParameter      parameter;

    LinkedList         *routerDiscoveryFunctionList;
    LinkedList         *routerTimeoutFunctionList;

    RandomSeed         seed;
} NetworkDataIcmp;


/* This is the Header Structure  of Icmp Message */

typedef struct
{
    unsigned char       icmpMessageType;
    unsigned char       icmpCode;
    unsigned short      icmpCheckSum;

    union
    {
        unsigned int    mustbeZero;
        unsigned int    gatewayAddr; // The address of a router that the host
                                     // should be use as next hop to reach
                                     // the destination node
        unsigned char       pointer;      /* This field is needed for
                                         Parameter Problem Error msg */

        struct
        {
            unsigned char  numAddr; // Number of router addresses advertised
                                    // in the message here I assume only one.

            unsigned char  addrEntrySize; // Size of information of each router
                                          // address in words (here is two)

            unsigned short lifeTime; // Maximum time router addresses may be
                                     //considered valid in Seconds
        } RouterAdvertisementHeader;

        struct
        {
            unsigned int reserved;
        } IcmpRouterSolicitation;

        struct
        {
            unsigned short idNumber;
            unsigned short sequenceNumber;
        } IcmpEchoTimeSecTrace;

    } Option;

} IcmpHeader;


typedef union
{
    struct
    {
        NodeAddress       routerAddress;
        unsigned int    preferenceLevel;
    } RouterAdvertisementData;

} IcmpData;

//structure for traceroute messages

typedef struct
{
    unsigned short outboundHopCount;
    unsigned short returnHopCount;
    unsigned int outputLinkSpeed;
    unsigned int outputLinkMTU;
} IcmpTraceRouteData;



// This function is used for initialize the Icmp module.

void NetworkIcmpInit(Node *node,
                     const NodeInput *nodeInput);


// This is a interface function of Icmp module to generate all
// type of ICMP Error messages.This function will be called
// from some outside module (e.g., nwip.pc,transport.pc) from which module
// ICMP error is occured.

void NetworkIcmpGenerateIcmpErrorMessage(Node *node,
                                         Message *msg,
                                         unsigned short icmpType,
                                         unsigned short icmpCode,
                                         unsigned int var);


// This is another interface function of ICMP module to generate all type of
// ICMP Request messages.This function will be called from any other module
// that needs to generate any type of Icmp Request message (such as Echo
// Request or TimeStamp Request message).

void NetworkIcmpGenerateIcmpReqestMessage(Node *node,
                                          NodeAddress destinationAddress,
                                          unsigned short icmpType,
                                          unsigned short icmpCode,
                                          unsigned int var);


// This is a interface function of ICMP module to receive all message
// which protocol is ICMP PROTOCOL

void NetworkIcmpHandleProtocolPacket(Node * node,
                                     Message *msg,
                                     NodeAddress sourceAddress,
                                     NodeAddress destinationAddress,
                                     int interfaceIndex);

/*
 * FUNCTION:   NetworkIcmpUpdateRedirectCache
 * PURPOSE:    Update ICMP Redirect cache to add a new entry.
 * RETURN:     NULL
 * PARAMETERS: node,           node which is sending ICMP redirect message
 *             ipSource          node to which ICMP Redirect message was sent,
 *             destination     destination for which redirect message was sent
 */

void NetworkIcmpUpdateRedirectCache(Node* node,
                                   NodeAddress ipSource,
                                   NodeAddress destination);

/*
 * FUNCTION:   NetworkIcmpDeletecacheEntry
 * PURPOSE:    Delete an entry from ICMP Redirect cache.
 * RETURN:     NULL
 * PARAMETERS: node,           node at which Redirect cache timer expired
 *             msg,            Redirect cache expire timer message
 */

void NetworkIcmpDeletecacheEntry (Node* node,Message* msg);

/*
 * FUNCTION:   NetworkIcmpHandleRedirect()
 * PURPOSE:    This function handles an ICMP Redirect message
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg, Redirect message received.
 *             sourceAddress, IP Address of the source of the Redirect packet
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpHandleRedirect( Node *node,
                              Message *msg,
                              NodeAddress sourceAddress,
                              int interfaceIndex);


// This function handles an ICMP Echo packet
void NetworkIcmpHandleEcho(Node * node,
                           Message *msg,
                           NodeAddress sourceAddress,
                           int interfaceIndex);


// This function handles different type of Icmp events

void NetworkIcmpHandleProtocolEvent(Node *node,
                                        Message *msg);


// Print out ICMP statistics, being called at the end

void NetworkIcmpFinalize (Node *node);


typedef
void (*NetworkIcmpRouterDiscoveryFunctionType)(
    Node *node,
    Message *msg,
    NodeAddress sourceAddr,
    NodeAddress destAddr,
    int interfaceId);

void NetworkIcmpSetRouterDiscoveryFunction(
          Node *node,
          NetworkIcmpRouterDiscoveryFunctionType routerDiscoveryFunctionPtr);


void NetworkIcmpCallRouterDiscoveryFunction(
    Node *node,
    Message *msg,
    NodeAddress sourceAddr,
    NodeAddress destAddr,
    int interfaceId);


typedef
void (*NetworkIcmpRouterTimeoutFunctionType)(
    Node *node,
    NodeAddress routerAddr);


void NetworkIcmpSetRouterTimeoutFunction(
          Node *node,
          NetworkIcmpRouterTimeoutFunctionType routerTimeoutFunctionPtr);


void NetworkIcmpCallRouterTimeoutFunction(
    Node *node,
    NodeAddress routerAddr);


void BytesSwapHton(UInt8* msg);


/*
 * FUNCTION:   NetworkIcmpRedirectIfApplicable
 * PURPOSE:    Redirects a packet if all of the checks are satisfied
 * RETURN:     NULL
 * PARAMETERS: node,              node that will send redirect
 *             msg,               message that causes redirect
 *             incomingInterface, interface that the message arrives on
 *             outgoingInterface, interface that the message leaves on
 *             nextHop,           the next hop destination of the message
 *             routeType,         host or network redirect
 */
void NetworkIcmpRedirectIfApplicable(
    Node* node,
    Message* msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop,
    BOOL routeType);

/*
 * FUNCTION:   NetworkIcmpCreateErrorMessage
 * PURPOSE:    Create a ICMP Error message and send it
 * RETURN:     BOOL
 * PARAMETERS: node,           node which generate the ICMP Error Message
 *             msg,            Message of data packet which generate the
 *                             ICMP Error Msg
 *             destinationAddress,  source address of the original Data
 *                                  packet which now becomes the destination
 *                                  address of the ICMP message
 *             interfaceId,    Incoming interface of the original data
 *                             packet which now becomes outgoing interface of
 *                             the ICMP packet
 *             icmpType,       ICMP Error Messgae Type
 *             icmpCode,       ICMP Error Message Code corresponding to Type
 *             pointer         for parameter problem msg
 *             gatewayAddress  for redirect msg
 */

BOOL NetworkIcmpCreateErrorMessage
(
    Node *node,
    Message *msg,
    NodeAddress destinationAddress,
    int interfaceId,
    unsigned short icmpType,
    unsigned short icmpCode,
    unsigned short pointer,
    NodeAddress gatewayAddress
);

/*
 * FUNCTION:   NetworkIcmpHandleTimestamp()
 * PURPOSE:    This function handles an ICMP Timestamp packet by initiating
 *             a TIMESTAMP REPLY.
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg, Timestamp packet received.
 *             sourceAddress, IP Address of the source of the Timestamp packet
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpHandleTimestamp( Node *node,
                              Message *msg,
                              NodeAddress sourceAddress,
                              int interfaceIndex);

/*
 * FUNCTION:   NetworkIcmpGenerateTraceroute()
 * PURPOSE:    Create a ICMP Traceroute message and send it
 * RETURN:     None
 * ASSUMPTION: None
 * PARAMETERS: node,     node in which Icmp message will be created.
 *             msg,
 *             sourceAddress, IP Address of the source of the packet with
 *             Traceroute option in IP Header
 *             interfaceIndex, interface on which the packet was received
 */

void NetworkIcmpGenerateTraceroute ( Node *node,
                  Message *msg,
                  NodeAddress sourceAddress,
                  int interfaceIndex);

/*
 * FUNCTION:   ReverseArray()
 * PURPOSE:    To reverse an array of NodeAddress type.
 * RETURN:     The pointer to the reversed array
 * ASSUMPTION: None
 * PARAMETERS: orig, pointer to the original array.
               size, size of the array.
 */

NodeAddress *ReverseArray(NodeAddress *orig, int size);

/*
 * FUNCTION:   NetworkIcmpCreateSecurityErrorMessage
 * PURPOSE:    Create a ICMP Security Error message and send it
 * RETURN:     None
 * PARAMETERS: node,           node which generate the ICMP Error Message
 *             msg,            Message of data packet which generate the
 *                             ICMP Error Msg
 *             incomingInterface, interface that the message arrives on
 */

void NetworkIcmpCreateSecurityErrorMessage( Node* node,
                                           Message* msg,
                                           int incomingInterface);

#endif /* _ICMP_H_ */

