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
// PROTOCOL :: Dynamic Host Configuration Protocol
// LAYER :: Application Layer
// REFERENCES :: [RFC 2131] “Dynamic Host Configuration Protocol,”
//               RFC 2131, Mar 1997.
//               http://www.ietf.org/rfc/rfc2131.txt
//               [RFC 2132] “DHCP Options and BOOTP Vendor Extensions,
//               RFC 2132, Mar 1997.
//               http://www.ietf.org/rfc/rfc2132.txt
// COMMENTS :: DHCPRELEASE can be triggered from client externally.
//             Assumptions:
//             1.BOOT file name parameter to be left null as the
//               BOOTP protocol is not implemented in QualNet.
//             2 The key for storage of IP address and configuration
//               parameters at server side will be hardware address unless
//               the client explicitly supplies an identifier using
//               the ‘client identifier’ option.
//             3.DHCP messages shall always be broadcasted before
//               an IP address is configured.
// **/

#ifndef _DHCP_APP_H_
#define _DHCP_APP_H_

#define DHCP_RETRANS_TIMER (10 * SECOND)
#define DHCP_MAX_RETRANS_TIMER (64 * SECOND)

#define DHCP_DEBUG 0

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define DHCP_SNAME_LEN 64
#define DHCP_FILE_LEN 128

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define DHCP_BROADCAST 32768
#define DHCP_T1 0.5
#define DHCP_T2 0.875
#define DHCP_T1_RETRANSMIT 0.1875
#define DHCP_T2_RETRANSMIT 0.0625

#define DHCP_RENEW_TIMEOUT 0
#define DHCP_REBIND_TIMEOUT 0

#define DHCP_OFFER_TIMEOUT 10

#define DHCP_INFINITE_LEASE -1

#define DHCP_UDP_OVERHEAD   28
#define DHCP_FIXED_NON_UDP  236
#define DHCP_FIXED_LEN      (DHCP_FIXED_NON_UDP + DHCP_UDP_OVERHEAD)

#define DHCP_BOOTP_MIN_LEN       300

#define DHCP_MTU_MAX        1500
#define DHCP_MTU_MIN            576

#define DHCP_MAX_OPTION_LEN (DHCP_MTU_MAX - DHCP_FIXED_LEN)
#define DHCP_MIN_OPTION_LEN (DHCP_MTU_MIN - DHCP_FIXED_LEN)

#define DHCP_CHADDR_LENGTH 16
#define DHCP_RELAY_MAX_HOP 16

#define DHCP_MINIMUM_LEASE_TIME 12


#define nTEST_DHCPRELEASE

// DHCP Option codes:

#define DHO_PAD                             0
#define DHO_SUBNET_MASK                     1
#define DHO_TIME_OFFSET                     2
#define DHO_ROUTERS                         3
#define DHO_TIME_SERVERS                    4
#define DHO_NAME_SERVERS                    5
#define DHO_DOMAIN_NAME_SERVERS             6
#define DHO_LOG_SERVERS                     7
#define DHO_COOKIE_SERVERS                  8
#define DHO_LPR_SERVERS                     9
#define DHO_IMPRESS_SERVERS                 10
#define DHO_RESOURCE_LOCATION_SERVERS       11
#define DHO_HOST_NAME                       12
#define DHO_BOOT_SIZE                       13
#define DHO_MERIT_DUMP                      14
#define DHO_DOMAIN_NAME                     15
#define DHO_SWAP_SERVER                     16
#define DHO_ROOT_PATH                       17
#define DHO_EXTENSIONS_PATH                 18
#define DHO_IP_FORWARDING                   19
#define DHO_NON_LOCAL_SOURCE_ROUTING        20
#define DHO_POLICY_FILTER                   21
#define DHO_MAX_DGRAM_REASSEMBLY            22
#define DHO_DEFAULT_IP_TTL                  23
#define DHO_PATH_MTU_AGING_TIMEOUT          24
#define DHO_PATH_MTU_PLATEAU_TABLE          25
#define DHO_INTERFACE_MTU                   26
#define DHO_ALL_SUBNETS_LOCAL               27
#define DHO_BROADCAST_ADDRESS               28
#define DHO_PERFORM_MASK_DISCOVERY          29
#define DHO_MASK_SUPPLIER                   30
#define DHO_ROUTER_DISCOVERY                31
#define DHO_ROUTER_SOLICITATION_ADDRESS     32
#define DHO_STATIC_ROUTES                   33
#define DHO_TRAILER_ENCAPSULATION           34
#define DHO_ARP_CACHE_TIMEOUT               35
#define DHO_IEEE802_3_ENCAPSULATION         36
#define DHO_DEFAULT_TCP_TTL                 37
#define DHO_TCP_KEEPALIVE_INTERVAL          38
#define DHO_TCP_KEEPALIVE_GARBAGE           39
#define DHO_NIS_DOMAIN                      40
#define DHO_NIS_SERVERS                     41
#define DHO_NTP_SERVERS                     42
#define DHO_VENDOR_ENCAPSULATED_OPTIONS     43
#define DHO_NETBIOS_NAME_SERVERS            44
#define DHO_NETBIOS_DD_SERVER               45
#define DHO_NETBIOS_NODE_TYPE               46
#define DHO_NETBIOS_SCOPE                   47
#define DHO_FONT_SERVERS                    48
#define DHO_X_DISPLAY_MANAGER               49
#define DHO_DHCP_REQUESTED_ADDRESS          50
#define DHO_DHCP_LEASE_TIME                 51
#define DHO_DHCP_OPTION_OVERLOAD            52
#define DHO_DHCP_MESSAGE_TYPE               53
#define DHO_DHCP_SERVER_IDENTIFIER          54
#define DHO_DHCP_PARAMETER_REQUEST_LIST     55
#define DHO_DHCP_MESSAGE                    56
#define DHO_DHCP_MAX_MESSAGE_SIZE           57
#define DHO_DHCP_RENEWAL_TIME               58
#define DHO_DHCP_REBINDING_TIME             59
#define DHO_VENDOR_CLASS_IDENTIFIER         60
#define DHO_DHCP_CLIENT_IDENTIFIER          61
#define DHO_NWIP_DOMAIN_NAME                62
#define DHO_NWIP_SUBOPTIONS                 63
#define DHO_USER_CLASS                      77
#define DHO_FQDN                            81
#define DHO_DHCP_AGENT_OPTIONS              82
#define DHO_CLIENT_LAST_TRANSACTION_TIME    91
#define DHO_ASSOCIATED_IP                   92
#define DHO_SUBNET_SELECTION                118
#define DHO_DOMAIN_SEARCH                   119
#define DHO_VIVCO_SUBOPTIONS                124
#define DHO_VIVSO_SUBOPTIONS                125
#define DHO_END                             255

#define DHCP_DHO_LEASE_TIME_LEN    4
#define DHCP_DHO_MESSAGE_TYPE_LEN  1

#define DHCP_RETRY_COUNTER_EXP_INC 2
#define DHCP_SERVER_DEFAULT_MAX_LEASE_TIME 100
#define DHCP_SERVER_DEFAULT_DEFAULT_LEASE_TIME 30

#define DHCP_CLIENT_RELEASE_INVALIDATION_INTERVAL "0.01"
#define DHCP_CLIENT_DECLINE_INVALIDATION_INTERVAL "10"
#define DHCP_DOMAIN_NAME_SERVER_OPTION_LENGTH 4
#define DHCP_LEASE_TIME_OPTION_LENGTH 4
#define DHCP_ADDRESS_OPTION_LENGTH 4
#define DHCP_SERVER_RENEWREBIND_DONOT_RESPOND_LEASETIME 0.9
enum dhcpLeaseStatus
{
    DHCP_OFFERED,
    DHCP_ALLOCATED,
    DHCP_AVAILABLE,
    DHCP_ACTIVE,
    DHCP_INACTIVE,
    DHCP_RENEW,
    DHCP_REBIND,
    DHCP_UNAVAILABLE,
    DHCP_MANUAL
};


struct dhcpLease
{
    char clientIdentifier[MAX_STRING_LENGTH];  // Client Identifier
    Address ipAddress;                         // IP Address
    Address subnetNumber;                      // subnet number to which this
                                               // IP belongs
    enum dhcpLeaseStatus status;               // Status of lease
    MacHWAddress macAddress;                   // MAC Address of client
    Address serverId;                          // IP Address of server
                                               // who alloted lease
    UInt32 leaseTime;                          // Total lease time interval
    Message* expiryMsg;                        // Lease expiry message
    Message* renewMsg;                         // Lease renewal message
    Message* rebindMsg;                        // Lease rebind message
    Int32 renewTimeout;                        // Renew timeout value
    Int32 rebindTimeout;                       // Rebind timeout value
    Address defaultGateway;                    // Default gateway for the
                                               // lease
    Address subnetMask;                        // Subnet Mask for the lease
    Address primaryDNSServer;                  // Primary DNS server for the
                                               // lease
    std::list<Address*>* listOfSecDNSServer;   // List of secondary DNS
                                               //servers for the lease

};


struct appDhcpServerManualAlloc
{
    Int32 nodeId;                   // Node Id for manual allocation
    Int32 incomingInterface;        // Incoming interface of server
    Address ipAddress;              // IP address to be manually allocated
};


enum dhcpClientState
{
    DHCP_CLIENT_START,
    DHCP_CLIENT_INIT,
    DHCP_CLIENT_SELECT,
    DHCP_CLIENT_REQUEST,
    DHCP_CLIENT_BOUND,
    DHCP_CLIENT_RENEW,
    DHCP_CLIENT_REBIND,
    DHCP_CLIENT_INFORM,
    DHCP_CLIENT_INIT_REBOOT
};



enum dhcpMessageType
{
    DHCPDISCOVER = 1,
    DHCPOFFER,
    DHCPREQUEST,
    DHCPACK,
    DHCPDECLINE,
    DHCPINFORM,
    DHCPNAK,
    DHCPRELEASE
};


struct dhcpData
{
    UInt8 op;      // 0: Message opcode type
    UInt8 htype;   // 1: Hardware addr type (net/if_types.h)
    UInt8 hlen;    // 2: Hardware addr length
    UInt8 hops;    // 3: Number of relay agent hops from client
    UInt32 xid;      // 4: Transaction ID
    UInt16 secs;     // 8: Seconds since client started looking
    UInt16 flags;    // 10: Flag bits
    UInt32 ciaddr;  // 12: Client IP address (if already in use) UInt32
    UInt32 yiaddr;  // 16: Client IP address UInt32
    UInt32 siaddr;  // 20: IP address of next server to talk to UInt32
    UInt32 giaddr;  // 24: DHCP relay agent IP address UInt32
    unsigned char chaddr[DHCP_CHADDR_LENGTH];//28: Client hardware address
    char sname [DHCP_SNAME_LEN];    // 44: Server name
    char file [DHCP_FILE_LEN];    // 108: Boot filename
    unsigned char options [DHCP_MAX_OPTION_LEN];
};



struct appDataDhcpServer
{
    UInt32 defaultLeaseTime;            // Default lease time that
                                        // can be allocated
    UInt32 maxLeaseTime;                // Max lease time that can
                                        // be allocated
    short sourcePort;                   // Source Port of server
    UInt32 numDiscoverRecv;             // Number of DISCOVER packets
                                        // received
    UInt32 numInformRecv;               // Number of INFORM packets
                                        // received
    UInt32 numOfferSent;                // Number of OFFER packets sent
    UInt32 numOfferReject;              // Number of OFFERS rejected
    UInt32 numRequestRecv;              // Number of REQUEST received
    UInt32 numDeclineRecv;              // Number of DECLINE received
    UInt32 numAckSent;                  // Number of ACK packets sent
    UInt32 numNakSent;                  // Number of NAK packets sent
    UInt32 numTotalLease;               // Total number of lease
    UInt32 numOfferedLease;             // Number of OFFERED lease
    UInt32 numAllocatedLease;           // Number of ALLOCATED lease
    UInt32 numAvailableLease;           // Number of AVAILABLE lease
    UInt32 numManualLease;              // Number of MANUAL lease
    UInt32 numUnavailableLease;         // Number of DECLINED lease
    UInt32 numManualLeaseInRange;       // Number of MANUAL allocated
                                        //lease that are in range
    RandomSeed jitterSeed;              // Delay jitter seed
    Address addressRangeStart;          // Starting address
    Address addressRangeEnd;            // Last address
    Address interfaceAddress;           // Interface address
    Address defaultGateway;             // Default gateway to be allocated
    Address subnetMask;                 // Subnet Mask to be allocated
    Address primaryDNSServer;           // Primary DNS server to be
                                        // allocated
    Message* timeoutMssg;               // Offer timeout message
    struct dhcpData* dataPacket;
    bool dhcpServerStatistics;
    std::list<struct dhcpLease*>* serverLeaseList; // lease list
    std::list<struct appDhcpServerManualAlloc*>* manualAllocationList;
                                    // List of manual allocation lease
    std::list<Address*>* listSecDnsServer; // List of secondary DNS server
                                          // allocate
};

struct appDataDhcpClient
{
    Int32 interfaceIndex;               // Interface index of client
    UInt32 recentXid;                    // XID of latest packet sent
    char dhcpClientIdentifier[MAX_STRING_LENGTH];   // Client identifier
    UInt32 dhcpLeaseTime;    // Lease time interval
    clocktype timeout;          // Timeout time for packet sent
    clocktype reacquireTime;
    Address rejectIP;           // Any IP for rejection
    short sourcePort;           // Source port of client
    D_UInt32 tos;               //
    UInt32 numDiscoverSent;     // Number of DISCOVER packet sent
    UInt32 numOfferRecv;        // Number of OFFER received
    UInt32 numRequestSent;      // Number of REQUEST sent
    UInt32 numDeclineSent;      // Number of DECLINE sent
    UInt32 numAckRecv;          // Number of ACK received
    UInt32 numNakRecv;          // Number of NAK received
    UInt32 numInformSent;       // Number of INFORM sent
    UInt32 numActiveLease;      // Number of ACTIVE lease
    UInt32 numInactiveLease;    // Number of INACTIVE lease
    UInt32 numRenewLease;       // Number of lease undergoing renewal
    UInt32 numRebindLease;      // Number of lease undergoing rebinding
    UInt32 numManualLease;      // Number of lease formed due to INFORM
    RandomSeed jitterSeed;      // Delay jitter seed
    enum dhcpClientState state;      // Client state
    MacHWAddress hardwareAddress;
    std::list<struct dhcpLease*>* clientLeaseList; // List of lease for client
    Message* timeoutMssg;       // Timeout message
    Int32 retryCounter;         // Retry counter for exponential backoff
    clocktype arpInterval;      // Time interval in getting response
                                // from ARP
    struct dhcpData* dataPacket;       // Data packet last sent
    Address lastIP;             // last IP allocated
    bool manetEnabled;
    bool dhcpClientStatistics;
    #ifdef TEST_DHCPRELEASE
    clocktype dhcpReleaseTime;      // Release time
    #endif

};

struct appDataDhcpRelay
{
    Int32 numClientPktsRelayed;  // Number of clients packets relayed
                                 //   from client to server list

    Int32 numServerPktsRelayed; // Number of server packets relayed
                                //   from server to client
    Int32 interfaceIndex;      // Interface Id where relay agnet enabled
    std::list<Address*>* serverAddrList; // List fo DHCP servers
    struct dhcpData* dataPacket;
    bool dhcpRelayStatistics;
};

//--------------------------------------------------------------------------
// NAME             : AppDhcpClientInit.
// PURPOSE          : Initialize DHCP client data structure.
// PARAMETERS       :
// + node           : Node*       : The pointer to the node.
// + interfaceIndex : Int32       : interfaceIndex
// + nodeInput      : NodeInput*  : The pointer to configuration
// RETURN           : NONE
// -------------------------------------------------------------------------

void AppDhcpClientInit(
    Node* node,
    Int32 InterfaceIndex,
    const NodeInput* nodeInput);

//---------------------------------------------------------------------------
// NAME             : AppDhcpServerInit.
// PURPOSE          : Initializes the DHCP server.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           : none.
// --------------------------------------------------------------------------

void AppDhcpServerInit(
    Node* node,
    Int32 InterfaceIndex,
    const NodeInput* nodeInput);

//--------------------------------------------------------------------------
// NAME             : AppDhcpServerNewDhcpServer.
// PURPOSE          : create a new DHCP server data structure, place it
//                    at the beginning of the application list.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           :
// struct appDataDhcpServer* : the pointer to the created DHCP server data
//                             structure NULL if no data structure allocated
//--------------------------------------------------------------------------
struct appDataDhcpServer* AppDhcpServerNewDhcpServer(
    Node* node,
    Int32 InterfaceIndex,
    const NodeInput* nodeInput);

//--------------------------------------------------------------------------
// NAME             : AppDhcpClientNewDhcpClient
// PURPOSE          : create a new DHCP client data structure, place it
//                    at the beginning of the application list.
// PARAMETERS       :
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN           :
// struct appDataDhcpClient* : the pointer to the created DHCP client data
//                             structure NULL if no data structure allocated
//--------------------------------------------------------------------------

struct appDataDhcpClient* AppDhcpClientNewDhcpClient(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput);

//---------------------------------------------------------------------------
// NAME         : AppLayerDhcpClient.
// PURPOSE      : Models the behaviour of DHCP Client on receiving the
//                message encapsulated in msg.
// PARAMETERS   :
// + node       : Node*     : The pointer to the node.
// + msg        : Message*  : message received by the layer
// RETURN       : none.
//---------------------------------------------------------------------------
void AppLayerDhcpClient(
    Node* node,
    Message* msg);

//--------------------------------------------------------------------------
// NAME                     : AppDhcpClientGetDhcpClient.
// PURPOSE                  : search for a DHCP client data structure.
// PARAMETERS               :
// + node                   : Node* : The pointer to the node.
// + interfaceIndex         : Int32 : Interface index which act as client
// RETURN                   :
// struct appDataDhcpClient : the pointer to the DHCP client data structure,
//                            NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpClient* AppDhcpClientGetDhcpClient(
    Node* node,
    Int32 InterfaceIndex);

//---------------------------------------------------------------------------
// NAME             : AppDhcpClientStateInit
// PURPOSE          : Models the behaviour of client when it enters
//                    INIT state
// PARAMETERS       :
// + node           : Node*    : pointer to the node which enters INIt state
// + interfaceIndex : Int32    : interface of node which enters INIT state
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateInit(
    Node* node,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientMakeDiscover.
// PURPOSE:        : make DHCPDISCOVER packet to send
// PARAMETERS:
// + clientPtr     : struct appDataDhcpClient*: pointer to the client data.
// + node          : Node*                    : client node.
// +interfaceIndex : Int32                    : interface that will send
//                                              the DHCPDISCOVER packet
// RETURN:
// struct dhcpData*: pointer to the DHCPDISCOVER packet created.
//                   NULL if nothing found.
//---------------------------------------------------------------------------

struct dhcpData* AppDhcpClientMakeDiscover(
    struct appDataDhcpClient* clientPtr,
    Node* node,
    Int32 InterfaceIndex);

//---------------------------------------------------------------------------
// NAME:         : AppLayerDhcpServer.
// PURPOSE:      : Models the behaviour of DHCP Server on receiving the
//                 message encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN        : none.
//---------------------------------------------------------------------------

void AppLayerDhcpServer(
    Node* node,
    Message* msg);

//--------------------------------------------------------------------------
// NAME                         : AppDhcpServerGetDhcpServer
// PURPOSE                      : search for a DHCP Server data structure.
// PARAMETERS                   :
// + node                       : Node*    : pointer to the node.
// + interfaceIndex             : Int32    : interface index which act
//                                          as Server
// RETURN                       :
// struct appDataDhcpServer*    : the pointer to the DHCP server data
//                                structure, NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpServer* AppDhcpServerGetDhcpServer(
    Node* node,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME:               : AppDhcpServerReceivedDiscover
// PURPOSE:            : models the behaviour of server when a DISCOVER
//                       message is received.
// PARAMETERS:
// +node               : Node*           : DHCP server node.
// +data               : struct dhcpData : DISCOVER packet received.
// +incomingInterface  : Int32           : interface on which packte is
//                                         received.
// +originatingNodeId  : NodeAddress     : Node that originated the message
// RETURN              : none
//--------------------------------------------------------------------------
void AppDhcpServerReceivedDiscover(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface,
    NodeAddress originatingNodeId);


//---------------------------------------------------------------------------
// NAME:               : AppDhcpServerFindLease.
// PURPOSE:            : search for  a DHCP lease to offer.
// PARAMETERS:
// +node               : Node*           : DHCP server.
// +data               : struct dhcpData : DISCOVER packet received.
// +incomingInterface  : Int32           : interface on which packet is
//                                         received.
// +originatingNodeId  : NodeAddress     : source which sent the message
//RETURN:
// struct dhcpLease*   : the pointer to the lease found,NULL if nothing
//                       found.
//---------------------------------------------------------------------------
struct dhcpLease* AppDhcpServerFindLease(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface,
    NodeAddress originatingNodeId);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpServerMakeOffer
// PURPOSE:         : make DHCPOFFER packet to send
// PARAMETERS:
// + node           : Node*             : pointer to the server node.
// + data           : struct dhcpData   : packet received from client.
// + lease          : struct dhcpLease* : pointer to the lease to offer
// + interfaceIndex : Int32             : interface index of server
// RETURN:
// struct dhcpData* : pointer to DHCPOFFER packet cretaed
//                    NULL if nothing found.
//---------------------------------------------------------------------------
struct dhcpData* AppDhcpServerMakeOffer(
    Node* node,
    struct dhcpData data,
    struct dhcpLease* lease,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:                 : AppDhcpClientStateSelect
// PURPOSE:              : models the behaviour when client enters the
//                         SELECT state
// PARAMETERS:
// + node                : Node*            : pointer to the client node
//                                            which received the message.
// + data                : struct dhcpData  : OFFER packet received
// + incomingInterface   : Int32            : Interface on which packet
//                                            is received
// RETURN:               : none.
// --------------------------------------------------------------------------
void AppDhcpClientStateSelect(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface);

//--------------------------------------------------------------------------
// NAME:             : AppDhcpClientMakeRequest
// PURPOSE:          : make DHCPREQUEST packet to send
// PARAMETERS:
// + node            : Node*           : pointer to client which received
//                                       message.
// + data            : struct dhcpData : dhcp packet to help in making
//                                       request.
// + interfaceIndex  : Int32           : interface which received the
//                                       message.
// RETURN:
// struct dhcpData*  : the DHCPREQUEST packet.NULL if nothing found.
//--------------------------------------------------------------------------
struct dhcpData* AppDhcpClientMakeRequest(
    Node* node,
    struct dhcpData data,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME:                : AppDhcpServerReceivedRequest
// PURPOSE:             : models the behaviour of server when a REQUEST
//                      : message is received.
// PARAMETERS:
// + node               : Node*           : DHCP server node.
// + data               : struct dhcpData : REQUEST packet received.
// +incomingInterface   : Int32           : interface on which packte is
//                                          received.
// RETURN               : none
//---------------------------------------------------------------------------
void AppDhcpServerReceivedRequest(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface);


//--------------------------------------------------------------------------
// NAME:              : AppDhcpServerMakeAck
// PURPOSE:           : constructs DHCPACK
// PARAMETERS:
// + node             : Node*             : DHCP server node.
// + data             : struct dhcpData   : request packet received
// + lease            : struct dhcpLease* : lease to be allocated.
// +interfaceIndex    : Int32             : InterfaceId
// RETURN:
// struct dhcpData*   : the pointer to the DHCP ACK packet,
//                      NULL if nothing found.
// --------------------------------------------------------------------------
struct dhcpData* AppDhcpServerMakeAck(
    Node* node,
    struct dhcpData data,
    struct dhcpLease* lease,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpClientStateBound
// PURPOSE:               : models the behaviour when client enters the
//                          BOUND state
// PARAMETERS:
// + node                 : Node*             : pointer to the client node
//                                              which received the message.
// + data                 : struct dhcpData   : ACK packet received
// + incomingInterface    : Int32             : Interface on which packet
//                                              is received
// RETURN:                : none
//---------------------------------------------------------------------------
void AppDhcpClientStateBound(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface);

//--------------------------------------------------------------------------
// NAME:        : AppDhcpClientFinalize.
// PURPOSE:     : Collect statistics of a DHCPClient session.
// PARAMETERS:
// +Node*       : node    : pointer to the node.
// RETURN:      : NONE
//--------------------------------------------------------------------------
void AppDhcpClientFinalize(Node* node);

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientPrintStats
// PURPOSE:        : Prints the stats in stat file.
// PARAMETERS:
// +node           : Node*                     : pointer to the node.
// +clientPtr      : struct appDataDhcpClient* : pointer to the DHCP client.
// +interfaceIndex : Int32                     : interface Index
// RETURN:         : none.
//--------------------------------------------------------------------------
void AppDhcpClientPrintStats(
    Node* node,
    struct appDataDhcpClient* clientPtr,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:        : AppDhcpServerFinalize.
// PURPOSE:     : Collect statistics of a CbrServer session.
// PARAMETERS:
// + node       : Node*    : pointer to the node.
// RETURN       : NONE
//---------------------------------------------------------------------------
void AppDhcpServerFinalize(Node* node);

//--------------------------------------------------------------------------
// NAME:           : AppDhcpServerPrintStats
// PURPOSE:        : Prints the stats in stat file.
// PARAMETERS:
// +node           : Node*                     : pointer to the node.
// +ServerPtr      : struct appDataDhcpServer* : pointer to the DHCP server.
// +interfaceIndex : Int32                     :interface Index
// RETURN:         : NONE
//--------------------------------------------------------------------------
void AppDhcpServerPrintStats(
    Node* node,
    struct appDataDhcpServer* ServerPtr,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME:           : AppDhcpClientStateRenewRebind
// PURPOSE:        : models the behaviour when client enters the RENEWstate
// PARAMETERS:
// +node           : Node*             : pointer to the client node which
//                                       received the message.
// +interfaceIndex : Int32             : Interface on which client is enabled
// +serverAddress  : Address           : server address for  unicast
// +clientLease    : struct dhcpLease* : Lease which enters into
//                                       RENEW/REBIND state.
// RETURN:         : none.
//--------------------------------------------------------------------------
void AppDhcpClientStateRenewRebind(
    Node* node,
    Int32 incomingInterface,
    Address ServerAddress,
    struct dhcpLease* clientLease);

//---------------------------------------------------------------------------
// NAME:                : AppDhcpClientSendDecline
// PURPOSE:             : models the behaviour when client needs to send
//                        DECLINE message
// PARAMETERS:
// + node               : Node*           : pointer to the client node which
//                                          received the message.
// + data               : struct dhcpData : ACK packet received
// + incomingInterface  : Int32           : Interface on which packet is
//                                          received
// RETURN:              : none.
//---------------------------------------------------------------------------
void AppDhcpClientSendDecline(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientMakeDecline
// PURPOSE:         : make DHCPDECLINE packet to send
// PARAMETERS:
// + node           : Node                      : pointer to node
// + data           : struct dhcpData           : data packet
// + clientPtr      : struct appDataDhcpClient* : pointer to the client data
// + interfaceIndex : Int32                     : interface that will send
// RETURN:
// struct dhcpData* : pointer to the DHCPDECLINE packet created.
//                    NULL if nothing found.
//---------------------------------------------------------------------------
struct dhcpData* AppDhcpClientMakeDecline(
    Node* node,
    struct dhcpData data,
    struct appDataDhcpClient* clientPtr,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientStateInform
// PURPOSE:         : Models the behaviour of client when it enters
//                    INFORM state
// PARAMETERS:
// + node           : Node* : pointer to the node which enters INFORM state.
// + interfaceIndex : Int32 : interface of node which enters INFORMstate
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateInform(
    Node* node,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:                : AppDhcpServerReceivedInform.
// PURPOSE:             : models the behaviour of server when a INFORM
//                      : message is received.
// PARAMETERS:
// + node               : Node*           : DHCP server node.
// + data               : struct dhcpData : INFORM packet received.
// + incomingInterface  : Int32           : interface on which packte is
//                                          received.
// RETURN:              : NONE
//---------------------------------------------------------------------------
void AppDhcpServerReceivedInform(
    Node* node,
    struct dhcpData data,
    Int32 incomingInterface);

//---------------------------------------------------------------------------
// NAME:            : AppDHCPClientArpReply.
// PURPOSE:         : models the behaviour of client when it gets ARP reply
//                    message is received.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// + reply          : bool     : TRUE if no duplicate found
//                               FALSE if duplicate found.
// RETURN:          : NONE
//---------------------------------------------------------------------------
void AppDHCPClientArpReply(
    Node* node,
    Int32 interfaceIndex,
    bool reply);


//--------------------------------------------------------------------------
// NAME:            : AppDhcpRelayInit.
// PURPOSE:         : Initialize DHCP relay agent data structure.
// PARAMETERS:
// + node           : Node*       : The pointer to the node.
// + interfaceIndex : Int32       : interfaceIndex
// + nodeInput      : NodeInput*  : The pointer to configuration
// RETURN:          : none.
// --------------------------------------------------------------------------
void AppDhcpRelayInit(
    Node* node,
    Int32 InterfaceIndex,
    const NodeInput* nodeInput);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpRelayNewDhcpRelay.
// PURPOSE:         : create a new DHCP Relay data structure, place it
//                    at the beginning of the application list.
// PARAMETERS:
// + node           : Node*         : The pointer to the node.
// + interfaceIndex : Int32         : interfaceIndex
// + nodeInput      : NodeInput*    : The pointer to configuration
// RETURN:
// struct appDataDhcpRelay* : the pointer to the created DHCP Relay data
//                            structure, NULL if no data structure allocated.
//---------------------------------------------------------------------------
struct appDataDhcpRelay* AppDhcpRelayNewDhcpRelay(
    Node* node,
    Int32 interfaceIndex,
    const NodeInput* nodeInput);

//--------------------------------------------------------------------------
// NAME:        : AppDhcpRelayFinalize.
// PURPOSE:     : Collect statistics of a dhcp relay session.
// PARAMETERS:
// +node        : Node*    : Node - pointer to the node.
// RETURN       : NONE
//--------------------------------------------------------------------------
void AppDhcpRelayFinalize(Node* node);

//--------------------------------------------------------------------------
// NAME:                    : AppDhcpRelayGetDhcpRelay.
// PURPOSE:                 : search for  a DHCP relay data structure.
// PARAMETERS:
// +node                    : Node*    : pointer to the node.
// +interfaceIndex          : Int32    : Interface index which act as client
// RETURN:
// struct appDataDhcpRelay* : the pointer to the DHCP client data structure,
//                            NULL if nothing found.
//--------------------------------------------------------------------------
struct appDataDhcpRelay* AppDhcpRelayGetDhcpRelay(
    Node* node,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:         : AppLayerDhcpRelay.
// PURPOSE:      : Models the behaviour of DHCP Relay on receiving the
//                 message encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppLayerDhcpRelay(
    Node* node,
    Message* msg);

//--------------------------------------------------------------------------
// NAME:            : AppDhcpRelayPrintStats
// PURPOSE:         : Prints the stats in stat file.
// PARAMETERS:
// +node            : Node*                      : pointer to the node.
// +relayPtr        : struct appDataDhcpRelay*   : pointer to the DHCP relay
// +interfaceIndex  : Int32                      : interface index
// RETURN:          : NONE
//--------------------------------------------------------------------------
void AppDhcpRelayPrintStats(
    Node* node,
    struct appDataDhcpRelay* relayPtr,
    Int32 interfaceIndex);


//--------------------------------------------------------------------------
// NAME:               : AppDhcpClientSendRelease
// PURPOSE:            : models the behaviour when client needs to send
//                       RELEASE message
// PARAMETERS:
// +node               : Node*   : pointer to the client node which received
//                                 the message.
// +serverId           : Address : serverId
// +incomingInterface  : Int32   : Interface on which packet is received
// RETURN:             : none.
//--------------------------------------------------------------------------
void AppDhcpClientSendRelease(
    Node* node,
    Address serverId,
    Int32 incomingInterface);

//--------------------------------------------------------------------------
// NAME:            : AppDHCPClientFaultEnd.
// PURPOSE:         : models the behaviour of client when the fault on
//                    DHCP client ends.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// RETURN           : NONE
// --------------------------------------------------------------------------
void AppDHCPClientFaultEnd(
    Node* node,
    Int32 interfaceIndex);

//--------------------------------------------------------------------------
// NAME:            : AppDHCPClientFaultStart.
// PURPOSE:         : models the behaviour of client when the fault on
//                    DHCP client starts.
// PARAMETERS:
// + node           : Node*    : DHCP client node.
// + interfaceIndex : Int32    : interface which act as client.
// RETURN           : NONE
//---------------------------------------------------------------------------
void AppDHCPClientFaultStart(
    Node* node,
    Int32 interfaceIndex);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpClientStateRebootInit
// PURPOSE:         : models the behaviour when client enters the INIT
//                    REBOOT state
// PARAMETERS:
// + node           : Node*    : pointer to the client node which received
//                               the message.
// + interfaceIndex : Int32    : Interface on which client is enabled
// RETURN:          : NONE
// --------------------------------------------------------------------------
void AppDhcpClientStateRebootInit(
    Node* node,
    Int32 interfaceIndex );


//---------------------------------------------------------------------------
// NAME:         : AppDhcpInitialization
// PURPOSE:      : initializes the DHCP model
// PARAMETERS:
// + node        : Node*         : The pointer to the node.
// + nodeInput   : NodeInout*    : The pointer to configuration
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpInitialization(Node* node,
                           const NodeInput* nodeInput);

//---------------------------------------------------------------------------
// NAME:            : AppDhcpCheckDhcpEntityConfigLevel
// PURPOSE:         : checks the configuration of DHCP entity(server/client
//                    /relay-agent) at an inteface of node
// PARAMETERS:
// + node           : Node*       : The pointer to the node.
// + nodeInput      : NodeInput*  : The pointer to configuration
// + interfaceIndex : Int32       : interfaceIndex
// + entityName     : const char* : DHCP enity name
// + matchType      : Int32*      : match level of configuration
// + findString     : const char* : Pointer to parameterValue to be matched
// RETURN:          : bool
//                    TRUE : if enity configuration present
//                    FALSE: if entity configuration not present
//---------------------------------------------------------------------------
bool AppDhcpCheckDhcpEntityConfigLevel(Node* node,
                                       const NodeInput* nodeInput,
                                       Int32 interfaceIndex,
                                       const char* entityName,
                                       Int32* matchType,
                                       const char* findString = "YES");

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*     : The pointer to the node.
// + msg         : Message*  : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleDhcpPacket(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleReleaseEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving
//                 DHCPRelease event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleReleaseEvent(
    Node* node,
    Message* msg);


//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleRenewEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving DHCP
//                 lease renew event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleRenewEvent(
    Node* node,
    Message* msg);


//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleRebindEvent.
// PURPOSE:      : Models the behaviour of DHCP Client on receiving DHCP
//                 lease rebind event.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleRebindEvent(
    Node* node,
    Message* msg);


//---------------------------------------------------------------------------
// NAME:         : AppDhcpClientHandleLeaseExpiry.
// PURPOSE:      : Models the behaviour of DHCP Client on lease expiry
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpClientHandleLeaseExpiry(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP server on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleDhcpPacket(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleLeaseExpiry.
// PURPOSE:      : Models the behaviour of DHCP Server on lease expiry
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleLeaseExpiry(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:         : AppDhcpServerHandleTimeout.
// PURPOSE:      : Models the behaviour of DHCP Server on timeout of offer
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpServerHandleTimeout(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:         : AppDhcpRelayHandleDhcpPacket.
// PURPOSE:      : Models the behaviour of DHCP relay on receiving a DHCP
//                 packet encapsulated in msg.
// PARAMETERS:
// + node        : Node*       : The pointer to the node.
// + msg         : Message*    : message received by the layer
// RETURN:       : none.
//---------------------------------------------------------------------------
void AppDhcpRelayHandleDhcpPacket(
    Node* node,
    Message* msg);

//---------------------------------------------------------------------------
// NAME:               : AppDhcpSendDhcpPacket.
// PURPOSE:            : Creates and sends a DHCP packet via UDP
// PARAMETERS:
// + node              : Node*             : The pointer to the node.
// + interfaceIndex    : Int32             : interfaceIndex
// + sourcePort.....  .: short             : sourcePort
// + destAddress       : NodeAddress       : destination address
// + destPort          : short             : destination port
// + priority......  ..: TosType           : priority of packet
// + data              : struct dhcpData*  : dhcp data packet
// + originator        : Int32             : originator node id used when
//                                           client packets are relayed from
//                                           relay agent
// RETURN:             : none.
//---------------------------------------------------------------------------
void AppDhcpSendDhcpPacket(Node* node,
                           Int32 interfaceIndex,
                           short sourcePort,
                           NodeAddress destAddress,
                           short destPort,
                           TosType priority,
                           struct dhcpData* data,
                           Int32 originator = 0);

extern int MAPPING_CompareAddress(
    const Address& address1,
    const Address& address2);

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpCopySecondaryDnsServerList.
// PURPOSE:               : Copy a list of secondary DNS server into
 //                         another list
// PARAMETERS:
// + fromDnsServerList    : std::list<Address*>* : from DNS server list
// + toDnsServerList      : std::list<Address*>* : to DNS server list
// RETURN:                : none.
//---------------------------------------------------------------------------

void AppDhcpCopySecondaryDnsServerList(
    std::list<Address*>* fromDnsServerList,
    std::list<Address*>* toDnsServerList);

//---------------------------------------------------------------------------
// NAME:                  : AppDhcpCheckInfiniteLeaseTime.
// PURPOSE:               : checks if a lease time is infinite
// PARAMETERS:
// + clocktype            : time              : time to check
// + nodeInput            : const NodeInput*  : pointer to node input
// RETURN:                ::
// bool                   :TRUE if inifinite lease FALSE otherwise
//---------------------------------------------------------------------------

bool AppDhcpCheckInfiniteLeaseTime(
                                clocktype time,
                                const NodeInput* nodeInput);

#endif

