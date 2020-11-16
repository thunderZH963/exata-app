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
// This file contains data structure used by the dns application and
// prototypes of functions defined in dns.cpp.
//

// /**
// PROTOCOL :: DNS
//
// SUMMARY  :: The Domain Name System (DNS) is introduced to allow the user
// the independence from knowing the physical location of a host & their IP
// address. It is a distributed database used by TCP/IP applications to map
// between hostnames and IP addresses. Each site (university department,
// campus, company for example) maintains its own database of information and
// runs a server program that other systems across the Internet can query.
// The DNS provides the protocol, which allows clients and servers to
// communicate with each other.

// The basic terminology or records involves in "Domain Name Service"
// process are as follows.
//     . DOMAIN NAME SPACE
//     . RESOURCE RECORDS
//     . NAME SERVERS
//     . RESOLVERS

//
// LAYER :: APPLICATION.
//
// STATISTICS::

// + numOfDnsUpdateSent:Num of Update packet sent
// + numOfDnsUpdateRecv:Num of Update packet recvd
// +numOfDnsQuerySent:Num of Query packet sent
// +numOfDnsQueryRecv:Num of Query packet recvd
// +numOfDnsReplySent:Num of Reply packet sent
// +numOfDnsReplyRecv:Num of Reply packet recvd
// +numOfDnsNameResolved:Total DNS name resolved
// +numOfDnsNameUnresolved:Total DNS name unresolved
// +avgDelayForSuccessfullAddressResolution:
//        time taken for successful resolution
// +avgDelayForUnsuccessfullAddressResolution:
//        time taken for unsuccessful resolution
//
// CONFIG_PARAM ::
// + DNS-ENABLED YES
// + DNS-SERVER YES
// + DNS-SERVER-PRIMARY
// + DNS-SERVER-SECONDARY
// + DNS-DOMAIN-NAMES-FILE
// + DNS-DOMAIN-NAME-SPACE-FILE
// + DNS-CACHE-TIMEOUT-INTERVAL
// + HOSTS-FILE

//
// VALIDATION :: $QUALNET_HOME/verification/atm-ip.
//
// IMPLEMENTED_FEATURES ::
// + PACKET TYPE : Only Signaling and Unicast data payload are implemented.
// + NETWORK TYPE : Point to point ATM link are supported.
// + LINK TYPE : Wired.
// + FUNCTIONALITY : IP Protocol Data Units are carried over the ATM cloud
//                   through the Gateways.
//                 : Logical Subnet concept is introduced. At present,
//                   single Logical IP subnet is supported within ATM cloud,
//                 : Routing within the ATM clouds is done statically. Static
//                   route file is provided externally during configuration.
//                 : Virtual path setup process for each application is done
//                   dynamically, Various signaling messages are exchanged
//                   for setup virtual paths.
//                 : BW are reserved for each application.

//
// OMITTED_FEATURES ::
// +   Recursive service of the DNS Server.
// +   Stub Resolver.
// +   Mail support and mail specific services.
// +   DNS Security extensions.
// +   Inverse queries and replies.
// +   DNS IPv6 extensions (RFC 3596).


#ifndef _DNS_APP_H_
#define _DNS_APP_H_

#include "types.h"

#include <list>



// CONSTANT    :: ALL_INTERFACE : -3
// DESCRIPTION :: Signifies all Interface Index of Dns Client Node
#define ALL_INTERFACE -3

// CONSTANT    :: ASCII_VALUE_OF_DIGIT_0 : 48
// DESCRIPTION :: Ascii value of '0'
#define ASCII_VALUE_OF_DIGIT_0 48

// CONSTANT    :: ASCII_VALUE_OF_DIGIT_9 : 57
// DESCRIPTION :: Ascii value of '0'
#define ASCII_VALUE_OF_DIGIT_9 57

// CONSTANT    :: ASCII_VALUE_OF_SMALL_A : 97
// DESCRIPTION :: Ascii value of 'a'
#define ASCII_VALUE_OF_SMALL_A 97

// CONSTANT    :: ASCII_VALUE_OF_SMALL_Z : 122
// DESCRIPTION :: Ascii value of 'z'
#define ASCII_VALUE_OF_SMALL_Z 122

// CONSTANT    :: ASCII_VALUE_OF_CAPS_A : 65
// DESCRIPTION ::  Ascii value of 'A'
#define ASCII_VALUE_OF_CAPS_A 65


// CONSTANT    :: ASCII_VALUE_OF_CAPS_Z : 90
// DESCRIPTION ::  Ascii value of 'Z'
#define ASCII_VALUE_OF_CAPS_Z 90

// CONSTANT    :: ASCII_VALUE_OF_SPECIAL_CHAR_HYPHEN : 45
// DESCRIPTION ::  Ascii value of HYPHEN
#define ASCII_VALUE_OF_SPECIAL_CHAR_HYPHEN 45

// CONSTANT    :: DNS_NAME_LENGTH : 256
// DESCRIPTION :: Maximum Dns Name String Length.
//                This value should be less than BIG_STRING_LENGTH.
#define DNS_NAME_LENGTH 256

// CONSTANT    :: DOT_SEPARATOR : "."
// DESCRIPTION :: Dot Separator
#define DOT_SEPARATOR  "."

// CONSTANT    :: ROOT_LABEL : "/"
// DESCRIPTION :: Label of Root
#define ROOT_LABEL    "/"

// CONSTANT    :: MAX_RR_RECORD_NO : 5
// DESCRIPTION :: MAX RR record for DNS Server
#define MAX_RR_RECORD_NO 5

// CONSTANT    :: MAX_NS_RR_RECORD_NO : 20
// DESCRIPTION :: MAX NS RR record for DNS Server
#define MAX_NS_RR_RECORD_NO 20

// CONSTANT    :: ZONE_REFRESH_INTERVAL : 300 * SECOND
// DESCRIPTION :: Zone Refresh Time Interval
#define ZONE_REFRESH_INTERVAL 300 * SECOND


// CONSTANT    :: CACHE_REFRESH_INTERVAL : 20 * SECOND
// DESCRIPTION :: Resolver Cache Interval
#define CACHE_REFRESH_INTERVAL 20 * SECOND


// CONSTANT    :: NOTIFY_REFRESH_INTERVAL : 60 * SECOND
// DESCRIPTION :: Notify Refresh Time Interval
#define NOTIFY_REFRESH_INTERVAL 60 * SECOND

// CONSTANT    :: ALL_INTERFACE : -3
// DESCRIPTION :: Signifies all Interface Index of Dns Client Node
#define ALL_INTERFACE -3


// CONSTANT    :: MAX_COUNT_OF_NOTIFY_RETRIES_SENT : 5
// DESCRIPTION :: Default value of Max number of times DNS Notify
//                retires will be sent
#define MAX_COUNT_OF_NOTIFY_RETRIES_SENT 5

// CONSTANT    :: MAX_COUNT_OF_DNS_QUERY_RETRIES : 5
// DESCRIPTION :: Default value of Max number of times DNS Query
//                retires will be sent
#define MAX_COUNT_OF_DNS_QUERY_RETRIES 5


// CONSTANT    :: TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY : 2 sec
// DESCRIPTION :: Default value of Timeout interval of DNS Query
//                reply
#define TIMEOUT_INTERVAL_OF_DNS_QUERY_REPLY (2*SECOND)


// CONSTANT    :: DEFAULT_MIN_ZONE_TRANSFER_INTERVAL : 5 sec
// DESCRIPTION :: Default value of minimum time interval between
//                consecutive Zone transfers
#define DEFAULT_MIN_ZONE_TRANSFER_INTERVAL (5*SECOND)


// ENUM        :: RrType
// DESCRIPTION :: Different RR Type for DNS
enum RrType
{
        R_INVALID = 0,
        A  = 1,          // an IPv4 host address
        NS,              // an authoritative name server
        MD,              // a mail destination (Obsolete - use MX)
        MF,              // a mail forwarder (Obsolete - use MX)
        CNAME,           // the canonical name for an alias
        SOA,             // marks the start of a zone of authority
        MB,              // a mailbox domain name (EXPERIMENTAL)
        MG,              // a mail group member (EXPERIMENTAL)
        MR,              // a mail rename domain name (EXPERIMENTAL)
        NIL,             // a null RR (EXPERIMENTAL)
        WKS,             // a well known service description
        PTR,             // a domain name pointer
        HINFO,           // host information
        MINFO,           // mailbox or mail list information
        MX,              // mail exchange
        TXT,             //  text strings
        AAAA = 28        // an IPv6 host address
} ;

// ENUM        :: RrClass
// DESCRIPTION :: Different RR Type for DNS
enum RrClass
{
    IN = 1,          //1 // the Internet
    CS,              //2 // the CSNET class (Obsolete)
    CH,              //3 // the CHAOS class
    HS               //4 // Hesiod
};

// ENUM        :: DNSMessageType
// DESCRIPTION :: Different Types of message used in DNS
enum DnsMessageType
{
        DNS_NOTIFY,
        DNS_UPDATE,
        DNS_QUERY,
        DNS_RESPONSE,
        DNS_ADD_SERVER
};

// STRUCT      :: DnsRrRecord
// DESCRIPTION :: Structure for Resource Record format
struct DnsRrRecord
{
    enum RrType rrType;
    enum RrClass rrClass;
    clocktype ttl;
    UInt32 rdLength;
    UInt32 pad;
    Address associatedIpAddr;
    char associatedDomainName[DNS_NAME_LENGTH];
};

typedef list<struct DnsRrRecord*>                      DnsRrRecordList;


// STRUCT      :: DnsServerZoneTransferClient
// DESCRIPTION :: Diffreent Parameters dor the Zone Transfer Client
struct DnsServerZoneTransferClient
{
    Int32  connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL sessionIsClosed;
    Int32  itemSize;
    Int32 itemsToSend;
    Int64 numBytesSent;
    clocktype endTime;
    clocktype lastItemSent;
    Int32 uniqueId;
    TosType tos;
    void* dataSentPtr;
};

// STRUCT      :: DnsServerZoneTransferServer
// DESCRIPTION :: Diffreent Parameters dor the Zone Transfer Server
struct DnsServerZoneTransferServer
{
    Int32  connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL sessionIsClosed;
    Int64 numBytesRecvd;
    clocktype lastItemRecvd;
};
//DnsServerZoneSlave;

// VARIOUS MESSAGE STRUCTURE

// STRUCT      :: DnsCommonHeader
// DESCRIPTION ::  DNS Common Header parameters

struct DnsCommonHeader
{
    UInt16 dns_id;
    UInt16 dns_hdr;
    UInt16 qdCount;
    UInt16 anCount;
    UInt16 nsCount;
    UInt16 arCount;
};


// STRUCT      :: DnsQuestion
// DESCRIPTION :: Structure for question section of DNS messages

struct DnsQuestion
{
    char dnsQname[DNS_NAME_LENGTH];
    enum RrType dnsQType;
    enum RrClass dnsQClass;
};

// STRUCT      :: DnsUpdateZone
// DESCRIPTION :: Structure for header structure of DNS Update zone
//                information packet
struct DnsUpdateZone
{
    char dnsZonename[DNS_NAME_LENGTH];
    enum RrType dnsZoneType;
    enum RrClass dnsZoneClass;
};

// Each link of dnsAnswer, dnsAuthority, dnsAdditional
// represents RR Record

// STRUCT      :: DnsZoneHeader
// DESCRIPTION ::  DNS Zone Common Header parameters
struct DnsZoneHeader{
    UInt16 dns_id;
    UInt16 dns_hdr;
    UInt16 zoCount;
    UInt16 prCount;
    UInt16 upCount;
    UInt16 adCount;
};

// STRUCT      :: DnsZoneTransferPacket
// DESCRIPTION :: General structure for  DNS Zone message
struct DnsZoneTransferPacket
{
    struct DnsZoneHeader dnsHeader;
    struct DnsUpdateZone dnsZone;

    // Dynamically allocating next part.

};


// STRUCT      :: DnsQueryPacket
// DESCRIPTION :: General structure for  DNS Query message
struct DnsQueryPacket
{
    struct DnsCommonHeader dnsHeader;
    struct DnsQuestion dnsQuestion;

    // Dynamically allocating next part.
    // DnsRrRecord dnsAnswer;
    // DnsAuthority dnsAuthority;
    // DnsAdditional dnsAdditional;
};

// STRUCT      :: DnsTreeInfo
// DESCRIPTION :: DNS server tree Data structure
struct DnsTreeInfo
{
    NodeAddress parentId;
    char domainName[DNS_NAME_LENGTH];
    Int32  level;
    Int32 zoneId;
    clocktype timeAdded;
};

// STRUCT      :: CacheRecord
// DESCRIPTION :: DNS server Cache Record
struct CacheRecord
{
    //char      urlNameString[DNS_NAME_LENGTH];;
    std::string* urlNameString;
    Address   associatedIpAddr;
    BOOL      deleted;
    clocktype cacheEntryTime;
};

//
// STRUCT      :: DnsServerData
// DESCRIPTION :: Data item structure used by DNS Server
//
struct DnsServerData
{
    struct DnsTreeInfo* dnsTreeInfo;
    DnsRrRecordList* rrList;
};

// STRUCT      :: ZonePrimaryServerInfo
// DESCRIPTION :: Data item structure used by DNS Server
//
struct ZonePrimaryServerInfo
{
    UInt32 zoneId;
    BOOL exists;

};

typedef list<Address*> ServerList;

// STRUCT      :: DnsClientData
// DESCRIPTION :: Data item structure used by DNS Client Node
// **/
struct DnsClientData
{
    Int16 interfaceNo;
    Address primaryDNS;
    Address secondaryDNS;
    //defined for handleing the case when preferred and alternate
    // DNS server are DulaIP node
    Address ipv6PrimaryDNS;
    Address ipv6SecondaryDNS;
    char* fqdn;
    Address oldIpAddress;
    Address ipv6Address;
    NetworkProtocolType networkType;
    BOOL isDnsAsignedDynamically;
    Address resolvedNameServer;
    Int16 retryCount;
    Message* nextMessage;
    BOOL isNameserverResolved;
    BOOL isUpdateSuccessful;
    ServerList* nameServerList;
    BOOL receivedNsQueryResult;
    BOOL rootQueried;
    Int16 rootQueriedCount;
};



// STRUCT      :: ClientResolveState
// DESCRIPTION :: Data Structure for resolve State of DNS Client
struct ClientResolveState
{
    //char queryUrl[DNS_NAME_LENGTH];
    std::string* queryUrl;
    //BOOL isResolvedPdns;//no need of this
    //BOOL isResolvedSdns;
    Address primaryDNS;
    Address secondaryDNS;

};

// STRUCT      :: DnsStat
// DESCRIPTION :: Satistics Parameters for DNS enable Nodes
struct DnsStat
{
    Int32 numOfDnsUpdateSent;
    Int32 numOfDnsUpdateRecv;

    Int32 numOfDnsQuerySent;
    Int32 numOfDnsSOAQuerySent;
    Int32 numOfDnsNSQuerySent;

    Int32 numOfDnsQueryRecv;
    Int32 numOfDnsReplySent;

    Int32 numOfDnsReplyRecv;
    Int32 numOfDnsSOAReplyRecv;
    Int32 numOfDnsNSReplyRecv;

    Int32 numOfDnsNameResolved;
    Int32 numOfDnsNameUnresolved;
    Int32 numOfDnsNameResolvedFromCache;

    clocktype avgDelayForSuccessfullAddressResolution;
    clocktype avgDelayForUnsuccessfullAddressResolution;
    Int32 numOfDnsNotifySent;
    Int32 numOfDnsNotifyResponseSent;

    Int32 numOfDnsUpdateRequestsSent;
    Int32 numOfDnsUpdateRequestsReceived;
};


// /**
// STRUCT      :: struct_Associated_data
// DESCRIPTION :: Zone Information for DNS ZONE TRANSFER Server and Client
// **/
typedef struct struct_Associated_data
{
    Address zoneServerAddress;
    char tempLabel[DNS_NAME_LENGTH];
    BOOL isZoneMaster;
    clocktype timeAdded;
} data;



// STRUCT      :: RetryQueueData
// DESCRIPTION :: Zone Information for DNS ZONE TRANSFER Server and Client

struct RetryQueueData
{
    Address zoneServerAddress;
    Int32 countRetrySent;
    struct DnsQueryPacket dnsNotifyPacket;
};


// STRUCT      :: NotifyReceivedData
// DESCRIPTION :: Zone Information for DNS ZONE TRANSFER Server and Client
struct NotifyReceivedData
{
    Address zoneServerAddress;
    BOOL duplicate;
};

typedef list<data*>                  ZoneDataList;
typedef list<struct RetryQueueData*>        RetryQueueList;
typedef list<struct NotifyReceivedData*>    NotifyReceivedList;

// /**
// STRUCT      :: ZoneData
// DESCRIPTION :: Zone Information for DNS ZONE TRANSFER Server and Client
// **/
struct ZoneData
{
    BOOL isMasterOrSlave;
    UInt32 zoneFreshCount;
    ZoneDataList* data;
    RetryQueueList* retryQueue; //This will be added for DNS Notify for Zone
                            //Master to track the slaves to whom Notify
                            //msg has been sent
    NotifyReceivedList* notifyRcvd; // This will be added for DNS Notify for
                            // Zone Slaves to track the DNS notify messages
                            //received
};

typedef list<Int16*>        AppReqInterfaceList;

// STRUCT      :: DnsAppReqListItem
// DESCRIPTION :: Data Structure for storing those application
//                Information, which request for DNS Service
//                to resolve the Server URL
struct DnsAppReqListItem
{
    //char serverUrl[DNS_NAME_LENGTH];
    std::string* serverUrl;
    AppType appType;
    //VOIP-DNS Changes
    //short sourcePort;
    UInt16 sourcePort;
    //VOIP-DNS Changes Over
    clocktype resolveStartTime;
    clocktype resolveEndTime;
    Int32 uniqueId;
    BOOL tcpMode ;
    Address addr;
    //LinkedList* appList;
    AppReqInterfaceList* interfaceList;
    Int16 retryCount;
    Int16 interfaceId;
    BOOL AAAASend;
    BOOL ASend;
    NetworkType queryNetworktype;
};

// STRUCT      :: AppDnsInfoTimer
// DESCRIPTION :: Data Structure for storing DNS timer info

struct AppDnsInfoTimer
{
    AppType type;       // timer type
    Int32 uniqueId;     // which connection this timer is meant for
    // VOIP-DNS Changes
    UInt16 sourcePort;   // the port of the session this timer is meant for
    //char serverUrl[DNS_NAME_LENGTH];
    std::string* serverUrl;
    //VOIP-DNS Changes Over
    BOOL tcpMode;
    Address addr;
    Int16 interfaceId;
    NetworkType sourceNetworktype;
};


// STRUCT      :: TcpConnInfo
// DESCRIPTION :: Data Structure for storing DNS TCP connecion info

struct TcpConnInfo
{
    Int32 totalFragment;
    char* packetToSend;
    char* tempPtr;
    TransportToAppDataReceived* dataRecvd;
    Int32 upCount;
};

typedef list<struct DnsAppReqListItem*>            DnsAppReqItemList;
typedef list<struct CacheRecord*>                  CacheRecordList;
typedef list<struct DnsClientData*>                DnsClientDataList;
typedef list<struct ClientResolveState*>           ClientResolveStateList;
typedef list<struct DnsServerZoneTransferServer*> ServerZoneTransferDataList;
typedef list<struct DnsServerZoneTransferClient*> ClientZoneTransferDataList;
typedef list<struct TcpConnInfo*>                  TcpConnInfoList;
typedef list<data*>                         NameServerList;


// STRUCT      :: DnsData
// DESCRIPTION :: Data item structure commonly used by DNS host and server

struct DnsData
{
    CacheRecordList* cache;      // linked list for Cache maintainance
    clocktype  cacheRefreshTime; // Time interval for CAche refreshing
    struct DnsStat stat;
    DnsAppReqItemList* appReqList;
    DnsClientDataList* clientData;   //linked list for storing Pimary and
                              // Secondary DNS Server
    struct ZoneData* zoneData;
    struct DnsServerData* server;  // DNS server data structure
    ClientResolveStateList* clientResolveState;
    BOOL dnsServer;

    //void *zoneTransferServerData;
    ServerZoneTransferDataList* zoneTransferServerData;
    ClientZoneTransferDataList* zoneTransferClientData;
    BOOL  dnsStats;
    //Int32 totalFragment;
    //char *packetToSend;
    //char *tempPtr;
    //TransportToAppDataReceived *dataRecvd;
    //Int32 upCount;
    TcpConnInfoList* tcpConnDataList;
    void* dataSentPtr;
    BOOL inNSrole;
    Address nsParentAddress;
    NameServerList* nameServerList;
    BOOL inSrole;
    BOOL isSecondaryActivated;
    char secondryDomain[DNS_NAME_LENGTH];
    clocktype secondaryTimeAdded;
    Message* addServer;
    Address secParentddress;
    Message* secZoneRefreshTimerMsg;
    clocktype lastZoneTransferTime;
    //BOOL AAAASend;
    //BOOL ASend;
    //char *fqdn;
};


//
// ENUM        :: DnsServerRole
// DESCRIPTION :: Different roles of Dns Server
//
enum DnsServerRole
{
    Primary = 0,//zone primary
    Secondary,    //Secondary
    NameServer    //Name Server
};


// ENUM        :: Rcode
// DESCRIPTION :: Different response code of url query
enum Rcode
{
    NOERROR = 0,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
    YXDOMAIN,
    YXRRSET,
    NXRRSET,
    NOTAUTH,
    NOTZONE
};



struct SupperAppReqInfo
{
    char* inputString;

    Address sourceAddr;
    //VOIP-DNS Changes
    //short sourcePort;
    UInt16 sourcePort;
    //VOIP-DNS Changes Over
    Address destAddr;
    short destPort;
};

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsConfigurationParametersInit
// LAYER        :: Application Layer
// PURPOSE      :: Initialization of DNS Config Parameters
// PARAMETERS   :: node - Pointer to node.
//                 nodeInput - Configuration Information
// RETURN       :: None
//--------------------------------------------------------------------------
void
AppDnsConfigurationParametersInit(Node* node,
                                  const NodeInput* nodeInput);


//--------------------------------------------------------------------------
// FUNCTION     :: DnsFinalize
// LAYER        :: Application Layer
// PURPOSE      :: Dns Finalization
// PARAMETERS   :: node - Partition Data Ptr
// RETURN       :: None
//--------------------------------------------------------------------------
void
DnsFinalize(Node* node);

//--------------------------------------------------------------------------
// FUNCTION     :: DnsZoneListInitialization
// LAYER        :: Application Layer
// PURPOSE      :: Zone List Initialization for MAster of the Zone
// PARAMETERS   :: node - Node Ptr
// RETURN       :: None
//--------------------------------------------------------------------------

void
DnsZoneListInitialization(Node* node);


//--------------------------------------------------------------------------
// FUNCTION     :: App_DnsRquest
// LAYER        :: Application Layer
// PURPOSE      :: Application request Dns to Resolve Addr
// PARAMETERS   :: node - Partition Data Ptr
//                 type - Application type
//                 uniqueId - Unique ID
//                 tcpMode - tcp mode
//                 localAddr - local address
//                 startTime - start time of application
//                 sourceNetworktype - source network type
// RETURN       :: None
//--------------------------------------------------------------------------

void
App_DnsRquest(Node* node,
              AppType type,
              UInt16 sourcePort,
              Int32 uniqueId,
              BOOL tcpMode,
              Address* localAddr,
              std::string serverUrl,
              clocktype startTime,
              NetworkType sourceNetworktype = NETWORK_INVALID);

//--------------------------------------------------------------------------
// FUNCTION     :: ADDR_IsUrl
// LAYER        :: Application Layer
// PURPOSE      :: Check for a string if is it a URL address
// PARAMETERS   :: const char* - Destination String
// RETURN       :: BOOL - TRUE if its is URL otherwise FALSE
//--------------------------------------------------------------------------
BOOL
ADDR_IsUrl(const char* destString);

//--------------------------------------------------------------------------
// FUNCTION     :: AppLayerDnsClient
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message served by DNS Client
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void
AppLayerDnsClient(Node* node, Message* msg);

//--------------------------------------------------------------------------
// FUNCTION     :: AppLayerDnsServer
// LAYER        :: Application Layer
// PURPOSE      :: Diffrent Type of Message processing by DNS Server
// PARAMETERS   :: node - Pointer to node.
//                 msg - Pointer to Message
// RETURN       :: None
//--------------------------------------------------------------------------
void
AppLayerDnsServer(Node* node,Message* msg);

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsComputeDomainName
// LAYER        :: Application Layer
// PURPOSE      :: computes domain name
// PARAMETERS   :: node - Pointer to node.
//                 label - label
//                 zoneId - zone id,
//                 level -  level
//                 treeStructureInput - pointer to node input
//                 parentNodeId -  parent node id
//                 domain - domain
// RETURN       :: None
//--------------------------------------------------------------------------

void
AppDnsComputeDomainName(Node* node,
                         char* label,
                         Int32 zoneId,
                         UInt32 level,
                         const NodeInput* treeStructureInput,
                         NodeAddress parentNodeId,
                         char* domain);

//--------------------------------------------------------------------------
// FUNCTION     :: AppDnsAddServerRRToParent
// LAYER        :: Application Layer
// PURPOSE      :: Adds server RR to parent
// PARAMETERS   :: node - Pointer to node.
//                 serverLabel - server label
//                 serverAddress - server address
//                 parentAddress - parent address
// RETURN       :: None
//--------------------------------------------------------------------------

void AppDnsAddServerRRToParent(Node* node,
                        char* serverLabel,
                        Address serverAddress,
                        Address parentAddress);
                        //clocktype timeAdded);

extern Int32
MAPPING_CompareAddress(
    const Address& address1,
    const Address& address2);

//--------------------------------------------------------------------------
// FUNCTION              : AppDnsGetAppServerAddressAndNode
// PURPOSE               : get application server address and node
// PARAMETERS            ::
// + node                : Node*         : node
// + destString          : char*         : destination address string
// + destAddr            : Address*      : application server address
// + serverDnsClientData : struct DnsClientData*: dns client data of
//                                         application server
// RETURN                ::
// Node*                 : server node
//--------------------------------------------------------------------------

Node*
AppDnsGetAppServerAddressAndNode(
                            Node* node,
                            char* destString,
                            Address* destAddr,
                            struct DnsClientData* serverDnsClientData);

//--------------------------------------------------------------------------
// NAME         : AppCheckValidUrl
// PURPOSE:     Used to check whether given URL is valid or not.
// PARAMETERS   ::
// + destString   : char*: stores server URL
// + isMdpEnabled : bool : TRUE if MDP is enabled
// + appType      : AppType : application type
// RETURN:      none.
//--------------------------------------------------------------------------
void AppCheckValidUrl(
                    char* destString,
                    bool isMdpEnabled,
                    char* appStr);

//---------------------------------------------------------------------------
// NAME           : AppSetDnsInfo.
// PURPOSE        : Used to set DNS info in client pointer.
// PARAMETERS::
// + node         : Node* : pointer to the node,
// + serverUrl    : char* : stores server URL
// + clientPtr    : T* : pointer storing client pointer
// RETURN         : NONE
//---------------------------------------------------------------------------
void
AppSetDnsInfo(Node* node, char* url, char** serverUrl);



//--------------------------------------------------------------------------
// NAME        : AppSendDnsRequest.
// PURPOSE     : Used to send DNS request for a tcp application client.
// PARAMETERS:
// + node      : Node*     : pointer to the node,
// + startTime : clocktype : start time of apllication session
// + appType   : AppType   : application source type
// + clientPtr : T*        : pointer storing client pointer
// RETURN      : NONE
//--------------------------------------------------------------------------
void
AppSendDnsRequest(
                Node* node,
                clocktype startTime,
                AppType appType,
                //T* clientPtr
                Address localAddr,
                UInt32 uniqueId,
                std::string url);

//--------------------------------------------------------------------------
// NAME        : AppDnsCheckForLocalHost.
// PURPOSE     : Used to check if destination string is localhost and update
//               destination address accordingly
// PARAMETERS:
// + node       : Node*    : pointer to the node,
// + sourceAddr : Address  : soirce address
// + destString : char     : destination string
// + destAddr   : Address* : updated destination address if localhost
// RETURN      :
// bool        : TRUE if localhost and destination address updated
//--------------------------------------------------------------------------

bool AppDnsCheckForLocalHost(
                    Node* node,
                    Address sourceAddr,
                    char* destString,
                    Address* destAddr);

//--------------------------------------------------------------------------
// NAME        : AppDnsConcatenatePeriodIfNotPresent.
// PURPOSE     : Used to concatenate a period to domain names, application
//               urls and urls specified in hosts file if it is not explicitly
//               specified
// PARAMETERS:
// + destString : std::string*     : destination string
// RETURN       :
// void         : NULL
//--------------------------------------------------------------------------

void AppDnsConcatenatePeriodIfNotPresent(
            std::string* destString);

#endif
