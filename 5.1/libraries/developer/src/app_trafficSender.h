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

#ifndef _APP_TRAFFIC_SENDER_H_
#define _APP_TRAFFIC_SENDER_H_

#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif // ADDON_DB

#define NO_UDP_FRAG -1

// Structure to store the information which is required for sending a UDP
// based application packet
struct AppUdpPacketSendingInfo
{
    UInt32 itemSize;
    STAT_AppStatistics* stats;
    StatsDBAppEventParam appParam;
    Int32 fragNo;
    Int32 fragSize;
};

// Structure to store the UDP message with the message details
struct AppBufferedUdpPacket
{
    Message* msg;
    Int32 itemSize;
    Int32 fragSize;
    Int32 fragNo;
};

// Function pointer that will be called when application session starts and
// packet need to be sent
typedef
bool (*AppplicationStartCallBack)(
                                Node* node,
                                Address* serverAddr,
                                UInt16 sourcePort,
                                Int32 uniqueId,
                                Int16 interfaceId,
                                std::string serverUrl,
                                AppUdpPacketSendingInfo* packetSendingInfo);

typedef std::list<AppBufferedUdpPacket*> UdpBufferedPacketList;
typedef std::string UrlStringType;
typedef std::list<AppTcpOpenTimer*> TcpOpenConnList;
typedef std::map<UrlStringType, UdpBufferedPacketList*> AppUdpPacketBufferMap;
typedef std::map<UrlStringType, TcpOpenConnList*> AppTcpOpenRequestBufferMap;
typedef std::map<std::string, Address> AppUrlToAddressCache;
typedef std::set<AppplicationStartCallBack> AppSessionStartHandlerList;
typedef std::map<std::string, std::list<UInt16> > AppUrlSourcePortMap;

// Traffic Sender class which will take care of processing  that is not
// specific to application and has been added to support other models
class AppTrafficSender
{
    public:

//---------------------------------------------------------------------------
// FUNCTION              : AppTrafficSender
// PURPOSE               : constructor
// PARAMETERS            :: NONE
// RETURN                :: NONE
//---------------------------------------------------------------------------
         AppTrafficSender();

//---------------------------------------------------------------------------
// FUNCTION              : finalize
// PURPOSE               : finalization function; to free the memory and
//                         statistics printing
// PARAMETERS            ::
// + node                   : Node* : pointer to node
// RETURN                :: NONE
//---------------------------------------------------------------------------
        void finalize(Node* node);

//---------------------------------------------------------------------------
// FUNCTION     : applicationClientDnsInit
// PURPOSE      : DNS specific initialization for an application
//                session
// PARAMETERS   ::
// + node           : Node*     : pointer to node
// + inputString    : char*     : application configuration string
// + destAddr       : Address*  : destination address ; this will
//                                be updated based on DNS processing
// + sourceAddr     : Address*  : source address; this will
//                                be updated based on DNS processing
// + destNodeId     : NodeId*   : destination node id as reterived
//                                from DNS data
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       ::
// Address      : url destination address
//---------------------------------------------------------------------------
        Address applicationClientDnsInit(
                Node* node,
                char* inputString,
                Address* destAddr,
                Address* sourceAddr,
                NodeId* destNodeId,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION              : getAppServerAddressAndNodeFromUrl
// PURPOSE               : get application server address and node from url
// PARAMETERS            ::
// + node                : Node*            : node pointer
// + destString          : char*            : destination address string
// + destAddr            : Address*         : application server address to
//                                            be updated by dns data
// + serverDnsClientData : DnsClientData*   : dns client data of application
//                                            server; updated by dns
// RETURN                ::
// Node*                 : server node if found; NULL if not found
//---------------------------------------------------------------------------
        Node* getAppServerAddressAndNodeFromUrl(
                    Node* node,
                    char* destString,
                    Address* destAddr,
                    struct DnsClientData* serverDnsClientData);

//---------------------------------------------------------------------------
// NAME         : appClientSetDnsInfo.
// PURPOSE      : Used to set DNS info in client pointer.
// PARAMETERS   ::
// + node           : Node*         : pointer to the node,
// + configuredUrl  : const char*   : stores the url that need to be copied
//                                    into client pointer url; read from .app
//                                    file
// + clientUrlPtr   : std::string*  : client pointer url string
// RETURN           :: NONE
//---------------------------------------------------------------------------
        void appClientSetDnsInfo(
                    Node* node,
                    const char* configuredUrl,
                    std::string* clientUrlPtr);

//---------------------------------------------------------------------------
// FUNCTION     : appUdpSend
// PURPOSE      : models the UDP based application packet sending. This
//                function buffers the application packet if corresponding
//                URL is not resolved. It also sends the data packet if URL
//                is resolved or there is no URL
// PARAMETERS   ::
// + node           : Node*         : pointer to node
// + msg            : Message*      : data packet
// + url            : std::string   : server url
// + clientAddr     : Address       : client address
// + appType        : AppType       : application type
// + sourcePort     : UInt16        : source port
// + packetSendingInfo  : AppUdpPacketSendingInfo      : udp packet sending
//                                                       info
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void appUdpSend(
                    Node* node,
                    Message* msg,
                    std::string url,
                    Address clientAddr,
                    AppType appType,
                    UInt16 sourcePort,
                    AppUdpPacketSendingInfo packetSendingInfo);

//---------------------------------------------------------------------------
// FUNCTION     : lookupUrlInAddressCache
// PURPOSE      : search for address of an URL in url address cache
// PARAMETERS   ::
// + url        : UrlStringType : url to be searched
// RETURN       ::
// Address      : address corresponding to url if found
//                address with network type as NETWORK_INVALID if not found
//---------------------------------------------------------------------------
        Address lookupUrlInAddressCache(UrlStringType url);

//---------------------------------------------------------------------------
// FUNCTION     : addApplicationDnsResolveFunction
// PURPOSE      : add callback function in list of functions that will be
//                called when url is resolved
// PARAMETERS   ::
// + node                       : Node*             : pointer to node
// + appStartFunctionPointer    : AppplicationStartCallBack :
//                                               application start
//                                               function pointer
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void addApplicationStartFunction(
                Node* node,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : processEvent
// PURPOSE      : layer function of traffic sender
// PARAMETERS   ::
// + node : Node*   : pointer to node
// + msg  : Message : event to be processed
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void processEvent(Node* node, Message* msg);

//---------------------------------------------------------------------------
// FUNCTION     : insertOpenRequestInTcpBuffer
// PURPOSE      : insert TCP open Info in TCP Open request buffer
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + appType            : AppType       : application type
// + localAddr          : Address*      : client address
// + localPort          : UInt16        : source port
// + remoteAddr         : Address       : server address
// + remotePort         : UInt16        : server port
// + uniqueId           : UInt32        : connection id
// + priority           : TosType       : priority
// + outgoingInterface  : Int32         : outgoing interface
// + url                : UrlStringType : server URL
// + startTime          : clocktype     : start time of application
// + destNodeId         : NodeId        : destination node id
// + clientInterfaceIndex   : Int16     : client interface index
// + destInterfaceIndex : Int16         : destination interface index
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void insertOpenRequestInTcpBuffer(
                                Node* node,
                                AppType appType,
                                Address localAddr,
                                UInt16 localPort,
                                Address remoteAddr,
                                UInt16 remotePort,
                                Int32 uniqueId,
                                TosType priority,
                                Int32 outgoingInterface,
                                UrlStringType url,
                                clocktype startTime,
                                NodeId destNodeId,
                                Int16 clientInterfaceIndex,
                                Int16 destInterfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION     : checkIfValidUrl
// PURPOSE      : validated the URL and checks if this is applicable for
//                this application session
// PARAMETERS   ::
// + node           : Node*         : pointer to node
// + destString     : std::string   : destination string
// + isMdpEnabled   : bool          : TRUE if MDP is enabled (dns not
//                                    supported if MDP enabled)
// + appStr         : const char*   : application string
// + destAddr       : Address*      : destination address ; this will
//                                    be updated with 0 if destination string
//                                    is URL
// RETURN       ::
// bool         : TRUE if url FALSE if not url
//---------------------------------------------------------------------------
    bool checkIfValidUrl(
                Node* node,
                std::string destString,
                bool isMdpEnabled,
                const char* appStr,
                Address* destAddr);

//---------------------------------------------------------------------------
// FUNCTION     : httpDnsInit
// PURPOSE      : dns specific http initialization done as fomat of HTTP
//                configuration is different from other applications
// PARAMETERS   ::
// + node                       : Node*     : pointer to node
// + sourceString               : char*     : source string
// + destString                 : char*     : destination string
// + destAddress                : Address*  : server address; will get
//                                            updated based on dns-data
// + sourceAddr                 : Address*  : source address; will get
//                                            updated based on dns-data
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void httpDnsInit(
                Node* node,
                char* sourceString,
                char* destString,
                Address* destAddr,
                Address* sourceAddr,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : superApplicationDnsInit
// PURPOSE      : dns specific super-application initialization done as
//                initialization of super-application is different from
//                other applications
// PARAMETERS   ::
// + node               : Node*     : pointer to node
// + inputString        : char*            : input sting
// + nodeInput          : const NodeInput* : node input
// + clientPtr          : SuperApplicationData* : pointer to super-app client
//                                                data
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void superApplicationDnsInit(
                Node* node,
                char* inputString,
                const NodeInput* nodeInput,
                SuperApplicationData* clientPtr,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : H323RasDnsInit
// PURPOSE      : dns specific H323 initialization
// PARAMETERS   ::
// + node               : Node*     : pointer to node
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void H323RasDnsInit(
                Node* node,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : SipDnsInit
// PURPOSE      : dns specific SIP initialization
// PARAMETERS   ::
// + node               : Node*     : pointer to node
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void SipDnsInit(
                Node* node,
                AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : appCheckUrlAndGetUrlDestinationAddress
// PURPOSE      : checks if destination is configured as url and find the
//                url destination address such that application server can be
//                initialized
// PARAMETERS   ::
// + node               : Node*     : pointer to node
// + inputString        : char*     : input sting
// + isMdpEnabled       : bool      : mdp enabled or not
// + sourceAddress      : Address*  : source address; this will
//                                    be updated based on DNS processing
// + destinationAddress : Address*  : destination address; this will
//                                    be updated based on DNS processing
// + destinationNodeId  : NodeId*   : destination node id as reterived
//                                    from DNS data
// + urlDestAddress     : Address*  : url destination address  as reterived
//                                    from DNS data
// + appStartFunctionPointer    : AppplicationStartCallBack:
//                                          callback function pointer to be
//                                          registered for this application
// RETURN       ::
// bool         : TRUE if destination configured as URL FALSE otherwise
//---------------------------------------------------------------------------
    bool appCheckUrlAndGetUrlDestinationAddress(
                        Node* node,
                        char* inputString,
                        bool isMdpEnabled,
                        Address* sourceAddress,
                        Address* destinationAddress,
                        NodeId* destinationNodeId,
                        Address* urlDestAddress,
                        AppplicationStartCallBack appStartFunctionPointer);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpOpenConnection
// PURPOSE      : Opens a TCP connection on specified destination address, if
//                URL then open connection is buffered
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + appType            : AppType       : application type
// + localAddr          : Address*      : client address
// + localPort          : UInt16        : source port
// + remoteAddr         : Address       : server address
// + remotePort         : UInt16        : server port
// + uniqueId           : UInt32        : connection id
// + priority           : TosType       : priority
// + outgoingInterface  : Int32         : outgoing interface
// + url                : UrlStringType : server URL
// + startTime          : clocktype     : start time of application
// + destNodeId         : NodeId        : destination node id
// + clientInterfaceIndex   : Int16     : client interface index
// + destInterfaceIndex : Int16         : destination interface index
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpOpenConnection(
                        Node* node,
                        AppType appType,
                        Address localAddr,
                        UInt16 localPort,
                        Address remoteAddr,
                        UInt16 remotePort,
                        Int32 uniqueId,
                        TosType priority,
                        Int32 outgoingInterface,
                        UrlStringType url,
                        clocktype startTime,
                        NodeId destNodeId,
                        Int16 clientInterfaceIndex,
                        Int16 destInterfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpListen
// PURPOSE      : Starts TCP listen
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + appType            : AppType       : application type
// + serverAddr         : Address       : server address
// + serverPort         : UInt16        : server port
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpListen(
                    Node *node,
                    AppType appType,
                    Address serverAddr,
                    UInt16 serverPort);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpListenWithPriority
// PURPOSE      : Start TCP listen with priority
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + appType            : AppType       : application type
// + serverAddr         : Address       : server address
// + serverPort         : UInt16        : server port
// + priority           : TosType       : ptiority
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpListenWithPriority(
                        Node *node,
                        AppType appType,
                        Address serverAddr,
                        UInt16 serverPort,
                        TosType priority);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpCloseConnection
// PURPOSE      : Closes a TCP connection
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + connectionId       : Int32         : connection id
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpCloseConnection(
                        Node *node,
                        Int32 connectionId);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpSend
// PURPOSE      : sends a TCP packet
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + msg                : Message*      : message
// + appParam           : StatsDBAppEventParam*  : Stat DB application
//                                                 parameter
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpSend(
                    Node *node,
                    Message* msg
#ifdef ADDON_DB
                    ,StatsDBAppEventParam* appParam = NULL
#endif
                    );


//---------------------------------------------------------------------------
// FUNCTION     : ifUrlLocalHost
// PURPOSE      : check if url is localhostt
// PARAMETERS   ::
// + urlString  : std::string   : url string
// RETURN       ::
// bool         : TRUE is if it localhost FALSE otherwise
//---------------------------------------------------------------------------
    bool ifUrlLocalHost(std::string urlString);

    private:
        // Map to store the UDP based application packets such that they are
        // sent when DNS is resolved
        AppUdpPacketBufferMap udpPacketBuffer;

        // Map to store the TCP Open Connection info such that TCP open
        // request can be scheduled when URL is resolved for an application
        AppTcpOpenRequestBufferMap tcpOpenRequestBufferMap;

        // Map to store the address of URL that are resolved for any node.
        AppUrlToAddressCache urlToAddressCache;

        // Set to store the callback functions to be called when URL is
        // resolved and application session starts
        AppSessionStartHandlerList sessionStartHandlerList;

        // List to store the application port numbers for which dns request
        // sent
        AppUrlSourcePortMap sourcePortMap;

//---------------------------------------------------------------------------
// NAME         : checkValidAppUrl
// PURPOSE:     : Used to check whether URL is valid for this application
//                session.
// PARAMETERS   ::
// + destString   : std::string : stores server URL
// + isMdpEnabled : bool        : TRUE if MDP is enabled
// + appStr       : const char* : application string to get the application
//                                type for informing the user about error
// RETURN :      NONE.
//---------------------------------------------------------------------------
        void checkValidAppUrl(
                    std::string* destString,
                    bool isMdpEnabled,
                    const char* appStr);

//---------------------------------------------------------------------------
// FUNCTION     : appSendDnsRequest
// PURPOSE      : send DNS request packet
// PARAMETERS   ::
// + node       : Node*             : pointer to node
// + serverUrl  : std::string       : server URL
// + clientAddr : Address           : client address
// + appItem    : DnsAppReqListItem : dns data
// + appType    : AppType           : application type
// + sourcePort : UInt16            : source port
// + timerType  : Int32             : timer which has expired for sending
//                                    DNS request
// + tcpMode    : bool              : TRUE if TCP based application
// + uniqueId   : UInt32            : connection id for TCP based application
// + startTime  : clocktype         : start time of application
// RETURN       ::
// bool         : TRUE if DNS request sent FALSE otherwise
//---------------------------------------------------------------------------
        bool appSendDnsRequest(
                    Node* node,
                    std::string serverUrl,
                    Address clientAddr,
                    struct DnsAppReqListItem* appItem,
                    AppType appType,
                    UInt16 sourcePort,
                    Int32 timerType,
                    bool tcpMode = FALSE,
                    UInt32 uniqueId = -1,
                    clocktype startTime = 0);

//---------------------------------------------------------------------------
// FUNCTION     : sendTcpOpenConnection
// PURPOSE      : send TCP Open request when URL is resolved
// PARAMETERS   ::
// + node   : Node*             : pointer to node
// + timer  : AppDnsInfoTimer   : dns timer info
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void sendTcpOpenConnection(
                            Node* node,
                            struct AppDnsInfoTimer* timer);

//---------------------------------------------------------------------------
// FUNCTION     : insertUrlAddressInCache
// PURPOSE      : insert a URL and corresponding address in cache
// PARAMETERS   ::
// + url        : std::string     : url string
// + address    : Address         : address corresponding to url
// RETURN       :: NONE
//---------------------------------------------------------------------------
        void insertUrlAddressInCache(
                                std::string url,
                                Address address);

//---------------------------------------------------------------------------
// FUNCTION     : insertPacketInUdpBuffer
// PURPOSE      : insert application packet in UDP buffer
// PARAMETERS   ::
// + msg        : Message*      : packet to be inserted
// + url        : std::string   : url the packet is destined to
// + sourcePort : UInt16        : source port for the application packet
// + itemSize   : Int32         : item size of current packet
// + fragSize   : Int32         : fragsize if this is fragment else 0
// + fragNo     : Int32         : fragment number if this is fragment else -1
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void insertPacketInUdpBuffer(
                            Message* msg,
                            std::string url,
                            UInt16 sourcePort,
                            Int32 itemSize,
                            Int32 fragSize,
                            Int32 fragNo);

//---------------------------------------------------------------------------
// FUNCTION              : getAppServerNodeFromDestString
// PURPOSE               : get the dns data and server node from server url
//                         using dns data structure
// PARAMETERS            ::
// + node                : Node*            : node
// + serverDnsClientData : DnsClientData*   : dns client data at this node
// + destString          : const char*      : destination address string
// RETURN                ::
// Node*    : application server node
//---------------------------------------------------------------------------
         Node* getAppServerNodeFromDestString(
                    Node* node,
                    DnsClientData* serverDnsClientData,
                    const char* destString);

//---------------------------------------------------------------------------
// FUNCTION     : getAppPacketListToSend
// PURPOSE      : get the list of application packet from udp packet buffer
// PARAMETERS   ::
// + node               : Node*                     : pointer to node
// + serverUrl          : std::string               : event to be processed
// + sourcePort         : UInt16                    : source port
// + returnPacketList   :UdpBufferedPacketList*    : packet list that will
//                                                    returned and will
//                                                    contain buffered
//                                                    packets corresponding
//                                                    to this source port
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void getAppPacketListToSend(
                        Node* node,
                        std::string serverUrl,
                        UInt16 sourcePort,
                        UdpBufferedPacketList* returnPacketList);

//---------------------------------------------------------------------------
// FUNCTION     : ifDnsRequestSent
// PURPOSE      : check if dns request sent for this source port
// PARAMETERS   ::
// + url        : std::string           : url string
// + sourcePort : UInt16                : source port for which the packets
// RETURN       ::
// bool         : TRUE if dns request sent
//                FALSE if dns request not sent
//---------------------------------------------------------------------------
    bool ifDnsRequestSent(std::string url, UInt16 sourcePort);

//---------------------------------------------------------------------------
// FUNCTION     : addSourcePortForUrl
// PURPOSE      : add source port for dns request sent
// PARAMETERS   ::
// + url        : std::string           : url string
// + sourcePort : UInt16                : source port for which dns request
//                                        sent
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void addSourcePortForUrl(
                        std::string url,
                        UInt16 sourcePort);

//---------------------------------------------------------------------------
// FUNCTION     : sendBufferedUdpPackets
// PURPOSE      : send the buffered UDP packets when URL is resolved
// PARAMETERS   ::
// + node       : Node*                 : pointer to node
// + url        : std::string           : url string
// + sourcePort : UInt16                : source port for which the packets
//                                        need to be send
// + destAddress: Address               : url address
// + packetSendingInfo  : AppUdpPacketSendingInfo      : udp packet sending
//                                                       info
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void sendBufferedUdpPackets(
                        Node* node,
                        std::string url,
                        UInt16 sourcePort,
                        Address destAddress,
                        AppUdpPacketSendingInfo packetSendingInfo);

//---------------------------------------------------------------------------
// FUNCTION     : sendUdpPackets
// PURPOSE      : sends UDP packets
// PARAMETERS   ::
// + node        : Node*                : pointer to node
// + msg         : Message*             : packet to be sent if URL is
//                                        resolved via cache or there is no
//                                        url
// + url         : std::string          : url string
// + sourcePort  : UInt16               : source port of application session
// + destAddress : Address              : remote address
// + packetSendingInfo  : AppUdpPacketSendingInfo*      : udp packet sending
//                                                       info
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void sendUdpPackets(
                Node* node,
                Message* msg,
                std::string url,
                UInt16 sourcePort,
                Address destAddress,
                AppUdpPacketSendingInfo* packetSendingInfo);

//---------------------------------------------------------------------------
// FUNCTION     : appTcpOpenConnTimer
// PURPOSE      : schedules a timer for opening TCP connection such that
//                address information is updated before TCP Open is done
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + appType            : AppType       : application type
// + localAddr          : Address*      : client address
// + localPort          : UInt16        : source port
// + remoteAddr         : Address       : server address
// + remotePort         : UInt16        : server port
// + uniqueId           : UInt32        : connection id
// + priority           : TosType       : priority
// + outgoingInterface  : Int32         : outgoing interface
// + startTime          : clocktype     : start time of application
// + destNodeId         : NodeId        : destination node id
// + clientInterfaceIndex   : Int16     : client interface index
// + destInterfaceIndex : Int16         : destination interface index
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void appTcpOpenConnTimer(
                        Node* node,
                        AppType appType,
                        Address localAddr,
                        UInt16 localPort,
                        Address remoteAddr,
                        UInt16 remotePort,
                        Int32 uniqueId,
                        TosType priority,
                        Int32 outgoingInterface,
                        clocktype startTime,
                        NodeId destNodeId,
                        Int16 clientInterfaceIndex,
                        Int16 destInterfaceIndex);

//---------------------------------------------------------------------------
// FUNCTION     : processTimerDnsSendPacket
// PURPOSE      : process the event when timer DNS_SEND_PACKET expires when
//                URL is not resolved and there is need to send DNS request
//                again
// PARAMETERS   ::
// + node       : Node*         : pointer to node
// + msg        : Message       : message received
// + appType    : AppType       : application type
// + url        : std::string   : url string
// + sourcePort : UInt16        : source port
// + clientAddr : Address       : client address
// + tcpMode    : bool          : TRUE if URL sepcified for TCP application
// + uniqueId   : UInt32        : unique id
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void processTimerDnsSendPacket(
                        Node* node,
                        Message* msg,
                        AppType appType,
                        std::string url,
                        UInt16 sourcePort,
                        Address clientAddr,
                        bool tcpMode = FALSE,
                        UInt32 uniqueId = -1);

//---------------------------------------------------------------------------
// FUNCTION     : sendUdpApplicationPackets
// PURPOSE      : does the sending of UDP application packets and updates
//                the stats
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + sentMsg            : Message*      : message to be sent
// + packetSendingInfo  : AppUdpPacketSendingInfo      : udp packet sending
//                                                       info
// + destAddr           : Address       : destination address
// RETURN       :: NONE
//---------------------------------------------------------------------------
    void sendUdpApplicationPackets(
                        Node* node,
                        Message* sentMsg,
                        AppUdpPacketSendingInfo packetSendingInfo,
                        Address destAddr);
};
#endif //_APP_TRAFFIC_SENDER_H_
