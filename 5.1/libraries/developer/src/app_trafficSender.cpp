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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "app_trafficSender.h"
#include "app_dns.h"
#include "application.h"
#include "network_ip.h"
#include "ipv6.h"

#define SUPERAPPLICATION_TCP   1
#define SUPERAPPLICATION_UDP   2

// Helper function
//---------------------------------------------------------------------------
// FUNCTION     : createTcpOpenInfo
// PURPOSE      : create TCP open Info to be inserted in TCP Open request
//                buffer
// PARAMETERS   ::
// + node               : Node*     : pointer to node
// + appType            : AppType   : application type
// + localAddr          : Address*  : client address
// + localPort          : UInt16    : source port
// + remoteAddr         : Address   : server address
// + remotePort         : UInt16    : server port
// + uniqueId           : UInt32    : connection id
// + priority           : TosType   : priority
// + outgoingInterface  : Int32     : outgoing interface
// + destNodeId         : NodeId        : destination node id
// + clientInterfaceIndex   : Int16     : client interface index
// + destInterfaceIndex : Int16         : destination interface index
// RETURN       ::
// AppTcpOpenTimer*     : TCP open connection info created
//---------------------------------------------------------------------------
AppTcpOpenTimer*
createTcpOpenInfo(
            Node* node,
            AppType appType,
            Address localAddr,
            UInt16 localPort,
            Address remoteAddr,
            UInt16 remotePort,
            Int32 uniqueId,
            TosType priority,
            Int32 outgoingInterface,
            NodeId destNodeId,
            Int16 clientInterfaceIndex,
            Int16 destInterfaceIndex)
{
    AppTcpOpenTimer* openRequest =
                    (AppTcpOpenTimer*) MEM_malloc(sizeof(AppTcpOpenTimer));
    openRequest->tcpOpenInfo.appType = appType;
    openRequest->tcpOpenInfo.localAddr = localAddr;
    openRequest->tcpOpenInfo.localPort = localPort;
    openRequest->tcpOpenInfo.remoteAddr = remoteAddr;
    openRequest->tcpOpenInfo.remotePort = remotePort;

    openRequest->tcpOpenInfo.uniqueId = uniqueId;
    openRequest->tcpOpenInfo.priority = priority;

    // Validate and set outgoing interface
    if (node->numberInterfaces < outgoingInterface ||
        outgoingInterface < ANY_INTERFACE)
    {
        char errString[MAX_STRING_LENGTH];
        sprintf(errString, "Node: %d\n"
            "Value of outgoingInterface is out of range\n", node->nodeId);
        ERROR_ReportWarning(errString);
        openRequest->tcpOpenInfo.outgoingInterface = ANY_INTERFACE;
    }
    else
    {
        openRequest->tcpOpenInfo.outgoingInterface = outgoingInterface;
    }
    openRequest->destNodeId = destNodeId;
    openRequest->clientInterfaceIndex = clientInterfaceIndex;
    openRequest->destInterfaceIndex = destInterfaceIndex;
    return (openRequest);
}

// Public function definition
//---------------------------------------------------------------------------
// FUNCTION              : AppTrafficSender
// PURPOSE               : constructor
// PARAMETERS            :: NONE
// RETURN                :: NONE
//---------------------------------------------------------------------------
AppTrafficSender::AppTrafficSender()
{
    udpPacketBuffer.clear();
    tcpOpenRequestBufferMap.clear();
    urlToAddressCache.clear();
    sessionStartHandlerList.clear();
}

//---------------------------------------------------------------------------
// FUNCTION              : finalize
// PURPOSE               : finalization function; to free the memory and
//                         statistics printing
// PARAMETERS            ::
// + node                   : Node* : pointer to node
// RETURN                :: NONE
//---------------------------------------------------------------------------
void AppTrafficSender::finalize(Node* node)
{
    // delete message stored in packetBuffer
    while (udpPacketBuffer.size() != 0)
    {
        AppUdpPacketBufferMap::iterator it = udpPacketBuffer.begin();
        // traverse the message list
        UdpBufferedPacketList* msgList = (it->second);
        while (msgList && msgList->size() != 0)
        {
            UdpBufferedPacketList::iterator itMsgList = msgList->begin();
            AppBufferedUdpPacket* bufferedMsg =
                                        (AppBufferedUdpPacket*)(*itMsgList);
            msgList->erase(itMsgList);
            MESSAGE_Free(node, bufferedMsg->msg);
            MEM_free(bufferedMsg);
            bufferedMsg = NULL;
        }
        delete (msgList);
        udpPacketBuffer.erase(it);
    }
    udpPacketBuffer.clear();

    // delete open connection in tcpOpenRequestBufferMap
    while (tcpOpenRequestBufferMap.size() != 0)
    {
        AppTcpOpenRequestBufferMap::iterator it =
                                        tcpOpenRequestBufferMap.begin();
        // traverse the message list
        TcpOpenConnList* tcpOpenList = (it->second);
        while (tcpOpenList && tcpOpenList->size() != 0)
        {
            TcpOpenConnList::iterator itTcpOpen = tcpOpenList->begin();
            AppTcpOpenTimer* tcpOpen = (AppTcpOpenTimer*)(*itTcpOpen);
            tcpOpenList->erase(itTcpOpen);
            MEM_free(tcpOpen);
            tcpOpen = NULL;
        }
        delete (tcpOpenList);
        tcpOpenRequestBufferMap.erase(it);
    }
    tcpOpenRequestBufferMap.clear();

    urlToAddressCache.clear();

    sessionStartHandlerList.clear();
}

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
Address AppTrafficSender::applicationClientDnsInit(
                Node* node,
                char* inputString,
                Address* destAddr,
                Address* sourceAddr,
                NodeId* destNodeId,
                AppplicationStartCallBack appStartFunctionPointer)
{
    Address urlDestAddress;
    char sourceString[MAX_STRING_LENGTH];
    char destString[BIG_STRING_LENGTH];
    NodeAddress sourceNodeId = ANY_NODEID;
    Address srcAddr;
    NodeAddress destinationNodeId = ANY_NODEID;
    Address destinationAddr;
    DnsClientData serverDnsClientData;

    sscanf(inputString, "%*s %s %s", sourceString, destString);

    IO_AppParseSourceAndDestStrings(
                    node,
                    inputString,
                    sourceString,
                    &sourceNodeId,
                    &srcAddr,
                    destString,
                    &destinationNodeId,
                    &destinationAddr);

    memcpy (&urlDestAddress, &destinationAddr, sizeof(Address));

    Node* destNode = NULL;

    // get the server node and destAddress of application
    // server
    destNode = getAppServerAddressAndNodeFromUrl(
                                            node,
                                            destString,
                                            &urlDestAddress,
                                            &serverDnsClientData);

    // Register the function that will be called when url is resolved
    addApplicationStartFunction (node, appStartFunctionPointer);

    // return if destination node cannot be found
    if (destNode == NULL)
    {
        // this means URL cannot be resolved as no interface
        // is mapped to this url
        memset (&urlDestAddress, 0, sizeof(Address));
        return (urlDestAddress);
    }
    // if this is localhost then update the destination address
    if (AppDnsCheckForLocalHost(node, srcAddr, destString, &destinationAddr))
    {
        memcpy(destAddr, &urlDestAddress, sizeof(Address));
    }
    *destNodeId = destNode->nodeId;

    if (IO_IsStringNonNegativeInteger(sourceString))
    {
        *sourceAddr = MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
                                                node,
                                                node->nodeId,
                                                urlDestAddress.networkType);
    }

    return (urlDestAddress);
}

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
Node*
AppTrafficSender::getAppServerAddressAndNodeFromUrl(
                            Node* node,
                            char* destString,
                            Address* destAddr,
                            DnsClientData* serverDnsClientData)
{
    Node* destNode = NULL;
    std::string destStringStr(destString);
    AppDnsConcatenatePeriodIfNotPresent(&destStringStr);
    strcpy(destString, destStringStr.c_str());

    // if destination string is localhost
    if (ifUrlLocalHost(destStringStr.c_str()) == TRUE)
    {
        NodeId nodeId = ANY_NODEID;
        NetworkProtocolType sourcetype =
                        NetworkIpGetNetworkProtocolType(node,
                                                        node->nodeId);
        if ((sourcetype == IPV4_ONLY) || (sourcetype == DUAL_IP))
        {
            IO_AppParseDestString(
                                node,
                                NULL,
                                "127.0.0.1",
                                &nodeId,
                                destAddr);
        }
        else if (sourcetype == IPV6_ONLY)
        {
            IO_AppParseDestString(
                                node,
                                NULL,
                                "::1",
                                &nodeId,
                                destAddr);
        }
        destNode = node;
    }
    else
    {
        // initialze server based on dns database at all nodes if it is not
        // localhost
        DnsClientData appServerDnsClientData;
        appServerDnsClientData.interfaceNo = ANY_INTERFACE;
        destNode = getAppServerNodeFromDestString(
                                            node,
                                            &appServerDnsClientData,
                                            destStringStr.c_str());
        memcpy(
            destAddr,
            &appServerDnsClientData.oldIpAddress,
            sizeof(Address));

        memcpy(
            serverDnsClientData,
            &appServerDnsClientData,
            sizeof(struct DnsClientData));
    }
    return (destNode);
}

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
void
AppTrafficSender::appClientSetDnsInfo(
                    Node* node,
                    const char* configuredUrl,
                    std::string* clientUrlPtr)
{
    clientUrlPtr->assign(configuredUrl);
    AppDnsConcatenatePeriodIfNotPresent(clientUrlPtr);
}

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
void
AppTrafficSender::appUdpSend(
                            Node* node,
                            Message* msg,
                            std::string url,
                            Address clientAddr,
                            AppType appType,
                            UInt16 sourcePort,
                            AppUdpPacketSendingInfo packetSendingInfo)
{
    bool msgBuffered = FALSE;
    AppToUdpSend* info = (AppToUdpSend*) MESSAGE_ReturnInfo(msg);

    // check if URL present or not
    if (url.length() != 0)
    {
        // check cache if address found or not
        Address destAddress = lookupUrlInAddressCache(url);
        if (destAddress.networkType != NETWORK_INVALID)
        {
            // address found send the packet by updating the address
            info->destAddr = destAddress;
        }
        else
        {
            // address not found
            // send dns request if not sent and buffer packet
            insertPacketInUdpBuffer(
                            msg,
                            url,
                            sourcePort,
                            packetSendingInfo.itemSize,
                            packetSendingInfo.fragSize,
                            packetSendingInfo.fragNo);
            if (ifDnsRequestSent(url, sourcePort) == FALSE)
            {
                // packet inserted in buffer; send dns request to
                // resolve URL as dns request not sent
                appSendDnsRequest(
                                node,
                                url,
                                clientAddr,
                                NULL,
                                appType,
                                sourcePort,
                                APP_TIMER_SEND_PKT);

                // add source port in source port list
                addSourcePortForUrl(url, sourcePort);
            }
            msgBuffered = TRUE;
        }
    }

    if (msgBuffered == FALSE)
    {
        // if this application session is not configured with url or URL
        // is already resolved
        // call send UDP packets
        msgBuffered = FALSE;
        sendUdpPackets(
                    node,
                    msg,
                    url,
                    sourcePort,
                    info->destAddr,
                    &packetSendingInfo);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : lookupUrlInAddressCache
// PURPOSE      : search for address of an URL in url address cache
// PARAMETERS   ::
// + url        : UrlStringType : url to be searched
// RETURN       ::
// Address      : address corresponding to url if found
//                address with network type as NETWORK_INVALID if not found
//---------------------------------------------------------------------------
Address AppTrafficSender::lookupUrlInAddressCache(UrlStringType url)
{
    Address address;
    memset(&address, 0, sizeof(Address));

    if (urlToAddressCache.size() != 0)
    {
        // traverse the cache and search for matching URL
        AppUrlToAddressCache::iterator it = urlToAddressCache.find(url);
        if (it != urlToAddressCache.end())
        {
            memcpy (&address, &it->second, sizeof(Address));
        }
    }
    return (address);
}

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
void AppTrafficSender::addApplicationStartFunction(
            Node* node,
            AppplicationStartCallBack appStartFunctionPointer)
{
    // insert the function pointer
    sessionStartHandlerList.insert(appStartFunctionPointer);

}

//---------------------------------------------------------------------------
// FUNCTION     : processEvent
// PURPOSE      : layer function of traffic sender
// PARAMETERS   ::
// + node : Node*   : pointer to node
// + msg  : Message : event to be processed
// RETURN       :: NONE
//---------------------------------------------------------------------------
void AppTrafficSender::processEvent(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_APP_DnsInformResolvedAddr:
        {
            AppDnsInfoTimer* timer =
                                (AppDnsInfoTimer*)MESSAGE_ReturnInfo(msg);

            if (MAPPING_GetNodeIdFromInterfaceAddress(node, timer->addr) ==
                INVALID_MAPPING)
            {
#ifdef DEBUG
                printf("Address resoved for URL not mapping to any node\n");
#endif
                break;
            }

            if (sessionStartHandlerList.size() == 0)
            {
                // This is not possible hence error state
                ERROR_ReportErrorArgs(
                        "Traffic Sender: Node %d handler for url %s not"
                        "found \n",
                        node->nodeId,
                        timer->serverUrl->c_str());
            }

            // if the URL is resolved for TCP based application then
            // send TCP Open Conection request
            if (timer->tcpMode == TRUE)
            {
                sendTcpOpenConnection(node, timer);
            }
            else
            {
                // url is resolved for UDP based application
                // call send UDP packets
                sendUdpPackets(
                            node,
                            NULL,
                            *timer->serverUrl,
                            timer->sourcePort,
                            timer->addr,
                            NULL);
            }

            // store the address in url address cache
            insertUrlAddressInCache(*timer->serverUrl, timer->addr);
            delete (timer->serverUrl);
            break;
        }
        case MSG_APP_TCP_Open_Timer:
        {
            AppTcpOpenTimer* timer =
                        (AppTcpOpenTimer*) MESSAGE_ReturnInfo(msg);
            AppAddressState addressState = ADDRESS_INVALID;

            addressState = AppTcpGetSessionAddressState(
                                    node,
                                    timer->destNodeId,
                                    timer->clientInterfaceIndex,
                                    timer->destInterfaceIndex,
                                    &timer->tcpOpenInfo);

            // do not open a TCP connection if either client or server are in
            // invalid address state
            if (addressState != ADDRESS_INVALID)
            {
                APP_TcpOpenConnection(
                        node,
                        timer->tcpOpenInfo.appType,
                        timer->tcpOpenInfo.localAddr,
                        timer->tcpOpenInfo.localPort,
                        timer->tcpOpenInfo.remoteAddr,
                        timer->tcpOpenInfo.remotePort,
                        timer->tcpOpenInfo.uniqueId,
                        PROCESS_IMMEDIATELY,
                        timer->tcpOpenInfo.priority,
                        timer->tcpOpenInfo.outgoingInterface);
            }
            else
            {
                char errString[MAX_STRING_LENGTH];
                sprintf(errString, "Node: %d\n"
                    "TCP Connection not opened for application %d session at"
                    " node %d due to invalid address state", node->nodeId,
                    (Int32)timer->tcpOpenInfo.appType, node->nodeId);
                ERROR_ReportWarning(errString);
            }
            break;
        }
        case MSG_APP_TimerDnsSendPacket:
        {
            AppDnsInfoTimer* timer =
                                (AppDnsInfoTimer*)MESSAGE_ReturnInfo(msg);
            processTimerDnsSendPacket
                            (node,
                             msg,
                             timer->type,
                             *timer->serverUrl,
                             timer->sourcePort,
                             timer->addr,
                             timer->tcpMode,
                             timer->uniqueId);
            delete (timer->serverUrl);
            break;
        }
        default:
        {
            break;
        }
    }
}

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
void AppTrafficSender::processTimerDnsSendPacket(
                        Node* node,
                        Message* msg,
                        AppType appType,
                        std::string url,
                        UInt16 sourcePort,
                        Address clientAddr,
                        bool tcpMode,
                        UInt32 uniqueId)
{
    DnsData* dnsData = (DnsData*)node->appData.dnsData;
    bool isUrlResolved = TRUE;
    DnsQueryPacket dnsQueryPacketRec;

    memcpy((char*)&dnsQueryPacketRec,
            MESSAGE_ReturnPacket(msg) +
            sizeof(DnsMessageType),
            sizeof(DnsQueryPacket));

    DnsAppReqItemList :: iterator item;
    DnsAppReqListItem* appItem = NULL;
    item = dnsData->appReqList->begin();

    // check for matching URL
    while (item != dnsData->appReqList->end())
    {
        appItem = (*item);
        if ((strcmp(appItem->serverUrl->c_str(),
            dnsQueryPacketRec.dnsQuestion.dnsQname) == 0))
        {
            isUrlResolved = FALSE;
            break;
        }
        item++;
    }
    if (isUrlResolved)
    {
        return;
    }
    appSendDnsRequest(
                node,
                url,
                clientAddr,
                appItem,
                appType,
                sourcePort,
                APP_TIMER_DNS_SEND_PKT,
                tcpMode,
                uniqueId);
}

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
void AppTrafficSender::insertOpenRequestInTcpBuffer(
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
                                Int16 destInterfaceIndex)
{
    // check cache if address found or not
    Address destAddress = lookupUrlInAddressCache(url);
    if (destAddress.networkType != NETWORK_INVALID)
    {
        NodeId newDestNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                            node,
                            destAddress);
        Int16 newDestInterfaceIndex = ANY_INTERFACE;
        if (destNodeId != INVALID_MAPPING)
        {
            newDestInterfaceIndex =
                (Int16)MAPPING_GetInterfaceIdForDestAddress(
                                node,
                                newDestNodeId,
                                destAddress);
        }

        // address found schedule TCP open timer
        appTcpOpenConnTimer(
                        node,
                        appType,
                        localAddr,
                        localPort,
                        destAddress,
                        remotePort,
                        uniqueId,
                        priority,
                        outgoingInterface,
                        startTime,
                        newDestNodeId,
                        clientInterfaceIndex,
                        newDestInterfaceIndex);
        return;
    }
    // create the open request
    AppTcpOpenTimer* tcpOpen = createTcpOpenInfo(
                                    node,
                                    appType,
                                    localAddr,
                                    localPort,
                                    remoteAddr,
                                    remotePort,
                                    uniqueId,
                                    priority,
                                    outgoingInterface,
                                    destNodeId,
                                    clientInterfaceIndex,
                                    destInterfaceIndex);

    bool openConnInserted = FALSE;

    // traverse the buffer to insert Open Request aginst this url
    AppTcpOpenRequestBufferMap::iterator it =
                                    tcpOpenRequestBufferMap.find(url);
    if (it != tcpOpenRequestBufferMap.end())
    {
        // insert the open request in list
        TcpOpenConnList* openConList = it->second;
        if (openConList == NULL)
        {
            openConList = new TcpOpenConnList;
            it->second = openConList;
        }
        openConList->push_back(tcpOpen);
        openConnInserted = TRUE;
    }
    if (openConnInserted == FALSE)
    {
        // no matching url found in list
        // now create a node to be inserted in map
        //.first create the message list
        TcpOpenConnList* openConList = new TcpOpenConnList;
        openConList->push_back(tcpOpen);
        UrlStringType urlStr(url);
        (tcpOpenRequestBufferMap)[urlStr] = openConList;
        openConnInserted = TRUE;
    }

    // send the DNS rquest
    appSendDnsRequest(
                    node,
                    url,
                    localAddr,
                    NULL,
                    appType,
                    localPort,
                    0,
                    TRUE,
                    uniqueId,
                    startTime);

    // add source port in source port list
    addSourcePortForUrl(url, localPort);
}

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
bool AppTrafficSender::checkIfValidUrl(
                                Node* node,
                                std::string destString,
                                bool isMdpEnabled,
                                const char* appStr,
                                Address* destAddr)
{
    bool isUrl = FALSE;
    if (ADDR_IsUrl(destString.c_str()))
    {
        checkValidAppUrl(&destString, isMdpEnabled, appStr);
        isUrl = TRUE;
        memset(destAddr, 0, sizeof(Address));
    }
    return (isUrl);
}

// Private function definition starts

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
void AppTrafficSender::checkValidAppUrl(
                    std::string* destString,
                    bool isMdpEnabled,
                    const char* appStr)
{
    AppDnsConcatenatePeriodIfNotPresent(destString);
    if (isMdpEnabled)
    {
        ERROR_ReportErrorArgs("%s : DNS does not support MDP\n",
            appStr);
    }
}

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
bool AppTrafficSender::appSendDnsRequest(
                                Node* node,
                                std::string serverUrl,
                                Address clientAddr,
                                DnsAppReqListItem* appItem,
                                AppType appType,
                                UInt16 sourcePort,
                                Int32 timerType,
                                bool tcpMode,
                                UInt32 uniqueId,
                                clocktype startTime)
{
    if (serverUrl.length() == 0)
    {
        return FALSE;
    }
    // get the current client address
    if (clientAddr.networkType == NETWORK_IPV6)
    {
        Int32 intfIndex;
        // check whether address exist
        intfIndex = (Int32) Ipv6GetInterfaceIndexFromAddress(
                                node,
                                &clientAddr.interfaceAddr.ipv6);

        if (intfIndex < 0 ||
            IS_LINKLADDR6(clientAddr.interfaceAddr.ipv6))
        {
           clientAddr.networkType = NETWORK_IPV6;
           Ipv6GetGlobalAggrAddress(
                       node,
                       0,
                       &clientAddr.interfaceAddr.ipv6);
        }
    }
    else if (clientAddr.networkType == NETWORK_IPV4)
    {
        clientAddr.interfaceAddr.ipv4 =
                        NetworkIpGetInterfaceAddress(
                                                    node,
                                                    DEFAULT_INTERFACE);
    }

    // Request Dns to resolve address
    int connectionId = uniqueId;
    NetworkType sourceNetworktype = clientAddr.networkType;

    if (timerType == APP_TIMER_DNS_SEND_PKT)
    {
        appItem->AAAASend = FALSE;
        appItem->ASend = FALSE;
        sourceNetworktype = appItem->queryNetworktype;
    }

    App_DnsRquest(
                node,
                appType,
                sourcePort,
                connectionId,
                tcpMode,
                &clientAddr,
                serverUrl,
                startTime,
                sourceNetworktype);
    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION     : sendTcpOpenConnection
// PURPOSE      : send TCP Open request when URL is resolved
// PARAMETERS   ::
// + node   : Node*             : pointer to node
// + timer  : AppDnsInfoTimer   : dns timer info
// RETURN       :: NONE
//---------------------------------------------------------------------------
void
AppTrafficSender::sendTcpOpenConnection(Node* node, AppDnsInfoTimer* timer)
{
    // Traverse the url and call all handler functions
    AppSessionStartHandlerList::iterator callbackIt =
                                    sessionStartHandlerList.begin();

    AppplicationStartCallBack appStartFunctionPointer;
    while (callbackIt != sessionStartHandlerList.end())
    {
        appStartFunctionPointer = (*callbackIt);

        if (!appStartFunctionPointer)
        {
            ERROR_ReportErrorArgs("In "
                        "sendTcpOpenConnection and invalid "
                        "handler function");
        }
        AppUdpPacketSendingInfo packetSendingInfo;
        appStartFunctionPointer(
                        node,
                        &timer->addr,
                        timer->sourcePort,
                        timer->uniqueId,
                        timer->interfaceId,
                        *timer->serverUrl,
                        &packetSendingInfo);
        callbackIt++;
    }

    // traverse the map to get the Open request List
    if (tcpOpenRequestBufferMap.size() == 0)
    {
        ERROR_ReportErrorArgs(
                "Traffic Sender: Node %d TCP Open not found",
                node->nodeId);
    }

    // traverse the buffer to find Open Request aginst this url
    AppTcpOpenRequestBufferMap::iterator it =
                        tcpOpenRequestBufferMap.find(*timer->serverUrl);
    if (it != tcpOpenRequestBufferMap.end())
    {
        // get the open request in list
        TcpOpenConnList* openConList = it->second;

        // traverse the list
        if (openConList)
        {
            TcpOpenConnList::iterator listIt = openConList->begin();
            while (listIt != openConList->end())
            {
                AppTcpOpenTimer* tcpOpen = (AppTcpOpenTimer*)(*listIt);
                if (tcpOpen->tcpOpenInfo.uniqueId == timer->uniqueId)
                {
                    memcpy (&tcpOpen->tcpOpenInfo.remoteAddr, &timer->addr,
                            sizeof(Address));
                    // update destination node id and interface index
                    NodeId destNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                            node,
                                            tcpOpen->tcpOpenInfo.remoteAddr);
                    if (destNodeId != INVALID_MAPPING)
                    {
                        tcpOpen->destNodeId = destNodeId;
                        tcpOpen->destInterfaceIndex =
                            (Int16)MAPPING_GetInterfaceIdForDestAddress(
                                            node,
                                            tcpOpen->destNodeId,
                                            tcpOpen->tcpOpenInfo.remoteAddr);
                    }
                    // schedule the open connection request
                    appTcpOpenConnTimer(
                                    node,
                                    tcpOpen->tcpOpenInfo.appType,
                                    tcpOpen->tcpOpenInfo.localAddr,
                                    tcpOpen->tcpOpenInfo.localPort,
                                    tcpOpen->tcpOpenInfo.remoteAddr,
                                    tcpOpen->tcpOpenInfo.remotePort,
                                    tcpOpen->tcpOpenInfo.uniqueId,
                                    tcpOpen->tcpOpenInfo.priority,
                                    tcpOpen->tcpOpenInfo.outgoingInterface,
                                    PROCESS_IMMEDIATELY,
                                    tcpOpen->destNodeId,
                                    tcpOpen->clientInterfaceIndex,
                                    tcpOpen->destInterfaceIndex);
                    // remove from list
                    listIt++;
                    openConList->remove(tcpOpen);
                    MEM_free(tcpOpen);
                    tcpOpen = NULL;
                }
                else
                {
                        listIt++;
                }
            }
            if (openConList->size() == 0)
            {
                delete (openConList);
                it->second = NULL;
                openConList = NULL;
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : insertUrlAddressInCache
// PURPOSE      : insert a URL and corresponding address in cache
// PARAMETERS   ::
// + url        : std::string     : url string
// + address    : Address         : address corresponding to url
// RETURN       :: NONE
//---------------------------------------------------------------------------
void AppTrafficSender::insertUrlAddressInCache(
                                    std::string url,
                                    Address address)
{
    // insert this URl in cache
    urlToAddressCache.insert(
                std::pair<std::string, Address>(url, address));
}

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
void AppTrafficSender::insertPacketInUdpBuffer(
                                Message* msg,
                                std::string url,
                                UInt16 sourcePort,
                                Int32 itemSize,
                                Int32 fragSize,
                                Int32 fragNo)
{
    bool msgInserted = FALSE;

    AppBufferedUdpPacket* bufferedMsg =
            (AppBufferedUdpPacket*)MEM_malloc(sizeof(AppBufferedUdpPacket));
    bufferedMsg->msg = msg;
    bufferedMsg->itemSize = itemSize;
    bufferedMsg->fragSize = fragSize;
    bufferedMsg->fragNo = fragNo;
    // traverse the buffer to insert message aginst this url
    AppUdpPacketBufferMap::iterator it = udpPacketBuffer.find(url);
    if (it != udpPacketBuffer.end())
    {
        // insert the mssage in list
        UdpBufferedPacketList* msgList = it->second;
        if (msgList == NULL)
        {
            msgList = new UdpBufferedPacketList;
            it->second = msgList;
        }
        msgList->push_back(bufferedMsg);
        msgInserted = TRUE;
    }
    if (msgInserted == FALSE)
    {
        // no matching url found in list
        // now create a node to be inserted in map
        //.first create the message list
        UdpBufferedPacketList* msgList = new UdpBufferedPacketList;
        msgList->push_back(bufferedMsg);
        UrlStringType urlStr(url);
        (udpPacketBuffer)[urlStr] = msgList;
        msgInserted = TRUE;
    }
}

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
Node* AppTrafficSender::getAppServerNodeFromDestString(
                    Node* node,
                    DnsClientData* serverDnsClientData,
                    const char* destString)
{
    NodePointerCollectionIter it = node->partitionData->allNodes->begin();
    Node* tmpNode = NULL;
    while (it != node->partitionData->allNodes->end())
    {
        tmpNode = *it;
        DnsData* dnsdata = (DnsData*)tmpNode->appData.dnsData;
        if (dnsdata == NULL)
        {
            it++;
            continue;
        }
        list<DnsClientData*>::iterator dnsIt;
        for (dnsIt = dnsdata->clientData->begin();
             dnsIt != dnsdata->clientData->end();
             dnsIt++)
        {
            DnsClientData* dnsClientData = (DnsClientData*)(*dnsIt);
            if (dnsClientData->fqdn &&
                !strcmp(dnsClientData->fqdn, destString))
            {
                memcpy(
                    serverDnsClientData,
                    dnsClientData,
                    sizeof(DnsClientData));
                return(tmpNode);
            }
        }
        it++;
    }
    return (NULL);
}

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
void AppTrafficSender::getAppPacketListToSend(
                        Node* node,
                        std::string serverUrl,
                        UInt16 sourcePort,
                        UdpBufferedPacketList* returnPacketList)
{
    // Traverse the map
    if (udpPacketBuffer.size() == 0)
    {
        return;
    }
    AppUdpPacketBufferMap::iterator it = udpPacketBuffer.find(serverUrl);
    if (it != udpPacketBuffer.end())
    {
        // insert the mssage in list
        // traverse the packet and find if packet belongs to
        // this application
        UdpBufferedPacketList* msgList = it->second;
        if (msgList != NULL)
        {
            UdpBufferedPacketList::iterator listIt = msgList->begin();
            while (listIt != msgList->end())
            {
                AppBufferedUdpPacket* bufferedMsg =
                                        (AppBufferedUdpPacket*)(*listIt);
                AppToUdpSend* info =
                    (AppToUdpSend*) MESSAGE_ReturnInfo(bufferedMsg->msg);
                if (info->sourcePort == sourcePort)
                {
                    listIt++;
                    returnPacketList->push_back(bufferedMsg);
                    // remove from the buffer
                    msgList->remove(bufferedMsg);
                }
                else
                {
                    listIt++;
                }
            }
            if (msgList->size() == 0)
            {
                delete (msgList);
                it->second = NULL;
            }
        }
    }
}

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
bool AppTrafficSender::ifDnsRequestSent(std::string url, UInt16 sourcePort)
{
    bool dnsRequestSent = FALSE;
    AppUrlSourcePortMap::iterator it = sourcePortMap.find(url);
    if (it != sourcePortMap.end())
    {
        // traverse the list to find the port number existing or not
        std::list<UInt16> portList = it->second;
        if (portList.size() != 0)
        {
            std::list<UInt16>::iterator portIt = portList.begin();
            while (portIt != portList.end())
            {
                UInt16 port = (*portIt);
                if (port == sourcePort)
                {
                    dnsRequestSent = TRUE;
                    break;
                }
                portIt++;
            }
        }
    }
    return (dnsRequestSent);
}

//---------------------------------------------------------------------------
// FUNCTION     : addSourcePortForUrl
// PURPOSE      : add source port for dns request sent
// PARAMETERS   ::
// + url        : std::string           : url string
// + sourcePort : UInt16                : source port for which dns request
//                                        sent
// RETURN       :: NONE
//---------------------------------------------------------------------------
void
AppTrafficSender::addSourcePortForUrl(std::string url, UInt16 sourcePort)
{
    AppUrlSourcePortMap::iterator it = sourcePortMap.find(url);
    if (it != sourcePortMap.end())
    {
        // traverse the list to find the port number existing or not
        std::list<UInt16> portList = it->second;
        portList.push_back(sourcePort);
        it->second = portList;
    }
    else
    {
        std::list<UInt16> portList;
        portList.push_back(sourcePort);
        sourcePortMap[url] = portList;
    }
}

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
void
AppTrafficSender::sendBufferedUdpPackets(
                                Node* node,
                                std::string url,
                                UInt16 sourcePort,
                                Address destAddress,
                                AppUdpPacketSendingInfo packetSendingInfo)
{
    // get the message list for this URL and application
    UdpBufferedPacketList msgList;
    getAppPacketListToSend(
                        node,
                        url,
                        sourcePort,
                        &msgList);

    UdpBufferedPacketList::iterator it;
    for (it = msgList.begin(); it != msgList.end(); ++it)
    {
        // get the meessage and send
        AppBufferedUdpPacket* bufferedMsg = (*it);
        // update the destination address
        AppToUdpSend* info =
                    (AppToUdpSend*) MESSAGE_ReturnInfo(bufferedMsg->msg);
        memcpy(&info->destAddr, &destAddress, sizeof(Address));
        packetSendingInfo.fragNo = bufferedMsg->fragNo;
        packetSendingInfo.fragSize = bufferedMsg->fragSize;
        packetSendingInfo.itemSize = bufferedMsg->itemSize;

        sendUdpApplicationPackets(
                            node,
                            bufferedMsg->msg,
                            packetSendingInfo,
                            destAddress);
    }
}

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
void
AppTrafficSender::sendUdpPackets(
                                Node* node,
                                Message* msg,
                                std::string url,
                                UInt16 sourcePort,
                                Address destAddress,
                                AppUdpPacketSendingInfo* packetSendingInfo)
{
    // if destination is in the form of URL call the handler functions such
    // that application is updated for sending the packet
    if (url.size() != 0)
    {
        AppSessionStartHandlerList::iterator it =
                                            sessionStartHandlerList.begin();

        AppplicationStartCallBack appStartFunctionPointer;
        while (it != sessionStartHandlerList.end())
        {
            appStartFunctionPointer = (*it);

            if (!appStartFunctionPointer)
            {
                ERROR_ReportErrorArgs("In "
                    "sendUdpPackets and invalid "
                    "handler function");
            }

            AppUdpPacketSendingInfo bufferedPacketSendingInfo;
            memset(
                &bufferedPacketSendingInfo,
                0,
                sizeof(AppUdpPacketSendingInfo));
            bool needToSendPacket = appStartFunctionPointer(
                                                node,
                                                &destAddress,
                                                sourcePort,
                                                0,
                                                0,
                                                url,
                                                &bufferedPacketSendingInfo);
            // send buffered packet
            if (msg == NULL && needToSendPacket == TRUE)
            {
                 // need to send buffered packets
                 sendBufferedUdpPackets(
                            node,
                            url,
                            sourcePort,
                            destAddress,
                            bufferedPacketSendingInfo);
            }
            if (msg != NULL && needToSendPacket == TRUE)
            {
                // update packet sending information as packets may not have
                // been buffered , url got resolved via cache
                memcpy(
                    packetSendingInfo,
                    &bufferedPacketSendingInfo,
                    sizeof(AppUdpPacketSendingInfo));
            }
            it++;
        }
    }
    if (msg != NULL)
    {
        // send the message
        sendUdpApplicationPackets(
                        node,
                        msg,
                        *packetSendingInfo,
                        destAddress);
    }
}

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
void AppTrafficSender::httpDnsInit(
                Node* node,
                char* sourceString,
                char* destString,
                Address* destAddr,
                Address* sourceAddr,
                AppplicationStartCallBack appStartFunctionPointer)
{
    NodeId* destNodeId = NULL;
    Address urlDestAddress;
    DnsClientData serverDnsClientData;
    memcpy (&urlDestAddress, destAddr, sizeof(Address));
    Node* destNode = NULL;

    // get the server node and destAddress of application
    // server
    destNode = getAppServerAddressAndNodeFromUrl(
                                            node,
                                            destString,
                                            &urlDestAddress,
                                            &serverDnsClientData);


    if (IO_IsStringNonNegativeInteger(sourceString) && destNode != NULL)
    {
        *sourceAddr = MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
                                                node,
                                                node->nodeId,
                                                urlDestAddress.networkType);
    }

    // Register the function that will be called when url is resolved
    addApplicationStartFunction(node, appStartFunctionPointer);

}
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
void AppTrafficSender::SipDnsInit(
                Node* node,
                AppplicationStartCallBack appStartFunctionPointer)
{
        // Register the function that will be called when url is resolved
        addApplicationStartFunction (node, appStartFunctionPointer);

}
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
void AppTrafficSender::H323RasDnsInit(
                Node* node,
                AppplicationStartCallBack appStartFunctionPointer)
{
        // Register the function that will be called when url is resolved
        addApplicationStartFunction (node, appStartFunctionPointer);

}
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
void AppTrafficSender::superApplicationDnsInit(
                Node* node,
                char* inputString,
                const NodeInput* nodeInput,
                SuperApplicationData* clientPtr,
                AppplicationStartCallBack appStartFunctionPointer)
{
    Address clientAddr;
    Address serverAddr;
    NodeId clientId = ANY_NODEID;
    NodeId serverId = ANY_NODEID;;
    char clientString[MAX_STRING_LENGTH];
    char serverString[BIG_STRING_LENGTH];
    // dns
    bool isUrl = FALSE;

    sscanf(inputString, "%*s %s %s",clientString, serverString);

    IO_AppParseSourceAndDestStrings(
                    node,
                    inputString,
                    clientString,
                    &clientId,
                    &clientAddr,
                    serverString,
                    &serverId,
                    &serverAddr);

    // dns
    std::string serverUrl(serverString);
    if (checkIfValidUrl(
                    node,
                    serverUrl,
                    clientPtr->isMdpEnabled,
                    "SUPER-APPLICATION",
                    &serverAddr) == TRUE)
    {
        isUrl = TRUE;
    }

    // add the address information
    AppSuperAppplicationClientAddAddressInformation(node, clientPtr);

    // dns
     Address urlDestAddress;
     urlDestAddress = node->appData.appTrafficSender->
                                    applicationClientDnsInit(
                                        node,
                                        inputString,
                                        &serverAddr,
                                        &clientAddr,
                                        &serverId,
                                        appStartFunctionPointer);
    DnsClientData serverDnsClientData;
    if (isUrl)
    {
        // set the dns info in client pointer if server url
        // is present
        Node* destNode = NULL;

        // super application does not support loopback and thus localhost
        // not supported
        if (ifUrlLocalHost(serverString) == TRUE)
        {
            char errorStr[5 * MAX_STRING_LENGTH] = {0};
            sprintf(errorStr, "SUPER-APPLICATION : Application doesn't "
                    "support Loopback Address!\n  %s\n",
                    inputString);
            ERROR_ReportWarning(errorStr);
            return;
        }
        // set the server url if it is not localhost
        appClientSetDnsInfo(
                        node,
                        serverString,
                        clientPtr->serverUrl);

        // send DNS request if TCP session; for UDP DNS request will be send
        // on timer expiry

        if (clientPtr->transportLayer == SUPERAPPLICATION_TCP)
        {
            // need to buffer the TCP open request untill
            // URL is resolved and send the DNS request
            Address localAddress;
            localAddress.networkType = NETWORK_IPV4;
            localAddress.interfaceAddr.ipv4 = clientPtr->clientAddr;
            Address remoteAddress;
            remoteAddress.networkType = NETWORK_IPV4;
            remoteAddress.interfaceAddr.ipv4 = clientPtr->serverAddr;
            insertOpenRequestInTcpBuffer(
                                        node,
                                        APP_SUPERAPPLICATION_CLIENT,
                                        localAddress,
                                        clientPtr->sourcePort,
                                        remoteAddress,
                                        APP_SUPERAPPLICATION_SERVER,
                                        clientPtr->uniqueId,
                                        clientPtr->reqTOS,
                                        ANY_INTERFACE,
                                        *clientPtr->serverUrl,
                                        clientPtr->sessionStart,
                                        clientPtr->destNodeId,
                                        clientPtr->clientInterfaceIndex,
                                        clientPtr->destInterfaceIndex);
        }
        // get the server node and destAddress of application
        // server
        destNode = getAppServerAddressAndNodeFromUrl(
                                            node,
                                            serverString,
                                            &serverAddr,
                                            &serverDnsClientData);

        // return if destination node cannot be found
        if (destNode == NULL)
        {
            return;
        }
        clientPtr->destNodeId = destNode->nodeId;
        IdToNodePtrMap* nodeHash = node->partitionData->nodeIdHash;
        Node* destnode =
            MAPPING_GetNodePtrFromHash(nodeHash, destNode->nodeId);
        if (destnode != NULL)
        {
            SuperApplicationInit(
                            destnode,
                            clientPtr->clientAddr,
                            serverAddr.interfaceAddr.ipv4,
                            inputString,
                            clientPtr->appFileIndex,
                            nodeInput,
                            clientPtr->mdpUniqueId);
        }
        // Register the function that will be called when url is resolved
        addApplicationStartFunction (node, appStartFunctionPointer);
    }
}

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
bool AppTrafficSender::appCheckUrlAndGetUrlDestinationAddress(
                        Node* node,
                        char* inputString,
                        bool isMdpEnabled,
                        Address* sourceAddress,
                        Address* destinationAddress,
                        NodeId* destinationNodeId,
                        Address* urlDestAddress,
                        AppplicationStartCallBack appStartFunctionPointer)

{
    char sourceString[MAX_STRING_LENGTH];
    char destString[MAX_STRING_LENGTH];
    char appStr[MAX_STRING_LENGTH];
    sscanf(inputString, "%s", appStr);
    bool isUrl = FALSE;
    // get source and destination string
    sscanf(inputString, "%*s %s %s", sourceString, destString);

   std::string destinationString(destString);
   memset(urlDestAddress, 0, sizeof(Address));
   if (node->appData.appTrafficSender->checkIfValidUrl(
                                            node,
                                            destinationString,
                                            isMdpEnabled,
                                            appStr,
                                            destinationAddress) == TRUE)
    {
        isUrl = TRUE;
        *urlDestAddress = node->appData.appTrafficSender->
                                            applicationClientDnsInit(
                                                node,
                                                inputString,
                                                destinationAddress,
                                                sourceAddress,
                                                destinationNodeId,
                                                appStartFunctionPointer);
   }
   return (isUrl);
}

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
void AppTrafficSender::appTcpOpenConnection(
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
                        Int16 destInterfaceIndex)
{
    if (remoteAddr.networkType == NETWORK_INVALID && url.size() != 0 &&
        ifUrlLocalHost(url) == FALSE)
    {
        // need to buffer the TCP open request untill
        // URL is resolved and send the DNS request
        insertOpenRequestInTcpBuffer(
                                    node,
                                    appType,
                                    localAddr,
                                    localPort,
                                    remoteAddr,
                                    remotePort,
                                    uniqueId,
                                    priority,
                                    outgoingInterface,
                                    url,
                                    startTime,
                                    destNodeId,
                                    clientInterfaceIndex,
                                    destInterfaceIndex);
    }
    else
    {
        // open TCP connection
        // schedule TCP Open timer to update address before opening
        // TCP connection at start time
        appTcpOpenConnTimer(
                        node,
                        appType,
                        localAddr,
                        localPort,
                        remoteAddr,
                        remotePort,
                        uniqueId,
                        priority,
                        outgoingInterface,
                        startTime,
                        destNodeId,
                        clientInterfaceIndex,
                        destInterfaceIndex);
    }
}

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
void AppTrafficSender::appTcpListen(
                        Node *node,
                        AppType appType,
                        Address serverAddr,
                        UInt16 serverPort)
{
    APP_TcpServerListen(
                    node,
                    appType,
                    serverAddr,
                    serverPort);
}

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
void AppTrafficSender::appTcpListenWithPriority(
                        Node *node,
                        AppType appType,
                        Address serverAddr,
                        UInt16 serverPort,
                        TosType priority)
{
    APP_TcpServerListenWithPriority(
                    node,
                    appType,
                    serverAddr,
                    serverPort,
                    priority);
}

//---------------------------------------------------------------------------
// FUNCTION     : appTcpCloseConnection
// PURPOSE      : Closes a TCP connection
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + connectionId       : Int32         : connection id
// RETURN       :: NONE
//---------------------------------------------------------------------------
void AppTrafficSender::appTcpCloseConnection(
                        Node *node,
                        Int32 connectionId)
{
    APP_TcpCloseConnection(
            node,
            connectionId);
}

//---------------------------------------------------------------------------
// FUNCTION     : appTcpSend
// PURPOSE      : sends a TCP packet
// PARAMETERS   ::
// + node               : Node*         : pointer to node
// + msg                : Message*      : message
// + appParam           : StatsDBAppEventParam*  : Stat DB application
//                                                  parameter
// RETURN       :: NONE
//---------------------------------------------------------------------------
void AppTrafficSender::appTcpSend(
                        Node *node,
                        Message* msg
#ifdef ADDON_DB
                        ,StatsDBAppEventParam* appParam
#endif
                        )
{
#ifdef ADDON_DB
    APP_TcpSend(node, msg, appParam);
#else
    APP_TcpSend(node, msg);
#endif
}

//---------------------------------------------------------------------------
// FUNCTION     : ifUrlLocalHost
// PURPOSE      : check if url is localhostt
// PARAMETERS   ::
// + urlString  : std::string   : url string
// RETURN       ::
// bool         : TRUE is if it localhost FALSE otherwise
//---------------------------------------------------------------------------
bool AppTrafficSender::ifUrlLocalHost(std::string urlString)
{
    bool isLocalHost = FALSE;
    if (!urlString.compare("localhost.") ||!urlString.compare("localhost"))
    {
        isLocalHost = TRUE;
    }
    return (isLocalHost);
}

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
void AppTrafficSender::appTcpOpenConnTimer(
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
                        Int16 destInterfaceIndex)
{
    Message* timerMsg = MESSAGE_Alloc(
                                node,
                                APP_LAYER,
                                APP_TRAFFIC_SENDER,
                                MSG_APP_TCP_Open_Timer);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTcpOpenTimer));

    AppTcpOpenTimer* timer = (AppTcpOpenTimer*) MESSAGE_ReturnInfo(timerMsg);

    timer->tcpOpenInfo.appType = appType;
    timer->tcpOpenInfo.localAddr = localAddr;
    timer->tcpOpenInfo.localPort = localPort;
    timer->tcpOpenInfo.remoteAddr = remoteAddr;
    timer->tcpOpenInfo.remotePort = remotePort;
    timer->tcpOpenInfo.uniqueId = uniqueId;
    timer->tcpOpenInfo.priority = priority;
    timer->tcpOpenInfo.outgoingInterface = outgoingInterface;
    timer->destNodeId = destNodeId;
    timer->clientInterfaceIndex = clientInterfaceIndex;
    timer->destInterfaceIndex = destInterfaceIndex;
    MESSAGE_Send(node, timerMsg, startTime);
}

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
void AppTrafficSender::sendUdpApplicationPackets(
                        Node* node,
                        Message* sentMsg,
                        AppUdpPacketSendingInfo packetSendingInfo,
                        Address destAddr)
{
    bool packetSent = FALSE;
#ifdef ADDON_DB
    // if addon_db not enabled for any protocol then
    // appParam->m_SessionInitiator will be 0
    if (packetSendingInfo.appParam.m_SessionInitiator != 0 &&
        strcmp(packetSendingInfo.appParam.m_ApplicationType,
                "SUPER-APPLICATION") != 0)
    {
            APP_UdpSend(node,
                    sentMsg,
                    PROCESS_IMMEDIATELY,
                    &packetSendingInfo.appParam);
            packetSent = TRUE;
    }
#endif // ADDON_DB
    if (packetSent == FALSE)
    {
        APP_UdpSend(node, sentMsg);
        packetSent = TRUE;
    }
    if (node->appData.appStats && packetSendingInfo.stats)
    {
        if (!(packetSendingInfo.stats->IsSessionStarted(STAT_Unicast))
            &&
            !(packetSendingInfo.stats->IsSessionStarted(STAT_Multicast)))
        {
            if (Address_IsMulticastAddress(&destAddr))
            {
                packetSendingInfo.stats->SessionStart(
                                                    node,
                                                    STAT_Multicast);
            }
            else
            {
                packetSendingInfo.stats->SessionStart(
                                                    node,
                                                    STAT_Unicast);
            }
        }
        if (MESSAGE_ReturnInfo(sentMsg, INFO_TYPE_StatsTiming) == NULL)
        {
            if (Address_IsMulticastAddress(&destAddr))
            {
                if (packetSendingInfo.fragNo != NO_UDP_FRAG)
                {
                    packetSendingInfo.stats->AddFragmentSentDataPoints(
                                                node,
                                                packetSendingInfo.fragSize,
                                                STAT_Multicast);
                    packetSendingInfo.stats->AddTiming(
                                                 node,
                                                 sentMsg,
                                                 packetSendingInfo.fragSize,
                                                 0);
                    if (packetSendingInfo.fragNo == 0)
                    {
                        packetSendingInfo.stats->AddMessageSentDataPoints(
                                               node,
                                               sentMsg,
                                               0,
                                               packetSendingInfo.itemSize,
                                               0,
                                               STAT_Multicast);
                    }
                }
                else
                {
                    packetSendingInfo.stats->AddMessageSentDataPoints(
                                                node,
                                                sentMsg,
                                                0,
                                                packetSendingInfo.itemSize,
                                                0,
                                                STAT_Multicast);
                    packetSendingInfo.stats->AddFragmentSentDataPoints(
                                                node,
                                                packetSendingInfo.itemSize,
                                                STAT_Multicast);

                }
            }
            else
            {
                if (packetSendingInfo.fragNo != NO_UDP_FRAG)
                {
                    packetSendingInfo.stats->AddFragmentSentDataPoints(
                                                node,
                                                packetSendingInfo.fragSize,
                                                STAT_Unicast);
                    packetSendingInfo.stats->AddTiming(node,
                                                 sentMsg,
                                                 packetSendingInfo.fragSize,
                                                 0);
                    if (packetSendingInfo.fragNo == 0)
                    {
                        packetSendingInfo.stats->AddMessageSentDataPoints(
                                                node,
                                                sentMsg,
                                                0,
                                                packetSendingInfo.itemSize,
                                                0,
                                                STAT_Unicast);
                    }
                }
                else
                {
                    packetSendingInfo.stats->AddMessageSentDataPoints(
                                                node,
                                                sentMsg,
                                                0,
                                                packetSendingInfo.itemSize,
                                                0,
                                                STAT_Unicast);
                    packetSendingInfo.stats->AddFragmentSentDataPoints(
                                                node,
                                                packetSendingInfo.itemSize,
                                                STAT_Unicast);
                }
            }
        }
    }
}








