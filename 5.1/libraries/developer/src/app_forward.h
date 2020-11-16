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

#ifndef _FORWARD_APP_H_
#define _FORWARD_APP_H_

#include "external.h"
#include <vector>
#include <list>
#include "stats_app.h"

#define MAX_TOS_BITS 256
#ifdef ADDON_DB
class SequenceNumber;
#endif // ADDON_DB

/*
 * Data item structure used by forward.
 */
typedef
struct struct_app_forward_data
{
    short sourcePort;

    char type;
    Int32 seqNo;
    clocktype txTime;
}
ForwardData;

struct EXTERNAL_ForwardIdentifier
{
    NodeAddress local;
    NodeAddress remote;
    char interfaceName[MAX_STRING_LENGTH];
    UInt8 ttl;
};

typedef
struct struct_app_forward_external_begin_send_data_tcp
{
    NodeAddress from;
    NodeAddress to;
    int         interfaceId;
    char        interfaceName [MAX_STRING_LENGTH];
}
EXTERNAL_ForwardBeginWendDataTCP;

/* Enumerates the state of a forward app's TCP connection */

enum FORWARD_TcpState
{
    FORWARD_TcpUninitialized = 1,
    FORWARD_TcpListening,
    FORWARD_TcpConnecting,
    FORWARD_TcpConnected
};

struct FORWARD_BufferedRequest
{
    FORWARD_BufferedRequest *next;

    char *messageData;
    int realDataSize;
    int virtualSize;
};

struct FORWARD_PacketTosStats
{
    int type;
    D_UInt32 numPriorityPacketSent;
    D_UInt32 numPriorityPacketReceived;
    int numPriorityFragsRcvd;
    int numPriorityFragsSent;
    int numPriorityBytesSent;
    int numPriorityBytesRcvd;
    clocktype totalPriorityDelay;
};

struct FORWARD_TcpHeaderInfo
{
    // The size of the packet including the tcp header
    Int32 packetSize;

    // How much of the tcp packet is virtual data.  packetSize - virtualSize
    // == real data size
    Int32 virtualSize;
    clocktype packetCreationTime;
};

#define FORWARD_UDP_FRAGMENT_SIZE (MIN(10000, IP_MAXPACKET-MSG_MAX_HDR_SIZE))
/* Structure containing forward information. */
struct FORWARD_UdpFragmentData
{
    Int32 seqNum;
    Int32 uniqueFragNo; // global for all messages
    Int32 messageId;
    Int32 numberFrags;
    Int32 messageSize;
    Int32 sessionId;
    BOOL isVirtual;
    clocktype udpTimeout;
    clocktype packetCreationTime;
    TosType tos;
};

struct FORWARD_UdpPacketRecon
{
    Int32 messageSize;
    Int32 receivedSize;
    Int32 remainingFragments;
    Int32 messageId;
    BOOL isVirtual;
    clocktype timeOut;
    clocktype packetCreateTime;
    char* packet; // For actual data
    TosType tos;
};

#define FORWARD_UDP_HASH_SIZE 31
class FORWARD_UdpRequestHash
{
private:
    std::map<Int32, FORWARD_UdpPacketRecon*> udpHash [FORWARD_UDP_HASH_SIZE];

public:
    void UdpHashRequest(FORWARD_UdpPacketRecon* udpPacketData, Int32 messageId);
    void UdpRemoveRequest(Int32 id);
    BOOL UdpCheckAndRetrieveRequest(Int32 messageId, FORWARD_UdpPacketRecon** udpPacketData);
};

struct FORWARD_UdpTimeOutInfo
{
    Int32 messageId;
    clocktype timeout;
};
struct FORWARD_TcpStatsInfo
{
    int numTcpMsgSent;
    int numTcpMsgRecd;
    int tcpBytesSent;
    int tcpBytesRecd;
    int numTcpFragSent;
    int numTcpFragRecd;
    int fragHopCount;
    double packetHopCount;
    clocktype firstTcpPacketSendTime;
    clocktype lastTcpPacketSendTime;
    clocktype firstTcpFragRecdTime;
    clocktype lastTcpFragRecdTime;
    clocktype tcpEndtoEndDelay;
    clocktype tcpJitter;
    clocktype actTcpJitter;
    clocktype lastDelayTime;
    STAT_AppStatistics* tcpAppStats;
};

struct FORWARD_UdpStatsInfo
{
    int numUdpFragsSent;
    int numUdpFragsReceived;
    int numUdpPacketsReceived;
    int numUdpMulticastFragsSent;
    int numUdpMulticastFragsRecv;
    int numUdpUnicastFragsSent;
    int numUdpUnicastFragsRecv;
    int numUdpMulticastPacketsReceived;
    int numUdpUnicastPacketsReceived;
    int numUdpMulticastBytesReceived;
    int numUdpUnicastBytesReceived;
    int hopCount;
    int udpUnicastHopCount;
    int udpMulticastHopCount;
    int numUdpBroadcastPacketsReceived;
    int numUdpBroadcastFragsSent;
    int numUdpBroadcastFragsRecv;
    int numUdpBroadcastBytesReceived;
    clocktype udpJitter;
    clocktype actUdpJitter;
    clocktype udpEndtoEndDelay;
    clocktype udpUnicastJitter;
    clocktype udpMulticastJitter;
    clocktype actUdpUnicastJitter;
    clocktype actUdpMulticastJitter;
    clocktype udpUnicastDelay;
    clocktype udpMulticastDelay;
    clocktype udpServerSessionStart;
    clocktype udpServerSessionFinish;
    int numUdpBytesReceived;
    double udpSendPktTput;
    double udpRcvdPktTput;
    clocktype lastDelayTime;
#ifdef ADDON_DB
    clocktype actUdpFragsJitter;
    clocktype lastFragDelayTime;
#endif // ADDON_DB
    STAT_AppStatistics* udpAppStats;
};

typedef
struct struct_app_forward_str
{
    EXTERNAL_Interface *iface;
    int interfaceId;
    NodeAddress localAddr;
    NodeAddress remoteAddr;
    BOOL isServer;
    BOOL isMdpEnabled;
    BOOL isUdpMulticast;

    // For UDP
    short sourcePort;
    int udpMessageId;
    int udpUniqueFragNo;
    int udpUniqueFragNoRcvd;
#ifdef HUMAN_IN_THE_LOOP_DEMO
    D_UInt32 tos;
#else
    TosType tos;
#endif

    std::vector<FORWARD_UdpTimeOutInfo*> timeOutInfo;
    FORWARD_UdpRequestHash udpHashRequest;
    // For TCP
    FORWARD_TcpState tcpState;
    int connectionId;
    int uniqueId;
    BOOL waitingForDataSent;

    // The following variables are used for TCP packet reassembly.

    // The receive packet buffer.  Holds only one message.  The buffer will
    // always have enough space to store the CURRENT message, no guarantees
    // are made for the next message.
    char *buffer;

    // The amount of memory allocated for the buffer
    int bufferMaxSize;

    // The amount of data currently in the buffer.  The same as the amount
    // of data received for the current message if it does not contain
    // virtual data.
    int bufferSize;

    // The amount of data received.
    int receivedSize;

    // If we are currently receiving a message
    BOOL receivingMessage;

    // The size of the comm effects request
    // messageSize == actualSize + virtualSize
    int messageSize;

    // The actual amount of data we are receiving.  This will always include
    // the Forward TCP Header size.
    int actualSize;

    // The amount of virtual data we are receiving.
    int virtualSize;

    FORWARD_BufferedRequest *requestBuffer;
    FORWARD_BufferedRequest *lastRequest;

    clocktype beginStatsPeriod;
    clocktype lastDelayTime;
    D_UInt32 numPacketsSent;
    D_UInt32 numPacketsReceived;

    int numFragsReceived;
    D_UInt32 numPacketsSentToNode;

    int jitterId;
    clocktype jitter;
    clocktype actJitter;
    int packetLossId;
    double packetLoss;

    // Udp specific stats
    FORWARD_UdpStatsInfo *udpStats;
    // Tcp Specific stats
    FORWARD_TcpStatsInfo* tcpStats;
    //std::vector<FORWARD_PacketTosStats*> tosStats;
    //std::vector<int> packetPriorityTypes;
    FORWARD_PacketTosStats* tosStats[MAX_TOS_BITS];

    // Tcp ttl
    UInt8 ttl;

    std::vector<MessageInfoHeader> tcpInfoField;
    std::list<int> upperLimit;
    int clientSessionId;
    int serverSessionId;
#ifdef ADDON_DB
    int sessionInitiator;
    SequenceNumber *messageIdCache;
    SequenceNumber *fragNoCache;
    char applicationName[MAX_STRING_LENGTH];
    int receiverId;
#endif
}
AppDataForward;

/*
 * NAME:        AppLayerForward.
 * PURPOSE:     Models the behaviour of Forward on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerForward(Node *nodePtr, Message *msg);

/*
 * NAME:        AppForwardInit.
 * PURPOSE:     Initialize a Forward session.
 * PARAMETERS:  node - pointer to the node,
 *              externalInterfaceName - the name of the external interface
 *                                      to use for packet forwarding
 *              localAddr - the node's address
 *              remoteAddr - the address of the remote node
 *              isServer - true if this is the server of the pair
 *              isUdp - true if this function is called for UDP transmission
 * RETURN:      none.
 */
void
AppForwardInit(
    Node *node,
    const char *externalInterfaceName,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    BOOL isServer,
    BOOL isUdp = FALSE);

/*
 * NAME:        AppForwardPrintStats.
 * PURPOSE:     Prints statistics of a Forward session.
 * PARAMETERS:  nodePtr - pointer to the this node.
 *              forwardPtr - pointer to the forward data structure.
 * RETURN:      none.
 */
void
AppForwardPrintStats(Node *nodePtr, AppDataForward *forwardPtr);

void
ForwardRunTimeStat(Node *node, AppDataForward *forwardPtr);

/*
 * NAME:        AppForwardFinalize.
 * PURPOSE:     Collect statistics of a Forward session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppForwardFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppForwardGetForward.
 * PURPOSE:     search for a forward data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              localAddr - the local address
 *              remoteAddr - the address of the remote node
 *              interfaceId - the interface to find
 * RETURN:      the pointer to the forward data structure,
 *              NULL if nothing found.
 */
AppDataForward* AppLayerGetForward(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    int interfaceId);

/*
 * NAME:        AppForwardGetForwardByNameAndServer.
 * PURPOSE:     search for a forward data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              localAddr - the local address
 *              remoteAddr - the address of the remote node
 *              interfaceName - the name of the interface to find
 *              isServer - whether to get the server or client
 * RETURN:      the pointer to the forward data structure,
 *              NULL if nothing found.
 */
AppDataForward* AppLayerGetForwardByNameAndServer(
    Node *node,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    char* interfaceName,
    BOOL isServer);

/*
 * NAME:        AppForwardGetForwardByConnectionId.
 * PURPOSE:     search for a forward data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              connectionId - the connection to search for
 * RETURN:      the pointer to the forward data structure,
 *              NULL if nothing found.
 */
AppDataForward* AppLayerGetForwardByConnectionId(
    Node *node,
    int connectionId);

/*
 * NAME:        AppLayerGetForwardByRemoteAndInterfaceId.
 * PURPOSE:     search for a forward data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              remoteAddr - remote address
 *              interfaceId - get forward app with this interface id
 *              isServer - TRUE if we are the server
 * RETURN:      the pointer to the forward data structure,
 *              NULL if nothing found.
 */
AppDataForward* AppLayerGetForwardByRemoteAndInterfaceIdAndServer(
    Node *node,
    NodeAddress remoteAddr,
    int interfaceId,
    BOOL isServer);

/*
 * NAME:        AppLayerGetForwardBySourcePort.
 * PURPOSE:     search for a forward data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              sourcePort - get forward app with this source port
 * RETURN:      the pointer to the forward data structure,
 *              NULL if nothing found.
 */
AppDataForward* AppLayerGetForwardBySourcePort(
    Node *node,
    int sourcePort);

Message * ForwardTcpSendNewHeaderVirtualData(
    Node *node,
    int connId,
    char *header,
    int headerLength,
    int payloadSize,
    TraceProtocolType traceProtocol
#ifdef ADDON_DB
    ,
    StatsDBAppEventParam* appParam
#endif
    ,UInt8 ttl);


Message * ForwardTcpSendData(
    Node *node,
    int connId,
    char *payload,
    int length,
    TraceProtocolType traceProtocol
#ifdef ADDON_DB
    ,
    StatsDBAppEventParam* appParam
#endif
    ,UInt8 ttl);

#endif /* _FORWARD_APP_H_ */

