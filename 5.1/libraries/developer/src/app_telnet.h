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
 * This file contains data structure used by telnet client and
 * prototypes of functions defined in telnet_client.pc.
 */
#ifndef TELNET_APP_H
#define TELNET_APP_H

#include "types.h"

#define STATE_NORMAL 0
#define STATE_IAC    1
#define STATE_WILL   2
#define STATE_WONT   3
#define STATE_DO     4
#define STATE_DONT   5
#define STATE_CLOSE  6

#define TELNET_IAC   255
#define TELNET_WILL  251
#define TELNET_WONT  252
#define TELNET_DO    253
#define TELNET_DONT  254

#define ISO_nl       0x0a
#define ISO_cr       0x0d

#ifndef TELNETD_CONF_LINELEN
#define TELNETD_CONF_LINELEN 40
#endif
#ifndef TELNETD_CONF_NUMLINES
#define TELNETD_CONF_NUMLINES 16
#endif



typedef
struct struct_app_telnet_client_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessDuration;
    BOOL sessionIsClosed;
    Int64 numBytesSent;
    Int64 numBytesRecvd;
    clocktype lastItemSent;

    Int32 uniqueId;
    RandomSeed durationSeed;
    RandomSeed intervalSeed;

    // Dynamic Address
    NodeId destNodeId; // destination node id for this app session 
    Int16 clientInterfaceIndex; // client interface index for this app 
                                // session
    Int16 destInterfaceIndex; // destination interface index for this app
                              // session
    std::string* serverUrl;
}
AppDataTelnetClient;

typedef
struct struct_app_telnet_server_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL sessionIsClosed;
    Int64 numBytesSent;
    Int64 numBytesRecvd;
    clocktype lastItemSent;
    RandomSeed packetSizeSeed;
//DERIUS for Standalone Telnet server
    int state;
    char *lines[TELNETD_CONF_NUMLINES];
    char buf[TELNETD_CONF_LINELEN];
    char bufPtr;
}
AppDataTelnetServer;

/*
 * NAME:        AppLayerTelnetClient.
 * PURPOSE:     Models the behaviour of TelnetClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerTelnetClient(Node *nodePtr, Message *msg);

/*
 * NAME:        AppTelnetClientInit.
 * PURPOSE:     Initialize a TelnetClient session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              sessDuration - length of telnet session.
 *              waitTime - time until the session starts.
 *              destString - destination string
 * RETURN:      none.
 */
void
AppTelnetClientInit(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    clocktype sessDuration,
    clocktype waitTime,
    char* destString);

/*
 * NAME:        AppTelnetClientFinalize.
 * PURPOSE:     Collect statistics of a TelnetClient session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppTelnetClientFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppTelnetClientPrintStats.
 * PURPOSE:     Prints statistics of a TelnetClient session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              clientPtr - pointer to the telnet client data structure.
 * RETURN:      none.
 */
void //inline//
AppTelnetClientPrintStats(Node *nodePtr, AppDataTelnetClient *clientPtr);

/*
 * NAME:        AppTelnetClientGetTelnetClient.
 * PURPOSE:     search for a telnet client data structure.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              connId - connection ID of the telnet client.
 * RETURN:      the pointer to the telnet client data structure,
 *              NULL if nothing found.
 */
AppDataTelnetClient * //inline//
AppTelnetClientGetTelnetClient(Node *nodePtr, int connId);

/*
 * NAME:        AppTelnetClientUpdateTelnetClient.
 * PURPOSE:     create a new telnet client data structure, place it
                at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created telnet client data structure,
 *              NULL if no data structure allocated.
 */
AppDataTelnetClient * //inline//
AppTelnetClientUpdateTelnetClient(Node *nodePtr,
                                  TransportToAppOpenResult *openResult);

/*
 * NAME:        AppTelnetClientNewTelnetClient.
 * PURPOSE:     create a new telnet client data structure, place it
                at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              localAddr - address of this client.
 *              serverAddr - server node of this telnet session.
 *              sessDuration - length of telnet session.
 * RETRUN:      the pointer to the created telnet client data structure,
 *              NULL if no data structure allocated.
 */
AppDataTelnetClient * //inline//
AppTelnetClientNewTelnetClient(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    clocktype sessDuration);

/*
 * NAME:        AppTelnetClientScheduleNextPkt.
 * PURPOSE:     schedule the next packet the client will send.  If next packet
 *              won't arrive until the finish deadline, schedule a close.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the telnet client data structure.
 * RETRUN:      none.
 */
void //inline//
AppTelnetClientScheduleNextPkt(Node *nodePtr,
                               AppDataTelnetClient *clientPtr);

/*
 * NAME:        AppTelnetClientSessDuration.
 * PURPOSE:     call tcplib function telnet_duration to get the duration
 *              of this session.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      session duration in clocktype.
 */
clocktype //inline//
AppTelnetClientSessDuration(Node *nodePtr,
                            AppDataTelnetClient *clientPtr);

/*
 * NAME:        AppTelnetClientPktInterval.
 * PURPOSE:     call tcplib function telnet_interarrival to get the
 *              between the arrival of the next packet and the current one.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      interarrival time in clocktype.
 */
clocktype //inline//
AppTelnetClientPktInterval(Node *nodePtr,
                           AppDataTelnetClient *clientPtr);



/*
 * NAME:        AppLayerTelnetServer.
 * PURPOSE:     Models the behaviour of Telnet server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerTelnetServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppTelnetServerInit.
 * PURPOSE:     listen on Telnet server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppTelnetServerInit(Node *nodePtr, Address serverAddr);

/*
 * NAME:        AppTelnetServerFinalize.
 * PURPOSE:     Collect statistics of a TelnetServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppTelnetServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppTelnetServerPrintStats.
 * PURPOSE:     Prints statistics of a TelnetServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void //inline//
AppTelnetServerPrintStats(Node *nodePtr, AppDataTelnetServer *serverPtr);

/*
 * NAME:        AppTelnetServerGetTelnetServer.
 * PURPOSE:     search for a telnet server data structure.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              connId - connection ID of the telnet server.
 * RETURN:      the pointer to the telnet server data structure,
 *              NULL if nothing found.
 */
AppDataTelnetServer * //inline//
AppTelnetServerGetTelnetServer(Node *nodePtr, int connId);

/*
 * NAME:        AppTelnetServerNewTelnetServer.
 * PURPOSE:     create a new telnet server data structure, place it
                at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created telnet server data structure,
 *              NULL if no data structure allocated.
 */
AppDataTelnetServer * //inline//
AppTelnetServerNewTelnetServer(Node *nodePtr,
                               TransportToAppOpenResult *openResult);


/*
 * NAME:        AppTelnetServerSendResponse.
 * PURPOSE:     call AppTelnetServerRespPktSize() to get the
 *              response packet size,
                and send the packet.
 * PARAMETERS:  node - pointer to the node,
 *              serverPtr - pointer to the server data structure.
                data - S_TELNET data from client
                size - size of S_TELNET data from client
 * RETRUN:      none.
 */
void //inline//
AppTelnetServerSendResponse(Node *node,     
                            AppDataTelnetServer *serverPtr, 
                            char * data, 
                            int size);


/*
 * NAME:        AppTelnetServerSendResponse.
 * PURPOSE:     call AppTelnetServerRespPktSize() to get the
 *              response packet size,
                and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void //inline//
AppTelnetServerSendResponse(Node *nodePtr,
                            AppDataTelnetServer *serverPtr);

/*
 * NAME:        AppTelnetServerRespPktSize.
 * PURPOSE:     call tcplib function telnet_pktsize().
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      telnet control packet size.
 */
int //inline//
AppTelnetServerRespPktSize(Node *nodePtr, AppDataTelnetServer *serverPtr);

//---------------------------------------------------------------------------
// FUNCTION             : AppTelnetClientAddAddressInformation.
// PURPOSE              : store client interface index, destination 
//                        interface index destination node id to get the 
//                        correct address when application starts
// PARAMETERS:
// + node               : Node*                : pointer to the node
// + clientPtr          : AppDataTelnetClient* : pointer to client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppTelnetClientAddAddressInformation(
                                  Node* node,
                                  AppDataTelnetClient* clientPtr);

//---------------------------------------------------------------------------
// FUNCTION             : AppTelnetClientGetClientPtr.
// PURPOSE              : get the TELNET client pointer based on unique id
// PARAMETERS           ::
// + node               : Node* : pointer to the node
// + uniqueId           : Int32 : unique id
// RETRUN               
// AppDataFtpClient*    : ftp client pointer
//---------------------------------------------------------------------------
AppDataTelnetClient*
AppTelnetClientGetClientPtr(
                        Node* node,
                        Int32 uniqueId);

//--------------------------------------------------------------------------
// FUNCTION    : AppTelnetUrlSessionStartCallBack
// PURPOSE     : To handle dns information
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : unsigned short : source port
// + uniqueId   : Int32          : connection id
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo : information required to 
//                                                 send buffered application 
//                                                 packets in case of UDP 
//                                                 based applications; not
//                                                 used by TELNET
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//--------------------------------------------------------------------------
bool
AppTelnetUrlSessionStartCallBack(
                        Node* node,
                        Address* serverAddr,
                        UInt16 sourcePort,
                        Int32 uniqueId,
                        Int16 interfaceId,
                        std::string serverUrl,
                        struct AppUdpPacketSendingInfo* packetSendingInfo);

#endif /* _TELNET_APP_H_ */
