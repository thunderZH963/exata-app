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
 * This file contains data structure used by the ftp application and
 * prototypes of functions defined in ftp.c.
 */

#ifndef FTP_APP_H
#define FTP_APP_H

#include "types.h"
#include "stats_app.h"

typedef
struct struct_app_ftp_client_str
{
    int         connectionId;
    Address     localAddr;
    Address     remoteAddr;
    clocktype   sessionStart;
    clocktype   sessionFinish;
    clocktype   lastTime;
    BOOL        sessionIsClosed;
    int         itemsToSend;
    int         itemSizeLeft;
    Int32       bytesRecvdDuringThePeriod;
    clocktype   lastItemSent;
    int         uniqueId;
    RandomSeed  seed;
    char        cmd[MAX_STRING_LENGTH];
    std::string* applicationName;
    STAT_AppStatistics* stats;

    // Dynamic Address
    NodeId destNodeId; // destination node id for this app session 
    Int16 clientInterfaceIndex; // client interface index for this app 
                                // session
    Int16 destInterfaceIndex; // destination interface index for this app
                              // session
    std::string* serverUrl;

}
AppDataFtpClient;

typedef
struct struct_app_ftp_server_str
{
    int         connectionId;
    Address     localAddr;
    Address     remoteAddr;
    clocktype   sessionStart;
    clocktype   sessionFinish;
    clocktype   lastTime;
    BOOL        sessionIsClosed;
    Int32       bytesRecvdDuringThePeriod;
    clocktype   lastItemSent;
    Int32       uniqueId;
    RandomSeed  seed;
//
    BOOL        isLoggedIn;
    int         portForDataConn;
    STAT_AppStatistics* stats;
}
AppDataFtpServer;

/*
 * NAME:        AppLayerFtpClient.
 * PURPOSE:     Models the behaviour of Ftp Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerFtpClient(Node *nodePtr, Message *msg);

/*
 * NAME:        AppFtpClientInit.
 * PURPOSE:     Initialize a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              waitTime - time until the session starts.
 *              appName - application alias name
 *              destString - destination string
 * RETURN:      none.
 */
void
AppFtpClientInit(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    int itemsToSend,
    clocktype waitTime,
    char* appName,
    char* destString);

/*
 * NAME:        AppFtpClientPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              clientPtr - pointer to the ftp client data structure.
 * RETURN:      none.
 */
void
AppFtpClientPrintStats(Node *nodePtr, AppDataFtpClient *clientPtr);

/*
 * NAME:        AppFtpClientFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppFtpClientFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppFtpClientGetFtpClient.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              connId - connection ID of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataFtpClient *
AppFtpClientGetFtpClient(Node *nodePtr, int connId);

/*
 * NAME:        AppFtpClientUpdateFtpClient.
 * PURPOSE:     update existing ftp client data structure by including
 *              connection id.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpClient *
AppFtpClientUpdateFtpClient(
    Node *nodePtr,
    TransportToAppOpenResult *openResult);

/*
 * NAME:        AppFtpClientNewFtpClient.
 * PURPOSE:     create a new ftp client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              clientAddr - address of this client.
 *              serverAddr - ftp server to this client.
 *              itemsToSend - number of ftp items to send in simulation.
 *              appName - user defined application alias name
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpClient *
AppFtpClientNewFtpClient(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    int itemsToSend,
    char* appName);

/*
 * NAME:        AppFtpClientSendNextItem.
 * PURPOSE:     Send the next item.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */
void
AppFtpClientSendNextItem(Node *nodePtr, AppDataFtpClient *clientPtr);

/*
 * NAME:        AppFtpClientSendNextPacket.
 * PURPOSE:     Send the remaining data.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */
void
AppFtpClientSendNextPacket(Node *nodePtr, AppDataFtpClient *clientPtr);

/*
 * NAME:        AppFtpClientItemsToSend.
 * PURPOSE:     call tcplib function ftp_nitems() to get the
 *              number of items to send in an ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      amount of items to send.
 */
int
AppFtpClientItemsToSend(AppDataFtpClient *clientPtr);

/*
 * NAME:        AppFtpClientItemSize.
 * PURPOSE:     call tcplib function ftp_itemsize() to get the size
 *              of each item.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      size of an item.
 */
int
AppFtpClientItemSize(AppDataFtpClient *clientPtr);

/*
 * NAME:        AppFtpServerCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppFtpClientCtrlPktSize(AppDataFtpClient *clientPtr);

/*
 * NAME:        AppLayerFtpServer.
 * PURPOSE:     Models the behaviour of Ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerFtpServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppFtpServerInit.
 * PURPOSE:     listen on Ftp server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppFtpServerInit(Node *nodePtr, Address serverAddr);

/*
 * NAME:        AppFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppFtpServerPrintStats(Node *nodePtr, AppDataFtpServer *serverPtr);


/*
 * NAME:        AppFtpServerFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppFtpServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppFtpServerGetFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataFtpServer *
AppFtpServerGetFtpServer(Node *nodePtr, int connId);

/*
 * NAME:        AppFtpServerNewFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataFtpServer *
AppFtpServerNewFtpServer(Node *nodePtr,
                         TransportToAppOpenResult *openResult);

/*
 * NAME:        AppFtpServerSendCtrlPkt.
 * PURPOSE:     call AppFtpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppFtpServerSendCtrlPkt(Node *nodePtr, AppDataFtpServer *serverPtr);

/*
 * NAME:        AppFtpServerCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppFtpServerCtrlPktSize(AppDataFtpServer *serverPtr);

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             :AppFtpClientAddAddressInformation.
// PURPOSE              :store client interface index, destination 
//                       interface index destination node id to get the 
//                       correct address when TCP starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataFtpClient* : pointer to CBR client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppFtpClientAddAddressInformation(Node* node,
                                  AppDataFtpClient* clientPtr);

//---------------------------------------------------------------------------
// FUNCTION             : AppFtpClientGetClientPtr.
// PURPOSE              : get the FTP client pointer
// PARAMETERS           ::
// + node               : Node* : pointer to the node
// + uniqueId           : Int32 : unique id
// RETURN               
// AppDataFtpClient*    : ftp client pointer
//---------------------------------------------------------------------------
AppDataFtpClient*
AppFtpClientGetClientPtr(Node* node,
                        Int32 uniqueId);

// dns
//--------------------------------------------------------------------------
// FUNCTION    :: AppFtpUrlSessionStartCallBack
// PURPOSE     :: To open the TCP connection at the client 
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
//                                                 used by FTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as 
//                this callback will initiate TCP Open request and not send 
//                packet
//--------------------------------------------------------------------------
bool
AppFtpUrlSessionStartCallBack(Node* node,
                     Address* serverAddr,
                     UInt16 sourcePort,
                     Int32 uniqueId,
                     Int16 interfaceId,
                     std::string serverUrl,
                     struct AppUdpPacketSendingInfo* packetSendingInfo);


#endif /* _FTP_APP_H_ */
