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
 * This file contains data structures and function prototypes used by
 * the generic FTP application.
 */

#ifndef GEN_FTP_APP_H
#define GEN_FTP_APP_H

#include "types.h"
#include "stats.h"
#include "stats_app.h"

typedef
struct struct_app_gen_ftp_client_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    BOOL sessionIsClosed;
    int itemSize;
    Int32 itemsToSend;
    clocktype endTime;
    Int32 uniqueId;
    TosType tos;
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
AppDataGenFtpClient;

typedef
struct struct_app_gen_ftp_server_str
{
    int connectionId;
    Address localAddr;
    Address remoteAddr;
    BOOL sessionIsClosed;
    Int32 uniqueId;
    STAT_AppStatistics* stats;
}
AppDataGenFtpServer;

/*
 * NAME:        AppLayerGenFtpClient.
 * PURPOSE:     Models the behaviour of ftp client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerGenFtpClient(Node *nodePtr, Message *msg);

/*
 * NAME:        AppGenFtpClientInit.
 * PURPOSE:     Initialize a ftp session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each item.
 *              startTime - time until the session starts.
 *              endTime - time when session is over.
 *              tos - the contents for the type of service field
 *              appName - application alias name
 *              destString - destination string
 * RETURN:      none.
 */
void
AppGenFtpClientInit(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype startTime,
    clocktype endTime,
    unsigned tos,
    char* appName,
    char* destString);

/*
 * NAME   :: AppGenFtpInitTrace
 * PURPOSE    :: FtpGen initialization  for tracing
 * PARAMETERS ::
 * + node : Node* : Pointer to node
 * + nodeInput    : const NodeInput* : Pointer to NodeInput
 * RETURN ::  void : NULL
 */

void AppGenFtpInitTrace(Node* node, const NodeInput* nodeInput);

/*
 * NAME:        AppGenFtpClientPrintStats.
 * PURPOSE:     Prints statistics of a ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              clientPtr - pointer to the ftp client data structure.
 * RETURN:      none.
 */
void
AppGenFtpClientPrintStats(Node *nodePtr, AppDataGenFtpClient *clientPtr);

/*
 * NAME:        AppGenFtpClientFinalize.
 * PURPOSE:     Collect statistics of a ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppGenFtpClientFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppGenFtpClientGetGenFtpClient.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              connId - connection ID of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpClient *
AppGenFtpClientGetGenFtpClient(Node *nodePtr, int connId);

/*
 * NAME:        AppGenFtpClientGetGenFtpClientWithUniqueId.
 * PURPOSE:     search for a ftp client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              uniqueId - uniqueId of the ftp client.
 * RETURN:      the pointer to the ftp client data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpClient * //inline//
AppGenFtpClientGetGenFtpClientWithUniqueId(Node *node, Int32 uniqueId);

/*
 * NAME:        AppGenFtpClientUpdateGenFtpClient.
 * PURPOSE:     update existing ftp client data structure by including
 *              connection id.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpClient *
AppGenFtpClientUpdateGenFtpClient(Node *nodePtr,
                                  TransportToAppOpenResult *openResult);

/*
 * NAME:        AppGenFtpClientNewGenFtpClient.
 * PURPOSE:     create a new ftp client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverAddr - ftp server to this client.
 *              itemsToSend - number of ftp items to send in simulation.
 *              itemSize - size of each item.
 *              endTime - when simulation of ftp ends.
 *              tos - given priority value.
 *              appName - application alias name
 * RETRUN:      the pointer to the created ftp client data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpClient *
AppGenFtpClientNewGenFtpClient(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype endTime,
    TosType tos,
    char* appName);

/*
 * NAME:        AppGenFtpClientSendNextItem.
 * PURPOSE:     Send the next item.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 * RETRUN:      none.
 */
void
AppGenFtpClientSendNextItem(Node *nodePtr,
                            AppDataGenFtpClient *clientPtr);

/*
 * NAME:        AppGenFtpClientSendPacket.
 * PURPOSE:     Send the remaining data.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the ftp client data structure.
 *              end - end of session.
 * RETURN:      none.
 */
void
AppGenFtpClientSendPacket(
    Node *nodePtr,
    AppDataGenFtpClient *clientPtr,
    BOOL end);


/*
 * NAME:        AppLayerGenFtpServer.
 * PURPOSE:     Models the behaviour of ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerGenFtpServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppGenFtpServerInit.
 * PURPOSE:     listen on ftp server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppGenFtpServerInit(Node *nodePtr, Address serverAddr);

/*
 * NAME:        AppGenFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppGenFtpServerPrintStats(Node *nodePtr, AppDataGenFtpServer *serverPtr);

/*
 * NAME:        AppGenFtpServerFinalize.
 * PURPOSE:     Collect statistics of a ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppGenFtpServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppGenFtpServerGetGenFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataGenFtpServer *
AppGenFtpServerGetGenFtpServer(Node *nodePtr, int connId);

/*
 * NAME:        AppGenFtpServerNewGenFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataGenFtpServer *
AppGenFtpServerNewGenFtpServer(Node *nodePtr,
                               TransportToAppOpenResult *openResult);

/*
 * FUNCTION   :: AppGenFtpPrintTraceXML
 * PURPOSE    :: Print packet trace information in XML format
 * PARAMETERS ::node     : Node*    : Pointer to node
 *              msg      : Message* : Pointer to packet to print headers
 * RETURN     ::  void   : NULL
*/
void AppGenFtpPrintTraceXML(Node* node, Message* msg);

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppGenFtpClientAddAddressInformation.
// PURPOSE              : store client interface index, destination 
//                        interface index destination node id to get the 
//                        correct address when application starts
// PARAMETERS:
// + node               : Node*                : pointer to the node
// + clientPtr          : AppDataGenFtpClient* : pointer to client data
// RETURN               : void
//---------------------------------------------------------------------------
void
AppGenFtpClientAddAddressInformation(
                                  Node* node,
                                  AppDataGenFtpClient* clientPtr);

//--------------------------------------------------------------------------
// FUNCTION    :: AppGenFtpUrlSessionStartCallBack
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
AppGenFtpUrlSessionStartCallBack(
                    Node* node,
                    Address* serverAddr,
                    UInt16 sourcePort,
                    Int32 uniqueId,
                    Int16 interfaceId,
                    std::string serverUrl,
                    struct AppUdpPacketSendingInfo* packetSendingInfo);

//---------------------------------------------------------------------------
// FUNCTION             : AppGenFtpClientGetClientPtr.
// PURPOSE              : get the FTP-GEN client pointer
// PARAMETERS:
// + node               : Node* : pointer to the node
// + uniqueId           : Int32*: unique id
// RETURN               
// AppDataGenFtpClient*    : gen - ftp client pointer
//---------------------------------------------------------------------------
AppDataGenFtpClient*
AppGenFtpClientGetClientPtr(Node* node, Int32 uniqueId);




#endif /* _GEN_FTP_APP_H_ */
