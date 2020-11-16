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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

/*
 * This file contains data structure used by the ftp application and
 * prototypes of functions defined in ftp.c.
 */

#ifndef EFTP_APP_H
#define EFTP_APP_H

#include "types.h"

typedef struct struct_app_eftp_client_str
{
    int         connectionId;
    Address     localAddr;
    Address     remoteAddr;
    clocktype   sessionStart;
    clocktype   sessionFinish;
    clocktype   lastTime;
    BOOL        sessionIsClosed;
    int         itemsToSend;
    Int64         itemSize;
    Int64       numBytesSent;
    Int64       numBytesRecvd;
    Int32       bytesRecvdDuringThePeriod;
    clocktype   lastItemSent;
    int         uniqueId;
    RandomSeed  seed;
//DERIUS
    Int64         sendPtr;
    std::string   fileToSend;
    char        cmd[MAX_STRING_LENGTH];

    
} AppDataEFtpClient;

typedef struct struct_app_eftp_server_str
{
    int         connectionId;
    Address     localAddr;
    Address     remoteAddr;
    clocktype   sessionStart;
    clocktype   sessionFinish;
    clocktype   lastTime;
    BOOL        sessionIsClosed;
    Int64       numBytesSent;
    Int64       numBytesRecvd;
    Int32       bytesRecvdDuringThePeriod;
    clocktype   lastItemSent;
    RandomSeed  seed;
//
    BOOL        isLoggedIn;
    int         portForDataConn;
} AppDataEFtpServer;

/*
 * NAME:        AppLayerEFtpServer.
 * PURPOSE:     Models the behaviour of Ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerEFtpServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppEFtpServerInit.
 * PURPOSE:     listen on Ftp server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppEFtpServerInit(
    Node *nodePtr, 
    Address serverAddr, 
    BOOL isFileAccessMode,
    const char* rootFileSystem);

/*
 * NAME:        AppEFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppEFtpServerPrintStats(Node *nodePtr, AppDataEFtpServer *serverPtr);


/*
 * NAME:        AppEFtpServerFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppEFtpServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppEFtpServerGetFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataEFtpServer *
AppEFtpServerGetFtpServer(Node *nodePtr, int connId);

/*
 * NAME:        AppEFtpServerNewFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataEFtpServer *
AppEFtpServerNewFtpServer(Node *nodePtr,
                         TransportToAppOpenResult *openResult);

/*
 * NAME:        AppEFtpServerSendCtrlPkt.
 * PURPOSE:     call AppEFtpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppEFtpServerSendCtrlPkt(Node *nodePtr, AppDataEFtpServer *serverPtr);

/*
 * NAME:        AppEFtpServerCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppEFtpServerCtrlPktSize(AppDataEFtpServer *serverPtr);

void AppEFtpServerWelcomeMessage(Node *node, AppDataEFtpServer *ftpServer);
void AppEFtpServerMessageToClient(Node *node, AppDataEFtpServer *serverPtr, char * output, int outputLen);
void AppEFtpServerMessageToClient(Node *node, AppDataEFtpClient *serverPtr, char * output, int outputLen);
int AppEFtpServerSizeForNum(int fileSize);


void AppEFtpServerCommandParse(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandList(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len);
void AppEFtpServerCommandPass(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len);
void AppEFtpServerCommandUser(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len);
void AppEFtpServerCommandQuit(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len);
void AppEFtpServerCommandType(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len);
void AppEFtpServerCommandSyst(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandPort(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandPasv(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandAuth(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandPwd(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandEprt(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);

void AppEFtpServerCommandUnknown(Node *node, AppDataEFtpServer *serverPtr, char *cmd, int len=0);

void AppEFtpServerSaveIpPortInfo(AppDataEFtpServer *ftpServer, char *cmd);
void AppEFtpServerSaveIpv6PortInfo(AppDataEFtpServer *ftpServer, char *cmd);

BOOL AppEFtpServerIsValidUser(void);
void AppEFtpServerNotLoggedInMessage(Node *node, AppDataEFtpServer *ftpServer);

void AppLayerEFtpServerData(Node *node, Message *msg);
void AppEFtpServerOpenDataPort(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
AppDataEFtpClient * AppEFtpServerDataPortConnect(Node *node, Address localAddr, Address remoteAddr);
void AppEFtpServerDataExecuteCommand(Node *node, AppDataEFtpClient *clientPtr);
AppDataEFtpClient * AppEFtpServerDataUpdateFtp(Node *node, TransportToAppOpenResult *openResult);
void AppEFtpServerCommandRetr(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerCommandStor(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len);
void AppEFtpServerSendFile(Node *node, AppDataEFtpClient *clientPtr);

int AppEFtpServerAvailableFile(Node *node, char * fileName);

AppDataEFtpClient * AppEFtpServerDataGetFtp(Node *node, int connId);

struct ftp_command_list {
    const char *commandstr;
    void (* pfunc)(Node *node, AppDataEFtpServer *serverPtr, char *str, int len);
};

struct available_file_list {
    const char *fileName;
    int fileSize; 
};
#endif /* _EFTP_APP_H_ */
