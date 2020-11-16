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
 * This file contains data structure used by telnet client and
 * prototypes of functions defined in telnet_client.pc.
 */
#ifndef ETELNET_APP_H
#define ETELNET_APP_H

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
struct struct_app_etelnet_client_str
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
}
AppDataETelnetClient;

typedef
struct struct_app_etelnet_server_str
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
    int state;
    char *lines[TELNETD_CONF_NUMLINES];
    char buf[TELNETD_CONF_LINELEN];
    char bufPtr;
}
AppDataETelnetServer;

/*
 * NAME:        AppLayerETelnetServer.
 * PURPOSE:     Models the behaviour of Telnet server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerETelnetServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppETelnetServerInit.
 * PURPOSE:     listen on Telnet server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppETelnetServerInit(Node *nodePtr, Address serverAddr);

/*
 * NAME:        AppETelnetServerFinalize.
 * PURPOSE:     Collect statistics of a ETelnetServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppETelnetServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppETelnetServerPrintStats.
 * PURPOSE:     Prints statistics of a ETelnetServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void //inline//
AppETelnetServerPrintStats(Node *nodePtr, AppDataETelnetServer *serverPtr);

/*
 * NAME:        AppETelnetServerGetETelnetServer.
 * PURPOSE:     search for a telnet server data structure.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              connId - connection ID of the telnet server.
 * RETURN:      the pointer to the telnet server data structure,
 *              NULL if nothing found.
 */
AppDataETelnetServer * //inline//
AppETelnetServerGetETelnetServer(Node *nodePtr, int connId);

/*
 * NAME:        AppETelnetServerNewETelnetServer.
 * PURPOSE:     create a new telnet server data structure, place it
                at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created telnet server data structure,
 *              NULL if no data structure allocated.
 */
AppDataETelnetServer * //inline//
AppETelnetServerNewETelnetServer(Node *nodePtr,
                               TransportToAppOpenResult *openResult);


/*
 * NAME:        AppETelnetServerSendResponse.
 * PURPOSE:     call AppETelnetServerRespPktSize() to get the
 *              response packet size,
                and send the packet.
 * PARAMETERS:  node - pointer to the node,
 *              serverPtr - pointer to the server data structure.
                data - S_TELNET data from client
                size - size of S_TELNET data from client
 * RETRUN:      none.
 */
void //inline//
AppETelnetServerSendResponse(Node *node,     
                            AppDataETelnetServer *serverPtr, 
                            char * data, 
                            int size);


/*
 * NAME:        AppETelnetServerSendResponse.
 * PURPOSE:     call AppETelnetServerRespPktSize() to get the
 *              response packet size,
                and send the packet.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void //inline//
AppETelnetServerSendResponse(Node *nodePtr,
                            AppDataETelnetServer *serverPtr);

/*
 * NAME:        AppETelnetServerRespPktSize.
 * PURPOSE:     call tcplib function telnet_pktsize().
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETRUN:      telnet control packet size.
 */
int //inline//
AppETelnetServerRespPktSize(Node *nodePtr, AppDataETelnetServer *serverPtr);

struct ptentry {
    char *commandstr;
    void (* pfunc)(Node *node, AppDataETelnetServer *serverPtr, char *str);
};

void AppETelnetServerSendWelcomeMsg(Node *node, AppDataETelnetServer *serverPtr);
void AppETelnetServerShellPrompt(Node *node, AppDataETelnetServer *serverPtr);

//TELNET command
void AppETelnetServerCommandHelp(Node *node, AppDataETelnetServer *serverPtr, char *str);
void AppETelnetServerCommandShellQuit(Node *node, AppDataETelnetServer *serverPtr, char *str);
void AppETelnetServerCommandUnknown(Node *node, AppDataETelnetServer *serverPtr, char *str);
void AppETelnetServerCommandTelnetStats(Node *node, AppDataETelnetServer *serverPtr, char *str);
void AppETelnetServerCommandTelnetConn(Node *node, AppDataETelnetServer *serverPtr, char *str);

#endif /* _ETELNET_APP_H_ */
