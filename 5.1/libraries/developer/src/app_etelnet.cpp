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
 * This file contains initialization function, message processing
 * function, and finalize function used by telnet application.
 */
#ifdef EXATA
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "product_info.h"
#include "api.h"
#include "transport_tcp.h"
#include "tcpapps.h"
#include "app_util.h"
#include "app_etelnet.h"
#define noDEBUG

static struct ptentry parsetab[] =
            {{(char*)"stats", AppETelnetServerCommandTelnetStats},
            {(char*)"conn", AppETelnetServerCommandTelnetConn},
            {(char*)"help", AppETelnetServerCommandHelp},
            {(char*)"exit", AppETelnetServerCommandShellQuit},
            {(char*)"?", AppETelnetServerCommandHelp},
            /* Default action */
            {(char*)NULL, AppETelnetServerCommandUnknown}};

/*
 * NAME:        AppLayerETelnetServer.
 * PURPOSE:     Models the behaviour of Telnet server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerETelnetServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataETelnetServer *serverPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: node %u got listenResult\n",
                   buf, node->nodeId);
#endif /* DEBUG */

            if (listenResult->connectionId == -1)
            {
                node->appData.numAppTcpFailure ++;
            }

            break;
        }
        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;

            openResult = (TransportToAppOpenResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: node %u got OpenResult\n", buf, node->nodeId);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_PASSIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure ++;
            }
            else
            {
                AppDataETelnetServer *serverPtr;
                serverPtr = AppETelnetServerNewETelnetServer(node, openResult);
                assert(serverPtr != NULL);
            }

            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: node %u sent data %ld\n", buf, node->nodeId,
                   dataSent->length);
#endif /* DEBUG */

            serverPtr = AppETelnetServerGetETelnetServer(node,
                                        dataSent->connectionId);
            assert(serverPtr != NULL);

            serverPtr->numBytesSent += (clocktype) dataSent->length;
            serverPtr->lastItemSent = node->getNodeTime();

            break;
        }
        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived *dataRecvd;

            dataRecvd = (TransportToAppDataReceived *)
                        MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: node %u received data %ld\n",
                   buf, node->nodeId, msg->packetSize);
#endif /* DEBUG */

            serverPtr = AppETelnetServerGetETelnetServer(
                            node,
                            dataRecvd->connectionId);

            assert(serverPtr != NULL);

            serverPtr->numBytesRecvd += (clocktype) msg->packetSize;

            //parsing the parameters
            AppETelnetServerSendResponse(node, serverPtr, msg->packet, msg->packetSize);
            
            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("%s: node %u got close result\n",
                   buf, node->nodeId);
#endif /* DEBUG */

            serverPtr = AppETelnetServerGetETelnetServer(node,
                                                 closeResult->connectionId);

            assert(serverPtr != NULL);

            if (serverPtr->sessionIsClosed == FALSE)
            {
                serverPtr->sessionIsClosed = TRUE;
                serverPtr->sessionFinish = node->getNodeTime();
            }

            break;
        }
        default:
            ctoa(node->getNodeTime(), buf);
            printf("Time %s: Node %u received message of unknown type"
                   " %d.\n", buf, node->nodeId, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppETelnetServerInit.
 * PURPOSE:     listen on Telnet server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppETelnetServerInit(Node *node, Address serverAddr)
{
    if (serverAddr.networkType != NETWORK_IPV4
        && serverAddr.networkType != NETWORK_IPV6)
    {
        return;
    }

    APP_TcpServerListen(
        node,
        APP_ETELNET_SERVER,
        serverAddr,
        (short) APP_ETELNET_SERVER);
}

/*
 * NAME:        AppETelnetServerFinalize.
 * PURPOSE:     Collect statistics of a ETelnetServer session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppETelnetServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataETelnetServer *serverPtr =
        (AppDataETelnetServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppETelnetServerPrintStats(node, serverPtr);
    }
}

/*
 * NAME:        AppETelnetServerPrintStats.
 * PURPOSE:     Prints statistics of a ETelnetServer session.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void //inline//
AppETelnetServerPrintStats(Node *node, AppDataETelnetServer *serverPtr)
{
    clocktype throughput;
    char addrStr[MAX_STRING_LENGTH];
    char startStr[MAX_STRING_LENGTH];
    char finishStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char numBytesSentStr[MAX_STRING_LENGTH];
    char numBytesRecvdStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(serverPtr->sessionStart, startStr);
    TIME_PrintClockInSecond(serverPtr->lastItemSent, finishStr);

    if (serverPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
    }
    else
    {
        sprintf(statusStr, "Closed");
    }

    if (serverPtr->sessionFinish <= serverPtr->sessionStart)
    {
        throughput = 0;
    }
    else
    {
        throughput =
            (clocktype) ((serverPtr->numBytesRecvd * 8.0 * SECOND)
            / (serverPtr->sessionFinish - serverPtr->sessionStart));
    }

    ctoa(throughput, throughputStr);
    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "First Packet Sent at (s) = %s", startStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Last Packet Sent at (s) = %s", finishStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesSent, numBytesSentStr);
    sprintf(buf, "Total Bytes Sent = %s", numBytesSentStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesRecvd, numBytesRecvdStr);
    sprintf(buf, "Total Bytes Received = %s", numBytesRecvdStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
    IO_PrintStat(
        node,
        "Application",
        "Telnet Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);
}

/*
 * NAME:        AppETelnetServerGetETelnetServer.
 * PURPOSE:     search for a telnet server data structure.
 * PARAMETERS:  node - pointer to the node,
 *              connId - connection ID of the telnet server.
 * RETURN:      the pointer to the telnet server data structure,
 *              NULL if nothing found.
 */
AppDataETelnetServer * //inline//
AppETelnetServerGetETelnetServer(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataETelnetServer *telnetServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_ETELNET_SERVER)
        {
            telnetServer = (AppDataETelnetServer *) appList->appDetail;

            if (telnetServer->connectionId == connId)
            {
                return telnetServer;
            }
        }
    }

    return NULL;
}

/*
 * NAME:        AppETelnetServerNewETelnetServer.
 * PURPOSE:     create a new telnet server data structure, place it
                at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node,
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created telnet server data structure,
 *              NULL if no data structure allocated.
 */
AppDataETelnetServer * //inline//
AppETelnetServerNewETelnetServer(Node *node,
                               TransportToAppOpenResult *openResult)
{
    AppDataETelnetServer *telnetServer;

    telnetServer = (AppDataETelnetServer *)
                    MEM_malloc(sizeof(AppDataETelnetServer));

    /*
     * fill in connection id, etc.
     */
    telnetServer->connectionId = openResult->connectionId;
    telnetServer->localAddr = openResult->localAddr;
    telnetServer->remoteAddr = openResult->remoteAddr;
    telnetServer->sessionStart = node->getNodeTime();
    telnetServer->sessionFinish = 0;
    telnetServer->sessionIsClosed = FALSE;
    telnetServer->numBytesSent = 0;
    telnetServer->numBytesRecvd = 0;
    telnetServer->lastItemSent = 0;
//DERIUS for Stand alone Telnet server
    telnetServer->state = STATE_NORMAL;
    telnetServer->bufPtr = 0;
    
    RANDOM_SetSeed(telnetServer->packetSizeSeed,
                   node->globalSeed,
                   node->nodeId,
                   APP_ETELNET_SERVER,
                   openResult->connectionId); // not invariant

    APP_RegisterNewApp(node, APP_ETELNET_SERVER, telnetServer);

    AppETelnetServerSendWelcomeMsg(node, telnetServer);
    AppETelnetServerShellPrompt(node, telnetServer);

    return telnetServer;
}

/*
 * NAME:        AppETelnetServerSendOpt.
 * PURPOSE:     process the option from client.
 *              transmit the telnet options available on server side to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              option - option from client.
 *              value - value of option. 
 * RETRUN:      void.
 */
static void
AppETelnetServerSendOpt(Node *node, AppDataETelnetServer *serverPtr, unsigned char option, unsigned char value)
{
    char *line;
    line = (char *)MEM_malloc(3);
    if (line != NULL) {
        line[0] = TELNET_IAC;
        line[1] = option;
        line[2] = value;
        if (serverPtr->sessionIsClosed == FALSE)
        {
            Message *tcpmsg = APP_TcpCreateMessage(
                node, serverPtr->connectionId, TRACE_ETELNET);
            APP_AddPayload(node, tcpmsg, line, 3);
            APP_TcpSend(node, tcpmsg);
        }
    }

    MEM_free(line);
}

/*
 * NAME:        AppETelnetServerSendWelcomeMsg.
 * PURPOSE:     send welcome message to client
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETRUN:      void.
 */
void AppETelnetServerSendWelcomeMsg(Node *node, AppDataETelnetServer *serverPtr)
{

    char welcomeMsg[] = "\nWelcome to EXata telnet server\n\n"; 

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node, serverPtr->connectionId, TRACE_ETELNET);
        APP_AddPayload(node, tcpmsg, welcomeMsg, strlen(welcomeMsg));
        APP_TcpSend(node, tcpmsg);
    }
}
 
/*
 * NAME:        AppETelnetServerCommandShellQuit.
 * PURPOSE:     process the command 'QUIT'.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
                str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerCommandShellQuit(Node *node, AppDataETelnetServer *serverPtr, char *str)
{
    serverPtr->state = STATE_CLOSE;
    APP_TcpCloseConnection(
                    node,
                    serverPtr->connectionId);

    serverPtr->sessionFinish = node->getNodeTime();
    serverPtr->sessionIsClosed = TRUE;
}

/*
 * NAME:        AppETelnetServerShellOutput.
 * PURPOSE:     send the output to client
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
                output - bytestream to send to client.
 * RETRUN:      void.
 */
void
AppETelnetServerShellOutput(Node *node, AppDataETelnetServer *serverPtr, char * output)
{
    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node, serverPtr->connectionId, TRACE_ETELNET);
        APP_AddPayload(node, tcpmsg, output, strlen(output));
        APP_TcpSend(node, tcpmsg);
    }
}

/*
 * NAME:        AppETelnetServerShellPrompt.
 * PURPOSE:     send shell prompt to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETRUN:      void.
 */
void
AppETelnetServerShellPrompt(Node *node, AppDataETelnetServer *serverPtr)
{
    char shellPrompt[64];
    const char* version = Product::GetVersionString();
    sprintf(shellPrompt,"EXata v%s>", version);

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node, serverPtr->connectionId, TRACE_ETELNET);
        APP_AddPayload(node, tcpmsg, shellPrompt, strlen(shellPrompt));
        APP_TcpSend(node, tcpmsg);
    }
}

/*
 * NAME:        AppETelnetServerCommandTelnetConn.
 * PURPOSE:     send connection info to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerCommandTelnetConn(Node *node, AppDataETelnetServer *serverPtr, char *str)
{
    char addrStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];

    IO_ConvertIpAddressToString(&serverPtr->localAddr, addrStr);
    sprintf(buf, "Server address = %s\n", addrStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    IO_ConvertIpAddressToString(&serverPtr->remoteAddr, addrStr);
    sprintf(buf, "Client address = %s\n", addrStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

}

/*
 * NAME:        AppETelnetServerCommandTelnetStats.
 * PURPOSE:     send status info to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerCommandTelnetStats(Node *node, AppDataETelnetServer *serverPtr, char *str)
{
    clocktype throughput;
    char startStr[MAX_STRING_LENGTH];
    char finishStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char numBytesSentStr[MAX_STRING_LENGTH];
    char numBytesRecvdStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(serverPtr->sessionStart, startStr);
    TIME_PrintClockInSecond(serverPtr->lastItemSent, finishStr);

    if (serverPtr->connectionId < 0)
    {
        sprintf(statusStr, "Failed");
    }
    else if (serverPtr->sessionIsClosed == FALSE)
    {
        serverPtr->sessionFinish = node->getNodeTime();
        sprintf(statusStr, "Not closed");
    }
    else
    {
        sprintf(statusStr, "Closed");
    }

    if (serverPtr->sessionFinish <= serverPtr->sessionStart)
    {
        throughput = 0;
    }
    else
    {
        throughput =
            (clocktype) ((serverPtr->numBytesRecvd * 8.0 * SECOND)
            / (serverPtr->sessionFinish - serverPtr->sessionStart));
    }
    ctoa(throughput, throughputStr);

    sprintf(buf, "First Packet Sent at (s) = %s\n", startStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    sprintf(buf, "Last Packet Sent at (s) = %s\n", finishStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    sprintf(buf, "Session Status = %s\n", statusStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    ctoa(serverPtr->numBytesSent, numBytesSentStr);
    sprintf(buf, "Total Bytes Sent = %s\n", numBytesSentStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    ctoa(serverPtr->numBytesRecvd, numBytesRecvdStr);
    sprintf(buf, "Total Bytes Received = %s\n", numBytesRecvdStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 

    sprintf(buf, "Throughput (bits/s) = %s\n", throughputStr);
    AppETelnetServerShellOutput(node, serverPtr, buf); 
}

/*
 * NAME:        AppETelnetServerCommandHelp.
 * PURPOSE:     send help info to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerCommandHelp(Node *node, AppDataETelnetServer *serverPtr, char *str)
{
    AppETelnetServerShellOutput(node,
                                serverPtr,
                                (char*)"Available commands:\n");
    AppETelnetServerShellOutput(node,
                                serverPtr,
                                (char*)"stats  - show network statistics\n");
    AppETelnetServerShellOutput(node,
                                serverPtr,
                                (char*)"conn    - show TCP connections\n");
    AppETelnetServerShellOutput(node,
                                serverPtr,
                                (char*)"help, ? - show help\n");
    AppETelnetServerShellOutput(node,
                                serverPtr,
                                (char*)"exit    - exit shell \n");
}

/*
 * NAME:        AppETelnetServerCommandUnknown.
 * PURPOSE:     send "unknown command error" info to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerCommandUnknown(Node *node,
                               AppDataETelnetServer *serverPtr,
                               char *str)
{
    if (strlen(str) > 0) {
        AppETelnetServerShellOutput(node,
                                    serverPtr,
                                    (char*)"unknown command\n");
    }
}


/*
 * NAME:        AppETelnetServerCommandTelnetStats.
 * PURPOSE:     send "unknown command error" info to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              str - empty here.
 * RETRUN:      void.
 */
void
AppETelnetServerShellInput(Node *node, AppDataETelnetServer *serverPtr, char *cmd)
{
    struct ptentry *p;
    for (p = parsetab; p->commandstr != NULL; ++p) {
        if (strncmp(p->commandstr, cmd, strlen(p->commandstr)) == 0) {
            break;
        }
    }

    p->pfunc(node, serverPtr, cmd);

    AppETelnetServerShellPrompt(node, serverPtr);
}

/*
 * NAME:        AppETelnetServerGetChar.
 * PURPOSE:     process the input.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              c - input from client.
 * RETRUN:      void.
 */
static void
AppETelnetServerGetChar(Node *node, AppDataETelnetServer *serverPtr, unsigned char c)
{
    if (c == ISO_cr) {
        return;
    }

    serverPtr->buf[(int)serverPtr->bufPtr] = c;
    if (serverPtr->buf[(int)serverPtr->bufPtr] == ISO_nl ||
        serverPtr->bufPtr == sizeof(serverPtr->buf) - 1) {
        if (serverPtr->bufPtr > 0) {
            serverPtr->buf[(int)serverPtr->bufPtr] = 0;
            /*      petsciiconv_topetscii(s->buf, TELNETD_CONF_LINELEN);*/
            AppETelnetServerShellInput(node, serverPtr, serverPtr->buf);
            serverPtr->bufPtr = 0;
        }
        else
        {
            AppETelnetServerShellPrompt(node, serverPtr);
        }
    } else {
        ++serverPtr->bufPtr;
    }
}

/*
 * NAME:        AppETelnetServerSendResponse.
 * PURPOSE:     process the input.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              data -  input from client.
 *              len -  length of input.
 * RETRUN:      void.
 */
void //inline//
AppETelnetServerSendResponse(Node *node, AppDataETelnetServer *serverPtr, char * data, int len)
{
    unsigned char c;
    char *dataPtr;

    dataPtr = (char *)data;

    while (len > 0) 
    {
        c = *dataPtr;
        ++dataPtr;
        --len;
        switch(serverPtr->state) 
        {
            case STATE_IAC:
                if (c == TELNET_IAC) {
                    //get_char(serverPtr, c);
                    serverPtr->state = STATE_NORMAL;
                } 
                else 
                {
                    switch(c) {
                        case TELNET_WILL:
                            serverPtr->state = STATE_WILL;
                            break;
                        case TELNET_WONT:
                            serverPtr->state = STATE_WONT;
                            break;
                        case TELNET_DO:
                            serverPtr->state = STATE_DO;
                            break;
                        case TELNET_DONT:
                            serverPtr->state = STATE_DONT;
                            break;
                        default:
                            serverPtr->state = STATE_NORMAL;
                            break;
                    }
                }
                break;
            case STATE_WILL:
                /* Reply with a DONT */
                AppETelnetServerSendOpt(node, serverPtr, TELNET_DONT, c);
                serverPtr->state = STATE_NORMAL;
                break;
            case STATE_WONT:
                /* Reply with a DONT */
                AppETelnetServerSendOpt(node, serverPtr, TELNET_DONT, c);
                serverPtr->state = STATE_NORMAL;
                break;
            case STATE_DO:
                /* Reply with a WONT */
                AppETelnetServerSendOpt(node, serverPtr, TELNET_WONT, c);
                serverPtr->state = STATE_NORMAL;
                break;
            case STATE_DONT:
                /* Reply with a WONT */
                AppETelnetServerSendOpt(node, serverPtr, TELNET_WONT, c);
                serverPtr->state = STATE_NORMAL;
                break;
            case STATE_NORMAL:
                if (c == TELNET_IAC) {
                    serverPtr->state = STATE_IAC;
                } else {
                    //user data, so read and process it
                    
                    AppETelnetServerGetChar(node, serverPtr, c);
                }
                break;
        }

    }

}

/*
 * NAME:        AppETelnetServerSendResponse.
 * PURPOSE:     call AppETelnetServerRespPktSize() to get the
 *              response packet size,
                and send the packet.
 * PARAMETERS:  node - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void //inline//
AppETelnetServerSendResponse(Node *node, AppDataETelnetServer *serverPtr)
{
    int pktSize;
    char *payload;

    pktSize = AppETelnetServerRespPktSize(node, serverPtr);

    payload = (char *)MEM_malloc(pktSize);
    memset(payload, 0, pktSize);

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node, serverPtr->connectionId, TRACE_ETELNET);
        APP_AddPayload(node, tcpmsg, payload, pktSize);
        APP_TcpSend(node, tcpmsg);
    }

    MEM_free(payload);
}

/*
 * NAME:        AppETelnetServerRespPktSize.
 * PURPOSE:     call tcplib function telnet_pktsize().
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      telnet control packet size.
 */
int
AppETelnetServerRespPktSize(Node *node, AppDataETelnetServer *serverPtr)
{
    int ctrlPktSize;
    ctrlPktSize = telnet_pktsize(serverPtr->packetSizeSeed);

#ifdef DEBUG
    printf("TELNET control pktsize = %d\n", ctrlPktSize);
#endif /* DEBUG */

    return (ctrlPktSize);
}
#endif
