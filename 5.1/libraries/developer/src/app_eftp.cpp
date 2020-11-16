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
 * function, and finalize function used by the ftp application.
 */
#ifdef EXATA
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include <iostream>
#include <fstream>

#include "api.h"
#include "transport_tcp.h"
#include "tcpapps.h"
#include "app_util.h"
#include "app_eftp.h"

#ifndef _WIN32  // unix/linux
#include <dirent.h>
#include <sys/mman.h>
#include <fcntl.h>
#endif

#ifndef _WIN32 // unix/linux
#include <dirent.h>
#else  // windows
#include <io.h>
#include <fcntl.h>
#endif

using namespace std;

static char userId[MAX_STRING_LENGTH];
static char passWd[MAX_STRING_LENGTH];
static BOOL isFileAccessMode;
static std::string rootFilesystem;

#define MAX_DATA_LENGTH 1000000    

static struct ftp_command_list parsetab[] =
            {{"LIST", AppEFtpServerCommandList},
            {"NLST", AppEFtpServerCommandList},
            {"PASS", AppEFtpServerCommandPass},
            {"USER", AppEFtpServerCommandUser},
            {"QUIT", AppEFtpServerCommandQuit},
            {"ABOR", AppEFtpServerCommandQuit},
            {"SYST", AppEFtpServerCommandSyst},
            {"PORT", AppEFtpServerCommandPort},
            {"PASV", AppEFtpServerCommandPasv},
            {"RETR", AppEFtpServerCommandRetr},
            {"STOR", AppEFtpServerCommandStor},
            {"TYPE", AppEFtpServerCommandType},
            {"AUTH", AppEFtpServerCommandAuth},
            {"EPRT", AppEFtpServerCommandEprt},
            {"EPSV", AppEFtpServerCommandPasv},
            {"PWD", AppEFtpServerCommandPwd},
            {"XPWD", AppEFtpServerCommandPwd},
            {NULL, AppEFtpServerCommandUnknown}};

static struct available_file_list availableFileList[] = 
                                {{"README", 131},
                                {".bash_history", 1234},
                                {".bash_profile", 3423},
                                {"default.config", 8742},
                                {"default.ipne", 16000},
                                {"default.app", 17000},
                                {"big.txt", 228742},
                                {"huge.txt", 1000000},
                                {"huge2.txt", 10000000},
                                {"huge3.txt", 100000000},
                                {NULL, 0} };

typedef struct
{
    char absPath[64];
} parm;

/*
 * Static Functions
 */

/*
 * NAME:        AppEFtpServerGetFtpServer.
 * PURPOSE:     search for a ftp server data structure.
 * PARAMETERS:  appList - link list of applications,
 *              connId - connection ID of the ftp server.
 * RETURN:      the pointer to the ftp server data structure,
 *              NULL if nothing found.
 */
AppDataEFtpServer *
AppEFtpServerGetFtpServer(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataEFtpServer *ftpServer;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_EFTP_SERVER)
        {
            ftpServer = (AppDataEFtpServer *) appList->appDetail;

            if (ftpServer->connectionId == connId)
            {
                return ftpServer;
            }
        }
    }

    return NULL;
}


/*
 * NAME:        AppEFtpServerNewFtpServer.
 * PURPOSE:     create a new ftp server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result of the open request.
 * RETRUN:      the pointer to the created ftp server data structure,
 *              NULL if no data structure allocated.
 */
AppDataEFtpServer *
AppEFtpServerNewFtpServer(Node *node,
                         TransportToAppOpenResult *openResult)
{
    AppDataEFtpServer *ftpServer;

    ftpServer = (AppDataEFtpServer *)
                MEM_malloc(sizeof(AppDataEFtpServer));

    /*
     * fill in connection id, etc.
     */
    ftpServer->connectionId = openResult->connectionId;
    ftpServer->localAddr = openResult->localAddr;
    ftpServer->remoteAddr = openResult->remoteAddr;
    ftpServer->sessionStart = node->getNodeTime();
    ftpServer->sessionFinish = node->getNodeTime();
    ftpServer->lastTime = 0;
    ftpServer->sessionIsClosed = FALSE;
    ftpServer->numBytesSent = 0;
    ftpServer->numBytesRecvd = 0;
    ftpServer->bytesRecvdDuringThePeriod = 0;
    ftpServer->lastItemSent = 0;

    RANDOM_SetSeed(ftpServer->seed,
                   node->globalSeed,
                   node->nodeId,
                   APP_EFTP_SERVER,
                   ftpServer->connectionId);

    APP_RegisterNewApp(node, APP_EFTP_SERVER, ftpServer);

    #ifdef DEBUG_OUTPUT_FILE
    {
        char fileName[MAX_STRING_LENGTH];
        FILE *fp;
        char dataBuf[MAX_STRING_LENGTH];

        sprintf(fileName, "FTP_Throughput_%d", node->nodeId);

        /*
         * Open a data file to accumulate different statistics
         * informations of this node.
         */
        fp = fopen(fileName, "w");
        if (fp)
        {
            sprintf(dataBuf, "%s\n", "Simclock   Throughput(in Kbps) ");
            fwrite(dataBuf, strlen(dataBuf), 1, fp);
            fclose(fp);
        }
    }
    #endif

    AppEFtpServerWelcomeMessage(node, ftpServer);
    ftpServer->isLoggedIn = FALSE;

    return ftpServer;
}

/*
 * NAME:        AppEFtpServerSendCtrlPkt.
 * PURPOSE:     call AppEFtpCtrlPktSize() to get the response packet
 *              size, and send the packet.
 * PARAMETERS:  node - pointer to the node,
 *              serverPtr - pointer to the server data structure.
 * RETRUN:      none.
 */
void
AppEFtpServerSendCtrlPkt(Node *node, AppDataEFtpServer *serverPtr)
{
    int pktSize;
    char *payload;

    pktSize = AppEFtpServerCtrlPktSize(serverPtr);

    if (pktSize > APP_MAX_DATA_SIZE)
    {
        /*
         * Control packet size is larger than APP_MAX_DATA_SIZE,
         * set it to APP_MAX_DATA_SIZE. This should be rare.
         */
        pktSize = APP_MAX_DATA_SIZE;
    }
    payload = (char *)MEM_malloc(pktSize);
    memset(payload,'d',pktSize);
    if (!serverPtr->sessionIsClosed)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node,
            serverPtr->connectionId,
            TRACE_EFTP);

        APP_AddPayload(node, tcpmsg, payload, pktSize);

        APP_TcpSend(node, tcpmsg);
    }
     MEM_free(payload);
}

/*
 * NAME:        AppEFtpServerCtrlPktSize.
 * PURPOSE:     call tcplib function ftp_ctlsize().
 * PARAMETERS:  node - pointer to the node.
 * RETRUN:      ftp control packet size.
 */
int
AppEFtpServerCtrlPktSize(AppDataEFtpServer *serverPtr)
{
    int ctrlPktSize;
    ctrlPktSize = ftp_ctlsize(serverPtr->seed);

#ifdef DEBUG
    printf("FTP: Node ftp control pktsize = %d\n",
           ctrlPktSize);
#endif /* DEBUG */

    return (ctrlPktSize);
}

/*
 * Public Functions
 */

void AppEFtpServerSendCtrlForSA(Node *node, AppDataEFtpServer *serverPtr)
{

    char welcomeMsg[33] = "\nWelcome to EXata FTP server\n\n";

    if (serverPtr->sessionIsClosed == FALSE)
    {
        //printf("SEND!!!\n");
        Message *tcpmsg = APP_TcpCreateMessage(
            node,
            serverPtr->connectionId,
            TRACE_EFTP);

        APP_AddPayload(node, tcpmsg, welcomeMsg, 33);

        APP_TcpSend(node, tcpmsg);
    }
    //else
    //    printf("closed\n");

}

/*
 * NAME:        AppLayerFtpServer.
 * PURPOSE:     Models the behaviour of Ftp Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerEFtpServer(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataEFtpServer *serverPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_FromTransListenResult:
        {
            TransportToAppListenResult *listenResult;

            listenResult = (TransportToAppListenResult *)
                           MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s got listenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            if (listenResult->connectionId == -1)
            {
                node->appData.numAppTcpFailure++;
            }

            break;
        }

        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;
            openResult = (TransportToAppOpenResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s got OpenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_PASSIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure++;
            }
            else
            {
                AppDataEFtpServer *serverPtr;
                serverPtr = AppEFtpServerNewFtpServer(node, openResult);
                assert(serverPtr != NULL);
            }

            break;
        }

        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server Node %ld at %s sent data %ld\n",
                   node->nodeId, buf, dataSent->length);
#endif /* DEBUG */

            serverPtr = AppEFtpServerGetFtpServer(node,
                                     dataSent->connectionId);

            assert(serverPtr != NULL);

            serverPtr->numBytesSent += (clocktype) dataSent->length;
            serverPtr->lastItemSent = node->getNodeTime();

            break;
        }

        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived *dataRecvd;
            char *packet;

            dataRecvd = (TransportToAppDataReceived *)
                            MESSAGE_ReturnInfo(msg);

            packet = MESSAGE_ReturnPacket(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s received data size %d\n",
                   node->nodeId, buf, MESSAGE_ReturnPacketSize(msg));
#endif /* DEBUG */

            serverPtr = AppEFtpServerGetFtpServer(node,
                                                 dataRecvd->connectionId);

            //assert(serverPtr != NULL);
            if (serverPtr == NULL)
            {
                // server pointer can be NULL due to the real-world apps
                break;
                    
            }
            assert(serverPtr->sessionIsClosed == FALSE);

            serverPtr->numBytesRecvd +=
                    (clocktype) MESSAGE_ReturnPacketSize(msg);

            AppEFtpServerCommandParse(node, serverPtr, msg->packet, msg->packetSize);

            break;
        }

        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP Server: Node %ld at %s got close result\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            serverPtr = AppEFtpServerGetFtpServer(node,
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
            printf("FTP Server: Node %u at time %s received "
                   "message of unknown type"
                   " %d.\n", node->nodeId, buf, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        AppEFtpServerInit.
 * PURPOSE:     listen on Ftp server port.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppEFtpServerInit(
    Node *node, 
    Address serverAddr,
    BOOL fileAccess,
    const char* root)
{
    if (serverAddr.networkType != NETWORK_IPV4
        && serverAddr.networkType != NETWORK_IPV6)
    {
        return;
    }

    /* The following two are static global variables */
    isFileAccessMode = fileAccess; 
    rootFilesystem = root;

    APP_TcpServerListen(
        node,
        APP_EFTP_SERVER,
        serverAddr,
        (short) APP_EFTP_SERVER);
}

/*
 * NAME:        AppEFtpServerPrintStats.
 * PURPOSE:     Prints statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppEFtpServerPrintStats(Node *node, AppDataEFtpServer *serverPtr)
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
    sprintf(buf, "Client Address = %s", addrStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "First Packet Sent at (s) = %s", startStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Last Packet Sent at (s) = %s", finishStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesSent, numBytesSentStr);
    sprintf(buf, "Total Bytes Sent = %s", numBytesSentStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    ctoa(serverPtr->numBytesRecvd, numBytesRecvdStr);
    sprintf(buf, "Total Bytes Received = %s", numBytesRecvdStr);

    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);

    sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
    IO_PrintStat(
        node,
        "Application",
        "Emulated FTP Server",
        ANY_DEST,
        serverPtr->connectionId,
        buf);
}

/*
 * NAME:        AppEFtpServerFinalize.
 * PURPOSE:     Collect statistics of a Ftp session.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppEFtpServerFinalize(Node *node, AppInfo* appInfo)
{
    AppDataEFtpServer *serverPtr = (AppDataEFtpServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        AppEFtpServerPrintStats(node, serverPtr);
    }
}

/*
 * NAME:        AppEFtpServerMessageToClient.
 * PURPOSE:     send the bytestream to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              output - bytestream to client.
 *              outputLen - length of output.
 * RETURN:      none.
 */
void
AppEFtpServerMessageToClient(Node *node, AppDataEFtpServer *serverPtr, char * output, int outputLen)
{
    
    //int outputLen;
    
//    outputLen = strlen(output);
    output[outputLen-2] = 0x0d;
    output[outputLen-1] = 0x0a;

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node,
            serverPtr->connectionId,
            TRACE_EFTP);

        APP_AddPayload(node, tcpmsg, output, outputLen);

        APP_TcpSend(node, tcpmsg);
    }
}

/*
 * NAME:        AppEFtpServerMessageToClient.
 * PURPOSE:     send the bytestream to client.
 * PARAMETERS:  node - pointer to the node.
 *              serverPtr - pointer to the ftp server data structure.
 *              output - bytestream to client.
 *              outputLen - length of output.
 *              flag - flag. If 0, it's not continuous, so add carege return and line feed.
 * RETURN:      none.
 */
void
AppEFtpServerMessageToClient(Node *node, AppDataEFtpClient *serverPtr, char * output, int outputLen, int flag)
{

//    int outputLen;

 //   outputLen = strlen(output);
    if (flag == 0) //not continuous         
    {
        output[outputLen-2] = 0x0d;
        output[outputLen-1] = 0x0a;
    }

    if (serverPtr->sessionIsClosed == FALSE)
    {
        Message *tcpmsg = APP_TcpCreateMessage(
            node,
            serverPtr->connectionId,
            TRACE_EFTP);

        APP_AddPayload(node, tcpmsg, output, outputLen);

        APP_TcpSend(node, tcpmsg);

    }

}

/*
 * NAME:        AppEFtpServerWelcomeMessage.
 * PURPOSE:     send the welcome message to client.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppEFtpServerWelcomeMessage(Node *node, AppDataEFtpServer *ftpServer)
{
    char welcomeMsg[MAX_STRING_LENGTH];
    
    sprintf(welcomeMsg, "220-Welcome to the EXata FTP server\r\n220 Login with user:anonymous pass:(blank) or user:(blank) pass:(blank)");

    AppEFtpServerMessageToClient(node, ftpServer, welcomeMsg, strlen(welcomeMsg)+2);
}

/*
 * NAME:        AppEFtpServerCommandParse.
 * PURPOSE:     parse the command from client.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client.
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandParse(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{

    struct ftp_command_list *p;
    for (p = parsetab; p->commandstr != NULL; ++p) {
        if (strcmp(p->commandstr, "PWD") == 0) {
            break;
        }
        if (strncmp(p->commandstr, cmd, 4) == 0) {
            break;
        }
    }

    p->pfunc(node, ftpServer, cmd, len);

}

/*
 * NAME:        AppEFtpServerCommandList.
 * PURPOSE:     response to the command "LIST".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "LIST".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandList(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[54] = "150 Opening ASCII mode data connection for /bin/ls.";
    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 54);

    AppEFtpServerOpenDataPort(node, ftpServer, cmd, len);
    
    sprintf(respMsg , "226 Transfer complete.");
    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 24);
}

/*
 * NAME:        AppEFtpServerNotLoggedInMessage.
 * PURPOSE:     not logged error.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 * RETURN:      none.
 */
void
AppEFtpServerNotLoggedInMessage(Node *node, AppDataEFtpServer *ftpServer)
{
    char respMsg[20] = "530 Not Logged In.";
    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 20);
}

/*
 * NAME:        AppEFtpServerCommandPass.
 * PURPOSE:     response to the command "PASS".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "PASS".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandPass(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    memcpy(passWd, cmd+5, len-7);
    passWd[len-7] = '\0';

    if (AppEFtpServerIsValidUser())
    {
        char respMsg[30] = "230 user logged in. proceed.";
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 30);
        ftpServer->isLoggedIn = TRUE;
 
    }
    else // not valid user
    {
        AppEFtpServerNotLoggedInMessage(node, ftpServer);
    }
}

/*
 * NAME:        AppEFtpServerCommandUser.
 * PURPOSE:     response to the command "USER".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "USER".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandUser(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[34] = "331 user name okay. need passwd.";

    memcpy(userId, cmd+5, len-7);
    userId[len-7] = '\0';
    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 34);
}

/*
 * NAME:        AppEFtpServerCommandQuit.
 * PURPOSE:     response to the command "QUIT".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "QUIT".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandQuit(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{

    APP_TcpCloseConnection(
                    node,
                    ftpServer->connectionId);

    ftpServer->sessionFinish = node->getNodeTime();
    ftpServer->sessionIsClosed = TRUE;

}

/*
 * NAME:        AppEFtpServerCommandSyst.
 * PURPOSE:     response to the command "SYST".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "SYST".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandSyst(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[19] = "215 UNIX type L8.";

    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 19);

}

void AppEFtpServerCommandEprt(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char str[42];
    memcpy(str,cmd, len);
    str[41] = '\0';
    printf("\ncmd:%s",str);
    char respMsg[30] = "200 EPRT command successful.";

    if (ftpServer->isLoggedIn == TRUE)
    {
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 30);

        // save tcp port information from EPRT command
        AppEFtpServerSaveIpv6PortInfo(ftpServer, cmd);
    }
    else
    {
        AppEFtpServerNotLoggedInMessage(node, ftpServer);
    }
}

/*
 * NAME:        AppEFtpServerCommandPort.
 * PURPOSE:     response to the command "PORT".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "PORT".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandPort(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[30] = "200 PORT command successful.";

    if (ftpServer->isLoggedIn == TRUE)
    {
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 30);
        //save IP and port information
        AppEFtpServerSaveIpPortInfo(ftpServer, cmd);  
    } 
    else
    {
        AppEFtpServerNotLoggedInMessage(node, ftpServer);
    }
}

#ifdef DERIUS
/*
 * NAME:        AppEFtpServerConvertIpAddressToDashString.
 * PURPOSE:     response to the command "PORT".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "PORT".
 *              len - length of command.
 * RETURN:      none.
 */
void //inline//
AppEFtpServerConvertIpAddressToDashString(
    NodeAddress ipAddress,
    char *addressString)
{
    sprintf(addressString, "%u,%u,%u,%u",
            (ipAddress & 0xff000000) >> 24,
            (ipAddress & 0xff0000) >> 16,
            (ipAddress & 0xff00) >> 8,
            ipAddress & 0xff);
}
#endif

/*
 * NAME:        AppEFtpServerCommandPasv.
 * PURPOSE:     response to the command "PASV".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "PASV".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandPasv(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    AppEFtpServerCommandUnknown(node, ftpServer, const_cast<char*>("PASV"));
}

/*
 * NAME:        AppEFtpServerCommandAuth.
 * PURPOSE:     response to the command "AUTH".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "AUTH".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandAuth(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    AppEFtpServerCommandUnknown(node, ftpServer, const_cast<char*>("AUTH"));
}

/*
 * NAME:        AppEFtpServerCommandPwd.
 * PURPOSE:     response to the command "PWD" and "XPWD.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "PWD" or "XPWD".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandPwd(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[34] = "257 \"/\" is the current directory";

    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 34);
}

/*
 * NAME:        AppEFtpServerGetExponent.
 * PURPOSE:     calculate decimal of 10 by index.
 * PARAMETERS:  index - number of digits.
 * RETURN:      int.
 */
int AppEFtpServerGetExponent(int index)
{
    int i;
    int retVal=1;

    if (index == 0)
        return 1;
    for (i=0; i<index; i++)
        retVal  *=10;

    return retVal;
}

/*
 * NAME:        AppEFtpServerSizeForNum.
 * PURPOSE:     calculate file size.
 * PARAMETERS:  fileSize.
 * RETURN:      int.
 */
int AppEFtpServerSizeForNum(int fileSize)
{
    int i;

    for (i=0; i<100; i++)
    {
        if ((fileSize >= AppEFtpServerGetExponent(i)) && (fileSize < AppEFtpServerGetExponent(i+1)))
        {
            return i+1;
        }
    }
    return 0;
}

/*
 * NAME:        AppEFtpServerCommandRetr.
 * PURPOSE:     response to the command "RETR".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "RETR".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandRetr(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    //char respMsg[MAX_STRING_LENGTH];
    char respMsg[1024];
    char cmdStr[5];
    char fileName[MAX_STRING_LENGTH];
    long fileSize;
    int extraSize;

    sscanf(cmd, "%s %s", cmdStr, fileName);

    extraSize = strlen(fileName);
    fileSize = AppEFtpServerAvailableFile(node, fileName);
    if (fileSize)
    {
        sprintf(respMsg,"150 Opening ASCII mode data connection for %s (%ld bytes).", fileName, fileSize);
        extraSize+= AppEFtpServerSizeForNum(fileSize);
        //AppEFtpServerMessageToClient(node, ftpServer, respMsg, 55+extraSize);
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, strlen(respMsg)+2);
        AppEFtpServerOpenDataPort(node, ftpServer, cmd, len);
        sprintf(respMsg , "226 Transfer complete.");
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 24);
    }
    else //file not available
    {
        sprintf(respMsg , "550 %s No such file or directory.", fileName);
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 33+extraSize);
    }
}

/*
 * NAME:        AppEFtpServerCommandStor.
 * PURPOSE:     response to the command "STOR".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "STOR".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandStor(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    int extraSize;
    char *respMsg;
    char storeCmd[5];
    char storeFile[MAX_STRING_LENGTH];

    sscanf(cmd, "%s %s", storeCmd, storeFile);

    extraSize = strlen(storeFile);

    respMsg = (char *)malloc(27+extraSize);
    sprintf(respMsg, "550 %s: cannot create file.", storeFile);

    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 27+extraSize);

    MEM_free(respMsg);
}

/*
 * NAME:        AppEFtpServerCommandType.
 * PURPOSE:     response to the command "TYPE".
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client, "TYPE".
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandType(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char typeCmd[5];
    char typeType[2];
    char respMsg[21];

    sscanf(cmd, "%s %s", typeCmd, typeType);
    sprintf(respMsg, "200 Type set to  %s.", typeType);
    AppEFtpServerMessageToClient(node, ftpServer, respMsg, 21);
}

/*
 * NAME:        AppEFtpServerCommandUnknown.
 * PURPOSE:     Unknown command from client.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client. unknown.
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerCommandUnknown(Node *node, AppDataEFtpServer *ftpServer, char *cmd, int len)
{
    char respMsg[MAX_STRING_LENGTH];
    char respTemp[MAX_STRING_LENGTH];
    
    if (len <3)
    {
        sprintf(respMsg, "500 \'%s\': command not understood.\n", cmd);
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 37);
    }
    else
    {
        memcpy(respTemp, cmd, len-2);
        respTemp[len-2]='\0';
        sprintf(respMsg, "500 \'%s\': command not understood.\n", respTemp);
        AppEFtpServerMessageToClient(node, ftpServer, respMsg, 33+len-2);
    }
}

/*
 * NAME:        AppEFtpServerIsValidUser.
 * PURPOSE:     check ip and password.
 * PARAMETERS:  
 * RETURN:      BOOL.
 */
BOOL
AppEFtpServerIsValidUser(void)
{

    if ((!memcmp(passWd, "exata", 5)) && (!memcmp(userId, "exata", 5)) )
    {
        return TRUE;
    }
    else if (!strcmp(passWd,"") && !strcmp(userId, ""))
    {
        return TRUE;
    }
    else if (!strcmp(passWd, "") && !strcmp(userId, "anonymous"))
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

void AppEFtpServerSaveIpv6PortInfo(AppDataEFtpServer *ftpServer, char *cmd)
{
    char eprtCmd[5];
    char ipv6EprtStr[MAX_STRING_LENGTH];
    char* ipv6Address = NULL;
    char* cmdPtr = NULL;
    UInt32 afNumber = 0;
    UInt32 tcpPort = 0;
    const char* dilim = "|";
    char token[MAX_STRING_LENGTH];
    char* next = NULL;

    sscanf(cmd, "%s %s", eprtCmd, ipv6EprtStr);

    cmdPtr = IO_GetDelimitedToken(token, ipv6EprtStr, dilim, &next);
    afNumber = atoi(cmdPtr);
    cmdPtr = IO_GetDelimitedToken(token, next, dilim, &next);
    ipv6Address = cmdPtr;
    cmdPtr = IO_GetDelimitedToken(token, next, dilim, &next);
    tcpPort = atoi(cmdPtr);

    ftpServer->portForDataConn = tcpPort;
}

/*
 * NAME:        AppEFtpServerSaveIpPortInfo.
 * PURPOSE:     Keep ip and port info for data connection.
 * PARAMETERS:  ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client.
 * RETURN:      none.
 */
void
AppEFtpServerSaveIpPortInfo(AppDataEFtpServer *ftpServer, char *cmd) 
{

    char portCmd[5];
    char ipPortStr[MAX_STRING_LENGTH];
    char *ipPtr;
    int ftpClientPort[2]; 
    int ftpClientIp[4];
    int i;
    const char *dilim = ",";
    char token[MAX_STRING_LENGTH];
    char * next;

    sscanf(cmd, "%s %s", portCmd, ipPortStr);

    ipPtr = IO_GetDelimitedToken(token, ipPortStr, dilim, &next);
    ftpClientIp[0] = atoi(ipPtr);
    for (i=1; i<4; i++)
    {
    ipPtr = IO_GetDelimitedToken(token, next, dilim, &next);
        ftpClientIp[i] = atoi(ipPtr);
    }

    ipPtr = IO_GetDelimitedToken(token, next, dilim, &next);
    ftpClientPort[0] = atoi(ipPtr);
    ipPtr = IO_GetDelimitedToken(token, next, dilim, &next);
    ftpClientPort[1] = atoi(ipPtr);

    ftpServer->portForDataConn = ftpClientPort[0]*256 + ftpClientPort[1];
    
}

/*
 * NAME:        AppEFtpServerOpenDataPort.
 * PURPOSE:     open data connection with client.
 * PARAMETERS:  node - pointer to the node.
 *              ftpServer - pointer to the ftp server data structure.
 *              cmd - command from client.
 *              len - length of command.
 * RETURN:      none.
 */
void
AppEFtpServerOpenDataPort(Node *node, AppDataEFtpServer *ftpServer, char * cmd, int len)
{
    AppDataEFtpClient *clientPtr;

    /* Check to make sure the number of ftp items is a correct value. */

    char startTimeStr[MAX_STRING_LENGTH];

    sprintf(startTimeStr, "0");
    
    clocktype waitTime = TIME_ConvertToClock(startTimeStr);

    clientPtr = AppEFtpServerDataPortConnect(node,
                                         ftpServer->localAddr,
                                         ftpServer->remoteAddr);
    memcpy(clientPtr->cmd, cmd, len);

    if (clientPtr == NULL)
    {
        printf("FTP Client: Node %d cannot allocate "
               "new ftp client\n", node->nodeId);

        assert(FALSE);
    }

    APP_TcpOpenConnection(
        node,
        APP_EFTP_SERVER_DATA,
        ftpServer->localAddr,
        APP_EFTP_SERVER_DATA,
        ftpServer->remoteAddr,
        (short) ftpServer->portForDataConn,
        clientPtr->uniqueId,
        waitTime,
        APP_DEFAULT_TOS);


}

/*
 * NAME:        AppEFtpServerDataPortConnect.
 * PURPOSE:     open data connection with client.
 * PARAMETERS:  node - pointer to the node.
 *              localAddr - local IP.
 *              remoteAddr - remote IP.
 * RETURN:      *AppDataEFtpClient.
 */
AppDataEFtpClient *
AppEFtpServerDataPortConnect(Node *node,
                         Address localAddr,
                         Address remoteAddr)
{

    AppDataEFtpClient *ftpClient;

    ftpClient = new AppDataEFtpClient;

    /*
     * fill in connection id, etc.
     */
    ftpClient->connectionId = -1;
    ftpClient->uniqueId = node->appData.uniqueId++;

    ftpClient->localAddr = localAddr;
    ftpClient->remoteAddr = remoteAddr;

    // Make unique seed.
    RANDOM_SetSeed(ftpClient->seed,
                   node->globalSeed,
                   node->nodeId,
                   APP_EFTP_SERVER_DATA,
                   ftpClient->uniqueId);

    ftpClient->itemSize = 0;
    ftpClient->sendPtr = 0;
    ftpClient->numBytesSent = 0;
    ftpClient->numBytesRecvd = 0;
    ftpClient->lastItemSent = 0;
    APP_RegisterNewApp(node, APP_EFTP_SERVER_DATA, ftpClient);

    return ftpClient;
}

/*
 * NAME:        AppLayerFtpServerData.
 * PURPOSE:     Models the behaviour of Ftp Data client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */

void
AppLayerEFtpServerData(Node *node, Message *msg)
{
    char buf[MAX_STRING_LENGTH];
    AppDataEFtpClient *serverDataPtr;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {

        case MSG_APP_FromTransOpenResult:
        {
            TransportToAppOpenResult *openResult;
            openResult = (TransportToAppOpenResult *)MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP DATA port: Node %ld at %s got OpenResult\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            assert(openResult->type == TCP_CONN_ACTIVE_OPEN);

            if (openResult->connectionId < 0)
            {
                node->appData.numAppTcpFailure++;
            }
            else
            {
                serverDataPtr = AppEFtpServerDataUpdateFtp(node, openResult);

                assert(serverDataPtr != NULL);

                AppEFtpServerDataExecuteCommand(node, serverDataPtr);

            }

            break;
        }
        case MSG_APP_FromTransDataSent:
        {
            TransportToAppDataSent *dataSent;

            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP DATA Port %ld at %s sent data %ld\n",
                   node->nodeId, buf, dataSent->length);
#endif /* DEBUG */

            serverDataPtr = AppEFtpServerDataGetFtp(node,
                                     dataSent->connectionId);

            assert(serverDataPtr != NULL);

            serverDataPtr->numBytesSent += (clocktype) dataSent->length;
            serverDataPtr->lastItemSent = node->getNodeTime();

            if (serverDataPtr->sendPtr < serverDataPtr->itemSize)
            {
                AppEFtpServerSendFile(node, serverDataPtr);
            }
            else
            {
                APP_TcpCloseConnection(
                    node,
                    serverDataPtr->connectionId);
            }

            break;
        }
        case MSG_APP_FromTransDataReceived:
        {
            TransportToAppDataReceived *dataRecvd;
            char *packet;

            dataRecvd = (TransportToAppDataReceived *)
                            MESSAGE_ReturnInfo(msg);

            packet = MESSAGE_ReturnPacket(msg);

#ifdef DEBUG
            printf("FTP DATA port: Node %ld at %s received data size %d\n",
                   node->nodeId, buf, MESSAGE_ReturnPacketSize(msg));
#endif /* DEBUG */

            serverDataPtr = AppEFtpServerDataGetFtp(node,
                                                 dataRecvd->connectionId);

            assert(serverDataPtr != NULL);
            assert(serverDataPtr->sessionIsClosed == FALSE);

            serverDataPtr->numBytesRecvd +=
                    (clocktype) MESSAGE_ReturnPacketSize(msg);
            /* Instant throughput is measured here after each 1 second */

            break;
        }
        case MSG_APP_FromTransCloseResult:
        {
            TransportToAppCloseResult *closeResult;

            closeResult = (TransportToAppCloseResult *)
                          MESSAGE_ReturnInfo(msg);

#ifdef DEBUG
            printf("FTP DATA port: Node %ld at %s got close result\n",
                   node->nodeId, buf);
#endif /* DEBUG */

            serverDataPtr = AppEFtpServerDataGetFtp(node,
                                                 closeResult->connectionId);
            //assert(serverDataPtr != NULL);
            if (serverDataPtr == NULL)
            {
                break;
            }

            if (serverDataPtr->sessionIsClosed == FALSE)
            {
                serverDataPtr->sessionIsClosed = TRUE;
                serverDataPtr->sessionFinish = node->getNodeTime();
            }

            break;
        }

        default:
            ctoa(node->getNodeTime(), buf);
            printf("FTP Server DATA: Node %u at time %s received "
                   "message of unknown type"
                   " %d.\n", node->nodeId, buf, msg->eventType);
#ifndef EXATA
            assert(FALSE);
#endif
    }

    MESSAGE_Free(node, msg);
 
}

#ifndef _WIN32  // linux/unix
void AppEFtpServerDataSetMode(struct stat fileStat, char * temp)
{

    strcat(temp, "-"); //always regular file

    if ((S_IRUSR & fileStat.st_mode) == S_IRUSR)
        strcat(temp, "r");
    else
        strcat(temp, "-");
    if ((S_IWUSR & fileStat.st_mode) == S_IWUSR)
        strcat(temp, "w");
    else
        strcat(temp, "-");
    if ((S_IXUSR & fileStat.st_mode) == S_IXUSR)
        strcat(temp, "x");
    else
        strcat(temp, "-");

    if ((S_IRGRP & fileStat.st_mode) == S_IRGRP)
        strcat(temp, "r");
    else
        strcat(temp, "-");
    if ((S_IWGRP & fileStat.st_mode) == S_IWGRP)
        strcat(temp, "w");
    else
        strcat(temp, "-");
    if ((S_IXGRP & fileStat.st_mode) == S_IXGRP)
        strcat(temp, "x");
    else
        strcat(temp, "-");

    if ((S_IROTH & fileStat.st_mode) == S_IROTH)
        strcat(temp, "r");
    else
        strcat(temp, "-");
    if ((S_IWOTH & fileStat.st_mode) == S_IWOTH)
        strcat(temp, "w");
    else
        strcat(temp, "-");
    if ((S_IXOTH & fileStat.st_mode) == S_IXOTH)
        strcat(temp, "x");
    else
        strcat(temp, "-");

}
#else //windows, always -rw-rw-rw-
void AppEFtpServerDataSetMode(char * temp)
{
    strcat(temp, "-"); //always regular file

    strcat(temp, "r");
    strcat(temp, "w");
    strcat(temp, "-");

    strcat(temp, "r");
    strcat(temp, "w");
    strcat(temp, "-");

    strcat(temp, "r");
    strcat(temp, "w");
    strcat(temp, "-");
}
#endif

#ifndef _WIN32  //linux/unix
void AppEFtpServerDataPrtFileInfo(Node *node,  AppDataEFtpClient *clientPtr, char * fileName, char * returnStr)
{
    struct tm *tmModified;

    std::string absPath;
    char buff[BUFSIZ];
    char temp[11];

    absPath = rootFilesystem + "/" + fileName;

    struct stat fileStat;
    if (stat(absPath.c_str(), &fileStat) == 0)
    {
        if (S_ISREG(fileStat.st_mode)) //regular files only
        {
            memset(temp, 0, 11);
            AppEFtpServerDataSetMode(fileStat, temp);
            tmModified = localtime(&(fileStat.st_mtime));
            strftime(buff, sizeof(buff), "%b %d %H:%M", tmModified);

            sprintf(returnStr, "%s   %ld qualnet qualnet %7d %s %s",
                    temp,
                    (long)fileStat.st_nlink,
                    (Int32)fileStat.st_size,
                    buff,
                    fileName);

            AppEFtpServerMessageToClient(node,
                                        clientPtr,
                                        returnStr,
                                        strlen(returnStr) + 2,
                                        0);

        }
    }
    else
    {
        printf("FTP server - stat error\n");
    }

}
#endif

void AppEFtpServerSendFile(Node *node, AppDataEFtpClient *clientPtr)
{
    char *payload;

    ifstream readFile;                                                                 
    readFile.open(clientPtr->fileToSend.c_str(), ios::in|ios::binary);                                       
    if ((clientPtr->itemSize - clientPtr->sendPtr) > APP_MAX_DATA_SIZE)
    {
        payload = (char *)MEM_malloc(APP_MAX_DATA_SIZE);
        readFile.seekg(clientPtr->sendPtr);
        if (!readFile.read(payload, APP_MAX_DATA_SIZE))
        { 
            printf("readFile.read error\n");
            readFile.clear(); //reading error
        }
        else
        {
            AppEFtpServerMessageToClient(node, clientPtr, payload, APP_MAX_DATA_SIZE, 1);
        }
        clientPtr->sendPtr += APP_MAX_DATA_SIZE;
    }
    else
    {
        Int64 restToSend;
        restToSend = clientPtr->itemSize - clientPtr->sendPtr;
        payload = (char *)MEM_malloc(restToSend);
        readFile.seekg(clientPtr->sendPtr);
        if (!readFile.read(payload, restToSend))
        { 
            readFile.clear(); //reading error
            printf("File Reading error\n");
        }
        else
        {
            AppEFtpServerMessageToClient(node, clientPtr, payload, restToSend, 1);
        }

        clientPtr->sendPtr += restToSend;

    }
    

}

/*
 * NAME:        AppEFtpServerDataExecuteCommand.
 * PURPOSE:     excute the command from client and respond back to client.
 * PARAMETERS:  node - pointer to the node.
 *              clientPtr - pointer to the ftp data client data structure.
 * RETURN:      none.
 */
void AppEFtpServerDataExecuteCommand(Node *node, AppDataEFtpClient *clientPtr)
{

    char payload[MAX_STRING_LENGTH];
    char cmdStr[5];
    char fileName[MAX_STRING_LENGTH];
    char *dataLoad;
    int i;
    int extraSize;

    if (( !memcmp(clientPtr->cmd, "LIST", 4)) || ( !memcmp(clientPtr->cmd, "NLST", 4)) )
    {
        if (isFileAccessMode) //if File Access is enabled
        {

#ifndef _WIN32  // linux/linux
        struct dirent **namelist;
        int n,i;
        n = scandir(rootFilesystem.c_str(), &namelist, 0, alphasort);
        if (n < 0)
            perror("scandir");
        else {
            while (n--)
            {
                AppEFtpServerDataPrtFileInfo(node, clientPtr, namelist[n]->d_name, payload);

                free(namelist[n]);
            }
            free(namelist);
            //free(lower);
        }
#else // windows
        struct _finddata_t    c_file;
        long hFile;
        std::string buf;
        char buff[MAX_STRING_LENGTH];
        char returnStr[MAX_STRING_LENGTH];
        char temp[11];
        
        struct tm *tmModified;

#ifdef DEBUG
        printf("node->ftpBaseDir=%s\n", rootFilesystem.c_str());
#endif

        buf = rootFilesystem + "/*.*";
        if ((hFile = _findfirst(buf.c_str(), &c_file)) == -1L)
        {
            printf("No files in current directory\n");
        }
        else
        {
            while (_findnext(hFile, &c_file)==0)    
            {
                if (c_file.attrib & _A_ARCH)
                {
                    memset(temp, NULL, 11);
                    AppEFtpServerDataSetMode(temp);
                    tmModified = localtime(&(c_file.time_write));
                    strftime(buff, sizeof buff, "%b %d %H:%M", tmModified);
                    sprintf(returnStr, "%s   1 qualnet qualnet %7d %s %s", temp, c_file.size, buff, c_file.name);
                    AppEFtpServerMessageToClient(node, clientPtr, returnStr, strlen(returnStr)+2, 0);
                }
            }
        }    

#endif //windows
        }
        else //memory access on the fly
        {
            for (i=0; availableFileList[i].fileSize>0; i++)
            {
                sprintf(payload, "-rw-r--r--   1 root root  %d May 22 13:41 %s", 
                    availableFileList[i].fileSize, availableFileList[i].fileName);
                extraSize = strlen(availableFileList[i].fileName);
                extraSize += AppEFtpServerSizeForNum(availableFileList[i].fileSize);
                AppEFtpServerMessageToClient(node, clientPtr, payload, 42+extraSize, 0);
            }
        }

        APP_TcpCloseConnection(
                    node,
                    clientPtr->connectionId);
    }        
    else
    if (!memcmp(clientPtr->cmd, "RETR", 4))
    {
        sscanf(clientPtr->cmd, "%s %s", cmdStr, fileName);

        if (isFileAccessMode) //if File Access is enabled
        {
            clientPtr->fileToSend = rootFilesystem + "/" + fileName;
#ifndef _WIN32  // linux/unix
            struct stat fileStat;

            if (stat(clientPtr->fileToSend.c_str(), &fileStat) == 0)
            {
                //set the item size
                clientPtr->sendPtr = 0;
                clientPtr->itemSize = fileStat.st_size; 
                AppEFtpServerSendFile(node, clientPtr);
            }
        }
#else //windows
            long hFile;
            struct _finddata_t c_file;
            hFile = _findfirst(clientPtr->fileToSend.c_str(), &c_file);
            if (hFile != -1L)
            {
                clientPtr->sendPtr = 0;
                clientPtr->itemSize = c_file.size; 
                AppEFtpServerSendFile(node, clientPtr);
            }

        }
#endif 
        else //from memory 
        {
            for (i=0; availableFileList[i].fileSize>0; i++)
            {
                if (!(strcmp(fileName, availableFileList[i].fileName)))
                {
                    dataLoad = (char *)malloc(availableFileList[i].fileSize);
                    memset(dataLoad,'d',availableFileList[i].fileSize);
                    AppEFtpServerMessageToClient(node, clientPtr, dataLoad, availableFileList[i].fileSize, 1);
    
                    // close connection
                    APP_TcpCloseConnection(
                        node,
                        clientPtr->connectionId);

                    MEM_free(dataLoad); 
                    break;
                }
            }
        }

    }
}

/*
 * NAME:        AppEFtpServerDataUpdateFtp.
 * PURPOSE:     open ftp data connection and create the data structure for 
 *              ftp data client.
 * PARAMETERS:  node - pointer to the node.
 *              openResult - result.
 * RETURN:      *AppDataEFtpClient.
 */
AppDataEFtpClient *
AppEFtpServerDataUpdateFtp(Node *node,
                            TransportToAppOpenResult *openResult)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataEFtpClient *tmpFtpClient = NULL;
    AppDataEFtpClient *ftpClient = NULL;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_EFTP_SERVER_DATA)
        {
            tmpFtpClient = (AppDataEFtpClient *) appList->appDetail;

#ifdef DEBUG
            printf("FTP Client: Node %d comparing uniqueId "
                   "%d with %d\n",
                   node->nodeId,
                   tmpFtpClient->uniqueId,
                   openResult->uniqueId);
#endif /* DEBUG */

            if (tmpFtpClient->uniqueId == openResult->uniqueId)
            {
                ftpClient = tmpFtpClient;
                break;
            }
        }
    }

    if (ftpClient == NULL)
    {
        assert(FALSE);
    }

    /*
     * fill in connection id, etc.
     */
    ftpClient->connectionId = openResult->connectionId;
    ftpClient->localAddr = openResult->localAddr;
    ftpClient->remoteAddr = openResult->remoteAddr;
    ftpClient->sessionStart = node->getNodeTime();
    ftpClient->sessionFinish = node->getNodeTime();
    ftpClient->lastTime = 0;
    ftpClient->sessionIsClosed = FALSE;
    ftpClient->bytesRecvdDuringThePeriod = 0;
#ifdef DEBUG
    char addrStr[MAX_STRING_LENGTH];
    printf("FTP Client: Node %d updating ftp client structure\n",
            node->nodeId);
    printf("    connectionId = %d\n", ftpClient->connectionId);
    IO_ConvertIpAddressToString(&ftpClient->localAddr, addrStr);
    printf("    localAddr = %s\n", addrStr);
    IO_ConvertIpAddressToString(&ftpClient->remoteAddr, addrStr);
    printf("    remoteAddr = %s\n", addrStr);
    printf("    itemsToSend = %d\n", ftpClient->itemsToSend);
#endif /* DEBUG */

    return ftpClient;

}

/*
 * NAME:        AppEFtpServerDataGetFtp.
 * PURPOSE:     search for a ftp data client data structure.
 * PARAMETERS:  node - pointer to the node.
 *              connId - connection ID of the ftp data connection.
 * RETURN:      the pointer to the ftp data structure,
 *              NULL if nothing found.
 */
AppDataEFtpClient *
AppEFtpServerDataGetFtp(Node *node, int connId)
{
    AppInfo *appList = node->appData.appPtr;
    AppDataEFtpClient *ftpClient;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_EFTP_SERVER_DATA)
        {
            ftpClient = (AppDataEFtpClient *) appList->appDetail;

            if (ftpClient->connectionId == connId)
            {
                return ftpClient;
            }
        }
    }
    return NULL;
}

/*
 * NAME:        AppEFtpServerAvailableFile.
 * PURPOSE:     check if the requested file is vailable.
 * PARAMETERS:  fileName - requested file.
 * RETURN:      return file size if found, otherwise return 0. 
 */

int AppEFtpServerAvailableFile(Node *node, char * fileName)
{

    if (isFileAccessMode) //if File Access is enabled
    {
        std::string absPath;
        absPath = rootFilesystem + "/" + fileName;

#ifndef _WIN32
        struct stat fileStat;
        if (stat(absPath.c_str(), &fileStat) == 0)
        {
            return fileStat.st_size;
        }
        else
        {
            return 0;
        }
#else // windows
        struct _finddata_t c_file;
        long hFile;

        if ((hFile = _findfirst(absPath.c_str(), &c_file)) == -1L)
        {
            return 0;
        }
        else
        {    
            return c_file.size;
        }
#endif // _WIN32
    }
    else  //memory access
    {
        int i;
   
        for (i=0 ; availableFileList[i].fileSize>0; i++)
        {
            if (!strcmp(availableFileList[i].fileName, fileName))
                return availableFileList[i].fileSize;
        }
    }

    return 0;
}
#endif
