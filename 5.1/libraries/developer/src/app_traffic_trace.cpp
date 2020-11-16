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
#include "app_util.h"
#include "app_traffic_trace.h"

#define TRAFFIC_TRACE_DEBUG 0
#define TRAFFIC_TRACE_INIT_DEBUG 0
#define TRAFFIC_TRACE_CHECK_TRACING 0

//-----------------------------------------------------
// NAME:        TrafficTraceClientPrintUsageAndQuit
// PURPOSE:     print usage and quit
// PARAMETERS:  none
// RETRUN:      none
//-----------------------------------------------------
static
void TrafficTraceClientPrintUsageAndQuit(void)
{
    printf("TRAFFIC-TRACE: Incorrect parameters.\n");
    printf("Usage: "TRAFFIC_TRACE_USAGE);
    exit(0);
}

//---------------------------------------------------------
// NAME:        TrafficTraceRequestNewConnectionSession
// PURPOSE:     print usage and quit
// PARAMETERS:  node - pointer to the node
//              clientPtr - pointer to the client
//              sendDelay - required delay
// RETRUN:      none
//---------------------------------------------------------
static
void TrafficTraceRequestNewConnectionSession(
    Node* node,
    TrafficTraceClient*  clientPtr,
    clocktype sendDelay)
{
    AppQosToNetworkSend* info = NULL;
    Message* setupMsg = NULL;

    // Schedule a message for Q-OSPF to inform origination of a new
    // connection session of a TRAFFIC-TRACE application. Info field of this
    // message contains Qos requirements and identification of new
    // connection.

    setupMsg = MESSAGE_Alloc(node,
                   NETWORK_LAYER,
                   ROUTING_PROTOCOL_OSPFv2,
                   MSG_ROUTING_QospfSetNewConnection);

    MESSAGE_InfoAlloc(node, setupMsg, sizeof(AppQosToNetworkSend));

    info = (AppQosToNetworkSend*) MESSAGE_ReturnInfo(setupMsg);

    info->clientType = APP_TRAFFIC_TRACE_CLIENT;

    info->sourcePort = (short) clientPtr->sourcePort;
    info->destPort = APP_TRAFFIC_TRACE_SERVER;
    info->sourceAddress = clientPtr->localAddr;
    info->destAddress = clientPtr->remoteAddr;

    info->priority = clientPtr->qosConstraints.priority;
    info->bandwidthRequirement = clientPtr->qosConstraints.bandwidth;
    info->delayRequirement = clientPtr->qosConstraints.delay;

    if (TRAFFIC_TRACE_INIT_DEBUG)
    {
        char srcAddr[MAX_STRING_LENGTH];
        char destAddr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(clientPtr->localAddr, srcAddr);
        IO_ConvertIpAddressToString(clientPtr->remoteAddr, destAddr);

        printf("\n\n"
               "Connection request going from .......\n"
               "....Source Addr %s Dest Addr %s\n"
               "....Source port %d Dest port %d\n\n",
            srcAddr, destAddr,
            clientPtr->sourcePort, APP_TRAFFIC_TRACE_SERVER);
    }
    MESSAGE_Send(node, setupMsg, sendDelay);
}


//---------------------------------------------------------------------
// NAME:        TrafficTraceClientGetClient.
// PURPOSE:     search for a traffic trace client data structure.
// PARAMETERS:  node - pointer to the node.
//              sourcePort - connection ID of the traffic trace client.
// RETURN:      the pointer to the traffic trace client data structure.
//              If nothing found, assertion false occures giving
//              a proper error message.
//---------------------------------------------------------------------
static
TrafficTraceClient* TrafficTraceClientGetClient(
    Node* node,
    int sourcePort)
{
    AppInfo* appList = NULL;
    TrafficTraceClient* clientPtr = NULL;
    char errorMsg[MAX_STRING_LENGTH];

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_TRACE_CLIENT)
        {
            clientPtr = (TrafficTraceClient*)  appList->appDetail;

            if (clientPtr->sourcePort == sourcePort)
            {
                return clientPtr;
            }
        }
    }

    // Not found
    sprintf(errorMsg, "TRAFFIC-TRACE Client: Node %d cannot find "
        "traffic trace client.\n", node->nodeId);
    ERROR_Assert(FALSE, errorMsg);

    // Though unreachable code. But kept to eliminate warning msg.
    return NULL;
}


//----------------------------------------------------------------------------
// NAME:        TrafficTraceClientNewClient.
// PURPOSE:     create a new traffic trace client data structure, place it
//              at the beginning of the application list.
// PARAMETERS:  node - pointer to the node.
// RETURN:      pointer to the created traffic trace client data structure,
//              NULL if no data structure allocated.
//----------------------------------------------------------------------------
static
TrafficTraceClient* TrafficTraceClientNewClient(Node* node)
{
    TrafficTraceClient* clientPtr;

    clientPtr = (TrafficTraceClient*)
        MEM_malloc(sizeof(TrafficTraceClient));

    // Initialize the client
    clientPtr->localAddr = 0;
    clientPtr->remoteAddr = 0;
    clientPtr->startTm = 0;
    clientPtr->endTm = 0;

    // Initialize the structure required to collect trace data.
    memset(&clientPtr->dataBlock, 0, sizeof(TrafficTraceGetDataBlock));

    DlbReset(&clientPtr->dlb, 0, 0, 0, node->getNodeTime());

    clientPtr->isDlbDrp = FALSE;
    clientPtr->delayedData = 0;
    clientPtr->delayedIntv = 0;
    clientPtr->dlbDrp = 0;
    clientPtr->trfType = TRAFFIC_TRACE_TRF_TYPE_TRC;
    clientPtr->lastSndTm = node->getNodeTime();
    clientPtr->totByteSent = 0;
    clientPtr->totDataSent = 0;

    MsTmWinInit(&clientPtr->sndThru,
                (clocktype) TRAFFIC_TRACE_CLIENT_SSIZE,
                TRAFFIC_TRACE_CLIENT_NSLOT,
                TRAFFIC_TRACE_CLIENT_WEIGHT,
                node->getNodeTime());

    clientPtr->seqNo = 0;
    clientPtr->fragNo = 0;
    clientPtr->totFrag = 0;
    clientPtr->sourcePort = node->appData.nextPortNum++;
    clientPtr->isClosed = FALSE;

    // Quality of service related variables.
    clientPtr->isSessionAdmitted = FALSE;
    clientPtr->isQosEnabled = FALSE;
    clientPtr->qosConstraints.bandwidth = 0;
    clientPtr->qosConstraints.delay = 0;
    clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
    clientPtr->isRetryRequired = FALSE;
    clientPtr->connectionRetryInterval = 0;

    APP_RegisterNewApp(node, APP_TRAFFIC_TRACE_CLIENT, clientPtr);

    return clientPtr;
}


//-----------------------------------------------------------------
// NAME:        TrafficTraceClientScheduleNextPkt.
// PURPOSE:     schedule the next packet that client will send. If
//              next packet won't arrive until the finish deadline,
//              schedule a close.
// PARAMETERS:  node - pointer to the node,
//              clientPtr - pointer to client data structure.
// RETRUN:      none.
//-----------------------------------------------------------------
static
void TrafficTraceClientScheduleNextPkt(
    Node* node,
    TrafficTraceClient* clientPtr,
    clocktype interval)
{
    AppTimer* timer = NULL;
    Message* timerMsg = MESSAGE_Alloc(node,
                                      APP_LAYER,
                                      APP_TRAFFIC_TRACE_CLIENT,
                                      MSG_APP_TimerExpired);

    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    timer->sourcePort = clientPtr->sourcePort;
    timer->type = APP_TIMER_SEND_PKT;

    MESSAGE_Send(node, timerMsg, interval);
}


//---------------------------------------------------------
// NAME:        TrafficTraceClientSkipToken.
// PURPOSE:     skip the first n tokens.
// PARAMETERS:  token - pointer to the input string,
//              tokenSep - pointer to the token separators,
//              skip - number of skips.
// RETRUN:      pointer to the next token position.
//---------------------------------------------------------
static
char* TrafficTraceClientSkipToken(char* token, const char* tokenSep, int skip)
{
    int idx;

    if (token == NULL)
    {
        return NULL;
    }
    // Eliminate preceding space
    idx = (int)strspn(token, tokenSep);
    token = (idx < (signed)strlen(token)) ? token + idx : NULL;

    while (skip > 0 && token != NULL)
    {
        token = strpbrk(token, tokenSep);

        if (token != NULL)
        {
            idx = (int)strspn(token, tokenSep);
            token = (idx < (signed)strlen(token)) ? token + idx : NULL;
        }
        skip--;
    }
    return token;
}


//--------------------------------------------------------
// NAME:        TrafficTraceClientReadTrace
// PURPOSE:     read in trace file and set client for that
// PARAMETERS:  node - pointer to node structure
//              clientPtr - pointer to the client
// RETRUN:      none
//--------------------------------------------------------
static
void TrafficTraceClientReadTrace(
    Node* node,
    TrafficTraceClient* clientPtr)
{
    FILE* file = NULL;
    int numElementScaned;
    int count;
    char buf0[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];
    char errMsg[MAX_STRING_LENGTH];

    FILE *fp = NULL;
    if (TRAFFIC_TRACE_CHECK_TRACING)
    {
        char now[MAX_STRING_LENGTH];
        char fileName[MAX_STRING_LENGTH];
        sprintf(fileName, "TraceFile_AFTER_READING_%d_%d_%d",
                clientPtr->localAddr,
                clientPtr->remoteAddr,
                clientPtr->sourcePort);
        fp = fopen(fileName, "a");

        TIME_PrintClockInSecond(node->getNodeTime(), now);
        fprintf(fp, "Current sim time..... %s\n", now);
    }

    // Open the file
    if ((file = fopen(clientPtr->dataBlock.fileName, "rb")) == NULL)
    {
        sprintf(errMsg,
            "TrafficTraceClientReadTrace:\n"
            "Cannot open file: %s\n",
            clientPtr->dataBlock.fileName);
        ERROR_ReportError(errMsg);
    }

    clientPtr->dataBlock.trcLen = TRAFFIC_TRACE_MAX_DATA_BLOCK_TO_READ;
    clientPtr->dataBlock.trcIdx = 0;
    clientPtr->dataBlock.numElementRead = 0;
    clientPtr->dataBlock.isNextScanedRequired = TRUE;

    if (!clientPtr->dataBlock.trcRec)
    {
        clientPtr->dataBlock.trcRec = (TrafficTraceTrcRec *)
            MEM_malloc(sizeof(TrafficTraceTrcRec)
                * TRAFFIC_TRACE_MAX_DATA_BLOCK_TO_READ);
    }

    // Read in the records. Before reading, place file pointer
    // in right place.

    fseek(file, clientPtr->dataBlock.lastFilePosition, SEEK_SET);

    for (count = 0;
         count < TRAFFIC_TRACE_MAX_DATA_BLOCK_TO_READ;
         count++)
    {
        numElementScaned = fscanf(file, "%s %s", buf0, buf1);

        if (numElementScaned != 2)
        {
            if (!feof(file))
            {
                sprintf(errMsg,
                    "TrafficTraceClientReadTrace:\n"
                    "Trace file %s not proper for client %x with "
                    "source port %d\n",
                    clientPtr->dataBlock.fileName,
                    clientPtr->localAddr,
                    clientPtr->sourcePort);
                ERROR_ReportError(errMsg);
            }
            else
            {
                clientPtr->dataBlock.isNextScanedRequired = FALSE;
                break;
            }
        }
        else
        {
            // Elements scanned properly.

            if (TRAFFIC_TRACE_CHECK_TRACING)
            {
                fprintf(fp, "%s    %s\n", buf0, buf1);
            }

            clientPtr->dataBlock.trcRec[count].interval =
                TIME_ConvertToClock(buf0);
            clientPtr->dataBlock.trcRec[count].dataLen = atol(buf1);
            clientPtr->dataBlock.numElementRead++;

            if (feof(file))
            {
                clientPtr->dataBlock.isNextScanedRequired = FALSE;
                break;
            }
        }
    }

    clientPtr->dataBlock.lastFilePosition = ftell(file);

    // Close the file
    fclose(file);

    if (TRAFFIC_TRACE_CHECK_TRACING)
    {
        fclose(fp);
    }
}


//----------------------------------------------------
// NAME:        TrafficTraceClientSendData
// PURPOSE:     send out application data as scheduled
// PARAMETERS:  node - pointer to the node
//              clientPtr - pointer to the client
// RETRUN:      none
//----------------------------------------------------
static
void TrafficTraceClientSendData(
    Node* node,
    TrafficTraceClient* clientPtr)
{
    char *payload;
    TrafficTraceData data;
    //init the TrafficTraceData
    memset(&data, 0, sizeof(data));

    Int32 dataLen = 0;
    clocktype dataIntv = 0;
    BOOL isGen = FALSE;

    clocktype dlbDelay;
    Int32 fragLen;

    dlbDelay = 0;

    if (clientPtr->delayedData)
    {
        isGen = TRUE;
        dataLen = clientPtr->delayedData;
        dataIntv = clientPtr->delayedIntv;
    }
    else
    {
        switch (clientPtr->trfType)
        {
            case TRAFFIC_TRACE_TRF_TYPE_TRC :
            {
                // No element found to send
                if (!clientPtr->dataBlock.numElementRead)
                {
                    isGen = FALSE;
                    return;
                }
                isGen = TRUE;

                // Data length
                dataLen = (Int32 ) ((clientPtr->dataBlock.trcRec
                           + clientPtr->dataBlock.trcIdx)->dataLen);

                dataIntv = (clientPtr->dataBlock.trcRec
                           + clientPtr->dataBlock.trcIdx)->interval;

                clientPtr->dataBlock.trcIdx++;

                break;
            }
            default :
            {
                ERROR_Assert(FALSE, "control reached an"
                    " unreachable block");
                break;
            }

        } // switch (clientPtr->trfType)
    } // end else

    if (isGen)
    {
        BOOL lastElementToSend = FALSE;

        // Refine the data interval
        if (dataIntv == 0)
        {
            dataIntv = 1 * NANO_SECOND;
        }

        // Check with DLB
        dlbDelay = DlbUpdate(&clientPtr->dlb, dataLen, node->getNodeTime());

        if (dlbDelay)
        {
            isGen = FALSE;

            if (clientPtr->isDlbDrp)
            {
                clientPtr->delayedData = 0;
                clientPtr->delayedIntv = 0;
                clientPtr->dlbDrp++;
            }
            else
            {
                clientPtr->delayedData = dataLen;
                clientPtr->delayedIntv = dataIntv;
                dataIntv = dlbDelay;
            }
        }
        else
        {
            clientPtr->delayedData = 0;
            clientPtr->delayedIntv = 0;
        }

        lastElementToSend = (!dlbDelay &&
                             (!clientPtr->dataBlock.isNextScanedRequired &&
                              clientPtr->dataBlock.trcIdx ==
                                clientPtr->dataBlock.numElementRead));

        if (clientPtr->isClosed == FALSE
            && ((clientPtr->endTm != 0
                    && node->getNodeTime() + dataIntv > clientPtr->endTm)
                || lastElementToSend))
        {
            clientPtr->isClosed = TRUE;
            clientPtr->endTm = node->getNodeTime();
        }

        if (isGen)
        {
            // Refine the data length
            dataLen = (dataLen < (signed) sizeof (TrafficTraceData)) ?
                sizeof (TrafficTraceData) : dataLen;

            // Statistics update
            clientPtr->totByteSent += dataLen;

            ERROR_Assert(
                clientPtr->totByteSent < TRAFFIC_TRACE_MAX_DATABYTE_SEND,
                "Total bytes sent exceed maximum limit, current packet"
                " size should be reduced for proper statistics");

            clientPtr->totDataSent++;
            clientPtr->lastSndTm = node->getNodeTime();

            MsTmWinNewData(&clientPtr->sndThru,
                           dataLen * 8.0,
                           node->getNodeTime());

            if (TRAFFIC_TRACE_DEBUG)
            {
                FILE *fp = NULL;
                char fileName[MAX_STRING_LENGTH];
                char dataBuf[MAX_STRING_LENGTH];
                clocktype currentTime = node->getNodeTime();

                sprintf(fileName, "ClientTraceFile_%d_%d_%d",
                    clientPtr->localAddr,
                    clientPtr->remoteAddr,
                    clientPtr->sourcePort);

                fp = fopen(fileName, "a");
                if (fp)
                {
                    sprintf(dataBuf, "%.6f\t%d\t%.6f\t%.6f\n",
                        (currentTime / (double)SECOND),
                        clientPtr->sourcePort,
                        MsTmWinAvg(&clientPtr->sndThru, currentTime),
                        MsTmWinTotalAvg(&clientPtr->sndThru, currentTime));

                    if (fwrite(dataBuf, strlen(dataBuf), 1, fp)!= 1)
                    {
                       ERROR_ReportWarning("Unable to write in file \n");
                    }

                    fclose(fp);
                }
            }

            // Set up data
            data.startTm    = clientPtr->startTm;
            data.endTm      = clientPtr->endTm;
            data.sourcePort = clientPtr->sourcePort;
            data.txTime     = node->getNodeTime();
            data.seqNo      = clientPtr->seqNo++;
            data.totFrag    = (Int32)(
                               (dataLen / APP_MAX_DATA_SIZE) +
                               (dataLen % APP_MAX_DATA_SIZE > 0 ? 1 : 0));
            data.fragNo     = 0;

            data.isMdpEnabled = clientPtr->isMdpEnabled;
            data.mdpUniqueId = clientPtr->mdpUniqueId;

            // Fragmentation
            while (dataLen > 0)
            {
                fragLen = (dataLen > APP_MAX_DATA_SIZE) ?
                    APP_MAX_DATA_SIZE : dataLen;

                if (dataLen > fragLen
                    && dataLen - fragLen < (signed) sizeof(TrafficTraceData))
                {
                    fragLen = dataLen - sizeof(TrafficTraceData);
                }

                payload = (char *)MEM_malloc(fragLen);
                memset(payload, 0, fragLen);

                memcpy(payload, &data, sizeof(data));

                Message *msg = APP_UdpCreateMessage(
                    node,
                    clientPtr->localAddr,
                    clientPtr->sourcePort,
                    clientPtr->remoteAddr,
                    APP_TRAFFIC_TRACE_SERVER,
                    TRACE_TRAFFIC_TRACE,
                    clientPtr->qosConstraints.priority);

                APP_AddPayload(
                    node,
                    msg,
                    payload,
                    fragLen);

                if (clientPtr->isMdpEnabled)
                {
                    APP_UdpSetMdpEnabled(msg, clientPtr->mdpUniqueId);
                }

                APP_UdpSend(node, msg);

                dataLen -= fragLen;
                data.fragNo++;
                MEM_free(payload);
            } // end while (dataLen > 0)
        } // end  if (isGen)
    } // end  if (isGen)

    // Previous scanned data already transfered, So
    // scan the trace file.
    if ((clientPtr->dataBlock.trcIdx
         == clientPtr->dataBlock.numElementRead) &&
        clientPtr->dataBlock.isNextScanedRequired)
    {
        TrafficTraceClientReadTrace(node, clientPtr);
    }

    if (!clientPtr->isClosed)
    {
        TrafficTraceClientScheduleNextPkt(node, clientPtr, dataIntv);
    }
}


//-------------------------------------------------------------------
// NAME:        TrafficTraceClientLayerRoutine.
// PURPOSE:     Models the behaviour of Traffic Trace Client  on
//              receiving the message encapsulated in msg.
// PARAMETERS:  node - pointer to the node which received the message.
//              msg - message received by the layer
// RETURN:      none.
//-------------------------------------------------------------------
void TrafficTraceClientLayerRoutine(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    TrafficTraceClient* clientPtr = NULL;
    AppTimer* timer = NULL;

    ctoa(node->getNodeTime(), buf);

    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            timer = (AppTimer*)MESSAGE_ReturnInfo(msg);
            clientPtr = TrafficTraceClientGetClient
                            (node, timer->sourcePort);

            switch (timer->type)
            {
                case APP_TIMER_SEND_PKT:
                {
                    TrafficTraceClientSendData(node, clientPtr);
                    break;
                }
                default:
                {
                   ERROR_Assert(FALSE, "Unknown timer type");
                   break;
                }
            }
            break;
        }
        case MSG_APP_SessionStatus:
        {
            NetworkToAppQosConnectionStatus* info = NULL;

            info = (NetworkToAppQosConnectionStatus*)
                    MESSAGE_ReturnInfo(msg);

            clientPtr = TrafficTraceClientGetClient(node, info->sourcePort);

            if (info->isSessionAdmitted)
            {
                // Session admitted. Modify start time and end time of
                // this session and schedule to send first packet.
                clientPtr->isSessionAdmitted = TRUE;

                clientPtr->endTm = (node->getNodeTime() +
                    (clientPtr->endTm - clientPtr->startTm));

                clientPtr->startTm = node->getNodeTime();

                TrafficTraceClientScheduleNextPkt(node, clientPtr, 0);
            }
            else if (clientPtr->isRetryRequired)
            {
                // Retry to establish the connection.
                TrafficTraceRequestNewConnectionSession(
                    node,
                    clientPtr,
                    clientPtr->connectionRetryInterval);
            }
            break;
        }
        default:
        {
            ctoa(node->getNodeTime(), buf);

            printf("TRAFFIC-TRACE Client: at time %s, node %d "
                "received message of unknown type %d.\n",
                buf, node->nodeId, msg->eventType);
#ifndef EXATA
            ERROR_Assert(FALSE, "Code has reached an "
                "unrechable block");
#endif
        }
    } // end switch (msg->eventType)
    MESSAGE_Free(node, msg);
}


//--------------------------------------------------------
// NAME:        TrafficTraceClientInit.
// PURPOSE:     Initialize a TrafficTraceClient session.
// PARAMETERS:  node - pointer to the node,
//              inputString - input string.
// RETURN:      none.
//--------------------------------------------------------
#define TOKENSEP    " ,\t"
void TrafficTraceClientInit(
    Node* node,
    char* inputString,
    NodeAddress localAddr,
    NodeAddress remoteAddr,
    BOOL isDestMulticast,
    BOOL isMdpEnabled,
    BOOL isProfileNameSet,
    char* profileName,
    Int32 uniqueId,
    const NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    TrafficTraceClient* clientPtr = NULL;
    char* tokenStr = NULL;
    int nToken = 0;
    RandomDistribution<clocktype> startEndTimeDistribution;
    Int32 bucketSize;
    Int32 tokenRate;
    Int32 peakRate;
    char delayStr[MAX_STRING_LENGTH];

    // Create a new client
    clientPtr = TrafficTraceClientNewClient(node);

    // Assign client and server address.
    clientPtr->localAddr = localAddr;
    clientPtr->remoteAddr = remoteAddr;

    // Skip client properties
    tokenStr = inputString;
    tokenStr = TrafficTraceClientSkipToken(
                   tokenStr, TOKENSEP, TRAFFIC_TRACE_SKIP_SRC_AND_DEST);

    startEndTimeDistribution.setSeed(node->globalSeed,
                                     node->nodeId,
                                     APP_TRAFFIC_TRACE_CLIENT);

    nToken = startEndTimeDistribution.setDistribution(tokenStr, "TRAFFIC-TRACE", RANDOM_CLOCKTYPE);
    clientPtr->startTm = startEndTimeDistribution.getRandomNumber();

    tokenStr = TrafficTraceClientSkipToken(tokenStr, TOKENSEP, nToken);

    nToken = startEndTimeDistribution.setDistribution(tokenStr, "TRAFFIC-TRACE", RANDOM_CLOCKTYPE);
    clientPtr->endTm = clientPtr->startTm
                           + startEndTimeDistribution.getRandomNumber();

    tokenStr = TrafficTraceClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (tokenStr == NULL)
    {
        TrafficTraceClientPrintUsageAndQuit();
    }
    nToken = sscanf(tokenStr, "%s", buf);

    if (nToken != 1)
    {
        TrafficTraceClientPrintUsageAndQuit();
    }

    tokenStr = TrafficTraceClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (strcmp(buf, "RND") == 0)
    {
        ERROR_ReportError(
            "TrafficTraceClientInit:\n"
            "TRAFFIC-TRACE application takes data from a trace file only");
    }
    else if (strcmp(buf, "TRC") == 0)
    {
        // Trace file-based traffic
        clientPtr->trfType = TRAFFIC_TRACE_TRF_TYPE_TRC;

        if (tokenStr == NULL)
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        nToken = sscanf(tokenStr, "%s", buf);

        if (nToken != 1)
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        tokenStr = TrafficTraceClientSkipToken(tokenStr, TOKENSEP, nToken);

        // Collect file name and file pointer
        strcpy(clientPtr->dataBlock.fileName, buf);
        clientPtr->dataBlock.lastFilePosition = 0;

        if (TRAFFIC_TRACE_CHECK_TRACING)
        {
            FILE *fp;
            char fileName[MAX_STRING_LENGTH];
            sprintf(fileName, "TraceFile_AFTER_READING_%d_%d_%d",
                clientPtr->localAddr,
                clientPtr->remoteAddr,
                clientPtr->sourcePort);
            fp = fopen(fileName, "w");
            fclose(fp);
        }

        TrafficTraceClientReadTrace(node, clientPtr);
    }
    else
    {
        TrafficTraceClientPrintUsageAndQuit();
    }

    if (tokenStr == NULL)
    {
        TrafficTraceClientPrintUsageAndQuit();
    }

    nToken = sscanf(tokenStr, "%s", buf);

    if (nToken != 1)
    {
        TrafficTraceClientPrintUsageAndQuit();
    }

    tokenStr = TrafficTraceClientSkipToken(tokenStr, TOKENSEP, nToken);

    if (strcmp(buf, "NOLB") == 0)
    {
        // No shaper
        DlbReset(&clientPtr->dlb, 0, 0, 0, node->getNodeTime());

    }
    else
    {
        if (strcmp(buf, "LB") == 0)
        {
            // Shaper with LB
            if (tokenStr == NULL)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            nToken = sscanf(tokenStr, "%d %d", &bucketSize, &tokenRate);

            if (nToken != 2)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            tokenStr = TrafficTraceClientSkipToken(
                           tokenStr, TOKENSEP, nToken);

            DlbReset(&clientPtr->dlb,
                     bucketSize,
                     tokenRate,
                     0,
                     node->getNodeTime());
        }
        else if (strcmp(buf, "DLB") == 0)
        {
            // Shaper with DLB
            if (tokenStr == NULL)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }
            nToken = sscanf(tokenStr, "%d %d %d",
                         &bucketSize, &tokenRate, &peakRate);
            if (nToken != 3)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            tokenStr = TrafficTraceClientSkipToken(
                           tokenStr, TOKENSEP, nToken);

            DlbReset(&clientPtr->dlb,
                     bucketSize,
                     tokenRate,
                     peakRate,
                     node->getNodeTime());
        }
        else
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        if (tokenStr == NULL)
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        nToken = sscanf(tokenStr, "%s", buf);

        if (nToken != 1)
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        tokenStr = TrafficTraceClientSkipToken(
                       tokenStr, TOKENSEP, nToken);

        if (strcmp(buf, "DROP") == 0)
        {
            clientPtr->isDlbDrp = TRUE;
        }
        else if (strcmp(buf, "DELAY") == 0)
        {
            clientPtr->isDlbDrp = FALSE;
        }
        else
        {
            TrafficTraceClientPrintUsageAndQuit();
        }
    }


    //client pointer initialization with respect to mdp
    clientPtr->isMdpEnabled = isMdpEnabled;
    clientPtr->mdpUniqueId = uniqueId;

    if (isMdpEnabled)
    {
        Address clientAddr, destAddr;

        memset(&clientAddr,0,sizeof(Address));
        memset(&destAddr,0,sizeof(Address));

        clientAddr.networkType = NETWORK_IPV4;
        clientAddr.interfaceAddr.ipv4 = localAddr;

        destAddr.networkType = NETWORK_IPV4;
        destAddr.interfaceAddr.ipv4 = remoteAddr;

        if (isDestMulticast)
        {
            // MDP Layer Init
            MdpLayerInit(node,
                         clientAddr,
                         destAddr,
                         clientPtr->sourcePort,
                         APP_TRAFFIC_TRACE_CLIENT,
                         isProfileNameSet,
                         profileName,
                         uniqueId,
                         nodeInput);
        }
        else
        {
            // MDP Layer Init
            MdpLayerInit(node,
                         clientAddr,
                         destAddr,
                         clientPtr->sourcePort,
                         APP_TRAFFIC_TRACE_CLIENT,
                         isProfileNameSet,
                         profileName,
                         uniqueId,
                         nodeInput,
                         -1,
                         TRUE);
        }
        if (tokenStr)
        {
            nToken = sscanf(tokenStr, "%s", buf);
            if (strcmp(buf, "MDP-ENABLED") == 0)
            {
                tokenStr = TrafficTraceClientSkipToken(tokenStr,
                                                       TOKENSEP,
                                                       nToken);
            }

            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", buf);
                if (strcmp(buf, "MDP-PROFILE") == 0)
                {
                    tokenStr = TrafficTraceClientSkipToken(tokenStr,
                                                           TOKENSEP,
                                                           nToken+1);
                }
            }
        }
    }


    // This section is for Quality of Service purpose. If quality
    // of service is demanded by specifying different CONSTRAINT
    // values in configuration file Quality of Service will be
    // activated.
    if (tokenStr == NULL)
    {
        clientPtr->isSessionAdmitted = TRUE;
        clientPtr->isQosEnabled = FALSE;
        clientPtr->qosConstraints.bandwidth = 0;
        clientPtr->qosConstraints.delay = 0;
        clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
        clientPtr->isRetryRequired = FALSE;
        clientPtr->connectionRetryInterval = 0;
    }
    else
    {
        // If destination is a multicast address, Quality of
        // Service cannot be provided for this multicast flow.
        if (isDestMulticast)
        {
            ERROR_ReportError(
                "Quality of Service cannot "
                "be provided for multicast flow\n");
        }

        nToken = sscanf(tokenStr, "%s", buf);

        if (nToken != 1)
        {
            TrafficTraceClientPrintUsageAndQuit();
        }

        tokenStr = TrafficTraceClientSkipToken(
                       tokenStr, TOKENSEP, nToken);

        if (strcmp(buf, "CONSTRAINT") == 0)
        {
            char tosStr[MAX_STRING_LENGTH];
            char tosValueStr[MAX_STRING_LENGTH];
            unsigned priorityInInt = APP_DEFAULT_TOS;

            clientPtr->isQosEnabled = TRUE;

            if (tokenStr == NULL)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            nToken = sscanf(tokenStr, "%d %s %s %s",
                        &clientPtr->qosConstraints.bandwidth,
                        delayStr,
                        tosStr,
                        tosValueStr);

            if (nToken < 2)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            clientPtr->qosConstraints.delay = (int) (
                TIME_ConvertToClock(delayStr)/MICRO_SECOND);

            if (clientPtr->qosConstraints.delay <= 0)
            {
                ERROR_ReportError(
                    "\nInvalid end-to-end delay constraint\n");
            }

            if (nToken == 2)
            {
                clientPtr->qosConstraints.priority = APP_DEFAULT_TOS;
            }

            if (nToken > 2)
            {
                if (!strcmp(tosStr, "RETRY-INTERVAL")
                    || !strcmp(tosStr, "MDP-ENABLED")
                    || !strcmp(tosStr, "MDP-PROFILE"))
                {
                    // qos_property: not contains [TOS] field
                    nToken = 2;
                }
                else
                {
                    if ((nToken == 4) &&
                        APP_AssignTos(tosStr, tosValueStr, &priorityInInt))
                    {
                        clientPtr->qosConstraints.priority =
                            (unsigned char)priorityInInt;
                    }
                    else
                    {
                        char errString[MAX_STRING_LENGTH];
                        sprintf(errString,
                            "Error in user application specification.\n"
                            "%s\n"
                            "Format of qos property is\n  <qos_property> ::="
                            " CONSTRAINT <bandwidth> <delay>"
                            "[ TOS <tos-value> | DSCP <dscp-value>"
                            " | PRECEDENCE <precedence-value> ]\n",
                            inputString);
                        ERROR_ReportError(errString);
                    }
                }
            }

            tokenStr = TrafficTraceClientSkipToken(
                           tokenStr, TOKENSEP, nToken);
        }
        else
        {
            ERROR_ReportWarning("Without Quality of Service, connection "
                    "retry not required\n");
            TrafficTraceClientPrintUsageAndQuit();
        }

        if (tokenStr)
        {
            nToken = sscanf(tokenStr, "%s", buf);
            if (strcmp(buf, "MDP-ENABLED") == 0)
            {
                tokenStr = TrafficTraceClientSkipToken(tokenStr,
                                                       TOKENSEP,
                                                       nToken);
            }

            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", buf);
                if (strcmp(buf, "MDP-PROFILE") == 0)
                {
                    tokenStr = TrafficTraceClientSkipToken(tokenStr,
                                                           TOKENSEP,
                                                           nToken+1);
                }
            }
        }

        // Check whether connection retry required or not. If required
        // get the interval of retry timer
        if (tokenStr == NULL)
        {
            clientPtr->isRetryRequired = FALSE;
            clientPtr->connectionRetryInterval = 0;
        }
        else
        {
            nToken = sscanf(tokenStr, "%s", buf);

            if (nToken != 1)
            {
                TrafficTraceClientPrintUsageAndQuit();
            }

            tokenStr = TrafficTraceClientSkipToken(
                           tokenStr, TOKENSEP, nToken);

            if (strcmp(buf, "RETRY-INTERVAL") == 0)
            {
                clientPtr->isRetryRequired = TRUE;

                if (tokenStr == NULL)
                {
                    TrafficTraceClientPrintUsageAndQuit();
                }
                nToken = sscanf(tokenStr, "%s", buf);

                clientPtr->connectionRetryInterval =
                    TIME_ConvertToClock(buf);

                if (clientPtr->connectionRetryInterval <= 0)
                {
                    ERROR_ReportError("\nInvalid retry interval\n");
                }

                tokenStr = TrafficTraceClientSkipToken(
                               tokenStr, TOKENSEP, nToken);
            }
            else
            {
                TrafficTraceClientPrintUsageAndQuit();
            }
        }

        if (TRAFFIC_TRACE_INIT_DEBUG)
        {
            char clockStr[MAX_STRING_LENGTH];

            ctoa((clientPtr->connectionRetryInterval / SECOND), clockStr);

            printf("\nTRAFFIC_TRACE: %d, Qos Bandwidth: %d, Qos Delay: %d,"
                    " Given Priority: %d\n\n",
                    clientPtr->isQosEnabled,
                    clientPtr->qosConstraints.bandwidth,
                    clientPtr->qosConstraints.delay,
                    clientPtr->qosConstraints.priority);

            printf("Connection retry property: %d retry interval %sS\n\n",
                    clientPtr->isRetryRequired, clockStr);
        }
    }

    if (TRAFFIC_TRACE_DEBUG)
    {
        FILE *fp;
        char fileName[MAX_STRING_LENGTH];
        sprintf(fileName, "ClientTraceFile_%d_%d_%d",
            clientPtr->localAddr,
            clientPtr->remoteAddr, clientPtr->sourcePort);
        fp = fopen(fileName, "w");
        fclose(fp);
    }

    // Issue a message for the first data. If Quality of Service is
    // requested, then send a connection setup message before issueing
    // the message for first data.
    if (clientPtr->isQosEnabled)
    {
        TrafficTraceRequestNewConnectionSession(
            node, clientPtr, clientPtr->startTm);
    }
    else
    {
        TrafficTraceClientScheduleNextPkt(
            node, clientPtr, clientPtr->startTm);
    }
}


//----------------------------------------------------------------
// NAME:        TrafficTraceClientPrintStats.
// PURPOSE:     Prints statistics of a TrafficTraceClient session.
// PARAMETERS:  node - pointer to the this node.
//              clientPtr - pointer to the client data structure.
// RETURN:      none.
//----------------------------------------------------------------
static
void TrafficTraceClientPrintStats(
    Node* node,
    TrafficTraceClient* clientPtr)
{
    clocktype throughput;

    char remoteAddrStr[MAX_STRING_LENGTH];
    char startTmStr[MAX_STRING_LENGTH];
    char endTmStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];

    if (clientPtr->isSessionAdmitted)
    {
        TIME_PrintClockInSecond(clientPtr->startTm, startTmStr);
        TIME_PrintClockInSecond(clientPtr->endTm, endTmStr);

        if (clientPtr->endTm != 0 && node->getNodeTime() >= clientPtr->endTm)
        {
            clientPtr->isClosed = TRUE;
            sprintf(statusStr, "Closed");
        }
        else
        {
            sprintf(statusStr, "Not closed");
        }

        if (clientPtr->lastSndTm > clientPtr->startTm)
        {
            throughput = (clocktype)((clientPtr->totByteSent * 8.0 * SECOND)
                / (clientPtr->lastSndTm - clientPtr->startTm));
        }
        else
        {
            throughput = 0;
        }

        ctoa(throughput, throughputStr);

        IO_ConvertIpAddressToString(clientPtr->remoteAddr, remoteAddrStr);
        sprintf(buf, "Server Address = %s", remoteAddrStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Session Start Time (s) = %s", startTmStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Session End Time (s) = %s", endTmStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Session Status = %s", statusStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        ctoa(clientPtr->totByteSent, buf1);
        sprintf(buf, "Total Bytes Sent = %s", buf1);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Total Data Units Sent = %d", clientPtr->totDataSent);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Total Data Units Dropped = %d", clientPtr->dlbDrp);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);

        sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);
    }
    else
    {
        IO_ConvertIpAddressToString(clientPtr->remoteAddr, remoteAddrStr);
        sprintf(buf, "Session Not Admitted For Server Address %s",
                remoteAddrStr);
        IO_PrintStat(
            node,
            "Application",
            "TRAFFIC-TRACE Client",
            ANY_DEST,
            clientPtr->sourcePort,
            buf);
    }
}


//-----------------------------------------------------------------------
// NAME:        TrafficTraceClientFinalize.
// PURPOSE:     Collect statistics of a TrafficTraceClient session.
// PARAMETERS:  node - pointer to the node.
//              appInfo - pointer to the application info data structure.
// RETURN:      none.
//-----------------------------------------------------------------------
void TrafficTraceClientFinalize(Node* node, AppInfo* appInfo)
{
    TrafficTraceClient* clientPtr = (TrafficTraceClient*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        TrafficTraceClientPrintStats(node, clientPtr);
    }
}


//-------------------------------------------------------------------------
// NAME:        TrafficTraceServerGetServer.
// PURPOSE:     search for a traffic trace server data structure.
// PARAMETERS:  node - traffic trace server.
//              remoteAddr - traffic trace client sending the data.
//              sourcePort - sourcePort of traffic trace client/server pair.
// RETURN:      the pointer to the traffic trace server data structure,
//              NULL if nothing found.
//-------------------------------------------------------------------------
static
TrafficTraceServer* TrafficTraceServerGetServer(
    Node* node,
    NodeAddress remoteAddr,
    int sourcePort)
{
    AppInfo* appList = NULL;
    TrafficTraceServer*  serverPtr = NULL;

    for (appList = node->appData.appPtr;
         appList != NULL;
         appList = appList->appNext)
    {
        if (appList->appType == APP_TRAFFIC_TRACE_SERVER)
        {
            serverPtr = (TrafficTraceServer*)  appList->appDetail;

            if ((serverPtr->sourcePort == sourcePort)
                && (serverPtr->remoteAddr == remoteAddr))
            {
                return serverPtr;
            }
        }
    }
    return NULL;
}


//----------------------------------------------------------------------------
// NAME:        TrafficTraceServerNewServer.
// PURPOSE:     create a new traffic trace server data structure, place it
//              at the beginning of the application list.
// PARAMETERS:  node - pointer to the node.
//              sourceAddr - local address
//              destAddr - remote address.
//              sourcePort - sourcePort of traffic trace client/server pair.
//              destPort - destination port of traffic trace client/server pair.
// RETRUN:      the pointer to the created traffic trace server data structure,
//              NULL if no data structure allocated.
//----------------------------------------------------------------------------
static
TrafficTraceServer* TrafficTraceServerNewServer(
    Node* node,
    NodeAddress remoteAddr,
    NodeAddress localAddress,
    short sourcePort)
{
    TrafficTraceServer*  serverPtr;

    serverPtr = (TrafficTraceServer*)
        MEM_malloc(sizeof(TrafficTraceServer));

    // Initialize
    serverPtr->localAddr = localAddress;
    serverPtr->remoteAddr = remoteAddr;
    serverPtr->sourcePort = sourcePort;

    serverPtr->startTm = node->getNodeTime();
    serverPtr->endTm = node->getNodeTime();
    serverPtr->lastRcvTm = 0;
    serverPtr->totByteRcvd = 0;
    serverPtr->totDataRcvd = 0;

    MsTmWinInit(&serverPtr->rcvThru,
                (clocktype) TRAFFIC_TRACE_SERVER_SSIZE,
                TRAFFIC_TRACE_SERVER_NSLOT,
                TRAFFIC_TRACE_SERVER_WEIGHT,
                node->getNodeTime());

    serverPtr->totDelay = 0;
    serverPtr->seqNo = 0;
    serverPtr->fragNo = 0;
    serverPtr->totFrag = 0;
    serverPtr->fragByte = 0;
    serverPtr->fragTm = 0;
    serverPtr->isClosed = FALSE;

    serverPtr->lastInterArrivalInterval = 0;
    serverPtr->lastPacketReceptionTime = 0;
    serverPtr->totalJitter = 0;

    APP_RegisterNewApp(node, APP_TRAFFIC_TRACE_SERVER, serverPtr);

    if (TRAFFIC_TRACE_DEBUG)
    {
        FILE *fp;
        char fileName[MAX_STRING_LENGTH];
        sprintf(fileName, "ServerTraceFile_%d_%d_%d", serverPtr->remoteAddr,
            serverPtr->localAddr, serverPtr->sourcePort);
        fp = fopen(fileName, "w");
        fclose(fp);
    }

    return serverPtr;
}


//----------------------------------------------------------------------------
// NAME:        TrafficTraceServerLayerRoutine.
// PURPOSE:     Models the behaviour of Traffic Trace Server on receiving the
//              message encapsulated in msg.
// PARAMETERS:  node - pointer to the node which received the message.
//              msg - message received by the layer
// RETURN:      none.
//----------------------------------------------------------------------------
void TrafficTraceServerLayerRoutine(Node* node, Message* msg)
{
    char clockStr[MAX_STRING_LENGTH];
    char errMsg[MAX_STRING_LENGTH];
    TrafficTraceServer* serverPtr = NULL;
    UdpToAppRecv* info = NULL;
    TrafficTraceData data;

    switch (msg->eventType)
    {
        case MSG_APP_FromTransport:
        {
            info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);
            memcpy(&data, MESSAGE_ReturnPacket(msg), sizeof(data));

            serverPtr = TrafficTraceServerGetServer(
                            node,
                            GetIPv4Address(info->sourceAddr),
                            data.sourcePort);

            // New connection.
            // So create new traffic trace server to handle client.
            if (serverPtr == NULL)
            {
                serverPtr = TrafficTraceServerNewServer(
                    node, GetIPv4Address(info->sourceAddr),
                    GetIPv4Address(info->destAddr),
                    data.sourcePort);
            }

            if ((data.seqNo == serverPtr->seqNo
                    && data.fragNo == serverPtr->fragNo)
                    || (data.seqNo > serverPtr->seqNo && data.fragNo == 0)
                    || (data.isMdpEnabled))
            {

                if (data.fragNo == 0)
                {
                    serverPtr->fragByte = 0;
                    serverPtr->fragTm = data.txTime;
                }

                serverPtr->endTm = node->getNodeTime();
                serverPtr->lastRcvTm = node->getNodeTime();
                serverPtr->seqNo = data.seqNo;
                serverPtr->fragNo = data.fragNo;
                serverPtr->totFrag = data.totFrag;
                serverPtr->fragByte += MESSAGE_ReturnPacketSize(msg);

                if (serverPtr->fragNo == serverPtr->totFrag - 1)
                {
                    serverPtr->totDataRcvd++;
                    serverPtr->totByteRcvd  += serverPtr->fragByte;
                    serverPtr->totDelay += node->getNodeTime()
                                           - serverPtr->fragTm;
                    serverPtr->seqNo++;
                    serverPtr->fragNo = 0;

                    MsTmWinNewData(&serverPtr->rcvThru,
                                   serverPtr->fragByte * 8.0,
                                   node->getNodeTime());

                    // Calculate jitter.
                    if (serverPtr->totDataRcvd > 1)
                    {
                        clocktype now = node->getNodeTime();
                        clocktype interArrivalInterval;

                        interArrivalInterval =
                            (now - serverPtr->lastPacketReceptionTime);

                        // Jitter can only be measured after receiving
                        // three packets.
                        if (serverPtr->totDataRcvd > 2)
                        {
                            serverPtr->totalJitter += (clocktype)
                                abs((int) (interArrivalInterval -
                                    serverPtr->lastInterArrivalInterval));
                        }
                        serverPtr->lastInterArrivalInterval =
                                        interArrivalInterval;
                    }

                    serverPtr->lastPacketReceptionTime = node->getNodeTime();

                    if (TRAFFIC_TRACE_DEBUG)
                    {
                        FILE *fp;
                        char fileName[MAX_STRING_LENGTH];
                        char dataBuf[MAX_STRING_LENGTH];
                        clocktype currentTime = node->getNodeTime();

                        sprintf(fileName, "ServerTraceFile_%d_%d_%d",
                            serverPtr->remoteAddr,
                            serverPtr->localAddr,
                            serverPtr->sourcePort);

                        fp = fopen(fileName, "a");

                        if (fp)
                        {
                            sprintf(dataBuf, "%.6f\t%d\t%.6f\t%.6f\n",
                                (currentTime / (double)SECOND),
                                serverPtr->sourcePort,
                                MsTmWinAvg(&serverPtr->rcvThru,
                                           currentTime),
                                MsTmWinTotalAvg(&serverPtr->rcvThru,
                                                currentTime));

                            if (fwrite(dataBuf, strlen(dataBuf), 1, fp)!= 1)
                            {
                               ERROR_ReportWarning("Unable to write in file \n");
                            }

                            fclose(fp);
                        }
                    }
                }
                else
                {
                    serverPtr->fragNo++;
                }
            }
            break;
        }
        default:
        {
            ctoa(node->getNodeTime(), clockStr);

            sprintf(errMsg,
                "TRAFFIC-TRACE Server: At time %s, node %d received "
                "message of unknown type %d.\n",
                clockStr, node->nodeId, msg->eventType);

            ERROR_Assert(FALSE, errMsg);
            break;
        }
    }
    MESSAGE_Free(node, msg);
}


//-------------------------------------------------------
// NAME:        TrafficTraceServerInit.
// PURPOSE:     listen on TrafficTraceServer server port.
// PARAMETERS:  node - pointer to the node.
// RETURN:      none.
//-------------------------------------------------------
void TrafficTraceServerInit(Node* node)
{
}


//----------------------------------------------------------------------------
// NAME:        TrafficTraceServerPrintStats.
// PURPOSE:     Prints statistics of a TrafficTraceServer session.
// PARAMETERS:  node - pointer to this node.
//              serverPtr - pointer to the traffic trace server data structure.
// RETURN:      none.
//----------------------------------------------------------------------------
static
void TrafficTraceServerPrintStats(
    Node* node,
    TrafficTraceServer* serverPtr)
{
    clocktype throughput;
    clocktype avgJitter;

    char remoteAddrStr[MAX_STRING_LENGTH];
    char jitterStr[MAX_STRING_LENGTH];
    char delayStr[MAX_STRING_LENGTH];
    char startTmStr[MAX_STRING_LENGTH];
    char endTmStr[MAX_STRING_LENGTH];
    char statusStr[MAX_STRING_LENGTH];
    char throughputStr[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    char buf1[MAX_STRING_LENGTH];

    TIME_PrintClockInSecond(serverPtr->startTm, startTmStr);
    TIME_PrintClockInSecond(serverPtr->endTm, endTmStr);

    if (serverPtr->endTm != 0 && node->getNodeTime() >= serverPtr->endTm)
    {
        serverPtr->isClosed = TRUE;
    }

    if (serverPtr->isClosed == FALSE)
    {
        sprintf(statusStr, "Not closed");
    }
    else
    {
        sprintf(statusStr, "Closed");
    }

    if (serverPtr->totDataRcvd == 0)
    {
        TIME_PrintClockInSecond(0, delayStr);
    }
    else
    {
        TIME_PrintClockInSecond(
            serverPtr->totDelay / serverPtr->totDataRcvd,
            delayStr);
    }

    if (serverPtr->lastRcvTm > serverPtr->startTm)
    {
        throughput = (clocktype) ((serverPtr->totByteRcvd * 8.0 * SECOND)
            / (serverPtr->lastRcvTm - serverPtr->startTm));
    }
    else
    {
        throughput = 0;
    }
    ctoa(throughput, throughputStr);

    IO_ConvertIpAddressToString(serverPtr->remoteAddr, remoteAddrStr);
    sprintf(buf, "Client Address = %s", remoteAddrStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session Start Time (s) = %s", startTmStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session End Time (s) = %s", endTmStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Session Status = %s", statusStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    ctoa(serverPtr->totByteRcvd, buf1);
    sprintf(buf, "Total bytes Received = %s", buf1);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Total Data Units Received = %d", serverPtr->totDataRcvd);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Throughput (bits/s) = %s", throughputStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    sprintf(buf, "Average End-to-End Delay (s) = %s", delayStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);

    if (serverPtr->totDataRcvd - 2 <= 0)
    {
        avgJitter = 0;
    }
    else
    {
        avgJitter = serverPtr->totalJitter /
                    (serverPtr->totDataRcvd - 2);
    }

    // Jitter can only be measured after receiving three packets.
    TIME_PrintClockInSecond(avgJitter, jitterStr);

    sprintf(buf, "Average Jitter (s) = %s", jitterStr);
    IO_PrintStat(
        node,
        "Application",
        "TRAFFIC-TRACE Server",
        ANY_DEST,
        serverPtr->sourcePort,
        buf);
}


//-----------------------------------------------------------------------
// NAME:        TrafficTraceServerFinalize.
// PURPOSE:     Collect statistics of a TrafficTraceServer session.
// PARAMETERS:  node - pointer to the node.
//              appInfo - pointer to the application info data structure.
// RETURN:      none.
//-----------------------------------------------------------------------
void TrafficTraceServerFinalize(Node* node, AppInfo* appInfo)
{
    TrafficTraceServer* serverPtr = (TrafficTraceServer*)appInfo->appDetail;

    if (node->appData.appStats == TRUE)
    {
        TrafficTraceServerPrintStats(node, serverPtr);
    }
}

