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

#include "api.h"
#include "app_util.h"
#include "app_sigint.h"
#include "partition.h"
#include "phy.h"
#include "mac.h"
#include "channel_scanner.h"
#include "network_ip.h"

void AppSigintPrintSummary(Node* node, AppSigint* sigint)
{
    char clockStr[100];
    TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
    bool detectedSomething = false;

    printf("** [SIGINT Node %d Summary] at time %sS:\n",
            node->nodeId,
            clockStr);

    for (int i = 0; i < node->numberChannels; i++)
    {
        if (sigint->numSignalsReceived[i] > 0)
        {
            detectedSomething = true;
            printf("**\tSignals detected on channel %d "
                    "(frequency %f) = %u\n",
                    i,
                    PROP_GetChannelFrequency(node, i),
                    sigint->numSignalsReceived[i]);
        }
    }

    if (!detectedSomething) {
        printf("**\tNo signals detected!\n");
    }

    fflush(stdout);
}

Message* Sigint_Initialize(
        Node *node,
        const char* config)
{
    char sigintString[MAX_STRING_LENGTH];
    NodeAddress sigintNodeId;
    Address sigintAddr;
    int scannerType;
    char duration[MAX_STRING_LENGTH];
    int numValues;
    char printVerbose[MAX_STRING_LENGTH];
    char printSummary[MAX_STRING_LENGTH];
#define SIGINT_CONFIG_MIN_PARAMS 2
    numValues = sscanf(config, "%*s %s %d %s %s %s",
            sigintString,
            &scannerType,
            duration,
            printVerbose,
            printSummary);
    if (numValues < SIGINT_CONFIG_MIN_PARAMS)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf(errorString, "Incorrect configuration format in\n%s", config);
        ERROR_ReportError(errorString);
    }

    //SendTimer Message to start the Sigint on this interface
    Message* stopMsg;

    // timer for start scanning
    stopMsg = MESSAGE_Alloc(
        node,
        APP_LAYER,
        APP_SIGINT,
        MSG_SIGINT_Stop);
    stopMsg->originatingNodeId = node->nodeId;

    MESSAGE_InfoAlloc(node, stopMsg, sizeof(SigintInfo));
    SigintInfo* sigInfo =
        (SigintInfo *) MESSAGE_ReturnInfo(stopMsg);
    sigInfo->duration = CLOCKTYPE_MAX;
    sigInfo->scannerType = -1;

    switch (numValues)
    {
     case 5:
        if (!strcmp(printSummary, "-v"))
        {
            sigInfo->printVerbose = true;
        }
        else if (!strcmp(printSummary, "-s"))
        {
            sigInfo->printSummary = true;
        }
        else
        {
            sigInfo->duration = TIME_ConvertToClock(printSummary); 
        }
     case 4:
         if (!strcmp(printVerbose, "-v"))
         {
             sigInfo->printVerbose = true;
         }
         else if (!strcmp(printVerbose, "-s"))
         {
             sigInfo->printSummary = true;
         }
         else
         {
             sigInfo->duration = TIME_ConvertToClock(printVerbose); 
         }
     case 3:
         if (!strcmp(duration, "-v"))
         {
             sigInfo->printVerbose = true;
         }
         else if (!strcmp(duration, "-s"))
         {
             sigInfo->printSummary = true;
         }
         else
         {
             sigInfo->duration = TIME_ConvertToClock(duration); 
         }
     case 2:
        break;
    }

    if (sigInfo->duration == CLOCKTYPE_MAX || sigInfo->duration == 0)
    {
        sigInfo->duration = TIME_ReturnMaxSimClock(node) + 1 - node->getNodeTime();
    }

    IO_AppParseSourceString(
                node,
                config,
                sigintString,
                &sigintNodeId,
                &sigintAddr);
    sigInfo->sigintAddress = sigintAddr.interfaceAddr.ipv4;
    sigInfo->scannerType = scannerType;
    return stopMsg;
    //MESSAGE_Send(node, msg, sigInfo->duration);
}

void SigintHandler(Node* node,
        int channelIndex,
        ChannelScannerCallbackEvent eventType,
        void *arg)
{
    AppSigint *sigint = (AppSigint *)arg;
    int interfaceIndex = sigint->interfaceIndex;
    if (sigint == NULL)
    {
        return;
    }
    if (eventType == CHANNEL_SCANNING_STARTED)
    {
        PhyData *thisPhy;
        thisPhy = node->phyData[interfaceIndex];

        if (!node->phyData[interfaceIndex]->isSigintInterface)
        {
            StartSigintNode(node, sigint);
        }
        if (sigint->currChannelListening[channelIndex] == FALSE)
        {
            sigint->currChannelListening[channelIndex] = TRUE;
        }
    }
    else if (eventType == CHANNEL_SCANNING_STOPPED)
    {
        PhyData *thisPhy;
        thisPhy = node->phyData[interfaceIndex];
        if (sigint->currChannelListening[channelIndex] == TRUE)
        {
            sigint->currChannelListening[channelIndex] = FALSE;
        }
    }
}

void StopSigintNode(Node *node, AppSigint *sigint)
{
    int interfaceIndex = sigint->interfaceIndex;
    PhyData *thisPhy;
    PropData* propData;
    thisPhy = node->phyData[interfaceIndex];
    node->phyData[interfaceIndex]->isSigintInterface = FALSE;

    //Reset the listening and listenable channels and prop data
    //to original values
    //But not if some other interface of 
    //this node is still a sigint interface

    for (int i = 0; i < node->numberChannels; i++) 
    {
        propData = &(node->propData[i]);
        thisPhy->channelListenable[i] = sigint->origChannelListenable[i];
        if (thisPhy->channelListenable[i] == FALSE)
        {
            propData->numPhysListenable--;
        }
        if (sigint->currChannelListening[i] == TRUE)
        {
            sigint->currChannelListening[i] = FALSE;
        }
        //If none of the phys(i.e. interfaces of the node) 
        //"can" listen on this channel, at this time,
        //then remove this node from the channel list
        if (propData->numPhysListenable == 0)
        {
            //propData->limitedInterference = FALSE;
            //PROP_RemoveFromChannelList(node, i);
            PROP_RemoveNodeFromList(node, i);
        }
    }
}

//need to review the path profile stuff here also
//as per what is done in Prop_AddNodeToList
void StartSigintNode(Node *node, AppSigint *sigint)
{
    int interfaceIndex = sigint->interfaceIndex;
    PhyData *thisPhy;
    PropData* propData;
    thisPhy = node->phyData[interfaceIndex];

    if (!node->phyData[interfaceIndex]->isSigintInterface)
    {
        node->phyData[interfaceIndex]->isSigintInterface = TRUE;
        sigint->origChannelListenable = new D_BOOL[node->numberChannels];
        sigint->origChannelListening = new D_BOOL[node->numberChannels];
        sigint->currChannelListening = new D_BOOL[node->numberChannels];
        sigint->numSignalsReceived = new UInt32[node->numberChannels];
        strcpy(sigint->statInterval, "3S");
        if (sigint->printSummary)
        {
            //Set up timer every 3 seconds to print summary statistics
            Message* msg;

            msg = MESSAGE_Alloc(
                node,
                APP_LAYER,
                APP_SIGINT,
                MSG_SIGINT_PrintSummary);
            MESSAGE_SetInstanceId(msg, interfaceIndex);
            MESSAGE_Send(node, msg,
                TIME_ConvertToClock(sigint->statInterval));
        }       

        for (int i = 0; i < node->numberChannels; i++) 
        {
            sigint->numSignalsReceived[i] = 0;
            sigint->origChannelListenable[i] = thisPhy->channelListenable[i];
            sigint->origChannelListening[i] = thisPhy->channelListening[i];
            if (!PHY_CanListenToChannel(node, interfaceIndex, i))
            {
                thisPhy->channelListenable[i] = TRUE;
                propData = &(node->propData[i]);
                int origNumPhysListenable = propData->numPhysListenable;
                if (origNumPhysListenable == 0)
                {
                    /*BOOL wasFound = FALSE;
                    BOOL limitedInterference = FALSE;

                    IO_ReadBoolInstance(
                        node->nodeId,
                        ANY_ADDRESS,
                        node->partitionData->nodeInput,
                        "PROPAGATION-LIMITED-INTERFERENCE",
                        i,
                        TRUE,
                        &wasFound,
                        &limitedInterference);

                    if (limitedInterference) {
                        propData->limitedInterference = TRUE;
                    }
                    else {
                        propData->limitedInterference = FALSE;
                    }*/

                    //PROP_AddToChannelList(node, i);
                    PROP_AddNodeToList(node, i);
                }
                propData->numPhysListenable++;
            }
            sigint->currChannelListening[i] = FALSE;
        }
    }
}
void Sigint_ProcessEvent(Node *node,
                         Message *msg)
{
    if (msg->eventType == MSG_SIGINT_Start)
    {
        char *strInfo;
        AppSigint* sigint;
        SigintInfo* sigInfo;
        strInfo = (char *)MESSAGE_ReturnInfo(msg);
        Node *sigintNode;

        sigintNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash, 
                                                msg->originatingNodeId);
        if (sigintNode == NULL)
        {
            printf("** [SIGINT] ERROR: Node %d does not exist!\n",
                    msg->originatingNodeId);
            MESSAGE_Free(node, msg);
            return;
        }
        Message *stopMsg = Sigint_Initialize(sigintNode, strInfo);
        
        sigInfo = (SigintInfo *) MESSAGE_ReturnInfo(stopMsg);
        ERROR_Assert(sigInfo != NULL, "SigInfo field is NULL!");
        sigint = SigintGetApp(sigintNode, sigInfo->sigintAddress);        
        
        if (sigint != NULL)
        {
            printf("** [SIGINT] ERROR: Another SigInt Instance is "
                    "already running on this node!\n");
            MESSAGE_Free(node, msg);
            MESSAGE_Free(node, stopMsg);
            return;
        }
        sigint = new AppSigint();
        sigint->channelScannerInstance = ChannelScannerStart(
            sigintNode,
            "SIGINT",
            sigInfo->scannerType,
            SigintHandler,
            (void *)sigint);
        if (sigint->channelScannerInstance == -1)
        {
            delete sigint;
            MESSAGE_Free(node, msg);
            MESSAGE_Free(node, stopMsg);
            return;
        }
   
        sigint->sigintAddress = sigInfo->sigintAddress;
        sigint->interfaceIndex = MAPPING_GetInterfaceIndexFromInterfaceAddress(
        sigintNode,
        sigint->sigintAddress);
        sigint->printSummary = sigInfo->printSummary;
        sigint->printVerbose = sigInfo->printVerbose;
        APP_RegisterNewApp(sigintNode, APP_SIGINT, sigint);
        StartSigintNode(sigintNode, sigint);        

        //Send a timer msg to end sigint mode for this node
        MESSAGE_Send(sigintNode, stopMsg, sigInfo->duration);
        MESSAGE_Free(node, msg);        
    }
    else if (msg->eventType == MSG_SIGINT_Stop)
    {
        Node *sigintNode = NULL;        
        SigintInfo* sigInfo;
        sigInfo = (SigintInfo *) MESSAGE_ReturnInfo(msg);
        ERROR_Assert(sigInfo != NULL, "SigInfo field is NULL!");
        if (node->nodeId == msg->originatingNodeId)
        {
            //this is the sigint node so no need to do anything
            sigintNode = node;
        }
        else
        {
            //When running in multiple partitions, 
            //the GUI will send a message to the first node 
            sigintNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash, 
                                                    msg->originatingNodeId);
            if (sigintNode == NULL)
            {
                printf("** [SIGINT] ERROR: Node %d does not exist!\n",
                        msg->originatingNodeId);
                MESSAGE_Free(node, msg);
                return;

            }
        }
        AppSigint *sigint;
        sigint = SigintGetApp(sigintNode, sigInfo->sigintAddress);
        if (sigint == NULL)
        {
            //printf("There is no sigint instance to kill on this node\n");
            MESSAGE_Free(node, msg);
            return;
        }

        AppSigintPrintSummary(node, sigint);

        ChannelScannerStop(
            sigintNode,
            sigint->channelScannerInstance);
        StopSigintNode(sigintNode, sigint);
        APP_UnregisterApp(sigintNode, sigint, false);
        delete sigint;
        MESSAGE_Free(node, msg);
    }
    else if (msg->eventType == MSG_SIGINT_PrintSummary)
    {
        int interfaceIndex = MESSAGE_GetInstanceId(msg);
        NodeAddress sigintAddress = NetworkIpGetInterfaceAddress(node, interfaceIndex);
        AppSigint *sigint;
        sigint = SigintGetApp(node, sigintAddress);
        if (sigint == NULL)
        {
            MESSAGE_Free(node, msg);
            return;
        }
        if (sigint->printSummary)
        {
            AppSigintPrintSummary(node, sigint);

            MESSAGE_Send(node, msg,
                TIME_ConvertToClock(sigint->statInterval));
        }
    }
}

static AppSigint*
SigintGetApp(Node* node, NodeAddress sigintAddr)
{
    AppInfo *appList = node->appData.appPtr;
    AppSigint *sigint;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_SIGINT)
        {
            sigint = (AppSigint *) appList->appDetail;

            if (sigint->sigintAddress == sigintAddr)
            {
                return sigint;
            }
        }
    }

    return NULL;
}


void Sigint_ProcessReceivedSignal(
   Node* node,
   int phyIndex,
   int channelIndex,
   PropRxInfo *propRxInfo)
{
    char clockStr[100];
    TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
    NodeAddress sigintAddress = NetworkIpGetInterfaceAddress(node, phyIndex);
    AppSigint *sigint = SigintGetApp(node, sigintAddress);
    if (sigint == NULL)
    {
        //there is no sigint on thisinterface
        return;
    }
    if (sigint->currChannelListening[channelIndex])
    {
        sigint->numSignalsReceived[channelIndex]++;
        if (sigint->printVerbose)
        {
            printf("** [SIGINT Node %d Report] Detected signal at %sS "
                    "Channel %d (%fHz), From Node %d, "
                    " RxPower=%fdBm, DOA (azimuth=%f, elevation=%f)\n", 
                    node->nodeId,
                    clockStr,
                    channelIndex,
                    PROP_GetChannelFrequency(node, channelIndex),
                    propRxInfo->txNodeId,
                    propRxInfo->rxPower_dBm,
                    propRxInfo->rxDOA.azimuth,
                    propRxInfo->rxDOA.elevation);
        }
    }
    
}


void
AppSigintFinalize(Node *node, AppInfo* appInfo)
{

}

