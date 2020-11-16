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

#ifndef APP_SIGINT_H_
#define APP_SIGINT_H_

#define SIGINT_DEFAULT_STATISTICS_INTERVAL "3S"

/* Specify sigint msg type */
enum
{
    MSG_SIGINT_Start,
    MSG_SIGINT_Stop,
    MSG_SIGINT_PrintSummary,
    MSG_SIGINT_GuiInit
};

/* Structure containing sigint information. */
struct AppSigint
{
    // My information
    NodeAddress sigintAddress;
    int interfaceIndex;
    int channelScannerInstance;
    bool printVerbose;
    bool printSummary; 
    D_BOOL* origChannelListenable;
    D_BOOL* origChannelListening;
    D_BOOL* currChannelListening;
    UInt32 *numSignalsReceived;
    char statInterval[MAX_STRING_LENGTH];
    AppSigint() :sigintAddress(0),
        interfaceIndex(-1),
        channelScannerInstance(-1),
        printVerbose(false), 
        printSummary(false){}
};

struct SigintInfo
{
    NodeAddress sigintAddress;
    int scannerType;
    clocktype duration;
   // clocktype startTime;
   // clocktype endTime;
    bool printVerbose;
    bool printSummary;  
    
};

/*
 * NAME:        StartSigintNode.
 * PURPOSE:     Start the sigint app.
 * PARAMETERS:  node - pointer to the node,   
 *              sigintAddress - interface address of the sigint node          
 * RETURN:      none.
 */
void StartSigintNode(Node *node, AppSigint *sigint);

/*
 * NAME:        StopSigintNode.
 * PURPOSE:     Stop the sigint app.
 * PARAMETERS:  node - pointer to the node,   
 *              sigintAddress - interface address of the sigint node          
 * RETURN:      none.
 */
void StopSigintNode(Node *node, AppSigint *sigint);

/*
 * NAME:        SigintGetApp.
 * PURPOSE:     search for a sigint data structure.
 * PARAMETERS:  node - pointer to the node.
 *              sigintAddr - interface address of the sigint node.
 * RETURN:      the pointer to the sigint data structure,
 *              NULL if nothing found.
 */
static AppSigint*
SigintGetApp(Node* node, NodeAddress sigintAddr);

/*
 * NAME:        Sigint_Initialize.
 * PURPOSE:     Initialize the sigint app.
 * PARAMETERS:  node - pointer to the node,   
 *              cyberInput - input string from the GUI           
 * RETURN:      none.
 */
Message *Sigint_Initialize(
        Node *node,
        const char* cyberInput);

/*
 * NAME:        Sigint_ProcessEvent.
 * PURPOSE:     Process messages for the sigint application.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void Sigint_ProcessEvent(Node *node,
                         Message *msg);

/*
 * NAME:        Sigint_ProcessReceivedSignal.
 * PURPOSE:     Process the signals received in sigint mode
 * PARAMETERS:  node - pointer to the node which received the message.
 *              phyIndex - interface index on which the signal was received
 *              channelIndex - channel on which the signal was received
 *              propRxInfo - propagation Info for receiver
 * RETURN:      none.
 */
void Sigint_ProcessReceivedSignal(
   Node* node,
   int phyIndex,
   int channelIndex,
   PropRxInfo *propRxInfo);

/*
 * NAME:        AppSigintFinalize.
 * PURPOSE:     Collect statistics of a sigint session,
 *              if it is still active at the end of simulation.
 * PARAMETERS:  node - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppSigintFinalize(Node *node, AppInfo* appInfo);

#endif /* APP_SIGINT_H_ */
