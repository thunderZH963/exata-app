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

#ifndef MCBR_APP_H
#define MCBR_APP_H

#include "types.h"
#include "stats_app.h"

#ifdef ADDON_DB
class SequenceNumber;
#endif // ADDON_DB

/*
 * Data item structure used by multicast cbr.
 */
typedef
struct struct_app_mcbr_data
{
    Int32 sourcePort;
    char type;
    Int32 seqNo;
    clocktype txTime;
    BOOL isMdpEnabled;
}
MCbrData;

/* Structure containing mcbr client information. */

typedef
struct struct_app_mcbr_client_str
{
    Address localAddr;
    Address remoteAddr;
    clocktype interval;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastSent;
    clocktype endTime;
    BOOL sessionIsClosed;
    Int32 itemsToSend;
    Int32 itemSize;
    Int32 sourcePort;
    Int32 seqNo;
    Int32 uniqueId;
    std::string* applicationName;
#ifdef ADDON_DB
    Int32 sessionId;
    Int32 receiverId;
#endif
    Int32 mdpUniqueId;
    BOOL isMdpEnabled;
#ifdef ADDON_NGCNMS
    Message* lastTimer;
#endif

    TosType tos;
    STAT_AppStatistics* stats;

    // Dynamic address
    Int16 clientInterfaceIndex; // client interface index for this app 
                                // session
}
AppDataMCbrClient;

/* Structure containing mcbr related information. */

typedef
struct struct_app_mcbr_server_str
{
    Address localAddr;
    Address remoteAddr;
    int sourcePort;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastReceived;
    BOOL sessionIsClosed;
    Int32 seqNo;
    Int32 uniqueId;
    STAT_AppStatistics* stats;
#ifdef ADDON_DB
    int sessionId;
    int sessionInitiator;
    int hopCount;
    SequenceNumber *seqNumCache;
#endif
}
AppDataMCbrServer;

/*
 * NAME:        AppLayerMCbrClient.
 * PURPOSE:     Models the behaviour of MCbrClient Client on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerMCbrClient(Node *nodePtr, Message *msg);

/*
 * NAME:        AppMCbrClientInit.
 * PURPOSE:     Initialize a MCbrClient session.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              serverAddr - address of the server,
 *              itemsToSend - number of items to send,
 *              itemSize - size of each packet,
 *              interval - interval of packet transmission rate.
 *              startTime - time until the session starts.
 *              endTime - time until the session end.
 *              srcString - source name
 *              destString - destination name
 *              tos - the contents for the type of service field.
 *              isMdpEnabled - true if MDP is enabled by user.
 *              isProfileNameSet - true if profile name is provided by user.
 *              profileName - mdp profile name.
 *              uniqueId - mdp session unique id.
 *              nodeInput - nodeInput for config file.
 * RETURN:      none.
 */
void
AppMCbrClientInit(
    Node *nodePtr,
    Address clientAddr,
    Address serverAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype interval,
    clocktype startTime,
    clocktype endTime,
    const char* srcString,
    const char* destString,
    unsigned tos,
    char* appName,
    BOOL isMdpEnabled = FALSE,
    BOOL isProfileNameSet = FALSE,
    char* profileName = NULL,
    Int32 uniqueId = -1,
    const NodeInput* nodeInput = NULL);

/*
 * NAME:        AppMCbrClientPrintStats.
 * PURPOSE:     Prints statistics of a MCbrClient session.
 * PARAMETERS:  nodePtr - pointer to the this node.
 *              clientPtr - pointer to the mcbr client data structure.
 * RETURN:      none.
 */
void
AppMCbrClientPrintStats(Node *nodePtr, AppDataMCbrClient *clientPtr);

/*
 * NAME:        AppMCbrClientFinalize.
 * PURPOSE:     Collect statistics of a MCbrClient session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppMCbrClientFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppMCbrClientGetMCbrClient.
 * PURPOSE:     search for a mcbr client data structure.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              sourcePort - connection ID of the mcbr client.
 * RETURN:      the pointer to the mcbr client data structure,
 *              NULL if nothing found.
 */
AppDataMCbrClient * //inline//
AppMCbrClientGetMCbrClient(Node *nodePtr, int sourcePort);

/*
 * NAME:        AppMCbrClientNewMCbrClient.
 * PURPOSE:     create a new mcbr client data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              remoteAddr - remote address.
 *              itemsToSend - number of items to send,
 *              itemSize - size of data packets.
 *              interval - interdeparture time of packets.
 *              startTime - time when session is started.
 *              endTime - time when session is ended.
 * RETURN:      the pointer to the created mcbr client data structure,
 *              NULL if no data structure allocated.
 */
AppDataMCbrClient * //inline//
AppMCbrClientNewMCbrClient(
    Node *nodePtr,
    Address localAddr,
    Address remoteAddr,
    Int32 itemsToSend,
    Int32 itemSize,
    clocktype interval,
    clocktype startTime,
    clocktype endTime,
    TosType tos,
    char* appName);

/*
 * NAME:        AppMCbrClientScheduleNextPkt.
 * PURPOSE:     schedule the next packet the client will send.  If next packet
 *              won't arrive until the finish deadline, schedule a close.
 * PARAMETERS:  nodePtr - pointer to the node,
 *              clientPtr - pointer to the mcbr client data structure.
 * RETRUN:      none.
 */
void //inline//
AppMCbrClientScheduleNextPkt(Node *nodePtr, AppDataMCbrClient *clientPtr);



/*
 * NAME:        AppLayerMCbrServer.
 * PURPOSE:     Models the behaviour of MCbrServer Server on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  nodePtr - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerMCbrServer(Node *nodePtr, Message *msg);

/*
 * NAME:        AppMCbrServerInit.
 * PURPOSE:     listen on MCbrServer server port.
 * PARAMETERS:  nodePtr - pointer to the node.
 * RETURN:      none.
 */
void
AppMCbrServerInit(Node *nodePtr);

/*
 * NAME:        AppMCbrServerPrintStats.
 * PURPOSE:     Prints statistics of a MCbrServer session.
 * PARAMETERS:  nodePtr - pointer to this node.
 *              serverPtr - pointer to the mcbr server data structure.
 * RETURN:      none.
 */
void
AppMCbrServerPrintStats(Node *nodePtr, AppDataMCbrServer *serverPtr);

/*
 * NAME:        AppMCbrServerFinalize.
 * PURPOSE:     Collect statistics of a MCbrServer session.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              appInfo - pointer to the application info data structure.
 * RETURN:      none.
 */
void
AppMCbrServerFinalize(Node *nodePtr, AppInfo* appInfo);

/*
 * NAME:        AppMCbrServerGetMCbrServer.
 * PURPOSE:     search for a mcbr server data structure.
 * PARAMETERS:  nodePtr - mcbr server.
 *              sourcePort - sourcePort of mcbr client/server pair.
 *              remoteAddr - mcbr client sending the data.
 * RETURN:      the pointer to the mcbr server data structure,
 *              NULL if nothing found.
 */
AppDataMCbrServer * //inline//
AppMCbrServerGetMCbrServer(
    Node *nodePtr,
    Address remoteAddr,
    int sourcePort);

/*
 * NAME:        AppMCbrServerNewMCbrServer.
 * PURPOSE:     create a new mcbr server data structure, place it
 *              at the beginning of the application list.
 * PARAMETERS:  nodePtr - pointer to the node.
 *              localAddr - local address.
 *              remoteAddr - remote address.
 *              sourcePort - sourcePort of mcbr client/server pair.
 * RETRUN:      the pointer to the created mcbr server data structure,
 *              NULL if no data structure allocated.
 */
AppDataMCbrServer * //inline//
AppMCbrServerNewMCbrServer(
    Node *nodePtr,
    Address localAddr,
    Address remoteAddr,
    int sourcePort);

#ifdef ADDON_NGCNMS
void
AppMCbrClientReInit(Node* node, Address sourceAddr);

void AppMCbrReset(Node* node);

#endif

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             :AppMcbrClientAddAddressInformation.
// PURPOSE              :store client interface index,to get the 
//                       correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataMCbrClient* : pointer to CBR client data
// RETRUN               : void
//---------------------------------------------------------------------------
void
AppMcbrClientAddAddressInformation(Node* node,
                                  AppDataMCbrClient* clientPtr);

//---------------------------------------------------------------------------
// FUNCTION             :AppMcbrClientGetSessionAddressState.
// PURPOSE              :get the current address sate of client
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataMCbrClient* : pointer to CBR client data
// RETRUN:     
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if client is having valid address
//                        ADDRESS_INVALID : if client is in 
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppMcbrClientGetSessionAddressState(Node* node,
                                   AppDataMCbrClient* clientPtr);


#endif /* _MCBR_APP_H_ */
