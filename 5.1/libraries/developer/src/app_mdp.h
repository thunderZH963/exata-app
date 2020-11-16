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


#ifndef _MDP_APP_H_
#define _MDP_APP_H_


#include "mdp/mdpSession.h"
#include "network.h"
#include "random.h"
#include <vector>


#define MDP_DEFAULT_TTL              8
#define MDP_DEFAULT_TX_RATE          64000
#define MDP_DEFAULT_SEGMENT_SIZE     1024
#define MDP_DEFAULT_BLOCK_SIZE       64
#define MDP_DEFAULT_NPARITY          32
#define MDP_DEFAULT_NUM_AUTO_PARITY  0
#define MDP_DEFAULT_NUM_REPEAT       0
#define MDP_DEFAULT_BUFFER_SIZE      1048576  // i.e. (1024*1024) or 1 Mbyte
#define MDP_DEFAULT_GRTT_ESTIMATE    0.5  // (0.5 * SECOND)
#define MDP_DEFAULT_SEGMENT_POOL_DEPTH  10 // (TBD) what's a good metric for setting this?

#define MDP_DEFAULT_TX_CACHE_COUNT_MIN  8
#define MDP_DEFAULT_TX_CACHE_COUNT_MAX  5000
#define MDP_DEFAULT_TX_CACHE_SIZE_MAX   (8*1024*1024)

#define MDP_DEFAULT_BASE_OBJECT_ID   1

#define MDP_DEFAULT_LOOPBACK_ENABLED         FALSE
#define MDP_DEFAULT_EMCON_ENABLED            FALSE
#define MDP_DEFAULT_REPORT_MESSAGES_ENABLED  FALSE
#define MDP_DEFAULT_FLOW_CONTROL_ENABLED     FALSE
#define MDP_DEFAULT_UNICAST_NACK_ENABLED     FALSE
#define MDP_DEFAULT_MULTICAST_ACK_ENABLED    FALSE
#define MDP_DEFAULT_POSITIVE_ACK_WITH_REPORT FALSE
#define MDP_DEFAULT_STREAM_INTEGRITY_ENABLED TRUE
#define MDP_DEFAULT_ARCHIVE_MODE_ENABLED     FALSE
#define MDP_DEFAULT_ARCHIVE_PATH             NULL // NULL refer to current dir

#define MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MIN  0 // for unbounded operation
#define MDP_DEFAULT_FLOW_CONTROL_TX_RATE_MAX  0 // for unbounded operation

#define MDP_DEFAULT_GRTT_REQ_INTERVAL_MIN     1
#define MDP_DEFAULT_GRTT_REQ_INTERVAL_MAX     40

#define MDP_REPORT_INTERVAL                   90

#define MDP_DEFAULT_TX_HOLD_QUEUE_EXPIRY_INERVAL  60 // in seconds
#define MDP_DEFAULT_SESSION_CLOSE_INTERVAL        60 // in seconds

// robustness factor
#define MDP_DEFAULT_ROBUSTNESS  20

// temp file handling when archive mode is disabled
// in case of File objects only
#define MDP_DEFAULT_FILE_TEMP_DELETION_ENABLED TRUE
#define MDP_DEFAULT_FILE_CACHE_COUNT_MIN  8
#define MDP_DEFAULT_FILE_CACHE_COUNT_MAX  5000
#define MDP_DEFAULT_FILE_CACHE_SIZE_MAX   (8*1024*1024)

/* Mdp type definitions */

typedef const void* MdpInstanceHandle;
typedef const void* MdpSessionHandle;
typedef const void* MdpNodeHandle;
typedef const void* MdpObjectHandle;

const MdpInstanceHandle MDP_NULL_INSTANCE = ((MdpInstanceHandle)0);
const MdpSessionHandle MDP_NULL_SESSION = ((MdpSessionHandle)0);
const MdpObjectHandle MDP_NULL_OBJECT = ((MdpObjectHandle)0);

const MdpNodeId MDP_NULL_NODE = ((MdpNodeId)0);



class MdpCommonParameters
{
public:
    // methods
    MdpCommonParameters()
    {
        ackList = new std::vector <UInt32>(0);
        archivePath = NULL;
    }
    ~MdpCommonParameters()
    {
        if (archivePath)
        {
            MEM_free (archivePath);
        }
        ackList->erase(ackList->begin(), ackList->end());
        delete ackList;
        ackList = NULL;
        archivePath = NULL;
    }
    // members
    UInt32 txBufferSize;
    UInt32 rxBufferSize;
    UInt32 baseObjectId;
    UInt32 robustFactor;
    UInt64 txCacheCountMin;
    UInt64 txCacheCountMax;
    UInt64 txCacheSizeMax;
    double initialGrtt;
    Int32 segmentSize;
    Int32 txRate;
    Int32 ttlCount;
    Int32 bufferSize;
    Int32 segmentPoolDepth;
    Int32 flowControlTxRateMin;
    Int32 flowControlTxRateMax;
    std::vector <UInt32>* ackList;
    UInt8 blockSize;
    UInt8 numParity;
    UInt8 numAutoParity;
    BOOL streamIntegrityEnabled;
    BOOL multicastAckEnabled;
    BOOL positiveAckEnabled;
    BOOL unicastNackEnabled;
    BOOL flowControlEnabled;
    BOOL reportMsgEnabled;
    BOOL emconEnabled;
    BOOL loopbackEnabled;
    TosType tos;
    BOOL  archiveModeEnabled;
    char* archivePath;
};
// MdpCommonParameters;



struct MdpPersistentInfo
{
    Address clientAddr;
    Address remoteAddr;
    Int32 uniqueId;
    Int32 virtualSize;
    UInt16 sourcePort;
    UInt16 destPort;
    AppType appType;
};


struct MdpPersistentObjectInfo
{
    MdpObjectType objectType;
    Int32 objectInfoSize;
    //char* objectInfo;
};


struct MdpSessionInfo
{
    Address localAddr;
    Address remoteAddr;
    Int32 uniqueId;
};

/*
 * Data item structure used for unique tuple entry
 */

struct MdpUniqueTuple
{
    Address sourceAddr;
    Address destAddr;
    MdpSession* session;
};

struct ltcompare_mdpMap1
{
    bool operator () (Int32 uniqueId1,
        Int32 uniqueId2) const
    {
        return (uniqueId1 < uniqueId2);
    }
};


struct ltcompare_mdpMap2
{
    bool operator () (UInt16 port1,
        UInt16 port2) const
    {
        return (port1 < port2);
    }
};



/*
 * Data item structure used by multicast mdp
 */

struct MdpData
{
    MdpCommonParameters* mdpCommonData;
    std::multimap<Int32, MdpUniqueTuple*, ltcompare_mdpMap1>*
                                                     multimap_MdpSessionList;
    Int32 totalSession;
    Int32 maxAppLines;
    Int32 sourcePort;
    RandomSeed seed;              /* seed for random number generator */
    BOOL mdpStats;
    char type;
    const void* mdpSessionHandle;
    class MdpSessionMgr* sessionManager;
    std::vector <UInt16>* receivePortList;
    // below vector is added for EXata node to handle unicast client replys
    std::vector <std::pair<UInt16, NodeAddress> >* outPortList;
    std::multimap<UInt16, MdpSession*, ltcompare_mdpMap2>*
                                               multimap_MdpSessionListByPort;
    // below variable is used to cache entries for all temp files
    // created/received by the MDP clients when archive mode is disabled.
    // It is used to ensure that all such files are getting deleted at
    // the end of simulation.
    MdpFileCache* temp_file_cache;
};



//--------------------------------------------------------------------------
// NAME         : MdpInit()
// PURPOSE      : Initializes MDP model.
// PARAMETERS       :
//          node    : A pointer to Node
//        nodeInput : A pointer to NodeInput
//
// RETURN VALUE : None.
//--------------------------------------------------------------------------
void MdpInit(Node* node, const NodeInput* nodeInput);



//--------------------------------------------------------------------------
// NAME         : MdpNewSessionInit()
// PURPOSE      : Initializes MDP session for the application.
// PARAMETERS       :
//          node    : A pointer to Node
//        localAddr : Local address
//       remoteAddr : Destination address
//         uniqueId : Unique id for session
//       sourcePort : Source port for application
//          appType : AppType of application
//    mdpCommonData : Pointer to struct MdpCommonParameters
//
// RETURN VALUE : MdpSession.
//--------------------------------------------------------------------------
MdpSession* MdpNewSessionInit(Node* node,
                              Address localAddr,
                              Address remoteAddr,
                              Int32 uniqueId,
                              Int32 sourcePort,
                              AppType appType,
                              MdpCommonParameters* mdpCommonData);

//--------------------------------------------------------------------------
// NAME         : MdpCreateOpenNewMdpSessionForNode()
// PURPOSE      : Create & open new MDP session for the new app MDP server
//                packets received from both simulation and emulation nodes.
// PARAMETERS       :
//          node    : A pointer to Node
//          msg     : Pointer to Message
// RETURN VALUE : MdpSession.
//--------------------------------------------------------------------------
MdpSession* MdpCreateOpenNewMdpSessionForNode(Node* node,
                                              Message* msg);

/*
 * NAME:        MDPFinalize.
 * PURPOSE:     Collect statistics of a MDP node for the sessions.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void MdpFinalize(Node *node);

/*
 * NAME:        GetMdpSessionHandleFromSessionMgr.
 * PURPOSE:     Reterving session list available at node level
 * PARAMETERS:  node - pointer to the node.
 *              sessionMgr - pointer to the class MdpSessionMgr.
 * RETURN:      pointer to first MdpSession in the list else NULL.
 */
MdpSession*
GetMdpSessionHandleFromSessionMgr(Node* node, MdpSessionMgr* sessionMgr);

/*
 * NAME:        MdpProcessEvent.
 * PURPOSE:     Models the behaviour of Mdp on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              msg - message received by the layer
 * RETURN:      none.
 */
void MdpProcessEvent(Node *node, Message *msg);


/*
 * NAME:        MdpInitOptParamWithDefaultValues.
 * PURPOSE:     Init common parameters with default value
 * PARAMETERS:  node - pointer to the node which received the message.
 *              mdpCommonData - pointer to struct MdpCommonParameters
 *              nodeInput - A pointer to NodeInput with default value NULL
 * RETURN:      none.
 */
void MdpInitOptParamWithDefaultValues(Node* node,
                                     MdpCommonParameters* mdpCommonData,
                                     const NodeInput* nodeInput = NULL);



/*
 * NAME:        MdpInitializeOptionalParameters.
 * PURPOSE:     Init parameters with user defined value
 * PARAMETERS:  node - pointer to the node which received the message.
 *              optionTokens - pointer to configuration string
 *              mdpCommonData - pointer to struct MdpCommonParameters
 * RETURN:      none.
 */
void MdpInitializeOptionalParameters(Node* node,
                                     char* optionTokens,
                                     MdpCommonParameters* mdpCommonData);


/*
 * NAME:        MdpLayerInit.
 * PURPOSE:     Init MDP layer for the called unicast/multicast applications
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientAddr - specify address of the sender node
 *                           i.e. local address.
 *              serverAddr - specify address of the receiver
 *                           i.e. destination address.
 *              sourcePort - source port of the sender.
 *              appType - application type for sender, for which MDP layer
 *                           is going to be initialize.
 *              isProfileNameSet - TRUE is MDP profile is defined.
 *                           Default value is FALSE.
 *              profileName - the profile name if "isProfileNameSet" is TRUE.
 *                           Default value is NULL.
 *              uniqueId - unique id for MDP session. Default value is -1.
 *              nodeInput - pointer to NodeInput. Default value is NULL.
 *              destPort - destination port of the receiver.
 *              destIsUnicast - whether dest address is unicast address.
 *                           Default value is FALSE.
 * RETURN:      void.
 */
void MdpLayerInit(Node* node,
                Address clientAddr,
                Address serverAddr,
                Int32 sourcePort,
                AppType appType,
                BOOL isProfileNameSet = FALSE,
                char* profileName = NULL,
                Int32 uniqueId = -1,
                const NodeInput* nodeInput = NULL,
                Int32 destPort = -1,
                BOOL destIsUnicast = FALSE);


/*
 * NAME:        MdpLayerInitForAppForward.
 * PURPOSE:     Init MDP layer for APP_FORWARD
 * PARAMETERS:  node - pointer to the node which received the message.
 *              clientAddr - local address
 *              serverAddr - destination address
 *              sourcePort - sender source port
 *              appType - AppType for sender
 *              uniqueId - APP_FORWARD unique id with respect to application.
 * RETURN:      none.
 */
void MdpLayerInitForAppForward(Node* node,
                  Address clientAddr,
                  Address serverAddr,
                  Int32 sourcePort,
                  AppType appType,
                  Int32 uniqueId);

/*
 * NAME:        MdpReadProfileFromApp.
 * PURPOSE:     Return TRUE if MDP profile defined in .app file found.
 * PARAMETERS:  node - pointer to the node.
 *              uniqueId - Mdp unique id with respect to application.
 *              mdpCommonData - pointer to MdpCommonParameters
 * RETURN:      BOOL.
 */
BOOL MdpReadProfileFromApp(Node* node,
                           Int32 uniqueId,
                           MdpCommonParameters* mdpCommonData);


/*
 * NAME:        MdpSendDataToApp.
 * PURPOSE:     Send received data objects by MDP to application receiver.
 *              In case of file object it sends notification.
 * PARAMETERS:  node - pointer to the node which received the message.
 *              info - UdpToAppRecv info of the received Message
 *              data - packet data
 *              objectSize - complete object size
 *              actualObjectSize - object size without virtual payload
 *              theMsgPtr - pointer to the Message
 *              objectType - Mdp object type data or file.
 *              objectInfo - Mdp object info if any
 *              objectInfoSize - Mdp object info size
 *              theSession - Mdp Session pointer
 * RETURN:      none.
 */
void MdpSendDataToApp(Node* node,
                   char* infoUdpToAppRecv,
                   char* data,
                   AppType appType,
                   Int32 objectSize,
                   Int32 actualObjectSize,
                   Message* theMsgPtr = NULL,
                   MdpObjectType objectType = MDP_OBJECT_INVALID,
                   char* objectInfo = NULL,
                   Int32 objectInfoSize = 0,
                   MdpSession* theSession = NULL);


/*
 * NAME:        MdpFindSessionInList.
 * PURPOSE:     Find session with respect to unique tuple entry
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourceAddr - sender address
 *              remoteAddr - dest address
 *              uniqueId - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInList(Node* node,
                                 Address sourceAddr,
                                 Address remoteAddr,
                                 Int32 uniqueId);


/*
 * NAME:        MdpFindSessionInListForEXataMulticastPort.
 * PURPOSE:     Find session with respect to multicast address on exata port
 * PARAMETERS:  node - pointer to the node which received the message.
 *              multicastAddr - dest address
 *              exataPort - exata port
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInListForEXataMulticastPort(Node* node,
                                                      Address multicastAddr,
                                                      Int32 exataPort);


/*
 * NAME:        MdpFindSessionInPortMapList.
 * PURPOSE:     Find first session entry with respect to local address
 *              and sourcePort of the application
 * PARAMETERS:  node - pointer to the node which received the message.
 *              localAddr - node local address
 *              sourcePort - source port of the application
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpFindSessionInPortMapList(Node* node,
                                 Address localAddr,
                                 UInt16 sourcePort);


/*
 * NAME:        MdpAddSessionInList.
 * PURPOSE:     Add unique tuple entry with respect to new session
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourceAddr - sender address
 *              remoteAddr - dest address
 *              uniqueId - unique id assigned
 *              newSession - new session
 * RETURN:      none.
 */
void MdpAddSessionInList(Node* node,
                         Address sourceAddr,
                         Address remoteAddr,
                         Int32 uniqueId,
                         MdpSession* newSession);


/*
 * NAME:        MdpAddSessionInPortMapList.
 * PURPOSE:     Add session entry with respect to port number in portMap, if
 *              not exist
 * PARAMETERS:  node - pointer to the node which received the message.
 *              sourcePort - sourcePort of the application
 *              newSession - new session
 * RETURN:      none.
 */
void MdpAddSessionInPortMapList(Node* node,
                         UInt16 sourcePort,
                         MdpSession* newSession);


/*
 * NAME:        MdpPersistentInfoForSessionInList.
 * PURPOSE:     Filling persistent info wrt existing session in list
 * PARAMETERS:  node - pointer to the node which received the message.
 *              mdpInfo - pointer to MdpPersistentInfo
 *              session - existing session
 * RETURN:      none.
 */
void MdpPersistentInfoForSessionInList(Node* node,
                                       MdpPersistentInfo* mdpInfo,
                                       MdpSession* session);


/*
 * NAME:        MdpAddSessionStatsCount.
 * PURPOSE:     Add stats for the session
 * PARAMETERS:  session - pointer to existing session.
 *              totalCommonStats - pointer to MdpCommonStats having
 *              aggregate info
 *              commonStats - pointer to MdpCommonStats of session
 *              totalClientStat - pointer to MdpClientStats having
 *              aggregate info
 *              clientStat - pointer to MdpClientStats of session
 * RETURN:      none.
 */
void MdpAddSessionStatsCount(MdpSession* session,
                             MdpCommonStats* totalCommonStats,
                             MdpCommonStats* commonStats,
                             MdpClientStats* totalClientStat = NULL,
                             MdpClientStats* clientStat = NULL);

/*
 * NAME:        MdpGetProtoAddress.
 * PURPOSE:     Conversion function from Address to MdpProtoAddress
 * PARAMETERS:  addr - address.
 *              port - source port
 * RETURN:      MdpProtoAddress.
 */
class MdpProtoAddress MdpGetProtoAddress(Address addr, UInt16 port);

/*
 * NAME:        MdpGetAppTypeForServer.
 * PURPOSE:     finding app type for receiver node of the application
 * PARAMETERS:  appType - app type for sender node
 * RETURN:      AppType.
 */
AppType MdpGetAppTypeForServer(AppType appType);


/*
 * NAME:        MdpGetAppTypeForClient.
 * PURPOSE:     finding app type for sender node of the application
 * PARAMETERS:  appType - app type for receiver node
 * RETURN:      AppType.
 */
AppType MdpGetAppTypeForClient(AppType appType);

/*
 * FUNCTION:   MdpIsExataIncomingPort
 * PURPOSE:    Used to verify whether port is MDP EXata incoming port
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be verify.
 * RETURN:     BOOL.
 */
BOOL MdpIsExataIncomingPort(Node* node,
                            UInt16 port);


/*
 * FUNCTION:   MdpAddPortInExataIncomingPortList
 * PURPOSE:    Used to add port in MDP EXata incoming port list if not exist
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be added.
 * RETURN:     BOOL.
 */
BOOL MdpAddPortInExataIncomingPortList(Node* node,
                                       UInt16 port);


/*
 * FUNCTION:   MdpAddPortInExataOutPortList
 * PURPOSE:    Used to add port and ipaddress pair in MDP EXata out port list
 *             if not exist for EXata node. This list is required to
 *             handle ACK, NACK, REPORT unicast reply
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be added.
 *             ipAddress - IP address that needs to be verify
 * RETURN:     BOOL.
 */
BOOL MdpAddPortInExataOutPortList(Node* node,
                                  UInt16 port,
                                  NodeAddress ipAddress);



/*
 * FUNCTION:   MdpIsExataPortInOutPortList
 * PURPOSE:    Used to verify whether port and ipAddress pair is in MDP
 *             EXata Out portlist
 * PARAMETERS: node - node pointer.
 *             port - port id that needs to be verify.
 *             ipAddress - IP address that needs to be verify
 * RETURN:     BOOL.
 */
BOOL MdpIsExataPortInOutPortList(Node* node,
                                 UInt16 port,
                                 NodeAddress ipAddress);


/*
 * FUNCTION:   MdpIsServerPacket
 * PURPOSE:    Used to verify whether the packet is from MDP sender
 * PARAMETERS: node - node pointer.
 *             msg - message pointer.
 * RETURN:     BOOL.
 */
BOOL MdpIsServerPacket(Node* node, Message* msg);


/*
 * FUNCTION:   MdpSwapIncomingPacketForNtoh
 * PURPOSE:    Used to do ntoh for MDP external incoming packets which
 *             are escaped through mdp_interface.cpp
 * PARAMETERS: node - node pointer.
 *             msg - message pointer.
 * RETURN:     BOOL.
 */
void MdpSwapIncomingPacketForNtoh(Node* node, Message* msg);




/*
 * FUNCTION:   MdpGetSession
 * PURPOSE:    Used to verify whether MDP session exist for the
 *             desire localAddr, remoteAddr, and uniqueId. If
 *             found then return session pointer
 * PARAMETERS: node - node pointer.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP.
 * RETURN:     MdpSession*.
*/
MdpSession* MdpGetSession(
    Node* node,
    Address localAddr,
    Address remoteAddr,
    Int32 uniqueId);




/*
 * NAME:        MdpGetSessionForEXataPort
 * PURPOSE:     Find session with respect to unique tuple entry for EXata
 *              unicast incoming port
 * PARAMETERS:  node - pointer to the node which received the message.
 *              localAddr - address of the sender.
 *              remoteAddr - address of the receiver.
 *              exataPort - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpGetSessionForEXataPort(
    Node* node,
    Address localAddr,
    Address remoteAddr,
    Int32 exataPort);




/*
 * NAME:        MdpGetSessionForEXataPortOnMulticast
 * PURPOSE:     Find session with respect to unique tuple entry for EXata
 *              incoming port for multicast traffic
 * PARAMETERS:  node - pointer to the node which received the message.
 *              multicastAddr - multicast address
 *              exataPort - unique id assigned
 * RETURN:      pointer to found MdpSession in the list else NULL.
 */
MdpSession* MdpGetSessionForEXataPortOnMulticast(
     Node* node,
     Address multicastAddr,
     Int32 exataPort);


/*
 * FUNCTION:   MdpLayerInitForOtherPartitionNodes
 * PURPOSE:    Init the MDP layer for the member nodes in the partition in
.*             which the calling node exists.
 * PARAMETERS: node - node that received the message.
 *             nodeInput - specify nodeinput. Default value is NULL.
 *             destAddr - specify the multicast destination address.
 *                      For unicast it is considered as NULL (Default value).
 *             isUnicast - specify whether application is unicast/multicast.
 *                         Default value is FALSE.
 * RETURN:     void.
 */
void MdpLayerInitForOtherPartitionNodes(
    Node* firstNode,
    const NodeInput* nodeInput,
    Address* destAddr = NULL,
    BOOL isUnicast = FALSE);



/*
 * FUNCTION:   MdpQueueDataObject
 * PURPOSE:    Used to queue MDP data object by upper application.
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP. For Exata this
 *                        will be considered as destport also
 *             itemSize - specify the complete item size
 *                        i.e. actual size + virtual size.
 *             payload - specify the payload for the item.
 *             virtualSize - specify the virtual size of the item
 *                           in the received message.
 *             theMsg - pointer to the received message.
 *             isFromAppForward - TRUE only when packet is queued from
 *                         APP_FORWARD application. Default value is FALSE.
 *             sourcePort - sending port of the application.
 *             dataObjectInfo - specify the data object info if any.
 *             dataInfosize - specify the data info size
 * RETURN:     void.
 */
void MdpQueueDataObject(
    Node* node,
    Address localAddr,
    Address remoteAddr,
    Int32 uniqueId,
    Int32 itemSize,
    const char* payload,
    Int32 virtualSize,
    Message* theMsg,
    BOOL isFromAppForward,
    UInt16 sourcePort,
    const char* dataObjectInfo = NULL,
    UInt16 dataInfosize = 0);



/*
 * FUNCTION:   MdpQueueFileObject
 * PURPOSE:    Used to queue MDP file object by the upper applications.
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             thePath - specify the path for the file object.
 *             fileName - specify the name of the file.
 *             uniqueId - specify unique id for MDP.
 *             sourcePort - specify sourceport of the application.
 *             theMsg - pointer to the received message.
 *             isFromAppForward - TRUE only when packet is queued from
 *                         APP_FORWARD application. Default value is FALSE.
 * RETURN:     void.
 */
void MdpQueueFileObject(
    Node* node,
    Address localAddr,
    Address remoteAddr,
    const char* thePath,
    char* fileName,
    Int32 uniqueId,
    UInt16 sourcePort,
    Message* theMsg = NULL,
    BOOL isFromAppForward = FALSE);



/*
 * FUNCTION:   MdpNotifyLastDataObject
 * PURPOSE:    Used to notify MDP that last data object is sent
 * PARAMETERS: node - node that received the message.
 *             localAddr - specify address of the sender node.
 *             remoteAddr - specify address of the receiver.
 *             uniqueId - specify unique id for MDP.
 * RETURN:     void.
 */
void MdpNotifyLastDataObject(
    Node* node,
    Address localAddr,
    Address remoteAddr,
    Int32 uniqueId);


#endif /* _MDP_APP_H_ */
