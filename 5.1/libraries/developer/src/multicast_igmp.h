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

#ifndef IGMP_H
#define IGMP_H

 // Each multicast routing protocol should provide a function that would
 // handle the event when an IGMP router receive a Group Membership Report
 // for a new group or an existing group leaves the subnet. IGMP will call
 // this function through a function pointer when a new group membership is
 // created or an existing group leaves. This function pointer will
 // initializes at beginning of simulation within Initialization function of
 // different multicast routing protocol.
 //
 // IgmpSetMulticastProtocolInfo() will set this pointer

typedef enum
{
    LOCAL_MEMBER_JOIN_GROUP,
    LOCAL_MEMBER_LEAVE_GROUP
} LocalGroupMembershipEventType;


typedef
void (*MulticastProtocolType) (
        Node *node,
        NodeAddress groupAddr,
        int interfaceId,
        LocalGroupMembershipEventType event);


struct IgmpRouter;

typedef
clocktype (*QueryDelayFuncType) (
    struct IgmpRouter* igmpRouter,
    Message* msg);


// TBD: Should be removed after mospf.* removes GROUP_ID with NodeAddress
typedef NodeAddress  GROUP_ID;

// all-systems-group (224.0.0.1)
#define IGMP_ALL_SYSTEMS_GROUP_ADDR      0xE0000001

// all-routers-group for IGMPv2(224.0.0.2)
#define IGMP_V2_ALL_ROUTERS_GROUP_ADDR   0xE0000002

// all-routers-group for IGMPv3 (224.0.0.22)
#define IGMP_V3_ALL_ROUTERS_GROUP_ADDR   0xE0000016

// Default value of unsolicited report count
#define IGMP_UNSOLICITED_REPORT_COUNT       2

#define IGMP_QUERY_RESPONSE_SCALE_FACTOR    10

#define IGMP_INVALID_TIMER_VAL                 -1

//IGMPv3 Router states and events to be handled.
#define IGMPV3_ROUTER_STATES                 2
#define IGMPV3_ROUTER_EVENTS                7

// IGMPv3 fixed packet sizes
#define IGMPV3_INFO_FIXED_SIZE              17
#define IGMPV3_REPORT_FIXED_SIZE            8
#define IGMPV2_QUERY_FIXED_SIZE             8
#define IGMPV3_QUERY_FIXED_SIZE             12

// Various timer values
#define IGMP_ROBUSTNESS_VAR                   2
#define IGMP_QUERY_INTERVAL                   ( 125 * SECOND )
#define IGMP_QUERY_RESPONSE_INTERVAL          100
#define IGMP_LAST_MEMBER_QUERY_INTERVAL       10
#define IGMP_UNSOLICITED_REPORT_INTERVAL      ( 10 * SECOND )
#define IGMP_V3_UNSOLICITED_REPORT_INTERVAL   ( 1 * SECOND )
#define IGMP_MAX_RESPONSE_TIME                10.0
#define IGMP_STARTUP_QUERY_INTERVAL           ( 0.25 * IGMP_QUERY_INTERVAL )
#define IGMP_OTHER_QUERIER_PRESENT_INTERVAL   ((IGMP_ROBUSTNESS_VAR \
        *IGMP_QUERY_INTERVAL )+( 0.5 * IGMP_QUERY_RESPONSE_INTERVAL))
#define IGMP_STARTUP_QUERY_COUNT              IGMP_ROBUSTNESS_VAR
#define IGMP_LAST_MEMBER_QUERY_COUNT          IGMP_ROBUSTNESS_VAR
#define IGMP_GROUP_MEMBERSHIP_INTERVAL        ((IGMP_ROBUSTNESS_VAR \
        *IGMP_QUERY_INTERVAL) + IGMP_QUERY_RESPONSE_INTERVAL)


// Igmp message types
#define IGMP_QUERY_MSG                      0x11
#define IGMP_MEMBERSHIP_REPORT_MSG          0x16
#define IGMP_LEAVE_GROUP_MSG                0x17
#define IGMP_V3_MEMBERSHIP_REPORT_MSG       0x22


// DVMRP Packet
#define IGMP_DVMRP                          0x13

// Record types to be sent in IGMPv3 Report packet
#define MODE_IS_INCLUDE                     1
#define MODE_IS_EXCLUDE                     2
#define CHANGE_TO_IN                        3
#define CHANGE_TO_EX                        4
#define ALLOW_NEW_SRC                       5
#define BLOCK_OLD_SRC                       6

// IGMP version enumerations
enum IgmpVersion{

IGMP_V2 = 2,
IGMP_V3

};

// Node type enumerations
enum IgmpNodeType{

    IGMP_HOST = 0,
    IGMP_ROUTER,
    IGMP_PROXY,

    // is not used, just kept in place of the default type
    IGMP_NORMAL_NODE
};

// State type enumerations for Igmp
enum IgmpStateType{
    IGMP_HOST_NON_MEMBER = 0,
    IGMP_HOST_DELAYING_MEMBER,
    IGMP_HOST_IDLE_MEMBER,

    IGMP_QUERIER,
    IGMP_NON_QUERIER,

    IGMP_ROUTER_NO_MEMBERS,
    IGMP_ROUTER_MEMBERS,
    IGMP_ROUTER_CHECKING_MEMBERSHIP,

    // any new state definitions MUST BE added before this
    IGMP_DEFAULT
};


// Type enumerations for Igmp host filter mode types
enum Igmpv3FilterModeType
{
    INCLUDE = 0,
    EXCLUDE
};

// Igmpv3 group record structure
struct GroupRecord
{
    UInt8                   record_type;
    UInt8                   aux_data_len;
    UInt16                  numSources;
    NodeAddress             groupAddress;
    vector<NodeAddress>     sourceAddress;
};

// Igmpv3 retx src info structure
struct RetxSourceInfo
{
    UInt16          retxCount;
    NodeAddress     sourceAddress;
};
// IGMP state change message info structure
struct IgmpStateChangeMsgInfoType
{
    NodeAddress                 grpAddr;
    Int32                       interfaceId;
    Igmpv3FilterModeType        filter;
    Int32                       numSrc;
    vector<NodeAddress>         srcList;
    char                        unsolicitedReportCount;
};

// Igmpv2 message type
struct IgmpMessage
{
    unsigned char           ver_type;
    unsigned char           maxResponseTime;
    short int               checksum;
    unsigned                groupAddress;
};

// Igmpv3 Query message type
struct IgmpQueryMessage
{
    UInt8                   ver_type;
    UInt8                   maxResponseCode;
    UInt16                  checksum;
    NodeAddress             groupAddress;
    // query_qrv_sFlag includes
    // 4 bits reserved field
    // 1 bit Suppress router-side processing flag
    // 3 bits Querier's Robustness Variable(QRV) field
    UInt8                   query_qrv_sFlag;
    UInt8                   qqic;
    UInt16                  numSources;
    vector<NodeAddress>     sourceAddress;
};

// Igmp Report message type
struct Igmpv3ReportMessage
{
    UInt8                   ver_type;
    UInt8                   reserved;
    UInt16                  checksum;
    UInt16                  resv;
    UInt16                  numGrpRecords;
    vector<struct GroupRecord>         groupRecord;
};

// Structure for holding group information in host
struct IgmpGroupInfoForHost
{
    NodeAddress            groupId;
    IgmpStateType          hostState;
    clocktype              groupDelayTimer;
    clocktype              lastQueryReceive;
    clocktype              lastReportSendOrReceive;
    clocktype              lastHostIntfTimerValue;
    clocktype              lastHostGrpTimerValue;
    BOOL                   isLastHost;
    RandomSeed             seed;
    // List of sources received in group-and-source-specific query.
    vector<NodeAddress>    recordedSrcList;
    // List of sources to be reported at the interface.
    vector<NodeAddress>    srcList;
    Igmpv3FilterModeType   filterMode;
    vector<struct GroupRecord> igmpv3GroupRecord;
    // Retx list info
    Igmpv3FilterModeType          retxfilterMode;
    UInt16                        retxCount;
    vector<struct RetxSourceInfo> retxBlockSrcList;
    vector<struct RetxSourceInfo> retxAllowSrcList;
    unsigned int                  retxSeqNo;

    RandomDistribution<clocktype> randomNum;

    struct IgmpGroupInfoForHost*    next;
};

// Igmp host structure
struct IgmpHost
{
    IgmpGroupInfoForHost*  groupListHeadPointer;
    int                    groupCount;
    clocktype              unsolicitedReportInterval;
    clocktype              lastOlderVerQuerierPresentTimer;
    clocktype              querierQueryInterval;
    Int32                  maxRespTime;
    char                   unsolicitedReportCount;
    // Version compatibility mode maintained for a host.
    IgmpVersion            hostCompatibilityMode;
};

// Routers timer
struct IgmpRouterTimer
{
    clocktype              startUpQueryInterval;
    clocktype              generalQueryInterval;
    clocktype              otherQuerierPresentInterval;
    clocktype              lastQueryReceiveTime;
};

// Structure for holding source information in router
struct SourceRecord
{
    NodeAddress            sourceAddr;
    clocktype              sourceTimer;
    clocktype              lastSourceTimerValue;
    int                    retransmitCount;
    BOOL                   isRetransmitOn;
};

// Structure for holding group information in router
struct IgmpGroupInfoForRouter
{
    NodeAddress                 groupId;
    IgmpStateType               membershipState;
    UInt16                      lastMemberQueryCount;
    clocktype                   groupMembershipInterval;
    clocktype                   lastMemberQueryInterval;
    clocktype                   lastReportReceive;
    clocktype                   lastGroupTimerValue;
    clocktype                   lastOlderHostPresentTimer;
    IgmpVersion                 rtrCompatibilityMode;
    Igmpv3FilterModeType        filterMode;
    vector<struct SourceRecord> rtrForwardListVector;
    vector<struct SourceRecord> rtrDoNotForwardListVector;

    struct IgmpGroupInfoForRouter*  next;
};


// Igmp router structure
struct IgmpRouter
{
    IgmpStateType          routersState;
    char                   startUpQueryCount;
    IgmpRouterTimer        timer;
    int                    numOfGroups;
    QueryDelayFuncType     queryDelayTimeFunc;

    IgmpGroupInfoForRouter* groupListHeadPointer;

    RandomSeed             timerSeed;
    clocktype              queryInterval;
    UInt8                  queryResponseInterval;
    UInt8                  lastMemberQueryInterval;
    UInt16                 lastMemberQueryCount;
    UInt8                  sFlag;
};


// Interface specific statistics structure
struct IgmpStatistics
{
    int                    igmpTotalMsgSend;
    int                    igmpTotalMsgReceived;
    int                    igmpBadMsgReceived;

    // Query message statistics
    int                    igmpTotalQueryReceived;
    int                    igmpGrpSpecificQueryReceived;
    int                    igmpGrpAndSourceSpecificQueryReceived;
    int                    igmpGenQueryReceived;
    int                    igmpBadQueryReceived;
    int                    igmpTotalQuerySend;
    int                    igmpGrpSpecificQuerySend;
    int                    igmpGrpAndSourceSpecificQuerySend;
    int                    igmpGenQuerySend;

    // Report message statistics
    int                    igmpTotalReportReceived;
    int                    igmpLeaveReportReceived;
    int                    igmpv2MembershipReportReceived;
    int                    igmpv3MembershipReportReceived;
    int                    igmpBadReportReceived;
    int                    igmpTotalReportSend;
    int                    igmpLeaveReportSend;
    int                    igmpv2MembershipReportSend;
    int                    igmpv3MembershipReportSend;

    // Host behavior
    int                    igmpTotalGroupJoin;
    int                    igmpTotalGroupLeave;

    // Only Router specific statistics
    int                    igmpTotalMembership;
};


//IGMP interface type enumeration
enum IgmpInterfaceType{
    IGMP_UPSTREAM = 0,
    IGMP_DOWNSTREAM,

    // igmp interface type for igmp host and igmp router
    IGMP_DEFAULT_INTERFACE
};


// Interface data structure.
struct IgmpInterfaceInfoType
{
    IgmpHost*              igmpHost;
    IgmpRouter*            igmpRouter;
    MulticastProtocolType  multicastProtocol;
    IgmpStatistics         igmpStat;
    BOOL                   isAdHocMode;     // is ad hoc wireless network
    Int32                  robustnessVariable;
    IgmpInterfaceType      igmpInterfaceType;
    IgmpNodeType           igmpNodeType;    // Host, Router or Proxy
    IgmpVersion            igmpVersion;
};


// Main layer structure.
struct IgmpData
{
    BOOL                   showIgmpStat;
    IgmpInterfaceInfoType* igmpInterfaceInfo[MAX_NUM_INTERFACES];
    NodeAddress            igmpUpstreamInterfaceAddr;
    LinkedList*            igmpProxyDataList;
    IgmpVersion            igmpProxyVersion;
};

// Igmp Proxy Database
struct IgmpProxyData
{
    NodeAddress                     grpAddr;
    Igmpv3FilterModeType            filterMode;
    vector<NodeAddress>             srcList;
};


//---------------------------------------------------------------------------
// FUNCTION     : IgmpInit()
// PURPOSE      : To initialize IGMP protocol.
// PARAMETERS   : node - this node
//                nodeInput - access to configuration file.
//                igmpLayerPtr - pointer to IGMP data.
//                interfaceIndex - initialised at this interface index.
// RETURN VALUE : None
// ASSUMPTION   : All routers and hosts support IGMPv2.
//---------------------------------------------------------------------------
void IgmpInit(
    Node* node,
    const NodeInput* nodeInput,
    IgmpData** igmpLayerPtr,
    int interfaceIndex);


//---------------------------------------------------------------------------
// FUNCTION     : IgmpLayer()
// PURPOSE      : Interface function to receive all the self messages
//              : given by the IP layer to IGMP to handle self message
//              : and timer events.
// PARAMETERS   : node - this node
//                msg - message pointer
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpLayer(Node* node, Message* msg);


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleProtocolPacket()
// PURPOSE      : Function to process IGMP packets received from IP.
// PARAMETERS   : node - this node
//                msg - message pointer
//                srcAddr - source address of message originator.
//                dstAddr - destination address of the message.
//                intfId - interface index on which message received.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpHandleProtocolPacket(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    int intfId);


//---------------------------------------------------------------------------
// FUNCTION     : IgmpFinalize()
// PURPOSE      : Print the statistics of IGMP protocol.
// PARAMETERS   : node - this node
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpFinalize(Node* node);


//---------------------------------------------------------------------------
// FUNCTION     : IgmpJoinGroup()
// PURPOSE      : This function will be called by ip.c when an multicast
//                application wants to join a group. The function needs to be
//                called at the very start of the simulation.
// PARAMETERS   : node - this node
//                interfaceId - on which interface index to join the group
//                groupToJoin - multicast group to join
//                timeToJoin - at what time multicast group is to be joined
//                filterMode - filter mode of the interface, either INCLUDE
//                or EXCLUDE (specific to IGMP version 3)
//                sourceList - list of sources from where multicast traffic
//                is to included or excluded (specific to IGMP version 3)
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpJoinGroup(
    Node* node,
    Int32 interfaceId,
    NodeAddress groupToJoin,
    clocktype timeToJoin,
    char filterMode[] = 0,
    vector<NodeAddress>* sourceList = NULL);


//---------------------------------------------------------------------------
// FUNCTION     : IgmpLeaveGroup()
// PURPOSE      : This function will be called by ip.c when an multicast
//                application wants to leave a group. The function needs to
//                be called at the very start of the simulation.
// PARAMETERS   : node - this node
//                interfaceId - from which interface index to leave the group
//                groupToLeave - multicast group to leave
//                timeToLeave - at what time multicast group is to be left
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpLeaveGroup(
    Node* node,
    Int32 interfaceId,
    NodeAddress groupToLeave,
    clocktype timeToLeave);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpSearchLocalGroupDatabase()
// PURPOSE      : This function helps multicast routing protocols to search
//                IGMP group database for the presence of specified group
//                address.
// PARAMETERS   : node - this node
//                grpAddr - multicast group address whose entry is checked.
//                interfaceId - interface index.
//                localMember - TRUE if group address is present, FALSE
//                otherwise.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpSearchLocalGroupDatabase(
    Node* node,
    NodeAddress grpAddr,
    int interfaceId,
    BOOL* localMember);

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SearchLocalGroupDatabase()
// PURPOSE      : This function helps multicast routing protocols to search
//                IGMPv3 group database for the presence of specified source
//                address in the router's forward list.
// PARAMETERS   : node - this node
//                grpAddr - multicast group address whose entry is checked.
//                interfaceId - interface index.
//                localMember - TRUE if source address is present, FALSE
//                otherwise.
//                srcAddr - address of source whose entry is checked.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void Igmpv3SearchLocalGroupDatabase(
    Node* node,
    NodeAddress grpAddr,
    int interfaceId,
    BOOL* localMember,
    NodeAddress srcAddr);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpFillGroupList()
// PURPOSE      : This function helps multicast routing protocols to collect
//                group information from IGMP database.
// PARAMETERS   : node - this node
//                grpList - linked list to be filled with IGMP information.
//                interfaceId - interface index for IGMP database collection
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpFillGroupList(
    Node* node,
    LinkedList** grpList,
    int interfaceId);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetMulticastProtocolInfo()
// PURPOSE      : This function is used to inform IGMP about the configured
//                multicast routing protocol.
// PARAMETERS   : node - this node
//                interfaceId - interface index.
//                mcastProtoPtr - type of multicast routing protocol.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpSetMulticastProtocolInfo(
    Node* node,
    int interfaceId,
    MulticastProtocolType mcastProtoPtr);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpGetMulticastProtocolInfo()
// PURPOSE      : This function returns the type of multicast routing
//                protocol configured at the interface.
// PARAMETERS   : node - this node
//                interfaceId - interface index.
// RETURN VALUE : MulticastProtocolType - type of multicast routing protocol
// ASSUMPTION   : None
//---------------------------------------------------------------------------
MulticastProtocolType IgmpGetMulticastProtocolInfo(
    Node* node,
    int interfaceId);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpCreatePacket()
// PURPOSE      : To create an IGMPv2 packet
// PARAMETERS   : msg - message packet pointer
//                type - type of IGMP message
//                maxResponseTime - maximum response time to be filled in
//                IGMPv2 message field.
//                groupAddress - multicast group address filled in
//                IGMPv2 message field.
// RETURN VALUE : None.
// ASSUMPTION   : Checksum field is always 0
//---------------------------------------------------------------------------
void IgmpCreatePacket(
    Message* msg,
    unsigned char type,
    unsigned char maxResponseTime,
    unsigned groupAddress);

void IgmpIahepUpdateGroupOnRedIntf(
        Node* node,
        int interfaceId,
        unsigned char type,
        unsigned grpAddr);
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3CreateReportPacket()
// PURPOSE      : To create an IGMP version 3 report packet
// PARAMETERS   : msg - message packet pointer
//                type - type of IGMP message
//                Igmpv3GrpRecord - vector of structure Group Record,
//                inserted in IGMPv3 report packet.
// RETURN VALUE : None.
// ASSUMPTION   : Checksum field is always 0
//---------------------------------------------------------------------------
void Igmpv3CreateReportPacket(
    Message* msg,
    unsigned char type,
    vector<GroupRecord>* Igmpv3GrpRecord);

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3CreateQueryPacket()
// PURPOSE      : To create an IGMP Version 3 query packet.
// PARAMETERS   : msg - message packet pointer
//                type - type of IGMP message
//                maxResponseTime - maximum response time to be filled in
//                IGMPv3 query packet.
//                groupAddress - multicast group address filled in
//                IGMPv3 query packet.
//                query_qrv_sFlag - The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
//                queryInterval - query interval value to be filled in
//                IGMPv3 query packet.
//                sourceAddress - vector of sources which are to be queried
// RETURN VALUE : None.
// ASSUMPTION   : Checksum field is always 0
//---------------------------------------------------------------------------
void Igmpv3CreateQueryPacket(
    Message* msg,
    UInt8 type,
    UInt8 maxResponseTime,
    NodeAddress groupAddress,
    UInt8 query_qrv_sFlag,
    clocktype queryInterval,
    vector<NodeAddress> sourceAddress);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpGetDataPtr()
// PURPOSE      : Get IGMP data pointer.
// PARAMETERS   : node - this node.
// RETURN VALUE : igmpDataPtr if found, NULL otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
IgmpData* IgmpGetDataPtr(Node* node);

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3IsSSMAddress()
// PURPOSE      : Check whether group is in SSM range or not.
// PARAMETERS   : node - this node.
//                groupAddress - multicast group address to be checked.
// RETURN VALUE : True if is in range False otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
bool Igmpv3IsSSMAddress(Node* node, NodeAddress groupAddress);

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3QuerySetResv()
// PURPOSE      : Set 4 bits reserved field in IGMP version 3 query packet.
// PARAMETERS   : qrv_sFlag - .The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
//                resv - input value of reserved field for set operation.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3QuerySetResv(UInt8* qrv_sFlag, UInt8 resv)
{
    resv = resv & maskChar(5, 8);
    *qrv_sFlag = *qrv_sFlag & (~(maskChar(1, 4)));
    *qrv_sFlag = *qrv_sFlag | LshiftChar(resv, 4);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3QuerySetSFlag()
// PURPOSE      : Set 1 bit 'Suppress Router-Side Processing' flag field in
//                IGMP version 3 query packet.
// PARAMETERS   : qrv_sFlag - .The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
//                SFlag - input value of 'Suppress router side processing'
//                flag field for set operation.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3QuerySetSFlag(UInt8* qrv_sFlag, UInt8 SFlag)
{
    SFlag = SFlag & maskChar(8, 8);
    *qrv_sFlag = *qrv_sFlag & (~(maskChar(5, 5)));
    *qrv_sFlag = *qrv_sFlag | LshiftChar(SFlag, 5);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3QuerySetQRV()
// PURPOSE      : Set 3 bits 'Querier's Robustness Variable' field in
//                IGMP version 3 query packet.
// PARAMETERS   : qrv_sFlag - .The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
//                queryRobustnessVariable - input value of querier's
//                robustness variable field for set operation.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3QuerySetQRV(UInt8* qrv_sFlag, UInt8 queryRobustnessVariable)
{
    queryRobustnessVariable = queryRobustnessVariable & maskChar(6, 8);
    *qrv_sFlag = *qrv_sFlag & (~(maskChar(6, 8)));
    *qrv_sFlag = *qrv_sFlag | LshiftChar(queryRobustnessVariable, 8);
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3QueryGetSFlag()
// PURPOSE      : Get 1 bit 'Suppress Router-Side Processing' flag field from
//                IGMP version 3 query packet.
// PARAMETERS   : qrv_sFlag - .The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
UInt8 Igmpv3QueryGetSFlag(UInt8 qrv_sFlag)
{
    unsigned char sFlag = qrv_sFlag;
    sFlag = sFlag & maskChar(5, 5);
    sFlag = RshiftChar(sFlag, 5);

    return sFlag;
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3QueryGetQRV()
// PURPOSE      : Set 3 bits 'Querier's Robustness Variable' field from
//                IGMP version 3 query packet.
// PARAMETERS   : qrv_sFlag - .The variable containing the value of
//                querier's robustness variable, reserved value and 'Suppress
//                router side processing' flag value.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
UInt8 Igmpv3QueryGetQRV(UInt8 qrv_sFlag)
{
    unsigned char qrv = qrv_sFlag;
    qrv = qrv & maskChar(6, 8);
    qrv = RshiftChar(qrv, 8);

    return qrv;
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpProxyHandleSubscription()
// PURPOSE      : Handle subscriptions coming from all down stream
//                interfaces.
// PARAMETERS   : node - this node.
//                grpAddr - multicast group address
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpProxyHandleSubscription(Node* node,
                                NodeAddress grpAddr);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpProxyMergeDownStreamSubscriptions()
// PURPOSE      : Merge subscriptions coming from down stream interfaces
//                based on merger rules section 3.2 RFC3376
// PARAMETERS   : proxyData - Subscription in the list.
//                currentSubscription - Current subscription coming from down
//                                      - downstream interface
//                modified - Bool variable to show whether subscription in 
//                           the list is modified or not after merging
// RETURN VALUE : IgmpProxyData*
// ASSUMPTION   : None
//---------------------------------------------------------------------------
IgmpProxyData* IgmpProxyMergeDownStreamSubscriptions(IgmpProxyData* proxyData,
                                         IgmpProxyData* currentSubscription,
                                         bool* modified);

//---------------------------------------------------------------------------
// FUNCTION     : IgmpCheckHostGroupList()
//
// PURPOSE      : Check whether the specified group exist in this list.
//
// RETURN VALUE : Group database pointer if found, NULL otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------


IgmpGroupInfoForHost* IgmpCheckHostGroupList(
    Node* node,
    NodeAddress grpAddr,
    IgmpGroupInfoForHost* listHead);

#endif // IGMP_H


