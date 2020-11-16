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

// PURPOSE: This is an implementation of Internet Group Management Protocol,
//          Version 2 as described in the RFC2236.
//          It resides at the network at the network layer just above IP.

// ASSUMPTION: 1. All nodes are only IGMPv2 enabled. Compatibility with
//                IGMPv1 was not done.

// REFERENCES: RFC2236, RFC4605

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <iterator>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "multicast_igmp.h"

#include "network_dualip.h"

#ifdef ADDON_DB
#include "dbapi.h"
#include "db_developer.h"
#endif

#ifdef ENTERPRISE_LIB
#include "multicast_dvmrp.h"
#include "multicast_mospf.h"
#endif // ENTERPRISE_LIB

#ifdef CYBER_CORE
#include "network_iahep.h"
#endif // CYBER_CORE

#include "multicast_pim.h"
#define DEBUG 0
#define IAHEP_DEBUG 0
static
void IgmpSendMembershipReport(
        Node* node,
        NodeAddress grpAddr,
        Int32 intfId,
        bool sendCurrentStateRecord = FALSE,
        vector<struct GroupRecord>* Igmpv3GrpRecord = NULL);

static
void IgmpHostHandleQuery(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpInterfaceInfoType* thisInterface,
    Int32 intfId);

static
void Igmpv3HostHandleQuery(
    Node* node,
    IgmpQueryMessage* igmpv3QueryPkt,
    IgmpInterfaceInfoType* thisInterface,
    Int32 intfId);

static
void IgmpRouterHandleReport(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId,
    Int32 robustnessVariable
#ifdef CYBER_CORE
    ,
    NodeAddress* blackMcstSrcAddress = NULL
#endif
                           );

static
void Igmpv3RouterHandleReport(
    Node* node,
    Igmpv3ReportMessage* igmpv3ReportPkt,
    IgmpRouter* igmpRouter,
    Int32 intfId,
    Int32 robustnessVariable);

static
void IgmpRouterHandleLeave(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId);


static void IgmpSetInterfaceType(Node* node,
                                 IgmpData* igmpData,
                                 Int32 interfaceIndex,
                                 IgmpInterfaceType igmpInterfaceType);


static
IgmpInterfaceType IgmpGetInterfaceType(
                                 Node* node,
                                 IgmpData* igmpData,
                                 Int32 interfaceIndex);


static BOOL IgmpValidateProxyParameters(Node* node,
                                        IgmpData* igmpData);


static BOOL IgmpCheckSubscriptionInAllOtherDownstreamInterface(
                                   Node* node,
                                   IgmpData* igmpData,
                                   NodeAddress groupId,
                                   Int32 interfaceIndex);


static
BOOL IgmpGetSubscription(Node* node,
                         Int32 interfaceIndex,
                         NodeAddress grpAddr);

static
void IgmpHandlePacketForProxy(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress grpAddr,
    Int32 intfId);

void IgmpProxyRoutingFunction(Node* node,
                              Message* msg,
                              NodeAddress grpAddr,
                              Int32 interfaceIndex,
                              BOOL* packetWasRouted,
                              NodeAddress prevHop);

static
void IgmpProxyForwardPacketOnInterface(Node* node,
                                       Message* msg,
                                       Int32 outgoingIntfId);

static
void Igmpv3HandleReportIncludeAndIsIncludeAndAllow(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);

static
void Igmpv3HandleReportIncludeAndIsExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportIncludeAndBlock(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportIncludeAndToExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportIncludeAndToInclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportExcludeAndIsIncludeAndAllow(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);

static
void Igmpv3HandleReportExcludeAndIsExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportExcludeAndBlock(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportExcludeAndToExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportExcludeAndToInclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval);
static
void Igmpv3HandleReportDummyFunction(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotforwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{}
static
void (*(Igmpv3ReportHandler[IGMPV3_ROUTER_STATES][IGMPV3_ROUTER_EVENTS])) (
                        Node* node,
                        Int32 intfId,
                        IgmpGroupInfoForRouter* ptr,
                        vector<NodeAddress> forwardList,
                        vector<NodeAddress> doNotforwardList,
                        vector<NodeAddress> sourceList,
                        clocktype groupMembershipInterval) = {
                            Igmpv3HandleReportDummyFunction,
                            Igmpv3HandleReportIncludeAndIsIncludeAndAllow,
                            Igmpv3HandleReportIncludeAndIsExclude,
                            Igmpv3HandleReportIncludeAndToInclude,
                            Igmpv3HandleReportIncludeAndToExclude,
                            Igmpv3HandleReportIncludeAndIsIncludeAndAllow,
                            Igmpv3HandleReportIncludeAndBlock,
                            Igmpv3HandleReportDummyFunction,
                            Igmpv3HandleReportExcludeAndIsIncludeAndAllow,
                            Igmpv3HandleReportExcludeAndIsExclude,
                            Igmpv3HandleReportExcludeAndToInclude,
                            Igmpv3HandleReportExcludeAndToExclude,
                            Igmpv3HandleReportExcludeAndIsIncludeAndAllow,
                            Igmpv3HandleReportExcludeAndBlock};


//---------------------------------------------------------------------------
// FUNCTION     : IgmpGetDataPtr()
// PURPOSE      : Get IGMP data pointer.
// RETURN VALUE : igmpDataPtr if found, NULL otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
IgmpData* IgmpGetDataPtr(Node* node)
{
    NetworkDataIp* ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    return ipLayer->igmpDataPtr;
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpConvertCodeToValue()
// PURPOSE      : Converts unsigned char code to integer value.
// PARAMETERS   : code - variable to be converted.
// RETURN VALUE : integer value.
//---------------------------------------------------------------------------
static
int Igmpv3ConvertCodeToValue(UInt8 code)
{
    int mant = code & 0x0F;
    int exp = (code & 0x70) >> 4;
    return ((mant | 0x10) << (exp + 3));
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3ConvertValueToCode()
// PURPOSE      : Converts integer value to floating point number.
// PARAMETERS   : value - variable to be converted to code value.
// RETURN VALUE : integer value.
//---------------------------------------------------------------------------
static
unsigned char Igmpv3ConvertValueToCode(double value)
{

    int exponent = ((int)(log(value)/log((double)2)) - 7);
    if (exponent > 7 || exponent < 0)
    {
        ERROR_ReportWarning("Out of range exponent while converting value"
            "to code\n");
    }
    int mant = (int)(value * pow((double)2, (double)(-exponent - 3)) - 16);
    if (mant > 15 || mant < 0)
    {
        ERROR_ReportWarning("Out of range mantissa while converting value"
            "to code\n");
    }
    return (UInt8)(0x80 | (exponent << 4) | mant);
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpIsSrcInAttachedSubnet()
// PURPOSE      : Check whether the source is in any of the attached subnet.
//                This is to prevent accepting multicast packet that comes
//                from a remote subnet. This kind of situation can occur in
//                wireless network if two subnet overlaps.
// RETURN VALUE : TRUE if source is in attached subnet, FALSE otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
BOOL IgmpIsSrcInAttachedSubnet(Node* node, NodeAddress srcAddr)
{
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        NodeAddress netAddr = NetworkIpGetInterfaceNetworkAddress(node, i);
        NodeAddress netMask = NetworkIpGetInterfaceSubnetMask(node, i);

        if (netAddr == (srcAddr & netMask))
        {
            return TRUE;
        }
    }

    return FALSE;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpIsMyPacket()
// PURPOSE      : Check whether the packet is meant for this node
// RETURN VALUE : TRUE if packet is meant for this node, FALSE otherwise.
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
BOOL IgmpIsMyPacket(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    BOOL retVal = FALSE;
    IgmpInterfaceType igmpInterfaceType = IGMP_DEFAULT_INTERFACE;

    if (grpAddr == IGMP_ALL_SYSTEMS_GROUP_ADDR)
    {
        retVal = TRUE;
    }
    else if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER)
    {
        retVal = TRUE;
    }
    else if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
    {
        if (intfId ==
            NetworkIpGetInterfaceIndexFromAddress(
                node, igmp->igmpUpstreamInterfaceAddr))
        {
            igmpInterfaceType = IGMP_UPSTREAM;
        }
        else
        {
            igmpInterfaceType = IGMP_DOWNSTREAM;
            retVal = TRUE;                      // this interface will act as router
        }
    }

    if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_HOST
        || igmpInterfaceType == IGMP_UPSTREAM)
    {
        IgmpGroupInfoForHost* tempGrpPtr = NULL;
        tempGrpPtr = igmp->igmpInterfaceInfo[intfId]->
                        igmpHost->groupListHeadPointer;

        while (tempGrpPtr)
        {
            if (tempGrpPtr->groupId == grpAddr)
            {
                retVal = TRUE;
                break;
            }
            tempGrpPtr = tempGrpPtr->next;
        }
    }

    return retVal;
}


static
clocktype IgmpSetRegularQueryTimerDelay(
    IgmpRouter* igmpRouter,
    Message* msg)
{
    return igmpRouter->timer.generalQueryInterval;
}


static
clocktype IgmpSetStartUpQueryTimerDelay(
    IgmpRouter* igmpRouter,
    Message* msg)
{
    char startupQueryCount;
    char* ptr;

    ptr = MESSAGE_ReturnInfo(msg) + sizeof(int);
    memcpy(&startupQueryCount, ptr, sizeof(char));

    // Increase Startup query count
    //startupQueryCount++;
    //memcpy(ptr, &startupQueryCount, sizeof(char));

    if (startupQueryCount == igmpRouter->startUpQueryCount) {
        igmpRouter->queryDelayTimeFunc =
            &IgmpSetRegularQueryTimerDelay;
        //as the [startupQueryCount] number of start up
        //queries have been sent, the query interval now
        //should be equal to General Query Interval and
        //not Start Up Query interval.
        return igmpRouter->timer.generalQueryInterval;
    }
    else
    {
        // Increase Startup query count
        startupQueryCount++;
    }
    memcpy(ptr, &startupQueryCount, sizeof(char));

    return igmpRouter->timer.startUpQueryInterval;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetQueryTimer()
// PURPOSE      : sets the timer to send query message
// RETURN VALUE : None
// ASSUMPTION   : This function shouldn't be called from IgmpInit(...)
//---------------------------------------------------------------------------
static
void IgmpSetQueryTimer(
    Node* node,
    Int32 intfId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    IgmpRouter* igmpRouter;
    Message* newMsg;
    char* dataPtr;
    clocktype delay;

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpQueryTimer);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(int) + sizeof(char));
    dataPtr = MESSAGE_ReturnInfo(newMsg);

    memcpy(dataPtr, &intfId, sizeof(int));
    dataPtr += sizeof(int);

    // XXX: Forcefully sending RegularQueryTimer, assuming this function
    //      shouldn't be called from IgmpInit(...) and when a
    //      router's state transit from NON_QUERIER to QUERIER the router
    //      will not send [Startup Query Count] General Queries spaced
    //      closely together [Startup Query Interval]
    memcpy(dataPtr, &igmpRouter->startUpQueryCount, sizeof(char));
    igmpRouter->queryDelayTimeFunc = &IgmpSetRegularQueryTimerDelay;

    delay = (igmpRouter->queryDelayTimeFunc)(igmpRouter, newMsg);

    // Send timer to self
    MESSAGE_Send(node, newMsg, delay);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetReportTimer()
//
// PURPOSE      : Set delay timer for the group specified
//                to send membership report.
//                Generate a random number between 0 to max response time as
//                specified in the query message, and send a self timer.
//
// RETURN VALUE : None
// ASSUMPTION   : Maximum clock granularity is 100 millisecond.
//---------------------------------------------------------------------------
static
void IgmpSetReportTimer(
    Node* node,
    unsigned char maxResponseTime,
    IgmpGroupInfoForHost* tempGrpPtr,
    Int32 intfId)
{
    Message* newMsg = NULL;
    Int32 random;
    char* ptr;


    random = RANDOM_nrand(tempGrpPtr->seed);
    tempGrpPtr->groupDelayTimer = (clocktype)
            (((random) % (maxResponseTime)) * 100 * MILLI_SECOND);

    tempGrpPtr->lastQueryReceive = node->getNodeTime();

    if (DEBUG)
    {
        char timeStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        TIME_PrintClockInSecond(tempGrpPtr->groupDelayTimer, timeStr);
        IO_ConvertIpAddressToString(tempGrpPtr->groupId, ipStr);
        printf("    Setting delay timer for group %s to %ss\n",
            ipStr, timeStr);
    }

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpGroupReplyTimer);

    MESSAGE_InfoAlloc(node, newMsg, (sizeof(NodeAddress) + sizeof(Int32)));
    memcpy(MESSAGE_ReturnInfo(newMsg),
           &tempGrpPtr->groupId,
           sizeof(NodeAddress));
    ptr = MESSAGE_ReturnInfo(newMsg) + sizeof(NodeAddress);
    *ptr = (char)intfId;

    // Send timer to self with delay
    MESSAGE_Send(node, newMsg, tempGrpPtr->groupDelayTimer);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HostSetInterfaceTimer()
// PURPOSE      : Set delay timer for the group specified
//                when a general query is received.
// PARAMETERS   : node - this node.
//                timerValue - time interval to which
//                MSG_NETWORK_Igmpv3HostReplyTimer is set.
//                tempGrpPtr - pointer to IgmpGroupInfoForHost.
//                intfId - interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HostSetInterfaceTimer(
    Node* node,
    clocktype timerValue,
    IgmpGroupInfoForHost* tempGrpPtr,
    Int32 intfId)
{
    Message* newMsg = NULL;
    char* ptr = NULL;
    NodeAddress grpAddr;

    tempGrpPtr->lastQueryReceive = node->getNodeTime();
    tempGrpPtr->lastHostIntfTimerValue = timerValue + node->getNodeTime();
    // Setting response for a general query
    grpAddr = 0;
    if (DEBUG)
    {
        char timeStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        TIME_PrintClockInSecond(tempGrpPtr->groupDelayTimer, timeStr);
        IO_ConvertIpAddressToString(tempGrpPtr->groupId, ipStr);
        printf("Setting IGMPv3 interface delay timer for group %s to %ss\n",
            ipStr, timeStr);
    }

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_Igmpv3HostReplyTimer);

    MESSAGE_InfoAlloc(node, newMsg, (sizeof(NodeAddress) + sizeof(Int32)));
    memcpy(MESSAGE_ReturnInfo(newMsg), &grpAddr, sizeof(NodeAddress));
    ptr = MESSAGE_ReturnInfo(newMsg) + sizeof(NodeAddress);
    *ptr = (char)intfId;

    // Send timer to self with delay.
    MESSAGE_Send(node, newMsg, timerValue);
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetGroupMembershipTimer()
// PURPOSE      : sets the timer for the membership of the specified group.
//                timer value = [Group Membership Interval].
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpSetGroupMembershipTimer(
    Node* node,
    IgmpGroupInfoForRouter* grpPtr,
    Int32 intfId)
{
    Message* newMsg;
    char* infoPtr;

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpGroupMembershipTimer);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(NodeAddress) + sizeof(int));

    infoPtr = MESSAGE_ReturnInfo(newMsg);
    memcpy(infoPtr, &grpPtr->groupId, sizeof(NodeAddress));
    memcpy(infoPtr + sizeof(NodeAddress), &intfId, sizeof(int));

    // Send timer to self
    MESSAGE_Send(node, newMsg, grpPtr->groupMembershipInterval);
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SetRouterGroupTimer()
// PURPOSE      : sets the timer for the membership of the specified group.
// PARAMETERS   : node - this node.
//                grpPtr - pointer to IgmpGroupInfoForRouter.
//                timerValue - set the group timer to this value.
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3SetRouterGroupTimer(
    Node* node,
    IgmpGroupInfoForRouter* grpPtr,
    clocktype timerValue,
    Int32 intfId)
{
    Message* newMsg;
    char* infoPtr;

    // Set the router group timer value.
    grpPtr->lastGroupTimerValue = node->getNodeTime() + timerValue;

    // Allocate new message
    newMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           GROUP_MANAGEMENT_PROTOCOL_IGMP,
                           MSG_NETWORK_Igmpv3RouterGroupTimer);

    MESSAGE_InfoAlloc(node,
                      newMsg,
                      sizeof(NodeAddress)
                       + sizeof(int));

    infoPtr = MESSAGE_ReturnInfo(newMsg);
    memcpy(infoPtr, &grpPtr->groupId, sizeof(NodeAddress));
    memcpy(infoPtr + sizeof(NodeAddress), &intfId, sizeof(int));

    // Send timer to self.
    MESSAGE_Send(node, newMsg, timerValue);

}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3IsSSMAddress()
// PURPOSE      : Check whether group is in SSM range or not.
// PARAMETERS   : node - this node.
//                groupAddress - multicast group address to be checked.
// RETURN VALUE : True if is in range False otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
bool Igmpv3IsSSMAddress(Node* node, NodeAddress groupAddress)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    if (groupAddress <= ip->SSMLastGrpAddr
        && groupAddress >= ip->SSMStartGrpAddr)
    {
        return TRUE;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SetSourceTimer()
// PURPOSE      : sets the timer for the membership of the specified sources
// PARAMETERS   : node - this node.
//                grpPtr - pointer to IgmpGroupInfoForRouter.
//                srcRecordVector - vector of Source Record structure.
//                timerValue - set the source timer to this value.
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3SetSourceTimer(
    Node* node,
    IgmpGroupInfoForRouter* grpPtr,
    vector<SourceRecord>* srcRecordVector,
    clocktype timerValue,
    Int32 intfId,
    vector<NodeAddress> sourceVector)
{
    Message* newMsg;
    char* infoPtr;
    vector<SourceRecord> :: iterator it;
    vector<NodeAddress> :: iterator itr;
    UInt32 i;
    NetworkDataIp* ipLayer = NULL;
    ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    for (i = 0; i < sourceVector.size(); i++)
    {
        // Search for this source in the source record list
        // and set the lastSourceTimerValue to the current delay time
        for (it = srcRecordVector->begin();
             it < srcRecordVector->end();
             ++it)
        {
            if ((*it).sourceAddr == sourceVector[i])
            {
                (*it).lastSourceTimerValue = node->getNodeTime() + timerValue;
                // Allocate new message
                newMsg = MESSAGE_Alloc(node,
                                       NETWORK_LAYER,
                                       GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                       MSG_NETWORK_Igmpv3SourceTimer);

                MESSAGE_InfoAlloc(node,
                                  newMsg,
                                  sizeof(NodeAddress)
                                    + sizeof(Int32)
                                    + sizeof(NodeAddress));

                infoPtr = MESSAGE_ReturnInfo(newMsg);
                memcpy(infoPtr, &grpPtr->groupId, sizeof(NodeAddress));
                infoPtr += sizeof(NodeAddress);
                memcpy(infoPtr, &intfId, sizeof(Int32));
                infoPtr += sizeof(Int32);
                memcpy(infoPtr, &sourceVector[i], sizeof(NodeAddress));

                // Send timer to self for the ith source
                MESSAGE_Send(node, newMsg, timerValue);
                break;
            }
        }
    }
    // multicast protocol notification
    if (timerValue > 0)
    {
        PimData* pim = (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
                                                     MULTICAST_PROTOCOL_PIM);
        if (pim)
        {
            if (pim->modeType != ROUTING_PIM_MODE_DENSE
                && ipLayer->isSSMEnable)
            {
                if (Igmpv3IsSSMAddress(node, grpPtr->groupId))
                {
                    if (sourceVector.empty())
                    {
                        return;
                    }
                    if (!pim->interface[intfId].srcGrpList)
                    {
                        ListInit(node, &pim->interface[intfId].srcGrpList);
                    }
                    else
                    {
                        ListFree(node,
                                 pim->interface[intfId].srcGrpList,
                                 FALSE);
                        ListInit(node, &pim->interface[intfId].srcGrpList);
                    }
                    RoutingPimSourceGroupList* srcGroupListPtr = NULL;

                    for (itr = sourceVector.begin();
                         itr < sourceVector.end();
                         ++itr)
                    {
                        srcGroupListPtr =(RoutingPimSourceGroupList*)
                               MEM_malloc(sizeof(RoutingPimSourceGroupList));
                        srcGroupListPtr->groupAddr = grpPtr->groupId;
                        srcGroupListPtr->srcAddr = *itr;
                        ListInsert(node,
                                   pim->interface[intfId].srcGrpList,
                                   node->getNodeTime(),
                                   (void*)srcGroupListPtr);
                    }
                }
            }
        }
        MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
        if (notifyMcastRtProto)
        {
            (notifyMcastRtProto)(node,
                                 grpPtr->groupId,
                                 intfId,
                                 LOCAL_MEMBER_JOIN_GROUP);
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3RouterLowerGrpTimer()
// PURPOSE      : Lowers the source timer to Last Member Query Time value of
//                specified sources and sets their retransmit count.
// PARAMETERS   : node - this node.
//                grpPtr - pointer to IgmpGroupInfoForRouter.
//                timerValue - lower group timer with this time interval.
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterLowerGrpTimer(
    Node* node,
    IgmpGroupInfoForRouter* grpPtr,
    clocktype timerValue,
    Int32 intfId)
{
    Message* newMsg = NULL;
    char* infoPtr = NULL;
    clocktype remDelay = 0;

    remDelay = grpPtr->lastGroupTimerValue - node->getNodeTime();
    if (remDelay > timerValue)
    {
        grpPtr->lastGroupTimerValue = timerValue + node->getNodeTime();

        // Allocate new message
        newMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_Igmpv3RouterGroupTimer);

        MESSAGE_InfoAlloc(node,
                          newMsg,
                          sizeof(NodeAddress)
                           + sizeof(int));

        infoPtr = MESSAGE_ReturnInfo(newMsg);
        memcpy(infoPtr, &grpPtr->groupId, sizeof(NodeAddress));
        memcpy(infoPtr + sizeof(NodeAddress), &intfId, sizeof(int));

        // Send timer to self.
        MESSAGE_Send(node, newMsg, timerValue);
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3RouterLowerSourceTimer()
// PURPOSE      : Lowers the source timer to Last Member Query Time value of
//                specified sources and sets their retransmit count.
// PARAMETERS   : node - this node.
//                grpPtr - pointer to IgmpGroupInfoForRouter.
//                srcRecordVector - vector of Source Record structure.
//                timerValue - lower source timer with this time interval
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterLowerSourceTimer(
    Node* node,
    IgmpGroupInfoForRouter* grpPtr,
    vector<SourceRecord>* srcRecordVector,
    clocktype timerValue,
    Int32 intfId,
    vector<NodeAddress> sourceVector)
{
    Message* newMsg = NULL;
    char* infoPtr = NULL;
    clocktype remDelay = 0;
    vector<SourceRecord> :: iterator it;
    UInt32 i;
    for (i = 0; i < sourceVector.size(); i++)
    {
        // Search for this source in the source record list
        for (it = srcRecordVector->begin();
             it < srcRecordVector->end();
             ++it)
        {
            if ((*it).sourceAddr == sourceVector[i])
            {
               (*it).retransmitCount = grpPtr->lastMemberQueryCount;
                remDelay = (*it).lastSourceTimerValue - node->getNodeTime();
                // If the remaining delay is greater than last member
                // query time then set the delay to LMQT.
                if (remDelay > timerValue)
                {
                    // Set number of retransmissions for each source to
                    // [Last Member Query Count].
                    (*it).lastSourceTimerValue = timerValue + node->getNodeTime();

                    // Allocate new message
                    newMsg = MESSAGE_Alloc(node,
                                           NETWORK_LAYER,
                                           GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                           MSG_NETWORK_Igmpv3SourceTimer);

                    MESSAGE_InfoAlloc(node,
                                      newMsg,
                                      sizeof(NodeAddress)
                                        + sizeof(int)
                                        + sizeof(NodeAddress));

                    infoPtr = MESSAGE_ReturnInfo(newMsg);
                    memcpy(infoPtr, &grpPtr->groupId, sizeof(NodeAddress));
                    infoPtr += sizeof(NodeAddress);
                    memcpy(infoPtr, &intfId, sizeof(Int32));
                    infoPtr += sizeof(Int32);
                    memcpy(infoPtr, &sourceVector[i], sizeof(NodeAddress));

                    // Send timer to self for the ith source
                    MESSAGE_Send(node, newMsg, timerValue);
                }
                break;
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HostSetGrpTimer()
// PURPOSE      : sets the time for group membership when an IGMPv3 group
//                specific or group and source specific query is encountered
// PARAMETERS   : node - this node.
//                delay - time interval to which
//                MSG_NETWORK_Igmpv3HostReplyTimer is set.
//                grpPtr - pointer to IgmpGroupInfoForHost.
//                intfId - interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HostSetGrpTimer(
    Node* node,
    clocktype delay,
    IgmpGroupInfoForHost* grpPtr,
    Int32 intfId)
{
    Message* newMsg = NULL;
    char* ptr;

    grpPtr->lastQueryReceive = node->getNodeTime();
    grpPtr->lastHostGrpTimerValue = delay + node->getNodeTime();

    if (DEBUG)
    {
        char timeStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        TIME_PrintClockInSecond(grpPtr->groupDelayTimer, timeStr);
        IO_ConvertIpAddressToString(grpPtr->groupId, ipStr);
        printf("Setting IGMPv3 group delay timer for group %s to %ss\n",
            ipStr, timeStr);
    }

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_Igmpv3HostReplyTimer);

    MESSAGE_InfoAlloc(node, newMsg, (sizeof(NodeAddress) + sizeof(Int32)));
    ptr = MESSAGE_ReturnInfo(newMsg);
    memcpy(ptr, &grpPtr->groupId, sizeof(NodeAddress));
    memcpy(ptr + sizeof(NodeAddress), &intfId, sizeof(Int32));

    // Send timer to self with delay
    MESSAGE_Send(node, newMsg, delay);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetLastMembershipTimer()
// PURPOSE      : sets the timer for the membership to the
//                [Group Membership Interval].
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpSetLastMembershipTimer(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    short count,
    UInt8 lastMemberQueryInterval)
{
    Message* newMsg;
    char* dataPtr;

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpLastMemberTimer);

    MESSAGE_InfoAlloc(
        node, newMsg, sizeof(NodeAddress) + sizeof(int) + sizeof(short));
    dataPtr = MESSAGE_ReturnInfo(newMsg);

    memcpy(dataPtr, &grpAddr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(dataPtr, &intfId, sizeof(int));
    dataPtr += sizeof(int);
    memcpy(dataPtr, &count, sizeof(short));

    // Send timer to self
    MESSAGE_Send(node, newMsg, (lastMemberQueryInterval / 10)*SECOND);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHostSetOrResetMembershipTimer()
//
// PURPOSE      : Set delay timer for the specified group. If a timer for the
//                group is already running, it is reset to the random value
//                only if the requested Max Response Time is less than the
//                remaining value of the running timer.
//
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHostSetOrResetMembershipTimer(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpGroupInfoForHost* grpPtr,
    Int32 intfId)
{
    if (grpPtr->hostState == IGMP_HOST_IDLE_MEMBER)
    {
        // Host is in idle member state. Set timer
        grpPtr->hostState = IGMP_HOST_DELAYING_MEMBER;

        IgmpSetReportTimer(node, igmpv2Pkt->maxResponseTime, grpPtr, intfId);
    }
    else
    {
        // If timer is already running reset it to the random
        // value only if the requested max response time is
        // less than the remaining value of the running timer
         clocktype remainingDelayTimer = grpPtr->groupDelayTimer -
                (node->getNodeTime() - grpPtr->lastQueryReceive);

         if (remainingDelayTimer >
             (((igmpv2Pkt->maxResponseTime)/10) * SECOND))
         {
            if (DEBUG) {
                printf("    Cancel previous timer\n");
            }

            IgmpSetReportTimer(
                node, igmpv2Pkt->maxResponseTime, grpPtr, intfId);

            // Cancellation of previous timer is done at layer function. For
            // that we have make a convention that when a host sends a report
            // it must update it's lastReportSendOrReceive timer to current
            // value (i.e; the current simulation time).
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpInsertHostGroupList()
//
// PURPOSE      : Create a new group entry in this list.
//
// RETURN VALUE : Group database pointer of new group.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
IgmpGroupInfoForHost* IgmpInsertHostGroupList(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;
    IgmpGroupInfoForHost* tmpGrpPtr;

    if (!igmp->igmpInterfaceInfo[intfId])
    {
        char errStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            ipStr);
        sprintf(errStr, "Node %u: Error inserting group\n"
            "         IGMP not running over interface %s!!\n",
            node->nodeId, ipStr);
        ERROR_Assert(FALSE, errStr);
        return NULL;
    }

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    // Allocate space for new group
    tmpGrpPtr = (IgmpGroupInfoForHost*)
        MEM_malloc(sizeof(IgmpGroupInfoForHost));
    memset(tmpGrpPtr, 0, sizeof(IgmpGroupInfoForHost));

    // Assign group information
    tmpGrpPtr->groupId = grpAddr;
    tmpGrpPtr->hostState = IGMP_HOST_DELAYING_MEMBER;
    tmpGrpPtr->groupDelayTimer = IGMP_UNSOLICITED_REPORT_INTERVAL;
    tmpGrpPtr->lastQueryReceive = (clocktype) 0;
    tmpGrpPtr->lastReportSendOrReceive = node->getNodeTime();
    tmpGrpPtr->isLastHost = TRUE;

    if (igmpHost->hostCompatibilityMode == IGMP_V3)
    {
        tmpGrpPtr->filterMode = INCLUDE;
        tmpGrpPtr->lastHostIntfTimerValue = (clocktype)0;
        tmpGrpPtr->lastHostGrpTimerValue = (clocktype)0;
        tmpGrpPtr->retxCount = 0;
        tmpGrpPtr->retxSeqNo = 0;
        tmpGrpPtr->retxfilterMode = INCLUDE;
    }
    RANDOM_SetSeed(tmpGrpPtr->seed,
                   node->globalSeed,
                   node->nodeId,
                   GROUP_MANAGEMENT_PROTOCOL_IGMP,
                   intfId); // RAND, I don't know if this is unique

    // Insert at top of list
    tmpGrpPtr->next = igmpHost->groupListHeadPointer;
    igmpHost->groupListHeadPointer = tmpGrpPtr;

    igmpHost->groupCount += 1;
    igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalGroupJoin += 1;

    if (DEBUG) {
        char grpStr[20];
        char intfStr[20];

        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            intfStr);
        printf("Group %s has been added in host %u's list on "
            "interface %s\n\n",
            grpStr, node->nodeId, intfStr);
    }

    return tmpGrpPtr;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpDeleteHostGroupList()
//
// PURPOSE      : Remove a group entry from this list.
//
// RETURN VALUE : TRUE if successfully deleted, FALSE otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
BOOL IgmpDeleteHostGroupList(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    BOOL* checkLastHostStatus)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;
    IgmpGroupInfoForHost* tmpGrpPtr;
    IgmpGroupInfoForHost* prev;

    *checkLastHostStatus = FALSE;

    if (!igmp->igmpInterfaceInfo[intfId])
    {
        char errStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            ipStr);
        sprintf(errStr, "Node %u: Error deleting group\n"
            "         IGMP not running over interface %s!!\n",
            node->nodeId, ipStr);
        ERROR_Assert(FALSE, errStr);
        return FALSE;
    }

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    tmpGrpPtr = igmpHost->groupListHeadPointer;
    prev = igmpHost->groupListHeadPointer;

    while (tmpGrpPtr && tmpGrpPtr->groupId != grpAddr)
    {
        prev = tmpGrpPtr;
        tmpGrpPtr = tmpGrpPtr->next;
    }

    // Return if entry doesn't exist.
    if (!tmpGrpPtr) {
        if (DEBUG) {
            printf("    No entry found for this group\n");
        }
        return FALSE;
    }

    // If this was first element of the list
    if (prev == tmpGrpPtr) {
        igmpHost->groupListHeadPointer = tmpGrpPtr->next;
    } else {
        prev->next = tmpGrpPtr->next;
    }

    if (tmpGrpPtr->isLastHost) {
        *checkLastHostStatus = TRUE;
    }

    MEM_free(tmpGrpPtr);

    igmpHost->groupCount -= 1;
    igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalGroupLeave += 1;

    if (DEBUG) {
        char grpStr[20];
        char intfStr[20];

        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            intfStr);
        printf("Group %s has been removed from host %u's list on "
            "interface %s\n\n",
            grpStr, node->nodeId, intfStr);
    }

    return TRUE;
}


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
    IgmpGroupInfoForHost* listHead)
{
    IgmpGroupInfoForHost* tmpGrpPtr;

    tmpGrpPtr = listHead;

    while (tmpGrpPtr)
    {
        if (tmpGrpPtr->groupId == grpAddr)
        {
            return tmpGrpPtr;
        }

        tmpGrpPtr = tmpGrpPtr->next;
    }

    return NULL;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpInsertRtrGroupList()
//
// PURPOSE      : Create a new group entry in this list.
//
// RETURN VALUE : Group database pointer of new group.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
IgmpGroupInfoForRouter* IgmpInsertRtrGroupList(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    Int32 robustnessVariable)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* tmpGrpPtr = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    vector<NodeAddress> tmpVector;

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    if (!igmp->igmpInterfaceInfo[intfId])
    {
        char errStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            ipStr);
        sprintf(errStr, "Node %u: Error inserting group\n"
            "         IGMP not running over interface %s!!\n",
            node->nodeId, ipStr);
        ERROR_Assert(FALSE, errStr);
        return NULL;
    }

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    // Allocate space for new group
    tmpGrpPtr = (IgmpGroupInfoForRouter*)
        MEM_malloc(sizeof(IgmpGroupInfoForRouter));
    memset(tmpGrpPtr, 0, sizeof(IgmpGroupInfoForRouter));
    // Assign group information
    tmpGrpPtr->groupId = grpAddr;
    tmpGrpPtr->membershipState = IGMP_ROUTER_MEMBERS;
    tmpGrpPtr->lastMemberQueryCount = igmpRouter->lastMemberQueryCount;
    //The default value for Query Response interval is 100 which on
    //converting into units comes out to be 10 seconds. In QualNet at
    //initialization it is stored as 100 or converting the value configured
    //by user (in seconds) to the normal value i.e. dividing by seconds and
    //multiplying by 10.Hence,it is required to divide the current value in
    //queryResponseInterval by 10 and multiply by SECOND.
    tmpGrpPtr->groupMembershipInterval = (clocktype)
                                    ((robustnessVariable * igmpRouter->queryInterval)
                              + (igmpRouter->queryResponseInterval * SECOND)
                               /IGMP_QUERY_RESPONSE_SCALE_FACTOR);
    tmpGrpPtr->lastMemberQueryInterval = igmpRouter->lastMemberQueryInterval;
    tmpGrpPtr->lastReportReceive = node->getNodeTime();
    tmpGrpPtr->lastOlderHostPresentTimer = (clocktype)0;
    // Version group compatibility mode is maintained per group record and
    // initialized with IGMP version
    tmpGrpPtr->rtrCompatibilityMode = thisInterface->igmpVersion;
    tmpGrpPtr->lastOlderHostPresentTimer = (clocktype)0;
    // Version group compatibility mode is maintained per group record and
    // initialized with IGMP version
    tmpGrpPtr->rtrCompatibilityMode = thisInterface->igmpVersion;

    if (tmpGrpPtr->rtrCompatibilityMode == IGMP_V3)
    {
        // router initial state is Include with empty source list
        // lastGroupTimerValue is used to set the group timer, initialized
        // with zero value.
        tmpGrpPtr->lastGroupTimerValue = 0;
        tmpGrpPtr->filterMode = INCLUDE;
    }

    // Insert at top of list
    tmpGrpPtr->next = igmpRouter->groupListHeadPointer;
    igmpRouter->groupListHeadPointer = tmpGrpPtr;

    igmpRouter->numOfGroups += 1;
    igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalMembership += 1;

    if (DEBUG) {
        char grpStr[20];
        char intfStr[20];

        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            intfStr);
        printf("Group %s has been added in router %u's list on "
            "interface %s\n\n",
            grpStr, node->nodeId, intfStr);
    }

    return tmpGrpPtr;
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3UpdateForwardListVector()
//
// PURPOSE      : Create a new source entry in the forward list vector.
// PARAMETERS   : rtrInfoPtr - pointer to IgmpGroupInfoForRouter.
//                sources - vector of sources to be updated.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3UpdateForwardListVector(
      IgmpGroupInfoForRouter* rtrInfoPtr,
      vector<NodeAddress> sources)
{
    SourceRecord srcRecord;
    bool srcNotFound;
    UInt32 i, j;

    for (i = 0; i < sources.size(); i++)
    {
        srcNotFound = TRUE;
        for (j = 0; j < rtrInfoPtr->rtrForwardListVector.size(); j++)
        {
            if (rtrInfoPtr->rtrForwardListVector[j].sourceAddr
                == sources[i])
            {
                srcNotFound = FALSE;
                break;
            }
        }
        if (srcNotFound)
        {
            // Source is not present in map insert this new value
            // into map.
            srcRecord.sourceAddr = sources[i];
            srcRecord.isRetransmitOn = FALSE;
            srcRecord.retransmitCount = 0;
            srcRecord.sourceTimer = rtrInfoPtr->groupMembershipInterval;
            srcRecord.lastSourceTimerValue = 0;
            rtrInfoPtr->rtrForwardListVector.push_back(srcRecord);
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3UpdateDoNotForwardListVector()
// PURPOSE      : Create a new source entry in the do not forward list vector
// PARAMETERS   : rtrInfoPtr - pointer to IgmpGroupInfoForRouter.
//                sources - vector of sources to be updated.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3UpdateDoNotForwardListVector(
      IgmpGroupInfoForRouter* rtrInfoPtr,
      vector<NodeAddress> sources)
{
    SourceRecord srcRecord;
    bool srcNotFound;
    UInt32 i, j;

    for (i = 0; i < sources.size(); i++)
    {
        srcNotFound = TRUE;
        for (j = 0; j < rtrInfoPtr->rtrDoNotForwardListVector.size(); j++)
        {
            if (rtrInfoPtr->rtrDoNotForwardListVector[j].sourceAddr
                == sources[i])
            {
                srcNotFound = FALSE;
                break;
            }
        }
        if (srcNotFound)
        {
            // Source is not present in map insert this new value
            // into map.
            srcRecord.sourceAddr = sources[i];
            srcRecord.isRetransmitOn = FALSE;
            srcRecord.retransmitCount = 0;
            srcRecord.sourceTimer = rtrInfoPtr->groupMembershipInterval;
            srcRecord.lastSourceTimerValue = 0;
            rtrInfoPtr->rtrDoNotForwardListVector.push_back(srcRecord);
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3DeleteSrcForwardListVector()
// PURPOSE      : Delete sources from forward list vector.
// PARAMETERS   : rtrInfoPtr - pointer to IgmpGroupInfoForRouter.
//                sources - vector of sources to be deleted.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3DeleteSrcForwardListVector(
      IgmpGroupInfoForRouter* rtrInfoPtr,
      vector<NodeAddress> sources)
{
    vector<SourceRecord> :: iterator it;
    UInt32 i;

    for (i = 0; i < sources.size(); i++)
    {
        for (it = rtrInfoPtr->rtrForwardListVector.begin();
             it < rtrInfoPtr->rtrForwardListVector.end(); ++it)
        {
            if ((*it).sourceAddr == sources[i])
            {
                // Delete the source value from the vector.
                rtrInfoPtr->rtrForwardListVector.erase(it);
                break;
            }
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3DeleteSrcDoNotForwardListVector()
// PURPOSE      : Delete sources from do not forward list vector.
// PARAMETERS   : rtrInfoPtr - pointer to IgmpGroupInfoForRouter.
//                sources - vector of sources to be deleted.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3DeleteSrcDoNotForwardListVector(
      IgmpGroupInfoForRouter* rtrInfoPtr,
      vector<NodeAddress> sources)
{
    vector<SourceRecord> :: iterator it;
    UInt32 i;

    for (i = 0; i < sources.size(); i++)
    {
        for (it = rtrInfoPtr->rtrDoNotForwardListVector.begin();
             it < rtrInfoPtr->rtrDoNotForwardListVector.end(); ++it)
        {
            if ((*it).sourceAddr == sources[i])
            {
                // Delete the source value from the vector.
                rtrInfoPtr->rtrDoNotForwardListVector.erase(it);
                break;
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpDeleteRtrGroupList()
//
// PURPOSE      : Remove a group entry from this list.
//
// RETURN VALUE : TRUE if successfully deleted, FALSE otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
BOOL IgmpDeleteRtrGroupList(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter;
    IgmpGroupInfoForRouter* tmpGrpPtr;
    IgmpGroupInfoForRouter* prev;

    if (!igmp->igmpInterfaceInfo[intfId])
    {
        char errStr[MAX_STRING_LENGTH];
        char ipStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            ipStr);
        sprintf(errStr, "Node %u: Error deleting group\n"
            "         IGMP not running over interface %s!!\n",
            node->nodeId, ipStr);
        ERROR_Assert(FALSE, errStr);
        return FALSE;
    }

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    tmpGrpPtr = igmpRouter->groupListHeadPointer;
    prev = igmpRouter->groupListHeadPointer;

    while (tmpGrpPtr && tmpGrpPtr->groupId != grpAddr)
    {
        prev = tmpGrpPtr;
        tmpGrpPtr = tmpGrpPtr->next;
    }

    // Return if entry doesn't exist.
    if (!tmpGrpPtr) {
        return FALSE;
    }

    // If this was first element of the list
    if (prev == tmpGrpPtr)
    {
        igmpRouter->groupListHeadPointer = tmpGrpPtr->next;
    }
    else
    {
        prev->next = tmpGrpPtr->next;
    }

    MEM_free(tmpGrpPtr);

    igmpRouter->numOfGroups -= 1;

    if (DEBUG) {
        char grpStr[20];
        char intfStr[20];

        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, intfId),
            intfStr);
        printf("Group %s has been removed from router %u's list on "
            "interface %s\n\n",
            grpStr, node->nodeId, intfStr);
    }

    return TRUE;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpCheckRtrGroupList()
//
// PURPOSE      : Check whether the specified group exist in this list.
//
// RETURN VALUE : Group database pointer if found, NULL otherwise.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
IgmpGroupInfoForRouter* IgmpCheckRtrGroupList(
    Node* node,
    NodeAddress grpAddr,
    IgmpGroupInfoForRouter* listHead)
{
    IgmpGroupInfoForRouter* tmpGrpPtr;

    tmpGrpPtr = listHead;

    while (tmpGrpPtr)
    {
        if (tmpGrpPtr->groupId == grpAddr)
        {
            return tmpGrpPtr;
        }

        tmpGrpPtr = tmpGrpPtr->next;
    }

    return NULL;
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SetOlderHostPresentTimer()
// PURPOSE      : sets the timer for an interface which receives a query
//                from an older version host.
// PARAMETERS   : node - this node.
//                grpAddr - multicast group address.
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3SetOlderHostPresentTimer(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    Message* newMsg = NULL;
    char* dataPtr = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    clocktype delay;

    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    thisInterface = igmpData->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface while setting OlderHostPresentTimer\n");

    igmpRouter = thisInterface->igmpRouter;
    ERROR_Assert(igmpRouter,
        "Invalid router info while setting OlderHostPresentTimer\n");
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);
    if (grpPtr)
    {
        if (DEBUG)
        {
            char grpStr[20];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("    Node %u starting older host present timer for group %s"
                "\n", node->nodeId, grpStr);
        }
        // Allocate new message
        newMsg = MESSAGE_Alloc(
                    node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_Igmpv3OlderHostPresentTimer);

        MESSAGE_InfoAlloc(node, newMsg, sizeof(NodeAddress) + sizeof(int));
        dataPtr = MESSAGE_ReturnInfo(newMsg);

        memcpy(dataPtr, &grpAddr, sizeof(NodeAddress));
        dataPtr += sizeof(NodeAddress);
        memcpy(dataPtr, &intfId, sizeof(int));

        delay = (clocktype)
               (((thisInterface->robustnessVariable) * igmpRouter->queryInterval)
                +((igmpRouter->queryResponseInterval * SECOND)
                   /IGMP_QUERY_RESPONSE_SCALE_FACTOR));

        grpPtr->lastOlderHostPresentTimer = node->getNodeTime() + delay;

        // Send timer to self
        MESSAGE_Send(node, newMsg, delay);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SetOlderVerQuerierPresentTimer()
// PURPOSE      : sets the timer for an interface which receives a query
//                from an older version querier.
// PARAMETERS   : node - this node.
//                grpAddr - multicast group address.
//                intfId - this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3SetOlderVerQuerierPresentTimer(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    Message* newMsg = NULL;
    char* dataPtr = NULL;
    clocktype delay;
    IgmpGroupInfoForHost* tempPtr = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpHost* igmpHost = NULL;

    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");

    thisInterface = igmpData->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface while setting OlderVerQuerierPresentTimer\n");

    igmpHost = thisInterface->igmpHost;
    ERROR_Assert(igmpHost,
        "Invalid host info while setting OlderVerQuerierPresentTimer\n");

    // Set the unsolicited report interval value to default value for IGMP
    // version 2 as it was earlier set according to version 3.
    igmpHost->unsolicitedReportInterval = IGMP_UNSOLICITED_REPORT_INTERVAL;

    if (grpAddr == 0)
    {
        tempPtr = igmpHost->groupListHeadPointer;
    }
    else
    {
        tempPtr = IgmpCheckHostGroupList(
            node, grpAddr, igmpHost->groupListHeadPointer);
    }
    if (tempPtr)
    {
        // Whenever a host changes its compatibility mode, it cancels all its
        // pending response and retransmission timers.
        tempPtr->lastHostGrpTimerValue = 0;
        tempPtr->lastHostIntfTimerValue = 0;
        tempPtr->groupDelayTimer = 0;
        tempPtr->recordedSrcList.clear();
        tempPtr->retxAllowSrcList.clear();
        tempPtr->retxBlockSrcList.clear();
        tempPtr->retxSeqNo++;
        tempPtr->retxCount = 0;
        // Set the host state for IGMP version 2 state machine
        tempPtr->hostState = IGMP_HOST_IDLE_MEMBER;
    }
    if (DEBUG)
    {
        char grpStr[20];
        IO_ConvertIpAddressToString(grpAddr, grpStr);
        printf("    Node %u starting older version querier present timer"
            " for group %s\n", node->nodeId, grpStr);
    }
    // Allocate new message
    newMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           GROUP_MANAGEMENT_PROTOCOL_IGMP,
                           MSG_NETWORK_Igmpv3OlderVerQuerierPresentTimer);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(NodeAddress) + sizeof(int));
    dataPtr = MESSAGE_ReturnInfo(newMsg);

    memcpy(dataPtr, &grpAddr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(dataPtr, &intfId, sizeof(int));

    delay = (clocktype)(((thisInterface->robustnessVariable)
                          * igmpHost->querierQueryInterval)
                         +((igmpHost->maxRespTime * SECOND)
                            / IGMP_QUERY_RESPONSE_SCALE_FACTOR));

    igmpHost->lastOlderVerQuerierPresentTimer = node->getNodeTime() + delay;

    // Send timer to self
    MESSAGE_Send(node, newMsg, delay);

}

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
//static
void IgmpCreatePacket(
    Message* msg,
    unsigned char type,
    unsigned char maxResponseTime,
    unsigned groupAddress)
{
    IgmpMessage* ptr = NULL;

    ptr = (IgmpMessage*) MESSAGE_ReturnPacket(msg);

    // Assign packet values
    ptr->ver_type = type;
    ptr->maxResponseTime = maxResponseTime;
    ptr->checksum = 0;
    ptr->groupAddress = groupAddress;
}

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
    UInt8 qrv,
    UInt8 sFlag,
    clocktype queryInterval,
    vector<NodeAddress> sourceAddress)
{
    char* pkt;
    vector<NodeAddress> :: iterator it;
    UInt8 qqic, maxResponseCode, resv = 0;
    UInt8 qrv_sFlag = 0;
    UInt16 checksum = 0;
    UInt16 numSrc = 0;

    pkt = (char*) MESSAGE_ReturnPacket(msg);

    // Set Reserved field (4 bit)
    Igmpv3QuerySetResv(&(qrv_sFlag), resv);
    // Set "Suppress Router side processing" flag field (1 bit)
    Igmpv3QuerySetSFlag(&(qrv_sFlag), sFlag);
    // Set "Querier's Robustness Variable" field (4 bit)
    Igmpv3QuerySetQRV(&(qrv_sFlag), qrv);

    if (maxResponseTime < 128)
    {
        maxResponseCode = maxResponseTime;
    }
    else
    {
        maxResponseCode = Igmpv3ConvertValueToCode(maxResponseTime);
    }
    queryInterval = queryInterval / SECOND;
    if (queryInterval < 128)
    {
        qqic = (UInt8)queryInterval;
    }
    else
    {
        qqic = Igmpv3ConvertValueToCode(queryInterval);
    }
    numSrc = (UInt16)sourceAddress.size();

    memcpy(pkt, &type, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &maxResponseCode, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &checksum, sizeof(UInt16));
    pkt += sizeof(UInt16);
    memcpy(pkt, &groupAddress, sizeof(NodeAddress));
    pkt += sizeof(NodeAddress);
    memcpy(pkt, &qrv_sFlag, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &qqic, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &numSrc, sizeof(UInt16));
    pkt += sizeof(UInt16);
    for (it = sourceAddress.begin(); it < sourceAddress.end(); ++it)
    {
        memcpy(pkt, &(*it), sizeof(NodeAddress));
        pkt += sizeof(NodeAddress);
    }
}

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
    UInt8 type,
    vector<GroupRecord>* Igmpv3GrpRecord)
{
    vector<GroupRecord> :: iterator it;
    vector<NodeAddress> :: iterator srcIt;

    UInt8 reserved = 0;
    UInt16 checksum = 0;
    UInt16 resv = 0;
    UInt16 numSrc = 0;
    numSrc = (UInt16)Igmpv3GrpRecord->size();

    char* pkt;
    pkt = (char*) MESSAGE_ReturnPacket(msg);

    memcpy(pkt, &type, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &reserved, sizeof(UInt8));
    pkt += sizeof(UInt8);
    memcpy(pkt, &checksum, sizeof(UInt16));
    pkt += sizeof(UInt16);
    memcpy(pkt, &resv, sizeof(UInt16));
    pkt += sizeof(UInt16);
    memcpy(pkt, &numSrc, sizeof(UInt16));
    pkt += sizeof(UInt16);
    for (it = Igmpv3GrpRecord->begin(); it < Igmpv3GrpRecord->end(); ++it)
    {
            memcpy(pkt, &(*it).record_type, sizeof(UInt8));
            pkt += sizeof(UInt8);
            memcpy(pkt, &(*it).aux_data_len, sizeof(UInt8));
            pkt += sizeof(UInt8);
            memcpy(pkt, &(*it).numSources, sizeof(UInt16));
            pkt += sizeof(UInt16);
            memcpy(pkt, &(*it).groupAddress, sizeof(Int32));
            pkt += sizeof(Int32);

            for (srcIt = (*it).sourceAddress.begin();
                 srcIt < (*it).sourceAddress.end();
                 ++srcIt)
            {
                memcpy(pkt, &(*srcIt), sizeof(NodeAddress));
                pkt += sizeof(NodeAddress);
            }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3CreateDataFromReportPkt()
// PURPOSE      : Fill Igmpv3 local data structure from report packet.
// PARAMETERS   : msg - message pointer
//                igmpv3ReportPkt - pointer to Igmpv3ReportMessage.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3CreateDataFromReportPkt(
         Message* msg,
         Igmpv3ReportMessage* igmpv3ReportPkt)
{
    char* pkt;
    pkt  = (char*)MESSAGE_ReturnPacket(msg);
    UInt8* version = (UInt8*)pkt;
    igmpv3ReportPkt->ver_type = *version;
    pkt += sizeof(UInt8);
    if (igmpv3ReportPkt->ver_type == IGMP_V3_MEMBERSHIP_REPORT_MSG)
    {
        UInt8* reserved = (UInt8*)pkt;
        igmpv3ReportPkt->reserved = *reserved;
        pkt += sizeof(UInt8);
        UInt16* checksum = (UInt16*)pkt;
        igmpv3ReportPkt->checksum = *checksum;
        pkt += sizeof(UInt16);
        UInt16* resv = (UInt16*)pkt;
        igmpv3ReportPkt->resv = *resv;
        pkt += sizeof(UInt16);
        UInt16* numGrpRecord = (UInt16*)pkt;
        igmpv3ReportPkt->numGrpRecords = *numGrpRecord;
        pkt += sizeof(UInt16);
        for (int i = 0; i < igmpv3ReportPkt->numGrpRecords; i++)
        {
            GroupRecord grpRecord;
            memset(&grpRecord, 0, sizeof(grpRecord));
            UInt8* recordType = (UInt8*)pkt;
            grpRecord.record_type = *recordType;
            pkt += sizeof(UInt8);
            UInt8* auxDataLen = (UInt8*)pkt;
            grpRecord.aux_data_len = *auxDataLen;
            pkt += sizeof(UInt8);
            UInt16* numSrc = (UInt16*)pkt;
            grpRecord.numSources = *numSrc;
            pkt += sizeof(UInt16);
            NodeAddress* grpAddr = (NodeAddress*)pkt;
            grpRecord.groupAddress = *grpAddr;
            pkt += sizeof(NodeAddress);
            for (int j = 0; j < grpRecord.numSources; j++)
            {
                NodeAddress* src = (NodeAddress*)pkt;
                grpRecord.sourceAddress.push_back(*src);
                pkt += sizeof(NodeAddress);
            }
            igmpv3ReportPkt->groupRecord.push_back(grpRecord);
        }
    }
    else
    {
        // In case when a version 3 router receives a version 2 membership
        // report or version 2 leave report, translate this report such that
        // it can be used by IGMP version 3 state machine.
        UInt8* reserved = (UInt8*)pkt;
        igmpv3ReportPkt->reserved = *reserved;
        pkt += sizeof(UInt8);
        UInt16* checksum = (UInt16*)pkt;
        igmpv3ReportPkt->checksum = *checksum;
        pkt += sizeof(UInt16);
        NodeAddress* grpAddr = (NodeAddress*)pkt;
        igmpv3ReportPkt->resv = 0;
        // number of group records is set to one ,as record type is set to
        // is_exclude mode when translating IGMPv2 report message and set to
        // to_include mode when translating IGMPv2 leave message.
        igmpv3ReportPkt->numGrpRecords = 1;

        GroupRecord grpRecord;
        memset(&grpRecord, 0, sizeof(grpRecord));

        if (igmpv3ReportPkt->ver_type == IGMP_MEMBERSHIP_REPORT_MSG)
        {
            grpRecord.record_type = MODE_IS_EXCLUDE;
        }
        else if (igmpv3ReportPkt->ver_type == IGMP_LEAVE_GROUP_MSG)
        {
            grpRecord.record_type = CHANGE_TO_IN;
        }
        grpRecord.aux_data_len = 0;
        grpRecord.numSources = 0;
        grpRecord.groupAddress = *grpAddr;
        // Source address field in the group record should be empty.
        igmpv3ReportPkt->groupRecord.push_back(grpRecord);
    }

}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3CreateDataFromQueryPkt()
// PURPOSE      : Fill Igmpv3 local data structure from query packet.
// PARAMETERS   : msg - message pointer
//                igmpv3QueryMsg - pointer to IgmpQueryMessage.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3CreateDataFromQueryPkt(
         Message* msg,
         IgmpQueryMessage* igmpv3QueryMsg)
{
    char* pkt;
    pkt  = (char*)MESSAGE_ReturnPacket(msg);
    // Fill version in query data structure
    UInt8* version = (UInt8*)pkt;
    igmpv3QueryMsg->ver_type = *version;
    pkt += sizeof(UInt8);
    // Fill maximum response code in query data structure
    UInt8* maxResponse = (UInt8*)pkt;
    igmpv3QueryMsg->maxResponseCode = *maxResponse;
    pkt += sizeof(UInt8);
    // Fill checksum in query data structure
    UInt16* checksum = (UInt16*)pkt;
    igmpv3QueryMsg->checksum = *checksum;
    pkt += sizeof(UInt16);
    // Fill group address in query data structure
    NodeAddress* grpAddr = (NodeAddress*)pkt;
    igmpv3QueryMsg->groupAddress = *grpAddr;
    pkt += sizeof(NodeAddress);
    // Fill Querier's Robustness Variable and SFlag in query data structure
    UInt8* qrv_Resv_S = (UInt8*)pkt;
    igmpv3QueryMsg->query_qrv_sFlag = *qrv_Resv_S;
    pkt += sizeof(UInt8);
    // Fill Querier's Query Interval Code in query data structure
    UInt8* qqic = (UInt8*)pkt;
    igmpv3QueryMsg->qqic = *qqic;
    pkt += sizeof(UInt8);
    // Fill number of sources in query data structure
    UInt16* numSrc = (UInt16*)pkt;
    igmpv3QueryMsg->numSources = *numSrc;
    pkt += sizeof(UInt16);
    // If the number of sources is not zero fill the source addresses in
    // query data structure.
    if (igmpv3QueryMsg->numSources != 0)
    {
        for (int i = 0; i < igmpv3QueryMsg->numSources;i++)
        {
            NodeAddress* srcAddr = (NodeAddress*)pkt;
            igmpv3QueryMsg->sourceAddress.push_back(*srcAddr);
            pkt += sizeof(NodeAddress);
        }
    }

}
//---------------------------------------------------------------------------
// FUNCTION     : IgmpSendQuery()
// PURPOSE      : Send Igmp Query Message on specified interface.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void IgmpSendQuery(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    UInt8 queryResponseInterval,
    UInt8 lastMemberQueryInterval,
    clocktype queryInterval)
{
    UInt8 queryRobustnessVariable = 0;
    UInt8 maxResponseTime = 0;
    NodeAddress srcAddr = 0;
    NodeAddress dstAddr = 0;
    UInt8 SFlag = 0;
    Int32 pktSize = 0;
    IgmpInterfaceInfoType* thisInterface = NULL;
    Message* newMsg = NULL;
    IgmpRouter* router;
    vector<NodeAddress> srcAddressVector;

    // RtrJoinStart
    IgmpMessage igmpv2Pkt;
    IgmpQueryMessage igmpv3QueryPkt;
    // RtrJoinEnd


    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    //Red IAHEP Node Can Not Send Query To IAHEP Node
#ifdef CYBER_CORE
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    if (ip->iahepEnabled)
    {
        if ((ip->iahepData->nodeType == RED_NODE &&
        IsIAHEPRedSecureInterface(node, intfId)) ||
        ip->iahepData->nodeType == IAHEP_NODE)
        {
           return;
        }
    }

#endif //CYBER_CORE

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    router = thisInterface->igmpRouter;
    queryRobustnessVariable = (UInt8)thisInterface->robustnessVariable;
    if (grpAddr == 0)
    {
        maxResponseTime = queryResponseInterval;
    }
    else
    {
        maxResponseTime = lastMemberQueryInterval;
    }

    if (thisInterface->igmpVersion == IGMP_V2)
    {
        // Allocate new message
        newMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_IgmpData);

        MESSAGE_PacketAlloc(node,
                            newMsg,
                            sizeof(IgmpMessage),
                            TRACE_IGMP);


        // Allocate IGMP packet
        IgmpCreatePacket(newMsg, IGMP_QUERY_MSG, maxResponseTime, grpAddr);
        // RtrJoinStart
         memcpy(&igmpv2Pkt, newMsg->packet, sizeof(IgmpMessage));
        // RtrJoinEnd

    }
    else if (thisInterface->igmpVersion == IGMP_V3)
    {
        // Size of general query to be sent.
        pktSize = IGMPV3_QUERY_FIXED_SIZE;

        // Build IGMPv3 General Query
        // Allocate new message
        newMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_IgmpData);

        MESSAGE_PacketAlloc(node,
                            newMsg,
                            pktSize,
                            TRACE_IGMP);

        // Allocate IGMPv3 query packet
        Igmpv3CreateQueryPacket(newMsg,
                                IGMP_QUERY_MSG,
                                maxResponseTime,
                                grpAddr,
                                queryRobustnessVariable,
                                SFlag,
                                queryInterval,
                                srcAddressVector);
         // RtrJoinStart
        Igmpv3CreateDataFromQueryPkt(newMsg, &igmpv3QueryPkt);
        // RtrJoinEnd

    }


    // Get IP address for this interface
    srcAddr = NetworkIpGetInterfaceAddress(node, intfId);

    // Group specific query is sent to group address.
    // For general query (group address is 0) it is sent to all systems
    // group multicast address
    if (grpAddr)
    {
        dstAddr = grpAddr;
    }
    else
    {
        dstAddr = IGMP_ALL_SYSTEMS_GROUP_ADDR;
    }

    if (DEBUG)
    {
        char netStr[20];
        char timeStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
        IO_ConvertIpAddressToString(NetworkIpGetInterfaceNetworkAddress(node,
                                        intfId), netStr);

        if (thisInterface->igmpStat.igmpTotalMsgSend == 0)
        {
            printf("Node %u starts up as a Querier on network %s\n",
                node->nodeId, netStr);
        }

        if (grpAddr == 0)
        {
            printf("Node %u send general query to subnet %s at %ss\n\n",
                node->nodeId, netStr, timeStr);
        }
        else
        {
            char grpStr[MAX_ADDRESS_STRING_LENGTH];

            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("Node %u send group specific query for group %s "
                "to subnet %s at %ss\n\n",
                node->nodeId, grpStr, netStr, timeStr);
        }
    }

    // Send query message.
    thisInterface->igmpStat.igmpTotalMsgSend += 1;
    thisInterface->igmpStat.igmpTotalQuerySend += 1;

    if (grpAddr == 0)
    {
        thisInterface->igmpStat.igmpGenQuerySend += 1;
    }
    else
    {
        thisInterface->igmpStat.igmpGrpSpecificQuerySend += 1;
    }

    NetworkIpSendRawMessageToMacLayer(node,
                                      newMsg,
                                      srcAddr,
                                      dstAddr,
                                      IPTOS_PREC_INTERNETCONTROL,
                                      IPPROTO_IGMP,
                                      1,
                                      intfId,
                                      ANY_DEST);

    // RtrJoinStart
    // Act as if we've received a Query

    //If this is a host also then the
    //stats for query received should be incremented

    if (grpAddr == 0 && thisInterface->igmpHost->groupCount != 0)
    {
        thisInterface->igmpStat.igmpGenQueryReceived += 1;
        thisInterface->igmpStat.igmpTotalQueryReceived += 1;
        igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalMsgReceived += 1;

        if (thisInterface->igmpVersion == IGMP_V2)
        {
            IgmpHostHandleQuery(node, &igmpv2Pkt, thisInterface, intfId);
        }
        else if (thisInterface->igmpVersion == IGMP_V3)
        {
            Igmpv3HostHandleQuery(node, &igmpv3QueryPkt, thisInterface, intfId);
        }
    }
    else if (grpAddr != 0 && thisInterface->igmpHost->groupCount != 0)
    {
        IgmpGroupInfoForHost* tempGrpPtr;
        tempGrpPtr = IgmpCheckHostGroupList(node,
                                            grpAddr,
                                            thisInterface->igmpHost->
                                                groupListHeadPointer);

        // If the group exist,then only we have to
        //increment the stats for group specific query
        if (tempGrpPtr)
        {
            thisInterface-> igmpStat.igmpGrpSpecificQueryReceived += 1;
            thisInterface->igmpStat.igmpTotalQueryReceived += 1;
            igmp->igmpInterfaceInfo[intfId]->
                igmpStat.igmpTotalMsgReceived += 1;
            if (thisInterface->igmpVersion == IGMP_V2)
            {
                IgmpHostHandleQuery(node, &igmpv2Pkt, thisInterface, intfId);
            }
            else if (thisInterface->igmpVersion == IGMP_V3)
            {
                Igmpv3HostHandleQuery(node, &igmpv3QueryPkt, thisInterface, intfId);
            }
        }
    }
    //IgmpHostHandleQuery(node, &igmpPkt, thisInterface, intfId);
// RtrJoinEnd
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SendGrpSpecificQuery()
// PURPOSE      : Send Igmp version 3 Group and Source Specific Query
//                Message on specified interface.
// PARAMETERS   : node - this node.
//                grpAddr - multicast group address that need to be queried.
//                intfId - this interface index.
//                queryInterval - query interval value.
//                grpRetransmitCount - keeps a count of the number of times
//                IGMPv3 group specific query is retransmitted.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3SendGrpSpecificQuery(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    clocktype queryInterval,
    Int32 grpRetransmitCount)
{
    UInt8 queryRobustnessVariable = 0;
    UInt8 maxResponseTime = 0;
    UInt8 sFlag = 0;
    Int32 pktSize = 0;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpQueryMessage igmpv3GrpSpecifcQueryPkt;
    Message* newMsg = NULL;
    IgmpRouter* router = NULL;
    IgmpGroupInfoForRouter* tempGrpPtr = NULL;
    NodeAddress dstAddr, srcAddr;
    vector<NodeAddress> srcList;
    clocktype lastMemberQueryInterval = (clocktype)0;

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    router = thisInterface->igmpRouter;
    queryRobustnessVariable = (UInt8)thisInterface->robustnessVariable;
    bool isQueryRcvd = FALSE;

    // Calculating the size of group specific query to be sent.
    pktSize = IGMPV3_QUERY_FIXED_SIZE;

    tempGrpPtr = IgmpCheckRtrGroupList(node,
                                       grpAddr,
                                       router->groupListHeadPointer);
    if (!tempGrpPtr)
    {
        if (DEBUG)
        {
            char grpStr[MAX_ADDRESS_STRING_LENGTH];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
                printf("Node %u IGMPv3 router group pointer for group %s "
                "not present\n\n",
                node->nodeId, grpStr);
        }
        return;
    }
    maxResponseTime = (UInt8) tempGrpPtr->lastMemberQueryInterval;
    lastMemberQueryInterval = ((tempGrpPtr->lastMemberQueryInterval / 10)
                               * SECOND);
    if (grpRetransmitCount > 0)
    {
        if ((tempGrpPtr->lastGroupTimerValue - node->getNodeTime()) >
            (lastMemberQueryInterval * tempGrpPtr->lastMemberQueryCount))
        {
            sFlag = 1;
        }
        // Allocate new message
        newMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_IgmpData);
        MESSAGE_PacketAlloc(node,
                            newMsg,
                            pktSize,
                            TRACE_IGMP);

        // Allocate IGMPv3 query packet with sources whose source
        // timer is less than or equal to LMQT.
        Igmpv3CreateQueryPacket(newMsg,
                                IGMP_QUERY_MSG,
                                maxResponseTime,
                                grpAddr,
                                queryRobustnessVariable,
                                sFlag,
                                queryInterval,
                                srcList);

        // RtrJoinStart
        Igmpv3CreateDataFromQueryPkt(newMsg, &igmpv3GrpSpecifcQueryPkt);
        isQueryRcvd = TRUE;
        // RtrJoinEnd

        // Get IP address for this interface
        srcAddr = NetworkIpGetInterfaceAddress(node, intfId);

        // Group and source specific query is sent to group address.
        dstAddr = grpAddr;

        if (DEBUG)
        {
            char netStr[20];
            char timeStr[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
            IO_ConvertIpAddressToString(NetworkIpGetInterfaceNetworkAddress(node,
                                            intfId), netStr);

            if (thisInterface->igmpStat.igmpTotalMsgSend == 0)
            {
                printf("Node %u starts up as a Querier on network %s\n",
                    node->nodeId, netStr);
            }

            char grpStr[MAX_ADDRESS_STRING_LENGTH];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("Node %u send IGMPv3 group specific query for group %s "
                "to subnet %s at %ss\n\n",
                node->nodeId, grpStr, netStr, timeStr);
        }

        // Send query message.
        NetworkIpSendRawMessageToMacLayer(node,
                                          newMsg,
                                          srcAddr,
                                          dstAddr,
                                          IPTOS_PREC_INTERNETCONTROL,
                                          IPPROTO_IGMP,
                                          1,
                                          intfId,
                                          ANY_DEST);
        grpRetransmitCount -= 1;
        thisInterface->igmpStat.igmpTotalMsgSend += 1;
        thisInterface->igmpStat.igmpTotalQuerySend += 1;
        thisInterface->igmpStat.igmpGrpSpecificQuerySend += 1;
    }
    if (grpRetransmitCount)
    {
        Message* msg;
        char* infoPtr;
        clocktype timerValue;

        // Allocate new message
        msg = MESSAGE_Alloc(
                   node,
                   NETWORK_LAYER,
                   GROUP_MANAGEMENT_PROTOCOL_IGMP,
                   MSG_NETWORK_Igmpv3GrpSpecificQueryRetransmitTimer);

        MESSAGE_InfoAlloc(node,
                          msg,
                          sizeof(NodeAddress)
                           + sizeof(int)
                           + sizeof(int));
        infoPtr = MESSAGE_ReturnInfo(msg);

        memcpy(infoPtr, &grpAddr, sizeof(NodeAddress));
        infoPtr += sizeof(NodeAddress);
        memcpy(infoPtr, &intfId, sizeof(Int32));
        infoPtr += sizeof(Int32);
        memcpy(infoPtr + sizeof(Int32), &grpRetransmitCount, sizeof(Int32));

        timerValue = lastMemberQueryInterval;
        // Send timer to self for the group to be retransmitted
        MESSAGE_Send(node, msg, timerValue);
    }

    // RtrJoinStart
    // Act as if we've received a Query

    //If this is a host also then the
    //stats for query received should be incremented

    if ((isQueryRcvd) && (thisInterface->igmpHost->groupCount != 0))
    {
        IgmpGroupInfoForHost* tempGrpPtr;
        tempGrpPtr = IgmpCheckHostGroupList(node,
                                            grpAddr,
                                            thisInterface->igmpHost->
                                                groupListHeadPointer);

        // If the group exist,then only we have to increment the stats
        // for group and source specific query.
        if (tempGrpPtr)
        {
            thisInterface-> igmpStat.igmpGrpSpecificQueryReceived += 1;
            thisInterface->igmpStat.igmpTotalQueryReceived += 1;
            igmp->igmpInterfaceInfo[intfId]->
                igmpStat.igmpTotalMsgReceived += 1;
            Igmpv3HostHandleQuery(node, &igmpv3GrpSpecifcQueryPkt, thisInterface, intfId);
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3SendGrpAndSourceSpecificQuery()
// PURPOSE      : Send Igmp version 3 Group and Source Specific Query
//                Message on specified interface.
// PARAMETERS   : node - this node.
//                grpAddr - multicast group address that need to be queried.
//                intfId - this interface index.
//                queryInterval - query interval value.
//                srcAddressVector - vector of source addresses that need
//                to be queried.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3SendGrpAndSrcSpecificQuery(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    clocktype queryInterval,
    vector<NodeAddress> srcAddressVector)
{
    UInt8 queryRobustnessVariable = 0;
    UInt8 maxResponseTime = 0;
    Int32 pktSize = 0;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpQueryMessage igmpPktClearSFlag, igmpPktSetSFlag;
    Message* clearSFlagMsg = NULL;
    Message* setSFlagMsg = NULL;
    IgmpRouter* router = NULL;
    IgmpGroupInfoForRouter* tempGrpPtr = NULL;
    NodeAddress dstAddr, srcAddr;
    vector<NodeAddress> srcListSetSFlag, srcListClearSFlag, retransmitSrcList;
    vector<NodeAddress> :: iterator it;
    UInt32 i,j,k;

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    memset(&igmpPktClearSFlag, 0, sizeof(IgmpQueryMessage));
    memset(&igmpPktSetSFlag, 0, sizeof(IgmpQueryMessage));

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    queryRobustnessVariable = (UInt8)thisInterface->robustnessVariable;
    router = thisInterface->igmpRouter;

    // Calculating the size of query to be sent.
    pktSize = IGMPV3_QUERY_FIXED_SIZE;
    for (it = srcAddressVector.begin();
         it < srcAddressVector.end();
         ++it)
    {
        pktSize += sizeof(NodeAddress);
    }
    tempGrpPtr = IgmpCheckRtrGroupList(node,
                                       grpAddr,
                                       router->groupListHeadPointer);
    if (tempGrpPtr)
    {
        maxResponseTime = (UInt8)tempGrpPtr->lastMemberQueryInterval;
        // Allocate new message
        clearSFlagMsg = MESSAGE_Alloc(node,
                                      NETWORK_LAYER,
                                      GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                      MSG_NETWORK_IgmpData);
        MESSAGE_PacketAlloc(node,
                            clearSFlagMsg,
                            pktSize,
                            TRACE_IGMP);

        // Allocate new message
        setSFlagMsg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_IgmpData);

        MESSAGE_PacketAlloc(node,
                            setSFlagMsg,
                            pktSize,
                            TRACE_IGMP);
        for (i = 0; i < srcAddressVector.size(); i++)
        {
            for (j = 0; j < tempGrpPtr->rtrForwardListVector.size(); j++)
            {
                if ((tempGrpPtr->rtrForwardListVector[j].sourceAddr
                     == srcAddressVector[i])
                   && (tempGrpPtr->rtrForwardListVector[j].retransmitCount > 0))
                {
                    if (tempGrpPtr->rtrForwardListVector[j].sourceTimer >
                            (((tempGrpPtr->lastMemberQueryInterval / 10)
                               * SECOND) * tempGrpPtr->lastMemberQueryCount))
                    {
                        srcListSetSFlag.push_back(srcAddressVector[i]);
                    }
                    else
                    {
                        srcListClearSFlag.push_back(srcAddressVector[i]);
                    }
                    retransmitSrcList.push_back(srcAddressVector[i]);
                    tempGrpPtr->rtrForwardListVector[j].retransmitCount -= 1;
                }
            }
        }
        if (!srcListClearSFlag.empty())
        {
            // Allocate IGMPv3 query packet with sources whose source
            // timer is less than or equal to LMQT.
            Igmpv3CreateQueryPacket(clearSFlagMsg,
                                    IGMP_QUERY_MSG,
                                    maxResponseTime,
                                    grpAddr,
                                    queryRobustnessVariable,
                                    0, // reset the sflag
                                    queryInterval,
                                    srcListClearSFlag);
            // RtrJoinStart
            Igmpv3CreateDataFromQueryPkt(clearSFlagMsg, &igmpPktClearSFlag);
            // RtrJoinEnd
        }
        if (!srcListSetSFlag.empty())
        {
            // Allocate IGMPv3 query packet with sources whose source
            // timer is greater than LMQT.
            Igmpv3CreateQueryPacket(setSFlagMsg,
                                    IGMP_QUERY_MSG,
                                    maxResponseTime,
                                    grpAddr,
                                    queryRobustnessVariable,
                                    1, // set the sflag
                                    queryInterval,
                                    srcListSetSFlag);
            // RtrJoinStart
                Igmpv3CreateDataFromQueryPkt(setSFlagMsg, &igmpPktSetSFlag);
            // RtrJoinEnd
        }

        // Get IP address for this interface
        srcAddr = NetworkIpGetInterfaceAddress(node, intfId);

        // Group and source specific query is sent to group address.
        dstAddr = grpAddr;

        if (DEBUG)
        {
            char netStr[20];
            char timeStr[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
            IO_ConvertIpAddressToString(
                NetworkIpGetInterfaceNetworkAddress(node, intfId), netStr);

            if (thisInterface->igmpStat.igmpTotalMsgSend == 0)
            {
                printf("Node %u starts up as a Querier on network %s\n",
                    node->nodeId, netStr);
            }

            char grpStr[MAX_ADDRESS_STRING_LENGTH];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("Node %u send group and source specific query for"
                " group %s to subnet %s at %ss\n\n",
                node->nodeId, grpStr, netStr, timeStr);
        }

        // Send query message.


        if (!srcListSetSFlag.empty())
        {
            NetworkIpSendRawMessageToMacLayer(node,
                                              setSFlagMsg,
                                              srcAddr,
                                              dstAddr,
                                              IPTOS_PREC_INTERNETCONTROL,
                                              IPPROTO_IGMP,
                                              1,
                                              intfId,
                                              ANY_DEST);
            thisInterface->igmpStat.igmpTotalMsgSend += 1;
            thisInterface->igmpStat.igmpTotalQuerySend += 1;
            thisInterface->igmpStat.igmpGrpAndSourceSpecificQuerySend += 1;
        }
        if (!srcListClearSFlag.empty())
        {
            NetworkIpSendRawMessageToMacLayer(node,
                                              clearSFlagMsg,
                                              srcAddr,
                                              dstAddr,
                                              IPTOS_PREC_INTERNETCONTROL,
                                              IPPROTO_IGMP,
                                              1,
                                              intfId,
                                              ANY_DEST);
            thisInterface->igmpStat.igmpTotalMsgSend += 1;
            thisInterface->igmpStat.igmpTotalQuerySend += 1;
            thisInterface->igmpStat.igmpGrpAndSourceSpecificQuerySend += 1;
        }
        if (!retransmitSrcList.empty())
        {
            Message* newMsg;
            char* infoPtr;
            clocktype timerValue;
            UInt32 numSrc;

            numSrc = retransmitSrcList.size();
            // Allocate new message
            newMsg = MESSAGE_Alloc(
               node,
               NETWORK_LAYER,
               GROUP_MANAGEMENT_PROTOCOL_IGMP,
               MSG_NETWORK_Igmpv3GrpAndSrcSpecificQueryRetransmitTimer);

            MESSAGE_InfoAlloc(node,
                              newMsg,
                              sizeof(NodeAddress)
                               + sizeof(int)
                               + sizeof(int)
                               + sizeof(NodeAddress) * retransmitSrcList.size());
            infoPtr = MESSAGE_ReturnInfo(newMsg);
            memcpy(infoPtr, &grpAddr, sizeof(NodeAddress));
            infoPtr += sizeof(NodeAddress);
            memcpy(infoPtr, &intfId, sizeof(Int32));
            infoPtr += sizeof(Int32);
            memcpy(infoPtr, &numSrc, sizeof(Int32));
            infoPtr += sizeof(Int32);
            for (k = 0; k < retransmitSrcList.size(); k++)
            {
                memcpy(infoPtr, &retransmitSrcList[k], sizeof(NodeAddress));
                infoPtr += sizeof(NodeAddress);
            }
            timerValue = (tempGrpPtr->lastMemberQueryInterval / 10) * SECOND;

            // Send timer to self for the retransmit list
            MESSAGE_Send(node, newMsg, timerValue);
        }
    }

    // RtrJoinStart
    // Act as if we've received a Query

    //If this is a host also then the
    //stats for query received should be incremented
    // If retransmitlist is non-empty, then we must have sent the Query. Only
    // in that case, we must treat as if we have got the query.
    if (!retransmitSrcList.empty() &&
        (thisInterface->igmpHost->groupCount != 0))
    {
        IgmpGroupInfoForHost* tempGrpPtr;
        tempGrpPtr = IgmpCheckHostGroupList(node,
                                            grpAddr,
                                            thisInterface->igmpHost->
                                                groupListHeadPointer);

        // If the group exist,then only we have to increment the stats
        // for group and source specific query.
        if (tempGrpPtr)
        {
            thisInterface-> igmpStat.igmpGrpAndSourceSpecificQueryReceived += 1;
            thisInterface->igmpStat.igmpTotalQueryReceived += 1;
            igmp->igmpInterfaceInfo[intfId]->
                igmpStat.igmpTotalMsgReceived += 1;
            if (!srcListSetSFlag.empty())
            {
                Igmpv3HostHandleQuery(node, &igmpPktSetSFlag, thisInterface, intfId);
            }
            if (!srcListClearSFlag.empty())
            {
                Igmpv3HostHandleQuery(node, &igmpPktClearSFlag, thisInterface, intfId);
            }
        }
    }

}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpSendMembershipReport()
// PURPOSE      : Send Igmp Membership Report Message on specified interface.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void IgmpSendMembershipReport(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId,
    bool sendCurrentStateRecord,
    vector<GroupRecord>* Igmpv3GrpRecord)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    IgmpInterfaceInfoType* thisInterface;
    Message* newMsg;
    Int32 pktSize;
    NodeAddress srcAddr;
    NodeAddress dstAddr;
    IgmpInterfaceType igmpInterfaceType = IGMP_DEFAULT_INTERFACE;
    vector<GroupRecord> :: iterator it;
    vector<struct RetxSourceInfo> :: iterator retxListIter;
// RtrJoinStart
    IgmpMessage igmpv2Pkt;
    Igmpv3ReportMessage igmpv3ReportPkt;
// RtrJoinEnd
    IgmpHost* igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;
    vector<struct GroupRecord> igmpv3GroupRecord;
    thisInterface = igmp->igmpInterfaceInfo[intfId];
    UInt32 i = 0;

    if (igmpHost->hostCompatibilityMode == IGMP_V2)
    {
        // Allocate new message
        newMsg = MESSAGE_Alloc(
                    node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_IgmpData);

        MESSAGE_PacketAlloc(node, newMsg, sizeof(IgmpMessage), TRACE_IGMP);

        // Allocate IGMP packet
        IgmpCreatePacket(
            newMsg, IGMP_MEMBERSHIP_REPORT_MSG, 0, grpAddr);

        // RtrJoinStart
        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER)
        {
            memcpy(&igmpv2Pkt, newMsg->packet, sizeof(IgmpMessage));
        }// RtrJoinEnd
        // Membership report should be sent to router as well as members of
        // the group.So it is to be sent to all system group.

        //according to RFC 2236, a host multicasts membership report to the
        //group. Hence the destination address should be the group address in
        //the packet
        dstAddr = grpAddr;
    }
    else
    {
        if (sendCurrentStateRecord == FALSE)
        {
            // Search for specified group
            IgmpGroupInfoForHost* grpPtr =
                IgmpCheckHostGroupList(node,
                                       grpAddr,
                                       igmpHost->groupListHeadPointer);
            GroupRecord grpRecord;
            memset(&grpRecord, 0, sizeof(GroupRecord));

            if (!grpPtr)
            {
                return;
            }

            // if filter-mode retxCount is non-zero,
            // then send filter-mode-change record.
            // The retxCount should then be decremented by 1, and rescheduled.
            // If it becomes 0, delete the record, and do not reschedule.
            if (grpPtr->retxCount)
            {
                grpRecord.aux_data_len = 0;
                grpRecord.groupAddress = grpAddr;
                grpRecord.numSources = 0;

                if (grpPtr->retxfilterMode == INCLUDE)
                {
                    // All the sources in the retxAllowSrcList
                    // with non-0 retxCount should also be
                    // sent as TO_IN(s1,s2....).
                    grpRecord.record_type = CHANGE_TO_IN;
                    for (i = 0; i < grpPtr->retxAllowSrcList.size(); i++)
                    {
                        if (grpPtr->retxAllowSrcList[i].retxCount)
                        {
                            grpRecord.sourceAddress.push_back(
                                grpPtr->retxAllowSrcList[i].sourceAddress);
                            grpRecord.numSources++;
                            //decrement the retxCount as we will be sending this FCR.
                            grpPtr->retxAllowSrcList[i].retxCount--;
                        }
                    }
                    Igmpv3GrpRecord->push_back(grpRecord);
                }
                else //Exclude mode
                {
                    // All the sources in the retxBlockSrcList
                    // with non-0 retxCount should also be
                    // sent as TO_EX(s21,s2....).

                    grpRecord.record_type = CHANGE_TO_EX;
                    for (i = 0; i < grpPtr->retxBlockSrcList.size(); i++)
                    {
                        if (grpPtr->retxBlockSrcList[i].retxCount)
                        {
                            grpRecord.sourceAddress.push_back(
                                grpPtr->retxBlockSrcList[i].sourceAddress);
                            grpRecord.numSources++;
                            //decrement the retxCount as we will be sending this FCR.
                            grpPtr->retxBlockSrcList[i].retxCount--;
                        }
                    }
                    Igmpv3GrpRecord->push_back(grpRecord);
                }
                //decrement the retxCount as we will be sending this FCR.
                grpPtr->retxCount--;
            }
            else // no pending filter change record
            {
                // Check if there are any pending BLOCK sourcelistchange records.
                // If yes, send them.
                grpRecord.aux_data_len = 0;
                grpRecord.groupAddress = grpAddr;
                grpRecord.numSources = 0;
                grpRecord.record_type = BLOCK_OLD_SRC;
                bool pushRecord = FALSE;
                for (i = 0; i < grpPtr->retxBlockSrcList.size(); i++)
                {
                    if (grpPtr->retxBlockSrcList[i].retxCount)
                    {
                        pushRecord = TRUE;
                        grpRecord.sourceAddress.push_back(
                                grpPtr->retxBlockSrcList[i].sourceAddress);
                        grpRecord.numSources++;
                        //decrement the retxCount as we will be sending this FCR.
                        grpPtr->retxBlockSrcList[i].retxCount--;
                    }
                }
                if (pushRecord)
                {
                    Igmpv3GrpRecord->push_back(grpRecord);
                }

                // Check if there are any pending ALLOW sourcelistchange records.
                // If yes, send them.
                grpRecord.aux_data_len = 0;
                grpRecord.groupAddress = grpAddr;
                grpRecord.numSources = 0;
                grpRecord.record_type = ALLOW_NEW_SRC;
                grpRecord.sourceAddress.clear();
                pushRecord = FALSE;
                for (i = 0; i < grpPtr->retxAllowSrcList.size(); i++)
                {
                    if (grpPtr->retxAllowSrcList[i].retxCount)
                    {
                        pushRecord = TRUE;
                        grpRecord.sourceAddress.push_back(
                            grpPtr->retxAllowSrcList[i].sourceAddress);
                        grpRecord.numSources++;
                        //decrement the retxCount as we will be sending this FCR.
                        grpPtr->retxAllowSrcList[i].retxCount--;
                    }
                }
                if (pushRecord)
                {
                    Igmpv3GrpRecord->push_back(grpRecord);
                }
            }

            // Delete the sourceRecords that have 0 retxCount from AllowList.
            retxListIter = grpPtr->retxAllowSrcList.begin();
            while (retxListIter != grpPtr->retxAllowSrcList.end())
            {
                if ((*retxListIter).retxCount == 0)
                {
                    // erase this element
                    retxListIter = grpPtr->retxAllowSrcList.erase(retxListIter);
                }
                else
                {
                    ++retxListIter;
                }
            }

            // Delete the sourceRecords that have 0 retxCount from BlockList.
            retxListIter = grpPtr->retxBlockSrcList.begin();
            while (retxListIter != grpPtr->retxBlockSrcList.end())
            {
                if ((*retxListIter).retxCount == 0)
                {
                    // erase this element
                    retxListIter = grpPtr->retxBlockSrcList.erase(retxListIter);
                }
                else
                {
                    ++retxListIter;
                }
            }
        }
        // Calculating the size of report to be sent.
        pktSize = IGMPV3_REPORT_FIXED_SIZE;
        for (it = Igmpv3GrpRecord->begin();
             it < Igmpv3GrpRecord->end(); ++it)
        {
            pktSize += IGMPV3_REPORT_FIXED_SIZE +
                (sizeof(NodeAddress) * (*it).numSources);
        }

        // Allocate new IGMPv3 report message
        newMsg = MESSAGE_Alloc(
                    node,
                    NETWORK_LAYER,
                    GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_IgmpData);

        MESSAGE_PacketAlloc(node, newMsg, pktSize, TRACE_IGMP);

        Igmpv3CreateReportPacket(newMsg,
                                 IGMP_V3_MEMBERSHIP_REPORT_MSG,
                                 Igmpv3GrpRecord);
        // RtrJoinStart
        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER)
        {
            Igmpv3CreateDataFromReportPkt(newMsg, &igmpv3ReportPkt);
        }// RtrJoinEnd

        // According to RFC 3376 Version 3 Reports are sent with an IP
        // destination address of 224.0.0.22, to which all IGMPv3-capable
        //  multicast routers listen.
        dstAddr = IGMP_V3_ALL_ROUTERS_GROUP_ADDR;
    }

    // Get IP address for this interface
    srcAddr = NetworkIpGetInterfaceAddress(node, intfId);

    if (DEBUG)
    {
        char grpStr[20];
        char netStr[20];
        char timeStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceNetworkAddress(node, intfId),
            netStr);

        printf("Node %u send membership report for group %s "
            "to subnet %s at %ss\n\n",
            node->nodeId, grpStr, netStr, timeStr);
    }

    if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
    {
        if (intfId ==
            NetworkIpGetInterfaceIndexFromAddress(
               node,igmp->igmpUpstreamInterfaceAddr))
        {
            igmpInterfaceType = IGMP_UPSTREAM;
        }
        else
        {
            igmpInterfaceType  =IGMP_DOWNSTREAM;
        }
    }

    if (!igmp->igmpInterfaceInfo[intfId]->isAdHocMode
        || igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_HOST
        || igmpInterfaceType == IGMP_UPSTREAM)
    {
        // Send membership report.
        thisInterface->igmpStat.igmpTotalMsgSend += 1;
        thisInterface->igmpStat.igmpTotalReportSend += 1;
        if (igmpHost->hostCompatibilityMode == IGMP_V2)
        {
            thisInterface->igmpStat.igmpv2MembershipReportSend += 1;
        }
        else
        {
            thisInterface->igmpStat.igmpv3MembershipReportSend += 1;
        }
#ifdef CYBER_CORE
        NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
        if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE &&
            IsIAHEPBlackSecureInterface(node, intfId))
        {
            NodeAddress mappedGrpAddr = IAHEPGetMulticastBroadcastAddressMapping(
                                            node, ip->iahepData, grpAddr);

            // TODO: upgrade to IGMPv3, cannot include src address in IGMPv2
            IAHEPCreateIgmpJoinLeaveMessage(
                node,
                mappedGrpAddr,
                IGMP_MEMBERSHIP_REPORT_MSG,
                NULL);

            ip->iahepData->grpAddressList->insert(grpAddr);

            ip->iahepData->updateAmdTable->getAMDTable(0)->
                    iahepStats.iahepIGMPReportsSent ++;

            if (IAHEP_DEBUG)
            {
                char addrStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(mappedGrpAddr, addrStr);
                printf("\nIAHEP Node: %d", node->nodeId);
                printf("\tJoins Group: %s\n", addrStr);
            }

        }
        //In case of IGMP-BYPASS Mode, join must Be sent to IAHEP Node
        else if (ip->iahepEnabled && ip->iahepData->nodeType == RED_NODE &&
            (dstAddr == BROADCAST_MULTICAST_MAPPEDADDRESS))
        {
            intfId = IAHEPGetIAHEPRedInterfaceIndex(node);
            NetworkIpSendRawMessageToMacLayer(
                node, newMsg, srcAddr, dstAddr, IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_IGMP, 1, intfId, ANY_DEST);
        }
        else
        {
                NetworkIpSendRawMessageToMacLayer(
                    node, newMsg, srcAddr, dstAddr, IPTOS_PREC_INTERNETCONTROL,
                    IPPROTO_IGMP, 1, intfId, ANY_DEST);
            }
#else
                NetworkIpSendRawMessageToMacLayer(node,
                                                  newMsg,
                                                  srcAddr,
                                                  dstAddr,
                                                  IPTOS_PREC_INTERNETCONTROL,
                                                  IPPROTO_IGMP,
                                                  1,
                                                  intfId,
                                                  ANY_DEST);
#endif //CYBER_CORE
    }
    else
    {
        // free the packet
        MESSAGE_Free(node, newMsg);
    }

// RtrJoinStart
    // Act as if we've received a Report
    if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER) {

        //As the router is receiving report here
        //hence stats should be incremented
        if (igmpHost->hostCompatibilityMode == IGMP_V2)
        {
            thisInterface->igmpStat.igmpv2MembershipReportReceived += 1;
            IgmpRouterHandleReport(node,
                                   &igmpv2Pkt,
                                   thisInterface->igmpRouter,
                                   srcAddr,
                                   intfId,
                                   thisInterface->robustnessVariable);
        }
        else
        {
            thisInterface->igmpStat.igmpv3MembershipReportReceived += 1;
            Igmpv3RouterHandleReport(node,
                                     &igmpv3ReportPkt,
                                     thisInterface->igmpRouter,
                                     intfId,
                                     thisInterface->robustnessVariable);
        }
        thisInterface->igmpStat.igmpTotalReportReceived += 1;
        igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalMsgReceived += 1;

    }
// RtrJoinEnd
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpSendLeaveReport()
// PURPOSE      : Send Igmp Leave Report Message on specified interface.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void IgmpSendLeaveReport(
    Node* node,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    IgmpInterfaceInfoType* thisInterface;
    Message* newMsg;
    NodeAddress srcAddr;
    NodeAddress dstAddr;

    // RtrJoinStart
    IgmpMessage igmpv2Pkt;
    // RtrJoinEnd

    thisInterface = igmp->igmpInterfaceInfo[intfId];

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpData);

    MESSAGE_PacketAlloc(node, newMsg, sizeof(IgmpMessage), TRACE_IGMP);

    // Allocate IGMP packet
    IgmpCreatePacket(
        newMsg, IGMP_LEAVE_GROUP_MSG, 0, grpAddr);

    // RtrJoinStart
    if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER) {
        memcpy(&igmpv2Pkt, newMsg->packet, sizeof(IgmpMessage));
    }
    // RtrJoinEnd

    // Get IP address for this interface
    srcAddr = NetworkIpGetInterfaceAddress(node, intfId);

    // Get destination address
    dstAddr = IGMP_V2_ALL_ROUTERS_GROUP_ADDR;

    if (DEBUG) {
        char grpStr[20];
        char netStr[20];
        char timeStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
        IO_ConvertIpAddressToString(grpAddr, grpStr);
        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceNetworkAddress(node, intfId),
            netStr);

        printf("Node %u send leave report for group %s "
            "to subnet %s at %ss\n\n",
            node->nodeId, grpStr, netStr, timeStr);
    }

    // Send membership report.
    thisInterface->igmpStat.igmpTotalMsgSend += 1;
    thisInterface->igmpStat.igmpTotalReportSend += 1;
    thisInterface->igmpStat.igmpLeaveReportSend += 1;

    NetworkIpSendRawMessageToMacLayer(
        node, newMsg, srcAddr, dstAddr, IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_IGMP, 1, intfId, ANY_DEST);

// RtrJoinStart
    // Act as if we've received a Leave Report
    if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER) {
        //the statistics for leave messages received should
        //be incremented here
        thisInterface->igmpStat.igmpTotalReportReceived += 1;
        thisInterface->igmpStat.igmpLeaveReportReceived += 1;
        igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalMsgReceived += 1;
        IgmpRouterHandleLeave(
            node, &igmpv2Pkt, thisInterface->igmpRouter, srcAddr, intfId);
    }
#ifdef ADDON_DB
        HandleMulticastDBStatus(node, intfId, "Leave", srcAddr, grpAddr);
#endif
// RtrJoinEnd
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHostInit()
// PURPOSE      : To initialize the IGMP host
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHostInit(
    Node* node,
    IgmpHost* igmpHost,
    const NodeInput* nodeInput,
    int interfaceIndex)
{
    char error[MAX_STRING_LENGTH];
    Int32 unsolicitedReportCount = 0;
    clocktype unsolicitedReportInterval = 0;
    BOOL retVal = FALSE;
    IgmpData* igmp = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    NodeAddress interfaceAddress;
    interfaceAddress = NetworkIpGetInterfaceAddress(node,interfaceIndex);

    igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    thisInterface = igmp->igmpInterfaceInfo[interfaceIndex];

    igmpHost->groupCount = 0;
    igmpHost->groupListHeadPointer = NULL;
    igmpHost->maxRespTime = (Int32)IGMP_MAX_RESPONSE_TIME;
    igmpHost->querierQueryInterval = IGMP_QUERY_INTERVAL;
    igmpHost->lastOlderVerQuerierPresentTimer = (clocktype) 0;
    igmpHost->hostCompatibilityMode = thisInterface->igmpVersion;
    // Get how many times we should send unsolicited report message
    IO_ReadInt(node->nodeId,
               interfaceAddress,
               nodeInput,
               "IGMP-UNSOLICITED-REPORT-COUNT",
               &retVal,
               &unsolicitedReportCount);

    if (!retVal)
    {
       if (DEBUG)
       {
           printf("Node %u: Unsolicited report count is not specified. "
                "Default value(2) is taken\n", node->nodeId);
       }
       unsolicitedReportCount = IGMP_UNSOLICITED_REPORT_COUNT;
    }
    else if (unsolicitedReportCount <= 0)
    {
        ERROR_ReportError("Unsolicitated Report Count should be a positive "
            "integer\n");
    }
    igmpHost->unsolicitedReportCount = (char) unsolicitedReportCount;

    retVal = FALSE;
    IO_ReadTime(node->nodeId,
                NetworkIpGetInterfaceAddress(node, interfaceIndex),
                nodeInput,
                "IGMP-UNSOLICIT-REPORT-INTERVAL",
                &retVal,
                &unsolicitedReportInterval);

    if (retVal)
    {
        if (unsolicitedReportInterval <= 0)
        {
            sprintf(error, "The Unsolicit Report Interval should be "
                "greater than zero\n");
            ERROR_ReportError(error);
        }
    }
    else
    {
       if (DEBUG) {
           printf("Node %u: Unsolicited report interval is not specified. "
                "Default value is taken\n", node->nodeId);
       }
       if (igmpHost->hostCompatibilityMode == IGMP_V2)
       {
           unsolicitedReportInterval = IGMP_UNSOLICITED_REPORT_INTERVAL;
       }
       else
       {
           unsolicitedReportInterval = IGMP_V3_UNSOLICITED_REPORT_INTERVAL;
       }
        igmpHost->unsolicitedReportInterval = unsolicitedReportInterval;
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpRouterInit()
// PURPOSE      : To initialize the IGMP router
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpRouterInit(
    Node* node,
    IgmpRouter* igmpRouter,
    int igmpInterfaceIndex,
    const NodeInput* nodeInput,
    Int32 robustnessVariable,
    clocktype queryInterval,
    UInt8 queryResponseInterval,
    UInt8 lastMemberQueryInterval,
    UInt16 lastMemberQueryCount)
{
    Message* newMsg = NULL;
    char* ptr;
    char startupQueryCount = 1;
    Int32 random;
    clocktype delay;

    // Initially all routers starts up as a querier
    igmpRouter->routersState = IGMP_QUERIER;

    // Initializes various timer value.
    igmpRouter->queryInterval = queryInterval;
    igmpRouter->queryResponseInterval = queryResponseInterval;
    igmpRouter->timer.startUpQueryInterval =
                             (clocktype) IGMP_STARTUP_QUERY_INTERVAL;

    igmpRouter->timer.generalQueryInterval = queryInterval;
    //The default value for Query Response interval is 100 which on
    //converting into units comes out to be 10 seconds. In QualNet at
    //initialization it is stored as 100 or converting the value configured
    //by user (in seconds) to the normal value i.e. dividing by seconds and
    //multiplying by 10.Hence,it is required to divide the current value in
    //queryResponseInterval by 10 and multiply by SECOND.
    igmpRouter->timer.otherQuerierPresentInterval =
                            (clocktype) ((robustnessVariable * queryInterval)
                             +( 0.5 * (igmpRouter->queryResponseInterval * SECOND)
                             /IGMP_QUERY_RESPONSE_SCALE_FACTOR));
    igmpRouter->lastMemberQueryInterval = lastMemberQueryInterval;
    igmpRouter->lastMemberQueryCount = lastMemberQueryCount;
    igmpRouter->timer.lastQueryReceiveTime = (clocktype) 0;
    igmpRouter->sFlag = 0;

    // Set startup query count.
    // The default value is the Robustness Variable
    igmpRouter->startUpQueryCount = (char)robustnessVariable;
    igmpRouter->numOfGroups = 0;
    igmpRouter->queryDelayTimeFunc = &IgmpSetStartUpQueryTimerDelay;
    igmpRouter->groupListHeadPointer = NULL;

    // Sending a self message for initiating of messaging system
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpQueryTimer);

    MESSAGE_InfoAlloc(node, newMsg, sizeof(int) + sizeof(char));
    ptr = MESSAGE_ReturnInfo(newMsg);

    // Assign start up query count and interface index
    memcpy(ptr, &igmpInterfaceIndex, sizeof(int));
    ptr += sizeof(int);
    memcpy(ptr, &startupQueryCount, sizeof(char));

    RANDOM_SetSeed(igmpRouter->timerSeed,
                   node->globalSeed,
                   node->nodeId,
                   GROUP_MANAGEMENT_PROTOCOL_IGMP,
                   igmpInterfaceIndex);

    // Send self timer
    random = RANDOM_nrand(igmpRouter->timerSeed);
    delay = (clocktype) ((random) % SECOND);

    MESSAGE_Send(node, newMsg, delay);
}


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
    char filterMode[],
    vector<NodeAddress>* sourceList)
{
    Message* ver2Msg = NULL;
    Message* ver3Msg = NULL;
    Int32 numSrc = 0;
    char* ptr;
    char* info;
    Int32 infoSize = 0;
    char unsolicitedReportCount = 0;
    vector<NodeAddress> :: iterator it;
    IgmpInterfaceInfoType* thisInterface;
    Igmpv3FilterModeType* fltrMode;
    IgmpStateChangeMsgInfoType* infoType = (IgmpStateChangeMsgInfoType*)
                     MEM_malloc(sizeof(IgmpStateChangeMsgInfoType));
    memset(infoType, 0, sizeof(IgmpStateChangeMsgInfoType));

    NetworkDataIp* ipLayer = NULL;

    ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    thisInterface = igmp->igmpInterfaceInfo[interfaceId];
    if (sourceList)
    {
        numSrc = sourceList->size();
    }
    // If IGMP not enable, then ignore joining group using IGMP.
    if (ipLayer->isIgmpEnable == FALSE)
    {
        char errStr[MAX_STRING_LENGTH];
        char buf[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(groupToJoin, buf);
        sprintf(errStr, "Node %u: IGMP is not enabled.\n"
            "    Unable to initiate join message for group %s\n",
            node->nodeId, buf);
        ERROR_ReportWarning(errStr);

        return;
    }

    if ((thisInterface) && (thisInterface->igmpVersion == IGMP_V3))
    {
        ver3Msg = MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               GROUP_MANAGEMENT_PROTOCOL_IGMP,
                               MSG_NETWORK_Igmpv3JoinGroupTimer);
        infoSize = IGMPV3_INFO_FIXED_SIZE;
        infoSize += numSrc * sizeof(NodeAddress) + sizeof(unsigned int);

        MESSAGE_InfoAlloc(node, ver3Msg, infoSize);
        info = (char*) MESSAGE_ReturnInfo(ver3Msg);

        memcpy(info, &groupToJoin, sizeof(NodeAddress));
        info += sizeof(NodeAddress);
        memcpy(info, &interfaceId, sizeof(Int32));
        info += sizeof(Int32);
        fltrMode = (Igmpv3FilterModeType*)info;
        if (!strcmp(filterMode, "INCLUDE"))
        {
            *fltrMode = INCLUDE;
        }
        else
        {
            *fltrMode = EXCLUDE;
        }
        info += sizeof(Igmpv3FilterModeType);
        memcpy(info, &numSrc, sizeof(Int32));
        info += sizeof(Int32);
        for (it = sourceList->begin(); it < sourceList->end(); ++it)
        {
            memcpy(info, &(*it), sizeof(NodeAddress));
            info += sizeof(NodeAddress);
        }
        memcpy(info, &unsolicitedReportCount, sizeof(char));
        info += sizeof(char);
        memset(info, 0, sizeof(unsigned int));

        MESSAGE_Send(node, ver3Msg, timeToJoin);
    }
    else if (((thisInterface) && (thisInterface->igmpVersion == IGMP_V2)) ||
             (!thisInterface))
    {
        if (((filterMode) &&
            (!strcmp(filterMode, "INCLUDE") ||
            !strcmp(filterMode, "EXCLUDE"))) || numSrc != 0)
        {
            ERROR_ReportError(
                "This is an IGMPv2 interface, wrong configuration"
                " parameters given in member file\n");
        }
        // Allocate new message
        ver2Msg = MESSAGE_Alloc(
                    node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_IgmpJoinGroupTimer);

        // Put the group address in info field
        MESSAGE_InfoAlloc(node, ver2Msg, (sizeof(NodeAddress) + sizeof(Int32)+ 1));
        memcpy(MESSAGE_ReturnInfo(ver2Msg), &groupToJoin, sizeof(NodeAddress));

        ptr = MESSAGE_ReturnInfo(ver2Msg) + sizeof(NodeAddress);
        *ptr = (char)interfaceId;
        ptr += sizeof(Int32);
        *ptr = 0;

        // Send timer to self
        MESSAGE_Send(node, ver2Msg, timeToJoin);
    }
}


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
    clocktype timeToLeave)
{
    Message* newMsg = NULL;
    NetworkDataIp* ipLayer = NULL;
    char* ptr;

    ipLayer = (NetworkDataIp *) node->networkData.networkVar;

    // If IGMP not enable, then ignore joining group using IGMP.
    if (ipLayer->isIgmpEnable == FALSE)
    {
        char errStr[MAX_STRING_LENGTH];
        char buf[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(groupToLeave, buf);
        sprintf(errStr, "Node %u: IGMP is not enabled.\n"
            "    Unable to initiate leave message for group %s\n",
            node->nodeId, buf);
        ERROR_ReportWarning(errStr);

        return;
    }

    // Allocate new message
    newMsg = MESSAGE_Alloc(
                node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                MSG_NETWORK_IgmpLeaveGroupTimer);

    // Put the group address in msg-info field
    MESSAGE_InfoAlloc(node, newMsg, (sizeof(NodeAddress) + sizeof(Int32)));
    memcpy(MESSAGE_ReturnInfo(newMsg), &groupToLeave, sizeof(NodeAddress));

    ptr = MESSAGE_ReturnInfo(newMsg) + sizeof(NodeAddress);
    *ptr = (char)interfaceId;

    // Send timer to self
    MESSAGE_Send(node, newMsg, timeToLeave);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleQueryTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpQueryTimer expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleQueryTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    IgmpRouter* igmpRouter;
    Int32 intfId;
    vector<NodeAddress> srcAddressVector;

    memcpy(&intfId, MESSAGE_ReturnInfo(msg), sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpQueryTimer\n");
    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    if (igmpRouter->routersState == IGMP_QUERIER)
    {
        Message* selfMsg;
        clocktype delay;

        if (DEBUG) {
            printf("Node %u got MSG_NETWORK_IgmpQueryTimer expired\n",
                node->nodeId);
        }

        // Send general query message to all-systems multicast group
        IgmpSendQuery(node,
                      0,
                      intfId,
                      igmpRouter->queryResponseInterval,
                      igmpRouter->lastMemberQueryInterval,
                      igmpRouter->queryInterval);

        delay = (igmpRouter->queryDelayTimeFunc)(igmpRouter, msg);

        selfMsg = MESSAGE_Duplicate(node, msg);

        // Send timer to self
        MESSAGE_Send(node, selfMsg, delay);
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleOtherQuerierPresentTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpOtherQuerierPresentTimer
//                expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleOtherQuerierPresentTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    IgmpRouter* igmpRouter;
    IgmpRouterTimer* igmpTimer;
    Int32 intfId;
    vector<NodeAddress>srcAddressVector;

    // Retrieve information
    memcpy(&intfId, MESSAGE_ReturnInfo(msg), sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpOtherQuerierPresentTimer\n");
    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    igmpTimer = &(igmpRouter->timer);

    // Check if Other Querier Present Timer has been expired.
    // If so, then set Routers status as IGMP_QUERIER
    if (((node->getNodeTime() - igmpTimer->lastQueryReceiveTime) >=
        igmpTimer->otherQuerierPresentInterval)
        && (igmpRouter->routersState == IGMP_NON_QUERIER))
    {
        igmpRouter->routersState = IGMP_QUERIER;

        if (DEBUG) {
            char timeStr[MAX_STRING_LENGTH];
            char netStr[20];

            TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
            IO_ConvertIpAddressToString(
                NetworkIpGetInterfaceNetworkAddress(node, intfId),
                netStr);
            printf("Node %u got MSG_NETWORK_IgmpOtherQuerierPresentTimer "
                "expired\n"
                "Node %u become Querier again on network %s "
                "at time %ss\n",
                node->nodeId, node->nodeId, netStr, timeStr);
        }

        // Send general query message to all-systems multicast group
        IgmpSendQuery(node,
                      0,
                      intfId,
                      igmpRouter->queryResponseInterval,
                      igmpRouter->lastMemberQueryInterval,
                      igmpRouter->queryInterval);

        // Set general query timer
        IgmpSetQueryTimer(node, intfId);
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleGroupReplyTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpGroupReplyTimer expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleGroupReplyTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;
    IgmpGroupInfoForHost* grpPtr;
    NodeAddress grpAddr;
    char* dataPtr;
    Int32 intfId;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(Int32));


    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpGroupReplyTimer\n");

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    // Search for specified group
    grpPtr = IgmpCheckHostGroupList(
                node, grpAddr, igmpHost->groupListHeadPointer);

    // Send report if the timer has not been cancelled yet
    if (grpPtr && grpPtr->hostState == IGMP_HOST_DELAYING_MEMBER)
    {
        if (grpPtr->groupDelayTimer != IGMP_INVALID_TIMER_VAL)
        {
            IgmpSendMembershipReport(node, grpAddr, intfId);
            grpPtr->lastReportSendOrReceive = node->getNodeTime();
        }
        grpPtr->isLastHost = TRUE;
        grpPtr->hostState = IGMP_HOST_IDLE_MEMBER;
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmp3HandleHostReplyTimer()
// PURPOSE      : Take action when MSG_NETWORK_Igmpv3HostReplyTimer
//                expire.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleHostReplyTimer(Node* node,Message* msg)
{

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost = NULL;
    IgmpGroupInfoForHost* grpPtr = NULL;
    NodeAddress grpAddr;
    char* dataPtr = NULL;
    Int32 intfId;
    IgmpInterfaceInfoType* thisInterface = NULL;
    vector<GroupRecord> Igmpv3GrpRecord;
    GroupRecord grpRecord;
    vector<NodeAddress> tmpVector;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(Int32));

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface in MSG_NETWORK_Igmpv3HostReplyTimer\n");

    igmpHost = thisInterface->igmpHost;

    if (grpAddr == 0)
    {
        // Handle general query
        grpPtr = igmpHost->groupListHeadPointer;

        while (grpPtr != NULL)
        {
            if (grpPtr->lastHostIntfTimerValue == 0)
            {
                // Handling an already expired host interface timer.
                return;
            }
            // Host interface timer is now expired.
            grpPtr->lastHostIntfTimerValue = 0;
            if (grpPtr->filterMode == INCLUDE)
            {
                grpRecord.record_type = MODE_IS_INCLUDE;
            }
            else
            {
                grpRecord.record_type = MODE_IS_EXCLUDE;
            }
            grpRecord.groupAddress = grpPtr->groupId;
            grpRecord.aux_data_len = 0;
            grpRecord.numSources = (UInt16)grpPtr->srcList.size();
            grpRecord.sourceAddress = grpPtr->srcList;
            Igmpv3GrpRecord.push_back(grpRecord);
            grpPtr = grpPtr->next;
        }
        IgmpSendMembershipReport(node, grpAddr, intfId, TRUE, &Igmpv3GrpRecord);
    }
    else
    {
        // Search for specified group
        grpPtr = IgmpCheckHostGroupList(
                    node, grpAddr, igmpHost->groupListHeadPointer);
        if (grpPtr)
        {
            if (grpPtr->lastHostGrpTimerValue == 0)
            {
                // Handling an already expired host group timer.
                return;
            }
            // Host group timer is now expired.
            grpPtr->lastHostGrpTimerValue = 0;
            if (grpPtr->recordedSrcList.empty())
            {
                if (DEBUG)
                {
                    printf("pending IGMPv3 group-specific query response\n");
                }
                if (grpPtr->filterMode == INCLUDE)
                {
                    grpRecord.record_type = MODE_IS_INCLUDE;
                }
                else
                {
                    grpRecord.record_type = MODE_IS_EXCLUDE;
                }
                grpRecord.groupAddress = grpAddr;
                grpRecord.aux_data_len = 0;
                grpRecord.numSources = (UInt16)grpPtr->srcList.size();
                grpRecord.sourceAddress = grpPtr->srcList;
                Igmpv3GrpRecord.push_back(grpRecord);
                IgmpSendMembershipReport(node,
                                         grpAddr,
                                         intfId,
                                         TRUE,
                                         &Igmpv3GrpRecord);
            }
            else
            {
                if (DEBUG)
                {
                    printf("pending IGMPv3 group-and-source-specific"
                        "query response\n");
                }
                if (grpPtr->filterMode == INCLUDE)
                {
                    set_intersection(grpPtr->srcList.begin(),
                                     grpPtr->srcList.end(),
                                     grpPtr->recordedSrcList.begin(),
                                     grpPtr->recordedSrcList.end(),
                                     back_inserter(tmpVector));
                }
                else
                {
                    set_difference(grpPtr->recordedSrcList.begin(),
                                   grpPtr->recordedSrcList.end(),
                                   grpPtr->srcList.begin(),
                                   grpPtr->srcList.end(),
                                   back_inserter(tmpVector));
                }
                grpRecord.record_type = MODE_IS_INCLUDE;
                grpRecord.groupAddress = grpAddr;
                grpRecord.aux_data_len = 0;
                grpRecord.numSources = (UInt16)tmpVector.size();
                grpRecord.sourceAddress = tmpVector;
                Igmpv3GrpRecord.push_back(grpRecord);

                // If the Current-State Record has a non-empty set of source
                // addresses, only then a response is sent.
                if (!tmpVector.empty())
                {
                    IgmpSendMembershipReport(node,
                                             grpAddr,
                                             intfId,
                                             TRUE,
                                             &Igmpv3GrpRecord);
                    // Source list associated with reported group is cleared.
                    grpPtr->recordedSrcList.clear();
                }
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleGroupMembershipTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpGroupMembershipTimer
//                expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleGroupMembershipTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter;
    IgmpGroupInfoForRouter* grpPtr;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpGroupMembershipTimer\n");

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    // Search for specified group
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);

    if (grpPtr && grpPtr->membershipState == IGMP_ROUTER_MEMBERS)
    {
        if ((node->getNodeTime() - grpPtr->lastReportReceive) >=
            grpPtr->groupMembershipInterval)
        {
            MulticastProtocolType notifyMcastRtProto =
                IgmpGetMulticastProtocolInfo(node, intfId);

            IgmpDeleteRtrGroupList(node, grpAddr, intfId);
#ifdef ADDON_DB
            HandleStatsDBIgmpSummary(node, "Delete", 0, grpAddr);
#endif
            if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
            {
                if (IgmpCheckSubscriptionInAllOtherDownstreamInterface(
                    node, igmp, grpAddr, intfId))
                {
                    return;
                }
                else
                {
                    Int32 upstreamIntfId = 0;

                    upstreamIntfId =
                        (Int32)NetworkIpGetInterfaceIndexFromAddress(
                                     node, igmp->igmpUpstreamInterfaceAddr);

                    //notify upstream. just call igmpleavegroup
                    //with timetoleave = 0
                    if (igmp->igmpProxyVersion == IGMP_V2)
                    {
                        IgmpLeaveGroup(node,
                                       upstreamIntfId,
                                       grpAddr,
                                       (clocktype)0);
                    }
                    else
                    {
                        IgmpProxyHandleSubscription(node,
                                                    grpAddr);
                    }
                }
            }
            else
            {
                // Notify multicast routing protocol
                if (notifyMcastRtProto)
                {
                    (notifyMcastRtProto)(
                        node, grpAddr, intfId, LOCAL_MEMBER_LEAVE_GROUP);
                }
            }
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3RouterHandleGroupTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpRouterGrouptTimer
//                expire.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterHandleGroupTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter;
    IgmpGroupInfoForRouter* grpPtr;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;

    NetworkDataIp* ipLayer = NULL;
    ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpRouterGroupTimer\n");

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    PimData* pim = (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
                                                     MULTICAST_PROTOCOL_PIM);

    // Search for specified group
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);
    // Make the switch of filter mode only if the timer is not zero
    // timer has expired.
    if (grpPtr)
    {
        if (node->getNodeTime() >= grpPtr->lastGroupTimerValue)
        {
            // timer has expired set it to zero.
            grpPtr->lastGroupTimerValue = 0;
            if (grpPtr->filterMode == EXCLUDE)
            {
                // switch to include mode. Retain the forward list
                // and clear the do not forward list.
                grpPtr->filterMode = INCLUDE;
                grpPtr->rtrDoNotForwardListVector.clear();
                if (grpPtr->rtrForwardListVector.empty())
                {
                    if (pim
                        && pim->modeType != ROUTING_PIM_MODE_DENSE
                        && ipLayer->isSSMEnable
                        && Igmpv3IsSSMAddress(node, grpPtr->groupId))
                    {
                        return;
                    }
                    MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
                    if (notifyMcastRtProto)
                    {
                        (notifyMcastRtProto)(node,
                                             grpPtr->groupId,
                                             intfId,
                                             LOCAL_MEMBER_LEAVE_GROUP);
                    }
                }
            }
            else
            {
                return;
            }
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3RouterHandleSourceTimer()
// PURPOSE      : Take action when MSG_NETWORK_Igmpv3SourceTimer
//                expire.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterHandleSourceTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    char* dataPtr = NULL;
    NodeAddress grpAddr;
    Int32 intfId = 0;
    NodeAddress src;
    SourceRecord srcRecord;
    vector<SourceRecord> :: iterator it;

    NetworkDataIp* ipLayer = NULL;
    ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));
    dataPtr += sizeof(int);
    memcpy(&src, dataPtr, sizeof(NodeAddress));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpSourceTimer\n");

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;
    ERROR_Assert(igmpRouter,
        "Invalid router info in MSG_NETWORK_IgmpSourceTimer\n");

    PimData* pim = (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
                                                     MULTICAST_PROTOCOL_PIM);
    PimDataSm* pimDataSm = NULL;
    RoutingPimSourceGroupList* srcGroupListPtr = NULL;
    if (pim)
    {
        if (pim->modeType == ROUTING_PIM_MODE_SPARSE_DENSE)
        {
            pimDataSm = ((PimDataSmDm*) pim->pimModePtr)->pimSm;
        }
        else if (pim->modeType == ROUTING_PIM_MODE_SPARSE)
        {
            pimDataSm = (PimDataSm*) pim->pimModePtr;
        }
    }

    // Search for specified group
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);
    if (grpPtr)
    {
        if (grpPtr->filterMode == INCLUDE)
        {
            for (it = grpPtr->rtrForwardListVector.begin();
                 it < grpPtr->rtrForwardListVector.end();
                 ++it)
            {
                if ((*it).sourceAddr == src)
                {
                    if (node->getNodeTime() >= (*it).lastSourceTimerValue)
                    {
                        // Timer for this source has expired
                        (*it).lastSourceTimerValue = 0;
                        // TO DO: prune this source using SSM
                        if (pimDataSm && ipLayer->isSSMEnable)
                        {
                            if (Igmpv3IsSSMAddress(node, grpPtr->groupId))
                            {
                                if (!pim->interface[intfId].srcGrpList)
                               {
                                    ListInit(node,
                                         &pim->interface[intfId].srcGrpList);
                               }
                               else
                               {
                                    ListFree(node,
                                           pim->interface[intfId].srcGrpList,
                                           FALSE);
                                    ListInit(node,
                                         &pim->interface[intfId].srcGrpList);
                                }
                                srcGroupListPtr = (RoutingPimSourceGroupList*)
                                   MEM_malloc(sizeof(RoutingPimSourceGroupList));
                                srcGroupListPtr->groupAddr = grpPtr->groupId;
                                srcGroupListPtr->srcAddr = (*it).sourceAddr;
                                ListInsert(node,
                                           pim->interface[intfId].srcGrpList,
                                           node->getNodeTime(),
                                           (void*)srcGroupListPtr);
                                MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
                                (notifyMcastRtProto)(node,
                                                     grpPtr->groupId,
                                                     intfId,
                                                     LOCAL_MEMBER_LEAVE_GROUP);
                            }
                        }
                        grpPtr->rtrForwardListVector.erase(it);
                        // If after this source deletion there are no
                        // sources left in the source record, then delete
                        // the group entry.
                        if (grpPtr->rtrForwardListVector.empty())
                        {
                            if (!(pimDataSm
                                  && ipLayer->isSSMEnable
                                  && Igmpv3IsSSMAddress(node,
                                                        grpPtr->groupId)))
                            {
                                MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
                                if (notifyMcastRtProto)
                                {
                                    (notifyMcastRtProto)(node,
                                                   grpPtr->groupId,
                                                   intfId,
                                                   LOCAL_MEMBER_LEAVE_GROUP);
                                }
                            }
                            IgmpDeleteRtrGroupList(node, grpAddr, intfId);
                            if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType
                                                               == IGMP_PROXY)
                            {
                                IgmpProxyHandleSubscription(node,
                                                            grpAddr);
                            }
                        }
                        break;
                    }
                }
                else
                {
                    //do nothing.
                }
            }
        }
        else
        {
            for (it = grpPtr->rtrForwardListVector.begin();
                 it < grpPtr->rtrForwardListVector.end();
                 ++it)
            {
                if ((*it).sourceAddr == src)
                {
                    if (node->getNodeTime() >= (*it).lastSourceTimerValue)
                    {
                        // Timer for this source has expired
                        (*it).lastSourceTimerValue = 0;

                        // Delete from forward list and add to do not
                        // forward list with source timer as zero
                        grpPtr->rtrForwardListVector.erase(it);
                        srcRecord.sourceAddr = src;
                        srcRecord.isRetransmitOn = FALSE;
                        srcRecord.retransmitCount = 0;
                        srcRecord.lastSourceTimerValue = 0;
                        grpPtr->
                            rtrDoNotForwardListVector.push_back(srcRecord);
                        // Suggest to not forward traffic from this source
                        if (pimDataSm && ipLayer->isSSMEnable)
                        {
                            if (Igmpv3IsSSMAddress(node, grpPtr->groupId))
                            {
                                if (!pim->interface[intfId].srcGrpList)
                                {
                                    ListInit(node,
                                             &pim->interface[intfId].srcGrpList);
                                }
                                else
                                {
                                    ListFree(node,
                                             pim->interface[intfId].srcGrpList,
                                             FALSE);
                                    ListInit(node,
                                             &pim->interface[intfId].srcGrpList);
                                }
                                srcGroupListPtr =
                                  (RoutingPimSourceGroupList*)MEM_malloc(
                                      sizeof(RoutingPimSourceGroupList));

                                srcGroupListPtr->groupAddr =
                                                         grpPtr->groupId;
                                srcGroupListPtr->srcAddr = src;

                                ListInsert(node,
                                           pim->interface[intfId].srcGrpList,
                                           node->getNodeTime(),
                                           (void*)srcGroupListPtr);

                                MulticastProtocolType notifyMcastRtProto =
                                IgmpGetMulticastProtocolInfo(node, intfId);
                                   (notifyMcastRtProto)(node,
                                                   grpPtr->groupId,
                                                   intfId,
                                                   LOCAL_MEMBER_LEAVE_GROUP);
                            }
                        }
                        break;
                    }
                }
            }
        }// End of EXCLUDE filter-mode case
    }// End of group pointer present case
    else
    {
        // no group entry.
        return;
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmp3HandleGrpSpecificQueryRetransmitTimer()
// PURPOSE      : Take action when
//                MSG_NETWORK_IgmpGrpSpecificQueryRetransmitTimer expire
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleGrpSpecificQueryRetransmitTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    char* dataPtr = NULL;
    NodeAddress grpAddr;
    Int32 intfId;
    Int32 retransmitCount = 0;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(Int32));
    dataPtr += sizeof(Int32);
    memcpy(&retransmitCount, dataPtr, sizeof(Int32));

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface in"
        "MSG_NETWORK_IgmpGrpSpecificQueryRetransmitTimer\n");
    igmpRouter = thisInterface->igmpRouter;

    grpPtr = IgmpCheckRtrGroupList(node,
                                   grpAddr,
                                   igmpRouter->groupListHeadPointer);
    if (grpPtr)
    {
        Igmpv3SendGrpSpecificQuery(
                                node,
                                grpAddr,
                                intfId,
                                igmpRouter->queryInterval,
                                retransmitCount);
    }

}

//---------------------------------------------------------------------------
// FUNCTION     : Igmp3HandleGrpAndSrcSpecificQueryRetransmitTimer()
// PURPOSE      : Take action when
//                MSG_NETWORK_IgmpGrpAndSrcSpecificQueryRetransmitTimer
//                expire
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleGrpAndSrcSpecificQueryRetransmitTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;
    Int32 numSrc;
    vector<NodeAddress> srcVector;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(Int32));
    dataPtr += sizeof(Int32);
    memcpy(&numSrc, dataPtr, sizeof(Int32));
    dataPtr += sizeof(Int32);
    for (int i = 0; i < numSrc; i++)
    {
        NodeAddress* src;
        src = (NodeAddress*)dataPtr;
        srcVector.push_back(*src);
        dataPtr += sizeof(NodeAddress);
    }

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface in"
        "MSG_NETWORK_IgmpGrpAndSrcSpecificQueryRetransmitTimer\n");
    igmpRouter = thisInterface->igmpRouter;

    grpPtr = IgmpCheckRtrGroupList(node,
                                   grpAddr,
                                   igmpRouter->groupListHeadPointer);
    if (grpPtr)
    {
        Igmpv3SendGrpAndSrcSpecificQuery(
                                node,
                                grpAddr,
                                intfId,
                                igmpRouter->queryInterval,
                                srcVector);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleJoinGroupTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpJoinGroupTimer expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleJoinGroupTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;
    IgmpGroupInfoForHost* grpPtr;
    char* dataPtr;
    NodeAddress grpAddr;
    char unsolicitedReportCount;
    Int32 intfId;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(Int32));

#ifdef ADDON_BOEINGFCS
    if (node->macData[intfId]->macProtocol ==
        MAC_PROTOCOL_LINK_EPLRS)
    {
        return;
    }
#endif

    dataPtr += sizeof(Int32);
    memcpy(&unsolicitedReportCount, dataPtr, sizeof(char));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpJoinGroupTimer\n");

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    grpPtr = IgmpCheckHostGroupList(
                node, grpAddr, igmpHost->groupListHeadPointer);

    switch (unsolicitedReportCount)
    {
        case 0:
        {
            // If the group exist, do nothing
            if (grpPtr) {
                    if (DEBUG) {
                    char grpStr[20];
                    char intfStr[20];

                    IO_ConvertIpAddressToString(grpAddr, grpStr);
                    IO_ConvertIpAddressToString(
                        NetworkIpGetInterfaceAddress(node, intfId),
                        intfStr);
                    printf("Host %u is already a member of group %s "
                        "on interface %s\n",
                        node->nodeId, grpStr, intfStr);
                }

                break;
            }

            grpPtr = IgmpInsertHostGroupList(node, grpAddr, intfId);

#ifdef ADDON_DB
            // Get IP address for this interface
            NodeAddress srcAddr = NetworkIpGetInterfaceAddress(node, intfId);
            HandleMulticastDBStatus(node, intfId, "Join", srcAddr, grpAddr);
#endif
            // Fall through case
        }
        default:
        {
           // Group member may leave the group while unsolicited report
           // is being sent so grpPtr to be checked for NULL value.If node
           // left the group then no needs to send unsolicited report

           if (!grpPtr){
              return;
            }

           if (DEBUG) {
                printf("Host %u sending unsolicited report\n", node->nodeId);
            }

           //Report should be sent only when the timer has not
           //been cancelled i.e. it is in the delaying member state
           //However, we do need to schedule the next report
           if ((unsolicitedReportCount == 0) ||
              (grpPtr->hostState == IGMP_HOST_DELAYING_MEMBER))
           {
            // Send unsolicited membership report
            IgmpSendMembershipReport(node, grpAddr, intfId);

            grpPtr->lastReportSendOrReceive = node->getNodeTime();
            grpPtr->isLastHost = TRUE;
            grpPtr->hostState = IGMP_HOST_IDLE_MEMBER;
           }
            unsolicitedReportCount++;

            if (unsolicitedReportCount < igmpHost->unsolicitedReportCount)
            {
                Message* selfMsg;

                grpPtr->hostState = IGMP_HOST_DELAYING_MEMBER;

                // Act as a query just has been received
                grpPtr->lastQueryReceive = node->getNodeTime();

                // Allocate message to trigger self
                memcpy(dataPtr, &unsolicitedReportCount, sizeof(char));
                selfMsg = MESSAGE_Duplicate(node, msg);

                // unsolicited Reports are sent after every
                // IGMP_UNSOLICITED_REPORT_INTERVAL

                // Send timer to self
                MESSAGE_Send(
                    node, selfMsg, igmpHost->unsolicitedReportInterval);
            }
            break;
        }
    } // switch
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleJoinGroupTimer()
// PURPOSE      : Take action when MSG_NETWORK_Igmpv3JoinGroupTimer expire.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleJoinGroupTimer(
    Node* node,
    Message* msg)
{
    UInt32 grpAddr;
    char unsolicitedReportCount;
    Int32 intfId;
    clocktype delayForReport;
    IgmpInterfaceInfoType* thisInterface = NULL;
    Igmpv3FilterModeType filterMode;
    vector<NodeAddress> sourceList, oldDiffNewList, newDiffOldList;
    Int32 numSources = 0;
    IgmpHost* igmpHost = NULL;
    IgmpGroupInfoForHost* grpPtr = NULL;
    bool sendReport = TRUE;
    char* info;
    char* info1;
    char* info_original;
    bool isAlreadyPresent = FALSE;
    Int32 i = 0;
    UInt32 it = 0;
    RetxSourceInfo sourceInfo;
    vector<NodeAddress> :: iterator iter;
    vector<GroupRecord> Igmpv3GrpRecord;
    vector<struct RetxSourceInfo> :: iterator retxListIter;
    unsigned int* retxSeqNo;

    GroupRecord grpRecord;
    memset(&grpRecord, 0, sizeof(GroupRecord));

    info = (char*) MESSAGE_ReturnInfo(msg);
    info_original = info;

    NodeAddress* grpAddress;
    grpAddress = (NodeAddress*)info;
    grpAddr = *grpAddress;
    info += sizeof(NodeAddress);

    Int32* interfaceId;
    interfaceId = (Int32*)info;
    intfId = *interfaceId;
    info += sizeof(Int32);

    Igmpv3FilterModeType* fltrMode;
    fltrMode = (Igmpv3FilterModeType*)info;
    filterMode = *fltrMode;
    info += sizeof(Igmpv3FilterModeType);

    Int32* numSrc;
    numSrc = (Int32*)info;
    numSources = *numSrc;
    info += sizeof(Int32);

    for (i = 0 ; i < numSources; i++)
    {
        NodeAddress* src;
        src = (NodeAddress*)info;
        sourceList.push_back(*src);
        info += sizeof(NodeAddress);
    }

    char* reportCount;
    reportCount = (char*) info;
    unsolicitedReportCount = *reportCount;
    info1 = info;

    info += sizeof(char);
    unsigned int seqNo = *((unsigned int*) info);

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    thisInterface = igmp->igmpInterfaceInfo[intfId];

    ERROR_Assert(thisInterface,
        "Invalid interface in MSG_NETWORK_Igmpv3JoinGroupTimer\n");

#ifdef ADDON_BOEINGFCS
    if (node->macData[intfId]->macProtocol ==
        MAC_PROTOCOL_LINK_EPLRS)
    {
        return;
    }
#endif

    igmpHost = thisInterface->igmpHost;
    ERROR_Assert(igmpHost,
        "Invalid host info in MSG_NETWORK_Igmpv3JoinGroupTimer\n");

    if (igmpHost->hostCompatibilityMode == IGMP_V2)
    {
        // Handling rescheduled timer but the version has changed to 2.
        return;
    }
    grpPtr = IgmpCheckHostGroupList(
                node, grpAddr, igmpHost->groupListHeadPointer);

    switch (unsolicitedReportCount)
    {
        case 0:
        {
            // If the group exist
            if (grpPtr)
            {
                if (DEBUG)
                {
                    char grpStr[20];
                    char intfStr[20];

                    IO_ConvertIpAddressToString(grpAddr, grpStr);
                    IO_ConvertIpAddressToString(
                        NetworkIpGetInterfaceAddress(node, intfId),
                        intfStr);
                    printf("Host %u is already a member of group %s "
                        "on interface %s\n",
                        node->nodeId, grpStr, intfStr);
                }
            }
            else
            {
                grpPtr = IgmpInsertHostGroupList(node, grpAddr, intfId);
            }
            // IGMPv3 Host interface state change trigger state machine
            // handling.
            sort(grpPtr->srcList.begin(), grpPtr->srcList.end());
            sort(sourceList.begin(), sourceList.end());

            // set difference (new sources - old sources)
            set_difference(sourceList.begin(),
                    sourceList.end(),
                    grpPtr->srcList.begin(),
                    grpPtr->srcList.end(),
                    back_inserter(newDiffOldList));
            // set difference (old sources - new sources)
            set_difference(grpPtr->srcList.begin(),
                    grpPtr->srcList.end(),
                    sourceList.begin(),
                    sourceList.end(),
                    back_inserter(oldDiffNewList));

            if ((grpPtr->filterMode == INCLUDE)
                && (filterMode == INCLUDE))
            {
                if (!oldDiffNewList.empty())
                {
                    // Update the blocked list of sources and its retxCount
                    for (it = 0;
                         it < oldDiffNewList.size();
                         it++)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = oldDiffNewList[it];
                        grpPtr->retxBlockSrcList.push_back(sourceInfo);
                        // Check if this is present in AllowList, if yes,
                        // delete it.
                        for (retxListIter = grpPtr->retxAllowSrcList.begin();
                             retxListIter < grpPtr->retxAllowSrcList.end();
                             ++retxListIter)
                        {
                            if ((*retxListIter).sourceAddress ==
                                sourceInfo.sourceAddress)
                            {
                                // found it, so erase
                                grpPtr->retxAllowSrcList.erase(retxListIter);
                                break;
                            }
                        }
                    }
                }
                if (!newDiffOldList.empty())
                {
                    //Update the allowed list of sources and its retxCount
                    for (it = 0;
                         it < newDiffOldList.size();
                         it++)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = newDiffOldList[it];
                        grpPtr->retxAllowSrcList.push_back(sourceInfo);
                        // Check if this is present in BlockList, if yes,
                        // delete it.
                        for (retxListIter = grpPtr->retxBlockSrcList.begin();
                             retxListIter < grpPtr->retxBlockSrcList.end();
                             ++retxListIter)
                        {
                            if ((*retxListIter).sourceAddress ==
                                sourceInfo.sourceAddress)
                            {
                                // found it, so erase
                                grpPtr->retxBlockSrcList.erase(retxListIter);
                                break;
                            }
                        }
                    }
                }
                if (newDiffOldList.empty() && oldDiffNewList.empty())
                {
                    sendReport = FALSE;
                }
            }
            else if ((grpPtr->filterMode == INCLUDE)
                    && (filterMode == EXCLUDE))
            {
                // Updated to New state
                grpPtr->filterMode = EXCLUDE;
                // Update retx filter mode state and retxcount
                grpPtr->retxfilterMode = EXCLUDE;
                grpPtr->retxCount =
                    (UInt16)thisInterface->robustnessVariable;
                vector<RetxSourceInfo> :: iterator iter;
                //update the retxSourceLists
                for (it = 0; it < sourceList.size(); it++)
                {
                    // If any source, is in the allowed mode,
                    // put it now in blocked list. If it is a new source and,
                    // not already present in blocked list,
                    // then add in the blocked list.
                    for (iter = grpPtr->retxAllowSrcList.begin();
                         iter < grpPtr->retxAllowSrcList.end();
                         ++iter)
                    {
                        if ((*iter).sourceAddress == sourceList[it])
                        {
                            // Delete the source value from the vector.
                            grpPtr->retxAllowSrcList.erase(iter);
                            break;
                        }
                    }
                    isAlreadyPresent = FALSE;
                    //Check if already present in allowed list or not.
                    for (iter = grpPtr->retxBlockSrcList.begin();
                         iter < grpPtr->retxBlockSrcList.end();
                         ++iter)
                    {
                        if ((*iter).sourceAddress == sourceList[it])
                        {
                            isAlreadyPresent = TRUE;
                            break;
                        }
                    }
                    if (!isAlreadyPresent)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = sourceList[it];
                        grpPtr->retxBlockSrcList.push_back(sourceInfo);
                    }
                }
            }
            else if ((grpPtr->filterMode == EXCLUDE)
                    && (filterMode == EXCLUDE))
            {
                if (!oldDiffNewList.empty())
                {
                    //Update the allowed list of sources and its retxCount
                    for (it = 0;
                         it < oldDiffNewList.size();
                         it++)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = oldDiffNewList[it];
                        grpPtr->retxAllowSrcList.push_back(sourceInfo);
                    }
                }
                if (!newDiffOldList.empty())
                {
                    //Update the blocked list of sources and its retxCount
                    for (it = 0;
                         it < newDiffOldList.size();
                         it++)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = newDiffOldList[it];
                        grpPtr->retxBlockSrcList.push_back(sourceInfo);
                    }
                }
                if (newDiffOldList.empty() && oldDiffNewList.empty())
                {
                    sendReport = FALSE;
                }
            }
            else if ((grpPtr->filterMode == EXCLUDE)
                    && (filterMode == INCLUDE))
            {
                // Update to new state
                grpPtr->filterMode = INCLUDE;
                // Update retx filter mode state and retxcount
                grpPtr->retxfilterMode = INCLUDE;
                grpPtr->retxCount =
                    (UInt16)thisInterface->robustnessVariable;
                vector<RetxSourceInfo> :: iterator iter;
                //update the retxSourceLists
                for (it = 0; it < sourceList.size(); it++)
                {
                    // If any source, is in the blocked mode,
                    // put it now in allowed list. If it is a new source and,
                    // not already present in allowed list,
                    // then add in the allowed list.
                    for (iter = grpPtr->retxBlockSrcList.begin();
                        iter < grpPtr->retxBlockSrcList.end();
                        ++iter)
                    {
                        if ((*iter).sourceAddress == sourceList[it])
                        {
                            // Delete the source value from the vector.
                            grpPtr->retxBlockSrcList.erase(iter);
                            break;
                        }
                    }
                    isAlreadyPresent = FALSE;
                    //Check if already present in allowed list or not.
                    for (iter = grpPtr->retxAllowSrcList.begin();
                        iter < grpPtr->retxAllowSrcList.end();
                        ++iter)
                    {
                        if ((*iter).sourceAddress == sourceList[it])
                        {
                            isAlreadyPresent = TRUE;
                            break;
                        }
                    }
                    if (!isAlreadyPresent)
                    {
                        sourceInfo.retxCount =
                            (UInt16)thisInterface->robustnessVariable;
                        sourceInfo.sourceAddress = sourceList[it];
                        grpPtr->retxAllowSrcList.push_back(sourceInfo);
                    }
                }
            }
            // Update the interface source list with new source list
            grpPtr->srcList = sourceList;

    #ifdef ADDON_DB
            // Get IP address for this interface
            NodeAddress srcAddr = NetworkIpGetInterfaceAddress(node, intfId);
            HandleMulticastDBStatus(node, intfId, "Join", srcAddr, grpAddr);
    #endif
            // Fall through case
        }
        default:
        {
            if (!grpPtr){
              return;
            }

            if (DEBUG) {
                printf("Host %u sending unsolicited report\n", node->nodeId);
            }
            // If this is a retransmission case, then handle only if this
            // timer is not cancelled already else return.
            if ((unsolicitedReportCount) &&
                (((grpPtr->retxCount) &&
                (filterMode != grpPtr->retxfilterMode)) ||
                (!(grpPtr->retxCount) && (seqNo < grpPtr->retxSeqNo))))
            {
                return;
            }

            if (sendReport)
            {
                // Send unsolicited membership report
                IgmpSendMembershipReport(node,
                                         grpAddr,
                                         intfId,
                                         FALSE,
                                         &Igmpv3GrpRecord);
                // if FM retxCount is non-0, reschedule this message again,
                // so that,the report can be retransmitted.
                // if FM retxCount is 0, check if there are pending
                // SLC records. If so, reschedule them.
                if ((grpPtr->retxCount) ||
                    (!grpPtr->retxAllowSrcList.empty()) ||
                    (!grpPtr->retxBlockSrcList.empty()))
                {
                    unsolicitedReportCount = 1;

                    Message* selfMsg;
                    char* reportCountVal;
                    Igmpv3FilterModeType* fltrMode;

                    // Act as a query just has been received
                    grpPtr->lastQueryReceive = node->getNodeTime();

                    // Allocate message to trigger self

                    reportCountVal = (char*) info1;
                    *reportCountVal = unsolicitedReportCount;

                    grpPtr->retxSeqNo++;
                    info1 += sizeof(char);
                    retxSeqNo = (unsigned int*)info1;
                    *retxSeqNo = grpPtr->retxSeqNo;

                    // set the retx filter mode
                    info = info_original;
                    info += (sizeof(NodeAddress) + sizeof(Int32));
                    fltrMode = (Igmpv3FilterModeType*)info;
                    *fltrMode = grpPtr->retxfilterMode;


                    selfMsg = MESSAGE_Duplicate(node, msg);
                    // Unsolicited Reports are sent after interval randomly
                    // calculated between (0, [Unsolicited Report Interval])
                    grpPtr->randomNum.setSeed(node->globalSeed,
                                              node->nodeId,
                                              GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                              intfId);
                    grpPtr->randomNum.setDistributionUniform(
                        0, igmpHost->unsolicitedReportInterval);
                    delayForReport = grpPtr->randomNum.getRandomNumber();

                    // Send timer to self
                    MESSAGE_Send(node, selfMsg, delayForReport);

                }
            }
        }
    } // switch
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleLeaveGroupTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpLeaveGroupTimer expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleLeaveGroupTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;
    BOOL retVal = FALSE;
    BOOL isLastHost = FALSE;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));

#ifdef ADDON_BOEINGFCS
    if (node->macData[intfId]->macProtocol ==
        MAC_PROTOCOL_LINK_EPLRS)
    {
        return;
    }
#endif

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpLeaveGroupTimer\n");

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    if (DEBUG) {
        char timeStr[MAX_STRING_LENGTH];
        char grpStr[20];

        printf("Node %u got MSG_NETWORK_IgmpLeaveGroupTimer expired\n",
            node->nodeId);

        TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
        IO_ConvertIpAddressToString(grpAddr, grpStr);
        printf("Node %u : Igmp receive group leave request from "
            "upper layer at time %s for group %s\n",
            node->nodeId, timeStr, grpStr);
    }

    // Delete group entry
    retVal = IgmpDeleteHostGroupList(
                node, grpAddr, intfId, &isLastHost);

    if (retVal && isLastHost) {
        // Send leave report
        IgmpSendLeaveReport(node, grpAddr, intfId);
    }
#ifdef CYBER_CORE
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE)
    {
        NodeAddress mappedGrpAddr = IAHEPGetMulticastBroadcastAddressMapping(
                                            node, ip->iahepData, grpAddr);

        IAHEPCreateIgmpJoinLeaveMessage(
            node,
            mappedGrpAddr,
            IGMP_LEAVE_GROUP_MSG,
            NULL);

        ip->iahepData->grpAddressList->erase(grpAddr);

        ip->iahepData->updateAmdTable->getAMDTable(0)->
                    iahepStats.iahepIGMPLeavesSent ++;

        if (IAHEP_DEBUG)
        {
            char addrStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(mappedGrpAddr, addrStr);
            printf("\nIAHEP Node: %d", node->nodeId);
            printf("\tLeaves Group: %s\n", addrStr);
        }
}
#endif //CYBER_CORE

}
//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleLastMemberTimer()
// PURPOSE      : Take action when MSG_NETWORK_IgmpLastMemberTimer expire.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandleLastMemberTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter;
    IgmpGroupInfoForRouter* grpPtr;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;
    short count;
    vector<NodeAddress> srcAddressVector;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));
    dataPtr += sizeof(int);
    memcpy(&count, dataPtr, sizeof(short));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_IgmpLastMemberTimer\n");

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;

    // Search for specified group
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);

    if (!grpPtr) {
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "Node %u: Group shouldn't be deleted before sending "
            "[Last Member Query Count] times group specific query\n",
            node->nodeId);
        ERROR_Assert(FALSE, errStr);
        return;
    }

    count++;

    // Keep setting timer until we've received a report or we've
    // sent the Group specific query [Last Member Query Count] times.

    if (((node->getNodeTime() - grpPtr->lastReportReceive) >
        (count * (grpPtr->lastMemberQueryInterval / 10)*SECOND))
        && (count < grpPtr->lastMemberQueryCount))
    {
        // Send Group specific Query message
        IgmpSendQuery(node,
                      grpAddr,
                      intfId,
                      igmpRouter->queryResponseInterval,
                      igmpRouter->lastMemberQueryInterval,
                      igmpRouter->queryInterval);

        IgmpSetLastMembershipTimer(node,
                                   grpAddr,
                                   intfId,
                                   count,
                                   igmpRouter->lastMemberQueryInterval);
    }
    else if ((count == grpPtr->lastMemberQueryCount)
        && ((node->getNodeTime() - grpPtr->lastReportReceive) >
            (count * (grpPtr->lastMemberQueryInterval / 10)*SECOND)))
    {
        MulticastProtocolType notifyMcastRtProto =
            IgmpGetMulticastProtocolInfo(node, intfId);

        ERROR_Assert(grpPtr->membershipState ==
            IGMP_ROUTER_CHECKING_MEMBERSHIP,
            "Group state should be IGMP_ROUTER_CHECKING_MEMBERSHIP\n");

        IgmpDeleteRtrGroupList(node, grpAddr, intfId);
#ifdef ADDON_DB
        HandleStatsDBIgmpSummary(node, "Delete", 0, grpAddr);
#endif
        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
        {
            if (IgmpCheckSubscriptionInAllOtherDownstreamInterface(
                node, igmp, grpAddr, intfId))
            {
                return;
            }
            else
            {
                Int32 upstreamIntfId = 0;

                upstreamIntfId =
                    (Int32)NetworkIpGetInterfaceIndexFromAddress(
                                 node, igmp->igmpUpstreamInterfaceAddr);

                //notify upstream. just call igmpleavegroup
                //with timetoleave = 0
                if (igmp->igmpProxyVersion == IGMP_V2)
                {
                    IgmpLeaveGroup(node,
                                   upstreamIntfId,
                                   grpAddr,
                                   (clocktype)0);
                }
                else
                {
                    IgmpProxyHandleSubscription(node,
                                                grpAddr);
                }

            }
        }
        else
        {
            // Notify multicast routing protocol
            if (notifyMcastRtProto)
            {
                (notifyMcastRtProto)(
                    node, grpAddr, intfId, LOCAL_MEMBER_LEAVE_GROUP);
            }
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmp3HandleOlderHostPresentTimer()
// PURPOSE      : Time-out for transitioning a member back to IGMPv3 mode
//                once an older version report is sent for that group.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None.
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleOlderHostPresentTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    char* dataPtr;
    NodeAddress grpAddr;
    Int32 intfId;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface in MSG_NETWORK_Igmpv3OlderHostPresentTimer\n");

    igmpRouter = igmp->igmpInterfaceInfo[intfId]->igmpRouter;
    ERROR_Assert(igmpRouter,
        "Invalid router info while handling OlderHostPresentTimer\n");

    grpPtr = IgmpCheckRtrGroupList(
                   node, grpAddr, igmpRouter->groupListHeadPointer);
    if (grpPtr
        && node->getNodeTime() >= grpPtr->lastOlderHostPresentTimer
        && grpPtr->lastOlderHostPresentTimer != 0)
    {
        // Set the IGMP group compatibility mode back to version 3.
        grpPtr->rtrCompatibilityMode = IGMP_V3;
        grpPtr->lastOlderHostPresentTimer = 0;
        if (DEBUG)
        {
            char grpStr[20];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("    Node %u older host present timer expired for group"
                " %s, setting the group compatibility mode back to version"
                " 3\n", node->nodeId, grpStr);
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : Igmp3HandleOlderVerQuerierPresentTimer()
// PURPOSE      : Time-out for transitioning a host back to IGMPv3 mode
//                once an older version query is heard.
// PARAMETERS   : node - this node.
//                msg - message pointer.
// RETURN VALUE : None.
// ASSUMPTION   : None.
//---------------------------------------------------------------------------
static
void Igmpv3HandleOlderVerQuerierPresentTimer(
    Node* node,
    Message* msg)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    char* dataPtr = NULL;
    IgmpHost* igmpHost = NULL;
    NodeAddress grpAddr;
    Int32 intfId;
    IgmpGroupInfoForHost* tempPtr = NULL;

    dataPtr = MESSAGE_ReturnInfo(msg);
    memcpy(&grpAddr, dataPtr, sizeof(NodeAddress));
    dataPtr += sizeof(NodeAddress);
    memcpy(&intfId, dataPtr, sizeof(int));

    ERROR_Assert(igmp->igmpInterfaceInfo[intfId],
        "Invalid interface"
        "in MSG_NETWORK_Igmpv3OlderVerQuerierPresentTimer\n");

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;
    if (grpAddr == 0)
    {
        tempPtr = igmpHost->groupListHeadPointer;
    }
    else
    {
        tempPtr = IgmpCheckHostGroupList(
            node, grpAddr, igmpHost->groupListHeadPointer);
    }

    ERROR_Assert(igmpHost,
        "Invalid host info while setting OlderVerQuerierPresentTimer\n");

    if (node->getNodeTime() >= igmpHost->lastOlderVerQuerierPresentTimer
        && igmpHost->lastOlderVerQuerierPresentTimer != 0)
    {
        // Set the IGMP version back to version 3.
        igmpHost->hostCompatibilityMode = IGMP_V3;
        igmpHost->lastOlderVerQuerierPresentTimer = 0;
        // Whenever a host changes its compatibility mode, it cancels all its
        // pending response and retransmission timers.
        if (tempPtr)
        {
            tempPtr->lastHostGrpTimerValue = 0;
            tempPtr->lastHostIntfTimerValue = 0;
            tempPtr->groupDelayTimer = IGMP_INVALID_TIMER_VAL;
            tempPtr->recordedSrcList.clear();
            tempPtr->retxAllowSrcList.clear();
            tempPtr->retxBlockSrcList.clear();
            tempPtr->retxSeqNo++;
            tempPtr->retxCount = 0;
        }
        if (DEBUG)
        {
            char grpStr[20];
            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("    Node %u older version querier present timer expired"
                " for group %s, setting the host compatibility mode back"
                " to version 3\n", node->nodeId, grpStr);
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : IgmpIsRouter()
// PURPOSE      : Check whether the node is a router
// RETURN VALUE : TRUE if this node is a router. FALSE otherwise.
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
BOOL IgmpIsRouter(
    Node* node,
    const NodeInput* nodeInput,
    Int32 interfaceId)
{
    char currentLine[200*MAX_STRING_LENGTH];

    // For IO_GetDelimitedToken
    char iotoken[MAX_STRING_LENGTH];
    char* next;

    const char *delims = "{,} \t\n";
    char *token = NULL;
    char *ptr = NULL;
    int i;
    Address srcAddr;
    NodeAddress nodeId;
    BOOL isSrcNodeId,isIpv6Addr;
    Int32 intfId;

    for (i = 0; i < nodeInput->numLines; i++)
    {
        if (strcmp(nodeInput->variableNames[i], "IGMP-ROUTER-LIST") == 0)
        {
            if ((ptr = strchr(nodeInput->values[i],'{')) == NULL)
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr,
                        "Could not find '{' character:\n  %s\n",
                        nodeInput->values[i]);
                ERROR_ReportError(errorStr);
            }
            else
            {
                strcpy(currentLine, ptr);
                token = IO_GetDelimitedToken(
                            iotoken, currentLine, delims, &next);
                if (!token)
                {
                    char errorStr[MAX_STRING_LENGTH];
                    sprintf(errorStr,
                            "Cann't find nodeId list, e.g. {1, 2, .. "
                            "}:\n%s\n",
                            currentLine);
                    ERROR_ReportError(errorStr);
                }
                while (TRUE)
                {
                    intfId = interfaceId;
                    IO_ParseNodeIdHostOrNetworkAddress(token,
                                                      &srcAddr,
                                                      &isSrcNodeId);
                    if (!isSrcNodeId)
                    {
                        intfId =
                          MAPPING_GetInterfaceIndexFromInterfaceAddress(node,
                                                                    srcAddr);
                        nodeId =
                          MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                                srcAddr);
                    }
                    else
                    {
                        if (srcAddr.networkType ==  NETWORK_IPV4)
                        {
                            nodeId = srcAddr.interfaceAddr.ipv4;
                        }
                        else
                        {
                            if (srcAddr.networkType == NETWORK_IPV6)
                            {
                                IO_ParseNodeIdHostOrNetworkAddress(token,
                                                 &srcAddr.interfaceAddr.ipv6,
                                                 &isIpv6Addr,
                                                 &nodeId);
                            }
                        }
                    }
                    if (node->nodeId == nodeId && intfId == interfaceId)
                    {
                        return TRUE;
                    }
                    token = IO_GetDelimitedToken(iotoken,
                                                 next,
                                                 delims,
                                                 &next);
                    if (!token)
                    {
                        break;
                    }
                    if (strncmp("thru", token, 4) == 0)
                    {
                        if (!isSrcNodeId)
                        {
                            char errorStr[MAX_STRING_LENGTH];
                            sprintf(errorStr,
                                    "thru should be used with Node Id \n%s",
                                    currentLine);
                            ERROR_ReportError(errorStr);
                        }
                        else
                        {
                            unsigned int maxNodeId;
                            unsigned int minNodeId;

                            minNodeId = nodeId;
                            token = IO_GetDelimitedToken(iotoken,
                                                         next,
                                                         delims,
                                                         &next);
                            if (!token)
                            {
                                char errorStr[MAX_STRING_LENGTH];
                                sprintf(errorStr,
                                        "Bad string input\n%s",
                                        currentLine);
                                ERROR_ReportError(errorStr);
                            }
                            maxNodeId = atoi(token);
                            if (maxNodeId < minNodeId)
                            {
                                char errorStr[MAX_STRING_LENGTH];
                                sprintf(errorStr,
                                        "Bad string input\n%s",
                                        currentLine);
                                ERROR_ReportError(errorStr);
                            }
                            if ((node->nodeId >= minNodeId)
                                              && (node->nodeId <= maxNodeId))
                            {
                                return TRUE;
                            }
                            else
                            {
                                token = IO_GetDelimitedToken(iotoken,
                                                             next,
                                                             delims,
                                                             &next);
                            }
                            if (!token)
                            {
                                break;
                            }
                        }
                    }
                }// End while
            }// End else
        }
    }// End for
    return FALSE;
}

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
    BOOL* localMember)
{
    IgmpData* igmp;
    IgmpRouter* igmpRouter = NULL;
    NetworkDataIp *ipLayer = (NetworkDataIp *) node->networkData.networkVar;

    *localMember = FALSE;

    // If IGMP is not running in this interface or if it's not a router
    if (ipLayer->isIgmpEnable == FALSE) {
        return;
    }

    igmp = IgmpGetDataPtr(node);
    if ((interfaceId < 0)
        || !igmp
        || !igmp->igmpInterfaceInfo[interfaceId]
        || igmp->igmpInterfaceInfo[interfaceId]->igmpNodeType != IGMP_ROUTER)
    {
        return;
    }

    igmpRouter = igmp->igmpInterfaceInfo[interfaceId]->igmpRouter;

    if (IgmpCheckRtrGroupList(
            node, grpAddr, igmpRouter->groupListHeadPointer))
    {
        *localMember = TRUE;
    }
}

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
    NodeAddress srcAddr)
{
    IgmpData* igmp;
    IgmpRouter* igmpRouter = NULL;
    NetworkDataIp *ipLayer = (NetworkDataIp *) node->networkData.networkVar;
    IgmpGroupInfoForRouter* tmpGrpPtr = NULL;
    vector<struct SourceRecord> :: iterator it;

    *localMember = FALSE;

    // If IGMP is not running in this interface or if it's not a router
    if (ipLayer->isIgmpEnable == FALSE) {
        return;
    }

    igmp = IgmpGetDataPtr(node);
    if ((interfaceId < 0)
        || !igmp
        || !igmp->igmpInterfaceInfo[interfaceId]
        || igmp->igmpInterfaceInfo[interfaceId]->igmpNodeType != IGMP_ROUTER)
    {
        return;
    }

    igmpRouter = igmp->igmpInterfaceInfo[interfaceId]->igmpRouter;
    tmpGrpPtr = IgmpCheckRtrGroupList(node,
                                      grpAddr,
                                      igmpRouter->groupListHeadPointer);


    if (tmpGrpPtr)
    {
        for (it = tmpGrpPtr->rtrForwardListVector.begin();
             it < tmpGrpPtr->rtrForwardListVector.end();
             ++it)
        {
            if ((*it).sourceAddr == srcAddr)
            {
                *localMember = TRUE;
            }
        }

    }
}

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
    MulticastProtocolType mcastProtoPtr)
{
    IgmpData* igmp = IgmpGetDataPtr(node);

    // If IGMP is not running in this interface
    if (!igmp || !igmp->igmpInterfaceInfo[interfaceId])
    {
        char errStr[MAX_STRING_LENGTH];
        char intfStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, interfaceId),
            intfStr);
        sprintf(errStr, "Node %u: IGMP is not running over interface %s\n",
            node->nodeId, intfStr);
        ERROR_Assert(FALSE, errStr);
    }

    igmp->igmpInterfaceInfo[interfaceId]->multicastProtocol = mcastProtoPtr;
}

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
    int interfaceId)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    IgmpInterfaceInfoType* thisIntf;

    // If IGMP is not running in this interface
    if (!igmp || !igmp->igmpInterfaceInfo[interfaceId])
    {
        char errStr[MAX_STRING_LENGTH];
        char intfStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceAddress(node, interfaceId),
            intfStr);
        sprintf(errStr, "Node %u: IGMP is not running over interface %s\n",
            node->nodeId, intfStr);
        ERROR_Assert(FALSE, errStr);
    }

    thisIntf = igmp->igmpInterfaceInfo[interfaceId];

    if (thisIntf->multicastProtocol)
    {
        return (thisIntf->multicastProtocol);
    }

    return NULL;
}


BOOL IgmpGrpIsInList(Node* node, LinkedList* grpList, NodeAddress groupId)
{
    ListItem* tempItem = NULL;
    NodeAddress* groupAddr = NULL;


    tempItem = grpList->first;

    while (tempItem)
    {
        groupAddr = (NodeAddress *) tempItem->data;

        if (*groupAddr == groupId)
        {
            return TRUE;
        }

        tempItem = tempItem->next;
    }

    return FALSE;
}

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
void IgmpFillGroupList(Node *node, LinkedList** grpList, int interfaceId)
{
    NetworkDataIp *ipLayer = (NetworkDataIp *) node->networkData.networkVar;
    IgmpGroupInfoForRouter *tempPtr = NULL;
    int i;
    int count = 0;


    ListInit(node, grpList);

    /* If IGMP is not running in this node or the node is not igmp router */
    IgmpNodeType nodeType =
          ipLayer->igmpDataPtr->igmpInterfaceInfo[interfaceId]->igmpNodeType;
    if ((ipLayer->isIgmpEnable == FALSE)
        || (nodeType != IGMP_ROUTER))
    {
        return;
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        /*
         * If IGMP is not running over this interface, then skip this
         * interface
        */
        if (ipLayer->igmpDataPtr->igmpInterfaceInfo[i] == NULL)
        {
            continue;
        }

        if (interfaceId != ANY_INTERFACE && interfaceId != i)
        {
            continue;
        }

        tempPtr = ipLayer->igmpDataPtr->igmpInterfaceInfo[i]
                          ->igmpRouter->groupListHeadPointer;

        while (tempPtr)
        {
            NodeAddress *groupAddr;

            if ((i != 0)
                && (IgmpGrpIsInList(node,
                                           *grpList,
                                           tempPtr->groupId)))

            {
                tempPtr = tempPtr->next;
                continue;
            }

            groupAddr = (NodeAddress *) MEM_malloc(sizeof(NodeAddress));

            memcpy(groupAddr, &tempPtr->groupId, sizeof(NodeAddress));

            ListInsert(node, *grpList, 0, (void *) groupAddr);

            count++;
            tempPtr = tempPtr->next;
        }
    }

    ERROR_Assert(count == (*grpList)->size, "Fail to fill up group list\n");
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHostHandleQuery()
// PURPOSE      : Host processing a received version 2 query.
// RETURN VALUE : TRUE if successfully process, FALSE otherwise.
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHostHandleQuery(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpInterfaceInfoType* thisInterface,
    Int32 intfId)
{
    IgmpGroupInfoForHost* tempGrpPtr;
    IgmpHost* igmpHost = NULL;

    igmpHost = thisInterface->igmpHost;

    if (DEBUG) {
        printf("    Host processing of  version 2 IGMP_QUERY_MSG\n");
    }

    if (igmpv2Pkt->groupAddress == 0)
    {
        // General query received
        if (DEBUG) {
            printf("    General query\n");
        }

#ifdef CYBER_CORE

        NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
        NodeAddress grpAddr = ANY_ADDRESS;
        set<NodeAddress>::iterator grpAddrIter;
        map<NodeAddress, NodeAddress>::iterator amdIter;
            map<NodeAddress, NodeAddress> tempGrpMapTable;

        if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE
            && IsIAHEPBlackSecureInterface(node, intfId))
        {

            amdIter = ip->iahepData->multicastAmdMapping->find(ANY_ADDRESS);
            if (amdIter !=  ip->iahepData->multicastAmdMapping->end())
            {
                    tempGrpMapTable.insert(
                    pair<NodeAddress, NodeAddress>
                    (ANY_ADDRESS, (NodeAddress)amdIter->second));
                }
            else
            {
                tempGrpMapTable.insert(
                    pair<NodeAddress, NodeAddress>
                    (ANY_ADDRESS, BROADCAST_MULTICAST_MAPPEDADDRESS));
            }

            for (grpAddrIter = ip->iahepData->grpAddressList->begin();
                            grpAddrIter != ip->iahepData->grpAddressList->end();
                            ++grpAddrIter)
            {
                grpAddr = *grpAddrIter;
                if (grpAddr != ANY_ADDRESS)
                {
                    amdIter = ip->iahepData->multicastAmdMapping->find(grpAddr);

                    if (amdIter !=  ip->iahepData->multicastAmdMapping->end())
                    {
                        tempGrpMapTable[grpAddr] = (NodeAddress)amdIter->second;
                    }
                    else
                    {
                        tempGrpMapTable[grpAddr] = grpAddr +
                            DEFAULT_RED_BLACK_MULTICAST_MAPPING;
                    }
                }
            }


            map<NodeAddress, NodeAddress>::iterator it;

            for (it = tempGrpMapTable.begin(); it != tempGrpMapTable.end();
                    ++it)
            {
                IAHEPCreateIgmpJoinLeaveMessage(
                    node,
                    it->second,
                    IGMP_MEMBERSHIP_REPORT_MSG,
                    NULL);

                thisInterface->igmpStat.igmpTotalMsgSend += 1;
                thisInterface->igmpStat.igmpTotalReportSend += 1;
                thisInterface->igmpStat.igmpv2MembershipReportSend += 1;

                ip->iahepData->updateAmdTable->getAMDTable(0)->
                    iahepStats.iahepIGMPReportsSent ++;

                if (IAHEP_DEBUG)
                {
                    char addrStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(it->second, addrStr);
                    printf("\nIAHEP Node: %d", node->nodeId);
                    printf("\tJoins Group: %s\n", addrStr);
                }
            }
        }
        else
        {
#endif //CYBER_CORE
        if (igmpHost->groupCount == 0)
        {
            if (DEBUG)
            {
                printf("    Currently no members\n");
            }

            // No member exist. Nothing to do.
            return;
        }

        tempGrpPtr = igmpHost->groupListHeadPointer;

        // Set delay timer for each group of which it is a member
        while (tempGrpPtr != NULL)
        {
            IgmpHostSetOrResetMembershipTimer(
                node, igmpv2Pkt, tempGrpPtr, intfId);

            tempGrpPtr = tempGrpPtr->next;
        }
#ifdef CYBER_CORE
        }
#endif //CYBER_CORE
    }
    else
    {
        // Group specific query
        if (DEBUG) {
            printf("    Group specific query\n");
        }

        // Search for specified group
        tempGrpPtr = IgmpCheckHostGroupList(
            node, igmpv2Pkt->groupAddress, igmpHost->groupListHeadPointer);

        // If the group exist, set timer for sending report
        if (tempGrpPtr)
        {
            IgmpHostSetOrResetMembershipTimer(
                node, igmpv2Pkt, tempGrpPtr, intfId);
        }
        else
        {
            IgmpData* igmp = IgmpGetDataPtr(node);

            ERROR_Assert(igmp, " IGMP interface not found");
            if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_HOST) {
                if (DEBUG) {
                    printf("    Received bad query\n");
                }

                thisInterface->igmpStat.igmpBadQueryReceived += 1;
                thisInterface->igmpStat.igmpBadMsgReceived += 1;
            }
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HostHandleQuery()
// PURPOSE      : Host processing a received version 3 query.
// PARAMETERS   : node - this node.
//                igmpv3QueryPkt - pointer to IgmpQueryMessage.
//                thisInterface - pointer to IgmpInterfaceInfoType.
//                intfId - interface index.
// RETURN VALUE : TRUE if successfully process, FALSE otherwise.
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HostHandleQuery(
    Node* node,
    IgmpQueryMessage* igmpv3QueryPkt,
    IgmpInterfaceInfoType* thisInterface,
    Int32 intfId)
{
    Int32 maxRespTime = 0;
    clocktype delayTimer = (clocktype)0;
    clocktype remDelay = (clocktype)0;
    IgmpGroupInfoForHost* tempGrpPtr = NULL;
    IgmpHost* igmpHost = NULL;

    igmpHost = thisInterface->igmpHost;

    if (DEBUG)
    {
        printf("Host processing of version 3 IGMP_QUERY_MSG\n");
    }
    if (igmpv3QueryPkt->qqic < 128)
    {
        igmpHost->querierQueryInterval = igmpv3QueryPkt->qqic;
    }
    else
    {
        igmpHost->querierQueryInterval = Igmpv3ConvertCodeToValue(
                                                igmpv3QueryPkt->qqic);
    }
    if (igmpv3QueryPkt->maxResponseCode < 128)
    {
        igmpHost->maxRespTime = igmpv3QueryPkt->maxResponseCode;
    }
    else
    {
        igmpHost->maxRespTime = Igmpv3ConvertCodeToValue(
                            igmpv3QueryPkt->maxResponseCode);
    }
    if (igmpHost->groupCount == 0)
    {
        if (DEBUG) {
            printf("    Currently no members\n");
        }

        // No member exist. Nothing to do.
        return;
    }
    if (igmpv3QueryPkt->groupAddress == 0)
    {
        // General IGMPv3 query received
        if (DEBUG)
        {
            printf("General query\n");
        }
        tempGrpPtr = igmpHost->groupListHeadPointer;
        // Set delay timer for each group of which it is a member
        while (tempGrpPtr != NULL)
        {
            // a delay for a response is randomly selected in the range
            // (0, [Max Resp Time])
            tempGrpPtr->randomNum.setSeed(node->globalSeed,
                                        node->nodeId,
                                        GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                        intfId);
            tempGrpPtr->randomNum.setDistributionUniform(
                        0,((maxRespTime / 10) * SECOND));
            delayTimer = tempGrpPtr->randomNum.getRandomNumber();
            // If there is a pending response to a previous General Query
            // scheduled sooner than the selected delay, no additional
            // response needs to be scheduled.
            if (tempGrpPtr->lastHostIntfTimerValue != 0)
            {
                // Pending response for a general query
                // Calculate remaining delay of the pending response
                remDelay = tempGrpPtr->lastHostIntfTimerValue
                    - node->getNodeTime();
                if (delayTimer >= remDelay)
                {
                    return;
                }
                else
                {
                    Igmpv3HostSetInterfaceTimer(
                        node,
                        delayTimer,
                        tempGrpPtr,
                        intfId);
                }
            }
            else
            {
                // If the received Query is a General Query,schedule a
                // response to the General Query after the selected delay.
                // Any previously pending response to a General Query is
                // canceled.
                    Igmpv3HostSetInterfaceTimer(
                        node,
                        delayTimer,
                        tempGrpPtr,
                        intfId);
            }
            tempGrpPtr = tempGrpPtr->next;
        }
    }
    else
    {
        // It is a group-specific or a group-and-source-specific query
        // Search for specified group
        tempGrpPtr = IgmpCheckHostGroupList(node,
                                            igmpv3QueryPkt->groupAddress,
                                            igmpHost->groupListHeadPointer);
        if (tempGrpPtr)
        {
            // a delay for a response is randomly selected in the range
            // (0, [Max Resp Time])
            tempGrpPtr->randomNum.setSeed(node->globalSeed,
                                        node->nodeId,
                                        GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                        intfId);
            tempGrpPtr->randomNum.setDistributionUniform(
                        0, ((maxRespTime / 10) * SECOND));
            delayTimer = tempGrpPtr->randomNum.getRandomNumber();
            if (tempGrpPtr->lastHostGrpTimerValue == 0)
            {
                if (igmpv3QueryPkt->numSources != 0)
                {
                    // Group and source specific query
                    if (DEBUG) {
                        printf("    Group and source specific query\n");
                    }
                    // Record the source list present in the query to be
                    // used when generating a response.
                    tempGrpPtr->recordedSrcList = igmpv3QueryPkt->sourceAddress;
                }
                else
                {
                    if (DEBUG) {
                     printf(" Group specific query\n");
                    }
                }
                Igmpv3HostSetGrpTimer(
                    node, delayTimer, tempGrpPtr, intfId);
            }
            // Pending query responses are present.
            else
            {
                if (igmpv3QueryPkt->numSources == 0
                    || tempGrpPtr->recordedSrcList.empty())
                {
                    if (DEBUG) {
                        printf(" Group specific query received and pending"
                         " response to a query present\n");
                    }
                    // group source-list is cleared and a single
                    // response is scheduled using the group timer
                    if (!tempGrpPtr->recordedSrcList.empty())
                    {
                        tempGrpPtr->recordedSrcList.clear();
                    }
                }
                // Group-and-Source-Specific Query with non-empty recorded
                // source-list
                else if (igmpv3QueryPkt->numSources != 0
                    && !tempGrpPtr->recordedSrcList.empty())
                {
                    if (DEBUG) {
                        printf(" Group and source specific query\n");
                    }
                    // The group source list is augmented to contain
                    //the list of sources in the new Query
                    set_union(tempGrpPtr->recordedSrcList.begin(),
                        tempGrpPtr->recordedSrcList.end(),
                        igmpv3QueryPkt->sourceAddress.begin(),
                        igmpv3QueryPkt->sourceAddress.end(),
                        tempGrpPtr->recordedSrcList.begin());
                }
                // Calculate remaining delay of the pending response
                remDelay = tempGrpPtr->lastHostGrpTimerValue
                    - node->getNodeTime();
                // The new response is to be sent at the earliest of the
                // remaining time for the pending report and selected delay.
                if (delayTimer >= remDelay)
                {
                    return;
                }
                else
                {
                    Igmpv3HostSetGrpTimer(
                        node, delayTimer, tempGrpPtr, intfId);
                }
            }
        }
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : IgmpHostHandleReport()
// PURPOSE      : Host processing a received report.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHostHandleReport(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpInterfaceInfoType* thisInterface)
{
    IgmpHost* igmpHost = NULL;
    IgmpGroupInfoForHost* tempGrpPtr = NULL;

    igmpHost = thisInterface->igmpHost;

    //This stat has already been incremented at the
    //time of calling this function

    //thisInterface->igmpStat.igmpTotalReportReceived += 1;

    if (DEBUG) {
        printf("    Host processing of IGMP_V2_MEMBERSHIP_REPORT_MSG\n");
    }

    // Search for specified group
    tempGrpPtr = IgmpCheckHostGroupList(
        node, igmpv2Pkt->groupAddress, igmpHost->groupListHeadPointer);

    // If the group exist cancel timer to prevent sending
    // of duplicate report in the subnet
    if (tempGrpPtr)
    {
        tempGrpPtr->lastReportSendOrReceive = node->getNodeTime();
        tempGrpPtr->hostState = IGMP_HOST_IDLE_MEMBER;

        // Remember that we are not the last host to reply to Query
        tempGrpPtr->isLastHost = FALSE;

        if (DEBUG) {
            char timeStr[MAX_STRING_LENGTH];
            char ipStr[MAX_ADDRESS_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
            IO_ConvertIpAddressToString(igmpv2Pkt->groupAddress, ipStr);
            printf("    Receive membership report for group %s at "
                "time %ss\n"
                "    Cancelling self timer",
                ipStr, timeStr);
        }
    }
    else
    {
        if (thisInterface->igmpNodeType == IGMP_HOST) {
            if (DEBUG) {
                printf("    Received bad membership report\n");
            }
            thisInterface->igmpStat.igmpBadReportReceived += 1;
            thisInterface->igmpStat.igmpBadMsgReceived += 1;
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandlePacketForHost()
// PURPOSE      : Host processing a incoming IGMP packet.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandlePacketForHost(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpMessage* igmpv2Pkt = NULL;
    IgmpQueryMessage igmpv3QueryPkt;
    Igmpv3ReportMessage igmpv3ReportPkt;
    IgmpData* igmp = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    IgmpHost* igmpHost = NULL;
    UInt8* ver_type;
    UInt16 numSrc;
    Int32 pktSize;
    NodeAddress groupAddr;

    ver_type = (UInt8*) MESSAGE_ReturnPacket(msg);
    igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    thisInterface = igmp->igmpInterfaceInfo[intfId];
    igmpHost = thisInterface->igmpHost;
    pktSize = MESSAGE_ReturnPacketSize(msg);

    switch (*ver_type)
    {
        case IGMP_QUERY_MSG:
        {
            igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);

            thisInterface->igmpStat.igmpTotalQueryReceived += 1;

            if (igmpHost->hostCompatibilityMode == IGMP_V3)
            {
                if (pktSize == IGMPV2_QUERY_FIXED_SIZE)
                {
                    grpAddr = igmpv2Pkt->groupAddress;

                    if (grpAddr == 0)
                    {
                        // Switch to older version when version 3 host
                        // receives version 2 general query
                        igmpHost->hostCompatibilityMode = IGMP_V2;
                        Igmpv3SetOlderVerQuerierPresentTimer(node,
                                                             grpAddr,
                                                             intfId);
                        thisInterface->igmpStat.igmpGenQueryReceived += 1;
                        IgmpHostHandleQuery(
                            node, igmpv2Pkt, thisInterface, intfId);
                    }
                }
                else if (pktSize >= IGMPV3_QUERY_FIXED_SIZE)
                {
                    Igmpv3CreateDataFromQueryPkt(msg, &igmpv3QueryPkt);
                    numSrc = igmpv3QueryPkt.numSources;
                    groupAddr = igmpv3QueryPkt.groupAddress;
                    Igmpv3HostHandleQuery(
                        node, &igmpv3QueryPkt, thisInterface, intfId);
                    if (numSrc > 0)
                    {
                        thisInterface->
                            igmpStat.igmpGrpAndSourceSpecificQueryReceived += 1;
                    }
                    else
                    {
                        if (groupAddr == 0)
                        {
                            thisInterface->igmpStat.igmpGenQueryReceived += 1;
                        }
                        else
                        {
                            thisInterface->
                                igmpStat.igmpGrpSpecificQueryReceived += 1;
                        }
                    }
                }
                else
                {
                    thisInterface-> igmpStat.igmpBadQueryReceived += 1;
                }
            }
            else
            {
                groupAddr = igmpv2Pkt->groupAddress;
                IgmpHostHandleQuery(
                    node, igmpv2Pkt, thisInterface, intfId);
                if (groupAddr == 0)
                {
                    thisInterface->igmpStat.igmpGenQueryReceived += 1;
                }
                else
                {
                    thisInterface->igmpStat.igmpGrpSpecificQueryReceived += 1;
                }
            }
            break;
        }
        case IGMP_MEMBERSHIP_REPORT_MSG:
        {
            igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);
            groupAddr = igmpv2Pkt->groupAddress;
            if (igmpHost->hostCompatibilityMode == IGMP_V3)
            {
                if (DEBUG)
                {
                    char netStr[20];
                    IO_ConvertIpAddressToString(
                       NetworkIpGetInterfaceNetworkAddress(node, intfId),
                       netStr);
                    printf("    Node %u version 3 host received"
                         "version 2 membership report on network %s\n",
                         node->nodeId, netStr);
                }
                return;
            }
            else
            {
                IgmpHostHandleReport(node, igmpv2Pkt, thisInterface);
                thisInterface->
                    igmpStat.igmpv2MembershipReportReceived += 1;
                thisInterface->igmpStat.igmpTotalReportReceived += 1;
            }
            break;
        }
        case IGMP_V3_MEMBERSHIP_REPORT_MSG:
        {
            thisInterface->igmpStat.igmpTotalReportReceived += 1;
            thisInterface->igmpStat.igmpv3MembershipReportReceived += 1;
            break;
        }
        default:
        {
            thisInterface->igmpStat.igmpBadMsgReceived += 1;

            if (DEBUG) {
                printf("    Invalid Message type");
            }
            break;
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmp3RouterHandleQuery()
// PURPOSE      : Router processing a received query.
// PARAMETERS   : node - this node.
//                igmpv3QueryPkt - pointer to IgmpQueryMessage.
//                igmpRouter - pointer to IgmpRouter.
//                srcAddr - source address from where the query is originated
//                intfId - query received at this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterHandleQuery(
    Node* node,
    IgmpQueryMessage* igmpv3QueryPkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId)
{
    NodeAddress intfAddr, grpAddr;
    clocktype delay;
    bool sFlag = TRUE;
    UInt8 qrv;
    UInt8 sFlagValue;
    Message* newMsg = NULL;
    IgmpInterfaceInfoType* thisInterface= NULL;

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    thisInterface = igmp->igmpInterfaceInfo[intfId];
    ERROR_Assert(thisInterface,
        "Invalid interface while processing of version 3 IGMP_QUERY_MSG\n");
    IgmpGroupInfoForRouter* tempGrpPtr = NULL;

    intfAddr = NetworkIpGetInterfaceAddress(node, intfId);

    if (DEBUG)
    {
        printf(" IGMPv3 Router processing of IGMP_QUERY_MSG\n");
    }
    grpAddr = igmpv3QueryPkt->groupAddress;

    if (igmpv3QueryPkt->maxResponseCode < 128)
    {
        igmpRouter->queryResponseInterval =
            igmpv3QueryPkt->maxResponseCode;
    }
    else
    {
        igmpRouter->queryResponseInterval = (UInt8)Igmpv3ConvertCodeToValue(
                            igmpv3QueryPkt->maxResponseCode);
    }
    if (igmpv3QueryPkt->qqic < 128)
    {
        igmpRouter->queryInterval = igmpv3QueryPkt->qqic;
    }
    else
    {
        igmpRouter->queryInterval = Igmpv3ConvertCodeToValue(
                                        igmpv3QueryPkt->qqic) * SECOND;
    }
    qrv = Igmpv3QueryGetQRV(igmpv3QueryPkt->query_qrv_sFlag);
    sFlagValue = Igmpv3QueryGetSFlag(igmpv3QueryPkt->query_qrv_sFlag);
    if (sFlagValue == 0)
    {
        sFlag = FALSE;
    }
    else
    {
        sFlag = TRUE;
    }
    // Set the robustness variable of the current interface to
    // robustness variable contained in query only if the query
    // value is greater than zero.
    if (qrv > 0)
    {
        thisInterface->robustnessVariable = qrv;
    }
    // Querier Router selection
    if ((grpAddr == 0) && (srcAddr <(signed) intfAddr)
        && (!igmp->igmpInterfaceInfo[intfId]->isAdHocMode))
    {
        if (igmpRouter->routersState == IGMP_QUERIER)
        {
            if (DEBUG) {
                char netStr[20];

                IO_ConvertIpAddressToString(
                    NetworkIpGetInterfaceNetworkAddress(node, intfId),
                    netStr);
                printf("    Node %u become non querier on network %s\n",
                        node->nodeId, netStr);
            }
            // Make this router as Non-Querier
            igmpRouter->routersState = IGMP_NON_QUERIER;
        }

        newMsg = MESSAGE_Alloc(
                    node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_IgmpOtherQuerierPresentTimer);

        MESSAGE_InfoAlloc(node, newMsg, sizeof(int));
        memcpy(MESSAGE_ReturnInfo(newMsg), &intfId, sizeof(int));
        //The default value for Query Response interval is 100 which on
        //converting into units comes out to be 10 seconds. In QualNet at
        //initialization it is stored as 100 or converting the value configured
        //by user (in seconds) to the normal value i.e. dividing by seconds and
        //multiplying by 10.Hence,it is required to divide the current value in
        //queryResponseInterval by 10 and multiply by SECOND.
            delay = (clocktype)
                (((thisInterface->robustnessVariable)
                  * igmpRouter->queryInterval)
                 +( 0.5 * (igmpRouter->queryResponseInterval * SECOND)
                   /IGMP_QUERY_RESPONSE_SCALE_FACTOR));

        MESSAGE_Send(node, newMsg, delay);
    }

    // If it is Group-Specific-Query or Group-and-Source-Specific-Query
    // and the router is Non-Querier.
    if ((grpAddr != 0) && (igmpRouter->routersState == IGMP_NON_QUERIER))
    {

        // Search for specific group
        tempGrpPtr = IgmpCheckRtrGroupList(node,
                                           grpAddr,
                                           igmpRouter->groupListHeadPointer);

        if (tempGrpPtr)
        {
            // Update timers if the "suppress router side processing" flag
            // in query is clear, else do not update timers.
            if (sFlag == TRUE)
            {
                // do nothing
            }
            else
            {
                // Group and source specific query
                if (igmpv3QueryPkt->numSources != 0)
                {
                    vector<SourceRecord> :: iterator iter;
                    UInt32 it = 0;
                    for (it;
                         it < igmpv3QueryPkt->sourceAddress.size();
                         it++)
                    {
                        for (iter = tempGrpPtr->rtrForwardListVector.begin();
                             iter < tempGrpPtr->rtrForwardListVector.end();
                             ++iter)
                        {
                            if ((*iter).sourceAddr
                                 == igmpv3QueryPkt->sourceAddress[it])
                            {
                                (*iter).sourceTimer =
                                    tempGrpPtr->lastMemberQueryCount
                                    * ((tempGrpPtr->lastMemberQueryInterval
                                        / 10) * SECOND);
                                break;
                            }
                        }
                    }
                }
                else
                {
                    // Group specific query
                    clocktype remainingDelay, delay;
                    remainingDelay =
                        tempGrpPtr->lastGroupTimerValue - node->getNodeTime();

                    delay = tempGrpPtr->lastMemberQueryCount
                        * ((tempGrpPtr->lastMemberQueryInterval / 10)
                            * SECOND);

                    // Group Timer is lowered to LMQT
                    if (remainingDelay > delay)
                    {
                        if (DEBUG) {
                            char timeStr[MAX_STRING_LENGTH];

                            TIME_PrintClockInSecond(delay, timeStr);
                            printf("Non Querier router setting group delay "
                                    "timer to new value %ss\n", timeStr);
                        }
                        // Set timer for the membership
                        Igmpv3SetRouterGroupTimer(
                            node, tempGrpPtr, delay, intfId);
                    }
                }// End of group specific query case
            }
        }// End of group pointer present case
    }// End of router is a non-querier case
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpRouterHandleQuery()
// PURPOSE      : Router processing a received query.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpRouterHandleQuery(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId,
    Int32 robustnessVariable)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpGroupInfoForRouter* tempGrpPtr;
    NodeAddress intfAddr;
    Message* newMsg;

    intfAddr = NetworkIpGetInterfaceAddress(node, intfId);

    if (DEBUG) {
        printf("    Router processing of IGMP_QUERY_MSG\n");
    }

    // Querier Router selection
    if ((igmpv2Pkt->groupAddress == 0) && (srcAddr <(signed) intfAddr) &&
        !igmp->igmpInterfaceInfo[intfId]->isAdHocMode)
    {
        if (igmpRouter->routersState == IGMP_QUERIER)
        {
            // If the router is in checking membership state
            // then ignore Querier to Non-Querier transition
            tempGrpPtr = igmpRouter->groupListHeadPointer;

            while ((tempGrpPtr != NULL)
                && (tempGrpPtr->membershipState !=
                    IGMP_ROUTER_CHECKING_MEMBERSHIP))
            {
                tempGrpPtr = tempGrpPtr->next;
            }

            if (!tempGrpPtr)
            {
                if (DEBUG) {
                    char netStr[20];

                    IO_ConvertIpAddressToString(
                        NetworkIpGetInterfaceNetworkAddress(node, intfId),
                        netStr);
                    printf("    Node %u become non querier on network %s\n",
                            node->nodeId, netStr);
                }

                // Make this router as Non-Querier
                igmpRouter->routersState = IGMP_NON_QUERIER;
            }
        }

        // Note the time when last query message receive
        igmpRouter->timer.lastQueryReceiveTime = node->getNodeTime();

        newMsg = MESSAGE_Alloc(
                    node, NETWORK_LAYER, GROUP_MANAGEMENT_PROTOCOL_IGMP,
                    MSG_NETWORK_IgmpOtherQuerierPresentTimer);

        MESSAGE_InfoAlloc(node, newMsg, sizeof(int));
        memcpy(MESSAGE_ReturnInfo(newMsg), &intfId, sizeof(int));
    //The default value for Query Response interval is 100 which on
    //converting into units comes out to be 10 seconds. In QualNet at
    //initialization it is stored as 100 or converting the value configured
    //by user (in seconds) to the normal value i.e. dividing by seconds and
    //multiplying by 10.Hence,it is required to divide the current value in
    //queryResponseInterval by 10 and multiply by SECOND.
        MESSAGE_Send(node,
                     newMsg,
                     (clocktype) ((robustnessVariable * igmpRouter->queryInterval)
                      +( 0.5 * (igmpRouter->queryResponseInterval * SECOND)
                      /IGMP_QUERY_RESPONSE_SCALE_FACTOR)));

    }

    // If it is Group-Specific-Query and the router is Non-Querier
    if ((igmpv2Pkt->groupAddress != 0)
        && (igmpRouter->routersState == IGMP_NON_QUERIER))
    {
        // Search for specific group
        tempGrpPtr = IgmpCheckRtrGroupList(
                        node, igmpv2Pkt->groupAddress,
                        igmpRouter->groupListHeadPointer);

        if (tempGrpPtr)
        {
            clocktype remainingDelay;
            clocktype checkingMembershipDelay;

            remainingDelay =
                tempGrpPtr->groupMembershipInterval -
                (node->getNodeTime() - tempGrpPtr->lastReportReceive);

            checkingMembershipDelay =
                tempGrpPtr->lastMemberQueryCount *
                ((igmpv2Pkt->maxResponseTime /10)* SECOND);

            // When a non-Querier receives a Group-Specific Query
            // message, if its existing group membership timer is
            // greater than [Last Member Query Count] times the Max
            // Response Time specified in the message, it sets its
            // group membership timer to that value.
            if (remainingDelay > checkingMembershipDelay)
            {
                tempGrpPtr->groupMembershipInterval =
                    checkingMembershipDelay;

                if (DEBUG) {
                    char timeStr[MAX_STRING_LENGTH];

                    TIME_PrintClockInSecond(
                        checkingMembershipDelay, timeStr);
                    printf("    Non Querier router setting group delay "
                        "timer to new value %ss\n",
                        timeStr);
                }

                // Set timer for the membership
                IgmpSetGroupMembershipTimer(
                    node, tempGrpPtr, intfId);
            }
        }
    }
    //IAHEP node need to get original multicast Address in case of Query
    //message recieved from Black Node
#ifdef CYBER_CORE
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE)
    {
        NodeAddress mappedGrpAddr = 0;
        map<NodeAddress,NodeAddress>::iterator it;

        if (igmpv2Pkt->groupAddress)
        {
            for (it=ip->iahepData->multicastAmdMapping->begin();
            it != ip->iahepData->multicastAmdMapping->end(); it++)
            {
                if ((*it).second == igmpv2Pkt->groupAddress)
                {
                    mappedGrpAddr = (*it).first;
                }
            }

            if (!mappedGrpAddr)
            {
                mappedGrpAddr = mappedGrpAddr
                    - DEFAULT_RED_BLACK_MULTICAST_MAPPING;
            }
        }

        IAHEPCreateIgmpJoinLeaveMessage(
            node,
            mappedGrpAddr,
            IGMP_QUERY_MSG,
            igmpv2Pkt);

        if (IAHEP_DEBUG)
        {
            char addrStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(mappedGrpAddr, addrStr);
            printf("\nIAHEP Node: %d", node->nodeId);
            printf("\nSends Query To Red Node For Group: %s\n", addrStr);
        }
    }
#endif

}
#ifdef CYBER_CORE
/*!
 * \brief Get PIM SM Data
 *
 * \param node      Pointer to current node
 * \param intfId    Interface index
 *
 * \return     Pointer to the pim sm data
 *
 * Get pim sm data for the node. Called when it is to check if PIM SM
 * is enabled.
 */
static
PimDataSm* IgmpGetPimSmData(
               Node* node,
               Int32 intfId)
{
    PimData* pim = NULL;
    PimDataSm* pimDataSm = NULL;

    if (pim = (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
        MULTICAST_PROTOCOL_PIM))
    {
        if (pim->modeType == ROUTING_PIM_MODE_SPARSE)
        {
            pimDataSm = (PimDataSm*)pim->pimModePtr;
        }
        else if (pim->modeType == ROUTING_PIM_MODE_SPARSE_DENSE)
        {
            pimDataSm = ((PimDataSmDm*)pim->pimModePtr)->pimSm;
        }
    }

    return pimDataSm;
}

/*!
 * \brief Check if PIM SM is enabled on the node
 *
 * \param node      Pointer to current node
 * \param intfId    Interface index
 *
 * \return     TRUE if PIM SM is enabled, otherwise FALSE
 *
 * Check if pim sm is enabled on the node. Called when black node receives
 * a report message.
 */
static
BOOL IgmpPimSmIsEnabled(
        Node* node,
        Int32 intfId)
{
    PimDataSm* pimDataSm = NULL;

    pimDataSm = IgmpGetPimSmData(node, intfId);
    if (pimDataSm)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

/*!
 * \brief Start the black network (S,G) PIM JOIN process by notifying
 *        PIM SM module at IAHEP node with (src,grp) info
 *
 * \param node      Pointer to current node
 * \param intfId    Interface index
 * \param blackMcstSrcAddr black source address
 * \param blackMcstGrpAddress black group address
 * \param event     JOIN or LEAVE message
 *
 * \return     NONE
 *
 * Start the black network (S,G) JOIN process. Called when black node receives
 * a report message.
 */
static
void IgmpStartPimSmSGJoinLeaveInBlackNetwork(
            Node* node,
            Int32 intfId,
            NodeAddress blackMcstSrcAddress,
            NodeAddress blackMcstGrpAddress,
            LocalGroupMembershipEventType event)
{
    PimDataSm* pimDataSm = NULL;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    pimDataSm = IgmpGetPimSmData(node, intfId);
    PimData* pim =
        (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
                                                       MULTICAST_PROTOCOL_PIM);

    // if a black router receivers a IGMP report with
    // blackSrcAddress inititate the PIM-SM SPT JOIN in black side
    if (pimDataSm
        && ip->iahepEnabled
        && ip->iahepData->nodeType == BLACK_NODE
        && IsIAHEPBlackSecureInterface(node, intfId))
    {
        Int32 mcastIntfId = intfId;

        for (int i = 0; i < node->numberInterfaces; i++)
        {
            if (IgmpGetMulticastProtocolInfo(node, i) != NULL)
            {
                mcastIntfId = i;
                break;
            }
        }

        MulticastProtocolType notifyMcastRtProto =
                IgmpGetMulticastProtocolInfo(node, mcastIntfId);
        if (notifyMcastRtProto)
        {
            if (!pim->interface[intfId].srcGrpList)
            {
                ListInit(node, &pim->interface[intfId].srcGrpList);
            }
            RoutingPimSourceGroupList srcGrpPair;
            srcGrpPair.srcAddr = blackMcstSrcAddress;
            srcGrpPair.groupAddr = blackMcstGrpAddress;
            ListInsert(node,
                       pim->interface[intfId].srcGrpList,
                       node->getNodeTime(),
                       (void*)&srcGrpPair);
            (notifyMcastRtProto)(node,
                                 blackMcstGrpAddress,
                                 intfId,
                                 event);
        }
    }
}
#endif
//---------------------------------------------------------------------------
// FUNCTION     : IgmpRouterHandleReport()
// PURPOSE      : Router processing a received report.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpRouterHandleReport(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId,
    Int32 robustnessVariable
#ifdef CYBER_CORE
    ,
    NodeAddress* mcstSrcAddress
#endif
                           )
{
    IgmpGroupInfoForRouter* grpPtr;
    NodeAddress grpAddr;
    NodeAddress intfAddr;
    IgmpData* igmp=NULL;
    NetworkDataIp* ip = (NetworkDataIp* ) node->networkData.networkVar;

    intfAddr = NetworkIpGetInterfaceAddress(node, intfId);

    if (DEBUG) {
        printf("    Router processing of IGMP_MEMBERSHIP_REPORT_MSG\n");
    }

    grpAddr = igmpv2Pkt->groupAddress;

    // Search for the specified group.
    grpPtr = IgmpCheckRtrGroupList(
                node, grpAddr, igmpRouter->groupListHeadPointer);

    if (grpPtr)
    {
        // If this group already exist in list
        if (DEBUG) {
            char grpStr[20];

            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("    Receive Membership Report for Group %s\n",
                grpStr);
        }

        // Group is already exist. Check membership state for this group,
        // i.e; whether the state is checking membership or member present.
        if (grpPtr->membershipState == IGMP_ROUTER_CHECKING_MEMBERSHIP
            || grpPtr->membershipState == IGMP_ROUTER_MEMBERS)
        {
            grpPtr->membershipState = IGMP_ROUTER_MEMBERS;
            /*grpPtr->groupMembershipInterval = IGMP_GROUP_MEMBERSHIP_INTERVAL;*/
            //The default value for Query Response interval is 100 which on
            //converting into units comes out to be 10 seconds. In QualNet at
            //initialization it is stored as 100 or converting the value configured
            //by user (in seconds) to the normal value i.e. dividing by seconds and
            //multiplying by 10.Hence,it is required to divide the current value in
            //queryResponseInterval by 10 and multiply by SECOND.
            grpPtr->groupMembershipInterval = (clocktype)
                ((robustnessVariable * igmpRouter->queryInterval)
                + (igmpRouter->queryResponseInterval * SECOND)
                /IGMP_QUERY_RESPONSE_SCALE_FACTOR);

            // Note that we've receive a membership report
            grpPtr->lastReportReceive = node->getNodeTime();

            // Set timer for the membership
            IgmpSetGroupMembershipTimer(node, grpPtr, intfId);
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            char grpStr[MAX_ADDRESS_STRING_LENGTH];

            IO_ConvertIpAddressToString(grpAddr, grpStr);
            sprintf(errStr, "Unknown router state at node %u for group %s\n",
                node->nodeId, grpStr);
            ERROR_Assert(FALSE, errStr);
        }
    }
    else
    {
        MulticastProtocolType notifyMcastRtProto =
            IgmpGetMulticastProtocolInfo(node, intfId);

        // No entry found for this group, so add it to list.
        grpPtr = IgmpInsertRtrGroupList(node,
                                        grpAddr,
                                        intfId,
                                        robustnessVariable);
        if (DEBUG) {
            char grpStr[20];

            IO_ConvertIpAddressToString(grpAddr, grpStr);
            printf("    Receive Membership Report for Group %s\n",
                grpStr);
        }

        // Set timer for the membership
        IgmpSetGroupMembershipTimer(node, grpPtr, intfId);

        igmp = IgmpGetDataPtr(node);
        ERROR_Assert(igmp, " IGMP interface not found");

        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
        {
            if (IgmpCheckSubscriptionInAllOtherDownstreamInterface(
                node, igmp, grpAddr, intfId))
            {
                return;
            }
            else
            {
                Int32 upstreamIntfId = 0;
                char filterMode[MAX_STRING_LENGTH] = {0};
                vector<NodeAddress> sourceList;
                upstreamIntfId =
                    (Int32)NetworkIpGetInterfaceIndexFromAddress(
                                     node, igmp->igmpUpstreamInterfaceAddr);

                //notify upstream. just call igmpjoingroup with timetojoin=0
                if (igmp->igmpProxyVersion == IGMP_V2)
                {
                    IgmpJoinGroup(node,
                                  upstreamIntfId,
                                  grpAddr,
                                  (clocktype)0,
                                  filterMode,
                                  &sourceList);
                }
                else
                {
                    IgmpProxyHandleSubscription(node,
                                                grpAddr);
                }
            }
        }
        else
        {
#ifdef CYBER_CORE
            BOOL pimSmEnabled = FALSE;
            pimSmEnabled = IgmpPimSmIsEnabled(node, intfId);
            if (pimSmEnabled &&
                ip->iahepData &&
                ip->iahepData->nodeType == BLACK_NODE &&
                mcstSrcAddress != NULL)
            {
                IgmpStartPimSmSGJoinLeaveInBlackNetwork(
                        node, intfId, *mcstSrcAddress, grpAddr,
                        LOCAL_MEMBER_JOIN_GROUP);
            }
            else
#endif
            // Notify multicast routing protocol about the new membership.
            if (notifyMcastRtProto)
            {
                (notifyMcastRtProto)(node,
                                     grpAddr,
                                     intfId,
                                     LOCAL_MEMBER_JOIN_GROUP);
            }
        }
    }

#ifdef ADDON_DB
    HandleStatsDBIgmpSummary(node, "Join", srcAddr, grpAddr);
#endif

#ifdef CYBER_CORE

    if (ip->iahepEnabled)
    {
        if (ip->iahepData->nodeType == IAHEP_NODE)
        {
            NodeAddress mappedGrpAddr = IAHEPGetMulticastBroadcastAddressMapping(
                                            node, ip->iahepData, grpAddr);

            NodeAddress blackSrcAddress;
            NodeAddress *mappedSrcAddr = NULL;

            if (mcstSrcAddress)
            {
                IAHEPAmdMappingType* amdEntry =
                        IAHEPGetAMDInfoForDestinationRedAddress(node, *mcstSrcAddress);

                if (amdEntry)
                {
                    blackSrcAddress = amdEntry->destBlackInterface;
                    mappedSrcAddr = &blackSrcAddress;
                }
            }
            IAHEPCreateIgmpJoinLeaveMessage(
                node,
                mappedGrpAddr,
                IGMP_MEMBERSHIP_REPORT_MSG,
                NULL,
                mappedSrcAddr);

            ip->iahepData->grpAddressList->insert(grpAddr);

            ip->iahepData->updateAmdTable->getAMDTable(0)->
                    iahepStats.iahepIGMPReportsSent ++;

            if (IAHEP_DEBUG)
            {
                char addrStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(mappedGrpAddr, addrStr);
                printf("\nIAHEP Node: %d", node->nodeId);
                printf("\tJoins Group: %s\n", addrStr);
            }
        }
    }
#endif
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
                                NodeAddress grpAddr)
{
    IgmpData* igmp = NULL;
    IgmpProxyData* subscription = NULL;
    ListItem* proxyDataListItem = NULL;
    IgmpRouter* igmpRouter = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    bool found = FALSE;
    bool modified = FALSE;
    int i = 0;
    igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    proxyDataListItem = igmp->igmpProxyDataList->first;
    IgmpProxyData* currentSubscription = NULL;
    IgmpProxyData* mergedSubscription = NULL;
    IgmpProxyData* tempSubscription = NULL;
    Int32 upstreamIntfId;
    char flterMode[MAX_STRING_LENGTH] = "\0";
    NetworkDataIp* ipLayer = NULL;
    ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    upstreamIntfId = (Int32)NetworkIpGetInterfaceIndexFromAddress(node,
                                            igmp->igmpUpstreamInterfaceAddr);
    currentSubscription = (IgmpProxyData*)MEM_malloc(sizeof(IgmpProxyData));
    memset(currentSubscription, 0, sizeof(IgmpProxyData));

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (i == upstreamIntfId)
        {
            continue;
        }
        else
        {
            igmpRouter = igmp->igmpInterfaceInfo[i]->igmpRouter;
            grpPtr = IgmpCheckRtrGroupList(node,
                                           grpAddr,
                                           igmpRouter->groupListHeadPointer);
            if (grpPtr)
            {
                currentSubscription->grpAddr = grpAddr;
                if (igmp->igmpInterfaceInfo[i]->igmpVersion == IGMP_V2)
                {
                    // Ignore IGMP_V2 subscriptions if SSM is enabled for
                    // SSM group
                    if (ipLayer->isSSMEnable
                        && Igmpv3IsSSMAddress(node, grpAddr))
                    {
                        continue;
                    }
                    currentSubscription->filterMode = EXCLUDE;
                }
                else
                {
                    currentSubscription->filterMode = grpPtr->filterMode;
                    vector<SourceRecord>::iterator itr;
                    if (currentSubscription->filterMode == INCLUDE)
                    {
                        for (itr = grpPtr->rtrForwardListVector.begin();
                             itr < grpPtr->rtrForwardListVector.end();
                             ++itr)
                        {
                            currentSubscription->srcList.push_back(
                                                          (*itr).sourceAddr);
                        }
                    }
                    else
                    {
                        for (itr = grpPtr->rtrDoNotForwardListVector.begin();
                             itr < grpPtr->rtrDoNotForwardListVector.end();
                             ++itr)
                        {
                            currentSubscription->srcList.push_back(
                                                          (*itr).sourceAddr);
                        }
                    }
                }
                if (mergedSubscription == NULL)
                {
                    mergedSubscription =
                           (IgmpProxyData*)MEM_malloc(sizeof(IgmpProxyData));
                    memset(mergedSubscription, 0, sizeof(IgmpProxyData));
                    mergedSubscription->grpAddr = grpAddr;
                    mergedSubscription->filterMode =
                                             currentSubscription->filterMode;
                    mergedSubscription->srcList.assign(
                                        currentSubscription->srcList.begin(),
                                        currentSubscription->srcList.end());
                }
                else
                {
                    tempSubscription = IgmpProxyMergeDownStreamSubscriptions(
                                                         mergedSubscription,
                                                         currentSubscription,
                                                         &modified);
                    if (modified)
                    {
                        // Remove old data and insert mergedsubscription
                        mergedSubscription->filterMode =
                                              tempSubscription->filterMode;
                        mergedSubscription->srcList.assign(
                                           tempSubscription->srcList.begin(),
                                           tempSubscription->srcList.end());
                    }
                    if (tempSubscription->srcList.size() != 0)
                    {
                        tempSubscription->srcList.clear();
                    }
                    MEM_free(tempSubscription);
                }
            }
        }
        currentSubscription->srcList.clear();
    }

    while (proxyDataListItem)
    {
        subscription = (IgmpProxyData*)proxyDataListItem->data;
        modified = FALSE;
        if (grpAddr == subscription->grpAddr)
        {
            found = TRUE;
            if (!mergedSubscription)
            {
                // if mergesubscription is NULL there is no downstreame
                // subscription , so this will be equivalent to INCLUDE NULL
                mergedSubscription =
                           (IgmpProxyData*)MEM_malloc(sizeof(IgmpProxyData));
                memset(mergedSubscription, 0, sizeof(IgmpProxyData));
                mergedSubscription->filterMode = INCLUDE;
            }
            if (mergedSubscription->filterMode == INCLUDE)
            {
                strcpy(flterMode, "INCLUDE");
            }
            else
            {
                strcpy(flterMode, "EXCLUDE");
            }
            sort(mergedSubscription->srcList.begin(),
                 mergedSubscription->srcList.end());

            if (mergedSubscription->filterMode != subscription->filterMode
                || mergedSubscription->srcList.size()
                                             != subscription->srcList.size())
            {
                modified = TRUE;
            }
            else
            {
                if (!equal(mergedSubscription->srcList.begin(),
                          mergedSubscription->srcList.end(),
                          subscription->srcList.begin()))
                {
                    modified = TRUE;
                }
            }
            if (modified)
            {
                // Remove old data and insert mergedsubscription
                subscription->filterMode = mergedSubscription->filterMode;
                subscription->srcList.assign(
                                         mergedSubscription->srcList.begin(),
                                         mergedSubscription->srcList.end());
                // send join on upstreamIntfId
                IgmpJoinGroup(node,
                              upstreamIntfId,
                              grpAddr,
                              (clocktype)0,
                              flterMode,
                              &mergedSubscription->srcList);
                if (subscription->filterMode == INCLUDE
                    && subscription->srcList.size() == 0)
                {
                    // remove entry from proxy data list
                    ListGet(node,
                            igmp->igmpProxyDataList,
                            proxyDataListItem,
                            TRUE,
                            FALSE);
                }
            }
            break;
        }
        proxyDataListItem = proxyDataListItem->next;
    }
    if (!(found || mergedSubscription == NULL))
    {
        ListInsert(node,
                   igmp->igmpProxyDataList,
                   node->getNodeTime(),
                   (void*)mergedSubscription);
        if (mergedSubscription->filterMode == INCLUDE)
        {
            strcpy(flterMode, "INCLUDE");
        }
        else
        {
            strcpy(flterMode, "EXCLUDE");
        }
        IgmpJoinGroup(node,
                      upstreamIntfId,
                      grpAddr,
                      (clocktype)0,
                      flterMode,
                      &mergedSubscription->srcList);
    }
}
//---------------------------------------------------------------------------
// FUNCTION     : IgmpProxyMergeDownStreamSubscriptions()
// PURPOSE      : Merge subscriptions coming from down stream interfaces
//                based on merger rules section 3.2 RFC3376
// PARAMETERS   : proxyData - Subscription in the list.
//                currentSubscription - Current subscription coming from down
//                                      - downstream interface
//                modified - Bool variable to show whether subscription in
//                           thr list is modified or not after merging
// RETURN VALUE : IgmpProxyData*
// ASSUMPTION   : None
//---------------------------------------------------------------------------
IgmpProxyData* IgmpProxyMergeDownStreamSubscriptions(IgmpProxyData* proxyData,
                                          IgmpProxyData* currentSubscription,
                                          bool* modified)
{
    IgmpProxyData* mergedSubscription = NULL;
    mergedSubscription = (IgmpProxyData*)MEM_malloc(sizeof(IgmpProxyData));
    memset(mergedSubscription, 0, sizeof(IgmpProxyData));
    sort(proxyData->srcList.begin(), proxyData->srcList.end());
    sort(currentSubscription->srcList.begin(),
         currentSubscription->srcList.end());
    if (proxyData->filterMode == EXCLUDE
        || currentSubscription->filterMode == EXCLUDE)
    {
         mergedSubscription->filterMode = EXCLUDE;
         if (proxyData->filterMode == EXCLUDE)
         {
             if (currentSubscription->filterMode == INCLUDE)
             {
                 set_difference(proxyData->srcList.begin(),
                                proxyData->srcList.end(),
                                currentSubscription->srcList.begin(),
                                currentSubscription->srcList.end(),
                                back_inserter(mergedSubscription->srcList));
             }
             else
             {
                 set_intersection(proxyData->srcList.begin(),
                                  proxyData->srcList.end(),
                                  currentSubscription->srcList.begin(),
                                  currentSubscription->srcList.end(),
                                  back_inserter(mergedSubscription->srcList));
             }
         }
         else
         {
             set_difference(currentSubscription->srcList.begin(),
                            currentSubscription->srcList.end(),
                            proxyData->srcList.begin(),
                            proxyData->srcList.end(),
                            back_inserter(mergedSubscription->srcList));
         }
    }
    else
    {
         mergedSubscription->filterMode = INCLUDE;
         set_union(proxyData->srcList.begin(),
                   proxyData->srcList.end(),
                   currentSubscription->srcList.begin(),
                   currentSubscription->srcList.end(),
                   back_inserter(mergedSubscription->srcList));
    }
    sort(mergedSubscription->srcList.begin(),
         mergedSubscription->srcList.end());

    if (mergedSubscription->filterMode != proxyData->filterMode
        || mergedSubscription->srcList.size() != proxyData->srcList.size())
    {
        *modified = TRUE;
    }
    else
    {
        if (!equal(mergedSubscription->srcList.begin(),
                  mergedSubscription->srcList.end(),
                  proxyData->srcList.begin()))
        {
            *modified = TRUE;
        }
    }
    return mergedSubscription;
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndIsIncludeAndAllow()
// PURPOSE      : Router processing a received report when previous router
//                state was Include and received report record-type is
//                MODE_IS_INCLUDE or ALLOW_NEW_SRC.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportIncludeAndIsIncludeAndAllow(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    vector<NodeAddress> tmpVector1;
    // A+B
    set_union(forwardList.begin(), forwardList.end(),
              sourceList.begin(), sourceList.end(),
              back_inserter(tmpVector1));
    // Update forward list A+B
    Igmpv3UpdateForwardListVector(ptr, tmpVector1);

    // Set the timer to group membership interval for the newly
    // received sources (B)
    Igmpv3SetSourceTimer(node,
                         ptr,
                         &ptr->rtrForwardListVector,
                         groupMembershipInterval,
                         intfId,
                         sourceList);

}
//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndIsExclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Include and received report record-type is
//                MODE_IS_EXCLUDE.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportIncludeAndIsExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3;
    clocktype sourceTimerValue, grpTimerValue;

    // A-B
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector1));
    // A*B
    set_intersection(
        forwardList.begin(), forwardList.end(),
        sourceList.begin(), sourceList.end(),
        back_inserter(tmpVector2));
    // B-A
    set_difference(
        sourceList.begin(), sourceList.end(),
        forwardList.begin(), forwardList.end(),
        back_inserter(tmpVector3));

    // Delete A-B
    Igmpv3DeleteSrcForwardListVector(ptr, tmpVector1);
    // Update forward list (A*B)
    Igmpv3UpdateForwardListVector(ptr,tmpVector2);
    // Update Do not forward list (B-A)
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector3);

    if (!tmpVector3.empty())
    {
        // Set the source timer of (B-A) sources to 0.
        sourceTimerValue = 0;
        Igmpv3SetSourceTimer(node,
                             ptr,
                             &ptr->rtrDoNotForwardListVector,
                             sourceTimerValue,
                             intfId,
                             tmpVector3);
    }
    // Set group timer
    grpTimerValue = groupMembershipInterval;
    Igmpv3SetRouterGroupTimer(node, ptr, grpTimerValue, intfId);

    // Router filter mode change.
    ptr->filterMode = EXCLUDE;

    if (ptr->rtrDoNotForwardListVector.empty()
        && ptr->rtrForwardListVector.empty())
    {
        // Instance when host interface requests traffic from all
        // sources
        MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
        if (notifyMcastRtProto)
        {
            (notifyMcastRtProto)(node,
                                 ptr->groupId,
                                 intfId,
                                 LOCAL_MEMBER_JOIN_GROUP);
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndBlock()
// PURPOSE      : Router processing a received report when previous router
//                state was Include and received report record-type is
//                BLOCK_OLD_SRC.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportIncludeAndBlock(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    vector<NodeAddress> tmpVector1;
    clocktype sourceTimerValue;

    // A*B
    set_intersection(forwardList.begin(), forwardList.end(),
                     sourceList.begin(), sourceList.end(),
                     back_inserter(tmpVector1));

    if (!tmpVector1.empty())
    {
        // Lower the source timers before sending group and source
        // specific query
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Timers of A*B sources to be lowered.
        Igmpv3RouterLowerSourceTimer(node,
                                     ptr,
                                     &ptr->rtrForwardListVector,
                                     sourceTimerValue,
                                     intfId,
                                     tmpVector1);
        // Send source-specific query
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector1);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndToExclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Include and received report record-type is
//                CHANGE_TO_EX.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportIncludeAndToExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3;
    clocktype sourceTimerValue, grpTimerValue;

    // A-B
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector1));
    // A*B
    set_intersection(forwardList.begin(), forwardList.end(),
                     sourceList.begin(), sourceList.end(),
                     back_inserter(tmpVector2));
    // B-A
    set_difference(sourceList.begin(), sourceList.end(),
                   forwardList.begin(), forwardList.end(),
                   back_inserter(tmpVector3));

    // Delete (A-B)
    Igmpv3DeleteSrcForwardListVector(ptr, tmpVector1);
    // Update forward list (A*B)
    Igmpv3UpdateForwardListVector(ptr, tmpVector2);
    // Update do not forward list (B-A)
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector3);

    if (!tmpVector3.empty())
    {
        // Set the source timer of difference vector to zero for (B-A)
        sourceTimerValue = 0;
        Igmpv3SetSourceTimer(node,
                             ptr,
                             &ptr->rtrDoNotForwardListVector,
                             sourceTimerValue,
                             intfId,
                             tmpVector3);
    }
    if (!tmpVector2.empty())
    {
        // Lower the source timers before sending group and source
        // specific query
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Lower source timer for A*B
        Igmpv3RouterLowerSourceTimer(node,
                                    ptr,
                                    &ptr->rtrForwardListVector,
                                    sourceTimerValue,
                                    intfId,
                                    tmpVector2);
        // Send source-specific query for (A*B)
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector2);
    }
    // Set group timer
    grpTimerValue = groupMembershipInterval;
    Igmpv3SetRouterGroupTimer(node, ptr, grpTimerValue, intfId);

    // Router filter mode change.
    ptr->filterMode = EXCLUDE;

    if (ptr->rtrDoNotForwardListVector.empty()
        && ptr->rtrForwardListVector.empty())
    {
        // Instance when host interface requests traffic from all
        // sources
        MulticastProtocolType notifyMcastRtProto =
                                  IgmpGetMulticastProtocolInfo(node, intfId);
        if (notifyMcastRtProto)
        {
            (notifyMcastRtProto)(node,
                                 ptr->groupId,
                                 intfId,
                                 LOCAL_MEMBER_JOIN_GROUP);
        }
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndToInclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Include and received report record-type is
//                CHANGE_TO_IN.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportIncludeAndToInclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    vector<NodeAddress> tmpVector1, tmpVector2;
    clocktype sourceTimerValue;

    // A+B
    set_union(forwardList.begin(), forwardList.end(),
              sourceList.begin(), sourceList.end(),
              back_inserter(tmpVector1));
    // Update forward list (A+B)
    Igmpv3UpdateForwardListVector(ptr, tmpVector1);

    // Set source timer of the new sources(B) to group membership interval
    sourceTimerValue = groupMembershipInterval;
    Igmpv3SetSourceTimer(node,
                         ptr,
                         &ptr->rtrForwardListVector,
                         sourceTimerValue,
                         intfId,
                         sourceList);

    // A-B
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector2));
    if (!tmpVector2.empty())
    {
        // Lower the source timers before sending group and source
        // specific query.
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Lower source timer of (A-B) sources.
        Igmpv3RouterLowerSourceTimer(node,
                                     ptr,
                                     &ptr->rtrForwardListVector,
                                     sourceTimerValue,
                                     intfId,
                                     tmpVector2);
        // Send source-specific query for (A-B)
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector2);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportIncludeAndToInclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Exclude and received report record-type is
//                MODE_IS_INCLUDE or ALLOW_NEW_SRC.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportExcludeAndIsIncludeAndAllow(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    vector<NodeAddress> tmpVector1, tmpVector2;
    clocktype sourceTimerValue;

    // X+A
    set_union(forwardList.begin(), forwardList.end(),
              sourceList.begin(), sourceList.end(),
              back_inserter(tmpVector1));
    // Update forward list (X+A).
    Igmpv3UpdateForwardListVector(ptr, tmpVector1);

    // Set source timer for newly received sources (A).
    sourceTimerValue = groupMembershipInterval;
    Igmpv3SetSourceTimer(node,
                         ptr,
                         &ptr->rtrForwardListVector,
                         sourceTimerValue,
                         intfId,
                         sourceList);

    // Y-A
    set_difference(doNotForwardList.begin(),doNotForwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector2));
    // Update do not forward list (Y-A).
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector2);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportExcludeAndIsExclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Exclude and received report record-type is
//                MODE_IS_EXCLUDE.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportExcludeAndIsExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3, tmpVector4,
        tmpVector5, tmpVector6;
    clocktype sourceTimerValue, grpTimerValue;

    // Y-A
    set_difference(doNotForwardList.begin(), doNotForwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector1));
    // X-A
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector2));
    // A-Y
    set_difference(sourceList.begin(), sourceList.end(),
                   doNotForwardList.begin(),doNotForwardList.end(),
                   back_inserter(tmpVector3));
    // Y*A
    set_intersection(doNotForwardList.begin(),doNotForwardList.end(),
                     sourceList.begin(), sourceList.end(),
                     back_inserter(tmpVector4));


    // Delete (X-A) sources
    Igmpv3DeleteSrcForwardListVector(ptr, tmpVector2);
    // Delete (Y-A) sources
    Igmpv3DeleteSrcDoNotForwardListVector(ptr, tmpVector1);
    // Update forward list (A-Y)
    Igmpv3UpdateForwardListVector(ptr, tmpVector3);
    // Update do not forward list (Y*A)
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector4);

    // A-X
    set_difference(sourceList.begin(), sourceList.end(),
                   forwardList.begin(),forwardList.end(),
                   back_inserter(tmpVector5));
    // A-X-Y
    set_difference(tmpVector5.begin(), tmpVector5.end(),
                   doNotForwardList.begin(), doNotForwardList.end(),
                   back_inserter(tmpVector6));
    if (!tmpVector6.empty())
    {
        // Set source timer of (A-X-Y)for the source membership.
        sourceTimerValue = groupMembershipInterval;
        Igmpv3SetSourceTimer(node,
                             ptr,
                             &ptr->rtrForwardListVector,
                             sourceTimerValue,
                             intfId,
                             tmpVector6);
    }
    // Set group timer
    grpTimerValue = groupMembershipInterval;
    Igmpv3SetRouterGroupTimer(node, ptr, grpTimerValue, intfId);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportExcludeAndBlock()
// PURPOSE      : Router processing a received report when previous router
//                state was Exclude and received report record-type is
//                BLOCK_OLD_SRC.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportExcludeAndBlock(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3, tmpVector4;
    clocktype sourceTimerValue;

    // A-Y
    set_difference(sourceList.begin(), sourceList.end(),
                   doNotForwardList.begin(), doNotForwardList.end(),
                   back_inserter(tmpVector1));
    // (X+(A-Y))
    set_union(forwardList.begin(), forwardList.end(),
              tmpVector1.begin(), tmpVector1.end(),
              back_inserter(tmpVector2));
    // Update forward list (X+(A-Y))
    Igmpv3UpdateForwardListVector(ptr, tmpVector2);

    // A-X
    set_difference(sourceList.begin(), sourceList.end(),
                   forwardList.begin(), forwardList.end(),
                   back_inserter(tmpVector3));
    // A-X-Y
    set_difference(tmpVector3.begin(), tmpVector3.end(),
                   doNotForwardList.begin(), doNotForwardList.end(),
                   back_inserter(tmpVector4));
    if (!tmpVector4.empty())
    {
        // Set source timer of (A-X-Y) sources for the source membership.
        sourceTimerValue = ptr->lastGroupTimerValue;
        Igmpv3SetSourceTimer(node,
                             ptr,
                             &ptr->rtrForwardListVector,
                             sourceTimerValue,
                             intfId,
                             tmpVector4);
    }

    if (!tmpVector1.empty())
    {
        // Lower the source timers before sending group and source specific query
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Lower source timer of (A-Y) sources
        Igmpv3RouterLowerSourceTimer(node,
                                     ptr,
                                     &ptr->rtrForwardListVector,
                                     sourceTimerValue,
                                     intfId,
                                     tmpVector1);
        // Send source-specific query
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector1);
    }
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportExcludeAndToExclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Exclude and received report record-type is
//                CHANGE_TO_EX.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportExcludeAndToExclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3, tmpVector4,
        tmpVector5, tmpVector6;
    clocktype sourceTimerValue, grpTimerValue;

    // Y-A
    set_difference(doNotForwardList.begin(), doNotForwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector1));
    // X-A
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector2));
    // A-Y
    set_difference(sourceList.begin(), sourceList.end(),
                   doNotForwardList.begin(), doNotForwardList.end(),
                   back_inserter(tmpVector3));
    // Y*A
    set_intersection(doNotForwardList.begin(), doNotForwardList.end(),
                     sourceList.begin(), sourceList.end(),
                     back_inserter(tmpVector4));

    // Delete X-A sources
    Igmpv3DeleteSrcForwardListVector(ptr, tmpVector2);
    // Delete Y-A sources
    Igmpv3DeleteSrcDoNotForwardListVector(ptr, tmpVector1);
    // Update forward list A-Y
    Igmpv3UpdateForwardListVector(ptr, tmpVector3);
    // Update do not forward list Y*A
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector4);

    // A-X
    set_difference(sourceList.begin(), sourceList.end(),
                   forwardList.begin(), forwardList.end(),
                   back_inserter(tmpVector5));
    // A-X-Y
    set_difference(tmpVector5.begin(), tmpVector5.end(),
                   doNotForwardList.begin(), doNotForwardList.end(),
                   back_inserter(tmpVector6));
    if (!tmpVector6.empty())
    {
        // Set source timer of A-X-Y sources for the source membership
        sourceTimerValue = ptr->lastGroupTimerValue;
        Igmpv3SetSourceTimer(node,
                             ptr,
                             &ptr->rtrForwardListVector,
                             sourceTimerValue,
                             intfId,
                             tmpVector6);
    }
    if (!tmpVector3.empty())
    {
        // Lower the source timers before sending group and source specific query
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Lower source timers of A-Y sources
        Igmpv3RouterLowerSourceTimer(node,
                                     ptr,
                                     &ptr->rtrDoNotForwardListVector,
                                     sourceTimerValue,
                                     intfId,
                                     tmpVector3);
        // Send source-specific query
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector3);
    }
    // Set group timer
    grpTimerValue = groupMembershipInterval;
    Igmpv3SetRouterGroupTimer(node, ptr, grpTimerValue, intfId);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3HandleReportExcludeAndToInclude()
// PURPOSE      : Router processing a received report when previous router
//                state was Exclude and received report record-type is
//                CHANGE_TO_IN.
// PARAMETERS   : node - this node.
//                intfId - interface index.
//                ptr - pointer to IgmpGroupInfoForRouter.
//                forwardList - vector containing forward list sources.
//                doNotForwardList - vector containing do not forward list
//                sources.
//                sourceList - vector of sources extracted from IGMPv3 report
//                groupMembershipInterval - group membership initerval value
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3HandleReportExcludeAndToInclude(
                             Node* node,
                             Int32 intfId,
                             IgmpGroupInfoForRouter* ptr,
                             vector<NodeAddress> forwardList,
                             vector<NodeAddress> doNotForwardList,
                             vector<NodeAddress> sourceList,
                             clocktype groupMembershipInterval)
{
    IgmpData* igmpData = IgmpGetDataPtr(node);
    ERROR_Assert(igmpData, " IGMP interface not found");
    IgmpRouter* igmpRouter = NULL;
    igmpRouter = igmpData->igmpInterfaceInfo[intfId]->igmpRouter;
    Int32 retransmitCount = 0;
    vector<NodeAddress> tmpVector1, tmpVector2, tmpVector3, tmpVector4;
    clocktype sourceTimerValue, grpTimerValue;

    // X+A
    set_union(forwardList.begin(), forwardList.end(),
              sourceList.begin(), sourceList.end(),
              back_inserter(tmpVector1));
    // Update forward list (X+A)
    Igmpv3UpdateForwardListVector(ptr, tmpVector1);

    // Set source timer of (A) sources for the source membership.
    sourceTimerValue = groupMembershipInterval;
    Igmpv3SetSourceTimer(node,
                         ptr,
                         &ptr->rtrForwardListVector,
                         sourceTimerValue,
                         intfId,
                         sourceList);

    // Y-A
    set_difference(doNotForwardList.begin(), doNotForwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector2));
    // Update do not forward list (Y-A)
    Igmpv3UpdateDoNotForwardListVector(ptr, tmpVector2);

    // X-A
    set_difference(forwardList.begin(), forwardList.end(),
                   sourceList.begin(), sourceList.end(),
                   back_inserter(tmpVector3));
    if (!tmpVector3.empty())
    {
        // Lower the source timers before sending group and source specific query
        sourceTimerValue = (((ptr->lastMemberQueryInterval / 10)
                            * SECOND) * ptr->lastMemberQueryCount);
        // Lower the source timer of (X-A) sources
        Igmpv3RouterLowerSourceTimer(node,
                                     ptr,
                                     &ptr->rtrForwardListVector,
                                     sourceTimerValue,
                                     intfId,
                                     tmpVector3);
        // Send group-and-source-specific query
        Igmpv3SendGrpAndSrcSpecificQuery(node,
                                         ptr->groupId,
                                         intfId,
                                         igmpRouter->queryInterval,
                                         tmpVector3);
    }
    grpTimerValue = (((ptr->lastMemberQueryInterval / 10) * SECOND)
                     * ptr->lastMemberQueryCount);
    // lower group timer
    Igmpv3RouterLowerGrpTimer(node,
                              ptr,
                              grpTimerValue,
                              intfId);
    retransmitCount = ptr->lastMemberQueryCount;
    // Send group-specific query
    Igmpv3SendGrpSpecificQuery(node,
                               ptr->groupId,
                               intfId,
                               igmpRouter->queryInterval,
                               retransmitCount);
}

//---------------------------------------------------------------------------
// FUNCTION     : Igmpv3RouterHandleReport()
// PURPOSE      : Router processing a received IGMPv3 report.
// PARAMETERS   : node - this node.
//                igmpv3ReportPkt - pointer to Igmpv3ReportMessage.
//                igmpRouter - pointer to IgmpRouter.
//                intfId - report received at this interface index.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void Igmpv3RouterHandleReport(
    Node* node,
    Igmpv3ReportMessage* igmpv3ReportPkt,
    IgmpRouter* igmpRouter,
    Int32 intfId,
    Int32 robustnessVariable)
{
    IgmpInterfaceInfoType *thisInterface = NULL;
    IgmpGroupInfoForRouter* grpPtr = NULL;
    NodeAddress grpAddr;
    NodeAddress intfAddr;
    clocktype groupMembershipInterval = 0;
    struct GroupRecord* Igmpv3GrpRecord = NULL;
    UInt32 numSrc = 0;
    vector<NodeAddress> sourceVector;
    vector<NodeAddress> rtrForwardList;
    vector<NodeAddress> rtrDoNotForwardList;
    vector<SourceRecord> :: iterator itf;
    vector<SourceRecord> :: iterator itd;

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    thisInterface = igmp->igmpInterfaceInfo[intfId];
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    // get pim-sm data pointer if any
    PimData* pim = (PimData*)NetworkIpGetMulticastRoutingProtocol(node,
                                                     MULTICAST_PROTOCOL_PIM);
    PimDataSm* pimDataSm = NULL;
    if (pim)
    {
        if (pim->modeType == ROUTING_PIM_MODE_SPARSE_DENSE)
        {
            pimDataSm = ((PimDataSmDm*) pim->pimModePtr)->pimSm;
        }
        else if (pim->modeType == ROUTING_PIM_MODE_SPARSE)
        {
            pimDataSm = (PimDataSm*) pim->pimModePtr;
        }
    }

    intfAddr = NetworkIpGetInterfaceAddress(node, intfId);
     // Loop for every group record present in the report.
    for (int i = 0; i < igmpv3ReportPkt->numGrpRecords; i++)
    {
        grpAddr = igmpv3ReportPkt->groupRecord[i].groupAddress;
        Igmpv3GrpRecord = &igmpv3ReportPkt->groupRecord[i];
        // Search for the specified group.
        grpPtr = IgmpCheckRtrGroupList(
                    node, grpAddr, igmpRouter->groupListHeadPointer);

        if (!grpPtr)
        {
             // No entry found for this group, so add it to list.
            grpPtr = IgmpInsertRtrGroupList(node,
                                            grpAddr,
                                            intfId,
                                            robustnessVariable);
        }
        if (igmpv3ReportPkt->ver_type == IGMP_MEMBERSHIP_REPORT_MSG
            || igmpv3ReportPkt->ver_type == IGMP_LEAVE_GROUP_MSG)
        {
            // The Group Compatibility Mode of a group record changes
            // whenever an older version report (than the current
            // compatibility mode) is heard.
            grpPtr->rtrCompatibilityMode = IGMP_V2;
            Igmpv3SetOlderHostPresentTimer(node, grpAddr, intfId);
        }
        if (grpPtr->rtrCompatibilityMode == IGMP_V2)
        {
            // When Group Compatibility Mode is IGMPv2, IGMPv3 BLOCK messages
            // are ignored, as are source-lists in TO_EX() messages.
            if (Igmpv3GrpRecord->record_type == BLOCK_OLD_SRC)
            {
                continue;
            }
            if (Igmpv3GrpRecord->record_type == CHANGE_TO_EX)
            {
                Igmpv3GrpRecord->sourceAddress.clear();
            }
        }
        // The default value for Query Response interval is 100 which on
        // converting into units comes out to be 10 seconds. In QualNet at
        // initialization it is stored as 100 or converting the value
        // configured by user (in seconds) to the normal value i.e. dividing
        // by seconds and multiplying by 10.Hence,it is required to divide
        // the current value in queryResponseInterval by 10 and multiply
        //  by SECOND.
        groupMembershipInterval = (clocktype)
            ((robustnessVariable * igmpRouter->queryInterval)
             + (igmpRouter->queryResponseInterval * SECOND)
             /IGMP_QUERY_RESPONSE_SCALE_FACTOR);

        for (itf = grpPtr->rtrForwardListVector.begin();
            itf != grpPtr->rtrForwardListVector.end();
            ++itf)
        {
            rtrForwardList.push_back((*itf).sourceAddr);
        }
        for (itd = grpPtr->rtrDoNotForwardListVector.begin();
            itd != grpPtr->rtrDoNotForwardListVector.end();
            ++itd)
        {
            rtrDoNotForwardList.push_back((*itd).sourceAddr);
        }

        sort(rtrForwardList.begin(), rtrForwardList.end());
        sort(rtrDoNotForwardList.begin(), rtrDoNotForwardList.end());

        numSrc = Igmpv3GrpRecord->numSources;
        sourceVector = Igmpv3GrpRecord->sourceAddress;
        sort(sourceVector.begin(), sourceVector.end());
        // SSM Behavior implementation
        if (ip->isSSMEnable
             && Igmpv3IsSSMAddress(node, grpPtr->groupId))
        {
            if (pimDataSm
                || igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
            {
                if (Igmpv3GrpRecord->record_type == MODE_IS_EXCLUDE
                    || Igmpv3GrpRecord->record_type == CHANGE_TO_EX
                    || numSrc == 0)
                {
                    continue;
                }
            }
        }

        (*Igmpv3ReportHandler
            [grpPtr->filterMode][Igmpv3GrpRecord->record_type])
                            (node,
                             intfId,
                             grpPtr,
                             rtrForwardList,
                             rtrDoNotForwardList,
                             sourceVector,
                             groupMembershipInterval);

        // Clear forward and do not forward list for next group record
        rtrForwardList.clear();
        rtrDoNotForwardList.clear();
        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
        {
                IgmpProxyHandleSubscription(node,
                                            grpAddr);
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpRouterHandleLeave()
// PURPOSE      : Router processing a leave group message.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpRouterHandleLeave(
    Node* node,
    IgmpMessage* igmpv2Pkt,
    IgmpRouter* igmpRouter,
    int srcAddr,
    Int32 intfId)
{
    IgmpInterfaceInfoType *thisInterface;
    IgmpGroupInfoForRouter* grpPtr;
    NodeAddress grpAddr;
    NodeAddress intfAddr;

    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    thisInterface = igmp->igmpInterfaceInfo[intfId];
    intfAddr = NetworkIpGetInterfaceAddress(node, intfId);

    grpAddr = igmpv2Pkt->groupAddress;

    if (DEBUG) {
        printf("    Router processing of IGMP_LEAVE_MSG\n");
    }

    if (igmpRouter->routersState == IGMP_QUERIER)
    {
        // Search for the specified group.
        grpPtr = IgmpCheckRtrGroupList(
                        node, grpAddr, igmpRouter->groupListHeadPointer);

        if (grpPtr)
        {
            clocktype delayTime;
            IgmpStateType originalState = grpPtr->membershipState;

            grpPtr->membershipState = IGMP_ROUTER_CHECKING_MEMBERSHIP;
            grpPtr->groupMembershipInterval =
                grpPtr->lastMemberQueryCount *
                (grpPtr->lastMemberQueryInterval / 10) * SECOND;
            delayTime = 0;

            if (DEBUG) {
                char grpStr[20];
                char intfStr[20];

                IO_ConvertIpAddressToString(grpAddr, grpStr);
                IO_ConvertIpAddressToString(intfAddr, intfStr);
                printf("    Receive leave report for group %s on "
                    "interface %s\n",
                    grpStr, intfStr);
            }

            // Send Group Specific Query message
            IgmpSendQuery(node,
                          grpAddr,
                          intfId,
                          igmpRouter->queryResponseInterval,
                          igmpRouter->lastMemberQueryInterval,
                          igmpRouter->queryInterval);

            // Set timer for the membership
            //IgmpSetGroupMembershipTimer(node, grpPtr, intfId);

            if (originalState != IGMP_ROUTER_CHECKING_MEMBERSHIP)
            {
                // Set last membership timer
                IgmpSetLastMembershipTimer(node,
                                           grpAddr,
                                           intfId,
                                           0,
                                           igmpRouter->lastMemberQueryInterval);
            }
//#ifdef ADDON_DB
        //HandleMulticastDBStatus(node, intfId, "Leave", srcAddr, grpAddr);
//#endif
        }
        else
        {
            IgmpData* igmp = IgmpGetDataPtr(node);

            ERROR_Assert(igmp, " IGMP interface not found");
            igmp->igmpInterfaceInfo[intfId]->
                igmpStat.igmpBadReportReceived += 1;
            igmp->igmpInterfaceInfo[intfId]->
                igmpStat.igmpBadMsgReceived += 1;
        }
    }
    else
    {
        if (DEBUG) {
            printf("    Ignore packet as it is Leave Report\n");
        }
    }

#ifdef ADDON_DB
    HandleStatsDBIgmpSummary(node, "Leave", srcAddr, grpAddr);
#endif


#ifdef CYBER_CORE
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->iahepEnabled && ip->iahepData->nodeType == IAHEP_NODE)
    {
        NodeAddress mappedGrpAddr = IAHEPGetMulticastBroadcastAddressMapping(
                                        node, ip->iahepData, grpAddr);

        IAHEPCreateIgmpJoinLeaveMessage(
            node,
            mappedGrpAddr,
            IGMP_LEAVE_GROUP_MSG,
            NULL);

        ip->iahepData->grpAddressList->erase(grpAddr);

        //Update Stats
        ip->iahepData->updateAmdTable->getAMDTable(0)->
            iahepStats.iahepIGMPLeavesSent ++;
        ip->iahepData->updateAmdTable->getAMDTable(0)->
            iahepStats.iahepIGMPLevingGrp = mappedGrpAddr;

        if (IAHEP_DEBUG)
        {
            char addrStr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(mappedGrpAddr, addrStr);
            printf("\nIAHEP Node: %d", node->nodeId);
            printf("\tLeaves Group: %s\n", addrStr);
        }
    }
#endif //CYBER_CORE
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandlePacketForRouter()
// PURPOSE      : Router processing a incoming IGMP packet.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandlePacketForRouter(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpMessage* igmpv2Pkt = NULL;
    IgmpQueryMessage igmpv3QueryPkt;
    Igmpv3ReportMessage igmpv3ReportPkt;
    IgmpData* igmp;
    IgmpRouter* igmpRouter = NULL;
    IgmpInterfaceInfoType* thisInterface;
    UInt16 numSrc;
    Int32 pktSize;
    UInt8* ver_type;
    NodeAddress groupAddr;

    ver_type = (UInt8*) MESSAGE_ReturnPacket(msg);

    igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    thisInterface = igmp->igmpInterfaceInfo[intfId];
    igmpRouter = thisInterface->igmpRouter;
    pktSize = MESSAGE_ReturnPacketSize(msg);

    switch (*ver_type)
    {
        case IGMP_QUERY_MSG:
        {
            // Router receives a query message from another router
            thisInterface->igmpStat.igmpTotalQueryReceived += 1;

            if (thisInterface->igmpVersion == IGMP_V3)
            {
                if (pktSize == IGMPV2_QUERY_FIXED_SIZE)
                {
                    igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);
                    groupAddr = igmpv2Pkt->groupAddress;
                    IgmpRouterHandleQuery(
                                    node,
                                    igmpv2Pkt,
                                    igmpRouter,
                                    srcAddr,
                                    intfId,
                                    thisInterface->robustnessVariable);
                    if (groupAddr == 0)
                    {
                        thisInterface->igmpStat.igmpGenQueryReceived += 1;
                    }
                    else
                    {
                        thisInterface->
                            igmpStat.igmpGrpSpecificQueryReceived += 1;
                    }
                }
                else if (pktSize >= IGMPV3_QUERY_FIXED_SIZE)
                {
                    Igmpv3CreateDataFromQueryPkt(msg, &igmpv3QueryPkt);
                    numSrc = igmpv3QueryPkt.numSources;
                    groupAddr = igmpv3QueryPkt.groupAddress;

                    Igmpv3RouterHandleQuery(node,
                                            &igmpv3QueryPkt,
                                            igmpRouter,
                                            srcAddr,
                                            intfId);
                    if (numSrc > 0)
                    {
                        thisInterface->
                            igmpStat.igmpGrpAndSourceSpecificQueryReceived += 1;
                    }
                    else
                    {
                        if (groupAddr == 0)
                        {
                            thisInterface->igmpStat.igmpGenQueryReceived += 1;
                        }
                        else
                        {
                            thisInterface->
                                igmpStat.igmpGrpSpecificQueryReceived += 1;
                        }
                    }
                }
                else
                {
                    thisInterface-> igmpStat.igmpBadQueryReceived += 1;
                }
            }
            else if (thisInterface->igmpVersion == IGMP_V2)
            {
                igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);
                groupAddr = igmpv2Pkt->groupAddress;
                IgmpRouterHandleQuery(node,
                                      igmpv2Pkt,
                                      igmpRouter,
                                      srcAddr,
                                      intfId,
                                      thisInterface->robustnessVariable);
                IgmpHostHandleQuery(node,
                                    igmpv2Pkt,
                                    thisInterface,
                                    intfId);
                if (groupAddr == 0)
                {
                    thisInterface->igmpStat.igmpGenQueryReceived += 1;
                }
                else
                {
                    thisInterface->
                        igmpStat.igmpGrpSpecificQueryReceived += 1;
                }
            }
            else
            {
                thisInterface->igmpStat.igmpBadQueryReceived += 1;
            }
            break;
        }
        case IGMP_MEMBERSHIP_REPORT_MSG:
        {
            // Router receives an IGMPv2 Membership report
            igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);
            groupAddr = igmpv2Pkt->groupAddress;
            if (thisInterface->igmpVersion == IGMP_V3)
            {
                // Translate v2 report to fill v3 router data structure.
                Igmpv3CreateDataFromReportPkt(msg, &igmpv3ReportPkt);
                Igmpv3RouterHandleReport(node,
                                         &igmpv3ReportPkt,
                                         igmpRouter,
                                         intfId,
                                         thisInterface->robustnessVariable);
            }
            else
            {
#ifdef CYBER_CORE
                NodeAddress mcstSrcAddress = ANY_DEST;
                if (MESSAGE_ReturnInfo(msg, INFO_TYPE_SourceAddr))
                {
                    memcpy(&mcstSrcAddress,
                           MESSAGE_ReturnInfo(msg, INFO_TYPE_SourceAddr),
                                              sizeof(NodeAddress));
                    IgmpRouterHandleReport(node,
                                        igmpv2Pkt,
                                        igmpRouter,
                                        srcAddr,
                                        intfId,
                                        thisInterface->robustnessVariable,
                                        &mcstSrcAddress);
                }
                else
    #endif
                IgmpRouterHandleReport(node,
                                       igmpv2Pkt,
                                       igmpRouter,
                                       srcAddr,
                                       intfId,
                                       thisInterface->robustnessVariable);

                // RtrJoinStart
                IgmpHostHandleReport(node, igmpv2Pkt, thisInterface);
                // RtrJoinEnd
            }
            thisInterface->igmpStat.igmpTotalReportReceived += 1;
            thisInterface->igmpStat.igmpv2MembershipReportReceived += 1;
            break;
        }
        case IGMP_V3_MEMBERSHIP_REPORT_MSG:
        {
            if (thisInterface->igmpVersion == IGMP_V2)
            {
                if (DEBUG)
                {
                    char netStr[20];
                    IO_ConvertIpAddressToString(
                       NetworkIpGetInterfaceNetworkAddress(node, intfId),
                       netStr);
                    printf("    Node %u version 2 router received"
                         "version 3 membership report on network %s\n",
                         node->nodeId, netStr);
                }
                return;
            }
            // Router receives a version 3 Membership report
            Igmpv3CreateDataFromReportPkt(msg, &igmpv3ReportPkt);
            Igmpv3RouterHandleReport(node,
                                     &igmpv3ReportPkt,
                                     igmpRouter,
                                     intfId,
                                     thisInterface->robustnessVariable);

            thisInterface->igmpStat.igmpTotalReportReceived += 1;
            thisInterface->igmpStat.igmpv3MembershipReportReceived += 1;
            break;
        }
        case IGMP_LEAVE_GROUP_MSG:
        {
            // Router receives a Leave report
            igmpv2Pkt = (IgmpMessage*) MESSAGE_ReturnPacket(msg);

            if (thisInterface->igmpVersion == IGMP_V2)
            {
                IgmpRouterHandleLeave(
                    node, igmpv2Pkt, igmpRouter, srcAddr, intfId);
            }
            else
            {
                // Translate v2 leave report to fill v3 router data structure
                Igmpv3CreateDataFromReportPkt(msg, &igmpv3ReportPkt);
                Igmpv3RouterHandleReport(node,
                                         &igmpv3ReportPkt,
                                         igmpRouter,
                                         intfId,
                                         thisInterface->robustnessVariable);
            }
            thisInterface->igmpStat.igmpTotalReportReceived += 1;
            thisInterface->igmpStat.igmpLeaveReportReceived += 1;
            break;
        }
        default:
        {
            thisInterface->igmpStat.igmpBadMsgReceived += 1;
            break;
        }
     }//end switch//
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpPrintStat()
// PURPOSE      : Print the statistics of IGMP protocol.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpPrintStat(Node* node)
{
    int i;
    char buf[MAX_STRING_LENGTH];
    char nodeType[MAX_STRING_LENGTH];
    IgmpData* igmp;
    IgmpInterfaceInfoType* thisInterface;

    igmp = IgmpGetDataPtr(node);

    for (i = 0; i < node->numberInterfaces; i++)
    {
        NodeAddress interfaceAddress = NetworkIpGetInterfaceAddress(node, i);

        if (!igmp || !igmp->igmpInterfaceInfo[i])
        {
            continue;
        }

        thisInterface = igmp->igmpInterfaceInfo[i];

        if (thisInterface->igmpNodeType == IGMP_HOST) {
            sprintf(nodeType, "IGMP-HOST");
        }
        else if (thisInterface->igmpNodeType == IGMP_PROXY) {
            sprintf(nodeType, "IGMP-PROXY");
        }
        else {
            sprintf(nodeType, "IGMP-ROUTER");
        }

        sprintf(buf, "Membership created in local network = %d",
                      thisInterface->igmpStat.igmpTotalMembership);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Group Joins = %d",
                      thisInterface->igmpStat.igmpTotalGroupJoin);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Group Leaves = %d",
                      thisInterface->igmpStat.igmpTotalGroupLeave);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);
        sprintf(buf, "Total Messages Sent = %d",
                      thisInterface->igmpStat.igmpTotalMsgSend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Messages Received = %d",
                      thisInterface->igmpStat.igmpTotalMsgReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Bad Messages Received = %d",
                      thisInterface->igmpStat.igmpBadMsgReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Reports Received = %d",
                      thisInterface->igmpStat.igmpTotalReportReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Bad Reports Received = %d",
                      thisInterface->igmpStat.igmpBadReportReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "IGMPv2 Membership Reports Received = %d",
                      thisInterface->igmpStat.igmpv2MembershipReportReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "IGMPv3 Membership Reports Received = %d",
                      thisInterface->igmpStat.igmpv3MembershipReportReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Leave Reports Received = %d",
                      thisInterface->igmpStat.igmpLeaveReportReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Queries Received = %d",
                      thisInterface->igmpStat.igmpTotalQueryReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Bad Queries Received = %d",
                      thisInterface->igmpStat.igmpBadQueryReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "General Queries Received = %d",
                      thisInterface->igmpStat.igmpGenQueryReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Group Specific Queries Received = %d",
                      thisInterface->igmpStat.igmpGrpSpecificQueryReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Group and Source Specific Queries Received = %d",
                      thisInterface->igmpStat.igmpGrpAndSourceSpecificQueryReceived);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Reports Sent = %d",
                      thisInterface->igmpStat.igmpTotalReportSend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "IGMPv2 Membership Reports Sent = %d",
                      thisInterface->igmpStat.igmpv2MembershipReportSend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "IGMPv3 Membership Reports Sent = %d",
                      thisInterface->igmpStat.igmpv3MembershipReportSend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Leave Reports Sent = %d",
                      thisInterface->igmpStat.igmpLeaveReportSend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Total Queries Sent = %d",
                      thisInterface->igmpStat.igmpTotalQuerySend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "General Queries Sent = %d",
                      thisInterface->igmpStat.igmpGenQuerySend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Group Specific Queries Sent = %d",
                      thisInterface->igmpStat.igmpGrpSpecificQuerySend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);

        sprintf(buf, "Group and Source Specific Queries Sent = %d",
                      thisInterface->igmpStat.igmpGrpAndSourceSpecificQuerySend);
        IO_PrintStat(
            node,
            "Network",
            nodeType,
            interfaceAddress,
            -1 /* instanceId */,
            buf);
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpInit()
// PURPOSE      : To initialize IGMP protocol.
// RETURN VALUE : None
// ASSUMPTION   : All routers and hosts support IGMPv2.
//---------------------------------------------------------------------------
void IgmpInit(
    Node* node,
    const NodeInput* nodeInput,
    IgmpData** igmpLayerPtr,
    int interfaceIndex)
{
    Int32 robustnessVariable;
    char error[MAX_STRING_LENGTH];
    char buf[MAX_STRING_LENGTH];
    clocktype queryResponseInterval;
    clocktype lastMemberQueryInterval;
    BOOL retVal = FALSE;
    NetworkDataIp* ipLayer = NULL;
    IgmpData* igmp = NULL;
    IgmpInterfaceInfoType* thisInterface = NULL;
    clocktype queryInterval;
    IgmpInterfaceType igmpInterfaceType = IGMP_DEFAULT_INTERFACE;
    NodeAddress igmpUpstreamInterfaceAddr = 0;
    BOOL isNodeId = FALSE;
    int numHostBits = 0;
    clocktype  interval;
    int intVal = 0;
    UInt16 lastMemberQueryCount = 0;

#ifdef ADDON_BOEINGFCS
    if (node->macData[interfaceIndex]->macProtocol ==
        MAC_PROTOCOL_LINK_EPLRS)
    {
        return;
    }
#endif

#ifdef ADDON_BOEINGFCS
    if (node->macData[interfaceIndex]->macProtocol ==
        MAC_PROTOCOL_LINK_EPLRS)
    {
        return;
    }
#endif

    ipLayer = (NetworkDataIp*) node->networkData.networkVar;

    // Allocate internal structure if initializes for the first time
    //if (ipLayer->isIgmpEnable == FALSE)
    if (*igmpLayerPtr == NULL)
    {
        // Set IGMP flag
        ipLayer->isIgmpEnable = TRUE;

        igmp = (IgmpData*) MEM_malloc(sizeof(IgmpData));

        memset(igmp, 0, sizeof(IgmpData));
        *igmpLayerPtr = igmp;

        // Check input file for IGMP-STATISTICS flag
        IO_ReadString(node->nodeId,
                      (unsigned)ANY_INTERFACE,
                      nodeInput,
                      "IGMP-STATISTICS",
                      &retVal,
                      buf);

        if (!retVal || !strcmp (buf, "NO"))
        {
            igmp->showIgmpStat = FALSE;
        }
        else if (!strcmp (buf, "YES"))
        {
            igmp->showIgmpStat = TRUE;
        }
        else
        {
            ERROR_ReportError(
                "IGMP-STATISTICS: Unknown value in configuration file.\n");
        }
        // Set Default Version to 2 for proxy device if any
        igmp->igmpProxyVersion = IGMP_V2;
    }
    else
    {
       // ERROR_Assert(*igmpLayerPtr, "Initialization error within IGMP\n");
        igmp = *igmpLayerPtr;
    }

    // All multicast nodes join the all-systems-group
    NetworkIpAddToMulticastGroupList(node, IGMP_ALL_SYSTEMS_GROUP_ADDR);

    // Allocate interface structure for this interface
    thisInterface = (IgmpInterfaceInfoType*)
        MEM_malloc(sizeof(IgmpInterfaceInfoType));

    igmp->igmpInterfaceInfo[interfaceIndex] = thisInterface;

    memset(thisInterface, 0, sizeof(IgmpInterfaceInfoType));

    // Check input file for IGMP-VERSION number
    IO_ReadString(
        node->nodeId,
        NetworkIpGetInterfaceAddress(node,interfaceIndex),
        nodeInput,
        "IGMP-VERSION",
        &retVal,
        buf);

    if (!retVal || !strcmp (buf, "2"))
    {
        igmp->igmpInterfaceInfo[interfaceIndex]->igmpVersion = IGMP_V2;
    }
    else if (!strcmp (buf, "3"))
    {
        igmp->igmpInterfaceInfo[interfaceIndex]->igmpVersion = IGMP_V3;
    }
    else
    {
        ERROR_ReportError(
            "IGMP-VERSION: Incorrect value in configuration file.\n");
    }

    // check if this is an ad hoc wireless network
    igmp->igmpInterfaceInfo[interfaceIndex]->isAdHocMode = FALSE;
    if (MAC_IsWirelessAdHocNetwork(node, interfaceIndex))
    {
        igmp->igmpInterfaceInfo[interfaceIndex]->isAdHocMode = TRUE;
    }

    // Check input file for IGMP-PROXY flag
    IO_ReadString(node->nodeId,
                  (unsigned)ANY_INTERFACE,
                  nodeInput,
                  "IGMP-PROXY",
                  &retVal,
                  buf);

    if (retVal && !strcmp(buf,"YES"))
    {
        igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType = IGMP_PROXY;
    }
    else
    {
        // Check input file to determine if this node is a router
        retVal = IgmpIsRouter(node, nodeInput,interfaceIndex);

        if (retVal)
        {
            igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType =
                                                                 IGMP_ROUTER;
        }
        else
        {
            igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType =
                                                                   IGMP_HOST;
        }
    }

    if (DEBUG) {
        char buf[20];
        char hostType[20];

        if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType
                     == IGMP_ROUTER)
        {
            sprintf(hostType, "%s", "Router");
        }
        else
        {
            sprintf(hostType, "%s", "Host");
        }

        IO_ConvertIpAddressToString(
            NetworkIpGetInterfaceNetworkAddress(node, interfaceIndex),
            buf);
        printf("Node %u initializes as %s for subnet %s\n",
            node->nodeId, hostType, buf);
    }

    if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType == IGMP_PROXY)
    {
        IO_ReadString(
            node->nodeId,
            NetworkIpGetInterfaceAddress(node,interfaceIndex),
            nodeInput,
            "IGMP-PROXY-UPSTREAM-INTERFACE",
            &retVal,
            buf);

        if (retVal)
        {
            IO_ParseNodeIdHostOrNetworkAddress(buf,
                &igmpUpstreamInterfaceAddr, &numHostBits, &isNodeId);

            if (isNodeId)
            {
                // Error
                sprintf(buf,"IGMP-PROXY: node %d\n\t"
                    "IGMP-PROXY-UPSTREAM-INTERFACE must be interface"
                    " address", node->nodeId);
                ERROR_ReportError(buf);
            }

            igmp->igmpUpstreamInterfaceAddr = igmpUpstreamInterfaceAddr;
        }
        else
        {
           // Error
            sprintf(buf,"IGMP-PROXY: node %d\n\t"
                "IGMP-PROXY-UPSTREAM-INTERFACE must be specified.",
                node->nodeId);

            ERROR_ReportError(buf);
        }
        if (igmpUpstreamInterfaceAddr ==
            NetworkIpGetInterfaceAddress(node,interfaceIndex))
        {
            igmpInterfaceType = IGMP_UPSTREAM;
        }
        else
        {
            igmpInterfaceType = IGMP_DOWNSTREAM;
        }
        IgmpSetInterfaceType(node, igmp, interfaceIndex, igmpInterfaceType);

        // set a dummy multicast router function
        NetworkIpSetMulticastRouterFunction(
            node, &IgmpProxyRoutingFunction, interfaceIndex);
        // set Igmp proxy version : if any of its interface is IGMPv3 than
        // proxy versrion should be IGMPv3
        if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpVersion == IGMP_V3)
        {
            igmp->igmpProxyVersion = IGMP_V3;
        }
        // init Igmp Proxy database list
        if (!igmp->igmpProxyDataList)
        {
            ListInit(node,&igmp->igmpProxyDataList);
        }
    }
    else
    {
        IgmpSetInterfaceType(
            node, igmp, interfaceIndex, IGMP_DEFAULT_INTERFACE);
    }
    retVal = FALSE;
    IO_ReadInt(node->nodeId,
               NetworkIpGetInterfaceAddress(node, interfaceIndex),
               nodeInput,
               "IGMP-ROBUSTNESS-VARIABLE",
               &retVal,
               &intVal);

    if (retVal)
    {
        //Robustness variable cannot be equal to zero.
        robustnessVariable = intVal;
        if (robustnessVariable <= 0)
        {
            sprintf(error, "The Robustness Variable should be greater than zero\n");
            ERROR_ReportError(error);
        }
        igmp->igmpInterfaceInfo[interfaceIndex]->robustnessVariable =
                                                    robustnessVariable;
    }
    else
    {
        igmp->igmpInterfaceInfo[interfaceIndex]->robustnessVariable = IGMP_ROBUSTNESS_VAR;
    }


    // If this node is a router.
    if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType == IGMP_ROUTER
        || igmpInterfaceType == IGMP_DOWNSTREAM)
    {
        retVal = FALSE;
        IO_ReadTime(node->nodeId,
                    NetworkIpGetInterfaceAddress(node, interfaceIndex),
                    nodeInput,
                    "IGMP-QUERY-INTERVAL",
                    &retVal,
                    &interval);

        if (retVal)
        {
            queryInterval = interval;
            if (queryInterval <= 0)
            {
                sprintf(error, "The Query Interval should be greater than zero\n");
                ERROR_ReportError(error);
            }
            queryInterval = (queryInterval / 1000000000) * SECOND;
        }
        else
        {
            queryInterval = (clocktype)IGMP_QUERY_INTERVAL;
        }
        retVal = FALSE;
        IO_ReadTime(node->nodeId,
                    NetworkIpGetInterfaceAddress(node, interfaceIndex),
                    nodeInput,
                    "IGMP-QUERY-RESPONSE-INTERVAL",
                    &retVal,
                    &interval);

        if (retVal)
        {
            queryResponseInterval = interval;
            if (queryResponseInterval <= 0)
            {
                sprintf(error, "The Query Response Interval should be"
                    " greater than zero\n");
                ERROR_ReportError(error);
            }
            queryResponseInterval = (queryResponseInterval / SECOND) * 10;
        }
        else
        {
            queryResponseInterval = IGMP_QUERY_RESPONSE_INTERVAL;
        }

        if ((queryResponseInterval / 10) >= (queryInterval / SECOND))
        {
            sprintf(error, "The number of seconds represented by the "
            "Query Response Interval must be less than "
            "the Query Interval\n");
            ERROR_ReportError(error);
        }
        retVal = FALSE;
        IO_ReadTime(node->nodeId,
                    NetworkIpGetInterfaceAddress(node, interfaceIndex),
                    nodeInput,
                    "IGMP-LAST-MEMBER-QUERY-INTERVAL",
                    &retVal,
                    &interval);

        if (retVal)
        {
            lastMemberQueryInterval = interval;
            if (lastMemberQueryInterval <= 0)
            {
                sprintf(error, "The Last Member Query Interval should be "
                    "greater than zero\n");
                ERROR_ReportError(error);
            }
            lastMemberQueryInterval = (lastMemberQueryInterval/SECOND)*10;
            if (lastMemberQueryInterval > 255)
            {
                sprintf(error, "The Last Member Query Interval should be "
                    "less than 25.5 seconds\n");
                ERROR_ReportError(error);
            }
        }
        else
        {
            lastMemberQueryInterval = IGMP_LAST_MEMBER_QUERY_INTERVAL;
        }

        retVal = FALSE;
        IO_ReadInt(node->nodeId,
                   NetworkIpGetInterfaceAddress(node, interfaceIndex),
                   nodeInput,
                   "IGMP-LAST-MEMBER-QUERY-COUNT",
                   &retVal,
                   &intVal);

        if (retVal)
        {
            lastMemberQueryCount = (UInt16)intVal;
            if (lastMemberQueryCount <= 0)
            {
                sprintf(error, "The Last Member Query Count should be "
                    "greater than zero\n");
                ERROR_ReportError(error);
            }
        }
        else
        {
            lastMemberQueryCount = (UInt16)IGMP_LAST_MEMBER_QUERY_COUNT;
        }

        if (thisInterface->igmpVersion == IGMP_V2)
        {
            // All multicast routers join the all-routers-group
            // 224.0.0.2 multicast address.
            NetworkIpAddToMulticastGroupList(
                node, IGMP_V2_ALL_ROUTERS_GROUP_ADDR);
        }
        else
        {   // All IGMPv3 multicast routers join the all-routers-group
            // 224.0.0.22 multicast address.
            NetworkIpAddToMulticastGroupList(
                node, IGMP_V3_ALL_ROUTERS_GROUP_ADDR);
        }


        // Allocate router structure
        thisInterface->igmpRouter = (IgmpRouter*)
            MEM_malloc(sizeof(IgmpRouter));

        // Initializes Igmp router structure.
        IgmpRouterInit(
            node,
            thisInterface->igmpRouter,
            interfaceIndex,
            nodeInput,
            igmp->igmpInterfaceInfo[interfaceIndex]->robustnessVariable,
            queryInterval,
            (UInt8)queryResponseInterval,
            (UInt8)lastMemberQueryInterval,
            lastMemberQueryCount);
    }

    // Every node have host behavior.
    // Allocate host structure.
    thisInterface->igmpHost = (IgmpHost*)
        MEM_malloc(sizeof(IgmpHost));

    // Initializes Igmp host structure
    IgmpHostInit(node, thisInterface->igmpHost, nodeInput, interfaceIndex);

    if (interfaceIndex == node->numberInterfaces-1
        && igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType
                            == IGMP_PROXY)
    {
        if (!IgmpValidateProxyParameters(node, igmp) )
        {
            ERROR_ReportError("IGMP_PROXY: Not properly initialised.");
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpLayer()
// PURPOSE      : Interface function to receive all the self messages
//              : given by the IP layer to IGMP to handle self message
//              : and timer events.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpLayer(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_NETWORK_IgmpQueryTimer:
        {
            IgmpHandleQueryTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpOtherQuerierPresentTimer:
        {
            IgmpHandleOtherQuerierPresentTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpGroupReplyTimer:
        {
            IgmpHandleGroupReplyTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3HostReplyTimer:
        {
            Igmpv3HandleHostReplyTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpGroupMembershipTimer:
        {
            IgmpHandleGroupMembershipTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3SourceTimer:
        {
            Igmpv3RouterHandleSourceTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3RouterGroupTimer:
        {
            Igmpv3RouterHandleGroupTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3GrpAndSrcSpecificQueryRetransmitTimer:
        {
            Igmpv3HandleGrpAndSrcSpecificQueryRetransmitTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3GrpSpecificQueryRetransmitTimer:
        {
            Igmpv3HandleGrpSpecificQueryRetransmitTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpJoinGroupTimer:
        {
            if (DEBUG) {
                printf("Node %u got MSG_NETWORK_IgmpJoinGroupTimer "
                    "expired\n",
                    node->nodeId);
            }

            IgmpHandleJoinGroupTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3JoinGroupTimer:
        {
            if (DEBUG) {
                printf("Node %u got MSG_NETWORK_Igmpv3JoinGroupTimer "
                    "expired\n",
                    node->nodeId);
            }

            Igmpv3HandleJoinGroupTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpLeaveGroupTimer:
        {
            IgmpHandleLeaveGroupTimer(node, msg);
            break;
        }
        case MSG_NETWORK_IgmpLastMemberTimer:
        {
            IgmpHandleLastMemberTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3OlderHostPresentTimer:
        {
            Igmpv3HandleOlderHostPresentTimer(node, msg);
            break;
        }
        case MSG_NETWORK_Igmpv3OlderVerQuerierPresentTimer:
        {
            Igmpv3HandleOlderVerQuerierPresentTimer(node, msg);
            break;
        }
#ifdef ADDON_DB
        case MSG_STATS_IGMP_InsertSummary:
        {
            StatsDb* db = node->partitionData->statsDb;

            if (db == NULL ||
                !db->statsIgmpTable->createIgmpSummaryTable)
            {
                break;
            }

            HandleStatsDBIgmpSummaryTableInsertion(node);

            MESSAGE_Send(node,
                         MESSAGE_Duplicate(node, msg),
                         db->statsIgmpTable->igmpSummaryInterval);

            break;
        }
#endif

        default:
        {
            char errStr[MAX_STRING_LENGTH];

            sprintf(errStr, "Unknown Event-Type for node %u", node->nodeId);
            ERROR_Assert(FALSE, errStr);

            break;
        }
    }

    MESSAGE_Free(node, msg);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandleProtocolPacket()
// PURPOSE      : Function to process IGMP packets received from IP.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpHandleProtocolPacket(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress dstAddr,
    Int32 intfId)
{
    IgmpData* igmp;
    UInt8* ver_type = (UInt8*) MESSAGE_ReturnPacket(msg);

#ifdef ENTERPRISE_LIB
    // Check for DVMRP message
    if (*ver_type == IGMP_DVMRP)
    {
       RoutingDvmrpHandleProtocolPacket(node, msg, srcAddr, dstAddr, intfId);
       return;
    }
#endif // ENTERPRISE_LIB
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;


    if (ip->isIgmpEnable == FALSE)
    {
        return;
    }

    igmp = IgmpGetDataPtr(node);

    // in case the packet is from external node with CPU_INTERFACE as intfId
    // replace the intfId to the interfaceIndex matching the external intf addr
    if (CPU_INTERFACE == intfId && NetworkIpIsMyIP(node, srcAddr))
    {
        intfId = NetworkIpGetInterfaceIndexFromAddress(node, srcAddr);
    }

    // Sanity check
    if (!igmp || !igmp->igmpInterfaceInfo[intfId])
    {
        MESSAGE_Free(node, msg);
        return;
    }

    // Check whether packet come from attached subnet
    if (!NetworkIpIsPointToPointNetwork(node, intfId)
        && !IgmpIsSrcInAttachedSubnet(node, srcAddr))
    {
        MESSAGE_Free(node, msg);
        return;
    }

    if (IgmpIsMyPacket(node, dstAddr, intfId))
    {
        if (DEBUG) {
            char srcStr[20];
            char intfStr[20];
            char timeStr[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(srcAddr, srcStr);
            IO_ConvertIpAddressToString(
                NetworkIpGetInterfaceAddress(node, intfId),
                intfStr);
            TIME_PrintClockInSecond(node->getNodeTime(), timeStr);
            printf("Node %u: Receive packet from %s on "
                "interface %s at %ss\n",
                node->nodeId, srcStr, intfStr, timeStr);
        }

        igmp->igmpInterfaceInfo[intfId]->igmpStat.igmpTotalMsgReceived += 1;

        if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_ROUTER)
        {
            IgmpHandlePacketForRouter(
                node, msg, srcAddr, dstAddr, intfId);
        }
        else if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType  == IGMP_HOST)
        {
            IgmpHandlePacketForHost(
                node, msg, srcAddr, dstAddr, intfId);
        }
        else if (igmp->igmpInterfaceInfo[intfId]->igmpNodeType == IGMP_PROXY)
        {
            IgmpHandlePacketForProxy(
                node, msg, srcAddr, dstAddr, intfId);
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];

            sprintf(errStr, "Node %u is not initialized or it's not IGMP "
                "enabled", node->nodeId);
            ERROR_Assert(FALSE, errStr);
        }
    }

    MESSAGE_Free(node, msg);
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpFinalize()
// PURPOSE      : Print the statistics of IGMP protocol.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IgmpFinalize(Node* node)
{
    IgmpData* igmp;
    int i;

    igmp = IgmpGetDataPtr(node);

    // Sanity checking
    if (!igmp)
    {
        return;
    }

    if (igmp->showIgmpStat)
    {
        IgmpPrintStat(node);
    }

    if (DEBUG)
    {
        printf("----------------------------------------------------------\n"
            "Node %u: Printing related group information\n"
            "------------------------------------------------------------",
            node->nodeId);

        for (i = 0; i < node->numberInterfaces; i++)
        {
            IgmpInterfaceInfoType* thisInterface;
            IgmpGroupInfoForHost* tempPtr;
            int j = 1;
            char buf[20];

            thisInterface = igmp->igmpInterfaceInfo[i];

            if (!thisInterface) {
                continue;
            }

            tempPtr = thisInterface->igmpHost->groupListHeadPointer;

            if (tempPtr)
            {
                IO_ConvertIpAddressToString(
                    NetworkIpGetInterfaceAddress(node, i),
                    buf);
                printf("--------------------------------------------------\n"
                    "Membership information for interface %s :\n"
                    "--------------------------------------------------\n",
                    buf);
            }

            while (tempPtr != NULL)
            {
                IO_ConvertIpAddressToString(tempPtr->groupId, buf);
                printf("%d.\t%15s\n", j, buf);
                tempPtr = tempPtr->next;
                j++;
            }

            if (thisInterface->igmpRouter)
            {

                int j = 1;
                IgmpGroupInfoForRouter* tempPtr;
                tempPtr = thisInterface->igmpRouter->groupListHeadPointer;

                printf("\nNode %u is router\n", node->nodeId);

                if (tempPtr)
                {
                    IO_ConvertIpAddressToString(
                        NetworkIpGetInterfaceAddress(node, i),
                        buf);
                    printf("\nGroup responsibility as a router on "
                        "interface %s\n",
                        buf);
                }
                while (tempPtr != NULL)
                {
                    IO_ConvertIpAddressToString(tempPtr->groupId, buf);
                    printf("%d.\t%15s\n", j, buf);
                    tempPtr = tempPtr->next;
                    j++;
                }

            }
            else
            {
                printf("\nNode %u is host\n", node->nodeId);
            }
        }
        printf("\n");
    }
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpSetInterfaceType()
// PURPOSE      : Sets igmpInterfaceType
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static void IgmpSetInterfaceType(Node* node,
                                 IgmpData* igmpData,
                                 Int32 interfaceIndex,
                                 IgmpInterfaceType igmpInterfaceType)
{
    //set the igmpInterfaceType of the corresponding interface
    igmpData->igmpInterfaceInfo[interfaceIndex]->igmpInterfaceType =
        igmpInterfaceType;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpGetInterfaceType()
// PURPOSE      : Checks igmpInterfaceType
// RETURN VALUE : IGMP_UPSTREAM/IGMP_DOWNSTREAM/IGMP_DEFAULT_INTERFACE
// ASSUMPTION   : None
//---------------------------------------------------------------------------

static
IgmpInterfaceType IgmpGetInterfaceType(
                                 Node* node,
                                 IgmpData* igmpData,
                                 Int32 interfaceIndex)
{
    IgmpInterfaceType igmpReqInterfaceType;

    //read the igmpInterfaceType of the corresponding interface
    igmpReqInterfaceType =
        igmpData->igmpInterfaceInfo[interfaceIndex]->igmpInterfaceType;

    if (igmpReqInterfaceType == IGMP_UPSTREAM
        || igmpReqInterfaceType == IGMP_DOWNSTREAM)
    {
        return igmpReqInterfaceType;
    }

    return IGMP_DEFAULT_INTERFACE;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpValidateProxyParameters ()
// PURPOSE      : Checks whether IGMP_PROXY device has been
//                initialised correctly by checking the
//                igmpInterfaceTypes and making sure that only one
//                upstream interface is present
// RETURN VALUE : TRUE if properly initialised. FALSE otherwise.
// ASSUMPTION   : None
//---------------------------------------------------------------------------


static
BOOL IgmpValidateProxyParameters(Node* node,
                                 IgmpData* igmpData)
{
    int upstreamCount = 0;
    Int32 i =0;
    IgmpInterfaceType igmpInterfaceType;

    for (i = 0; i < (Int32)node->numberInterfaces; i++)
    {
        igmpInterfaceType = IgmpGetInterfaceType(node, igmpData, i);

        if (igmpInterfaceType == IGMP_UPSTREAM)
        {
            upstreamCount++;
        }
        else if (igmpInterfaceType == IGMP_DEFAULT_INTERFACE)
        {
            //set corresponding interfaceType to IGMP_DOWNSTREAM
            IgmpSetInterfaceType(node, igmpData, i, IGMP_DOWNSTREAM);
        }
    }
    if (upstreamCount != 1)
    {
        return FALSE;
    }
    return TRUE;
}

//---------------------------------------------------------------------------
//FUNCTION    : IgmpCheckSubscriptionInAllOtherDownstreamInterface ()
//PURPOSE     : Checks whether IGMP_PROXY device has been initialised
//              correctly by checking the igmpInterfaceTypes and
//              making sure that only one upstream interface is
//              present
//RETURN VALUE: TRUE if grouId is present in any other downstream
//              interface. FALSE otherwise.
//ASSUMPTION  : None
//---------------------------------------------------------------------------

static BOOL IgmpCheckSubscriptionInAllOtherDownstreamInterface(
                                   Node* node,
                                   IgmpData* igmpData,
                                   NodeAddress groupId,
                                   Int32 interfaceIndex)
{
    Int32 i = 0;
    IgmpInterfaceType igmpInterfaceType;
    IgmpRouter* igmpRouter;

    for (i = 0; i < (Int32)node->numberInterfaces; i++)
    {
        if (i == interfaceIndex) //all interfaces except interfaceIndex
        {
            continue;
        }

        igmpInterfaceType = IgmpGetInterfaceType(node, igmpData, i);

        if (igmpInterfaceType == IGMP_UPSTREAM)
        {
            continue;
        }

        igmpRouter = igmpData->igmpInterfaceInfo[i]->igmpRouter;

        if (IgmpCheckRtrGroupList(
            node, groupId, igmpRouter->groupListHeadPointer) )
        {
            return TRUE;
        }
    }
    return FALSE;
}


//---------------------------------------------------------------------------
// FUNCTION     : IgmpHandlePacketForProxy()
// PURPOSE      : Proxy processing a incoming IGMP packet.
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
static
void IgmpHandlePacketForProxy(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress grpAddr,
    Int32 intfId)
{
    IgmpData* igmp = NULL;

    igmp = IgmpGetDataPtr(node);

    ERROR_Assert(igmp, " IGMP interface not found");
    if (intfId ==
        (Int32)NetworkIpGetInterfaceIndexFromAddress(
                    node, igmp->igmpUpstreamInterfaceAddr))
    {
        IgmpHandlePacketForHost(node, msg, srcAddr, grpAddr, intfId);
    }
    else
    {
        IgmpHandlePacketForRouter(node, msg, srcAddr, grpAddr, intfId);
    }
}


// --------------------------------------------------------------------------
// FUNCTION     :IgmpGetSubscription()
// PURPOSE      :Checks whether a particular interface is subscribed to a
//               multicast group or not
// ASSUMPTION   :None
// RETURN VALUE :TRUE if specified interface is subscribed, else FALSE
// --------------------------------------------------------------------------


static
BOOL IgmpGetSubscription(Node* node,
                         Int32 interfaceIndex,
                         NodeAddress grpAddr,
                         NodeAddress srcAddr)
{
    IgmpData* igmp;
    IgmpHost* igmpHost;
    IgmpRouter* igmpRouter;
    IgmpInterfaceType igmpInterfaceType = IGMP_UPSTREAM;
    vector<struct SourceRecord> :: iterator it;
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    igmp = IgmpGetDataPtr(node);

    ERROR_Assert(igmp, " IGMP interface not found");
    if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType == IGMP_PROXY)
    {
        igmpInterfaceType =
            IgmpGetInterfaceType(node, igmp, interfaceIndex);
    }

    if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType == IGMP_HOST
        || igmpInterfaceType == IGMP_UPSTREAM)
    {
        igmpHost = igmp->igmpInterfaceInfo[interfaceIndex]->igmpHost;

        if (IgmpCheckHostGroupList(
            node, grpAddr, igmpHost->groupListHeadPointer) )
        {
            return TRUE;
        }
    }
    else if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType
        == IGMP_ROUTER || igmpInterfaceType == IGMP_DOWNSTREAM)
    {
        igmpRouter = igmp->igmpInterfaceInfo[interfaceIndex]->igmpRouter;
        IgmpGroupInfoForRouter* tmpGrpPtr = NULL;
        tmpGrpPtr = IgmpCheckRtrGroupList(node,
                                          grpAddr,
                                          igmpRouter->groupListHeadPointer);
        if (igmp->igmpProxyVersion == IGMP_V3
            && ip->isSSMEnable
            && Igmpv3IsSSMAddress(node, grpAddr))
        {
            if (tmpGrpPtr)
            {
                for (it = tmpGrpPtr->rtrForwardListVector.begin();
                     it < tmpGrpPtr->rtrForwardListVector.end();
                     ++it)
                {
                    if ((*it).sourceAddr == srcAddr)
                    {
                        return TRUE;
                    }
                 }
            }
        }
        else
        {
            if (tmpGrpPtr)
            {
                if (tmpGrpPtr->rtrCompatibilityMode == IGMP_V3
                    && igmp->igmpProxyVersion == IGMP_V3)
                {
                    if (tmpGrpPtr->filterMode == INCLUDE
                        && tmpGrpPtr->rtrForwardListVector.size() == 0)
                    {
                        return FALSE;
                    }
                }
                return TRUE;
            }
        }
    }
    return FALSE;
}



// --------------------------------------------------------------------------
// FUNCTION     :IgmpProxyRoutingFunction()
// PURPOSE      :Handle multicast forwarding of packet
// ASSUMPTION   :None
// RETURN VALUE :NULL
// --------------------------------------------------------------------------

void IgmpProxyRoutingFunction(Node* node,
                              Message* msg,
                              NodeAddress grpAddr,
                              Int32 interfaceIndex,
                              BOOL* packetWasRouted,
                              NodeAddress prevHop)
{
    Int32 i = 0;
    IgmpData* igmp = NULL;
    IpHeaderType* ipHeader = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    NodeAddress srcAddr = ipHeader->ip_src;
    igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");

    if (igmp->igmpInterfaceInfo[interfaceIndex]->igmpNodeType == IGMP_PROXY)
    {

        for (i = 0; i < (Int32)node->numberInterfaces; i++)
        {
            if (i == interfaceIndex)
            {
#ifdef ADDON_BOEINGFCS
                // for RIP packet self generated by SRW interface
                // due to the IGMP Proxy
                // the RIP packet should still be forwarded to the SRW subent
                if (node->macData[interfaceIndex]->macProtocol == MAC_PROTOCOL_CES_SRW_PORT &&
                    prevHop == ANY_IP)
                {
                    IgmpProxyForwardPacketOnInterface(
                        node,
                        MESSAGE_Duplicate(node, msg),
                        i);
                }
                else
                {
                    continue;
                }

#else
                continue;
#endif
            }

            if (NetworkIpGetInterfaceAddress(node,i) ==
                igmp->igmpUpstreamInterfaceAddr)
            {
                //send packet
                IgmpProxyForwardPacketOnInterface(node,
                                                MESSAGE_Duplicate(node, msg),
                                                i);
            }
            else if (IgmpGetSubscription(node, i, grpAddr,srcAddr))
            {
                if (IGMP_QUERIER ==
                    igmp->igmpInterfaceInfo[i]->igmpRouter->routersState)
                {
                    IgmpProxyForwardPacketOnInterface(node,
                                                MESSAGE_Duplicate(node, msg),
                                                i);
                }
            }
        }

        *packetWasRouted = TRUE;
        MESSAGE_Free(node, msg);
    }
    else
    {
        ERROR_ReportWarning("IGMP-PROXY routing function "
            "called for a non-proxy device");
    }
}

// --------------------------------------------------------------------------
// FUNCTION     :IgmpProxyForwardPacketOnInterface()
// PURPOSE      :Forwards packet on specified interface
// ASSUMPTION   :None
// RETURN VALUE :NULL
// --------------------------------------------------------------------------
static
void IgmpProxyForwardPacketOnInterface(Node* node,
                                       Message* msg,
                                       Int32 outgoingIntfId)
{
    NodeAddress nextHop;

    nextHop = NetworkIpGetInterfaceBroadcastAddress(node, outgoingIntfId);

    NetworkIpSendPacketToMacLayer(node, msg, outgoingIntfId, nextHop);
}



#ifdef ADDON_DB
/**
* To get the first node on each partition that is actually running IGMP.
*
* @param partition Data structure containing partition information
* @return First node on the partition that is running IGMP
*/
Node* StatsDBIgmpGetInitialNodePointer(PartitionData* partition)
{
    Node* traverseNode = partition->firstNode;
    IgmpData* igmp = NULL;


    while (traverseNode != NULL)
    {
        if (traverseNode->partitionId != partition->partitionId)
        {
            traverseNode = traverseNode->nextNodeData;
            continue;
        }

        NetworkDataIp* ip = (NetworkDataIp*)
                                        traverseNode->networkData.networkVar;

        if (ip->isIgmpEnable)
        {
            igmp = IgmpGetDataPtr(traverseNode);
        }

        if (igmp == NULL)
        {
            traverseNode = traverseNode->nextNodeData;
            continue;
        }

        // we've found a node that has IGMP on it!
        return traverseNode;
    }

    return NULL;
}
#endif

void IgmpIahepUpdateGroupOnRedIntf(
        Node* node,
        int intfId,
        unsigned char type,
        unsigned grpAddr)
{
    IgmpData* igmp = IgmpGetDataPtr(node);
    ERROR_Assert(igmp, " IGMP interface not found");
    IgmpHost* igmpHost;

    igmpHost = igmp->igmpInterfaceInfo[intfId]->igmpHost;

    IgmpGroupInfoForHost* grpPtr = IgmpCheckHostGroupList(
                node, grpAddr, igmpHost->groupListHeadPointer);

    if (!grpPtr && IGMP_MEMBERSHIP_REPORT_MSG == type)
    {
        // if the group join is from host not red ndoe itself
        // this is checked in iahep code
        // add the group into local interface's host list so it can
        // response properly to query msg from iahep/black side
        grpPtr = IgmpInsertHostGroupList(node, grpAddr, intfId);
        // since report is sent in iahep module right after this function call
        // update the states
        grpPtr->lastReportSendOrReceive = node->getNodeTime();
        grpPtr->isLastHost = TRUE;
        grpPtr->hostState = IGMP_HOST_IDLE_MEMBER;
    }
    else if (grpPtr && IGMP_LEAVE_GROUP_MSG == type)
    {
        BOOL retVal = FALSE;
        BOOL isLastHost;
        retVal = IgmpDeleteHostGroupList(
                node, grpAddr, intfId, &isLastHost);
        if (retVal && isLastHost)
        {
            // Send leave report
            IgmpSendLeaveReport(node, grpAddr, intfId);
        }
    }
}

