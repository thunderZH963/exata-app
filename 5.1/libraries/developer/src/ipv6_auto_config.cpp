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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "main.h"
#include "partition.h"
#include "fileio.h"
#include "api.h"
#include "ipv6.h"
#include "ip6_icmp.h"
#include "if_ndp6.h"
#include "ipv6_auto_config.h"

#define DEBUG_IPV6 0

// -------------------------------------------------------------------------
// Function             : IPv6AutoConfigParseAutoConfig
// Layer                : Network
// Purpose              : parse auto-config parameters.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + nodeInput          : const NodeInput *nodeInput: Pointer to nodeInput
// Return               : None
// -------------------------------------------------------------------------

void IPv6AutoConfigParseAutoConfig(Node* node, const NodeInput *nodeInput)
{
    Int32 i = 0;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo = NULL;
    memset(
        &ip->ipv6->autoConfigParameters,
        0,
        sizeof(Ipv6AutoConfigParam));
    char buf[MAX_STRING_LENGTH];
    char prefTimeStr[MAX_STRING_LENGTH];
    char validTimeStr[MAX_STRING_LENGTH];
    BOOL retVal = FALSE;
    BOOL readValue = FALSE;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {
            interfaceInfo = ip->interfaceInfo[i]->ipv6InterfaceInfo;
            memset(
                &interfaceInfo->autoConfigParam,
                0,
                sizeof(Ipv6AutoConfigInterfaceParam));
            in6_addr address;

            Ipv6GetGlobalAggrAddress(node, i, &address);

            IO_ReadBoolInstance(
                    node->nodeId,
                    &address,
                    nodeInput,
                    "IPV6-AUTOCONFIG-ENABLE",
                    i,
                    TRUE,
                    &retVal,
                    &readValue);

            if (!retVal || !readValue)
            {
                continue;
            }

            IO_ReadStringInstance(
                    node->nodeId,
                    &address,
                    nodeInput,
                    "IPV6-AUTOCONFIG-DEVICE-TYPE",
                    i,
                    TRUE,
                    &retVal,
                    buf);

            if (retVal && !strcmp(buf, "IPV6-AUTOCONFIG-HOST"))
            {
                // if auto-config enable
                interfaceInfo->autoConfigParam.isAutoConfig = TRUE;

                IO_ReadBoolInstance(
                    node->nodeId,
                    &address,
                    nodeInput,
                    "DEBUG-IPV6-AUTOCONFIG-ADDR",
                    i,
                    TRUE,
                    &retVal,
                    &readValue);

                if (retVal && readValue == TRUE)
                {
                    // auto-config address debug print enabled
                    interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr
                                                                = TRUE;
                }

                IO_ReadBoolInstance(
                    node->nodeId,
                    &address,
                    nodeInput,
                    "IPV6-AUTOCONFIG-ENABLE-DAD",
                    i,
                    TRUE,
                    &retVal,
                    &readValue);

                if (retVal && readValue == TRUE)
                {
                    if (!interfaceInfo->autoConfigParam.isAutoConfig)
                    {
                        ERROR_ReportError("An interface cannot be a configured "
                            "for DAD if it is not auto-configurable.\n");
                    }

                    // DAD enabled
                    interfaceInfo->autoConfigParam.isDadConfigured = TRUE;

                    IO_ReadBoolInstance(
                        node->nodeId,
                        &address,
                        nodeInput,
                        "DEBUG-IPV6-AUTOCONFIG-DAD",
                        i,
                        TRUE,
                        &retVal,
                        &readValue);

                    if (retVal && readValue == TRUE)
                    {
                        interfaceInfo->autoConfigParam.
                                            isDebugPrintAutoconfDad = TRUE;
                    }
                }
            }
            else if (retVal && !strcmp(buf, "IPV6-AUTOCONFIG-ROUTER"))
            {
                if (interfaceInfo->autoConfigParam.isAutoConfig)
                {
                    ERROR_ReportErrorArgs("Interface %d of node %d cannot"
                        " be a Delegated Router, since it is"
                        " auto-configurable.\n", i, node->nodeId);
                }
                else if (ip->ipForwardingEnabled == FALSE)
                {
                    ERROR_ReportErrorArgs("IP forwarding is not enabled on"
                        " interface %d of node %d, hence this interface "
                        "cannot be configured as Delegated router.\n",
                        i,
                        node->nodeId);
                }
                else if (interfaceInfo->prefixLen != MAX_PREFIX_LEN)
                {
                    ERROR_ReportErrorArgs(
                         "Delegated Prefix Length is not 64 at interface %d"
                         " of node %d.\n",
                         i,
                         node->nodeId);
                }

                interfaceInfo->autoConfigParam.isDelegatedRouter = TRUE;
            }
        }
    }
}

// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigMakeInterfaceIdentifier
// Layer                : Network
// Purpose              : adds new interface address generated using Auto-
//                        config and sets its status to PREFFERED or TENTATIVE
//                        depending on whether DAD is enabled on this interface
//                        or not.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + interfaceIndex     : Int32 interfaceIndex: interface index
// Return               : bool
// --------------------------------------------------------------------------
bool IPv6AutoConfigMakeInterfaceIdentifier(
                                Node* node,
                                Int32 interfaceIndex)
{
    bool autoConfigIntfacePresent = FALSE;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                    ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    // copy interface identifier in rightmost 64 bits.
    // we are making interface identifier by using mac-address
    // if mac-address in less than 64 bits interface identifier is
    // created by setting zeros in between.

    if (interfaceInfo->autoConfigParam.isAutoConfig)
    {
        MacHWAddress macAddr = GetMacHWAddress(node, interfaceIndex);
        memcpy(&interfaceInfo->siteLocalAddr.s6_addr32[2],
               macAddr.byte,
               macAddr.hwLength);

        MAPPING_CreateIpv6LinkLocalAddr(
                                    node,
                                    interfaceIndex,
                                    &interfaceInfo->globalAddr,
                                    &interfaceInfo->linkLocalAddr,
                                    0);
    }
    else
    {
        MAPPING_CreateIpv6LinkLocalAddr(
                            node,
                            interfaceIndex,
                            &(interfaceInfo->globalAddr),
                            &(interfaceInfo->linkLocalAddr),
                            interfaceInfo->prefixLen);
    }
    // Print the debug information at the console when linklocal
    // address is assigned.
    if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
    {
        char addressStr[MAX_STRING_LENGTH];
        printf("\n\nCreation of Link Local Address...\n");
        printf("Node Id: %d\n", node->nodeId);
        IO_ConvertIpAddressToString(
                                &interfaceInfo->linkLocalAddr,
                                addressStr);
        printf("Link Local Address: %s\n", addressStr);
    }

    if (ip->ipv6->autoConfigParameters.eligiblePrefixList == NULL)
    {
        ip->ipv6->autoConfigParameters.eligiblePrefixList =
                                            new NewEligiblePrefixList;
    }

    if (!interfaceInfo->autoConfigParam.isAutoConfig)
    {
        // add prefix info to the prefix list.
        newEligiblePrefix* prefixInfo =
                                (newEligiblePrefix*)MEM_malloc(
                                sizeof(newEligiblePrefix));

        memset(prefixInfo, 0, sizeof(newEligiblePrefix));

        Ipv6GetPrefix(
                    &interfaceInfo->globalAddr,
                    &prefixInfo->prefix,
                    interfaceInfo->prefixLen);

        prefixInfo->prefixLen = interfaceInfo->prefixLen;
        prefixInfo->prefixReceivedCount = 0;
        prefixInfo->interfaceIndex = interfaceIndex;

        prefixInfo->prefLifeTime = CLOCKTYPE_MAX;
        prefixInfo->validLifeTime = CLOCKTYPE_MAX;
        prefixInfo->LAReserved |= ND_OPT_PI_FLAG_ONLINK;

        ip->ipv6->autoConfigParameters.eligiblePrefixList->push_back(
                                                                prefixInfo);
    }
    else
    {
        // add link-local address in mapping
        MAPPING_ValidateIpv6AddressForInterface(
                                    node,
                                    interfaceIndex,
                                    interfaceInfo->linkLocalAddr,
                                    MAX_PREFIX_LEN,
                                    NETWORK_IPV6,
                                    CLOCKTYPE_MAX);

        autoConfigIntfacePresent = TRUE;
    }

    if (!interfaceInfo->autoConfigParam.isDadConfigured)
    {
        interfaceInfo->autoConfigParam.addressState = PREFERRED;
    }
    else
    {
        interfaceInfo->autoConfigParam.addressState = TENTATIVE;
        if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
        {
            printf("Address State: TENTATIVE\n");
        }
    }
    return autoConfigIntfacePresent;
}

//---------------------------------------------------------------------------
// FUNCTION         :: lookupPrefixItemInPrefixList
// LAYER            :: Network
// PURPOSE          :: lookup the prefix info for the given prefix.
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + prefix         :  in6_addr*     : Prefix to search
// + prefixLen      :  Int32           : prefix length
// RETURN           :: newEligiblePrefix* : prefix info.
//---------------------------------------------------------------------------
newEligiblePrefix* lookupPrefixItemInPrefixList(
                                Node* node,
                                in6_addr* prefix,
                                Int32 prefixLen)
{
    IPv6Data* ipv6 = (IPv6Data*) node->networkData.networkVar->ipv6;

    if (ipv6->autoConfigParameters.eligiblePrefixList == NULL)
    {
        return NULL;
    }

    NewEligiblePrefixList::iterator listItem =
                    ipv6->autoConfigParameters.eligiblePrefixList->begin();

    newEligiblePrefix* prefixInfo = NULL;

    while (listItem != ipv6->autoConfigParameters.eligiblePrefixList->end())
    {
        prefixInfo = (newEligiblePrefix*)*listItem;

        // compare the prefix
        if (prefixInfo->prefixLen == prefixLen)
        {
            if (!CMP_ADDR6(prefixInfo->prefix, *prefix))
            {
                return (*listItem);
            }
        }
        listItem++;
    }
    return NULL;
}


// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigReadPrefValidLifeTime
// Layer                : Network
// Purpose              : Read preffered, valid life-time for
//                        auto-configurable prefixes.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + intfIndex          : int  intfIndex: interface index
// + nodeInput          : const NodeInput *nodeInput: Pointer to nodeInput
// Return               : None
// --------------------------------------------------------------------------

void IPv6AutoConfigReadPrefValidLifeTime(
                               Node* node,
                               Int32 intfIndex,
                               const NodeInput *nodeInput)
{
    Int32 i = 0;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                            ip->interfaceInfo[intfIndex]->ipv6InterfaceInfo;

    char buf[MAX_STRING_LENGTH];
    BOOL retVal = FALSE;
    char prefTimeStr[MAX_STRING_LENGTH];
    char prefixStr[MAX_STRING_LENGTH];
    char validTimeStr[MAX_STRING_LENGTH];
    clocktype prefLifeTime = CLOCKTYPE_MAX;
    clocktype validLifeTime = CLOCKTYPE_MAX;

    in6_addr address;
    in6_addr prefix;
    in6_addr subnetPrefix;


    NodeId nodeId = 0;
    in6_addr prefixAddress;

    Ipv6GetGlobalAggrAddress(node, intfIndex, &address);
    Ipv6GetPrefix(&address, &prefix, interfaceInfo->prefixLen);

    if (interfaceInfo->prefixLen != MAX_PREFIX_LEN)
    {
        ERROR_ReportError(
             "Delegated Prefix Lenth is not 64.\n");
    }

    IO_ReadStringInstance(
            node->nodeId,
            &address,
            nodeInput,
            "IPV6-AUTOCONFIG-NETWORK-PREFIX",
            intfIndex,
            TRUE,
            &retVal,
            buf);
    if (retVal)
    {
        BOOL isIpAddr = FALSE;
        UInt32 prefixLength = 0;
        in6_addr validPrefix;
        IO_ParseNodeIdHostOrNetworkAddress(
                                    buf,
                                    &prefixAddress,
                                    &isIpAddr,
                                    &nodeId,
                                    &prefixLength);
        if (nodeId > 0)
        {
             ERROR_ReportErrorArgs("Invalid value for IPV6-NETWORK-PREFIX"
                " at node %d interface %d. Only prefix allowed \n",
                node->nodeId, intfIndex);
        }

        Ipv6GetPrefix(&prefixAddress,
                        &validPrefix, interfaceInfo->prefixLen);
        if (CMP_ADDR6(prefixAddress, validPrefix))
        {
            ERROR_ReportErrorArgs("Invalid prefix for"
                " IPV6-AUTOCONFIG-NETWORK-PREFIX"
                " at node %d interface %d\n",
                node->nodeId, intfIndex);
        }
        memcpy(&prefix, &prefixAddress, sizeof(in6_addr));
    }

    IO_ReadTimeInstance(
            node->nodeId,
            &address,
            nodeInput,
            "IPV6-AUTOCONFIG-PREFIX-PREFERRED-LIFETIME",
            intfIndex,
            TRUE,
            &retVal,
            &prefLifeTime);
    if (!retVal || prefLifeTime == 0)
    {
        prefLifeTime = CLOCKTYPE_MAX;
    }

    IO_ReadTimeInstance(
            node->nodeId,
            &address,
            nodeInput,
            "IPV6-AUTOCONFIG-PREFIX-VALID-LIFETIME",
            intfIndex,
            TRUE,
            &retVal,
            &validLifeTime);
    if (!retVal || validLifeTime == 0)
    {
        validLifeTime = CLOCKTYPE_MAX;
    }

    newEligiblePrefix* prefixItem = lookupPrefixItemInPrefixList(
                                        node,
                                        &prefix,
                                        interfaceInfo->prefixLen);

    if (prefixItem == NULL)
    {
        newEligiblePrefix* prefixInfo =
                                (newEligiblePrefix*)MEM_malloc(
                                sizeof(newEligiblePrefix));

        memset(prefixInfo, 0, sizeof(newEligiblePrefix));
        prefixInfo->prefix = prefix;
        prefixInfo->prefixLen = interfaceInfo->prefixLen;
        prefixInfo->prefixReceivedCount = 0;
        prefixInfo->interfaceIndex = intfIndex;

        prefixInfo->prefLifeTime = CLOCKTYPE_MAX;
        prefixInfo->validLifeTime = CLOCKTYPE_MAX;
        prefixInfo->LAReserved |= ND_OPT_PI_FLAG_ONLINK;

        ip->ipv6->autoConfigParameters.eligiblePrefixList->push_back(
                                                                prefixInfo);
        prefixItem = lookupPrefixItemInPrefixList(
                                        node,
                                        &prefix,
                                        interfaceInfo->prefixLen);
    }
    prefixItem->prefLifeTime = prefLifeTime;
    prefixItem->validLifeTime = validLifeTime;

    if (prefixItem->prefLifeTime > prefixItem->validLifeTime)
    {
        ERROR_ReportError("Preferred life time should be less "
                                "than valid life-time\n");
    }

    prefixItem->LAReserved |= ND_OPT_PI_FLAG_AUTO;

    interfaceInfo->autoConfigParam.prefLifetime =
                                    prefixItem->prefLifeTime;
    interfaceInfo->autoConfigParam.validLifetime =
                                    prefixItem->validLifeTime;

    // schedule an event for preferred life-time.
    if (prefixItem->prefLifeTime < CLOCKTYPE_MAX)
    {
        Message* msgForRtAdvUpdate;

        msgForRtAdvUpdate =
                   MESSAGE_Alloc(
                        node,
                        NETWORK_LAYER,
                        NETWORK_PROTOCOL_IPV6,
                        MSG_NETWORK_Address_Deprecate_Event);

        MESSAGE_InfoAlloc(node,
                          msgForRtAdvUpdate,
                          sizeof(IPv6AutoconfigDeprecateEventInfo));

        IPv6AutoconfigDeprecateEventInfo* packetInfo =
            (IPv6AutoconfigDeprecateEventInfo*)
            MESSAGE_ReturnInfo(msgForRtAdvUpdate);

        packetInfo->interfaceIndex = intfIndex;
        COPY_ADDR6(prefix, packetInfo->deprecatedPrefix);

        MESSAGE_Send(node,
                     msgForRtAdvUpdate,
                     prefixItem->prefLifeTime);
    }
}

// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigInit
// Layer                : Network
// Purpose              : creates event for IPv6 auto-config intialization
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// Return               : None
// --------------------------------------------------------------------------

void IPv6AutoConfigInit(Node* node)
{
    Message* message = MESSAGE_Alloc(
                            node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_IPV6,
                            MSG_NETWORK_Ipv6_AutoConfigInitEvent);
    MESSAGE_Send(node, message, PROCESS_IMMEDIATELY);
}


// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigHandleInitEvent
// Layer                : Network
// Purpose              : IPv6 auto-config intialization
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// Return               : None
// --------------------------------------------------------------------------

void IPv6AutoConfigHandleInitEvent(Node* node)
{
    Int32 i = 0;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo = NULL;

    // Now start the interface init
    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->interfaceType == NETWORK_IPV6
            || ip->interfaceInfo[i]->interfaceType == NETWORK_DUAL)
        {
            interfaceInfo = ip->interfaceInfo[i]->ipv6InterfaceInfo;

            if (interfaceInfo->autoConfigParam.isAutoConfig)
            {
                in6_addr oldGlobalAddress;
                COPY_ADDR6(interfaceInfo->globalAddr, oldGlobalAddress);

                if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
                {
                    char addressStr[MAX_STRING_LENGTH];
                    printf("\n\nDefault Configured Global Address changed to"
                           " Link Local Address"
                            "(At AutoconfigInit Time)...\n");
                    printf("Node Id: %d\n", node->nodeId);
                    IO_ConvertIpAddressToString(
                                        &interfaceInfo->globalAddr,
                                        addressStr);
                    printf("Default Configured Address: %s\n",
                            addressStr);
                }

                // make configured address invalid
                IPv6InvalidateGlobalAddress(node, i, FALSE);

                // Print the debug information at the console when
                // global address is assigned.
                if (interfaceInfo->
                        autoConfigParam.isDebugPrintAutoconfAddr)
                {
                    char addressStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(
                                            &interfaceInfo->globalAddr,
                                            addressStr);
                    printf("Global Address: %s\n", addressStr);
                }
                Ipv6SendNotificationOfAddressChange (
                                        node, i, &oldGlobalAddress);

                Address address;
                SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
                GUI_SendAddressChange(
                        node->nodeId,
                        i,
                        address,
                        NETWORK_IPV6);

            }
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION     :: IPv6InvalidateGlobalAddress
// LAYER        :: Network
// PURPOSE      :: Invalidate GlobalAddress state
// PARAMETERS   ::
// + node               : Node* : node to be updated
// + interfaceIndex     : Int32 : node's interface index
// + isDeprecated       : bool : if global address becomes deprecated.
//                               the default value is FALSE.
// RETURN       :: None
//---------------------------------------------------------------------------
void
IPv6InvalidateGlobalAddress(
    Node* node,
    Int32 interfaceIndex,
    bool isDeprecated)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* iface =
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    // invalidate the mapping also
    MAPPING_InvalidateGlobalAddressForInterface(
        node,
        interfaceIndex,
        &iface->globalAddr,
        isDeprecated,
        iface->autoConfigParam.validLifetime);

    if (isDeprecated)
    {
        // set global address to deprecated address
        COPY_ADDR6(iface->globalAddr, iface->autoConfigParam.depGlobalAddr);
        iface->autoConfigParam.depValidLifetime =
                                iface->autoConfigParam.validLifetime;
        iface->autoConfigParam.depGlobalAddrPrefixLen = iface->prefixLen;
    }

    // overwrite the global address by link-local address
    COPY_ADDR6(iface->linkLocalAddr, iface->globalAddr);

    iface->prefixLen = 64;
    iface->autoConfigParam.prefLifetime = CLOCKTYPE_MAX;
    iface->autoConfigParam.validLifetime = CLOCKTYPE_MAX;
}


//---------------------------------------------------------------------------
// API              :: Ipv6SendNotificationOfAddressChange
// LAYER            :: Network
// PURPOSE          :: Allows the ipv6 layer to send prefix changed
//                     notification to all the protocols which are using old
//                     prefix.
// PARAMETERS       ::
// node             :  Node* node: Pointer to node.
// + interfaceIndex :  int       : Interface Index
// + oldGlobalAddress : in6_addr*  old global address
// RETURN           :  void      : NULL.
//---------------------------------------------------------------------------

void Ipv6SendNotificationOfAddressChange (
                                Node* node,
                                int interfaceIndex,
                                in6_addr* oldGlobalAddress)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    if (ipv6->autoConfigParameters.prefixChangedHandlerList == NULL)
    {
        return;
    }

    Ipv6PrefixChangedHandlerFunctionList::iterator listItem =
                ipv6->autoConfigParameters.prefixChangedHandlerList->begin();

    Ipv6PrefixChangedHandlerFunctionType prefixChangedHandler;

    while (listItem !=
            ipv6->autoConfigParameters.prefixChangedHandlerList->end())
    {
        prefixChangedHandler = (Ipv6PrefixChangedHandlerFunctionType)
                                                              (*listItem);

        if (prefixChangedHandler == NULL)
        {
            continue;
        }
        (prefixChangedHandler)(node, interfaceIndex, oldGlobalAddress);
        listItem++;
    }
    Ipv6InterfaceInitAdvt(node, interfaceIndex);
}


//---------------------------------------------------------------------------
// FUNCTION                : IPv6AutoConfigConfigureNewGlobalAddress
// PURPOSE                 : This functionis used to return the list item
//                           where the prefixreceived count is the maximum.
// PARAMETERS              ::
// node                    : Node* node : Node data pointer
// interfaceId             : Int32 : interface identifier
// eligiblePrefixList      : NewEligiblePrefixList : eligible prefix list
// minReceiveCount         : Int32 : minimum receive count
// list                    : newEligiblePrefix* : prefix information.
//---------------------------------------------------------------------------

newEligiblePrefix* IPv6AutoConfigConfigureNewGlobalAddress(
                            Node* node,
                            Int32 interfaceId,
                            NewEligiblePrefixList* eligiblePrefixList,
                            Int32 minReceiveCount)
{
    newEligiblePrefix* return_list_ptr = NULL;
    NewEligiblePrefixList::iterator listItem = eligiblePrefixList->begin();

    clocktype bestPrefTime = 0;
    clocktype currentTime = node->getNodeTime();

    newEligiblePrefix* prefixInfo = NULL;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    while (listItem != eligiblePrefixList->end())
    {
        prefixInfo = (newEligiblePrefix*)(*listItem);

        // Remove the prefix if its prefered time is expired.
        if (prefixInfo->prefLifeTime < currentTime ||
            ((currentTime - prefixInfo->timeStamp) > PREFIX_EXPIRY_INTERVAL))
        {
            in6_addr tempPrefix;
            Ipv6GetPrefix(
                    &interfaceInfo->globalAddr,
                    &tempPrefix, prefixInfo->prefixLen);
            if (!CMP_ADDR6(prefixInfo->prefix, tempPrefix))
            {
                listItem++;
                continue;
            }
            newEligiblePrefix* itemToBeRemoved =
                                            (newEligiblePrefix*)*listItem;
            listItem++;
            // remove the prefix
            eligiblePrefixList->remove(itemToBeRemoved);
            MEM_free(itemToBeRemoved);
            itemToBeRemoved = NULL;
            continue;
        }

        if (prefixInfo->prefixReceivedCount >= minReceiveCount
            && prefixInfo->isPrefixAutoLearned
            && prefixInfo->LAReserved & ND_OPT_PI_FLAG_AUTO
            && prefixInfo->prefLifeTime > bestPrefTime
            && prefixInfo->interfaceIndex == interfaceId)
        {
            bestPrefTime = prefixInfo->prefLifeTime;
            return_list_ptr = *listItem;
        }
        listItem++;
    }
    if (return_list_ptr != NULL)
    {
        return(return_list_ptr);
    }
    return NULL;
}


//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6AutoConfigSetDeprecatedAddress
// PURPOSE             :: Set the deprecated address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int : Index of the concerned interface
// + addr               : in6_addr* : IPv6 address pointer
// + lifetime           : clocktype : IPv6 deprecated address
//                                              lifetime.
// RETURN              :: None
//---------------------------------------------------------------------------
void
Ipv6AutoConfigSetDeprecatedAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr,
    clocktype lifetime)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    COPY_ADDR6(*addr, interfaceInfo->autoConfigParam.depGlobalAddr);

   interfaceInfo->autoConfigParam.depValidLifetime = lifetime;
}


//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6AutoConfigSetPreferedAddress
// PURPOSE             :: Set the prefered address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int  : Index of the concerned interface
// + subnetPrefix       : in6_addr* : IPv6 prefered address pointer
// + prefixLen          : int : prefix length
// + preflifetime       : clocktype : preferred life time
// + validlifetime      : clocktype : valid life time
// RETURN              :: None
//---------------------------------------------------------------------------
void Ipv6AutoConfigSetPreferedAddress(
    Node* node,
    int interfaceId,
    in6_addr* subnetPrefix,
    int prefixLen,
    clocktype preflifetime,
    clocktype validlifetime)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                           ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    in6_addr newPreferedAddr;

    // create the new prefered address from the subnet address
    COPY_ADDR6(*subnetPrefix, newPreferedAddr);
    MAPPING_UpdateIPv6AddressFromPreviousAddress(
        &interfaceInfo->linkLocalAddr,
        &newPreferedAddr,
        prefixLen);

    // using globalAddr for now
    COPY_ADDR6(newPreferedAddr, interfaceInfo->globalAddr);

    interfaceInfo->autoConfigParam.prefLifetime = preflifetime;
    interfaceInfo->autoConfigParam.validLifetime = validlifetime;
    interfaceInfo->prefixLen = prefixLen;
}
//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6AutoConfigGetPreferedAddress
// PURPOSE             :: Get the prefered address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int : Index of the concerned interface
// + addr               : in6_addr*  : IPv6 prefered address pointer
//                          - output
// RETURN              :: None
//---------------------------------------------------------------------------
void
Ipv6AutoConfigGetPreferedAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    // use globalAddr for now
    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->globalAddr,
        *addr);
}
//---------------------------------------------------------------------------
// FUNCTION     :: IPv6AutoConfigUpdateInterfaceInfo
// LAYER        :: Network
// PURPOSE      :: Update IPV6 interface information for an interface:
// PARAMETERS   ::
// + node               : Node* : node to be updated
// + interfaceIndex     : int : node's interface index
// + subnetPrefix       : in6_addr* : new subnet prefix
// + subnetPrefixLen    : unsigned int* : new subnet prefix length
// + preferedLifetime   : clocktype : prefered lifetime of new prefix
// + validLifetime      : clocktype : valid lifetime of new prefix
// RETURN       :: None
//---------------------------------------------------------------------------
void
IPv6AutoConfigUpdateInterfaceInfo(
                        Node* node,
                        int interfaceIndex,
                        in6_addr* subnetPrefix,
                        unsigned int subnetPrefixLen,
                        clocktype preferedLifetime,
                        clocktype validLifetime)
{
    in6_addr prevAddr;
    CLR_ADDR6(prevAddr);
    in6_addr prevSubnetAddr;
    CLR_ADDR6(prevSubnetAddr);
    in6_addr newPreferedAddr;
    CLR_ADDR6(newPreferedAddr);
    clocktype prefLifetime = 0;

    NetworkDataIp* ip = (NetworkDataIp* ) node->networkData.networkVar;
    IPv6InterfaceInfo* iface =
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    unsigned int prefixLen = iface->prefixLen;

    ///////////////////////////////////////////////
    // First update the IPv6 interface's address //
    ///////////////////////////////////////////////

    // move current prefered address to the depricated address
    // and update the deprecated lifetime value
    Ipv6AutoConfigGetPreferedAddress(
        node,
        interfaceIndex,
        &prevAddr);

    // Get the prefix to compare
    Ipv6GetPrefix(
        &prevAddr,
        &prevSubnetAddr,
        prefixLen);

    if (SAME_ADDR6(prevSubnetAddr, *subnetPrefix))
    {
        ERROR_ReportError(
            "IPv6UpdateAddressInfo: New subnet address "
            "is the same as the current subnet address\n");
    }

    // save as new depricated address
    // any previous deprecated address in lost
    Ipv6AutoConfigSetDeprecatedAddress(
        node,
        interfaceIndex,
        &prevAddr,
        iface->autoConfigParam.validLifetime);

    // update the prefered address with the new address
    Ipv6AutoConfigSetPreferedAddress(
        node,
        interfaceIndex,
        subnetPrefix,
        subnetPrefixLen,
        preferedLifetime,
        validLifetime);

    MAPPING_ValidateIpv6AddressForInterface(
                               node,
                               interfaceIndex,
                               iface->globalAddr,
                               iface->prefixLen,
                               NETWORK_IPV6,
                               iface->autoConfigParam.prefLifetime);
}

//---------------------------------------------------------------------------
// FUNCTION     :: IPv6AutoConfigHandleAddressDeprecateEvent
// LAYER        :: Network
// PURPOSE      :: Handles address deprecate event.
// PARAMETERS   ::
// + node       :  Node* : node to be updated
// + msg        :  Message* msg : pointer to message
// RETURN       :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleAddressDeprecateEvent(
                                Node* node,
                                Message* msg)
{
    in6_addr oldDeprecatedAddr;
    in6_addr deprecatedPrefix;
    IPv6AutoconfigDeprecateEventInfo* packetInfo =
        (IPv6AutoconfigDeprecateEventInfo*) MESSAGE_ReturnInfo(msg);
    Int32 interfaceId = packetInfo->interfaceIndex;

    COPY_ADDR6(packetInfo->deprecatedPrefix, deprecatedPrefix);
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo *interfaceInfo =
                      ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    interfaceInfo->autoConfigParam.msgDeprecateTimer = NULL;

    in6_addr prefix;

    ip->ipv6->autoConfigParameters.autoConfigStats.numOfPrefixesDeprecated++;
    Ipv6GetPrefix(&interfaceInfo->globalAddr,
                  &prefix,
                  interfaceInfo->prefixLen);

    newEligiblePrefix* prefixItem = lookupPrefixItemInPrefixList(
                                                node,
                                                &prefix,
                                                interfaceInfo->prefixLen);
    if (prefixItem)
    {
        MEM_free(prefixItem);
        ip->ipv6->
            autoConfigParameters.eligiblePrefixList->remove(prefixItem);
    }

    if (interfaceInfo->autoConfigParam.isDelegatedRouter &&
        CMP_ADDR6(prefix, deprecatedPrefix))
    {
        interfaceInfo->autoConfigParam.isDelegatedRouter = false;
        return;
    }

    // save old deprecated address
    COPY_ADDR6(interfaceInfo->autoConfigParam.depGlobalAddr,
               oldDeprecatedAddr);

    in6_addr oldGlobalAddress;
    COPY_ADDR6(interfaceInfo->globalAddr, oldGlobalAddress);

    if (interfaceInfo->autoConfigParam.isDadConfigured)
    {
        interfaceInfo->autoConfigParam.isDadEnable = TRUE;

        IPv6InvalidateGlobalAddress(node, interfaceId, TRUE);

        // if the address was manually configured, make the interface
        // auto-configurable as this address is now deprecated.
        if (!interfaceInfo->autoConfigParam.isAutoConfig)
        {
            interfaceInfo->autoConfigParam.isAutoConfig = TRUE;
            // add link-local address in mapping
            MAPPING_ValidateIpv6AddressForInterface(
                                            node,
                                            interfaceId,
                                            interfaceInfo->linkLocalAddr,
                                            MAX_PREFIX_LEN,
                                            NETWORK_IPV6,
                                            CLOCKTYPE_MAX);
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                printf("\n\nManually Configured Address deprecates"
                    "(Interface made Autoconfigurable)...\n");
            }
        }

        Ipv6SendNotificationOfAddressChange(
                                    node,
                                    interfaceId,
                                    &oldGlobalAddress);

        Address address;
        SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
        GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);

        // Now this is important as this field would be checked
        // by the receiving interface during DAD to estabilish
        // uniqueness of the link local address.
        interfaceInfo->autoConfigParam.addressState = TENTATIVE;

        ndsol6_output(
                    node,
                    interfaceId,
                    NULL,
                    &interfaceInfo->linkLocalAddr,
                    FALSE);

        // Print Statements to print Duplicate address detection
        // related information.
        if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
        {
            printf("\n\nDuplicate Address Detection"
                    " Procedure Starts...\n");
            printf("Neighbor Solicitation for DAD Sent\n");
        }
        if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr ||
            interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
        {
            char addressStr[MAX_STRING_LENGTH];
            printf("\n\nGlobal Address Deprecates...\n");
            printf("\n\nGlobal Address set to Link Local Address\n");
            printf("Node Id: %d\n",node->nodeId);
            IO_ConvertIpAddressToString(
                                    &interfaceInfo->globalAddr,
                                    addressStr);
            printf("Global Address: %s\n", addressStr);
            printf("Address State: TENTATIVE\n");
        }
        // Create an event to look for the advertisement
        // if received in reply to this solicitation that would
        // suggest that the link local address is not unique
        // And if no advertisement is received then we set
        Int32* interfaceIndxPtr = NULL;
        interfaceInfo->autoConfigParam.msgWaitNDAdvEvent =
                                        MESSAGE_Alloc(
                                            node,
                                            NETWORK_LAYER,
                                            NETWORK_PROTOCOL_IPV6,
                                            MSG_NETWORK_Ipv6_Wait_For_NDAdv);

        MESSAGE_InfoAlloc(
                        node,
                        interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                        sizeof(Int32));

        interfaceIndxPtr = (Int32*) MESSAGE_ReturnInfo(
                        interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);

        *interfaceIndxPtr = interfaceId;

        MESSAGE_Send(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                    WAIT_FOR_NDADV_INTERVAL);
    }
    else
    {
        newEligiblePrefix* returnAddr = (newEligiblePrefix*)
                    IPv6AutoConfigConfigureNewGlobalAddress(
                        node,
                        interfaceId,
                        ip->ipv6->autoConfigParameters.eligiblePrefixList);

        if (returnAddr == NULL)
        {
            IPv6InvalidateGlobalAddress(node, interfaceId, TRUE);

            // if the address was manually configured, make the
            // interface auto-configurable as this address is now
            // deprecated.
            if (!interfaceInfo->autoConfigParam.isAutoConfig)
            {
                interfaceInfo->autoConfigParam.isAutoConfig = TRUE;
                // add link-local address in mapping
                MAPPING_ValidateIpv6AddressForInterface(
                                            node,
                                            interfaceId,
                                            interfaceInfo->linkLocalAddr,
                                            MAX_PREFIX_LEN,
                                            NETWORK_IPV6,
                                            CLOCKTYPE_MAX);

                if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
                {
                    printf("\n\nManually Configured Address "
                            "deprecates(Interface made"
                            "Autoconfigurable)...\n");
                }
            }

            // Print the debug information at the console when
            // global address is set to Link Local Address.
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("\n\nGlobal Address Deprecates...\n");
                printf("\nGlobal Address set to Link Local Address"
                          "(No Prefix Available)...\n");
                printf("Node Id: %d\n", node->nodeId);
                printf("Interface Id: %d\n", interfaceId);
                IO_ConvertIpAddressToString(
                                        &interfaceInfo->globalAddr,
                                        addressStr);
                printf("Global Address: %s\n", addressStr);
                printf("Address State: PREFERRED\n");
            }

            Ipv6SendNotificationOfAddressChange(
                                    node,
                                    interfaceId,
                                    &oldGlobalAddress);

            Address address;
            SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
            GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);
        }
        else
        {
            // Print the debug information at the console when
            // global address is assigned.
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("\n\nGlobal Address deprecates...\n");
                printf("Node Id: %d\n", node->nodeId);
                printf("Interface Id: %d\n", interfaceId);
                IO_ConvertIpAddressToString(
                                 &interfaceInfo->globalAddr,
                                 addressStr);
                printf("Deprecated Address: %s\n", addressStr);
                printf("Address State: DEPRECATED\n");
                char clockStr[MAX_STRING_LENGTH];
                TIME_PrintClockInSecond(
                    interfaceInfo->autoConfigParam.validLifetime / SECOND,
                    clockStr,
                    node);
                printf("Valid LifeTime(Deprecated Address): %s\n",
                    clockStr);
            }

            IPv6AutoConfigUpdateInterfaceInfo(
                                node,
                                interfaceId,
                                &returnAddr->prefix,
                                returnAddr->prefixLen,
                                returnAddr->prefLifeTime,
                                returnAddr->validLifeTime);

            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("New Global Address Created...\n");
                IO_ConvertIpAddressToString(
                                    &interfaceInfo->globalAddr,
                                    addressStr);
                printf("Global Address: %s\n", addressStr);
                printf("Address State: PREFERRED\n");
            }

            Ipv6SendNotificationOfAddressChange (
                                           node,
                                           interfaceId,
                                           &oldGlobalAddress);

            Address address;
            SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
            GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);

            in6_addr defaultAddr;
            // set the source to default router
            memset(&defaultAddr, 0, sizeof(in6_addr));
            MacHWAddress llAddress;

            updatePrefixList(node,
                        interfaceId,
                        &defaultAddr,
                        0,  // Prefix Length
                        1,
                        llAddress,
                        RT_REMOTE,
                        AUTOCONF,
                        returnAddr->previousHop);

            if (returnAddr->prefLifeTime < CLOCKTYPE_MAX)
            {
                interfaceInfo->autoConfigParam.msgDeprecateTimer =
                                MESSAGE_Alloc(node,
                                     NETWORK_LAYER,
                                     NETWORK_PROTOCOL_IPV6,
                                     MSG_NETWORK_Address_Deprecate_Event);

                MESSAGE_InfoAlloc(
                            node,
                            interfaceInfo->autoConfigParam.msgDeprecateTimer,
                            sizeof(IPv6AutoconfigDeprecateEventInfo));

                IPv6AutoconfigDeprecateEventInfo* packetInfo =
                    (IPv6AutoconfigDeprecateEventInfo*) MESSAGE_ReturnInfo(
                    interfaceInfo->autoConfigParam.msgDeprecateTimer);

                packetInfo->interfaceIndex = interfaceId;
                COPY_ADDR6(returnAddr->prefix, packetInfo->deprecatedPrefix);

                MESSAGE_Send(
                            node,
                            interfaceInfo->autoConfigParam.msgDeprecateTimer,
                            returnAddr->prefLifeTime - node->getNodeTime());
            }
            ip->ipv6->autoConfigParameters.
                    autoConfigStats.numOfprefixchanges++;
        }
    }

    // cancel the old invalid timer if any for old deprecated address
    if (interfaceInfo->autoConfigParam.msgInvalidTimer)
    {
        MESSAGE_CancelSelfMsg(
            node,
            interfaceInfo->autoConfigParam.msgInvalidTimer);
        interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
    }


    if (interfaceInfo->autoConfigParam.depValidLifetime < CLOCKTYPE_MAX)
    {
        interfaceInfo->autoConfigParam.msgInvalidTimer =
                         MESSAGE_Alloc(node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_IPV6,
                               MSG_NETWORK_Address_Invalid_Event);

        MESSAGE_InfoAlloc(node,
                        interfaceInfo->autoConfigParam.msgInvalidTimer,
                        sizeof(Int32));

        Int32* interfaceIdPtr = (Int32*) MESSAGE_ReturnInfo(
                            interfaceInfo->autoConfigParam.msgInvalidTimer);

        *interfaceIdPtr = interfaceId;

        MESSAGE_Send(
        node,
        interfaceInfo->autoConfigParam.msgInvalidTimer,
        interfaceInfo->autoConfigParam.depValidLifetime - node->getNodeTime());
    }
}

//---------------------------------------------------------------------------
// API              :: Ipv6AddPrefixChangedHandlerFunction
// LAYER            :: Network
// PURPOSE          :: Add a Prefix change handler function to the List, This
//                     handler will be called when address prefix changes.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + PrefixChangeFunctionPointer
//                  :  Ipv6PrefixChangedHandlerFunctionType :
//                      prefix change function pointer
// RETURN           :: void  : NULL.
//---------------------------------------------------------------------------
void Ipv6AddPrefixChangedHandlerFunction(
            Node* node,
            Ipv6PrefixChangedHandlerFunctionType prefixChangeFunctionPointer)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;

    if (ipv6 == NULL)
    {
        return;
    }
    if (ipv6->autoConfigParameters.prefixChangedHandlerList == NULL)
    {
        ipv6->autoConfigParameters.prefixChangedHandlerList =
                    new Ipv6PrefixChangedHandlerFunctionList;
    }

    ipv6->autoConfigParameters.prefixChangedHandlerList->
                            push_back(prefixChangeFunctionPointer);
}


//---------------------------------------------------------------------------
// FUNCTION         :: IPv6AutoConfigAttachPrefixesRouterAdv
// LAYER            :: Network
// PURPOSE          :: attaches prefixes, that a router advertises, to 
//                     router adv
// PARAMETERS       ::
// + node           :  Node* : node to be updated
// + ndopt_pi       :  struct nd_opt_prefix_info_struct* ndopt_pi :
//                     prefix info
// + interfaceIndex :  Int32 : interface index
// RETURN           :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigAttachPrefixesRouterAdv(
                Node* node,
                struct nd_opt_prefix_info_struct* ndopt_pi,
                Int32 interfaceIndex)
{

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;
    // This is the code where we traverse the list of obtained prefixes and
    // attach these prefixes in the router advertisement packet. So that
    // the receiving node can configures accordingly.

    NewEligiblePrefixList :: iterator listItem =
                ipv6->autoConfigParameters.eligiblePrefixList->begin();
    while (listItem != ipv6->autoConfigParameters.eligiblePrefixList->end())
    {
        in6_addr addr;
        newEligiblePrefix* prefixInfo = (newEligiblePrefix*)(*listItem);

        if (!ndopt_pi)
        {
            ERROR_ReportError("No Prefix available\n");
            break;
        }
        if (!(prefixInfo->LAReserved & ND_OPT_PI_FLAG_AUTO) ||
            prefixInfo->interfaceIndex != interfaceIndex)
        {
            listItem++;
            continue;
        }
        ndopt_pi->nd_opt_pi_type = ND_OPT_PREFIX_INFORMATION;
        ndopt_pi->nd_opt_pi_len = 4;
        ndopt_pi->nd_opt_pi_prefix_len = prefixInfo->prefixLen;

        ndopt_pi->nd_opt_pi_flags_reserved = prefixInfo->LAReserved;

        ndopt_pi->nd_opt_pi_valid_time = prefixInfo->validLifeTime / SECOND;

        ndopt_pi->nd_opt_pi_preferred_time =
                                        prefixInfo->prefLifeTime / SECOND;

        Ipv6GetPrefix(
                &prefixInfo->prefix,
                &(ndopt_pi->nd_opt_pi_prefix),
                prefixInfo->prefixLen);

        if (DEBUG_IPV6)
        {
            char addressstr[80];
            IO_ConvertIpAddressToString(&addr, addressstr);
            printf("Router Advertisement %u %s Prefix Added %d\n",
                node->nodeId, addressstr, prefixInfo->interfaceIndex);
        }
        listItem++;
        ndopt_pi++;
    }
}

//---------------------------------------------------------------------------
// API              :: IPv6AutoConfigGetSrcAddrForNbrAdv
// LAYER            :: Network
// PURPOSE          :: get source address for neighbor advertisement
// PARAMETERS       ::
// + node           :  Node*    : Pointer to node.
// + interfaceId    :  Int32    : Interface Id.
// + src_addr       :  in6_addr : to store source address
// RETURN           :: void  : NULL.
//---------------------------------------------------------------------------
void IPv6AutoConfigGetSrcAddrForNbrAdv(
                    Node* node,
                    Int32 interfaceId,
                    in6_addr* src_addr)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                           ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    if (!interfaceInfo->autoConfigParam.isDadEnable)
    {
        if (interfaceInfo->autoConfigParam.addressState == PREFERRED)
        {
            Ipv6GetGlobalAggrAddress(node, interfaceId, src_addr);
        }
        else
        {
            *src_addr = interfaceInfo->linkLocalAddr;
        }
    }
}


//---------------------------------------------------------------------------
// API              :: IPv6AutoConfigHandleAddressChange
// LAYER            :: Network
// PURPOSE          :: Handles address change when duplicate address is detected
// PARAMETERS       ::
// + node           :  Node*    : Pointer to node.
// + msg            :  Message* : Pointer to message.
// + linkLayerAddr  :  MacHWAddress : link layer address.
// + interfaceId    :  Int32    : Interface Id.
// RETURN           :: NONE.
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleAddressChange(
        Node* node,
        Message* msg,
        MacHWAddress linkLayerAddr,
        Int32 interfaceId)
{
    NetworkDataIp* ip6 = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                     ip6->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    newEligiblePrefix* returnAddr = NULL;

    if (IS_LINKLADDR6(interfaceInfo->globalAddr))
    {
        returnAddr = (newEligiblePrefix*)
                IPv6AutoConfigConfigureNewGlobalAddress(
                    node,
                    interfaceId,
                    ip6->ipv6->autoConfigParameters.eligiblePrefixList);
        if (returnAddr != NULL)
        {
            Ipv6AutoConfigSetPreferedAddress (
                               node,
                               interfaceId,
                               &returnAddr->prefix,
                               returnAddr->prefixLen,
                               returnAddr->prefLifeTime,
                               returnAddr->validLifeTime);

            // Print the debug information at the console when
            // global address is assigned.
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("\n\nConfiguring Global Address...\n");
                printf("Node Id: %d\n", node->nodeId);
                printf("Interface Id: %d\n", interfaceId);
                IO_ConvertIpAddressToString(
                                    &interfaceInfo->globalAddr,
                                    addressStr);
                printf("Global Address: %s\n", addressStr);
                printf("Address State: PREFERRED\n");
            }

            Ipv6SendNotificationOfAddressChange (
                                           node,
                                           interfaceId,
                                           &interfaceInfo->globalAddr);

            Address address;
            SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
            GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);

            MAPPING_ValidateIpv6AddressForInterface(
                           node,
                           interfaceId,
                           interfaceInfo->globalAddr,
                           interfaceInfo->prefixLen,
                           NETWORK_IPV6,
                           interfaceInfo->autoConfigParam.prefLifetime);

            in6_addr defaultAddr;
            // set the source to default router
            memset(&defaultAddr, 0, sizeof(in6_addr));

            IPv6AutoConfigUpdatePrefixList(
                        node,
                        interfaceId,
                        &defaultAddr,
                        0,  // Prefix Length
                        1,
                        linkLayerAddr,
                        RT_REMOTE,
                        AUTOCONF,
                        returnAddr->previousHop);

            if (returnAddr->prefLifeTime < CLOCKTYPE_MAX)
            {
                interfaceInfo->autoConfigParam.msgDeprecateTimer =
                               MESSAGE_Alloc(
                               node,
                               NETWORK_LAYER,
                               NETWORK_PROTOCOL_IPV6,
                               MSG_NETWORK_Address_Deprecate_Event);

                MESSAGE_InfoAlloc(
                        node,
                        interfaceInfo->autoConfigParam.msgDeprecateTimer,
                        sizeof(IPv6AutoconfigDeprecateEventInfo));

                IPv6AutoconfigDeprecateEventInfo* packetInfo =
                    (IPv6AutoconfigDeprecateEventInfo*) MESSAGE_ReturnInfo(
                    interfaceInfo->autoConfigParam.msgDeprecateTimer);

                packetInfo->interfaceIndex = interfaceId;
                COPY_ADDR6(returnAddr->prefix, packetInfo->deprecatedPrefix);

                MESSAGE_Send(
                    node,
                    interfaceInfo->autoConfigParam.msgDeprecateTimer,
                    returnAddr->prefLifeTime - node->getNodeTime());
            }
            ip6->ipv6->
              autoConfigParameters.autoConfigStats.numOfprefixchanges++;
            if (interfaceInfo->autoConfigParam.msgWaitNDAdvEvent)
            {
                MESSAGE_CancelSelfMsg(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);
                interfaceInfo->autoConfigParam.msgWaitNDAdvEvent
                                                = NULL;
            }
            // cancel the old invalid timer if any
            // for old deprecated address
            if (interfaceInfo->autoConfigParam.msgInvalidTimer)
            {
                MESSAGE_CancelSelfMsg(
                    node,
                    interfaceInfo->autoConfigParam.msgInvalidTimer);
                interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
            }

            interfaceInfo->autoConfigParam.isDadEnable = FALSE;
            interfaceInfo->autoConfigParam.addressState = PREFERRED;

            MESSAGE_Free(node, msg);
            return;
        }
        // If link local address is configured as global address
        // DAD fails and there is no prefix in eligible prefix list
        else
        {
            NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

            IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
            MAPPING_InvalidateGlobalAddressForInterface(
                node,
                interfaceId,
                &interfaceInfo->globalAddr,
                FALSE,
                0);
            if (interfaceInfo->autoConfigParam.msgWaitNDAdvEvent)
            {
                MESSAGE_CancelSelfMsg(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);
                interfaceInfo->autoConfigParam.msgWaitNDAdvEvent = NULL;
            }
            // cancel the old invalid timer if any
            // for old deprecated address
            if (interfaceInfo->autoConfigParam.msgInvalidTimer)
            {
                MESSAGE_CancelSelfMsg(
                    node,
                    interfaceInfo->autoConfigParam.msgInvalidTimer);
                interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
            }
            interfaceInfo->autoConfigParam.isDadEnable = FALSE;
            interfaceInfo->autoConfigParam.addressState = INVALID;
            return;
        }
    }

    // if link local address is not configured as global address

    interfaceInfo->autoConfigParam.validLifetime = CLOCKTYPE_MAX;

    Ipv6SendNotificationOfAddressChange (
                                   node,
                                   interfaceId,
                                   &interfaceInfo->globalAddr);


    Address address;
    SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
    GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);

    MAPPING_ValidateIpv6AddressForInterface(
                           node,
                           interfaceId,
                           interfaceInfo->globalAddr,
                           interfaceInfo->prefixLen,
                           NETWORK_IPV6,
                           interfaceInfo->autoConfigParam.prefLifetime);

    if (interfaceInfo->autoConfigParam.msgWaitNDAdvEvent)
    {
        MESSAGE_CancelSelfMsg(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);
        interfaceInfo->autoConfigParam.msgWaitNDAdvEvent = NULL;
    }
    // cancel the old invalid timer if any
    // for old deprecated address
    if (interfaceInfo->autoConfigParam.msgInvalidTimer)
    {
        MESSAGE_CancelSelfMsg(
            node,
            interfaceInfo->autoConfigParam.msgInvalidTimer);
        interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
    }

    // DAD fails and there is no prefix in the eligible prefix list

    interfaceInfo->autoConfigParam.isDadEnable = FALSE;
    interfaceInfo->autoConfigParam.addressState = PREFERRED;

    MESSAGE_Free(node, msg);
    return;
}

//---------------------------------------------------------------------------
// API              :: IPv6AutoConfigHandleNbrAdvForDAD
// LAYER            :: Network
// PURPOSE          :: configures new global address when neighbor
//                     advertisement
//                     is recieved.
// PARAMETERS       ::
// + node           :  Node*    : Pointer to node.
// + interfaceId    :  Int32    : Interface Id.
// + tgtaddr        :  in6_addr : to store target address
// + linkLayerAddr  :  MacHWAddress : link local address
// + msg            :  Message* pointer to message structure
// RETURN           :: BOOL.
//---------------------------------------------------------------------------
BOOL IPv6AutoConfigHandleNbrAdvForDAD(
                                Node* node,
                                Int32 interfaceId,
                                in6_addr tgtaddr,
                                MacHWAddress linkLayerAddr,
                                Message* msg)
{
    NetworkDataIp* ip6 = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                     ip6->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    // Used to test Duplicate Address Detection Functionality
    if (!CMP_ADDR6(interfaceInfo->linkLocalAddr, tgtaddr) &&
        !CMP_ADDR6(interfaceInfo->globalAddr, tgtaddr))
    {
        // modify interface identifier
        memcpy(&interfaceInfo->linkLocalAddr.s6_addr8[14],
               &node->nodeId,
               sizeof(NodeAddress));

        // update global address for new interface identifier
        memcpy(&interfaceInfo->globalAddr.s6_addr32[2],
            &interfaceInfo->linkLocalAddr.s6_addr32[2],
            sizeof(UInt32) * 2);
        // Print Statements when InterfaceId is not unique
        if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
        {
            char addressStr[MAX_STRING_LENGTH];
            printf("\n\nNeighbor Advertisement for DAD"
                                              " received...\n");
            printf("DAD Fails, InterfaceId is not unique\n");
            printf("Node Id: %d\n",node->nodeId);
            IO_ConvertIpAddressToString(
                &interfaceInfo->linkLocalAddr,
                addressStr);
            printf("Link local address: %s\n", addressStr);
            printf("Originating NdAdvt Node Id: %d\n",
                                         msg->originatingNodeId);
            IO_ConvertIpAddressToString(
                                  &interfaceInfo->linkLocalAddr,
                                  addressStr);

            printf("Manually Configured Link Local Address: %s\n",
                                                      addressStr);
            IO_ConvertIpAddressToString(
                             &interfaceInfo->globalAddr,
                             addressStr);

            printf("Manually Configured Global Address: %s\n",
                                                       addressStr);
        }
        IPv6AutoConfigHandleAddressChange(
            node,
            msg,
            linkLayerAddr,
            interfaceId);
        Ipv6InterfaceInitAdvt(node, interfaceId);
        return TRUE;
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigUpdatePrefixList
// LAYER               :: Network
// PURPOSE             :: Prefix list updating function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +addr                : in6_addr* addr : IPv6 Address of destination
// +prefixLen           : UInt32         : Prefix Length
// +report              : int report: error report flag
// +linkLayerAddr       : NodeAddress linkLayerAddr: Link layer address
// +routeFlag           : int routeFlag: route Flag
// +routeType           : int routeType: Route type e.g. gatewayed/local.
// +gatewayAddr         : in6_addr gatewayAddr: Gateway's ipv6 address.
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigUpdatePrefixList(
    Node* node,
    Int32 interfaceId,
    in6_addr* addr,
    UInt32 prefixLen,
    Int32 report,
    MacHWAddress& linkLayerAddr,
    Int32 routeFlag,
    Int32 routeType,
    in6_addr gatewayAddr)
{
    IPv6Data* ipv6 = node->networkData.networkVar->ipv6;
    rn_leaf* rn = NULL;

    if (DEBUG_IPV6)
    {
        char addressStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(addr, addressStr);
        printf("\tSearching For :%s linkLayer",addressStr);
        MAC_PrintHWAddr(&linkLayerAddr);
    }
    rn = rtalloc1(
                node,
                ipv6->rt_tables,
                addr,
                report,
                0UL,
                linkLayerAddr);

    rn->keyPrefixLen = prefixLen;

    if (rn)
    {
        if (rn->flags != RT_LOCAL)
        {
            if (rn->rn_option == 1) // Means to add then.
            {
                rn->flags = (unsigned char) routeFlag;
                rn->interfaceIndex = interfaceId;
                rn->type = routeType;

                rn->gateway = gatewayAddr;

                rn->rn_option = RTM_REACHHINT; // Means Reachable.
                rn->ln_state = LLNDP6_REACHABLE;
                rn->expire = node->getNodeTime() + NDPT_KEEP;

                // Default router list entry.
                ipv6->defaultRouter = (defaultRouterList*)
                    MEM_malloc(sizeof(defaultRouterList));

                // insert into the list in-place of overwriting it.
                memset(ipv6->defaultRouter,0,sizeof(defaultRouterList));

                COPY_ADDR6(gatewayAddr, ipv6->defaultRouter->routerAddr);

                ipv6->defaultRouter->outgoingInterface = interfaceId;
                ipv6->defaultRouter->linkLayerAddr = linkLayerAddr;
                ipv6->defaultRouter->next = NULL;
            }
        }
    }
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigForwardNbrAdv
// LAYER               :: Network
// PURPOSE             :: Forwards neighbor advertisement.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +tgtaddr             : in6_addr tgtaddr: target address
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigForwardNbrAdv(
                            Node* node,
                            Int32 interfaceId,
                            in6_addr tgtaddr,
                            Message* msg)
{
    NetworkDataIp* ip6 = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                     ip6->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    // This code is used for forwarding neighbor advertisement, The aim of
    // forwarding neighbor advertisements is to enable Multi hop duplicate
    // address detection.
    // There is a forwarding flag in the packet which is set by the sender of
    // this advertisement which suggests that this advertisement is a reply
    // to a Dad solicitation.
    // To avoid looping of the neighbor advertisements packets every
    // interface maintains a list of sender's address and doesn't forward the
    // packet if the sender already exist in the list. however the list is
    // refreshed after a certian time.
    if (interfaceInfo->autoConfigParam.receivedAdvList == NULL)
    {
        interfaceInfo->autoConfigParam.receivedAdvList =
                                                new Ipv6ReceivedAdvList;
    }
    Ipv6ReceivedAdvEntry* item = NULL;
    Ipv6ReceivedAdvList :: iterator listItem =
                    interfaceInfo->autoConfigParam.receivedAdvList->begin();
    while (listItem != interfaceInfo->autoConfigParam.receivedAdvList->end())
    {
        Ipv6ReceivedAdvEntry* tempItem = (Ipv6ReceivedAdvEntry*)
                                                    *listItem;
        if (!CMP_ADDR6(tempItem->senderAddr, tgtaddr))
        {
            item = tempItem;
            break;
        }
        listItem++;
    }
    if (item)
    {
        if ((node->getNodeTime() - item->timeStamp) <
                    2 * WAIT_FOR_NDADV_INTERVAL)
        {
            MESSAGE_Free(node, msg);
        }
        else
        {
            item->timeStamp = node->getNodeTime();
        }
    }
    else
    {
        Ipv6ReceivedAdvEntry* newTempItem = (Ipv6ReceivedAdvEntry*)MEM_malloc
                            (sizeof(Ipv6ReceivedAdvEntry));
        newTempItem->senderAddr = tgtaddr;
        newTempItem->timeStamp = node->getNodeTime();
        interfaceInfo->autoConfigParam.receivedAdvList->
                    push_back(newTempItem);

        // forward neighbor advertisement but after delay of 0.5 seconds
        // such that current advertisements do not collide
        interfaceInfo->autoConfigParam.forwardNAdv = msg;
        Message* message = MESSAGE_Alloc(
                            node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_IPV6,
                            MSG_NETWORK_Forward_NAdv_Event);
        MESSAGE_InfoAlloc(
                        node,
                        message,
                        sizeof(Int32));

        Int32* interfaceIndex = (Int32*)MESSAGE_ReturnInfo(message);

        *interfaceIndex = interfaceId;
        MESSAGE_Send(
            node,
            message,
            (clocktype) WAIT_FOR_ADVSOL_FORWARD_INTERVAL);
    }
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigInitiateDAD
// LAYER               :: Network
// PURPOSE             :: Initiates DAD process.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                        interface
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigInitiateDAD(
                            Node* node,
                            Int32 interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

    interfaceInfo->autoConfigParam.isDadEnable = TRUE;

    // Now this is important as this field would be checked
    // by the receiving interface during DAD to estabilish the
    // uniqueness of the link local address.
    interfaceInfo->autoConfigParam.addressState = TENTATIVE;

    ndsol6_output(
                node,
                interfaceIndex,
                NULL,
                &interfaceInfo->linkLocalAddr,
                FALSE);
    // Print Statements to print Duplicate address detection related
    // information.
    if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
    {
        char addressStr[MAX_STRING_LENGTH];
        printf("\n\nDuplicate Address Detection Procedure "
                                                      "Starts...\n");
        printf("Node Id: %d\n",node->nodeId);
        IO_ConvertIpAddressToString(
                                 &interfaceInfo->linkLocalAddr,
                                 addressStr);
        printf("Tentative link local address: %s\n", addressStr);
        printf("Neighbor Solicitation for DAD Sent\n");
    }

    // Create an event to look for the advertisement which
    // if received in reply to this solicitation would suggest that
    // the link local address is not unique, And if no advertisement
    // is received then we set the state as preferred.
    Int32* interfaceIndxPtr = NULL;
    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent =
    MESSAGE_Alloc(node,
                NETWORK_LAYER,
                NETWORK_PROTOCOL_IPV6,
                MSG_NETWORK_Ipv6_Wait_For_NDAdv);

    MESSAGE_InfoAlloc(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                    sizeof(Int32));

    interfaceIndxPtr =
               (Int32*) MESSAGE_ReturnInfo(
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);

    *interfaceIndxPtr = interfaceIndex;

    MESSAGE_Send(
                node,
                interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                WAIT_FOR_NDADV_INTERVAL);
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessNbrSolForDAD
// LAYER               :: Network
// PURPOSE             :: Processes neighbor solicitation received for DAD.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                        interface
// +nsp                 : nd_neighbor_solicit* nsp : neighbor solicitation
//                        data
// +linkLayerAddr       : MacHWAddress linkLayerAddr : link layer address
// +msg                 : Message* msg : pointer to message
// RETURN              :: bool
//---------------------------------------------------------------------------
bool IPv6AutoConfigProcessNbrSolForDAD(
                                   Node* node,
                                   Int32 interfaceIndex,
                                   nd_neighbor_solicit* nsp,
                                   MacHWAddress linkLayerAddr,
                                   Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    bool isSameLinkLocalAddr =
            !CMP_ADDR6(nsp->nd_ns_target, interfaceInfo->linkLocalAddr);

    // This is a code for a hook which is used to test DAD in a multihop
    // enviroment.
    // Some simple scenarios are taken where the node with a preferred
    // is multi hop away from the node performing duplicate address
    // detection.
//#define TEST_DAD_FAILURE
#ifdef TEST_DAD_FAILURE
    static BOOL isDADNdSend = FALSE;
    if (node->nodeId == 4 && msg->originatingNodeId == 1 && !isDADNdSend)
    {
        isDADNdSend = TRUE;
        isSameLinkLocalAddr = 1;
    }
#endif //TEST_DAD_FAILURE
    if (!interfaceInfo->autoConfigParam.isDadEnable)
    {
        if (isSameLinkLocalAddr)
        {
            in6_addr dst_addr;
            Ipv6SolicitationMulticastAddress(
                            &dst_addr,
                            &interfaceInfo->linkLocalAddr);
             if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
            {
                printf("\n\nNeighbor Advertisement For Dad Sent...\n");
                printf("Node Id: %d\n",node->nodeId);
                char addressStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(
                    &interfaceInfo->linkLocalAddr,
                    addressStr);
                printf("Link local address: %s\n", addressStr);
                printf("Originating NdSol Node Id: %d\n",
                                            msg->originatingNodeId);
            }
             ndadv6_output(
                          node,
                          interfaceIndex,
                          &dst_addr,
                          &nsp->nd_ns_target,
                          FORWARD_ADV | SOLICITED_ADV);
            return TRUE;
        }
    }
    else
    {
        if (isSameLinkLocalAddr)
        {
            // modify interface identifier
            memcpy(&interfaceInfo->linkLocalAddr.s6_addr8[14],
                   &node->nodeId,
                   sizeof(NodeAddress));

            // update global address for new interface identifier
            memcpy(&interfaceInfo->globalAddr.s6_addr32[2],
                &interfaceInfo->linkLocalAddr.s6_addr32[2],
                sizeof(UInt32) * 2);
            //Print Statements when InterfaceId is not unique
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("\n\nNeighbor Solicitation for DAD received..."
                        "\n");
                printf("DAD Fails, link local address is not unique\n");
                printf("Node Id: %d\n",node->nodeId);
                IO_ConvertIpAddressToString(
                    &interfaceInfo->linkLocalAddr,
                    addressStr);
                printf("Link local address: %s\n", addressStr);
                printf("Originating NdSol Node Id: %d\n",
                                              msg->originatingNodeId);
                IO_ConvertIpAddressToString(
                                     &interfaceInfo->linkLocalAddr,
                                     addressStr);
                printf("Manually Configured Link Local Address: %s\n",
                                                             addressStr);
                IO_ConvertIpAddressToString(
                                     &interfaceInfo->globalAddr,
                                     addressStr);
                printf("Manually Configured Global Address: %s\n",
                                                             addressStr);
            }

            IPv6AutoConfigHandleAddressChange(
                node,
                msg,
                linkLayerAddr,
                interfaceIndex);
            return TRUE;
        }
    }
    return FALSE;
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigForwardNbrSolForDAD
// LAYER               :: Network
// PURPOSE             :: Forwards neighbor solicitation.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                        interface
// +tgtaddr             : in6_addr tgtaddr : target address
// +nsp                 : nd_neighbor_solicit* nsp : neighbor solicitation
//                        data
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigForwardNbrSolForDAD(
                   Node* node,
                   Int32 interfaceIndex,
                   in6_addr tgtaddr,
                   nd_neighbor_solicit* nsp,
                   Message* msg)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    // This is the solicitation forwarding code which forwards neighbor
    // solicitation for Dad.
    // A list is maintained to avoid looping of the neighbor solicitation
    // messages and a message is not forwarded if the list has an entry
    // which has the same timestampo as that of the received packet.
    // Time stamp is the time when the packet was generated which set
    // by the originator of the neighbor solicitation performing Dad.
    // The use of timestamp is to provide a mechanism to enable two or
    // more nodes be able to send Dad solicitations.

    if (interfaceInfo->autoConfigParam.receivedSolList == NULL)
    {
        interfaceInfo->autoConfigParam.receivedSolList =
                            new Ipv6ReceivedAdvList;
    }
    Ipv6ReceivedAdvEntry* item = NULL;
    Ipv6ReceivedAdvList :: iterator listItem =
                    interfaceInfo->autoConfigParam.receivedSolList->begin();
    while (listItem !=
               interfaceInfo->autoConfigParam.receivedSolList->end())
    {
        Ipv6ReceivedAdvEntry* tempItem = (Ipv6ReceivedAdvEntry*)*listItem;
        in6_addr targetAddr = tempItem->senderAddr;
        if (!CMP_ADDR6(targetAddr, tgtaddr) &&
            tempItem->timeStamp ==
                (clocktype)nsp->nd_ns_hdr.icmp6_data32[0])
        {
            item = tempItem;
            break;
        }
            listItem++;
    }
    if (item)
    {
         MESSAGE_Free(node, msg);
    }
    else
    {
        Ipv6ReceivedAdvEntry* newTempItem = (Ipv6ReceivedAdvEntry*)
                              MEM_malloc(sizeof(Ipv6ReceivedAdvEntry));
        COPY_ADDR6(tgtaddr, newTempItem->senderAddr);
        newTempItem->timeStamp = (clocktype)nsp->nd_ns_hdr.icmp6_data32[0];
        interfaceInfo->autoConfigParam.receivedSolList->
                                                push_back(newTempItem);

        // forward neighbor solicitation but after delay of 0.5 seconds
        // such that current advertisements do not collide
        interfaceInfo->autoConfigParam.forwardNSol = msg;
        Message* message = MESSAGE_Alloc(
                            node,
                            NETWORK_LAYER,
                            NETWORK_PROTOCOL_IPV6,
                            MSG_NETWORK_Forward_NSol_Event);
        MESSAGE_InfoAlloc(
                        node,
                        message,
                        sizeof(Int32));

        Int32* interfaceId = (Int32*)MESSAGE_ReturnInfo(message);

        *interfaceId = interfaceIndex;
        MESSAGE_Send(node, message, (Int64)WAIT_FOR_ADVSOL_FORWARD_INTERVAL);
        //ip->ipv6->autoConfigParameters.autoConfigStats.numOfSolForwarded++;
        // delay of 1 second added in forwarding the solicitation
        //icmp6_send(node, msg, 0, NULL, interfaceIndex, IP_FORWARDING);
    }
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessRouterAdv
// LAYER               :: Network
// PURPOSE             :: Process router advertisement.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : Int32 interfaceId : Index of the concerned
//                        interface
// +ndopt_pi            : nd_opt_prefix_info* ndopt_pi : prefix information
// +src_addr            : in6_addr src_addr : source address
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigProcessRouterAdv(
                            Node* node,
                            Int32 interfaceId,
                            nd_opt_prefix_info* ndopt_pi,
                            in6_addr src_addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;
    // Ipv6 Stateless Autoconfiguration.............................
    // Here in this part of the code check if global address is
    // available or not, if global address is not present then we
    // create the global address and set its address state to
    // tentative or preferred based upon the current state of the
    // link local address on receiving the prefix information we add
    // this info in the eligible prefix list.
    // Now if global address is already present then check if the
    // configured prefix is same as the prefix obtained if the two
    // are same then check if the time stamps i.e.difference the last
    // time this prefix was received and the current time, if this
    // value is less than 20 seconds then increment the prefix
    // received counter by one.
    // Also timestamp is updated only at the time when the prefix is
    // received from the same previous hop as which had configured
    // the currently configured address.
    // If the two prefixes are not the same then simply insert the
    // newly obtained prefix in the prefix list or update the list
    // if the prefix is already present in the list.

    if (interfaceInfo->autoConfigParam.isAutoConfig == TRUE)
    {
        newEligiblePrefix* prefixItem = lookupPrefixItemInPrefixList(
                                            node,
                                            &ndopt_pi->nd_opt_pi_prefix,
                                            ndopt_pi->nd_opt_pi_prefix_len);

        if (prefixItem != NULL)
        {
            if ((node->getNodeTime() - (prefixItem->timeStamp)) <
                                                  PREFIX_EXPIRY_INTERVAL / 2)
            {
                prefixItem->prefixReceivedCount++;
            }
            else
            {
                prefixItem->prefixReceivedCount = 1;
            }

            if (!(prefixItem->LAReserved & ND_OPT_PI_FLAG_AUTO)
                    && (ndopt_pi->nd_opt_pi_flags_reserved
                                            & ND_OPT_PI_FLAG_AUTO))
            {
                prefixItem->LAReserved =
                            ndopt_pi->nd_opt_pi_flags_reserved;

                // save source address of the packet
                // to make it default router
                COPY_ADDR6(src_addr, prefixItem->previousHop);

                prefixItem->interfaceIndex = interfaceId;
            }

            if (!CMP_ADDR6(prefixItem->previousHop, src_addr))
            {
                prefixItem->timeStamp = node->getNodeTime();
                prefixItem->prefLifeTime =
                                ndopt_pi->nd_opt_pi_preferred_time * SECOND;

                prefixItem->validLifeTime =
                                    ndopt_pi->nd_opt_pi_valid_time * SECOND;
            }
        }
        else
        if (ndopt_pi->nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO)
        {

            // This is a pointer to the new eligible
            // prefix structure
            newEligiblePrefix* newPrefixInfo = (newEligiblePrefix*)
                                MEM_malloc(sizeof(newEligiblePrefix));

            memset(newPrefixInfo,
                    0,
                    sizeof(newEligiblePrefix));

            Ipv6GetPrefix(
                    &ndopt_pi->nd_opt_pi_prefix,
                    &newPrefixInfo->prefix,
                    ndopt_pi->nd_opt_pi_prefix_len);

            newPrefixInfo->prefixLen = ndopt_pi->nd_opt_pi_prefix_len;

            newPrefixInfo->LAReserved = ndopt_pi->nd_opt_pi_flags_reserved;

            newPrefixInfo->prefLifeTime =
                                ndopt_pi->nd_opt_pi_preferred_time * SECOND;

            newPrefixInfo->validLifeTime =
                                    ndopt_pi->nd_opt_pi_valid_time * SECOND;

            // Prefix info received for first time
            newPrefixInfo->prefixReceivedCount = 1;

            newPrefixInfo->interfaceIndex = interfaceId;

            newPrefixInfo->isPrefixAutoLearned = TRUE;

            newPrefixInfo->timeStamp = node->getNodeTime();

            // save source address of the packet to set default router
            COPY_ADDR6(src_addr, newPrefixInfo->previousHop);

            ip->ipv6->autoConfigParameters.eligiblePrefixList->
                                            push_back(newPrefixInfo);
            ip->ipv6->
                autoConfigParameters.autoConfigStats.numOfPrefixesReceived++;
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION             : IPv6AutoConfigValidateCurrentConfiguredPrefix
// PURPOSE             :: Validate currently configured prefix
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : newEligiblePrefix* : prefix info.
//---------------------------------------------------------------------------
newEligiblePrefix* IPv6AutoConfigValidateCurrentConfiguredPrefix(
                    Node* node,
                    Int32 interfaceId)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    IPv6InterfaceInfo *interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    IPv6Data* ipv6 = ip->ipv6;

    in6_addr prefix;

    Ipv6GetPrefix(&interfaceInfo->globalAddr,
                     &prefix, interfaceInfo->prefixLen);

    newEligiblePrefix* returnAddr = NULL;
    newEligiblePrefix* prefixItem = lookupPrefixItemInPrefixList(
                                                node,
                                                &prefix,
                                                interfaceInfo->prefixLen);
    if (prefixItem)
    {
        if ((node->getNodeTime() - prefixItem->timeStamp) >
                PREFIX_EXPIRY_INTERVAL)
        {
            returnAddr = (newEligiblePrefix*)
                        IPv6AutoConfigConfigureNewGlobalAddress(
                            node,
                            interfaceId,
                            ipv6->autoConfigParameters.eligiblePrefixList);

            if (returnAddr)
            {
                in6_addr oldGlobalAddress;
                COPY_ADDR6(interfaceInfo->globalAddr, oldGlobalAddress);

                prefixItem->prefLifeTime = 0;
                prefixItem->validLifeTime = 0;
                IPv6InvalidateGlobalAddress(node, interfaceId, TRUE);

                // cancel deprecated timer and schedule invalid timer
                if (interfaceInfo->autoConfigParam.msgDeprecateTimer)
                {
                    MESSAGE_CancelSelfMsg(
                        node,
                        interfaceInfo->autoConfigParam.msgDeprecateTimer);
                    interfaceInfo->autoConfigParam.msgDeprecateTimer = NULL;
                }

                if (interfaceInfo->autoConfigParam.depValidLifetime <
                                                    CLOCKTYPE_MAX)
                {
                    interfaceInfo->autoConfigParam.msgInvalidTimer =
                                     MESSAGE_Alloc(
                                        node,
                                       NETWORK_LAYER,
                                       NETWORK_PROTOCOL_IPV6,
                                       MSG_NETWORK_Address_Invalid_Event);

                    MESSAGE_InfoAlloc(
                          node,
                          interfaceInfo->autoConfigParam.msgInvalidTimer,
                          sizeof(Int32));

                    Int32* interfaceIdPtr = (int*) MESSAGE_ReturnInfo(
                            interfaceInfo->autoConfigParam.msgInvalidTimer);

                    *interfaceIdPtr = interfaceId;

                    MESSAGE_Send(
                         node,
                         interfaceInfo->autoConfigParam.msgInvalidTimer,
                         interfaceInfo->autoConfigParam.depValidLifetime -
                            node->getNodeTime());
                }

                Ipv6SendNotificationOfAddressChange(node,
                                               interfaceId,
                                               &oldGlobalAddress);

                Address address;
                SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
                GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);
            }
        }
        return returnAddr;
    }
    return NULL;
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessRouterAdvForDAD
// LAYER               :: Network
// PURPOSE             :: Process router advertisement for DAD.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : Int32 interfaceId : Index of the concerned
//                        interface
// +returnAddr          : newEligiblePrefix* returnAddr :
// +defaultAddr         : in6_addr defaultAddr :
// +linkLayerAddr       : MacHWAddress linkLayerAddr : link layer address
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigProcessRouterAdvForDAD(
                            Node* node,
                            Int32 interfaceId,
                            newEligiblePrefix* returnAddr,
                            in6_addr defaultAddr,
                            MacHWAddress linkLayerAddr)
{

    // if auto-configurable interface
    // and global address was set to link-local
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
               ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo;

    if (returnAddr == NULL)
    {
        returnAddr = (newEligiblePrefix*)
                    IPv6AutoConfigConfigureNewGlobalAddress(
                        node,
                        interfaceId,
                        ip->ipv6->autoConfigParameters.eligiblePrefixList);
    }
    if (returnAddr != NULL)
    {
        if (interfaceInfo->autoConfigParam.isDadConfigured)
        {
            interfaceInfo->autoConfigParam.isDadEnable = TRUE;

            // Now this is important as this field would be checked
            // by the receiving interface during DAD to estabilish
            // uniqueness of the link local address.
            interfaceInfo->autoConfigParam.addressState = TENTATIVE;

            ndsol6_output(
                        node,
                        interfaceId,
                        NULL,
                        &interfaceInfo->linkLocalAddr,
                        FALSE);
            // Print Statements to print Duplicate address detection
            // related information.
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
            {
                printf("\n\nDuplicate Address Detection Procedure "
                                                        "Starts...\n");
                printf("Node Id: %d\n",node->nodeId);
                char addressStr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(
                    &interfaceInfo->linkLocalAddr,
                    addressStr);
                printf("Link local address: %s\n", addressStr);
                printf("Neighbor Solicitation for DAD Sent\n");
            }
            // Create an event to look for the advertisement
            // if received in reply to this solicitation that would
            // suggest that the link local address is not unique
            // And if no advertisement is received then we set
            Int32* interfaceIndxPtr = NULL;
            interfaceInfo->autoConfigParam.msgWaitNDAdvEvent =
                    MESSAGE_Alloc(
                                node,
                                NETWORK_LAYER,
                                NETWORK_PROTOCOL_IPV6,
                                MSG_NETWORK_Ipv6_Wait_For_NDAdv);

            MESSAGE_InfoAlloc(
                    node,
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                    sizeof(Int32));

            interfaceIndxPtr =
               (Int32*) MESSAGE_ReturnInfo(
                    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);

            *interfaceIndxPtr = interfaceId;

            MESSAGE_Send(
                     node,
                     interfaceInfo->autoConfigParam.msgWaitNDAdvEvent,
                     WAIT_FOR_NDADV_INTERVAL);
        }
        else
        {
            in6_addr oldGlobalAddress;
            COPY_ADDR6(interfaceInfo->globalAddr, oldGlobalAddress);

            Ipv6AutoConfigSetPreferedAddress(
                                   node,
                                   interfaceId,
                                   &returnAddr->prefix,
                                   returnAddr->prefixLen,
                                   returnAddr->prefLifeTime,
                                   returnAddr->validLifeTime);

            // Print the debug information at the console when
            // global address is assigned.
            if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
            {
                char addressStr[MAX_STRING_LENGTH];
                printf("\n\nConfiguring Global Address"
                                          "(Configure New Prefix)...\n");
                printf("Node Id: %d\n", node->nodeId);
                printf("Interface Id: %d\n", interfaceId);
                IO_ConvertIpAddressToString(
                                  &interfaceInfo->globalAddr,
                                  addressStr);
                printf("Global Address: %s\n", addressStr);
                printf("Address State: PREFERRED\n");
            }

            Ipv6SendNotificationOfAddressChange (
                                   node,
                                   interfaceId,
                                   &oldGlobalAddress);

            Address address;
            SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
            GUI_SendAddressChange(
                        node->nodeId,
                        interfaceId,
                        address,
                        NETWORK_IPV6);

            MAPPING_ValidateIpv6AddressForInterface(
                               node,
                               interfaceId,
                               interfaceInfo->globalAddr,
                               interfaceInfo->prefixLen,
                               NETWORK_IPV6,
                               interfaceInfo->autoConfigParam.prefLifetime);

            //set the source to default router
            memset(&defaultAddr, 0, sizeof(in6_addr));

            IPv6AutoConfigUpdatePrefixList(node,
                interfaceId,
                &defaultAddr,
                0,  // Prefix Length
                1,
                linkLayerAddr,
                RT_REMOTE,
                AUTOCONF,
                returnAddr->previousHop);

            // Adding Default route entry.
            if (Ipv6IsForwardingEnabled(ip->ipv6))
            {
                in6_addr gatewayAddr;
                memset(&gatewayAddr, 0, sizeof(in6_addr));
                MacHWAddress llAddr =
                    Ipv6GetLinkLayerAddress(node, interfaceId);

                IPv6AutoConfigUpdatePrefixList(node,
                    interfaceId,
                    &returnAddr->prefix,
                    returnAddr->prefixLen,
                    1,
                    llAddr,
                    RT_LOCAL,
                    0,
                    gatewayAddr);
            }

            if (returnAddr->prefLifeTime < CLOCKTYPE_MAX)
            {
                interfaceInfo->autoConfigParam.msgDeprecateTimer =
                        MESSAGE_Alloc(
                                    node,
                                    NETWORK_LAYER,
                                    NETWORK_PROTOCOL_IPV6,
                                    MSG_NETWORK_Address_Deprecate_Event);

                MESSAGE_InfoAlloc(
                    node,
                    interfaceInfo->autoConfigParam.msgDeprecateTimer,
                    sizeof(IPv6AutoconfigDeprecateEventInfo));

                IPv6AutoconfigDeprecateEventInfo* packetInfo =
                    (IPv6AutoconfigDeprecateEventInfo*) MESSAGE_ReturnInfo(
                    interfaceInfo->autoConfigParam.msgDeprecateTimer);

                memcpy(packetInfo, &interfaceId, sizeof(Int32));
                packetInfo->interfaceIndex = interfaceId;
                COPY_ADDR6(returnAddr->prefix, packetInfo->deprecatedPrefix);

                MESSAGE_Send(
                    node,
                    interfaceInfo->autoConfigParam.msgDeprecateTimer,
                    returnAddr->prefLifeTime - node->getNodeTime());
            }
            ip->ipv6->autoConfigParameters.autoConfigStats.
                                        numOfprefixchanges++;
        }
    }
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigHandleWaitNDAdvExpiry
// LAYER               :: Network
// PURPOSE             :: to do required processing if no ND adv is received.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleWaitNDAdvExpiry(
                            Node* node,
                            Message* msg)
{
    Int32* interfaceIndx = ((Int32*)MESSAGE_ReturnInfo(msg));

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                        ip->interfaceInfo[*interfaceIndx]->ipv6InterfaceInfo;
    interfaceInfo->autoConfigParam.msgWaitNDAdvEvent = NULL;

    if (interfaceInfo->autoConfigParam.addressState == TENTATIVE)
    {
        if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfDad)
        {
            char addressStr[MAX_STRING_LENGTH];
            printf("\n\nTimer For DAD Expired\n");
            printf("DAD Completed Successfully, "
                      "Configured Interface Identifier is unique\n");
            printf("Node Id: %d\n", node->nodeId);
            IO_ConvertIpAddressToString(
                                 &interfaceInfo->linkLocalAddr,
                                 addressStr);
            printf("Link local address: %s\n", addressStr);
        }
        interfaceInfo->autoConfigParam.addressState = PREFERRED;

        // if auto-configurable interface
        if (interfaceInfo->autoConfigParam.isAutoConfig == TRUE)
        {
            newEligiblePrefix* returnAddr = (newEligiblePrefix*)
                    IPv6AutoConfigConfigureNewGlobalAddress(
                        node,
                        *interfaceIndx,
                        ip->ipv6->autoConfigParameters.eligiblePrefixList);

            if (returnAddr != NULL)
            {
                in6_addr oldGlobalAddress;
                COPY_ADDR6(
                    interfaceInfo->globalAddr, oldGlobalAddress);

                Ipv6AutoConfigSetPreferedAddress (
                                           node,
                                           *interfaceIndx,
                                           &returnAddr->prefix,
                                           returnAddr->prefixLen,
                                           returnAddr->prefLifeTime,
                                           returnAddr->validLifeTime);

                // Print the debug information at the console when
                // global address is assigned.
                if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
                {
                    char addressStr[MAX_STRING_LENGTH];
                    printf("\n\nCreation of Global Address...\n");
                    printf("Node Id: %d\n", node->nodeId);
                    printf("Interface Id: %d\n", *interfaceIndx);
                    IO_ConvertIpAddressToString(
                                     &interfaceInfo->globalAddr,
                                     addressStr);
                    printf("Global Address: %s\n", addressStr);
                    printf("Address State: PREFERRED\n");
                }

                Ipv6SendNotificationOfAddressChange (
                                               node,
                                               *interfaceIndx,
                                               &oldGlobalAddress);

                Address address;
                SetIPv6AddressInfo(&address, interfaceInfo->globalAddr);
                GUI_SendAddressChange(
                        node->nodeId,
                        *interfaceIndx,
                        address,
                        NETWORK_IPV6);

                MAPPING_ValidateIpv6AddressForInterface(
                               node,
                               *interfaceIndx,
                               interfaceInfo->globalAddr,
                               interfaceInfo->prefixLen,
                               NETWORK_IPV6,
                               interfaceInfo->autoConfigParam.prefLifetime);

                in6_addr defaultAddr;
                // set the source to default router
                memset(&defaultAddr, 0, sizeof(in6_addr));

                MacHWAddress llAddress;
                updatePrefixList(node,
                            *interfaceIndx,
                            &defaultAddr,
                            0,  // Prefix Length
                            1,
                            llAddress,
                            RT_REMOTE,
                            AUTOCONF,
                            returnAddr->previousHop);

                if (returnAddr->prefLifeTime < CLOCKTYPE_MAX)
                {
                    interfaceInfo->autoConfigParam.msgDeprecateTimer =
                                MESSAGE_Alloc(node,
                                     NETWORK_LAYER,
                                     NETWORK_PROTOCOL_IPV6,
                                     MSG_NETWORK_Address_Deprecate_Event);

                    MESSAGE_InfoAlloc(
                            node,
                            interfaceInfo->autoConfigParam.msgDeprecateTimer,
                            sizeof(IPv6AutoconfigDeprecateEventInfo));

                    IPv6AutoconfigDeprecateEventInfo* packetInfo =
                        (IPv6AutoconfigDeprecateEventInfo*) MESSAGE_ReturnInfo(
                        interfaceInfo->autoConfigParam.msgDeprecateTimer);

                    packetInfo->interfaceIndex = *interfaceIndx;
                    COPY_ADDR6(returnAddr->prefix,
                            packetInfo->deprecatedPrefix);

                    MESSAGE_Send(
                            node,
                            interfaceInfo->autoConfigParam.msgDeprecateTimer,
                            returnAddr->prefLifeTime - node->getNodeTime());
                }
                ip->ipv6->autoConfigParameters.autoConfigStats.
                                                numOfprefixchanges++;
            }
        }
        interfaceInfo->autoConfigParam.isDadEnable = FALSE;
        Ipv6InterfaceInitAdvt(node, *interfaceIndx);
    }
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigHandleAddressInvalidExpiry
// LAYER               :: Network
// PURPOSE             :: Handles address invalid event.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleAddressInvalidExpiry(
                            Node* node,
                            Message* msg)
{

    Int32* interfaceIdPtr = (Int32*) MESSAGE_ReturnInfo(msg);

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[*interfaceIdPtr]->ipv6InterfaceInfo;

    interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;

    // invalidate the mapping
    MAPPING_InvalidateGlobalAddressForInterface(
                node,
                *interfaceIdPtr,
                &interfaceInfo->autoConfigParam.depGlobalAddr,
                FALSE,
                0);

    if (interfaceInfo->autoConfigParam.isDebugPrintAutoconfAddr)
    {
        printf("\n\nDeprecated Address Invalidates...\n");
        printf("Node Id: %d\n",node->nodeId);
        printf("Interface Id: %d\n", *interfaceIdPtr);
        printf("Deprecated Address: 0:0:0:0:0:0:0:0\n");
    }

    //APP_HandleAddressChangeEvent(
    //            node,
    //            &interfaceInfo->depGlobalAddr);

    memset(&interfaceInfo->autoConfigParam.depGlobalAddr,
            0,
            sizeof(in6_addr));
    interfaceInfo->autoConfigParam.depValidLifetime = 0;

    interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
    ip->ipv6->autoConfigParameters.autoConfigStats.numOfPrefixesInvalidated++;
}

//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigPrintStats
// LAYER               :: Network
// PURPOSE             :: Print stats
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigPrintStats(Node* node)
{
    // Print auto-configuration stats
     char buf[MAX_STRING_LENGTH];
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;
    sprintf(buf, "No. of neighbor solicitations for DAD sent = %u",
        ipv6->autoConfigParameters.autoConfigStats.numOfNDSolForDadSent);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of neighbor solicitations for DAD received = %u",
           ipv6->autoConfigParameters.autoConfigStats.numOfNDSolForDadRecv);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of neighbor solicitations for DAD forwarded = %u",
            ipv6->autoConfigParameters.autoConfigStats.numOfSolForwarded);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of neighbor advertisement for DAD sent = %u",
           ipv6->autoConfigParameters.autoConfigStats.numOfNDAdvForDadSent);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of neighbor advertisement for DAD received = %u",
           ipv6->autoConfigParameters.autoConfigStats.numOfNDAdvForDadRecv);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of Neighbor advertisements for DAD forwarded = %u",
           ipv6->autoConfigParameters.autoConfigStats.numOfAdvertForwarded);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of times prefixes updated = %u",
           ipv6->autoConfigParameters.autoConfigStats.numOfprefixchanges);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of prefixes received = %u",
    ipv6->autoConfigParameters.autoConfigStats.numOfPrefixesReceived);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of packets drop due invalid source address = %u",
    ipv6->autoConfigParameters.autoConfigStats.numOfPktDropDueToInvalidSrc);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of times address is deprecated = %u",
    ipv6->autoConfigParameters.autoConfigStats.numOfPrefixesDeprecated);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);

    sprintf(buf, "No. of times address is invalidated = %u",
    ipv6->autoConfigParameters.autoConfigStats.numOfPrefixesInvalidated);
    IO_PrintStat(
            node,
            "Network",
            "IPv6",
            "",
            -1 , // instance Id
            buf);
}


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigFinalize
// LAYER               :: Network
// PURPOSE             :: IPv6 Auto-config finalizing function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigFinalize(Node* node)
{
    bool isAutoConfigEnable = FALSE;

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;
    for (Int32 i = 0; i < node->numberInterfaces; i++)
    {
        IPv6InterfaceInfo* interfaceInfo =
                                ip->interfaceInfo[i]->ipv6InterfaceInfo;
        if (interfaceInfo &&
            interfaceInfo->autoConfigParam.isAutoConfig == TRUE)
        {
            isAutoConfigEnable = TRUE;
        }
    }
    if (isAutoConfigEnable == TRUE)
    {
        IPv6AutoConfigPrintStats(node);
    }
    // free eligiblePrefixList;
    if (ipv6->autoConfigParameters.eligiblePrefixList)
    {
        NewEligiblePrefixList :: iterator listItem =
                    ipv6->autoConfigParameters.eligiblePrefixList->begin();

        newEligiblePrefix* prefixInfo = NULL;
        while (ipv6->autoConfigParameters.eligiblePrefixList->size() != 0)
        {
            listItem =
                    ipv6->autoConfigParameters.eligiblePrefixList->begin();
            prefixInfo = (newEligiblePrefix*)(*listItem);
            ipv6->autoConfigParameters.eligiblePrefixList->
                                                remove(prefixInfo);
            MEM_free(prefixInfo);
            prefixInfo = NULL;
        }
        delete (ipv6->autoConfigParameters.eligiblePrefixList);
        ipv6->autoConfigParameters.eligiblePrefixList = NULL;

    }
    for (Int32 i = 0; i < node->numberInterfaces; i++)
    {
        if (NetworkIpGetInterfaceType(node, i) == NETWORK_IPV6
            || NetworkIpGetInterfaceType(node, i) == NETWORK_DUAL)
        {
        IPv6InterfaceInfo* interfaceInfo =
                       ip->interfaceInfo[i]->ipv6InterfaceInfo;
        if (interfaceInfo->autoConfigParam.msgWaitNDAdvEvent)
        {
            MESSAGE_CancelSelfMsg(
                node,
                interfaceInfo->autoConfigParam.msgWaitNDAdvEvent);
            interfaceInfo->autoConfigParam.msgWaitNDAdvEvent = NULL;
        }

        if (interfaceInfo->autoConfigParam.msgDeprecateTimer)
        {
            MESSAGE_CancelSelfMsg(
                node,
                interfaceInfo->autoConfigParam.msgDeprecateTimer);
            interfaceInfo->autoConfigParam.msgDeprecateTimer = NULL;
        }

        if (interfaceInfo->autoConfigParam.msgInvalidTimer)
        {
            MESSAGE_CancelSelfMsg(
                node,
                interfaceInfo->autoConfigParam.msgInvalidTimer);
            interfaceInfo->autoConfigParam.msgInvalidTimer = NULL;
        }

        if (interfaceInfo->autoConfigParam.receivedAdvList)
        {
            Ipv6ReceivedAdvList :: iterator listItem =
                    interfaceInfo->autoConfigParam.receivedAdvList->begin();

            Ipv6ReceivedAdvEntry* rcvAdvEntry = NULL;
            while (interfaceInfo->autoConfigParam.receivedAdvList->size()
                                                                      != 0)
            {
                listItem =
                    interfaceInfo->autoConfigParam.receivedAdvList->begin();
                rcvAdvEntry = (Ipv6ReceivedAdvEntry*)(*listItem);
                interfaceInfo->autoConfigParam.receivedAdvList->
                                                    remove(rcvAdvEntry);
                MEM_free(rcvAdvEntry);
                rcvAdvEntry = NULL;
            }
            delete (interfaceInfo->autoConfigParam.receivedAdvList);
            interfaceInfo->autoConfigParam.receivedAdvList = NULL;
        }

        if (interfaceInfo->autoConfigParam.receivedSolList)
        {
            Ipv6ReceivedAdvList:: iterator listItem =
                    interfaceInfo->autoConfigParam.receivedSolList->begin();

            Ipv6ReceivedAdvEntry* rcvSolEntry = NULL;
            while (interfaceInfo->autoConfigParam.receivedSolList->size()
                                                                    != 0)
            {
                 listItem =
                    interfaceInfo->autoConfigParam.receivedSolList->begin();
                rcvSolEntry = (Ipv6ReceivedAdvEntry*)(*listItem);
                interfaceInfo->autoConfigParam.receivedSolList->
                                                    remove(rcvSolEntry);
                MEM_free(rcvSolEntry);
                rcvSolEntry = NULL;
            }
            delete (interfaceInfo->autoConfigParam.receivedSolList);
            interfaceInfo->autoConfigParam.receivedSolList = NULL;
            }
        }
    }

}

//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigAddPrefixInPrefixList
// LAYER               :: Network
// PURPOSE             :: Adds new prefix to prefix list
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +borrowedinterfaceInfo
//                      : IpInterfaceInfoType* borrowedinterfaceInfo :
//                          Interface info
// +interfaceIndex      : Int32 interfaceIndex : interface index
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigAddPrefixInPrefixList(
                            Node* node,
                            IpInterfaceInfoType* borrowedinterfaceInfo,
                            Int32 interfaceIndex)
{

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPv6Data* ipv6 = ip->ipv6;
    if (ipv6->autoConfigParameters.eligiblePrefixList)
    {
        // add prefix info to the prefix list.
        newEligiblePrefix* prefixInfo =
                            (newEligiblePrefix*)MEM_malloc(
                                     sizeof(newEligiblePrefix));

        memset(prefixInfo, 0, sizeof(newEligiblePrefix));

        char addressString[MAX_STRING_LENGTH];
        char subnetString[MAX_STRING_LENGTH];

        // Create IPv6 Testing Address Prefix (RFC 2471)
        strcpy(subnetString, "N64-2002:");

        sprintf(addressString, "%.2x%.2x:%.2x%.2x::\0",
            (borrowedinterfaceInfo->ipAddress & 0xff000000) >> 24,
            (borrowedinterfaceInfo->ipAddress & 0xff0000) >> 16,
            (borrowedinterfaceInfo->ipAddress & 0xff00) >> 8,
            borrowedinterfaceInfo->ipAddress & 0xff);

        strcat(subnetString, addressString);

        unsigned int prefixlen = 0;

        IO_ParseNetworkAddress(
                subnetString,
                &prefixInfo->prefix,
                &prefixlen);

        AddressMapType* map = node->partitionData->addressMapPtr;

        // get address counter from IPv6 subnet list.
        Int32 addressCounter = MAPPING_GetIPv6NetworkAddressCounter(
                                        map,
                                        prefixInfo->prefix,
                                        prefixlen);

        // update address counter of IPv6 subnet list.
        MAPPING_UpdateIPv6NetworkAddressCounter(
                    map,
                    prefixInfo->prefix,
                    prefixlen,
                    addressCounter + 1);

        prefixInfo->prefixLen = prefixlen;
        prefixInfo->prefixReceivedCount = 0;
        prefixInfo->interfaceIndex = interfaceIndex;
        prefixInfo->prefLifeTime = CLOCKTYPE_MAX;
        prefixInfo->validLifeTime = CLOCKTYPE_MAX;
        prefixInfo->LAReserved |= ND_OPT_PI_FLAG_ONLINK;
        prefixInfo->LAReserved |= ND_OPT_PI_FLAG_AUTO;
        prefixInfo->timeStamp = node->getNodeTime();

        ipv6->autoConfigParameters.eligiblePrefixList->push_back(prefixInfo);
    }
}

//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6GetDeprecatedAddress
// PURPOSE             :: Get the deprecated address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int : Index of the concerned interface
// + addr               : in6_addr* : IPv6 address pointer, output
// RETURN              :: None
//---------------------------------------------------------------------------
void
Ipv6GetDeprecatedAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    COPY_ADDR6(
        ip->interfaceInfo[interfaceId]->ipv6InterfaceInfo->
            autoConfigParam.depGlobalAddr,
        *addr);
}