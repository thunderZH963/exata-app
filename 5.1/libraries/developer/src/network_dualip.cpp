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

// /**
// PROTOCOL   :: Dual-IP
// LAYER      :: Network
// REFERENCES ::
// + rfc 4213
// + rfc 2185
// + rfc 3056
// COMMENTS   :: None
// **/

#include "network_dualip.h"
#include "main.h"
#include "partition.h"

#define DUAL_IP_DEBUG   0

#define BUFFER_SIZE     512

// /**
// FUNCTION            :: TunnelGetTunnelTypeStr
// LAYER               :: Network
// PURPOSE             :: get TunnelType String.
// PARAMETERS          ::
// + tunnelType        :: TunnelType   : tunnel Type.
// RETURN              :: char* TunnelType String
// **/
static
const char* TunnelGetTunnelTypeStr(TunnelType tunnelType)
{
    const char *tempString;
    if (tunnelType == IPv4_TUNNEL)
    {
       tempString = "Tunnel(v4)";
    }
    else if (tunnelType == IPv6_TUNNEL)
    {
       tempString = "Tunnel(v6)";
    }
    else if (tunnelType == SixToFour_TUNNEL)
    {
       tempString = "Tunnel(6to4)";
    }
    else
    {
       tempString = "Tunnel(unknown)";
    }
    return tempString;
}

// FUNCTION            :: TunnelIsVirtualInterface
// LAYER               :: Network
// PURPOSE             :: checking for virtual Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex        ::   int     :.Interface Index
// RETURN              :: BOOL
// **/
BOOL TunnelIsVirtualInterface(Node* node, int intIndex)
{
    if (intIndex < 0)
    {
        return FALSE;
    }
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    return ip->interfaceInfo[intIndex]->isVirtualInterface;
}

// FUNCTION            :: Is6to4Interface
// LAYER               :: Network
// PURPOSE             :: checking for 6to4 Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex        ::   int     :.Interface Index
// RETURN              :: BOOL
// **/
BOOL Is6to4Interface(Node* node, int intIndex)
{
    if (intIndex < 0)
    {
        return FALSE;
    }
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    return ip->interfaceInfo[intIndex]->ipv6InterfaceInfo->is6to4Enabled;
}

// FUNCTION            :: TunnelAddVirtualInterface
// LAYER               :: Network
// PURPOSE             :: Adding pseudo Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + tunnelInfo        :: TunnelInfoType* tunnelInfo: tunnel Information.
// + intIndex          :: int intIndex: borrowed interface index.
// RETURN              :: None
// **/
void TunnelAddVirtualInterface(Node* node,
                               TunnelInfoType* tunnelInfo,
                               int intIndex)
{
    if (intIndex < 0)
    {
        char buff[MAX_STRING_LENGTH];
        sprintf(buff,
            "%s stack is not enable on any interface of the node\n",
            tunnelInfo->tunnelType == IPv6_TUNNEL ? "IPv4" : "IPv6");
        ERROR_ReportError(buff);
    }

    ERROR_Assert(TunnelIsVirtualInterface(node, intIndex) == FALSE,
       "Virtual Interface can not borrow from some other virtual interface");

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    IpInterfaceInfoType* borrowedinterfaceInfo = ip->interfaceInfo[intIndex];

    int interfaceIndex = node->numberInterfaces;

    tunnelInfo->pseudoIntIndex = interfaceIndex;
    tunnelInfo->borrowedIntIndex = intIndex;

    ListInit(node, &tunnelInfo->interfaceStatusHandlerList);

    node->numberInterfaces++;

    ip->interfaceInfo[interfaceIndex] =
        (IpInterfaceInfoType*) MEM_malloc(sizeof(IpInterfaceInfoType));

    memset(ip->interfaceInfo[interfaceIndex],
           0,
           sizeof(IpInterfaceInfoType));

    ERROR_Assert(
        (interfaceIndex >= 0) && (interfaceIndex < MAX_NUM_INTERFACES),
        "Number of interfaces has exceeded MAX_NUM_INTERFACES or is < 0");

    ip->interfaceInfo[interfaceIndex]->isVirtualInterface = TRUE;
    ip->interfaceInfo[interfaceIndex]->ipFragUnit =
                            ip->interfaceInfo[intIndex]->ipFragUnit;

    // Initialize tunnnel info for first tunnel configured on
    // this interface
    ListInit(
        node,
        &ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo);

    // Insert into the tunnel-list of this interface
    ListInsert(
        node,
        ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo,
        node->getNodeTime(),
        (void *)tunnelInfo);


    //if tunnelType is IPv6_TUNNEL
    if (tunnelInfo->tunnelType == IPv6_TUNNEL)
    {
        //add v4 pseudo interface
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV4;
        ip->interfaceInfo[interfaceIndex]->ipAddress =
            borrowedinterfaceInfo->ipAddress;

        ip->interfaceInfo[interfaceIndex]->multicastEnabled =
            borrowedinterfaceInfo->multicastEnabled;

        ip->interfaceInfo[interfaceIndex]->numHostBits = 0;
    }
    else if (tunnelInfo->tunnelType == IPv4_TUNNEL)
    {
        IPv6InterfaceInfo* ipv6InterfaceInfo;
        //add v6 pseudo interface
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV6;

        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo =
            (IPv6InterfaceInfo*) MEM_malloc(sizeof(IPv6InterfaceInfo));

        memset(ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo,
            0, sizeof(IPv6InterfaceInfo));

        ipv6InterfaceInfo =
            ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

        ipv6InterfaceInfo->globalAddr =
            borrowedinterfaceInfo->ipv6InterfaceInfo->globalAddr;
        ipv6InterfaceInfo->prefixLen = 0;
        ipv6InterfaceInfo->linkLocalAddr =
            borrowedinterfaceInfo->ipv6InterfaceInfo->linkLocalAddr;
        ipv6InterfaceInfo->multicastAddr =
            borrowedinterfaceInfo->ipv6InterfaceInfo->multicastAddr;
        ipv6InterfaceInfo->multicastEnabled =
            borrowedinterfaceInfo->ipv6InterfaceInfo->multicastEnabled;
        ipv6InterfaceInfo->mtu =
            borrowedinterfaceInfo->ipv6InterfaceInfo->mtu;
    }
    else if (tunnelInfo->tunnelType == SixToFour_TUNNEL)
    {
        IPv6InterfaceInfo* ipv6InterfaceInfo;
        //add v6 pseudo interface
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV6;

        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo =
            (IPv6InterfaceInfo*) MEM_malloc(sizeof(IPv6InterfaceInfo));

        memset(ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo,
            0, sizeof(IPv6InterfaceInfo));

        ipv6InterfaceInfo =
            ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;

        ipv6InterfaceInfo->globalAddr =
            borrowedinterfaceInfo->ipv6InterfaceInfo->globalAddr;
        ipv6InterfaceInfo->prefixLen = 0;
        ip->interfaceInfo[interfaceIndex]->interfaceType = NETWORK_IPV6;

        ipv6InterfaceInfo->is6to4Enabled = TRUE;
        ip->ipv6->defaultRouteFlag = TRUE;

        // Ipv6 auto-config
        if (ipv6InterfaceInfo->autoConfigParam.isAutoConfig)
        {
            IPv6AutoConfigAddPrefixInPrefixList(
                node, borrowedinterfaceInfo, interfaceIndex);
        }
        rn_leaf* keyNode;

        keyNode = (rn_leaf*) MEM_malloc(sizeof(rn_leaf));

         memset(keyNode, 0, sizeof(rn_leaf));

        IO_ParseNetworkAddress(
            "N64-2002::",
            &keyNode->key,
            &keyNode->keyPrefixLen);

        keyNode->keyPrefixLen = 16;
        keyNode->linkLayerAddr = MacHWAddress();
        keyNode->flags = RT_LOCAL;
        keyNode->type = 0;
        keyNode->interfaceIndex = interfaceIndex;
        keyNode->rn_option = RTM_REACHHINT; // Means Reachable

        if (DUAL_IP_DEBUG)
        {
            printf("Before adding default route \n");
            Ipv6PrintForwardingTable(node);
        }

        // Insert into Radix Tree.
        (rn_leaf*)rn_insert(node,(void*)keyNode, ip->ipv6->rt_tables);

        if (DUAL_IP_DEBUG)
        {
            printf("After adding default route \n");
            Ipv6PrintForwardingTable(node);
        }
    }
    //initialize routing protocols type for this interface
    TunnelSetRoutingProtocolType(node, interfaceIndex);
}

// /**
// API                 :: Initialize6to4Tunnel
// LAYER               :: Network
// PURPOSE             :: parse and initialize 6to4 tunnels.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + nodeInput          : const NodeInput*.
// RETURN              :: void
// **/
void Initialize6to4Tunnel(Node* node, const NodeInput* nodeInput)
{
    int i = 0;
    NodeAddress InterfaceAddress;
    NodeId nodeId;
    BOOL isNodeId;
    int interfaceIndex;

    // Check each user's configuration parameters
    for (i = 0; i < nodeInput->numLines; i++)
    {
        if (strcmp(
            nodeInput->variableNames[i], "IPv6-ENABLE-6to4-TUNNELING") == 0)
        {
            if (strcmp(nodeInput->values[i], "YES") == 0)
            {
                char* token = NULL;
                char* next = NULL;
                char delims[] = " ,\t";
                char iotoken[MAX_STRING_LENGTH];

                token = IO_GetDelimitedToken(iotoken,
                                             nodeInput->qualifiers[i],
                                             delims,
                                             &next);
                while (token)
                {
                    // Get interface address.
                    IO_ParseNodeIdOrHostAddress(
                            token,
                            &InterfaceAddress,
                            &isNodeId);

                    if (isNodeId)
                    {
                        char buf[MAX_STRING_LENGTH];

                        sprintf(buf, "IPv6-ENABLE-6to4-TUNNELING parameter "
                            "must have an IP address as its qualifier.\n");

                        ERROR_ReportError(buf);
                    }
                    nodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                    node, InterfaceAddress);

                    interfaceIndex =
                            MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                                    node, InterfaceAddress);

                    if (node->nodeId == nodeId)
                    {
                        TunnelInfoType* tunneldata = (TunnelInfoType*)
                                        MEM_malloc(sizeof(TunnelInfoType));

                        memset(tunneldata, 0, sizeof(TunnelInfoType));

                        tunneldata->originalIntIndex = interfaceIndex;
                        SetIPv4AddressInfo(&tunneldata->tunnelStartAddress,
                                           InterfaceAddress);
                        SetIPv4AddressInfo(&tunneldata->tunnelEndAddress,
                                           ANY_ADDRESS);
                        tunneldata->tunnelType = SixToFour_TUNNEL;

                        NetworkDataIp* ip =
                                (NetworkDataIp*)node->networkData.networkVar;

                        if (ip->interfaceInfo[interfaceIndex]->
                                                 InterfacetunnelInfo == NULL)
                        {
                            // Initialize tunnnel-list for first tunnel
                            //  configured on this interface
                            ListInit(
                                node,
                                &ip->interfaceInfo[interfaceIndex]->
                                                        InterfacetunnelInfo);
                        }
                        // Insert into the tunnel-list of this interface
                        ListInsert(
                          node,
                          ip->interfaceInfo[interfaceIndex]->
                                                         InterfacetunnelInfo,
                          node->getNodeTime(),
                          (void *)tunneldata);

                        //add 6to4 interface
                        TunnelAddVirtualInterface(node,
                                                  tunneldata,
                                                  interfaceIndex);

                        //Disable IPV6 stack on the 6to4 interface
                        MEM_free(ip->interfaceInfo[interfaceIndex]->
                                                          ipv6InterfaceInfo);
                        ip->interfaceInfo[interfaceIndex]->
                                                    ipv6InterfaceInfo = NULL;
                        ip->interfaceInfo[interfaceIndex]->
                                                interfaceType = NETWORK_IPV4;
                    }

                    // fetching next IP address, if any
                    token = IO_GetDelimitedToken(iotoken,
                                                 next,
                                                 delims,
                                                 &next);
                }// end of while (token != NULL)
            }
        }
    }
}

// /**
// API                 :: getTunnelPropDelay
// LAYER               :: Network
// PURPOSE             :: Get Propagaion delay for the tunnel.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: clocktype
// **/
clocktype getTunnelPropDelay(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                    ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    return tunneldata->propagationDelay;
}

// /**
// API                 :: TunnelInterfaceIsEnabled
// LAYER               :: Network
// PURPOSE             :: To check the tunnel is enabled or not?
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: BOOL
// **/
BOOL TunnelInterfaceIsEnabled(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                    ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    return NetworkIpInterfaceIsEnabled(node, tunneldata->originalIntIndex);
}

// /**
// API                 :: getTunnelBandwidth
// LAYER               :: Network
// PURPOSE             :: Get Bandwidth of the tunnel.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: Int64
// **/
Int64 getTunnelBandwidth(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                    ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    return tunneldata->tunnelBandwidth;
}

// /**
// API                 :: TunnelSetRoutingProtocolType
// LAYER               :: Network
// PURPOSE             :: Borrow Routing Protocol type from a interface.
// PARAMETERS          ::
// + node               : Node*   : node structure pointer.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: void
// **/
void TunnelSetRoutingProtocolType(Node* node, int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                    ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    IpInterfaceInfoType* borrowedinterfaceInfo =
                            ip->interfaceInfo[tunneldata->borrowedIntIndex];

    if (tunneldata ->tunnelType == IPv6_TUNNEL)
    {
        ip->interfaceInfo[interfaceIndex]->routingProtocolType =
                                borrowedinterfaceInfo->routingProtocolType;

        ip->interfaceInfo[interfaceIndex]->multicastProtocolType =
                                borrowedinterfaceInfo->multicastProtocolType;
    }
    else if (tunneldata ->tunnelType == IPv4_TUNNEL)
    {
        IPv6InterfaceInfo *interfaceInfo1;
        IPv6InterfaceInfo *interfaceInfo2;
        interfaceInfo1 = ip->interfaceInfo[interfaceIndex]
                        ->ipv6InterfaceInfo;

        interfaceInfo2 = borrowedinterfaceInfo->ipv6InterfaceInfo;

        interfaceInfo1->routingProtocolType =
                                        interfaceInfo2->routingProtocolType;
    }
    else if (tunneldata ->tunnelType == SixToFour_TUNNEL)
    {
        ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo
            ->routingProtocolType = ROUTING_PROTOCOL_NONE;
    }
    else
    {
       ERROR_Assert(FALSE, "Invalid Tunnel Type");
    }
}

// /**
// FUNCTION            :: TunnelInit
// LAYER               :: Network
// PURPOSE             :: Tunnel Initialization.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + nodeInput          : const NodeInput* : Node input.
// RETURN              :: None
// **/
void TunnelInit(Node* node, const NodeInput* nodeInput)
{
    //parse and initialize 6to4 tunnels
    Initialize6to4Tunnel(node, nodeInput);

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    NodeInput tunnelInput;
    BOOL wasFound = FALSE;
    int lineNum;
    char delims[] = "{,} \n\t";

    IO_ReadCachedFile(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TUNNEL-CONFIG-FILE",
        &wasFound,
        &tunnelInput);

    if (wasFound == TRUE)
    {
        // tunnel is configured on this node
        for (lineNum = 0; lineNum < tunnelInput.numLines; lineNum++)
        {
            char nodeIdStr[MAX_STRING_LENGTH];
            char tunnelTypeStr[MAX_STRING_LENGTH];
            char tunnelIdStr[MAX_STRING_LENGTH];
            char tunnelStartAddressStr[MAX_STRING_LENGTH];
            char tunnelInterfaceAddressStr[MAX_STRING_LENGTH];
            char tunnelEndAddressStr[MAX_STRING_LENGTH];

            char *paramStr = (char*)MEM_malloc(MAX_STRING_LENGTH);
            char valueStr[MAX_STRING_LENGTH] = {0};

            int nodeId;
            int interfaceID;
            char *next = NULL;
            int intIndex = ANY_INTERFACE;
            BOOL isNext = FALSE;
            BOOL isTunnelInterfaceAddress = FALSE;
//support fix for ticket#1087 start
            BOOL isInterfaceId = FALSE;
//support fix for ticket#1087 end
            // read tunnel info;
            IO_GetDelimitedToken(
                nodeIdStr, tunnelInput.inputStrings[lineNum], delims, &next);

            nodeId = atoi(nodeIdStr);

            if (node->nodeId != (unsigned int)nodeId)
            {
                continue;
            }

            TunnelInfoType* tunneldata = (TunnelInfoType*)MEM_malloc(
                                       sizeof(TunnelInfoType));

            memset(tunneldata, 0, sizeof(TunnelInfoType));

            IO_GetDelimitedToken(tunnelTypeStr, next, delims, &next);

            if (strcmp(tunnelTypeStr, "v4-tunnel") == 0)
            {
                tunneldata->tunnelType = IPv4_TUNNEL;
            }
            else if (strcmp(tunnelTypeStr, "v6-tunnel") == 0)
            {
                tunneldata->tunnelType = IPv6_TUNNEL;
            }
            else
            {
                // report error for unknown dualIp tunnel
                ERROR_ReportError("Tunnels other than IPv6 and IPv4 are not"
                    " supported\n");
            }

            IO_GetDelimitedToken(tunnelIdStr, next, delims, &next);

            IO_GetDelimitedToken(tunnelStartAddressStr, next, delims, &next);

//support fix for ticket#1087 start
            //checking for interface id
            if (strchr(tunnelStartAddressStr, '.')
                || strchr(tunnelStartAddressStr, ':'))
            {
                //Either v4 or v6 address
                isInterfaceId = FALSE;
            }
            else
            {
                //seems interface id
                isInterfaceId = TRUE;
            }
//support fix for ticket#1087 end
            IO_GetDelimitedToken(tunnelEndAddressStr, next, delims, &next);

            if (tunnelEndAddressStr[0] == '[')
            {
                strcpy (tunnelInterfaceAddressStr, tunnelEndAddressStr);
                isTunnelInterfaceAddress = TRUE;

                IO_GetDelimitedToken(
                    tunnelEndAddressStr, next, delims, &next);
            }

            if (IO_GetDelimitedToken(paramStr, next, delims, &next) != NULL)
            {
                if (paramStr[0] == '[')
                {
                    if (IO_GetDelimitedToken(paramStr, next, delims, &next)
                                    != NULL)
                    {
                        isNext = TRUE;
                    }
                    else
                    {
                        isNext = FALSE;
                    }
                }
                else
                {
                    isNext = TRUE;
                }
            }

            while (isNext)
            {
                if (IO_GetDelimitedToken(valueStr, next, delims, &next)
                                == NULL)
                {
                    ERROR_ReportError("Configuration Error in tunnel file");
                }
                if (!strcmp(paramStr, "INHERIT-FROM"))
                {
                    intIndex = atoi(valueStr);
                }
                else if (!strcmp(paramStr, "BANDWIDTH"))
                {
                    tunneldata->tunnelBandwidth = atoi(valueStr);
                }
                else if (!strcmp(paramStr, "PROPOGATION-DELAY"))
                {
                    tunneldata->propagationDelay = atoi(valueStr);
                }
                else
                {
                    ERROR_ReportError("Configuration Error in tunnel file");
                }

                if (IO_GetDelimitedToken(paramStr, next, delims, &next)
                            == NULL)
                {
                    isNext = FALSE;
                }
            }

            if (tunneldata->tunnelType == IPv4_TUNNEL)
            {
                // configure v4-tunnel
                NodeAddress tunnelStartAddress;
                NodeAddress tunnelEndAddress;
                int numHostBits;
                BOOL isNodeId;

//support fix for ticket#1087 start
                if (isInterfaceId)
                {
                    interfaceID = atoi(tunnelStartAddressStr);

                    if (interfaceID >= node->numberInterfaces
                        || interfaceID < 0)
                    {
                        char buf[MAX_STRING_LENGTH];

                        sprintf(buf,"\nTunnel starting interface id %d is "
                            "not bound to any interface of node %u",
                            interfaceID,
                            node->nodeId);
                        // report error
                        ERROR_ReportError(buf);
                    }

                    Address startAddress;
                    memset(&startAddress, 0, sizeof(Address));

                    if (NetworkIpIsUnnumberedInterface(node,interfaceID))
                    {
                        //getting address for unnumbered interface
                        startAddress.interfaceAddr.ipv4 =
                            NetworkIpGetIpAddressForUnnumberedInterface(node,
                                                                interfaceID);

                        if (startAddress.interfaceAddr.ipv4 != ANY_ADDRESS)
                        {
                            startAddress.networkType = NETWORK_IPV4;
                        }
                        else
                        {
                            startAddress.networkType = NETWORK_INVALID;
                        }
                    }
                    else
                    {
                        startAddress =
                            MAPPING_GetInterfaceAddressForInterface(node,
                                                        node->nodeId,
                                                        NETWORK_IPV4,
                                                        interfaceID);
                    }

                    if (startAddress.networkType == NETWORK_INVALID)
                    {
                        char buf[MAX_STRING_LENGTH];

                        sprintf(buf,"\nTunnel starting interface id %d is "
                            "not bound to any IPv4 interface of node %u",
                            interfaceID,
                            node->nodeId);
                        // report error
                        ERROR_ReportError(buf);
                    }
                    else
                    {
                        memcpy(&tunnelStartAddress,
                               &startAddress.interfaceAddr.ipv4,
                               sizeof(NodeAddress));
                    }
                }
                else
                {
                IO_ParseNodeIdHostOrNetworkAddress(
                    tunnelStartAddressStr,
                    &tunnelStartAddress,
                    &numHostBits,
                    &isNodeId);

                interfaceID = NetworkIpGetInterfaceIndexFromAddress(
                                node,
                                tunnelStartAddress);

                if (interfaceID == ANY_INTERFACE)
                {
                    char buf[MAX_STRING_LENGTH];

                    sprintf(buf,"\nTunnel starting address %s is not"
                        " bound to any interface of node %u",
                        tunnelStartAddressStr,
                        node->nodeId);
                    // report error
                    ERROR_ReportError(buf);
                }
                }
//support fix for ticket#1087 end
                if (ip->interfaceInfo[interfaceID]->InterfacetunnelInfo ==
                           NULL)
                {
                    // Initialize tunnnel-list for first tunnel configured on
                    // this interface
                    ListInit(
                       node,
                       &ip->interfaceInfo[interfaceID]->InterfacetunnelInfo);
                }

                // get tunnel end IPv4 address
                IO_ParseNodeIdHostOrNetworkAddress(
                    tunnelEndAddressStr,
                    &tunnelEndAddress,
                    &numHostBits,
                    &isNodeId);

                tunneldata->originalIntIndex = interfaceID;

                //set generic address from IPv4 address.
                MAPPING_SetAddress(NETWORK_IPV4,
                    &tunneldata->tunnelStartAddress, &tunnelStartAddress);

                //set generic address from IPv4 address.
                MAPPING_SetAddress(NETWORK_IPV4,
                    &tunneldata->tunnelEndAddress, &tunnelEndAddress);

                if (intIndex == ANY_INTERFACE)
                {
                    BOOL isRoutingEnabled = FALSE;

                    if ((ip->interfaceInfo[interfaceID]->interfaceType ==
                        NETWORK_IPV4)
                     || IsIPV6RoutingEnabledOnInterface(node, interfaceID)
                                                            == FALSE)
                    {
                        // determine the IPv6-interface of a node having the
                        // lowest interface index.
                        int i;
                        for (i = 0; i < node->numberInterfaces; i++)
                        {
                            if (ip->interfaceInfo[i]->interfaceType ==
                                            NETWORK_IPV6
                                || ip->interfaceInfo[i]->interfaceType ==
                                            NETWORK_DUAL)
                            {
                                intIndex = i;
                                if (IsIPV6RoutingEnabledOnInterface(node, i))
                                {
                                    isRoutingEnabled = TRUE;
                                    break;
                                }
                            }
                        }
                    }
                    if ((isRoutingEnabled == FALSE)
                        && ip->interfaceInfo[interfaceID]->interfaceType !=
                        NETWORK_IPV4)
                    {
                        intIndex = interfaceID;
                    }
                }
                else
                {
                    ERROR_Assert((ip->interfaceInfo[intIndex]->interfaceType
                                                            == NETWORK_IPV6
                                || ip->interfaceInfo[intIndex]->interfaceType
                                                            == NETWORK_DUAL),
                                "V6 virtual interface can not"
                                 " inherit from non IPv6 interface");
                }
            }
            else
            {
                // configure v6-tunnel
                in6_addr tunnelStartAddress;
                in6_addr tunnelEndAddress;
                int numHostBits;
                unsigned int isNodeId;

//support fix for ticket#1087 start
                if (isInterfaceId)
                {
                    interfaceID = atoi(tunnelStartAddressStr);

                    if (interfaceID >= node->numberInterfaces
                        || interfaceID < 0)
                    {
                        char buf[MAX_STRING_LENGTH];

                        sprintf(buf,"\nTunnel starting interface id %d is "
                            "not bound to any interface of node %u",
                            interfaceID,
                            node->nodeId);
                        // report error
                        ERROR_ReportError(buf);
                    }

                    Address startAddress =
                        MAPPING_GetInterfaceAddressForInterface(node,
                                                    node->nodeId,
                                                    NETWORK_IPV6,
                                                    interfaceID);

                    if (startAddress.networkType == NETWORK_INVALID)
                    {
                        char buf[MAX_STRING_LENGTH];

                        sprintf(buf,"\nTunnel starting interface id %d is "
                            "not bound to any IPv6 interface of node %u",
                            interfaceID,
                            node->nodeId);
                        // report error
                        ERROR_ReportError(buf);
                    }
                    else
                    {
                        memcpy(&tunnelStartAddress,
                               &startAddress.interfaceAddr.ipv6,
                               sizeof(in6_addr));
                    }
                }
                else
                {
                IO_ParseNodeIdHostOrNetworkAddress(
                    tunnelStartAddressStr,
                    &tunnelStartAddress,
                    &numHostBits,
                    &isNodeId);

                interfaceID = Ipv6GetInterfaceIndexFromAddress(node,
                                  &tunnelStartAddress);

                if (interfaceID == ANY_INTERFACE)
                {
                    char buf[MAX_STRING_LENGTH];

                    sprintf(buf,"\nTunnel starting address %s is not"
                        " bound to any interface of node %u",
                        tunnelStartAddressStr,
                        node->nodeId);

                    // report error
                    ERROR_ReportError(buf);
                }
                }
//support fix for ticket#1087 end
                if (ip->interfaceInfo[interfaceID]->InterfacetunnelInfo ==
                            NULL)
                {
                    // Initialize tunnnel-list for first tunnel configured on
                    // this interface
                    ListInit(
                       node,
                       &ip->interfaceInfo[interfaceID]->InterfacetunnelInfo);
                }

                // get tunnel end IPv6 address
                IO_ParseNodeIdHostOrNetworkAddress(
                    tunnelEndAddressStr,
                    &tunnelEndAddress,
                    &numHostBits,
                    &isNodeId);

                tunneldata->originalIntIndex = interfaceID;

                //set generic address from IPv6 address.
                MAPPING_SetAddress(NETWORK_IPV6,
                    &tunneldata->tunnelStartAddress, &tunnelStartAddress);

                //set generic address from IPv6 address.
                MAPPING_SetAddress(NETWORK_IPV6,
                    &tunneldata->tunnelEndAddress, &tunnelEndAddress);

                if (intIndex == ANY_INTERFACE)
                {
                    BOOL isRoutingEnabled = FALSE;

                    if ((ip->interfaceInfo[interfaceID]->interfaceType ==
                                                            NETWORK_IPV6)
                      || ((IsIPV4RoutingEnabledOnInterface(node, interfaceID)
                                                            == FALSE)
                            && (IsIPV4MulticastEnabledOnInterface(node,
                                        interfaceID) == FALSE)))
                    {
                        // determine the IPv4-interface of a node having the
                        // lowest interface index.
                        int i;
                        for (i = 0; i < node->numberInterfaces; i++)
                        {
                            if (ip->interfaceInfo[i]->interfaceType ==
                                            NETWORK_IPV4
                                || ip->interfaceInfo[i]->interfaceType ==
                                            NETWORK_DUAL)
                            {
                                intIndex = i;
                                if (IsIPV4RoutingEnabledOnInterface(node, i))
                                {
                                    isRoutingEnabled = TRUE;
                                    break;
                                }
                            }
                        }
                        if (isRoutingEnabled == FALSE)
                        {
                            for (i = 0; i < node->numberInterfaces; i++)
                            {
                                if (ip->interfaceInfo[i]->interfaceType ==
                                                NETWORK_IPV4
                                    || ip->interfaceInfo[i]->interfaceType ==
                                                NETWORK_DUAL)
                                {
                                     intIndex = i;
                                     if (IsIPV4MulticastEnabledOnInterface(
                                                        node, i))
                                     {
                                         isRoutingEnabled = TRUE;
                                         break;
                                     }
                                }
                            }
                        }
                    }
                    if ((isRoutingEnabled == FALSE)
                        && ip->interfaceInfo[interfaceID]->interfaceType !=
                        NETWORK_IPV6)
                    {
                        intIndex = interfaceID;
                    }
                }
                else
                {
                    ERROR_Assert((ip->interfaceInfo[intIndex]->interfaceType
                                                            == NETWORK_IPV4
                                || ip->interfaceInfo[intIndex]->interfaceType
                                                            == NETWORK_DUAL),
                                "V4 virtual interface can not"
                                 " inherit from non IPv4 interface");
                }
            }

            // Insert into the tunnel-list of this interface
            ListInsert(
                node,
                ip->interfaceInfo[interfaceID]->InterfacetunnelInfo,
                node->getNodeTime(),
                (void *)tunneldata);

            if (tunneldata->tunnelBandwidth == 0)
            {
                tunneldata->tunnelBandwidth =
                                    node->macData[interfaceID]->bandwidth;
            }
            if (tunneldata->propagationDelay == 0)
            {
                tunneldata->propagationDelay =
                                    node->macData[interfaceID]->propDelay;
            }

            ERROR_Assert(intIndex >= 0 && intIndex < node->numberInterfaces,
            "INHERIT-FROM interface index is either < 0 or greater than"
            "the number of interface at node");

            TunnelAddVirtualInterface(node, tunneldata, intIndex);

            if (isTunnelInterfaceAddress)
            {
                // For IO_GetDelimitedToken
                char* next;
                char delims[] = {"]"};
                char iotoken[MAX_STRING_LENGTH];
                IO_GetDelimitedToken(iotoken,
                                  &tunnelInterfaceAddressStr[1],
                                  delims,
                                  &next);

                NetworkDataIp* ip =
                    (NetworkDataIp *) node->networkData.networkVar;
                int interfaceIndex = node->numberInterfaces - 1;

                if (tunneldata->tunnelType == IPv4_TUNNEL)
                {
                    in6_addr tunnelInterfaceAddress;

                    int numHostBits;
                    unsigned int isNodeId;

                    IO_ParseNodeIdHostOrNetworkAddress(
                        iotoken,
                        &tunnelInterfaceAddress,
                        &numHostBits,
                        &isNodeId);

                    ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo
                        ->globalAddr = tunnelInterfaceAddress;

                    ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo
                        ->prefixLen = 0;

                }
                else
                {
                    NodeAddress tunnelInterfaceAddress;
                    int numHostBits;
                    BOOL isNodeId;

                    IO_ParseNodeIdHostOrNetworkAddress(
                        iotoken,
                        &tunnelInterfaceAddress,
                        &numHostBits,
                        &isNodeId);

                    ip->interfaceInfo[interfaceIndex]->ipAddress =
                                                    tunnelInterfaceAddress;

                    ip->interfaceInfo[interfaceIndex]->numHostBits = 0;
                }
            }
        }
    }
}

// /**
// API                 :: GetIPv4addressFrom6to4Address
// LAYER               :: Network
// PURPOSE             :: retrieve ipv4 address from 6to4 ipv6 address.
// PARAMETERS          ::
// + ip6_dst           :: in6_addr*   : 6to4 ipv6 address.
// RETURN              :: NodeAddress : ipv4 address
// **/
NodeAddress GetIPv4addressFrom6to4Address(in6_addr* ip6_dst)
{
    NodeAddress address = 0;
    int i = 0;

    for (; i < 4; i++)
    {
        address = address << 8;
        address += ip6_dst->s6_addr[i + 2];
    }

    if (DUAL_IP_DEBUG)
    {
        char ipv4AddrStr[MAX_STRING_LENGTH];
        char IPV6AddrStr[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(address, ipv4AddrStr);
        IO_ConvertIpAddressToString(ip6_dst, IPV6AddrStr);

        printf("%s (6to4 address) => %s (IPv4 address)\n",
            IPV6AddrStr,
            ipv4AddrStr);
    }

    return address;
}

// /**
// API                 :: TunnelSendIPv6Pkt
// LAYER               :: Network
// PURPOSE             :: Encapsulates IPv6 pkt within IPv4 pkt to
//                        route it through IPv4-tunnel.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + msg                : Message* : Ptr to Messasge containing
//                                   IPv6 pkt to be encapsulated.
// +imo                 : ip_moptions *imo: Multicast Option Pointer.
// +interfaceID         : int interfaceID : Index of the concerned Interface
// RETURN              :: BOOL
// **/
BOOL TunnelSendIPv6Pkt(
    Node* node,
    Message* msg,
    ip_moptions* imo,
    int interfaceID)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                        ip->interfaceInfo[interfaceID]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    ip6_hdr* ip6hdr = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    NodeAddress srcAddr = tunneldata->tunnelStartAddress.interfaceAddr.ipv4;
    NodeAddress destAddr = tunneldata->tunnelEndAddress.interfaceAddr.ipv4;

    if (!NetworkIpInterfaceIsEnabled(node, tunneldata->originalIntIndex))
    {
        // this interface is down
        MacHWAddress macAddr;
        macAddr.hwLength = MAC_IPV4_LINKADDRESS_LENGTH;
        macAddr.hwType = IPV4_LINKADDRESS;
        macAddr.byte = (unsigned char*)MEM_malloc(macAddr.hwLength);
        memcpy(macAddr.byte, &destAddr, MAC_IPV4_LINKADDRESS_LENGTH);

        Ipv6NotificationOfPacketDrop(
            node,
            msg,
            macAddr,
            interfaceID);

        // increment stats for ipv6 pkt dropped
        tunneldata->tunnelStats.numPktDroppedTunnelFailure++;

        return FALSE;
    }

    if (IS_MULTIADDR6(ip6hdr->ip6_dst))
    {
        if (imo != NULL)
        {
            // multicast options is provided
            ip6hdr->ip6_hlim = (unsigned char) imo->imo_multicast_ttl;
        }
        else
        {
            // else do nothing for now else expanding ttl 
            //will not work for reactive protocols
            //ip6hdr->ip6_hlim = IP_DEFAULT_MULTICAST_TTL;
        }

        // Multicasts with a time-to-live of zero may be looped-
        // back, above, but must not be transmitted on a network.
        if (ip6hdr->ip6_hlim == 0)
        {
            //Trace drop
            ActionData acnData;
            acnData.actionType = DROP;
            acnData.actionComment = DROP_HOP_LIMIT_ZERO;
            TRACE_PrintTrace(node,
                            msg,
                            TRACE_NETWORK_LAYER,PACKET_IN,
                            &acnData);

            MESSAGE_Free(node, msg);
            return FALSE;
        }

        // increment stats for ipv6 pkt encapsulation
        tunneldata->tunnelStats.numMulticastSent++;
    }
    else
    {
        if (tunneldata->tunnelType == SixToFour_TUNNEL)
        {
            // Extract IPv4 address from the 6to4 address
            destAddr = GetIPv4addressFrom6to4Address(&ip6hdr->ip6_dst);
        }

        // increment stats for ipv6 pkt encapsulation
        tunneldata->tunnelStats.numUnicstSent++;
    }

    NetworkIpSendRawMessage(node,
        MESSAGE_Duplicate(node, msg),
        srcAddr,
        destAddr,
        tunneldata->originalIntIndex,
        ip6_hdrGetClass(ip6hdr->ipv6HdrVcf),
        IPPROTO_IPV6,
        IPDEFTTL);

    if (DUAL_IP_DEBUG)
    {
        char ipv6srcAddrStr[MAX_STRING_LENGTH];
        char ipv6destAddrStr[MAX_STRING_LENGTH];
        char tunnelEndAddrStr[MAX_STRING_LENGTH];

        const char* tunnelTypeStr = TunnelGetTunnelTypeStr(tunneldata->tunnelType);

        IO_ConvertIpAddressToString(&ip6hdr->ip6_src,
            ipv6srcAddrStr);
        IO_ConvertIpAddressToString(&ip6hdr->ip6_dst,
            ipv6destAddrStr);

        IO_ConvertIpAddressToString(destAddr, tunnelEndAddrStr);

        printf("Node %d: interfaceIndex %d has sent an"
            " IPv6 pkt with srcAddr= %s and destAddr= %s\n"
            "through a %s with tunnel endpoint %s",
            node->nodeId,
            interfaceID,
            ipv6srcAddrStr,
            ipv6destAddrStr,
            tunnelTypeStr,
            tunnelEndAddrStr);
    }

    MESSAGE_Free(node, msg);
    return TRUE;
}

// /**
// API                 :: TunnelSendIPv4Pkt
// LAYER               :: Network
// PURPOSE             :: Encapsulates IPv4 pkt within IPv6 pkt to
//                        route it through IPv6-tunnel.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + msg                : Message* : Ptr to Messasge containing
//                                   IPv6 pkt to be encapsulated.
// + outgoingInterface  : int          : Index of outgoing interface.
// + nextHop            : NodeAddress  : Next hop IP address.
// RETURN              :: BOOL
// **/
BOOL TunnelSendIPv4Pkt (
    Node *node,
    Message *msg,
    int outgoingInterface,
    NodeAddress nextHop)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
        ip->interfaceInfo[outgoingInterface]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    in6_addr sourceAddress;
    in6_addr destAddress;
    int outgoingInterfaceIndex;
    NodeAddress outgoingBroadcastAddr;

    sourceAddress = GetIPv6Address(tunneldata->tunnelStartAddress);
    destAddress = GetIPv6Address(tunneldata->tunnelEndAddress);

    if (!NetworkIpInterfaceIsEnabled(node, tunneldata->originalIntIndex))
    {
        // this outgoing interface is down
        NetworkIpNotificationOfPacketDrop(
            node,
            msg,
            nextHop,
            outgoingInterface);

        // increment stats for ipv6 pkt dropped
        tunneldata->tunnelStats.numPktDroppedTunnelFailure++;

        return FALSE;
    }

    // call IPv6 layer's packet sending function to encapsulate the
    // the IPv4 packet and route it to the tunnel end node.

    Ipv6SendRawMessage(
        node,
        MESSAGE_Duplicate(node, msg),
        sourceAddress,
        destAddress,
        tunneldata->originalIntIndex,
        IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len),
        IPPROTO_IPV6,
        IPDEFTTL);

    if (DUAL_IP_DEBUG)
    {
        char ipv4srcAddrStr[MAX_STRING_LENGTH];
        char ipv4destAddrStr[MAX_STRING_LENGTH];
        char tunnelEndAddrStr[MAX_STRING_LENGTH];

        const char* tunnelTypeStr = TunnelGetTunnelTypeStr(tunneldata->tunnelType);

        IO_ConvertIpAddressToString(ipHeader->ip_src,
            ipv4srcAddrStr);
        IO_ConvertIpAddressToString(ipHeader->ip_dst,
            ipv4destAddrStr);
        IO_ConvertIpAddressToString(&destAddress,
            tunnelEndAddrStr);

        printf("Node %d: interfaceIndex %d has sent an"
            " IPv4 pkt with srcAddr= %s and destAddr= %s\n"
            "through a %s with tunnel endpoint %s",
            node->nodeId,
            outgoingInterface,
            ipv4srcAddrStr,
            ipv4destAddrStr,
            tunnelTypeStr,
            tunnelEndAddrStr);
    }

    if (NetworkIpIsMulticastAddress(node, nextHop))
    {
        // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numMulticastSent++;
    }
    else if (IsOutgoingBroadcast(
            node,
            nextHop,
            &outgoingInterfaceIndex,
            &outgoingBroadcastAddr))
    {
        // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numBroadcastSent++;
    }
    else
    {
        // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numUnicstSent++;
    }

    MESSAGE_Free(node, msg);
    return TRUE;
}

// /**
// API                 :: TunnelHandleIPv6Pkt
// LAYER               :: Network
// PURPOSE             :: Decapsulates IPv6 pkt from IPv4 pkt
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + msg                : Message* : Ptr to Messasge containing
//                                   IPv6 pkt encapsulated within IPv4 pkt.
// +interfaceIndex      : int : Interface Index
// RETURN              :: None
// **/
void TunnelHandleIPv6Pkt(
    Node *node,
    Message* msg,
    int interfaceIndex)
{
    NodeAddress sourceAddress;
    NodeAddress destinationAddress;
    unsigned char ipProtocolNumber;
    unsigned ttl =0;
    TosType priority;

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];
    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    int tunnelInterface = ANY_INTERFACE;

    if (interfaceInfo->InterfacetunnelInfo == NULL)
    {
        tunnelInterface = NetworkIpGetInterfaceIndexFromAddress (node,
                                                           ipHeader->ip_dst);
        if (tunnelInterface == ANY_INTERFACE)
        {
            //if an IPV4 interface has received a encapsulated ipv6 packet
            // simply drop it.
            MESSAGE_Free(node, msg);
            return;
        }
        else
        {
            interfaceInfo = ip->interfaceInfo[tunnelInterface];
            if (interfaceInfo->InterfacetunnelInfo == NULL)
            {
               //if an IPV4 interface has received a encapsulated ipv6 packet
               // simply drop it.
               MESSAGE_Free(node, msg);
               return;
            }
        }
    }

    ListItem* tunnelPtr = interfaceInfo->InterfacetunnelInfo->first;

    TunnelInfoType* tunneldata = NULL;

    // Check whether any tunnel is configured on this interface
    // with tunnel-end point as the source of the packet.
    while (tunnelPtr)
    {
        tunneldata = (TunnelInfoType*)tunnelPtr->data;

        if (tunneldata->tunnelEndAddress.interfaceAddr.ipv4 ==
            ipHeader->ip_src)
        {
            break;
        }

        tunnelPtr = tunnelPtr->next;
    }

    if (tunnelPtr == NULL)
    {
        // Check whether any 6to4 tunnel is configured on this interface
        tunnelPtr = interfaceInfo->InterfacetunnelInfo->first;

        while (tunnelPtr)
        {
            tunneldata = (TunnelInfoType*)tunnelPtr->data;

            if ((tunneldata->tunnelStartAddress.interfaceAddr.ipv4 ==
                                                        ipHeader->ip_dst)
                && tunneldata->tunnelType == SixToFour_TUNNEL)
            {
                break;
            }

            tunnelPtr = tunnelPtr->next;
        }
    }

    if (tunnelPtr == NULL)
    {
       //if none of the tunnel's end address matches with the source address
       // and no 6to4 tunnel is configured, simply drop it.
       MESSAGE_Free(node, msg);
       return;
    }

    NetworkIpRemoveIpHeader(
                            node,
                            msg,
                            &sourceAddress,
                            &destinationAddress,
                            &priority,
                            &ipProtocolNumber,
                            &ttl);

    // Send decapsulated IPv6 pkt to IPv6 layer's pkt
    // receiving function.
    ip6_hdr* ipv6Header = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    if (IS_MULTIADDR6(ipv6Header->ip6_dst))
    {
        // increment stats for ipv6 pkt encapsulation
        tunneldata->tunnelStats.numMulticastRecv++;
    }
    else
    {
        tunneldata->tunnelStats.numUnicstRecv++;
    }

    if (DUAL_IP_DEBUG)
    {
        char ipv6srcAddrStr[MAX_STRING_LENGTH];
        char ipv6destAddrStr[MAX_STRING_LENGTH];
        char tunnelEndAddrStr[MAX_STRING_LENGTH];

        const char* tunnelTypeStr = TunnelGetTunnelTypeStr(tunneldata->tunnelType);

        IO_ConvertIpAddressToString(&ipv6Header->ip6_src,
            ipv6srcAddrStr);
        IO_ConvertIpAddressToString(&ipv6Header->ip6_dst,
            ipv6destAddrStr);
        IO_ConvertIpAddressToString(sourceAddress, tunnelEndAddrStr);

        printf("Node %d: interfaceIndex %d has received a encapsulated"
            " IPv6 pkt with srcAddr= %s and destAddr= %s\n"
            "through a %s with tunnel endpoint %s",
            node->nodeId,
            interfaceIndex,
            ipv6srcAddrStr,
            ipv6destAddrStr,
            tunnelTypeStr,
            tunnelEndAddrStr);
    }

    MacHWAddress macAddr;
    macAddr.hwLength = MAC_IPV4_LINKADDRESS_LENGTH;
    macAddr.hwType = IPV4_LINKADDRESS;
    macAddr.byte = (unsigned char*)MEM_malloc(macAddr.hwLength);
    memcpy(macAddr.byte, &sourceAddress, MAC_IPV4_LINKADDRESS_LENGTH);

    ip6_input(node, msg, 0, tunneldata->pseudoIntIndex, &macAddr);

    return;
}

// /**
// API                 :: TunnelHandleIPv4Pkt
// LAYER               :: Network
// PURPOSE             :: Decapsulates IPv4 pkt from IPv6 pkt and send
//                        it to the IPv4 layer's pkt-receiving function.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + msg                : Message* : Ptr to Messasge containing
//                                   IPv4 pkt encapsulated within IPv6 pkt.
// +interfaceIndex      : int : Interface Index
// RETURN              :: None
// **/
void TunnelHandleIPv4Pkt(
    Node *node,
    Message* msg,
    int interfaceIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    ip6_hdr *ipv6Header = (ip6_hdr*) MESSAGE_ReturnPacket(msg);

    int tunnelInterface = ANY_INTERFACE;

    if (interfaceInfo->InterfacetunnelInfo == NULL)
    {
        tunnelInterface = Ipv6GetInterfaceIndexFromAddress(node,
                                                       &ipv6Header->ip6_dst);
        if (tunnelInterface == ANY_INTERFACE)
        {
           //if an IPV6 interface has received a encapsulated ipv4 packet
           // simply drop it.
            MESSAGE_Free(node, msg);
            return;
        }
        else
        {
            interfaceInfo = ip->interfaceInfo[tunnelInterface];

            if (interfaceInfo->InterfacetunnelInfo == NULL)
            {
               //if an IPV6 interface has received a encapsulated ipv4 packet
               // simply drop it.
                MESSAGE_Free(node, msg);
                return;
            }
        }
    }
    ListItem* tunnelPtr = interfaceInfo->InterfacetunnelInfo->first;

    TunnelInfoType* tunneldata = NULL;



    // Check whether any tunnel is configured on this interface
    // with tunnel-end point as the source of the packet.
    while (tunnelPtr)
    {
        tunneldata = (TunnelInfoType*)tunnelPtr->data;

        if (SAME_ADDR6(tunneldata->tunnelEndAddress.interfaceAddr.ipv6,
            ipv6Header->ip6_src))
        {
            break;
        }

        tunnelPtr = tunnelPtr->next;
    }

    if (tunnelPtr == NULL)
    {
       //if none of the tunnel's end address matches with the source address
       // simply drop it.
       MESSAGE_Free(node, msg);
       return;
    }

    Address sourceAddress;
    Address destinationAddress;
    TosType priority;
    unsigned char protocol;
    unsigned hLim;

    //trace recd pkt
     ActionData acnData;
     acnData.actionType = RECV;
     acnData.actionComment = NO_COMMENT;
     TRACE_PrintTrace(node, msg, TRACE_NETWORK_LAYER, PACKET_IN, &acnData);

    // remove IPv6 header from the encapsulating IPv6 packet to decapsulate
    // IPv4 packet from it.

    Ipv6RemoveIpv6Header(
        node,
        msg,
        &sourceAddress,
        &destinationAddress,
        &priority,
        &protocol,
        &hLim);

    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;
    int outgoingInterfaceIndex;
    NodeAddress outgoingBroadcastAddr;

    // increment stats for ipv4 pkt decapsulation
    if (NetworkIpIsMulticastAddress(node, ipHeader->ip_dst))
    {
        // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numMulticastRecv++;
    }
    else if (IsOutgoingBroadcast(
            node,
            ipHeader->ip_dst,
            &outgoingInterfaceIndex,
            &outgoingBroadcastAddr))
    {
            // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numBroadcastRecv++;
    }
    else
    {
            // increment stats for ipv4 pkt encapsulation
        tunneldata->tunnelStats.numUnicstRecv++;
    }

    if (DUAL_IP_DEBUG)
    {
        char ipv4srcAddrStr[MAX_STRING_LENGTH];
        char ipv4destAddrStr[MAX_STRING_LENGTH];
        char tunnelEndAddrStr[MAX_STRING_LENGTH];

        const char* tunnelTypeStr = TunnelGetTunnelTypeStr(tunneldata->tunnelType);

        IO_ConvertIpAddressToString(ipHeader->ip_src,
            ipv4srcAddrStr);
        IO_ConvertIpAddressToString(ipHeader->ip_dst,
            ipv4destAddrStr);
        IO_ConvertIpAddressToString(&sourceAddress.interfaceAddr.ipv6,
            tunnelEndAddrStr);

        printf("Node %d: interfaceIndex %d has received a encapsulated"
            " IPv4 pkt with srcAddr= %s and destAddr= %s\n"
            "through a %s with tunnel endpoint %s",
            node->nodeId,
            interfaceIndex,
            ipv4srcAddrStr,
            ipv4destAddrStr,
            tunnelTypeStr,
            tunnelEndAddrStr);
    }

    // Send the decapsulated IPv4 pkt to the IPv4 layer's
    // pkt-receiving function.

    NetworkIpReceivePacketFromMacLayer(
        node,
        msg,
        ANY_ADDRESS, // last hop address
        tunneldata->pseudoIntIndex);

    return;
}

// /**
// API                 :: TunnelSetInterfaceStatusHandlerFunction
// LAYER               :: Network
// PURPOSE             :: Set the interface handler function to be called
//                        when interface faults occur.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// +interfaceIndex      : int : Interface Index
// +statusHandler       : MacReportInterfaceStatus : status Handler
// RETURN              :: None
// **/
void
TunnelSetInterfaceStatusHandlerFunction(Node *node,
                                      int interfaceIndex,
                                      MacReportInterfaceStatus statusHandler)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    LinkedList* listptr =
                    ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo;

    TunnelInfoType* tunneldata = (TunnelInfoType*)listptr->first->data;

    assert(tunneldata->interfaceStatusHandlerList != NULL);

    ListInsert(node,
               tunneldata->interfaceStatusHandlerList,
               node->getNodeTime(),
               (void *) statusHandler);
}

// /**
// API                 :: TunnelInformInterfaceStatusHandler
// LAYER               :: Network
// PURPOSE             :: Call the interface handler functions when interface
//                        goes up and down.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// +interfaceIndex      : int : Interface Index
// +state               : MacInterfaceState : current Interface state
// RETURN              :: None
// **/
void TunnelInformInterfaceStatusHandler(Node *node,
                                      int interfaceIndex,
                                      MacInterfaceState state)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    if (interfaceInfo->InterfacetunnelInfo == NULL)
    {
        return;
    }
    ListItem* tunnelPtr = interfaceInfo->InterfacetunnelInfo->first;

    TunnelInfoType* tunneldata = NULL;

    // Inform to all the tunnels configured on this interface
    while (tunnelPtr)
    {
        tunneldata = (TunnelInfoType*)tunnelPtr->data;
        ListItem *item;
        MacReportInterfaceStatus statusHandler;

        item = tunneldata->interfaceStatusHandlerList->first;

        while (item)
        {
            statusHandler = (MacReportInterfaceStatus) item->data;

            assert(statusHandler);

            (statusHandler)(node, tunneldata->pseudoIntIndex, state);

            item = item->next;
        }

        tunnelPtr = tunnelPtr->next;
    }
}

// /**
// API                 :: TunnelNotificationOfIPV6PacketDrop
// LAYER               :: Network
// PURPOSE             :: Tunnel callback functions when a packet is dropped.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + msg                : Message* : Ptr to Messasge containing
//                                   IPv6 pkt encapsulated within IPv4 pkt.
// +interfaceIndex      : int : Interface Index
// RETURN              :: None
// **/
void
TunnelNotificationOfIPV6PacketDrop(Node *node,
                                  Message *msg,
                                  int interfaceIndex)
{
    NodeAddress sourceAddress;
    NodeAddress destinationAddress;
    unsigned char ipProtocolNumber;
    unsigned ttl = 0;
    TosType priority;

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IpInterfaceInfoType* interfaceInfo = ip->interfaceInfo[interfaceIndex];

    if (interfaceInfo->InterfacetunnelInfo == NULL)
    {
        char buff[MAX_STRING_LENGTH];
        sprintf(buff,
            "Node %d interfaceIndex %d - No tunnel is configured\n",
            node->nodeId, interfaceIndex);
        ERROR_ReportError(buff);
    }
    ListItem* tunnelPtr = interfaceInfo->InterfacetunnelInfo->first;

    TunnelInfoType* tunneldata = NULL;

    IpHeaderType *ipHeader = (IpHeaderType *) msg->packet;

    // search for the tunnel with tunnel-end point as the dest of the packet
    while (tunnelPtr)
    {
        tunneldata = (TunnelInfoType*)tunnelPtr->data;

        if (tunneldata->tunnelEndAddress.interfaceAddr.ipv4 ==
            ipHeader->ip_dst)
        {
            break;
        }

        tunnelPtr = tunnelPtr->next;
    }

    NetworkIpRemoveIpHeader(
                            node,
                            msg,
                            &sourceAddress,
                            &destinationAddress,
                            &priority,
                            &ipProtocolNumber,
                            &ttl);

    MacHWAddress macAddr;
    macAddr.hwLength = MAC_IPV4_LINKADDRESS_LENGTH;
    macAddr.hwType = IPV4_LINKADDRESS;
    macAddr.byte = (unsigned char*)MEM_malloc(macAddr.hwLength);
    memcpy(macAddr.byte, &destinationAddress, MAC_IPV4_LINKADDRESS_LENGTH);

    Ipv6NotificationOfPacketDrop(
            node,
            msg,
            macAddr,
            tunneldata->pseudoIntIndex);

    // increment stats for ipv6 pkt dropped
    tunneldata->tunnelStats.numPktDroppedTunnelFailure++;

    return;
}

// /**
// FUNCTION            :: TunnelFinalize
// LAYER               :: Network
// PURPOSE             :: Tunnel Finalization.
// PARAMETERS          ::
// + node               : Node*   : Pointer to node structure.
// + interfaceIndex     : int     : interface Index.
// RETURN              :: None
// **/
void TunnelFinalize(Node* node, int interfaceIndex)
{
    char buf[BUFFER_SIZE];
    char addrStr[MAX_STRING_LENGTH];

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    if (node->networkData.networkStats == FALSE
        || ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo == NULL)
    {
        return;
    }

    ListItem* tunnelPtr =
        ip->interfaceInfo[interfaceIndex]->InterfacetunnelInfo->first;

    TunnelInfoType* tunneldata = NULL;

    // Check whether any tunnel is configured on this interface
    while (tunnelPtr)
    {
        tunneldata = (TunnelInfoType*)tunnelPtr->data;
        TunnelStatsType stats = tunneldata->tunnelStats;

        const char* tunnelTypeStr = TunnelGetTunnelTypeStr(tunneldata->tunnelType);

        IO_ConvertIpAddressToString(&tunneldata->tunnelEndAddress, addrStr);

        sprintf(buf, "Broadcast Packets Sent at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numBroadcastSent);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Broadcast Packets Rcvd at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numBroadcastRecv);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Multicast Packets Sent at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numMulticastSent);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Multicast Packets Rcvd at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numMulticastRecv);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Unicast Packets Sent at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numUnicstSent);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Unicast Packets Rcvd at %s"
            " with Endpoint %s = %u",
            tunnelTypeStr,
            addrStr,
            stats.numUnicstRecv);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

        sprintf(buf, "Packets Dropped at %s"
            " with Endpoint %s due to tunnel failure = %u",
            tunnelTypeStr,
            addrStr,
            stats.numPktDroppedTunnelFailure);

      IO_PrintStat(node, "Network", "Tunnel", ANY_DEST, interfaceIndex, buf);

      tunnelPtr = tunnelPtr->next;
    }
    return;
}
