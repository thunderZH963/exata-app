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

//
// PROTOCOL   :: IAHEP
// LAYER      :: Network

// MAJOR REFERENCES ::
// +
// MINOR REFERENCES ::
// +

// COMMENTS   :: None
//

#include "api.h"
#include "main.h"
#include "fileio.h"
#include "network_ip.h"
#include "network_ipsec.h"
#include "network_ipsec_esp.h"
#include "network_isakmp.h"
#include "network_iahep.h"
#include "routing_ospfv2.h"
#include "mac.h"

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#ifdef ADDON_BOEINGFCS
#include "routing_ces_rospf.h"
#endif

#ifdef WIRELESS_LIB
#include "routing_aodv.h"
#include "routing_dymo.h"
#endif //WIRELESS_LIB

#define DEFAULT_INSTANCE -1
#define RED_INSTANCE 0
#define BLACK_INSTANCE 1

/***** Start: OPAQUE-LSA *****/
#define USE_OPAQUE_TO_DISTRIBUTE_IAHEP_DEVICE_ADDRS 1
/***** End: OPAQUE-LSA *****/


extern void
AddIpHeader(
            Node *node,
            Message *msg,
            NodeAddress sourceAddress,
            NodeAddress destinationAddress,
            TosType priority,
            UInt8 protocol,
            unsigned ttl);


extern void IgmpCreatePacket(
                             Message* msg,
                             unsigned char type,
                             unsigned char maxResponseTime,
                             unsigned groupAddress);


// FUNCTION      ::    IAHEPGetFirstRedInterface
// LAYER         ::    Network
// PURPOSE       ::    To get ip-address of first IAHEP RED Interface
// PARAMETERS    ::
// + node        ::    Node* - The IAHEP node pointer
// RETURN        ::    NodeAddress
// NOTE          ::
NodeAddress IAHEPGetFirstRedInterface(Node* node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->iahepInterfaceType == RED_INTERFACE)
        {
            return ip->interfaceInfo[i]->ipAddress;
        }
    }
    return ANY_ADDRESS;
}

// FUNCTION      ::    IAHEPGetRedRoutingProtocol
// LAYER         ::    Network
// PURPOSE       ::    To get Routing Protocol type for IAHEP RED Interface
// PARAMETERS    ::
// + node        ::    Node* - The IAHEP node pointer
// RETURN        ::    NetworkRoutingProtocolType
// NOTE          ::
NetworkRoutingProtocolType IAHEPGetRedRoutingProtocol(Node* node)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->iahepInterfaceType == RED_INTERFACE)
        {
            return ip->interfaceInfo[i]->routingProtocolType;
        }
    }
    return ROUTING_PROTOCOL_NONE;
}

// FUNCTION      ::    IAHEPGetMulticastProtocol
// LAYER         ::    Network
// PURPOSE       ::    To get Multicast Protocol type for IAHEP RED Interface
// PARAMETERS    ::
// + node        ::    Node* - The IAHEP node pointer
// RETURN        ::    NetworkRoutingProtocolType
// NOTE          ::
NetworkRoutingProtocolType IAHEPGetRedMulticastProtocol(Node* node)
{
    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (IsIAHEPRedSecureInterface(node, i))
        {
            return ip->interfaceInfo[i]->multicastProtocolType;
        }
    }
    return ROUTING_PROTOCOL_NONE;
}

// FUNCTION            :: IAHEPGetAMDInfoForDestBlackInterface
// LAYER               :: Network
// PURPOSE             :: To get AMD info for given destination BLACK address
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + address           :: NodeAddress     :.destination BLACK address
// RETURN              :: IAHEPAmdMappingType* : AMD info
// **/
IAHEPAmdMappingType* IAHEPGetAMDInfoForDestBlackInterface(Node* node,
                                                          NodeAddress address)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (Int32 i = 0; i < ip->iahepData->updateAmdTable->sizeOfAMDTable();
        i++)
    {
        if (ip->iahepData->updateAmdTable->getAMDTable(i)->destBlackInterface
            == address)
        {
            return ip->iahepData->updateAmdTable->getAMDTable(i);
        }
    }
    return NULL;
}

// FUNCTION            :: IAHEPGetAMDInfoForDestinationRedAddress
// LAYER               :: Network
// PURPOSE             :: To get AMD info for given local and remote
//                       BLACK address
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + remoteRedIPAddress:: NodeAddress     :.Destination Red Address
// RETURN              :: IAHEPAmdMappingType* : AMD info
// **/
IAHEPAmdMappingType* IAHEPGetAMDInfoForDestinationRedAddress(
    Node* node,
    NodeAddress remoteRedIPAddress)
{
    Int32 i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (i = 0; i < ip->iahepData->updateAmdTable->sizeOfAMDTable(); i++)
    {
        if (ip->iahepData->updateAmdTable->getAMDTable(i)->destRedInterface
            == remoteRedIPAddress)
        {
            return ip->iahepData->updateAmdTable->getAMDTable(i);
        }
    }
    return NULL;
}


// FUNCTION      ::    IAHEPInitMappingForROSPFSimulatedHellos
// LAYER         ::    Network
// PURPOSE       ::    Function to Initialize IAHEP mapping for ROSPF
//               ::     simmulated hellos.
// PARAMETERS    ::
// + node        ::    Node*   : Pointer to node structure.
// + nodeInput   ::    const NodeInput* : QualNet main configuration file.
// RETURN        ::    void
// NOTE          :: [<Black Addr>] IAHEP-DEVICE-ADDRESS <IAHEP-to-Black Addr>
void
IAHEPInitMappingForROSPFSimulatedHellos(Node* node,
                                        const NodeInput* nodeInput)
{
    int i;
    int j;
    BOOL isNodeId = FALSE;
    NodeAddress myAddress;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    /***** Start: OPAQUE-LSA *****/
    if (ip->iahepData->nodeType == IAHEP_NODE)
    /***** End: OPAQUE-LSA *****/
    {
        ip->iahepData->IahepDeviceMapping =
            new std::map<NodeAddress, NodeAddress>;
    }

    for (i = 0; i < nodeInput->numLines; i++)
    {
        if (strcmp(nodeInput->variableNames[i],
            "IAHEP-DEVICE-ADDRESS") == 0)
        {
            NodeAddress blackAddrs;
            NodeAddress blackIahepAddrs;

            // Get new interface address.
            IO_ParseNodeIdOrHostAddress(
                nodeInput->qualifiers[i],
                &blackAddrs,
                &isNodeId);

            if (isNodeId)
            {
                char buf[MAX_STRING_LENGTH];

                sprintf(buf, "IAHEP-DEVICE-ADDRESS parameter must"
                    " have an IP address as its "
                    "qualifier.\n");

                ERROR_ReportError(buf);
            }

            // Get new interface address.
            IO_ParseNodeIdOrHostAddress(
                nodeInput->values[i],
                &blackIahepAddrs,
                &isNodeId);

            if (isNodeId)
            {
                char buf[MAX_STRING_LENGTH];

                sprintf(buf, "IAHEP-DEVICE-ADDRESS parameter must "
                    "have an IP address as its "
                    "value.\n");

                ERROR_ReportError(buf);
            }

/***** Start: OPAQUE-LSA *****/
#if USE_OPAQUE_TO_DISTRIBUTE_IAHEP_DEVICE_ADDRS
            if (ip->iahepData->nodeType == BLACK_NODE)
            {
                for (j = 0; j < node->numberInterfaces; j++)
                {
                    myAddress = NetworkIpGetInterfaceAddress(node, j);
                    if (blackAddrs == myAddress &&
                        (ip->interfaceInfo[j]->iahepInterfaceType ==
                            IAHEP_BLACK_INTERFACE))
                    {
                        ip->interfaceInfo[j]->iahepDeviceAddress =
                            blackIahepAddrs;
                    }
                }
            }
#else
            if (ip->iahepData->nodeType == IAHEP_NODE)
            {
                ip->iahepData->IahepDeviceMapping->insert(
                    make_pair(blackAddrs, blackIahepAddrs));
            }
#endif
/***** End: OPAQUE-LSA *****/
        }
    }
}

/***** Start: OPAQUE-LSA *****/

//---------------------------------------------------------------------------
// FUNCTION      ::    IAHEPUpdateMappingForROSPFSimulatedHellos
// LAYER         ::    Network
// PURPOSE       ::    Function to Update IAHEP mapping based on ROSPF
//               ::     simmulated hellos.
// PARAMETERS    ::
// + node        ::    Node*   : Pointer to node structure.
// + blackAddr   ::    NodeAddress : Black interface address of advertising
//                                   router
// + haipeDeviceAddress    :: NodeAddress : HAIPE device address
// RETURN        ::    void
// **/
//---------------------------------------------------------------------------
void
IAHEPUpdateMappingForROSPFSimulatedHellos(Node* node,
                                          NodeAddress blackAddr,
                                          NodeAddress haipeDeviceAddress)
{
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    ERROR_Assert(ip->iahepData->IahepDeviceMapping != NULL,
        "Cannot update HAIPE device mapping based on sim hello as "
        "structure is NULL");

    // Replace if key exists, else insert new mapping
    (*(ip->iahepData->IahepDeviceMapping))[blackAddr] =
        haipeDeviceAddress;
}

/***** End: OPAQUE-LSA *****/

// FUNCTION      ::    IAHEPInit
// LAYER         ::    Network
// PURPOSE       ::    Function to Initialize IAHEP for a node
// PARAMETERS    ::
// + node        ::    Node*   : Pointer to node structure.
// + nodeInput   ::    const NodeInput* : QualNet main configuration file.
// RETURN        ::    void
// NOTE          ::
void IAHEPInit(Node* node, const NodeInput* nodeInput)
{
    BOOL retVal = FALSE;
    BOOL retValProto = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};
    int rate;
    int size;
    char errStr[MAX_STRING_LENGTH] = {0};
    char protocolString[MAX_STRING_LENGTH] = {0};
    NetworkRoutingProtocolType routingProtocolType = ROUTING_PROTOCOL_NONE;
    NetworkRoutingProtocolType multicastRoutingProtocol =
        ROUTING_PROTOCOL_NONE;
    NodeAddress myAddress;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;

    for (int i = 0; i < node->numberInterfaces; i++)
    {
        myAddress = NetworkIpGetInterfaceAddress(node, i);

        IO_ReadString(
            node->nodeId,
            myAddress,
            nodeInput,
            "IAHEP-INTERFACE-TYPE",
            &retVal,
            buf);

        IO_ReadString(
            node->nodeId,
            myAddress,
            nodeInput,
            "ROUTING-PROTOCOL",
            &retValProto,
            protocolString);

        if (ip->iahepData->nodeType == IAHEP_NODE)
        {
            if (retVal)
            {
                if (!strcmp(buf, "RED"))
                {
                    ip->interfaceInfo[i]->iahepInterfaceType =
                        IAHEP_RED_INTERFACE;
                }
                else if (!strcmp(buf, "BLACK"))
                {
                    ip->interfaceInfo[i]->iahepInterfaceType =
                        IAHEP_BLACK_INTERFACE;
                }
                else
                {
                    sprintf(errStr, "Node [%d]:IAHEP-INTERFACE-TYPE"
                        " expects RED or BLACK", node->nodeId);
                    ERROR_Assert(FALSE, errStr);
                }
            }
            else
            {
                sprintf(errStr, "Node [%d]:IAHEP-INTERFACE-TYPE"
                    " expects RED or BLACK", node->nodeId);
                ERROR_Assert(FALSE, errStr);
            }

            NetworkIpAddUnicastRoutingProtocolType(
                node,
                routingProtocolType,
                i,
                NETWORK_IPV4);

            ip->interfaceInfo[i]->multicastProtocolType =
                multicastRoutingProtocol;

            // Set the router function
            NetworkIpSetRouterFunction(
                node,
                &IAHEPRouterFunction,
                i);

            //Reading Encapsulation Size: To add Encapsulation overhead
            IO_ReadInt(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "IAHEP-ENCAPSULATION-OVERHEAD-SIZE",
                &retVal,
                &size);
            if (!retVal)
            {
                ip->interfaceInfo[i]->iahepEncapsulationOverheadSize = 0;
            }
            else
            {
                ip->interfaceInfo[i]->iahepEncapsulationOverheadSize = size;
            }

            //Reading Encryption Rate: To add Encryption Delay
            //Value to be read in bps
            IO_ReadInt(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "IAHEP-ENCRYPTION-RATE",
                &retVal,
                &rate);
            if (!retVal)
            {
                ip->interfaceInfo[i]->iahepControlEncryptionRate = 0;
            }
            else
            {
                ip->interfaceInfo[i]->iahepControlEncryptionRate = rate;
            }

            //Reading HMAC Rate: To Add Authentication Delay
            //Value to be read in bps
            IO_ReadInt(
                node->nodeId,
                NetworkIpGetInterfaceAddress(node, i),
                nodeInput,
                "IAHEP-AUTHENTICATION-RATE",
                &retVal,
                &rate);
            if (!retVal)
            {
                ip->interfaceInfo[i]->iahepControlHMACRate = 0;
            }
            else
            {
                ip->interfaceInfo[i]->iahepControlHMACRate = rate;
            }
        }
        else if (ip->iahepData->nodeType == BLACK_NODE)
        {
            if (retVal)
            {
                if (!strcmp(buf, "BLACK"))
                {
                    ip->interfaceInfo[i]->iahepInterfaceType =
                        IAHEP_BLACK_INTERFACE;

                    if (retValProto && strcmp(protocolString, "NONE"))
                    {
                        sprintf(errStr, "ROUTING-PROTOCOL should be set to "
                            "NONE  on interfaceIndex %d of node %d\n",
                            i, node->nodeId);
                        ERROR_ReportError(errStr);
                    }

                    NetworkIpAddUnicastRoutingProtocolType(
                        node,
                        routingProtocolType,
                        i,
                        NETWORK_IPV4);
                }
                else
                {
                    sprintf(errStr, "WRONG IAHEP-INTERFACE-TYPE on BLACK"
                        "Node: %d", node->nodeId);
                    ERROR_Assert(FALSE, errStr);
                }
            }
            else
            {
                ip->interfaceInfo[i]->iahepInterfaceType = BLACK_INTERFACE;
            }
        }
        else //Red Node
        {
            if (retVal)
            {
                if (!strcmp(buf, "RED"))
                {
                    ip->interfaceInfo[i]->iahepInterfaceType =
                        IAHEP_RED_INTERFACE;
                }
                else
                {
                    sprintf(errStr, "WRONG IAHEP-INTERFACE-TYPE on RED"
                        "Node: %d", node->nodeId);
                    ERROR_Assert(FALSE, errStr);
                }
            }
            else
            {
                ip->interfaceInfo[i]->iahepInterfaceType = RED_INTERFACE;
            }
        }
    }

    if (ip->iahepData->nodeType == IAHEP_NODE ||
        ip->iahepData->nodeType == RED_NODE)
    {
        ip->iahepData->securityName = STRONG_STAR;
        IO_ReadString(
            node->nodeId,
            myAddress,
            nodeInput,
            "MLS-STAR-PROPERTY",
            &retVal,
            buf);

        if (retVal)
        {
            if (!strcmp(buf, "STRONG"))
            {
                ip->iahepData->securityName =
                    STRONG_STAR;
            }
            else if (!strcmp(buf, "LIBERAL"))
            {
                ip->iahepData->securityName =
                    LIBERAL_STAR;
            }
            else
            {
                sprintf(errStr, "Node [%d]:MLS-STAR-PROPERTY"
                    " expects STRONG or LIBERAL", node->nodeId);
                ERROR_Assert(FALSE, errStr);
            }
        }
    }

    if (ip->iahepData->nodeType == IAHEP_NODE)
    {
        NodeInput amdInput;
        ip->iahepData->updateAmdTable = new UpdateAMDTable;
        ip->iahepData->grpAddressList = new set<NodeAddress>;

        IO_ReadCachedFile(node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "IAHEP-AMD-FILE",
            &retVal,
            &amdInput);

        if (!retVal)
        {
            ERROR_ReportError("IAHEP-AMD-FILE Not Present");
        }
        else
        {
            if (amdInput.numLines != 0)
            {
                IAHEPUpdateAMDInfoForStaticAMDConfiguration(
                    node,
                    amdInput,
                    nodeInput);

                if (!ip->iahepData->localBlackAddress)
                {
                    sprintf(errStr, "AMD Entry Not Found For Node %d",
                        node->nodeId);
                    ERROR_Assert(FALSE, errStr);
                }
            }
            else
            {
                ERROR_ReportError("IAHEP-AMD-FILE Can Not be Empty");
            }
        }

        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IAHEP-IGMP-MODE",
                      &retVal,
                      buf);

        if (retVal)
        {
            if (!strcmp(buf,"BYPASS"))
            {
                ip->iahepData->IGMPIsByPassMode = TRUE;

                //IGMP Should Not Run In BYPASS Mode
                ip->isIgmpEnable = FALSE;
            }
        }

        //IAHEP Node needs to Join Broadcast Group at Initialization
        NodeAddress brdCastMappedAddress = ANY_ADDRESS;

        int i;
        for (i = 0; i< node->numberInterfaces; i++)
        {
            if (IsIAHEPBlackSecureInterface(node, i)&&
                !(ip->iahepData->IGMPIsByPassMode))
            {
                // Check if IGMP data is initialized before joining
                if (ip->isIgmpEnable &&
                    (ip->igmpDataPtr == NULL ||
                     ip->igmpDataPtr->igmpInterfaceInfo[i] == NULL))
                {
                    IgmpInit(node, nodeInput, &ip->igmpDataPtr, i);
                }

                IgmpJoinGroup(node, i, brdCastMappedAddress, (clocktype)0);

                if (IAHEP_DEBUG)
                {
                    char addrStr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(brdCastMappedAddress, addrStr);
                    printf("\nIAHEP Node: %d", node->nodeId);
                    printf("\tJoins Group: %s\n", addrStr);
                }

                break;
            }
        }

        IAHEPInitMappingForROSPFSimulatedHellos(node, nodeInput);
    }
    /***** Start: OPAQUE-LSA *****/
    else if (ip->iahepData->nodeType == BLACK_NODE)
    {
        IAHEPInitMappingForROSPFSimulatedHellos(node, nodeInput);
    }
    /***** End: OPAQUE-LSA *****/
}

// FUNCTION            :: IsIAHEPRedSecureInterface
// LAYER               :: Network
// PURPOSE             :: Checking if IAHEP Red Secure Interface or not.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex        ::   int     :.Interface Index
// RETURN              :: BOOL
//
BOOL IsIAHEPRedSecureInterface(Node* node, int intIndex)
{
    if (intIndex < 0 || intIndex >= MAX_NUM_INTERFACES)
    {
        return FALSE;
    }
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    if (ip->interfaceInfo[intIndex]->iahepInterfaceType == IAHEP_RED_INTERFACE)
    {
        return TRUE;
    }
    return FALSE;
}


// FUNCTION            :: IAHEPGetIAHEPRedInterfaceIndex
// LAYER               :: Network
// PURPOSE             :: Returns IAHEP Red Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// RETURN              :: int
// **/
int IAHEPGetIAHEPRedInterfaceIndex(Node* node)
{
    Int8 errStr[MAX_STRING_LENGTH];
    Int32 intfId = ANY_INTERFACE;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    for (UInt32 i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->iahepInterfaceType == IAHEP_RED_INTERFACE)
        {
            intfId = i;
            break;
        }
    }

    if (intfId == ANY_INTERFACE)
    {
        sprintf(errStr, "Node %u: Got invalid Iahep Interface\n",
            node->nodeId);
        ERROR_Assert(FALSE, errStr);
    }
    return intfId;
}

// FUNCTION            :: IAHEPGetIAHEPBlackInterfaceIndex
// LAYER               :: Network
// PURPOSE             :: Returns IAHEP Red Interface.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// RETURN              :: int
// **/
int IAHEPGetIAHEPBlackInterfaceIndex(Node* node)
{
    Int32 intfId = ANY_INTERFACE;
    Int8 errStr[MAX_STRING_LENGTH];
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    for (UInt32 i = 0; i < node->numberInterfaces; i++)
    {
        if (ip->interfaceInfo[i]->iahepInterfaceType == IAHEP_BLACK_INTERFACE)
        {
            intfId = i;
            break;
        }
    }
    if (intfId == ANY_INTERFACE)
    {
        sprintf(errStr, "Node %u: Got invalid Iahep Interface\n",
            node->nodeId);
        ERROR_Assert(FALSE, errStr);
    }
    return intfId;
}

// FUNCTION            :: IsIAHEPBlackSecureInterface
// LAYER               :: Network
// PURPOSE             :: Checking if IAHEP BLACK Secure Interface or not.
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + intIndex          :: int     :.Interface Index
// RETURN              :: BOOL
// **/
BOOL IsIAHEPBlackSecureInterface(Node* node, int intIndex)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    if (intIndex < 0 || intIndex >= MAX_NUM_INTERFACES)
    {
        return FALSE;
    }
    if (ip->interfaceInfo[intIndex]->iahepInterfaceType == IAHEP_BLACK_INTERFACE)
    {
        return TRUE;
    }
    return FALSE;
}


// /**
// API        :: IAHEPProcessingRequired
// LAYER      :: Network
// PURPOSE    :: Returns whether protocol is routing or not.
// PARAMETERS ::
// + unsigned char       : ipProto
// + short               : appType
// RETURN     :: BOOL :
// **/
BOOL IAHEPProcessingRequired(unsigned char ipProto)
{
    BOOL retVal = TRUE;

    switch(ipProto)
    {
    case IPPROTO_IGMP:
#ifdef ADDON_BOEINGFCS
    case IPPROTO_ROUTING_CES_ROSPF:
#endif
        retVal = FALSE;
        break;
    }

    return retVal;
}

//--------------------------------------------------------------------
// FUNCTION: IAHEPRouterFunction
// PURPOSE: Determine the action to take for a the given packet
//          set the PacketWasRouted variable to TRUE if no further handling
//          of this packet by IP is necessary
// ARGUMENTS: node, The node handling the routing
//            msg,  The packet to route to the destination
//            destAddr, The destination of the packet
//            previousHopAddress, last hop of this packet
//            packetWasRouted, set to FALSE if ip is supposed to handle the
//                             routing otherwise TRUE
// RETURN:   None
//--------------------------------------------------------------------

void
IAHEPRouterFunction(
                    Node *node,
                    Message *msg,
                    NodeAddress destAddr,
                    NodeAddress previousHopAddress,
                    BOOL* packetWasRouted)
{

    UInt32 ttl =0;
    clocktype delay= 0;
    Int32 temp1 = -1;
    TosType priority = 0;
    NodeAddress temp2 = -1;
    UInt8 ipProtocolNumber = 0;
    IahepMLSHeader *mlsLevelRcvd = NULL;
    UInt8 securityLevelRecieved;
    NodeAddress sourceAddress = ANY_ADDRESS;
    NodeAddress destinationAddress = ANY_ADDRESS;
    NodeAddress destRedAddrRecieved = ANY_ADDRESS;
    NodeAddress destinationBlackAddress = ANY_ADDRESS;

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType* ipHeader = (IpHeaderType *) (MESSAGE_ReturnPacket (msg));
    Int32 hLen = sizeof(IpHeaderType);
    Int32 incomingInterface =
        NetworkIpGetInterfaceIndexForNextHop(node, previousHopAddress);
    IAHEPAmdMappingType* amdInfo =
        ip->iahepData->updateAmdTable->getAMDTable(0);

    // INFO_TYPE_RPProcessed is added only by RP nodes
    BOOL RPProcessed = FALSE;
    if (MESSAGE_ReturnInfo(msg, INFO_TYPE_RPProcessed))
    {
        RPProcessed = TRUE;
        MESSAGE_RemoveInfo(node, msg, INFO_TYPE_RPProcessed);
    }

    Int32 blackIntf = IAHEPGetIAHEPBlackInterfaceIndex(node);
    Int32 iahepPktLen = 0;

    if (IsIAHEPRedSecureInterface(node, incomingInterface))
    {
        if (MESSAGE_ReturnInfo(msg, INFO_TYPE_IAHEP_NextHop) != NULL)
        {
            destRedAddrRecieved =
                *(NodeAddress*)MESSAGE_ReturnInfo(msg, INFO_TYPE_IAHEP_NextHop);
        }
        else
        {
            ERROR_Assert(FALSE, "NextHop Info Can Not Be Empty\n");
        }

        //int offset = IpHeaderGetIpFragOffset(ipHeader->ipFragment);

        MESSAGE_RemoveInfo (node, msg, INFO_TYPE_IAHEP_NextHop);

        //MLS Check Can Only Apply to Unicast Packets.
        if (!NetworkIpIsMulticastAddress(node, destRedAddrRecieved) &&
            !(IsOutgoingBroadcast(node, destRedAddrRecieved, &temp1, &temp2))
            && (ipHeader->ip_p == IPPROTO_UDP
            || ipHeader->ip_p == IPPROTO_TCP))
        {
            if (IAHEPMLSOutgoingPropertyCheck(node, msg, destRedAddrRecieved))
            {
                *packetWasRouted = FALSE;
                return;
            }
        }

        /*IpHeaderGetIpFragOffset(ipHeader->ipFragment);
        if (offset)
        {
            ipHeader = (IpHeaderType *) (MESSAGE_ReturnPacket (msg));
            IpHeaderSetIpFragOffset(&(ipHeader->ipFragment), (UInt16)offset);
        }*/

        ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

        iahepPktLen = IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - hLen;

        //Delays Are Calculated Before Adding the Encryption OverHead
        //Encryption Delay
        delay = 0;
        if (ip->interfaceInfo[blackIntf]->iahepControlEncryptionRate > 0)
        {
            delay = (iahepPktLen * 8 * SECOND)/
                ip->interfaceInfo[blackIntf]->iahepControlEncryptionRate;
        }

        // Authentication Delay
        if (ip->interfaceInfo[blackIntf]->iahepControlHMACRate > 0)
        {
            delay += (iahepPktLen * 8 * SECOND)/
                ip->interfaceInfo[blackIntf]->iahepControlHMACRate;
        }

        //Adding IAHEP Node Specific Headers

        // Add overhead bytes in virtual payload field, this includes
        //    iahepEncapsulationOverheadSize
        MESSAGE_AddVirtualPayload(
            node, msg,
            ip->interfaceInfo[blackIntf]->iahepEncapsulationOverheadSize);

        MESSAGE_AddHeader(
            node,
            msg,
            sizeof(IahepMLSHeader),
            TRACE_MLS_IAHEP);

        IahepMLSHeader *securityVal =
            (IahepMLSHeader*) MESSAGE_ReturnPacket(msg);
        securityVal->mls_level = ip->iahepData->MLSSecurityLevel;

        destinationBlackAddress = IAHEPGetBlackDestinationAddressForPkt(node, msg,
            destRedAddrRecieved);

        NodeAddress sourceBlackAddress;
        if (RPProcessed)
        {
            sourceBlackAddress = ip->iahepData->localBlackAddress;
        }
        else
        {
            IAHEPAmdMappingType *mapping =
                IAHEPGetAMDInfoForDestinationRedAddress(
                node, sourceAddress);

            if (mapping != NULL)
            {
                sourceBlackAddress = mapping->destBlackInterface;
            }
            else
            {
                sourceBlackAddress = ip->iahepData->localBlackAddress;

                //char errStr[MAX_STRING_LENGTH] = {0};
                //sprintf(errStr, "Haipe Node %d , using localBlackAddress instead"
                //    " of Red Node mapping\n",
                //    node->nodeId);
                //ERROR_ReportWarning(errStr);
            }
        }

        clocktype hdrdelay = 0;
        TosType tos = IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
        AddIpHeader(
            node,
            msg,
            sourceBlackAddress,
            destinationBlackAddress,
            tos,
            IPPROTO_IP,
            hdrdelay);

        //Send After Processing Delay
        IAHEPSendPktAfterProcessingDelay(
            node,
            msg,
            'o',
            previousHopAddress,
            delay);

        *packetWasRouted = TRUE;
        amdInfo->iahepStats.numOfPktsSent++;

        if (IAHEP_DEBUG)
        {
            printf("\nIAHEP Node [%d]", node->nodeId);
            printf("\tSending Packet on Black Intf\n");
            printf("SeqNo.: %d\t origProtocol: %d\n", msg->sequenceNumber,
                msg->originatingProtocol);
        }
    }
    else if (IsIAHEPBlackSecureInterface(node, incomingInterface))
    {
        amdInfo->iahepStats.numOfPktsRcvd++;

        //Recieve After Processing Delay
        IAHEPRoutingMsgInfoType *routingInfoType = NULL;

        routingInfoType = (IAHEPRoutingMsgInfoType*)
            MESSAGE_ReturnInfo(
            msg,
            INFO_TYPE_IAHEP_RUTNG);

        if (!routingInfoType)
        {
            iahepPktLen =
                IpHeaderGetIpLength(ipHeader->ip_v_hl_tos_len) - hLen;

            //Encryption Delay
            delay = 0;
            if (ip->interfaceInfo[blackIntf]->iahepControlEncryptionRate > 0)
            {
                delay = (iahepPktLen * 8 * SECOND)/
                    ip->interfaceInfo[blackIntf]->iahepControlEncryptionRate;
            }

            // Authentication Delay
            if (ip->interfaceInfo[blackIntf]->iahepControlHMACRate > 0)
            {
                delay += (iahepPktLen * 8 * SECOND)/
                    ip->interfaceInfo[blackIntf]->iahepControlHMACRate;
            }
            IAHEPSendPktAfterProcessingDelay(
                node,
                msg,
                'i',
                previousHopAddress,
                delay);
            
            *packetWasRouted = TRUE;
            return;
        }
        else
        {
            MESSAGE_RemoveInfo (node, msg, INFO_TYPE_IAHEP_RUTNG);
        }

        NetworkIpRemoveIpHeader(
            node,
            msg,
            &sourceAddress,
            &destinationAddress,
            &priority,
            &ipProtocolNumber,
            &ttl);

        ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

        mlsLevelRcvd = (IahepMLSHeader *) (MESSAGE_ReturnPacket(msg));
        securityLevelRecieved = mlsLevelRcvd->mls_level;

        MESSAGE_RemoveHeader(
            node,
            msg,
            sizeof (IahepMLSHeader),
            TRACE_MLS_IAHEP);

        // Remove overhead bytes in virtual payload field, this includes
        //    iahepEncapsulationOverheadSize

        MESSAGE_RemoveVirtualPayload(
            node, msg,
            ip->interfaceInfo[blackIntf]->iahepEncapsulationOverheadSize);

        ipHeader = (IpHeaderType *)MESSAGE_ReturnPacket(msg);

        //MLS Check For Incoming Packets
        if (ipHeader->ip_p == IPPROTO_UDP
            || ipHeader->ip_p == IPPROTO_TCP)
        {
            if (IAHEPMLSIncomingPropertyCheck(node, msg, securityLevelRecieved))
            {   
                *packetWasRouted = FALSE;
                return;
            }
        }

        IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
            MESSAGE_ReturnPacketSize(msg));

#ifdef ADDON_BOEINGFCS
        /***** Start: ROSPF Redirect *****/
        IAHEPAmdMappingType *mapping =
                IAHEPGetAMDInfoForDestBlackInterface(node, 
                                                     sourceAddress);
        ERROR_Assert(mapping != NULL, "Could not find Black Source");
        NodeAddress sourceRedAddress = mapping->destRedInterface;

        // Add metadata that may be necessary for 
        // ROSPF redirects in an info field
        MESSAGE_AddInfo(node, 
                        msg, 
                        sizeof(RospfRedirectMetadata), 
                        INFO_TYPE_ROSPFRedirectMetadata);

        RospfRedirectMetadata *redirMeta = (RospfRedirectMetadata *)
            MESSAGE_ReturnInfo(msg, INFO_TYPE_ROSPFRedirectMetadata);
        redirMeta->incomingInterface = ANY_INTERFACE;
        redirMeta->prevHopAddr = sourceRedAddress;
        /***** End: ROSPF Redirect *****/
#endif

        NetworkIpSendPacketOnInterface(
            node,
            msg,
            CPU_INTERFACE,
            IAHEPGetIAHEPRedInterfaceIndex(node),
            0);

        *packetWasRouted = TRUE;
        if (IAHEP_DEBUG)
        {
            printf("\nIAHEP Node [%d]", node->nodeId);
            printf("\tRecieved Packet On Black Intf\n");
            printf("SeqNo.: %d\t origProtocol: %d\n", msg->sequenceNumber,
                msg->originatingProtocol);
        }
    }
    else { 
        char errStr[MAX_STRING_LENGTH];

        sprintf(errStr, "IAHEP node %d, Trying to route self originated packet!\n",
            node->nodeId);
        ERROR_ReportError(errStr);
    }
}

// FUNCTION   :: IAHEPFinalize
// LAYER      :: Network
// PURPOSE    :: Finalise function for IAHEP, to Print Collected Statistics
// PARAMETERS ::
// + node              : Node*    : The node pointer
// RETURN     :: void
// NOTE       ::
void IAHEPFinalize(Node* node)
{
    UInt32 interfaceIndex = ANY_INTERFACE;
    char buf[MAX_STRING_LENGTH];
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;


    if (ip->iahepData->nodeType == IAHEP_NODE)
    {
        interfaceIndex = IAHEPGetIAHEPBlackInterfaceIndex(node);

        IAHEPAmdMappingType* amdInfo =
            ip->iahepData->updateAmdTable->getAMDTable(0);
        IpInterfaceInfoType* intfInfo = ip->interfaceInfo[interfaceIndex];

        sprintf(buf, "MLS:Number Of Outgoing Unicast Packets Dropped Under"
            "STRONG PROPERTY = %u", amdInfo->iahepStats.
            iahepMLSOutgoingUnicastPacketsDroppedUndrPropSTRONG);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex,
            buf);

        sprintf(buf, "MLS:Number Of Outgoing Unicast Packets Dropped Under"
            "LIBERAL PROPERTY = %u", amdInfo->iahepStats.
            iahepMLSOutgoingUnicastPacketsDroppedUndrPropLIBREAL);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex,
            buf);

        sprintf(buf, "MLS:Number Of Incoming Unicast Packets Dropped Under"
            "SIMPLE PROPERTY = %u", amdInfo->iahepStats.
            iahepMLSIncomingPacketsDroppedUndrPropSIMPLE);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);

        sprintf(buf, "Number of IP Fragments Padded = %u",
            (UInt32) intfInfo->iahepstats.iahepIPFragsPadded);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);

        sprintf(buf, "Number of Packets Received = %u",
            amdInfo->iahepStats.numOfPktsRcvd);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);

        sprintf(buf, "Number of Packets Sent = %u",
            amdInfo->iahepStats.numOfPktsSent);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);

        sprintf(buf, "Number Of IGMP Report Messages Sent = %u",
            amdInfo->iahepStats.iahepIGMPReportsSent);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);

        sprintf(buf, "Number Of IGMP Leave Messages Sent = %u",
            amdInfo->iahepStats.iahepIGMPLeavesSent);
        IO_PrintStat(node, "Network", "IAHEP", ANY_DEST, interfaceIndex ,
            buf);
    }

    //Freeing the Allocated Memory
    if (ip->iahepData->nodeType == IAHEP_NODE)
    {
        int sizeOfTable = ip->iahepData->updateAmdTable->sizeOfAMDTable();
        for (int i = 0; i< sizeOfTable; i++)
        {
            MEM_free (ip->iahepData->updateAmdTable->getAMDTable(i));
        }
        delete(ip->iahepData->updateAmdTable);
        delete(ip->iahepData->multicastAmdMapping);
        delete(ip->iahepData->IahepToBlackMapping);
        delete(ip->iahepData->grpAddressList);
    }
    MEM_free(ip->iahepData);
    return;
}

// /**
// API                 :: IAHEPMLSOutgoingPropertyCheck
// PURPOSE             :: Function MLS Handling for Outgoing Packets.
// PARAMETERS          ::
//+node*                : node.
//unsigned              : address
// RETURN               : BOOL.
// **/
BOOL IAHEPMLSOutgoingPropertyCheck(Node* node, Message *msg,
                                   NodeAddress destAddress)
{
    BOOL retVal = FALSE;
    UInt8 MLSFromAMDTable;

    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    int i;
    for (i = 0; i < ip->iahepData->updateAmdTable->sizeOfAMDTable();
        i++)
    {
        if (destAddress == ip->iahepData->updateAmdTable->getAMDTable(i)->
            destRedInterface)
        {
            MLSFromAMDTable = ip->iahepData->updateAmdTable->
                getAMDTable(i)->destSecurityLevel;
            break;
        }
    }

    if (ip->iahepData->securityName == STRONG_STAR)
    {
        if (ip->iahepData->MLSSecurityLevel != MLSFromAMDTable)
        {
            ip->iahepData->updateAmdTable->getAMDTable(0)->iahepStats.
                iahepMLSOutgoingUnicastPacketsDroppedUndrPropSTRONG++;
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                ANY_INTERFACE,
                "NetworkPacketDrop",
                "IAHEP MLS Drop under STRONG_STAR Property",
                0,
                0,
                0,
                0);
#endif

            MESSAGE_Free(node, msg);
            retVal = TRUE;
        }
    }
    else if (ip->iahepData->securityName == LIBERAL_STAR)
    {
        if (ip->iahepData->MLSSecurityLevel > MLSFromAMDTable)
        {
            ip->iahepData->updateAmdTable->getAMDTable(0)->iahepStats.
                iahepMLSOutgoingUnicastPacketsDroppedUndrPropLIBREAL++;
#ifdef ADDON_DB

            HandleNetworkDBEvents(
                node,
                msg,
                ANY_INTERFACE,
                "NetworkPacketDrop",
                "IAHEP MLS Drop under LIBERAL_STAR Property",
                0,
                0,
                0,
                0);
#endif
            MESSAGE_Free(node, msg);
            retVal = TRUE;
        }
    }

    return retVal;
}

// /**
// API                 :: IAHEPMLSIncomingPropertyCheck
// PURPOSE             :: Function MLS Handling for Incoming Packets.
// PARAMETERS          ::
//+node*                : node.
//UInt8                 :sourceLevel
// RETURN               :BOOL.
// **/
BOOL IAHEPMLSIncomingPropertyCheck (Node* node, Message *msg,
                                    UInt8 sourceLevel)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    BOOL retVal = FALSE;

    //This is By Default Enforced SIMPLE Property
    if (ip->iahepData->MLSSecurityLevel < sourceLevel)
    {
        ip->iahepData->updateAmdTable->getAMDTable(0)->
            iahepStats.iahepMLSIncomingPacketsDroppedUndrPropSIMPLE++;
#ifdef ADDON_DB

        HandleNetworkDBEvents(
            node,
            msg,
            ANY_INTERFACE,
            "NetworkPacketDrop",
            "IAHEP MLS Drop under SIMPLE Property",
            0,
            0,
            0,
            0);
#endif
        MESSAGE_Free(node, msg);
        retVal = TRUE;
    }
    return retVal;
}

//---------------------------------------------------------------------------
// FUNCTION     IAHEPUpdateAMDInfoForStaticAMDConfiguration
// PURPOSE      This Function Fills The AMDInfo Data Structure when
//              static AMD Configuration is used.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeInput amdInput
//              NodeInput nodeInput
// RETURN       None.
// NOTES        None.
//---------------------------------------------------------------------------
void IAHEPUpdateAMDInfoForStaticAMDConfiguration (Node *node,
                                                  NodeInput amdInput,
                                                  const NodeInput* nodeInput)
{
    int counter = 0;
    Int32 temp1 = -1;
    NodeAddress temp2 = -1;
    Int32 numValRead = 0;
    BOOL isNodeId = 0;
    int numHostBits = 0;
    BOOL areValuesStored = FALSE;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    ip->iahepData->multicastAmdMapping = new map<NodeAddress,
        NodeAddress>;

    while (counter < amdInput.numLines)
    {
        const char*   currentLine = amdInput.inputStrings[counter];
        char          param1Str[MAX_STRING_LENGTH] = {0};
        char          param2Str[MAX_STRING_LENGTH] = {0};
        char          param3Str[MAX_STRING_LENGTH] = {0};
        NodeAddress   frstParameter = ANY_ADDRESS;
        NodeAddress   scndParameter = ANY_ADDRESS;

        UInt32 securityLevel = 1;

        //Format: RedInterfaceAddress BlackInterfaceAddress MLSLevel
        //Format: MulticastAddress MulticastAddress MLSLevel
        numValRead = sscanf(
            currentLine,
            "%s%s%s",
            param1Str,
            param2Str,
            param3Str);

        if (numValRead == 3 || numValRead == 2)
        {
            IO_ParseNodeIdHostOrNetworkAddress(
                param1Str,
                &frstParameter,
                &numHostBits,
                &isNodeId);

            IO_ParseNodeIdHostOrNetworkAddress(
                param2Str,
                &scndParameter,
                &numHostBits,
                &isNodeId);

            if (numValRead == 3)
            {
                IO_ParseNodeIdHostOrNetworkAddress(
                    param3Str,
                    &securityLevel,
                    &numHostBits,
                    &isNodeId);
            }

            IAHEPCheckEntriesInAMDTable(
                node,
                frstParameter,
                scndParameter,
                securityLevel,
                numValRead);

            if ((NetworkIpIsMulticastAddress(node, frstParameter) ||
                IsOutgoingBroadcast(
                node,
                frstParameter,
                &temp1,
                &temp2))&&
                NetworkIpIsMulticastAddress(node, scndParameter))
            {
                ip->iahepData->multicastAmdMapping->insert(
                    pair <NodeAddress, NodeAddress>(frstParameter,
                    scndParameter));
                counter++;
                continue;
            }
            else//Both Addresses Are Unicast, Update AMDTable Data Structure
            {
                areValuesStored = IAHEPUpdateAMDTableFromAMDFile(
                    node,
                    frstParameter,
                    scndParameter,
                    securityLevel);
                if (areValuesStored)
                {
                    counter++;
                    continue;
                }
            }
        }
    }
}


//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPSendRecvPktsWithDelay
// LAYER      :: Network
// PURPOSE    :: Function To Send Packet On Appropriate Interface
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + msg       : Message* : Event that expired
// RETURN     :: void : NULL
//---------------------------------------------------------------------------
void IAHEPSendRecvPktsWithDelay (Node* node, Message* msg)
{
    IAHEPRoutingMsgInfoType *routingInfoType = NULL;

    routingInfoType = (IAHEPRoutingMsgInfoType*)
        MESSAGE_ReturnInfo(
        msg,
        INFO_TYPE_IAHEP_RUTNG);

    if (routingInfoType)
    {
        switch (routingInfoType->inOut)
        {
            case 'o':
            {
                MESSAGE_RemoveInfo (node, msg, INFO_TYPE_IAHEP_RUTNG);
                NetworkIpSendPacketOnInterface(
                    node,
                    msg,
                    CPU_INTERFACE,
                    IAHEPGetIAHEPBlackInterfaceIndex(node),
                    0);

                break;
            }
            case 'i':
            {
                NetworkIpReceivePacket(
                    node,
                    msg,
                    routingInfoType->previousHopAddress,
                    IAHEPGetIAHEPRedInterfaceIndex(node));
                MESSAGE_RemoveInfo (node, msg, INFO_TYPE_IAHEP_RUTNG);

                break;
            }
            default:
            {
                ERROR_Assert(FALSE, "IAHEP Routing Packet: "
                    "Unknown event type\n");
            }
        }

    }
}

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPSendPktAfterProcessingDelay
// LAYER               :: Network
// PURPOSE    :: Function to to Send The Pkt after Encryption and Auth Delay
// PARAMETERS          ::
// + node      : Node*    : The node processing the event
// + msg       : Message* : Event that expired
// + char      : inOut
// + NodeAddress : previousHopAddress
// + clocktype : delay
// RETURN     :: void : NULL
//---------------------------------------------------------------------------
void IAHEPSendPktAfterProcessingDelay(Node* node,
                                      Message* msg,
                                      char inOut,
                                      NodeAddress previousHopAddress,
                                      clocktype delay)
{
    IAHEPRoutingMsgInfoType *routingInfoType = NULL;

    MESSAGE_AddInfo(
        node,
        msg,
        sizeof(IAHEPRoutingMsgInfoType),
        INFO_TYPE_IAHEP_RUTNG);

    routingInfoType = (IAHEPRoutingMsgInfoType*)
        MESSAGE_ReturnInfo(
        msg,
        INFO_TYPE_IAHEP_RUTNG);

    ERROR_Assert(routingInfoType, "IAHEPRouting: Fail to "
        "allocate an info field.");

    memset(routingInfoType, 0, sizeof(IAHEPRoutingMsgInfoType));
    routingInfoType->inOut = inOut;
    routingInfoType->previousHopAddress = previousHopAddress;

    MESSAGE_SetLayer(
        msg,
        NETWORK_LAYER,
        NETWORK_PROTOCOL_IP);
    MESSAGE_SetEvent(msg, MSG_NETWORK_IAHEP);
    MESSAGE_Send(node, msg, delay);
}

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPGetMulticastBroadcastAddressMapping
// LAYER      :: Network
// PURPOSE    :: Function returns Muitlcast-broadcast address to Red Node
// PARAMETERS ::
// + node           : Pointer of Node Type
// + iahepData      : IAHEPData*    : Pointer to IAHEPData structure
// + addr: NodeAddress : Address in Header of incoming packet
// RETURN     :: NodeAddress
//---------------------------------------------------------------------------
NodeAddress IAHEPGetMulticastBroadcastAddressMapping(
    Node *node,
    IAHEPData* iahepData,
    NodeAddress addr)
{
    Int32 temp1 = 0;
    NodeAddress temp2 = 0;
    map<NodeAddress,NodeAddress>::iterator it;
    it = iahepData->multicastAmdMapping->find(addr);

    //If Join for Group 239.255.255.255 is recieved from
    //Red node, AMD Data structures should not be checked
    if (addr == BROADCAST_MULTICAST_MAPPEDADDRESS)
    {
        return BROADCAST_MULTICAST_MAPPEDADDRESS;
    }


    if (it != iahepData->multicastAmdMapping->end())
    {
        return it->second;
    }
    else if (IsOutgoingBroadcast(node, addr, &temp1, &temp2))
    {
        return BROADCAST_MULTICAST_MAPPEDADDRESS;
    }

    NodeAddress multicastAddr;
    multicastAddr = addr + DEFAULT_RED_BLACK_MULTICAST_MAPPING;

    if (multicastAddr >= IP_MAX_MULTICAST_ADDRESS ||
        multicastAddr < IP_MIN_RESERVED_MULTICAST_ADDRESS)
    {
        char errStr[MAX_STRING_LENGTH];
        char grpStr[MAX_ADDRESS_STRING_LENGTH];

        IO_ConvertIpAddressToString(multicastAddr, grpStr);
        sprintf(errStr, "IAHEP node %d, Red Multicast Address maps to "
            "an invalid Black Multicast Address %s\n",
            node->nodeId, grpStr);
        ERROR_ReportError(errStr);
    }

    return (multicastAddr);
}


//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPCheckEntriesInAMDTable
// LAYER      :: Network
// PURPOSE    :: This Function provides checking on AMD File Entries
// PARAMETERS          ::
// + node      : Node*    : The node processing the event
// + NodeAddress          : remoteRedIPAddress
// + NodeAddress          : remoteBlackIPAddress
// + UInt8                : MLSLevel
// + int                  : numOfValuesInFile
// RETURN     :: void
//---------------------------------------------------------------------------
void IAHEPCheckEntriesInAMDTable(Node* node, NodeAddress remoteRedIPAddress,
                                 NodeAddress remoteBlackIPAddress,
                                 UInt32 mlsRead,
                                 UInt32 numOfValuesInFile)
{
    char errStr[MAX_STRING_LENGTH];
    BOOL fstVarMcast = FALSE;
    BOOL scndVarMcast = FALSE;
    BOOL fstVarBcast = FALSE;
    BOOL scndVarBcast = FALSE;
    Int32 iahepoutgoingInterfaceToUse = ANY_INTERFACE;
    NodeAddress iahepoutgoingBroadcastAddress = ANY_ADDRESS;

    if (mlsRead < 1 || mlsRead > 255)
    {
        sprintf(errStr, "\nWrong MLS Level In AMD-File: %d\n", mlsRead);
        ERROR_Assert(FALSE, errStr);
    }

    if (NetworkIpIsMulticastAddress(node, remoteRedIPAddress))
    {
        fstVarMcast = TRUE;
    }

    if (NetworkIpIsMulticastAddress(node, remoteBlackIPAddress))
    {
        scndVarMcast = TRUE;
    }

    if (IsOutgoingBroadcast(
        node,
        remoteRedIPAddress,
        &iahepoutgoingInterfaceToUse,
        &iahepoutgoingBroadcastAddress))
    {
        fstVarBcast = TRUE;
    }

    if (IsOutgoingBroadcast(
        node,
        remoteBlackIPAddress,
        &iahepoutgoingInterfaceToUse,
        &iahepoutgoingBroadcastAddress))
    {
        scndVarBcast = TRUE;
    }

    if (numOfValuesInFile == 3 || numOfValuesInFile == 2)
    {
        if ((fstVarMcast || fstVarBcast) && scndVarMcast)
        {
            return;
        }

        //Both Var are Unicast
        if (!fstVarMcast && !scndVarMcast && !fstVarBcast && !scndVarBcast)
        {
            return;
        }
        ERROR_Assert(FALSE, "Wrong Configuration in IAHEP-AMD-FILE");

    }
    else
    {
        ERROR_Assert(FALSE, "Entry Can Have 2 or 3 Parameters in IAHEP "
            "AMD File");
    }
}

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPUpdateAMDTableFromAMDFile
// LAYER      :: Network
// PURPOSE    :: This Function is to Update the AMD Table data Structure
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + NodeAddress          : remoteRedIPAddress
// + NodeAddress          : remoteBlackIPAddress
// + UInt8                : MLS Level
// RETURN     :: BOOL
//---------------------------------------------------------------------------
BOOL IAHEPUpdateAMDTableFromAMDFile(Node* node,
                                    NodeAddress remoteRedIPAddress,
                                    NodeAddress remoteBlackIPAddress,
                                    UInt32 remoteMLSLevelStore)
{
    char errStr[MAX_STRING_LENGTH];
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    UInt32 blackInterfaceIndex = NetworkIpGetInterfaceIndexFromAddress(
        node, remoteBlackIPAddress);

    IAHEPAmdMappingType *mapping = IAHEPGetAMDInfoForDestinationRedAddress(
        node,
        remoteRedIPAddress);

    if (mapping != NULL)
    {
        // We are allowed to have multiple black references
        // for each red reference.  If the mapping lookup
        // found an entry, we only add our new entry if the
        // found entry also has the same black address.
        // MAC 2009/11/17
        /*if (mapping->destBlackInterface == remoteBlackIPAddress)
        {
        ERROR_ReportWarning("\nDuplicate Entries Exist In AMD File \n");
        retVal = TRUE;
        }*/
    }

    UInt8 mlsLevel = 1;
    mlsLevel = (UInt8) remoteMLSLevelStore;
    ip->iahepData->updateAmdTable->AMDInsertAtEnd(
        remoteBlackIPAddress,
        remoteRedIPAddress,
        mlsLevel);


    //Lets Store Self MLS Level, Local Black From This Entry
    if (blackInterfaceIndex != ANY_INTERFACE)
    {
        if (remoteMLSLevelStore)
        {
            // remoteMLSLevelStore is a UInt8 with a valid value range
            // from 0 to 255.
            // It cannot ever be greater than 255 and so checking for
            // that condition is unnecessary.
            if (remoteMLSLevelStore < 1)
            {
                sprintf(errStr, "\nNode [%d] Wrong MLS Level In AMD "
                    "File: [%d]\n", node->nodeId,
                    remoteMLSLevelStore);
                ERROR_Assert(FALSE, errStr);
            }

            ip->iahepData->MLSSecurityLevel = (UInt8)remoteMLSLevelStore;
        }
        else
        {
            ip->iahepData->MLSSecurityLevel = 1;
        }
        ip->iahepData->localBlackAddress = remoteBlackIPAddress;
    }
    return TRUE;
}


//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPCreateIgmpJoinLeaveMessage
// LAYER      :: Network
// PURPOSE    :: Function creates and send IGMP Join and Leave message for
//               IAHEP multicast
// PARAMETERS          ::
// + node      : Node*    : The node processing the event
// + grpAddr   : NodeAddress    : Red multicast groupaddress
//+ messageType   : unsigned char    : Join or Leave IGMP message
// RETURN     :: Void
//---------------------------------------------------------------------------
void IAHEPCreateIgmpJoinLeaveMessage(Node* node,
                                     NodeAddress grpAddr,
                                     unsigned char messageType,
                                     IgmpMessage* igmpPkt,
                                     NodeAddress* srcAddr)
{
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    Message* igmpMessage = NULL;
    int intfId = ANY_INTERFACE;

    igmpMessage = MESSAGE_Alloc(node,
        NETWORK_LAYER,
        GROUP_MANAGEMENT_PROTOCOL_IGMP,
        MSG_NETWORK_IgmpData);

    MESSAGE_PacketAlloc(node,
        igmpMessage,
        sizeof(IgmpMessage),
        TRACE_IGMP);

    IgmpCreatePacket(igmpMessage, messageType, 0, grpAddr);
    if (srcAddr != NULL)
    {
        MESSAGE_AddInfo(node, igmpMessage, sizeof(NodeAddress),
                        INFO_TYPE_SourceAddr);
        memcpy(MESSAGE_ReturnInfo(igmpMessage, INFO_TYPE_SourceAddr),
               srcAddr,
               sizeof(NodeAddress));
    }

    if (igmpPkt)
    {
        memcpy((IgmpMessage*) MESSAGE_ReturnPacket(igmpMessage),
            (IgmpMessage*) igmpPkt,
            sizeof(IgmpMessage));
    }
    if (ip->iahepData->nodeType == IAHEP_NODE)
    {
        //In Case Of IGMP_Query, Send It To Red Node.
        if (messageType == IGMP_QUERY_MSG)
        {
            intfId = IAHEPGetIAHEPRedInterfaceIndex(node);
        }
        else
        {
            intfId = IAHEPGetIAHEPBlackInterfaceIndex(node);
        }
    }
    else if (ip->iahepData->nodeType == RED_NODE)
    {
        intfId = IAHEPGetIAHEPRedInterfaceIndex(node);
        // add/delete the group to the red interface's host list
        IgmpIahepUpdateGroupOnRedIntf(node, intfId, messageType, grpAddr);
    }

    if (intfId != ANY_INTERFACE)
    {
        IAHEPSendIGMPMessageToMacLayer(
            node,
            igmpMessage,
            NetworkIpGetInterfaceAddress(node, intfId),
            grpAddr,
            IPTOS_PREC_INTERNETCONTROL,
            IPPROTO_IGMP,
            1,
            intfId,
            ANY_DEST);
    }
    else
    {
        MESSAGE_Free(node, igmpMessage);
    }
}

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPGetBlackDestinationAddressForPkt
// LAYER      :: Network
// PURPOSE    :: Function to Get Destination Black IP Address
// PARAMETERS          ::
// + node      : Node*    : The node processing the event
//+ message   : Message *
//+ NodeAddres: unsigned int
// RETURN     :: NodeAddress
//---------------------------------------------------------------------------
NodeAddress IAHEPGetBlackDestinationAddressForPkt(Node *node, Message* msg,
                                             NodeAddress destRedAddrRecieved)
{
    Int32 temp1 = 0;
    NodeAddress temp2 = 0;
    NodeAddress destBlackAddress = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;
    IpHeaderType* ipHdr = (IpHeaderType*) (MESSAGE_ReturnPacket(msg) +
        sizeof(IahepMLSHeader));

    if (NetworkIpIsMulticastAddress(node, ipHdr->ip_dst))
    {
        destBlackAddress = IAHEPGetMulticastBroadcastAddressMapping(
            node, ip->iahepData, ipHdr->ip_dst);
    }
    else if (IsOutgoingBroadcast(
        node,
        ipHdr->ip_dst,
        &temp1,
        &temp2))
    {
        ipHdr->ip_dst = ANY_DEST;
        destBlackAddress = IAHEPGetMulticastBroadcastAddressMapping(
            node, ip->iahepData, ipHdr->ip_dst);
    }
    else // Must Be Unicast Pkt
    {
        for (Int32 i = 0; i < ip->iahepData->updateAmdTable->sizeOfAMDTable();
            i++)
        {
            if (ip->iahepData->updateAmdTable->getAMDTable(i)->
                destRedInterface == destRedAddrRecieved)
            {
                destBlackAddress = ip->iahepData->updateAmdTable->
                    getAMDTable(i)->destBlackInterface;
                break;
            }
        }
    }
    return destBlackAddress;
}

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPAddDestinationRedHeader
// LAYER      :: Network
// PURPOSE    :: Function to Send Remote Red Information To Directly Connected
//              : IAHEP Node
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + message   : Message * : packet with red IP header on it
// + nextHop   : NodeAddress : red nextHop address
// RETURN     :: void
//---------------------------------------------------------------------------
void IAHEPAddDestinationRedHeader(Node *node, Message *msg, NodeAddress nextHop)
{
    //Adding Info For Next Hop
    NodeAddress *nextHopInfo = NULL;

    nextHopInfo = (NodeAddress*)MESSAGE_AddInfo(node,
                                                msg,
                                                sizeof(NodeAddress),
                                                INFO_TYPE_IAHEP_NextHop);

    *nextHopInfo = nextHop;
}

