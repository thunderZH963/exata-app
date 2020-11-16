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

/*
 * PURPOSE:         Multicast static routing.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "network_ip.h"
#include "ipv6.h"
#include "multicast_static.h"

/*
 * NAME:        RoutingMulticastStaticInit.
 *
 * PURPOSE:     Handling all initializations needed by multicast static routing.
 *
 * PARAMETERS:  node, node doing the initialization.
 *              nodeInput, input from configuration file.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */
void
RoutingMulticastStaticInit(Node *node, const NodeInput *nodeInput)
{
    int i;
    NodeInput routeInput;
    BOOL retVal;
    IO_ReadCachedFile(node->nodeId,
                         ANY_ADDRESS,
                         nodeInput,
                         "MULTICAST-STATIC-ROUTE-FILE",
                         &retVal,
                         &routeInput);

    if (retVal == FALSE)
    {
        printf("RoutingMulticastStatic: Missing "
               "MULTICAST-STATIC-ROUTE-FILE.\n");
        abort();
    }

    NetworkInitMulticastForwardingTable(node);

    for (i = 0; i < routeInput.numLines; i++)
    {
        char sourceAddressString[MAX_STRING_LENGTH];
        char mcastAddressString[MAX_STRING_LENGTH];
        char nextInterfaceString[MAX_STRING_LENGTH];
        NodeAddress nodeId;
        int numParameters;
        int length;
        char *inputStr;
        int val;
        BOOL isIpv6 = FALSE;

        inputStr = routeInput.inputStrings[i];
        length = (int)strlen(inputStr);
        assert(length > 0);

        while (inputStr[0] == ' ')
        {
            inputStr++;
        }

        numParameters = sscanf(
                  inputStr,
                  "%u",
                  &nodeId);

        while (inputStr[0] != ' ')
        {
            inputStr++;
        }

        while (inputStr[0] == ' ')
        {
            inputStr++;
        }

        numParameters = sscanf(
                  inputStr,
                  "%s",
                  sourceAddressString);

        while (inputStr[0] != ' ')
        {
            inputStr++;
        }

        while (inputStr[0] == ' ')
        {
            inputStr++;
        }

        numParameters = sscanf(
                  inputStr,
                  "%s",
                  mcastAddressString);

        while (inputStr[0] != ' ')
        {
            inputStr++;
        }

        while (inputStr[0] == ' ')
        {
            inputStr++;
        }

        numParameters = sscanf(
                  inputStr,
                  "%s",
                  nextInterfaceString);

        if (nodeId == node->nodeId)
        {
            Address sourceAddress;
            int sourceNumSubnetBits;
            Address mcastAddress;
            int mcastNumSubnetBits;
            Address nextInterfaceAddress;
            int nextInterfaceSubnetBits;
            BOOL isNodeId;
            NodeId nodeId = 0;
            BOOL isIpAddr;
            int interfaceIndex;
            UInt32 prefixLen = 0;

            if (MAPPING_GetNetworkIPVersion(mcastAddressString)
                == NETWORK_IPV6)
            {
                isIpv6 = TRUE;

                sourceAddress.networkType = NETWORK_IPV6;

                IO_ParseNodeIdHostOrNetworkAddress(
                    sourceAddressString,
                    &sourceAddress.interfaceAddr.ipv6,
                    &isIpAddr,
                    &nodeId);

                assert(nodeId == FALSE);

                mcastAddress.networkType = NETWORK_IPV6;

                IO_ParseNodeIdHostOrNetworkAddress(
                    mcastAddressString,
                    &mcastAddress.interfaceAddr.ipv6,
                    &isIpAddr,
                    &nodeId,
                    &prefixLen);

                assert(nodeId == FALSE);

                if (strchr(nextInterfaceString, '.'))
                {
                    nextInterfaceAddress.networkType = NETWORK_IPV4;

                    IO_ParseNodeIdHostOrNetworkAddress(
                        nextInterfaceString + 2,
                        &nextInterfaceAddress.interfaceAddr.ipv4,
                        &nextInterfaceSubnetBits,
                        &isNodeId);
                }
                else
                {
                    nextInterfaceAddress.networkType = NETWORK_IPV6;

                    IO_ParseNodeIdHostOrNetworkAddress(
                        nextInterfaceString,
                        &nextInterfaceAddress.interfaceAddr.ipv6,
                        &isIpAddr,
                        &nodeId,
                        &prefixLen);
                }

                assert(nodeId == FALSE);
            }
            else
            {
                sourceAddress.networkType = NETWORK_IPV4;

                IO_ParseNodeIdHostOrNetworkAddress(
                    sourceAddressString,
                    &sourceAddress.interfaceAddr.ipv4,
                    &sourceNumSubnetBits,
                    &isNodeId);

                assert(isNodeId == FALSE);

                mcastAddress.networkType = NETWORK_IPV4;

                IO_ParseNodeIdHostOrNetworkAddress(
                    mcastAddressString,
                    &mcastAddress.interfaceAddr.ipv4,
                    &mcastNumSubnetBits,
                    &isNodeId);

                assert(isNodeId == FALSE);

                assert(mcastAddress.interfaceAddr.ipv4
                        >= IP_MIN_MULTICAST_ADDRESS);

                nextInterfaceAddress.networkType = NETWORK_IPV4;

                IO_ParseNodeIdHostOrNetworkAddress(
                    nextInterfaceString,
                    &nextInterfaceAddress.interfaceAddr.ipv4,
                    &nextInterfaceSubnetBits,
                    &isNodeId);

                assert(isNodeId == FALSE);

                if (nextInterfaceSubnetBits != 0)
                {
                    printf("RoutingMulticastStatic: Next hop address can't"
                            " be a subnet\n  %s\n",
                        routeInput.inputStrings[i]);

                    abort();
                }
            }

            interfaceIndex = RoutingMulticastStaticGetInterfaceIndex(
                                node,
                                nextInterfaceAddress);

            assert(interfaceIndex != -1);

            if (isIpv6)
            {
                Ipv6UpdateMulticastForwardingTable(
                    node,
                    GetIPv6Address(sourceAddress),
                    GetIPv6Address(mcastAddress),
                    interfaceIndex);
            }
            else
            {
                NetworkUpdateMulticastForwardingTable(
                    node,
                    GetIPv4Address(sourceAddress),
                    GetIPv4Address(mcastAddress),
                    interfaceIndex);
            }

            while (inputStr[0] != ' ' &&
                   inputStr[0] != '\n' &&
                   inputStr[0] != '\0')
            {
                inputStr++;
            }

            length = (int)strlen(inputStr);

            while (inputStr[0] == ' ' && length > 0)
            {
                inputStr++;
            }

            while (inputStr[0] != '\n' && inputStr[0] != '\0')
            {
                val = sscanf(inputStr, "%s", nextInterfaceString);

                if (isIpv6)
                {
                    if (strchr(nextInterfaceString, '.'))
                    {
                        nextInterfaceAddress.networkType = NETWORK_IPV4;

                        IO_ParseNodeIdHostOrNetworkAddress(
                            nextInterfaceString + 2,
                            &nextInterfaceAddress.interfaceAddr.ipv4,
                            &nextInterfaceSubnetBits,
                            &isNodeId);
                    }
                    else
                    {
                        nextInterfaceAddress.networkType = NETWORK_IPV6;

                        IO_ParseNodeIdHostOrNetworkAddress(
                            nextInterfaceString,
                            &nextInterfaceAddress.interfaceAddr.ipv6,
                            &isIpAddr,
                            &nodeId,
                            &prefixLen);
                    }

                    assert(nodeId == FALSE);
                }
                else
                {
                    nextInterfaceAddress.networkType = NETWORK_IPV4;

                    IO_ParseNodeIdHostOrNetworkAddress(
                        nextInterfaceString,
                        &nextInterfaceAddress.interfaceAddr.ipv4,
                        &nextInterfaceSubnetBits,
                        &isNodeId);

                    assert(isNodeId == FALSE);

                    if (nextInterfaceSubnetBits != 0)
                    {
                        printf("RoutingMulticastStatic: "
                                "Next hop address can't be a subnet\n  %s\n",
                            routeInput.inputStrings[i]);

                        abort();
                    }
                }

                interfaceIndex = RoutingMulticastStaticGetInterfaceIndex(
                                    node,
                                    nextInterfaceAddress);

                assert(interfaceIndex != -1);

                if (isIpv6)
                {
                    Ipv6UpdateMulticastForwardingTable(
                        node,
                        GetIPv6Address(sourceAddress),
                        GetIPv6Address(mcastAddress),
                        interfaceIndex);
                }
                else
                {
                    NetworkUpdateMulticastForwardingTable(
                        node,
                        GetIPv4Address(sourceAddress),
                        GetIPv4Address(mcastAddress),
                        interfaceIndex);
                }

                while (inputStr[0] != ' ' &&
                       inputStr[0] != '\n' &&
                       inputStr[0] != '\0')
                {
                    inputStr++;
                }

                length = (int)strlen(inputStr);

                while (inputStr[0] == ' ' && length > 0)
                {
                    inputStr++;
                }
            }
        }
    }//for//
}

/*
 * NAME:        RoutingMulticastStaticLayer.
 *
 * PURPOSE:     Handles all messages sent to network layer.
 *
 * PARAMETERS:  node, node receiving message.
 *              msg, message for node to interpret.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */
void
RoutingMulticastStaticLayer(Node *node, const Message *msg)
{
    char clockStr[MAX_STRING_LENGTH];

    ctoa(node->getNodeTime(), clockStr);
    printf("RoutingMulticastStatic: Got unknown event type %d\n", msg->eventType);
    assert(FALSE); abort();
}

/*
 * NAME:        RoutingMulticastStaticFinalize.
 *
 * PURPOSE:     Handling all finalization needed by multicast static routing.
 *
 * PARAMETERS:  node, node doing the finalization.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */
void
RoutingMulticastStaticFinalize(Node *node)
{
    /* No finalize instructions. */
}

int RoutingMulticastStaticGetInterfaceIndex(Node* node, Address addr)
{
    int interfaceIndex = -1;

    if (addr.networkType == NETWORK_IPV4)
    {
        interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(
                            node,
                            GetIPv4Address(addr));
    }
    else
    {
        interfaceIndex = Ipv6GetInterfaceIndexFromAddress(
                            node,
                            &addr.interfaceAddr.ipv6);
    }

    return interfaceIndex;
}
