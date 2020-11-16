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

#include "api.h"
#include "network_ip.h"
#include "ipv6.h"
#include "routing_static.h"



/*
 * NAME:        RoutingStaticInit.
 *
 * PURPOSE:     Handling all initializations needed by static routing.
 *
 * PARAMETERS:  node, node doing the initialization.
 *              nodeInput, input from configuration file.
 *              type, either STATIC or DEFAULT routes.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */
void
RoutingStaticInit(
    Node *node,
    const NodeInput *nodeInput,
    NetworkRoutingProtocolType type)
{
    int i;
    NodeInput routeInput;
    BOOL retVal;


    IO_ReadCachedFile(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "STATIC-ROUTE-FILE",
        &retVal,
        &routeInput);

    if (type == ROUTING_PROTOCOL_STATIC)
    {
        if (retVal == FALSE)
        {
            ERROR_ReportError("RoutingStatic: Missing STATIC-ROUTE-FILE.\n");
        }
    }
    else if (type == ROUTING_PROTOCOL_DEFAULT)
    {
        IO_ReadCachedFile(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "DEFAULT-ROUTE-FILE",
            &retVal,
            &routeInput);

        if (retVal == FALSE)
        {
            ERROR_ReportError("RoutingStatic: Missing DEFAULT-ROUTE-FILE.\n");
        }
    }
    else
    {
        ERROR_ReportError("Only static or default routes are supported.");
    }


    for (i = 0; i < routeInput.numLines; i++)
    {
        char destAddressString[MAX_STRING_LENGTH];
        char nextHopString[MAX_STRING_LENGTH];
        NodeAddress sourceAddress;
        int cost = 1;
        int outgoingInterfaceIndex = ANY_INTERFACE;
        NodeAddress outgoingInterfaceAddress = 0;
        char outgoingInterfaceAddressStr[MAX_STRING_LENGTH];
        int outgoingHostBits;

        NodeAddress destAddress;
        int destNumHostBits;
        NodeAddress nextHopAddress;
        int nextHopHostBits;
        BOOL isNodeId;

        // For IO_GetDelimitedToken
        char* next;
        const char* delims = " \t\n";
        char* token = NULL;
        char iotoken[MAX_STRING_LENGTH];
        char currentLine[MAX_STRING_LENGTH];

        char err[MAX_STRING_LENGTH];

        strcpy(currentLine, routeInput.inputStrings[i]);

        token = IO_GetDelimitedToken(iotoken, currentLine, delims, &next);

        if (!isdigit(*token))
        {
            sprintf(err, "Static Routing: First argument must be node id:\n"
                "%s", routeInput.inputStrings[i]);
            ERROR_ReportError(err);
        }

        // Get source node.
        sourceAddress = atoi(token);

        if (sourceAddress != node->nodeId)
        {
            continue;
        }

        // Retrieve next token.
        token = IO_GetDelimitedToken(iotoken, next, delims, &next);

        if (token == NULL)
        {
            sprintf(err,
                "Static Routing: Wrong arguments:\n %s",
                routeInput.inputStrings[i]);
            ERROR_ReportError(err);
        }

        // Get destination address.
        strcpy(destAddressString, token);
        // if the static routing is of ipv6.
        if ((strstr(destAddressString, "SLA") == NULL) &&
            (strchr(destAddressString, ':') == NULL))
        {
            IO_ParseNodeIdHostOrNetworkAddress(
                destAddressString,
                &destAddress,
                &destNumHostBits,
                &isNodeId);

            if (isNodeId)
            {
                sprintf(err, "Static Routing: destination must be a network or "
                        "host address\n  %s\n", routeInput.inputStrings[i]);

                ERROR_ReportError(err);
            }

            // Retrieve next token.
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            if (token == NULL)
            {
                sprintf(err,
                    "Static Routing: Wrong arguments:\n %s",
                    routeInput.inputStrings[i]);
                ERROR_ReportError(err);
            }

            // Get next hop address.
            strcpy(nextHopString, token);

            IO_ParseNodeIdHostOrNetworkAddress(
                nextHopString,
                &nextHopAddress,
                &nextHopHostBits,
                &isNodeId);

            if (nextHopHostBits != 0 || isNodeId)
            {
                sprintf(err, "Static Routing: Next hop address must be an "
                        "interface address\n  %s\n", routeInput.inputStrings[i]);

                ERROR_ReportError(err);

            }

            // Retrieve next token.
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);

            // Outgoing interface address is optional.
            if (token != NULL && strchr(token, '.'))
            {
                // Get outgoing interface address.
                strcpy(outgoingInterfaceAddressStr, token);

                IO_ParseNodeIdHostOrNetworkAddress(
                    outgoingInterfaceAddressStr,
                    &outgoingInterfaceAddress,
                    &outgoingHostBits,
                    &isNodeId);

                if (outgoingHostBits != 0 || isNodeId)
                {
                    sprintf(err, "Static Routing: Next hop address must be an "
                        "interface address\n  %s\n", routeInput.inputStrings[i]);

                    ERROR_ReportError(err);
                }

                outgoingInterfaceIndex = NetworkIpGetInterfaceIndexFromAddress(
                                             node,
                                             outgoingInterfaceAddress);

                // Retrieve next token.
                token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            }

            // Cost of the route is optional.
            if (token != NULL)
            {
                // Get cost of the route.
                cost = atoi(token);

                // Retrieve next token.
                token = IO_GetDelimitedToken(iotoken, next, delims, &next);

                if (token != NULL)
                {
                    sprintf(err, "Static Routing: wrong arguements:\n  %s\n",
                        routeInput.inputStrings[i]);
                    ERROR_ReportError(err);
                }
            }

            NetworkUpdateForwardingTable(
                node,
                destAddress,
                ConvertNumHostBitsToSubnetMask(destNumHostBits),
                nextHopAddress,
                outgoingInterfaceIndex,
                cost,
                type);
        }
        else
        {
            // Ipv6 entry point.
            if (type == ROUTING_PROTOCOL_DEFAULT)
            {
                //Set the defaultRouteFlag to TRUE, this is used in rn_match
                //to search for default route when no route for destination
                // host or network. is found.
                ((IPv6Data*) node->networkData.networkVar->ipv6)
                                        ->defaultRouteFlag = TRUE;
            }
            Ipv6RoutingStaticEntry(
                    node,
                    routeInput.inputStrings[i]);
        }
    }
}

/*
 * NAME:        RoutingStaticLayer.
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
RoutingStaticLayer(Node *node, const Message *msg)
{
    char clockStr[MAX_STRING_LENGTH];

    ctoa(node->getNodeTime(), clockStr);
    printf("RoutingStatic: Got unknown event type %d\n", msg->eventType);
#ifndef EXATA
    assert(FALSE); abort();
#endif
}

/*
 * NAME:        RoutingStaticFinalize.
 *
 * PURPOSE:     Handling all finalization needed by static routing.
 *
 * PARAMETERS:  node, node doing the finalization.
 *
 * RETURN:      None.
 *
 * ASSUMPTION:  None.
 */
void
RoutingStaticFinalize(Node *node)
{
    /* No finalize instructions. */
}

