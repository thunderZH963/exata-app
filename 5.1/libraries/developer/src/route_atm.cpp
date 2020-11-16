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
// PROTOCOL     :: ATM-Static-Route.
// LAYER        :: ADAPTATION.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// COMMENTS     :: None
// **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "network_ip.h"
#include "atm.h"
#include "adaptation_aal5.h"
#include "route_atm.h"

#define DEBUG 0


// /**
// FUNCTION    :: AtmRoutingStaticInit
// LAYER       :: Adaptation
// PURPOSE     :: Handling all initializations needed by static routing.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput* : Pointer to config file.
// RETURN       : void : None
// **/
void AtmRoutingStaticInit(Node *node, const NodeInput *nodeInput)
{
    int i;
    NodeInput atmRouteInput;
    BOOL retVal;

    IO_ReadCachedFile(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-STATIC-ROUTE-FILE",
        &retVal,
        &atmRouteInput);

    if (!retVal)
    {
        ERROR_Assert(FALSE,
            "You must specified ATM-STATIC-ROUTE-FILE for ATM Route\n");
    }

    for (i = 0; i < atmRouteInput.numLines; i++)
    {
        char destAddressString[MAX_STRING_LENGTH];
        char outIntfString[MAX_STRING_LENGTH];
        int outIntfId = ANY_INTERFACE;
        NodeAddress sourceAddress;

        AtmAddress destAtmAddr;
        AtmAddress nextAtmNode;

        BOOL isAtmAddr = FALSE;
        NodeId nodeId;

        // For IO_GetDelimitedToken
        char* next;
        const char* delims = " \t\n";
        char* token = NULL;
        char iotoken[MAX_STRING_LENGTH];
        char currentLine[MAX_STRING_LENGTH];

        char err[MAX_STRING_LENGTH];

        strcpy(currentLine, atmRouteInput.inputStrings[i]);

        // Get first Token
        token = IO_GetDelimitedToken(iotoken, currentLine, delims, &next);

        if (!isdigit(*token))
        {
            sprintf(err, "Static Routing: First argument must be node id:\n"
                "%s", atmRouteInput.inputStrings[i]);
            ERROR_ReportError(err);
        }

        // First token is Source NodeId
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
                atmRouteInput.inputStrings[i]);
            ERROR_ReportError(err);
        }

        // second token should be destination address
        strcpy(destAddressString, token);

        // This Dest-Address is ATM Address

        IO_ParseNodeIdHostOrNetworkAddress(
            destAddressString,
            &destAtmAddr,
            &isAtmAddr,
            &nodeId);

        if (nodeId)
        {
            sprintf(err, "Static Routing: destination must be a network or "
                "host address\n  %s\n", atmRouteInput.inputStrings[i]);

            ERROR_ReportError(err);
        }
        else if (isAtmAddr)
        {
            // check if it is a network address
            // or interface specific part
            if (destAtmAddr.ESI_pt1 != 0)
            {
                // It is interface specific Addr
                // get the addr from mapping

                unsigned int u_atmVal[] = {0, 0, 0};
                int node1AtmInterface;
                int node1GenericInterface;

                // Generate ATM network address
                u_atmVal[0] = destAtmAddr.ICD;
                u_atmVal[1] = destAtmAddr.aid_pt1;
                u_atmVal[2] = destAtmAddr.aid_pt2;

                Address readAddr = MAPPING_GetNodeInfoFromAtmNetInfo(node,
                    destAtmAddr.ESI_pt1,
                    &node1AtmInterface,
                    &node1GenericInterface,
                    u_atmVal);

                ERROR_Assert(node1GenericInterface != -1,
                                " Error in ATM-STATIC-ROUTE-FILE\n");

                memcpy(&destAtmAddr,
                    &readAddr.interfaceAddr.atm,
                    sizeof(AtmAddress));
            }


        }

        // Retrieve next token.
        token = IO_GetDelimitedToken(iotoken, next, delims, &next);

        if (token == NULL)
        {
            sprintf(err,
                "Static Routing: Wrong arguments:\n %s",
                atmRouteInput.inputStrings[i]);
            ERROR_ReportError(err);
        }

        // Final Token should be My outgoing Interface Id
        // this is the interface which is directly connected
        // to next network element i.e. ATM Switch
        strcpy(outIntfString, token);
        outIntfId = atoi(outIntfString);

        // Get ATM Addr for Dest
        // AALGetAtmAddressForIPAddr(node, destAddress, &destAtmAddr);

        // Get NextHop ATM switch Addr

        Address nextHopAddr =
            Atm_GetAddrForOppositeNodeId(node, outIntfId);

        memcpy(&nextAtmNode,
            &nextHopAddr.interfaceAddr.atm,
            sizeof(AtmAddress));

        Aal5UpdateFwdTable(node, outIntfId,
            &destAtmAddr, &nextAtmNode);
    }
}


// /**
// FUNCTION    :: AtmRoutingStaticLayer
// LAYER       :: Adaptation
// PURPOSE     :: Handles all messages sent to network layer.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : const Message* : Pointer to message.
// RETURN       : void : None
// **/
void AtmRoutingStaticLayer(Node *node, const Message *msg)
{
    char clockStr[MAX_STRING_LENGTH];

    ctoa(node->getNodeTime(), clockStr);
    printf("RoutingStatic: Got unknown event type %d\n", msg->eventType);
    assert(FALSE); abort();
}


// /**
// FUNCTION    :: AtmRoutingStaticFinalize
// LAYER       :: Adaptation
// PURPOSE     :: Handling all finalization needed by static routing.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void AtmRoutingStaticFinalize(Node *node)
{
    if (DEBUG)
    {
        printf(" node %u call finalize \n", node->nodeId);
    }
}

