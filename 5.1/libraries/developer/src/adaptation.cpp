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
// PROTOCOL     :: Adaptation.
// LAYER        :: ADAPTATION.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// COMMENTS     :: None
// **/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "network_ip.h"
#include "adaptation_aal5.h"

//-----------------------------------------------------------------------
// DEFINES (none)
//-----------------------------------------------------------------------

//-----------------------------------------------------------------------
// STRUCTS, ENUMS, AND TYPEDEFS (none)
//-----------------------------------------------------------------------

//-----------------------------------------------------------------------
// PROTOTYPES FOR FUNCTIONS WITH INTERNAL LINKAGE (none)
//-----------------------------------------------------------------------

//-----------------------------------------------------------------------
// FUNCTIONS WITH EXTERNAL LINKAGE
//-----------------------------------------------------------------------

//-----------------------------------------------------------------------
// Init functions
//-----------------------------------------------------------------------


// /**
// FUNCTION    :: ADAPTATION_Initialize
// LAYER       :: Adaptation
// PURPOSE     :: Initialization function for adaptation layer.
//                Initializes AAL5.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + nodeInput : const NodeInput* : Pointer to config file.
// RETURN       : void : None
// **/
void ADAPTATION_Initialize(Node *node, const NodeInput *nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;

    // presently this is working only for ATM Node

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-NODE",
        &retVal,
        buf);

    if (!retVal)
    {
        // It is not an ATM node,
        // hence no adaptation protocol required

        node->adaptationData.adaptationProtocol =
            ADAPTATION_PROTOCOL_NONE;
        return;
    }

    // Presently this parameter is checked for ATM Only
    // Adaptation parameter is a node specific value
    // Init the type of adaptation node
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-END-SYSTEM",
        &retVal,
        buf);

    if (retVal && !strcmp(buf, "YES"))
    {
        node->adaptationData.endSystem = TRUE;
        node->adaptationData.genlSwitch = FALSE;
    }
    else
    {
        node->adaptationData.endSystem = FALSE;
        node->adaptationData.genlSwitch = TRUE;
    }

    // Init the type of adaptation protocol
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ADAPTATION-PROTOCOL",
        &retVal,
        buf);

    if (!retVal || strcmp(buf, "AAL5"))
    {
        ERROR_ReportError("ADAPTATION-PROTOCOL parameter must be AAL5");
    }
    else
    {
        AtmAdaptationLayer5Init(node, nodeInput);
    }

    // Init adaptation layer statistics
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ADAPTATION-LAYER-STATISTICS",
        &retVal,
        buf);

    if (retVal == FALSE || strcmp(buf, "NO") == 0)
    {
        node->adaptationData.adaptationStats = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        node->adaptationData.adaptationStats = TRUE;
    }
    else
    {
        ERROR_ReportError(
            "Expecting YES or NO for ADAPTATION-PROTOCOL-STATISTICS "
            "parameter");
    }
}

//------------------------------------------------------------------------
// Layer function
//------------------------------------------------------------------------


// /**
// FUNCTION    :: ADAPTATION_ProcessEvent
// LAYER       :: Adaptation
// PURPOSE     :: Calls layer function of ATM.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// RETURN       : void : None
// **/
void ADAPTATION_ProcessEvent(Node *node, Message *msg)
{
    // presently this is working only for ATM Node

    if (node->adaptationData.adaptationProtocol
        == ADAPTATION_PROTOCOL_NONE)
    {
        return;
    }

    // Dual IP handling should be properly done here
    switch (node->adaptationData.adaptationProtocol)
    {
        case ADAPTATION_PROTOCOL_AAL5:
        {
            AtmAdaptationLayer5ProcessEvent(node, msg);
            break;
        }
        default:
            printf("%u\n", MESSAGE_GetProtocol(msg));
            ERROR_ReportError("Undefined switch value");
            break;
    }
}

//------------------------------------------------------------------------
// Finalize function
//------------------------------------------------------------------------


// /**
// FUNCTION    :: ADAPTATION_Finalize
// LAYER       :: Adaptation
// PURPOSE     :: Calls finalize function of ATM.
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void ADAPTATION_Finalize(Node *node)
{
    // presently this is working only for ATM Node
    if (node->adaptationData.adaptationProtocol
        == ADAPTATION_PROTOCOL_NONE)
    {
        return;
    }

    switch (node->adaptationData.adaptationProtocol)
    {
    case ADAPTATION_PROTOCOL_AAL5:
        {
            AtmAdaptationLayer5Finalize(node);
            break;
        }
    default:
        ERROR_ReportError("Undefined switch value");
        break;
    }
}


// /**
// FUNCTION    :: ADAPTATION_ReceivePacketFromNetworkLayer
// LAYER       :: Adaptation
// PURPOSE     :: Adaptation-layer receives packets from Transport
//                layer, now check type of adaptation and call pro
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// RETURN       : void : None
// **/
void ADAPTATION_ReceivePacketFromNetworkLayer(Node *node,
                                              Message *msg)

{
    // The packet is received from IP

    // TBD: this part may be changed after LLC implementation
    // Thus to an LLCencapsulation is used to identify
    // higher layer PDU contained in the AAL5 frame

    AdaptationLLCEncapInfo encapInfo;

    // Following llc header value
    // indicates SNAP header follows.
    encapInfo.llcHdr = 0xaaaa0300;

    // OUI & PID jointly identify a
    // routed or bridged protocol
    encapInfo.OUI = 0x0000;
    encapInfo.ethernetType = 0x0800;

    MESSAGE_AddHeader(node,
        msg,
        sizeof(AdaptationLLCEncapInfo),
        TRACE_IP);

    // copy header information
    memcpy(MESSAGE_ReturnPacket(msg),
        &encapInfo,
        sizeof(AdaptationLLCEncapInfo));


    switch (node->adaptationData.adaptationProtocol)
    {
    case ADAPTATION_PROTOCOL_AAL5:
        {
            AalReceivePacketFromNetworkLayer(node, msg);

            break;
        }
    default:
        ERROR_ReportError("Undefined switch value");
        break;
    }
}


// /**
// FUNCTION    :: SendToIP
// LAYER       :: Adaptation
// PURPOSE     :: Adaptation-layer handed over the packet to upper layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + interfaceIndex : int : Interface index.
// + previousHopAddress : NodeAddress : Previous hop address.
// RETURN       : void : None
// **/
void SendToIP(Node* node,
              Message* msg,
              int interfaceIndex,
              NodeAddress previousHopAddress)
{
    AdaptationToNetworkInfo *infoPtr;

    // Send the packet to IP Layer
    MESSAGE_SetEvent(msg, MSG_NETWORK_FromAdaptation);
    MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
    MESSAGE_SetInstanceId(msg, 0);
    MESSAGE_InfoAlloc(node, msg, sizeof(AdaptationToNetworkInfo));

    infoPtr = (AdaptationToNetworkInfo*) MESSAGE_ReturnInfo(msg);

    infoPtr->intfId = interfaceIndex;
    infoPtr->prevHop = previousHopAddress;

    MESSAGE_Send(node, msg, PROCESS_IMMEDIATELY);
}


// /**
// FUNCTION    :: ADAPTATION_DeliverPacketToNetworkLayer
// LAYER       :: Adaptation
// PURPOSE     :: Adaptation-layer receives packets and handed
//                it to the Network Layer
// PARAMETERS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + incomingIntf : int : Incommingnterface index.
// RETURN       : void : None
// **/
void ADAPTATION_DeliverPacketToNetworkLayer(
    Node* node,
    Message* msg,
    int incomingIntf)
{
    // send to upper layer depending
    // upon the encapsulation header
    AdaptationLLCEncapInfo encapInfo;

    // copy encasulation header information
    memcpy(&encapInfo,
        MESSAGE_ReturnPacket(msg),
        sizeof(AdaptationLLCEncapInfo));

    // remove encapsulation header

    MESSAGE_RemoveHeader(node,
        msg,
        sizeof(AdaptationLLCEncapInfo),
        TRACE_IP);

    if ((encapInfo.llcHdr == 0xaaaa0300)
        &&(encapInfo.OUI == 0x0000)
        &&(encapInfo.ethernetType == 0x0800))
    {
        // this is a packet for network protocol IP

        NodeAddress prevNetAddr =
            MAPPING_GetInterfaceAddressForInterface(node,
            node->nodeId,
            incomingIntf);

        // Send msg for IP

        SendToIP(node, msg,  incomingIntf, prevNetAddr);
    }
    else
    {
        ERROR_ReportError("Undefined protocol for AAL5 Packet");

    }
}
