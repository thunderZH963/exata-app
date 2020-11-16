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

#ifndef _BELLMANFORD_H_
#define _BELLMANFORD_H_

//-----------------------------------------------------------------------------
// DEFINES (none)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// STRUCTS, ENUMS, AND TYPEDEFS (none)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// INLINED FUNCTIONS (none)
//-----------------------------------------------------------------------------

//-----------------------------------------------------------------------------
// PROTOTYPES FOR FUNCTIONS WITH EXTERNAL LINKAGE
//-----------------------------------------------------------------------------

void
RoutingBellmanfordInit(Node *node);

void
RoutingBellmanfordLayer(Node *node, Message *msg);

void
RoutingBellmanfordFinalize(Node *node, int interfaceIndex);

/*
// FUNCTION   :: RoutingBellmanfordInitTrace
// PURPOSE    :: Bellmanford initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
*/
void RoutingBellmanfordInitTrace(Node* node, const NodeInput* nodeInput);

//Interface Utility Functions
//
//
// FUNCTION     BellmanfordHookToRedistribute
// PURPOSE      Added for route redistribution
// Parameters:
//      node:
//      destAddress:
//      destAddressMask:
//      nextHopAddress:
//      interfaceIndex:
//      routeCost:
//      Changed by C Shaw
void BellmanfordHookToRedistribute(
        Node* node,
        NodeAddress destAddress,
        NodeAddress destAddressMask,
        NodeAddress nextHopAddress,
        int interfaceIndex,
        void* routeCost);

//
// FUNCTION   :: RoutingBellmanfordPrintTraceXML
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
//
void RoutingBellmanfordPrintTraceXML(Node* node, Message* msg);

// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION   :: RoutingBellmanfordHandleChangeAddressEvent
// PURPOSE    :: Handles any change in the interface address for Bellmanford
// PARAMETERS ::
// + node               : Node* : Pointer to Node structure
// + interfaceIndex     : Int32 : interface index
// + oldAddress         : Address* : current address
// + subnetMask         : NodeAddress : subnetMask
// + networkType        : NetworkType : type of network protocol
// RETURN :: void : NULL
//---------------------------------------------------------------------------
void RoutingBellmanfordHandleChangeAddressEvent(
    Node* node,
    Int32 interfaceIndex,
    Address* oldAddress,
    NodeAddress subnetMask,
    NetworkType networkType);

#endif // _BELLMANFORD_H_
