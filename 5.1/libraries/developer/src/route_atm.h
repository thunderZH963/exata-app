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
// PROTOCOL :: ATM_IP
//
// SUMMARY  :: As the name suggest the main goal of ATM-IP interaction
// is to transfer IP traffic over the ATM network to reach the final
// destination. In this regard, Classical IP over ATM model is
// introduced with the concept of a logical entity called
// LOGICAL IP SUBNET that treats the ATM network as a number of
// separate IP subnets connected through routers. The membership to
// an LIS is defined by software configuration. Transportation of
// various protocol data unit over an ATM network are categorized
// into the following subsection
//    Addressing
//    Address resolution
//    Data encapsulation
//    Routing

//
// LAYER :: ADAPTATION (Static route within ATM cloud)
//
//
// VALIDATION :: $QUALNET_HOME/verification/atm-ip.
//
// IMPLEMENTED_FEATURES ::
// + PACKET TYPE : Only Signaling and Unicast data payload are implemented.
// + NETWORK TYPE : Point to point ATM link are supported.
// + LINK TYPE : Wired.
// + FUNCTIONALITY : IP Protocol Data Units are carried over the ATM cloud
//                   through the Gateways.
//                 : Logical Subnet concept is introduced. At present,
//                   single Logical IP subnet is supported within ATM cloud,
//                 : Routing within the ATM clouds is done statically. Static
//                   route file is provided externally during configuration.
//                 : Virtual path setup process for each application is done
//                   dynamically, Various signaling messages are exchanged
//                   for setup virtual paths.
//                 : BW are reserved for each application.

//
// OMITTED_FEATURES ::
// +PACKET TYPE : Broadcast and multicast packets are not implemented.
// +ROUTE TYPE : Only static route within ATM cloud is implemented.
// + PNNI Routing is not implemented within ATM.
// + PVC is not implemented.

// ASSUMPTIONS ::
// + ATM is working as a backbone cloud to transfer the traffic i.e. all the
// IP clouds are connected to backbone ATM cloud & have a DEFAULT-GATEWAY,
//.acting as an entry/exit point to/from the ATM cloud.
// + all application requires a fixed BW, described as SAAL_DEFAULT_BW
// parameter.
// + All nodes in a single ATM cloud are part of the same Logical Subnet.
// + Every ATM end-system should have at least one interface connected to IP.

//
// STANDARD/RFC ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000

// **/


#ifndef _ATM_ROUTE_H_
#define _ATM_ROUTE_H_


// /**
// FUNCTION    :: AtmRoutingStaticLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Function for ATM ststic routing.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : const Message* : Pointer to message.
// RETURN       : void : None
// **/
void
AtmRoutingStaticLayer(
    Node *node,
    const Message *msg);


// /**
// FUNCTION    :: AtmRoutingStaticInit
// LAYER       :: Adaptation Layer
// PURPOSE     :: Handling all initializations needed by static routing.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput * : Pointer to config file.
// RETURN       : void : None
// **/
void
AtmRoutingStaticInit(
    Node *node,
    const NodeInput *nodeInput);


// /**
// FUNCTION    :: AtmRoutingStaticFinalize
// LAYER       :: Adaptation Layer
// PURPOSE     :: Handling all finalization needed by static routing.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
AtmRoutingStaticFinalize(Node *node);


#endif /* _STATIC_ROUTING_H_ */

