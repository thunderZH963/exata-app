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
// LAYER :: ADAPTATION (general adptation).
//
// STATISTICS::

//
// CONFIG_PARAM ::
// + adaptationProtocol : AdaptationProtocolType: adapatation protocol used
// + endSystem : BOOL : true if the node is an END system
// + genlSwitch : BOOL: true if the node is an ATM switch
//
// VALIDATION :: $QUALNET_HOME/verification/atm-ip.
//
// IMPLEMENTED_FEATURES :: (used only for ATM cloud)
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


#ifndef _ADAPTATION_H_
#define _ADAPTATION_H_

// /**
// ENUM        :: AdaptationUtilityProtocolType
// DESCRIPTION :: Enlisted different ATM-related protocol
// **/

enum AdaptationUtilityProtocolType
{
    ATM_PROTOCOL_AAL,
    ATM_PROTOCOL_SAAL,
    ATM_PROTOCOL_PNNI
};


// /**
// ENUM        :: AdaptationProtocolType
// DESCRIPTION :: Enlisted different adaptation protocol
// **/

enum AdaptationProtocolType
{
    ADAPTATION_PROTOCOL_AAL1,
    ADAPTATION_PROTOCOL_AAL2,
    ADAPTATION_PROTOCOL_AAL3,
    ADAPTATION_PROTOCOL_AAL4,
    ADAPTATION_PROTOCOL_AAL5,

    ADAPTATION_PROTOCOL_NONE

};


// /**
// STRUCT      :: AdaptationToNetworkInfo
// DESCRIPTION :: Info to be passed to NEtwork layer
// **/

struct AdaptationToNetworkInfo
{
    int intfId;
    NodeAddress prevHop;
};


// /**
// STRUCT      :: AdaptationLLCEncapInfo
// DESCRIPTION :: Encapsulation related header
// **/

struct AdaptationLLCEncapInfo
{
    // 3 bytes + 3 bytes structure is modified with 4+ 2 byte
    // At present for IP OUI is 0
    unsigned int llcHdr;
    unsigned short  OUI;
    unsigned short ethernetType;
};



// typedef to Atm Adaptation layer 5 in network/atm_aal/aal5.

struct struct_adaptation_aal5_str;

// /**
// STRUCT      :: AdaptationData
// DESCRIPTION :: Main data structure of adaptation layer
// **/

struct AdaptationData
{
    void *adaptationVar;
    AdaptationProtocolType adaptationProtocol;
    BOOL endSystem;
    BOOL genlSwitch;

    BOOL adaptationStats;  // TRUE if statistics are collected
};


// /**
// FUNCTION   :: ADAPTATION_ReceivePacketFromNetworkLayer
// LAYER      :: Adaptation
// PURPOSE    :: Packet notificaton function.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + msg       : Message* : Pointer to Message.
// RETURN     :: void : NULL
// **/

void ADAPTATION_ReceivePacketFromNetworkLayer(Node *node,
                                              Message *msg);


// /**
// FUNCTION   :: ADAPTATION_DeliverPacketToNetworkLayer
// LAYER      :: Adaptation
// PURPOSE    :: Packet notificaton function.
// PARAMETERS ::
// + node      : Node* : Pointer to node.
// + msg       : Message* : Pointer to Message.
// + incomingIntf : int: Incoming interface index.
// RETURN     :: void : NULL
// **/

void ADAPTATION_DeliverPacketToNetworkLayer(Node* node,
                                            Message* msg,
                                            int incomingIntf);
//
#endif // _ADAPTATION_H_

