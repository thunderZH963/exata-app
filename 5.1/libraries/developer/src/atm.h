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
// PROTOCOL :: ATM_IP (ATM basic)
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
// LAYER :: ADAPTATION + ATM_Layer2.
//
// CONFIG_PARAM ::
// + ATM-NODE: node-Id : All the nodes present in ATM cloud
// are configured here.

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


#ifndef ATM_H
#define ATM_H


// /**
// ENUM        :: AtmIntfType
// DESCRIPTION :: different types of interface
// **/

typedef enum
{
    ATM_INTF_UNI,
    ATM_INTF_NNI,
    ATM_INTF_IP,
    ATM_INTF_INVALID
}AtmIntfType;


// /**
// ENUM        :: AtmPrimitives
// DESCRIPTION :: Event/message types exchanged in the simulation in ATM
// **/

typedef enum
{
    MSG_ATM_LAYER2_AtmDataRequest,
    MSG_ATM_LAYER2_PhyDataRequest,
    MSG_ATM_LAYER2_PhyDataIndication,
    MSG_ATM_LAYER2_TransmissionFinished,
    MSG_ATM_LAYER2_FrameIndication,

    // Message field for ATM
    // SAAL
    MSG_ATM_LAYER2_BWChk,
    MSG_ATM_LAYER2_BWSupported,
    MSG_ATM_ADAPTATION_SaalConnectTimer,
    MSG_ATM_ADAPTATION_SaalT301Timer,
    MSG_ATM_ADAPTATION_SaalT303Timer,
    MSG_ATM_ADAPTATION_SaalT306Timer,
    MSG_ATM_ADAPTATION_SaalT310Timer,
    MSG_ATM_ADAPTATION_SaalT313Timer,
    MSG_ATM_ADAPTATION_SaalTimeoutTimer,
    MSG_ATM_ADAPTATION_SaalPacket,

    // AAL5
    MSG_ATM_ADAPTATION_CpcsUnidataInvoke,
    MSG_ATM_ADAPTATION_SarUnidataInvoke,
    MSG_ATM_ADAPTATION_ATMDataIndication,
    MSG_ATM_ADAPTATION_SarUnidataSignal,
    MSG_ATM_ADAPTATION_CpcsUnidataSignal,
    MSG_ATM_ADAPTATION_ATMLayer2

} AtmPrimitives;


// /**
// STRUCTURE   :: AtmTransTableRow
// DESCRIPTION :: Translation table row
// **/

typedef struct struct_atm_trans_table_row
{
    unsigned short VCI;
    unsigned char VPI;
    unsigned short finalVCI;
    unsigned char finalVPI;
    int outIntf;
    int inIntf;

}AtmTransTableRow;


// /**
// STRUCTURE   :: AtmTransTable
// DESCRIPTION :: Translation table
// **/

typedef struct struct_atm_trans_table
{
    unsigned int             numRows;
    unsigned int             allottedNumRow;
    AtmTransTableRow* row;
}AtmTransTable;


// /**
// STRUCTURE   :: Aal5ToAtml2Info
// DESCRIPTION :: Information related to ATM DATA in between ALL and LAYER2
// **/

typedef struct struct_aal5_to_atm_l2Info
{
    int incomingIntf;
    unsigned short incomingVCI;
    unsigned char incomingVPI;
    int outIntf;
    unsigned short outVCI;
    unsigned char outVPI;
    BOOL atmUU;
    unsigned short atmLP;
    unsigned short atmCI;

}Aal5ToAtml2Info;



// /**
// STRUCTURE   :: AtmBWInfo
// DESCRIPTION :: Information of connection setup or release
//                in between ALL and LAYER2
// **/

typedef struct struct_atm_bw_info
{
    unsigned char vpi;
    unsigned short vci;
    unsigned int reqdBw;
}AtmBWInfo;


// /**
// FUNCTION    :: Atm_BWCheck
// LAYER       :: Adaptation
// PURPOSE     :: Check congestion is occur into this link or interface.
// PARAMETERS  ::
// + node        : Node* : Pointer to node.
// + incomingIntf: int : For which flow this BW specified.
// + outgoingIntf: int : Which interface
// + isAdd       : BOOL: Add this BW or reduce this BW.
// + bwInfo      : AtmBWInfo* : Pointer to AtmBWInfo.
// RETURN :: BOOL : Return TRUE if action executed properly,
//                  otherwise FALSE.
// **/

BOOL Atm_BWCheck(Node* node,
                int incomingIntf,
                int outgoingIntf,
                BOOL isAdd,
                AtmBWInfo* bwInfo);


// /**
// NAME         :: Atm_GetAddrForOppositeNodeId
// LAYER        :: Adaptation
// PURPOSE      :: Get the Address of opposite direction of a ATM-LINK.
// PARAMETER    ::
// + node        : Node * : Pointer to node.
// + atmInfIndex : int : Interface index related to ATM network.
// RETURN       :: Address : returns the address
// NOTE         :: If interface Index of opposite node is not valid,
//                 networkType of return Address is NETWORK_INVALID.
// **/

Address Atm_GetAddrForOppositeNodeId(
    Node* node,
    int atmInfIndex);

#endif

