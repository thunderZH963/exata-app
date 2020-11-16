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
// PROTOCOL :: ATM_IP (ATM Layer 2)
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
// LAYER :: ATM_Layer2.
//
// STATISTICS ::

// + atmCellReceive : Total number of Atm Cell received at
//                    this interfaces.
// + atmCellInHdrError : Total number of Atm Cell discarded
//                       due to header error.
// + atmCellAddrError : Total number of Atm Cell discarded due
//                      to incorrect destination address.
// + atmCellForward : Total number of Atm Cell for which an
//                    attempt was made to forward
// + atmCellNoRoutes : Total number of Atm Cell discarded
//                     because no route could be found.
// + numControlCell : Total number of Control Cell received
// + numAtmCellInDelivers : Total number of Atm Cell delivered
//                          to upper layer.

// CONFIG_PARAM ::
// + ATM-NODE : node-Id : All the nodes present in ATM
//                      cloud are configured here.
// + ATM-LINK : Two ATM nodes are connected by a link using
//              this parameter.ICD format is used.
// + bandwidth : double : This parameter indicates link Bandwidth
//                        of the ATM Link in bits per second (bps).
// + propDelay: double : This parameter indicates ATM Link propagation
//                        delay for wired point-to-point ATM links.
// + nodeType : AtmLayer2NodeType: indicates if it is an
//              ATM-END-system or ATM-Switch

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

#ifndef ATM_LAYER2_H
#define ATM_LAYER2_H

#include "sch_atm.h"
#include "if_queue.h"
#include "atm_logical_subnet.h"

 // /**
 // CONSTANT    :: ATM_LAYER2_LINK_DEFAULT_BANDWIDTH : 112000 bps
 // DESCRIPTION :: Default bandwidth of the ATM link layer 2
 // **/
 #define ATM_LAYER2_LINK_DEFAULT_BANDWIDTH  112000

 // /**
 // CONSTANT    :: ATM_LAYER2_LINK_DEFAULT_PROPAGATION-DELAY 50MS
 // DESCRIPTION :: Default prapagation of the ATM link layer 2
 // **/
 #define ATM_LAYER2_LINK_DEFAULT_PROPAGATION_DELAY  50 * MILLI_SECOND

// /**
// CONSTANT    :: ATM_CELL_LENGTH : 53
// DESCRIPTION :: ATM cell length in bytes
// **/

#define ATM_CELL_LENGTH 53


// /**
// CONSTANT    :: ATM_CELL_HEADER : 5
// DESCRIPTION :: ATM cell header in bytes
// **/

#define ATM_CELL_HEADER 5


// /**
// CONSTANT    :: ATM_NUM_CELL_IN_FRAME : 4
// DESCRIPTION :: Number of ATM Cell in per Frame
// **/

#define ATM_NUM_CELL_IN_FRAME 4


// /**
// ENUM        :: AtmLayer2InterfaceState
// DESCRIPTION :: Interface state of ATM layer2
// **/

typedef enum
{
    ATM_LAYER2_INTERFACE_DISABLE,
    ATM_LAYER2_INTERFACE_ENABLE
} AtmLayer2InterfaceState;


// /**
// ENUM        ::   AtmLayer2LinkStatus
// DESCRIPTION ::   Atm Link status
// **/

typedef enum {
    ATM_LAYER2_LINK_IS_IDLE = 0,
    ATM_LAYER2_LINK_IS_BUSY = 1
} AtmLayer2LinkStatus;


// /**
// ENUM        ::   AtmLayer2Intf
// DESCRIPTION ::   Atm Interface type
// **/

typedef enum
{
    ATM_LAYER2_INVALID = 0,
    ATM_LAYER2_INTF_UNI = 1,
    ATM_LAYER2_INTF_NNI = 2
} AtmLayer2Intf;


// /**
// ENUM        ::   AtmLayer2NodeType
// DESCRIPTION ::   Atm Node type
// **/

typedef enum
{
    ATM_LAYER2_ENDSYSTEM = 0,
    ATM_LAYER2_SWITCH = 1
} AtmLayer2NodeType;


// /**
// STRUCT      :: AtmUniPart
// DESCRIPTION :: UNI header part of Atm cell
// **/

typedef struct struct_atm_uni_part
{
    unsigned int atm_gfc:4,     // Generic flow control field
                 atm_vpi:8,     // Virtual path identifier
                 atm_vci:16,    // Virtual channel identifier
                 atm_pt:3,      // Paylod type field
                 atm_clp:1;     // Cell loss priority field
} AtmUniPart;


// /**
// STRUCT      :: AtmNniPart
// DESCRIPTION :: NNI header part of Atm cell
// **/

typedef struct struct_atm_nni_part
{
    unsigned int atm_vpi:12,    // Virtual path identifier
                 atm_vci:16,    // Virtual channel identifier
                 atm_pt:3,      // Paylod type field
                 atm_clp:1;     // Cell loss priority field
} AtmNniPart;


// /**
// UNION      :: MainPart
// DESCRIPTION :: Union of UNI and NNI part of Atm cell
// **/

typedef union
{
    AtmUniPart atmUniPart;
    AtmNniPart atmNniPart;
} MainPart;

// /**
// STRUCT      :: AtmCellHeader
// DESCRIPTION :: Atm cell header
// **/

typedef struct struct_atm_cell_header
{
    MainPart mainPart;
    unsigned char  atm_hec;     // Header error control, unused
} AtmCellHeader;


// /**
// STRUCT      :: AtmLayer2Data
// DESCRIPTION :: Main data structure of ATM LAYER2
// **/

typedef struct struct_atm_layer2_str
{
    int         interfaceIndex;
    BOOL        atmLayer2Stats;
    BOOL        atmLayer2InfIsEnabled;
    int         bandwidth;   // In bytes.
    clocktype   propDelay;
    AtmScheduler*  atmScheduler;

    AtmLayer2NodeType nodeType;
    AtmLayer2LinkStatus atmLinkStatus;
    AtmLayer2Intf interfaceType;
    Node*       otherNode;
    NodeAddress otherNodeId;
    int otherNodeInterfaceIndex;

    // Total number of Atm Cell received at this interfaces.
    unsigned int atmCellReceive;
    // Total number of Atm Cell discarded due to header error.
    unsigned int atmCellInHdrError;
    // Total number of Atm Cell discarded due to incorrect
    // destination address.
    unsigned int atmCellAddrError;
    // Total number of Atm Cell for which an attempt was made to forward.
    unsigned int atmCellForward;
    // Total number of Atm Cell discarded because no route could be found.
    unsigned int atmCellNoRoutes;
    // Total number of Control Cell received.
    unsigned int numControlCell;
    // Total number of Atm Cell delivered to upper layer.
    unsigned int numAtmCellInDelivers;
    clocktype totalBusyTime;
    LogicalSubnet* logicalSubnet;

} AtmLayer2Data;


// /**
// FUNCTION   :: Atm_Layer2CongestionExperienced
// LAYER      :: ATM Layer2
// PURPOSE    :: Check congestion is occur into this link or interface.
// PARAMETERS ::
// +   msg : Message* : pointer to Message.
// RETURN    :: Void : NULL
// **/

void Atm_Layer2CongestionExperienced(Message* msg);


// /**
// FUNCTION   :: Atm_Layer2GetAtmData
// LAYER      :: ATM Layer2
// PURPOSE    :: queue has packet to send.
// PARAMETERS ::
// + node : Node* : The Node Pointer
// + interfaceIndex : int : at this interface.
// RETURN     :: AtmLayer2Data* : pointer to AtmLayer2Data
// **/

AtmLayer2Data* Atm_Layer2GetAtmData(Node* node, int interfaceIndex);

#endif

