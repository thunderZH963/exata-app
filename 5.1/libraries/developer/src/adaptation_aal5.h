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
// LAYER :: ADAPTATION (ATM adaptation layer 5).
//
// STATISTICS::

// + numCpcsSduSent : Total number of CPCS sdu sent
// + numCpcsSduRecv : Total number of CPCS sdu recv
// + numAtmSduSent : Total number of ATM SDU sent
// + numAtmSduRecv : Total number of ATM SDU recv
// + numAtmSduDropped : Total number of ATM SDU dropped
// + numPktSegmented : Total number of Packet segmented
// + numPktReassembled : Total number of Packet reassembled
// + numDataPktSend : Total number of DataPacket send
// + numDataPktRecvd : Total number of Data Packet Recvd
// + numSaalPktSend : Total number of Saal Packet reassembled;
// + numSaalPktRecvd : Total number of Saal Packet Recvd
// + numPktFromIPNetwork : Total number of Pkt from IP network
// + numIpPktDiscarded : Total number of erronious Packet Discarded
// + numPktFwdToIPNetwork : Total number of Packet Forwarded to IP
// + numPktDroppedForNoRoute : Total number of Packet Dropped for no route

//
// CONFIG_PARAM ::
// + conncTimeoutTime : TIME : SVC connection refresh Time
// + conncRefreshTime : TIME : Virtual connection timeout time

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


#ifndef AAL5_H
#define AAL5_H

#include "api.h"
#include "partition.h"
#include "mac_link.h"
#include "list.h"
#include "network_ip.h"
#include "atm.h"
#include "adaptation_saal.h"
#include "atm_logical_subnet.h"


// /**
// CONSTANT    :: SAR_PDU_LENGTH : 48
// DESCRIPTION :: Length of protocol data unit for segmentation and
//                reassamble.
// **/
#define SAR_PDU_LENGTH                  48


// /**
// CONSTANT    :: MAX_SDU_DELIVER_LENGTH : 3000
// DESCRIPTION :: Maximum deliver length for Service data unit.
// **/
#define MAX_SDU_DELIVER_LENGTH          3000


// /**
// CONSTANT    :: AAL_INITIAL_TABLE_SIZE : 10
// DESCRIPTION :: Initial table size of adaptetion layer.
// **/
#define AAL_INITIAL_TABLE_SIZE          10


// /**
// CONSTANT    :: AAL_SAAL_TTL : 1
// DESCRIPTION :: ATM adaptetion layer signalling ttl.
// **/
#define AAL_SAAL_TTL                    1


// /**
// CONSTANT    :: ATM_SAAL_VCI : 5
// DESCRIPTION ::
// **/
#define ATM_SAAL_VCI                    5


// /**
// CONSTANT    :: CONTROL_PORT : 100
// DESCRIPTION ::
// **/
#define CONTROL_PORT                    100


// /**
// CONSTANT    :: ATM_DATA_MIN_VCI : 32
// DESCRIPTION :: Minimum ATM data for vitual cunnecting interface.
// **/
#define ATM_DATA_MIN_VCI                32


// /**
// CONSTANT    :: ATM_DATA_MAX_VCI : 65535
// DESCRIPTION :: Maximum ATM data for vitual cunnecting interface.
// **/
#define ATM_DATA_MAX_VCI                65535


// /**
// MACRO       :: ATM_DEFAULT_CONNECTION_TIMEOUT_TIME : (1 * MINUTE)
// DESCRIPTION :: Timeout time for default ATM connection.
// **/
#define ATM_DEFAULT_CONNECTION_TIMEOUT_TIME     (1 * MINUTE)


// /**
// MACRO       :: ATM_DEFAULT_CONNECTION_REFRESH_TIME : (5 * MINUTE)
// DESCRIPTION :: Refresh time for default ATM connection.
// **/
#define ATM_DEFAULT_CONNECTION_REFRESH_TIME     (5 * MINUTE)


// /**
// ENUM        :: Aal5ServiceType
// DESCRIPTION :: Various service type for adaptetion protocol AAL5.
// **/
typedef enum
{
    AAL5_MESSAGE_MODE,
    AAL5_STREAMING_MODE
} Aal5ServiceType;


// /**
// ENUM        :: Aal5SignalingType
// DESCRIPTION :: Various signaling type for adaptetion protocol AAL5.
// **/
typedef enum
{
    SIGNALING_PVC,
    SIGNALING_SVC
} Aal5SignalingType;


// /**
// STRUCT      :: Aal5CpcsPduTrailer
// DESCRIPTION :: Cpcs protocol data unit trailer for Aal5.
// **/
typedef struct struct_aal5_cpcsPdu_trailer
{
    unsigned char cpcsUU;
    unsigned char  cpi;
    unsigned short payloadLength;
    unsigned int crc;
} Aal5CpcsPduTrailer;


// /**
// STRUCT      :: Aal5CpcsPrimitive
// DESCRIPTION :: Cpcs primitive for Aal5.
// **/
typedef struct struct_aal5_cppcs_primitive
{
    //dynamically allot char* interfaceData;
    BOOL more;
    BOOL cpcsLP;
    BOOL cpcsCI;
    unsigned char cpcsUU;
    unsigned short receptionStatus;

    // dynamically allot interfaceData;
} Aal5CpcsPrimitive;


// /**
// STRUCT      :: Aal5SarPrimitive
// DESCRIPTION :: Sar primitive for Aal5.
// **/
typedef struct struct_aal5_sar_primitive
{
    // dynamically allot interfaceData;
    BOOL more;
    unsigned short sarLP;
    unsigned short sarCI;
} Aal5SarPrimitive;


// /**
// STRUCT      :: Aal5AtmDataPrimitive
// DESCRIPTION :: Atm data primitive for Aal5.
// **/
typedef struct struct_aal5_atm_data_primitive
{
    // dynamically allot interfaceData;

   // BOOL more;
    BOOL atmUU;
    unsigned short atmLP;
    unsigned short atmCI;
} Aal5AtmDataPrimitive;


// /**
// STRUCT      :: Aal5MsgInfo
// DESCRIPTION :: Message structure for Aal5.
// **/
// TBD: If Reqd, need to Modify
typedef struct struct_aal5_msg_info
{
    int outIntf;
    int incomingIntf;

    unsigned short incomingVCI;
    unsigned char incomingVPI;

    unsigned short outVCI;
    unsigned char outVPI;
} Aal5MsgInfo;


// /**
// STRUCT      :: Aal5BufferListItem
// DESCRIPTION :: Buffer list item for Aal5.
// **/
typedef struct struct_aal5_buffer_list_item
{
    unsigned char VPI;
    unsigned short VCI;
    clocktype timeStamp;
    Message* dataInfo;
} Aal5BufferListItem;


// /**
// STRUCT      :: Aal5ReAssItem
// DESCRIPTION :: Reassembling item for Aal5.
// **/
typedef struct struct_aal5_reAss_item
{
    unsigned short VCI;
    unsigned short VPI;
    unsigned int iduNumber;
    int inIntf;
    char* cpcsPdu;
    char* reAssBuff;
    Message* msgInfo; // keep first fragment for copy info
} Aal5ReAssItem;


// /**
// STRUCT      :: Aal5AssociatedIPListItem
// DESCRIPTION :: Associated IP list item for Aal5.
// **/
typedef struct struct_aal5_associated_IPlist_item
{
    Address ipAddr;

} Aal5AssociatedIPListItem;


// /**
// STRUCT      :: Aal5AddrInfoTableRow
// DESCRIPTION :: Row structure for address info table of Aal5.
// **/
typedef struct struct_aal5_addr_info_table_row
{
    Address memberlogicalIP;
    AtmAddress memberATMAddress;
    LinkedList* associatedIPList;

} Aal5AddrInfoTableRow;


// /**
// STRUCT      :: Aal5AddrInfoTable
// DESCRIPTION :: Address Info table
// **/
typedef struct struct_aal5_addr_info_table
{
    unsigned int             numRows;
    unsigned int             allottedNumRow;
    Aal5AddrInfoTableRow* row;
} Aal5AddrInfoTable;


// /**
// STRUCT      :: Aal5FwdTableRow
// DESCRIPTION :: Row structure for forwarding table of Aal5.
// **/
typedef struct struct_aal5_fwd_table_row
{
    AtmAddress destAtmAddr;
    AtmAddress nextAtmNode;
    int outIntf;
} Aal5FwdTableRow;


// /**
// STRUCT      :: Aal5FwdTable
// DESCRIPTION :: Forwarding table of Aal5.
// **/
typedef struct struct_aal5_fwd_table
{
    unsigned int             numRows;
    unsigned int             allottedNumRow;
    Aal5FwdTableRow* row;
} Aal5FwdTable;


// /**
// STRUCT      :: Aal5ConncTableRow
// DESCRIPTION :: Row structure for connection table of Aal5.
// **/
typedef struct struct_aal5_connc_table_row
{
    Address appSrcAddr;
    Address appDstAddr;
    unsigned short appSrcPort;
    unsigned short appDstPort;
    unsigned short VCI;
    unsigned char VPI;
    Aal5SignalingType saalType;
    SaalSignalingStatus saalStatus;
    clocktype lastPktRecvdTime;

} Aal5ConncTableRow;


// /**
// STRUCTURE   :: Aal5ConncTable
// DESCRIPTION :: Connection table
// **/
typedef struct struct_aal5_connc_table
{
    unsigned int             numRows;
    unsigned int             allottedNumRow;
    Aal5ConncTableRow* row;
} Aal5ConncTable;


// /**
// STRUCT      :: Aal5Stats
// DESCRIPTION :: Structure for Aal5 status.
// **/

typedef struct struct_aal5_stats
{
    int numCpcsSduSent;
    int numCpcsSduRecv;

    int numAtmSduSent;
    int numAtmSduRecv;
    int numAtmSduDropped;

    int numPktSegmented;
    int numPktReassembled;

    int numDataPktSend;
    int numDataPktRecvd;

    int numSaalPktSend;
    int numSaalPktRecvd;

    int numPktFromIPNetwork;
    int numIpPktDiscarded;
    int numPktFwdToIPNetwork;
    int numPktDroppedForNoRoute;

} Aal5Stats;


// /**
// STRUCT      :: Aal5InterfaceData
// DESCRIPTION :: Interface data for Aal5.
// **/
typedef struct struct_aal5_interface_data
{

    AtmIntfType interfaceType;
    int intfId;

    AtmAddress atmIntfAddr;

    int          totalBandwidth;   // In bytes.
    clocktype    propDelay;

    clocktype conncTimeoutTime;
    clocktype conncRefreshTime;

    // ARP Table: maintained at each ARP server
    // At present a similar table is maintained at
    // each ATM end system

    Aal5AddrInfoTable addrInfoTable;

} Aal5InterfaceData;


// /**
// STRUCT      :: Aal5Data
// DESCRIPTION :: Data structure for Aal5.
// **/
typedef struct struct_adaptation_aal5_str
{
    AtmAddress atmRouterId;
    Aal5InterfaceData* myIntfData;

    // Routing Info
    unsigned char routingType;
    void* rouitingLayerPtr;

    Aal5Stats stats;
    LinkedList* reAssBuffList;
    LinkedList* bufferList;

    // Maintained at all ATM node
    // for routing packet within ATM cloud

    Aal5FwdTable fwdTable;

    // for transmission of cell within ATM cloud
    AtmTransTable transTable;

    // Maintained at ATM End system
    // for originating connection Id, for a
    // particular application from network

    Aal5ConncTable conncTable;

    // Signalling Data Ptr
    void* saalNodeInfo;

} Aal5Data;


// /**
// FUNCTION    :: AtmAdaptationLayer5Init
// LAYER       :: Adaptation Layer
// PURPOSE     :: Initializing AAL5 parameter for this node
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput* : Pointer to config file.
// RETURN       : void : None
// **/
void
AtmAdaptationLayer5Init(
    Node *node,
    const NodeInput *nodeInput);


// /**
// FUNCTION    :: AtmAdaptationLayer5ProcessEvent
// LAYER       :: Adaptation Layer
// PURPOSE     :: Process the packet depending upon the type of ATM packet
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void
AtmAdaptationLayer5ProcessEvent(
    Node *node,
    Message *msg);


// /**
// FUNCTION    :: Aal5HandleProtocolPrimitive
// LAYER       :: Adaptation Layer
// PURPOSE     :: Handle the received protocol specific primitive
//                in various sublayer
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void
Aal5HandleProtocolPrimitive(
    Node *node,
    Message *msg);


// /**
// FUNCTION    :: AtmAdaptationLayer5Finalize
// LAYER       :: Adaptation Layer
// PURPOSE     :: Finalize function for ATM adaptation layer.
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
AtmAdaptationLayer5Finalize(Node *node);


// /**
// FUNCTION    :: AalReceivePacketFromNetworkLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: A packet is received from the network layer
//                for processing in the ATM layer
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message
// RETURN       : void : None
// **/
void
AalReceivePacketFromNetworkLayer(
    Node *node,
    Message *msg);

// /**
// FUNCTION    :: AalGetPtrForThisAtmNode
// LAYER       :: Adaptation Layer
// PURPOSE     :: Get the related adaptation layer Ptr for this ATM Node
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : Aal5Data* : Pointer to AAL5 data.
// **/
Aal5Data*
AalGetPtrForThisAtmNode(Node *node);


// /**
// FUNCTION    :: Aal5UpdateTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create/Modify entry in Translation table
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPCI       : unsigned char  : VPCI value
// + finalVPI   : unsigned char  : finalVPI value
// + outIntf    : int : Outgoing Interface
// RETURN       : void : None
// **/
void
Aal5UpdateTransTable(
    Node* node,
    unsigned short VCI,
    unsigned char VPCI,
    unsigned char finalVPI,
    int outIntf);


// /**
// FUNCTION    :: Aal5UpdateFwdTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Create/Modify entry in Forwarding table
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + outIntf    : unsigned int : Outgoing Interface
// + destAtmAddr: AtmAddress* : Pointer to destination address
// + nextAtmNode: AtmAddress* : Pointer to next ATM node
// RETURN       : void : None
// **/
void
Aal5UpdateFwdTable(
    Node *node,
    unsigned int outIntf,
    AtmAddress *destAtmAddr,
    AtmAddress *nextAtmNode);


// /**
// FUNCTION    :: Aal5PrintTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: To printf ATM Trans table
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
Aal5PrintTransTable(Node *node);


// /**
// FUNCTION    :: Aal5UpdateConncTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Set status for this application
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// + status     : unsigned char : status
// RETURN       : void : None
// **/
void
Aal5UpdateConncTable(
    Node* node,
    unsigned short VCI,
    unsigned char VPI,
    unsigned char status);


// /**
// FUNCTION    :: Aal5PrintAddrInfoTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Print AddrInfo table
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// RETURN       : void : None
// **/
void
Aal5PrintAddrInfoTable(Node *node);


// /**
// NAME        :: Aal5UpdateAddressInfoTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Update address table with information
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + intfId     : int : Interface Identifier.
// + destAtmAddr: AtmAddress* : Pointer to destination address.
// + destIpAddr : Address* : Pointer to destination IP address.
// RETURN       : void : None.
// **/
void
Aal5UpdateAddressInfoTable(
    Node *node,
    int intfId,
    AtmAddress *destAtmAddr,
    Address *destIpAddr);


// /**
// FUNCTION    :: AalCheckIfItIsInAttachedNetwork
// LAYER       :: Adaptation Layer
// PURPOSE     :: Check If the dest and the node is in same network
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + addrPtr    : AtmAddress* : Pointer to ATM address
// RETURN       : BOOL
// **/
BOOL
AalCheckIfItIsInAttachedNetwork(
    Node *node,
    AtmAddress *addrPtr);


// /**
// FUNCTION    :: Aal5GetAtmAddrAndLogicalIPForDest
// LAYER       :: Adaptation Layer
// PURPOSE     :: AAL5 function to get logical IP address for destination
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + destIP     : Address : Logical Ip Address for destination.
// + atmAddr    : AtmAddress* : Pointer to ATm address.
// RETURN       : void : None
// **/
void
Aal5GetAtmAddrAndLogicalIPForDest(
    Node *node,
    Address destIP,
    AtmAddress *atmAddr);

// /**
// FUNCTION    :: AalGetOutIntfAndNextHopForDest
// LAYER       :: Adaptation Layer
// PURPOSE     :: Get the outgoing Interface & the next op from
//                the forwarding table of the node
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + destAtmAddr : AtmAddress* : Pointer to Destination Address
// + outIntf    : int* : Pointer to outgoing interface index.
// + nextHop    : AtmAddress* : Pointer to nextHop
// RETURN       : void : None
// **/
void
AalGetOutIntfAndNextHopForDest(
    Node *node,
    AtmAddress *destAtmAddr,
    int *outIntf,
    AtmAddress *nextHop);


// /**
// FUNCTION    :: AalSendSignalingMsgToLinkLayer
// LAYER       :: Adaptation Layer
// PURPOSE     :: After creating a signaling message it needs to be passed
//                thru various sublayer for processing
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// + srcIdentifier: AtmAddress* : Pointer to ATM source.
// + destIdentifier: AtmAddress* : Pointer to ATM destination.
// + ttl        : unsigned : Time to leave.
// + outgoingInterface: int : outgoing interface index.
// + nextHop    : AtmAddress* : Pointer to nextHop.
// + VCI        : unsigned short : VCI value
// RETURN       : void : None
// **/
void
AalSendSignalingMsgToLinkLayer(
    Node *node,
    Message *msg,
    AtmAddress* srcIdentifier,
    AtmAddress* destIdentifier,
    unsigned ttl,
    int outgoingInterface,
    AtmAddress* nextHop,
    unsigned short VCI);


// /**
// FUNCTION    :: Aal5SearchTransTable
// LAYER       :: Adaptation Layer
// PURPOSE     :: Search the Translation Table for matching Entry
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// RETURN       : AtmTransTableRow* : Pointer to ATM Trans-Table row.
// **/
AtmTransTableRow*
Aal5SearchTransTable(
    Node *node,
    unsigned short VCI,
    unsigned char VPI);


// /**
// FUNCTION    :: Aal5CollectDataFromBuffer
// LAYER       :: Adaptation Layer
// PURPOSE     :: Collect the datat packet from buffer after
//                path establishment
// ARGUMENTS   ::
// + node       : Node* : Pointer to node.
// + VCI        : unsigned short : VCI value
// + VPI        : unsigned char : VPI value
// RETURN       : void : None
// **/
void
Aal5CollectDataFromBuffer(
    Node *node,
    unsigned short VCI,
    unsigned char VPI);

#endif

