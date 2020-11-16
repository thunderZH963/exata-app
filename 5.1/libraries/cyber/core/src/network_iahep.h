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

//
// PROTOCOL :: IAHEP

// MAJOR REFERENCES ::
// +
// MINOR REFERENCES ::
// +

// COMMENTS   :: None

#ifndef IAHEP_H
#define IAHEP_H

#include "network_ip.h"
#include <iostream>
#include <vector>
#include <set>
#include <map>

using namespace std;

#define IAHEP_DEBUG 0

#define IAHEP_RED_INTERFACE 1 //Between Red and IAHEP node
#define IAHEP_BLACK_INTERFACE 2 //Between Black and IAHEP node
#define RED_INTERFACE 3 //Between Red Node and Red subnet
#define BLACK_INTERFACE 4 //Between Black Node and Black subnet

#define BROADCAST_MULTICAST_MAPPEDADDRESS 0xEFFFFFFF //239.255.255.255

#define MULTICAST_BROADCAST_ADDRESS 0xE7FFFFFF  //231.255.255.255

#define DEFAULT_RED_BLACK_MULTICAST_MAPPING 0x08000000 //8.0.0.0

// STRUCT      :: IAHEPStatsType
// DESCRIPTION :: It is used to hold stats of a IAHEP
typedef struct
{
    UInt32 numOfPktsSent;
    UInt32 numOfPktsRcvd;
    // Number of IP fragments padded.
    D_UInt32 iahepIPFragsPadded;

    //MLS Stats
    //MLS:Number Of Outgoing Unicast Packets Dropped At Node Under MLS Property STRONG
    UInt32 iahepMLSOutgoingUnicastPacketsDroppedUndrPropSTRONG;
    //MLS:Number Of Outgoing Unicast Packets Dropped At Node Under MLS Property LIBERAL
    UInt32 iahepMLSOutgoingUnicastPacketsDroppedUndrPropLIBREAL;
    //MLS:Number Of Incoming Packets Dropped At Node Under MLS Property SIMPLE
    UInt32 iahepMLSIncomingPacketsDroppedUndrPropSIMPLE;

    //IGMP IAHEP Stats
    UInt32 iahepIGMPReportsSent;
    //Number Of Leave Messages Send By Red IAHEP Node To Black Node
    UInt32 iahepIGMPLeavesSent;
    //Group For Which Leave Message Is Send By Red IAHEP Node To Black Node
    NodeAddress iahepIGMPLevingGrp;
}IAHEPStatsType;

// /**
// STRUCT      :: IAHEPRoutingMsgInfoType
// DESCRIPTION :: IAHEP Routing message information structure.
// **/
typedef struct
{
    char inOut;
    NodeAddress previousHopAddress;
} IAHEPRoutingMsgInfoType;

// /**
// STRUCT      :: IAHEPHeaderInfoType
// DESCRIPTION :: IAHEP Header message information structure is used because
//              : IAHEP Fragment Header Creation part is moved to NetworkIpS
//              : endPktOnInterface from NetworkIpSendRawMessage.
// **/
typedef struct
{
    NodeAddress sourceAddress;
    NodeAddress destinationAddress;
    TosType priority;
    unsigned ttl;
    unsigned char protocol;
} IAHEPHeaderInfoType;

// STRUCT      :: IAHEPNodeType
// DESCRIPTION :: It is used to hold the node type for IAHEP
typedef enum
{
    INVALID_NODE = 0,
    RED_NODE,
    IAHEP_NODE,
    BLACK_NODE
}IAHEPNodeType;

// STRUCT      :: MLSPropertyName
// DESCRIPTION :: It is used to hold the MLS Property for IAHEP
typedef enum
{
   LIBERAL_STAR = 0, //Writing To Levels Above
    STRONG_STAR //Equal Level Read & Write
}MLSPropertyName;

// STRUCT      :: IahepFragmentHeader
// DESCRIPTION :: It is used to hold the IAHEP fragment info
typedef struct
{
    NodeAddress remoteblackaddress;
    clocktype lastseqrecvd;
} IahepPeerEntry;

// STRUCT      :: IahepFragmentHeader
// DESCRIPTION :: It is used to hold the IAHEP fragment info
typedef struct iahep_header_str
{
    UInt16 packet_len;
    UInt16 ip_id;
    char   ipFragment;
    UInt16   offset;
} IahepFragmentHeader;

// STRUCT      :: IahepMLSHeader
// DESCRIPTION :: It is used to hold the IAHEP MLS Security Level
typedef struct iahep_header_mls
{
    UInt8 mls_level;
} IahepMLSHeader;

// STRUCT      :: IahepDestRedAddrHeader
// DESCRIPTION :: It is used by Red Node to Send Destination Red IP Address
//information to IAHEP Node
typedef struct iahep_dest_red_header
{
    NodeAddress destRedNodeAddress;
} IahepDestRedAddrHeader;

// STRUCT      :: IAHEPAmdMappingType
// DESCRIPTION :: It is used to hold the AMD for IAHEP
typedef struct IAHEPamdmappingtype
{
    NodeAddress     destBlackInterface;
    NodeAddress     destRedInterface;
    UInt8           destSecurityLevel; //Destination Node MLS Secuirty Level
    IAHEPStatsType  iahepStats;
}IAHEPAmdMappingType;

// CLASS      :: UpdateAMDTable
// DESCRIPTION :: Used to perform operations on AMDTable
class UpdateAMDTable
{
    std::vector<IAHEPAmdMappingType*> vectorAMDTable;
    public:
        void AMDInsertAtEnd(NodeAddress a, NodeAddress b, UInt8 c)
        {
            IAHEPAmdMappingType* amdInfo = NULL;
            amdInfo = (IAHEPAmdMappingType*) MEM_malloc(sizeof(IAHEPAmdMappingType));
            amdInfo->destBlackInterface = a;
            amdInfo->destRedInterface = b;
            amdInfo->destSecurityLevel = c;
            memset(&(amdInfo->iahepStats), 0, sizeof(IAHEPStatsType));

            vectorAMDTable.push_back(amdInfo);
        }
        int sizeOfAMDTable ()
        {
            return vectorAMDTable.size();
        }
        IAHEPAmdMappingType *getBaseAddress ()
        {
            return vectorAMDTable[0];
        }
        IAHEPAmdMappingType *getAMDTable (int entry)
        {
            return vectorAMDTable [entry];
        }
};

// STRUCT      :: IAHEPData
// DESCRIPTION :: It is used to hold the IAHEP Data
typedef struct
{
    //Class to Operate on AMDTable
    UpdateAMDTable *updateAmdTable;
    //By having a separate multicast mapping,
    //should have a better runtime performance.
    map<NodeAddress,NodeAddress>* multicastAmdMapping;
    map<NodeAddress,NodeAddress>* IahepToBlackMapping;
    map<NodeAddress, NodeAddress>* IahepDeviceMapping;

    set<NodeAddress>* grpAddressList;
    IAHEPNodeType        nodeType;
    UInt8 MLSSecurityLevel; //MLS Security Level of Connected RED Node
    MLSPropertyName  securityName; //MLS Security Property Name For RED Node
    NodeAddress localBlackAddress;
    BOOL IGMPIsByPassMode;

}IAHEPData;

// FUNCTION      ::    IAHEPInit
// LAYER         ::    Network
// PURPOSE       ::    Function to Initialize IAHEP for a node
// PARAMETERS    ::
// + node        ::    Node*   : Pointer to node structure.
// + nodeInput   ::    const NodeInput* : QualNet main configuration file.
// RETURN        ::    void
// NOTE          ::
void IAHEPInit(Node* node,
                const NodeInput* nodeInput);

// FUNCTION   :: IAHEPFinalize
// LAYER      :: Network
// PURPOSE    :: Finalise function for IAHEP, to Print Collected Statistics
// PARAMETERS ::
// + node              : Node*    : The node pointer
// RETURN     :: void
// NOTE       :
void IAHEPFinalize(Node* node);

int IAHEPGetIAHEPRedInterfaceIndex(Node*);
int IAHEPGetIAHEPBlackInterfaceIndex(Node*);
BOOL IsIAHEPRedSecureInterface(Node* node, Int32 intIndex);
BOOL IsIAHEPBlackSecureInterface(Node* node, Int32 intIndex);

void IAHEPRouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL *packetWasRouted);

NodeAddress IAHEPGetBlackDestinationAddressForPkt(Node *, Message *, NodeAddress);

// /**
// API                 :: IAHEPMLSOutgoingPropertyCheck
// PURPOSE             :: Function MLS Handling for Outgoing Packets.
// PARAMETERS          ::
//+node*                : node.
//+Message*             : msg.
//unsigned              : address
// RETURN               :BOOL.
BOOL IAHEPMLSOutgoingPropertyCheck (Node*, Message*, NodeAddress);

// /**
// API                 :: IAHEPMLSIncomingPropertyCheck
// PURPOSE             :: Function MLS Handling for Incoming Packets.
// PARAMETERS          ::
//+node*                : node.
//+Message*             : msg
//UInt8                 : Level Of Source Node
// RETURN               :BOOL.
// **/
BOOL IAHEPMLSIncomingPropertyCheck (Node*, Message*, UInt8);

// /**
// API        :: IAHEPProcessingRequired
// LAYER      :: Network
// PURPOSE    :: Returns whether IAHEP Processing is Needed Or Not
// PARAMETERS ::
// + unsigned char       : ipProto
// + short               : appType
// RETURN     :: BOOL :
// **/
BOOL IAHEPProcessingRequired(unsigned char);

// /**
// FUNCTION     IAHEPUpdateAMDInfoForStaticAMDConfiguration
// PURPOSE      This Function Fills The AMDInfo Data Structure when
//              static AMD Configuration is used.
// PARAMETERS   Node *node
//                  Pointer to node.
//              NodeInput amdInput
// RETURN       None.
//
// NOTES        None.
// /**
void IAHEPUpdateAMDInfoForStaticAMDConfiguration(
        Node*, NodeInput, const NodeInput*);

// /**
// FUNCTION   :: IAHEPSendRecvPktsWithDelay
// LAYER      :: Network
// PURPOSE    :: Function to handle events for IAHEP, required to simulate
//               delay
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + msg       : Message* : Event that expired
// RETURN     :: void : NULL
// **/
void IAHEPSendRecvPktsWithDelay(Node*, Message*);

// /**
// FUNCTION   :: IAHEPSendPktAfterProcessingDelay
// LAYER      :: Network
// PURPOSE    :: Function to to Send The Pkt after Encryption and Auth Delay
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + msg       : Message* : Event that expired
// + char      : inOut
// + NodeAddress : previousHopAddress
// + clocktype : delay
// RETURN     :: void : NULL
// **/
void IAHEPSendPktAfterProcessingDelay (Node*, Message*, char, NodeAddress,
                                       clocktype);

// FUNCTION   :: IAHEPUpdateAMDTableFromAMDFile
// LAYER      :: Network
// PURPOSE    :: This Function is to Update the AMD Table data Structure
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + NodeAddress          : remoteRedIPAddress
// + NodeAddress          : remoteBlackIPAddress
// + UInt8                : MLS Level
// RETURN     :: BOOL
BOOL IAHEPUpdateAMDTableFromAMDFile(Node*, NodeAddress, NodeAddress,
                                    UInt32);

// FUNCTION   :: IAHEPCheckEntriesInAMDTable
// LAYER      :: Network
// PURPOSE    :: This Function provides checking on AMD File Entries
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + NodeAddress          : remoteRedIPAddress
// + NodeAddress          : remoteBlackIPAddress
// + UInt32                : MLSLevel
// + int                  : numOfValuesInFile
// RETURN        ::    void
void IAHEPCheckEntriesInAMDTable(Node*, NodeAddress, NodeAddress, UInt32,
                                 UInt32);

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPGetMulticastBroadcastAddressMapping
// LAYER      :: Network
// PURPOSE    :: Function returns Muitlcast-broadcast address to Red Node
// PARAMETERS ::
// + node           : Pointer of Node Type
// + iahepData      : IAHEPData*    : Pointer to IAHEPData structure
// + addr: NodeAddress : Address in Header of incoming packet
// RETURN     :: NodeAddress
//---------------------------------------------------------------------------
NodeAddress IAHEPGetMulticastBroadcastAddressMapping(
    Node *node,
    IAHEPData* iahepData,
    NodeAddress addr);

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPCreateIgmpJoinLeaveMessage
// LAYER               :: Network
// PURPOSE    :: Function creates and send IGMP Join and Leave message for
//               IAHPE multicast addressr
// PARAMETERS          ::
// + node      : Node*    : The node processing the event
// + grpAddr   : NodeAddress    : Red multicast groupaddress
//+ messageType   : unsigned char    : Join or Leave IGMP message
// RETURN     :: Void
//---------------------------------------------------------------------------
void IAHEPCreateIgmpJoinLeaveMessage(
     Node* node,
     NodeAddress grpAddr,
     unsigned char messageType,
     IgmpMessage* igmpPkt = NULL,
     NodeAddress *srcAddr = NULL);

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPAddDestinationRedHeader
// LAYER      :: Network
// PURPOSE    :: Function to Send Remote Red Information To Directly Connected
//              : IAHEP Node
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + message   : Message * : packet with red IP header on it
// + nextHop   : NodeAddress : red nextHop address
// RETURN     :: void
//---------------------------------------------------------------------------
void IAHEPAddDestinationRedHeader(Node*, Message*, NodeAddress nextHop);

//---------------------------------------------------------------------------
// FUNCTION   :: IAHEPFillIAHEPtoBlackDS
// LAYER      :: Network
// PURPOSE    :: Function to maintain IAHEP to BLACK Mapping at IAHEP Node
// PARAMETERS ::
// + node      : Node*    : The node processing the event
//+ NodeInput  : nodeInput *
// RETURN     :: void
//---------------------------------------------------------------------------
void IAHEPFillIAHEPtoBlackDS(Node *, const NodeInput *);

// FUNCTION            :: IAHEPGetAMDInfoForDestBlackInterface
// LAYER               :: Network
// PURPOSE             :: To get AMD info for given destination BLACK address
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + address           :: NodeAddress     :.destination BLACK address
// RETURN              :: IAHEPAmdMappingType* : AMD info
// **/
IAHEPAmdMappingType* IAHEPGetAMDInfoForDestBlackInterface(Node* node,
                                                         NodeAddress address);
//---------------------------------------------------------------------------
// FUNCTION            :: IAHEPGetAMDInfoForDestinationRedAddress
// LAYER               :: Network
// PURPOSE             :: To get AMD info for given local and remote
//                       BLACK address
// PARAMETERS          ::
// + node              :: Node*   : Pointer to node structure.
// + remoteRedIPAddress:: NodeAddress     :.Destination Red Address
// RETURN              :: IAHEPAmdMappingType* : AMD info
// **/
//---------------------------------------------------------------------------
IAHEPAmdMappingType* IAHEPGetAMDInfoForDestinationRedAddress(Node* node,
                                                        NodeAddress address);

/***** Start: OPAQUE-LSA *****/
//---------------------------------------------------------------------------
// FUNCTION      ::    IAHEPUpdateMappingForROSPFSimulatedHellos
// LAYER         ::    Network
// PURPOSE       ::    Function to Update IAHEP mapping based on ROSPF
//               ::     simmulated hellos.
// PARAMETERS    ::
// + node        ::    Node*   : Pointer to node structure.
// + blackAddr   ::    NodeAddress : Black interface address of advertising
//                                   router
// + haipeDeviceAddress    :: NodeAddress : HAIPE device address
// RETURN        ::    void
// **/
//---------------------------------------------------------------------------
void
IAHEPUpdateMappingForROSPFSimulatedHellos(Node* node,
                                          NodeAddress blackAddr,
                                          NodeAddress haipeDeviceAddress);

/***** End: OPAQUE-LSA *****/
#endif // IAHEP_H
