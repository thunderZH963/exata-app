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

#ifndef IPV6_AUTOCONFIG_H
#define IPV6_AUTOCONFIG_H

// CONSTANT    :: PREFIX_EXPIRY_INTERVAL : 40 * SECOND
// DESCRIPTION :: the time interval for which the node doesn't receive the
//                prefix, the prefix will not be an eligibile prefix
#define PREFIX_EXPIRY_INTERVAL      40 * SECOND

// CONSTANT    :: WAIT_FOR_NDADV_INTERVAL : 2 * SECOND
// DESCRIPTION :: the time interval for which the node wait after sending
//                neighbor solicitation for DAD.
#define WAIT_FOR_NDADV_INTERVAL      2 * SECOND

// CONSTANT    :: WAIT_FOR_ADVSOL_FORWARD_INTERVAL : 0.5 * SECOND
// DESCRIPTION :: the time interval for which the node waits before
//                forwarding any neighbor solicitation or adevrtisement
#define WAIT_FOR_ADVSOL_FORWARD_INTERVAL      0.1 * SECOND

// CONSTANT    :: FORWARD_ADV : 0x10000000
// DESCRIPTION :: meant to be forwarded.
#define FORWARD_ADV      0x10000000

// STRUCT      :: newEligiblePrefix
// DESCRIPTION :: Contains fields to be stored in the list of eligible
//                prefixes used to confiugure addresses during stateless
//                address autoconfiguration in ipv6.
struct newEligiblePrefix
{
    in6_addr prefix;            // This is the field to store the prefix
    Int32 prefixLen;            // This is the prefix length of the prefix.
    Int32 interfaceIndex;
    Int32 prefixReceivedCount;  // No of times the prefixes has been
                                // received
    in6_addr previousHop;       // previous hop of the advertisements
    clocktype prefLifeTime;     // Prefered life time of the prefix
    clocktype validLifeTime;    // Valid Life time of the prefix.
    bool isPrefixAutoLearned;
    unsigned char LAReserved;
    clocktype timeStamp;
};
//---------------------------------------------------------------------------
// Function Pointer Type :: Ipv6PrefixChangedHandlerFunctionType
// DESCRIPTION           :: Instance of this type is used to
//                          register prefix change handler Functions.
//---------------------------------------------------------------------------

typedef
void (*Ipv6PrefixChangedHandlerFunctionType)(
    Node* node,
    const Int32 interfaceIndex,
    in6_addr* oldGlobalAddress);

// STRUCT      :: Ipv6ReceivedAdvEntry
// DESCRIPTION :: Structure to store sender's address and
//                timestamp at which it is added.
struct Ipv6ReceivedAdvEntry
{
    in6_addr senderAddr;
    clocktype timeStamp;
};

typedef std::list<newEligiblePrefix*> NewEligiblePrefixList;
typedef std::list<Ipv6PrefixChangedHandlerFunctionType>
                        Ipv6PrefixChangedHandlerFunctionList;
typedef std::list<Ipv6ReceivedAdvEntry*> Ipv6ReceivedAdvList;

//----------------------------------------------------------
// STRUCT      :: AutoConfigStats
// DESCRIPTION :: structure to obtain the necessary stats related
//                to auto-configuration
//----------------------------------------------------------

struct AutoConfigStats
{
    UInt32 numOfprefixchanges;
    UInt32 numOfAdvertForwarded;
    UInt32 numOfSolForwarded;
    UInt32 numOfPktDropDueToInvalidSrc;
    UInt32 numOfNDSolForDadRecv;
    UInt32 numOfNDSolForDadSent;
    UInt32 numOfNDAdvForDadSent;
    UInt32 numOfNDAdvForDadRecv;
    UInt32 numOfPrefixesReceived;
    UInt32 numOfPrefixesDeprecated;
    UInt32 numOfPrefixesInvalidated;
};

//----------------------------------------------------------
// STRUCT      :: Ipv6AutoConfigParam
// DESCRIPTION :: structure to store the ipv6 auto-configuration node related
//                information
//----------------------------------------------------------

struct Ipv6AutoConfigParam
{
    NewEligiblePrefixList* eligiblePrefixList;
    Ipv6PrefixChangedHandlerFunctionList* prefixChangedHandlerList;
        // Autoconfiguration statistics
    AutoConfigStats autoConfigStats;
};

//----------------------------------------------------------
// STRUCT      :: Ipv6AutoConfigInterfaceParam
// DESCRIPTION :: structure to store the ipv6 auto-configuration interface
//                related information
//----------------------------------------------------------

struct Ipv6AutoConfigInterfaceParam
{
    bool isAutoConfig; // is auto address configurable interface
    bool isDebugPrintAutoconfAddr;
    bool isDadConfigured;
    bool isDelegatedRouter;
    bool isDebugPrintAutoconfDad;
    AddressState addressState;
    clocktype prefLifetime;         // global address prefered lifetime
    clocktype validLifetime;        // global address valid lifetime
      // deprecated address info
    in6_addr depGlobalAddr;         // deprecated global address
    int depGlobalAddrPrefixLen;     // Prefix length of deprecated address
    clocktype depValidLifetime;     // deprecated address valid lifetime
    Message* msgWaitNDAdvEvent;     // timer event.to wait for ND
    Message* msgDeprecateTimer;     // deprecate message timer
    Message* msgInvalidTimer;       // invalid message timer
    BOOL isDadEnable;               // is DAD process on?
    Ipv6ReceivedAdvList* receivedAdvList; // List with each interface to
                                    // avoid looping of advertisement packets
                                    // meant for DAD.
    Ipv6ReceivedAdvList* receivedSolList; // List with each interface to
                                    // avoid looping of solicitation packets
                                    // meant for DAD.
    clocktype nsTimeStamp;          // timestamp that is added to NS packet
                                    // to check if this packet is Looped back
                                    // or NS of some other interface
                                    // performing DAD.
    Message* forwardNSol;
    Message* forwardNAdv;


};

//----------------------------------------------------------
// STRUCT      :: IPv6AutoconfigDeprecateEventInfo
// DESCRIPTION :: structure to store the ipv6 auto-configuration deprecate
//                prefix event information
//----------------------------------------------------------

struct IPv6AutoconfigDeprecateEventInfo
{
    Int32 interfaceIndex;
    in6_addr deprecatedPrefix;
};

//---------------------------------------------------------------------------
// Function             : IPv6AutoConfigParseAutoConfig
// Layer                : Network
// Purpose              : parse auto-config parameters.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + nodeInput          : const NodeInput *nodeInput: Pointer to nodeInput
// Return               : None
//---------------------------------------------------------------------------
void IPv6AutoConfigParseAutoConfig(Node* node, const NodeInput* nodeInput);


// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigMakeInterfaceIdentifier
// Layer                : Network
// Purpose              : adds new interface address generated using Auto-
//                        config and sets its status to PREFFERED or
//                        TENTATIVE depending on whether DAD is enabled on
//                        this interface or not.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + interfaceIndex     : Int32 interfaceIndex: interface index
// Return               : bool
// --------------------------------------------------------------------------
bool IPv6AutoConfigMakeInterfaceIdentifier(
                                Node* node,
                                Int32 interfaceIndex);


//---------------------------------------------------------------------------
// FUNCTION         :: lookupPrefixItemInPrefixList
// LAYER            :: Network
// PURPOSE          :: lookup the prefix info for the given prefix.
// PARAMETERS       ::
// + node           :  Node* node    : Pointer to node
// + prefix         :  in6_addr*     : Prefix to search
// + prefixLen      :  int           : prefix length
// + item           :  ListItem**    : ListItem pointer
// RETURN           :: void* : prefix info.
//
newEligiblePrefix* lookupPrefixItemInPrefixList(
                                Node* node,
                                in6_addr* prefix,
                                Int32 prefixLen);


// -------------------------------------------------------------------------
// Function: IPv6AutoConfigReadPrefValidLifeTime
// Layer...: Network
// Purpose:  Read preffered, valid life-time for auto-configurable prefixes.
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// + intfIndex          : int  intfIndex: interface index
// + nodeInput          : const NodeInput *nodeInput: Pointer to nodeInput
// Return: None
// -------------------------------------------------------------------------

void IPv6AutoConfigReadPrefValidLifeTime(
                               Node* node,
                               Int32 intfIndex,
                               const NodeInput *nodeInput);


//---------------------------------------------------------------------------
// Function             : IPv6AutoConfigInit
// Layer                : Network
// Purpose              : creates event for IPv6 auto-config intialization
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// Return               : None
//---------------------------------------------------------------------------
void IPv6AutoConfigInit(Node* node);


//---------------------------------------------------------------------------
// FUNCTION     :: IPv6InvalidateGlobalAddress
// LAYER        :: Network
// PURPOSE      :: Invalidate GlobalAddress state :
// PARAMETERS   ::
// + node               : Node* : node to be updated
// + interfaceIndex     : int : node's interface index
// + isDeprecated       : BOOL : if global address becomes deprecated.
//                               the default value is FALSE.
// RETURN       :: None
//---------------------------------------------------------------------------
void
IPv6InvalidateGlobalAddress(
    Node* node,
    Int32 interfaceIndex,
    bool isDeprecated);


//---------------------------------------------------------------------------
// API              :: Ipv6SendNotificationOfAddressChange
// LAYER            :: Network
// PURPOSE          :: Allows the ipv6 layer to send prefix changed
//                     notification to all the protocols which are using old
//                     prefix.
// PARAMETERS       ::
// node             :  Node* node: Pointer to node.
// + interfaceIndex :  int       : Interface Index
// + oldGlobalAddress : in6_addr*  old global address
// RETURN           :  void      : NULL.
//---------------------------------------------------------------------------
void Ipv6SendNotificationOfAddressChange (
                                Node* node,
                                int interfaceIndex,
                                in6_addr* oldGlobalAddress);


// --------------------------------------------------------------------------
// Function             : IPv6AutoConfigHandleInitEvent
// Layer                : Network
// Purpose              : IPv6 auto-config intialization
// PARAMETERS          ::
// + node               : Node *node : Pointer to node
// Return               : None
// --------------------------------------------------------------------------
void IPv6AutoConfigHandleInitEvent(Node* node);


//---------------------------------------------------------------------------
// FUNCTION                :configureNewGlobalAddress
// PURPOSE                 :This functionis used to return the list item
//                          where the prefixreceived count is the maximum.
// PARAMETERS              ::
// node                    : Node* node: Node data pointer
// list                    : LinkedList* list : POinter to start of the list
//                           to be traversed.
//---------------------------------------------------------------------------
newEligiblePrefix* IPv6AutoConfigConfigureNewGlobalAddress(
            Node* node,
            Int32 interfaceId,
            NewEligiblePrefixList* eligiblePrefixList,
            Int32 minReceiveCount = 1);


//---------------------------------------------------------------------------
// FUNCTION     :: IPv6AutoConfigHandleAddressDeprecateEvent
// LAYER        :: Network
// PURPOSE      :: Handles address deprecate event.
// PARAMETERS   ::
// + node       :  Node* : node to be updated
// + msg        :  Message* msg : pointer to message
// RETURN       :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleAddressDeprecateEvent(
                                Node* node,
                                Message* msg);


//---------------------------------------------------------------------------
// API              :: Ipv6AddPrefixChangedHandlerFunction
// LAYER            :: Network
// PURPOSE          :: Add a Prefix change handler function to the List, This
//                     handler will be called when address prefix changes.
// PARAMETERS       ::
// + node           :  Node*             : Pointer to node.
// + PrefixChangeFunctionPointer
//                  :  Ipv6PrefixChangedHandlerFunctionType :
// RETURN           :: void  : NULL.
//---------------------------------------------------------------------------
void Ipv6AddPrefixChangedHandlerFunction(
        Node* node,
        Ipv6PrefixChangedHandlerFunctionType prefixChangeFunctionPointer);


//---------------------------------------------------------------------------
// FUNCTION         :: IPv6AutoConfigAttachPrefixesRouterAdv
// LAYER            :: Network
// PURPOSE          :: attaches prefixes, that a router advertises, to 
//                     router adv
// PARAMETERS       ::
// + node           :  Node* : node to be updated
// + ndopt_pi       :  struct nd_opt_prefix_info_struct* ndopt_pi :
//                     prefix info
// + interfaceIndex :  Int32 : interface index
// RETURN           :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigAttachPrefixesRouterAdv(
                Node* node,
                struct nd_opt_prefix_info_struct* ndopt_pi,
                Int32 interfaceIndex);


//---------------------------------------------------------------------------
// API              :: IPv6AutoConfigGetSrcAddrForNbrAdv
// LAYER            :: Network
// PURPOSE          :: get source address for neighbor advertisement
// PARAMETERS       ::
// + node           :  Node*    : Pointer to node.
// + interfaceId    :  Int32    : Interface Id.
// + src_addr       :  in6_addr : to store source address
// RETURN           :: void  : NULL.
//---------------------------------------------------------------------------
void IPv6AutoConfigGetSrcAddrForNbrAdv(
                    Node* node,
                    Int32 interfaceId,
                    in6_addr* src_addr);


//---------------------------------------------------------------------------
// API                 :: updatePrefixList
// LAYER               :: Network
// PURPOSE             :: Prefix list updating function.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +addr                : in6_addr* addr : IPv6 Address of destination
// +prefixLen           : UInt32         : Prefix Length
// +report              : int report: error report flag
// +linkLayerAddr       : NodeAddress linkLayerAddr: Link layer address
// +routeFlag           : int routeFlag: route Flag
// +routeType           : int routeType: Route type e.g. gatewayed/local.
// +gatewayAddr         : in6_addr gatewayAddr: Gateway's ipv6 address.
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigUpdatePrefixList(
    Node* node,
    Int32 interfaceId,
    in6_addr *addr,
    UInt32 prefixLen,
    Int32 report,
    MacHWAddress& linkLayerAddr,
    Int32 routeFlag,
    Int32 routeType,
    in6_addr gatewayAddr);


//---------------------------------------------------------------------------
// API              :: IPv6AutoConfigHandleNbrAdvForDAD
// LAYER            :: Network
// PURPOSE          :: configures new global address when neighbor
//                     advertisement is recieved.
// PARAMETERS       ::
// + node           :  Node*    : Pointer to node.
// + interfaceId    :  Int32    : Interface Id.
// + src_addr       :  in6_addr : to store source address
// RETURN           :: void  : NULL.
//---------------------------------------------------------------------------
BOOL IPv6AutoConfigHandleNbrAdvForDAD(
                                Node* node,
                                Int32 interfaceId,
                                in6_addr tgtaddr,
                                MacHWAddress linkLayerAddr,
                                Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigForwardNbrAdv
// LAYER               :: Network
// PURPOSE             :: Forwards neighbor advertisement.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : int interfaceId : Index of the concerned interface
// +tgtaddr             : in6_addr tgtaddr: target address
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigForwardNbrAdv(
                            Node* node,
                            Int32 interfaceId,
                            in6_addr tgtaddr,
                            Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigInitiateDAD
// LAYER               :: Network
// PURPOSE             :: Initiates DAD process.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                                               interface
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigInitiateDAD(
                            Node* node,
                            Int32 InterfaceIndex);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessNbrSolForDAD
// LAYER               :: Network
// PURPOSE             :: Processes neighbor solicitation received for DAD.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                                               interface
// +nsp                 : nd_neighbor_solicit* nsp : neighbor solicitation
//                                                   data
// +linkLayerAddr       : MacHWAddress linkLayerAddr : link layer address
// +msg                 : Message* msg : pointer to message
// RETURN              :: bool
//---------------------------------------------------------------------------
bool IPv6AutoConfigProcessNbrSolForDAD(
                                   Node* node,
                                   Int32 interfaceIndex,
                                   struct nd_neighbor_solicit_struct* nsp,
                                   MacHWAddress linkLayerAddr,
                                   Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigForwardNbrSolForDAD
// LAYER               :: Network
// PURPOSE             :: Forwards neighbor solicitation.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceIndex      : Int32 interfaceIndex : Index of the concerned
//                                               interface
// +tgtaddr             : in6_addr tgtaddr : target address
// +nsp                 : nd_neighbor_solicit* nsp : neighbor solicitation
//                                                   data
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigForwardNbrSolForDAD(
                   Node* node,
                   Int32 interfaceIndex,
                   in6_addr tgtaddr,
                    struct nd_neighbor_solicit_struct* nsp,
                   Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessRouterAdv
// LAYER               :: Network
// PURPOSE             :: Process router advertisement.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : Int32 interfaceId : Index of the concerned
//                                            interface
// +ndopt_pi            : nd_opt_prefix_info* ndopt_pi : prefix information
// +src_addr            : in6_addr src_addr : source address
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigProcessRouterAdv(
                            Node* node,
                            Int32 interfaceId,
                            struct nd_opt_prefix_info_struct* ndopt_pi,
                            in6_addr src_addr);


//---------------------------------------------------------------------------
// FUNCTION             : IPv6AutoConfigValidateCurrentConfiguredPrefix
// PURPOSE             :: Validate currently configured prefix
// PARAMETERS          ::
// +node                : Node* node : Pointer to the node
// +interfaceId         : int interfaceId : Index of the concerned Interface
// RETURN               : void* : void Pointer
//---------------------------------------------------------------------------
newEligiblePrefix* IPv6AutoConfigValidateCurrentConfiguredPrefix(
                    Node* node,
                    Int32 interfaceId);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigProcessRouterAdvForDAD
// LAYER               :: Network
// PURPOSE             :: Process router advertisement for DAD.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +interfaceId         : Int32 interfaceId : Index of the concerned
//                                            interface
// +returnAddr          : newEligiblePrefix* returnAddr :
// +defaultAddr         : in6_addr defaultAddr :
// +linkLayerAddr       : MacHWAddress linkLayerAddr : link layer address
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigProcessRouterAdvForDAD(
                            Node* node,
                            Int32 interfaceId,
                            newEligiblePrefix* returnAddr,
                            in6_addr defaultAddr,
                            MacHWAddress linkLayerAddr);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigHandleWaitNDAdvExpiry
// LAYER               :: Network
// PURPOSE             :: to do required processing if no ND adv is received.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleWaitNDAdvExpiry(
                            Node* node,
                            Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigHandleAddressInvalidExpiry
// LAYER               :: Network
// PURPOSE             :: Handles address invalid event.
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +msg                 : Message* msg : pointer to message
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigHandleAddressInvalidExpiry(
                            Node* node,
                            Message* msg);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigFinalize
// LAYER               :: Network
// PURPOSE             :: IPv6 Auto-config finalizing function
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigFinalize(Node* node);


//---------------------------------------------------------------------------
// API                 :: IPv6AutoConfigAddPrefixInPrefixList
// LAYER               :: Network
// PURPOSE             :: Adds new prefix to prefix list
// PARAMETERS          ::
// +node                : Node* node : Pointer to node
// +borroewdinterfaceInfo
//                      : IpInterfaceInfoType* borroewdinterfaceInfo :
//                          Interface info
// +interfaceIndex      : Int32 interfaceIndex : interface index
// RETURN              :: None
//---------------------------------------------------------------------------
void IPv6AutoConfigAddPrefixInPrefixList(
                            Node* node,
                            IpInterfaceInfoType* borroewdinterfaceInfo,
                            Int32 interfaceIndex);
//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6GetPreferedAddress
// PURPOSE             :: Get the prefered address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int : Index of the concerned interface
// + addr               : in6_addr*  : IPv6 prefered address pointer
//                          - output
// RETURN              :: None
//---------------------------------------------------------------------------
void
Ipv6AutoConfigGetPreferedAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr);

//---------------------------------------------------------------------------
// FUNCTION            :: Ipv6GetDeprecatedAddress
// PURPOSE             :: Get the deprecated address of the interface.
// PARAMETERS          ::
// + node               : Node* : Pointer to node
// + interfaceId        : int : Index of the concerned interface
// + addr               : in6_addr* : IPv6 address pointer, output
// RETURN              :: None
//---------------------------------------------------------------------------
void
Ipv6GetDeprecatedAddress(
    Node* node,
    int interfaceId,
    in6_addr* addr);

bool
IPv6AutoConfigIsPreferredAddress(
        Node* node,
        Int32 interfaceId);
#endif // IPV6_AUTOCONFIG_H
