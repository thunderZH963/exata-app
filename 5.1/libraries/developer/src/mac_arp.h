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
// PACKAGE     :: Address Resulution Protocol header
// DESCRIPTION :: Data structures and parameters used in network layer
//                are defined here.
// **/

#ifndef ARP_H
#define ARP_H


// /**
// CONSTANT    :: ARP_DEFAULT_TIMEOUT_INTERVAL : 20 * MINUTE
// DESCRIPTION :: The ARP cache timeout value is user configurable.
//                If not specified, the default ARP cache timeout value is
//                used, i.e, each entry lasts 20 minutes after it is created
//                RFC 1122:
//                Periodically time out cache entries, even if they are in
//                use. Note that this timeout should be restarted when the
//                cache entry is "refreshed".
// **/
#define ARP_DEFAULT_TIMEOUT_INTERVAL                 20 * MINUTE

// /**
// CONSTANT    :: ARP_BUFFER_SIZE : 1
// DESCRIPTION :: Default buffer size to store IP packet, 
//                when mac address is not resolved
// **/
#define ARP_BUFFER_SIZE                              1

// /**
// CONSTANT    :: ARP_STATICT_TIMEOUT : 0
// DESCRIPTION :: The cache entry of ARP never deleted
// **/
#define ARP_STATICT_TIMEOUT                          0

// /**
// CONSTANT    :: ARP_STATIC_FILE_ATTRIBUTE : 7
// DESCRIPTION :: Number of attribute of ARP cache File
// **/
#define ARP_STATIC_FILE_ATTRIBUTE                    7

// /**
// CONSTANT    :: ARP_ENTRY_TYPE_STATIC : 0
// DESCRIPTION :: Entry type static in the ARP table
// **/
#define ARP_ENTRY_TYPE_STATIC                        0

// /**
// CONSTANT    :: ARP_ENTRY_TYPE_DYNAMIC : 1
// DESCRIPTION :: Entry type dynamic in the ARP table
// **/
#define ARP_ENTRY_TYPE_DYNAMIC                       1

// /**
// CONSTANT    :: ARP_HRD_NETROM : 0
// DESCRIPTION :: From KA9Q NET/ROM pseudo
//                ARP protocol HARDWARE identifiers.
// **/
#define ARP_HRD_NETROM                               0

// /**
// CONSTANT    :: ARP_HRD_ETHER : 1
// DESCRIPTION :: Ethernet 10/100Mbps
//                ARP protocol HARDWARE identifiers.
// **/
#define ARP_HRD_ETHER                                1

// /**
// CONSTANT    :: ARP_HRD_EETHER : 2
// DESCRIPTION :: ARP protocol hardware type Experimental Ethernet
// **/
#define ARP_HRD_EETHER                               2

// /**
// CONSTANT    :: ARP_HRD_AX25 : 3
// DESCRIPTION :: ARP protocol hardware type AX.25 Level 2
// **/
#define ARP_HRD_AX25                                 3

// /**
// CONSTANT    :: ARP_HRD_PRONET : 4
// DESCRIPTION :: ARP protocol hardware type PROnet token ring
// **/
#define ARP_HRD_PRONET                               4

// /**
// CONSTANT    :: ARP_HRD_CHAOS : 5
// DESCRIPTION :: ARP protocol hardware Chaosnet
// **/
#define ARP_HRD_CHAOS                                5

// /**
// CONSTANT    :: ARP_HRD_IEEE802 : 6
// DESCRIPTION :: IEEE 802.2 Ethernet/TR/TB
// **/
#define ARP_HRD_IEEE802                              6

// /**
// CONSTANT    :: ARP_HRD_ARCNET : 7
// DESCRIPTION :: Hardware type ARCnet
// **/
#define ARP_HRD_ARCNET                               7

// /**
// CONSTANT    :: ARP_HRD_APPLETLK : 8
// DESCRIPTION :: Hardware type APPLEtalk
// **/
#define ARP_HRD_APPLETLK                             8

// /**
// CONSTANT    :: ARP_HRD_DLCI : 15
// DESCRIPTION :: Frame Relay DLCI
// **/
#define ARP_HRD_DLCI                                 15

// /**
// CONSTANT    :: ARP_HRD_ATM : 19
// DESCRIPTION :: ATM 10/100Mbps
// **/
#define ARP_HRD_ATM                                  19

// /**
// CONSTANT    :: ARPHRD_METRICOM : 23
// DESCRIPTION :: Hardware type ARPHRD_METRICOM
// **/
#define ARPHRD_METRICOM                              23

// /**
// CONSTANT    :: ARPHRD_IEEE_1394 : 24
// DESCRIPTION :: Hardware type ARPHRD_IEEE_1394
// **/
#define ARPHRD_IEEE_1394                             24

// /**
// CONSTANT    :: ARPHRD_EUI_64 : 27
// DESCRIPTION :: Hardware identifier
// **/
#define ARPHRD_EUI_64                                27

// /**
// CONSTANT    :: ARP_HRD_UNKNOWN : 0xffff
// DESCRIPTION :: Unknown Hardware type
//                ARP protocol HARDWARE identifiers.
// **/
#define ARP_HRD_UNKNOWN                              0xffff

// /**
// CONSTANT    :: ARP_PROTOCOL_ADDR_SIZE_IP : 4
// DESCRIPTION :: IPv4 protocol address size in byte
// **/
#define ARP_PROTOCOL_ADDR_SIZE_IP                    4





// /**
// CONSTANT    :: PROTOCOL_TYPE_RARP : 0x08035
// DESCRIPTION :: RARP type
// **/
#define PROTOCOL_TYPE_RARP                           0x08035

// /**
// CONSTANT    :: ARP_QUEUE_SIZE : 300000
// DESCRIPTION :: Queue Size in bytes
// **/
#define ARP_QUEUE_SIZE 30000

// /**
// CONSTANT    :: MAX_RETRY_COUNT : 5
// DESCRIPTION :: Maximum Retry count
// **/
#define MAX_RETRY_COUNT 5

// /**
// ENUM        :: ArpOp
// DESCRIPTION :: The opcode field in ArpPacket represents different type of
//                opcode
// **/
typedef enum arp_opcode
{
    ARPOP_INVALID,
    ARPOP_REQUEST,          // ARP request
    ARPOP_REPLY,            // ARP reply
    ARPOP_RREQUEST,         // RARP request
    ARPOP_RREPLY,           // RARP reply
    ARPOP_InREQUEST = 8,    // InARP request
    ARPOP_InREPLY,          // InARP reply.
    ARPOP_NAK,              // (ATM)ARP NAK.
} ArpOp;


// /**
// STRUCT      :: ArpPacket
// DESCRIPTION :: Struture of the ARP message.
// **/
typedef struct arp_packet_str
{
    unsigned short hardType;
    unsigned short protoType;
    unsigned char hardSize;
    unsigned char protoSize;
    unsigned short opCode;

    unsigned char  s_macAddr[MAX_MACADDRESS_LENGTH];
    NodeAddress s_IpAddr;
    unsigned char d_macAddr[MAX_MACADDRESS_LENGTH];
    NodeAddress d_IpAddr;

} ArpPacket;


// /**
// STRUCT      :: ArpTTableElement
// DESCRIPTION :: Struture of the element of Arp translation Table.
// **/
typedef struct arp_translation_table_element_str
{
    NodeAddress protocolAddr;
    unsigned char  hwAddr[MAX_STRING_LENGTH];
    unsigned short protoType;
    unsigned short hwType;
    unsigned short hwLength;
    clocktype expireTime;
    unsigned int interfaceIndex;
    BOOL entryType;  //for Static ARP Cache Entries
                     //the value is zero otherwise 1
} ArpTTableElement;


// /**
// STRUCT      :: ArpBuffer
// DESCRIPTION :: Struture of the ARP Buffer.
// **/
typedef struct arp_buffer
{
    NodeAddress nextHopAddr;
    int interfaceIndex;
    int incomingInterface;
    TosType priority;
    int networkType;
    Message *buffer;
} ArpBuffer;


// /**
// STRUCT      :: ArpStat
// DESCRIPTION :: Struture of the ARP statistics collection.
// **/
typedef struct arp_stat_str
{

    unsigned totalReqSend;
    unsigned totalReplySend;
    unsigned totalReqRecvd;
    unsigned totalReplyRecvd;

#if 0
    //Count the number of proxy reply done
    //The proxy reply also included into the arpReply
    unsigned totalProxyReply;
#endif
    //The Gratuitous request also included into the arpRequest
    unsigned totalGratReqSend;

    unsigned numPktDiscarded;

    // ARP Cache Statistics
    unsigned totalCacheEntryCreated;
    // Change in Hardware Address
    unsigned totalCacheEntryUpdated;
    unsigned totalCacheEntryAgedout;
    // Age out +  deletion due to fault
    unsigned totalCacheEntryDeleted;
    unsigned arppacketdropped;
} ArpStat;


// /**
// STRUCT      :: ArpRequestSentDb
// DESCRIPTION :: Struture of the ARP request Sent Database.
//                A mechanism to prevent ARP flooding (repeatedly sending an
//                ARP Request for the same IP address, at a high rate) MUST
//                be included.  The recommended maximum rate is 1 per second
//                per destination (RFC 1122)
// **/
typedef struct arp_request_sentdb_str
{
    NodeAddress protocolAddr;
    clocktype   sentTime;
    int         RetryCount;
    LinkedList* arpBuffer;
    // DHCP
    bool isDHCP;
} ArpRequestSentDb;


// /**
// STRUCT      :: ArpInterfaceInfo
// DESCRIPTION :: Structure hold the information related to interface
// **/
typedef struct arp_data_interface_info
{
    unsigned short  hardType;
    unsigned short  protoType;
    BOOL            isEnable;
    LinkedList*     arpDb;
    Queue*          requestQueue;
    BOOL            isArpBufferEnable;
    int             maxBufferSize;
    BOOL            isArpStatEnable;
    struct arp_stat_str stats;
} ArpInterfaceInfo;

// /**
// STRUCT      :: ArpData
// DESCRIPTION :: Main Data Struture of ARP at each interface.
// **/
typedef struct arp_data_str
{
    ArpInterfaceInfo    interfaceInfo[MAX_NUM_INTERFACES];
    LinkedList*         arpTTable;
    clocktype           arpExpireInterval;
    int                 maxRetryCount;
} ArpData;


// /**
// STRUCT      :: AddressResolutionModule
// DESCRIPTION :: Struture stored in MacData where data structures related to
//               Address Resolution Protocols like ARP, RARP, etc are stored.
// **/
typedef struct address_resolution_module
{
    ArpData* arpData;
    ArpData* rarpData;
} AddressResolutionModule;


// /**
// FUNCTION     ArpReceivePacket
// PURPOSE:     This is the API function between IP and ARP.
//              Receive ARP packet
// PARAMETERS   Node *node
//                  Pointer to node.
//              msg
//                  which will be process.
//              interfaceIndex
//                  incoming interface.
// RETURN      :: void : NULL
// **/
void ArpReceivePacket(
         Node* node,
         Message* msg,
         int interfaceIndex);

// /**
// FUNCTION   ::  ArpSneakPacket
// PURPOSE:   ::  Sneak ARP packet, node is working in promiscous mode
// PARAMETERS ::  
// + node : Node* Pointer to node.
// + msg :  Message pointer 
// + interfaceIndex :incoming interface.
// RETURN      :: void : NULL
 //**/
void ArpSneakPacket(
         Node* node,
         Message* msg,
         int interfaceIndex);

// /**
// FUNCTION    :: ArpTTableLookup
// LAYER       :: NETWORK
// PURPOSE     :: This is the API function between IP and ARP.
//                This function search for the Ethernet address
//                corresponding to protocolAddress from ARP
//                cache or Translation Table.
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int  : outgoing interface.
// + protoType : unsigned short  : Protocol Type
// + priority : TosType  :
// + protocolAddress : NodeAddress : Ethernet address surch for
//                                   this Ip address.
// + macAddr : MacAddress** : Ethernet address corresponding
//                            Ip address if exist.
// + msg : Message**  : Message pointer
// +  incomingInterface : int : Incoming Interface
// +  networkType : int : Network Type
// RETURN      :: BOOL : If success TRUE
// **/

BOOL ArpTTableLookup(
         Node* node,
         int interfaceIndex,
         unsigned short protoType,
         TosType priority,
         NodeAddress protocolAddress,
         MacHWAddress* macAddr,
         Message** msg,
         int incomingInterface,
         int networkType);

// /**
// FUNCTION    :: ArpInit
// LAYER       :: NETWORK
// PURPOSE     :: Initialize ARP all data structure and configuration
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + nodeInput  : const NodeInput* : Pointer to node input.
// RETURN      :: void : NULL
// **/
void ArpInit(
         Node* node,
         const NodeInput* nodeInput);

// /**
// FUNCTION    :: ArpHandleHWInterfaceFault
// LAYER       :: NETWORK
// PURPOSE     :: Handle Interface Fault Situations
// PARAMETERS  ::
// + node        : Node* : Pointer to node.
// + interfaceIndex : int : Interface Index
// + isInterfaceFaulty : BOOL : Denotes interface fault status.
// RETURN      :: void : NULL
// **/
void ArpHandleHWInterfaceFault(
         Node* node,
         int interfaceIndex,
         BOOL isInterfaceFaulty);

// /**
// FUNCTION    :: ArpProxy
// LAYER       :: NETWORK
// PURPOSE     :: This function is used for Proxy ARP reply.
//                It is special used by home agent or gateway to
//                to response in absence of host in home network.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : arp Request or Reply message
// + interfaceIndex : int  : Interface Index
// + proxyIp        : NodeAddress : The Ip address of the host
//                    whose proxy has been given.
// RETURN      :: void : NULL
// **/
void ArpProxy(
         Node* node,
         Message* msg,
         int interfaceIndex,
         NodeAddress proxyIp);

// /**
// FUNCTION      :: ArpProxyCreatePacket
// LAYER         :: NETWORK
// PURPOSE       :: This function creates an ARP reply packet
//                  for the node which is not in same home network.
// PARAMETERS    ::
// + node         : Node* : Pointer to node which indiates the host.
// + arpData      : ArpData* : arp main Data structure of this interface.
// + opCode       : ArpOp : Type of operation that is Reply in case of
//                          proxy arp.
// + proxyAddress : NodeAddress : used for proxy IP
// + destIPAddr   : NodeAddress :
// + dstMacAddr   : MacHWAddress  : Destination hardware address.
// + interfaceIndex: int        :
// RETURN      :: Message* : Pointer to a Message structure
// **/
Message* ArpProxyCreatePacket(
             Node* node,
             ArpData* arpData,
             ArpOp opCode,
             NodeAddress proxyAddress,
             NodeAddress destAddr,
             MacHWAddress& dstMacAddr,
             int interfaceIndex);

// /**
// FUNCTION    :: ArpGratuitous
// LAYER       :: NETWORK
// PURPOSE     :: This function is used for Gratuitous ARP reply.
//                It is special used by home agent or gateway to
//                to update the others ARP cache when the host
//                (which is responsible) came to know that the
//                host is not at home network. Gratuitous may be either
//                ARP request or ARP reply. Here ARP-request has been used
// PARAMETERS  ::
// + node      : Node* : Pointer to node that is host which
//                       is either gateway or home agent.
// + msg       : Message* : arp Request or Reply message
// + interfaceIndex : int : Interface Index
// + gratIPAddress  : NodeAddress : The Ip address of the host
//                                  whose mac address has beenupdated
//                                  in the ARP-cache table of other nodes.
// RETURN      :: void : NULL
// **/
void ArpGratuitous(
         Node* node,
         Message* msg,
         int interfaceIndex,
         NodeAddress gratIPAddress);

// /**
// FUNCTION      :: ArpGratuitousCreatePacket
// LAYER         :: NETWORK
// PURPOSE       :: This function creates an ARP reply packet
//                  for the node which is not in same home network.
// PARAMETERS    ::
// + node         : Node* : Pointer to node which indiates the host.
// + arpData      : ArpData* : arp main Data structure of this interface.
// + opCode       : ArpOp : The ARP message type
// + gratIPAddress: NodeAddress : The ip against whose the MAC addess
//                                 will be updated.
// + destIPAddr   : NodeAddress : The node who has send the ARP-request
// + dstMacHWAddr   : MacAddress  : The hardware address
// + interfaceIndex: int : Interface of the node
// RETURN      :: Message* : Pointer to a Message structure
// **/
Message* ArpGratuitousCreatePacket(
             Node* node,
             ArpData* arpData,
             ArpOp opCode,
             NodeAddress gratIPAddress,
             NodeAddress destIPAddr,
             MacHWAddress& dstMacAddr,
             int interfaceIndex);

// /**
// FUNCTION    :: ArpLayer
// LAYER       :: NETWORK
// PURPOSE     :: Handle ARP events
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// + msg        : Message* : Pointer to message.
// RETURN      :: void : NULL
// **/
void ArpLayer(
         Node* node,
         Message* msg);

// /**
// FUNCTION    :: ArpFinalize
// LAYER       :: NETWORK
// PURPOSE     :: Finalize function for the ARP protocol.
// PARAMETERS  ::
// + node       : Node* : Pointer to node.
// RETURN      :: void : NULL
// **/
void ArpFinalize(Node* node);

// /**
// FUNCTION    :: ArpPrintTrace
// LAYER       :: NETWORK
// PURPOSE     :: Print out packet trace information.
// PARAMETERS  ::
// + node       : Node* : node printing out the trace information.
// + msg        : Message* : packet to be printed.
// RETURN      :: void : NULL
// **/
void ArpPrintTrace(Node *node, Message *msg);

// /**
// FUNCTION    :: ArpLookUpHarwareAddress
// LAYER       :: NETWORK
// PURPOSE     :: The function is used whenever required
//                to get the hardware address against the ip address
// PARAMETERS  ::
// + node       : Node*: Pointer to node whome require to know the
//                       hardware address
// + protocolAddress : NodeAddress  : The ip-address whose hardware
//                                     address is looking for.
// + interfaceIndex: int  : The interface number of the protocol address
// + hwType     : unsigned short :
// + hwAddr     : unsigned char  : The hardware address has been assigned
//                                 to the character pointer
// RETURN      :: BOOL : Return the boolean value
// **/
BOOL ArpLookUpHarwareAddress(
         Node* node,
         NodeAddress protocolAddress,
         int interface,
         unsigned short hwType,
         unsigned char  *hwAddr);

// /**
// FUNCTION    :: ArpInterfaceChecking
// LAYER       :: NETWORK
// PURPOSE     :: This function is used to retrieve the interface through
//                which the neighbour has been connected to node
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + neighbourIp : NodeAddress : The ip-address which will is the static
//                               entry
// + nodeInterface : int* : The interface through which the neighbourIp
//                          has been connected
// RETURN      :: void : NULL
// **/
void ArpInterfaceChecking(
         Node* node,
         NodeAddress neighbourIp,
         int *nodeInterface);

// /**
// FUNCTION    :: ArpSeperateNodeAndInterface
// LAYER       :: NETWORK
// PURPOSE     :: It does check whether the ipAddressStr is either
//                nodeid-interface (nodeid-interface) or ip-address
//                if this is nodeid-interface, the values set into
//                nodeId and interface with the value and the BOOL set TRUE
//                Otherwise the BOOL value is FALSE
// PARAMETERS  ::
// + ipAddressStr[] : const char :
//                   Character string which has either nodeid-interface or
//                   ip-address string
//                   - the multicast protocol to get.
//                   interfaceId - specific interface index or ANY_INTERFACE
// + nodeId : NodeAddress* :The value to be set after extracting the
//                          nodeid from string
// + intfIndex : int* : The value to be set after extracting the interface
//                      from string
// + isNodeId : BOOL* : The value to be set TRUE if the string is
//                      nodeid-interface otherwise FALSE
// RETURN      :: void : NULL
// **/
void ArpSeperateNodeAndInterface(
         const char ipAddressStr[],
         NodeAddress* nodeId,
         int* intfIndex,
         BOOL* isNodeId);

// /**
// FUNCTION            :: ArpConvertStringAddressToNetworkAddress
// LAYER               :: NETWORK
// PURPOSE             :: Convert the input ip address in character
//                        format to NodeAddress
// PARAMETERS          ::
// + addressString      : const char : String which has ip-string
//                                     in character format
// + outputNodeAddress  : NodeAddress* : The string value converted
//                                       to NodeAddress value
// RETURN              :: void : NULL
// **/
void ArpConvertStringAddressToNetworkAddress(
         const char addressString[],
         NodeAddress *outputNodeAddress);

// /**
// FUNCTION    :: ArpIsEnable
// LAYER       :: NETWORK
// PURPOSE     :: The function is used for checking whether ARP is
//                enable or not.
// PARAMETERS  ::
// + node       : Node* :Pointer to node.
// RETURN      :: BOOL  : The boolean (either True or false) value
// **/
BOOL ArpIsEnable(Node* node);

// /**
// FUNCTION    :: ArpIsEnable overloading
// LAYER       :: NETWORK
// PURPOSE     :: The function is used for checking whether ARP is
//                enable or not.
// PARAMETERS  ::
// + node       : Node* :Pointer to node.
// + int       : interface :Pointer to node.
// RETURN      :: BOOL  : The boolean (either True or false) value
// **/
BOOL ArpIsEnable(Node* node, int interface);

// /**
// FUNCTION    :: EnqueueArpPacket
// LAYER       :: NETWORK
// PURPOSE     :: This function enqueues an ARP packet into the ARP Queue
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int : Interface of the node
// + msg:  Message* message to enqueue
// + arpData : ArpData* : arp main Data structure of this interface.
// + isFull : BOOL : Queue is Full or not
// + nextHop : NodeAddress : nextHop Ip address.
// + dstHWAddr : MacHWAddress& : destination hardware address address
// **/

void EnqueueArpPacket(Node* node,
                      int interfaceIndex,
                      Message *msg,
                      ArpData *arpData,
                      BOOL *isFull,
                      NodeAddress nextHop,
                      MacHWAddress& destHWAddr);

// /**
// FUNCTION    :: DequeueArpPacket
// LAYER       :: NETWORK
// PURPOSE     :: This function dequeues an ARP packet from the ARP Queue
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int : Interface of the node
// + msg:  Message** variable for the mesaage dequeued
// + nextHop : NodeAddress : nextHop Ip address.
// + dstHWAddr : MacHWAddress& : destination hardware address address
// Return BOOL : True when message is successfully dequeued
// **/
BOOL DequeueArpPacket(Node *node,
                      int interfaceIndex,
                      Message **msg,
                      NodeAddress *nextHopAddr,
                      MacHWAddress *destMacAddr);

// /**
// FUNCTION    :: ArpQueueIsEmpty
// LAYER       :: NETWORK
// PURPOSE     :: Checks if ARP queue is empty
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface for which request queue is checked
// RETURN: BOOL True when Queue is empty
//**/
BOOL ArpQueueIsEmpty(Node *node,
                     int interfaceIndex);

// /**
// FUNCTION    :: ArpQueueTopPacket
// LAYER       :: NETWORK
// PURPOSE     :: Peeks at the top packet in  ARP queue
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface for which request queue is checked
// + msg:  Message** variable for the mesaage
// + nextHop : NodeAddress : nextHop Ip address.
// + destMacAddr : MacHWAddress* : destination hardware address address
// Return BOOL : True when message is successfully found
//**/

BOOL ArpQueueTopPacket(
                  Node *node,
                  int interfaceIndex,
                  Message **msg,
                  NodeAddress *nextHopAddr,
                  MacHWAddress *destMacAddr);

// /**
// FUNCTION    :: ReverseArpTableLookUp
// LAYER       :: NETWORK
// PURPOSE     :: Finds IP address for a give Mac Address
// PARAMETERS  ::
// + node : Node* Pointer to node
// + interfaceIndex : int :interface of the node
// + macAddr : MacHWAddress* :hardware address
// Return NodeAddress : Ip address for a mac address
//**/
NodeAddress ReverseArpTableLookUp(
              Node* node,
              int interfaceIndex,
              MacHWAddress* macAddr);

// /**
// FUNCTION            :: ARPNotificationOfPacketDrop
// LAYER       :: NETWORK
// PURPOSE             :: Notify for ARP Drop
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + msg : Message**  : Message pointer
// + nextHopAddress : NodeAddress : Ip address of node
// + interfaceIndex : int  : outgoing interface.
// RETURN      :: NULL
// **/
void ARPNotificationOfPacketDrop(Node *node,
                                 Message *msg,
                                 NodeAddress nextHopAddress,
                                 int interfaceIndex);
// DHCP
//---------------------------------------------------------------------------
// FUNCTION            :: ArpCheckAddressForDhcp
// LAYER       :: NETWORK
// PURPOSE             :: Validate the Ipaddress for DHCP
// PARAMETERS  ::
// + node : Node* : Pointer to node.
// + Address : ipAddress  : Address to check
// + incomingInterface : int  : interface for broadcast
// RETURN      ::
// BOOL ......result
//---------------------------------------------------------------------------
void ArpCheckAddressForDhcp(
             Node* node,
             Address ipAddress,
             Int32 interfaceIndex);
#endif ///* ARP_H */
