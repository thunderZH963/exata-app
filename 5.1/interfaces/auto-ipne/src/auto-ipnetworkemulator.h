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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#ifndef _AUTO_IP_NETWORK_EMULATOR_H_
#define _AUTO_IP_NETWORK_EMULATOR_H_

//#define RETAIN_IP_HEADER

#include "api.h"
#include "external.h"

// forward declarations
typedef struct pcap pcap_t;
typedef struct libnet_context libnet_t;

// define char[6] as data structure to be used for STL
struct StlMacAddress {
    char address[6];
    bool operator<(StlMacAddress& other) const
    {
        for (int i = 0; i < 6; i++)
        {
            if (address[i] == other.address[i])
                continue;
            return (address[i] < other.address[i]);
        }
        return true;
    }
};


//---------------------------------------------------------------------------
// Constants
//---------------------------------------------------------------------------

// /**
// DEFINE      :: AutoIPNE_MAX_SOCKETS
// DESCRIPTION :: The number of sockets AutoIPNE may have open at the same time
// **/
#define AutoIPNE_MAX_SOCKETS 32

// /**
// DEFINE      :: AutoIPNE_ETHERNET_HEADER_LENGTH
// DESCRIPTION :: The size of an ethernet frame in bytes
// **/
#define AutoIPNE_ETHERNET_HEADER_LENGTH sizeof(struct libnet_ethernet_hdr)

// /**
// DEFINE      :: AutoIPNE_MIN_PACKET_CAPTURE_SIZE
// DESCRIPTION :: Minimum size of packet that can be logged
// **/
#define AutoIPNE_MIN_PACKET_CAPTURE_SIZE 64

// /**
// DEFINE      :: AutoIPNE_DEFAULT_STATISTICS_INTERVAL
// DESCRIPTION :: Default interval between printing dynamic external node stats
// **/
#define AutoIPNE_DEFAULT_STATISTICS_INTERVAL (3 * SECOND)

enum {
    AUTO_IPNE_MODE_DISABLED,
    AUTO_IPNE_MODE_NAT_DISABLED_ROUTING_DISABLED, /* nat no, router-true emulation */
    AUTO_IPNE_MODE_NAT_DISABLED_ROUTING_ENABLED, /* nat no, application-true emulation */
    AUTO_IPNE_MODE_NAT_ENABLED /* nat yes */
};

// Ensure that the cumm stats follows immediately to the local stat
enum {
    AUTO_IPNE_STATS_ALL_IN_PKT,
    AUTO_IPNE_STATS_ALL_IN_PKT_CUMM,
    AUTO_IPNE_STATS_ALL_OUT_PKT,
    AUTO_IPNE_STATS_ALL_OUT_PKT_CUMM,
    AUTO_IPNE_STATS_ALL_IN_BYTES,
    AUTO_IPNE_STATS_ALL_IN_BYTES_CUMM,
    AUTO_IPNE_STATS_ALL_OUT_BYTES,
    AUTO_IPNE_STATS_ALL_OUT_BYTES_CUMM,

    AUTO_IPNE_STATS_TCP_IN_PKT,
    AUTO_IPNE_STATS_TCP_IN_PKT_CUMM,
    AUTO_IPNE_STATS_TCP_OUT_PKT,
    AUTO_IPNE_STATS_TCP_OUT_PKT_CUMM,
    AUTO_IPNE_STATS_UDP_IN_PKT,
    AUTO_IPNE_STATS_UDP_IN_PKT_CUMM,
    AUTO_IPNE_STATS_UDP_OUT_PKT,
    AUTO_IPNE_STATS_UDP_OUT_PKT_CUMM,
    AUTO_IPNE_STATS_MULTI_IN_PKT,
    AUTO_IPNE_STATS_MULTI_IN_PKT_CUMM,
    AUTO_IPNE_STATS_MULTI_OUT_PKT,
    AUTO_IPNE_STATS_MULTI_OUT_PKT_CUMM,
    AUTO_IPNE_STATS_TCP_IN_BYTES,
    AUTO_IPNE_STATS_TCP_IN_BYTES_CUMM,
    AUTO_IPNE_STATS_TCP_OUT_BYTES,
    AUTO_IPNE_STATS_TCP_OUT_BYTES_CUMM,
    AUTO_IPNE_STATS_UDP_IN_BYTES,
    AUTO_IPNE_STATS_UDP_IN_BYTES_CUMM,
    AUTO_IPNE_STATS_UDP_OUT_BYTES,
    AUTO_IPNE_STATS_UDP_OUT_BYTES_CUMM,
    AUTO_IPNE_STATS_MULTI_IN_BYTES,
    AUTO_IPNE_STATS_MULTI_IN_BYTES_CUMM,
    AUTO_IPNE_STATS_MULTI_OUT_BYTES,
    AUTO_IPNE_STATS_MULTI_OUT_BYTES_CUMM,

    // Do not add any enum entry after this
    AUTO_IPNE_STATS_SIZE
};



//---------------------------------------------------------------------------
// Function Pointer Prototypes
//---------------------------------------------------------------------------

// /**
// FUNCTION    :: AutoIPNE_EmulatePacketFunction
// DESCRIPTION :: Function used to emulate a packet into QualNet.  This is
//                used when a new packet is sniffed on the network.  If the
//                packet is from a given socket then the socket may specify
//                its own custom injection function.
// **/
typedef void (AutoIPNE_EmulatePacketFunction)(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    int size);

// /**
// TYPEDEF     :: AutoIPNE_SocketFunction
// DESCRIPTION :: This function will process a packet that is associated
//                with a socket.  It has a few responsibilities:
//
//                1) Modify the packet based on a specific protocol's needs.
//                   Ie, VOIP packets must swap real <-> qualnet addresses.
//                2) Update the UDP/TCP checksum for each modification
//                3) Tell QualNet which function to use to inject the packet
//                   into the simulation.  Most sockets will not do anything
//                   here, which will cause the default IP packet injection
//                   function to be used.
// **/
typedef void (*AutoIPNE_SocketFunction)(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    UInt8 *data,
    int packetSize,
    UInt16 *sum,
    AutoIPNE_EmulatePacketFunction **func);


// /**
// STRUCT      :: AutoIPNE_NodeMapping
// DESCRIPTION :: Data used to store information of a virtual node
// **/
struct AutoIPNE_NodeMapping
{
    // The device associated with this node mapping
    int deviceIndex;

    // IPNE Mode (with or without NAT)
    int ipneMode;

    // The physical address of operational host (in network byte order)
    Address physicalAddress;

    // The address of virtual node (in network byte order)
    // Will be different from physical address only when NAT is enabled
    Address virtualAddress;

    // MAC address of the operational host
    char     macAddress[6];
    int     macAddressSize;
    char     macAddressString[18];

    AutoIPNE_NodeMapping *next;

    // The node pointer
    Node *node;

    // The interface index
    int interfaceIndex;

    bool isVirtualLan;

    std::map<int, StlMacAddress> *virtualLanARP;
};



// /**
// STRUCT      :: AutoIPNEIPSocket
// DESCRIPTION :: Data used to maintain an IP socket.  Any address or port
//                value that is set to 0 will be ignored.
// **/
struct AutoIPNEIPSocket
{
    // The first address in network byte order
    UInt32 addr1;

    // The first port
    UInt16 port1;

    // The second address in network byte order
    UInt32 addr2;

    // The second port
    UInt16 port2;

    // The function to call for packets sent by this socket
    AutoIPNE_SocketFunction func;
};

// /**
// STRUCT      :: AutoIpneV4V6Address
// DESCRIPTION :: Structure to store V4/V6 related information like address,
//                subnet mask, prefix length, scope id.
// **/
struct AutoIpneV4V6Address
{
    Address address;
    union
    {
        UInt32 subnetmask;
        struct
        {
            UInt8 OnLinkPrefixLength;
            UInt64 scopeId;
        }ipv6;
    }u;
};

// /**
// STRUCT      :: AutoIPNEDeviceData
// DESCRIPTION :: Data used to store information on each device that AutoIPNE
//                is sniffing/injecting packets on.
// **/
struct AutoIPNEDeviceData
{
    // pcap data for sniffing
    pcap_t *pcapFrame;

    // libnet data for injecting at network layer
    libnet_t *libnetFrame;

    // libnet data for injecting at link layer
    libnet_t *libnetLinkFrame;

    // The name of the device we are sniffing on
    char device[MAX_STRING_LENGTH];

    // The mac address of this device
    char macAddress[MAX_STRING_LENGTH];

    //DERIUS
        // The IP address of this device
    char ipAddress[MAX_STRING_LENGTH];

    // list to store v4/v6 address of a device
    std::list<AutoIpneV4V6Address> *interfaceAddress;

    // Information on virtual nodes
    AutoIPNE_NodeMapping *mappingsList;

    // If pcap can operate on this device
    BOOL disabled;

    // Device traffic statistics
    UInt32 received;
    UInt32 dropped;

};
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
// /**
// STRUCT      :: MiQualnetNodeIdMapEntry
// DESCRIPTION :: Contains Mi node Id, Qualnet node Id and Ip address of nodes
// **/

struct MiQualnetNodeIdMapEntry
{
    NodeId qualNodeId;
    UInt16 miNodeId;
    char fakeMacAddressString[MAX_STRING_LENGTH];
    char realMacAddressString[MAX_STRING_LENGTH];
    NodeAddress ipAddress;
    int interfaceIndex;
};

struct compareFunction
{
    bool operator() (
        const std::pair<NodeId, int> &k1,
        const std::pair<NodeId, int> &k2) const
    {
        if (k1.first != k2.first)
        {
            return (k1.first < k2.first);
        }
        else 
        {
            return (k1.second < k2.second);
        }
    }
};

//Key = Mi Node Id, Value = MiQualnetNodeIdMapEntry
typedef std::map<UInt16, MiQualnetNodeIdMapEntry *> MiToQualnetNodeIdMap;
typedef std::map<UInt16, MiQualnetNodeIdMapEntry *>::iterator MiToQualnetNodeIdMapIter;

//Key = Qualnet Node Id, Value = MiQualnetNodeIdMapEntry
typedef std::map<std::pair<NodeId,int>, MiQualnetNodeIdMapEntry *, compareFunction> QualnetToMiNodeIdMap;
typedef std::map<std::pair<NodeId,int>, MiQualnetNodeIdMapEntry *, compareFunction>::iterator QualnetToMiNodeIdMapIter;
#endif

// /**
// STRUCT      :: AutoIPNEData
// DESCRIPTION :: Data that is used for this external interface
// **/
struct AutoIPNEData
{
    bool isAutoIPNE; // MUST be the first field

    // Number of devices we are sniffing/injecting on
    int numDevices;

    // Array of devices
    AutoIPNEDeviceData *deviceArray;

    // Number of virtual nodes
    int numVirtualNodes;


    // ospf 
    int ospfSocket;
    int numOspfNodes;
    NodeAddress* ospfNodeAddress;
    BOOL ospfEnabled;

    BOOL incomingPacketLog;
    BOOL outgoingPacketLog;
    void *incomingSuccessPacketLogger;
    void *incomingIgnoredPacketLogger;
    void *outgoingPacketLogger;
    int packetLogCaptureSize;
    // Socket information
    //int numSockets;
    //AutoIPNEIPSocket sockets[AutoIPNE_MAX_SOCKETS];

    // Nat specifies whether or not Nat-Yes mode is being used
//    BOOL nat;

    // TRUE if we should do true network emulation.  FALSE if we should only
    // sniff packets between virtual nodes.  True emulation may only be used
    // if nat is disabled.
//    BOOL trueEmulation;

#if 1
    //DERIUS
    // Number of ARP target nodes   
    int numArpReq;
    // Number of ARP response received
    int numArpReceived;
    // The addresses of the nodes of ARP target
    NodeAddress* arpNodeAddress;
    // Number of ARP request for TrueEmulation to resolve MAC address
    //BOOL arpRequest;
    // TRUE if ARP is retransmitted 
    BOOL arpRetransmission;          
    // For ARP retransmission delay 
    clocktype arpSentTime;
#endif

    // AutoIPNE statistics
    clocktype jitter;
    clocktype avgReceiveDelayInterval;
    clocktype maxReceiveDelayInterval;
    clocktype lastReceiveTime;
    clocktype lastSendIntervalDelay;
    unsigned long stats[AUTO_IPNE_STATS_SIZE];

    // True if AutoIPNE will explicitly caluclate UDP/TCP checksums instead of
    // incrementally calculating them
    BOOL explictlyCalculateChecksum;

    // True if unknown protocols in Nat-Yes mode will be routed (not
    // simulated) by AutoIPNE
    BOOL routeUnknownProtocols;

    // True if AutoIPNE should print debug information
    BOOL debug;

    // TRUE if AutoIPNE should print a log of all packets sniffed/injected
    BOOL printPacketLog;

    // TRUE if AutoIPNE should print occasional statistics to stdout
    BOOL printStatistics;

    // The last time statistics were printed to stdout
    clocktype lastStatisticsPrint;

    // Generic Multicast Mac address (for boeing for the time being)
    BOOL genericMulticastMac;

    //PRECEDENCE
    BOOL precEnabled;
    // number of PRECEDENCE pairs
    int numPrecPairs;

    // Priority
    char precPriority;

    NodeAddress* precSrcAddress;
    char ** precSrcAddressString;
    NodeAddress* precDstAddress;
    char ** precDstAddressString;

    PartitionData* partitionData;

    // Mac spoofing option
    //BOOL macSpoofingEnabled;


#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
    
    MiToQualnetNodeIdMap* miQualNodeMap;
    QualnetToMiNodeIdMap* qualMiNodeMap;

#endif

};

//---------------------------------------------------------------------------
// Functions
//---------------------------------------------------------------------------

// /**
// API       :: LibnetIpAddressToULong
// PURPOSE   :: Take a libnet IP address (which differs on unix/windows) and
//              convert it to a UInt32
// PARAMETERS::
// + addr : in_addr : The libnet IP address
// RETURN    :: The 4 byte IP address
// **/
#ifdef _NETINET_IN_H
UInt32 LibnetIpAddressToULong(in_addr addr);
#endif

// /**
// API       :: PreProcessIpNatYes
// PURPOSE   :: This functions will swap the IP addresses in the IP header
//              as well as update the given checksum.  Works for TCP, UDP,
//              ICMP checksums (ones-complement style).
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// + ip : struct libnet_ipv4_hdr* : Pointer to the IP header
// + checksum : UInt16* : Pointer to the checksum in the TCP or UDP header
// RETURN    :: None
// **/
void PreProcessIpPacketNatYes(
    EXTERNAL_Interface* iface,
    struct libnet_ipv4_hdr* ip,
    UInt16* checksum);

// /**
// API       :: CompareAutoIPNEIPSocket
// PURPOSE   :: This function will check if 2 sockets match.  It is
//              essentially a large, ugly comparison.  The size is necessary
//              because any 0 value is ignored, but a socket should not
//              match if the comparison is based entirely on 0 values.
// PARAMETERS::
// + addr1 : UInt32 : The address of the first end of the socket
// + port1 : UInt16 : The port of the first end of the socket
// + addr2 : UInt32 : The address of the second end of the socket
// + port2 : UInt16 : The port of the second end of the socket
// + s : AutoIPNEIPSocket* : The socket to compare it with
// RETURN    :: void
// **/
int CompareAutoIPNEIPSocket(
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    AutoIPNEIPSocket* s);



// /**
// API       :: autoConfMAC
// PURPOSE   :: This function will generate a ARP request to
//                resolve MAC address from IP address in configuration file 
//                with TrueEmulation mode.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + deviceName : char * : The device name of destination node attached
// + realAddress : char * : target IP address
// RETURN    :: void
// **/

void    autoConfMAC(EXTERNAL_Interface* iface, 
                                        char * deviceName, 
                                        char * realAddress);

    
    
// /**
// API       :: IPAddressToString
// PURPOSE   :: This function will convert an IP address to a string.  IP
//              address should be in network byte order.
// PARAMETERS::
// addr : void* : Pointer to the address
// string : char* : The string.  The size should be at least 16 bytes.
// RETURN    :: void
// **/
void IPAddressToString(void *addr, char *string);

// /**
// API       :: PrintIPAddress
// PURPOSE   :: This function will print an IP address to stdout.  IP
//              address should be in network byte order.
// PARAMETERS::
// addr : void* : Pointer to the address
// RETURN    :: void
// **/
void PrintIPAddress(void *addr);

// /**

// /**
// API       :: SwapAddress
// PURPOSE   :: This function will swap a real IP address for a qualnet IP
//              address and vice versa.  It will also update a checksum
//              if provided.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The external interface
// + address : UInt8* : The address in network byte order
// + addressSize : int : The size of the address
// + sum : UInt16* : The checksum.  NULL if none.
// + packetStart : UInt8* : The start of the packet.  NULL if it is part of
//                           the virtual header.  See the function
//                           IncrementallyAdjustChecksum.
// RETURN    :: int : Returns 0 on success, non-zero on failure.
// **/
int SwapAddress(
    EXTERNAL_Interface *iface,
    UInt8 *address,
    int addressSize,
    UInt16 *sum,
    UInt8 *packetStart);



// /**
// API       :: SwapMulticastAddress
// PURPOSE   :: This function  swaps the destination multicast address
//              based on the mapping specified
// PARAMETERS::
// + node : Node * : Pointer to  Node data structure
// + iface : EXTERNAL_Interface * : Pointer to external interface
// + address : UInt8 * : Pointer to the address that needs to be swapped
// + addressSize: int: size of the address
// + sum : UInt16 * : Pointer to the checksum field
// + packetStart : UInt8 * : Pointer to start of packet
// RETURN    :: int :  return 0
// **/

int SwapMulticastAddress(
    Node *node,
    EXTERNAL_Interface *iface,
    UInt8 *address,
    int addressSize,
    UInt16 *sum,
    UInt8 *packetStart);


// /**
// API       :: AutoIPNECheckMulticastAndDoNAT
// PURPOSE   :: This function  checks if the destination is a multicast
//              address and initiates swapping of this destination addresses
// PARAMETERS::
// + node : Node * : Pointer to  Node data structure
// + iface : EXTERNAL_Interface * : Pointer to external interface
// + forwardData : void * : pointer to packet
// + forwardSize : int : size of the packet
// RETURN    :: void
// **/
void AutoIPNECheckMulticastAndDoNAT(
        Node * node,
        EXTERNAL_Interface *iface,
        void *forwardData,
        int forwardSize);



// /**
// API       :: InjectLinkPacket
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectLinkPacket(
    EXTERNAL_Interface *iface,
    UInt8 *dest,
    UInt8 *source,
    UInt16 type,
    UInt8 *packet,
    int packetSize,
    clocktype receiveTime);

// /**
// API       :: InjectIpPacketAtNetworkLayer
// PURPOSE   :: This function will forward an IP packet to the external
//              source.  This function will forward an entire IP packet to
//              the network, meaning that it should include the link and
//              network headers.  A new packet will be created from these
//              headers and the data in the packet will be forwarded to the
//              network.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet.  Includes link + network
//                      headers.
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/


//DERIUS

// /**
// API       :: InjectLinkPacket for ARP request
// PURPOSE   :: This function will forward a link layer packet to the
//              external source.  All arguments should be in host byte order
//              except iface, packetSize and receiveTIme. This function is 
//                overloading function of InjectLinkPacket
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + dest : UInt8* : The destination 6 byte mac address
// + source : UInt8* : The source 7 byte mac address
// + type : UInt16 : The packet type
// + packet : UInt8* : Pointer to the packet data to forward
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// + deviceIndex: int : device index
// RETURN    :: void
// **/

void InjectLinkPacket(
    EXTERNAL_Interface *iface,
    UInt8 *dest,
    UInt8 *source,
    UInt16 type,
    UInt8 *packet,
    int packetSize,
    clocktype receiveTime,
    int deviceIndex);
//DERIUS


void InjectIpPacketAtNetworkLayer(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    int packetSize,
    clocktype receiveTime);

// /**
// API       :: InjectIpPacketAtLinkLayer
// PURPOSE   :: This function will insert an IP packet directly at the link
//              layer destined for the next hop of the packet i.e. the  external
//              source.  This function will create the outgoing IP packet
//              based its arguments.  Only the data of the outgoing packet
//              should be passed in the "packet" parameter.  All arguments
//              should be in host byte order except for packet, which will
//              be forwarded as passed. The function creates an ethernet header
//              after looking up the ethernet destination address of the next
//              hop and the corresponding source ethernet address. This
//              function then writes the packet directly at the link layer
//              avoiding the use of the nodes kernel ip routing tables.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + myAddress : NodeAddress : The address of the node that is forwarding
//                             the IP packet.
// + tos : UInt8 : The TOS field of the outgoing IP packet
// + id : UInt16 : The id field
// + offset : UInt16 : The offset field
// + ttl : UInt8 : The TTL field
// + protocol : UInt8 : The protocol field
// + srcAddr : UInt32 : The source addr field
// + destAddr : UInt32 : The dest addr field
// + packet : UInt8* : Pointer to the packet.  ONLY the data portion
//                             of the packet.
// + packetSize : int : The size of the packet
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void InjectIpPacketAtLinkLayer(
    EXTERNAL_Interface *iface,
    NodeAddress myAddress,
    UInt8 tos,
    UInt16 id,
    UInt16 offset,
    UInt8 ttl,
    UInt8 protocol,
    UInt32 srcAddr,
    UInt32 destAddr,
    UInt8 *packet,
    int packetSize,
    clocktype receiveTime);


// /**
// API       :: EmualateIpPacket
// PURPOSE   :: This is the default function used to inject a packet into
//              the QualNet simulation.  It will create a message from the
//              src to dst QualNet nodes.  It will call
//              EmulateIpPacketNatYes, EmulateIpPacketNatNo or
//              EmulateIpPacketTruEmulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + packet : UInt8* : Pointer to the packet sniffed from the network.
//                      Contains link and network headers.
// + packetSize : int : The size of the packet
// NOTES     :: In order for this function to work properly, mappings must
//              be created between real <-> qualnet nodes by calling
//              EXTERNAL_CreateMapping.
// RETURN    :: void
// **/
void EmulateIpPacket(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    int packetSize);

// /**
// API       :: AutoIPNE_ForwardFromNetworkLayer
// PURPOSE   :: This function will take a packet from the network layer and
//              inject it to the physical network.  Use in True-Emulation
//              mode.
// PARAMETERS::
// + node : Node* : The node that is forwarding the packet
// + interfaceIndex : int : The interface it was received on
// + msg : Message* : The packet
// RETURN    :: TRUE if the packet was injected, FALSE if not
// **/
BOOL AutoIPNE_ForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg,
    NodeAddress previousHopAddress,
    BOOL eavesdrop);

// /**
// API       :: AutoIPNE_ForwardFromNetworkLayer
// PURPOSE   :: This function will take a packet from the network layer and
//              inject it to the physical network.  Use in True-Emulation
//              mode. This version of API is added for Ipv6 support on EXata
// PARAMETERS::
// + node : Node* : The node that is forwarding the packet
// + interfaceIndex : int : The interface it was received on
// + msg : Message* : The packet
// + eavesdrop : BOOL : eavesdrop
// RETURN    :: TRUE if the packet was injected, FALSE if not
// **/
BOOL AutoIPNE_ForwardFromNetworkLayer(
    Node* node,
    int interfaceIndex,
    Message* msg);

// /**
// API       :: AutoIPNE_HandleIPStatisticsReceivePacket
// PURPOSE   :: This function will compute statistics upon receiving info
//              from the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + bytes : int : Number of bytes in this packet
// + now : clocktype : The current time
// RETURN    :: void
// **/
void AutoIPNE_HandleIPStatisticsReceivePacket(
    EXTERNAL_Interface *iface,
    int bytes,
    clocktype now);

// /**
// API       :: AutoIPNE_HandleIPStatisticsSendPacket
// PURPOSE   :: This function will compute statistics upon injecting info
//              back into the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + bytes : int : Number of bytes in this packet
// + receiveTime : clocktype : The time the packet was received.  This is
//                             the "now" value passed to
//                             HandleIPStatisticsReceive
// + now : clocktype : The current time
// RETURN    :: void
// **/
void AutoIPNE_HandleIPStatisticsSendPacket(
    EXTERNAL_Interface *iface,
    int bytes,
    clocktype receiveTime,
    clocktype now);

// /**
// API       :: AddAutoIPNEIPSocketPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given port.
// PARAMETERS::
// + data : AutoIPNEData* : The IP interface data structure.
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddAutoIPNEIPSocketPort(
    AutoIPNEData *data,
    UInt16 port,
    AutoIPNE_SocketFunction func);

// /**
// API       :: AddAutoIPNEIPSocketAddressPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given
//              address and port.
// PARAMETERS::
// + data : AutoIPNEData* : The IP interface data structure.
// + addr : UInt32 : The address
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddAutoIPNEIPSocketAddressPort(
    AutoIPNEData *data,
    UInt32 addr,
    UInt16 port,
    AutoIPNE_SocketFunction func);

// /**
// API       :: AddAutoIPNEIPSocketPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with addr1 and port1
//              and the other end with addr2 and port2.  Any address or port
//              value that is set to 0 will be ignored.
// PARAMETERS::
// + data : AutoIPNEData* : The IP interface data structure.
// + addr1 : UInt32 : The first address
// + port1 : UInt16 : The first port
// + addr2 : UInt32 : The second address
// + port2 : UInt16 : The second port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddAutoIPNEIPSocket(
    AutoIPNEData *data,
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    AutoIPNE_SocketFunction func);


//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: AutoIPNE_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              AutoIPNEData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void AutoIPNE_Initialize(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: AutoIPNE_InitializeNodes
// PURPOSE   :: This function is where the bulk of the IPNetworkEmulator
//              initialization is done.  It will:
//                  - Parse the interface configuration data
//                  - Create mappings between real <-> qualnet proxy
//                    addresses
//                  - Create instances of the FORWARD app on each node that
//                    is associated with a qualnet proxy address
//                  - Initialize the libpcap/libnet libraries using the
//                    configuration data
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void AutoIPNE_InitializeNodes(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: AutoIPNE_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void AutoIPNE_Receive(EXTERNAL_Interface *iface);

// /**
// API       :: AutoIPNE_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void AutoIPNE_Forward(
    EXTERNAL_Interface *iface,
    Node *node,
    void *forwardData,
    int forwardSize);

// /**
// API       :: AutoIPNE_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void AutoIPNE_Finalize(EXTERNAL_Interface *iface);

// /**
// API       :: AutoIPNE_AddVirtualNode
// PURPOSE   :: This function maps an IPv6 virtual address with an Ipv6
//              physical address
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + physicalAddress : Address : Ipv6 address of operational
//                         host
// + virtualAddress : Address : Ipv6 address of virtual node
// RETURN    :: BOOL : Whether mapping was successful or not
// **/

BOOL AutoIPNE_AddVirtualNode(
    EXTERNAL_Interface* iface,
    Address physicalAddress,
    Address virtualAddress,
    BOOL routingDisabled = FALSE);

BOOL AutoIPNE_RemoveVirtualNode(
    EXTERNAL_Interface *iface,
    Address physicalAddress,
    Address virtualAddress,
    BOOL routingDisabled);

// /**
// API       :: AutoIPNE_RemoveIPv6VirtualNode
// PURPOSE   :: This function removes mapping of an IPv6 virtual address with an Ipv6
//              physical address
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + physicalAddressIpv6 : Address : Ipv6 address of operational
//                         host
// + virtualAddressIpv6 : Address : Ipv6 address of virtual node
// RETURN    :: BOOL : Whether mapping was successful removed or not
// **/
bool AutoIPNE_RemoveIPv6VirtualNode(
    EXTERNAL_Interface* iface,
    Address physicalAddressIpv6,
    Address virtualAddressIpv6);

void AutoIPNE_DisableInterface(
    Node *node,
    Address interfaceAddress);
//Mapping for macAddress
//Key in the mapping table is not the macAddress alone but also the
//corresponding device index. This is required to ensure that more than 1
//physical interface with the same MAC address can be stored without any
//collisions
BOOL AutoIPNE_CreateMacKey(
    char key[],
    char* macAddress,
    int deviceIndex);
#ifdef JNE_BLACKSIDE_INTEROP_INTERFACE
void  AutoIPNE_InitializeMiQualNodeMap(
     AutoIPNEData* data);

void  AutoIPNE_InitializeQualnetMiNodeMap(
     AutoIPNEData* data);

MiQualnetNodeIdMapEntry* AutoIPNE_FindEntryForQualNodeId(
                        AutoIPNEData* data, 
                        NodeId qualNodeId,
                        int interfaceIndex);

MiQualnetNodeIdMapEntry* AutoIPNE_FindEntryForMIId(
                        AutoIPNEData* data, 
                        UInt16 miId);
#endif
#endif /* _IP_NETWORK_EMULATOR_H_ */
