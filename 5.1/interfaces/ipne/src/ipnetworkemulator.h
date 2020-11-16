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

#ifndef _IP_NETWORK_EMULATOR_H_
#define _IP_NETWORK_EMULATOR_H_

#include "api.h"
#include "external.h"

// forward declarations
typedef struct pcap pcap_t;
typedef struct libnet_context libnet_t;

//---------------------------------------------------------------------------
// Constants
//---------------------------------------------------------------------------

// /**
// DEFINE      :: IPNE_MAX_SOCKETS
// DESCRIPTION :: The number of sockets IPNE may have open at the same time
// **/
#define IPNE_MAX_SOCKETS 32

// /**
// DEFINE      :: IPNE_ETHERNET_HEADER_LENGTH
// DESCRIPTION :: The size of an ethernet frame in bytes
// **/
#define IPNE_ETHERNET_HEADER_LENGTH sizeof(struct libnet_ethernet_hdr)


#ifdef DERIUS
//run time stat Identifier
#define IN_TOTAL    0x0001 
#define OUT_TOTAL   0x0002
#define IN_ARP      0x0004
#define OUT_ARP     0x0008
#define IN_ICMP     0x0010
#define OUT_ICMP    0x0020
#define IN_TCP      0x0040
#define OUT_TCP     0x0080
#define IN_UDP      0x0100
#define OUT_UDP     0x0200
#endif


//---------------------------------------------------------------------------
// Function Pointer Prototypes
//---------------------------------------------------------------------------

// /**
// FUNCTION    :: IPNE_EmulatePacketFunction
// DESCRIPTION :: Function used to emulate a packet into QualNet.  This is
//                used when a new packet is sniffed on the network.  If the
//                packet is from a given socket then the socket may specify
//                its own custom injection function.
// **/
typedef void (IPNE_EmulatePacketFunction)(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    int size);

// /**
// TYPEDEF     :: IPNE_SocketFunction
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
typedef void (*IPNE_SocketFunction)(
    EXTERNAL_Interface *iface,
    UInt8 *packet,
    UInt8 *data,
    int packetSize,
    UInt16 *sum,
    IPNE_EmulatePacketFunction **func);

#ifdef DERIUS
// /**
// STRUCT      :: IPNE_Statstype
// DESCRIPTION :: Data used to store dynamic stats info
// **/
typedef struct {
        UInt32  ipneInNumPackets;
        int     ipneInNumPacketsId;
        UInt32  ipneOutNumPackets;
        int     ipneOutNumPacketsId;
        //ARP packets
        UInt32  ipneInArpPackets;
        int     ipneInArpPacketsId;
        UInt32  ipneOutArpPackets;
        int     ipneOutArpPacketsId;
        //ICMP packets
        UInt32  ipneInIcmpPackets;
        int     ipneInIcmpPacketsId;
        UInt32  ipneOutIcmpPackets;
        int     ipneOutIcmpPacketsId;
        //TCP packets
        UInt32  ipneInTcpPackets;
        int     ipneInTcpPacketsId;
        UInt32  ipneOutTcpPackets;
        int     ipneOutTcpPacketsId;
        //UDP packets
        UInt32  ipneInUdpPackets;
        int     ipneInUdpPacketsId;
        UInt32  ipneOutUdpPackets;
        int     ipneOutUdpPacketsId;
} IPNE_StatsType;
#endif

// /**
// STRUCT      :: IPNE_NodeMapping
// DESCRIPTION :: Data used to store information of a virtual node
// **/
struct IPNE_NodeMapping
{
    // The device associated with this node mapping
    int deviceIndex;

    // The real address in network byte order
    NodeAddress realAddress;
    int realAddressSize;
    char realAddressString[MAX_STRING_LENGTH];
    int realAddressStringSize;
    char realAddressWideString[MAX_STRING_LENGTH];
    int realAddressWideStringSize;

    // Only used for true emulation
    char macAddress[6];
    int macAddressSize;
    char macAddressString[18];
    int macAddressStringSize;

    // The proxy address in network byte order.  Only used for NAT-Enabled.
    NodeAddress proxyAddress;
    int proxyAddressSize;
    char proxyAddressString[MAX_STRING_LENGTH];
    int proxyAddressStringSize;
    char proxyAddressWideString[MAX_STRING_LENGTH];
    int proxyAddressWideStringSize;

    //Multicast Receive real address for the node. Used for NAT enabled
    //Multicast enabled

    NodeAddress multicastReceiveRealAddress;
    int multicastReceiveRealAddressSize;
    char multicastReceiveRealAddressString[MAX_STRING_LENGTH];
    int multicastReceiveRealAddressStringSize;
    char multicastReceiveRealAddressWideString[MAX_STRING_LENGTH];
    int multicastReceiveRealAddressWideStringSize;

    //Multicast Transmit address for the node. Used for NAT enabled
    //Multicast enabled

    NodeAddress multicastTransmitAddress;
    int multicastTransmitAddressSize;
    char multicastTransmitAddressString[MAX_STRING_LENGTH];
    int multicastTransmitAddressStringSize;
    char multicastTransmitAddressWideString[MAX_STRING_LENGTH];
    int multicastTransmitAddressWideStringSize;

};

// /**
// STRUCT      :: IPSocket
// DESCRIPTION :: Data used to maintain an IP socket.  Any address or port
//                value that is set to 0 will be ignored.
// **/
struct IPSocket
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
    IPNE_SocketFunction func;
};

// /**
// STRUCT      :: DeviceData
// DESCRIPTION :: Data used to store information on each device that IPNE
//                is sniffing/injecting packets on.
// **/
struct DeviceData
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
};

// /**
// STRUCT      :: IPNEData
// DESCRIPTION :: Data that is used for this external interface
// **/
struct IPNEData
{
    bool isAutoIPNE;  // Must be the first field


    // Number of devices we are sniffing/injecting on
    int numDevices;

    // Array of devices
    DeviceData *deviceArray;

    // Socket information
    int numSockets;
    IPSocket sockets[IPNE_MAX_SOCKETS];

    // Nat specifies whether or not Nat-Yes mode is being used
    BOOL nat;

    // TRUE if we should do true network emulation.  FALSE if we should only
    // sniff packets between virtual nodes.  True emulation may only be used
    // if nat is disabled.
    BOOL trueEmulation;


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

    // IPNE statistics
    int sentPackets;
    int receivedPackets;
    clocktype jitter;
    clocktype avgReceiveDelayInterval;
    clocktype maxReceiveDelayInterval;
    clocktype lastReceiveTime;
    clocktype lastSendIntervalDelay;

    // True if IPNE will explicitly caluclate UDP/TCP checksums instead of
    // incrementally calculating them
    BOOL explictlyCalculateChecksum;

    // True if unknown protocols in Nat-Yes mode will be routed (not
    // simulated) by IPNE
    BOOL routeUnknownProtocols;

    // True if IPNE should print debug information
    BOOL debug;

    // TRUE if IPNE should print a log of all packets sniffed/injected
    BOOL printPacketLog;

    // TRUE if IPNE should print occasional statistics to stdout
    BOOL printStatistics;

    // The last time statistics were printed to stdout
    clocktype lastStatisticsPrint;

    // If OSPF is turned on
    BOOL ospfEnabled;

    // number of OSPF Routers to interface
    int numOspfNodes;

    // The addresses` of the nodes running OSPF in host byte order
    NodeAddress* ospfNodeAddress;

    // The addresses of the node running OSPF in string form
    char** ospfNodeAddressString;

    // The socket used for accepting incoming OSPF packets.  All incoming
    // packets are ignored and are instead sniffed through IPNE.  This
    // avoids an ICMP protocol not supported response to the operational
    // OSPF host.
    int ospfSocket;

    //Multicasting support
    BOOL multicastEnabled;

    //Start OLSR interface
    
    // If OLSR is turned on
    BOOL olsrEnabled;
    // number of OLSR Routers to interface
    int numOlsrNodes;
    // The addresses of the nodes running OLSR in host byte order
    NodeAddress* olsrNodeAddress;
    // The addresses of the node running OSPF in string form
    char** olsrNodeAddressString;
    // The addresses of the node running OSPF in string form
    BOOL olsrNetDirectedBroadcast;
    
    //End OLSR interface

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

    // Mac spoofing option
    BOOL macSpoofingEnabled;

    //Start Rip interface
    BOOL ripEnabled;
    // number of Rip Routers to interface
    int numRipNodes;
    
    // The addresses of the nodes running Rip in host byte order
    NodeAddress* ripNodeAddress;

    // The addresses of the node running Rip in string form
    char** ripNodeAddressString;
    //End Rip interface

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
// + iface : EXTERNAL_Interface* : The IPNE interface
// + ip : struct libnet_ipv4_hdr* : Pointer to the IP header
// + checksum : UInt16* : Pointer to the checksum in the TCP or UDP header
// RETURN    :: None
// **/
void PreProcessIpPacketNatYes(
    EXTERNAL_Interface* iface,
    struct libnet_ipv4_hdr* ip,
    UInt16* checksum);

// /**
// API       :: CompareIPSocket
// PURPOSE   :: This function will check if 2 sockets match.  It is
//              essentially a large, ugly comparison.  The size is necessary
//              because any 0 value is ignored, but a socket should not
//              match if the comparison is based entirely on 0 values.
// PARAMETERS::
// + addr1 : UInt32 : The address of the first end of the socket
// + port1 : UInt16 : The port of the first end of the socket
// + addr2 : UInt32 : The address of the second end of the socket
// + port2 : UInt16 : The port of the second end of the socket
// + s : IPSocket* : The socket to compare it with
// RETURN    :: void
// **/
int CompareIPSocket(
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    IPSocket* s);

UInt16 ComputeIcmpStyleChecksum(
    UInt8* packet,
    UInt16 length);

// /**
// API       :: ComputeTcpStyleChecksum
// PURPOSE   :: This function will compute a TCP checksum.  It may be used
//              for TCP type checksum, including UDP.  It assumes all
//              parameters are passed in network byte order.  The packet
//              pointer should point to the beginning of the tcp header,
//              with the packet data following.  The checksum field of the
//              TCP header should be 0.
// PARAMETERS::
// + srcAddress : UInt32 : The source IP address
// + dstAddress : UInt32 : The destination IP address
// + protocol : UInt8 : The protocol (in the IP header)
// + tcpLength : UInt16 : The length of the TCP header + packet data
// + packet : UInt8* : Pointer to the beginning of the packet
// RETURN    :: UInt16 :Checksum value
// **/

UInt16 ComputeTcpStyleChecksum(
        UInt32 srcAddress,
        UInt32 dstAddress,
        UInt8 protocol,
        UInt16 tcpLength,
        UInt8 *packet);


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
// API       :: IncrementallyAdjustChecksum
// PURPOSE   :: This function will adjust an internet checksum if some part
//              of its packet data changes.  This can be used on the actual
//              packet data or on a virtual header.
// PARAMETERS::
// + sum : UInt16* : The checksum
// + oldData : UInt8* : The data that will be replaced
// + newData : UInt8* : The new data that will replace the old data
// + len : int : The length of the data that will be replaced
// + packetStart : UInt8* : The start of the packet.  NULL if it is part of
//                           the virtual header.  This parameter is
//                           necessary because the checksum covers 2 bytes
//                           of data and we need to know if the old data
//                           begins at an odd or even address relative to
//                           the start of the packet.
// RETURN    :: void
// **/
void IncrementallyAdjustChecksum(
    UInt16 *sum,
    UInt8 *oldData,
    UInt8 *newData,
    int len,
    UInt8 *packetStart);

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
// API       :: IPNECheckMulticastAndDoNAT
// PURPOSE   :: This function  checks if the destination is a multicast
//              address and initiates swapping of this destination addresses
// PARAMETERS::
// + node : Node * : Pointer to  Node data structure
// + iface : EXTERNAL_Interface * : Pointer to external interface
// + forwardData : void * : pointer to packet
// + forwardSize : int : size of the packet
// RETURN    :: void
// **/
void IPNECheckMulticastAndDoNAT(
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
// API       :: IPNE_ForwardFromNetworkLayer
// PURPOSE   :: This function will take a packet from the network layer and
//              inject it to the physical network.  Use in True-Emulation
//              mode.
// PARAMETERS::
// + node : Node* : The node that is forwarding the packet
// + interfaceIndex : int : The interface it was received on
// + msg : Message* : The packet
// RETURN    :: TRUE if the packet was injected, FALSE if not
// **/
BOOL IPNE_ForwardFromNetworkLayer(Node* node, int interfaceIndex, Message* msg);

// /**
// API       :: HandleIPStatisticsReceivePacket
// PURPOSE   :: This function will compute statistics upon receiving info
//              from the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + now : clocktype : The current time
// RETURN    :: void
// **/
void HandleIPStatisticsReceivePacket(
    EXTERNAL_Interface *iface,
    clocktype now);

// /**
// API       :: HandleIPStatisticsSendPacket
// PURPOSE   :: This function will compute statistics upon injecting info
//              back into the external source
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + receiveTime : clocktype : The time the packet was received.  This is
//                             the "now" value passed to
//                             HandleIPStatisticsReceive
// + now : clocktype : The current time
// RETURN    :: void
// **/
void HandleIPStatisticsSendPacket(
    EXTERNAL_Interface *iface,
    clocktype receiveTime,
    clocktype now);

// /**
// API       :: AddIPSocketPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given port.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocketPort(
    IPNEData *data,
    UInt16 port,
    IPNE_SocketFunction func);

// /**
// API       :: AddIPSocketAddressPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with the given
//              address and port.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + addr : UInt32 : The address
// + port : UInt16 : The port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocketAddressPort(
    IPNEData *data,
    UInt32 addr,
    UInt16 port,
    IPNE_SocketFunction func);

// /**
// API       :: AddIPSocketPort
// PURPOSE   :: This function will add information for a new socket.  This
//              will match any socket that has one end with addr1 and port1
//              and the other end with addr2 and port2.  Any address or port
//              value that is set to 0 will be ignored.
// PARAMETERS::
// + data : IPNEData* : The IP interface data structure.
// + addr1 : UInt32 : The first address
// + port1 : UInt16 : The first port
// + addr2 : UInt32 : The second address
// + port2 : UInt16 : The second port
// + func : SocketFunction : The function to call when receiving packets
//                           that match this socket
// RETURN    :: void
// **/
void AddIPSocket(
    IPNEData *data,
    UInt32 addr1,
    UInt16 port1,
    UInt32 addr2,
    UInt16 port2,
    IPNE_SocketFunction func);

//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: IPNE_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              IPNEData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void IPNE_Initialize(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: IPNE_InitializeNodes
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
void IPNE_InitializeNodes(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: IPNE_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void IPNE_Receive(EXTERNAL_Interface *iface);

// /**
// API       :: IPNE_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void IPNE_Forward(
    EXTERNAL_Interface *iface,
    Node *node,
    void *forwardData,
    int forwardSize);

// /**
// API       :: IPNE_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void IPNE_Finalize(EXTERNAL_Interface *iface);

#ifdef DERIUS
// /**
// API       :: IPNE_InitStats
// PURPOSE   :: Initialization for dynamic statistics
// PARAMETERS::
// + node : Node *: Node pointer
// + stats  : IPNE_StatsType : IPNE dynamic stat structure
// RETURN    :: void
// **/
static void IPNE_InitStats(Node* node, IPNE_StatsType *stats);

// /**
// API       :: IPNE_RunTimeStat
// PURPOSE   :: periodic report of dynamic stat
// PARAMETERS::
// + node : Node *: Node pointer
// RETURN    :: void
// **/
void IPNE_RunTimeStat(Node* node);

// /**
// API       :: AddRunTimeStat
// PURPOSE   :: add runtime stat
// PARAMETERS::
// + iface : EXTERNAL_Interface *: interface pointer
// + virtualNodeAddress : NodeAddress: virtual node address
// + id : unsigned char: identifier of packets
// RETURN    :: void
// **/
void AddRunTimeStat(EXTERNAL_Interface* iface, NodeAddress virtualNodeAddress, unsigned int id);
#endif

void StringToAddress(char* string, NodeAddress* address);

#endif /* _IP_NETWORK_EMULATOR_H_ */
