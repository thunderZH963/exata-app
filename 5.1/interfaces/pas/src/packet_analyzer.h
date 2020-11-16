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
#include <string.h>

//supporting MAC protocol
#define    PACKET_SNIFFER_ETHERNET     0x80    
#define    PACKET_SNIFFER_DOT11        0x40

#define PACKET_SNIFFER_ENABLE_APP        0x80
#define PACKET_SNIFFER_ENABLE_UDP        0x40
#define PACKET_SNIFFER_ENABLE_TCP        0x20
#define PACKET_SNIFFER_ENABLE_ROUTING     0x10
#define PACKET_SNIFFER_ENABLE_MAC        0x08

// /**
// CONSTANT    :: ETYPE_IPV6 : 0x86dd
// DESCRIPTION :: Ether type for Ipv6 packets
// **/
#ifndef ETYPE_IPV6
#define ETYPE_IPV6 0x86dd
#endif

enum {
    EXTERNAL_MESSAGE_PAS_InitLibnet,
    EXTERNAL_MESSAGE_PAS_EnablePSI,
    EXTERNAL_MESSAGE_PAS_EnableDot11,
    EXTERNAL_MESSAGE_PAS_EnableApp,
    EXTERNAL_MESSAGE_PAS_EnableUdp,
    EXTERNAL_MESSAGE_PAS_EnableTcp,
    EXTERNAL_MESSAGE_PAS_EnableRouting,
    EXTERNAL_MESSAGE_PAS_EnableMac
};

struct PASData
{
    BOOL     isPAS;     // is PAS enabled
    int     pasId;
    BOOL      isDot11;  // network layer: 0x80 dot11: 0x40
    unsigned long pasCnt;
    char    pasFilterBit;
    BOOL    deviceNotFound;
    BOOL    isRealtime;
    clocktype    realTimeStartAt;
};

typedef unsigned short int u_int16_t;
// /**
// STRUCT      :: Ethereal_header
// DESCRIPTION :: Elements of 802.3 frame header.
// **/
typedef struct Ethereal_Header
{
    // sourceAddr & destAddr : 6 byte Ethernet address each.
    Mac802Address destAddr;
    Mac802Address sourceAddr;

    // Length of data / type field.
    unsigned short lengthOfData;

    // Frame header optionally carry VLAN tag information.
    // In this case, lengthOfData field indicates the presence of
    // four bytes VLAN tag. Original length of data followed after
    // this tagged field.

} MacEtherealHeader;

/*
 * A value from the header.
 *
 * It appears from looking at the linux-wlan-ng and Prism II HostAP
 * drivers, and various patches to the orinoco_cs drivers to add
 * Prism headers, that:
 *
 *      the "did" identifies what the value is (i.e., what it's the value
 *      of);
 *
 *      "status" is 0 if the value is present or 1 if it's absent;
 *
 *      "len" is the length of the value (always 4, in that code);
 *
 *      "data" is the value of the data (or 0 if not present).
 *
 * Note: all of those values are in the *host* byte order of the machine
 * on which the capture was written.
 */


struct val_80211 {
    unsigned int did;
    unsigned short status, len;
    unsigned int data;
};

/*
 * Header attached during Prism monitor mode.
 *
 * At least according to one paper I've seen, the Prism 2.5 chip set
 * provides:
 *
 *      RSSI (receive signal strength indication) is "the total power
 *      received by the radio hardware while receiving the frame,
 *      including signal, interfereence, and background noise";
 *
 *      "silence value" is "the total power observed just before the
 *      start of the frame".
 *
 * None of the drivers I looked at supply the "rssi" or "sq" value,
 * but they do supply "signal" and "noise" values, along with a "rate"
 * value that's 1/5 of the raw value from what is presumably a raw
 * HFA384x frame descriptor, with the comment "set to 802.11 units",
 * which presumably means the units are 500 Kb/s.
 *
 * I infer from the current NetBSD "wi" driver that "signal" and "noise"
 * are adjusted dBm values, with the dBm value having 100 added to it
 * for the Prism II cards (although the NetBSD code has an XXX comment
 * for the #define for WI_PRISM_DBM_OFFSET) and 149 (with no XXX comment)
 * for the Orinoco cards.
 */

struct prism_hdr {
    unsigned int msgcode, msglen;
    char devname[16];
    struct val_80211 hosttime, mactime, channel, rssi, sq, signal,
        noise, rate, istx, frmlen;
};

void
PAS_CreateFrames(
    Node * node,
    Message *msg) ;

void HeaderSwap(unsigned char * frameToSend);
void PIM_HeaderSwap(unsigned char * frameToSend, BOOL incoming,BOOL isNullReg);

//void SwapUdpHeader(TransportUdpHeader* header);
void SwapUdpHeader(unsigned char * header);

void SwapRtpHeader(unsigned char* rtpHeader);
void SwapRtcpHeader(unsigned char* rtcpHeader, UInt16 packetSize);

UInt16 PAS_ICMPv4Checksum( UInt8* packet, UInt16 length);

// /**
// API       :: PAS_IPv4
// PURPOSE   :: create IPv4 packet and write to exata interface
// PARAMETERS::
// + node   : node pointer
// + ip     : pointer to IP packet
// RETURN    :: void
// **/
void PAS_IPv4(Node* node, IpHeaderType * ipHeader, NodeAddress previousHopAddress, int packetSize = 0);

// /**
// API       :: PAS_IPv6
// PURPOSE   :: Create IPv6 packet and write to exata interface
// PARAMETERS::
// + node     : Node * : Node pointer
// + ip     : UInt8 * : Pointer to IPv6 packet
// + lastHopAddr : MacHWAddress * :Last hop MAC address
// + interfaceIndex : Int32 : Incoming/outgoing interface index
// RETURN    :: void
// **/
void PAS_IPv6(
    Node* node,
    UInt8* ip,
    MacHWAddress* lastHopAddr = NULL,
    Int32 interfaceIndex = 0);

// /**
// API       :: PAS_InjectLinkPacket
// PURPOSE   :: Injects packet at link layer
// PARAMETERS::
// + dest     : UInt8 * : Destination MAC address
// + source     : UInt8 * : Source MAC address
// + type : UInt16 : Packet type (v4/v6)
// + packet : UInt8 * : Pointer to the  packet
// + packetSize : Int32 : Size of packet
// + libnetPAS : libnet_context * : libnet context
// RETURN    :: void
// **/
void PAS_InjectLinkPacket(
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    Int32 packetSize,
    struct libnet_context* libnetPAS);

void InjectLinkPacketForCapturing(
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize);
void LibnetInitForDiagnosis();
void PAS_ComputeIcmpv6Checksum(
    in6_addr *src,
       in6_addr *dst,
    struct libnet_icmpv6_hdr *icmp,
     int icmpLen);

void ProcessTcpForDiagnosis(
    struct libnet_ipv6_hdr* ip,
    UInt8* tcpHeader,
    UInt16* checksum);

void ProcessUdpForDiagnosis(
    UInt8* udpHeader,
     struct libnet_ipv6_hdr* ip6);




void InjectIpv6PacketAtLinkLayerForDiagnosis(  
    unsigned char tc,
    unsigned long fl,
    unsigned short len,
    unsigned char nh,
    unsigned char hl,
    Address srcAddr,
    Address destAddr,
    unsigned char *packet,
    int packetSize);

/** 
 * FUNCTION     :: ENEV_Verification 
 * PURPOSE      :: ckeck if exata interface is available
 * PARAMETERS   :: 
**/
BOOL ENETV_Verification(BOOL isNetLayer, char * deviceName);


int  PAS_CreateRawSocket(int protocol);

int PAS_RawBindToInterface( int protocol);
int PAS_SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len);

UInt16 PAS_ComputeTcpStyleChecksum(
    UInt32 srcAddress,
    UInt32 dstAddress,
    UInt8 protocol,
    UInt16 tcpLength,
    UInt8 *packet);


/*  
 * FUNCTION     PAS_Initialize 
 * PURPOSE      Function used to initialize PAS
 * PARAMETERS:     partitionData : pointer of partition
 */
//void PAS_Initialize(PartitionData* partitionData);
void PAS_Initialize( 
    EXTERNAL_Interface* iface,
    NodeInput* nodeInput);


/*  
 * FUNCTION     PAS_Finalize 
 * PURPOSE      Function used to finalize PAS
 */
void PAS_Finalize(PartitionData* partitionData);

int InChecksum(u_int16_t *addr, int len);
void CalculateChecksum(int protocol, UInt8 *buf, int len);

BOOL PAS_LayerCheck(Node * node, int interfaceIndex, char fromWhichLayer);


/*  
 * FUNCTION     PAS_IsProcessRunnging 
 * PURPOSE      Function used to check if a process is 
 *        running on windows
 * PARAMETERS:  pName: process name
 */
bool PAS_IsProcessRunning(std::string pName);

void PAS_Receive(EXTERNAL_Interface *iface);

void PAS_Forward( EXTERNAL_Interface *iface, Node *node, void *forwardData, int forwardSize);
void PAS_InitializeNodes( EXTERNAL_Interface *iface, NodeInput *nodeInput);

void PAS_HandleExternalMessage(
    Node *node,
    Message *msg);
