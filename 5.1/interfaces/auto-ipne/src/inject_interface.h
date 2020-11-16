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
#ifndef AUTO_IPNE_INJECT_INTERFACE
#define AUTO_IPNE_INJECT_INTERFACE

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
// RETURN    :: void
// **/
void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime,
    int    deviceIndex);


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
void AutoIPNEInjectLinkPacket(
    EXTERNAL_Interface* iface,
    UInt8* dest,
    UInt8* source,
    UInt16 type,
    UInt8* packet,
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
void AutoIPNEInjectIpPacketAtLinkLayer(
    EXTERNAL_Interface* iface,
    NodeAddress myAddress,
    UInt8 tos,
    UInt16 id,
    UInt16 offset,
    UInt8 ttl,
    UInt8 protocol,
    UInt32 srcAddr,
    UInt32 destAddr,
    UInt8* packet,
    int packetSize,
    clocktype receiveTime,
    char *ipOptions,
    int ipHeaderLength);

// /**
// API       :: InjectIpPacketAtLinkLayer
// PURPOSE   :: This function will insert an IPv6 packet directly at the link
//              layer destined for the next hop of the packet i.e. the  external
//              source.  This function will create the outgoing IPv6 packet
//              based its arguments. Only the data of the outgoing packet
//              should be passed in the "packet" parameter.  All arguments
//              should be in host byte order except for packet, which will
//              be forwarded as passed. The function creates an ethernet header
//              after looking up the ethernet destination address of the next
//              hop and the corresponding source ethernet address. This
//              function then writes the packet directly at the link layer
//              avoiding the use of the nodes kernel ipv6 routing tables.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + myAddress : Address : The address of the node that is forwarding
//                             the IPv6 packet.
// + tc : UInt8 : The Traffic class
// + flow_label : UInt16 : Flow label
// + payload_length : UInt16 : Payload length
// + protocol : UInt8 : The protocol field
// + hop_lim : UInt8 : Hop limit
// + srcAddr : struct libnet_in6_addr : The source addr field
// + destAddr : struct libnet_in6_addr : The dest addr field
// + packet : UInt8* : Pointer to the packet.  ONLY the data portion
//                     of the packet.
// + receiveTime : clocktype : The time the packet was received
// RETURN    :: void
// **/
void AutoIPNEInjectIpPacketAtLinkLayer(
    EXTERNAL_Interface* iface,
    Address myAddress,
    UInt8 tc,
    UInt32 flow_label,
    UInt16 payload_length,
    UInt8 protocol,
    UInt8 hop_lim,
    struct libnet_in6_addr srcAddr,
    struct libnet_in6_addr destAddr,
    UInt8* packet,
    clocktype receiveTime);

void AutoIPNEInitializeInjectInterface(AutoIPNEData *data);

/*!
 \brief Provide the complement set of interface indices available to the 
 emulation environment.

 \param ext a pointer to the local auto_ipne external interface data structure
 \param exclude the index of the network interface to exclude from the set
 \param intfs a reference to a list of interfaces to hold the result of the complement operation
 */
void AutoIPNEInterfaceSetComplement(EXTERNAL_Interface* ext,
                                    int exclude, std::list<int>& intf);

/*!
 \brief Send a raw packet to a list of network interfaces (by interface indices)
 \param ext a pointer to the local auto_ipne external interface data structure
 \param receivers a reference to a list of receiver interface indices
 \param buf a pointer to a packet to be sent on the interface
 \param buf_size the size of the packet in bytes
 */
void AutoIPNESendRaw(EXTERNAL_Interface* ext,
                     const std::list<int>& receivers,
                     UInt8* buf, int buf_size);
/*!
 \param iface a pointer to the local external interface data structure
 \param ifdev the integer identifier of the target interface
 \param buf a pointer to the buffer to be injected (must be an ethernet frame)
 \param buf_size the size of the buffer in bytes
*/
void AutoIPNEForceInject(EXTERNAL_Interface* iface,
                         int ifdev,
                         UInt8* buf,
                         int buf_size);

/*!
 \brief Constant mapping to an unknown or invalid device identifier
*/
static const int AutoIPNEInvalidDeviceIdentifier = -1;

/*!
 \brief Map a device name to an integer identifier

 \param ext a pointer to the local external interface data structure
 \param devstr a string representation of the target device (e.g. "eth0")

 \returns the target interface identifier or AutoIPNEInvalidDeviceIdentifier if none is found.
*/
int AutoIPNEDeviceIndex(EXTERNAL_Interface* ext, 
                        const std::string& devstr);

#endif

