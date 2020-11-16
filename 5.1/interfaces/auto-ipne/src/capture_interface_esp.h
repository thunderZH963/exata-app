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
#ifndef AUTO_IPNE_CAPTURE_INTERFACE_ESP
#define AUTO_IPNE_CAPTURE_INTERFACE_ESP

// /**
// API       :: AutoIPNEHandleSniffedESPPacket
// PURPOSE   :: This function will handle an incoming ESP packet received
//              from outside Exata. Once the pcket is decrypted,this function
//              will be invoked from the ESP model to get the original packet
//              This function will not be invoked from the interface code
//              but instead will be called from the IPSEC model itself
//              once the packet has been decrypted.
// PARAMETERS::
// + node : Node* : The node structure
// + msg : Message* : Pointer to the msg structure
// + dat : char* : Pointer to the decrypted packet
// + ipHdr : IpHeaderType*: Ip header stucture
// + proto: The protocol depending on which the further functions will
//          be invoked
// RETURN    :: void
// **/
void AutoIPNEHandleSniffedESPPacket(Node*         node,
                                    Message*      msg,
                                    char*         dat,
                                    IpHeaderType* ipHdr,
                                    unsigned int  proto);

// /**
// API       :: AutoIPNEHandleSniffedTunnelPacket
// PURPOSE   :: This function will handle an incoming ESP packet received
//             from outside Exata. Once the pcket is decrypted, this function
//             will be invoked from the ESP model to get the original packet.
//             this function works for the decrypted tunneled packet.
// PARAMETERS::
// + node : Node* : The node structure
// + msg : Message* : Pointer to the msg
// + packet : UInt8* : The pointer to the sniffed packet
// RETURN    :: void
// **/
void AutoIPNEHandleSniffedTunnelPacket(Node*     node,
                                       Message*  msg,
                                       UInt8*    packet);


#endif

