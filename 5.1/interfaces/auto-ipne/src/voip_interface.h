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

#ifndef _VOIP_INTERFACE_H_
#define _VOIP_INTERFACE_H_
#if 0 


// /**
// API       :: InitializeVoipInterface
// PURPOSE   :: Initialize AutoIPNE to work with VOIP
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// RETURN    :: None
// **/
void InitializeVoipInterface(EXTERNAL_Interface* iface);

// /**
// API       :: HandleH225
// PURPOSE   :: Handle an incoming H.225 packet.  This is called by the
//              AutoIPNE socket interface for packets on port 1720.  The socket
//              listener is added by InitializeVoipInterface.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// + packet : UInt8* : Pointer to beginning of the IP packet
// + data : UInt8* : Pointer to beginning of the H.225 header
// + size : Int32 : The size of the packet in bytes
// + sum : UInt16* : Pointer to the IP checksum
// + func : AutoIPNE_EmulatePacketFunction** : Function to use for packet
//          injection.  Not changed.
// RETURN    :: None
// **/
void HandleH225(
    EXTERNAL_Interface* iface,
    UInt8* packet,
    UInt8* data,
    Int32 size,
    UInt16* sum,
    AutoIPNE_EmulatePacketFunction** func);

// /**
// API       :: HandleH245
// PURPOSE   :: Handle an incoming H.245 packet.  This is called by the
//              AutoIPNE socket interface.  The socket listener is added
//              according to H.225.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// + packet : UInt8* : Pointer to beginning of the IP packet
// + data : UInt8* : Pointer to beginning of the H.225 header
// + size : Int32 : The size of the packet in bytes
// + sum : UInt16* : Pointer to the IP checksum
// + func : AutoIPNE_EmulatePacketFunction** : Function to use for packet
//          injection.  Not changed.
// RETURN    :: None
// **/
void HandleH245(
    EXTERNAL_Interface *iface,
    UInt8* packet,
    UInt8* data,
    Int32 size,
    UInt16* sum,
    AutoIPNE_EmulatePacketFunction* *func);

// /**
// API       :: HandleH323
// PURPOSE   :: Handle an incoming H.323 packet.  This is called by the
//              AutoIPNE socket interface.  The socket listener is added
//              according to H.245.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// + packet : UInt8* : Pointer to beginning of the IP packet
// + data : UInt8* : Pointer to beginning of the H.225 header
// + size : Int32 : The size of the packet in bytes
// + sum : UInt16* : Pointer to the IP checksum
// + func : AutoIPNE_EmulatePacketFunction** : Function to use for packet
//          injection.  Not changed.
// RETURN    :: None
// **/
void HandleH323(
    EXTERNAL_Interface *iface,
    UInt8* packet,
    UInt8* data,
    Int32 size,
    UInt16* sum,
    AutoIPNE_EmulatePacketFunction** func);

#endif 
#endif /* _VOIP_INTERFACE_H_ */
