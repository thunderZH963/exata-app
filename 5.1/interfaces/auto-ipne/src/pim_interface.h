// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
// //                          600 Corporate Pointe
// //                          Suite 1200
// //                          Culver City, CA 90230
// //                          info@scalable-networks.com
// //
// // This source code is licensed, not sold, and is subject to a written
// // license agreement.  Among other things, no portion of this source
// // code may be copied, transmitted, disclosed, displayed, distributed,
// // translated, used as the basis for a derivative work, or used, in
// // whole or in part, for any program or purpose other than its intended
// // use in compliance with the license agreement as part of the EXata
// // software.  This source code and certain of the algorithms contained
// // within it are confidential trade secrets of Scalable Network
// // Technologies, Inc. and may not be used as the basis for any other
// // software, hardware, product or service.

#ifndef _PIM_INTERFACE_H_
#define _PIM_INTERFACE_H_

//#include "multicast_pim.h"


class PIMPacketHandler
{
public:
    static void ReformatIncomingPacket(unsigned char *packet, int pktLen);
    static void ReformatOutgoingPacket(unsigned char *packet, int pktLen);

/**
// API       :: PIMSwapBytes
// PURPOSE   :: Swap header bytes for an PIM packet
// PARAMETERS::
// + pimPacket : unsigned char * : The start of the  PIM packet
// + in : BOOL: TRUE if the packet is coming in to EXata, FALSE if
//                outgoing
// RETURN    :: static void
// **/

//    static void PIMSwapBytes(unsigned char *pimPacket, int pktLen, BOOL in);

/**
// API       :: PIMSwapBytes
// PURPOSE   :: Swap header bytes for the HELLO message
// PARAMETERS::
// + pimPacket : unsigned char * : The start of the  PIM packet
// + in : BOOL: TRUE if the packet is coming in to EXata, FALSE if
//                outgoing
// RETURN    :: static void
// **/

//    static void PIMSwapHello(unsigned char *pimPacket, BOOL in);

// /**
// API       :: ComputePIMChecksum
// PURPOSE   :: Computes the checksum for an entire PIM packet
// PARAMETERS::
// + packet : UInt8* : The packet to compute the checksum for.
// + packetLength : int : The length of the packet
// RETURN :: UInt16 : The checksum
// **/

    static UInt16 ComputePIMChecksum( UInt8* packet, int packetLength);


};

#endif
