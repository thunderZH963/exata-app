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

#ifndef _OLSR_INTERFACE_H_
#define _OLSR_INTERFACE_H_

#include "routing_olsr-inria.h"

//#include "routing_olsr-inria.h"

class OLSRPacketHandler 
{
public:
    static void ReformatIncomingPacket(unsigned char *packet);
    static void ReformatOutgoingPacket(unsigned char *packet);

private:
    
    /**
    // API       :: OLSRSwapBytes
    // PURPOSE   :: Swap header bytes for an OLSR packet
    // PARAMETERS::
    // + olsrPacket : unsigned char * : The start of the  OLSR packet
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //                outgoing
    // RETURN    :: static void
    // **/

    static void OLSRSwapBytes(unsigned char *olsrPacket, BOOL in);



    /**
    // API       :: OLSRSwapHello
    // PURPOSE   :: Swap header bytes for the hello message
    // PARAMETERS::
    // + m : olsrmsg * : The start of the  hello message
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/

    static void OLSRSwapHello(olsrmsg *m, BOOL in);



    /**
    // API       :: OLSRSwapTC
    // PURPOSE   :: Swap header bytes for the TC message
    // PARAMETERS::
    // + m : olsrmsg * : The start of the  TC message
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/
    static void OLSRSwapTC(olsrmsg *m, BOOL in);



    /**
    // API       :: OLSRSwapMid
    // PURPOSE   :: Swap header bytes for the MID message
    // PARAMETERS::
    // + m : olsrmsg * : The start of the  MID message
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/

    static void OLSRSwapMid(olsrmsg *m, BOOL in);


    /**
    // API       :: OLSRSwapHna
    // PURPOSE   :: Swap header bytes for the HNA message
    // PARAMETERS::
    // + m : olsrmsg * : The start of the  HNA message
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/

    static void OLSRSwapHna(olsrmsg *m, BOOL in);

    /**
    // API       :: OLSRSwapMsgHeader
    // PURPOSE   :: Swap header bytes for the message header
    // PARAMETERS::
    // + m : olsrmsg * : The start of the  message header
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/
    static void OLSRSwapMsgHeader(olsrmsg *m, BOOL in);


    /**
    // API       :: OLSRSwapPacketHeader
    // PURPOSE   :: Swap header bytes for the packet header
    // PARAMETERS::
    // + olsr : olsrpacket * : The start of the  packet header
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //               outgoing
    // RETURN    :: static void
    // **/

    static void OLSRSwapPacketHeader(olsrpacket *olsr, BOOL in);
};

#if 0
static void InitializeOlsrInterface(EXTERNAL_Interface *iface);


/**
// API       :: OLSRSwapBytes
// PURPOSE   :: Swap header bytes for an OLSR packet
// PARAMETERS::
// + olsrPacket : unsigned char * : The start of the  OLSR packet
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//                outgoing
// RETURN    :: static void
// **/

static void OLSRSwapBytes(unsigned char *olsrPacket, BOOL in);



/**
// API       :: OLSRSwapHello
// PURPOSE   :: Swap header bytes for the hello message
// PARAMETERS::
// + m : olsrmsg * : The start of the  hello message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/

static void OLSRSwapHello(olsrmsg *m, BOOL in);



 /**
// API       :: OLSRSwapTC
// PURPOSE   :: Swap header bytes for the TC message
// PARAMETERS::
// + m : olsrmsg * : The start of the  TC message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/
static void OLSRSwapTC(olsrmsg *m, BOOL in);



 /**
// API       :: OLSRSwapMid
// PURPOSE   :: Swap header bytes for the MID message
// PARAMETERS::
// + m : olsrmsg * : The start of the  MID message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/

static void OLSRSwapMid(olsrmsg *m, BOOL in);


 /**
// API       :: OLSRSwapHna
// PURPOSE   :: Swap header bytes for the HNA message
// PARAMETERS::
// + m : olsrmsg * : The start of the  HNA message
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/

static void OLSRSwapHna(olsrmsg *m, BOOL in);

 /**
// API       :: OLSRSwapMsgHeader
// PURPOSE   :: Swap header bytes for the message header
// PARAMETERS::
// + m : olsrmsg * : The start of the  message header
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/
static void OLSRSwapMsgHeader(olsrmsg *m, BOOL in);


 /**
// API       :: OLSRSwapPacketHeader
// PURPOSE   :: Swap header bytes for the packet header
// PARAMETERS::
// + olsr : olsrpacket * : The start of the  packet header
// + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
//               outgoing
// RETURN    :: static void
// **/

static void OLSRSwapPacketHeader(olsrpacket *olsr, BOOL in);


 /**
// API       :: HandleOLSR
// PURPOSE   :: Add an OLSR packet to QualNet.  Called by the IP
//              Network Emulator when an  OLSR  packet is sniffed
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The  IPNE interface pointer
// + packet : unsigned char* : The start of the packet, including ethernet
//            and network headers
// + data: unsigned char* : Pointer to OLSR data
// + size : int : The size of the packet in bytes
// + sum : unsigned short * : pointer to checksum
// + func : QualnetPacketInjectFunction ** : Pointer to packet injection
//                                          function
// RETURN    :: static void
// **/

// HandleOLSR -
//
// iface - The interface the packet sniffer is running on
// packet - The start of the packet, including ethernet and network headers
// size - The size of the packet in bytes
static void HandleOLSR(
    EXTERNAL_Interface* iface,
    unsigned char* packet,
    unsigned char* data,
    int size,
    unsigned short* sum,
    AutoIPNE_EmulatePacketFunction **func);

#endif
#endif /* _OLSR_INTERFACE_H_ */
