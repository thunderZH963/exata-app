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

#ifndef _IGMPv3_INTERFACE_H_
#define _IGMPv3_INTERFACE_H_
#include "multicast_igmp.h"

#define IGMPV2_HEADER_SIZE 8

class IGMPv3PacketHandler
{
public:

    //-----------------------------------------------------------------------
    // FUNCTION     : ReformatIncomingPacket()
    // PURPOSE      : Function to convert packet from network order to host
    //              : order
    // PARAMETERS   :
    // + packet     : unsigned char* : pointer to packet
    // RETURN VALUE : None
    // ASSUMPTION   : None
    //-----------------------------------------------------------------------
    static void ReformatIncomingPacket(unsigned char* packet);


    //-----------------------------------------------------------------------
    // FUNCTION     : ReformatOutgoingPacket()
    // PURPOSE      : Function to convert packet from host order to network
    //              : order
    // PARAMETERS   :
    // + packet     : unsigned char* : pointer to packet
    // RETURN VALUE : None
    // ASSUMPTION   : None
    //-----------------------------------------------------------------------
    static void ReformatOutgoingPacket(unsigned char* packet);


    //-----------------------------------------------------------------------
    // FUNCTION     : IgmpSwapBytes()
    // PURPOSE      : Function to swap bytes for IGMP packets
    // PARAMETERS   :
    // + packet     : unsigned char* : pointer to packet 
    // + in         : BOOL           : TRUE if the packet is coming in to 
    //                               : QualNet,FALSE if outgoing
    // RETURN VALUE : None
    // ASSUMPTION   : None
    //-----------------------------------------------------------------------
    static void IgmpSwapBytes(unsigned char* packet,
                              BOOL in);
};
#endif
