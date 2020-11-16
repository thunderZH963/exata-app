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

#ifndef _MDP_INTERFACE_H_
#define _MDP_INTERFACE_H_


class MDPPacketHandler
{
public:
    static BOOL ReformatIncomingPacket(unsigned char* packet, Int32 size);
    static BOOL ReformatOutgoingPacket(unsigned char* packet, Int32 size);
    static void CheckAndProcessOutgoingMdpPacket(Node* node,
                                        IpHeaderType* ipHeader,
                                        struct libnet_ipv4_hdr* ip,
                                        Message* msg,
                                        int ipHeaderLength);
private:

    /**
    // API       :: MDPSwapBytes
    // PURPOSE   :: Swap bytes for an MDP packet
    // PARAMETERS::
    // + mdpPacket : unsigned char * : The start of the  MDP packet
    // + size : Int32 : The size of the  MDP packet payload
    // + in : BOOL: TRUE if the packet is coming in to QualNet, FALSE if
    //                outgoing
    // RETURN    :: static BOOL : return TRUE is packet is MDP server packet
    // **/

    static BOOL MDPSwapBytes(unsigned char* mdpPacket, Int32 size, BOOL in);
};

#endif /* _MDP_INTERFACE_H_ */
