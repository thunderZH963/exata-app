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

#ifndef _AUTO_IPNE_IPSEC_INTERFACE_H_
#define _AUTO_IPNE_IPSEC_INTERFACE_H_

class ESPPacketHandler
{
public:

    //**
    // FUNCTION   :: ReformatIncomingPacket()
    // LAYER      :: Network
    // PURPOSE    :: Reformat incoming ESP packet.
    // PARAMETERS ::
    // + packet   :: unsigned char* : Incoming ESP packet to be formated.
    // RETURN     :: void : NULL
    //**
    static void ReformatIncomingPacket(unsigned char* packet);

    //**
    // FUNCTION   :: ReformatOutgoingPacket()
    // LAYER      :: Network
    // PURPOSE    :: Reformat outgoing ESP packet.
    // PARAMETERS ::
    // + packet   :: unsigned char* : Outgoing ESP packet to be formated.
    // RETURN     :: void : NULL
    //**
    static void ReformatOutgoingPacket(unsigned char* packet);
};

class AHPacketHandler
{
public:
    ///**
    // FUNCTION   :: ReformatIncomingPacket()
    // LAYER      :: Network
    // PURPOSE    :: Reformat incoming AH packet.
    // PARAMETERS ::
    // + packet   :: unsigned char* : Incoming AH packet to be formated.
    // RETURN     :: void : NULL
    //**
    static void ReformatIncomingPacket(unsigned char* packet);

    //**
    // FUNCTION   :: ReformatOutgoingPacket()
    // LAYER      :: Network
    // PURPOSE    :: Reformat outgoing AH packet.
    // PARAMETERS ::
    // + packet   :: unsigned char* : Outgoing AH packet to be formated.
    // RETURN     :: void : NULL
    //**
    static void ReformatOutgoingPacket(unsigned char* packet);
};

#endif /* _IPSEC_INTERFACE_H_ */
