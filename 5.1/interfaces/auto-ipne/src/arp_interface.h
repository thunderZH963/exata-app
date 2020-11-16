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

#ifndef _ARP_INTERFACE_H_
#define _ARP_INTERFACE_H_

// /**
// class      :: AutoIPNE_ArpPacket
// DESCRIPTION :: An ARP packet
// **/

class AutoIPNE_ArpPacketClass
{
    public:
    AutoIPNE_ArpPacketClass(){};
    ~AutoIPNE_ArpPacketClass(){};

    Int16 hardwareType;
    Int16 protocolType;
    UInt8 hardwareSize;
    UInt8 protocolSize;
    Int16 opcode;
    UInt8 senderHardwareAddress[6];
    UInt8 senderProtocolAddress[4];
    UInt8 targetHardwareAddress[6];
    UInt8 targetProtocolAddress[4];

    void unpack(UInt8 * arp);
    void pack(UInt8 * buffer, UInt8 * virtualMac);

};

// /**
// API       :: AutoIPNE_ProcessArp
// PURPOSE   :: Process a sniffed arp packet
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The AutoIPNE interface
// + arp : unsigned char* : Pointer to the beginning of the arp packet
// RETURN    :: bool
// **/
bool AutoIPNE_ProcessArp(
    EXTERNAL_Interface *iface,
    UInt8* arp,
    int deviceIndex);

#endif /* _ARP_INTERFACE_H_ */
