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

#ifndef _AUTO_IPNE_OSPF_INTERFACE_H_
#define _AUTO_IPNE_OSPF_INTERFACE_H_

#include "routing_ospfv2.h"

// /**
// DEFINE      :: LSA_CHECKSUM_OFFSET
// DESCRIPTION :: Offset into link state header for checksum
// **/
#define LSA_CHECKSUM_OFFSET 15

// /**
// DEFINE      :: LSA_CHECKSUM_MODX
// DESCRIPTION :: Breaks checksum computation into chunks
// **/
#define LSA_CHECKSUM_MODX 4102

class OSPFPacketHandler
{
public:
    static void ReformatIncomingPacket(unsigned char *packet);
    static void ReformatOutgoingPacket(unsigned char *packet);

    // /**
    // API       :: InitializeOspfInterface
    // PURPOSE   :: Initialize OSPF interface
    // PARAMETERS::
    // + iface : EXTERNAL_Interface* : The IPNE interface
    // **/
    static void InitializeOspfInterface(EXTERNAL_Interface* iface);


private:


    // /**
    // API       :: OspfSwapBytes
    // PURPOSE   :: Swap bytes from host to network order and vice versa
    // PARAMETERS::
    // + ospfHeader : UInt8* : Pointer to the OSPF header
    // + in : BOOL : TRUE if the packet is entering QualNet, FALSE it if it is
    //               leaving QualNet.
    // **/
    static void OspfSwapBytes(UInt8* ospfHeader, BOOL in);

    // /**
    // API       :: CalculateLinkStateChecksum
    // PURPOSE   :: Compute the checksum of a link state header and packet
    //              contents.  Returns the checksum in HOST byte order.
    // PARAMETERS::
    // + node : Node* : Node computing checksum
    // + lsh : Ospfv2LinkStateHeader* : Pointer to the link state header.  Data
    //       portion should follow immediately.  The size of the header and data
    //       portion should match the lsh->length field exactly.
    // RETURN :: UInt16 : The checksum
    // **/
    static UInt16 CalculateLinkStateChecksum(
            Node* node,
            Ospfv2LinkStateHeader* lsh);

    // /**
    // API       :: PreProcessIpPacketOspf
    // PURPOSE   :: Process an OSPF packet that is about to be added to QualNet.
    //              Called by the IP Network Emulator when an OSPF packet is
    //              sniffed.
    // PARAMETERS::
    // + iface : EXTERNAL_Interface* : The IPNE interface
    // + packet : UInt8* : The start of the packet, including ethernet and
    //                      network headers
    // **/
    static void PreProcessIpPacketOspf(
            EXTERNAL_Interface* iface,
            UInt8* packet);

    // /**
    // API       :: ProcessOutgoingIpPacketOspf
    // PURPOSE   :: Process an OSPF packet that is about to be sent to the
    //              physical network.
    // PARAMETERS::
    // + iface : EXTERNAL_Interface* : The IPNE interface
    // + myAddress : NodeAddress : The address of the node that is sending the
    //                             packet
    // + packet : UInt8* : The start of the OSPF header
    // + inject : BOOL* : Set to TRUE if the packet should be sent to the
    //                    physical network, FALSE if it should not
    // **/
    static void ProcessOutgoingIpPacketOspf(
            EXTERNAL_Interface* iface,
            NodeAddress myAddress,
            UInt8* packet,
            BOOL* inject);

    // Not supported
    static void IgmpSwapBytes(
            UInt8* igmpHeader,
            BOOL in);

    // Not supported
    static void HandleIgmpInject(
            EXTERNAL_Interface* iface,
            UInt8* packet,
            int size);


    static UInt16 ComputeOspfChecksum(
            UInt8* packet,
            int packetLength);


    static void OspfSwapHello(Ospfv2CommonHeader* ospfCommon);


    static void OspfSwapDatabaseDescription(
            Ospfv2CommonHeader* ospfCommon,
            BOOL in);

    // /**     
    // API       :: OspfSwapRospfDbdg                                                
    // PURPOSE   :: Swap bytes for the DB digest packet                
    // PARAMETERS::                                                    
    // + ospfCommon : Ospfv2CommonHeader* : The start of the common header     
    // + in : BOOL : TRUE if the packet is coming in to QualNet, FALSE if outgoing     
    static void OspfSwapRospfDbdg(Ospfv2CommonHeader* ospfCommon, BOOL in);                                                       

    static void OspfSwapLinkStateRequestBytes(Ospfv2CommonHeader* ospfCommon);


    static Ospfv2LinkStateHeader* OspfSwapLinkStateBytes(
            Ospfv2LinkStateHeader* lsh,
            BOOL in,
            BOOL computeChecksum);


    static void OspfSwapLinkStateUpdateBytes(
            Ospfv2CommonHeader* ospfCommon,
            BOOL in);

    static void OspfSwapLinkStateAckBytes(
            Ospfv2CommonHeader* ospfCommon,
            BOOL in);





};

#endif /* _OSPF_INTERFACE_H_ */
