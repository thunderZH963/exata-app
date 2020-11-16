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

#include <stdio.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_socket.h"
#include "auto-ipnetworkemulator.h"

#include "network_ip.h"

#include "igmpv3_interface.h"
#include "multicast_igmp.h"


//---------------------------------------------------------------------------
// FUNCTION     : ReformatIncomingPacket()
// PURPOSE      : Function to convert packet from network order to host order
// PARAMETERS   :
// + packet     : unsigned char* : pointer to packet 
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IGMPv3PacketHandler::ReformatIncomingPacket(unsigned char* packet)
{
    IgmpSwapBytes(packet, TRUE);
}

//---------------------------------------------------------------------------
// FUNCTION     : ReformatOutgoingPacket()
// PURPOSE      : Function to convert packet from host order to network order
// PARAMETERS   :
// + packet     : unsigned char* : pointer to packet 
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------
void IGMPv3PacketHandler::ReformatOutgoingPacket(unsigned char *packet)
{
    IgmpSwapBytes(packet, FALSE);
}

//---------------------------------------------------------------------------
// FUNCTION     : IgmpSwapBytes()
// PURPOSE      : Function to swap bytes for IGMP packets
// PARAMETERS   :
// + packet     : unsigned char* : pointer to packet 
// + in         : BOOL           : TRUE if the packet is coming in to QualNet,
//                               : FALSE if outgoing
// RETURN VALUE : None
// ASSUMPTION   : None
//---------------------------------------------------------------------------

void IGMPv3PacketHandler::IgmpSwapBytes(unsigned char* packet,
                                        BOOL in)
{
    u_int8_t* igmp_type;
    igmp_type = (u_int8_t*)packet;
    unsigned char* data_ptr = packet;
    switch (*igmp_type)
    {
        case IGMP_QUERY_MSG:
        {
            UInt16* checksum;
            NodeAddress* groupAddress;
            UInt16* numSources;
            UInt16 numSrc,tempNumSrc;
            int itr;
            NodeAddress* srcAddress;

            // ver_type size:1 byte no need to swap move data_ptr
            data_ptr += sizeof(UInt8);

            // maxRepsonseCode size 1 byte no need to swap , move data_ptr
            data_ptr += sizeof(UInt8);

            // checksum: size 2 bytes, for incoming packet ignore it, 
            // for outgoing packet zero out checksum.Move data_ptr 2 bytes
            if (!in)
            {
                checksum = (UInt16*)data_ptr;
                *checksum = 0;
            }
            data_ptr += sizeof(UInt16);

            // groupAddress ,swap bytes and move data_ptr
            groupAddress = (NodeAddress*)data_ptr;
            data_ptr += sizeof(NodeAddress);
            EXTERNAL_ntoh(groupAddress,
                          sizeof(NodeAddress));

            // query_qrv_sFlag size 1 byte, no need to swap move data_ptr
            data_ptr += sizeof(UInt8);

            // qqic size 1 byte, no need to swap move data_ptr
            data_ptr += sizeof(UInt8);

            // numSources, swap bytes and move data_ptr
            numSources = (UInt16*)data_ptr;
            tempNumSrc = *numSources;
            EXTERNAL_ntoh(numSources,
                          sizeof(*numSources));
            data_ptr += sizeof(*numSources);
            if (!in)
            {
                numSrc = tempNumSrc;
            }
            else
            {
                numSrc = *numSources;
            }

            // swap srcAddress and move data_ptr
            for (itr = 0; itr < numSrc; itr++)
            {
                srcAddress = (NodeAddress*)data_ptr;
                EXTERNAL_ntoh(srcAddress,
                              sizeof(NodeAddress));
                data_ptr += sizeof(NodeAddress);
            }
            break;
        }

        case IGMP_V3_MEMBERSHIP_REPORT_MSG:
        {
            UInt16* checksum;
            UInt16* resv;
            UInt16* numGrpRecords;
            UInt16* numSources;
            Int16 i;
            Int16 itr;
            NodeAddress* srcAddress;
            NodeAddress* groupAddress;
            UInt16 numSrc,tempNumSrc;
            UInt16 numGrpRcds, tempNumGrpRcds;

            // ver_type size:1 byte, no need to swap move data_ptr
            data_ptr += sizeof(UInt8);

            // reserved size:1 byte, no need to swap move data_ptr
            data_ptr += sizeof(UInt8);

            // checksum: size 2 bytes, for incoming packet ignore it, 
            // for outgoing packet calculate checksum.Move data_ptr 2 byte
            if (!in)
            {
                checksum = (UInt16*)data_ptr;
                *checksum = 0;
            }
            data_ptr += sizeof(UInt16);

            // resv swap byte, move data_ptr
            resv = (UInt16*)data_ptr;
            EXTERNAL_ntoh(resv,
                          sizeof(*resv));
            data_ptr += sizeof(UInt16);

            // numGrpRecords swap byte, move data_ptr
            numGrpRecords = (UInt16*)data_ptr;
            tempNumGrpRcds = *numGrpRecords;
            EXTERNAL_ntoh(numGrpRecords,
                          sizeof(*numGrpRecords));
            data_ptr +=  sizeof(UInt16);
            if (!in)
            {
                numGrpRcds = tempNumGrpRcds;
            }
            else
            {
                numGrpRcds = *numGrpRecords;
            }

            // Swap byte for each GroupRecord
            for (i = 0; i < numGrpRcds; i++)
            {
                // record_type size:1 byte no need to swap move data_ptr
                data_ptr += sizeof(UInt8);

                // aux_data_len size:1 byte no need to swap move data_ptr
                data_ptr += sizeof(UInt8);

                // numSources swap bytes and move data_ptr
                numSources = (UInt16*)data_ptr;
                tempNumSrc = *numSources;
                EXTERNAL_ntoh(numSources,
                              sizeof(*numSources));
                data_ptr += sizeof(UInt16);
                if (!in)
                {
                    numSrc = tempNumSrc;
                }
                else
                {
                    numSrc = *numSources;
                }

                // groupAddress swap bytes and move data_ptr
                groupAddress = (NodeAddress*)data_ptr;
                EXTERNAL_ntoh(groupAddress,
                            sizeof(*groupAddress));
                data_ptr += sizeof(NodeAddress);

                for (itr = 0; itr < numSrc; itr++)
                {
                    srcAddress = (NodeAddress*)data_ptr;
                    EXTERNAL_ntoh(srcAddress,
                                  sizeof(NodeAddress));
                    data_ptr += sizeof(NodeAddress);
                }
            }
            break;
        }
        default:
        {
            char buf[MAX_STRING_LENGTH];
            sprintf(buf,
                    "Unknown packet type\n");
            ERROR_ReportWarning(buf);
            return;
        }
    }
}















