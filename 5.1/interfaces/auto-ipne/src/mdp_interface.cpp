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

#ifndef _WIN32 // unix/linux
#include <netinet/if_ether.h>
#else // windows
#include "iphlpapi.h"
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_socket.h"
#include "auto-ipnetworkemulator.h"
#include "mdp_interface.h"
#include "app_mdp.h"
#include "network_ip.h"
#include "transport_udp.h"
#define DEBUG 0

BOOL MDPPacketHandler::ReformatIncomingPacket(unsigned char* packet,
                                              Int32 size)
{
    return(MDPSwapBytes(packet, size, TRUE));
}

BOOL MDPPacketHandler::ReformatOutgoingPacket(unsigned char* packet,
                                              Int32 size)
{
    return(MDPSwapBytes(packet, size, FALSE));
}

void MDPPacketHandler::CheckAndProcessOutgoingMdpPacket(Node* node,
                                                IpHeaderType* ipHeader,
                                                struct libnet_ipv4_hdr* ip,
                                                Message* msg,
                                                int ipHeaderLength)
{
    if (ip->ip_p == IPPROTO_UDP && msg->headerProtocols[0] == TRACE_MDP)
    {
        UInt8* nextHeader;
        nextHeader = ((UInt8*) ip) + ipHeaderLength;

        unsigned char* mdpPayload = NULL;
        mdpPayload = (unsigned char *)((unsigned char *)nextHeader
                                       + sizeof(TransportUdpHeader));
        int remainingSize = MESSAGE_ReturnPacketSize(msg)
                            - ipHeaderLength
                            - sizeof(TransportUdpHeader);/* 8 for UDP */
        // now do required hton conversion on MDP payload
        MDPPacketHandler::ReformatOutgoingPacket(mdpPayload,
                                                 remainingSize);
    }
    return;
}
BOOL MDPPacketHandler::MDPSwapBytes(unsigned char* mdpPacket,
                                    Int32 size,
                                    BOOL in)
{
    MdpMessage msg;
    register UInt32 len = 0;
    Int32 count = 0;
    unsigned char* buffer = mdpPacket;
    BOOL isServerMsg = TRUE;

    if (in)
    {
        // Packet in network byte order,
        // so first have to convert in host byte.

        // common fields first.
        msg.type = (unsigned char) buffer[len++];
        msg.version = (unsigned char) buffer[len++];

        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));  // UInt32 sender
        len += sizeof(UInt32);

        // Now unpack fields unique to message type
        switch (msg.type)
        {
            case MDP_REPORT:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_REPORT\n");
                }
                isServerMsg = FALSE;
                msg.report.status = (unsigned char) buffer[len++];
                msg.report.flavor = (unsigned char) buffer[len++];
                switch (msg.report.flavor)
                {
                    case MDP_REPORT_HELLO:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_REPORT_HELLO\n");
                        }
                        // skip field report.node_name
                        //strncpy(report.node_name,
                        //        &buffer[len],
                        //        MDP_NODE_NAME_MAX);
                        len += MDP_NODE_NAME_MAX;                              // for report.node_name
                        if (msg.report.status & MDP_CLIENT)
                        {
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for duration
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for success
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for active
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for fail
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for resync
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.count
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_00
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_05
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_10
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_20
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_40
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_50
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for tx_rate
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack_cnt
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for supp_cnt
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.buf_total
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.peak
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for buf_stat.overflow
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for goodput
                            len += sizeof(UInt32);
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for rx_rate
                            len += sizeof(UInt32);
                        }
                        break;
                    }
                    default:
                    {
                        if (DEBUG)
                        {
                            printf("MdpMessage::MDPSwapBytes(): "
                                   "Invalid report type! %u\n",
                                   msg.report.flavor);
                        }
                    }
                }
                break;
            }
            case MDP_INFO:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_INFO\n");
                }
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);
                
                // skipping 4 bytes for object.ndata,
                // object.nparity, object.flags, and object.grtt
                len += 4;
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.info.segment_size
                len += sizeof(UInt16);
                break;
            }
            case MDP_DATA:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_DATA\n");
                }
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);

                // skipping 2 bytes for object.ndata, and object.nparity
                len += 2;
                msg.object.flags = (unsigned char)buffer[len++];   // for object.flags
                len++;                                             // for object.grtt
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.data.offset
                len += sizeof(UInt32);

                if (msg.object.flags & MDP_DATA_FLAG_RUNT)
                {
                    EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));   // for object.data.segment_size
                    len += sizeof(UInt16);
                }
                break;
            }
            case MDP_PARITY:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_PARITY\n");
                }
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);
                
                // skipping 4 bytes for object.ndata,
                // object.nparity, object.flags, and object.grtt
                len += 4;
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for object.parity.offset
                len += sizeof(UInt32);
                break;
            }
            case MDP_CMD:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_CMD\n");
                }
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for cmd.sequence
                len += sizeof(UInt16);
                len++;                                             // for cmd.grtt
                msg.cmd.flavor = (unsigned char)buffer[len++];

                switch (msg.cmd.flavor)
                {
                    case MDP_CMD_FLUSH:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_CMD_FLUSH\n");
                        }
                        len++;                                      // for cmd.flush.flags
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.flush.object_id
                        len += sizeof(UInt32);
                        break;
                    }
                    case MDP_CMD_SQUELCH:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_CMD_SQUELCH\n");
                        }
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.squelch.sync_id
                        len += sizeof(UInt32);
                        // for cmd.squelch.data
                        unsigned char* squelchPtr = &buffer[len];
                        unsigned char* squelchEnd = squelchPtr +
                                                         (size - (Int32)len);
                        while (squelchPtr < squelchEnd)
                        {
                            EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));
                            squelchPtr += sizeof(UInt32);
                            len += sizeof(UInt32);
                        }
                        break;
                    }
                    case MDP_CMD_ACK_REQ:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_CMD_ACK_REQ\n");
                        }
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.ack_req.object_id
                        len += sizeof(UInt32);
                        // rest is data, unpack them for ack node ids
                        count = 0;
                        unsigned char* ptr = &buffer[len];
                        while (count < (size - (Int32)len))
                        {
                            EXTERNAL_ntoh(&ptr[count], sizeof(UInt32)); // for nodeId
                            count += sizeof(UInt32);
                        }
                        break;
                    }
                    case MDP_CMD_GRTT_REQ:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_CMD_GRTT_REQ\n");
                        }
                        // skipping 2 bytes for cmd.grtt_req.flags,
                        // and cmd.grtt_req.sequence
                        len += 2;
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_sec
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_usec
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_sec
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_usec
                        len += sizeof(UInt32);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.segment_size
                        len += sizeof(UInt16);
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));// for cmd.grtt_req.rate
                        len += sizeof(UInt32);
                        len++;                                      // for cmd.grtt_req.rtt
                        EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.loss
                        len += sizeof(UInt16);
                        // rest is data, unpack them for representative node ids
                        count = 0;
                        unsigned char* ptr = &buffer[len];
                        while (count < (size - (Int32)len))
                        {
                            EXTERNAL_ntoh(&ptr[count], sizeof(UInt32)); // for repId
                            count += sizeof(UInt32);
                            count++;                                    // for repRtt
                        }
                        break;
                    }
                    case MDP_CMD_NACK_ADV:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Receiving MDP_CMD_NACK_ADV\n");
                        }
                        // for cmd.nack_adv.data
                        // Unpack the concatenated Object/Repair Nacks
                        char* optr = (char*)&buffer[len];
                        char* nack_end = optr + (size - (Int32)len);
                        while (optr < nack_end)
                        {
                            MdpObjectNack onack;
                            count = 0;
                            EXTERNAL_ntoh(&optr[count], sizeof(UInt32));  // for object_id
                            count += sizeof(UInt32);
                            EXTERNAL_ntoh(&optr[count], sizeof(UInt16));  // for nack_len
                            memcpy(&onack.nack_len,
                                   &optr[count],
                                   sizeof(UInt16));
                            count += sizeof(UInt16);
                            // rest is data, so increasing the count with nack_len
                            onack.data = &optr[count];
                            count += onack.nack_len;
                            // and increasing the optr for next Object Nack
                            optr += count;

                            // Now Unpack the concatenated Repair Nacks
                            char* rptr = onack.data;
                            char* onack_end = rptr + onack.nack_len;
                            MdpRepairNack rnack;

                            while (rptr < onack_end)
                            {
                                count = 0;
                                rnack.type = (MdpRepairType) rptr[count++];

                                switch (rnack.type)
                                {
                                    case MDP_REPAIR_OBJECT:
                                    case MDP_REPAIR_INFO:
                                        break;
                                    case MDP_REPAIR_SEGMENTS:
                                        rnack.nerasure =
                                                (unsigned char)rptr[count++];
                                    case MDP_REPAIR_BLOCKS:
                                        EXTERNAL_ntoh(&rptr[count],
                                                      sizeof(UInt32));  // for offset
                                        count += sizeof(UInt32);
                                        EXTERNAL_ntoh(&rptr[count],
                                                      sizeof(UInt16));
                                        memcpy(&rnack.mask_len,
                                               &rptr[count],
                                               sizeof(UInt16));
                                        count += sizeof(UInt16);
                                        // rest is mask, so increasing the
                                        // count with mask_len
                                        rnack.mask = &rptr[count];
                                        count += rnack.mask_len;
                                        break;
                                    default:
                                        if (DEBUG)
                                        {
                                            printf("MdpMessage::"
                                                   "MDPSwapBytes(): "
                                                   "Invalid repair nack!\n");
                                        }
                                        // this shouldn't happen
                                }
                                // increase the rptr for next Repair Nack
                                rptr += count;
                            }
                        }
                        break;
                    }
                    default:
                    {
                        if (DEBUG)
                        {
                            printf("MdpMessage::MDPSwapBytes(): "
                                   "Invalid MDP_CMD type!\n");
                        }
                    }
                }
                break;
            }
            case MDP_NACK:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_NACK\n");
                }
                isServerMsg = FALSE;
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.server_id
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_sec
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_usec
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for nack.loss_estimate
                len += sizeof(UInt16);
                len++;                                             // for nack.grtt_req_sequence
                // for nack.data
                // Unpack the concatenated Object/Repair Nacks
                char* optr = (char*)&buffer[len];
                char* nack_end = optr + (size - (Int32)len);
                while (optr < nack_end)
                {
                    MdpObjectNack onack;
                    count = 0;
                    EXTERNAL_ntoh(&optr[count], sizeof(UInt32));  // for object_id
                    count += sizeof(UInt32);
                    EXTERNAL_ntoh(&optr[count], sizeof(UInt16));  // for nack_len
                    memcpy(&onack.nack_len, &optr[count], sizeof(UInt16));
                    count += sizeof(UInt16);
                    // rest is data, so increasing the count with nack_len
                    onack.data = &optr[count];
                    count += onack.nack_len;
                    // and increasing the optr for next Object Nack
                    optr += count;

                    // Now Unpack the concatenated Repair Nacks
                    char* rptr = onack.data;
                    char* onack_end = rptr + onack.nack_len;
                    MdpRepairNack rnack;

                    while (rptr < onack_end)
                    {
                        count = 0;
                        rnack.type = (MdpRepairType) rptr[count++];

                        switch (rnack.type)
                        {
                            case MDP_REPAIR_OBJECT:
                            case MDP_REPAIR_INFO:
                                break;
                            case MDP_REPAIR_SEGMENTS:
                                rnack.nerasure =
                                                (unsigned char)rptr[count++];
                            case MDP_REPAIR_BLOCKS:
                                EXTERNAL_ntoh(&rptr[count], sizeof(UInt32));  // for offset
                                count += sizeof(UInt32);
                                EXTERNAL_ntoh(&rptr[count], sizeof(UInt16));
                                memcpy(&rnack.mask_len,
                                       &rptr[count],
                                       sizeof(UInt16));
                                count += sizeof(UInt16);
                                // rest is mask, so increasing the
                                // count with mask_len
                                rnack.mask = &rptr[count];
                                count += rnack.mask_len;
                                break;
                            default:
                                if (DEBUG)
                                {
                                    printf("MdpMessage::MDPSwapBytes(): "
                                           "Invalid repair nack!\n");
                                }
                                // this shouldn't happen
                        }
                        // increase the rptr for next Repair Nack
                        rptr += count;
                    }
                }
                break;
            }
            case MDP_ACK:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Receiving MDP_ACK\n");
                }
                isServerMsg = FALSE;
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.server_id
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_sec
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_usec
                len += sizeof(UInt32);
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt16));       // for ack.loss_estimate
                len += sizeof(UInt16);
                // skipping 2 bytes for ack.grtt_req_sequence and ack.type
                len += 2;
                EXTERNAL_ntoh(&buffer[len], sizeof(UInt32));       // for ack.object_id
                len += sizeof(UInt32);
                break;
            }
            default:
            {
                if (DEBUG)
                {
                    printf("MdpMessage::MDPSwapBytes(): "
                           "Invalid MDP message type!\n");
                }
            }
        }
    }


    // This is output to network, so put it in
    // network order last.
    // hton conversion here
    if (!in)
    {
        // Packet in host byte order,
        // so first have to convert in network byte.
        // common fields first.
        msg.type = (unsigned char) buffer[len++];
        msg.version = (unsigned char) buffer[len++];

        EXTERNAL_hton(&buffer[len], sizeof(UInt32));  // UInt32 sender
        len += sizeof(UInt32);

        // Now unpack fields unique to message type
        switch (msg.type)
        {
            case MDP_REPORT:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_REPORT\n");
                }
                isServerMsg = FALSE;
                msg.report.status = (unsigned char) buffer[len++];
                msg.report.flavor = (unsigned char) buffer[len++];
                switch (msg.report.flavor)
                {
                    case MDP_REPORT_HELLO:
                    {
                        // skip field report.node_name
                        //strncpy(&buffer[len],
                        //        report.node_name,
                        //        MDP_NODE_NAME_MAX);
                        len += MDP_NODE_NAME_MAX;                              // for report.node_name
                        if (msg.report.status & MDP_CLIENT)
                        {
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for duration
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for success
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for active
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for fail
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for resync
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.count
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_00
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_05
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_10
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_20
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_40
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for blk_stat.lost_50
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for tx_rate
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for nack_cnt
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for supp_cnt
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for buf_stat.buf_total
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for buf_stat.peak
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for buf_stat.overflow
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for goodput
                            len += sizeof(UInt32);
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for rx_rate
                            len += sizeof(UInt32);
                        }
                        break;
                    }
                    default:
                    {
                        if (DEBUG)
                        {
                            printf("MdpMessage::MDPSwapBytes(): "
                                   "Invalid report type! %u\n",
                                   msg.report.flavor);
                        }
                    }
                }
                break;
            }
            case MDP_INFO:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_INFO\n");
                }
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);
                
                // skipping 4 bytes for object.ndata,
                // object.nparity, object.flags, and object.grtt
                len += 4;
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for object.info.segment_size
                len += sizeof(UInt16);
                break;
            }
            case MDP_DATA:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_DATA\n");
                }
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);

                // skipping 2 bytes for object.ndata, and object.nparity
                len += 2;
                msg.object.flags = (unsigned char)buffer[len++];   // for object.flags
                len++;                                             // for object.grtt
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.data.offset
                len += sizeof(UInt32);

                if (msg.object.flags & MDP_DATA_FLAG_RUNT)
                {
                    EXTERNAL_hton(&buffer[len], sizeof(UInt16));   // for object.data.segment_size
                    len += sizeof(UInt16);
                }
                break;
            }
            case MDP_PARITY:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_PARITY\n");
                }
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for object.sequence
                len += sizeof(UInt16);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_id
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.object_size
                len += sizeof(UInt32);

                // skipping 4 bytes for object.ndata,
                // object.nparity, object.flags, and object.grtt
                len += 4;
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for object.parity.offset
                len += sizeof(UInt32);
                break;
            }
            case MDP_CMD:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_CMD\n");
                }
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for cmd.sequence
                len += sizeof(UInt16);
                len++;                                             // for cmd.grtt
                msg.cmd.flavor = (unsigned char)buffer[len++];

                switch (msg.cmd.flavor)
                {
                    case MDP_CMD_FLUSH:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: Sending MDP_CMD_FLUSH\n");
                        }
                        len++;                                      // for cmd.flush.flags
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.flush.object_id
                        len += sizeof(UInt32);
                        break;
                    }
                    case MDP_CMD_SQUELCH:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Sending MDP_CMD_SQUELCH\n");
                        }
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.squelch.sync_id
                        len += sizeof(UInt32);
                        // for cmd.squelch.data
                        unsigned char* squelchPtr = &buffer[len];
                        unsigned char* squelchEnd = squelchPtr +
                                                         (size - (Int32)len);
                        while (squelchPtr < squelchEnd)
                        {
                            EXTERNAL_hton(&buffer[len], sizeof(UInt32));
                            squelchPtr += sizeof(UInt32);
                            len += sizeof(UInt32);
                        }
                        break;
                    }
                    case MDP_CMD_ACK_REQ:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Sending MDP_CMD_ACK_REQ\n");
                        }
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.ack_req.object_id
                        len += sizeof(UInt32);
                        // rest is data, unpack them for ack node ids
                        count = 0;
                        unsigned char* ptr = &buffer[len];
                        while (count < (size - (Int32)len))
                        {
                            EXTERNAL_hton(&ptr[count], sizeof(UInt32)); // for nodeId
                            count += sizeof(UInt32);
                        }
                        break;
                    }
                    case MDP_CMD_GRTT_REQ:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Sending MDP_CMD_GRTT_REQ\n");
                        }
                        // skipping 2 bytes for cmd.grtt_req.flags,
                        // and cmd.grtt_req.sequence
                        len += 2;
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_sec
                        len += sizeof(UInt32);
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.send_time.tv_usec
                        len += sizeof(UInt32);
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_sec
                        len += sizeof(UInt32);
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.hold_time.tv_usec
                        len += sizeof(UInt32);
                        EXTERNAL_hton(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.segment_size
                        len += sizeof(UInt16);
                        EXTERNAL_hton(&buffer[len], sizeof(UInt32));// for cmd.grtt_req.rate
                        len += sizeof(UInt32);
                        len++;                                      // for cmd.grtt_req.rtt
                        EXTERNAL_hton(&buffer[len], sizeof(UInt16));// for cmd.grtt_req.loss
                        len += sizeof(UInt16);
                        // rest is data, unpack them for
                        // representative node ids
                        count = 0;
                        unsigned char* ptr = &buffer[len];
                        while (count < (size - (Int32)len))
                        {
                            EXTERNAL_hton(&ptr[count], sizeof(UInt32)); // for repId
                            count += sizeof(UInt32);
                            count++;                                    // for repRtt
                        }
                        break;
                    }
                    case MDP_CMD_NACK_ADV:
                    {
                        if (DEBUG)
                        {
                            printf("MdpInterface: "
                                   "Sending MDP_CMD_NACK_ADV\n");
                        }
                        // for cmd.nack_adv.data
                        // Unpack the concatenated Object/Repair Nacks
                        char* optr = (char*)&buffer[len];
                        char* nack_end = optr + (size - (Int32)len);
                        while (optr < nack_end)
                        {
                            MdpObjectNack onack;
                            count = 0;
                            EXTERNAL_hton(&optr[count], sizeof(UInt32));  // for object_id
                            count += sizeof(UInt32);
                            memcpy(&onack.nack_len,
                                   &optr[count],
                                   sizeof(UInt16));
                            EXTERNAL_hton(&optr[count], sizeof(UInt16));  // for nack_len
                            count += sizeof(UInt16);
                            // rest is data, so increasing the
                            // count with nack_len
                            onack.data = &optr[count];
                            count += onack.nack_len;
                            // and increasing the optr for next Object Nack
                            optr += count;

                            // Now Unpack the concatenated Repair Nacks
                            char* rptr = onack.data;
                            char* onack_end = rptr + onack.nack_len;
                            MdpRepairNack rnack;

                            while (rptr < onack_end)
                            {
                                count = 0;
                                rnack.type = (MdpRepairType) rptr[count++];

                                switch (rnack.type)
                                {
                                    case MDP_REPAIR_OBJECT:
                                    case MDP_REPAIR_INFO:
                                        break;
                                    case MDP_REPAIR_SEGMENTS:
                                        rnack.nerasure =
                                                (unsigned char)rptr[count++];
                                    case MDP_REPAIR_BLOCKS:
                                        EXTERNAL_hton(&rptr[count],
                                                      sizeof(UInt32));  // for offset
                                        count += sizeof(UInt32);
                                        memcpy(&rnack.mask_len,
                                               &rptr[count],
                                               sizeof(UInt16));
                                        EXTERNAL_hton(&rptr[count],
                                                      sizeof(UInt16));
                                        count += sizeof(UInt16);
                                        // rest is mask, so increasing the
                                        // count with mask_len
                                        rnack.mask = &rptr[count];
                                        count += rnack.mask_len;
                                        break;
                                    default:
                                        if (DEBUG)
                                        {
                                            printf("MdpMessage::"
                                                   "MDPSwapBytes(): "
                                                   "Invalid repair nack!\n");
                                        }
                                        // this shouldn't happen
                                }
                                // increase the rptr for next Repair Nack
                                rptr += count;
                            }
                        }
                        break;
                    }
                    default:
                    {
                        if (DEBUG)
                        {
                            printf("MdpMessage::MDPSwapBytes(): "
                                   "Invalid MDP_CMD type!\n");
                        }
                    }
                }
                break;
            }
            case MDP_NACK:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_NACK\n");
                }
                isServerMsg = FALSE;
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for nack.server_id
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_sec
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for nack.grtt_response.tv_usec
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for nack.loss_estimate
                len += sizeof(UInt16);
                len++;                                             // for nack.grtt_req_sequence
                // for nack.data
                // Unpack the concatenated Object/Repair Nacks
                char* optr = (char*)&buffer[len];
                char* nack_end = optr + (size - (Int32)len);
                while (optr < nack_end)
                {
                    MdpObjectNack onack;
                    count = 0;
                    EXTERNAL_hton(&optr[count], sizeof(UInt32));  // for object_id
                    count += sizeof(UInt32);
                    memcpy(&onack.nack_len, &optr[count], sizeof(UInt16));
                    EXTERNAL_hton(&optr[count], sizeof(UInt16));  // for nack_len
                    count += sizeof(UInt16);
                    // rest is data, so increasing the count with nack_len
                    onack.data = &optr[count];
                    count += onack.nack_len;
                    // and increasing the optr for next Object Nack
                    optr += count;

                    // Now Unpack the concatenated Repair Nacks
                    char* rptr = onack.data;
                    char* onack_end = rptr + onack.nack_len;
                    MdpRepairNack rnack;

                    while (rptr < onack_end)
                    {
                        count = 0;
                        rnack.type = (MdpRepairType) rptr[count++];

                        switch (rnack.type)
                        {
                            case MDP_REPAIR_OBJECT:
                            case MDP_REPAIR_INFO:
                                break;
                            case MDP_REPAIR_SEGMENTS:
                                rnack.nerasure =
                                                (unsigned char)rptr[count++];
                            case MDP_REPAIR_BLOCKS:
                                EXTERNAL_hton(&rptr[count], sizeof(UInt32));  // for offset
                                count += sizeof(UInt32);
                                memcpy(&rnack.mask_len,
                                       &rptr[count],
                                       sizeof(UInt16));
                                EXTERNAL_hton(&rptr[count], sizeof(UInt16));
                                count += sizeof(UInt16);
                                // rest is mask, so increasing the
                                // count with mask_len
                                rnack.mask = &rptr[count];
                                count += rnack.mask_len;
                                break;
                            default:
                                if (DEBUG)
                                {
                                    printf("MdpMessage::MDPSwapBytes(): "
                                           "Invalid repair nack!\n");
                                }
                                // this shouldn't happen
                        }
                        // increase the rptr for next Repair Nack
                        rptr += count;
                    }
                }
                break;
            }
            case MDP_ACK:
            {
                if (DEBUG)
                {
                    printf("MdpInterface: Sending MDP_ACK\n");
                }
                isServerMsg = FALSE;
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for ack.server_id
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_sec
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for ack.grtt_response.tv_usec
                len += sizeof(UInt32);
                EXTERNAL_hton(&buffer[len], sizeof(UInt16));       // for ack.loss_estimate
                len += sizeof(UInt16);
                // skipping 2 bytes for ack.grtt_req_sequence and ack.type
                len += 2;
                EXTERNAL_hton(&buffer[len], sizeof(UInt32));       // for ack.object_id
                len += sizeof(UInt32);
                break;
            }
            default:
            {
                if (DEBUG)
                {
                    printf("MdpMessage::MDPSwapBytes(): "
                           "Invalid MDP message type!\n");
                }
            }
        }
    }
    return (isServerMsg);
}
