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
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.
/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * (1) source code distributions retain this paragraph in its entirety,
 *
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided
 *     with the distribution, and
 *
 * (3) all advertising materials mentioning features or use of this
 *     software display the following acknowledgment:
 *
 *      "This product includes software written and developed
 *       by Brian Adamson and Joe Macker of the Naval Research
 *       Laboratory (NRL)."
 *
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/


#ifdef UNIX
#include <sys/types.h>
#include <netinet/in.h>
#endif // UNIX

#include<string.h>
#include<math.h>
#include<stdio.h>
#include "qualnet_error.h"
#include "mdpMessage.h"

// static helper functions for pack file name info properly
static void MdpPackFileNameInfo(char* buffer, UInt32* len, MdpMessage* msg)
{
    // Properly convert file name MDP_PROTO_PATH_DELIMITERs
    char* ptr = buffer + *len;
    char* end = ptr + msg->object.info.len;
    while ((ptr < end) && (*ptr != '\0'))
    {
        if (MDP_PROTO_PATH_DELIMITER == *ptr) *ptr = '/';
        ptr++;
    }
}

// static helper functions for unpack file name info properly
static void MdpUnpackFileNameInfo(MdpMessage* msg)
{
    // Properly convert file name MDP_PROTO_PATH_DELIMITERs
    char* ptr = msg->object.info.data;
    char* end = ptr + msg->object.info.actual_data_len; //object.info.len;
    while ((ptr < end) && (*ptr != '\0'))
    {
        if ('/' == *ptr) *ptr = MDP_PROTO_PATH_DELIMITER;
        ptr++;
    }
}


// These are very conservative Pack() & Unpack() message routines
// If we pay more attention to Mdp protocol field alignment and to
// the ability of various machines/compilers to follow alignment
// rules as we would expect, these routines could be optimized somewhat
// Note that protocol field alignment may result in some wasted protocol
// header space ... we'll go with the implementation below until some
// committee forces us into something else (good or bad)

// (TBD) Get rid of the use of "temp_short" & "temp_long" even though
//       it will possibly invalidate messages after packing ???

int MdpMessage::Pack(char *buffer)
{
    register UInt32 len = 0;
    register UInt32 temp_long;
    register unsigned short temp_short;

    // If these assertions fail, the code base needs some reworking
    // for compiler with different size settings (or set compiler
    // settings so these values work)
    //assert(sizeof(char) == 1);
    //assert(sizeof(short) == 2);
    //assert(sizeof(Int32) == 4);

    // Pack common fields first
    buffer[len++] = type;
    buffer[len++] = version;
    temp_long = sender;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);

    // Now pack fields specific to message type
    switch (type)
    {
        case MDP_REPORT:
            buffer[len++] = report.status;
            buffer[len++] = report.flavor;
            switch (report.flavor)
            {
                case MDP_REPORT_HELLO:
                    strncpy(&buffer[len],report.node_name,MDP_NODE_NAME_MAX);
                    len += MDP_NODE_NAME_MAX;
                    if (report.status & MDP_CLIENT)
                        len += report.client_stats.Pack(&buffer[len]);
                    break;

                default:
                    printf("MdpMessage::Pack() Invalid report type!\n");
                    return 0;
            }
            break;

        case MDP_INFO:
            temp_short = object.sequence;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);

            temp_long = object.object_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_long = object.object_size;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            buffer[len++] = object.ndata;             // ndata
            buffer[len++] = object.nparity;           // nparity
            buffer[len++] = object.flags;             // flags
            buffer[len++] = object.grtt;              // grtt

            temp_short = object.info.segment_size;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);

            // Copy the info data into the packet
            memcpy(&buffer[len], object.info.data, object.info.len); // info content

            if (object.flags & MDP_DATA_FLAG_FILE)
            {
                MdpPackFileNameInfo(buffer, &len, this);
            }

            // Right now object.info.len and object.info.actual_data_len are
            // same so below statements comment does not have any affects
            //memcpy(&buffer[len],
            //       object.info.data,
            //       object.info.actual_data_len); // info content
            //len += object.info.actual_data_len;

            len += object.info.len;
            break;

        case MDP_DATA:
            temp_short = object.sequence;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);

            temp_long = object.object_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_long = object.object_size;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            buffer[len++] = object.ndata;             // ndata
            buffer[len++] = object.nparity;           // nparity
            buffer[len++] = object.flags;             // flags
            buffer[len++] = object.grtt;              // grtt

            temp_long = object.data.offset;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            // Pack optional "seg_size" field for "RUNT" data msg
            if (object.flags & MDP_DATA_FLAG_RUNT)
            {
                temp_short = object.data.segment_size;
                memcpy(&buffer[len], &temp_short, sizeof(short));
                len += sizeof(short);
            }

            if (object.data.actual_data_len)
            {
                memcpy(&buffer[len],
                       object.data.data,
                       object.data.actual_data_len); // data
                len += object.data.actual_data_len;
            }
            break;

        case MDP_PARITY:
            temp_short = object.sequence;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);

            temp_long = object.object_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_long = object.object_size;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            buffer[len++] = object.ndata;             // ndata
            buffer[len++] = object.nparity;           // nparity
            buffer[len++] = object.flags;             // flags
            buffer[len++] = object.grtt;              // grtt

            temp_long = object.parity.offset;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            buffer[len++] = object.parity.id;                // id

            if (object.parity.actual_data_len)
            {
                memcpy(&buffer[len],
                       object.parity.data,
                       object.parity.actual_data_len); // data
                len += object.parity.actual_data_len;
            }
            break;

        case MDP_CMD:
            temp_short = cmd.sequence;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);
            buffer[len++] = cmd.grtt;                           // grtt

            buffer[len++] = cmd.flavor;                         // flavor
            switch (cmd.flavor)
            {
                case MDP_CMD_FLUSH:
                    buffer[len++] = cmd.flush.flags;
                    temp_long = cmd.flush.object_id;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);
                    break;

                case MDP_CMD_SQUELCH:
                    temp_long = cmd.squelch.sync_id;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);
                    memcpy(&buffer[len], cmd.squelch.data, cmd.squelch.len);
                    len += cmd.squelch.len;
                    break;

                case MDP_CMD_ACK_REQ:
                    temp_long = cmd.ack_req.object_id;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);

                    memcpy(&buffer[len], cmd.ack_req.data,
                           cmd.ack_req.len);                    // data
                    len += cmd.ack_req.len;
                    break;

                case MDP_CMD_GRTT_REQ:
                    buffer[len++] = cmd.grtt_req.flags;         // flags

                    buffer[len++] = cmd.grtt_req.sequence;       // sequence

                    temp_long = (UInt32)cmd.grtt_req.send_time.tv_sec;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);                        // send_time
                    temp_long = (UInt32)cmd.grtt_req.send_time.tv_usec;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);

                    temp_long = (UInt32)cmd.grtt_req.hold_time.tv_sec;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);                        // hold_time
                    temp_long = (UInt32)cmd.grtt_req.hold_time.tv_usec;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);

                    temp_short = cmd.grtt_req.segment_size;
                    memcpy(&buffer[len], &temp_short, sizeof(short));
                    len += sizeof(short);

                    temp_long = cmd.grtt_req.rate;
                    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                    len += sizeof(UInt32);

                    buffer[len++] = cmd.grtt_req.rtt;           // rtt

                    temp_short = cmd.grtt_req.loss;
                    memcpy(&buffer[len], &temp_short, sizeof(short));
                    len += sizeof(short);

                    memcpy(&buffer[len], cmd.grtt_req.data,cmd.grtt_req.len);
                    len += cmd.grtt_req.len;                    // data
                    break;

                case MDP_CMD_NACK_ADV:
                    memcpy(&buffer[len], cmd.nack_adv.data,cmd.nack_adv.len);
                    len += cmd.nack_adv.len;                    // data
                    break;

                default:
                    printf("mdp: MdpMessage::Pack() : Bad server cmd!\n");
                    return 0;
            }
            break;

        case MDP_NACK:
            temp_long = nack.server_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_long = (UInt32)nack.grtt_response.tv_sec;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);                        // grtt_response
            temp_long = (UInt32)nack.grtt_response.tv_usec;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_short = nack.loss_estimate;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);                       // loss_estimate

            buffer[len++] = nack.grtt_req_sequence;     // grtt_req_sequence

            memcpy(&buffer[len], nack.data, nack.nack_len);  // data
            len += nack.nack_len;
            break;

        case MDP_ACK:
            temp_long = ack.server_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_long = (UInt32)ack.grtt_response.tv_sec;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);                        // grtt_response
            temp_long = (UInt32)ack.grtt_response.tv_usec;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);

            temp_short = ack.loss_estimate;
            memcpy(&buffer[len], &temp_short, sizeof(short));
            len += sizeof(short);                       // loss_estimate

            buffer[len++] = ack.grtt_req_sequence;      // grtt_req_sequence

            buffer[len++] = (char)ack.type;                   // type

            temp_long = ack.object_id;
            memcpy(&buffer[len], &temp_long, sizeof(UInt32));
            len += sizeof(UInt32);
            break;

        default:
            printf("mdp: MdpMessage::Pack() : Bad message type!\n");
            return 0;
            break;
    }
    return len;
}  // end MdpMessage::Pack()

bool MdpMessage::Unpack(char *buffer, int packet_length,
                        int virtual_length, bool* isServerPacket)
{
    register UInt32 len = 0;
    register UInt32 temp_long;
    // Unpack common fields first.
    type = (unsigned char) buffer[len++];
    version = (unsigned char) buffer[len++];
    memcpy(&sender, &buffer[2], sizeof(UInt32));
    len += sizeof(UInt32);

    // Now unpack fields unique to message type
    switch (type)
    {
        case MDP_REPORT:
            *isServerPacket = false;
            report.status = (unsigned char) buffer[len++];
            report.flavor = (unsigned char) buffer[len++];
            switch (report.flavor)
            {
                case MDP_REPORT_HELLO:
                    strncpy(report.node_name,&buffer[len],MDP_NODE_NAME_MAX);
                    len += MDP_NODE_NAME_MAX;
                    if (report.status & MDP_CLIENT)
                        len += report.client_stats.Unpack(&buffer[len]);
                    break;

                default:
                    printf("MdpMessage::Unpack(): Invalid report type!\n");
                    return false;
            }
            return true;

        case MDP_INFO:
            memcpy(&object.sequence, &buffer[len], sizeof(short));
            len += sizeof(short);

            memcpy(&object.object_id, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            memcpy(&object.object_size, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            object.ndata = buffer[len++];                 // ndata
            object.nparity = buffer[len++];               // nparity
            object.flags = buffer[len++];                 // flags
            object.grtt = buffer[len++];                  // grtt

            memcpy(&object.info.segment_size, &buffer[len], sizeof(short));
            len += sizeof(short);                       // segment_size

            object.info.len = (unsigned short)
                                    ((packet_length + virtual_length) - len);      // info len
            object.info.actual_data_len =
                                       (unsigned short)(packet_length - len);

            if (object.info.actual_data_len)
            {
                object.info.data = &buffer[len];                   // info content
            }
            else
            {
                object.info.data = NULL;
            }

            // (TBD) This file hack stuff needs to go somewhere else
            if (object.flags & MDP_DATA_FLAG_FILE)
            {
                MdpUnpackFileNameInfo(this);
            }

            return true;

        case MDP_DATA:
            memcpy(&object.sequence, &buffer[len], sizeof(short));
            len += sizeof(short);

            memcpy(&object.object_id, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            memcpy(&object.object_size, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            object.ndata = (unsigned char) buffer[len++]; // ndata
            object.nparity = (unsigned char) buffer[len++]; // nparity
            object.flags = (unsigned char) buffer[len++]; // flags
            object.grtt = buffer[len++];                  // grtt

            memcpy(&object.data.offset, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            if (object.flags & MDP_DATA_FLAG_RUNT)    // opt. segment_size needed
            {
                memcpy(&object.data.segment_size,&buffer[len],sizeof(short));
                len += sizeof(short);
            }

            object.data.len = (unsigned short)
                                    ((packet_length + virtual_length) - len);
            object.data.actual_data_len =
                                       (unsigned short)(packet_length - len);

            if (object.data.actual_data_len)
            {
                object.data.data = &buffer[len];
            }
            else
            {
                object.data.data = NULL;
            }
            return true;

        case MDP_PARITY:
            memcpy(&object.sequence, &buffer[len], sizeof(short));
            len += sizeof(short);

            memcpy(&object.object_id, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            memcpy(&object.object_size, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            object.ndata = (unsigned char) buffer[len++]; // ndata
            object.nparity = (unsigned char) buffer[len++]; // nparity
            object.flags = (unsigned char) buffer[len++]; // flags
            object.grtt = buffer[len++];                  // grtt

            memcpy(&object.parity.offset, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            object.parity.id = (unsigned char) buffer[len++];      // id

            object.parity.len = (unsigned short)
                                    ((packet_length + virtual_length) - len);
            object.parity.actual_data_len =
                                       (unsigned short)(packet_length - len);
            if (object.parity.actual_data_len)
            {
                object.parity.data = &buffer[len];
            }
            else
            {
                object.parity.data = NULL;
            }
            return true;

        case MDP_CMD:
            memcpy(&cmd.sequence, &buffer[len], sizeof(short));
            len += sizeof(short);
            cmd.grtt = buffer[len++];                 // grtt

            cmd.flavor = buffer[len++];
            switch (cmd.flavor)
            {
                case MDP_CMD_FLUSH:
                    cmd.flush.flags = buffer[len++];
                    memcpy(&cmd.flush.object_id,&buffer[len],sizeof(UInt32));
                    break;

                case MDP_CMD_SQUELCH:
                    memcpy(&cmd.squelch.sync_id,&buffer[len],sizeof(UInt32));
                    len += sizeof(UInt32);
                    cmd.squelch.len = (unsigned short)(packet_length - len);  // len
                    cmd.squelch.data = &buffer[len];        // data
                    break;

                case MDP_CMD_ACK_REQ:
                    memcpy(&cmd.ack_req.object_id,
                           &buffer[len],
                           sizeof(UInt32));
                    len += sizeof(UInt32);

                    cmd.ack_req.len = (unsigned short)(packet_length - len);  // len
                    cmd.ack_req.data = &buffer[len];        // data
                    break;

                case MDP_CMD_GRTT_REQ:
                    cmd.grtt_req.flags = buffer[len++];     // flags
                    cmd.grtt_req.sequence = buffer[len++];  // sequence

                    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
                    cmd.grtt_req.send_time.tv_sec = temp_long;
                    len += sizeof(UInt32);                    // send_time

                    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
                    cmd.grtt_req.send_time.tv_usec = temp_long;
                    len += sizeof(UInt32);

                    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
                    cmd.grtt_req.hold_time.tv_sec = temp_long;
                    len += sizeof(UInt32);                    // hold_time

                    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
                    cmd.grtt_req.hold_time.tv_usec = temp_long;
                    len += sizeof(UInt32);

                    memcpy(&cmd.grtt_req.segment_size,
                           &buffer[len],
                           sizeof(short));
                    len += sizeof(short);                   // segment_size

                    memcpy(&cmd.grtt_req.rate, &buffer[len], sizeof(UInt32));
                    len += sizeof(UInt32);                    // rate

                    cmd.grtt_req.rtt = buffer[len++];       // rtt
                    memcpy(&cmd.grtt_req.loss, &buffer[len], sizeof(short));
                    len += sizeof(short);                   // loss

                    cmd.grtt_req.len = (unsigned short)(packet_length - len); // len
                    cmd.grtt_req.data = &buffer[len];       // data
                    break;

                case MDP_CMD_NACK_ADV:
                    cmd.nack_adv.data = &buffer[len];       // data
                    cmd.nack_adv.len = (unsigned short)(packet_length - len); // len
                    break;
                default:
                    type = MDP_MSG_INVALID;
                    return false;
            }
            return true;

        case MDP_NACK:
            *isServerPacket = false;
            memcpy(&nack.server_id, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            memcpy(&temp_long, &buffer[len], sizeof(UInt32));
            nack.grtt_response.tv_sec = temp_long;
            len += sizeof(UInt32);                    // grtt_response

            memcpy(&temp_long, &buffer[len], sizeof(UInt32));
            nack.grtt_response.tv_usec = temp_long;
            len += sizeof(UInt32);

            memcpy(&nack.loss_estimate, &buffer[len], sizeof(short));
            len += sizeof(short);                   // loss_estimate

            nack.grtt_req_sequence = buffer[len++]; // grtt_req_sequence
            nack.nack_len = (unsigned short)(packet_length - len);    // len
            nack.data = &buffer[len];               // data
            return true;

        case MDP_ACK:
            *isServerPacket = false;
            memcpy(&ack.server_id, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);

            memcpy(&temp_long, &buffer[len], sizeof(UInt32));
            ack.grtt_response.tv_sec = temp_long;
            len += sizeof(UInt32);                    // grtt_response

            memcpy(&temp_long, &buffer[len], sizeof(UInt32));
            ack.grtt_response.tv_usec = temp_long;
            len += sizeof(UInt32);

            memcpy(&ack.loss_estimate, &buffer[len], sizeof(short));
            len += sizeof(short);                   // loss_estimate

            ack.grtt_req_sequence = buffer[len++];  // grtt_req_sequence
            ack.type = (MdpAckType) buffer[len++];  // type
            memcpy(&ack.object_id, &buffer[len], sizeof(UInt32));
            return true;

        default:
            type = MDP_MSG_INVALID;
            return false;
    }
}  // end MdpMessage::Unpack()

/***********************************************************************
 *  MdpMessageQueue implementation
 */

// These are the priorities used for queuing messages
// Bigger number is higher priority (FIFO otherwise)
static const int MSG_PRIORITY[] =
{
    -1,     // MDP_INVALID_MSG
     0,     // MDP_REPORT
    10,     // MDP_INFO
     6,     // MDP_DATA
     8,     // MDP_PARITY
    12,     // MDP_CMD
    12,     // MDP_NACK
    12      // MDP_ACK
};

MdpMessageQueue::MdpMessageQueue()
    : head(NULL), tail(NULL)
{
}


void MdpMessageQueue::RequeueMessage(MdpMessage *theMsg)
{
    theMsg->prev = NULL;
    theMsg->next = head;
    if (theMsg->next)
        head->prev = theMsg;
    else
        tail = theMsg;
    head = theMsg;
}  // end MdpMessageQueue::RequeueMessage()

void MdpMessageQueue::QueueMessage(MdpMessage *theMsg)
{
    MdpMessage *prev = tail;
    while (prev)
    {
        if (MSG_PRIORITY[theMsg->type] > MSG_PRIORITY[prev->type])
        {
            prev = prev->prev;  // Go up the queue
        }
        else
        {
            theMsg->prev = prev;
            theMsg->next = prev->next;
            if (theMsg->next)
                theMsg->next->prev = theMsg;
            else
                tail = theMsg;
            prev->next = theMsg;
            return;
        }
    }

    // theMsg goes to top of the queue
    theMsg->next = head;
    if (theMsg->next)
        head->prev = theMsg;
    else
        tail = theMsg;
    theMsg->prev = NULL;
    head = theMsg;
}  // end MdpMessageQueue::QueueMessage()

MdpMessage* MdpMessageQueue::GetNextMessage()
{
    MdpMessage *theMsg = head;
    if (theMsg)
    {
        head = head->next;
        if (head)
            head->prev = NULL;
        else
            tail = NULL;
    }
    return theMsg;
}  // end MdpMessageQueue::GetNextMessage()

void MdpMessageQueue::Remove(MdpMessage *theMsg)
{
    assert(theMsg);
    if (theMsg->prev)
        theMsg->prev->next = theMsg->next;
    else
        head = theMsg->next;
    if (theMsg->next)
        theMsg->next->prev = theMsg->prev;
    else
        tail = theMsg->prev;
}  // end MdpMessageQueue::Remove()

MdpMessage* MdpMessageQueue::FindNackAdv()
{
    MdpMessage *theMsg = head;
    while (theMsg)
    {
        if ((MDP_CMD == theMsg->type) &&
            (MDP_CMD_NACK_ADV == theMsg->cmd.flavor))
            return theMsg;
        theMsg = theMsg->next;
    }
    return (MdpMessage*)NULL;
}  // end MdpMessageQueue::FindNackAdv()


/**********************************************************************
 * Routines for packing and parsing NACK data content
 * (TBD) Think of better ways to pack NACKs than raw masks ???
 */

const UInt32 MDP_NACK_OBJECT_HEADER_LEN = sizeof(UInt32) + sizeof(short);

bool MdpObjectNack::Init(UInt32 id, char *buffer, UInt32 buflen)
{
    // Make sure there's room for at least one RepairNack
    if (buflen > MDP_NACK_OBJECT_HEADER_LEN)
    {
        object_id = id;
        data = &buffer[MDP_NACK_OBJECT_HEADER_LEN];
        nack_len = 0;
        max_len = (unsigned short)(buflen - MDP_NACK_OBJECT_HEADER_LEN);
        return true;
    }
    else
    {
        return false;
    }
}  // end MdpObjectNack::Init()


bool MdpObjectNack::AppendRepairNack(MdpRepairNack *nack)
{
    int len = nack->Pack(&data[nack_len], max_len);
    if (len)
    {
        nack_len = nack_len +(unsigned short)len;
        max_len = max_len - (unsigned short)len;
        return true;
    }
    else
    {
        return false;
    }
}  // end

int MdpObjectNack::Pack()
{
    if (nack_len > 0)
    {
        // Pack object_id & nack_len
        UInt32 temp_long = object_id;
        char *header_ptr = data - MDP_NACK_OBJECT_HEADER_LEN;
        memcpy(header_ptr, &temp_long, sizeof(UInt32));
        unsigned short temp_short = nack_len;
        memcpy(&header_ptr[sizeof(UInt32)], &temp_short, sizeof(short));
        return (nack_len + MDP_NACK_OBJECT_HEADER_LEN);
    }
    else
    {
        return 0;
    }
} // end MdpObjectNack::Pack()

int MdpObjectNack::Unpack(char *buffer)
{
    register int len = 0;
    memcpy(&object_id, buffer, sizeof(UInt32));
    len += sizeof(UInt32);
    memcpy(&nack_len, &buffer[len], sizeof(short));
    len += sizeof(short);
    data = &buffer[len];
    len += nack_len;
    return len;
}  // end MdpObjectNack::Unpack()


int MdpRepairNack::Pack(char* buffer, unsigned int buflen)
{
    register int len = 0;
    if (buflen-- > 0)
        buffer[len++] = (char)type;
    else
        return 0;
    switch (type)
    {
        case MDP_REPAIR_OBJECT:
        case MDP_REPAIR_INFO:
            return 1;

        case MDP_REPAIR_SEGMENTS:
            // Note: MDP_REPAIR_SEGMENT masks should be sent intact
            if (buflen-- > 0)
                buffer[len++] = nerasure;
            else
                return 0;
            if (buflen >= (sizeof(UInt32) + sizeof(short) + mask_len))
            {
                UInt32 temp_long = offset;
                memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                len += sizeof(UInt32);
                unsigned short temp_short = mask_len;
                memcpy(&buffer[len], &temp_short, sizeof(short));
                len += sizeof(short);
                memcpy(&buffer[len], mask, mask_len);
                len += mask_len;
                return len;
            }
            else
            {
                return 0;
            }

        case MDP_REPAIR_BLOCKS:
            // Note: MDP_REPAIR_BLOCK masks may get shortened to fit
            if (buflen > (sizeof(UInt32) + sizeof(short)))
            {
                UInt32 temp_long = offset;
                memcpy(&buffer[len], &temp_long, sizeof(UInt32));
                len += sizeof(UInt32);
                unsigned short temp_short = mask_len;
                memcpy(&buffer[len], &temp_short, sizeof(short));
                len += sizeof(short);
                buflen -= (sizeof(UInt32) + sizeof(short));
                if (buflen < mask_len)
                {
                    memcpy(&buffer[len], mask, buflen);
                    len += buflen;
                }
                else
                {
                    memcpy(&buffer[len], mask, mask_len);
                    len += mask_len;
                }
                return len;
            }
            else
            {
                return 0;
            }

        default:
            // this shouldn't happen
            printf( "MdpRepairNack::Pack() Invalid repair nack!\n");
            return 0;
    }
}  // end MdpRepairNack::Pack()

int MdpRepairNack::Unpack(char* buffer)
{
    register int len = 0;
    type = (MdpRepairType) buffer[len++];
    switch (type)
    {
        case MDP_REPAIR_OBJECT:
        case MDP_REPAIR_INFO:
            break;

        case MDP_REPAIR_SEGMENTS:
            nerasure = buffer[len++];
        case MDP_REPAIR_BLOCKS:
            memcpy(&offset, &buffer[len], sizeof(UInt32));
            len += sizeof(UInt32);
            memcpy(&mask_len, &buffer[len], sizeof(short));
            len += sizeof(short);
            mask = &buffer[len];
            len += mask_len;
            break;

        default:
            printf("MdpRepairNack::Unpack() Invalid repair nack!\n");
            type = MDP_REPAIR_INVALID;  // this shouldn't happen
            break;
    }
    return len;
}  // end MdpRepairNack::Unpack()


bool MdpGrttReqCmd::AppendRepresentative(UInt32 repId,
                                         double repRtt,
                                         UInt16 maxLen)
{
    if (!data)
    {
        len = 0;
        return false;
    }
    if (maxLen < (len+sizeof(UInt32)+1))
    {
        return false;
    }
    else
    {
        char* ptr = data + len;
        memcpy(ptr, &repId, sizeof(UInt32));
        ptr += sizeof(UInt32);
        *ptr = QuantizeRtt(repRtt);
        len += (sizeof(UInt32) + 1);
        return true;
    }
}  // end MdpGrttReqCmd::PackRepresentative()


bool MdpGrttReqCmd::FindRepresentative(UInt32 repId, double* repRtt)
{
    char* end = data + len;
    while (data < end)
    {
        if (0 == memcmp(data, &repId, sizeof(UInt32)))
        {
            data += sizeof(UInt32);
            *repRtt = UnquantizeRtt((unsigned char)(*data));
            return true;
        }
        data += (sizeof(UInt32) + 1);
    }
    return false;
}  // end MdpAckReqCmd::FindRepresentative()


bool MdpAckReqCmd::AppendAckingNode(UInt32  nodeId,
                                    UInt16 maxLen)
{
    if (!data)
    {
        len = 0;
        return false;
    }
    if (maxLen < (len+sizeof(UInt32)))
    {
        return false;
    }
    else
    {
        memcpy((data+len), &nodeId, sizeof(UInt32));
        len += sizeof(UInt32);
        return true;
    }
}  // end MdpAckReqCmd::AppendAckingNode()


bool MdpAckReqCmd::FindAckingNode(UInt32 nodeId)
{
    const char* ptr = data;
    const char* end = ptr + len;
    while (ptr < end)
    {
        if (0 == memcmp(ptr, &nodeId, sizeof(UInt32))) return true;
        ptr += sizeof(UInt32);
    }
    return false;
}  // end MdpAckReqCmd::FindAckingNode()


/****************************************************************
 *  RTT quantization routines:
 *  These routines are valid for 1.0e-06 <= RTT <= 1000.0 seconds
 *  They allow us to pack our RTT estimates into a 1 byte fields
 */

// valid for rtt = 1.0e-06 to 1.0e+03
unsigned char QuantizeRtt(double rtt)
{
    if (rtt > RTT_MAX)
        rtt = RTT_MAX;
    else if (rtt < RTT_MIN)
        rtt = RTT_MIN;
    if (rtt < 3.3e-05)
        return ((unsigned char)ceil((rtt*RTT_MIN)) - 1);
    else
        return ((unsigned char)(ceil(255.0 - (13.0*log(RTT_MAX/rtt)))));
}  // end QuantizeRtt()




/***********************************************************************
 *  MdpMessagePool implementation
 */

MdpMessagePool::MdpMessagePool()
    : message_count(0), message_total(0),
      message_list(NULL)
{
}

MdpMessagePool::~MdpMessagePool()
{
    Destroy();
}

MdpError MdpMessagePool::Init(UInt32 count)
{
    //assert(!message_list);
    UInt32 i;
    for (i = 0; i < count; i++)
    {
        MdpMessage* theMsg = new MdpMessage;
        memset(theMsg, 0, sizeof(MdpMessage));
        if (theMsg)
        {
            if (message_list)
            {
                message_list->prev = theMsg;
            }
            else
            {
                theMsg->prev = NULL;;
            }
            theMsg->next = message_list;
            message_list = theMsg;
        }
        else
        {
            break;
        }
    }
    message_count = message_total = i;
    if (i != count)
    {
        Destroy();
        return MDP_ERROR_MEMORY;
    }
    else
    {
        return MDP_ERROR_NONE;
    }
}  // end MdpMessagePool::Init()

void MdpMessagePool::Destroy()
{
    //assert(message_count == message_total);
    MdpMessage* theMsg = message_list;
    while (theMsg)
    {
        MdpMessage* nextMsg = theMsg->next;
        delete theMsg;
        theMsg = nextMsg;
    }
    message_list = NULL;
    message_count = message_total = 0;
}  // end MdpMessagePool::Destroy()

MdpMessage *MdpMessagePool::Get()
{
    MdpMessage *theMsg = message_list;
    if (theMsg)
    {
        message_count--;
        message_list = theMsg->next;
        if (message_list)
        {
            message_list->prev = NULL;
        }
        theMsg->next =  NULL;
        theMsg->prev = NULL;
    }
    else
    {
        theMsg = new MdpMessage;
        memset(theMsg, 0, sizeof(MdpMessage));

        theMsg->prev = NULL;
        theMsg->next = NULL;
    }
    return theMsg;
}  // end MdpMessagePool::Get()

void MdpMessagePool::Put(MdpMessage *theMsg)
{
    assert(theMsg);
    //reset message contains
    memset(theMsg, 0, sizeof(MdpMessage));

    if (message_list)
    {
        message_list->prev = theMsg;
    }
    theMsg->prev = NULL;
    theMsg->next = message_list;
    message_list = theMsg;
    message_count++;
}  // end MdpMessagePool::Put()

/***************************************************************
 * Client statistics class implementations
 */

int MdpBlockStats::Pack(char *buffer)
{
    UInt32 temp_long = count;
    memcpy(buffer, &temp_long, sizeof(UInt32));
    int len = sizeof(UInt32);
    temp_long = lost_00;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = lost_05;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long =  lost_10;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = lost_20;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = lost_40;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = lost_50;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    return len;
}  // end MdpBlockStats::Pack()

int MdpBlockStats::Unpack(char *buffer)
{
      UInt32 temp_long;
      memcpy(&temp_long, buffer, sizeof(UInt32));
      count = temp_long;
      int len = sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_00 = temp_long;
      len += sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_05 = temp_long;
      len += sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_10 = temp_long;
      len += sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_20 = temp_long;
      len += sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_40 = temp_long;
      len += sizeof(UInt32);
      memcpy(&temp_long, &buffer[len], sizeof(UInt32));
      lost_50 = temp_long;
      len += sizeof(UInt32);
      return len;
}  // end MdpBlockStats::Unpack()


int MdpBufferStats::Pack(char *buffer)
{
    UInt32 temp_long = buf_total;
    memcpy(buffer, &temp_long, sizeof(UInt32));
    int len = sizeof(UInt32);
    temp_long = peak;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = overflow;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    return len;
}  // end MdpBufferStats::Pack()

int MdpBufferStats::Unpack(char *buffer)
{
    UInt32 temp_long;
    memcpy(&temp_long, buffer, sizeof(UInt32));
    buf_total = temp_long;
    int len = sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    peak = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    overflow = temp_long;
    len += sizeof(UInt32);
    return len;
}  // end MdpBufferStats::Unpack()

int MdpClientStats::Pack(char *buffer)
{
    UInt32 temp_long = duration;
    memcpy(buffer, &temp_long, sizeof(UInt32));
    int len = sizeof(UInt32);
    temp_long = success;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = active;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = fail;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = resync;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    len += blk_stat.Pack(&buffer[len]);
    temp_long = tx_rate;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = nack_cnt;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = supp_cnt;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    len += buf_stat.Pack(&buffer[len]);
    temp_long = goodput;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    temp_long = rx_rate;
    memcpy(&buffer[len], &temp_long, sizeof(UInt32));
    len += sizeof(UInt32);
    return len;
}  // end MdpClientStats::Pack()


int MdpClientStats::Unpack(char *buffer)
{
    UInt32 temp_long;
    memcpy(&temp_long, buffer, sizeof(UInt32));
    duration = temp_long;
    int len = sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    success = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    active = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    fail = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    resync = temp_long;
    len += sizeof(UInt32);
    len += blk_stat.Unpack(&buffer[len]);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    tx_rate = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    nack_cnt = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    supp_cnt = temp_long;
    len += sizeof(UInt32);
    len += buf_stat.Unpack(&buffer[len]);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    goodput = temp_long;
    len += sizeof(UInt32);
    memcpy(&temp_long, &buffer[len], sizeof(UInt32));
    rx_rate = temp_long;
    len += sizeof(UInt32);
    return len;
}  // end MdpClientStats::Unpack()
