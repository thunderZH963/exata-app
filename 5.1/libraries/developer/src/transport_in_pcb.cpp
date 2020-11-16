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

/*
 *
 * Ported from FreeBSD 2.2.2.
 * This file contains Internet PCB management routine.
 */

/*
 * Copyright (c) 1982, 1986, 1991, 1993, 1995
 *  The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *  This product includes software developed by the University of
 *  California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  @(#)in_pcb.c    8.2 (Berkeley) 1/4/94
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "transport_in_pcb.h"

static void insque(struct inpcb *, struct inpcb *);
static void remque(struct inpcb *);
static int fill_buf(struct inp_buf *, struct pending_buf *);

static void InpSendBufIncreasePosition(struct inp_buf *theBuf,
                                       UInt32 theIncrement, BufAction theAction, BOOL flag);
static UInt32 InpSendBufGetReadCount(struct inp_buf *theBuf);
static UInt32 InpSendBufGetWriteCount(struct inp_buf *theBuf);
static UInt32 InpSendBufGetLengthToEnd(struct inp_buf *theBuf,
                                       BufAction theAction);
static UInt32 InpSendBufGetReadLengthToEnd(struct inp_buf *theBuf);
static UInt32 InpSendBufGetWriteLengthToEnd(struct inp_buf *theBuf);
static void InpSendBufReadOffset(struct inp_buf *theBuf, unsigned char *theData,
                                 UInt32 theLength, UInt32 theOffset);
static void InpSendBufWrite(struct inp_buf *theBuf, unsigned char *theData,
                            UInt32 theLength);

#define TYPICAL_PACKET_SIZE 512
#define INITIAL_NUM_ENTRIES 16

// Info field copying function
static void CopyInfoField(
    Node* node,
    Message* srcMsg,
    infoField_buf* info_buf)
{
    unsigned int i;

    infofield_array* dstMsg = new infofield_array();

    // Copy the info field content.
    MessageInfoHeader* scrHdrPtr = NULL;
    MessageInfoHeader infoHdr;
    BOOL insertInfo = FALSE;

    for (i = 0; i <  srcMsg->infoArray.size(); i++)
    {
        scrHdrPtr = &(srcMsg->infoArray[i]);

        infoHdr.infoSize = 0;
        infoHdr.infoType = INFO_TYPE_UNDEFINED;
        infoHdr.info = NULL;
        insertInfo = TRUE;

        if (i != 0 ||
            scrHdrPtr->infoSize > SMALL_INFO_SPACE_SIZE)
        {

            infoHdr.info = MESSAGE_InfoFieldAlloc(
                               node,
                               scrHdrPtr->infoSize);
            ERROR_Assert(infoHdr.info != NULL,
                         "Out of memory");
        }
        else
        {
            infoHdr.info = (char*)&(dstMsg->smallInfoSpace[0]);
        }

        memcpy(infoHdr.info,
               scrHdrPtr->info,
               scrHdrPtr->infoSize);
        infoHdr.infoType = scrHdrPtr->infoType;
        infoHdr.infoSize = scrHdrPtr->infoSize;

        dstMsg->infoArray.push_back(infoHdr);
        insertInfo = FALSE;

    }

    dstMsg->packetSize = MESSAGE_ReturnActualPacketSize(srcMsg) +
        MESSAGE_ReturnVirtualPacketSize(srcMsg);;
    dstMsg->virtualSize = MESSAGE_ReturnVirtualPacketSize(srcMsg);
    dstMsg->remPktSize = MESSAGE_ReturnActualPacketSize(srcMsg) +
                         MESSAGE_ReturnVirtualPacketSize(srcMsg);
    dstMsg->msgSeqNum = srcMsg->sequenceNumber;
    dstMsg->fragId = 0;
    dstMsg->retransSize = 0;
    dstMsg->retransmission = FALSE;
    dstMsg->isInfoFieldSent = FALSE;
    info_buf->info.push_back(dstMsg);

}

/*
 * Insert a pcb into the head of a queue.
 */
static void
insque(struct inpcb *inp, struct inpcb *head)
{
    struct inpcb *next;

    next = head->inp_next;
    head->inp_next = inp;
    inp->inp_next = next;
    inp->inp_prev = head;
    if (next != head) next->inp_prev = inp;
}

/*
 * Remove a pcb from a queue.
 */
static void
remque(struct inpcb *inp)
{
    struct inpcb *prev, *next;

    prev = inp->inp_prev;
    next = inp->inp_next;
    next->inp_prev = prev;
    prev->inp_next = next;
}

static void
add_send_buf_entry(
    struct inp_buf *buf,
    int dataSize,
    int dataType)
{
    int numEntries;

    if (dataSize <= 0) {
        return;
    }

    numEntries = buf->numEntries;

    if (numEntries == buf->maxEntries) {
        struct inp_buf_entry *newEntries;
        int index;

        newEntries = (struct inp_buf_entry *)
                     MEM_malloc(sizeof (struct inp_buf_entry)
                                * (numEntries + INITIAL_NUM_ENTRIES));

        index = buf->maxEntries - buf->headIndex;

        memcpy(newEntries, &buf->entries[buf->headIndex],
               sizeof(struct inp_buf_entry) * index);

        memcpy(&newEntries[index], buf->entries,
               sizeof(struct inp_buf_entry) * (buf->maxEntries - index));

        MEM_free(buf->entries);

        buf->tailIndex = buf->maxEntries-1;
        buf->headIndex = 0;

        buf->entries = newEntries;
        buf->maxEntries += INITIAL_NUM_ENTRIES;
    }

    assert((buf->tailIndex >= 0) &&
           (buf->tailIndex < buf->maxEntries));

    if (numEntries == 0) {
        buf->tailIndex++;
        if (buf->tailIndex == buf->maxEntries) {
            buf->tailIndex = 0;
        }

        buf->entries[buf->tailIndex].start_char = 0;
        buf->entries[buf->tailIndex].end_char = dataSize;
        buf->entries[buf->tailIndex].dataType = dataType;

        buf->numEntries++;
    }
    else {
        int index = buf->tailIndex;

        if (buf->entries[index].dataType == dataType) {
            buf->entries[index].end_char += dataSize;
        }
        else {
            buf->tailIndex++;
            if (buf->tailIndex == buf->maxEntries) {
                buf->tailIndex = 0;
            }
            index = (buf->tailIndex + (buf->maxEntries - 1)) % buf->maxEntries;

            buf->entries[buf->tailIndex].start_char =
                buf->entries[index].end_char;

            buf->entries[buf->tailIndex].end_char =
                buf->entries[buf->tailIndex].start_char + dataSize;

            buf->entries[buf->tailIndex].dataType = dataType;

            buf->numEntries++;
        }
    }
}


static void
modify_send_buf_entries(
    struct inp_buf *buf,
    Int32 actualLengthToCopy,
    Int32 virtualLengthToCopy)
{
    add_send_buf_entry(buf, actualLengthToCopy, INPCB_DATATYPE_ACTUAL);
    add_send_buf_entry(buf, virtualLengthToCopy, INPCB_DATATYPE_VIRTUAL);
}


static void
assign_actual_virtual_data_sizes(
    struct inp_buf *buf,
    int *actualLength,
    int *virtualLength,
    int len,
    int off)
{
    int i = buf->headIndex;
    int remainingLen = len;
    int offset = off;

    *actualLength = 0;
    *virtualLength = 0;

    while (remainingLen)
    {
        if (buf->entries[i].end_char > offset)
        {
            int availableLen = MIN(remainingLen,
                                   buf->entries[i].end_char - offset);

            ERROR_Assert(buf->entries[i].start_char <= offset,
                         "TCP Send Buffer is Corrupted");

            if (buf->entries[i].dataType == INPCB_DATATYPE_ACTUAL)
            {
                *actualLength += *virtualLength + availableLen;
                *virtualLength = 0;
            }
            else
            {
                *virtualLength += availableLen;
            }

            remainingLen -= availableLen;
            offset += availableLen;
        }

        i = (i + 1) % buf->maxEntries;
    }
}


char *
prepare_outgoing_packet(
    Node *node,
    Message *msg,
    struct inp_buf *buf,
    int len,
    int hdrlen,
    int off)
{
    char *tcpseg;
    int actualLength,
    virtualLength;

    assign_actual_virtual_data_sizes(
        buf,
        &actualLength,
        &virtualLength,
        len,
        off);

    ERROR_Assert(actualLength + virtualLength == len,
                 "Virtual Payload Memory Error.");
    MESSAGE_PacketAlloc(node, msg, hdrlen + actualLength, TRACE_TCP);
    MESSAGE_AddVirtualPayload(node, msg, virtualLength);

    tcpseg = MESSAGE_ReturnPacket(msg);
    assert(tcpseg != NULL);

    if (actualLength) {
        InpSendBufReadOffset(buf, (unsigned char *)(tcpseg + hdrlen),
                             actualLength, off);
    }

    return tcpseg;
}


/*
 * Add length of data pointed to by content to buf.
 */
static int
fill_buf(struct inp_buf *buf, struct pending_buf *blocked_pkt)
{
    int lengthAdded,
    lengthInPending;

    lengthInPending = blocked_pkt->hiwat + blocked_pkt->virtualLength
                      - blocked_pkt->cc;

    if (lengthInPending <= 0) {
        return 0;
    }

    lengthAdded = (int)InpSendBufGetCount(buf, BUF_WRITE); // Maximum possible
    if (lengthInPending <= lengthAdded) {
        lengthAdded = lengthInPending;  /* actual length of bytes to add */
    }

    if (lengthAdded > 0) {
        int actualLengthInPending,
        actualLengthToCopy,
        virtualLengthToCopy;

        actualLengthInPending
        = MAX (0, lengthInPending - blocked_pkt->virtualLength);

        actualLengthToCopy = MIN(actualLengthInPending, lengthAdded);
        virtualLengthToCopy = lengthAdded - actualLengthToCopy;

        if (actualLengthToCopy > 0) {
            unsigned char *content;

            content = blocked_pkt->buffer + blocked_pkt->cc;

            /* add len bytes to buffer */
            InpSendBufWrite(buf, content, actualLengthToCopy);
        }

        if (lengthAdded > 0) {
            InpSendBufIncreasePosition(buf, lengthAdded, BUF_WRITE, FALSE);
        }
        modify_send_buf_entries(buf, actualLengthToCopy, virtualLengthToCopy);
    }

    blocked_pkt->cc += lengthAdded;

    return lengthAdded;
}

/*
 * Allocate a pcb and insert it into a queue.
 */
struct inpcb *
            in_pcballoc(struct inpcb *head, int snd_bufsize, int rcv_bufsize)
{
    struct inpcb *inp;

    inp = (struct inpcb *)MEM_malloc(sizeof(struct inpcb));
    assert(inp != NULL);

    memset((char *)inp, 0, sizeof(struct inpcb));
    inp->inp_head = (struct inpcb *) head;
    inp->info_buf = new infoField_buf;
    inp->info_buf->pktSentSize = 0;
    inp->info_buf->tcpSeqNum = 0;
    inp->info_buf->pktAcked = 0;
    inp->info_buf->initTcpSeqNum = 0;
    inp->info_buf->setTcpSeqNum = FALSE;
    inp->info_buf->pktSizeRemovedFromBuffer = 0;
    inp->ttl = IPDEFTTL;
    if (snd_bufsize > 0){
        inp->inp_snd.buffer = (unsigned char *) MEM_malloc(snd_bufsize);
        assert(inp->inp_snd.buffer != NULL);

    }

    inp->inp_snd.headIndex = 1;

    if (snd_bufsize > TYPICAL_PACKET_SIZE)
    {
        inp->inp_snd.entries =
            (struct inp_buf_entry *)
            MEM_malloc(sizeof (struct inp_buf_entry)
                       * (int) (snd_bufsize / TYPICAL_PACKET_SIZE));
        inp->inp_snd.maxEntries = (int) (snd_bufsize / TYPICAL_PACKET_SIZE);
    }
    else if (snd_bufsize > 0)
    {
        //Allocate atleast one
        inp->inp_snd.entries =
            (struct inp_buf_entry *)
            MEM_malloc(sizeof (struct inp_buf_entry));
        inp->inp_snd.maxEntries = 1;
    }
    else
    {
        inp->inp_snd.entries = NULL;
        inp->inp_snd.maxEntries = 0;
    }

    inp->inp_rcv_hiwat = rcv_bufsize;
    inp->inp_snd.hiwat = snd_bufsize;

    inp->inp_snd.start = 0;
    inp->inp_snd.end = 0;
    inp->inp_snd.wrap = BUF_NOWRAP;

    inp->remote_unique_id = -1;
    insque(inp, head);
    return inp;
}

/*
 * Remove a pcb and delete it.
 */
void
in_pcbdetach(struct inpcb *inp)
{
    remque(inp);
    if (inp->inp_snd.buffer)
    {
        MEM_free(inp->inp_snd.buffer);
    }
    if (inp->inp_snd.entries)
    {
        MEM_free(inp->inp_snd.entries);
    }
    if (inp->blocked_pkt.buffer)
    {
        MEM_free(inp->blocked_pkt.buffer);
    }
    delete inp->info_buf;
    MEM_free(inp);
}

/*
 * Look for a pcb in a queue using 4-tuple.
 */
struct inpcb *
            in_pcblookup(struct inpcb *head, Address* local_addr, short local_port,
                         Address* remote_addr, short remote_port, int flag)
{
    struct inpcb *inp;

    for (inp = head->inp_next; inp != head; inp = inp->inp_next) {
        if (inp->inp_local_port != local_port) continue;
        if (!Address_IsSameAddress(&inp->inp_local_addr, local_addr)) continue;
        if (inp->inp_remote_port == -1
                && Address_IsAnyAddress(&inp->inp_remote_addr)
                && flag == INPCB_WILDCARD)
            return inp;
        if (inp->inp_remote_port != remote_port) continue;
        if (!Address_IsSameAddress(&inp->inp_remote_addr, remote_addr)) continue;
        break;
    }
    return inp;
}

/*
 * Search a pcb in a queue using connection id.
 */
struct inpcb *
            in_pcbsearch(struct inpcb *head, int con_id)
{
    struct inpcb *inp;

    for (inp = head->inp_next; inp != head; inp = inp->inp_next) {
        if (inp->con_id != con_id) continue;
        break;
    }
    return inp;
}

int
get_block_pkt_count(struct inpcb *inp)
{
    return (inp->blocked_pkt.hiwat + inp->blocked_pkt.virtualLength
            - inp->blocked_pkt.cc);
}
/*
 * Try to add data from application to send buffer.
 * If the buffer is full, record the pointer to the
 * data in pending buffer.
 */
int
append_buf(Node *node, struct inpcb *inp, unsigned char *payload,
           int actualLength, int virtualLength, Message* origMsg)

{
    int len, length;
    Message *msg;
    TransportToAppDataSent *dataSent;

    if (payload != NULL) {
        /* new data from the application */
        if (inp->blocked_pkt.hiwat != 0){
            /* there's a pending packet, can't send this one */
            msg = MESSAGE_Alloc(node, APP_LAYER,
                                inp->app_proto_type,
                                MSG_APP_FromTransDataSent);
            MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppDataSent));
            dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);
            dataSent->connectionId = inp->con_id;
            dataSent->length = 0;

            MESSAGE_Send(node, msg, TRANSPORT_DELAY);
            return 0;
        }
        if (actualLength > (signed)inp->blocked_pkt.bufCapacity) {
            if (inp->blocked_pkt.buffer) {
                MEM_free(inp->blocked_pkt.buffer);
            }

            inp->blocked_pkt.buffer = (unsigned char *)
                                      MEM_malloc(actualLength);

            inp->blocked_pkt.bufCapacity = actualLength;
        }

        memcpy(inp->blocked_pkt.buffer, payload, actualLength);
        inp->blocked_pkt.hiwat = actualLength;
        inp->blocked_pkt.virtualLength = virtualLength;
        inp->blocked_pkt.cc = 0;
    }

    if (inp->blocked_pkt.hiwat == 0 &&
            inp->blocked_pkt.virtualLength <= 0) {
        return 0;
    }

    // save the attached info field
    if (origMsg != NULL)
    {
        inp->info_buf->connId = inp->con_id;
        CopyInfoField(node, origMsg, inp->info_buf);
    }

    /* move data from the blocked packet buffer to the send buffer */
    length = inp->blocked_pkt.hiwat + inp->blocked_pkt.virtualLength
             - inp->blocked_pkt.cc;
    len = fill_buf(&(inp->inp_snd), &(inp->blocked_pkt));
    if (len == length){
        /*
         * The pending packet has been moved to the send buffer.
         * notify the sender
         */
        msg = MESSAGE_Alloc(node, APP_LAYER,
                            inp->app_proto_type, MSG_APP_FromTransDataSent);
        MESSAGE_InfoAlloc(node, msg, sizeof(TransportToAppDataSent));
        dataSent = (TransportToAppDataSent *) MESSAGE_ReturnInfo(msg);
        dataSent->connectionId = inp->con_id;
        dataSent->length = inp->blocked_pkt.hiwat
                           + inp->blocked_pkt.virtualLength;
        MESSAGE_Send(node, msg, TRANSPORT_DELAY);
        inp->blocked_pkt.cc = 0;
        inp->blocked_pkt.hiwat = 0;
        inp->blocked_pkt.virtualLength = 0;
    }
    return len;
}

/*
 * Delete length bytes of data from a buffer.
 */
void
del_buf(Node *node, struct inpcb *inp, int length,  int ack)
{
    unsigned int i = 0;
    int entriesToRemove = 0;
    struct inp_buf_entry *entries = inp->inp_snd.entries;

    if (length == 0) return;

    ERROR_Assert(length <= (int)InpSendBufGetCount(&inp->inp_snd, BUF_READ),
                 "del_buf: deleting more than buffer count");

    for (i = 0; i < (unsigned int)inp->inp_snd.numEntries; i++) {
        int index = (inp->inp_snd.headIndex + i) % inp->inp_snd.maxEntries;

        entries[index].start_char = MAX(0, entries[index].start_char - length);
        entries[index].end_char -= length;

        if (entries[index].end_char <= 0) {
            entriesToRemove++;
        }
    }

    if (entriesToRemove) {
        inp->inp_snd.headIndex =
            (inp->inp_snd.headIndex + entriesToRemove)
            % inp->inp_snd.maxEntries;
        inp->inp_snd.numEntries -= entriesToRemove;
    }

    /* delete length bytes from buffer */
    if (length > 0) {
        InpSendBufIncreasePosition(&inp->inp_snd,
                                   (UInt32)length, BUF_READ, TRUE);
    }
    (void)append_buf(node, inp, NULL, 0, 0, NULL);


    // get rid of the info Buffer information.
    // Length = bytes we have already acked.
    //inp->info_buf->pktAcked += length;
    std::list<infofield_array*>::iterator iter;
    for (iter = inp->info_buf->info.begin();
         iter != inp->info_buf->info.end();
         )
    {
        infofield_array* hdrPtr = *iter;
        if (inp->info_buf->initTcpSeqNum + hdrPtr->packetSize < (UInt32)ack)
        {
            inp->info_buf->pktSizeRemovedFromBuffer += hdrPtr->packetSize;

            // Add the  bytes being removed to the sequence number.
            inp->info_buf->initTcpSeqNum += hdrPtr->packetSize;

            for (unsigned int j = 0; j < hdrPtr->infoArray.size(); j++)
            {
                MessageInfoHeader* infoHdr = &(hdrPtr->infoArray[j]);
                if (infoHdr->infoSize > 0)
                {
                    MESSAGE_InfoFieldFree(node, infoHdr);
                    infoHdr->infoSize = 0;
                    infoHdr->info = NULL;
                    infoHdr->infoType = INFO_TYPE_UNDEFINED;
                }
            }
            hdrPtr->infoArray.clear();
            delete hdrPtr;
            inp->info_buf->info.erase(iter);
            iter = inp->info_buf->info.begin();
        }
        /*if ((length + inp->info_buf->tcpSeqNum == ack ||
             inp->info_buf->tcpSeqNum == ack) &&
            inp->info_buf->info.at(i)->remPktSize == 0)
        {

            for (int j = 0; j < hdrPtr->infoArray.size(); j++)
            {
                MessageInfoHeader* infoHdr = &(hdrPtr->infoArray[j]);
                if (infoHdr->infoSize > 0)
                {
                    MESSAGE_InfoFieldFree(node, infoHdr);
                    infoHdr->infoSize = 0;
                    infoHdr->info = NULL;
                    infoHdr->infoType = INFO_TYPE_UNDEFINED;
                }
            }
            hdrPtr->infoArray.clear();
            delete hdrPtr;
            inp->info_buf->pktAcked = ack;

        }
        else if ((inp->info_buf->pktAcked + hdrPtr->packetSize + hdrPtr->virtualSize) < ack)
        {
            //inp->info_buf->pktAcked += hdrPtr->packetSize + hdrPtr->virtualSize;
            //infofield_array* hdrPtr = inp->info_buf->info[i];
            //int ackedCount = inp->info_buf->pktAcked + hdrPtr->packetSize + hdrPtr->virtualSize;
            // We are ahead of the ack packets. So delete the once already acked.
            //if (ackedCount < ack)
            //{
                // so delete this info field.
                for (int j = 0; j < hdrPtr->infoArray.size(); j++)
                {
                    MessageInfoHeader* infoHdr = &(hdrPtr->infoArray[j]);
                    if (infoHdr->infoSize > 0)
                    {
                        MESSAGE_InfoFieldFree(node, infoHdr);
                        infoHdr->infoSize = 0;
                        infoHdr->info = NULL;
                        infoHdr->infoType = INFO_TYPE_UNDEFINED;
                    }
                }
                hdrPtr->infoArray.clear();
                delete hdrPtr;
            //}
            // update the pktAcked field;


        }*/
        else
        {
            break;
        }
    }
   /* inp->info_buf->info.erase(inp->info_buf->info.begin(),
                              inp->info_buf->info.begin() + iter);
    //break;*/
}


/* Imlementation of a circular buffer for use with the struct inp_buf
 *
 * The relevant variables for the send buffer are:
 *      start - the start position for the read
 *      end   - the start position for the write
 *      wrap  - the action which caused the read or write positions wrap
 *      hiwat - high watermark, size of buffer
 *      buffer- data content of buffer
 */

/* Increment read or write position */
static
void InpSendBufIncreasePosition(struct inp_buf *theBuf,
                                UInt32 theIncrement, BufAction theAction, BOOL flag)
{
    UInt32 aLengthToEnd;
    UInt32 *aPositionPtr;

    ERROR_Assert(theIncrement > 0 && theIncrement <= theBuf->hiwat,
                 "InpSendBufIncreasePosition: increment out of bounds");
    ERROR_Assert(theIncrement <= InpSendBufGetCount(theBuf, theAction),
                 "InpSendBufIncreasePosition: increment larger than available space");

    aPositionPtr = &theBuf->end;
    if (theAction == BUF_READ) {
        aPositionPtr = &theBuf->start;
    }

    aLengthToEnd = InpSendBufGetLengthToEnd(theBuf, theAction);
    if (theIncrement < aLengthToEnd) {
        if (theAction == BUF_READ && flag) {
            memset(theBuf->buffer + *aPositionPtr, 0, theIncrement);
        }

        *aPositionPtr += theIncrement;
    }
    else {
        if (theAction == BUF_READ && flag) {
            memset(theBuf->buffer + *aPositionPtr, 0, aLengthToEnd);
            memset(theBuf->buffer, 0, theIncrement - aLengthToEnd);
        }

        *aPositionPtr = theIncrement - aLengthToEnd;
    }

    if (theBuf->start == theBuf->end) {
        theBuf->wrap = BUF_WRITEWRAP;
        if (theAction == BUF_READ) {
            theBuf->wrap = BUF_READWRAP;
        }
    }
    else {
        theBuf->wrap = BUF_NOWRAP;
    }
}


/* Get count of characters that can be read or written */
UInt32 InpSendBufGetCount(struct inp_buf *theBuf, BufAction theAction)
{
    UInt32 aCount = 0;
    UInt32 aReadPosition  = theBuf->start;
    UInt32 aWritePosition = theBuf->end;

    // get the write count
    if (aWritePosition == aReadPosition) {
        aCount = theBuf->hiwat;
        if (theBuf->wrap == BUF_WRITEWRAP) {
            aCount = 0;
        }
    }
    else if (aWritePosition > aReadPosition ) {
        aCount = (theBuf->hiwat - aWritePosition) + aReadPosition;
    }
    else {
        aCount = aReadPosition - aWritePosition;
    }

    // get read count is required
    if (theAction == BUF_READ) {
        if (theBuf->wrap == BUF_READWRAP ) {
            aCount = 0;
        }
        else {
            aCount = theBuf->hiwat - aCount;
        }
    }

    return aCount;
}


/* Get count of characters that can be read */
static
UInt32 InpSendBufGetReadCount(struct inp_buf *theBuf)
{
    return InpSendBufGetCount(theBuf, BUF_READ);
}

/* Get count of characters that can be written */
static
UInt32 InpSendBufGetWriteCount(struct inp_buf *theBuf)
{
    return InpSendBufGetCount(theBuf, BUF_WRITE);
}


/* Get count of characters till high watermark */
static
UInt32 InpSendBufGetLengthToEnd(struct inp_buf *theBuf,
                                BufAction theAction)
{
    if (theAction == BUF_READ) {
        return theBuf->hiwat - theBuf->start;
    }
    else {
        return theBuf->hiwat - theBuf->end;
    }
}


static
UInt32 InpSendBufGetReadLengthToEnd(struct inp_buf *theBuf)
{
    return theBuf->hiwat - theBuf->start;
}


static
UInt32 InpSendBufGetWriteLengthToEnd(struct inp_buf *theBuf)
{
    return theBuf->hiwat - theBuf->end;
}


/* Read a given length from buffer*/
void InpSendBufRead(struct inp_buf *theBuf,
                    unsigned char *theData, UInt32 theLength)
{
    UInt32 aLengthToEnd, aBalanceLength;

    ERROR_Assert(theLength > 0 || theLength <= theBuf->hiwat,
                 "InpSendBufRead: read length out of bounds");
    ERROR_Assert(theLength <= InpSendBufGetCount(theBuf, BUF_READ),
                 "InpSendBufRead: read length larger than content");

    aLengthToEnd = InpSendBufGetReadLengthToEnd(theBuf);
    if (theLength <= aLengthToEnd) {
        memcpy(theData, theBuf->buffer + theBuf->start, theLength);
    }
    else {
        if (aLengthToEnd > 0) {
            memcpy(theData, theBuf->buffer + theBuf->start, aLengthToEnd);
        }

        aBalanceLength = theLength - aLengthToEnd;
        if (aBalanceLength > 0) {
            memcpy(theData + aLengthToEnd, theBuf->buffer, aBalanceLength);
        }
    }
}


/* Read a given length from buffer starting from the offset */
static
void InpSendBufReadOffset(struct inp_buf *theBuf, unsigned char *theData,
                          UInt32 theLength, UInt32 theOffset)
{
    UInt32 aReadPosition = theBuf->start;
    BufWrap aWrap = theBuf->wrap;

    ERROR_Assert(theLength > 0 && theLength <= theBuf->hiwat,
                 "InpSendBufReadOffset: read length out of bounds");
    ERROR_Assert(theOffset + theLength <= InpSendBufGetCount(theBuf, BUF_READ),
                 "InpSendBufReadOffset: read length larger than content");

    if (theOffset > 0) {
        InpSendBufIncreasePosition(theBuf, theOffset, BUF_READ, FALSE);
    }
    InpSendBufRead(theBuf, theData, theLength);

    theBuf->start = aReadPosition;
    theBuf->wrap = aWrap;
}


/* Write a given length to buffer */
static
void InpSendBufWrite(struct inp_buf *theBuf,
                     unsigned char *theData, UInt32 theLength)
{
    UInt32 aLengthToEnd, aBalanceLength;

    ERROR_Assert(theLength > 0 || theLength <= theBuf->hiwat,
                 "InpSendBufWrite: write length out of bounds");
    ERROR_Assert(theLength <= InpSendBufGetCount(theBuf, BUF_WRITE),
                 "InpSendBufWrite: write length larger than available space");

    aLengthToEnd = InpSendBufGetWriteLengthToEnd(theBuf);
    if (theLength <= aLengthToEnd) {
        memcpy(theBuf->buffer + theBuf->end, theData, theLength);
    }
    else {
        if (aLengthToEnd > 0) {
            memcpy(theBuf->buffer + theBuf->end, theData, aLengthToEnd);
        }

        aBalanceLength = theLength - aLengthToEnd;
        if (aBalanceLength > 0) {
            memcpy(theBuf->buffer, theData + aLengthToEnd, aBalanceLength);
        }
    }
}


/* Get max size */
UInt32 InpSendBufGetSize(struct inp_buf *theBuf)
{
    return theBuf->hiwat;
}

