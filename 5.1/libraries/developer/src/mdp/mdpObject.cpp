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


#include "mdpObject.h"
#include "mdpSession.h"
#include "app_util.h"
#include <fcntl.h>

#ifdef MDP_FOR_UNIX
#include <unistd.h>
#endif
#ifdef MDP_FOR_WINDOWS
#include <windows.h>
#endif


// MdpVectorPool routines
MdpVectorPool::MdpVectorPool()
    : vector_size(0), vector_count_actual(0), vector_count(0),
      vector_total(0), vector_list(NULL),
      peak_usage(0), overrun_count(0), overrun_flag(0)
{
}

MdpVectorPool::~MdpVectorPool()
{
    Destroy();
}  // end MdpVectorPool::~MdpVectorPool()

// Allocate data vectors and link them (minimum vector size
UInt32 MdpVectorPool::Init(UInt32 count, UInt32 size)
{
    Destroy();
    if (size < sizeof(char *)) size = sizeof(char *);
    vector_size = size;
    char *prev = NULL;

    char *ptr = (char *) calloc(size, sizeof(char));
    if (ptr)
    {
        *((char **)ptr) = prev;
        prev = ptr;
    }
    else
    {
        return 0;
    }

    vector_list = prev;
    vector_count_actual++;
    // tracking the vectorpool by assuming the complete pool allocation
    vector_total = vector_count = count;
    return count;
}  // end MdpVectorPool::Init()

void MdpVectorPool::Destroy()
{

    char *vector = vector_list;
    while (vector)
    {
        vector_list = *((char **)vector);
        free (vector);
        vector_total--;
        vector = vector_list;
    }
    vector_total = vector_count = vector_size = 0;
    vector_count_actual = 0;
}  // end MdpVectorPool::Destroy()


char *MdpVectorPool::Get()
{
    char *vector = vector_list;
    if (vector)
    {
        vector_list = *((char **)vector);
        vector_count--;
        vector_count_actual--;
        overrun_flag = 0;
        UInt32 usage = vector_total - vector_count;
        if (usage > peak_usage) peak_usage = usage;
        memset(vector, 0, vector_size);
    }
    else
    {
        if (vector_count_actual <= vector_total
            && (vector_count > 0 && vector_count < vector_total))
        {
            char* newVector = (char *) calloc(vector_size, sizeof(char));

            if (!newVector)
            {
                return NULL;
            }

            vector_count--;
            overrun_flag = 0;
            UInt32 usage = vector_total - vector_count;
            if (usage > peak_usage) peak_usage = usage;
            memset(newVector, 0, vector_size);
            return newVector;
        }
        else
        {
            if (!overrun_flag) overrun_count++;
            overrun_flag = 1;
            if (MDP_DEBUG)
            {
                printf("mdp: VectorPool has been exhausted!\n");
            }
        }
    }
    return vector;
}  // end MdpVectorPool::Get()

void MdpVectorPool::Put(char *vector)
{
    ASSERT(vector);
    memset(vector, 0, sizeof(char *));  // validity of pointer is tested

    *((char **)vector) = vector_list;
    vector_list = vector;
    vector_count++;
    vector_count_actual++;
}  // end MdpVectorPool::Put()


bool MdpVectorPool::IsVectorExist()
{
    if (vector_count <=0)
    {
        if (!overrun_flag) overrun_count++;
        overrun_flag = 1;
        return false;
    }
    return true;
}

void MdpVectorPool::IncreaseVectorCountUsage()
{
    vector_count--;
    overrun_flag = 0;
    UInt32 usage = vector_total - vector_count;
    if (usage > peak_usage) peak_usage = usage;
}

void MdpVectorPool::DecreaseVectorCountUsage()
{
    vector_count++;
}



/**************************************************************************
 * MdpBlock implementation
 */

MdpBlock::MdpBlock()
{
    id = 0;
    dVec = NULL;
    dVecSizeArray = NULL;
    erasure_count = 0;
    parity_count = 0;
    parity_offset = 0;
    status = 0;
}

MdpBlock::~MdpBlock()
{
    Destroy();
}  // end MdpBlock::~MdpBlock()

bool MdpBlock::Init(int blockSize)
{
    Destroy();
    dVec = new char *[blockSize];
    if (!dVec) return false;
    memset(dVec, 0, blockSize*sizeof(char *));
    block_size = (unsigned char)blockSize;

    dVecSizeArray = (short*) MEM_malloc(blockSize * sizeof(short));
    // keeping -1 for representing no vector
    int i = 0;
    for (; i < blockSize; i++)
    {
        dVecSizeArray[i] = -1;
    }
    // Init vector_mask
    int error = 0;
    if (!vector_mask.Init(blockSize)) error++;
    if (!repair_mask.Init(blockSize)) error++;
    if (error)
    {
        Destroy();
        return false;
    }
    else
    {
        return true;
    }
}  // end MdpBlock::Init()

void MdpBlock::Destroy()
{
    if (dVec)
    {
        delete []dVec;
        dVec = NULL;
        MEM_free(dVecSizeArray);
        vector_mask.Destroy();
        repair_mask.Destroy();
    }
}  // end MdpBlock::Destroy()

bool MdpBlock::Fill(MdpVectorPool* pool, int numVectors)
{
    ASSERT(numVectors <= block_size);
    for (int i = 0; i < numVectors; i++)
    {
        if (!dVec[i])
        {
            dVec[i] = pool->Get();
            if (!dVec[i])
            {
                if (MDP_DEBUG)
                {
                    printf("MdpBlock::Fill() Error getting vector from pool\n");
                }
                return false;
            }
        }
    }
    return true;
}  // end MdpBlock::Fill()

bool MdpBlock::FillZero(MdpVectorPool* pool, int vectorSize, int numVectors)
{
    ASSERT(numVectors <= block_size);
    for (int i = 0; i < numVectors; i++)
    {
        if (!dVec[i])
        {
            dVec[i] = pool->Get();
            if (!dVec[i])
            {
                if (MDP_DEBUG)
                {
                    printf("MdpBlock::FillZero() Error getting vector from pool\n");
                }
                return false;
            }
            vector_mask.Set(i);  // mark erasures
            memset(dVec[i], 0, vectorSize);
        }
    }
    return true;
}  // end MdpBlock::Fill()

void MdpBlock::Empty(MdpVectorPool *pool)
{
    for (int i = 0; i < block_size; i++)
    {
        if (dVec[i])
        {
            pool->Put(dVec[i]);
            dVec[i] = NULL;
        }
        dVecSizeArray[i] = -1;
    }
}  // end MdpBlock::Empty()

void MdpBlock::ResetVectorSizeArray()
{
    for (int i = 0; i < block_size; i++)
    {
        dVecSizeArray[i] = -1;
    }
}

// MdpBlockPool implementation
MdpBlockPool::MdpBlockPool()
    : block_count_actual(0), block_count(0), block_total(0),block_list(NULL),
      peak_usage(0), overrun_count(0), overrun_flag(0)
{

}

MdpBlockPool::~MdpBlockPool()
{
    //if (NULL != block_list) Destroy();
}

UInt32  MdpBlockPool::Init(UInt32 blockCount, int blockSize)
{
    ASSERT(!block_total);
    ASSERT(!block_list);
    block_size = blockSize;

    MdpBlock *block = new MdpBlock;
    if (!block->Init(blockSize))
    {
        delete block;
        return 0;
    }
    if (block_list)
    {
        block_list->prev = block;
    }

    block->prev = NULL;;
    block->next = block_list;
    block_list = block;

    block_count_actual++;
    // tracking the blockpool by assuming the complete block allocation
    block_count = block_total = blockCount;
    return blockCount;
}  // end MdpBlockPool::Init()

void MdpBlockPool::Destroy()
{

    MdpBlock *block = block_list;
    while (block)
    {
        block_list = block_list->next;
        delete block;
        block = block_list;
    }
    block_list = NULL;
    block_total = 0;
    block_count = 0;
    block_count_actual = 0;
}  // end MdpBlockPool::Destroy()

MdpBlock* MdpBlockPool::Get()
{
    ASSERT(block_total);
    MdpBlock *block = block_list;
    if (block)
    {
        block_list = block_list->next;
        block_count--;
        block_count_actual --;
        if (block_list)
        {
            block_list->prev = NULL;
        }
        block->next =  NULL;
        block->prev = NULL;

        block->ResetVectorSizeArray();
        block->ClearMask();
        block->ClearRepairMask();

        overrun_flag = 0;
        UInt32 usage = block_total - block_count;
        if (usage > peak_usage) peak_usage = usage;
    }
    else
    {
        if ((UInt32)block_count_actual < block_total
            && (block_count > 0 && block_count < block_total))
        {
            block = new MdpBlock;
            if (!block->Init(block_size))
            {
                delete block;
                return NULL;
            }
            block->prev = NULL;;
            block->next = NULL;

            block_count--;
            overrun_flag = 0;
            UInt32 usage = block_total - block_count;
            if (usage > peak_usage) peak_usage = usage;
        }
        else
        {
            if (!overrun_flag) overrun_count++;
            overrun_flag = 1;
        }
    }
    return block;
}  // end MdpBlockPool::Get()

void MdpBlockPool::Put(MdpBlock *block)
{
    ASSERT(block_total);
    ASSERT(block_count <= block_total);
    ASSERT(block);
    if (block_list)
    {
        block_list->prev = block;
    }

    block->prev = NULL;;
    block->next = block_list;
    block_list = block;
    block_count++;
    block_count_actual ++;
}  // end MdpBlockPool::Put()


MdpBlockBuffer::MdpBlockBuffer()
    : head(NULL), tail(NULL), block_count(0),
      index_len(0), index(NULL)
{
}

MdpBlockBuffer::~MdpBlockBuffer()
{
    Destroy();
};

bool MdpBlockBuffer::Index(UInt32 max_blocks)
{
    ASSERT(max_blocks >= block_count);
    ASSERT(!index);
    //if (index) {delete [] index; index_len = 0;}
    index = new MdpBlock*[max_blocks];
    if (!index) return false;
    memset(index, 0, max_blocks * sizeof(MdpBlock*));
    index_len = max_blocks;
    if (block_count)
    {
        MdpBlock *nextBlock = head;
        while (nextBlock)
        {
            ASSERT(nextBlock->id < index_len);
            ASSERT(!index[nextBlock->id]);  // make sure there's no collision
            index[nextBlock->id] = nextBlock;
            nextBlock = nextBlock->next;
        }
    }
    return true;
}  // end MdpBlockBuffer::Index()

void MdpBlockBuffer::Empty(MdpBlockPool *bpool, MdpVectorPool *vpool)
{
    MdpBlock *next = head;
    while (next)
    {
        Remove(next);
        next->Empty(vpool);
        bpool->Put(next);
        next = head;
    }
}  // end MdpBlockBuffer::Empty()

void MdpBlockBuffer::Destroy()
{
    ASSERT(IsEmpty());
    if (index) delete []index;
    index_len = 0;
    index = NULL;
}  // end MdpBlockBuffer::Destroy();

void MdpBlockBuffer::Prepend(MdpBlock *theBlock)
{
    ASSERT(theBlock);
    if (index)
    {
        ASSERT(theBlock->id < index_len);
        ASSERT(!index[theBlock->id]);
        index[theBlock->id] = theBlock;
    }
    theBlock->prev = NULL;
    theBlock->next = head;
    if (theBlock->next)
        head->prev = theBlock;
    else
        tail = theBlock;
    head = theBlock;
    block_count++;
}  // end MdpBlockBuffer::Prepend();

// Get pointer to block by index
MdpBlock* MdpBlockBuffer::GetBlock(UInt32 theIndex)
{
    ASSERT(index);
    ASSERT(theIndex < index_len);
    MdpBlock* theBlock = index[theIndex];
    if (theBlock) Touch(theBlock);  // puts it to head of linked list
    return theBlock;
}  // end MdpBlockBuffer::GetBlock()


void MdpBlockBuffer::Remove(MdpBlock* theBlock)
{
    ASSERT(theBlock);
    if (index)
    {
        ASSERT(theBlock->id < index_len);
        ASSERT(index[theBlock->id] == theBlock);
        index[theBlock->id] = NULL;
    }
    if (theBlock->prev)
        theBlock->prev->next = theBlock->next;
    else
        head = theBlock->next;
    if (theBlock->next)
        theBlock->next->prev = theBlock->prev;
    else
        tail = theBlock->prev;
    block_count--;
}  // end MdpBlockBuffer::Remove();



// Promotes block to head of linked list
void MdpBlockBuffer::Touch(MdpBlock *theBlock)
{
    ASSERT(theBlock);
    if (theBlock == head) return;
    // First remove block from current location
    ASSERT(theBlock->prev);  // this should always be true if it's not the head
    theBlock->prev->next = theBlock->next;
    if (theBlock->next)
        theBlock->next->prev = theBlock->prev;
    else
        tail = theBlock->prev;
    // Put at head of list
    theBlock->prev = NULL;
    theBlock->next = head;
    ASSERT(head);  // this should always be true
    head->prev = theBlock;
    head = theBlock;
}  // end MdpBlockBuffer::Touch()

// Helper MdpBlockBufferIterator class implementation
MdpBlockBufferIterator::MdpBlockBufferIterator(MdpBlockBuffer &theBuffer)
    : next(theBuffer.head)
{
}

MdpBlock *MdpBlockBufferIterator::Next()
{
    if (next)
    {
        MdpBlock *theBlock = next;
        next = next->next;
        return theBlock;
    }
    else
    {
        return NULL;
    }
}  // end MdpBlockBufferIterator::Next()


/***************************************************************************
 * MdpObject implementation
 */

MdpObject::MdpObject(MdpObjectType      theType,
                     class MdpSession*  theSession,
                     MdpServerNode*     theSender,
                     UInt32             transportId,
                     char*              theMsgPtr,
                     Int32              theVirtualSize)
    : type(theType), session(theSession), sender(theSender),
      transport_id(transportId),
      info(NULL), info_size(0), object_size(0), status(0),
      data_recvd(0), block_size(0), last_block_id(0), last_block_len(0),
      last_offset(0), first_pass(true),
      notify_pending(0), notify_abort(false), notify_error(MDP_ERROR_NONE),
      user_data(NULL), msgPtr(theMsgPtr), virtualSize(theVirtualSize),
      prev(NULL), next(NULL), list(NULL)
{
    nacking_mode = session->EmconClient() ? MDP_NACKING_NONE : theSession->DefaultNackingMode();
    tx_completion_time = 0;
    current_block_id = 0;
    current_vector_id = 0;

    repair_timer.SetInterval(0.0);
    repair_timer.SetRepeat(0);

    actual_last_block_id = 0; //this is for virtual payload support
    actual_last_block_len = 0; //this is for virtual payload support
    actual_last_offset = 0; //this is for virtual payload support
}  // end MdpObject::MdpObject()

MdpObject::~MdpObject()
{
    MdpObject::Close();
    Notify(MDP_NOTIFY_OBJECT_DELETE, notify_error);
    if (info) delete []info;
}

void MdpObject::Close()
{
    if (repair_timer.IsActive())
        repair_timer.Deactivate(this->session->GetNode());
    status = 0;
    block_size = 0;
    object_size = 0;
    transmit_mask.Destroy();
    repair_mask.Destroy();
    FreeBuffers();
    block_buffer.Destroy();

    if (msgPtr)
    {
        MESSAGE_Free(this->session->GetNode(),(Message*)msgPtr);
    }
}  // end MdpObject::Close()

MdpError MdpObject::TxAbort()
{
    if (!sender)
    {
        if (NotifyPending())
        {
            notify_abort = true;
        }
        else
        {

            ASSERT(list);
            list->Remove(this);
            delete this;
        }
        return MDP_ERROR_NONE;
    }
    else
    {
        return MDP_ERROR_OBJECT_INVALID;
    }
}  // end MdpObject::TxAbort()

MdpError MdpObject::RxAbort()
{
    if (sender)
    {
        if (NotifyPending())
        {
            notify_abort = true;
        }
        else
        {
            sender->DeactivateRecvObject(transport_id, this);
            delete this;
        }
        return MDP_ERROR_NONE;
    }
    else
    {
        return MDP_ERROR_OBJECT_INVALID;
    }
}  // end MdpObject::RxAbort()


void MdpObject::Notify(MdpNotifyCode notifyCode, MdpError errorCode)
{
    notify_pending++;
    session->Notify(notifyCode, sender, this, errorCode);
    notify_pending--;
    notify_error = MDP_ERROR_NONE;
}  // end MdpObject::Notify()

bool MdpObject::SetInfo(const char* theInfo, unsigned short infoSize)
{
    ASSERT(theInfo);
    if (!sender)
    {
        if (infoSize > session->SegmentSize())
            return false;
    }

    if (info)
    {
        if (info_size != infoSize)
        {
            delete []info;
            info = new char[infoSize+1];
            memset(info, 0, infoSize+1);
        }
    }
    else
    {
        info = new char[infoSize+1];
        memset(info, 0, infoSize+1);
    }
    if (info)
    {
        memcpy(info, theInfo, infoSize);
        info_size = infoSize;
        return true;
    }
    else
    {
        info_size = 0;
        return false;
    }
}  // end MdpObject::SetInfo()


UInt32 MdpObject::SenderId()
    {return (sender ? sender->Id() : 0);}

UInt32 MdpObject::LocalNodeId()
    {return session->LocalNodeId();}

// This routine inits object parameters which are dependent
// upon BlockInfo _and_ SizeInfo so SetObjectSize() and
// SetBlockInfo() must be called first.
bool MdpObject::Index()
{
    ASSERT(block_size != 0);
    last_block_id = object_size / block_size;
    if (0 != object_size)
    {
        // How much data in last block?
        UInt32 remainder = object_size % block_size;
        if (remainder)
        {
            last_block_len = (remainder / segment_size) + 1;
        }
        else
        {
            last_block_len = ndata;
            last_block_id--;
        }

        last_offset = (last_block_id * block_size) +
                      ((last_block_len-1) * segment_size);

        actual_last_block_id = (object_size - virtualSize) / block_size;
        // How much data in actual last block in case of vitual payload?
        UInt32 actual_remainder = (object_size - virtualSize) % block_size;

        if (actual_last_block_id == 0 && actual_remainder == 0)
        {
            // case when actual data in the application packet is 0
            actual_last_block_len = (actual_remainder / segment_size) + 1;
        }
        else if (actual_remainder)
        {
            actual_last_block_len = (actual_remainder / segment_size) + 1;
        }
        else
        {
            actual_last_block_len = ndata;
            actual_last_block_id--;
        }
        actual_last_offset = (actual_last_block_id * block_size) +
                      ((actual_last_block_len-1) * segment_size);

        if (!block_buffer.Index(last_block_id + 1))
        {
            if (MDP_DEBUG)
            {
                printf("MdpObject::Index(): Error indexing block_buffer");
            }
            return false;
        }
        if (!transmit_mask.Init(last_block_id + 1))
        {
            if (MDP_DEBUG)
            {
                printf("MdpObject::Index(): Error initializing transmit_mask");
            }
            block_buffer.Destroy();
            return false;
        }
        if (!repair_mask.Init(last_block_id + 1))
        {
            if (MDP_DEBUG)
            {
                printf("MdpObject::Index(): Error initializing repair_mask");
            }
            transmit_mask.Destroy();
            block_buffer.Destroy();
            return false;
        }
    }
    else
    {
        last_block_len = 0;
        last_offset = 0;
        block_buffer.Index(0);
        transmit_mask.Destroy();
        repair_mask.Destroy();
    }
    // Set mask for blocks to be tx'd (from SERVER _or_ to CLIENT)
    transmit_mask.Reset();
    // Set mask for blocks needing repair (none initially)
    repair_mask.Clear();
    return true;
}  // end MdpObject::Index()

void MdpObject::FreeBuffers()
{
    if (sender)
        block_buffer.Empty(sender->BlockPool(), sender->VectorPool());
    else
        block_buffer.Empty(&session->server_block_pool,
                           &session->server_vector_pool);
}  // end MdpObject::FreeBuffers()

// if "anyBlock == true, steal else exclude blockId or less
MdpBlock* MdpObject::ClientStealBlock(bool anyBlock, UInt32 blockId)
{
    MdpBlock *blk = NULL;
    UInt32 i = last_block_id + 1;
    while (i--)
    {
        if (!anyBlock && (i == blockId)) break;
        blk = block_buffer.GetBlock(i);
        if (blk) break;
    }
    if (blk)
    {
        block_buffer.Remove(blk);
        // Adjust data_recvd for state loss from stolen block
        UInt32 lastSegmentLen;
        UInt32 blockLen;
        if (i == last_block_id)
        {
            blockLen = last_block_len - 1;
            lastSegmentLen = object_size - last_offset;
        }
        else
        {
            blockLen = ndata - 1;
            lastSegmentLen = segment_size;
        }
        UInt32 j = 0;
        for (; j < blockLen; j++)
        {
            if (blk->IsFilled(j))
                data_recvd -= segment_size;
        }
        if (blk->IsFilled(j++)) data_recvd -= lastSegmentLen;
        blockLen += nparity + 1;
        for (; j < blockLen ; j++)
        {
            if (blk->IsFilled(j))
                data_recvd -= segment_size;
        }
        return blk;
    }
    else
    {
        return NULL;
    }
}  // end MdpObject::ClientStealBlock()

// if "anyBlock == true, steal any, else exclude blockId or less
MdpBlock* MdpObject::ServerStealBlock(bool anyBlock, UInt32 blockId)
{
    UInt32 i = last_block_id + 1;
    while (i--)
    {
        MdpBlock* blk = block_buffer.GetBlock(i);
        if (blk)
        {
            if (anyBlock || (i > blockId) ||
               (!blk->TxPending() && !blk->RepairPending()))
            {
                block_buffer.Remove(blk);
                return blk;
            }
        }
    }
    return NULL;
}  // end MdpObject::ServerStealBlock()

//  This routine supplies the object's next DATA or PARITY
//  message for transmission by an MDP_SERVER session
MdpMessage* MdpObject::BuildNextServerMsg(MdpMessagePool*   m_pool,
                                          MdpVectorPool*    v_pool,
                                          MdpBlockPool*     b_pool,
                                          MdpEncoder*       encoder)
{
    MdpMessage* theMsg = m_pool->Get();
    if (!theMsg)
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Server unable to obtain needed message resources!\n");
        }
        return NULL;
    }

    if (info_transmit_pending)
    {
        // updating the vector pool statistics and at the same time avoiding
        // the actual vector allocation
        if (!(v_pool->IsVectorExist()))
        {
            if (!(session->ServerReclaimResources(this, 0)))
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Server unable to obtain needed vector resources!\n");
                }
                m_pool->Put(theMsg);
                return NULL;
            }
            else
            {
                if (v_pool->IsVectorExist())
                {
                    v_pool->IncreaseVectorCountUsage();
                }
            }
        }
        else
        {
            v_pool->IncreaseVectorCountUsage();
        }

        ASSERT(info);
        theMsg->type = MDP_INFO;
        theMsg->version = MDP_PROTOCOL_VERSION;
        // MdpSession::Serve() fills in "sender" field
        theMsg->object.object_id = transport_id;
        theMsg->object.object_size = object_size;
        theMsg->object.ndata = (unsigned char)ndata;
        theMsg->object.nparity = (unsigned char)nparity;
        theMsg->object.flags = MDP_DATA_FLAG_INFO;
        if (MDP_OBJECT_FILE == type)
            theMsg->object.flags |= MDP_DATA_FLAG_FILE;
        if (info_repair_pending || current_block_id)
            theMsg->object.flags |= MDP_DATA_FLAG_REPAIR;
        theMsg->object.info.segment_size = (unsigned short)segment_size;
        theMsg->object.grtt = session->grtt_quantized;
        theMsg->object.info.data = info;
        theMsg->object.info.len = info_size;
        theMsg->object.info.actual_data_len = info_size;  //keep it same
        info_transmit_pending = false;
        return theMsg;
    }

    UInt32 blockId = transmit_mask.FirstSet();
    ASSERT(blockId <= last_block_id);
    unsigned int numData;
    if (blockId != last_block_id)
        numData = ndata;
    else
        numData = last_block_len;
    if (blockId > current_block_id) current_block_id = blockId;
    MdpBlock* theBlock = block_buffer.GetBlock(blockId);
    if (!theBlock)
    {
        // New block ... init state and go
        theBlock = b_pool->Get();
        if (!theBlock)
        {
            if (!(session->ServerReclaimResources(this, blockId)))
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Server unable to obtain needed block resources!\n");
                }
                m_pool->Put(theMsg);
                return NULL;
            }
            else
            {
                theBlock = b_pool->Get();
                ASSERT(theBlock);
            }
        }

        // EMCON Mode may transmit some parity automatically
        theBlock->TxInit(blockId, numData + session->auto_parity);

        // Load parity slots with Zero-filled vectors
        int block_len = (numData+nparity);
        for (int i = numData; i < block_len; i++)
        {
            char* vector = v_pool->Get();
            if (!vector)
            {
                if (!(session->ServerReclaimResources(this, blockId)))
                {
                    theBlock->Empty(v_pool);
                    b_pool->Put(theBlock);
                    m_pool->Put(theMsg);
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server unable to obtain needed vector resources!\n");
                    }
                    return NULL;
                }
                else
                {
                    vector = v_pool->Get();
                    ASSERT(vector);
                }
            }
            memset(vector, 0, segment_size);
            theBlock->AttachVector(vector, i);
            theBlock->SetVectorSize((short)segment_size, i);
        }

        // Put new block in our block_buffer
        block_buffer.Prepend(theBlock);
    }

    if (!theBlock->TxActive())
    {
        // Pull in any pending repairs at "last instant" before block is made TX_ACTIVE
        //DMSG(6, "mdp: Server BuildNextServerMsg() !TxActive block obj:%lu"
        //        " (block rp = %d)\n", transport_id, theBlock->RepairPending());
        if (theBlock->RepairPending() || repair_mask.Test(blockId))
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server BuildNextServerMsg() activating "
                    "\"last instant\" block repairs for object: %u\n",
                    transport_id);
            }
            theBlock->ActivateRepairs(); // add in repairs and clear repair_mask
            repair_mask.Unset(blockId);
        }
        // Mark block as being TX_ACTIVE ...
        theBlock->SetStatusFlag(MDP_BLOCK_FLAG_TX_ACTIVE);
    }

    // Get next vector to tx (from block's vector_mask)
    unsigned int vectorId = theBlock->GetNextTxVector();

    current_vector_id = vectorId;
    if (vectorId < numData)  // Build data message using object data
    {
        theMsg->type = MDP_DATA;
        theMsg->object.object_id = transport_id;
        theMsg->object.object_size = object_size;
        theMsg->object.ndata = (unsigned char)ndata;
        theMsg->object.nparity = (unsigned char)nparity;
        UInt32 offset = (blockId * block_size) +
                               (vectorId * segment_size);
        if (MDP_OBJECT_FILE == type)
            theMsg->object.flags = MDP_DATA_FLAG_FILE;
        else
            theMsg->object.flags = 0;
        if (info)
            theMsg->object.flags |= MDP_DATA_FLAG_INFO;
        if (offset == last_offset)
        {
            theMsg->object.flags |= MDP_DATA_FLAG_RUNT;
            theMsg->object.data.segment_size = (unsigned short)segment_size;
        }
        if (theBlock->InRepair() || (blockId < current_block_id))
            theMsg->object.flags |= MDP_DATA_FLAG_REPAIR;
        theMsg->object.grtt = session->grtt_quantized;
        theMsg->object.data.offset = offset;
        char *vector = v_pool->Get();
        if (!vector)
        {
            if (!(session->ServerReclaimResources(this, blockId)))
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Server unable to obtain needed vector resources!\n");
                }
                m_pool->Put(theMsg);
                return NULL;
            }
            else
            {
                vector = v_pool->Get();
                ASSERT(vector);
            }
        }

        char *buffer = NULL;
        // init with NULL
        theMsg->object.data.data = NULL;

        if (type == MDP_OBJECT_FILE)
        {
            // init with vector
            buffer = vector;
        }

        unsigned short segmentSize = 0;
        unsigned short actualSegmentSize = 0;
        if (!(ReadSegment(offset, buffer, &segmentSize, &actualSegmentSize, &theMsg->object.data.data)))
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server error reading data segment for object:%u\n",
                    transport_id);
            }
            m_pool->Put(theMsg);
            session->RemoveTxObject(this);
            return NULL;
            //theMsg = NULL;
        }
        else
        {
            theMsg->object.data.len = segmentSize;
            theMsg->object.data.actual_data_len = actualSegmentSize;

            theBlock->SetVectorSize(actualSegmentSize, vectorId);

            if (type == MDP_OBJECT_FILE)
            {
                theMsg->object.data.data = vector;
            }

            if (!theBlock->ParityReady() && nparity)
            {
                if (type == MDP_OBJECT_DATA)
                {
                    //for MDP_OBJECT_DATA object
                    memcpy(vector, theMsg->object.data.data, actualSegmentSize);
                }

                if (blockId != last_block_id)
                    encoder->Encode(vector, theBlock->VectorList(ndata));
                else
                    encoder->Encode(vector, theBlock->VectorList(last_block_len));
                // Bad assumption on parity readiness for recalled blocks
                // OK for initial transmission ... but recalled blocks should
                // regenerate parity when NACKed for old
                if (vectorId == (numData-1))
                    theBlock->SetStatusFlag(MDP_BLOCK_FLAG_PARITY_READY);
            }

            if (type != MDP_OBJECT_FILE)
            {
                // vector need to be freed for MDP_OBJECT_DATA object
                v_pool->Put(vector);
            }
        }
    }
    else  // it's a parity vector, so use parity data
    {
        ASSERT(vectorId < (numData+nparity));
        if (!theBlock->ParityReady() &&
            (!CalculateBlockParity(blockId, theBlock, encoder)))
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server error regenerating parity for object:%u\n",
                    transport_id);
            }
            m_pool->Put(theMsg);
            theMsg = NULL;
        }
        else
        {
            theMsg->type = MDP_PARITY;
            theMsg->object.object_id = transport_id;
            theMsg->object.object_size = object_size;
            theMsg->object.ndata = (unsigned char)ndata;
            theMsg->object.nparity = (unsigned char)nparity;
            if (MDP_OBJECT_FILE == type)
                theMsg->object.flags = MDP_DATA_FLAG_FILE;
            else
                theMsg->object.flags = 0;
            if (info)
                theMsg->object.flags |= MDP_DATA_FLAG_INFO;
            if (theBlock->InRepair() || (blockId < current_block_id))
                theMsg->object.flags |= MDP_DATA_FLAG_REPAIR;
            theMsg->object.grtt = session->grtt_quantized;
            theMsg->object.parity.offset = blockId * block_size;
            theMsg->object.parity.id = (unsigned char)vectorId;

            // updating the vector pool statistics and at the same time
            // avoiding the actual vector allocation
            if (!(v_pool->IsVectorExist()))
            {
                if (!(session->ServerReclaimResources(this, blockId)))
                {
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server unable to obtain needed vector resources!\n");
                    }
                    m_pool->Put(theMsg);
                    return NULL;
                }
                else
                {
                    if (v_pool->IsVectorExist())
                    {
                        v_pool->IncreaseVectorCountUsage();
                    }
                }
            }
            else
            {
                v_pool->IncreaseVectorCountUsage();
            }

                theMsg->object.parity.data = theBlock->Vector(vectorId);
                theMsg->object.parity.len = (unsigned short)segment_size;
                theMsg->object.parity.actual_data_len =
                          (unsigned short)theBlock->ReturnActualVectorSize(vectorId);
        }
    }

    if (!theBlock->TxPending())  // Block transmission complete
    {
        if (theMsg)
        {
            theMsg->object.flags |= MDP_DATA_FLAG_BLOCK_END;
        }

        // Transmit/Repair pass complete, update theBlock's parity offset
        if (theBlock->ParityOffset() < nparity)
        {
            ASSERT((theBlock->ParityOffset()+theBlock->ParityCount()) <= nparity);
            theBlock->SetParityOffset(theBlock->ParityOffset() +
                                      theBlock->ParityCount());
        }
        theBlock->SetParityCount(0);
        theBlock->ClearStatusFlag(MDP_BLOCK_FLAG_IN_REPAIR);  // ??? Set this flag instead
        theBlock->ClearStatusFlag(MDP_BLOCK_FLAG_TX_ACTIVE);
        transmit_mask.Unset(blockId);
        // For EMCON, transmit object info at end of each block
        if (session->EmconServer() && info) info_transmit_pending = true;
    }
    return theMsg;
}  // end MdpObject::BuildNextServerMsg()

bool MdpObject::OnRepairTimeout()
{
    repair_timer.Deactivate(session->GetNode());

    if (MDP_DEBUG)
    {
        printf("mdp: Server repair aggregation timeout ended for object:%u ... \n", transport_id);
    }

    info_repair_pending = false;
    if (repair_mask.IsSet())
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Server incorporating repairs for object:%u ...\n",
                transport_id);
        }
        transmit_mask.Add(&repair_mask);
        repair_mask.Clear();
    }
    if (TxPending())
    {
        if (session->TxQueueIsEmpty())
        {
            session->Serve();
        }
    }
    else  // all object repairs have been incorporated at last instant by "MdpObject::BuildNextServerMsg()"
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Server all pending repairs already incorporated ...\n");
        }
        session->DeactivateTxObject(this);
    }
    return false;
}  // end MdpObject::OnRepairTimeout()

bool MdpObject::CalculateBlockParity(UInt32 blockId,
                                        MdpBlock *theBlock,
                                        MdpEncoder *encoder)
{
    char vector[MDP_SEGMENT_SIZE_MAX];
    memset(vector, 0, MDP_SEGMENT_SIZE_MAX);
    UInt32 offset = blockId * block_size;
    int numData;
    if (blockId != last_block_id)
        numData = ndata;
    else
        numData = last_block_len;
    for (int i = 0; i < numData; i++)
    {
        unsigned short segmentSize = 0;
        unsigned short actualSegmentSize = 0;
        if (!(ReadSegment(offset, vector, &segmentSize, &actualSegmentSize)))
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server error reading object data segment for object:%u\n",
                     transport_id);
            }
            return false;
        }
        encoder->Encode(vector, theBlock->VectorList(numData));
        offset += segment_size;
    }
    theBlock->SetStatusFlag(MDP_BLOCK_FLAG_PARITY_READY);
    return true;
}  // end MdpObject::CalculateBlockParity()


bool MdpObject::ServerHandleRepairNack(MdpRepairNack* theNack)
{
    bool increasedRepairState = false;
    switch (theNack->type)
    {
        case MDP_REPAIR_SEGMENTS:
        {
            UInt32 blockId = theNack->offset;
            if (MDP_DEBUG)
            {
                printf("mdp: Server handling MDP_REPAIR_SEGMENTS nack for "
                    "object:%u block:%u (%d segments needed)\n",
                    transport_id, blockId, theNack->nerasure);
            }
            // Get state for the block one way or another.
            // Do we have the state readily available?
            MdpBlock* theBlock = block_buffer.GetBlock(blockId);
            int numData;
            if (blockId != last_block_id)
                numData = ndata;
            else
                numData = last_block_len;
            // If not, attempt to recover state
            if (!theBlock)
            {
                if (MDP_DEBUG)
                {
                    printf("Server recv'd MDP_NACK_REPAIR outside buffer window for object: %u!\n",
                        transport_id);
                }
                theBlock = session->server_block_pool.Get();
                if (!theBlock)
                {
                    session->ServerReclaimResources(this, blockId);
                    theBlock = session->server_block_pool.Get();
                }
                if (theBlock)
                {
                    // Init, populate parity vectors, and set repair info
                    theBlock->TxInit(blockId, 0);
                    int blockEnd = numData + nparity;
                    for (int i = numData; i < blockEnd; i++)
                    {
                        char *vector = session->server_vector_pool.Get();
                        if (!vector)
                        {
                            if (!(session->ServerReclaimResources(this, blockId)))
                            {
                                theBlock->Empty(&session->server_vector_pool);
                                session->server_block_pool.Put(theBlock);
                                if (MDP_DEBUG)
                                {
                                    printf("mdp: Server unable to recover repair state for object:%u block:%u\n",
                                        transport_id, blockId);
                                }
                                return false;
                            }
                            else
                            {
                                vector = session->server_vector_pool.Get();
                                ASSERT(vector);
                            }
                        }
                        memset(vector, 0, segment_size);
                        theBlock->AttachVector(vector, i);
                        theBlock->SetVectorSize((short)segment_size, i);
                    }
                    block_buffer.Prepend(theBlock);
                    // Regenerate party so we'll have it when we need it
                    CalculateBlockParity(blockId, theBlock, &session->encoder);
                    // Explicit parity repair only for recovered blocks with no state
                    theBlock->SetParityOffset(nparity);
                }
                else
                {
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server unable to recover repair state for object:%u block:%u\n",
                                transport_id, blockId);
                    }
                    return false;
                }
            }  // end if (!theBlock)

            ASSERT(theBlock);
            ASSERT(theNack->mask_len == ((ndata+nparity+7) >> 3));
            theBlock->SetStatusFlag(MDP_BLOCK_FLAG_IN_REPAIR);
            unsigned int p_offset = theBlock->ParityOffset();
            unsigned int n_erase = theNack->nerasure;
            if (theBlock->TxActive())
            {
                // Update only future portions of block vector_mask
                unsigned int first = theBlock->FirstSet();
                if (p_offset < nparity)
                {
                    if (n_erase > (nparity - p_offset))
                    {
                        // Not enough parity, revert to explicit repair only
                        theBlock->SetParityOffset(nparity);
                        ::MaskUnsetBits(theNack->mask, 0, first);
                        theBlock->AddRawMask(theNack->mask, theNack->mask_len);
                    }
                    else if (n_erase > theBlock->ParityCount())
                    {
                        theBlock->SetMaskBits(first,
                            (numData+p_offset+n_erase-first));
                        theBlock->SetParityCount(n_erase);
                        // (TBD) Update theNACK nerasure field
                    }
                }
                else
                {
                    // We're already doing explicit repair
                    ::MaskUnsetBits(theNack->mask, 0, first);
                    theBlock->AddRawMask(theNack->mask, theNack->mask_len);
                }
                //MaskCopy(theNack->mask, theBlock->Mask(), theNack->mask_len);
                return false;  // Don't start repair_timer on TX_ACTIVE block
            }
            else  // just update block repair mask
            {
                if (p_offset < nparity)
                {
                    if (n_erase > (nparity - p_offset))
                    {
                        // Not enough fresh parity, revert to EXPLICIT repair only
                        theBlock->SetParityOffset(nparity);
                        // For unicast NACK suppression, check for increaseReparState
                        MaskAdd(theNack->mask, theBlock->RepairMask(), theNack->mask_len);
                        MaskSubtract(theNack->mask, theBlock->RepairMask(), theNack->mask_len);
                        if (MaskFirstSet(theNack->mask, theNack->mask_len) <
                            (UInt32)(theNack->mask_len << 3))
                        {
                            increasedRepairState = true;
                        }
                        // (TBD) After debug, AddRepairs in above conditional instead of always
                        theBlock->AddRepairs(theNack->mask, theNack->mask_len);
                        // Update NACK content for advertisement
                        MaskCopy(theNack->mask, theBlock->RepairMask(), theNack->mask_len);

                    }
                    else if (n_erase > theBlock->ParityCount())
                    {
                        // Use additional fresh (unused) PARITY repair
                        increasedRepairState = true;
                        theBlock->SetRepairs((numData + p_offset + theBlock->ParityCount()),
                                             (n_erase - theBlock->ParityCount()));
                        theBlock->SetParityCount(n_erase);
                    }
                    else
                    {
                        // Update the lightweight NACK for possible re-advertisement
                        MaskSetBits(theNack->mask, numData, theBlock->ParityCount());
                    }
                }
                else
                {
                    // We're in EXPLICT repair mode
                    // For unicast NACK suppression, check for increasedReparState
                    MaskAdd(theNack->mask, theBlock->RepairMask(), theNack->mask_len);
                    MaskSubtract(theNack->mask, theBlock->RepairMask(), theNack->mask_len);
                    if (MaskFirstSet(theNack->mask, theNack->mask_len) <
                        (UInt32)(theNack->mask_len << 3))
                    {
                        increasedRepairState = true;
                    }
                    // (TBD) After debug, AddRepairs in above conditional instead of always
                    theBlock->AddRepairs(theNack->mask, theNack->mask_len);
                    // Update NACK content for advertisement
                    MaskCopy(theNack->mask, theBlock->RepairMask(), theNack->mask_len);
                }
                repair_mask.Set(blockId);
            }  // end if/else (theBlock->TxActive())
        }
        break;

        case MDP_REPAIR_BLOCKS:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server handling MDP_REPAIR_BLOCKS nack for object: %u\n", transport_id);
            }
            // For MDP_BLOCK_REPAIR, theNack->id is a block id offset
            ASSERT(((theNack->offset >> 3) + theNack->mask_len) <= repair_mask.MaskLen());
            UInt32 blockId = ::MaskFirstSet(theNack->mask, theNack->mask_len);
            ASSERT(blockId < ((UInt32) theNack->mask_len << 3));
            blockId += theNack->offset;
            ASSERT(blockId <= last_block_id);

            // Before adding, do check on applicable portion of repair mask
            UInt32 maskOffset = theNack->offset >> 3;
            MaskAdd(theNack->mask, repair_mask.Mask()+maskOffset, theNack->mask_len);
            MaskSubtract(theNack->mask, repair_mask.Mask()+maskOffset, theNack->mask_len);
            if (MaskFirstSet(theNack->mask, theNack->mask_len) <
                (UInt32)(theNack->mask_len << 3))
            {
                increasedRepairState = true;
            }
            // (TBD) After debug, AddRepairs in above conditional instead of always
            repair_mask.AddRawOffsetMask(theNack->mask, theNack->mask_len, maskOffset);
            MaskCopy(theNack->mask, repair_mask.Mask()+maskOffset, theNack->mask_len);

            while (blockId <= last_block_id)
            {
                MdpBlock *theBlock = block_buffer.GetBlock(blockId);
                if (theBlock)
                {
                    theBlock->SetStatusFlag(MDP_BLOCK_FLAG_IN_REPAIR);
                    unsigned int numData;
                    if (blockId != last_block_id)
                        numData = ndata;
                    else
                        numData = last_block_len;
                    if (theBlock->TxActive())
                    {
                        if (MDP_DEBUG)
                        {
                            printf("mdp: Server handling MDP_REPAIR_BLOCKS nack (TxActive block)\n");
                        }
                        repair_mask.Unset(blockId);
                        if (theBlock->FirstSet() < numData)
                        {
                            theBlock->SetMaskBits(theBlock->FirstSet(),
                                                  numData + session->auto_parity
                                                  - theBlock->FirstSet());
                        }
                    }
                    else
                    {
                        if (MDP_DEBUG)
                        {
                            printf("mdp: Server handling MDP_REPAIR_BLOCKS nack\n");
                        }
                        theBlock->SetRepairs(0, numData + session->auto_parity);
                    }
                }
                else
                {
//#ifdef PROTO_DEBUG
//                    if (!theBlock)
//                    {
//                        printf("mdp: Server handling MDP_REPAIR_BLOCKS nack "
//                                "(no block %lu state) for object: %lu\n",
//                                blockId, transport_id);
//                    }
//#endif // PROTO_DEBUG
                }
                blockId = ::MaskNextSet((blockId - theNack->offset + 1),
                                         theNack->mask,
                                         theNack->mask_len);
                if (blockId < ((UInt32)theNack->mask_len << 3))
                    blockId += theNack->offset;
                else
                    break;
            }
        }
        break;

        case MDP_REPAIR_INFO:
            if (MDP_DEBUG)
            {
                printf("mdp: Server handling MDP_REPAIR_INFO nack for object: %u\n", transport_id);
            }
            if (info && !info_repair_pending)
            {
                info_repair_pending = true;
                info_transmit_pending = true;
                increasedRepairState = true;
            }
            break;

        case MDP_REPAIR_OBJECT:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: Server handling MDP_REPAIR_OBJECT nack for object: %u\n", transport_id);
            }
            if (info && !info_repair_pending)
            {
                info_repair_pending = true;
                info_transmit_pending = true;
                increasedRepairState = true;
            }
            if (0 == object_size) break;
            // Is weight of repair_mask being increased?
            // I.e. Are there any unset, non-TxActive blocks?
            UInt32 blockId = repair_mask.NextUnset(0);

            while (blockId <= last_block_id)
            {
                MdpBlock* theBlock = block_buffer.GetBlock(blockId);
                if (!theBlock || !theBlock->TxActive())
                {
                    increasedRepairState = true;
                    break;
                }
                blockId++;
                blockId = repair_mask.NextUnset(blockId);
            }

            repair_mask.Reset();
            MdpBlock* theBlock = block_buffer.Head();
//#ifdef PROTO_DEBUG
//            if (!theBlock)
//            {
//                printf("mdp: Server handling MDP_REPAIR_OBJECT nack (no blocks) for object: %lu\n", transport_id);
//            }
//#endif // PROTO_DEBUG
            while (theBlock)
            {
                theBlock->SetStatusFlag(MDP_BLOCK_FLAG_IN_REPAIR);
                UInt32 blockId = theBlock->Id();
                unsigned int numData;
                if (blockId != last_block_id)
                    numData = ndata;
                else
                    numData = last_block_len;
                if (theBlock->TxActive())
                {
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server handling MDP_REPAIR_OBJECT nack (TxActive block)\n");
                    }
                    repair_mask.Unset(blockId);
                    if (theBlock->FirstSet() < numData)
                    {
                        theBlock->SetMaskBits(theBlock->FirstSet(),
                                              numData + session->auto_parity
                                              - theBlock->FirstSet());
                    }
                }
                else
                {
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server handling MDP_REPAIR_OBJECT nack (!TxActive block)\n");
                    }
                    theBlock->SetRepairs(0, numData + session->auto_parity);
                }
                theBlock = theBlock->Next();
            }
        }
        break;

        default:
            if (MDP_DEBUG)
            {
                printf("mdp: Server recv'd UNKNOWN nack type:%d ?! (mask_len = %u)\n",
                    theNack->type, theNack->mask_len);
            }
            return false;
    }  // end switch (theNack->type);

    // If this is the first current NACK for this object, start the object's repair timer
    // (TBD) Reset timer interval if this low_block < timer's current_block ??
    // Collect NACKs while this timer is active
    if (!repair_timer.IsActive(session->GetNode()->getNodeTime()))
    {
        // BACKOFF related (NACK collection/aggregation time)
        double repairDelay;
        if (session->IsUnicast())
            repairDelay = 0.0;
        else
            repairDelay = (MDP_BACKOFF_WINDOW+1.0) * session->GrttEstimate();
        repair_timer.SetInterval(repairDelay);
        session->ActivateTimer(repair_timer, OBJECT_REPAIR_TIMEOUT, this);
        if (MDP_DEBUG)
        {
            printf("mdp: Server initiated repair cycle for object:%u (timeout = %f sec) ...\n",
                transport_id, repairDelay);
        }
    }
    return increasedRepairState;
}  // end MdpObject::ServerHandleRepairNack()



// Client will later "subtract" other NACKs heard from its own object repair
// mask to determine if it needs to suppress it's own NACK
// returns "true" if we should start the repair_timer
void MdpObject::ClientHandleRepairNack(MdpRepairNack *theNack)
{
    switch (theNack->type)
    {
        case MDP_REPAIR_SEGMENTS:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: client handling MDP_REPAIR_SEGMENT NACK ...\n");
            }
            UInt32 blockId = theNack->offset;
            // Update our repair_timer's "current_block_id" if other clients
            // are nacking for later blocks than us.
            if (blockId > last_block_id)
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Received bad MDP_REPAIR_SEGMENT nack from another client!\n");
                }
                blockId = last_block_id;
            }
            ClientRepairCheck(blockId+1, true);
            // Find the corresponding block
            MdpBlock* blk = block_buffer.GetBlock(blockId);
            if (blk) blk->AddRepairs(theNack->mask, theNack->mask_len);
            break;
        }

        case MDP_REPAIR_BLOCKS:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: client handling MDP_REPAIR_BLOCK NACK ...\n");
            }
            UInt32 blockId = theNack->offset + ::MaskLastSet(theNack->mask, theNack->mask_len);
            // Update our repair_timer's "current_block_id" if other clients
            // are nacking for later blocks than us.
            if (blockId > last_block_id)
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Received bad MDP_REPAIR_SEGMENT nack from another client!\n");
                }
                blockId = last_block_id;
            }
            ClientRepairCheck(blockId+1, true);
            repair_mask.AddRawOffsetMask(theNack->mask, theNack->mask_len, (theNack->offset >> 3));
            break;
        }

        case MDP_REPAIR_OBJECT:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: client handling MDP_REPAIR_OBJECT NACK ...\n");
            }
            ClientRepairCheck(last_block_id+1, true);
            repair_mask.Reset();
            break;
        }

        case MDP_REPAIR_INFO:
        {
            info_repair_pending = true;
            break;
        }

        default:
        {
            if (MDP_DEBUG)
            {
                printf("mdp: client recv'd UNKNOWN nack type:%d ?! (mask_len = %u)\n",
                    theNack->type, theNack->mask_len);
            }
            break;
        }
    }
}  // end MdpObject::ClientHandleRepairNack()

bool MdpObject::RepairPending()
{
    return repair_timer.IsActive(session->GetNode()->getNodeTime());
}

// This routine Starts/Updates client repair_timer based on the
// receipt of a message from the server with a block_id greater
// than blocks need outstanding repair. Repairs are "marked" in
// the object's "repair_mask"

bool MdpObject::ClientRepairCheck(UInt32 blockId, bool repair_timer_active)
{
    bool start_timer = false;
    // Do we need MDP_INFO for this object?
    if (info_transmit_pending)
    {
        info_repair_pending = false;
        start_timer = true;
    }

    // Check to see if repairs of previous blocks are needed
    if (!repair_timer_active)
    {
        // Check for older blocks needing repair or retransmission
        UInt32 nextId = transmit_mask.FirstSet();
        if (nextId < blockId)
        {
            if (repair_mask.IsSet())
            {
                session->SetNackRequired(TRUE);
            }
            repair_mask.Clear();
            while (nextId < blockId)
            {
                MdpBlock *blk = block_buffer.GetBlock(nextId);
                if (blk)
                {
                    if (blk->RepairPending())
                    {
                        session->SetNackRequired(TRUE);
                    }
                    blk->ClearRepairMask();
                    // This conditional is only for client stats reporting
                    // (TBD) #ifdef PROTO_DEBUG this?
                    if (!blk->InRepair())  // first pass stats reporting
                    {
                        blk->SetStatusFlag(MDP_BLOCK_FLAG_IN_REPAIR);
                        unsigned int numData;
                        if (nextId == last_block_id)
                            numData = last_block_len;
                        else
                            numData = ndata;
                        // Only track full-sized blocks
                        if (numData == ndata)
                        {
                            double loss = (double) blk->ErasureCount() /
                                         (double) numData;
                            if (loss <= 0.05)
                                session->client_stats.blk_stat.lost_05++;
                            else if (loss <= 0.10)
                                session->client_stats.blk_stat.lost_10++;
                            else if (loss <= 0.20)
                                session->client_stats.blk_stat.lost_20++;
                            else if (loss <= 0.40)
                                session->client_stats.blk_stat.lost_40++;
                            else
                                session->client_stats.blk_stat.lost_50++;
                        }
                    }  // end if (!blk->InRepair())
                }  // end if (blk)
                nextId = transmit_mask.NextSet(++nextId);
            }  // end while (nextId < blockId)
            start_timer = true;
        }  // end if (first_set < blockId)
        current_block_id = blockId;
        return start_timer;
    }  // else set current backwards if server has rewound
    else if (blockId < current_block_id) //(current_block_id < blockId)
    {
        current_block_id = blockId;
    }
    return false;  // timer was already running
}  // end MdpObject::ClientRepairCheck()

// This is called when the object sender's "repair_timer" fires
// and this object requires repair.
void MdpObject::BuildNack(MdpObjectNack *objectNack, bool current)
{
    // If it's not the current object, NACK for the whole thing
    UInt32 currentBlock;
    if (current)
        currentBlock = current_block_id;
    else
        currentBlock = last_block_id + 1;

    // Reset current_block_id for future repair cycles
    current_block_id = 0;

    // Are we missing MDP_INFO that no one else has NACK'd for?
    if (info_transmit_pending && !info_repair_pending)
    {
        MdpRepairNack theNack;
        theNack.type = MDP_REPAIR_INFO;
        if (!objectNack->AppendRepairNack(&theNack)) return;
        if (MDP_DEBUG)
        {
            printf("mdp: client requesting INFO_REPAIR for object:%u\n",
                transport_id);
        }
    }
    if (MDP_NACKING_INFOONLY == nacking_mode) return;

    UInt32 nextId = transmit_mask.FirstSet();
    if (nextId < currentBlock)
    {
        do
        {
            if (!(repair_mask.Test(nextId)))  // no-one else asked for full block repair
            {
                MdpBlock *theBlock = block_buffer.GetBlock(nextId);
                if (theBlock)
                {
                    unsigned int numData;
                    if (last_block_id != nextId)
                        numData = ndata;
                    else
                        numData = last_block_len;

                    // 1) Evaluate the current block tx_mask
                    MdpRepairNack theNack;
                    unsigned int repair_start, repair_end;  // range of segments to request retransmission
                    theNack.type = MDP_REPAIR_SEGMENTS;
                    if (theBlock->ErasureCount() <= nparity)
                    {
                        // Just NACK for the parity we need
                        repair_start = numData;
                        repair_end = repair_start + theBlock->ErasureCount();
                    }
                    else
                    {
                        // NACK for all parity plus some additional data
                        repair_start = theBlock->FirstSet();
                        unsigned int count = nparity;
                        while (count--)
                            repair_start = theBlock->NextSet(++repair_start);
                        ASSERT(repair_start < numData);
                        repair_end = numData + nparity;
                    }

                    // 2) Subtract out what other clients have already asked for
                    theBlock->FilterRepairs();  // repair_mask = tx_mask - repair_mask

                    // 3) Is there anything we need left in our range of interest?
                    if (theBlock->RepairsInRange(repair_start, repair_end))
                    {
                        // Copy vector_mask and trim to create a repair NACK mask
                        theBlock->CaptureRepairs();  // repair_mask = tx_mask
                        theBlock->UnsetRepairs(0, repair_start);
                        theBlock->UnsetRepairs(repair_end, (numData+nparity) - repair_end);
                        if (MDP_DEBUG)
                        {
                            printf("mdp: client requesting SEGMENT_REPAIR for object:%u block:%u (%d needed)\n",
                                        transport_id, nextId, theBlock->ErasureCount() - theBlock->ParityCount());
                        }
                        theNack.offset = nextId;
                        theNack.nerasure = (unsigned char)(theBlock->ErasureCount() - theBlock->ParityCount());
                        theNack.mask = (char*) theBlock->RepairMask();
                        theNack.mask_len = (unsigned short)((ndata + nparity + 7) >> 3);
                        if (!objectNack->AppendRepairNack(&theNack))
                        {
                            if (MDP_DEBUG)
                            {
                                printf("MdpObject::BuildNack() full nack msg ...\n");
                            }
                            return;  // full nack message
                        }
                    }  // end if (theBlock->RepairsInRange())
                }
                else // request BLOCK_REPAIR for old blocks we have not recv'd and have no state ...
                {
                    repair_mask.Set(nextId);
                }  // end if/else(theBlock)
            }
            else
            {
                // Don't NACK blocks others have requested BLOCK_REPAIR for
                repair_mask.Unset(nextId);
                // (TBD) I don't think these 2 lines are necessary since
                // the block repair mask gets cleared with NACK cycle
                // initiation.
                MdpBlock* theBlock = block_buffer.GetBlock(nextId);
                if (theBlock) theBlock->ClearRepairMask();
            }   // end if/else (!repair_mask.Test(nextId))
            nextId = transmit_mask.NextSet(++nextId);
        } while (nextId < currentBlock);

        // 2) repair_mask &= tx_mask to only NACK missing blocks we need
        repair_mask.And(transmit_mask);

        // Send a RepairNack for our low range of missing blocks
        // (Up to what will fit in remainder of the nack message)
        if (repair_mask.FirstSet() < currentBlock)
        {
            MdpRepairNack theNack;
            theNack.type = MDP_REPAIR_BLOCKS;
            UInt32 mask_offset = repair_mask.FirstSet() >> 3;
            theNack.offset = mask_offset << 3;

            ASSERT(currentBlock);
            theNack.mask_len = (unsigned short) (((currentBlock-1) >> 3) - mask_offset + 1);
            theNack.mask = (char *) repair_mask.Mask() + mask_offset;

            // Don't NACK for blocks beyond currentBlock prematurely.
            UInt32 clr_cnt = (7 - ((currentBlock-1) & 0x07));
            if ((currentBlock+clr_cnt) > last_block_id)
                clr_cnt = last_block_id - currentBlock + 1;
            repair_mask.UnsetBits(currentBlock, clr_cnt);

            if (!objectNack->AppendRepairNack(&theNack))
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: client MdpObject::BuildNack() full nack msg ...\n");
                }
                return;
            }

            if (MDP_DEBUG)
            {
                printf("mdp: client requesting BLOCK retransmission(s) for object:%u\n",
                    transport_id);
            }
        }  // end if (repair_mask.FirstSet() < currentBlock)
    }  // end if (transmit_mask.FirstSet() < currentBlock)
}  // end  MdpObject::BuildNack()

MdpDataObject::MdpDataObject(class MdpSession*      theSession,
                             class MdpServerNode*   theSender,
                             char *                 theMsgPtr,
                             Int32                  theVirtualSize,
                             UInt32                 transportId,
                             UInt32                 object_size)
    : MdpObject(MDP_OBJECT_DATA, theSession, theSender,
                transportId, theMsgPtr, theVirtualSize),
      data_ptr(NULL)
{
    if (object_size > 0)
    {
        data_ptr = (char*)MEM_malloc(object_size - theVirtualSize + 1);
        memset(data_ptr, 0, (object_size - theVirtualSize + 1));
    }
}

MdpError MdpDataObject::Open()
{
    if (!MdpIsExataIncomingPort(this->Session()->GetNode(),
                            this->Session()->GetAddr().GetPort()))
    {
        if (data_ptr || info || object_size > 0)
            return MDP_ERROR_NONE;
        else
            return MDP_ERROR;
    }
    else
    {
        if (data_ptr || info)
            return MDP_ERROR_NONE;
        else
            return MDP_ERROR;
    }
    return MDP_ERROR;
}

MdpDataObject::~MdpDataObject()
{
    if (IsOpen())
    {
        if (session->IsServer())
        {
            //MEM_free(data_ptr);
        }
        Close();
    }
}  // end MdpDataObject::~MdpDataObject()

bool MdpDataObject::SetData(char* dataPtr, UInt32 dataLen)
{
    if (sender)
    {
        if (dataLen < object_size) return false;
    }
    else
    {
        object_size = dataLen;
    }
        data_ptr = dataPtr;
    return true;
}  // end MdpDataObject::SetData()

bool MdpDataObject::ReadSegment(UInt32 offset,
                                char* buffer,
                                UInt16* size,
                                UInt16* actualSize,
                                char** data_buffer_ptr)
{
    ASSERT(IsOpen());

    UInt32 actual_size = 0;
    if (virtualSize > 0)
    {
        actual_size = object_size - virtualSize;
    }
    else
    {
        actual_size = object_size;
    }
    //calculting segment size
    if (offset == last_offset)
    {
        *size = (UInt16)(object_size - last_offset);
        // Clear tail if it's the last short segment
        if (buffer)
        {
            memset(&buffer[*size], 0, (segment_size - *size));
        }
    }
    else
    {
        *size = (UInt16)segment_size;
    }
    ASSERT((offset + *size) <= object_size);

    // now calculating actualSize the data_ptr has right now
    if (offset <= actual_size)
    {
        if (offset == actual_last_offset)
        {
            *actualSize = (UInt16)(actual_size - offset);
            if (buffer)
            {
                memset(&buffer[*actualSize], 0, (segment_size - *actualSize));
            }
        }
        else
        {
            *actualSize = (UInt16)segment_size;
        }

        if (data_buffer_ptr)
        {
            *data_buffer_ptr = data_ptr + offset;
        }

        if (buffer)
        {
            memcpy(buffer, data_ptr + offset, *actualSize);
            memset(&buffer[*actualSize], 0, (segment_size - *actualSize));
        }
    }
    else
    {
        // comes in condition when (offset > actual_size)
        *actualSize = 0;
        if (data_buffer_ptr)
        {
            *data_buffer_ptr = NULL;
        }
    }
    return true;
}  // end MdpDataObject::ReadSegment()

bool MdpDataObject::WriteSegment(UInt32             offset,
                                 char*              buffer,
                                 UInt16             size)
{
    if (size > 0)
    {
        ASSERT(IsOpen());
        ASSERT((offset + size) <= object_size);

        if (buffer)
        {
            UInt32 actual_size = 0;
            unsigned short actualSize = 0;
            if (virtualSize > 0)
            {
                actual_size = object_size - virtualSize;
            }
            else
            {
                actual_size = object_size;
            }
            // now calculating actualSize the data_ptr has right now
            if (offset <= actual_size)
            {
                if (offset == actual_last_offset)
                {
                    actualSize = (unsigned short)(actual_size - offset);
                }
                else
                {
                    actualSize = (unsigned short)size;
                }

                memcpy(data_ptr + offset, buffer, actualSize);
            }
        }
    }
    return true;
}  // end MdpDataObject::WriteSegment()


MdpFileObject::MdpFileObject(class MdpSession*  theSession,
                             MdpServerNode*     theSender,
                             UInt32             transportId,
                             char *             theMsgPtr)
    : MdpObject(MDP_OBJECT_FILE, theSession, theSender,
                transportId, theMsgPtr)
{
    path = (char*)malloc(MDP_PATH_MAX+1);
    memset(path, 0, (MDP_PATH_MAX+1));
}

MdpFileObject::~MdpFileObject()
{
    if (IsOpen()) Close();
    // Unlink _receive_ files which are incomplete
    if (sender && TxPending())
    {
        char full_name[MDP_PATH_MAX];
        strncpy(full_name, path, MDP_PATH_MAX);
        int len = MIN(MDP_PATH_MAX, strlen(full_name));
        int name_len = MIN(info_size, MDP_PATH_MAX-len);
        strncpy(full_name+len, info, name_len);
        if ((name_len+len) < MDP_PATH_MAX)
            full_name[name_len+len] = '\0';
        file.Unlink(full_name);
    }

    if (path)
        free(path);
    path = NULL;
}  // end ~MdpFileObject()


MdpError MdpFileObject::SetFile(const char* thePath, const char* theName)
{
    // (TBD) return appropriate error type
    if (!SetPath(thePath)) return MDP_ERROR;
    int name_len = MIN(MDP_PATH_MAX, strlen(theName));
    if (!SetInfo(theName, (UInt16)name_len))
    {
        SetPath("\0");
        return MDP_ERROR;
    }
    else
    {
        return MDP_ERROR_NONE;
    }
}  // end MdpFileObject::SetFile()

bool MdpFileObject::SetPath(const char* thePath)
{
    if (thePath)
    {
        int pathLen = strlen(thePath);
        memcpy(path, thePath, pathLen);
        path[pathLen] = '\0';
    }
    else
    {
        path[0] = '\0';
    }
    int len = MIN(MDP_PATH_MAX, strlen(path));
    if (MDP_PROTO_PATH_DELIMITER != path[len-1])
    {
        if (len < MDP_PATH_MAX)
        {
            path[len++] = MDP_PROTO_PATH_DELIMITER;
            if (len < MDP_PATH_MAX) path[len] = '\0';
        }
        else
        {
            path[0] = '\0';
            return false;
        }
    }
    return true;
}  // end MdpFileObject::SetPath()


// Set file object name ... if "theInfo" is NULL,
// a temporary name is created
bool MdpFileObject::SetInfo(const char* theInfo, unsigned short infoSize)
{
    // Skip leading MDP_PROTO_PATH_DELIMITER if given in the name
    if (theInfo && (MDP_PROTO_PATH_DELIMITER == theInfo[0]))
    {
        theInfo++;
        infoSize--;
    }
    bool create_temp_name = false;
    char new_name[MDP_PATH_MAX];
    memset(new_name, 0, MDP_PATH_MAX);

    char *name_ptr = NULL;

    if (IsClientObject())
    {
        if (theInfo)
        {
            if (!session->ArchiveMode())
            {
                // Does target name file already exist?
                // We don't want to overwrite files in this mode
                strncpy(new_name, session->ArchivePath(), MDP_PATH_MAX);
                int len = MIN(MDP_PATH_MAX, strlen(new_name));
                name_ptr = new_name + len;
                unsigned int name_len = MIN(infoSize, MDP_PATH_MAX-len);
                strncat(new_name, theInfo, name_len);
                if ((name_len + len) < MDP_PATH_MAX)
                    new_name[name_len+len] = '\0';

                // Flatten new file name for temp cache mode as needed
                char *ptr = name_ptr;
                char *end = new_name + MDP_PATH_MAX;
                while ((ptr < end) && (*ptr != '\0'))
                {
                    if (MDP_PROTO_PATH_DELIMITER == *ptr) *ptr = '_';
                    ptr++;
                }

                // Uncomment this if you don't want to overwrite
                // existing files of the same name in the recv cache directory
                if (MdpFileExists(new_name)) create_temp_name = true;

                // The below uses a temp name only when the recv file name already
                // exists _and_ is "busy" ... if the file isn't busy it
                // gets overwritten
                // if (MdpFileIsLocked(new_name)) create_temp_name = true;
            }
            else
            {
                strncpy(new_name, path, MDP_PATH_MAX);
                int len = MIN(MDP_PATH_MAX, strlen(new_name));
                name_ptr = new_name + len;
                unsigned int name_len = MIN(infoSize, MDP_PATH_MAX-len);
                strncat(new_name, theInfo, name_len);
                if ((name_len+len) < MDP_PATH_MAX)
                    new_name[name_len+len] = '\0';
            }
        }
        else
        {
            create_temp_name = true;
        }
    }
    else
    {
        ASSERT(theInfo);
        strncpy(new_name, path, MDP_PATH_MAX);
        int len = strlen(new_name);
        len = MIN(MDP_PATH_MAX, len);
        name_ptr = new_name + len;
        unsigned int name_len = MDP_PATH_MAX-len;
        name_len = MIN(infoSize, name_len);
        strncat(new_name, theInfo, name_len);
        if ((name_len+len) < MDP_PATH_MAX)
            new_name[name_len+len] = '\0';
    }

    if (create_temp_name)
    {
        strncpy(new_name, session->ArchivePath(), MDP_PATH_MAX);
        int len = strlen(new_name);
        len = MIN(MDP_PATH_MAX, len);
        // Need at least 9 spare characters for mdpXXXXXX temp name
        if (len > (MDP_PATH_MAX - 9))
        {
            printf("mdp: Error creating temporary file - name too long!");
            return false;
        }
        strcat(new_name, "mdpXXXXXX");
#ifdef MDP_FOR_WINDOWS
        char* ptr = _mktemp(new_name);
        if (!ptr)
        {
            printf("mdp: Error creating temporary file name!");
            return false;
        }
#else
        int fd = mkstemp(new_name);
        if (fd < 0)
        {
            printf("mdp: Error creating temporary file name!");
            return false;
        }
        else
        {
            close(fd);
            unlink(new_name);
        }
#endif  // if/else WIN32
        // Point to beginning of file portion of new_name
        name_ptr = strrchr(new_name, MDP_PROTO_PATH_DELIMITER);
        if (name_ptr)
            name_ptr++;
        else
            name_ptr = new_name;

        // Append desired file name to temp name if possible
        // This gives us a clue as to the file's actual name & type
        if (theInfo)
        {
            int len = strlen(new_name);
            len = MIN(MDP_PATH_MAX, len);
            if (len < MDP_PATH_MAX)
            {
                strncat(new_name, "-", MDP_PATH_MAX - len);
                len++;
            }
            int space = MAX(0, MDP_PATH_MAX-len);
            int oldlen = MIN(MDP_PATH_MAX, infoSize);
            if (oldlen >= space)
            {
                theInfo += (oldlen-space);
                strncpy(new_name + len, theInfo, space);
            }
            else
            {
                space = oldlen;
                strncpy(new_name+len, theInfo, space);
                new_name[len+space] = '\0';
            }

            if (IsClientObject() && !session->ArchiveMode())
            {
                // Flatten theInfo so directories aren't created
                char* ptr = new_name+len;
                char* end = ptr + space;
                while ((ptr < end) && (*ptr != '\0'))
                {
                    if (MDP_PROTO_PATH_DELIMITER == *ptr) *ptr = '_';
                    ptr++;
                }
            }
        }
        // cache temp file name in global MdpFileCache variable
        MdpData* mdpData = (MdpData*)Session()->GetNode()->appData.mdp;
        mdpData->temp_file_cache->CacheFile(new_name);
    }

    // If file is open, attempt to rename it
    if (file.IsOpen())
    {
        char old_name[MDP_PATH_MAX];
        memset(old_name, 0, MDP_PATH_MAX);
        strncpy(old_name, path, MDP_PATH_MAX);
        int len = MIN(MDP_PATH_MAX, strlen(old_name));
        unsigned int name_len = MIN(info_size, MDP_PATH_MAX-len);
        strncat(old_name, info, name_len);
        // Don't touch MdpFileObject path/name if Rename fails
        if (!file.Rename(old_name, new_name))
            return false;
    }

    // Note: "path" includes trailing MDP_PROTO_PATH_DELIMITER
    unsigned int path_len = name_ptr - new_name;
    strncpy(path, new_name, path_len);
    if (path_len < MDP_PATH_MAX) path[path_len] = '\0';

    unsigned int name_len = MIN(MDP_PATH_MAX-path_len, strlen(name_ptr));
    unsigned short max_name_len = 0;
    if (sender)
        max_name_len = sender->SegmentSize();
    else
        max_name_len = session->SegmentSize();
    name_len = MIN(name_len, max_name_len);
    if ((path_len+name_len) < max_name_len)
    {
        name_ptr[name_len] = '\0';
        name_len++;
    }

    return (MdpObject::SetInfo(name_ptr, (UInt16)name_len));
}  // end MdpFileObject::SetInfo()


// Returns 0 if all is OK, error code otherwise
MdpError MdpFileObject::Open()
{
    ASSERT(!IsOpen());
    ASSERT(info);
    char fileName[MDP_PATH_MAX];
    strncpy(fileName, path, MDP_PATH_MAX);
    unsigned int len = MIN(MDP_PATH_MAX, strlen(fileName));
    unsigned int name_len = MIN(info_size, MDP_PATH_MAX-len);
    strncat(fileName, info, name_len);
    if ((len+name_len) < MDP_PATH_MAX)
        fileName[len+name_len] = '\0';
    if (sender)
    {
        // If there's a sender, we're receiving the file
        // Don't open files that are locked
        if (MdpFileIsLocked(fileName))
        {
            printf("mdp: Error trying to open locked file for recv!\n");
            return MDP_ERROR_FILE_LOCKED;
        }
        else
        {
            if (file.Open(fileName, O_WRONLY | O_CREAT | O_TRUNC))
            {
                if (sender) file.Lock();
            }
            else
            {
                printf("mdp: Recv file.Open() error!\n");
                return MDP_ERROR_FILE_OPEN;
            }
        }
    }
    else
    {
        // We're sending the file, so open it for reading
        if (file.Open(fileName, O_RDONLY))
        {
            UInt32 size = file.Size();
            // We now allow ZERO size files
            SetObjectSize(size);
        }
        else
        {
            return MDP_ERROR_FILE_OPEN;
        }
    }
    return MDP_ERROR_NONE;
}  // end MdpFileObject::Open()

void MdpFileObject::Close()
{
    if (IsOpen())
    {
        MdpObject::Close();
        if (sender) file.Unlock();
        file.Close();
    }
}  // end MdpFileObject::Close()


bool MdpFileObject::ReadSegment(UInt32 offset,
                                char*  buffer,
                                UInt16* size,
                                UInt16* actualSize,
                                char** data_buffer_ptr)
{
    ASSERT(IsOpen());
    if (offset == last_offset)
    {
        *size = (UInt16)(object_size - last_offset);
        // Clear tail if it's the last short segment
        memset(&buffer[*size], 0, (segment_size - *size));
    }
    else
    {
        *size = (UInt16)segment_size;
    }

    *actualSize = *size;

    if (offset != file.Offset())
    {
        if (!file.Seek(offset))
        {
            printf("mdp: file.Seek() error!");
            return false;
        }
    }
    int nbytes = file.Read(buffer, *size);
    if (nbytes > 0) file.SetOffset(file.Offset() + nbytes);
    return ((int)*size == nbytes);
}  // end MdpFileObject::Read()

bool MdpFileObject::WriteSegment(UInt32             offset,
                                 char*              buffer,
                                 UInt16             size)
{
    ASSERT(IsOpen());
    if (offset != file.Offset())
    {
        if (!file.Seek(offset)) return false;
    }
    int nbytes =  size;
    size = (UInt16)file.Write(buffer, nbytes);
    if (size > 0) file.SetOffset(file.Offset() + (UInt32)size);

    return ((int)size == nbytes);
}  // end MdpFileObject::Write()


/*********************************************************************
 * MdpObjectList implementation (for simple lists for now)
 *  (linked-list ordered by "windowed" object_id)
 */

MdpObjectList::MdpObjectList()
    : head(NULL), tail(NULL), object_count(0),
      byte_count(0)
{
}

MdpObjectList::~MdpObjectList()
{
    Destroy();  // Empty before destruction
}


// Search list starting at head
MdpObject *MdpObjectList::FindFromHead(UInt32 transport_id)
{
    MdpObject *next = head;
    while (next)
    {
        if (next->transport_id == transport_id)
            return next;
        else
            next = next->next;
    }
    return NULL;
}  // end MdpObjectList::FindFromHead()

// Search list starting at tail
MdpObject *MdpObjectList::FindFromTail(UInt32 transport_id)
{
    MdpObject *prev = tail;
    while (prev)
    {
        if (prev->transport_id == transport_id)
            return prev;
        else
            prev = prev->prev;
    }
    return NULL;
}  // end MdpObjectList::FindFromTail()

MdpObject *MdpObjectList::Find(MdpObject *theObject)
{
    MdpObject *next = head;
    while (next)
    {
        if (next == theObject)
            return next;
        else
            next = next->next;
    }
    return NULL;
}  // end MdpObjectList::Find()


// "Windowed" ordered, linked-list insertion, searches from tail
void MdpObjectList::Insert(MdpObject *theObject)
{
    ASSERT(theObject);
    object_count++;
    byte_count += theObject->Size();
    theObject->list = this;
    UInt32 id = theObject->transport_id;
    MdpObject *prev = tail;
    while (prev)
    {
        ASSERT(prev->transport_id != id);  // Shouldn't have duplicate objects on list
        // "Windowed" delta calculation
        UInt32 diff = id - prev->transport_id;
        if ((diff < (UInt32) MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER) && (id < prev->transport_id)))
        {
            // Insert theObject after prev
            theObject->next = prev->next;
            if (theObject->next)
                prev->next->prev = theObject;
            else
                tail = theObject;
            prev->next = theObject;
            theObject->prev = prev;
            return;
        }
        else
        {
            // Move on up the list
            prev = prev->prev;
        }
    }
    // theObject goes to top of list
    theObject->next = head;
    if (theObject->next)
        head->prev = theObject;
    else
        tail = theObject;
    head = theObject;
    theObject->prev = NULL;
}  // end MdpObjectList::Insert()


void MdpObjectList::Remove(MdpObject *theObject)
{
    ASSERT(theObject);
    object_count--;
    byte_count -= theObject->Size();
    if (theObject->prev)
        theObject->prev->next = theObject->next;
    else
        head = theObject->next;
    if (theObject->next)
        theObject->next->prev  = theObject->prev;
    else
        tail = theObject->prev;
    theObject->list = (MdpObjectList *) NULL;
}  // end MdpObjectList::RemoveObject()

// Behead the list and return a pointer to the head
MdpObject *MdpObjectList::RemoveHead()
{
    MdpObject *theObject = head;
    if (theObject)
    {
        object_count--;
        byte_count -= theObject->Size();
        head = theObject->next;
        if (head)
            head->prev = NULL;
        else
            tail = NULL;
        theObject->list = NULL;
    }
    return theObject;
}  // end MdpObjectList::GetNextObject()

void MdpObjectList::Destroy()
{
    MdpObject *next = head;
    while (next)
    {
        head = next->next;
        if (next->IsOpen()) next->Close();
        delete next;
        next = head;
    }
    tail = NULL;
    object_count = 0;
    byte_count = 0;
}  // end MdpObjectList::Destroy()
