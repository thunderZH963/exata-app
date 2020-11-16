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

#ifndef _MDP_OBJECT
#define _MDP_OBJECT

#include <stdlib.h>
#include "mdpBitMask.h"   // For bit mask routines
#include "mdpMessage.h"  // for some protocol limits (e.g. OBJECT_NAME_MAX)
#include "mdpItem.h"
#include "mdpEncoder.h"
#include "mdpProtoTimer.h"

//typedef UInt32 MdpObjectTransportId;

/* Mdp "Notify" codes */
enum MdpNotifyCode
{
    MDP_NOTIFY_ERROR,
    MDP_NOTIFY_TX_OBJECT_START,
    MDP_NOTIFY_TX_OBJECT_FIRST_PASS,
    MDP_NOTIFY_TX_OBJECT_ACK_COMPLETE,
    MDP_NOTIFY_TX_OBJECT_FINISHED,
    MDP_NOTIFY_TX_QUEUE_EMPTY,
    MDP_NOTIFY_RX_OBJECT_START,
    MDP_NOTIFY_RX_OBJECT_INFO,
    MDP_NOTIFY_RX_OBJECT_UPDATE,
    MDP_NOTIFY_RX_OBJECT_COMPLETE,
    MDP_NOTIFY_OBJECT_DELETE,
    MDP_NOTIFY_SERVER_CLOSED,
    MDP_NOTIFY_REMOTE_SERVER_INACTIVE
};

/****************************************************************
 * "Vectors" are simply data chunks (arrays of type "char") which
 * are used for MDP data messages and receive data buffering.  A
 * vector corresponds to one "segment" of an MdpObject.  We have
 * "vector pools" which are simply pre-allocated data arrays available
 * for use in an MdpSession.
 */

class MdpVectorPool
{
    // Members
    protected:
        UInt32   vector_size;
        UInt32   vector_count_actual;
        UInt32   vector_count;
        UInt32   vector_total;
        char     *vector_list;
        UInt32   peak_usage;     // for buffer usage reports
        UInt32   overrun_count;  // for buffer usage reports
        int      overrun_flag;   // for buffer usage reports

    // Methods
    public:
        MdpVectorPool();
        virtual ~MdpVectorPool();
        virtual UInt32 Count() {return vector_count;}
        UInt32 Size() {return vector_size;}
        UInt32 Total() {return vector_total;}
        UInt32 CountActual() {return vector_count_actual;}

        /*virtual*/ UInt32 Init(UInt32 count, UInt32 size);
        /*virtual*/ void Destroy();
        /*virtual*/ char *Get();
        /*virtual*/ void Put(char *vector);
        UInt32 PeakValue()
            { return peak_usage;}
        UInt32 PeakUsage()
            {return (peak_usage * vector_size);}
        UInt32 Overruns() {return overrun_count;}

        bool IsVectorExist();
        void IncreaseVectorCountUsage();
        void DecreaseVectorCountUsage();
};


/****************************************************************
 * MdpBlock - Mid level  MDP data entity ... The MdpBlock is
 *            a basic unit of MDP's reliability protocol.  Up
 *            to 256 "vectors" (data and parity) comprise an MDP
 *            block.
 */

// MdpBlock status flags
const int MDP_BLOCK_FLAG_TX_ACTIVE       = 0x01;
const int MDP_BLOCK_FLAG_IN_REPAIR       = 0x02;
const int MDP_BLOCK_FLAG_PARITY_READY    = 0x04;


class MdpBlock
{
    friend class MdpBlockBuffer;
    friend class MdpBlockBufferIterator;
    friend class MdpBlockPool;

    // Members
    private:
        UInt32          id;
        unsigned char   block_size;     // No. of vectors in block
        char            **dVec;         // array of vector pointers
        short           *dVecSizeArray; // for storing the size of respective
                                        // vectors in **dVec based on index
        int             status;
        unsigned char   erasure_count;   // how many marks in data portion of vector_mask
        unsigned char   parity_count;    // how many parity vectors we have
        unsigned char   parity_offset;

        MdpBitMask      vector_mask;     // marks segments pending transmission
        MdpBitMask      repair_mask;     // marks segments needing repair

        MdpBlock        *prev, *next;

    // Methods
    public:
        MdpBlock();
        ~MdpBlock();
        bool Init(int blockSize);
        void Destroy();

        // Populate any empty slots with vectors from given pool
        bool Fill(MdpVectorPool *pool, int num_vectors);  // returns false if pool empties too soon
        // Fills block with zero filled vectors, marking erasures in vector_mask
        bool FillZero(MdpVectorPool *pool, int vector_size, int num_vectors);

        // Return attached vectors to the given pool
        void Empty(MdpVectorPool *pool);

        void ResetVectorSizeArray();

        // These routines manipulate the block's vector_mask
        void ClearMask() // clear all bits
        {
            vector_mask.Clear();
        }
        void ResetMask() // set all bits
        {
            vector_mask.Reset();
        }
        void SetMask(int index) {vector_mask.Set(index);}
        void UnsetMask(int index) {vector_mask.Unset(index);}
        void SetMaskBits(int index, int count)
            {vector_mask.SetBits(index, count);}
        void UnsetMaskBits(int index, int count)
            {vector_mask.UnsetBits(index, count);}
        unsigned int FirstSet() {return vector_mask.FirstSet();}
        unsigned int NextSet(int index) {return vector_mask.NextSet(index);}
        const char* Mask() {return vector_mask.Mask();}
        unsigned int MaskLen() {return vector_mask.MaskLen();}
        void AddRawMask(const char* mask, int mask_len)
            {vector_mask.AddRawMask(mask, mask_len);}
        void DisplayMask() {vector_mask.Display();}

        void DisplayRepairMask() {repair_mask.Display();}
        void UnsetRepair(int index) {repair_mask.Unset(index);}
        void SetRepairs(int index, int count)
            {repair_mask.SetBits(index, count);}
        void UnsetRepairs(int index, int count)
            {repair_mask.UnsetBits(index, count);}
        void ClearRepairMask() {repair_mask.Clear();}
        const char* RepairMask() {return repair_mask.Mask();}
        bool RepairPending() {return repair_mask.IsSet();}
        void AddRepairs(char *theMask, int theLen)
            {repair_mask.AddRawMask(theMask, theLen);}
        void ActivateRepairs()
        {
            vector_mask.Add(&repair_mask);
            repair_mask.Clear();
        }
        void FilterRepairs() {repair_mask.XCopy(vector_mask);}
        bool RepairsInRange(unsigned int start, unsigned int end)
        {
            return (repair_mask.NextSet(start) < end);
        }
        void CaptureRepairs() {repair_mask.Copy(vector_mask);}


        void TxInit(UInt32 blockId, int maxData)
        {
            id = blockId;
            // Mark DATA vectors for transmission
            repair_mask.Clear();
            vector_mask.Clear();
            vector_mask.SetBits(0, maxData);
            erasure_count = (unsigned char)maxData;
            parity_count = 0;
            parity_offset = 0;
            status = 0;
        }

        void RxInit(UInt32 block_id, int maxData, int maxParity)
        {
            id = block_id;
            repair_mask.Clear();
            vector_mask.Clear();
            // mark everything as erasures
            vector_mask.SetBits(0, maxData + maxParity);
            erasure_count = (unsigned char)maxData;
            parity_count = 0;
            parity_offset = 0;
            status = 0;
        }
        int GetNextTxVector()
        {
            int vid = vector_mask.FirstSet();
            if (vid < block_size) vector_mask.Unset(vid);
            return vid;
        }
        bool TxPending() {return vector_mask.IsSet();}

        unsigned int ParityCount() {return (parity_count);}
        void IncrementParityCount() {parity_count++;}
        void SetParityCount(unsigned int value) {parity_count = (unsigned char)value;}
        unsigned int ErasureCount() {return erasure_count;}
        void DecrementErasureCount() {erasure_count--;}

        unsigned int ParityOffset() {return (parity_offset);}
        void SetParityOffset(unsigned int value) {parity_offset = (unsigned char)value;}

        bool TxActive() {return (0 != (status & MDP_BLOCK_FLAG_TX_ACTIVE));}
        bool InRepair() {return (0 != (status & MDP_BLOCK_FLAG_IN_REPAIR));}
        bool ParityReady() {return (0 != (status & MDP_BLOCK_FLAG_PARITY_READY));}
        void SetStatusFlag(int flag) {status |= flag;}
        void ClearStatusFlag(int flag) {status &= ~flag;}

        // Attach a vector to the block
        void AttachVector(char *vector, int index)
        {
            ASSERT(index < block_size);
            ASSERT(vector);
            ASSERT(!dVec[index]);
            dVec[index] = vector;
        }

        // Remove a particular vector
        char *RemoveVector(int index)
        {
            ASSERT(index < block_size);
            char *vector = dVec[index];
            dVec[index] = NULL;
            return vector;
        }

        UInt32 Id() {return id;}
        MdpBlock *Next() {return next;}
        char **VectorList(int index = 0) {return &dVec[index];}
        char *Vector(int index)
        {
            ASSERT(dVec);
            ASSERT(index < block_size);
            return dVec[index];
        }
        bool IsFilled(int index) {return (bool)((dVec[index] != NULL) && (dVecSizeArray[index] != -1));}

        bool IsVectorExist(int index) {return (bool)(dVecSizeArray[index] != -1);}

        void SetVectorSize(short size, int index)
        {
            dVecSizeArray[index] = size;
        }

        void UnsetVectorSize(int index)
        {
            dVecSizeArray[index] = -1;
        }

        void AddVectorSize(short size, int index)
        {
            dVecSizeArray[index] += size;
        }

        short ReturnActualVectorSize(int index)
        {
            return dVecSizeArray[index];
        }
};  // end class MdpBlock


class MdpBlockPool
{
    protected:
        int             block_size;
        int             block_count_actual;
        UInt32          block_count;
        UInt32          block_total;
        MdpBlock        *block_list;
        UInt32          peak_usage;     // for buffer usage reports
        UInt32          overrun_count;  // for buffer usage reports
        int             overrun_flag;   // for buffer usage reports

    public:
        MdpBlockPool();
        ~MdpBlockPool();
        /*virtual*/ UInt32 Init(UInt32 blockCount, int blockSize);
        /*virtual*/ void Destroy();
        /*virtual*/ MdpBlock *Get();
        /*virtual*/ void Put(MdpBlock *block);
        /*virtual*/ UInt32 Count() {return block_count;}
        UInt32 Total() {return block_total;}
        UInt32 CountActual() {return block_count_actual;}

        UInt32 PeakValue()
        {return peak_usage;}
        UInt32 PeakUsage()
        {return (peak_usage * (sizeof(MdpBlock) +
                      block_size * sizeof(char *)));}
        UInt32 Overruns() {return overrun_count;}
};


// This class stores blocks for an MdpObject
// It's indexed so we can quickly find blocks by their Id
// And it's a linked list with staler blocks towards the tail
// (This will let us prune stale blocks when memory constrained)

class MdpBlockBuffer
{
    friend class MdpBlockBufferIterator;

    // Members
    private:
        MdpBlock        *head, *tail; // Linked list of the blocks
        UInt32          block_count;  // No. of blocks in buffer
        UInt32          index_len;    // Length of index
        MdpBlock        **index;      // Indexed array of the blocks

    // Methods
    public:
        MdpBlockBuffer();
        ~MdpBlockBuffer();
        bool Index(UInt32 max_blocks);
        void Empty(MdpBlockPool *bpool, MdpVectorPool *vpool);
        void Destroy();
        MdpBlock *GetBlock(UInt32 theIndex);
        void Prepend(MdpBlock *theBlock);
        void Remove(MdpBlock *theBlock);
        MdpBlock *Head() {return head;}
        MdpBlock *Tail() {return tail;}
        MdpBlock *OldestBlock() {return tail;}
        void FreeOldestBlock(MdpBlockPool *bpool, MdpVectorPool *vpool)
        {
            ASSERT(tail);
            MdpBlock *blk  = tail;
            Remove(blk);
            blk->Empty(vpool);
            bpool->Put(blk);
        }
        bool IsEmpty() {return (head == NULL);}
        bool IsIndexed() {return (index != NULL);}

        MdpBlock* Index0() {return index[0];}
        MdpBlock** theIndex() {return index;}

    private:
        void Touch(MdpBlock *theBlock);
};

// Helper MdpBlockBufferIterator class
class MdpBlockBufferIterator
{
    // Members
    private:
        MdpBlock *next;

    public:
        MdpBlockBufferIterator(MdpBlockBuffer &theBuffer);
        MdpBlock *Next();
};




/****************************************************************
 * MdpObject - Highest level MDP data entity ... corresponds to a
 *            file or other information object being transferred.
 */

// Mdp major object types
enum MdpObjectType
{
    MDP_OBJECT_INVALID,
    MDP_OBJECT_FILE,
    MDP_OBJECT_DATA,
    MDP_OBJECT_SIM
};

// Object Status Flags
const int MDP_OBJECT_FLAG_HAVE_INFO = 0x01;

enum MdpNackingMode
{
    MDP_NACKING_NONE,
    MDP_NACKING_INFOONLY,
    MDP_NACKING_NORMAL
};

class MdpObject
#ifdef USE_INHERITANCE
    : public ProtoTimerOwner
#endif // USE_INHERITANCE
{
    friend class MdpSession;
    friend class MdpServerNode;
    friend class MdpObjectList;
    friend class MdpObjectListIterator;

    public:
    // Methods
        MdpObject(MdpObjectType      theType,
                  class MdpSession*  theSession,
                  MdpServerNode*     theSender,
                  UInt32             transportId,
                  char*              theMsgPtr = NULL,
                  Int32              theVirtualSize = 0);
        virtual ~MdpObject();
        MdpObjectType Type() {return type;}
        UInt32 SenderId();
        UInt32 TransportId() {return transport_id;}
        const char *Info() {return info;}
        unsigned short InfoSize() {return info_size;}
        UInt32 Size() {return object_size;}
        UInt32 RecvBytes() {return data_recvd;}
        bool IsClientObject()
                      {return ((class MdpServerNode*) NULL != sender);}
        bool IsServerObject()
                      {return ((class MdpServerNode*) NULL == sender);}
        UInt32 LocalNodeId();

        enum MdpNackingMode NackingMode() {return nacking_mode;}
        void SetNackingMode(MdpNackingMode theMode)
            {nacking_mode = theMode;}

        void Notify(enum MdpNotifyCode notifyCode, MdpError errorCode);
        void SetUserData(const void* userData)
            {user_data = userData;}
        const void* GetUserData()
            {return user_data;}
        void SetMsgPtr(char* theMsgPtr)
        {
            msgPtr = theMsgPtr;
        }
        char* GetMsgPtr()
        {
            return msgPtr;
        }
        void SetVirtualSize(Int32 theVirtualSize)
        {
            virtualSize = theVirtualSize;
        }
        Int32 GetVirtualSize()
        {
            return virtualSize;
        }
        void AddVirtualSize(Int32 theVirtualSize)
        {
            virtualSize = virtualSize + theVirtualSize;
        }
        bool FirstPass() {return first_pass;}
        void SetFirstPass() {first_pass = true;}
        void ClearFirstPass() {first_pass = false;}
        bool NotifyPending() {return (0 != notify_pending);}
        bool WasAborted() {return notify_abort;}
        MdpError RxAbort();
        MdpError TxAbort();
        void SetError(MdpError theError) {notify_error = theError;}
        MdpSession* Session() {return session;}
        MdpObject* Next() {return next;}

        bool OnRepairTimeout();
        MdpProtoTimer getRepairTimer(){return repair_timer;}

        clocktype GetTxCompletionTime() { return tx_completion_time;}
        void SetTxCompletionTime(clocktype time)
        {
            tx_completion_time = time;
        }

    protected:
    // Members
        // General object info
        MdpObjectType           type;
        class MdpSession*       session;
        class MdpServerNode*    sender;  // NULL sender means locally originated object
        UInt32                  transport_id;
        char*                   info;     // optional info field (file objects use it for file names)
        unsigned short          info_size;
        UInt32                  object_size;
        int                     status;

        UInt32                  data_recvd;  // No. of data bytes successfully recv'd

        // Block info
        unsigned int            ndata;          // Max no. of data segments per block
        unsigned int            nparity;        // Max no. of parity segments per block
        unsigned int            segment_size;   // Bytes per segment (packet)
        UInt32                  block_size;     // Max no. of data bytes per block

        // Block parameters based on object_size & Block Info
        UInt32                  last_block_id;  // Id of last block in object
        int                     last_block_len; // No. of data vectors in last block
        UInt32                  last_offset;    // Offset of last data segment

        UInt32                  actual_last_block_id; //this is for virtual payload support
        int                     actual_last_block_len; //this is for virtual payload support
        UInt32                  actual_last_offset; //this is for virtual payload support

        // Timers (this is used for locally originated objects only)
        MdpProtoTimer           repair_timer;
        clocktype               tx_completion_time;

        UInt32                  current_block_id;
        UInt32                  current_vector_id;
        MdpNackingMode          nacking_mode;

        // State for transporting the object
        bool                    info_transmit_pending;
        bool                    info_repair_pending;
        MdpBitMask              transmit_mask; // Transmission-pending blocks
        MdpBitMask              repair_mask;   // Used for snapshots of repair state
        MdpBlockBuffer          block_buffer;
        bool                    first_pass;    // Denotes first pass transmission

        int                     notify_pending;
        bool                    notify_abort;
        MdpError                notify_error;
        const void*             user_data;
        //for saving qualnet message ptr
        char*                   msgPtr;
        Int32                   virtualSize;

        MdpObject*              prev;          // for object linked lists
        MdpObject*              next;
        class MdpObjectList*    list;

    // Methods
        //MdpObject(MdpObjectType theType, class MdpSession* theSession,
        //          MdpServerNode* theSender, UInt32 transportId);
        virtual MdpError Open() = 0;
        virtual void Close();
        virtual bool IsOpen() = 0;
        virtual bool ReadSegment(UInt32 offset,
                                char* buffer,
                                UInt16* size,
                                UInt16* actualSize,
                                char** data_buffer_ptr = NULL) = 0;
        virtual bool WriteSegment(UInt32 offset, char* buffer, UInt16 size) = 0;
        virtual bool SetInfo(const char *theInfo, unsigned short infoSize);

        void SetStatusFlag(int value) {status |= value;}
        void UnsetStatusFlag(int value) {status &= ~value;}

        bool HaveInfo() {return (!info_transmit_pending);}
        void SetHaveInfo(bool value)
        {
            if (value)
                info_transmit_pending = false;
            else
                info_transmit_pending = true;
        }
        void SetObjectSize(UInt32 theSize)
        {
            ASSERT(!block_size);
            object_size = theSize;
        }
        bool TxInit(unsigned char numData, unsigned char numParity,
                    unsigned int segmentSize)
        {
            ASSERT(IsOpen());
            //ASSERT(object_size);
            block_buffer.Destroy();  // Make sure object wasn't already init'd
            transmit_mask.Destroy();
            repair_mask.Destroy();
            segment_size = segmentSize;
            ndata = numData;
            nparity = numParity;
            block_size = numData * segmentSize;
            if (info)
                info_transmit_pending = true;
            else
                info_transmit_pending = false;
            info_repair_pending = false;
            current_block_id = 0;
            return Index();  // "Index()" inits transmit_mask
        }
        bool TxPending() {return (transmit_mask.IsSet() || info_transmit_pending);}
        bool RxInit(unsigned char numData, unsigned char numParity,
                    unsigned int segmentSize)
        {
            ASSERT(IsOpen());
            //ASSERT(object_size);
            block_buffer.Destroy();  // Make sure object wasn't already init'd
            transmit_mask.Destroy();
            repair_mask.Destroy();
            segment_size = segmentSize;
            ndata = numData;
            nparity = numParity;
            block_size = numData * segmentSize;
            info_transmit_pending = true;
            info_repair_pending = false;
            current_block_id = 0;
            return Index();  // "Index()" inits transmit_mask
        }
        bool RxPending() {return (transmit_mask.IsSet() || info_transmit_pending);}
        bool RepairPending();
        bool ClientRepairCheck(UInt32 block_id, bool repair_timer_active);
        void ClientHandleRepairNack(MdpRepairNack *theNack);
        bool ClientFlushObject(bool repair_timer_active)
            {return ClientRepairCheck(last_block_id + 1, repair_timer_active);}
        bool ServerHandleRepairNack(MdpRepairNack *theNack);

        bool Index();  // Prepares new object for transmission/reception

        MdpBlock *OldestBlock() {return block_buffer.OldestBlock();}
        void FreeOldestBlock(MdpBlockPool* bPool, MdpVectorPool* vPool)
            {block_buffer.FreeOldestBlock(bPool, vPool);}
        bool HaveBuffers() {return !block_buffer.IsEmpty();}
        void FreeBuffers();
        MdpBlock* ClientStealBlock(bool anyBlock, UInt32 blockId);
        MdpBlock* ServerStealBlock(bool anyBlock, UInt32 blockId);
        MdpMessage *BuildNextServerMsg(MdpMessagePool* mPool, MdpVectorPool* vPool,
                                       MdpBlockPool*   bPool, MdpEncoder* encoder);
        void BuildNack(MdpObjectNack* objectNack, bool current);
        bool CalculateBlockParity(UInt32 blockId, MdpBlock* theBlock,
                                  MdpEncoder* encoder);
        bool HandleRecvData(UInt32 dataOffset,
                            int parityId,
                            bool blockEnd,
                            char* dataPtr,
                            UInt16 dataLen,
                            UInt16 actualDataLen);

};  // end class MdpObject


class MdpFileObject : public MdpObject
{
    // Members
    private:
        //char path[MDP_PATH_MAX];
        char *path;
        MdpFile file;  // file descriptor (TBD-abstract this for cross-platform ports)

    public:
        MdpFileObject(class MdpSession*     theSession,
                      class MdpServerNode*  theSender,
                      UInt32                transportId,
                      char *                theMsgPtr = NULL);
        ~MdpFileObject();
        MdpError SetFile(const char* thePath, const char* theName);
        // MdpFileObjects currently use the "info" for file name
        // so we override the base class "SetInfo()" method
        virtual bool SetInfo(const char* theInfo, unsigned short infoSize);
        char* GetPath() {return path;}
        bool SetPath(const char* thePath);
        MdpError Open();
        void Close();
        bool IsOpen() {return file.IsOpen();}
        bool ReadSegment(UInt32 offset,
                         char* buffer,
                         UInt16* size,
                         UInt16* actualSize = 0,
                         char** data_buffer_ptr = NULL);
        bool WriteSegment(UInt32 offset, char* buffer, UInt16 size);
};  // end class MdpFileObject


class MdpDataObject : public MdpObject
{
    private:
        char *data_ptr;

    public:
        MdpDataObject(class MdpSession*         theSession,
                      class MdpServerNode*      theSender,
                      char *                    theMsgPtr,
                      Int32                     theVirtualSize,
                      UInt32                    transportId,
                      UInt32                    objectSize);
        ~MdpDataObject();

        MdpError Open();

        void Close()
        {
            //MEM_free(data_ptr);
            //MdpObject::Close();
        }
        bool SetData(char* dataPtr, UInt32 dataLen);
        char* GetData(UInt32* dataLen)
        {
            *dataLen = object_size;
            return data_ptr;
        }
        char* GetActualData(UInt32* dataLen)
        {
            if (virtualSize > 0)
            {
                *dataLen = object_size - virtualSize;
            }
            else
            {
                *dataLen = object_size;
            }
            return data_ptr;
        }
        bool IsOpen() {return ((NULL != data_ptr)
                               || (NULL != info)
                               || (object_size > 0));}
        bool ReadSegment(UInt32 offset,
                        char* buffer,
                        UInt16* size,
                        UInt16* actualSize,
                        char** data_buffer_ptr = NULL);
        bool WriteSegment(UInt32 offset, char* buffer, UInt16 size);
};  // end class MdpDataObject


// Ordered linked-list of MdpObjects

// We may want to make this into a Tree instead (if list grows long)
// Note: if tree is used ... items will generally be added in order
// of object_id ... so we may want to consider strategies for speeding
// search

class MdpObjectList
{
    friend class MdpObjectListIterator;
    // Members
    private:
        MdpObject   *head, *tail;
        UInt32      object_count;
        UInt32      byte_count;

    // Methods
    public:
        MdpObjectList();
        ~MdpObjectList();
        MdpObject *Find(MdpObject *theObject);
        MdpObject *FindFromHead(UInt32 transportId);
        MdpObject *FindFromTail(UInt32 transportId);
        void Insert(MdpObject *theObject);
        void Remove(MdpObject *theObject);
        MdpObject *RemoveHead();  // removes head
        MdpObject *Head() {return head;}
        MdpObject *Tail() {return tail;}
        bool IsEmpty() {return ((MdpObject *) NULL == head);}
        UInt32 ObjectCount() {return object_count;}
        UInt32 ByteCount() {return byte_count;}
        void Destroy();
};

class MdpObjectListIterator
{
    private:
        MdpObject *next;

    public:
        MdpObjectListIterator(MdpObjectList &list)
            : next(list.head) {}
        MdpObject *Next()
        {
            MdpObject *obj = next;
            next = (next ? next->next : (MdpObject *) NULL);
            return obj;
        }
        void Reset(MdpObjectList &list) {next = list.head;};
};



#endif // _MDP_OBJECT

