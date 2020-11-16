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


#ifndef _MDP_NODE
#define _MDP_NODE


#include "mdpObject.h"



// Pick a random number from 0..max
// the definition of this function is shifted in mdpNode.cpp
double UniformRand(double max, char* theSession = NULL);

inline double erand(double max, double groupSize, char* theSession)
{
    double lambda = log(groupSize) + 1;
    double x = UniformRand(lambda/max,theSession)+lambda/(max*(exp(lambda)-1));
    return ((max/lambda)*log(x*(exp(lambda)-1)*(max/lambda)));
}

// MdpNode base class
class MdpNode
{
    friend class MdpNodeTree;
    friend class MdpNodeList;

    public:
    // Construction
        MdpNode(UInt32 nodeId);
        virtual ~MdpNode();

    // Methods
        UInt32 Id() {return id;}
        void SetId(UInt32 value) {id = value;}

        MdpNode* NextInTree();
        MdpNode* PrevInTree();
        MdpNode* NextInList() {return right;}
        MdpNode* PrevInList() {return left;}
        void SetUserData(const void* userData)
            {user_data = userData;}
        const void* GetUserData()
            {return user_data;}
    protected:
    // Members
        UInt32          id;
        MdpNode*        left;
        MdpNode*        right;
        MdpNode*        parent;
        const void*     user_data;
};  // end class MdpNode

// Used for binary trees of MdpNodes
class MdpNodeTree
{
    public:
    // Methods
        MdpNodeTree();
        ~MdpNodeTree();
        MdpNode* FindNodeById(UInt32 node_id);
        void DeleteNode(MdpNode *theNode)
        {
            ASSERT(theNode);
            DetachNode(theNode);
            delete theNode;
        }
        void AttachNode(MdpNode *theNode);
        void DetachNode(MdpNode *theNode);
        void Destroy();
        MdpNode* Head();  // first item in ordered node tree

    private:
    // Members
        MdpNode* root;
    // Methods
        void DeleteAllNodes(MdpNode** theRoot);
};


class MdpNodeList
{
    public:
    // Construction
        MdpNodeList();
        ~MdpNodeList();

        MdpNode* FindNodeById(UInt32 nodeId);
        void Append(MdpNode* theNode);
        void Remove(MdpNode* theNode);
        MdpNode* Head() {return head;}
        void Destroy() {head = tail = NULL;}

    // Members
    private:
        MdpNode*                    head;
        MdpNode*                    tail;
};


// Some protocol robustness factors (TBD) move to mdpMessage.h ?
//#define MDP_DEFAULT_ROBUSTNESS    20  //shifted to file app_mdp.h

#define MDP_NODE_ACTIVITY_TIMEOUT_MIN   5.0

#define MDP_MSG_POOL_DEPTH    0  //300  // (TBD) what's a good metric for setting this?


// Receive object server synchronization status indicators
// Is the object "complete", "pending", "new" , or "out of range" ?
enum MdpRecvObjectStatus
{
    MDP_RECV_OBJECT_INVALID,
    MDP_RECV_OBJECT_NEW,
    MDP_RECV_OBJECT_PENDING,
    MDP_RECV_OBJECT_COMPLETE
};

class LossEventEstimator
{
    public:
        LossEventEstimator();
        void SetEventWindow(unsigned short windowDepth)
            {event_window = windowDepth;}
        void SetEventWindowTime(double theTime)
            {event_window_time = theTime;}
        bool ProcessRecvPacket(unsigned short theSequence,
                               BOOL ecnStatus,
                               Node* node);
        double LossFraction();
        double MdpLossFraction()
            {return ((loss_interval > 0.0) ? (1.0/loss_interval) : 0.0);}
        double TfrcLossFraction();
        UInt32 CurrentLossInterval() {return history[0];}
        bool NoLoss() {return no_loss;}
        void SetInitialLoss(double theLoss) {initial_loss = theLoss;}

    private:
    // Members
        bool            init;
        UInt32          lag_mask;
        unsigned int    lag_depth;
        UInt32          lag_test_bit;
        unsigned short  lag_index;

        unsigned short  event_window;
        unsigned short  event_index;
        double          event_window_time;
        double          event_index_time;
        bool            seeking_loss_event;

        bool            no_loss;
        double          initial_loss;

        double          loss_interval;  // EWMA of loss event interval

        UInt32              history[9];  // loss interval history
        double              discount[9];
        double              current_discount;
        static const double weight[8];

        void Init(unsigned short theSequence)
            {init = true; Sync(theSequence);}
        void Sync(unsigned short theSequence)
            {lag_index = theSequence;}
        void ChangeLagDepth(unsigned int theDepth)
        {
            theDepth = (theDepth > 20) ? 20 : theDepth;
            lag_depth = theDepth;
            lag_test_bit = 0x01 << theDepth;
        }
        int SequenceDelta(unsigned short a, unsigned short b);

};  // end class LossEventEstimator



// MdpServer class - used to keep state on servers in the session
class MdpServerNode : public MdpNode
#ifdef USE_INHERITANCE
    , public ProtoTimerOwner
#endif // USE_INHERITANCE
{
    public:
    // Construction
        MdpServerNode(UInt32 nodeId, class MdpSession* theSession);
        ~MdpServerNode();

    // Methods
        // Server information routines
        //void SetName(char* theName)
        //    {strncpy(name, theName, MDP_NODE_NAME_MAX);}
        //const char* Name() {return name;}
        void SetAddress(MdpProtoAddress* theAddr)
            {memcpy(&addr, theAddr, sizeof(MdpProtoAddress));}
        const MdpProtoAddress* Address() const {return &addr;}

        bool LocalRepresentative() {return local_representative;}

        // Server resource allocation routines
        bool Open();
        void Close();
        bool IsOpen() {return object_transmit_mask.IsInited();}
        bool Activate(UInt32 bufferSize, Int32 segment_pool_depth);
        void Deactivate();
        void Delete();

        // Resource mgmt routines
        void SetCoding(unsigned short segmentSize,
                       unsigned char numData,
                       unsigned char numParity)
        {
            segment_size = segmentSize;
            ndata = numData;
            nparity = numParity;
        }
        bool VerifyCoding(unsigned short segmentSize,
                          unsigned char numData,
                          unsigned char numParity)
        {
            return ((segment_size == segmentSize) &&
                    (ndata == numData) &&
                    (nparity == numParity));
        }
        bool ReclaimResources(MdpObject* theObject, UInt32 blockId);
        unsigned short SegmentSize() {return segment_size;}
        MdpBlockPool *BlockPool() {return &block_pool;}
        MdpBlock *BlockGetFromPool() {return block_pool.Get();}
        void BlockReturnToPool(MdpBlock *blk)
        {
            blk->Empty(&vector_pool);
            block_pool.Put(blk);
        }
        MdpVectorPool* VectorPool() {return &vector_pool;}
        char* VectorGetFromPool() {return vector_pool.Get();}
        void VectorReturnToPool(char *vect) {vector_pool.Put(vect);}
        void MessageReturnToPool(MdpMessage* msg) {msg_pool.Put(msg);}

        // Server packet loss estimation
        void UpdateLossEstimate(unsigned short theSequence,
                                BOOL ecnStatus);
        double LossEstimate() {return loss_estimator.LossFraction();}

        // Server round trip estimation
        double GrttEstimate() {return grtt_advertise;}
        void UpdateGrtt(unsigned char new_grtt_quantized);
        void CalculateGrttResponse(struct timevalue* ack_time);
        void HandleGrttRequest(MdpMessage* theMsg);
        unsigned char GrttReqSequence() {return grtt_req_sequence;}

        // Server object reception and repair state
        void Sync(UInt32 objectId);
        void HardSync(UInt32 objectId);
        bool ServerSynchronized() {return server_synchronized;}
        MdpRecvObjectStatus ObjectSequenceCheck(UInt32 object_id);
        void ObjectRepairCheck(UInt32 object_id,
                               UInt32 block_id);
        bool FlushServer(UInt32 object_id);
        MdpObject* FindRecvObjectById(UInt32 theId)
            {return live_objects.FindFromHead(theId);}
        MdpObject* NewRecvObject(UInt32   objectId,
                                 MdpObjectType   theType,
                                 UInt32          objectSize,
                                 Int32           virtualSize,
                                 const char*     theInfo,
                                 UInt16          infoSize);
        void ActivateRecvObject(UInt32 objectId,
                                class MdpObject* theObject);
        void DeactivateRecvObject(UInt32 objectId,
                                  class MdpObject* theObject);
        MdpObject* CurrentRecvObject() {return live_objects.Head();}
        MdpObject* LatestRecvObject() {return live_objects.Tail();}
        MdpObject* FindRecvObject(MdpObject* theObject)
            {return live_objects.Find(theObject);}
        void AcknowledgeRecvObject(UInt32 object_id);
        void HandleRepairNack(char* nackData, unsigned short nackLen);
        void HandleSquelchCmd(UInt32         syncId,
                              char*          squelchPtr,
                              UInt16         squelchLen);
        void Decode(char** vectorList, int numData, const char* erasureMask)
            {decoder.Decode(vectorList, numData, erasureMask);}

        // Server activity monitor
        bool IsActive() {return active;}
        void ResetActivityTimer();

        void Notify(enum MdpNotifyCode notifyCode, MdpObject* theObject,
                    MdpError errorCode);
        bool NotifyPending() {return (0 != notify_pending);}
        bool WasDeleted() {return notify_delete;}

        MdpSession* GetSessionPtr()
        {
            return session;
        }
        // Server statistics routines
        UInt32 PendingCount() {return live_objects.ObjectCount();}
        UInt32 PeakValue()
            {return (block_pool.PeakValue() + vector_pool.PeakValue());}
        UInt32 PeakUsage()
            {return (block_pool.PeakUsage() + vector_pool.PeakUsage());}
        UInt32 Overruns()
            {return (block_pool.Overruns() + vector_pool.Overruns());}
        UInt32 ReceivePendingLow()
            {return recv_pending_low;}
        MdpProtoTimer getRepairTimer(){return repair_timer;}
        MdpProtoTimer getAckTimer(){return ack_timer;}
        MdpProtoTimer getActivityTimer(){return activity_timer;}
        bool OnActivityTimeout();
        bool OnRepairTimeout();
        bool OnAckTimeout();
    private:
    // Members
        class MdpSession*   session;
        //char                name[MDP_NODE_NAME_MAX];
        int                 status;
        MdpProtoAddress     addr;

        MdpSlidingMask      object_transmit_mask;
        MdpSlidingMask      object_repair_mask;
        MdpObjectList       live_objects;   // objects recv'd from this node
        bool                server_synchronized;
        UInt32              recv_pending_low;
        UInt32              recv_pending_high;
        double              grtt_advertise; // Greatest round-trip time est. (sec)
        unsigned char       grtt_quantized; // quantized version of grtt estimate
        struct timevalue    last_grtt_req_send_time;
        struct timevalue    last_grtt_req_recv_time;
        unsigned char       grtt_req_sequence;
        MdpDecoder          decoder;
        unsigned short      segment_size;
        unsigned char       ndata, nparity;
        bool                active;
        MdpProtoTimer       activity_timer;

        //below two variables are used for optimizing the
        //memory usage for activity_timer
        clocktype           lastActivityTimerEnd;
        double              lastActivityTimerInterval;

        MdpProtoTimer       repair_timer;
        UInt32              current_object_id;
        MdpProtoTimer       ack_timer;
        UInt32              server_pos_ack_object_id;
        LossEventEstimator  loss_estimator;

        bool                local_representative;

        // Server node buffer pools
        MdpMessagePool      msg_pool;
        MdpBlockPool        block_pool;
        MdpVectorPool       vector_pool;
        bool                buffer_limited;

        int                 notify_pending;
        bool                notify_delete;

    // Methods
         // Timeout functions

};  // end class MdpServerNode

class MdpAckingNode : public MdpNode
{
    public:
    // Construction
        MdpAckingNode(UInt32 nodeId, class MdpSession* theSession);

    // Methods
        bool HasAcked() {return ack_status;}
        UInt32 LastAckObject() {return ack_object_id;}
        void SetLastAckObject(UInt32 theId);
        unsigned char AckReqCount() {return ack_req_count;}

        void DecrementAckReqCount() {ack_req_count--;}

    private:
    // Members
        class MdpSession* session;
        bool              ack_status;
        UInt32            ack_object_id;
        unsigned char     ack_req_count;
};  // end class MdpAckingNode

class MdpRepresentativeNode : public MdpNode
{
    public:
    // Construction
        MdpRepresentativeNode(UInt32 nodeId);

    // Methods
        unsigned char TimeToLive() {return ttl;}
        unsigned char DecrementTimeToLive() {return --ttl;}
        void ResetTimeToLive() {ttl = 5;}
        double RttEstimate() {return rtt_estimate;}
        void SetRttEstimate(double value)
        {
            rtt_estimate = value;
            rtt_rough = value;
        }
        double RttVariance() {return rtt_variance;}
        void SetRttVariance(double value) {rtt_variance = value;}
        double RttSqrt() {return rtt_sqrt;}
        void SetRttSqrt(double value) {rtt_sqrt = value;}

        void UpdateRttEstimate(double value);
        void UpdateRttEstimateNormal(double value);
        void UpdateRttEstimateAsymmetric(double value);

        double LossEstimate() {return loss_estimate;}
        void SetLossEstimate(double value) {loss_estimate = value;}
        double RateEstimate() {return rate_estimate;}
        void SetRateEstimate(double value) {rate_estimate = value;}
        unsigned char GrttReqSequence() {return grtt_req_sequence;}
        void SetGrttReqSequence(unsigned char value)
            {grtt_req_sequence = value;}

    private:
    // Members
        unsigned char   ttl;
        double          loss_estimate;
        double          rtt_estimate;
        double          rtt_rough;
        double          rtt_variance;
        double          rtt_sqrt;
        double          rate_estimate;
        unsigned char   grtt_req_sequence;

};  // end class MdpRepresentativeNode

#endif // MDP_NODE
