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


#include "mdpNode.h"
#include "mdpSession.h"

#include "app_mdp.h"
#include <errno.h>


static const double MAXRATE  = 25000000.0;
static const double SAMLLFLOAT  = 0.0000001;

static double p_to_b(double p, double rtt, double tzero, int psize, int bval)
{
    if (p < 0 || rtt < 0) return MAXRATE;
    double res=rtt*sqrt(2*bval*p/3);
    double tmp1=3*sqrt(3*bval*p/8);
    if (tmp1>1.0) tmp1=1.0;
    double tmp2=tzero*p*(1+32*p*p);
    res+=tmp1*tmp2;
    if (res < SAMLLFLOAT)
        res=MAXRATE;
    else
        res=psize/res;
    if (res > MAXRATE)
        res = MAXRATE;
    return res;
}  // end

static double b_to_p(double b, double rtt, double tzero, int psize, int bval)
{
    int ctr=0;
    double p=0.5;
    double pi=0.25;
    while (TRUE)
    {
        double bres = p_to_b(p,rtt,tzero,psize, bval);
        /*
         * if we're within 5% of the correct value from below, this is OK
         * for this purpose.
         */
        if ((bres > 0.95*b) && (bres < 1.05*b))
            return p;
        if (bres>b)
            p+=pi;
        else
            p-=pi;
        pi/=2.0;
        ctr++;
        if (ctr>30) return p;
    }
}  // end b_to_p()


double UniformRand(double max, char* theSession)
{
    MdpSession* session = (MdpSession*) theSession;
    MdpData* mdpData = (MdpData*)session->GetNode()->appData.mdp;
    double temp = RANDOM_erand(mdpData->seed);
    return (max * temp);
}

LossEventEstimator::LossEventEstimator()
    : init(false),
      lag_mask(0xffffffff), lag_depth(0), lag_test_bit(0x01),
      event_window(0), event_index(0),
      event_window_time(0.0), event_index_time(0.0),
      seeking_loss_event(true),
      no_loss(true), initial_loss(0.0), loss_interval(0.0),
      current_discount(1.0)
{
    memset(history, 0, 9*sizeof(UInt32));
    discount[0] = 1.0;
}

const double LossEventEstimator::weight[8] =
{
    1.0, 1.0, 1.0, 1.0,
    0.8, 0.6, 0.4, 0.2
};

int LossEventEstimator::SequenceDelta(unsigned short a, unsigned short b)
{
    int delta = a - b;
    if (delta < -0x8000)
        return (delta + 0x10000);
    else if (delta < 0x8000)
        return delta;
    else
        return delta - 0x10000;
}  // end LossEventEstimator::SequenceDelta()


bool LossEventEstimator::ProcessRecvPacket(unsigned short theSequence,
                                           BOOL           ecnStatus,
                                           Node*          node)
{
    if (!init)
    {
        Init(theSequence);
        return false;
    }
    unsigned int outageDepth = 0;
    // Process packet through lag filter and check for loss
    int delta = SequenceDelta(theSequence, lag_index);
    if (delta > 100)        // Very new packet arrived
    {
        Sync(theSequence);  // resync
        return false;
    }
    else if (delta > 0)     // New packet arrived
    {
        if (lag_depth)
        {
            unsigned int outage = 0;
            for (int i = 0; i < delta; i++)
            {
                if (i <= (int)lag_depth)
                {
                    outage++;
                    if (lag_mask & lag_test_bit)
                    {
                        if (outage > 1)
                            outageDepth = MAX(outage, outageDepth);
                        outage = 0;
                    }
                    else
                    {
                        lag_mask |= lag_test_bit;
                    }
                    lag_mask <<= 1;
                }
                else
                {
                    outage += delta - lag_depth - 1;
                    break;
                }
            }
            outageDepth = MAX(outage, outageDepth);
            lag_mask |= 0x01;
        }
        else
        {
            if (delta > 1) outageDepth = delta - 1;
        }
        lag_index = theSequence;
    }
    else if (delta < -100)              // Very old packet arrived
    {
         Sync(theSequence); // resync
         return false;
    }
    else if (delta < -((int)lag_depth)) // Old packet arrived
    {
        ChangeLagDepth(-delta);
    }
    else if (delta < 0)                 // Lagging packet arrived
    {                                   // (duplicates have no effect)
        lag_mask |= (0x01 << (-delta));
        return false;
    }
    else // (delta == 0)
    {
        return false;                    // Duplicate packet arrived, ignore
    }

    if (ecnStatus) outageDepth += 1;

    bool newLossEvent = false;

    if (!seeking_loss_event)
    {
        struct timevalue currentTime;
        ProtoSystemTime(currentTime, node->getNodeTime());
        double theTime = (((double)currentTime.tv_sec) +
                      (((double)currentTime.tv_usec)/1.0e06));
        if (theTime > event_index_time)
        //if (SequenceDelta(theSequence, event_index) > event_window)
        {
            seeking_loss_event = true;
        }

        // (TBD) Should we reset our history on
        //  outages within the event_window???
    }

    if (seeking_loss_event)
    {
        double scale;
        if (history[0] > loss_interval)
            scale = 0.125 / (1.0 + log((double)(event_window ? event_window : 1)));
        else
            scale = 0.125;
        if (outageDepth)  // non-zero outageDepth means pkt loss(es)
        {
            if (no_loss)  // first loss
            {
                //fprintf(stderr, "First Loss: seq:%u init:%f history:%lu adjusted:",
                //                 theSequence, initial_loss, history[0]);
                if (initial_loss != 0.0)
                {
                    UInt32 initialHistory = (UInt32) ((1.0 / initial_loss) + 0.5);
                    history[0] = MAX(initialHistory, history[0]/2);
                }
                //fprintf(stderr, "%lu\n", history[0]);
                no_loss = false;
            }

            // Old method
            if (loss_interval > 0.0)
                loss_interval += scale*(((double)history[0]) - loss_interval);
            else
                loss_interval = (double) history[0];

            // New method
            // New loss event, shift loss interval history & discounts
            memmove(&history[1], &history[0], 8*sizeof(UInt32));
            history[0] = 0;
            memmove(&discount[1], &discount[0], 8*sizeof(double));
            discount[0] = 1.0;
            current_discount = 1.0;

            event_index = theSequence;
            //if (event_window)
                seeking_loss_event = false;
            newLossEvent = true;
            no_loss = false;
            struct timevalue currentTime;
            ProtoSystemTime(currentTime, node->getNodeTime());
            event_index_time = (((double)currentTime.tv_sec) +
                                (((double)currentTime.tv_usec)/1.0e06));
            event_index_time += event_window_time;
        }
        else
        {
            //if (no_loss) fprintf(stderr, "No loss (seq:%u) ...\n", theSequence);
            if (loss_interval > 0.0)
            {
                double diff = ((double)history[0]) - loss_interval;
                if (diff >= 1.0)
                {
                    //scale *= (diff * diff) / (loss_interval * loss_interval);
                    loss_interval += scale*log(diff);
                }
            }
        }
    }
    else
    {
        if (outageDepth) history[0] = 0;
    }  // end if/else (seeking_loss_event)

    if (history[0] < 100000) history[0]++;

    return newLossEvent;
}  // end LossEventEstimator::ProcessRecvPacket()

double LossEventEstimator::LossFraction()
{
    return (TfrcLossFraction());    // ACIRI TFRC approach
}  // end LossEventEstimator::LossFraction()



// TFRC Loss interval averaging with discounted, weighted averaging
double LossEventEstimator::TfrcLossFraction()
{
    if (!history[1]) return 0.0;
    // Compute older weighted average s1->s8 for discount determination
    double average = 0.0;
    double scaling = 0.0;
    unsigned int i;
    for (i = 1; i < 9; i++)
    {
        if (history[i])
        {
            average += history[i] * weight[i-1] * discount[i];
            scaling += discount[i] * weight[i-1];
        }
        else
        {
            break;
        }
    }
    double s1 = average / scaling;

    // Compute discount if applicable
     if (history[0] > (2.0*s1))
    {
        current_discount = (2.0*s1) / (double) history[0];
        current_discount = MAX (current_discount, 0.5);
    }

    // Re-compute older weighted average s1->s8 with discounting
    if (current_discount < 1.0)
    {
        average = 0.0;
        scaling = 0.0;
        for (i = 1; i < 9; i++)
        {
            if (history[i])
            {
                average += current_discount * history[i] * weight[i-1] * discount[i];
                scaling += current_discount * discount[i] * weight[i-1];
            }
            else
            {
                break;
            }
        }
        s1 = average / scaling;
    }

    // Compute newer weighted average s0->s7 with discounting
    average = 0.0;
    scaling = 0.0;
    for (i = 0; i < 8; i++)
    {
        if (history[i])
        {
            double d = (i > 0) ? current_discount : 1.0;
            average += d * history[i] * weight[i] * discount[i];
            scaling += d * discount[i] * weight[i];
        }
        else
        {
            break;
        }
    }
    double s0 = average / scaling;
    // Use max of old/new averages
    return (1.0 /  MAX(s0, s1));
}  // end LossEventEstimator::LossFraction()


MdpNode::MdpNode(UInt32 theId)
    : id(theId), left(NULL), right(NULL), parent(NULL), user_data(NULL)
{

}

MdpNode::~MdpNode()
{
}



MdpServerNode::MdpServerNode(UInt32 nodeId, MdpSession* theSession)
    : MdpNode(nodeId), session(theSession), server_synchronized(false),
    recv_pending_low(0), recv_pending_high(0),
    segment_size(theSession->SegmentSize()), ndata(0), nparity(0),
    active(false), server_pos_ack_object_id(0),
    local_representative(false), buffer_limited(false),
    notify_pending(0), notify_delete(false)
{
    memset(&last_grtt_req_send_time, 0, sizeof(struct timevalue));
    memset(&last_grtt_req_recv_time, 0, sizeof(struct timevalue));
    grtt_req_sequence = 128;

    //strcpy(name, "Unknown");
    grtt_advertise = MDP_DEFAULT_GRTT_ESTIMATE;
    grtt_quantized = QuantizeRtt(grtt_advertise);

    // Init our ProtoTimers
    memset(&activity_timer,0,sizeof(MdpProtoTimer));
    memset(&repair_timer,0,sizeof(MdpProtoTimer));
    memset(&ack_timer,0,sizeof(MdpProtoTimer));

    lastActivityTimerEnd = 0;
    lastActivityTimerInterval = 0;

    unsigned int activeRepeats = session->RobustFactor();
    activeRepeats = MAX(1, activeRepeats);
    double activeTimeout = 2.0 * session->GrttEstimate() * activeRepeats;
    activeTimeout = MAX(activeTimeout, MDP_NODE_ACTIVITY_TIMEOUT_MIN);

    //activity_timer.SetListener(this, &MdpServerNode::OnActivityTimeout);
    activity_timer.SetInterval(activeTimeout);
    activity_timer.SetRepeat(activeRepeats);
    activity_timer.ResetRepeatCount();
    session->ActivateTimer(activity_timer, ACTIVITY_TIMEOUT, this);

    // The intervals for these timer are dynamically set
    //repair_timer.SetListener(this, &MdpServerNode::OnRepairTimeout);
    repair_timer.SetInterval(0.0);
    repair_timer.SetRepeat(1);
    repair_timer.ResetRepeatCount();
    //session->ActivateTimer(repair_timer, REPAIR_TIMEOUT, this);

    //ack_timer.SetListener(this, &MdpServerNode::OnAckTimeout);
    ack_timer.SetInterval(0.0);
    ack_timer.SetRepeat(0);
    //session->ActivateTimer(ack_timer, ACK_TIMEOUT, this);

}

MdpServerNode::~MdpServerNode()
{
    Close();
}

// Server resource allocation
bool MdpServerNode::Open()
{
    if (IsOpen()) Close();
    // (TBD) Make object stream sync window user-tunable
    if (!object_transmit_mask.Init(256))
    {
        Close();
        return false;
    }
    if (!object_repair_mask.Init(256))
    {
        Close();
        return false;
    }
    return true;
}  // end MdpServerNode::Open()

void MdpServerNode::Close()
{
    if (IsActive()) Deactivate();
    object_repair_mask.Destroy();
    object_transmit_mask.Destroy();
    server_synchronized = false;
}  // end MdpServerNode::Close()

bool MdpServerNode::Activate(UInt32 bufferSize, Int32 segment_pool_depth)
{
    ASSERT(!IsActive());
        //&& IsOpen());
    // Init decoder
    if (!decoder.Init(nparity, segment_size))
    {
        if (MDP_DEBUG)
        {
            printf("MdpNode::Activate(): Error initing decoder!\n");
        }
        return false;
    }
    // Allocate server buffer memory
    unsigned int blockSize = ndata + nparity;
    UInt32 bit_mask_len = blockSize/8;
    if (blockSize%8) bit_mask_len += 1;

    Int64 block_p_depth = (Int64)(
        ((Int32)bufferSize - (segment_pool_depth * segment_size) - (nparity*segment_size)) /
        (sizeof(MdpBlock) + (blockSize *sizeof(char*)) +
         (2 * (Int32)bit_mask_len) + (ndata * segment_size)));

    if (block_p_depth <= 0)
    {
        char errStr[MAX_STRING_LENGTH + 50];

        if (segment_pool_depth > 0)
        {
            sprintf(errStr,"Receiver Block pool count comes out "
                           "to be %" TYPES_64BITFMT "d. "
                           "Need at least 1 block for buffering. "
                           "Either increase the RX-BUFFER-SIZE or "
                           "decrease the segment size. "
                           "SEGMENT-POOL-SIZE can also be decremented. Its "
                           "current value is %d \n",
                           block_p_depth, segment_pool_depth);
        }
        else
        {
            sprintf(errStr,"Receiver Block pool count comes out "
                           "to be %" TYPES_64BITFMT "d. "
                           "Need at least 1 block for buffering. "
                           "Either increase the RX-BUFFER-SIZE or "
                           "decrease the segment size.\n",
                           block_p_depth);
        }
        ERROR_ReportError(errStr);

        this->session->rxBufferSize = bufferSize = (UInt32)MDP_DEFAULT_BUFFER_SIZE;
        this->session->client_window_size = this->session->rxBufferSize;
    }

    UInt32 block_pool_depth =
        (bufferSize - (segment_pool_depth * segment_size) - (nparity*segment_size)) /
        (sizeof(MdpBlock) + (blockSize *sizeof(char*)) +
         (2 * bit_mask_len) + (ndata * segment_size));
    if (block_pool_depth < 1)
    {
        if (MDP_DEBUG)
        {
            printf("MdpNode::Activate(): Bad parameters! (need at least 1 block of buffering)\n");
        }
        return false;
    }
    UInt32 vector_pool_depth =
                   segment_pool_depth + nparity + (block_pool_depth * ndata);

    if (MDP_DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        ctoa(session->node->getNodeTime(), clockStr);
        printf("MdpNode::Activate(): Allocating %u blocks for recv "
               "buffering at time %s...\n", block_pool_depth, clockStr);
    }
    if (block_pool_depth != block_pool.Init(block_pool_depth, blockSize))
    {
        if (MDP_DEBUG)
        {
            printf("MdpNode::Activate(): Error allocating recv buffer block resources!\n");
        }
        block_pool.Destroy();
        decoder.Destroy();
        return false;
    }
    if (MDP_DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        ctoa(session->node->getNodeTime(), clockStr);
        printf("MdpNode::Activate(): Allocating %u vectors(%d) for recv "
               "buffering at time %s...\n",
            vector_pool_depth, segment_size, clockStr);
    }
    if (vector_pool_depth != vector_pool.Init(vector_pool_depth, segment_size))
    {
        if (MDP_DEBUG)
        {
            printf("MdpNode::Activate(): Error allocating recv buffer vector resources!\n");
        }
        vector_pool.Destroy();
        block_pool.Destroy();
        decoder.Destroy();
        return false;
    }
    if (MDP_ERROR_NONE != msg_pool.Init(MDP_MSG_POOL_DEPTH))
    {
        if (MDP_DEBUG)
        {
            printf("MdpNode::Activate(): Error allocating recv buffer message resources!\n");
        }
        vector_pool.Destroy();
        block_pool.Destroy();
        decoder.Destroy();
        return false;
    }
    active = true;
    buffer_limited = false;
    return true;
}  // end MdpServerNode::Activate()

void MdpServerNode::Deactivate()
{
    if (MDP_DEBUG)
    {
        printf("MdpNode::Deactivate(): server node:%u gone inactive ...\n",
            Id());
    }
    if (activity_timer.IsActive()) activity_timer.Deactivate(
                                                   this->session->GetNode());
    if (repair_timer.IsActive()) repair_timer.Deactivate(
                                                   this->session->GetNode());
    if (ack_timer.IsActive()) ack_timer.Deactivate(this->session->GetNode());
    // Drop state on any pending receive objects
    live_objects.Destroy();
    // Purge any outstanding messages from the session's tx_queue
    session->PurgeClientMessages(this);
    msg_pool.Destroy();
    block_pool.Destroy();
    vector_pool.Destroy();
    decoder.Destroy();
    active = false;
}  // end MdpServerNode::Deactivate()

void MdpServerNode::Delete()
{
    Close();
    if (NotifyPending())
        notify_delete = true;
    else
        delete this;
}  // end MdpServerNode::Delete()


void MdpServerNode::Sync(UInt32 objectId)
{
    while (object_transmit_mask.IsSet() &&
          (MDP_RECV_OBJECT_INVALID == ObjectSequenceCheck(objectId)))
    {
        MdpObject* theObject = FindRecvObjectById(recv_pending_low);
        DeactivateRecvObject(recv_pending_low, theObject);
        // (TBD) Increment session client stats failure count?
        // (TBD) Set theObject error value?
        if (theObject) delete theObject;
        session->IncrementFailures();
    }
    if (!object_transmit_mask.IsSet() &&
        (MDP_RECV_OBJECT_INVALID == ObjectSequenceCheck(objectId)))
    {
        server_synchronized = false;
    }
}  // end MdpServerNode::Sync()

void MdpServerNode::HardSync(UInt32 objectId)
{
    // while (object_transmit_mask.IsSet() && (INVALID _or_ recv_pending_low < syncId))
    UInt32 diff = recv_pending_low - objectId;
    while (object_transmit_mask.IsSet() &&
           ((MDP_RECV_OBJECT_INVALID == ObjectSequenceCheck(objectId)) ||
            ((diff > MDP_SIGNED_BIT_INTEGER) || 
              ((diff == MDP_SIGNED_BIT_INTEGER) && (recv_pending_low > objectId)))))

    {
        MdpObject* theObject = FindRecvObjectById(recv_pending_low);
        DeactivateRecvObject(recv_pending_low, theObject);
        // (TBD) Set theObject error value?
        if (theObject) delete theObject;
        session->IncrementFailures();
        diff = recv_pending_low - objectId;
    }

    if (!object_transmit_mask.IsSet() &&
        (MDP_RECV_OBJECT_INVALID == ObjectSequenceCheck(objectId)))
    {
        server_synchronized = false;
    }

}  // end MdpServerNode::HardSync()

// Steal resources so another object/block can be buffered
// Rules for stealing depend upon "nacking mode" (reliability)
// of objects in question
bool MdpServerNode::ReclaimResources(MdpObject*     theObject,
                                     UInt32         blockId)
{
    ASSERT(theObject);
    // First, try to get resources from any incomplete "unreliable"
    //(non-NACKED) objects starting with oldest objects
    MdpObject *obj = live_objects.Head();
    while (obj)
    {
        if (MDP_NACKING_NONE == obj->NackingMode())
        {
            if ((obj == theObject) || obj->HaveBuffers())
                break;
        }
        obj = obj->next;
    }

    // If no "unreliable" objects are using resources,
    // try to free resources from newest "reliable" (NACKED)
    // objects
    if (!obj && (MDP_NACKING_NONE != theObject->NackingMode()))
    {
        obj = live_objects.Tail();
        while (obj)
        {
            if (obj->HaveBuffers() || obj == theObject)
                break;
            else
                obj = obj->prev;
        }
    }

    if (obj && obj->HaveBuffers())
    {
        MdpBlock* blk = obj->ClientStealBlock((obj != theObject), blockId);
        if (blk)
        {
            if (MDP_DEBUG)
            {
                printf("mdp: client stealing resources from object:%u block:%u\n",
                    obj->TransportId(), blk->Id());
            }
            blk->Empty(&vector_pool);
            block_pool.Put(blk);
            buffer_limited = false;
            return true;
        }
    }
    if (!buffer_limited)
    {
        buffer_limited = true;
        if (MDP_DEBUG)
        {
            printf("mdp: client has no idle resources to reclaim!\n");
        }
    }
    return false;
}  // end MdpServerNode::ReclaimResources()


void MdpServerNode::UpdateLossEstimate(unsigned short theSequence,
                                       BOOL ecnStatus)
{
    if (loss_estimator.ProcessRecvPacket(theSequence,
                                         ecnStatus,
                                         this->session->GetNode()))
    {
        // This makes reps immediately send a congestion control
        // response when new congestion events occur
        //if (ack_timer.IsActive()) ack_timer.Deactivate();
        //if (local_representative) OnAckTimeout();
    }
}  // end MdpServerNode::UpdateLossEstimate()

// Server round trip time estimation
void MdpServerNode::UpdateGrtt(unsigned char new_grtt_quantized)
{
    if (new_grtt_quantized != grtt_quantized)
    {
        grtt_quantized = new_grtt_quantized;
        grtt_advertise = UnquantizeRtt(new_grtt_quantized);
    }
}  // end MdpServerNode::UpdateGrtt()

void MdpServerNode::CalculateGrttResponse(struct timevalue* response)
{
    ASSERT(response);

    if (last_grtt_req_send_time.tv_sec || last_grtt_req_send_time.tv_usec)
    {
        // 1st - Get current time
            ProtoSystemTime(*response, this->session->GetNode()->getNodeTime());

        // 2nd - Calculate hold_time (current_time - recv_time)
        if (response->tv_usec < last_grtt_req_recv_time.tv_usec)
        {
            response->tv_sec = response->tv_sec - last_grtt_req_recv_time.tv_sec - 1;
            response->tv_usec = 1000000 - (last_grtt_req_recv_time.tv_usec -
                                           response->tv_usec);
        }
        else
        {
            response->tv_sec = response->tv_sec - last_grtt_req_recv_time.tv_sec;
            response->tv_usec = response->tv_usec - last_grtt_req_recv_time.tv_usec;
        }

        // 3rd - Calculate adjusted grtt_send_time (send_time + hold_time)
        response->tv_sec += last_grtt_req_send_time.tv_sec;
        response->tv_usec += last_grtt_req_send_time.tv_usec;

        if (response->tv_usec > 1000000)
        {
            response->tv_usec -= 1000000;
            response->tv_sec += 1;
        }
    }
    else  // we haven't had a grtt_request from this server yet
    {
        response->tv_sec = 0;
        response->tv_usec = 0;
    }
}  // end MdpServerNode::CalculateGrttResponse()


void MdpServerNode::HandleGrttRequest(MdpMessage* theMsg)
{
    // Record receive time and send time of GRTT_REQUEST
    ProtoSystemTime(last_grtt_req_recv_time,
                    this->session->GetNode()->getNodeTime());
    memcpy(&last_grtt_req_send_time, &theMsg->cmd.grtt_req.send_time, sizeof(struct timevalue));
    grtt_req_sequence = theMsg->cmd.grtt_req.sequence;
    double rttEstimate = 0.0;
    bool rep = theMsg->cmd.grtt_req.FindRepresentative(session->LocalNodeId(),
                                                       &rttEstimate);
    bool wildcard = (theMsg->cmd.grtt_req.flags & MDP_CMD_GRTT_FLAG_WILDCARD) ? true : false;

    if (rep)
    {
        if (!local_representative)
        {
           local_representative = true;
//           printf("RepresentativeStatus> time>%lu.%06lu server>%d node>%d elected.\n",
//                 last_grtt_req_recv_time.tv_sec, last_grtt_req_recv_time.tv_usec,
//                 id, session->LocalNodeId());
        }
        // Local rttEstimate was provided in representative list.
    }
    else
    {
        if (local_representative)
        {
            if (!wildcard)
            {
                local_representative = false;
//                printf("RepresentativeStatus> time>%lu.%06lu server>%lu node>%lu impeached.\n",
//                     last_grtt_req_recv_time.tv_sec, last_grtt_req_recv_time.tv_usec,
//                     id, session->LocalNodeId());
            }
        }
        else
        {
            rttEstimate = UnquantizeRtt(theMsg->cmd.grtt_req.rtt);
        }
    }  // end if/else rep

    double pktsPerRtt = ((double)theMsg->cmd.grtt_req.rate * rttEstimate) /
                         (double)theMsg->cmd.grtt_req.segment_size;
    loss_estimator.SetEventWindow((unsigned short)(pktsPerRtt + 0.5));
    loss_estimator.SetEventWindowTime(rttEstimate);

    // Track initializer for loss estimator
    if (loss_estimator.NoLoss())
    {
        double lossInit = b_to_p(((double)theMsg->cmd.grtt_req.rate)/2.0,
                                  rttEstimate, 4.0*rttEstimate, // Use 4*Rtt for Tzero
                                  theMsg->cmd.grtt_req.segment_size, 1);
        //fprintf(stderr, "Setting initial loss: %f\n", lossInit);
        loss_estimator.SetInitialLoss(lossInit);
    }

    if (rep || wildcard)
    {
        // Explicitly respond to request
        double holdTime = 0.0;
        if (!rep)
        {
            holdTime = (theMsg->cmd.grtt_req.hold_time.tv_sec) +
                        (theMsg->cmd.grtt_req.hold_time.tv_usec / 1.0e06);
        }
        if (ack_timer.IsActive(session->GetNode()->getNodeTime()))
        {
            if (ack_timer.GetInterval() > (clocktype)(holdTime * SECOND))
            {
                ack_timer.Deactivate(this->session->GetNode());
            }
            else
                return;
        }
        ack_timer.SetInterval(UniformRand(holdTime,(char*)(this->session)));
        session->ActivateTimer(ack_timer, ACK_TIMEOUT, this);
    }
}  // end MdpServerNode::HandleGrttRequest()


MdpRecvObjectStatus MdpServerNode::ObjectSequenceCheck(UInt32 object_id)
{
    // Have we already established receive sync with this server?
    if (server_synchronized)
    {
        // if (object_id < recv_pending_low)
        UInt32 diff = object_id - recv_pending_low;
        if ((diff > MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER) && (object_id > recv_pending_low)))
        {
            if (object_transmit_mask.NumBits() < (recv_pending_low - object_id))
            {
                return MDP_RECV_OBJECT_INVALID;
            }
            else
                return MDP_RECV_OBJECT_COMPLETE;
        }
        else
        {
            // if recv_pending_high < object_id
            diff = recv_pending_high - object_id;
            if ((diff > MDP_SIGNED_BIT_INTEGER) ||
                ((diff == MDP_SIGNED_BIT_INTEGER) && (recv_pending_high > object_id)))
            {
                diff = object_id - (recv_pending_low & (~((UInt32)0x07)));
                if (diff < object_transmit_mask.NumBits())
                    return MDP_RECV_OBJECT_NEW;
                else // It's out of range (we're way out of sync with server)
                {
                    return MDP_RECV_OBJECT_INVALID;
                }
            }
            else
            {
                if (object_transmit_mask.Test(object_id))
                    return MDP_RECV_OBJECT_PENDING;
                else
                    return MDP_RECV_OBJECT_COMPLETE;
            }
        }
    }
    else
    {
        // We can sync up anywhere in the object stream
        return MDP_RECV_OBJECT_NEW;
    }
}  // end MdpServerNode::ObjectSequenceCheck()


void MdpServerNode::ObjectRepairCheck(UInt32 objectId,
                                      UInt32 blockId)
{
    ASSERT(server_synchronized);

    if (session->EmconClient()) return;

    if (!repair_timer.IsActive(session->GetNode()->getNodeTime()))
    {
        // 1) Are there any older objects pending repair?
        // if (recv_pending_low <= objectId)
        UInt32 diff = recv_pending_low - objectId;
        if ((0 == diff) ||
            (diff > MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER) && (recv_pending_low > objectId)))
        {
            if (object_repair_mask.IsSet()) object_repair_mask.Clear();
            UInt32 index;
            if (object_transmit_mask.FirstSet(&index))
            {
                do
                {
                    if (object_repair_mask.CanFreeSet(index))
                        object_repair_mask.Set(index);
                } while (objectId != index++);
            }
        }
        else
        {
            return;
        }

        bool start_timer = false;
        MdpObject *obj = live_objects.Head();
        while (obj)
        {
            UInt32 transport_id = obj->TransportId();
            // if transport_id < objectId
            UInt32 diff = transport_id - objectId;
            if ((diff > MDP_SIGNED_BIT_INTEGER) ||
                ((diff == MDP_SIGNED_BIT_INTEGER) && (transport_id > objectId)))
            {
                start_timer |= obj->ClientFlushObject(false);
                object_repair_mask.Unset(transport_id);
                obj = obj->next;
            }
            else if (0 == diff)
            {
                start_timer |= obj->ClientRepairCheck(blockId, false);
                object_repair_mask.Unset(transport_id);
                break;
            }
            else
            {
                break;
            }
        }
        start_timer |= object_repair_mask.IsSet();

        if (start_timer)
        {
            object_repair_mask.Clear();
            // BACKOFF related
            //double backoff = UniformRand(MDP_BACKOFF_WINDOW*grtt_advertise);
            double backoff;
            if (session->IsUnicast())
                backoff = 0.0;
            else
            {
                backoff = erand(MDP_BACKOFF_WINDOW*grtt_advertise,
                                (double)MDP_GROUP_SIZE,
                                (char*)this->session);
            }
            repair_timer.SetInterval(backoff);
            repair_timer.ResetRepeatCount();
            session->ActivateTimer(repair_timer, REPAIR_TIMEOUT, this);
            if (MDP_DEBUG)
            {
                printf("mdp: client installing ObjectRepairTimer for "
                       "server:%d (timeout = %" TYPES_64BITFMT "d)...\n",
                    session->GetNode()->nodeId, repair_timer.GetInterval());
            }
        }
        current_object_id = objectId;
    }
    else if (repair_timer.GetRepeatCount())
    {
        // This set current object backwards if server has rewound
        // if (objectId < current_object_id)
        UInt32 diff = objectId - current_object_id;
        if ((diff > MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER)) && (objectId > current_object_id))
        {
            current_object_id = objectId;
        }
    }
}  // end MdpServerNode::ObjectRepairCheck()


bool MdpServerNode::FlushServer(UInt32 objectId)
{
    MdpRecvObjectStatus objectStatus = ObjectSequenceCheck(objectId);
    switch (objectStatus)
    {
        case MDP_RECV_OBJECT_NEW:
            ActivateRecvObject(objectId, NULL);
            break;

        case MDP_RECV_OBJECT_INVALID:
            // ???
            return (object_transmit_mask.IsSet());

        default:
            break;
    }
    ObjectRepairCheck(objectId+1, 0);
    // Indicate if anything is receive pending
    return (object_transmit_mask.IsSet());
}  // end MdpServerNode::FlushServer()

void MdpServerNode::HandleSquelchCmd(UInt32         syncId,
                                     char*          squelchPtr,
                                     UInt16         squelchLen)
{
    if (server_synchronized)
    {
        // if INVALID _or_ recv_pending_low < syncId
        UInt32 diff = recv_pending_low - syncId;
        if ((MDP_RECV_OBJECT_INVALID == ObjectSequenceCheck(syncId)) ||
            ((diff > MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER) && (recv_pending_low > syncId))))
        {
            HardSync(syncId);
            session->IncrementResyncs();
        }

        char *squelchEnd = squelchPtr + squelchLen;
        while (squelchPtr < squelchEnd)
        {
            UInt32 objectId;
            memcpy(&objectId, squelchPtr, sizeof(UInt32));
            squelchPtr += sizeof(UInt32);
            MdpObject* theObject = NULL;
            MdpRecvObjectStatus objectStatus = ObjectSequenceCheck(objectId);
            switch (objectStatus)
            {
                case MDP_RECV_OBJECT_PENDING:
                    theObject = FindRecvObjectById(objectId);
                case MDP_RECV_OBJECT_NEW:
                    DeactivateRecvObject(objectId, theObject);
                    if (theObject)
                    {
                        delete theObject;
                        session->IncrementFailures();
                    }
                    break;

                default:
                    break;
            }
        }
    }
}  // end MdpServerNode::HandleSquelchCmd()

// Only call this after getting a MDP_RECV_OBJECT_NEW or
// MDP_RECV_OBJECT_PENDING from "ObjectSequenceCheck()"
MdpObject* MdpServerNode::NewRecvObject(UInt32      objectId,
                                        MdpObjectType   theType,
                                        UInt32          objectSize,
                                        Int32           virtualSize,
                                        const char*     theInfo,
                                        UInt16         infoSize)
{
    ActivateRecvObject(objectId, NULL);
    MdpObject* theObject = NULL;

    switch (theType)
    {
        case MDP_OBJECT_DATA:
            theObject = new MdpDataObject(session,
                                          this,
                                          NULL,
                                          virtualSize,
                                          objectId,
                                          objectSize);
            if (theObject)
            {
                if (theInfo)
                {
                    if (!theObject->SetInfo(theInfo, infoSize))
                    {
                        delete theObject;
                        DeactivateRecvObject(objectId, NULL);
                        return NULL;
                    }
                }
            }
            break;

        case MDP_OBJECT_FILE:
            theObject = new MdpFileObject(session, this, objectId);
            if (theObject)
            {
                if (!((MdpFileObject*)theObject)->SetPath(session->ArchivePath()))
                {
                    delete theObject;
                    DeactivateRecvObject(objectId, NULL);
                    return NULL;
                }
                if (!theObject->SetInfo(theInfo, infoSize))
                {
                    delete theObject;
                    DeactivateRecvObject(objectId, NULL);
                    return NULL;
                }
            }
            break;

        case MDP_OBJECT_SIM:
            break;

        default:
            // (TBD) Notify unsupported object type
            break;
    }
    if (theObject)
    {
        theObject->SetObjectSize(objectSize);
        theObject->Notify(MDP_NOTIFY_RX_OBJECT_START, MDP_ERROR_NONE);
        if (theObject->WasAborted())
        {
            theObject->RxAbort();
            theObject = NULL;
        }
        else if (MDP_ERROR_NONE != theObject->Open())
        {
            if (MDP_DEBUG)
            {
                printf("mdp: node:%u Error opening the object for receive!\n",
                    session->LocalNodeId());
            }
            DeactivateRecvObject(objectId, NULL);
            theObject->SetError(MDP_ERROR_FILE_OPEN);
            delete theObject;
            theObject = NULL;
        }
        else
        {
            if (theObject->RxInit(ndata, nparity, segment_size))
            {
                ActivateRecvObject(objectId, theObject);
            }
            else
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: node:%u Error initing the object for receive!\n",
                        session->LocalNodeId());
                }
                DeactivateRecvObject(theObject->TransportId(), NULL);
                theObject->SetError(MDP_ERROR_MEMORY);
                delete theObject;
                theObject = NULL;
            }
        }
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u Error allocating memory for new MdpObject!\n",
                session->LocalNodeId());
        }
        DeactivateRecvObject(objectId, NULL);
    }
    return theObject;
}  // end MdpServerNode::NewRecvObject()

// Only call this after getting a MDP_RECV_OBJECT_NEW or
// MDP_RECV_OBJECT_PENDING from "ObjectSequenceCheck()"
void MdpServerNode::ActivateRecvObject(UInt32 object_id, class MdpObject *theObject)
{
    if (theObject) live_objects.Insert(theObject);
    if (server_synchronized)
    {
        // if recv_pending_high < object_id
        UInt32 diff = recv_pending_high - object_id;
        if ((diff > MDP_SIGNED_BIT_INTEGER) ||
            ((diff == MDP_SIGNED_BIT_INTEGER) && (recv_pending_high > object_id)))
        {
            UInt32 index = recv_pending_high + 1;
            while (index != object_id)
            {
                ASSERT(object_transmit_mask.CanFreeSet(index));
                object_transmit_mask.Set(index++);
            }
            ASSERT(object_transmit_mask.CanFreeSet(index));
            object_transmit_mask.Set(object_id);
            recv_pending_high = object_id;
            object_transmit_mask.FirstSet(&recv_pending_low);
        }
        else
        {
            ASSERT(object_transmit_mask.Test(object_id));
        }
    }
    else
    {
        object_transmit_mask.Set(object_id);
        recv_pending_low = recv_pending_high = object_id;
        server_synchronized = true;
    }
}  // end MdpServerNode::ActivateRecvObject()

void MdpServerNode::DeactivateRecvObject(UInt32 object_id,
                                         class MdpObject *theObject)
{
    //ASSERT(server_synchronized);
    if (theObject)
    {
        live_objects.Remove(theObject);
        theObject->Close();
    }
    object_transmit_mask.Unset(object_id);
    if (object_repair_mask.Test(object_id))
        object_repair_mask.Unset(object_id);
    if (object_transmit_mask.IsSet())
        object_transmit_mask.FirstSet(&recv_pending_low);
    else
        recv_pending_low = recv_pending_high+1;
    // If server has timed out and no active recv objects,
    // free up buffering resources used by this server node
    if (!live_objects.Head() &&
        !activity_timer.IsActive(session->GetNode()->getNodeTime()))
    {
         if (MDP_DEBUG)
         {
            printf("mdp: All pending objects deactivate _and_ server has timed out!\n");
         }
         Deactivate();
         Close();
         session->DeleteRemoteServer(this);
    }
}  // end MdpServerNode::DeactivateRecvObject()

void MdpServerNode::AcknowledgeRecvObject(UInt32 object_id)
{
    server_pos_ack_object_id = object_id;
    if (ack_timer.IsActive(session->GetNode()->getNodeTime()))
    {
        if (ack_timer.GetInterval() > (clocktype)(grtt_advertise * SECOND))
        {
            ack_timer.Deactivate(this->session->GetNode());
        }
        else
            return;
    }
    ack_timer.SetInterval(UniformRand(grtt_advertise,(char*)(this->session)));
    session->ActivateTimer(ack_timer, ACK_TIMEOUT, this);
}  // end MdpServerNode::AcknowledgeRecvObject()

void MdpServerNode::ResetActivityTimer()
{
    double theInterval = grtt_advertise;
    unsigned int activeRepeats = session->RobustFactor();
    activeRepeats = MAX(1, activeRepeats);
    activity_timer.SetRepeat(activeRepeats);
    theInterval *= (2*activeRepeats);
    if (theInterval < MDP_NODE_ACTIVITY_TIMEOUT_MIN)
        theInterval = MDP_NODE_ACTIVITY_TIMEOUT_MIN;
    if (activity_timer.IsActive(session->GetNode()->getNodeTime()))
    {

        char intervalTimeStr[MAX_CLOCK_STRING_LENGTH];
        char timerIntervalStr[MAX_CLOCK_STRING_LENGTH];

        ctoa((clocktype)(theInterval * SECOND), intervalTimeStr);
        ctoa(activity_timer.GetInterval(), timerIntervalStr);

        if (strcmp(intervalTimeStr, timerIntervalStr) != 0)
        {
            //clocktype oldTimerInterval = activity_timer.GetInterval();

            activity_timer.SetInterval(theInterval);
            lastActivityTimerEnd = session->node->getNodeTime() +
                                                activity_timer.GetInterval();
            lastActivityTimerInterval = theInterval;

            // case when newInterval is less than the oldInterval
            // and remaining time of current timer is more than the
            // new interval timeout
            clocktype timeOut = activity_timer.GetTimeout();
            if (timeOut > lastActivityTimerEnd)
            {
                activity_timer.Deactivate(this->session->GetNode());
                session->ActivateTimer(activity_timer, ACTIVITY_TIMEOUT, this);
            }
        }
        else
        {
            activity_timer.ResetRepeatCount();
            if (activity_timer.GetRepeat() > 0)
            {
                lastActivityTimerEnd = session->node->getNodeTime() +
                                                activity_timer.GetInterval();
            }
        }
    }
    else
    {
        activity_timer.SetInterval(theInterval);
        session->ActivateTimer(activity_timer, ACTIVITY_TIMEOUT, this);
        lastActivityTimerEnd = session->node->getNodeTime() +
                                                activity_timer.GetInterval();
        lastActivityTimerInterval = theInterval;
    }
}  // end MdpServerNode::ResetActivityTimer()


bool MdpServerNode::OnAckTimeout()
{
    MdpMessage *theMsg = msg_pool.Get();

    //ack_timer.msg = NULL;
    ack_timer.Deactivate(session->GetNode());

    if (theMsg)
    {
        theMsg->type = MDP_ACK;
        theMsg->version = MDP_PROTOCOL_VERSION;
        theMsg->sender = session->LocalNodeId();
        theMsg->ack.server_id = id;
        // TxTimeout will fill in grtt_send_time field
        theMsg->ack.type = MDP_ACK_OBJECT;
        theMsg->ack.object_id = server_pos_ack_object_id;
        memset(&theMsg->ack.grtt_response, 0, sizeof(struct timevalue));
        // For now, MDP_ACKs are always unicast to the server
        if (session->MulticastAcks())
            theMsg->ack.dest = session->Address();
        else
            theMsg->ack.dest = &addr;
        theMsg->ack.server = this;
        session->QueueMessage(theMsg);
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("Server msg_pool is empty, can't transmit MDP_ACK\n");
        }
    }
    return true;  // one shots never need re-installed
}  // end MdpServerNode::OnAckTimeout()


bool MdpServerNode::OnRepairTimeout()
{

    //repair_timer.msg = NULL;
    if (!repair_timer.GetRepeatCount())
    {
        // Timer was in "repeat nack hold-off" phase
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u client NACK holdoff timeout ended ...\n",
                session->LocalNodeId());
        }
        // free repair_timer message
        MESSAGE_Free(this->session->GetNode(), repair_timer.msg);
        repair_timer.msg = NULL;
        repair_timer.Deactivate(session->GetNode());
        return true;
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u client NACK backoff timeout ended ...\n",
                session->LocalNodeId());
        }
        // decrease timer repeat_count
        repair_timer.DecrementRepeatCount();
    }
    // Ask for repairs up through current object
    // First grab an MdpMessage and data vector to use for potential NACK
    MdpMessage *theMsg;
    char *vector;
    theMsg = msg_pool.Get();
    if (!theMsg)
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Sender msg_pool is empty, can't queue NACK!\n");
        }
        //repair_timer.Deactivate(this->session->GetNode());
        // free repair_timer message
        MESSAGE_Free(this->session->GetNode(), repair_timer.msg);
        repair_timer.msg = NULL;
        repair_timer.Deactivate(session->GetNode());
        // Reset repair cycle for pending objects
        MdpObject *obj = live_objects.Head();
        while (obj)
        {
            obj->current_block_id = 0;
            obj = obj->next;
        }
        return false;
    }
    vector = vector_pool.Get();
    if (!vector)
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Sender vector_pool is empty, can't queue NACK!\n");
        }
        msg_pool.Put(theMsg);
        //repair_timer.Deactivate(this->session->GetNode());
        // free repair_timer message
        MESSAGE_Free(this->session->GetNode(), repair_timer.msg);
        repair_timer.msg = NULL;
        repair_timer.Deactivate(session->GetNode());
        // Reset repair cycle for pending objects
        MdpObject *obj = live_objects.Head();
        while (obj)
        {
            obj->current_block_id = 0;
            obj = obj->next;
        }
        return false;
    }
    theMsg->type = MDP_NACK;
    theMsg->version = MDP_PROTOCOL_VERSION;
    theMsg->sender = session->LocalNodeId();
    theMsg->nack.server_id = id;
    memset(&theMsg->nack.grtt_response, 0, sizeof(struct timevalue));
    // Note: MdpTransmitTimer timeout will calculate grtt_send_time
    theMsg->nack.server = this;
    theMsg->nack.data = vector;
    if (session->UnicastNacks())
        theMsg->nack.dest = &addr;
    else
        theMsg->nack.dest = &session->addr;

    unsigned int content = 0;

    // new object_repair_mask = object_transmit_mask - object_repair_mask
    UInt32 index;
    UInt32 current_id = current_object_id;

    if (current_object_id < recv_pending_low)
    {
        current_id = recv_pending_high;
    }

    if (object_transmit_mask.FirstSet(&index))
    {
        // while (index <= current_object_id)
        UInt32 diff = index - current_id;
        while ((diff > MDP_SIGNED_BIT_INTEGER) ||
               (0 == diff) ||
               ((MDP_SIGNED_BIT_INTEGER == diff) && (index < current_id)))
        {
            if (object_transmit_mask.Test(index))
            {
                if (object_repair_mask.Test(index))
                {
                    object_repair_mask.Unset(index);
                }
                else
                {
                    ASSERT(object_repair_mask.CanFreeSet(index));
                    object_repair_mask.Set(index);
                }
            }
            else
            {
                object_repair_mask.Unset(index);
            }
            diff = ++index - current_id;
        }
    }
    else
    {
        object_repair_mask.Clear();
    }

    // At this point the "object_repair_mask" contains repairs for objects which
    // we haven't been completely repair suppressed by someone else

    // Pack repair nacks for objects for which we have state
    MdpObject* obj = live_objects.Head();
    while (obj)
    {
        UInt32 transport_id = obj->TransportId();
        if (object_repair_mask.Test(transport_id))  // no-one else has asked for full repair
        {
            object_repair_mask.Unset(transport_id);
            // if (transport_id < current_object_id)
            UInt32 diff = transport_id - current_id;
            if ((diff > MDP_SIGNED_BIT_INTEGER) ||
                ((MDP_SIGNED_BIT_INTEGER == diff) && (transport_id < current_id)))
            {
                MdpObjectNack onack;
                if (onack.Init(transport_id, &vector[content],
                               segment_size - content))
                {
                    obj->BuildNack(&onack, false);
                    content += onack.Pack();
                }
                else
                {
                    obj->current_block_id = 0;
                    obj = obj->next;
                    break;
                }
            }
            else if (0 == diff)  // BuildNack for current_object_id
            {
                MdpObjectNack onack;
                if (onack.Init(transport_id, &vector[content],
                               segment_size - content))
                {
                    obj->BuildNack(&onack, true);
                    content += onack.Pack();
                }
                else
                {
                    obj->current_block_id = 0;
                }
                obj = obj->next;
                break;
            }
            else
            {
                break;
            }
        }
        else
        {
            obj->current_block_id = 0;
        }
        obj = obj->next;
    }  // end while (obj)

    while (obj)
    {
        obj->current_block_id = 0;
        obj = obj->next;
    }

    // If there's anything left in the "object_repair_mask"
    // While there's room, pack nacks for objects we're missing state
    // and no-one else has nack'd
    if (object_repair_mask.FirstSet(&index))
    {
        MdpNackingMode nackingMode = session->DefaultNackingMode();
        //if ((MDP_NACKING_NONE != nackingMode))
        if ((MDP_NACKING_NONE != nackingMode) && session->StreamIntegrity())
        {
            MdpObjectNack onack;
            MdpRepairNack rnack;
            // default nack for INFOONLY or NORMAL
            if (MDP_NACKING_INFOONLY == nackingMode)
                rnack.type = MDP_REPAIR_INFO;
            else
                rnack.type = MDP_REPAIR_OBJECT;
            rnack.type = MDP_REPAIR_OBJECT;
            while (object_repair_mask.NextSet(&index))
            {
                // if index <= current_id
                UInt32 diff = index - current_id;
                if ((diff > MDP_SIGNED_BIT_INTEGER) ||
                    (diff == 0) ||
                    ((MDP_SIGNED_BIT_INTEGER == diff) && (index < current_id)))
                {
                    if (onack.Init(index, &vector[content], segment_size - content))
                    {
                        if (onack.AppendRepairNack(&rnack))
                        {
                            content += onack.Pack();
                            if (MDP_DEBUG)
                            {
                                printf("mdp: client requesting OBJECT_REPAIR for object:%u\n",
                                    index);
                            }
                        }
                        else
                        {
                            if (MDP_DEBUG)
                            {
                                printf("MdpNodeRepairTimer::DoTimeout() full nack msg ...\n");
                            }
                            break;
                        }
                    }
                    else
                    {
                        if (MDP_DEBUG)
                        {
                            printf("MdpNodeRepairTimer::DoTimeout() full nack msg ...\n");
                        }
                        break;
                    }
                    index++;
                }
                else
                {
                    break;
                }
            }  // end while (object_repair_mask.NextSet())
        }  // end if ((MDP_NACKING_NONE != nackingMode) && session->StreamIntegrity())
    }  // end if (object_repair_mask.FirstSet(&index))

    // If we've accumulated any NACK content, send it; else NACK was suppressed
    if (content)
    {
        session->client_stats.nack_cnt++;
        // reset nack required status
        //session->SetNackRequired(FALSE);
        theMsg->nack.nack_len = (unsigned short)content;

        session->QueueMessage(theMsg);
        if (MDP_DEBUG)
        {
            printf("mdp: client MDP_NACK message was queued.\n");
        }
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("mdp: client MDP_NACK message was SUPPRESSED.\n");
        }
        if (session->GetNackRequired())
        {
            session->client_stats.supp_cnt++;
            //session->SetNackRequired(FALSE);
        }
        // Return unused resources to pools
        vector_pool.Put(vector);
        msg_pool.Put(theMsg);
    }
    // Set NACK hold-off interval (BACKOFF related)
    double holdOff;
    if (session->IsUnicast())
        holdOff = 1.5 * grtt_advertise;
    else
    {
        holdOff = (MDP_BACKOFF_WINDOW+2.0) * grtt_advertise;
    }
    if (MDP_DEBUG)
    {
        printf("mdp: node:%u client starting NACK holdoff timeout: %lf sec\n",
            session->LocalNodeId(),
            (MDP_BACKOFF_WINDOW+2.0)*grtt_advertise);
    }
    repair_timer.SetInterval(holdOff);
    session->ActivateTimer(repair_timer, REPAIR_TIMEOUT, this);
    return true;
}  // end MdpServerNode::OnRepairTimeout()


bool MdpServerNode::OnActivityTimeout()
{
    if (session->node->getNodeTime() < lastActivityTimerEnd)
    {
        activity_timer.SetIntervalInClocktype(lastActivityTimerEnd -
                                                  session->node->getNodeTime());
        session->ActivateTimer(activity_timer, ACTIVITY_TIMEOUT, this);
        // reset interval value to original value
        activity_timer.SetInterval(lastActivityTimerInterval);
        return true;
    }

    //decrease timer repeat_count
    activity_timer.DecrementRepeatCount();
    // We did a little trick here by normally just resetting
    // the repeat count so we wouldn't reinstall the timer
    // on every packet arrival ... so don't count first timeout
    int repeatCount = activity_timer.GetRepeatCount();

    if (repeatCount < activity_timer.GetRepeat())
    {
        if (MDP_DEBUG)
        {
            printf("mdp: node:%u ActivityTimeout for server:%u (repeats:%d)\n",
                    session->LocalNodeId(), Id(), activity_timer.GetRepeatCount());
        }
        MdpObject* latest_obj = live_objects.Tail();
        if (repeatCount)
        {
            // (TBD) we may only want to "flush" through the greatest ordinal
            //       server transmit point
            if (latest_obj) FlushServer(latest_obj->TransportId());

            // since repeat_count value is not 0, regenerate the timer with
            // last activity timer interval
            session->ActivateTimer(activity_timer, ACTIVITY_TIMEOUT, this);
            lastActivityTimerEnd = session->node->getNodeTime() +
                                               activity_timer.GetInterval();
        }
        else
        {
            Notify(MDP_NOTIFY_REMOTE_SERVER_INACTIVE, NULL, MDP_ERROR_NONE);
            // currently delete does not play any role
            //if (notify_delete)
            //{
            //    Delete();
            //    return false;
            //}
            if (!latest_obj)
            {
                // free qualnet message
                MESSAGE_Free(session->GetNode(), activity_timer.msg);
                activity_timer.msg = NULL;
                activity_timer.Deactivate(session->GetNode());
                // No pending objects, so free server resources
                Deactivate();
                // (TBD) Let the application control whether we drop
                // _all_ state on the remote server, ... for now
                // we'll drop all state on inactive remote servers
                Close();
                session->DeleteRemoteServer(this);
                return false;
            }
        }
    }
    return true;
}  // end MdpServerNode::OnActivityTimeout()

void MdpServerNode::Notify(MdpNotifyCode    notifyCode,
                           MdpObject*       theObject,
                           MdpError         errorCode)
{
    notify_pending++;
    session->Notify(notifyCode, (MdpNode*)this, theObject, errorCode);
    notify_pending--;
}  // end MdpServerNode::Notify()



MdpAckingNode::MdpAckingNode(UInt32 nodeId, class MdpSession* theSession)
    : MdpNode(nodeId), session(theSession), ack_status(false), ack_object_id(0)
{
    ack_req_count = (unsigned char)session->RobustFactor();
    // (TBD) Make minimum ack_req_count a parameter instead of 1?
    if (ack_req_count < 1) ack_req_count = 1;
}

void MdpAckingNode::SetLastAckObject(UInt32 objectId)
{
    if (ack_object_id != objectId)
    {
        ack_object_id = objectId;
        ack_req_count = (unsigned char)session->RobustFactor();
        // (TBD) Make minimum ack_req_count a parameter instead of 1?
        if (ack_req_count < 1) ack_req_count = 1;
    }
    ack_status = true;
}  // end MdpAckingNode::SetLastAckObject()

MdpRepresentativeNode::MdpRepresentativeNode(UInt32 nodeId)
    : MdpNode(nodeId), ttl(5), loss_estimate(0.0), rtt_estimate(0.5), rtt_rough(0.5),
      rtt_variance(1.0), rate_estimate(0.0), grtt_req_sequence(0)
{

}

void MdpRepresentativeNode::UpdateRttEstimate(double value)
{
        UpdateRttEstimateNormal(value);
}  // end MdpRepresentativeNode::UpdateRttEstimate()

// Asymmetric RTT smoothing
void MdpRepresentativeNode::UpdateRttEstimateAsymmetric(double value)
{
    double err = value - rtt_rough;
    rtt_rough += (1.0/8.0) * err;
    rtt_variance += (1.0/4.0) * (fabs(err) - rtt_variance);

    // Smoothed asymmetric update of RTT (better for multicast?)
    err = value - rtt_estimate;
    if (err < 0.0)
        rtt_estimate += (1.0/64.0) * err;
    else
        rtt_estimate += (1.0/8.0) * err;

    // Update rtt_sqrt average
    err = sqrt(value) - rtt_sqrt;
    rtt_sqrt += (0.05) * err;

}  // end MdpRepresentativeNode::UpdateRttEstimate()

// Normal RTT smoothing

void MdpRepresentativeNode::UpdateRttEstimateNormal(double value)
{
    // For rtt variance tracking (not so smooth)
    double err = value - rtt_rough;
    rtt_rough += (1.0/8.0) * err;
    rtt_variance += (1.0/4.0) * (fabs(err) - rtt_variance);

    // Highly smoothed rtt_estimate
    err = value - rtt_estimate;
    rtt_estimate += (0.05) * err;
    // Update rtt_sqrt average
    err = sqrt(value) - rtt_sqrt;
    rtt_sqrt += (0.05) * err;
}  // end MdpRepresentativeNode::UpdateRttEstimateNormal()



// Below is the implementation of binary tree and link list
// manipulations for our MdpNode base class

MdpNode* MdpNode::NextInTree()
{
    if (right)
    {
        MdpNode* y = right;
        while (y->left) y = y->left;
        return y;
    }
    else
    {
        MdpNode* x = this;
        MdpNode* y = parent;
        while (y && (y->right == x))
        {
            x = y;
            y = y->parent;
        }
        return y;
    }
}  // end MdpNode::NextInTree()


MdpNode* MdpNode::PrevInTree()
{
    if (left)
    {
        MdpNode* x = left;
        while (x->right) x = x->right;
        return x;
    }
    MdpNode* x = this;
    MdpNode* y = parent;
    while (y && (y->left == x))
    {
        x = y;
        y = y->parent;
    }
    return y;
}  // end MdpNode::PrevInTree()


MdpNodeTree::MdpNodeTree()
    : root(NULL)
{

}

MdpNodeTree::~MdpNodeTree()
{
    Destroy();
}


MdpNode *MdpNodeTree::FindNodeById(UInt32 node_id)
{
    MdpNode* x = root;
    while (x && (x->id != node_id))
    {
        if (node_id < x->id)
            x = x->left;
        else
            x = x->right;
    }
    return x;
}  // end MdpNodeTree::FindNodeById()



void MdpNodeTree::AttachNode(MdpNode *node)
{
    ASSERT(node);
    node->left = NULL;
    node->right = NULL;
    MdpNode *x = root;
    while (x)
    {
        if (node->id < x->id)
        {
            if (!x->left)
            {
                x->left = node;
                node->parent = x;
                return;
            }
            else
            {
                x = x->left;
            }
        }
        else
        {
           if (!x->right)
           {
               x->right = node;
               node->parent = x;
               return;
           }
           else
           {
               x = x->right;
           }
        }
    }
    root = node;  // root _was_ NULL
}  // end MdpNodeTree::AddNode()


void MdpNodeTree::DetachNode(MdpNode* node)
{
    ASSERT(node);
    MdpNode *y, *x;
    if (!node->left || !node->right)
        y = node;
    else
        y = node->NextInTree();
    if (y->left)
        x = y->left;
    else
        x = y->right;
    if (x) x->parent = y->parent;
    if (!y->parent)
        root = x;
    else if (y == y->parent->left)
        y->parent->left = x;
    else
        y->parent->right = x;

    if (node != y)
    {
        y->parent = node->parent;
        if (y->parent)
        {
            if (y->id < y->parent->id)
                y->parent->left = y;
            else
                y->parent->right = y;
        }
        else
        {
            root = y;
        }
        y->left = node->left;
        if (y->left) y->left->parent = y;
        y->right = node->right;
        if (y->right) y->right->parent = y;
    }
}  // end MdpNodeTree::DetachNode()


MdpNode *MdpNodeTree::Head()
{
    MdpNode *x = root;
    if (!x) return NULL;
    while (x->left) x = x->left;
    return x;
}  // end MdpNodeTree::Head()


void MdpNodeTree::Destroy()
{
    MdpNode* node = Head();
    while (node)
    {
        DetachNode(node);
        delete node;
        node = Head();
    }
}  // end MdpNodeTree::Destroy()

MdpNodeList::MdpNodeList()
    : head(NULL), tail(NULL)
{
}

MdpNode* MdpNodeList::FindNodeById(UInt32 nodeId)
{
    MdpNode *next = head;
    while (next)
    {
        if (nodeId == next->id)
            return next;
        else
            next = next->right;
    }
    return NULL;
}  // MdpNodeList::Find()

void MdpNodeList::Append(MdpNode *theNode)
{
    ASSERT(theNode);
    theNode->left = tail;
    if (tail)
        tail->right = theNode;
    else
        head = theNode;
    tail = theNode;
    theNode->right = NULL;
}  // end MdpNodeList::Append()

void MdpNodeList::Remove(MdpNode *theNode)
{
    ASSERT(theNode);
    if (theNode->right)
        theNode->right->left = theNode->left;
    else
        tail = theNode->left;
    if (theNode->left)
        theNode->left->right = theNode->right;
    else
        head = theNode->right;
}  // end MdpNodeList::Remove()


