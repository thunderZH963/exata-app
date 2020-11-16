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


#include "mdpSession.h"
#include "app_util.h"
#include "application.h"
#include "app_mdp.h"
#include <errno.h>

#ifdef MDP_FOR_WINDOWS
#include <windows.h>
#include <direct.h>
#else
// for unix
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#endif

#define MDP_DEBUG_MSG_FLOW 0

/**************************************************************************
 * MdpSessionMgr implementation
 */

MdpSessionMgr::MdpSessionMgr(MdpProtoTimerMgr& timerMgr, UInt32 nodeId)
    :  node_id(nodeId), list_head(NULL), list_tail(NULL),
       timer_mgr(timerMgr), mdp_notifier(NULL)
{

}

MdpSessionMgr::~MdpSessionMgr()
{
    Close();
}

void MdpSessionMgr::Close()
{
    // Close open sessions
    // Note: will delete cached archive files
    //  session->SetArchiveMode(true) to prevent cache file deletion
    MdpSession *session = list_head;
    while (session)
    {
        session->Close(true);
        list_head = list_head->next;
        delete session;
        session = list_head;
    }
    list_tail = (MdpSession*)NULL;
}  // end MdpSessionMgr::Shutdown()

MdpSession* MdpSessionMgr::NewSession(Node* node)
{
    MdpSession *theSession = new MdpSession(this, node);

    if (theSession) Add(theSession);
    return theSession;
}  // end MdpSessionMgr::NewSession()

void MdpSessionMgr::DeleteSession(MdpSession *theSession)
{
    if (theSession->NotifyPending())
    {
        theSession->SetNotifyAbort();
    }
    else
    {
        Remove(theSession);
        delete theSession;
    }
}  // end MdpSessionMgr::DeleteSession()


void MdpSessionMgr::Add(MdpSession *theSession)
{
    theSession->next = (MdpSession *) NULL;
    if (list_tail == NULL)
    {
        list_tail = list_head = theSession;
    }
    else
    {
        list_tail->next = theSession;
        list_tail = theSession;
    }
    list_tail = theSession;
    theSession->mgr = this;
}  // end MdpSessionMgr::AddSession()


// This routine assumes the session is in the list
void MdpSessionMgr::Remove(MdpSession *theSession)
{
    if (theSession->prev)
        theSession->prev->next = theSession->next;
    else
        list_head = theSession->next;
    if (theSession->next)
        theSession->next->prev = theSession->prev;
    else
        list_tail = theSession->prev;
    theSession->mgr = (MdpSessionMgr *) NULL;
}  // end MdpSessionMgr::RemoveSession()

//MdpSession *MdpSessionMgr::FindSessionByName(char *theName)
//{
//    MdpSession *nextSession = list_head;
//    while (nextSession)
//    {
//        if (!memcmp(theName, nextSession->name, sizeof(theName)))
//            return nextSession;
//        else
//            nextSession = nextSession->next;
//    }
//    return (MdpSession*)NULL;
//}  // end MdpSessionMgr::FindSessionByName()


MdpSession *MdpSessionMgr::FindSessionByUniqueId(Int32 uniqueId)
{
    MdpSession *nextSession = list_head;
    while (nextSession)
    {
        if (nextSession->mdpUniqueId == uniqueId)
            return nextSession;
        else
            nextSession = nextSession->next;
    }
    return (MdpSession*)NULL;
}  // end MdpSessionMgr::FindSessionByUniqueId()

MdpSession *MdpSessionMgr::FindSession(const MdpSession *theSession)
{
    MdpSession *nextSession = list_head;
    while (nextSession)
    {
        if (theSession == nextSession)
            return nextSession;
        else
            nextSession = nextSession->next;
    }
    return (MdpSession *) NULL;
}  // end MdpSessionMgr::FindSession()

void MdpSessionMgr::NotifyApplication(MdpNotifyCode  notifyCode,
                                      MdpSession*    theSession,
                                      MdpNode*       theNode,
                                      MdpObject*     theObject,
                                      MdpError       errorCode)
{
    if (mdp_notifier)
        mdp_notifier->Notify(notifyCode, this, theSession,
                             theNode, theObject, errorCode);
}  // end MdpSessionMgr::Notify()


MdpSession::MdpSession(MdpSessionMgr *theMgr, Node* node)
    : tx_port(0), ttl(MDP_DEFAULT_TTL),
      loopback(FALSE), port_reuse(false), tos(0),
      status(0), server_status(0), client_status(0),
      mgr(theMgr),
      single_socket(false), ecn_status(FALSE),
      tx_rate(MDP_DEFAULT_TX_RATE/8 ), tx_rate_min(0), tx_rate_max(0),
      user_data(NULL),segment_pool_depth(MDP_DEFAULT_SEGMENT_POOL_DEPTH),
      ndata(MDP_DEFAULT_BLOCK_SIZE), nparity(MDP_DEFAULT_NPARITY),
      segment_size(MDP_DEFAULT_SEGMENT_SIZE), auto_parity(0),
      server_sequence(1), next_transport_id(1), status_reporting(FALSE),
      congestion_control(FALSE), fast_start(false),
      rate_increase_factor(1.0), rate_decrease_factor(0.75),
      representative_count(0), goal_tx_rate(MDP_DEFAULT_TX_RATE/8),
      nominal_packet_size(0.0),
      grtt_req_interval_min(MDP_DEFAULT_GRTT_REQ_INTERVAL_MIN),
      grtt_req_interval_max(MDP_DEFAULT_GRTT_REQ_INTERVAL_MAX),
      grtt_req_probing(TRUE),
      grtt_req_sequence(0), grtt_max(MDP_GRTT_MAX),
      bottleneck_id(MDP_NULL_NODE), bottleneck_sequence(128),
      bottleneck_rtt(MDP_DEFAULT_GRTT_ESTIMATE), bottleneck_loss(0.0),
      grtt_response(false), grtt_current_peak(0),
      grtt_decrease_delay_count(0),tx_pend_queue_active(false),
      archive_path(NULL), archive_mode(false), client_window_size(0),
      stream_integrity(TRUE), default_nacking_mode(MDP_NACKING_NORMAL),
      notify_pending(0), notify_abort(false),
      robust_factor(MDP_DEFAULT_ROBUSTNESS),
      prev(NULL), next(NULL)
{

    isServerOpen = FALSE;
    nackRequired = FALSE;
    fictional_rate = (double)goal_tx_rate;

    // assuming that the receiver app exist while opening the session
    isReceiverAppExist = TRUE;

    client_stats.Init();
    commonStats.Init();

    interface_name[0] = '\0';
    last_report_time.tv_sec = 0;
    last_report_time.tv_usec = 0;
    // Calculate quantized version of initial grtt
    grtt_measured = MDP_DEFAULT_GRTT_ESTIMATE;
    double pktInterval = (double)segment_size / (double)tx_rate;
    // min grtt should be 2*pktInterval
    pktInterval *= 2.0;
    grtt_advertise = MAX(pktInterval, grtt_measured);
    grtt_quantized = QuantizeRtt(grtt_advertise);
    grtt_advertise = UnquantizeRtt(grtt_quantized);
    grtt_req_interval = grtt_req_interval_min;
    // Init some object queueing defaults
    pend_count_min = hold_count_min = MDP_DEFAULT_TX_CACHE_COUNT_MIN;
    pend_count_max = hold_count_max = MDP_DEFAULT_TX_CACHE_COUNT_MAX;
    pend_size_max = hold_size_max = MDP_DEFAULT_TX_CACHE_SIZE_MAX;  // will be set when opened as a server (unless first overridden)

    SetNode(node);
    // Init session timers
    memset(&report_timer,0,sizeof(MdpProtoTimer));
    memset(&tx_timer,0,sizeof(MdpProtoTimer));
    memset(&tx_interval_timer,0,sizeof(MdpProtoTimer));
    memset(&grtt_req_timer,0,sizeof(MdpProtoTimer));

    report_timer.SetInterval(MDP_REPORT_INTERVAL);
    report_timer.SetRepeat(-1);

    tx_timer.SetInterval(0.0);
    tx_timer.SetRepeat(-1);

    tx_interval_timer.SetInterval(0.0);
    tx_interval_timer.SetRepeat(-1);

    grtt_req_timer.SetInterval(0.0);
    grtt_req_timer.SetRepeat(-1);

    memset(&tx_hold_queue_expiry_timer,0,sizeof(MdpProtoTimer));
    tx_hold_queue_expiry_timer.SetInterval(
                                   MDP_DEFAULT_TX_HOLD_QUEUE_EXPIRY_INERVAL);
    tx_hold_queue_expiry_timer.SetRepeat(-1);

    isLastDataObjectReceived = false;

    memset(&session_close_timer,0,sizeof(MdpProtoTimer));
    session_close_timer.SetInterval(MDP_DEFAULT_SESSION_CLOSE_INTERVAL);
    session_close_timer.SetRepeat(-1);
}  // end MdpSession::MdpSession()

MdpSession::~MdpSession()
{
    if (IsOpen()) Close(true);
    //if (archive_path)
    free(archive_path);
    archive_path = NULL;
}  // end MdpSession::~MdpSession()



MdpDataObject *MdpSession::NewTxDataObject(const char*      infoPtr,
                                           UInt16           infoSize,
                                           char*            dataPtr,
                                           UInt32           dataSize,
                                           MdpError*        error,
                                           char *           theMsg,
                                           Int32            virtualSize)
{
    MdpDataObject *theObject
        = new MdpDataObject(this, (MdpServerNode*)NULL, theMsg,
                            virtualSize, next_transport_id, 0);

    if (theObject)
    {
        if (infoPtr)
        {
            if (!theObject->SetInfo(infoPtr, infoSize))
            {
                delete theObject;
                if (error) *error = MDP_ERROR_MEMORY;
                return NULL;
            }
        }
        theObject->SetData(dataPtr, dataSize);
        theObject->SetVirtualSize(virtualSize);

        // Queue it for transmission
        MdpError err = QueueTxObject(theObject);
        if (MDP_ERROR_NONE != err)
        {
            if (error) *error = err;
            delete theObject;
            return NULL;
        }
        else
        {
            next_transport_id++;
            return theObject;
        }
    }
    else
    {
        if (error) *error = MDP_ERROR_MEMORY;
        return NULL;
    }

}  // end MdpSession::NewTxDataObject()


MdpFileObject *MdpSession::NewTxFileObject(const char* thePath,
                                           const char* theName,
                                           MdpError*   error,
                                           char *      theMsg)
{
    ASSERT(thePath);
    ASSERT(theName);
    // Form file name
    char full_name[MDP_PATH_MAX];
    memset(full_name, 0, MDP_PATH_MAX);
    int pathLen = 0;
    // first calculate the path length
    pathLen = strlen(thePath);

    if ((pathLen + 1) > MDP_PATH_MAX)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"Invalid value %s for "
                       "the PATH. Path length is more than "
                       "the allowed length %d. \n",
                       thePath, MDP_PATH_MAX);
        ERROR_ReportError(errStr);
    }

    strncpy(full_name, thePath, pathLen);
    int len = MIN(pathLen, MDP_PATH_MAX);
    if ((MDP_PROTO_PATH_DELIMITER != thePath[len-1]) &&
        (MDP_PROTO_PATH_DELIMITER != theName[0]) && (len < MDP_PATH_MAX ))
    {
        full_name[len] = MDP_PROTO_PATH_DELIMITER;
        len++;
    }

    int fileNameSize = strlen(theName);
    strncat(full_name, theName, fileNameSize);
    //strncat(full_name, theName, MDP_PATH_MAX - len);


    // Make sure it's a valid file
    if (MDP_FILE_NORMAL == MdpFileGetType(full_name))
    {
        MdpFileObject *theObject =
            new MdpFileObject(this, (MdpServerNode*) NULL,
                              next_transport_id, theMsg);

        if (theObject)
        {
            // Note: If the file name is too long (> segment_size),
            // this will fail and NULL will be returned.
            MdpError err = theObject->SetFile(thePath, theName);
            if (MDP_ERROR_NONE != err)
            {
                if (error) *error = err;
                delete theObject;
                return NULL;
            }

            // Queue it for transmission
            err = QueueTxObject(theObject);
            if (MDP_ERROR_NONE != err)
            {
                if (error) *error = err;
                delete theObject;
                return NULL;
            }
            else
            {
                next_transport_id++;
                return theObject;
            }
        }
        else
        {
            if (error) *error = MDP_ERROR_MEMORY;
            return NULL;
        }
    }
    else
    {
        if (error) *error = MDP_ERROR_FILE_OPEN;
        return NULL;
    }
}  // end MdpSession::NewTxFileObject()

MdpError MdpSession::QueueTxObject(MdpObject *theObject)
{
    ASSERT(theObject);
    // Make sure session is open as a server
    if (!IsServer()) return MDP_ERROR_SESSION_INVALID;
    UInt32 pmin = pend_count_min;
    if (!pmin) pmin = 1;
    UInt32 pmax = pend_count_max;
    if (!pmin) pmax = 1;
    if ((tx_pend_queue.ObjectCount() >= pmax) ||
        ((tx_pend_queue.ObjectCount() >= pmin) &&
         ((tx_pend_queue.ByteCount()+theObject->Size()) > pend_size_max)))
    {
        return MDP_ERROR_TX_QUEUE_FULL;
    }
    else
    {
        if (congestion_control && !IsActiveServing())
        {
            double interval = MIN(grtt_advertise, bottleneck_rtt);
            // Probes should occupy no more than our transmit rate
            double nominal = ((double)segment_size)/((double)tx_rate);
            interval = MAX(interval, nominal);

            if (grtt_req_timer.IsActive(node->getNodeTime()))
            {
                if (grtt_req_timer.GetTimeRemaining(node->getNodeTime())
                                                                  > interval)
                {
                    grtt_req_timer.Deactivate(node);
                    grtt_req_timer.SetInterval(interval);
                    ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
                }
            }
            else
            {
                grtt_req_timer.SetInterval(interval);
                ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
            }
        }
        tx_pend_queue.Insert(theObject);
        if (tx_interval_timer.IsActive(node->getNodeTime()))
        {
            tx_interval_timer.Deactivate(node);
        }
        if (!tx_timer.IsActive(node->getNodeTime()))
        {
            ActivateTimer(tx_timer, TX_TIMEOUT, this);
        }
        if (tx_queue.IsEmpty()) Serve();
        return MDP_ERROR_NONE;
    }
}  // end MdpSession::QueueTxObject()

MdpObject* MdpSession::FindTxObject(MdpObject *theObject)
{
    // Search transmit object queues for object
    MdpObject *obj = tx_hold_queue.Find(theObject);
    if (!obj)
    {
        obj = tx_repair_queue.Find(theObject);
        if (!obj)
            obj = tx_pend_queue.Find(theObject);
    }
    return obj;
}  // end MdpSession::FindTxObject()

MdpObject* MdpSession::FindTxObjectById(UInt32 theId)
{
    // Search transmit object queues for object
    MdpObject* obj = tx_hold_queue.FindFromTail(theId);
    if (!obj)
    {
        obj = tx_repair_queue.FindFromTail(theId);
        if (!obj)
            obj = tx_pend_queue.FindFromTail(theId);
    }
    return obj;
}  // end MdpSession::FindTxObjectById()

MdpError MdpSession::RemoveTxObject(MdpObject* theObject)
{
    ASSERT(theObject);
    bool current = ((theObject->TransportId() == current_tx_object_id) &&
                   !theObject->NotifyPending());
    MdpError result = theObject->TxAbort();
    if (current)
    {
        if (tx_pend_queue.IsEmpty())
        {
            // NOTE: If the user queue's something,
            // "Serve()" is re-entrantly called
            Notify(MDP_NOTIFY_TX_QUEUE_EMPTY, NULL, NULL, MDP_ERROR_NONE);
        }
    }
    return result;
}  // end MdpSession::RemoveTxObject()

// The following routine decides what the
// server should send next ... This is being called
// when a new server message is needed
// (If "false" is returned, session may no longer be valid!
bool MdpSession::Serve()
{
    // Find lowest ordinal TxPending object in the repair_queue
    MdpObject *theObject = tx_repair_queue.Head();
    while (theObject && !theObject->TxPending())
    {
        ASSERT(theObject->RepairPending());
        theObject = theObject->next;
    }
    if (!theObject)  // Nothing currently pending transmission
    {
        // First, get any positive acknowledgements for
        // current object before sending another
        if (pos_ack_pending)
        {
            if (tx_interval_timer.IsActive(node->getNodeTime())) return true;
            if (TransmitObjectAckRequest(current_tx_object_id))
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: Server requesting postive acknowledgement for obj:%u\n",
                        current_tx_object_id);
                }
                flush_count++;  // pack_req's count as flushes
                tx_interval_timer.SetInterval(2.0 * GrttEstimate());
                ActivateTimer(tx_interval_timer, TX_INTERVAL_TIMEOUT,this);
                return true;
            }
            else
            {
                // Everyone has acknowledged
                pos_ack_pending = false;
                MdpObject* currentTxObject = FindTxObjectById(current_tx_object_id);
                if (currentTxObject)
                {
                    currentTxObject->Notify(MDP_NOTIFY_TX_OBJECT_ACK_COMPLETE,
                                            MDP_ERROR_NONE);
                    if (currentTxObject->WasAborted()) currentTxObject->TxAbort();
                }
            }
        }  // end if (pos_ack_pending)

        // Get next object in the tx_pend_queue
        theObject = tx_pend_queue.RemoveHead();
        if (theObject)
        {
            tx_pend_queue_active = true;
            MdpError err = theObject->Open();
            if (err != MDP_ERROR_NONE)
            {
                theObject->SetError(err);
                delete theObject;
                return Serve();  // try again (TBD) have user restart server ???
            }
            // theObject's size was filled on theObject->Open()
            if (!theObject->TxInit((unsigned char)ndata,
                                   (unsigned char)nparity,
                                   (unsigned int)segment_size))
            {
                theObject->Close();
                theObject->SetError(MDP_ERROR_MEMORY);
                delete theObject;
                return Serve();  // try again (TBD) have user restart server ???
            }
            tx_repair_queue.Insert(theObject);
            theObject->Notify(MDP_NOTIFY_TX_OBJECT_START, MDP_ERROR_NONE);
            if (theObject->WasAborted())
            {
                theObject->TxAbort();
                theObject = NULL;
                return Serve();
            }
            current_tx_object_id = theObject->TransportId();
            theObject->SetFirstPass();

            pos_ack_pending = pos_ack_list.Head() ? true : false;
        }
        else
        {
            // Notify application of empty queue if we haven't already
            if (tx_pend_queue_active)
            {
                tx_pend_queue_active = false;
                // Serve() will be called re-entrantly if
                // something is queued by application
                Notify(MDP_NOTIFY_TX_QUEUE_EMPTY, NULL, NULL, MDP_ERROR_NONE);
            }
            // Flush if we're done transmitting for the moment
            if (tx_queue.IsEmpty()
                && !tx_interval_timer.IsActive(node->getNodeTime()))
            {
                if (flush_count < robust_factor)
                {
                    TransmitFlushCmd(current_tx_object_id);
                    flush_count++;
                    tx_interval_timer.SetInterval(2.0 * GrttEstimate());
                    ActivateTimer(tx_interval_timer, TX_INTERVAL_TIMEOUT, this);
                }
                else if (ServerIsClosing())
                {
                    // Complete graceful close & notify app
                    CloseServer(true);
                    Notify(MDP_NOTIFY_SERVER_CLOSED, NULL, NULL, MDP_ERROR_NONE);
                }
            }
            return true;
        }  // end if/else(tx_pend_queue.RemoveHead())
    }  // end if (!theObject)

    ASSERT(theObject);
    // Deactivate the tx_interval_timer if it's active
    if (tx_interval_timer.IsActive(node->getNodeTime()))
        tx_interval_timer.Deactivate(node);

    // Build MDP_DATA message & queue it for transmission
    MdpMessage *theMsg =
        theObject->BuildNextServerMsg(&msg_pool, &server_vector_pool,
                                      &server_block_pool, &encoder);

    if (theMsg)
    {
        // Fill in common message fields
        theMsg->version = MDP_PROTOCOL_VERSION;
        theMsg->sender = mgr->node_id;
        QueueMessage(theMsg);

        // (TBD) Make Pos ack process part of object state
        // Reset positive ack polling/ object flushing with new activity
        if (!theObject->TxPending())// && !theObject->RepairPending())
        {
            // This object transmission complete for now
            if (!theObject->RepairPending())
            {
                DeactivateTxObject(theObject);
                if (MDP_DEBUG)
                {
                    char clockStr[MAX_CLOCK_STRING_LENGTH];
                    ctoa(node->getNodeTime(), clockStr);
                    printf("mdp: Server sent last pending vector for obj: %u at time %s\n",
                        theObject->TransportId(), clockStr);
                }
            }
            if (theObject->FirstPass())
            {
                theObject->ClearFirstPass();
                theObject->Notify(MDP_NOTIFY_TX_OBJECT_FIRST_PASS,
                                  MDP_ERROR_NONE);
                if (theObject->WasAborted())
                {
                    RemoveTxObject(theObject);
                    theObject = NULL;
                }
            }
        }
        // Reset flushing on any object transmit activity
        flush_count = 0;
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Server failed to get a message from object: %.64s\n",
                theObject->Info());
        }
        // Probably out of resources because of pending tx messages
        // This will allow us to recover but we need a better approach here
        if (tx_queue.IsEmpty())
        {
            tx_interval_timer.SetInterval(GrttEstimate());
            ActivateTimer(tx_interval_timer, TX_INTERVAL_TIMEOUT, this);
        }
    }
    return true;
}  // end MdpSession::Serve()


bool MdpSession::OnReportTimeout()
{
    struct timevalue currentTime;
    ProtoSystemTime(currentTime, node->getNodeTime());

    UInt32 period = (UInt32)(currentTime.tv_sec - last_report_time.tv_sec);

    DeactivateTimer(report_timer);

    if (period)
    {
        client_stats.duration += period;
        client_stats.tx_rate /= period;
        client_stats.rx_rate /= period;
        client_stats.goodput /= period;
    }
    else
    {
        client_stats.tx_rate = 0;
        client_stats.rx_rate = 0;
        client_stats.goodput = 0;
    }
    // Update client buffer usage reporting
    client_stats.buf_stat.peak = ClientBufferPeakUsage();
    client_stats.buf_stat.overflow = ClientBufferOverruns();

    // Get latest current recv objects pending;
    client_stats.active = PendingRecvObjectCount();

#ifdef PROTO_DEBUG
    if (MDP_DEBUG)
    {
    // Print out the report we would (or will) send
    // Only if we've heard from a server
    //if (server_list.Head())
    {
        MdpClientStats *stat = &client_stats;
        printf("*******************************************************\n");
        printf("MDP_REPORT for node:%lu \n", LocalNodeId());
        printf("   Session duration : %lu sec.\n", stat->duration);
        printf("   Objects completed: %lu\n", stat->success);
        printf("   Objects pending  : %lu\n", stat->active);
        printf("   Objects failed   : %lu\n", stat->fail);
        printf("   Server resyncs   : %lu\n", stat->resync);
        printf("   Current goodput  : %.3f kbps\n",
                        ((double)stat->goodput * 8.0)/1000.0);
        printf("   Current rx rate  : %.3f kbps\n",
                        ((double)stat->rx_rate * 8.0)/1000.0);
        printf("   Current tx rate  : %.3f kbps\n",
                        ((double)stat->tx_rate * 8.0)/1000.0);
        printf("   NACKs transmitted: %lu\n", stat->nack_cnt);
        printf("   NACKs suppressed : %lu\n", stat->supp_cnt);
        printf("   Block loss stats : %lu, %lu, %lu, %lu, %lu, %lu\n",
                        stat->blk_stat.lost_00, stat->blk_stat.lost_05,
                        stat->blk_stat.lost_10, stat->blk_stat.lost_20,
                        stat->blk_stat.lost_40, stat->blk_stat.lost_50);
        printf("   Buffer usage     : peak>%luK overruns>%lu\n",
                        (stat->buf_stat.peak+500)/1000,
                        stat->buf_stat.overflow);
        printf("*******************************************************\n");
    }
    }
#endif // PROTO_DEBUG

    // If we're not supposed to send reports, bail
    if (status_reporting && tx_rate)
    {
        MdpServerNode* nextServer;
        if (UnicastNacks() && !IsServer())
            nextServer = (MdpServerNode*) server_list.Head();
        else
            nextServer = (MdpServerNode*) true;  // dummy server for broadcast
        while (nextServer)
        {
            MdpMessage *theMsg = msg_pool.Get();
            if (theMsg)
            {
                theMsg->type = MDP_REPORT;
                theMsg->version = MDP_PROTOCOL_VERSION;
                theMsg->sender = LocalNodeId();
                theMsg->report.status = (unsigned char)(status & 0x00ff);
                theMsg->report.flavor = MDP_REPORT_HELLO;
                //strncpy(theMsg->report.node_name, LocalNodeName(), MDP_NODE_NAME_MAX);
                memset(theMsg->report.node_name, 0, MDP_NODE_NAME_MAX);
                strncpy(theMsg->report.node_name, LocalNodeName(), strlen(LocalNodeName()));

                // if MDP_CLIENT, update client_stats into MDP_REPORT
                if (IsClient())
                    memcpy(&theMsg->report.client_stats, &client_stats,
                           sizeof(MdpClientStats));

                if (UnicastNacks() && !IsServer())
                {
                    theMsg->report.dest = nextServer->Address();
                    QueueMessage(theMsg);
                    nextServer = (MdpServerNode*) nextServer->NextInTree();
                }
                else
                {
                    theMsg->report.dest = &addr;  // broadcast to session addr
                    QueueMessage(theMsg);
                    break;  // send only one report for broadcast
                }
            }
            else
            {
                if (MDP_DEBUG)
                {
                    printf("Session msg_pool is empty, can't transmit MDP_REPORT\n");
                }
                break;
            }
        }  // end while (nextServer);
    }  // end if (status_reporting)
    // Reset counters
    client_stats.tx_rate = 0;
    client_stats.rx_rate = 0;
    client_stats.goodput = 0;
    last_report_time = currentTime;
    // Application is never notified on this timeout
    return true;
}  // end MdpSession::OnReportTimeout()

void MdpSession::PurgeClientMessages(MdpServerNode *theServer)
{
    // Remove client messages destined to specific remote server from tx_queue
    MdpMessage *next = tx_queue.Head();
    while (next)
    {
        switch (next->type)
        {
            case MDP_NACK:
                if (theServer == next->nack.server
                    && next->nack.data)
                {
                    theServer->VectorReturnToPool(next->nack.data);
                    next->nack.data = NULL;
                }
                else
                {
                    next = next->Next();
                    continue;
                }
                break;

            case MDP_ACK:
                if (theServer != next->ack.server)
                {
                    next = next->Next();
                    continue;
                }
                break;

            default:
                // Ignore other message types
                next = next->Next();
                continue;
        }
        MdpMessage *msg = next;
        next = next->Next();
        tx_queue.Remove(msg);
        theServer->MessageReturnToPool(msg);
    }
}  // end MdpSession::PurgeClientMessages()

void MdpSession::PurgeServerMessages()
{
    // Remove messages specific to local server from tx_queue
    MdpMessage *next = tx_queue.Head();
    while (next)
    {
        switch (next->type)
        {
            case MDP_INFO:
                if (next->object.info.data)
                {
                    server_vector_pool.Put(next->object.info.data);
                    next->object.info.data = NULL;
                }
                break;

            case MDP_DATA:
                if ((next->object.flags & MDP_DATA_FLAG_FILE)
                    && next->object.data.data)
                {
                    server_vector_pool.Put(next->object.data.data);
                    next->object.data.data = NULL;
                }
                break;

            case MDP_PARITY:
                if (next->object.parity.data)
                {
                    server_vector_pool.Put(next->object.parity.data);
                    next->object.parity.data = NULL;
                }
                break;

            case MDP_CMD:
                if (MDP_CMD_SQUELCH == next->cmd.flavor
                    && next->cmd.squelch.data)
                {
                    server_vector_pool.Put(next->cmd.squelch.data);
                    next->cmd.squelch.data = NULL;
                }
                else if (MDP_CMD_ACK_REQ == next->cmd.flavor
                         && next->cmd.ack_req.data)
                {
                    server_vector_pool.Put(next->cmd.ack_req.data);
                    next->cmd.ack_req.data = NULL;
                }
                else if (MDP_CMD_GRTT_REQ == next->cmd.flavor
                         && next->cmd.grtt_req.data)
                {
                    server_vector_pool.Put(next->cmd.grtt_req.data);
                    next->cmd.grtt_req.data = NULL;
                }
                else if (MDP_CMD_NACK_ADV == next->cmd.flavor
                         && next->cmd.nack_adv.data)
                {
                    server_vector_pool.Put(next->cmd.nack_adv.data);
                    next->cmd.nack_adv.data = NULL;
                }
                break;

            default:
                // Ignore other message types
                next = next->Next();
                continue;
        }
        MdpMessage *msg = next;
        next = next->Next();
        tx_queue.Remove(msg);
        msg_pool.Put(msg);
    }
}  // end MdpSession::PurgeServerMessages()

bool MdpSession::OnTxTimeout()
{
    bool result;
    bool msgSent = false;
    MdpPersistentInfo mdpInfo;
    MdpObject* objectPtr = NULL;
    Message* theMsgPtr = NULL;
    UInt32 objectId;
    Int32 theVirtualSize = 0;    //virtual size in original app sim packet
    Int32 virtualPayloadSize = 0; //virtual size for this MDP packet
#ifdef ADDON_DB
    BOOL fragIdSpecified = FALSE;
    Int32 fragId = -1;
#endif

    // Get next server message
    MdpMessage* theMsg = tx_queue.GetNextMessage();

    if (theMsg)
    {
        // "Pre-Pack()" message specific processing
        const MdpProtoAddress* destAddr = NULL;
        bool clientMsg = false;
        switch (theMsg->type)
        {
            case MDP_REPORT:
                if (MDP_DEBUG_MSG_FLOW)
                {
                     printf("MdpSession::OnTxTimeout: "
                            "Node %d Sending MDP_REPORT\n",
                             node->nodeId);
                }
                destAddr = theMsg->report.dest;
                clientMsg = true;
                // incrementing REPORT sent msg stat count at receiver
                commonStats.numReportMsgSentCount++;
                break;

            case MDP_CMD:
                if (MDP_DEBUG_MSG_FLOW)
                {
                     printf("MdpSession::OnTxTimeout: "
                            "Node %d Sending MDP_CMD\n",
                             node->nodeId);
                }
                theMsg->cmd.sequence = server_sequence++;
                theMsg->cmd.grtt = grtt_quantized;
                destAddr = &addr;

                switch (theMsg->cmd.flavor)
                {
                    case MDP_CMD_FLUSH:
                        if (MDP_DEBUG_MSG_FLOW)
                        {
                            printf("MdpSession::OnTxTimeout: "
                                   "Node %d Sending MDP_CMD_FLUSH\n",
                                    node->nodeId);
                        }
                        // incrementing CMD FLUSH sent stat count
                        commonStats.numCmdFlushMsgSentCount++;
                        break;
                    case MDP_CMD_SQUELCH:
                        if (MDP_DEBUG_MSG_FLOW)
                        {
                            printf("MdpSession::OnTxTimeout: "
                                   "Node %d Sending MDP_CMD_SQUELCH\n",
                                    node->nodeId);
                        }
                        // incrementing CMD SQUELCH sent stat count
                        commonStats.numCmdSquelchMsgSentCount++;
                        break;
                    case MDP_CMD_ACK_REQ:
                        if (MDP_DEBUG_MSG_FLOW)
                        {
                            printf("MdpSession::OnTxTimeout: "
                                   "Node %d Sending MDP_CMD_ACK_REQ\n",
                                    node->nodeId);
                        }
                        // incrementing CMD ACK REQ sent stat count
                        commonStats.numCmdAckReqMsgSentCount++;
                        break;
                    case MDP_CMD_GRTT_REQ:
                        {
                            if (MDP_DEBUG_MSG_FLOW)
                            {
                                printf("MdpSession::OnTxTimeout: "
                                   "Node %d Sending MDP_CMD_GRTT_REQ\n",
                                    node->nodeId);
                            }
                            ProtoSystemTime(theMsg->cmd.grtt_req.send_time,
                                            node->getNodeTime());
                            // incrementing CMD GRTT REQ sent stat count
                            commonStats.numCmdGrttReqMsgSentCount++;
                            break;
                        }
                    case MDP_CMD_NACK_ADV:
                        if (MDP_DEBUG_MSG_FLOW)
                        {
                            printf("MdpSession::OnTxTimeout: "
                                   "Node %d Sending MDP_CMD_NACK_ADV\n",
                                    node->nodeId);
                        }
                        // incrementing CMD NACK ADV sent stat count
                        commonStats.numCmdNackAdvMsgSentCount++;
                        break;
                }

                // incrementing total CMD msg sent stat count
                commonStats.numCmdMsgSentCount++;
                break;

            case MDP_INFO:
                if (MDP_DEBUG_MSG_FLOW)
                {
                    printf("MdpSession::OnTxTimeout: "
                           "Node %d Sending MDP_INFO\n",
                            node->nodeId);
                }
                // incrementing INFO sent msg stat count
                commonStats.numInfoMsgSentCount++;
                virtualPayloadSize = theMsg->object.info.len -
                                        theMsg->object.info.actual_data_len;
            case MDP_DATA:
                if (theMsg->type == MDP_DATA)
                {
                    if (MDP_DEBUG_MSG_FLOW)
                    {
                        printf("MdpSession::OnTxTimeout: "
                               "Node %d Sending MDP_DATA\n",
                                node->nodeId);
                    }
                    // incrementing DATA sent msg stat count
                    commonStats.numDataMsgSentCount++;
                    virtualPayloadSize = theMsg->object.data.len -
                                        theMsg->object.data.actual_data_len;
#ifdef ADDON_DB
                    MdpObject* currentTxObject =
                        FindTxObjectById(theMsg->object.object_id);
                    fragIdSpecified = TRUE;
                    fragId = currentTxObject->current_block_id *
                             currentTxObject->ndata +
                             currentTxObject->current_vector_id;

                    if ((theMsg->object.flags & MDP_DATA_FLAG_BLOCK_END) &&
                        fragId == 0)
                    {
                        fragIdSpecified = FALSE;
                    }
#endif
                }
            case MDP_PARITY:
                if (theMsg->type == MDP_PARITY)
                {
                    if (MDP_DEBUG_MSG_FLOW)
                    {
                        printf("MdpSession::OnTxTimeout: "
                               "Node %d Sending MDP_PARITY\n",
                                node->nodeId);
                    }
                    // incrementing PARITY sent msg stat count
                    commonStats.numParityMsgSentCount++;
                    virtualPayloadSize = theMsg->object.parity.len -
                                       theMsg->object.parity.actual_data_len;
                }
                theMsg->object.sequence = server_sequence++;
                destAddr = &addr;
                objectId = theMsg->object.object_id;
                objectPtr = FindTxObjectById(objectId);
                theMsgPtr = (Message*)objectPtr->GetMsgPtr();
                theVirtualSize = objectPtr->GetVirtualSize();
                break;

            case MDP_NACK:
                if (MDP_DEBUG_MSG_FLOW)
                {
                    printf("MdpSession::OnTxTimeout: "
                           "Node %d Sending MDP_NACK\n",
                            node->nodeId);
                }
                theMsg->nack.server->CalculateGrttResponse(
                                                &theMsg->nack.grtt_response);
                theMsg->nack.loss_estimate = QuantizeLossFraction(theMsg->nack.server->LossEstimate());
                theMsg->nack.grtt_req_sequence = theMsg->nack.server->GrttReqSequence();
                destAddr = theMsg->nack.dest;
                // incrementing NACK msg sent stat count
                commonStats.numNackMsgSentCount++;
                clientMsg = true;
                break;

            case MDP_ACK:
                if (MDP_DEBUG_MSG_FLOW)
                {
                    printf("MdpSession::OnTxTimeout: "
                           "Node %d Sending MDP_ACK\n",
                            node->nodeId);
                }
                theMsg->ack.server->CalculateGrttResponse(
                                        &theMsg->ack.grtt_response);
                theMsg->ack.loss_estimate = QuantizeLossFraction(theMsg->ack.server->LossEstimate());
                theMsg->ack.grtt_req_sequence = theMsg->ack.server->GrttReqSequence();
                destAddr = theMsg->ack.dest;
                // incrementing ACK msg sent stat count
                commonStats.numPosAckMsgSentCount++;
                clientMsg = true;
                break;
        }
        // Pack the message into a buffer and send
        char buffer[MSG_SIZE_MAX];
        memset(buffer, 0, MSG_SIZE_MAX);
        unsigned int len = theMsg->Pack(buffer);
        ASSERT((len > 0) && (len <= MSG_SIZE_MAX));

        if (!clientMsg || !EmconClient())
        {
            // Send the message
            // (TBD) Error check the SendTo() call and "Notify" user on error
            msgSent = true;
            // filling persistent info
            MdpPersistentInfoForSessionInList(node, &mdpInfo, this);
            mdpInfo.appType = this->GetAppType();
            mdpInfo.virtualSize = theVirtualSize;
            mdpInfo.sourcePort = (Int16) this->localAddress.GetPort();

            // Initiate the UDP message
            Message *msg = APP_UdpCreateMessage(
                node,
                localAddress.GetAddress(),
                (short) this->localAddress.GetPort(),
                destAddr->GetAddress(),
                destAddr->GetPort(),
                TRACE_MDP,
                tos);

            // Call helper function to copy previous message info
            APP_UdpCopyMdpInfo(
                node,
                msg,
                (char*)& mdpInfo,
                theMsgPtr
#ifdef ADDON_DB
                , fragIdSpecified,
                fragId
#endif
                );

            // Add the buffer data as the payload.
            APP_AddPayload(
                node,
                msg,
                buffer,
                len);

            APP_AddVirtualPayload(node, msg, virtualPayloadSize);

            APP_UdpSend(node, msg);

            if (msgSent)
            {
                // MDP_REPORTS are not currently counted in the data we collect
                if (theMsg->type != MDP_REPORT)
                {
                    if (IsClient())
                    {
                        client_stats.tx_rate += (len + virtualPayloadSize);
                    }
                    else if (IsServer())
                    {
                        commonStats.senderTxRate += (len + virtualPayloadSize);
                    }
                }

                if (IsServer() && theMsg->type == MDP_DATA)
                {
                    commonStats.totalBytesSent += theMsg->object.data.len;
                }

                if (IsServer() && theMsg->type == MDP_PARITY)
                {
                    commonStats.totalBytesSent += theMsg->object.parity.len;
                }
                 // Update transmit packet size average
                nominal_packet_size += 0.05 *
                                        (((double)(len + virtualPayloadSize))
                                                      - nominal_packet_size);
            }
            // Calculate next timeout for the "tx_timer"
            tx_timer.SetInterval((double)(len + virtualPayloadSize)
                                                          / (double)tx_rate);
            ActivateTimer(tx_timer, TX_TIMEOUT, this);
            result = true;
        }
        else
        {
            tx_timer.SetInterval(0.0);
            ActivateTimer(tx_timer, TX_TIMEOUT,this);
            result = true;
        }

        // Return theMsg and vectors to associcated pools ...
        switch (theMsg->type)
        {
            case MDP_REPORT:
                msg_pool.Put(theMsg);
                break;

            case MDP_CMD:
                if (MDP_CMD_GRTT_REQ == theMsg->cmd.flavor)
                {
                    if (theMsg->cmd.grtt_req.data)
                    {
                        server_vector_pool.Put(theMsg->cmd.grtt_req.data);
                    }
                    theMsg->cmd.grtt_req.data = NULL; // (TBD) remove after debug
                    theMsg->cmd.grtt_req.len = 0;
                }
                else if (MDP_CMD_ACK_REQ == theMsg->cmd.flavor)
                {
                    if (theMsg->cmd.ack_req.data)
                    {
                        server_vector_pool.Put(theMsg->cmd.ack_req.data);
                    }
                    theMsg->cmd.ack_req.data = NULL; // (TBD) remove after debug
                    theMsg->cmd.ack_req.len = 0;
                }
                else if (MDP_CMD_SQUELCH == theMsg->cmd.flavor)
                {
                    if (theMsg->cmd.squelch.data)
                    {
                        server_vector_pool.Put(theMsg->cmd.squelch.data);
                    }
                    theMsg->cmd.squelch.data = NULL; // (TBD) remove after debug
                    theMsg->cmd.squelch.len = 0;
                }
                else if (MDP_CMD_NACK_ADV == theMsg->cmd.flavor)
                {
                    if (theMsg->cmd.nack_adv.data)
                    {
                       server_vector_pool.Put(theMsg->cmd.nack_adv.data);
                    }
                    theMsg->cmd.nack_adv.data = NULL; // (TBD) remove after debug
                    theMsg->cmd.nack_adv.len = 0;
                }
                msg_pool.Put(theMsg);
                break;

            case MDP_INFO:
                server_vector_pool.DecreaseVectorCountUsage();
                theMsg->object.info.data = NULL;       // (TBD) remove after DEBUG
                theMsg->object.info.len = 0;
                theMsg->object.info.actual_data_len = 0;
                msg_pool.Put(theMsg);
                break;

            case MDP_DATA:
                if (theMsg->object.flags & MDP_DATA_FLAG_FILE)
                {
                    if (theMsg->object.data.data)
                    {
                        server_vector_pool.Put(theMsg->object.data.data);
                    }
                }
                theMsg->object.data.data = NULL;   // (TBD) remove after DEBUG
                theMsg->object.data.len = 0;
                theMsg->object.data.actual_data_len = 0;
                msg_pool.Put(theMsg);
                break;

            case MDP_PARITY:
                server_vector_pool.DecreaseVectorCountUsage();
                theMsg->object.parity.data = NULL;   // (TBD) remove after DEBUG
                theMsg->object.parity.len = 0;
                theMsg->object.parity.actual_data_len = 0;
                msg_pool.Put(theMsg);
                break;

            case MDP_NACK:
                if (theMsg->nack.data)
                {
                    theMsg->nack.server->VectorReturnToPool(
                                                     theMsg->nack.data);
                }
                theMsg->nack.data = NULL;   // (TBD) remove after DEBUG
                theMsg->nack.nack_len = 0;
                theMsg->nack.server->MessageReturnToPool(theMsg);
                break;

             case MDP_ACK:
                theMsg->ack.server->MessageReturnToPool(theMsg);
                break;
        }
        // Put next server message into queue
        if (tx_queue.IsEmpty() && IsServer())
        {
            Serve();
        }
    }
    else
    {
        // free tx_timer message
        MESSAGE_Free(node, tx_timer.msg);
        tx_timer.msg = NULL;
        tx_timer.Deactivate(node);
        result = false;
    }  // end if/else(theMsg)
    if (notify_abort)
    {
        if (MDP_DEBUG)
        {
            printf("MdpSession::OnTxTimeout() notify_abort, deleting session ...\n");
        }
        mgr->DeleteSession(this);
        return false;
    }
    else
    {
        return result;
    }
}  // end MdpSession::OnTxTimeout()

bool MdpSession::OnTxIntervalTimeout()
{

  DeactivateTimer(tx_interval_timer);
  if (0 == tx_rate) return true;

  if (tx_queue.IsEmpty() && IsServer()) Serve();
  if (notify_abort)
  {
      mgr->DeleteSession(this);
  }
  return false;
}  // end MdpSession::OnTxIntervalTimeout()

const int MDP_GRTT_DECREASE_DELAY = 2;
bool MdpSession::OnGrttReqTimeout()
{
    DeactivateTimer(grtt_req_timer);
    if (0 == tx_rate) return true;
    MdpMessage* theMsg = msg_pool.Get();
    if (theMsg)
    {
        if (grtt_response && (grtt_wildcard_period >= grtt_req_interval))
        {
            // Introduce new peak with linear smoothing filter
            // Increases grtt quickly, decreases it slowly
            // only after MDP_GRTT_DECREASE_DELAY consecutive smaller
            // peak responses
            if (grtt_current_peak < grtt_measured)
            {
                if (grtt_decrease_delay_count-- == 0)
                {
                    grtt_measured = 0.5 * grtt_measured +
                                    0.5 * grtt_current_peak;
                    grtt_decrease_delay_count = MDP_GRTT_DECREASE_DELAY;
                    grtt_current_peak = 0.0;
                }
            }
            else
            {
                // Increase has already been incorporated into estimate
                grtt_current_peak = 0.0;
                grtt_decrease_delay_count = MDP_GRTT_DECREASE_DELAY;
            }
            if (grtt_measured < MDP_GRTT_MIN)
                grtt_measured = MDP_GRTT_MIN;
            else if (grtt_measured > grtt_max)
                grtt_measured = grtt_max;

            double pktInterval = (double)segment_size/(double)tx_rate;
            // min grtt should be 2*pktInterval
            pktInterval *= 2.0;
            grtt_advertise = MAX(pktInterval, grtt_measured);
            grtt_quantized = QuantizeRtt(grtt_advertise);
            // Recalculate grtt_advertise since quantization rounds upward
            grtt_advertise = UnquantizeRtt(grtt_quantized);
            grtt_response = false;
        }  // end if (grtt_response ...)

        // Queue next MDP_GRTT_REQ
        theMsg->type = MDP_CMD;
        theMsg->version = MDP_PROTOCOL_VERSION;
        theMsg->sender = mgr->node_id;
        theMsg->cmd.grtt = grtt_quantized;
        theMsg->cmd.flavor = MDP_CMD_GRTT_REQ;
        // Message transmission routine will fill in grtt.send_time
        memset(&theMsg->cmd.grtt_req.send_time, 0, sizeof(struct timevalue));
        double interval = 0, holdTime = 0;
        if (congestion_control && IsActiveServing())
        {
            AdjustRate(false);

            // Prepare next request for congestion control representatives
            // Get a vector
            char* vector = server_vector_pool.Get();
            if (vector)
            {
                theMsg->cmd.grtt_req.data = vector;
                theMsg->cmd.grtt_req.len = 0;
                // Pack vector with reps and their rtt's (quantized)
                MdpRepresentativeNode* nextRep = (MdpRepresentativeNode*) representative_list.Head();
                while (nextRep)
                {
                    if (nextRep->DecrementTimeToLive())
                    {
                        if (!theMsg->cmd.grtt_req.AppendRepresentative(nextRep->Id(),
                                                                       nextRep->RttEstimate(),
                                                                       (unsigned short)segment_size))
                        {
                            if (MDP_DEBUG)
                            {
                                printf("MdpSession::OnGrttReqTimeout() Probe rep list overflow!\n");
                            }
                        }
                        nextRep = (MdpRepresentativeNode*) nextRep->NextInTree();
                    }
                    else
                    {
                        //fprintf(stderr, "IMPEACHING rep: %u\n", nextRep->Id());
                        MdpRepresentativeNode* theRep = nextRep;
                        nextRep = (MdpRepresentativeNode*) nextRep->NextInTree();

                        representative_list.DetachNode(theRep);
                        delete theRep;
                        // If all representatives go away, reset probing
                        // (TBD) go back to "slow/no start"
                        if (!(--representative_count))
                        {
                            grtt_req_interval = grtt_req_interval_min;
                            grtt_wildcard_period = grtt_req_interval + 1.0;
                        }
                    }

                }  // end while (nextRep)
            }
            else
            {
                if (MDP_DEBUG)
                {
                    printf("Session server_vector_pool is empty, can't transmit MDP_GRTT_REQ\n");
                }
                msg_pool.Put(theMsg);
                return true;
            }

            interval = MIN(grtt_measured, bottleneck_rtt);
            // Probes should occupy less than our total transmit rate
            double nominal = ((double)segment_size)/((double)tx_rate);
            interval = MAX(interval, nominal);
            //if (fast_start) fprintf(stderr, "Probe interval: %f (grtt:%f brtt:%f nom:%f)\n",
            //                                 interval, grtt_measured, bottleneck_rtt, nominal);

            // Periodically do "wildcard" probe that everyone responds to
            if (grtt_wildcard_period >= grtt_req_interval)
            {
                theMsg->cmd.grtt_req.flags = MDP_CMD_GRTT_FLAG_WILDCARD;
                grtt_wildcard_period = interval;
                holdTime = grtt_req_interval;
                if (grtt_req_interval < grtt_req_interval_max)
                {
                    grtt_req_interval *= 2.0;
                    if (grtt_req_interval > grtt_req_interval_max)
                        grtt_req_interval = grtt_req_interval_max;
                }
                if (grtt_req_interval < grtt_req_interval_min)
                    grtt_req_interval = grtt_req_interval_min;
            }
            else
            {
                // We evaluate grtt response once per grtt_req_interval
                // "grtt_wildcard_period" keeps track of how long
                // it has been.
                grtt_wildcard_period += interval;
                theMsg->cmd.grtt_req.flags = 0;
                holdTime = 0.0; //grtt_measured/2.0;
            }
        }
        else  // !(congestion_control && IsActiveServing())
        {
            interval = holdTime = grtt_req_interval;
            if (congestion_control)
                theMsg->cmd.grtt_req.flags = MDP_CMD_GRTT_FLAG_WILDCARD;
            else
                 theMsg->cmd.grtt_req.flags = 0;  // Don't ACK when no congestion control
            theMsg->cmd.grtt_req.data = NULL;
            theMsg->cmd.grtt_req.len = 0;
            if (grtt_req_interval < grtt_req_interval_max)
            {
                grtt_req_interval *= 2.0;
                if (grtt_req_interval > grtt_req_interval_max)
                    grtt_req_interval = grtt_req_interval_max;
            }
            if (grtt_req_interval < grtt_req_interval_min)
                grtt_req_interval = grtt_req_interval_min;
            // We evaluate grtt response once per grtt_req_interval
            // "grtt_wildcard_period" keeps track of how long
            // it has been.
            grtt_wildcard_period = interval;
        }  // end if/else(congestion_control)

        grtt_req_sequence++;  // incr before send
        theMsg->cmd.grtt_req.sequence = grtt_req_sequence;

        // "hold_time" field is used to tell clients how to set their grtt_ack back-off timers
        theMsg->cmd.grtt_req.hold_time.tv_sec = (UInt32) holdTime;
        theMsg->cmd.grtt_req.hold_time.tv_usec =
            (UInt32)(((holdTime -  (double)theMsg->cmd.grtt_req.hold_time.tv_sec) * 1.0e06) + 0.5);
        theMsg->cmd.grtt_req.segment_size = (unsigned short)segment_size;
        theMsg->cmd.grtt_req.rate = tx_rate;
        theMsg->cmd.grtt_req.rtt = QuantizeRtt(bottleneck_rtt);
        theMsg->cmd.grtt_req.loss = QuantizeLossFraction(bottleneck_loss);

        grtt_req_timer.SetInterval(interval);
        ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
        QueueMessage(theMsg);
    }
    else
    {
        if (MDP_DEBUG)
        {
            printf("Session msg_pool is empty, can't transmit MDP_GRTT_REQ\n");
        }
    }
    // Application not currently notified on this timeout
    return true;
}  // end MdpSession::OnGrttReqTimeout()



bool MdpSession::OnTxHoldQueueExpiryTimeout()
{

    if (tx_hold_queue.ObjectCount() > 0)
    {
        // Find oldest tx_hold_queue (inactive) object
        MdpObject *obj = tx_hold_queue.Head();
        MdpObject *currentObj = NULL;
        clocktype expiryTime = (MDP_DEFAULT_TX_HOLD_QUEUE_EXPIRY_INERVAL
                                * SECOND);

        while (obj)
        {
            currentObj = obj;
            obj = obj->next;

            if (currentObj->GetTxCompletionTime() > 0 &&
                (node->getNodeTime() - currentObj->GetTxCompletionTime())
                                                                >=expiryTime)
            {
                tx_hold_queue.Remove(currentObj);
                ASSERT(currentObj);
                if (currentObj->IsOpen()) currentObj->Close();
                currentObj->Notify(MDP_NOTIFY_TX_OBJECT_FINISHED,
                                   MDP_ERROR_NONE);
                delete currentObj;
            }
        }
    }

    if (isLastDataObjectReceived
        && tx_pend_queue.IsEmpty()
        && tx_repair_queue.IsEmpty()
        && tx_hold_queue.IsEmpty()
        && tx_queue.IsEmpty())
    {
        ActivateTimer(session_close_timer,
                      SESSION_CLOSE_TIMEOUT,
                      this);
        //free tx_hold_queue_expiry_timer message
        MESSAGE_Free(node, tx_hold_queue_expiry_timer.msg);
        tx_hold_queue_expiry_timer.msg = NULL;
        tx_hold_queue_expiry_timer.Deactivate(node);
    }
    else
    {
        ActivateTimer(tx_hold_queue_expiry_timer,
                      TX_HOLD_QUEUE_EXPIRY_TIMEOUT,
                      this);
    }

    return true;
}


bool MdpSession::OnSessionCloseTimeout()
{
    session_close_timer.Deactivate(node);

    if (isLastDataObjectReceived
        && tx_pend_queue.IsEmpty()
        && tx_repair_queue.IsEmpty()
        && tx_hold_queue.IsEmpty()
        && tx_queue.IsEmpty())
    {
        //(TBD: Is this the correct time to close the server)
        // Start graceful end-of-transmission flushing
        SetServerFlag(MDP_SERVER_CLOSING);
        Serve();
    }
    else
    {
        ActivateTimer(session_close_timer,
                      SESSION_CLOSE_TIMEOUT,
                      this);
    }
    return true;
}



void MdpSession::AdjustRate(bool activeResponse)
{
//#ifdef ADJUST_RATE // Temporarily turn on/off rate adjustment
    // Adjust transmit rate within bounds
    if (goal_tx_rate >= tx_rate)
    {
        unsigned int probe_advance;
        int diff = grtt_req_sequence - bottleneck_sequence;
        if (diff < 0) diff += 256;
        if (diff < 2)
            probe_advance = 3;  // normal increase towards goal
        else if (diff < 3)
            probe_advance = 2;  // hold steady regardless of goal
        else if (diff < 4)
            probe_advance = 1;  // slow decrease regardless of goal
        else
            probe_advance = 0;  // fast decrease regardless of goal
        if (activeResponse)
            probe_advance = MAX(probe_advance, 2);  // increase on responses only
        //else if (fast_start)
        //    probe_advance = 2;
        else
            probe_advance = MIN(probe_advance, 2);  // decrease on timeout only

        // Only increase if recent ACK
        switch (probe_advance)
        {
            case 3:  // timely response, increase
            {
                // Exp increase
                UInt32 exp_rate =
                    (UInt32)(((double)tx_rate) / rate_decrease_factor);
                // Lin increase
                UInt32 lin_rate = tx_rate +
                    (UInt32)(rate_increase_factor * ((double)nominal_packet_size));
                //if (fast_start)
                    tx_rate = MAX(lin_rate, exp_rate);  // fast increase
                //else
                //    tx_rate = MIN(lin_rate, exp_rate);  // slow increase
                if (tx_rate > goal_tx_rate)
                    tx_rate = goal_tx_rate;
            }
            break;

            case 2:  // less than timely response, no change
                break;

            case 1:  // late response
            case 0:  // very late response
            {
                //fprintf(stderr, "Late response(%u) diff:%u\n", probe_advance, diff);
                // Lin decrease
                UInt32 lin_rate =
                    (UInt32)(rate_increase_factor * ((double)nominal_packet_size));
                if (tx_rate > lin_rate)
                    lin_rate = tx_rate - lin_rate;
                else
                    lin_rate = 0;
                // Exp decrease
                UInt32 exp_rate =
                    (UInt32) (((double)tx_rate) * rate_decrease_factor);

                if (probe_advance)
                    tx_rate = MAX(lin_rate, exp_rate);  // slow decrease
                else
                    tx_rate = MIN(lin_rate, exp_rate);  // fast decrease

                // Don't go below one packet per GRTT or one packet per second for now
                UInt32 minRate =
                    (UInt32) MIN((double)segment_size, ((double)segment_size)/grtt_measured);
                minRate = MAX(minRate, 1);
                if (tx_rate < minRate) tx_rate = minRate;
            }
            break;

            default:
            {
                // should never happen
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "This condition should not come in "
                        "function MdpSession::AdjustRate(). "
                        "Need to check the problem. \n");
                ERROR_ReportError(errStr);
            }
        }  // end switch (probe_advance)
    }
    else // if (goal_tx_rate < tx_rate)
    {
        // Decrease rate quickly towards goal
        // Lin decrease
        UInt32 lin_rate =
            (UInt32)(rate_increase_factor * ((double) segment_size));
        if (tx_rate > lin_rate)
            lin_rate = tx_rate - lin_rate;
        else
            lin_rate = 0;
        // Exp decrease
        UInt32 exp_rate =
            (UInt32) (((double)tx_rate) * rate_decrease_factor);

        tx_rate = MIN(lin_rate, exp_rate);  // fast decrease

        // Minumum rate bound MIN(1 segment per GRTT, 1 segment per second)
        UInt32 minRate = (UInt32)(((double)segment_size)/grtt_measured);
        minRate = (UInt32) MIN((UInt32)segment_size, minRate);
        minRate = MAX(minRate, 1);
        minRate = MAX(minRate, goal_tx_rate);
        if (tx_rate < minRate) tx_rate = minRate;
    }

    // Stay within rate bounds if they have been set
    // (ZERO min/max indicates no bound)
    if (tx_rate_max && (tx_rate > tx_rate_max)) tx_rate = tx_rate_max;
    if (tx_rate_min && (tx_rate < tx_rate_min)) tx_rate = tx_rate_min;

    double pktInterval = (double)segment_size / (double)tx_rate;
    // min grtt should be 2*pktInterval
    pktInterval *= 2.0;
    grtt_advertise = MAX(pktInterval, grtt_measured);
    grtt_quantized = QuantizeRtt(grtt_advertise);
    grtt_advertise = UnquantizeRtt(grtt_quantized);

#ifdef PROTO_DEBUG
    if (MDP_DEBUG)
    {
    if (congestion_control)
    {
        // For debugging congestion control, log current bottlneck info and tx rate
        struct timevalue currentTime;
        ProtoSystemTime(currentTime, this->GetNode()->getNodeTime());
        double theTime = (double) currentTime.tv_sec +
                 ((double) currentTime.tv_usec)/1.0e06;
        MdpRepresentativeNode* rep = (MdpRepresentativeNode*) representative_list.Head();
        if (rep)
        {
            // Find bottleneck representative
            MdpRepresentativeNode* next_rep = rep;
            while (next_rep)
            {
                if (rep->RateEstimate() < rep->RateEstimate())
                    rep = next_rep;
                next_rep = (MdpRepresentativeNode*)  next_rep->NextInTree();
            }
            printf("RateControlStatus> time>%f loss>%f rtt>%f tzero>%f goal_rate>%f "
                    "tx_rate>%f frate>%f grtt>%f server>%lu\n",
                theTime, rep->LossEstimate(), rep->RttEstimate(),
                rep->RttEstimate() + 4.0 * rep->RttVariance(),
                ((double)(goal_tx_rate*8))/1000.0, ((double)(tx_rate * 8))/1000.0,
                ((fictional_rate*8.0)/1000.0), grtt_measured, LocalNodeId());

        } // end if (rep)
    }  // end if (congestion_control)
    }
#endif // PROTO_DEBUG
//#endif  // ADJUST_RATE
}  // end MdpSession::AdjustRate()

void MdpSession::ServerProcessClientResponse(UInt32   clientId,
                                             struct timevalue* grttTimestamp,
                                             UInt16   lossQuantized,
                                             unsigned char   clientSequence)
{
    struct timevalue currentTime;
    ProtoSystemTime(currentTime, node->getNodeTime());
    double clientRtt = 0;

    // Only process ack if it's "valid" (non-zero grttTimestamp field)
    if (grttTimestamp->tv_sec || grttTimestamp->tv_usec)
    {
        // Calculate rtt_estimate for this client and process the response
        if (currentTime.tv_usec < grttTimestamp->tv_usec)
        {
            clientRtt =
                (double)(currentTime.tv_sec - grttTimestamp->tv_sec - 1);
            clientRtt +=
                ((double)(1000000 - (grttTimestamp->tv_usec - currentTime.tv_usec))) / 1.0e06;
        }
        else
        {
            clientRtt =
                (double)(currentTime.tv_sec - grttTimestamp->tv_sec);
            clientRtt +=
                ((double) (currentTime.tv_usec - grttTimestamp->tv_usec)) / 1.0e06;
        }

        // Lower limit on RTT (because of coarse timer resolution on some systems,
        // this can sometimes actually end up a negative value!)
        if (clientRtt < 1.0e-06)
        {
            clientRtt = 1.0e-06;
        }

        // Process client's grtt response
        grtt_response = true;
        if (clientRtt > grtt_current_peak)
        {
            // Immediately incorporate bigger RTT's
            grtt_current_peak = clientRtt;
            if (clientRtt > grtt_measured)
            {
                grtt_decrease_delay_count = MDP_GRTT_DECREASE_DELAY;
                grtt_measured = 0.25 * grtt_measured + 0.75 * clientRtt;
                if (grtt_measured > grtt_max) grtt_measured = grtt_max;

                double pktInterval = (double)segment_size/(double)tx_rate;
                // min grtt should be 2*pktInterval
                pktInterval *= 2.0;
                grtt_advertise = MAX(pktInterval, grtt_measured);
                grtt_quantized = QuantizeRtt(grtt_advertise);
                // Recalculate grtt_advertise since quantization rounds upward
                grtt_advertise = UnquantizeRtt(grtt_quantized);
            }
        }
        //if (fast_start) fprintf(stderr, "New clientRtt: %f\n", clientRtt);
    }
    else
    {
        clientRtt = grtt_measured;
    }

    double clientLoss = (double) UnquantizeLossFraction(lossQuantized);
    if (clientLoss > 0.0001)
    {
        if (fast_start)
        {
            //fprintf(stderr, "FastStart terminated.\n");
            fast_start = false;
        }
    }
    else
    {
        clientLoss = 0.0001;
    }

    MdpRepresentativeNode* theRep =
        (MdpRepresentativeNode*) representative_list.FindNodeById(clientId);
    if (theRep)
    {
        theRep->UpdateRttEstimate(clientRtt);
        theRep->SetLossEstimate(clientLoss);

        double clientRate = CalculateGoalRate(clientLoss,
                                              theRep->RttEstimate(),
                                              theRep->RttVariance());
                                              //0.75 * theRep->RttEstimate());
        // Adjustment to prevent oscillation due to queue/RTT cycling
        clientRate *= theRep->RttSqrt() / sqrt(clientRtt);

        theRep->SetRateEstimate(clientRate);
        theRep->SetGrttReqSequence(clientSequence);
        theRep->ResetTimeToLive();
    }
    else
    {
        // Potential new representative
        double clientRate = CalculateGoalRate(clientLoss, clientRtt, 0.75*clientRtt);
        // No scalling of the rate required
        if (representative_count < 1)
        {
            theRep = new MdpRepresentativeNode(clientId);
            if (!theRep)
            {
                if (MDP_DEBUG)
                {
                    printf("mdp: node:%u Server error allocating MdpRepresentativeNode\n",
                            LocalNodeId());
                }
                return;
            }
            representative_list.AttachNode(theRep);
            representative_count++;
        }
        else
        {
            double maxRate = 0.0;
            MdpRepresentativeNode* nextRep = (MdpRepresentativeNode*)representative_list.Head();
            while (nextRep)
            {
                if (nextRep->RateEstimate() > maxRate)
                {
                    theRep = nextRep;
                    maxRate = nextRep->RateEstimate();
                }
                nextRep = (MdpRepresentativeNode*)nextRep->NextInTree();
            }
            if (clientRate < theRep->RateEstimate())
            {
                // Bump old guy off the list (nodes sorted by id)
                representative_list.DetachNode(theRep);
                theRep->SetId(clientId);
                representative_list.AttachNode(theRep);
                theRep->ResetTimeToLive();
            }
            else
            {
                return; // This guy didn't make the list;
            }
        }
        ASSERT(theRep);
        theRep->SetRttEstimate(clientRtt);
        theRep->SetRttVariance(0.75*clientRtt);
        theRep->SetRttSqrt(sqrt(clientRtt));
        theRep->SetLossEstimate(clientLoss);
        theRep->SetRateEstimate(clientRate);
        theRep->SetGrttReqSequence(clientSequence);
    }  // end if/else(theRep)

    // Find minimum rate among representatives
    MdpRepresentativeNode* nextRep =
        (MdpRepresentativeNode*)representative_list.Head();
    ASSERT(nextRep);
    //MdpNodeId prevBottleneck = bottleneck_id;
    bottleneck_id = nextRep->Id();
    double minRate = nextRep->RateEstimate();
    bottleneck_sequence = nextRep->GrttReqSequence();

    bottleneck_rtt = nextRep->RttEstimate();
    bottleneck_loss = nextRep->LossEstimate();
    while (nextRep)
    {
        if (nextRep->RateEstimate() < minRate)
        {
            bottleneck_id = nextRep->Id();
            minRate = nextRep->RateEstimate();
            bottleneck_sequence = nextRep->GrttReqSequence();
            bottleneck_rtt = nextRep->RttEstimate();
            bottleneck_loss = nextRep->LossEstimate();
        }
        nextRep = (MdpRepresentativeNode*)nextRep->NextInTree();
    }

    fictional_rate =
        CalculateGoalRate(bottleneck_loss, bottleneck_rtt, 0.75*bottleneck_rtt);
    goal_tx_rate = (UInt32) (minRate + 0.5);

    // ??? Adjust only if IsActiveServing() ???
    if (congestion_control && (bottleneck_id == clientId)) AdjustRate(true);

//#ifdef PROTO_DEBUG
//    if (prevBottleneck != bottleneck_id)
//    {
//        struct timevalue currentTime;
//        ProtoSystemTime(currentTime);
//        double theTime = (double) currentTime.tv_sec +
//                 ((double) currentTime.tv_usec)/1.0e06;
//        printf("mdp bottleneckStatus> time>%f bottleneck>%lu\n",
//                  theTime, prevBottleneck);
//        printf("mdp bottleneckStatus> time>%f bottleneck>%lu\n",
//                  theTime, bottleneck_id);
//    }
//#endif // PROTO_DEBUG

}  // end MdpSession::ServerProcessClientResponse()

// tRTT = round trip time estimate (sec)
// l = packet loss fraction
double MdpSession::CalculateGoalRate(double l, double tRTT, double tRTTvar)
{
    if (tRTT < 1.0e-08) tRTT = 1.0e-08;
    double t0 = tRTT + (4.0 * tRTTvar);
    const double b = 1.0;
    if (l < 1.0e-08) l = 1.0e-08;
    double result =  (nominal_packet_size) /
        (
         (tRTT * sqrt((2.0/3.0) * b * l)) +
         (t0 * MIN(1.0, (3.0*sqrt((3.0/8.0)*b*l))) * l * (1 + 32.0 * l * l))
        );

    return result;
}  // end MdpSession::CalculateGoalRate()


// Moves object from session (active) tx_repair_queue
// to (idle) tx_hold_queue
void MdpSession::DeactivateTxObject(MdpObject* theObject)
{
    tx_repair_queue.Remove(theObject);
    tx_hold_queue.Insert(theObject);
    theObject->SetTxCompletionTime(node->getNodeTime());

    while ((tx_hold_queue.ObjectCount() > hold_count_max) ||
           ((tx_hold_queue.ObjectCount() > hold_count_min) &&
            ((tx_hold_queue.ByteCount()+theObject->Size()) > hold_size_max)))
    {
        MdpObject *obj = tx_hold_queue.Head();

        if (obj->TransportId() == theObject->TransportId())
        {
            obj = obj->next;
            if (!obj)
            {
               // in rare case of single oject just return
               return;
            }
        }
        ASSERT(obj);
        tx_hold_queue.Remove(obj);
        if (obj->IsOpen()) obj->Close();
        obj->Notify(MDP_NOTIFY_TX_OBJECT_FINISHED, MDP_ERROR_NONE);
        delete obj;
    }
}  // end MdpSession::DeactivateTxObject()

// Moves object from session (inactive) tx_hold_queue
// to (idle) tx_repair_queue
void MdpSession::ReactivateTxObject(MdpObject* theObject)
{
    if (congestion_control && !! IsActiveServing())
    {
        double interval = MIN(grtt_measured, bottleneck_rtt);
        // Probes should occupy no more than our transmit rate
        double nominal = ((double)segment_size)/((double)tx_rate);
        interval = MAX(interval, nominal);

        if (grtt_req_timer.IsActive(node->getNodeTime()))
        {
            if (grtt_req_timer.GetTimeRemaining(node->getNodeTime())
                                                              > interval)
            {
                grtt_req_timer.Deactivate(node);
                grtt_req_timer.SetInterval(interval);
                ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
            }
        }
        else
        {
            grtt_req_timer.SetInterval(interval);
            ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
        }
    }
    tx_hold_queue.Remove(theObject);
    tx_repair_queue.Insert(theObject);
    //init the tx completion time again
    theObject->SetTxCompletionTime(0);
}  // end MdpSession::ActivateTxObject()

bool MdpSession::TransmitObjectAckRequest(UInt32 object_id)
{
    MdpAckingNode* nextNode = (MdpAckingNode*) pos_ack_list.Head();
    MdpMessage* msg = NULL;
    char* vector = NULL;
    while (nextNode)
    {
        if (((nextNode->LastAckObject() != object_id) || !nextNode->HasAcked())
            && (nextNode->AckReqCount() > 0))
        {
            if (!msg)
            {
                msg = msg_pool.Get();
                if (msg)
                {
                    vector = server_vector_pool.Get();
                    if (!vector)
                    {
                        if (MDP_DEBUG)
                        {
                            printf("mdp: Server error getting vector for AckReqCmd!");
                        }
                        msg_pool.Put(msg);
                        msg = NULL;
                        return true;
                    }
                }
                else
                {
                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server msg_pool empty! can't send AckReqCmd!");
                    }
                    return true;
                }
                msg->type = MDP_CMD;
                msg->version = MDP_PROTOCOL_VERSION;
                msg->sender = mgr->node_id;
                msg->cmd.grtt = grtt_quantized;
                msg->cmd.flavor = MDP_CMD_ACK_REQ;
                msg->cmd.ack_req.object_id = object_id;
                msg->cmd.ack_req.data = vector;
                msg->cmd.ack_req.len = 0;
                // (TBD) Add grtt est to ACK_REQ
            }
            if (msg->cmd.ack_req.AppendAckingNode(nextNode->Id(), (unsigned short)segment_size))
                nextNode->DecrementAckReqCount();
            else
                break;  // message vector is full
        }
        else
        {
            // Give up on this node for this object
            // (TBD) report (notify) failure to ACK ???
            nextNode->SetLastAckObject(object_id);
        }
        nextNode = (MdpAckingNode*) nextNode->NextInTree();
    }  // end while (nextNode)
    if (msg)
    {
        QueueMessage(msg);
        return true;
    }
    else
    {
        return false; // evidently ACKing is complete
    }
}  // end MdpSession::TransmitObjectAckRequest()

void MdpSession::TransmitFlushCmd(UInt32 object_id)
{
    if (MDP_DEBUG)
    {
        char clockStr[MAX_CLOCK_STRING_LENGTH];
        ctoa(node->getNodeTime(), clockStr);
        printf("mdp: Server flushing (object_id = %u) at time %s...\n", object_id, clockStr);
    }
    MdpMessage *msg = msg_pool.Get();
    if (!msg)
    {
        if (MDP_DEBUG)
        {
            printf("mdp: Server msg_pool empty! can't send FlushCmd!");
        }
        return;
    }
    msg->type = MDP_CMD;
    msg->version = MDP_PROTOCOL_VERSION;
    msg->sender = mgr->node_id;
    msg->cmd.grtt = grtt_quantized;
    msg->cmd.flavor = MDP_CMD_FLUSH;
    if (ServerIsClosing())
        msg->cmd.flush.flags = MDP_CMD_FLAG_EOT;
    else
        msg->cmd.flush.flags = 0;
    msg->cmd.flush.object_id = object_id;
    QueueMessage(msg);
}  // end MdpSession::TransmitFlushCmd()



// This method is called when the server finds
// itself "resource-constrained"
// Note that "theObject" should be in the tx_repair_queue when this is called
bool MdpSession::ServerReclaimResources(MdpObject*    theObject,
                                        UInt32        blockId)
{
    // 1) Find oldest tx_hold_queue (inactive) object with resources
    MdpObject *obj = tx_hold_queue.Head();
    while (obj)
    {
        if (obj->HaveBuffers())
            break;
        else
            obj = obj->next;
    }

    if (obj)
    {
        ASSERT(obj != theObject);
        // Free all of the old object's resources
        obj->FreeBuffers();
        if (MDP_DEBUG)
        {
            printf("mdp: Server reclaimed resources from object: %u\n",
                obj->TransportId());
        }
        return true;
    }
    else // 2) Reverse search tx_repair_queue for (active) object with resources
    {
        obj = tx_repair_queue.Tail();
        while (obj)
        {
            if (obj->HaveBuffers() || obj == theObject)
            {
                MdpBlock* blk = obj->ServerStealBlock((obj != theObject), blockId);
                if (blk)
                {
                   blk->Empty(&server_vector_pool);
                   server_block_pool.Put(blk);

                    if (MDP_DEBUG)
                    {
                        printf("mdp: Server reclaimed resources from object: %u block:%u\n",
                                obj->TransportId(), blk->Id());
                    }
                   return true;
                }
            }
            obj = obj->prev;
        }
        return false;
    }
}  // end MdpSession::ServerReclaimResources()


UInt32 MdpSession::PendingRecvObjectCount()
{
    MdpServerNode *nextServer = (MdpServerNode*) server_list.Head();
    UInt32 total = 0;
    while (nextServer)
    {
        total += nextServer->PendingCount();
        nextServer = (MdpServerNode*) nextServer->NextInTree();
    }
    return total;
}  // end MdpSession::PendingRecvObjectCount()


MdpServerNode* MdpSession::NewRemoteServer(UInt32 nodeId)
{
    MdpServerNode* theServer = new MdpServerNode(nodeId, this);
    if (theServer->Open())
    {
        if (theServer) server_list.AttachNode(theServer);
        return theServer;
    }
    else
    {
        delete theServer;
        return NULL;
    }
}  // end MdpSession::NewRemoteServer()

void MdpSession::DeleteRemoteServer(MdpServerNode* theServer)
{
    server_list.DetachNode(theServer);
    theServer->Delete();
}  // end // end MdpSession::NewRemoteServer()


bool MdpSession::AddAckingNode(UInt32 nodeId)
{
    if (!pos_ack_list.FindNodeById(nodeId))
    {
        MdpAckingNode* theAcker = new MdpAckingNode(nodeId, this);
        if (theAcker)
        {
            pos_ack_list.AttachNode(theAcker);
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return true;  // already in list
    }
}  // end MdpSession::AddAckingNode()

void MdpSession::RemoveAckingNode(UInt32 nodeId)
{
    MdpAckingNode* theAcker = (MdpAckingNode*) pos_ack_list.FindNodeById(nodeId);
    if (theAcker)
        pos_ack_list.DeleteNode(theAcker);
}  // end MdpSession::RemoveAckingNode()


void MdpSession::SetTxRate(UInt32 value)
{
    bool jumpStart = (tx_rate == 0);
    tx_rate = value >> 3;

    if (tx_rate_min || tx_rate_max)
    {
        if (tx_rate < tx_rate_min)
            tx_rate = tx_rate_min;
        else if (tx_rate > tx_rate_max)
            tx_rate = tx_rate_max;
    }

    goal_tx_rate = tx_rate;
    double pktInterval = (double)segment_size / (double)tx_rate;
    grtt_advertise = MAX(pktInterval, grtt_measured);
    grtt_quantized = QuantizeRtt(grtt_advertise);
    grtt_advertise = UnquantizeRtt(grtt_quantized);
    if (tx_timer.IsActive(node->getNodeTime()) && node->getNodeTime() > 0)
    {
        if (tx_rate)
        {
            clocktype timeElapsed = tx_timer.GetInterval() -
                                 tx_timer.GetTimeRemaining(node->getNodeTime());
            double interval = (timeElapsed > pktInterval) ?
                              0.0 : (pktInterval - timeElapsed);
            tx_timer.Deactivate(node);
            tx_timer.SetInterval(interval);
            ActivateTimer(tx_timer, TX_TIMEOUT, this);
        }
        else
        {
            tx_timer.Deactivate(node);
        }
    }
    else if (jumpStart)
    {
        tx_timer.SetInterval(0.0);
        ActivateTimer(tx_timer, TX_TIMEOUT, this);
    }
}  // end MdpSession::SetTxRate()

void MdpSession::SetTxRateBounds(UInt32 min, UInt32 max)
{
    min >>= 3;
    max >>= 3;
    tx_rate_min = MIN(min, max);
    tx_rate_max = MAX(min, max);
    if (min || max)
    {
        tx_rate = MIN(tx_rate, tx_rate_max);
        tx_rate = MAX(tx_rate, tx_rate_min);
        double pktInterval = (double)segment_size / (double)tx_rate;
        grtt_advertise = MAX(pktInterval, grtt_measured);
        grtt_quantized = QuantizeRtt(grtt_advertise);
        grtt_advertise = UnquantizeRtt(grtt_quantized);
        if (tx_rate < tx_rate_min)
            SetTxRate(tx_rate_min);
        else if (tx_rate > tx_rate_max)
            SetTxRate(tx_rate_max);
    }
}  // end MdpSession::SetTxRate()

void MdpSession::SetMulticastLoopback(BOOL state)
{
    loopback = state;
    //if (rx_socket.IsOpen()) rx_socket.SetLoopback(state);
}

void MdpSession::SetPortReuse(bool state)
{
    port_reuse = state;
    //if (rx_socket.IsOpen()) rx_socket.SetReuse(state);
}

void MdpSession::SetTTL(unsigned char theTTL)
{
    ttl = theTTL;
    //if (rx_socket.IsOpen()) rx_socket.SetTTL(theTTL);
}  // end MdpSession ::SetTTL()

bool MdpSession::SetTOS(unsigned char theTOS)
{
    tos = theTOS;
    return true;
}  // end MdpSession::SetTOS()

bool MdpSession::SetAddress(MdpProtoAddress theAddress,
                            unsigned short rxPort,
                            unsigned short txPort)
{
    if (IsOpen()) return false;
    //bool result = addr.ResolveFromString(theAddress);
    addr = theAddress;
    addr.PortSet(rxPort);
    tx_port = txPort;
    if (rxPort == txPort)
        single_socket = true;
    else
        single_socket = false;
    return true;
}

bool MdpSession::SetGrttProbeInterval(double intervalMin, double intervalMax)
{
    if ((intervalMax < intervalMin) || (intervalMin < 0.1) ||
        (intervalMax < 5.0))
    {
        return false;
    }
    else
    {
        grtt_req_interval_min = intervalMin;
        grtt_req_interval_max = intervalMax;
        return true;
    }
}  // end MdpSession::SetGrttProbeInterval()

void MdpSession::SetGrttProbing(BOOL state)
{
    if (grtt_req_timer.IsActive(node->getNodeTime()))
    {
        if (!state) grtt_req_timer.Deactivate(node);
    }
    else
    {
        if (state)
        {
            grtt_response = false;
            grtt_current_peak = 0;
            grtt_decrease_delay_count = 0;
            bottleneck_sequence = 128;
            grtt_req_sequence = 0;
            grtt_req_timer.SetInterval(0.0);
            grtt_req_interval = grtt_req_interval_min;
            grtt_wildcard_period = grtt_req_interval_min * 2.0;
            ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
        }
    }
    grtt_req_probing = state;
}  // end MdpSession::SetGrttProbing()


// Queue a message for transmission
void MdpSession::QueueMessage(MdpMessage *theMsg)
{
    ASSERT(theMsg);
    tx_queue.QueueMessage(theMsg);
    if (tx_rate && !tx_timer.IsActive(node->getNodeTime()))
    {
        // Install tx_timer if it's not already active
        tx_timer.SetInterval(0.0);
        ActivateTimer(tx_timer, TX_TIMEOUT, this);
    }
}  // end MdpSession::QueueMessage()


void MdpSession::SetStatusReporting(BOOL state)
{
    // report_timer always runs to collect statistics
    // for DEBUG printouts
//#ifdef PROTO_DEBUG
    status_reporting = state;
//#else
    //if (state != status_reporting)
    //{
        if (status_reporting)
        {
           if ((IsServer()
               || IsClient())
               && (!report_timer.IsActive(node->getNodeTime())))
           {
               ActivateTimer(report_timer, REPORT_TIMEOUT, this);
           }
        }
        else
        {
            if (report_timer.IsActive(node->getNodeTime()))
                report_timer.Deactivate(node);
        }
//        status_reporting = state;
//    }
//#endif // end if/else PROTO_DEBUG
}  // end MdpSession::SetStatusReporting()

MdpError MdpSession::Open()
{
    // For now, clients & servers share a common message pool
    if (0 == msg_pool.Depth())
    {
        if (MDP_ERROR_NONE != msg_pool.Init(MDP_MSG_POOL_DEPTH))
        {
            CloseServer(true);  // quick, hard shutdown
            return MDP_ERROR_MEMORY;
        }
    }
    return MDP_ERROR_NONE;
}  // end MdpSession::Open()

void MdpSession::Close(bool hardShutdown)
{
    if (IsServer())
    {
        CloseServer(hardShutdown);
        if (!IsClient()) return;
    }
    if (IsClient())
    {
        CloseClient();
        return;
    }

    // Purge general (MDP_REPORT) messages from tx_queue
    MdpMessage *next = tx_queue.Head();
    while (next)
    {
        MdpMessage *msg;
        switch (next->type)
        {
            case MDP_REPORT:
                msg = next;
                next = next->Next();
                tx_queue.Remove(msg);
                msg_pool.Put(msg);
                break;

            default:
                 // This should never happen
                if (MDP_DEBUG)
                {
                    printf("mdp: Illegal messages remain in tx_queue?!\n");
                }
                break;
        }
    }
    // Delete any node & rx_object information
    pos_ack_list.Destroy();
    server_list.Destroy();

    // Shutdown any outstanding timers
    if (report_timer.IsActive()) report_timer.Deactivate(node);
    if (tx_timer.IsActive()) tx_timer.Deactivate(node);

    if (IsServer())
    {
        if (grtt_req_timer.IsActive())
        {
            grtt_req_timer.Deactivate(node);
        }
        if (tx_interval_timer.IsActive())
        {
            tx_interval_timer.Deactivate(node);
        }
        if (tx_hold_queue_expiry_timer.IsActive())
        {
            tx_hold_queue_expiry_timer.Deactivate(node);
        }
        if (session_close_timer.IsActive())
        {
            session_close_timer.Deactivate(node);
        }
    }

    msg_pool.Destroy();
}  // end MdpSession::Close();


/*******************************************************************
 * Mdp Server control routines
 */

// Server-specific initialization
MdpError MdpSession::OpenServer(UInt16         segmentSize,
                                unsigned char  numData,
                                unsigned char  numParity,
                                UInt32         bufferSize)
{
    if ((segmentSize < MDP_SEGMENT_SIZE_MIN) ||
        (segmentSize > MDP_SEGMENT_SIZE_MAX))
        return MDP_ERROR_PARAMETER_INVALID;
    segment_size = segmentSize;
    nominal_packet_size = (double)segmentSize + 24;
    int blockSize = numData + numParity;
    if (blockSize > 256) return MDP_ERROR_PARAMETER_INVALID;
    ndata = numData;
    nparity = numParity;

    // Check to see if we need to do a general init first
    if (!IsClient())
    {
        // Since client side hasn't already initialized
        // the session, we need to do it now
        MdpError err = Open();
        if (err != MDP_ERROR_NONE) return err;
    }
    client_stats.Init();
    // Allocate server block buffer memory
    UInt32 bit_mask_len = blockSize/8;
    if (blockSize%8) bit_mask_len += 1;

    Int64 block_p_depth = (Int64)((Int32)bufferSize - (segment_pool_depth * segmentSize)) /
        (sizeof(MdpBlock) + (blockSize *sizeof(char *)) +
         (2 * (Int32)bit_mask_len) + (numParity*segmentSize));

    if (block_p_depth <= 0)
    {
        char errStr[MAX_STRING_LENGTH];

        if (segment_pool_depth > 0)
        {
            sprintf(errStr, "Sender Block pool count comes out "
                           "to be %" TYPES_64BITFMT "d. "
                           "Either increase the TX-BUFFER-SIZE or "
                           "decrease the segment size. "
                           "SEGMENT-POOL-SIZE can also be decremented. Its "
                           "current value is %d\n",
                           block_p_depth, segment_pool_depth);
        }
        else
        {
            sprintf(errStr, "Sender Block pool count comes out "
                           "to be %" TYPES_64BITFMT "d. "
                           "Either increase the TX-BUFFER-SIZE or "
                           "decrease the segment size.\n",
                           block_p_depth);
        }
        ERROR_ReportError(errStr);

        txBufferSize = bufferSize = (UInt32)MDP_DEFAULT_BUFFER_SIZE;
    }

    UInt32 block_pool_depth = (bufferSize - (segment_pool_depth * segmentSize)) /
                    (sizeof(MdpBlock) + (blockSize *sizeof(char *)) +
                     (2 * bit_mask_len) + (numParity*segmentSize));

    if (block_pool_depth == 0)
    {
        CloseServer(true);
        return MDP_ERROR_PARAMETER_INVALID;
    }
    UInt32 vector_pool_depth =
                           segment_pool_depth + block_pool_depth * numParity;
    if (MDP_DEBUG)
    {
        printf("MdpSession::OpenServer(): Allocating %u blocks for server buffering ...\n", block_pool_depth);
    }

    if (block_pool_depth != server_block_pool.Init(block_pool_depth, blockSize))
    {
        CloseServer(true);
        return MDP_ERROR_MEMORY;
    }
    if (vector_pool_depth!= server_vector_pool.Init(vector_pool_depth, segmentSize))
    {
        CloseServer(true);
        return MDP_ERROR_MEMORY;
    }

    // Default tx_pend & rx_hold queue depths
    //pend_size_max = (block_pool_depth * numData * segmentSize);

    if (nparity > 0)
    {
        if (!encoder.Init(nparity, segmentSize))
        {
            CloseServer(true);
            return MDP_ERROR_MEMORY;
        }
    }

    // Server inits
    SetStatusFlag(MDP_SERVER);
    pos_ack_pending = false;

    // Set GRTT request timer to fire right away with minimum subsequent interval
    grtt_response = false;
    grtt_current_peak = 0;
    grtt_decrease_delay_count = 0;
    bottleneck_sequence = 128;
    grtt_req_sequence = 0;
    grtt_req_timer.SetInterval(0.0);
    grtt_req_interval = grtt_req_interval_min;
    grtt_wildcard_period = grtt_req_interval_min * 2.0;

    // Kick start probing on startup
    if (grtt_req_probing)
    {
        OnGrttReqTimeout();
        //ActivateTimer(grtt_req_timer, GRTT_REQ_TIMEOUT, this);
    }

    if (congestion_control)
    {
        goal_tx_rate = tx_rate = segmentSize;
        if (tx_rate_min || tx_rate_max)
            goal_tx_rate = tx_rate = MAX(tx_rate_min, 1);
    }
    else
    {
        goal_tx_rate = tx_rate;
    }

    double pktInterval = (double)segment_size / (double)tx_rate;
    // min grtt should be 2*pktInterval
    pktInterval *= 2.0;
    grtt_advertise = MAX(grtt_measured, pktInterval);
    grtt_quantized = QuantizeRtt(grtt_advertise);
    grtt_advertise = UnquantizeRtt(grtt_quantized);

    if (!report_timer.IsActive(node->getNodeTime())
//#ifndef PROTO_DEBUG
        && status_reporting  // always start timer for DEBUG
//#endif // !PROTO_DEBUG
       )
    {
        ActivateTimer(report_timer, REPORT_TIMEOUT, this);
        // (TBD) send initial report immediately ?!
    }

    ActivateTimer(tx_hold_queue_expiry_timer,
                  TX_HOLD_QUEUE_EXPIRY_TIMEOUT,
                  this);

    isServerOpen = TRUE;
    flush_count = robust_factor;
    return MDP_ERROR_NONE;
}  // end MdpSession::OpenServer()


void MdpSession::CloseServer(bool hardShutdown)
{
    isServerOpen = FALSE;
    // Stop probing
    if (grtt_req_timer.IsActive()) grtt_req_timer.Deactivate(node);
    // Dequeue all pending & held objects
    tx_pend_queue.Destroy();
    tx_hold_queue.Destroy();
    tx_repair_queue.Destroy();

    encoder.Destroy();

    // Remove server-specific messages from tx_queue
    PurgeServerMessages();

    representative_list.Destroy();
    representative_count = 0;

    // Free memory allocated for server buffering
    server_block_pool.Destroy();
    server_vector_pool.Destroy();
    if (IsClient())
    {
        if (report_timer.IsActive())
            report_timer.Deactivate(node);
    }

    if (IsServer())
    {
        if (tx_interval_timer.IsActive())
        {
            tx_interval_timer.Deactivate(node);
        }
        if (tx_timer.IsActive())
        {
            tx_timer.Deactivate(node);
        }
        if (report_timer.IsActive())
        {
            report_timer.Deactivate(node);
        }
        if (tx_hold_queue_expiry_timer.IsActive())
        {
            tx_hold_queue_expiry_timer.Deactivate(node);
        }
        if (session_close_timer.IsActive())
        {
            session_close_timer.Deactivate(node);
        }
    }

    if (hardShutdown)
    {
        UnsetStatusFlag(MDP_SERVER);
        // If we were server-only, do a complete session close
        if (!IsClient()) Close(true);
    }
    else
    {
        // Start graceful end-of-transmission flushing
        SetServerFlag(MDP_SERVER_CLOSING);
        Serve();
    }
}  // end MdpSession::CloseServer()


MdpError MdpSession::OpenClient(UInt32 bufferSize)
{
    // Check to see if we need to do a general init first
    if (!IsServer())
    {
        // Since client side hasn't already initialized
        // the session, we need to do it now
        MdpError err = Open();
        if (err != MDP_ERROR_NONE) return err;
    }
    client_window_size = bufferSize;
    if (grtt_req_timer.IsActive(node->getNodeTime()))
    {
        grtt_req_timer.Deactivate(node);
    }
    SetStatusFlag(MDP_CLIENT);
    // Client inits
    ProtoSystemTime(last_report_time, node->getNodeTime());
    client_stats.Init();
    if (!report_timer.IsActive(node->getNodeTime())
//#ifndef PROTO_DEBUG
        && status_reporting
//#endif // !PROTO_DEBUG
       )
    {
        ActivateTimer(report_timer, REPORT_TIMEOUT, this);
        // (TBD) send initial report immediately ?!
    }
    return MDP_ERROR_NONE;
}  // end MdpSession::OpenClient()


void MdpSession::CloseClient()
{
    UnsetStatusFlag(MDP_CLIENT);

    // Remove client-specific messages from tx_queue
    MdpMessage *next = tx_queue.Head();
    while (next)
    {
        MdpMessage *msg = next;
        next = next->Next();
        switch (msg->type)
        {
            case MDP_NACK:
                msg->nack.server->VectorReturnToPool(msg->nack.data);
                tx_queue.Remove(msg);
                msg->nack.server->MessageReturnToPool(msg);
                break;

            case MDP_ACK:
                tx_queue.Remove(msg);
                msg->ack.server->MessageReturnToPool(msg);
                break;

            default:
                break;
        }
    }
    // If we were client-only, do a complete session close
    if (!IsServer()) Close(true);
}  // end MdpSession::CloseClient()


UInt32 MdpSession::ClientBufferPeakValue()
{
    UInt32 usage = 0;
    MdpServerNode *next_server = (MdpServerNode*) server_list.Head();
    while (next_server)
    {
        usage += next_server->PeakValue();
        next_server = (MdpServerNode*) next_server->NextInTree();
    }
    return usage;
}  // end MdpSession::ClientBufferPeakValue()

UInt32 MdpSession::ClientBufferPeakUsage()
{
    UInt32 usage = 0;
    MdpServerNode *next_server = (MdpServerNode*) server_list.Head();
    while (next_server)
    {
        usage += next_server->PeakUsage();
        next_server = (MdpServerNode*) next_server->NextInTree();
    }
    return usage;
}  // end MdpSession::ClientPeakBufferUsage()

UInt32 MdpSession::ClientBufferOverruns()
{
    UInt32 overruns = 0;
    MdpServerNode *next_server = (MdpServerNode*) server_list.Head();
    while (next_server)
    {
        overruns += next_server->Overruns();
        next_server = (MdpServerNode*) next_server->NextInTree();
    }
    return overruns;
}  // end MdpSession::ClientBufferOverruns()


MdpError MdpSession::SetArchiveDirectory(const char *path)
{
    BOOL useCurrentDir = FALSE;
    int pathLen = 0;
    int archivePathLen = 0;
    const int maxPathLenvalue = MDP_PATH_MAX;
    char* tempArchivePath = NULL;   //used to save extra memory allocation

    // getting node name info
    int nodeNameLen = strlen(node->hostname);
    std::string nodeName = node->hostname;

    // first calculate the length
    if (path)
    {
        pathLen = strlen(path);
    }
    else
    {
        useCurrentDir = TRUE;
    }

    if ((pathLen + nodeNameLen + 2) > maxPathLenvalue)
    {
        // Here 2 is added above for delimiter and null char
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"Invalid value %s for "
                       "ARCHIVE-PATH. Path length is more than "
                       "the allowed length %d. "
                       "Continue with the default location: "
                       "Current Dir.\n",
                       path, maxPathLenvalue - nodeNameLen);
        ERROR_ReportWarning(errStr);

        useCurrentDir = TRUE;
    }

    // Save current directory if required
    char dirBuf[maxPathLenvalue];

    if (useCurrentDir)
    {
#ifdef MDP_FOR_WINDOWS
        char* cwd = _getcwd(dirBuf, maxPathLenvalue - nodeNameLen - 2);
#else
        char* cwd = getcwd(dirBuf, maxPathLenvalue - nodeNameLen - 2);
#endif

        if (cwd == NULL)
        {
            char errStr[MAX_STRING_LENGTH];
            switch (errno)
            {
                case EACCES:
                {
                    sprintf(errStr,"Permission to access the current "
                                   "working directory for archive "
                                   "is denied.\n");
                    break;
                }
                case ENOENT:
                {
                    sprintf(errStr,"The current working directory "
                                   "for archive has been unlinked. \n");
                    break;
                }
                case ERANGE:
                {
                    sprintf(errStr,"The current working directory path name "
                                   "for archive is too long too handle. \n");
                    break;
                }
                default:
                {
                    sprintf(errStr,"Error in accessing the current working "
                                   "directory for archive.\n");
                }
                ERROR_ReportError(errStr);
            }
        }
    }// if (useCurrentDir)

    // now first allocate memory for temp archive_path variable
    tempArchivePath = (char*)malloc (maxPathLenvalue);
    memset(tempArchivePath, 0, maxPathLenvalue);

    // now proceed further
    if (!useCurrentDir)
    {
        strncpy(tempArchivePath, path, pathLen);
    }
    else
    {
        strncpy(tempArchivePath, dirBuf, strlen(dirBuf));
    }

    // make complete archive path using node name
    sprintf(tempArchivePath, "%s%c", tempArchivePath, MDP_PROTO_PATH_DELIMITER);
    strncat(tempArchivePath, nodeName.c_str(), nodeName.size());
    archivePathLen = strlen(tempArchivePath);

    // now allocate memory for actual archive_path
    archive_path = (char*)malloc (archivePathLen+2);
    memset(archive_path, 0, archivePathLen+2);
    memcpy(archive_path, tempArchivePath, archivePathLen);

    free(tempArchivePath);

    // delaying archive directory creation till
    // we receive FILE Object message or we have not to
    // deal with current directory
//#ifdef MDP_FOR_WINDOWS
//    // making node name directory
//    if (_mkdir(archive_path))
//    {
//        char errStr[MAX_STRING_LENGTH];
//        sprintf(errStr,"Failed to create archive directory \"%s\": %s\n",
//                       archive_path, strerror(errno));
//        //ERROR_ReportWarning(errStr);
//     }
//#else
//    if (mkdir(archive_path, 0777))
//    {
//        char errStr[MAX_STRING_LENGTH];
//        sprintf(errStr,"Error opening file \"%s\": %s\n",
//                       archive_path, strerror(errno));
//        //ERROR_ReportWarning(errStr);
//    }
//#endif

    int len = MIN(maxPathLenvalue, archivePathLen);

    if (archive_path[len-1] != MDP_PROTO_PATH_DELIMITER)
    {
        if (len < maxPathLenvalue)
        {
            archive_path[len++] = MDP_PROTO_PATH_DELIMITER;
            if (len < maxPathLenvalue) archive_path[len] = '\0';
        }
        else
        {
            archive_path[len-1] = MDP_PROTO_PATH_DELIMITER;
        }
    }

    if (useCurrentDir)
    {
        return MDP_ERROR_NONE;
    }
    else
    {
        // here archive path found and it is not current dir
        // so create the required node dir
#ifdef MDP_FOR_WINDOWS
        // making node name directory
        if (_mkdir(archive_path))
        {
            if (MDP_DEBUG)
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr,"Failed to create archive "
                           "directory \"%s\": %s\n",
                           archive_path, strerror(errno));
                //ERROR_ReportWarning(errStr);
            }
         }
#else
        if (mkdir(archive_path, 0777))
        {
            if (MDP_DEBUG)
            {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr,"Failed to create dir \"%s\": %s\n",
                           archive_path, strerror(errno));
                //ERROR_ReportWarning(errStr);
            }
        }
#endif

        // avoiding this check for normal cases
        // to overcome this, this check is again
        // done while receiving the FileObject message
        if (MdpFileIsWritable(archive_path))
        {
            return MDP_ERROR_NONE;
        }
        else
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr,"Error in accessing the archive path %s "
                   "for writable state. \n", archive_path);
            ERROR_ReportError(errStr);

            return MDP_ERROR_FILE_OPEN;
        }
    }
}  // end MdpSession::SetArchive()
