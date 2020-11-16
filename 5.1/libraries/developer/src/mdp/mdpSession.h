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

#ifndef _MDP_SESSION
#define _MDP_SESSION


#include "mdpNode.h"


/********************************************************************
 * The MdpSession class maintains the primary state for a single instance
 * of the MDPv2 Protocol for a particular destination address/port
 */

// Some session constants (TBD) Move to appropriate places
const int SERVER_PACK_REQ_REPEAT = 20;
const unsigned int MDP_RECV_START_THRESHOLD = 2;


class MdpNotifier
{
    public:
        virtual bool Notify(enum MdpNotifyCode   notifyCode,
                            class MdpSessionMgr* sessionMgr,
                            class MdpSession*    session,
                            MdpNode*             node,
                            MdpObject*           object,
                            MdpError             errorCode) = 0;

        virtual ~MdpNotifier(){};

};  // end class MdpNotifier



class MdpSessionMgr
{
    friend class MdpSession;

    // Methods
    public:
        MdpSessionMgr(MdpProtoTimerMgr& timerMgr, UInt32 nodeId);
        ~MdpSessionMgr();
        UInt32 LocalNodeId() {return node_id;}
        void SetLocalNodeId(UInt32 theId) {node_id = theId;}
        //void SetNodeName(const char *theName)
        //    {strncpy(node_name, theName, MDP_NODE_NAME_MAX);}
        void Close();  // shutdown all sessions
        MdpSession* FindSessionByAddress(const MdpProtoAddress *theAddr);
        MdpSession* FindSession(const MdpSession *theSession);
        //MdpSession* FindSessionByName(char *theName);
        MdpSession* FindSessionByUniqueId(Int32 uniqueId);
        MdpSession* NewSession(Node* node);
        void Add(class MdpSession* theSession);
        void Remove(class MdpSession* theSession);

        void DeleteSession(MdpSession *theSession);

        void SetNotifier(MdpNotifier* mdpNotifier)
            {mdp_notifier = mdpNotifier;}
        void SetListHead(MdpSession* head){list_head = head;}
        void SetListTail(MdpSession* tail){list_tail = tail;}
        void SetUserData(const void* userData)
            {user_data = userData;}
        const void* GetUserData()
            {return user_data;}

        MdpSession* GetSessionListHead()
        {
            return list_head;
        }

    private:
        // Call the installed application notifier if there is one
        void NotifyApplication(enum MdpNotifyCode notifyCode,
                               MdpSession*   theSession,
                               MdpNode*      theNode,
                               MdpObject*    theObject,
                               MdpError      errorCode);
        //char                  node_name[MDP_NODE_NAME_MAX];
        UInt32                  node_id;
        class MdpSession*       list_head;
        class MdpSession*       list_tail;

        MdpProtoTimerMgr&       timer_mgr;
        MdpNotifier*            mdp_notifier;
        const void*             user_data;
};  // end class MdpSessionMgr


// Session status flags (low session status byte has MdpReport'ing status flags)
enum MdpServerFlag
{
    MDP_SERVER_EMCON    = 0x01,
    MDP_SERVER_CLOSING  = 0x02
};

enum MdpClientFlag
{
    MDP_CLIENT_UNICAST_NACKS    = 0x01,
    MDP_CLIENT_EMCON            = 0x02,
    MDP_CLIENT_ACKING           = 0x04,
    MDP_CLIENT_MULTICAST_ACKS   = 0x08
};



class MdpSession
{
    friend class MdpSessionMgr;
    friend class MdpServerNode;
    friend class MdpObject;

    // Methods
    public:
        MdpSession(MdpSessionMgr* theMgr, Node* node);
        ~MdpSession();
       // Inits session as a server
        MdpError OpenServer(UInt16          segmentSize,
                            unsigned char   numData,
                            unsigned char   numParity,
                            UInt32          bufferSize);
        void CloseServer(bool hardShutdown);
        unsigned short SegmentSize() {return (unsigned short)segment_size;}
        MdpError OpenClient(UInt32 bufferSize);
        void CloseClient();
        void Close(bool hardShutdown);  // shutdown session

        void SetUserData(const void* userData)
            {user_data = userData;}
        const void* GetUserData()
            {return user_data;}

        BOOL IsServer() {return (0 != (status & MDP_SERVER));}
        BOOL IsClient() {return (0 != (status & MDP_CLIENT));}
        BOOL IsOpen() {return (status != 0);}
        // Set/get session parameters
        //void SetName(const char* theName) {strncpy(name, theName, MDP_SESSION_NAME_MAX);}
        void SetNode(Node* theNode){node = theNode;}
        Node* GetNode(){return node;}
        void SetUniqueId(Int32 uniqueId){mdpUniqueId = uniqueId;}
        Int32 GetUniqueId(){return mdpUniqueId;}
        const MdpProtoAddress* Address() {return &addr;}
        bool SetAddress(MdpProtoAddress theAddress, unsigned short rxPort,
                        unsigned short txPort = 0);
        void SetSessionTxBufferSize(UInt32 theSize)
        {
            txBufferSize = theSize;
        }
        UInt32 GetSessionTxBufferSize()
        {
            return txBufferSize;
        }
        void SetSessionRxBufferSize(UInt32 theSize)
        {
            rxBufferSize = theSize;
        }
        UInt32 GetSessionRxBufferSize()
        {
            return rxBufferSize;
        }
        void SetSegmentPoolDepth(Int32 theSize)
        {
            segment_pool_depth = theSize;
        }
        Int32 GetSegmentPoolDepth()
        {
            return segment_pool_depth;
        }
        void SetSegmentSize(Int32 segmentSize)
        {
            segment_size = segmentSize;
        }
        Int32 GetSegmentSize()
        {
            return segment_size;
        }
        void SetBlockSize(UInt32 blockSize)
        {
            ndata = blockSize;
        }
        UInt32 GetBlockSize()
        {
            return ndata;
        }
        void SetNumParity(UInt32 numParity)
        {
            nparity = numParity;
        }
        UInt32 GetNumParity()
        {
            return nparity;
        }
        void SetNumAutoParity(UInt32 numAutoParity)
        {
            auto_parity = numAutoParity;
        }
        UInt32 GetNumAutoParity()
        {
            return auto_parity;
        }
        BOOL IsServerOpen() { return isServerOpen;}
        BOOL IsUnicast() {return (!addr.IsMulticast());}
        bool SetGrttProbeInterval(double intervalMin, double intervalMax);
        void SetGrttProbing(BOOL state);
        void SetTTL(unsigned char theTTL);
        bool SetTOS(unsigned char theTOS);
        bool SetMulticastInterface(const char* interfaceName)
        {
            // (TBD) allow this to be dynamically changed?
            strncpy(interface_name, interfaceName, 16);
            interface_name[15] = '\0';
            return true;
        }
        void SetMulticastLoopback(BOOL state);
        void SetPortReuse(bool state);
        UInt32 TxRate() {return (tx_rate << 3);}
        void SetTxRate(UInt32 value);
        void SetTxRateBounds(UInt32 min, UInt32 max);
        double GrttEstimate() {return grtt_advertise;}
        void SetGrttEstimate(double value)
        {
            value = value > (double)MDP_GRTT_MIN ? value : (double)MDP_GRTT_MIN;
            value = value < grtt_max ? value : grtt_max;
            grtt_measured = value;
            double pktInterval = (double)segment_size/ (double)tx_rate;
            value = MAX(pktInterval, value);
            grtt_quantized = QuantizeRtt(value);
            grtt_advertise = UnquantizeRtt(grtt_quantized);
        }
        double GrttMax() {return grtt_max;}
        void SetGrttMax(double value)
        {
            value = value < 120.0 ? value : 120.0;
            grtt_max = value > 1.0 ? value : 1.0;
            grtt_measured = grtt_max < grtt_measured ? grtt_max : grtt_measured;
            double pktInterval = (double)segment_size/ (double)tx_rate;
            grtt_advertise = MAX(pktInterval, grtt_measured);
            grtt_quantized = QuantizeRtt(grtt_advertise);
            grtt_advertise = UnquantizeRtt(grtt_quantized);
        }
        BOOL GetCongestionControlState()
            {return congestion_control;}
        void SetCongestionControl(BOOL state)
            {congestion_control = state;}
        void SetFastStart(bool state)
            {fast_start = state;}
        void SetTxCacheDepth(UInt32 minCount, UInt32 maxCount, UInt32 maxSize)
        {
            // Trust no one
            pend_count_min = hold_count_min = MIN(minCount, maxCount);
            pend_count_max = hold_count_max = MAX(minCount, maxCount);
            pend_size_max  = hold_size_max  = maxSize;
        }
        MdpError SetArchiveDirectory(const char *thePath);
        const char *ArchivePath() {return archive_path;}
        void SetArchiveMode(BOOL value) {archive_mode = value;}
        BOOL ArchiveMode() {return archive_mode;}
        void SetAutoParity(unsigned char value) {auto_parity = value;}
        unsigned char AutoParity() {return (unsigned char)auto_parity;}
        void SetUnicastNacks(BOOL state)
        {
            state ? SetClientFlag(MDP_CLIENT_UNICAST_NACKS) :
                    UnsetClientFlag(MDP_CLIENT_UNICAST_NACKS);
        }
        BOOL UnicastNacks() {return (client_status & MDP_CLIENT_UNICAST_NACKS);}
        void SetMulticastAcks(BOOL state)
        {
            state ? SetClientFlag(MDP_CLIENT_MULTICAST_ACKS) :
                    UnsetClientFlag(MDP_CLIENT_MULTICAST_ACKS);
        }
        void SetAddr(MdpProtoAddress addr)
        {
            this->addr = addr;
        }
        MdpProtoAddress GetAddr()
        {
            return this->addr;
        }
        void SetLocalAddr(MdpProtoAddress addr)
        {
            localAddress = addr;
        }
        MdpProtoAddress GetLocalAddr()
        {
            return localAddress;
        }
        void SetAppType(AppType theAppType)
        {
            appType = theAppType;
        }
        AppType GetAppType()
        {
            return appType;
        }
        bool MulticastAcks()
            {return (0 != (client_status & MDP_CLIENT_MULTICAST_ACKS));}
        void SetEmconClient(BOOL state)
        {
            // (TBD) Update existing recv obj nacking_mode on EMCON change
            if (state)
            {
                SetClientFlag(MDP_CLIENT_EMCON);
                status_reporting = FALSE;
            }
            else
            {
                UnsetClientFlag(MDP_CLIENT_EMCON);
            }
        }
        void SetNackRequired(BOOL state)
        {
            nackRequired = state;
        }
        BOOL GetNackRequired()
        {
            return nackRequired;
        }
        void SetReceiverAppExistStatus(BOOL state)
        {
            isReceiverAppExist = state;
        }
        BOOL GetReceiverAppExistStatus()
        {
            return isReceiverAppExist;
        }
        unsigned int RobustFactor() {return robust_factor;}
        void SetRobustFactor(unsigned int theValue)
            {robust_factor = theValue;}
        BOOL StreamIntegrity() {return stream_integrity;}
        void SetStreamIntegrity(BOOL state)
            {stream_integrity = state;}
        MdpNackingMode DefaultNackingMode() {return default_nacking_mode;}
        void SetDefaultNackingMode(MdpNackingMode theMode)
            {default_nacking_mode = theMode;}
        BOOL EmconClient()
            {return (0 != (client_status & MDP_CLIENT_EMCON));}
        void SetEmconServer(BOOL state)
        {
            state ? SetServerFlag(MDP_SERVER_EMCON) :
                    UnsetServerFlag(MDP_SERVER_EMCON);
        }
        BOOL EmconServer() {return (0 != (server_status & MDP_SERVER_EMCON));}
        BOOL ServerIsClosing()
        {
            return (0 != (server_status & MDP_SERVER_CLOSING));
        }

        void SetStatusReporting(BOOL state);
        void SetClientAcking(BOOL state)
        {
            state ? SetStatusFlag(MDP_ACKING) :
                    UnsetStatusFlag(MDP_ACKING);
        }
        BOOL ClientAcking() {return (0 != (status & MDP_ACKING));}

        void Notify(enum MdpNotifyCode   notifyCode,
                    MdpNode*        theNode,
                    MdpObject*      theObject,
                    MdpError        errorCode)
        {
            notify_pending++;
            mgr->NotifyApplication(notifyCode, this, theNode, theObject, errorCode);
            notify_pending--;
        }
        BOOL NotifyPending() {return (0 != notify_pending);}
        void SetNotifyAbort() {notify_abort = true;}

        MdpClientStats & GetMdpClientStats()
        {
            return client_stats;
        }
        MdpCommonStats & GetMdpCommonStats()
        {
            return commonStats;
        }
        MdpSession* GetNextPointer()
        {
            return next;
        }

        MdpNode* FindServerById(UInt32 nodeId)
        {
            return server_list.FindNodeById(nodeId);
        }
        void DeleteRemoteServer(MdpServerNode* theServer);

        // Public server routines
        MdpDataObject* NewTxDataObject(const char*      infoPtr,
                                       UInt16           infoSize,
                                       char*            dataPtr,
                                       UInt32           dataSize,
                                       MdpError*        error,
                                       char *           theMsg = NULL,
                                       Int32            virtualSize = 0);


        MdpFileObject* NewTxFileObject(const char*      path,
                                       const char*      name,
                                       MdpError*        error,
                                       char *           theMsg = NULL);
        MdpError QueueTxObject(MdpObject* theObject);
        MdpObject* FindTxObject(MdpObject* theObject);
        MdpObject* FindTxObjectById(UInt32 theId);
        MdpError RemoveTxObject(MdpObject* theObject);
        void SetBaseObjectTransportId(UInt32 baseId)
            {next_transport_id = baseId;}

        // Protocol state information
        UInt32 PendingRecvObjectCount();
        UInt32 ClientBufferPeakValue();
        UInt32 ClientBufferPeakUsage();
        UInt32 ClientBufferOverruns();

        // Congestion control
        double CalculateGoalRate(double l, double tRTT, double t0);

        void IncrementResyncs() {client_stats.resync++;}
        void IncrementFailures() {client_stats.fail++;}

        bool HandleRecvPacket(char *buffer,
                              UInt32 len,
                              MdpProtoAddress *src,
                              BOOL unicast,
                              char* info,
                              Message* theMsgPtr = NULL,
                              Int32 virtualSize = 0);
        void SetEcnEnable(BOOL state) {ecn_enable = state;}
        void SetEcnStatus(BOOL state) {ecn_status = state;}

        bool OnReportTimeout();
        bool OnTxTimeout();
        bool OnTxIntervalTimeout();
        bool OnGrttReqTimeout();

        bool OnTxHoldQueueExpiryTimeout();
        bool OnSessionCloseTimeout();

        bool GetLastDataObjectStatus(){return isLastDataObjectReceived;}
        void SetLastDataObjectStatus(BOOL status)
        {
            isLastDataObjectReceived = !!status;
        }

        MdpProtoTimer getGrttReqTimer(){return grtt_req_timer;}
        MdpProtoTimer getTxIntervalTimer(){return tx_interval_timer;}
        MdpProtoTimer getTxTimer(){return tx_timer;}
        MdpProtoTimer getReportTimer(){return report_timer;}

        //changing from private to public
        bool AddAckingNode(UInt32 nodeId);
        void RemoveAckingNode(UInt32 nodeId);
    private:
    // Members
        //char             name[MDP_SESSION_NAME_MAX];
        MdpProtoAddress  addr;
        MdpProtoAddress  localAddress;
        unsigned short   tx_port;
        unsigned char    ttl;
        char             interface_name[16];
        BOOL             loopback;
        BOOL             isServerOpen;
        bool             port_reuse;
        unsigned char    tos;

        int              status;      // Node reporting status
        int              server_status;
        int              client_status;

        MdpSessionMgr    *mgr;
        Node             *node;
        Int32            mdpUniqueId;
        bool             single_socket; // if tx & rx port are the same
        BOOL             ecn_enable;    // ECN hack for simulations only
        BOOL             ecn_status;    // ECN hack for simulations only
        UInt32           tx_rate;    // max bytes per second (UDP payload)
        UInt32           tx_rate_min;  // lower bound on congestion control rate
        UInt32           tx_rate_max;  // upper bound on congestion control rate
        MdpMessageQueue  tx_queue;
        MdpProtoTimer    tx_timer;

        MdpProtoTimer    report_timer;

        MdpNodeTree      server_list; // Note: Servers may also be clients
                                      // but will appear only in server_list

        const void*      user_data;
        UInt32           txBufferSize;
        UInt32           rxBufferSize;
        AppType          appType;
        Int32            segment_pool_depth;

        // additional custom parameter used to discard the packets
        // if receiver application on MDP exata port does not found
        BOOL             isReceiverAppExist;

        // Server-specific state
        // Blocking parameters for file transmissions
        unsigned int    ndata, nparity;
        Int32           segment_size;
        unsigned int    auto_parity;
        unsigned short  server_sequence;
        UInt32          next_transport_id;

        BOOL            status_reporting;
        BOOL            congestion_control;  // on or off
        bool            fast_start;
        double          rate_increase_factor;
        double          rate_decrease_factor;
        MdpNodeTree     representative_list;
        unsigned int    representative_count;
        UInt32          goal_tx_rate;
        double          fictional_rate;  // (TBD) lose this
        double          nominal_packet_size;
        MdpNodeTree     pos_ack_list;  // list of positive acking clients
        MdpMessagePool  msg_pool;
        MdpVectorPool   server_vector_pool;
        MdpBlockPool    server_block_pool;

        MdpProtoTimer   grtt_req_timer;

        double           grtt_req_interval;
        double           grtt_req_interval_min;
        double           grtt_req_interval_max;
        BOOL             grtt_req_probing;
        double           grtt_wildcard_period;
        unsigned char    grtt_req_sequence;
        double           grtt_max;
        MdpNodeId        bottleneck_id;
        unsigned char    bottleneck_sequence;
        double           bottleneck_rtt;
        double           bottleneck_loss;
        unsigned char    grtt_quantized;
        double           grtt_advertise;
        double           grtt_measured;
        // State for collecting grtt estimates (TBD - make a GrttFilter class???)
        bool             grtt_response;
        double           grtt_current_peak;
        int              grtt_decrease_delay_count;

        bool            tx_pend_queue_active;
        UInt32          current_tx_object_id;
        MdpProtoTimer   tx_interval_timer;
        unsigned int    flush_count;
        bool            pos_ack_pending;

        MdpObjectList   tx_pend_queue;      // Tx objects pending transmission
        UInt32          pend_count_min;
        UInt32          pend_count_max;
        UInt32          pend_size_max;
        MdpObjectList   tx_repair_queue;    // Active tx objects
        MdpObjectList   tx_hold_queue;      // Tx objects held for potential repair
        UInt32          hold_count_min;
        UInt32          hold_count_max;
        UInt32          hold_size_max;

        MdpProtoTimer   tx_hold_queue_expiry_timer;
        bool            isLastDataObjectReceived;
        MdpProtoTimer   session_close_timer;

        MdpEncoder      encoder;

        // Client state
        // (TBD) Move file-specific stuff out of MDP protocol core
        char            *archive_path;
        BOOL            archive_mode;
        UInt32          client_window_size; // per server buffering (in bytes)
        BOOL            stream_integrity;
        BOOL            nackRequired;
        MdpNackingMode  default_nacking_mode;

        // For client statistics reporting
        MdpClientStats  client_stats;
        struct timevalue  last_report_time;
        //For other common stats
        MdpCommonStats  commonStats;

        int             notify_pending;
        bool            notify_abort;   // true when session is deleted
                                        // during notify callback
        unsigned int    robust_factor;  // flush repeats, ack attempts, etc

        MdpSession      *prev, *next;

   // Methods
        MdpError Open();  // Generic initialization called by OpenServer() or OpenClient();
        void SetStatusFlag(MdpStatusFlag flag) {status |= (int) flag;}
        void UnsetStatusFlag(MdpStatusFlag flag) {status &= ~((int) flag);}
        void SetServerFlag(MdpServerFlag flag) {server_status |= (int) flag;}
        void UnsetServerFlag(MdpServerFlag flag) {server_status &= ~((int) flag);}
        void SetClientFlag(MdpClientFlag flag) {client_status |= (int) flag;}
        void UnsetClientFlag(MdpClientFlag flag) {client_status &= ~((int) flag);}
        void ActivateTimer(MdpProtoTimer& theTimer, timeoutEventType eventType, void* classPtr)
            {mgr->timer_mgr.ActivateTimer(theTimer, eventType, node, classPtr);}

        void DeactivateTimer(MdpProtoTimer& theTimer)
            {mgr->timer_mgr.DeactivateTimer(theTimer, node);}


        bool TxQueueIsEmpty() {return (tx_queue.IsEmpty());}

        bool IsActiveServing() {return (!(tx_pend_queue.IsEmpty() &&
                                          tx_repair_queue.IsEmpty()));}

        UInt32 LocalNodeId() {return mgr->LocalNodeId();}
        const char *LocalNodeName() {return node->hostname;}

        void PurgeClientMessages(MdpServerNode* theServer);
        void PurgeServerMessages();

        bool Serve();
        void QueueMessage(MdpMessage *theMsg);
        void DeactivateTxObject(MdpObject* theObject);
        void ReactivateTxObject(MdpObject* theObject);
        void TransmitObjectInfo(MdpObject* theObject);
        void TransmitFlushCmd(UInt32 objectId);
        bool TransmitObjectAckRequest(UInt32 objectId);
        bool ServerReclaimResources(MdpObject* theObject, UInt32 blockId);

        MdpServerNode* NewRemoteServer(UInt32 nodeId);

        // MdpSession message handlers
        void HandleMdpReport(MdpMessage *theMsg, MdpProtoAddress *src);

        void HandleObjectMessage(MdpMessage* theMsg,
                                 MdpProtoAddress* src,
                                 char* info,
                                 Message* theMsgPtr = NULL,
                                 Int32 virtualSize = 0);

        void HandleMdpServerCmd(MdpMessage *theMsg,
                                MdpProtoAddress *src);

        void ClientHandleMdpNack(MdpMessage *theMsg);
        void ServerHandleMdpNack(MdpMessage *theMsg, BOOL unicast);
        void ServerHandleMdpAck(MdpMessage *theMsg);
        void ServerProcessClientResponse(UInt32   clientId,
                                         struct timevalue* grttTimestamp,
                                         UInt16          lossQuantized,
                                         unsigned char   clientSequence);
        void AdjustRate(bool activeResponse);
};  // end class MdpSession

#endif // _MDP_SESSION
