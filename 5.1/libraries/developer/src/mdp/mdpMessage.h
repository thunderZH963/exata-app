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

#ifndef _MDP_MESSAGE
#define _MDP_MESSAGE

#include<math.h>
#include<string.h>
#include "mdpProtoDefs.h"
#include "mdpError.h"
#include "mdpProtoAddress.h"

const double MDP_BACKOFF_WINDOW = 2; // Number of GRTT periods for NACK backoff
const unsigned int MDP_GROUP_SIZE = 1000; // Group size estimate (TBD - automate this)

const unsigned char MDP_PROTOCOL_VERSION    = 9;
const unsigned int  MSG_SIZE_MAX            = 8192;
const unsigned int  MDP_SESSION_NAME_MAX    = 64;
const unsigned int  MDP_NODE_NAME_MAX       = 64;

const int MDP_SEGMENT_SIZE_MIN = 64;
const int MDP_SEGMENT_SIZE_MAX = 8128;

// "timeoutEventType" shifted from mdpApi.h
enum timeoutEventType
{
    GRTT_REQ_TIMEOUT,
    ACK_TIMEOUT,
    TX_INTERVAL_TIMEOUT,
    TX_TIMEOUT,
    REPORT_TIMEOUT,
    ACTIVITY_TIMEOUT,
    REPAIR_TIMEOUT,
    OBJECT_REPAIR_TIMEOUT,
    TX_HOLD_QUEUE_EXPIRY_TIMEOUT,
    SESSION_CLOSE_TIMEOUT
};


enum MdpMessageType
{
    MDP_MSG_INVALID,
    MDP_REPORT,
    MDP_INFO,
    MDP_DATA,
    MDP_PARITY,     // MDP_PARITY could be made a type of MDP_DATA
    MDP_CMD,
    MDP_NACK,
    MDP_ACK
};

// MDP Node report "status" flags
enum MdpStatusFlag
{
    MDP_CLIENT =    0x01,
    MDP_SERVER =    0x02,
    MDP_ACKING =    0x04    // Client will provide positive ack of receipt
};

// MdpReport types
enum MdpReportType
{
    MDP_REPORT_INVALID,
    MDP_REPORT_HELLO
};

// MDP default info field for various timer events
struct struct_mdpTimerInfo
{
    timeoutEventType mdpEventType;
    void*            mdpclassPtr;
};

/*********************************************************************
 * These "Stats" classes are used for clients reporting statistics of protocol
 * performance via MDP_REPORT messages
 ********************************************************************/

class MdpBlockStats
{
    public:
        UInt32   count;    // total number of blocks received
        UInt32   lost_00;  // blocks recv'd error free first pass
        UInt32   lost_05;  // 0-5% loss first pass
        UInt32   lost_10;  // 5-10% loss first pass
        UInt32   lost_20;  // 10-20% loss first pass
        UInt32   lost_40;  // 20-40% loss first pass
        UInt32   lost_50;  // more than 40% loss first pass

    public:
        int Pack(char *buffer);
        int Unpack(char *buffer);
};

class MdpBufferStats
{
    public:
        UInt32   buf_total;  // buffer memory allocated (bytes)
        UInt32   peak;       // peak buffer usage
        UInt32   overflow;   // buffer overflow count

    public:
        int Pack(char *buffer);
        int Unpack(char *buffer);
};

class MdpCommonStats
{
    public:
        UInt64 numReportMsgSentCount;
        UInt64 numReportMsgRecCount;
        UInt64 numInfoMsgSentCount;
        UInt64 numInfoMsgRecCount;
        UInt64 numDataMsgSentCount;
        UInt64 numDataMsgRecCount;
        UInt64 numParityMsgSentCount;
        UInt64 numParityMsgRecCount;
        UInt64 numCmdMsgSentCount;
        UInt64 numCmdMsgRecCount;
        UInt64 numCmdFlushMsgSentCount;
        UInt64 numCmdFlushMsgRecCount;
        UInt64 numCmdSquelchMsgSentCount;
        UInt64 numCmdSquelchMsgRecCount;
        UInt64 numCmdAckReqMsgSentCount;
        UInt64 numCmdAckReqMsgRecCount;
        UInt64 numCmdGrttReqMsgSentCount;
        UInt64 numCmdGrttReqMsgRecCount;
        UInt64 numCmdNackAdvMsgSentCount;
        UInt64 numCmdNackAdvMsgRecCount;
        UInt64 numNackMsgSentCount;
        UInt64 numNackMsgRecCount;
        UInt64 numGrttAckMsgSentCount;
        UInt64 numGrttAckMsgRecCount;
        UInt64 numPosAckMsgSentCount;
        UInt64 numPosAckMsgRecCount;
        UInt64 numDataObjFailToQueue;
        UInt64 numFileObjFailToQueue;
        UInt64 senderTxRate;
        UInt64 totalBytesSent;
    public:
        void Init()
            {memset(this, 0, sizeof(MdpCommonStats));}
};

class MdpClientStats
{
    public:
        UInt32   duration;   // Period (secs) of client's participation
        UInt32   success;    // No. of successful object transfers
        UInt32   active;     // No. of current pending transfers
        UInt32   fail;       // No. of failed object transfers
        UInt32   resync;     // No. of server re-sync's
        MdpBlockStats   blk_stat;   // Recv block loss statistics
        UInt32   tx_rate;    // Node tx_rate (bytes/sec)
        UInt32   nack_cnt;   // Transmitted NACK count
        UInt32   supp_cnt;   // Suppressed NACK count
        MdpBufferStats  buf_stat;   // Buffer usage stats
        UInt32   goodput;    // ave. recv'd bytes/sec
        UInt32   rx_rate;
        UInt32   bytes_recv; // No of bytes received.
    public:
        int Pack(char *buffer);
        int Unpack(char *buffer);
        void Init()
            {memset(this, 0, sizeof(MdpClientStats));}
};


class MdpReportMsg
{
    // Members
    public:
        unsigned char           status;
        unsigned char           flavor;
        char                    node_name[MDP_NODE_NAME_MAX];
        MdpClientStats          client_stats;
        const MdpProtoAddress*  dest;
};


// MDP Object flags
const int MDP_DATA_FLAG_REPAIR      = 0x01; // Marks packets which are repair transmissions
const int MDP_DATA_FLAG_BLOCK_END   = 0x02; // Marks end of transmission for a block
const int MDP_DATA_FLAG_RUNT        = 0x04; // Marks the last data packet for an object
const int MDP_DATA_FLAG_INFO        = 0x10; // Indicates availability of MDP_INFO
const int MDP_DATA_FLAG_UNRELIABLE  = 0x20;
const int MDP_DATA_FLAG_FILE        = 0x80; // Indicates object data should be stored in a file

class MdpInfoMsg  // (TBD) add other information (MIME-type, etc))
{
    public:
        UInt16          segment_size; // Size (in bytes) of a full data segment
        UInt16          len;
        UInt32          actual_data_len; //used for sim purpose only not
                                         //sending in actual message
        char*           data;
};

class MdpDataMsg
{
    // Members
    public:
        UInt32          offset;    // Offset (in bytes) of attached data
        UInt16          segment_size;  // opt. segment size (only for LAST_FLAG msgs)
        UInt16          len;       // Length of data vector (not a packet field)
        UInt32          actual_data_len; //used for sim purpose only not
                                         //sending in actual message
        char*           data;     // Pointer to data vector
};

class MdpParityMsg
{
    // Members
    public:
        UInt32          offset; // Offset of start of encoding block
        unsigned char   id;     // Parity vector id
        UInt16          len;    // Length of parity vector (not a packet field)
        UInt32          actual_data_len; //used for sim purpose only not
                                         //sending in actual message
        char*           data;   // Points to parity vector
};

class MdpObjectMsg
{
    public:
        UInt16          sequence;
        UInt32          object_id;    // MDP server transfer object identifier
        UInt32          object_size;  // Size (in bytes) of the object
        unsigned char   ndata;        // Data segments per block
        unsigned char   nparity;      // Max parity segments per block
        unsigned char   flags;        // See MDP object flags defined above
        unsigned char   grtt;         // Server's current grtt estimate (quantized)
        union
        {
            MdpInfoMsg      info;
            MdpDataMsg      data;
            MdpParityMsg    parity;
        };
};


// MdpCmdMsg flavors
enum
{
    MDP_CMD_NULL,
    MDP_CMD_FLUSH,      // commands clients to flush pending NACKs for this server
    MDP_CMD_SQUELCH,    // commands clients to quit NACKing a particular object
    MDP_CMD_ACK_REQ,    // requests clients to ACK receipt of a specific object
    MDP_CMD_GRTT_REQ,   // requests clients to include GRTT_ACK in MDP_NACKs
    MDP_CMD_NACK_ADV    // Advertises repair state from unicast NACKs
};

enum
{
    MDP_CMD_FLAG_EOT = 0x01  // end-of-transmission flag
};

class MdpFlushCmd
{
    public:
        char          flags;
        UInt32        object_id; // last object transmitted
};

class MdpSquelchCmd
{
    public:
        UInt32          sync_id;    // "lowest" objectId valid for this server
        UInt16          len;        // len of attached data (not sent)
        char*           data;       // list of objectId's to squelch
};

class MdpAckReqCmd
{
    public:
        UInt32          object_id;      // which object to ack
        UInt16          len;            // len of attached data (not sent)
        char*           data;           // list of nodes needed to ACK

        bool FindAckingNode(UInt32 nodeId);
        bool AppendAckingNode(UInt32 nodeId, UInt16 maxLen);
};


enum
{
    MDP_CMD_GRTT_FLAG_WILDCARD = 0x01   // Wildcard response (everyone)
};

class MdpGrttReqCmd
{
    public:
        char           flags;
        unsigned char  sequence;
        struct timevalue  send_time;    // server request time stamp
        struct timevalue  hold_time;    // client response window (should quantize)
        unsigned short segment_size; // server tx segment_size
        UInt32         rate;         // current server tx_rate (bytes/second)
        unsigned char  rtt;          // quantized current bottleneck rtt estimate
        UInt16         loss;         // current bottleneck loss estimate
        UInt16         len;          // length of data content (not sent)
        char*          data;         // list of representative node id's
                                     // and their rtt's

        bool AppendRepresentative(UInt32 repId, double repRtt,
                                  UInt16 maxLen);
        bool FindRepresentative(UInt32 repId, double* repRtt);

};

class MdpNackAdvCmd
{
    public:
        unsigned short len;
        char*          data;
};

class MdpCmdMsg
{
    public:
        unsigned short  sequence;
        unsigned char   grtt;
        unsigned char   flavor;     // command flavor (see above)
        union
        {
            MdpFlushCmd     flush;
            MdpSquelchCmd   squelch;
            MdpAckReqCmd    ack_req;
            MdpGrttReqCmd   grtt_req;
            MdpNackAdvCmd   nack_adv;
        };
};


// An "MdpNackMsg" contains a concatenation of one or more
// "MdpObjectNacks".  Each "MdpObjectNack" contains a
// concatenation of one or more "MdpRepairNacks" of varying
// types.

class MdpNackMsg
{
    public:
    // Members
        UInt32                  server_id;
        struct timevalue        grtt_response;
        UInt16                  loss_estimate;
        unsigned char           grtt_req_sequence;
        char*                   data;
        UInt16                  nack_len;  // nack_len field _not_ explicitly sent
                                           // receiver derives from packet size
        const MdpProtoAddress*  dest;
        class MdpServerNode*    server;

};

enum MdpRepairType
{
    MDP_REPAIR_INVALID = 0,
    MDP_REPAIR_SEGMENTS,    // (1) Repair needed only for some segments
    MDP_REPAIR_BLOCKS,      // (2) Entire block retransmissions needed
    MDP_REPAIR_INFO,        // (3) Object info needed
    MDP_REPAIR_OBJECT       // (4) Entire object needs retransmitted
};

class MdpRepairNack
{
    public:
    // Members
        MdpRepairType   type;
        unsigned char   nerasure;  // MDP_REPAIR_SEGMENT only
        UInt32          offset;    // MDP_REPAIR_BLOCK, MDP_REPAIR_SEGMENT
        UInt16          mask_len;  // length of attached BLOCK/SEGMENT repair mask
        char*           mask;      // pointer to mask data

        MdpRepairNack()
        {
            // initializing the class variables
            type = MDP_REPAIR_INVALID;
            nerasure = 0;
            offset = 0;
            mask_len = 0;
            mask = NULL;
        }

        int Pack(char* buffer, unsigned int buflen);
        int Unpack(char* buffer);
};

class MdpObjectNack
{
    public:
    // Members
        UInt32          object_id;
        UInt16          nack_len;     // nack_len field _is_ explicitly sent
        UInt16          max_len;
        char*           data;

        MdpObjectNack()
        {
            // initializing the class variables
            object_id = 0;
            nack_len = 0;
            max_len = 0;
            data = NULL;
        }

        bool Init(UInt32 id, char* buffer, UInt32 buflen);
        bool AppendRepairNack(MdpRepairNack* nack);
        int Pack();
        int Unpack(char* buffer);
};


enum MdpAckType
{
    MDP_ACK_INVALID = 0,
    MDP_ACK_OBJECT,
    MDP_ACK_GRTT
};

class MdpAckMsg
{
    // Members
    public:
        UInt32                  server_id;    // ID of server to receive ACK
        struct timevalue        grtt_response;
        UInt16                  loss_estimate;
        unsigned char           grtt_req_sequence;
        MdpAckType              type;
        UInt32                  object_id;    // ID of object we are ACKing

        const MdpProtoAddress*  dest;
        class MdpServerNode*    server;
};

class MdpMessage
{
    friend class MdpMessageQueue;
    friend class MdpMessagePool;

    // Members
    public:
        // (TBD) Compress type/version fields?
        unsigned char       type;    // Type of MDP message
        unsigned char       version; // MDP protocol version number
        UInt32              sender;  // Node id of message source
        union
        {
            MdpReportMsg        report;
            MdpObjectMsg        object;  // includes MDP_INFO, MDP_DATA, & MDP_PARITY
            MdpCmdMsg           cmd;
            MdpNackMsg          nack;
            MdpAckMsg           ack;
        };

    private:
        MdpMessage *prev;
        MdpMessage *next;   // for message queues, pools, etc

    // Methods
    public:
        // Returns length of message packed
        int Pack(char *buffer);
        // Returns FALSE if message is bad
        bool Unpack(char *buffer, int packet_length,
                    int virtual_length, bool* isServerPacket);
        MdpMessage* Next() {return next;}
};

// (TBD) make these static members of the MdpMessage class for name space protection
// Some utility routines
int AppendNackData(char *buffer,
                   unsigned char type,
                   UInt32 id,
                   UInt32 mask_len,
                   unsigned char *mask);

// Returns number of bytes parsed
int ParseNackData(char *buffer,
                  unsigned char *type,
                  UInt32 *id,
                  UInt32 *mask_len,
                  unsigned char **mask);


// These are the GRTT estimation bounds set for the current
// MDPv2 protocol.  (Note that our Grtt quantization routines
// are good for the range of 1.0e-06 <= 1000.0)
#define MDP_GRTT_MIN   0.001  // 1 msec
#define MDP_GRTT_MAX   15.0   // 15 sec

#define RTT_MIN    1.0e-06
#define RTT_MAX    1000.0

inline double UnquantizeRtt(unsigned char rtt_q)
{
    return ((rtt_q < 31) ?
            (((double)(rtt_q+1))/(double)RTT_MIN) :
            (RTT_MAX/exp(((double)(255-rtt_q))/(double)13.0)));
}

unsigned char QuantizeRtt(double rtt);

inline unsigned short QuantizeLossFraction(double loss)
{
    return (unsigned short) (65535.0 * loss);
}  // end QuantizeLoss()

inline double UnquantizeLossFraction(unsigned short loss_q)
{
    return (((double)loss_q) / 65535.0);
}  // end UnquantizeLoss


// Prioritized FIFO queue of MDP messages
class MdpMessageQueue
{
    // Members
    private:
        MdpMessage *head, *tail;

    // Methods
    public:
        MdpMessageQueue();
        bool IsEmpty() {return (head == NULL);}
        void QueueMessage(MdpMessage *theMsg);
        void RequeueMessage(MdpMessage *theMsg);
        MdpMessage *GetNextMessage();
        MdpMessage *Head() {return head;}
        void Remove(MdpMessage *theMsg);
        MdpMessage* FindNackAdv();
};


// Right now, the pool maintains a fixed amount of messages as
// dictated on "Init()" ... eventually some hooks for dynamic
// resource management will be added.
class MdpMessagePool
{
    // Members
    private:
        UInt32          message_count;
        UInt32          message_total;
        MdpMessage      *message_list;

    // Methods
    public:
        MdpMessagePool();
        ~MdpMessagePool();
        MdpError Init(UInt32 count);
        void Destroy();
        MdpMessage *Get();
        void Put(MdpMessage *);
        UInt32 Count() {return message_count;}
        UInt32 Depth() {return message_total;}
};
#endif // _MDP_MESSAGE
