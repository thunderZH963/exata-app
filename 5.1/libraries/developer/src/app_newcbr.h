//
// Created by 张画 on 2020/11/16.
//



#ifndef _NEWCBR_APP_H_
#define _NEWCBR_APP_H_

#include "types.h"
#include "dynamic.h"
#include "stats_app.h"
#include "application.h"

#ifdef ADDON_DB
class SequenceNumber;
#endif // ADDON_DB
/*
 * Header size defined to be consistent accross 32/64 bit platforms
 */
#define NEWCBR_HEADER_SIZE 40

/*
 * Data item structure used by newcbr.
 */
typedef
struct struct_app_newcbr_data
{
    short sourcePort;
    char type;
    BOOL isMdpEnabled;
    Int32 seqNo;
    clocktype txTime;
#ifdef ADDON_BOEINGFCS
    Int32 txPartitionId;
#endif // ADDON_BOEINGFCS

#if defined(ADVANCED_WIRELESS_LIB) || defined(UMTS_LIB) || defined(MUOS_LIB)
    Int32 pktSize;
    clocktype interval;
#endif // ADVANCED_WIRELESS_LIB || UMTS_LIB || MUOS_LIB
} NewcbrData;


/* Structure containing newcbr client information. */
typedef
struct struct_app_newcbr_client_str
{
    Address localAddr;
    Address remoteAddr;
    D_Clocktype interval;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastSent;
    clocktype endTime;
    BOOL sessionIsClosed;
    UInt32 itemsToSend;
    UInt32 itemSize;
    short sourcePort;
    Int32 seqNo;
    D_UInt32 tos;
    int  uniqueId;
    Int32 mdpUniqueId;
    BOOL isMdpEnabled;
    std::string* applicationName;
#ifdef ADDON_DB
    Int32 sessionId;
    Int32 receiverId;
#endif // ADDON_DB

#ifdef ADDON_NGCNMS
    Message* lastTimer;
#endif
    STAT_AppStatistics* stats;

    // Dynamic Address
    NodeId destNodeId; // destination node id for this app session
    Int16 clientInterfaceIndex; // client interface index for this app
    // session
    Int16 destInterfaceIndex; // destination interface index for this app
    // session
    // dns
    std::string* serverUrl;
} AppDataNewcbrClient;

/* Structure containing newcbr related information. */

typedef
struct struct_app_newcbr_server_str
{
    Address localAddr;
    Address remoteAddr;
    short sourcePort;
    clocktype sessionStart;
    clocktype sessionFinish;
    clocktype sessionLastReceived;
    BOOL sessionIsClosed;
    Int32 seqNo;
    int uniqueId ;

    //    clocktype lastInterArrivalInterval;
    //    clocktype lastPacketReceptionTime;

#ifdef ADDON_DB
    Int32 sessionId;
    Int32 sessionInitiator;
    Int32 hopCount;
    SequenceNumber *seqNumCache;
#endif // ADDON_DB


#ifdef ADDON_BOEINGFCS
    // The number of packets received from a different partition
    UInt32 numPktsRecvdDP;

    // Total end to end delay between nodes on different partitions
    clocktype totalEndToEndDelayDP;

    // Total jitter between nodes on different partitions
    clocktype totalJitterDP;

    // Used for calculating jitter for packets on different partitions
    clocktype lastPacketReceptionTimeDP;
    clocktype lastInterArrivalIntervalDP;

    // Whether or not to perform sequence number check on incoming data packets
    BOOL useSeqNoCheck;
#endif /* ADDON_BOEINGFCS */
    STAT_AppStatistics* stats;
} AppDataNewcbrServer;

