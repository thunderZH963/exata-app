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
 ------------------------------------------------------------------------------
 SUPER-APPLICATION

 SUPER-APPLICATION is a generic application. SUPER-APPLICATION can simulate
 both UDP and TCP flows. 2-way flow (request-response) is supported for UDP
 based applications. Request packets travel from source to destination
 whereas response packets travel from destination to source. In order to use
 SUPER-APPLICATION, the following format is needed:

     SUPER-APPLICATION <src> <dest> <Keyword 1> <value 1>
        <Keyword 2> <value 2>  ..... <Keyword n> <value n>

 The following are the required keyword and value pairs:

     DELIVERY-TYPE <RELIABLE|UNRELIABLE> : Specifies  TCP or UDP
     START-TIME <time_distribution_type> : specifies application start time.
     DURATION <time_distribution_type>   : specifies application duration.
     REQUEST-NUM <int_distribution_type> :is the number of items to send.
     REQUEST-SIZE <int_distribution_type> : is size of each item.
     REQUEST-INTERVAL <time_distribution_type> : is inter-departure time
        between requests items.

 The following optional keyword and value pairs are also supported:
     REQUEST-TOS [TOS <tos-value> | DSCP <dscp-value> | PRECEDENCE
        <precedence-value>] :  <tos-value> is the value of the TOS bits of
        the IP header.<dscp-value> is the value of the DSCP bits of the IP
        header.<precedence-value> is the contents of the Precedence bits of
        IP header. When no REQUEST-TOS is specified, default value of
        APP_DEFAULT_TOS ( Ox00) is used.
     REPLY-TOS [TOS <tos-value> | DSCP <dscp-value> | PRECEDENCE
        <precedence-value>] :  <tos-value> is the value of the TOS bits of
        the IP header.<dscp-value> is the value of the DSCP bits of the IP
        header.<precedence-value> is the contents of the Precedence bits of
        IP header. When no REPLY-TOS is specified, default value of
        APP_DEFAULT_TOS ( Ox00) is used.
     REPLY-PROCESS <YES|NO> : indicates if reply is to be sent. When
        REPLY-PROCESS is YES, then all reply related keywords are required.
     REPLY-NUM <int_distribution_type> : is the number of reply packets to
        send per request
     REPLY-SIZE <int_distribution_type> : is the size of reply packets
     REPLY-PROCESS-DELAY <time_distribution_type> : is the wait time at the
        server for sending the first response packet when a request is received.
     REPLY-INTERDEPARTURE-DELAY <time_distribution_type>: is the delay between
        the reply packets.
     FRAGMENT-SIZE <bytes> : is the max application fragment size. Packets will
       be broken into multiple fragments when packet size exceeds FRAGMENT-SIZE.
       FRAGMENT-SIZ is only supported for UDP.
     SOURCE-PORT <port number> : is the port number to be used at the source.
        The application chooses a free source port when user does not specify a
        source port. User specified ports must be unique.
     DESTINATION-PORT <port number> : is the port number to be used at the
        destination. The application uses the it's default well known port when
        destination port is not specified by the user. User specified ports must
        be unique. */

#ifdef ADDON_BOEINGFCS

/*REQUIRED-TPUT <bps>: is the required throughput in bits per second
   (in the form of an int) for admission control and QAF purposes
   the QoS table.  An integer value of milliseconds should be given*/


#endif

/*
 Where
             <time_distribution_type> ::= DET time_value |
                                          UNI time_value time_value |
                                          EXP time_value

              <time_value> ::= integer [ NS | MS | S | M | H | D ]

             <int_distribution_type> ::= DET integer |
                                         UNI integer integer |
                                         EXP integer

 EXAMPLE:

     a) SUPER-APPLICATION 1 2 DELIVERY-TYPE RELIABLE START-TIME DET 60S DURATION
         DET 10S REQUEST-NUM DET 5 REQUEST-SIZE DET 1460  REQUEST-INTERVAL DET 0S
         REQUEST-TOS PRECEDENCE 0 REPLY-PROCESS NO

        Node 1 sends to node 2 five items of 1460B each using TCP from 60 seconds
         simulation time till 70 seconds simulation time. If five items are sent
         before 10 seconds elapsed, no other items are sent. Precedence is set
         to 0.

     b) SUPER-APPLICATION 1 2 DELIVERY-TYPE UNRELIABLE START-TIME DET 10S DURATION
         DET 21S REQUEST-NUM DET 3 REQUEST-SIZE DET 123  REQUEST-INTERVAL DET 1S
         REQUEST-TOS PRECEDENCE 1 REPLY-PROCESS YES FRAGMENT-SIZE 200 DESTINATION-PORT
         1751 SOURCE-PORT 2345 REPLY-NUM DET 2 REPLY-SIZE DET 140 REPLY-PROCESS-DELAY
         DET 1S REPLY-INTERDEPARTURE-DELAY DET 0.1S

        Node 1 sends to node 2 three (request) packets of 123 bytes each using UDP.
         Node 1 starts sending at 10 seconds simulation time and sends for a
         duration of 21 seconds. Packets are sent with a 1 sec interval with
         precedence set to 1. Node 1 uses port 2345 whereas Node 2 uses port 1751.
         The fragment size is bigger than packet size, so no fragmentation takes
         place. On receiving the request packets, Node 2 replies with 2 packets of
         140 bytes each, for every request packet received. On receiving a
         request packet, node 2 waits 1 second before sending the first of 2
         reply packets for that request packet. The second reply packet is
         sent 0.1 seconds after the first one.

 ---------------------------------------------------------------

 Behavior & Limitations

 a) Response is only supported with DELIVERY-TYPE UNRELIABLE.

 b) Default value for REPLY-PROCESS is NO. Replies are not processed unless
    this is explicitly set to YES.

 c) Both client and server print out all possible statistics even if they are
    not collected. This will be changed in the next release. Not collected
    statistics are set to zero. Example: The client reports "Number of reply
    packets sent = 0" since this stat is only collected at the server.

 d) The REPLY-INTERDEPARTURE-DELAY and REQUEST-INTERVAL is applicable between
    packets and not fragments. If fragmentation occurs then all fragments are
    sent back to back.

 e) 0 second duration indicates "till end of simulation".
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api.h"
#include "WallClock.h"
#include "app_util.h"
#include "tcpapps.h"
#include "transport_tcp.h"
#include "network_ip.h"
#include "app_superapplication.h"
#include "random.h"
#ifdef ADDON_DB
#include "db.h"
#include "dbapi.h"
#endif

// Pseudo traffic sender layer
#include "app_dns.h"
#include "app_trafficSender.h"

#ifdef HITL_INTERFACE
#include "hitl.h"
#endif // HITL_INTERFACE

//UserCodeStartBodyData
#include "partition.h"
#define TPUT_STAT_DEBUG 0
#define E2E_STAT_DEBUG 0
#define JITTER_STAT_DEBUG 0
#define MCR_STAT_DEBUG 0
#define DEBUG_QOS_ENABLED 0

#define SUPERAPPLICATION_TCP   1
#define SUPERAPPLICATION_UDP   2
#define SUPERAPPLICATION_TOKENSEP   " ,\t"
//#define SUPERAPPLICATION_MAX_DATABYTE_SEND   0xFFFFFFFF
#define SUPERAPPLICATION_DEBUG_REQ_SEND   0
#define SUPERAPPLICATION_DEBUG_REP_SEND   0
#define SUPERAPPLICATION_DEBUG_REP_REC   0
#define SUPERAPPLICATION_DEBUG_REQ_REC   0
#define SUPERAPPLICATION_DEBUG_TIMER_SET_CLIENT   0
#define SUPERAPPLICATION_DEBUG_TIMER_REC_CLIENT   0
#define SUPERAPPLICATION_DEBUG_TIMER_SET_SERVER   0
#define SUPERAPPLICATION_DEBUG_TIMER_REC_SERVER   0
#define SUPERAPPLICATION_DEBUG_PORTS   0
#define SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE   0
#define SUPERAPPLICATION_INVALID_SOURCE_PORT   -1
#define SUPERAPPLICATION_REALTIME_PROCESS_DELAY     (10 * MILLI_SECOND)


// new addons
#define INPUT_LENGTH 1000
#define SUPERAPPLICATION_DEBUG_TCP_REPLY 0
#define SUPERAPPLICATION_DEBUG_VOICE 0
#define SUPERAPPLICATION_DEBUG_VOICE_RECV 0
#define SUPERAPPLICATION_DEBUG_VOICE_SEND 0
#define SUPERAPPLICATION_DEBUG_VOICE_TALK_TIME_OUT 0
#define SUPERAPPLICATION_DEBUG_CONDITION_STACK 0
#define SUPERAPPLICATION_DEBUG_CHAIN 0
#define SUPERAPPLICATION_DEBUG_TRIGGER_SESSION 0

#define MIN_TALK_TIME (1 * SECOND)
#define SUPERAPPLICATION_DEFAULT_TCP_CONNECTION_RETRY_LIMIT 0
#define SUPERAPPLICATION_DEFAULT_TCP_CONNECTION_RETRY_INTERVAL (1 * SECOND)

#ifdef ADDON_BOEINGFCS
#define DEBUG_QOS 0
#endif

#ifdef ADDON_BOEINGFCS

// If set to 1 statistics will be tracked differently for packets with a
// sender and receiver on different partitions.  If set to 0 statistics will
// be combined.
#define TRACK_STATISTICS_DIFFERENT_PARTITION 0

// If set to 1 real time stats will be collected for packets with a sender
// and receiver on different partitions.  If set to 0 then no output will
// be generated for different partitions.
#define TRACK_REALTIME_DIFFERENT_PARTITION 0

// If set to 1 real time stats will be collected for packets with a sender
// and receiver on different subnets.  If set to 0 then no output will
// be generated for different subnets.
#define TRACK_REALTIME_DIFFERENT_SUBNET 0

#define MAX_INT_DOUBLE pow(2.0, sizeof(time_t) * 8)

static clocktype SuperApplicationCpuTime(SuperApplicationData *dataPtr)
{
    clocktype guess;
    clock_t now;
    int i;

    // If the cpu timing system needs to be initialized
    if (dataPtr->cpuTimingStarted == FALSE)
    {
        // A return value of (clock_t) -1 indicates that this function is
        // not supported.  In that case return 0.
        if (clock() == (clock_t) -1)
        {
            return 0;
        }

        dataPtr->cpuTimingStarted = TRUE;

        // Make a few guesses at the CPU timing interval
        dataPtr->cpuTimingInterval = 1 * SECOND;
        for (i = 0; i < 4; i++)
        {
            dataPtr->lastCpuTime = clock();
            do
            {
                now = clock();
            } while (now == dataPtr->lastCpuTime);

            guess = (now - dataPtr->lastCpuTime) * SECOND / CLOCKS_PER_SEC;
            if (guess < dataPtr->cpuTimingInterval)
            {
                dataPtr->cpuTimingInterval = guess;
            }
        }
        /*printf("guess = %f\n",
               (double) dataPtr->cpuTimingInterval / SECOND);*/
    }

    // Get time and convert to qualnet time
    now = clock();

    if (now > dataPtr->lastCpuTime)
    {
        guess = (now - dataPtr->lastCpuTime) * SECOND / CLOCKS_PER_SEC;
        if ((guess != 0) && (guess < dataPtr->cpuTimingInterval))
        {
            dataPtr->cpuTimingInterval = guess;
            //printf("updated to %f\n",
            //    (double) dataPtr->cpuTimingInterval / SECOND);
        }
        dataPtr->lastCpuTime = now;
    }

    return (clocktype) now * SECOND / CLOCKS_PER_SEC;
}

clocktype ComputeCpuTimeDiff(
    clocktype receivedCpuTime,
    clocktype sentCpuTime)
{
    clocktype cpuTime;

    if (receivedCpuTime >= sentCpuTime)
    {
        cpuTime = receivedCpuTime - sentCpuTime;
    }
    else
    {
        // Handle overflow.  This will make a best guess at the cpuTime but
        // may not be accurate.
        int received;
        int sent;

        // Convert back to clock format
        received = (int) (receivedCpuTime * CLOCKS_PER_SEC / SECOND);
        sent = (int) (sentCpuTime * CLOCKS_PER_SEC / SECOND);

        // Compute elapsed time based on clock format
        cpuTime = (received - sent) * SECOND / CLOCKS_PER_SEC;
    }

    return cpuTime;
}

static void SuperApplicationElapsedTime(
    SuperApplicationData *dataPtr,
    clocktype sentRealTime,
    clocktype receivedRealTime,
    clocktype sentCpuTime,
    clocktype receivedCpuTime,
    clocktype *elapsed,
    char *type)
{
    clocktype cpuTime;
    clocktype realTime;

    realTime = receivedRealTime - sentRealTime;
    cpuTime = ComputeCpuTimeDiff(receivedCpuTime, sentCpuTime);

    // Option C occurs if the process was swapped out, and the measured
    // cpu time is an UNreliable value, but we know that the elapsed real
    // time was greater than the cpu timing interval.  This is the least
    // reliable.
    if (cpuTime < realTime && realTime > dataPtr->cpuTimingInterval && cpuTime == 0)
    {
        *type = 'C';
        *elapsed = dataPtr->cpuTimingInterval;
    }
    // Option B occurs if the process was swapped out, and the measured
    // cpu time is a reliable value.  This is the second least reliable.
    else if (cpuTime < realTime)
    {
        *type = 'B';
        *elapsed = cpuTime;
    }
    // Otherwise we just use real time.  This is most reliable.
    else
    {
        *type = 'A';
        *elapsed = realTime;
    }
}

static void SuperApplicationHandleRealTimeStats(
    Node *node,
    BOOL samePartition,
    SuperApplicationData *appData,
    char *prefix,
    NodeAddress sourceAddr,
    NodeAddress destAddr,
    short port,
    Int32 seqNo,
    clocktype txRealTime,
    clocktype txCpuTime,
    clocktype txTime,
    unsigned numPackets)
{
    clocktype rxRealTime;
    clocktype rxCpuTime;
    clocktype rxTime;
    clocktype elapsedCpuTimeEstimate;
    clocktype elapsedSimTime;
    char type;
    FILE *f;

    rxRealTime = node->partitionData->wallClock->getRealTime();
    rxCpuTime = SuperApplicationCpuTime(appData);
    rxTime = node->getNodeTime();
    elapsedSimTime = rxTime - txTime;

#if TRACK_REALTIME_DIFFERENT_SUBNET
    // Determine if they are in the same subnet
    NodeAddress mask;

    // TODO: Need to figure out proper interface
    mask = NetworkIpGetInterfaceSubnetMask(node, 0);
    BOOL same = (sourceAddr & mask) == (destAddr & mask);
    if (!same)
    {
        return;
    }
#endif

    if (elapsedSimTime > 0 && rxCpuTime > txCpuTime)
    {
        SuperApplicationElapsedTime(
            appData,
            txRealTime,
            rxRealTime,
            txCpuTime,
            rxCpuTime,
            &elapsedCpuTimeEstimate,
            &type);

        appData->stats.totalRealTimePerSimTime +=
            (double) elapsedCpuTimeEstimate / elapsedSimTime;
        appData->stats.avgRealTimePerSimTime =
            appData->stats.totalRealTimePerSimTime
            / numPackets;

        if (elapsedCpuTimeEstimate > (elapsedSimTime + appData->delayRealTimeProcessing))
        {
            appData->stats.numSlowPackets += 1;
            //printf("*** slow packet ***\n");
        }

        if (appData->realTimeOutput)
        {
            char sourceStr[20];
            char destStr[20];
            char cpuTime[MAX_STRING_LENGTH];
            char realTime[MAX_STRING_LENGTH];
            char cpuTimeEstimate[MAX_STRING_LENGTH];
            char simTime[MAX_STRING_LENGTH];

            IO_ConvertIpAddressToString(sourceAddr, sourceStr);
            IO_ConvertIpAddressToString(destAddr, destStr);

            f = node->partitionData->realTimeFd;
            assert(f != NULL);

            ctoa(rxCpuTime - txCpuTime, cpuTime);
            ctoa(rxRealTime - txRealTime, realTime);
            ctoa(elapsedCpuTimeEstimate, cpuTimeEstimate);
            ctoa(elapsedSimTime, simTime);

            fprintf(f, "%s\t%c\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\t%f\n",
                    prefix,
                    type,
                    samePartition,
                    sourceStr,
                    destStr,
                    port,
                    seqNo,
                    cpuTime,
                    realTime,
                    cpuTimeEstimate,
                    simTime,
                    (double) elapsedCpuTimeEstimate / elapsedSimTime);
        }
    }
}

#endif /* ADDON_BOEINGFCS */

//UserCodeEndBodyData

//Statistic Function Declarations
static void SuperApplicationInitStats(Node* node, SuperApplicationStatsType *stats);
void SuperApplicationPrintStats(Node *node, SuperApplicationData* dataPtr);

//Utility Function Declarations
static char* SuperApplicationDataSkipToken(char* token,const char* tokenSep,int skip);
static SuperApplicationData* SuperApplicationClientNewClient(Node* node);
static void SuperApplicationClientInit(Node* node,char* inputString,SuperApplicationData* clientPtr,
                                       NodeAddress clientAddr, NodeAddress serverAddr);
static void SuperApplicationClientValidateParam(Node* node,SuperApplicationData* clientPtr,BOOL isSourcePort);
static void SuperApplicationServerValidateParam(Node* node,SuperApplicationData* serverPtr,BOOL isDestinationPort);
static void SuperApplicationServerHandleOpenResult_TCP(Node* node,SuperApplicationData* serverPtr,Message* msg);
static void SuperApplicationClientHandleOpenResult_TCP(Node* node,SuperApplicationData* clientPtr,Message* msg);
static void SuperApplicationClientOpenConnection_TCP(Node* node,SuperApplicationData* clientPtr);
static void SuperApplicationClientSchedulePacket_TCP(Node* node,SuperApplicationData* clientPtr,clocktype interval);
static void SuperApplicationClientScheduleFirstPacket_UDP(Node* node,SuperApplicationData* clientPtr);
static void SuperApplicationServerScheduleNextRepPkt_UDP(Node* node,SuperApplicationData* serverPtr,clocktype interval,Message* msg);
static void SuperApplicationClientSendData_TCP(Node* node,SuperApplicationData* clientPtr,Message* msg);
static void SuperApplicationClientSendData_UDP(Node* node,SuperApplicationData* clientPtr,Message* msg);
static void SuperApplicationServerSendData_UDP(Node* node,SuperApplicationData* serverPtr,Message* msg);
static void SuperApplicationClientScheduleNextPkt(Node* node,SuperApplicationData* clientPtr,clocktype interval,Message* msg);
static void SuperApplicationServerInit(Node* node,char* inputString,SuperApplicationData* serverPtr, NodeAddress clientAddr, NodeAddress serverAddr);

//static void SuperApplicationScheduleNextReply_TCP(Node* node,SuperApplicationData* serverPtr);
static void SuperApplicationScheduleNextReply_UDP(Node* node,SuperApplicationData* serverPtr);
static void SuperApplicationClientReceivePacket_UDP(Node* node,Message* msg,SuperApplicationData* clientPtr);
static void SuperApplicationServerProcessFragRcvd_TCP(Node* node,SuperApplicationData* serverPtr,SuperApplicationTCPDataPacket *data);
static void SuperApplicationServerReceivePacket_TCP(Node* node,Message* msg,SuperApplicationData* serverPtr);
static void SuperApplicationServerReceivePacket_UDP(Node* node,Message* msg,SuperApplicationData* serverPtr);
static SuperApplicationData* SuperApplicationServerNewServer(Node* node);
static void SuperApplicationDataPrintUsageAndQuit();
static SuperApplicationData* SuperApplicationServerSetDataPtr(Node* node, Message* msg);



// for tcp reply
static void SuperApplicationServerScheduleNextRepPkt_TCP(Node* node, SuperApplicationData* serverPtr,clocktype interval,Message*msg);
static void SuperApplicationServerSendData_TCP(Node* node, SuperApplicationData* serverPtr, Message* msg);
static void SuperApplicationScheduleNextReply_TCP(Node* node, SuperApplicationData* serverPtr, clocktype delay);
static void SuperApplicationClientReceivePacket_TCP(Node* node, Message* msg, SuperApplicationData* clientPtr);
static void SuperApplicationClientProcessFragRcvd_TCP(Node* node, SuperApplicationData* clientPtr);
static void enterSuperApplicationServer_TimerExpired_SendReply_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
// end for tcp reply

static void SuperAppTriggerUpdateChain(Node* node, int numPacketsRecvd, char* chainId);
static void SuperAppUpdateChainStats(Node* node, SuperApplicationData* dataPtr);
static void SuperAppTrigger(Node* node,
                            SuperApplicationData* clientPtr,
                            BOOL isSourcePort,
                            RandomDistribution<clocktype> randomDuration,
                            BOOL isFragmentSize
#ifdef ADDON_BOEINGFCS
                            , BOOL burstyKeywordFound
#endif
                           );
static void SuperAppTriggerSendMsg(Node* node,
                                   SuperApplicationData* clientPtr,
                                   BOOL isSourcePort,
                                   RandomDistribution<clocktype> rndDuration,
                                   BOOL isFragmentSize
#ifdef ADDON_BOEINGFCS
                                   , BOOL burstyKeywordFound
#endif
                                  );

static int SuperApplicationInsertClientCondition(Node* node, SuperApplicationData* clientPtr, char* inputstring);


// FUNCTION SuperApplicationMulticastServerInit
// PURPOSE  Initialize SuperApplication server. for multicast data.
// Parameters:
//  node            : Pointer to the node structure
//  configData      : pointer to the SuperAppConfigurationData.
SuperApplicationData* SuperApplicationMulticastServerInit(Node *node,
                             SuperAppConfigurationData *configData)
{
    SuperApplicationData* serverPtr = NULL;

    serverPtr = SuperApplicationServerNewServer(node);
    // Do the parsing & register the application
    serverPtr->protocol = APP_SUPERAPPLICATION_SERVER;
    serverPtr->sourcePort = configData->sourcePort;
    serverPtr->destinationPort = configData->destinationPort;
    serverPtr->serverAddr = configData->serverAddr;
    serverPtr->clientAddr = configData->clientAddr;
    // name at server side will be overwritten after receiving the first packet
    strcpy(serverPtr->applicationName, configData->applicationName);
    strcpy(serverPtr->printName, configData->applicationName);

    serverPtr->transportLayer = SUPERAPPLICATION_UDP;
    serverPtr->isMdpEnabled = configData->isMdpEnabled;
    serverPtr->isProfileNameSet = configData->isProfileNameSet;
    if (configData->isProfileNameSet)
    {
        strcpy(serverPtr->profileName,configData->profileName);
    }
    serverPtr->mdpUniqueId = configData->mdpUniqueId;
    serverPtr->appFileIndex = configData->appFileIndex;
#ifdef ADDON_BOEINGFCS
    serverPtr->printRealTimeStats = configData->printRealTimeStats;
#endif
    // Register the application
    APP_RegisterNewApp(node, APP_SUPERAPPLICATION_SERVER, serverPtr,
                       serverPtr->destinationPort);
    return serverPtr;
}

// for conditions
static int SuperAppGetNumInChain(SuperAppChainIdList* chain, char* chainId){
    if (chain->numInList == 0)
    {
        //nothing in chain id list
        return 0;
    }
    else
    {
        SuperAppChainIdElement* curr =chain->head;
        while (curr !=NULL) {
            if (strcmp(curr->chainID, chainId) == 0){
                return curr->numSeen;
            }
            curr = curr->next;
        }
        return 0;
    }
}

static
void SuperAppCheckDistributionType(char* keyword, char* tokenStr) {
    char buf[MAX_STRING_LENGTH] = "";
    sscanf(tokenStr, "%s", buf);
    if (strcmp(buf, "DET") != 0 &&
            strcmp(buf, "UNI") != 0 &&
            strcmp(buf, "EXP") != 0 &&
            strcmp(buf, "TPD") != 0)
    {
        char errorStr[MAX_STRING_LENGTH] = "";
        sprintf(errorStr, "ERROR, Distribution type for %s was not defined or Unknown\n", keyword);
        ERROR_ReportError(errorStr);
    }
}

#ifdef ADDON_NGCNMS
void SuperApplicationResetServerClientAddr(Node* node,
        NodeAddress oldAddr,
        NodeAddress newAddr)
{
    SuperApplicationData* dataPtr;
    AppInfo* appList = node->appData.appPtr;

    for (; appList != NULL; appList = appList->appNext) {
        if (appList->appType == APP_SUPERAPPLICATION_SERVER) {
            dataPtr = (SuperApplicationData*) appList->appDetail;

            if (dataPtr->clientAddr == oldAddr) {
                dataPtr->clientAddr = newAddr;
                dataPtr->seqNo = 0;
                dataPtr->fragNo = 0;
                dataPtr->uniqueFragNo = 0;
                dataPtr->repSeqNo = 0;
                dataPtr->repFragNo = 0;
            }
        }
    }

}
#endif

// /**
// FUNCTION   :: SuperApplicationPrintTraceXML
// LAYER      :: NETWORK
// PURPOSE    :: Print packet trace information in XML format
// PARAMETERS ::
// + node     : Node*    : Pointer to node
// + msg      : Message* : Pointer to packet to print headers from
// RETURN     ::  void   : NULL
// **/

void SuperApplicationPrintTraceXML(Node* node, Message* msg)
{
    char buf[MAX_STRING_LENGTH];
    int packetSize = 0;
    sprintf(buf, "<superApplication>");
    TRACE_WriteToBufferXML(node, buf);

    switch (msg->eventType)
    {
    case MSG_TRANSPORT_FromAppSend:
    {
        char sourceAddr[MAX_STRING_LENGTH];
        char targetAddr[MAX_STRING_LENGTH];

        packetSize = MESSAGE_ReturnPacketSize(msg);

        sprintf(buf, "<msg_transport_fromappsend>");
        TRACE_WriteToBufferXML(node, buf);

        SuperApplicationData* dataPtr = NULL;
        AppInfo* appList = node->appData.appPtr;
        dataPtr = (SuperApplicationData*) appList->appDetail;
        if (dataPtr == NULL) {
            dataPtr = SuperApplicationServerSetDataPtr(node, msg);
        }

        IO_ConvertIpAddressToString(dataPtr->clientAddr , sourceAddr);
        IO_ConvertIpAddressToString(dataPtr->serverAddr , targetAddr);

        sprintf(buf,"%d %s %hu %s %hu %d %d ",
                dataPtr->connectionId,
                sourceAddr,
                dataPtr->sourcePort,
                targetAddr,
                dataPtr->destinationPort,
                dataPtr->reqTOS,
                packetSize);

        TRACE_WriteToBufferXML(node, buf);

        sprintf(buf, "</msg_transport_fromappsend>");
        TRACE_WriteToBufferXML(node, buf);
        break;
    }
    case MSG_APP_FromTransport:
    {
        sprintf(buf, "<msg_app_fromTransport>");
        TRACE_WriteToBufferXML(node, buf);
        char clientAddr[MAX_STRING_LENGTH];
        char serverAddr[MAX_STRING_LENGTH];
        UdpToAppRecv *info;
        info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);

        packetSize = MESSAGE_ReturnPacketSize(msg);

        IO_ConvertIpAddressToString(&info->sourceAddr, clientAddr);
        IO_ConvertIpAddressToString(&info->destAddr , serverAddr);
        sprintf(buf,"%s %hu %s %hu %d ",
                clientAddr,
                info->sourcePort,
                serverAddr,
                info->destPort,
                packetSize);
        TRACE_WriteToBufferXML(node, buf);
        sprintf(buf, "</msg_app_fromTransport>");
        TRACE_WriteToBufferXML(node, buf);
        break;
    }
    case MSG_APP_FromTransDataReceived:
    {
        char srcAddr[MAX_STRING_LENGTH];
        char serverAddr[MAX_STRING_LENGTH];

        sprintf(buf, "<msg_app_fromTransport>");
        TRACE_WriteToBufferXML(node, buf);

        SuperApplicationData* dataPtr = NULL;
        AppInfo* appList = node->appData.appPtr;
        dataPtr = (SuperApplicationData*) appList->appDetail;
        packetSize = MESSAGE_ReturnPacketSize(msg);

        IO_ConvertIpAddressToString(dataPtr->clientAddr , srcAddr);

        IO_ConvertIpAddressToString(dataPtr->serverAddr, serverAddr);

        sprintf(buf,"%s %hu %s %hu %d ",
                srcAddr,
                dataPtr->sourcePort,
                serverAddr,
                dataPtr->destinationPort,
                packetSize
               );

        TRACE_WriteToBufferXML(node, buf);
        sprintf(buf, "</msg_app_fromTransport>");
        TRACE_WriteToBufferXML(node, buf);
        break;
    }
    }
    sprintf(buf, "</superApplication>");
    TRACE_WriteToBufferXML(node, buf);

}//END OF FUNCTION SuperApplicationPrintTraceXML


static SuperApplicationData* SuperApplicationServerSetDataPtr(Node* node, Message* msg) {
    UdpToAppRecv* info;
    SuperApplicationData* dataPtr;
    SuperApplicationUDPDataPacket* udpData;
    AppInfo* appList = node->appData.appPtr;
    udpData = (SuperApplicationUDPDataPacket *)
             MESSAGE_ReturnInfo(msg, INFO_TYPE_SuperAppUDPData);
    info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_SUPERAPPLICATION_SERVER)
        {
            dataPtr = (SuperApplicationData*) appList->appDetail;

            if ((dataPtr->sourcePort == SUPERAPPLICATION_INVALID_SOURCE_PORT)
                && (dataPtr->serverAddr == GetIPv4Address(info->destAddr))
                && (dataPtr->clientAddr == GetIPv4Address(info->sourceAddr))
                && (dataPtr->destinationPort == info->destPort)
                && (dataPtr->appFileIndex == udpData->appFileIndex))
            {
                dataPtr->sourcePort   = info->sourcePort;
                dataPtr->connectionId = 0;

                return dataPtr;
            }
            // dynamic addressing
            if (dataPtr->sourcePort == SUPERAPPLICATION_INVALID_SOURCE_PORT
                && MAPPING_GetInterfaceAddressForInterface(node,
                    node->nodeId,info->incomingInterfaceIndex) ==
                GetIPv4Address(info->destAddr)
                && dataPtr->destinationPort == info->destPort
                && dataPtr->appFileIndex == udpData->appFileIndex)
            {
                dataPtr->clientAddr = GetIPv4Address(info->sourceAddr);
                dataPtr->serverAddr = GetIPv4Address(info->destAddr);
                dataPtr->sourcePort = info->sourcePort;
                dataPtr->connectionId = 0;

                return dataPtr;
            }
        }
    }

    return NULL;
}

static void SuperApplicationServerPrintClientCondition(Node* node) {
    unsigned int x = 0 ; // testing purpose only

    SuperAppClientList* clist =
        (SuperAppClientList*)node->appData.clientPtrList;

    for (unsigned int cindex = 0; cindex < clist->clientList.size(); cindex++) {

        printf("CONDITION: for node %d to node %d is \n ",
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clist->clientList[cindex].clientPtr->clientAddr),
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clist->clientList[cindex].clientPtr->serverAddr));

        for (x=0; x < clist->clientList[cindex].clientPtr->conditionList.size(); x++) {
            if (clist->clientList[cindex].clientPtr->conditionList[x].isOpt) {
                printf(" %s ", clist->clientList[cindex].clientPtr->conditionList[x].opt);
            }
            else if (clist->clientList[cindex].clientPtr->conditionList[x].isArg) {
                printf(" CHAINID = %s AND PACKET %s %d ",
                       clist->clientList[cindex].clientPtr->conditionList[x].chainID,
                       clist->clientList[cindex].clientPtr->conditionList[x].opt,
                       clist->clientList[cindex].clientPtr->conditionList[x].numNeed);
            }
            else if (clist->clientList[cindex].clientPtr->conditionList[x].isNot) {
                printf(" NOT ");
            }
            else if (clist->clientList[cindex].clientPtr->conditionList[x].isOpen) {
                printf(" ( ");
            }
            else if (clist->clientList[cindex].clientPtr->conditionList[x].isClose) {
                printf(" ) ");
            }
        }
        printf("\n");
    }
}

//State Function Declarations
static void enterSuperApplicationServerIdle_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_TimerExpired_SendReply_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClientIdle_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_ReceiveReply_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_TimerExpired_SendRequest_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_ReceiveData_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_ReceiveReply_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_ConnectionClosed_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_ReceiveData_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_ConnectionClosed_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServerIdle_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_ConnectionOpenResult_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClientIdle_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationServer_ListenResult_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_ConnectionOpenResult_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_TimerExpired_SendRequest_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_DataSent_TCP(Node* node, SuperApplicationData* dataPtr, Message* msg);

// new function for superapplication
static void SuperAppExpandAppInput (const NodeInput* nodeInput, NodeInput* appInput);

//static void SuperAppClientScheduleConversation (Node* node, SuperApplicationData* dataPtr);
static BOOL SuperAppVoiceStartTalking (Node* node, SuperApplicationData* dataPtr, char* dataType, clocktype reqInterval);
static void SuperApplicationClientScheduleTalkTimeOut(Node* node, SuperApplicationData* clientPtr);
static void SuperApplicationServerScheduleTalkTimeOut(Node* node, SuperApplicationData* serverPtr);
static void SuperApplicationClientScheduleNextVoicePacket_UDP(Node* node,SuperApplicationData* clientPtr);
static void enterSuperApplicationServer_TimeExpired_StartTalk_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);
static void enterSuperApplicationClient_TimeExpired_StartTalk_UDP(Node* node, SuperApplicationData* dataPtr, Message* msg);

// for conditions
static BOOL SuperApplicationCheckConditionKeyword(char* keyword);
static BOOL SuperApplicationCheckKeyword(char* keyword);
static BOOL SuperAppCheckConditions(Node* node,
                                    SuperApplicationData* clientPtr);
static void SuperAppEvaluateCondition(Node* node,
                                      vector<SuperAppClientConditionElement> *conditionList);
static BOOL SuperAppCheckConditionElement(Node* node, SuperAppClientConditionElement *cElement);


//Utility Function Definitions
//UserCodeStart
// FUNCTION SuperApplicationDataSkipToken
// PURPOSE  Skip the first n tokens
// Parameters:
//  token:  Pointer to the input string
//  tokenSep:   Pointer to the token separators
//  skip:   Number of skips
static char* SuperApplicationDataSkipToken(char* token,const char* tokenSep,int skip) {
    unsigned int idx;
    if (token == NULL)
    {
        return NULL;
    }
    // Eliminate preceding space
    idx = (unsigned int)strspn(token, tokenSep);
    token = (idx < (unsigned int)strlen(token)) ? token + idx : NULL;
    while (skip > 0 && token != NULL)
    {
        token = strpbrk(token, tokenSep);
        if (token != NULL)
        {
            idx = (unsigned int)strspn(token, tokenSep);
            token = (idx < (unsigned int)strlen(token)) ? token + idx : NULL;
        }
        skip--;
    }
    return token;
}


// FUNCTION SuperApplicationClientNewClient
// PURPOSE  Create a new SuperApplication client data structure
// Parameters:
//  node:   Node pointer
static SuperApplicationData* SuperApplicationClientNewClient(Node* node) {
    SuperApplicationData* clientPtr;
    clientPtr = new SuperApplicationData;
    //clientPtr = (SuperApplicationData*) MEM_malloc(sizeof(SuperApplicationData));

    // Set connectionId and other fields to 0
    //memset(clientPtr, 0, sizeof(SuperApplicationData));

    // Initialize the client
    clientPtr->clientAddr = MAPPING_GetDefaultInterfaceAddressFromNodeId
                            (node,node->nodeId);
    clientPtr->serverAddr = 0;
    clientPtr->sessionStart = 0;
    clientPtr->sessionFinish = 0;
    clientPtr->totalReqPacketsToSend = 0;
    clientPtr->randomReqSize.setDistributionNull();
    clientPtr->randomReqInterval.setDistributionNull();
    clientPtr->sourcePort = 0;
    // Use well known port for server by default
    clientPtr->destinationPort = APP_SUPERAPPLICATION_SERVER;
    clientPtr->connectionId = 0;
    clientPtr->uniqueId = node->appData.uniqueId++;
    clientPtr->sessionId = clientPtr->uniqueId;
    clientPtr->isClosed = FALSE;
    // Set State values
    clientPtr->waitingForReply = FALSE;
    clientPtr->processReply = FALSE;
    clientPtr->seqNo = 0;
    clientPtr->repSeqNo = 0;

    clientPtr->fragmentationEnabled = FALSE;
    // Set default values
    clientPtr->reqTOS = APP_DEFAULT_TOS;
    clientPtr->waitTillReply = FALSE;
    //strcpy(clientPtr->applicationName,"SuperApplication-Client");
    clientPtr->fragmentationSize = APP_MAX_DATA_SIZE;

    // for voice session
    clientPtr->isTalking = FALSE;
    clientPtr->isVoice = FALSE;
    clientPtr->isVideo = FALSE;
    clientPtr->isJustMyTurnToTalk = TRUE;
    clientPtr->averageTalkTime = 0;
    clientPtr->talkTime = 0;
    clientPtr->firstTalkTime = 0;
    clientPtr->talkTimeOut = NULL;
    clientPtr->randomAverageTalkTime.setDistributionNull();

    // for conditions
    clientPtr->isConditions = FALSE;

    clientPtr->repFragNo = 0;

    // Initialize all the values in SuperApplicationData
    clientPtr->state = 0;
    clientPtr->protocol = 0;
    clientPtr->transportLayer = 0;
    clientPtr->fragNo = 0;
    clientPtr->uniqueFragNo = 0;
    clientPtr->lastReqInterArrivalInterval = 0;
    clientPtr->lastReqPacketReceptionTime = 0;
    clientPtr->totalReqJitter = 0;
    clientPtr->totalReqJitterPacket = 0;
    clientPtr->randomRepSize.setDistributionNull();
    clientPtr->randomRepInterval.setDistributionNull();
    clientPtr->randomRepInterDepartureDelay.setDistributionNull();
    clientPtr->gotLastReqPacket = FALSE;
    clientPtr->repTOS = 0;
    clientPtr->randomRepPacketsToSendPerReq.setDistributionNull();
    clientPtr->lastRepInterArrivalInterval = 0;
    clientPtr->appFileIndex = 0;
    clientPtr->bufferSize = 0;
    clientPtr->buffer = NULL;
    clientPtr->fragmentBufferSize = 0;
    clientPtr->fragmentBuffer = NULL;
    clientPtr->waitFragments = 0;
    clientPtr->lastReqFragSentTime = 0;
    clientPtr->lastRepFragSentTime = 0;
    clientPtr->firstRepFragRcvTime = 0;
    clientPtr->lastRepFragRcvTime = 0;
    clientPtr->firstReqFragRcvTime = 0;
    clientPtr->lastReqFragRcvTime = 0;
    clientPtr->totalJitterForRep = 0;
    clientPtr->totalJitterForReq = 0;
    clientPtr->actJitterForRep = 0;
    clientPtr->actJitterForReq = 0;
    clientPtr->totalEndToEndDelayForRep = 0;
    clientPtr->totalEndToEndDelayForReq = 0;
    clientPtr->firstRepFragSentTime = 0;
    clientPtr->firstReqFragSentTime = 0;
    clientPtr->firstRepPacketRcvTime = 0;
    clientPtr->firstReqPacketRcvTime = 0;
    clientPtr->lastRepPacketRcvTime = 0;
    clientPtr->lastReqPacketRcvTime = 0;
    clientPtr->totalJitterForReqPacket = 0;
    clientPtr->totalJitterForRepPacket = 0;
    clientPtr->actJitterForReqPacket = 0;
    clientPtr->actJitterForRepPacket = 0;
    clientPtr->lastReqInterArrivalIntervalPacket = 0;
    clientPtr->lastRepInterArrivalIntervalPacket = 0;
    clientPtr->packetSentTime = 0;
    clientPtr->totalEndToEndDelayForReqPacket = 0;
    clientPtr->totalEndToEndDelayForRepPacket = 0;
    clientPtr->firstReqPacketSentTime = 0;
    clientPtr->lastReqPacketSentTime = 0;
    clientPtr->maxEndToEndDelayForReqPacket = 0;
    clientPtr->minEndToEndDelayForReqPacket = 0;
    clientPtr->totalEndToEndDelayForReqPacketDP = 0;
    clientPtr->maxEndToEndDelayForReqPacketDP = 0;
    clientPtr->minEndToEndDelayForReqPacketDP = 0;
    clientPtr->groupLeavingTime = 0;
    clientPtr->timeSpentOutofGroup = 0;
    clientPtr->initStats = 0;
    clientPtr->printStats = 0;

    clientPtr->isTriggered = FALSE;
    clientPtr->isChainId = FALSE;
    clientPtr->readyToSend = FALSE;

    clientPtr->isMdpEnabled = FALSE;
    clientPtr->isProfileNameSet = FALSE;
    strcpy(clientPtr->profileName,"\0");
    clientPtr->mdpUniqueId = -1; //Invalid value

    clientPtr->connRetryLimit =
                SUPERAPPLICATION_DEFAULT_TCP_CONNECTION_RETRY_LIMIT;
    clientPtr->connRetryInterval =
                SUPERAPPLICATION_DEFAULT_TCP_CONNECTION_RETRY_INTERVAL;
    clientPtr->connRetryCount = 0;

#ifdef ADDON_BOEINGFCS
    clientPtr->cpuTimingStarted = FALSE;
    clientPtr->cpuTimeStart = 0;
    clientPtr->lastCpuTime = 0;
    clientPtr->cpuTimingInterval = 0;
    clientPtr->realTimeOutput = FALSE;
    clientPtr->printRealTimeStats = TRUE;
    clientPtr->randomBurstyTimer.setDistributionNull();
    clientPtr->maxEndToEndDelayForReq = 0;
    clientPtr->minEndToEndDelayForReq = 0;
    clientPtr->delayRealTimeProcessing = 0;
    clientPtr->totalJitterForReqDP = 0;
    clientPtr->totalJitterForReqPacketDP = 0;
    clientPtr->actJitterForReqDP = 0;
    clientPtr->actJitterForReqPacketDP = 0;
    clientPtr->lastReqFragRcvTimeDP = 0;
    clientPtr->lastReqPacketRcvTimeDP = 0;
    clientPtr->lastReqInterArrivalIntervalDP = 0;
    clientPtr->lastReqInterArrivalIntervalPacketDP = 0;
    clientPtr->totalEndToEndDelayForReqDP = 0;
    clientPtr->maxEndToEndDelayForReqDP = 0;
    clientPtr->minEndToEndDelayForReqDP = 0;
    clientPtr->requiredDelay = 0;
    clientPtr->requiredTput = 0;

    clientPtr->burstyTimer = 0;
    clientPtr->burstyLow = 0;
    clientPtr->burstyMedium = 0;
    clientPtr->burstyHigh = 0;
    clientPtr->burstyInterval = 0;
#endif /* ADDON_BOEINGFCS */
#ifdef ADDON_DB
    clientPtr->sessionInitiator = node->nodeId;
    clientPtr->msgSeqCache = NULL;
    clientPtr->fragSeqCache = NULL;
    clientPtr->prevMsg = NULL;
    clientPtr->prevMsgSize = 0;
    clientPtr->prevMsgRecvdComplete = FALSE;
#endif

    clientPtr->stats.appStats = NULL;
    // dynamic addressing
    clientPtr->clientNodeId = ANY_NODEID;
    clientPtr->destNodeId = ANY_NODEID;
    clientPtr->clientInterfaceIndex = ANY_INTERFACE;
    clientPtr->destInterfaceIndex = ANY_INTERFACE;
    clientPtr->serverUrl = new std::string();
    clientPtr->serverUrl->clear();
    return clientPtr;
}


// FUNCTION SuperApplicationClientInit
// PURPOSE  Init client. Read in the properties.
// Parameters:
//  node:   Node pointer
//  inputString:    Input string containing user specified application configuration properties
//  clientPtr:  Pointer to the client state structure.
//  serverAddr:  Address of the sever.
//  mdpUniqueId:  Mdp session unique Id.
static void SuperApplicationClientInit(Node* node,
                                       char* inputString,
                                       SuperApplicationData* clientPtr,
                                       NodeAddress clientAddr,
                                       NodeAddress serverAddr,
                                       Int32 mdpUniqueId = -1) {

#ifdef ADDON_BOEINGFCS
    char err[MAX_STRING_LENGTH];
    BOOL burstyKeywordFound = FALSE;
    clientPtr->isBursty = FALSE;
#endif

    char appStr[MAX_STRING_LENGTH];
    char keywordValue[MAX_STRING_LENGTH];
    char keywordValue2[MAX_STRING_LENGTH];
    char* tokenStr = NULL;
    int nToken;
    BOOL issessionStart = FALSE;
    BOOL isDuration = FALSE;
    BOOL isDeliveryType = FALSE;
    BOOL isReqNum = FALSE;
    BOOL isReqInt = FALSE;
    BOOL isReqSize = FALSE;
    BOOL isSourcePort = FALSE;
    BOOL isFragmentSize = FALSE;
#ifdef ADDON_BOEINGFCS
    BOOL isReqTput  = FALSE;
    BOOL isReqDelay = FALSE;
#endif
    BOOL isChainID = FALSE;
    RandomDistribution<clocktype> randomsessionStart;
    RandomDistribution<clocktype> randomReqNum;
    RandomDistribution<clocktype> randomDuration;
    RandomDistribution<clocktype> randomInterval;
    char sourceString[MAX_STRING_LENGTH];
    char destString[MAX_STRING_LENGTH];
    char keyword[MAX_STRING_LENGTH];
    // for new addons
    BOOL newSyntax = FALSE;
    BOOL isDataRate = FALSE;
    BOOL isAverageTalkTime = FALSE;
    BOOL isCondition = FALSE;
    BOOL isSlientGap = FALSE;

    double dataRate = 0.0;

    VideoEncodingScheme videoCodec[] =
        {
            {"H.261", "DET 160", "DET 20MS"},     // p X 64kbit/s where p is range from 1 to 30 in here p = 1
            {"H.263", "DET 160", "DET 20MS"},     // 64kbit/s
            {"MPEG1.M", "DET 2500", "DET 20MS"},  // 1Mbit/s
            {"MPEG1.H", "DET 7500", "DET 20MS"},  // 3Mbit/s
            {"MPEG2.M", "DET 12500", "DET 20MS"}, // 5Mbit/s
            {"MPEG2.H", "DET 37500", "DET 20MS"}  // 15Mbit/s
        };

    VoiceEncodingScheme voiceCodec[] =
        {
            {"G.711", "DET 160", "DET 20MS"},
            {"G.729", "DET 20", "DET 20MS"},
            {"G.723.lar6.3", "DET 23", "DET 30MS"},
            {"G.723.lar5.3", "DET 20", "DET 30MS"},
            {"G.726ar32", "DET 80", "DET 20MS"},
            {"G.726ar24", "DET 60", "DET 20MS"},
            {"G.728ar16", "DET 40", "DET 30MS"},
            {"CELP", "DET 18", "DET 30MS"},
            {"MELP", "DET 8", "DET 22.5MS"}
        };

    // Read in the client properties
    tokenStr = inputString;
    nToken = sscanf(tokenStr, "%s %s %s",
                    appStr, sourceString, destString);

   clientPtr->clientAddr = clientAddr;
   clientPtr->serverAddr = serverAddr;

#ifdef ADDON_DB
    // dns
    if (serverAddr == ANY_ADDRESS || serverAddr == 0 ||
        NetworkIpIsMulticastAddress(node, serverAddr))
    {
        clientPtr->receiverId = 0;
    }
    else
    {
        clientPtr->receiverId =
            MAPPING_GetNodeIdFromInterfaceAddress(node, serverAddr);
    }
#endif // ADDON_DB

    if (nToken != 3)
    {
        ERROR_ReportError("SuperApplication: Src or Dst value not specified.");
    }
    // Advance input string by 2 segments
    tokenStr = SuperApplicationDataSkipToken(
                   tokenStr,
                   SUPERAPPLICATION_TOKENSEP,
                   nToken);
    sprintf(clientPtr->applicationName,"SuperApplication-%d-%d",
            node->nodeId,
            clientPtr->uniqueId);
    strcpy(clientPtr->printName, "SuperApplication");

    while (tokenStr != NULL)
    {
        // Read keyword
        nToken = sscanf(tokenStr, "%s", keyword);
        // Advance input string by 1
        tokenStr = SuperApplicationDataSkipToken(
                       tokenStr,
                       SUPERAPPLICATION_TOKENSEP,
                       nToken);
        if (strcmp(keyword,"REQUEST-NUM")== 0)
        {
            randomReqNum.setSeed(node->globalSeed,
                                 node->nodeId,
                                 APP_SUPERAPPLICATION_CLIENT,
                                 clientPtr->uniqueId);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomReqNum.setDistribution(tokenStr, "SuperApplication", RANDOM_INT);

            if (clientPtr->isVoice == FALSE && clientPtr->isVideo == FALSE) {
                clientPtr->totalReqPacketsToSend =
                    (UInt32) randomReqNum.getRandomNumber();
            }
            isReqNum = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REQUEST-SIZE")==0)
        {
            if (clientPtr->isVoice == FALSE && clientPtr->isVideo == FALSE) {
                clientPtr->randomReqSize.setSeed(node->globalSeed,
                                                 node->nodeId,
                                                 APP_SUPERAPPLICATION_CLIENT,
                                                 clientPtr->uniqueId);
                SuperAppCheckDistributionType(keyword, tokenStr);
                nToken = clientPtr->randomReqSize.setDistribution(tokenStr, "Superapplication", RANDOM_INT);
            }
            isReqSize = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REQUEST-INTERVAL")==0)
        {
            if (clientPtr->isVoice == FALSE && clientPtr->isVideo == FALSE)
            {
                clientPtr->randomReqInterval.setSeed(node->globalSeed,
                                                     node->nodeId,
                                                     APP_SUPERAPPLICATION_CLIENT,
                                                     clientPtr->uniqueId);
                SuperAppCheckDistributionType(keyword, tokenStr);
                nToken = clientPtr->randomReqInterval.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            }
            isReqInt = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REQUEST-DATA-RATE") == 0)
        {
            if (clientPtr->isVoice == FALSE && clientPtr->isVideo == FALSE) {
                nToken = sscanf(tokenStr, "%lf", &dataRate);
                newSyntax = TRUE;
                isDataRate = TRUE;

                tokenStr = SuperApplicationDataSkipToken(
                               tokenStr,
                               SUPERAPPLICATION_TOKENSEP,
                               nToken);
            }
        }
        else if (strcmp(keyword,"START-TIME")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            randomsessionStart.setSeed(node->globalSeed,
                                       node->nodeId,
                                       APP_SUPERAPPLICATION_CLIENT,
                                       clientPtr->uniqueId);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomsessionStart.setDistribution(
                            tokenStr, "Superapplication", RANDOM_CLOCKTYPE);

            issessionStart = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"DURATION")==0)
        {
            randomDuration.setSeed(node->globalSeed,
                                   node->nodeId,
                                   APP_SUPERAPPLICATION_CLIENT,
                                   clientPtr->uniqueId);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomDuration.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            isDuration = TRUE; // User specifed duration
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"CONNECTION-RETRY")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
               tokenStr,
               SUPERAPPLICATION_TOKENSEP,
               nToken);
            if (atoi(keywordValue))
            {
                clientPtr->connRetryLimit = (int)atoi(keywordValue);
            }
            else
            {
                if (strcmp(keywordValue, "0"))
                {
                    ERROR_ReportError("SuperApplication: For Parameter "
                    "CONNECTION-RETRY, max-retry is not valid value\n");
                }
            }
            randomInterval.setSeed(node->globalSeed,
                                   node->nodeId,
                                   APP_SUPERAPPLICATION_CLIENT,
                                   clientPtr->uniqueId);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomInterval.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            clientPtr->connRetryInterval = randomInterval.getRandomNumber();

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REQUEST-TOS")==0)
        {
            unsigned tos = APP_DEFAULT_TOS;
            nToken = sscanf(tokenStr, "%s %s", keywordValue, keywordValue2);

            if (!APP_AssignTos(keywordValue, keywordValue2, &tos))
            {
                ERROR_ReportError("SuperApplication: Unable to get equivalent"
                    "8-bit Req TOS value\n");
            }
            clientPtr->reqTOS = (unsigned char)tos;

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"WAIT-TILL-REPLY")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if (strcmp(keywordValue,"YES")==0)
            {
                clientPtr->waitTillReply = TRUE;
            }
            else if (strcmp(keywordValue,"NO")==0)
            {
                clientPtr->waitTillReply = FALSE;
            }
            else
            {
                ERROR_ReportError("SuperApplication: Unknown WAIT-TILL-REPLY"
                    " value ");
            }
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REPLY-PROCESS") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if ((strcmp(keywordValue, "YES") == 0) ||
                (strcmp(keywordValue, "yes") == 0) ||
                (strcmp(keywordValue, "Yes") == 0) ||
                (strcmp(keywordValue, "y") == 0)   ||
                (strcmp(keywordValue, "Y") == 0))
            {
                clientPtr->processReply = TRUE;
            }
            else if ((strcmp(keywordValue, "NO") == 0) ||
                     (strcmp(keywordValue, "no") == 0) ||
                     (strcmp(keywordValue, "N")  == 0) ||
                     (strcmp(keywordValue, "No") == 0))
            {
                clientPtr->processReply = FALSE;
            }
            else
            {
                ERROR_ReportError("SuperApplication: Invalid value for "
                    "Reply-Process.");
            }
        }
        else if (strcmp(keyword,"DELIVERY-TYPE")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if (clientPtr->isVoice == FALSE && clientPtr->isVideo == FALSE) {
                // Set the transport layer protcol.
                // More protocols may be added here.
                if (strcmp(keywordValue,"RELIABLE") == 0)
                    clientPtr->transportLayer = SUPERAPPLICATION_TCP;
                else if (strcmp(keywordValue,"UNRELIABLE") == 0)
                    clientPtr->transportLayer = SUPERAPPLICATION_UDP;
                else
                {
                    ERROR_ReportError("SuperApplication: Unknown DELIVERY-TYPE.");
                }
            }
            isDeliveryType=TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"APPLICATION-NAME")==0)
        {
            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", keywordValue);
                //strcat(keywordValue,"-CLIENT");
                strcpy(clientPtr->applicationName, keywordValue);
                tokenStr = SuperApplicationDataSkipToken(
                               tokenStr,
                               SUPERAPPLICATION_TOKENSEP,
                               nToken);
            }
            strcpy(clientPtr->printName, clientPtr->applicationName);
        }
        else if (strcmp(keyword,"SOURCE-PORT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            clientPtr->sourcePort = (short)atoi(keywordValue);
            isSourcePort = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        if (strcmp(keyword,"DESTINATION-PORT") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            clientPtr->destinationPort = (short)atoi(keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"FRAGMENT-SIZE")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            isFragmentSize = TRUE;
            clientPtr->fragmentationSize =
                (unsigned short) atoi(keywordValue);
            clientPtr->fragmentationEnabled = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
#ifdef ADDON_BOEINGFCS
        else if (strcmp(keyword, "REQUIRED-TPUT") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            isReqTput  = TRUE;
            clientPtr->requiredTput= atoi(keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REQUIRED-DELAY") == 0)
        {
            char paramStr0[MAX_STRING_LENGTH];
            nToken = sscanf(tokenStr, "%s", paramStr0);
            if (nToken != 1)
            {
                SuperApplicationDataPrintUsageAndQuit();
            }
            clientPtr->requiredDelay = (TRUE) ? (clocktype)TIME_ConvertToClock(paramStr0)
                                       : (clocktype)atol(paramStr0);


            char timex[MAX_STRING_LENGTH];
            TIME_PrintClockInSecond(clientPtr->requiredDelay, timex);
            //printf("Set required delay to %s\n", timex);
            isReqDelay  = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
#endif

#ifdef ADDON_BOEINGFCS
        else if (strcmp(keyword,"REAL-TIME-OUTPUT") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if (strcmp(keywordValue, "YES") == 0)
            {
                clientPtr->realTimeOutput = TRUE;
                //printf("RT output\n");
            }
            else if (strcmp(keywordValue, "NO") == 0)
            {
                clientPtr->realTimeOutput = FALSE;
                //printf("No RT output\n");
            }
            else
            {
                sprintf(err, "Unknown REAL-TIME-OUTPUT value \"%s\"",
                        tokenStr);
                ERROR_ReportWarning(err);
            }
        }
        else if (strcmp(keyword,"PRINT-REAL-TIME-STATS") == 0)
        {
            if (strcmp(tokenStr, "YES") == 0)
            {
                clientPtr->printRealTimeStats = TRUE;
            }
            else if (strcmp(tokenStr, "NO") == 0)
            {
                clientPtr->printRealTimeStats = FALSE;
            }
            else
            {
                sprintf(err, "Unknown PRINT-REAL-TIME-STATS value \"%s\"",
                        tokenStr);
                ERROR_ReportWarning(err);
            }
        }
        else if (strcmp(keyword,"BURSTY") == 0)
        {
            char intervalParam[MAX_STRING_LENGTH];
            char param1[MAX_STRING_LENGTH];
            char param2[MAX_STRING_LENGTH];
            char param3[MAX_STRING_LENGTH];

            clientPtr->randomBurstyTimer.setSeed(node->globalSeed,
                                                 node->nodeId,
                                                 APP_SUPERAPPLICATION_CLIENT);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = clientPtr->randomBurstyTimer.setDistribution(tokenStr, "SuperApplication", RANDOM_CLOCKTYPE);

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);

            nToken = sscanf(tokenStr, "%s %s %s",
                            param1, param2, param3);

            clientPtr->isBursty = TRUE;
            clientPtr->burstyLow = TIME_ConvertToClock(param1);
            clientPtr->burstyMedium = TIME_ConvertToClock(param2);
            clientPtr->burstyHigh = TIME_ConvertToClock(param3);

            clientPtr->burstyInterval = clientPtr->burstyLow;
            burstyKeywordFound = TRUE;

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
#endif /* ADDON_BOEINGFCS */

        else if (strcmp(keyword, "CONDITIONS") == 0)
        {
            nToken = SuperApplicationInsertClientCondition(node,
                     clientPtr,
                     tokenStr);

            isCondition = TRUE;

            tokenStr = SuperApplicationDataSkipToken(tokenStr,
                       SUPERAPPLICATION_TOKENSEP,
                       nToken);

        }
        else if (strcmp(keyword,"CHAIN-ID")==0)
        {
            nToken = sscanf(tokenStr, "%s", clientPtr->chainID);
            isChainID = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "ENCODING-SCHEME") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);

            if (strcmp(keywordValue, "VOICE") == 0) {
                char codecScheme[MAX_STRING_LENGTH]="";
                int index = 0;
                int upperIndex = sizeof(voiceCodec)/sizeof(VoiceEncodingScheme);
                BOOL isCodecFound = FALSE;
                nToken = sscanf(tokenStr, "%s", codecScheme);

                // searching for codec
                for (index = 0; index < upperIndex; index++) {
                    if (strcmp (voiceCodec[index].codeScheme, codecScheme) == 0) {
                        // video traffic only support using UDP
                        // set the transport layer protocol
                        clientPtr->transportLayer = SUPERAPPLICATION_UDP;
                        // inserting the request number
                        clientPtr->totalReqPacketsToSend = 0;

                        clientPtr->randomReqSize.setDistribution(voiceCodec[index].packetSize,
                                "Superapplication", RANDOM_INT);

                        clientPtr->randomReqInterval.setDistribution(voiceCodec[index].packetInterval,
                                "Superapplication", RANDOM_CLOCKTYPE);

                        isCodecFound = TRUE;
                        clientPtr->isVoice = TRUE;
                        break;
                    }
                }
                if (isCodecFound == FALSE) {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,"Voice Codec error:  CES doesn't support "
                        "%s codec\n", codecScheme);
                    ERROR_ReportError(errStr);
                }
            }
            else if (strcmp(keywordValue, "VIDEO")==0){
                char codecScheme[MAX_STRING_LENGTH]="";
                int index = 0;
                int upperIndex = sizeof(videoCodec)/sizeof(VideoEncodingScheme);
                BOOL isCodecFound = FALSE;
                nToken = sscanf(tokenStr, "%s", codecScheme);
                // searching for codec
                for (index = 0; index < upperIndex; index++){
                    if (strcmp (videoCodec[index].codeScheme, codecScheme) ==0){
                        // video traffic only support using UDP
                        // set the transport layer protocol
                        clientPtr->transportLayer = SUPERAPPLICATION_UDP;
                        // inserting the request number
                        clientPtr->totalReqPacketsToSend = 0;

                        // inserting the request size
                        clientPtr->randomReqSize.setDistribution(videoCodec[index].packetSize,
                                "Superapplication", RANDOM_INT);

                        // inserting the request interval
                        clientPtr->randomReqInterval.setDistribution(videoCodec[index].packetInterval,
                                "Superapplication", RANDOM_CLOCKTYPE);

                        isCodecFound = TRUE;
                        clientPtr->isVideo = TRUE;
                        break;
                    }
                }
                if (isCodecFound == FALSE) {
                    char errStr[MAX_STRING_LENGTH];
                    sprintf(errStr,"Video Codec error:  CES doesn't support "
                        "%s codec\n", codecScheme);
                    ERROR_ReportError(errStr);
                }
            }
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "AVERAGE-TALK-TIME") == 0) {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = clientPtr->randomAverageTalkTime.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);

            isAverageTalkTime = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "MEAN-SPURT-GAP-RATIO") == 0) {
            nToken = sscanf(tokenStr, "%f", &clientPtr->gapRatio);
            isSlientGap = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "MDP-ENABLED") == 0) {
            clientPtr->isMdpEnabled = TRUE;
            clientPtr->mdpUniqueId = mdpUniqueId;
        }
        else if (strcmp(keyword,"MDP-PROFILE")==0)
        {
            clientPtr->isProfileNameSet = TRUE;

            if (!tokenStr)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Please specify MDP-PROFILE name.\n");
                ERROR_ReportError(errorString);
            }

            nToken = sscanf(tokenStr, "%s", keywordValue);
            strcpy(clientPtr->profileName,keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
    }//while (tokenStr != NULL)

    //if transport type is not SUPERAPPLICATION_UDP and dest address is not
    // a multicast/unicast address then disable MDP
    if (clientPtr->transportLayer != SUPERAPPLICATION_UDP
        || serverAddr == ANY_ADDRESS)
    {
        clientPtr->isMdpEnabled = FALSE;
        clientPtr->isProfileNameSet = FALSE;
    }
    // Check if all required parameters were specified
    if (newSyntax == FALSE &&
        clientPtr->isVoice == FALSE &&
        clientPtr->isVideo == FALSE &&
        ((issessionStart == FALSE) || (isDuration==FALSE) ||
         (isDeliveryType == FALSE) || (isReqSize == FALSE) ||
         (isReqNum == FALSE) || (isReqInt == FALSE)))
    {
        printf("SuperApplication Client: All required parameters "
               "not specified.\n");
        if (issessionStart == FALSE)  printf("    START-TIME required.\n");
        if (isDuration == FALSE) printf("    DURATION required.\n");
        if (isDeliveryType == FALSE)
            printf("    DELIVERY-TYPE required.\n");
        if (isReqSize == FALSE)
            printf("    REQUEST-SIZE required.\n");
        if (isReqNum == FALSE)
            printf("    REQUEST-NUM required.\n");
        if (isReqInt == FALSE)
            printf("    REQUEST-INTERVAL required.\n");
        ERROR_ReportError("");
    }
    // check if all required parameter were specified for data-rate
    if (newSyntax == TRUE &&
            clientPtr->isVoice == FALSE &&
            clientPtr->isVideo == FALSE)
    {
        if (issessionStart == FALSE) {
            ERROR_ReportError("    START-TIME required.");
        }
        if (isDuration == FALSE) {
            ERROR_ReportError("    DURATION required.");
        }
        if (isDeliveryType == FALSE) {
            ERROR_ReportError("    DELIVERY-TYPE required.");
        }
        if (isReqNum == FALSE) {
            ERROR_ReportError("    REQUEST-NUM required.");
        }
        if (isDataRate == FALSE) {
            ERROR_ReportError("    DATA-RATE required.");
        }
        if (isReqInt == FALSE && isReqSize == FALSE) {
            ERROR_ReportError("    REQUEST-SIZE or REQUEST-INTERVAL required.");
        }
        if (isReqInt == TRUE && isReqSize == TRUE) {
            ERROR_ReportError("    ONLY REQUEST-SIZE or REQUEST-INTERVAL is "
                "required when REQUEST-DATA-RATE is used\n");
        }
        double requestInt = 0.0;
        double requestSize = 0.0;
        char reqinputstring[MAX_STRING_LENGTH]="";

        if (isReqInt == TRUE) {
            requestInt = (int) clientPtr->randomReqInterval.getRandomNumber();
            requestInt = requestInt/1000000000;
            requestSize = dataRate * requestInt;
            sprintf(reqinputstring, "DET %lf", requestSize);

            clientPtr->randomReqSize.setDistribution(reqinputstring, "Superapplication", RANDOM_INT);

        }
        if (isReqSize == TRUE) {
            requestSize = clientPtr->randomReqSize.getRandomNumber();
            requestInt = requestSize / dataRate;
            sprintf(reqinputstring, "DET %lfS", requestInt);

            clientPtr->randomReqInterval.setDistribution(reqinputstring, "Superapplication", RANDOM_CLOCKTYPE);

        }
    }
    // check if all required parameter were specified for voip
    if (clientPtr->isVoice || clientPtr->isVideo) {
        if (issessionStart == FALSE) {
            ERROR_ReportError("    START-TIME required.");
        }
        if (isDuration == FALSE) {
            ERROR_ReportError("    DURATION required.");
        }
        if (isAverageTalkTime == FALSE && clientPtr->isVoice){
            ERROR_ReportError("    AVERAGE-TALK-TIME required for voice sesson.");
        }
        if (isFragmentSize == TRUE){
            ERROR_ReportError("    Fragment not support in VOIP application.");
        }
        if (isDeliveryType == TRUE) {
            printf("    Warning: When using voice/video codec, DeliveryType is set to UDP\n");
        }
        if (isReqInt == TRUE) {
            printf("    Warning: When using voice/video codec, ");
            printf("    request interval is set depending on each voice/video codec\n");
        }
        if (isReqSize == TRUE) {
            printf("    Warning: When using voice/video codec, ");
            printf("    request size is set depending on each voice/video codec\n");
        }
    }
    if (clientPtr->isVoice && isSlientGap == FALSE) {
        clientPtr->gapRatio = (float) VOIP_MEAN_SPURT_GAP_RATIO;
    }

    clientPtr->isConditions = isCondition;
    clientPtr->isChainId = isChainID;

    if (isCondition == TRUE){
        clientPtr->readyToSend = FALSE;
        clientPtr->isConditions = TRUE;
        clientPtr->isTriggered = TRUE;
        clientPtr->sessionStart = randomsessionStart.getRandomNumber();

        SuperAppClientElement client;

        client.clientPtr = clientPtr;
        // for condition, start-time is use for trigger delay
        client.delay = randomsessionStart.getRandomNumber();
        client.isSourcePort = isSourcePort;
        client.randomDuration = randomDuration;
        client.isFragmentSize = isFragmentSize;
#ifdef ADDON_BOEINGFCS
        client.burstyKeywordFound = burstyKeywordFound;
#endif
        SuperAppClientList* clist = (SuperAppClientList*)node->appData.clientPtrList;
        clist->clientList.push_back(client);

        if (SUPERAPPLICATION_DEBUG_CONDITION_STACK){
            SuperApplicationServerPrintClientCondition(node);
        }
    }
    else {
        clientPtr->readyToSend = TRUE;
        //randomsessionStart.setSeed(node->globalSeed);
        clientPtr->sessionStart = randomsessionStart.getRandomNumber();
        clientPtr->sessionStart -= getSimStartTime(node);

        //randomDuration.setSeed(node->globalSeed);
        if (randomDuration.getDistributionType() == DNULL)
        {
            clientPtr->sessionFinish = 0;
        }
        else
        {
            clientPtr->sessionFinish = clientPtr->sessionStart
                                       + randomDuration.getRandomNumber();
        }
        if ((isFragmentSize == TRUE) &&
                (clientPtr->transportLayer == SUPERAPPLICATION_TCP))
        {
            ERROR_ReportError("SuperApplication Client: FRAGMENT-SIZE is not"
                " supported with TCP");
        }

        if (isSourcePort == FALSE)
        {
            // User did not specify source port.
            // Select a free port
            //clientPtr->sourcePort = APP_GetFreePort(node);
            clientPtr->sourcePort = APP_GetFreePortForEachServer(node, clientPtr->serverAddr);
        }
        // Make sure all parameter values are valid
        SuperApplicationClientValidateParam(
            node,
            clientPtr,
            isSourcePort);
        if (SUPERAPPLICATION_DEBUG_PORTS)
        {
            printf (" Client node %d running on port %d \n",
                    node->nodeId,
                    clientPtr->sourcePort);
        }
        // Register the application
        clientPtr->protocol = APP_SUPERAPPLICATION_CLIENT;
        APP_RegisterNewApp(node,
                           APP_SUPERAPPLICATION_CLIENT,
                           clientPtr,
                           clientPtr->sourcePort);
#ifdef ADDON_BOEINGFCS
        if (burstyKeywordFound == TRUE &&
                clientPtr->transportLayer == SUPERAPPLICATION_UDP)
        {
            clocktype rndTimer = 0;
            AppTimer *timer;
            Message *timerMsg;

            timerMsg = MESSAGE_Alloc(node,
                                     APP_LAYER,
                                     APP_SUPERAPPLICATION_CLIENT,
                                     MSG_APP_TimerExpired);

            MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

            timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

            timer->connectionId = 0;
            timer->sourcePort = clientPtr->sourcePort;
            timer->address = clientPtr->serverAddr;
            timer->type = SUPERAPPLICATION_BURSTY_TIMER;

            rndTimer = clientPtr->randomBurstyTimer.getRandomNumber();


            MESSAGE_Send(node,
                         timerMsg,
                         clientPtr->sessionStart + rndTimer);
        }

#endif /* ADDON_BOEINGFCS */
    }
#ifdef HITL_INTERFACE
    if (clientPtr->transportLayer == SUPERAPPLICATION_TCP)
    {
        HITL_TcpSessionKey hitlTcpSessionKey(
                               clientPtr->sourcePort, //src port
                               clientPtr->destinationPort, //dst port
                               clientPtr->clientAddr, //src ip
                               clientPtr->serverAddr); //dst ip
        HITL_AddSuperAppTcpSession(node, //nodeId
                               hitlTcpSessionKey, //session key from above
                               clientPtr->randomReqSize.getRandomNumber()); //msg size
    } else if (clientPtr->transportLayer == SUPERAPPLICATION_UDP)
    {
        // borrowing TCP session key structure
        HITL_TcpSessionKey hitlUdpSessionKey(
                               clientPtr->sourcePort, //src port
                               clientPtr->destinationPort, //dst port
                               clientPtr->clientAddr, //src ip
                               clientPtr->serverAddr); //dst ip
        HITL_AddSuperAppUdpSession(node, //nodeId
                               hitlUdpSessionKey, //session key from above
                               clientPtr->randomReqSize.getRandomNumber()); //msg size
    }
#endif // HITL_INTERFACE
}


// FUNCTION SuperApplicationClientValidateParam
// PURPOSE  Validate the application configuration parameters supplied by the user.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to the client state structure.
//  isSourcePort:   Indicate if user specifed source port number
static
void SuperApplicationClientValidateParam(Node* node,SuperApplicationData* clientPtr,BOOL isSourcePort) {
    // Check to make sure the number of items is a correct value.
    if (clientPtr->totalReqPacketsToSend < 0)
    {
        ERROR_ReportError("SuperApplication: Items to send needs to be >= 0.");
    }
    //clientPtr->randomReqSize.setSeed(node->globalSeed);
    // Check that the item size is  correct value.
    if (clientPtr->randomReqSize.getRandomNumber() <= 0)
    {
        ERROR_ReportError("SuperApplication: Item size needs to be > 0.");
    }
    //clientPtr->randomReqInterval.setSeed(node->globalSeed);
    // Check that the interval is a correct value.
    if (clientPtr->randomReqInterval.getRandomNumber() <= 0)
    {
        ERROR_ReportError("SuperApplication: Request interval needs to be > 0.");
    }
    // Check that start time is < end time.
    if (clientPtr->sessionStart > clientPtr->sessionFinish)
    {
        ERROR_ReportError("SuperApplication: Sesssion start time is greater "
            "than session end time.\n");
    }
    // Check fragmentation unit is correct
    if (((clientPtr->transportLayer == SUPERAPPLICATION_UDP) &&
         (clientPtr->fragmentationSize <=
             (2*sizeof(SuperApplicationUDPDataPacket)))) ||
        (clientPtr->fragmentationSize > APP_MAX_DATA_SIZE) ||
        ((clientPtr->transportLayer == SUPERAPPLICATION_TCP) &&
        (clientPtr->fragmentationSize <=
                sizeof(SuperApplicationTCPDataPacket))))
    {
        // Minimum size for TCP packet
        if (clientPtr->transportLayer == SUPERAPPLICATION_TCP)
            printf("SuperApplication: "
                   " Fragment size should  >= %" TYPES_SIZEOFMFT "u and < %d\n",
                   sizeof(SuperApplicationTCPDataPacket),
                   APP_MAX_DATA_SIZE);
        // Minimum size for UDP packet
        if (clientPtr->transportLayer == SUPERAPPLICATION_UDP)
            printf("SuperApplication: "
                   " Fragment size should  >= %" TYPES_SIZEOFMFT "u and < %d \n",
                   2*sizeof(SuperApplicationUDPDataPacket),
                   APP_MAX_DATA_SIZE);
        printf("APP_MAX_DATA_SIZE is defined in QUALNET_HOME/application/"
               "application.h .\n");
        ERROR_ReportError("");
    }
    if (isSourcePort == TRUE)
    {
        if (APP_IsFreePort(node, clientPtr->sourcePort) == FALSE)
        {
            ERROR_ReportError("SuperApplication: User specified source port "
                "is busy. Possible causes are :\n"
                   "    -Another application may have requested the same "
                   "port. \n"
                   "    -Node is running an application that uses this port "
                   "number as APP_TYPE (Check AppType enumeration in "
                   " QUALNET_HOME\\application\\application.h).");
        }
        if (clientPtr->sourcePort <0)
        {
            ERROR_ReportError("SuperApplication: Source port needs to "
                "be > 0.\n");
        }
    }
}


// FUNCTION SuperApplicationServerValidateParam
// PURPOSE  Validate the application configuration parameters supplied by the user.
// Parameters:
//  node:   Node pointer
//  serverPtr:
//  isDestinationPort:  Indicate if user specifed destination port number
static void SuperApplicationServerValidateParam(Node* node,SuperApplicationData* serverPtr,BOOL isDestinationPort) {
    // Check to make sure the number of items is a correct value.
    serverPtr->randomRepPacketsToSendPerReq.setSeed(node->globalSeed);
    if (serverPtr->randomRepPacketsToSendPerReq.getRandomNumber() < 0)
    {
        ERROR_ReportError("SuperApplication: Reply items to send needs to "
            "be >= 0.\n");
    }
    // Check to make sure the item size is a correct value.
    serverPtr->randomRepSize.setSeed(node->globalSeed);
    if (serverPtr->randomRepSize.getRandomNumber() <= 0)
    {
        ERROR_ReportError("SuperApplication: Reply item size needs to "
            "be > 0.\n");
    }
    // Check to make sure the interval is a correct value.
    serverPtr->randomRepInterval.setSeed(node->globalSeed);
    if (serverPtr->randomRepInterval.getRandomNumber() <= 0)
    {
        ERROR_ReportError("SuperApplication: Reply interval needs to "
            "be > 0.\n");
    }
    // Check to make sure the interval is a correct value.
    serverPtr->randomRepInterDepartureDelay.setSeed(node->globalSeed);
    if (serverPtr->randomRepInterDepartureDelay.getRandomNumber() <= 0)
    {
        ERROR_ReportError("SuperApplication: Reply inter-departure delay "
            "needs to be > 0.\n");
    }
}


// FUNCTION SuperApplicationServerHandleOpenResult_TCP
// PURPOSE  Handle the open result.
// Parameters:
//  node:   Node pointer
//  serverPtr:  Pointer to server state variable
//  msg:    Pointer to the message containing the open result.
static void SuperApplicationServerHandleOpenResult_TCP(Node* node,SuperApplicationData* serverPtr,Message* msg) {
    TransportToAppOpenResult *openResult;
    openResult = (TransportToAppOpenResult *)
                 MESSAGE_ReturnInfo(msg);
    ERROR_Assert(openResult->type == TCP_CONN_PASSIVE_OPEN,
                 "SuperApplication Server: OpenResult->type != "
                 "TCP_CONN_PASSIVE_OPEN");
    if (openResult->connectionId <= 0)
    {
        /* Keep trying until connection is established. */
        if (SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE)
        {
            char clockStr[24];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
            printf("At %s sec, Server (%d:%d) failed to establish"
                   "connection. Received connection id = %d. \n",
                   clockStr,
                   node->nodeId,
                   serverPtr->destinationPort,
                   openResult->connectionId);
        }
        node->appData.numAppTcpFailure++;
    }
    else
    {
        // Update server
        serverPtr->connectionId = openResult->connectionId;
        serverPtr->sourcePort = openResult->remotePort;
        serverPtr->clientAddr = GetIPv4Address(openResult->remoteAddr);
        if (SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE)
        {
            char clockStr[24];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
            printf("At %s sec, Server (%d:%d) established"
                   " connection(PASSIVE_OPEN).Current connection id = %d.\n",
                   clockStr,
                   node->nodeId,
                   serverPtr->destinationPort,
                   openResult->connectionId);
        }
#ifdef ADDON_DB
        STATSDB_HandleSessionDescTableInsert(node,
            openResult->clientUniqueId, //serverPtr->uniqueId,
            serverPtr->clientAddr, serverPtr->serverAddr,
            serverPtr->sourcePort, serverPtr->destinationPort,
            "SUPER-APPLICATION", "TCP");

        // should be recorded at the receiver's side
        STATSDB_HandleAppConnCreation(node, serverPtr->clientAddr,
            serverPtr->serverAddr, openResult->clientUniqueId);

#endif
    }
    // Free the message
    MESSAGE_Free(node, msg);
}


// FUNCTION SuperApplicationClientHandleOpenResult_TCP
// PURPOSE  Handle the open result.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
//  msg:    Pointer to the message containing the open result.
static void SuperApplicationClientHandleOpenResult_TCP(Node* node,SuperApplicationData* clientPtr,Message* msg) {
    TransportToAppOpenResult *openResult;
    openResult = (TransportToAppOpenResult *)
                 MESSAGE_ReturnInfo(msg);
    ERROR_Assert(openResult->type == TCP_CONN_ACTIVE_OPEN,
                 "SuperApplication Client: OpenResult->type != "
                 "TCP_CONN_ACTIVE_OPEN");
    if (openResult->connectionId <= 0)
    {
        /* Keep trying until connection is established. */
        if (SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE)
        {
            char clockStr[24];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
            printf("At %s sec, Client (%d:%d) failed to establish"
                   "connection.Current connection id = %d. Trying again.\n",
                   clockStr,
                   node->nodeId,
                   clientPtr->destinationPort,
                   openResult->connectionId);
        }

        if ((clientPtr->connRetryLimit > clientPtr->connRetryCount) ||
            (clientPtr->connRetryLimit == 0))
        {
            clientPtr->connRetryCount++;
            Address clientAddr;
            clientAddr.networkType = NETWORK_IPV4;
            clientAddr.interfaceAddr.ipv4 = clientPtr->clientAddr;
            Address serverAddr;
            serverAddr.networkType = NETWORK_IPV4;
            serverAddr.interfaceAddr.ipv4 = clientPtr->serverAddr;
            node->appData.appTrafficSender->appTcpOpenConnection(
                                node,
                                APP_SUPERAPPLICATION_CLIENT,
                                clientAddr,
                                clientPtr->sourcePort,
                                serverAddr,
                                clientPtr->destinationPort,
                                clientPtr->uniqueId,
                                clientPtr->reqTOS,
                                ANY_INTERFACE,
                                *clientPtr->serverUrl,
                                clientPtr->connRetryInterval,
                                clientPtr->destNodeId,
                                clientPtr->clientInterfaceIndex,
                                clientPtr->destInterfaceIndex);
            node->appData.numAppTcpFailure++;
        }
    }
    else
    {
        // Update client
        clientPtr->connectionId = openResult->connectionId;
        if (SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE)
        {
            char clockStr[24];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
            printf("At %s sec, Client (%d:%d) established"
                   " connection(ACTIVE_OPEN).Current connection id = %d.\n",
                   clockStr,
                   node->nodeId,
                   clientPtr->destinationPort,
                   openResult->connectionId);
        }
#ifdef ADDON_BOEINGFCS
        // Check if we have bursty option turned on.
        // If yes then set the timer.
        if (clientPtr->isBursty)
        {
            clocktype rndTimer = 0;
            AppTimer *timer;
            Message *timerMsg;

            timerMsg = MESSAGE_Alloc(node,
                                     APP_LAYER,
                                     APP_SUPERAPPLICATION_CLIENT,
                                     MSG_APP_TimerExpired);

            MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

            timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

            timer->connectionId = clientPtr->connectionId;
            timer->sourcePort = 0;
            timer->type = SUPERAPPLICATION_BURSTY_TIMER;

            rndTimer = clientPtr->randomBurstyTimer.getRandomNumber();

            MESSAGE_Send(node,
                         timerMsg,
                         clientPtr->sessionStart + rndTimer);
        }
#endif
        SuperApplicationClientSchedulePacket_TCP(node,clientPtr,0);
    }
    // Free the message
    MESSAGE_Free(node, msg);
}


// FUNCTION SuperApplicationClientOpenConnection_TCP
// PURPOSE  Initialize SuperApplication, with TCP as transport layer.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
static void SuperApplicationClientOpenConnection_TCP(Node* node,SuperApplicationData* clientPtr) {
    char clockStr[24];
    TIME_PrintClockInSecond(clientPtr->sessionStart, clockStr, node);

    Address clientAddr;
    clientAddr.networkType = NETWORK_IPV4;
    clientAddr.interfaceAddr.ipv4 = clientPtr->clientAddr;
    Address serverAddr;
    serverAddr.networkType = NETWORK_IPV4;
    serverAddr.interfaceAddr.ipv4 = clientPtr->serverAddr;
    node->appData.appTrafficSender->appTcpOpenConnection(
                                node,
                                APP_SUPERAPPLICATION_CLIENT,
                                clientAddr,
                                clientPtr->sourcePort,
                                serverAddr,
                                clientPtr->destinationPort,
                                clientPtr->uniqueId,
                                clientPtr->reqTOS,
                                ANY_INTERFACE,
                                *clientPtr->serverUrl,
                                clientPtr->sessionStart,
                                clientPtr->destNodeId,
                                clientPtr->clientInterfaceIndex,
                                clientPtr->destInterfaceIndex);
}


// FUNCTION SuperApplicationClientSchedulePacket_TCP
// PURPOSE  Initialize ( Register and schedule first packet) for SuperApplication, with TCP as transport layer.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
//  interval:   Time interval for the timer
static void SuperApplicationClientSchedulePacket_TCP(Node* node,SuperApplicationData* clientPtr,clocktype interval) {
    AppTimer* timer = NULL;
    Message* timerMsg = NULL;
    // Schedule self timer message to send packet
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_CLIENT,
                             MSG_APP_TimerExpired);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));
    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connectionId (and not source port)
    // when TCP is being used. Designer uses this to distinguish between UDP/TCP
    // in SuperApplicationProcessEvent.
    timer->connectionId = clientPtr->connectionId;
    timer->sourcePort = 0;
    timer->type = APP_TIMER_SEND_PKT;
    SuperApplicationClientScheduleNextPkt(node,clientPtr,interval,timerMsg);
}


// FUNCTION SuperApplicationClientScheduleFirstPacket_UDP
// PURPOSE  Initialize ( Register and schedule first packet) for SuperApplication, with UDP as transport layer.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
static
void SuperApplicationClientScheduleFirstPacket_UDP(Node* node,SuperApplicationData* clientPtr) {
    AppTimer* timer = NULL;
    Message* timerMsg = NULL;
    // Schedule self timer message to send packet
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_CLIENT,
                             MSG_APP_TimerExpired);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));
    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connection id to 0 when UDP is being
    // used. Designer uses this to distinguish between UDP/TCP.
    timer->connectionId = 0;
    timer->sourcePort = clientPtr->sourcePort;
    timer->address = clientPtr->serverAddr;
    timer->type = APP_TIMER_SEND_PKT;
    if (!clientPtr->isTriggered) {
        SuperApplicationClientScheduleNextPkt(node,clientPtr,clientPtr->sessionStart,timerMsg);
    }
    else if (clientPtr->readyToSend) {
        if (SUPERAPPLICATION_DEBUG_TRIGGER_SESSION){
            printf("start trigger session from Node %d to Node %d\n",
                   MAPPING_GetNodeIdFromInterfaceAddress(node, clientPtr->clientAddr),
                   MAPPING_GetNodeIdFromInterfaceAddress(node, clientPtr->serverAddr));
        }
        SuperApplicationClientScheduleNextPkt(node,clientPtr,clientPtr->sessionStart,timerMsg);
    }
}

// FUNCTION SuperApplicationClientScheduleNextVoicePacket_UDP
// PURPOSE  Initialize ( Register and schedule first packet) for SuperApplication, with UDP as transport layer.
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
static
void SuperApplicationClientScheduleNextVoicePacket_UDP(Node* node,SuperApplicationData* clientPtr) {
    AppTimer* timer = NULL;
    Message* timerMsg = NULL;
    clocktype delay = 0;
    // Schedule self timer message to send packet
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_CLIENT,
                             MSG_APP_TimerExpired);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));
    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connection id to 0 when UDP is being
    // used. Designer uses this to distinguish between UDP/TCP.
    timer->connectionId = 0;
    timer->sourcePort = clientPtr->sourcePort;
    timer->address = clientPtr->serverAddr;
    timer->type = APP_TIMER_SEND_PKT;

    SuperApplicationClientScheduleNextPkt(node,clientPtr,delay,timerMsg);
}

// FUNCTION SuperApplicationServerScheduleNextRepPkt_UDP
// PURPOSE  Schedule next reply packet when SuperApplication uses UDP
// Parameters:
//  node:   Node pointer
//  serverPtr:  Pointer to client state variable
//  interval:   Interval after which the packet is to be scheduled
//  msg:    Message pointer
static void SuperApplicationServerScheduleNextRepPkt_UDP(Node* node,SuperApplicationData* serverPtr,clocktype interval,Message* msg) {
    SuperAppTimer* replyPacketTimer;
    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(msg);
    if (serverPtr->isVoice){
        replyPacketTimer->reqSeqNo = serverPtr->seqNo;
    }
    if (SUPERAPPLICATION_DEBUG_TIMER_SET_SERVER)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server scheduling timer for reply packet \n",
               clockStr);
        printf("    Connection :  S(%u:%u)->C(%u,%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("    Reply for  :  packet (%u of %u) for %u req seq no\n",
               replyPacketTimer->numRepSent,
               replyPacketTimer->numRepToSend,
               replyPacketTimer->reqSeqNo);
        TIME_PrintClockInSecond((interval + node->getNodeTime()), clockStr, node);
        printf("    Alarm time :  %s sec\n", clockStr);
        TIME_PrintClockInSecond(interval, clockStr);
        printf("    Interval   :  %s sec\n", clockStr);
    }
    MESSAGE_Send(node, msg, interval);
}


// FUNCTION SuperApplicationClientSendData_TCP
// PURPOSE  Send data and schedule next timer
// Parameters:
//  node:   Pointer to the node structure
//  clientPtr:  Pointer to client state variable
//  msg:    Pointer to message
static void SuperApplicationClientSendData_TCP(Node* node,SuperApplicationData* clientPtr,Message* msg) {
    UInt32 reqSize;
    clocktype reqInterval;
    SuperApplicationTCPDataPacket data;
    char *payload;

    if (clientPtr->isClosed)
    {
        MESSAGE_Free(node, msg);
        return;
    }

    if (SUPERAPPLICATION_DEBUG_TIMER_REC_CLIENT)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client got timer alarm: \n",clockStr);
        printf("    Purpose     : Send request packet\n");
        printf("    Connection  : C(%u:%u)->S(%u,%u)\n",
               node->nodeId,
               clientPtr->sourcePort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clientPtr->serverAddr),
               clientPtr->destinationPort);
        printf("    Req seq no  : %c \n",clientPtr->seqNo);
    }
    // Calculate data request packet length
    //clientPtr->randomReqSize.setSeed(node->globalSeed);
    reqSize = (Int32) clientPtr->randomReqSize.getRandomNumber();

    payload = (char *)MEM_malloc(reqSize);
    memset(payload,0,reqSize);
    // Time for txing next data request
    //clientPtr->randomReqInterval.setSeed(node->globalSeed);
    reqInterval = clientPtr->randomReqInterval.getRandomNumber();
    // Set up data
    data.totalPacketBytes = reqSize;
    data.totalFragmentBytes = reqSize;
    data.appFileIndex = clientPtr->appFileIndex;
    data.seqNo      = clientPtr->seqNo;
    data.totFrag    = 1;
    data.fragNo     = 0;
    data.uniqueFragNo = clientPtr->uniqueFragNo ++;
    data.isLastPacket = FALSE;
    data.txTime     = node->getNodeTime();

    // determine if this packet is the last packet to send.
    if ((clientPtr->stats.numReqPacketsSent + 1 == clientPtr->totalReqPacketsToSend) &&
        (clientPtr->totalReqPacketsToSend > 0) )
    {
        data.isLastPacket = TRUE;
        if (!clientPtr->processReply && node->appData.appStats)
        {
            if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
            {
                if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                {
                    clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                }
            }
            else
            {
                if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                {
                    clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                }
            }
        }
    }

#ifdef ADDON_BOEINGFCS
    data.txRealTime = node->partitionData->wallClock->getRealTime();
    data.txCpuTime = SuperApplicationCpuTime(clientPtr);
    data.txPartitionId = node->partitionId;
#endif /* ADDON_BOEINGFCS */

    // STATS DB CODE
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.m_SessionInitiator = node->nodeId;
    appParam.SetPriority(clientPtr->reqTOS);
    appParam.SetFragNum(data.fragNo);
    appParam.SetSessionId(clientPtr->uniqueId);
    appParam.SetAppType("SUPER-APPLICATION");
    appParam.SetAppName(clientPtr->applicationName);
    appParam.m_ReceiverId = clientPtr->receiverId;
    appParam.SetReceiverAddr(clientPtr->serverAddr);
    appParam.SetMsgSize(reqSize);
    appParam.m_TotalMsgSize = reqSize;
    if (data.totFrag > 1)
    {
        appParam.m_fragEnabled = TRUE;
    }
#endif
    if (SUPERAPPLICATION_DEBUG_REQ_SEND)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client sending request packet of %u byte with"
               "\n",
               clockStr,
               reqSize);
    }

    if (SUPERAPPLICATION_DEBUG_REQ_SEND)
    {
        printf("    Total fragment bytes : %u \n",reqSize);
        printf("    TOS                  : %d \n",clientPtr->reqTOS);
        printf("    Packet seq no.       : %d \n",data.seqNo);
        printf("    Fragment no          : %d \n",data.fragNo);
        printf("    Total fragments      : %d \n",data.totFrag);
        printf(" \n");
    }

#ifdef ADDON_BOEINGFCS
    int numReqPackets = 1;
    if (clientPtr->totalReqPacketsToSend > 0)
    {
        numReqPackets = clientPtr->totalReqPacketsToSend;
    }
    float numBytes = (float) (reqSize * numReqPackets * 8);
    float interval = (float) reqInterval / SECOND;
    float dataRate = (numBytes / interval) / 1000.0;

    Message *tempMsg = APP_TcpCreateMessage(
        node,
        clientPtr->connectionId,
        TRACE_SUPERAPPLICATION,
        clientPtr->reqTOS);

    APP_AddPayload(
        node,
        tempMsg,
        payload,
        reqSize);

    APP_AddInfo(
        node,
        tempMsg,
        &data,
        sizeof(SuperApplicationTCPDataPacket),
        INFO_TYPE_SuperAppTCPData);

    TransportToAppDataReceived appData;
    appData.connectionId = clientPtr->connectionId;
    appData.priority = clientPtr->reqTOS;

    APP_AddInfo(
        node,
        tempMsg,
        &appData,
        sizeof(TransportToAppDataReceived),
        INFO_TYPE_TransportToAppData);

#ifdef ADDON_DB
    node->appData.appTrafficSender->appTcpSend(node, tempMsg, &appParam);
#else
    node->appData.appTrafficSender->appTcpSend(node, tempMsg);
#endif
/**/
#else
    Message *tempMsg = APP_TcpCreateMessage(
        node,
        clientPtr->connectionId,
        TRACE_SUPERAPPLICATION,
        clientPtr->reqTOS);

    APP_AddPayload(
        node,
        tempMsg,
        payload,
        reqSize);

    APP_AddInfo(
        node,
        tempMsg,
        &data,
        sizeof(SuperApplicationTCPDataPacket),
        INFO_TYPE_SuperAppTCPData);

#ifdef ADDON_DB
    node->appData.appTrafficSender->appTcpSend(node, tempMsg, &appParam);
#else
    node->appData.appTrafficSender->appTcpSend(node, tempMsg);
#endif

#endif
    if (node->appData.appStats)
    {
        if (!clientPtr->stats.appStats->IsSessionStarted(STAT_Unicast))
        {
            clientPtr->stats.appStats->SessionStart(node);
        }

        clientPtr->stats.appStats->AddFragmentSentDataPoints(node,
                                                    reqSize,
                                                    STAT_Unicast);
        clientPtr->stats.appStats->AddMessageSentDataPoints(node,
                                                   tempMsg,
                                                   0,
                                                   reqSize,
                                                   0,
                                                   STAT_Unicast);
    }
    clientPtr->waitFragments++;

    // Statistics update
    clientPtr->stats.numReqBytesSent += reqSize;
    clientPtr->stats.numReqFragsSent += 1;

    // Statistics update
    clientPtr->lastReqFragSentTime = node->getNodeTime();
    // 1 Packet is sent when all it's fragments are sent
    clientPtr->stats.numReqPacketsSent += 1;
    // Check if it was the first fragment
    if (clientPtr->stats.numReqPacketsSent == 1)
        clientPtr->firstReqFragSentTime = node->getNodeTime();
    if (clientPtr->lastReqFragSentTime > clientPtr->firstReqFragSentTime)
    {
        clientPtr->stats.reqSentThroughput =  (double)
                                              ((double)(clientPtr->stats.numReqBytesSent * 8.0 * SECOND)
                                               / (clientPtr->lastReqFragSentTime - clientPtr->firstReqFragSentTime));
    }
    // Packet sent so increment sequence number
    clientPtr->seqNo++;
    // add the packet send time
    //clientPtr->packetSentTime = node->getNodeTime();
    // Free the timer message
    MESSAGE_Free(node, msg);
    MEM_free(payload);
}


// FUNCTION SuperApplicationSendMessage_UDP
// PURPOSE  Completes and sends a UDP message that was started by
//          SuperApplicationClientSendMessage_UDP or
//          SuperApplicationServerSendMessage_UDP.
// Parameters:
//  node        : Pointer to the node structure
//  statePtr    : Pointer to state variable, i.e., clientPtr or ServerPtr
//  realPayload : actual payload data; may be NULL if none
//  realSize    : Size of realPayload; may be zero if none
//  virtualSize : Size of virtual payload
//  data        : SuperApplicationUDPDataPacket*
//  fragSize    : fragment size
//  reqSize     : request size in case of client
//
static void
SuperApplicationSendMessage_UDP(
    Node* node,
    Message* msg,
    SuperApplicationData* statePtr,
    char* realPayload,
    int realSize,
    int virtualSize,
    SuperApplicationUDPDataPacket* data,
    Int32 fragSize,
    Int32 reqSize
#ifdef ADDON_DB
    , StatsDBAppEventParam* appParam
#endif
    )

{
    int dataSize = realSize + virtualSize;
#ifdef ADDON_DB
    UInt64 fragSentForThisPacket = 0;
    UInt64 bytesSentForThisPacket = 0;
    UInt64 msgSent = 0;
#endif

    APP_AddPayload(
        node,
        msg,
        realPayload,
        realSize);

    APP_AddVirtualPayload(
        node,
        msg,
        virtualSize);

    APP_AddInfo(
        node,
        msg,
        &dataSize,
        sizeof(int),
        INFO_TYPE_DataSize);

    APP_AddInfo(
        node,
        msg,
        data,
        sizeof(SuperApplicationUDPDataPacket),
        INFO_TYPE_SuperAppUDPData);

    if (statePtr->isMdpEnabled)
    {
        APP_UdpSetMdpEnabled(msg, statePtr->mdpUniqueId);
    }

    // STATS DB CODE.
#ifdef ADDON_DB
    if (appParam != NULL)
    {
        HandleStatsDBAppSendEventsInsertion(node,
            msg,
            dataSize,
            appParam);

        if (strcmp(appParam->m_ApplicationType, "SUPER-APPLICATION") == 0)
        {
            APP_AddInfo(
                node,
                msg,
                &appParam->m_SessionId,
                sizeof(int),
                INFO_TYPE_StatsDbAppSessionId);
        }
    }

    bytesSentForThisPacket = dataSize;
    fragSentForThisPacket = 1;
    if (data->fragNo == data->totFrag - 1)
    {
        msgSent = 1;
    }
#endif

    AppUdpPacketSendingInfo packetSendingInfo;
#ifdef ADDON_DB
    packetSendingInfo.appParam = *appParam;
#endif
    packetSendingInfo.itemSize = reqSize;
    packetSendingInfo.stats = statePtr->stats.appStats;
    if (statePtr->protocol == APP_SUPERAPPLICATION_SERVER)
    {
        packetSendingInfo.fragNo = NO_UDP_FRAG;
        packetSendingInfo.fragSize = 0;
    }
    else
    {
        packetSendingInfo.fragNo = data->fragNo;
        packetSendingInfo.fragSize = fragSize;
    }
    Address localAddress;
    localAddress.networkType = NETWORK_IPV4;
    localAddress.interfaceAddr.ipv4 = statePtr->clientAddr;
    node->appData.appTrafficSender->appUdpSend(
                                        node,
                                        msg,
                                        *statePtr->serverUrl,
                                        localAddress,
                                        APP_SUPERAPPLICATION_CLIENT,
                                        (short)statePtr->sourcePort,
                                        packetSendingInfo);
}

// FUNCTION SuperApplicationClientSendMessage_UDP
// PURPOSE  Creates and sends a Client UDP message
// Parameters:
//  node        : Pointer to the node structure
//  clientPtr   : Pointer to state variable
//  realPayload : Actual payload data; may be NULL if none
//  realSize    : Size of realPayload
//  virtualSize : Size of virtual payload
//  data        : SuperApplicationUDPDataPacket*
//  fragSize    : fragment size
//  reqSize     : request size
//  RETURN      : the sent message
//
static Message*
SuperApplicationClientSendMessage_UDP(
    Node* node,
    SuperApplicationData* clientPtr,
    char* realPayload,
    int realSize,
    int virtualSize,
    SuperApplicationUDPDataPacket* data,
    Int32 fragSize,
    Int32 reqSize
#ifdef ADDON_DB
    , StatsDBAppEventParam* appParam
#endif
    )
{
    Message *msg = APP_UdpCreateMessage(
        node,
        clientPtr->clientAddr,
        (short) clientPtr->sourcePort,
        clientPtr->serverAddr,
        (short) clientPtr->destinationPort,
        TRACE_SUPERAPPLICATION,
        clientPtr->reqTOS);

    APP_AddInfo(
        node,
        msg,
        (char*) &clientPtr->clientAddr,
        sizeof(NodeAddress),
        INFO_TYPE_SourceAddr);

    APP_AddInfo(
        node,
        msg,
        (char*) &clientPtr->serverAddr,
        sizeof(NodeAddress),
        INFO_TYPE_DestAddr);

    APP_AddInfo(
        node,
        msg,
        (char*) &clientPtr->sourcePort,
        sizeof(short),
        INFO_TYPE_SourcePort);

    APP_AddInfo(
        node,
        msg,
        (char*) &clientPtr->destinationPort,
        sizeof(short), 
        INFO_TYPE_DestPort);

    SuperApplicationSendMessage_UDP(
        node,
        msg,
        clientPtr,
        realPayload,
        realSize,
        virtualSize,
        data,
        fragSize,
        reqSize
#ifdef ADDON_DB
        , appParam
#endif
        );

    return msg;
}


// FUNCTION SuperApplicationServerSendMessage_UDP
// PURPOSE  Creates and sends a Server UDP message
// Parameters:
//  node        : Pointer to the node structure
//  serverPtr   : Pointer to state variable
//  realPayload : Actual payload data; may be NULL if none
//  realSize    : Size of realPayload
//  virtualSize : Size of virtual payload
//  data        : SuperApplicationUDPDataPacket*
//  itemSize    : itemSize
//  RETURN      : The sent message
//
static Message*
SuperApplicationServerSendMessage_UDP(
    Node* node,
    SuperApplicationData* serverPtr,
    char* realPayload,
    int realSize,
    int virtualSize,
    SuperApplicationUDPDataPacket* data,
    Int32 itemSize
#ifdef ADDON_DB
    , StatsDBAppEventParam* appParam
#endif
    )
{
    Message *msg = APP_UdpCreateMessage(
        node,
        serverPtr->serverAddr,
        (short) serverPtr->destinationPort,
        serverPtr->clientAddr,
        (short) serverPtr->sourcePort,
        TRACE_SUPERAPPLICATION,
        serverPtr->reqTOS);

    APP_AddInfo(
        node, 
        msg,
        (char*) &serverPtr->serverAddr,
        sizeof(NodeAddress), 
        INFO_TYPE_SourceAddr);        

    APP_AddInfo(
        node, 
        msg,
        (char*) &serverPtr->clientAddr,
        sizeof(NodeAddress), 
        INFO_TYPE_DestAddr);

    APP_AddInfo(
        node, 
        msg,
        (char*) &serverPtr->destinationPort,
        sizeof(short), 
        INFO_TYPE_SourcePort);

    APP_AddInfo(
        node, 
        msg,
        (char*) &serverPtr->sourcePort,
        sizeof(short), 
        INFO_TYPE_DestPort);

    SuperApplicationSendMessage_UDP(
        node,
        msg,
        serverPtr,
        realPayload,
        realSize,
        virtualSize,
        data,
        0,
        itemSize
#ifdef ADDON_DB
        , appParam
#endif
        );

    return msg;
}


// FUNCTION SuperApplicationClientSendData_UDP
// PURPOSE  Send data and schedule next timer
// Parameters:
//  node:   Pointer to the node structure
//  clientPtr:  Pointer to client state variable
//  msg:    Pointer to message
static void SuperApplicationClientSendData_UDP(Node* node,SuperApplicationData* clientPtr,Message* msg) {
    UInt32 reqSize;
    Int32 fragSize;
    Int32 virtualPayload;
    float maxFragmentSize;
    clocktype reqInterval;
    SuperApplicationUDPDataPacket data;
    char *payload = NULL;
    char dataType = 'm';
    BOOL isMyTurnToTalk = FALSE;

    //init the SuperApplicationUDPDataPacket
    memset(&data, 0, sizeof(data));

    // check if it is the first conversation.
    if ((clientPtr->isVoice) && (clientPtr->isJustMyTurnToTalk))
    {
        clientPtr->averageTalkTime = clientPtr->randomAverageTalkTime.getRandomNumber();
        clientPtr->talkTime = (clocktype) (clientPtr->averageTalkTime * clientPtr->gapRatio);

        // add min talk time
        if (clientPtr->talkTime < MIN_TALK_TIME) {
            char errorStr[MAX_STRING_LENGTH] = "";
            sprintf(errorStr, "MIN-TALK-TIME for voice application is 1 second.  Change talkTime to 1 second.\n");
            ERROR_ReportWarning(errorStr);
            clientPtr->talkTime = MIN_TALK_TIME;
        }
        // end min talk time

        if (SUPERAPPLICATION_DEBUG_VOICE){
            char clockStr[24];
            char talkTimeStr[24];
            TIME_PrintClockInSecond (clientPtr->talkTime, talkTimeStr);
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : C(%u:%u)->S(%u:%u)\n",
                   node->nodeId,
                   clientPtr->sourcePort,
                   MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                         clientPtr->serverAddr),
                   clientPtr->destinationPort);
            printf("    At %s sec, Turn for client to talk:\n", clockStr);
            printf("    Talk Time for this turn is %s sec:\n", talkTimeStr);
        }

        clientPtr->isJustMyTurnToTalk = FALSE;
        clientPtr->isTalking = TRUE;
        clientPtr->firstTalkTime = node->getNodeTime();
    }

    if (SUPERAPPLICATION_DEBUG_TIMER_REC_CLIENT)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client got timer alarm: \n",clockStr);
        printf("    Purpose     : Send request packet\n");
        printf("    Connection  : C(%u:%u)->S(%u,%u)\n",
               node->nodeId,
               clientPtr->sourcePort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clientPtr->serverAddr),
               clientPtr->destinationPort);
        printf("    Req seq no  : %d \n",clientPtr->seqNo);
    }
    // Calculate data request packet length
    //clientPtr->randomReqSize.setSeed(node->globalSeed);
    reqSize = (Int32) clientPtr->randomReqSize.getRandomNumber();
    // Time for txing next data request
    //clientPtr->randomReqInterval.setSeed(node->globalSeed);
    reqInterval = clientPtr->randomReqInterval.getRandomNumber();

    // Calculate which type of data packet to send for voip session
    if (clientPtr->isVoice == TRUE){
        isMyTurnToTalk = SuperAppVoiceStartTalking(node,
                         clientPtr,
                         &dataType,
                         reqInterval);
        if (SUPERAPPLICATION_DEBUG_VOICE_SEND){
            char clockStr[24];
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : C(%u:%u)->S(%u:%u)\n",
                   node->nodeId,
                   clientPtr->sourcePort,
                   MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                         clientPtr->serverAddr),
                   clientPtr->destinationPort);
            printf("    At %s sec, Client send voice packet:\n", clockStr);
            printf("    Voice Packet type is: %c\n", dataType);
        }
        if (dataType == 'o'){
            clientPtr->state = SUPERAPPLICATION_CLIENTIDLE_UDP;
            clientPtr->isTalking = FALSE;
            SuperApplicationClientScheduleTalkTimeOut(node, clientPtr);
        }
    }

    // Convert to float for division
    maxFragmentSize = clientPtr->fragmentationSize;

    // Set up data
    data.txTime     = node->getNodeTime();
    if (clientPtr->isTriggered) {
        data.triggerDelay = clientPtr->sessionStart;
    }
    else {
        data.triggerDelay = 0;
    }
    data.seqNo      = clientPtr->seqNo;
    if (reqSize > maxFragmentSize)
    {
        data.totFrag    = (int)ceil(reqSize / maxFragmentSize);
    }
    else
    {
        data.totFrag = 1;
    }
    data.fragNo     = 0;
    data.uniqueFragNo = clientPtr->uniqueFragNo ++;
    data.appFileIndex = clientPtr->appFileIndex;
    data.sessionId = clientPtr->uniqueId;
    data.totalMessageSize = reqSize;
    data.isMdpEnabled = clientPtr->isMdpEnabled;
    data.isLastPacket = FALSE;

    // Check for sending last packet, or last packet sent within session finish
    if (((clientPtr->stats.numReqPacketsSent + 1 == 
               clientPtr->totalReqPacketsToSend) &&
        (clientPtr->totalReqPacketsToSend > 0)) ||
        // Session is over
        ((clientPtr->sessionFinish != clientPtr->sessionStart)
         && (node->getNodeTime() + reqInterval >= clientPtr->sessionFinish)))
    {
        data.isLastPacket = TRUE;
        if (!clientPtr->processReply && node->appData.appStats &&
            clientPtr->stats.appStats)
        {
            if (NetworkIpIsMulticastAddress(node,clientPtr->serverAddr))
            {
                clientPtr->stats.appStats->SessionFinish(node,STAT_Multicast);
            }
            else
            {
                clientPtr->stats.appStats->SessionFinish(node,STAT_Unicast);
            }
        }
    }

#ifdef ADDON_BOEINGFCS
    data.txRealTime = node->partitionData->wallClock->getRealTime();
    data.txCpuTime = SuperApplicationCpuTime(clientPtr);
    data.txPartitionId = node->partitionId;
#endif /* ADDON_BOEINGFCS */

    // Application layer fragmentation
    if (SUPERAPPLICATION_DEBUG_REQ_SEND)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client sending request packet of %u byte with"
               "\n",
               clockStr,
               reqSize);
    }
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.m_SessionInitiator = node->nodeId;
    appParam.SetPriority(clientPtr->reqTOS);
    appParam.SetSessionId(clientPtr->uniqueId);
    appParam.SetAppType("SUPER-APPLICATION");
    appParam.SetAppName(clientPtr->applicationName);
    appParam.m_ReceiverId = clientPtr->receiverId;
     // dns
    if (clientPtr->serverAddr != 0)
    {
        appParam.SetReceiverAddr(clientPtr->serverAddr);
    }
    appParam.m_TotalMsgSize = reqSize;
    if (data.totFrag > 1)
    {
        appParam.m_fragEnabled = TRUE;
    }
#endif
    // Dynamic address
    // Create and send a UDP msg with header and virtual
    // payload.
    // if the client has not yet acquired a valid
    // address then the application packets should not be
    // generated
    // check whether client and server are in valid address
    // state
    // if this is session start then packets will not be sent
    // if in invalid address state and session will be closed
    // ; if the session has already started and address
    // becomes invalid during application session then
    // packets will get generated but will be dropped at
    //  network layer
    if (AppSuperApplicationClientGetSessionAddressState(node, clientPtr)
                            == ADDRESS_FOUND)
    {
        // update the message info with new address as same msg is used for
        // scehduling next packet
        AppTimer* timer;
        timer = (AppTimer*) MESSAGE_ReturnInfo(msg);
        if (timer->address != clientPtr->serverAddr)
        {
            timer->address = clientPtr->serverAddr;
        }
        while (reqSize > 0)
        {
            // STATS DB CODE.
#ifdef ADDON_DB
            appParam.m_IsFragmentation = FALSE;
            appParam.SetFragNum(data.fragNo);
            if (data.totFrag > 1 && data.fragNo == 0)
            {
                // we have fragmentation
                appParam.m_IsFragmentation = TRUE;
            }
#endif
            if (clientPtr->isVoice == FALSE)
            {
                fragSize = (int)((reqSize > maxFragmentSize) ?
                                 maxFragmentSize : reqSize);

                // Part of the fragment that will be virtual data
                virtualPayload = fragSize;
            }else{
                fragSize = reqSize;
                payload = (char *)MEM_malloc(sizeof(dataType));
                memset(payload, 0, sizeof(dataType));
                memcpy(payload, &dataType, sizeof(dataType));
                virtualPayload = fragSize - sizeof(dataType);
            }

            if (SUPERAPPLICATION_DEBUG_REQ_SEND)
            {
                printf("    Connection           : C(%u:%u)->S(%u:%u)\n",
                       node->nodeId,
                       clientPtr->sourcePort,
                       MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                             clientPtr->serverAddr),
                       clientPtr->destinationPort);
                printf("    Total fragment bytes : %" TYPES_SIZEOFMFT "u \n",(sizeof(data) + virtualPayload));
                printf("    Virtual payload      : %u \n",virtualPayload);
                printf("    TOS                  : %d \n",clientPtr->reqTOS);
                printf("    Fragment seq no.     : %d \n",data.seqNo);
                printf("    Fragment no          : %d \n",data.fragNo);
                printf("    Total fragments      : %d \n",data.totFrag);
            }

#ifdef ADDON_BOEINGFCS
            Message * tempMsg = NULL;
            int numReqPackets = 1;
            if (clientPtr->totalReqPacketsToSend > 0)
            {
                numReqPackets = clientPtr->totalReqPacketsToSend;
            }
            float numBits = (float) (reqSize * numReqPackets * 8);
            float interval = (float) reqInterval / SECOND;
            float dataRate = (numBits / interval) / 1000.0;

            if (clientPtr->isVoice == FALSE){
                tempMsg = SuperApplicationClientSendMessage_UDP(
                    node,
                    clientPtr,
                    NULL,
                    0,
                    virtualPayload,
                    (SuperApplicationUDPDataPacket*) &data,
                    fragSize,
                    reqSize
#ifdef ADDON_DB
                    , &appParam
#endif
                    );
            }else{
                tempMsg = SuperApplicationClientSendMessage_UDP(
                    node,
                    clientPtr,
                    payload,
                    sizeof(dataType),
                    virtualPayload,
                    (SuperApplicationUDPDataPacket*) &data,
                    fragSize,
                    reqSize
#ifdef ADDON_DB
                    , &appParam
#endif
                    );

            }

#else
            Message * tempMsg = NULL;
            if (clientPtr->isVoice == FALSE){
                tempMsg = SuperApplicationClientSendMessage_UDP(
                    node,
                    clientPtr,
                    NULL,
                    0,
                    virtualPayload,
                    (SuperApplicationUDPDataPacket*) &data,
                    fragSize,
                    reqSize
#ifdef ADDON_DB
                    , &appParam
#endif
                    );
            }
            else{
                tempMsg = SuperApplicationClientSendMessage_UDP(
                    node,
                    clientPtr,
                    payload,
                    sizeof(dataType),
                    virtualPayload,
                    (SuperApplicationUDPDataPacket*) &data,
                    fragSize,
                    reqSize
#ifdef ADDON_DB
                    , &appParam
#endif
                    );
            }
#endif
            if (node->appData.appStats)
            {
                //clientPtr->stats.numReqBytesSent += reqSize;
                clientPtr->lastReqFragSentTime = node->getNodeTime();
                if (data.fragNo == 0 && data.seqNo == 0)
                {
                    clientPtr->firstReqFragSentTime =
                                            clientPtr->lastReqFragSentTime;
                }
            }
            clientPtr->stats.numReqBytesSent += fragSize;
            clientPtr->stats.numReqFragsSent += 1;
            reqSize -= fragSize;
            data.fragNo++;
            data.uniqueFragNo = clientPtr->uniqueFragNo ++;

            if (payload)
            {
                MEM_free(payload);
            }
        } // end while (reqSize > 0)
        // Statistics update
        // 1 Packet is sent when all it's fragments are sent

        clientPtr->lastReqPacketSentTime = node->getNodeTime();
        if (clientPtr->stats.numReqPacketsSent == 0) {
            clientPtr->firstReqPacketSentTime =
            clientPtr->lastReqPacketSentTime;
        }

        clientPtr->stats.numReqBytesSentPacket += reqSize;
        clientPtr->stats.numReqPacketsSent += 1;
        // Check if it was the first fragment
        if (clientPtr->stats.numReqPacketsSent == 1)
            clientPtr->firstReqFragSentTime = node->getNodeTime();
        if (clientPtr->lastReqFragSentTime > clientPtr->firstReqFragSentTime)
        {
            clientPtr->stats.reqSentThroughput = (double)
                                             ((double) (clientPtr->stats.numReqBytesSent * 8 * SECOND)
                                             / (clientPtr->lastReqFragSentTime - clientPtr->firstReqFragSentTime));
        }

        if (clientPtr->lastReqPacketSentTime > clientPtr->firstReqPacketSentTime)
        {
            clientPtr->stats.reqSentThroughputPacket =
            (double)((double)(clientPtr->stats.numReqBytesSentPacket * 8 * SECOND)
                      / (clientPtr->lastReqPacketSentTime - clientPtr->firstReqPacketSentTime));
        }

        // Packet sent so increment sequence number
        clientPtr->seqNo++;

        if (// Required number of requests sent
            ((clientPtr->stats.numReqPacketsSent ==
              clientPtr->totalReqPacketsToSend) &&
             (clientPtr->totalReqPacketsToSend > 0)) ||
            // Session is over
            (clientPtr->sessionFinish != clientPtr->sessionStart
             && node->getNodeTime() + reqInterval >= clientPtr->sessionFinish))
        {
            if ((SUPERAPPLICATION_DEBUG_TIMER_REC_CLIENT) ||
                    (SUPERAPPLICATION_DEBUG_TIMER_SET_CLIENT))
            {
                char clockStr[24];
                TIME_PrintClockInSecond(reqInterval+node->getNodeTime(), clockStr, node);
                printf("Closing connection  : \n");
                printf("    Proposed next pkt schedule time : %s \n" ,clockStr);
                TIME_PrintClockInSecond(clientPtr->sessionFinish, clockStr, node);
                printf("    Session finish time             : %s \n" ,clockStr);
                printf("    Status of req sent              :  %f of ",
                       (Float64)clientPtr->stats.numReqPacketsSent);
                if (clientPtr->totalReqPacketsToSend == 0)
                    printf("unspecified max. \n");
                else
                    printf("%u \n",clientPtr->totalReqPacketsToSend);
            }
            clientPtr->isClosed = TRUE;
            if (!clientPtr->processReply && node->appData.appStats &&
                clientPtr->stats.appStats)
            {
                if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
                {
                    if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                    {
                        clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                    }
                }
                else
                {
                    if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                    {
                        clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                    }
                }
            }
            if (clientPtr->isMdpEnabled)
            {
                //notify MDP that last packet is enqueued
                Address sourceNodeAddr;
                Address destNodeAddr;

                sourceNodeAddr.networkType = NETWORK_IPV4;
                sourceNodeAddr.interfaceAddr.ipv4 = clientPtr->clientAddr;

                destNodeAddr.networkType = NETWORK_IPV4;
                destNodeAddr.interfaceAddr.ipv4 = clientPtr->serverAddr;

                MdpNotifyLastDataObject(node,
                                        sourceNodeAddr,
                                        destNodeAddr,
                                        clientPtr->mdpUniqueId);
            }

#ifdef ADDON_BOEINGFCS
            if (clientPtr->stats.numReqPacketsSent == 1) {
                clientPtr->lastReqFragSentTime += 1*SECOND;
                clientPtr->stats.reqSentThroughput =
                    (double)((double)(clientPtr->stats.numReqBytesSent * 8 * SECOND)
                              / (clientPtr->lastReqFragSentTime - clientPtr->firstReqFragSentTime));
            }
#endif
        }
    }
    else
    {
        clientPtr->isClosed = TRUE;
        clientPtr->sessionStart = 0;
    }
    // Set up next timer
    if (!clientPtr->isClosed)
    {

        if (clientPtr->isVoice == FALSE){
            SuperApplicationClientScheduleNextPkt(
                node,
                clientPtr,
                reqInterval,
                msg);
        }else{
            if (isMyTurnToTalk){
                SuperApplicationClientScheduleNextPkt(
                    node,
                    clientPtr,
                    reqInterval,
                    msg);
            }
            else {
                MESSAGE_Free(node, msg);
            }
        }
    }
    else
    {
        // Free the timer message
        MESSAGE_Free(node, msg);
    }
}


// FUNCTION SuperApplicationServerSendData_UDP
// PURPOSE  Send data and schedule next timer
// Parameters:
//  node:   Pointer to the node structure
//  serverPtr:  Pointer to server state variable
//  msg:    Pointer to message
static void SuperApplicationServerSendData_UDP(Node* node,SuperApplicationData* serverPtr,Message* msg) {
    SuperAppTimer* replyPacketTimer;
    Int32      repSize;
    Int32      fragSize;
    Int32 virtualPayload;
    float maxFragmentSize;
    clocktype repInterval;
    SuperApplicationUDPDataPacket data;
    char *payload = NULL;
    BOOL isMyTurnToTalk = FALSE;
    char dataType = 'm';
    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(msg);

    //init the SuperApplicationUDPDataPacket
    memset(&data, 0, sizeof(data));

    if ((serverPtr->isVoice) && (serverPtr->isJustMyTurnToTalk)){

        serverPtr->averageTalkTime = serverPtr->randomAverageTalkTime.getRandomNumber();

        serverPtr->talkTime = (clocktype) (serverPtr->averageTalkTime * serverPtr->gapRatio);


        if (serverPtr->talkTime < MIN_TALK_TIME) {
            char errorStr[MAX_STRING_LENGTH] = "";
            sprintf(errorStr, "MIN-TALK-TIME for voice application is 1 second.  Change talkTime to 1 second.\n");
            ERROR_ReportWarning(errorStr);
            serverPtr->talkTime = MIN_TALK_TIME;
        }

        if (SUPERAPPLICATION_DEBUG_VOICE){
            char clockStr[24];
            char talkTimeStr[24];
            TIME_PrintClockInSecond (serverPtr->talkTime, talkTimeStr);
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : S(%u:%u)->C(%u:%u)\n",
                   node->nodeId,
                   serverPtr->destinationPort,
                   MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                         serverPtr->clientAddr),
                   serverPtr->sourcePort);
            printf("    At %s sec, Turn for server to talk:\n", clockStr);
            printf("    Talk Time for this turn is %s sec:\n", talkTimeStr);
        }
        serverPtr->isJustMyTurnToTalk = FALSE;
        serverPtr->isTalking = TRUE;
        serverPtr->firstTalkTime = node->getNodeTime();
    }

    if (SUPERAPPLICATION_DEBUG_TIMER_REC_SERVER)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server got timer alarm: \n",clockStr);
        printf("    Purpose     : Send reply packet\n");
        printf("    Connection  : S(%u:%u)->C(%u:%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("    Reply for   : %u req seq no \n",replyPacketTimer->reqSeqNo);
    }
    replyPacketTimer->numRepSent += 1;
    // Calculate data reply packet length
    //serverPtr->randomRepSize.setSeed(node->globalSeed);
    repSize = (Int32) serverPtr->randomRepSize.getRandomNumber();
    // Time for txing next data repuest
    //serverPtr->randomRepInterDepartureDelay.setSeed(node->globalSeed);
    repInterval = serverPtr->randomRepInterDepartureDelay.getRandomNumber();

    if (serverPtr->isVoice == TRUE){
        isMyTurnToTalk = SuperAppVoiceStartTalking(node,
                         serverPtr,
                         &dataType,
                         repInterval);
        if (SUPERAPPLICATION_DEBUG_VOICE_SEND){
            char clockStr[24];
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : S(%u:%u)->C(%u:%u)\n",
                   node->nodeId,
                   serverPtr->destinationPort,
                   MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                         serverPtr->clientAddr),
                   serverPtr->sourcePort);
            printf("    At %s sec, Server send voice packet:\n", clockStr);
            printf("    Voice Packet type is: %c\n", dataType);
        }
        if (dataType == 'o'){
            serverPtr->state =  SUPERAPPLICATION_SERVERIDLE_UDP;
            serverPtr->isTalking = FALSE;
            SuperApplicationServerScheduleTalkTimeOut(node, serverPtr);
        }
    }


    // Convert fragmentationSize to float for division
    maxFragmentSize = serverPtr->fragmentationSize;
    /*ERROR_Assert(
        serverPtr->stats.numRepBytesSent < SUPERAPPLICATION_MAX_DATABYTE_SEND,
        "Total bytes sent exceed maximum limit, current packet"
        " size should be reduced for proper statistics");*/
    // Set up data
    data.txTime     = node->getNodeTime();
    data.seqNo      = serverPtr->repSeqNo;
    if (repSize > maxFragmentSize)
    {
        data.totFrag    = (int)ceil(repSize / maxFragmentSize);
    }
    else
    {
        data.totFrag = 1;
    }

    data.fragNo     = 0;
    data.uniqueFragNo = serverPtr->uniqueFragNo ++;
    data.appFileIndex = serverPtr->appFileIndex;
    data.sessionId = serverPtr->uniqueId;
    data.totalMessageSize = repSize;
    data.isMdpEnabled = serverPtr->isMdpEnabled;

#ifdef ADDON_BOEINGFCS
    data.txRealTime = node->partitionData->wallClock->getRealTime();
    data.txCpuTime = SuperApplicationCpuTime(serverPtr);
    data.txPartitionId = node->partitionId;
#endif /* ADDON_BOEINGFCS */

    // Application layer fragmentation
    if (SUPERAPPLICATION_DEBUG_REP_SEND)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server (%u: %d) sending reply packet "
               "%u of %u for req seq no = %u. Sending %u byte packet to "
               " (%d:%hu) with:\n",
               clockStr,
               node->nodeId,
               serverPtr->destinationPort,
               replyPacketTimer->numRepSent,
               replyPacketTimer->numRepToSend,
               replyPacketTimer->reqSeqNo,
               repSize,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->serverAddr),
               serverPtr->sourcePort);
    }
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.SetPriority(serverPtr->repTOS);
    //appParam.SetSessionId(serverPtr->uniqueId);
    appParam.SetSessionId(serverPtr->sessionId);
    appParam.m_SessionInitiator = serverPtr->sessionInitiator;
    appParam.SetAppType("SUPER-APPLICATION");
    appParam.SetAppName(serverPtr->applicationName);
    appParam.m_ReceiverId = serverPtr->receiverId;
    appParam.SetReceiverAddr(serverPtr->clientAddr);
    appParam.m_TotalMsgSize = repSize;
    if (data.totFrag > 1)
    {
        appParam.m_fragEnabled = TRUE;
    }
#endif
    while (repSize > 0)
    {
        // STATS DB CODE.
#ifdef ADDON_DB
        appParam.SetFragNum(data.fragNo);
        appParam.m_IsFragmentation = FALSE;
        if (data.totFrag > 1 && data.fragNo == 0)
        {
            appParam.m_IsFragmentation = TRUE;
        }
#endif
        if (serverPtr->isVoice == FALSE){
            fragSize = (int)((repSize > maxFragmentSize) ?
                              maxFragmentSize : repSize);

            // Part of the fragment that will be virtual data
            virtualPayload = fragSize;
        } else {
            fragSize = repSize;
            payload = (char *)MEM_malloc(sizeof(dataType));
            memset(payload, 0, sizeof(dataType));
            memcpy(payload, &dataType, sizeof(dataType));
            virtualPayload = fragSize - sizeof(dataType);
        }
        if (SUPERAPPLICATION_DEBUG_REP_SEND)
        {
            printf("    Total fragment bytes : %" TYPES_SIZEOFMFT "u \n",(sizeof(data) + virtualPayload));
            printf("    Virtual payload      : %d \n",virtualPayload);
            printf("    TOS                  : %d \n",serverPtr->repTOS);
            printf("    Fragment seq no.     : %d \n",data.seqNo);
            printf("    Fragment no          : %d \n",data.fragNo);
            printf("    Total fragments      : %d \n",data.totFrag);
            printf("    Ports (Src,Dst)      : %d, %d \n",serverPtr->sourcePort,
                   serverPtr->destinationPort);
            printf("\n");
        }
        if (node->appData.appStats)
        {
            if (!serverPtr->stats.appStats->IsSessionStarted(STAT_Unicast))
            {
                serverPtr->stats.appStats->SessionStart(node);
            }
            if (replyPacketTimer->lastReplyToSent) {
                if (replyPacketTimer->numRepSent ==
                    replyPacketTimer->numRepToSend)
                {
                    data.isLastPacket = TRUE;
                    if (!serverPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                    {
                        serverPtr->stats.appStats->SessionFinish(node);
                    }
                }
            }
        }
        Message * tempMsg = NULL;
        if (serverPtr->isVoice == FALSE) {
            tempMsg = SuperApplicationServerSendMessage_UDP(
                node,
                serverPtr,
                NULL,
                0,
                virtualPayload,
                (SuperApplicationUDPDataPacket*) &data,
                fragSize
#ifdef ADDON_DB
                , &appParam
#endif
                );
        } else {
            tempMsg = SuperApplicationServerSendMessage_UDP(
                node,
                serverPtr,
                payload,
                sizeof(dataType),
                virtualPayload,
                (SuperApplicationUDPDataPacket*) &data,
                fragSize
#ifdef ADDON_DB
                , &appParam
#endif
                );
        }
        serverPtr->lastRepFragSentTime = node->getNodeTime();
        if (serverPtr->stats.numRepBytesSent == 0) {
            serverPtr->firstRepFragSentTime =
                serverPtr->lastRepFragSentTime;
        }
        serverPtr->stats.numRepBytesSent += fragSize;
        serverPtr->stats.numRepFragsSent += 1;
        repSize -= fragSize;
        data.fragNo++;
        data.uniqueFragNo = serverPtr->uniqueFragNo ++;
        if (payload)
        {
            MEM_free(payload);
        }
    } // end while (repSize > 0)
    // Statistics update
    // 1 Packet is sent when all it's fragments are sent
    serverPtr->stats.numRepPacketsSent += 1;

    if (serverPtr->lastRepFragSentTime > serverPtr->firstRepFragSentTime)
    {
        serverPtr->stats.repSentThroughput = (double)((double)(serverPtr->stats.numRepBytesSent * 8 * SECOND)
                                             / (serverPtr->lastRepFragSentTime - serverPtr->firstRepFragSentTime));
    }
    // Packet sent so increment sequence number
    serverPtr->repSeqNo++;
    if (serverPtr->isVoice==FALSE){
        if (replyPacketTimer->numRepSent == replyPacketTimer->numRepToSend)
        {
            if (serverPtr->isMdpEnabled)
            {
                //notify MDP that last packet is enqueued
                Address sourceNodeAddr;
                Address destNodeAddr;

                sourceNodeAddr.networkType = NETWORK_IPV4;
                sourceNodeAddr.interfaceAddr.ipv4 = serverPtr->serverAddr;

                destNodeAddr.networkType = NETWORK_IPV4;
                destNodeAddr.interfaceAddr.ipv4 = serverPtr->clientAddr;

                MdpNotifyLastDataObject(node,
                                        sourceNodeAddr,
                                        destNodeAddr,
                                        serverPtr->mdpUniqueId);
            }

            // Free the timer message
            MESSAGE_Free(node, msg);
        }
        else
        {
            SuperApplicationServerScheduleNextRepPkt_UDP(
                node,
                serverPtr,
                repInterval,
                msg);
        }
    }else{
        if (isMyTurnToTalk) {
            SuperApplicationServerScheduleNextRepPkt_UDP(
                node,
                serverPtr,
                repInterval,
                msg);
        } else {
            MESSAGE_Free(node, msg);
        }
    }
}


// FUNCTION SuperApplicationClientScheduleNextPkt
// PURPOSE  Schedule a timer for the next packet
// Parameters:
//  node:   Node pointer
//  clientPtr:  Pointer to client state variable
//  interval:   Interval after which the packet is to be scheduled
//  msg:    Message pointer
static void SuperApplicationClientScheduleNextPkt(Node* node,SuperApplicationData* clientPtr,clocktype interval,Message* msg) {
    if (SUPERAPPLICATION_DEBUG_TIMER_SET_CLIENT)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client scheduling timer for a request packet \n",
               clockStr);
        printf("    Connection :  C(%u:%u)->S(%u,%u)\n",
               node->nodeId,
               clientPtr->sourcePort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clientPtr->serverAddr),
               clientPtr->destinationPort);
        printf("    Seq no     :  %d  \n",clientPtr->seqNo);
        TIME_PrintClockInSecond((interval + node->getNodeTime()), clockStr, node);
        printf("    Alarm time :  %s sec\n", clockStr);
        TIME_PrintClockInSecond(interval, clockStr);
        printf("    Interval   :  %s sec\n", clockStr);
    }
    MESSAGE_Send(node, msg, interval);
}

// FUNCTION SuperApplicationServerInit
// PURPOSE  Initialize SuperApplication server. Read user configuration parameters for the server
// Parameters:
//  node:   Pointer to the node structure
//  inputString:    User configuration parameter string
//  serverPtr:  Pointer to server state variable
static void SuperApplicationServerInit(Node* node,
                                       char* inputString,
                                       SuperApplicationData* serverPtr,
                                       NodeAddress clientAddr,
                                       NodeAddress serverAddr,
                                       Int32 mdpUniqueId = -1) {

#ifdef ADDON_BOEINGFCS
    char err[MAX_STRING_LENGTH];
#endif /* ADDON_BOEINGFCS */

    char keywordValue[MAX_STRING_LENGTH];
    char keywordValue2[MAX_STRING_LENGTH];
    char errStr[MAX_STRING_LENGTH];
    char* tokenStr = NULL;
    int nToken;
    BOOL isDestinationPort = FALSE;
    BOOL isSendReply = FALSE;
    BOOL isRepInterDepartureDelay = FALSE;
    BOOL isRepProcessDelay = FALSE;
    BOOL isRepSize = FALSE;
    BOOL isRepNum = FALSE;
    BOOL isChainID = FALSE;
#ifdef ADDON_BOEINGFCS
    BOOL isReqTput = FALSE;
    BOOL isReqDelay = FALSE;
#endif
    bool isSlientGap = FALSE;
    char keyword[MAX_STRING_LENGTH];
    // for voip
    BOOL isAverageTalkTime = FALSE;
    RandomDistribution<clocktype> randomsessionStart;
    RandomDistribution<clocktype> randomDuration;

    VoiceEncodingScheme voiceCodec[] =
        {
            {"G.711", "DET 160", "DET 20MS"},
            {"G.729", "DET 20", "DET 20MS"},
            {"G.723.lar6.3", "DET 23", "DET 30MS"},
            {"G.723.lar5.3", "DET 20", "DET 30MS"},
            {"G.726ar32", "DET 80", "DET 20MS"},
            {"G.726ar24", "DET 60", "DET 20MS"},
            {"G.728ar16", "DET 40", "DET 30MS"},
            {"CELP", "DET 18", "DET 30MS"},
            {"MELP", "DET 8", "DET 22.5MS"}
        };

    tokenStr = inputString;
    serverPtr->clientAddr = clientAddr;
    serverPtr->serverAddr = serverAddr;

#ifdef ADDON_DB
    if (clientAddr == ANY_ADDRESS ||
        NetworkIpIsMulticastAddress(node, clientAddr))
    {
        serverPtr->receiverId = 0;
    }
    else
    {
        serverPtr->receiverId =
            MAPPING_GetNodeIdFromInterfaceAddress(node, clientAddr);
    }
#endif // ADDON_DB

    // Advance input string by 3 token; appStr, sourceString, destString
    tokenStr = SuperApplicationDataSkipToken(
                   tokenStr,
                   SUPERAPPLICATION_TOKENSEP,
                   3);
    // App name at server side will be overwritten once recv first packet
    strcpy(serverPtr->applicationName,"SuperApplication");
    strcpy(serverPtr->printName, serverPtr->applicationName);
    while (tokenStr != NULL)
    {
        // Read keyword
        nToken = sscanf(tokenStr, "%s", keyword);
        // Advance input string by 1
        tokenStr = SuperApplicationDataSkipToken(
                       tokenStr,
                       SUPERAPPLICATION_TOKENSEP,
                       nToken);
        if (strcmp(keyword,"REPLY-PROCESS") == 0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            isSendReply = TRUE;
            if ((strcmp(keywordValue,"YES") == 0)  ||
                (strcmp(keywordValue,"yes") == 0)  ||
                (strcmp(keywordValue,"Yes") == 0) ||
                (strcmp(keywordValue,"y") == 0) ||
                (strcmp(keywordValue,"Y") == 0))
            {
                serverPtr->processReply = TRUE;
            }
            else if ((strcmp(keywordValue,"NO") == 0) ||
                     (strcmp(keywordValue,"no") == 0) ||
                     (strcmp(keywordValue,"n") == 0) ||
                     (strcmp(keywordValue,"N") == 0) ||
                     (strcmp(keywordValue,"No") == 0))
            {
                serverPtr->processReply = FALSE;
            }
            else
            {
                ERROR_ReportError("SuperApplication: Invalid value for "
                    "REPLY-PROCESS.\n");
            }
        }
        else if (strcmp(keyword,"REPLY-PROCESS-DELAY")==0)
        {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = serverPtr->randomRepInterval.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            isRepProcessDelay = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REPLY-SIZE")==0)
        {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = serverPtr->randomRepSize.setDistribution(tokenStr, "Superapplication", RANDOM_INT);
            isRepSize = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REPLY-NUM")==0)
        {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = serverPtr->randomRepPacketsToSendPerReq.setDistribution(
                         tokenStr, "Superapplication", RANDOM_INT);
            isRepNum = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REPLY-INTERDEPARTURE-DELAY")==0)
        {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = serverPtr->randomRepInterDepartureDelay.setDistribution(
                         tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            isRepInterDepartureDelay = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"REPLY-TOS")==0 ||
                 strcmp(keyword,"REQUEST-TOS")==0)
        {
            unsigned tos = APP_DEFAULT_TOS;
            nToken = sscanf(tokenStr, "%s %s", keywordValue, keywordValue2);
            if (!APP_AssignTos(keywordValue, keywordValue2, &tos))
            {
                ERROR_ReportError("SuperApplication: Unable to get "
                    "equivalent 8-bit Reply TOS value\n");
            }

            // assign tos correctly...
            if (strcmp(keyword,"REPLY-TOS")==0)
            {
                serverPtr->repTOS = (unsigned char) tos;
                // Commented to resolve bug# 5716
                //if (node->appData.appStats)
                //{
                // serverPtr->stats.appStats->setTos(serverPtr->repTOS);
                //}
            }
            else if (strcmp(keyword,"REQUEST-TOS")==0)
            {
                serverPtr->reqTOS = (unsigned char) tos;
            }
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"DELIVERY-TYPE")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            // Set the transport layer protcol.
            // More protocols may be added here.

            if (serverPtr->isVoice == FALSE && serverPtr->isVideo == FALSE) {
                if (strcmp(keywordValue,"RELIABLE") == 0)
                    serverPtr->transportLayer = SUPERAPPLICATION_TCP;
                else if (strcmp(keywordValue,"UNRELIABLE") == 0)
                    serverPtr->transportLayer = SUPERAPPLICATION_UDP;
                else
                {
                    ERROR_ReportError("SuperApplication: Unknown "
                        "DELIVERY-TYPE.\n");
                }
            }
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"APPLICATION-NAME")==0)
        {
            if (tokenStr)
            {
                nToken = sscanf(tokenStr, "%s", keywordValue);
                //strcat(keywordValue,"-SERVER");
                strcpy(serverPtr->applicationName, keywordValue);
                tokenStr = SuperApplicationDataSkipToken(
                               tokenStr,
                               SUPERAPPLICATION_TOKENSEP,
                               nToken);
            }
            strcpy(serverPtr->printName, serverPtr->applicationName);
        }
        else if (strcmp(keyword,"FRAGMENT-SIZE")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            serverPtr->fragmentationSize =
                (unsigned short) atoi(keywordValue);
            serverPtr->fragmentationEnabled = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"SOURCE-PORT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            serverPtr->sourcePort = (short)atoi(keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"DESTINATION-PORT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            serverPtr->destinationPort =
                (short) atoi(keywordValue);
            isDestinationPort = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword,"CHAIN-ID")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if (strcmp(keywordValue, "=")==0){
                // do nothing, it is for conditions
            }else{
                strcpy(serverPtr->chainID, keywordValue);
                isChainID = TRUE;
            }
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "ENCODING-SCHEME")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);

            if (strcmp(keywordValue, "VOICE")== 0){
                char codecScheme[MAX_STRING_LENGTH]="";
                int index = 0;
                int upperIndex = sizeof(voiceCodec)/sizeof(VoiceEncodingScheme);
                BOOL isCodecFound = FALSE;
                nToken = sscanf(tokenStr, "%s", codecScheme);

                // searching for codec
                for (index = 0; index < upperIndex; index++){
                    if (strcmp (voiceCodec[index].codeScheme, codecScheme) ==0){
                        // video traffic only support using UDP
                        // set the transport layer protocol
                        serverPtr->transportLayer = SUPERAPPLICATION_UDP;
                        // inserting the request number
                        serverPtr->totalReqPacketsToSend = 0;

                        // inserting the request size
                        serverPtr->randomRepSize.setDistribution(voiceCodec[index].packetSize, "Superapplication", RANDOM_INT);

                        // inserting the request interval
                        serverPtr->randomRepInterDepartureDelay.setDistribution(voiceCodec[index].packetInterval,
                                "Superapplication", RANDOM_CLOCKTYPE);

                        serverPtr->processReply = FALSE;
                        isCodecFound = TRUE;
                        serverPtr->isVoice = TRUE;
                        break;
                    }
                }
                if (isCodecFound == FALSE){
                    sprintf(errStr, "Voice Codec error:  CES doesn't "
                        "support %s codec\n", codecScheme);
                    ERROR_ReportError(errStr);
                }
            } else if (strcmp(keywordValue, "VIDEO") == 0) {
                serverPtr->isVideo = TRUE;
                serverPtr->transportLayer = SUPERAPPLICATION_UDP;
            }
        }
        else if (strcmp(keyword, "AVERAGE-TALK-TIME") == 0){

            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = serverPtr->randomAverageTalkTime.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);

            isAverageTalkTime = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "MEAN-SPURT-GAP-RATIO") == 0) {
            nToken = sscanf(tokenStr, "%f", &serverPtr->gapRatio);
            isSlientGap = TRUE;
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        // only use for voice session
        else if (strcmp(keyword,"DURATION")==0)
        {
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomDuration.setDistribution(tokenStr, "Superapplication", RANDOM_CLOCKTYPE);

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        // only use for voice session
        else if (strcmp(keyword,"START-TIME")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomsessionStart.setDistribution(
                            tokenStr, "Superapplication", RANDOM_CLOCKTYPE);

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
#ifdef ADDON_BOEINGFCS
        else if (strcmp(keyword,"REAL-TIME-OUTPUT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            if (strcmp(keywordValue, "YES") == 0)
            {
                serverPtr->realTimeOutput = TRUE;
                //printf("RT output\n");

                // Create the rt output file for this partition if it has
                // not been created yet.
                if (!node->partitionData->realTimeLogEnabled)
                {
                    char fileName[MAX_STRING_LENGTH];
                    char experimentName[MAX_STRING_LENGTH];
                    int wasFound;

                    IO_ReadString(
                        ANY_NODEID,
                        ANY_ADDRESS,
                        node->partitionData->nodeInput,
                        "EXPERIMENT-NAME",
                        &wasFound,
                        experimentName);
                    if (!wasFound)
                    {
                        ERROR_ReportError("SuperApp experiment name not "
                                          "found!!!");
                    }
                    sprintf(fileName, "%s%d.rt", experimentName,
                            node->partitionData->partitionId);

                    node->partitionData->realTimeLogEnabled = TRUE;
                    node->partitionData->realTimeFd = fopen(fileName, "w");
                    assert(node->partitionData->realTimeFd != NULL);
                }
            }
            else if (strcmp(keywordValue, "NO") == 0)
            {
                serverPtr->realTimeOutput = FALSE;
                //printf("No RT output\n");
            }
            else
            {
                sprintf(err, "Unknown REAL-TIME-OUTPUT value \"%s\"",
                        tokenStr);
                ERROR_ReportWarning(err);
            }
        }
        else if (strcmp(keyword,"PRINT-REAL-TIME-STATS") == 0)
        {
            if (strcmp(tokenStr, "YES") == 0)
            {
                serverPtr->printRealTimeStats = TRUE;
            }
            else if (strcmp(tokenStr, "NO") == 0)
            {
                serverPtr->printRealTimeStats = FALSE;
            }
            else
            {
                sprintf(err, "Unknown PRINT-REAL-TIME-STATS value \"%s\"",
                        tokenStr);
                ERROR_ReportWarning(err);
            }
        }
#endif /* ADDON_BOEINGFCS */

#ifdef ADDON_BOEINGFCS
        else if (strcmp(keyword, "REQUIRED-TPUT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            isReqTput  = TRUE;
            serverPtr->requiredTput= atoi(keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REPLY-REQUIRED-TPUT")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            isReqTput  = TRUE;
            serverPtr->requiredTput= atoi(keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REQUIRED-DELAY")==0)
        {
            char paramStr0[MAX_STRING_LENGTH];
            nToken = sscanf(tokenStr, "%s", paramStr0);
            if (nToken != 1)
            {
                SuperApplicationDataPrintUsageAndQuit();
            }
            serverPtr->requiredDelay = (TRUE) ? (clocktype)TIME_ConvertToClock(paramStr0)
                                       : (clocktype)atol(paramStr0);


            char timex[MAX_STRING_LENGTH];
            isReqDelay  = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
        else if (strcmp(keyword, "REPLY-REQUIRED-DELAY")==0)
        {
            char paramStr0[MAX_STRING_LENGTH];
            nToken = sscanf(tokenStr, "%s", paramStr0);
            if (nToken != 1)
            {
                SuperApplicationDataPrintUsageAndQuit();
            }
            serverPtr->requiredDelay = (TRUE) ? (clocktype)TIME_ConvertToClock(paramStr0)
                                       : (clocktype)atol(paramStr0);


            isReqDelay  = TRUE;
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }

#endif

        else if (strcmp(keyword, "MDP-ENABLED") == 0) {
            serverPtr->isMdpEnabled = TRUE;
            serverPtr->mdpUniqueId = mdpUniqueId;
        }
        else if (strcmp(keyword,"MDP-PROFILE")==0)
        {
            serverPtr->isProfileNameSet = TRUE;

            if (!tokenStr)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Please specify MDP-PROFILE name.\n");
                ERROR_ReportError(errorString);
            }

            nToken = sscanf(tokenStr, "%s", keywordValue);
            strcpy(serverPtr->profileName,keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
        }
    }//while (tokenStr != NULL)

    //if transport type is not SUPERAPPLICATION_UDP and dest address is not
    // a unicast address then disable MDP
    if (serverPtr->transportLayer != SUPERAPPLICATION_UDP
        || NetworkIpIsMulticastAddress(node, serverAddr)
        || serverAddr == ANY_ADDRESS)
    {
        serverPtr->isMdpEnabled = FALSE;
        serverPtr->isProfileNameSet = FALSE;
    }
    serverPtr->isChainId = isChainID;
    // check if all required paramteters were specified for voip
    if (serverPtr->isVoice)
    {
        // get start time and end time for voip application
        serverPtr->sessionStart = randomsessionStart.getRandomNumber();

        if (randomDuration.getDistributionType() == DNULL)
        {
            serverPtr->sessionFinish = 0;
        }
        else
        {
            serverPtr->sessionFinish = serverPtr->sessionStart
                                       + randomDuration.getRandomNumber();
        }
        if (isAverageTalkTime == FALSE){
            ERROR_ReportError("AVERAGE-TALK-TIME required.\n");
        }
        if (isSendReply == TRUE){
            ERROR_ReportError("Reply not support for voip application.\n");
        }
    }
    if (serverPtr->isVoice && isSlientGap == FALSE) {
        serverPtr->gapRatio = (float) VOIP_MEAN_SPURT_GAP_RATIO;
    }
    // Check if all required parameters were specified
    if ((serverPtr->processReply == TRUE) &&
            ((isRepProcessDelay == FALSE) ||
             (isRepSize == FALSE) ||
             (isRepNum == FALSE) ||
             (isRepInterDepartureDelay == FALSE)))
    {
        printf("inputString is %s\n", inputString);
        if (isRepProcessDelay == FALSE)
            printf("    REPLY-PROCESS-DELAY required.\n");
        if (isRepSize == FALSE) printf("    REPLY-SIZE required.\n");
        if (isRepNum == FALSE) printf("    REPLY-NUM required.\n");
        if (isRepInterDepartureDelay == FALSE)
            printf("    REPLY-INTERDEPARTURE-DELAY required.\n");
        ERROR_ReportError("SuperApplication Server: All required parameters "
               "not specified.\n");

    }

    if (isDestinationPort == TRUE)
    {
        if (APP_IsFreePort(node, serverPtr->destinationPort) == FALSE)
        {
            ERROR_ReportError("SuperApplication: User specified destination "
                "port is busy. Possible causes are :\n"
                   "    -Another application may have requested the same "
                   "port. \n"
                   "    -Node is running an application that uses this port "
                   "number as APP_TYPE (Check AppType enumeration in "
                   " QUALNET_HOME\\application\\application.h). \n");
        }
        if (serverPtr->destinationPort <0)
        {
            ERROR_ReportError("SuperApplication: Destination port needs to "
                "be > 0.\n");
        }
    }

    // MERGE - this line seems as though it should be here, not
    // inside of the if (isVoiceVideo) statment. It is required
    // to denote a superApp server regardless of voice, video,
    // or regular data. This line is required for standard
    // qualnet to verify.
    serverPtr->protocol = APP_SUPERAPPLICATION_SERVER;

    // Register the application
    APP_RegisterNewApp(node, APP_SUPERAPPLICATION_SERVER, serverPtr,
                       serverPtr->destinationPort);

    // Make sure all parameter values are valid
    if (serverPtr->processReply == TRUE)
    {
        SuperApplicationServerValidateParam(
            node,
            serverPtr,
            isDestinationPort);
    }
    if (SUPERAPPLICATION_DEBUG_PORTS)
    {
        printf (" Server node %d running on port %d \n",
                node->nodeId,
                serverPtr->destinationPort);
    }
}


// FUNCTION SuperApplicationScheduleNextReply_TCP
// PURPOSE  SuperApplication server process schedule next reply packet.
// Parameters:
//  node:   Pointer to the node
//  serverPtr:  Pointer to server state variable
static void SuperApplicationScheduleNextReply_TCP(Node* node,SuperApplicationData* serverPtr, clocktype delay) {
    SuperAppTimer* replyPacketTimer;
    Message* timerMsg = NULL;
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_SERVER,
                             MSG_APP_TimerExpired);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(replyPacketTimer));
    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connectionId (and not source port)
    // when TCP is being used. Designer uses this to distinguish between UDP/TCP
    // in SuperApplicationProcessEvent.
    replyPacketTimer->connectionId = serverPtr->connectionId;
    replyPacketTimer->sourcePort = 0;
    replyPacketTimer->type = APP_TIMER_SEND_PKT;
    replyPacketTimer->numRepToSend = serverPtr->randomRepPacketsToSendPerReq.getRandomNumber();
    replyPacketTimer->numRepSent= 0;
    replyPacketTimer->reqSeqNo = serverPtr->seqNo - 1;
    replyPacketTimer->lastReplyToSent = serverPtr->gotLastReqPacket;
    if (SUPERAPPLICATION_DEBUG_TIMER_SET_SERVER)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec Server scheduling timer for a NEW reply packet \n",
               clockStr);
        printf("    Connection :  S(%u:%u)->C(%u,%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("    Reply for  : %u req seq no \n",
               replyPacketTimer->reqSeqNo);
        TIME_PrintClockInSecond((delay + node->getNodeTime()), clockStr, node);
        printf("    Alarm time :  %s sec\n", clockStr);
        TIME_PrintClockInSecond(delay, clockStr);
        printf("    Interval   :  %s sec\n", clockStr);
    }

    //Trace sending packet
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, timerMsg, TRACE_APPLICATION_LAYER,
                     PACKET_OUT, &acnData);

    MESSAGE_Send(node, timerMsg, delay);
}


// FUNCTION SuperApplicationScheduleNextReply_UDP
// PURPOSE  SuperApplication server process schedule next reply packet.
// Parameters:
//  node:   Pointer to the node
//  serverPtr:  Pointer to server state variable
static void SuperApplicationScheduleNextReply_UDP(Node* node,SuperApplicationData* serverPtr) {
    SuperAppTimer* replyPacketTimer;
    clocktype delay;
    Message* timerMsg = NULL;
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_SERVER,
                             MSG_APP_TimerExpired);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(replyPacketTimer));
    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connection id to 0 when UDP is being
    // used. Designer uses this to distinguish between UDP/TCP.
    replyPacketTimer->connectionId = 0;
    replyPacketTimer->sourcePort = serverPtr->sourcePort;
    replyPacketTimer->address = serverPtr->clientAddr;
    replyPacketTimer->lastReplyToSent = serverPtr->gotLastReqPacket;
    replyPacketTimer->type = APP_TIMER_SEND_PKT;
    if (serverPtr->isVoice == FALSE){
        //serverPtr->randomRepPacketsToSendPerReq.setSeed(node->globalSeed);
        replyPacketTimer->numRepToSend = (Int32)
                                         serverPtr->randomRepPacketsToSendPerReq.getRandomNumber();
        replyPacketTimer->numRepSent= 0;
        replyPacketTimer->reqSeqNo = serverPtr->seqNo - 1;
        //serverPtr->randomRepInterval.setSeed(node->globalSeed);
        delay = serverPtr->randomRepInterval.getRandomNumber();
    }
    else {
        replyPacketTimer->numRepToSend = 0;
        replyPacketTimer->numRepSent = 0;
        replyPacketTimer->reqSeqNo = serverPtr->repSeqNo;
        delay = 0;
    }
    if (SUPERAPPLICATION_DEBUG_TIMER_SET_SERVER)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec Server scheduling timer for a NEW reply packet \n",
               clockStr);
        printf("    Connection :  S(%u:%u)->C(%u,%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("    Reply for  : %d req seq no \n",
               replyPacketTimer->reqSeqNo);
        TIME_PrintClockInSecond((delay + node->getNodeTime()), clockStr, node);
        printf("    Alarm time :  %s sec\n", clockStr);
        TIME_PrintClockInSecond(delay, clockStr);
        printf("    Interval   :  %s sec\n", clockStr);
    }

    //Trace sending packet
    ActionData acnData;
    acnData.actionType = SEND;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, timerMsg, TRACE_APPLICATION_LAYER,
                     PACKET_OUT, &acnData);

    MESSAGE_Send(node, timerMsg, delay);
}


// FUNCTION SuperApplicationClientReceivePacket_UDP
// PURPOSE  SuperApplication client process received repuest packet.
// Parameters:
//  node:   Pointer to the node
//  msg:    Pointer to received message
//  clientPtr:  Pointer to client state variable
static void SuperApplicationClientReceivePacket_UDP(Node* node,Message* msg,SuperApplicationData* clientPtr) {
    SuperApplicationUDPDataPacket *data;
    BOOL completePacketRvd = FALSE;
    char dataType = 0;

    // trace recd pkt
    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node, msg, TRACE_APPLICATION_LAYER, PACKET_IN, &acnData);

    //Extract the super application UDP header.

    data = (SuperApplicationUDPDataPacket *)MESSAGE_ReturnInfo(msg,
                                        INFO_TYPE_SuperAppUDPData);

#ifdef ADDON_DB
    AppMsgStatus msgStatus = APP_MSG_OLD;
    clocktype delay = node->getNodeTime() - data->txTime;
#endif // ADDON_DB

     if (clientPtr->isVoice == TRUE)
      {
        //Extract data type of UDP packet.
        memcpy(&dataType, MESSAGE_ReturnPacket(msg), sizeof(dataType));
        if (SUPERAPPLICATION_DEBUG_VOICE_RECV){
            char clockStr[24];
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : S(%u:%u)->C(%u:%u)\n",
                   MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                         clientPtr->serverAddr),
                   clientPtr->destinationPort,
                   node->nodeId,
                   clientPtr->sourcePort);
            printf("    At %s sec, Client receive voice packet:\n", clockStr);
            printf("    Voice Packet type is: %c\n", dataType);
            printf("    Voice Packet Size is: %d\n", MESSAGE_ReturnPacketSize(msg));
        }
    }


    UInt64 fragSize = MESSAGE_ReturnPacketSize(msg);
    if (node->appData.appStats)
    {
        if (!clientPtr->stats.appStats->IsSessionStarted(STAT_Unicast))
        {
            clientPtr->stats.appStats->SessionStart(node);
        }

        clientPtr->stats.appStats->AddFragmentReceivedDataPoints(
            node,
            msg,
            MESSAGE_ReturnPacketSize(msg),
            STAT_Unicast);

        clientPtr->stats.appStats->AddMessageReceivedDataPoints(
            node,
            msg,
            0,
            MESSAGE_ReturnPacketSize(msg),
            0,
            STAT_Unicast);
    }
    clientPtr->stats.numRepFragsRcvd += 1;
    clientPtr->stats.numRepFragsRcvdOutOfSeq += 1;
    clientPtr->totalEndToEndDelayForRep += (double)
        (node->getNodeTime() - data->txTime) / SECOND;
    // Calculate jitter

    clocktype now = node->getNodeTime();
    clocktype interArrivalInterval;
    interArrivalInterval = now -
        data->txTime;
    // Jitter can only be measured after receiving
    // 2 fragments.

    if (clientPtr->stats.numRepFragsRcvd > 1)
    {
        clocktype jitter = interArrivalInterval -
            clientPtr->lastRepInterArrivalInterval;
        // get absolute value of jitter.
        if (jitter < 0) {
            jitter = -jitter;
        }
        if (clientPtr->stats.numRepFragsRcvd == 2)
        {
            clientPtr->actJitterForRep = jitter;
        }
        else
        {
            clientPtr->actJitterForRep += static_cast<clocktype>(
               ((double)jitter - clientPtr->actJitterForRep) / 16.0);
        }
        clientPtr->totalJitterForRep += clientPtr->actJitterForRep;
    }
    clientPtr->lastRepInterArrivalInterval = interArrivalInterval;

    clientPtr->lastRepFragRcvTime = node->getNodeTime();
    if (clientPtr->stats.numRepFragBytesRcvd == 0) {
        clientPtr->firstRepFragRcvTime =
            clientPtr->lastRepFragRcvTime;
    }

    clientPtr->stats.numRepFragBytesRcvd += fragSize;
    clientPtr->stats.numRepPacketBytesRcvdThisPacket += fragSize;

    if (clientPtr->lastRepFragRcvTime > clientPtr->firstRepFragRcvTime)
    {
        clientPtr->stats.repRcvdThroughput = (double)
                                             ((double)(clientPtr->stats.numRepFragBytesRcvd * 8 * SECOND)
                                             / (clientPtr->lastRepFragRcvTime - clientPtr->firstRepFragRcvTime));
    }

    if (SUPERAPPLICATION_DEBUG_REP_REC)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client received reply fragment with:\n",
               clockStr);
        printf("    Connection                     : S(%u:%u)->C(%u:%u)\n",
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clientPtr->serverAddr),
               clientPtr->destinationPort,
               node->nodeId,
               clientPtr->sourcePort);
        TIME_PrintClockInSecond(data->txTime, clockStr, node);
        printf("    Fragment seq number            : %d \n",data->seqNo);
        printf("    Fragment no                    : %d \n",data->fragNo);
        printf("    TxTime                         : %s s \n",clockStr);
        printf("    Total fragments                : %d \n",data->totFrag);
        printf("    Bytes in this fragment         : %d \n",
               MESSAGE_ReturnPacketSize(msg));
        printf("New Client stats are: \n");
        printf("    No. rep frag received          : %f \n",
               (Float64)clientPtr->stats.numRepFragsRcvd);
        printf("    No. rep frag bytes received    : %f \n",
               (Float64)clientPtr->stats.numRepFragBytesRcvd);
    }
    if ((data->seqNo == clientPtr->repSeqNo
            && data->fragNo == clientPtr->repFragNo)
            || (data->seqNo > clientPtr->repSeqNo
                && data->fragNo == 0)
            || data->isMdpEnabled)
    {
#ifdef ADDON_DB
        StatsDb* db = node->partitionData->statsDb;
        msgStatus = APP_MSG_NEW;
#endif // ADDON_DB

        if (data->fragNo == 0)
        {
            clientPtr->repFragNo = 0;
        }
        if (clientPtr->repFragNo == data->totFrag - 1)
        {
            // Complete rep packet received
            clientPtr->stats.numRepPacketsRcvd++;
            clientPtr->stats.numRepCompletePacketBytesRcvd
                += data->totalMessageSize;
            clocktype packetDelay = node->getNodeTime() - data->txTime;
            clientPtr->totalEndToEndDelayForRepPacket +=
                (double)packetDelay / SECOND;

            // Update Packet Jitter

            clocktype now = node->getNodeTime();
            clocktype interArrivalInterval;
            interArrivalInterval = now - data->txTime;
            // Jitter can only be measured after receiving
            // 2 fragments.
            if (clientPtr->stats.numRepPacketsRcvd > 1)
            {
                clocktype jitter = interArrivalInterval -
                    clientPtr->lastRepInterArrivalIntervalPacket;
                // get absolute value of jitter.
                if (jitter < 0) {
                    jitter = -jitter;
                }
                if (clientPtr->stats.numRepPacketsRcvd == 2)
                {
                    clientPtr->actJitterForRepPacket = jitter;
                }
                else
                {
                    clientPtr->actJitterForRepPacket += static_cast<clocktype>(
                       ((double)jitter - clientPtr->actJitterForRepPacket) / 16.0);
                }
                clientPtr->totalJitterForRepPacket += clientPtr->actJitterForRepPacket;
            }
            clientPtr->lastRepInterArrivalIntervalPacket = interArrivalInterval;

            clientPtr->lastRepPacketRcvTime = node->getNodeTime();
            if (clientPtr->stats.numRepPacketsRcvd == 1) {
                clientPtr->firstRepPacketRcvTime =
                    clientPtr->lastRepPacketRcvTime;
            }

            clientPtr->stats.numRepPacketBytesRcvd +=
                clientPtr->stats.numRepPacketBytesRcvdThisPacket;
            clientPtr->stats.numRepPacketBytesRcvdThisPacket = 0;

            // NOTE: throughput is only  tracked for nodes on the same partition
            if (clientPtr->lastRepPacketRcvTime > clientPtr->firstRepPacketRcvTime) {
                clientPtr->stats.repRcvdThroughputPacket = (double)
                    ((double)(clientPtr->stats.numRepPacketBytesRcvd * 8 * SECOND)
                             / (clientPtr->lastRepPacketRcvTime - clientPtr->firstRepPacketRcvTime));
                if (clientPtr->isChainId) {
                    clientPtr->stats.chainTputWithTrigger =
                        (double)((clientPtr->stats.numRepPacketBytesRcvd * 8 * SECOND)
                                 / (clientPtr->lastRepPacketRcvTime - clientPtr->firstRepPacketRcvTime +
                                    data->triggerDelay));
                }
            }
            if (data->isLastPacket && node->appData.appStats)
            {
                if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
                {
                    if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                    {
                        clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                    }
                }
                else
                {
                    if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                    {
                        clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                    }
                }
            }

#ifdef ADDON_DB
           if (db != NULL)
           {
               if (node->partitionData->statsDb->statsAppEvents->recordFragment)
               {
                   std::vector<frag_Info>::iterator it;
                   it = clientPtr->fragCache.begin();
                   while (it != clientPtr->fragCache.end())
                   {
                       frag_Info fragInfo;
                       fragInfo = *it;
                       if (data->seqNo > clientPtr->repSeqNo)
                       {
                           if (clientPtr->prevMsgRecvdComplete == TRUE)
                           {
                               //do nothing
                           }
                           else if (clientPtr->prevMsgRecvdComplete == FALSE)
                           {

                               HandleStatsDBAppDropEventsInsertion(
                                   node, fragInfo.fragMsg, (char*)"AppDrop",
                                   fragInfo.fragDelay, fragInfo.fragSize, 
                                   (char*)"Not Enough Fragments Received "
                                   "For Reassembly");
                           }
                       }

                       MESSAGE_Free(node, fragInfo.fragMsg);
                       it++;
                   }
                   clientPtr->fragCache.clear();
               }
               else
               {
                   if (clientPtr->prevMsg != NULL)
                   {
                       if (data->seqNo > clientPtr->repSeqNo)
                       {
                           if (clientPtr->prevMsgRecvdComplete == TRUE)
                           {
                               //do nothing
                           }
                           else if (clientPtr->prevMsgRecvdComplete == FALSE)
                           {
                               HandleStatsDBAppDropEventsInsertion(
                                   node,clientPtr->prevMsg, (char*)"AppDrop",
                                   -1, clientPtr->prevMsgSize, 
                                   (char*)"Not Enough Fragments Received For "
                                   "Reassembly");
                           }
                       }
                       MESSAGE_Free(node, clientPtr->prevMsg);
                       clientPtr->prevMsg = NULL;
                   }
               }
           }

#endif
            // Expect the new packet
            clientPtr->repSeqNo = data->seqNo + 1;
            clientPtr->repFragNo = 0;
            // Subtract the fragments received in order
            clientPtr->stats.numRepFragsRcvdOutOfSeq -= data->totFrag;
            completePacketRvd = TRUE;

#ifdef ADDON_BOEINGFCS
            if (data->txPartitionId == node->partitionId
                    || TRACK_REALTIME_DIFFERENT_PARTITION)
            {
                SuperApplicationHandleRealTimeStats(
                    node,
                    data->txPartitionId == node->partitionId,
                    clientPtr,
                    (char*) "SuperApp-UDP-client",
                    clientPtr->serverAddr,
                    clientPtr->clientAddr,
                    clientPtr->sourcePort,
                    data->seqNo,
                    data->txRealTime,
                    data->txCpuTime,
                    data->txTime,
                    clientPtr->stats.numRepFragsRcvd);
            }
#endif /* ADDON_BOEINGFCS */

        }
        else if (data->seqNo > clientPtr->repSeqNo
                && data->fragNo == 0)
       {
           //This is the first fragment of next packet
           //Expect the next fragment of this packet
#ifdef ADDON_DB
           if (db != NULL)
           {
               if (!node->partitionData->statsDb->statsAppEvents->recordFragment)
               {
                   if (clientPtr->prevMsg != NULL)
                   {
                       HandleStatsDBAppDropEventsInsertion(
                           node,clientPtr->prevMsg,
                           (char*) "AppDrop",-1, clientPtr->prevMsgSize, 
                           (char*) "Not Enough Fragments Received For "
                           "Reassembly");
                       MESSAGE_Free(node, clientPtr->prevMsg);
                       clientPtr->prevMsg = NULL;
                   }
                   clientPtr->prevMsg = MESSAGE_Duplicate(node, msg);
                   clientPtr->prevMsgSize = data->totalMessageSize;
                   clientPtr->prevMsgRecvdComplete = completePacketRvd;
               }
               else
               {
                   std::vector<frag_Info>::iterator it;
                   it = clientPtr->fragCache.begin();
                   while (it != clientPtr->fragCache.end())
                   {
                       frag_Info fragInfo;
                       fragInfo = *it;
                       HandleStatsDBAppDropEventsInsertion(
                           node,fragInfo.fragMsg,
                           (char*) "AppDrop",fragInfo.fragDelay, 
                           fragInfo.fragSize, 
                           (char*) "Not Enough Fragments Received For Reassembly");
                       MESSAGE_Free(node, fragInfo.fragMsg);
                       it++;
                   }
                   clientPtr->fragCache.clear();
                   frag_Info fragmentInfo;
                   fragmentInfo.fragMsg = MESSAGE_Duplicate(node, msg);
                   fragmentInfo.fragSize = MESSAGE_ReturnPacketSize(msg);
                   fragmentInfo.fragDelay = delay;
                   clientPtr->fragCache.push_back(fragmentInfo);
                   clientPtr->prevMsgRecvdComplete = completePacketRvd;
               }
           }
#endif
            clientPtr->repSeqNo = data->seqNo;
            clientPtr->repFragNo++;
       }
        else
        {
            // Expect next fragment
#ifdef ADDON_DB
            if (db != NULL)
            {
                if (node->partitionData->statsDb->statsAppEvents->recordFragment)
                {
                    frag_Info fragmentInfo;
                    fragmentInfo.fragMsg = MESSAGE_Duplicate(node, msg);
                    fragmentInfo.fragSize = MESSAGE_ReturnPacketSize(msg);
                    fragmentInfo.fragDelay = delay;
                    clientPtr->fragCache.push_back(fragmentInfo);
                    clientPtr->prevMsgRecvdComplete = completePacketRvd;
                }
                else
                {
                    if (clientPtr->prevMsg != NULL)
                    {
                        MESSAGE_Free(node, clientPtr->prevMsg);
                        clientPtr->prevMsg = NULL;
                    }
                    clientPtr->prevMsg = MESSAGE_Duplicate(node, msg);
                    clientPtr->prevMsgSize = data->totalMessageSize;
                    clientPtr->prevMsgRecvdComplete = completePacketRvd;
                }
            }
#endif
            clientPtr->repFragNo++;
        }
    }
    if (SUPERAPPLICATION_DEBUG_REP_REC)
    {
        printf("    No. rep packets received       : %f \n",
               (Float64)clientPtr->stats.numRepPacketsRcvd);
    }
    if (clientPtr->isVoice){
        // cancel self timer if any.
        if (clientPtr->talkTimeOut != NULL){
            MESSAGE_CancelSelfMsg(node, clientPtr->talkTimeOut);
            clientPtr->talkTimeOut =  NULL;
        }
        // schedule to talk back.
        if (dataType == 'o')
        {
            // if it is already talking, don't start talking again
            if (clientPtr->isTalking == FALSE){
                clientPtr->isJustMyTurnToTalk = TRUE;
                SuperApplicationClientScheduleNextVoicePacket_UDP(node, clientPtr);
            }
        }

    }

// STATS DB CODE
#ifdef ADDON_DB
    // Set the session Id
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL)
    {
        if (!node->partitionData->statsDb->statsAppEvents->recordFragment)
        {
            if (completePacketRvd || data->totFrag == 1)
            {
                APP_ReportStatsDbReceiveEvent(
                    node,
                    msg,
                    &(clientPtr->msgSeqCache),
                    data->seqNo,
                    delay,
                    clientPtr->actJitterForRepPacket,
                    data->totalMessageSize,
                    clientPtr->stats.numRepPacketsRcvd,
                    msgStatus);
            }
        }
        else
        {
            APP_ReportStatsDbReceiveEvent(
                node,
                msg,
                &(clientPtr->fragSeqCache),
                data->uniqueFragNo,
                delay,
                clientPtr->actJitterForRep,
                MESSAGE_ReturnPacketSize(msg),
                clientPtr->stats.numRepFragsRcvd,
                msgStatus);
        }

        // Hop Count stats.
        StatsDBNetworkEventParam* ipParamInfo;
        ipParamInfo = (StatsDBNetworkEventParam*)
                MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

        if (ipParamInfo == NULL)
        {
                printf ("ERROR: We should have Network Events Info");
        }
        else
        {
                clientPtr->stats.hopCount += (int) ipParamInfo->m_HopCount;
        }
    }
#endif


    // Free the message
    MESSAGE_Free(node, msg);
}


// FUNCTION SuperApplicationServerProcessFragRcvd_TCP
// PURPOSE  Process the received fragment.
// Parameters:
//  node:   Pointer to the node
//  serverPtr:  Pointer to server state variable
//  appFileIndex:   Index in the application file of this application
static void SuperApplicationServerProcessFragRcvd_TCP(Node* node,SuperApplicationData* serverPtr,SuperApplicationTCPDataPacket *data) {
    if (serverPtr->stats.numReqFragsRcvd == 0)
    {
        // First fragment received. Init server
        NodeInput appInput;
        BOOL retVal;
        serverPtr->firstReqFragRcvTime = node->getNodeTime();
        NodeInput*  nodeInput = node->partitionData->nodeInput;
        IO_ReadCachedFile(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "APP-CONFIG-FILE",
            &retVal,
            &appInput);
        if (retVal == FALSE)
        {
            ERROR_ReportError("SuperApplication: Unable to read "
                "APP-CONFIG-FILE for server.\n");
        }
    }
    serverPtr->stats.numReqFragsRcvd++;


    clocktype now = node->getNodeTime();
    clocktype interArrivalInterval;
    interArrivalInterval = now - data->txTime;
    // Jitter can only be measured after receiving
    // 2 fragments.
    if (serverPtr->stats.numReqFragsRcvd > 1)
    {
        clocktype jitter = interArrivalInterval -
            serverPtr->lastReqInterArrivalInterval;
        // get absolute value of jitter.
        if (jitter < 0) {
            jitter = -jitter;
        }
        if (serverPtr->stats.numReqFragsRcvd == 2)
        {
            serverPtr->actJitterForReq = jitter;
        }
        else
        {
            serverPtr->actJitterForReq += static_cast<clocktype>(
              ((double)jitter - serverPtr->actJitterForReq) / 16.0);
        }
        serverPtr->totalJitterForReq += serverPtr->actJitterForReq;
    }
    /*if (node->appData.jitterPerDescriptorStats &&
    strlen(serverPtr->applicationName)>0 &&
    foundJElement!=NULL)
    {
    char tstr[MAX_STRING_LENGTH];
    TIME_PrintClockInSecond(now, tstr);
    foundJElement->totalJitter += jitter;
    }*/
    serverPtr->lastReqInterArrivalInterval = interArrivalInterval;


    // TODO: take care of DP here?
    serverPtr->lastReqFragRcvTime = node->getNodeTime();
    if (serverPtr->lastReqFragRcvTime > serverPtr->firstReqFragRcvTime)
        serverPtr->stats.reqRcvdThroughput = (double)((double)(serverPtr->stats.numReqFragBytesRcvd * 8 * SECOND)
                                             / (serverPtr->lastReqFragRcvTime - serverPtr->firstReqFragRcvTime));
}


// FUNCTION SuperApplicationServerReceivePacket_TCP
// PURPOSE  SuperApplication server process the received request packet.
// Parameters:
//  node:   Pointer to the node
//  msg:    Pointer to received message
//  serverPtr:  Pointer to server state variable
static void SuperApplicationServerReceivePacket_TCP(Node* node,Message* msg,SuperApplicationData* serverPtr) {
    BOOL completePacketRvd;
    BOOL completeFragmentRvd;
    int packetSize;
    int headerSize;
    Int32 totalBytesRead,totalFragBytesRead;
    char *packet;
    char *tmpBuffer;
    char *tmpFragmentBuffer;
    packet = (char *) MESSAGE_ReturnPacket(msg);
    packetSize = MESSAGE_ReturnPacketSize(msg);
    headerSize = sizeof(SuperApplicationTCPDataPacket);
    totalBytesRead = serverPtr->bufferSize + packetSize;
    totalFragBytesRead = serverPtr->fragmentBufferSize + packetSize;
    serverPtr->stats.numReqFragBytesRcvd += packetSize;
    serverPtr->stats.numReqPacketBytesRcvdThisPacket += packetSize;
    ERROR_Assert(MESSAGE_ReturnVirtualPacketSize(msg) == 0,
                "SuperApplication: Data should not be sent as virtual data");

    if (SUPERAPPLICATION_DEBUG_REQ_REC)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server received fragment from TCP with \n",
               clockStr);
        printf("    Connection                              : C"
               "(%u:%u)->S(%u:%u)\n",
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort,
               node->nodeId,
               serverPtr->destinationPort);
        printf("    Total bytes received till now           : %f\n",
               (Float64)serverPtr->stats.numReqFragBytesRcvd);
        printf("    Bytes received from TCP                 : %u\n",
               packetSize);
    }

    // extract the info field.
    int numFrags = 0;
#ifdef ADDON_DB
    int lowerLimit = 0;
    int upperLimit = 0;
#endif
    int countInfo = 0;
    numFrags = MESSAGE_ReturnNumFrags(msg);

    // Update the packet buffer
    // tmpBuffer will contain contents of buffer and current packet.

    tmpBuffer = (char *) MEM_malloc(totalBytesRead);
    memset(tmpBuffer,0,totalBytesRead);

    if (serverPtr->bufferSize > 0)
    {
        memcpy(tmpBuffer, serverPtr->buffer, serverPtr->bufferSize);
        MEM_free(serverPtr->buffer);
    }

// Make sure whether the below code section is really required for ADDON_DB
#ifdef ADDON_DB
    else
    {
        // First Packet.
        lowerLimit = msg->infoBookKeeping.at(countInfo).infoLowerLimit;
        upperLimit = msg->infoBookKeeping.at(countInfo).infoUpperLimit;

        serverPtr->upperLimit.push_back(upperLimit - lowerLimit);
        for (int k = lowerLimit; k < upperLimit; k++)
        {
            MessageInfoHeader infoHdr;
            infoHdr.infoSize = msg->infoArray.at(k).infoSize;
            infoHdr.infoType = msg->infoArray.at(k).infoType;
            infoHdr.info = (char*) MEM_malloc(infoHdr.infoSize);
            memcpy(infoHdr.info, msg->infoArray.at(k).info, infoHdr.infoSize);
            serverPtr->tcpInfoField.push_back(infoHdr);
        }
    }
#endif

    if (packetSize > 0)
    {
        // Packet contains real (non-virtual) data
        // Copy real data into buffer
        memcpy(tmpBuffer + (serverPtr->bufferSize), packet, packetSize);
    }

    // Free the buffer after reading the buffer + packet in tempBuffer
    // Update the fragment buffer
    // tmpFragmentBuffer will contain contents of the fragment being received.

    tmpFragmentBuffer = (char *) MEM_malloc(totalFragBytesRead);
    memset(tmpFragmentBuffer,0,totalFragBytesRead);

    if (serverPtr->fragmentBufferSize > 0)
    {
        memcpy(tmpFragmentBuffer, serverPtr->fragmentBuffer, serverPtr->fragmentBufferSize);
        MEM_free(serverPtr->fragmentBuffer);
    }

    if (packetSize > 0)
    {
        // Packet contains real (non-virtual) data
        // Copy real data into buffer
        memcpy(tmpFragmentBuffer + (serverPtr->fragmentBufferSize), packet, packetSize);
    }

    serverPtr->fragmentBufferSize = totalFragBytesRead;
    completeFragmentRvd = TRUE; // Assume complete req fragment received

    // Check if we have the whole fragment
    while (totalFragBytesRead > 0 && (completeFragmentRvd == TRUE))
    {
        //Extract the super application TCP header.
        SuperApplicationTCPDataPacket *header;
        header = (SuperApplicationTCPDataPacket *)MESSAGE_ReturnInfo(msg,
                                    INFO_TYPE_SuperAppTCPData,countInfo);

        int remainingFragBufferSize;
        if (SUPERAPPLICATION_DEBUG_REQ_REC)
        {
            printf("    Bytes received for this frag            : %d"
                   " of %d \n",
                   totalFragBytesRead,
                   header->totalFragmentBytes);
            printf("    Fragment no                             : %d \n",header->fragNo);
        }

        if (totalFragBytesRead >= header->totalFragmentBytes)
        {
            // Complete fragment received
            remainingFragBufferSize = totalFragBytesRead - header->totalFragmentBytes;
            // Complete Application layer fragment received. Several fragments
            // obtained from TCP may constitute one application layer fragment
            // (decided by FRAGMENTATION_UNIT provided to SuperApplication.
            // Alternatively several Application layer fragments may be received
            // together from TCP
            SuperApplicationServerProcessFragRcvd_TCP(node,serverPtr,header);
            if (SUPERAPPLICATION_DEBUG_REQ_REC)
            {
                printf("    Status                                  : Complete fragment received.\n");
            }
            if (remainingFragBufferSize > 0)
            {
                char* tmpFragmentBuffer2;
                tmpFragmentBuffer2 = (char *) MEM_malloc(remainingFragBufferSize);
                memcpy(tmpFragmentBuffer2,
                       tmpFragmentBuffer + header->totalFragmentBytes,
                       remainingFragBufferSize);
                MEM_free(tmpFragmentBuffer);
                tmpFragmentBuffer = tmpFragmentBuffer2;

                // For the info field
                countInfo++;

// Make sure whether the below code section is really required for ADDON_DB
#ifdef ADDON_DB
                if (countInfo < (int) msg->infoBookKeeping.size())
                {
                    lowerLimit = msg->infoBookKeeping.at(countInfo).infoLowerLimit;
                    upperLimit = msg->infoBookKeeping.at(countInfo).infoUpperLimit;

                    serverPtr->upperLimit.push_back(upperLimit - lowerLimit);
                    for (int k = lowerLimit; k < upperLimit; k++)
                    {
                        MessageInfoHeader infoHdr;
                        infoHdr.infoSize = msg->infoArray.at(k).infoSize;
                        infoHdr.infoType = msg->infoArray.at(k).infoType;
                        infoHdr.info = (char*) MEM_malloc(infoHdr.infoSize);
                        memcpy(infoHdr.info, msg->infoArray.at(k).info, infoHdr.infoSize);
                        serverPtr->tcpInfoField.push_back(infoHdr);
                    }
                }
#endif
            }
            else
            {
                ERROR_Assert(remainingFragBufferSize == 0,
                             "SuperApplication: remaining bytes can not be negative");
                MEM_free(tmpFragmentBuffer);
                tmpFragmentBuffer = NULL;
            }

            serverPtr->fragmentBufferSize = remainingFragBufferSize;

            clocktype delay = node->getNodeTime() - header->txTime;
#ifdef ADDON_BOEINGFCS
            serverPtr->maxEndToEndDelayForReq = MAX(delay , serverPtr->maxEndToEndDelayForReq);
            serverPtr->minEndToEndDelayForReq = MIN(delay , serverPtr->minEndToEndDelayForReq);
#endif
            serverPtr->totalEndToEndDelayForReq += (double)delay / SECOND;

            // Update bytes read of next fragment
            totalFragBytesRead = remainingFragBufferSize;

            if (header->fragNo == 0) {
                serverPtr->packetSentTime = header->txTime;
            }

        }
        else
        {
            if (SUPERAPPLICATION_DEBUG_REQ_REC)
            {
                printf("    Status                                  : Complete fragment not received.\n");
            }
            // Not enough to make a packet yet
            // (header, but not enough payload)
            completeFragmentRvd = FALSE;
        }

        if (SUPERAPPLICATION_DEBUG_REQ_REC)
        {
            if (totalFragBytesRead >= headerSize && (completeFragmentRvd == TRUE))
                printf("Processing next fragment \n");
            if ((totalFragBytesRead >0) && (totalFragBytesRead < headerSize))
                printf("Header for next fragment not received yet.\n");
        }
    }

    if (serverPtr->fragmentBufferSize > 0)
    {
        serverPtr->fragmentBuffer = (char *) MEM_malloc(serverPtr->fragmentBufferSize);
        memset(serverPtr->fragmentBuffer,0,serverPtr->fragmentBufferSize);
        memcpy(serverPtr->fragmentBuffer,
               tmpFragmentBuffer ,
               serverPtr->fragmentBufferSize);
    }
    if (tmpFragmentBuffer)
    {
        MEM_free(tmpFragmentBuffer);
        tmpFragmentBuffer = NULL;
    }

    serverPtr->bufferSize = totalBytesRead;
    completePacketRvd = TRUE; // Assume complete req packet received
    countInfo = -1;
    BOOL statsUpdated = FALSE;

    while (totalBytesRead > 0 && (completePacketRvd == TRUE))
    {
        countInfo++;
        //Extract the super application TCP header.
        SuperApplicationTCPDataPacket *header;
        header = (SuperApplicationTCPDataPacket *)MESSAGE_ReturnInfo(msg,
                                    INFO_TYPE_SuperAppTCPData,countInfo);

        int remainingBufferSize = 0;
        if (SUPERAPPLICATION_DEBUG_REQ_REC)
        {
            printf("    Bytes received for this packet          : %u "
                   " of %d \n",
                   totalBytesRead,
                   header->totalPacketBytes);
            printf("    Sequence Number of this packet          : %u "
                   "\n",
                   header->seqNo);
        }
        if (node->appData.appStats)
        {
            if (!serverPtr->stats.appStats)
            {
                Address lAddr;
                Address rAddr;
                // setting addresses
                SetIPv4AddressInfo(&lAddr, serverPtr->clientAddr);
                SetIPv4AddressInfo(&rAddr, serverPtr->serverAddr);

                std::string customName;
                if (serverPtr->applicationName == NULL)
                {
                    customName = "Super-App Server";
                }
                else
                {
                    customName = serverPtr->applicationName;
                }

                serverPtr->stats.appStats = new STAT_AppStatistics(
                    node,
                    "SUPER-APP Server",
                    STAT_Unicast,
                    STAT_AppSenderReceiver,
                    customName.c_str());
                serverPtr->stats.appStats->Initialize(
                    node,
                    lAddr,
                    rAddr,
                    STAT_AppStatistics::GetSessionId(msg),
                    serverPtr->uniqueId);
                serverPtr->stats.appStats->SessionStart(node);
                serverPtr->stats.appStats->EnableAutoRefragment();
            }

            if (!statsUpdated)
            {
                serverPtr->stats.appStats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Unicast);
                statsUpdated = TRUE;
            }
        }
        if (totalBytesRead >= header->totalPacketBytes)
        {
            // Complete packet received
            remainingBufferSize = totalBytesRead - header->totalPacketBytes;
            if (SUPERAPPLICATION_DEBUG_REQ_REC)
            {
                printf("    Status                                  : "
                       "Complete packet rcvd. Also, %d bytes of next packet/frag rcvd.\n",remainingBufferSize);
            }
            if (remainingBufferSize > 0)
            {
                char* tmpBuffer2;
                tmpBuffer2 = (char *) MEM_malloc(remainingBufferSize);
                memcpy(tmpBuffer2,
                       tmpBuffer + header->totalPacketBytes,
                       remainingBufferSize);
                MEM_free(tmpBuffer);
                tmpBuffer = tmpBuffer2;
            }
            else
            {
                ERROR_Assert(remainingBufferSize == 0,
                             "SuperApplication: remaining bytes can not be negative");
                MEM_free(tmpBuffer);
                tmpBuffer = NULL;
            }

            // Expect the new packet
            serverPtr->seqNo ++;
            serverPtr->bufferSize = remainingBufferSize;

            clocktype packetDelay = node->getNodeTime() - header->txTime;

#ifdef ADDON_NGCNMS0
            clocktype sent = -1;
            char* sentChar = MESSAGE_ReturnInfo(msg,
                                                INFO_TYPE_SendTime);
            if (sentChar != NULL) {
                sent = *((clocktype*)sentChar);
            }
            packetDelay = node->getNodeTime() - sent;
#endif
#ifdef ADDON_DB
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL)
            {
                StatsDBAppEventParam* appParamInfo = NULL;
                appParamInfo = (StatsDBAppEventParam*)
                        MESSAGE_ReturnInfo(msg, INFO_TYPE_AppStatsDbContent);
                if (appParamInfo == NULL)
                {
                    ERROR_ReportWarning("SuperApplication: Unable to find Application Layer Stats Info Field\n");
                    return;
                }
                serverPtr->sessionId = appParamInfo->m_SessionId;
                serverPtr->sessionInitiator = appParamInfo->m_SessionInitiator;
                // copy application name as the session ID in app name is not known to
                // server before recieving the first packet.
                strcpy(serverPtr->applicationName, appParamInfo->m_ApplicationName);
                if (appParamInfo->m_PktCreationTimeSpecified)
                {
                    packetDelay = node->getNodeTime() - appParamInfo->m_PktCreationTime;
                }
            }
#endif
            serverPtr->maxEndToEndDelayForReqPacket =
                MAX(packetDelay , serverPtr->maxEndToEndDelayForReqPacket);

            serverPtr->minEndToEndDelayForReqPacket =
                MIN(packetDelay , serverPtr->minEndToEndDelayForReqPacket);

            serverPtr->totalEndToEndDelayForReqPacket +=
                (double)packetDelay / SECOND;

            if (serverPtr->stats.numReqPacketBytesRcvd == 0) {
                serverPtr->firstReqPacketRcvTime = node->getNodeTime();

            }
            serverPtr->stats.numReqPacketsRcvd++;
            serverPtr->stats.numReqCompletePacketBytesRcvd +=
                totalBytesRead - remainingBufferSize ;

            // trace recd pkt
            ActionData acnData;
            acnData.actionType = RECV;
            acnData.actionComment = NO_COMMENT;
            TRACE_PrintTrace(node,
                             msg,
                             TRACE_APPLICATION_LAYER,
                             PACKET_IN,
                             &acnData);

            // Update Packet Jitter
            clocktype jitter = 0;
            clocktype now = node->getNodeTime();
            clocktype interArrivalInterval;
            interArrivalInterval = now - header->txTime;
            // Jitter can only be measured after receiving
            // 2 fragments.
            if (serverPtr->stats.numReqPacketsRcvd > 1)
            {
                jitter = interArrivalInterval -
                    serverPtr->lastReqInterArrivalIntervalPacket;
                // get absolute value of jitter.
                if (jitter < 0) {
                    jitter = -jitter;
                }
                if (serverPtr->stats.numReqPacketsRcvd == 2)
                {
                    serverPtr->actJitterForReqPacket = jitter;
                }
                else
                {
                    serverPtr->actJitterForReqPacket += static_cast<clocktype>(
                       ((double)jitter - serverPtr->actJitterForReqPacket) / 16.0);
                }
                serverPtr->totalJitterForReqPacket += serverPtr->actJitterForReqPacket;
            }
            serverPtr->lastReqInterArrivalIntervalPacket = interArrivalInterval;

            // Create the new message with the correct set of info fields.

// Make sure whether the below code section is really required for ADDON_DB
#ifdef ADDON_DB
            // Note, for TCP, there is no need to worry about
            // duplicate and out of order.
            db = node->partitionData->statsDb;
            if (db != NULL)
            {
                Message* newMsg;
                newMsg = MESSAGE_Duplicate(node, msg);
                // clean up the info field from the new message.
                for (unsigned int i = 0; i < newMsg->infoArray.size(); i++)
                {
                    MessageInfoHeader* hdr = &(newMsg->infoArray[i]);
                    MESSAGE_InfoFieldFree(node, hdr);
                }

                newMsg->infoArray.clear();
                if (!serverPtr->upperLimit.empty())
                {
                    for (int i = 0; i < serverPtr->upperLimit.front(); i++)
                    {
                        MessageInfoHeader infoHdr;
                        char* info;
                        infoHdr = serverPtr->tcpInfoField.at(i);
                        info = MESSAGE_AddInfo(
                                    node,
                                    newMsg,
                                    infoHdr.infoSize,
                                    infoHdr.infoType);
                        memcpy(info, infoHdr.info, infoHdr.infoSize);
                    }

                    // Clean up the info.
                    for (unsigned int i = 0;
                            i < (unsigned) serverPtr->upperLimit.front(); i++)
                    {
                        if (i >= serverPtr->tcpInfoField.size())
                        {
                            ERROR_ReportWarning("TCP Info field has less Infos that specified in BookKeeping\n");
                            break;
                        }
                        MessageInfoHeader* hdr = &(serverPtr->tcpInfoField[i]);
                        if (hdr->infoSize > 0)
                        {
                            MEM_free(hdr->info);
                            hdr->infoSize = 0;
                            hdr->info = NULL;
                            hdr->infoType = INFO_TYPE_UNDEFINED;
                        }
                    }

                    if (!serverPtr->tcpInfoField.empty())
                    {
                        serverPtr->tcpInfoField.erase(serverPtr->tcpInfoField.begin(),
                            serverPtr->tcpInfoField.begin() + serverPtr->upperLimit.front());
                    }

                    serverPtr->upperLimit.pop_front();
                }

                // only report event for completed messages
                // if record fragment is not enabled.
                if (!node->partitionData->statsDb->statsAppEvents->recordFragment)
                {
                    // Send the update to the database.
                    int NumreqMsgRcvd = serverPtr->stats.numReqPacketsRcvd;

                    HandleStatsDBAppReceiveEventsInsertion(node,
                        newMsg,
                        "AppReceiveFromLower",
                        packetDelay,
                        serverPtr->actJitterForReqPacket,
                        totalBytesRead - remainingBufferSize,
                        NumreqMsgRcvd);
                }
                else
                {
                    // Putting code for handling fragments here too as currently
                    // there is no support to app fragmentation for TCP mode.
                    // This code has to be moved up once that is supported.
                    HandleStatsDBAppReceiveEventsInsertion(
                        node,
                        newMsg,
                        "AppReceiveFromLower",
                        packetDelay,
                        serverPtr->actJitterForReq,
                        header->totalFragmentBytes,
                        serverPtr->stats.numReqFragsRcvd);
                }

                StatsDBNetworkEventParam* ipParamInfo = NULL;
                ipParamInfo = (StatsDBNetworkEventParam*)
                    MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

                if (ipParamInfo == NULL)
                {
                    printf ("ERROR: We should have Network Events Info");
                }
                else
                {
                    serverPtr->stats.hopCount += (int) ipParamInfo->m_HopCount;
                }

                // Free the new message created
                MESSAGE_Free(node, newMsg);
            }
#endif

            serverPtr->lastReqPacketRcvTime = node->getNodeTime();
            if ((Float64)(serverPtr->stats.numReqPacketsRcvd) == 1) {
                serverPtr->firstReqPacketRcvTime =
                    serverPtr->lastReqPacketRcvTime;
            }

            serverPtr->stats.numReqPacketBytesRcvd +=
                serverPtr->stats.numReqPacketBytesRcvdThisPacket;

            serverPtr->stats.numReqPacketBytesRcvdThisPacket = 0;

            serverPtr->lastReqPacketRcvTime = node->getNodeTime();
            if (serverPtr->lastReqPacketRcvTime > serverPtr->firstReqPacketRcvTime) {
                serverPtr->stats.reqRcvdThroughputPacket =
                    (double)((double)(serverPtr->stats.numReqPacketBytesRcvd * 8 * SECOND)
                             / (serverPtr->lastReqPacketRcvTime - serverPtr->firstReqPacketRcvTime));
            }

            totalBytesRead = remainingBufferSize;


#ifdef ADDON_BOEINGFCS
            if (node->getNodeTime() - header->txTime > 0
                    && (header->txPartitionId == node->partitionId
                        || TRACK_REALTIME_DIFFERENT_PARTITION))
            {
                clocktype elapsed;
                char type;

                SuperApplicationElapsedTime(
                    serverPtr,
                    header->txRealTime,
                    node->partitionData->wallClock->getRealTime(),
                    header->txCpuTime,
                    SuperApplicationCpuTime(serverPtr),
                    &elapsed,
                    &type);

                SuperApplicationHandleRealTimeStats(
                    node,
                    header->txPartitionId == node->partitionId,
                    serverPtr,
                    (char*) "SuperApp-TCP-server",
                    serverPtr->clientAddr,
                    serverPtr->serverAddr,
                    serverPtr->sourcePort,
                    header->seqNo,
                    header->txRealTime,
                    header->txCpuTime,
                    header->txTime,
                    serverPtr->stats.numReqFragsRcvd);
            }
#endif /* ADDON_BOEINGFCS */

            // update chain id list
            if (serverPtr->isChainId){
                SuperAppTriggerUpdateChain(node,
                                           1,
                                           serverPtr->chainID);
            }
            // Reply currently disabled for TCP
            if (header->isLastPacket)
            {
                serverPtr->gotLastReqPacket = TRUE;
                if (!serverPtr->processReply && node->appData.appStats)
                {
                    if (!serverPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                    {
                        serverPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                    }
                }
            }
            if (serverPtr->processReply == TRUE)
            {
                clocktype delay = serverPtr->randomRepInterval.getRandomNumber();
                SuperApplicationScheduleNextReply_TCP(node, serverPtr, delay);
            }


            // Check Clist list if any and trigger a session if conditions meet
            SuperAppClientList* clist = (SuperAppClientList*)node->appData.clientPtrList;
            unsigned int cindex = 0;
            for (cindex = 0; cindex < clist->clientList.size(); cindex++)
            {
                if (strcmp(serverPtr->chainID, clist->clientList[cindex].clientPtr->chainID) == 0)
                {
                    if (SuperAppCheckConditions(node, clist->clientList[cindex].clientPtr) == TRUE)
                    {
                        // start trigger the conditions session
                        clist->clientList[cindex].clientPtr->readyToSend = TRUE;

                        SuperAppTriggerSendMsg(
                            node,
                            clist->clientList[cindex].clientPtr,
                            clist->clientList[cindex].isSourcePort,
                            clist->clientList[cindex].randomDuration,
                            clist->clientList[cindex].isFragmentSize
#ifdef ADDON_BOEINGFCS
                            , clist->clientList[cindex].burstyKeywordFound
#endif /* ADDON_BOEINGFCS */
                            );
                    }
                }
            }

        }
        else
        {
            if (SUPERAPPLICATION_DEBUG_REQ_REC)
            {
                printf("    Status                                  : "
                       "Complete packet not rcvd.\n");
            }
            // Not enough to make a packet yet
            // (header, but not enough payload)
            completePacketRvd = FALSE;
        }
    }

    if (serverPtr->bufferSize > 0)
    {
        serverPtr->buffer = (char *) MEM_malloc(serverPtr->bufferSize);
        memset(serverPtr->buffer,0,serverPtr->bufferSize);
        memcpy(serverPtr->buffer,
               tmpBuffer ,
               serverPtr->bufferSize);
    }
    if (tmpBuffer)
    {
        MEM_free(tmpBuffer);
        tmpBuffer = NULL;
    }
}


// FUNCTION SuperApplicationServerReceivePacket_UDP
// PURPOSE  SuperApplication server process received request packet.
// Parameters:
//  node:   Pointer to the node
//  msg:    Pointer to received message
//  serverPtr:  Pointer to server state variable
static void SuperApplicationServerReceivePacket_UDP(Node* node,Message* msg,SuperApplicationData* serverPtr) {
    SuperApplicationUDPDataPacket *data;
    UdpToAppRecv* info;
    BOOL completePacketRvd = FALSE;
    char dataType = 0;
    clocktype jitter = 0;
#ifdef ADDON_DB
    AppMsgStatus msgStatus = APP_MSG_OLD;
#endif // ADDON_DB

    info = (UdpToAppRecv*)MESSAGE_ReturnInfo(msg);

    //Extract the super application UDP header.
    data = (SuperApplicationUDPDataPacket *)MESSAGE_ReturnInfo(msg,
        INFO_TYPE_SuperAppUDPData);

    // trace recd pkt
    ActionData acnData;
    acnData.actionType = RECV;
    acnData.actionComment = NO_COMMENT;
    TRACE_PrintTrace(node,
        msg,
        TRACE_APPLICATION_LAYER,
        PACKET_IN,
        &acnData);

    if (serverPtr->isVoice == TRUE)
    {
        //Extract data type of UDP packet.
        memcpy(&dataType, MESSAGE_ReturnPacket(msg), sizeof(dataType));

        if (SUPERAPPLICATION_DEBUG_VOICE_RECV) {
            char clockStr[24];
            TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
            printf("    Connection           : C(%u:%u)->S(%u:%u)\n",
                MAPPING_GetNodeIdFromInterfaceAddress(node,
                serverPtr->clientAddr),
                serverPtr->sourcePort,
                node->nodeId,
                serverPtr->destinationPort);
            printf("    At %s sec, Server receive voice packet:\n", clockStr);
            printf("    Voice Packet type is: %c\n", dataType);
            printf("    Voice Packet Size is: %d\n", MESSAGE_ReturnPacketSize(msg));
        }
    }
    if (serverPtr->stats.numReqFragsRcvd == 0)
    {
        // First packet received. Init server
        NodeInput appInput;
        BOOL retVal;
        int i;
        NodeInput*  nodeInput = node->partitionData->nodeInput;
        i = data->appFileIndex;
        IO_ReadCachedFile(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "APP-CONFIG-FILE",
            &retVal,
            &appInput);
        if (retVal == FALSE)
        {
            ERROR_ReportError("SuperApplication: Unable to read "
                "APP-CONFIG-FILE for server.\n");
        }

        if (node->appData.appStats)
        {
            std::string customName;
            if (serverPtr->applicationName == NULL)
            {
                customName = "Super-App Server";
            }
            else
            {
                customName = serverPtr->applicationName;
            }
            // Create statistics
            if (NetworkIpIsMulticastAddress(node,serverPtr->serverAddr))
            {
                serverPtr->stats.appStats = new STAT_AppStatistics(
                    node,
                    "SUPER-APP Server",
                    STAT_Multicast,
                    STAT_AppSenderReceiver,
                    customName.c_str());
            }
            else
            {
                serverPtr->stats.appStats = new STAT_AppStatistics(
                    node,
                    "SUPER-APP Server",
                    STAT_Unicast,
                    STAT_AppSenderReceiver,
                    customName.c_str());
            }

            serverPtr->stats.appStats->Initialize(
                node,
                info->sourceAddr,
                info->destAddr,
                STAT_AppStatistics::GetSessionId(msg),
                serverPtr->uniqueId);
            // Added to resolve bug# 5716
            serverPtr->stats.appStats->setTos(serverPtr->repTOS);
            serverPtr->stats.appStats->SessionStart(node);
        }
    }

    clocktype delay = node->getNodeTime() - data->txTime;
    if (serverPtr->fragNo == 0) {
        serverPtr->packetSentTime = data->txTime;
    }
    clocktype packetDelay = node->getNodeTime() - serverPtr->packetSentTime;

#ifdef ADDON_NGCNMS0
    clocktype sent = -1;
    char* sentChar = MESSAGE_ReturnInfo(msg,
        INFO_TYPE_SendTime);
    if (sentChar != NULL) {
        sent = *((clocktype*)sentChar);
    }
    delay = node->getNodeTime() - sent;
    if (serverPtr->fragNo == 0) {
        serverPtr->packetSentTime = sent;
    }
    packetDelay = node->getNodeTime() - serverPtr->packetSentTime;
#endif

    // Calculate jitter
#ifdef ADDON_BOEINGFCS
    if (data->txPartitionId == node->partitionId
        || !TRACK_STATISTICS_DIFFERENT_PARTITION)
    {
        clocktype curr = node->getNodeTime();
        serverPtr->maxEndToEndDelayForReq = MAX(delay , serverPtr->maxEndToEndDelayForReq);
        serverPtr->minEndToEndDelayForReq = MIN(delay , serverPtr->minEndToEndDelayForReq);
        serverPtr->totalEndToEndDelayForReq += (double)delay / SECOND;

        UInt64 fragSize = MESSAGE_ReturnPacketSize(msg);

        serverPtr->stats.numReqFragsRcvd += 1;
        serverPtr->stats.numReqFragsRcvdOutOfSeq += 1;


        clocktype now = node->getNodeTime();
        clocktype interArrivalInterval;
        interArrivalInterval = now -
            data->txTime;
        // Jitter can only be measured after receiving
        // 2 fragments.
        if (serverPtr->stats.numReqFragsRcvd > 1)
        {
            jitter = interArrivalInterval -
                serverPtr->lastReqInterArrivalInterval;
            // get absolute value of jitter.
            if (jitter < 0) {
                jitter = -jitter;
            }
            if (serverPtr->stats.numReqFragsRcvd == 2)
            {
                serverPtr->actJitterForReq = jitter;
            }
            else
            {
                serverPtr->actJitterForReq += static_cast<clocktype>(
                    ((double)jitter - serverPtr->actJitterForReq) / 16.0);
            }

            serverPtr->totalJitterForReq += serverPtr->actJitterForReq;
        }
        serverPtr->lastReqInterArrivalInterval = interArrivalInterval;

        serverPtr->lastReqFragRcvTime = node->getNodeTime();
        if (serverPtr->stats.numReqFragBytesRcvd == 0) {
            serverPtr->firstReqFragRcvTime =
                serverPtr->lastReqFragRcvTime;
        }
        serverPtr->stats.numReqFragBytesRcvd += fragSize;
        serverPtr->stats.numReqPacketBytesRcvdThisPacket += fragSize;

        // NOTE: throughput is only  tracked for nodes on the same partition
        if (serverPtr->lastReqFragRcvTime > serverPtr->firstReqFragRcvTime) {
            serverPtr->stats.reqRcvdThroughput = (double)((double)(serverPtr->stats.numReqFragBytesRcvd * 8 * SECOND)
                / (serverPtr->lastReqFragRcvTime - serverPtr->firstReqFragRcvTime));
            if (serverPtr->isChainId) {
                serverPtr->stats.chainTputWithTrigger = (double)((serverPtr->stats.numReqFragBytesRcvd * 8 * SECOND)
                    / (serverPtr->lastReqFragRcvTime - serverPtr->firstReqFragRcvTime +
                    data->triggerDelay));
            }
        }
    }
    else
    {
        serverPtr->maxEndToEndDelayForReqDP = MAX(delay , serverPtr->maxEndToEndDelayForReqDP);
        serverPtr->minEndToEndDelayForReqDP = MIN(delay , serverPtr->minEndToEndDelayForReqDP);
        serverPtr->totalEndToEndDelayForReqDP += (double)delay / SECOND;
        serverPtr->stats.numReqFragsRcvdDP += 1;
        /*serverPtr->stats.numReqFragsRcvdOutOfSeq += 1;
        serverPtr->stats.numReqFragBytesRcvd += MESSAGE_ReturnPacketSize(msg);
        if (serverPtr->stats.numReqFragsRcvd == 1)
        serverPtr->firstReqFragRcvTime = node->getNodeTime();*/

        clocktype now = node->getNodeTime();
        clocktype interArrivalInterval;
        interArrivalInterval = now -
            data->txTime;
        // Jitter can only be measured after receiving
        // 2 fragments.
        if (serverPtr->stats.numReqFragsRcvdDP > 1)
        {
            jitter = interArrivalInterval -
                serverPtr->lastReqInterArrivalIntervalDP;
            // get absolute value of jitter.
            if (jitter < 0) {
                jitter = -jitter;
            }
            if (serverPtr->stats.numReqFragsRcvdDP == 2)
            {
                serverPtr->actJitterForReqDP = jitter;
            }
            else
            {
                serverPtr->actJitterForReqDP += static_cast<clocktype>(
                    ((double)jitter - serverPtr->actJitterForReqDP) / 16.0);
            }
            serverPtr->totalJitterForReqDP += serverPtr->actJitterForReqDP;


        }
        serverPtr->lastReqInterArrivalIntervalDP = interArrivalInterval;

        serverPtr->lastReqFragRcvTimeDP = node->getNodeTime();
    }

#else /* ADDON_BOEINGFCS */

    UInt64 fragSize = MESSAGE_ReturnPacketSize(msg);
    serverPtr->totalEndToEndDelayForReq += (double)delay / SECOND;

    serverPtr->stats.numReqFragsRcvd += 1;
    serverPtr->stats.numReqFragsRcvdOutOfSeq += 1;

    if (data->isLastPacket)
    {
        serverPtr->gotLastReqPacket = TRUE;
        if (!serverPtr->processReply && node->appData.appStats)
        {
            if (NetworkIpIsMulticastAddress(node,serverPtr->serverAddr))
            {
                if (!serverPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                {
                    serverPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                }

            }
            else
            {
                if (!serverPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                {
                    serverPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                }
            }
        }
    }

    clocktype now = node->getNodeTime();
    clocktype interArrivalInterval;
    interArrivalInterval = now - data->txTime;
    // Jitter can only be measured after receiving
    // 2 fragments.
    if (serverPtr->stats.numReqFragsRcvd > 1)
    {
        jitter = interArrivalInterval -
            serverPtr->lastReqInterArrivalInterval;
        // get absolute value of jitter.
        if (jitter < 0) {
            jitter = -jitter;
        }
        if (serverPtr->stats.numReqFragsRcvd == 2)
        {
            serverPtr->actJitterForReq = jitter;
        }
        else
        {
            serverPtr->actJitterForReq += static_cast<clocktype>(
                ((double)jitter - serverPtr->actJitterForReq) / 16.0);
        }

        serverPtr->totalJitterForReq += serverPtr->actJitterForReq;
    }
    serverPtr->lastReqInterArrivalInterval = interArrivalInterval;

    serverPtr->lastReqFragRcvTime = node->getNodeTime();
    if (serverPtr->stats.numReqFragBytesRcvd == 0) {
        serverPtr->firstReqFragRcvTime =
            serverPtr->lastReqFragRcvTime;
    }
    serverPtr->stats.numReqFragBytesRcvd += fragSize;
    serverPtr->stats.numReqPacketBytesRcvdThisPacket += fragSize;
#endif /* ADDON_BOEINGFCS */

    if (node->appData.appStats)
    {
        if (NetworkIpIsMulticastAddress(node,serverPtr->serverAddr))
        {
            serverPtr->stats.appStats->AddFragmentReceivedDataPoints(
                node,
                msg,
                MESSAGE_ReturnPacketSize(msg),
                STAT_Multicast);
        }
        else
        {
            serverPtr->stats.appStats->AddFragmentReceivedDataPoints(
                node,
                msg,
                MESSAGE_ReturnPacketSize(msg),
                STAT_Unicast);
        }
    }
    if (serverPtr->lastReqFragRcvTime > serverPtr->firstReqFragRcvTime) {
        serverPtr->stats.reqRcvdThroughput =
            (double)((double)(serverPtr->stats.numReqFragBytesRcvd * 8 * SECOND) /
            (serverPtr->lastReqFragRcvTime - serverPtr->firstReqFragRcvTime
            - serverPtr->timeSpentOutofGroup));
        if (serverPtr->isChainId) {
            serverPtr->stats.chainTputWithTrigger =
                (double)((serverPtr->stats.numReqFragBytesRcvd * 8 * SECOND)
                /(serverPtr->lastReqFragRcvTime
                - serverPtr->firstReqFragRcvTime + data->triggerDelay
                - serverPtr->timeSpentOutofGroup));
        }
    }

    if (SUPERAPPLICATION_DEBUG_REQ_REC)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server received request fragment with \n",
            clockStr);
        TIME_PrintClockInSecond(data->txTime, clockStr, node);
        printf("    Connection                     : C(%u:%u)->S(%u:%u)\n",
            MAPPING_GetNodeIdFromInterfaceAddress(node,
            serverPtr->clientAddr),
            serverPtr->sourcePort,
            node->nodeId,
            serverPtr->destinationPort);
        printf("    Fragment seq number            : %d \n",data->seqNo);
        printf("    Fragment no                    : %d \n",data->fragNo);
        printf("    TxTime                         : %s s \n",clockStr);
        printf("    Total fragments                : %d \n",data->totFrag);
        printf("    Bytes in this fragment         : %d \n",
            MESSAGE_ReturnPacketSize(msg));
        printf("New Server stats are: \n");
        printf("    No. req frag received          : %f \n",
            (Float64)serverPtr->stats.numReqFragsRcvd);
        printf("    No. req frag bytes received    : %f \n",
            (Float64)serverPtr->stats.numReqFragBytesRcvd);
    }
    if ((data->seqNo == serverPtr->seqNo
        && data->fragNo == serverPtr->fragNo)
        || (data->seqNo > serverPtr->seqNo
        && data->fragNo ==  0)
        || data->isMdpEnabled)
    {
#ifdef ADDON_DB
        StatsDb* db = node->partitionData->statsDb;
        msgStatus = APP_MSG_NEW;
#endif // ADDON_DB
        if (data->fragNo == 0)
        {
            serverPtr->fragNo = 0;
        }
        if (serverPtr->fragNo == data->totFrag - 1)
        {
#ifdef ADDON_DB
            if (db != NULL)
            {
                if (node->partitionData->statsDb->
                        statsAppEvents->recordFragment)
                {
                    std::vector<frag_Info>::iterator it;
                    it = serverPtr->fragCache.begin();
                    while (it != serverPtr->fragCache.end())
                    {
                        frag_Info fragInfo;
                        fragInfo = *it;
                        if (data->seqNo > serverPtr->seqNo)
                        {
                            if (serverPtr->prevMsgRecvdComplete == TRUE)
                            {
                                //do nothing
                            }
                            else if (serverPtr->prevMsgRecvdComplete
                                     == FALSE)
                            {

                                HandleStatsDBAppDropEventsInsertion(
                                    node,
                                    fragInfo.fragMsg,
                                    "AppDrop",
                                    fragInfo.fragDelay,
                                    fragInfo.fragSize,
                                    (char*)("Not Enough Fragments Received "
                                        "For Reassembly"));

                            }
                        }

                        MESSAGE_Free(node, fragInfo.fragMsg);
                        it++;
                    }
                    serverPtr->fragCache.clear();
                }
                else if (!node->partitionData->
                            statsDb->statsAppEvents->recordFragment)
                {
                    if (serverPtr->prevMsg != NULL)
                    {
                        if (data->seqNo > serverPtr->seqNo)
                        {
                            if (serverPtr->prevMsgRecvdComplete == TRUE)
                            {
                                //do nothing
                            }
                            else if (serverPtr->prevMsgRecvdComplete
                                     == FALSE)
                            {
                                HandleStatsDBAppDropEventsInsertion(
                                    node,
                                    serverPtr->prevMsg,
                                    "AppDrop",
                                    -1,
                                    serverPtr->prevMsgSize,
                                    (char*)("Not Enough Fragments Received "
                                        "For Reassembly"));
                            }
                        }
                        MESSAGE_Free(node, serverPtr->prevMsg);
                        serverPtr->prevMsg = NULL;
                    } // end of if
                }// end of else if
            }// end of if (db != NULL)
#endif
            // Complete packet received
            // Expect the new packet
            serverPtr->seqNo = data->seqNo + 1;
            serverPtr->fragNo = 0;

            // Subtract the fragments received in order
            serverPtr->stats.numReqFragsRcvdOutOfSeq -= data->totFrag;

            completePacketRvd = TRUE;
        
            if (node->appData.appStats)
            {
                // Control will come here only when last fragment is received
                // and all the fragments in this packet are received in an
                // order which is same as sent.
                if (NetworkIpIsMulticastAddress(node,serverPtr->serverAddr))
                {
                    serverPtr->stats.appStats->AddMessageReceivedDataPoints(
                        node,
                        msg,
                        0,
                        data->totalMessageSize,
                        0,
                        STAT_Multicast);
                }
                else
                {
                    serverPtr->stats.appStats->AddMessageReceivedDataPoints(
                        node,
                        msg,
                        0,
                        data->totalMessageSize,
                        0,
                        STAT_Unicast);
                }
            }
#ifdef ADDON_BOEINGFCS
            BOOL samePartition = data->txPartitionId == node->partitionId;
            if (samePartition || !TRACK_STATISTICS_DIFFERENT_PARTITION)
            {
                clocktype curr = node->getNodeTime();
                serverPtr->maxEndToEndDelayForReqPacket =
                    MAX(packetDelay , serverPtr->maxEndToEndDelayForReqPacket);

                serverPtr->minEndToEndDelayForReqPacket =
                    MIN(packetDelay , serverPtr->minEndToEndDelayForReqPacket);

                serverPtr->totalEndToEndDelayForReqPacket +=
                    (double)packetDelay / SECOND;

                serverPtr->stats.numReqPacketsRcvd++;
                serverPtr->stats.numReqCompletePacketBytesRcvd += data->totalMessageSize;

                if (serverPtr->isChainId) {
                    serverPtr->stats.chainTransDelay =
                        delay;
                    serverPtr->stats.chainTransDelayWithTrigger=
                        delay +
                        data->triggerDelay;
                }
                else {
                    serverPtr->stats.chainTransDelay = 0;
                    serverPtr->stats.chainTransDelayWithTrigger = 0;
                }

                if (serverPtr->isChainId) {
                    SuperAppTriggerUpdateChain(node,
                        1,
                        serverPtr->chainID);
                }

                // Update Packet Jitter

                clocktype now = node->getNodeTime();
                clocktype interArrivalInterval;
                interArrivalInterval = now -
                    data->txTime;
                // Jitter can only be measured after receiving
                // 2 fragments.
                if (serverPtr->stats.numReqPacketsRcvd > 1)
                {
                    jitter = interArrivalInterval -
                        serverPtr->lastReqInterArrivalIntervalPacket;
                    // get absolute value of jitter.
                    if (jitter < 0) {
                        jitter = -jitter;
                    }
                    if (serverPtr->stats.numReqPacketsRcvd == 2)
                    {
                        serverPtr->actJitterForReqPacket = jitter;
                    }
                    else
                    {
                        serverPtr->actJitterForReqPacket += static_cast<clocktype>(
                            ((double)jitter - serverPtr->actJitterForReqPacket) / 16.0);
                    }
                    serverPtr->totalJitterForReqPacket += serverPtr->actJitterForReqPacket;

                }
                serverPtr->lastReqInterArrivalIntervalPacket = interArrivalInterval;

                serverPtr->lastReqPacketRcvTime = node->getNodeTime();
                if ((Float64)(serverPtr->stats.numReqPacketBytesRcvd) == 0) {
                    serverPtr->firstReqPacketRcvTime =
                        serverPtr->lastReqPacketRcvTime;
                }
                serverPtr->stats.numReqPacketBytesRcvd +=
                    serverPtr->stats.numReqPacketBytesRcvdThisPacket;
                serverPtr->stats.numReqPacketBytesRcvdThisPacket = 0;

                // NOTE: throughput is only  tracked for nodes on the same partition
                if (serverPtr->lastReqPacketRcvTime > serverPtr->firstReqPacketRcvTime) {
                    serverPtr->stats.reqRcvdThroughputPacket =
                        (double)((double)(serverPtr->stats.numReqPacketBytesRcvd * 8 * SECOND)
                        / (serverPtr->lastReqPacketRcvTime - serverPtr->firstReqPacketRcvTime));
                    if (serverPtr->isChainId) {
                        serverPtr->stats.chainTputWithTrigger =
                            (double)((serverPtr->stats.numReqPacketBytesRcvd * 8 * SECOND)
                            / (serverPtr->lastReqPacketRcvTime - serverPtr->firstReqPacketRcvTime +
                            data->triggerDelay));
                    }
                }
            }
            else
            {

                serverPtr->maxEndToEndDelayForReqPacketDP =
                    MAX(packetDelay , serverPtr->maxEndToEndDelayForReqPacketDP);

                serverPtr->minEndToEndDelayForReqPacketDP =
                    MIN(packetDelay , serverPtr->minEndToEndDelayForReqPacketDP);

                serverPtr->totalEndToEndDelayForReqPacketDP +=
                    (double)packetDelay / SECOND;

                serverPtr->stats.numReqPacketsRcvdDP++;
                // Update Packet Jitter

                clocktype now = node->getNodeTime();
                clocktype interArrivalInterval;
                interArrivalInterval = now -
                    data->txTime;
                // Jitter can only be measured after receiving
                // 2 fragments.
                if (serverPtr->stats.numReqPacketsRcvdDP > 1)
                {
                    jitter = interArrivalInterval -
                        serverPtr->lastReqInterArrivalIntervalPacketDP;
                    // get absolute value of jitter.
                    if (jitter < 0) {
                        jitter = -jitter;
                    }
                    if (serverPtr->stats.numReqPacketsRcvdDP == 2)
                    {
                        serverPtr->actJitterForReqPacketDP = jitter;
                    }
                    else
                    {
                        serverPtr->actJitterForReqPacketDP += static_cast<clocktype>(
                            ((double)jitter - serverPtr->actJitterForReqPacketDP) / 16.0);
                    }
                    serverPtr->totalJitterForReqPacketDP += serverPtr->actJitterForReqPacketDP;

                }
                serverPtr->lastReqInterArrivalIntervalPacketDP = interArrivalInterval;

                serverPtr->lastReqPacketRcvTimeDP = node->getNodeTime();

            }

            if (samePartition || TRACK_REALTIME_DIFFERENT_PARTITION)
            {
                SuperApplicationHandleRealTimeStats(
                    node,
                    samePartition,
                    serverPtr,
                    (char*) "SuperApp-UDP-server",
                    serverPtr->clientAddr,
                    serverPtr->serverAddr,
                    serverPtr->sourcePort,
                    data->seqNo,
                    data->txRealTime,
                    data->txCpuTime,
                    data->txTime,
                    serverPtr->stats.numReqFragsRcvd);
            }
#else
            serverPtr->stats.numReqPacketsRcvd++;
            serverPtr->stats.numReqCompletePacketBytesRcvd += data->totalMessageSize;

            if (serverPtr->isChainId) {
                serverPtr->stats.chainTransDelay =
                    node->getNodeTime() - data->txTime;
                serverPtr->stats.chainTransDelayWithTrigger =
                    node->getNodeTime() - data->txTime +
                    data->triggerDelay;
            }
            else {
                serverPtr->stats.chainTransDelay = 0;
                serverPtr->stats.chainTransDelayWithTrigger = 0;
            }

            if (serverPtr->isChainId) {
                SuperAppTriggerUpdateChain(node,
                    1,
                    serverPtr->chainID);
            }

            // Update Packet Jitter

            clocktype now = node->getNodeTime();
            clocktype interArrivalInterval;
            interArrivalInterval = now - data->txTime;
            // Jitter can only be measured after receiving
            // 2 fragments.
            if (serverPtr->stats.numReqPacketsRcvd > 1)
            {
                jitter = interArrivalInterval -
                    serverPtr->lastReqInterArrivalIntervalPacket;
                // get absolute value of jitter.
                if (jitter < 0) {
                    jitter = -jitter;
                }
                if (serverPtr->stats.numReqPacketsRcvd == 2)
                {
                    serverPtr->actJitterForReqPacket = jitter;
                }
                else
                {
                    serverPtr->actJitterForReqPacket += static_cast<clocktype>(
                        ((double)jitter - serverPtr->actJitterForReqPacket) / 16.0);
                }

                serverPtr->totalJitterForReqPacket += serverPtr->actJitterForReqPacket;
            }
            serverPtr->lastReqInterArrivalIntervalPacket = interArrivalInterval;

            packetDelay = node->getNodeTime() - data->txTime;
            serverPtr->totalEndToEndDelayForReqPacket +=
                (double)packetDelay / SECOND;
            serverPtr->lastReqPacketRcvTime = node->getNodeTime();
            if ((Float64)(serverPtr->stats.numReqPacketBytesRcvd) == 0) {
                serverPtr->firstReqPacketRcvTime =
                    serverPtr->lastReqPacketRcvTime;
            }
            serverPtr->stats.numReqPacketBytesRcvd +=
                serverPtr->stats.numReqPacketBytesRcvdThisPacket;
            serverPtr->stats.numReqPacketBytesRcvdThisPacket = 0;

            // NOTE: throughput is only  tracked for nodes on the same partition
            if (serverPtr->lastReqPacketRcvTime > serverPtr->firstReqPacketRcvTime)
            {
                serverPtr->stats.reqRcvdThroughputPacket =
                    (double)((double)(serverPtr->stats.numReqPacketBytesRcvd * 8 * SECOND)
                    / (serverPtr->lastReqPacketRcvTime - serverPtr->firstReqPacketRcvTime));
                if (serverPtr->isChainId) {
                    serverPtr->stats.chainTputWithTrigger =
                        (double)((serverPtr->stats.numReqPacketBytesRcvd * 8 * SECOND)
                        / (serverPtr->lastReqPacketRcvTime - serverPtr->firstReqPacketRcvTime +
                        data->triggerDelay));
                }
            }

#endif /* ADDON_BOEINGFCS */
            SuperAppClientList* clist = (SuperAppClientList*)node->appData.clientPtrList;
            unsigned int cindex = 0;
            for (cindex = 0; cindex < clist->clientList.size(); cindex++)
            {
                if (clist->clientList[cindex].clientPtr->readyToSend == FALSE)
                {
                    if (SuperAppCheckConditions(node, clist->clientList[cindex].clientPtr) == TRUE)
                    {
                        // start trigger the conditions session.
                        clist->clientList[cindex].clientPtr->readyToSend = TRUE;


                        SuperAppTriggerSendMsg(node,
                            clist->clientList[cindex].clientPtr,
                            clist->clientList[cindex].isSourcePort,
                            clist->clientList[cindex].randomDuration,
                            clist->clientList[cindex].isFragmentSize
#ifdef ADDON_BOEINGFCS
                            ,clist->clientList[cindex].burstyKeywordFound

#endif /* ADDON_BOEINGFCS */
                            );
                    } // end if (SuperAppCheckConditions)
                } // end if (clist->clientList[cindex].clientPtr->readyToSend == FALSE)
            } // end of for

        } // end if (serverPtr->fragNo == data->totFrag - 1)
        else if (data->seqNo > serverPtr->seqNo
            && data->fragNo == 0)
        {
            //This is the first fragment of next packet
            //Expect the next fragment of this packet
#ifdef ADDON_DB
            if (db != NULL)
            {
                if (!node->partitionData->statsDb->
                        statsAppEvents->recordFragment)
                {
                    if (serverPtr->prevMsg != NULL)
                    {
                        HandleStatsDBAppDropEventsInsertion(
                            node,
                            serverPtr->prevMsg,
                            "AppDrop",
                            -1,
                            serverPtr->prevMsgSize,
                            (char*)("Not Enough Fragments Received "
                                "For Reassembly"));
                        MESSAGE_Free(node, serverPtr->prevMsg);
                        serverPtr->prevMsg = NULL;
                    }
                    serverPtr->prevMsg = MESSAGE_Duplicate(node, msg);
                    serverPtr->prevMsgSize = data->totalMessageSize;
                    serverPtr->prevMsgRecvdComplete = completePacketRvd;
                }
                else
                {
                    std::vector<frag_Info>::iterator it;
                    it = serverPtr->fragCache.begin();
                    while (it != serverPtr->fragCache.end())
                    {
                        frag_Info fragInfo;
                        fragInfo = *it;
                        HandleStatsDBAppDropEventsInsertion(
                            node,
                            fragInfo.fragMsg,
                            "AppDrop",
                            fragInfo.fragDelay,
                            fragInfo.fragSize,
                            (char*)("Not Enough Fragments "
                                "Received For Reassembly"));
                        MESSAGE_Free(node, fragInfo.fragMsg);
                        it++;
                    }
                    serverPtr->fragCache.clear();
                    frag_Info fragmentInfo;
                    fragmentInfo.fragMsg = MESSAGE_Duplicate(node, msg);
                    fragmentInfo.fragSize = MESSAGE_ReturnPacketSize(msg);
                    fragmentInfo.fragDelay = delay;
                    serverPtr->fragCache.push_back(fragmentInfo);
                    serverPtr->prevMsgRecvdComplete = completePacketRvd;
                }
            }
#endif
            serverPtr->seqNo = data->seqNo;
            serverPtr->fragNo++;
        } // end of else if (data->seqNo > serverPtr->seqNo)
        else
        {
            // Expect next fragment
#ifdef ADDON_DB
            if (db != NULL)
            {
                if (node->partitionData->statsDb->statsAppEvents->recordFragment)
                {
                    frag_Info fragmentInfo;
                    fragmentInfo.fragMsg = MESSAGE_Duplicate(node, msg);
                    fragmentInfo.fragSize = MESSAGE_ReturnPacketSize(msg);
                    fragmentInfo.fragDelay = delay;
                    serverPtr->fragCache.push_back(fragmentInfo);
                    serverPtr->prevMsgRecvdComplete = completePacketRvd;
                }
                else
                {

                    if (serverPtr->prevMsg != NULL)
                    {
                        MESSAGE_Free(node, serverPtr->prevMsg);
                        serverPtr->prevMsg = NULL;
                    }
                    serverPtr->prevMsg = MESSAGE_Duplicate(node, msg);
                    serverPtr->prevMsgSize = data->totalMessageSize;
                    serverPtr->prevMsgRecvdComplete = completePacketRvd;
                }
            }
#endif
            serverPtr->fragNo++;
        } // end of else
    } // end if ((data->seqNo == serverPtr->seqNo)

    if (SUPERAPPLICATION_DEBUG_REQ_REC)
    {
        printf("    No. req packets received       : %f \n",
            (Float64)serverPtr->stats.numReqPacketsRcvd);
    }
    if (serverPtr->isVoice == FALSE) {
        if ((completePacketRvd == TRUE) && (serverPtr->processReply == TRUE))
        {
            SuperApplicationScheduleNextReply_UDP(node, serverPtr);
        }
    }else{

        // cancel self timer if any.
        if (serverPtr->talkTimeOut !=NULL){
            MESSAGE_CancelSelfMsg(node, serverPtr->talkTimeOut);
            serverPtr->talkTimeOut = NULL;
        }

        // schedule to talk
        if (dataType == 'o')
        {
            // won't start talking if it is already talking
            if (serverPtr->isTalking == FALSE){
                serverPtr->isJustMyTurnToTalk = TRUE;
                SuperApplicationScheduleNextReply_UDP(node, serverPtr);
            }
        }
    }
#ifdef ADDON_DB
    StatsDb* db = node->partitionData->statsDb;
    if (db != NULL)
    {
        // Set the session Id
        StatsDBAppEventParam* appParamInfo = NULL;
        appParamInfo = (StatsDBAppEventParam*) MESSAGE_ReturnInfo(msg, INFO_TYPE_AppStatsDbContent);
        if (appParamInfo != NULL)
        {
            serverPtr->sessionId = appParamInfo->m_SessionId;
            serverPtr->sessionInitiator = appParamInfo->m_SessionInitiator;
            strcpy(serverPtr->applicationName, appParamInfo->m_ApplicationName);
        }

        if (!node->partitionData->statsDb->statsAppEvents->recordFragment)
        {
            if (completePacketRvd || data->totFrag == 1)
            {
                APP_ReportStatsDbReceiveEvent(
                    node,
                    msg,
                    &(serverPtr->msgSeqCache),
                    data->seqNo,
                    delay,
                    serverPtr->actJitterForReqPacket,
                    data->totalMessageSize,
                    serverPtr->stats.numReqPacketsRcvd,
                    msgStatus);
            }
        }
        else
        {
            APP_ReportStatsDbReceiveEvent(
                node,
                msg,
                &(serverPtr->fragSeqCache),
                data->uniqueFragNo,
                delay,
                serverPtr->actJitterForReq,
                MESSAGE_ReturnPacketSize(msg),
                serverPtr->stats.numReqFragsRcvd,
                msgStatus);
        }


        // Hop Count stats.
        StatsDBNetworkEventParam* ipParamInfo;
        ipParamInfo = (StatsDBNetworkEventParam*)
            MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

        if (ipParamInfo == NULL)
        {
            printf ("ERROR: We should have Network Events Info");
        }
        else
        {
            serverPtr->stats.hopCount += (int) ipParamInfo->m_HopCount;
        }
    }
#endif // ADDON_DB

    // Free the message
    MESSAGE_Free(node, msg);
}


// FUNCTION SuperApplicationServerNewServer
// PURPOSE  Create a new server
// Parameters:
//  node:   Pointer to node structure
static SuperApplicationData* SuperApplicationServerNewServer(Node* node) {
    SuperApplicationData* serverPtr;
    serverPtr = new SuperApplicationData;
    //serverPtr = (SuperApplicationData*) MEM_malloc(sizeof(SuperApplicationData));
    //memset(serverPtr, 0, sizeof(SuperApplicationData));

    // Designer uses INVALID_SOURCE_PORT to recognise non-configured server
    // when the first packet comes in
    serverPtr->destinationPort = APP_SUPERAPPLICATION_SERVER;
    serverPtr->uniqueId = node->appData.uniqueId++;
    serverPtr->sessionId = -1;
    serverPtr->randomRepInterDepartureDelay.setDistribution(
        "UNI 0S 0S", "Superapplication", RANDOM_CLOCKTYPE);
    // Set State values
    serverPtr->seqNo = 0;
    serverPtr->fragNo = 0;
    serverPtr->uniqueFragNo = 0;
    serverPtr->repSeqNo = 0;
    serverPtr->repFragNo = 0;
    serverPtr->isClosed = FALSE;
    // Set default values
    serverPtr->processReply = FALSE;
    serverPtr->gotLastReqPacket = FALSE;
    serverPtr->repTOS = APP_DEFAULT_TOS;
    //strcpy(serverPtr->applicationName,"SuperApplication-Server");
    serverPtr->fragmentationSize = APP_MAX_DATA_SIZE;
    serverPtr->fragmentationEnabled = FALSE;
    // Set other init values
    serverPtr->lastReqInterArrivalInterval = 0;
    serverPtr->lastReqInterArrivalIntervalPacket = 0;

    // for voice session
    serverPtr->isTalking = FALSE;
    serverPtr->isVoice = FALSE;
    serverPtr->isVideo = FALSE;
    serverPtr->isJustMyTurnToTalk = FALSE;
    serverPtr->averageTalkTime = 0;
    serverPtr->talkTime = 0;
    serverPtr->firstTalkTime = 0;
    serverPtr->talkTimeOut = NULL;
    serverPtr->randomAverageTalkTime.setDistributionNull();

    // for conditions
    serverPtr->isConditions = FALSE;

    serverPtr->serverAddr = 0;
    serverPtr->sessionStart = 0;
    serverPtr->sessionFinish = 0;
    serverPtr->totalReqPacketsToSend = 0;
    serverPtr->randomReqSize.setDistributionNull();
    serverPtr->randomReqInterval.setDistributionNull();
    serverPtr->sourcePort = 0;

    // Use well known port for server by default
    serverPtr->connectionId = 0;
    serverPtr->isClosed = FALSE;
    // Set State values
    serverPtr->waitingForReply = FALSE;
    serverPtr->processReply = FALSE;
    serverPtr->seqNo = 0;
    serverPtr->repSeqNo = 0;

    serverPtr->fragmentationEnabled = FALSE;
    // Set default values
    serverPtr->reqTOS = APP_DEFAULT_TOS;
    serverPtr->waitTillReply = FALSE;
    //strcpy(clientPtr->applicationName,"SuperApplication-Client");
    serverPtr->fragmentationSize = APP_MAX_DATA_SIZE;

    // for conditions
    serverPtr->isConditions = FALSE;

    serverPtr->repFragNo = 0;

    // Initialize all the values in SuperApplicationData
    serverPtr->state = 0;
    serverPtr->protocol = 0;
    serverPtr->transportLayer = 0;
    serverPtr->descriptorName = NULL;
    serverPtr->fragNo = 0;
    serverPtr->uniqueFragNo = 0;
    serverPtr->lastReqInterArrivalInterval = 0;
    serverPtr->lastReqPacketReceptionTime = 0;
    serverPtr->totalReqJitter = 0;
    serverPtr->totalReqJitterPacket = 0;
    serverPtr->randomRepSize.setDistributionNull();
    serverPtr->randomRepInterval.setDistributionNull();
    serverPtr->randomRepInterDepartureDelay.setDistributionNull();
    serverPtr->gotLastReqPacket = FALSE;
    serverPtr->repTOS = 0;
    serverPtr->randomRepPacketsToSendPerReq.setDistributionNull();
    serverPtr->lastRepInterArrivalInterval = 0;
    serverPtr->appFileIndex = 0;
    serverPtr->bufferSize = 0;
    serverPtr->buffer = NULL;
    serverPtr->fragmentBufferSize = 0;
    serverPtr->fragmentBuffer = NULL;
    serverPtr->waitFragments = 0;
    serverPtr->lastReqFragSentTime = 0;
    serverPtr->lastRepFragSentTime = 0;
    serverPtr->firstRepFragRcvTime = 0;
    serverPtr->lastRepFragRcvTime = 0;
    serverPtr->firstReqFragRcvTime = 0;
    serverPtr->lastReqFragRcvTime = 0;
    serverPtr->totalJitterForRep = 0;
    serverPtr->totalJitterForReq = 0;
    serverPtr->actJitterForRep = 0;
    serverPtr->actJitterForReq = 0;
    serverPtr->totalEndToEndDelayForRep = 0;
    serverPtr->totalEndToEndDelayForReq = 0;
    serverPtr->firstRepFragSentTime = 0;
    serverPtr->firstReqFragSentTime = 0;
    serverPtr->firstRepPacketRcvTime = 0;
    serverPtr->firstReqPacketRcvTime = 0;
    serverPtr->lastRepPacketRcvTime = 0;
    serverPtr->lastReqPacketRcvTime = 0;
    serverPtr->totalJitterForReqPacket = 0;
    serverPtr->totalJitterForRepPacket = 0;
    serverPtr->actJitterForReqPacket = 0;
    serverPtr->actJitterForRepPacket = 0;
    serverPtr->lastRepInterArrivalIntervalPacket = 0;
    serverPtr->packetSentTime = 0;
    serverPtr->totalEndToEndDelayForReqPacket = 0;
    serverPtr->totalEndToEndDelayForRepPacket = 0;
    serverPtr->firstReqPacketSentTime = 0;
    serverPtr->lastReqPacketSentTime = 0;
    serverPtr->maxEndToEndDelayForReqPacket = 0;
    serverPtr->minEndToEndDelayForReqPacket = 0;
    serverPtr->totalEndToEndDelayForReqPacketDP = 0;
    serverPtr->maxEndToEndDelayForReqPacketDP = 0;
    serverPtr->minEndToEndDelayForReqPacketDP = 0;
    serverPtr->groupLeavingTime = 0;
    serverPtr->timeSpentOutofGroup = 0;
    serverPtr->initStats = 0;
    serverPtr->printStats = 0;

    serverPtr->isTriggered = FALSE;
    serverPtr->isChainId = FALSE;
    serverPtr->readyToSend = FALSE;

    serverPtr->isMdpEnabled = FALSE;
    serverPtr->isProfileNameSet = FALSE;
    strcpy(serverPtr->profileName,"\0");
    serverPtr->mdpUniqueId = -1; //Invalid value

#ifdef ADDON_BOEINGFCS
    serverPtr->cpuTimingStarted = FALSE;
    serverPtr->cpuTimeStart = 0;
    serverPtr->lastCpuTime = 0;
    serverPtr->cpuTimingInterval = 0;
    serverPtr->realTimeOutput = FALSE;
    serverPtr->printRealTimeStats = TRUE;
    serverPtr->randomBurstyTimer.setDistributionNull();
    serverPtr->maxEndToEndDelayForReq = 0;
    serverPtr->minEndToEndDelayForReq = 0;
    serverPtr->delayRealTimeProcessing = 0;
    serverPtr->totalJitterForReqDP = 0;
    serverPtr->totalJitterForReqPacketDP = 0;
    serverPtr->actJitterForReqDP = 0;
    serverPtr->actJitterForReqPacketDP = 0;
    serverPtr->lastReqFragRcvTimeDP = 0;
    serverPtr->lastReqPacketRcvTimeDP = 0;
    serverPtr->lastReqInterArrivalIntervalDP = 0;
    serverPtr->lastReqInterArrivalIntervalPacketDP = 0;
    serverPtr->totalEndToEndDelayForReqDP = 0;
    serverPtr->maxEndToEndDelayForReqDP = 0;
    serverPtr->minEndToEndDelayForReqDP = 0;
    serverPtr->requiredDelay = 0;
    serverPtr->requiredTput = 0;

    serverPtr->burstyTimer = 0;
    serverPtr->burstyLow = 0;
    serverPtr->burstyMedium = 0;
    serverPtr->burstyHigh = 0;
    serverPtr->burstyInterval = 0;
#endif /* ADDON_BOEINGFCS */

#ifdef ADDON_DB
    serverPtr->sessionInitiator = 0;
    serverPtr->msgSeqCache = NULL;
    serverPtr->fragSeqCache = NULL;
    serverPtr->prevMsg = NULL;
    serverPtr->prevMsgSize = 0;
    serverPtr->prevMsgRecvdComplete = FALSE;
#endif
    serverPtr->stats.appStats = NULL;

    serverPtr->serverUrl = new std::string();
    serverPtr->serverUrl->clear();

    SuperApplicationInitStats(node, &(serverPtr->stats));

    return serverPtr;
}


// FUNCTION SuperApplicationDataPrintUsageAndQuit
// PURPOSE  Print the distirbution usage and quit
static void SuperApplicationDataPrintUsageAndQuit() {
    ERROR_ReportError("SuperApplication: Incorrect distribution parameters.\n"
        "    <time_distribution_type> can be [DET time_value] OR "
           "[UNI time_value time_value] OR [EXP time_value]\n"
           "    <int_random_dist> can be [DET integer] OR [UNI integer integer"
           "] OR [EXP integer]");
}



//UserCodeEnd

//State Function Definitions
static void enterSuperApplicationServerIdle_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServerIdle_UDP

    //UserCodeEndServerIdle_UDP

}

static void enterSuperApplicationServer_TimerExpired_SendReply_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_TimerExpired_SendReply_UDP
    SuperApplicationServerSendData_UDP(node,dataPtr,msg);
    //UserCodeEndServer_TimerExpired_SendReply_UDP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_UDP;
    enterSuperApplicationServerIdle_UDP(node, dataPtr, msg);
}

static void enterSuperApplicationClientIdle_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClientIdle_UDP

    //UserCodeEndClientIdle_UDP

}

static void enterSuperApplicationClient_ReceiveReply_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_ReceiveReply_UDP
    SuperApplicationClientReceivePacket_UDP(node,msg,dataPtr);
    //UserCodeEndClient_ReceiveReply_UDP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_UDP;
    enterSuperApplicationClientIdle_UDP(node, dataPtr, msg);
}

static void enterSuperApplicationClient_TimerExpired_SendRequest_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_TimerExpired_SendRequest_UDP
    SuperApplicationClientSendData_UDP(node,dataPtr,msg);
    //UserCodeEndClient_TimerExpired_SendRequest_UDP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_UDP;
    enterSuperApplicationClientIdle_UDP(node, dataPtr, msg);
}

static void enterSuperApplicationServer_ReceiveData_UDP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_ReceiveData_UDP
    SuperApplicationServerReceivePacket_UDP(node,msg,dataPtr);
    //UserCodeEndServer_ReceiveData_UDP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_UDP;
    enterSuperApplicationServerIdle_UDP(node, dataPtr, msg);
}

static void enterSuperApplicationClient_ReceiveReply_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_ReceiveReply_TCP
    SuperApplicationClientReceivePacket_TCP(node, msg, dataPtr);
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
    enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
    if (msg)
    {
        MESSAGE_Free(node, msg);
    }
    //UserCodeEndClient_ReceiveReply_TCP
}

static void enterSuperApplicationClient_ConnectionClosed_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_ConnectionClosed_TCP
    if (dataPtr->isClosed == FALSE)
    {
        dataPtr->isClosed = TRUE;
        dataPtr->sessionFinish = node->getNodeTime();
    }
    //UserCodeEndClient_ConnectionClosed_TCP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
    enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
}

static void enterSuperApplicationServer_ReceiveData_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_ReceiveData_TCP
    SuperApplicationServerReceivePacket_TCP(node,msg,dataPtr);
    //UserCodeEndServer_ReceiveData_TCP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
    enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
    if (msg)
    {
        MESSAGE_Free(node, msg);
    }
}

static void enterSuperApplicationServer_ConnectionClosed_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_ConnectionClosed_TCP

    //UserCodeEndServer_ConnectionClosed_TCP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
    enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
    if (node->appData.appStats)
    {
        if (!dataPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
        {
            dataPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
        }
    }
}

static void enterSuperApplicationServerIdle_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServerIdle_TCP

    //UserCodeEndServerIdle_TCP

}

static void enterSuperApplicationServer_ConnectionOpenResult_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_ConnectionOpenResult_TCP
    SuperApplicationServerHandleOpenResult_TCP (node,dataPtr,msg);
    //UserCodeEndServer_ConnectionOpenResult_TCP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
    enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
}

static void enterSuperApplicationClientIdle_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClientIdle_TCP

    //UserCodeEndClientIdle_TCP

}

static void enterSuperApplicationServer_ListenResult_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartServer_ListenResult_TCP
    TransportToAppListenResult *listenResult;

    listenResult = (TransportToAppListenResult *)
                   MESSAGE_ReturnInfo(msg);
    if (listenResult->connectionId == -1)
    {
        if (SUPERAPPLICATION_DEBUG_TCP_HANDSHAKE)
        {
            char clockStr[24];
            TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
            printf("At %s sec, Server (%d:%d) failed to listen. "
                   "Trying again.\n",
                   clockStr,
                   node->nodeId,
                   dataPtr->destinationPort);
        }


        Address serverAddr;
        serverAddr.networkType = NETWORK_IPV4;
        serverAddr.interfaceAddr.ipv4 = dataPtr->serverAddr;
        node->appData.appTrafficSender->appTcpListenWithPriority(
                                    node,
                                    APP_SUPERAPPLICATION_SERVER,
                                    serverAddr,
                                    dataPtr->destinationPort,
                                    dataPtr->reqTOS);

        node->appData.numAppTcpFailure++;
    }

    // Free the message
    MESSAGE_Free(node, msg);

    //UserCodeEndServer_ListenResult_TCP
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
    enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
}

static void enterSuperApplicationClient_ConnectionOpenResult_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    // dynamic address
    // update the clientPtr
    TransportToAppOpenResult* openResult =
                (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);
    if (openResult)
    {
        dataPtr->clientAddr = openResult->localAddr.interfaceAddr.ipv4;
        dataPtr->serverAddr = openResult->remoteAddr.interfaceAddr.ipv4;
    }
    //UserCodeStartClient_ConnectionOpenResult_TCP
    SuperApplicationClientHandleOpenResult_TCP (node,dataPtr,msg);
    //UserCodeEndClient_ConnectionOpenResult_TCP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
    enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
}

static void enterSuperApplicationClient_TimerExpired_SendRequest_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_TimerExpired_SendRequest_TCP
    SuperApplicationClientSendData_TCP(node,dataPtr,msg);
    //UserCodeEndClient_TimerExpired_SendRequest_TCP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
    enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
}

static void enterSuperApplicationClient_DataSent_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg) {

    //UserCodeStartClient_DataSent_TCP
    clocktype reqInterval;
    SuperApplicationData* clientPtr = dataPtr;

    clientPtr->waitFragments --;

    if (clientPtr->waitFragments == 0)
    {
        // Last fragment sent. Complete packet has now been sent
        // Time for txing next data request
        //clientPtr->randomReqInterval.setSeed(node->globalSeed);
        reqInterval = clientPtr->randomReqInterval.getRandomNumber();

        if (clientPtr->isClosed == FALSE)
        {
            if (// Required number of requests sent
                ((clientPtr->stats.numReqPacketsSent ==
                  clientPtr->totalReqPacketsToSend) &&
                 (clientPtr->totalReqPacketsToSend > 0)) ||
                // Session is over
                (clientPtr->sessionFinish != clientPtr->sessionStart
                 && node->getNodeTime() + reqInterval >= clientPtr->sessionFinish))
            {
                if ((SUPERAPPLICATION_DEBUG_TIMER_REC_CLIENT) ||
                        (SUPERAPPLICATION_DEBUG_TIMER_SET_CLIENT))
                {
                    char clockStr[24];
                    TIME_PrintClockInSecond(reqInterval+node->getNodeTime(), clockStr, node);
                    printf("Closing connection  : \n");
                    printf("    Proposed next pkt schedule time : %s \n" ,clockStr);
                    TIME_PrintClockInSecond(clientPtr->sessionFinish, clockStr, node);
                    printf("    Session finish time             : %s \n" ,clockStr);
                    printf("    Status of req sent              :  %f of ",
                           (Float64)clientPtr->stats.numReqPacketsSent);
                    if (clientPtr->totalReqPacketsToSend == 0)
                        printf("unspecified max. \n");
                    else
                        printf("%u \n",clientPtr->totalReqPacketsToSend);
                }
                // MERGE - missed this in initial merge. May affect reliable traffic.

                if (clientPtr->processReply) {
                    if ((clientPtr->sessionFinish != clientPtr->sessionStart) &&
                            (node->getNodeTime() + reqInterval >= clientPtr->sessionFinish))
                    {
                        node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                clientPtr->connectionId);
                        if (node->appData.appStats)
                        {
                            if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
                            {
                                if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                                {
                                    clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                                }
                            }
                            else
                            {
                                if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                                {
                                    clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                                }
                            }
                        }
                    }
                }
                else
                {
                    node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                clientPtr->connectionId);
                    if (node->appData.appStats)
                    {
                        if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
                        {
                            if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                            {
                                clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                            }
                        }
                        else
                        {
                            if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                            {
                                clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                            }
                        }
                    }
                }
                clientPtr->isClosed = TRUE;
            }
        }

        // Set up next timer
        if (!clientPtr->isClosed)
        {
            SuperApplicationClientSchedulePacket_TCP(
                node,
                clientPtr,
                reqInterval);
        }
    }
    // Free the message
    MESSAGE_Free(node, msg);

    //UserCodeEndClient_DataSent_TCP
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
    enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
}


// ************************************************************
// void sendMsg
// Purpose: Does the job that SuperApp would normally do for
//          sending out flows that now have to wait to be
//          triggered
// *************************************************************
static
void SuperAppTriggerSendMsg(Node* node,
                            SuperApplicationData* clientPtr,
                            BOOL isSourcePort,
                            RandomDistribution<clocktype> randomDuration,
                            BOOL isFragmentSize
#ifdef ADDON_BOEINGFCS
                            , BOOL burstyKeywordFound
#endif
                           )
{
    clocktype duration=0;

    if (randomDuration.getDistributionType() == DNULL)
    {
        clientPtr->sessionFinish = 0;
    }
    else
    {
        //randomDuration.setSeed(node->globalSeed);
        duration = randomDuration.getRandomNumber() + node->getNodeTime();
        if (duration == 0){
            clientPtr->sessionFinish = clientPtr->sessionStart;
        }else{
            clientPtr->sessionFinish = clientPtr->sessionStart
                                       + randomDuration.getRandomNumber() + node->getNodeTime();
        }
    }

    if ((isFragmentSize == TRUE) &&
            (clientPtr->transportLayer == SUPERAPPLICATION_TCP))
    {
        ERROR_ReportError("SuperApplication Client: FRAGMENT-SIZE is not "
            "supported with TCP");
    }

    if (isSourcePort == FALSE && clientPtr->sourcePort == 0)
    {
        // User did not specify source port.
        // Select a free port
        clientPtr->sourcePort = APP_GetFreePort(node);
    }
    // Make sure all parameter values are valid
    SuperApplicationClientValidateParam(
        node,
        clientPtr,
        isSourcePort);
    if (SUPERAPPLICATION_DEBUG_PORTS)
    {
        printf (" Client node %d running on port %d \n",
                node->nodeId,
                clientPtr->sourcePort);
    }
    // Register the application
    if (isSourcePort == FALSE && clientPtr->protocol == 0)
    {
        clientPtr->protocol = APP_SUPERAPPLICATION_CLIENT;
        APP_RegisterNewApp(node,
                           APP_SUPERAPPLICATION_CLIENT,
                           clientPtr,
                           clientPtr->sourcePort);
    }

#ifdef ADDON_BOEINGFCS
    if (burstyKeywordFound == TRUE &&
            clientPtr->transportLayer == SUPERAPPLICATION_UDP)
    {
        clocktype rndTimer = 0;
        AppTimer *timer;
        Message *timerMsg;

        timerMsg = MESSAGE_Alloc(node,
                                 APP_LAYER,
                                 APP_SUPERAPPLICATION_CLIENT,
                                 MSG_APP_TimerExpired);

        MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));

        timer = (AppTimer *)MESSAGE_ReturnInfo(timerMsg);

        timer->connectionId = 0;
        timer->sourcePort = clientPtr->sourcePort;
        timer->type = SUPERAPPLICATION_BURSTY_TIMER;

        rndTimer = clientPtr->randomBurstyTimer.getRandomNumber();

        MESSAGE_Send(node,
                     timerMsg,
                     clientPtr->sessionStart + rndTimer);
    }
#endif /* ADDON_BOEINGFCS */
    if (clientPtr->transportLayer == SUPERAPPLICATION_TCP){
        SuperApplicationClientOpenConnection_TCP(node, clientPtr);
    }else{
        SuperApplicationClientScheduleFirstPacket_UDP(node, clientPtr);
    }
}



// ************************************************************
// void SuperAppTriggerUpdateChain
// Purpose: Called when a client that is listed as being chained
//          sending out flows that now have to wait to be
//          triggered
// *************************************************************
static
void SuperAppTriggerUpdateChain(Node* node,
                                int numPacketsRecvd,
                                char* chainId)
{
    SuperAppTriggerData* trigger = (SuperAppTriggerData*)(node->appData.triggerAppData);
    SuperAppChainIdList* chain = &trigger->chainIdList;

    if (SUPERAPPLICATION_DEBUG_CHAIN){
        printf("Received new packet for chain %s at node %d\n", chainId, node->nodeId);
    }

    if (chain->numInList == 0) {
        chain->tail = (SuperAppChainIdElement*)
                      MEM_malloc(sizeof(SuperAppChainIdElement));
        chain->tail->prev = NULL;
        chain->head = chain->tail;
        memset(chain->tail->chainID, 0, MAX_STRING_LENGTH);
        memcpy(chain->tail->chainID, chainId, strlen(chainId));
        chain->tail->numSeen = numPacketsRecvd;
        chain->tail->numNeeded = 0;
        chain->numInList++;
        chain->tail->next = NULL;
    }else{
        SuperAppChainIdElement* curr = NULL;
        curr = chain->head;
        BOOL found = FALSE;
        while (curr != NULL) {
            if (strncmp(curr->chainID, chainId, MAX_STRING_LENGTH)==0) {
                found = TRUE;
                curr->numSeen += numPacketsRecvd;
                if (SUPERAPPLICATION_DEBUG_CHAIN){
                    printf("Seen total of %d packets in CHAIN-ID %s at node %d\n", curr->numSeen, chainId, node->nodeId);
                }
            }
            curr = curr->next;
        }

        if (found==FALSE) {
            chain->tail->next = (SuperAppChainIdElement*)
                                MEM_malloc(sizeof(SuperAppChainIdElement));
            chain->tail->next->prev = chain->tail;
            chain->tail = chain->tail->next;
            memset(chain->tail->chainID, 0, MAX_STRING_LENGTH);
            memcpy(chain->tail->chainID, chainId, strlen(chainId));
            chain->tail->numSeen = numPacketsRecvd;
            chain->tail->numNeeded = 0;
            chain->numInList++;
            chain->tail->next = NULL;

            if (SUPERAPPLICATION_DEBUG_CHAIN){
                printf("Seen total of %d packets in CHAIN-ID %s at node %d\n", chain->tail->numSeen, chainId, node->nodeId);
            }
        }
    }
}




// ************************************************************
// void TriggerAppInit
// Purpose: Initializes chain list
// *************************************************************
void SuperAppTriggerInit(Node* node)
{
    SuperAppTriggerData* triggerAppData =
        (SuperAppTriggerData*)(node->appData.triggerAppData);

    if (triggerAppData == NULL)
    {
        triggerAppData =
            (SuperAppTriggerData*) MEM_malloc(sizeof(SuperAppTriggerData));
        (&triggerAppData->chainIdList)->head = NULL;
        (&triggerAppData->chainIdList)->tail = NULL;
        (&triggerAppData->chainIdList)->numInList = 0;

        (&triggerAppData->stats)->head = NULL;
        (&triggerAppData->stats)->tail = NULL;
        (&triggerAppData->stats)->numInList = 0;

        node->appData.triggerAppData = (void*)triggerAppData;
    }
}

static
void SuperAppUpdateChainStats(Node* node, SuperApplicationData* dataPtr)
{
    SuperAppTriggerData* trigger =
        (SuperAppTriggerData*)(node->appData.triggerAppData);
    SuperAppChainStatsList* stats = &trigger->stats;

    if (stats->numInList == 0) {
        stats->tail = (SuperAppChainStatsElement*)
                      MEM_malloc(sizeof(SuperAppChainStatsElement));
        stats->tail->prev = NULL;
        stats->head = stats->tail;

        memset(stats->tail->chainID, 0, MAX_STRING_LENGTH);
        stats->tail->pktsRecv = 0;
        stats->tail->pktsSent = 0;
        memcpy(stats->tail->chainID, dataPtr->chainID, strlen(dataPtr->chainID));
        stats->tail->next = NULL;
        stats->tail->pktsRecv = (int)dataPtr->stats.numReqPacketsRcvd;
        stats->tail->pktsSent = (int)dataPtr->stats.numReqPacketsSent;
        stats->numInList = 1;
    }
    else {
        SuperAppChainStatsElement* curr = stats->head;
        BOOL found = FALSE;
        while (curr) {
            if (strncmp(curr->chainID, dataPtr->chainID, MAX_STRING_LENGTH)==0) {
                found = TRUE;
                curr->pktsRecv += (int)dataPtr->stats.numReqPacketsRcvd;
                curr->pktsSent += (int)dataPtr->stats.numReqPacketsSent;
            }
            curr = curr->next;
        }

        if (!found) {
            stats->tail->next =
                (SuperAppChainStatsElement*)
                MEM_malloc(sizeof(SuperAppChainStatsElement));
            stats->tail->next->prev = stats->tail;
            stats->tail = stats->tail->next;

            memset(stats->tail->chainID, 0, MAX_STRING_LENGTH);
            memcpy(stats->tail->chainID, dataPtr->chainID, strlen(dataPtr->chainID));
            stats->tail->pktsRecv = (int)dataPtr->stats.numReqPacketsRcvd;
            stats->tail->pktsSent = (int)dataPtr->stats.numReqPacketsSent;
            stats->tail->next = NULL;
            stats->numInList++;
        }
    }

}



//Statistic Function Definitions
static void SuperApplicationInitStats(Node* node, SuperApplicationStatsType *stats) {
    memset(stats, 0, sizeof(stats));
    if (node->guiOption) {
        stats->numReqBytesSentId = GUI_DefineMetric("Number of Request Bytes Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqPacketsSentId = GUI_DefineMetric("Number of Request Packets Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqFragsSentId = GUI_DefineMetric("Number of Request Fragments Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepBytesSentId = GUI_DefineMetric("Number of Reply Bytes Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepPacketsSentId = GUI_DefineMetric("Number of Reply Packets Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepFragsSentId = GUI_DefineMetric("Number of Reply Fragments Sent", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepFragsRcvdOutOfSeqId = GUI_DefineMetric("Number of Out-of-order Reply Fragments Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepPacketsRcvdId = GUI_DefineMetric("Number of Complete Reply Packets Received ", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepFragsRcvdId = GUI_DefineMetric("Number of Reply Fragments Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numRepFragBytesRcvdId = GUI_DefineMetric("Total Reply Fragment Bytes Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqFragsRcvdOutOfSeqId = GUI_DefineMetric("Number of Out-of-order Request Fragments Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqPacketsRcvdId = GUI_DefineMetric("Number of Complete Request Packets Received ", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqFragsRcvdId = GUI_DefineMetric("Number of Request Fragments Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numReqFragBytesRcvdId = GUI_DefineMetric("Total Request Fragment Bytes Received", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);
        stats->reqSentThroughputId = GUI_DefineMetric("Throughput for Requests Sent (bits/s)", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);
        stats->reqRcvdThroughputId = GUI_DefineMetric("Throughput for Requests Received (bits/s)", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);
        stats->repSentThroughputId = GUI_DefineMetric("Throughput for Replies Sent (bits/s)", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);
        stats->repRcvdThroughputId = GUI_DefineMetric("Throughput for Replies Received (bits/s)", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);

#ifdef ADDON_BOEINGFCS

        stats->totalRealTimePerSimTimeId = GUI_DefineMetric("Total Packet Real Time/Simulation Time Ratio", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);
        stats->avgRealTimePerSimTimeId = GUI_DefineMetric("Average Packet Real Time/Simulation Time Ratio", node->nodeId, GUI_APP_LAYER, 0, GUI_DOUBLE_TYPE,GUI_CUMULATIVE_METRIC);
        stats->numSlowPacketsId = GUI_DefineMetric("Total Packets with Real Time Greater than Simulation Time", node->nodeId, GUI_APP_LAYER, 0, GUI_UNSIGNED_TYPE,GUI_CUMULATIVE_METRIC);

#endif /* ADDON_BOEINGFCS */

    }

    memset(&(stats->numReqBytesSent), 0, sizeof(D_UInt64));
    stats->numReqBytesSent = 0;

    stats->lastNumReqBytesSent = 0;

    memset(&(stats->numReqPacketsSent), 0, sizeof(D_UInt64));
    stats->numReqPacketsSent = 0;

    memset(&(stats->numReqFragsSent), 0, sizeof(D_UInt64));
    stats->numReqFragsSent = 0;

    memset(&(stats->numRepBytesSent), 0, sizeof(D_UInt64));
    stats->numRepBytesSent = 0;

    stats->lastNumRepBytesSent = 0;

    memset(&(stats->numRepPacketsSent), 0, sizeof(D_UInt64));
    stats->numRepPacketsSent = 0;

    memset(&(stats->numRepFragsSent), 0, sizeof(D_UInt64));
    stats->numRepFragsSent = 0;

    memset(&(stats->numRepFragsRcvdOutOfSeq), 0, sizeof(D_UInt64));
    stats->numRepFragsRcvdOutOfSeq = 0;

    memset(&(stats->numRepPacketsRcvd), 0, sizeof(D_UInt64));
    stats->numRepPacketsRcvd = 0;

    memset(&(stats->numRepFragsRcvd), 0, sizeof(D_UInt64));
    stats->numRepFragsRcvd = 0;

    memset(&(stats->numRepFragBytesRcvd), 0, sizeof(D_UInt64));
    stats->numRepFragBytesRcvd = 0;

    stats->lastNumRepFragBytesRcvd = 0;

    memset(&(stats->numReqFragsRcvdOutOfSeq), 0, sizeof(D_UInt64));
    stats->numReqFragsRcvdOutOfSeq = 0;

    memset(&(stats->numReqPacketsRcvd), 0, sizeof(D_UInt64));
    stats->numReqPacketsRcvd = 0;

    memset(&(stats->numReqFragsRcvd), 0, sizeof(D_UInt64));
    stats->numReqFragsRcvd = 0;

    memset(&(stats->numReqFragBytesRcvd), 0, sizeof(D_UInt64));
    stats->numReqFragBytesRcvd = 0;

    memset(&(stats->lastNumReqFragBytesRcvd), 0, sizeof(D_UInt64));
    stats->lastNumReqFragBytesRcvd = 0;

    memset(&(stats->numReqPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->numReqPacketBytesRcvd = 0;

    memset(&(stats->lastNumReqPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->lastNumReqPacketBytesRcvd = 0;

    memset(&(stats->numRepPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->numRepPacketBytesRcvd = 0;

    memset(&(stats->lastNumRepPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->lastNumRepPacketBytesRcvd = 0;


    memset(&(stats->reqSentThroughput), 0, sizeof(D_Float64));
    stats->reqSentThroughput = 0;

    memset(&(stats->reqRcvdThroughput), 0, sizeof(D_Float64));
    stats->reqRcvdThroughput = 0;

    memset(&(stats->repSentThroughput), 0, sizeof(D_Float64));
    stats->repSentThroughput = 0;

    memset(&(stats->repRcvdThroughput), 0, sizeof(D_Float64));
    stats->repRcvdThroughput = 0;


    memset(&(stats->numReqBytesSentPacket), 0, sizeof(D_UInt64));
    stats->numReqBytesSentPacket = 0;

    stats->lastNumReqBytesSentPacket = 0;

    memset(&(stats->numRepBytesSentPacket), 0, sizeof(D_UInt64));
    stats->numRepBytesSentPacket = 0;

    stats->lastNumRepBytesSentPacket = 0;

    memset(&(stats->numReqPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->numReqPacketBytesRcvd = 0;

    stats->lastNumRepPacketBytesRcvd = 0;

    memset(&(stats->numRepPacketBytesRcvd), 0, sizeof(D_UInt64));
    stats->lastNumReqPacketBytesRcvd = 0;
    stats->numReqPacketBytesRcvdThisPacket = 0;
    stats->numRepPacketBytesRcvdThisPacket = 0;
    stats->numRepPacketBytesRcvd = 0;

    stats->lastNumRepBytesSentPacket = 0;

    memset(&(stats->reqSentThroughputPacket), 0, sizeof(D_Float64));
    stats->reqSentThroughputPacket = 0;

    memset(&(stats->reqRcvdThroughputPacket), 0, sizeof(D_Float64));
    stats->reqRcvdThroughputPacket = 0;

    memset(&(stats->repSentThroughputPacket), 0, sizeof(D_Float64));
    stats->repSentThroughputPacket = 0;

    memset(&(stats->repRcvdThroughputPacket), 0, sizeof(D_Float64));
    stats->repRcvdThroughputPacket = 0;

    stats->chainTransDelay = 0;

    stats->chainTransDelayWithTrigger = 0;

    stats->chainTputWithTrigger = 0;

    stats->numRepCompletePacketBytesRcvd = 0 ;
    stats->numReqCompletePacketBytesRcvd = 0 ;
#ifdef ADDON_BOEINGFCS
    stats->totalRealTimePerSimTime = 0;
    stats->avgRealTimePerSimTime = 0;
    stats->numSlowPackets = 0;
    stats->numReqFragsRcvdDP = 0;
    stats->numReqPacketsRcvdDP = 0;
#endif /* ADDON_BOEINGFCS */

#ifdef ADDON_DB
    stats->hopCount = 0;
#endif
}

void SuperApplicationPrintStats(Node* node, SuperApplicationData* dataPtr) {
    SuperApplicationStatsType *stats = &(dataPtr->stats);
    char buf[MAX_STRING_LENGTH];

#ifdef ADDON_BOEINGFCS
    float percentageNonRealtime = 0.0;
#endif /* ADDON_BOEINGFCS */

    char statProtocolName[MAX_STRING_LENGTH];
    strcpy(statProtocolName, dataPtr->printName);
    /*
        if (dataPtr->protocol == APP_SUPERAPPLICATION_SERVER) {
            strcat(statProtocolName, "Server");
        } else {
            strcat(statProtocolName, "Client");
        }*/

    sprintf(buf, "Number of out of order reply fragments received = ""%" TYPES_64BITFMT "u", (UInt64)stats->numRepFragsRcvdOutOfSeq);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
    sprintf(buf, "Number of complete reply packets received  = ""%" TYPES_64BITFMT "u", (UInt64)stats->numRepPacketsRcvd);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
    sprintf(buf, "Number of out of order request fragments received = ""%" TYPES_64BITFMT "u", (UInt64)stats->numReqFragsRcvdOutOfSeq);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
    sprintf(buf, "Number of complete request packets received  = ""%" TYPES_64BITFMT "u", (UInt64)stats->numReqPacketsRcvd);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);

#ifdef ADDON_BOEINGFCS

    if (dataPtr->printRealTimeStats)
    {
        sprintf(buf, "Total transactional real-time (all packets) = %lf", stats->totalRealTimePerSimTime);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
        sprintf(buf, "Average transactional real-time (per packet) = %lf", stats->avgRealTimePerSimTime);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
        sprintf(buf, "Packets slower than transactional real-time = %ld", stats->numSlowPackets);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);

        if (stats->numReqPacketsRcvd > 0)
        {
            percentageNonRealtime = (float) stats->numSlowPackets /
                                    (float) stats->numReqPacketsRcvd;
        }

        sprintf(buf, "Percentage of packets slower than transactional real-time = %f", percentageNonRealtime);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
    }

#endif /* ADDON_BOEINGFCS */

}

void SuperApplicationRunTimeStat(Node* node, SuperApplicationData* dataPtr) {
    //clocktype now = node->getNodeTime();
    clocktype now = node->getNodeTime() + getSimStartTime(node);
    if (node->guiOption) {
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqBytesSentId, (unsigned int)dataPtr->stats.numReqBytesSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqPacketsSentId, (unsigned int)dataPtr->stats.numReqPacketsSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqFragsSentId, (unsigned int)dataPtr->stats.numReqFragsSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepBytesSentId, (unsigned int)dataPtr->stats.numRepBytesSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepPacketsSentId, (unsigned int)dataPtr->stats.numRepPacketsSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepFragsSentId, (unsigned int)dataPtr->stats.numRepFragsSent, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepFragsRcvdOutOfSeqId, (unsigned int)dataPtr->stats.numRepFragsRcvdOutOfSeq, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepPacketsRcvdId, (unsigned int)dataPtr->stats.numRepPacketsRcvd, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepFragsRcvdId, (unsigned int)dataPtr->stats.numRepFragsRcvd, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numRepFragBytesRcvdId, (unsigned int)dataPtr->stats.numRepFragBytesRcvd, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqFragsRcvdOutOfSeqId, (unsigned int)dataPtr->stats.numReqFragsRcvdOutOfSeq, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqPacketsRcvdId, (unsigned int)dataPtr->stats.numReqPacketsRcvd, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqFragsRcvdId, (unsigned int)dataPtr->stats.numReqFragsRcvd, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numReqFragBytesRcvdId, (unsigned int)dataPtr->stats.numReqFragBytesRcvd, now);
        GUI_SendRealData(node->nodeId, dataPtr->stats.reqSentThroughputId, dataPtr->stats.reqSentThroughput, now);
        GUI_SendRealData(node->nodeId, dataPtr->stats.reqRcvdThroughputId, dataPtr->stats.reqRcvdThroughput, now);
        GUI_SendRealData(node->nodeId, dataPtr->stats.repSentThroughputId, dataPtr->stats.repSentThroughput, now);
        GUI_SendRealData(node->nodeId, dataPtr->stats.repRcvdThroughputId, dataPtr->stats.repRcvdThroughput, now);

#ifdef ADDON_BOEINGFCS
        GUI_SendRealData(node->nodeId, dataPtr->stats.totalRealTimePerSimTimeId, dataPtr->stats.totalRealTimePerSimTime, now);
        GUI_SendRealData(node->nodeId, dataPtr->stats.avgRealTimePerSimTimeId, dataPtr->stats.avgRealTimePerSimTime, now);
        GUI_SendUnsignedData(node->nodeId, dataPtr->stats.numSlowPacketsId, dataPtr->stats.numSlowPackets, now);
#endif /* ADDON_BOEINGFCS */

    }
}

// /**
// FUNCTION   :: SuperApplicationInitTrace
// LAYER      :: APPLCATION
// PURPOSE    :: SuperApplication initialization  for tracing
// PARAMETERS ::
// + node : Node* : Pointer to node
// + nodeInput    : const NodeInput* : Pointer to NodeInput
// RETURN ::  void : NULL
// **/

void SuperApplicationInitTrace(Node* node, const NodeInput* nodeInput)

{
    char buf[MAX_STRING_LENGTH];
    BOOL retVal;
    BOOL traceAll = TRACE_IsTraceAll(node);
    BOOL trace = FALSE;
    static BOOL writeMap = TRUE;

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "TRACE-SUPERAPPLICATION",
        &retVal,
        buf);

    if (retVal)
    {
        if (strcmp(buf, "YES") == 0)
        {
            trace = TRUE;
        }
        else if (strcmp(buf, "NO") == 0)
        {
            trace = FALSE;
        }
        else
        {
            ERROR_ReportError(
                "TRACE-SUPERAPPLICATION should be either \"YES\" or \"NO\".\n");
        }
    }
    else
    {
        if (traceAll || node->traceData->layer[TRACE_APPLICATION_LAYER])
        {
            trace = TRUE;
        }
    }

    if (trace)
    {
        TRACE_EnableTraceXML(node, TRACE_SUPERAPPLICATION,
                             "SUPERAPPLICATION", SuperApplicationPrintTraceXML, writeMap);
    }
    else
    {
        TRACE_DisableTraceXML(node, TRACE_SUPERAPPLICATION,
                              "SUPERAPPLICATION", writeMap);
    }
    writeMap = FALSE;
}

void
SuperApplicationInit(Node* node,
                     NodeAddress clientAddr,
                     NodeAddress serverAddr,
                     char* inputstring,
                     int iindex,
                     const NodeInput *nodeInput,
                     Int32 mdpUniqueId) {

    SuperApplicationData *dataPtr = NULL;

    ERROR_Assert(clientAddr != serverAddr, "SuperApp does not support loopback (client address must be different than server address)");

    // Perform common init functions for UDP & TCP
    NodeAddress clientNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                node, clientAddr);

    NodeAddress serverNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                               node, serverAddr);
    BOOL isClient = FALSE;
    BOOL isServer = FALSE;

    if (node->nodeId == clientNodeId)
    {
        // Allocate memory
        dataPtr = SuperApplicationClientNewClient(node);
        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, clientAddr);
        SetIPv4AddressInfo(&rAddr, serverAddr);

        // Do the parsing & register the application
        SuperApplicationClientInit(node,
                                   inputstring,
                                   dataPtr,
                                   clientAddr,
                                   serverAddr,
                                   mdpUniqueId);

        // dns
        // Skipped if the server network type is not valid
        // it should happen only when the server address is given by a URL
        // statistics will be initialized when url is resolved by dns
        if (serverAddr != 0 && node->appData.appStats)
        {
            std::string customName;
            if (dataPtr->applicationName == NULL)
            {
                customName = "Super-App Client";
            }
            else
            {
                customName = dataPtr->applicationName;
            }
            if (NetworkIpIsMulticastAddress(node,serverAddr))
            {
                dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                      "SUPER-APP CLIENT Request",
                                                      STAT_Multicast,
                                                      STAT_AppSenderReceiver,
                                                      customName.c_str());
            }
            else
            {
                dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                      "SUPER-APP CLIENT Request",
                                                      STAT_Unicast,
                                                      STAT_AppSenderReceiver,
                                                      customName.c_str());
            }
        
            dataPtr->stats.appStats->Initialize(
                 node,
                 lAddr,
                 rAddr,
                 (STAT_SessionIdType)dataPtr->uniqueId,
                 dataPtr->uniqueId);

            dataPtr->stats.appStats->setTos(dataPtr->reqTOS);
        }

        if (dataPtr->transportLayer != SUPERAPPLICATION_UDP && node->appData.appStats)
        {
            dataPtr->stats.appStats->EnableAutoRefragment();
        }
        isClient = TRUE;

        if (dataPtr->isMdpEnabled)
        {
            Address localAddr, destAddr;
            memset(&localAddr,0,sizeof(Address));
            memset(&destAddr,0,sizeof(Address));

            localAddr.networkType = NETWORK_IPV4;
            localAddr.interfaceAddr.ipv4 = clientAddr;

            destAddr.networkType = NETWORK_IPV4;
            destAddr.interfaceAddr.ipv4 = serverAddr;

            if (NetworkIpIsMulticastAddress(node, serverAddr))
            {
                // MDP Layer Init
                MdpLayerInit(node,
                             localAddr,
                             destAddr,
                             dataPtr->sourcePort,
                             APP_SUPERAPPLICATION_CLIENT,
                             dataPtr->isProfileNameSet,
                             dataPtr->profileName,
                             dataPtr->mdpUniqueId,
                             nodeInput,
                             dataPtr->destinationPort);
            }
            else
            {
                // MDP Layer Init
                MdpLayerInit(node,
                             localAddr,
                             destAddr,
                             dataPtr->sourcePort,
                             APP_SUPERAPPLICATION_CLIENT,
                             dataPtr->isProfileNameSet,
                             dataPtr->profileName,
                             dataPtr->mdpUniqueId,
                             nodeInput,
                             dataPtr->destinationPort,
                             TRUE);
            }
        }
    }

    if (NetworkIpIsMulticastAddress(node, serverAddr) &&
                            dataPtr->transportLayer == SUPERAPPLICATION_TCP)
    {
       ERROR_Assert(FALSE, "SuperApp does not support multicast for reliable"
            " communication.");
    }

    if (node->nodeId == serverNodeId)
    {
        // Allocate memory
        dataPtr = SuperApplicationServerNewServer(node);
        // Do the parsing & register the application
        SuperApplicationServerInit(node,inputstring,dataPtr, clientAddr,
            serverAddr, mdpUniqueId);

        isServer = TRUE;

        if (dataPtr->isMdpEnabled)
        {
            // Init MDP layer for the unicast destination node on UDP
            MdpLayerInitForOtherPartitionNodes(node,
                                               nodeInput,
                                               NULL,
                                               TRUE);

            if (dataPtr->processReply)
            {
                Address localAddr, destAddr;
                memset(&localAddr,0,sizeof(Address));
                memset(&destAddr,0,sizeof(Address));

                localAddr.networkType = NETWORK_IPV4;
                localAddr.interfaceAddr.ipv4 = clientAddr;

                destAddr.networkType = NETWORK_IPV4;
                destAddr.interfaceAddr.ipv4 = serverAddr;

                // MDP Layer and Session Init for the unicast reply process
                MdpLayerInit(node,
                             destAddr,
                             localAddr,
                             dataPtr->destinationPort,
                             APP_SUPERAPPLICATION_SERVER,
                             dataPtr->isProfileNameSet,
                             dataPtr->profileName,
                             dataPtr->mdpUniqueId,
                             nodeInput,
                             dataPtr->sourcePort,
                             TRUE);
            }
        }
    }

    // Store the statement number of app-config. This is sent
    // in the first packet that is sent to the server. This enables
    // the server to initialise itself on receiving the first packet.
    // On receiving the first packet, the server will know which
    // (addr,port) the client is on from the transport layer. This index
    // value is then used by server to initialise itself using the correct
    // statementfrom the application config file. This is required since the
    // server may have to send reply back to the client and thus should
    // have the correct reply information listed in the app statement that
    // initialised the client.

    dataPtr->appFileIndex = iindex;
    dataPtr->initStats = TRUE;

    RANDOM_SetSeed(dataPtr->seed,
                   node->globalSeed,
                   node->nodeId,
                   // can use CLIENT or SERVER... just need to pass
                   // in a unique identifier.
                   APP_SUPERAPPLICATION_CLIENT,
                   DEFAULT_INTERFACE);

#ifdef ADDON_BOEINGFCS
    // Used to offset start time in .app file so that the .app file
    // does not need to be updated if we just want to offset the start
    // time.  Have not been tested with all features of SuperApp, so
    // this parameter is for internal use only.
    dataPtr->startTimeOffset = 0;
    BOOL retVal;

    IO_ReadTime(
            node->nodeId,
            ANY_ADDRESS,
            nodeInput,
            "APP-START-TIME-OFFSET",
            &retVal,
            &dataPtr->startTimeOffset);

    dataPtr->sessionStart += dataPtr->startTimeOffset;
    dataPtr->sessionFinish += dataPtr->startTimeOffset;

#endif

    // Client: Perform functions specific to UDP / TCP
    if (isClient)
    {
        // dynamic address
        AppplicationStartCallBack callbackFunction;
        if (dataPtr->transportLayer == SUPERAPPLICATION_TCP &&
            dataPtr->isConditions == FALSE)
        {
            callbackFunction =
                        &AppSuperApplicationUrlTCPSessionStartCallBack;
        }
        else
        {
            callbackFunction =
                        &AppSuperApplicationUrlUDPSessionStartCallBack;
        }
        node->appData.appTrafficSender->superApplicationDnsInit(
                                node,
                                inputstring,
                                nodeInput,
                                dataPtr,
                                callbackFunction);
        if (dataPtr->transportLayer == SUPERAPPLICATION_UDP)
        {
            // Perform init function for UDP Client
            SuperApplicationClientScheduleFirstPacket_UDP(node,dataPtr);
        }
        else
        {
            dataPtr->connectionId = -1;
            // Perform init function for TCP Client
            if (dataPtr->isConditions == FALSE && dataPtr->serverAddr != 0)
            {
                SuperApplicationClientOpenConnection_TCP(node, dataPtr);
            }
        }
    }

    // Server: Perform functions specific to UDP / TCP
    if (isServer)
    {
        if (dataPtr->transportLayer == SUPERAPPLICATION_TCP)
        {
            // Dynamic address
            // Delay Super-app server listening by start time
            // such that server may acquire an address by that time
            Address clientAddr;
            Address serverAddr;
            NodeAddress clientId;
            NodeAddress serverId;
            char clientString[MAX_STRING_LENGTH];
            char serverString[BIG_STRING_LENGTH];

            sscanf(inputstring,
                    "%*s %s %s",
                    clientString, serverString);
            IO_AppParseSourceAndDestStrings(
                        node,
                        inputstring,
                        clientString,
                        &clientId,
                        &clientAddr,
                        serverString,
                        &serverId,
                        &serverAddr);

            // get the server node and destAddress of application
            // server
            if (ADDR_IsUrl(serverString))
            {
                DnsClientData serverDnsClientData;
                Node* destNode =
                    node->appData.appTrafficSender->getAppServerAddressAndNodeFromUrl(
                                                    node,
                                                    serverString,
                                                    &serverAddr,
                                                    &serverDnsClientData);
             }

            // get the start time
            clocktype startTime = AppSuperApplicationGetSessionStartTime(
                                                        node,
                                                        inputstring,
                                                        dataPtr);

            // to ensure that server listens earlier than TCP
            // open; therefore listen timer should be set at unit
            // time (1 ns) before Open. If start time is less than
            // 1 nano second(0S) then listenTime remains as 0S which
            // is the least possible simulation time
            clocktype listenTime = 0;
            if (startTime > 1 * NANO_SECOND)
            {
                listenTime = startTime - 1 * NANO_SECOND;
            }
            AppStartTcpAppSessionServerListenTimer(
                                        node,
                                        APP_SUPERAPPLICATION_SERVER,
                                        serverAddr,
                                        serverString,
                                        listenTime);

            dataPtr->connectionId = -1;
            // add the address information
            AppSuperAppplicationClientAddAddressInformation(node, dataPtr);
        }
        else
        {
            dataPtr->sourcePort = SUPERAPPLICATION_INVALID_SOURCE_PORT;
            // UDP server is fully initialised only on receiving first
            // packet from client
        }
    }

    //UserCodeEndInit
    if (dataPtr->initStats) {
        SuperApplicationInitStats(node, &(dataPtr->stats));
#ifdef ADDON_BOEINGFCS
        dataPtr->maxEndToEndDelayForReq = 0;
        dataPtr->minEndToEndDelayForReq = CLOCKTYPE_MAX;
        dataPtr->maxEndToEndDelayForReqDP = 0;
        dataPtr->minEndToEndDelayForReqDP = CLOCKTYPE_MAX;

        dataPtr->maxEndToEndDelayForReqPacket = 0;
        dataPtr->minEndToEndDelayForReqPacket = CLOCKTYPE_MAX;
        dataPtr->maxEndToEndDelayForReqPacketDP = 0;
        dataPtr->minEndToEndDelayForReqPacketDP = CLOCKTYPE_MAX;

        char buf[MAX_STRING_LENGTH];

        // first check if the transport layer protocol for SIP is UDP
        IO_ReadString(ANY_NODEID,
                      ANY_ADDRESS,
                      nodeInput,
                      "PROCESSING-DELAY",
                      &retVal,
                      buf);

        if (retVal)
        {
            dataPtr->delayRealTimeProcessing = TIME_ConvertToClock(buf);
        } else {
            dataPtr->delayRealTimeProcessing = SUPERAPPLICATION_REALTIME_PROCESS_DELAY;
        }

#endif
    }
    if (isClient && dataPtr->transportLayer == SUPERAPPLICATION_UDP) {
        Message *msg = NULL;
        dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_UDP;
        enterSuperApplicationClientIdle_UDP(node, dataPtr, msg);
        return;
    }
    if (isServer && dataPtr->transportLayer == SUPERAPPLICATION_UDP) {
        Message *msg = NULL;
        dataPtr->state = SUPERAPPLICATION_SERVERIDLE_UDP;
        enterSuperApplicationServerIdle_UDP(node, dataPtr, msg);
        return;
    }
    if (isClient && dataPtr->transportLayer == SUPERAPPLICATION_TCP) {
        Message *msg = NULL;
        dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_TCP;
        enterSuperApplicationClientIdle_TCP(node, dataPtr, msg);
        return;
    }
    if (isServer && dataPtr->transportLayer == SUPERAPPLICATION_TCP) {
        Message *msg = NULL;
        dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
        enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
        return;
    }

}


void
SuperAppTriggerFinalize(Node* node, SuperApplicationData* dataPtr)
{
    SuperAppTriggerData* trigger =
        (SuperAppTriggerData*)(node->appData.triggerAppData);
    SuperAppChainStatsList* stats = &trigger->stats;
    const char* ProtocolName = "Trigger Chain";
    char buf[MAX_STRING_LENGTH];

    if (stats->numInList > 0) {
        SuperAppChainStatsElement* curr = stats->head;
        while (curr!=NULL) {
            if (strcmp(curr->chainID,dataPtr->chainID) == 0) {
                sprintf(buf, "Chain ID = %s", curr->chainID);
                IO_PrintStat(node,
                             "Application",
                             ProtocolName,
                             ANY_DEST,
                             0,
                             buf);

                sprintf(buf, "Number of Packets Sent = %d", curr->pktsSent);
                IO_PrintStat(node,
                             "Application",
                             ProtocolName,
                             ANY_DEST,
                             0,
                             buf);

                sprintf(buf, "Number of Packets Received = %d", curr->pktsRecv);
                IO_PrintStat(node,
                             "Application",
                             ProtocolName,
                             ANY_DEST,
                             0,
                             buf);
            }
            curr = curr->next;
        }
    }
}

void
SuperApplicationClientFinalize(Node* node)
{
}

void
SuperApplicationFinalize(Node* node, SuperApplicationData* dataPtr) {

    //UserCodeStartFinalize

    char buf[MAX_STRING_LENGTH];
    char SrcAddrStr[MAX_STRING_LENGTH];
    char DstAddrStr[MAX_STRING_LENGTH];
    char statProtocolName[MAX_STRING_LENGTH];
    char clockStr[MAX_STRING_LENGTH];

    clocktype avgJitter;
    clocktype avgDelay;

    // shouldnt ALWAYS be true!!
    //dataPtr->printStats = TRUE;
    dataPtr->printStats = node->appData.appStats;
    strcpy(statProtocolName,dataPtr->printName);
    IO_ConvertIpAddressToString(dataPtr->clientAddr, SrcAddrStr);
    // dynamic address
    if (dataPtr->serverAddr == 0 && dataPtr->serverUrl->length() != 0)
    {
        strcpy(DstAddrStr, dataPtr->serverUrl->c_str());
    }
    else
    {
        IO_ConvertIpAddressToString(dataPtr->serverAddr, DstAddrStr);
    }

    if (dataPtr->printStats && dataPtr->stats.appStats)
    {
        if (NetworkIpIsMulticastAddress(node, dataPtr->serverAddr))
        {
            if (!dataPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
            {
                dataPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
            }
        }
        else
        {
            if (!dataPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
            {
                dataPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
            }
        }
    }

    if (dataPtr->protocol == APP_SUPERAPPLICATION_SERVER) {
        //strcat(statProtocolName, "Server");
        sprintf(buf, "Client Address = %s", SrcAddrStr);
    } else {
        //strcat(statProtocolName, "Client");
        sprintf(buf, "Server Address = %s", DstAddrStr);
    }

    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST,
    dataPtr->sourcePort, buf);

    sprintf(buf, "Connection: Client(%s: %d) - Server(%s: %d)",
            SrcAddrStr,
            dataPtr->sourcePort,
            DstAddrStr,
            dataPtr->destinationPort);
    IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);

    if (dataPtr->printStats && dataPtr->stats.appStats)
    {
        if (dataPtr->protocol == APP_SUPERAPPLICATION_SERVER)
        {
            dataPtr->stats.appStats->Print(node,
                            "Application",
                            "SUPER-APP Server",
                            ANY_ADDRESS,
                            dataPtr->sourcePort);
        }
        else
        {
            dataPtr->stats.appStats->Print(node,
                            "Application",
                            "SUPER-APP Client",
                            ANY_ADDRESS,
                            dataPtr->sourcePort);
        }
    }
    if (dataPtr->isChainId && dataPtr->protocol == APP_SUPERAPPLICATION_SERVER) {
        TIME_PrintClockInSecond(dataPtr->stats.chainTransDelay, clockStr);
        sprintf(buf, "Chain transmission delay (s) = %s", clockStr);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);

        TIME_PrintClockInSecond(dataPtr->stats.chainTransDelayWithTrigger, clockStr);
        sprintf(buf, "Chain transmission delay with Trigger (s) = %s", clockStr);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);

        sprintf(buf, "Throughput with Trigger (bits / s) = %f", dataPtr->stats.chainTputWithTrigger);
        IO_PrintStat(node, "Application", statProtocolName, ANY_DEST, dataPtr->sourcePort, buf);
    }

    //UserCodeEndFinalize

    if (dataPtr->printStats) {
        SuperApplicationPrintStats(node, dataPtr);
    }
    if (dataPtr->isChainId && dataPtr->isTriggered) {
        SuperAppUpdateChainStats(node, dataPtr);
        if (dataPtr->printStats) {
            SuperAppTriggerFinalize(node, dataPtr);
        }
    }

#ifdef ADDON_DB
    if (dataPtr->msgSeqCache != NULL)
    {
        delete dataPtr->msgSeqCache;
        dataPtr->msgSeqCache = NULL;
    }

    if (dataPtr->fragSeqCache != NULL)
    {
        delete dataPtr->fragSeqCache;
        dataPtr->fragSeqCache = NULL;
    }

    // STATS DB CODE (TESTING ONLY)
    /*printf ("------------NETWORK EVENTS TABLE-----------------------------------------------------\n");
    STATSDB_PrintTable(node->partitionData, node, STATSDB_NETWORK_EVENTS_TABLE);
    printf ("#-------------------------------------------------------------------------------------\n");
    printf ("------------APPLICATION EVENTS TABLE--------------------------------------------------\n");
    STATSDB_PrintTable(node->partitionData, node, STATSDB_APP_EVENTS_TABLE);
    printf ("#-------------------------------------------------------------------------------------\n");
    printf ("------------NETWORK CONNECTIVITY TABLE--------------------------------------------------\n");
    STATSDB_PrintTable(node->partitionData, node, STATSDB_NETWORK_CONNECTIVITY_TABLE);
    printf ("#-------------------------------------------------------------------------------------\n");
    printf("PRINT IS DONE\n\n\n\n");*/
#endif
    if (dataPtr->serverUrl)
    {
        delete (dataPtr->serverUrl);
        dataPtr->serverUrl = NULL;
    }

}


void
SuperApplicationProcessEvent(Node* node, Message* msg) {

    SuperApplicationData* dataPtr = NULL;

    int event;
    AppInfo* appList = node->appData.appPtr;
    int     id;
    int     tcpLocalPort = -1;
    NodeAddress     address = (NodeAddress) -1;
    short appType = APP_GetProtocolType(node,msg);
    BOOL tcpMode = TRUE;
    NodeAddress tcpClientAddr;
    int     tcpClientPort = -1;


    switch (msg->eventType) {
    case MSG_APP_FromTransListenResult:
    {
        TransportToAppListenResult* listenResult;
        listenResult = (TransportToAppListenResult*) MESSAGE_ReturnInfo(msg);
        id         = -1;
        tcpLocalPort = listenResult->localPort;
        break;
    }
    case MSG_APP_FromTransOpenResult:
    {
        TransportToAppOpenResult* openResult = NULL;
        openResult = (TransportToAppOpenResult*) MESSAGE_ReturnInfo(msg);
        id         = -1;
        tcpLocalPort = openResult->localPort;
        tcpClientAddr = GetIPv4Address(openResult->remoteAddr);
        tcpClientPort = openResult->remotePort;

        break;
    }
    case MSG_APP_FromTransDataSent:
    {
        TransportToAppDataSent* dataSent;
        dataSent = (TransportToAppDataSent*) MESSAGE_ReturnInfo(msg);
        id         = dataSent->connectionId;
        break;
    }
    case MSG_APP_FromTransDataReceived:
    {
        TransportToAppDataReceived* dataReceived;
        dataReceived = (TransportToAppDataReceived*) MESSAGE_ReturnInfo(msg);
        id         = dataReceived->connectionId;
        break;
    }
    case MSG_APP_FromTransCloseResult:
    {
        TransportToAppCloseResult* closeResult;
        closeResult = (TransportToAppCloseResult *) MESSAGE_ReturnInfo(msg);
        id         = closeResult->connectionId;
        break;
    }

    case MSG_APP_TimerExpired:
    {
        AppTimer* timer;
        timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

        if (timer)
        {
            if (timer->connectionId <= 0) {
                tcpMode = FALSE;
                id = timer->sourcePort;
                /*if (APP_GetProtocolType(node,msg) == APP_SUPERAPPLICATION_CLIENT) {
                    address = MAPPING_GetDefaultInterfaceAddressFromNodeId(node, node->nodeId);
                } else {*/
                    address = timer->address;
                //}
            } else {
                id = timer->connectionId;
            }
        }
        if (appType == APP_SUPERAPPLICATION_SERVER)
        {
            // now start listening at the updated address if
            // in valid address state
            Address serverAddress;
            AppTcpListenTimer* timerInfo = (AppTcpListenTimer*)
                        MESSAGE_ReturnInfo(msg, INFO_TYPE_AppServerListen);
            if (timerInfo != NULL)
            {
                if (AppTcpValidServerAddressState(node, msg, &serverAddress))
                {
                    for (; appList != NULL; appList = appList->appNext)
                    {
                        if (appList->appType == appType)
                        {
                            dataPtr = (SuperApplicationData*) appList->appDetail;
                            if (dataPtr->serverAddr ==
                                timerInfo->address.interfaceAddr.ipv4)
                            {
                                dataPtr->serverAddr =
                                    serverAddress.interfaceAddr.ipv4;
                                // update the client address
                                Int32 serverAddresState = 0;
                                Address clientAddress;
                                memset(&clientAddress,
                                       0, sizeof(Address));
                                MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                                node,
                                                dataPtr->clientNodeId,
                                                dataPtr->clientInterfaceIndex,
                                                timerInfo->address.networkType,
                                                &clientAddress);
                                dataPtr->clientAddr =
                                            clientAddress.interfaceAddr.ipv4;
                                Address serverAddr;
                                serverAddr.networkType = NETWORK_IPV4;
                                serverAddr.interfaceAddr.ipv4 =
                                                        dataPtr->serverAddr;
                                node->appData.appTrafficSender->
                                    appTcpListenWithPriority(
                                        node,
                                        APP_SUPERAPPLICATION_SERVER,
                                        serverAddr,
                                        dataPtr->destinationPort,
                                        dataPtr->reqTOS);
                            }
                        }
                    }
                }
                return;
            }
        }
        break;
    }
    case MSG_APP_FromTransport:
    {
        UdpToAppRecv* info;
        info = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
        tcpMode = FALSE;
        if (APP_GetProtocolType(node,msg) == APP_SUPERAPPLICATION_CLIENT) {
            id = info->destPort;
            //address = GetIPv4Address(info->destAddr);
            address = GetIPv4Address(info->sourceAddr);
        } else {
            id = info->sourcePort;
            address = GetIPv4Address(info->sourceAddr);
        }
        break;
    }
    case MSG_APP_TALK_TIME_OUT:
    {
        AppTimer* timer;
        timer = (AppTimer *) MESSAGE_ReturnInfo(msg);
        tcpMode = FALSE;
        id = timer->sourcePort;
        address = timer->address;
        break;
    }
    default:
        return;
    }

    for (; appList != NULL; appList = appList->appNext) {
        if (appList->appType == appType) {

            dataPtr = (SuperApplicationData*) appList->appDetail;
            if (tcpMode && dataPtr->transportLayer == SUPERAPPLICATION_TCP) {
                if (id == -1) {
                    // handle open and listen result for tcp
                    if (APP_GetProtocolType(node,msg) == APP_SUPERAPPLICATION_CLIENT) {
                        if (dataPtr->sourcePort == tcpLocalPort) {
                            break;
                        }
                    } else {
                        /* Using clientAddr/destinationPort/sourcePort as key
                         * to identify the correct dataPtr.*/
                        if (((msg->eventType == MSG_APP_FromTransOpenResult)
                            && (dataPtr->clientAddr == tcpClientAddr)
                            && (dataPtr->destinationPort == tcpLocalPort)
                            && (!dataPtr->sourcePort ||
                            (dataPtr->sourcePort == tcpClientPort))
                            && (dataPtr->connectionId == -1))
                            || ((msg->eventType == MSG_APP_FromTransListenResult)
                            && (dataPtr->connectionId == -1)))
                        {
                            break;
                        }
                    }
                    // end handle open and listen result for tcp
                } else if (dataPtr->connectionId == id) {
                    break;
                }
            } else if (!tcpMode && dataPtr->transportLayer == SUPERAPPLICATION_UDP) {
                if (appList->appType == APP_SUPERAPPLICATION_CLIENT
                    // if url then address will be 0 untill URL is resolved
                    // but sourcePort will be unique to identify session
                    && (dataPtr->serverAddr == address || address == 0)
                    && dataPtr->sourcePort == id)
                {
                    break;
                }
                if (appList->appType == APP_SUPERAPPLICATION_SERVER
                    && dataPtr->clientAddr == address
                    && dataPtr->sourcePort == id)
                {
                    break;
                }

                /*if ((dataPtr->clientAddr == address) &&
                        (dataPtr->sourcePort == id)) {
                    break;
                }*/
            }
            dataPtr = NULL;
        }
    }

    if (tcpMode ||
            (APP_GetProtocolType(node,msg) == APP_SUPERAPPLICATION_CLIENT)) {
        ERROR_Assert(dataPtr != NULL, "Data structure not found");
    }
    if (dataPtr == NULL) {
        dataPtr = SuperApplicationServerSetDataPtr(node, msg);
    }
    if (dataPtr == NULL){
        ERROR_ReportError("can't find server pointer\n");
    }



#ifdef ADDON_BOEINGFCS
    if (msg->eventType == MSG_APP_TimerExpired)
    {
        clocktype rndTimer = 0;
        AppTimer* timer;
        timer = (AppTimer *) MESSAGE_ReturnInfo(msg);

        if (timer->type == SUPERAPPLICATION_BURSTY_TIMER)
        {
            int val = 0;
            int count = 0;

            if (dataPtr->burstyLow > 0)
                count++;
            if (dataPtr->burstyMedium > 0)
                count++;
            if (dataPtr->burstyHigh> 0)
                count++;

            val = RANDOM_nrand(dataPtr->seed) % count;

            if (val == 0)
            {
                dataPtr->burstyInterval = dataPtr->burstyLow;
            }
            else if (val == 1)
            {
                dataPtr->burstyInterval = dataPtr->burstyMedium;
            }
            else if (val == 2)
            {
                dataPtr->burstyInterval = dataPtr->burstyHigh;
            }
            else
                assert(0);

            assert(dataPtr->burstyInterval > 0);

            dataPtr->randomReqInterval.setDistributionDeterministic(dataPtr->burstyInterval);

            rndTimer = dataPtr->randomBurstyTimer.getRandomNumber();

            MESSAGE_Send(node, msg, rndTimer);
            return;
        }
    }
#endif /* ADDON_BOEINGFCS */

    event = msg->eventType;
    switch (dataPtr->state) {
    case SUPERAPPLICATION_SERVERIDLE_UDP:
        switch (event) {
        case MSG_APP_FromTransport:
            dataPtr->state = SUPERAPPLICATION_SERVER_RECEIVEDATA_UDP;
            enterSuperApplicationServer_ReceiveData_UDP(node, dataPtr, msg);
            break;
        case MSG_APP_TimerExpired:
            dataPtr->state = SUPERAPPLICATION_SERVER_TIMEREXPIRED_SENDREPLY_UDP;
            enterSuperApplicationServer_TimerExpired_SendReply_UDP(node, dataPtr, msg);
            break;
        case MSG_APP_TALK_TIME_OUT:
            dataPtr->state = SUPERAPPLICATION_SERVER_TIMEREXPIRED_STARTTALK_UDP;
            enterSuperApplicationServer_TimeExpired_StartTalk_UDP(node, dataPtr, msg);
            break;
        default:
            assert(FALSE);
        }
        break;
    case SUPERAPPLICATION_SERVER_TIMEREXPIRED_SENDREPLY_UDP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENTIDLE_UDP:
        switch (event) {
        case MSG_APP_TimerExpired:
            dataPtr->state = SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_UDP;
            enterSuperApplicationClient_TimerExpired_SendRequest_UDP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransport:
            dataPtr->state = SUPERAPPLICATION_CLIENT_RECEIVEREPLY_UDP;
            enterSuperApplicationClient_ReceiveReply_UDP(node, dataPtr, msg);
            break;
        case MSG_APP_TALK_TIME_OUT:
            dataPtr->state = SUPERAPPLICATION_CLIENT_TIMEREXPIRED_STARTTALK_UDP;
            enterSuperApplicationClient_TimeExpired_StartTalk_UDP(node, dataPtr, msg);
            break;
        default:
            assert(FALSE);
        }
        break;
    case SUPERAPPLICATION_CLIENT_RECEIVEREPLY_UDP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_UDP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_SERVER_RECEIVEDATA_UDP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_RECEIVEREPLY_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_CONNECTIONCLOSED_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_SERVER_RECEIVEDATA_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_SERVER_CONNECTIONCLOSED_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_SERVERIDLE_TCP:
        switch (event) {
        case MSG_APP_FromTransCloseResult:
            dataPtr->state = SUPERAPPLICATION_SERVER_CONNECTIONCLOSED_TCP;
            enterSuperApplicationServer_ConnectionClosed_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransDataReceived:
            dataPtr->state = SUPERAPPLICATION_SERVER_RECEIVEDATA_TCP;
            enterSuperApplicationServer_ReceiveData_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransListenResult:
            dataPtr->state = SUPERAPPLICATION_SERVER_LISTENRESULT_TCP;
            enterSuperApplicationServer_ListenResult_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransOpenResult:
            dataPtr->state = SUPERAPPLICATION_SERVER_CONNECTIONOPENRESULT_TCP;
            enterSuperApplicationServer_ConnectionOpenResult_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_TimerExpired:
            dataPtr->state = SUPERAPPLICATION_SERVER_TIMEREXPIRED_SENDREPLY_TCP;
            enterSuperApplicationServer_TimerExpired_SendReply_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransDataSent:
            if (msg)
            {
                MESSAGE_Free(node, msg);
            }
            //printf("Reply send\n");
            break;

        default:
            assert(FALSE);
        }
        break;
    case SUPERAPPLICATION_SERVER_CONNECTIONOPENRESULT_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENTIDLE_TCP:
        switch (event) {
        case MSG_APP_FromTransCloseResult:
            dataPtr->state = SUPERAPPLICATION_CLIENT_CONNECTIONCLOSED_TCP;
            enterSuperApplicationClient_ConnectionClosed_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransDataSent:
            dataPtr->state = SUPERAPPLICATION_CLIENT_DATASENT_TCP;
            enterSuperApplicationClient_DataSent_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_TimerExpired:
            dataPtr->state = SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_TCP;
            enterSuperApplicationClient_TimerExpired_SendRequest_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransOpenResult:
            dataPtr->state = SUPERAPPLICATION_CLIENT_CONNECTIONOPENRESULT_TCP;
            enterSuperApplicationClient_ConnectionOpenResult_TCP(node, dataPtr, msg);
            break;
        case MSG_APP_FromTransDataReceived:
            dataPtr->state = SUPERAPPLICATION_CLIENT_RECEIVEREPLY_TCP;
            enterSuperApplicationClient_ReceiveReply_TCP(node, dataPtr, msg);
            break;
        default:
            assert(FALSE);
        }
        break;
    case SUPERAPPLICATION_SERVER_LISTENRESULT_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_CONNECTIONOPENRESULT_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_TCP:
        assert(FALSE);
        break;
    case SUPERAPPLICATION_CLIENT_DATASENT_TCP:
        assert(FALSE);
        break;
    default:
        ERROR_ReportError("Illegal transition");
        break;
    }
}

// FUNCTION SuperApplicationCheckConditionKeyword
// PURPOSE  Check if a word is a special keyword for superapplication expect for CHAIN-ID.
// Parameters:
// keyword - word that will check against all other special keyword in superapplication
// Return:
//         TRUE - if there is a match for special keyword.
//         FALSE - if there is no match found.
static
BOOL SuperApplicationCheckConditionKeyword(char* keyword) {
    if (strcmp(keyword, "DELIVERY-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "UNRELIABLE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "RELIBALE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "START-TIME") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DET") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "EXP") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "UNI") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DURATION") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-NUM") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-SIZE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-INTERVAL") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-TOS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "PRECEDENCE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-PROCESS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "NO") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-PROCESS-DELAY") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-INTERDEPARTURE-DELAY") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "FRAGMENT-SIZE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCE-PORT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DESTINATION-PORT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DELIVERY-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "PACKETS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "CONDITIONS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "TIME-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPEAT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCES") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DESTINATIONS") == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

// FUNCTION SuperApplicationCheckKeyword
// PURPOSE  Check if a word is a special keyword for superapplication.
// Parameters:
// keyword - word that will check against all other special keyword in superapplication
// Return:
//         TRUE - if there is a match for special keyword.
//         FALSE - if there is no match found.
static
BOOL SuperApplicationCheckKeyword(char* keyword) {
    if (strcmp(keyword, "DELIVERY-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "UNRELIABLE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "RELIBALE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "START-TIME") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DET") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "EXP") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "UNI") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DURATION") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-NUM") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-SIZE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-INTERVAL") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REQUEST-TOS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "PRECEDENCE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-PROCESS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "NO") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "CHAIN-ID") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-PROCESS-DELAY") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPLY-INTERDEPARTURE-DELAY") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "FRAGMENT-SIZE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCE-PORT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DESTINATION-PORT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DELIVERY-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "PACKETS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "CONDITIONS") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "TIME-TYPE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCE") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "REPEAT") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "SOURCES") == 0) {
        return TRUE;
    } else if (strcmp(keyword, "DESTINATIONS") == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

// FUNCTION: SuperApplicationCheckInputString
// PURPOSE:  Check if user enable any of the special keyword
// Parameters:
//  appInput:    - pointer to the appInput.
//  i:           - index for the user configurations
//  isStartArray - return value for this function.  true if start array is enable
//  isUNI        - return value for this function.  true if UNI distribution is use
//  isRepeate    - return value for this function.  true if reapeat is enable
//  isSource     - return value for this function.  true if sources list is enable
//  isDestination - rtuern value for this function. true if destination list is enable
void  SuperApplicationCheckInputString(NodeInput* appInput,
                                       int i,
                                       BOOL* isStartArray,
                                       BOOL* isUNI,
                                       BOOL* isRepeat,
                                       BOOL* isSources,
                                       BOOL* isDestinations,
                                       BOOL* isConditions)
{

    char* tempstring = appInput->inputStrings[i];
    char keyword[MAX_STRING_LENGTH]="";
    int nToken=0;

    *isStartArray = FALSE;
    *isUNI = FALSE;
    *isRepeat = FALSE;
    *isSources = FALSE;
    *isDestinations = FALSE;

    while (tempstring!=NULL){
        nToken = sscanf(tempstring, "%s", keyword);
        // check if start time array is enable
        if (strcmp(keyword, "START-TIME") == 0) {
            // Skip two token, one for START-TIME AND other for DET, UNI OR EXP
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            nToken = sscanf(tempstring, "%s", keyword);
            if (strcmp(keyword, "UNI") == 0) {
                *isUNI = TRUE;
                nToken = 3;
            } else {
                nToken = 2;
            }
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);

            // Fix for simulation crash
            // when no keyword is supplied after START-TIME
            if (tempstring)
            {
                nToken = sscanf(tempstring, "%s", keyword);
                if (SuperApplicationCheckKeyword(keyword) == FALSE)
                {
                    *isStartArray = TRUE;
                }
            }
        }
        // check if multiple sources enable
        if (strcmp(keyword, "SOURCES") == 0) {
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         1);
            *isSources = TRUE;
        }
        // check if multiple destinations enable
        if (strcmp(keyword, "DESTINATIONS") == 0) {
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         1);
            *isDestinations = TRUE;
        }
        if (strcmp(keyword, "CONDITIONS") == 0) {
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         1);
            *isConditions = TRUE;
        }

        // check if Repeate is enable
        if (strcmp(keyword, "REPEAT") == 0) {
            *isRepeat = TRUE;
            //can check for error here;
        }


        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     1);
    }
}

// FUNCTION: SuperApplicationHandleStartTimeInputString
// PURPOSE:  This function will take a list of start-time(s) and reconstruct each start-time
//           with the same configuration for multiple session.
// Parameters:
//  appInput -   pointer to appInput structure.
//  i        -   index for user configuration parameter string
//  isUNI    -   if the distribution type is UNI
void SuperApplicationHandleStartTimeInputString(
    const NodeInput* nodeInput,
    NodeInput* appInput,
    int i,
    BOOL isUNI)
{
    char* tempstring = appInput->inputStrings[i];
    char firsthalfstring[INPUT_LENGTH]="";  //store first half of string before start-time
    char secondhalfstring[INPUT_LENGTH]=""; //store second half of string after start-time
    char keyword[MAX_STRING_LENGTH]="";
    char newinputstring[INPUT_LENGTH]="";   //the new inputstrng to addinto inputstrings[]
    char timeinputstring[INPUT_LENGTH]="";  //store START-TIME ARRAY if enable
    int nToken=0;
    char startTimeStrA[MAX_STRING_LENGTH];//store the START-TIME
    char startTimeStrB[MAX_STRING_LENGTH];//store the START-TIME use in UNI distrubition

    // spilt the InputStrings into two parts.
    while (strcmp(keyword,"START-TIME")) {
        nToken = sscanf(tempstring, "%s", keyword);
        strcat(firsthalfstring, keyword);
        strcat(firsthalfstring, " ");
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
    }
    // skip the START-TIME TYPE e.g. DET, EXP, UNI
    nToken = sscanf(tempstring, "%s", keyword);
    tempstring = SuperApplicationDataSkipToken(tempstring,
                 SUPERAPPLICATION_TOKENSEP,
                 nToken);
    strcat(firsthalfstring, keyword);
    strcat(firsthalfstring, " ");

    // store the timeinput string
    nToken = sscanf(tempstring, "%s", keyword);
    while (SuperApplicationCheckKeyword(keyword) == FALSE)
    {
        strcat(timeinputstring, keyword);
        strcat(timeinputstring, " ");
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        nToken = sscanf(tempstring, "%s", keyword);
    }

    // save the secondhalf of input string
    strcpy(secondhalfstring, tempstring);
    tempstring = timeinputstring;
    strcat(newinputstring, firsthalfstring);

    // reconstruct the oringal inputstring and store back in appInput.
    if (isUNI) {
        nToken = sscanf(tempstring, "%s %s", startTimeStrA, startTimeStrB);
        strcat(newinputstring, startTimeStrA);
        strcat(newinputstring, " ");
        strcat(newinputstring, startTimeStrB);
        strcat(newinputstring, " ");
    } else {
        nToken = sscanf(tempstring, "%s", startTimeStrA);
        strcat(newinputstring, startTimeStrA);
        strcat(newinputstring, " ");
    }
    tempstring = SuperApplicationDataSkipToken(tempstring,
                 SUPERAPPLICATION_TOKENSEP,
                 nToken);
    // if tempstring == NULL means that user didn't specify the START-TIME array is not used
    if (tempstring != NULL) {
        strcat(newinputstring, secondhalfstring);
        strcpy(appInput->inputStrings[i], newinputstring);
        strcpy(newinputstring, "");
    }
    // go through the list and construct new input.
    while (tempstring != NULL) {
        strcpy(newinputstring, firsthalfstring);
        if (isUNI) {
            nToken = sscanf(tempstring, "%s %s", startTimeStrA, startTimeStrB);
            strcat(newinputstring, startTimeStrA);
            strcat(newinputstring, " ");
            strcat(newinputstring, startTimeStrB);
            strcat(newinputstring, " ");
        } else {
            nToken = sscanf(tempstring, "%s", startTimeStrA);
            strcat(newinputstring, startTimeStrA);
            strcat(newinputstring, " ");
        }
        strcat(newinputstring, secondhalfstring);

        // check to see if excess the limit of appInput.
        // double the size of array if necessary.
        if (appInput->numLines >  appInput->maxNumLines-1) {
            SuperAppExpandAppInput(nodeInput,appInput);
        }

        // store the new application input at the end of appInput.inputString list
        appInput->inputStrings[appInput->numLines]= (char*)
                MEM_malloc(sizeof(newinputstring));
        strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
        appInput->numLines++;
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
    }
}

// FUNCTION: SuperApplicationHandleDestinationInputString
// PURPOSE:  This function will take a list of Sources addresses and a list of destinations
//           addresses to reconstruct each unique source and destination pair with the
//           same configuration user input for the multiple session.
// Parameters:
//  appInput -  pointer to the appInput structure.
//  i        -  index for user configuration parameter string
void SuperApplicationHandleDestinationInputString(
    const NodeInput* nodeInput,
    NodeInput* appInput,
    int i)
{
    char* tempstring = appInput->inputStrings[i];
    char firsthalfstring[INPUT_LENGTH] = "";
    char secondhalfstring[INPUT_LENGTH] = "";
    char newinputstring[INPUT_LENGTH] = "";
    char* destinationstring = NULL;
    char keyword[MAX_STRING_LENGTH] = "";
    char destA[MAX_STRING_LENGTH] = "";
    char destB[MAX_STRING_LENGTH] = "";
    int nToken = 0;
    int rangeA = 0;
    int rangeB = 0;
    int index = 0;
    BOOL isfirstpass = TRUE;

    nToken = sscanf(tempstring, "%s", keyword);
    while (strcmp(keyword, "DESTINATIONS")) {
        strcat(firsthalfstring, keyword);
        strcat(firsthalfstring, " ");
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        nToken = sscanf(tempstring, "%s", keyword);
    }
    tempstring = SuperApplicationDataSkipToken(tempstring,
                 SUPERAPPLICATION_TOKENSEP,
                 nToken);

    destinationstring = (char*)MEM_malloc(strlen(tempstring));
    memset(destinationstring, 0, strlen(tempstring));

    nToken = sscanf(tempstring, "%s", keyword);

    while (SuperApplicationCheckKeyword(keyword) == FALSE) {
        strcat(destinationstring, keyword);
        strcat(destinationstring, " ");

        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        nToken = sscanf(tempstring, "%s", keyword);
    }

    // store the second half of the string
    strcpy(secondhalfstring, tempstring);

    tempstring = destinationstring;

    while (tempstring != NULL){
        nToken = sscanf(tempstring, "%s %s", destA, destB);
        if ((strcmp(destB, "thru") == 0) ||
            (strcmp(destB, "THRU") == 0) ||
            (strcmp(destB, "-") == 0))
        {
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            nToken = sscanf(tempstring, "%s", destB);
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            // get the range and start generate the destination id
            rangeA = atoi(destA);
            rangeB = atoi(destB);

            // print error message if range B is less than range A
            if (rangeA > rangeB) {
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr,"ERROR: Node Id on left of THRU has "
                    "to be smaller then Node ID on the right of THRU\n %s",
                    appInput->inputStrings[i]);
                ERROR_ReportError(errStr);
            }

            for (index=rangeA; index <= rangeB; index++) {
                sprintf(destA, "%d", index);
                strcpy(newinputstring, firsthalfstring);
                strcat(newinputstring, destA);
                strcat(newinputstring, " ");
                strcat(newinputstring, secondhalfstring);

                if (isfirstpass) {
                    strcpy(appInput->inputStrings[i], newinputstring);
                    isfirstpass = FALSE;
                } else {
                    // check to see if excess the limit of appInput.
                    // double the size of array if necessary.
                    if (appInput->numLines > appInput->maxNumLines-1) {
                        SuperAppExpandAppInput(nodeInput,appInput);
                    }

                    appInput->inputStrings[appInput->numLines]= (char*)
                            MEM_malloc(sizeof(newinputstring));
                    strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
                    appInput->numLines++;
                }
            }
        } else {
            // if destB is not "THRU OR -" skip only one token
            strcpy(newinputstring, firsthalfstring);
            strcat(newinputstring, destA);
            strcat(newinputstring, " ");
            strcat(newinputstring, secondhalfstring);

            if (isfirstpass) {
                strcpy(appInput->inputStrings[i], newinputstring);
                isfirstpass = FALSE;
            } else {
                // check to see if excess the limit of appInput.
                // double the size of array if necessary.
                if (appInput->numLines > appInput->maxNumLines-1) {
                    SuperAppExpandAppInput(nodeInput,appInput);
                }

                appInput->inputStrings[appInput->numLines]= (char*)
                        MEM_malloc(sizeof(newinputstring));
                strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
                appInput->numLines++;
            }
            // if destB is not "THRU OR -" skip only one token
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         1);
        }
    }

    if (destinationstring != NULL)
    {
        MEM_free(destinationstring);
    }
}

// FUNCTION: SuperApplicationHandleSourceInputString
// PURPOSE:  This function will take a list of Sources addresses and a list of destinations
//           addresses to reconstruct each unique source and destination pair with the
//           same configuration user input for the multiple session.
// Parameters:
//  appInput -  pointer to the appInput structure.
//  i        -  index for user configuration parameter string
void SuperApplicationHandleSourceInputString(
    const NodeInput* nodeInput,
    NodeInput* appInput,
    int i){

    char* tempstring = appInput->inputStrings[i];
    char firsthalfstring[INPUT_LENGTH] = "";
    char secondhalfstring[INPUT_LENGTH] = "";
    char newinputstring[INPUT_LENGTH] = "";
    char* sourcestring = NULL;
    char keyword[MAX_STRING_LENGTH] = "";
    char sourceA[MAX_STRING_LENGTH] = "";
    char sourceB[MAX_STRING_LENGTH] = "";
    int nToken = 0;
    int rangeA = 0;
    int rangeB = 0;
    int index = 0;
    BOOL isfirstpass = TRUE;

    nToken = sscanf(tempstring, "%s", keyword);
    while (strcmp(keyword, "SOURCES")) {
        strcat(firsthalfstring, keyword);
        strcat(firsthalfstring, " ");
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        nToken = sscanf(tempstring, "%s", keyword);
    }
    tempstring = SuperApplicationDataSkipToken(tempstring,
                 SUPERAPPLICATION_TOKENSEP,
                 nToken);

    sourcestring = (char*)MEM_malloc(strlen(tempstring));
    memset(sourcestring, 0, strlen(tempstring));

    nToken = sscanf(tempstring, "%s", keyword);

    while (SuperApplicationCheckKeyword(keyword) == FALSE) {
        strcat(sourcestring, keyword);
        strcat(sourcestring, " ");

        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        nToken = sscanf(tempstring, "%s", keyword);
    }

    // make sure user specify DESTINATIONS when using SOURCES LIST.

    if (strcmp(keyword, "DESTINATIONS") != 0) {
        ERROR_ReportErrorArgs("HAVE TO SPECIFIES BOTH SOURCES AND "
                              "DESTINATIONS\nSUPER-APPLICATION Client Server"
                              " (%d)\nIllegal configurations", i+1);
    }

    // store the second half of the string
    strcpy(secondhalfstring, tempstring);
    tempstring = sourcestring;

    while (tempstring != NULL) {
        nToken = sscanf(tempstring, "%s %s", sourceA, sourceB);
        if ((strcmp(sourceB, "thru") == 0) ||
            (strcmp(sourceB, "THRU") == 0) ||
            (strcmp(sourceB, "-") == 0))
        {
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            nToken = sscanf(tempstring, "%s", sourceB);
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            // get the range and start generate the destination id
            rangeA = atoi(sourceA);
            rangeB = atoi(sourceB);

            // print error message if range B is less than range A
            if (rangeA > rangeB){
                char errStr[MAX_STRING_LENGTH];
                sprintf(errStr, "ERROR: Node Id on left of THRU has to be "
                    "smaller then Node ID on the right of THRU\n %s",
                    appInput->inputStrings[i]);
                ERROR_ReportError(errStr);
            }

            for (index=rangeA; index <= rangeB; index++) {
                sprintf(sourceA, "%d", index);
                strcpy(newinputstring, firsthalfstring);
                strcat(newinputstring, sourceA);
                strcat(newinputstring, " ");
                strcat(newinputstring, secondhalfstring);

                if (isfirstpass) {
                    strcpy(appInput->inputStrings[i], newinputstring);
                    isfirstpass = FALSE;
                } else {
                    // check to see if excess the limit of appInput.
                    // double the size of array if necessary.
                    if (appInput->numLines > appInput->maxNumLines-1) {
                        SuperAppExpandAppInput(nodeInput,appInput);
                    }

                    appInput->inputStrings[appInput->numLines]= (char*)
                            MEM_malloc(sizeof(newinputstring));
                    strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
                    appInput->numLines++;
                }
            }
        } else {
            // if destB is not "THRU OR -" skip only one token
            strcpy(newinputstring, firsthalfstring);
            strcat(newinputstring, sourceA);
            strcat(newinputstring, " ");
            strcat(newinputstring, secondhalfstring);

            if (isfirstpass) {
                strcpy(appInput->inputStrings[i], newinputstring);
                isfirstpass = FALSE;
            } else {
                // check to see if excess the limit of appInput.
                // double the size of array if necessary.
                if (appInput->numLines > appInput->maxNumLines-1) {
                    SuperAppExpandAppInput(nodeInput,appInput);
                }

                appInput->inputStrings[appInput->numLines]= (char*)
                        MEM_malloc(sizeof(newinputstring));
                strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
                appInput->numLines++;
            }
            // if destB is not "THRU OR -" skip only one token
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         1);
        }
    }

    if (sourcestring != NULL)
    {
        MEM_free(sourcestring);
    }
}

// FUNCTION: SuperApplicationHandleRepeatInputString
// PURPOSE:  This function will take a repeat interval for each configuration and reconstruct each
//           configuration with a different start time.
// Parameters:
//  appInput -  pointer to the appInput structure.
//  i        -  index for user configuration parameter string
//  isUNI    -  is the destribution is UNI.
//  simulationTime - total simulation time.
void SuperApplicationHandleRepeatInputString(Node* node,
        const NodeInput* nodeInput,
        NodeInput* appInput,
        int i,
        BOOL isUNI,
        double simulationTime)
{

    char firsthalfstring[INPUT_LENGTH] = "";
    char secondhalfstring[INPUT_LENGTH] = "";
    char newinputstring[INPUT_LENGTH] = "";
    char* tempstring = NULL;
    char keyword[MAX_STRING_LENGTH] = "";
    int nToken = 0;
    char repeatTimeStr[MAX_STRING_LENGTH];     //Time between next application
    clocktype repeatTime = 0;
    double rTime = 0.0;
    BOOL isRepeat = FALSE;
    char startTimeStrA[MAX_STRING_LENGTH];     //store the START-TIME
    char startTimeStrB[MAX_STRING_LENGTH];     //store the START-TIME use in UNI distrubition
    clocktype startTimeA = 0;
    clocktype startTimeB = 0;
    double sTimeA = 0.0;
    double sTimeB = 0.0;
    double sTime = 0.0;
    int rNum = 0;
    char timeinputstring[MAX_STRING_LENGTH]="";
    double simTime = simulationTime;
    BOOL isSimulation = FALSE;
    RandomDistribution<clocktype> randomReqInterval;
    RandomDistribution<int> randomReqNum;


    tempstring = appInput->inputStrings[i];
    // go through the list, and if repeat is enble, remove it from inpustring and store its value
    while (tempstring!=NULL) {
        nToken = sscanf(tempstring, "%s", keyword);
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        if (strcmp(keyword, "REPEAT") != 0){
            strcat(newinputstring, keyword);
            strcat(newinputstring, " ");
        } else {
            isRepeat = TRUE;
            nToken = randomReqInterval.setDistribution(tempstring, "Superapplication", RANDOM_CLOCKTYPE);
            repeatTime = randomReqInterval.getRandomNumber();

            TIME_PrintClockInSecond(repeatTime, repeatTimeStr);
            rTime = atof(repeatTimeStr);
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);

            nToken = randomReqNum.setDistribution(tempstring, "Superapplication", RANDOM_INT);

            rNum = (int)randomReqNum.getRandomNumber();

            if (rNum == 0) {
                isSimulation = TRUE;
            }
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
        }
    }
    if (isRepeat) {
        strcpy(appInput->inputStrings[i], newinputstring);
        strcpy(newinputstring, "");
        strcpy(keyword, "");
        strcpy(firsthalfstring, "");
        strcpy(secondhalfstring, "");
        strcpy(timeinputstring, "");
        tempstring = appInput->inputStrings[i];

        while (strcmp(keyword,"START-TIME")) {
            nToken = sscanf(tempstring, "%s", keyword);
            strcat(firsthalfstring, keyword);
            strcat(firsthalfstring, " ");
            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
        }
        // skip the START-TIME TYPE e.g. DET, EXP, UNI
        nToken = sscanf(tempstring, "%s", keyword);
        strcat(firsthalfstring, keyword);
        strcat(firsthalfstring, " ");
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);

        // if distribution type is in UNI, start-time will have two values
        if (isUNI) {
            nToken = sscanf(tempstring, "%s %s", startTimeStrA, startTimeStrB);
            startTimeA = (clocktype)TIME_ConvertToClock(startTimeStrA);
            startTimeB = (clocktype)TIME_ConvertToClock(startTimeStrB);
            TIME_PrintClockInSecond(startTimeA, startTimeStrA);
            TIME_PrintClockInSecond(startTimeB, startTimeStrB);
            sTimeA=atof(startTimeStrA);
            sTimeB=atof(startTimeStrB);
            sTime = sTimeB;
        } else {
            nToken = sscanf(tempstring, "%s", startTimeStrA);
            startTimeA = (clocktype)TIME_ConvertToClock(startTimeStrA);
            TIME_PrintClockInSecond(startTimeA, startTimeStrA);
            sTimeA = atof(startTimeStrA);
            sTime = sTimeA;
        }
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        strcpy(secondhalfstring, tempstring);

        // construct each repeat configuration and insert it into Inputstring
        while ((isSimulation==TRUE || rNum!= 0) && simTime >= (sTime+rTime))
        {
            strcpy(newinputstring, "");
            strcpy(timeinputstring,"");
            if (isUNI) {
                sTimeA = sTimeA + rTime;
                sTimeB = sTimeB + rTime;
                sTime = sTimeB;
                sprintf(startTimeStrA, "%fS ", sTimeA);
                strcat(timeinputstring, startTimeStrA);
                sprintf(startTimeStrB, "%fS ", sTimeB);
                strcat(timeinputstring, startTimeStrB);
            } else {
                sTimeA = sTimeA + rTime;
                sTime = sTimeA;
                sprintf(startTimeStrA, "%fS ", sTimeA);
                strcat(timeinputstring, startTimeStrA);
            }

            strcat(newinputstring, firsthalfstring);
            strcat(newinputstring, timeinputstring);
            strcat(newinputstring, secondhalfstring);

            // check to see if excess the limit of appInput.
            // double the size of array if necessary.
            if (appInput->numLines > appInput->maxNumLines-1) {
                SuperAppExpandAppInput(nodeInput,appInput);
            }
            appInput->inputStrings[appInput->numLines]= (char*)
                    MEM_malloc(sizeof(newinputstring));
            strcpy(appInput->inputStrings[appInput->numLines], newinputstring);
            appInput->numLines++;

            tempstring = SuperApplicationDataSkipToken(tempstring,
                         SUPERAPPLICATION_TOKENSEP,
                         nToken);
            rNum--;
        }
    }
}

// FUNCTION: SuperAppExpandAppInput
// PURPOSE:  This function will expand the current appInput->inputStrings size.
// Parameters:
//  appInput -  pointer to the appInput structure.
static void SuperAppExpandAppInput (const NodeInput* nodeInput, NodeInput* appInput){

    // expand the appInput size
    int index = 0;
    char **tempStrings;
    BOOL wasFound = FALSE;

    while (appInput->numLines >= appInput->maxNumLines) {
        appInput->maxNumLines += INPUT_ALLOCATION_UNIT;
    }

    tempStrings = appInput->inputStrings;
    appInput->inputStrings = (char **)
                             MEM_malloc(appInput->maxNumLines * sizeof(char *));

    memcpy(appInput->inputStrings, tempStrings,
           appInput->numLines * sizeof(char *));

    if (index == -1) {
        char errorStr[MAX_STRING_LENGTH] = "";
        sprintf(errorStr, "ERROR, unable to located APP-CONFIG-FILE\n");
        ERROR_ReportError(errorStr);
    }


    index = IO_ReadCachedFileIndex(ANY_NODEID,
                                   ANY_ADDRESS,
                                   nodeInput,
                                   "APP-CONFIG-FILE",
                                   &wasFound);
    nodeInput->cached[index]->inputStrings = appInput->inputStrings;
    MEM_free(tempStrings);
}

static void enterSuperApplicationServer_TimerExpired_SendReply_TCP(Node* node,
        SuperApplicationData* dataPtr,
        Message *msg)
{
    SuperApplicationServerSendData_TCP(node, dataPtr, msg);
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_TCP;
    enterSuperApplicationServerIdle_TCP(node, dataPtr, msg);
}

// FUNCTION SuperApplicationServerSendData_TCP
// PURPOSE  Send data and schedule next timer
// Parameters:
//  node:   Pointer to the node structure
//  serverPtr:  Pointer to server state variable
//  msg:    Pointer to message
static void SuperApplicationServerSendData_TCP(
    Node* node,
    SuperApplicationData* serverPtr,
    Message* msg)
{
    SuperAppTimer* replyPacketTimer;
    Int32 repSize;
    clocktype repInterval;
    SuperApplicationTCPDataPacket data;
    char *payload;

    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(msg);

    if (SUPERAPPLICATION_DEBUG_TIMER_REC_SERVER) {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server got timer alarm: \n", clockStr);
        printf("Purpose: Send reply packet\n");
        printf("Connection: S(%u:%u)->C(%u:%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("Reply for:%u req seq no \n", replyPacketTimer->reqSeqNo);
    }

    replyPacketTimer->numRepSent += 1;
    repSize = (int) serverPtr->randomRepSize.getRandomNumber();
    //repSize = sizeof(data);

    /*ERROR_Assert(
        serverPtr->stats.numRepBytesSent < SUPERAPPLICATION_MAX_DATABYTE_SEND,
        "Total bytes sent exceed maximum limit, current packet"
        " size should be reduced for proper statistics");*/

    payload = (char *)MEM_malloc(repSize);
    memset(payload,0,repSize);

    repInterval = serverPtr->randomRepInterDepartureDelay.getRandomNumber();

    data.totalPacketBytes = repSize;
    data.totalFragmentBytes = repSize;
    data.appFileIndex = 0;
    data.seqNo = serverPtr->repSeqNo;
    data.totFrag = 1;
    data.fragNo = 0;
    data.uniqueFragNo = serverPtr->uniqueFragNo ++;
    data.isLastPacket = FALSE;
    data.txTime = node->getNodeTime();

    // STATS DB CODE
#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.SetPriority(serverPtr->reqTOS);
    appParam.SetFragNum(data.fragNo);
    appParam.SetSessionId(serverPtr->sessionId);
    appParam.m_SessionInitiator = serverPtr->sessionInitiator;
    //appParam.SetSessionId(serverPtr->uniqueId);
    appParam.SetAppType("SUPER-APPLICATION");
    appParam.SetAppName(serverPtr->applicationName);
    appParam.m_ReceiverId = serverPtr->receiverId;
    appParam.SetReceiverAddr(serverPtr->clientAddr);
    appParam.SetMsgSize(repSize);
    appParam.m_TotalMsgSize = repSize;
    if (data.totFrag > 1)
    {
        appParam.m_fragEnabled = TRUE;
    }
#endif
    if (SUPERAPPLICATION_DEBUG_REP_SEND) {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server (%u: %d) sending reply packet "
               "%u of %u for req seq no = %u. Sending %u byte packet to "
               " (%d:%hu) with:\n",
               clockStr,
               node->nodeId,
               serverPtr->destinationPort,
               replyPacketTimer->numRepSent,
               replyPacketTimer->numRepToSend,
               replyPacketTimer->reqSeqNo,
               repSize,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->serverAddr),
               serverPtr->sourcePort);
    }
    if (replyPacketTimer->lastReplyToSent) {
        if (replyPacketTimer->numRepSent ==
                replyPacketTimer->numRepToSend)
        {
            data.isLastPacket = TRUE;
            if (node->appData.appStats)
            {
                if (!serverPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                {
                    serverPtr->stats.appStats->SessionFinish(node);
                }
            }
        }
    }

    Message *tempMsg = APP_TcpCreateMessage(
        node,
        serverPtr->connectionId,
        TRACE_SUPERAPPLICATION);

    APP_AddPayload(
        node,
        tempMsg,
        payload,
        repSize);

    APP_AddInfo(
        node,
        tempMsg,
        &data,
        sizeof(SuperApplicationTCPDataPacket),
        INFO_TYPE_SuperAppTCPData);

#ifdef ADDON_DB
    node->appData.appTrafficSender->appTcpSend(node, tempMsg, &appParam);
#else
    node->appData.appTrafficSender->appTcpSend(node, tempMsg);
#endif

    serverPtr->waitFragments++;
    if (node->appData.appStats)
    {
        if (!serverPtr->stats.appStats->IsSessionStarted(STAT_Unicast))
        {
              serverPtr->stats.appStats->SessionStart(node);
        }
        serverPtr->stats.appStats->AddFragmentSentDataPoints(node,
                                                    repSize,
                                                    STAT_Unicast);
        serverPtr->stats.appStats->AddMessageSentDataPoints(node,
                                                   tempMsg,
                                                   0,
                                                   repSize,
                                                   0,
                                                   STAT_Unicast);
    }
    serverPtr->stats.numRepBytesSent += repSize;
    serverPtr->stats.numRepFragsSent += 1;

    serverPtr->lastRepFragSentTime = node->getNodeTime();

    serverPtr->stats.numRepPacketsSent += 1;

    if (serverPtr->stats.numRepPacketsSent == 1){
        serverPtr->firstRepFragSentTime = node->getNodeTime();
    }
    if (serverPtr->lastRepFragSentTime > serverPtr->firstRepFragSentTime){
        serverPtr->stats.repSentThroughput = (double) ((double)(serverPtr->stats.numRepBytesSent * 8.0 * SECOND)
                                              / (serverPtr->lastRepFragSentTime - serverPtr->firstRepFragSentTime));
    }

    serverPtr->repSeqNo++;

    if (replyPacketTimer->numRepSent == replyPacketTimer->numRepToSend){
        MESSAGE_Free(node, msg);
    } else {
        SuperApplicationServerScheduleNextRepPkt_TCP(
            node,
            serverPtr,
            repInterval,
            msg);
    }
    MEM_free(payload);
}

// FUNCTION SuperApplicationServerScheduleNextRepPkt_TCP
// PURPOSE  Send a self timer to schedule next replay packet.
// Parameters:
//  node - Pointer to the node structure
//  serverPtr - Pointer to server state variable
//  interval - time between packet
//  msg - Pointer to message
static void SuperApplicationServerScheduleNextRepPkt_TCP(
    Node* node,
    SuperApplicationData* serverPtr,
    clocktype interval,
    Message* msg)
{

    SuperAppTimer* replyPacketTimer;
    replyPacketTimer = (SuperAppTimer*) MESSAGE_ReturnInfo(msg);

    if (SUPERAPPLICATION_DEBUG_TIMER_SET_SERVER) {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Server scheduling timer for reply packet \n",
               clockStr);
        printf("    Connection :  S(%u:%u)->C(%u,%u)\n",
               node->nodeId,
               serverPtr->destinationPort,
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     serverPtr->clientAddr),
               serverPtr->sourcePort);
        printf("    Reply for  :  packet (%u of %u) for %u req seq no\n",
               replyPacketTimer->numRepSent,
               replyPacketTimer->numRepToSend,
               replyPacketTimer->reqSeqNo);
        TIME_PrintClockInSecond((interval + node->getNodeTime()), clockStr, node);
        printf("    Alarm time :  %s sec\n", clockStr);
        TIME_PrintClockInSecond(interval, clockStr);
        printf("    Interval   :  %s sec\n", clockStr);
    }
    MESSAGE_Send(node, msg, interval);
}


static void SuperApplicationClientReceivePacket_TCP(
    Node* node,
    Message* msg,
    SuperApplicationData* clientPtr)
{

    BOOL completePacketRvd;
    BOOL completeFragmentRvd;
    int packetSize;
    int headerSize;
    int countInfo = 0;
#ifdef ADDON_DB
    int lowerLimit = 0;
    int upperLimit = 0;
#endif
    long totalBytesRead;
    long totalFragBytesRead;
    char *packet;
    char *tmpBuffer;
    char *tmpFragmentBuffer;
    clocktype delay = 0;
    packet = (char*) MESSAGE_ReturnPacket(msg);
    packetSize = MESSAGE_ReturnPacketSize(msg);
    headerSize = sizeof(SuperApplicationTCPDataPacket);
    totalBytesRead = clientPtr->bufferSize + packetSize;
    totalFragBytesRead = clientPtr->fragmentBufferSize + packetSize;
    clientPtr->stats.numRepFragBytesRcvd += packetSize;
    clientPtr->stats.numRepPacketBytesRcvdThisPacket += packetSize;
    ERROR_Assert(MESSAGE_ReturnVirtualPacketSize(msg) == 0,
                "SuperApplication: Data should not be sent as virtual data");

    if (SUPERAPPLICATION_DEBUG_REP_REC)
    {
        char clockStr[24];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr, node);
        printf("At %s sec, Client received fragment from TCP with \n",clockStr);
        printf("Connection: C"
               "(%u:%u)->S(%u:%u)\n",
               MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                     clientPtr->serverAddr),
               clientPtr->sourcePort,
               node->nodeId,
               clientPtr->destinationPort);
        //printf("Total bytes received till now: %u\n",
        //     clientPtr->stats.numRepFragBytesRcvd);
        printf("Bytes received from TCP: %u\n",
               packetSize);
    }

    // Update the packet buffer
    // tmpBuffer will contain contents of buffer and current packet.

    tmpBuffer = (char *) MEM_malloc(totalBytesRead);
    memset(tmpBuffer,0,totalBytesRead);

    if (clientPtr->bufferSize > 0)
    {
        memcpy(tmpBuffer, clientPtr->buffer, clientPtr->bufferSize);
        MEM_free(clientPtr->buffer);
    }

#ifdef ADDON_DB
    else
    {
        // First Packet.
        lowerLimit = msg->infoBookKeeping.at(countInfo).infoLowerLimit;
        upperLimit = msg->infoBookKeeping.at(countInfo).infoUpperLimit;

        clientPtr->upperLimit.push_back(upperLimit - lowerLimit);
        for (int k = lowerLimit; k < upperLimit; k++)
        {
            MessageInfoHeader infoHdr;
            infoHdr.infoSize = msg->infoArray.at(k).infoSize;
            infoHdr.infoType = msg->infoArray.at(k).infoType;
            infoHdr.info = (char*) MEM_malloc(infoHdr.infoSize);
            memcpy(infoHdr.info, msg->infoArray.at(k).info, infoHdr.infoSize);
            clientPtr->tcpInfoField.push_back(infoHdr);
        }
    }
#endif
    if (packetSize > 0)
    {
        // Packet contains real (non-virtual) data
        // Copy real data into buffer
        memcpy(tmpBuffer + (clientPtr->bufferSize), packet, packetSize);
    }

    // Free the buffer after reading the buffer + packet in tempBuffer
    // Update the fragment buffer
    // tmpFragmentBuffer will contain contents of the fragment being received.

    tmpFragmentBuffer = (char *) MEM_malloc(totalFragBytesRead);
    memset(tmpFragmentBuffer,0,totalFragBytesRead);

    if (clientPtr->fragmentBufferSize > 0)
    {
        memcpy(tmpFragmentBuffer, clientPtr->fragmentBuffer, clientPtr->fragmentBufferSize);
        MEM_free(clientPtr->fragmentBuffer);
    }

    if (packetSize > 0)
    {
        // Packet contains real (non-virtual) data
        // Copy real data into buffer
        memcpy(tmpFragmentBuffer + (clientPtr->fragmentBufferSize), packet, packetSize);
    }

    clientPtr->fragmentBufferSize = totalFragBytesRead;
    completeFragmentRvd = TRUE;  //Assume complete rep fragment received

    //check if we have the whole fragment
    //countInfo = -1;
    while (totalFragBytesRead > 0 && (completeFragmentRvd == TRUE))
    {
        //countInfo++;
        //Extract the super application TCP header.
        SuperApplicationTCPDataPacket *header;
        header = (SuperApplicationTCPDataPacket *)MESSAGE_ReturnInfo(msg,
                                       INFO_TYPE_SuperAppTCPData,countInfo);
        delay = node->getNodeTime() - header->txTime;

        int remainingFragBufferSize = 0;

        if (SUPERAPPLICATION_DEBUG_REP_REC)
        {
            printf("Bytes received for this frag: %lu"
                   " of %d \n",
                   totalFragBytesRead,
                   header->totalFragmentBytes);
            printf("Fragment no: %d \n",header->fragNo);
        }

        if (totalFragBytesRead >= header->totalFragmentBytes)
        {
            // Complete fragment received
            remainingFragBufferSize = totalFragBytesRead - header->totalFragmentBytes;
            // Complete Application layer fragment received.  Several fragments
            // obtained from TCP may constitute one application layer fragment
            // (decided by FRAGMENTATION_UNIT provided to SuperApplication.
            // Alternatively several Application layer fragments may be received
            // together from TCP
            SuperApplicationClientProcessFragRcvd_TCP(node, clientPtr);
            if (node->appData.appStats)
            {
                if (!clientPtr->stats.appStats->IsSessionStarted(STAT_Unicast))
                {
                    clientPtr->stats.appStats->SessionStart(node);
                }

                clientPtr->stats.appStats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Unicast);
            }
            if (SUPERAPPLICATION_DEBUG_REP_REC)
            {
                printf("Status: Complete fragment received.\n");
            }

            if (remainingFragBufferSize > 0)
            {
                char* tmpFragmentBuffer2;
                tmpFragmentBuffer2 = (char *) MEM_malloc(remainingFragBufferSize);

                memcpy(tmpFragmentBuffer2,
                       tmpFragmentBuffer + header->totalFragmentBytes,
                       remainingFragBufferSize);
                MEM_free(tmpFragmentBuffer);
                tmpFragmentBuffer = tmpFragmentBuffer2;
                // For the info field
                countInfo++;

// Make sure whether the below code section is really required for ADDON_DB
#ifdef ADDON_DB
                if (countInfo < (int) msg->infoBookKeeping.size())
                {
                    lowerLimit = msg->infoBookKeeping.at(countInfo).infoLowerLimit;
                    upperLimit = msg->infoBookKeeping.at(countInfo).infoUpperLimit;

                    clientPtr->upperLimit.push_back(upperLimit - lowerLimit);
                    for (int k = lowerLimit; k < upperLimit; k++)
                    {
                        MessageInfoHeader infoHdr;
                        infoHdr.infoSize = msg->infoArray.at(k).infoSize;
                        infoHdr.infoType = msg->infoArray.at(k).infoType;
                        infoHdr.info = (char*) MEM_malloc(infoHdr.infoSize);
                        memcpy(infoHdr.info, msg->infoArray.at(k).info, infoHdr.infoSize);
                        clientPtr->tcpInfoField.push_back(infoHdr);
                    }
                }
#endif
            }
            else
            {
                ERROR_Assert(remainingFragBufferSize == 0,
                             "SuperApplication: remaining bytes can not be negative");
                MEM_free(tmpFragmentBuffer);
                tmpFragmentBuffer = NULL;
            }

            clientPtr->fragmentBufferSize = remainingFragBufferSize;
            // update bytes read of next fragment
            totalFragBytesRead = remainingFragBufferSize;
        }
        else
        {
            if (SUPERAPPLICATION_DEBUG_REP_REC)
            {
                printf("Status: Complete fragment not received.\n");
            }
            // Not enough to make a packet yet
            // (header, but not enought payload)
            completeFragmentRvd = FALSE;
        }

        if (SUPERAPPLICATION_DEBUG_REP_REC)
        {
            if (totalFragBytesRead >= headerSize && (completeFragmentRvd == TRUE)){
                printf("Processing next fragment \n");
            }
            if ((totalFragBytesRead > 0) && (totalFragBytesRead < headerSize)){
                printf("Header for next fragment not received yet.\n");
            }
        }
    }

    if (clientPtr->fragmentBufferSize > 0)
    {
        clientPtr->fragmentBuffer = (char *) MEM_malloc(clientPtr->fragmentBufferSize);
        memset(clientPtr->fragmentBuffer,0,clientPtr->fragmentBufferSize);
        memcpy(clientPtr->fragmentBuffer,
               tmpFragmentBuffer ,
               clientPtr->fragmentBufferSize);
    }

    if (tmpFragmentBuffer)
    {
        MEM_free(tmpFragmentBuffer);
        tmpFragmentBuffer = NULL;
    }

    countInfo = -1;
    clientPtr->bufferSize = totalBytesRead;
    completePacketRvd = TRUE; // Assume complete req packet received
    while (totalBytesRead > 0 && (completePacketRvd == TRUE))
    {
        countInfo++;
        //Extract the super application TCP header.
        SuperApplicationTCPDataPacket *header;
        header = (SuperApplicationTCPDataPacket *)MESSAGE_ReturnInfo(msg,
                                   INFO_TYPE_SuperAppTCPData,countInfo);

        int remainingBufferSize = 0;
        if (SUPERAPPLICATION_DEBUG_REP_REC)
        {
            printf("    Bytes received for this packet          : %ld "
                   " of %d \n",
                   totalBytesRead,
                   header->totalPacketBytes);
            printf("    Sequence Number of this packet          : %u "
                   "\n",
                   header->seqNo);
        }
        if (totalBytesRead >= header->totalPacketBytes)
        {
            // Complete packet received
            remainingBufferSize = totalBytesRead - header->totalPacketBytes;
            if (SUPERAPPLICATION_DEBUG_REP_REC)
            {
                printf("    Status                                  : "
                       "Complete packet rcvd. Also, %d bytes of next packet/frag rcvd.\n",remainingBufferSize);
            }
            if (remainingBufferSize > 0)
            {
                char* tmpBuffer2;
                tmpBuffer2 = (char *) MEM_malloc(remainingBufferSize);
                memcpy(tmpBuffer2,
                       tmpBuffer + header->totalPacketBytes,
                       remainingBufferSize);
                MEM_free(tmpBuffer);
                tmpBuffer = tmpBuffer2;
            }
            else
            {
                ERROR_Assert(remainingBufferSize == 0,
                             "SuperApplication: remaining bytes can not be negative");
                MEM_free(tmpBuffer);
                tmpBuffer = NULL;
            }

            // Expect the new packet
            clientPtr->repSeqNo ++;
            clientPtr->bufferSize = remainingBufferSize;

            // Complete packet received
            clientPtr->stats.numRepPacketsRcvd++;
            clientPtr->stats.numRepCompletePacketBytesRcvd += header->totalPacketBytes ;
            totalBytesRead = remainingBufferSize;
            if (SUPERAPPLICATION_DEBUG_TCP_REPLY) {
                printf("reply packet received from Node: %d at Node: %d\n",
                       MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                             clientPtr->serverAddr),
                       node->nodeId);
            }
            //Update packet Delay
            clocktype packetDelay = node->getNodeTime() - header->txTime;
            clientPtr->totalEndToEndDelayForRepPacket +=
                (double)packetDelay / SECOND;
            // Update Packet Jitter

            clocktype now = node->getNodeTime();
            clocktype interArrivalInterval;
            interArrivalInterval = now - header->txTime;
            // Jitter can only be measured after receiving
            // 2 fragments.
            if (clientPtr->stats.numRepPacketsRcvd > 1)
            {
                clocktype jitter = interArrivalInterval -
                    clientPtr->lastRepInterArrivalIntervalPacket;
                // get absolute value of jitter.
                if (jitter < 0) {
                    jitter = -jitter;
                }
                if (clientPtr->stats.numRepPacketsRcvd == 2)
                {
                     clientPtr->actJitterForRepPacket = jitter;
                }
                else
                {
                     clientPtr->actJitterForRepPacket += static_cast<clocktype>(
                        ((double)jitter - clientPtr->actJitterForRepPacket) / 16.0);
                }

                clientPtr->totalJitterForRepPacket += clientPtr->actJitterForRepPacket;
            }
            clientPtr->lastRepInterArrivalIntervalPacket = interArrivalInterval;

            clientPtr->lastRepPacketRcvTime = node->getNodeTime();
            if (clientPtr->stats.numRepPacketsRcvd == 1) {
                clientPtr->firstRepPacketRcvTime =
                    clientPtr->lastRepPacketRcvTime;
            }

            clientPtr->stats.numRepPacketBytesRcvd +=
                clientPtr->stats.numRepPacketBytesRcvdThisPacket;
            clientPtr->stats.numRepPacketBytesRcvdThisPacket = 0;

            if (clientPtr->lastRepPacketRcvTime > clientPtr->firstRepPacketRcvTime) {
                clientPtr->stats.repRcvdThroughputPacket = (double)
                    ((double)(clientPtr->stats.numRepPacketBytesRcvd * 8 * SECOND)
                             / (clientPtr->lastRepPacketRcvTime - clientPtr->firstRepPacketRcvTime));
            }

            // close connectionId once received the last reply packet
            if (header->isLastPacket) {
                node->appData.appTrafficSender->appTcpCloseConnection(
                                                node,
                                                clientPtr->connectionId);
                if (node->appData.appStats)
                {
                    if (NetworkIpIsMulticastAddress(node, clientPtr->serverAddr))
                    {
                        if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Multicast))
                        {
                            clientPtr->stats.appStats->SessionFinish(node, STAT_Multicast);
                        }
                    }
                    else
                    {
                        if (!clientPtr->stats.appStats->IsSessionFinished(STAT_Unicast))
                        {
                            clientPtr->stats.appStats->SessionFinish(node, STAT_Unicast);
                         }
                    }
                }
            }

#ifdef ADDON_DB
            StatsDb* db = node->partitionData->statsDb;
            if (db != NULL)
            {
                Message* newMsg;
                newMsg = MESSAGE_Duplicate(node, msg);
                // clean up the info field from the new message.
                for (unsigned int i = 0; i < newMsg->infoArray.size(); i++)
                {
                    MessageInfoHeader* hdr = &(newMsg->infoArray[i]);
                    MESSAGE_InfoFieldFree(node, hdr);
                }

                newMsg->infoArray.clear();
                if (!clientPtr->upperLimit.empty())
                {
                    for (int i = 0; i < clientPtr->upperLimit.front(); i++)
                    {
                        MessageInfoHeader infoHdr;
                        char* info;
                        infoHdr = clientPtr->tcpInfoField.at(i);
                        info = MESSAGE_AddInfo(
                                    node,
                                    newMsg,
                                    infoHdr.infoSize,
                                    infoHdr.infoType);
                        memcpy(info, infoHdr.info, infoHdr.infoSize);
                    }

                    // Clean up the info.
                    for (unsigned int i = 0;
                            i < (unsigned) clientPtr->upperLimit.front(); i++)
                    {
                        if (i >= clientPtr->tcpInfoField.size())
                        {
                            ERROR_ReportWarning("TCP Info field has less Infos that specified in BookKeeping\n");
                            break;
                        }
                        MessageInfoHeader* hdr = &(clientPtr->tcpInfoField[i]);
                        if (hdr->infoSize > 0)
                        {
                            MEM_free(hdr->info);
                            hdr->infoSize = 0;
                            hdr->info = NULL;
                            hdr->infoType = INFO_TYPE_UNDEFINED;
                        }
                    }

                    if (!clientPtr->tcpInfoField.empty())
                    {
                        clientPtr->tcpInfoField.erase(clientPtr->tcpInfoField.begin(),
                            clientPtr->tcpInfoField.begin() + clientPtr->upperLimit.front());
                    }

                    clientPtr->upperLimit.pop_front();
                }
                if (!node->partitionData->statsDb->statsAppEvents->recordFragment)
                {
                    HandleStatsDBAppReceiveEventsInsertion(
                        node,
                        newMsg,
                        "AppReceiveFromLower",
                        delay,
                        clientPtr->actJitterForRepPacket,
                        header->totalPacketBytes,
                        clientPtr->stats.numRepPacketsRcvd);
                }
                else
                {
                    // Putting code for handling fragments here too as currently
                    // there is no support to app fragmentation for TCP mode.
                    // This code has to be moved up once that is supported.
                    HandleStatsDBAppReceiveEventsInsertion(
                        node,
                        newMsg,
                        "AppReceiveFromLower",
                        delay,
                        clientPtr->actJitterForRep,
                        header->totalFragmentBytes,
                        clientPtr->stats.numRepFragsRcvd);
                }

                // Hop Count stats.
                StatsDBNetworkEventParam* ipParamInfo;
                ipParamInfo = (StatsDBNetworkEventParam*)
                        MESSAGE_ReturnInfo(msg, INFO_TYPE_NetStatsDbContent);

                if (ipParamInfo == NULL)
                {
                    printf ("ERROR: We should have Network Events Info");
                }
                else
                {
                    clientPtr->stats.hopCount += (int) ipParamInfo->m_HopCount;
                }
                // Free the new message created
                MESSAGE_Free(node, newMsg);
           }
#endif
        }
        else {
            if (SUPERAPPLICATION_DEBUG_REQ_REC)
            {
                printf("    Status                                  : "
                       "Complete packet not rcvd.\n");
            }
            // Not enough to make a packet yet
            // (header, but not enough payload)
            completePacketRvd = FALSE;
        }
    }

    if (clientPtr->bufferSize > 0)
    {
        clientPtr->buffer = (char *) MEM_malloc(clientPtr->bufferSize);
        memset(clientPtr->buffer,0,clientPtr->bufferSize);
        memcpy(clientPtr->buffer,
               tmpBuffer ,
               clientPtr->bufferSize);
    }
    if (tmpBuffer)
    {
        MEM_free(tmpBuffer);
        tmpBuffer = NULL;
    }

}

static void SuperApplicationClientProcessFragRcvd_TCP(Node* node, SuperApplicationData* clientPtr){
    if (clientPtr->stats.numRepFragsRcvd == 0) {
        // First fragment received. Init server
        clientPtr->firstRepFragRcvTime = node->getNodeTime();
    }
    clientPtr->stats.numRepFragsRcvd++;
    clientPtr->lastRepFragRcvTime = node->getNodeTime();
    if (clientPtr->lastRepFragRcvTime > clientPtr->firstRepFragRcvTime) {
        clientPtr->stats.repRcvdThroughput = (double)
                                             ((double)(clientPtr->stats.numRepFragBytesRcvd * 8 * SECOND)
                                             / (clientPtr->lastRepFragRcvTime - clientPtr->firstRepFragRcvTime));
    }
}

// FUNCTION SuperAppVoiceStartTalking
// PURPOSE  Check if it will keep talking, and set the corresponding data type.
// Parameters:
// node -    node which is talking
// dataPtr - pointer for the server/client which calling this function
// reqInterval - packet interval
// Return:
//         TRUE - if his turn to talk is not finish yet
//         FALSE - if his turn is over.
static
BOOL SuperAppVoiceStartTalking (Node* node, SuperApplicationData* dataPtr, char* dataType, clocktype reqInterval){

    // if current time + next packet interval time is less then talk time
    // schedule packet type to be 'm', meaning more packet to come

    if (((node->getNodeTime() - dataPtr->firstTalkTime +
             reqInterval) < dataPtr->talkTime) &&
            (((node->getNodeTime() +
                  reqInterval) < dataPtr->sessionFinish) ||
               (dataPtr->sessionFinish == dataPtr->sessionStart)))
    {
        *dataType = 'm';
        return TRUE;
    }
    // if current time + next packet interval time is more then talk time
    // schedule packet type to be 'o', meaning it is the last packet for this turm
    else if (((node->getNodeTime() - dataPtr->firstTalkTime +
                 reqInterval) >= dataPtr->talkTime) &&
              (((node->getNodeTime() +
                   reqInterval) < dataPtr->sessionFinish) ||
                (dataPtr->sessionFinish == dataPtr->sessionStart)))
    {
        *dataType = 'o';
        return FALSE;
    }
    // else if current time + next packet interval time is more then session finish
    // schedule packet type to be 'c', meaning close connection after this packet.
    else {
        *dataType = 'c';
        return FALSE;
    }
}

// FUNCTION SuperApplicationClientScheduleTalkTimeOut
// PURPOSE  Schedule a timer, if not hear anything, timer expireds and it will start talking
//          if someone else is talking, timer got reset.
// Parameters:
// node - node which is talking
// clientPtr - pointer for the client who set the timeout
static void SuperApplicationClientScheduleTalkTimeOut(
    Node* node,
    SuperApplicationData* clientPtr)
{

    AppTimer* timer = NULL;
    Message* timerMsg = NULL;
    clocktype delay = 0;
    delay = clientPtr->randomReqInterval.getRandomNumber() * TALK_TIME_OUT;

    // Schedule self timer message to start talk.
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_CLIENT,
                             MSG_APP_TALK_TIME_OUT);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));
    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connection id to 0 when UDP is being
    // used. Designer uses this to distinguish between UDP/TCP.
    timer->connectionId = 0;
    timer->sourcePort = clientPtr->sourcePort;
    //timer->address = clientPtr->clientAddr;
    timer->address = clientPtr->serverAddr;
    timer->type = APP_TIMER_SEND_PKT;
    clientPtr->talkTimeOut = timerMsg;
    MESSAGE_Send(node, timerMsg, delay);
}

// FUNCTION SuperApplicationServerScheduleTalkTimeOut
// PURPOSE  Schedule a timer, if not hear anything, timer expireds and it will start talking
//          if someone else is talking, timer got reset.
// Parameters:
// node - node which is talking
// serverPtr - pointer for the server who set the timeout
static void SuperApplicationServerScheduleTalkTimeOut(
    Node* node,
    SuperApplicationData* serverPtr)
{
    AppTimer* timer = NULL;
    Message* timerMsg = NULL;
    clocktype delay = 0;
    delay = serverPtr->randomRepInterDepartureDelay.getRandomNumber() * TALK_TIME_OUT;


    // Schedule self timer message to start talk.
    timerMsg = MESSAGE_Alloc(node,
                             APP_LAYER,
                             APP_SUPERAPPLICATION_SERVER,
                             MSG_APP_TALK_TIME_OUT);
    MESSAGE_InfoAlloc(node, timerMsg, sizeof(AppTimer));
    timer = (AppTimer*) MESSAGE_ReturnInfo(timerMsg);
    // Designer requirement. Always set connection id to 0 when UDP is being
    // used. Designer uses this to distinguish between UDP/TCP.
    timer->connectionId = 0;
    timer->sourcePort = serverPtr->sourcePort;
    timer->address = serverPtr->clientAddr;
    timer->type = APP_TIMER_SEND_PKT;
    serverPtr->talkTimeOut = timerMsg;
    MESSAGE_Send(node, timerMsg, delay);
}

// FUNCTION SuperApplicationServer_TimeExpired_StartTalk_UDP
// PURPOSE  Self timer expired -> meaning that we diddn't hear anyone talking
//          Starting talking upon timer expired
// Parameters:
// node    - node which will starting talking
// dataPtr - pointer for the server who set the timeout
// msg     - timer
static void enterSuperApplicationServer_TimeExpired_StartTalk_UDP(
    Node* node,
    SuperApplicationData* dataPtr,
    Message* msg)
{
    if (SUPERAPPLICATION_DEBUG_VOICE_TALK_TIME_OUT) {
        char clockStr[24];
        TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
        printf("    At %s sec, Talk Time Out for Server %d is Expired:\n",
               clockStr,
               node->nodeId);
        printf("    Server %d will now schedule to talk back.\n",
               node->nodeId);
    }
    dataPtr->isJustMyTurnToTalk = TRUE;
    dataPtr->talkTimeOut = NULL;
    SuperApplicationScheduleNextReply_UDP(node, dataPtr);
    MESSAGE_Free(node, msg);
    dataPtr->state = SUPERAPPLICATION_SERVERIDLE_UDP;
    enterSuperApplicationServerIdle_UDP(node, dataPtr, msg);
}

// FUNCTION SuperApplicationClient_TimeExpired_StartTalk_UDP
// PURPOSE  Self timer expired -> meaning that we diddn't hear anyone talking
//          Starting talking upon timer expired
// Parameters:
// node    - node which will starting talking
// dataPtr - pointer for the client who set the timeout
// msg     - timer
static void enterSuperApplicationClient_TimeExpired_StartTalk_UDP(
    Node* node,
    SuperApplicationData* dataPtr,
    Message* msg)
{
    if (SUPERAPPLICATION_DEBUG_VOICE_TALK_TIME_OUT) {
        char clockStr[24];
        TIME_PrintClockInSecond (node->getNodeTime(), clockStr, node);
        printf("    At %s sec, Talk Time Out for Client %d is Expired:\n",
               clockStr,
               node->nodeId);
        printf("    Client %d will now schedule to talk back.\n",
               node->nodeId);
    }
    dataPtr->isJustMyTurnToTalk = TRUE;
    dataPtr->talkTimeOut = NULL;
    SuperApplicationClientScheduleNextVoicePacket_UDP(node, dataPtr);
    MESSAGE_Free(node, msg);
    dataPtr->state = SUPERAPPLICATION_CLIENTIDLE_UDP;
    enterSuperApplicationClientIdle_UDP(node, dataPtr, msg);
}

// FUNCTION SuperAppClientListInit
// PURPOSE  Initialize the client List, all in application.cpp
// Parameters:
// node    - node which contain the client list
void SuperAppClientListInit(Node* node){

    SuperAppClientList* clist = new SuperAppClientList;
    node->appData.clientPtrList = (void*)clist;
}

// FUNCTION SuperApplicationInsertClientCondition
// PURPOSE  Insert client conditions into a Queue for later evaluate
// Parameters:
// node    - node which contain the client list
// clientPtr - pointer that will store in client list
// inputstring - user configurations, contains conditions configurations
// Return:
//         number of token it has read
static int SuperApplicationInsertClientCondition(Node* node,
        SuperApplicationData* clientPtr,
        char* inputstring)
{
    SuperAppClientConditionElement conditionElement;
    char* tempstring = NULL;
    int nToken = 0;
    int numSkip = 0;
    char keyword[MAX_STRING_LENGTH]="";
    char keywordValue[MAX_STRING_LENGTH]="";
    char numNeed[MAX_STRING_LENGTH]="";
    int countOpen = 0;
    int countClose = 0;

    tempstring = inputstring;

    // inserting the condition one by one to our condition List.
    while (tempstring!=NULL) {
        nToken = sscanf(tempstring, "%s", keyword);

        // insert open parenthesis into our condition List
        if (strcmp(keyword, "(") == 0) {
            conditionElement.isOpen   = TRUE;
            conditionElement.isOpt    = FALSE;
            conditionElement.isArg    = FALSE;
            conditionElement.isNot    = FALSE;
            conditionElement.isClose  = FALSE;
            conditionElement.isResult = FALSE;
            clientPtr->conditionList.push_back(conditionElement);
            countOpen++;
        }
        // insert close parenthesis into our condition List
        else if (strcmp(keyword, ")") == 0) {
            conditionElement.isClose  = TRUE;
            conditionElement.isOpt    = FALSE;
            conditionElement.isArg    = FALSE;
            conditionElement.isNot    = FALSE;
            conditionElement.isOpen   = FALSE;
            conditionElement.isResult = FALSE;
            clientPtr->conditionList.push_back(conditionElement);
            countClose++;
        }
        // insert NOT operator into our condition List
        else if (strcmp(keyword, "NOT") == 0) {
            conditionElement.isNot    = TRUE;
            conditionElement.isOpt    = FALSE;
            conditionElement.isArg    = FALSE;
            conditionElement.isOpen   = FALSE;
            conditionElement.isClose  = FALSE;
            conditionElement.isResult = FALSE;
            clientPtr->conditionList.push_back(conditionElement);
        }
        // insert other operator into our condition List
        else if (strcmp(keyword, "AND") == 0 ||
                 strcmp(keyword, "OR") == 0 ||
                 strcmp(keyword, "XOR") == 0)
        {
            conditionElement.isOpt    = TRUE;
            conditionElement.isArg    = FALSE;
            conditionElement.isNot    = FALSE;
            conditionElement.isOpen   = FALSE;
            conditionElement.isClose  = FALSE;
            conditionElement.isResult = FALSE;
            strcpy(conditionElement.opt, keyword);
            clientPtr->conditionList.push_back(conditionElement);
        }

        // insert the argument into our condition List
        // it is of the form "CHAIN-ID = 3 AND PACKET = 10"
        // make sure it is not the CHAIN-ID keyword we use for specify the name
        // of the chain id.
        // by compare the next token, we can decided if this is intend for conditions
        // or for name of chain-id
        else if (strcmp(keyword, "CHAIN-ID") == 0) {
            sscanf(tempstring, "%s %s",keyword, keywordValue);

            if (strcmp(keywordValue, "=") == 0) {
                nToken = sscanf(tempstring, "%*s %*s %s %*s %*s %s %s",
                                conditionElement.chainID,
                                conditionElement.opt,
                                numNeed);

                conditionElement.numNeed = atoi(numNeed);

                if (nToken != 3) {
                    ERROR_ReportError("UNKNOW FORMAT OF CONDITION, PLEASE "
                        "CHECK USER GUIDE FOR DETAILS\n");
                }
                nToken = 7;

                conditionElement.isArg         = TRUE;
                conditionElement.isOpt         = FALSE;
                conditionElement.isNot         = FALSE;
                conditionElement.isOpen        = FALSE;
                conditionElement.isClose       = FALSE;
                conditionElement.isResult      = FALSE;
                conditionElement.trueorfalse = FALSE;
                clientPtr->conditionList.push_back(conditionElement);
            } else {
                // reach end of conditions, return number of skip token
                return numSkip;
            }
        }
        // if reach special keyword for other configurations,
        // means conditions ended, and return number of skip token
        else if (SuperApplicationCheckConditionKeyword(keyword)) {
            return numSkip;
        }
        tempstring = SuperApplicationDataSkipToken(tempstring,
                     SUPERAPPLICATION_TOKENSEP,
                     nToken);
        numSkip +=nToken;
    }

    // if open '( ' not equals to ')' meaning we have an error here.
    if (countOpen != countClose)
    {
        ERROR_ReportError("Number of open and close braces don't match\n");
    }
    // reach the ended of user configurations, return number of skip token
    return numSkip;
}


// FUNCTION SuperApplicationHandleConditionsInputString
// PURPOSE  Check user configurations, insert space between
//          parenthesis and = opterator.
// Parameters:
// appInput    - holds the user configurations
// i           - index number for which the user configurations is store.
void SuperApplicationHandleConditionsInputString(NodeInput* appInput,
        int i)
{
    char* tempstring = appInput->inputStrings[i];
    char newinputstring[INPUT_LENGTH]="";
    BOOL isChange = FALSE;

    int stringIndex = 0;
    int index = 0;
    int length = 0;

    length = (int)strlen(tempstring);

    // going through the input string one char at a time
    for (index = 0; index < length; index++) {

        // inserting space before and after each parenthesis
        if (tempstring[index] == '(' || tempstring[index] == ')') {
            sprintf(newinputstring+stringIndex, " %c ", tempstring[index]);
            stringIndex+=3;
            isChange = TRUE;
        }

        // inserting space before and after each operator "=, <, >, <=, >="
        else if ((tempstring[index] == '<') ||
                 (tempstring[index] == '>') ||
                 (tempstring[index] == '='))
        {
            if ((tempstring[index+1] == '<') ||
                   (tempstring[index+1] == '>') ||
                   (tempstring[index+1] == '='))
            {
                sprintf(newinputstring+stringIndex, " %c%c ", tempstring[index], tempstring[index+1]);
                stringIndex+=4;
                isChange = TRUE;
                index+=1;
            } else {
                sprintf(newinputstring+stringIndex, " %c ", tempstring[index]);
                stringIndex+=3;
                isChange = TRUE;
            }
        }
        else {
            sprintf(newinputstring+stringIndex, "%c", tempstring[index]);
            stringIndex+=1;
        }
    }
    // if we have made the changes in input string,
    // allocated the space and copy back the the input string.
    if (isChange){
        MEM_free(appInput->inputStrings[i]);
        appInput->inputStrings[i] = (char*)MEM_malloc(INPUT_LENGTH * sizeof(char));
        strcpy(appInput->inputStrings[i], newinputstring);
    }
}

// FUNCTION SuperAppCheckConditions
// PURPOSE Check user conditions
// Parameters:
// node    - node which contain the client list
// clientPtr - client which holds the conditions list
// Return:
//        TRUE if conditions meet
//        FALSE if conditions not meet.
static BOOL SuperAppCheckConditions(Node* node,
                                    SuperApplicationData* clientPtr)
{
    unsigned int cindex = 0;
    vector <SuperAppClientConditionElement> clist;
    SuperAppClientConditionElement conditionElement;

    // evaluate the queue from top to bottom
    for (cindex = 0; cindex < clientPtr->conditionList.size(); cindex++) {
        conditionElement.isOpt = clientPtr->conditionList[cindex].isOpt;
        conditionElement.isArg = clientPtr->conditionList[cindex].isArg;
        conditionElement.isNot = clientPtr->conditionList[cindex].isNot;
        conditionElement.isOpen = clientPtr->conditionList[cindex].isOpen;
        conditionElement.isClose = clientPtr->conditionList[cindex].isClose;
        conditionElement.isResult = clientPtr->conditionList[cindex].isResult;
        conditionElement.trueorfalse = clientPtr->conditionList[cindex].trueorfalse;

        strcpy(conditionElement.chainID, clientPtr->conditionList[cindex].chainID);
        strcpy(conditionElement.opt, clientPtr->conditionList[cindex].opt);
        conditionElement.numNeed = clientPtr->conditionList[cindex].numNeed;
        clist.push_back(conditionElement);

        // if we see a close ')' call Evaluate Condition
        // to evaluate the inner conditions
        if (conditionElement.isClose) {
            SuperAppEvaluateCondition(node, &clist);
        }
    }
    // evaluate the remaining conditions if any
    SuperAppEvaluateCondition(node, &clist);

    // after the evaluation, should only have one element left in queue
    if (clist.size() != 1) {
        ERROR_ReportError("ERROR ON USER DEFINE CONDITIONS, PLEASE SEE USER "
            "GUIDE FOR REFERENCE\n");
    }

    if (SUPERAPPLICATION_DEBUG_CONDITION_STACK) {
        if (clist[0].trueorfalse) {
            printf("Condition is TRUE\n");
        } else {
            printf("Condition is FALSE\n");
        }
    }
    // return true or false for conditions.
    return clist[0].trueorfalse;
}

// FUNCTION SuperAppEvaluateCondition
// PURPOSE Check inner conditions e.g. condition within "(  )"
// Parameters:
// node    - node which contain the client list
// conditionList - condition element which is inside "(  )"
static void SuperAppEvaluateCondition(
    Node* node,
    vector<SuperAppClientConditionElement> *conditionList)
{
    vector<SuperAppClientConditionElement> tempList;

    int cindex = 0;
    SuperAppClientConditionElement conditionElement;
    BOOL isOpen = FALSE;

    // evaluate from left to right
    // pop the stack until a open parenthesis
    while (conditionList->size() != 0 && isOpen == FALSE) {

        if ((conditionList->back().isClose == FALSE) &&
            (conditionList->back().isOpen == FALSE))
        {
            conditionElement.isOpt = conditionList->back().isOpt;
            conditionElement.isArg = conditionList->back().isArg;
            conditionElement.isNot = conditionList->back().isNot;
            conditionElement.isOpen = conditionList->back().isOpen;
            conditionElement.isClose = conditionList->back().isClose;
            conditionElement.isResult = conditionList->back().isResult;
            conditionElement.trueorfalse = conditionList->back().trueorfalse;
            strcpy(conditionElement.chainID, conditionList->back().chainID);
            strcpy(conditionElement.opt, conditionList->back().opt);
            conditionElement.numNeed = conditionList->back().numNeed;
            tempList.push_back(conditionElement);
        }

        if (conditionList->back().isOpen) {
            conditionList->pop_back();
            isOpen = TRUE;
            break;
        }
        conditionList->pop_back();
    }
    BOOL isNot = FALSE;
    BOOL isXor = FALSE;
    BOOL isAnd = FALSE;
    BOOL isOr  = FALSE;


    // debug statement for condition stack
    // print the condition stack within the parenthesis
    if (SUPERAPPLICATION_DEBUG_CONDITION_STACK) {
        int x = 0;
        for (x = (int) (tempList.size() - 1); x >= 0; x--) {
            if (tempList[x].isOpen) {
                printf(" ( ");
            }
            else if (tempList[x].isClose) {
                printf(" ) ");
            }
            else if (tempList[x].isResult) {
                if (tempList[x].trueorfalse) {
                    printf(" T ");
                }
                else {
                    printf(" F ");
                }
            }
            else if (tempList[x].isArg) {
                printf("CHAIN-ID = %s AND PACKET %s %d ",
                       tempList[x].chainID,
                       tempList[x].opt,
                       tempList[x].numNeed);
            }
            else if (tempList[x].isNot) {
                printf(" NOT ");
            }
            else if (tempList[x].isOpt) {
                printf(" %s ", tempList[x].opt);
            }
        }
        printf("\n");
    }

    vector<SuperAppClientConditionElement> trueFalseList;
    SuperAppClientConditionElement tempResult;

    // evaluate each condition elemente, at the end,
    // it should only return one element of type result.
    // evaluate each operator according to their precedence
    // The order of precedence is as follow;
    // NOT, XOR, AND, OR
    for (cindex = (int)(tempList.size()-1); cindex >= 0; cindex--) {
        if (tempList[cindex].isResult) {
            if (isNot) {
                isNot = FALSE;
                if (tempList[cindex].trueorfalse){
                    tempList[cindex].trueorfalse = FALSE;
                } else {
                    tempList[cindex].trueorfalse = TRUE;
                }
            }
            trueFalseList.push_back(tempList[cindex]);
        }
        // check any existence operator
        // and set the corresponding variable to ture if exists
        else if (tempList[cindex].isOpt) {
            if (strcmp(tempList[cindex].opt, "XOR") == 0) {
                isXor = TRUE;
            } else if (strcmp(tempList[cindex].opt, "AND") == 0) {
                isAnd = TRUE;
            } else if (strcmp(tempList[cindex].opt, "OR") == 0) {
                isOr = TRUE;
            }
            trueFalseList.push_back(tempList[cindex]);
        }
        else if (tempList[cindex].isNot) {
            isNot = TRUE;
        }
        else if (tempList[cindex].isArg) {
            tempResult.isOpt = FALSE;
            tempResult.isArg = FALSE;
            tempResult.isNot = FALSE;
            tempResult.isOpen = FALSE;
            tempResult.isClose = FALSE;
            tempResult.isResult = TRUE;
            tempResult.trueorfalse =
                SuperAppCheckConditionElement(node, &tempList[cindex]);
            if (isNot) {
                isNot = FALSE;
                if (tempResult.trueorfalse) {
                    tempResult.trueorfalse = FALSE;
                } else {
                    tempResult.trueorfalse = TRUE;
                }
            }
            trueFalseList.push_back(tempResult);
        }
    }

    // going through the condition stack and evaluate the XOR operator
    if (isXor) {
        unsigned int x = 0;
        BOOL foundOpt = FALSE;
        BOOL leftResult = FALSE;
        vector<SuperAppClientConditionElement> ResultList;
        leftResult = trueFalseList[0].trueorfalse;

        for (x=0; x<trueFalseList.size(); x++) {
            if (trueFalseList[x].isOpt) {
                if (strcmp(trueFalseList[x].opt, "XOR") == 0) {
                    foundOpt = TRUE;
                } else {
                    ResultList.push_back(trueFalseList[x]);
                }
            } else if (trueFalseList[x].isResult) {
                if (foundOpt == FALSE) {
                    leftResult = trueFalseList[x].trueorfalse;
                    ResultList.push_back(trueFalseList[x]);
                } else {
                    SuperAppClientConditionElement xorElement;

                    foundOpt = FALSE;

                    xorElement.isOpt = FALSE;
                    xorElement.isArg = FALSE;
                    xorElement.isNot = FALSE;
                    xorElement.isOpen = FALSE;
                    xorElement.isClose = FALSE;
                    xorElement.isResult = TRUE;

                    if (leftResult == trueFalseList[x].trueorfalse) {
                        xorElement.trueorfalse = FALSE;
                        leftResult = FALSE;
                    } else {
                        xorElement.trueorfalse = TRUE;
                        leftResult = TRUE;
                    }
                    ResultList.pop_back();
                    ResultList.push_back(xorElement);
                }
            }
        }
        // copy the result back to condition stack
        // condition stack should now be free of operator "XOR"
        while (!trueFalseList.empty()) {
            trueFalseList.pop_back();
        }
        for (x=0; x<ResultList.size(); x++) {
            trueFalseList.push_back(ResultList[x]);
        }
    }

    // going through the condition stack and evaluate the AND operator
    if (isAnd) {
        unsigned int x = 0;
        BOOL foundOpt = FALSE;
        BOOL leftResult = FALSE;
        vector<SuperAppClientConditionElement> ResultList;
        leftResult = trueFalseList[0].trueorfalse;

        for (x=0; x<trueFalseList.size(); x++) {
            if (trueFalseList[x].isOpt) {
                if (strcmp(trueFalseList[x].opt, "AND") == 0) {
                    foundOpt = TRUE;
                } else {
                    ResultList.push_back(trueFalseList[x]);
                }
            } else if (trueFalseList[x].isResult) {
                if (foundOpt == FALSE) {
                    leftResult = trueFalseList[x].trueorfalse;
                    ResultList.push_back(trueFalseList[x]);
                } else {
                    SuperAppClientConditionElement andElement;

                    foundOpt = FALSE;

                    andElement.isOpt = FALSE;
                    andElement.isArg = FALSE;
                    andElement.isNot = FALSE;
                    andElement.isOpen = FALSE;
                    andElement.isClose = FALSE;
                    andElement.isResult = TRUE;

                    if (leftResult &&  trueFalseList[x].trueorfalse) {
                        andElement.trueorfalse = TRUE;
                        leftResult = TRUE;
                    } else {
                        andElement.trueorfalse = FALSE;
                        leftResult = FALSE;
                    }
                    ResultList.pop_back();
                    ResultList.push_back(andElement);
                }
            }
        }

        // copy the result back to condition stack
        // condition stack should now be free of operator "AND"
        while (!trueFalseList.empty()) {
            trueFalseList.pop_back();
        }
        for (x=0; x<ResultList.size(); x++) {
            trueFalseList.push_back(ResultList[x]);
        }
    }

    // going through the condition stack and evaluate the OR operator
    if (isOr) {
        unsigned int x = 0;
        BOOL foundOpt = FALSE;
        BOOL leftResult = FALSE;
        vector<SuperAppClientConditionElement> ResultList;
        leftResult = trueFalseList[0].trueorfalse;

        for (x=0; x<trueFalseList.size(); x++) {
            if (trueFalseList[x].isOpt) {
                if (strcmp(trueFalseList[x].opt, "OR") == 0) {
                    foundOpt = TRUE;
                } else {
                    ResultList.push_back(trueFalseList[x]);
                }
            } else if (trueFalseList[x].isResult) {
                if (foundOpt == FALSE) {
                    leftResult = trueFalseList[x].trueorfalse;
                    ResultList.push_back(trueFalseList[x]);
                } else {
                    SuperAppClientConditionElement orElement;

                    foundOpt = FALSE;

                    orElement.isOpt = FALSE;
                    orElement.isArg = FALSE;
                    orElement.isNot = FALSE;
                    orElement.isOpen = FALSE;
                    orElement.isClose = FALSE;
                    orElement.isResult = TRUE;

                    if (leftResult ||  trueFalseList[x].trueorfalse) {
                        orElement.trueorfalse = TRUE;
                        leftResult = TRUE;
                    } else {
                        orElement.trueorfalse = FALSE;
                        leftResult = FALSE;
                    }
                    ResultList.pop_back();
                    ResultList.push_back(orElement);
                }
            }
        }

        // copy the result back to condition stack
        // condition stack should now be free of operator "OR"
        while (!trueFalseList.empty()) {
            trueFalseList.pop_back();
        }
        for (x=0; x<ResultList.size(); x++) {
            trueFalseList.push_back(ResultList[x]);
        }
    }

    if (trueFalseList.size()!=1) {
        ERROR_ReportError("Condition Fail\n");
    }


    // should only have one element left
    // insert back to condition list.
    conditionList->push_back(trueFalseList[0]);
    if (SUPERAPPLICATION_DEBUG_CONDITION_STACK) {
        if (trueFalseList[0].trueorfalse) {
            printf("inserting TRUE back to stack\n");
        }
        else {
            printf("insert FALSE back to stack\n");
        }
    }
}


// FUNCTION SuperAppCheckConditionElement
// PURPOSE Check condition element of type argument
// Parameters:
// node    - node which contain the client list
// cElement - condition element of type argument
static BOOL SuperAppCheckConditionElement(
    Node* node,
    SuperAppClientConditionElement *cElement)
{
    int numSeen = 0;

    SuperAppTriggerData* trigger = (SuperAppTriggerData*)(node->appData.triggerAppData);
    SuperAppChainIdList* chain = &trigger->chainIdList;

    numSeen = SuperAppGetNumInChain(chain, cElement->chainID);

    // evaluate each condition element
    // depending on the operator.
    if (strcmp(cElement->opt, "<") == 0) {
        if (numSeen < cElement->numNeed) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
    else if (strcmp(cElement->opt, "<=") == 0) {
        if (numSeen <= cElement->numNeed) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
    else if (strcmp(cElement->opt, ">") == 0) {
        if (numSeen > cElement->numNeed) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
    else if (strcmp(cElement->opt, ">=") == 0) {
        if (numSeen >= cElement->numNeed) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
    else if (strcmp(cElement->opt, "=") == 0) {
        if (numSeen == cElement->numNeed) {
            return TRUE;
        } else {
            return FALSE;
        }
    }
    else {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,"UNKNOWN OPTERTOR TYPE %s\n", cElement->opt);
        ERROR_ReportError(errStr);
        return FALSE; // To remove compiler warning
    }
}


void SuperApp_ChangeTputStats(Node* node, BOOL before, BOOL after) {

    // if Tput stats change from YES to NO
    // nothing to do.
    AppInfo* appList = node->appData.appPtr;
    SuperApplicationData* dataPtr = NULL;
    // if Tput stats change from NO to YES
    // update clientPtr time
    // NOTICES: that before will never equals to after.
    if (after) {
        // loop throught the appList and check for each application
        // if application is equals to "SUPERAPPLICATION_CLIENT"
        // do an update on the client ptr.
        for (; appList != NULL; appList = appList->appNext) {
            if (appList->appType == APP_SUPERAPPLICATION_CLIENT) {
                dataPtr = (SuperApplicationData*) appList->appDetail;
                dataPtr->firstReqFragSentTime = node->getNodeTime();
                dataPtr->lastReqFragSentTime  = node->getNodeTime();
                if (dataPtr->processReply == TRUE) {
                    dataPtr->firstRepFragRcvTime = node->getNodeTime();
                    dataPtr->lastRepFragRcvTime  = node->getNodeTime();
                }
            } else if (appList->appType == APP_SUPERAPPLICATION_SERVER) {
                dataPtr = (SuperApplicationData*) appList->appDetail;
                dataPtr->firstReqFragRcvTime = node->getNodeTime();
                dataPtr->lastReqFragRcvTime = node->getNodeTime();
                if (dataPtr->processReply == TRUE) {
                    dataPtr->firstRepFragSentTime = node->getNodeTime();
                    dataPtr->lastRepFragSentTime  = node->getNodeTime();
                }
            }
        }
    }
}

#ifdef ADDON_NGCNMS
void SupperApp_FreeAppDetail(SuperApplicationData* dataPtr)
{
    if (dataPtr->buffer)
    {
        MEM_free(dataPtr->buffer);
    }
    if (dataPtr->fragmentBuffer)
    {
        MEM_free(dataPtr->fragmentBuffer);
    }
    while (!dataPtr->conditionList.empty())
    {
        dataPtr->conditionList.clear();
    }

    MEM_free(dataPtr);
}

// FUNCTION SuperAppDestructor
// PURPOSE Free the super application data structure
// Parameters:
// node    - node which contain the client list
// nodeInput - The configuration file.
void SuperAppDestructor(Node* node, const NodeInput *nodeInput)
{
    SuperApplicationData* dataPtr;
    AppInfo* appList = node->appData.appPtr;
    AppInfo* appListNext = NULL;
    node->appData.appPtr = appList;

    while (appList != NULL)
    {
        appListNext = appList->appNext;

        if ((node->appData.appPtr->appType == APP_SUPERAPPLICATION_SERVER) ||
                (node->appData.appPtr->appType == APP_SUPERAPPLICATION_CLIENT))
        {
            dataPtr = (SuperApplicationData*) appList->appDetail;
            SupperApp_FreeAppDetail(dataPtr);

            node->appData.appPtr = appList->appNext;
            MEM_free(appList);
            appList = node->appData.appPtr;
        }
        else if (appListNext && ((appListNext->appType == APP_SUPERAPPLICATION_SERVER) ||
                                 (appListNext->appType == APP_SUPERAPPLICATION_CLIENT)))
        {
            dataPtr = (SuperApplicationData*) appListNext->appDetail;
            SupperApp_FreeAppDetail(dataPtr);

            appList->appNext = appListNext->appNext;
            MEM_free(appListNext);
        }
        else
        {
            appList = appList->appNext;
        }
    }
}
#endif

// FUNCTION     : SuperAppReadMulticastConfiguration
// PURPOSE      : Read user configuration parameters for the multicast server
// Parameters:
//  serverAddr      : ip address of server
//  inputString     : User configuration parameter string
//  multicastServ   : Pointer to SuperAppConfigurationData
void SuperAppReadMulticastConfiguration(
                                NodeAddress serverAddr,
                                NodeAddress clientAddr,
                                char* inputstring,
                                SuperAppConfigurationData* multicastServ,
                                Int32 mdpUniqueId)
{
    char keywordValue[MAX_STRING_LENGTH];
    char* tokenStr = NULL;
    char keyword[MAX_STRING_LENGTH];
    char deliveryType[MAX_STRING_LENGTH];

    //setting default values
    multicastServ->serverAddr = serverAddr;
    multicastServ->clientAddr = clientAddr;
    multicastServ->destinationPort = APP_SUPERAPPLICATION_SERVER;
    multicastServ->sourcePort = -1;

    strcpy(multicastServ->applicationName,"SuperApplication");

    multicastServ->isMdpEnabled = FALSE;
    multicastServ->isProfileNameSet = FALSE;
    multicastServ->profileName[0] = '\0';
    multicastServ->mdpUniqueId = mdpUniqueId;
    multicastServ->next = NULL;
    multicastServ->appFileIndex = -1;
#ifdef ADDON_BOEINGFCS
    multicastServ->printRealTimeStats = TRUE;
#endif
    // Read in the server properties
    tokenStr = inputstring;

    // Advance input string by 3 token; appStr, sourceString, destString
    tokenStr = SuperApplicationDataSkipToken(
                   tokenStr,
                   SUPERAPPLICATION_TOKENSEP,
                   3);
    while (tokenStr != NULL)
    {
        // Read keyword
        sscanf(tokenStr, "%s", keyword);
        // Advance input string by 1
        tokenStr = SuperApplicationDataSkipToken(
                       tokenStr,
                       SUPERAPPLICATION_TOKENSEP,
                       1);

        if (strcmp(keyword,"SOURCE-PORT") == 0)
        {
            sscanf(tokenStr, "%s", keywordValue);
            multicastServ->sourcePort = (short) atoi(keywordValue);
            if (multicastServ->sourcePort < 0)
            {
                ERROR_ReportError("SuperApplication: Source port needs "
                    "to be > 0.\n");
            }
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           1);
        }

        else if (strcmp(keyword,"DESTINATION-PORT") == 0)
        {
            sscanf(tokenStr, "%s", keywordValue);
            multicastServ->destinationPort = (short) atoi(keywordValue);
            if (multicastServ->destinationPort < 0)
            {
                ERROR_ReportError("SuperApplication: Destination port needs "
                    "to be > 0.\n");
            }
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           1);
        }
        else if (strcmp(keyword,"DELIVERY-TYPE") == 0)
        {
            sscanf(tokenStr, "%s", keywordValue);
            strcpy(deliveryType,keywordValue);

            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           1);
        }
        else if (strcmp(keyword,"REPLY-PROCESS") == 0)
        {
            sscanf(tokenStr, "%s", keywordValue);
            if (strcmp(keywordValue,"YES") == 0)
            {
                ERROR_ReportError("Multicast application does not support "
                                    "REPLY-PROCESS");
            }
        }
        else if (strcmp(keyword,"APPLICATION-NAME")==0)
        {
            sscanf(tokenStr, "%s", keywordValue);
            //strcat(keywordValue,"-SERVER");
            strcpy(multicastServ->applicationName,keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           1);
        }
        else if (strcmp(keyword,"MDP-ENABLED")==0)
        {
            multicastServ->isMdpEnabled = TRUE;
        }
        else if (strcmp(keyword,"MDP-PROFILE")==0)
        {
            multicastServ->isProfileNameSet = TRUE;

            if (!tokenStr)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Please specify MDP-PROFILE name\n");
                ERROR_ReportError(errorString);
            }
            sscanf(tokenStr, "%s", keywordValue);
            strcpy(multicastServ->profileName,keywordValue);
            tokenStr = SuperApplicationDataSkipToken(
               tokenStr,
               SUPERAPPLICATION_TOKENSEP,
               1);
        }
#ifdef ADDON_BOEINGFCS
        else if (strcmp(keyword,"PRINT-REAL-TIME-STATS") == 0)
        {
            if (strcmp(tokenStr, "YES") == 0)
            {
                multicastServ->printRealTimeStats = TRUE;
            }
            else if (strcmp(tokenStr, "NO") == 0)
            {
                multicastServ->printRealTimeStats = FALSE;
            }
            else
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Unknown PRINT-REAL-TIME-STATS value \"%s\"",
                        tokenStr);
                ERROR_ReportWarning(errorString);
            }
        }
#endif

    }

    //if transport type is not SUPERAPPLICATION_UDP then disable MDP
    if (strcmp(deliveryType, "UNRELIABLE") != 0)
    {
        multicastServ->isMdpEnabled = FALSE;
        multicastServ->isProfileNameSet = FALSE;
        strcpy(multicastServ->profileName,"\0");
    }
}

// FUNCTION     : SuperApplicationUpdateMulticastGroupLeavingTime
// PURPOSE      : Update the time node leaves multicast group.
// Parameters:
// node          : pointer to Node.
// groupAddress  : ip address of multicast server
void SuperApplicationUpdateMulticastGroupLeavingTime(Node *node,
                                                NodeAddress groupAddress)
{
    // seacrh whether any superapplication server is configured for
   // this multicast address if yes then update timers.
    SuperApplicationData* dataPtr = NULL;
    AppInfo* appList = node->appData.appPtr;

    for (; appList != NULL; appList = appList->appNext)
    {
       dataPtr = (SuperApplicationData*) appList->appDetail;
       if (appList->appType == APP_SUPERAPPLICATION_SERVER)
        {
          if (dataPtr->serverAddr == groupAddress)
            {
              dataPtr->groupLeavingTime = node->getNodeTime();
            }
        }
    }
}

// FUNCTION     : SuperApplicationUpdateTimeSpentOutofMulticastGroup
// PURPOSE      : Initilize the multicast server and update the timer.
//                Timers update total time spent out of multicast group.
// Parameters:
// node          : pointer to Node.
// groupAddress  : ip address of multicast server
void SuperApplicationUpdateTimeSpentOutofMulticastGroup(Node *node,
                                                NodeAddress groupAddress)
{
    // Update all active superapplication apps for the time duration spent
    // outside of the multicast group

    SuperApplicationData* serverPtr = NULL;
    AppInfo* appList = node->appData.appPtr;
    BOOL initializeServer = FALSE;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_SUPERAPPLICATION_SERVER)
        {
            serverPtr = (SuperApplicationData*) appList->appDetail;

            if (serverPtr->serverAddr == groupAddress)
            {
                initializeServer = TRUE;
                if (serverPtr->groupLeavingTime != 0)
                {
                    serverPtr->timeSpentOutofGroup += node->getNodeTime() -
                        serverPtr->groupLeavingTime;
                    serverPtr->groupLeavingTime = 0;
                }
            }
        }
    }

    if (initializeServer == FALSE)
    {
       ListItem* listItem = node->appData.superAppconfigData->first;

        while (listItem != NULL)
        {
            SuperAppConfigurationData* confData = (SuperAppConfigurationData*)
                       listItem->data;

            if (confData->serverAddr == groupAddress)
            {
                serverPtr = SuperApplicationMulticastServerInit(node, confData);
            }
            listItem = listItem->next;
        }
    }
}
// Dynamic address
//---------------------------------------------------------------------------
// FUNCTION             : AppSuperAppplicationClientAddAddressInformation.
// PURPOSE              : store client interface index, destination
//                        interface index destination node id to get the
//                        correct address when appplication starts
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : SuperApplicationData* : pointer to suepr-app client
//                                                data
// RETRUN               : NONE
//---------------------------------------------------------------------------
void
AppSuperAppplicationClientAddAddressInformation(Node* node,
                                  SuperApplicationData* clientPtr)
{
    // Store the client and destination interface index such that we can get
    // the correct address when the application starts

    NodeId destNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                node,
                                                clientPtr->serverAddr);
    if (destNodeId != INVALID_MAPPING)
    {
        clientPtr->destNodeId = destNodeId;
        clientPtr->destInterfaceIndex =
            (Int16)MAPPING_GetInterfaceIdForDestAddress(
                                                node,
                                                destNodeId,
                                                clientPtr->serverAddr);
    }
    // Handle loopback address in destination
    if (destNodeId == INVALID_MAPPING)
    {
        if (NetworkIpIsLoopbackInterfaceAddress(clientPtr->serverAddr))
        {
            clientPtr->destNodeId = node->nodeId;
            clientPtr->destInterfaceIndex = DEFAULT_INTERFACE;
        }
    }
    clientPtr->clientNodeId = MAPPING_GetNodeIdFromInterfaceAddress(
                                                node,
                                                clientPtr->clientAddr);
    clientPtr->clientInterfaceIndex =
        (Int16)MAPPING_GetInterfaceIndexFromInterfaceAddress(
                                            node,
                                            clientPtr->clientAddr);
}

//---------------------------------------------------------------------------
// FUNCTION             : AppSuperApplicationClientGetSessionAddressState.
// PURPOSE              : get the current address sate of client and server
// PARAMETERS:
// + node               : Node* : pointer to the node
// + clientPtr          : AppDataCbrClient* : pointer to CBR client data
// RETRUN:
// addressState         : AppAddressState :
//                        ADDRESS_FOUND : if both client and server
//                                        are having valid address
//                        ADDRESS_INVALID : if either of them are in
//                                          invalid address state
//---------------------------------------------------------------------------
AppAddressState
AppSuperApplicationClientGetSessionAddressState(Node* node,
                                   SuperApplicationData* clientPtr)
{
    // variable to determine the server current address state
    Int32 serverAddresState = 0;
    // variable to determine the client current address state
    Int32 clientAddressState = 0;

    // Get the current client and destination address if the
    // session is starting
    // Address state is checked only at the session start; if this is not
    // starting of session then return FOUND_ADDRESS

    Address clientAddr;
    Address serverAddr;
    // setting addresses
    SetIPv4AddressInfo(&clientAddr, clientPtr->clientAddr);
    SetIPv4AddressInfo(&serverAddr, clientPtr->serverAddr);
    if (clientPtr->seqNo == 0)
    {
        clientAddressState =
            MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    node->nodeId,
                                    clientPtr->clientInterfaceIndex,
                                    clientAddr.networkType,
                                    &(clientAddr));

        if (clientPtr->destNodeId != ANY_NODEID &&
            clientPtr->destInterfaceIndex != ANY_INTERFACE)
        {
            serverAddresState =
                MAPPING_GetInterfaceAddrForNodeIdAndIntfId(
                                    node,
                                    clientPtr->destNodeId,
                                    clientPtr->destInterfaceIndex,
                                    serverAddr.networkType,
                                    &(serverAddr));
        }
    }
    // if either client or server are not in valid address state
    // then mapping will return INVALID_MAPPING
    if (clientAddressState == INVALID_MAPPING ||
        serverAddresState == INVALID_MAPPING)
    {
        return ADDRESS_INVALID;
    }
    clientPtr->clientAddr = clientAddr.interfaceAddr.ipv4;
    clientPtr->serverAddr = serverAddr.interfaceAddr.ipv4;
    return ADDRESS_FOUND;
}

//--------------------------------------------------------------------------
// NAME         : AppSuperApplicationGetSessionStartTime.
// PURPOSE      : Used to get the session start time to schedule server
//                listen timer
// PARAMETERS   ::
// + node           : Node*                 : pointer to the node
// + inputstring    : char*                 : input string
// + serverPtr      : SuperApplicationData* : server pointer
// RETURN:
// clocktype    : start time.
//--------------------------------------------------------------------------
clocktype
AppSuperApplicationGetSessionStartTime(
                                    Node* node,
                                    char* inputstring,
                                    SuperApplicationData* serverPtr)
{
    char* tokenStr = NULL;
    char keyword[MAX_STRING_LENGTH];
    char keywordValue[MAX_STRING_LENGTH];
    Int32 nToken;
    bool isTriggered = FALSE;
    clocktype waitTime = 0;
    tokenStr = inputstring;
    RandomDistribution<clocktype> randomsessionStart;

    // Advance input string by 3 token; appStr, sourceString, destString
    tokenStr = SuperApplicationDataSkipToken(
                   tokenStr,
                   SUPERAPPLICATION_TOKENSEP,
                   3);
    while (tokenStr != NULL)
    {
        // Read keyword
        nToken = sscanf(tokenStr, "%s", keyword);
        // Advance input string by 1
        tokenStr = SuperApplicationDataSkipToken(
                       tokenStr,
                       SUPERAPPLICATION_TOKENSEP,
                       nToken);
        if (strcmp(keyword,"START-TIME")==0)
        {
            nToken = sscanf(tokenStr, "%s", keywordValue);
            SuperAppCheckDistributionType(keyword, tokenStr);
            nToken = randomsessionStart.setDistribution(
                            tokenStr, "Superapplication", RANDOM_CLOCKTYPE);
            if (strcmp(keywordValue, "TRIGGERED")==0)
            {
                nToken = 1;
                //Dynamic Address Change
                isTriggered = TRUE;
            }
            // Advance input string
            tokenStr = SuperApplicationDataSkipToken(
                           tokenStr,
                           SUPERAPPLICATION_TOKENSEP,
                           nToken);
       }
    }
    // Dynamic Address Change
    // Calculate client session start time
    // The server would start listening at this time
    if (serverPtr->isVoice && serverPtr->isConditions)
    {
        waitTime = serverPtr->sessionStart;
    }
    else if (!serverPtr->isVoice && serverPtr->isConditions)
    {
        waitTime = randomsessionStart.getRandomNumber();
    }
    else
    {
        waitTime = randomsessionStart.getRandomNumber();
    }
    return waitTime;

}

//dns

//---------------------------------------------------------------------------
// FUNCTION             : AppSuperApplicationClientGetClientPtr.
// PURPOSE              : get the Super Application client pointer
// PARAMETERS           ::
// + node               : Node* : pointer to the node
// + sourcePort         : unsigned short : source port of the client
// + uniqueId           : Int32 : unique id
// + tcpMode            : bool : tcpMode
// RETURN
// SuperApplicationData*    : Super Application client pointer
//---------------------------------------------------------------------------
SuperApplicationData*
AppSuperApplicationClientGetClientPtr(
                        Node* node,
                        unsigned short sourcePort,
                        Int32 uniqueId,
                        bool tcpMode)
{
    AppInfo* appList = node->appData.appPtr;
    SuperApplicationData* dataPtr = NULL;
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_SUPERAPPLICATION_CLIENT)
        {
            dataPtr = (SuperApplicationData*) appList->appDetail;

            if (tcpMode)
            {
                if (dataPtr->uniqueId == uniqueId)
                {
                    return dataPtr;
                }
            }
            else
            {
                if (dataPtr->sourcePort == sourcePort)
                {
                    return dataPtr;
                }
            }
        }
    }
    return (NULL);
}

//--------------------------------------------------------------------------
// FUNCTION    :: AppSuperApplicationUrlTCPSessionStartCallBack
// PURPOSE     :: To update the client when URL is resolved for TCP based
//                super-application
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : UInt16         : source port
// + uniqueId   : Int32          : connection id
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo* : information required to
//                                                  send buffered application
//                                                  packets in case of UDP
//                                                  based applications; not
//                                                  used by HTTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as
//                this callback will initiate TCP Open request and not send
//                packet
//---------------------------------------------------------------------------
bool
AppSuperApplicationUrlTCPSessionStartCallBack(
                     Node* node,
                     Address* serverAddr,
                     UInt16 sourcePort,
                     Int32 uniqueId,
                     Int16 interfaceId,
                     std::string serverUrl,
                     AppUdpPacketSendingInfo* packetSendingInfo)
{
     SuperApplicationData* dataPtr =
         AppSuperApplicationClientGetClientPtr(
                                        node,
                                        sourcePort,
                                        uniqueId,
                                        TRUE);

     if (dataPtr == NULL)
     {
         return (FALSE);
     }

     if (dataPtr->stats.numReqPacketsSent != 0)
     {
#ifdef DEBUG
        printf("Session already started so ignore this response\n");
#endif
        return (FALSE);
    }
    if (serverAddr->networkType == NETWORK_IPV6)
    {
        ERROR_ReportErrorArgs("SUPER-APPLICATION is not Supported for "
            "IPV6");
    }

    // Update client RemoteAddress field and session Start
    dataPtr->serverAddr = serverAddr->interfaceAddr.ipv4;
    AppSuperAppplicationClientAddAddressInformation(node, dataPtr);
    // add the stats info that was skipped
    if (node->appData.appStats)
    {
        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, dataPtr->clientAddr);
        SetIPv4AddressInfo(&rAddr, serverAddr->interfaceAddr.ipv4);
        std::string customName;
        if (dataPtr->applicationName == NULL)
        {
            customName = "Super-App Server";
        }
        else
        {
            customName = dataPtr->applicationName;
        }
        if (NetworkIpIsMulticastAddress(
                        node,
                        serverAddr->interfaceAddr.ipv4))
        {
            dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                  "SUPER-APP CLIENT Request",
                                                  STAT_Multicast,
                                                  STAT_AppSenderReceiver,
                                                  customName.c_str());
        }
        else
        {
            dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                  "SUPER-APP CLIENT Request",
                                                  STAT_Unicast,
                                                  STAT_AppSenderReceiver,
                                                  customName.c_str());
        }

        dataPtr->stats.appStats->Initialize(
                 node,
                 lAddr,
                 rAddr,
                 (STAT_SessionIdType)dataPtr->uniqueId,
                 dataPtr->uniqueId);

        dataPtr->stats.appStats->setTos(dataPtr->reqTOS);

        dataPtr->stats.appStats->EnableAutoRefragment();
    }
    memset (packetSendingInfo, 0, sizeof(AppUdpPacketSendingInfo));
    return (FALSE);
}

//--------------------------------------------------------------------------
// FUNCTION    :: AppSuperApplicationUrlUDPSessionStartCallBack
// PURPOSE     :: To update the client when URL is resolved for UDP based
//                super-application
// PARAMETERS   ::
// + node       : Node*          : pointer to the node
// + serverAddr : Address*       : server address
// + sourcePort : UInt16         : source port
// + uniqueId   : Int32          : connection id
// + interfaceId: Int16          : interface index,
// + serverUrl  : std::string    : server URL
// + packetSendingInfo : AppUdpPacketSendingInfo* : information required to
//                                                 send buffered application
//                                                 packets in case of UDP
//                                                 based applications; not
//                                                 used by HTTP
// RETURN       :
// bool         : TRUE if application packet can be sent; FALSE otherwise
//                TCP based application will always return FALSE as
//                this callback will initiate TCP Open request and not send
//                packet
//---------------------------------------------------------------------------
bool
AppSuperApplicationUrlUDPSessionStartCallBack(
                     Node* node,
                     Address* serverAddr,
                     UInt16 sourcePort,
                     Int32 uniqueId,
                     Int16 interfaceId,
                     std::string serverUrl,
                     AppUdpPacketSendingInfo* packetSendingInfo)
{
     SuperApplicationData* dataPtr =
         AppSuperApplicationClientGetClientPtr(
                                        node,
                                        sourcePort,
                                        uniqueId,
                                        FALSE);

     if (dataPtr == NULL)
     {
         return (FALSE);
     }

     if (dataPtr->serverAddr != 0)
     {
#ifdef DEBUG
        printf("Session already started so ignore this response\n");
#endif
        return (FALSE);
    }
    if (serverAddr->networkType == NETWORK_IPV6)
    {
        ERROR_ReportErrorArgs("SUPER-APPLICATION is not Supported for "
            "IPV6");
    }

    // Update client RemoteAddress field and session Start
    dataPtr->serverAddr = serverAddr->interfaceAddr.ipv4;

    // add the stats info that was skipped
    if (node->appData.appStats)
    {
        Address lAddr;
        Address rAddr;
        // setting addresses
        SetIPv4AddressInfo(&lAddr, dataPtr->clientAddr);
        SetIPv4AddressInfo(&rAddr, serverAddr->interfaceAddr.ipv4);
        std::string customName;
        if (dataPtr->applicationName == NULL)
        {
            customName = "Super-App Server";
        }
        else
        {
            customName = dataPtr->applicationName;
        }
        if (NetworkIpIsMulticastAddress(
                        node,
                        serverAddr->interfaceAddr.ipv4))
        {
            dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                  "SUPER-APP CLIENT Request",
                                                  STAT_Multicast,
                                                  STAT_AppSenderReceiver,
                                                  customName.c_str());
        }
        else
        {
            dataPtr->stats.appStats = new STAT_AppStatistics(node,
                                                  "SUPER-APP CLIENT Request",
                                                  STAT_Unicast,
                                                  STAT_AppSenderReceiver,
                                                  customName.c_str());
        }

        dataPtr->stats.appStats->Initialize(
                 node,
                 lAddr,
                 rAddr,
                 (STAT_SessionIdType)dataPtr->uniqueId,
                 dataPtr->uniqueId);

        dataPtr->stats.appStats->setTos(dataPtr->reqTOS);

    }

#ifdef ADDON_DB
    StatsDBAppEventParam appParam;
    appParam.m_SessionInitiator = node->nodeId;
    appParam.SetPriority(dataPtr->reqTOS);
    appParam.SetSessionId(dataPtr->uniqueId);
    appParam.SetAppType("SUPER-APPLICATION");
    appParam.SetAppName(dataPtr->applicationName);
    appParam.m_ReceiverId = dataPtr->receiverId;
    appParam.SetReceiverAddr(dataPtr->serverAddr);
#endif
    // Dynamic address
    // Create and send a UDP msg with header and virtual
    // payload.
    // if the client has not yet acquired a valid
    // address then the application packets should not be
    // generated
    // check whether client and server are in valid address
    // state
    // if this is session start then packets will not be sent
    // if in invalid address state and session will be closed
    // ; if the session has already started and address
    // becomes invalid during application session then
    // packets will get generated but will be dropped at
    //  network layer
    if (AppSuperApplicationClientGetSessionAddressState(node, dataPtr)
                            == ADDRESS_FOUND)
    {
#ifdef ADDON_DB
        memcpy(
            &packetSendingInfo->appParam,
            &appParam,
            sizeof(StatsDBAppEventParam));
#else
        memset(
            &packetSendingInfo->appParam,
            NULL,
            sizeof(StatsDBAppEventParam));
#endif
        packetSendingInfo->itemSize = 0;
        packetSendingInfo->stats = dataPtr->stats.appStats;
        return (TRUE);
    }
    else
    {
        dataPtr->isClosed = TRUE;
        dataPtr->sessionStart = 0;
    }
    return (FALSE);
}

