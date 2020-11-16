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

#ifndef _SUPERAPPLICATION_APP_H_
#define _SUPERAPPLICATION_APP_H_

#include <vector>
#include <list>
#include "stats_app.h"
using namespace std;

#ifdef ADDON_BOEINGFCS
#include <time.h>
// Used so that a new timer is not needed.
#define SUPERAPPLICATION_BURSTY_TIMER 100

#endif /* ADDON_BOEINGFCS */
#define SUPERAPPLICATION_INVALID_SOURCE_PORT -1
#define VOIP_MEAN_SPURT_GAP_RATIO 0.4
#define TALK_TIME_OUT 4
typedef struct struct_superapplication_str SuperApplicationData;

//UserCodeStart
#include "dynamic.h"
#include "random.h"

#ifdef ADDON_DB
class SequenceNumber;
#endif // ADDON_DB

//  Data packet sent using TCP
typedef struct struct_superapplication_tcp_data {
    Int32 seqNo; // Sequencenumberofthefragment
    Int32 fragNo; // Fragmentnumber,ifthepacketwasfragmented
    Int32 uniqueFragNo; // fragment number unique for all pkts
    Int32 totFrag; // Totalnumberoffragments
    int totalPacketBytes; // IncludessizeofthisheadRandomDistribution<double>::erandpayload
    int totalFragmentBytes; // Totalfragmentationbytes
    int appFileIndex; // Indexintheapplicationfile
    BOOL isLastPacket; // indicate if it is the last packet it will send
#ifdef ADDON_BOEINGFCS
    clocktype txTimeQos;
    NodeAddress sourceAddr;
    short sourcePort;
    NodeAddress destAddr;
    short destPort;
    TosType origPrio;
#endif

    //MERGE - this parameter is referenced outside of BOEINGFCS code,
    // so took it out of flags.

    clocktype txTime;     // The simulation time this packet was sent

#ifdef ADDON_BOEINGFCS
    clocktype txRealTime; // The time this packet was sent (wall clock)
    clocktype txCpuTime;  // The time this packet was sent (cpu time)
    int txPartitionId;    // Partition id of the node that sent the packet
#endif /* ADDON_BOEINGFCS */

} SuperApplicationTCPDataPacket;


//  Data packet sent using UDP
typedef struct struct_superapplication_udp_data {
    Int32 seqNo; // Sequencenumberofthefragment
    Int32 fragNo; // Fragmentnumber,ifthepacketwasfragmented
    Int32 uniqueFragNo; // Fragment number unique for all pkts
    Int32 totFrag; // Totalnumberoffragments
    Int32 appFileIndex; // Indexintheapplicationfile
    Int32 sessionId;
    Int32 totalMessageSize;
#ifdef ADDON_BOEINGFCS
    Int32 txPartitionId;    // Partition id of the node that sent the packet
    Int32 empySpace; // so that 32 and 64 bit architectures produce the same
                     // size packet...
#endif
    clocktype txTime; // Timewhenthefirstfragmentwastransmitted.Thisisthepackettransmissiontimeincaseofnofragmentation
    clocktype triggerDelay;
#ifdef ADDON_BOEINGFCS
    clocktype txRealTime; // The time this packet was sent (wall clock)
    clocktype txCpuTime;  // The time this packet was sent (cpu time)
#endif /* ADDON_BOEINGFCS */
    BOOL isMdpEnabled;
    BOOL isLastPacket; // indicate if it is the last packet it will send
} SuperApplicationUDPDataPacket;


typedef struct super_app_timer {
    int type; // Timertype
    int connectionId; // Whichconnectionthistimerismeantfor
    short sourcePort; // Whichsessionthistimerismeantfor
    NodeAddress address;
    Int32 reqSeqNo; // Seqnoofreqpacketforwhichreplyisbeingsent
    Int32 numRepSent;
    Int32 numRepToSend; // Numberofreplypacketstosend
    BOOL lastReplyToSent; // indicate if this is last reply to send
} SuperAppTimer;


// new addons for video codec
typedef struct video_encoding_scheme{
  char codeScheme[20];
  char packetSize[20];
  char packetInterval[20];
} VideoEncodingScheme;

// new addons for voice codec
typedef struct voice_encoding_scheme{
  char codeScheme[20];
  char packetSize[20];
  char packetInterval[20];
} VoiceEncodingScheme;

//UserCodeEnd

typedef struct {
    D_UInt64 numReqBytesSent;
    UInt64 lastNumReqBytesSent;
    int numReqBytesSentId;
    D_UInt64 numReqPacketsSent;
    int numReqPacketsSentId;
    D_UInt64 numReqFragsSent;
    int numReqFragsSentId;
    D_UInt64 numRepBytesSent;
    UInt64 lastNumRepBytesSent;
    int numRepBytesSentId;
    D_UInt64 numRepPacketsSent;
    int numRepPacketsSentId;
    D_UInt64 numRepFragsSent;
    int numRepFragsSentId;
    D_UInt64 numRepFragsRcvdOutOfSeq;
    int numRepFragsRcvdOutOfSeqId;
    D_UInt64 numRepPacketsRcvd;
    int numRepPacketsRcvdId;
    D_UInt64 numRepFragsRcvd;
    int numRepFragsRcvdId;
    D_UInt64 numRepFragBytesRcvd;
    UInt64 lastNumRepFragBytesRcvd;
    int numRepFragBytesRcvdId;
    D_UInt64 numReqFragsRcvdOutOfSeq;
    int numReqFragsRcvdOutOfSeqId;
    D_UInt64 numReqPacketsRcvd;
    int numReqPacketsRcvdId;
    D_UInt64 numReqFragsRcvd;
    int numReqFragsRcvdId;
    D_UInt64 numReqFragBytesRcvd;
    UInt64 lastNumReqFragBytesRcvd;
    int numReqFragBytesRcvdId;
    D_Float64 reqSentThroughput;
    int reqSentThroughputId;
    D_Float64 reqRcvdThroughput;
    int reqRcvdThroughputId;
    D_Float64 repSentThroughput;
    int repSentThroughputId;
    D_Float64 repRcvdThroughput;
    int repRcvdThroughputId;

    D_UInt64 numReqBytesSentPacket;
    UInt64 lastNumReqBytesSentPacket;

    D_UInt64 numRepBytesSentPacket;
    UInt64 lastNumRepBytesSentPacket;

    D_UInt64 numRepPacketBytesRcvd;
    UInt64 lastNumRepPacketBytesRcvd;

    D_UInt64 numReqPacketBytesRcvd;
    UInt64 lastNumReqPacketBytesRcvd;
    UInt64 numReqPacketBytesRcvdThisPacket;
    UInt64 numRepPacketBytesRcvdThisPacket;

    D_Float64 reqSentThroughputPacket;
    D_Float64 reqRcvdThroughputPacket;
    D_Float64 repSentThroughputPacket;
    D_Float64 repRcvdThroughputPacket;

    UInt64 numRepCompletePacketBytesRcvd ;
    UInt64 numReqCompletePacketBytesRcvd ;
#ifdef ADDON_BOEINGFCS
    double totalRealTimePerSimTime;
    int totalRealTimePerSimTimeId;
    double avgRealTimePerSimTime;
    int avgRealTimePerSimTimeId;
    UInt64 numSlowPackets;
    int numSlowPacketsId;

    // Number of frags received from a different partition
    UInt64 numReqFragsRcvdDP;

    // Number of packets received from a different partition
    UInt64 numReqPacketsRcvdDP;
#endif /* ADDON_BOEINGFCS */

    clocktype chainTransDelay;
    clocktype chainTransDelayWithTrigger;
    double chainTputWithTrigger;

#ifdef ADDON_DB
    int hopCount;
#endif

    STAT_AppStatistics* appStats;

} SuperApplicationStatsType;


enum {
    SUPERAPPLICATION_SERVERIDLE_UDP,
    SUPERAPPLICATION_SERVER_TIMEREXPIRED_SENDREPLY_UDP,
    SUPERAPPLICATION_CLIENTIDLE_UDP,
    SUPERAPPLICATION_CLIENT_RECEIVEREPLY_UDP,
    SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_UDP,
    SUPERAPPLICATION_SERVER_RECEIVEDATA_UDP,
    SUPERAPPLICATION_CLIENT_RECEIVEREPLY_TCP,
    SUPERAPPLICATION_CLIENT_CONNECTIONCLOSED_TCP,
    SUPERAPPLICATION_SERVER_RECEIVEDATA_TCP,
    SUPERAPPLICATION_SERVER_CONNECTIONCLOSED_TCP,
    SUPERAPPLICATION_SERVERIDLE_TCP,
    SUPERAPPLICATION_SERVER_CONNECTIONOPENRESULT_TCP,
    SUPERAPPLICATION_CLIENTIDLE_TCP,
    SUPERAPPLICATION_FINAL_STATE,
    SUPERAPPLICATION_SERVER_LISTENRESULT_TCP,
    SUPERAPPLICATION_CLIENT_CONNECTIONOPENRESULT_TCP,
    SUPERAPPLICATION_CLIENT_TIMEREXPIRED_SENDREQUEST_TCP,
    SUPERAPPLICATION_CLIENT_DATASENT_TCP,
    SUPERAPPLICATION_SERVER_DATASENT_TCP,
    SUPERAPPLICATION_INITIAL_STATE,
    SUPERAPPLICATION_DEFAULT_STATE,
    SUPERAPPLICATION_SERVER_TIMEREXPIRED_SENDREPLY_TCP,
    SUPERAPPLICATION_SERVER_TIMEREXPIRED_STARTTALK_UDP,
    SUPERAPPLICATION_CLIENT_TIMEREXPIRED_STARTTALK_UDP
};

enum {
    SUPERAPPLICATION_TRIGGER_TYPE_PACKETS
};


// Structure clients within a list of clients
typedef struct struct_super_app_client_ptr_element {
    struct struct_super_app_client_ptr_element* prev;
    struct struct_super_app_client_ptr_element* next;

    SuperApplicationData* clientPtr;
    clocktype delay;
    BOOL isSourcePort;
    RandomDistribution<clocktype> randomDuration;
    BOOL isFragmentSize;
} SuperAppClientPtrElement;


// Structure for a list of clients within a chain
typedef struct struct_super_app_client_ptr_list {
    SuperAppClientPtrElement* head;
    SuperAppClientPtrElement* tail;
    int numInList;
} SuperAppClientPtrList;

// Structure clients element
typedef struct struct_super_app_client_element {
  SuperApplicationData* clientPtr;
  clocktype delay;
  BOOL isSourcePort;
  RandomDistribution<clocktype>     randomDuration;
  BOOL isFragmentSize;
#ifdef ADDON_BOEINGFCS
    BOOL burstyKeywordFound;
#endif
} SuperAppClientElement;

typedef struct struct_clientptrlist{
  vector<SuperAppClientElement> clientList;
} SuperAppClientList;

typedef struct struct_super_app_client_condition_element{
  BOOL isOpt;
  BOOL isArg;
  BOOL isNot;
  BOOL isOpen;
  BOOL isClose;
  BOOL isResult;

  char chainID[MAX_STRING_LENGTH];
  char opt[MAX_STRING_LENGTH];
  int numNeed;
  BOOL trueorfalse;
} SuperAppClientConditionElement;


typedef struct struct_super_app_chain_stats_element {
    struct_super_app_chain_stats_element* prev;
    struct_super_app_chain_stats_element* next;

    char chainID[MAX_STRING_LENGTH];
    int pktsSent;
    int pktsRecv;
} SuperAppChainStatsElement;

typedef struct struct_super_app_chain_stats_list {
    SuperAppChainStatsElement* head;
    SuperAppChainStatsElement* tail;
    int numInList;
} SuperAppChainStatsList;

// Structure for each chain
typedef struct struct_super_app_chain_id_element {
    struct struct_super_app_chain_id_element* prev;
    struct struct_super_app_chain_id_element* next;

    // Server updates
    char chainID[MAX_STRING_LENGTH];
    int numNeeded;
    int numSeen;

    // Client msg send vars
    SuperAppClientPtrList* clientPtrs;
} SuperAppChainIdElement;


// Structure for the list of chains
typedef struct struct_super_app_chain_id_list {
    SuperAppChainIdElement* head;
    SuperAppChainIdElement* tail;
    int numInList;
} SuperAppChainIdList;


// Chainlist, store per node in AppData
typedef struct struct_super_app_trigger_data {
    SuperAppChainIdList chainIdList;
    SuperAppChainStatsList stats;
} SuperAppTriggerData;


#ifdef ADDON_DB
typedef struct
{
   Message *fragMsg;
   Int32 fragSize;
   clocktype fragDelay;
}frag_Info;
#endif

struct struct_superapplication_str
{
    int state;
    int       connectionId;
    int       uniqueId;
    short     sourcePort;
    int       protocol;
    clocktype sessionStart;
    clocktype sessionFinish;
    BOOL      sessionIsClosed;
    NodeAddress clientAddr;
    NodeAddress serverAddr;
    unsigned short transportLayer; //Transport Layer (currently TCP & UDP are supported)
    RandomDistribution<Int32>     randomReqSize; //Request size
    RandomDistribution<clocktype> randomReqInterval; //Interval of the request
    BOOL waitTillReply; //Indicate if the client should wait till reply is received before sending another request
    unsigned char reqTOS; //TOS of the request
    UInt32 totalReqPacketsToSend;
    char applicationName[MAX_STRING_LENGTH]; //Application being simulated by SuperApp. This name is used to print stats
    char printName[MAX_STRING_LENGTH]; // Name to be printed into statistics file
    char **descriptorName; //Application being simulated by SuperApp. This name is used to print stats
    short destinationPort;
    unsigned short fragmentationSize;
    BOOL waitingForReply; //Indicate if client is waiting for a Reply
    Int32 seqNo; //Packet sequence number
    Int32 fragNo; //Packet fragment number
    Int32 uniqueFragNo; // Fragment number unique for all packets
    BOOL isClosed;
    BOOL fragmentationEnabled; //Indicate if fragmentation size was specified by client
    clocktype lastReqInterArrivalInterval;
    clocktype lastReqPacketReceptionTime;
    clocktype totalReqJitter;
    clocktype totalReqJitterPacket;
    RandomDistribution<Int32>     randomRepSize; //Reply size
    RandomDistribution<clocktype> randomRepInterval; //Interval between reply packets
    RandomDistribution<clocktype> randomRepInterDepartureDelay; //Inter-departure interval of the reply
    BOOL processReply; //Indicate if reply is to be sent
    BOOL gotLastReqPacket; //Indicate if Last Request packet has received.
    unsigned char repTOS; //TOS of the reply
    RandomDistribution<Int32> randomRepPacketsToSendPerReq; //Request packets to send per reply
    clocktype lastRepInterArrivalInterval;
    int appFileIndex; //Index in the application file
    Int32 repSeqNo; //Reply sequence number
    Int32 repFragNo; //Reply fragment number
    Int32  bufferSize; //Size of buffer for storing data from TCP
    char* buffer; //Buffer for storing  fragments received from TCP
    Int32 fragmentBufferSize; //Size of buffer for storing fragment info for packets from TCP
    char* fragmentBuffer; //Buffer for storing  fragments received from TCP
    int waitFragments; //Number of fragments that constitute one packet. Wait for this many fragments tobe sent before regarding the packet as sent.
    clocktype lastReqFragSentTime; //Time when the last req frag was sent by client
    clocktype lastRepFragSentTime; //Time when the last reply fragment was set by server
    clocktype firstRepFragRcvTime; //Time when the reply first fragment was received by client
    clocktype lastRepFragRcvTime; //Time when the last reply fragment was received by the server
    clocktype firstReqFragRcvTime; //Time when the first request fragment was received by the server
    clocktype lastReqFragRcvTime; //Time when the last request fragment was received by the server
    clocktype actJitterForRep; //Used to calculate the smoothed jitter for the current reply fragment
    clocktype actJitterForReq; //Used to calculate the smoothed jitter for the current request fragment
    clocktype totalJitterForRep; //Used to calculate avg jitter for replies received
    clocktype totalJitterForReq; //Used to calculate average jitter for request packets received
    double totalEndToEndDelayForReq; //Used to calculate average end-to-end delay for requests
    double totalEndToEndDelayForRep; //Used to calculate average end to end delay for reply
    clocktype firstReqFragSentTime; //Time when the first request fragment was sent
    clocktype firstRepFragSentTime; //Time when the first reply fragment was sent
    // BAB: Added 4/28/06
    // Request and Reply Receive and Jitter Info for Packets
    clocktype firstReqPacketRcvTime; //Time when the first request packet was received by the server
    clocktype lastReqPacketRcvTime; //Time when the last request packet was received by the server
    clocktype actJitterForReqPacket; //Used to calculate the smoothed jitter for the current complete req message
    clocktype totalJitterForReqPacket; //Used to calculate average jitter for request packets received
    clocktype firstRepPacketRcvTime; //Time when the first request packet was received by the server
    clocktype lastRepPacketRcvTime; //Time when the last request packet was received by the server
    clocktype totalJitterForRepPacket; //Used to calculate average jitter for request packets received
    clocktype actJitterForRepPacket; //Used to calculate the smoothed jitter for the current complete rep message

    // Interarrival Info for Packets
    clocktype lastReqInterArrivalIntervalPacket;
    clocktype lastRepInterArrivalIntervalPacket;

    // E2E Delay info for packets
    clocktype packetSentTime;   // Used to store the sent time of the first fragment of a packet
    double totalEndToEndDelayForReqPacket; //Used to calculate average end-to-end delay for requests
    double totalEndToEndDelayForRepPacket; //Used to calculate average end-to-end delay for replies
    clocktype firstReqPacketSentTime; //Time when the first request fragment was sent
    clocktype lastReqPacketSentTime; //Time when the last req frag was sent by client
    clocktype maxEndToEndDelayForReqPacket; //Time of longest end-to-end delay for requests
    clocktype minEndToEndDelayForReqPacket; //Time of shortest end-to-end delay for requests
    double totalEndToEndDelayForReqPacketDP; //Used to calculate average end-to-end delay for requests
    clocktype maxEndToEndDelayForReqPacketDP; //Time of longest end-to-end delay for requests
    clocktype minEndToEndDelayForReqPacketDP; //Time of shortest end-to-end delay for requests

   // Parameter added for throughput calculation
    clocktype groupLeavingTime;              //Time when node leaves a group.
    clocktype timeSpentOutofGroup;           //Total time spent by node out of group.

   // end BAB add
    SuperApplicationStatsType stats;
    RandomSeed seed;
    int initStats;
    int printStats;

#ifdef ADDON_BOEINGFCS
    BOOL cpuTimingStarted;
    clock_t cpuTimeStart;
    clock_t lastCpuTime;
    clocktype cpuTimingInterval;
    BOOL realTimeOutput;
    BOOL printRealTimeStats;

    BOOL isBursty;
    clocktype burstyTimer;
    clocktype burstyLow;
    clocktype burstyMedium;
    clocktype burstyHigh;
    clocktype burstyInterval;
    RandomDistribution<clocktype>     randomBurstyTimer;
    clocktype maxEndToEndDelayForReq; //Time of longest end-to-end delay for requests
    clocktype minEndToEndDelayForReq; //Time of shortest end-to-end delay for requests
    clocktype delayRealTimeProcessing; //Delay involved in real time processing

    // Jitter for superapplications on different partitions
    clocktype totalJitterForReqDP;
    clocktype totalJitterForReqPacketDP;
    clocktype actJitterForReqDP;
    clocktype actJitterForReqPacketDP;

    // Last received fragment time on different partitions
    clocktype lastReqFragRcvTimeDP;
    clocktype lastReqPacketRcvTimeDP;

    // Used for computing jitter for different pratitions
    clocktype lastReqInterArrivalIntervalDP;
    clocktype lastReqInterArrivalIntervalPacketDP;

    // Used to calculate end-to-end delay for different partitions
    double totalEndToEndDelayForReqDP;

    // Time of longest end-to-end delay for requests, differet partitions
    clocktype maxEndToEndDelayForReqDP;

    // Time of shortest end-to-end delay for requests, different partitions
    clocktype minEndToEndDelayForReqDP;

    int requiredTput;
    clocktype requiredDelay;

    clocktype startTimeOffset;
#endif
    BOOL isTriggered;
    char chainID[MAX_STRING_LENGTH];
    BOOL isChainId;
    BOOL readyToSend;
    // for voice and video session
    BOOL isVoice;
    BOOL isVideo;
    BOOL isJustMyTurnToTalk;
    BOOL isTalking;
    clocktype averageTalkTime;
    clocktype talkTime;
    clocktype firstTalkTime;
    Message* talkTimeOut;
    RandomDistribution<clocktype> randomAverageTalkTime; // average talk time
    float gapRatio; // voip mean spurt gap ratio.

    // for conditions;
    vector <SuperAppClientConditionElement> conditionList;
    BOOL isConditions;

    std::vector<MessageInfoHeader> tcpInfoField;
    std::list<int> upperLimit;

    int sessionId;
#ifdef ADDON_DB
    int sessionInitiator;
    int receiverId;
    SequenceNumber *msgSeqCache;
    SequenceNumber *fragSeqCache;
    Message *prevMsg;
    Int32 prevMsgSize;
    BOOL prevMsgRecvdComplete;
    //frag_Info fragmentInfo;
    std::vector<frag_Info> fragCache;
#endif
    Int32 mdpUniqueId;
    BOOL isMdpEnabled;
    BOOL isProfileNameSet;
    char profileName[MAX_STRING_LENGTH];
    int connRetryLimit;
    int connRetryCount;
    clocktype connRetryInterval;

    // Dynamic Addressing
    NodeId clientNodeId;        // client node id for this app session
    NodeId destNodeId;          // destination node id for this app session 
    Int16 clientInterfaceIndex; // client interface index for this app 
                                // session
    Int16 destInterfaceIndex;   // destination interface index for this app
                                // session
    // dns
    std::string* serverUrl;
};


void
SuperApplicationInit(Node* node,
                     NodeAddress clientAddr,
                     NodeAddress serverAddr,
                     char* inputstring,
                     int iindex,
                     const NodeInput *nodeInput,
                     Int32 mdpUniqueId = -1);


void
SuperApplicationFinalize(Node* node, SuperApplicationData* dataPtr);

void
SuperApplicationClientFinalize(Node* node);

void
SuperApplicationProcessEvent(Node* node, Message* msg);


void SuperApplicationRunTimeStat(Node* node, SuperApplicationData* dataPtr);

void SuperAppTriggerInit(Node* node);

void SuperAppTriggerFinalize(Node* node);
void  SuperApplicationCheckInputString(NodeInput* appInput,
                                       int i,
                                       BOOL* isStartArray,
                                       BOOL* isUNI,
                                       BOOL* isRepeat,
                                       BOOL* isSources,
                                       BOOL* isDestinations,
                                       BOOL* isConditions);

void SuperApplicationHandleStartTimeInputString(const NodeInput* nodeInput,
                                                NodeInput* appInput,
                                                int i,
                                                BOOL isUNI);

void SuperApplicationHandleRepeatInputString(Node* node,
                                             const NodeInput* nodeInput,
                                             NodeInput* appInput,
                                             int i,
                                             BOOL isUNI,
                                             double simulationTime);

void SuperApplicationHandleSourceInputString(const NodeInput* nodeInput,
                                             NodeInput* appInput,
                                             int i);

void SuperApplicationHandleDestinationInputString(const NodeInput* nodeInput,
                                                  NodeInput* appInput,
                                                  int i);

void SuperApplicationHandleConditionsInputString(NodeInput* appInput,
                                                 int i);

void SuperApplicationInitTrace(Node* node, const NodeInput* nodeInput);

void SuperAppClientListInit(Node* node);
#ifdef ADDON_BOEINGFCS
void SuperApp_ChangeTputStats(Node* node, BOOL before, BOOL after);

#endif

#ifdef ADDON_NGCNMS
void SuperAppDestructor(Node* node, const NodeInput *nodeInput);

void SuperApplicationResetServerClientAddr(Node* node,
                       NodeAddress oldAddr,
                                           NodeAddress newAddr);
#endif


//
// STRUCT      :: srtuct_superAppConf_data
// DESCRIPTION :: Structure for storing superapplication config data for
//                multicast servers. Preserving only those config parameter
//                which are required for multcast server init
//
typedef struct  srtuct_superAppConf_data
{
    NodeAddress serverAddr;
    NodeAddress clientAddr;
    short destinationPort;
    short sourcePort;
    char applicationName[MAX_STRING_LENGTH]; //Application being simulated by SuperApp. This name is used to print stats
    char **descriptorName; //Application being simulated by SuperApp. This name is used to print stats
    Int32 mdpUniqueId;
    BOOL isMdpEnabled;
    BOOL isProfileNameSet;
    char profileName[MAX_STRING_LENGTH];

    // other configuration parameters
    srtuct_superAppConf_data * next;
    Int32 appFileIndex;

#ifdef ADDON_BOEINGFCS
    BOOL printRealTimeStats;
#endif

} SuperAppConfigurationData;

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
                                        Int32 mdpUniqueId = -1);


// FUNCTION     : SuperApplicationUpdateMulticastGroupLeavingTime
// PURPOSE      : Update the time node leaves multicast group.
// Parameters:
// node          : pointer to Node.
// groupAddress  : ip address of multicast server
void SuperApplicationUpdateMulticastGroupLeavingTime(Node *node,
                                                         NodeAddress groupAddress);

// FUNCTION     : SuperApplicationUpdateTimeSpentOutofMulticastGroup
// PURPOSE      : Initilize the multicast server and update the timer.
//                Timers update total time spent out of multicast group.
// Parameters:
// node          : pointer to Node.
// groupAddress  : ip address of multicast server
void SuperApplicationUpdateTimeSpentOutofMulticastGroup(Node *node,
                                                        NodeAddress groupAddress);

//---------------------------------------------------------------------------
// FUNCTION             : AppSuperApplicationClientGetClientPtr.
// PURPOSE              : get the Super Application client pointer
// PARAMETERS           ::
// + node               : Node*          : pointer to the node
// + sourcePort         : unsigned short : source port of the client
// + uniqueId           : Int32          : unique id
// + tcpMode            : bool           : tcpMode
// RETURN               
// SuperApplicationData*    : Super Application client pointer if found 
//                            else NULL
//---------------------------------------------------------------------------
SuperApplicationData*
AppSuperApplicationClientGetClientPtr(
                        Node* node,
                        UInt16 sourcePort,
                        Int32 uniqueId,
                        bool tcpMode);

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
                                  SuperApplicationData* clientPtr);

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
                                   SuperApplicationData* clientPtr);

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
                                    SuperApplicationData* serverPtr);

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
                     struct AppUdpPacketSendingInfo* packetSendingInfo);

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
AppSuperApplicationUrlTCPSessionStartCallBack(
                     Node* node,
                     Address* serverAddr,
                     UInt16 sourcePort,
                     Int32 uniqueId,
                     Int16 interfaceId,
                     std::string serverUrl,
                     struct AppUdpPacketSendingInfo* packetSendingInfo);
#endif

