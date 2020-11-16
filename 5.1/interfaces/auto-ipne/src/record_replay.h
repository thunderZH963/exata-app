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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#ifndef RECORD_REPLAY_H
#define RECORD_REPLAY_H

#define REPLAY_FILE_VERSION_V0 0
#define REPLAY_FILE_VERSION_V1 1

class RecordReplayInterface {
public:
    RecordReplayInterface();
    ~RecordReplayInterface();    

    void Initialize(PartitionData* partitionData);  

    void RecordAddVirtualHost(NodeAddress virtualNodeAddress);
    void RecordAddIPv6VirtualHost(Address virtualNodeAddress);

    void RecordRemoveVirtualHost(NodeAddress virtualNodeAddress);
    void RecordRemoveIPv6VirtualHost(Address virtualNodeAddress);

    void RecordHandleSniffedPacket(
        NodeAddress interfaceAddress,  //this is the from address 
        clocktype delay,
        NodeAddress srcAddr,
        NodeAddress destAddr,
        unsigned short identification,
        BOOL dontFragment,
        BOOL moreFragments,
        unsigned short fragmentOffset,
        TosType tos,
        unsigned char protocol,
        unsigned int ttl,
        char * payload,
        int payloadSize,
        NodeAddress nextHopAddr,
        int ipHeaderLength,
        char *ipOptions);

    void RecordHandleIPv6SniffedPacket(
         Address interfaceAddress,  //this is the from address 
         clocktype delay,
         Address srcAddr,
         Address destAddr,
         TosType tos,
         unsigned char protocol,
         unsigned hlim,
         char * payload,
         Int32 payloadSize);

    void RecordOutgoingPacket(
        NodeAddress interfaceAddress,  
        clocktype delay,
        NodeAddress srcAddr,
        NodeAddress destAddr,
        unsigned short identification,
        BOOL dontFragment,
        BOOL moreFragments,
        unsigned short fragmentOffset,
        TosType tos,
        unsigned char protocol,
        unsigned int ttl,
        char * payload,
        int payloadSize,
        NodeAddress nextHopAddr,
        int ipHeaderLength,
        char *ipOptions);

    void RecordOutgoingIPv6Packet(
                      Address interfaceAddress,  //this is the from address 
                      clocktype delay,
                      Address srcAddr,
                      Address destAddr,
                      TosType tos,
                      unsigned char protocol,
                      unsigned hlim,
                      char* payload,
                      Int32 payloadSize);

    BOOL GetRecordMode()
    {
        return recordMode;
    }

    BOOL GetReplayMode()
    {
        return replayMode;
    }

    
    void ReplayProcessTimerEvent(Node *node, Message* msg);

    BOOL ReplayForwardFromNetworkLayer(
        Node* node,
        int interfaceIndex,
        Message* msg,
        BOOL skipCheck);
    BOOL ReplayForwardFromNetworkLayer(
        Node* node,
        int interfaceIndex,
        Message* msg);


private:

   // static const clocktype MAX_TIMESTAMP = 0xFFFFFFFF00000000; 
   // static const clocktype MIN_TIMESTAMP = 0xFFFFFFFF;
    //Common variables shared by record and replay
    PartitionData  *partition;
    FILE* recordFile;
    FILE* replayFile;
    UInt32 version;

    struct TimeZone 
    {
        int  tz_minuteswest; //minutes W of Greenwich
        int  tz_dsttime;      //type of dst correction 
    };

    struct TimeValue 
    {
        unsigned int tv_sec; 
        unsigned int tv_usec;
    };
    struct RealTimeHdr 
    {
        TimeValue ts;    /* time stamp */
        unsigned int caplen;    /* length of portion present */
        unsigned int len;   /* length this packet (off wire) */
    };
    struct RecordFileHeader
    {
        int eventType;        
        NodeAddress interfaceAddress;  //this is the from address below
       
        NodeAddress srcAddr;
        NodeAddress destAddr;
        int identification;
        BOOL dontFragment;
        BOOL moreFragments;      
        TosType tos;       
        unsigned int ttl;
        int payloadSize;
        NodeAddress nextHopAddr; 
        short protocol;
        unsigned  short fragmentOffset;
        int ipHeaderLength;
        RealTimeHdr pcapheader;
        int unused;
        clocktype delay;
        clocktype timestamp;
    };

    struct RecordIPv6FileHeader
    {
        int eventType;        
        Address interfaceAddress;  //this is the from address below

        Address srcAddr;
        Address destAddr;
        TosType tos;
        unsigned hlim;
        Int32 payloadSize;
        unsigned char protocol;
        RealTimeHdr pcapheader;
        int unused;
        clocktype delay;
        clocktype timestamp;
    };


   enum 
    {
        MSG_PacketIn,
        MSG_NodeJoin,
        MSG_NodeLeave,
        MSG_SetReplayInterface,
        MSG_ResetReplayInterface,
        MSG_PacketOut,
        MSG_IPv6PacketIn,
        MSG_IPv6NodeJoin,
        MSG_IPv6NodeLeave
    };


    //Private variables for record mode
    BOOL recordMode;
    
    //Private variables for replay mode
    BOOL replayMode;

    struct ReplayInfo
    {
        NodeAddress interfaceAddress;  //this is the from address below
        clocktype delay;
        NodeAddress srcAddr;
        NodeAddress destAddr;
        unsigned short identification;
        BOOL dontFragment;
        BOOL moreFragments;
        unsigned short fragmentOffset;
        TosType tos;
        unsigned char protocol;
        unsigned int ttl;
        char *payload;
        int payloadSize;
        NodeAddress nextHopAddr;
        int ipHeaderLength;
        char *ipOptions;
    };

    struct IPv6ReplayInfo
    {
        Address interfaceAddress;  //this is the from address below
        clocktype delay;
        Address srcAddr;
        Address destAddr;
        TosType tos;
        unsigned char protocol;
        unsigned hlim;
        char *payload;
        int payloadSize;
    };

    //Private functions for record phase
    void InitializeRecordInterface(const NodeInput* nodeInput);
    string IntToString(int num);
    

    //Private functions for replay phase
    void InitializeReplayInterface(const NodeInput* nodeInput);
    void SendTimerMsg(Message *msg); 
#ifdef _WIN32
    int getTimeOfDayWin(TimeValue *tv, TimeZone *tz);
#endif    
};

#endif
