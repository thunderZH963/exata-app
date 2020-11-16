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
#ifndef DB_DEVELOPER_H
#define DB_DEVELOPER_H

#include <string>
#include <vector>
#include <iostream>


using namespace std;

// Protocol Specific Code

struct StatsDBIGMPSummary
{
    int m_NumJoinRecvd;
    std::vector<NodeAddress> m_NodeList;
};


class StatsDBIgmpTable
{
public:

    //data members
    BOOL createIgmpSummaryTable;

    //this interval is currently same as STATS-DB-SUMMARY-INTERVAL
    clocktype igmpSummaryInterval;

    struct ltndaddr
    {
        bool operator () (std::pair<NodeAddress, NodeAddress> s1,
            std::pair<NodeAddress, NodeAddress> s2) const
        {
            BOOL retVal = FALSE;
            if(s1.first < s2.first)
            {
                retVal = TRUE;
            }
            else if ((s1.first == s2.first) && (s1.second < s2.second))
            {
                retVal = TRUE;
            }
            return retVal;
        }
    };
    std::map<std::pair<NodeAddress, NodeAddress>,
                      StatsDBIGMPSummary*, ltndaddr> map_IGMPSummary;
    typedef std::map<std::pair<NodeAddress, NodeAddress>,
        StatsDBIGMPSummary*, ltndaddr>::const_iterator Const_IGMPSummaryIter;

    //member functions
    StatsDBIgmpTable();

};


void InitializeStatsDBIgmpTable(PartitionData* paritionData,
                                NodeInput* nodeInput);
void InitializeStatsDBIgmpSummaryTable(PartitionData* partition,
                                          NodeInput* nodeInput);

void StatsDBSendIgmpTableTimerMessage(PartitionData* partition);

/**
* To get the first node on each partition that is actually running PIM.
*
* @param partition Data structure containing partition information
* @return First node on the partition that is running PIM
*/
Node* StatsDBIgmpGetInitialNodePointer(PartitionData* partition);


void HandleStatsDBIgmpSummary(Node* node,
                             const std::string& eventType,
                             NodeAddress srcAddr,
                             NodeAddress groupAddr);

void HandleStatsDBIgmpSummaryTableInsertion(Node* node);


void STATSDB_HandleIgmpSummaryTableInsert(Node* node,
                        std::vector<std::string>* insertList);
// for Multicast Network Summary table on IP layer
void HandleStatsDBIpMulticastNetSummaryTableInsertion(Node* node);

void StatsDBSendIpTableTimerMessage(PartitionData* partition);
#endif // DB_DEVELOPER_H
