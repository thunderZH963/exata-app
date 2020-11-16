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

#include <string>
#include <vector>
#include <iostream>
#include <math.h>
#include <stdio.h>
#include <iomanip>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#endif

#ifdef ADDON_DB
#include "api.h"
#include "partition.h"
#include "WallClock.h"
#include "external_util.h"
#include "db_developer.h"
#include "db.h"
#include "dbapi.h"
#include "db-core.h"
#include "network_ip.h"

#ifdef PARALLEL //Parallel
#include "parallel.h"
#endif

#ifdef USE_MPI
#include <mpi.h>
#endif

#include "db-dynamic.h"

StatsDBIgmpTable::StatsDBIgmpTable()
{
    createIgmpSummaryTable = FALSE;

    //this interval is currently same as STATS-DB-SUMMARY-INTERVAL
    igmpSummaryInterval = 0;
}



void InitializeStatsDBIgmpTable(PartitionData* partition,
                                NodeInput* nodeInput)
{
    char buf[MAX_STRING_LENGTH];
    BOOL wasFound = FALSE;
    BOOL igmpTableCreated = FALSE;

    StatsDb* db = NULL;
    db = partition->statsDb;
    db->statsIgmpTable = NULL;

    // Check which tables are to be defined in the Protocol table
    // category. Check for the user configurations.

    IO_ReadString(
        ANY_NODEID,
        ANY_ADDRESS,
        nodeInput,
        "STATS-DB-MULTICAST-IGMP-SUMMARY-TABLE",
        &wasFound,
        buf);


    if (wasFound)
    {
        if (strcmp(buf, "YES") == 0)
        {
            if (!igmpTableCreated)
            {
                db->statsIgmpTable = new StatsDBIgmpTable();
                igmpTableCreated = TRUE;
            }

            // Initialize the IGMP_Summary table.
            db->statsIgmpTable->createIgmpSummaryTable = TRUE;
            if (partition->partitionId == 0)
            {
                InitializeStatsDBIgmpSummaryTable(partition, nodeInput);
            }

        }
        else if (strcmp(buf, "NO") != 0)
        {
            // We have invalid values.
            ERROR_ReportWarning(
                "Invalid Value for STATS-DB-MULTICAST-IGMP-SUMMARY-TABLE"
                "parameter, using Default\n");
        }
    }

    //for interval the parameter value STATS-DB-SUMMARY-INTERVAL is used
    if (igmpTableCreated)
    {
        // Set Summary Interval timer.
        IO_ReadString(
            ANY_NODEID,
            ANY_ADDRESS,
            nodeInput,
            "STATS-DB-SUMMARY-INTERVAL",
            &wasFound,
            buf);

        if (wasFound)
        {
            db->statsIgmpTable->igmpSummaryInterval=TIME_ConvertToClock(buf);
        }
        else
        {
            db->statsIgmpTable->igmpSummaryInterval =
                                            STATSDB_DEFAULT_SUMMARY_INTERVAL;
        }

        //value check
        if (db->statsIgmpTable->igmpSummaryInterval <= 0)
        {
            // We have invalid values.
            ERROR_ReportWarning(
                "Value for STATS-DB-SUMMARY-INTERVAL should be greater "
                "than 0. Continue with default value.\n");

            db->statsIgmpTable->igmpSummaryInterval =
                                             STATSDB_DEFAULT_SUMMARY_INTERVAL;
        }

    }

}




void InitializeStatsDBIgmpSummaryTable(PartitionData* partition,
                                          NodeInput* nodeInput)
{
    // In this function we initialize the IGMP_Summary Table.
    // That is we create the table with the columns based on the
    // user input.

    clocktype start = 0;
    clocktype end = 0;

    StatsDb* db = partition->statsDb;

    DBColumns columns;
    columns.reserve(5);
    columns.push_back(string_pair("Timestamp", "real"));
    columns.push_back(string_pair("RouterNodeID", "integer"));
    columns.push_back(string_pair("MulticastAddress", "VARCHAR(64)"));
    columns.push_back(string_pair("JoinMsgReceived", "bigint unsigned"));
    columns.push_back(string_pair("ActiveNodeIds", "text"));

    if (STATS_DEBUG)
    {
        start = partition->wallClock->getRealTime();
    }

    CreateTable(db, "IGMP_Summary", columns);

    if (STATS_DEBUG)
    {
        end = partition->wallClock->getRealTime();
        clocktype diff = end - start;
        char temp[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(diff, temp);
       printf("Time Taken to create IGMP_Summary table partition %d, %s\n",
                partition->partitionId,
                temp);
    }
}




void StatsDBSendIgmpTableTimerMessage(PartitionData* partition)
{
    // In this function we send a timer message to the first node of
    // each partition. Once the message is received we calculate the
    // Summary stats for the simulation.
    // Create the Timer message and send out.

    StatsDb* db = partition->statsDb;
    if (!db || !db->statsIgmpTable)
    {
        return;
    }

    Node* firstNode = NULL;

    firstNode = StatsDBIgmpGetInitialNodePointer(partition);

    if (firstNode == NULL)
    {
        // none of the nodes on this partition are running IGMP
        // so dont waste the timers...
        return;
    }

    if (db->statsIgmpTable->createIgmpSummaryTable)
    {
        Message* igmpSummaryTimer;
        StatsDb* db = partition->statsDb;
        igmpSummaryTimer = MESSAGE_Alloc(firstNode,
                                        NETWORK_LAYER,
                                        GROUP_MANAGEMENT_PROTOCOL_IGMP,
                                        MSG_STATS_IGMP_InsertSummary);
        MESSAGE_Send(partition->firstNode,
            igmpSummaryTimer,
            db->statsIgmpTable->igmpSummaryInterval);
    }
}



void HandleStatsDBIgmpSummary(Node* node,
                             const std::string& eventType,
                             NodeAddress srcAddr,
                             NodeAddress groupAddr)
{
    StatsDb* db = node->partitionData->statsDb;

    // Check if the Table exists.
    if (!db || !db->statsIgmpTable ||
        !db->statsIgmpTable->createIgmpSummaryTable)
    {
        // Table does not exist
        return;
    }

    int i;
    std::pair<NodeAddress, NodeAddress> key(node->nodeId, groupAddr);

    StatsDBIgmpTable::Const_IGMPSummaryIter iter =
                               db->statsIgmpTable->map_IGMPSummary.find(key);

    StatsDBIGMPSummary *pStatus = NULL;

    if (iter == db->statsIgmpTable->map_IGMPSummary.end())
    {
        //create new
        db->statsIgmpTable->map_IGMPSummary[key] = new StatsDBIGMPSummary;
        pStatus = db->statsIgmpTable->map_IGMPSummary[key];
        pStatus->m_NumJoinRecvd = 0;
    }
    else
    {
        pStatus = iter->second;
    }

    if (!pStatus)
    {
        ERROR_ReportWarning("Something is not ok with map. "
            "Ignoring the value to add/update.\n");
        return;
    }

    if (eventType == "Join")
    {
        pStatus->m_NumJoinRecvd++;

        BOOL isExist = FALSE;

        NodeAddress nodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                                   srcAddr);
        for (i = 0;i < pStatus->m_NodeList.size(); i++)
        {
            if (pStatus->m_NodeList.at(i) == nodeId)
            {
                isExist = TRUE;
                break;
            }
        }

        if (!isExist)
        {
            pStatus->m_NodeList.push_back(nodeId);
        }
    }
    else if (eventType == "Leave")
    {
        BOOL isExist = FALSE;

        NodeAddress nodeId = MAPPING_GetNodeIdFromInterfaceAddress(node,
                                                                   srcAddr);
        std::vector<NodeAddress> tmp;
        vector<NodeAddress>::iterator startIterator;

        startIterator = pStatus->m_NodeList.begin();

        for (i = 0;i < pStatus->m_NodeList.size(); i++)
        {
            if (pStatus->m_NodeList.at(i) == nodeId)
            {
                pStatus->m_NodeList.erase(startIterator);
            }
            if (pStatus->m_NodeList.end() != startIterator)
            {
                startIterator++;
            }
        }
    }
    else if (eventType == "Delete")
    {
        if (!pStatus->m_NumJoinRecvd && pStatus != NULL)
        {
            delete(db->statsIgmpTable->map_IGMPSummary[key]);
            db->statsIgmpTable->map_IGMPSummary.erase(key);
        }
    }
    else
    {
        ERROR_ReportWarning("Uknown eventType received "
            "in HandleStatsDBIgmpSummary. \n");
    }
}



void HandleStatsDBIgmpSummaryTableInsertion(Node* node)
{
    StatsDb* db = node->partitionData->statsDb;

    // Calculate only if the IGMP Summary is enabled.
    if (!db || !db->statsIgmpTable ||
        !db->statsIgmpTable->createIgmpSummaryTable)
    {
        return;
    }

    std::vector<std::string> insertList;

    STATSDB_HandleIgmpSummaryTableInsert(node, &insertList);

    for (size_t i = 0; i < insertList.size(); i++)
    {
        AddInsertQueryToBuffer(db, insertList[i]);
    }
}




void STATSDB_HandleIgmpSummaryTableInsert(
    Node* node,
    std::vector<std::string>* insertList)
{
    if (node != node->partitionData->firstNode)
    {
        return ;
    }

    StatsDb* db = node->partitionData->statsDb;

    if (!db || !db->statsIgmpTable ||
        !db->statsIgmpTable->createIgmpSummaryTable)
    {
        return ;
    }

    int i;
    std::string currentTime =
        STATSDB_DoubleToString((double) node->getNodeTime() / SECOND);

    StatsDBIgmpTable::Const_IGMPSummaryIter citer =
                                db->statsIgmpTable->map_IGMPSummary.begin();

    for (; citer != db->statsIgmpTable->map_IGMPSummary.end(); ++citer)
    {
        if (citer->second->m_NodeList.size() == 0 &&
            citer->second->m_NumJoinRecvd == 0)
        {
            continue;
        }
        std::string queryStr = "INSERT INTO IGMP_Summary "
            "(Timestamp, RouterNodeID, MulticastAddress, "
            "JoinMsgReceived, ActiveNodeIds";
        queryStr += ") ";

        // Now to enter the values.
        queryStr += "VALUES('";
        queryStr += currentTime;
        queryStr += "', ";
        queryStr += "'";
        queryStr += STATSDB_IntToString(citer->first.first);
        queryStr += "', ";

        char grpAddrStr[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(citer->first.second, grpAddrStr);

        queryStr += "'";
        queryStr += grpAddrStr;
        queryStr += "', ";

        queryStr += "'";
        queryStr += STATSDB_IntToString(citer->second->m_NumJoinRecvd);
        queryStr += "', ";
        queryStr += "'";

        for (i = 0;i < citer->second->m_NodeList.size();i++)
        {
            queryStr += STATSDB_IntToString(citer->second->m_NodeList.at(i));
            if (i+1 != citer->second->m_NodeList.size())
            {
                queryStr += ", ";
            }
        }
        queryStr += "');";
        citer->second->m_NumJoinRecvd = 0;
        // Now to insert the content into the table.
        insertList->push_back(queryStr);
    }
    return ;
}

void StatsDBSendIpTableTimerMessage(PartitionData* partition)
{
    StatsDb* db = partition->statsDb;

    if (!db || !db->statsSummaryTable
        || !db->statsSummaryTable->createMulticastNetSummaryTable)
    {
        //table not exist
        return;
    }

    Node* firstNode = partition->firstNode;

    while (firstNode != NULL)
    {
        if (firstNode->partitionId != partition->partitionId)
        {
            firstNode = firstNode->nextNodeData;
            continue;
        }

        break;
    }

    if (firstNode == NULL)
    {
        // none of the nodes on this partition are required to have multicast
        // network summary collection on IP...so dont waste the timers.
        return;
    }

    if (db->statsSummaryTable->createMulticastNetSummaryTable)
    {
        Message* ipMulticastNetSummaryTimer;
        ipMulticastNetSummaryTimer = MESSAGE_Alloc(firstNode,
                                         NETWORK_LAYER,
                                         NETWORK_PROTOCOL_IP,
                                         MSG_STATS_MULTICAST_InsertSummary);
        MESSAGE_Send(firstNode,
                     ipMulticastNetSummaryTimer,
                     db->statsSummaryTable->summaryInterval);
    }
}
#endif // ADDON_DB
