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

#include "api.h"
#include "app_util.h"
#include "network_ip.h"
#include "app_dos.h"
#include "partition.h"
#include "application.h"

static const clocktype APP_DOS_PACKET_INTERVAL = 100 * MILLI_SECOND;
static const int APP_DOS_PACKET_SIZE = 512;
/*
From .app file
DOS <victim> <num-of-attacker> <attacker1> <attacker2>...<attackerN> <attack-type> <port> 
    <num-of-items> <item-size> <interval> <start-time> <end-time>
From gui
DOS <victim> <num-of-attacker> <attacker1> <attacker2>...<attackerN> <attack-type> <port> 
<duration> [interval=10MS]
*/

unsigned int AppDOSVictimGetNewInstanceId(Node* node)
{
    AppInfo *appList = node->appData.appPtr;
    AppDOSVictim *dos;
    int instanceId = -1;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DOS_VICTIM)
        {
            dos = (AppDOSVictim *) appList->appDetail;

            if (dos->instanceId > instanceId)
            {
                instanceId = dos->instanceId;
            }
        }
    }

    return instanceId + 1;
}

AppDOSAttacker* AppDOSAttackerGetApp(Node* node, int instanceId, NodeAddress victimAddress)
{
    AppInfo *appList = node->appData.appPtr;
    AppDOSAttacker *dos;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DOS_ATTACKER)
        {
            dos = (AppDOSAttacker *) appList->appDetail;

            if (dos->instanceId == instanceId)
            {
                if (dos->victimAddress.interfaceAddr.ipv4 == victimAddress)
                {
                    return dos;
                }
            }
        }
    }

    return NULL;
}

AppDOSVictim* AppDOSVictimGetApp(Node* node, int destPort)
{
    AppInfo *appList = node->appData.appPtr;
    AppDOSVictim *dos;

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DOS_VICTIM)
        {
            dos = (AppDOSVictim *) appList->appDetail;

            if (dos->destPort == destPort)
            {
                return dos;
            }
        }
    }
    return NULL;
}

void AppDOSAttackerStop(Node *srcNode, int instanceId, 
                       NodeAddress victimAddr)
{
    AppDOSAttacker* dos = AppDOSAttackerGetApp(srcNode, instanceId, victimAddr);
    if (dos == NULL)
    {
        //nothing to do
        return;
    }
    dos->endTime = srcNode->getNodeTime();
}

void AppDOSVictimStop(Node* node)
{
    //we stop the traffic from going by setting the DOS session end time to 
    //current sim time.
    AppInfo *appList = node->appData.appPtr;
    AppDOSVictim *dos = NULL;
    list<int>::iterator it;
    
    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DOS_VICTIM)
        {
            dos = (AppDOSVictim *) appList->appDetail;
            for (it = dos->sourceIdList.begin(); it != dos->sourceIdList.end(); it++)
            {
                int sourceNodeId = *it;
                Node* srcNode = NULL;
                BOOL nodeFound = PARTITION_ReturnNodePointer(
                        node->partitionData,     
                        &srcNode,
                        sourceNodeId,
                        FALSE /* do not retreive node pointer from remote partitions */);

#ifdef PARALLEL
                if (!nodeFound)
                {
                    if (!PARTITION_ReturnNodePointer(
                            node->partitionData,     
                            &srcNode,
                            sourceNodeId,
                            TRUE /* retreive node pointer from remote partitions */))
                    {
                        char errorString[MAX_STRING_LENGTH];
                        sprintf(errorString, "[DOS] Invalid Attacker Specified: "
                            "Attacker node %d does not exist!, Ignoring this attacker\n", sourceNodeId);
                        ERROR_SmartReportError(errorString, 0);
                        continue;
                    }

                    //initialize at remote node by sending a message
                    Message* dosStopMessage;
                    dosStopMessage = MESSAGE_Alloc(srcNode,
                        APP_LAYER,
                        APP_DOS_ATTACKER,
                        MSG_DOS_StopAttacker);
                    MESSAGE_SetInstanceId(dosStopMessage, dos->instanceId);
                    NodeAddress *victim;
                    MESSAGE_InfoAlloc(srcNode, dosStopMessage, sizeof(NodeAddress));
                    victim = (NodeAddress *) MESSAGE_ReturnInfo(dosStopMessage);
                    *victim = dos->myAddress;
                    MESSAGE_RemoteSendSafely(srcNode,
                        sourceNodeId,
                        dosStopMessage,
                        0);
                    continue;
                }
#endif
                if (nodeFound ==  TRUE)
                {
                    AppDOSAttackerStop(srcNode, dos->instanceId, 
                        dos->myAddress);
                }
            }
        }
    }

    if (!dos)
    {
        printf ("[DOS] No active DOS application on node %d\n", node->nodeId);
        return;
    }
    else
    {
        printf("[DOS] DOS sessions from node %d stopped\n", node->nodeId);
    }
    return ;
}

void AppDosAttackerInitialize( 
        Node* srcNode,
        int attackType,
        NodeAddress sourceNodeId,
        Address victimAddr,
        int packetCount,
        int packetSize,
        clocktype packetInterval,
        clocktype startTime,
        clocktype endTime,
        clocktype duration,
        int victimPort,
        int instanceId
        )
{
    AppDOSAttacker *dos = new AppDOSAttacker();

    dos->myAddress = MAPPING_GetDefaultInterfaceAddressInfoFromNodeId(
        srcNode, srcNode->nodeId, NETWORK_IPV4);

    if (victimAddr.networkType == NETWORK_INVALID)
    {
        char errorString[MAX_STRING_LENGTH];
        char ipAddy[MAX_ADDRESS_STRING_LENGTH];
        IO_ConvertIpAddressToString(victimAddr.interfaceAddr.ipv4, ipAddy);
        sprintf(errorString, "Victim node cannot be found for: %s", ipAddy);
        ERROR_ReportError(errorString);
    }
    if (startTime == 0)
    {
        startTime = srcNode->getNodeTime();
    }
    if (duration != 0)
    {
        endTime = startTime + duration;
    }

    dos->victimAddress = victimAddr;
    dos->attackType = attackType;
    dos->victimPort = victimPort;
  
    dos->startTime = startTime;
    dos->endTime = endTime;
    dos->duration = duration;
    dos->packetInterval = packetInterval;
    dos->packetCount = packetCount;
    dos->packetSize = packetSize;

    dos->udpPacketsSent = 0;
    dos->tcpSYNSent = 0;
    dos->fragmentsSent = 0;
    dos->firstPacketAt = 0;

    //dos->instanceId = AppDOSGetNewInstanceId(srcNode);
    dos->uniqueId = srcNode->appData.uniqueId++;
    dos->instanceId = instanceId;
    APP_RegisterNewApp(srcNode, APP_DOS_ATTACKER, dos);

    // Start timer to initiate attack
    Message* timer = MESSAGE_Alloc(srcNode,
            APP_LAYER,
            APP_DOS_ATTACKER,
            MSG_APP_TimerExpired);

    MESSAGE_SetInstanceId(timer, dos->instanceId);
    NodeAddress *victim;
    MESSAGE_InfoAlloc(srcNode, timer, sizeof(NodeAddress));

    victim = (NodeAddress *) MESSAGE_ReturnInfo(timer);
    *victim = victimAddr.interfaceAddr.ipv4;
    clocktype delay;

    if (dos->startTime < srcNode->getNodeTime())
    {
        //send it now
       delay = 0;
       //dos->endTime = srcNode->getNodeTime() + dos->duration;
    }
    else
    {
        delay = dos->startTime - srcNode->getNodeTime();
        //dos->endTime = dos->startTime + dos->duration;

    }
    MESSAGE_Send(srcNode, timer, delay);

    dos->stats = new STAT_AppStatistics(
        srcNode,
        "DOS",
        STAT_Unicast,
        STAT_AppSender);
    dos->stats->Initialize(
        srcNode,
        dos->myAddress,
        victimAddr,
        dos->uniqueId,
        dos->uniqueId);


#ifdef DEBUG
    printf("[DOS] DOS Attack configured at Node %d [Instance =%d]\n",
            node->nodeId,
            dos->instanceId);
    printf("\tVictim: Address=%x Protocol=%s Port=%d\n",
            dos->victimAddress.interfaceAddr.ipv4,
            (dos->victimProtocol == IPPROTO_TCP) ? "TCP" : "UDP",
            dos->victimPort);
    printf("\tAttack: Start=%llu End=%llu Interval=%llu\n",
            dos->startTime,
            dos->endTime,
            dos->packetInterval);
    printf("\tAdvanced: SYN=%d FRAG=%d\n",
            dos->doSYNAttack,
            dos->doFragmentAttack);
#endif
}

void DOS_Finalize(Node *node)
{
    if (node->appData.appStats != TRUE) {
        return;
    }

    AppInfo *appList = node->appData.appPtr;
    AppDOSAttacker *dos;
    char buf[MAX_STRING_LENGTH];

    for (; appList != NULL; appList = appList->appNext)
    {
        if (appList->appType == APP_DOS_ATTACKER)
        {
            dos = (AppDOSAttacker *) appList->appDetail;

            sprintf(buf, "First packet sent at (sec) = %lf",
                    (double)dos->firstPacketAt / SECOND);
            IO_PrintStat(node, "Application", "DOS",
                    ANY_DEST, dos->instanceId, buf);

            sprintf(buf, "Last packet sent at (sec) = %lf",
                    (double)dos->lastPacketAt / SECOND);
            IO_PrintStat(node, "Application", "DOS",
                    ANY_DEST, dos->instanceId, buf);

            if (dos->attackType == AppDOSAttacker::ATTACK_BASIC)
            {
                sprintf(buf, "Number of UDP Packets Sent = %ld",
                        dos->udpPacketsSent);
                IO_PrintStat(node, "Application", "DOS",
                        ANY_DEST, dos->instanceId, buf);
            }
            if (dos->attackType == AppDOSAttacker::ATTACK_SYN)
            {
                sprintf(buf, "Number of TCP SYN Packets Sent = %ld",
                        dos->tcpSYNSent);
                IO_PrintStat(node, "Application", "DOS",
                        ANY_DEST, dos->instanceId, buf);
            }
            if (dos->attackType == AppDOSAttacker::ATTACK_BASIC)
            {
                sprintf(buf, "Number of IP Fragment Packet Sent = %ld",
                        dos->fragmentsSent);
                IO_PrintStat(node, "Application", "DOS",
                        ANY_DEST, dos->instanceId, buf);
            }
        }
    }
}

void AppDosInputError(BOOL fromGUI)
{
    char errorString[BIG_STRING_LENGTH];
    if (fromGUI)
    {
        sprintf(errorString, "Wrong DOS configuration format! Correct format is:\n"
            "dos &lt;victim&gt; &lt;num-attackers&gt; [&lt;attacker1&gt; &lt;attacker2&gt; ...&lt;attackerN&gt;] "
            "&lt;attack-type&gt; &lt;victim port&gt; &lt;interval&gt; &lt;duration&gt;");
    }
    else
    {
        sprintf(errorString, "Wrong DOS configuration format! Correct format is:\n"
            "DOS <victim> <num-attackers> <attacker1> <attacker2> ...<attackerN> <attack-type> "
            "<victim port> <num-of-items> <item-size> <interval> <start time> <end time>");
    }
    ERROR_SmartReportError(errorString, !fromGUI);
    return;
}

void AppDosVictimProcessEvent(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_DOS_VictimInit:
        {
            NodeAddress victimNodeId;
            Address victimAddr;     
            Node *victimNode;
            BOOL fromGUI = MESSAGE_GetInstanceId(msg);  

            victimNode = node;

            //Now parse all the parameters after getting 
            //the info field from the msg
            char *inputString;
            inputString = (char *)MESSAGE_ReturnInfo(msg);

            unsigned int victimPort;
            unsigned int packetSize;
            unsigned int packetCount;

            char startTimeStr[MAX_STRING_LENGTH];
            clocktype sTime;

            char durationStr[MAX_STRING_LENGTH];
            clocktype dTime;

            char endTimeStr[MAX_STRING_LENGTH];
            clocktype eTime;

            char packetIntervalStr[MAX_STRING_LENGTH];
            clocktype pktInterval;

            char attackString[MAX_STRING_LENGTH];
            int attackType;

            int numAttackers;

            NodeAddress sourceNodeId;
            //std::list<int> sourceIdList;

            char* next;
            char *token;
            const char *delims = " \t\n";
            char iotoken[MAX_STRING_LENGTH];

            // token = "DOS" : already checked at this point
            token = IO_GetDelimitedToken(
                iotoken, inputString, delims, &next);
            // Retrieve next token: victimNode: already checked at this point
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            IO_AppParseSourceString(
            node,
            inputString,
            token,
            &victimNodeId,
            &victimAddr);
            //This token: num of attackers
            token = IO_GetDelimitedToken(iotoken, next, delims, &next);
            if (!token)
            {
                AppDosInputError(fromGUI);
                return;
            }
            numAttackers = atoi(token);
            if (numAttackers == 0)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Valid number of attackers have to be specified. \n\t");
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            AppDOSVictim *dos = new AppDOSVictim();
            dos->stats = NULL;
            dos->myAddress = victimAddr.interfaceAddr.ipv4;
#define MIN_DOS_GUI_PARAMS 4
            int count = 0;
            bool attackersSpecified = false;
            if (fromGUI)
            {
                char *temp = (char*)malloc(strlen(next) + 1);
                strcpy(temp, next);
                token = IO_GetDelimitedToken(
                        iotoken, temp, delims, &temp);
 
                while (token != NULL)
                {
                    count ++;
                    token = IO_GetDelimitedToken(
                        iotoken, temp, delims, &temp);
                    
                }
                if (count > MIN_DOS_GUI_PARAMS)
                {
                    //This means that attacker list is specified in the GUI command, 
                    //so we need to read this next
                    int actualNumParameters = numAttackers + MIN_DOS_GUI_PARAMS;
                    if (count != actualNumParameters)
                    {
                         delete dos;
                         AppDosInputError(fromGUI);
                         return;
                    }
                    attackersSpecified = true;
                }
                else if (count < MIN_DOS_GUI_PARAMS)
                {
                    delete dos;
                    AppDosInputError(fromGUI);
                    return;
                }
            }
            if (!fromGUI || (fromGUI && attackersSpecified))
            {
                for (int i = 0; i < numAttackers; i++)
                {
                    token = IO_GetDelimitedToken(
                        iotoken, next, delims, &next);

                    if (!token)
                    {
                        if (fromGUI)
                        {
                            delete dos;
                        }
                        AppDosInputError(fromGUI);
                        return;
                    }

                    sourceNodeId = atoi(token);
                    if (sourceNodeId == 0)
                    {
                        char errorString[MAX_STRING_LENGTH]; 
                        sprintf(errorString, "[DOS] Not enough valid attackers specified, "
                            "Specify as many attackers as the 'num-attackers' specified\n");
                        delete dos;
                        ERROR_SmartReportError(errorString, !fromGUI);
                        return;
                    }
                    if (victimNodeId != sourceNodeId)
                    {
                        dos->sourceIdList.push_back(sourceNodeId);
                    }
                }
            }
            else if (fromGUI && !attackersSpecified)
            {
                //attackers have not been specified,
                //so autoconfigure this list from
                //partitionData->allNodes
                Node *currentNode;
                if (numAttackers > node->partitionData->numNodes)
                {
                    printf("[DOS] DOS to victim node %d: "
                        "NumAttackers should be less than or equal to the "
                        "number of nodes in the simulation\n", victimNodeId);
                    delete dos;
                    return;
                }
                NodePointerCollectionIter it = node->partitionData->allNodes->begin();
                //for (int i = 0; i < numAttackers; i++)
                //{
                int count = 0;
                while (it != node->partitionData->allNodes->end())
                {
                    currentNode = *it;
                    sourceNodeId = currentNode->nodeId;
                    if (victimNodeId == sourceNodeId)
                    {
                        it++;
                        continue;
                    }

                    dos->sourceIdList.push_back(sourceNodeId);
                    count++;
                    if (count == numAttackers)
                    {
                        break;
                    }
                    it++;
                }

            }
        
            if (fromGUI)
            {
                //pktInterval = APP_DOS_PACKET_INTERVAL;
                packetSize = APP_DOS_PACKET_SIZE;
                packetCount = 0;
                int numValues = sscanf(next, "%s %d %s %s",
                    attackString,
                    &victimPort,
                    packetIntervalStr,
                    durationStr);
                if (numValues != MIN_DOS_GUI_PARAMS)
                {
                    if (fromGUI)
                    {
                        delete dos;
                    }
                    AppDosInputError(fromGUI);
                    return;
                }                  
                sTime = 0;
                eTime = 0;
                dTime = TIME_ConvertToClock(durationStr);
                IO_ConvertStringToUpperCase(attackString);                
            }
            else
            {
#define MIN_DOS_PARAMS 7
                //next holds the remaining string
                //use sscanf to parse this now
                int numValues = sscanf(next, "%s %d %d %d %s %s %s",
                    attackString,
                    &victimPort,
                    &packetCount,
                    &packetSize,
                    packetIntervalStr,                
                    startTimeStr,
                    endTimeStr);
                if (numValues != MIN_DOS_PARAMS)
                {
                    if (fromGUI)
                    {
                        delete dos;
                    }
                    AppDosInputError(fromGUI);
                    return;
                }
                sTime = TIME_ConvertToClock(startTimeStr);
                eTime = TIME_ConvertToClock(endTimeStr);
                if (eTime == 0)
                {
                    eTime = TIME_ReturnMaxSimClock(victimNode) + 1;
                    dTime = 0;
                }
                else
                {
                    dTime = eTime - sTime;
                }
            }
            pktInterval = TIME_ConvertToClock(packetIntervalStr);

            /* Check to make sure the number of cbr items is a correct value. */
            if (packetCount < 0)
            {
                char errorString[MAX_STRING_LENGTH]; 
                sprintf(errorString, "[DOS] DOS to victim node %d: Number of items to send needs"
                    " to be >= 0\n", victimNodeId);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }

            /* Make sure that packet is within max limit. */
            if (packetSize > APP_MAX_DATA_SIZE)
            {
                char errorString[MAX_STRING_LENGTH]; 
                sprintf(errorString, "[DOS] DOS to victim node %d: Item size needs to be &lt;= %d.\n",
                    victimNodeId, APP_MAX_DATA_SIZE);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }

            /* Make sure interval is valid. */
            if (pktInterval <= 0)
            {
                char errorString[MAX_STRING_LENGTH]; 
                sprintf(errorString, "[DOS] DOS to victim node %d: Interval needs to be > than 0.\n",
                    victimNodeId);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            /* Make sure start time is valid. */
            if (sTime < 0)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] DOS to victim node %d: Start time needs to be >= 0.\n",
                    victimNodeId);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }

            /* Check to make sure the end time is a correct value. */
            if (!((eTime > sTime) || (eTime == 0)))
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] DOS to victim node %d: End time needs to be > than"
                    "start time or equal to 0.\n", victimNodeId);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            if (dTime < 0)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] DOS to victim node %d: Duration needs to be > than"
                    "or equal to 0.\n", victimNodeId);
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            if (! strcmp(attackString, "BASIC"))
            {
                attackType = AppDOSAttacker::ATTACK_BASIC;
            }
            else if (! strcmp(attackString, "SYN"))
            {
                attackType = AppDOSAttacker::ATTACK_SYN;
            }
            else if (! strcmp(attackString, "FRAG"))
            {
                attackType = AppDOSAttacker::ATTACK_FRAG;
            }
            else
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] Attack type missing or specified wrongly:"
                    " The attack type must be BASIC, SYN or FRAG \n\t");
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            //get the node list
            list<int>::iterator it;
            if (dos->sourceIdList.size() == 0)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] No valid attackers have been specified, "
                    "change attacker list and try again \n\t");
                delete dos;
                ERROR_SmartReportError(errorString, !fromGUI);
                return;
            }
            dos->instanceId = AppDOSVictimGetNewInstanceId(victimNode);
            dos->uniqueId = victimNode->appData.uniqueId++;
            dos->destPort = victimPort;
            APP_RegisterNewApp(victimNode, APP_DOS_VICTIM, dos);


            for (it = dos->sourceIdList.begin(); it != dos->sourceIdList.end(); it++)
            {
                sourceNodeId = *it;
                Node* srcNode = NULL;
                //srcNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash, sourceNodeId);
                BOOL nodeFound = PARTITION_ReturnNodePointer(
                        node->partitionData,     
                        &srcNode,
                        sourceNodeId,
                        FALSE /* do not retreive node pointer from remote partitions */);
#ifdef PARALLEL
                if (!nodeFound)
                {
                    if (!PARTITION_ReturnNodePointer(
                            node->partitionData,     
                            &srcNode,
                            sourceNodeId,
                            TRUE /* retreive node pointer from remote partitions */))
                    {
                        char errorString[MAX_STRING_LENGTH];
                        sprintf(errorString, "[DOS] Invalid Attacker Specified: "
                            "Attacker node %d does not exist!, Ignoring this attacker\n", sourceNodeId);
                        ERROR_SmartReportError(errorString, 0);
                        continue;
                    }

                    //initialize at remote node by sending a message
                    Message* dosInitMessage;
                    dosInitMessage = MESSAGE_Alloc(srcNode,
                        APP_LAYER,
                        APP_DOS_ATTACKER,
                        MSG_DOS_AttackerInit);

                    AppDOSAttacker *dosInfo;
                    MESSAGE_InfoAlloc(srcNode, dosInitMessage, sizeof(AppDOSAttacker));
                    dosInfo = (AppDOSAttacker*)MESSAGE_ReturnInfo(dosInitMessage);

                    dosInfo->attackType = attackType;
                    dosInfo->instanceId = dos->instanceId;
                    dosInfo->victimAddress = victimAddr;
                    dosInfo->packetCount = packetCount;
                    dosInfo->packetSize = packetSize;
                    dosInfo->packetInterval = pktInterval;
                    dosInfo->startTime = sTime;
                    dosInfo->endTime = eTime;
                    dosInfo->duration = dTime;
                    dosInfo->victimPort = victimPort;
                    MESSAGE_RemoteSendSafely(srcNode,
                        sourceNodeId,
                        dosInitMessage,
                        0);
                    continue;
                }
#endif
                if (nodeFound ==  TRUE)
                {
                    AppDosAttackerInitialize(srcNode,
                        attackType,
                        sourceNodeId,
                        victimAddr,
                        packetCount,
                        packetSize,
                        pktInterval,
                        sTime,
                        eTime,
                        dTime,
                        victimPort,
                        dos->instanceId);
                }
            }
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_DOS_StopVictim:
        {
            Node *victimNode;
            if (node->nodeId == msg->originatingNodeId)
            {
                //this is the sigint node so no need to do anything
                victimNode = node;
            }
            else
            {
                //When running in multiple partitions, 
                //the GUI will send a message to the first node 
                victimNode = MAPPING_GetNodePtrFromHash(node->partitionData->nodeIdHash, 
                    msg->originatingNodeId);
                if (victimNode == NULL)
                {
                    printf("[DOS] ERROR: Node %d does not exist!\n",
                        msg->originatingNodeId);
                    MESSAGE_Free(node, msg);
                    return;

                }
            }
            AppDOSVictimStop(victimNode);
            MESSAGE_Free(node, msg);
            break;
        }
        default:
        // discard everything else
        MESSAGE_Free(node, msg);
    }
}
void AppDosAttackerProcessEvent(Node* node, Message* msg)
{
    switch (msg->eventType)
    {
        case MSG_APP_TimerExpired:
        {
            //victimaddress should also be stored here, we need to retrieve it
            int instanceId = MESSAGE_GetInstanceId(msg);
            NodeAddress *info = (NodeAddress *) MESSAGE_ReturnInfo(msg);
            AppDOSAttacker* dos = AppDOSAttackerGetApp(node, instanceId, *info);

            if (dos == NULL)
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "[DOS] INTERNAL ERROR: Cannot locate DOS app on node for instanceId=%d.",
                    node->nodeId,
                    instanceId);
                ERROR_ReportError(errorString);
            }

            switch (dos->attackType)
            {
               case AppDOSAttacker::ATTACK_BASIC:
               {
                    Message *udpmsg = APP_UdpCreateMessage(
                        node,
                        dos->myAddress.interfaceAddr.ipv4,
                        APP_DOS_ATTACKER,
                        dos->victimAddress.interfaceAddr.ipv4,
                        dos->victimPort,
                        TRACE_UDP,
                        APP_DEFAULT_TOS);

                    APP_AddVirtualPayload(node, udpmsg, dos->packetSize);

                    APP_AddInfo(node, udpmsg, 
                        &dos->packetSize, sizeof(int), INFO_TYPE_DataSize);

                    APP_UdpSend(node, udpmsg, PROCESS_IMMEDIATELY);

                    if (dos->stats->GetMessagesSent().GetValue(node->getNodeTime()) == 0)
                    {                         
                        dos->stats->SessionStart(node);
                    }
                    dos->stats->AddMessageSentDataPoints(
                        node,
                        udpmsg,
                        0,
                        dos->packetSize,
                        0,
                        STAT_Unicast);
                    dos->stats->AddFragmentSentDataPoints(
                        node,
                        dos->packetSize,
                        STAT_Unicast);                        

                    dos->udpPacketsSent ++;
                    if (dos->firstPacketAt == 0) {
                        dos->firstPacketAt = node->getNodeTime();
                        printf("[DOS] DOS session started from node %d to victim node %x\n",
                        node->nodeId, dos->victimAddress.interfaceAddr.ipv4);
                    }
                    dos->lastPacketAt = node->getNodeTime();

                    break;
              }
              case AppDOSAttacker::ATTACK_SYN:
              {
                    APP_TcpOpenConnection(
                        node,
                        APP_DOS_ATTACKER,
                        dos->myAddress,
                        node->appData.nextPortNum++,
                        dos->victimAddress,
                        dos->victimPort,
                        0,  //  unique id
                        PROCESS_IMMEDIATELY);

                    dos->tcpSYNSent ++;
                    if (dos->firstPacketAt == 0) {
                        dos->firstPacketAt = node->getNodeTime();
                        printf("[DOS] DOS session started from node %d to victim node %x\n",
                        node->nodeId, dos->victimAddress.interfaceAddr.ipv4);
                    }
                    dos->lastPacketAt = node->getNodeTime();
                    break;
              }
              case AppDOSAttacker::ATTACK_FRAG:
              {
                    Message* fragMsg = MESSAGE_Alloc(node, 0, 0, 0);
                    // fragMsgSize: create room for IP and below headers
                    static const int fragMsgSize = 64; 
                    MESSAGE_PacketAlloc(node, fragMsg, fragMsgSize, TRACE_DOS);
                    MESSAGE_AddVirtualPayload(node, fragMsg, dos->packetSize);
                    AddIpHeader(
                        node,
                        fragMsg,
                        dos->myAddress.interfaceAddr.ipv4,
                        dos->victimAddress.interfaceAddr.ipv4,
                        APP_DEFAULT_TOS,
                        IPPROTO_TCP,
                        fragMsgSize);

                    IpHeaderType* ipHeader = (IpHeaderType*) fragMsg->packet;
                    //Generating a fragment, setting morefrag and offset to non-zero value
                    //in order to generate one that is not the first fragment
                    IpHeaderSetIpMoreFrag(&ipHeader->ipFragment, TRUE);
                    // We don't really care about actual value, as along it is not zero
                    static const int nonZeroFragOffset = 100;
                    IpHeaderSetIpFragOffset(&ipHeader->ipFragment, nonZeroFragOffset);

                    int interfaceIndex =
                        NetworkIpGetInterfaceIndexFromAddress(
                        node,
                        dos->myAddress.interfaceAddr.ipv4);

                    RoutePacketAndSendToMac(
                        node,
                        fragMsg,
                        CPU_INTERFACE,
                        interfaceIndex,
                        ANY_IP);

                    dos->fragmentsSent ++;
                    if (dos->firstPacketAt == 0) {
                        dos->firstPacketAt = node->getNodeTime();
                        printf("[DOS] DOS session started from node %d to victim node %x\n",
                        node->nodeId, dos->victimAddress.interfaceAddr.ipv4);
                    }
                    dos->lastPacketAt = node->getNodeTime();

                    break;
              }
            }


            if (((dos->packetCount > 1) &&
                (node->getNodeTime() + dos->packetInterval
                < dos->endTime)) ||
                ((dos->packetCount == 0) &&
                (node->getNodeTime() + dos->packetInterval
                < dos->endTime)) ||
                ((dos->packetCount > 1) &&
                (dos->endTime == 0)) ||
                ((dos->packetCount == 0) &&
                (dos->endTime == 0)))
            {
                 MESSAGE_Send(node, msg, dos->packetInterval);
                 if (dos->packetCount > 0)
                 {
                     dos->packetCount--;
                 }
            }
            /*if ((node->getNodeTime() + dos->packetInterval) < dos->endTime)
            {
                MESSAGE_Send(node, msg, dos->packetInterval);
            }*/
            else
            {
                MESSAGE_Free(node, msg);
                printf("[DOS] DOS session ended from node %d to victim node %x\n",
                        node->nodeId, dos->victimAddress.interfaceAddr.ipv4);
            }

            break;
        }
        case MSG_DOS_AttackerInit:
        {
            AppDOSAttacker* dosInfo;
            dosInfo = (AppDOSAttacker*)MESSAGE_ReturnInfo(msg);

            AppDosAttackerInitialize(node,
                dosInfo->attackType,
                node->nodeId,
                dosInfo->victimAddress,
                dosInfo->packetCount,
                dosInfo->packetSize,
                dosInfo->packetInterval,
                dosInfo->startTime,
                dosInfo->endTime,
                dosInfo->duration,
                dosInfo->victimPort,
                dosInfo->instanceId
                );
            MESSAGE_Free(node, msg);
            break;
        }
        case MSG_DOS_StopAttacker:
        {
            int instanceId = MESSAGE_GetInstanceId(msg);
            NodeAddress *info = (NodeAddress *) MESSAGE_ReturnInfo(msg);
            AppDOSAttackerStop(node, instanceId, *info);
            MESSAGE_Free(node, msg);
            break;
        }
        default:
        // discard everything else
        MESSAGE_Free(node, msg);
    }
}

void DOS_ProcessEvent(Node* node, Message* msg)
{
    short protocolType;
    protocolType = APP_GetProtocolType(node,msg);
    switch(protocolType)
    {
        case APP_DOS_VICTIM:
        {
            AppDosVictimProcessEvent(node, msg);
            break;
        }
        case APP_DOS_ATTACKER:
        {
            AppDosAttackerProcessEvent(node, msg);
            break;
        }
    }
}

bool DOS_Drop(Node *node, Message *msg)
{
    if (msg->eventType == MSG_APP_FromTransport)
    {
        UdpToAppRecv *info;
        info = (UdpToAppRecv *) MESSAGE_ReturnInfo(msg);
        if (info == NULL)
        {
            //do nothing
            return false;
        }
        else
        {
            //check if this message's source port is dos
            if (info->sourcePort == APP_DOS_ATTACKER)
            {
                AppDOSVictim* dos = AppDOSVictimGetApp(node, info->destPort);
                ERROR_Assert(dos != NULL, "Could not find DOS app");
                if (dos->stats == NULL)
                {
                    dos->stats = new STAT_AppStatistics(
                        node,
                        "dosVictim",
                        STAT_Unicast,
                        STAT_AppReceiver,
                        "DOS Victim");
                    dos->stats->Initialize(
                        node,
                        info->sourceAddr,
                        info->destAddr,
                        STAT_AppStatistics::GetSessionId(msg),
                        dos->uniqueId);
                    dos->stats->SessionStart(node);
                }

                dos->stats->AddFragmentReceivedDataPoints(
                    node,
                    msg,
                    MESSAGE_ReturnPacketSize(msg),
                    STAT_Unicast);

                dos->stats->AddMessageReceivedDataPoints(
                    node,
                    msg,
                    0,
                    MESSAGE_ReturnPacketSize(msg),
                    0,
                    STAT_Unicast);                      

                //MESSAGE_Free(node, msg);
                return true;
            }
        }

    }
    return false;
}
