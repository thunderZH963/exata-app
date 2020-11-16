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
#include "partition.h"
#include "random.h"
#include "netSnmpAgent.h"
#include "app_netsnmp.h"

/*
 * NAME:        AppNetSnmpAgentInit.
 * PURPOSE:     Initialize a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node,
 *              nodeInput - nodeInput for config file.
 * RETURN:      none.
 */

void
AppNetSnmpAgentInit(Node* node, const NodeInput* nodeInput)
{

#ifdef SNMP_DEBUG
    printf("AppNetSnmpAgentInit:node %d\n",node->nodeId);
#endif
    char snmpInput[MAX_STRING_LENGTH];
    BOOL wasFound;
    // Read in the CONFIG-FILE
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        SNMP_ENABLED,
        &wasFound,
        snmpInput);
    if (wasFound == FALSE || strcmp(snmpInput, "NO") == 0)
    {
        node->isSnmpEnabled = FALSE;
    }
    else
    {
        if (strcmp(snmpInput, "YES") == 0)
        {
            node->isSnmpEnabled = TRUE;
        }
        else
        {
            node->isSnmpEnabled = FALSE;
            ERROR_ReportWarning(
                "Expecting YES or NO for SNMP-ENABLED parameter.\n");
        }
    }
    if (node->isSnmpEnabled == FALSE)
    {
        return;
    }

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SNMP-VERSION",
        &wasFound,
        snmpInput);
    if (wasFound == TRUE)
    {
        if (strcmp(snmpInput, "1") == 0)
        {
            node->snmpVersion = 1;
        }
        else if (strcmp(snmpInput, "2") == 0)
        {
            node->snmpVersion = 2;
        }
        else if (strcmp(snmpInput, "3") == 0)
        {
            node->snmpVersion = 3;
        }
        else
        {
           char errorString[MAX_STRING_LENGTH];
            sprintf(errorString,
                    "Expecting 1/2/3 as SNMP-VERSION "
                    "parameter");
            ERROR_ReportError(errorString);
        }

    }
    else
    {
        //default version
        node->snmpVersion = 1;
    }

    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SNMPD-CONF-FILE",
        &wasFound,
        snmpInput);
    if (wasFound == FALSE)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf (errorString,
                "Parameter SNMPD-CONF-FILE required for SNMPv3");
        ERROR_ReportError(errorString);
    }
    else if (wasFound == TRUE)
    {
        node->snmpdConfigFilePath = (char*)MEM_malloc(strlen(snmpInput)+1);
        memcpy (node->snmpdConfigFilePath, snmpInput, strlen(snmpInput));
        node->snmpdConfigFilePath[strlen(snmpInput)] = '\0';
        int i;
        for (i = strlen(node->snmpdConfigFilePath) - 1; i >= 0; i--)
        {
            if (node->snmpdConfigFilePath[i] == '.')
                break;
        }
        char* ext = node->snmpdConfigFilePath + i;
        if (strcmp(ext, ".conf"))
        {
            char errorString[MAX_STRING_LENGTH];
            sprintf (errorString,
                    "SNMPD-CONF-FILE should be *.conf");
            ERROR_ReportError(errorString);
        }
    }

    node->managerAddress = MAPPING_GetDefaultInterfaceAddressFromNodeId
                            (node, DEFAULT_MANAGER_NODE);
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SNMP-MANAGER-ADDRESS",
        &wasFound,
        snmpInput);
    if (wasFound == TRUE)
    {
        IO_ConvertStringToNodeAddress (snmpInput, &node->managerAddress);
    }

    node->generateTrap = FALSE;
    node->generateInform = FALSE;
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "SNMP-NOTIFICATION-TYPE",
        &wasFound,
        snmpInput);

    if (wasFound == FALSE || strcmp(snmpInput, "NONE") == 0)
    {
        node->generateTrap = FALSE;
        node->generateInform = FALSE;
    }
    else if (strcmp(snmpInput, "TRAP") == 0)
    {
        node->generateTrap = TRUE;
    }
    else if (strcmp(snmpInput, "INFORM") == 0)
    {
        node->generateInform = TRUE;
    }
    else
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf(errorString,
                "Expecting NONE, TRAP or INFORM for SNMP-NOTIFICATION-TYPE "
                "parameter");
        ERROR_ReportError(errorString);
    }

    /* Create an object of class NetSnmpAgent*/
    class NetSnmpAgent* netSnmpAgent = new NetSnmpAgent;
    netSnmpAgent->NetSnmpAgentInit(node);
    node->netSnmpAgent = netSnmpAgent;
    node->SNMP_TRAP_LINKDOWN_counter = -1;

    if ((node->generateTrap == TRUE && node->generateInform == TRUE) ||
        (node->generateTrap == FALSE && node->generateInform == FALSE))
    {
        node->notification_para = SEND_NOTRAP_NOINFORM;
    }
    else if (node->generateTrap == TRUE && node->generateInform == FALSE)
    {
        node->notification_para = (int) SEND_TRAP;
    }
    else if (node->generateTrap == FALSE && node->generateInform == TRUE)
    {
        node->notification_para = SEND_INFORM;
    }

    if (node->notification_para != SEND_NOTRAP_NOINFORM)
    {
        Message*   TrapMsg = MESSAGE_Alloc(node,
                                           APP_LAYER,
                                           APP_SNMP_TRAP,
                                           MSG_SNMPV3_TRAP);


        int* TrapTypeInfo;
        MESSAGE_AddInfo(node, TrapMsg, sizeof(int),INFO_TYPE_SNMPV3);
        TrapTypeInfo = (int*)MESSAGE_ReturnInfo(TrapMsg,
            INFO_TYPE_SNMPV3);
        *TrapTypeInfo = SNMP_TRAP_COLDSTART;
        MESSAGE_Send(node, TrapMsg,0);
    }

    APP_RegisterNewApp(node, APP_SNMP_AGENT, node->netSnmpAgent);
    APP_InserInPortTable(node, APP_SNMP_AGENT, APP_SNMP_AGENT);
}


/*
 * NAME:        AppLayerNetSnmpAgent.
 * PURPOSE:     Models the behaviour of NetSnmpAgent on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node,
 *              msg - message received by the layer
 * RETURN:      none.
 */

void
AppLayerNetSnmpAgent(Node* node, Message* msg)
{
    char error[MAX_STRING_LENGTH];

    switch (msg->eventType)
    {
        case MSG_SNMPV3_TRAP:
        {
         if (node->isSnmpEnabled != 0)
         {
           if (msg->infoArray.size() > 0)
           {
            for (int i = 0; i < (int) msg->infoArray.size(); i++)
            {
                MessageInfoHeader* infor;
                infor = &(msg->infoArray[i]);
                if (infor->infoType == INFO_TYPE_SNMPV3)
                {
                    int* TrapTypeInfo = (int*)infor->info;
                    if (node->partitionData->isEmulationMode)
                    node->netSnmpAgent->send_trap(node,msg,
                                                *TrapTypeInfo);
                    break;
                }
            }
           }
         }
         break;
        }

        case MSG_APP_FromTransport:
        {
        if (node->isSnmpEnabled != 0)
        {
            UdpToAppRecv* info1;
            info1 = (UdpToAppRecv*) MESSAGE_ReturnInfo(msg);
            node->netSnmpAgent->info = (UdpToAppRecv*)
                                    MESSAGE_ReturnInfo(msg);
            static int debug_count = 0;
            unsigned int    interfaceId;
            interfaceId = MAPPING_GetInterfaceIdForDestAddress(
                node,
                node->nodeId,
                GetIPv4Address(node->netSnmpAgent->info->destAddr));

            node->netSnmpAgent->setCurrentPacket((unsigned char*)
                                    msg->packet, msg->packetSize);
            node->netSnmpAgent->agent_check_and_process(1);
            debug_count++;
            break;
        }
        break;
        }

        default:
        {
            char buf[MAX_STRING_LENGTH];

            TIME_PrintClockInSecond(node->getNodeTime(), buf);
            sprintf(error, "SNMP agent: At time %sS, node %d received "
                    "message of unknown type "
                    "%d\n", buf, node->nodeId, msg->eventType);
            ERROR_ReportError(error);
        }
    }

    MESSAGE_Free(node, msg);
}

/*
 * NAME:        printQualNetError.
 * PURPOSE:     Prints the Snmp errors report.
 * PARAMETERS:  node - pointer to the node,
 *              errorString - the error string to be printed.
 * RETURN:      none.
 */

void
printQualNetError(Node* node, char* errorString)
{
    char buf[MAX_STRING_LENGTH];
    char error[MAX_STRING_LENGTH];
    TIME_PrintClockInSecond(node->getNodeTime(), buf, node);
    sprintf(error, "SNMP agent: at time %sS, node %d  %s",
                    buf, node->nodeId, errorString);
    ERROR_ReportError(error);
}


/*
 * NAME:        AppNetSnmpAgentFinalize.
 * PURPOSE:     Collect statistics of a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */


void
AppNetSnmpAgentFinalize(Node* node)
{
#ifdef SNMP_DEBUG
    printf("AppNetSnmpAgentFinalize:node %d\n",node->nodeId);
#endif

    if (node->appData.appStats == TRUE)
    {
        AppSnmpAgentPrintStats(node);
    }

    if (node->netSnmpAgent)
    {
        node->netSnmpAgent->~NetSnmpAgent();
        free(node->netSnmpAgent);
    }
}

/*
 * NAME:        AppSnmpAgentPrintStats.
 * PURPOSE:     Print statistics of a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */

void
AppSnmpAgentPrintStats(Node* node)
{
    char buf[MAX_STRING_LENGTH];
    char app_buf[MAX_STRING_LENGTH];

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[9]);
    sprintf(buf, "Total in packets = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);


    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[10]);
    sprintf(buf, "Total out packets = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[23]);
    sprintf(buf, "Total Get requests = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[24]);
    sprintf(buf, "Total GetNext requests = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[43]);
    sprintf(buf, "Total GetBulk requests = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[36]);
    sprintf(buf, "Total responses = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[37]);
    sprintf(buf, "Total traps sent = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[40]);
    sprintf(buf, "Total informs sent = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

    sprintf(app_buf,"%d",node->netSnmpAgent->statistics[39]);
    sprintf(buf, "Total inform ack received = %s",app_buf);
    IO_PrintStat(
        node,
        "Application",
        "Snmp Agent",
        ANY_DEST,
        APP_SNMP_AGENT,
        buf);

}
