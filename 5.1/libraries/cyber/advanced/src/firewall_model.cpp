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
#include "partition.h"
#include "firewall_model.h"
#include "firewall_table.h"

FirewallModel::FirewallModel(Node* node)
{
    this->node = node;
    firewallEnabled = false;

    // statistics
    filterTableInputChainPacketInspected = 0;
    filterTableInputChainPacketDropped = 0;
    filterTableOutputChainPacketInspected = 0;
    filterTableOutputChainPacketDropped = 0;
    filterTableForwardChainPacketInspected = 0;
    filterTableForwardChainPacketDropped = 0;
}

void FirewallModel::init(const NodeInput* cyberInput)
{
    char firstToken[MAX_STRING_LENGTH];
    char secondToken[MAX_STRING_LENGTH];

    for (int i = 0; i < cyberInput->numLines; ++i)
    {
        sscanf(cyberInput->inputStrings[i], "%s %s", firstToken, secondToken);

        if (strcmp(firstToken, "FIREWALL") == 0)
        {
            int nodeId = atoi(secondToken);
            if (nodeId == node->nodeId)
            {
                turnFirewallOn();
                processCommand(cyberInput->inputStrings[i]);
            }
        }
    }
}

void FirewallModel::finalize()
{
    if (node->networkData.networkStats != TRUE) {
        return;
    }

    if (tables[FirewallModel::FILTER_TABLE] == NULL) {
        return;
    }

    char buf[MAX_STRING_LENGTH];

    sprintf(buf, "INPUT Chain Number of Packets Inspected = ""%" TYPES_64BITFMT "u",
            filterTableInputChainPacketInspected);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

    sprintf(buf, "INPUT Chain Number of Packets Dropped = ""%" TYPES_64BITFMT "u",
            filterTableInputChainPacketDropped);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

    sprintf(buf, "OUTPUT Chain Number of Packets Inspected = ""%" TYPES_64BITFMT "u",
            filterTableOutputChainPacketInspected);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

    sprintf(buf, "OUTPUT Chain Number of Packets Dropped = ""%" TYPES_64BITFMT "u",
            filterTableOutputChainPacketDropped);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

    sprintf(buf, "FORWARD Chain Number of Packets Inspected = ""%" TYPES_64BITFMT "u",
            filterTableForwardChainPacketInspected);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

    sprintf(buf, "FORWARD Chain Number of Packets Dropped = ""%" TYPES_64BITFMT "u",
            filterTableForwardChainPacketDropped);
    IO_PrintStat(node, "Network", "Firewall", ANY_DEST, -1, buf);

}

void FirewallModel::print()
{
    printf("NODE %d\n", node->nodeId);
    for (int i = 0; i < MAX_TABLES; i++)
    {
        if (tables[i]) {
            tables[i]->print();
        }
    }
}

bool FirewallModel::isFirewallOn()
{
    return firewallEnabled;
}

void FirewallModel::turnFirewallOn()
{
    if (firewallEnabled) {
        return;
    }


    // The firewall is enabled on this node
    firewallEnabled = true;

    // Create the tables
    tables[MANGLE_TABLE] = NULL; // do not create this table
    tables[NAT_TABLE] = NULL; // do not create this table
    tables[RAW_TABLE] = NULL; // do not create this table
    tables[FILTER_TABLE] = new FirewallTable(node, "FILTER");
    tables[FILTER_TABLE]->init();

}

void FirewallModel::turnFirewallOff()
{
    // do not delete existing rules; just disable firewall
    firewallEnabled = false;
}

void FirewallModel::processEvent(Node *node, Message *msg)
{
    char *rule;
    rule = (char *)MESSAGE_ReturnInfo(msg);
    Node *firewallNode;

    BOOL nodeFound = PARTITION_ReturnNodePointer(
                        node->partitionData,     
                        &firewallNode,
                        msg->originatingNodeId,
                        FALSE /* do not retreive node pointer from remote partitions */);
    if (nodeFound == FALSE)
    {
        printf("Node %d does not exist!\n", msg->originatingNodeId);
        assert(FALSE);
    }
    if (firewallNode->firewallModel == NULL)
    {
        firewallNode->firewallModel = new FirewallModel(firewallNode);
    }
    firewallNode->firewallModel->turnFirewallOn();
    firewallNode->firewallModel->processCommand(rule);
    MESSAGE_Free(node,msg);
}

void FirewallModel::processCommand(const char* command)
{
    char chainName[MAX_STRING_LENGTH];
    char entry[MAX_STRING_LENGTH];
    int currentTable = FILTER_TABLE;
    bool ruleFound = false;
    int ruleAdditionIndex = -1;
    const char* delims = " \t";
    char *ptr;

    strcpy(entry, command);
    // remove the first two tokens ('FIREWALL' and <node-id>)
    strtok(entry, delims);
    strtok(NULL, delims);
    ptr = strtok(NULL, delims);

    while (ptr)
    {
        if (!strcmp(ptr, "--table") || !strcmp(ptr, "-t"))
        {
            ptr = strtok(NULL, delims);
            if (ptr == NULL) {

            }
            if (!IO_CaseInsensitiveStringsAreEqual(ptr, "FILTER", 6))
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Node %d: %s table is not supported:\n%s",
                        node->nodeId,
                        ptr,
                        command);
                ERROR_ReportError(errorString);
            }
        }

        if (!strcmp(ptr, "--new-chain") || !strcmp(ptr, "-N"))
        {
            ptr = strtok(NULL, delims);
            if (ptr == NULL) {
                // todo
            }
            if (!tables[currentTable]->createChain(ptr, false))
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString,
                        "Node %u: Cannot create new chain by name %s:\n%s",
                        node->nodeId,
                        ptr,
                        command);
                ERROR_ReportError(errorString);
            }
        }

        if (!strcmp(ptr, "-A") || !strcmp(ptr, "--append"))
        {
            // read chain name
            ptr = strtok(NULL, delims);
            strcpy(chainName, ptr);
            ruleFound = true;
            ruleAdditionIndex = -1;
            break;
        }

        if (!strcmp(ptr, "-P") || !strcmp(ptr, "--policy"))
        {
            // read chain name
            ptr = strtok(NULL, delims);
            strcpy(chainName, ptr);

            // read policy
            ptr = strtok(NULL, delims);
            if (!strcmp(ptr, "ACCEPT"))
            {
                if (!tables[currentTable]->setDefaultPolicyForChain(
                        FirewallModel::FIREWALL_ACTION_ACCEPT,
                        chainName))
                {
                    char errorString[MAX_STRING_LENGTH];
                    sprintf(errorString, "Node %d: Cannot set policy %s for chain %s:\n%s",
                            node->nodeId,
                            ptr,
                            chainName,
                            command);
                    ERROR_ReportError(errorString);
                }
            }
            else if (!strcmp(ptr, "DROP"))
            {
                if (!tables[currentTable]->setDefaultPolicyForChain(
                        FirewallModel::FIREWALL_ACTION_DROP,
                        chainName))
                {
                    char errorString[MAX_STRING_LENGTH];
                    sprintf(errorString, "Node %d: Cannot set policy %s for chain %s:\n%s",
                            node->nodeId,
                            ptr,
                            chainName,
                            command);
                    ERROR_ReportError(errorString);
                }
            }
            else if (!strcmp(ptr, "REJECT"))
            {
                if (!tables[currentTable]->setDefaultPolicyForChain(
                        FirewallModel::FIREWALL_ACTION_REJECT,
                        chainName))
                {
                    char errorString[MAX_STRING_LENGTH];
                    sprintf(errorString, "Node %d: Cannot set policy %s for chain %s:\n%s",
                            node->nodeId,
                            ptr,
                            chainName,
                            command);
                    ERROR_ReportError(errorString);
                }
            }
            else
            {
                char errorString[MAX_STRING_LENGTH];
                sprintf(errorString, "Node %d: Illegal policy %s:\n%s",
                        node->nodeId,
                        ptr,
                        command);
                ERROR_ReportError(errorString);
            }
        }

        // These options are not support
        if (!strcmp(ptr, "-D")
                || !strcmp(ptr, "--delete")
                || !strcmp(ptr, "-I")
                || !strcmp(ptr, "--insert")
                || !strcmp(ptr, "-R")
                || !strcmp(ptr, "--replace")
                || !strcmp(ptr, "-L")
                || !strcmp(ptr, "--list")
                || !strcmp(ptr, "-F")
                || !strcmp(ptr, "--flush")
                || !strcmp(ptr, "-Z")
                || !strcmp(ptr, "--zero")
                || !strcmp(ptr, "-X")
                || !strcmp(ptr, "--delete-chain")
                || !strcmp(ptr, "-E")
                || !strcmp(ptr, "--rename-chain")
                || !strcmp(ptr, "-h"))
        {
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString, "Node %u: Option %s is not supported:\n%s",
                    node->nodeId,
                    ptr,
                    command);
            ERROR_ReportError(errorString);
        }


        ptr = strtok(NULL, delims);
    }

    if (ruleFound)
    {
        strcpy(entry, command);

        if (!tables[currentTable]->addRuleToChain(
                entry,
                chainName,
                ruleAdditionIndex))
        {
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString, "Node %d: Cannot add rule to chain %s:\n%s\n",
                    node->nodeId,
                    chainName,
                    command);
            ERROR_ReportWarning(errorString);
        }
    }

}

int FirewallModel::inspect(
        int table,
        const char* chain,
        Message* msg,
        int inInterface,
        int outInterface)
{
    if (!tables[table])
    {
        return FIREWALL_ACTION_ACCEPT;
    }

    int response = tables[table]->inspect(chain, msg, inInterface, outInterface);

    // Statistics
    if (table == FirewallModel::FILTER_TABLE)
    {
        if (!strcmp(chain, "INPUT"))
        {
            filterTableInputChainPacketInspected ++;
            if ((response == FirewallModel::FIREWALL_ACTION_DROP)
                    || (response == FirewallModel::FIREWALL_ACTION_REJECT))
            {
                filterTableInputChainPacketDropped ++;
            }
        }
        else if (!strcmp(chain, "OUTPUT"))
        {
            filterTableOutputChainPacketInspected ++;
            if ((response == FirewallModel::FIREWALL_ACTION_DROP)
                    || (response == FirewallModel::FIREWALL_ACTION_REJECT))
            {
                filterTableOutputChainPacketDropped ++;
            }
        }
        if (!strcmp(chain, "FORWARD"))
        {
            filterTableForwardChainPacketInspected ++;
            if ((response == FirewallModel::FIREWALL_ACTION_DROP)
                    || (response == FirewallModel::FIREWALL_ACTION_REJECT))
            {
                filterTableForwardChainPacketDropped ++;
            }
        }
    }

    return response;
}
