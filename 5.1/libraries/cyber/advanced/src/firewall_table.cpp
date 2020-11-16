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
#include "firewall_table.h"
#include "firewall_chain.h"

FirewallTable::FirewallTable(Node* node, const char* name) {
    this->node = node;
    this->tableName.assign(name);
}

FirewallTable::~FirewallTable() {
    // TODO Auto-generated destructor stub
}

void FirewallTable::init()
{
    // Create pre-defined chains
    createChain("INPUT", true);
    createChain("OUTPUT", true);
    createChain("FORWARD", true);
}

void FirewallTable::print()
{
    printf("TABLE %s\n", tableName.c_str());
    FirewallChainMap::iterator it;

    for (it = chains.begin(); it != chains.end(); ++it) {
        it->second->print();
    }
}

bool FirewallTable::createChain(const char* chainName, bool isPredefined)
{
    FirewallChain* chain;

    // Check if there is a chain already with this name
    FirewallChainMap::iterator it;
    it = chains.find(chainName);
    if (it != chains.end()) {
        return false;
    }

    // insert new chain
    chain = new FirewallChain(node, chainName, isPredefined, this);
    chains.insert(std::pair<const char*, FirewallChain*>(chainName, chain));
    return true;
}

bool FirewallTable::setDefaultPolicyForChain(
        int policy,
        const char* chainName)
{
    FirewallChain* chain;

    // Check if a chain exists by this name
    FirewallChainMap::iterator it;
    it = chains.find(chainName);
    if (it == chains.end()) {
        return false;
    }

    chain = it->second;
    chain->setDefaultPolicy(policy);

    return true;
}

bool FirewallTable::addRuleToChain(
        const char* ruleStr,
        const char* chainName,
        int index)
{
    FirewallChain* chain;

    // Check if a chain exists by this name
    FirewallChainMap::iterator it;
    it = chains.find(chainName);
    if (it == chains.end()) 
    {
        return false;
    }

    chain = it->second;
    if (chain->addRule(ruleStr, index))
    {
        return true;
    }
    else
    {
        return false;
    }
}

int FirewallTable::inspect(
        const char* chainName,
        Message* msg,
        int inInterface,
        int outInterface)
{
    FirewallChain* chain;
    int response;
    char jumpChainName[MAX_STRING_LENGTH];

    // Check if a chain exists by this name
    FirewallChainMap::iterator it;
    it = chains.find(chainName);
    if (it == chains.end()) 
    {
        return false;
    }

    chain = it->second;
    chain->inspect(
            msg,
            inInterface,
            outInterface,
            &response,
            jumpChainName);

    switch (response)
    {
    case FirewallModel::FIREWALL_ACTION_ACCEPT:
    case FirewallModel::FIREWALL_ACTION_DROP:
    case FirewallModel::FIREWALL_ACTION_REJECT:
    {
        return response;
    }
    case FIREWALL_TABLE_GOTO_CHAIN:
    {
        // Verify that the new chain exists, and is not built-in
        it = chains.find(jumpChainName);
        if (it == chains.end())
        {
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString, "Chain %s not found", jumpChainName);
            ERROR_ReportError(errorString);
        }

        if (it->second->isPredefinedChain())
        {
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString, "Cannot jump to built-in %s chain", jumpChainName);
            ERROR_ReportError(errorString);
        }

        // We do not come back to this table again
        int subResponse;
        subResponse = inspect(jumpChainName, msg, inInterface, outInterface);
        if (subResponse == FirewallModel::FIREWALL_ACTION_UNDEFINED)
        {
            if (chain->isPredefinedChain())
            {
                return chain->getDefaultPolicy();
            }
        }
        return subResponse;
    }
    case FIREWALL_TABLE_RETURN:
    {
        break;
    }
    }

    // No rule matched; so return default policy (if built-in chain)
    if (chain->isPredefinedChain())
    {
        return chain->getDefaultPolicy();
    }

    return FirewallModel::FIREWALL_ACTION_UNDEFINED;
}
