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
#include "firewall_model.h"
#include "firewall_table.h"
#include "firewall_chain.h"
#include "firewall_rule.h"

FirewallChain::FirewallChain(
        Node* node,
        const char* name,
        bool isPredefined,
        FirewallTable* table)
{
    this->node = node;
    strcpy(this->name, name);
    defaultPolicy = FirewallModel::FIREWALL_ACTION_ACCEPT;
    this->isPredefined = isPredefined;
    parentTable = table;
}

FirewallChain::~FirewallChain()
{

}

bool FirewallChain::isPredefinedChain()
{
    return isPredefined;
}

void FirewallChain::setDefaultPolicy(int policy)
{
    defaultPolicy = policy;
}

int FirewallChain::getDefaultPolicy()
{
    return defaultPolicy;
}

bool FirewallChain::addRule(const char* ruleStr, int index)
{
    FirewallRule* rule = new FirewallRule(node);
    bool success = false;
    success = rule->parse(ruleStr, this->name);

    if (!success)
        return false;

    if (index >= rules.size()) {
        index = -1;
    }

    if (index == -1) {
        rules.push_back(rule);
    } else {
        rules.insert(rules.begin() + index, rule);
    }
    return true;
}


void FirewallChain::inspect(
        Message* msg,
        int inInterface,
        int outInterface,
        int* response,
        char* jumpChainName)
{
    FirewallRule* rule;
    std::vector<FirewallRule*>::iterator it;

    for (it = rules.begin(); it != rules.end(); ++it)
    {
        rule = *it;
        bool matched = rule->match(
                msg,
                inInterface,
                outInterface,
                response,
                jumpChainName);

        // if not matched, try the next rule
        if (!matched) {
            continue;
        }

        // If this is a terminating match, return from here
        switch (*response)
        {
        case FirewallModel::FIREWALL_ACTION_ACCEPT:
        case FirewallModel::FIREWALL_ACTION_DROP:
        case FirewallModel::FIREWALL_ACTION_REJECT:
        case FirewallTable::FIREWALL_TABLE_GOTO_CHAIN:
        case FirewallTable::FIREWALL_TABLE_RETURN:
        {
            return;
        }
        case FirewallTable::FIREWALL_TABLE_JUMP_CHAIN:
        {
            int subResponse;
            subResponse = parentTable->inspect(
                    jumpChainName,
                    msg,
                    inInterface,
                    outInterface);
            if (subResponse != FirewallModel::FIREWALL_ACTION_UNDEFINED) {
                *response = subResponse;
                return;
            }
            break;
        }
        }

        // If this is a non-terminating match, request my parent classes to handle it
        // TODO: handle cases like LOG, PSI etc
    }

    *response = defaultPolicy;
}

void FirewallChain::print()
{
    printf("Chain %s (default: ", name);
    switch (defaultPolicy)
    {
    case FirewallModel::FIREWALL_ACTION_ACCEPT:
        printf("ACCEPT)\n");
        break;
    case FirewallModel::FIREWALL_ACTION_DROP:
        printf("DROP)\n");
        break;
    case FirewallModel::FIREWALL_ACTION_REJECT:
        printf("REJECT)\n");
        break;
    }

    std::vector<FirewallRule*>::iterator it;

    for (it = rules.begin(); it != rules.end(); ++it)
    {
        (*it)->print();
    }
}
