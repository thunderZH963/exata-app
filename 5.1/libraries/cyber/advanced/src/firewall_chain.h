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

#ifndef FIREWALL_CHAIN_H_
#define FIREWALL_CHAIN_H_

class FirewallRule;

class FirewallChain {
public:
    FirewallChain(
            Node* node,
            const char* name,
            bool isPredefined,
            FirewallTable* table);
    ~FirewallChain();

    bool isPredefinedChain();
    int getDefaultPolicy();
    void setDefaultPolicy(int policy);
    bool addRule(const char* ruleStr, int index);

    void print();

    void inspect(
            Message* msg,
            int inInterface,
            int outInterface,
            int* response,
            char* jumpChainName);


private:
    int defaultPolicy;
    char name[MAX_STRING_LENGTH];
    Node* node;
    std::vector<FirewallRule*> rules;
    bool isPredefined;
    FirewallTable* parentTable;

};

#endif /* FIREWALL_CHAIN_H_ */
