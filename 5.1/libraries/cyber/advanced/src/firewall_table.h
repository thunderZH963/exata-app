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

#ifndef FIREWALL_TABLE_H_
#define FIREWALL_TABLE_H_

class FirewallChain;

struct ltstr
{
  bool operator()(const char* s1, const char* s2) const
  {
    return strcmp(s1, s2) < 0;
  }
};

typedef std::map<const char*, FirewallChain*, ltstr> FirewallChainMap;

class FirewallTable {
public:
    static const int FIREWALL_TABLE_JUMP_CHAIN = 0x2000;
    static const int FIREWALL_TABLE_GOTO_CHAIN = 0x2001;
    static const int FIREWALL_TABLE_RETURN = 0x2002;


    FirewallTable(Node* node, const char* name);
    ~FirewallTable();
    void init();
    void finalize();
    void print();

    bool createChain(const char* name, bool isPredefined);
    bool setDefaultPolicyForChain(int policy, const char* name);
    bool addRuleToChain(
            const char* ruleStr,
            const char* name,
            int index);

    int inspect(
            const char* chain,
            Message* msg,
            int inInterface,
            int outInterface);

private:
    FirewallChainMap chains;
    Node* node;
    string tableName;
};

#endif /* FIREWALL_TABLE_H_ */
