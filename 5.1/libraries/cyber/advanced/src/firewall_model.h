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

#ifndef FIREWALL_MODEL_H_
#define FIREWALL_MODEL_H_

class FirewallTable;

class FirewallModel
{
public:
    // Tables
    static const int MANGLE_TABLE = 0;
    static const int NAT_TABLE = 1;
    static const int RAW_TABLE = 2;
    static const int FILTER_TABLE = 3;
    static const int MAX_TABLES = 4;

    // Actions (externally visible)
    static const int FIREWALL_ACTION_UNDEFINED = 0x0;
    static const int FIREWALL_ACTION_ACCEPT = 0x1000;
    static const int FIREWALL_ACTION_DROP = 0x1001;
    static const int FIREWALL_ACTION_REJECT = 0x1002;

    FirewallModel(Node* node);

    void init(const NodeInput* nodeInput);
    void finalize();
    void print();

    bool isFirewallOn();
    void turnFirewallOn();
    void turnFirewallOff();

    void processCommand(const char* command);

    int inspect(
            int table,
            const char* chain,
            Message* msg,
            int inInterface,
            int outInterface);
    static void processEvent(Node *node, Message *msg);


private:
    Node* node;
    bool firewallEnabled;
    FirewallTable* tables[FirewallModel::MAX_TABLES];

    // this should ideally be in FirewallTable or FirewallChain
    // will refactor later
    UInt64 filterTableInputChainPacketInspected;
    UInt64 filterTableInputChainPacketDropped;
    UInt64 filterTableOutputChainPacketInspected;
    UInt64 filterTableOutputChainPacketDropped;
    UInt64 filterTableForwardChainPacketInspected;
    UInt64 filterTableForwardChainPacketDropped;
};


#endif /* FIREWALL_MODEL_H_ */
