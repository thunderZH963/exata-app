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

#ifndef FIREWALL_RULE_H_
#define FIREWALL_RULE_H_

class FirewallRule
{
public:
    FirewallRule(Node* node);
    bool parse(const char* str, const char* chainName);
    bool match(
            const Message* msg,
            int inInterface,
            int outInterface,
            int* action,
            char* jumpChain);

    void print();

    void runTestCases();

private:
    // -p option
    int protocol;

    // -s option
    NodeAddress srcAddress;
    NodeAddress srcMask;

    // -d option
    NodeAddress dstAddress;
    NodeAddress dstMask;

    // -i option
    int inInterfaceIndex;

    // -o option
    int outInterfaceIndex;

    // -f option
    bool fragment;

    // --sport option
    int sportBegin;
    int sportEnd;

    // --dport option
    int dportBegin;
    int dportEnd;

    // --tcp-flags option
    int tcpFlagsCheckMask;
    int tcpFlagsSetMask;

    // --tcp-options
    int tcpOption;

    // -m icmp --icmp-type
    int icmpCode;
    int icmpType;

    // -m addrtype
    int srcAddrType;
    int dstAddrType;
    enum {
        UNSPEC,
        UNICAST,
        LOCAL,
        BROADCAST,
        ANYCAST,
        MULTICAST,
        BLACKHOLE,
        UNREACHABLE,
        PROHIBIT,
        THROW,
        NAT,
        XRESOLVE
    };

    // -m mac
    Address macAddress;

    static const char UNDECLARED = 0;
    static const char EQUAL_TO = 1;
    static const char NOT_EQUAL_TO = 2;
    static const char GREATER_THAN = 3;
    static const char LESSER_THAN = 4;
    static const char RANGE = 5;
    static const char NOT_IN_RANGE = 6;

    // Have all char's together for compact memory
    char protocolClause;
    char srcAddressClause;
    char dstAddressClause;
    char inInterfaceIndexClause;
    char outInterfaceIndexClause;
    char fragmentClause;
    char sportClause;
    char dportClause;
    char tcpFlagsCheckClause;
    char tcpOptionClause;
    char icmpClause;
    char srcAddrTypeClause;
    char dstAddrTypeClause;
    char macAddressClause;

    enum {
        TOKEN_DASH,
        TOKEN_DOUBLE_DASH,
        TOKEN_NOT,
        TOKEN_OTHER
    };
    bool readNextToken(char* token, int* tokenType);
    const char* ruleStr;

    Node* node;

    int action;
    char jumpChainName[MAX_STRING_LENGTH];
};

#endif /* FIREWALL_RULE_H_ */
