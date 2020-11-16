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

#include <stdio.h>
#include "api.h"
#include "network_ip.h"
#include "transport_tcp_hdr.h"
#include "transport_udp.h"
#include "firewall_model.h"
#include "firewall_table.h"
#include "firewall_chain.h"
#include "firewall_rule.h"

bool is_number(const char* str)
{
    for (int i = 0; i < strlen(str); i++)
    {
        if (!isdigit(str[i])) {
            return false;
        }
    }
    return true;
}

static void setMask(unsigned int* tcpFlags, char individualFlagChar)
{
#define CWR 0x80
#define ECE 0x40
#define URG 0x20
#define ACK 0x10
#define PSH 0x08
#define RST 0x04
#define SYN 0x02
#define FIN 0x01

    int flagMask = *tcpFlags;
    switch (individualFlagChar)
    {
    case 'C':
        {
            *tcpFlags = *tcpFlags | CWR;
        }
        break;
    case 'E':
        {
            *tcpFlags  = *tcpFlags  | ECE;
        }
        break;
    case 'U':
        {
           *tcpFlags  = *tcpFlags  | URG;
        }
        break;
    case 'A':
        {
           *tcpFlags  = *tcpFlags  | ACK;
        }
        break;
    case 'P':
        {
            *tcpFlags  = *tcpFlags | PSH;
        }
        break;
    case 'R':
        {
            *tcpFlags = *tcpFlags | RST;
        }
        break;
    case 'S':
        {
            *tcpFlags = *tcpFlags | SYN;
        }
        break;
    case 'F':
        {
           *tcpFlags = *tcpFlags | FIN;
        }
        break;
    }
}

static unsigned int tcpFlagsMask(char * token)
{
    unsigned int tcpFlags = 0;
    if (token == NULL)
    {
        return tcpFlags;
    }
    else
    {
        if (!strcmp(token, "ALL"))
        {
            tcpFlags = 255;
            return tcpFlags;
        }
        else if (!strcmp(token, "NONE"))
        {
            tcpFlags = 0;
            return tcpFlags;
        }
        else
        {
            char* individualFlags;
            individualFlags = strtok(token, ",");
            while (individualFlags)
            {
                setMask(&tcpFlags, *individualFlags);   
                individualFlags = strtok(NULL, ",");
            } 
            return tcpFlags;
        }
    }
}

FirewallRule::FirewallRule(Node* node)
{
    this->node = node;

    protocolClause = UNDECLARED;
    srcAddressClause = UNDECLARED;
    dstAddressClause = UNDECLARED;
    inInterfaceIndexClause = UNDECLARED;
    outInterfaceIndexClause = UNDECLARED;
    fragmentClause = UNDECLARED;
    sportClause = UNDECLARED;
    dportClause = UNDECLARED;
    tcpFlagsCheckClause = UNDECLARED;
    tcpOptionClause = UNDECLARED;
    icmpClause = UNDECLARED;
    srcAddrTypeClause = UNDECLARED;
    dstAddrTypeClause = UNDECLARED;
    macAddressClause = UNDECLARED;
}

void FirewallRule::print()
{
    printf("RULE: ");

    if (protocolClause != UNDECLARED)
    {
        printf(" -p %s%d",
                (protocolClause == NOT_EQUAL_TO)?"! ":"",
                protocol);
    }

    if (srcAddressClause != UNDECLARED)
    {
        char str[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(srcAddress, str);

        printf(" -s %s%s",
                (srcAddressClause == NOT_EQUAL_TO)?"! ":"",
                        str);
        if (srcMask != INVALID_ADDRESS) {
            IO_ConvertIpAddressToString(srcMask, str);
            printf("/%s", str);
        }
    }

    if (dstAddressClause != UNDECLARED)
    {
        char str[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(dstAddress, str);

        printf(" -d %s%s",
                (dstAddressClause == NOT_EQUAL_TO)?"! ":"",
                        str);
        if (dstMask != INVALID_ADDRESS) {
            IO_ConvertIpAddressToString(dstMask, str);
            printf("/%s", str);
        }

    }

    if (inInterfaceIndexClause != UNDECLARED)
    {
        printf(" -i %s%d",
                (inInterfaceIndexClause == NOT_EQUAL_TO)?"! ":"",
                        inInterfaceIndex);
    }

    if (outInterfaceIndexClause != UNDECLARED)
    {
        printf(" -o %s%d",
                (outInterfaceIndexClause == NOT_EQUAL_TO)?"! ":"",
                        outInterfaceIndex);
    }

    if (fragmentClause != UNDECLARED)
    {
        printf(" %s-f",
                (fragmentClause == NOT_EQUAL_TO)?"! ":"");
    }

    if (sportClause != UNDECLARED)
    {
        printf(" --sport %s%d:%d",
                (sportClause == NOT_EQUAL_TO)?"! ":"",
                        sportBegin,
                        sportEnd);
    }

    if (dportClause != UNDECLARED)
    {
        printf(" --dport %s%d:%d",
                (dportClause == NOT_EQUAL_TO)?"! ":"",
                        dportBegin,
                        dportEnd);
    }

    switch (action)
    {
    case FirewallModel::FIREWALL_ACTION_ACCEPT:
        printf(" -j ACCEPT"); break;
    case FirewallModel::FIREWALL_ACTION_DROP:
        printf(" -j DROP"); break;
    case FirewallModel::FIREWALL_ACTION_REJECT:
        printf(" -j REJECT"); break;
    case FirewallTable::FIREWALL_TABLE_JUMP_CHAIN:
        printf(" -j %s", jumpChainName); break;
    case FirewallTable::FIREWALL_TABLE_GOTO_CHAIN:
        printf(" -g %s", jumpChainName); break;
    case FirewallTable::FIREWALL_TABLE_RETURN:
        printf(" -j RETURN");
    }

    printf("\n");
}


bool FirewallRule::parse(const char* str, const char *chainName)
{
    char token[MAX_STRING_LENGTH];
    bool found;
    bool beginsWithNegation = false;

    ruleStr = str;
    int tokenType;


#define TOKENIS(y) !strcmp(token, y)
#define CHECK_NEGATION(clause) \
    if (tokenType == TOKEN_NOT) { \
        clause = NOT_EQUAL_TO; \
        found = readNextToken(token, &tokenType); \
        ASSERT_TOKEN(found && tokenType == TOKEN_OTHER); \
    } \
    else { \
        clause = EQUAL_TO; \
    }
/*#define ASSERT_TOKEN(cond) if (!(cond)) {\
    char errorString[MAX_STRING_LENGTH]; \
    sprintf(errorString, "Syntax error at:\n%s\n", str); \
    int loc = strlen(errorString); \
    for (int i = 0; i < (ruleStr - str); i++) { \
        errorString[loc++] = '-'; \
    } \
    errorString[loc++] = '^'; \
    errorString[loc] = '\0'; \
    ERROR_ReportError(errorString); \
}*/
#define ASSERT_TOKEN(cond)  ASSERT_TOKEN_MSG(cond, "Syntax Error")

#define ASSERT_TOKEN_MSG(cond, msg) if (!(cond)) {\
    char errorString[MAX_STRING_LENGTH]; \
    sprintf(errorString, "%s:\n%s\n", msg, str); \
    int loc = strlen(errorString); \
    for (int i = 0; i < (ruleStr - str); i++) { \
    errorString[loc++] = '-'; \
    } \
    errorString[loc++] = '^'; \
    errorString[loc] = '\0'; \
    ERROR_ReportWarning(errorString); \
    return false; \
}

    // Skip the first two tokens ('FIREWALL' and <node-id>)
    readNextToken(token, &tokenType);
    readNextToken(token, &tokenType);

    while (readNextToken(token, &tokenType))
    {
        ASSERT_TOKEN(tokenType != TOKEN_OTHER);

        if (tokenType == TOKEN_NOT) {
            beginsWithNegation = true;
            continue;
        }


        /**
         * PROTOCOL option
         */
        if (TOKENIS("--protocol") || TOKENIS("-p"))
        {
            ASSERT_TOKEN(!beginsWithNegation);

            // next tokens: ! token; token
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));

            CHECK_NEGATION(protocolClause);

            if (IO_CaseInsensitiveStringsAreEqual(token, "all", 3)) {
                protocol = 0;
            } else if (IO_CaseInsensitiveStringsAreEqual(token, "tcp", 3)) {
                protocol = IPPROTO_TCP;
            } else if (IO_CaseInsensitiveStringsAreEqual(token, "udp", 3)) {
                protocol = IPPROTO_UDP;
            } else if (IO_CaseInsensitiveStringsAreEqual(token, "icmp", 4)) {
                protocol = IPPROTO_ICMP;
            } else if (is_number(token)) {
                protocol = atoi(token);
            } else {
                ASSERT_TOKEN(false);
            }

            continue;
        } // if -p, --protocol

        /**
         * SRC ADDRESS option
         */
        if (TOKENIS("-s") || TOKENIS("--src") || TOKENIS("--source"))
        {
            ASSERT_TOKEN(!beginsWithNegation);

            // next tokens: ! token; token
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));

            CHECK_NEGATION(srcAddressClause);


            char *slash = strchr(token, '/');
            if (slash) {
                *slash = '\0';
                IO_ConvertStringToNodeAddress(
                                        token,
                                        &srcAddress);
                if (is_number(slash + 1)) {
                    srcMask =
                            ConvertNumHostBitsToSubnetMask(32 - atoi(slash + 1));
                } else {
                    IO_ConvertStringToNodeAddress(
                            slash + 1,
                            &srcMask);
                }

            } else {
                IO_ConvertStringToNodeAddress(
                        token,
                        &srcAddress);
                srcMask = ConvertNumHostBitsToSubnetMask(0);
            }

            continue;
        }

        /**
         * DEST ADDRESS option
         */
        if (TOKENIS("-d") || TOKENIS("--dst") || TOKENIS("--destination"))
        {
            ASSERT_TOKEN(!beginsWithNegation);

            // next tokens: ! token; token
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));

            CHECK_NEGATION(dstAddressClause);

            char *slash = strchr(token, '/');
            if (slash) {
                *slash = '\0';
                IO_ConvertStringToNodeAddress(
                                        token,
                                        &dstAddress);
                if (is_number(slash + 1)) {
                    dstMask =
                            ConvertNumHostBitsToSubnetMask(32 - atoi(slash + 1));
                } else {
                    IO_ConvertStringToNodeAddress(
                            slash + 1,
                            &dstMask);
                }

            } else {
                IO_ConvertStringToNodeAddress(
                        token,
                        &dstAddress);
                dstMask = ConvertNumHostBitsToSubnetMask(0);
            }

            continue;
        }

        /**
         * IN INTERFACE
         */
        if (TOKENIS("-i") || TOKENIS("--in-interface"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            char errorMsg[MAX_STRING_LENGTH];
            sprintf(errorMsg, "Parameter %s cannot be used with the OUTPUT chain", token); 
            ASSERT_TOKEN_MSG(strcmp(chainName, "OUTPUT"), errorMsg);

            // next tokens: ! token; token
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));

            CHECK_NEGATION(inInterfaceIndexClause);

            if (TOKENIS("+"))
            {
                inInterfaceIndex = ANY_INTERFACE;
            }
            else
            {
                ASSERT_TOKEN(is_number(token));
                inInterfaceIndex = atoi(token);
            }

            continue;
        }

        /**
         * OUT INTERFACE
         */
        if (TOKENIS("-o") || TOKENIS("--out-interface"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            char errorMsg[MAX_STRING_LENGTH];
            sprintf(errorMsg, "Parameter %s cannot be used with the INPUT chain", token); 
            ASSERT_TOKEN_MSG(strcmp(chainName, "INPUT"), errorMsg);

            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));

            CHECK_NEGATION(outInterfaceIndexClause);

            if (TOKENIS("+"))
            {
                outInterfaceIndex = ANY_INTERFACE;
            }
            else
            {
                ASSERT_TOKEN(is_number(token));
                outInterfaceIndex = atoi(token);
            }

            continue;
        }

        /**
         * FRAGMENT
         */
        if (TOKENIS("-f") || TOKENIS("--fragment"))
        {
            if (beginsWithNegation) {
                fragmentClause = NOT_EQUAL_TO;                
            } else {
                fragmentClause = EQUAL_TO;               
            }
            fragment = true;
            beginsWithNegation = false;

            continue;
        }
        /**
         * -m addrtype
         */
        if (TOKENIS("--src-type"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(tokenType == TOKEN_OTHER);

            if (TOKENIS("UNICAST")) {
                srcAddrType = UNICAST;
            }
            // etc. ...
            continue;
        }

        /**
         * SPORT
         */
        if (TOKENIS("--sport") || TOKENIS("--source-port"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            char errorMsg[MAX_STRING_LENGTH];
            sprintf(errorMsg, "Parameter %s cannot be used with "
                "protocols other than tcp and udp", token); 
            ASSERT_TOKEN_MSG(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP, errorMsg);
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));
            CHECK_NEGATION(sportClause);
            char* colonAt = strchr(token, ':');
            if (colonAt)
            {
                *colonAt = '\0';
                if (strlen(token) == 0) {
                    sportBegin = 0;
                } else {
                    ASSERT_TOKEN(is_number(token));
                    sportBegin = atoi(token);
                }

                if (strlen(colonAt + 1) == 0) {
                    sportEnd = 65535;
                } else {
                    ASSERT_TOKEN(is_number(colonAt + 1));
                    sportEnd = atoi(colonAt + 1);
                }
                if (sportClause == NOT_EQUAL_TO)
                {
                    sportClause = NOT_IN_RANGE;
                }
                else if (sportClause == EQUAL_TO)
                {
                    sportClause = RANGE;
                }
            }
            else
            {
                ASSERT_TOKEN(is_number(token));
                sportBegin = sportEnd = atoi(token);
            }
            continue;
        }

        /**
         * DPORT
         */
        if (TOKENIS("--dport") || TOKENIS("--destination-port"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            char errorMsg[MAX_STRING_LENGTH];
            sprintf(errorMsg, "Parameter %s cannot be used with "
                "protocols other than tcp and udp", token); 
            ASSERT_TOKEN_MSG(protocol == IPPROTO_TCP || protocol == IPPROTO_UDP, errorMsg);
            found = readNextToken(token, &tokenType); 
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));
            CHECK_NEGATION(dportClause);
            char* colonAt = strchr(token, ':');
            if (colonAt)
            {
                *colonAt = '\0';
                if (strlen(token) == 0) {
                    dportBegin = 0;
                } else {
                    ASSERT_TOKEN(is_number(token));
                    dportBegin = atoi(token);
                }

                if (strlen(colonAt + 1) == 0) {
                    dportEnd = 65535;
                } else {
                    ASSERT_TOKEN(is_number(colonAt + 1));
                    dportEnd = atoi(colonAt + 1);
                }
                if (dportClause == NOT_EQUAL_TO)
                {
                    dportClause = NOT_IN_RANGE;
                }
                else if (dportClause == EQUAL_TO)
                {
                    dportClause = RANGE;
                }
            }
            else
            {
                ASSERT_TOKEN(is_number(token));
                dportBegin = dportEnd = atoi(token);
            }
            continue;
        }

        /**
         * JUMP
         */
        if (TOKENIS("-j") ||  TOKENIS("--jump"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found && (tokenType == TOKEN_OTHER));

            if (TOKENIS("DROP"))
            {
                action = FirewallModel::FIREWALL_ACTION_DROP;
            }
            else if (TOKENIS("ACCEPT"))
            {
                action = FirewallModel::FIREWALL_ACTION_ACCEPT;
            }
            else if (TOKENIS("REJECT"))
            {
                action = FirewallModel::FIREWALL_ACTION_REJECT;
            }
            else if (TOKENIS("RETURN"))
            {
                action = FirewallTable::FIREWALL_TABLE_RETURN;
            }
            else
            {
                action = FirewallTable::FIREWALL_TABLE_JUMP_CHAIN;
                strcpy(jumpChainName, token);
            }
            continue;
        }

        /**
         * GOTO
         */
        if (TOKENIS("-g") || TOKENIS("--goto"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found && (tokenType == TOKEN_OTHER));

            action = FirewallTable::FIREWALL_TABLE_GOTO_CHAIN;
            strcpy(jumpChainName, token);

            continue;
        }

        if (TOKENIS("--tcp-flags"))
        {
            ASSERT_TOKEN(!beginsWithNegation);
            char errorMsg[MAX_STRING_LENGTH];
            sprintf(errorMsg, "Parameter %s cannot be used with "
                "protocols other than tcp", token); 
            ASSERT_TOKEN_MSG(protocol == IPPROTO_TCP, errorMsg);
            found = readNextToken(token, &tokenType);
            ASSERT_TOKEN(found);
            ASSERT_TOKEN((tokenType == TOKEN_NOT) || (tokenType == TOKEN_OTHER));
            CHECK_NEGATION(tcpFlagsCheckClause);
            tcpFlagsCheckMask = tcpFlagsMask(token);
            found = readNextToken(token, &tokenType);
            tcpFlagsSetMask = 0;
            tcpFlagsSetMask = tcpFlagsMask(token);
            tcpFlagsCheckMask |= tcpFlagsSetMask;
            continue;
        }


        /**
         * Ignore rules we dont understand
         * Strategy is that we will we skip one extra token
         * TODO: check for options with no parameters
         */
        int dummy;
        readNextToken(token, &tokenType);
        CHECK_NEGATION(dummy);

    }

    if (fragmentClause == EQUAL_TO)
    {
        //this means that only second fragments and onwards will be considered
        //so we need to disable other clauses related to tcp and udp
        if ((sportClause != UNDECLARED) || (dportClause != UNDECLARED) ||
                (tcpFlagsCheckClause != UNDECLARED))
        {
            sportClause = UNDECLARED;
            dportClause = UNDECLARED;
            tcpFlagsCheckClause = UNDECLARED;
            ERROR_ReportWarning("Tcp or udp related parameters specified will be"
                " ignored when -f is specified\n");
        }
    }
    return true;
}

bool FirewallRule::readNextToken(char* token, int* tokenType)
{
    int tokenLoc = 0;
    bool readingToken = false;
    int numDashes = 0;

    while (*ruleStr != '\0')
    {
        switch (*ruleStr)
        {
        case ' ':
        case '\t':
        {
            if (readingToken)
            {
                token[tokenLoc] = '\0';
                switch (numDashes) {
                case 0: *tokenType = TOKEN_OTHER; break;
                case 1: *tokenType = TOKEN_DASH; break;
                case 2: *tokenType = TOKEN_DOUBLE_DASH; break;
                }
                ruleStr++;
                return true;
            }
            break;
        }
        case '-':
        {
            if (!readingToken) {
                numDashes ++;
            }
            token[tokenLoc++] = '-';
            break;
        }
        case '!':
        {
            if (!readingToken)
            {
                *tokenType = TOKEN_NOT;
                ruleStr++;
                return true;
            }
            break;
        }
        default:
        {
            readingToken = true;
            token[tokenLoc++] = *ruleStr;
        }
        }

        ruleStr ++;
    }

    if (readingToken)
    {
        token[tokenLoc] = '\0';
        switch (numDashes) {
        case 0: *tokenType = TOKEN_OTHER; break;
        case 1: *tokenType = TOKEN_DASH; break;
        case 2: *tokenType = TOKEN_DOUBLE_DASH; break;
        }
        return true;
    }
    return false;
}


bool FirewallRule::match(
          const Message* msg,
          int inInterface,
          int outInterface,
          int* action,
          char* jumpChain)
{
    // Start with IP header
    IpHeaderType* ipHeader = (IpHeaderType *)msg->packet;

#define MATCH_RULE(clause, cond_when_equal) \
        if ((clause == EQUAL_TO) && !(cond_when_equal)) return false; \
        if ((clause == NOT_EQUAL_TO) && (cond_when_equal)) return false;

    MATCH_RULE(protocolClause,
            (protocol == 0) || (protocol == ipHeader->ip_p));
    MATCH_RULE(srcAddressClause,
            (srcAddress & srcMask) == (ipHeader->ip_src & srcMask));
    MATCH_RULE(dstAddressClause,
            (dstAddress & dstMask) == (ipHeader->ip_dst & dstMask));
    MATCH_RULE(inInterfaceIndexClause,
            (inInterfaceIndex == ANY_INTERFACE)
            || (inInterfaceIndex == inInterface));
    MATCH_RULE(outInterfaceIndexClause,
            (outInterfaceIndex == ANY_INTERFACE)
            || (outInterfaceIndex == outInterface));
    bool isFirstFragment =
            (IpHeaderGetIpFragOffset(ipHeader->ipFragment) == 0);
    MATCH_RULE(fragmentClause, fragment == !isFirstFragment);
            
    char* nextHeader =
            (msg->packet + (IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4));
    switch (ipHeader->ip_p)
    {
    case IPPROTO_TCP:
    {
        struct tcphdr* tcp = (struct tcphdr *)nextHeader;
        MATCH_RULE(sportClause, tcp->th_sport == sportBegin);
        MATCH_RULE(dportClause, tcp->th_dport == dportBegin);
        if ((sportClause == RANGE)
                && ((tcp->th_sport < sportBegin)
                        || (tcp->th_sport > sportEnd)))
        {
            return false;
        }
        if ((sportClause == NOT_IN_RANGE)
                && ((tcp->th_sport >= sportBegin)
                        && (tcp->th_sport <= sportEnd)))
        {
            return false;
        }
        if ((dportClause == RANGE)
                && ((tcp->th_dport < dportBegin)
                        || (tcp->th_dport > dportEnd)))
        {
            return false;
        }
        if ((dportClause == NOT_IN_RANGE)
                && ((tcp->th_dport >= dportBegin)
                        && (tcp->th_dport <= dportEnd)))
        {
            return false;
        }
        MATCH_RULE(tcpFlagsCheckClause, (tcp->th_flags & tcpFlagsCheckMask) 
            == tcpFlagsSetMask);
        break;
    }
    case IPPROTO_UDP:
    {
        TransportUdpHeader* udp = (TransportUdpHeader *)nextHeader;

        MATCH_RULE(sportClause, udp->sourcePort == sportBegin);
        MATCH_RULE(dportClause, udp->destPort == dportBegin);
        if ((sportClause == RANGE)
                && ((udp->sourcePort < sportBegin)
                        || (udp->sourcePort > sportEnd)))
        {
            return false;
        }
        if ((sportClause == NOT_IN_RANGE)
                && ((udp->sourcePort >= sportBegin)
                        && (udp->sourcePort <= sportEnd)))
        {
            return false;
        }
        
        if ((dportClause == RANGE)
                && ((udp->destPort < dportBegin)
                        || (udp->destPort > dportEnd)))
        {
            return false;
        }
        
       
        if ((dportClause == NOT_IN_RANGE)
                && ((udp->destPort >= dportBegin)
                        && (udp->destPort <= dportEnd)))
        {
            return false;
        }
        
        break;
    }
    case IPPROTO_ICMP:
    {
        break;
    }
    }


    // The rule has matched!
    *action = this->action;
    strcmp(jumpChain, this->jumpChainName);
    return true;
}
