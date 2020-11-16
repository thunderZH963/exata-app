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

#ifndef APP_NETSNMP_H
#define APP_NETSNMP_H

#include <asn1_netsnmp.h>

// CONSTANTS
#define DEFAULT_MANAGER_NODE 1

const char SNMP_ENABLED[] = "SNMP-ENABLED";

#ifndef u_char
typedef unsigned char u_char;
#endif

typedef struct struct_plain_text_data {
    u_char pduType;
    long requestID;
    long errorStatus;
    long errorIndex;
    oid* objId;
    int objIdLen;
    u_char* value;
}plainTextData;

typedef struct struct_app_SNMPv3_Message_ScopedPduData_ScopedPDU {
    u_char* contextEngineID;
    u_char* contextName;
    plainTextData data;
}ScopedPDU;

typedef struct struct_app_SNMPv3_Message_ScopedPduData {
    void* pduData;
}ScopedPduData;

typedef struct struct_app_SNMPv3_Message_HeaderData {
    long msgID;
    long msgMaxSize;
    /*
     * .... ...1    authFlag
     * .... ..1.    privFlag
     * .... .1..    reportableFlag
                 Please observe:
     * .... ..00    is OK, means noAuthNoPriv
     * .... ..01       is OK, means authNoPriv
     * .... ..10       reserved, MUST NOT be used.
     * .... ..11       is OK, means authPriv
     */
    u_char* msgFlags;
    long msgSecurityModel;
}HeaderData;

typedef struct struct_Security_Parameters {
    u_char* msgAuthoritativeEngineID;
    long msgAuthoritativeEngineBoots;
    long msgAuthoritativeEngineTime;
    u_char* msgUserName;
    u_char* msgAuthenticationParameters;
    u_char* msgPrivacyParameters;
}SecurityParameters_netsnmp;

typedef struct struct_app_SNMPv3_Message {
    /** snmp version */
    long msgVersion;
    /* Administrative Parameters */
    HeaderData msgGlobalData;
    /*    security model-specific parameters
     *    and format defined by Security Model */
    SecurityParameters_netsnmp msgSecurityParameters;
    ScopedPduData msgData;
}appSNMPv3Message;


/*
 * NAME:        AppNetSnmpAgentInit.
 * PURPOSE:     Initialize a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node,
 *              nodeInput - nodeInput for config file.
 * RETURN:      none.
 */
void
AppNetSnmpAgentInit(Node*  node, const NodeInput* nodeInput);


/*
 * NAME:        AppLayerNetSnmpAgent.
 * PURPOSE:     Models the behaviour of NetSnmpAgent on receiving the
 *              message encapsulated in msg.
 * PARAMETERS:  node - pointer to the node,
 *              msg - message received by the layer
 * RETURN:      none.
 */
void
AppLayerNetSnmpAgent(Node* node, Message* msg);

/*
 * NAME:        printQualNetError.
 * PURPOSE:     Prints the Snmp errors report.
 * PARAMETERS:  node - pointer to the node,
 *              errorString - the error string to be printed.
 * RETURN:      none.
 */
void
printQualNetError(Node* node, char* errorString);

/*
 * NAME:        AppNetSnmpAgentFinalize.
 * PURPOSE:     Collect statistics of a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppNetSnmpAgentFinalize(Node* node);

/*
 * NAME:        AppSnmpAgentPrintStats.
 * PURPOSE:     Print statistics of a NetSnmpAgent session.
 * PARAMETERS:  node - pointer to the node.
 * RETURN:      none.
 */
void
AppSnmpAgentPrintStats(Node*  node);

#endif /*APP_NETSNMP_H */
