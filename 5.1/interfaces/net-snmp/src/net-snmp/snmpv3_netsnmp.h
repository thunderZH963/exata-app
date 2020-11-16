/*
 * snmpv3.h
 */

#ifndef SNMPV3_H_NETSNMP
#define SNMPV3_H_NETSNMP

#ifdef __cplusplus
extern          "C" {
#endif

#include "asn1_netsnmp.h"

size_t          snmpv3_get_engineID(u_char*  buf, size_t buflen);

#define MAX_ENGINEID_LENGTH 32 /* per SNMP-FRAMEWORK-MIB SnmpEngineID TC */

#define ENGINEID_TYPE_IPV4    1
#define ENGINEID_TYPE_IPV6    2
#define ENGINEID_TYPE_MACADDR 3
#define ENGINEID_TYPE_TEXT    4
#define ENGINEID_TYPE_EXACT   5
#define ENGINEID_TYPE_NETSNMP_RND 128

#define    DEFAULT_NIC "eth0"

    int             snmpv3_clone_engineID(u_char** , size_t* , u_char* ,
                                          size_t);
#ifdef __cplusplus
}
#endif
#endif                          /* SNMPV3_H_NETSNMP */
