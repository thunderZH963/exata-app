/*
 * SNMPv3 View-based Access Control Model
 */

#ifndef _MIBGROUP_VACM_CONF_H_NETSNMP
#define _MIBGROUP_VACM_CONF_H_NETSNMP


#include "callback_netsnmp.h"
#include "types_netsnmp.h"

#define VACM_CREATE_SIMPLE_V3       1
#define VACM_CREATE_SIMPLE_COM      2
#define VACM_CREATE_SIMPLE_COMIPV4  3
#define VACM_CREATE_SIMPLE_COMIPV6  4
#define VACM_CREATE_SIMPLE_COMUNIX  5

 void vacm_parse_authgroup(const char* , char*);

#define VACM_CHECK_VIEW_CONTENTS_NO_FLAGS        0
#define VACM_CHECK_VIEW_CONTENTS_DNE_CONTEXT_OK  1

#endif                          /* _MIBGROUP_VACM_CONF_H */
