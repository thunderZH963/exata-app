#ifndef _MIBGROUP_SYSTEM_MIB_H_NETSNMP
#define _MIBGROUP_SYSTEM_MIB_HNETSNMP

#define SYS_STRING_LEN    256

#include "snmp_vars_netsnmp.h"

FindVarMethod var_system;
WriteMethod write_systemContact;
WriteMethod write_systemName;
WriteMethod write_systemLocation;

#define SYSDESCR    1
#define SYSOBJECTID 2
#define SYSUPTIME   3
#define SYSCONTACT  4
#define SYSNAME     5
#define SYSLOCATION 6
#define SYSSERVICES 7

#endif                          /* _MIBGROUP_SYSTEM_MIB_H_NETSNMP */
