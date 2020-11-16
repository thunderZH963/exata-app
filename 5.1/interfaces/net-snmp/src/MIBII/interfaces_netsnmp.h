/*
 *  Interfaces MIB group interface - interfaces.h
 *
 */
#ifndef _MIBGROUP_INTERFACES_H_NETSNMP
#define _MIBGROUP_INTERFACES_H_NETSNMP

#include "snmp_vars_netsnmp.h"
#ifndef USING_IF_MIB_IFTABLE_MODULE

     struct in_ifaddr;
     struct ifnet;
     int             Interface_Scan_Get_Count(void);
     int             Interface_Index_By_Name(char* , int);
     void            Interface_Scan_Init(void);

     int             Interface_Scan_Next(short* , char* , struct ifnet* ,
                                         struct in_ifaddr*);

     extern FindVarMethod var_interfaces;
     extern FindVarMethod var_ifEntry;

#endif /* USING_IF_MIB_IFTABLE_MODULE */

#define NETSNMP_IFNUMBER        0
#define NETSNMP_IFINDEX         1
#define NETSNMP_IFDESCR         2
#define NETSNMP_IFTYPE          3
#define NETSNMP_IFMTU           4
#define NETSNMP_IFSPEED         5
#define NETSNMP_IFPHYSADDRESS   6
#define NETSNMP_IFADMINSTATUS   7
#define NETSNMP_IFOPERSTATUS    8
#define NETSNMP_IFLASTCHANGE    9
#define NETSNMP_IFINOCTETS      10
#define NETSNMP_IFINUCASTPKTS   11
#define NETSNMP_IFINNUCASTPKTS  12
#define NETSNMP_IFINDISCARDS    13
#define NETSNMP_IFINERRORS      14
#define NETSNMP_IFINUNKNOWNPROTOS 15
#define NETSNMP_IFOUTOCTETS     16
#define NETSNMP_IFOUTUCASTPKTS  17
#define NETSNMP_IFOUTNUCASTPKTS 18
#define NETSNMP_IFOUTDISCARDS   19
#define NETSNMP_IFOUTERRORS     20
#define NETSNMP_IFOUTQLEN       21
#define NETSNMP_IFSPECIFIC      22

#endif                          /* _MIBGROUP_INTERFACES_H_NETSNMP */
