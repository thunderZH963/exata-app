/*
 *  Template MIB group interface - ip.h
 *
 */

#ifndef IP_NETSNMP_H
#define IP_NETSNMP_H

#include "cache_handler_netsnmp.h"
#include "snmp_vars_netsnmp.h"

FindVarMethod var_ip;

extern NetsnmpCacheLoad ip_load;
extern NetsnmpCacheFree ip_free;
void*  SNMP_GetIpRouteEntry1(Node* node, unsigned int interfaceId, int routeIndex, int oidIndex);
int SNMP_GetMaxTableSize1(Node*  node, unsigned int interfaceId);

#define IPFORWARDING      1
#define IPDEFAULTTTL      2
#define IPINRECEIVES      3
#define IPINHDRERRORS      4
#define IPINADDRERRORS      5
#define IPFORWDATAGRAMS   6
#define IPINUNKNOWNPROTOS 7
#define IPINDISCARDS      8
#define IPINDELIVERS      9
#define IPOUTREQUESTS     10
#define IPOUTDISCARDS     11
#define IPOUTNOROUTES     12
#define IPREASMTIMEOUT     13
#define IPREASMREQDS     14
#define IPREASMOKS     15
#define IPREASMFAILS     16
#define IPFRAGOKS     17
#define IPFRAGFAILS     18
#define IPFRAGCREATES     19
#define IPADDRTABLE     20    /* Placeholder */
#define IPROUTETABLE     21    /* Placeholder */
#define IPMEDIATABLE     22    /* Placeholder */
#define IPROUTEDISCARDS     23

#define IPADADDR      1
#define IPADIFINDEX      2
#define IPADNETMASK      3
#define IPADBCASTADDR      4
#define IPADREASMMAX      5

#define IPROUTEDEST      1
#define IPROUTEIFINDEX      2
#define IPROUTEMETRIC1      3
#define IPROUTEMETRIC2      4
#define IPROUTEMETRIC3      5
#define IPROUTEMETRIC4      6
#define IPROUTENEXTHOP      7
#define IPROUTETYPE      8
#define IPROUTEPROTO      9
#define IPROUTEAGE     10
#define IPROUTEMASK     11
#define IPROUTEMETRIC5     12
#define IPROUTEINFO     13

#endif                          /* IP_NETSNMP_H */
