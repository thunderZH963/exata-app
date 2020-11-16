/*
 *  IP MIB group implementation - ip_netsnmp.cpp
 *
 */
#include "net-snmp-config_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "snmp_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "at_netsnmp.h"
#include "var_route_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "netSnmpAgent.h"
#include "node.h"
#include "network_ip.h"
#include "scalar_group_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "ip_netsnmp.h"
#include "routing_aodv.h"
#include "routing_dymo.h"
#include "routing_dsr.h"
#include "routing_iarp.h"
#include "routing_fsrl.h"
#include "snmp_impl_netsnmp.h"

#ifndef MIB_STATS_CACHE_TIMEOUT
#define MIB_STATS_CACHE_TIMEOUT    5
#endif
#ifndef IP_STATS_CACHE_TIMEOUT
#define IP_STATS_CACHE_TIMEOUT    MIB_STATS_CACHE_TIMEOUT
#endif

//value for ipForwarding is
//1 : forwarding
//2 : notForwarding
#ifndef FORWARDING_ENABLED
#define FORWARDING_ENABLED 1
#endif

#ifndef FORWARDING_DISABLED
#define FORWARDING_DISABLED 2
#endif

struct variable ip_variables[] = {
    {IPFORWARDING,ASN_INTEGER, NETSNMP_OLDAPI_RWRITE,
     var_ip, 1, {1}},
    {IPDEFAULTTTL, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ip, 1, {2}},
    {IPINRECEIVES, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {3}},
    {IPINHDRERRORS, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {4}},
    {IPINADDRERRORS, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {5}},
    {IPFORWDATAGRAMS, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {6}},
    {IPINUNKNOWNPROTOS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {7}},
    {IPINDISCARDS,    ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {8}},
    {IPINDELIVERS, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {9}},
    {IPOUTREQUESTS, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {10}},
    {IPOUTDISCARDS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {11}},
    {IPOUTNOROUTES, ASN_COUNTER32,   NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {12}},
    {IPREASMTIMEOUT,ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {13}},
    {IPREASMREQDS,ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {14}},
    {IPREASMOKS,ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {15}},
    {IPREASMFAILS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {16}},
    {IPFRAGOKS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {17}},
    {IPFRAGFAILS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {18}},
    {IPFRAGCREATES, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {19}},
    {IPADADDR,      ASN_IPADDRESS, NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 3, {20,1,1}},
    {IPADIFINDEX,   ASN_INTEGER,   NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 3, {20,1,2}},
    {IPADNETMASK,   ASN_IPADDRESS, NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 3, {20,1,3}},
    {IPADBCASTADDR, ASN_INTEGER,  NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 3, {20,1,4}},
    {IPADREASMMAX,  ASN_INTEGER,  NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 3, {20,1,5}},
    {IPROUTEDEST,    ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,1}},
    {IPROUTEIFINDEX, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,2}},
    {IPROUTEMETRIC1, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,3}},
    {IPROUTEMETRIC2, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,4}},
    {IPROUTEMETRIC3, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,5}},
    {IPROUTEMETRIC4, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,6}},
    {IPROUTENEXTHOP, ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,7}},
    {IPROUTETYPE,    ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,8}},
    {IPROUTEPROTO,   ASN_INTEGER,   NETSNMP_OLDAPI_RONLY,
     var_ipRouteEntry, 3, {21,1,9}},
    {IPROUTEAGE,     ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,10}},
    {IPROUTEMASK,    ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,11}},
    {IPROUTEMETRIC5, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 3, {21,1,12}},
    {IPROUTEINFO,    ASN_OBJECT_ID, NETSNMP_OLDAPI_RONLY,
     var_ipRouteEntry, 3, {21,1,13}},
    {IPMEDIAIFINDEX,     ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_atEntry, 3, {22,1,1}},
    {IPMEDIAPHYSADDRESS, ASN_OCTET_STR, NETSNMP_OLDAPI_RWRITE,
     var_atEntry, 3, {22,1,2}},
    {IPMEDIANETADDRESS,  ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_atEntry, 3, {22,1,3}},
    {IPMEDIATYPE,        ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_atEntry, 3, {22,1,4}},
    {IPROUTEDISCARDS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_ip, 1, {23}}};




struct variable1 ipaddr_variables[] = {
    {IPADADDR,      ASN_IPADDRESS, NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 1, {1}},
    {IPADIFINDEX,   ASN_INTEGER,   NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 1, {2}},
    {IPADNETMASK,   ASN_IPADDRESS, NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 1, {3}},
    {IPADBCASTADDR, ASN_INTEGER,  NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 1, {4}},
    {IPADREASMMAX,  ASN_INTEGER,  NETSNMP_OLDAPI_RONLY,
     var_ipAddrEntry, 1, {5}}
};

struct variable1 iproute_variables[] = {
    {IPROUTEDEST,    ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {1}},
    {IPROUTEIFINDEX, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {2}},
    {IPROUTEMETRIC1, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {3}},
    {IPROUTEMETRIC2, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {4}},
    {IPROUTEMETRIC3, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {5}},
    {IPROUTEMETRIC4, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {6}},
    {IPROUTENEXTHOP, ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {7}},
    {IPROUTETYPE,    ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {8}},
    {IPROUTEPROTO,   ASN_INTEGER,   NETSNMP_OLDAPI_RONLY,
     var_ipRouteEntry, 1, {9}},
    {IPROUTEAGE,     ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {10}},
    {IPROUTEMASK,    ASN_IPADDRESS, NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {11}},
    {IPROUTEMETRIC5, ASN_INTEGER,   NETSNMP_OLDAPI_RWRITE,
     var_ipRouteEntry, 1, {12}},
    {IPROUTEINFO,    ASN_OBJECT_ID, NETSNMP_OLDAPI_RONLY,
     var_ipRouteEntry, 1, {13}}
};


/*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath, and the OID of the MIB module
 */
oid             ip_oid[]                = { SNMP_OID_MIB2, 4 };
oid             ipaddr_variables_oid[]  = { SNMP_OID_MIB2, 4, 20, 1 };
oid             iproute_variables_oid[] = { SNMP_OID_MIB2, 4, 21, 1 };
oid             ipmedia_variables_oid[] = { SNMP_OID_MIB2, 4, 22, 1 };
oid             ip_module_oid[] = { SNMP_OID_MIB2, 4 };
oid             ip_module_oid_len = sizeof(ip_module_oid) / sizeof(oid);
int             ip_module_count = 0;    /* Need to liaise with icmp.c */

void
NetSnmpAgent::init_ip(void)
{
#ifdef SNMP_DEBUG
    printf("init_ip:Initializing MIBII/ip at node %d\n",node->nodeId);
#endif

    /*
     * .... with a local cache
     *    (except for HP-UX 11, which extracts objects individually)
     */
#ifndef hpux11
    /*netsnmp_inject_handler(reginfo,
            netsnmp_get_cache_handler(IP_STATS_CACHE_TIMEOUT,
                    ip_load,ip_free,
                    ip_oid, OID_LENGTH(ip_oid)));*/
#endif

    /*
     * register (using the old-style API) to handle the IP tables
     */
    int i, j, k;
    int ip_variables_length = sizeof(ip_variables)/sizeof(struct variable);
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkForwardingTable* rt = &ip->forwardTable;
    int no_interfaces = node->numberInterfaces;
    int no_routes = SNMP_GetMaxTableSize1(node, DEFAULT_INTERFACE);
    variable *extended_ip_variables;
    // new size of the MIB variable is the previous size +
    // (no_interfaces - 1) * size of addr table +
    // (no_routes - 1) * size of route table
    // NOTE: If no_routes comes out to be zero,
    // the ipRouteTable will not be registerd.
    // ipRouteTable will be registerd when the routes are generated.
    // Updating of the MIB-TREE is not handled,
    // will be done in later fixes.
    int extended_ip_variables_length =
            ip_variables_length +
            (no_interfaces - 1) *
            (int) (sizeof(ipaddr_variables)/sizeof(struct variable1)) +
            (no_routes - 1) *
            (int) (sizeof(iproute_variables)/sizeof(struct variable1));
    extended_ip_variables = (variable *)
        malloc(sizeof(variable) * extended_ip_variables_length);
    memset(extended_ip_variables, 0,
        sizeof(variable) * extended_ip_variables_length);

    int extended_ip_variables_index = 0;
    oid *extended_oid;
    for (i = 0; i < ip_variables_length; i++)
    {
        if (ip_variables[i].findVar == var_ipAddrEntry)
        {
            for (j = 0; j < no_interfaces; j++)
            {
                extended_ip_variables[extended_ip_variables_index] =
                    ip_variables[i];
                extended_oid =
                    &(extended_ip_variables[extended_ip_variables_index].
                    name[3]);
                NodeAddress add = NetworkIpGetInterfaceAddress(node, j);
                EXTERNAL_hton(&add, sizeof(add));
                unsigned char*  temp_add = (unsigned char*)&add;
                for (k = 0; k < sizeof(add); k++)
                {
                    *extended_oid++ =(oid)*temp_add++;
                }
                extended_ip_variables[extended_ip_variables_index].namelen =
                    extended_ip_variables[extended_ip_variables_index].namelen
                    + sizeof(add);
                extended_ip_variables_index++;
            }
        }
        else if (ip_variables[i].findVar == var_ipRouteEntry && rt != NULL)
        {            
            for (j = 0; j < no_routes; j++)
            {
                extended_ip_variables[extended_ip_variables_index] =
                    ip_variables[i];
                extended_oid =
                    &(extended_ip_variables[extended_ip_variables_index].
                    name[3]);
                NodeAddress add = rt->row[j].destAddress;
                EXTERNAL_hton(&add, sizeof(add));
                unsigned char*  temp_add = (unsigned char*)&add;
                for (k = 0; k < sizeof(add); k++)
                {
                    *extended_oid++ =(oid)*temp_add++;
                }
                extended_ip_variables[extended_ip_variables_index].namelen = 
                    extended_ip_variables[extended_ip_variables_index].namelen
                    + sizeof(add);
                extended_ip_variables_index++;
            }
        }
        else 
        {
            extended_ip_variables[extended_ip_variables_index++] =
                ip_variables[i];
        }
    }
    // Instead of calling register_mib through REGISTER_MIB,
    // it has been directly called, since, calculation of the length of
    // extended_ip_variables cannot be done as in REGISTER_MIB.
    register_mib("mibII/ip", 
        (struct variable*) extended_ip_variables, sizeof(struct variable),
        extended_ip_variables_length, ip_oid, sizeof(ip_oid)/sizeof(oid));
    REGISTER_SYSOR_ENTRY(ip_module_oid,
                        (char*)"The MIB module for managing IP and"
                        " ICMP implementations");



}



     /*********************
     *
     *  System independent handler
     *      (mostly)
     *
     *********************/







u_char*
var_ip(struct variable* vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_ip:handler MIBII/ip at node %d\n",node->nodeId);
#endif

    Int32* long_return = (Int32*) var_buf;
    *long_return = -1;

    if (vp->name[6] > name[6])
    {
        memcpy(name,vp->name,(int) vp->namelen*  sizeof(oid));
        (*length)= (int) vp->namelen;
    }

    if (vp->magic == 23)
    {
        memcpy(name, vp->name, (int) vp->namelen*  sizeof(oid));
        *length=(int) vp->namelen;
        name[*length] = 0;
        (*length)++;
        *write_method = 0;
        *var_len = sizeof(Int32);
        *long_return=0;
        return (unsigned char*) long_return;
    }

    if (name[7] != vp->name[7])
    {
        name[7] = vp->name[7];
    }

    if (*length == 7)
    {
        name[*length] = 1;
        (*length)+= 2;
    }

    if (*length == 8 || *length == 10)
    {
        (*length)++;
    }

    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    int      type = ASN_COUNTER;
    *var_len = sizeof(Int32);
    if (ip)
    {
        switch (vp->magic) {
        case IPFORWARDING:
            {
            if (ip->ipForwardingEnabled)
               *long_return = FORWARDING_ENABLED;
            else
               *long_return = FORWARDING_DISABLED;
            }
            type = ASN_INTEGER;
            break;
        case IPDEFAULTTTL:
            {
            *long_return = IPDEFTTL;
            }
            type = ASN_INTEGER;
            break;
        case IPINRECEIVES:
            {
            *long_return = ip->stats.ipInReceives;
            }
            break;
        case IPINHDRERRORS:
            {
            *long_return = ip->stats.ipInHdrErrors;
            }
            break;
        case IPINADDRERRORS:
            {
            *long_return = ip->stats.ipInAddrErrors;
            }
            break;
        case IPFORWDATAGRAMS:
            {
            *long_return = ip->stats.ipInForwardDatagrams;
            }
            break;
        case IPINUNKNOWNPROTOS:
            {
            *long_return = ip->stats.ipInUnknownProtos;
            }
            break;
        case IPINDISCARDS:
            {
            *long_return = ip->stats.ipInDiscards;

            }
            break;
        case IPINDELIVERS:
            {
            *long_return = ip->stats.ipInDelivers;

            }
            break;
        case IPOUTREQUESTS:
            {
             *long_return = ip->stats.ipOutRequests;

            }
            break;
        case IPOUTDISCARDS:
            {
             *long_return = ip->stats.ipOutDiscards;

            }
            break;
        case IPOUTNOROUTES:
            {
             *long_return = ip->stats.ipOutNoRoutes;

            }
            break;
        case IPREASMTIMEOUT:
            {
             *long_return = 0;
             type = ASN_INTEGER;
            }
            break;
        case IPREASMREQDS:
            {
             *long_return = ip->stats.ipReasmReqds;

            }
            break;
        case IPREASMOKS:
            {
             *long_return = ip->stats.ipReasmOKs;

            }
            break;
        case IPREASMFAILS:
            {
             *long_return = ip->stats.ipReasmFails;

            }
            break;
        case IPFRAGOKS:
            {
             *long_return = ip->stats.ipFragOKs;

            }
            break;
        case IPFRAGFAILS:
            {
             *long_return = ip->stats.ipFragFails;

            }
            break;
        case IPFRAGCREATES:
            {
             *long_return = ip->stats.ipFragsCreated;

            }
            break;
        case IPROUTEDISCARDS:
            {
             *long_return = 0;

            }
        default:
              return (unsigned char*) long_return;
        }
    }
    return (unsigned char*) long_return;
}

void*  SNMP_GetIpRouteEntry1(Node* node, unsigned int interfaceId, int routeIndex, int oidIndex)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    switch (ip->interfaceInfo[interfaceId]->routingProtocolType)
    {
#ifdef WIRELESS_LIB
        case ROUTING_PROTOCOL_LAR1:
        {
            return NULL;
        }
        case ROUTING_PROTOCOL_AODV:
        {
            AodvData* aodv = NULL;
            int i=0;
            int hashIndex = 0;
            BOOL    found = FALSE;
            aodv = (AodvData*)NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_AODV,
                                NETWORK_IPV4);
            AodvRouteEntry* rtEntry = NULL;

            //increase the routing table index by one because it begins with 0
            routeIndex++;

            for (i = 0; i < AODV_ROUTE_HASH_TABLE_SIZE; i++)
            {
                for (rtEntry = aodv->routeTable.routeHashTable[i]; rtEntry != NULL;
                    rtEntry = rtEntry->hashNext)
                {
                    hashIndex++;
                    if (hashIndex == routeIndex)
                    {
                        //routeIndex's entry in the routing table found
                        found = TRUE;
                    }
                    if (found)
                        break;
                }
                if (found)
                    break;
            }

            // if entry is NULL, return
            if (rtEntry == NULL)
                return rtEntry;

            switch (oidIndex){
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = GetIPv4Address(rtEntry->destination);
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex =  rtEntry->outInterface + 1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &rtEntry->hopCount;
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = GetIPv4Address(rtEntry->nextHop);
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if (rtEntry->hopCount == 1)
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else if (rtEntry->hopCount == -1)
                    {
                        *routeType = 1;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = rtEntry->lifetime/SECOND;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = ConvertNumHostBitsToSubnetMask(
                        ip->interfaceInfo[interfaceId]->numHostBits);
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
            break;
        }
        case ROUTING_PROTOCOL_DYMO:
        {
            DymoData* dymo = NULL;
            dymo = (DymoData*) NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_DYMO,
                                NETWORK_IPV4);
            DymoRouteEntry* rtEntry = NULL;
            int i=0;
            int hashIndex = 0;
            BOOL    found = FALSE;

            //increase the routing table index by one because it begins with 0
            routeIndex++;

            for (i = 0; i < DYMO_ROUTE_HASH_TABLE; i++)
            {
                for (rtEntry = dymo->routeTable.routeHashTable[i]; rtEntry != NULL;
                    rtEntry = rtEntry->hashNext)
                {
                    hashIndex++;
                    if (hashIndex == routeIndex)
                    {
                        //routeIndex's entry in the routing table found
                        found = TRUE;
                    }
                    if (found)
                        break;
                }
                if (found)
                    break;
            }
            // if entry is NULL, return
            if (rtEntry == NULL)
                return rtEntry;

            switch (oidIndex)
            {
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = GetIPv4Address(rtEntry->destination);
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex =  rtEntry->intface +1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &(rtEntry->hopCount);
                    break;
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = GetIPv4Address(rtEntry->nextHop);
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if (rtEntry->hopCount == 1)
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = 0;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = ConvertNumHostBitsToSubnetMask(
                        ip->interfaceInfo[interfaceId]->numHostBits);
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
            break;
        }
        case ROUTING_PROTOCOL_DSR:
        {
            DsrData* dsr = (DsrData*)
                NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DSR);
            DsrRouteCache* rtCache = &dsr->routeCache;
            DsrRouteEntry* rtEntry = NULL;
            int hashIndex = 0;
            BOOL    found = FALSE;
            for (rtEntry = rtCache->deleteListHead; rtEntry != NULL; rtEntry = rtEntry->deleteNext)
            {
                if (hashIndex == routeIndex)
                {
                    //routeIndex's entry in the routing table found
                    found = TRUE;
                }
                if (found)
                    break;
                else
                    hashIndex++;
            }

            if (rtEntry == NULL)
                return rtEntry;

            switch (oidIndex) {
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = rtEntry->destAddr;
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex = 1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &(rtEntry->hopCount);
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = rtEntry->path[rtEntry->hopCount - 1];
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if (rtEntry->hopCount == 1)
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = rtEntry->routeEntryTime/SECOND;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = (ip->interfaceInfo[interfaceId]->ipAddrNetMask);
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
            break;
        }
        case ROUTING_PROTOCOL_FSRL:
        {
            FsrlData* fisheye = (FsrlData*) NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_FSRL);
            FisheyeRoutingTable* routingTable = &(fisheye->routingTable);
            switch (oidIndex)
            {
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = (routingTable->row)[routeIndex].destAddr;
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex =  (routingTable->row)[routeIndex].outgoingInterface +1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &((routingTable->row)[routeIndex].distance);
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = (routingTable->row)[routeIndex].nextHop;
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if ((routingTable->row)[routeIndex].distance == 1)
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = 0;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = (ip->interfaceInfo[(routingTable->row)[routeIndex].outgoingInterface]->ipAddrNetMask);
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
            break;
        }
        case ROUTING_PROTOCOL_STAR:
        {
            break;
        }
        case ROUTING_PROTOCOL_IARP:
        {
            IarpData* iarpData = (IarpData*) NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_IARP);

            switch (oidIndex) {
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = iarpData->routeTable.routingTable[routeIndex].destinationAddress;
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex = iarpData->routeTable.routingTable[routeIndex].outGoingInterface +1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &(iarpData->routeTable.routingTable[routeIndex].hopCount);
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = iarpData->routeTable.routingTable[routeIndex].nextHopAddress;
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if (iarpData->routeTable.routingTable[routeIndex].hopCount == 1)
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = iarpData->routeTable.routingTable[routeIndex].lastHard/SECOND;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = iarpData->routeTable.routingTable[routeIndex].subnetMask;
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
            break;
        }
        case ROUTING_PROTOCOL_ZRP:
        {
            return NULL;
        }
        case ROUTING_PROTOCOL_IERP:
        {
            return NULL;
        }
#endif
        default:
            NetworkForwardingTable* rt = &ip->forwardTable;
            switch (oidIndex) {
                case I_ipRouteDest:
                    NodeAddress* destAddr;
                    destAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *destAddr = rt->row[routeIndex].destAddress;
                    return destAddr;
                case I_ipRouteIfIndex:
                    int*  ifIndex;
                    ifIndex = (int*)MEM_malloc(sizeof(int));
                    *ifIndex = rt->row[routeIndex].interfaceIndex +1;
                    return ifIndex;
                case I_ipRouteMetric1:
                    return &(rt->row[routeIndex].cost);
                case I_ipRouteMetric2:
                case I_ipRouteMetric3:
                case I_ipRouteMetric4:
                case I_ipRouteNextHop:
                    NodeAddress* nextHopAddr;
                    nextHopAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *nextHopAddr = rt->row[routeIndex].nextHopAddress;
                    return nextHopAddr;
                case I_ipRouteType:
                    int*  routeType;
                    routeType = (int*)MEM_malloc(sizeof(int));
                    if (rt->row[routeIndex].cost == 1) //direct
                    {
                        *routeType = 3;
                        return routeType;
                    }
                    else
                    {
                        *routeType = 4;
                        return routeType;
                    }
                case I_ipRouteProto:
                case I_ipRouteAge:
                    int*  routeAge;
                    routeAge = (int*)MEM_malloc(sizeof(int));
                    *routeAge = 0;
                    return routeAge;
                case I_ipRouteMask:
                    NodeAddress* netMask;
                    netMask = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
                    *netMask = rt->row[routeIndex].destAddressMask;
                    return netMask;
                case I_ipRouteMetric5:
                case I_ipRouteInfo:
                    break;
            }
    } //switch (ip->interfaceInfo[i]->routingProtocolType)
    return NO_MIBINSTANCE;
}



int SNMP_GetMaxTableSize1(Node*  node, unsigned int interfaceId)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    switch (ip->interfaceInfo[interfaceId]->routingProtocolType)
    {
#ifdef WIRELESS_LIB
        case ROUTING_PROTOCOL_LAR1:
        {
            if (NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_LAR1))
            {
                //get the size of routing table in LAR1 routing table
            }
            break;
        }
        case ROUTING_PROTOCOL_AODV:
        {
            AodvData* aodv = NULL;

            aodv = (AodvData*)(NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_AODV));
            return aodv->routeTable.size;
        }
        case ROUTING_PROTOCOL_DYMO:
        {
            DymoData* dymo = NULL;
            dymo = (DymoData*) NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_DYMO,
                                NETWORK_IPV4);
            return dymo->routeTable.size;
        }
        case ROUTING_PROTOCOL_DSR:
        {
            DsrData* dsr = (DsrData*)
                NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_DSR);
            DsrRouteCache* rtCache = &dsr->routeCache;
            return rtCache->count;
        }
        case ROUTING_PROTOCOL_FSRL:
        {
            FsrlData* fisheye = (FsrlData*) NetworkIpGetRoutingProtocol(
                                node,
                                ROUTING_PROTOCOL_FSRL);
            FisheyeRoutingTable* routingTable = &(fisheye->routingTable);
            return routingTable->rtSize;
        }
        case ROUTING_PROTOCOL_STAR:
        {
            return 0;
        }
        case ROUTING_PROTOCOL_IARP:
        {
            IarpData* iarpData = (IarpData*) NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_IARP);
            return iarpData->routeTable.numEntries;
        }
        case ROUTING_PROTOCOL_ZRP:
        {
            return 0;
        }
        case ROUTING_PROTOCOL_IERP:
        {
            return 0;
        }
#endif
        default:
            NetworkForwardingTable* rt = &ip->forwardTable;
            return rt->size;
    } //switch (ip->interfaceInfo[i]->routingProtocolType)
return 0;
}
