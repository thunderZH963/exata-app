#include <net-snmp-config_netsnmp.h>
#include "asn1_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "string.h"
#include "snmp_api_netsnmp.h"
#include "snmp_vars_netsnmp.h"
#include "ip_netsnmp.h"
#include "var_route_netsnmp.h"
#include "system_netsnmp.h"
#include "network_ip.h"

#define FIRST_ITEM  0

struct routeEntry {
    int i;
    NetworkForwardingTableRow row;
};

u_char*
var_ipRouteEntry(struct variable* vp,
                    oid* name,
                    size_t* length,
                    int exact,
                    u_char*  var_buf,
                    size_t* var_len,
                    WriteMethod** write_method,
                    Node* node)
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    oid             lowest[14];
    oid             current[14], *op;
    int             lowinterface = -1;

    void*  ipRouteEntryValue=NULL;
    int maxTableSize;
    NodeAddress* tempNodeAddr;
    tempNodeAddr = (NodeAddress*)MEM_malloc(sizeof(NodeAddress));
    maxTableSize = SNMP_GetMaxTableSize1(node, DEFAULT_INTERFACE);
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    int i=0;
    static int vp_type;

    memcpy(current, vp->name, (int) vp->namelen * sizeof(oid));

    vp_type=vp->type;
    NodeAddress aaa;
    int interface_found=0;
    NetworkForwardingTable* rt = &ip->forwardTable;
    map<NodeAddress, routeEntry> intfaceInfo;
    map<NodeAddress, routeEntry>::iterator it;
    for (i=0; i < maxTableSize; i++) {
        routeEntry rE;
        rE.i = i;
        rE.row = rt->row[i];
        intfaceInfo.insert(pair<NodeAddress, routeEntry>
            (rt->row[i].destAddress, rE));
    }
    i = 0;
    for (it = intfaceInfo.begin(); it != intfaceInfo.end(); it++) {
        op = &current[10];
        aaa = it->first;
        EXTERNAL_hton(&aaa, sizeof(aaa));
        unsigned char*  qqq = (unsigned char*)&aaa;
        if (op[0] == qqq[0] && op[1] == qqq[1] &&
            op[2] == qqq[2] && op[3] == qqq[3])
        {
            interface_found = 1;
            break;
        }
        i++;
    }
    if (interface_found != 1) return NULL;

    memcpy(name, current, 14 * sizeof(oid));
    *length = 14;

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    switch (vp->magic) {
    case IPROUTEDEST:
            vp->type = ASN_IPADDRESS;
            if (i >= maxTableSize) // last item of address entry
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 2);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(long_return, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    return (unsigned char*) long_return;
                }
                else
                    return NO_MIBINSTANCE;
            }
            *var_len = 4;
            if (i < maxTableSize)
            {
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 1);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(tempNodeAddr,ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    EXTERNAL_hton(tempNodeAddr, sizeof(NodeAddress));
                    return (unsigned char*)tempNodeAddr;
                }
                else
                    return NO_MIBINSTANCE;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTEIFINDEX:
        vp->type = ASN_INTEGER;
        if (i >= maxTableSize) // last item of interface index
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 3);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(long_return, ipRouteEntryValue, 4);
                    return (unsigned char*) long_return;
                }
                else
                    return NO_MIBINSTANCE;
            }

            *var_len = 4;
            if (i < maxTableSize)
            {
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 2);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(long_return, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    return (unsigned char*) long_return;
                }
                else
                    return NO_MIBINSTANCE;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTEMETRIC1:
        vp->type = ASN_INTEGER;
        if (i >= maxTableSize) // last item of RouteMetric1
            {
                *var_len = sizeof(Int32);
                *long_return = -1;
                return (unsigned char*) long_return;
            }

            *var_len = 4;
            ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 3);
            if (ipRouteEntryValue != NULL)
            {
                memcpy(long_return, ipRouteEntryValue, 4);
                return (unsigned char*) long_return;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTEMETRIC2:
            vp->type = ASN_INTEGER;
         if (i >= maxTableSize) // last item of RouteMetric2
            {
                *var_len = sizeof(Int32);
                *long_return = -1;
                return (unsigned char*) long_return;
            }

            *var_len = 4;
            *long_return = -1;
            return (unsigned char*) long_return;
    case IPROUTEMETRIC3:
            vp->type = ASN_INTEGER;
        if (i > maxTableSize) // last item of RouteMetric3
            {
               *var_len = sizeof(Int32);
                *long_return = -1;
                return (unsigned char*) long_return;
            }
            *var_len = 4;
            *long_return = -1;
            return (unsigned char*) long_return;
    case IPROUTEMETRIC4:
            vp->type = ASN_INTEGER;
           if (i >= maxTableSize) // last item of RouteMetric4
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 6);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(tempNodeAddr, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    EXTERNAL_hton(tempNodeAddr, sizeof(NodeAddress));
                    return (unsigned char*)tempNodeAddr;
                }
                else
                    return NO_MIBINSTANCE;
            }
            *var_len = 4;
            *long_return = -1;
            return (unsigned char*) long_return;
    case IPROUTEMETRIC5:
            vp->type = ASN_INTEGER;
            if (i > maxTableSize) // last item of Route metric5
            {
                *var_len = sizeof(Int32);
                *long_return = 0;
                return (unsigned char*) long_return;
            }
            *var_len = 4;
            *long_return = -1;
            return (unsigned char*) long_return;
    case IPROUTENEXTHOP:
        vp->type = ASN_IPADDRESS;
        if (i >= maxTableSize) // last item of next hop
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 7);
                EXTERNAL_hton(ipRouteEntryValue, sizeof(Int32));
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(long_return, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    return (unsigned char*) long_return;
                }
                    return NO_MIBINSTANCE;
            }
            *var_len = 4;
            ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 7);
            if (ipRouteEntryValue != NULL)
            {
                memcpy(tempNodeAddr, ipRouteEntryValue, 4);
                MEM_free(ipRouteEntryValue);
                EXTERNAL_hton(tempNodeAddr, sizeof(NodeAddress));
                return (unsigned char*)tempNodeAddr;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTETYPE:
        vp->type = ASN_INTEGER;
        if (i >= maxTableSize) // last item of Route type
            {
                *var_len = sizeof(Int32);
                *long_return = 1;
                return (unsigned char*) long_return;
            }
            *var_len = 4;
            ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 8);
            if (ipRouteEntryValue != NULL)
            {
                memcpy(long_return, ipRouteEntryValue, 4);
                MEM_free(ipRouteEntryValue);
                return (unsigned char*) long_return;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTEPROTO:
        vp->type = ASN_INTEGER;
        if (i >= maxTableSize) // last item of Route Protocol
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 9);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(long_return, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    return (unsigned char*) long_return;
                }
                else
                    return NO_MIBINSTANCE;
            }
            *var_len = 4;
            *long_return = 1;
            return (unsigned char*) long_return;
    case IPROUTEAGE:
        vp->type = ASN_INTEGER;
        if (i >= maxTableSize) // last item of Route Age
            {
                *var_len = sizeof(Int32);
                ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, FIRST_ITEM, 10);
                if (ipRouteEntryValue != NULL)
                {
                    memcpy(tempNodeAddr, ipRouteEntryValue, 4);
                    MEM_free(ipRouteEntryValue);
                    EXTERNAL_hton(tempNodeAddr, sizeof(NodeAddress));
                    return (unsigned char*)tempNodeAddr;
                }
                else
                    return NO_MIBINSTANCE;
            }
            *var_len = 4;
            ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 10);
            if (ipRouteEntryValue != NULL)
            {
                memcpy(long_return, ipRouteEntryValue, 4);
                MEM_free(ipRouteEntryValue);
                return (unsigned char*) long_return;
            }
            else
                return NO_MIBINSTANCE;
    case IPROUTEMASK:
        vp->type = ASN_IPADDRESS;
        if (i >= maxTableSize) // last item of Route Mask
        {
            *var_len = sizeof(Int32);
            *long_return = -1;
            return (unsigned char*) long_return;
        }
        *var_len = 4;
        ipRouteEntryValue = SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, i, 11);
        if (ipRouteEntryValue != NULL)
        {
            memcpy(tempNodeAddr, ipRouteEntryValue, 4);
            MEM_free(ipRouteEntryValue);
            EXTERNAL_hton(tempNodeAddr, sizeof(NodeAddress));
            return (unsigned char*)tempNodeAddr;
        }
        else
            return NO_MIBINSTANCE;
    case IPROUTEINFO:
        vp->type = ASN_OBJECT_ID;
        if (exact == 0)
            i = 0;
        if (name[*length-1] >= (unsigned int)maxTableSize) // last item of Route Info
        {
            *var_len = sizeof(Int32);
            *long_return = 0;
            return (unsigned char*) long_return;
        }
        *var_len = 4;
        *long_return = 0;
        return (unsigned char*) long_return;
    break;
    }
    return NULL;
}
