/*
 *  UDP MIB implementation - udp.c
 *
 */

#include "net-snmp-config_netsnmp.h"
#include "types_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "cache_handler_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "netSnmpAgent.h"

#include <transport_udp.h>
#include <transport.h>
#include <network_ip.h>

#include "udp_netsnmp.h"
#include "udpTable_netsnmp.h"

#define PORT_TABLE_HASH_SIZE    503

#ifndef MIB_STATS_CACHE_TIMEOUT
#define MIB_STATS_CACHE_TIMEOUT    5
#endif
#ifndef UDP_STATS_CACHE_TIMEOUT
#define UDP_STATS_CACHE_TIMEOUT    MIB_STATS_CACHE_TIMEOUT
#endif

        /***************************************
     *
     *  Initialisation & common implementation functions
     *
         ***************************************/

/*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath, and the OID for the MIB module
 */
oid             udp_oid[]               = { SNMP_OID_MIB2, 7 };
oid             udp_module_oid[]        = { SNMP_OID_MIB2, 50 };

struct variable3 udp_variables[] = {
    {UDPINDATAGRAMS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_udp, 1, {1}},
    {UDPNOPORTS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_udp, 1, {2}},
    {UDPOUTDATAGRAMS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_udp, 1, {3}},
    {UDPINERRORS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_udp, 1, {4}},
    {UDPLOCALADDRESS, ASN_IPADDRESS, NETSNMP_OLDAPI_RONLY,
     var_udpEntry, 3, {5, 1, 1}},
    {UDPLOCALPORT, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_udpEntry, 3, {5, 1, 2}}
};

void
NetSnmpAgent::init_udp(void)
{
#ifdef SNMP_DEBUG
    printf("init_udp:Initializing MIBII/udp at node %d\n", node->nodeId);
#endif
    REGISTER_MIB("mibII/udp", udp_variables, variable3, udp_oid);
    REGISTER_SYSOR_ENTRY(udp_module_oid,
                        (char*)"The MIB module for managing UDP "
                        "implementations");

}

u_char*
var_udp(struct variable*  vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_udp:handler MIBII/udp at node %d\n",node->nodeId);
#endif

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    memcpy(name,vp->name, (int) vp->namelen * sizeof(oid));
    (*length)= (int) vp->namelen;
    if (*length == 8)
    {
        name[*length] = 0;
        (*length)++;
    }

    TransportDataUdp* udp = (TransportDataUdp*) node->transportData.udp;
    if (udp)
    {
        switch (vp->magic) {
            case UDPINDATAGRAMS:
                if (udp->udpStatsEnabled)
                {
                    *long_return = (Int32)(udp->newStats->GetDataSegmentsSent(STAT_Unicast).GetValue(node->getNodeTime()) +
                        udp->newStats->GetDataSegmentsSent(STAT_Broadcast).GetValue(node->getNodeTime()) +
                        udp->newStats->GetDataSegmentsSent(STAT_Multicast).GetValue(node->getNodeTime()));
                }
                return (unsigned char*) long_return;
            case UDPNOPORTS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case UDPOUTDATAGRAMS:
                if (udp->udpStatsEnabled)
                {
                    *long_return = (Int32)(udp->newStats->GetDataSegmentsReceived(STAT_Unicast).GetValue(node->getNodeTime()) +
                    udp->newStats->GetDataSegmentsReceived(STAT_Broadcast).GetValue(node->getNodeTime()) +
                    udp->newStats->GetDataSegmentsReceived(STAT_Multicast).GetValue(node->getNodeTime()));;
                }
                return (unsigned char*) long_return;
            case UDPINERRORS:
                *long_return = 0;
                return (unsigned char*) long_return;
        }
    }
    return (unsigned char*) long_return;
}

u_char*
var_udpEntry(struct variable*  vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_udpEntry:handler MIBII/udpEntry at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name, (int) vp->namelen*  sizeof(oid));
   (*length)= (int) vp->namelen;

    short udpEntryPort[64];
    int i, udpEntryIndex = 0;
    PortInfo* portInfo;
    PortInfo* portTable;

    portTable = (PortInfo*)node->appData.portTable;

    for (i = 0; i< PORT_TABLE_HASH_SIZE; i++)
    {
        portInfo = &(portTable[i]);
        if (portInfo->portNumber != 0)
        {
            udpEntryPort[udpEntryIndex++] = portInfo->portNumber;
        }
    }

    //length has been incremented to include the interface index in the OID
    if (*length == 10)
    {
        (*length)++;
    }

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    switch (vp->magic) {
        case UDPLOCALADDRESS:
            if (name[*length - 1] >= (unsigned int)node->numberInterfaces) // last item of IP
            {
                long_return = 0;
                return (unsigned char*) long_return;
            }
            NodeAddress ipAddress;
            ipAddress = NetworkIpGetInterfaceAddress(node,
                name[*length - 1]);
            EXTERNAL_hton(&ipAddress, sizeof(ipAddress));
            *long_return = ipAddress;
            return (unsigned char*) long_return;
        case UDPLOCALPORT:
            *var_len = sizeof(Int32);
            if (name[*length - 1] >= (unsigned int)node->numberInterfaces) // last item of port
            {
                long_return = 0;
                return (unsigned char*) long_return;
            }
            *long_return = udpEntryPort[name[(*length - 1)]];
            return (unsigned char*) long_return;
    }
    return NO_MIBINSTANCE;
}
