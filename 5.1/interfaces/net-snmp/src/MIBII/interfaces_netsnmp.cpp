/*
 *  Interfaces MIB group implementation - interfaces.c
 *
 */

/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include "net-snmp-config_netsnmp.h"
#include "types_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "agent_registry_netsnmp.h"
#include "netSnmpAgent.h"

#include "interfaces_netsnmp.h"
#include "header_generic_netsnmp.h"
#include "snmp_agent_netsnmp.h"
#include <network_ip.h>

oid             nullOid[] = { 0, 0 };
int             nullOidLen = sizeof(nullOid);

struct timeval convert_2_timeval(clocktype nanosec);

struct variable3 interfaces_variables[] = {
    {NETSNMP_IFNUMBER, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_interfaces, 1, {1}},
    {NETSNMP_IFINDEX, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 1}},
    {NETSNMP_IFDESCR, ASN_OCTET_STR, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 2}},
    {NETSNMP_IFTYPE, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 3}},
    {NETSNMP_IFMTU, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 4}},
    {NETSNMP_IFSPEED, ASN_GAUGE, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 5}},
    {NETSNMP_IFPHYSADDRESS, ASN_OCTET_STR, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 6}},
    {NETSNMP_IFADMINSTATUS, ASN_INTEGER, NETSNMP_OLDAPI_RWRITE,
     var_ifEntry, 3, {2, 1, 7}},
    {NETSNMP_IFOPERSTATUS, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 8}},
    {NETSNMP_IFLASTCHANGE, ASN_TIMETICKS, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 9}},
    {NETSNMP_IFINOCTETS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 10}},
    {NETSNMP_IFINUCASTPKTS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 11}},
    {NETSNMP_IFINNUCASTPKTS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 12}},
    {NETSNMP_IFINDISCARDS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 13}},
    {NETSNMP_IFINERRORS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 14}},
    {NETSNMP_IFINUNKNOWNPROTOS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 15}},
    {NETSNMP_IFOUTOCTETS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 16}},
    {NETSNMP_IFOUTUCASTPKTS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 17}},
    {NETSNMP_IFOUTNUCASTPKTS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 18}},
    {NETSNMP_IFOUTDISCARDS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 19}},
    {NETSNMP_IFOUTERRORS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 20}},
    {NETSNMP_IFOUTQLEN, ASN_GAUGE, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 21}},
    {NETSNMP_IFSPECIFIC, ASN_OBJECT_ID, NETSNMP_OLDAPI_RONLY,
     var_ifEntry, 3, {2, 1, 22}}
};

/*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath, and the OID of the MIB module
 */
oid             interfaces_variables_oid[] = { SNMP_OID_MIB2, 2 };
oid             interfaces_module_oid[] = { SNMP_OID_MIB2, 31 };

void
NetSnmpAgent::init_interfaces(void)
{
#ifdef SNMP_DEBUG
    printf("init_interfaces:Initializing MIBII/interfaces at node %d\n",node->nodeId);
#endif
    /*
     * register ourselves with the agent to handle our mib tree
     */
    REGISTER_MIB("mibII/interfaces", interfaces_variables, variable3,
                 interfaces_variables_oid);
    REGISTER_SYSOR_ENTRY(interfaces_module_oid,
                        (char*)"The MIB module to describe generic objects"
                        " for network interface sub-layers");
}

WriteMethod     writeIfEntry;
Int32            admin_status = 0;
Int32            oldadmin_status = 0;

u_char*
var_interfaces(struct variable*  vp,
                oid* name,
                size_t* length,
                int exact,
                u_char*  var_buf,
                size_t* var_len,
                WriteMethod** write_method,
                Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_interfaces:handler MIBII/interfaces at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name,(int) vp->namelen * sizeof(oid));
    (*length)= (int) vp->namelen;

    if (*length == 8)
    {
        name[*length] = 1;
        (*length)++;
    }
    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    switch (vp->magic) {
        case NETSNMP_IFNUMBER:
            *write_method = 0;
            *var_len = sizeof(long_return);
            *long_return = node->numberInterfaces;
            return (unsigned char*) long_return;
    }
    return NO_MIBINSTANCE;
}

u_char*
var_ifEntry(struct variable*  vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_ifEntry:handler MIBII/ifEntry at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name,(int) vp->namelen*  sizeof(oid));
    (*length)= (int) vp->namelen;
    //length has been incremented to include the interface index in the OID
    //and if last byte of OID is 0 is changed to 1, since, interface index
    //for this interface MIB starts with 1.
    if (*length == 10)
    {
        if (name[*length] == 0)
        {
            name[*length] = 1;
        }
        (*length)++;
    }
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    char returnStr[ 128 ];
    if (name[*length-1] > (unsigned int)node->numberInterfaces)
    {
        return NO_MIBINSTANCE;
    }
    //the NetSNMP interface index starts from 1
    //while the Qualnet interface index is from 0
    int interfaceIndex = name[(*length - 1)] - 1;
    if (ip)
    {
        switch (vp->magic) {
        case NETSNMP_IFINDEX:
            *var_len = 4;
            *long_return = interfaceIndex;
            return (unsigned char*) long_return;
        case NETSNMP_IFDESCR:
            sprintf(returnStr, "%s",(const char*)
                ip->interfaceInfo[interfaceIndex]->ifDescr);
            *var_len = strlen(returnStr);
            memcpy(var_buf, returnStr, *var_len);
            return var_buf;
        case NETSNMP_IFTYPE:
            *long_return = 1;
            *var_len = sizeof(Int32);
             return (unsigned char*) long_return;
        case NETSNMP_IFMTU:
            *long_return = DEFAULT_ETHERNET_MTU;
            *var_len = sizeof(Int32);
            return (unsigned char*) long_return;
        case NETSNMP_IFSPEED:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->bandwidth;
            return (unsigned char*) long_return;
        case NETSNMP_IFPHYSADDRESS:
            memcpy(var_buf, node->macData[interfaceIndex]->macHWAddr.byte,
                node->macData[interfaceIndex]->macHWAddr.hwLength);
            *var_len = node->macData[interfaceIndex]->macHWAddr.hwLength;
            return var_buf;
        case NETSNMP_IFADMINSTATUS:
            *long_return = 1;
            *var_len = sizeof(Int32);
            admin_status = *long_return;
            *write_method = NULL;
            return (u_char*) long_return;
        case NETSNMP_IFOPERSTATUS:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->interfaceIsEnabled;
            return (unsigned char*) long_return;
        case NETSNMP_IFLASTCHANGE:
            *var_len = sizeof(Int32);
            if (node->macData[interfaceIndex]->interfaceState == INTERFACE_DOWN)
            {
                timeval temp = convert_2_timeval(
                    node->macData[interfaceIndex]->interfaceDownTime);
                *long_return = netsnmp_timeval_uptime(&temp);
            }
            else
            {
                timeval temp = convert_2_timeval(
                    node->macData[interfaceIndex]->interfaceUpTime);
                *long_return = netsnmp_timeval_uptime(&temp);
            }
            return (unsigned char*) long_return;
        case NETSNMP_IFINOCTETS:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->ifInOctets;
            return (unsigned char*) long_return;
        case NETSNMP_IFINUCASTPKTS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifInUcastPkts;
            return (unsigned char*) long_return;
        case NETSNMP_IFINNUCASTPKTS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifInNUcastPkts;
            return (unsigned char*) long_return;
        case NETSNMP_IFINDISCARDS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifInDiscards;
            return (unsigned char*) long_return;
        case NETSNMP_IFINERRORS:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->ifInErrors;
            return (unsigned char*) long_return;
        case NETSNMP_IFINUNKNOWNPROTOS:
            *var_len = sizeof(Int32);
            //0 is returned since, the associated variable for
            //IFINUNKNOWNPROTOS is not available at interface level
            *long_return = 0;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTOCTETS:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->ifOutOctets;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTUCASTPKTS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifOutUcastPkts;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTNUCASTPKTS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifOutNUcastPkts;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTDISCARDS:
            *var_len = sizeof(Int32);
            *long_return = ip->interfaceInfo[interfaceIndex]->ifOutDiscards;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTERRORS:
            *var_len = sizeof(Int32);
            *long_return = node->macData[interfaceIndex]->ifOutErrors;
            return (unsigned char*) long_return;
        case NETSNMP_IFOUTQLEN:
            *var_len = sizeof(Int32);
            //0 is returned since,
            //the associated variable for IFOUTQLEN is not available
            *long_return = 0;
            return (unsigned char*) long_return;
        case NETSNMP_IFSPECIFIC:
            *var_len = sizeof(Int32);
            *long_return = 0;
            return (unsigned char*) long_return;
        }
    }
    else
    {
        return (unsigned char*) long_return;
    }
    return NO_MIBINSTANCE;
}
