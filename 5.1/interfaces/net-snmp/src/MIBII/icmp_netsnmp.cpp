
#include "net-snmp-config_netsnmp.h"

#include "cache_handler_netsnmp.h"
#include "scalar_group_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "netSnmpAgent.h"
#include "types_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include <network_ip.h>
#include <network_icmp.h>

#include "icmp_netsnmp.h"

/*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath
 */
oid         icmp_oid[]               = { SNMP_OID_MIB2, 5 };

struct variable3 icmp_variables[] = {
    {ICMPINMSGS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {1}},
    {ICMPINERRORS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {2}},
    {ICMPINDESTUNREACHS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {3}},
    {ICMPINTIMEEXCDS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {4}},
    {ICMPINPARMPROBS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {5}},
    {ICMPINSRCQUENCHS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {6}},
    {ICMPINREDIRECTS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {7}},
    {ICMPINECHOS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {8}},
    {ICMPINECHOREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {9}},
    {ICMPINTIMESTAMPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {10}},
    {ICMPINTIMESTAMPREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {11}},
    {ICMPINADDRMASKS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {12}},
    {ICMPINADDRMASKREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {13}},
    {ICMPOUTMSGS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {14}},
    {ICMPOUTERRORS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {15}},
    {ICMPOUTDESTUNREACHS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {16}},
    {ICMPOUTTIMEEXCDS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {17}},
    {ICMPOUTPARMPROBS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {18}},
    {ICMPOUTSRCQUENCHS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {19}},
    {ICMPOUTREDIRECTS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {20}},
    {ICMPOUTECHOS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {21}},
    {ICMPOUTECHOREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {22}},
    {ICMPOUTTIMESTAMPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {23}},
    {ICMPOUTTIMESTAMPREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {24}},
    {ICMPOUTADDRMASKS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {25}},
    {ICMPOUTADDRMASKREPS, ASN_COUNTER32, NETSNMP_OLDAPI_RONLY,
     var_icmp, 1, {26}}
};

void
NetSnmpAgent::init_icmp(void)
{
#ifdef SNMP_DEBUG
    printf("init_icmp:Initializing MIBII/icmp at node %d\n",node->nodeId);
#endif
    REGISTER_MIB("mibII/icmp", icmp_variables, variable3, icmp_oid);
}

u_char*
var_icmp(struct variable*  vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_icmp:handler MIBII/icmp at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name,(int) vp->namelen * sizeof(oid));
    (*length)= (int) vp->namelen;
    if (*length == 8)
    {
        name[*length] = 0;
        (*length)++;
    }
    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = 4;
    NetworkDataIp* ipLayer = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp* icmp = (NetworkDataIcmp*) ipLayer->icmpStruct;
    if (icmp){
        IcmpStat icmpStat = icmp->icmpStat;
        IcmpErrorStat icmpErrorStat = icmp->icmpErrorStat;
        switch (vp->magic) {
            case ICMPINMSGS:
                *long_return = icmpStat.icmpEchoReceived +
                            icmpStat.icmpTimestampReceived;
                return (unsigned char*) long_return;
            case ICMPINERRORS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPINDESTUNREACHS:
                *long_return = icmpErrorStat.icmpNetworkUnreacableRecd +
                            icmpErrorStat.icmpHostUnreacableRecd ;
                return (unsigned char*) long_return;
            case ICMPINTIMEEXCDS:
                *long_return = icmpErrorStat.icmpTTLExceededRecd;
                return (unsigned char*) long_return;
            case ICMPINPARMPROBS:
                *long_return = icmpErrorStat.icmpParameterProblemRecd;
                return (unsigned char*) long_return;
            case ICMPINSRCQUENCHS:
                *long_return = icmpErrorStat.icmpSrcQuenchRecd;
                return (unsigned char*) long_return;
            case ICMPINREDIRECTS:
                *long_return = icmpErrorStat.icmpRedirectReceive;
                return (unsigned char*) long_return;
            case ICMPINECHOS:
                *long_return = icmpStat.icmpEchoReceived;
                return (unsigned char*) long_return;
            case ICMPINECHOREPS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPINTIMESTAMPS:
                *long_return = icmpStat.icmpTimestampReceived;
                return (unsigned char*) long_return;
            case ICMPINTIMESTAMPREPS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPINADDRMASKS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPINADDRMASKREPS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPOUTMSGS:
                *long_return = icmpStat.icmpEchoReplyGenerated +
                            icmpStat.icmpTimestampReplyGenerated;
                return (unsigned char*) long_return;
            case ICMPOUTERRORS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPOUTDESTUNREACHS:
                *long_return = icmpErrorStat.icmpNetworkUnreacableSent +
                            icmpErrorStat.icmpHostUnreacableSent;
                return (unsigned char*) long_return;
            case ICMPOUTTIMEEXCDS:
                *long_return = icmpErrorStat.icmpTTLExceededSent;
                return (unsigned char*) long_return;
            case ICMPOUTPARMPROBS:
                *long_return = icmpErrorStat.icmpParameterProblemSent;
                return (unsigned char*) long_return;
            case ICMPOUTSRCQUENCHS:
                *long_return = icmpErrorStat.icmpSrcQuenchSent;
                return (unsigned char*) long_return;
            case ICMPOUTREDIRECTS:
                *long_return = icmpErrorStat.icmpRedirctGenerate;
                return (unsigned char*) long_return;
            case ICMPOUTECHOS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPOUTECHOREPS:
                *long_return = icmpStat.icmpEchoReplyGenerated;
                return (unsigned char*) long_return;
            case ICMPOUTTIMESTAMPS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPOUTTIMESTAMPREPS:
                *long_return = icmpStat.icmpTimestampReplyGenerated;
                return (unsigned char*) long_return;
            case ICMPOUTADDRMASKS:
                *long_return = 0;
                return (unsigned char*) long_return;
            case ICMPOUTADDRMASKREPS:
                *long_return = 0;
                return (unsigned char*) long_return;
        }
    }
    else
    {
        *long_return = 0;
        return (unsigned char*) long_return;
    }
    return NO_MIBINSTANCE;
}
