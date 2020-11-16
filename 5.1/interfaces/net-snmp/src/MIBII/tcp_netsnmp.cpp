
/*
 *  TCP MIB group implementation - tcp.c
 *
 */
#include "net-snmp-config_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "node.h"
#include "network_ip.h"
#include "agent_handler_netsnmp.h"
#include "snmp_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "var_route_netsnmp.h"
#include "netSnmpAgent.h"
#include "scalar_group_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "tcp_netsnmp.h"
#include "transport.h"
#include "transport_tcp.h"
#include "transport_tcp_timer.h"
#include "transport_tcp_var.h"

        /*********************
     *
     *  Initialisation & common implementation functions
     *
     *********************/

struct variable3 tcp_variables[] = {
    {TCPRTOALGORITHM, ASN_INTEGER, 0x01,
     var_tcp, 1, {1}},
    {TCPRTOMIN, ASN_INTEGER,   0x01,
     var_tcp, 1, {2}},
    {TCPRTOMAX, ASN_INTEGER,   0x01,
     var_tcp, 1, {3}},
    {TCPMAXCONN, ASN_INTEGER,   0x01,
     var_tcp, 1, {4}},
    {TCPACTIVEOPENS, ASN_COUNTER32,   0x01,
     var_tcp, 1, {5}},
    {TCPPASSIVEOPENS, ASN_COUNTER32,   0x01,
     var_tcp, 1, {6}},
    {TCPATTEMPTFAILS, ASN_COUNTER32, 0x01,
     var_tcp, 1, {7}},
    {TCPESTABRESETS,    ASN_COUNTER32,   0x01,
     var_tcp, 1, {8}},
    {TCPCURRESTAB,   ASN_GAUGE32,   0x01,
     var_tcp, 1, {9}},
    {TCPINSEGS,     ASN_COUNTER32,   0x01,
     var_tcp, 1, {10}},
    {TCPOUTSEGS,    ASN_COUNTER32, 0x01,
     var_tcp, 1, {11}},
    {TCPRETRANSSEGS, ASN_COUNTER32,   0x01,
     var_tcp, 1, {12}},
    {TCPCONNSTATE, ASN_INTEGER,   0x01,
     var_tcptable, 3, {13,1,1}},
    {TCPCONNLOCALADDRESS, ASN_IPADDRESS,   0x01,
     var_tcptable, 3, {13,1,2}},
    {TCPCONNLOCALPORT, ASN_INTEGER,   0x01,
     var_tcptable, 3, {13,1,3}},
    {TCPCONNREMADDRESS, ASN_IPADDRESS,   0x01,
     var_tcptable, 3, {13,1,4}},
    {TCPCONNREMPORT, ASN_INTEGER,   0x01,
     var_tcptable, 3, {13,1,5}},
    {TCPINERRS,    ASN_COUNTER32, 0x01,
     var_tcp, 1, {14}},
    {TCPOUTRSTS,    ASN_COUNTER32, 0x01,
     var_tcp, 1, {15}}

};

 /*
 * Define the OID pointer to the top of the mib tree that we're
 * registering underneath, and the OID for the MIB module
 */
oid             tcp_oid[]               = { SNMP_OID_MIB2, 6 };
oid             tcp_module_oid[]        = { SNMP_OID_MIB2, 49 };

void
NetSnmpAgent::init_tcp(void)
{
#ifdef SNMP_DEBUG
    printf("init_tcp:Initializing MIBII/tcp at node %d\n",node->nodeId);
#endif
    REGISTER_MIB("mibII/tcp",  tcp_variables,
                       variable3,tcp_oid);


}

u_char*
var_tcp(struct variable* vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_tcp:handler MIBII/tcp at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name, (int) vp->namelen * sizeof(oid));
    (*length)= (int) vp->namelen;

    if (*length == 8)
    {
        (*length)++;
    }

    *write_method = 0;

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);
    struct inpcb* inp;
    struct inpcb head;
    int inpCount = 0;

    TransportDataTcp* tcpLayer =
        (TransportDataTcp*)node->transportData.tcp;
    if (tcpLayer){
        head = tcpLayer->head;

        for (inp = head.inp_next; inp != &(tcpLayer->head); inp = inp->inp_next)
        {
            inpCount++;
        }

        if (name[*length-1] >= (unsigned int)inpCount)
        {
            return NO_MIBINSTANCE;
        }

        struct tcpstat* tcp_stat = tcpLayer->tcpStat;
        if (tcp_stat)
        {
            switch (vp->magic) {
                case TCPRTOALGORITHM:
                    *long_return =(Int32)1;
                    break;
                case TCPRTOMIN:
                    *long_return =(Int32)0;
                    break;
                case TCPRTOMAX:
                    *long_return =(Int32)0;
                    break;
                case TCPMAXCONN:
                    *long_return =(Int32)-1 ;
                    break;
                case TCPACTIVEOPENS:
                    *long_return = tcp_stat->tcps_connattempt;
                    break;
                case TCPPASSIVEOPENS:
                    *long_return = tcp_stat->tcps_accepts;
                    break;
                case TCPATTEMPTFAILS:
                    *long_return = tcp_stat->tcps_conndrops +
                                    tcp_stat->tcps_drops;
                    break;
                case TCPESTABRESETS:
                    *long_return = tcp_stat->tcps_closed;
                    break;
                case TCPCURRESTAB:
                    *long_return = tcp_stat->tcps_connects -
                                    tcp_stat->tcps_closed;
                case TCPINSEGS:
                    *long_return = tcp_stat->tcps_rcvtotal;
                    break;
                case TCPOUTSEGS:
                    *long_return = tcp_stat->tcps_sndtotal;
                    break;
                case TCPRETRANSSEGS:
                    *long_return = tcp_stat->tcps_sndrexmitpack;
                    break;
                case TCPINERRS:
                    *long_return = tcp_stat->tcps_rcvbadsum +
                                    tcp_stat->tcps_rcvbadoff +
                                           tcp_stat->tcps_rcvshort;
                case TCPOUTRSTS:
                    *long_return = tcp_stat->tcps_sndrst;
                    break;
                default:
                    return (unsigned char*) long_return;
            }
        }
        else
        {
            return (unsigned char*) long_return;
        }
    }
    else
    {
        return (unsigned char*) long_return;
    }

    return NO_MIBINSTANCE;
}

u_char*
var_tcptable(struct variable* vp,
                oid* name,
                size_t* length,
                int exact,
                u_char*  var_buf,
                size_t* var_len,
                WriteMethod** write_method,
                Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_tcptable:handler MIBII/tcptable at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name, (int) vp->namelen * sizeof(oid));
    (*length)= (int) vp->namelen;

    //length has been incremented to include the interface index in the OID
    if (*length == 10)
    {
        (*length)++;
    }

    NodeAddress ipAddress;
    struct inpcb* inp;
    struct inpcb head;
    int    inpCount = 0;
    int    i;

    // tcp layer from node pointer
    TransportDataTcp* tcpLayer =
        (TransportDataTcp*)node->transportData.tcp;

    head = tcpLayer->head;

    for (inp = head.inp_next; inp != &(tcpLayer->head); inp = inp->inp_next)
    {
        inpCount++;
    }

    *write_method = 0;

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    if (name[*length-1] >= (unsigned int)inpCount)
    {
        return NO_MIBINSTANCE;
    }

    switch (vp->magic) {
        case TCPCONNSTATE:
            inp = tcpLayer->head.inp_next;
            for (i=0; (unsigned int)i < name[*length-1]; i++)
                inp = inp->inp_next;

            if (Address_IsAnyAddress(&inp->inp_remote_addr)) //not connected->listen state
                *long_return = 2;
            else
                *long_return = 5; //established

            return (unsigned char*) long_return;
            break;
        case TCPCONNLOCALADDRESS:
            inp = tcpLayer->head.inp_next;
            for (i=0; (unsigned int)i < name[*length-1]; i++)
                inp = inp->inp_next;

            ipAddress = GetIPv4Address(inp->inp_local_addr);
            EXTERNAL_hton(&ipAddress, sizeof(ipAddress));
            *long_return = ipAddress;
               return (unsigned char*) long_return;
        case TCPCONNLOCALPORT:
            inp = tcpLayer->head.inp_next;
            for (i=0; (unsigned int)i < name[*length-1]; i++)
                inp = inp->inp_next;

            *long_return = inp->inp_local_port;
            return (unsigned char*) long_return;
        case TCPCONNREMADDRESS:
            inp = tcpLayer->head.inp_next;
            for (i=0; (unsigned int)i < name[*length-1]; i++)
                inp = inp->inp_next;

            if (Address_IsAnyAddress(&inp->inp_remote_addr))
            {
                *long_return = 0;
            }
            else
            {
                ipAddress = GetIPv4Address(inp->inp_remote_addr);
                EXTERNAL_hton(&ipAddress, sizeof(ipAddress));
                *long_return = ipAddress;
            }
            return (unsigned char*) long_return;
        case TCPCONNREMPORT:
            inp = tcpLayer->head.inp_next;
            for (i=0; (unsigned int)i < name[*length-1]; i++)
                inp = inp->inp_next;

            *long_return = inp->inp_remote_port;
            return (unsigned char*) long_return;
        default:
            return (unsigned char*) long_return;
    }

    return (unsigned char*) long_return;
}
