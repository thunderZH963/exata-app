/*
 *  TCP MIB group interface - tcp.h
 *
 */
#ifndef _MIBGROUP_TCP_H
#define _MIBGROUP_TCP_H
#include "snmp_vars_netsnmp.h"

FindVarMethod var_tcp;
FindVarMethod var_tcptable;

Netsnmp_Node_Handler tcp_handler;


#define TCPRTOALGORITHM      1
#define TCPRTOMIN         2
#define TCPRTOMAX         3
#define TCPMAXCONN         4
#define TCPACTIVEOPENS         5
#define TCPPASSIVEOPENS      6
#define TCPATTEMPTFAILS      7
#define TCPESTABRESETS         8
#define TCPCURRESTAB         9
#define TCPINSEGS        10
#define TCPOUTSEGS        11
#define TCPRETRANSSEGS        12
#define TCPCONNTABLE        13    /* Placeholder */
#define TCPINERRS           14
#define TCPOUTRSTS          15



#define TCPCONNSTATE      1
#define TCPCONNLOCALADDRESS      2
#define TCPCONNLOCALPORT      3
#define TCPCONNREMADDRESS      4
#define TCPCONNREMPORT      5


#endif                          /* _MIBGROUP_TCP_H */
