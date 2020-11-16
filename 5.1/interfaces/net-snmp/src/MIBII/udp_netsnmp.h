/*
 *  Template MIB group interface - udp_netsnmp.h
 *
 */
#ifndef _MIBGROUP_UDP_H_NETSNMP
#define _MIBGROUP_UDP_H_NETSNMP

extern Netsnmp_Node_Handler udp_handler;
extern FindVarMethod var_udp;
extern FindVarMethod var_udpEntry;

#define UDPINDATAGRAMS        1
#define UDPNOPORTS            2
#define UDPINERRORS            3
#define UDPOUTDATAGRAMS     4
#define UDPTABLE            5

#endif                          /* _MIBGROUP_UDP_H_NETSNMP */
