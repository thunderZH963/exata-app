#ifndef STASH_TO_NEXT_H_NETSNMP
#define STASH_TO_NEXT_H_NETSNMP

#include "agent_handler_netsnmp.h"

/*
 * The helper merely intercepts GETSTASH requests and converts them to
 * GETNEXT reequests.
 */


netsnmp_mib_handler* netsnmp_get_stash_to_next_handler(void);
Netsnmp_Node_Handler netsnmp_stash_to_next_helper;


#endif
