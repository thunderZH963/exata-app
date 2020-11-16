/*
 * bulk_to_next.h
 */
#ifndef BULK_TO_NEXT_H_NETSNMP
#define BULK_TO_NEXT_H_NETSNMP

#include "agent_handler_netsnmp.h"
/*
 * The helper merely intercepts GETBULK requests and converts them to
 * * GETNEXT reequests.
 */

Netsnmp_Node_Handler netsnmp_bulk_to_next_helper;
void netsnmp_bulk_to_next_fix_requests(netsnmp_request_info* requests);

#endif /* BULK_TO_NEXT_H_NETSNMP */
