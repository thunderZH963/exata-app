/*
 * testhandler.h
 */
#ifndef NETSNMP_INSTANCE_H_NETSNMP
#define NETSNMP_INSTANCE_H_NETSNMP

#include "agent_handler_netsnmp.h"

/*
 * The instance helper is designed to simplify the task of adding simple
 * * instances to the mib tree.
 */

/*
 * GETNEXTs are auto-converted to a GET.
 * * non-valid GETs are dropped.
 * * The client can assume that if you're called for a GET, it shouldn't
 * * have to check the oid at all.  Just answer.
 */




#define INSTANCE_HANDLER_NAME "instance"

netsnmp_mib_handler* netsnmp_get_instance_handler(void);




/* identical functions that register a in a particular context */

Netsnmp_Node_Handler netsnmp_instance_helper_handler;
Netsnmp_Node_Handler netsnmp_instance_ulong_handler;
Netsnmp_Node_Handler netsnmp_instance_long_handler;
Netsnmp_Node_Handler netsnmp_instance_int_handler;
Netsnmp_Node_Handler netsnmp_instance_uint_handler;
Netsnmp_Node_Handler netsnmp_instance_counter32_handler;
Netsnmp_Node_Handler netsnmp_instance_num_file_handler;



#endif /** NETSNMP_INSTANCE_H */
