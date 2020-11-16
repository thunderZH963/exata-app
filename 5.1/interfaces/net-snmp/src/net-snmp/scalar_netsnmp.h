/*
 * scalar.h
 */
#ifndef NETSNMP_SCALAR_H_NETSNMP
#define NETSNMP_SCALAR_H_NETSNMP


/*
 * The scalar helper is designed to simplify the task of adding simple
 * scalar objects to the mib tree.
 */

/*
 * GETNEXTs are auto-converted to a GET.
 * * non-valid GETs are dropped.
 * * The client can assume that if you're called for a GET, it shouldn't
 * * have to check the oid at all.  Just answer.
 */

Netsnmp_Node_Handler netsnmp_scalar_helper_handler;



#endif /** NETSNMP_SCALAR_H_NETSNMP */
