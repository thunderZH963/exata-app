/*
 *  util_funcs/header_generic.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_HEADER_GENERIC_H_NETSNMP
#define _MIBGROUP_UTIL_FUNCS_HEADER_GENERIC_H_NETSNMP

int header_generic(struct variable* , oid* , size_t* , int, size_t* ,
                   WriteMethod**);

#endif /* _MIBGROUP_UTIL_FUNCS_HEADER_GENERIC_H_NETSNMP */
