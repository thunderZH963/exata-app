/*
 * container_list_sl.h
 * $Id: container_list_ssll.h 11068 2004-09-14 02:29:16Z rstory $
 *
 */
#ifndef NETSNMP_CONTAINER_SSLL_H_NETSNMP
#define NETSNMP_CONTAINER_SSLL_H_NETSNMP


#include "containers_netsnmp.h"


    netsnmp_container* netsnmp_container_get_sorted_singly_linked_list(void);
    netsnmp_container* netsnmp_container_get_singly_linked_list(int fifo);

#endif /** NETSNMP_CONTAINER_SSLL_H */
