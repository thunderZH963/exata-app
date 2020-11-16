/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/*
 * @file netsnmp_data_list.h
 *
 * @addtogroup agent
 * @addtogroup library *
 *
 * $Id: data_list.h 16926 2008-05-10 09:30:39Z magfr $
 *
 * External definitions for functions and variables in netsnmp_data_list.c.
 *
 * @{
 */

#ifndef DATA_LIST_H_NETSNMP
#define DATA_LIST_H_NETSNMP

/** @struct netsnmp_data_list_s
 * used to iterate through lists of data
 */
typedef void    (Netsnmp_Free_List_Data) (void*);

typedef struct netsnmp_data_list_s {
    struct netsnmp_data_list_s* next;
    char*           name;
     /** The pointer to the data passed on. */
        void*           data;
        /** must know how to free netsnmp_data_list->data */
        Netsnmp_Free_List_Data* free_func;
} netsnmp_data_list;

void netsnmp_free_list_data(netsnmp_data_list* head);    /* single */
void*           netsnmp_get_list_data(netsnmp_data_list* head,
                                          const char* node);
netsnmp_data_list*
      netsnmp_create_data_list(const char* , void* , Netsnmp_Free_List_Data*);
    void            netsnmp_data_list_add_node(netsnmp_data_list** head,
                                               netsnmp_data_list* node);
        void            netsnmp_add_list_data(netsnmp_data_list** head,
                                          netsnmp_data_list* node);
        int
netsnmp_remove_list_node(netsnmp_data_list** realhead, const char* name);

        void
netsnmp_free_all_list_data(netsnmp_data_list* head);
#endif /* DATA_LIST_H_NETSNMP */

