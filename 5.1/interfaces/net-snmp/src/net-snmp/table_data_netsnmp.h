/*
 * table_iterator.h
 */
#ifndef _TABLE_DATA_HANDLER_H_NETSNMP
#define _TABLE_DATA_HANDLER_H_NETSNMP

#include "agent_handler_netsnmp.h"
#include "table_netsnmp.h"


#define TABLE_DATA_NAME "table_data"
#define TABLE_DATA_ROW  "table_data"
#define TABLE_DATA_TABLE "table_data_table"

    typedef struct netsnmp_table_row_s {
        netsnmp_variable_list* indexes; /* stored permanently if store_indexes = 1 */
        oid*            index_oid;
        size_t          index_oid_len;
        void*           data;   /* the data to store */

        struct netsnmp_table_row_s* next, *prev;        /* if used in a list */
    } netsnmp_table_row;

    typedef struct netsnmp_table_data_s {
        netsnmp_variable_list* indexes_template;        /* containing only types */
        char*           name;   /* if !NULL, it's registered globally */
        int             flags;  /* not currently used */
        int             store_indexes;
        netsnmp_table_row* first_row;
        netsnmp_table_row* last_row;
    } netsnmp_table_data;

    netsnmp_table_data* netsnmp_create_table_data(const char* name);
      netsnmp_table_row*  netsnmp_create_table_data_row(void);
    netsnmp_table_row*  netsnmp_table_data_clone_row(netsnmp_table_row*  row);
    void*               netsnmp_table_data_delete_row(netsnmp_table_row*  row);
    int                 netsnmp_table_data_add_row(netsnmp_table_data* table,
                                                      netsnmp_table_row*  row);
    void
       netsnmp_table_data_replace_row(netsnmp_table_data* table,
                                      netsnmp_table_row* origrow,
                                      netsnmp_table_row* newrow);
    void*   netsnmp_table_data_remove_and_delete_row(netsnmp_table_data* table,
                                                     netsnmp_table_row*  row);
    void*          netsnmp_extract_table_row_data(netsnmp_request_info*);
    int netsnmp_table_data_build_result(struct netsnmp_handler_registration_s* reginfo,
                                        netsnmp_agent_request_info*   reqinfo,
                                        netsnmp_request_info*         request,
                                        netsnmp_table_row* row, int column,
                                        u_char type, u_char*  result_data,
                                        size_t result_data_len);

#define netsnmp_table_data_add_index(thetable, type) snmp_varlist_add_variable(&thetable->indexes_template, NULL, 0, type, NULL, 0)
#define netsnmp_table_row_add_index(row, type, value, value_len) snmp_varlist_add_variable(&row->indexes, NULL, 0, type, (const u_char*) value, value_len)



#endif                          /* _TABLE_DATA_HANDLER_H_NETSNMP */
