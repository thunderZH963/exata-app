/*
 * table_iterator.h
 */
#ifndef _TABLE_DATA_SET_HANDLER_H_NETSNMP
#define _TABLE_DATA_SET_HANDLER_H_NETSNMP


#include "table_data_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "table_netsnmp.h"

#define TABLE_DATA_SET_NAME "netsnmp_table_data_set"

/*
 * return SNMP_ERR_NOERROR or some SNMP specific protocol error id
 */
typedef int     (Netsnmp_Value_Change_Ok) (char* old_value,
                                           size_t old_value_len,
                                           char* new_value,
                                           size_t new_value_len,
                                           void* mydata);

/*
 * stored within a given row
 */
typedef struct netsnmp_table_data_set_storage_s {
    unsigned int    column;

    /*
     * info about it?
     */
    char            writable;
    Netsnmp_Value_Change_Ok* change_ok_fn;
    void*           my_change_data;

    /*
     * data actually stored
     */
    u_char          type;
    union {                 /* value of variable */
    void*           voidp;
    long*           integer;
    u_char*         string;
    oid*            objid;
    u_char*         bitstring;
    struct counter64* counter64;
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
            float*          floatVal;
            double*         doubleVal;
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
        } data;
        u_long          data_len;

        struct netsnmp_table_data_set_storage_s* next;
    } netsnmp_table_data_set_storage;

    typedef struct netsnmp_table_data_set_s {
        netsnmp_table_data* table;
        netsnmp_table_data_set_storage* default_row;
        int             allow_creation; /* set to 1 to allow creation of new rows */
        unsigned int    rowstatus_column;
    } netsnmp_table_data_set;

typedef struct data_set_tables_s {
    netsnmp_table_data_set* table_set;
} data_set_tables;

netsnmp_table_data_set* netsnmp_create_table_data_set(const char*);

netsnmp_table_data_set_storage
*netsnmp_table_data_set_find_column(netsnmp_table_data_set_storage* ,
                                        unsigned int);
int  netsnmp_mark_row_column_writable(netsnmp_table_row* row,
                                        int column, int writable);
int  netsnmp_set_row_column(netsnmp_table_row* ,
                                        unsigned int, int, const char* ,
                                        size_t);

    void netsnmp_table_dataset_add_index(netsnmp_table_data_set
                                                    *table, u_char type);

#endif                          /* _TABLE_DATA_SET_HANDLER_H_NETSNMP */
