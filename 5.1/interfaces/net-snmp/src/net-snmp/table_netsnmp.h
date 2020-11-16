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
 * Portions of this file are copyrighted by:
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/*
 * @file table.h
 *
 * @addtogroup table
 *
 * @{
 */
#ifndef _TABLE_HANDLER_H_NETSNMP
#define _TABLE_HANDLER_H_NETSNMP


#include "oid_stash_netsnmp.h"
#include "agent_handler_netsnmp.h"
/**
 * The table helper is designed to simplify the task of writing a
 * table handler for the net-snmp agent.  You should create a normal
 * handler and register it using the netsnmp_register_table() function
 * instead of the netsnmp_register_handler() function.
 */

/**
 * Notes:
 *
 *   1) illegal indexes automatically get handled for get/set cases.
 *      Simply check to make sure the value is type ASN_NULL before
 *      you answer a request.
 */

/**
 * used as an index to parent_data lookups
 */
#define TABLE_HANDLER_NAME "table"

#define netsnmp_table_helper_add_index(tinfo, type) \
        snmp_varlist_add_variable(&tinfo->indexes, NULL, 0, (u_char)type, NULL, 0);

/** @typedef struct netsnmp_column_info_t netsnmp_column_info
 * Typedefs the netsnmp_column_info_t struct into netsnmp_column_info */

/**
 * @struct netsnmp_column_info_t
 * column info struct.  OVERLAPPING RANGES ARE NOT SUPPORTED.
 */
    typedef struct netsnmp_column_info_t {
        char            isRange;
     /** only useful if isRange == 0 */
        char            list_count;

        union {
            unsigned int    range[2];
            unsigned int*   list;
        } details;

        struct netsnmp_column_info_t* next;

    } netsnmp_column_info;

/** @typedef struct netsnmp_table_registration_info_s netsnmp_table_registration_info
  * Typedefs the netsnmp_table_registration_info_s  struct into
  * netsnmp_table_registration_info */

/**
 * @struct netsnmp_table_registration_info_s
 * Table registration structure.
 */
    typedef struct netsnmp_table_registration_info_s {
     /** list of varbinds with only 'type' set */
        netsnmp_variable_list* indexes;
     /** calculated automatically */
        unsigned int    number_indexes;

       /**
        * the minimum columns number. If there are columns
        * in-between which are not valid, use valid_columns to get
        * automatic column range checking.
        */
        unsigned int    min_column;
     /** the maximum columns number */
        unsigned int    max_column;

     /** more details on columns */
        netsnmp_column_info* valid_columns;

    } netsnmp_table_registration_info;

/** @typedef struct netsnmp_table_request_info_s netsnmp_table_request_info
  * Typedefs the netsnmp_table_request_info_s  struct into
  * netsnmp_table_request_info */

/**
 * @struct netsnmp_table_request_info_s
 * The table request info structure.
 */
    typedef struct netsnmp_table_request_info_s {
     /** 0 if OID not long enough */
        unsigned int    colnum;
        /** 0 if failure to parse any */
        unsigned int    number_indexes;
     /** contents freed by helper upon exit */
        netsnmp_variable_list* indexes;

        oid             index_oid[MAX_OID_LEN];
        size_t          index_oid_len;
        netsnmp_table_registration_info* reg_info;
    } netsnmp_table_request_info;

    netsnmp_table_registration_info
        *netsnmp_find_table_registration_info(struct netsnmp_handler_registration_s
                                              *reginfo);

#endif                          /* _TABLE_HANDLER_H_NETSNMP */
/** @} */
