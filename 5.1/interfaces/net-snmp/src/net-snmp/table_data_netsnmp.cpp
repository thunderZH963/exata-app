#include "table_data_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "mib_netsnmp.h"
#include "varbind_api_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "tools_netsnmp.h"
#include<string.h>
#include<malloc.h>
#include "netSnmpAgent.h"

/** creates and returns a pointer to table data set */
netsnmp_table_data*
netsnmp_create_table_data(const char* name)
{
    netsnmp_table_data* table =
        (netsnmp_table_data*) calloc(1, sizeof(netsnmp_table_data));
    if (name && table)
        table->name = strdup(name);
    return table;
}

/** creates and returns a pointer to table data set */
netsnmp_table_row*
netsnmp_create_table_data_row(void)
{
    netsnmp_table_row* row =
         (netsnmp_table_row*) calloc(1, sizeof(netsnmp_table_row));
    return row;
}


 /* generates the index portion of an table oid from a varlist.
 */
void
netsnmp_table_data_generate_index_oid(netsnmp_table_row* row)
{
    build_oid(&row->index_oid, &row->index_oid_len, NULL, 0, row->indexes);
}

/**
 * Adds a row of data to a given table (stored in proper lexographical order).
 *
 * returns SNMPERR_SUCCESS on successful addition.
 *      or SNMPERR_GENERR  on failure (E.G., indexes already existed)
 */
int
netsnmp_table_data_add_row(netsnmp_table_data* table,
                           netsnmp_table_row* row)
{
    int rc, dup = 0;
    netsnmp_table_row* nextrow = NULL, *prevrow;

    if (!row || !table)
        return SNMPERR_GENERR;

    if (row->indexes)
        netsnmp_table_data_generate_index_oid(row);

    /*
     * we don't store the index info as it
     * takes up memory.
     */
    if (!table->store_indexes) {
        row->indexes = NULL;
    }

    if (!row->index_oid) {
        return SNMPERR_GENERR;
    }

    /*
     * check for simple append
     */
    if ((prevrow = table->last_row) != NULL) {
        rc = snmp_oid_compare((unsigned int*)prevrow->index_oid, prevrow->index_oid_len,
                              (unsigned int*)row->index_oid, row->index_oid_len);
        if (0 == rc)
            dup = 1;
    }
    else
        rc = 1;

    /*
     * if no last row, or newrow < last row, search the table and
     * insert it into the table in the proper oid-lexographical order
     */
    if (rc > 0) {
        for (nextrow = table->first_row, prevrow = NULL;
             nextrow != NULL; prevrow = nextrow, nextrow = nextrow->next) {
            if (NULL == nextrow->index_oid) {
                /** xxx-rks: remove invalid row? */
                continue;
            }
            rc = snmp_oid_compare((unsigned int*)nextrow->index_oid, nextrow->index_oid_len,
                                  (unsigned int*)row->index_oid, row->index_oid_len);
            if (rc > 0)
                break;
            if (0 == rc) {
                dup = 1;
                break;
            }
        }
    }

    if (dup) {
        /*
         * exact match.  Duplicate entries illegal
         */
        return SNMPERR_GENERR;
    }

    /*
     * ok, we have the location of where it should go
     */
    /*
     * (after prevrow, and before nextrow)
     */
    row->next = nextrow;
    row->prev = prevrow;

    if (row->next)
        row->next->prev = row;

    if (row->prev)
        row->prev->next = row;

    if (NULL == row->prev)      /* it's the (new) first row */
        table->first_row = row;
    if (NULL == row->next)      /* it's the last row */
        table->last_row = row;


    return SNMPERR_SUCCESS;
}

/**
 * removes a row of data to a given table and returns it (no free's called)
 *
 * returns the row pointer itself on successful removing.
 *      or NULL on failure (bad arguments)
 */
netsnmp_table_row*
netsnmp_table_data_remove_row(netsnmp_table_data* table,
                              netsnmp_table_row* row)
{
    if (!row || !table)
        return NULL;

    if (row->prev)
        row->prev->next = row->next;
    else
        table->first_row = row->next;

    if (row->next)
        row->next->prev = row->prev;
    else
        table->last_row = row->prev;

    return row;
}

/* builds a result given a row, a varbind to set and the data */
int
netsnmp_table_data_build_result(netsnmp_handler_registration* reginfo,
                                netsnmp_agent_request_info* reqinfo,
                                netsnmp_request_info* request,
                                netsnmp_table_row* row,
                                int column,
                                u_char type,
                                u_char*  result_data,
                                size_t result_data_len)
{
    oid             build_space[MAX_OID_LEN];

    if (!reginfo || !reqinfo || !request)
        return SNMPERR_GENERR;

    if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GETBULK) {
        /*
         * only need to do this for getnext type cases where oid is changing
         */
        memcpy(build_space, reginfo->rootoid,   /* registered oid */
               reginfo->rootoid_len * sizeof(oid));
        build_space[reginfo->rootoid_len] = 1;  /* entry */
        build_space[reginfo->rootoid_len + 1] = column; /* column */
        memcpy(build_space + reginfo->rootoid_len + 2,  /* index data */
               row->index_oid, row->index_oid_len * sizeof(oid));
    }
    return SNMPERR_SUCCESS;     /* WWWXXX: check for bounds */
}

/** finds the data in "datalist" stored at the searchfor oid */
netsnmp_table_row*
netsnmp_table_data_get_from_oid(netsnmp_table_data* table,
                                oid*  searchfor, size_t searchfor_len)
{
    netsnmp_table_row* row;
    if (!table)
        return NULL;

    for (row = table->first_row; row != NULL; row = row->next) {
        if (row->index_oid &&
            snmp_oid_compare((unsigned int*)searchfor, searchfor_len,
                             (unsigned int*)row->index_oid, row->index_oid_len) == 0)
            return row;
    }
    return NULL;
}
/*
 * The helper handler that takes care of passing a specific row of
 * data down to the lower handler(s).  It sets request->processed if
 * the request should not be handled.
 */
int
NetSnmpAgent::netsnmp_table_data_helper_handler(netsnmp_mib_handler* handler,
                                  netsnmp_handler_registration* reginfo,
                                  netsnmp_agent_request_info* reqinfo,
                                  netsnmp_request_info* requests,Node* node)
{
    netsnmp_table_data* table = (netsnmp_table_data*) handler->myvoid;
    netsnmp_request_info* request;
    int             valid_request = 0;
    netsnmp_table_row* row;
    netsnmp_table_request_info* table_info;
    netsnmp_table_registration_info* table_reg_info =
        netsnmp_find_table_registration_info(reginfo);
    int             result, regresult;
    int             oldmode;

    for (request = requests; request; request = request->next) {
        if (request->processed)
            continue;

        table_info = netsnmp_extract_table_info(request);
        if (!table_info)
            continue;           /* ack */
        switch (reqinfo->mode) {
        case MODE_GET:
        case MODE_GETNEXT:
        case MODE_SET_RESERVE1:
            netsnmp_request_add_list_data(request,
                                      netsnmp_create_data_list(
                                          TABLE_DATA_TABLE, table, NULL));
        }

        /*
         * find the row in question
         */
        switch (reqinfo->mode) {
        case MODE_GETNEXT:
        case MODE_GETBULK:     /* XXXWWW */
            if (request->requestvb->type != ASN_NULL)
                continue;
            /*
             * loop through data till we find the next row
             */
            result = snmp_oid_compare(request->requestvb->name,
                                      request->requestvb->name_length,
                                      reginfo->rootoid,
                                      reginfo->rootoid_len);
            regresult = snmp_oid_compare(request->requestvb->name,
                                         SNMP_MIN(request->requestvb->
                                                  name_length,
                                                  reginfo->rootoid_len),
                                         reginfo->rootoid,
                                         reginfo->rootoid_len);
            if (regresult == 0
                && request->requestvb->name_length < reginfo->rootoid_len)
                regresult = -1;

            if (result < 0 || 0 == result) {
                /*
                 * before us entirely, return the first
                 */
                row = table->first_row;
                table_info->colnum = table_reg_info->min_column;
            } else if (regresult == 0 && request->requestvb->name_length ==
                       reginfo->rootoid_len + 1 &&
                       /* entry node must be 1, but any column is ok */
                       request->requestvb->name[reginfo->rootoid_len] == 1) {
                /*
                 * exactly to the entry
                 */
                row = table->first_row;
                table_info->colnum = table_reg_info->min_column;
            } else if (regresult == 0 && request->requestvb->name_length ==
                       reginfo->rootoid_len + 2 &&
                       /* entry node must be 1, but any column is ok */
                       request->requestvb->name[reginfo->rootoid_len] == 1) {
                /*
                 * exactly to the column
                 */
                row = table->first_row;
            } else {
                /*
                 * loop through all rows looking for the first one
                 * that is equal to the request or greater than it
                 */
                for (row = table->first_row; row; row = row->next) {
                    /*
                     * compare the index of the request to the row
                     */
                    result =
                        snmp_oid_compare((unsigned int*)row->index_oid,
                                         row->index_oid_len,
                                         request->requestvb->name + 2 +
                                         reginfo->rootoid_len,
                                         request->requestvb->name_length -
                                         2 - reginfo->rootoid_len);
                    if (result == 0) {
                        /*
                         * equal match, return the next row
                         */
                        if (row) {
                            row = row->next;
                        }
                        break;
                    } else if (result > 0) {
                        /*
                         * the current row is greater than the
                         * request, use it
                         */
                        break;
                    }
                }
            }
            if (!row) {
                table_info->colnum++;
                if (table_info->colnum <= table_reg_info->max_column) {
                    row = table->first_row;
                }
            }
            if (row) {
                valid_request = 1;
                netsnmp_request_add_list_data(request,
                                              netsnmp_create_data_list
                                              (TABLE_DATA_ROW, row,
                                               NULL));
                /*
                 * Set the name appropriately, so we can pass this
                 *  request on as a simple GET request
                 */
                netsnmp_table_data_build_result(reginfo, reqinfo, request,
                                                row,
                                                table_info->colnum,
                                                ASN_NULL, NULL, 0);
            } else {            /* no decent result found.  Give up. It's beyond us. */
                request->processed = 1;
            }
            break;

        case MODE_GET:
            if (request->requestvb->type != ASN_NULL)
                continue;
            /*
             * find the row in question
             */
            if (request->requestvb->name_length < (reginfo->rootoid_len + 3)) { /* table.entry.column... */
                /*
                 * request too short
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                break;
            } else if (NULL ==
                       (row =
                        netsnmp_table_data_get_from_oid(table,
                                                        (oid*)(request->
                                                        requestvb->name +
                                                        reginfo->
                                                        rootoid_len + 2),
                                                        request->
                                                        requestvb->
                                                        name_length -
                                                        reginfo->
                                                        rootoid_len -
                                                        2))) {
                /*
                 * no such row
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_NOSUCHINSTANCE);
                break;
            } else {
                valid_request = 1;
                netsnmp_request_add_list_data(request,
                                              netsnmp_create_data_list
                                              (TABLE_DATA_ROW, row,
                                               NULL));
            }
            break;

        case MODE_SET_RESERVE1:
            valid_request = 1;
            if (NULL !=
                (row =
                 netsnmp_table_data_get_from_oid(table,
                                                 (oid*)(request->requestvb->name +
                                                 reginfo->rootoid_len + 2),
                                                 request->requestvb->
                                                 name_length -
                                                 reginfo->rootoid_len -
                                                 2))) {
                netsnmp_request_add_list_data(request,
                                              netsnmp_create_data_list
                                              (TABLE_DATA_ROW, row,
                                               NULL));
            }
            break;

        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            valid_request = 1;

        }
    }

    if (valid_request &&
       (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GETBULK)) {
        /*
         * If this is a GetNext or GetBulk request, then we've identified
         *  the row that ought to include the appropriate next instance.
         *  Convert the request into a Get request, so that the lower-level
         *  handlers don't need to worry about skipping on, and call these
         *  handlers ourselves (so we can undo this again afterwards).
         */
        oldmode = reqinfo->mode;
        reqinfo->mode = MODE_GET;
        result = netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                         requests, this->node);
        reqinfo->mode = oldmode;
        handler->flags |= MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE;
        return result;
    }
    else
        /* next handler called automatically - 'AUTO_NEXT' */
        return SNMP_ERR_NOERROR;
}



/** swaps out origrow with newrow.  This does *not* delete/free anything! */
void
netsnmp_table_data_replace_row(netsnmp_table_data* table,
                               netsnmp_table_row* origrow,
                               netsnmp_table_row* newrow)
{
    netsnmp_table_data_remove_row(table, origrow);
    netsnmp_table_data_add_row(table, newrow);
}

/** Creates a table_data handler and returns it */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_table_data_handler(netsnmp_table_data* table)
{
    netsnmp_mib_handler* ret = NULL;

    if (!table) {
        return NULL;
    }

    if (ret) {
        ret->flags |= MIB_HANDLER_AUTO_NEXT;
        ret->myvoid = (void*) table;
    }
    return ret;
}

/** registers a handler as a data table.
 *  If table_info != NULL, it registers it as a normal table too. */
int
NetSnmpAgent::netsnmp_register_table_data(netsnmp_handler_registration* reginfo,
                            netsnmp_table_data* table,
                            netsnmp_table_registration_info* table_info)
{
    netsnmp_inject_handler(reginfo, netsnmp_get_table_data_handler(table));
    return netsnmp_register_table(reginfo, table_info);
}

/** extracts the row being accessed passed from the table_data helper */
netsnmp_table_row*
NetSnmpAgent::netsnmp_extract_table_row(netsnmp_request_info* request)
{
    return (netsnmp_table_row*) netsnmp_request_get_list_data(request,
                                                               TABLE_DATA_ROW);

}


/** clones a data row. DOES NOT CLONE THE CONTAINED DATA. */
netsnmp_table_row*
netsnmp_table_data_clone_row(netsnmp_table_row* row)
{
    netsnmp_table_row* newrow = NULL;
    if (!row)
        return NULL;

    memdup((u_char**) & newrow, (u_char*) row,
           sizeof(netsnmp_table_row));
    if (!newrow)
        return NULL;

    if (row->indexes) {
        newrow->indexes = snmp_clone_varbind(newrow->indexes);
        if (!newrow->indexes) {
            free(newrow);
            return NULL;
        }
    }

    if (row->index_oid) {
        newrow->index_oid =
            (oid*)snmp_duplicate_objid((const unsigned int*)row->index_oid, row->index_oid_len);
        if (!newrow->index_oid) {
            free(newrow);
            return NULL;
        }
    }

    return newrow;
}

/** deletes a row's memory.
 *  returns the void data that it doesn't know how to delete. */
void*
netsnmp_table_data_delete_row(netsnmp_table_row* row)
{
    void*           data;

    if (!row)
        return NULL;

    SNMP_FREE(row->index_oid);
    data = row->data;
    free(row);

    /*
     * return the void * pointer
     */
    return data;
}


/**
 * removes and frees a row of data to a given table and returns the void*
 *
 * returns the void * data on successful deletion.
 *      or NULL on failure (bad arguments)
 */
void*
netsnmp_table_data_remove_and_delete_row(netsnmp_table_data* table,
                                         netsnmp_table_row* row)
{
    if (!row || !table)
        return NULL;

    /*
     * remove it from the list
     */
    netsnmp_table_data_remove_row(table, row);
    return netsnmp_table_data_delete_row(row);
}
