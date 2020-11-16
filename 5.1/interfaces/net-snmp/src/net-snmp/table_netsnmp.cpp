#include "table_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"
#include "varbind_api_netsnmp.h"
#include "mib_netsnmp.h"
#include<stdlib.h>
#include<string.h>
#include "netSnmpAgent.h"


/*
 * internal routines
 */
void
table_data_free_func(void* data)
{
    netsnmp_table_request_info* info = (netsnmp_table_request_info*) data;
    if (!info)
        return;
    free(info);
}

/** extracts the registered netsnmp_table_registration_info object from a
 *  netsnmp_handler_registration object */
netsnmp_table_registration_info*
netsnmp_find_table_registration_info(netsnmp_handler_registration* reginfo)
{
    return (netsnmp_table_registration_info*)
        netsnmp_find_handler_data_by_name(reginfo, TABLE_HANDLER_NAME);
}

/** Extracts the processed table information from a given request.
 *  Call this from subhandlers on a request to extract the processed
 *  netsnmp_request_info information.  The resulting information includes the
 *  index values and the column number.
 *
 * @param request populated netsnmp request structure
 *
 * @return populated netsnmp_table_request_info structure
 */
netsnmp_table_request_info*
NetSnmpAgent::netsnmp_extract_table_info(netsnmp_request_info* request)
{
    return (netsnmp_table_request_info*)
        netsnmp_request_get_list_data(request, TABLE_HANDLER_NAME);
}


 void
NetSnmpAgent::table_helper_cleanup(netsnmp_agent_request_info* reqinfo,
                     netsnmp_request_info* request, int status)
{
    netsnmp_set_request_error(reqinfo, request, status);
    netsnmp_free_request_data_sets(request);
    if (!request)
        return;
    request->parent_data = NULL;
}

/*
 * find the closest column to current (which may be current).
 *
 * called when a table runs out of rows for column X. This
 * function is called with current = X + 1, to verify that
 * X + 1 is a valid column, or find the next closest column if not.
 *
 * All list types should be sorted, lowest to highest.
 */
unsigned int
netsnmp_closest_column(unsigned int current,
                       netsnmp_column_info* valid_columns)
{
    unsigned int    closest = 0;
    int             idx;

    if (valid_columns == NULL)
        return 0;

    for (; valid_columns; valid_columns = valid_columns->next) {

        if (valid_columns->isRange) {
            /*
             * if current < low range, it might be closest.
             * otherwise, if it's < high range, current is in
             * the range, and thus is an exact match.
             */
            if (current < valid_columns->details.range[0]) {
                if ((valid_columns->details.range[0] < closest) ||
                     (0 == closest)) {
                    closest = valid_columns->details.range[0];
                }
            } else if (current <= valid_columns->details.range[1]) {
                closest = current;
                break;       /* can not get any closer! */
            }

        } /* range */
        else {                  /* list */
            /*
             * if current < first item, no need to iterate over list.
             * that item is either closest, or not.
             */
            if (current < valid_columns->details.list[0]) {
                if ((valid_columns->details.list[0] < closest) ||
                    (0 == closest))
                    closest = valid_columns->details.list[0];
                continue;
            }

            /** if current > last item in list, no need to iterate */
            if (current >
                valid_columns->details.list[(int)valid_columns->list_count - 1])
                continue;       /* not in list range. */

            /** skip anything less than current*/
            for (idx = 0; valid_columns->details.list[idx] < current; ++idx)
                ;

            /** check for exact match */
            if (current == valid_columns->details.list[idx]) {
                closest = current;
                break;      /* can not get any closer! */
            }

            /** list[idx] > current; is it < closest? */
            if ((valid_columns->details.list[idx] < closest) ||
                (0 == closest))
                closest = valid_columns->details.list[idx];

        }                       /* list */
    }                           /* for */

    return closest;
}



/** implements the table helper handler */
int
NetSnmpAgent::table_helper_handler(netsnmp_mib_handler* handler,
                     netsnmp_handler_registration* reginfo,
                     netsnmp_agent_request_info* reqinfo,
                     netsnmp_request_info* requests,
                     Node* node = NULL)
{

    netsnmp_request_info* request;
    netsnmp_table_registration_info* tbl_info;
    int             oid_index_pos;
    unsigned int    oid_column_pos;
    unsigned int    tmp_idx;
    size_t          tmp_len;
    int             incomplete, out_of_range, cleaned_up = 0;
    int             status = SNMP_ERR_NOERROR, need_processing = 0;
    oid*            tmp_name;
    netsnmp_table_request_info* tbl_req_info;
    netsnmp_variable_list* vb;

    if (!reginfo || !handler)
        return SNMPERR_GENERR;

    oid_index_pos  = reginfo->rootoid_len + 2;
    oid_column_pos = reginfo->rootoid_len + 1;
    tbl_info = (netsnmp_table_registration_info*) handler->myvoid;

    if ((!handler->myvoid) || (!tbl_info->indexes)) {
        /*
         * XXX-rks: unregister table?
         */
        return SNMP_ERR_GENERR;
    }

    /*
     * if the agent request info has a state reference, then this is a
     * later pass of a set request and we can skip all the lookup stuff.
     *
     * xxx-rks: this might break for handlers which only handle one varbind
     * at a time... those handlers should not save data by their handler_name
     * in the netsnmp_agent_request_info.
     */
    if (netsnmp_agent_get_list_data(reqinfo, handler->next->handler_name)) {
        if (MODE_IS_SET(reqinfo->mode)) {
            return netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                             requests,
                                             this->node);
        } else {
/** XXX-rks: memory leak. add cleanup handler? */
            netsnmp_free_agent_data_sets(reqinfo);
        }
    }

    if (MODE_IS_SET(reqinfo->mode) &&
         (reqinfo->mode != MODE_SET_RESERVE1)) {
        /*
         * for later set modes, we can skip all the index parsing,
         * and we always need to let child handlers have a chance
         * to clean up, if they were called in the first place (i.e. have
         * a valid table info pointer).
         */
        if (NULL != netsnmp_extract_table_info(requests)) /*{
            DEBUGMSGTL(("table:helper","no table info for set - skipping\n"));
        }
        else*/
            need_processing = 1;
    }
    else {
        /*
         * for RESERVE1 and GETS, only continue if we have at least
         * one valid request.
         */

        /*
         * loop through requests
         */

        for (request = requests; request; request = request->next) {
            netsnmp_variable_list* var = request->requestvb;

            if (request->processed) {
                continue;
            }

            /*
             * this should probably be handled further up
             */
            if ((reqinfo->mode == MODE_GET) && (var->type != ASN_NULL)) {
                /*
                 * valid request if ASN_NULL
                 */
                netsnmp_set_request_error(reqinfo, request,
                                          SNMP_ERR_WRONGTYPE);
                continue;
            }

            if (reqinfo->mode == MODE_SET_RESERVE1) {
                u_char*         buf = NULL;
                if (buf != NULL) {
                    free(buf);
                }
            }

            /*
             * check to make sure its in table range
             */

            out_of_range = 0;
            /*
             * if our root oid is > var->name and this is not a GETNEXT,
             * then the oid is out of range. (only compare up to shorter
             * length)
             */
            if (reginfo->rootoid_len > var->name_length)
                tmp_len = var->name_length;
            else
                tmp_len = reginfo->rootoid_len;
            if (snmp_oid_compare(reginfo->rootoid, reginfo->rootoid_len,
                                 var->name, tmp_len) > 0) {
                if (reqinfo->mode == MODE_GETNEXT) {
                    if (var->name != var->name_loc)
                        SNMP_FREE(var->name);
                } else {
                    out_of_range = 1;
                }
            }
            /*
             * if var->name is longer than the root, make sure it is
             * table.1 (table.ENTRY).
             */
            else if ((var->name_length > reginfo->rootoid_len) &&
                     (var->name[reginfo->rootoid_len] != 1)) {
                if ((var->name[reginfo->rootoid_len] < 1) &&
                    (reqinfo->mode == MODE_GETNEXT)) {
                    var->name[reginfo->rootoid_len] = 1;
                    var->name_length = reginfo->rootoid_len;
                } else {
                    out_of_range = 1;
                }
            }
            /*
             * if it is not in range, then mark it in the request list
             * because we can't process it, and set an error so
             * nobody else wastes time trying to process it either.
             */
            if (out_of_range) {
                /*
                 *  Reject requests of the form 'myTable.N'   (N != 1)
                 */
                if (reqinfo->mode == MODE_SET_RESERVE1)
                    table_helper_cleanup(reqinfo, request,
                                         SNMP_ERR_NOTWRITABLE);
                else if (reqinfo->mode == MODE_GET)
                    table_helper_cleanup(reqinfo, request,
                                         SNMP_NOSUCHOBJECT);
                continue;
            }


            /*
             * Check column ranges; set-up to pull out indexes from OID.
             */

            incomplete = 0;
            tbl_req_info = netsnmp_extract_table_info(request);
            if (NULL == tbl_req_info) {
                tbl_req_info =
                    (netsnmp_table_request_info*) calloc(1, sizeof(netsnmp_table_request_info));

                if (tbl_req_info == NULL) {
                    table_helper_cleanup(reqinfo, request,
                                         SNMP_ERR_GENERR);
                    continue;
                }
                tbl_req_info->reg_info = tbl_info;
                /*tbl_req_info->indexes = snmp_clone_varbind(tbl_info->indexes);*/
                tbl_req_info->number_indexes = 0;       /* none yet */
                netsnmp_request_add_list_data(request,
                                              netsnmp_create_data_list
                                              (TABLE_HANDLER_NAME,
                                               (void*) tbl_req_info,
                                               table_data_free_func));
            }

            /*
             * do we have a column?
             */
            if (var->name_length > oid_column_pos) {
                /*
                 * oid is long enough to contain COLUMN info
                 */
                if (var->name[oid_column_pos] < tbl_info->min_column) {
                    if (reqinfo->mode == MODE_GETNEXT) {
                        /*
                         * fix column, truncate useless column info
                         */
                        var->name_length = oid_column_pos;
                        tbl_req_info->colnum = tbl_info->min_column;
                    } else
                        out_of_range = 1;
                } else if (var->name[oid_column_pos] > tbl_info->max_column)
                    out_of_range = 1;
                else
                    tbl_req_info->colnum = var->name[oid_column_pos];

                if (out_of_range) {
                    /*
                     * this is out of range...  remove from requests, free
                     * memory
                     */
                    /*
                     *  Reject requests of the form 'myEntry.N'   (invalid N)
                     */
                    if (reqinfo->mode == MODE_SET_RESERVE1)
                        table_helper_cleanup(reqinfo, request,
                                             SNMP_ERR_NOTWRITABLE);
                    else if (reqinfo->mode == MODE_GET)
                        table_helper_cleanup(reqinfo, request,
                                             SNMP_NOSUCHOBJECT);
                    continue;
                }
                /*
                 * use column verification
                 */
                else if (tbl_info->valid_columns) {
                    tbl_req_info->colnum =
                        netsnmp_closest_column(var->name[oid_column_pos],
                                               tbl_info->valid_columns);
                    /*
                     * xxx-rks: document why the continue...
                     */
                    if (tbl_req_info->colnum == 0)
                        continue;
                    if (tbl_req_info->colnum != var->name[oid_column_pos]) {
                        /*
                         * different column! truncate useless index info
                         */
                        var->name_length = oid_column_pos + 1; /* pos is 0 based */
                    }
                }
                /*
                 * var->name_length may have changed - check again
                 */
                if ((int)var->name_length <= oid_index_pos) { /* pos is 0 based */
                    tbl_req_info->index_oid_len = 0; /** none available */
                } else {
                    /*
                     * oid is long enough to contain INDEX info
                     */
                    tbl_req_info->index_oid_len =
                        var->name_length - oid_index_pos;
                    memcpy(tbl_req_info->index_oid, &var->name[oid_index_pos],
                           tbl_req_info->index_oid_len*  sizeof(oid));
                    tmp_name = tbl_req_info->index_oid;
                }
            } else if (reqinfo->mode == MODE_GETNEXT ||
                       reqinfo->mode == MODE_GETBULK) {
                /*
                 * oid is NOT long enough to contain column or index info, so start
                 * at the minimum column. Set index oid len to 0 because we don't
                 * have any index info in the OID.
                 */
                tbl_req_info->index_oid_len = 0;
                tbl_req_info->colnum = tbl_info->min_column;
            } else {
                /*
                 * oid is NOT long enough to contain index info,
                 * so we can't do anything with it.
                 *
                 * Reject requests of the form 'myTable' or 'myEntry'
                 */
                if (reqinfo->mode == MODE_GET) {
                    table_helper_cleanup(reqinfo, request, SNMP_NOSUCHOBJECT);
                } else if (reqinfo->mode == MODE_SET_RESERVE1) {
                    table_helper_cleanup(reqinfo, request, SNMP_ERR_NOTWRITABLE);
                }
                continue;
            }

            /*
             * set up tmp_len to be the number of OIDs we have beyond the column;
             * these should be the index(s) for the table. If the index_oid_len
             * is 0, set tmp_len to -1 so that when we try to parse the index below,
             * we just zero fill everything.
             */
            if (tbl_req_info->index_oid_len == 0) {
                incomplete = 1;
                tmp_len = -1;
            } else
                tmp_len = tbl_req_info->index_oid_len;


            /*
             * for each index type, try to extract the index from var->name
             */
            for (tmp_idx = 0, vb = tbl_req_info->indexes;
                 tmp_idx < tbl_info->number_indexes;
                 ++tmp_idx, vb = vb->next_variable) {
                if (incomplete && tmp_len) {
                    /*
                     * incomplete/illegal OID, set up dummy 0 to parse
                     */
                    /*
                     * no sense in trying anymore if this is a GET/SET.
                     *
                     * Reject requests of the form 'myObject'   (no instance)
                     */
                    if (reqinfo->mode != MODE_GETNEXT) {
                        table_helper_cleanup(reqinfo, requests,
                                             SNMP_NOSUCHINSTANCE);
                        cleaned_up = 1;
                    }
                    tmp_len = 0;
                    tmp_name = (oid*) & tmp_len;
                    break;
                }
                /*
                 * try and parse current index
                 */
                if (parse_one_oid_index(&tmp_name, &tmp_len,
                                        vb, 1) != SNMPERR_SUCCESS) {
                    incomplete = 1;
                    tmp_len = -1;   /* is this necessary? Better safe than
                                     * sorry */
                } else {
                    /*
                     * do not count incomplete indexes
                     */
                    if (incomplete)
                        continue;
                    ++tbl_req_info->number_indexes; /** got one ok */
                    if (tmp_len <= 0) {
                        incomplete = 1;
                        tmp_len = -1;       /* is this necessary? Better safe
                                             * than sorry */
                    }
                }
            }                       /** for loop */

            if (!cleaned_up) {
                unsigned int    count;
                u_char*         buf = NULL;
                size_t          out_len = 0;
                for (vb = tbl_req_info->indexes, count = 0;
                     vb && count < tbl_req_info->number_indexes;
                     count++, vb = vb->next_variable) {
                    out_len = 0;
                }
                if (buf != NULL) {
                    free(buf);
                }
            }
            /*
             * do we have sufficent index info to continue?
             */

            if (((unsigned int)reqinfo->mode != MODE_GETNEXT) &&
                ((tbl_req_info->number_indexes != tbl_info->number_indexes) ||
                 ((int)tmp_len != -1))) {
                table_helper_cleanup(reqinfo, request, SNMP_NOSUCHINSTANCE);
                continue;
            }

            ++need_processing;

        }                           /* for each request */
    }

    /*
     * bail if there is nothing for our child handlers
     */
    if (0 == need_processing)
        return status;

    /*
     * call our child access function
     */
    status =
        netsnmp_call_next_handler(handler, reginfo, reqinfo, requests,
         this->node);

    /*
     * check for sparse tables
     */

    return status;
}


/** Given a netsnmp_table_registration_info object, creates a table handler.
 *  You can use this table handler by injecting it into a calling
 *  chain.  When the handler gets called, it'll do processing and
 *  store it's information into the request->parent_data structure.
 *
 *  The table helper handler pulls out the column number and indexes from
 *  the request oid so that you don't have to do the complex work of
 *  parsing within your own code.
 *
 *  @param tabreq is a pointer to a netsnmp_table_registration_info struct.
 *    The table handler needs to know up front how your table is structured.
 *    A netsnmp_table_registeration_info structure that is
 *    passed to the table handler should contain the asn index types for the
 *    table as well as the minimum and maximum column that should be used.
 *
 *  @return Returns a pointer to a netsnmp_mib_handler struct which contains
 *    the handler's name and the access method
 *
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_table_handler(netsnmp_table_registration_info* tabreq)
{
    netsnmp_mib_handler* ret = NULL;

    if (!tabreq) {
        return NULL;
    }

    ret = netsnmp_create_handler(TABLE_HANDLER_NAME, NULL);
    if (ret) {
        ret->myvoid = (void*) tabreq;
        tabreq->number_indexes = count_varbinds(tabreq->indexes);
    }
    return ret;
}

/** creates a table handler given the netsnmp_table_registration_info object,
 *  inserts it into the request chain and then calls
 *  netsnmp_register_handler() to register the table into the agent.
 */
int
NetSnmpAgent::netsnmp_register_table(netsnmp_handler_registration* reginfo,
                       netsnmp_table_registration_info* tabreq)
{
    int rc = netsnmp_inject_handler(reginfo, netsnmp_get_table_handler(tabreq));
    if (SNMPERR_SUCCESS != rc)
        return rc;

    return netsnmp_register_handler(reginfo);
}


static void
_row_stash_data_list_free(void* ptr) {
    netsnmp_oid_stash_node** tmp = (netsnmp_oid_stash_node**)ptr;
    netsnmp_oid_stash_free(tmp, NULL);
    free(ptr);
}

/** returns a row-wide place to store data in.
    @todo This function will likely change to add free pointer functions. */
netsnmp_oid_stash_node**
NetSnmpAgent::netsnmp_table_get_or_create_row_stash(netsnmp_agent_request_info* reqinfo,
                                      const u_char*  storage_name)
{
    netsnmp_oid_stash_node** stashp = NULL;
    stashp = (netsnmp_oid_stash_node**)
            netsnmp_agent_get_list_data(reqinfo, (const char*)storage_name);

    if (!stashp) {
        /*
         * hasn't be created yet.  we create it here.
         */
        stashp =
            (netsnmp_oid_stash_node**) calloc(1, sizeof(netsnmp_oid_stash_node));


        if (!stashp)
            return NULL;        /* ack. out of mem */

        netsnmp_agent_add_list_data(reqinfo,
                                    netsnmp_create_data_list((const char*)storage_name,
                                                             stashp,
                                                             _row_stash_data_list_free));
    }
    return stashp;
}

/**
 * This function can be used to setup the table's definition within
 * your module's initialize function, it takes a variable index parameter list
 * for example: the table_info structure is followed by two integer index types
 * netsnmp_table_helper_add_indexes(
 *                  table_info,
 *                ASN_INTEGER,
 *            ASN_INTEGER,
 *            0);
 *
 * @param tinfo is a pointer to a netsnmp_table_registration_info struct.
 *    The table handler needs to know up front how your table is structured.
 *    A netsnmp_table_registeration_info structure that is
 *    passed to the table handler should contain the asn index types for the
 *    table as well as the minimum and maximum column that should be used.
 *
 * @return void
 *
 */
void
NetSnmpAgent::netsnmp_table_helper_add_indexes(netsnmp_table_registration_info* tinfo,
                                 ...)
{
    va_list         debugargs;
    int             type;

    va_start(debugargs, tinfo);
    while ((type = va_arg(debugargs, int)) != 0) {
        netsnmp_table_helper_add_index(tinfo, type);
    }
    va_end(debugargs);
}
