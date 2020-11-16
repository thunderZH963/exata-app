/*
 * table_iterator.c
 */
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

/** @defgroup table_iterator table_iterator
 *  The table iterator helper is designed to simplify the task of writing a table handler for the net-snmp agent when the data being accessed is not in an oid sorted form and must be accessed externally.
 *  @ingroup table
    Functionally, it is a specialized version of the more
    generic table helper but easies the burden of GETNEXT processing by
    manually looping through all the data indexes retrieved through
    function calls which should be supplied by the module that wishes
    help.  The module the table_iterator helps should, afterwards,
    never be called for the case of "MODE_GETNEXT" and only for the GET
    and SET related modes instead.

    The fundamental notion between the table iterator is that it
    allows your code to iterate over each "row" within your data
    storage mechanism, without requiring that it be sorted in a
    SNMP-index-compliant manner.  Through the get_first_data_point and
    get_next_data_point hooks, the table_iterator helper will
    repeatedly call your hooks to find the "proper" row of data that
    needs processing.  The following concepts are important:

      - A loop context is a pointer which indicates where in the
        current processing of a set of rows you currently are.  Allows
    the get_*_data_point routines to move from one row to the next,
    once the iterator handler has identified the appropriate row for
    this request, the job of the loop context is done.  The
        most simple example would be a pointer to an integer which
        simply counts rows from 1 to X.  More commonly, it might be a
        pointer to a linked list node, or someother internal or
        external reference to a data set (file seek value, array
        pointer, ...).  If allocated during iteration, either the
        free_loop_context_at_end (preferably) or the free_loop_context
        pointers should be set.

      - A data context is something that your handler code can use
        in order to retrieve the rest of the data for the needed
        row.  This data can be accessed in your handler via
    netsnmp_extract_iterator_context api with the netsnmp_request_info
    structure that's passed in.
    The important difference between a loop context and a
        data context is that multiple data contexts can be kept by the
        table_iterator helper, where as only one loop context will
        ever be held by the table_iterator helper.  If allocated
        during iteration the free_data_context pointer should be set
        to an appropriate function.

    The table iterator operates in a series of steps that call your
    code hooks from your netsnmp_iterator_info registration pointer.

      - the get_first_data_point hook is called at the beginning of
        processing.  It should set the variable list to a list of
        indexes for the given table.  It should also set the
        loop_context and maybe a data_context which you will get a
        pointer back to when it needs to call your code to retrieve
        actual data later.  The list of indexes should be returned
        after being update.

      - the get_next_data_point hook is then called repeatedly and is
        passed the loop context and the data context for it to update.
        The indexes, loop context and data context should all be
        updated if more data is available, otherwise they should be
        left alone and a NULL should be returned.  Ideally, it should
        update the loop context without the need to reallocate it.  If
        reallocation is necessary for every iterative step, then the
        free_loop_context function pointer should be set.  If not,
        then the free_loop_context_at_end pointer should be set, which
        is more efficient since a malloc/free will only be performed
        once for every iteration.
 *
 *  @{
 */

#include "net-snmp-config_netsnmp.h"
#include "table_iterator_netsnmp.h"
#include "table_netsnmp.h"
#include "serialize_netsnmp.h"
#include "netSnmpAgent.h"

    /*
     * The rest of the table maintenance section of the
     *   generic table API is Not Applicable to this helper.
     *
     * The contents of a iterator-based table will be
     *  maintained by the table-specific module itself.
     */

/* ==================================
 *
 * Iterator API: MIB maintenance
 *
 * ================================== */

/** returns a netsnmp_mib_handler object for the table_iterator helper */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_table_iterator_handler(netsnmp_iterator_info* iinfo)
{
    netsnmp_mib_handler* me;

    if (!iinfo)
        return NULL;

    me =
        netsnmp_create_handler(TABLE_ITERATOR_NAME, NULL
                               /*netsnmp_table_iterator_helper_handler*/);

    if (!me)
        return NULL;

    me->myvoid = iinfo;
    return me;
}

/**
 * Creates and registers a table iterator helper handler calling
 * netsnmp_create_handler with a handler name set to TABLE_ITERATOR_NAME
 * and access method, netsnmp_table_iterator_helper_handler.
 *
 * If NOT_SERIALIZED is not defined the function injects the serialize
 * handler into the calling chain prior to calling netsnmp_register_table.
 *
 * @param reginfo is a pointer to a netsnmp_handler_registration struct
 *
 * @param iinfo is a pointer to a netsnmp_iterator_info struct
 *
 * @return MIB_REGISTERED_OK is returned if the registration was a success.
 *    Failures are MIB_REGISTRATION_FAILED, MIB_DUPLICATE_REGISTRATION.
 *    If iinfo is NULL, SNMPERR_GENERR is returned.
 *
 */
int
NetSnmpAgent::netsnmp_register_table_iterator(netsnmp_handler_registration* reginfo,
                                netsnmp_iterator_info* iinfo)
{
    reginfo->modes |= HANDLER_CAN_STASH;
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_table_iterator_handler(iinfo));
    if (!iinfo)
        return SNMPERR_GENERR;
    if (!iinfo->indexes && iinfo->table_reginfo &&
                           iinfo->table_reginfo->indexes)
        iinfo->indexes = snmp_clone_varbind(iinfo->table_reginfo->indexes);

    return netsnmp_register_table(reginfo, iinfo->table_reginfo);
}

/** @} */
