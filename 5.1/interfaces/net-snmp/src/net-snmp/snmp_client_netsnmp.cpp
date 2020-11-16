/*
 * snmp_client.c - a toolkit of common functions for an SNMP client.
 *
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/**********************************************************************
    Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/** @defgroup snmp_client various PDU processing routines
 *  @ingroup library
 *
 *  @{
 */
#include "net-snmp-config_netsnmp.h"
#include "pdu_api_netsnmp.h"

#include "types_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "snmp_netsnmp.h"
#include "asn1_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "snmp_secmod_netsnmp.h"
#include "netSnmpAgent.h"
#include<stdio.h>

#include <malloc.h>
#include <string.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif


/*
* Add object identifier name to SNMP variable.
 * If the name is large, additional memory is allocated.
 * Returns 0 if successful.
 */

int
snmp_set_var_objid(netsnmp_variable_list*  vp,
                   const oid*  objid, size_t name_length)
{
    size_t          len = sizeof(oid) * name_length;

    if (vp->name != vp->name_loc && vp->name != NULL &&
        vp->name_length > (sizeof(vp->name_loc) / sizeof(oid))) {
        /*
         * Probably previously-allocated "big storage".  Better free it
         * else memory leaks possible.
         */
        free(vp->name);
    }


    /* use built-in storage for smaller values */

    if (len <= sizeof(vp->name_loc)) {
        vp->name = vp->name_loc;
    } else {
        vp->name = (oid*) malloc(len);
        if (!vp->name)
            return 1;
    }
    if (objid)
        memmove(vp->name, objid, len);
    vp->name_length = name_length;
    return 0;
}








netsnmp_pdu*
NetSnmpAgent::snmp_pdu_create(int command)
{
    netsnmp_pdu*    pdu;

    pdu = (netsnmp_pdu*) calloc(1, sizeof(netsnmp_pdu));
    if (pdu) {
        pdu->version = SNMP_DEFAULT_VERSION;
        pdu->command = command;
        pdu->errstat = SNMP_DEFAULT_ERRSTAT;
        pdu->errindex = SNMP_DEFAULT_ERRINDEX;
        pdu->securityModel = SNMP_DEFAULT_SECMODEL;
        pdu->transport_data = NULL;
        pdu->transport_data_length = 0;
        pdu->securityNameLen = 0;
        pdu->contextNameLen = 0;
        pdu->time = 0;
        pdu->reqid = Sessions->internal->requests->request_id;
        pdu->msgid = Sessions->internal->requests->message_id;
        pdu->contextEngineIDLen = engineIDLength;
        pdu->contextEngineID = (u_char*)malloc(pdu->contextEngineIDLen);
        memcpy(pdu->contextEngineID, engineID, pdu->contextEngineIDLen + 1);
        pdu->securityEngineIDLen = engineIDLength;
        pdu->securityEngineID = (u_char*)malloc(pdu->securityEngineIDLen);
        memcpy(pdu->securityEngineID, engineID, pdu->contextEngineIDLen + 1);

    }
    return pdu;

}






/*
 * Clone an SNMP variable data structure.
 * Sets pointers to structure private storage, or
 * allocates larger object identifiers and values as needed.
 *
 * Caller must make list association for cloned variable.
 *
 * Returns 0 if successful.
 */
int
snmp_clone_var(netsnmp_variable_list*  var, netsnmp_variable_list*  newvar)
{
    if (!newvar || !var)
        return 1;

    memmove(newvar, var, sizeof(netsnmp_variable_list));
    newvar->next_variable = NULL;
    newvar->name = NULL;
    newvar->val.string = NULL;
    newvar->data = NULL;
    newvar->dataFreeHook = NULL;
    newvar->index = 0;

    ///*
    // * Clone the object identifier and the value.
    // * Allocate memory iff original will not fit into local storage.
    // */
    if (snmp_set_var_objid(newvar, var->name, var->name_length))
        return 1;

    /*
     * need a pointer to copy a string value.
     */
    if (var->val.string) {
        if (var->val.string != &var->buf[0]) {
            if (var->val_len <= sizeof(var->buf))
                newvar->val.string = newvar->buf;
            else {
                newvar->val.string = (u_char*) malloc(var->val_len);
                if (!newvar->val.string)
                    return 1;
            }
            memmove(newvar->val.string, var->val.string, var->val_len);
        } else {                /* fix the pointer to new local store */
            newvar->val.string = newvar->buf;
            /*
             * no need for a memmove, since we copied the whole var
             * struct (and thus var->buf) at the beginning of this function.
             */
        }
    } else {
        newvar->val.string = NULL;
        newvar->val_len = 0;
    }

    return 0;
}

static
netsnmp_variable_list*
_copy_varlist(netsnmp_variable_list*  var,      /* source varList */
              int errindex,     /* index of variable to drop (if any) */
              int copy_count)
{                               /* !=0 number variables to copy */
    netsnmp_variable_list* newhead, *newvar, *oldvar;
    int             ii = 0;

    newhead = NULL;
    oldvar = NULL;

    while (var && (copy_count-- > 0)) {
        /*
         * Drop the specified variable (if applicable)
         */
        if (++ii == errindex) {
            var = var->next_variable;
            continue;
        }

        /*
         * clone the next variable. Cleanup if alloc fails
         */
        newvar = (netsnmp_variable_list*)
            malloc(sizeof(netsnmp_variable_list));
        if (snmp_clone_var(var, newvar)) {
            if (newvar)
                free((char*) newvar);
            snmp_free_varbind(newhead);
            return NULL;
        }

        /*
         * add cloned variable to new list
         */
        if (NULL == newhead)
            newhead = newvar;
        if (oldvar)
            oldvar->next_variable = newvar;
        oldvar = newvar;

        var = var->next_variable;
    }
    return newhead;
}

/*
 * Copy some or all variables from source PDU to target PDU.
 * This function consolidates many of the needs of PDU variables:
 * Clone PDU : copy all the variables.
 * Split PDU : skip over some variables to copy other variables.
 * Fix PDU   : remove variable associated with error index.
 *
 * Designed to work with _clone_pdu_header.
 *
 * If drop_err is set, drop any variable associated with errindex.
 * If skip_count is set, skip the number of variable in pdu's list.
 * While copy_count is greater than zero, copy pdu variables to newpdu.
 *
 * If an error occurs, newpdu is freed and pointer is set to 0.
 *
 * Returns a pointer to the cloned PDU if successful.
 * Returns 0 if failure.
 */
netsnmp_pdu*
_copy_pdu_vars(netsnmp_pdu* pdu,        /* source PDU */
               netsnmp_pdu* newpdu,     /* target PDU */
               int drop_err,    /* !=0 drop errored variable */
               int skip_count,  /* !=0 number of variables to skip */
               int copy_count)
{                               /* !=0 number of variables to copy */
    netsnmp_variable_list* var, *oldvar;
    int             ii, copied, drop_idx;

    if (!newpdu)
        return NULL;            /* where is PDU to copy to ? */

    if (drop_err)
        drop_idx = pdu->errindex - skip_count;
    else
        drop_idx = 0;

    var = pdu->variables;
    while (var && (skip_count-- > 0))   /* skip over pdu variables */
        var = var->next_variable;

    oldvar = NULL;
    ii = 0;
    copied = 0;
    if (pdu->flags & UCD_MSG_FLAG_FORCE_PDU_COPY)
        copied = 1;             /* We're interested in 'empty' responses too */

    newpdu->variables = _copy_varlist(var, drop_idx, copy_count);
    if (newpdu->variables)
        copied = 1;

#if ALSO_TEMPORARILY_DISABLED
    /*
     * Error if bad errindex or if target PDU has no variables copied
     */
    if ((drop_err && (ii < pdu->errindex))
#if TEMPORARILY_DISABLED
        /*
         * SNMPv3 engineID probes are allowed to be empty.
         * See the comment in snmp_api.c for further details
         */
        || copied == 0
#endif
        ) {
        snmp_free_pdu(newpdu);
        return 0;
    }
#endif
    return newpdu;
}

/*
 * Creates and allocates a clone of the input PDU,
 * but does NOT copy the variables.
 * This function should be used with another function,
 * such as _copy_pdu_vars.
 *
 * Returns a pointer to the cloned PDU if successful.
 * Returns 0 if failure.
 */
netsnmp_pdu*
NetSnmpAgent::_clone_pdu_header(netsnmp_pdu* pdu)
{
    netsnmp_pdu*    newpdu;
    struct snmp_secmod_def* sptr;

    newpdu = (netsnmp_pdu*) malloc(sizeof(netsnmp_pdu));
    if (!newpdu)
        return NULL;
    memmove(newpdu, pdu, sizeof(netsnmp_pdu));

    /*
     * reset copied pointers if copy fails
     */
    newpdu->variables = NULL;
    newpdu->enterprise = NULL;
    newpdu->community = NULL;
    newpdu->securityEngineID = NULL;
    newpdu->securityName = NULL;
    newpdu->contextEngineID = NULL;
    newpdu->contextName = NULL;
    newpdu->transport_data = NULL;

    /*
     * copy buffers individually. If any copy fails, all are freed.
     */
    if (snmp_clone_mem((void**) &newpdu->enterprise, pdu->enterprise,
                       sizeof(oid) * pdu->enterprise_length) ||
        snmp_clone_mem((void**) &newpdu->community, pdu->community,
                       pdu->community_len) ||
        snmp_clone_mem((void**) &newpdu->contextEngineID,
                       pdu->contextEngineID, pdu->contextEngineIDLen)
        || snmp_clone_mem((void**) &newpdu->securityEngineID,
                          pdu->securityEngineID, pdu->securityEngineIDLen)
        || snmp_clone_mem((void**) &newpdu->contextName, pdu->contextName,
                          pdu->contextNameLen)
        || snmp_clone_mem((void**) &newpdu->securityName,
                          pdu->securityName, pdu->securityNameLen)
        || snmp_clone_mem((void**) &newpdu->transport_data,
                          pdu->transport_data,
                          pdu->transport_data_length)) {
        snmp_free_pdu(newpdu);
        return NULL;
    }
    if ((sptr = find_sec_mod(newpdu->securityModel)) != NULL &&
        sptr->pdu_clone != NULL) {
        /*
         * call security model if it needs to know about this
         */
        (*sptr->pdu_clone) (pdu, newpdu);
    }

    return newpdu;
}

/*
 * Creates (allocates and copies) a clone of the input PDU.
 * If drop_err is set, don't copy any variable associated with errindex.
 * This function is called by snmp_clone_pdu and snmp_fix_pdu.
 *
 * Returns a pointer to the cloned PDU if successful.
 * Returns 0 if failure.
 */
netsnmp_pdu*
NetSnmpAgent::_clone_pdu(netsnmp_pdu* pdu, int drop_err)
{
    netsnmp_pdu*    newpdu;
    newpdu = _clone_pdu_header(pdu);
    newpdu = _copy_pdu_vars(pdu, newpdu, drop_err, 0, 10000);   /* skip none, copy all */

    return newpdu;
}

/*
 * This function will clone a PDU including all of its variables.
 *
 * Returns a pointer to the cloned PDU if successful.
 * Returns 0 if failure
 */
netsnmp_pdu*
NetSnmpAgent::snmp_clone_pdu(netsnmp_pdu* pdu)
{
    return _clone_pdu(pdu, 0);  /* copies all variables */
}

/*
 * This function will clone a full varbind list
 *
 * Returns a pointer to the cloned PDU if successful.
 * Returns 0 if failure
 */
netsnmp_variable_list*
snmp_clone_varbind(netsnmp_variable_list*  varlist)
{
    return _copy_varlist(varlist, 0, 10000);    /* skip none, copy all */
}



/*
 * Add some value to SNMP variable.
 * If the value is large, additional memory is allocated.
 * Returns 0 if successful.
 */

int
snmp_set_var_value(netsnmp_variable_list*  vars,
                   const void*  value, size_t len)
{
    int             largeval = 1;

    /*
     * xxx-rks: why the unconditional free? why not use existing
     * memory, if len < vars->val_len ?
     */
    if (vars->val.string && vars->val.string != vars->buf) {
        free(vars->val.string);
    }
    vars->val.string = NULL;
    vars->val_len = 0;

    /*
     * use built-in storage for smaller values
     */
    if (len <= sizeof(vars->buf)) {
        vars->val.string = (u_char*) vars->buf;
        largeval = 0;
    }

    if ((0 == len) || (NULL == value)) {
        vars->val.string[0] = 0;
        return 0;
    }

    vars->val_len = len;
    switch (vars->type) {
    case ASN_INTEGER:
    case ASN_UNSIGNED:
    case ASN_TIMETICKS:
    case ASN_COUNTER:
        if (value) {
            if (vars->val_len == sizeof(int)) {
                if (ASN_INTEGER == vars->type) {
                    const int*      val_int
                        = (const int*) value;
                    *(vars->val.integer) = (long) *val_int;
                } else {
                    const u_int*    val_uint
                        = (const u_int*) value;
                    *(vars->val.integer) = (unsigned long) *val_uint;
                }
            }
#if SIZEOF_LONG != SIZEOF_INT
            else if (vars->val_len == sizeof(long)){
                const u_long*   val_ulong
                    = (const u_long*) value;
                *(vars->val.integer) = *val_ulong;
                if (*(vars->val.integer) > 0xffffffff) {
                    *(vars->val.integer) &= 0xffffffff;
                }
            }
#endif
#if defined(SIZEOF_LONG_LONG) && (SIZEOF_LONG != SIZEOF_LONG_LONG)
#if !defined(SIZEOF_INTMAX_T) || (SIZEOF_LONG_LONG != SIZEOF_INTMAX_T)
            else if (vars->val_len == sizeof(long long)){
                const unsigned long long*   val_ullong
                    = (const unsigned long long*) value;
                *(vars->val.integer) = (long) *val_ullong;
                if (*(vars->val.integer) > 0xffffffff) {
                    *(vars->val.integer) &= 0xffffffff;
                }
            }
#endif
#endif
#if defined(SIZEOF_INTMAX_T) && (SIZEOF_LONG != SIZEOF_INTMAX_T)
            else if (vars->val_len == sizeof(intmax_t)){
                const uintmax_t* val_uintmax_t
                    = (const uintmax_t*) value;
                *(vars->val.integer) = (long) *val_uintmax_t;
                if (*(vars->val.integer) > 0xffffffff) {
                    *(vars->val.integer) &= 0xffffffff;
                }
            }
#endif
#if SIZEOF_SHORT != SIZEOF_INT
            else if (vars->val_len == sizeof(short)) {
                if (ASN_INTEGER == vars->type) {
                    const short*      val_short
                        = (const short*) value;
                    *(vars->val.integer) = (long) *val_short;
                } else {
                    const u_short*    val_ushort
                        = (const u_short*) value;
                    *(vars->val.integer) = (unsigned long) *val_ushort;
                }
            }
#endif
            else if (vars->val_len == sizeof(char)) {
                if (ASN_INTEGER == vars->type) {
                    const char*      val_char
                        = (const char*) value;
                    *(vars->val.integer) = (long) *val_char;
                } else {
                    const u_char*    val_uchar
                        = (const u_char*) value;
                    *(vars->val.integer) = (unsigned long) *val_uchar;
                }
            }
            else {
                return (1);
            }
        } else
            *(vars->val.integer) = 0;
        vars->val_len = sizeof(long);
        break;

    case ASN_OBJECT_ID:
    case ASN_PRIV_IMPLIED_OBJECT_ID:
    case ASN_PRIV_INCL_RANGE:
    case ASN_PRIV_EXCL_RANGE:
        if (largeval) {
            vars->val.objid = (oid*) malloc(vars->val_len);
        }
        if (vars->val.objid == NULL) {
            return 1;
        }
        memmove(vars->val.objid, value, vars->val_len);
        break;

    case ASN_IPADDRESS: /* snmp_build_var_op treats IPADDR like a string */
    case ASN_PRIV_IMPLIED_OCTET_STR:
    case ASN_OCTET_STR:
    case ASN_BIT_STR:
    case ASN_OPAQUE:
    case ASN_NSAP:
        if (vars->val_len >= sizeof(vars->buf)) {
            vars->val.string = (u_char*) malloc(vars->val_len + 1);
        }
        if (vars->val.string == NULL) {
            return 1;
        }
        memmove(vars->val.string, value, vars->val_len);
        /*
         * Make sure the string is zero-terminated; some bits of code make
         * this assumption.  Easier to do this here than fix all these wrong
         * assumptions.
         */
        vars->val.string[vars->val_len] = '\0';
        break;

    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
    case ASN_NULL:
        vars->val_len = 0;
        vars->val.string = NULL;
        break;

#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    case ASN_OPAQUE_U64:
    case ASN_OPAQUE_I64:
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
    case ASN_COUNTER64:
        if (largeval) {
            return (1);
        }
        vars->val_len = sizeof(struct counter64);
        memmove(vars->val.counter64, value, vars->val_len);
        break;

#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    case ASN_OPAQUE_FLOAT:
        if (largeval) {
            return (1);
        }
        vars->val_len = sizeof(float);
        memmove(vars->val.floatVal, value, vars->val_len);
        break;

    case ASN_OPAQUE_DOUBLE:
        if (largeval) {
            return (1);
        }
        vars->val_len = sizeof(double);
        memmove(vars->val.doubleVal, value, vars->val_len);
        break;

#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */

    default:
        return (1);
    }
    return 0;
}

netsnmp_variable_list*
find_varbind_in_list(netsnmp_variable_list* vblist,
                      oid* name, size_t len)
{
    for (; vblist != NULL; vblist = vblist->next_variable)
        if (!snmp_oid_compare(vblist->name, vblist->name_length, name, len))
            return vblist;

    return NULL;
}

/*
 * Possibly make a copy of source memory buffer.
 * Will reset destination pointer if source pointer is NULL.
 * Returns 0 if successful, 1 if memory allocation fails.
 */
int
snmp_clone_mem(void** dstPtr, const void* srcPtr, unsigned len)
{
    *dstPtr = NULL;
    if (srcPtr) {
        *dstPtr = malloc(len + 1);
        if (!*dstPtr) {
            return 1;
        }
        memmove(*dstPtr, srcPtr, len);
        /*
         * this is for those routines that expect 0-terminated strings!!!
         * someone should rather have called strdup
         */
        ((char*) *dstPtr)[len] = 0;
    }
    return 0;
}


int
snmp_set_var_typed_integer(netsnmp_variable_list*  newvar,
                           u_char type, long val)
{
    newvar->type = type;
    return snmp_set_var_value(newvar, &val, sizeof(long));
}


/**
 * snmp_set_var_typed_value is used to set data into the netsnmp_variable_list
 * structure.  Used to return data to the snmp request via the
 * netsnmp_request_info structure's requestvb pointer.
 *
 * @param newvar   the structure gets populated with the given data, type,
 *                 val_str, and val_len.
 * @param type     is the asn data type to be copied
 * @param val_str  is a buffer containing the value to be copied into the
 *                 newvar structure.
 * @param val_len  the length of val_str
 *
 * @return returns 0 on success and 1 on a malloc error
 */
int
snmp_set_var_typed_value(netsnmp_variable_list*  newvar, u_char type,
                         const void*  val_str, size_t val_len)
{
    newvar->type = type;
    return snmp_set_var_value(newvar, val_str, val_len);
}


int
NetSnmpAgent::snmp_synch_input(int op,
                 netsnmp_session*  session,
                 int reqid, netsnmp_pdu* pdu, void* magic)
{
    struct synch_state* state = (struct synch_state*) magic;
    int             rpt_type;

    if (reqid != state->reqid && pdu && pdu->command != SNMP_MSG_REPORT) {
        return 0;
    }

    state->waiting = 0;

    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE && pdu) {
        if (pdu->command == SNMP_MSG_REPORT) {
            rpt_type = snmpv3_get_report_type(pdu);
            if (SNMPV3_IGNORE_UNAUTH_REPORTS ||
                rpt_type == SNMPERR_NOT_IN_TIME_WINDOW) {
                state->waiting = 1;
            }
            state->pdu = NULL;
            state->status = STAT_ERROR;
            session->s_snmp_errno = rpt_type;
        } else if (pdu->command == SNMP_MSG_RESPONSE) {
            /*
             * clone the pdu to return to snmp_synch_response
             */
            state->pdu = snmp_clone_pdu(pdu);
            state->status = STAT_SUCCESS;
            session->s_snmp_errno = SNMPERR_SUCCESS;
        }
        else {
            char msg_buf[50];
            state->status = STAT_ERROR;
            session->s_snmp_errno = SNMPERR_PROTOCOL;
            snprintf(msg_buf, sizeof(msg_buf), "Expected RESPONSE-PDU but got %s-PDU",
                     snmp_pdu_type(pdu->command));
            snmp_set_detail(msg_buf);
            return 0;
        }
    } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
        state->pdu = NULL;
        state->status = STAT_TIMEOUT;
        session->s_snmp_errno = SNMPERR_TIMEOUT;
    } else if (op == NETSNMP_CALLBACK_OP_DISCONNECT) {
        state->pdu = NULL;
        state->status = STAT_ERROR;
        session->s_snmp_errno = SNMPERR_ABORT;
    }

    return 1;
}


int
NetSnmpAgent::snmp_sess_synch_response(void* sessp,
                         netsnmp_pdu* pdu, netsnmp_pdu** response)
{
    netsnmp_session* ss;
    struct synch_state lstate, *state;
    int     (NetSnmpAgent::*cbsav) (int, netsnmp_session* , int,
                                          netsnmp_pdu* , void*);
    void*           cbmagsav;

    ss = snmp_sess_session(sessp);
    memset((void*) &lstate, 0, sizeof(lstate));
    state = (synch_state*)&lstate;
    cbsav = ss->callback;
    cbmagsav = ss->callback_magic;
    ss->callback = &NetSnmpAgent::snmp_synch_input;
    ss->callback_magic = (void*) state;

    if ((state->reqid = snmp_sess_send(sessp, pdu)) == 0) {
        snmp_free_pdu(pdu);
        state->status = STAT_ERROR;
    } else
        state->waiting = 1;

    *response = state->pdu;
    ss->callback = cbsav;
    ss->callback_magic = cbmagsav;
    return state->status;
}

int
count_varbinds(netsnmp_variable_list*  var_ptr)
{
    int             count = 0;

    for (; var_ptr != NULL; var_ptr = var_ptr->next_variable)
        count++;

    return count;
}

void
snmp_replace_var_types(netsnmp_variable_list*  vbl, u_char old_type,
                       u_char new_type)
{
    while (vbl) {
        if (vbl->type == old_type) {
            snmp_set_var_typed_value(vbl, new_type, NULL, 0);
        }
        vbl = vbl->next_variable;
    }
}
