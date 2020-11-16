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
/** creates a netsnmp_mib_handler structure given a name and a access method.
 *  The returned handler should then be @link netsnmp_register_handler()
 *  registered.@endlink
 *
 *  @param name is the handler name and is copied then assigned to
 *              netsnmp_mib_handler->handler_name
 *
 *  @param handler_access_method is a function pointer used as the access
 *       method for this handler registration instance for whatever required
 *         needs.
 *
 *  @return a pointer to a populated netsnmp_mib_handler struct to be
 *          registered
 *
 *  @see netsnmp_create_handler_registration()
 *  @see netsnmp_register_handler()
 */
#include "netSnmpAgent.h"
#include "agent_handler_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"
#include "callback_netsnmp.h"
#include "snmp_agent_netsnmp.h"
#include "data_list_netsnmp.h"



/** clones a mib handler (name, flags and access methods only; not myvoid)
 * see also netsnmp_handler_dup
 */
static netsnmp_mib_handler*
_clone_handler(netsnmp_mib_handler* it)
{
    netsnmp_mib_handler* dup;

    if (NULL == it)
        return NULL;

    dup = netsnmp_create_handler(it->handler_name, it->access_method);
    if (NULL != dup)
        dup->flags = it->flags;

    return dup;
}


/** inject a new handler into the calling chain of the handlers
   definedy by the netsnmp_handler_registration pointer.  The new handler is
   injected at the top of the list and hence will be the new handler
   to be called first.*/
int
NetSnmpAgent::netsnmp_inject_handler(netsnmp_handler_registration* reginfo,
                       netsnmp_mib_handler* handler)
{
    return netsnmp_inject_handler_before(reginfo, handler, NULL);
}


/** inject a new handler into the calling chain of the handlers
   definedy by the netsnmp_handler_registration pointer.  The new
   handler is injected after the before_what handler, or if NULL at
   the top of the list and hence will be the new handler to be called
   first.*/
int
NetSnmpAgent::netsnmp_inject_handler_before(netsnmp_handler_registration
                                            *reginfo,
                                            netsnmp_mib_handler* handler,
                                            const char* before_what)
{
    netsnmp_mib_handler* handler2 = handler;

    if (handler == NULL || reginfo == NULL) {
        return SNMP_ERR_GENERR;
    }
    while (handler2->next) {
        handler2 = handler2->next;
    }
    if (before_what) {
        netsnmp_mib_handler* nexth,* prevh = NULL;
        if (reginfo->handler == NULL) {
            return SNMP_ERR_GENERR;
        }
        for (nexth = reginfo->handler; nexth;
            prevh = nexth, nexth = nexth->next) {
            if (strcmp(nexth->handler_name, before_what) == 0)
                break;
        }
        if (!nexth)
            return SNMP_ERR_GENERR;
        if (prevh) {
            /* after prevh and before nexth */
            prevh->next = handler;
            handler2->next = nexth;
            handler->prev = prevh;
            nexth->prev = handler2;
            return SNMPERR_SUCCESS;
        }

    }
    handler2->next = reginfo->handler;
    if (reginfo->handler)
        reginfo->handler->prev = handler2;
    reginfo->handler = handler;
    return SNMPERR_SUCCESS;
}





void
NetSnmpAgent::netsnmp_inject_handler_into_subtree(netsnmp_subtree* tp,
                                    const char* name,
                                    netsnmp_mib_handler* handler,
                                    const char* before_what)
{
    netsnmp_subtree* tptr;
    netsnmp_mib_handler* mh;

    for (tptr = tp; tptr != NULL; tptr = tptr->next) {

        if (strcmp(tptr->label_a, name) == 0) {
            netsnmp_inject_handler_before(tptr->reginfo,
                                            _clone_handler(handler),
                                            before_what);
        } else if (tptr->reginfo != NULL &&
           tptr->reginfo->handlerName != NULL &&
                   strcmp(tptr->reginfo->handlerName, name) == 0) {

            netsnmp_inject_handler_before(tptr->reginfo,
                                            _clone_handler(handler),
                                            before_what);
        } else {
            for (mh = tptr->reginfo->handler; mh != NULL; mh = mh->next) {
                if (mh->handler_name && strcmp(mh->handler_name, name)
                                        == 0) {

                    netsnmp_inject_handler_before(tptr->reginfo,
                                                  _clone_handler(handler),
                                                  before_what);
                    break;
                } else {

                }
            }
        }
    }
}

netsnmp_mib_handler*
netsnmp_create_handler(const char* name,
                       Netsnmp_Node_Handler*  handler_access_method)
{
    netsnmp_mib_handler* ret = SNMP_MALLOC_TYPEDEF(netsnmp_mib_handler);
    if (ret) {
        ret->access_method = handler_access_method;
        if (NULL != name) {
            ret->handler_name = strdup(name);
            if (NULL == ret->handler_name)
                SNMP_FREE(ret);
        }
    }
    return ret;
}


int
NetSnmpAgent::netsnmp_register_handler(netsnmp_handler_registration* reginfo)
{
    netsnmp_mib_handler* handler;
    int flags = 0;

    if (reginfo == NULL) {
        return SNMP_ERR_GENERR;
    }

    /*
     * don't let them register for absolutely nothing.  Probably a mistake
     */
    if (0 == reginfo->modes) {
        reginfo->modes = HANDLER_CAN_DEFAULT;
    }

    /*
     * for handlers that can't GETBULK, force a conversion handler on them
     */
    if (!(reginfo->modes & HANDLER_CAN_GETBULK)) {
        netsnmp_inject_handler(reginfo,
                               netsnmp_get_bulk_to_next_handler());
    }

    for (handler = reginfo->handler; handler; handler = handler->next) {
        if (handler->flags & MIB_HANDLER_INSTANCE)
            flags = FULLY_QUALIFIED_INSTANCE;
    }

    return netsnmp_register_mib(reginfo->handlerName,
                                NULL, 0, 0,
                                reginfo->rootoid, reginfo->rootoid_len,
                                reginfo->priority,
                                reginfo->range_subid,
                                reginfo->range_ubound, NULL,
                                reginfo->contextName, reginfo->timeout,
                                flags,
                                reginfo, 1);

}

/** calls the next handler in the chain after the current one with
   with appropriate NULL checking, etc. */
int
netsnmp_call_next_handler(netsnmp_mib_handler* current,
                          netsnmp_handler_registration* reginfo,
                          netsnmp_agent_request_info* reqinfo,
                          netsnmp_request_info* requests,
                          Node* node)
{

    if (current == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        return SNMP_ERR_GENERR;
    }

    return netsnmp_call_handler_out(current->next, reginfo, reqinfo,
                                    requests, node);
}

/* calls a handler with with appropriate NULL checking of arguments,
 * etc. */
int
NetSnmpAgent::netsnmp_call_handler(netsnmp_mib_handler* next_handler,
                     netsnmp_handler_registration* reginfo,
                     netsnmp_agent_request_info* reqinfo,
                     netsnmp_request_info* requests)
{
    Netsnmp_Node_Handler* nh;
    int             ret;

    if (next_handler == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        return SNMP_ERR_GENERR;
    }

    do {
    nh = next_handler->access_method;
    if (!nh) {
        if (next_handler->next) {
            return SNMP_ERR_GENERR;
        }
        /*
         * The final handler registration in the chain may well not need
         * to include a handler routine, if the processing of this object
         * is handled completely by the agent toolkit helpers.
         */
        return SNMP_ERR_NOERROR;
    }

    /*
     * XXX: define acceptable return statuses
     */
#ifdef SNMP_DEBUG
    printf("netsnmp_call_handler:Calling %s\n",next_handler->handler_name);
#endif
    ret = (*nh) (next_handler, reginfo, reqinfo, requests, this->node);

    if (! (next_handler->flags & MIB_HANDLER_AUTO_NEXT))
        break;

    /*
     * did handler signal that it didn't want auto next this time around?
     */
    if (next_handler->flags & MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE) {
        next_handler->flags &= ~MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE;
        break;
    }

    next_handler = next_handler->next;

    } while (next_handler);

    return ret;
}

/** calls a handler with with appropriate NULL checking of arguments, etc. */
int
netsnmp_call_handler_out(netsnmp_mib_handler* next_handler,
                     netsnmp_handler_registration* reginfo,
                     netsnmp_agent_request_info* reqinfo,
                     netsnmp_request_info* requests, Node* node)
{
    Netsnmp_Node_Handler* nh;
    int             ret;

    if (next_handler == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        return SNMP_ERR_GENERR;
    }

    do {
    nh = next_handler->access_method;
    if (!nh) {
        if (next_handler->next) {
            return SNMP_ERR_GENERR;
        }
        /*
         * The final handler registration in the chain may well not need
         * to include a handler routine, if the processing of this object
         * is handled completely by the agent toolkit helpers.
         */
        return SNMP_ERR_NOERROR;
    }


    /*
     * XXX: define acceptable return statuses
     */
    ret = (*nh) (next_handler, reginfo, reqinfo, requests, node);


    if (! (next_handler->flags & MIB_HANDLER_AUTO_NEXT))
        break;

    /*
     * did handler signal that it didn't want auto next this time around?
     */
    if (next_handler->flags & MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE) {
        next_handler->flags &= ~MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE;
        break;
    }

    next_handler = next_handler->next;

    } while (next_handler);

    return ret;
}

/** free the resources associated with a handler registration object */
void
netsnmp_handler_registration_free(netsnmp_handler_registration* reginfo)
{
    if (reginfo != NULL) {
        netsnmp_handler_free(reginfo->handler);
        SNMP_FREE(reginfo->handlerName);
        SNMP_FREE(reginfo->contextName);
        SNMP_FREE(reginfo->rootoid);
        reginfo->rootoid_len = 0;
        SNMP_FREE(reginfo);
    }
}

/** free's the resourceses associated with a given handler */
void
netsnmp_handler_free(netsnmp_mib_handler* handler)
{
    if (handler != NULL) {
        if (handler->next != NULL) {
            /** make sure we aren't pointing to ourselves.  */
            netsnmp_handler_free(handler->next);
            handler->next = NULL;
        }
        /** XXX : segv here at shutdown if SHUTDOWN_AGENT_CLEANLY
         *  defined. About 30 functions down the stack, starting
         *  in clear_context() -> clear_subtree()
         */
        if ((handler->myvoid != NULL) && (handler->data_free != NULL))
        {
            handler->data_free(handler->myvoid);
        }
        SNMP_FREE(handler->handler_name);
        SNMP_FREE(handler);
    }
}

/** duplicates the handler registration object */
netsnmp_handler_registration*
netsnmp_handler_registration_dup(netsnmp_handler_registration* reginfo)
{
    netsnmp_handler_registration* r = NULL;

    if (reginfo == NULL) {
        return NULL;
    }


    r = (netsnmp_handler_registration*) calloc(1,
                                        sizeof
                                        (netsnmp_handler_registration));

    if (r != NULL) {
        r->modes = reginfo->modes;
        r->priority = reginfo->priority;
        r->range_subid = reginfo->range_subid;
        r->timeout = reginfo->timeout;
        r->range_ubound = reginfo->range_ubound;
        r->rootoid_len = reginfo->rootoid_len;

        if (reginfo->handlerName != NULL) {
            r->handlerName = strdup(reginfo->handlerName);
            if (r->handlerName == NULL) {
                netsnmp_handler_registration_free(r);
                return NULL;
            }
        }

        if (reginfo->contextName != NULL) {
            r->contextName = strdup(reginfo->contextName);
            if (r->contextName == NULL) {
                netsnmp_handler_registration_free(r);
                return NULL;
            }
        }

        if (reginfo->rootoid != NULL) {
            r->rootoid =
                snmp_duplicate_objid(reginfo->rootoid,
                                     reginfo->rootoid_len);
            if (r->rootoid == NULL) {
                netsnmp_handler_registration_free(r);
                return NULL;
            }
        }

        r->handler = netsnmp_handler_dup(reginfo->handler);
        if (r->handler == NULL) {
            netsnmp_handler_registration_free(r);
            return NULL;
        }
        return r;
    }

    return NULL;
}

/** dulpicates a handler and all subsequent handlers
 * see also _clone_handler
 */
netsnmp_mib_handler*
netsnmp_handler_dup(netsnmp_mib_handler* handler)
{
    netsnmp_mib_handler* h = NULL;

    if (handler == NULL) {
        return NULL;
    }

    h = _clone_handler(handler);

    if (h != NULL) {
        h->myvoid = handler->myvoid;
        h->data_free = handler->data_free;

        if (handler->next != NULL) {
            h->next = netsnmp_handler_dup(handler->next);
            if (h->next == NULL) {
                netsnmp_handler_free(h);
                return NULL;
            }
            h->next->prev = h;
        }
        h->prev = NULL;
        return h;
    }
    return NULL;
}

/** @internal
 *  register's the injectHandle parser token.
 */
void
NetSnmpAgent::netsnmp_init_handler_conf(void)
{
    snmpd_register_config_handler("injectHandler",
                      &NetSnmpAgent::parse_injectHandler_conf,
                      NULL,
                      "injectHandler NAME INTONAME [BEFORE_OTHER_NAME]");
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_READ_CONFIG,
                           &NetSnmpAgent::handler_mark_doneit, NULL);

    se_add_pair_to_slist("agent_mode", strdup("GET"), MODE_GET);
    se_add_pair_to_slist("agent_mode", strdup("GETNEXT"), MODE_GETNEXT);
    se_add_pair_to_slist("agent_mode", strdup("GETBULK"), MODE_GETBULK);
    se_add_pair_to_slist("agent_mode", strdup("SET_BEGIN"),
                         MODE_SET_BEGIN);
    se_add_pair_to_slist("agent_mode", strdup("SET_RESERVE1"),
                         MODE_SET_RESERVE1);
    se_add_pair_to_slist("agent_mode", strdup("SET_RESERVE2"),
                         MODE_SET_RESERVE2);
    se_add_pair_to_slist("agent_mode", strdup("SET_ACTION"),
                         MODE_SET_ACTION);
    se_add_pair_to_slist("agent_mode", strdup("SET_COMMIT"),
                         MODE_SET_COMMIT);
    se_add_pair_to_slist("agent_mode", strdup("SET_FREE"), MODE_SET_FREE);
    se_add_pair_to_slist("agent_mode", strdup("SET_UNDO"), MODE_SET_UNDO);

    se_add_pair_to_slist("babystep_mode", strdup("pre-request"),
                         MODE_BSTEP_PRE_REQUEST);
    se_add_pair_to_slist("babystep_mode", strdup("object_lookup"),
                         MODE_BSTEP_OBJECT_LOOKUP);
    se_add_pair_to_slist("babystep_mode", strdup("check_value"),
                         MODE_BSTEP_CHECK_VALUE);
    se_add_pair_to_slist("babystep_mode", strdup("row_create"),
                         MODE_BSTEP_ROW_CREATE);
    se_add_pair_to_slist("babystep_mode", strdup("undo_setup"),
                         MODE_BSTEP_UNDO_SETUP);
    se_add_pair_to_slist("babystep_mode", strdup("set_value"),
                         MODE_BSTEP_SET_VALUE);
    se_add_pair_to_slist("babystep_mode", strdup("check_consistency"),
                         MODE_BSTEP_CHECK_CONSISTENCY);
    se_add_pair_to_slist("babystep_mode", strdup("undo_set"),
                         MODE_BSTEP_UNDO_SET);
    se_add_pair_to_slist("babystep_mode", strdup("commit"),
                         MODE_BSTEP_COMMIT);
    se_add_pair_to_slist("babystep_mode", strdup("undo_commit"),
                         MODE_BSTEP_UNDO_COMMIT);
    se_add_pair_to_slist("babystep_mode", strdup("irreversible_commit"),
                         MODE_BSTEP_IRREVERSIBLE_COMMIT);
    se_add_pair_to_slist("babystep_mode", strdup("undo_cleanup"),
                         MODE_BSTEP_UNDO_CLEANUP);
    se_add_pair_to_slist("babystep_mode", strdup("post_request"),
                         MODE_BSTEP_POST_REQUEST);
    se_add_pair_to_slist("babystep_mode", strdup("original"), 0xffff);

    /*
     * xxx-rks: hmmm.. will this work for modes which are or'd together?
     *          I'm betting not...
     */
    se_add_pair_to_slist("handler_can_mode", strdup("GET/GETNEXT"),
                         HANDLER_CAN_GETANDGETNEXT);
    se_add_pair_to_slist("handler_can_mode", strdup("SET"),
                         HANDLER_CAN_SET);
    se_add_pair_to_slist("handler_can_mode", strdup("GETBULK"),
                         HANDLER_CAN_GETBULK);
    se_add_pair_to_slist("handler_can_mode", strdup("BABY_STEP"),
                         HANDLER_CAN_BABY_STEP);
}




void
NetSnmpAgent::parse_injectHandler_conf(const char* token, char* cptr)
{
    char            handler_to_insert[256], reg_name[256];
    subtree_context_cache* stc;
    netsnmp_mib_handler* handler;

    /*
     * XXXWWW: ensure instead that handler isn't inserted twice
     */
    if (doneit)     /* we only do this once without restart the agent */
        return;

    cptr = copy_nword(cptr, handler_to_insert, sizeof(handler_to_insert));
    handler = (netsnmp_mib_handler*)
                netsnmp_get_list_data(handler_reg, handler_to_insert);
    if (!handler) {
        return;
    }

    if (!cptr) {
        return;
    }
    cptr = copy_nword(cptr, reg_name, sizeof(reg_name));

    for (stc = context_subtrees; stc; stc = stc->next) {

        netsnmp_inject_handler_into_subtree(stc->first_subtree, reg_name,
                                            handler, cptr);
    }
}

/** @internal
 *  callback to ensure injectHandler parser doesn't do things twice
 *  @todo replace this with a method to check the handler chain instead.
 */
int
NetSnmpAgent::handler_mark_doneit(int majorID, int minorID,
                    void* serverarg, void* clientarg)
{
    doneit = 1;
    return 0;
}

void
handler_free_callback(void* free)
{
    netsnmp_handler_free((netsnmp_mib_handler*)free);
}


/** registers a given handler by name so that it can be found easily later.
 */
void
NetSnmpAgent::netsnmp_register_handler_by_name(const char* name,
                                 netsnmp_mib_handler* handler)
{
    netsnmp_add_list_data(&handler_reg,
                          netsnmp_create_data_list(name, (void*) handler,
                                                   handler_free_callback));
}


netsnmp_handler_registration*
NetSnmpAgent::netsnmp_create_handler_registration(const char* name,
                                    Netsnmp_Node_Handler*
                                    handler_access_method,
                                    const oid*  reg_oid,
                                    size_t reg_oid_len, int modes)
{
    netsnmp_handler_registration* rv = NULL;
    netsnmp_mib_handler* handler =
        netsnmp_create_handler(name, handler_access_method);
    if (handler) {
        rv = netsnmp_handler_registration_create(
            name, handler, reg_oid, reg_oid_len, modes);
        if (!rv)
            netsnmp_handler_free(handler);
    }
    return rv;
}


/** creates a handler registration structure given a name, a
 *  access_method function, a registration location oid and the modes
 *  the handler supports. If modes == 0, then modes will automatically
 *  be set to the default value of only HANDLER_CAN_DEFAULT, which is
 *  by default read-only GET and GETNEXT requests. A hander which supports
 *  sets but not row creation should set us a mode of HANDLER_CAN_SET_ONLY.
 *  @note This ends up calling netsnmp_create_handler(name, handler_access_method)
 *  @param name is the handler name and is copied then assigned to
 *              netsnmp_handler_registration->handlerName.
 *
 *  @param handler is a function pointer used as the access
 *    method for this handler registration instance for whatever required
 *    needs.
 *
 *  @param reg_oid is the registration location oid.
 *
 *  @param reg_oid_len is the length of reg_oid, can use the macro,
 *         OID_LENGTH
 *
 *  @param modes is used to configure read/write access.  If modes == 0,
 *    then modes will automatically be set to the default
 *    value of only HANDLER_CAN_DEFAULT, which is by default read-only GET
 *    and GETNEXT requests.  The other two mode options are read only,
 *    HANDLER_CAN_RONLY, and read/write, HANDLER_CAN_RWRITE.
 *
 *        - HANDLER_CAN_GETANDGETNEXT
 *        - HANDLER_CAN_SET
 *        - HANDLER_CAN_GETBULK
 *
 *        - HANDLER_CAN_RONLY   (HANDLER_CAN_GETANDGETNEXT)
 *        - HANDLER_CAN_RWRITE  (HANDLER_CAN_GETANDGETNEXT |
 *            HANDLER_CAN_SET)
 *        - HANDLER_CAN_DEFAULT HANDLER_CAN_RONLY
 *
 *  @return Returns a pointer to a netsnmp_handler_registration struct.
 *          NULL is returned only when memory could not be allocated for the
 *          netsnmp_handler_registration struct.
 *
 *
 *  @see netsnmp_create_handler()
 *  @see netsnmp_register_handler()
 */
netsnmp_handler_registration*
netsnmp_handler_registration_create(const char* name,
                                netsnmp_mib_handler* handler,
                                const oid*  reg_oid, size_t reg_oid_len,
                                int modes)
{
    netsnmp_handler_registration* the_reg;
    the_reg = SNMP_MALLOC_TYPEDEF(netsnmp_handler_registration);
    if (!the_reg)
        return NULL;

    if (modes)
        the_reg->modes = modes;
    else
        the_reg->modes = HANDLER_CAN_DEFAULT;

    the_reg->handler = handler;
    the_reg->priority = DEFAULT_MIB_PRIORITY;
    if (name)
        the_reg->handlerName = strdup(name);
    the_reg->rootoid = snmp_duplicate_objid((const unsigned int*)reg_oid,
                                             reg_oid_len);
    the_reg->rootoid_len = reg_oid_len;
    return the_reg;
}

/** add data to a request that can be extracted later by submodules
 *
 * @param request the netsnmp request info structure
 *
 * @param node this is the data to be added to the linked list
 *             request->parent_data
 *
 * @return void
 *
 */
void
netsnmp_request_add_list_data(netsnmp_request_info* request,
                              netsnmp_data_list* node)
{
    if (request) {
        if (request->parent_data)
            netsnmp_add_list_data(&request->parent_data, node);
        else
            request->parent_data = node;
    }
}

/** remove data from a request
 *
 * @param request the netsnmp request info structure
 *
 * @param name this is the name of the previously added data
 *
 * @return 0 on successful find-and-delete, 1 otherwise.
 *
 */
int
netsnmp_request_remove_list_data(netsnmp_request_info* request,
                                 const char* name)
{
    if ((NULL == request) || (NULL ==request->parent_data))
        return 1;

    return netsnmp_remove_list_node(&request->parent_data, name);
}


/** extract data from a request that was added previously by a parent module
 *
 * @param request the netsnmp request info function
 *
 * @param name used to compare against the request->parent_data->name value,
 *             if a match is found request->parent_data->data is returned
 *
 * @return a void pointer(request->parent_data->data), otherwise NULL is
 *         returned if request is NULL or request->parent_data is NULL or
 *         request->parent_data object is not found.
 */
void*
NetSnmpAgent::netsnmp_request_get_list_data(netsnmp_request_info* request,
                              const char* name)
{
    if (request)
        return netsnmp_get_list_data(request->parent_data, name);
    return NULL;
}


/** extract data from a request that was added previously by a parent module
 *
 * @param request the netsnmp request info function
 *
 * @param name used to compare against the request->parent_data->name value,
 *             if a match is found request->parent_data->data is returned
 *
 * @return a void pointer(request->parent_data->data), otherwise NULL is
 *         returned if request is NULL or request->parent_data is NULL or
 *         request->parent_data object is not found.
 */
void*
netsnmp_request_get_list_data(netsnmp_request_info* request,
                              const char* name)
{
    if (request)
        return netsnmp_get_list_data(request->parent_data, name);
    return NULL;
}

/** Returns a handler from a chain based on the name */
netsnmp_mib_handler*
netsnmp_find_handler_by_name(netsnmp_handler_registration* reginfo,
                             const char* name)
{
    netsnmp_mib_handler* it;
    for (it = reginfo->handler; it; it = it->next) {
        if (strcmp(it->handler_name, name) == 0) {
            return it;
        }
    }
    return NULL;
}
/** Returns a handler's void * pointer from a chain based on the name.
 This probably shouldn't be used by the general public as the void *
 data may change as a handler evolves.  Handlers should really
 advertise some function for you to use instead. */
void*
netsnmp_find_handler_data_by_name(netsnmp_handler_registration* reginfo,
                                  const char* name)
{
    netsnmp_mib_handler* it = netsnmp_find_handler_by_name(reginfo, name);
    if (it)
        return it->myvoid;
    return NULL;
}
void
NetSnmpAgent::netsnmp_free_request_data_sets(netsnmp_request_info* request)
{
    if (request && request->parent_data) {
        netsnmp_free_all_list_data(request->parent_data);
        request->parent_data = NULL;
    }
}

/** @internal
 *  calls all the handlers for a given mode.
 */
int
NetSnmpAgent::netsnmp_call_handlers(netsnmp_handler_registration* reginfo,
                      netsnmp_agent_request_info* reqinfo,
                      netsnmp_request_info* requests)
{
#ifdef SNMP_DEBUG
    printf("netsnmp_call_handlers:node %d\n",node->nodeId);
#endif
    netsnmp_request_info* request;
    int             status;

    if (reginfo == NULL || reqinfo == NULL || requests == NULL) {
        return SNMP_ERR_GENERR;
    }

    if (reginfo->handler == NULL) {
        return SNMP_ERR_GENERR;
    }

    switch (reqinfo->mode) {
    case MODE_GETBULK:
    case MODE_GET:
    case MODE_GETNEXT:
        if (!(reginfo->modes & HANDLER_CAN_GETANDGETNEXT))
            return SNMP_ERR_NOERROR;    /* legal */
        break;

    case MODE_SET_RESERVE1:
    case MODE_SET_RESERVE2:
    case MODE_SET_ACTION:
    case MODE_SET_COMMIT:
    case MODE_SET_FREE:
    case MODE_SET_UNDO:
        if (!(reginfo->modes & HANDLER_CAN_SET)) {
            for (; requests; requests = requests->next) {
                netsnmp_set_request_error(reqinfo, requests,
                                          SNMP_ERR_NOTWRITABLE);
            }
            return SNMP_ERR_NOERROR;
        }
        break;

    default:
        return SNMP_ERR_GENERR;
    }

    for (request = requests ; request; request = request->next) {
        request->processed = 0;
    }

    status = netsnmp_call_handler(reginfo->handler, reginfo,
                                  reqinfo, requests);

    return status;
}

/** clears the entire handler-registration list
 */
void
NetSnmpAgent::netsnmp_clear_handler_list(void)
{
    netsnmp_free_all_list_data(handler_reg);
    handler_reg = NULL;
}
