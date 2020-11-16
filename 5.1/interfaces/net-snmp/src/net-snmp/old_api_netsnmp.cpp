
#include "net-snmp-config_netsnmp.h"
#include "types_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "netSnmpAgent.h"
#include "old_api_netsnmp.h"
#include "tools_netsnmp.h"

/*
 * don't use these!
 */
void            set_current_agent_session(netsnmp_agent_session* asp);
netsnmp_agent_session* netsnmp_get_current_agent_session(void);

/** @defgroup old_api old_api
 *  Calls mib module code written in the old style of code.
 *  @ingroup handler
 *  This is a backwards compatilibity module that allows code written
 *  in the old API to be run under the new handler based architecture.
 *  Use it by calling netsnmp_register_old_api().
 *  @{
 */

/** returns a old_api handler that should be the final calling
 * handler.  Don't use this function.  Use the netsnmp_register_old_api()
 * function instead.
 */
netsnmp_mib_handler*
get_old_api_handler(void)
{
    return netsnmp_create_handler("old_api", netsnmp_old_api_helper);
}

/** Registers an old API set into the mib tree.  Functionally this
 * mimics the old register_mib_context() function (and in fact the new
 * register_mib_context() function merely calls this new old_api one).
 */
int
NetSnmpAgent::netsnmp_register_old_api(const char* moduleName,
                         struct variable* var,
                         size_t varsize,
                         size_t numvars,
                         oid*  mibloc,
                         size_t mibloclen,
                         int priority,
                         int range_subid,
                         oid range_ubound,
                         netsnmp_session*  ss,
                         const char* context, int timeout, int flags)
{

    unsigned int    i;

    /*
     * register all subtree nodes
     */
    for (i = 0; i < numvars; i++) {
        struct variable* vp;
        netsnmp_handler_registration* reginfo =
            SNMP_MALLOC_TYPEDEF(netsnmp_handler_registration);
        if (reginfo == NULL)
            return SNMP_ERR_GENERR;

        memdup((u_char**) &vp,
               (void*) (struct variable*) ((char*) var + varsize * i),
               varsize);

        reginfo->handler = get_old_api_handler();
        reginfo->handlerName = strdup(moduleName);
        reginfo->rootoid_len = (mibloclen + vp->namelen);
        reginfo->rootoid =
            (oid*) malloc(reginfo->rootoid_len * sizeof(oid));
        if (reginfo->rootoid == NULL)
            return SNMP_ERR_GENERR;

        memcpy(reginfo->rootoid, mibloc, mibloclen * sizeof(oid));
        memcpy(reginfo->rootoid + mibloclen, vp->name, vp->namelen
               * sizeof(oid));
        reginfo->handler->myvoid = (void*) vp;

        reginfo->priority = priority;
        reginfo->range_subid = range_subid;

        reginfo->range_ubound = range_ubound;
        reginfo->timeout = timeout;
        reginfo->contextName = (context) ? strdup(context) : NULL;
        reginfo->modes = HANDLER_CAN_RWRITE;

        /*
         * register ourselves in the mib tree
         */
        if (netsnmp_register_handler(reginfo) != MIB_REGISTERED_OK) {
            /** netsnmp_handler_registration_free(reginfo); already freed */
            SNMP_FREE(vp);
        }
    }
    return SNMPERR_SUCCESS;
}

/** implements the old_api handler */
int
netsnmp_old_api_helper(netsnmp_mib_handler* handler,
                       netsnmp_handler_registration* reginfo,
                       netsnmp_agent_request_info* reqinfo,
                       netsnmp_request_info* requests,Node* node)
{
#ifdef SNMP_DEBUG
    printf("netsnmp_old_api_helper:node %d;handlerName %s\n",node->nodeId,reginfo->handlerName);
#endif

    struct variable compat_var, *cvp = &compat_var;
    int             exact = 1;
    int             status;
    int             cmp;

    struct variable* vp;
    WriteMethod*    write_method = NULL;
    u_char          buf[SPRINT_MAX_LEN];
    size_t          len = 4;
    u_char*         access = NULL;
    netsnmp_old_api_cache* cacheptr;
    netsnmp_agent_session* oldasp = NULL;
    oid             tmp_name[MAX_OID_LEN];
    size_t          tmp_len;

    vp = (struct variable*) handler->myvoid;

    memset(tmp_name, 0, MAX_OID_LEN * sizeof(oid));

    /*
     * create old variable structure with right information
     */
    memcpy(cvp->name, reginfo->rootoid,
           reginfo->rootoid_len * sizeof(oid));
    cvp->namelen = reginfo->rootoid_len;
    cvp->type = vp->type;
    cvp->magic = vp->magic;
    cvp->acl = vp->acl;
    cvp->findVar = vp->findVar;

    switch (reqinfo->mode) {
    case MODE_GETNEXT:
    case MODE_GETBULK:
        exact = 0;
    }
    cmp = snmp_oid_compare(requests->requestvb->name,
                   requests->requestvb->name_length,
                   reginfo->rootoid, reginfo->rootoid_len);
    for (; requests; requests = requests->next) {

        switch (reqinfo->mode) {

        case MODE_GET:
#ifdef SNMP_DEBUG
    printf("netsnmp_old_api_helper:MODE_GET\n");
#endif
            /*
             * Actually call the old mib-module function
             */
            if (vp && vp->findVar) {
                memcpy(tmp_name, requests->requestvb->name,
                                 requests->requestvb->name_length * sizeof(oid));
                tmp_len = requests->requestvb->name_length;
                access = (*(vp->findVar)) (cvp, tmp_name, &tmp_len,
                                           exact, buf, &len, &write_method,node);
                snmp_set_var_objid(requests->requestvb, tmp_name, tmp_len);
            }
            else
                access = NULL;


            if (access) {
                /*
                 * result returned
                 */
                if (reqinfo->mode != MODE_SET_RESERVE1)
                    snmp_set_var_typed_value(requests->requestvb,
                                             cvp->type, access, len);
            }

            /*
             * AAA: fall through for everything that is a set (see BBB)
             */
            if (reqinfo->mode != MODE_SET_RESERVE1)
                continue;

            cacheptr = SNMP_MALLOC_TYPEDEF(netsnmp_old_api_cache);
            if (!cacheptr)
                return netsnmp_set_request_error(reqinfo, requests,
                                                 SNMP_ERR_RESOURCEUNAVAILABLE);
            cacheptr->data = access;
            cacheptr->write_method = write_method;
            write_method = NULL;
            netsnmp_request_add_list_data(requests,
                                          netsnmp_create_data_list
                                          (OLD_API_NAME, cacheptr, free));
            /*
             * BBB: fall through for everything that is a set (see AAA)
             */
            break;
        case MODE_GETBULK:
        case MODE_GETNEXT:
#ifdef SNMP_DEBUG
    printf("netsnmp_old_api_helper:MODE_GETNEXT\n");
#endif
            if (cmp < 0 || (cmp == 0 && requests->inclusive) ||
                (cmp == 0 && reqinfo->mode == MODE_GETBULK)) {
                if (vp && vp->findVar) {
                    memcpy(tmp_name,requests->requestvb->name,
                                    requests->requestvb->name_length * sizeof(oid));
                    tmp_len = requests->requestvb->name_length;
                    access = (*(vp->findVar)) (cvp, tmp_name, &tmp_len,
                                               exact, buf, &len, &write_method,node);
                    snmp_set_var_objid(requests->requestvb, tmp_name, tmp_len);
                }
                else
                    access = NULL;


                if (access) {
                    /*
                     * result returned
                     */
                    if (reqinfo->mode != MODE_SET_RESERVE1)
                        snmp_set_var_typed_value(requests->requestvb,
                                                 cvp->type, access, len);
                }

                /*
                 * AAA: fall through for everything that is a set (see BBB)
                 */
                if (reqinfo->mode != MODE_SET_RESERVE1)
                    continue;

                cacheptr = SNMP_MALLOC_TYPEDEF(netsnmp_old_api_cache);
                if (!cacheptr)
                    return netsnmp_set_request_error(reqinfo, requests,
                                                     SNMP_ERR_RESOURCEUNAVAILABLE);
                cacheptr->data = access;
                cacheptr->write_method = write_method;
                write_method = NULL;
                netsnmp_request_add_list_data(requests,
                                              netsnmp_create_data_list
                                              (OLD_API_NAME, cacheptr, free));
                /*
                 * BBB: fall through for everything that is a set (see AAA)
                 */
            } else {
                return SNMP_ERR_NOERROR;
            }
            break;

        case MODE_SET_RESERVE1:
#ifdef SNMP_DEBUG
    printf("netsnmp_old_api_helper:MODE_SET\n");
#endif
            if (vp && vp->findVar) {
                memcpy(tmp_name, requests->requestvb->name,
                                 requests->requestvb->name_length*sizeof(oid));
                tmp_len = requests->requestvb->name_length;
                access = (*(vp->findVar)) (cvp, tmp_name, &tmp_len,
                                           exact, buf, &len, &write_method,node);
                snmp_set_var_objid(requests->requestvb, tmp_name, tmp_len);
            }
            else
                access = NULL;

            cacheptr = SNMP_MALLOC_TYPEDEF(netsnmp_old_api_cache);
            if (!cacheptr)
                return netsnmp_set_request_error(reqinfo, requests,
                                                 SNMP_ERR_RESOURCEUNAVAILABLE);
            cacheptr->data = access;
            cacheptr->write_method = write_method;
            write_method = NULL;
            netsnmp_request_add_list_data(requests,
                                          netsnmp_create_data_list
                                          (OLD_API_NAME, cacheptr, free));

        default:
            /*rest of the set modes comes here*/
             cacheptr =
                (netsnmp_old_api_cache*)
                netsnmp_request_get_list_data(requests, OLD_API_NAME);

            if (cacheptr == NULL || cacheptr->write_method == NULL) {
                /*
                 * WWW: try to set ourselves if possible?
                 */
                return netsnmp_set_request_error(reqinfo, requests,
                                                 SNMP_ERR_NOTWRITABLE);
            }

            oldasp = netsnmp_get_current_agent_session();
            set_current_agent_session(reqinfo->asp);
            status =
                (*(cacheptr->write_method)) (reqinfo->mode,
                                             requests->requestvb->val.
                                             string,
                                             requests->requestvb->type,
                                             requests->requestvb->val_len,
                                             cacheptr->data,
                                             requests->requestvb->name,
                                             requests->requestvb->
                                             name_length,node);
            set_current_agent_session(oldasp);

            if (status != SNMP_ERR_NOERROR) {
                netsnmp_set_request_error(reqinfo, requests, status);
            }

            /*
             * clean up is done by the automatic freeing of the
             * cache stored in the request.
             */


            break;

        }
      }
    return SNMP_ERR_NOERROR;
}

/*
 * don't use this!
 */
static netsnmp_agent_session* current_agent_session = NULL;
netsnmp_agent_session*
netsnmp_get_current_agent_session(void)
{
    return current_agent_session;
}

/*
 * don't use this!
 */
void
set_current_agent_session(netsnmp_agent_session* asp)
{
    current_agent_session = asp;
}

/** @} */
