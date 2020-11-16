#include "net-snmp-config_netsnmp.h"

#include "stash_cache_netsnmp.h"
#include "stash_to_next_netsnmp.h"
#include "cache_handler_netsnmp.h"
#include "netSnmpAgent.h"

extern NetsnmpCacheLoad _netsnmp_stash_cache_load;
extern NetsnmpCacheFree _netsnmp_stash_cache_free;

netsnmp_stash_cache_info*
netsnmp_get_new_stash_cache(void)
{
    netsnmp_stash_cache_info* cinfo;

    cinfo = SNMP_MALLOC_TYPEDEF(netsnmp_stash_cache_info);
    if (cinfo != NULL)
        cinfo->cache_length = 30;
    return cinfo;
}

/** updates a given cache depending on whether it needs to or not.
 */
int
_netsnmp_stash_cache_load(netsnmp_cache* cache, void* magic , struct Node* node)
{
    netsnmp_mib_handler*          handler  = cache->cache_hint->handler;
    netsnmp_handler_registration* reginfo  = cache->cache_hint->reginfo;
    netsnmp_agent_request_info*   reqinfo  = cache->cache_hint->reqinfo;
    netsnmp_request_info*         requests = cache->cache_hint->requests;
    netsnmp_stash_cache_info*     cinfo    = (netsnmp_stash_cache_info*) magic;
    int old_mode;
    int ret;

    if (!cinfo) {
        cinfo = netsnmp_get_new_stash_cache();
        cache->magic = cinfo;
    }

    /* change modes to the GET_STASH mode */
    old_mode = reqinfo->mode;
    reqinfo->mode = MODE_GET_STASH;
    netsnmp_agent_add_list_data(reqinfo,
                                netsnmp_create_data_list(STASH_CACHE_NAME,
                                                         &cinfo->cache, NULL));

    /* have the next handler fill stuff in and switch modes back */
    ret = netsnmp_call_next_handler(handler->next, reginfo, reqinfo, requests, node);
    reqinfo->mode = old_mode;

    return ret;
}

void
_netsnmp_stash_cache_free(netsnmp_cache* cache, void* magic)
{
    netsnmp_stash_cache_info* cinfo = (netsnmp_stash_cache_info*) magic;
    netsnmp_oid_stash_free(&cinfo->cache,
                          (NetSNMPStashFreeNode*) snmp_free_var);
    return;
}

/** @internal Implements the stash_cache handler */
int
netsnmp_stash_cache_helper(netsnmp_mib_handler* handler,
                           netsnmp_handler_registration* reginfo,
                           netsnmp_agent_request_info* reqinfo,
                           netsnmp_request_info* requests,
                           Node* node)
{
    netsnmp_cache*            cache;
    netsnmp_stash_cache_info* cinfo;
    netsnmp_oid_stash_node*   cnode;
    netsnmp_variable_list*    cdata;
    netsnmp_request_info*     request;

    cache = netsnmp_cache_reqinfo_extract(reqinfo, reginfo->handlerName);
    if (!cache) {
        return SNMP_ERR_GENERR;
    }
    cinfo = (netsnmp_stash_cache_info*) cache->magic;

    switch (reqinfo->mode) {

    case MODE_GET:
        for (request = requests; request; request = request->next) {
            cdata = (netsnmp_variable_list*)
                netsnmp_oid_stash_get_data(cinfo->cache,
                                           requests->requestvb->name,
                                           requests->requestvb->name_length);
            if (cdata && cdata->val.string && cdata->val_len) {
                snmp_set_var_typed_value(request->requestvb, cdata->type,
                                         cdata->val.string, cdata->val_len);
            }
        }
        break;

    case MODE_GETNEXT:
        for (request = requests; request; request = request->next) {
            cnode =
                netsnmp_oid_stash_getnext_node(cinfo->cache,
                                               requests->requestvb->name,
                                               requests->requestvb->name_length);
            if (cnode && cnode->thedata) {
                cdata = (netsnmp_variable_list*) cnode->thedata;
                if (cdata->val.string && cdata->name && cdata->name_length) {
                    snmp_set_var_typed_value(request->requestvb, cdata->type,
                                             cdata->val.string, cdata->val_len);
                    snmp_set_var_objid(request->requestvb, cdata->name,
                                       cdata->name_length);
                }
            }
        }
        break;

    default:
        cinfo->cache_valid = 0;
        return netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                         requests, node);
    }

    return SNMP_ERR_NOERROR;
}

/** returns a stash_cache handler that can be injected into a given
 *  handler chain (with the specified timeout and root OID values),
 *  but *only* if that handler chain explicitly supports stash cache processing.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_timed_bare_stash_cache_handler(int timeout, oid* rootoid, size_t rootoid_len)
{
    netsnmp_mib_handler* handler;
    netsnmp_cache*       cinfo;

    cinfo = netsnmp_cache_create(timeout, _netsnmp_stash_cache_load,
                                 _netsnmp_stash_cache_free, rootoid, rootoid_len);

    if (!cinfo)
        return NULL;

    handler = netsnmp_cache_handler_get(cinfo);
    if (!handler) {
        free(cinfo);
        return NULL;
    }

    handler->next = netsnmp_create_handler("stash_cache", netsnmp_stash_cache_helper);
    if (!handler->next) {
        netsnmp_handler_free(handler);
        free(cinfo);
        return NULL;
    }

    handler->myvoid = cinfo;
    handler->data_free = free;

    return handler;
}

/** returns a single stash_cache handler that can be injected into a given
 *  handler chain (with a fixed timeout), but *only* if that handler chain
 *  explicitly supports stash cache processing.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_bare_stash_cache_handler(void)
{
    return netsnmp_get_timed_bare_stash_cache_handler(30, NULL, 0);
}

/** returns a stash_cache handler sub-chain that can be injected into a given
 *  (arbitrary) handler chain, using a fixed cache timeout.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_stash_cache_handler(void)
{
    netsnmp_mib_handler* handler = netsnmp_get_bare_stash_cache_handler();
    if (handler && handler->next) {
        handler->next->next = netsnmp_get_stash_to_next_handler();
    }
    return handler;
}

/** initializes the stash_cache helper which then registers a stash_cache
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
NetSnmpAgent::netsnmp_init_stash_cache_helper(void)
{
    netsnmp_register_handler_by_name("stash_cache",
                                     netsnmp_get_stash_cache_handler());
}
