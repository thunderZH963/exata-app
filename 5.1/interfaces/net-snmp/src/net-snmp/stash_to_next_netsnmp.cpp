#include "net-snmp-config_netsnmp.h"

#include "stash_to_next_netsnmp.h"
#include "stash_cache_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "types_netsnmp.h"
#include "snmp_agent_netsnmp.h"
#include "netSnmpAgent.h"
/** returns a stash_to_next handler that can be injected into a given
 *  handler chain.
 */
netsnmp_mib_handler*
netsnmp_get_stash_to_next_handler(void)
{
    netsnmp_mib_handler* handler =
        netsnmp_create_handler("stash_to_next",
                               netsnmp_stash_to_next_helper);

    if (NULL != handler)
        handler->flags |= MIB_HANDLER_AUTO_NEXT;

    return handler;
}

/** @internal Implements the stash_to_next handler */
int
netsnmp_stash_to_next_helper(netsnmp_mib_handler* handler,
                            netsnmp_handler_registration* reginfo,
                            netsnmp_agent_request_info* reqinfo,
                            netsnmp_request_info* requests,
                            Node* node)
{

    int             ret = SNMP_ERR_NOERROR;
    int             namelen;
    int             finished = 0;
    netsnmp_oid_stash_node** cinfo;
    netsnmp_variable_list*   vb;
    netsnmp_request_info*    reqtmp;

    /*
     * Don't do anything for any modes except GET_STASH. Just return,
     * and the agent will call the next handler (AUTO_NEXT).
     *
     * If the handler chain already supports GET_STASH, we don't
     * need to do anything here either.  Once again, we just return
     * and the agent will call the next handler (AUTO_NEXT).
     *
     * Otherwise, we munge the mode to GET_NEXT, and call the
     * next handler ourselves, repeatedly until we've retrieved the
     * full contents of the table or subtree.
     *   Then restore the mode and return to the calling handler
     * (setting AUTO_NEXT_OVERRRIDE so the agent knows what we did).
     */
    if (MODE_GET_STASH == reqinfo->mode) {
        if (reginfo->modes & HANDLER_CAN_STASH) {
            return ret;
        }
        cinfo  = netsnmp_extract_stash_cache(reqinfo);
        reqtmp = SNMP_MALLOC_TYPEDEF(netsnmp_request_info);
        vb = reqtmp->requestvb = SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
        vb->type = ASN_NULL;
        snmp_set_var_objid(vb, reginfo->rootoid, reginfo->rootoid_len);

        reqinfo->mode = MODE_GETNEXT;
        while (!finished) {
            ret = netsnmp_call_next_handler(handler, reginfo, reqinfo, reqtmp, node);
            namelen = SNMP_MIN(vb->name_length, reginfo->rootoid_len);
            if (!snmp_oid_compare(reginfo->rootoid, reginfo->rootoid_len,
                                   vb->name, namelen) &&
                 vb->type != ASN_NULL && vb->type != SNMP_ENDOFMIBVIEW) {
                /*
                 * This result is relevant so save it, and prepare
                 * the request varbind for the next query.
                 */
                netsnmp_oid_stash_add_data(cinfo, vb->name, vb->name_length,
                                            snmp_clone_varbind(vb));
                    /*
                     * Tidy up the response structure,
                     *  ready for retrieving the next entry
                     */
                netsnmp_free_all_list_data(reqtmp->parent_data);
                reqtmp->parent_data = NULL;
                reqtmp->processed = 0;
                vb->type = ASN_NULL;
            } else {
                finished = 1;
            }
        }
        reqinfo->mode = MODE_GET_STASH;

        /*
         * let the handler chain processing know that we've already
         * called the next handler
         */
        handler->flags |= MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE;
    }

    return ret;
}

/** extracts a pointer to the stash_cache info from the reqinfo structure. */
netsnmp_oid_stash_node**
netsnmp_extract_stash_cache(netsnmp_agent_request_info* reqinfo)
{
    return (netsnmp_oid_stash_node**)
        netsnmp_agent_get_list_data(reqinfo, STASH_CACHE_NAME);
}
