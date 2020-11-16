/** @defgroup bulk_to_next bulk_to_next
 *  Convert GETBULK requests into GETNEXT requests for the handler.
 *  The only purpose of this handler is to convert a GETBULK request
 *  to a GETNEXT request.  It is inserted into handler chains where
 *  the handler has not set the HANDLER_CAN_GETBULK flag.
 *  @ingroup utilities
 *  @{
 */

#include "netSnmpAgent.h"
#include "agent_handler_netsnmp.h"
#include "snmp_netsnmp.h"

#include "bulk_to_next.h"
int
netsnmp_bulk_to_next_helper(netsnmp_mib_handler* handler,
                            netsnmp_handler_registration* reginfo,
                            netsnmp_agent_request_info* reqinfo,
                            netsnmp_request_info* requests,
                            Node* node = NULL)
{

    int             ret = SNMP_ERR_NOERROR;

    if (MODE_GETBULK == reqinfo->mode) {

        ret =
            netsnmp_call_next_handler(handler, reginfo, reqinfo, requests, node);

        /*
         * update the varbinds for the next request series
         */
        netsnmp_bulk_to_next_fix_requests(requests);

        /*
         * let agent handler know that we've already called next handler
         */
        handler->flags |= MIB_HANDLER_AUTO_NEXT_OVERRIDE_ONCE;
    }

    return ret;
}


/** returns a bulk_to_next handler that can be injected into a given
 *  handler chain.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_bulk_to_next_handler(void)
{
    netsnmp_mib_handler* handler =
        netsnmp_create_handler("bulk_to_next",
                               netsnmp_bulk_to_next_helper);

    if (NULL != handler)
        handler->flags |= MIB_HANDLER_AUTO_NEXT;

    return handler;
}


/** initializes the bulk_to_next helper which then registers a bulk_to_next
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
NetSnmpAgent::netsnmp_init_bulk_to_next_helper(void)
{
    netsnmp_register_handler_by_name("bulk_to_next",
                                     netsnmp_get_bulk_to_next_handler());
}

/** takes answered requests and decrements the repeat count and
 *  updates the requests to the next to-do varbind in the list */
void
netsnmp_bulk_to_next_fix_requests(netsnmp_request_info* requests)
{
    netsnmp_request_info* request;
    /*
     * Make sure that:
     *    - repeats remain
     *    - last handler provided an answer
     *    - answer didn't exceed range end (ala check_getnext_results)
     *    - there is a next variable
     * then
     * update the varbinds for the next request series
     */
    for (request = requests; request; request = request->next) {
        if (request->repeat > 0 &&
            request->requestvb->type != ASN_NULL &&
            request->requestvb->type != ASN_PRIV_RETRY &&
            (snmp_oid_compare(request->requestvb->name,
                              request->requestvb->name_length,
                              (oid*)request->range_end,
                              request->range_end_len) < 0) &&
            request->requestvb->next_variable) {
            request->repeat--;
            snmp_set_var_objid(request->requestvb->next_variable,
                               request->requestvb->name,
                               request->requestvb->name_length);
            request->requestvb = request->requestvb->next_variable;
            request->requestvb->type = ASN_PRIV_RETRY;
            /*
             * if inclusive == 2, it was set in check_getnext_results for
             * the previous requestvb. Now that we've moved on, clear it.
             */
            if (2 == request->inclusive)
                request->inclusive = 0;
        }
    }
}
