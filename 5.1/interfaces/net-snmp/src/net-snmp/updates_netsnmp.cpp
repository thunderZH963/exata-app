#include "updates_netsnmp.h"
#include "snmp_agent_netsnmp.h"

static int
handle_updates(netsnmp_mib_handler* handler,
               netsnmp_handler_registration* reginfo,
               netsnmp_agent_request_info* reqinfo,
               netsnmp_request_info* requests,
               Node* node = NULL)
{
    int* set = (int*)handler->myvoid;

    if (reqinfo->mode == MODE_SET_RESERVE1 && *set < 0)
        netsnmp_request_set_error(requests, SNMP_ERR_NOTWRITABLE);
    else if (reqinfo->mode == MODE_SET_COMMIT)
        *set = 1;
    return SNMP_ERR_NOERROR;
}

netsnmp_handler_registration*
netsnmp_create_update_handler_registration(
    const char* name, const oid* id, size_t idlen, int mode, int* set)
{
    netsnmp_handler_registration* res = NULL;
    netsnmp_mib_handler* hnd = netsnmp_create_handler("update", handle_updates);
    if (hnd) {
        hnd->myvoid = set;
        res = netsnmp_handler_registration_create(name, hnd, id, idlen, mode);
    }
    return res;
}
