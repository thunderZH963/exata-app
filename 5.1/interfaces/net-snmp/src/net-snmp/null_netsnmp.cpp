#include "netSnmpAgent.h"
#include "agent_handler_netsnmp.h"
#include "stdlib.h"
int
netsnmp_null_handler(netsnmp_mib_handler* handler,
                     netsnmp_handler_registration* reginfo,
                     netsnmp_agent_request_info* reqinfo,
                     netsnmp_request_info* requests, Node* node= NULL)
{
    switch (reqinfo->mode) {
    case MODE_GETNEXT:
    case MODE_GETBULK:
        return SNMP_ERR_NOERROR;

    case MODE_GET:
        netsnmp_request_set_error_all(requests, SNMP_NOSUCHOBJECT);
        return SNMP_ERR_NOERROR;

    default:
        netsnmp_request_set_error_all(requests, SNMP_ERR_NOSUCHNAME);
        return SNMP_ERR_NOERROR;
    }
    return(1);
}
int
NetSnmpAgent::netsnmp_register_null(unsigned int*  loc, size_t loc_len)
{
    return netsnmp_register_null_context(loc, loc_len, NULL);
}

int
NetSnmpAgent::netsnmp_register_null_context(unsigned int*  loc, size_t loc_len,
                              const char* contextName)
{
    netsnmp_handler_registration* reginfo;
    reginfo = (netsnmp_handler_registration*)calloc
        (1, sizeof(netsnmp_handler_registration));
    if (reginfo != NULL) {
        reginfo->handlerName = strdup("");
        reginfo->rootoid = loc;
        reginfo->rootoid_len = loc_len;
         reginfo->handler =
            netsnmp_create_handler("null", netsnmp_null_handler);
        if (contextName)
            reginfo->contextName = strdup(contextName);
        reginfo->modes = HANDLER_CAN_DEFAULT | HANDLER_CAN_GETBULK;
    }
    return netsnmp_register_handler(reginfo);
}
