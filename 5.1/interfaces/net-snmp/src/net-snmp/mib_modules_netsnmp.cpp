#include "netSnmpAgent.h"

/*
 * wrapper to call all the mib module initialization functions
 */


int
NetSnmpAgent::_shutdown_mib_modules(int majorID, int minorID, void* serve, void* client)
{
    need_shutdown = 0;
    return SNMPERR_SUCCESS; /* callback rc ignored */
}

void
NetSnmpAgent::init_mib_modules(void)
{
    static int once = 0;

#  include "mib_modules_inits_netsnmp.h"

    need_shutdown = 1;

    if (once == 0) {
        int rc;
        once = 1;
        rc = snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                                     SNMP_CALLBACK_SHUTDOWN,
                                     &NetSnmpAgent::_shutdown_mib_modules,
                                     NULL);
    }
}
