#include "serialize_netsnmp.h"

#include "read_only_netsnmp.h"
#include "netSnmpAgent.h"

/** call the initialization sequence for all handlers with init_ routines. */
void
NetSnmpAgent::netsnmp_init_helpers(void)
{
    netsnmp_init_serialize();
    netsnmp_init_read_only_helper();
    netsnmp_init_bulk_to_next_helper();
    netsnmp_init_table_dataset();
    netsnmp_init_stash_cache_helper();
}
