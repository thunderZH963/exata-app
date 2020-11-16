#ifndef SERIALIZE_H_NETSNMP
#define SERIALIZE_H_NETSNMP

#include "agent_handler_netsnmp.h"

    netsnmp_mib_handler* netsnmp_get_serialize_handler(void);
    void            netsnmp_init_serialize(void);

#endif /* SERIALIZE_H_NETSNMP */
