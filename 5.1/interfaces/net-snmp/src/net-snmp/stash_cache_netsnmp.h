#ifndef STASH_CACHE_H_NETSNMP
#define STASH_CACHE_H_NETSNMP

#include "tools_netsnmp.h"
#include "agent_handler_netsnmp.h"
#include "types_netsnmp.h"
#include "oid_stash_netsnmp.h"

#define STASH_CACHE_NAME "stash_cache"

typedef struct netsnmp_stash_cache_info_s {
   int                      cache_valid;
   marker_t                 cache_time;
   netsnmp_oid_stash_node*  cache;
   int                      cache_length;
} netsnmp_stash_cache_info;

typedef struct netsnmp_stash_cache_data_s {
   void*              data;
   size_t             data_len;
   u_char             data_type;
} netsnmp_stash_cache_data;

Netsnmp_Node_Handler netsnmp_stash_cache_helper;
netsnmp_oid_stash_node**  netsnmp_extract_stash_cache(netsnmp_agent_request_info* reqinfo);
#endif /* STASH_CACHE_H */
