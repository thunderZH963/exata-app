#ifndef CACHE_HANDLER_NETSNMP
#define CACHE_HANDLER_NETSNMP

#include "agent_handler_netsnmp.h"

    typedef struct netsnmp_cache_s netsnmp_cache;

    typedef int  (NetsnmpCacheLoad)(netsnmp_cache* , void*, struct Node*);
    typedef void (NetsnmpCacheFree)(netsnmp_cache* , void*);
    Netsnmp_Node_Handler netsnmp_cache_helper_handler;

#define NETSNMP_CACHE_DONT_INVALIDATE_ON_SET                0x0001
#define NETSNMP_CACHE_DONT_FREE_BEFORE_LOAD                 0x0002
#define NETSNMP_CACHE_DONT_FREE_EXPIRED                     0x0004
#define NETSNMP_CACHE_DONT_AUTO_RELEASE                     0x0008
#define NETSNMP_CACHE_PRELOAD                               0x0010
#define NETSNMP_CACHE_AUTO_RELOAD                           0x0020

    struct netsnmp_cache_s {
        /*
     * For operation of the data caches
     */
        int      flags;
        int      enabled;
        int      valid;
        char     expired;
        int      timeout;    /* Length of time the cache is valid (in s) */
        marker_t timestamp;    /* When the cache was last loaded */
        u_long   timer_id;      /* periodic timer id */

        NetsnmpCacheLoad* load_cache;
        NetsnmpCacheFree* free_cache;

       /*
        * void pointer for the user that created the cache.
        * You never know when it might not come in useful ....
        */
        void*             magic;

       /*
        * hint from the cache helper. contains the standard
        * handler arguments.
        */
       netsnmp_handler_args*          cache_hint;

        /*
     * For SNMP-management of the data caches
     */
    netsnmp_cache* next, *prev;
        oid* rootoid;
        int  rootoid_len;

    };
    netsnmp_cache*   netsnmp_cache_reqinfo_extract(netsnmp_agent_request_info*  reqinfo,
                              const char* name);
    int netsnmp_cache_is_valid(netsnmp_agent_request_info*  reqinfo,
                       const char* name);
    int            netsnmp_cache_check_and_reload(netsnmp_cache*  cache);
    void netsnmp_cache_reqinfo_insert(netsnmp_cache* cache,
                                      netsnmp_agent_request_info*  reqinfo,
                                      const char* name);
    int netsnmp_cache_check_expired(netsnmp_cache* cache);
    unsigned int netsnmp_cache_timer_start(netsnmp_cache* cache);
#endif

