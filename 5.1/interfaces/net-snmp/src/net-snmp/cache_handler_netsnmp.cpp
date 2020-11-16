
#include "netSnmpAgent.h"
#include "cache_handler_netsnmp.h"
#include "ds_agent_netsnmp.h"
#include "tools_netsnmp.h"

#define CACHE_NAME "cache_info"

static int cache_outstanding_valid = 0;
static netsnmp_cache*  cache_head = NULL;

#define CACHE_RELEASE_FREQUENCY 60      /* Check for expired caches every 60s */
void            release_cached_resources(unsigned int regNo,
                                         void* clientargs);
/** returns a cache
 */
netsnmp_cache*
NetSnmpAgent::netsnmp_cache_create(int timeout, NetsnmpCacheLoad*  load_hook,
                     NetsnmpCacheFree*  free_hook,
                     const oid*  rootoid, int rootoid_len)
{
    struct netsnmp_cache_s*  cache = NULL;

    cache = SNMP_MALLOC_TYPEDEF(netsnmp_cache);
    if (NULL == cache) {
        return NULL;
    }
    cache->timeout = timeout;
    cache->load_cache = load_hook;
    cache->free_cache = free_hook;
    cache->enabled = 1;

    if (0 == cache->timeout)
        cache->timeout = netsnmp_ds_get_int(NETSNMP_DS_APPLICATION_ID,
                                            NETSNMP_DS_AGENT_CACHE_TIMEOUT);


    /*
     * Add the registered OID information, and tack
     * this onto the list for cache SNMP management
     *
     * Note that this list is not ordered.
     *    table_iterator rules again!
     */
    if (rootoid) {
        cache->rootoid = snmp_duplicate_objid(rootoid, rootoid_len);
        cache->rootoid_len = rootoid_len;
        cache->next = cache_head;
        if (cache_head)
            cache_head->prev = cache;
        cache_head = cache;
    }

    return cache;
}


/** returns a cache handler that can be injected into a given handler chain.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_cache_handler_get(netsnmp_cache* cache)
{
    netsnmp_mib_handler* ret = NULL;

    ret = netsnmp_create_handler("cache_handler",
                                 netsnmp_cache_helper_handler);
    if (ret) {
        ret->flags |= MIB_HANDLER_AUTO_NEXT;
        ret->myvoid = (void*) cache;

        if (NULL != cache) {
            if ((cache->flags & NETSNMP_CACHE_PRELOAD) && ! cache->valid) {
                /*
                 * load cache, ignore rc
                 * (failed load doesn't affect registration)
                 */
                (void)_cache_load(cache);
            }
            if (cache->flags & NETSNMP_CACHE_AUTO_RELOAD)
                netsnmp_cache_timer_start(cache);

        }
    }
    return ret;
}


/** returns a cache handler that can be injected into a given handler chain.
 */
netsnmp_mib_handler*
NetSnmpAgent::netsnmp_get_cache_handler(int timeout, NetsnmpCacheLoad*  load_hook,
                          NetsnmpCacheFree*  free_hook,
                          const oid*  rootoid, int rootoid_len)
{
    netsnmp_mib_handler* ret = NULL;
    netsnmp_cache*  cache = NULL;

    ret = netsnmp_cache_handler_get(NULL);
    if (ret) {
        cache = netsnmp_cache_create(timeout, load_hook, free_hook,
                                     rootoid, rootoid_len);
        ret->myvoid = (void*) cache;
    }
    return ret;
}


/** Implements the cache handler */
int
netsnmp_cache_helper_handler(netsnmp_mib_handler*  handler,
                             netsnmp_handler_registration*  reginfo,
                             netsnmp_agent_request_info*  reqinfo,
                             netsnmp_request_info*  requests,Node* node=NULL)
{
    netsnmp_cache*  cache = NULL;
    netsnmp_handler_args cache_hint;

    cache = (netsnmp_cache*) handler->myvoid;
    /*
     * Make the handler-chain parameters available to
     * the cache_load hook routine.
     */
    cache_hint.handler = handler;
    cache_hint.reginfo = reginfo;
    cache_hint.reqinfo = reqinfo;
    cache_hint.requests = requests;
    cache->cache_hint = &cache_hint;

    switch (reqinfo->mode) {

    case MODE_GET:
    case MODE_GETNEXT:
    case MODE_GETBULK:
    case MODE_SET_RESERVE1:

        /*
         * only touch cache once per pdu request, to prevent a cache
         * reload while a module is using cached data.
         *
         * XXX: this won't catch a request reloading the cache while
         * a previous (delegated) request is still using the cache.
         * maybe use a reference counter?
         */
        if (netsnmp_cache_is_valid(reqinfo, reginfo->handlerName))
            break;

        /*
         * call the load hook, and update the cache timestamp.
         * If it's not already there, add to reqinfo
         */
        netsnmp_cache_check_and_reload(cache);
        netsnmp_cache_reqinfo_insert(cache, reqinfo, reginfo->handlerName);
        /** next handler called automatically - 'AUTO_NEXT' */
        break;

    case MODE_SET_RESERVE2:
    case MODE_SET_FREE:
    case MODE_SET_ACTION:
    case MODE_SET_UNDO:
        /** next handler called automatically - 'AUTO_NEXT' */
        break;

        /*
         * A (successful) SET request wouldn't typically trigger a reload of
         *  the cache, but might well invalidate the current contents.
         * Only do this on the last pass through.
         */
    case MODE_SET_COMMIT:
        if (cache->valid &&
            ! (cache->flags & NETSNMP_CACHE_DONT_INVALIDATE_ON_SET)) {
            cache->free_cache(cache, cache->magic);
            cache->valid = 0;
        }
        /** next handler called automatically - 'AUTO_NEXT' */
        break;

    default:
        netsnmp_request_set_error_all(requests, SNMP_ERR_GENERR);
        return SNMP_ERR_GENERR;
    }
    return SNMP_ERR_NOERROR;
}

static void
_cache_free(netsnmp_cache* cache)
{
    if (NULL != cache->free_cache) {
        cache->free_cache(cache, cache->magic);
        cache->valid = 0;
    }
}

int
NetSnmpAgent::_cache_load(netsnmp_cache* cache)
{
    int ret = -1;

    /*
     * If we've got a valid cache, then release it before reloading
     */
    if (cache->valid &&
        (! (cache->flags & NETSNMP_CACHE_DONT_FREE_BEFORE_LOAD)))
        _cache_free(cache);

    if (cache->load_cache)
        ret = cache->load_cache(cache, cache->magic, this->node);
    if (ret < 0) {
        cache->valid = 0;
        return ret;
    }
    cache->valid = 1;
    cache->expired = 0;

    return ret;
}

unsigned int
netsnmp_cache_timer_start(netsnmp_cache* cache)
{
    if (NULL == cache)
        return 0;

    if (0 != cache->timer_id) {
        return cache->timer_id;
    }

    if (! (cache->flags & NETSNMP_CACHE_AUTO_RELOAD)) {
        return 0;
    }

    cache->timer_id = 0;
    if (0 == cache->timer_id) {
        return 0;
    }

    cache->flags &= ~NETSNMP_CACHE_AUTO_RELOAD;
    return cache->timer_id;
}

/** Is the cache valid for a given request? */
int
netsnmp_cache_is_valid(netsnmp_agent_request_info*  reqinfo,
                       const char* name)
{
    netsnmp_cache*  cache = netsnmp_cache_reqinfo_extract(reqinfo, name);
    return (cache && cache->valid);
}

NETSNMP_STATIC_INLINE char*
_build_cache_name(const char* name)
{
    char* dup = (char*)malloc(strlen(name) + strlen(CACHE_NAME) + 2);
    if (NULL == dup)
        return NULL;
    sprintf(dup, "%s:%s", CACHE_NAME, name);
    return dup;
}

/** Extract the cache information for a given request (PDU) */
netsnmp_cache*
netsnmp_cache_reqinfo_extract(netsnmp_agent_request_info*  reqinfo,
                              const char* name)
{
    netsnmp_cache*  result;
    char* cache_name = _build_cache_name(name);
    result = (netsnmp_cache*)
            netsnmp_agent_get_list_data(reqinfo, cache_name);
    SNMP_FREE(cache_name);
    return result;
}

/** Reload the cache if required */
int
netsnmp_cache_check_and_reload(netsnmp_cache*  cache)
{
    if (!cache) {
        return 0;    /* ?? or -1 */
    }
    return 0;
}

/** Insert the cache information for a given request (PDU) */
void
netsnmp_cache_reqinfo_insert(netsnmp_cache* cache,
                             netsnmp_agent_request_info*  reqinfo,
                             const char* name)
{
    char* cache_name = _build_cache_name(name);
    if (NULL == netsnmp_agent_get_list_data(reqinfo, cache_name)) {
        netsnmp_agent_add_list_data(reqinfo,
                                    netsnmp_create_data_list(cache_name,
                                                             cache, NULL));
    }
    SNMP_FREE(cache_name);
}

/** run regularly to automatically release cached resources.
 * xxx - method to prevent cache from expiring while a request
 *     is being processed (e.g. delegated request). proposal:
 *     set a flag, which would be cleared when request finished
 *     (which could be acomplished by a dummy data list item in
 *     agent req info & custom free function).
 */
void
release_cached_resources(unsigned int regNo, void* clientargs)
{
    netsnmp_cache*  cache = NULL;

    cache_outstanding_valid = 0;
    for (cache = cache_head; cache; cache = cache->next) {
        if (cache->valid &&
            ! (cache->flags & NETSNMP_CACHE_DONT_AUTO_RELEASE)) {
            /*
             * Check to see if this cache has timed out.
             * If so, release the cached resources.
             * Otherwise, note that we still have at
             *   least one active cache.
             */
            if (netsnmp_cache_check_expired(cache)) {
                if (! (cache->flags & NETSNMP_CACHE_DONT_FREE_EXPIRED))
                    _cache_free(cache);
            } else {
                cache_outstanding_valid = 1;
            }
        }
    }
}

/** Check if the cache timeout has passed. Sets and return the expired flag. */
int
netsnmp_cache_check_expired(netsnmp_cache* cache)
{
    if (NULL == cache)
        return 0;

    if (!cache->valid || (NULL == cache->timestamp) || (-1 == cache->timeout))
        cache->expired = 1;
    else
        cache->expired = atime_ready(cache->timestamp, 1000 * cache->timeout);

    return cache->expired;
}
