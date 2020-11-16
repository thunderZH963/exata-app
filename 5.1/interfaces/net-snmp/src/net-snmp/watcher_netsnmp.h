/*
 * watcher.h
 */
#ifndef NETSNMP_WATCHER_H_NETSNMP
#define NETSNMP_WATCHER_H_NETSNMP

#include "asn1_netsnmp.h"
#include "agent_handler_netsnmp.h"

/** @ingroup watcher
 *  @{
 */

/*
 * if handler flag has this bit set, the timestamp will be
 * treated as a pointer to the timestamp. If this bit is
 * not set (the default), the timestamp is a struct timeval
 * that must be compared to the agent starttime.
 */
#define NETSNMP_WATCHER_DIRECT MIB_HANDLER_CUSTOM1

/** The size of the watched object is constant.
 *  @hideinitializer
 */
#define WATCHER_FIXED_SIZE    0x01
/** The maximum size of the watched object is stored in max_size.
 *  If WATCHER_SIZE_STRLEN is set then it is supposed that max_size + 1
 *  bytes could be stored in the buffer.
 *  @hideinitializer
 */
#define WATCHER_MAX_SIZE      0x02
/** If set then the variable data_size_p points to is supposed to hold the
 *  current size of the watched object and will be updated on writes.
 *  @hideinitializer
 *  @since Net-SNMP 5.5
 */
#define WATCHER_SIZE_IS_PTR   0x04
/** If set then data is suppposed to be a zero-terminated character array
 *  and both data_size and data_size_p are ignored. Additionally \\0 is a
 *  forbidden character in the data set.
 *  @hideinitializer
 *  @since Net-SNMP 5.5
 */
#define WATCHER_SIZE_STRLEN   0x08

typedef struct netsnmp_watcher_info_s {
    void*     data;
    size_t    data_size;
    size_t    max_size;
    u_char    type;
    int       flags;
    size_t*   data_size_p;
} netsnmp_watcher_info;

netsnmp_watcher_info*
netsnmp_init_watcher_info(netsnmp_watcher_info *, void *, size_t, u_char, int);

netsnmp_watcher_info*
netsnmp_init_watcher_info6(netsnmp_watcher_info* ,
               void* , size_t, u_char, int, size_t, size_t*);

netsnmp_watcher_info*
netsnmp_create_watcher_info(void* , size_t, u_char, int);

netsnmp_watcher_info*
netsnmp_create_watcher_info6(void* , size_t, u_char, int, size_t, size_t*);

Netsnmp_Node_Handler  netsnmp_watcher_helper_handler;

Netsnmp_Node_Handler  netsnmp_watched_timestamp_handler;

Netsnmp_Node_Handler  netsnmp_watched_spinlock_handler;


#endif /** NETSNMP_WATCHER_H */
