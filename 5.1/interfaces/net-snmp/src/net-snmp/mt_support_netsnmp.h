#ifndef MT_SUPPORT_H_NETSNMP
#define MT_SUPPORT_H_NETSNMP



/*
 * Lock group identifiers
 */

#define MT_LIBRARY_ID      0
#define MT_LIB_REQUESTID   2
#define MT_LIB_MESSAGEID   3

#define MT_MAX_IDS         3    /* one greater than last from above */
#define MT_MAX_SUBIDS      10


/*
 * Lock resource identifiers for library resources
 */

#define MT_LIB_NONE        0
#define MT_LIB_SESSION     1
#define MT_LIB_REQUESTID   2
#define MT_LIB_MESSAGEID   3
#define MT_LIB_SESSIONID   4
#define MT_LIB_TRANSID     5

#define MT_LIB_MAXIMUM     6    /* must be one greater than the last one */


int             snmp_res_lock(int groupID, int resourceID);
int             snmp_res_unlock(int groupID, int resourceID);


#endif /* MT_SUPPORT_H_NETSNMP */
