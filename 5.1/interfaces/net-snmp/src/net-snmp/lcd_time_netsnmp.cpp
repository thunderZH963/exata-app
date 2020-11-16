/*
 * lcd_time.c
 *
 * XXX  Should etimelist entries with <0,0> time tuples be timed out?
 * XXX  Need a routine to free the memory?  (Perhaps at shutdown?)
 */

/*
 * Global static hashlist to contain Enginetime entries.
 *
 * New records are prepended to the appropriate list at the hash index.
 */


#include "lcd_time_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"
#include "netSnmpAgent.h"
#include "scapi_netsnmp.h"
#include "transform_oids_netsnmp.h"



/*******************************************************************-o-******
 * get_enginetime
 *
 * Parameters:
 *    *engineID
 *     engineID_len
 *    *engineboot
 *    *engine_time
 *
 * Returns:
 *    SNMPERR_SUCCESS        Success -- when a record for engineID is found.
 *    SNMPERR_GENERR        Otherwise.
 *
 *
 * Lookup engineID and return the recorded values for the
 * <engine_time, engineboot> tuple adjusted to reflect the estimated time
 * at the engine in question.
 *
 * Special case: if engineID is NULL or if engineID_len is 0 then
 * the time tuple is returned immediately as zero.
 *
 * XXX    What if timediff wraps?  >shrug<
 * XXX  Then: you need to increment the boots value.  Now.  Detecting
 *            this is another matter.
 */
int
NetSnmpAgent::get_enginetime(u_char*  engineID,
               u_int engineID_len,
               u_int*  engineboot,
               u_int*  engine_time, u_int authenticated)
{
    int             rval = SNMPERR_SUCCESS;
    time_t          timediff = 0;
    Enginetime      e = NULL;



    /*
     * Sanity check.
     */
    if (!engine_time || !engineboot) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
    }


    /*
     * Compute estimated current engine_time tuple at engineID if
     * a record is cached for it.
     */
    *engine_time = *engineboot = 0;

    if (!engineID || (engineID_len <= 0)) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
    }

    if (!(e = search_enginetime_list(engineID, engineID_len))) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_quit);
    }
#ifdef LCD_TIME_SYNC_OPT
    if (!authenticated || e->authenticatedFlag) {
#endif
        *engine_time = e->engineTime;
        *engineboot = e->engineBoot;

       timediff = snmpv3_local_snmpEngineTime() - e->lastReceivedEngineTime;

#ifdef LCD_TIME_SYNC_OPT
    }
#endif

    if (timediff > (int) (ENGINETIME_MAX - *engine_time)) {
        *engine_time = (timediff - (ENGINETIME_MAX - *engine_time));

        /*
         * FIX -- move this check up... should not change anything
         * * if engineboot is already locked.  ???
         */
        if (*engineboot < ENGINEBOOT_MAX) {
            *engineboot += 1;
        }

    } else {
        *engine_time += timediff;
    }

  get_enginetime_quit:
    return rval;

}                               /* end get_enginetime() */

/*******************************************************************-o-******
 * get_enginetime
 *
 * Parameters:
 *    *engineID
 *     engineID_len
 *    *engineboot
 *    *engine_time
 *
 * Returns:
 *    SNMPERR_SUCCESS        Success -- when a record for engineID is found.
 *    SNMPERR_GENERR        Otherwise.
 *
 *
 * Lookup engineID and return the recorded values for the
 * <engine_time, engineboot> tuple adjusted to reflect the estimated time
 * at the engine in question.
 *
 * Special case: if engineID is NULL or if engineID_len is 0 then
 * the time tuple is returned immediately as zero.
 *
 * XXX    What if timediff wraps?  >shrug<
 * XXX  Then: you need to increment the boots value.  Now.  Detecting
 *            this is another matter.
 */
int
NetSnmpAgent::get_enginetime_ex(u_char*  engineID,
                  u_int engineID_len,
                  u_int*  engineboot,
                  u_int*  engine_time,
                  u_int*  last_engine_time, u_int authenticated)
{
    int             rval = SNMPERR_SUCCESS;
    time_t          timediff = 0;
    Enginetime      e = NULL;



    /*
     * Sanity check.
     */
    if (!engine_time || !engineboot || !last_engine_time) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_ex_quit);
    }


    /*
     * Compute estimated current engine_time tuple at engineID if
     * a record is cached for it.
     */
    *last_engine_time = *engine_time = *engineboot = 0;

    if (!engineID || (engineID_len <= 0)) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_ex_quit);
    }

    if (!(e = search_enginetime_list(engineID, engineID_len))) {
        QUITFUN(SNMPERR_GENERR, get_enginetime_ex_quit);
    }
#ifdef LCD_TIME_SYNC_OPT
    if (!authenticated || e->authenticatedFlag) {
#endif
        *last_engine_time = *engine_time = e->engineTime;
        *engineboot = e->engineBoot;

       timediff = snmpv3_local_snmpEngineTime() - e->lastReceivedEngineTime;

#ifdef LCD_TIME_SYNC_OPT
    }
#endif

    if (timediff > (int) (ENGINETIME_MAX - *engine_time)) {
        *engine_time = (timediff - (ENGINETIME_MAX - *engine_time));

        /*
         * FIX -- move this check up... should not change anything
         * * if engineboot is already locked.  ???
         */
        if (*engineboot < ENGINEBOOT_MAX) {
            *engineboot += 1;
        }

    } else {
        *engine_time += timediff;
    }

  get_enginetime_ex_quit:
    return rval;

}                               /* end get_enginetime_ex() */


void NetSnmpAgent::free_enginetime(unsigned char* engineID, size_t engineID_len)
{
    Enginetime      e = NULL;
    int             rval = 0;

    rval = hash_engineID(engineID, engineID_len);
    if (rval < 0)
    return;

    e = etimelist[rval];

    while (e != NULL) {
    etimelist[rval] = e->next;
    SNMP_FREE(e->engineID);
    SNMP_FREE(e);
    e = etimelist[rval];
    }

}

/*******************************************************************-o-****
**
 * free_etimelist
 *
 * Parameters:
 *   None
 *
 * Returns:
 *   void
 *
 *
 * Free all of the memory used by entries in the etimelist.
 *
 */
void NetSnmpAgent::free_etimelist(void)
{
     int index = 0;
     Enginetime e = NULL;
     Enginetime nextE = NULL;

     for (; index < ETIMELIST_SIZE; ++index)
     {
           e = etimelist[index];

           while (e != NULL)
           {
                 nextE = e->next;
                 SNMP_FREE(e->engineID);
                 SNMP_FREE(e);
                 e = nextE;
           }

           etimelist[index] = NULL;
     }
     return;
}

/*******************************************************************-o-******
 * set_enginetime
 *
 * Parameters:
 *    *engineID
 *     engineID_len
 *     engineboot
 *     engine_time
 *
 * Returns:
 *    SNMPERR_SUCCESS        Success.
 *    SNMPERR_GENERR        Otherwise.
 *
 *
 * Lookup engineID and store the given <engine_time, engineboot> tuple
 * and then stamp the record with a consistent source of local time.
 * If the engineID record does not exist, create one.
 *
 * Special case: engineID is NULL or engineID_len is 0 defines an engineID
 * that is "always set."
 *
 * XXX    "Current time within the local engine" == time(NULL)...
 */
int
NetSnmpAgent::set_enginetime(u_char*  engineID,
               u_int engineID_len,
               u_int engineboot, u_int engine_time, u_int authenticated)
{
    int             rval = SNMPERR_SUCCESS, iindex;
    Enginetime      e = NULL;



    /*
     * Sanity check.
     */
    if (!engineID || (engineID_len <= 0)) {
        return rval;
    }


    /*
     * Store the given <engine_time, engineboot> tuple in the record
     * for engineID.  Create a new record if necessary.
     */
    if (!(e = search_enginetime_list(engineID, engineID_len))) {
        if ((iindex = hash_engineID(engineID, engineID_len)) < 0) {
            QUITFUN(SNMPERR_GENERR, set_enginetime_quit);
        }

        e = (Enginetime) calloc(1, sizeof(*e));

        e->next = etimelist[iindex];
        etimelist[iindex] = e;

        e->engineID = (u_char*) calloc(1, engineID_len);
        memcpy(e->engineID, engineID, engineID_len);

        e->engineID_len = engineID_len;
    }
#ifdef LCD_TIME_SYNC_OPT
    if (authenticated || !e->authenticatedFlag) {
        e->authenticatedFlag = authenticated;
#else
    if (authenticated) {
#endif
        e->engineTime = engine_time;
        e->engineBoot = engineboot;
        e->lastReceivedEngineTime = snmpv3_local_snmpEngineTime();
    }

    e = NULL;                   /* Indicates a successful update. */

  set_enginetime_quit:
    SNMP_FREE(e);

    return rval;

}                               /* end set_enginetime() */




/*******************************************************************-o-******
 * search_enginetime_list
 *
 * Parameters:
 *    *engineID
 *     engineID_len
 *
 * Returns:
 *    Pointer to a etimelist record with engineID <engineID>  -OR-
 *    NULL if no record exists.
 *
 *
 * Search etimelist for an entry with engineID.
 *
 * ASSUMES that no engineID will have more than one record in the list.
 */
Enginetime
NetSnmpAgent::search_enginetime_list(u_char*  engineID, u_int engineID_len)
{
    int             rval = SNMPERR_SUCCESS;
    Enginetime      e = NULL;


    /*
     * Sanity check.
     */
    if (!engineID || (engineID_len <= 0)) {
        QUITFUN(SNMPERR_GENERR, search_enginetime_list_quit);
    }


    /*
     * Find the entry for engineID if there be one.
     */
    rval = hash_engineID(engineID, engineID_len);
    if (rval < 0) {
        QUITFUN(SNMPERR_GENERR, search_enginetime_list_quit);
    }
    e = etimelist[rval];

    for (/*EMPTY*/; e; e = e->next) {
        if ((engineID_len == e->engineID_len)
            && !memcmp(e->engineID, engineID, engineID_len)) {
            break;
        }
    }


  search_enginetime_list_quit:
    return e;

}                               /* end search_enginetime_list() */





/*******************************************************************-o-******
 * hash_engineID
 *
 * Parameters:
 *    *engineID
 *     engineID_len
 *
 * Returns:
 *    >0            etimelist index for this engineID.
 *    SNMPERR_GENERR        Error.
 *
 *
 * Use a cheap hash to build an index into the etimelist.  Method is
 * to hash the engineID, then split the hash into u_int's and add them up
 * and modulo the size of the list.
 *
 */
int
hash_engineID(u_char*  engineID, u_int engineID_len)
{
    int             rval = SNMPERR_GENERR;
    size_t          buf_len = SNMP_MAXBUF;
    u_int           additive = 0;
    u_char*         bufp, buf[SNMP_MAXBUF];
    void*           context = NULL;



    /*
     * Sanity check.
     */
    if (!engineID || (engineID_len <= 0)) {
        QUITFUN(SNMPERR_GENERR, hash_engineID_quit);
    }


    /*
     * Hash engineID into a list index.
     */
#ifndef NETSNMP_DISABLE_MD5
    rval = sc_hash(usmHMACMD5AuthProtocol,
                   sizeof(usmHMACMD5AuthProtocol) / sizeof(oid),
                   engineID, engineID_len, buf, &buf_len);
#else
    rval = sc_hash(usmHMACSHA1AuthProtocol,
                   sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid),
                   engineID, engineID_len, buf, &buf_len);
#endif
    QUITFUN(rval, hash_engineID_quit);

    for (bufp = buf; (bufp - buf) < (int) buf_len; bufp += 4) {
        additive += (u_int) * bufp;
    }

  hash_engineID_quit:
    SNMP_FREE(context);
    memset(buf, 0, SNMP_MAXBUF);

    return (rval < 0) ? rval : (additive % ETIMELIST_SIZE);

}                               /* end hash_engineID() */
