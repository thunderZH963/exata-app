/*
 * callback.c: A generic callback mechanism
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/** @defgroup callback A generic callback mechanism
 *  @ingroup library
 *
 *  @{
 */





/**
 * This function calls the callback function for each registered callback of
 * type major and minor.
 *
 * @param major is the SNMP callback major type used
 *
 * @param minor is the SNMP callback minor type used
 *
 * @param caller_arg is a void pointer which is sent in as the callback's
 *    serverarg parameter, if needed.
 *
 * @return Returns SNMPERR_GENERR if major is >= MAX_CALLBACK_IDS or
 * minor is >= MAX_CALLBACK_SUBIDS, otherwise SNMPERR_SUCCESS is returned.
 *
 * @see snmp_register_callback
 * @see snmp_unregister_callback
 */

#include "netSnmpAgent.h"
#include "callback_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "tools_netsnmp.h"
#include<string.h>

/*
 * the chicken. or the egg.  You pick.
 */
void
NetSnmpAgent::init_callbacks(void)
{
    /*
     * (poses a problem if you put init_callbacks() inside of
     * init_snmp() and then want the app to register a callback before
     * init_snmp() is called in the first place.  -- Wes
     */
    if (0 == _callback_need_init)
        return;

    _callback_need_init = 0;

    memset(thecallbacks, 0, sizeof(thecallbacks));
}



int
NetSnmpAgent::snmp_call_callbacks(int major, int minor, void* caller_arg)
{
    struct snmp_gen_callback* scp;
    unsigned int    count = 0;

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if (_callback_need_init)
        init_callbacks();

    /*
     * for each registered callback of type major and minor
     */
    for (scp = thecallbacks[major][minor]; scp != NULL; scp = scp->next) {

        /*
         * skip unregistered callbacks
         */
        if (NULL == scp->sc_callback)
            continue;

        /*
         * call them
         */
        (this->*(scp->sc_callback)) (major, minor, caller_arg,
                               scp->sc_client_arg);
        count++;
    }

    return SNMPERR_SUCCESS;
}

int
NetSnmpAgent::netsnmp_register_callback(int major, int minor,
             int (NetSnmpAgent::*new_callback) (int majorID, int minorID,
                void* serverarg, void* clientarg),
                          void* arg, int priority)
{
    struct snmp_gen_callback* newscp = NULL, *scp = NULL;
    struct snmp_gen_callback** prevNext = &(thecallbacks[major][minor]);

    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if (_callback_need_init)
        init_callbacks();

    if ((newscp = SNMP_MALLOC_STRUCT(snmp_gen_callback)) == NULL) {
        return SNMPERR_GENERR;
    } else {
        newscp->priority = priority;
        newscp->sc_client_arg = arg;
        newscp->sc_callback = new_callback;
        newscp->next = NULL;

        for (scp = thecallbacks[major][minor]; scp != NULL;
             scp = scp->next) {
            if (newscp->priority < scp->priority) {
                newscp->next = scp;
                break;
            }
            prevNext = &(scp->next);
        }

        *prevNext = newscp;

        return SNMPERR_SUCCESS;
    }
}


 /* @param new_callback is the callback function that is registered.
 *
 * @param arg when not NULL is a void pointer used whenever new_callback
 *    function is exercised.
 *
 * @return
 *    Returns SNMPERR_GENERR if major is >= MAX_CALLBACK_IDS or minor is >=
 *    MAX_CALLBACK_SUBIDS or a snmp_gen_callback pointer could not be
 *    allocated, otherwise SNMPERR_SUCCESS is returned.
 *     - \#define MAX_CALLBACK_IDS    2
 *    - \#define MAX_CALLBACK_SUBIDS 16
 *
 * @see snmp_call_callbacks
 * @see snmp_unregister_callback
 */
int
NetSnmpAgent::snmp_register_callback(int major, int minor,
               int (NetSnmpAgent::*new_callback) (int majorID, int minorID,
                void* serverarg, void* clientarg),
                void* arg)
{
    return netsnmp_register_callback(major, minor, new_callback, arg,
                                      NETSNMP_CALLBACK_DEFAULT_PRIORITY);
}



/**
 * find and clear client args that match ptr
 *
 * @param ptr  pointer to search for
 * @param i    callback id to start at
 * @param j    callback subid to start at
 */
int
NetSnmpAgent::netsnmp_callback_clear_client_arg(void* ptr, int i, int j)
{
    struct snmp_gen_callback* scp = NULL;
    int rc = 0;

    /*
     * don't init i and j before loop, since the caller specified
     * the starting point explicitly. But* after* the i loop has
     * finished executing once, init j to 0 for the next pass
     * through the subids.
     */
    for (; i < MAX_CALLBACK_IDS; i++,j=0) {
        for (; j < MAX_CALLBACK_SUBIDS; j++) {
            scp = thecallbacks[i][j];
            while (scp != NULL) {
                if ((NULL != scp->sc_callback) &&
                    (scp->sc_client_arg != NULL) &&
                    (scp->sc_client_arg == ptr)) {
                    scp->sc_client_arg = NULL;
                    ++rc;
                }
                scp = scp->next;
            }
        }
    }

    return rc;
}


int
NetSnmpAgent::snmp_callback_available(int major, int minor)
{
    if (major >= MAX_CALLBACK_IDS || minor >= MAX_CALLBACK_SUBIDS) {
        return SNMPERR_GENERR;
    }

    if (_callback_need_init)
        init_callbacks();

    if (thecallbacks[major][minor] != NULL) {
        return SNMPERR_SUCCESS;
    }

    return SNMPERR_GENERR;
}




void
NetSnmpAgent::clear_callback(void)
{
    unsigned int i = 0, j = 0;
    struct snmp_gen_callback* scp = NULL;

    if (_callback_need_init)
        init_callbacks();

    for (i = 0; i < MAX_CALLBACK_IDS; i++) {
        for (j = 0; j < MAX_CALLBACK_SUBIDS; j++) {
            scp = thecallbacks[i][j];
            while (scp != NULL) {
                thecallbacks[i][j] = scp->next;
                /*
                 * if there is a client arg, check for duplicates
                 * and then free it.
                 */
                if ((NULL != scp->sc_callback) &&
                    (scp->sc_client_arg != NULL)) {
                    void* tmp_arg;
                    /*
                     * save the client arg, then set it to null so that it
                     * won't look like a duplicate, then check for duplicates
                     * starting at the current i,j (earlier dups should have
                     * already been found) and free the pointer.
                     */
                    tmp_arg = scp->sc_client_arg;
                    scp->sc_client_arg = NULL;
                    (void)netsnmp_callback_clear_client_arg(tmp_arg, i, j);
                    free(tmp_arg);
                }
                SNMP_FREE(scp);
                scp = thecallbacks[i][j];
            }
        }
    }
}
