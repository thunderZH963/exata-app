/*
 * snmp_alarm.c:
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
/** @defgroup snmp_alarm  generic library based alarm timers for various parts of an application
 *  @ingroup library
 *
 *  @{
 */

#include "netSnmpAgent.h"

struct snmp_alarm*
NetSnmpAgent::sa_find_next(void)
{
    struct snmp_alarm* a, *lowest = NULL;
    struct timeval  t_now = {0};

    for (a = thealarms; a != NULL; a = a->next) {
        /* check for time delta skew */
        if ((a->t_next.tv_sec - t_now.tv_sec) > a->t.tv_sec)
        {
            a->t_next.tv_sec = t_now.tv_sec + a->t.tv_sec;
            a->t_next.tv_usec = t_now.tv_usec + a->t.tv_usec;
        }
        if (lowest == NULL) {
            lowest = a;
        } else if (a->t_next.tv_sec == lowest->t_next.tv_sec) {
            if (a->t_next.tv_usec < lowest->t_next.tv_usec) {
                lowest = a;
            }
        } else if (a->t_next.tv_sec < lowest->t_next.tv_sec) {
            lowest = a;
        }
    }
    return lowest;
}

struct snmp_alarm*
    NetSnmpAgent::sa_find_specific(unsigned int clientreg)
{
    struct snmp_alarm* sa_ptr;
    for (sa_ptr = thealarms; sa_ptr != NULL; sa_ptr = sa_ptr->next) {
        if (sa_ptr->clientreg == clientreg) {
            return sa_ptr;
        }
    }
    return NULL;
}

int
NetSnmpAgent::get_next_alarm_delay_time(struct timeval* delta)
{
    struct snmp_alarm* sa_ptr;
    struct timeval  t_diff, t_now = {0};

    sa_ptr = sa_find_next();

    if (sa_ptr) {

        if ((t_now.tv_sec > sa_ptr->t_next.tv_sec) ||
            ((t_now.tv_sec == sa_ptr->t_next.tv_sec) &&
             (t_now.tv_usec > sa_ptr->t_next.tv_usec))) {
            /*
             * Time has already passed.  Return the smallest possible amount of
             * time.
             */
            delta->tv_sec = 0;
            delta->tv_usec = 1;
            return sa_ptr->clientreg;
        } else {
            /*
             * Time is still in the future.
             */
            t_diff.tv_sec = sa_ptr->t_next.tv_sec - t_now.tv_sec;
            t_diff.tv_usec = sa_ptr->t_next.tv_usec - t_now.tv_usec;

            while (t_diff.tv_usec < 0) {
                t_diff.tv_sec -= 1;
                t_diff.tv_usec += 1000000;
            }

            delta->tv_sec = t_diff.tv_sec;
            delta->tv_usec = t_diff.tv_usec;
            return sa_ptr->clientreg;
        }
    }

    /*
     * Nothing Left.
     */
    return 0;
}

/**  @} */
