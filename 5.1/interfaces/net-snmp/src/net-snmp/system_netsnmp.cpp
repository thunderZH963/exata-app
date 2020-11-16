/*
 * system.c
 */
/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/***********************************************************
        Copyright 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright (C) 2007 Apple, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
/*
 * System dependent routines go here
 */

#include "net-snmp-config_netsnmp.h"
#include <types_netsnmp.h>
#include "system_netsnmp.h"
#include <sys/timeb.h>
#include "string.h"

int
netsnmp_gethostbyname_v4(const char* name, in_addr_t* addr_out)
{

#if HAVE_GETADDRINFO
    struct addrinfo* addrs = NULL;
    struct addrinfo hint;
    int             err;

    memset(&hint, 0, sizeof hint);
    hint.ai_flags = 0;
    hint.ai_family = PF_INET;
    hint.ai_socktype = SOCK_DGRAM;
    hint.ai_protocol = 0;

    err = getaddrinfo(name, NULL, &hint, &addrs);
    if (err != 0) {
#if HAVE_GAI_STRERROR
        snmp_log(LOG_ERR, "getaddrinfo: %s %s\n", name,
                 gai_strerror(err));
#else
        snmp_log(LOG_ERR, "getaddrinfo: %s (error %d)\n", name,
                 err);
#endif
        return -1;
    }
    if (addrs != NULL) {
        memcpy(addr_out,
               &((struct sockaddr_in*) addrs->ai_addr)->sin_addr,
               sizeof(in_addr_t));
        freeaddrinfo(addrs);
    } else {
        DEBUGMSGTL(("get_thisaddr",
                    "Failed to resolve IPv4 hostname\n"));
    }
    return 0;

#elif HAVE_GETHOSTBYNAME
    struct hostent* hp = NULL;

    hp = gethostbyname(name);
    if (hp == NULL) {
        DEBUGMSGTL(("get_thisaddr",
                    "hostname (couldn't resolve)\n"));
        return -1;
    } else if (hp->h_addrtype != AF_INET) {
        DEBUGMSGTL(("get_thisaddr",
                    "hostname (not AF_INET!)\n"));
        return -1;
    } else {
        DEBUGMSGTL(("get_thisaddr",
                    "hostname (resolved okay)\n"));
        memcpy(addr_out, hp->h_addr, sizeof(in_addr_t));
    }
    return 0;

#elif HAVE_GETIPNODEBYNAME
    struct hostent* hp = NULL;
    int             err;

    hp = getipnodebyname(peername, AF_INET, 0, &err);
    if (hp == NULL) {
        DEBUGMSGTL(("get_thisaddr",
                    "hostname (couldn't resolve = %d)\n", err));
        return -1;
    }
    DEBUGMSGTL(("get_thisaddr",
                "hostname (resolved okay)\n"));
    memcpy(addr_out, hp->h_addr, sizeof(in_addr_t));
    return 0;

#else /* HAVE_GETIPNODEBYNAME */
    return -1;
#endif
}

u_int
calculate_sectime_diff(struct timeval* now, struct timeval* then)
{
    struct timeval  tmp, diff;
    memcpy(&tmp, now, sizeof(struct timeval));
    tmp.tv_sec--;
    tmp.tv_usec += 1000000L;
    diff.tv_sec = tmp.tv_sec - then->tv_sec;
    diff.tv_usec = tmp.tv_usec - then->tv_usec;
    if (diff.tv_usec > 1000000L) {
        diff.tv_usec -= 1000000L;
        diff.tv_sec++;
    }
    if (diff.tv_usec >= 500000L)
        return diff.tv_sec + 1;
    return  diff.tv_sec;
}

                          /* !HAVE_GETTIMEOFDAY */

/*******************************************************************/
