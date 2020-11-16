/*
 * snmp_auth.c
 *
 * Community name parse/build routines.
 */
/**********************************************************************
    Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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

#include "net-snmp-config_netsnmp.h"

#ifdef KINETICS
#include "gw.h"
#include "fp4/cmdmacro.h"
#endif

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#ifdef vms
#include <in.h>
#endif

#include "types_netsnmp.h"

#include "asn1_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "mib_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "tools_netsnmp.h"
/*
 * Globals.
 */

/*******************************************************************-o-******
 * snmp_comstr_parse
 *
 * Parameters:
 *    *data        (I)   Message.
 *    *length        (I/O) Bytes left in message.
 *    *psid        (O)   Community string.
 *    *slen        (O)   Length of community string.
 *    *version    (O)   Message version.
 *
 * Returns:
 *    Pointer to the remainder of data.
 *
 *
 * Parse the header of a community string-based message such as that found
 * in SNMPv1 and SNMPv2c.
 */
u_char*
snmp_comstr_parse(u_char*  data,
                  size_t*  length,
                  u_char*  psid, size_t*  slen, long* version)
{
    u_char          type;
    long            ver;
    size_t          origlen = *slen;

    /*
     * Message is an ASN.1 SEQUENCE.
     */
    data = asn_parse_sequence(data, length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "auth message");
    if (data == NULL) {
        return NULL;
    }

    /*
     * First field is the version.
     */
    data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
    *version = ver;
    if (data == NULL) {
        return NULL;
    }

    /*
     * second field is the community string for SNMPv1 & SNMPv2c
     */
    data = asn_parse_string(data, length, &type, psid, slen);
    if (data == NULL) {
        return NULL;
    }
    psid[SNMP_MIN(*slen, origlen - 1)] = '\0';
    return (u_char*) data;

}                               /* end snmp_comstr_parse() */
