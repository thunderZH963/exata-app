#ifndef SNMP_SYSTEM_H_NETSNMP
#define SNMP_SYSTEM_H_NETSNMP

#ifndef NET_SNMP_CONFIG_H_NETSNMP
#error "Please include <net-snmp-config_netsnmp.h> before this file"
#endif

#ifdef __cplusplus
extern          "C" {
#endif

/* Portions of this file are subject to the following copyrights.  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/***********************************************************
        Copyright 1993 by Carnegie Mellon University

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
 * portions Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */


    /*
     * function to create a daemon. Will fork and call setsid().
     *
     * Returns: -1 : fork failed
     *           0 : No errors
     */

#include <types_netsnmp.h>     /* For definition of in_addr_t */

    /* Simply resolve a hostname and return first IPv4 address.
     * Returns -1 on error */
    int             netsnmp_gethostbyname_v4(const char* name,
                                             in_addr_t* addr_out);

    /*
     * structure of a directory entry
     */
    typedef struct direct {
        long            d_ino;  /* inode number (not used by MS-DOS) */
        int             d_namlen;       /* Name length */
        char            d_name[257];    /* file name */
    } _DIRECT;


    typedef struct _dir_struc {
        char*           start;  /* Starting position */
        char*           curr;   /* Current position */
        long            size;   /* Size of string table */
        long            nfiles; /* number if filenames in table */
        struct direct   dirstr; /* Directory structure to return */
    } DIR_netsnmp;


u_int
calculate_sectime_diff(struct timeval* now, struct timeval* then);

#ifdef __cplusplus
}
#endif
#endif                          /* SNMP_SYSTEM_NETSNMP_H */
