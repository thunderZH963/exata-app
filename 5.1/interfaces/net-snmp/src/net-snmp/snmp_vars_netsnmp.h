/*
 * Definitions for SNMP (RFC 1067) agent variable finder.
 *
 */

#ifndef SNMP_VARS_H_NETSNMP
#define SNMP_VARS_H_NETSNMP

/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/***********************************************************
    Copyright 1988, 1989 by Carnegie Mellon University
    Copyright 1989    TGV, Incorporated

              All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */
#include "types_netsnmp.h"
#include "node.h"
struct variable;

    /*
     * fail overloads non-negative integer value. it must be -1 !
     */
#define MATCH_FAILED    (-1)
#define MATCH_SUCCEEDED    0

    /*
     * Function pointer called by the master agent for writes.
     */
    typedef int     (WriteMethod) (int action,
                                   unsigned char*  var_val,
                                   unsigned char var_val_type,
                                   size_t var_val_len,
                                   unsigned char*  statP,
                                   oid*  name, size_t length,Node* node);

    /*
     * Function pointer called by the master agent for mib information retrieval
     */
    typedef u_char* (FindVarMethod) (struct variable*  vp,
                                     oid*  name,
                                     size_t*  length,
                                     int exact,
                                     u_char*  var_buf,
                                     size_t*  var_len,
                                     WriteMethod**  write_method,
                                     Node* node);

struct variable {
        unsigned char          magic;  /* passed to function as a hint */
        char            type;   /* type of variable */
        /*
         * See important comment in snmp_vars.c relating to acl
         */
        unsigned short         acl;    /* access control list for variable */
        FindVarMethod*  findVar;        /* function that finds variable */
        unsigned char          namelen;        /* length of above */
        unsigned int            name[MAX_OID_LEN];      /* object identifier of variable */
    };

struct variable1 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[1];    /* object identifier of variable */
};

struct variable2 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[2];    /* object identifier of variable */
};

struct variable3 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[3];    /* object identifier of variable */
};

struct variable4 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[4];    /* object identifier of variable */
};

struct variable7 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[7];    /* object identifier of variable */
};

struct variable8 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[8];    /* object identifier of variable */
};

struct variable13 {
    u_char          magic;      /* passed to function as a hint */
    u_char          type;       /* type of variable */
    u_short         acl;        /* access control list for variable */
    FindVarMethod*  findVar;    /* function that finds variable */
    u_char          namelen;    /* length of name below */
    oid             name[13];   /* object identifier of variable */
};


#endif /* SNMP_VARS_H_NETSNMP */


