#include <net-snmp-config_netsnmp.h>

#include <stdio.h>
#include <string.h>
#include "types_netsnmp.h"

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <malloc.h>

#include "snmp_api_netsnmp.h"
#include "snmp_transport_netsnmp.h"
#include "tools_netsnmp.h"


/*
 * The standard SNMP domains.
 */

oid             netsnmpUDPDomain[] = { 1, 3, 6, 1, 6, 1, 1 };
size_t          netsnmpUDPDomain_len = OID_LENGTH(netsnmpUDPDomain);
oid             netsnmpCLNSDomain[] = { 1, 3, 6, 1, 6, 1, 2 };
size_t          netsnmpCLNSDomain_len = OID_LENGTH(netsnmpCLNSDomain);
oid             netsnmpCONSDomain[] = { 1, 3, 6, 1, 6, 1, 3 };
size_t          netsnmpCONSDomain_len = OID_LENGTH(netsnmpCONSDomain);
oid             netsnmpDDPDomain[] = { 1, 3, 6, 1, 6, 1, 4 };
size_t          netsnmpDDPDomain_len = OID_LENGTH(netsnmpDDPDomain);
oid             netsnmpIPXDomain[] = { 1, 3, 6, 1, 6, 1, 5 };
size_t          netsnmpIPXDomain_len = OID_LENGTH(netsnmpIPXDomain);

/*
 * Make a deep copy of an netsnmp_transport.
 */

netsnmp_transport*
netsnmp_transport_copy(netsnmp_transport* t)
{
    netsnmp_transport* n = NULL;

    n = (netsnmp_transport*) malloc(sizeof(netsnmp_transport));
    if (n == NULL) {
        return NULL;
    }
    memset(n, 0, sizeof(netsnmp_transport));

    if (t->domain != NULL) {
        n->domain = t->domain;
        n->domain_length = t->domain_length;
    } else {
        n->domain = NULL;
        n->domain_length = 0;
    }

    if (t->local != NULL) {
        n->local = (u_char*) malloc(t->local_length);
        if (n->local == NULL) {
            netsnmp_transport_free(n);
            return NULL;
        }
        n->local_length = t->local_length;
        memcpy(n->local, t->local, t->local_length);
    } else {
        n->local = NULL;
        n->local_length = 0;
    }

    if (t->remote != NULL) {
        n->remote = (u_char*) malloc(t->remote_length);
        if (n->remote == NULL) {
            netsnmp_transport_free(n);
            return NULL;
        }
        n->remote_length = t->remote_length;
        memcpy(n->remote, t->remote, t->remote_length);
    } else {
        n->remote = NULL;
        n->remote_length = 0;
    }

    if (t->data != NULL && t->data_length > 0) {
        n->data = malloc(t->data_length);
        if (n->data == NULL) {
            netsnmp_transport_free(n);
            return NULL;
        }
        n->data_length = t->data_length;
        memcpy(n->data, t->data, t->data_length);
    } else {
        n->data = NULL;
        n->data_length = 0;
    }

    n->msgMaxSize = t->msgMaxSize;
    n->f_accept = t->f_accept;
    n->f_recv = t->f_recv;
    n->f_send = t->f_send;
    n->f_close = t->f_close;
    n->f_fmtaddr = t->f_fmtaddr;
    n->sock = t->sock;
    n->flags = t->flags;

    return n;
}

void
netsnmp_transport_free(netsnmp_transport* t)
{
    if (NULL == t)
        return;

    if (t->local != NULL) {
        SNMP_FREE(t->local);
    }
    if (t->remote != NULL) {
        SNMP_FREE(t->remote);
    }
    if (t->data != NULL) {
        SNMP_FREE(t->data);
    }
    SNMP_FREE(t);
}
