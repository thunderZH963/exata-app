
#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#if HAVE_IO_H
#include <io.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "types_netsnmp.h"
#include "snmp_transport_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "snmpCallbackDomain_netsnmp.h"
#include "netSnmpAgent.h"
#include "tools_netsnmp.h"

#ifndef NETSNMP_STREAM_QUEUE_LEN
#define NETSNMP_STREAM_QUEUE_LEN  5
#endif

static int      callback_count = 0;

typedef struct callback_hack_s {
    void*           orig_transport_data;
    netsnmp_pdu*    pdu;
} callback_hack;

typedef struct callback_queue_s {
    int             callback_num;
    netsnmp_callback_pass* item;
    struct callback_queue_s* next, *prev;
} callback_queue;

callback_queue* thequeue;
static netsnmp_transport_list* trlist = NULL;

int
NetSnmpAgent::netsnmp_callback_hook_parse(netsnmp_session*  sp,
                            netsnmp_pdu* pdu,
                            u_char*  packetptr, size_t len)
{
    if (SNMP_MSG_RESPONSE == pdu->command ||
        SNMP_MSG_REPORT == pdu->command)
        pdu->flags |= UCD_MSG_FLAG_RESPONSE_PDU;
    else
        pdu->flags &= (~UCD_MSG_FLAG_RESPONSE_PDU);

    return SNMP_ERR_NOERROR;
}

int
NetSnmpAgent::netsnmp_callback_hook_build(netsnmp_session*  sp,
                            netsnmp_pdu* pdu, u_char*  ptk, size_t*  len)
{
    /*
     * very gross hack, as this is passed later to the transport_send
     * function
     */
    callback_hack*  ch = SNMP_MALLOC_TYPEDEF(callback_hack);
    if (ch == NULL)
        return -1;
    ch->pdu = pdu;
    ch->orig_transport_data = pdu->transport_data;
    pdu->transport_data = ch;
    switch (pdu->command) {
    case SNMP_MSG_GETBULK:
        if (pdu->max_repetitions < 0) {
            sp->s_snmp_errno = SNMPERR_BAD_REPETITIONS;
            return -1;
        }
        if (pdu->non_repeaters < 0) {
            sp->s_snmp_errno = SNMPERR_BAD_REPEATERS;
            return -1;
        }
        break;
    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_TRAP:
    case SNMP_MSG_TRAP2:
        pdu->flags &= (~UCD_MSG_FLAG_EXPECT_RESPONSE);
        /*
         * Fallthrough
         */
    default:
        if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
            pdu->errstat = 0;
        if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
            pdu->errindex = 0;
        break;
    }

    /*
     * Copy missing values from session defaults
     */
    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
        if (pdu->community_len == 0) {
            if (sp->community_len == 0) {
                sp->s_snmp_errno = SNMPERR_BAD_COMMUNITY;
                return -1;
            }
            pdu->community = (u_char*) malloc(sp->community_len);
            if (pdu->community == NULL) {
                sp->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->community,
                    sp->community, sp->community_len);
            pdu->community_len = sp->community_len;
        }
        break;
#endif
    case SNMP_VERSION_3:
        if (pdu->securityNameLen == 0) {
      pdu->securityName = (char*)malloc(sp->securityNameLen);
            if (pdu->securityName == NULL) {
                sp->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->securityName,
                     sp->securityName, sp->securityNameLen);
            pdu->securityNameLen = sp->securityNameLen;
        }
        if (pdu->securityModel == -1)
            pdu->securityModel = sp->securityModel;
        if (pdu->securityLevel == 0)
            pdu->securityLevel = sp->securityLevel;
        /* WHAT ELSE ?? */
    }
    *len = 1;
    return 1;
}

int
NetSnmpAgent::netsnmp_callback_check_packet(u_char*  pkt, size_t len)
{
    return 1;
}

netsnmp_pdu*
NetSnmpAgent::netsnmp_callback_create_pdu(netsnmp_transport* transport,
                            void* opaque, size_t olength)
{
    netsnmp_pdu*    pdu;
    netsnmp_callback_pass* cp =
        callback_pop_queue(((netsnmp_callback_info*) transport->data)->
                           callback_num);
    if (!cp)
        return NULL;
    pdu = cp->pdu;
    pdu->transport_data = opaque;
    pdu->transport_data_length = olength;
    if (opaque)                 /* if created, we're the server */
        *((int*) opaque) = cp->return_transport_num;
    SNMP_FREE(cp);
    return pdu;
}

netsnmp_callback_pass*
NetSnmpAgent::callback_pop_queue(int num)
{
    netsnmp_callback_pass* cp;
    callback_queue* ptr;

    for (ptr = thequeue; ptr; ptr = ptr->next) {
        if (ptr->callback_num == num) {
            if (ptr->prev) {
                ptr->prev->next = ptr->next;
            } else {
                thequeue = ptr->next;
            }
            if (ptr->next) {
                ptr->next->prev = ptr->prev;
            }
            cp = ptr->item;
            return cp;
        }
    }
    return NULL;
}

netsnmp_session*
NetSnmpAgent::netsnmp_callback_open(int attach_to,
                      int (NetSnmpAgent::*return_func) (int op,
                                          netsnmp_session*  session,
                                          int reqid, netsnmp_pdu* pdu,
                                          void* magic),
                      int (NetSnmpAgent::*fpre_parse) (netsnmp_session* ,
                                         struct netsnmp_transport_s* ,
                                         void* , int),
                      int (NetSnmpAgent::*fpost_parse) (netsnmp_session* , netsnmp_pdu* ,
                                          int))
{
    netsnmp_session callback_sess, *callback_ss;
    netsnmp_transport* callback_tr;

    callback_tr = netsnmp_callback_transport(attach_to);
    snmp_sess_init(&callback_sess);
    callback_sess.callback = return_func;
    if (attach_to) {
        /*
         * client
         */
        /*
         * trysess.community = (u_char*) callback_ss;
         */
    } else {
        callback_sess.isAuthoritative = SNMP_SESS_AUTHORITATIVE;
    }
    callback_sess.remote_port = 0;
    callback_sess.retries = 0;
    callback_sess.timeout = 30000000;
    callback_sess.version = SNMP_DEFAULT_VERSION;       /* (mostly) bogus */
    callback_ss = snmp_add_full(&callback_sess, callback_tr,
                                fpre_parse,
                                &NetSnmpAgent::netsnmp_callback_hook_parse,
                                fpost_parse,
                                &NetSnmpAgent::netsnmp_callback_hook_build,
                                NULL,
                                &NetSnmpAgent::netsnmp_callback_check_packet,
                                &NetSnmpAgent::netsnmp_callback_create_pdu);
    if (callback_ss)
        callback_ss->local_port =
            ((netsnmp_callback_info*) callback_tr->data)->callback_num;
    return callback_ss;
}


/* Open a Callback-domain transport for SNMP.  Local is TRUE if addr
 * is the local address to bind to (i.e. this is a server-type
 * session); otherwise addr is the remote address to send things to
 * (and we make up a temporary name for the local end of the
 * connection).
 */

netsnmp_transport*
NetSnmpAgent::netsnmp_callback_transport(int to)
{

    netsnmp_transport* t = NULL;
    netsnmp_callback_info* mydata;

    /*
     * transport
     */
    t = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    if (!t)
        return NULL;

    /*
     * our stuff
     */
    mydata = SNMP_MALLOC_TYPEDEF(netsnmp_callback_info);
    mydata->linkedto = to;
    mydata->callback_num = ++callback_count;
    mydata->data = NULL;
    t->data = mydata;

    t->sock = mydata->pipefds[0];

    netsnmp_transport_add_to_list(&trlist, t);

    return t;
}
/*
 * You can write something into opaque that will subsequently get passed back
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...
 */

int
NetSnmpAgent::netsnmp_callback_recv(netsnmp_transport* t, void* buf, int size,
              void** opaque, int* olength)
{
    int rc = 1;
    netsnmp_callback_info* mystuff = (netsnmp_callback_info*) t->data;

    if (mystuff && mystuff->linkedto) {
        /*
         * we're the client.  We don't need to do anything.
         */
    } else {
        /*
         * malloc the space here, but it's filled in by
         * snmp_callback_created_pdu() below
         */
        int*            returnnum = (int*) calloc(1, sizeof(int));
        *opaque = returnnum;
        *olength = sizeof(int);
    }
    return rc;
}



int
NetSnmpAgent::netsnmp_callback_send(netsnmp_transport* t, void* buf, int size,
              void** opaque, int* olength)
{
    return 0;
}



int
NetSnmpAgent::netsnmp_callback_close(netsnmp_transport* t)
{
    int rc = 0;
    return rc;
}



int
NetSnmpAgent::netsnmp_callback_accept(netsnmp_transport* t)
{
    return 0;
}


/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.
 */

char*
NetSnmpAgent::netsnmp_callback_fmtaddr(netsnmp_transport* t, void* data, int len)
{
    char buf[SPRINT_MAX_LEN];
    netsnmp_callback_info* mystuff;

    if (!t)
        return strdup("callback: unknown");

    mystuff = (netsnmp_callback_info*) t->data;

    if (!mystuff)
        return strdup("callback: unknown");

    snprintf(buf, SPRINT_MAX_LEN, "callback: %d on fd %d",
             mystuff->callback_num, mystuff->pipefds[0]);
    return strdup(buf);
}

/** adds a transport to a linked list of transports.
    Returns 1 on failure, 0 on success */
int
netsnmp_transport_add_to_list(netsnmp_transport_list** transport_list,
                              netsnmp_transport* transport)
{
    netsnmp_transport_list* newptr =
        (netsnmp_transport_list*)
                MEM_malloc(sizeof(netsnmp_transport_list));
    memset(newptr, 0, sizeof(netsnmp_transport_list));
    if (!newptr)
        return 1;

    newptr->next = *transport_list;
    newptr->transport = transport;

    *transport_list = newptr;

    return 0;
}

/**  removes a transport from a linked list of transports.
     Returns 1 on failure, 0 on success */
int
netsnmp_transport_remove_from_list(netsnmp_transport_list** transport_list,
                                   netsnmp_transport* transport)
{
    netsnmp_transport_list* ptr = *transport_list, *lastptr = NULL;

    while (ptr && ptr->transport != transport) {
        lastptr = ptr;
        ptr = ptr->next;
    }

    if (!ptr)
        return 1;

    if (lastptr)
        lastptr->next = ptr->next;
    else
        *transport_list = ptr->next;

    SNMP_FREE(ptr);

    return 0;
}

