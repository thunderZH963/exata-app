/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/******************************************************************
    Copyright 1989, 1991, 1992 by Carnegie Mellon University

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
 * Copyright Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/** @defgroup library The Net-SNMP library
 *  @{
 */
/*
 * snmp_api.c - API for access to snmp.
 */

/*
 * snmp_duplicate_objid: duplicates (mallocs) an objid based on the
 * input objid
 */

#include <string.h>
#include "netSnmpAgent.h"
#include "node.h"
#include "snmp_api_netsnmp.h"
#include "types_netsnmp.h"
#include "netSnmpAgent.h"
#include "snmp_transport_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "tools_netsnmp.h"
#include "mt_support_netsnmp.h"
#include "default_store_netsnmp.h"
#include "snmp_agent_netsnmp.h"
#include "pdu_api_netsnmp.h"
#include "vacm_netsnmp.h"
#include "snmp_secmod_netsnmp.h"
#include "tools_netsnmp.h"
#include "callback_netsnmp.h"
#include "lcd_time_netsnmp.h"
#include "containers_netsnmp.h"
#include "snmp_netsnmp.h"
#include "varbind_api_netsnmp.h"
#include "snmpusm_netsnmp.h"
#include "keytools_netsnmp.h"
#include "snmp_tc_netsnmp.h"

#include "large_fd_set_netsnmp.h"
#include "transform_oids_netsnmp.h"
#include "system_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "default_store_netsnmp.h"
#include "snmpv3_netsnmp.h"
#include "asn1_netsnmp.h"
#include "app_netsnmp.h"
#include <app_util.h>
#include <application.h>
#include <trace.h>
#include <errno.h>

#ifndef WIN32
#include <sys/time.h>
#endif


#include <agent_trap_netsnmp.h>
#include "instance_netsnmp.h"

#ifdef JNE_LIB
#include "hmsNotification.h"
#include "jne.h"
#endif

/*
 * don't set higher than 0x7fffffff, and I doubt it should be that high
 * * = 4 gig snmp messages max
 */
#define MAXIMUM_PACKET_SIZE 0x7fffffff

static char     snmp_detail[192];
static int      snmp_detail_f = 0;
int             snmp_errno = 0;
/*
 * Globals.
 */
#define MAX_PACKET_LENGTH    (0x7fffffff)
#ifndef NETSNMP_STREAM_QUEUE_LEN
#define NETSNMP_STREAM_QUEUE_LEN  5
#endif

static oid      default_enterprise[] = { 1, 3, 6, 1, 4, 1, 3, 1, 1 };

#ifndef DONT_SHARE_ERROR_WITH_OTHER_THREADS
#define SET_SNMP_ERROR(x) snmp_errno=(x)
#else
#define SET_SNMP_ERROR(x)
#endif

/*
 * enterprises.cmu.systems.cmuSNMP
 */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_RETRIES        5
#define DEFAULT_TIMEOUT        1000000L
#define DEFAULT_REMPORT        SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME        0

netsnmp_pdu* snmp_create_sess_pdu(netsnmp_transport* transport,
                                  void* opaque, size_t olength);

static int snmpv3_verify_msg(netsnmp_request_list* rp, netsnmp_pdu* pdu);

static int snmp_parse_version(u_char* , size_t);

static void     snmpv3_calc_msg_flags(int, int, u_char*);


unsigned int*
snmp_duplicate_objid(const unsigned int*   objToCopy, size_t objToCopyLen)
{
    unsigned int*             returnOid;
    if (objToCopy != NULL && objToCopyLen != 0) {
        returnOid = (unsigned int*) malloc(objToCopyLen * sizeof(unsigned int));
        if (returnOid) {
            memcpy(returnOid, objToCopy, objToCopyLen * sizeof(unsigned int));
        }
    } else
        returnOid = NULL;
    return returnOid;
}

int
NetSnmpAgent::snmp_select_info(int* block)
    /*
     * input:  set to 1 if input timeout value is undefined
     * set to 0 if input timeout value is defined
     * output: set to 1 if output timeout value is undefined
     * set to 0 if output rimeout vlaue id defined
     */
{
    return snmp_sess_select_info((void*) 0, block);
}

void
NetSnmpAgent::snmp_read(void)
{
#ifdef SNMP_DEBUG
    printf("snmp_read:Reading Incoming packet for node %d\n",node->nodeId);
#endif
    snmp_read2();
}

void
NetSnmpAgent::snmp_read2(void)
{
    struct snmp_session_list* slp;
    slp = Sessions;
    snmp_sess_read2((void*) slp);
}

/*
 * returns 0 if success, -1 if fail
 */
int
NetSnmpAgent::snmp_sess_read(void* sessp)
{
  int rc;
  rc = snmp_sess_read2(sessp);
  return rc;
}

int
NetSnmpAgent::snmp_sess_read2(void* sessp)
{
    struct snmp_session_list* psl;
    netsnmp_session* pss;
    int             rc;

    rc = _sess_read(sessp);
    psl = (struct snmp_session_list*) sessp;
    pss = psl->session;
    return rc;
}

/*
 * Same as snmp_read, but works just one session.
 * returns 0 if success, -1 if fail
 * MTR: can't lock here and at snmp_read
 * Beware recursive send maybe inside snmp_read callback function.
 */
int
NetSnmpAgent::_sess_read(void* sessp)
{
    struct snmp_session_list* slp = (struct snmp_session_list*) sessp;
    netsnmp_session* sp = slp ? slp->session : NULL;
    struct snmp_internal_session* isp = slp ? slp->internal : NULL;
    netsnmp_transport* transport = slp ? slp->transport : NULL;
    size_t          pdulen = 0, rxbuf_len = 65536;
    u_char*         rxbuf /*= snmpMsgData*/;
    int             olength = 0, rc = 0;
    void*           opaque = NULL;

    sp->s_snmp_errno = 0;
    sp->s_errno = 0;
    transport->flags = 1;

    /*
     * We've successfully accepted a new stream-based connection.
     * It's not too clear what should happen here if we are using the
     * single-session API at this point.  Basically a "session
     * accepted" callback is probably needed to hand the new session
     * over to the application.
     *
     * However, for now, as in the original snmp_api, we will ASSUME
     * that we're using the traditional API, and simply add the new
     * session to the list.  Note we don't have to get the Session
     * list lock here, because under that assumption we already hold
     * it (this is also why we don't just use snmp_add).
     *
     * The moral of the story is: don't use listening stream-based
     * transports in a multi-threaded environment because something
     * will go HORRIBLY wrong (and also that SNMP/TCP is not trivial).
     *
     * Another open issue: what should happen to sockets that have
     * been accept()ed from a listening socket when that original
     * socket is closed?  If they are left open, then attempting to
     * re-open the listening socket will fail, which is semantically
     * confusing.  Perhaps there should be some kind of chaining in
     * the transport structure so that they can all be closed.
     * Discuss.  ;-)
     */

    netsnmp_transport* new_transport = netsnmp_transport_copy(transport);
    if (new_transport != NULL)
    {
        new_transport->flags &= ~NETSNMP_TRANSPORT_FLAG_LISTEN;
        struct snmp_session_list* nslp = NULL;
        nslp = (struct snmp_session_list*)snmp_sess_add_ex(sp,
            new_transport, isp->hook_pre, isp->hook_parse,
        isp->hook_post, isp->hook_build,
        isp->hook_realloc_build, isp->check_packet,
        isp->hook_create_pdu);

        if (nslp != NULL) {
            nslp->next = Sessions;
            Sessions = nslp;
            /*
             * Tell the new session about its existance if possible.
             */
            (void)(this->*(nslp->session->callback))(NETSNMP_CALLBACK_OP_CONNECT,
                                          nslp->session, 0, NULL,
                                          sp->callback_magic);
        }
    }
    /*
     * Work out where to receive the data to.
     */

    if (isp->packet == NULL) {
        /*
         * We have no saved packet.  Allocate one.
         */
        if ((isp->packet = (u_char*) malloc(rxbuf_len)) == NULL) {
            return 0;
        } else {
            rxbuf = isp->packet;
            isp->packet_size = rxbuf_len;
            isp->packet_len = 0;
        }
    } else {
        /*
         * We have saved a partial packet from last time.  Extend that, if
         * necessary, and receive new data after the old data.
         */
        u_char*         newbuf;

        if (isp->packet_size < isp->packet_len + rxbuf_len) {
            newbuf =
                (u_char*) realloc(isp->packet,
                                   isp->packet_len + rxbuf_len);
            if (newbuf == NULL) {
                return 0;
            } else {
                isp->packet = newbuf;
                isp->packet_size = isp->packet_len + rxbuf_len;
                rxbuf = isp->packet + isp->packet_len;
            }
        } else {
            rxbuf = isp->packet + isp->packet_len;
            rxbuf_len = isp->packet_size - isp->packet_len;
        }
    }
    int length = currPacketSize;
    memcpy(rxbuf, currPacket, currPacketSize);
    transport->flags = 1;
    if (length == -1 && !(transport->flags & NETSNMP_TRANSPORT_FLAG_STREAM)) {
        sp->s_snmp_errno = SNMPERR_BAD_RECVFROM;
        sp->s_errno = errno;
        snmp_set_detail(strerror(errno));
        SNMP_FREE(rxbuf);
        if (opaque != NULL) {
            SNMP_FREE(opaque);
        }
        return -1;
    }

    if (0 == length && transport->flags & NETSNMP_TRANSPORT_FLAG_EMPTY_PKT) {
        /* this allows for a transport that needs to return from
         * packet processing that doesn't necessarily have any
         * consumable data in it. */

        /* reset the flag since it's a per-message flag */
        transport->flags &= (~NETSNMP_TRANSPORT_FLAG_EMPTY_PKT);

        return 0;
    }

    /*
     * Remote end closed connection.
     */

    if (length <= 0 && transport->flags & NETSNMP_TRANSPORT_FLAG_STREAM) {
        /*
         * Alert the application if possible.
         */
        if (sp->callback != NULL) {
            (void)(this->* sp->callback)(NETSNMP_CALLBACK_OP_DISCONNECT, sp, 0,
                                NULL, sp->callback_magic);
        }
        /*
         * Close socket and mark session for deletion.
         */
        (this->*(transport->f_close))(transport);
        SNMP_FREE(isp->packet);
        if (opaque != NULL) {
            SNMP_FREE(opaque);
        }
        return -1;
    }

    if (transport->flags & NETSNMP_TRANSPORT_FLAG_STREAM) {
        u_char* pptr = isp->packet;
        void* ocopy = NULL;

        isp->packet_len += length;

        while (isp->packet_len > 0) {
            /*
             * Get the total data length we're expecting (and need to wait
             * for).
             */
            pdulen = asn_check_packet(pptr, isp->packet_len);
            if ((pdulen > MAX_PACKET_LENGTH) || (pdulen < 0)) {
                /*
                 * Illegal length, drop the connection.
                 */
                if (sp->callback != NULL) {
                  (void)(this->*(sp->callback))(NETSNMP_CALLBACK_OP_DISCONNECT,
                             sp, 0, NULL, sp->callback_magic);
                }
                (this->*(transport->f_close))(transport);
                if (opaque != NULL) {
                    SNMP_FREE(opaque);
                }
                /** XXX-rks: why no SNMP_FREE(isp->packet); ?? */
                return -1;
            }

            if (pdulen > isp->packet_len || pdulen == 0) {
                /*
                 * We don't have a complete packet yet.  If we've already
                 * processed a packet, break out so we'll shift this packet
                 * to the start of the buffer. If we're already at the
                 * start, simply return and wait for more data to arrive.
                 */
                if (pptr != isp->packet)
                    break; /* opaque freed for us outside of loop. */

                if (opaque != NULL) {
                    SNMP_FREE(opaque);
                }
                return 0;
            }

            /*  We have *at least* one complete packet in the buffer now.  If
            we have possibly more than one packet, we must copy the opaque
            pointer because we may need to reuse it for a later packet.  */

            if (pdulen < isp->packet_len) {
                if (olength > 0 && opaque != NULL) {
                    ocopy = malloc(olength);
                    if (ocopy != NULL) {
                        memcpy(ocopy, opaque, olength);
                    }
                }
            } else if (pdulen == isp->packet_len) {
                /*  Common case -- exactly one packet.  No need to copy the
                    opaque pointer.  */
                ocopy = opaque;
                opaque = NULL;
            }

            if ((rc = _sess_process_packet(sessp, sp, isp, transport,
                                           ocopy, ocopy?olength:0, pptr,
                                           pdulen))) {
                /*
                 * Something went wrong while processing this packet -- set the
                 * errno.
                 */
                if (sp->s_snmp_errno != 0) {
                    SET_SNMP_ERROR(sp->s_snmp_errno);
                }
            }

            /*  ocopy has been free()d by _sess_process_packet by this point,
            so set it to NULL.  */

            ocopy = NULL;

            /*  Step past the packet we've just dealt with.  */

                pptr += pdulen;
                isp->packet_len -= pdulen;
        }

        /* If we had more than one packet, then we were working with copies
        of the opaque pointer, so we still need to free() the opaque
        pointer itself. */

        if (opaque != NULL) {
            SNMP_FREE(opaque);
        }

        if (isp->packet_len >= MAXIMUM_PACKET_SIZE) {
            /*
             * Obviously this should never happen!
             */
            (this->*(transport->f_close))(transport);
            /** XXX-rks: why no SNMP_FREE(isp->packet); ?? */
            return -1;
        } else if (isp->packet_len == 0) {
            /*
             * This is good: it means the packet buffer contained an integral
             * number of PDUs, so we don't have to save any data for next
             * time.  We can free() the buffer now to keep the memory
             * footprint down.
             */
            SNMP_FREE(isp->packet);
            isp->packet = NULL;
            isp->packet_size = 0;
            isp->packet_len = 0;
            return rc;
        }

        /*
         * If we get here, then there is a partial packet of length
         * isp->packet_len bytes starting at pptr left over.  Move that to the
         * start of the buffer, and then realloc() the buffer down to size to
         * reduce the memory footprint.
         */

        memmove(isp->packet, pptr, isp->packet_len);

        if ((rxbuf = (u_char*)realloc(isp->packet, isp->packet_len)) == NULL) {
            /*
             * I don't see why this should ever fail, but it's not a big deal.
             */
        } else {
            isp->packet = rxbuf;
            isp->packet_size = isp->packet_len;
        }
        return rc;
    } else {
        rc = _sess_process_packet(sessp, sp, isp, transport, opaque,
                                  olength, rxbuf, length);
        SNMP_FREE(rxbuf);
        return rc;
    }
}

/*
 * generic statistics counter functions
 */
u_int
NetSnmpAgent::snmp_increment_statistic(int which)
{
    if (which >= 0 && which < MAX_STATS) {
        statistics[which]++;
        return this->statistics[which];
    }
    return 0;
}


u_int
NetSnmpAgent::snmp_increment_statistic_by(int which, int count)
{
    if (which >= 0 && which < MAX_STATS) {
        statistics[which] += count;
        return this->statistics[which];
    }
    return 0;
}


netsnmp_agent_session*
NetSnmpAgent::init_agent_snmp_session(netsnmp_session*  session, netsnmp_pdu* pdu)
{
    netsnmp_agent_session* asp = (netsnmp_agent_session*)
        calloc(1, sizeof(netsnmp_agent_session));

    if (asp == NULL) {
        return NULL;
    }

    asp->session = session;
    asp->pdu = snmp_clone_pdu(pdu);
    asp->orig_pdu = snmp_clone_pdu(pdu);
    asp->rw = READ;
    asp->exact = TRUE;
    asp->next = NULL;
    asp->mode = RESERVE1;
    asp->status = SNMP_ERR_NOERROR;
    asp->index = 0;
    asp->oldmode = 0;
    asp->treecache_num = -1;
    asp->treecache_len = 0;
    asp->reqinfo = SNMP_MALLOC_TYPEDEF(netsnmp_agent_request_info);

    return asp;
}

/*
 * Frees the variable and any malloc'd data associated with it.
 */
void
snmp_free_var_internals(netsnmp_variable_list*  var)
{
    if (!var)
        return;

    if (var->name != var->name_loc)
        SNMP_FREE(var->name);
    if (var->val.string != var->buf)
        SNMP_FREE(var->val.string);
    if (var->data) {
        if (var->dataFreeHook) {
            var->dataFreeHook(var->data);
            var->data = NULL;
        } else {
            SNMP_FREE(var->data);
        }
    }
}

void
snmp_free_var(netsnmp_variable_list*  var)
{
    snmp_free_var_internals(var);
    free((char*) var);
}

void
snmp_free_varbind(netsnmp_variable_list*  var)
{
    netsnmp_variable_list* ptr;
    while (var) {
        ptr = var->next_variable;
        snmp_free_var(var);
        var = ptr;
    }
}

/** handles an incoming SNMP packet into the agent */
int
NetSnmpAgent::handle_snmp_packet(int op, netsnmp_session*  session,
                   int reqid, netsnmp_pdu* pdu, void* magic)
{
#ifdef SNMP_DEBUG
    printf("handle_snmp_packet:node %d\n",node->nodeId);
#endif
    netsnmp_agent_session* asp;
    int             status, access_ret, rc;

    /*
     * We only support receiving here.
     */
    if (op != NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        return 1;
    }

    /*
     * RESPONSE messages won't get this far, but TRAP-like messages
     * might.
     */
    if (pdu->command == SNMP_MSG_TRAP || pdu->command == SNMP_MSG_INFORM ||
        pdu->command == SNMP_MSG_TRAP2) {
        pdu->command = SNMP_MSG_TRAP2;
        snmp_increment_statistic(STAT_SNMPUNKNOWNPDUHANDLERS);
        return 1;
    }

    /*
     * send snmpv3 authfail trap.
     */
    if (pdu->version  == SNMP_VERSION_3 &&
        session->s_snmp_errno == SNMPERR_USM_AUTHENTICATIONFAILURE) {
           return 1;
    }

    if (magic == NULL) {
        asp = init_agent_snmp_session(session, pdu);
        status = SNMP_ERR_NOERROR;
    } else {
        asp = (netsnmp_agent_session*) magic;
        status = asp->status;
    }

    if ((access_ret = check_access(asp->pdu)) != 0) {
        if (access_ret == VACM_NOSUCHCONTEXT) {
            /*
             * rfc3413 section 3.2, step 5 says that we increment the
             * counter but don't return a response of any kind
             */

            /*
             * we currently don't support unavailable contexts, as
             * there is no reason to that I currently know of
             */
            snmp_increment_statistic(STAT_SNMPUNKNOWNCONTEXTS);

            /*
             * drop the request
             */
            netsnmp_remove_and_free_agent_snmp_session(asp);
            return 0;
        } else {
            /*
             * access control setup is incorrect
             */
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
#if defined(NETSNMP_DISABLE_SNMPV1)
            if (asp->pdu->version != SNMP_VERSION_2c) {
#else
#if defined(NETSNMP_DISABLE_SNMPV2C)
            if (asp->pdu->version != SNMP_VERSION_1) {
#else
            if (asp->pdu->version != SNMP_VERSION_1
                && asp->pdu->version != SNMP_VERSION_2c) {
#endif
#endif
                asp->pdu->errstat = SNMP_ERR_AUTHORIZATIONERROR;
                asp->pdu->command = SNMP_MSG_RESPONSE;
                snmp_increment_statistic(STAT_SNMPOUTPKTS);
                if (!snmp_send(asp->session, asp->pdu))
                    snmp_free_pdu(asp->pdu);
                asp->pdu = NULL;
                netsnmp_remove_and_free_agent_snmp_session(asp);
                return 1;
            } else {
#endif /* support for community based SNMP */
                /*
                 * drop the request
                 */
                netsnmp_remove_and_free_agent_snmp_session(asp);
                return 0;
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
            }
#endif /* support for community based SNMP */
        }
    }

    rc = netsnmp_handle_request(asp, status);

    /*
     * done
     */
    return rc;
}


/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
NetSnmpAgent::snmp_free_pdu(netsnmp_pdu* pdu)
{
    struct snmp_secmod_def* sptr;

    if (!pdu)
        return;

    /*
     * If the command field is empty, that probably indicates
     *   that this PDU structure has already been freed.
     *   Log a warning and return (rather than freeing things again)
     *
     * Note that this does not pick up dual-frees where the
     *   memory is set to random junk, which is probably more serious.
     *
     * rks: while this is a good idea, there are two problems.
     *         1) agentx sets command to 0 in some cases
     *         2) according to Wes, a bad decode of a v3 message could
     *            result in a 0 at this offset.
     *      so I'm commenting it out until a better solution is found.
     *      note that I'm leaving the memset, below....
     *
     */
    if ((sptr = find_sec_mod(pdu->securityModel)) != NULL &&
        sptr->pdu_free != NULL) {
        (*sptr->pdu_free) (pdu);
    }
    snmp_free_varbind(pdu->variables);
    SNMP_FREE(pdu->enterprise);
    SNMP_FREE(pdu->community);
    SNMP_FREE(pdu->contextEngineID);
    SNMP_FREE(pdu->securityEngineID);
    SNMP_FREE(pdu->contextName);
    SNMP_FREE(pdu->securityName);
    SNMP_FREE(pdu->transport_data);
    memset(pdu, 0, sizeof(netsnmp_pdu));
    free((char*) pdu);
}

/** Compares 2 OIDs to determine if they are exactly equal.
 *  This should be faster than doing a snmp_oid_compare for different
 *  length OIDs, since the length is checked first and if != returns
 *  immediately.  Might be very slighly faster if lengths are ==.
 * @param in_name1 A pointer to the first oid.
 * @param len1     length of the first OID (in segments, not bytes)
 * @param in_name2 A pointer to the second oid.
 * @param len2     length of the second OID (in segments, not bytes)
 * @return 0 if they are equal, 1 if they are not.
 */
int
netsnmp_oid_equals(const unsigned int*  in_name1,
                   size_t len1, const unsigned int*  in_name2, size_t len2)
{
    register const unsigned int* name1 = in_name1;
    register const unsigned int* name2 = in_name2;
    register int    len = len1;

    /*
     * len = minimum of len1 and len2
     */
    if (len1 != len2)
        return 1;
    /*
     * find first non-matching OID
     */
    while (len-- > 0) {
        /*
         * these must be done in seperate comparisons, since
         * subtracting them and using that result has problems with
         * subids > 2^31.
         */
        if (*(name1++) != *(name2++))
            return 1;
    }
    return 0;
}






/** lexicographical compare two object identifiers.
 *
 * Caution: this method is called often by
 *          command responder applications (ie, agent).
 *
 * @return -1 if name1 < name2, 0 if name1 = name2, 1 if name1 > name2
 */
int
snmp_oid_compare(const oid*  in_name1,
                 size_t len1, const oid*  in_name2, size_t len2)
{
    register int    len;
    register const oid* name1 = in_name1;
    register const oid* name2 = in_name2;

    /*
     * len = minimum of len1 and len2
     */
    if (len1 < len2)
        len = len1;
    else
        len = len2;
    /*
     * find first non-matching OID
     */
    while (len-- > 0) {
        /*
         * these must be done in seperate comparisons, since
         * subtracting them and using that result has problems with
         * subids > 2^31.
         */
        if (*(name1) != *(name2)) {
            if (*(name1) < *(name2))
                return -1;
            return 1;
        }
        name1++;
        name2++;
    }
    /*
     * both OIDs equal up to length of shorter OID
     */
    if (len1 < len2)
        return -1;
    if (len2 < len1)
        return 1;
    return 0;
}

long
NetSnmpAgent::snmp_get_next_reqid(void)
{
    long            retVal;
   snmp_res_lock(MT_LIBRARY_ID, MT_LIB_REQUESTID);
    retVal = 1 + Reqid;         /*MTCRITICAL_RESOURCE */
    if (!retVal)
        retVal = 2;
    Reqid = retVal;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_16BIT_IDS))
        retVal &= 0x7fff;    /* mask to 15 bits */
    else
        retVal &= 0x7fffffff;    /* mask to 31 bits */

    if (!retVal) {
        Reqid = retVal = 2;
    }
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_REQUESTID);
    return retVal;
}

long
NetSnmpAgent::snmp_get_next_msgid(void)
{
    long            retVal;
    snmp_res_lock(MT_LIBRARY_ID, MT_LIB_MESSAGEID);
    retVal = 1 + Msgid;         /*MTCRITICAL_RESOURCE */
    if (!retVal)
        retVal = 2;
    Msgid = retVal;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_16BIT_IDS))
        retVal &= 0x7fff;    /* mask to 15 bits */
    else
        retVal &= 0x7fffffff;    /* mask to 31 bits */

    if (!retVal) {
        Msgid = retVal = 2;
    }
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_MESSAGEID);
    return retVal;
}

/** lexicographical compare two object identifiers and return the point where they differ
 *
 * Caution: this method is called often by
 *          command responder applications (ie, agent).
 *
 * @return -1 if name1 < name2, 0 if name1 = name2, 1 if name1 > name2 and offpt = len where name1 != name2
 */
int
netsnmp_oid_compare_ll(const unsigned int*  in_name1,
                       size_t len1, const unsigned int*  in_name2, size_t len2,
                       size_t* offpt)
{
    register int    len;
    register const unsigned int* name1 = in_name1;
    register const unsigned int* name2 = in_name2;
    int initlen;

    /*
     * len = minimum of len1 and len2
     */
    if (len1 < len2)
        initlen = len = len1;
    else
        initlen = len = len2;
    /*
     * find first non-matching OID
     */
    while (len-- > 0) {
        /*
         * these must be done in seperate comparisons, since
         * subtracting them and using that result has problems with
         * subids > 2^31.
         */
        if (*(name1) != *(name2)) {
            *offpt = initlen - len;
            if (*(name1) < *(name2))
                return -1;
            return 1;
        }
        name1++;
        name2++;
    }
    /*
     * both OIDs equal up to length of shorter OID
     */
    *offpt = initlen - len;
    if (len1 < len2)
        return -1;
    if (len2 < len1)
        return 1;
    return 0;
}

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
netsnmp_variable_list*
snmp_varlist_add_variable(netsnmp_variable_list**  varlist,
                          const oid*  name,
                          size_t name_length,
                          u_char type, const void*  value, size_t len)
{
    netsnmp_variable_list* vars, *vtmp;
    int rc;

    if (varlist == NULL)
        return NULL;

    vars = SNMP_MALLOC_TYPEDEF(netsnmp_variable_list);
    if (vars == NULL)
        return NULL;

    vars->type = type;

    rc = snmp_set_var_value(vars, value, len);
    if ((0 != rc) ||
        (name != NULL && snmp_set_var_objid(vars, name, name_length))) {
        snmp_free_var(vars);
        return NULL;
    }

    /*
     * put only qualified variable onto varlist
     */
    if (*varlist == NULL) {
        *varlist = vars;
    } else {
        for (vtmp = *varlist; vtmp->next_variable;
             vtmp = vtmp->next_variable);

        vtmp->next_variable = vars;
    }

    return vars;
}

void
snmp_set_detail(const char* detail_string)
{
    if (detail_string != NULL) {
        strncpy((char*) snmp_detail, detail_string, sizeof(snmp_detail));
        snmp_detail[sizeof(snmp_detail) - 1] = '\0';
        snmp_detail_f = 1;
    }
}

 /*  Do a "deep free()" of a netsnmp_session.
 *
 *  CAUTION:  SHOULD ONLY BE USED FROM snmp_sess_close() OR SIMILAR.
 *                                                      (hence it is static)
 */

void
NetSnmpAgent::snmp_free_session(netsnmp_session*  s)
{
    if (s) {
        SNMP_FREE(s->peername);
        SNMP_FREE(s->community);
        SNMP_FREE(s->contextEngineID);
        SNMP_FREE(s->contextName);
        SNMP_FREE(s->securityEngineID);
        SNMP_FREE(s->securityName);
        SNMP_FREE(s->securityAuthProto);
        SNMP_FREE(s->securityPrivProto);
        SNMP_FREE(s->paramName);

        /*
         * clear session from any callbacks
         */
        netsnmp_callback_clear_client_arg(s, 0, 0);

        free((char*) s);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int
NetSnmpAgent::snmp_sess_close(void* sessp)
{
    struct snmp_session_list* slp = (struct snmp_session_list*) sessp;
    netsnmp_transport* transport;
    struct snmp_internal_session* isp;
    netsnmp_session* sesp = NULL;
    struct snmp_secmod_def* sptr;

    if (slp == NULL) {
        return 0;
    }

    if (slp->session != NULL &&
        (sptr = find_sec_mod(slp->session->securityModel)) != NULL &&
        sptr->session_close != NULL) {
        (*sptr->session_close) (slp->session);
    }

    isp = slp->internal;
    slp->internal = NULL;

    if (isp) {
        netsnmp_request_list* rp, *orp;

        SNMP_FREE(isp->packet);

        /*
         * Free each element in the input request list.
         */
        rp = isp->requests;
        while (rp) {
            orp = rp;
            rp = rp->next_request;
            snmp_free_pdu(orp->pdu);
            free((char*) orp);
        }

        free((char*) isp);
    }

    transport = slp->transport;
    slp->transport = NULL;

    if (transport) {
        netsnmp_transport_free(transport);
    }

    sesp = slp->session;
    slp->session = NULL;

    /*
     * The following is necessary to avoid memory leakage when closing AgentX
     * sessions that may have multiple subsessions.  These hang off the main
     * session at ->subsession, and chain through ->next.
     */

    if (sesp != NULL && sesp->subsession != NULL) {
        netsnmp_session* subsession = sesp->subsession, *tmpsub;

        while (subsession != NULL) {
            tmpsub = subsession->next;
            snmp_free_session(subsession);
            subsession = tmpsub;
        }
    }

    snmp_free_session(sesp);
    free((char*) slp);
    return 1;
}

struct snmp_session_list*
NetSnmpAgent::_sess_copy(netsnmp_session*  in_session)
{
    struct snmp_session_list* slp;
    struct snmp_internal_session* isp;
    netsnmp_session* session;
    struct snmp_secmod_def* sptr;
    char*           cp;
    u_char*         ucp;
    size_t          i;

    in_session->s_snmp_errno = 0;
    in_session->s_errno = 0;

    /*
     * Copy session structure and link into list
     */
    slp = (struct snmp_session_list*) calloc(1, sizeof(struct snmp_session_list));
    if (slp == NULL) {
        in_session->s_snmp_errno = SNMPERR_MALLOC;
        return (NULL);
    }

    slp->transport = NULL;

    isp = (struct snmp_internal_session*)calloc(1, sizeof(struct snmp_internal_session));

    if (isp == NULL) {
        snmp_sess_close(slp);
        in_session->s_snmp_errno = SNMPERR_MALLOC;
        return (NULL);
    }

    slp->internal = isp;
    slp->session = (netsnmp_session*)malloc(sizeof(netsnmp_session));
    if (slp->session == NULL) {
        snmp_sess_close(slp);
        in_session->s_snmp_errno = SNMPERR_MALLOC;
        return (NULL);
    }
    memmove(slp->session, in_session, sizeof(netsnmp_session));
    session = slp->session;

    /*
     * zero out pointers so if we have to free the session we wont free mem
     * owned by in_session
     */
    session->peername = NULL;
    session->community = NULL;
    session->contextEngineID = NULL;
    session->contextName = NULL;
    session->securityEngineID = NULL;
    session->securityName = NULL;
    session->securityAuthProto = NULL;
    session->securityPrivProto = NULL;
    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (in_session->peername != NULL) {
        session->peername = (char*)malloc(strlen(in_session->peername) + 1);
        if (session->peername == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
        strcpy(session->peername, in_session->peername);
    }

    /*
     * Fill in defaults if necessary
     */
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    if (in_session->community_len != SNMP_DEFAULT_COMMUNITY_LEN) {
        ucp = (u_char*) malloc(in_session->community_len);
        if (ucp != NULL)
            memmove(ucp, in_session->community, in_session->community_len);
    } else {
        if ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                    NETSNMP_DS_LIB_COMMUNITY)) != NULL) {
            session->community_len = strlen(cp);
            ucp = (u_char*) malloc(session->community_len);
            if (ucp)
                memmove(ucp, cp, session->community_len);
        } else {
#ifdef NETSNMP_NO_ZEROLENGTH_COMMUNITY
            session->community_len = strlen(DEFAULT_COMMUNITY);
            ucp = (u_char*) malloc(session->community_len);
            if (ucp)
                memmove(ucp, DEFAULT_COMMUNITY, session->community_len);
#else
            ucp = (u_char*) strdup("");
#endif
        }
    }

    if (ucp == NULL) {
        snmp_sess_close(slp);
        in_session->s_snmp_errno = SNMPERR_MALLOC;
        return (NULL);
    }
    session->community = ucp;   /* replace pointer with pointer to new data */
#endif

    if (session->securityLevel <= 0) {
        session->securityLevel =
            netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SECLEVEL);
    }

    if (session->securityLevel == 0)
        session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;

    if (in_session->securityAuthProtoLen > 0) {
        session->securityAuthProto =
            snmp_duplicate_objid((const unsigned int*)in_session->securityAuthProto,
                                 in_session->securityAuthProtoLen);
        if (session->securityAuthProto == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
    } else if (get_default_authtype(&i) != NULL) {
        session->securityAuthProto =
            snmp_duplicate_objid(get_default_authtype(NULL), i);
        session->securityAuthProtoLen = i;
    }

    if (in_session->securityPrivProtoLen > 0) {
        session->securityPrivProto =
            snmp_duplicate_objid((const unsigned int*)in_session->securityPrivProto,
                                 in_session->securityPrivProtoLen);
        if (session->securityPrivProto == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
    } else if (get_default_privtype(&i) != NULL) {
        session->securityPrivProto =
            snmp_duplicate_objid(get_default_privtype(NULL), i);
        session->securityPrivProtoLen = i;
    }

    if (in_session->securityEngineIDLen > 0) {
        ucp = (u_char*) malloc(in_session->securityEngineIDLen);
        if (ucp == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
        memmove(ucp, in_session->securityEngineID,
                in_session->securityEngineIDLen);
        session->securityEngineID = ucp;

    }

    if (in_session->contextEngineIDLen > 0) {
        ucp = (u_char*) malloc(in_session->contextEngineIDLen);
        if (ucp == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
        memmove(ucp, in_session->contextEngineID,
                in_session->contextEngineIDLen);
        session->contextEngineID = ucp;
    } else if (in_session->securityEngineIDLen > 0) {
        /*
         * default contextEngineID to securityEngineIDLen if defined
         */
        ucp = (u_char*) malloc(in_session->securityEngineIDLen);
        if (ucp == NULL) {
            snmp_sess_close(slp);
            in_session->s_snmp_errno = SNMPERR_MALLOC;
            return (NULL);
        }
        memmove(ucp, in_session->securityEngineID,
                in_session->securityEngineIDLen);
        session->contextEngineID = ucp;
        session->contextEngineIDLen = in_session->securityEngineIDLen;
    }

    if (in_session->contextName) {
        session->contextName = strdup(in_session->contextName);
        if (session->contextName == NULL) {
            snmp_sess_close(slp);
            return (NULL);
        }
    } else {
        if ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                        NETSNMP_DS_LIB_CONTEXT)) != NULL)
            cp = strdup(cp);
        else
            cp = strdup(SNMP_DEFAULT_CONTEXT);
        if (cp == NULL) {
            snmp_sess_close(slp);
            return (NULL);
        }
        session->contextName = cp;
        session->contextNameLen = strlen(cp);
    }

    if (in_session->securityName) {
        session->securityName = strdup(in_session->securityName);
        if (session->securityName == NULL) {
            snmp_sess_close(slp);
            return (NULL);
        }
    } else if ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_SECNAME)) != NULL) {
        cp = strdup(cp);
        if (cp == NULL) {
            snmp_sess_close(slp);
            return (NULL);
        }
        session->securityName = cp;
        session->securityNameLen = strlen(cp);
    }

    if ((in_session->securityAuthKeyLen <= 0) &&
        ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_AUTHMASTERKEY)))) {
        size_t buflen = sizeof(session->securityAuthKey);
        u_char* tmpp = session->securityAuthKey;
        session->securityAuthKeyLen = 0;
        /* it will be a hex string */
        if (!snmp_hex_to_binary(&tmpp, &buflen,
                                &session->securityAuthKeyLen, 0, cp)) {
            snmp_set_detail("error parsing authentication master key");
            snmp_sess_close(slp);
            return NULL;
        }
    } else if ((in_session->securityAuthKeyLen <= 0) &&
        ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_AUTHPASSPHRASE)) ||
         (cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_PASSPHRASE)))) {
        session->securityAuthKeyLen = USM_AUTH_KU_LEN;
        if (generate_Ku((const oid*)session->securityAuthProto,
                        session->securityAuthProtoLen,
                        (u_char*) cp, strlen(cp),
                        session->securityAuthKey,
                        &session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
            snmp_set_detail
                ("Error generating a key (Ku) from the supplied authentication pass phrase.");
            snmp_sess_close(slp);
            return NULL;
        }
    }


    if ((in_session->securityPrivKeyLen <= 0) &&
        ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_PRIVMASTERKEY)))) {
        size_t buflen = sizeof(session->securityPrivKey);
        u_char* tmpp = session->securityPrivKey;
        session->securityPrivKeyLen = 0;
        /* it will be a hex string */
        if (!snmp_hex_to_binary(&tmpp, &buflen,
                                &session->securityPrivKeyLen, 0, cp)) {
            snmp_set_detail("error parsing encryption master key");
            snmp_sess_close(slp);
            return NULL;
        }
    } else if ((in_session->securityPrivKeyLen <= 0) &&
        ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_PRIVPASSPHRASE)) ||
         (cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                     NETSNMP_DS_LIB_PASSPHRASE)))) {
        session->securityPrivKeyLen = USM_PRIV_KU_LEN;
        if (generate_Ku((const oid*)session->securityAuthProto,
                        session->securityAuthProtoLen,
                        (u_char*) cp, strlen(cp),
                        session->securityPrivKey,
                        &session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
            snmp_set_detail
                ("Error generating a key (Ku) from the supplied privacy pass phrase.");
            snmp_sess_close(slp);
            return NULL;
        }
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
        session->retries = DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
        session->timeout = DEFAULT_TIMEOUT;
    session->sessid = snmp_get_next_sessid();

    snmp_call_callbacks(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_SESSION_INIT,
                        session);

    if ((sptr = find_sec_mod(session->securityModel)) != NULL &&
        sptr->session_open != NULL) {
        /*
         * security module specific inialization
         */
        (*sptr->session_open) (session);
    }

    return (slp);
}

struct snmp_session_list*
NetSnmpAgent::snmp_sess_copy(netsnmp_session*  pss)
{
    struct snmp_session_list* psl;
    psl = _sess_copy(pss);
    if (!psl) {
        if (!pss->s_snmp_errno) {
            pss->s_snmp_errno = SNMPERR_GENERR;
        }
        SET_SNMP_ERROR(pss->s_snmp_errno);
    }
    return psl;
}

void*
NetSnmpAgent::snmp_sess_add_ex(netsnmp_session*  in_session,
                 netsnmp_transport* transport,
                 int (NetSnmpAgent::*fpre_parse) (netsnmp_session* , netsnmp_transport* ,
                                void* , int),
                 int (NetSnmpAgent::*fparse) (netsnmp_session* , netsnmp_pdu* , u_char* ,
                                size_t),
                 int (NetSnmpAgent::*fpost_parse) (netsnmp_session* , netsnmp_pdu* ,
                                int),
                 int (NetSnmpAgent::*fbuild) (netsnmp_session* , netsnmp_pdu* , u_char* ,
                                size_t*),
                 int (NetSnmpAgent::*frbuild) (netsnmp_session* , netsnmp_pdu* ,
                                u_char** , size_t* , size_t*),
                 int (NetSnmpAgent::*fcheck) (u_char* , size_t),
                 netsnmp_pdu* (NetSnmpAgent::*fcreate_pdu) (netsnmp_transport* , void* ,
                                size_t))
{
    struct snmp_session_list* slp;
    _init_snmp();

    if (transport == NULL)
        return NULL;

    if (in_session == NULL) {
        (this->*(transport->f_close))(transport);
        netsnmp_transport_free(transport);
        return NULL;
    }


    if ((slp = snmp_sess_copy(in_session)) == NULL) {
        (this->*(transport->f_close))(transport);
        netsnmp_transport_free(transport);
        return (NULL);
    }

    slp->transport = transport;
    slp->internal->hook_pre = fpre_parse;
    slp->internal->hook_parse = fparse;
    slp->internal->hook_post = fpost_parse;
    slp->internal->hook_build = fbuild;
    slp->internal->hook_realloc_build = frbuild;
    slp->internal->check_packet = fcheck;
    slp->internal->hook_create_pdu = fcreate_pdu;

    slp->session->rcvMsgMaxSize = 65507;

    if (slp->session->version == SNMP_VERSION_3) {
        if (!snmpv3_engineID_probe(slp, in_session)) {
            return NULL;
        }
        if (create_user_from_session(slp->session) != SNMPERR_SUCCESS) {
            in_session->s_snmp_errno = SNMPERR_UNKNOWN_USER_NAME;
            snmp_sess_close(slp);
        }
    }

    slp->session->flags &= ~SNMP_FLAGS_DONT_PROBE;

    return (void*) slp;
}                               /*  end snmp_sess_add_ex()  */

/**
 * Calls the functions to do config file loading and  mib module parsing
 * in the correct order.
 *
 * @param type label for the config file "type"
 *
 * @return void
 *
 * @see init_agent
 */
void
NetSnmpAgent::init_snmp(const char* type)
{
    if (init_snmp_init_done) {
        return;
    }

    init_snmp_init_done = 1;

    /*
     * make the type available everywhere else
     */
    if (type && !netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_APPTYPE)) {
        netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                  NETSNMP_DS_LIB_APPTYPE, type);
    }

    _init_snmp();

    /*
     * set our current locale properly to initialize isprint() type functions
     */
#ifdef HAVE_SETLOCALE
    setlocale(LC_CTYPE, "");
#endif

    /*snmp_debug_init(); */   /* should be done first, to turn on debugging ASAP */
    netsnmp_container_init_list();
    init_callbacks();
    snmp_init_statistics();
    register_mib_handlers();
    register_default_handlers();
    init_snmpv3(type);
    init_snmp_enum(type);
    init_vacm();

    read_premib_configs();
#ifndef NETSNMP_DISABLE_MIB_LOADING
    netsnmp_init_mib();
#endif /* NETSNMP_DISABLE_MIB_LOADING */

    read_configs();

}                               /* end init_snmp() */

struct timeval convert_2_timeval(clocktype nanosec);

void
NetSnmpAgent::_init_snmp(void)
{

    long            tmpReqid, tmpMsgid;

    if (_init_snmp_init_done)
        return;
    _init_snmp_init_done = 1;
    Reqid = 1;

#ifndef NETSNMP_DISABLE_MIB_LOADING
    netsnmp_init_mib_internals();
#endif /* NETSNMP_DISABLE_MIB_LOADING */

    tmpReqid = RANDOM_nrand(snmpRandomSeed);
    tmpMsgid = RANDOM_nrand(snmpRandomSeed);

    if (tmpReqid == 0)
        tmpReqid = 1;
    if (tmpMsgid == 0)
        tmpMsgid = 1;
    Reqid = tmpReqid;
    Msgid = tmpMsgid;

    netsnmp_register_default_domain("snmp", "udp udp6");
    netsnmp_register_default_domain("snmptrap", "udp udp6");

    netsnmp_register_default_target("snmp", "udp", ":161");
    netsnmp_register_default_target("snmp", "tcp", ":161");
    netsnmp_register_default_target("snmp", "udp6", ":161");
    netsnmp_register_default_target("snmp", "tcp6", ":161");
    netsnmp_register_default_target("snmp", "ipx", "/36879");
    netsnmp_register_default_target("snmptrap", "udp", ":162");
    netsnmp_register_default_target("snmptrap", "tcp", ":162");
    netsnmp_register_default_target("snmptrap", "udp6", ":162");
    netsnmp_register_default_target("snmptrap", "tcp6", ":162");
    netsnmp_register_default_target("snmptrap", "ipx", "/36880");

    netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID,
                       NETSNMP_DS_LIB_HEX_OUTPUT_LENGTH, 16);

#ifdef NETSNMP_USE_REVERSE_ASNENCODING
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID,
               NETSNMP_DS_LIB_REVERSE_ENCODE,
               NETSNMP_DEFAULT_ASNENCODING_DIRECTION);
#endif
}

void
NetSnmpAgent::snmp_init_statistics(void)
{
    memset(statistics, 0, sizeof(statistics));
}



void
NetSnmpAgent::register_default_handlers(void)
{
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "dumpPacket",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DUMP_PACKET);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "reverseEncodeBER",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_REVERSE_ENCODE);
    netsnmp_ds_register_config(ASN_INTEGER, "snmp", "defaultPort",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DEFAULT_PORT);
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defCommunity",
                      NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_COMMUNITY);
#endif
    netsnmp_ds_register_premib(ASN_BOOLEAN, "snmp", "noTokenWarnings",
                      NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NO_TOKEN_WARNINGS);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "noRangeCheck",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_CHECK_RANGE);
    netsnmp_ds_register_premib(ASN_OCTET_STR, "snmp", "persistentDir",
                  NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PERSISTENT_DIR);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "tempFilePattern",
                  NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_TEMP_FILE_PATTERN);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "noDisplayHint",
                  NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_NO_DISPLAY_HINT);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "16bitIDs",
                  NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_16BIT_IDS);
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "clientaddr",
                      NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_CLIENT_ADDR);
    netsnmp_ds_register_config(ASN_INTEGER, "snmp", "serverSendBuf",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SERVERSENDBUF);
    netsnmp_ds_register_config(ASN_INTEGER, "snmp", "serverRecvBuf",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SERVERRECVBUF);
    netsnmp_ds_register_config(ASN_INTEGER, "snmp", "clientSendBuf",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_CLIENTSENDBUF);
    netsnmp_ds_register_config(ASN_INTEGER, "snmp", "clientRecvBuf",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_CLIENTRECVBUF);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "noPersistentLoad",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "noPersistentSave",
              NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_SAVE);
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp",
                               "noContextEngineIDDiscovery",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_NO_DISCOVERY);

    netsnmp_register_service_handlers();
}

/*
 * lexicographical compare two object identifiers.
 * * Returns -1 if name1 < name2,
 * *          0 if name1 = name2,
 * *          1 if name1 > name2
 * *
 * * Caution: this method is called often by
 * *          command responder applications (ie, agent).
 */
int
snmp_oid_ncompare(const oid*  in_name1,
                  size_t len1,
                  const oid*  in_name2, size_t len2, size_t max_len)
{
    register int    len;
    register const oid* name1 = in_name1;
    register const oid* name2 = in_name2;
    size_t          min_len;

    /*
     * len = minimum of len1 and len2
     */
    if (len1 < len2)
        min_len = len1;
    else
        min_len = len2;

    if (min_len > max_len)
        min_len = max_len;

    len = min_len;

    /*
     * find first non-matching OID
     */
    while (len-- > 0) {
        /*
         * these must be done in seperate comparisons, since
         * subtracting them and using that result has problems with
         * subids > 2^31.
         */
        if (*(name1) != *(name2)) {
            if (*(name1) < *(name2))
                return -1;
            return 1;
        }
        name1++;
        name2++;
    }

    if (min_len != max_len) {
        /*
         * both OIDs equal up to length of shorter OID
         */
        if (len1 < len2)
            return -1;
        if (len2 < len1)
            return 1;
    }

    return 0;
}

#define ERROR_STAT_LENGTH 11
int
NetSnmpAgent::snmpv3_make_report(netsnmp_pdu* pdu, int error)
{

    Int32            ltmp;
    static oid      unknownSecurityLevel[] =
        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0 };
    static oid      notInTimeWindow[] =
        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 2, 0 };
    static oid      unknownUserName[] =
        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 3, 0 };
    static oid      unknownEngineID[] =
        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0 };
    static oid      wrongDigest[] = { 1, 3, 6, 1, 6, 3, 15, 1, 1, 5, 0 };
    static oid      decryptionError[] =
        { 1, 3, 6, 1, 6, 3, 15, 1, 1, 6, 0 };
    oid*            err_var = 0;
    int             err_var_len = 0;
    int             stat_ind = 0;
    struct snmp_secmod_def* sptr;

    switch (error) {
    case SNMPERR_USM_UNKNOWNENGINEID:
        stat_ind = STAT_USMSTATSUNKNOWNENGINEIDS;
        err_var = unknownEngineID;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_USM_UNKNOWNSECURITYNAME:
        stat_ind = STAT_USMSTATSUNKNOWNUSERNAMES;
        err_var = unknownUserName;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL:
        stat_ind = STAT_USMSTATSUNSUPPORTEDSECLEVELS;
        err_var = unknownSecurityLevel;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_USM_AUTHENTICATIONFAILURE:
        stat_ind = STAT_USMSTATSWRONGDIGESTS;
        err_var = wrongDigest;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_USM_NOTINTIMEWINDOW:
        stat_ind = STAT_USMSTATSNOTINTIMEWINDOWS;
        err_var = notInTimeWindow;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_USM_DECRYPTIONERROR:
        stat_ind = STAT_USMSTATSDECRYPTIONERRORS;
        err_var = decryptionError;
        err_var_len = ERROR_STAT_LENGTH;
        break;
    case SNMPERR_SUCCESS:
        break;
    default:
        return SNMPERR_GENERR;
    }

    snmp_free_varbind(pdu->variables);  /* free the current varbind */

    pdu->variables = NULL;
    SNMP_FREE(pdu->securityEngineID);
    pdu->securityEngineID =
        snmpv3_generate_engineID(&pdu->securityEngineIDLen);
    SNMP_FREE(pdu->contextEngineID);
    pdu->contextEngineID =
        snmpv3_generate_engineID(&pdu->contextEngineIDLen);
    pdu->command = SNMP_MSG_REPORT;
    pdu->errstat = 0;
    pdu->errindex = 0;
    SNMP_FREE(pdu->contextName);
    pdu->contextName = strdup("");
    pdu->contextNameLen = strlen(pdu->contextName);

    /*
     * reports shouldn't cache previous data.
     */
    /*
     * FIX - yes they should but USM needs to follow new EoP to determine
     * which cached values to use
     */
    if (pdu->securityStateRef) {
        sptr = find_sec_mod(pdu->securityModel);
        if (sptr) {
            if (sptr->pdu_free_state_ref) {
                (*sptr->pdu_free_state_ref) (pdu->securityStateRef);
            }
        }
        pdu->securityStateRef = NULL;
    }

    if (error == SNMPERR_USM_NOTINTIMEWINDOW) {
        pdu->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    } else {
        pdu->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
    }

    /*
     * find the appropriate error counter
     */
    if (stat_ind)
    {
        ltmp = snmp_get_statistic(stat_ind,this->node);

    /*
     * return the appropriate error counter
     */
    snmp_pdu_add_variable(pdu, err_var, err_var_len,
                          ASN_COUNTER, & ltmp, sizeof(ltmp));
    }

    return SNMPERR_SUCCESS;
}                               /* end snmpv3_make_report() */

u_int
snmp_get_statistic(int which,Node* node)
{
    if (which >= 0 && which < MAX_STATS)
        return node->netSnmpAgent->statistics[which];
    return 0;
}

/**
 * probe for peer engineID
 *
 * @param slp         session list pointer.
 * @param in_session  session for errors
 *
 * @note
 *  - called by _sess_open(), snmp_sess_add_ex()
 *  - in_session is the user supplied session provided to those functions.
 *  - the first session in slp should the internal allocated copy of in_session
 *
 * @return 0 : error
 * @return 1 : ok
 *
 */
int
NetSnmpAgent::snmpv3_engineID_probe(struct snmp_session_list* slp,
                      netsnmp_session*  in_session)
{
    netsnmp_pdu*    pdu = NULL, *response = NULL;
    netsnmp_session* session;
    int             status;

    if (slp == NULL || slp->session == NULL) {
        return 0;
    }

    session = slp->session;

    /*
     * If we are opening a V3 session and we don't know engineID we must probe
     * it -- this must be done after the session is created and inserted in the
     * list so that the response can handled correctly.
     */

    if ((session->flags & SNMP_FLAGS_DONT_PROBE) == SNMP_FLAGS_DONT_PROBE)
        return 1;

    if (session->version == SNMP_VERSION_3) {
        struct snmp_secmod_def* sptr = find_sec_mod(session->securityModel);

        if (NULL != sptr && NULL != sptr->probe_engineid) {
            status = (*sptr->probe_engineid) (slp, session);
            if (status)
                return 0;
            return 1; /* success! */
        } else if (session->securityEngineIDLen == 0) {
            if (snmpv3_build_probe_pdu(&pdu) != 0) {
                return 0;
            }
            session->flags |= SNMP_FLAGS_DONT_PROBE; /* prevent recursion */
            status = snmp_sess_synch_response(slp, pdu, &response);

            if ((response == NULL) && (status == STAT_SUCCESS)) {
                status = STAT_ERROR;
            }

            switch (status) {
            case STAT_SUCCESS:
                in_session->s_snmp_errno = SNMPERR_INVALID_MSG;
                break;
            case STAT_ERROR:   /* this is what we expected -> Report == STAT_ERROR */
                in_session->s_snmp_errno = SNMPERR_UNKNOWN_ENG_ID;
                break;
            case STAT_TIMEOUT:
                in_session->s_snmp_errno = SNMPERR_TIMEOUT;
            default:
                break;
            }

            if (slp->session->securityEngineIDLen == 0) {
                return 0;
            }

            in_session->s_snmp_errno = SNMPERR_SUCCESS;
        }

        /*
         * if boot/time supplied set it for this engineID
         */
        if (session->engineBoots || session->engineTime) {
            set_enginetime(session->securityEngineID,
                           session->securityEngineIDLen,
                           session->engineBoots, session->engineTime,
                           TRUE);
        }

        if (create_user_from_session(slp->session) != SNMPERR_SUCCESS) {
            in_session->s_snmp_errno = SNMPERR_UNKNOWN_USER_NAME;
            return 0;
        }
    }

    return 1;
}

/*
 * create_user_from_session(netsnmp_session *session):
 *
 * creates a user in the usm table from the information in a session.
 * If the user already exists, it is updated with the current
 * information from the session
 *
 * Parameters:
 * session -- IN: pointer to the session to use when creating the user.
 *
 * Returns:
 * SNMPERR_SUCCESS
 * SNMPERR_GENERR
 */
int
NetSnmpAgent::create_user_from_session(netsnmp_session*  session)
{
    struct usmUser* user;
    int             user_just_created = 0;
    char* cp;

    /*
     * - don't create-another/copy-into user for this session by default
     * - bail now (no error) if we don't have an engineID
     */
    if (SNMP_FLAGS_USER_CREATED == (session->flags & SNMP_FLAGS_USER_CREATED) ||
        session->securityModel != SNMP_SEC_MODEL_USM ||
        session->version != SNMP_VERSION_3 ||
        session->securityNameLen == 0 ||
        session->securityEngineIDLen == 0)
        return SNMPERR_SUCCESS;

    session->flags |= SNMP_FLAGS_USER_CREATED;

    /*
     * now that we have the engineID, create an entry in the USM list
     * for this user using the information in the session
     */
    user = usm_get_user_from_list(session->securityEngineID,
                                  session->securityEngineIDLen,
                                  session->securityName,
                                  usm_get_userList(), 0);
    if (user == NULL) {
        /*DEBUGMSGTL(("snmp_api", "Building user %s...\n",
                    session->securityName));*/
        /*
         * user doesn't exist so we create and add it
         */
        user = (struct usmUser*) calloc(1, sizeof(struct usmUser));
        if (user == NULL)
            return SNMPERR_GENERR;

        /*
         * copy in the securityName
         */
        if (session->securityName) {
            user->name = strdup(session->securityName);
            user->secName = strdup(session->securityName);
            if (user->name == NULL || user->secName == NULL) {
                usm_free_user(user);
                return SNMPERR_GENERR;
            }
        }

        /*
         * copy in the engineID
         */
        if (memdup(&user->engineID, session->securityEngineID,
                   session->securityEngineIDLen) != SNMPERR_SUCCESS) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->engineIDLen = session->securityEngineIDLen;

        user_just_created = 1;
    }
    /*
     * copy the auth protocol
     */
    if (session->securityAuthProto != NULL) {
        SNMP_FREE(user->authProtocol);
        user->authProtocol =
            snmp_duplicate_objid((u_int*)session->securityAuthProto,
                                 session->securityAuthProtoLen);
        if (user->authProtocol == NULL) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->authProtocolLen = session->securityAuthProtoLen;
    }

    /*
     * copy the priv protocol
     */
    if (session->securityPrivProto != NULL) {
        SNMP_FREE(user->privProtocol);
        user->privProtocol =
            snmp_duplicate_objid((u_int*)session->securityPrivProto,
                                 session->securityPrivProtoLen);
        if (user->privProtocol == NULL) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->privProtocolLen = session->securityPrivProtoLen;
    }

    /*
     * copy in the authentication Key.  If not localized, localize it
     */
    if (session->securityAuthLocalKey != NULL
        && session->securityAuthLocalKeyLen != 0) {
        /* already localized key passed in.  use it */
        SNMP_FREE(user->authKey);
        if (memdup(&user->authKey, session->securityAuthLocalKey,
                   session->securityAuthLocalKeyLen) != SNMPERR_SUCCESS) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->authKeyLen = session->securityAuthLocalKeyLen;
    } else if (session->securityAuthKey != NULL
        && session->securityAuthKeyLen != 0) {
        SNMP_FREE(user->authKey);
        user->authKey = (u_char*) calloc(1, USM_LENGTH_KU_HASHBLOCK);
        if (user->authKey == NULL) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->authKeyLen = USM_LENGTH_KU_HASHBLOCK;
        if (generate_kul(user->authProtocol, user->authProtocolLen,
                         session->securityEngineID,
                         session->securityEngineIDLen,
                         session->securityAuthKey,
                         session->securityAuthKeyLen, user->authKey,
                         &user->authKeyLen) != SNMPERR_SUCCESS) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
    } else if ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                           NETSNMP_DS_LIB_AUTHLOCALIZEDKEY))) {
        size_t buflen = USM_AUTH_KU_LEN;
        SNMP_FREE(user->authKey);
        user->authKey = (u_char*)malloc(buflen); /* max length needed */
        user->authKeyLen = 0;
        /* it will be a hex string */
        if (!snmp_hex_to_binary(&user->authKey, &buflen, &user->authKeyLen,
                                0, cp)) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
    }

    /*
     * copy in the privacy Key.  If not localized, localize it
     */
    if (session->securityPrivLocalKey != NULL
        && session->securityPrivLocalKeyLen != 0) {
        /* already localized key passed in.  use it */
        SNMP_FREE(user->privKey);
        if (memdup(&user->privKey, session->securityPrivLocalKey,
                   session->securityPrivLocalKeyLen) != SNMPERR_SUCCESS) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->privKeyLen = session->securityPrivLocalKeyLen;
    } else if (session->securityPrivKey != NULL
        && session->securityPrivKeyLen != 0) {
        SNMP_FREE(user->privKey);
        user->privKey = (u_char*) calloc(1, USM_LENGTH_KU_HASHBLOCK);
        if (user->privKey == NULL) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
        user->privKeyLen = USM_LENGTH_KU_HASHBLOCK;
        if (generate_kul(user->authProtocol, user->authProtocolLen,
                         session->securityEngineID,
                         session->securityEngineIDLen,
                         session->securityPrivKey,
                         session->securityPrivKeyLen, user->privKey,
                         &user->privKeyLen) != SNMPERR_SUCCESS) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
    } else if ((cp = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                           NETSNMP_DS_LIB_PRIVLOCALIZEDKEY))) {
        size_t buflen = USM_PRIV_KU_LEN;
        SNMP_FREE(user->privKey);
        user->privKey = (u_char*)malloc(buflen); /* max length needed */
        user->privKeyLen = 0;
        /* it will be a hex string */
        if (!snmp_hex_to_binary(&user->privKey, &buflen, &user->privKeyLen,
                                0, cp)) {
            usm_free_user(user);
            return SNMPERR_GENERR;
        }
    }

    if (user_just_created) {
        /*
         * add the user into the database
         */
        user->userStatus = RS_ACTIVE;
        user->userStorageType = ST_READONLY;
        usm_add_user(user);
    }

    return SNMPERR_SUCCESS;


}                               /* end create_user_from_session() */

int
NetSnmpAgent::snmpv3_build_probe_pdu(netsnmp_pdu** pdu)
{
    struct usmUser* user;

    /*
     * create the pdu
     */
    if (!pdu)
        return -1;
    *pdu = snmp_pdu_create(SNMP_MSG_GET);
    if (!(*pdu))
        return -1;
    (*pdu)->version = SNMP_VERSION_3;
    (*pdu)->securityName = strdup("");
    (*pdu)->securityNameLen = strlen((*pdu)->securityName);
    (*pdu)->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
    (*pdu)->securityModel = SNMP_SEC_MODEL_USM;

    /*
     * create the empty user
     */
    user = usm_get_user(NULL, 0, (*pdu)->securityName);
    if (user == NULL) {
        user = (struct usmUser*) calloc(1, sizeof(struct usmUser));
        if (user == NULL) {
            snmp_free_pdu(*pdu);
            *pdu = (netsnmp_pdu*) NULL;
            return -1;
        }
        user->name = strdup((*pdu)->securityName);
        user->secName = strdup((*pdu)->securityName);
        user->authProtocolLen = sizeof(usmNoAuthProtocol) / sizeof(oid);
        user->authProtocol =
            snmp_duplicate_objid(usmNoAuthProtocol, user->authProtocolLen);
        user->privProtocolLen = sizeof(usmNoPrivProtocol) / sizeof(oid);
        user->privProtocol =
            snmp_duplicate_objid(usmNoPrivProtocol, user->privProtocolLen);
        usm_add_user(user);
    }
    return 0;
}

int
NetSnmpAgent::_sess_async_send(void* sessp,
                 netsnmp_pdu* pdu)
{
    struct snmp_session_list* slp = (struct snmp_session_list*) sessp;
    netsnmp_session* session;
    struct snmp_internal_session* isp;
    netsnmp_transport* transport = NULL;
    u_char*         pktbuf = NULL, *packet = NULL;
    size_t          pktbuf_len = 0, offset = 0, length = 0;
    int             result;
    long            reqid;

    if (slp == NULL) {
        return 0;
    } else {
        session = slp->session;
        isp = slp->internal;
        transport = slp->transport;
        if (!session || !isp) {
            return 0;
        }
    }

    if (pdu == NULL) {
        session->s_snmp_errno = SNMPERR_NULL_PDU;
        return 0;
    }

    session->s_snmp_errno = 0;
    session->s_errno = 0;

    /*
     * Check/setup the version.
     */
    if (pdu->version == SNMP_DEFAULT_VERSION) {
        if (session->version == SNMP_DEFAULT_VERSION) {
            session->s_snmp_errno = SNMPERR_BAD_VERSION;
            return 0;
        }
        pdu->version = session->version;
    } else if (session->version == SNMP_DEFAULT_VERSION) {
        /*
         * It's OK
         */
    } else if (pdu->version != session->version) {
        /*
         * ENHANCE: we should support multi-lingual sessions
         */
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        return 0;
    }

    /*
     * do we expect a response?
     */
    switch (pdu->command) {

        case SNMP_MSG_RESPONSE:
        case SNMP_MSG_TRAP:
        case SNMP_MSG_TRAP2:
        case SNMP_MSG_REPORT:
            pdu->flags &= ~UCD_MSG_FLAG_EXPECT_RESPONSE;
            break;

        default:
            pdu->flags |= UCD_MSG_FLAG_EXPECT_RESPONSE;
            break;
    }

    /*
     * check to see if we need a v3 engineID probe
     */
    if ((pdu->version == SNMP_VERSION_3) &&
        (pdu->flags & UCD_MSG_FLAG_EXPECT_RESPONSE) &&
        (session->securityEngineIDLen == 0) &&
        (0 == (session->flags & SNMP_FLAGS_DONT_PROBE))) {
        int rc;
        rc = snmpv3_engineID_probe(slp, session);
        if (rc == 0)
            return 0; /* s_snmp_errno already set */
    }

    /*
     * check to see if we need to create a v3 user from the session info
     */
    if (create_user_from_session(session) != SNMPERR_SUCCESS) {
        session->s_snmp_errno = SNMPERR_UNKNOWN_USER_NAME;
        return 0;
    }

    if ((pktbuf = (u_char*)malloc(2048)) == NULL) {
        session->s_snmp_errno = SNMPERR_MALLOC;
        return 0;
    } else {
        pktbuf_len = 2048;
    }

#if TEMPORARILY_DISABLED
    /*
     *  NULL variable are allowed in certain PDU types.
     *  In particular, SNMPv3 engineID probes are of this form.
     *  There is an internal PDU flag to indicate that this
     *    is acceptable, but until the construction of engineID
     *    probes can be amended to set this flag, we'll simply
     *    skip this test altogether.
     */
    if (pdu->variables == NULL) {
        switch (pdu->command) {
        case SNMP_MSG_GET:
        case SNMP_MSG_SET:
        case SNMP_MSG_GETNEXT:
        case SNMP_MSG_GETBULK:
        case SNMP_MSG_RESPONSE:
        case SNMP_MSG_TRAP2:
        case SNMP_MSG_REPORT:
        case SNMP_MSG_INFORM:
            session->s_snmp_errno = snmp_errno = SNMPERR_NO_VARS;
            return 0;
        case SNMP_MSG_TRAP:
            break;
        }
    }
#endif


    /*
     * Build the message to send.
     */
    if (isp->hook_realloc_build) {
        result = (this->*(isp->hook_realloc_build))(session, pdu,
                                         &pktbuf, &pktbuf_len, &offset);
        packet = pktbuf;
        length = offset;
    } else {

        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_REVERSE_ENCODE)) {
            result =
                snmp_build(&pktbuf, &pktbuf_len, &offset, session, pdu);
            packet = pktbuf + pktbuf_len - offset;
            length = offset;
        } else {

            packet = pktbuf;
            length = pktbuf_len;
            result = snmp_build(&pktbuf, &length, &offset, session, pdu);
        }
    }

    if (result < 0) {
        SNMP_FREE(pktbuf);
        return 0;
    }

    /*
     * Make sure we don't send something that is bigger than the msgMaxSize
     * specified in the received PDU.
     */

    if (session->sndMsgMaxSize != 0 && length > session->sndMsgMaxSize) {
        session->s_snmp_errno = SNMPERR_TOO_LONG;
        SNMP_FREE(pktbuf);
        return 0;
    }

    sendResponse((char*)pktbuf, length);
    SNMP_FREE(pktbuf);

    reqid = pdu->reqid;

    return reqid;
}

int
NetSnmpAgent::snmp_sess_send(void* sessp, netsnmp_pdu* pdu)
{
    return snmp_sess_async_send(sessp, pdu);
}

int
NetSnmpAgent::snmp_sess_async_send(void* sessp,
                     netsnmp_pdu* pdu)
{
    int             rc;

    if (sessp == NULL) {
        snmp_errno = SNMPERR_BAD_SESSION;       /*MTCRITICAL_RESOURCE */
        return (0);
    }
    /*
     * send pdu
     */
    rc = _sess_async_send(sessp, pdu);
    if (rc == 0) {
        struct snmp_session_list* psl;
        netsnmp_session* pss;
        psl = (struct snmp_session_list*) sessp;
        pss = psl->session;
    }
    return rc;
}

/*
 * Input : an opaque pointer, returned by snmp_sess_open.
 * returns NULL or pointer to session.
 */
netsnmp_session*
NetSnmpAgent::snmp_sess_session(void* sessp)
{
    struct snmp_session_list* slp = (struct snmp_session_list*) sessp;
    if (slp == NULL)
        return (NULL);
    return (slp->session);
}

/*
 * Same as snmp_select_info, but works just one session.
 */
int
NetSnmpAgent::snmp_sess_select_info(void* sessp,
                      int* block)
{
  int rc;
  rc = snmp_sess_select_info2(sessp, block);
  return rc;
}

/*
 * This function processes a complete (according to asn_check_packet or the
 * AgentX equivalent) packet, parsing it into a PDU and calling the relevant
 * callbacks.  On entry, packetptr points at the packet in the session's
 * buffer and length is the length of the packet.
 */

int
NetSnmpAgent::_sess_process_packet(void* sessp, netsnmp_session*  sp,
                     struct snmp_internal_session* isp,
                     netsnmp_transport* transport,
                     void* opaque, int olength,
                     u_char*  packetptr, int length)
{
#ifdef SNMP_DEBUG
    printf("_sess_process_packet:node %d\n",node->nodeId);
#endif

    netsnmp_pdu*    pdu;
    netsnmp_request_list* rp, *orp = NULL;
    struct snmp_secmod_def* sptr;
    int             ret = 0, handled = 0;

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                NETSNMP_DS_LIB_DUMP_PACKET)) {
        if (transport->f_fmtaddr != NULL) {
            char* addrtxt = (this->*(transport->f_fmtaddr))(transport, opaque, olength);
            if (addrtxt != NULL) {
                SNMP_FREE(addrtxt);
            }
        }
        xdump(packetptr, length, "");
    }

   /*
    * Do transport-level filtering (e.g. IP-address based allow/deny).
    */

    if (isp->hook_pre) {
        if ((this->*(isp->hook_pre))(sp, transport, opaque, olength) == 0) {
            if (opaque != NULL) {
                SNMP_FREE(opaque);
            }
            return -1;
        }
    }

    pdu = snmp_create_sess_pdu(transport, opaque, olength);

    /* if the transport was a magic tunnel, mark the PDU as having come
    through one. */
    if (transport->flags & NETSNMP_TRANSPORT_FLAG_TUNNELED) {
        pdu->flags |= UCD_MSG_FLAG_TUNNELED;
    }

    if (pdu == NULL) {
        if (opaque != NULL) {
            SNMP_FREE(opaque);
        }
        return -1;
    }

    ret = snmp_parse(sessp, sp, pdu, packetptr, length);

    if (isp->hook_post) {
        if ((this->*(isp->hook_post))(sp, pdu, ret) == 0) {
            ret = SNMPERR_ASN_PARSE_ERR;
        }
    }

    if (ret != SNMP_ERR_NOERROR) {
        /*
        * Call the security model to free any securityStateRef supplied w/ msg.
        */
        if (pdu->securityStateRef != NULL) {
            sptr = find_sec_mod(pdu->securityModel);
            if (sptr != NULL) {
                if (sptr->pdu_free_state_ref != NULL) {
                    (*sptr->pdu_free_state_ref) (pdu->securityStateRef);
                }
            }
            pdu->securityStateRef = NULL;
        }
        snmp_free_pdu(pdu);
        return -1;
    }

    if (pdu->flags & UCD_MSG_FLAG_RESPONSE_PDU) {
        /*
         * Call USM to free any securityStateRef supplied with the message.
         */
        if (pdu->securityStateRef) {
            sptr = find_sec_mod(pdu->securityModel);
            if (sptr) {
                if (sptr->pdu_free_state_ref) {
                    (*sptr->pdu_free_state_ref) (pdu->securityStateRef);
                } else {
                    /*snmp_log(LOG_ERR,
                    "Security Model %d can't free state references\n",
                    pdu->securityModel);*/
                }
            }
            pdu->securityStateRef = NULL;
        }

        for (rp = isp->requests; rp; orp = rp, rp = rp->next_request) {
            int (NetSnmpAgent::*callback) (int, netsnmp_session* , int,
                                      netsnmp_pdu* , void*);
            void* magic;

            if (pdu->version == SNMP_VERSION_3) {
                /*
                * msgId must match for v3 messages.
                */
                if (rp->message_id != pdu->msgid) {
                    continue;
                }

                /*
                * Check that message fields match original, if not, no further
                * processing.
                */
                if (!snmpv3_verify_msg(rp, pdu)) {
                    break;
                }
            } else {
                if (rp->request_id != pdu->reqid) {
                    continue;
                }
            }

            if (rp->callback) {
                callback = rp->callback;
                magic = rp->cb_data;
            } else {
                callback = sp->callback;
                magic = sp->callback_magic;
            }
            handled = 1;

            /*
            * MTR snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);  ?* XX lock
            * should be per session !
            */

            if (callback == NULL
            || (this->*(callback))(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE, sp,
            pdu->reqid, pdu, magic) == 1) {
                /*
                * Successful, so delete request.
                */
                if (isp->requests == rp) {
                    isp->requests = rp->next_request;
                    if (isp->requestsEnd == rp) {
                        isp->requestsEnd = NULL;
                    }
                } else {
                    orp->next_request = rp->next_request;
                    if (isp->requestsEnd == rp) {
                        isp->requestsEnd = orp;
                    }
                }
                snmp_free_pdu(rp->pdu);
                free((char*) rp);
                /*
                * There shouldn't be any more requests with the same reqid.
                */
                break;
            }
            /*
            * MTR snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);  ?* XX lock should be per session !
            */
        }
    } else {
        if (sp->callback) {
            /*
            * MTR snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);
            */
            handled = 1;
            (this->*(sp->callback))(NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE,
               sp, pdu->reqid, pdu, sp->callback_magic);
            /*
            * MTR snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);
            */
        }
    }

    /*
    * Call USM to free any securityStateRef supplied with the message.
    */
    if (pdu != NULL && pdu->securityStateRef &&
                    pdu->command == SNMP_MSG_TRAP2) {
        sptr = find_sec_mod(pdu->securityModel);
        if (sptr) {
            if (sptr->pdu_free_state_ref) {
                (*sptr->pdu_free_state_ref) (pdu->securityStateRef);
            }
        }
        pdu->securityStateRef = NULL;
    }

    if (!handled) {
        snmp_increment_statistic(STAT_SNMPUNKNOWNPDUHANDLERS);
    }

    snmp_free_pdu(pdu);
#ifdef JNE_LIB
    JneData& jneData = JNE_GetJneData(node);
        
    if (jneData.sendHmsLoginStatusTrap > 0)
    {  

        //Traps sent according to wireshark capture between live radio and JNE
        send_hmsNotificationUserLoginStatusTrap_trap(node,2,1);
        send_hmsNotificationUserLoginStatusTrap_trap(node,0,1);
        send_hmsNotificationChanActPresetWfInstantiationStatusTrap_trap(node);

        //Preset Channel ID related traps
        /*send_hmsNotificationChanActPresetWfFrequencyViolationTrap_trap(node);
        send_hmsNotificationChanHARpActivateTrap_trap(node);
        send_hmsNotificationChanHARpDeactivateTrap_trap(node);
        send_hmsNotificationChanHARcIsolatedTrap_trap(node);
        send_hmsNotificationChanHARcRnodePresentTrap_trap(node);
        send_hmsNotificationChanConfirmWfCommandRequiredTrap_trap(node);
        send_hmsNotificationChanSINCGARSERFChanNumTrap_trap(node);
        send_hmsNotificationHfAle_trap(node);
        send_hmsNotificationChanWfReturnStatusTrap_trap(node);*/
        //send_hmsNotificationChanActPresetWfInstantiationStatusTrap_trap(node);


        //Command status related traps
        /*send_hmsNotificationKeyFillTrap_trap(node);
        send_hmsNotificationKeyUpdateStatusTrap_trap(node);
        send_hmsNotificationEditUserTableStatusTrap_trap(node);
        */
        //send_hmsNotificationRadioLogoutUserTrap_trap(node);

    }
#endif //JNE_LIB
    return 0;
}

netsnmp_pdu*
snmp_create_sess_pdu(netsnmp_transport* transport, void* opaque,
                     size_t olength)
{
    netsnmp_pdu* pdu = (netsnmp_pdu*)calloc(1, sizeof(netsnmp_pdu));
    if (pdu == NULL) {
        return NULL;
    }

    /*
     * Save the transport-level data specific to this reception (e.g. UDP
     * source address).
     */

    pdu->transport_data = opaque;
    pdu->transport_data_length = olength;
    pdu->tDomain = (u_long*)transport->domain;
    pdu->tDomainLen = transport->domain_length;
    return pdu;
}

int
NetSnmpAgent::snmp_parse(void* sessp,
           netsnmp_session*  pss,
           netsnmp_pdu* pdu, u_char*  data, size_t length)
{
    int             rc;

    rc = _snmp_parse(sessp, pss, pdu, data, length);
    if (rc) {
        if (!pss->s_snmp_errno) {
            pss->s_snmp_errno = SNMPERR_BAD_PARSE;
        }
        SET_SNMP_ERROR(pss->s_snmp_errno);
    }

    return rc;
}

static int
snmpv3_verify_msg(netsnmp_request_list* rp, netsnmp_pdu* pdu)
{
    netsnmp_pdu*    rpdu;

    if (!rp || !rp->pdu || !pdu)
        return 0;
    /*
     * Reports don't have to match anything according to the spec
     */
    if (pdu->command == SNMP_MSG_REPORT)
        return 1;
    rpdu = rp->pdu;
    if (rp->request_id != pdu->reqid || rpdu->reqid != pdu->reqid)
        return 0;
    if (rpdu->version != pdu->version)
        return 0;
    if (rpdu->securityModel != pdu->securityModel)
        return 0;
    if (rpdu->securityLevel != pdu->securityLevel)
        return 0;

    if (rpdu->contextEngineIDLen != pdu->contextEngineIDLen ||
        memcmp(rpdu->contextEngineID, pdu->contextEngineID,
               pdu->contextEngineIDLen))
        return 0;
    if (rpdu->contextNameLen != pdu->contextNameLen ||
        memcmp(rpdu->contextName, pdu->contextName, pdu->contextNameLen))
        return 0;

    /* tunneled transports don't have a securityEngineID...  that's
       USM specific (and maybe other future ones) */
    if (pdu->securityModel == SNMP_SEC_MODEL_USM &&
        (rpdu->securityEngineIDLen != pdu->securityEngineIDLen ||
        memcmp(rpdu->securityEngineID, pdu->securityEngineID,
               pdu->securityEngineIDLen)))
        return 0;

    /* the securityName must match though regardless of secmodel */
    if (rpdu->securityNameLen != pdu->securityNameLen ||
        memcmp(rpdu->securityName, pdu->securityName,
               pdu->securityNameLen))
        return 0;
    return 1;
}

int
snmpv3_get_report_type(netsnmp_pdu* pdu)
{
    static oid      snmpMPDStats[] = { 1, 3, 6, 1, 6, 3, 11, 2, 1 };
    static oid      usmStats[] = { 1, 3, 6, 1, 6, 3, 15, 1, 1 };
    netsnmp_variable_list* vp;
    int             rpt_type = SNMPERR_UNKNOWN_REPORT;

    if (pdu == NULL || pdu->variables == NULL)
        return rpt_type;
    vp = pdu->variables;
    if (vp->name_length == REPORT_STATS_LEN + 2) {
        if (memcmp(snmpMPDStats, vp->name, REPORT_STATS_LEN * sizeof(oid))
            == 0) {
            switch (vp->name[REPORT_STATS_LEN]) {
            case REPORT_snmpUnknownSecurityModels_NUM:
                rpt_type = SNMPERR_UNKNOWN_SEC_MODEL;
                break;
            case REPORT_snmpInvalidMsgs_NUM:
                rpt_type = SNMPERR_INVALID_MSG;
                break;
            }
        } else
            if (memcmp(usmStats, vp->name, REPORT_STATS_LEN * sizeof(oid))
                == 0) {
            switch (vp->name[REPORT_STATS_LEN]) {
            case REPORT_usmStatsUnsupportedSecLevels_NUM:
                rpt_type = SNMPERR_UNSUPPORTED_SEC_LEVEL;
                break;
            case REPORT_usmStatsNotInTimeWindows_NUM:
                rpt_type = SNMPERR_NOT_IN_TIME_WINDOW;
                break;
            case REPORT_usmStatsUnknownUserNames_NUM:
                rpt_type = SNMPERR_UNKNOWN_USER_NAME;
                break;
            case REPORT_usmStatsUnknownEngineIDs_NUM:
                rpt_type = SNMPERR_UNKNOWN_ENG_ID;
                break;
            case REPORT_usmStatsWrongDigests_NUM:
                rpt_type = SNMPERR_AUTHENTICATION_FAILURE;
                break;
            case REPORT_usmStatsDecryptionErrors_NUM:
                rpt_type = SNMPERR_DECRYPTION_ERR;
                break;
            }
        }
    }
    return rpt_type;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.
 * If any errors are encountered, -1 or USM error is returned.
 * Otherwise, a 0 is returned.
 */
int
NetSnmpAgent::_snmp_parse(void* sessp,
            netsnmp_session*  session,
            netsnmp_pdu* pdu, u_char*  data, size_t length)
{
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    u_char          community[COMMUNITY_MAX_LEN];
    size_t          community_length = COMMUNITY_MAX_LEN;
#endif
    int             result = -1;

    static oid      snmpEngineIDoid[]   = { 1,3,6,1,6,3,10,2,1,1,0};
    static size_t   snmpEngineIDoid_len = 11;

    static char     ourEngineID[SNMP_SEC_PARAM_BUF_SIZE];
    static size_t   ourEngineID_len = sizeof(ourEngineID);

    netsnmp_pdu*    pdu2 = NULL;

    session->s_snmp_errno = 0;
    session->s_errno = 0;

    /*
     * Ensure all incoming PDUs have a unique means of identification
     * (This is not restricted to AgentX handling,
     * though that is where the need becomes visible)
     */
    pdu->transid = snmp_get_next_transid();

    if (session->version != SNMP_DEFAULT_VERSION) {
        pdu->version = session->version;
    } else {
        pdu->version = snmp_parse_version(data, length);
    }

    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
        /*
         * authenticates message and returns length if valid
         */
        data = snmp_comstr_parse(data, &length,
                                 community, &community_length,
                                 &pdu->version);
        if (data == NULL)
            return -1;

        if (pdu->version != session->version &&
            session->version != SNMP_DEFAULT_VERSION) {
            session->s_snmp_errno = SNMPERR_BAD_VERSION;
            return -1;
        }

        /*
         * maybe get the community string.
         */
        pdu->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        pdu->securityModel =
#ifndef NETSNMP_DISABLE_SNMPV1
            (pdu->version == SNMP_VERSION_1) ? SNMP_SEC_MODEL_SNMPv1 :
#endif
                                               SNMP_SEC_MODEL_SNMPv2c;
        SNMP_FREE(pdu->community);
        pdu->community_len = 0;
        pdu->community = (u_char*) 0;
        if (community_length) {
            pdu->community_len = community_length;
            pdu->community = (u_char*) malloc(community_length);
            if (pdu->community == NULL) {
                session->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->community, community, community_length);
        }
        if (session->authenticator) {
            data = session->authenticator(data, &length,
                                          community, community_length);
            if (data == NULL) {
                session->s_snmp_errno = SNMPERR_AUTHENTICATION_FAILURE;
                return -1;
            }
        }

        result = snmp_pdu_parse(pdu, data, &length);
        if (result < 0) {
            /*
             * This indicates a parse error.
             */
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        }
        break;
#endif /* support for community based SNMP */

    case SNMP_VERSION_3:
        result = snmpv3_parse(pdu, data, &length, NULL, session);

        if (result) {
            struct snmp_secmod_def* secmod =
                find_sec_mod(pdu->securityModel);
            if (!sessp) {
                session->s_snmp_errno = result;
            } else {
                /*
                 * Call the security model to special handle any errors
                 */

                if (secmod && secmod->handle_report) {
                    struct snmp_session_list* slp = (struct snmp_session_list*) sessp;
                    (this->*secmod->handle_report)(sessp, slp->transport, session,
                                             result, pdu);
                }
            }
            if (pdu->securityStateRef != NULL) {
                if (secmod && secmod->pdu_free_state_ref) {
                    secmod->pdu_free_state_ref(pdu->securityStateRef);
                    pdu->securityStateRef = NULL;
                }
            }
        }

        /* Implement RFC5343 here for two reasons:
           1) From a security perspective it handles this otherwise
              always approved request earlier.  It bypasses the need
              for authorization to the snmpEngineID scalar, which is
              what is what RFC3415 appendix A species as ok.  Note
              that we haven't bypassed authentication since if there
              was an authentication eror it would have been handled
              above in the if (result) part at the lastet.
           2) From an application point of view if we let this request
              get all the way to the application, it'd require that
              all application types supporting discovery also fire up
              a minimal agent in order to handle just this request
              which seems like overkill.  Though there is no other
              application types that currently need discovery (NRs
              accept notifications from contextEngineIDs that derive
              from the NO not the NR).  Also a lame excuse for doing
              it here.
           3) Less important technically, but the net-snmp agent
              doesn't currently handle registrations of different
              engineIDs either and it would have been a lot more work
              to implement there since we'd need to support that
              first. :-/ Supporting multiple context engineIDs should
              be done anyway, so it's not a valid excuse here.
           4) There is a lot less to do if we trump the agent at this
              point; IE, the agent does a lot more unnecessary
              processing when the only thing that should ever be in
              this context by definition is the single scalar.
        */

        /* special RFC5343 engineID discovery engineID check */
        if (!netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                                    NETSNMP_DS_LIB_NO_DISCOVERY) &&
            SNMP_MSG_RESPONSE       != pdu->command &&
            NULL                    != pdu->contextEngineID &&
            pdu->contextEngineIDLen == 5 &&
            pdu->contextEngineID[0] == 0x80 &&
            pdu->contextEngineID[1] == 0x00 &&
            pdu->contextEngineID[2] == 0x00 &&
            pdu->contextEngineID[3] == 0x00 &&
            pdu->contextEngineID[4] == 0x06) {

            /* define a result so it doesn't get past us at this point
               and gets dropped by future parts of the stack */
            result = SNMPERR_JUST_A_CONTEXT_PROBE;

            /* ensure exactly one variable */
            if (NULL != pdu->variables &&
                NULL == pdu->variables->next_variable &&

                /* if it's a GET, match it exactly */
                ((SNMP_MSG_GET == pdu->command &&
                  snmp_oid_compare(snmpEngineIDoid,
                                   snmpEngineIDoid_len,
                                   pdu->variables->name,
                                   pdu->variables->name_length) == 0)
                 /* if it's a GETNEXT ensure it's less than the engineID oid */
                 ||
                 (SNMP_MSG_GETNEXT == pdu->command &&
                  snmp_oid_compare(snmpEngineIDoid,
                                   snmpEngineIDoid_len,
                                   pdu->variables->name,
                                   pdu->variables->name_length) > 0)))
            {

                /* Note: we're explictly not handling a GETBULK.  Deal. */

                /* set up the response */
                pdu2 = snmp_clone_pdu(pdu);

                /* free the current varbind */
                snmp_free_varbind(pdu2->variables);

                /* set the variables */
                pdu2->variables = NULL;
                pdu2->command = SNMP_MSG_RESPONSE;
                pdu2->errstat = 0;
                pdu2->errindex = 0;

                ourEngineID_len =
                    snmpv3_get_engineID((u_char*)ourEngineID, ourEngineID_len);
                if (0 != ourEngineID_len) {

                    snmp_pdu_add_variable(pdu2,
                                          snmpEngineIDoid, snmpEngineIDoid_len,
                                          ASN_OCTET_STR,
                                          ourEngineID, ourEngineID_len);

                    /* send the response */
                    if (0 == snmp_sess_send(sessp, pdu2)) {

                        snmp_free_pdu(pdu2);
                    }
                }
            }
        }

        break;
    case SNMPERR_BAD_VERSION:
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        break;
    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_2p:
    default:
        snmp_increment_statistic(STAT_SNMPINBADVERSIONS);

        /*
         * need better way to determine OS independent
         * INT32_MAX value, for now hardcode
         */
        if (pdu->version < 0 || pdu->version > 2147483647) {
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        }
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        break;
    }

    return result;
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by *pkt.  *pkt_len is the size of the data area available.
 * Returns the length of the completed packet in *offset.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */

int
NetSnmpAgent::_snmp_build(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
            netsnmp_session*  session, netsnmp_pdu* pdu)
{
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    u_char*         h0e = NULL;
    long            version;
#endif /* support for community based SNMP */

    u_char*         h0, *h1;
    u_char*         cp;
    size_t          length;

    session->s_snmp_errno = 0;
    session->s_errno = 0;

    if (pdu->version == SNMP_VERSION_3) {
        return snmpv3_build(pkt, pkt_len, offset, session, pdu);
    }

    switch (pdu->command) {
    case SNMP_MSG_RESPONSE:
        /*
         * Fallthrough
         */
    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_SET:
        /*
         * all versions support these PDU types
         */
        /*
         * initialize defaulted PDU fields
         */

        if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
            pdu->errstat = 0;
        if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
            pdu->errindex = 0;
        break;

    case SNMP_MSG_TRAP2:
        /*
         * Fallthrough
         */
    case SNMP_MSG_INFORM:
#ifndef NETSNMP_DISABLE_SNMPV1
        /*
         * not supported in SNMPv1 and SNMPsec
         */
        if (pdu->version == SNMP_VERSION_1) {
            session->s_snmp_errno = SNMPERR_V2_IN_V1;
            return -1;
        }
#endif
        if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
            pdu->errstat = 0;
        if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
            pdu->errindex = 0;
        break;

    case SNMP_MSG_GETBULK:
        /*
         * not supported in SNMPv1 and SNMPsec
         */
#ifndef NETSNMP_DISABLE_SNMPV1
        if (pdu->version == SNMP_VERSION_1) {
            session->s_snmp_errno = SNMPERR_V2_IN_V1;
            return -1;
        }
#endif
        if (pdu->max_repetitions < 0) {
            session->s_snmp_errno = SNMPERR_BAD_REPETITIONS;
            return -1;
        }
        if (pdu->non_repeaters < 0) {
            session->s_snmp_errno = SNMPERR_BAD_REPEATERS;
            return -1;
        }
        break;

    case SNMP_MSG_TRAP:
        /*
         * *only* supported in SNMPv1 and SNMPsec
         */
#ifndef NETSNMP_DISABLE_SNMPV1
        if (pdu->version != SNMP_VERSION_1) {
            session->s_snmp_errno = SNMPERR_V1_IN_V2;
            return -1;
        }
#endif
        /*
         * initialize defaulted Trap PDU fields
         */
        pdu->reqid = 1;         /* give a bogus non-error reqid for traps */
        if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH) {
            pdu->enterprise = (oid*) malloc(sizeof(DEFAULT_ENTERPRISE));
            if (pdu->enterprise == NULL) {
                session->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->enterprise, DEFAULT_ENTERPRISE,
                    sizeof(DEFAULT_ENTERPRISE));
            pdu->enterprise_length =
                sizeof(DEFAULT_ENTERPRISE) / sizeof(oid);
        }
        if (pdu->time == SNMP_DEFAULT_TIME)
            pdu->time = DEFAULT_TIME;
        /*
         * don't expect a response
         */
        pdu->flags &= (~UCD_MSG_FLAG_EXPECT_RESPONSE);
        break;

    case SNMP_MSG_REPORT:      /* SNMPv3 only */
    default:
        session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
        return -1;
    }

    /*
     * save length
     */
    length = *pkt_len;

    /*
     * setup administrative fields based on version
     */
    /*
     * build the message wrapper and all the administrative fields
     * upto the PDU sequence
     * (note that actual length of message will be inserted later)
     */
    h0 = *pkt;
    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
#ifdef NETSNMP_NO_ZEROLENGTH_COMMUNITY
        if (pdu->community_len == 0) {
            if (session->community_len == 0) {
                session->s_snmp_errno = SNMPERR_BAD_COMMUNITY;
                return -1;
            }
            pdu->community = (u_char*) malloc(session->community_len);
            if (pdu->community == NULL) {
                session->s_snmp_errno = SNMPERR_MALLOC;
                return -1;
            }
            memmove(pdu->community,
                    session->community, session->community_len);
            pdu->community_len = session->community_len;
        }
#else                           /* !NETSNMP_NO_ZEROLENGTH_COMMUNITY */
        if (pdu->community_len == 0 && pdu->command != SNMP_MSG_RESPONSE) {
            /*
             * copy session community exactly to pdu community
             */
            if (0 == session->community_len) {
                SNMP_FREE(pdu->community);
                pdu->community = NULL;
            } else if (pdu->community_len == session->community_len) {
                memmove(pdu->community,
                        session->community, session->community_len);
            } else {
                SNMP_FREE(pdu->community);
                pdu->community = (u_char*) malloc(session->community_len);
                if (pdu->community == NULL) {
                    session->s_snmp_errno = SNMPERR_MALLOC;
                    return -1;
                }
                memmove(pdu->community,
                        session->community, session->community_len);
            }
            pdu->community_len = session->community_len;
        }
#endif                          /* !NETSNMP_NO_ZEROLENGTH_COMMUNITY */

#ifdef NETSNMP_USE_REVERSE_ASNENCODING
        if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_REVERSE_ENCODE)) {
            rc = snmp_pdu_realloc_rbuild(pkt, pkt_len, offset, pdu);
            if (rc == 0) {
                return -1;
            }

            rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                                           (u_char) (ASN_UNIVERSAL |
                                                     ASN_PRIMITIVE |
                                                     ASN_OCTET_STR),
                                           pdu->community,
                                           pdu->community_len);
            if (rc == 0) {
                return -1;
            }


            /*
             * Store the version field.
             */
            version = pdu->version;
            rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                        (u_char) (ASN_UNIVERSAL |
                                                  ASN_PRIMITIVE |
                                                  ASN_INTEGER),
                                        (long*) &version,
                                        sizeof(version));
            if (rc == 0) {
                return -1;
            }

            /*
             * Build the final sequence.
             */

            rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                             (u_char) (ASN_SEQUENCE |
                                                       ASN_CONSTRUCTOR),
                                             *offset - start_offset);

            if (rc == 0) {
                return -1;
            }
            return 0;
        } else {

#endif                          /* NETSNMP_USE_REVERSE_ASNENCODING */
            /*
             * Save current location and build SEQUENCE tag and length
             * placeholder for SNMP message sequence
             * (actual length will be inserted later)
             */
            cp = asn_build_sequence(*pkt, pkt_len,
                                    (u_char) (ASN_SEQUENCE |
                                              ASN_CONSTRUCTOR), 0);
            if (cp == NULL) {
                return -1;
            }
            h0e = cp;

            /*
             * store the version field
             */
            version = pdu->version;
            cp = asn_build_int(cp, pkt_len,
                               (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                         ASN_INTEGER), (long*) &version,
                               sizeof(version));
            if (cp == NULL)
                return -1;

            /*
             * store the community string
             */
            cp = asn_build_string(cp, pkt_len,
                                  (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                            ASN_OCTET_STR), pdu->community,
                                  pdu->community_len);
            if (cp == NULL)
                return -1;
            break;

#ifdef NETSNMP_USE_REVERSE_ASNENCODING
        }
#endif                          /* NETSNMP_USE_REVERSE_ASNENCODING */
        break;
#endif /* support for community based SNMP */
    case SNMP_VERSION_2p:
    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    default:
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        return -1;
    }

    h1 = cp;
    cp = snmp_pdu_build(pdu, cp, pkt_len);
    if (cp == NULL)
        return -1;


    /*
     * insert the actual length of the message sequence
     */
    switch (pdu->version) {
#ifndef NETSNMP_DISABLE_SNMPV1
    case SNMP_VERSION_1:
#endif
#ifndef NETSNMP_DISABLE_SNMPV2C
    case SNMP_VERSION_2c:
#endif
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
        asn_build_sequence(*pkt, &length,
                           (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           cp - h0e);
        break;
#endif /* support for community based SNMP */

    case SNMP_VERSION_2p:
    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    default:
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        return -1;
    }
    *pkt_len = cp - *pkt;
    return 0;
}

int
NetSnmpAgent::snmp_build(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
           netsnmp_session*  pss, netsnmp_pdu* pdu)
{
    int             rc;
    rc = _snmp_build(pkt, pkt_len, offset, pss, pdu);
    if (rc) {
        if (!pss->s_snmp_errno) {
            pss->s_snmp_errno = SNMPERR_BAD_ASN1_BUILD;
        }
        SET_SNMP_ERROR(pss->s_snmp_errno);
        rc = -1;
    }
    return rc;
}

/*
 * Parses the packet received to determine version, either directly
 * from packets version field or inferred from ASN.1 construct.
 */
static int
snmp_parse_version(u_char*  data, size_t length)
{
    u_char          type;
    long            version = SNMPERR_BAD_VERSION;

    data = asn_parse_sequence(data, &length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR), "version");
    if (data) {
        data =
            asn_parse_int(data, &length, &type, &version, sizeof(version));
        if (!data || type != ASN_INTEGER) {
            return SNMPERR_BAD_VERSION;
        }
    }
    return version;
}

int
NetSnmpAgent::snmp_pdu_parse(netsnmp_pdu* pdu, u_char*  data, size_t*  length)
{
    u_char          type;
    u_char          msg_type;
    u_char*         var_val;
    int             badtype = 0;
    size_t          len;
    size_t          four;
    netsnmp_variable_list* vp = NULL;
    oid             objid[MAX_OID_LEN];

    /*
     * Get the PDU type
     */
    data = asn_parse_header(data, length, &msg_type);
    if (data == NULL)
        return -1;
    pdu->command = msg_type;
    pdu->flags &= (~UCD_MSG_FLAG_RESPONSE_PDU);

    /*
     * get the fields in the PDU preceeding the variable-bindings sequence
     */
    switch (pdu->command) {
    case SNMP_MSG_TRAP:
        /*
         * enterprise
         */
        pdu->enterprise_length = MAX_OID_LEN;
        data = asn_parse_objid(data, length, &type, objid,
                               &pdu->enterprise_length);
        if (data == NULL)
            return -1;
        pdu->enterprise =
            (oid*) malloc(pdu->enterprise_length*  sizeof(oid));
        if (pdu->enterprise == NULL) {
            return -1;
        }
        memmove(pdu->enterprise, objid,
                pdu->enterprise_length*  sizeof(oid));

        /*
         * agent-addr
         */
        four = 4;
        data = asn_parse_string(data, length, &type,
                                (u_char*) pdu->agent_addr, &four);
        if (data == NULL)
            return -1;

        /*
         * generic trap
         */
        data = asn_parse_int(data, length, &type, (long*) &pdu->trap_type,
                             sizeof(pdu->trap_type));
        if (data == NULL)
            return -1;
        /*
         * specific trap
         */
        data =
            asn_parse_int(data, length, &type,
                          (long*) &pdu->specific_type,
                          sizeof(pdu->specific_type));
        if (data == NULL)
            return -1;

        /*
         * timestamp
         */
        data = asn_parse_unsigned_int(data, length, &type, &pdu->time,
            sizeof(pdu->time));
        if (data == NULL)
            return -1;

        break;

    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_REPORT:
        pdu->flags |= UCD_MSG_FLAG_RESPONSE_PDU;
        /*
         * fallthrough
         */

    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_GETBULK:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_INFORM:
    case SNMP_MSG_SET:
        /*
         * PDU is not an SNMPv1 TRAP
         */

        /*
         * request id
         */
        data = asn_parse_int(data, length, &type, &pdu->reqid,
                             sizeof(pdu->reqid));
        if (data == NULL) {
            return -1;
        }

        data = asn_parse_int(data, length, &type, &pdu->errstat,
                             sizeof(pdu->errstat));
        if (data == NULL) {
            return -1;
        }

        data = asn_parse_int(data, length, &type, &pdu->errindex,
                             sizeof(pdu->errindex));
        if (data == NULL) {
            return -1;
        }
    break;

    default:
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return -1;
    }

    /*
     * get header for variable-bindings sequence
     */
    data = asn_parse_sequence(data, length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "varbinds");
    if (data == NULL)
        return -1;

    /*
     * get each varBind sequence
     */
    while ((int) *length > 0) {
        netsnmp_variable_list* vptemp;
        vptemp = (netsnmp_variable_list*) malloc(sizeof(*vptemp));
        if (NULL == vptemp) {
            return -1;
        }
        memset(vptemp, 0, sizeof(netsnmp_variable_list));
        if (NULL == vp) {
            pdu->variables = vptemp;
        } else {
            vp->next_variable = vptemp;
        }
        vp = vptemp;

        vp->next_variable = NULL;
        vp->val.string = NULL;
        vp->name_length = MAX_OID_LEN;
        vp->name = NULL;
        vp->index = 0;
        vp->data = NULL;
        vp->dataFreeHook = NULL;
        data = snmp_parse_var_op(data, objid, &vp->name_length, &vp->type,
                                 &vp->val_len, &var_val, length);
        if (vp->name_length == 11 && check_for_inform_ack(objid))
            snmp_increment_statistic(STAT_INFORM_ACK);

        if (data == NULL)
            return -1;
        if (snmp_set_var_objid(vp, objid, vp->name_length))
            return -1;

        len = MAX_PACKET_LENGTH;
        switch ((short) vp->type) {
        case ASN_INTEGER:
            vp->val.integer = (long*) vp->buf;
            vp->val_len = sizeof(long);
            asn_parse_int(var_val, &len, &vp->type,
                          (long*) vp->val.integer,
                          sizeof(*vp->val.integer));
            break;
        case ASN_COUNTER:
        case ASN_GAUGE:
        case ASN_TIMETICKS:
        case ASN_UINTEGER:
            vp->val.integer = (long*) vp->buf;
            vp->val_len = sizeof(u_long);
            asn_parse_unsigned_int(var_val, &len, &vp->type,
                                   (u_long*) vp->val.integer,
                                   vp->val_len);
            break;
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
        case ASN_OPAQUE_COUNTER64:
        case ASN_OPAQUE_U64:
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
        case ASN_COUNTER64:
            vp->val.counter64 = (struct counter64*) vp->buf;
            vp->val_len = sizeof(struct counter64);
            asn_parse_unsigned_int64(var_val, &len, &vp->type,
                                     (struct counter64*) vp->val.
                                     counter64, vp->val_len);
            break;
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
        case ASN_OPAQUE_FLOAT:
            vp->val.floatVal = (float*) vp->buf;
            vp->val_len = sizeof(float);
            asn_parse_float(var_val, &len, &vp->type,
                            vp->val.floatVal, vp->val_len);
            break;
        case ASN_OPAQUE_DOUBLE:
            vp->val.doubleVal = (double*) vp->buf;
            vp->val_len = sizeof(double);
            asn_parse_double(var_val, &len, &vp->type,
                             vp->val.doubleVal, vp->val_len);
            break;
        case ASN_OPAQUE_I64:
            vp->val.counter64 = (struct counter64*) vp->buf;
            vp->val_len = sizeof(struct counter64);
            asn_parse_signed_int64(var_val, &len, &vp->type,
                                   (struct counter64*) vp->val.counter64,
                                   sizeof(*vp->val.counter64));

            break;
#endif                          /* NETSNMP_WITH_OPAQUE_SPECIAL_TYPES */
        case ASN_OCTET_STR:
        case ASN_IPADDRESS:
        case ASN_OPAQUE:
        case ASN_NSAP:
            if (vp->val_len < sizeof(vp->buf)) {
                vp->val.string = (u_char*) vp->buf;
            } else {
                vp->val.string = (u_char*) malloc(vp->val_len);
            }
            if (vp->val.string == NULL) {
                return -1;
            }
            asn_parse_string(var_val, &len, &vp->type, vp->val.string,
                             &vp->val_len);
            break;
        case ASN_OBJECT_ID:
            vp->val_len = MAX_OID_LEN;
            asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
            vp->val_len *= sizeof(oid);
            vp->val.objid = (oid*) malloc(vp->val_len);
            if (vp->val.objid == NULL) {
                return -1;
            }
            memmove(vp->val.objid, objid, vp->val_len);
            break;
        case SNMP_NOSUCHOBJECT:
        case SNMP_NOSUCHINSTANCE:
        case SNMP_ENDOFMIBVIEW:
        case ASN_NULL:
            break;
        case ASN_BIT_STR:
            vp->val.bitstring = (u_char*) malloc(vp->val_len);
            if (vp->val.bitstring == NULL) {
                return -1;
            }
            asn_parse_bitstring(var_val, &len, &vp->type,
                                vp->val.bitstring, &vp->val_len);
            break;
        default:
            badtype = -1;
            break;
        }
    }
    return badtype;
}

int
NetSnmpAgent::snmpv3_parse(netsnmp_pdu* pdu,
             u_char*  data,
             size_t*  length,
             u_char**  after_header, netsnmp_session*  sess)
{
    u_char          type, msg_flags;
    long            ver, msg_max_size, msg_sec_model;
    size_t          max_size_response;
    u_char          tmp_buf[SNMP_MAX_MSG_SIZE];
    size_t          tmp_buf_len;
    u_char          pdu_buf[SNMP_MAX_MSG_SIZE];
    u_char*         mallocbuf = NULL;
    size_t          pdu_buf_len = SNMP_MAX_MSG_SIZE;
    u_char*         sec_params;
    u_char*         msg_data;
    u_char*         cp;
    size_t          asn_len, msg_len;
    int             ret, ret_val;
    struct snmp_secmod_def* sptr;


    msg_data = data;
    msg_len = *length;


    /*
     * message is an ASN.1 SEQUENCE
     */
    data = asn_parse_sequence(data, length, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR), "message");
    if (data == NULL) {
        /*
         * error msg detail is set
         */
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }

    /*
     * parse msgVersion
     */
    data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
    if (data == NULL) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }
    pdu->version = ver;

    /*
     * parse msgGlobalData sequence
     */
    cp = data;
    asn_len = *length;
    data = asn_parse_sequence(data, &asn_len, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "msgGlobalData");
    if (data == NULL) {
        /*
         * error msg detail is set
         */
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }
    *length -= data - cp;       /* subtract off the length of the header */

    /*
     * msgID
     */
    data =
        asn_parse_int(data, length, &type, &pdu->msgid,
                      sizeof(pdu->msgid));
    if (data == NULL || type != ASN_INTEGER) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }

    /*
     * Check the msgID we received is a legal value.  If not, then increment
     * snmpInASNParseErrs and return the appropriate error (see RFC 2572,
     * para. 7.2, section 2 -- note that a bad msgID means that the received
     * message is NOT a serialiization of an SNMPv3Message, since the msgID
     * field is out of bounds).
     */

    if (pdu->msgid < 0 || pdu->msgid > 0x7fffffff) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }

    /*
     * msgMaxSize
     */
    data = asn_parse_int(data, length, &type, &msg_max_size,
                         sizeof(msg_max_size));
    if (data == NULL || type != ASN_INTEGER) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }

    /*
     * Check the msgMaxSize we received is a legal value.  If not, then
     * increment snmpInASNParseErrs and return the appropriate error (see RFC
     * 2572, para. 7.2, section 2 -- note that a bad msgMaxSize means that the
     * received message is NOT a serialiization of an SNMPv3Message, since the
     * msgMaxSize field is out of bounds).
     *
     * Note we store the msgMaxSize on a per-session basis which also seems
     * reasonable; it could vary from PDU to PDU but that would be strange
     * (also since we deal with a PDU at a time, it wouldn't make any
     * difference to our responses, if any).
     */

    if (msg_max_size < 484) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    } else if (msg_max_size > 0x7fffffff) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    } else {
        sess->sndMsgMaxSize = msg_max_size;
    }

    /*
     * msgFlags
     */
    tmp_buf_len = SNMP_MAX_MSG_SIZE;
    data = asn_parse_string(data, length, &type, tmp_buf, &tmp_buf_len);
    if (data == NULL || type != ASN_OCTET_STR || tmp_buf_len != 1) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }
    msg_flags = *tmp_buf;
    if (msg_flags & SNMP_MSG_FLAG_RPRT_BIT)
        pdu->flags |= SNMP_MSG_FLAG_RPRT_BIT;
    else
        pdu->flags &= (~SNMP_MSG_FLAG_RPRT_BIT);

    /*
     * msgSecurityModel
     */
    data = asn_parse_int(data, length, &type, &msg_sec_model,
                         sizeof(msg_sec_model));
    if (data == NULL || type != ASN_INTEGER ||
        msg_sec_model < 1 || msg_sec_model > 0x7fffffff) {
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
        return SNMPERR_ASN_PARSE_ERR;
    }
    sptr = find_sec_mod(msg_sec_model);
    if (!sptr) {
        snmp_increment_statistic(STAT_SNMPUNKNOWNSECURITYMODELS);
        return SNMPERR_UNKNOWN_SEC_MODEL;
    }
    pdu->securityModel = msg_sec_model;

    if (msg_flags & SNMP_MSG_FLAG_PRIV_BIT &&
        !(msg_flags & SNMP_MSG_FLAG_AUTH_BIT)) {
        snmp_increment_statistic(STAT_SNMPINVALIDMSGS);
        return SNMPERR_INVALID_MSG;
    }
    pdu->securityLevel = ((msg_flags & SNMP_MSG_FLAG_AUTH_BIT)
                          ? ((msg_flags & SNMP_MSG_FLAG_PRIV_BIT)
                             ? SNMP_SEC_LEVEL_AUTHPRIV
                             : SNMP_SEC_LEVEL_AUTHNOPRIV)
                          : SNMP_SEC_LEVEL_NOAUTH);
    /*
     * end of msgGlobalData
     */

    /*
     * securtityParameters OCTET STRING begins after msgGlobalData
     */
    sec_params = data;
    pdu->contextEngineID = (u_char*) calloc(1, SNMP_MAX_ENG_SIZE);
    pdu->contextEngineIDLen = SNMP_MAX_ENG_SIZE;

    /*
     * Note: there is no length limit on the msgAuthoritativeEngineID field,
     * although we would EXPECT it to be limited to 32 (the SnmpEngineID TC
     * limit).  We'll use double that here to be on the safe side.
     */

    pdu->securityEngineID = (u_char*) calloc(1, SNMP_MAX_ENG_SIZE * 2);
    pdu->securityEngineIDLen = SNMP_MAX_ENG_SIZE * 2;
    pdu->securityName = (char*) calloc(1, SNMP_MAX_SEC_NAME_SIZE);
    pdu->securityNameLen = SNMP_MAX_SEC_NAME_SIZE;

    if ((pdu->securityName == NULL) ||
        (pdu->securityEngineID == NULL) ||
        (pdu->contextEngineID == NULL)) {
        return SNMPERR_MALLOC;
    }

    if (pdu_buf_len < msg_len
        && pdu->securityLevel == SNMP_SEC_LEVEL_AUTHPRIV) {
        /*
         * space needed is larger than we have in the default buffer
         */
        mallocbuf = (u_char*) calloc(1, msg_len);
        pdu_buf_len = msg_len;
        cp = mallocbuf;
    } else {
        memset(pdu_buf, 0, pdu_buf_len);
        cp = pdu_buf;
    }

    if (sptr->decode) {
        struct snmp_secmod_incoming_params parms;
        parms.msgProcModel = pdu->msgParseModel;
        parms.maxMsgSize = msg_max_size;
        parms.secParams = sec_params;
        parms.secModel = msg_sec_model;
        parms.secLevel = pdu->securityLevel;
        parms.wholeMsg = msg_data;
        parms.wholeMsgLen = msg_len;
        parms.secEngineID = pdu->securityEngineID;
        parms.secEngineIDLen = &pdu->securityEngineIDLen;
        parms.secName = pdu->securityName;
        parms.secNameLen = &pdu->securityNameLen;
        parms.scopedPdu = &cp;
        parms.scopedPduLen = &pdu_buf_len;
        parms.maxSizeResponse = &max_size_response;
        parms.secStateRef = &pdu->securityStateRef;
        parms.sess = sess;
        parms.pdu = pdu;
        parms.msg_flags = msg_flags;
        ret_val = (this->*sptr->decode) (&parms);
    } else {
        return (-1);
    }

    if (ret_val != SNMPERR_SUCCESS) {
        /*
         * Parse as much as possible -- though I don't see the point? [jbpn].
         */
        if (cp) {
            cp = snmpv3_scopedPDU_parse(pdu, cp, &pdu_buf_len);
        }
        if (cp) {
            snmp_pdu_parse(pdu, cp, &pdu_buf_len);
        }

        if (mallocbuf) {
            SNMP_FREE(mallocbuf);
        }
        return ret_val;
    }

    /*
     * parse plaintext ScopedPDU sequence
     */
    if (strlen((char*)cp) != 0)
    {
        *length = pdu_buf_len;
        data = snmpv3_scopedPDU_parse(pdu, cp, length);
        if (data == NULL) {
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
            if (mallocbuf) {
                SNMP_FREE(mallocbuf);
            }
            return SNMPERR_ASN_PARSE_ERR;
        }


        /*
         * parse the PDU.
         */
        if (after_header != NULL) {
            *after_header = data;
            tmp_buf_len = *length;
        }

        ret = snmp_pdu_parse(pdu, data, length);

        if (after_header != NULL) {
            *length = tmp_buf_len;
        }

        if (ret != SNMPERR_SUCCESS) {
            snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
            if (mallocbuf) {
                SNMP_FREE(mallocbuf);
            }
            return SNMPERR_ASN_PARSE_ERR;
        }
    }
    if (mallocbuf) {
        SNMP_FREE(mallocbuf);
    }
    return SNMPERR_SUCCESS;
}                               /* end snmpv3_parse() */

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
netsnmp_variable_list*
snmp_pdu_add_variable(netsnmp_pdu* pdu,
                      const oid*  name,
                      size_t name_length,
                      u_char type, const void*  value, size_t len)
{
    return snmp_varlist_add_variable(&pdu->variables, name, name_length,
                                     type, value, len);
}

/*
 * SNMPv3
 * * Takes a session and a pdu and serializes the ASN PDU into the area
 * * pointed to by packet.  out_length is the size of the data area available.
 * * Returns the length of the completed packet in out_length.  If any errors
 * * occur, -1 is returned.  If all goes well, 0 is returned.
 */
int
NetSnmpAgent::snmpv3_build(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
             netsnmp_session*  session, netsnmp_pdu* pdu)
{
    int             ret;

    session->s_snmp_errno = 0;
    session->s_errno = 0;

    /*
     * do validation for PDU types
     */
    switch (pdu->command) {
    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_REPORT:
        /*
         * Fallthrough
         */
    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_SET:
    case SNMP_MSG_INFORM:
        if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
            pdu->errstat = 0;
        if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
            pdu->errindex = 0;
        break;

    case SNMP_MSG_GETBULK:
        if (pdu->max_repetitions < 0) {
            session->s_snmp_errno = SNMPERR_BAD_REPETITIONS;
            return -1;
        }
        if (pdu->non_repeaters < 0) {
            session->s_snmp_errno = SNMPERR_BAD_REPEATERS;
            return -1;
        }
        break;

    case SNMP_MSG_TRAP:
        session->s_snmp_errno = SNMPERR_V1_IN_V2;
        return -1;

    default:
        session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
        return -1;
    }

    /* Do we need to set the session security engineid? */
    if (pdu->securityEngineIDLen == 0) {
        if (session->securityEngineIDLen) {
            snmpv3_clone_engineID(&pdu->securityEngineID,
                                  &pdu->securityEngineIDLen,
                                  session->securityEngineID,
                                  session->securityEngineIDLen);
        }
    }

    /* Do we need to set the session context engineid? */
    if (pdu->contextEngineIDLen == 0) {
        if (session->contextEngineIDLen) {
            snmpv3_clone_engineID(&pdu->contextEngineID,
                                  &pdu->contextEngineIDLen,
                                  session->contextEngineID,
                                  session->contextEngineIDLen);
        } else if (pdu->securityEngineIDLen) {
            snmpv3_clone_engineID(&pdu->contextEngineID,
                                  &pdu->contextEngineIDLen,
                                  pdu->securityEngineID,
                                  pdu->securityEngineIDLen);
        }
    }

    if (pdu->contextName == NULL) {
        if (!session->contextName) {
            session->s_snmp_errno = SNMPERR_BAD_CONTEXT;
            return -1;
        }
        pdu->contextName = strdup(session->contextName);
        if (pdu->contextName == NULL) {
            session->s_snmp_errno = SNMPERR_GENERR;
            return -1;
        }
        pdu->contextNameLen = session->contextNameLen;
    }
    if (pdu->securityNameLen == 0 && pdu->securityName == NULL) {
        if (session->securityModel != NETSNMP_TSM_SECURITY_MODEL &&
            session->securityNameLen == 0) {
            session->s_snmp_errno = SNMPERR_BAD_SEC_NAME;
            return -1;
        }
        if (session->securityName) {
            pdu->securityName = strdup(session->securityName);
            if (pdu->securityName == NULL) {
                session->s_snmp_errno = SNMPERR_GENERR;
                return -1;
            }
            pdu->securityNameLen = session->securityNameLen;
        }
    }
    if (pdu->securityLevel == 0) {
        if (session->securityLevel == 0) {
            session->s_snmp_errno = SNMPERR_BAD_SEC_LEVEL;
            return -1;
        }
        pdu->securityLevel = session->securityLevel;
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_REVERSE_ENCODE)) {
        ret = snmpv3_packet_realloc_rbuild(pkt, pkt_len, offset,
                                           session, pdu, NULL, 0);
    } else {
        ret = snmpv3_packet_build(session, pdu, *pkt, pkt_len, NULL, 0);
    }

    if (-1 != ret) {
        session->s_snmp_errno = ret;
    }

    return ret;

}                               /* end snmpv3_build() */

/*
 * on error, returns NULL (likely an encoding problem).
 */
u_char*
NetSnmpAgent::snmp_pdu_build(netsnmp_pdu* pdu, u_char*  cp, size_t*  out_length)
{
    u_char*         h1, *h1e, *h2, *h2e;
    netsnmp_variable_list* vp;
    size_t          length;

    length = *out_length;
    /*
     * Save current location and build PDU tag and length placeholder
     * (actual length will be inserted later)
     */
    h1 = cp;
    cp = asn_build_sequence(cp, out_length, (u_char) pdu->command, 0);
    if (cp == NULL)
        return NULL;
    h1e = cp;

    /*
     * store fields in the PDU preceeding the variable-bindings sequence
     */
    if (pdu->command != SNMP_MSG_TRAP) {
        /*
         * PDU is not an SNMPv1 trap
         */

        /*
         * request id
         */
        cp = asn_build_int(cp, out_length,
                           (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                     ASN_INTEGER), &pdu->reqid,
                           sizeof(pdu->reqid));
        if (cp == NULL)
            return NULL;

        /*
         * error status (getbulk non-repeaters)
         */
        cp = asn_build_int(cp, out_length,
                           (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                     ASN_INTEGER), &pdu->errstat,
                           sizeof(pdu->errstat));
        if (cp == NULL)
            return NULL;

        /*
         * error index (getbulk max-repetitions)
         */
        cp = asn_build_int(cp, out_length,
                           (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                     ASN_INTEGER), &pdu->errindex,
                           sizeof(pdu->errindex));
        if (cp == NULL)
            return NULL;
    } else {
        /*
         * an SNMPv1 trap PDU
         */

        /*
         * enterprise
         */
        cp = asn_build_objid(cp, out_length,
                             (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                       ASN_OBJECT_ID),
                             (oid*) pdu->enterprise,
                             pdu->enterprise_length);
        if (cp == NULL)
            return NULL;

        /*
         * agent-addr
         */
        cp = asn_build_string(cp, out_length,
                              (u_char) (ASN_IPADDRESS | ASN_PRIMITIVE),
                              (u_char*) pdu->agent_addr, 4);
        if (cp == NULL)
            return NULL;

        /*
         * generic trap
         */
        cp = asn_build_int(cp, out_length,
                           (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                     ASN_INTEGER),
                           (long*) &pdu->trap_type,
                           sizeof(pdu->trap_type));
        if (cp == NULL)
            return NULL;

        /*
         * specific trap
         */
        cp = asn_build_int(cp, out_length,
                           (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                     ASN_INTEGER),
                           (long*) &pdu->specific_type,
                           sizeof(pdu->specific_type));
        if (cp == NULL)
            return NULL;

        /*
         * timestamp
         */
        cp = asn_build_unsigned_int(cp, out_length,
                                    (u_char) (ASN_TIMETICKS |
                                              ASN_PRIMITIVE), &pdu->time,
                                    sizeof(pdu->time));
        if (cp == NULL)
            return NULL;
    }

    /*
     * Save current location and build SEQUENCE tag and length placeholder
     * for variable-bindings sequence
     * (actual length will be inserted later)
     */
    h2 = cp;
    cp = asn_build_sequence(cp, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (cp == NULL)
        return NULL;
    h2e = cp;

    /*
     * Store variable-bindings
     */
    for (vp = pdu->variables; vp; vp = vp->next_variable) {
        cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type,
                               vp->val_len, (u_char*) vp->val.string,
                               out_length);
        if (cp == NULL)
            return NULL;
    }

    /*
     * insert actual length of variable-bindings sequence
     */
    asn_build_sequence(h2, &length,
                       (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                       cp - h2e);

    /*
     * insert actual length of PDU sequence
     */
    asn_build_sequence(h1, &length, (u_char) pdu->command, cp - h1e);

    return cp;
}

/*
 * snmp v3 utility function to parse into the scopedPdu. stores contextName
 * and contextEngineID in pdu struct. Also stores pdu->command (handy for
 * Report generation).
 *
 * returns pointer to begining of PDU or NULL on error.
 */
u_char*
snmpv3_scopedPDU_parse(netsnmp_pdu* pdu, u_char*  cp, size_t*  length)
{
    u_char          tmp_buf[SNMP_MAX_MSG_SIZE];
    size_t          tmp_buf_len;
    u_char          type;
    size_t          asn_len;
    u_char*         data;

    pdu->command = 0;           /* initialize so we know if it got parsed */
    asn_len = *length;
    data = asn_parse_sequence(cp, &asn_len, &type,
                              (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                              "plaintext scopedPDU");
    if (data == NULL) {
        return NULL;
    }
    *length -= data - cp;

    /*
     * contextEngineID from scopedPdu
     */
    data = asn_parse_string(data, length, &type, pdu->contextEngineID,
                            &pdu->contextEngineIDLen);
    if (data == NULL) {
        return NULL;
    }

    /*
     * check that it agrees with engineID returned from USM above
     * * only a warning because this could be legal if we are a proxy
     */
    if (pdu->securityEngineIDLen != pdu->contextEngineIDLen ||
        memcmp(pdu->securityEngineID, pdu->contextEngineID,
               pdu->securityEngineIDLen) != 0) {
    }

    /*
     * parse contextName from scopedPdu
     */
    tmp_buf_len = SNMP_MAX_CONTEXT_SIZE;
    data = asn_parse_string(data, length, &type, tmp_buf, &tmp_buf_len);
    if (data == NULL) {
        return NULL;
    }

    if (tmp_buf_len) {
        pdu->contextName = (char*) malloc(tmp_buf_len);
        memmove(pdu->contextName, tmp_buf, tmp_buf_len);
        pdu->contextNameLen = tmp_buf_len;
    } else {
        pdu->contextName = strdup("");
        pdu->contextNameLen = 0;
    }
    if (pdu->contextName == NULL) {
        return NULL;
    }

    /*
     * Get the PDU type
     */
    asn_len = *length;
    cp = asn_parse_header(data, &asn_len, &type);
    if (cp == NULL)
        return NULL;

    pdu->command = type;

    return data;
}

/*
 * returns 0 if success, -1 if fail, not 0 if SM build failure
 */
int
NetSnmpAgent::snmpv3_packet_build(netsnmp_session*  session, netsnmp_pdu* pdu,
                    u_char*  packet, size_t*  out_length,
                    u_char*  pdu_data, size_t pdu_data_len)
{
    u_char*         global_data, *sec_params, *spdu_hdr_e;
    size_t          global_data_len, sec_params_len;
    u_char          spdu_buf[SNMP_MAX_MSG_SIZE];
    size_t          spdu_buf_len, spdu_len;
    u_char*         cp;
    int             result;
    struct snmp_secmod_def* sptr;

    global_data = packet;

    /*
     * build the headers for the packet, returned addr = start of secParams
     */
    sec_params = snmpv3_header_build(session, pdu, global_data,
                                     out_length, 0, NULL);
    if (sec_params == NULL)
        return -1;
    global_data_len = sec_params - global_data;
    sec_params_len = *out_length;       /* length left in packet buf for sec_params */


    /*
     * build a scopedPDU structure into spdu_buf
     */
    spdu_buf_len = SNMP_MAX_MSG_SIZE;
    cp = snmpv3_scopedPDU_header_build(pdu, spdu_buf, &spdu_buf_len,
                                       &spdu_hdr_e);
    if (cp == NULL)
        return -1;

    /*
     * build the PDU structure onto the end of spdu_buf
     */
    if (pdu_data) {
        memcpy(cp, pdu_data, pdu_data_len);
        cp += pdu_data_len;
    } else {
        cp = snmp_pdu_build(pdu, cp, &spdu_buf_len);
        if (cp == NULL)
            return -1;
    }

    /*
     * re-encode the actual ASN.1 length of the scopedPdu
     */
    spdu_len = cp - spdu_hdr_e; /* length of scopedPdu minus ASN.1 headers */
    spdu_buf_len = SNMP_MAX_MSG_SIZE;
    if (asn_build_sequence(spdu_buf, &spdu_buf_len,
                           (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           spdu_len) == NULL)
        return -1;
    spdu_len = cp - spdu_buf;   /* the length of the entire scopedPdu */


    /*
     * call the security module to possibly encrypt and authenticate the
     * message - the entire message to transmitted on the wire is returned
     */
    cp = NULL;
    *out_length = SNMP_MAX_MSG_SIZE;
    sptr = find_sec_mod(pdu->securityModel);
    if (sptr && sptr->encode_forward) {
        struct snmp_secmod_outgoing_params parms;
        parms.msgProcModel = pdu->msgParseModel;
        parms.globalData = global_data;
        parms.globalDataLen = global_data_len;
        parms.maxMsgSize = SNMP_MAX_MSG_SIZE;
        parms.secModel = pdu->securityModel;
        parms.secEngineID = pdu->securityEngineID;
        parms.secEngineIDLen = pdu->securityEngineIDLen;
        parms.secName = pdu->securityName;
        parms.secNameLen = pdu->securityNameLen;
        parms.secLevel = pdu->securityLevel;
        parms.scopedPdu = spdu_buf;
        parms.scopedPduLen = spdu_len;
        parms.secStateRef = pdu->securityStateRef;
        parms.secParams = sec_params;
        parms.secParamsLen = &sec_params_len;
        parms.wholeMsg = &cp;
        parms.wholeMsgLen = out_length;
        parms.session = session;
        parms.pdu = pdu;
        result = (this->*sptr->encode_forward) (&parms);
    } else {
        result = -1;
    }
    return result;

}                               /* end snmpv3_packet_build() */

u_char*
NetSnmpAgent::snmpv3_header_build(netsnmp_session*  session, netsnmp_pdu* pdu,
                    u_char*  packet, size_t*  out_length,
                    size_t length, u_char**  msg_hdr_e)
{
    u_char*         global_hdr, *global_hdr_e;
    u_char*         cp;
    u_char          msg_flags;
    long            max_size;
    long            sec_model;
    u_char*         pb, *pb0e;

    /*
     * Save current location and build SEQUENCE tag and length placeholder
     * * for SNMP message sequence (actual length inserted later)
     */
    cp = asn_build_sequence(packet, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            length);
    if (cp == NULL)
        return NULL;
    if (msg_hdr_e != NULL)
        *msg_hdr_e = cp;
    pb0e = cp;


    /*
     * store the version field - msgVersion
     */
    cp = asn_build_int(cp, out_length,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                 ASN_INTEGER), (long*) &pdu->version,
                       sizeof(pdu->version));
    if (cp == NULL)
        return NULL;

    global_hdr = cp;
    /*
     * msgGlobalData HeaderData
     */
    cp = asn_build_sequence(cp, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (cp == NULL)
        return NULL;
    global_hdr_e = cp;


    /*
     * msgID
     */
    cp = asn_build_int(cp, out_length,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                 ASN_INTEGER), &pdu->msgid,
                       sizeof(pdu->msgid));
    if (cp == NULL)
        return NULL;

    /*
     * msgMaxSize
     */
    max_size = session->rcvMsgMaxSize;
    cp = asn_build_int(cp, out_length,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                 ASN_INTEGER), &max_size,
                       sizeof(max_size));
    if (cp == NULL)
        return NULL;

    /*
     * msgFlags
     */
    snmpv3_calc_msg_flags(pdu->securityLevel, pdu->command, &msg_flags);
    cp = asn_build_string(cp, out_length,
                          (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                    ASN_OCTET_STR), &msg_flags,
                          sizeof(msg_flags));
    if (cp == NULL)
        return NULL;

    /*
     * msgSecurityModel
     */
    sec_model = pdu->securityModel;
    cp = asn_build_int(cp, out_length,
                       (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                 ASN_INTEGER), &sec_model,
                       sizeof(sec_model));
    if (cp == NULL)
        return NULL;


    /*
     * insert actual length of globalData
     */
    pb = asn_build_sequence(global_hdr, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            cp - global_hdr_e);
    if (pb == NULL)
        return NULL;


    /*
     * insert the actual length of the entire packet
     */
    pb = asn_build_sequence(packet, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            length + (cp - pb0e));
    if (pb == NULL)
        return NULL;

    return cp;

}                               /* end snmpv3_header_build() */

u_char*
NetSnmpAgent::snmpv3_scopedPDU_header_build(netsnmp_pdu* pdu,
                              u_char*  packet, size_t*  out_length,
                              u_char**  spdu_e)
{
    size_t          init_length;
    u_char*         scopedPdu, *pb;


    init_length = *out_length;

    pb = scopedPdu = packet;
    pb = asn_build_sequence(pb, out_length,
                            (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (pb == NULL)
        return NULL;
    if (spdu_e)
        *spdu_e = pb;

    pb = asn_build_string(pb, out_length,
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                          pdu->contextEngineID, pdu->contextEngineIDLen);
    if (pb == NULL)
        return NULL;

    pb = asn_build_string(pb, out_length,
                          (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                          (u_char*) pdu->contextName,
                          pdu->contextNameLen);
    if (pb == NULL)
        return NULL;

    return pb;

}                               /* end snmpv3_scopedPDU_header_build() */

static void
snmpv3_calc_msg_flags(int sec_level, int msg_command, u_char*  flags)
{
    *flags = 0;
    if (sec_level == SNMP_SEC_LEVEL_AUTHNOPRIV)
        *flags = SNMP_MSG_FLAG_AUTH_BIT;
    else if (sec_level == SNMP_SEC_LEVEL_AUTHPRIV)
        *flags = SNMP_MSG_FLAG_AUTH_BIT | SNMP_MSG_FLAG_PRIV_BIT;

    if (SNMP_CMD_CONFIRMED(msg_command))
        *flags |= SNMP_MSG_FLAG_RPRT_BIT;

    return;
}

const char*
snmp_pdu_type(int type)
{
    static char unknown[20];
    switch(type) {
    case SNMP_MSG_GET:
        return "GET";
    case SNMP_MSG_GETNEXT:
        return "GETNEXT";
    case SNMP_MSG_RESPONSE:
        return "RESPONSE";
    case SNMP_MSG_SET:
        return "SET";
    case SNMP_MSG_GETBULK:
        return "GETBULK";
    case SNMP_MSG_INFORM:
        return "INFORM";
    case SNMP_MSG_TRAP2:
        return "TRAP2";
    case SNMP_MSG_REPORT:
        return "REPORT";
    default:
        snprintf(unknown, sizeof(unknown), "?0x%2X?", type);
    return unknown;
    }
}

int
NetSnmpAgent::snmp_close(netsnmp_session*  session)
{
    struct snmp_session_list* slp = NULL, *oslp = NULL;

    {                           /*MTCRITICAL_RESOURCE */
        snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);
        if (Sessions && Sessions->session == session) { /* If first entry */
            slp = Sessions;
            Sessions = slp->next;
        } else {
            for (slp = Sessions; slp; slp = slp->next) {
                if (slp->session == session) {
                    if (oslp)   /* if we found entry that points here */
                        oslp->next = slp->next; /* link around this entry */
                    break;
                }
                oslp = slp;
            }
        }
        snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);
    }                           /*END MTCRITICAL_RESOURCE */
    if (slp == NULL) {
        return 0;
    }
    return snmp_sess_close((void*) slp);
}


int
NetSnmpAgent::snmp_sess_select_info2(void* sessp, int* block)
{
    struct snmp_session_list* slptest = (struct snmp_session_list*) sessp;
    struct snmp_session_list* slp, *next = NULL;
    netsnmp_request_list* rp;
    struct timeval  now, earliest, delta = {0, 0};
    int             active = 0, requests = 0;
    int             next_alarm = 0;


    timerclear(&earliest);

    /*
     * For each request outstanding, add its socket to the fdset,
     * and if it is the earliest timeout to expire, mark it as lowest.
     * If a single session is specified, do just for that session.
     */

    if (sessp) {
        slp = slptest;
    } else {
        slp = Sessions;
    }

    for (; slp; slp = next) {
        next = slp->next;

        if (slp->transport == NULL) {
            /*
             * Close in progress -- skip this one.
             */
            continue;
        }

        if (slp->transport->sock == -1) {
            /*
             * This session was marked for deletion.
             */
            if (sessp == NULL) {
                snmp_close(slp->session);
            } else {
                snmp_sess_close(slp);
            }
            continue;
        }

        if (slp->internal != NULL && slp->internal->requests) {
            /*
             * Found another session with outstanding requests.
             */
            requests++;
            for (rp = slp->internal->requests; rp; rp = rp->next_request) {
                if ((!timerisset(&earliest)
                     || (timercmp(&rp->expire, &earliest, <)))) {
                    earliest = rp->expire;
                }
            }
        }

        active++;
        if (sessp) {
            /*
             * Single session processing.
             */
            break;
        }
    }

    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_ALARM_DONT_USE_SIG)) {
        next_alarm = get_next_alarm_delay_time(&delta);
    }
    if (next_alarm == 0 && requests == 0) {
        /*
         * If none are active, skip arithmetic.
         */
        *block = 1; /* can block - timeout value is undefined if no requests */
        return active;
    }

    /*
     * * Now find out how much time until the earliest timeout.  This
     * * transforms earliest from an absolute time into a delta time, the
     * * time left until the select should timeout.
     */
    now = convert_2_timeval(this->node->getNodeTime());
    if (next_alarm) {
        delta.tv_sec += now.tv_sec;
        delta.tv_usec += now.tv_usec;
        while (delta.tv_usec >= 1000000) {
            delta.tv_usec -= 1000000;
            delta.tv_sec += 1;
        }
        if (!timerisset(&earliest) ||
            ((earliest.tv_sec > delta.tv_sec) ||
             ((earliest.tv_sec == delta.tv_sec) &&
              (earliest.tv_usec > delta.tv_usec)))) {
            earliest.tv_sec = delta.tv_sec;
            earliest.tv_usec = delta.tv_usec;
        }
    }

    if (earliest.tv_sec < now.tv_sec) {
        earliest.tv_sec = 0;
        earliest.tv_usec = 0;
    } else if (earliest.tv_sec == now.tv_sec) {
        earliest.tv_sec = 0;
        earliest.tv_usec = (earliest.tv_usec - now.tv_usec);
        if (earliest.tv_usec < 0) {
            earliest.tv_usec = 100;
        }
    } else {
        earliest.tv_sec = (earliest.tv_sec - now.tv_sec);
        earliest.tv_usec = (earliest.tv_usec - now.tv_usec);
        if (earliest.tv_usec < 0) {
            earliest.tv_sec--;
            earliest.tv_usec = (1000000L + earliest.tv_usec);
        }
    }

    return active;
}

long
NetSnmpAgent::snmp_get_next_transid(void)
{
    long            retVal;
    snmp_res_lock(MT_LIBRARY_ID, MT_LIB_TRANSID);
    retVal = 1 + Transid;       /*MTCRITICAL_RESOURCE */
    if (!retVal)
        retVal = 2;
    Transid = retVal;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_16BIT_IDS))
        retVal &= 0x7fff;    /* mask to 15 bits */
    else
        retVal &= 0x7fffffff;    /* mask to 31 bits */

    if (!retVal) {
        Transid = retVal = 2;
    }
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_TRANSID);
    return retVal;
}

/*
 * returns 0 if success, -1 if fail, not 0 if SM build failure
 */
int
NetSnmpAgent::snmpv3_packet_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                             size_t*  offset, netsnmp_session*  session,
                             netsnmp_pdu* pdu, u_char*  pdu_data,
                             size_t pdu_data_len)
{
    u_char*         scoped_pdu, *hdrbuf = NULL, *hdr = NULL;
    size_t          hdrbuf_len = SNMP_MAX_MSG_V3_HDRS, hdr_offset =
        0, spdu_offset = 0;
    size_t          body_end_offset = *offset, body_len = 0;
    struct snmp_secmod_def* sptr = NULL;
    int             rc = 0;

    /*
     * Build a scopedPDU structure into the packet buffer.
     */
    if (pdu_data) {
        while ((*pkt_len - *offset) < pdu_data_len) {
            if (!asn_realloc(pkt, pkt_len)) {
                return -1;
            }
        }

        *offset += pdu_data_len;
        memcpy(*pkt + *pkt_len - *offset, pdu_data, pdu_data_len);
    } else {
        rc = snmp_pdu_realloc_rbuild(pkt, pkt_len, offset, pdu);
        if (rc == 0) {
            return -1;
        }
    }
    body_len = *offset - body_end_offset;

    rc = snmpv3_scopedPDU_header_realloc_rbuild(pkt, pkt_len, offset,
                                                pdu, body_len);
    if (rc == 0) {
        return -1;
    }
    spdu_offset = *offset;

    if ((hdrbuf = (u_char*) malloc(hdrbuf_len)) == NULL) {
        return -1;
    }

    rc = snmpv3_header_realloc_rbuild(&hdrbuf, &hdrbuf_len, &hdr_offset,
                                      session, pdu);
    if (rc == 0) {
        SNMP_FREE(hdrbuf);
        return -1;
    }
    hdr = hdrbuf + hdrbuf_len - hdr_offset;
    scoped_pdu = *pkt + *pkt_len - spdu_offset;

    /*
     * Call the security module to possibly encrypt and authenticate the
     * message---the entire message to transmitted on the wire is returned.
     */

    sptr = find_sec_mod(pdu->securityModel);
    if (sptr && sptr->encode_reverse) {
        struct snmp_secmod_outgoing_params parms;

        parms.msgProcModel = pdu->msgParseModel;
        parms.globalData = hdr;
        parms.globalDataLen = hdr_offset;
        parms.maxMsgSize = SNMP_MAX_MSG_SIZE;
        parms.secModel = pdu->securityModel;
        parms.secEngineID = pdu->securityEngineID;
        parms.secEngineIDLen = pdu->securityEngineIDLen;
        parms.secName = pdu->securityName;
        parms.secNameLen = pdu->securityNameLen;
        parms.secLevel = pdu->securityLevel;
        parms.scopedPdu = scoped_pdu;
        parms.scopedPduLen = spdu_offset;
        parms.secStateRef = pdu->securityStateRef;
        parms.wholeMsg = pkt;
        parms.wholeMsgLen = pkt_len;
        parms.wholeMsgOffset = offset;
        parms.session = session;
        parms.pdu = pdu;

        rc = (this->*(sptr->encode_reverse))(&parms);
    } else {
        rc = -1;
    }

    SNMP_FREE(hdrbuf);
    return rc;
}                               /* end snmpv3_packet_realloc_rbuild() */

/*
 * On error, returns 0 (likely an encoding problem).
 */
int
NetSnmpAgent::snmp_pdu_realloc_rbuild(u_char**  pkt, size_t*  pkt_len, size_t*  offset,
                        netsnmp_pdu* pdu)
{
#ifndef VPCACHE_SIZE
#define VPCACHE_SIZE 50
#endif
    netsnmp_variable_list* vpcache[VPCACHE_SIZE];
    netsnmp_variable_list* vp, *tmpvp;
    size_t          start_offset = *offset;
    int             i, wrapped = 0, notdone, final, rc = 0;

    for (vp = pdu->variables, i = VPCACHE_SIZE - 1; vp;
         vp = vp->next_variable, i--) {
        if (i < 0) {
            wrapped = notdone = 1;
            i = VPCACHE_SIZE - 1;
        }
        vpcache[i] = vp;
    }
    final = i + 1;

    do {
        for (i = final; i < VPCACHE_SIZE; i++) {
            vp = vpcache[i];
            rc = snmp_realloc_rbuild_var_op(pkt, pkt_len, offset, 1,
                                            vp->name, &vp->name_length,
                                            vp->type,
                                            (u_char*) vp->val.string,
                                            vp->val_len);
            if (rc == 0) {
                return 0;
            }
        }

        if (wrapped) {
            notdone = 1;
            for (i = 0; i < final; i++) {
                vp = vpcache[i];
                rc = snmp_realloc_rbuild_var_op(pkt, pkt_len, offset, 1,
                                                vp->name, &vp->name_length,
                                                vp->type,
                                                (u_char*) vp->val.string,
                                                vp->val_len);
                if (rc == 0) {
                    return 0;
                }
            }

            if (final == 0) {
                tmpvp = vpcache[VPCACHE_SIZE - 1];
            } else {
                tmpvp = vpcache[final - 1];
            }
            wrapped = 0;

            for (vp = pdu->variables, i = VPCACHE_SIZE - 1;
                 vp && vp != tmpvp; vp = vp->next_variable, i--) {
                if (i < 0) {
                    wrapped = 1;
                    i = VPCACHE_SIZE - 1;
                }
                vpcache[i] = vp;
            }
            final = i + 1;
        } else {
            notdone = 0;
        }
    } while (notdone);

    /*
     * Save current location and build SEQUENCE tag and length placeholder for
     * variable-bindings sequence (actual length will be inserted later).
     */

    rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                     (u_char) (ASN_SEQUENCE |
                                               ASN_CONSTRUCTOR),
                                     *offset - start_offset);

    /*
     * Store fields in the PDU preceeding the variable-bindings sequence.
     */
    if (pdu->command != SNMP_MSG_TRAP) {
        /*
         * Error index (getbulk max-repetitions).
         */
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                              | ASN_INTEGER),
                                    &pdu->errindex, sizeof(pdu->errindex));
        if (rc == 0) {
            return 0;
        }

        /*
         * Error status (getbulk non-repeaters).
         */
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                              | ASN_INTEGER),
                                    &pdu->errstat, sizeof(pdu->errstat));
        if (rc == 0) {
            return 0;
        }

        /*
         * Request ID.
         */
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                              | ASN_INTEGER), &pdu->reqid,
                                    sizeof(pdu->reqid));
        if (rc == 0) {
            return 0;
        }
    } else {
        /*
         * An SNMPv1 trap PDU.
         */

        /*
         * Timestamp.
         */
        rc = asn_realloc_rbuild_unsigned_int(pkt, pkt_len, offset, 1,
                                             (u_char) (ASN_TIMETICKS |
                                                       ASN_PRIMITIVE),
                                             &pdu->time,
                                             sizeof(pdu->time));
        if (rc == 0) {
            return 0;
        }

        /*
         * Specific trap.
         */
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                              | ASN_INTEGER),
                                    (long*) &pdu->specific_type,
                                    sizeof(pdu->specific_type));
        if (rc == 0) {
            return 0;
        }

        /*
         * Generic trap.
         */
        rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                    (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                              | ASN_INTEGER),
                                    (long*) &pdu->trap_type,
                                    sizeof(pdu->trap_type));
        if (rc == 0) {
            return 0;
        }

        /*
         * Agent-addr.
         */
        rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                                       (u_char) (ASN_IPADDRESS |
                                                 ASN_PRIMITIVE),
                                       (u_char*) pdu->agent_addr, 4);
        if (rc == 0) {
            return 0;
        }

        /*
         * Enterprise.
         */
        rc = asn_realloc_rbuild_objid(pkt, pkt_len, offset, 1,
                                      (u_char) (ASN_UNIVERSAL |
                                                ASN_PRIMITIVE |
                                                ASN_OBJECT_ID),
                                      (oid*) pdu->enterprise,
                                      pdu->enterprise_length);
        if (rc == 0) {
            return 0;
        }
    }

    /*
     * Build the PDU sequence.
     */
    rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                     (u_char) pdu->command,
                                     *offset - start_offset);
    return rc;
}

int
NetSnmpAgent::snmpv3_scopedPDU_header_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                                       size_t*  offset, netsnmp_pdu* pdu,
                                       size_t body_len)
{
    size_t          start_offset = *offset;
    int             rc = 0;

    /*
     * contextName.
     */
    rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                                   (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                             | ASN_OCTET_STR),
                                   (u_char*) pdu->contextName,
                                   pdu->contextNameLen);
    if (rc == 0) {
        return 0;
    }

    /*
     * contextEngineID.
     */
    rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                                   (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                             | ASN_OCTET_STR),
                                   pdu->contextEngineID,
                                   pdu->contextEngineIDLen);
    if (rc == 0) {
        return 0;
    }

    rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                     (u_char) (ASN_SEQUENCE |
                                               ASN_CONSTRUCTOR),
                                     *offset - start_offset + body_len);

    return rc;
}

int
NetSnmpAgent::snmpv3_header_realloc_rbuild(u_char**  pkt, size_t*  pkt_len,
                             size_t*  offset, netsnmp_session*  session,
                             netsnmp_pdu* pdu)
{
    size_t          start_offset = *offset;
    u_char          msg_flags;
    long            max_size, sec_model;
    int             rc = 0;

    /*
     * msgSecurityModel.
     */
    sec_model = pdu->securityModel;
    rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                          ASN_INTEGER), &sec_model,
                                sizeof(sec_model));
    if (rc == 0) {
        return 0;
    }

    /*
     * msgFlags.
     */
    snmpv3_calc_msg_flags(pdu->securityLevel, pdu->command, &msg_flags);
    rc = asn_realloc_rbuild_string(pkt, pkt_len, offset, 1,
                                   (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE
                                             | ASN_OCTET_STR), &msg_flags,
                                   sizeof(msg_flags));
    if (rc == 0) {
        return 0;
    }

    /*
     * msgMaxSize.
     */
    max_size = session->rcvMsgMaxSize;
    rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                          ASN_INTEGER), &max_size,
                                sizeof(max_size));
    if (rc == 0) {
        return 0;
    }

    /*
     * msgID.
     */
    rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                          ASN_INTEGER), &pdu->msgid,
                                sizeof(pdu->msgid));
    if (rc == 0) {
        return 0;
    }

    /*
     * Global data sequence.
     */
    rc = asn_realloc_rbuild_sequence(pkt, pkt_len, offset, 1,
                                     (u_char) (ASN_SEQUENCE |
                                               ASN_CONSTRUCTOR),
                                     *offset - start_offset);
    if (rc == 0) {
        return 0;
    }

    /*
     * Store the version field - msgVersion.
     */
    rc = asn_realloc_rbuild_int(pkt, pkt_len, offset, 1,
                                (u_char) (ASN_UNIVERSAL | ASN_PRIMITIVE |
                                          ASN_INTEGER),
                                (long*) &pdu->version,
                                sizeof(pdu->version));
    return rc;
}                               /* end snmpv3_header_realloc_rbuild() */

int
NetSnmpAgent::sendResponse(char* response, int length)
{
#ifdef SNMP_DEBUG
    printf("sendResponse:Sending Response from node %d source_port:%d\n",node->nodeId,
        node->netSnmpAgent->info->sourcePort);
#endif
    Address sourceAddr;
    NetworkGetInterfaceInfo(node, 
                            node->netSnmpAgent->info->
                            incomingInterfaceIndex,
                            &sourceAddr);
    Message *udpmsg = APP_UdpCreateMessage(
        node,
        GetIPv4Address(sourceAddr),
        (short) APP_SNMP_AGENT,
        this->node->managerAddress,
        node->netSnmpAgent->info->sourcePort,
        TRACE_SNMP);

    APP_AddPayload(node, udpmsg, response, length);

    APP_UdpSend(node, udpmsg);

    return 1;
}


/*
 * Initializes the session structure.
 * May perform one time minimal library initialization.
 * No MIB file processing is done via this call.
 */
void
NetSnmpAgent::snmp_sess_init(netsnmp_session*  session)
{
    _init_snmp();

    /*
     * initialize session to default values
     */

    memset(session, 0, sizeof(netsnmp_session));
    session->remote_port = SNMP_DEFAULT_REMPORT;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    session->retries = SNMP_DEFAULT_RETRIES;
    session->version = SNMP_DEFAULT_VERSION;
    session->securityModel = SNMP_DEFAULT_SECMODEL;
    session->rcvMsgMaxSize = SNMP_MAX_MSG_SIZE;
    session->flags |= SNMP_FLAGS_DONT_PROBE;
}


netsnmp_session*
NetSnmpAgent::snmp_add_full(netsnmp_session*  in_session,
              netsnmp_transport* transport,
              int (NetSnmpAgent::*fpre_parse) (netsnmp_session* , netsnmp_transport* ,
                                 void* , int),
              int (NetSnmpAgent::*fparse) (netsnmp_session* , netsnmp_pdu* , u_char* ,
                             size_t),
              int (NetSnmpAgent::*fpost_parse) (netsnmp_session* , netsnmp_pdu* , int),
              int (NetSnmpAgent::*fbuild) (netsnmp_session* , netsnmp_pdu* , u_char* ,
                             size_t*), int (NetSnmpAgent::*frbuild) (netsnmp_session* ,
                                                        netsnmp_pdu* ,
                                                        u_char** ,
                                                        size_t* ,
                                                        size_t*),
              int (NetSnmpAgent::*fcheck) (u_char* , size_t),
              netsnmp_pdu* (NetSnmpAgent::*fcreate_pdu) (netsnmp_transport* , void* ,
                                           size_t))
{
    struct snmp_session_list* slp;
    slp = (struct snmp_session_list*) snmp_sess_add_ex(in_session, transport,
                                                   fpre_parse, fparse,
                                                   fpost_parse, fbuild,
                                                   frbuild, fcheck,
                                                   fcreate_pdu);
    if (slp == NULL) {
        return NULL;
    }

    snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);
    slp->next = Sessions;
    Sessions = slp;
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);

    return (slp->session);
}

/*
 * These functions send PDUs using an active session:
 * snmp_send             - traditional API, no callback
 * snmp_async_send       - traditional API, with callback
 * snmp_sess_send        - single session API, no callback
 * snmp_sess_async_send  - single session API, with callback
 *
 * Call snmp_build to create a serialized packet (the pdu).
 * If necessary, set some of the pdu data from the
 * session defaults.
 * If there is an expected response for this PDU,
 * queue a corresponding request on the list
 * of outstanding requests for this session,
 * and store the callback vectors in the request.
 *
 * Send the pdu to the target identified by this session.
 * Return on success:
 *   The request id of the pdu is returned, and the pdu is freed.
 * Return on failure:
 *   Zero (0) is returned.
 *   The caller must call snmp_free_pdu if 0 is returned.
 */
int
NetSnmpAgent::snmp_send(netsnmp_session*  session, netsnmp_pdu* pdu)
{
   return snmp_async_send(session, pdu);

}
int
NetSnmpAgent::snmp_async_send(netsnmp_session*  session,
                netsnmp_pdu* pdu)
{
    void* sessp = snmp_sess_pointer(session);
    return snmp_sess_async_send(sessp, pdu);
}
/*
 * returns NULL or internal pointer to session
 * use this pointer for the other snmp_sess* routines,
 * which guarantee action will occur ONLY for this given session.
 */
void*
NetSnmpAgent::snmp_sess_pointer(netsnmp_session*  session)
{
    struct snmp_session_list* slp;

    for (slp = Sessions; slp; slp = slp->next) {
        if (slp->session == session) {
            break;
        }
    }

    if (slp == NULL) {
        snmp_errno = SNMPERR_BAD_SESSION;       /*MTCRITICAL_RESOURCE */
        return (NULL);
    }
    return ((void*) slp);
}
long
NetSnmpAgent::snmp_get_next_sessid(void)
{
    long            retVal;
    retVal = 1 + Sessid;        /*MTCRITICAL_RESOURCE */
    if (!retVal)
        retVal = 2;
    Sessid = retVal;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_16BIT_IDS))
        retVal &= 0x7fff;    /* mask to 15 bits */
    else
        retVal &= 0x7fffffff;    /* mask to 31 bits */

    if (!retVal) {
        Sessid = retVal = 2;
    }
    return retVal;
}



/** Given two OIDs, determine the common prefix to them both.
 * @param in_name1 A pointer to the first oid.
 * @param len1     Length of the first oid.
 * @param in_name2 A pointer to the second oid.
 * @param len2     Length of the second oid.
 * @return length of largest common index of commonality.  1 = first, 0 if none*          or -1 on error.
 */
int
netsnmp_oid_find_prefix(const oid*  in_name1, size_t len1,
                        const oid*  in_name2, size_t len2)
{
    int i;
    size_t min_size;

    if (!in_name1 || !in_name2 || !len1 || !len2)
        return -1;

    if (in_name1[0] != in_name2[0])
        return 0;   /* No match */
    min_size = SNMP_MIN(len1, len2);
    for (i = 0; i < (int)min_size; i++) {
        if (in_name1[i] != in_name2[i])
            return i + 1;    /* Why +1 ?? */
    }
    return min_size;    /* or +1? - the spec isn't totally clear */
}




int check_for_inform_ack(oid obj[])
{
    oid ob[11] = {1,3,6,1,6,3,1,1,4,1,0};
    int count=0,z=0;
    while (count < 11)
    {
     if (ob[count]  != obj[count])
       z=-1;
     count++;
    }

    if (z==0) return 1;
    else return 0;
}

int
NetSnmpAgent::snmp_close_sessions(void)
{
    struct snmp_session_list* slp;

    snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);
    while (Sessions) {
        slp = Sessions;
        Sessions = Sessions->next;
        snmp_sess_close((void*) slp);
    }
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);
    return 1;
}
