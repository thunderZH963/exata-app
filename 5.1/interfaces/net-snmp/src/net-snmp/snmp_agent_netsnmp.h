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
/*
 * @file snmp_agent.h
 *
 * @addtogroup agent
 * @addtogroup table
 * External definitions for functions and variables in snmp_agent.c.
 *
 * @{
 */

#ifndef SNMP_AGENT_H_NETSNMP
#define SNMP_AGENT_H_NETSNMP

#include "snmp_netsnmp.h"
#include "types_netsnmp.h"
#include "data_list_netsnmp.h"
#include "snmp_client_netsnmp.h"

//#define SNMP_DEBUG 1

#define MODE_GET              SNMP_MSG_GET
#define MODE_GETNEXT          SNMP_MSG_GETNEXT
#define MODE_GETBULK          SNMP_MSG_GETBULK
#define MODE_GET_STASH        SNMP_MSG_INTERNAL_GET_STASH




#define MODE_SET_BEGIN        SNMP_MSG_INTERNAL_SET_BEGIN
#define MODE_SET_RESERVE1     SNMP_MSG_INTERNAL_SET_RESERVE1
#define MODE_SET_RESERVE2     SNMP_MSG_INTERNAL_SET_RESERVE2
#define MODE_SET_ACTION       SNMP_MSG_INTERNAL_SET_ACTION
#define MODE_SET_COMMIT       SNMP_MSG_INTERNAL_SET_COMMIT
#define MODE_SET_FREE         SNMP_MSG_INTERNAL_SET_FREE
#define MODE_SET_UNDO         SNMP_MSG_INTERNAL_SET_UNDO
#define MODE_IS_SET(x)         ((x < 128) || (x == -1) || (x == SNMP_MSG_SET))



#define MODE_BSTEP_PRE_REQUEST   SNMP_MSG_INTERNAL_PRE_REQUEST
#define MODE_BSTEP_POST_REQUEST  SNMP_MSG_INTERNAL_POST_REQUEST


#define MODE_BSTEP_OBJECT_LOOKUP       SNMP_MSG_INTERNAL_OBJECT_LOOKUP
#define MODE_BSTEP_CHECK_VALUE         SNMP_MSG_INTERNAL_CHECK_VALUE
#define MODE_BSTEP_ROW_CREATE          SNMP_MSG_INTERNAL_ROW_CREATE
#define MODE_BSTEP_UNDO_SETUP          SNMP_MSG_INTERNAL_UNDO_SETUP
#define MODE_BSTEP_SET_VALUE           SNMP_MSG_INTERNAL_SET_VALUE
#define MODE_BSTEP_CHECK_CONSISTENCY   SNMP_MSG_INTERNAL_CHECK_CONSISTENCY
#define MODE_BSTEP_UNDO_SET            SNMP_MSG_INTERNAL_UNDO_SET
#define MODE_BSTEP_COMMIT              SNMP_MSG_INTERNAL_COMMIT
#define MODE_BSTEP_UNDO_COMMIT         SNMP_MSG_INTERNAL_UNDO_COMMIT
#define MODE_BSTEP_IRREVERSIBLE_COMMIT SNMP_MSG_INTERNAL_IRREVERSIBLE_COMMIT
#define MODE_BSTEP_UNDO_CLEANUP        SNMP_MSG_INTERNAL_UNDO_CLEANUP


/** @typedef struct netsnmp_request_info_s netsnmp_request_info
 * Typedefs the netsnmp_request_info_s struct into
 * netsnmp_request_info*/
/** @struct netsnmp_request_info_s
 * The netsnmp request info structure.
 */
typedef struct netsnmp_request_info_s {
/**
 * variable bindings
 */
    netsnmp_variable_list* requestvb;

/**
 * can be used to pass information on a per-request basis from a
 * helper to the later handlers
 */
    netsnmp_data_list* parent_data;

   /*
    * pointer to the agent_request_info for this request
    */
   struct netsnmp_agent_request_info_s* agent_req_info;

/** don't free, reference to (struct tree)->end */
    unsigned long*            range_end;
    size_t          range_end_len;

   /*
    * flags
    */
    int             delegated;
    int             processed;
    int             inclusive;

    int             status;
/** index in original pdu */
    int             index;

   /** get-bulk */
    int             repeat;
    int             orig_repeat;
    netsnmp_variable_list* requestvb_start;

   /* internal use */
    struct netsnmp_request_info_s* next;
    struct netsnmp_request_info_s* prev;
    struct netsnmp_subtree_s*      subtree;
} netsnmp_request_info;


    int
        netsnmp_request_set_error_all(netsnmp_request_info* requests,
                                       int error_value);

/** @typedef struct netsnmp_agent_request_info_s netsnmp_agent_request_info
 * Typedefs the netsnmp_agent_request_info_s struct into
 * netsnmp_agent_request_info
 */

/** @struct netsnmp_agent_request_info_s
 * The agent transaction request structure
 */
typedef struct netsnmp_agent_request_info_s {
    int mode;
    struct netsnmp_agent_session_s* asp;    /* may not be needed */
    /*
     * can be used to pass information on a per-pdu basis from a
     * helper to the later handlers
     */
    netsnmp_data_list* agent_data;
} netsnmp_agent_request_info;

typedef struct netsnmp_cachemap_s {
    int globalid;
    int cacheid;
    struct netsnmp_cachemap_s* next;
} netsnmp_cachemap;

typedef struct netsnmp_tree_cache_s {
    struct netsnmp_subtree_s* subtree;
    netsnmp_request_info* requests_begin;
    netsnmp_request_info* requests_end;
} netsnmp_tree_cache;

typedef struct netsnmp_agent_session_s {
    int             mode;
    netsnmp_session* session;
    netsnmp_pdu*    pdu;
    netsnmp_pdu*    orig_pdu;
    int             rw;
    int             exact;
    int             status;
    int             index;
    int             oldmode;

    struct netsnmp_agent_session_s* next;

    /*
     * new API pointers
     */
    netsnmp_agent_request_info* reqinfo;
    netsnmp_request_info* requests;
    netsnmp_tree_cache* treecache;
    netsnmp_variable_list** bulkcache;
    int             treecache_len;  /* length of cache array */
    int             treecache_num;  /* number of current cache entries */
    netsnmp_cachemap* cache_store;
    int             vbcount;
} netsnmp_agent_session;

typedef struct agent_set_cache_s {
    /*
     * match on these 2
     */
    int             transID;
    netsnmp_session* sess;

    /*
     * store this info
     */
    netsnmp_tree_cache* treecache;
    int             treecache_len;
    int             treecache_num;

    int             vbcount;
    netsnmp_request_info* requests;
    netsnmp_variable_list* saved_vars;
    netsnmp_data_list* agent_data;

    /*
     * list
     */
    struct agent_set_cache_s* next;
} agent_set_cache;

void
        netsnmp_free_agent_request_info(netsnmp_agent_request_info* ari);
struct netsnmp_agent_request_info_s;
typedef struct netsnmp_agent_request_info_s  netsnmp_agent_request_info;

    int             netsnmp_set_request_error(netsnmp_agent_request_info
                                              *reqinfo,
                                              netsnmp_request_info
                                              *request, int error_value);



void
netsnmp_agent_add_list_data(netsnmp_agent_request_info* ari,
                            netsnmp_data_list* node);

u_long netsnmp_get_agent_uptime(struct Node* node);
u_long netsnmp_marker_uptime(marker_t pm);
u_long netsnmp_timeval_uptime(struct timeval*  tv);

int
netsnmp_request_set_error(netsnmp_request_info* request, int error_value);

void*    netsnmp_agent_get_list_data(netsnmp_agent_request_info* ari,
                    const char* name);

#endif /* SNMP_AGENT_H_NETSNMP */
