/*
 * agent_trap_netsnmp.c
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
/** @defgroup agent_trap Trap generation routines for mib modules to use
 *  @ingroup agent
 *
 * @{
 */



/*******************
     *
     * Config file handling
     *
     *******************/
#include "netSnmpAgent.h"
#include "snmp_netsnmp.h"
#include "net-snmp-config_netsnmp.h"
#include "asn1_netsnmp.h"
#include "types_netsnmp.h"
#include "varbind_api_netsnmp.h"
#include "snmp_api_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "callback_netsnmp.h"
#include "agent_callback_netsnmp.h"
#include "default_store_netsnmp.h"
#include "system_netsnmp.h"
#include "api.h"
#include "read_config_netsnmp.h"
#include "agent_trap_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "snmpv3_netsnmp.h"
#include "app_util.h"
#include "application.h"
#include "network_ip.h"
#include "tools_netsnmp.h"

#ifdef JNE_LIB
#include "jne.h"
#endif

#define SNMPV2_TRAP_OBJS_PREFIX    SNMP_OID_SNMPMODULES,1,1,4
#define SNMPV2_COMM_OBJS_PREFIX    SNMP_OID_SNMPMODULES,18,1
#define SNMPV2_TRAPS_PREFIX    SNMP_OID_SNMPMODULES,1,1,5
#define SNMPV2_TRAPS_PREFIX    SNMP_OID_SNMPMODULES,1,1,5

oid             snmptrap_oid[] = { SNMPV2_TRAP_OBJS_PREFIX, 1, 0 };
oid             objid_enterprisetrap[] = { NETSNMP_NOTIFICATION_MIB };
oid             trap_version_id[] = { NETSNMP_SYSTEM_MIB };
oid             sysuptime_oid[] = { SNMP_OID_MIB2, 1, 3, 0 };
size_t          sysuptime_oid_len;
#define SNMPV2_TRAP_OBJS_PREFIX    SNMP_OID_SNMPMODULES,1,1,4
oid             snmptrapenterprise_oid[] =  { SNMPV2_TRAP_OBJS_PREFIX, 3, 0 };
size_t          snmptrap_oid_len;
size_t          snmptrapenterprise_oid_len;
#define SNMPV2_COMM_OBJS_PREFIX    SNMP_OID_SNMPMODULES,18,1
oid             agentaddr_oid[] = { SNMPV2_COMM_OBJS_PREFIX, 3, 0 };
size_t          agentaddr_oid_len;

#define SNMPV2_TRAPS_PREFIX    SNMP_OID_SNMPMODULES,1,1,5
oid             trap_prefix[]    = { SNMPV2_TRAPS_PREFIX };
oid             cold_start_oid[] = { SNMPV2_TRAPS_PREFIX, 1 };  /* SNMPv2-MIB */
oid             warm_start_oid[] = { SNMPV2_TRAPS_PREFIX, 2 };  /* SNMPv2-MIB */
oid             link_down_oid[]  = { SNMPV2_TRAPS_PREFIX, 3 };  /* IF-MIB */
oid             link_up_oid[]    = { SNMPV2_TRAPS_PREFIX, 4 };  /* IF-MIB */
oid             auth_fail_oid[]  = { SNMPV2_TRAPS_PREFIX, 5 };  /* SNMPv2-MIB */
oid             egp_xxx_oid[]    = { SNMPV2_TRAPS_PREFIX, 99 }; /* ??? */
#define SNMPV2_COMM_OBJS_PREFIX    SNMP_OID_SNMPMODULES,18,1
oid             community_oid[] = { SNMPV2_COMM_OBJS_PREFIX, 4, 0 };
size_t          community_oid_len;

#define SNMP_AUTHENTICATED_TRAPS_ENABLED   1
#define SNMP_AUTHENTICATED_TRAPS_DISABLED  2

int   snmp_enableauthentraps = SNMP_AUTHENTICATED_TRAPS_DISABLED;




void
NetSnmpAgent::snmpd_parse_config_authtrap(const char* token, char* cptr)
{
    int             i;

    i = atoi(cptr);
    if (i == 0) {
        if (strcmp(cptr, "enable") == 0) {
            i = SNMP_AUTHENTICATED_TRAPS_ENABLED;
        } else if (strcmp(cptr, "disable") == 0) {
            i = SNMP_AUTHENTICATED_TRAPS_DISABLED;
        }
    }
    if (i < 1 || i > 2) {
       /* config_perror("authtrapenable must be 1 or 2");*/
    } else {
        if (strcmp(token, "pauthtrapenable") == 0) {
            if (snmp_enableauthentrapsset < 0) {
                /*
                 * This is bogus (and shouldn't happen anyway) -- the value
                 * of snmpEnableAuthenTraps.0 is already configured
                 * read-only.
                 */
                return;
            } else {
                snmp_enableauthentrapsset++;
            }
        } else {
            if (snmp_enableauthentrapsset > 0) {
                /*
                 * This is bogus (and shouldn't happen anyway) -- we already
                 * read a persistent value of snmpEnableAuthenTraps.0, which
                 * we should ignore in favour of this one.
                 */
            }
            snmp_enableauthentrapsset = -1;
        }
        snmp_enableauthentraps = i;
    }
}

void
NetSnmpAgent::snmpd_parse_config_trapsink(const char* token, char* cptr)
{
    char*           sp,* cp,* pp = NULL;

    if (!snmp_trapcommunity)
        snmp_trapcommunity = strdup("public");
    sp = strtok(cptr, " \t\n");
    cp = strtok(NULL, " \t\n");
    if (cp)
        pp = strtok(NULL, " \t\n");
}

void
NetSnmpAgent::snmpd_parse_config_informsink(const char* word, char* cptr)
{
    char* sp,* cp,* pp = NULL;

    if (!snmp_trapcommunity)
        snmp_trapcommunity = strdup("public");
    sp = strtok(cptr, " \t\n");
    cp = strtok(NULL, " \t\n");
    if (cp)
        pp = strtok(NULL, " \t\n");
}

void
NetSnmpAgent::snmpd_parse_config_trapsess(const char* word, char* cptr)
{
    char*           argv[MAX_ARGS],* cp = cptr;
    char    tmp[SPRINT_MAX_LEN];
    int             argn, arg;
    netsnmp_session session,* ss=NULL;
    size_t          len=0;

    /*
     * inform or trap?  default to trap
     */
    traptype = SNMP_MSG_TRAP2;

    /*
     * create the argv[] like array
     */
    argv[0] = strdup("snmpd-trapsess"); /* bogus entry for getopt() */
    for (argn = 1; cp && argn < MAX_ARGS; argn++) {
        cp = copy_nword(cp, tmp, SPRINT_MAX_LEN);
        argv[argn] = strdup(tmp);
    }

    arg = snmp_parse_args(argn, argv, &session, "C:", &NetSnmpAgent::trapOptProc);

    for (; argn > 0; argn--) {
        free(argv[argn - 1]);
    }

    if (!ss) {
        return;
    }

    /*
     * If this is an SNMPv3 TRAP session, then the agent is
     *   the authoritative engine, so set the engineID accordingly
     */
    if (ss->version == SNMP_VERSION_3 &&
        traptype != SNMP_MSG_INFORM   &&
        ss->securityEngineIDLen == 0) {
            memdup(&ss->securityEngineID, tmp, len);
            ss->securityEngineIDLen = len;
    }

#ifndef NETSNMP_DISABLE_SNMPV1
    if (ss->version == SNMP_VERSION_1) {
        add_trap_session(ss, SNMP_MSG_TRAP, 0, SNMP_VERSION_1);
    } else {
#endif
        add_trap_session(ss, traptype, (traptype == SNMP_MSG_INFORM),
                         ss->version);
#ifndef NETSNMP_DISABLE_SNMPV1
    }
#endif
}

void
NetSnmpAgent::snmpd_free_trapsinks(void)
{
    struct trap_sink* sp = sinks;
    while (sp) {
        sinks = sinks->next;
        free_trap_session(sp);
        sp = sinks;
    }
}

void
NetSnmpAgent::free_trap_session(struct trap_sink* sp)
{
    snmp_close(sp->sesp);
    free(sp);
}

void
NetSnmpAgent::send_trap(Node* node, Message* msg,int trap)
{
    switch(trap)
    {
     case SNMP_TRAP_COLDSTART :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,1,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         break;
        }
     case SNMP_TRAP_WARMSTART :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,2,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         break;
        }
     case SNMP_TRAP_LINKDOWN :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,3,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         node->SNMP_TRAP_LINKDOWN_counter = 1;
        break;
        }
     case SNMP_TRAP_LINKUP :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,4,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         break;
        }
     case SNMP_TRAP_AUTHFAIL :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,5,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         break;
        }
     case SNMP_TRAP_EGPNEIGHBORLOSS :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,6,trap_version_id,OID_LENGTH(trap_version_id),NULL,NULL,0);
         break;
        }
     case SNMP_TRAP_ENTERPRISESPECIFIC :
        {
         node->netSnmpAgent->netsnmp_send_traps(trap,7,objid_enterprisetrap,OID_LENGTH(objid_enterprisetrap),NULL,NULL,0);
         break;
        }
    }
}

int
NetSnmpAgent::netsnmp_send_traps(int trap, int specific,
                          oid*  enterprise, int enterprise_length,
                          netsnmp_variable_list*  vars,
                          char*  context, int flags)
{

    int response_len=0;
    int response_len2 = 0;
    if (node->snmpVersion == 1)
    {
        response_len = Snmpv1SendTrap(specific);
    }
    else if (node->snmpVersion == 2)
    {
        response_len = Snmpv2SendTrap(specific);
    }
    else if (node->snmpVersion == 3)
    {   
#ifdef JNE_LIB        
        JneData& jneData = JNE_GetJneData(node);
        if (jneData.sendHmsLoginStatusTrap > 0)
            response_len = SendHmsLogoutTrap(trap,vars);
        else  
#endif        
            response_len = Snmpv3SendTrap(specific);
    }

    unsigned char*  resp = (unsigned char*)
                        MEM_malloc(sizeof(unsigned char)*response_len);
    
    memcpy(resp,response,response_len);

        
        int interfaceIndex = 
            NetworkGetInterfaceIndexForDestAddress(node,
                                                   node->managerAddress);

    Message *udpmsg = APP_UdpCreateMessage(
        node,
        MAPPING_GetInterfaceAddressForInterface(
            node, node->nodeId, interfaceIndex),
        APP_SNMP_AGENT,
        node->managerAddress,
        APP_SNMP_TRAP,
        TRACE_SNMP);

    APP_AddPayload(node, udpmsg, resp, response_len);

    APP_UdpSend(node, udpmsg, (clocktype) 0);

    if (this->node->notification_para == 1)
        snmp_increment_statistic(STAT_SNMPOUTTRAPS);
    if (this->node->notification_para == 2)
        snmp_increment_statistic(STAT_OUTINFORM);

    snmp_increment_statistic(STAT_SNMPOUTPKTS);

    MEM_free(resp);

    #ifdef SNMP_DEBUG
        printf("netsnmp_send_traps:Trap sent from node %d\n",node->nodeId);
    #endif

    return 1;
}

int
NetSnmpAgent::create_v1_trap_session(char* sink, const char* sinkport, char* com)
{
    return 1;
}

int
NetSnmpAgent::create_v2_inform_session(const char* sink, const char* sinkport, char* com)
{
    return 1;
}

void
NetSnmpAgent::trapOptProc(int argc, char* const* argv, int opt)
{
    if (node->generateTrap)
        traptype = SNMP_MSG_TRAP2;
    else if (node->generateInform)
        traptype = SNMP_MSG_INFORM;
}

void
NetSnmpAgent::snmpd_parse_config_trapcommunity(const char* word, char* cptr)
{
    if (snmp_trapcommunity != NULL) {
        free(snmp_trapcommunity);
    }
    snmp_trapcommunity = (char*) MEM_malloc(strlen(cptr) + 1);
    if (snmp_trapcommunity != NULL) {
        copy_nword(cptr, snmp_trapcommunity, strlen(cptr) + 1);
    }
}

void
NetSnmpAgent::snmpd_free_trapcommunity(void)
{
    if (snmp_trapcommunity) {
        free(snmp_trapcommunity);
        snmp_trapcommunity = NULL;
    }
}

      /*******************
     *
     * Trap handling
     *
     *******************/


netsnmp_pdu*
NetSnmpAgent::convert_v2pdu_to_v1(netsnmp_pdu* template_v2pdu)
{
    netsnmp_pdu*           template_v1pdu;
    netsnmp_variable_list* first_vb,* vblist;
    netsnmp_variable_list* var;

    /*
     * Make a copy of the v2 Trap PDU
     *   before starting to convert this
     *   into a v1 Trap PDU.
     */
    template_v1pdu = snmp_clone_pdu(template_v2pdu);
    if (!template_v1pdu) {
        return NULL;
    }
    template_v1pdu->command = SNMP_MSG_TRAP;
    first_vb = template_v1pdu->variables;
    vblist   = template_v1pdu->variables;

    /*
     * The first varbind should be the system uptime.
     */
    if (!vblist ||
        snmp_oid_compare(vblist->name,  vblist->name_length,
                         sysuptime_oid, sysuptime_oid_len)) {
        snmp_free_pdu(template_v1pdu);
        return NULL;
    }
    template_v1pdu->time = *vblist->val.integer;
    vblist = vblist->next_variable;

    /*
     * The second varbind should be the snmpTrapOID.
     */
    if (!vblist ||
        snmp_oid_compare(vblist->name, vblist->name_length,
                         snmptrap_oid, snmptrap_oid_len)) {
        snmp_free_pdu(template_v1pdu);
        return NULL;
    }

    /*
     * Check the v2 varbind list for any varbinds
     *  that are not valid in an SNMPv1 trap.
     *  This basically means Counter64 values.
     *
     * RFC 2089 said to omit such varbinds from the list.
     * RFC 2576/3584 say to drop the trap completely.
     */
    for (var = vblist->next_variable; var; var = var->next_variable) {
        if (var->type == ASN_COUNTER64) {
            snmp_free_pdu(template_v1pdu);
            return NULL;
        }
    }

    /*
     * Set the generic & specific trap types,
     *    and the enterprise field from the v2 varbind list.
     * If there's an agentIPAddress varbind, set the agent_addr too
     */
    if (!snmp_oid_compare(vblist->val.objid, OID_LENGTH(trap_prefix),
                          trap_prefix,       OID_LENGTH(trap_prefix))) {
        /*
         * For 'standard' traps, extract the generic trap type
         *   from the snmpTrapOID value, and take the enterprise
         *   value from the 'snmpEnterprise' varbind.
         */
        template_v1pdu->trap_type =
            vblist->val.objid[OID_LENGTH(trap_prefix)] - 1;
        template_v1pdu->specific_type = 0;

        var = find_varbind_in_list(vblist,
                             snmptrapenterprise_oid,
                             snmptrapenterprise_oid_len);
        if (var) {
            template_v1pdu->enterprise_length = var->val_len/sizeof(oid);
            template_v1pdu->enterprise =
                snmp_duplicate_objid(var->val.objid,
                                     template_v1pdu->enterprise_length);
        } else {
            template_v1pdu->enterprise        = NULL;
            template_v1pdu->enterprise_length = 0;        /* XXX ??? */
        }
    } else {
        /*
         * For enterprise-specific traps, split the snmpTrapOID value
         *   into enterprise and specific trap
         */
        size_t len = vblist->val_len / sizeof(oid);
        if (len <= 2) {
            snmp_free_pdu(template_v1pdu);
            return NULL;
        }
        template_v1pdu->trap_type     = SNMP_TRAP_ENTERPRISESPECIFIC;
        template_v1pdu->specific_type = vblist->val.objid[len - 1];
        len--;
        if (vblist->val.objid[len-1] == 0)
            len--;
        SNMP_FREE(template_v1pdu->enterprise);
        template_v1pdu->enterprise =
            snmp_duplicate_objid(vblist->val.objid, len);
        template_v1pdu->enterprise_length = len;
    }
    var = find_varbind_in_list(vblist, agentaddr_oid,
                                        agentaddr_oid_len);
    if (var) {
        memcpy(template_v1pdu->agent_addr,
               var->val.string, 4);
    }

    /*
     * The remainder of the v2 varbind list is kept
     * as the v2 varbind list.  Update the PDU and
     * free the two redundant varbinds.
     */
    template_v1pdu->variables = vblist->next_variable;
    vblist->next_variable = NULL;
    snmp_free_varbind(first_vb);

    return template_v1pdu;
}


netsnmp_pdu*
NetSnmpAgent::convert_v1pdu_to_v2(netsnmp_pdu* template_v1pdu)
{
    netsnmp_pdu*           template_v2pdu;
    netsnmp_variable_list* first_vb;
    netsnmp_variable_list* var;
    oid                    enterprise[MAX_OID_LEN];
    size_t                 enterprise_len;

    /*
     * Make a copy of the v1 Trap PDU
     *   before starting to convert this
     *   into a v2 Trap PDU.
     */
    template_v2pdu = snmp_clone_pdu(template_v1pdu);
    if (!template_v2pdu) {
        return NULL;
    }
    template_v2pdu->command = SNMP_MSG_TRAP2;
    first_vb = template_v2pdu->variables;

    /*
     * Insert an snmpTrapOID varbind before the original v1 varbind list
     *   either using one of the standard defined trap OIDs,
     *   or constructing this from the PDU enterprise & specific trap fields
     */
    if (template_v1pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC) {
        memcpy(enterprise, template_v1pdu->enterprise,
                           template_v1pdu->enterprise_length*sizeof(oid));
        enterprise_len               = template_v1pdu->enterprise_length;
        enterprise[enterprise_len++] = 0;
        enterprise[enterprise_len++] = template_v1pdu->specific_type;
    } else {
        memcpy(enterprise, cold_start_oid, sizeof(cold_start_oid));
    enterprise[9]  = template_v1pdu->trap_type+1;
        enterprise_len = sizeof(cold_start_oid)/sizeof(oid);
    }

    var = NULL;
    if (!snmp_varlist_add_variable(&var,
             snmptrap_oid, snmptrap_oid_len,
             ASN_OBJECT_ID,
             (u_char*)enterprise, enterprise_len*sizeof(oid))) {
        snmp_free_pdu(template_v2pdu);
        return NULL;
    }
    var->next_variable        = template_v2pdu->variables;
    template_v2pdu->variables = var;

    /*
     * Insert a sysUptime varbind at the head of the v2 varbind list
     */
    var = NULL;
    if (!snmp_varlist_add_variable(&var,
             sysuptime_oid, sysuptime_oid_len,
             ASN_TIMETICKS,
             (u_char*)&(template_v1pdu->time),
             sizeof(template_v1pdu->time))) {
        snmp_free_pdu(template_v2pdu);
        return NULL;
    }
    var->next_variable        = template_v2pdu->variables;
    template_v2pdu->variables = var;

    /*
     * Append the other three conversion varbinds,
     *  (snmpTrapAgentAddr, snmpTrapCommunity & snmpTrapEnterprise)
     *  if they're not already present.
     *  But don't bomb out completely if there are problems.
     */
    var = find_varbind_in_list(template_v2pdu->variables,
                                agentaddr_oid, agentaddr_oid_len);
    if (!var && (template_v1pdu->agent_addr[0]
              || template_v1pdu->agent_addr[1]
              || template_v1pdu->agent_addr[2]
              || template_v1pdu->agent_addr[3])) {
        if (!snmp_varlist_add_variable(&(template_v2pdu->variables),
                 agentaddr_oid, agentaddr_oid_len,
                 ASN_IPADDRESS,
                 (u_char*)&(template_v1pdu->agent_addr),
                 sizeof(template_v1pdu->agent_addr))) {}
    }
    var = find_varbind_in_list(template_v2pdu->variables,
                                community_oid, community_oid_len);
    if (!var && template_v1pdu->community) {
        if (!snmp_varlist_add_variable(&(template_v2pdu->variables),
                 community_oid, community_oid_len,
                 ASN_OCTET_STR,
                 template_v1pdu->community,
                 template_v1pdu->community_len))  {}
    }
    var = find_varbind_in_list(template_v2pdu->variables,
                                snmptrapenterprise_oid,
                                snmptrapenterprise_oid_len);
    if (!var) {
        if (!snmp_varlist_add_variable(&(template_v2pdu->variables),
                 snmptrapenterprise_oid, snmptrapenterprise_oid_len,
                 ASN_OBJECT_ID,
                 (u_char*)template_v1pdu->enterprise,
                 template_v1pdu->enterprise_length*sizeof(oid))){}
    }
    return template_v2pdu;
}

/**
 * Captures responses or the lack there of from INFORMs that were sent
 * 1) a response is received from an INFORM
 * 2) one isn't received and the retries/timeouts have failed
*/
int
handle_inform_response(int op, netsnmp_session*  session,
                       int reqid, netsnmp_pdu* pdu,
                       void* magic)
{
    /* XXX: possibly stats update */
    switch (op) {

    case NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
        break;

    case NETSNMP_CALLBACK_OP_TIMED_OUT:
        break;

    case NETSNMP_CALLBACK_OP_SEND_FAILED:
        break;
    }

    return 1;
}




/*
 * send_trap_to_sess: sends a trap to a session but assumes that the
 * pdu is constructed correctly for the session type.
 */
void
NetSnmpAgent::send_trap_to_sess(netsnmp_session*  sess, netsnmp_pdu* template_pdu)
{
    netsnmp_pdu*    pdu;
    int            result;
    unsigned char           tmp[SPRINT_MAX_LEN];
    int            len;


    if (!sess || !template_pdu)
        return;

#ifndef NETSNMP_DISABLE_SNMPV1
    if (sess->version == SNMP_VERSION_1 &&
        (template_pdu->command != SNMP_MSG_TRAP))
        return;                 /* Skip v1 sinks for v2 only traps */
    if (sess->version != SNMP_VERSION_1 &&
        (template_pdu->command == SNMP_MSG_TRAP))
        return;                 /* Skip v2+ sinks for v1 only traps */
#endif
    template_pdu->version = sess->version;
    pdu = snmp_clone_pdu(template_pdu);
    pdu->sessid = sess->sessid; /* AgentX only ? */

    if (template_pdu->command == SNMP_MSG_INFORM
#ifdef USING_AGENTX_PROTOCOL_MODULE
         || template_pdu->command == AGENTX_MSG_NOTIFY
#endif
        ) {
        result =
            snmp_async_send(sess, pdu);

    } else {
        if ((sess->version == SNMP_VERSION_3) &&
                (pdu->command == SNMP_MSG_TRAP2) &&
                (pdu->securityEngineIDLen == 0)) {
        len = snmpv3_get_engineID(tmp, sizeof(tmp));
            memdup(&pdu->securityEngineID, tmp, len);
            pdu->securityEngineIDLen = len;
        }

        result = snmp_send(sess, pdu);
    }
}





int
NetSnmpAgent::add_trap_session(netsnmp_session*  ss, int pdutype, int confirm,
                 int version)
{
    if (snmp_callback_available(SNMP_CALLBACK_APPLICATION,
                                SNMPD_CALLBACK_REGISTER_NOTIFICATIONS) ==
        SNMPERR_SUCCESS) {
        /*
         * something else wants to handle notification registrations
         */
        struct agent_add_trap_args args;
        args.ss = ss;
        args.confirm = confirm;
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                            SNMPD_CALLBACK_REGISTER_NOTIFICATIONS,
                            (void*) &args);
    } else {
        /*
         * no other support exists, handle it ourselves.
         */
        struct trap_sink* new_sink;

        new_sink = (struct trap_sink*) malloc(sizeof(*new_sink));
        if (new_sink == NULL)
            return 0;

        new_sink->sesp = ss;
        new_sink->pdutype = pdutype;
        new_sink->version = version;
        new_sink->next = sinks;
        sinks = new_sink;
    }
    return 1;
}


int
NetSnmpAgent::netsnmp_send_traps2(int trap, int specific,
                          oid * enterprise, int enterprise_length,
                          netsnmp_variable_list * vars,
                          char * context, int flags)
{
    netsnmp_pdu           *template_v1pdu;
    netsnmp_pdu           *template_v2pdu;
    netsnmp_variable_list *vblist = NULL;
    netsnmp_variable_list *trap_vb;
    netsnmp_variable_list *var;
    in_addr_t             *pdu_in_addr_t;
    u_long                 uptime;
    struct trap_sink *sink;
    const char            *v1trapaddress;
    int                    res = 0;

    //DEBUGMSGTL(( "trap", "send_trap %d %d ", trap, specific));
    //DEBUGMSGOID(("trap", enterprise, enterprise_length));
    //DEBUGMSG(( "trap", "\n"));

    if (vars) {
        vblist = snmp_clone_varbind( vars );
        if (!vblist) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to clone varbind list\n");
            return -1;
        }
    }

    if (trap == -1 ) {
        /*
         * Construct the SNMPv2-style notification PDU
         */
        if (!vblist) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: called with NULL v2 information\n");
            return -1;
        }
        template_v2pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
        if (!template_v2pdu) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to construct v2 template PDU\n");
            snmp_free_varbind(vblist);
            return -1;
        }

        /*
         * Check the varbind list we've been given.
         * If it starts with a 'sysUptime.0' varbind, then use that.
         * Otherwise, prepend a suitable 'sysUptime.0' varbind.
         */
        if (!snmp_oid_compare( vblist->name,    vblist->name_length,
                               sysuptime_oid, sysuptime_oid_len )) {
            template_v2pdu->variables = vblist;
            trap_vb  = vblist->next_variable;
        } else {
            uptime   = netsnmp_get_agent_uptime(node);
            var = NULL;
            snmp_varlist_add_variable( &var,
                           sysuptime_oid, sysuptime_oid_len,
                           ASN_TIMETICKS, (u_char*)&uptime, sizeof(uptime));
            if (!var) {
                //snmp_log(LOG_WARNING,
                //     "send_trap: failed to insert sysUptime varbind\n");
                snmp_free_pdu(template_v2pdu);
                snmp_free_varbind(vblist);
                return -1;
            }
            template_v2pdu->variables = var;
            var->next_variable        = vblist;
            trap_vb  = vblist;
        }

        /*
         * 'trap_vb' should point to the snmpTrapOID.0 varbind,
         *   identifying the requested trap.  If not then bomb out.
         * If it's a 'standard' trap, then we need to append an
         *   snmpEnterprise varbind (if there isn't already one).
         */
        if (!trap_vb ||
            snmp_oid_compare(trap_vb->name, trap_vb->name_length,
                             snmptrap_oid,  snmptrap_oid_len)) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: no v2 trapOID varbind provided\n");
            snmp_free_pdu(template_v2pdu);
            return -1;
        }
        if (!snmp_oid_compare(vblist->val.objid, OID_LENGTH(trap_prefix),
                              trap_prefix,       OID_LENGTH(trap_prefix))) {
            var = find_varbind_in_list( template_v2pdu->variables,
                                        snmptrapenterprise_oid,
                                        snmptrapenterprise_oid_len);
            if (!var &&
                !snmp_varlist_add_variable( &(template_v2pdu->variables),
                     snmptrapenterprise_oid, snmptrapenterprise_oid_len,
                     ASN_OBJECT_ID,
                     enterprise, enterprise_length*sizeof(oid))) {
                //snmp_log(LOG_WARNING,
                //     "send_trap: failed to add snmpEnterprise to v2 trap\n");
                snmp_free_pdu(template_v2pdu);
                return -1;
            }
        }
            

        /*
         * If everything's OK, convert the v2 template into an SNMPv1 trap PDU.
         */
        template_v1pdu = convert_v2pdu_to_v1( template_v2pdu );
        if (!template_v1pdu) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to convert v2->v1 template PDU\n");
        }

    } else {
        /*
         * Construct the SNMPv1 trap PDU....
         */
        template_v1pdu = snmp_pdu_create(SNMP_MSG_TRAP);
        if (!template_v1pdu) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to construct v1 template PDU\n");
            snmp_free_varbind(vblist);
            return -1;
        }
        template_v1pdu->trap_type     = trap;
        template_v1pdu->specific_type = specific;
        template_v1pdu->time          = netsnmp_get_agent_uptime(node);

        if (snmp_clone_mem((void **) &template_v1pdu->enterprise,
                       enterprise, enterprise_length * sizeof(oid))) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to set v1 enterprise OID\n");
            snmp_free_varbind(vblist);
            snmp_free_pdu(template_v1pdu);
            return -1;
        }
        template_v1pdu->enterprise_length = enterprise_length;

        template_v1pdu->flags    |= UCD_MSG_FLAG_FORCE_PDU_COPY;
        template_v1pdu->variables = vblist;

        /*
         * ... and convert it into an SNMPv2-style notification PDU.
         */

        template_v2pdu = convert_v1pdu_to_v2( template_v1pdu );
        if (!template_v2pdu) {
            //snmp_log(LOG_WARNING,
            //         "send_trap: failed to convert v1->v2 template PDU\n");
        }
    }

    /*
     * Check whether we're ignoring authFail traps
     */
    if (template_v1pdu) {
      if (template_v1pdu->trap_type == SNMP_TRAP_AUTHFAIL &&
        snmp_enableauthentraps == SNMP_AUTHENTICATED_TRAPS_DISABLED) {
        snmp_free_pdu(template_v1pdu);
        snmp_free_pdu(template_v2pdu);
        return 0;
      }

    /*
     * Ensure that the v1 trap PDU includes the local IP address
     */
       pdu_in_addr_t = (in_addr_t *) template_v1pdu->agent_addr;
       v1trapaddress = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                                             NETSNMP_DS_AGENT_TRAP_ADDR);
       if (v1trapaddress != NULL) {
           /* "v1trapaddress" was specified in config, try to resolve it */
           res = netsnmp_gethostbyname_v4(v1trapaddress, pdu_in_addr_t);
       }
       if (v1trapaddress == NULL || res < 0) {
           /* "v1trapaddress" was not specified in config or the resolution failed,
            * try any local address */
           //*pdu_in_addr_t = get_myaddr();
       }

    }

    /* A context name was provided, so copy it and its length to the v2 pdu
     * template. */
    if (context != NULL)
    {
        template_v2pdu->contextName    = strdup(context);
        template_v2pdu->contextNameLen = strlen(context);
    }

    //Look at snmp_send for net-snmp sending functionality (convert pdu to packet)
    /*APP_UdpSendNewData(
        node,
        APP_SNMP_TRAP,
        MAPPING_GetDefaultInterfaceAddressFromNodeId(node, node->nodeId),
        (AppType) (short) APP_SNMP_AGENT,
        node->managerAddress,
        (char*)(resp),
        sizeof(,
        (clocktype) 0,
        TRACE_SNMP);
    */
    /*
     *  Now loop through the list of trap sinks
     *   and call the trap callback routines,
     *   providing an appropriately formatted PDU in each case
     */
    for (sink = sinks; sink; sink = sink->next) {
#ifndef NETSNMP_DISABLE_SNMPV1
        if (sink->version == SNMP_VERSION_1) {
          if (template_v1pdu) {
            send_trap_to_sess(sink->sesp, template_v1pdu);
          }
        } else {
#endif
          if (template_v2pdu) {
            template_v2pdu->command = sink->pdutype;
            send_trap_to_sess(sink->sesp, template_v2pdu);
          }
#ifndef NETSNMP_DISABLE_SNMPV1
        }
#endif
    }
    
    
    
    if (template_v1pdu)
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                        SNMPD_CALLBACK_SEND_TRAP1, template_v1pdu);
    if (template_v2pdu)
        snmp_call_callbacks(SNMP_CALLBACK_APPLICATION,
                        SNMPD_CALLBACK_SEND_TRAP2, template_v2pdu);
    snmp_free_pdu(template_v1pdu);
    snmp_free_pdu(template_v2pdu);
    return 0;
}


void NetSnmpAgent::send_v2trap(netsnmp_variable_list * vars)
{
    netsnmp_send_traps(-1, -1,  trap_version_id, OID_LENGTH(trap_version_id), vars, NULL, 0);
}

