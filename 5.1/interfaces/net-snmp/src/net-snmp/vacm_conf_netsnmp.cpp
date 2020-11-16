/*
 * SNMPv3 View-based Access Control Model
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



/**
 * Registers the VACM token handlers for inserting rows into the vacm tables.
 * These tokens will be recognised by both 'snmpd' and 'snmptrapd'.
 */

#ifndef WIN32
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <arpa/inet.h>
#endif

#include "vacm_conf_netsnmp.h"
#include "netSnmpAgent.h"
#include "agent_callback_netsnmp.h"
#include "vacm_netsnmp.h"
#include "snmp_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "ds_agent_netsnmp.h"
#include "system_netsnmp.h"
#include "tools_netsnmp.h"


#define EXAMPLE_NETWORK        "NETWORK"
#define EXAMPLE_COMMUNITY    "COMMUNITY"

void
NetSnmpAgent::init_vacm_config_tokens(void) {
    snmpd_register_config_handler("group", &NetSnmpAgent::vacm_parse_group,
                                  &NetSnmpAgent::vacm_free_group,
                                  "name v1|v2c|usm|... security");
    snmpd_register_config_handler("access", &NetSnmpAgent::vacm_parse_access,
                                  &NetSnmpAgent::vacm_free_access,
                                  "name context model level prefix read write notify");
    snmpd_register_config_handler("setaccess", &NetSnmpAgent::vacm_parse_setaccess,
                                  &NetSnmpAgent::vacm_free_access,
                                  "name context model level prefix viewname viewval");
    snmpd_register_config_handler("view", &NetSnmpAgent::vacm_parse_view, &NetSnmpAgent::vacm_free_view,
                                  "name type subtree [mask]");
    snmpd_register_config_handler("vacmView", &NetSnmpAgent::vacm_parse_config_view, NULL,
                                  NULL);
    snmpd_register_config_handler("vacmGroup", &NetSnmpAgent::vacm_parse_config_group,
                                  NULL, NULL);
    snmpd_register_config_handler("vacmAccess", &NetSnmpAgent::vacm_parse_config_access,
                                  NULL, NULL);
    snmpd_register_config_handler("vacmAuthAccess", &NetSnmpAgent::vacm_parse_config_auth_access,
                                  NULL, NULL);

    /* easy community auth handler */
    snmpd_register_config_handler("authcommunity",
                                  &NetSnmpAgent::vacm_parse_authcommunity,
                                  NULL, "authtype1,authtype2 community [default|hostname|network/bits [oid|-V view]]");

    /* easy user auth handler */
    snmpd_register_config_handler("authuser",
        &NetSnmpAgent::vacm_parse_authuser,
                                  NULL, "authtype1,authtype2 [-s secmodel] user [noauth|auth|priv [oid|-V view]]");
    /* easy group auth handler */
    snmpd_register_config_handler("authgroup",
                                  &NetSnmpAgent::vacm_parse_authuser,
                                  NULL, "authtype1,authtype2 [-s secmodel] group [noauth|auth|priv [oid|-V view]]");

    snmpd_register_config_handler("authaccess", &NetSnmpAgent::vacm_parse_authaccess,
                                  &NetSnmpAgent::vacm_free_access,
                                  "name authtype1,authtype2 [-s secmodel] group view [noauth|auth|priv [context|context*]]");

    snmpd_register_config_handler("com2sec", &NetSnmpAgent::netsnmp_udp_parse_security,
                                &NetSnmpAgent::netsnmp_udp_com2SecList_free,
                                "[-Cn CONTEXT] secName IPv4-network-address[/netmask] community");

    /*
     * Define standard views "_all_" and "_none_"
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_PRE_READ_CONFIG,
                           &NetSnmpAgent::vacm_standard_views, NULL);
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_READ_CONFIG,
                           &NetSnmpAgent::vacm_warn_if_not_configured, NULL);
}

/**
 * Registers the easier-to-use VACM token handlers for quick access rules.
 * These tokens will only be recognised by 'snmpd'.
 */
void
NetSnmpAgent::init_vacm_snmpd_easy_tokens(void) {
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    snmpd_register_config_handler("rwcommunity", &NetSnmpAgent::vacm_parse_rwcommunity, NULL,
                                  "community [default|hostname|network/bits [oid]]");
    snmpd_register_config_handler("rocommunity", &NetSnmpAgent::vacm_parse_rocommunity, NULL,
                                  "community [default|hostname|network/bits [oid]]");
#ifdef NETSNMP_TRANSPORT_UDPIPV6_DOMAIN
    snmpd_register_config_handler("rwcommunity6", vacm_parse_rwcommunity6, NULL,
                                  "community [default|hostname|network/bits [oid]]");
    snmpd_register_config_handler("rocommunity6", vacm_parse_rocommunity6, NULL,
                                  "community [default|hostname|network/bits [oid]]");
#endif
#endif /* support for community based SNMP */
    snmpd_register_config_handler("rwuser", &NetSnmpAgent::vacm_parse_rwuser, NULL,
                                  "user [noauth|auth|priv [oid]]");
    snmpd_register_config_handler("rouser", &NetSnmpAgent::vacm_parse_rouser, NULL,
                                  "user [noauth|auth|priv [oid]]");
}

void
NetSnmpAgent::init_vacm_conf(void)
{
    init_vacm_config_tokens();
    init_vacm_snmpd_easy_tokens();
    /*
     * register ourselves to handle access control  ('snmpd' only)
     */
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
        SNMPD_CALLBACK_ACM_CHECK, &NetSnmpAgent::vacm_in_view_callback,
                           NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_ACM_CHECK_INITIAL,
                           &NetSnmpAgent::vacm_in_view_callback, NULL);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_ACM_CHECK_SUBTREE,
                           &NetSnmpAgent::vacm_in_view_callback, NULL);
}



void
NetSnmpAgent::vacm_parse_group(const char* token, char* param)
{
    char            group[VACMSTRINGLEN], model[VACMSTRINGLEN], security[VACMSTRINGLEN];
    int             imodel;
    struct vacm_groupEntry* gp = NULL;
    char*           st;

    st = copy_nword(param, group, sizeof(group)-1);
    st = copy_nword(st, model, sizeof(model)-1);
    st = copy_nword(st, security, sizeof(security)-1);

    if (group[0] == 0) {
        return;
    }
    if (model[0] == 0) {
        return;
    }
    if (security[0] == 0) {
        return;
    }
    if (strcasecmp(model, "v1") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0)
        imodel = SNMP_SEC_MODEL_SNMPv2c;
    else if (strcasecmp(model, "any") == 0) {
        imodel = SNMP_SEC_MODEL_ANY;
    } else {
        if ((imodel = se_find_value_in_slist("snmp_secmods", model)) ==
            SE_DNE) {
            return;
        }
    }
    if (strlen(security) + 1 > sizeof(gp->groupName)) {
        return;
    }
    gp = vacm_createGroupEntry(imodel, security);
    if (!gp) {
        return;
    }
    strncpy(gp->groupName, group, sizeof(gp->groupName));
    gp->groupName[ sizeof(gp->groupName)-1 ] = 0;
    gp->storageType = SNMP_STORAGE_PERMANENT;
    gp->status = SNMP_ROW_ACTIVE;
    free(gp->reserved);
    gp->reserved = NULL;
}

void
NetSnmpAgent::vacm_free_group(void)
{
    vacm_destroyAllGroupEntries();
}

#define PARSE_CONT 0
#define PARSE_FAIL 1

int
NetSnmpAgent::_vacm_parse_access_common(const char* token, char* param, char** st,
                          char** name, char** context, int* imodel,
                          int* ilevel, int* iprefix)
{
    char* model, *level, *prefix;

    *name = strtok(param, " \t\n");
    if (!*name) {
        return PARSE_FAIL;
    }
    *context = strtok(NULL, " \t\n");
    if (!*context) {
        return PARSE_FAIL;
    }

    model = strtok(NULL, " \t\n");
    if (!model) {
        return PARSE_FAIL;
    }
    level = strtok(NULL, " \t\n");
    if (!level) {
        return PARSE_FAIL;
    }
    prefix = strtok(NULL, " \t\n");
    if (!prefix) {
        return PARSE_FAIL;
    }

    if (strcmp(*context, "\"\"") == 0)
        **context = 0;
    if (strcasecmp(model, "any") == 0)
        *imodel = SNMP_SEC_MODEL_ANY;
    else if (strcasecmp(model, "v1") == 0)
        *imodel = SNMP_SEC_MODEL_SNMPv1;
    else if (strcasecmp(model, "v2c") == 0)
        *imodel = SNMP_SEC_MODEL_SNMPv2c;
    else {
        if ((*imodel = se_find_value_in_slist("snmp_secmods", model))
            == SE_DNE) {
            return PARSE_FAIL;
        }
    }

    if (strcasecmp(level, "noauth") == 0)
        *ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "noauthnopriv") == 0)
        *ilevel = SNMP_SEC_LEVEL_NOAUTH;
    else if (strcasecmp(level, "auth") == 0)
        *ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "authnopriv") == 0)
        *ilevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
    else if (strcasecmp(level, "priv") == 0)
        *ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else if (strcasecmp(level, "authpriv") == 0)
        *ilevel = SNMP_SEC_LEVEL_AUTHPRIV;
    else {
        return PARSE_FAIL;
    }

    if (*ilevel > SNMP_SEC_LEVEL_NOAUTH &&
        node->snmpVersion < SNMP_VERSION_3)
    {
        char errorString[MAX_STRING_LENGTH];
        sprintf (errorString,
            "SNMP-VERSION is configued as %d for Node Id: %d,"
                " the user cannot be created with access as %s",
                node->snmpVersion, node->nodeId, level);
        ERROR_ReportError(errorString);
    }

    if (strcmp(prefix, "exact") == 0)
        *iprefix = 1;
    else if (strcmp(prefix, "prefix") == 0)
        *iprefix = 2;
    else if (strcmp(prefix, "0") == 0) {
        *iprefix = 1;
    } else {
        return PARSE_FAIL;
    }

    return PARSE_CONT;
}

/* **************************************/
/* authorization parsing token handlers */
/* **************************************/

int
NetSnmpAgent::vacm_parse_authtokens(const char* token, char** confline)
{
    char authspec[SNMP_MAXBUF_MEDIUM];
    char* type;
    int viewtype, viewtypes = 0;

    *confline = copy_nword(*confline, authspec, sizeof(authspec));

    if (!*confline) {
        return -1;
    }

    type = strtok(authspec, ",|:");
    while (type && *type != '\0') {
        viewtype = se_find_value_in_slist(VACM_VIEW_ENUM_NAME, type);
        if (viewtype < 0 || viewtype >= VACM_MAX_VIEWS) {
        } else {
            viewtypes |= (1 << viewtype);
        }
        type = strtok(NULL, ",|:");
    }
    return viewtypes;
}

void
NetSnmpAgent::vacm_parse_authuser(const char* token, char* confline)
{
    int viewtypes = vacm_parse_authtokens(token, &confline);
    if (viewtypes != -1)
        vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3, viewtypes);
}

void
NetSnmpAgent::vacm_parse_authcommunity(const char* token, char* confline)
{
    int viewtypes = vacm_parse_authtokens(token, &confline);
    if (viewtypes != -1)
        vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COM, viewtypes);
}

void
NetSnmpAgent::vacm_parse_authaccess(const char* token, char* confline)
{
    char* group, *view, *tmp;
    const char* context;
    int  model = SNMP_SEC_MODEL_ANY;
    int  level, prefix;
    int  i;
    struct vacm_accessEntry* ap;
    int  viewtypes = vacm_parse_authtokens(token, &confline);

    if (viewtypes == -1)
        return;

    group = strtok(confline, " \t\n");
    if (!group) {
        return;
    }
    view = strtok(NULL, " \t\n");
    if (!view) {
        return;
    }

    /*
     * Check for security model option
     */
    if (strcasecmp(view, "-s") == 0) {
        tmp = strtok(NULL, " \t\n");
        if (tmp) {
            if (strcasecmp(tmp, "any") == 0)
                model = SNMP_SEC_MODEL_ANY;
            else if (strcasecmp(tmp, "v1") == 0)
                model = SNMP_SEC_MODEL_SNMPv1;
            else if (strcasecmp(tmp, "v2c") == 0)
                model = SNMP_SEC_MODEL_SNMPv2c;
            else {
                model = se_find_value_in_slist("snmp_secmods", tmp);
                if (model == SE_DNE) {
                    return;
                }
            }
        } else {
            return;
        }
        view = strtok(NULL, " \t\n");
        if (!view) {
            return;
        }
    }
    if (strlen(view) >= VACMSTRINGLEN) {
        return;
    }

    /*
     * Now parse optional fields, or provide default values
     */

    tmp = strtok(NULL, " \t\n");
    if (tmp) {
        if (strcasecmp(tmp, "noauth") == 0)
            level = SNMP_SEC_LEVEL_NOAUTH;
        else if (strcasecmp(tmp, "noauthnopriv") == 0)
            level = SNMP_SEC_LEVEL_NOAUTH;
        else if (strcasecmp(tmp, "auth") == 0)
            level = SNMP_SEC_LEVEL_AUTHNOPRIV;
        else if (strcasecmp(tmp, "authnopriv") == 0)
            level = SNMP_SEC_LEVEL_AUTHNOPRIV;
        else if (strcasecmp(tmp, "priv") == 0)
            level = SNMP_SEC_LEVEL_AUTHPRIV;
        else if (strcasecmp(tmp, "authpriv") == 0)
            level = SNMP_SEC_LEVEL_AUTHPRIV;
        else {
                return;
        }
    } else {
        /*  What about  SNMP_SEC_MODEL_ANY ?? */
        if (model == SNMP_SEC_MODEL_SNMPv1 ||
             model == SNMP_SEC_MODEL_SNMPv2c)
            level = SNMP_SEC_LEVEL_NOAUTH;
        else
            level = SNMP_SEC_LEVEL_AUTHNOPRIV;
    }


    context = tmp = strtok(NULL, " \t\n");
    if (tmp) {
        tmp = (tmp + strlen(tmp)-1);
        if (tmp && *tmp == '*') {
            *tmp = '\0';
            prefix = 2;
        } else {
            prefix = 1;
        }
    } else {
        context = "";
        prefix  = 1;   /* Or prefix(2) ?? */
    }

    /*
     * Now we can create the access entry
     */
    ap = vacm_getAccessEntry(group, context, model, level);
    if (!ap) {
        ap = vacm_createAccessEntry(group, context, model, level);
    }
    if (!ap) {
        return;
    }

    for (i = 0; i <= VACM_MAX_VIEWS; i++) {
        if (viewtypes & (1 << i)) {
            strcpy(ap->views[i], view);
        }
    }
    ap->contextMatch = prefix;
    ap->storageType  = SNMP_STORAGE_PERMANENT;
    ap->status       = SNMP_ROW_ACTIVE;
    if (ap->reserved)
        free(ap->reserved);
    ap->reserved = NULL;
}

void
NetSnmpAgent::vacm_parse_setaccess(const char* token, char* param)
{
    char* name, *context, *viewname, *viewval;
    int  imodel, ilevel, iprefix;
    int  viewnum;
    char*   st;
    struct vacm_accessEntry* ap;

    if (_vacm_parse_access_common(token, param, &st, &name,
                                  &context, &imodel, &ilevel, &iprefix)
        == PARSE_FAIL) {
        return;
    }

    viewname = strtok(NULL, " \t\n");
    if (!viewname) {
        return;
    }
    viewval = strtok(NULL, " \t\n");
    if (!viewval) {
        return;
    }

    if (strlen(viewval) + 1 > sizeof(ap->views[VACM_VIEW_NOTIFY])) {
        return;
    }

    viewnum = se_find_value_in_slist(VACM_VIEW_ENUM_NAME, viewname);
    if (viewnum < 0 || viewnum >= VACM_MAX_VIEWS) {
        return;
    }

    ap = vacm_getAccessEntry(name, context, imodel, ilevel);
    if (!ap) {
        ap = vacm_createAccessEntry(name, context, imodel, ilevel);
    }
    if (!ap) {
        return;
    }
    if (!ap) {
        return;
    }

    strcpy(ap->views[viewnum], viewval);
    ap->contextMatch = iprefix;
    ap->storageType = SNMP_STORAGE_PERMANENT;
    ap->status = SNMP_ROW_ACTIVE;
    free(ap->reserved);
    ap->reserved = NULL;
}

void
NetSnmpAgent::vacm_parse_access(const char* token, char* param)
{
    char*           name, *context, *readView, *writeView, *notify;
    int             imodel, ilevel, iprefix;
    struct vacm_accessEntry* ap;
    char*   st;


    if (_vacm_parse_access_common(token, param, &st, &name,
                                  &context, &imodel, &ilevel, &iprefix)
        == PARSE_FAIL) {
        return;
    }

    readView = strtok(NULL, " \t\n");
    if (!readView) {
        return;
    }
    writeView = strtok(NULL, " \t\n");
    if (!writeView) {
        return;
    }
    notify = strtok(NULL, " \t\n");
    if (!notify) {
        return;
    }

    if (strlen(readView) + 1 > sizeof(ap->views[VACM_VIEW_READ])) {
        return;
    }
    if (strlen(writeView) + 1 > sizeof(ap->views[VACM_VIEW_WRITE])) {
        return;
    }
    if (strlen(notify) + 1 > sizeof(ap->views[VACM_VIEW_NOTIFY])) {
        return;
    }
    ap = vacm_createAccessEntry(name, context, imodel, ilevel);
    if (!ap) {
        return;
    }
    strcpy(ap->views[VACM_VIEW_READ], readView);
    strcpy(ap->views[VACM_VIEW_WRITE], writeView);
    strcpy(ap->views[VACM_VIEW_NOTIFY], notify);
    ap->contextMatch = iprefix;
    ap->storageType = SNMP_STORAGE_PERMANENT;
    ap->status = SNMP_ROW_ACTIVE;
    free(ap->reserved);
    ap->reserved = NULL;
}

void
NetSnmpAgent::vacm_free_access(void)
{
    vacm_destroyAllAccessEntries();
}

void
NetSnmpAgent::vacm_parse_view(const char* token, char* param)
{
    char*           name, *type, *subtree, *mask;
    int             inclexcl;
    struct vacm_viewEntry* vp;
    oid             suboid[MAX_OID_LEN];
    size_t          suboid_len = 0;
    size_t          mask_len = 0;
    u_char          viewMask[VACMSTRINGLEN];
    int             i;

    name = strtok(param, " \t\n");
    if (!name) {
        return;
    }
    type = strtok(NULL, " \n\t");
    if (!type) {
        return;
    }
    subtree = strtok(NULL, " \t\n");
    if (!subtree) {
        return;
    }
    mask = strtok(NULL, "\0");

    if (strcmp(type, "included") == 0)
        inclexcl = SNMP_VIEW_INCLUDED;
    else if (strcmp(type, "excluded") == 0)
        inclexcl = SNMP_VIEW_EXCLUDED;
    else {
        return;
    }
    suboid_len = strlen(subtree)-1;
    if (subtree[suboid_len] == '.')
        subtree[suboid_len] = '\0';   /* stamp on a trailing . */
    suboid_len = MAX_OID_LEN;
    if (!snmp_parse_oid(subtree, suboid, &suboid_len)) {
        return;
    }
    if (mask) {
        int             val;
        i = 0;
        for (mask = strtok(mask, " .:"); mask; mask = strtok(NULL, " .:")) {
            if ((unsigned int)i >= sizeof(viewMask)) {
                return;
            }
            if (sscanf(mask, "%x", &val) == 0) {
                return;
            }
            viewMask[i] = val;
            i++;
        }
        mask_len = i;
    } else {
        for (i = 0; (unsigned int)i < sizeof(viewMask); i++)
            viewMask[i] = 0xff;
    }
    vp = vacm_createViewEntry(name, suboid, suboid_len);
    if (!vp) {
        return;
    }
    memcpy(vp->viewMask, viewMask, sizeof(viewMask));
    vp->viewMaskLen = mask_len;
    vp->viewType = inclexcl;
    vp->viewStorageType = SNMP_STORAGE_PERMANENT;
    vp->viewStatus = SNMP_ROW_ACTIVE;
    free(vp->reserved);
    vp->reserved = NULL;
}

void
NetSnmpAgent::vacm_free_view(void)
{
    vacm_destroyAllViewEntries();
}

void
NetSnmpAgent::vacm_gen_com2sec(int commcount, const char* community, const char* addressname,
                 const char* publishtoken,
                 void (NetSnmpAgent::*parser)(const char* , char*),
                 char* secname, size_t secname_len,
                 char* viewname, size_t viewname_len, int version)
{
    char            line[SPRINT_MAX_LEN];

    /*
     * com2sec6|comsec anonymousSecNameNUM    ADDRESS  COMMUNITY
     */
    snprintf(secname, secname_len-1, "comm%d", commcount);
    secname[secname_len-1] = '\0';
    if (viewname) {
        snprintf(viewname, viewname_len-1, "viewComm%d", commcount);
        viewname[viewname_len-1] = '\0';
    }
    snprintf(line, sizeof(line), "%s %s '%s'",
             secname, addressname, community);
    line[ sizeof(line)-1 ] = 0;
    (*this.*parser)(publishtoken, line);

    /*
     * sec->group mapping
     */
    /*
     * group   anonymousGroupNameNUM  any      anonymousSecNameNUM
     */
    if (version & SNMP_SEC_MODEL_SNMPv1) {
        snprintf(line, sizeof(line),
             "grp%.28s v1 %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        vacm_parse_group("group", line);
    }

    if (version & SNMP_SEC_MODEL_SNMPv2c) {
        snprintf(line, sizeof(line),
             "grp%.28s v2c %s", secname, secname);
        line[ sizeof(line)-1 ] = 0;
        vacm_parse_group("group", line);
    }
}

void
NetSnmpAgent::vacm_parse_rwuser(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_READ_BIT | VACM_VIEW_WRITE_BIT);
}

void
NetSnmpAgent::vacm_parse_rouser(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_READ_BIT);
}

void
NetSnmpAgent::vacm_parse_rocommunity(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_READ_BIT);
}

void
NetSnmpAgent::vacm_parse_rwcommunity(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_READ_BIT | VACM_VIEW_WRITE_BIT);
}

void
NetSnmpAgent::vacm_parse_rocommunity6(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_READ_BIT);
}

void
NetSnmpAgent::vacm_parse_rwcommunity6(const char* token, char* confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_READ_BIT | VACM_VIEW_WRITE_BIT);
}


void
NetSnmpAgent::netsnmp_udp_parse_security(const char* token, char* param)
{
    char            secName[VACMSTRINGLEN];
    char            contextName[VACMSTRINGLEN];
    char            community[COMMUNITY_MAX_LEN];
    char            source[SNMP_MAXBUF_SMALL];
    char*           cp = NULL;
    const char*     strmask = NULL;
    com2SecEntry*   e = NULL;
    in_addr_t   network = 0, mask = 0;

    /*
     * Get security, source address/netmask and community strings.
     */

    cp = copy_nword(param, secName, sizeof(secName));
    if (strcmp(secName, "-Cn") == 0) {
        if (!cp) {
            return;
        }
        cp = copy_nword(cp, contextName, sizeof(contextName));
        cp = copy_nword(cp, secName, sizeof(secName));
    } else {
        contextName[0] = '\0';
    }
    if (secName[0] == '\0') {
        return;
    } else if (strlen(secName) > (VACMSTRINGLEN - 1)) {
        return;
    }
    cp = copy_nword(cp, source, sizeof(source));
    if (source[0] == '\0') {
        return;
    } else if (strncmp(source, EXAMPLE_NETWORK, strlen(EXAMPLE_NETWORK)) ==
               0) {
        return;
    }
    cp = copy_nword(cp, community, sizeof(community));
    if (community[0] == '\0') {
        return;
    } else
        if (strncmp
            (community, EXAMPLE_COMMUNITY, strlen(EXAMPLE_COMMUNITY))
            == 0) {
        return;
    } else if (strlen(community) > (COMMUNITY_MAX_LEN - 1)) {
        return;
    }

    /*
     * Process the source address/netmask string.
     */

    cp = strchr(source, '/');
    if (cp != NULL) {
        /*
         * Mask given.
         */
        *cp = '\0';
        strmask = cp + 1;
    }

    /*
     * Deal with the network part first.
     */

    if ((strcmp(source, "default") == 0)
        || (strcmp(source, "0.0.0.0") == 0)) {
        network = 0;
        strmask = "0.0.0.0";
    } else {
        /*
         * Try interpreting as a dotted quad.
         */
        network = 0;

        if (network == (in_addr_t) -1) {
            /*
             * Nope, wasn't a dotted quad.  Must be a hostname.
             */
            int ret = netsnmp_gethostbyname_v4(source, &network);
            if (ret < 0) {
                return;
            }
        }
    }

    /*
     * Now work out the mask.
     */

    if (strmask == NULL || *strmask == '\0') {
        /*
         * No mask was given.  Use 255.255.255.255.
         */
        mask = 0xffffffffL;
    } else {
        if (strchr(strmask, '.')) {
            /*
             * Try to interpret mask as a dotted quad.
             */
            mask = 0;
            if (mask == (in_addr_t) -1 &&
                strncmp(strmask, "255.255.255.255", 15) != 0) {
                return;
            }
        } else {
            /*
             * Try to interpret mask as a "number of 1 bits".
             */
            int             maskLen = atoi(strmask), maskBit = 0x80000000L;
            if (maskLen <= 0 || maskLen > 32) {
                return;
            }
            while (maskLen--) {
                mask |= maskBit;
                maskBit >>= 1;
            }
            EXTERNAL_hton(&mask, sizeof(mask));
        }
    }

    /*
     * Check that the network and mask are consistent.
     */

    if (network & ~mask) {
        return;
    }

    e = (com2SecEntry*) malloc(sizeof(com2SecEntry));
    if (e == NULL) {
        return;
    }

    /*
     * Everything is okay.  Copy the parameters to the structure allocated
     * above and add it to END of the list.
     */


    strcpy(e->contextName, contextName);
    strcpy(e->secName, secName);
    strcpy(e->community, community);
    e->network = network;
    e->mask = mask;
    e->next = NULL;

    if (com2SecListLast != NULL) {
        com2SecListLast->next = e;
        com2SecListLast = e;
    } else {
        com2SecListLast = com2SecList = e;
    }
}


void
NetSnmpAgent::netsnmp_udp_com2SecList_free(void)
{
    com2SecEntry*   e = com2SecList;
    while (e != NULL) {
        com2SecEntry*   tmp = e;
        e = e->next;
        free(tmp);
    }
    com2SecList = com2SecListLast = NULL;
}


void
NetSnmpAgent::vacm_create_simple(const char* token, char* confline,
                   int parsetype, int viewtypes)
{
    char            line[SPRINT_MAX_LEN];
    char            community[COMMUNITY_MAX_LEN];
    char            theoid[SPRINT_MAX_LEN];
    char            viewname[SPRINT_MAX_LEN];
    char*           view_ptr = viewname;
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    char            addressname[SPRINT_MAX_LEN];
#endif
    const char*     rw = "none";
    char            model[SPRINT_MAX_LEN];
    char*           cp, *tmp;
    char            secname[SPRINT_MAX_LEN];
    char            grpname[SPRINT_MAX_LEN];
    char            authlevel[SPRINT_MAX_LEN];
    char            context[SPRINT_MAX_LEN];
    int             ctxprefix = 1;  /* Default to matching all contexts */
    static int      commcount = 0;
    /* Conveniently, the community-based security
       model values can also be used as bit flags */
    int             commversion = SNMP_SEC_MODEL_SNMPv1 |
                                  SNMP_SEC_MODEL_SNMPv2c;

    /*
     * init
     */
    strcpy(model, "any");
    memset(context, 0, sizeof(context));
    memset(secname, 0, sizeof(secname));
    memset(grpname, 0, sizeof(grpname));

    /*
     * community name or user name
     */
    cp = copy_nword(confline, community, sizeof(community));

    if (parsetype == VACM_CREATE_SIMPLE_V3) {
        /*
         * maybe security model type
         */
        if (strcmp(community, "-s") == 0) {
            /*
             * -s model ...
             */
            if (cp)
                cp = copy_nword(cp, model, sizeof(model));
            if (!cp) {
                return;
            }
            if (cp)
                cp = copy_nword(cp, community, sizeof(community));
        } else {
            strcpy(model, "usm");
        }
        /*
         * authentication level
         */
        if (cp && *cp)
            cp = copy_nword(cp, authlevel, sizeof(authlevel));
        else
            strcpy(authlevel, "auth");
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    } else {
        if (strcmp(community, "-v") == 0) {
            /*
             * -v version ...
             */
            if (cp)
                cp = copy_nword(cp, model, sizeof(model));
            if (!cp) {
                return;
            }
            if (strcasecmp(model,  "1") == 0)
                strcpy(model, "v1");
            if (strcasecmp(model, "v1") == 0)
                commversion = SNMP_SEC_MODEL_SNMPv1;
            if (strcasecmp(model,  "2c") == 0)
                strcpy(model, "v2c");
            if (strcasecmp(model, "v2c") == 0)
                commversion = SNMP_SEC_MODEL_SNMPv2c;
            if (cp)
                cp = copy_nword(cp, community, sizeof(community));
        }
        /*
         * source address
         */
        if (cp && *cp) {
            cp = copy_nword(cp, addressname, sizeof(addressname));
        } else {
            strcpy(addressname, "default");
        }
        /*
         * authlevel has to be noauth
         */
        strcpy(authlevel, "noauth");
#endif /* support for community based SNMP */
    }

    /*
     * oid they can touch
     */
    if (cp && *cp) {
        if (strncmp(cp, "-V ", 3) == 0) {
             cp = skip_token(cp);
             cp = copy_nword(cp, viewname, sizeof(viewname));
             view_ptr = NULL;
        } else {
             cp = copy_nword(cp, theoid, sizeof(theoid));
        }
    } else {
        strcpy(theoid, ".1");
        strcpy(viewname, "_all_");
        view_ptr = NULL;
    }
    /*
     * optional, non-default context
     */
    if (cp && *cp) {
        cp = copy_nword(cp, context, sizeof(context));
        tmp = (context + strlen(context)-1);
        if (tmp && *tmp == '*') {
            *tmp = '\0';
            ctxprefix = 1;
        } else {
            /*
             * If no context field is given, then we default to matching
             *   all contexts (for compatability with previous releases).
             * But if a field context is specified (not ending with '*')
             *   then this should be taken as an exact match.
             * Specifying a context field of "" will match the default
             *   context (and *only* the default context).
             */
            ctxprefix = 0;
        }
    }

    if (viewtypes & VACM_VIEW_WRITE_BIT)
        rw = viewname;

    commcount++;

#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
    if (parsetype == VACM_CREATE_SIMPLE_COMIPV4 ||
        parsetype == VACM_CREATE_SIMPLE_COM) {
        vacm_gen_com2sec(commcount, community, addressname,
            "com2sec", &NetSnmpAgent::netsnmp_udp_parse_security,
                         secname, sizeof(secname),
                         view_ptr, sizeof(viewname), commversion);
    }

#ifdef NETSNMP_TRANSPORT_UNIX_DOMAIN
    if (parsetype == VACM_CREATE_SIMPLE_COMUNIX ||
        parsetype == VACM_CREATE_SIMPLE_COM) {
        snprintf(line, sizeof(line), "%s %s '%s'",
                 secname, addressname, community);
        line[ sizeof(line)-1 ] = 0;
        netsnmp_unix_parse_security("com2secunix", line);
    }
#endif

#ifdef NETSNMP_TRANSPORT_UDPIPV6_DOMAIN
    if (parsetype == VACM_CREATE_SIMPLE_COMIPV6 ||
        parsetype == VACM_CREATE_SIMPLE_COM) {
        vacm_gen_com2sec(commcount, community, addressname,
                         "com2sec6", &netsnmp_udp6_parse_security,
                         secname, sizeof(secname),
                         view_ptr, sizeof(viewname), commversion);
    }
#endif
#endif /* support for community based SNMP */

    if (parsetype == VACM_CREATE_SIMPLE_V3) {
        /* support for SNMPv3 user names */
        if (view_ptr) {
            sprintf(viewname,"viewUSM%d",commcount);
        }
        if (strcmp(token, "authgroup") == 0) {
            strncpy(grpname, community, sizeof(grpname));
            grpname[ sizeof(grpname)-1 ] = 0;
        } else {
            strncpy(secname, community, sizeof(secname));
            secname[ sizeof(secname)-1 ] = 0;

            /*
             * sec->group mapping
             */
            /*
             * group   anonymousGroupNameNUM  any      anonymousSecNameNUM
             */
            snprintf(grpname, sizeof(grpname), "grp%.28s", secname);
            for (tmp=grpname; *tmp; tmp++)
                if (!isalnum(*tmp))
                    *tmp = '_';
            snprintf(line, sizeof(line),
                     "%s %s \"%s\"", grpname, model, secname);
            line[ sizeof(line)-1 ] = 0;
            vacm_parse_group("group", line);
        }
    } else {
        snprintf(grpname, sizeof(grpname), "grp%.28s", secname);
        for (tmp=grpname; *tmp; tmp++)
            if (!isalnum(*tmp))
                *tmp = '_';
    }

    /*
     * view definition
     */
    /*
     * view    anonymousViewNUM       included OID
     */
    if (view_ptr) {
        snprintf(line, sizeof(line), "%s included %s", viewname, theoid);
        line[ sizeof(line)-1 ] = 0;
        vacm_parse_view("view", line);
    }

    /*
     * map everything together
     */
    if ((viewtypes == VACM_VIEW_READ_BIT) ||
        (viewtypes == (VACM_VIEW_READ_BIT | VACM_VIEW_WRITE_BIT))) {
        /* Use the simple line access command */
        /*
         * access  anonymousGroupNameNUM  "" MODEL AUTHTYPE prefix anonymousViewNUM [none/anonymousViewNUM] [none/anonymousViewNUM]
         */
        snprintf(line, sizeof(line),
                 "%s %s %s %s %s %s %s %s",
                 grpname, context[0] ? context : "\"\"",
                 model, authlevel,
                (ctxprefix ? "prefix" : "exact"),
                 viewname, rw, rw);
        line[ sizeof(line)-1 ] = 0;
        vacm_parse_access("access", line);
    } else {
        /* Use one setaccess line per access type */
        /*
         * setaccess  anonymousGroupNameNUM  "" MODEL AUTHTYPE prefix viewname viewval
         */
        int i;
        for (i = 0; i <= VACM_MAX_VIEWS; i++) {
            if (viewtypes & (1 << i)) {
                snprintf(line, sizeof(line),
                         "%s %s %s %s %s %s %s",
                         grpname, context[0] ? context : "\"\"",
                         model, authlevel,
                        (ctxprefix ? "prefix" : "exact"),
                         se_find_label_in_slist(VACM_VIEW_ENUM_NAME, i),
                         viewname);
                line[ sizeof(line)-1 ] = 0;
                vacm_parse_setaccess("setaccess", line);
            }
        }
    }
}

int
NetSnmpAgent::vacm_standard_views(int majorID, int minorID, void* serverarg,
                            void* clientarg)
{
    char            line[SPRINT_MAX_LEN];

    memset(line, 0, sizeof(line));

    snprintf(line, sizeof(line), "_all_ included .0");
    vacm_parse_view("view", line);
    snprintf(line, sizeof(line), "_all_ included .1");
    vacm_parse_view("view", line);
    snprintf(line, sizeof(line), "_all_ included .2");
    vacm_parse_view("view", line);

    snprintf(line, sizeof(line), "_none_ excluded .0");
    /*vacm_parse_view("view", line);*/
    snprintf(line, sizeof(line), "_none_ excluded .1");
    vacm_parse_view("view", line);
    snprintf(line, sizeof(line), "_none_ excluded .2");
    vacm_parse_view("view", line);

    return SNMP_ERR_NOERROR;
}

int
NetSnmpAgent::vacm_warn_if_not_configured(int majorID, int minorID, void* serverarg,
                            void* clientarg)
{
    const char*  name = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                        NETSNMP_DS_LIB_APPTYPE);
    const int agent_mode =  netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                                   NETSNMP_DS_AGENT_ROLE);
    if (NULL==name)
        name = "snmpd";

    if (!vacm_is_configured()) {
        /*
         *  An AgentX subagent relies on the master agent to apply suitable
         *    access control checks, so doesn't need local VACM configuration.
         *  The trap daemon has a separate check (see below).
         *
         *  Otherwise, an AgentX master or SNMP standalone agent requires some
         *    form of VACM configuration.  No config means that no incoming
         *    requests will be accepted, so warn the user accordingly.
         */
        if ((MASTER_AGENT == agent_mode) && (strcmp(name, "snmptrapd") != 0)) {
            /*snmp_log(LOG_WARNING,
                 "Warning: no access control information configured.\n  It's "
                 "unlikely this agent can serve any useful purpose in this "
                 "state.\n  Run \"snmpconf -g basic_setup\" to help you "
                 "configure the %s.conf file for this agent.\n", name);*/
        }

        /*
         *  The trap daemon implements VACM-style access control for incoming
         *    notifications, but offers a way of turning this off (for backwards
         *    compatability).  Check for this explicitly, and warn if necessary.
         *
         *  NB:  The NETSNMP_DS_APP_NO_AUTHORIZATION definition is a duplicate
         *       of an identical setting in "apps/snmptrapd_ds.h".
         *       These two need to be kept in synch.
         */
#ifndef NETSNMP_DS_APP_NO_AUTHORIZATION
#define NETSNMP_DS_APP_NO_AUTHORIZATION 17
#endif
        if (!strcmp(name, "snmptrapd") &&
            !netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                    NETSNMP_DS_APP_NO_AUTHORIZATION)) {
            /*snmp_log(LOG_WARNING,
                 "Warning: no access control information configured.\n"
                 "This receiver will *NOT* accept any incoming notifications.\n");*/
        }
    }
    return SNMP_ERR_NOERROR;
}

int
NetSnmpAgent::vacm_in_view_callback(int majorID, int minorID, void* serverarg,
                      void* clientarg)
{
    struct view_parameters* view_parms =
        (struct view_parameters*) serverarg;
    int             retval;

    if (view_parms == NULL)
        return 1;
    retval = vacm_in_view(view_parms->pdu, view_parms->name,
                          view_parms->namelen, view_parms->check_subtree);
    if (retval != 0)
        view_parms->errorcode = retval;
    return retval;
}


/**
 * vacm_in_view: decides if a given PDU can be acted upon
 *
 * Parameters:
 *    *pdu
 *    *name
 *     namelen
 *       check_subtree
 *
 * Returns:
 * VACM_SUCCESS(0)       On success.
 * VACM_NOSECNAME(1)       Missing security name.
 * VACM_NOGROUP(2)       Missing group
 * VACM_NOACCESS(3)       Missing access
 * VACM_NOVIEW(4)       Missing view
 * VACM_NOTINVIEW(5)       Not in view
 * VACM_NOSUCHCONTEXT(6)   No Such Context
 * VACM_SUBTREE_UNKNOWN(7) When testing an entire subtree, UNKNOWN (ie, the entire
 *                         subtree has both allowed and disallowed portions)
 *
 * Debug output listed as follows:
 *    \<securityName\> \<groupName\> \<viewName\> \<viewType\>
 */
int
NetSnmpAgent::vacm_in_view(netsnmp_pdu* pdu, oid*  name, size_t namelen,
             int check_subtree)
{
    int viewtype;

    switch (pdu->command) {
    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_GETBULK:
        viewtype = VACM_VIEW_READ;
        break;
    case SNMP_MSG_SET:
        viewtype = VACM_VIEW_WRITE;
        break;
    case SNMP_MSG_TRAP:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_INFORM:
        viewtype = VACM_VIEW_NOTIFY;
        break;
    default:
        viewtype = VACM_VIEW_READ;
    }
    return vacm_check_view(pdu, name, namelen, check_subtree, viewtype);
}

/**
 * vacm_check_view: decides if a given PDU can be taken based on a view type
 *
 * Parameters:
 *    *pdu
 *    *name
 *     namelen
 *       check_subtree
 *       viewtype
 *
 * Returns:
 * VACM_SUCCESS(0)       On success.
 * VACM_NOSECNAME(1)       Missing security name.
 * VACM_NOGROUP(2)       Missing group
 * VACM_NOACCESS(3)       Missing access
 * VACM_NOVIEW(4)       Missing view
 * VACM_NOTINVIEW(5)       Not in view
 * VACM_NOSUCHCONTEXT(6)   No Such Context
 * VACM_SUBTREE_UNKNOWN(7) When testing an entire subtree, UNKNOWN (ie, the entire
 *                         subtree has both allowed and disallowed portions)
 *
 * Debug output listed as follows:
 *    \<securityName\> \<groupName\> \<viewName\> \<viewType\>
 */
int
NetSnmpAgent::vacm_check_view(netsnmp_pdu* pdu, oid*  name, size_t namelen,
                int check_subtree, int viewtype)
{
    return vacm_check_view_contents(pdu, name, namelen, check_subtree, viewtype,
                                    VACM_CHECK_VIEW_CONTENTS_NO_FLAGS);
}


#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
int
NetSnmpAgent::netsnmp_udp_getSecName(void* opaque, int olength,
                       const char* community,
                       size_t community_len, char** secName,
                       char** contextName)
{
    com2SecEntry*   c;
    char*           ztcommunity = NULL;

    if (secName != NULL) {
        *secName = NULL;  /* Haven't found anything yet */
    }

    /*
     * Special case if there are NO entries (as opposed to no MATCHING
     * entries).
     */

    if (com2SecList == NULL) {
        return 0;
    }

    /*
     * If there is no IPv4 source address, then there can be no valid security
     * name.
     */

    for (c = com2SecList; c != NULL; c = c->next) {
        if ((community_len == strlen(c->community)) &&
        (memcmp(community, c->community, community_len) == 0)) {
            if (secName != NULL) {
                *secName = c->secName;
                *contextName = c->contextName;
            }
            break;
        }
    }
    if (ztcommunity != NULL) {
        free(ztcommunity);
    }
    return 1;
}
#endif /* support for community based SNMP */


int
NetSnmpAgent::vacm_check_view_contents(netsnmp_pdu* pdu, oid*  name, size_t namelen,
                         int check_subtree, int viewtype, int flags)
{
    struct vacm_accessEntry* ap;
    struct vacm_groupEntry* gp;
    struct vacm_viewEntry* vp;
    char            vacm_default_context[1] = "";
    char*           contextName = vacm_default_context;
    char*           sn = NULL;
    char*           vn;
    const char*     pdu_community;

    /*
     * len defined by the vacmContextName object
     */
#define CONTEXTNAMEINDEXLEN 32
    char            contextNameIndex[CONTEXTNAMEINDEXLEN + 1];

#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)

    if (pdu->version == SNMP_VERSION_1 || pdu->version == SNMP_VERSION_2c)
    {
        pdu_community = (const char*)pdu->community;
        if (!pdu_community)
            pdu_community = "";
            char*           buf;
            if (pdu->community) {
                buf = (char*) MEM_malloc(1 + pdu->community_len);
                memcpy(buf, pdu->community, pdu->community_len);
                buf[pdu->community_len] = '\0';
            } else {
                buf = strdup("NULL");
            }

            free(buf);

        /*
         * Okay, if this PDU was received from a UDP or a TCP transport then
         * ask the transport abstraction layer to map its source address and
         * community string to a security name for us.
         */

            if (!netsnmp_udp_getSecName(pdu->transport_data,
                                        pdu->transport_data_length,
                                        pdu_community,
                                        pdu->community_len, &sn,
                                        &contextName)) {

                sn = NULL;
            }
            /* force the community -> context name mapping here */
            SNMP_FREE(pdu->contextName);
            pdu->contextName = strdup(contextName);
            pdu->contextNameLen = strlen(contextName);



    } else
#endif /* support for community based SNMP */
      if (find_sec_mod(pdu->securityModel)) {
        /*
         * any legal defined v3 security model
         */
        sn = pdu->securityName;
        contextName = pdu->contextName;
    } else {
        sn = NULL;
    }

    if (sn == NULL) {
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
        snmp_increment_statistic(STAT_SNMPINBADCOMMUNITYNAMES);
#endif
        return VACM_NOSECNAME;
    }

    if (pdu->contextNameLen > CONTEXTNAMEINDEXLEN) {
        return VACM_NOSUCHCONTEXT;
    }
    /*
     * NULL termination of the pdu field is ugly here.  Do in PDU parsing?
     */
    if (pdu->contextName)
        strncpy(contextNameIndex, pdu->contextName, pdu->contextNameLen);
    else
        contextNameIndex[0] = '\0';

    contextNameIndex[pdu->contextNameLen] = '\0';
    if (!(flags & VACM_CHECK_VIEW_CONTENTS_DNE_CONTEXT_OK) &&
        !netsnmp_subtree_find_first(contextNameIndex)) {
        return VACM_NOSUCHCONTEXT;
    }


    gp = vacm_getGroupEntry(pdu->securityModel, sn);
    if (gp == NULL) {
        return VACM_NOGROUP;
    }

    ap = vacm_getAccessEntry(gp->groupName, contextNameIndex,
                             pdu->securityModel, pdu->securityLevel);
    if (ap == NULL) {
        return VACM_NOACCESS;
    }

    if (name == NULL) { /* only check the setup of the vacm for the request */
        return VACM_SUCCESS;
    }

    if (viewtype < 0 || viewtype >= VACM_MAX_VIEWS) {
        return VACM_NOACCESS;
    }
    vn = ap->views[viewtype];

    if (check_subtree) {
        return vacm_checkSubtree(vn, name, namelen);
    }

    vp = vacm_getViewEntry(vn, name, namelen, VACM_MODE_FIND);

    if (vp == NULL) {
        return VACM_NOVIEW;
    }

    if (vp->viewType == SNMP_VIEW_EXCLUDED) {
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
#if defined(NETSNMP_DISABLE_SNMPV1)
        if (pdu->version == SNMP_VERSION_2c)
#else
#if defined(NETSNMP_DISABLE_SNMPV2C)
        if (pdu->version == SNMP_VERSION_1)
#else
        if (pdu->version == SNMP_VERSION_1 || pdu->version == SNMP_VERSION_2c)
#endif
#endif
        {
            snmp_increment_statistic(STAT_SNMPINBADCOMMUNITYUSES);
        }
#endif
        return VACM_NOTINVIEW;
    }

    return VACM_SUCCESS;

}                               /* end vacm_in_view() */
