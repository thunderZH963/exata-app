/*
 * security service wrapper to support pluggable security models
 */

#include <net-snmp-config_netsnmp.h>
#include <stdio.h>
#include <ctype.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "types_netsnmp.h"

#include "snmp_api_netsnmp.h"
#include "callback_netsnmp.h"
#include "snmp_secmod_netsnmp.h"
#include "netSnmpAgent.h"
#include "snmp_enum_netsnmp.h"
#include "snmpusm_netsnmp.h"
#include "system_netsnmp.h"
#include "tools_netsnmp.h"


void
NetSnmpAgent::init_secmod(void)
{
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_SESSION_INIT,
                           &NetSnmpAgent::set_default_secmod,
                           NULL);

    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defSecurityModel",
                   NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SECMODEL);
    /*
     * this file is generated by configure for all the stuff we're using
     */
#include "snmpsm_init_netsnmp.h"
}


int
NetSnmpAgent::register_sec_mod(int secmod, const char* modname,
                 struct snmp_secmod_def* newdef)
{
    int             result;
    struct snmp_secmod_list* sptr;
    char*           othername;

    for (sptr = registered_services; sptr; sptr = sptr->next) {
        if (sptr->securityModel == secmod) {
            return SNMPERR_GENERR;
        }
    }
    sptr = SNMP_MALLOC_STRUCT(snmp_secmod_list);
    if (sptr == NULL)
        return SNMPERR_MALLOC;
    sptr->secDef = newdef;
    sptr->securityModel = secmod;
    sptr->next = registered_services;
    registered_services = sptr;
    if ((result =
         se_add_pair_to_slist("snmp_secmods", strdup(modname), secmod))
        != SE_OK) {
        switch (result) {
        case SE_NOMEM:
            break;

        case SE_ALREADY_THERE:
            othername = se_find_label_in_slist("snmp_secmods", secmod);
            if (strcmp(othername, modname) != 0) {
            }
            break;

        default:
            break;
        }
        return SNMPERR_GENERR;
    }
    return SNMPERR_SUCCESS;
}

int
NetSnmpAgent::unregister_sec_mod(int secmod)
{
    struct snmp_secmod_list* sptr, *lptr;

    for (sptr = registered_services, lptr = NULL; sptr;
         lptr = sptr, sptr = sptr->next) {
        if (sptr->securityModel == secmod) {
            if (lptr)
                lptr->next = sptr->next;
            else
                registered_services = sptr->next;
        SNMP_FREE(sptr->secDef);
            SNMP_FREE(sptr);
            return SNMPERR_SUCCESS;
        }
    }
    /*
     * not registered
     */
    return SNMPERR_GENERR;
}

void
NetSnmpAgent::clear_sec_mod(void)
{
    struct snmp_secmod_list* tmp = registered_services, *next = NULL;

    while (tmp != NULL) {
    next = tmp->next;
    SNMP_FREE(tmp->secDef);
    SNMP_FREE(tmp);
    tmp = next;
    }
    registered_services = NULL;
}


struct snmp_secmod_def*
NetSnmpAgent::find_sec_mod(int secmod)
{
    struct snmp_secmod_list* sptr;

    for (sptr = registered_services; sptr; sptr = sptr->next) {
        if (sptr->securityModel == secmod) {
            return sptr->secDef;
        }
    }
    /*
     * not registered
     */
    return NULL;
}

int
NetSnmpAgent::set_default_secmod(int major, int minor, void* serverarg, void* clientarg)
{
    netsnmp_session* sess = (netsnmp_session*) serverarg;
    char*           cptr;
    int             model;

    if (!sess)
        return SNMPERR_GENERR;
    if (sess->securityModel == SNMP_DEFAULT_SECMODEL) {
        if ((cptr = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                      NETSNMP_DS_LIB_SECMODEL)) != NULL) {
            if ((model = se_find_value_in_slist("snmp_secmods", cptr))
        != SE_DNE) {
                sess->securityModel = model;
            } else {
                sess->securityModel = USM_SEC_MODEL_NUMBER;
                return SNMPERR_GENERR;
            }
        } else {
            sess->securityModel = USM_SEC_MODEL_NUMBER;
        }
    }
    return SNMPERR_SUCCESS;
}
