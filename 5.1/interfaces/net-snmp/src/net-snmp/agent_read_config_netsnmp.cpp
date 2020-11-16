/*
 * agent_read_config.c
 */

#include "netSnmpAgent.h"
#include "default_store_netsnmp.h"
#include "ds_agent_netsnmp.h"
#include "read_config_netsnmp.h"

void
NetSnmpAgent::init_agent_read_config(const char* app)
{
    if (app != NULL) {
        netsnmp_ds_set_string(NETSNMP_DS_LIBRARY_ID,
                  NETSNMP_DS_LIB_APPTYPE, app);
    } else {
        app = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                    NETSNMP_DS_LIB_APPTYPE);
    }


    register_app_config_handler("authtrapenable",
        &NetSnmpAgent::snmpd_parse_config_authtrap, NULL,
                                "1 | 2\t\t(1 = enable, 2 = disable)");
    register_app_config_handler("pauthtrapenable",
                                &NetSnmpAgent::snmpd_parse_config_authtrap,
                                NULL, NULL);


    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_ROLE) == MASTER_AGENT) {
    }
    register_app_config_handler("trapcommunity",
                                &NetSnmpAgent::snmpd_parse_config_trapcommunity,
                                &NetSnmpAgent::snmpd_free_trapcommunity,
                                "community-string");
    netsnmp_ds_register_config(ASN_OCTET_STR, app, "v1trapaddress",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_TRAP_ADDR);
    register_app_config_handler("agentuser",
                                &NetSnmpAgent::snmpd_set_agent_user, NULL, "userid");
    register_app_config_handler("agentgroup",
                                &NetSnmpAgent::snmpd_set_agent_group, NULL, "groupid");
    register_app_config_handler("agentaddress",
                                &NetSnmpAgent::snmpd_set_agent_address, NULL,
                                "SNMP bind address");
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "quit",
                   NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_QUIT_IMMEDIATELY);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "leave_pidfile",
                   NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_LEAVE_PIDFILE);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "dontLogTCPWrappersConnects",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DONT_LOG_TCPWRAPPERS_CONNECTS);
    netsnmp_ds_register_config(ASN_INTEGER, app, "maxGetbulkRepeats",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_MAX_GETBULKREPEATS);
    netsnmp_ds_register_config(ASN_INTEGER, app, "maxGetbulkResponses",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_MAX_GETBULKRESPONSES);
    netsnmp_init_handler_conf();
}


void
NetSnmpAgent::snmpd_set_agent_user(const char* token, char* cptr)
{
#if defined(HAVE_GETPWNAM) && defined(HAVE_PWD_H)
    struct passwd*  info;
#endif
    if (cptr[0] == '#') {
        char*           ecp;
        int             uid;
        uid = strtoul(cptr + 1, &ecp, 10);
        if (*ecp != 0) {
            /*config_perror("Bad number");*/
    } else {
        netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_USERID, uid);
    }
    }
#if defined(HAVE_GETPWNAM) && defined(HAVE_PWD_H)
    else if ((info = getpwnam(cptr)) != NULL) {
        netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
               NETSNMP_DS_AGENT_USERID, info->pw_uid);
    } else {
        config_perror("User not found in passwd database");
    }
    endpwent();
#endif
}

void
NetSnmpAgent::snmpd_set_agent_group(const char* token, char* cptr)
{
#if defined(HAVE_GETGRNAM) && defined(HAVE_GRP_H)
    struct group*   info;
#endif

    if (cptr[0] == '#') {
        char*           ecp;
        int             gid = strtoul(cptr + 1, &ecp, 10);
        if (*ecp != 0) {
            /*config_perror("Bad number");*/
    } else {
            netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
                   NETSNMP_DS_AGENT_GROUPID, gid);
    }
    }
#if defined(HAVE_GETGRNAM) && defined(HAVE_GRP_H)
    else if ((info = getgrnam(cptr)) != NULL) {
        netsnmp_ds_set_int(NETSNMP_DS_APPLICATION_ID,
               NETSNMP_DS_AGENT_GROUPID, info->gr_gid);
    } else {
        config_perror("Group not found in group database");
    }
    endpwent();
#endif
}

void
NetSnmpAgent::snmpd_set_agent_address(const char* token, char* cptr)
{
    char            buf[SPRINT_MAX_LEN];
    char*           ptr;

    /*
     * has something been specified before?
     */
    ptr = netsnmp_ds_get_string(NETSNMP_DS_APPLICATION_ID,
                NETSNMP_DS_AGENT_PORTS);

    if (ptr) {
        /*
         * append to the older specification string
         */
        sprintf(buf, "%s,%s", ptr, cptr);
    } else {
        strcpy(buf, cptr);
    }

    netsnmp_ds_set_string(NETSNMP_DS_APPLICATION_ID,
              NETSNMP_DS_AGENT_PORTS, buf);
}


void
NetSnmpAgent::snmpd_register_config_handler(const char* token,
                              void (NetSnmpAgent::*parser) (const char* , char*),
                              void (NetSnmpAgent::*releaser) (void), const char* help)
{
    register_app_config_handler(token, parser, releaser, help);
}


/*
 * this function is intended for use by mib-modules to store permenant
 * configuration information generated by sets or persistent counters
 */
void
NetSnmpAgent::snmpd_store_config(const char* line)
{
    read_app_config_store(line);
}
