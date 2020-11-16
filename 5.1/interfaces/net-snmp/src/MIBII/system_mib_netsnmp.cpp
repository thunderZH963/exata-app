/*
 *  System MIB group implementation - system.c
 *
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


#include "system_mib_netsnmp.h"
#include "netSnmpAgent.h"
#include "node.h"
#include "snmp_client_netsnmp.h"
#include "watcher_netsnmp.h"
#include "scalar_netsnmp.h"
#include "updates_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "snmp_impl_netsnmp.h"
#include "tools_netsnmp.h"

        /*********************
     *
     *  Kernel & interface information,
     *   and internal forward declarations
     *
     *********************/



extern WriteMethod write_system;
oid sysObjID[]={1,3,6,1,2,1,1};

// start writable variables in system mib
#define MAX_WRITEABLE_SYSTEM_VAR_LEN 256
char SYSTEM_CONTACT_NETSNMP[MAX_WRITEABLE_SYSTEM_VAR_LEN]= "";
char SYSTEM_LOCATION_NETSNMP[MAX_WRITEABLE_SYSTEM_VAR_LEN]="";
//end



#if (defined (WIN32) && defined (HAVE_WIN32_PLATFORM_SDK)) || defined (mingw32)
static void     windowsOSVersionString(char [], size_t);
#endif

        /*********************
     *
     *  snmpd.conf config parsing
     *
     *********************/

int
write_systemContact(int action,
          u_char*  var_val,
          u_char var_val_type,
          size_t var_val_len, u_char*  statP, oid*  name, size_t length,Node* node)

{
#ifdef SNMP_DEBUG
    printf("write_systemContact:Write Method for variable:systemContact at node %d\n",node->nodeId);
#endif
   int  var, retval = SNMP_ERR_NOERROR;
   var = name[7];

    switch (action) {
        case RESERVE1:
          break;

        case RESERVE2:
          break;

        case FREE:
             /* Release any resources that have been allocated */
          break;

        case ACTION:
            sprintf(SYSTEM_CONTACT_NETSNMP,"%s",var_val);
            SYSTEM_CONTACT_NETSNMP[var_val_len]='\0';
            /*
              * The variable has been stored in 'value' for you to use,
              * and you have just been asked to do something with it.
              * Note that anything done here must be reversable in the UNDO case
              */
          break;

        case UNDO:
             /* Back out any changes made in the ACTION case */
          break;

        case COMMIT:
             /*
              * Things are working well, so it's now safe to make the change
              * permanently.  Make sure that anything done here can't fail!
              */
          break;
    }

return retval;
}



int
write_systemLocation(int action,
          u_char*  var_val,
          u_char var_val_type,
          size_t var_val_len, u_char*  statP, oid*  name, size_t length,Node* node)

{
#ifdef SNMP_DEBUG
    printf("write_systemLocation:Write Method for variable:systemLocation at node %d\n",node->nodeId);
#endif
   int  var, retval = SNMP_ERR_NOERROR;
   var = name[7];

    switch (action) {
        case RESERVE1:
          break;

        case RESERVE2:
          break;

        case FREE:
             /* Release any resources that have been allocated */
          break;

        case ACTION:
            sprintf(SYSTEM_LOCATION_NETSNMP,"%s",var_val);
            SYSTEM_LOCATION_NETSNMP[var_val_len]='\0';
            /*
              * The variable has been stored in 'value' for you to use,
              * and you have just been asked to do something with it.
              * Note that anything done here must be reversable in the UNDO case
              */
          break;

        case UNDO:
             /* Back out any changes made in the ACTION case */
          break;

        case COMMIT:
             /*
              * Things are working well, so it's now safe to make the change
              * permanently.  Make sure that anything done here can't fail!
              */
          break;
    }

return retval;
}



int
write_systemName(int action,
          u_char*  var_val,
          u_char var_val_type,
          size_t var_val_len, u_char*  statP, oid*  name, size_t length,Node* node)

{
#ifdef SNMP_DEBUG
    printf("write_systemName:Write Method for variable:systemName at node %d\n",node->nodeId);
#endif
   int  var, retval = SNMP_ERR_NOERROR;
   var = name[7];

    switch (action) {
        case RESERVE1:
          break;

        case RESERVE2:
          break;

        case FREE:
             /* Release any resources that have been allocated */
          break;

        case ACTION:
            sprintf(node->netSnmpAgent->SYSTEM_NAME_NETSNMP,"%s\\0",var_val);
            node->netSnmpAgent->SYSTEM_NAME_NETSNMP[var_val_len]='\0';
            /*
              * The variable has been stored in 'value' for you to use,
              * and you have just been asked to do something with it.
              * Note that anything done here must be reversable in the UNDO case
              */
          break;

        case UNDO:
             /* Back out any changes made in the ACTION case */
          break;

        case COMMIT:
             /*
              * Things are working well, so it's now safe to make the change
              * permanently.  Make sure that anything done here can't fail!
              */
          break;
    }

return retval;
}






void
NetSnmpAgent::system_parse_config_sysdescr(const char* token, char* cptr)
{
    if (strlen(cptr) >= sizeof(version_descr)) {
    } else if (strcmp(cptr, "\"\"") == 0) {
        version_descr[0] = '\0';
    } else {
        strcpy(version_descr, cptr);
    }
}

NETSNMP_STATIC_INLINE void
system_parse_config_string(const char* token, char* cptr,
                           const char* name, char* value, size_t size,
                           int* guard)
{
    if (*token == 'p' && strcasecmp(token + 1, name) == 0) {
        if (*guard < 0) {
            /*
             * This is bogus (and shouldn't happen anyway) -- the value is
             * already configured read-only.
             */
            /*snmp_log(LOG_WARNING,
                     "ignoring attempted override of read-only %s.0\n", name);*/
            return;
        } else {
            ++(*guard);
        }
    } else {
        if (*guard > 0) {
            /*
             * Fall through and copy in this value.
             */
        }
        *guard = -1;
    }

    if (strcmp(cptr, "\"\"") == 0) {
        *value = '\0';
    } else if (strlen(cptr) < size) {
        strcpy(value, cptr);
    }
}

void
NetSnmpAgent::system_parse_config_sysloc(const char* token, char* cptr)
{
    system_parse_config_string(token, cptr, "sysLocation", sysLocation,
                               sizeof(sysLocation), &sysLocationSet);
}

void
NetSnmpAgent::system_parse_config_syscon(const char* token, char* cptr)
{
    system_parse_config_string(token, cptr, "sysContact", sysContact,
                               sizeof(sysContact), &sysContactSet);
}

void
NetSnmpAgent::system_parse_config_sysname(const char* token, char* cptr)
{
    system_parse_config_string(token, cptr, "sysName", sysName,
                               sizeof(sysName), &sysNameSet);
}

void
NetSnmpAgent::system_parse_config_sysServices(const char* token, char* cptr)
{
    sysServices = atoi(cptr);
    sysServicesConfiged = 1;
}

void
NetSnmpAgent::system_parse_config_sysObjectID(const char* token, char* cptr)
{
    sysObjectIDLength = MAX_OID_LEN;
    if (!read_objid(cptr, sysObjectID, &sysObjectIDLength)) {
        memcpy(sysObjectID, version_sysoid, version_sysoid_len*  sizeof(oid));
        sysObjectIDLength = version_sysoid_len;
    }
}


        /*********************
     *
     *  Initialisation & common implementation functions
     *
     *********************/

oid             system_module_oid[] = { SNMP_OID_SNMPMODULES, 1 };
int             system_module_oid_len = OID_LENGTH(system_module_oid);
int             system_module_count = 0;

int
NetSnmpAgent::system_store(int a, int b, void* c, void* d)
{
    char            line[SNMP_MAXBUF_SMALL];

    if (sysLocationSet > 0) {
        snprintf(line, SNMP_MAXBUF_SMALL, "psyslocation %s", sysLocation);
        snmpd_store_config(line);
    }
    if (sysContactSet > 0) {
        snprintf(line, SNMP_MAXBUF_SMALL, "psyscontact %s", sysContact);
        snmpd_store_config(line);
    }
    if (sysNameSet > 0) {
        snprintf(line, SNMP_MAXBUF_SMALL, "psysname %s", sysName);
        snmpd_store_config(line);
    }

    return 0;
}

int
handle_sysServices(netsnmp_mib_handler* handler,
                   netsnmp_handler_registration* reginfo,
                   netsnmp_agent_request_info* reqinfo,
                   netsnmp_request_info* requests,
                   Node* node = NULL)
{
#if NETSNMP_NO_DUMMY_VALUES
    if (reqinfo->mode == MODE_GET && !sysServicesConfiged)
        netsnmp_request_set_error(requests, SNMP_NOSUCHINSTANCE);
#endif
    return SNMP_ERR_NOERROR;
}

int
handle_sysUpTime(netsnmp_mib_handler* handler,
                   netsnmp_handler_registration* reginfo,
                   netsnmp_agent_request_info* reqinfo,
                   netsnmp_request_info* requests,
                   Node* node = NULL)
{
    snmp_set_var_typed_integer(requests->requestvb, ASN_TIMETICKS,
                               netsnmp_get_agent_uptime(node));
    return SNMP_ERR_NOERROR;
}

struct variable1 system_variables[] = {
    {SYSDESCR, ASN_OCTET_STR, NETSNMP_OLDAPI_RONLY,
     var_system, 1, {1}},
    {SYSOBJECTID, ASN_OBJECT_ID, NETSNMP_OLDAPI_RONLY,
     var_system, 1, {2}},
    {SYSUPTIME, SNMP_TIMETICKS,NETSNMP_OLDAPI_RONLY,
     var_system, 1, {3}},
    {SYSCONTACT, ASN_OCTET_STR, NETSNMP_OLDAPI_RWRITE,
     var_system, 1, {4}},
    {SYSNAME, ASN_OCTET_STR, NETSNMP_OLDAPI_RWRITE,
     var_system, 1, {5}},
    {SYSLOCATION, ASN_OCTET_STR, NETSNMP_OLDAPI_RWRITE,
     var_system, 1, {6}},
    {SYSSERVICES, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
     var_system, 1, {7}}
};



oid             system_variables_oid[] = { SNMP_OID_MIB2,1};

void
NetSnmpAgent::init_system_mib(void)
{
#ifdef SNMP_DEBUG
    printf("init_system_mib:Initializing MIBII/system at node %d\n",node->nodeId);
#endif
 REGISTER_MIB("mibII/system", system_variables, variable1, system_variables_oid);

}



u_char*
var_system(struct variable* vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_system:handler MIBII/system at node %d\n",node->nodeId);
#endif
    memcpy(name,vp->name, (int) vp->namelen * sizeof(oid));
   (*length)= (int) vp->namelen;
    if (*length == 8)
    {
        (*length)++;
    }

    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    char st[256];

    if (name[*length-1] > 0)
    {
        return NO_MIBINSTANCE;
    }

    switch (vp->magic) {
    case SYSDESCR:
        sprintf(st,"%s nodeId:%d",
            (u_char*)node->netSnmpAgent->SYSTEM_NAME_NETSNMP,
            node->nodeId);
        *var_len = strlen(st);
        memcpy(var_buf, st, *var_len);
        return var_buf;
        break;
    case SYSOBJECTID:
        *var_len=(7*sizeof(int));
        return (u_char*) &sysObjID;
        break;
    case SYSUPTIME:
        *var_len=(sizeof(Int32));
        *long_return = netsnmp_get_agent_uptime(node);
        return (u_char*) long_return;
        break;
    case SYSCONTACT:
        *write_method = write_systemContact;
        *var_len=strlen(SYSTEM_CONTACT_NETSNMP);
        return (u_char*)SYSTEM_CONTACT_NETSNMP;
        break;
    case SYSNAME:
        *write_method = write_systemName;
        *var_len=strlen(node->netSnmpAgent->SYSTEM_NAME_NETSNMP);
        return (u_char*)node->netSnmpAgent->SYSTEM_NAME_NETSNMP;
        break;
    case SYSLOCATION:
        *write_method = write_systemLocation;
        *var_len=strlen(SYSTEM_LOCATION_NETSNMP);
        return (u_char*)SYSTEM_LOCATION_NETSNMP;
        break;
    case SYSSERVICES:
        return (u_char*) long_return;
        break;
    default:
         break;
    }
    return NO_MIBINSTANCE;

}
