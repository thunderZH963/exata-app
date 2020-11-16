
#include "net-snmp-config_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "node.h"
#include "network_ip.h"
#include "agent_handler_netsnmp.h"
#include "snmp_netsnmp.h"
#include "var_struct_netsnmp.h"
#include "var_route_netsnmp.h"
#include "netSnmpAgent.h"
#include "scalar_group_netsnmp.h"
#include "sysORTable_netsnmp.h"
#include "snmp_api_netsnmp.h"

static const oid snmp_oid[] = { 1, 3, 6, 1, 2, 1, 11 };

int
handle_snmp(netsnmp_mib_handler* handler,
        netsnmp_handler_registration* reginfo,
        netsnmp_agent_request_info* reqinfo,
        netsnmp_request_info* requests, Node* node)
{
#ifdef SNMP_DEBUG
    printf("handle_snmp:handler MIBII/snmp at node %d\n",node->nodeId);
#endif
    netsnmp_request_info*  request;
    netsnmp_variable_list* requestvb;
    Int32     ret_value=-1;
    oid      subid;
    int      type = ASN_COUNTER;

            request=requests;
            requestvb = request->requestvb;
            subid = requestvb->name[OID_LENGTH(snmp_oid)];


switch (subid + 8) {
    case STAT_SNMPINPKTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPOUTPKTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPINBADVERSIONS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPINBADCOMMUNITYNAMES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPINBADCOMMUNITYUSES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPINASNPARSEERRS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
    case STAT_SNMPINTOOBIGS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
   case STAT_SNMPINTOTALREQVARS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPINTOTALSETVARS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
 case STAT_SNMPINGETREQUESTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
 case STAT_SNMPINGETNEXTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
 case STAT_SNMPINSETREQUESTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPINGETRESPONSES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
case STAT_SNMPINTRAPS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
 case STAT_SNMPOUTTOOBIGS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;

  case STAT_SNMPOUTNOSUCHNAMES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTBADVALUES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTGENERRS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTGETREQUESTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTGETNEXTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTSETREQUESTS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTGETRESPONSES:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case STAT_SNMPOUTTRAPS:
        {
        ret_value=(Int32)snmp_get_statistic(subid+8,node);
        }
        break;
  case AUTHTRAPENABLE :
       {
        ret_value=0;
        type=ASN_INTEGER;
       }
  default:
        ret_value=0;
        break;
}


snmp_set_var_typed_value(request->requestvb, (u_char)type,
                         (u_char*)&ret_value, sizeof(ret_value));
    return SNMP_ERR_NOERROR;
}

void
NetSnmpAgent::init_snmp_mib(void)
{
#ifdef SNMP_DEBUG
    printf("init_snmp_mib:Initializing MIBII/snmp at node %d\n",node->nodeId);
#endif
    netsnmp_handler_registration* reginfo;

    reginfo = netsnmp_create_handler_registration("mibII/snmp", handle_snmp, snmp_oid,
        OID_LENGTH(snmp_oid),HANDLER_CAN_RONLY);
    netsnmp_register_scalar_group(reginfo,1,30);


}
