#ifndef NET_SNMP_VARBIND_API_H_NETSNMP
#define NET_SNMP_VARBIND_API_H_NETSNMP



netsnmp_variable_list*
       snmp_clone_varbind(netsnmp_variable_list*  varlist);

void            snmp_free_var(netsnmp_variable_list* var);     /* frees just this one */
void            snmp_free_varbind(netsnmp_variable_list* varlist); /* frees all in list */

/* Setting Values */
int             snmp_set_var_value(netsnmp_variable_list*  var,
                                       const void*  value, size_t len);
int             snmp_set_var_objid(netsnmp_variable_list*  var,
                                       const oid*  name, size_t name_length);
    /* Creation */
netsnmp_variable_list*
    snmp_pdu_add_variable(netsnmp_pdu* pdu,
                    const oid*  name, size_t name_length,u_char type,
                    const void*  value, size_t len);
netsnmp_variable_list*
    snmp_varlist_add_variable(netsnmp_variable_list**  varlist,
                    const oid*  name, size_t name_length,u_char type,
                    const void*  value, size_t len);
#endif
