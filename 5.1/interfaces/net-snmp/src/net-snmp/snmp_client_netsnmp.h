#ifndef SNMP_CLIENT_H_NETSNMP
#define SNMP_CLIENT_H_NETSNMP

#include "varbind_api_netsnmp.h"
#include "pdu_api_netsnmp.h"

#define STAT_SUCCESS    0
#define STAT_ERROR    1
#define STAT_TIMEOUT 2

struct synch_state {
        int             waiting;
        int             status;
        /*
         * status codes
         */
#define STAT_SUCCESS    0
#define STAT_ERROR    1
#define STAT_TIMEOUT 2
        int             reqid;
        netsnmp_pdu*    pdu;
    };



netsnmp_variable_list* find_varbind_in_list (netsnmp_variable_list* vblist,
                                            oid* name, size_t len);
int   snmp_clone_mem(void** , const void* , unsigned);

netsnmp_pdu*
    _copy_pdu_vars(
        netsnmp_pdu* pdu,        /* source PDU */
                            netsnmp_pdu* newpdu,     /* target PDU */
                            int drop_err,    /* !=0 drop errored variable */
                            int skip_count,  /* !=0 number of variables to skip */
                            int copy_count);

int snmp_synch_input(int op, netsnmp_session*  session,
                            int reqid, netsnmp_pdu* pdu, void* magic);
 int
snmp_set_var_typed_integer(netsnmp_variable_list*  newvar,
                           u_char type, long val);

int
snmp_set_var_typed_value(netsnmp_variable_list*  newvar, u_char type,
                         const void*  val_str, size_t val_len);
    int count_varbinds(netsnmp_variable_list*  var_ptr);

    void snmp_replace_var_types(netsnmp_variable_list*  vbl,
                                           u_char old_type,
                                           u_char new_type);

    int snmp_clone_var(netsnmp_variable_list* ,
                                   netsnmp_variable_list*);
 #endif /* SNMP_CLIENT_H_NETSNMP */


