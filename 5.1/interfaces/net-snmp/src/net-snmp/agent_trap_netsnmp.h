#ifndef AGENT_TRAP_H_NETSNMP
#define AGENT_TRAP_H_NETSNMP


#ifdef __cplusplus
extern          "C" {
#endif


void            send_trap_to_sess(snmp_session*  sess,
                                  netsnmp_pdu* template_pdu);
int
handle_inform_response(int op, netsnmp_session*  session,
                       int reqid, netsnmp_pdu* pdu,
                       void* magic);

    #ifdef __cplusplus
}



#endif
#endif                          /* AGENT_TRAP_H_NETSNMP */


