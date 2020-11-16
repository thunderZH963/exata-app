#ifndef NET_SNMP_PDU_API_H
#define NET_SNMP_PDU_API_H

    /**
     *  Library API routines concerned with SNMP PDUs.
     */

#include "types_netsnmp.h"

netsnmp_pdu*    snmp_pdu_create(int type);
netsnmp_pdu*    snmp_fix_pdu(netsnmp_pdu* pdu, int idx);

    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

#include "snmp_api_netsnmp.h"
#include "snmp_client_netsnmp.h"
#include "asn1_netsnmp.h"

#endif                          /* NET_SNMP_PDU_API_H */


