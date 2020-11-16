#ifndef MIB_H_NETSNMP
#define MIB_H_NETSNMP

#include "types_netsnmp.h"

#define MODULE_NOT_FOUND    0
#define MODULE_LOADED_OK    1
#define MODULE_ALREADY_LOADED    2

u_char
mib_to_asn_type(int mib_type);

#define NETSNMP_STRING_OUTPUT_GUESS  1
#define NETSNMP_STRING_OUTPUT_ASCII  2
#define NETSNMP_STRING_OUTPUT_HEX    3

#define NETSNMP_OID_OUTPUT_SUFFIX  1
#define NETSNMP_OID_OUTPUT_MODULE  2
#define NETSNMP_OID_OUTPUT_FULL    3
#define NETSNMP_OID_OUTPUT_NUMERIC 4
#define NETSNMP_OID_OUTPUT_UCD     5
#define NETSNMP_OID_OUTPUT_NONE    6

/*
 * Set default here as some uses of read_objid require valid pointer.
 */



int
build_oid(oid**  out, size_t*  out_len,
          oid*  prefix, size_t prefix_len, netsnmp_variable_list*  indexes);

int
snprint_objid(char* buf, size_t buf_len,
              const oid*  objid, size_t objidlen);

int
parse_one_oid_index(oid**  oidStart, size_t*  oidLen,
                    netsnmp_variable_list*  data, int complete);
#endif /* MIB_H_NETSNMP */
