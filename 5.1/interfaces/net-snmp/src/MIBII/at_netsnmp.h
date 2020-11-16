#ifndef AT_NETSNMP
#define AT_NETSNMP

#define ATIFINDEX    0
#define ATPHYSADDRESS    1
#define ATNETADDRESS    2

#define IPMEDIAIFINDEX          0
#define IPMEDIAPHYSADDRESS      1
#define IPMEDIANETADDRESS       2
#define IPMEDIATYPE             3
#include "snmp_vars_netsnmp.h"

FindVarMethod var_atEntry;
FindVarMethod var_at;


#endif
