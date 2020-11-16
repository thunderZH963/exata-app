#include "net-snmp-config_netsnmp.h"
#include "asn1_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "string.h"
#include "netSnmpAgent.h"
#include "snmp_api_netsnmp.h"
#include "snmp_vars_netsnmp.h"
#include "ip_netsnmp.h"
#include "at_netsnmp.h"

oid             at_var_oid[] = { SNMP_OID_MIB2, 3, 1, 1 };

struct variable1 at_var[] = {
    {ATIFINDEX, ASN_INTEGER, 0x1,
     var_at, 1, {1}},
    {ATPHYSADDRESS, ASN_OCTET_STR, 0x1,
     var_at, 1, {2}},
    {ATNETADDRESS, ASN_IPADDRESS, 0x1,
     var_at, 1, {3}}
};

void
NetSnmpAgent::init_at(void)
{
#ifdef SNMP_DEBUG
    printf("init_at:Initializing MIBII/at at node %d\n",node->nodeId);
#endif
    REGISTER_MIB("mibII/at", at_var, variable1, at_var_oid);
}

u_char*
var_atEntry(struct variable* vp,
            oid* name,
            size_t* length,
            int exact,
            u_char*  var_buf,
            size_t* var_len,
            WriteMethod** write_method,
            Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_atEntry:handler MIBII/atEntry at node %d\n",node->nodeId);
#endif
    /*
     * Address Translation table object identifier is of form:
     * 1.3.6.1.2.1.3.1.?.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     *
     * IP Net to Media table object identifier is of form:
     * 1.3.6.1.2.1.4.22.1.?.interface.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 11.
     */

    memcpy(name, vp->name, (int) vp->namelen * sizeof(oid));
    *length=(int) vp->namelen;

    *write_method = 0;
    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    switch (vp->magic) {
    case IPMEDIAIFINDEX:       /* also ATIFINDEX */
        return (u_char*) long_return;
        break;
    case IPMEDIAPHYSADDRESS:   /* also ATPHYSADDRESS */
        return (u_char*) long_return;
        break;
    case IPMEDIANETADDRESS:    /* also ATNETADDRESS */
        return (u_char*) long_return;
        break;
    case IPMEDIATYPE:
        return (u_char*) long_return;
        break;
    default:
         break;
    }
    return NO_MIBINSTANCE;
}



u_char*
var_at(struct variable* vp,
       oid* name,
       size_t* length,
       int exact,
       u_char* var_buf,
       size_t* var_len,
       WriteMethod** write_method,
       Node* node)
{
#ifdef SNMP_DEBUG
    printf("var_at:handler MIBII/at at node %d\n",node->nodeId);
#endif
    /*
     * Address Translation table object identifier is of form:
     * 1.3.6.1.2.1.3.1.?.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     *
     * IP Net to Media table object identifier is of form:
     * 1.3.6.1.2.1.4.22.1.?.interface.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 11.
     */

    memcpy(name, vp->name, (int) vp->namelen * sizeof(oid));
    *length=(int) vp->namelen;

    //length has been incremented to include the interface index in the OID
    if (*length == 10)
    {
        (*length)++;
    }

    if (name[7] != vp->name[7])
    {
        name[7] = vp->name[7];
    }

    *write_method = 0;
    Int32* long_return = (Int32*) var_buf;
    *long_return = 0;
    *var_len = sizeof(Int32);

    switch (vp->magic) {
    case IPMEDIAIFINDEX:       /* also ATIFINDEX */
        return (u_char*) long_return;
        break;
    case IPMEDIAPHYSADDRESS:   /* also ATPHYSADDRESS */
        return (u_char*) long_return;
        break;
    case IPMEDIANETADDRESS:    /* also ATNETADDRESS */
        return (u_char*) long_return;
        break;
    case IPMEDIATYPE:
        return (u_char*) long_return;
        break;
    default:
         break;
    }
    return NO_MIBINSTANCE;
}
