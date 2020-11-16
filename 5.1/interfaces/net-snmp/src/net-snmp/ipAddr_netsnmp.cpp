#include <net-snmp-config_netsnmp.h>
#include "asn1_netsnmp.h"
#include "ipAddr_netsnmp.h"
#include "string.h"
#include "snmp_api_netsnmp.h"
#include "node.h"
#include "network_ip.h"
#include "ip_netsnmp.h"


#define MAXIPDATAGRAMSIZE 65535

Int32 long_return;
#define FIRST_ITEM  0
unsigned char tempNodeAddr[4];
u_char*
var_ipAddrEntry(struct variable* vp,
                oid* name,
                size_t* length,
                int exact,
                u_char*  var_buf,
                size_t* var_len,
                WriteMethod** write_method,
                Node* node)
{
     /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */

    oid             lowest[14];
    oid             current[14], *op;
    int             lowinterface = -1;
    int i=0;

    static int vp_type;

    memcpy(current, vp->name, (int) vp->namelen*  sizeof(oid));
    vp_type=vp->type;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NodeAddress aaa;
    int interface_found=0;
    map<NodeAddress, IpInterfaceInfoType*> intfaceInfo;
    map<NodeAddress, IpInterfaceInfoType*>::iterator it;
    for (i=0; i < node->numberInterfaces; i++) {
        intfaceInfo.insert(pair<NodeAddress, IpInterfaceInfoType*>
            (NetworkIpGetInterfaceAddress(node, i), ip->interfaceInfo[i]));
    }

    for (it = intfaceInfo.begin(); it != intfaceInfo.end(); it++) {
        op = &current[10];
        aaa = it->first;
        EXTERNAL_hton(&aaa, sizeof(aaa));
        unsigned char*  qqq = (unsigned char*)&aaa;
        if (op[0] == qqq[0] && op[1] == qqq[1] &&
            op[2] == qqq[2] && op[3] == qqq[3])
        {
            interface_found = 1;
            break;
        }
    }
    if (interface_found != 1) return NULL;

    memcpy(name, current, 14 * sizeof(oid));
    *length = 14;

    *write_method = 0;
    *var_len = sizeof(long_return);
    if (ip)
    {
        switch (vp->magic) {
        case IPADADDR:
            *var_len = sizeof(Int32);
            long_return = it->second->ipAddress;
            EXTERNAL_hton(&long_return, sizeof(long_return));
            vp->type = ASN_IPADDRESS;
            return (unsigned char*) &long_return;
        case IPADIFINDEX:
            *var_len = 4;
            *tempNodeAddr = it->second->ipAddrIfIdx+1;
            vp->type = ASN_INTEGER;
            return (unsigned char*) tempNodeAddr;
        case IPADNETMASK:
            *var_len = sizeof(Int32);
            long_return = it->second->ipAddrNetMask;
            EXTERNAL_hton(&long_return, sizeof(long_return));
            vp->type = ASN_IPADDRESS;
            return (unsigned char*) &long_return;
        case IPADBCASTADDR:
            *var_len = 4;
            long_return = it->second->ipAddrBcast;
            vp->type = ASN_INTEGER;
            return (unsigned char*) &long_return;
        case IPADREASMMAX:
            vp->type = ASN_INTEGER;
            void*  ipRouteEntryValue;
            *var_len = sizeof(Int32);
            ipRouteEntryValue = 
                SNMP_GetIpRouteEntry1(node, DEFAULT_INTERFACE, 0, 1);
            if (ipRouteEntryValue != NULL)
            {
                MEM_free(ipRouteEntryValue);
                long_return = MAXIPDATAGRAMSIZE;
                return (unsigned char*) &long_return;
            }
            else
                return NO_MIBINSTANCE;
            return (unsigned char*) tempNodeAddr;
        }
    }
    else
    {
        return (unsigned char*) &long_return;
    }
    return NULL;
}
