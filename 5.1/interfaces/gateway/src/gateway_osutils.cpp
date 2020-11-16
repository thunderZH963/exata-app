// Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.
//                          600 Corporate Pointe
//                          Suite 1200 
//                          Culver City, CA 90230
//                          info@scalable-networks.com
//
// This source code is licensed, not sold, and is subject to a written
// license agreement.  Among other things, no portion of this source
// code may be copied, transmitted, disclosed, displayed, distributed,
// translated, used as the basis for a derivative work, or used, in
// whole or in part, for any program or purpose other than its intended
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.


#include <stdio.h>
#include <stdlib.h>
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <sys/types.h>
    #include <sys/select.h>
    #include <arpa/inet.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <ifaddrs.h>
    #include "qualnet_upa.h"
#endif    
#include <string.h>

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "pcap.h"
#include "libnet.h"

#include "product_info.h"
#include "api.h"
#include "partition.h"
#include "fileio.h"
#include "internetgateway.h"
#include "gateway_osutils.h"
#include "auto-ipnetworkemulator.h"
#include "capture_interface.h"

#include "types.h"

unsigned short GatewayOSUtilsGetFreeNatPortNum(
    GatewayData* gwData)
{
    return gwData->lastNatPort++;
}

void GatewayOSUtilsIpv6Initialize(
    EXTERNAL_Interface* iface,
    GatewayData* gwData)
{
    AutoIPNEData* data = NULL;
    data = (AutoIPNEData*)iface->data;

#ifdef _WIN32
    if (Product::GetWindowsVersion() >= WINVER_VISTA_ABOVE)
    {
        typedef Int32 (WINAPI* importFunction)(ADDRESS_FAMILY,
                                               PMIB_IPFORWARD_TABLE2*);
        HINSTANCE hDLL = LoadLibrary(TEXT("Iphlpapi.dll"));  // Handle to DLL
        importFunction GetIpv6ForwardTableFunc;
        if (hDLL != NULL)
        {
            GetIpv6ForwardTableFunc = (importFunction)GetProcAddress(
                                                      hDLL,
                                                      "GetIpForwardTable2");
            if (!GetIpv6ForwardTableFunc)
            {
                ERROR_ReportError("Unable to get function pointer to API "
                    "GetIpForwardTable2");
            }
        }
        else
        {
              ERROR_ReportError("Unable to get DLL handler for Iphlpapi.dll");
        }

        PMIB_IPFORWARDTABLE pIpForwardTable;
        PMIB_IPFORWARD_TABLE2 pIpForwardTable2;
        DWORD dwRetVal = 0;
        SOCKADDR_INET nextHop;
        NET_LUID luid;
        BOOL dGatewayPresent = FALSE;
        BOOL dGatewayResolved = FALSE;
        struct sockaddr_in6 inet6DefaultGateway;
        Int8 macAddress[6];
        Int32 macAddressSize = 0;
        Int32 deviceIndex = -1;
        in6_addr defaultIpv6InfAddress;
        memset(&inet6DefaultGateway, 0, sizeof(sockaddr_in6));
        if ((dwRetVal = GetIpv6ForwardTableFunc(AF_INET6, &pIpForwardTable2))
            == NO_ERROR)
        {
            for (int i = 0; i < pIpForwardTable2->NumEntries; i++)
            {
                SOCKADDR_INET prefix
                    = pIpForwardTable2->Table[i].DestinationPrefix.Prefix;
                UInt8 prefixLength
                 = pIpForwardTable2->Table[i].DestinationPrefix.PrefixLength;
                ERROR_Assert(prefix.si_family == AF_INET6, "");
                SOCKADDR_IN6 inet6Addr = prefix.Ipv6;
                if (memcmp(&inet6Addr.sin6_addr,
                           &inet6DefaultGateway.sin6_addr,
                           sizeof(IN6_ADDR))
                        == 0
                        && prefixLength == 0)
                {
                    nextHop = pIpForwardTable2->Table[i].NextHop;
                    luid = pIpForwardTable2->Table[i].InterfaceLuid;
                    dGatewayPresent = TRUE;
                    break;
                }
            }
        }

        if (!dGatewayPresent)
        {
            ERROR_ReportError("Ipv6 default gateway is not configured");
        }

        PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
        PIP_ADAPTER_ADDRESSES pAddresses = NULL;
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = NULL;
        ULONG outBufLen = 1500;
        ULONG iterations = 0;
        ULONG family = AF_INET6;
        ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

        do
        {
            pAddresses = (IP_ADAPTER_ADDRESSES*)MEM_malloc(outBufLen);
            dwRetVal = GetAdaptersAddresses(family, flags, NULL,
                            pAddresses, &outBufLen);

            if (dwRetVal == ERROR_BUFFER_OVERFLOW)
            {
                MEM_free(pAddresses);
                pAddresses = NULL;
            } 
            else
            {
                break;
            }
            iterations++;
        } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < 3));

        if (dwRetVal != NO_ERROR)
        {
            char str[MAX_STRING_LENGTH];
            sprintf(str, "Call to GetAdaptersAddresses failed with ",
                "error: %d\n", dwRetVal);
            ERROR_ReportError(str);
        }

        pCurrAddresses = pAddresses;
        while (pCurrAddresses)
        {
            if (pCurrAddresses->Luid.Value == luid.Value)
            {
                // Interface luid matches
                pUnicast = pCurrAddresses->FirstUnicastAddress;
                while (pUnicast)
                {
                    sockaddr_in6* ipv6Addr
                         = (sockaddr_in6*)pUnicast->Address.lpSockaddr;
                    if (memcmp(ipv6Addr->sin6_addr.s6_addr,
                            nextHop.Ipv6.sin6_addr.s6_addr,
                            pUnicast->OnLinkPrefixLength / 8) == 0)
                    {
#ifdef GATEWAY_DEBUG
                        printf("Attempting to resolve the gateway\n");
#endif
                        dGatewayResolved
                             = DetermineOperationHostMACAddressIpv6(
                                data,
                                ipv6Addr->sin6_addr,
                                ipv6Addr->sin6_scope_id,
                                nextHop.Ipv6.sin6_addr,
                                macAddress,
                                &macAddressSize,
                                deviceIndex);
                        if (dGatewayResolved)
                        {
#ifdef GATEWAY_DEBUG
                            printf("Gateway resolved\n");
#endif
                            defaultIpv6InfAddress = ipv6Addr->sin6_addr;
                            break;
                        }
                    }
                    pUnicast = pUnicast->Next;
                }
                break;
            }
            pCurrAddresses = pCurrAddresses->Next;
        }

        if (!dGatewayResolved)
        {
            ERROR_ReportError("\nCoudn't connect to the gateway");
        }
        gwData->defaultIpv6InterfaceAddress = defaultIpv6InfAddress;
        memcpy(&gwData->ipv6InternetRouterMacAddress, (char*)&macAddress, 6);
        sprintf(gwData->defaultIpv6InterfaceName,
            "\\Device\\NPF_%s",
            pCurrAddresses->AdapterName);
    }
    else
    {
        ERROR_Assert(FALSE, "\nIpv6 gateway functionality is currently not "
            "supported on operating systems below Windows Vista");
    }

#else
    FILE* fp = NULL;
    Int8 line[MAX_STRING_LENGTH];
    Int8* devName, *destination, delims[] = " \t";
    Int8* delim = FALSE;
    BOOL devFound = FALSE;
    Int32 temp =0;

    // Find the default network device
    if ((fp = fopen("/proc/net/ipv6_route", "r")) == NULL)
    {
        ERROR_ReportError("Cannot open /proc/net/ipv6_route file");
    }
    while (!feof(fp))
    {
        temp = fscanf(fp, "%[^\n]%*c\n", line);
        delim = strtok(line, delims);
        if (!strcmp(delim, "00000000000000000000000000000000"))
        {
            delim = strtok(NULL, delims);
            if (!strcmp(delim, "00"))
            {
                delim = strtok(NULL, delims);
                delim = strtok(NULL, delims);
                destination = strtok(NULL, delims);
                delim = strtok(NULL, delims);
                delim = strtok(NULL, delims);
                delim = strtok(NULL, delims);
                delim = strtok(NULL, delims);
                devName  = strtok(NULL, delims);
                if (strcmp(devName, "lo") == 0)
                {
                    // do not select the loopback interface
                    continue;
                }
                devFound = TRUE;
#ifdef GATEWAY_DEBUG
                printf("\ndevice name selected for default "
                    "gateway:%s",devName);
#endif
                sprintf(gwData->defaultIpv6InterfaceName, "%s", devName);
                break;
            }
        }
    }
    fclose(fp);

    if (!devFound)
    {
        ERROR_ReportError("Ipv6 default gateway is not configured");
    }

    // Find the interface address for this default network device
    char dstStr[40];
    int count = 0;
    int k = 0, m = 0;

    // Creating ipv6 address string of the default gateway ipv6 address
    for (k =0, m = 0; k < strlen(destination), m < 39; k++, m++)
    {
        count++;
        if (count > 4)
        {
            dstStr[m] = ':';
            count = 0;
            k--;
        }
        else
        {
            dstStr[m] = destination[k];
        }
    }
    dstStr[m] = '\0';

    Address ipv6Address;
    ipv6Address.networkType = NETWORK_IPV6;
    BOOL isNodeId = FALSE;
    IO_ParseNodeIdHostOrNetworkAddress(dstStr, &ipv6Address, &isNodeId);

#ifdef GATEWAY_DEBUG
     char buf[MAX_STRING_LENGTH];
     IO_ConvertIpAddressToString(&ipv6Address, buf);
     printf("\nDefault gateway Ipv6 Address: %s",buf);
#endif

    struct ifaddrs* ifa = NULL;
    struct ifaddrs* ifEntry = NULL;
    int rc = 0;
    BOOL found = FALSE;
    rc = getifaddrs(&ifa);
    if (rc == 0)
    {
        for (ifEntry = ifa; ifEntry != NULL; ifEntry = ifEntry->ifa_next)
        {
            if (!strcmp(ifEntry->ifa_name, devName))
            {
                if (ifEntry->ifa_addr->sa_family == AF_INET6)
                {
#ifdef GATEWAY_DEBUG
                    in6_addr addr
                        = (in6_addr)((struct sockaddr_in6*)
                            ifEntry->ifa_addr)->sin6_addr;
                    Address addr2;
                    addr2.networkType = NETWORK_IPV6;
                    addr2.interfaceAddr.ipv6 = addr;
                    char buf2[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(&addr2, buf2);
                    printf("\nInferface Ipv6 Address %s",buf2);
#endif
                    // Assuming an prefix length of 64 bits
                    if (memcmp(&((struct sockaddr_in6*)
                                  ifEntry->ifa_addr)->sin6_addr,
                               &ipv6Address.interfaceAddr.ipv6,
                               8) == 0)
                    {
                         found = TRUE;
                         gwData->defaultIpv6InterfaceAddress
                            = ((struct sockaddr_in6*)
                                ifEntry->ifa_addr)->sin6_addr;
                         break;
                    }
                }
            }
        }
    }
    else
    {
        ERROR_ReportError("\nCall to getifaddrs API failed");
    }

    if (!found)
    {
        ERROR_ReportError("Could not find the interface address that is in "
            " the same subnet as the gateway");
    }

    /* ip6table
       Remove our custom chain created from last exata execution, but
       not cleanly uninstalled */

    /* 1. Create the new chain (if chain already existed, this command with
          do nothing) */
    temp = system("ip6tables -N EXATA-IG"); 

    // 2. Empty this chain
    temp = system("ip6tables -F EXATA-IG"); 

    // 3. Remove the chain from INPUT rules (no affect if no rule existed)
    temp = system("ip6tables -D INPUT -j EXATA-IG");

    // 4. Add the exata chain as a rule in INPUT chain
    temp = system("ip6tables -I INPUT 1 -j EXATA-IG");

    // 5. Allow the UPA ports (5134, 5135, 5136, 5137 and 3134)
    char str[MAX_STRING_LENGTH];
    sprintf(str, "ip6tables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_CONTROL_PORT);
    temp = system(str);
    sprintf(str, "ip6tables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_DATA_PORT);
    temp = system(str);
    sprintf(str, "ip6tables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_CONTROL_PORT_IPV6);
    temp = system(str);
    sprintf(str, "ip6tables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_DATA_PORT_IPV6);
    temp = system(str);
    sprintf(str, "ip6tables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_MULTICAST_PORT_IPV6);
    temp = system(str);
#endif
}

void GatewayOSUtilsInitialize(
    GatewayData* gwData)
{
#ifdef _WIN32
    /* This is what is happening:
        a) Reading the routing table to find a route with 0.0.0.0 destination
            (that is, the route entry for default route).
            API used: GetIpForwardTable
            Output: Device Index and Default Router IP address
        b) From the Device Index, we find the device name (to be used by pcap)
            API used: GetAdaptersInfo
        c) From the default router IP address, we find the MAC address for
            that router API used: SendARP
        d) Finally we turn on the windows firewall
    */

    DWORD result = 0;
    DWORD size = 0;
    INT i = 0;
    DWORD gatewayRouter;
    ULONG macAddress[2], macAddressLen = 6;
    MIB_IPFORWARDTABLE* forwardTable = NULL;
    MIB_IPFORWARDROW* forwardRow = NULL;

    // first read the size of the routing table
    GetIpForwardTable(NULL, &size, FALSE);

    // Now actually read the routes
    forwardTable = (MIB_IPFORWARDTABLE *)MEM_malloc(size);
    if ((result = GetIpForwardTable(forwardTable, &size, FALSE)) != NO_ERROR)
    {
        ERROR_ReportError("Cannot read the routing table\n");
    }

    forwardRow = &forwardTable->table[0];

    // Find out the default interface
    for (i = 0; i < forwardTable->dwNumEntries; i++)
    {
        if (forwardRow->dwForwardDest == 0) /* the default address */
        {
            // Do some sanity checks
            if ((forwardRow->dwForwardMask != 0) ||
                (forwardRow->dwForwardType != 4))
            {
                ERROR_ReportError("Gateway configuration is not correct");
            }
            break;
        }

        forwardRow++;
    }

    if (i == forwardTable->dwNumEntries)
    {
        ERROR_ReportError("Cannot find default interface to Internet\n");
    }

    gatewayRouter = forwardRow->dwForwardNextHop;

    // Get the device name, given the device index
    IP_ADAPTER_INFO adapter;
    PIP_ADAPTER_INFO adapterInfo;

    size = sizeof(adapter);
    GetAdaptersInfo(&adapter, &size);

    adapterInfo = (PIP_ADAPTER_INFO)MEM_malloc(size);

    if (GetAdaptersInfo(adapterInfo, &size) != ERROR_SUCCESS)
    {
        ERROR_ReportError("Cannot read the name of the default interface\n");
    }

    PIP_ADAPTER_INFO tempAdapter=adapterInfo;
    while (tempAdapter)
    {
        if (forwardRow->dwForwardIfIndex == tempAdapter->Index)
        {
            gwData->defaultInterfaceAddress
                = inet_addr(tempAdapter->IpAddressList.IpAddress.String);
            gwData->defaultInterfaceAddress
                = ntohl(gwData->defaultInterfaceAddress);
            sprintf(gwData->defaultInterfaceName,
                "\\Device\\NPF_%s", tempAdapter->AdapterName);
            break;
        }
        tempAdapter = tempAdapter->Next;
    }

    if (!tempAdapter)
    {
        ERROR_ReportError("Cannot find the matching entry in AdaptorsInfo\n");
    }

    MEM_free((void *)forwardTable);
    MEM_free((void *)adapterInfo);

    // Find the MAC address of the default router
    if ((result = SendARP(gatewayRouter, INADDR_ANY, &macAddress[0],
                    &macAddressLen))
                != NO_ERROR)
    {
        char str[MAX_STRING_LENGTH];
        sprintf(str,"Coundn't resolve the MAC address of Ipv4 gateway. "
            "Errorcode:%d\n", WSAGetLastError());
        ERROR_ReportError(str);
    }

    memcpy(&gwData->internetRouterMacAddress, (char *)&macAddress, 6);
#else // _WIN32
    FILE* fp = NULL;
    Int8 line[MAX_STRING_LENGTH];
    Int8* devName, *destination, delims[] = " \t";
    BOOL devFound = FALSE;
    Int32 temp = 0;

    // Find the default network device
    if ((fp = fopen("/proc/net/route", "r")) == NULL)
    {
        ERROR_ReportError("Cannot open /proc/net/route file");
    }
    while (!feof(fp))
    {
        temp = fscanf(fp, "%[^\n]%*c\n", line);
        devName = strtok(line, delims);
        if (!strcmp(devName, "Iface"))
        {
            // this is header
            continue;
        }

        destination = strtok(NULL, delims);
        if (!strcmp(destination, "00000000"))
        {
            devFound = TRUE;
            sprintf(gwData->defaultInterfaceName, "%s", devName);
            break;
        }
    }
    fclose(fp);

    if (!devFound)
    {
        ERROR_ReportError("This machine does not have a default interface");
    }
    
    // Find the interface address for this default network device 
    struct ifreq ifr;
    int s, err;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        assert(0); // TODO
    }

    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, devName);
    err = ioctl(s, SIOCGIFADDR, &ifr);

    if (err < 0)
    {
        ERROR_ReportError("ioctl call failed");
    }

    close(s);

    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    gwData->defaultInterfaceAddress = ntohl(addr->sin_addr.s_addr);

    /* iptable
       Remove our custom chain created from last exata execution, but
       not cleanly uninstalled */

    /* 1. Create the new chain (if chain already existed, this command with
          do nothing) */
    temp = system("iptables -N EXATA-IG");

    // 2. Empty this chain
    temp = system("iptables -F EXATA-IG");

    // 3. Remove the chain from INPUT rules (no affect if no rule existed)
    temp = system("iptables -D INPUT -j EXATA-IG");
    // 4. Add the exata chain as a rule in INPUT chain
    temp = system("iptables -I INPUT 1 -j EXATA-IG");

    // 5. Allow the UPA ports (5134 and 5134)
    char str[MAX_STRING_LENGTH];
    sprintf(str, "iptables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_CONTROL_PORT);
    temp = system(str);
    sprintf(str, "iptables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_DATA_PORT);
    temp = system(str);
    sprintf(str, "iptables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_CONTROL_PORT_IPV6);
    temp = system(str);
    sprintf(str, "iptables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_DATA_PORT_IPV6);
    temp = system(str);
    sprintf(str, "iptables -I EXATA-IG 1 -p udp  --destination-port %d -j "
        "ACCEPT", UPA_MULTICAST_PORT_IPV6);
    temp = system(str);
#endif
}

void GatewayOSUtilsFinalize(
    GatewayData* gwData)
{
#ifdef _WIN32

#else
    Int32 temp = 0;

    // Remove our custom chain
    if (gwData->libnetHandle)
    {
        temp = system("iptables -D INPUT -j EXATA-IG");
        temp = system("iptables -F EXATA-IG");
        temp = system("iptables -X EXATA-IG");
    }

    if (gwData->ipv6LibnetHandle)
    {
        temp = system("ip6tables -D INPUT -j EXATA-IG");
        temp = system("ip6tables -F EXATA-IG");
        temp = system("ip6tables -X EXATA-IG");
    }

#endif
}

void GatewayOSUtilsAddPort(
    GatewayData* gwData,
    UInt16 port,
    BOOL isIpv6)
{
#ifdef _WIN32

#else

    Int32 temp = 0;
    char sysCommand[MAX_STRING_LENGTH];
#ifdef GATEWAY_DEBUG
    printf("Adding IG port number : %d\n", port);
#endif
    if (isIpv6)
    {
        sprintf(sysCommand,
            "ip6tables -I EXATA-IG 1 -p tcp --destination-port %d -j DROP",
            port);
        temp = system(sysCommand);
        sprintf(sysCommand,
            "ip6tables -I EXATA-IG 1 -p udp --destination-port %d -j DROP",
            port);
        temp = system(sysCommand);
    }
    else
    {
        sprintf(sysCommand,
            "iptables -I EXATA-IG 1 -p tcp --destination-port %d -j DROP",
            port);
        temp = system(sysCommand);
        sprintf(sysCommand,
            "iptables -I EXATA-IG 1 -p udp --destination-port %d -j DROP",
            port);
        temp = system(sysCommand);
    }
#endif
}

void GatewayOSUtilsDeletePort(
    GatewayData* gwData,
    UInt16 port)
{
#ifdef _WIN32

#else
    Int32 temp = 0;
    char sysCommand[MAX_STRING_LENGTH];

    sprintf(sysCommand,
            "iptables -D EXATA-IG -p tcp --destination-port %d -j DROP",
            port);
    temp = system(sysCommand);
    sprintf(sysCommand,
            "iptables -D EXATA-IG -p udp --destination-port %d -j DROP",
            port);
    temp = system(sysCommand);
#endif
}
