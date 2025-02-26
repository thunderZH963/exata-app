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

#include "api.h"
#include "partition.h"
#include "internetgateway.h"
#include "gateway_osutils.h"
#include "gateway_interface.h"
#include "gateway_nat.h"

unsigned short GatewayNatGetPortNumber(
    GatewayData *gwData,
    AddressPortPair *apPair,
    BOOL isIpv6)
{
    int natPort;
    char *natKey;

    apPair->zero = 0;
    if (gwData->egressNATTable->count((char *)apPair) > 0)
    {
        return (unsigned short)((*gwData->egressNATTable)[(char *)apPair]);
    }
    
    natPort = GatewayOSUtilsGetFreeNatPortNum(gwData);
    natKey = (char *)MEM_malloc(sizeof(AddressPortPair));
    memcpy(natKey, (char *)apPair, sizeof(AddressPortPair));

    gwData->egressNATTable->insert(
            std::pair<char *,int>(natKey, natPort));
    gwData->ingressNATTable->insert(
                std::pair<int, char *>(natPort, natKey));

    GatewayOSUtilsAddPort(gwData, natPort, isIpv6);
    return (unsigned short)natPort;
}

AddressPortPair *GatewayNatGetAddressPortPair(
    GatewayData *gwData,
    unsigned short natPort)
{
    return (AddressPortPair *)(*gwData->ingressNATTable)[natPort];
}
