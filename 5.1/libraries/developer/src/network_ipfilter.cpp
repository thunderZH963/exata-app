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
#include "network_ip.h"
#include "network_ipfilter.h"


BOOL NetworkIpAddFilter(
    Node *node,
    NodeAddress sourceAddress,
    NodeAddress destAddress,
    int filterType)
{
    node = node->partitionData->firstNode;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    if(ip->numFilters >= MAX_FILTERS) // TODO
    {
        return FALSE;
    }
    /* Find if the filter already exists */
    for(i=0; i < ip->numFilters; i++)
    {
        if(ip->filters[i].srcAddress == sourceAddress &&
                ip->filters[i].destAddress == destAddress)
        {
            ip->filters[i].filterType |= filterType;
            return TRUE;
        }
    }

    ip->filters[ip->numFilters].srcAddress  = sourceAddress;
    ip->filters[ip->numFilters].destAddress = destAddress;
    ip->filters[ip->numFilters].filterType  = filterType;
    ip->numFilters++;

    return TRUE;
}

void NetworkIpRemoveFilter(
    Node *node,
    NodeAddress sourceAddress,
    NodeAddress destAddress,
    int filterType)
{
    node = node->partitionData->firstNode;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    /* Find if the filter already exists */
    for(i=0; i < ip->numFilters; i++)
    {
        if(ip->filters[i].srcAddress == sourceAddress &&
                ip->filters[i].destAddress == destAddress)
        {
            ip->filters[i].filterType ^= filterType;
            // If no filterType exist then delete the filter
            if(ip->filters[i].filterType == 0)
            {
                ip->filters[i].srcAddress = ip->filters[ip->numFilters - 1].srcAddress;
                ip->filters[i].destAddress = ip->filters[ip->numFilters - 1].destAddress;
                ip->filters[i].filterType = ip->filters[ip->numFilters - 1].filterType;
                ip->numFilters --;
            }

            return;
        }
    }
}

BOOL NetworkIpEmptyFilter(
    Node *node)
{
    node = node->partitionData->firstNode;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    return (ip->numFilters == 0);
}

BOOL NetworkIpCheckFilter(
    Node *node,
    NodeAddress sourceAddress,
    NodeAddress destAddress,
    int *filterType)
{
    node = node->partitionData->firstNode;
    NetworkDataIp *ip = (NetworkDataIp *) node->networkData.networkVar;
    int i;

    /* Find if the filter already exists */
    for(i=0; i < ip->numFilters; i++)
    {
        if((ip->filters[i].srcAddress == sourceAddress &&
                ip->filters[i].destAddress == destAddress) ||
        (ip->filters[i].srcAddress == destAddress &&
                ip->filters[i].destAddress == sourceAddress))
        {
            *filterType = ip->filters[i].filterType;
            return TRUE;
        }
    }

    return FALSE;
}

