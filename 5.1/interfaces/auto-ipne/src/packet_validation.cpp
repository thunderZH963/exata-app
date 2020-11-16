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
#include <errno.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "transport_udp.h"
#include "ipv6.h"

BOOL CheckNetworkRoutingProtocol(
Node *node,
int interfaceIndex,
int ip_p)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    IpInterfaceInfoType *ifinfo = ip->interfaceInfo[interfaceIndex];
    switch(ip_p)
    {
        case  IPPROTO_AODV :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_AODV ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_AODV ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_AODV ));
        case  IPPROTO_DSR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_DSR ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_DSR ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_DSR ));
        case  IPPROTO_FSRL :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_FSRL ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_FSRL ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_FSRL ));

#ifdef ADDON_BOEINGFCS
        case  IPPROTO_NETWORK_CES_CLUSTER :
        case  IPPROTO_NETWORK_CES_REGION :
            return true;
/*
        case  IPPROTO_NETWORK_CES_CLUSTER :
            return  ((ifinfo->routingProtocolType ==  ROUTING_CLUSTER ) ||
                (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_CLUSTER ) ||
                (ifinfo->multicastProtocolType ==  ROUTING_CLUSTER ));
        case  IPPROTO_NETWORK_CES_REGION :
            return  ((ifinfo->routingProtocolType ==  NETWORK_CES_REGION ) ||
                (ifinfo->intraRegionRoutingProtocolType ==  NETWORK_CES_REGION ) ||
                (ifinfo->multicastProtocolType ==  NETWORK_CES_REGION ));
*/
#endif
        case  IPPROTO_STAR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_STAR ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_STAR ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_STAR ));
        case  IPPROTO_LAR1 :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_LAR1 ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_LAR1 ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_LAR1 ));

        case  IPPROTO_OSPF :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_OSPF)||
                (ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_OSPFv2 ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_OSPFv2 ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_OSPF)||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_OSPFv2 ));
        case  IPPROTO_IGRP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_IGRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_IGRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_IGRP ));
#if 0
        case  IPPROTO_EIGRP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_EIGRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_EIGRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_EIGRP ));
#endif
        case  IPPROTO_BRP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_BRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_BRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_BRP ));

        case  IPPROTO_IARP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_IARP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_IARP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_IARP ));
        case  IPPROTO_ZRP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_ZRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_ZRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_ZRP ));
        case  IPPROTO_IERP :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_IERP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_IERP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_IERP ));
        case  IPPROTO_IGMP :
            return  ((ifinfo->routingProtocolType ==  GROUP_MANAGEMENT_PROTOCOL_IGMP ) ||
                     (ip->isIgmpEnable) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  GROUP_MANAGEMENT_PROTOCOL_IGMP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  GROUP_MANAGEMENT_PROTOCOL_IGMP ));
        case  IPPROTO_DVMRP :
            return  ((ifinfo->routingProtocolType ==  MULTICAST_PROTOCOL_DVMRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  MULTICAST_PROTOCOL_DVMRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  MULTICAST_PROTOCOL_DVMRP ));
        case  IPPROTO_ODMRP :
            return  ((ifinfo->routingProtocolType ==  MULTICAST_PROTOCOL_ODMRP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  MULTICAST_PROTOCOL_ODMRP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  MULTICAST_PROTOCOL_ODMRP ));
        case  IPPROTO_PIM :
            return  ((ifinfo->routingProtocolType ==  MULTICAST_PROTOCOL_PIM ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  MULTICAST_PROTOCOL_PIM ) ||
#endif
                    (ifinfo->multicastProtocolType ==  MULTICAST_PROTOCOL_PIM ));
#ifdef ADDON_MAODV
        case  IPPROTO_MAODV :
            return  ((ifinfo->routingProtocolType ==  MULTICAST_PROTOCOL_MAODV ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  MULTICAST_PROTOCOL_MAODV ) ||
#endif
                    (ifinfo->multicastProtocolType ==  MULTICAST_PROTOCOL_MAODV ));
#endif

#ifdef CELLULAR_LIB

        case  IPPROTO_GSM :
            return  ((ifinfo->routingProtocolType ==  NETWORK_PROTOCOL_GSM ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  NETWORK_PROTOCOL_GSM ) ||
#endif
                    (ifinfo->multicastProtocolType ==  NETWORK_PROTOCOL_GSM ));

#endif
        case  IPPROTO_DYMO :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_DYMO ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_DYMO ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_DYMO ));
#ifdef ADDON_BOEINGFCS
        case  IPPROTO_IPIP_ROUTING_CES_MALSR:
        case  IPPROTO_IPIP_ROUTING_CES_ROSPF:
        case  IPPROTO_ROUTING_CES_MALSR :
        case  IPPROTO_ROUTING_CES_SRW :
        case  IPPROTO_ROUTING_CES_ROSPF :
        case  IPPROTO_ROUTING_CES_MPR :
        case  IPPROTO_CES_SDR :
        case  IPPROTO_CES_EPLRS :
        case  IPPROTO_RPIM :
            return true;

/*
        case  IPPROTO_ROUTING_CES_MALSR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_MALSR ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_MALSR ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_MALSR ));
        case  IPPROTO_ROUTING_CES_SRW :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_SRW ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_SRW ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_SRW ));
        case  IPPROTO_ROUTING_CES_ROSPF :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_ROSPF ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_ROSPF ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_ROSPF ));
        case  IPPROTO_ROUTING_CES_MPR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_MPR ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_MPR ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_MPR ));
        case  IPPROTO_CES_SDR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_SDR ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_SDR ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_SDR ));
        case  IPPROTO_CES_EPLRS :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_EPLRS ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_EPLRS ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_EPLRS ));

        case  IPPROTO_RPIM :
            return  ((ifinfo->routingProtocolType ==  MULTICAST_PROTOCOL_RPIM ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  MULTICAST_PROTOCOL_RPIM ) ||
                    (ifinfo->multicastProtocolType ==  MULTICAST_PROTOCOL_RPIM ));
*/
#endif
#ifdef IA_LIB
        case  IPPROTO_ANODR :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_ANODR ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_ANODR ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_ANODR ));
#endif
#ifdef ADDON_BOEINGFCS
    case IPPROTO_CES_HSLS:
        return true;
#endif
        default:
            {
                return false;
            }
    }
    return false;
}


BOOL CheckApplicationRoutingProtocol(
        Node *node,
        int interfaceIndex,
        int app_p)
{
    NetworkDataIp *ip = (NetworkDataIp *)node->networkData.networkVar;
    IpInterfaceInfoType *ifinfo = ip->interfaceInfo[interfaceIndex];
    switch(app_p)
    {

              case  APP_EXTERIOR_GATEWAY_PROTOCOL_BGPv4 :
            return  ((ifinfo->routingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_IBGPv4) ||
                                 (ifinfo->routingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_EBGPv4) ||
                                 (ifinfo->routingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_BGPv4_LOCAL) ||


#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_IBGPv4 ) ||
                                        (ifinfo->intraRegionRoutingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_EBGPv4 ) ||
                                        (ifinfo->intraRegionRoutingProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_BGPv4_LOCAL) ||
#endif
                    (ifinfo->multicastProtocolType ==  EXTERIOR_GATEWAY_PROTOCOL_IBGPv4 ));

              case  APP_ROUTING_BELLMANFORD :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_BELLMANFORD ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_BELLMANFORD ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_BELLMANFORD ));

               case  APP_ROUTING_FISHEYE :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_FISHEYE) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_FISHEYE ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_FISHEYE));

case  APP_ROUTING_OLSR_INRIA :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_OLSR_INRIA ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_OLSR_INRIA ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_OLSR_INRIA ));
case  APP_ROUTING_RIP:
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_RIP ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_RIP ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_RIP ));
        case  APP_ROUTING_RIPNG :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_RIPNG ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_RIPNG ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_RIPNG ));
        case  APP_ROUTING_OLSRv2_NIIGATA :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_OLSRv2_NIIGATA ) ||
#ifdef ADDON_BOEINGFCS
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_OLSRv2_NIIGATA ) ||
#endif
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_OLSRv2_NIIGATA ));
#ifdef ADDON_BOEINGFCS
        case  APP_ROUTING_HSLS :
            return true;
/*
        case  APP_ROUTING_HSLS :
            return  ((ifinfo->routingProtocolType ==  ROUTING_PROTOCOL_CES_HSLS ) ||
                    (ifinfo->intraRegionRoutingProtocolType ==  ROUTING_PROTOCOL_CES_HSLS ) ||
                    (ifinfo->multicastProtocolType ==  ROUTING_PROTOCOL_CES_HSLS ));
*/
#endif
        default:
            {
                return false;
            }
    }
    return false;
}

BOOL CheckNetworkRoutingProtocolIpv6(
    Node* node,
    Int32 interfaceIndex,
    Int32 ip_p)
{
    NetworkDataIp* ip = (NetworkDataIp *)node->networkData.networkVar;
    ipv6_interface_struct* ifinfo
        = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    switch(ip_p)
    {
        case  IPPROTO_AODV :
            return (ifinfo->routingProtocolType == ROUTING_PROTOCOL_AODV6);
        case  IPPROTO_OSPF :
            return (ifinfo->routingProtocolType == ROUTING_PROTOCOL_OSPFv3);
        case  IPPROTO_DYMO :
            return (ifinfo->routingProtocolType == ROUTING_PROTOCOL_DYMO6);
        default:
            {
                return FALSE;
            }
    }
    return FALSE;
}

BOOL CheckApplicationRoutingProtocolIpv6(
    Node* node,
    Int32 interfaceIndex,
    Int32 app_p)
{
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    ipv6_interface_struct* ifinfo
         = ip->interfaceInfo[interfaceIndex]->ipv6InterfaceInfo;
    switch (app_p)
    {
        case APP_ROUTING_OLSR_INRIA:
        {
            return (ifinfo->routingProtocolType
                                            == ROUTING_PROTOCOL_OLSR_INRIA);
        }
        case APP_ROUTING_RIPNG:
        {
            return (ifinfo->routingProtocolType == ROUTING_PROTOCOL_RIPNG);
        }
        case APP_ROUTING_OLSRv2_NIIGATA:
        {
            return (ifinfo->routingProtocolType
                                        == ROUTING_PROTOCOL_OLSRv2_NIIGATA);
        }
        default:
        {
            return FALSE;
        }
    }
    return FALSE;
}
