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

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#endif

#include "api.h"
#include "network_ip.h"
#include "packet_analyzer.h"
#include "transport_udp.h"


BOOL PAS_FilterCheck(IpHeaderType * ipHeader, char filterBit)
{
    if (ipHeader->ip_p == IPPROTO_ICMP) 
        return TRUE;
    if ((filterBit & PACKET_SNIFFER_ENABLE_UDP) && //UDP             
           (ipHeader->ip_p == IPPROTO_UDP))
    {
        if (filterBit & PACKET_SNIFFER_ENABLE_ROUTING) //ROUTING
        {
            return TRUE;
        }
        else
        {
            int ipHeaderLength;                                                         
            TransportUdpHeader *udp;                                                    
            unsigned short destPortNumber;                                              
            UInt8*    nextHeader;                                                       
                                                                                            
            ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;            
            nextHeader = ((UInt8*) ipHeader) + ipHeaderLength;                          
            udp = (TransportUdpHeader *) nextHeader;                                    
                                                                                     
            destPortNumber=udp->destPort;                                               
            switch (destPortNumber)
            {                                                                       
            case APP_ROUTING_BELLMANFORD:                                           
            case APP_ROUTING_FISHEYE:                                               
            case APP_ROUTING_STATIC:                                                
            case APP_ROUTING_HSRP:                                                  
            case APP_ROUTING_OLSR_INRIA:                                            
            case APP_ROUTING_RIP:                                                   
            case APP_ROUTING_RIPNG:                                                 
            case APP_ROUTING_OLSRv2_NIIGATA:                                        
                return FALSE;                                                       
            default:                                                                
                return TRUE;                                                        
            }
        }
       }

    if ((filterBit & PACKET_SNIFFER_ENABLE_TCP) && // TCP            
        (ipHeader->ip_p == IPPROTO_TCP))
    {
        return TRUE;
    }

    if (filterBit & PACKET_SNIFFER_ENABLE_ROUTING) //ROUTING                                                
    {                                                                                       
        switch(ipHeader->ip_p)                                                              
        {                                                                                   
            case IPPROTO_OSPF:                                                              
            case IPPROTO_IGMP:
            case IPPROTO_PIM:
            case IPPROTO_AODV:                                                              
            case IPPROTO_DYMO:                                                              
            case IPPROTO_DSR:                                                               
            case IPPROTO_ODMRP:                                                             
            case IPPROTO_LAR1:                                                              
            case IPPROTO_STAR:                                                              
            case IPPROTO_DAWN:                                                              
            case IPPROTO_BELLMANFORD:                                                       
            case IPPROTO_FISHEYE:                                                           
            case IPPROTO_FSRL:                                                              
            case IPPROTO_DVMRP:                                                             
            case IPPROTO_ZRP:                                                               
            case IPPROTO_IERP:                                                              
            case IPPROTO_IARP:                                                              
#ifdef ADDON_BOEINGFCS
            case IPPROTO_NETWORK_CES_CLUSTER:
            case IPPROTO_ROUTING_CES_MALSR:
            case IPPROTO_ROUTING_CES_ROSPF:
            case IPPROTO_IPIP_ROUTING_CES_MALSR:
            case IPPROTO_IPIP_ROUTING_CES_ROSPF:
            case IPPROTO_NETWORK_CES_REGION:
            case IPPROTO_ROUTING_CES_MPR:
            case IPPROTO_ROUTING_CES_SRW:
            case IPPROTO_IPIP_ROUTING_CES_SRW:
            case IPPROTO_IPIP_SDR:
            case IPPROTO_IPIP_CES_SDR:
            case IPPROTO_MULTICAST_CES_SRW_MOSPF:
#endif
                return TRUE;                                                                
            case IPPROTO_UDP:                                                               
                int ipHeaderLength;                                                         
                TransportUdpHeader *udp;                                                    
                unsigned short destPortNumber;                                              
                UInt8*    nextHeader;                                                       
                                                                                            
                ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;            
                nextHeader = ((UInt8*) ipHeader) + ipHeaderLength;                          
                udp = (TransportUdpHeader *) nextHeader;                                    
                                                                                     
                destPortNumber=udp->destPort;                                               
                                                                                     
                switch (destPortNumber)                                                     
                {                                                                           
                    case APP_ROUTING_BELLMANFORD:                                           
                    case APP_ROUTING_FISHEYE:                                               
                    case APP_ROUTING_STATIC:                                                
                    case APP_ROUTING_HSRP:                                                  
                    case APP_ROUTING_OLSR_INRIA:                                            
                    case APP_ROUTING_RIP:                                                   
                    case APP_ROUTING_RIPNG:                                                 
                    case APP_ROUTING_OLSRv2_NIIGATA:                                        
#ifdef ADDON_BOEINGFCS
                    case APP_ROUTING_HSLS:
#endif
                        return TRUE;                                                        
                }                                                                           
        } //switch                                                                          
    }  //if (filterBit & PAS_ROUTING_FILTER) //ROUTING                                       

    if (filterBit & PACKET_SNIFFER_ENABLE_APP) //APP -> non routing
    {
        if (ipHeader->ip_p == IPPROTO_TCP) 
            return TRUE;
        if (ipHeader->ip_p == IPPROTO_UDP)
        {
            int ipHeaderLength;
            TransportUdpHeader *udp;
            unsigned short destPortNumber;
            UInt8*    nextHeader;

            ipHeaderLength = IpHeaderGetHLen(ipHeader->ip_v_hl_tos_len) * 4;        
            nextHeader = ((UInt8*) ipHeader) + ipHeaderLength;                      
            udp = (TransportUdpHeader *) nextHeader;                                
                                                                                     
            destPortNumber=udp->destPort;
                                                                                     
            switch (destPortNumber)
            {                                                                       
            case APP_ROUTING_BELLMANFORD:                                           
            case APP_ROUTING_FISHEYE:                                               
            case APP_ROUTING_STATIC:                                                
            case APP_ROUTING_HSRP:                                                  
            case APP_ROUTING_OLSR_INRIA:                                            
            case APP_ROUTING_RIP:                                                   
            case APP_ROUTING_RIPNG:                                                 
            case APP_ROUTING_OLSRv2_NIIGATA:                                        
#ifdef ADDON_BOEINGFCS
            case APP_ROUTING_HSLS:
#endif
                return FALSE;                                                       
            default:                                                                
                return TRUE;                                                        
            }                                                                       
                    
        }
        switch(ipHeader->ip_p)
        {
            case IPPROTO_OSPF:
            case IPPROTO_AODV:
            case IPPROTO_DYMO:
            case IPPROTO_DSR:
            case IPPROTO_ODMRP:
            case IPPROTO_LAR1:
            case IPPROTO_STAR:
            case IPPROTO_DAWN:
            case IPPROTO_BELLMANFORD:
            case IPPROTO_FISHEYE:
            case IPPROTO_FSRL:
            case IPPROTO_DVMRP:
            case IPPROTO_ZRP:
            case IPPROTO_IERP:
            case IPPROTO_IARP:
#ifdef ADDON_BOEINGFCS
            case IPPROTO_NETWORK_CES_CLUSTER:
            case IPPROTO_ROUTING_CES_MALSR:
            case IPPROTO_ROUTING_CES_ROSPF:
            case IPPROTO_IPIP_ROUTING_CES_MALSR:
            case IPPROTO_IPIP_ROUTING_CES_ROSPF:
            case IPPROTO_NETWORK_CES_REGION:
            case IPPROTO_ROUTING_CES_MPR:
            case IPPROTO_ROUTING_CES_SRW:
            case IPPROTO_IPIP_ROUTING_CES_SRW:
            case IPPROTO_IPIP_SDR:
            case IPPROTO_IPIP_CES_SDR:
            case IPPROTO_MULTICAST_CES_SRW_MOSPF:
#endif
                return FALSE;
            default:
                return TRUE;
        }
    }
    return FALSE;
}


BOOL PAS_FilterCheckIpv6(libnet_ipv6_hdr* ipHeader, Int8 filterBit)
{
    if (ipHeader->ip_nh == IPPROTO_ICMPV6
        || ipHeader->ip_nh == LIBNET_IPV6_NH_FRAGMENT)
    {
        return TRUE;
    }
    if ((filterBit & PACKET_SNIFFER_ENABLE_UDP)
        && (ipHeader->ip_nh == IPPROTO_UDP))
    {
        if (filterBit & PACKET_SNIFFER_ENABLE_ROUTING)
        {
            return TRUE;
        }
        else
        {
            TransportUdpHeader* udp = NULL;
            UInt8* nextHeader = ((UInt8*) ipHeader) + LIBNET_IPV6_H;
            udp = (TransportUdpHeader *) nextHeader;

            switch (udp->destPort)
            {
                case APP_ROUTING_OLSR_INRIA:
                case APP_ROUTING_RIPNG:
                case APP_ROUTING_OLSRv2_NIIGATA:
                    return FALSE;
                default:
                    return TRUE;
            }
        }
    }

    if ((filterBit & PACKET_SNIFFER_ENABLE_TCP)
        && (ipHeader->ip_nh == IPPROTO_TCP))
    {
        return TRUE;
    }

    if (filterBit & PACKET_SNIFFER_ENABLE_ROUTING)
    {
        switch(ipHeader->ip_nh)
        {
            case IPPROTO_AODV:
            case IPPROTO_OSPF:
            case IPPROTO_DYMO:
                return TRUE;
            case IPPROTO_UDP:
                TransportUdpHeader* udp = NULL;
                UInt8* nextHeader = ((UInt8*) ipHeader) + LIBNET_IPV6_H;
                udp = (TransportUdpHeader *) nextHeader;

                switch (udp->destPort)
                {
                    case APP_ROUTING_OLSR_INRIA:
                    case APP_ROUTING_RIPNG:
                    case APP_ROUTING_OLSRv2_NIIGATA:
                        return TRUE;
                }
        } // switch
    }  // if (filterBit & PAS_ROUTING_FILTER)

    if (filterBit & PACKET_SNIFFER_ENABLE_APP) //APP -> non routing
    {
        if (ipHeader->ip_nh == IPPROTO_TCP)
        {
            return TRUE;
        }

        if (ipHeader->ip_nh == IPPROTO_UDP)
        {
            TransportUdpHeader* udp = NULL;
            UInt8* nextHeader = ((UInt8*) ipHeader) + LIBNET_IPV6_H;
            udp = (TransportUdpHeader *) nextHeader;

            switch (udp->destPort)
            {
                case APP_ROUTING_OLSR_INRIA:
                case APP_ROUTING_RIPNG:
                case APP_ROUTING_OLSRv2_NIIGATA:
                    return FALSE;
                default:
                    return TRUE;
            }
        }

        switch(ipHeader->ip_nh)
        {
            case IPPROTO_AODV:
            case IPPROTO_OSPF:
            case IPPROTO_DYMO:
                return FALSE;
            default:
                return TRUE;
        }
    }
    return FALSE;
}
