/*
 *  $Id: libnet_internal.c,v 1.2.78.1 2009-03-18 19:34:40 rich Exp $
 *
 *  libnet
 *  libnet_internal.c - secret routines!
 *
 *  Copyright (c) 1998 - 2004 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#if (HAVE_CONFIG_H)
#include "../include/config.h"
#endif
#if (!(_WIN32) || (__CYGWIN__)) 
#include "../include/libnet.h"
#else
#include "../include/win32/libnet.h"
#endif

void
libnet_diag_dump_hex(u_int8_t *packet, u_int32_t len, int swap, FILE *stream)
{
    int i, s_cnt;
    u_int16_t *p;

    p     = (u_int16_t *)packet;
    s_cnt = len / sizeof(u_int16_t);

    fprintf(stream, "\t");
    for (i = 0; --s_cnt >= 0; i++)
    {
        if ((!(i % 8)))
        {
            fprintf(stream, "\n%02x\t", (i * 2));
        }
        fprintf(stream, "%04x ", swap ? ntohs(*(p++)) : *(p++));
    }

    /*
     *  Mop up an odd byte.
     */
    if (len & 1)
    {
        if ((!(i % 8)))
        {
            fprintf(stream, "\n%02x\t", (i * 2));
        }
        fprintf(stream, "%02x ", *(u_int8_t *)p);
    }
    fprintf(stream, "\n");
}


void
libnet_diag_dump_context(libnet_t *l)
{
    if (l == NULL)
    { 
        return;
    } 

    fprintf(stderr, "fd:\t\t%d\n", l->fd);
 
    switch (l->injection_type)
    {
        case LIBNET_LINK:
            fprintf(stderr, "injection type:\tLIBNET_LINK\n");
            break;
        case LIBNET_RAW4:
            fprintf(stderr, "injection type:\tLIBNET_RAW4\n");
            break;
        case LIBNET_RAW6:
            fprintf(stderr, "injection type:\tLIBNET_RAW6\n");
            break;
        case LIBNET_LINK_ADV:
            fprintf(stderr, "injection type:\tLIBNET_LINK_ADV\n");
            break;
        case LIBNET_RAW4_ADV:
            fprintf(stderr, "injection type:\tLIBNET_RAW4_ADV\n");
            break;
        case LIBNET_RAW6_ADV:
            fprintf(stderr, "injection type:\tLIBNET_RAW6_ADV\n");
            break;
        default:
            fprintf(stderr, "injection type:\tinvalid injection type %d\n", 
                    l->injection_type);
            break;
    }
    
    fprintf(stderr, "pblock start:\t%p\n", l->protocol_blocks);
    fprintf(stderr, "pblock end:\t%p\n", l->pblock_end);
    fprintf(stderr, "link type:\t%d\n", l->link_type);
    fprintf(stderr, "link offset:\t%d\n", l->link_offset);
    fprintf(stderr, "aligner:\t%d\n", l->aligner);
    fprintf(stderr, "device:\t\t%s\n", l->device);
    fprintf(stderr, "packets sent:\t%lld\n", l->stats.packets_sent);
    fprintf(stderr, "packet errors:\t%lld\n", l->stats.packet_errors);
    fprintf(stderr, "bytes written:\t%lld\n", l->stats.bytes_written);
    fprintf(stderr, "ptag state:\t%d\n", l->ptag_state);
    fprintf(stderr, "context label:\t%s\n", l->label);
    fprintf(stderr, "last errbuf:\t%s\n", l->err_buf);
    fprintf(stderr, "total size:\t%d\n", l->total_size);
}

void
libnet_diag_dump_pblock(libnet_t *l)
{
    u_int32_t n;
    libnet_pblock_t *p;

    for (p = l->protocol_blocks; p; p = p->next)
    {
        fprintf(stderr, "pblock type:\t%s\n", 
                libnet_diag_dump_pblock_type(p->type));
        fprintf(stderr, "ptag number:\t%d\n", p->ptag);
        fprintf(stderr, "IP offset:\t%d\n", p->ip_offset);
        fprintf(stderr, "pblock address:\t%p\n", p);
        fprintf(stderr, "next pblock\t%p ", p->next);
        if (p->next)
        {
            fprintf(stderr, "(%s)",
                    libnet_diag_dump_pblock_type(p->next->type));
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "prev pblock\t%p ", p->prev);
        if (p->prev)
        {
            fprintf(stderr, "(%s)",
                    libnet_diag_dump_pblock_type(p->prev->type));
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "buf:\t\t");
        for (n = 0; n < p->b_len; n++)
        {
            fprintf(stderr, "%02x", p->buf[n]);
        }
        fprintf(stderr, "\nbuffer length:\t%d\n", p->b_len);
        if ((p->flags) & LIBNET_PBLOCK_DO_CHECKSUM)
        {
            fprintf(stderr, "checksum flag:\tYes\n");
            fprintf(stderr, "chksum length:\t%d\n", p->h_len);
        }
        else
        {
            fprintf(stderr, "checksum flag:\tNo\n");
        }
        fprintf(stderr, "bytes copied:\t%d\n\n", p->copied);
    }
}

char *
libnet_diag_dump_pblock_type(u_int8_t type)
{
    static int8_t buf[50];
    switch (type)
    {
        case LIBNET_PBLOCK_ARP_H:
            return ("arp header");
        case LIBNET_PBLOCK_DHCPV4_H:
            return ("dhcpv4 header");
        case LIBNET_PBLOCK_DNSV4_H:
            return ("dnsv4 header");
        case LIBNET_PBLOCK_ETH_H:
            return ("ethernet header");
        case LIBNET_PBLOCK_ICMPV4_H:
            return ("icmpv4 header");
        case LIBNET_PBLOCK_ICMPV4_ECHO_H:
            return ("icmpv4 echo header");
        case LIBNET_PBLOCK_ICMPV4_MASK_H:
            return ("icmpv4 mask header");
        case LIBNET_PBLOCK_ICMPV4_UNREACH_H:
            return ("icmpv4 unreachable header");
        case LIBNET_PBLOCK_ICMPV4_TIMXCEED_H:
            return ("icmpv4 time exceeded header");
        case LIBNET_PBLOCK_ICMPV4_REDIRECT_H:
            return ("icmpv4 redirect header");
        case LIBNET_PBLOCK_ICMPV4_TS_H:
            return ("icmpv4 timestamp header");
        case LIBNET_PBLOCK_IGMP_H:
            return ("igmp header");
        case LIBNET_PBLOCK_IPV4_H:
            return ("ipv4 header");
        case LIBNET_PBLOCK_IPO_H:
            return ("ip options header");
        case LIBNET_PBLOCK_IPDATA:
            return ("ip data");
        case LIBNET_PBLOCK_OSPF_H:
            return ("ospf header");
        case LIBNET_PBLOCK_OSPF_HELLO_H:
            return ("ospf hello header");
        case LIBNET_PBLOCK_OSPF_DBD_H:
            return ("ospf dbd header");
        case LIBNET_PBLOCK_OSPF_LSR_H:
            return ("ospf lsr header");
        case LIBNET_PBLOCK_OSPF_LSU_H:
            return ("ospf lsu header");
        case LIBNET_PBLOCK_OSPF_LSA_H:
            return ("ospf lsa header");
        case LIBNET_PBLOCK_OSPF_AUTH_H:
            return ("ospf authentication header");
        case LIBNET_PBLOCK_OSPF_CKSUM:
            return ("ospf checksum");
        case LIBNET_PBLOCK_LS_RTR_H:
            return ("ospf ls rtr header");
        case LIBNET_PBLOCK_LS_NET_H:
            return ("ospf ls net header");
        case LIBNET_PBLOCK_LS_SUM_H:
            return ("ospf ls sum header");
        case LIBNET_PBLOCK_LS_AS_EXT_H:
            return ("ospf ls as extension header");
        case LIBNET_PBLOCK_NTP_H:
            return ("ntp header");
        case LIBNET_PBLOCK_RIP_H:
            return ("rip header");
        case LIBNET_PBLOCK_TCP_H:
            return ("tcp header");
        case LIBNET_PBLOCK_TCPO_H:
            return ("tcp options header");
        case LIBNET_PBLOCK_TCPDATA:
            return ("tcp data");
        case LIBNET_PBLOCK_UDP_H:
            return ("udp header");
        case LIBNET_PBLOCK_VRRP_H:
            return ("vrrp header");
        case LIBNET_PBLOCK_DATA_H:
            return ("data");
        case LIBNET_PBLOCK_CDP_H:
            return ("cdp header");
        case LIBNET_PBLOCK_IPSEC_ESP_HDR_H:
            return ("ipsec esp header");
        case LIBNET_PBLOCK_IPSEC_ESP_FTR_H:
            return ("ipsec esp footer");
        case LIBNET_PBLOCK_IPSEC_AH_H:
            return ("ipsec authentication header");
        case LIBNET_PBLOCK_802_1Q_H:
            return ("802.1q header");
        case LIBNET_PBLOCK_802_2_H:
            return ("802.2 header");
        case LIBNET_PBLOCK_802_2SNAP_H:
            return ("802.2SNAP header");
        case LIBNET_PBLOCK_802_3_H:
            return ("802.3 header");
        case LIBNET_PBLOCK_STP_CONF_H:
            return ("stp configuration header");
        case LIBNET_PBLOCK_STP_TCN_H:
            return ("stp tcn header");
        case LIBNET_PBLOCK_ISL_H:
            return ("isl header");
        case LIBNET_PBLOCK_IPV6_H:
            return ("ipv6 header");
        case LIBNET_PBLOCK_802_1X_H:
            return ("802.1x header");
        case LIBNET_PBLOCK_RPC_CALL_H:
            return ("rpc call header");
        case LIBNET_PBLOCK_MPLS_H:
            return ("mlps header");
        case LIBNET_PBLOCK_FDDI_H:
            return ("fddi header");
        case LIBNET_PBLOCK_TOKEN_RING_H:
            return ("token ring header");
        case LIBNET_PBLOCK_BGP4_HEADER_H:
            return ("bgp header");
        case LIBNET_PBLOCK_BGP4_OPEN_H:
            return ("bgp open header");
        case LIBNET_PBLOCK_BGP4_UPDATE_H:
            return ("bgp update header");
        case LIBNET_PBLOCK_BGP4_NOTIFICATION_H:
            return ("bgp notification header");
        case LIBNET_PBLOCK_GRE_H:
            return ("gre header");
        case LIBNET_PBLOCK_GRE_SRE_H:
            return ("gre sre header");
        case LIBNET_PBLOCK_IPV6_FRAG_H:
            return ("ipv6 fragmentation header");
        case LIBNET_PBLOCK_IPV6_ROUTING_H:
            return ("ipv6 routing header");
        case LIBNET_PBLOCK_IPV6_DESTOPTS_H:
            return ("ipv6 destination options header");
        case LIBNET_PBLOCK_IPV6_HBHOPTS_H:
            return ("ipv6 hop by hop options header");
        default:
            snprintf(buf, sizeof(buf),
                    "%s(): unknown pblock type: %d", __func__, type);
            return (buf);
    }
    return ("unreachable code");
}
/* EOF */
