/*

 *  $Id: libnet_build_dns.c,v 1.1.10.3 2010-11-03 03:44:14 rich Exp $

 *

 *  libnet

 *  libnet_build_dns.c - DNS packet assembler

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





libnet_ptag_t

libnet_build_dnsv4(u_int16_t h_len, u_int16_t id, u_int16_t flags,

            u_int16_t num_q, u_int16_t num_anws_rr, u_int16_t num_auth_rr,

            u_int16_t num_addi_rr, u_int8_t *payload, u_int32_t payload_s,

            libnet_t *l, libnet_ptag_t ptag)

{



    u_int32_t n, h;

    u_int offset;

    libnet_pblock_t *p;

    struct libnet_dnsv4_hdr dns_hdr;



    if (l == NULL)

    { 

        return (-1);

    } 



    if (h_len != LIBNET_UDP_DNSV4_H && h_len != LIBNET_TCP_DNSV4_H)

    {

        snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,

                "%s(): invalid header length: %d", __func__, h_len);

       return (-1);

    }

    offset = (h_len == LIBNET_UDP_DNSV4_H ? sizeof(dns_hdr.h_len) : 0);

    n = h_len + payload_s;

    h = 0;          /* no checksum */



    /*

     *  Find the existing protocol block if a ptag is specified, or create

     *  a new one.

     */

    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_DNSV4_H);

    if (p == NULL)

    {

        return (-1);

    }

    /*

     * The sizeof(dns_hdr.h_len) is not counted is the packet size

     * for TCP packet.

     * And since this will be ignored for udp packets, let's compute it 

     * anyway.

     */



    memset(&dns_hdr, 0, sizeof(dns_hdr));

    dns_hdr.h_len       = htons(n - sizeof (dns_hdr.h_len));

    dns_hdr.id          = htons(id);

    dns_hdr.flags       = htons(flags);

    dns_hdr.num_q       = htons(num_q);

    dns_hdr.num_answ_rr = htons(num_anws_rr);

    dns_hdr.num_auth_rr = htons(num_auth_rr);

    dns_hdr.num_addi_rr = htons(num_addi_rr);



    /*

     * A dirty trick: DNS can be either TCP or UDP based, and depending on

     * that, the header changes. A 'length' field is present in TCP packets,

     * but not in UDP packets. As they are the first 2 bytes of the header,

     * they are skipped if the packet is UDP...

     */

    n = libnet_pblock_append(l, p, ((u_int8_t *)&dns_hdr)+ offset, h_len);

    if (n == -1)

    {

        goto bad;

    }



    if ((payload && !payload_s) || (!payload && payload_s))

    {

         snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,

                 "%s(): payload inconsistency\n", __func__);

        goto bad;

    }

 

    if (payload && payload_s)

    {

        n = libnet_pblock_append(l, p, payload, payload_s);

        if (n == -1)

        {

            goto bad; 

        }

    }

 

    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_DNSV4_H));

bad:

    libnet_pblock_delete(l, p);

    return (-1);

}



/* EOF */

