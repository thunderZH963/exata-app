/*
 *  $Id: libnet_build_cdp.c,v 1.2.78.1 2009-03-18 19:34:39 rich Exp $
 *
 *  libnet
 *  libnet_build_cdp.c - CDP packet assembler
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
libnet_build_cdp(u_int8_t version, u_int8_t ttl, u_int16_t sum, u_int16_t type,
u_int16_t len, u_int8_t *value, u_int8_t *payload, u_int32_t payload_s,
libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n,h;
    libnet_pblock_t *p;
    struct libnet_cdp_hdr cdp_hdr;

    if (l == NULL)
    { 
        return (-1); 
    }

    n = LIBNET_CDP_H + len + payload_s;
    h = LIBNET_CDP_H + len + payload_s;

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_CDP_H);
    if (p == NULL)
    {
        return (-1);
    }

    memset(&cdp_hdr, 0, sizeof(cdp_hdr));
    cdp_hdr.cdp_version = version;
    cdp_hdr.cdp_ttl     = ttl;
    cdp_hdr.cdp_sum     = (sum ? htons(sum) : 0);
    cdp_hdr.cdp_type    = htons(type);
    cdp_hdr.cdp_len     = htons(len + 4);   /* 4 bytes for len and type */

    n = libnet_pblock_append(l, p, (u_int8_t *)&cdp_hdr, LIBNET_CDP_H);
    if (n == -1)
    {
        goto bad;
    }

    n = libnet_pblock_append(l, p, value, len);
    if (n == -1)
    {
        /* err msg set in libnet_pblock_append() */
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

    if (sum == 0)
    {
        /*
         *  If checksum is zero, by default libnet will compute a checksum
         *  for the user.  The programmer can override this by calling
         *  libnet_toggle_checksum(l, ptag, 1);
         */
        libnet_pblock_setflags(p, LIBNET_PBLOCK_DO_CHECKSUM);
    }
    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_CDP_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}


int
/* Not Yet Implemented */
libnet_build_cdp_value(u_int16_t type, u_int16_t len, u_int8_t *value, libnet_t *l,
        libnet_ptag_t ptag)
{
    u_int32_t n;
    libnet_pblock_t *p;
    struct libnet_cdp_value_hdr cdp_value_hdr;

    if (l == NULL)
    { 
        return (-1); 
    }

    /*
     *  Find the existing protocol block.
     */
    p = libnet_pblock_find(l, ptag);
    if (p == NULL)
    {
        /* err msg set in libnet_pblock_find */
        return (-1);
    }
    if (p->type != LIBNET_PBLOCK_CDP_H)
    {
         snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
            "libnet_build_cdp_value: ptag references different type than expected");
        return (-1);
    }

	memset(&cdp_value_hdr, 0, sizeof(cdp_value_hdr));
	cdp_value_hdr.cdp_type  = htons(type);
    cdp_value_hdr.cdp_len   = htons(len + 4);   /* 4 bytes for len and type */

    switch (type)
    {
        case LIBNET_CDP_DEVID:
            break;
        case LIBNET_CDP_ADDRESS:
            break;
        case LIBNET_CDP_PORTID:
            break;
        case LIBNET_CDP_CAPABIL:
            break;
        case LIBNET_CDP_VERSION:
            break;
        case LIBNET_CDP_PLATFORM:
            break;
        case LIBNET_CDP_IPPREFIX:
            break;
        default:
            break;
    }

    n = libnet_pblock_append(l, p, (u_int8_t *)&cdp_value_hdr, LIBNET_CDP_H);
    if (n == -1)
    {
        return (-1);
    }

    n = libnet_pblock_append(l, p, value, len);
    if (n == -1)
    {
        /* err msg set in libnet_pblock_append() */
        return (-1);
    }

    return (1);
}

/* EOF */
