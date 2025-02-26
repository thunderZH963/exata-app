/*
 *  $Id: libnet_build_bgp.c,v 1.2.78.1 2009-03-18 19:34:39 rich Exp $
 *
 *  libnet
 *  libnet_build_bgp.c - BGP packet assembler (RFC 1771)
 *
 *  Copyright (c) 2003 Frederic Raynal <pappy@security-labs.org>
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
libnet_build_bgp4_header(u_int8_t marker[LIBNET_BGP4_MARKER_SIZE], 
       u_int16_t len, u_int8_t type, u_int8_t *payload, u_int32_t payload_s,
       libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    struct libnet_bgp4_header_hdr bgp4_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = LIBNET_BGP4_HEADER_H + payload_s;   /* size of memory block */
    h = 0;                                  /* BGP headers have no checksum */

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_BGP4_HEADER_H);
    if (p == NULL)
    {
        return (-1);
    }

	memset(&bgp4_hdr, 0, sizeof(bgp4_hdr));
	memcpy(bgp4_hdr.marker, marker, LIBNET_BGP4_MARKER_SIZE * sizeof (u_int8_t));
    bgp4_hdr.len = htons(len);
    bgp4_hdr.type = type;

    n = libnet_pblock_append(l, p, (u_int8_t *)&bgp4_hdr, LIBNET_BGP4_HEADER_H);
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
            /* err msg set in libnet_pblock_append() */
            goto bad;
        }
    }
    
    return (ptag ? ptag : libnet_pblock_update(l, p, h,
            LIBNET_PBLOCK_BGP4_HEADER_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

libnet_ptag_t
libnet_build_bgp4_open(u_int8_t version, u_int16_t src_as, u_int16_t hold_time,
            u_int32_t bgp_id, u_int8_t opt_len, u_int8_t *payload, u_int32_t payload_s,
	    libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    u_int16_t val;

    if (l == NULL)
    { 
        return (-1);
    } 

    n = LIBNET_BGP4_OPEN_H + payload_s;     /* size of memory block */
    h = 0;                                  /* BGP msg have no checksum */

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_BGP4_OPEN_H);
    if (p == NULL)
    {
        return (-1);
    }

    /* for memory alignment reason, we need to append each field separately */
    n = libnet_pblock_append(l, p, (u_int8_t *)&version, sizeof (version));
    if (n == -1)
    {
        goto bad;
    }

    val = htons(src_as);
    n = libnet_pblock_append(l, p, (u_int8_t *)&val, sizeof(src_as));
    if (n == -1)
    {
        goto bad;
    }

    val = htons(hold_time);
    n = libnet_pblock_append(l, p, (u_int8_t *)&val, sizeof(hold_time));
    if (n == -1)
    {
        goto bad;
    }

    n = htonl(bgp_id);
    n = libnet_pblock_append(l, p, (u_int8_t *)&n, sizeof(bgp_id));
    if (n == -1)
    {
        goto bad;
    }

    n = libnet_pblock_append(l, p, (u_int8_t *)&opt_len, sizeof(opt_len));
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
            /* err msg set in libnet_pblock_append() */
            goto bad;
        }
    }
    
    return (ptag ? ptag : libnet_pblock_update(l, p, h,
           LIBNET_PBLOCK_BGP4_OPEN_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

libnet_ptag_t
libnet_build_bgp4_update(u_int16_t unfeasible_rt_len, u_int8_t *withdrawn_rt,
            u_int16_t total_path_attr_len, u_int8_t *path_attributes,
	    u_int16_t info_len, u_int8_t *reachability_info,
	    u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    u_int16_t length;

    if (l == NULL)
    { 
        return (-1);
    } 

    /* size of memory block */
    n = LIBNET_BGP4_UPDATE_H + unfeasible_rt_len + total_path_attr_len +
            info_len + payload_s;

    /* BGP msg have no checksum */
    h = 0;                                  

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_BGP4_UPDATE_H);
    if (p == NULL)
    {
        return (-1);
    }

    /* for memory alignment reason, we need to append each field separately */
    length = htons(unfeasible_rt_len);
    n = libnet_pblock_append(l, p, (u_int8_t *)&length, 
            sizeof (unfeasible_rt_len));
    if (n == -1)
    {
        goto bad;
    }

    if (unfeasible_rt_len && withdrawn_rt)
    {
	n = libnet_pblock_append(l, p, withdrawn_rt, unfeasible_rt_len);
	if (n == -1)
	{
	    goto bad;
	}
    }

    length = htons(total_path_attr_len);
    n = libnet_pblock_append(l, p, (u_int8_t *)&length,
            sizeof (total_path_attr_len));
    if (n == -1)
    {
        goto bad;
    }

    if (total_path_attr_len && path_attributes)
    {
	n = libnet_pblock_append(l, p, path_attributes, total_path_attr_len);
	if (n == -1)
	{
	    goto bad;
	}
    }

    if (info_len && reachability_info)
    {
	n = libnet_pblock_append(l, p, reachability_info, info_len);
	if (n == -1)
	{
	    goto bad;
	}
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
            /* err msg set in libnet_pblock_append() */
            goto bad;
        }
    }
    
    return (ptag ? ptag : libnet_pblock_update(l, p, h,
            LIBNET_PBLOCK_BGP4_UPDATE_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

libnet_ptag_t
libnet_build_bgp4_notification(u_int8_t err_code, u_int8_t err_subcode,
	    u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{
    u_int32_t n, h;
    libnet_pblock_t *p;
    struct libnet_bgp4_notification_hdr bgp4_hdr;

    if (l == NULL)
    { 
        return (-1);
    } 

    n =  LIBNET_BGP4_NOTIFICATION_H + + payload_s;    /* size of memory block */
    h = 0; 

    /*
     *  Find the existing protocol block if a ptag is specified, or create
     *  a new one.
     */
    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_BGP4_NOTIFICATION_H);
    if (p == NULL)
    {
        return (-1);
    }

	memset(&bgp4_hdr, 0, sizeof(bgp4_hdr));
	bgp4_hdr.err_code    = err_code;
    bgp4_hdr.err_subcode = err_subcode;

    n = libnet_pblock_append(l, p, (u_int8_t *)&bgp4_hdr,
            LIBNET_BGP4_NOTIFICATION_H);
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
            /* err msg set in libnet_pblock_append() */
            goto bad;
        }
    }
    
    return (ptag ? ptag : libnet_pblock_update(l, p, h,
            LIBNET_PBLOCK_BGP4_NOTIFICATION_H));
bad:
    libnet_pblock_delete(l, p);
    return (-1);
}

/* EOF */
