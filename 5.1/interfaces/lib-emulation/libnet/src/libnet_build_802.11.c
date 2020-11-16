/*

 *  $Id: libnet_build_802.11.c,v 1.1.10.3 2010-11-03 03:44:13 rich Exp $

 *

 *  libnet

 *  libnet_build_802_11.c - ethernet packet assembler

 *

 *  Copyright (c) 2001-2013, SCALABLE Network Technologies, Inc.  All Rights Reserved.

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

//libnet_build_802_11(u_int8_t *dst, u_int8_t *src, u_int16_t type, u_int8_t *payload,

libnet_build_802_11(u_int8_t *payload, u_int32_t payload_s, libnet_t *l, libnet_ptag_t ptag)

{

    u_int32_t n, h;

    libnet_pblock_t *p;

    //struct libnet_ethernet_hdr eth_hdr;



    if (l == NULL)

    { 

        return (-1);

    } 



    /* sanity check injection type if we're not in advanced mode */

    if (l->injection_type != LIBNET_LINK &&

            !(((l->injection_type) & LIBNET_ADV_MASK)))

    {

         snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,

            "%s(): called with non-link layer wire injection primitive",

                    __func__);

        p = NULL;

        goto bad;

    }



    //n = LIBNET_ETH_H + payload_s;

    // no header required since it's ready to sent

    n=payload_s; 

    h = 0;

 

    /*

     *  Find the existing protocol block if a ptag is specified, or create

     *  a new one.

     */

    //p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_ETH_H);

    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_802_11_H);

    if (p == NULL)

    {

        return (-1);

    }



#ifdef DERIUS

    memset(&eth_hdr, 0, sizeof(eth_hdr));

    memcpy(eth_hdr.ether_dhost, dst, ETHER_ADDR_LEN);  /* destination address */

    memcpy(eth_hdr.ether_shost, src, ETHER_ADDR_LEN);  /* source address */

    eth_hdr.ether_type = htons(type);                  /* packet type */

#endif



    //n = libnet_pblock_append(l, p, (u_int8_t *)&eth_hdr, LIBNET_ETH_H);

    n = libnet_pblock_append(l, p, (u_int8_t *)payload, payload_s);

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

 

/*

    if (payload && payload_s)

    {

        n = libnet_pblock_append(l, p, payload, payload_s);

        if (n == -1)

        {

            goto bad;

        }

    }

*/ 

    //return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_ETH_H));

    //

    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_802_11_H));

bad:

    libnet_pblock_delete(l, p);

    return (-1);

}

