/*

 *  $Id: libnet_build_data.c,v 1.1.10.3 2010-11-03 03:44:13 rich Exp $

 *

 *  libnet

 *  libnet_build_data.c - generic data block builder

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

libnet_build_data(u_int8_t *payload, u_int32_t payload_s, libnet_t *l,

            libnet_ptag_t ptag)

{

    u_int32_t n, h;

    libnet_pblock_t *p;



    if (l == NULL)

    { 

        return (-1);

    } 



    n = payload_s;

    h = 0;          /* no checksum on generic block */



    /*

     *  Find the existing protocol block if a ptag is specified, or create

     *  a new one.

     */

    p = libnet_pblock_probe(l, ptag, n, LIBNET_PBLOCK_DATA_H);

    if (p == NULL)

    {

        return (-1);

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



    return (ptag ? ptag : libnet_pblock_update(l, p, h, LIBNET_PBLOCK_DATA_H));

bad:

    libnet_pblock_delete(l, p);

    return (-1);

}



/* EOF */

