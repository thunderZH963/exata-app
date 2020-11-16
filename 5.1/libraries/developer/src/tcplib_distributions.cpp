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
// use in compliance with the license agreement as part of the QualNet
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

/*
 *
 * Ported from TCPLIB.  This file contains gam_dist().
 */

/*
 * Copyright (c) 1991 University of Southern California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of Southern California. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
*/

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "random.h"
#include "tcplib_distributions.h"

/* Numerical Recipes in C, p. 220. */
float
gam_dist(float n, float n2, float s, RandomSeed seed)
{
    int i, r;
    double g, rm, rs, v1, v2, y, e;

    if (!s)
    {
        return 0.0;
    }

    r = (int) ((double) n2 / s + 0.5); /* Kleinrock, p. 124 */

    if (r < 1)
    {
        perror("gam_dist: bad r\n");
        exit(1);
    }

    if (r < 6)
    {
        g = 1.0;
        for (i = 0; i <= r; i++)
        {
            g *= (float) RANDOM_erand(seed);
        }
        g = -log((double) g);
    }
    else
    {
        do
        {
            do
            {
                do
                {
                    v1 = 2.0 * RANDOM_erand(seed) - 1.0;
                    v2 = 2.0 * RANDOM_erand(seed) - 1.0;
                } while ((v1 * v2) + (v1 * v2) > 1.0);

                y = v2 / v1;
                rm = r - 1;
                rs = sqrt(2.0 * rm + 1.0);
                g = rs * y + rm;
            } while (g <= 0.0);

            e = (1.0 + y * y) * exp(rm * log((double) g / rm) - rs * y);
        } while (RANDOM_erand(seed) > e);
    }

    g = (double) ((g * (double) n) / (double) r);
    return ((float) g);
}

