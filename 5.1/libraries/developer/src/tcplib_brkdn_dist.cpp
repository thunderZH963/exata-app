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
 * Ported from TCPLIB.  This file contains functions to get the
 * next application randomly.
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

//#ifndef lint
//static char rcsid[] =
//#endif

#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include "main.h"
#include "random.h"
#include "tcplib_distributions.h"
#include "tcplib_app_brkdn.h"
#include "tcplib_brkdn_dist.h"

struct brkdn_dist *
brkdn_dist(RandomSeed seed)
{
    int i;
    struct brkdn_dist *apps =
        (struct brkdn_dist *) MEM_malloc(NUMAPP * sizeof(struct brkdn_dist));
    float normalizer = 0.0;

    for (i = 0; i < NUMAPP; i++)
    {
        apps[i].appname = apps_brkdn[i].appname;
        apps[i].cdf = gam_dist(
                          apps_brkdn[i].mean,
                          apps_brkdn[i].mean_sqr,
                          apps_brkdn[i].var,
                          seed);
        normalizer += apps[i].cdf;
    }

    apps[0].cdf /= normalizer;
    for (i = 1; i < NUMAPP; i++)
    {
        apps[i].cdf /= normalizer;
        apps[i].cdf += apps[i - 1].cdf;
    }

    return apps;
}

const char *
next_app(struct brkdn_dist brkdn[], RandomSeed seed)
{
        int i = 0;
        float prob = (float) RANDOM_erand(seed);

        while (i < NUMAPP && brkdn[i].cdf < prob)
        {
            i++;
        }

        if (i == NUMAPP)
        {
            perror("next_app: bad prob");
        }

        return brkdn[i].appname;
}
