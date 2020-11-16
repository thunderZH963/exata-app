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
 * Ported from TCPLIB.  This file contains tcplib() and lookup().
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

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include "random.h"
#include "tcplib.h"

int
lookup(struct histmap *hmp, const char *h_name)
{
    int i;
    struct histmap *p;

    for (i = 0, p = hmp;
         i < MAXHIST && p->h_name != 0 && strcmp(p->h_name, h_name);
         i++, ++p)
    {
        /* Do nothing. */
    }

    if (i == MAXHIST)
    {
        perror("Too many characteristics.");
        exit(1);
    }
    if (p->h_name == 0)
    {
        perror("Characteristic not found.");
        exit(1);
    }

    return i;
}

#define MAXRAND 2147483647
#define uniform_rand(from, to, seed)\
  ((from) + (((double) RANDOM_nrand((seed))/MAXRAND) * ((to) - (from))))

double
tcplib(struct histmap *hmp, struct entry *tbl, RandomSeed seed)
{
    double prob;
    int maxbin = hmp->nbins-1;
    int base = 0;
    int bound = maxbin;
    int mid = (int)((float) maxbin / 2.0 + 0.5);

    prob = ((double) (RANDOM_nrand(seed) % PRECIS)) / (double) PRECIS;

    do
    {
        while (prob <= tbl[mid-1].prob && mid != 1)
        {
            bound = mid;
            mid -= (int) (((float) (mid - base)) / 2.0 + 0.5);
        }

        while (prob > tbl[mid].prob)
        {
            base = mid;
            mid += (int) (((float) (bound - mid)) / 2.0 + 0.5);
        }
    } while (!(mid == 1 || (prob >= tbl[mid-1].prob && prob <= tbl[mid].prob)));

    if (mid == 1 && prob < tbl[0].prob)
    {
        return ((double) tbl[0].value);
    }
    else
    {
        return ((double) uniform_rand(tbl[mid-1].value, tbl[mid].value, seed));
    }
}

