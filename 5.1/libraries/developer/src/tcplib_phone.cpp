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
 * Ported from TCPLIB.  This file contains functions for generating
 * the duration of talk spurts of a phone conversion, etc.
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
 *
*/

#include "random.h"
#include "tcplib.h"
#include "tcplib_phone.h"

static struct entry pause[] =
{
    { 200.000000F, 0.013000F },
    { 225.000000F, 0.050000F },
    { 250.000000F, 0.087000F },
    { 275.000000F, 0.125000F },
    { 300.000000F, 0.155000F },
    { 325.000000F, 0.191000F },
    { 350.000000F, 0.225000F },
    { 375.000000F, 0.262000F },
    { 400.000000F, 0.287000F },
    { 450.000000F, 0.325000F },
    { 500.000000F, 0.363000F },
    { 550.000000F, 0.400000F },
    { 600.000000F, 0.438000F },
    { 650.000000F, 0.462000F },
    { 700.000000F, 0.478000F },
    { 750.000000F, 0.512000F },
    { 800.000000F, 0.537000F },
    { 850.000000F, 0.550000F },
    { 900.000000F, 0.575000F },
    { 950.000000F, 0.591000F },
    { 1000.000000F, 0.611000F },
    { 1125.000000F, 0.633000F },
    { 1250.000000F, 0.658000F },
    { 1375.000000F, 0.675000F },
    { 1500.000000F, 0.700000F },
    { 1625.000000F, 0.718000F },
    { 1750.000000F, 0.737000F },
    { 1875.000000F, 0.758000F },
    { 2000.000000F, 0.775000F },
    { 2250.000000F, 0.791000F },
    { 2500.000000F, 0.813000F },
    { 2750.000000F, 0.825000F },
    { 3000.000000F, 0.841000F },
    { 3250.000000F, 0.858000F },
    { 3500.000000F, 0.874000F },
    { 3750.000000F, 0.883000F },
    { 4000.000000F, 0.900000F },
    { 4500.000000F, 0.913000F },
    { 5000.000000F, 0.925000F },
    { 5500.000000F, 0.934000F },
    { 6000.000000F, 0.941000F },
    { 6500.000000F, 0.950000F },
    { 7000.000000F, 0.958000F },
    { 7500.000000F, 0.962000F },
    { 8000.000000F, 0.966000F },
    { 8500.000000F, 0.974000F },
    { 9000.000000F, 0.975000F },
    { 9500.000000F, 0.977000F },
    { 10000.000000F, 0.983000F },
    { 11250.000000F, 0.987000F },
    { 12500.000000F, 0.989000F },
    { 13750.000000F, 0.991000F },
    { 15000.000000F, 0.997000F },
    { 16250.000000F, 0.998000F },
    { 18750.000000F, 0.999000F },
    { 20000.000000F, 1.000000F }
};

float
phone_talkspurt(RandomSeed seed)
{
    return ((float) tcplib(&phone_histmap[lookup(phone_histmap, "talkspurt")], talkspurt, seed));
}

float
phone_pause(RandomSeed seed)
{
    return ((float) tcplib(&phone_histmap[lookup(phone_histmap, "pause")], pause, seed));
}

