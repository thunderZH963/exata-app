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
 * Ported from TCPLIB. Header file of phone.c.
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

static struct entry talkspurt[] =
{
    { 10.000000F, 0.000000F },
    { 11.250000F, 0.008000F },
    { 12.500000F, 0.017000F },
    { 13.750000F, 0.024000F },
    { 15.000000F, 0.026000F },
    { 16.250000F, 0.033000F },
    { 17.500000F, 0.041000F },
    { 18.750000F, 0.049000F },
    { 20.000000F, 0.051000F },
    { 22.500000F, 0.055000F },
    { 25.000000F, 0.060000F },
    { 27.500000F, 0.065000F },
    { 30.000000F, 0.070000F },
    { 32.500000F, 0.073000F },
    { 35.000000F, 0.075000F },
    { 37.500000F, 0.079000F },
    { 40.000000F, 0.083000F },
    { 45.000000F, 0.087000F },
    { 50.000000F, 0.091000F },
    { 55.000000F, 0.095000F },
    { 60.000000F, 0.099000F },
    { 65.000000F, 0.101000F },
    { 70.000000F, 0.104000F },
    { 75.000000F, 0.109000F },
    { 80.000000F, 0.114000F },
    { 85.000000F, 0.119000F },
    { 90.000000F, 0.123000F },
    { 95.000000F, 0.124000F },
    { 100.000000F, 0.125000F },
    { 112.500000F, 0.131000F },
    { 125.000000F, 0.138000F },
    { 137.500000F, 0.144000F },
    { 150.000000F, 0.151000F },
    { 162.500000F, 0.164000F },
    { 175.000000F, 0.174000F },
    { 187.500000F, 0.190000F },
    { 200.000000F, 0.201000F },
    { 225.000000F, 0.217000F },
    { 250.000000F, 0.237000F },
    { 275.000000F, 0.250000F },
    { 300.000000F, 0.273000F },
    { 325.000000F, 0.287000F },
    { 350.000000F, 0.308000F },
    { 375.000000F, 0.325000F },
    { 400.000000F, 0.341000F },
    { 450.000000F, 0.366000F },
    { 500.000000F, 0.391000F },
    { 550.000000F, 0.416000F },
    { 600.000000F, 0.445000F },
    { 650.000000F, 0.462000F },
    { 700.000000F, 0.471000F },
    { 750.000000F, 0.495000F },
    { 800.000000F, 0.502000F },
    { 850.000000F, 0.520000F },
    { 900.000000F, 0.530000F },
    { 950.000000F, 0.550000F },
    { 1000.000000F, 0.563000F },
    { 1125.000000F, 0.587000F },
    { 1250.000000F, 0.608000F },
    { 1375.000000F, 0.626000F },
    { 1500.000000F, 0.658000F },
    { 1625.000000F, 0.683000F },
    { 1750.000000F, 0.708000F },
    { 1875.000000F, 0.728000F },
    { 2000.000000F, 0.762000F },
    { 2250.000000F, 0.782000F },
    { 2500.000000F, 0.824000F },
    { 2750.000000F, 0.848000F },
    { 3000.000000F, 0.862000F },
    { 3250.000000F, 0.883000F },
    { 3500.000000F, 0.900000F },
    { 3750.000000F, 0.916000F },
    { 4000.000000F, 0.930000F },
    { 4500.000000F, 0.951000F },
    { 5000.000000F, 0.966000F },
    { 5500.000000F, 0.978000F },
    { 6000.000000F, 0.982000F },
    { 6500.000000F, 0.986000F },
    { 7000.000000F, 0.990000F },
    { 7500.000000F, 0.998000F },
    { 9500.000000F, 0.999000F },
    { 10000.000000F, 1.000000F }
};

static struct histmap phone_histmap[] =
{
    { "talkspurt", 82 },
    { "pause", 56 }
};

