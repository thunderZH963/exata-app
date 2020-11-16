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
 * Ported from TCPLIB.  This file contains distribution of applications.
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

#define NUMAPP 5

struct app_brkdn
{
    const char *appname;
    float mean;
    float mean_sqr;
    float var;
};

static struct app_brkdn apps_brkdn[] =
{
    { "ftp", 2.160000e-02F, 4.665599e-04F, 3.281600e-04F },
    { "telnet", 6.120000e-02F, 3.745440e-03F, 2.816840e-03F },
    { "nntp", 5.600000e-03F, 3.136000e-05F, 3.696001e-05F },
    { "smtp", 3.798000e-01F, 1.442481e-01F, 8.871418e-02F },
    { "phone", 1.032701e-40F, 0.0 /*1.066471e-80F*/, 0.000000e+00F },
    { 0 }
};

