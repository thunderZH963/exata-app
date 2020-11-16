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
/*********************************************************************
 *
 * AUTHORIZATION TO USE AND DISTRIBUTE
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that:
 *
 * (1) source code distributions retain this paragraph in its entirety,
 *
 * (2) distributions including binary code include this paragraph in
 *     its entirety in the documentation or other materials provided
 *     with the distribution, and
 *
 * (3) all advertising materials mentioning features or use of this
 *     software display the following acknowledgment:
 *
 *      "This product includes software written and developed
 *       by Brian Adamson and Joe Macker of the Naval Research
 *       Laboratory (NRL)."
 *
 *  The name of NRL, the name(s) of NRL  employee(s), or any entity
 *  of the United States Government may not be used to endorse or
 *  promote  products derived from this software, nor does the
 *  inclusion of the NRL written and developed software  directly or
 *  indirectly suggest NRL or United States  Government endorsement
 *  of this product.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 ********************************************************************/

#ifndef _MDP_PROTO_DEFS
#define _MDP_PROTO_DEFS


#include "types.h"
#include "clock.h"
#include "qualnet_error.h"

#if defined (WIN32) || defined (_WIN32) || defined (__WIN64)
#include <time.h>
#include <sys/timeb.h>
#include <io.h>
#include <sys/types.h>
const char MDP_PROTO_PATH_DELIMITER = '\\';
#define MDP_PATH_MAX MAX_PATH
typedef void *HANDLE;
#define MDP_FOR_WINDOWS

#else //for UNIX

#include <sys/time.h>
#include <sys/times.h>
#include <limits.h>
#include <sys/types.h>
#include <stdio.h>
#include <dirent.h>
const char MDP_PROTO_PATH_DELIMITER = '/';
#define MDP_PATH_MAX _POSIX_PATH_MAX
#define MDP_FOR_UNIX
#endif

#ifndef MAX
#define MAX(X,Y) ((X>Y)?(X):(Y))
#endif //!MAX
#ifndef MIN
#define MIN(X,Y) ((X<Y)?(X):(Y))
#endif //!MIN


#define ASSERT(expr) ERROR_Assert(expr, "")

//#define PROTO_DEBUG
#define MDP_SIGNED_BIT_INTEGER 0x80000000

#define MDP_DEBUG 0

typedef UInt64 MdpNodeId;
typedef UInt64 MdpObjectTransportId;

struct timevalue
{
    Int64    tv_sec;         /* seconds */
    Int64    tv_usec;        /* and microseconds */
};

inline void ProtoSystemTime(struct timevalue& theTime, clocktype simTime)
{
    theTime.tv_sec = simTime / 1000000000;
    theTime.tv_usec = simTime / 1000 - theTime.tv_sec * 1000000;
}


#endif // _MDP_PROTO_DEFS
