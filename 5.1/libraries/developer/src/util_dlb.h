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

#ifndef _DLB_H
#define _DLB_H

#include "types.h"

// Dual Leaky Bucket struct
// This struct simply provides a way of determining whether or not a given
// length of data should be accepted according to predetermined (D)LB
// parameters.
typedef struct {
    // Parameters that are set by users ///////////////////////////////////////
    Int32       bucketSize;     // Token bucket size in byte (regular LB param)
    Int32       tokenRate;      // Token rate in bps (regular LB param)
    Int32       peakRate;       // Peak rate in bps (it becomes Dual LB if > 0)

    // Private records ////////////////////////////////////////////////////////
    clocktype   lastTokenTm;    // Last time tokens were generated
    clocktype   lastAccTm;      // Last time data was accepted
    Int32       curBktSize;     // Current bucket size
} Dlb;

/*
 * NAME:        DlbReset
 * PURPOSE:     resets dual leaky bucket with given parameters
 * PARAMETERS:  dlb - pointer to the dual leaky bucket
 *              bucketSize - new bucket size in bytes
 *              tokenRate - token generation rate in bps
 *              peakRate - maximum allowed rate (if zero, it becomes just a
 *                         leaky bucket)
 * RETURN:      none
 */
void DlbReset(Dlb* dlb, Int32 bucketSize, Int32 tokenRate, Int32 peakRate,
              clocktype theTime);

/*
 * NAME:        DlbUpdate
 * PURPOSE:     updates dual leaky bucket with given data length
 * PARAMETERS:  dlb - pointer to the dual leaky bucket
 *              dataLen - data length in bytes
 * RETURN:      time difference between now and when the data is allowed
 */
clocktype DlbUpdate(Dlb* dlb, Int32 dataLen, clocktype theTime);

#endif  // _DLB_H

