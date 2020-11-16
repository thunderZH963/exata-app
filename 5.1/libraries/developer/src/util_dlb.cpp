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

#include <stdlib.h>

#include "api.h"
#include "util_dlb.h"

#define SIM2SEC(x) (((double)(x)) / SECOND)
#define SEC2SIM(x) ((x) * SECOND)

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
              clocktype theTime)
{
    dlb->lastTokenTm = dlb->lastAccTm = theTime;
    dlb->bucketSize  = bucketSize;
    dlb->tokenRate   = tokenRate;
    dlb->peakRate    = peakRate;
    dlb->curBktSize  = bucketSize;
}

/*
 * NAME:        DlbUpdate
 * PURPOSE:     updates dual leaky bucket with given data length
 * PARAMETERS:  dlb - pointer to the dual leaky bucket
 *              dataLen - data length in bytes
 * RETURN:      time difference between now and when the data is allowed
 */
clocktype DlbUpdate(Dlb* dlb, Int32 dataLen, clocktype theTime)
{
    Int32        newToken;
    clocktype   tmAmt;

    if (dlb->bucketSize > 0 && dlb->tokenRate > 0) {  // Yes, LB is on.

        // Generate some tokens according to the time difference between
        // now and the last time when some tokens were consumed.
        newToken = (Int32)(dlb->tokenRate
            * SIM2SEC(theTime - dlb->lastTokenTm) / 8.0);
        dlb->curBktSize += newToken;
        if (newToken)   // time should be changed only when new token got in.
            dlb->lastTokenTm = theTime;

        // Discard any overflown tokens.
        if (dlb->curBktSize > dlb->bucketSize)
            dlb->curBktSize = dlb->bucketSize;

        // Data should be checked if it can be admitted through LB.
        if (dlb->curBktSize < dataLen) {
            // Well, the data should wait for more tokens to get in.
            // Let's compute the time that enough tokens get in.
            tmAmt = (clocktype) (SEC2SIM(((dataLen - dlb->curBktSize) * 8.0)
                                 / (double)dlb->tokenRate));
            assert(tmAmt > 0);
        } else if (dlb->peakRate > 0) {    // 'dual' LB
            // Check if the data can be admitted without violating
            // the maximum peak rate.
            tmAmt = (clocktype) (SEC2SIM(dataLen * 8.0
                                 / (double)dlb->peakRate) + dlb->lastAccTm);
            if (tmAmt > theTime) {
                // Now, the data cannot be txed since it would exceed the
                // allowed peak rate for the connection by dual leaky bucket.
                // So, the data should be delayed.
                tmAmt -= theTime;
                assert(tmAmt > 0);
            } else {
                dlb->curBktSize -= dataLen;
                dlb->lastAccTm = theTime;
                tmAmt = 0;
            }
        } else {
            // Yes, the data can be admitted.
            dlb->curBktSize -= dataLen;
            tmAmt = 0;
        }
    } else
        tmAmt = 0;

    return tmAmt;
}

