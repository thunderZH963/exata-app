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


#include "mdpBitMask.h"

// Hamming weights for given one-byte bit masks
unsigned char WEIGHT[256] =
{
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8
};

// Erasure location vectors for given one-byte bit masks
unsigned char BITLOCS[256][8] =
{
    {0, 0, 0, 0, 0, 0, 0, 0}, {7, 0, 0, 0, 0, 0, 0, 0},
    {6, 0, 0, 0, 0, 0, 0, 0}, {6, 7, 0, 0, 0, 0, 0, 0},
    {5, 0, 0, 0, 0, 0, 0, 0}, {5, 7, 0, 0, 0, 0, 0, 0},
    {5, 6, 0, 0, 0, 0, 0, 0}, {5, 6, 7, 0, 0, 0, 0, 0},
    {4, 0, 0, 0, 0, 0, 0, 0}, {4, 7, 0, 0, 0, 0, 0, 0},
    {4, 6, 0, 0, 0, 0, 0, 0}, {4, 6, 7, 0, 0, 0, 0, 0},
    {4, 5, 0, 0, 0, 0, 0, 0}, {4, 5, 7, 0, 0, 0, 0, 0},
    {4, 5, 6, 0, 0, 0, 0, 0}, {4, 5, 6, 7, 0, 0, 0, 0},
    {3, 0, 0, 0, 0, 0, 0, 0}, {3, 7, 0, 0, 0, 0, 0, 0},
    {3, 6, 0, 0, 0, 0, 0, 0}, {3, 6, 7, 0, 0, 0, 0, 0},
    {3, 5, 0, 0, 0, 0, 0, 0}, {3, 5, 7, 0, 0, 0, 0, 0},
    {3, 5, 6, 0, 0, 0, 0, 0}, {3, 5, 6, 7, 0, 0, 0, 0},
    {3, 4, 0, 0, 0, 0, 0, 0}, {3, 4, 7, 0, 0, 0, 0, 0},
    {3, 4, 6, 0, 0, 0, 0, 0}, {3, 4, 6, 7, 0, 0, 0, 0},
    {3, 4, 5, 0, 0, 0, 0, 0}, {3, 4, 5, 7, 0, 0, 0, 0},
    {3, 4, 5, 6, 0, 0, 0, 0}, {3, 4, 5, 6, 7, 0, 0, 0},
    {2, 0, 0, 0, 0, 0, 0, 0}, {2, 7, 0, 0, 0, 0, 0, 0},
    {2, 6, 0, 0, 0, 0, 0, 0}, {2, 6, 7, 0, 0, 0, 0, 0},
    {2, 5, 0, 0, 0, 0, 0, 0}, {2, 5, 7, 0, 0, 0, 0, 0},
    {2, 5, 6, 0, 0, 0, 0, 0}, {2, 5, 6, 7, 0, 0, 0, 0},
    {2, 4, 0, 0, 0, 0, 0, 0}, {2, 4, 7, 0, 0, 0, 0, 0},
    {2, 4, 6, 0, 0, 0, 0, 0}, {2, 4, 6, 7, 0, 0, 0, 0},
    {2, 4, 5, 0, 0, 0, 0, 0}, {2, 4, 5, 7, 0, 0, 0, 0},
    {2, 4, 5, 6, 0, 0, 0, 0}, {2, 4, 5, 6, 7, 0, 0, 0},
    {2, 3, 0, 0, 0, 0, 0, 0}, {2, 3, 7, 0, 0, 0, 0, 0},
    {2, 3, 6, 0, 0, 0, 0, 0}, {2, 3, 6, 7, 0, 0, 0, 0},
    {2, 3, 5, 0, 0, 0, 0, 0}, {2, 3, 5, 7, 0, 0, 0, 0},
    {2, 3, 5, 6, 0, 0, 0, 0}, {2, 3, 5, 6, 7, 0, 0, 0},
    {2, 3, 4, 0, 0, 0, 0, 0}, {2, 3, 4, 7, 0, 0, 0, 0},
    {2, 3, 4, 6, 0, 0, 0, 0}, {2, 3, 4, 6, 7, 0, 0, 0},
    {2, 3, 4, 5, 0, 0, 0, 0}, {2, 3, 4, 5, 7, 0, 0, 0},
    {2, 3, 4, 5, 6, 0, 0, 0}, {2, 3, 4, 5, 6, 7, 0, 0},
    {1, 0, 0, 0, 0, 0, 0, 0}, {1, 7, 0, 0, 0, 0, 0, 0},
    {1, 6, 0, 0, 0, 0, 0, 0}, {1, 6, 7, 0, 0, 0, 0, 0},
    {1, 5, 0, 0, 0, 0, 0, 0}, {1, 5, 7, 0, 0, 0, 0, 0},
    {1, 5, 6, 0, 0, 0, 0, 0}, {1, 5, 6, 7, 0, 0, 0, 0},
    {1, 4, 0, 0, 0, 0, 0, 0}, {1, 4, 7, 0, 0, 0, 0, 0},
    {1, 4, 6, 0, 0, 0, 0, 0}, {1, 4, 6, 7, 0, 0, 0, 0},
    {1, 4, 5, 0, 0, 0, 0, 0}, {1, 4, 5, 7, 0, 0, 0, 0},
    {1, 4, 5, 6, 0, 0, 0, 0}, {1, 4, 5, 6, 7, 0, 0, 0},
    {1, 3, 0, 0, 0, 0, 0, 0}, {1, 3, 7, 0, 0, 0, 0, 0},
    {1, 3, 6, 0, 0, 0, 0, 0}, {1, 3, 6, 7, 0, 0, 0, 0},
    {1, 3, 5, 0, 0, 0, 0, 0}, {1, 3, 5, 7, 0, 0, 0, 0},
    {1, 3, 5, 6, 0, 0, 0, 0}, {1, 3, 5, 6, 7, 0, 0, 0},
    {1, 3, 4, 0, 0, 0, 0, 0}, {1, 3, 4, 7, 0, 0, 0, 0},
    {1, 3, 4, 6, 0, 0, 0, 0}, {1, 3, 4, 6, 7, 0, 0, 0},
    {1, 3, 4, 5, 0, 0, 0, 0}, {1, 3, 4, 5, 7, 0, 0, 0},
    {1, 3, 4, 5, 6, 0, 0, 0}, {1, 3, 4, 5, 6, 7, 0, 0},
    {1, 2, 0, 0, 0, 0, 0, 0}, {1, 2, 7, 0, 0, 0, 0, 0},
    {1, 2, 6, 0, 0, 0, 0, 0}, {1, 2, 6, 7, 0, 0, 0, 0},
    {1, 2, 5, 0, 0, 0, 0, 0}, {1, 2, 5, 7, 0, 0, 0, 0},
    {1, 2, 5, 6, 0, 0, 0, 0}, {1, 2, 5, 6, 7, 0, 0, 0},
    {1, 2, 4, 0, 0, 0, 0, 0}, {1, 2, 4, 7, 0, 0, 0, 0},
    {1, 2, 4, 6, 0, 0, 0, 0}, {1, 2, 4, 6, 7, 0, 0, 0},
    {1, 2, 4, 5, 0, 0, 0, 0}, {1, 2, 4, 5, 7, 0, 0, 0},
    {1, 2, 4, 5, 6, 0, 0, 0}, {1, 2, 4, 5, 6, 7, 0, 0},
    {1, 2, 3, 0, 0, 0, 0, 0}, {1, 2, 3, 7, 0, 0, 0, 0},
    {1, 2, 3, 6, 0, 0, 0, 0}, {1, 2, 3, 6, 7, 0, 0, 0},
    {1, 2, 3, 5, 0, 0, 0, 0}, {1, 2, 3, 5, 7, 0, 0, 0},
    {1, 2, 3, 5, 6, 0, 0, 0}, {1, 2, 3, 5, 6, 7, 0, 0},
    {1, 2, 3, 4, 0, 0, 0, 0}, {1, 2, 3, 4, 7, 0, 0, 0},
    {1, 2, 3, 4, 6, 0, 0, 0}, {1, 2, 3, 4, 6, 7, 0, 0},
    {1, 2, 3, 4, 5, 0, 0, 0}, {1, 2, 3, 4, 5, 7, 0, 0},
    {1, 2, 3, 4, 5, 6, 0, 0}, {1, 2, 3, 4, 5, 6, 7, 0},
    {0, 0, 0, 0, 0, 0, 0, 0}, {0, 7, 0, 0, 0, 0, 0, 0},
    {0, 6, 0, 0, 0, 0, 0, 0}, {0, 6, 7, 0, 0, 0, 0, 0},
    {0, 5, 0, 0, 0, 0, 0, 0}, {0, 5, 7, 0, 0, 0, 0, 0},
    {0, 5, 6, 0, 0, 0, 0, 0}, {0, 5, 6, 7, 0, 0, 0, 0},
    {0, 4, 0, 0, 0, 0, 0, 0}, {0, 4, 7, 0, 0, 0, 0, 0},
    {0, 4, 6, 0, 0, 0, 0, 0}, {0, 4, 6, 7, 0, 0, 0, 0},
    {0, 4, 5, 0, 0, 0, 0, 0}, {0, 4, 5, 7, 0, 0, 0, 0},
    {0, 4, 5, 6, 0, 0, 0, 0}, {0, 4, 5, 6, 7, 0, 0, 0},
    {0, 3, 0, 0, 0, 0, 0, 0}, {0, 3, 7, 0, 0, 0, 0, 0},
    {0, 3, 6, 0, 0, 0, 0, 0}, {0, 3, 6, 7, 0, 0, 0, 0},
    {0, 3, 5, 0, 0, 0, 0, 0}, {0, 3, 5, 7, 0, 0, 0, 0},
    {0, 3, 5, 6, 0, 0, 0, 0}, {0, 3, 5, 6, 7, 0, 0, 0},
    {0, 3, 4, 0, 0, 0, 0, 0}, {0, 3, 4, 7, 0, 0, 0, 0},
    {0, 3, 4, 6, 0, 0, 0, 0}, {0, 3, 4, 6, 7, 0, 0, 0},
    {0, 3, 4, 5, 0, 0, 0, 0}, {0, 3, 4, 5, 7, 0, 0, 0},
    {0, 3, 4, 5, 6, 0, 0, 0}, {0, 3, 4, 5, 6, 7, 0, 0},
    {0, 2, 0, 0, 0, 0, 0, 0}, {0, 2, 7, 0, 0, 0, 0, 0},
    {0, 2, 6, 0, 0, 0, 0, 0}, {0, 2, 6, 7, 0, 0, 0, 0},
    {0, 2, 5, 0, 0, 0, 0, 0}, {0, 2, 5, 7, 0, 0, 0, 0},
    {0, 2, 5, 6, 0, 0, 0, 0}, {0, 2, 5, 6, 7, 0, 0, 0},
    {0, 2, 4, 0, 0, 0, 0, 0}, {0, 2, 4, 7, 0, 0, 0, 0},
    {0, 2, 4, 6, 0, 0, 0, 0}, {0, 2, 4, 6, 7, 0, 0, 0},
    {0, 2, 4, 5, 0, 0, 0, 0}, {0, 2, 4, 5, 7, 0, 0, 0},
    {0, 2, 4, 5, 6, 0, 0, 0}, {0, 2, 4, 5, 6, 7, 0, 0},
    {0, 2, 3, 0, 0, 0, 0, 0}, {0, 2, 3, 7, 0, 0, 0, 0},
    {0, 2, 3, 6, 0, 0, 0, 0}, {0, 2, 3, 6, 7, 0, 0, 0},
    {0, 2, 3, 5, 0, 0, 0, 0}, {0, 2, 3, 5, 7, 0, 0, 0},
    {0, 2, 3, 5, 6, 0, 0, 0}, {0, 2, 3, 5, 6, 7, 0, 0},
    {0, 2, 3, 4, 0, 0, 0, 0}, {0, 2, 3, 4, 7, 0, 0, 0},
    {0, 2, 3, 4, 6, 0, 0, 0}, {0, 2, 3, 4, 6, 7, 0, 0},
    {0, 2, 3, 4, 5, 0, 0, 0}, {0, 2, 3, 4, 5, 7, 0, 0},
    {0, 2, 3, 4, 5, 6, 0, 0}, {0, 2, 3, 4, 5, 6, 7, 0},
    {0, 1, 0, 0, 0, 0, 0, 0}, {0, 1, 7, 0, 0, 0, 0, 0},
    {0, 1, 6, 0, 0, 0, 0, 0}, {0, 1, 6, 7, 0, 0, 0, 0},
    {0, 1, 5, 0, 0, 0, 0, 0}, {0, 1, 5, 7, 0, 0, 0, 0},
    {0, 1, 5, 6, 0, 0, 0, 0}, {0, 1, 5, 6, 7, 0, 0, 0},
    {0, 1, 4, 0, 0, 0, 0, 0}, {0, 1, 4, 7, 0, 0, 0, 0},
    {0, 1, 4, 6, 0, 0, 0, 0}, {0, 1, 4, 6, 7, 0, 0, 0},
    {0, 1, 4, 5, 0, 0, 0, 0}, {0, 1, 4, 5, 7, 0, 0, 0},
    {0, 1, 4, 5, 6, 0, 0, 0}, {0, 1, 4, 5, 6, 7, 0, 0},
    {0, 1, 3, 0, 0, 0, 0, 0}, {0, 1, 3, 7, 0, 0, 0, 0},
    {0, 1, 3, 6, 0, 0, 0, 0}, {0, 1, 3, 6, 7, 0, 0, 0},
    {0, 1, 3, 5, 0, 0, 0, 0}, {0, 1, 3, 5, 7, 0, 0, 0},
    {0, 1, 3, 5, 6, 0, 0, 0}, {0, 1, 3, 5, 6, 7, 0, 0},
    {0, 1, 3, 4, 0, 0, 0, 0}, {0, 1, 3, 4, 7, 0, 0, 0},
    {0, 1, 3, 4, 6, 0, 0, 0}, {0, 1, 3, 4, 6, 7, 0, 0},
    {0, 1, 3, 4, 5, 0, 0, 0}, {0, 1, 3, 4, 5, 7, 0, 0},
    {0, 1, 3, 4, 5, 6, 0, 0}, {0, 1, 3, 4, 5, 6, 7, 0},
    {0, 1, 2, 0, 0, 0, 0, 0}, {0, 1, 2, 7, 0, 0, 0, 0},
    {0, 1, 2, 6, 0, 0, 0, 0}, {0, 1, 2, 6, 7, 0, 0, 0},
    {0, 1, 2, 5, 0, 0, 0, 0}, {0, 1, 2, 5, 7, 0, 0, 0},
    {0, 1, 2, 5, 6, 0, 0, 0}, {0, 1, 2, 5, 6, 7, 0, 0},
    {0, 1, 2, 4, 0, 0, 0, 0}, {0, 1, 2, 4, 7, 0, 0, 0},
    {0, 1, 2, 4, 6, 0, 0, 0}, {0, 1, 2, 4, 6, 7, 0, 0},
    {0, 1, 2, 4, 5, 0, 0, 0}, {0, 1, 2, 4, 5, 7, 0, 0},
    {0, 1, 2, 4, 5, 6, 0, 0}, {0, 1, 2, 4, 5, 6, 7, 0},
    {0, 1, 2, 3, 0, 0, 0, 0}, {0, 1, 2, 3, 7, 0, 0, 0},
    {0, 1, 2, 3, 6, 0, 0, 0}, {0, 1, 2, 3, 6, 7, 0, 0},
    {0, 1, 2, 3, 5, 0, 0, 0}, {0, 1, 2, 3, 5, 7, 0, 0},
    {0, 1, 2, 3, 5, 6, 0, 0}, {0, 1, 2, 3, 5, 6, 7, 0},
    {0, 1, 2, 3, 4, 0, 0, 0}, {0, 1, 2, 3, 4, 7, 0, 0},
    {0, 1, 2, 3, 4, 6, 0, 0}, {0, 1, 2, 3, 4, 6, 7, 0},
    {0, 1, 2, 3, 4, 5, 0, 0}, {0, 1, 2, 3, 4, 5, 7, 0},
    {0, 1, 2, 3, 4, 5, 6, 0}, {0, 1, 2, 3, 4, 5, 6, 7}
};

// This routine parses a bit mask with location bits set
// and returns the number of locations found and
// a vector ("locs") with the indices of the set locations
// The maximum location index for the regular MaskParse is 255
int MaskParse(const char *mask, int len, unsigned char *locs)
{
    int total_weight = 0;
    for (int i = 0; i < len; i++)
    {
        const unsigned char val = (unsigned char)*mask++;
        if (val)
        {
            const unsigned char *ptr = BITLOCS[val];
            int weight = WEIGHT[val];
            unsigned char base = (unsigned char)(i << 3);
            for (int j = 0; j < weight; j++)
                *locs++ = base + *ptr++;
            total_weight += weight;
        }
    }
    return total_weight;
}  // end MaskParse()

// This can parse longer masks
UInt32 MaskParseLong(const char* mask, UInt32 len,
                         UInt32* locs, UInt32 locs_len)
{
    UInt32 total_weight = 0;
    for (UInt32 i = 0; i < len; i++)
    {
        const unsigned char val = (unsigned char)*mask++;
        if (val)
        {
            const unsigned char *ptr = BITLOCS[val];
            int weight = WEIGHT[val];
            UInt32 base = i << 3;
            if ((total_weight + weight) > locs_len)
                weight = locs_len - total_weight;
            for (int j = 0; j < weight; j++)
                *locs++ = base + *ptr++;
            total_weight += weight;
        }
    }
    return total_weight;
}  // end MaskParseLong()

UInt32 MaskFirstSet(const char* mask, UInt32 mask_len)
{
    UInt32 mask_index = 0;
    while (mask_index < mask_len)
    {
        if (*mask)
            return (( mask_index << 3) + BITLOCS[(unsigned char)*mask][0]);
        mask_index++;
        mask++;
    }
    return mask_len << 3;
}  // end MaskFirstSet()

UInt32 MaskNextSet(UInt32 index, const char* mask,
                   UInt32 maskLen)
{
    UInt32 mask_index = index >> 3;
    mask += mask_index;
    int w = WEIGHT[(unsigned char)*mask];
    int remainder = index & 0x07;
    for (int i = 0; i < w; i++)
    {
        int loc = BITLOCS[(unsigned char)*mask][i];
        if (loc >= remainder) return (mask_index << 3) + loc;
    }
    while (++mask_index < maskLen)
    {
        mask++;
        if ((unsigned char)*mask)
            return (mask_index << 3) +
                   BITLOCS[(unsigned char)*mask][0];
    }
    return (maskLen << 3);
}  // end MaskNextSet()

UInt32 MaskLastSet(const char* mask, UInt32 maskLen)
{
    UInt32 len = maskLen;
    unsigned char* ptr = (unsigned char*)mask + len - 1;
    while (len--)
    {
        if (*ptr)
        {
           return ((len << 3) + BITLOCS[*ptr][WEIGHT[*ptr]-1]);
        }
        else
        {
            ptr--;
        }
    }
    return (maskLen << 3);
}  // end MaskLastSet()

void MaskSetBits(char* mask, UInt32 index, UInt32 count)
{
    if (0 == count) return;
    UInt32 mask_index = index >> 3;

    // To set appropriate bits in first byte
    unsigned int bit_index = index & 0x07;
    unsigned int bit_remainder = 8 - bit_index;

    if (count <= bit_remainder)
    {
        mask[mask_index] |= (0x00ff >> bit_index) &
                            (0x00ff << (bit_remainder - count));
    }
    else
    {
        mask[mask_index] |= 0x00ff >> bit_index;
        count -= bit_remainder;
        UInt32 nbytes = count >> 3;
        memset(&mask[++mask_index], 0xff, nbytes);
        count &= 0x07;
        if (count) mask[mask_index+nbytes] |= 0xff << (8-count);
    }
}  // end MaskSetBits()

void MaskUnsetBits(char* mask, UInt32 index, UInt32 count)
{
    if (0 == count) return;
    UInt32 mask_index = index >> 3;

    // To unset appropriate bits in first byte
    unsigned int bit_index = index & 0x07;
    unsigned int bit_remainder = 8 - bit_index;

    if (count <= bit_remainder)
    {
        mask[mask_index] &= (0x00ff << bit_remainder) |
                            (0x00ff >> (bit_index + count));
    }
    else
    {
        mask[mask_index] &= 0x00ff << bit_remainder;
        count -= bit_remainder;
        UInt32 nbytes = count >> 3;
        memset(&mask[++mask_index], 0, nbytes);
        count &= 0x07;
        if (count) mask[mask_index+nbytes] &= 0xff >> count;
    }
}  // end MaskUnsetBits()

// Note masks are expected to be 8-bit aligned
// mask1 = mask1 + mask2 (mask1 | mask2)
void MaskAdd(char* mask1, const char* mask2, UInt32 maskLen)
{
    for (unsigned int i = 0; i < maskLen; i++)
        mask1[i] |= mask2[i];
}  // end MaskAdd()

// mask1 = mask1 - mask2 (mask1 & ~mask2)
void MaskSubtract(char* mask1, const char* mask2, UInt32 maskLen)
{
    for (unsigned int i = 0; i < maskLen; i++)
        mask1[i] &= (~mask2[i]);
}  // end MaskXCopy()

/****************************************************************
 * MdpBitMask implementation
 */

MdpBitMask::MdpBitMask()
    : num_bits(0), first_set(0), mask_len(0), mask(NULL)
{
}

MdpBitMask::~MdpBitMask()
{
    Destroy();
}

bool MdpBitMask::Init(UInt32 numBits)
{
    ASSERT(!mask);
    mask_len = (numBits + 7) >> 3;
    first_set = numBits;
    num_bits = numBits;
    // Allocate memory for mask
    mask = new unsigned char[mask_len];
    if (mask)
    {
        Clear();
        return true;
    }
    else
    {
        return false;
    }

}  // end MdpBitMask::Init()

void MdpBitMask::Destroy()
{
    if (mask) delete []mask;
    mask = NULL;
    mask_len = first_set = num_bits = 0;
}

void MdpBitMask::Set(UInt32 index)
{
    ASSERT(index < num_bits);
    mask[(index >> 3)] |= (0x80 >> (index & 0x07));
    if (index < first_set) first_set = index;
}  // end MdpBitMask::Set()


void MdpBitMask::Unset(UInt32 index)
{
    ASSERT(index < num_bits);
    mask[(index >> 3)] &= ~(0x80 >> (index & 0x07));
    if (index == first_set) first_set = NextSet(index);
}  // end MdpBitMask::Unset()


UInt32 MdpBitMask::NextSet(UInt32 index)
{
    ASSERT(index <=  num_bits);
    if (index == num_bits) return num_bits;
    if (index < first_set) return first_set;
    UInt32 mask_index = index >> 3;
    if (mask[mask_index])
    {
        int w = WEIGHT[mask[mask_index]];
        int remainder = index & 0x07;
        for (int i = 0; i < w; i++)
        {
            int loc = BITLOCS[mask[mask_index]][i];
            if (loc >= remainder) return (mask_index << 3) + loc;
        }
    }
    while (++mask_index < mask_len)
    {
        if (mask[mask_index])
            return (mask_index << 3) +
                   BITLOCS[mask[mask_index]][0];
    }
    return num_bits;
}  // end MdpBitMask::NextSet()

UInt32 MdpBitMask::NextUnset(UInt32 index)
{
    ASSERT(index <= num_bits);
    UInt32 maskIndex = index >> 3;
    unsigned char bit = (unsigned char)(0x80 >> (index & 0x07));
    while (index < num_bits)
    {
        unsigned char val = mask[maskIndex];
        while (bit && (index < num_bits))
        {
            if (0 == (val & bit)) return index;
            index++;
            bit >>= 0x01;
        }
        bit = 0x80;
        maskIndex++;
    }
    return index;
}  // end MdpBitMask::NextUnset()


void MdpBitMask::SetBits(UInt32 index, UInt32 count)
{
    if (0 == count) return;
    ASSERT((index+count) <= num_bits);
    UInt32 mask_index = index >> 3;
    // To set appropriate bits in first byte
    unsigned int bit_index = index & 0x07;
    unsigned int bit_remainder = 8 - bit_index;
    if (count <= bit_remainder)
    {
        mask[mask_index] |= (0x00ff >> bit_index) &
                            (0x00ff << (bit_remainder - count));
    }
    else
    {
        mask[mask_index] |= 0x00ff >> bit_index;
        count -= bit_remainder;
        UInt32 nbytes = count >> 3;
        memset(&mask[++mask_index], 0xff, nbytes);
        count &= 0x07;
        if (count)
            mask[mask_index+nbytes] |= 0xff << (8-count);
    }
    if (index < first_set) first_set = index;
}  // end MdpBitMask::SetBits()


void MdpBitMask::UnsetBits(UInt32 index, UInt32 count)
{
    if (0 == count) return;
    ASSERT((index+count) <= num_bits);
    UInt32 end = index + count;
    UInt32 mask_index = index >> 3;
    // To unset appropriate bits in first byte
    unsigned int bit_index = index & 0x07;
    unsigned int bit_remainder = 8 - bit_index;
    if (count <= bit_remainder)
    {
        mask[mask_index] &= (0x00ff << bit_remainder) |
                            (0x00ff >> (bit_index + count));
    }
    else
    {
        mask[mask_index] &= 0x00ff << bit_remainder;
        count -= bit_remainder;
        UInt32 nbytes = count >> 3;
        memset(&mask[++mask_index], 0, nbytes);
        count &= 0x07;
        if (count)
            mask[mask_index+nbytes] &= 0xff >> count;
    }
    if (first_set >= index) first_set = NextSet(end);
}  // end MdpBitMask::UnsetBits()

void MdpBitMask::Add(MdpBitMask *theMask)
{
    ASSERT(theMask->mask_len == mask_len);
    for (unsigned int i = 0; i < mask_len; i++)
        mask[i] |= theMask->mask[i];
    if (theMask->first_set < first_set)
        first_set = theMask->first_set;
}  // end MdpBitMask::Add()

void MdpBitMask::XCopy(MdpBitMask& theMask)
{
    ASSERT(mask_len == theMask.mask_len);
    for (unsigned int i = 0; i < mask_len; i++)
        mask[i] = theMask.mask[i] & ~mask[i];
    if (theMask.first_set < first_set)
        first_set = theMask.first_set;
    else
        first_set = NextSet(theMask.first_set);
}  // end MdpBitMask::XCopy()

void MdpBitMask::And(MdpBitMask& theMask)
{
    ASSERT(mask_len == theMask.mask_len);
    for (unsigned int i = 0; i < mask_len; i++)
        mask[i] &= theMask.mask[i];
    first_set = NextSet(first_set);
}  // end MdpBitMask::And()

void MdpBitMask::AddRawMask(const char* theMask, UInt32 theLen)
{
    ASSERT(theLen <= mask_len);
    for (unsigned int i = 0; i < theLen; i++) mask[i] |= theMask[i];
    UInt32 lowBit = ::MaskFirstSet(theMask, theLen);
    if ((lowBit < first_set) && (lowBit < (theLen << 3)))
        first_set = lowBit;
}  // end MdpBitMask::AddRawMask()

void MdpBitMask::AddRawOffsetMask(const char* theMask,
                                  UInt32 theLen,
                                  UInt32 theOffset)
{
    ASSERT(theOffset+theLen <= mask_len);
    char* ptr1 = (char*)mask + theOffset;
    const char* ptr2 =  theMask;
    for (unsigned int i = 0; i < theLen; i++) *ptr1++ |= *ptr2++;
    UInt32 lowBit = ::MaskFirstSet(theMask, theLen) + (theOffset << 3);
    if ((lowBit < first_set) && (lowBit < ((theLen+theOffset) << 3)))
        first_set = lowBit;
}  // end MdpBitMask::AddRawOffsetMask()

//#ifdef PROTO_DEBUG
//void MdpBitMask::Display()
//{
//    for (UInt32 i = 0; i < mask_len; i++)
//    {
//        unsigned char bit = 0x80;
//        for (int j = 0; j < 8; j++)
//        {
//           if ((num_bits == ((i << 3) + j))) break;
//           if (mask[i] & bit)
//               printf("1");
//            else
//               printf("0");
//            bit >>= 1;
//        }
//    }
//}  // end MdpBitMask::Display()
//
//
//void MdpSlidingMask::Display()
//{
//    printf("offset:0x%08x mask:", offset);
//    bit_mask.Display();
//}  // end MdpSlidingMask::Display()
//#endif // PROTO_DEBUG


MdpSlidingMask::MdpSlidingMask()
    : offset(0)
{

}

// Test to see if the mask can be set for the corresponding index
// without allocating memory
bool MdpSlidingMask::CanFreeSet(UInt32 index)
{
    if (bit_mask.IsSet())
    {
        UInt32 diff = index - offset;
        // if (index < offset)
        if ((diff > MDP_SIGNED_BIT_INTEGER)
            || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < offset)))
        {
            if (((bit_mask.num_bits - 
                  MaskLastSet((char *)bit_mask.mask, bit_mask.mask_len)
                  + 7) >> 3)
                < ((offset - index + 7) >> 3))
                return false;
            else
                return true;
        }
        else
        {
            UInt32 end = offset + bit_mask.num_bits;
            diff = index - end;
            if ((diff > MDP_SIGNED_BIT_INTEGER)
                || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < end)))  // index < end
                return true;
            else
                return false;
        }
    }
    else
    {
        return true;  // mask is free to be set for any offset
    }
}  // end MdpSlidingMask::CanFreeSet()

bool MdpSlidingMask::InCurrentRange(UInt32 index)
{
    if (bit_mask.IsSet())
    {
        // if (index < offset)
        UInt32 diff = index - offset;
        if ((diff > MDP_SIGNED_BIT_INTEGER)
            || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < offset))) // index < offset
        {
            return false;
        }
        else
        {
            // if (index < end)
            UInt32 end = offset + bit_mask.num_bits;
            diff = index - end;
            if ((diff > MDP_SIGNED_BIT_INTEGER)
                || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < end)))  // index < end
                return true;
            else
                return false;
        }
    }
    else
    {
        return false;  // mask is free to be set for any offset
    }
}  // end MdpSlidingMask::InCurrentRange()

bool MdpSlidingMask::Set(UInt32 index)
{
    if (bit_mask.IsSet())
    {
        UInt32 diff = index - offset;
        if ((diff > MDP_SIGNED_BIT_INTEGER)
            || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < offset)))
        {
            UInt32 space_needed = (offset - index + 7) >> 3;
            UInt32 space_avail =
                (bit_mask.num_bits - 
                 MaskLastSet((char *)bit_mask.mask, bit_mask.mask_len)
                 + 7) >> 3;
            if (space_avail < space_needed)
            {
                UInt32 old_len = bit_mask.mask_len;
                UInt32 new_len = old_len * 2;
                while (new_len < (old_len + space_needed - space_avail))
                {
                    new_len *= 2;
                }
                if (new_len > 0x1fffffff) return false;
                unsigned char *new_mask = new unsigned char[new_len];
                if (!new_mask) return false;
                memset(new_mask, 0, space_needed);
                memcpy(&new_mask[space_needed], bit_mask.mask, old_len);
                memset(&new_mask[space_needed+old_len],
                       0,
                       new_len - (space_needed+old_len));
                delete []bit_mask.mask;
                bit_mask.mask = new_mask;
                bit_mask.mask_len = new_len;
                bit_mask.num_bits = new_len << 3;
            }
            else
            {
                // Reverse slide
                unsigned char *mask = bit_mask.mask;
                memmove(&mask[space_needed],
                        mask,
                        bit_mask.mask_len - space_needed);
                memset(mask, 0, space_needed);
            }
            bit_mask.first_set += space_needed << 3;
            offset = index & (~((UInt32)0x07));
        }
        else
        {
            UInt32 end = offset + bit_mask.num_bits;
            diff = index - end;
            if (!((diff > MDP_SIGNED_BIT_INTEGER)
                || ((MDP_SIGNED_BIT_INTEGER == diff) && (index < end))))
            {
                UInt32 space_needed = (index - end + 7) >> 3;
                UInt32 old_len = bit_mask.mask_len;
                UInt32 new_len = old_len * 2;
                while (new_len < (old_len + space_needed)) new_len *= 2;
                if (new_len > 0x1fffffff) return false;
                unsigned char *new_mask = new unsigned char[new_len];
                if (!new_mask) return false;
                memcpy(new_mask, bit_mask.mask, old_len);
                memset(&new_mask[old_len], 0, new_len - old_len);
                delete []bit_mask.mask;
                bit_mask.mask = new_mask;
                bit_mask.mask_len = new_len;
                bit_mask.num_bits = new_len << 3;
            }
        }
    }
    else
    {
        offset = index & (~((UInt32)0x07));
    }
    bit_mask.Set(index - offset);
    return true;
}  // end MdpSlidingMask::Set()


bool MdpSlidingMask::NextSet(UInt32 *index)
{
    ASSERT(index);
    if (InCurrentRange(*index))
    {
        UInt32 next_set = bit_mask.NextSet(*index - offset);
        if (next_set < bit_mask.num_bits)
        {
            *index = next_set + offset;
            return true;
        }
        else
        {
            return false;
        }
    }
    else
    {
        return false;
    }
}  // end MdpSlidingMask::NextSet()

// Slide down unset mask prefix and update offset
void MdpSlidingMask::Slide()
{
    if (bit_mask.IsSet())
    {
        UInt32 i = 0;
        UInt32 mask_len = bit_mask.mask_len;
        unsigned char *mask = bit_mask.mask;
        while ((i < mask_len) && (0 == mask[i])) i++;
        memmove(mask, &mask[i], mask_len - i);
        memset(&mask[mask_len-i], 0, i);
        offset += i << 3;
        if (bit_mask.first_set < bit_mask.num_bits)
            bit_mask.first_set -= i << 3;
    }
}  // end MdpSlidingMask::Compress()
