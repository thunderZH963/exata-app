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

#ifndef _MDP_BIT_MASK
#define _MDP_BIT_MASK

#include "mdpProtoDefs.h"  // for ASSERT()
#include <string.h>   // for memset()

// The "ParseMask" routines return the number of bits set in the
// mask and fill the "locs" array with the indices of the set bits

// This can only handle masks for up to 256-member vectors
int MaskParse(const char *mask, int len, unsigned char *locs);

// This can handle very large bit masks
UInt32 MaskParseLong(const char *mask, UInt32 len,
                         UInt32 *locs, UInt32 locs_len);

inline void MaskSet(char *mask, UInt32 index)
{
    mask[(index >> 3)] |= (0x80 >> (index & 0x07));
}

inline void MaskUnset(char *mask, UInt32 index)
{
    mask[(index >> 3)] &= ~(0x80 >> (index & 0x07));
}

void MaskSetBits(char *mask, UInt32 index, UInt32 count);
void MaskUnsetBits(char *mask, UInt32 index, UInt32 count);


UInt32 MaskFirstSet(const char* mask, UInt32 mask_len);
UInt32 MaskNextSet(UInt32 index, const char *mask,
                   UInt32 mask_len);
UInt32 MaskLastSet(const char *mask, UInt32 mask_len);


inline bool MaskTest(const char *mask, UInt32 index)
{
    return (0 != (mask[(index >> 3)] & (0x80 >> (index & 0x07))));
}

// Compute mask1 = mask1 + mask2 (mask1 | mask2)
void MaskAdd(char* mask1, const char* mask2, UInt32 maskLen);
// Compute mask1 = mask1 - mask2 (mask1 & ~mask2)
void MaskSubtract(char* mask1, const char* mask2, UInt32 maskLen);

// Set mask1 = mask2
inline void MaskCopy(char* mask1, const char* mask2, UInt32 maskLen)
{
    memcpy(mask1, mask2, maskLen);
}

// This class is a useful smarter bit mask (i.e it tracks where
// the lowest set bit location is (Note everything is set on reset)
class MdpBitMask
{
    friend class MdpBitMaskIterator;
    friend class MdpSlidingMask;     // dynamic BitMask variation

    // Members
    protected:
        UInt32          num_bits;
        UInt32          first_set;  // index of lowest set bit
        UInt32          mask_len;
        unsigned char*  mask;

    // Methods
    public:
        MdpBitMask();
        ~MdpBitMask();
        bool Init(UInt32 numBits);
        bool IsInited() {return (NULL != mask);}
        void Destroy();

        void Reset()  // set to all one's
        {
            if (!mask_len) return;
            memset(mask, 0xff, mask_len-1);
            mask[mask_len-1] = (unsigned char)
                               (0x00ff << ((8 - (num_bits & 0x07)) & 0x07));
            first_set = 0;
        }
        void Clear()  // set to all zero's
        {
            if (mask)
            {
                memset(mask, 0, mask_len);
            }
            first_set = num_bits;
        };
        UInt32 NumBits() {return num_bits;}
        const char* Mask() {return (char*)mask;}
        UInt32 MaskLen() {return mask_len;}
        UInt32 FirstSet() {return first_set;}
        UInt32 NextSet(UInt32 index);
        UInt32 NextUnset(UInt32 index);
        void Set(UInt32 index);
        void Unset(UInt32 index);
        void SetBits(UInt32 baseIndex, UInt32 count);
        void UnsetBits(UInt32 baseIndex, UInt32 count);
        bool Test(UInt32 index)
        {
            ASSERT(index < num_bits);
            return((0 != (mask[(index >> 3)] & (0x80 >> (index & 0x07)))));
        }
        bool IsSet() {return (first_set < num_bits);}
        bool IsClear() {return (first_set >= num_bits);}

        void Copy(MdpBitMask &theMask)
        {
            ASSERT(mask_len == theMask.mask_len);
            memcpy(mask, theMask.mask, mask_len);
            first_set = theMask.first_set;
        }
        void Add(MdpBitMask *theMask);
        void AddRawMask(const char *theMask, UInt32 theLen);
        void AddRawOffsetMask(const char *theMask, UInt32 theLen,
                              UInt32 theOffset);
        void Display();

        void XCopy(MdpBitMask &theMask);
        void And(MdpBitMask &theMask);
};

// This class could be re-implemented using a circular buffer
// strategy to optimize performance further (no memmove()
class MdpSlidingMask
{
    public:
    // Methods
        MdpSlidingMask();
        bool Init(UInt32 numBits)
        {
            offset = 0;
            // Make sure numBits is byte multiple
            return bit_mask.Init(((numBits+7) >> 3) << 3);
        }
        bool IsInited() {return bit_mask.IsInited();}
        void Clear()
        {
            offset = 0;
            bit_mask.Clear();
        }
        void Destroy()
        {
            bit_mask.Destroy();
            offset = 0;
        }
        void SetOffset(UInt32 theOffset)
        {
            offset = theOffset & (~((UInt32)0x07));
        }
        bool IsSet() {return bit_mask.IsSet();}
        bool InCurrentRange(UInt32 index);
        bool CanFreeSet(UInt32 index);
        UInt32 FirstSet() {return offset + bit_mask.FirstSet();}
        bool Set(UInt32 index);
        bool Test(UInt32 index)
        {
            return (InCurrentRange(index) ?
                                    bit_mask.Test(index - offset) : false);
        }
        void Unset(UInt32 index)
        {
            // Make sure it's in range
            if (InCurrentRange(index))
            {
                bit_mask.Unset(index - offset);
                Slide();
            }
        }
        bool FirstSet(UInt32 *index)
        {
            if (bit_mask.IsSet())
            {
                ASSERT(index);
                *index = offset + bit_mask.FirstSet();
                return true;
            }
            else
            {
                return false;
            }
        }
        bool NextSet(UInt32 *index);
        UInt32 NumBits() {return bit_mask.NumBits();}
        void Copy(MdpSlidingMask &theMask)
        {
            offset = theMask.offset;
            bit_mask.Copy(theMask.bit_mask);
        }

//#ifdef PROTO_DEBUG
        //void Display();
//#endif // PROTO_DEBUG

    private:
    // Members
        UInt32        offset;
        MdpBitMask    bit_mask;
    // Methods
        void Slide();
};

#endif // _MDP_BIT_MASK
