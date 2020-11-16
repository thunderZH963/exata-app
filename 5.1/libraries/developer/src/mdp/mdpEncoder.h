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

#ifndef _MDP_ENCODER
#define _MDP_ENCODER

#include <stdlib.h>
//#include "protokit.h"  // for bool type, NULL definition, DEBUG stuff

class MdpEncoder
{
    // Members
    private:
        int             npar;       // No. of parity packets (N-k)
        int             vecSize;    // Size of biggest vector to encode
        unsigned char   *genPoly;   // Ptr to generator polynomial
        unsigned char   *pScratch;  // scratch space for encoding

    // Methods
    public:
        MdpEncoder();
        ~MdpEncoder();
        bool Init(int numParity, int vectorSize);
        void Destroy();
        bool IsReady(){return (bool)(genPoly != NULL);}
        void Encode(char *dataVector, char **parityVectorList);
        int NumParity() {return npar;}
        int VectorSize() {return vecSize;}

    private:
        bool CreateGeneratorPolynomial();
};


class MdpDecoder
{
    // Members
    private:
        int             npar;          // No. of parity packets (n-K)
        int             vector_size;   // Size of biggest vector to encode
        unsigned char   *Lambda;       // Erasure location polynomial ("2*npar" ints)
        unsigned char   **sVec;        // Syndrome vectors (pointers to "npar" vectors)
        unsigned char   **oVec;        // Omega vectors (pointers to "npar" vectors)
        unsigned char   *erasure_locs;  // Up to npar erasure locations

    // Methods
    public:
        MdpDecoder();
        ~MdpDecoder();
        bool Init(int numParity, int vectorSize);
        int Decode(char **vectorList, int ndata, const char *erasureMask);
        int NumParity() {return npar;}
        int VectorSize() {return vector_size;}
        void Destroy();
};



#endif // _MDP_ENCODER
