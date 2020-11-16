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


#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "mdpEncoder.h"
#include "mdpBitMask.h"  // for erasure mask parsing
#include "mdpGalois.h"  // for Galois math routines

MdpEncoder::MdpEncoder()
    : npar(0), vecSize(0),
      genPoly(NULL), pScratch(NULL)
{

}  // end MdpEncoder::MdpEncoder()

MdpEncoder::~MdpEncoder()
{
    if (genPoly) Destroy();
}

bool MdpEncoder::Init(int numParity, int vecSizeMax)
{
    // Debugging assertions
    ASSERT((numParity>=0)&&(numParity<129));
    ASSERT(vecSizeMax >= 0);
    if (genPoly) Destroy();
    npar = numParity;
    vecSize = vecSizeMax;
    // Create generator polynomial
    if (!CreateGeneratorPolynomial())
    {
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error creating generator polynomial!\n");
        }
        return false;
    }
    // Allocate scratch space for encoding
    // if (!(pScratch = (unsigned char *) calloc(vecSizeMax, sizeof(char))))
    pScratch = new unsigned char[vecSizeMax];
    // memset(pScratch, 0, vecSizeMax * sizeof(unsigned char));
    if (!pScratch)
    {
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error allocating memory for encoder scratch space.\n");
        }
        Destroy();
        return false;
    }
    return true;
}  // end MdpEncoder::Init()

// Free memory allocated for encoder state
// (Encoder must be re-inited before use)
void MdpEncoder::Destroy()
{
    if (pScratch)
    {
        delete []pScratch;
        pScratch = NULL;
    }
    if (genPoly)
    {
        free(genPoly);
        genPoly = NULL;
    }
}  // end MdpEncoder::Destroy()


bool MdpEncoder::CreateGeneratorPolynomial()
{
    int n, i, j;
    unsigned char *tp, *tp1, *tp2;
    int degree = 2*npar;
    if (genPoly) free(genPoly);

    genPoly = (unsigned char *) calloc(npar+1, sizeof(unsigned char));
    if (!genPoly)
    {
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error allocating memory for "
                   "generator polynomial.\n");
        }
        return false;
    }
    /* Allocate memory for temporary polynomial arrays */
    tp = (unsigned char *) calloc(2*degree, sizeof(unsigned char));
    if (!tp)
    {
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error allocating memory while "
                   "computing genpoly.\n");
        }
        return false;
    }
    tp1 = (unsigned char *) calloc(2*degree, sizeof(unsigned char));
    if (!tp1)
    {
        free(tp);
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error allocating memory while "
                   "computing genpoly.\n");
        }
        return false;
    }
    tp2 = (unsigned char *) calloc(2*degree, sizeof(unsigned char));
    if (!tp2)
    {
        free(tp1);
        free(tp);
        if (MDP_DEBUG)
        {
            printf("MdpEncoder: Error allocating memory while "
                   "computing genpoly.\n");
        }
        return false;
    }
    /* multiply (x + a^n) for n = 1 to npar */
    memset(tp1, 0, degree*sizeof(unsigned char));
    tp1[0] = 1;
    for (n = 1; n <= npar; n++)
    {
        memset(tp, 0, degree*sizeof(unsigned char));
        tp[0] = gexp(n);  /* set up x+a^n */
        tp[1] = 1;
        /* Polynomial multiplication */
        memset(genPoly, 0, (npar+1)*sizeof(unsigned char));
        for (i = 0; i < degree; i++)
        {
            memset(&tp2[degree], 0, degree*sizeof(unsigned char));

            /* Scale tp2 by p1[i] */
            for (j=0; j<degree; j++)
            {
                tp2[j]=gmult(tp1[j], tp[i]);
            }

            /* Mult(shift) tp2 right by i */
            for (j = (degree*2)-1; j >= i; j--)
            {
                tp2[j] = tp2[j-i];
            }
            memset(tp2, 0, i*sizeof(unsigned char));

            /* Add into partial product */
            for (j=0; j < (npar+1); j++)
            {
                genPoly[j] ^= tp2[j];
            }
        }
        memcpy(tp1, genPoly, (npar+1)*sizeof(unsigned char));
        memset(&tp1[npar+1], 0, (2*degree)-(npar+1));
    }
    free(tp2);
    free(tp1);
    free(tp);
    return true;  /* Everything OK */
}  // end MdpEncoder::CreateGeneratorPolynomial()



// Encode data vectors one at a time.  The user of this function
// must keep track of when parity is ready for transmission
// Parity data is written to list of parity vectors supplied by caller
void MdpEncoder::Encode(char *data, char **pVec)
{

//#if defined(NS2)
//    return;  // lobotomize FEC for faster simulations
//#endif

    if (!data)
    {
        return;
    }

    int i, j;
    unsigned char *userData, *LSFR1, *LSFR2, *pVec0;
    int npar_minus_one = npar - 1;
    unsigned char *gen_poly = &genPoly[npar_minus_one];
    ASSERT(pScratch);  // Make sure it's been init'd first
    // Assumes parity vectors are zero-filled at block start !!!
    // Copy pVec[0] for use in calculations
    memcpy(pScratch, pVec[0], vecSize);
    if (npar > 1)
    {
        for (i = 0; i < npar_minus_one; i++)
        {
            pVec0 = pScratch;
            userData = (unsigned char *) data;
            LSFR1 = (unsigned char *) pVec[i];
            LSFR2 = (unsigned char *) pVec[i+1];
            for (j = 0; j < vecSize; j++)
                *LSFR1++ = *LSFR2++ ^
                    gmult(*gen_poly, (*userData++ ^ *pVec0++));
            gen_poly--;
        }
    }
    pVec0 = pScratch;
    userData = (unsigned char *) data;
    LSFR1 = (unsigned char *) pVec[npar_minus_one];
    for (j = 0; j < vecSize; j++)
        *LSFR1++ = gmult(*gen_poly, (*userData++ ^ *pVec0++));
}  // end MdpEncoder::Encode()


/********************************************************************************
 *  MdpDecoder implementation routines
 */

MdpDecoder::MdpDecoder()
    : npar(0), vector_size(0),
      Lambda(NULL), sVec(NULL), oVec(NULL)
{

}

MdpDecoder::~MdpDecoder()
{
    if (Lambda) Destroy();
}

bool MdpDecoder::Init(int numParity, int vecSizeMax)
{
    // Debugging assertions
    ASSERT((numParity>=0)&&(numParity<=128));
    ASSERT(vecSizeMax >= 0);

    if (Lambda) Destroy();  // Check if already inited ...

    npar = numParity;
    vector_size = vecSizeMax;

    Lambda = (unsigned char *) calloc(2*npar, sizeof(char));
    if (!Lambda)
    {
        if (MDP_DEBUG)
        {
            printf("MdpDecoder: Error allocating memory for Lambda.\n");
        }
        return(false);
    }

    /* Allocate memory for sVec ptr and the syndrome vectors */
    sVec = (unsigned char  **) calloc(npar, sizeof(char *));
    if (!sVec)
    {
        if (MDP_DEBUG)
        {
            printf("MdpDecoder: Error allocating memory for sVec ptr.\n");
        }
        Destroy();
        return(false);
    }
    int i;
    for (i=0; i < npar; i++)
    {
        sVec[i] = (unsigned char *) calloc(vecSizeMax, sizeof(char));
        if (!sVec[i])
        {
            if (MDP_DEBUG)
            {
                printf("MdpDecoder: Error allocating memory for new sVec.\n");
            }
            Destroy();
            return(false);
        }
    }

    /* Allocate memory for the oVec ptr and the Omega vectors */
    oVec = (unsigned char **) calloc(npar, sizeof(char *));
    if (!oVec)
    {
        if (MDP_DEBUG)
        {
            printf("MdpDecoder: Error allocating memory for new oVec ptr.\n");
        }
        Destroy();
        return(false);
    }

    for (i=0; i < npar; i++)
    {
        oVec[i] = (unsigned char *) calloc(vecSizeMax, sizeof(char));
        if (!oVec[i])
        {
            if (MDP_DEBUG)
            {
                printf("MdpDecoder: Error allocating memory for new oVec.\n");
            }
            Destroy();
            return(false);
        }
    }

    // Alloc memory for the erasure_locs
    erasure_locs = (unsigned char *) calloc(npar, sizeof(char));
    if (!erasure_locs)
    {
        if (MDP_DEBUG)
        {
            printf("MdpDecoder: calloc(erasure_locs) error.\n");
        }
        Destroy();
        return false;
    }
    return(true);
}  // end MdpDecoder::Init()


void MdpDecoder::Destroy()
{
    if (Lambda)
        free(Lambda);
    else
        return;
    Lambda = NULL;

    if (oVec)
    {
        for (int i=0; i<npar; i++)
            if (oVec[i]) free(oVec[i]);
        free(oVec);
    }
    if (sVec)
    {
        for (int i = 0; i < npar; i++)
            if (sVec[i]) free(sVec[i]);
        free(sVec);
    }
    if (erasure_locs) free(erasure_locs);
}  // end MdpDecoder::Destroy()


// This will crash & burn if (NErasures > npar)
int MdpDecoder::Decode(char** dVec, int ndata, const char* ErasureMask)
{
    register unsigned char *S, *Omega, *data;
    int i, j, k, n;
    int X, denom, Lk;
    int degree = 2*npar;
    register int nvecs = npar + ndata;
    int nvecs_minus_one = nvecs - 1;
    int vecSize = vector_size;

    // Debugging assertions
    ASSERT(Lambda);

    // Convert "ErasureMask" bit mask to vector of erasure locations
    int NErasures = MaskParse(ErasureMask, ((nvecs+7) >> 3), erasure_locs);
    ASSERT(NErasures && (NErasures<=npar));

//#if defined(NS2)
//    return NErasures;  // lobotomize FEC for faster simulations
//#endif

     /* (A) Compute syndrome vectors */

    /* First zero out erasure vectors (MDP provides zero-filled vecs) */

    /* Then calculate syndrome (based on zero value erasures) */
    for (i = 0; i < npar; i++)
    {
        X = gexp(i+1);
        S = sVec[i];
        memset(S, 0, vecSize*sizeof(char));
        for (j = 0; j < nvecs; j++)
        {
            S = sVec[i];
            data = (unsigned char *) dVec[j];
            for (n = 0; n < vecSize; n++)
            {
                *S = *data++ ^ gmult(X, *S);
                S++;
            }
        }
    }

    /* (B) Init Lambda (the erasure locator polynomial) */
    memset(Lambda, 0, degree*sizeof(char));
    Lambda[0] = 1;
    for (i = 0; i < NErasures; i++)
    {
        X = gexp(nvecs_minus_one - erasure_locs[i]);
        for (j = (degree-1); j > 0; j--)
            Lambda[j] = Lambda[j] ^ gmult(X, Lambda[j-1]);
    }

    /* (C) Compute modified Omega using Lambda */
    for (i = 0; i < npar; i++)
    {
        k = i;
        memset(oVec[i], 0, vecSize*sizeof(char));
        int m = i + 1;
        for (j = 0; j < m; j++)
        {
            Omega = oVec[i];
            S = sVec[j];
            Lk = Lambda[k--];
            for (n = 0; n < vecSize; n++)
                *Omega++ ^= gmult(*S++, Lk);
        }
    }

    /* (D) Finally, fill in the Erasures */
    for (i = 0; i < NErasures; i++)
    {
        // Only repair data erasures
        if (erasure_locs[i] >= ndata) return NErasures;

        /* evaluate Lambda' (derivative) at alpha^(-i)
           ( all odd powers disappear) */
        k = nvecs_minus_one - erasure_locs[i];
        denom = 0;
        for (j = 1; j < degree; j += 2)
            denom ^= gmult(Lambda[j], gexp(((255-k)*(j-1)) % 255));
        /* Invert for use computing errror value below */
        denom = ginv(denom);

        /* Now evaluate Omega at alpha^(-i) (numerator) */
        unsigned char *erased_vector =
                (unsigned char *) dVec[erasure_locs[i]];
        for (j = 0; j < npar; j++)
        {
            data = erased_vector;
            Omega = oVec[j];
            X = gexp(((255-k)*j) % 255);
            for (n = 0; n < vecSize; n++)
                *data++ ^= gmult(*Omega++, X);
        }

        /* Scale numerator with denominator */
        data = erased_vector;
        for (n = 0; n < vecSize; n++)
        {
            *data = gmult(*data, denom);
            data++;
        }
    }
    return(NErasures);
}



