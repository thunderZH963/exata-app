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

/**
 * Certificate implementation.
 *
 * The CA is not sensitive to certificate format.
 * It signs the certificate's MD5/SHA1 checksum which is
 * the de facto standard operation defined by WTLS.
 *
 * We currently support two formats:
 * 1. WTLSCertificate (rsa-sha1) defined in WTLS standard.
 * 2. A basic compact certificate defined as three critical
 *    components <id, PKid, Tvalid(Tstart, Tend)>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

#include "api.h"
#include "crypto.h"
#include "certificate_wtls.h"

#define ECC_PUBKEY_ITEMS 3
#define ECC_BLOCKLENGTH(PLAINTEXTLENGTH,ECC_KEYLENGTH) ((PLAINTEXTLENGTH)+ECC_PUBKEY_ITEMS*ECC_KEYLENGTH)

#ifdef DO_ECC_CRYPTO
//-------------------------------------------------------------------------
// FUNCTION : ECCChooseRandomNumber
// PURPOSE  : Generate an ECC random number
// ARGUMENTS: n: if not 0, the upper bound; otherwise no upper bound
//            keyBitLength: bit length of public key
// RETURN   : the generated random number
//-------------------------------------------------------------------------
MPI EccChooseRandomNumber(MPI n, int keyBitLength)
{
   // ECC seeds should be purely random.  The variance in the value settings
   // should not change the ANODR protocol behavior.
    static unsigned short eccSeed[3] = {543, 586, 5664};

    MPI result = mpi_alloc_set_ui(0);
    byte *k = (byte *)xmalloc(b2B(keyBitLength)+3);

    while (1)
    {
        int i;

        // Choose the random nonce k
        for (i=0; i<(b2B(keyBitLength)+3)/4; i++)
        {
            ((Int32 *)k)[i] = pc_nrand(eccSeed);
        }
        mpi_from_bitstream(result, k, b2B(keyBitLength));

        // It must be in proper range
        if (mpi_cmp_ui(result, 5664) > 0 &&
           (n? (mpi_cmp(result, n) < 0) : 1))
        {
            xfree(k);
            return result;
        }
    }
}

//-------------------------------------------------------------------------
// FUNCTION : ECCPublicKeyEncryption
// PURPOSE  : ECC Public Key encrypter
// ARGUMENTS: ciphertext: storing the result for encrypter
//            pubkey: the encryption key
//            keyBitLength: bit length of public key
//            plaintext: the input plaintext to be encrypted
//            plaintextBitLength: bit length of plaintext
// RETURN   : NONE
//-------------------------------------------------------------------------
void EccPubKeyEncryption(
    byte *ciphertext,
    MPI *pubKey,
    int keyBitLength,
    byte *plaintext,
    int  plaintextBitLength)
{
    MPI plainMpi = mpi_alloc_set_ui(0);
    MPI cipherMpi[4];
    int i;

    // The random nonce k
    pubKey[10] = EccChooseRandomNumber(pubKey[6]/*pk.n*/, keyBitLength);

    // Prepare the plaintext placeholder
    mpi_from_bitstream(plainMpi, plaintext, b2B(plaintextBitLength));
    // Do the ECC encryption
    ecc_encrypt(PUBKEY_ALGO_ECC, cipherMpi, plainMpi, pubKey);
    // Deliver the ciphertext
    memset(ciphertext,
           0,
           b2B(ECC_BLOCKLENGTH(plaintextBitLength, keyBitLength)));
    int ciphertextLength = 0;
    for (i=0; i<4; i++)
    {
        ciphertextLength +=
            mpi_to_bitstream(ciphertext + i*b2B(keyBitLength),
                             b2B(i==3? plaintextBitLength:keyBitLength),
                             cipherMpi[i],
                             1);
    }
    if (ciphertextLength !=
       b2B(ECC_BLOCKLENGTH(plaintextBitLength, keyBitLength)))
    {
        fprintf(stderr, "Encryption anomaly in ciphertext's length.\n");
    }

    // free the temporary MPIs
    for (i=0; i<4; i++)
    {
        mpi_free(cipherMpi[i]);
    }
    mpi_free(plainMpi);
}

//-------------------------------------------------------------------------
// FUNCTION : ECCPublicKeyDecryption
// PURPOSE  : ECC Public Key decrypter
// ARGUMENTS: plaintext: storing the result for decrypter
//            plaintextBitLength: bit length of plaintext
//            skey: the decryption key
//            keyBitLength: bit length of private key
//            ciphertext: the input ciphertext to be decrypted
// RETURN   : NONE
//-------------------------------------------------------------------------
void
EccPubKeyDecryption(
    byte *plaintext,
    int  plaintextBitLength,
    MPI *skey,
    int keyBitLength,
    byte *ciphertext)
{
    MPI cipherMpi[4];
    MPI plainMpi;
    int i;

    // Acquire R.x R.y R.z
    for (i=0; i<ECC_PUBKEY_ITEMS; i++)
    {
        cipherMpi[i] = mpi_alloc_set_ui(0);
        mpi_from_bitstream(
            cipherMpi[i],
            ciphertext + i*b2B(keyBitLength),
            b2B(keyBitLength));
    }
    // Acquire C (the AES ciphertext used in ECC)
    cipherMpi[3] = mpi_alloc_set_ui(0);
    mpi_from_bitstream(
        cipherMpi[3],
        ciphertext + QUALNET_ECC_PUBLIC_KEYLENG(keyBitLength),
        b2B(plaintextBitLength));

    // Do the ECC decryption
    ecc_decrypt(PUBKEY_ALGO_ECC,
                &plainMpi,
                cipherMpi,
                skey);

    // Deliver the plaintext
    int plaintextLength =
        mpi_to_bitstream(plaintext,
                         b2B(plaintextBitLength),
                         plainMpi,
                         1);
    if (plaintextLength != b2B(plaintextBitLength))
    {
        fprintf(stderr, "Decryption anomaly in plaintext length.\n");
    }

    // free the temporary memory
    for (i=0; i<4; i++)
    {
        mpi_free(cipherMpi[i]);
    }
    mpi_free(plainMpi);
}

//-------------------------------------------------------------------------
// FUNCTION : SignCertificate
// PURPOSE  : Sign a unsigned plain certificate.
//            This function is useful only when real crypto applies.
// ARGUMENTS: plaincert: unsigned plain certificate
//            plaincert_leng: length of plaincert in bytes
//            signature: signature of plaincert
//            signature_leng: length of signature in bytes
//            sigalgo: signature algorithm
//            caSK: certificate authority (CA)'s private key
// RETURN   : NONE
//-------------------------------------------------------------------------
void SignCertificate(byte *plaincert,
                     length_t plaincert_leng,
                     byte *signature,
                     length_t *signature_leng,
                     SignatureAlgorithm sigalgo,
                     WTLS_PrivateKey *caSK)
{
    switch(sigalgo)
    {
        case SA_ECDSA_SHA:
        {
            byte md[b2B(160)];
            MPI hash = mpi_alloc_set_ui(0);
            MPI data[2];

            /* obtain the SHA1 checksum of the clear text */
            MD_HANDLE digest = md_open(DIGEST_ALGO_SHA1,1);//algo SHA1
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_SHA1, md, b2B(160));
            md_close(digest);// destroy and free hash state.

            mpi_from_bitstream(hash, md, b2B(160));

            ECPrivateKey *ecSK = &caSK->key.ecKey;
            ecc_sign(PUBKEY_ALGO_ECC, data, hash, ecSK->sk);
            mpi_to_bitstream(signature,
                             b2B(QUALNET_ECC_KEYLENGTH),
                             data[0],
                             1);
            mpi_to_bitstream(signature+b2B(QUALNET_ECC_KEYLENGTH),
                             b2B(QUALNET_ECC_KEYLENGTH),
                             data[1],
                             1);
            *signature_leng = 2*b2B(QUALNET_ECC_KEYLENGTH);
            mpi_free(data[0]);
            mpi_free(data[1]);
            mpi_free(hash);
            return;
        }
        case SA_ECDSA_MD5:
        {
            byte md[b2B(128)];
            MPI hash = mpi_alloc_set_ui(0);
            MPI data[2];

            /* obtain the MD5 checksum of the clear text */
            MD_HANDLE digest = md_open(DIGEST_ALGO_MD5,1);//algo MD5
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(128));
            md_close(digest);// destroy and free hash state.

            mpi_from_bitstream(hash, md, b2B(128));

            ECPrivateKey *ecSK = &caSK->key.ecKey;
            ecc_sign(PUBKEY_ALGO_ECC, data, hash, ecSK->sk);
            mpi_to_bitstream(signature,
                             b2B(QUALNET_ECC_KEYLENGTH),
                             data[0],
                             1);
            mpi_to_bitstream(signature+b2B(QUALNET_ECC_KEYLENGTH),
                             b2B(QUALNET_ECC_KEYLENGTH),
                             data[1],
                             1);
            *signature_leng = 2*b2B(QUALNET_ECC_KEYLENGTH);
            mpi_free(data[0]);
            mpi_free(data[1]);
            mpi_free(hash);
            return;
        }
#if 0
        case SA_RSA_MD5:
        {
            RSAPublicKey *rsaPK = &caPK->key.rsaPubKey;

            recovered = (byte *)xcalloc(b2B(128), sizeof(char));
            RSA_PK_crypt(recovered, &leng, signature,
                         signature_leng, rsaPK, 0);
            if (leng != b2B(128))
            {
                fprintf(stderr,
                        "Something wrong "
                        "in PK-verification implementation.\n");
                exit(1);
            }

            MPI md = mpi_alloc_set_ui(0);

            /* obtain the MD5 checksum of the clear text */
            MD_HANDLE digest = md_open(DIGEST_ALGO_MD5,1);//algo MD5
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(128));
            md_close(digest);// destroy and free hash state.

            /* verify the result */
            if (memcmp(recovered, md, b2B(128)) == 0)
            {
                free(recovered);
                printf("MD5 signature is signed ok.\n");
                return 1;
            }
            break;
        }
        case SA_RSA_SHA:
        {
            RSAPublicKey *rsaPK = &caPK->key.rsaPubKey;

            recovered = (byte *)xcalloc(b2B(160), sizeof(char));
            RSA_PK_crypt(recovered, &leng,
                         signature, signature_leng, rsaPK, 0);
            if (leng != b2B(160))
            {
                fprintf(stderr, "Something wrong in "
                        "PK-verification implementation.\n");
                exit(1);
            }

            MPI md = mpi_alloc_set_ui(0);

            /* obtain the SHA1 checksum of the clear text */
            MD_HANDLE digest = md_open(DIGEST_ALGO_SHA1,1);//algo SHA1
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(160));
            md_close(digest);// destroy and free hash state.

            /* verify the result */
            if (memcmp(recovered, md, b2B(160)) == 0)
            {
                free(recovered);
                printf("SHA1 signature is signed ok.\n");
                return 1;
            }
            break;
        }
#endif
        default:
            break;
    }
}

//-------------------------------------------------------------------------
// FUNCTION : VerifyCertificate
// PURPOSE  : Verify the validity of a certificate.
//            This function is useful only when real crypto applies.
// ARGUMENTS: plaincert: unsigned plain certificate
//            plaincert_leng: length of plaincert in bytes
//            signature: signature of plaincert
//            signature_leng: length of signature in bytes
//            sigalgo: signature algorithm
//            caPK: certificate authority (CA)'s public key
// RETURN   : 1: valid certificate,  0: invalid certificate
//-------------------------------------------------------------------------
int VerifyCertificate(byte *plaincert,
                      length_t plaincert_leng,
                      byte *signature,
                      length_t signature_leng,
                      SignatureAlgorithm sigalgo,
                      WTLS_PublicKey *caPK)
{
    byte *recovered;
    length_t leng;
    MD_HANDLE digest;
    byte md[20];

    switch(sigalgo)
    {
        case SA_ECDSA_SHA:
        {
            MPI hash = mpi_alloc_set_ui(0);
            MPI data[2];

            /* obtain the MD5 checksum of the clear text */
            digest = md_open(DIGEST_ALGO_SHA1,1);//algo SHA1
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_SHA1, md, b2B(160));
            md_close(digest);// destroy and free hash state.

            mpi_from_bitstream(hash, md, b2B(160));

            ECPublicKey *ecPK = &caPK->key.ecPublicKey;
            data[0] = mpi_alloc_set_ui(0);
            data[1] = mpi_alloc_set_ui(0);
            mpi_from_bitstream(data[0], signature, b2B(ecPK->nbits));
            mpi_from_bitstream(data[1],
                               signature+b2B(ecPK->nbits), b2B(ecPK->nbits));
            int ret = ecc_verify(PUBKEY_ALGO_ECC, hash, data, ecPK->pk);
            mpi_free(data[0]);
            mpi_free(data[1]);
            mpi_free(hash);
            return ret;
        }
        case SA_ECDSA_MD5:
        {
            MPI hash = mpi_alloc_set_ui(0);
            MPI data[2];

            /* obtain the MD5 checksum of the clear text */
            digest = md_open(DIGEST_ALGO_MD5,1);//algo MD5
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(128));
            md_close(digest);// destroy and free hash state.

            mpi_from_bitstream(hash, md, b2B(128));

            ECPublicKey *ecPK = &caPK->key.ecPublicKey;
            data[0] = mpi_alloc_set_ui(0);
            data[1] = mpi_alloc_set_ui(0);
            mpi_from_bitstream(data[0], signature, b2B(ecPK->nbits));
            mpi_from_bitstream(data[1],
                               signature+b2B(ecPK->nbits), b2B(ecPK->nbits));
            int ret = ecc_verify(PUBKEY_ALGO_ECC, hash, data, ecPK->pk);
            mpi_free(data[0]);
            mpi_free(data[1]);
            mpi_free(hash);
            return ret;
        }
#if 0
        case SA_RSA_SHA:
        {
            RSAPublicKey *rsaPK = &caPK->key.rsaPublicKey;

            recovered = (byte *)xcalloc(b2B(160), sizeof(char));
            RSA_PK_crypt(recovered, &leng,
                         signature, signature_leng, rsaPK, 0);
            if (leng != b2B(160))
            {
                fprintf(stderr, "Something wrong in "
                        "PK-verification implementation.\n");
                exit(1);
            }

            /* obtain the SHA1 checksum of the clear text */
            digest = md_open(DIGEST_ALGO_SHA1,1);//algo SHA1
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(160));
            md_close(digest);// destroy and free hash state.

            /* verify the result */
            if (memcmp(recovered, md, b2B(160)) == 0)
            {
                free(recovered);
                printf("SHA1 signature is signed ok.\n");
                return 1;
            }
            free(recovered);
            break;
        }
        case SA_RSA_MD5:
        {
            RSAPublicKey *rsaPK = &caPK->key.rsaPublicKey;

            recovered = (byte *)xcalloc(b2B(128), sizeof(char));
            RSA_PK_crypt(recovered, &leng,
                         signature, signature_leng, rsaPK, 0);
            if (leng != b2B(128))
            {
                fprintf(stderr, "Something wrong in "
                        "PK-verification implementation.\n");
                exit(1);
            }

            /* obtain the MD5 checksum of the clear text */
            digest = md_open(DIGEST_ALGO_MD5,1);//algo MD5
            md_write(digest, plaincert, plaincert_leng);//hashing input string
            md_digest(digest, DIGEST_ALGO_MD5, md, b2B(128));
            md_close(digest);// destroy and free hash state.

            /* verify the result */
            if (memcmp(recovered, md, b2B(128)) == 0)
            {
                free(recovered);
                printf("MD5 signature is signed ok.\n");
                return 1;
            }
            free(recovered);
            break;
        }
#endif
        default:
            break;
    }
    return 0;
}

///**
// * FUNCTION: ECPublicKey_encode/decode
// * PURPOSE: Assemble/disassemble MANET compact ECPublicKey
// *          This function is useful only when real crypto applies.
// *
// * In SIMPLE MANET ECC, we will reduce communication overhead by using
// * a single fixed-length elliptic curve from all mobile nodes.
// * This way, there is no need to exchange the curve parameters
// * like the prime p and the modulo n,  because they are well-known
// * default values in the MANET.  Thus the public key is just the random
// * EC point Q (with coordinates Q.x, Q.y, Q.z)
// *
// * @format:
// * keyBitLength(length_t)
// * Q.x(keyBitLength) Q.y(keyBitLength) Q.z(keyBitLength)
// *
// * ARGUMENTS: result: store encoded result for encoder
// *            pk: input public key
// *            input: store encoded input for decoder
// * RETURN: length of result for encoder
// *         NONE for decoder
// */
length_t ECPublicKey_encode(byte *result, ECPublicKey *pk)
{
    length_t pk_leng;
    byte *loc = result + sizeof(length_t);

    mpi_to_bitstream(loc,b2B(pk->nbits), pk->pk[7], 1);
    loc += b2B(pk->nbits);
    mpi_to_bitstream(loc,b2B(pk->nbits), pk->pk[8], 1);
    loc += b2B(pk->nbits);
    mpi_to_bitstream(loc,b2B(pk->nbits), pk->pk[9], 1);
    loc += b2B(pk->nbits);

    pk_leng = loc - result;
    memcpy(result, &pk_leng, sizeof(length_t));
    lengtht_endian(result);

    return pk_leng;
}
void
ECPublicKey_decode(byte **input, ECPublicKey *pk)
{
    byte *in = *input;
    length_t keyBitLength;

    keyBitLength = lengtht_decode(in);
    in += sizeof(length_t);
    if (pk != NULL)
    {
        pk->nbits = keyBitLength;
        mpi_from_bitstream(pk->pk[7], in, b2B(keyBitLength));
        in += b2B(keyBitLength);
        mpi_from_bitstream(pk->pk[8], in, b2B(keyBitLength));
        in += b2B(keyBitLength);
        mpi_from_bitstream(pk->pk[9], in, b2B(keyBitLength));
        in += b2B(keyBitLength);
    }

    *input = in;
}
#endif // DO_ECC_CRYPTO

//-------------------------------------------------------------------------
// FUNCTION : AssembleCompactCertificate
// PURPOSE  : create certificate from ID, ID's Public Key, and valid time
// ARGUMENTS: res: the place holding the result
//            id: the identifier
//            idLength: the length of identifier
//            pubKey: the ID's public key string (if it is there)
//            keyBitLength: length of the identifier's public key (in bits)
//            tstart: starting valid time
//            tend: ending valid time
// RETURN   : the length of the assembled certificate
//-------------------------------------------------------------------------
length_t AssembleCompactCertificate(byte *res,
                                  char *id,
                                  length_t idLength, // in bytes
#ifdef DO_ECC_CRYPTO
                                  MPI *pubKey,
#endif // DO_ECC_CRYPTO
                                  length_t keyBitLength, // in bits
                                  uint32 tstart,
                                  uint32 tend)
{
    byte *ptr = res;

    /* handle <id> */
    lengtht_encode(ptr, idLength);
    ptr += sizeof(length_t);
    memcpy(ptr, id, idLength);
    ptr += idLength;

    /* handle <pk_id> */
    lengtht_encode(ptr, keyBitLength);
    ptr += sizeof(length_t);
#ifdef DO_ECC_CRYPTO
    int i;
    for (i=0; i<ECC_PUBKEY_ITEMS; i++)
    {
        mpi_to_bitstream(ptr, b2B(keyBitLength), pubKey[i], 1);
        ptr += b2B(keyBitLength);
    }
#else
    memset(ptr, 0, QUALNET_ECC_PUBLIC_KEYLENG(keyBitLength));
    ptr += QUALNET_ECC_PUBLIC_KEYLENG(keyBitLength);
#endif // DO_ECC_CRYPTO

    /* handle <Tvalid> */
    uint32_encode(ptr, (uint32)tstart);
    ptr += sizeof(uint32);
    uint32_encode(ptr, (uint32)tend);
    ptr += sizeof(uint32);

    /* Now the entire certificate looks like
       id (exact copy) + ECC pubkey (in bitstream) + Tvalid (exact copy) */

    length_t ret = (length_t)(ptr - res);

    ERROR_Assert(ret < QUALNET_MAX_CERTIFICATE_LENGTH,
                 "Certificate length exceeds maximal length.\n");
    return ret;
}

//-------------------------------------------------------------------------
// FUNCTION : DeassembleCompactCertificate
// PURPOSE  : turn a certificate into ID, ID's Public Key, and valid time
// ARGUMENTS: cert: the input certificate
//            id: placeholder for identifier
//            idLength: placeholder for length of identifier
//            pubKey: placeholder for ID's public key (if needed)
//            keyBitLength: placeholder for length of the public key in bits
//            tstart: placeholder for starting valid time
//            tend: placeholder for ending valid time
// RETURN   : the length of the assembled certificate
// Assumption: This routine assumes that all placeholders are INITIALIZED.
//             The caller must pre-allocate the placeholders.
//-------------------------------------------------------------------------
void DeassembleCompactCertificate(byte *cert,
                                  char *id,  // placeholder
                                  length_t *idLength,// in bytes
#ifdef DO_ECC_CRYPTO
                                  MPI *pubKey, // placeholder, initialized
#endif // DO_ECC_CRYPTO
                                  length_t *keyBitLength, // in bits
                                  uint32 *tstart,    // placeholder
                                  uint32 *tend)      // placeholder
{
    /* handle <id> */
    *idLength = lengtht_decode(cert);
    cert += sizeof(length_t);
    memcpy(id, cert, *idLength);
    cert += *idLength;

    /* handle <pk_id> */
    *keyBitLength = lengtht_decode(cert);
    cert += sizeof(length_t);
#ifdef DO_ECC_CRYPTO
    int i;

    for (i=0; i<ECC_PUBKEY_ITEMS; i++)
    {
        mpi_from_bitstream(pubKey[i], cert, b2B(*keyBitLength));
        cert += b2B(*keyBitLength);
    }
#else
    cert += QUALNET_ECC_PUBLIC_KEYLENG(*keyBitLength);
#endif // DO_ECC_CRYPTO

    /* handle <Tvalid> */
    *tstart = uint32_decode(cert);
    cert += sizeof(uint32);
    *tend = uint32_decode(cert);
}

//-------------------------------------------------------------------------
// FUNCTION : CompactCertificateLength
// PURPOSE  : predict the length of a signed certificate
//            from a plain certificate
// ARGUMENTS: cert: the input plain certificate
// RETURN   : the length of the signed certificate
//-------------------------------------------------------------------------
length_t CompactCertificateLength(byte *cert)
{
    length_t idLength, keyBitLength;

    idLength = lengtht_decode(cert);
    cert += sizeof(length_t) + idLength;

    keyBitLength = lengtht_decode(cert);

    return
        (length_t)(sizeof(length_t) + idLength + // id
        sizeof(length_t) + QUALNET_ECC_PUBLIC_KEYLENG(keyBitLength) + // pubkey
        sizeof(long)+sizeof(long)); // tstart & tend
}

//-------------------------------------------------------------------------
// FUNCTION : PrintCertificateLength
// PURPOSE  : print the a plain certificate into a file
// ARGUMENTS: out: the output file
//            cert: the input plain certificate
// RETURN   : NONE
//-------------------------------------------------------------------------
void PrintCompactCertificate(FILE *out, byte *cert)
{
    byte buffer[MAX_STRING_LENGTH];
    int i;

    /* handle <id> */
    length_t idLength = lengtht_decode(cert);
    cert += sizeof(length_t);
    memset(buffer, 0, MAX_STRING_LENGTH);
    memcpy(buffer, cert, idLength);

    fprintf(out, "Certificate = {%s,\n\tpubkey=", buffer);
    cert += idLength;

    /* handle <pk_id> */
    length_t keyBitLength = lengtht_decode(cert);
    cert += sizeof(length_t);

    for (i=0; i<ECC_PUBKEY_ITEMS; i++)
    {
        bitstream_to_hexstr(buffer, cert, b2B(keyBitLength));
        fprintf(out, "%s;", buffer);
        cert += b2B(keyBitLength);
    }

    /* handle <Tvalid> */
    uint32 tstart = uint32_decode(cert);
    fprintf(out, "\n\tstart time=%X\n", (unsigned int)tstart);
    cert += sizeof(uint32);

    uint32 tend = uint32_decode(cert);
    fprintf(out, "\tend time=%X\n", (unsigned int)tend);
}

//-------------------------------------------------------------------------
// FUNCTION : RSAPublicKey_encode/decode
// PURPOSE  : encode/decode between an RSA public key and bit string
//            @format: length(length_t) rsa_public_key(length)
// ARGUMENTS: result: storing the result for encoder
//            input: storing input string for decoder
//            pk: the RSA public key
// RETURN   : the length of the result for encoder
//            NONE for decoder
//-------------------------------------------------------------------------
length_t RSAPublicKey_encode(byte *result, RSAPublicKey *pk)
{
    length_t pke_leng, pkm_leng;
    length_t pk_leng;
    byte *loc = result + sizeof(length_t);

    pke_leng =
        (length_t)hexstr_to_bitstream(loc+sizeof(length_t),
                                      b2B(pk->nbits),
                                      pk->e);
    pkm_leng =
        (length_t)hexstr_to_bitstream(loc+2*sizeof(length_t)+pke_leng,
                                      b2B(pk->nbits),
                                      pk->m);
    pk_leng = pke_leng + 2*sizeof(length_t) + pkm_leng;

    memcpy(loc+sizeof(length_t)+pke_leng, &pkm_leng, sizeof(length_t));
    lengtht_endian(loc+sizeof(length_t)+pke_leng);
    memcpy(loc, &pke_leng, sizeof(length_t));
    lengtht_endian(loc);

    memcpy(result, &pk_leng, sizeof(length_t));
    return pk_leng;
}
void RSAPublicKey_decode(byte **input, RSAPublicKey *pk)
{
    byte *in = *input;
    length_t leng;

    leng = lengtht_decode(in);
    in += sizeof(length_t);
    if (pk != NULL)
    {
        pk->e = (byte *)xcalloc(leng*2+1, 1);
        bitstream_to_hexstr(pk->e, in, leng);
    }
    in += leng;

    leng = lengtht_decode(in);
    in += sizeof(length_t);
    if (pk != NULL)
    {
        pk->m = (byte *)xcalloc(leng*2+1, 1);
        bitstream_to_hexstr(pk->m, in, leng);
    }
    in += leng;

    if (pk != NULL)
        pk->nbits = leng*8;

    *input = in;
}


//-------------------------------------------------------------------------
// FUNCTION : WTLSCertificate_encode
// PURPOSE  : Assemble parts into a compact WTLS certificate
//  @format: to_be_signed_certificate(leng prepended) signature(leng builtin)
// ARGUMENTS: result: storing the result
//            to_be_signed_cert: the plain certificate
//            signature: the signature
// RETURN   : the length of the result
//-------------------------------------------------------------------------
length_t WTLSCertificate_encode(byte *result,
                              byte *to_be_signed_cert,
                              byte *signature)
{
    register length_t i=0;
    length_t sz;

    memcpy(&sz, to_be_signed_cert, sizeof(length_t));
    memcpy(result, to_be_signed_cert+sizeof(length_t), sz);
    i = (length_t)(i + sz);

    if (signature != NULL)
    {
        length_t leng;

        leng = sizeof(length_t) + lengtht_decode(signature);
        memcpy(result+i, signature, leng);
        i =(length_t)(i + leng);
    }
    return i;
}
/* No need to have "WTLSCertificate_decode", invoking
   ToBeSignedCert_decode is enough.
 */
