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

#define DES_BLOCK 8
#define RSA_CIPHER_LENGTH 256
#define MIN_KEY_LENGTH 5

#define MAX_DIGEST_LENGTH 64
#define HMAC_MD5_96_DIGEST_LENGTH 12
#define HMAC_SHA1_96_DIGEST_LENGTH 12

#define DEBUG_HASH 0
#define DEBUG_ENCRYPTION 0
#ifdef OPENSSL_LIB
#include "qualnet_error.h"
#include "network_crypto.h"


// /**
// FUNCTION    :: CRYPTO_AES_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using AES family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_AES_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    AES_KEY key1, key2;
    unsigned char* initVector = NULL;
    unsigned char* initVector1 = NULL;

    if (((inPacketLength * 8) % AES_BLOCK_SIZE) != 0)
    {
        ERROR_ReportWarning("Input packet size must be multiple "
                            "of AES_BLOCK_SIZE");
        return NULL;
    }

    if (!strcmp(cipherName, "AES-CTR"))
    {
        unsigned char* ctr_key = NULL;
        unsigned char* nonce = NULL;
        unsigned char iv_trail[NONCE_SIZE] = {0x00, 0x00, 0x00, 0x01};
        ctr_key = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE + 1);
        memset(ctr_key, 0, AES_BLOCK_SIZE + 1);
        memcpy(ctr_key,key,AES_BLOCK_SIZE);

        // modify the IV by prepending it with a byte string of 00 00 00 01
        // appending it with the 4 nonce bytes coming in the key.

        nonce = (unsigned char*) MEM_malloc(NONCE_SIZE + 1);
        memset(nonce, 0, NONCE_SIZE + 1);
        memcpy(nonce, &key[keyLength - NONCE_SIZE], NONCE_SIZE);

        initVector1 = (unsigned char*)
                      MEM_malloc(AES_BLOCK_SIZE + NONCE_SIZE + 1);
        memset(initVector1, 0, AES_BLOCK_SIZE + NONCE_SIZE + 1);
        memcpy(initVector1, nonce, NONCE_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector1 + NONCE_SIZE,
                   initializationVector,
                   (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        memcpy(initVector1 + NONCE_SIZE + ivLength,
               iv_trail,
               NONCE_SIZE);

        memcpy(key, ctr_key, AES_BLOCK_SIZE);
        key[AES_BLOCK_SIZE] = '\0';
        keyLength = AES_BLOCK_SIZE;
        MEM_free(ctr_key);
        MEM_free(nonce);
    }
    if (AES_set_encrypt_key(key, 8 * keyLength, &key1) != 0)
    {
        // key size should be either 128 bit or 192 bit or 256 bit
        ERROR_Assert(FALSE, "Can not set AES Encryption key");
    }

    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int) inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    if (!strcmp(cipherName, "AES-CBC"))
    // Same as AES_CBC128
    {
        unsigned char * initVector =
            (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_cbc_encrypt(inPacket,
                        outPacket,
                        (unsigned int) inPacketLength,
                        &key1,
                        initVector,
                        AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB1"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_cfb1_encrypt(inPacket,
                         outPacket,
                         (unsigned int) inPacketLength,
                         &key1,
                         initVector,
                         &num,
                         AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB128"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_cfb128_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                           &key1,
                           initVector,
                           &num,
                           AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB8"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_cfb8_encrypt(inPacket,
                         outPacket,
                         (unsigned int) inPacketLength,
                         &key1,
                         initVector,
                         &num,
                         AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CTR"))
    {
        unsigned int num = 0;
        unsigned char blockCounter[AES_BLOCK_SIZE];
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initVector1, AES_BLOCK_SIZE );
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_ctr128_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                            &key1,
                            initVector,
                            blockCounter,
                            &num);
        MEM_free(initVector);
        MEM_free(initVector1);
    }
    else if (!strcmp(cipherName, "AES-ECB"))
    {
        AES_ecb_encrypt(inPacket, outPacket, &key1, AES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "AES-IGE"))
    {
        initVector = (unsigned char*) MEM_malloc(2 * AES_BLOCK_SIZE);
        memset(initVector, 0, 2 * AES_BLOCK_SIZE);
        if (ivLength <= (2 * AES_BLOCK_SIZE))
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(32Bytes)");
        }
        AES_ige_encrypt(inPacket,
                        outPacket,
                        (unsigned int) inPacketLength,
                        &key1,
                        initVector,
                        AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-BI-IGE"))
    {
        initVector = (unsigned char*) MEM_malloc(4 * AES_BLOCK_SIZE);
        memset(initVector, 0, 4 * AES_BLOCK_SIZE);
        if (ivLength <= (4 * AES_BLOCK_SIZE))
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(64Bytes)");
        }

        // Here key1 and key2 both are same. To have different key2,
        // we need to pass this as argument (only aplicable to AES_BI_IGE).
        if (AES_set_encrypt_key(key, 8 * keyLength, &key2) != 0)
        {
            ERROR_Assert(FALSE, "Can not set AES Encryption key");
        }

        AES_bi_ige_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                            &key1,
                            &key2,
                            initVector,
                            AES_ENCRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-OFB128"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector,(unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_ofb128_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                           &key1,
                           initVector,
                           &num);
        MEM_free(initVector);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}

// /**
// FUNCTION    :: CRYPTO_AES_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using AES family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_AES_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    AES_KEY key1, key2;
    unsigned char* initVector = NULL;
    unsigned char* initVector1 = NULL;

    if (((inPacketLength * 8) % AES_BLOCK_SIZE) != 0)
    {
        ERROR_ReportWarning("Input packet size must be multiple "
                            "of AES_BLOCK_SIZE");
        return NULL;
    }
    if (!strcmp(cipherName, "AES-CTR"))
    {
        unsigned char* ctr_key = NULL;
        unsigned char* nonce = NULL;
        unsigned char iv_trail[NONCE_SIZE] = {0x00, 0x00, 0x00, 0x01};
        ctr_key = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE + 1);
        memset(ctr_key, 0, AES_BLOCK_SIZE + 1);
        memcpy(ctr_key, key, AES_BLOCK_SIZE);

        /* modify the IV by prepending it with a byte string of 00 00 00 01
        * appending it with the 4 nonce bytes coming in the key*/
        nonce = (unsigned char*) MEM_malloc(NONCE_SIZE + 1);
        memset(nonce, 0, NONCE_SIZE + 1);
        memcpy(nonce, &key[keyLength - NONCE_SIZE], NONCE_SIZE);

        initVector1 =
            (unsigned char*) MEM_malloc(AES_BLOCK_SIZE + NONCE_SIZE + 1);
        memset(initVector1, 0, AES_BLOCK_SIZE + NONCE_SIZE + 1);
        memcpy(initVector1, nonce, NONCE_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector1 + NONCE_SIZE,
                   initializationVector,
                   (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        memcpy(initVector1 + NONCE_SIZE + ivLength,
               iv_trail,
               NONCE_SIZE);

        memcpy(key, ctr_key, AES_BLOCK_SIZE);
        key[AES_BLOCK_SIZE] = '\0';
        keyLength = AES_BLOCK_SIZE;
        MEM_free(ctr_key);
        MEM_free(nonce);
    }


    if (AES_set_decrypt_key(key, 8 * keyLength, &key1) != 0)
    {
        // key size should be either 128 bit or 192 bit or 256 bit
        ERROR_Assert(FALSE, "Can not set AES Encryption key");
    }

    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    if (!strcmp(cipherName, "AES-CBC"))
    // Same as AES_CBC128
    {
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_cbc_encrypt(inPacket,
                        outPacket,
                        (unsigned int)inPacketLength,
                        &key1,
                        initVector,
                        AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB1"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_set_encrypt_key(key, 8 * keyLength, &key1);
        AES_cfb1_encrypt(inPacket,
                         outPacket,
                         (unsigned int)inPacketLength,
                         &key1,
                         initVector,
                         &num,
                         AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB128"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_set_encrypt_key(key, 8 * keyLength, &key1);
        AES_cfb128_encrypt(inPacket,
                           outPacket,
                           (unsigned int)inPacketLength,
                            &key1,
                            initVector,
                            &num,
                            AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CFB8"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_set_encrypt_key(key, 8 * keyLength, &key1);
        AES_cfb8_encrypt(inPacket,
                         outPacket,
                         (unsigned int) inPacketLength,
                         &key1,
                         initVector,
                         &num,
                         AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-CTR"))
    {
        unsigned int num = 0;
        unsigned char blockCounter[AES_BLOCK_SIZE];
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initVector1, AES_BLOCK_SIZE);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_set_encrypt_key(key, 8 * keyLength, &key1);
        AES_ctr128_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                            &key1,
                            initVector,
                            blockCounter,
                            &num);
        MEM_free(initVector);
        MEM_free(initVector1);
    }
    else if (!strcmp(cipherName, "AES-ECB"))
    {
        AES_ecb_encrypt(inPacket, outPacket, &key1, AES_DECRYPT);
    }
    else if (!strcmp(cipherName, "AES-IGE"))
    {
        initVector = (unsigned char*) MEM_malloc(2 * AES_BLOCK_SIZE);
        memset(initVector, 0, 2 * AES_BLOCK_SIZE);
        if (ivLength <= (2 * AES_BLOCK_SIZE))
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(32Bytes)");
        }
        AES_ige_encrypt(inPacket,
                        outPacket,
                        (unsigned int) inPacketLength,
                        &key1,
                        initVector,
                        AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-BI-IGE"))
    {
        initVector = (unsigned char*) MEM_malloc(4 * AES_BLOCK_SIZE);
        memset(initVector, 0, 4 * AES_BLOCK_SIZE);
        if (ivLength <= (4 * AES_BLOCK_SIZE))
        {
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(64Bytes)");
        }

        // Here key1 and key2 both are same. To have different key2,
        // we need to pass this as argument (only aplicable to AES_BI_IGE).
        if (AES_set_decrypt_key(key, 8 * keyLength, &key2) != 0)
        {
            ERROR_Assert(FALSE, "Can not set AES Encryption key");
        }

        AES_bi_ige_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                           &key1,
                           &key2,
                           initVector,
                           AES_DECRYPT);
        MEM_free(initVector);
    }
    else if (!strcmp(cipherName, "AES-OFB128"))
    {
        int num = 0;
        initVector = (unsigned char*) MEM_malloc(AES_BLOCK_SIZE);
        memset(initVector, 0, AES_BLOCK_SIZE);
        if (ivLength <= AES_BLOCK_SIZE)
        {
            memcpy(initVector, initializationVector,(unsigned int)ivLength);
        }
        else
        {
            ERROR_Assert(FALSE, "IV size should be AES_BLOCK_SIZE(16Bytes)");
        }
        AES_set_encrypt_key(key, 8 * keyLength, &key1);
        AES_ofb128_encrypt(inPacket,
                           outPacket,
                           (unsigned int) inPacketLength,
                           &key1,
                           initVector,
                           &num);
        MEM_free(initVector);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_BF_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using BF family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_BF_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0,(unsigned int) inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    int n = 0;

    BF_KEY bf_key;

    if (!strcmp(cipherName, "BF-ECB"))
    {
        if ((inPacketLength % BF_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength; i += BF_BLOCK)
        {
            BF_set_key(&bf_key, keyLength, key);
            BF_ecb_encrypt(&(inPacket[i]),
                           &(outPacket[i]),
                           &bf_key,
                           BF_ENCRYPT);
        }
    }
    else if (!strcmp(cipherName, "BF-CBC"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_cbc_encrypt(inPacket,
                       outPacket,
                       inPacketLength,
                       &bf_key,
                       initializationVector,
                       BF_ENCRYPT);
    }
    else if (!strcmp(cipherName, "BF-CFB64"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_cfb64_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &bf_key,
                         initializationVector,
                         &n,
                         BF_ENCRYPT);
    }
    else if (!strcmp(cipherName, "BF-OFB64"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_ofb64_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &bf_key,
                         initializationVector,
                         &n);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}

// /**
// FUNCTION    :: CRYPTO_BF_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using BF family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_BF_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    int n = 0;
    BF_KEY bf_key;

    if (!strcmp(cipherName, "BF-ECB"))
    {
        if ((inPacketLength % BF_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength; i += BF_BLOCK)
        {
            BF_set_key(&bf_key, keyLength, key);
            BF_ecb_encrypt(&(inPacket[i]),
                           &(outPacket[i]),
                           &bf_key,
                           BF_DECRYPT);
        }
    }
    else if (!strcmp(cipherName, "BF-CBC"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_cbc_encrypt(inPacket,
                       outPacket,
                       inPacketLength,
                       &bf_key,
                       initializationVector,
                       BF_DECRYPT);
    }
    else if (!strcmp(cipherName, "BF-CFB64"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_cfb64_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &bf_key,
                         initializationVector,
                         &n,
                         BF_DECRYPT);
    }
    else if (!strcmp(cipherName, "BF-OFB64"))
    {
        BF_set_key(&bf_key, keyLength, key);
        BF_ofb64_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &bf_key,
                         initializationVector,
                         &n);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_CAST_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using CAST family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_CAST_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    CAST_KEY cast_key;

    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    CAST_set_key(&cast_key, keyLength, key);

    if (!strcmp(cipherName, "CAST-CBC"))
    {
        CAST_cbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &cast_key,
                         initializationVector,
                         CAST_ENCRYPT);
    }
    else if (!strcmp(cipherName, "CAST-CFB64"))
    {
        int num = 0;
        CAST_cfb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &cast_key,
                           initializationVector,
                           &num,
                           CAST_ENCRYPT);
    }
    else if (!strcmp(cipherName, "CAST-ECB"))
    {
        if ((inPacketLength % CAST_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of CAST_BLOCK");
            return NULL;
        }

        for (int i = 0; i < inPacketLength; i += CAST_BLOCK)
        {
            CAST_ecb_encrypt(&(inPacket[i]),
                             &(outPacket[i]),
                             &cast_key,
                             CAST_ENCRYPT);
        }
    }
    else if (!strcmp(cipherName, "CAST-OFB64"))
    {
        int num = 0;
        CAST_ofb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &cast_key,
                           initializationVector,
                           &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_CAST_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using CAST family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_CAST_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    CAST_KEY cast_key;

    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    CAST_set_key(&cast_key, keyLength, key);

    if (!strcmp(cipherName, "CAST-CBC"))
    {
        CAST_cbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &cast_key,
                         initializationVector,
                         CAST_DECRYPT);
    }
    else if (!strcmp(cipherName, "CAST-CFB64"))
    {
        int num = 0;
        CAST_cfb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &cast_key,
                           initializationVector,
                           &num,
                           CAST_DECRYPT);
    }
    else if (!strcmp(cipherName, "CAST-ECB"))
    {
        if ((inPacketLength % CAST_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of CAST_BLOCK");
            return NULL;
        }

        for (int i = 0; i < inPacketLength; i += CAST_BLOCK)
        {
            CAST_ecb_encrypt(&(inPacket[i]),
                             &(outPacket[i]),
                             &cast_key,
                             CAST_DECRYPT);
        }
    }
    else if (!strcmp(cipherName, "CAST-OFB64"))
    {
        int num = 0;
        CAST_ofb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &cast_key,
                           initializationVector,
                           &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_DES_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using DES family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_DES_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    unsigned char tdesKey1[8], tdesKey2[8], tdesKey3[8];
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock iv1, iv2;
    int err = 0;

    if (keyLength == 0)
    {
        ERROR_ReportWarning("encryption key is not specified or "
                            "keyLength is zero\n"
                            "continuing with NULL key");
    }
    if (((keyLength % DES_BLOCK) != 0) || ((keyLength / DES_BLOCK) > 3))
    {
        ERROR_ReportWarning("keyLength should be 8, 16 or 24 bytes");
        *outPacketLength = 0;
        return NULL;
    }
    if (ivLength > (2 * DES_BLOCK))
    {
        ERROR_ReportWarning("initialization vector length "
                            "should be max 16 bytes");
        *outPacketLength = 0;
        return NULL;
    }

    // to set key
    memset(tdesKey1, 0, sizeof(tdesKey1));
    memset(tdesKey2, 0, sizeof(tdesKey2));
    memset(tdesKey3, 0, sizeof(tdesKey3));

    if (keyLength > 0)
    {
        memcpy(tdesKey1, key, sizeof(tdesKey1));
        err = DES_set_key_checked(&tdesKey1, &ks1);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }
    if (keyLength > 8)
    {
        memcpy(tdesKey2, &(key[8]), sizeof(tdesKey2));
        err = DES_set_key_checked(&tdesKey2, &ks2);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }
    if (keyLength > 16)
    {
        memcpy(tdesKey3, &(key[16]), sizeof(tdesKey3));
        err = DES_set_key_checked(&tdesKey3, &ks3);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }

    // to set initialization vector
    memset(iv1, 0, sizeof(iv1));
    memset(iv2, 0, sizeof(iv2));
    if (ivLength > 0)
    {
        memcpy(iv1, &(initializationVector[0]), sizeof(iv1));
    }
    if (ivLength > 8)
    {
        memcpy(iv2, &(initializationVector[8]), sizeof(iv2));
    }

    // For out packet
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    if (!strcmp(cipherName, "DES-CBC"))
    {
        DES_cbc_encrypt(inPacket,
                        outPacket,
                        inPacketLength,
                        &ks1,
                        &iv1,
                        DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-CFB"))
    {
        DES_cfb_encrypt(inPacket,
                        outPacket,
                        DES_BLOCK * sizeof(char),
                        inPacketLength,
                        &ks1,
                        &iv1,
                        DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-CFB64"))
    {
        int num = 0;
        DES_cfb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &ks1,
                          &iv1,
                          &num,
                          DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-ECB"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb_encrypt(&in, &out, &ks1, DES_ENCRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-ECB2"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb2_encrypt(&in, &out, &ks1, &ks2, DES_ENCRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-ECB3"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb3_encrypt(&in, &out, &ks1, &ks2, &ks3, DES_ENCRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-EDE2-CBC"))
    {
        DES_ede2_cbc_encrypt(inPacket,
                             outPacket,
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &iv1,
                             DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE2-CFB64"))
    {
        int num = 0;
        DES_ede2_cfb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &iv1,
                               &num,
                               DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE2-OFB64"))
    {
        int num = 0;
        DES_ede2_ofb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &iv1,
                               &num);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CBC"))
    {
        DES_ede3_cbc_encrypt(inPacket,
                             outPacket,
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &ks3,
                             &iv1,
                             DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CBCM"))
    {
        DES_ede3_cbcm_encrypt(inPacket,
                              outPacket,
                              inPacketLength,
                              &ks1,
                              &ks2,
                              &ks3,
                              &iv1,
                              &iv2,
                              DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CFB"))
    {
        DES_ede3_cfb_encrypt(inPacket,
                             outPacket,
                             DES_BLOCK * sizeof(char),
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &ks3,
                             &iv1,
                             DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CFB64"))
    {
        int num = 0;
        DES_ede3_cfb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &ks3,
                               &iv1,
                               &num,
                               DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-OFB64"))
    {
        int num = 0;
        DES_ede3_ofb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &ks3,
                               &iv1,
                               &num);
    }
    else if (!strcmp(cipherName, "DES-NCBC"))
    {
        DES_ncbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-OFB"))
    {
        DES_ofb_encrypt(inPacket,
                        outPacket,
                        DES_BLOCK * sizeof(char),
                        inPacketLength,
                        &ks1,
                        &iv1);
    }
    else if (!strcmp(cipherName, "DES-OFB64"))
    {
        int num = 0;
        DES_ofb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &ks1,
                          &iv1,
                          &num);
    }
    else if (!strcmp(cipherName, "DES-PCBC"))
    {
        DES_pcbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         DES_ENCRYPT);
    }
    else if (!strcmp(cipherName, "DES-XCBC"))
    {
        DES_xcbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         &tdesKey2,
                         &tdesKey3,
                         DES_ENCRYPT);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);

        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_DES_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using DES family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_DES_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    unsigned char tdesKey1[8], tdesKey2[8], tdesKey3[8];
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock iv1, iv2;
    int err = 0;

    if (keyLength == 0)
    {
        ERROR_ReportWarning("decryption key is not specified or "
                                    "keyLength is zero\n"
                                    "continuing with NULL key");
    }
    if (((keyLength % DES_BLOCK) != 0) || ((keyLength / DES_BLOCK) > 3))
    {
        ERROR_ReportWarning("keyLength should be 8, 16 or 24 bytes");
        *outPacketLength = 0;
        return NULL;
    }
    if (ivLength > (2 * DES_BLOCK))
    {
        ERROR_ReportWarning("initialization vector length "
                                "should be max 16 bytes");
        *outPacketLength = 0;
        return NULL;
    }

    // to set key
    memset(tdesKey1, 0, sizeof(tdesKey1));
    memset(tdesKey2, 0, sizeof(tdesKey2));
    memset(tdesKey3, 0, sizeof(tdesKey3));

    if (keyLength > 0)
    {
        memcpy(tdesKey1, key, sizeof(tdesKey1));
        err = DES_set_key_checked(&tdesKey1, &ks1);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }
    if (keyLength > 8)
    {
        memcpy(tdesKey2, &(key[8]), sizeof(tdesKey2));
        err = DES_set_key_checked(&tdesKey2, &ks2);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }
    if (keyLength > 16)
    {
        memcpy(tdesKey3, &(key[16]), sizeof(tdesKey3));
        err = DES_set_key_checked(&tdesKey3, &ks3);
        if (err == -1)
        {
            ERROR_ReportWarning(
                "Every Byte of key schedule should have odd parity");
            return NULL;
        }
        else if (err == -2)
        {
            ERROR_ReportWarning("Key is weak");
            return NULL;
        }
    }

    // to set initialization vector
    memset(iv1, 0, sizeof(iv1));
    memset(iv2, 0, sizeof(iv2));
    if (ivLength > 0)
    {
        memcpy(iv1, &(initializationVector[0]), sizeof(iv1));
    }
    if (ivLength > 8)
    {
        memcpy(iv2, &(initializationVector[8]), sizeof(iv2));
    }

    // For out packet
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0,(unsigned int) inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;
    if (!strcmp(cipherName, "DES-CBC"))
    {
        DES_cbc_encrypt(inPacket,
                        outPacket,
                        inPacketLength,
                        &ks1,
                        &iv1,
                        DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-CFB"))
    {
        DES_cfb_encrypt(inPacket,
                        outPacket,
                        DES_BLOCK * sizeof(char),
                        inPacketLength,
                        &ks1,
                        &iv1,
                        DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-CFB64"))
    {
        int num = 0;
        DES_cfb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &ks1,
                          &iv1,
                          &num,
                          DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-ECB"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb_encrypt(&in, &out, &ks1, DES_DECRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-ECB2"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb2_encrypt(&in, &out, &ks1, &ks2, DES_DECRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-ECB3"))
    {
        const_DES_cblock in, out;
        if ((inPacketLength % DES_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength / DES_BLOCK; i++)
        {
            memcpy(in, &(inPacket[DES_BLOCK * i]), sizeof(const_DES_cblock));
            DES_ecb3_encrypt(&in, &out, &ks1, &ks2, &ks3, DES_DECRYPT);
            memcpy(&(outPacket[DES_BLOCK * i]), &out, sizeof(const_DES_cblock));
        }
    }
    else if (!strcmp(cipherName, "DES-EDE2-CBC"))
    {
        DES_ede2_cbc_encrypt(inPacket,
                             outPacket,
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &iv1,
                             DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE2-CFB64"))
    {
        int num = 0;
        DES_ede2_cfb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &iv1,
                               &num,
                               DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE2-OFB64"))
    {
        int num = 0;
        DES_ede2_ofb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &iv1,
                               &num);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CBC"))
    {
        DES_ede3_cbc_encrypt(inPacket,
                             outPacket,
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &ks3,
                             &iv1,
                             DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CBCM"))
    {
        DES_ede3_cbcm_encrypt(inPacket,
                              outPacket,
                              inPacketLength,
                              &ks1,
                              &ks2,
                              &ks3,
                              &iv1,
                              &iv2,
                              DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CFB"))
    {
        DES_ede3_cfb_encrypt(inPacket,
                             outPacket, DES_BLOCK * sizeof(char),
                             inPacketLength,
                             &ks1,
                             &ks2,
                             &ks3,
                             &iv1,
                             DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-CFB64"))
    {
        int num = 0;
        DES_ede3_cfb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &ks3,
                               &iv1,
                               &num,
                               DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-EDE3-OFB64"))
    {
        int num = 0;
        DES_ede3_ofb64_encrypt(inPacket,
                               outPacket,
                               inPacketLength,
                               &ks1,
                               &ks2,
                               &ks3,
                               &iv1,
                               &num);
    }
    else if (!strcmp(cipherName, "DES-NCBC"))
    {
        DES_ncbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-OFB"))
    {
        DES_ofb_encrypt(inPacket,
                        outPacket,
                        DES_BLOCK * sizeof(char),
                        inPacketLength,
                        &ks1,
                        &iv1);
    }
    else if (!strcmp(cipherName, "DES-OFB64"))
    {
        int num = 0;
        DES_ofb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &ks1,
                          &iv1,
                          &num);
    }
    else if (!strcmp(cipherName, "DES-PCBC"))
    {
        DES_pcbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         DES_DECRYPT);
    }
    else if (!strcmp(cipherName, "DES-XCBC"))
    {
        DES_xcbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &ks1,
                         &iv1,
                         &tdesKey2,
                         &tdesKey3,
                         DES_DECRYPT);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_IDEA_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using IDEA family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_IDEA_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength =(unsigned int) inPacketLength;

    IDEA_KEY_SCHEDULE eKey;

    unsigned char k[16];
    memset(k, 0, sizeof(k));

    memcpy(k, key, (unsigned int)keyLength);

    if (!strcmp(cipherName, "IDEA-ECB"))
    {
        if ((inPacketLength % IDEA_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength; i += IDEA_BLOCK)
        {
            idea_set_encrypt_key(k, &eKey);
            idea_ecb_encrypt(&(inPacket[i]), &(outPacket[i]), &eKey);
        }
    }
    else if (!strcmp(cipherName, "IDEA-CBC"))
    {
        idea_set_encrypt_key(k, &eKey);
        idea_cbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &eKey,
                         initializationVector,
                         IDEA_ENCRYPT);
    }
    else if (!strcmp(cipherName, "IDEA-CFB64"))
    {
        int num = 0;
        idea_set_encrypt_key(k, &eKey);
        idea_cfb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &eKey,
                           initializationVector,
                           &num,
                           IDEA_ENCRYPT);
    }
    else if (!strcmp(cipherName, "IDEA-OFB64"))
    {
        int num = 0;
        idea_set_encrypt_key(k, &eKey);
        idea_ofb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &eKey,
                           initializationVector,
                           &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_IDEA_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using IDEA family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_IDEA_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    IDEA_KEY_SCHEDULE eKey,dkey;

    unsigned char k[16];
    memset(k, 0, sizeof(k));

    memcpy(k, key,(unsigned int) keyLength);

    if (!strcmp(cipherName, "IDEA-ECB"))
    {
        if ((inPacketLength % IDEA_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        for (int i = 0; i < inPacketLength; i += IDEA_BLOCK)
        {
            idea_set_encrypt_key(k, &eKey);
            idea_set_decrypt_key(&eKey, &dkey);
            idea_ecb_encrypt(&(inPacket[i]), &(outPacket[i]), &dkey);
        }
    }
    else if (!strcmp(cipherName, "IDEA-CBC"))
    {
        idea_set_encrypt_key(k, &eKey);
        idea_set_decrypt_key(&eKey, &dkey);
        idea_cbc_encrypt(inPacket,
                         outPacket,
                         inPacketLength,
                         &dkey,
                         initializationVector,
                         IDEA_DECRYPT);
    }
    else if (!strcmp(cipherName, "IDEA-CFB64"))
    {
        int num = 0;
        idea_set_encrypt_key(k, &eKey);
        idea_cfb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &eKey,
                           initializationVector,
                           &num,
                           IDEA_DECRYPT);
    }
    else if (!strcmp(cipherName, "IDEA-OFB64"))
    {
        int num = 0;
        idea_set_encrypt_key(k, &eKey);
        idea_ofb64_encrypt(inPacket,
                           outPacket,
                           inPacketLength,
                           &eKey,
                           initializationVector,
                           &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_RC2_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using RC2 family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_RC2_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    RC2_KEY rc_key;

    if (!strcmp(cipherName, "RC2-ECB"))
    {
        if ((inPacketLength % RC2_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        RC2_set_key(&rc_key, keyLength, key, 0 );
        for (int i = 0; i < inPacketLength; i += RC2_BLOCK)
        {
            RC2_ecb_encrypt(&(inPacket[i]),
                            &(outPacket[i]),
                            &rc_key,
                            RC2_ENCRYPT);
        }
    }
    else if (!strcmp(cipherName, "RC2-CBC"))
    {
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_cbc_encrypt(inPacket,
                        outPacket,
                        inPacketLength,
                        &rc_key,
                        initializationVector,
                        RC2_ENCRYPT);
    }
    else if (!strcmp(cipherName, "RC2-CFB64"))
    {
        int num = 0;
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_cfb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &rc_key,
                          initializationVector,
                          &num,
                          RC2_ENCRYPT);
    }
    else if (!strcmp(cipherName, "RC2-OFB64"))
    {
        int num = 0;
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_ofb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &rc_key,
                          initializationVector,
                          &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_RC2_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using RC2 family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_RC2_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* key,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc((unsigned int)inPacketLength);
    memset(outPacket, 0, (unsigned int)inPacketLength);
    *outPacketLength = (unsigned int)inPacketLength;

    RC2_KEY rc_key;

    if (!strcmp(cipherName, "RC2-ECB"))
    {
        if ((inPacketLength % RC2_BLOCK) != 0)
        {
            MEM_free(outPacket);
            *outPacketLength = 0;
            ERROR_ReportWarning(
                        "Input packet size must be multiple of 8 bytes");
            return NULL;
        }
        RC2_set_key(&rc_key, keyLength, key, 0 );
        for (int i = 0; i < inPacketLength; i += RC2_BLOCK)
        {
            RC2_ecb_encrypt(&(inPacket[i]),
                            &(outPacket[i]),
                            &rc_key,
                            RC2_DECRYPT);
        }
    }
    else if (!strcmp(cipherName, "RC2-CBC"))
    {
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_cbc_encrypt(inPacket,
                        outPacket,
                        inPacketLength,
                        &rc_key,
                        initializationVector,
                        RC2_DECRYPT);
    }
    else if (!strcmp(cipherName, "RC2-CFB64"))
    {
        int num = 0;
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_cfb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &rc_key,
                          initializationVector,
                          &num,
                          RC2_DECRYPT);
    }
    else if (!strcmp(cipherName, "RC2-OFB64"))
    {
        int num = 0;
        RC2_set_key(&rc_key, keyLength, key, 0 );
        RC2_ofb64_encrypt(inPacket,
                          outPacket,
                          inPacketLength,
                          &rc_key,
                          initializationVector,
                          &num);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        MEM_free(outPacket);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_RSA_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet using RSA family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_RSA_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc(RSA_CIPHER_LENGTH);
    memset(outPacket, 0, RSA_CIPHER_LENGTH);

    unsigned char n[] =
        "\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
        "\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
        "\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
        "\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
        "\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
        "\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
        "\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
        "\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
        "\xCB";

    unsigned char e[] = "\x11";

    unsigned char d[] =
        "\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
        "\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
        "\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
        "\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
        "\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
        "\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
        "\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
        "\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
        "\xC1";

    unsigned char p[] =
        "\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
        "\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
        "\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
        "\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
        "\x99";

    unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
        "\x03";

    unsigned char dmp1[] =
        "\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
        "\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
        "\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
        "\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    unsigned char dmq1[] =
        "\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
        "\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
        "\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
        "\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";

    unsigned char iqmp[] =
        "\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
        "\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
        "\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
        "\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
        "\xF7";

    RSA* rsa_key;
    rsa_key = RSA_new();

    rsa_key->n = BN_bin2bn(n, sizeof(n)-1, rsa_key->n);
    rsa_key->e = BN_bin2bn(e, sizeof(e)-1, rsa_key->e);
    rsa_key->d = BN_bin2bn(d, sizeof(d)-1, rsa_key->d);
    rsa_key->p = BN_bin2bn(p, sizeof(p)-1, rsa_key->p);
    rsa_key->q = BN_bin2bn(q, sizeof(q)-1, rsa_key->q);
    rsa_key->dmp1 = BN_bin2bn(dmp1, sizeof(dmp1)-1, rsa_key->dmp1);
    rsa_key->dmq1 = BN_bin2bn(dmq1, sizeof(dmq1)-1, rsa_key->dmq1);
    rsa_key->iqmp = BN_bin2bn(iqmp, sizeof(iqmp)-1, rsa_key->iqmp);

    if (!strcmp(cipherName, "RSA-PKCS1"))
    {
        *outPacketLength = (unsigned int)RSA_public_encrypt(inPacketLength,
                                                            inPacket,
                                                            outPacket,
                                                            rsa_key,
                                                            RSA_PKCS1_PADDING);
    }
    else if (!strcmp(cipherName, "RSA-PKCS1-OAEP"))
    {
        *outPacketLength = (unsigned int)RSA_public_encrypt(inPacketLength,
                                                            inPacket,
                                                            outPacket,
                                                            rsa_key,
                                                            RSA_PKCS1_OAEP_PADDING);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Encryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_RSA_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet using RSA family of algos.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_RSA_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName)
{
    unsigned char* outPacket;
    outPacket = (unsigned char*) MEM_malloc(RSA_CIPHER_LENGTH);
    memset(outPacket, 0, RSA_CIPHER_LENGTH);

    unsigned char n[] =
        "\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
        "\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
        "\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
        "\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
        "\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
        "\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
        "\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
        "\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
        "\xCB";

    unsigned char e[] = "\x11";

    unsigned char d[] =
        "\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
        "\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
        "\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
        "\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
        "\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
        "\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
        "\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
        "\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
        "\xC1";

    unsigned char p[] =
        "\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
        "\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
        "\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
        "\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
        "\x99";

    unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
        "\x03";

    unsigned char dmp1[] =
        "\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
        "\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
        "\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
        "\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    unsigned char dmq1[] =
        "\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
        "\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
        "\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
        "\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";

    unsigned char iqmp[] =
        "\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
        "\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
        "\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
        "\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
        "\xF7";

    RSA* rsa_key;
    rsa_key = RSA_new();

    rsa_key->n = BN_bin2bn(n, sizeof(n)-1, rsa_key->n);
    rsa_key->e = BN_bin2bn(e, sizeof(e)-1, rsa_key->e);
    rsa_key->d = BN_bin2bn(d, sizeof(d)-1, rsa_key->d);
    rsa_key->p = BN_bin2bn(p, sizeof(p)-1, rsa_key->p);
    rsa_key->q = BN_bin2bn(q, sizeof(q)-1, rsa_key->q);
    rsa_key->dmp1 = BN_bin2bn(dmp1, sizeof(dmp1)-1, rsa_key->dmp1);
    rsa_key->dmq1 = BN_bin2bn(dmq1, sizeof(dmq1)-1, rsa_key->dmq1);
    rsa_key->iqmp = BN_bin2bn(iqmp, sizeof(iqmp)-1, rsa_key->iqmp);

    if (!strcmp(cipherName, "RSA-PKCS1"))
    {
        *outPacketLength = (unsigned int)RSA_private_decrypt(inPacketLength,
                                                             inPacket,
                                                             outPacket,
                                                             rsa_key,
                                                             RSA_PKCS1_PADDING);
    }
    else if (!strcmp(cipherName, "RSA-PKCS1-OAEP"))
    {
        *outPacketLength = (unsigned int)RSA_private_decrypt(inPacketLength,
                                                             inPacket,
                                                             outPacket,
                                                             rsa_key,
                                                             RSA_PKCS1_OAEP_PADDING);
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s Decryption is not supported", cipherName);
        ERROR_ReportWarning(err);
        *outPacketLength = 0;
        return NULL;
    }

    return outPacket;
}
// /**
// FUNCTION    :: CRYPTO_EncryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to encrypt the
//                packet.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : encrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for encryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : encrypted packet
// **/
unsigned char* CRYPTO_EncryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* encryptionKey,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* encryptPacket = NULL;

    if (strcmp(cipherName,"NULL") &&
       (encryptionKey != NULL) &&
       (keyLength < MIN_KEY_LENGTH))
    {
        ERROR_ReportError("Key should not be less than 40 bits.");
    }


    if (!(strncmp(cipherName, "NULL", 4)))
    {
        encryptPacket =
            (unsigned char*) MEM_malloc((unsigned int)(inPacketLength + 1));
        memset(encryptPacket, 0, (unsigned int)(inPacketLength + 1));
        memcpy(encryptPacket, inPacket, (unsigned int)inPacketLength);
        *outPacketLength = (unsigned int)inPacketLength;
    }
    else if (!(strncmp(cipherName, "DES", 3)))
    {
        unsigned char initVector[16];
        unsigned char key[24];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        if (encryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, encryptionKey, (unsigned int)keyLength);
        }
        encryptPacket = CRYPTO_DES_EncryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "IDEA", 4)))
    {
        unsigned char initVector[8];
        unsigned char key[16];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        if (encryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, encryptionKey, (unsigned int)keyLength);
        }
        encryptPacket = CRYPTO_IDEA_EncryptPacket(inPacket,
                                                  inPacketLength,
                                                  outPacketLength,
                                                  cipherName,
                                                  key,
                                                  keyLength,
                                                  initVector,
                                                  ivLength);
    }
    else if (!(strncmp(cipherName, "BF", 2)))
    {
        unsigned char initVector[8];
        unsigned char* key = NULL;

        memset(initVector, 0, sizeof(initVector));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        if (encryptionKey != NULL)
        {
            key = (unsigned char*)MEM_malloc((unsigned int)(keyLength + 1));
            memset(key, 0, (unsigned int)(keyLength + 1));
            memcpy(key, encryptionKey, (unsigned int)keyLength);
        }
        encryptPacket = CRYPTO_BF_EncryptPacket(inPacket,
                                                inPacketLength,
                                                outPacketLength,
                                                cipherName,
                                                key,
                                                keyLength,
                                                initVector,
                                                ivLength);
        MEM_free(key);
    }

    else if (!(strncmp(cipherName, "CAST", 4)))
    {
        unsigned char initVector[8];
        unsigned char key[16];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (encryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, encryptionKey,(unsigned int) keyLength);
        }
        encryptPacket = CRYPTO_CAST_EncryptPacket(inPacket,
                                                  inPacketLength,
                                                  outPacketLength,
                                                  cipherName,
                                                  key,
                                                  keyLength,
                                                  initVector,
                                                  ivLength);
    }
    else if (!(strncmp(cipherName, "AES", 3)))
    {
        unsigned char initVector[64];
        unsigned char key[32];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        if (encryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, encryptionKey,(unsigned int) keyLength);
        }
        encryptPacket = CRYPTO_AES_EncryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "RC2", 3)))
    {
        unsigned char initVector[8];
        unsigned char key[128];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (encryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, encryptionKey,(unsigned int) keyLength);
        }
        encryptPacket = CRYPTO_RC2_EncryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "RSA", 3)))
    {
        encryptPacket = CRYPTO_RSA_EncryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName);
    }
    else
    {
        *outPacketLength = 0;
    }

    if (DEBUG_ENCRYPTION)
    {
        unsigned int len = *outPacketLength;
        printf("INPUT: 0x");
        for (int i = 0; i < inPacketLength; i++)
        {
            printf("%02x", inPacket[i]);
        }
        printf("\n%s ENCRYPTION: 0x", cipherName);
        for (unsigned int i = 0; i < len; i++)
        {
            printf("%02x", encryptPacket[i]);
        }
        printf("\n");
    }

    return encryptPacket;
}

// /**
// FUNCTION    :: CRYPTO_DecryptPacket
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to decrypt the
//                packet.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + outPacketLength      : unsigned int* : decrypted pkt length
// + cipherName           : char* : Algo name
// + key                  : unsigned char* : Keys to be used for decryption
// + keyLength            : int : length of key
// + initializationVector : unsigned char* : pointer to the IV
// + ivLength             : int : length of the IV
// RETURN      :: unsigned char* : decrypted packet
// **/
unsigned char* CRYPTO_DecryptPacket(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned int* outPacketLength,
    char* cipherName,
    unsigned char* decryptionKey,
    int keyLength,
    unsigned char* initializationVector,
    int ivLength)
{
    unsigned char* decryptPacket = NULL;

    if (strcmp(cipherName,"NULL") &&
       (decryptionKey != NULL) &&
       (keyLength < MIN_KEY_LENGTH))
    {
        ERROR_ReportError("Key should not be less than 40 bits.");
    }


    if (!(strncmp(cipherName, "NULL", 4)))
    {
        decryptPacket =
            (unsigned char*) MEM_malloc((unsigned int)(inPacketLength + 1));
        memset(decryptPacket, 0, (unsigned int)(inPacketLength + 1));
        memcpy(decryptPacket, inPacket, (unsigned int)inPacketLength);
        *outPacketLength = (unsigned int)inPacketLength;
    }
    else if (!(strncmp(cipherName, "DES", 3)))
    {
        unsigned char initVector[16];
        unsigned char key[24];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (decryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, decryptionKey,(unsigned int) keyLength);
        }
        decryptPacket = CRYPTO_DES_DecryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "IDEA", 4)))
    {
        unsigned char initVector[8];
        unsigned char key[16];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (decryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, decryptionKey, (unsigned int)keyLength);
        }
        decryptPacket = CRYPTO_IDEA_DecryptPacket(inPacket,
                                                  inPacketLength,
                                                  outPacketLength,
                                                  cipherName,
                                                  key,
                                                  keyLength,
                                                  initVector,
                                                  ivLength);
    }
    else if (!(strncmp(cipherName, "BF", 2)))
    {
        unsigned char initVector[8];
        unsigned char *key = NULL;

        memset(initVector, 0, sizeof(initVector));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (decryptionKey != NULL)
        {
            key = (unsigned char*)MEM_malloc((unsigned int)(keyLength + 1));
            memset(key, 0, (unsigned int)(keyLength + 1));
            memcpy(key, decryptionKey, (unsigned int)keyLength);
        }
        decryptPacket = CRYPTO_BF_DecryptPacket(inPacket,
                                                inPacketLength,
                                                outPacketLength,
                                                cipherName,
                                                key,
                                                keyLength,
                                                initVector,
                                                ivLength);
        MEM_free(key);
    }
    else if (!(strncmp(cipherName, "CAST", 4)))
    {
        unsigned char initVector[8];
        unsigned char key[16];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector, (unsigned int)ivLength);
        }
        if (decryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, decryptionKey,(unsigned int) keyLength);
        }
        decryptPacket = CRYPTO_CAST_DecryptPacket(inPacket,
                                                  inPacketLength,
                                                  outPacketLength,
                                                  cipherName,
                                                  key,
                                                  keyLength,
                                                  initVector,
                                                  ivLength);
    }
    else if (!(strncmp(cipherName, "AES", 3)))
    {
        unsigned char initVector[64];
        unsigned char key[32];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (decryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, decryptionKey,(unsigned int) keyLength);
        }
        decryptPacket = CRYPTO_AES_DecryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "RC2", 3)))
    {
        unsigned char initVector[8];
        unsigned char key[128];

        memset(initVector, 0, sizeof(initVector));
        memset(key, 0, sizeof(key));

        if (initializationVector != NULL)
        {
            if ((unsigned int)ivLength > sizeof(initVector))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Initialization Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(initVector));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(initVector, initializationVector,(unsigned int) ivLength);
        }
        if (decryptionKey != NULL)
        {
            if ((unsigned int)keyLength > sizeof(key))
            {
                char errorStr[MAX_STRING_LENGTH];
                sprintf(errorStr, "Key Value should not exeed "
                                  "%u bytes\n", (UInt32)sizeof(key));
                ERROR_Assert(FALSE, errorStr);
            }
            memcpy(key, decryptionKey, (unsigned int)keyLength);
        }
        decryptPacket = CRYPTO_RC2_DecryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName,
                                                 key,
                                                 keyLength,
                                                 initVector,
                                                 ivLength);
    }
    else if (!(strncmp(cipherName, "RSA", 3)))
    {
        decryptPacket = CRYPTO_RSA_DecryptPacket(inPacket,
                                                 inPacketLength,
                                                 outPacketLength,
                                                 cipherName);
    }
    else
    {
        *outPacketLength = 0;
    }

    if (DEBUG_ENCRYPTION)
    {
        unsigned int len = *outPacketLength;
        printf("INPUT: 0x");
        for (int i = 0; i < inPacketLength; i++)
        {
            printf("%02x", inPacket[i]);
        }
        printf("\n%s DECRYPTION: 0x", cipherName);
        for (unsigned int i = 0; i < len; i++)
        {
            printf("%02x", decryptPacket[i]);
        }
        printf("\n");
    }

    return decryptPacket;
}

// /**
// FUNCTION    :: CRYPTO_GetIcvValue
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to get
//                the signature on the incoming pkt.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + key                  : unsigned char* : Keys to be used for signing
// + keyLength            : int : length of key
// + outPacketLength      : unsigned int* : pointer to the signature
// + authAlgo             : char* : authentication algo
// RETURN      :: unsigned char* : signature
// **/
unsigned char* CRYPTO_GetIcvValue(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned char* key,
    int keyLength,
    unsigned int* outPacketLength,
    char* authAlgo)
{
    unsigned char* md = NULL;
    *outPacketLength = 0;
    if (!(strcmp(authAlgo, "MD4")))
    {
        md = (unsigned char*) MEM_malloc(MD4_DIGEST_LENGTH);
        memset(md, 0, MD4_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int)inPacketLength,
                   md,
                   NULL,
                   EVP_md4(),
                   NULL);
        *outPacketLength = MD4_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-MD4")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_md4(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "MD5")))
    {
        md = (unsigned char*) MEM_malloc(MD5_DIGEST_LENGTH);
        memset(md, 0, MD5_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                  (unsigned int)inPacketLength,
                  md,
                  NULL,
                  EVP_md5(),
                  NULL);
        *outPacketLength = MD5_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-MD5")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_md5(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "HMAC-MD5-96")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_md5(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int)inPacketLength,
                  md, outPacketLength);
        memset(&(md[HMAC_MD5_96_DIGEST_LENGTH]),
                0,
                MD5_DIGEST_LENGTH - HMAC_MD5_96_DIGEST_LENGTH);
        *outPacketLength = HMAC_MD5_96_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "MDC2")))
    {
        md = (unsigned char*) MEM_malloc(MDC2_DIGEST_LENGTH);
        memset(md, 0, MDC2_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  NULL,
                  EVP_mdc2(),
                  NULL);
        *outPacketLength = MDC2_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-MDC2")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_mdc2(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "RIPEMD160")))
    {
        md = (unsigned char*) MEM_malloc(RIPEMD160_DIGEST_LENGTH);
        memset(md, 0, RIPEMD160_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int)inPacketLength,
                   md,
                   NULL,
                   EVP_ripemd160(),
                   NULL);
        *outPacketLength = RIPEMD160_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-RIPEMD160")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_ripemd160(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int)inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "SHA")))
    {
        md = (unsigned char*) MEM_malloc(SHA_DIGEST_LENGTH);
        memset(md, 0, SHA_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int) inPacketLength,
                   md,
                   NULL,
                   EVP_sha(),
                   NULL);
        *outPacketLength = SHA_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "SHA1")))
    {
        md = (unsigned char*) MEM_malloc(SHA_DIGEST_LENGTH);
        memset(md, 0, SHA_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int) inPacketLength,
                   md,
                   NULL,
                   EVP_sha1(),
                   NULL);
        *outPacketLength = SHA_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA1")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha1(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int)inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA-1-96")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha1(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int)inPacketLength,
                  md,
                  outPacketLength);
        memset(&(md[HMAC_SHA1_96_DIGEST_LENGTH]),
                0,
                SHA_DIGEST_LENGTH - HMAC_SHA1_96_DIGEST_LENGTH);
        *outPacketLength = HMAC_SHA1_96_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "SHA224")))
    {
        md = (unsigned char*) MEM_malloc(SHA224_DIGEST_LENGTH);
        memset(md, 0, SHA224_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int)inPacketLength,
                   md,
                   NULL,
                   EVP_sha224(),
                   NULL);
        *outPacketLength = SHA224_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA224")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha224(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "SHA256")))
    {
        md = (unsigned char*) MEM_malloc(SHA256_DIGEST_LENGTH);
        memset(md, 0, SHA256_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int) inPacketLength,
                   md,
                   NULL,
                   EVP_sha256(),
                   NULL);
        *outPacketLength = SHA256_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA256")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha256(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "SHA384")))
    {
        md = (unsigned char*) MEM_malloc(SHA384_DIGEST_LENGTH);
        memset(md, 0, SHA384_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int) inPacketLength,
                   md,
                   NULL,
                   EVP_sha384(),
                   NULL);
        *outPacketLength = SHA384_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA384")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha384(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "SHA512")))
    {
        md = (unsigned char*) MEM_malloc(SHA512_DIGEST_LENGTH);
        memset(md, 0, SHA512_DIGEST_LENGTH);
        EVP_Digest(inPacket,
                   (unsigned int) inPacketLength,
                   md,
                   NULL,
                   EVP_sha512(),
                   NULL);
        *outPacketLength = SHA512_DIGEST_LENGTH;
    }
    else if (!(strcmp(authAlgo, "HMAC-SHA512")))
    {
        md = (unsigned char*) MEM_malloc(MAX_DIGEST_LENGTH);
        memset(md, 0, MAX_DIGEST_LENGTH);
        md = HMAC(EVP_sha512(),
                  key,
                  keyLength,
                  inPacket,
                  (unsigned int) inPacketLength,
                  md,
                  outPacketLength);
    }
    else if (!(strcmp(authAlgo, "NULL")))
    {
        // Do nothing as it is null authentication algo.
    }
    else
    {
        char err[MAX_STRING_LENGTH];
        sprintf(err, "%s authentication algo is not supported", authAlgo);
        ERROR_ReportWarning(err);
    }

    if (DEBUG_HASH)
    {
        unsigned int len = *outPacketLength;
        char buf[MAX_STRING_LENGTH];
        if (!(strncmp(authAlgo, "HMAC", 4)))
        {
            printf("KEY: %s\n", key);
        }
        printf("INPUT: %s\n%s HASH: ", inPacket, authAlgo);
        for (unsigned int i = 0; i < len; i++)
        {
            sprintf(&(buf[3 * i]), "%02x ", md[i]);
        }
        printf("0x%s\n", buf);
    }

    return md;
}

// /**
// FUNCTION    :: CRYPTO_VerifyIcvValue
// LAYER       :: Network
// PURPOSE     :: Function to invoke the OPENSSL libraries to verify
//                the signature on the incoming pkt.
// PARAMETERS  ::
// + inPacket             : unsigned char* : Incoming pkt
// + inPacketLength       : int : incoming pkt length
// + key                  : unsigned char* : Keys to be used for signing
// + keyLength            : int : length of key
// + icvPacket            : unsigned char* : incoming signature
// + icvPacketLength      : int : Length of the incoming signature
// + authAlgo             : char* : authentication algo
// RETURN      :: bool
// **/
bool CRYPTO_VerifyIcvValue(
    unsigned char* inPacket,
    int inPacketLength,
    unsigned char* key,
    int keyLength,
    unsigned char* icvPacket,
    int icvPacketLength,
    char* authAlgo)
{
    unsigned int outPacketLength = (unsigned int)-1;
    unsigned char* icv = CRYPTO_GetIcvValue(
                                    inPacket,
                                    inPacketLength,
                                    key,
                                    keyLength,
                                    &outPacketLength,
                                    authAlgo);

    if ((outPacketLength == 0) && (icvPacketLength == 0))
    {
        return TRUE;
    }

    if ((outPacketLength == (unsigned int)icvPacketLength) &&
        (strncmp((char*)icv, (char*)icvPacket, outPacketLength) == 0))
    {
        MEM_free(icv);
        return TRUE;
    }

    if (icv != NULL)
    {
        MEM_free(icv);
    }

    return FALSE;
}
#endif
