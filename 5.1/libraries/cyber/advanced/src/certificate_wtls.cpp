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

#include <stdio.h>
#include <time.h>
#include <limits.h>

#include "api.h"
#include "crypto.h"
#include "certificate_wtls.h"

/* For various WTLS pseudorandom bit generation */
const byte *client_finish_label = (byte *)"client finished";
const byte *server_finish_label = (byte *)"server finished";
const byte *client_expansion_label = (byte *)"client expansion";
const byte *server_expansion_label = (byte *)"server expansion";
const byte *client_exportkey_label = (byte *)"client write key";
const byte *server_exportkey_label = (byte *)"server write key";
const byte *client_exportiv_label = (byte *)"client write IV";
const byte *server_exportiv_label = (byte *)"server write IV";

/* length_t(2B) parameter_index(1B) */
byte *RSA_parameter_specifier;
/* Identifier for RSA:
   length_t(2B) type(1B) charset(1B) length(1B) "RSA"(4B) */
byte *RSA_identifier;
/* Identifier for ECDSA:
   length_t(2B) type(1B) charset(1B) length(1B) "ECDSA"(6B) */
byte *ECDSA_identifier;

/* Identifier for certificate issuer */
/* length_t(2B) type(1B) charset(1B) length(1B) "SNT"(4B) */
#define ISSUER "SNT"
byte *issuer;
/* Identifier for certificate subject */
/* length_t(2B) type(1B) charset(1B) length(1B) "QualNet"(8B) */
#define SUBJECT "QualNet"
byte *subject;

/* KeyExchangeId for trusted Certificate Authorities */
#define NUM_TRUSTED     0
length_t num_trusted_key_ids = NUM_TRUSTED;
byte *trusted_key_ids[1/*NUM_TRUSTED*/];/*each prepended length_t leng*/
KeyExchangeSuite trusted_key_suites[1/*NUM_TRUSTED*/];
/* only GCC supports 0-length arrays */

/****************************************************************
 * Cryptographic functions
 ****************************************************************/
/**
 * FUNCTION: WTLS_H
 * PURPOSE: The cryptographic hash function H in WTLS document
 * PARAMETER: res: storing the result
 *            res_leng: maximal length of the "res" storage
 *            input: the input data
 *            input_leng: the input data length
 *            mac: indicating the MAC algorithm to be used
 *            mac_size: indicating the MAC result length
 * RETURN: none.
 */
static void WTLS_H(byte *res,
                   length_t *res_leng,
                   byte *input,
                   length_t input_leng,
                   MACAlgorithm mac,
                   uint8 mac_size)
{
#ifdef DO_MAC_CRYPTO
    if (mac >= MD5_40 && mac <= MD5)
    {
        MD_HANDLE digest = md_open(DIGEST_ALGO_MD5,1);//algo MD5
        md_write(digest, input, input_leng);//hashing input string
        *res_leng = md_digest(digest, DIGEST_ALGO_MD5, res, b2B(128));
        md_close(digest);// destroy and free hash state.
        if (mac == MD5)
        {
            return;
        }
    }
    else if (mac >= SHA_40 && mac <= SHA)
    {
        MD_HANDLE digest = md_open(DIGEST_ALGO_SHA1,1);//algo SHA1
        md_write(digest, input, input_leng);//hashing input string
        *res_leng = md_digest(digest, DIGEST_ALGO_SHA1, res, b2B(160));
        md_close(digest);// destroy and free hash state.
        if (mac == SHA)
        {
            return;
        }
    }
    else if (mac == SHA_XOR_40)
    {
        register length_t i, pad_input_leng = (input_leng+4)/5;
        byte *pad_input = (byte *)xcalloc(pad_input_leng, 1);

        for (i=0; i<pad_input_leng; i++)
        {
            pad_input[i] = (i<input_leng)? input[i] : 0;
        }
        for (i=5; i<pad_input_leng; i+=5)
        {
            pad_input[0] ^= pad_input[i];
            pad_input[1] ^= pad_input[i+1];
            pad_input[2] ^= pad_input[i+2];
            pad_input[3] ^= pad_input[i+3];
            pad_input[4] ^= pad_input[i+4];
        }
        memcpy(res, pad_input, 5);
        *res_leng = 5;
        free(pad_input);
        return;
    }

    *res_leng = mac_size;
#else
    // No real crypto, just manipulate the arguments
    //memset(res, input[input_leng-1]+mac+mac_size, *res_leng);
#endif // DO_MAC_CRYPTO
}

/*
 * FUNCTION: HMAC
 * PURPOSE: the function with same name in WTLS document
 * PARAMETER: res: storing the result (data and res can overlap in memory)
 *            res_leng: maximal length of the "res" storage
 *            K: the HMAC key
 *            K_leng: the HMAC key length
 *            data: the input data
 *            data_leng: the input data length
 *            sp: security parameter
 * RETURN: none.
 */
#define B_LENG 64
static const byte ipad=0x36, opad=0x5C;

static void
HMAC_hash(byte *res,
          length_t *res_leng,
          byte *K,
          length_t K_leng,
          byte *data,
          length_t data_leng,
          SecurityParameters *sp)
{
    register unsigned int i;
    byte h_res[20];
    length_t L = 0;
    register length_t step3_leng = B_LENG+data_leng, step6_leng;
    byte step1[B_LENG], *step2=(byte *)xcalloc(step3_leng, 1), *step5;

    if (K_leng > B_LENG)
    {
        WTLS_H(h_res, &L, K, K_leng, sp->mac_algorithm, sp->mac_size);
        memcpy(K, h_res, L);
        K_leng = L;
    }
    /* step 1 */
    for (i=0; i<B_LENG; i++)
        step1[i] = (i<K_leng)? K[i]: '\0';
    /* step 2 */
    for (i=0; i<B_LENG; i++)
        step2[i] = step1[i] ^ ipad;
    /* step 3 */
    for (i=0; i<data_leng; i++)
        step2[B_LENG+i] = data[i];
    /* step 4 */
    WTLS_H(h_res, &L, step2, step3_leng, sp->mac_algorithm, sp->mac_size);
    /* step 5 */
    step6_leng = B_LENG+L;
    step5 = (byte *)xcalloc(step6_leng, 1);
    for (i=0; i<B_LENG; i++)
        step5[i] = step1[i] ^ opad;
    /* step 6 */
    for (i=0; i<L; i++)
        step5[B_LENG+i] = h_res[i];
    /* step 7 */
    WTLS_H(h_res, &L, step5, step6_leng, sp->mac_algorithm, sp->mac_size);

    memcpy(res, h_res, L);
    *res_leng = L;
    free(step2);
    free(step5);
}

/*
 * FUNCTION: P_hash
 * PURPOSE: Pseudorandom hash function.
 *          The function with same name in WTLS document
 * PARAMETER: res: storing the result
 *            res_leng: maximal length of the "res" storage
 *            secret: the secret key
 *            secret_leng: the secret key length
 *            seed: the hash seed
 *            seed_leng: the hash seed length
 *            sp: security parameter
 * RETURN: none.
 */
static void P_hash(byte *res,
                   length_t res_leng,
                   byte *secret,
                   length_t secret_leng,
                   byte *seed,
                   length_t seed_leng,
                   SecurityParameters *sp)
{
    byte *A=(byte *)xcalloc(20+seed_leng, 1);
    length_t L;
    register length_t i, res_sz;

    /* compute A[1] at first */
    HMAC_hash(A, &L, secret, secret_leng, seed, seed_leng, sp);

    for (res_sz = 0; res_sz < res_leng; res_sz = res_sz + L)
    {
        /* compute next need */
        for (i=0; i<seed_leng; i++)
            A[L+i] = seed[i];
        HMAC_hash(A, &L, secret, secret_leng, A, L+seed_leng, sp);
        if (res_leng - res_sz < L)
            memcpy(res+res_sz, A, res_leng-res_sz);
        else
            memcpy(res+res_sz, A, L);
    }
    free(A);
}

/*
 * FUNCTION: PRF.
 * PURPOSE: PseudoRandom Function
 *          The function with same name in WTLS document
 * PARAMETER: res: storing the result (data and res can overlap in memory)
 *            res_leng: maximal length of the "res" storage
 *            secret: the secret key
 *            secret_leng: the secret key length
 *            label: the label used
 *            label_leng: the label's length
 *            seed: the seed
 *            seed_leng: the seed length
 *            sp: security parameter
 * RETURN: none.
 */
void PRF(byte *res,
         length_t res_leng,
         byte *secret,
         length_t secret_leng,
         const byte *label,
         length_t label_leng,
         byte *seed,
         length_t seed_leng,
         SecurityParameters *sp)
{
    register length_t labelseed_leng = label_leng+seed_leng;
    byte *labelseed = (byte *)xcalloc(labelseed_leng, 1);

    memcpy(labelseed, label, label_leng);
    memcpy(labelseed+label_leng, seed, seed_leng);
    P_hash(res, res_leng, secret, secret_leng, labelseed, labelseed_leng, sp);
}

/*
 * FUNCTION: compute_master_secret
 * PURPOSE: The function computing the master secret
 * PARAMETER: master_secret: storing the result
 *            pre_master_secret: storing the pre_master_secret
 *            client_random: pointer to the client random string
 *            server_random: pointer to the server random string
 *            sp: security parameter
 * RETURN: none.
 */
static const byte *master_secret_label = (byte *)"master secret";
void compute_master_secret(
    byte *master_secret,
    byte *pre_master_secret,  /* always 20 bytes in WTLS */
    byte *client_random,      /* always 20 bytes in WTLS */
    byte *server_random,      /* always 20 bytes in WTLS */
    SecurityParameters *sp)
{
    byte random[32];

    memcpy(random, client_random, 16);
    memcpy(random+16, server_random, 16);
    PRF(master_secret, 20,
        pre_master_secret, 20,
        master_secret_label, (length_t)strlen((char *)master_secret_label),
        random, 32, sp);
}

/*
 * FUNCTION: assign_keysizes
 * PURPOSE: get key sizes for various security context
 * PARAMETER: sp: Security parameter
 * RETURN: flag 0: ok; 1: something wrong.
 */
int assign_keysizes(SecurityParameters *sp)
{
    BulkCipherAlgorithm ba = sp->bulk_cipher_algorithm;
    MACAlgorithm ma = sp->mac_algorithm;

    switch(ba)
    {
    case (uint8)NULL:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_stream;
        sp->key_material_length = 0;
        sp->key_size = 0;
        sp->iv_size = 0;
        break;
    case RC5_CBC_40:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 5;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case RC5_CBC_56:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 7;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case RC5_CBC:
        sp->is_exportable = exportable_false;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 16;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case DES_CBC_40:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 5;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case DES_CBC:
        sp->is_exportable = exportable_false;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 8;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case TripleDES_CBC_EDE:
        sp->is_exportable = exportable_false;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 24;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case IDEA_CBC_40:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 5;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case IDEA_CBC_56:
        sp->is_exportable = exportable_true;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 7;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    case IDEA_CBC:
        sp->is_exportable = exportable_false;
        sp->cipher_type = ciphertype_block;
        sp->key_material_length = 16;
        sp->key_size = 8;
        sp->iv_size = 8;
        break;
    default:
        return 1;
    }

    switch(ma)
    {
    case SHA_0:
        sp->mac_key_size = 0;
        sp->mac_size = 0;
        break;
    case SHA_40:
        sp->mac_key_size = 20;
        sp->mac_size = 5;
        break;
    case SHA_80:
        sp->mac_key_size = 20;
        sp->mac_size = 10;
        break;
    case SHA:
        sp->mac_key_size = 20;
        sp->mac_size = 20;
        break;
    case SHA_XOR_40:
        sp->mac_key_size = 0;
        sp->mac_size = 5;
        break;
    case MD5_40:
        sp->mac_key_size = 16;
        sp->mac_size = 5;
        break;
    case MD5_80:
        sp->mac_key_size = 16;
        sp->mac_size = 10;
        break;
    case MD5:
        sp->mac_key_size = 16;
        sp->mac_size = 16;
        break;
    default:
        return 1;
    }

    sp->refresh_seq = (1 << sp->key_refresh);
    return 0;
}

/*
 * FUNCTION: key_block
 * PURPOSE: The function computing cipher key
 * PARAMETER: cw_mac: client hash
 *            cw_key: client key
 *            cw_iv: client IV
 *            sw_mac: server hash
 *            sw_key: server key
 *            sw_iv: server IV
 *            sp: security parameter
 * RETURN: none.
 */
void key_block(byte *cw_mac, byte *cw_key, byte *cw_iv,
               byte *sw_mac, byte *sw_key, byte *sw_iv,
               SecurityParameters *sp)
{
    byte seed[34];
    uint16 seq_num = (sp->cur_seq/sp->refresh_seq)*(sp->refresh_seq);
    register length_t macsz = sp->mac_key_size;
    register length_t keysz = sp->key_material_length;
    register length_t ivsz = sp->iv_size;
    register length_t keyblocksz = macsz + keysz + ivsz;
    byte keyblock[40/*leng*/];  /* no cipher algorithm in WTLS needs > 40B */

    memcpy(seed, &seq_num, sizeof(uint16));
    memcpy(seed+sizeof(uint16), sp->server_random, 16);
    memcpy(seed+sizeof(uint16)+16, sp->client_random, 16);

    /* This routine is optimized so that computing
       one set of client/server key is faster than
       computing both sets */
    if (cw_mac || cw_key || cw_iv)
    {
        PRF(keyblock, keyblocksz,
            sp->master_secret, 20,
            client_expansion_label,
            (length_t)strlen((char *)client_expansion_label),
            seed, 34, sp);
        memcpy(cw_mac, keyblock, macsz);
        memcpy(cw_key, keyblock+macsz, keysz);
        memcpy(cw_iv, keyblock+macsz+keysz, ivsz);

        if (sp->is_exportable)
        {
            PRF(keyblock, keysz,
                cw_key, keysz,
                client_exportkey_label,
                (length_t)strlen((char *)client_exportkey_label),
                seed+2, 32, sp);
            memcpy(cw_key, keyblock, keysz);
            PRF(keyblock, ivsz,
                NULL, 0,
                client_exportiv_label,
                (length_t)strlen((char *)client_exportiv_label),
                seed, 34, sp);
            memcpy(cw_iv, keyblock, ivsz);
        }
    }
    if (sw_mac || sw_key || sw_iv)
    {
        PRF(keyblock, keyblocksz,
            sp->master_secret, 20,
            server_expansion_label,
            (length_t)strlen((char *)server_expansion_label),
            seed, 34, sp);
        memcpy(sw_mac, keyblock, macsz);
        memcpy(sw_key, keyblock+macsz, keysz);
        memcpy(sw_iv, keyblock+macsz+keysz, ivsz);

        if (sp->is_exportable)
        {
            PRF(keyblock, keysz,
                sw_key, keysz,
                server_exportkey_label,
                (length_t)strlen((char *)server_exportkey_label),
                seed+2, 32, sp);
            memcpy(sw_key, keyblock, keysz);
            PRF(keyblock, ivsz,
                NULL, 0,
                server_exportiv_label,
                (length_t)strlen((char *)server_exportiv_label),
                seed, 34, sp);
            memcpy(sw_iv, keyblock, ivsz);
        }
    }
}

#ifdef DEBUG
/* Some debug routines, not part of regular code */
static char *blockciphernames[] =
    {"NULL", "RC5_CBC_40", "RC5_CBC_56", "RC5_CBC",
     "DES_CBC_40", "DES_CBC", "3DES_CBC_EDE",
     "IDEA_CBC_40", "IDEA_CBC_56", "IDEA_CBC"
    };
char * bulk_algo_name(BulkCipherAlgorithm ba)
{
    if (ba < IDEA_CBC)
        return blockciphernames[ba];
    else
        return "";
}
static char *macnames[] =
    {"SHA_0", "SHA_40", "SHA_80", "SHA", "SHA_XOR_40",
     "MD5_40", "MD5_80", "MD5"
    };
char *mac_algo_name(MACAlgorithm ma)
{
    if (ma < MD5)
        return macnames[ma];
    else
        return "";
}
void print_sec_param(SecurityParameters *sp)
{
    int i;

    printf("=========== Finalized security parameters: begin =============\n");
    printf("Entity: %s\n",
           (sp->entity==entity_client)? "client" : "server");
    printf("BulkCipherAlgorithm: %s\n",
           bulk_algo_name(sp->bulk_cipher_algorithm));
    printf("CipherType (is block cipher?): %d\n",
           sp->cipher_type == ciphertype_block);
    printf("KeySize: %d\n", sp->key_size);
    printf("IVSize: %d\n", sp->iv_size);
    printf("KeyMaterialLength: %d\n", sp->key_material_length);
    printf("IsExportable?: %s\n",
           (sp->is_exportable == exportable_true)? "TRUE":"FALSE");
    printf("MACAlgorithm: %s\n",
           mac_algo_name(sp->mac_algorithm));
    printf("MACKeySize: %d\n", sp->mac_key_size);
    printf("MACSize: %d\n", sp->mac_size);
    printf("MasterSecret: ");
    for (i=0; i<20; i++)
        printf("%02x ", sp->master_secret[i]);
    printf("\nClientRandom: ");
    for (i=0; i<16; i++)
        printf("%02x ", sp->client_random[i]);
    printf("\nServerRandom: ");
    for (i=0; i<16; i++)
        printf("%02x ", sp->server_random[i]);
    printf("\n");
    printf("SequenceNumberMode: %d\n", sp->sequence_number_mode);
    printf("KeyRefresh: %d\n", sp->key_refresh);
    printf("CompressionMethod: %d\n\n", sp->compression_algorithm);
    printf("KeyExchangeSuite: %d\n", sp->key_exchange_suite);
    printf("SessioID: %s\n", sp->session_id);
    printf("=========== Finalized security parameters: end =============\n");
    fflush(stdout);
}
#endif

/*****************************************************************
 * Common Encoders & Decoders:
 *  Specific encoders & decoders are put into client & server
 *  respecitively, so that the code size is smaller for them.
 *
 * An important remark:
 * Things with length_t will be encoded into the stream,
 * thus endian_....() are applied.
 * Things with length_t is for the convenience of encoding,
 * thus no need to apply endian_....().
 ****************************************************************/

/*
 * Generic converters
 */

//-------------------------------------------------------------------------
// FUNCTION : uint16_encode
// PURPOSE  : uint16 -> byte stream
// ARGUMENTS: result: the place holding the output
//            in: the input unsigned 16-bit integer
// RETURN   : void
//-------------------------------------------------------------------------
void
uint16_encode(byte *result, uint16 in)
{
    result[0] = (byte)(in >> 8);
    result[1] = (byte)(in & 0xff);
}
//-------------------------------------------------------------------------
// FUNCTION : uint16_decode
// PURPOSE  : byte stream -> uint16
// ARGUMENTS: in: the place holding the input
// RETURN   : the output unsigned 16-bit integer
//-------------------------------------------------------------------------
uint16
uint16_decode(byte *in)
{
    return (in[0] << 8) | in[1];
}
//-------------------------------------------------------------------------
// FUNCTION : uint16_endian
// PURPOSE  : treat the input as unsigned 16-bit integer, make it big endian
// ARGUMENTS: in: the place holding the input (and the output)
// RETURN   : void
//-------------------------------------------------------------------------
void
uint16_endian(byte *in)
{
    uint16 i;

    memcpy(&i, in, sizeof(uint16));
    in[0] = (byte)(i >> 8);
    in[1] = (byte)(i & 0xff);
}

/* uint32 <-> byte stream, similar to uint16 cases */
void
uint32_encode(byte *result, uint32 in)
{
    register int i;

    for (i=0; i<4; i++)
        result[i] = (byte)(in >> (24-i*8));
}
uint32
uint32_decode(byte *in)
{
    return (in[0]<<24) | (in[1]<<16) | (in[2]<<8) | in[3];
}
void
uint32_endian(byte *in)
{
    uint32 i;
    register length_t j;

    memcpy(&i, in, sizeof(uint32));

    for (j=0; j<4; j++)
        in[j] = (byte)(i >> (24-j*8));
}

/* uint64 <-> byte stream, similar to uint16 cases */
void
uint64_encode(byte *result, uint64 in)
{
    register int i;

    for (i=0; i<4; i++)
    {
        result[i] = (byte)(in[0] >> (24-i*8));
        result[i+4] = (byte)(in[1] >> (24-i*8));
    }
}
void
uint64_decode(uint64 result, byte *in)
{
    result[0] = (in[0]<<24) | (in[1]<<16) | (in[2]<<8) | in[3];
    result[1] = (in[4]<<24) | (in[5]<<16) | (in[6]<<8) | in[7];
}
void
uint64_endian(byte *in)
{
    uint64 i;
    register length_t j;

    memcpy(&i[0], in, sizeof(uint32));
    memcpy(&i[1], in+sizeof(uint32), sizeof(uint32));

    for (j=0; j<4; j++)
    {
        in[j] = (byte)(i[0] >> (24-j*8));
        in[j+4] = (byte)(i[1] >> (24-j*8));
    }
}

/* length_t <-> byte stream, similar to uint16 cases */
void
lengtht_encode(byte *result, length_t in)
{
    uint16_encode(result, in);
}
length_t
lengtht_decode(byte *in)
{
    return uint16_decode(in);
}
void
lengtht_endian(byte *in)
{
    uint16_endian(in);
}

/*********************************************
 * Converters for Section 9.2 Record Layer
 *********************************************/
/**
 * FUNCTION: WTLSText_decode
 * PURPOSE:
 * Converters for: WTLSPlaintext and WTLSCiphertext
 *
 * The caller decides whether his fragment is plaintext/ciphertext, then
 * call this routine with appropriate arguments.
 *
 * @return: the result in `result', and the length of result in return value.
 * No size prepended to the result, since WTLSPlaintext is an outmost message.
 *
 * @format: see Page 38
 *
 * ARGUMENTS:
 * @param record_type:
 *    bit 0 FragmentLengthIndication (0: no length field, 1: otherwise)
 *    bit 1 SequenceNumberIndication (0: no sequence# field, 1: otherwise)
 *    bit 2 indicates whether it is a plaintext or ciphertext
 *    bit 3 reserved
 *    bit 4--7 content type
 * @param sequence_number:
 *        pass 0 here if there is no explicit sequence number
 *        associated with this record.
 * @param length: have to pass length here, WTLS's argument doesn't hold for
 *                C language which has no way to tell the length of a byte
 *                stream except an explicit length indication.
 *
 * Sample call:
 * char buffer[LINE_MAX];
 * ContentType content_type = ct_application_data;
 * SequenceNumberIndication seq_ind = sni_with;
 * uint16 seq_num = 100;
 * uint16 fragment_leng = 1024;
 * byte fragment[fragment_leng];
 * int is_ciphertext=1; // fragment holds cipher text, set to 0 otherwise
 * result_leng = WTLSText_encode(buffer,
 *                               is_ciphertext,
 *                               content_type,
 *                               seq_ind,
 *                               seq_num,
 *                               fragment_leng,
 *                               fragment);
 *
 *      ......the result is put in "buffer" and the meaningful length of
 *            the buffer is "result_leng".......
 *
 *      At receiver side the same message is stored in input "buffer", then
 *
 * WTLSText_decode(&is_ciphertext, &seq_num,
 *                 &fragment_length, fragment, buffer);
 *      ......the "fragment" is restored with "fragment_leng"
 * RETURN: length of encoded result
 */
length_t WTLSText_encode(byte *result,
                       int flag,
                       ContentType content_type,
                       SequenceNumberIndication seq_ind,
                       uint16 sequence_number,
                       uint16 length,
                       byte *fragment)
{
    register length_t i=0;
    opaque record_type = (byte)
        ((content_type << 4) | ((flag?1:0)<<2) | ((seq_ind?1:0)<<1) | 0x1);

    result[i++] = record_type;

    if (seq_ind)
    {
        memcpy(result+i, &sequence_number, sizeof(uint16));
        uint16_endian(result+i);
        i += sizeof(uint16);
    }

    memcpy(result+i, &length, sizeof(uint16));
    uint16_endian(result+i);
    i += sizeof(uint16);

    memcpy(result+i, fragment, length);
    i = i + length;

    return i;
}

//-------------------------------------------------------------------------
// FUNCTION : WTLSText_TCP_encode
// PURPOSE  : TCP record type encoder
// ARGUMENTS: result: storing the encoded result
//            flag: flag to affect record type
//            content_type: content type, used with flag
//            length: length of the TCP text followed
// RETURN   : NONE
//-------------------------------------------------------------------------
/* The fast encoder assumes the caller is smart enough to
   maintain a 3-byte prefix area in the buffer so that
   the fragment need not be copied.
*/
void WTLSText_TCP_encode(byte *result,
                         int flag,
                         ContentType content_type,
                         uint16 length)
{
    opaque record_type =
        (byte)((content_type << 4) | ((flag?1:0)<<2) | 0x1);

    *result++ = record_type;

    memcpy(result, &length, sizeof(uint16));
    uint16_endian(result);
}

//-------------------------------------------------------------------------
// FUNCTION : WTLSText_UDP_encode
// PURPOSE  : UDP record type encoder
// ARGUMENTS: result: storing the encoded result
//            flag: flag to affect record type
//            content_type: content type, used with flag
//            length: length of the UDP text followed
// RETURN   : NONE
//-------------------------------------------------------------------------
/* The fast encoder assumes the caller is smart enough to
   maintain a 5-byte prefix area in the buffer so that
   the fragment need not be copied.
*/
void WTLSText_UDP_encode(byte *result,
                         int flag,
                         ContentType content_type,
                         uint16 sequence_number,
                         uint16 length)
{
    opaque record_type =
        (byte)((content_type << 4) | ((flag?1:0)<<2) | 0x1);

    *result++ = record_type;

    memcpy(result, &sequence_number, sizeof(uint16));
    uint16_endian(result);
    result += sizeof(uint16);

    memcpy(result, &length, sizeof(uint16));
    uint16_endian(result);
}

/*****************************
 * Converters for Section 10.5
 *****************************/
//-------------------------------------------------------------------------
// FUNCTION : Handshake_encode
// PURPOSE  : Handshake encoder
//      result@format: msg_type(1B) length(2B) body(length)
// ARGUMENTS: result: storing the encoded result
//            msg_type: type of the handshake message
//            length: length of handshake message
//            body: the handshake message of length `length'
// RETURN   : The length of the encoded result for encoder
//-------------------------------------------------------------------------
length_t Handshake_encode(byte *result,
                        HandshakeType msg_type,
                        uint16 length,
                        byte *body)
{
    length_t i=0;
    uint16 j=length;

    result[i++] = (byte)msg_type;

    memcpy(result+i, &length, sizeof(uint16));
    uint16_endian(result+i);
    i += sizeof(uint16);

    switch(msg_type)
    {
    case hello_request:
    case server_hello_done:
    default:
        j = 0;
        break;
    case client_hello:
    case server_hello:
    case certificate:
    case certificate_request:
    case client_key_exchange:
    case certificate_verify:
    case finished:
        memcpy(result+i, body, j);
        break;
    case server_key_exchange:
        ERROR_ReportError("Not implemented yet. Modify me!\n");
    }
    i = i + j;
    return i;
}

//-------------------------------------------------------------------------
// FUNCTION : ParameterSet_encode/decode
// PURPOSE  : Encoder/decoder for ParameterSet
//    For encoder@returns result in `result', which is
//    prepended with length.
//      result@format: length(2B) params(length)
// ARGUMENTS: result: storing the result
//            length: length of params
//            params: parameter set in binary format
//            algo: which public key algorithm
//            input: the input parameter set for decoder
// RETURN   : The length of the encoded result for encoder
//          : NONE for decoder
//-------------------------------------------------------------------------
length_t ParameterSet_encode(byte *result,
                           length_t length,
                           byte *params)
{
    length_t i=sizeof(length_t);

    memcpy(result+i, &length, sizeof(length_t));
    lengtht_endian(result+i);
    i += sizeof(length_t);

    memcpy(result+i, params, length);
    i = i + length;

    i -= sizeof(length_t);
    memcpy(result, &i, sizeof(length_t));
    return i;
}
void ParameterSet_decode(
    byte *result,
    byte **input,
    PublicKeyAlgorithm algo)
{
    byte *in = *input;
    uint16 length;

    length = uint16_decode(in);
    in += sizeof(uint16);

    switch(algo)
    {
    case algo_rsa:
        break;
#ifdef DO_ECC_CRYPTO
    case algo_diffie_hellman:
        DHParameters_decode(result, &in);
        break;
    case algo_elliptic_curve:
        ECParameters_decode(result, &in);
        break;
#endif // DO_ECC_CRYPTO
    default:
        // No crypto, just manipulate the arguments
        *result = 0;
    }

    *input = in;
}

//-------------------------------------------------------------------------
// FUNCTION : ParameterSpecifier_encode/decode
// PURPOSE  : Encoder/decoder for ParameterSpecifer
//    For encoder@returns result in `result', which is
//    prepended with length.
//      result@format: leng(length_t) parameter_index(1B)
//                     parameter_set(length(2B) params(length))
// ARGUMENTS: result: storing the result
//            parameter_index: index number
//            parameter_set: parameter set in binary format
//            algo: which public key algorithm
//            input: the input parameter specifier id for decoder
// RETURN   : The length of the encoded result for encoder
//          : NONE for decoder
//-------------------------------------------------------------------------
length_t ParameterSpecifier_encode(
    byte *result,
    ParameterIndex parameter_index,       /* uint8 */
    byte *parameter_set)
{
    length_t i=sizeof(length_t);
    length_t sz;

    result[i++] = parameter_index;

    switch(parameter_index)
    {
    case 255:
        memcpy(&sz, parameter_set, sizeof(length_t));
        memcpy(result+i, parameter_set, sizeof(length_t)+sz);
        i += sizeof(length_t) + sz;
    default:
        break;
    }

    i -= sizeof(length_t);
    memcpy(result, &i, sizeof(length_t));
    return i;
}
void ParameterSpecifier_decode(byte *result,
                               byte **input,
                               PublicKeyAlgorithm algo)
{
    byte *in = *input;
    ParameterIndex parameter_index;     /* uint8 */

    parameter_index = *in++;
    switch(parameter_index)
    {
    case 255:
        ParameterSet_decode(result, &in, algo);
        break;
    default:
        break;
    }

    *input = in;
}

//-------------------------------------------------------------------------
// FUNCTION : Identifier_encode/decode
// PURPOSE  : Encoder/decoder for Identifier
//    For encoder@returns result in `result', which is
//    prepended with length.
//      result@format: leng(length_t) identifier_type(1B)
//        { [ character_set(1B) name(length(1B) contents(length)) ]
//          [ identifier(length(1B) contents(length)) ]
//          [ key_hash(20B) ]
//          [ distinguished_name(length(1B) contents(length)) ] }
// ARGUMENTS: result: storing the result
//            identifier_type: which type of the identifier
//            character_set: which character set
//            length: identifier's total length
//            name: name
//            identifier: for binary format
//            key_hash: for hashed
//            distinguished_name: for X.509
//            input: the input identifier id for decoder
// RETURN   : The length of the encoded result for encoder
//          : NONE for decoder
//-------------------------------------------------------------------------
length_t Identifier_encode(byte *result,
                         IdentifierType identifier_type,
                         CharacterSet character_set,   /* for text */
                         length_t leng,
                         byte *name,
                         byte *identifier,             /* for binary */
                         byte *key_hash,               /* for key_hash_sha */
                         byte *distinguished_name)     /* for x509_name */
{
    length_t i=sizeof(length_t);

    result[i++] = (byte)identifier_type;
    switch(identifier_type)
    {
    case null:
    default:
        break;
    case text:
        result[i++] = (byte)character_set;
    case binary:
    case x509_name:
        if (leng > 0xff)
        {
            ERROR_ReportError("Invalid WTLS identifier.\n");
        }
        result[i++] = (byte)leng;
        switch(identifier_type)
        {
        case text:
            memcpy(result+i, name, leng);
            break;
        case binary:
            memcpy(result+i, identifier, leng);
            break;
        case x509_name:
            memcpy(result+i, distinguished_name, leng);
            break;
        default:
            break;
        }
        i = i + leng;
        break;
    case key_hash_sha:
        memcpy(result+i, key_hash, 20) ;
        i += 20;
        break;
    }

    i -= sizeof(length_t);
    memcpy(result, &i, sizeof(length_t));
    return i;
}
void Identifier_decode(byte *result, byte **input)
{
    byte *in = *input;
    IdentifierType identifier_type;
    CharacterSet character_set; /* for text only */
    length_t leng;

    identifier_type = (IdentifierType)*in++;
    switch(identifier_type)
    {
    case null:
    default:
        break;
    case text:
        character_set = *in++;
    case binary:
    case key_hash_sha:
    case x509_name:
        leng = *in++;
        memcpy(result, in, leng);
        in += leng;
        break;
    }

    *input = in;
}

//-------------------------------------------------------------------------
// FUNCTION : KeyExchangeId_encode/decode
// PURPOSE  : Encoder/decoder for KeyExchangeId
//    For encoder@returns result in `result', which is
//    prepended with length.
//      result@format: leng(length_t) key_exchange_suite(1B)
//      parameter_specifier(above) identifier(above)
// ARGUMENTS: result: storing the encoded result for encoder
//            suite: which key exchange suite
//            para_spec: parameter specification
//            indentifier: key exchange identifier
//            input: the input key exchange id for decoder
// RETURN   : The length of the encoded result for encoder
//          : NONE for decoder
//-------------------------------------------------------------------------
length_t KeyExchangeId_encode(byte *result,
                            KeyExchangeSuite suite,       /* uint8 */
                            byte *para_spec,
                            byte *identifier)
{
    length_t i=sizeof(length_t);
    length_t sz;

    result[i++] = suite;

    memcpy(&sz, para_spec, sizeof(length_t));
    memcpy(result+i, para_spec+sizeof(length_t), sz);
    i = i + sz;

    memcpy(&sz, identifier, sizeof(length_t));
    memcpy(result+i, identifier+sizeof(length_t), sz);
    i = i + sz;

    i -= sizeof(length_t);
    memcpy(result, &i, sizeof(length_t));
    return i;
}
void KeyExchangeId_decode(KeyExchangeSuite *suite,
                          byte *para_spec,
                          byte *identifier,
                          byte **input)
{
    byte *in = *input;
    KeyExchangeSuite key_exchange_suite;        /* uint8 */

    key_exchange_suite = *in++;
    *suite = key_exchange_suite;

    if (key_exchange_suite == 0)
    {
        /* no key exchange, WTLS authentication class 1 */
    }
    else if (key_exchange_suite == 1)
    {
        /* already had a shared secret */
    }
    else if (key_exchange_suite >= 2 && key_exchange_suite <= 4)
    {
        /* DH key exchange suite */
    }
    else if (key_exchange_suite >= 5 && key_exchange_suite <= 10)
    {
        /* RSA key exchange suite */
        ParameterSpecifier_decode(para_spec,
                                  &in, algo_rsa);
        Identifier_decode(identifier, &in);
    }
    else if (key_exchange_suite >= 11 && key_exchange_suite <= 18)
    {
        /* ECDH key exchange suite */
    }

    *input = in;
}

//-------------------------------------------------------------------------
// FUNCTION : ToBeSignedCert_encode
// PURPOSE  : Disassemble a plain certificate into parts
// ARGUMENTS: result: storing the result
//            cert_version: the version info
//            signature_algorithm: signing algorithm used
//            issuer: the certificate issuer
//            valid_not_before: certificate starting time
//            valid_not_after: certificate end time
//            subject: the subject
//            public_key_type: which public key type used
//            para_spec: parameter specifier for the public key
//            public_key: the certificate owner's personal public key
// RETURN   : the size of the result plain certificate
// @format: cert_version(1B) signature_algorithm(1B)
//          issuer(Identifier) valid_not_before(4B) valid_not_after(4B)
//          subject(Identifier) public_key_type(1B)
//          parameter_specifier(ParameterSpecifier)
//          public_key(WTLS_PublicKey)
//-------------------------------------------------------------------------
length_t
ToBeSignedCert_encode(byte *result,
                      uint8 cert_version,
                      SignatureAlgorithm signature_algorithm,
                      byte *issuer,     /* Identifier */
                      uint32 valid_not_before,
                      uint32 valid_not_after,
                      byte *subject,    /* Identifier */
                      PublicKeyType public_key_type,
                      byte *para_spec,  /* Parameter_Specifier */
                      byte *public_key) /* RSAPublicKey */
{
    length_t i=0;
    length_t length;
    length_t sz;

    result[i++] = cert_version;
    result[i++] = (byte)signature_algorithm;

    memcpy(&sz, issuer, sizeof(length_t));
    issuer += sizeof(length_t);
    length = (length_t)sz;
    memcpy(result+i, &length, sizeof(length_t));
    lengtht_endian(result+i);
    i += sizeof(length_t);
    memcpy(result+i, issuer, sz);
    i = i + sz;

    memcpy(result+i, &valid_not_before, sizeof(uint32));
    uint32_endian(result+i);
    i += sizeof(uint32);
    memcpy(result+i, &valid_not_after, sizeof(uint32));
    uint32_endian(result+i);
    i += sizeof(uint32);

    memcpy(&sz, subject, sizeof(length_t));
    subject += sizeof(length_t);
    length = (length_t)sz;
    memcpy(result+i, &length, sizeof(length_t));
    lengtht_endian(result+i);
    i += sizeof(length_t);
    memcpy(result+i, subject, sz);
    i = i + sz;

    result[i++] = (byte)public_key_type;

    memcpy(&sz, para_spec, sizeof(length_t));
    memcpy(result+i, para_spec+sizeof(length_t), sz);
    i = i + sz;

    memcpy(&sz, public_key, sizeof(length_t));
    memcpy(result+i, public_key+sizeof(length_t), sz);
    i = i + sz;

    return i;
}

//-------------------------------------------------------------------------
// FUNCTION : ToBeSignedCert_decode
// PURPOSE  : Disassemble a plain certificate into parts
// ARGUMENTS: sigalgo: storing signing algorithm result
//            issuer: storing the certificate issuer
//            subject: storing the subject
//            pk: storing the certificate owner's personal public key
//            input: the input plain certificate
// RETURN   : 1: valid certificate; 0: invalid certificate
//-------------------------------------------------------------------------
int
ToBeSignedCert_decode(SignatureAlgorithm *sigalgo,
                      byte *issuer,     /* Identifier */
                      byte *subject,    /* Identifier */
                      RSAPublicKey *pk,
                      byte **input)
{
    byte *in = *input;
    uint8 cert_version;
    PublicKeyType public_key_type;
    length_t leng;
    uint32 vtstart, vtend, curtime;

    cert_version = *in++;
    if (cert_version != 1)
        ERROR_ReportWarningArgs("Suspicious WTLS certificate version `"
                                "%d'.\n", cert_version);

    if (sigalgo != NULL)
    {
        *sigalgo = (SignatureAlgorithm)*in++;
        if (*sigalgo != SA_ECDSA_SHA && *sigalgo != SA_ECDSA_MD5)
        {
            ERROR_ReportWarning("Only supports (ECDSA_SHA and ECDSA_MD5)"
                                " signed WTLS certificiate.\n");
            return 0;
        }
    }
    else
        in++;

    leng = lengtht_decode(in);
    in += sizeof(length_t);
    if (issuer != NULL)
        memcpy(issuer, in, leng);
    in += leng;

    vtstart = uint32_decode(in);
    in += sizeof(uint32);
    vtend = uint32_decode(in);
    in += sizeof(uint32);
    curtime = (uint32)time(NULL);
    if (curtime > vtend || curtime < vtstart)
        /* invalid certificate */
        return 0;

    leng = lengtht_decode(in);
    in += sizeof(length_t);
    if (subject != NULL)
        memcpy(subject, in, leng);
    in += leng;

    public_key_type = (PublicKeyType)*in++;
    if (public_key_type != pkt_rsa)
    {
        /* currently only RSA is supported */
        ERROR_ReportWarning("Only supports (RSA) public key "
                            "cryptosystem.\n");
        return 0;
    }

    /* skip parameter_specifier */
    ParameterSpecifier_decode(NULL, &in, algo_rsa);

    RSAPublicKey_decode(&in, pk);

    *input = in;
    return 1;
}
