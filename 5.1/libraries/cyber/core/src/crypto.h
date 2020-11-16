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

#ifndef NETIA_CRYPTO_H
#define NETIA_CRYPTO_H

#ifdef __cplusplus
extern "C" {
#endif

//-------------------------------------------------------------------
// ECC crypto assumption:
//
// Each node's interface XXX has its own private default.privatekey.XXX and
// public default.publickey.XXX.   The private key is *only* carried
// by XXX, while the public key is carried by all nodes.
// (We will implement certificate-based public key authentication
//  in separated IA modules)
//
// In QualNet, default.privatekey.XXX and default.publickey.XXX are
// generated under the current execution directory on the fly.
// The user doesn't need to worry about it.  If QualNet complains about
// ECC errors, the files should be manually deleted and will be
// re-generated automatically.
//-------------------------------------------------------------------

// If defined, will do real ECC or AES crypto-operations, respectively.
// Nevertheless, the simulation results must be the same as those runs
// with no crypto-operations (disabling DO_ECC_CRYPTO & DO_AES_CRYPTO).
//
// Caveats:
// 1. Elliptic Curve Cryptosystem (ECC) will incur expensive
//    public key crypto-opeations.  It would slow down the simulation host
//    tremendously (compared to AES crypto-operations).
// 2. Due to pseudorandom nature of QualNet, the ECC key
//    selection may not be random enough.  To test the correctness
//    of your ECC key generations, you must at first turn on
//    DEBUG_ROUTE to 1 (thus also turn on DEBUG_ECC).
//    If such a run reports no ECC error, then turn DEBUG_ROUTE off to 0
//    to do real simulations using your random ECC keys.
//#define DO_ECC_CRYPTO
//#define DO_AES_CRYPTO

// # of bits ==> # of Bytes
#define b2B(x)  (((int)x+7)/8)
#define QUALNET_ECC_KEYLENGTH   192   // 192-bit length for ECC
#define QUALNET_ECC_PUBLIC_KEYLENGTH    (3*QUALNET_ECC_KEYLENGTH) // Q.x Q.y Q.z
#define QUALNET_ECC_PUBLIC_KEYLENG(x)   (3*b2B(x))      // x is length in bits
// Note that in GPG's ECC, any ECC ciphertext length is
// "AES ciphertext length + 3*192-bit R", that is,
// the corresponding AES ciphertext length plus extra 576 bits for ECC's R.
#define QUALNET_ECC_BLOCKLENGTH(PLAINTEXTLENGTH) ((PLAINTEXTLENGTH)+3*QUALNET_ECC_KEYLENGTH)

// Currently let's use a compact certificate with maximum length 120 bytes
#define QUALNET_MAX_CERTIFICATE_LENGTH        120
#define QUALNET_MAX_DIGITALSIGNATURE_LENGTH   32  // for 256-bit SHA256
#define QUALNET_MAX_STRING_LENGTH             300

#define AES_DEFAULT_DELAY       (40 * MICRO_SECOND)
#define ECC_DEFAULT_DELAY       (40 * MILLI_SECOND)

typedef unsigned char byte;

// For ciphers
#define CIPHER_ALGO_NONE         0
#define CIPHER_ALGO_IDEA         1
#define CIPHER_ALGO_3DES         2
#define CIPHER_ALGO_CAST5        3
#define CIPHER_ALGO_BLOWFISH     4  /* blowfish 128 bit key */
/* 5 & 6 are reserved */
#define CIPHER_ALGO_AES          7
#define CIPHER_ALGO_AES192       8
#define CIPHER_ALGO_AES256       9
#define CIPHER_ALGO_TWOFISH     10  /* twofish 256 bit */
#define CIPHER_ALGO_DUMMY      110  /* no encryption at all */

#define PUBKEY_ALGO_RSA        1
#define PUBKEY_ALGO_RSA_E      2     /* RSA encrypt only */
#define PUBKEY_ALGO_RSA_S      3     /* RSA sign only */
#define PUBKEY_ALGO_ELGAMAL_E 16     /* encrypt only ElGamal (but not for v3)*/
#define PUBKEY_ALGO_DSA       17
#define PUBKEY_ALGO_ELGAMAL   20     /* sign and encrypt elgamal */
/*begin ECC mod*/
#define PUBKEY_ALGO_ECC      103     /*experimental: ECC; encrypt: ECDH+AES, sign:ECDSA*/
#define PUBKEY_ALGO_ECC_E    104     /* ECC encrypt only */
#define PUBKEY_ALGO_ECC_S    105     /* ECC sign only */
/*end ECC mod*/

#define PUBKEY_USAGE_SIG     1      /* key is good for signatures */
#define PUBKEY_USAGE_ENC     2      /* key is good for encryption */
#define PUBKEY_USAGE_CERT    4      /* key is also good to certify other keys*/
#define PUBKEY_USAGE_AUTH    8      /* key is good for authentication */
#define PUBKEY_USAGE_UNKNOWN 128    /* key has an unknown usage bit */

#define DIGEST_ALGO_MD5       1
#define DIGEST_ALGO_SHA1      2
#define DIGEST_ALGO_RMD160    3
/* 4, 5, 6, and 7 are reserved */
#define DIGEST_ALGO_SHA256    8
#define DIGEST_ALGO_SHA384    9
#define DIGEST_ALGO_SHA512   10

#define COMPRESS_ALGO_NONE   0
#define COMPRESS_ALGO_ZIP    1
#define COMPRESS_ALGO_ZLIB   2
#define COMPRESS_ALGO_BZIP2  3

#define is_RSA(a)     ((a)==PUBKEY_ALGO_RSA || (a)==PUBKEY_ALGO_RSA_E \
                       || (a)==PUBKEY_ALGO_RSA_S )
#define is_ELGAMAL(a) ((a)==PUBKEY_ALGO_ELGAMAL_E)
#define is_DSA(a)     ((a)==PUBKEY_ALGO_DSA)
/*begin ECC mod*/
#define is_ECC(a)     ((a)==PUBKEY_ALGO_ECC || (a)==PUBKEY_ALGO_ECC_E \
                       || (a)==PUBKEY_ALGO_ECC_S )
/*end ECC mod*/

#define CIPHER_MODE_ECB       1
#define CIPHER_MODE_CFB       2
#define CIPHER_MODE_PHILS_CFB 3
#define CIPHER_MODE_AUTO_CFB  4
#define CIPHER_MODE_DUMMY     5  /* used with algo DUMMY for no encryption */
#define CIPHER_MODE_CBC       6

typedef struct {
    int algo;
    int keylen;
    int algo_info_printed;
    int use_mdc;
    byte key[32]; /* this is the largest used keylen (256 bit) */
} DEK;

struct cipher_handle_s;
typedef struct cipher_handle_s *CIPHER_HANDLE;

struct md_digest_list_s;

struct gcry_md_context {
    int  secure;
    FILE  *debug;
    int finalized;
    struct md_digest_list_s *list;
    int  bufcount;
    int  bufsize;
    byte buffer[1];
};

typedef struct gcry_md_context *MD_HANDLE;

#ifdef DO_ECC_CRYPTO
// For Elliptic Curve Cryptosystem
int ecc_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
int ecc_check_secret_key( int algo, MPI *skey );
/* resarr[] should be uninitialized MPIs, will be allocated by ecc_encrypt() */
int ecc_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey );
int ecc_decrypt( int algo, MPI *result, MPI *data, MPI *skey );
int ecc_sign( int algo, MPI *resarr, MPI data, MPI *skey );
int ecc_verify( int algo, MPI hash, MPI *data, MPI *pkey );
unsigned ecc_get_nbits( int algo, MPI *pkey );
int test_ecc_key( int algo, MPI *skey, unsigned nbits );
#endif // DO_ECC_CRYPTO

#ifdef DO_RSA_CRYPTO
// For RSA Cryptosystem
int rsa_generate( int algo, unsigned nbits, MPI *skey, MPI **retfactors );
int rsa_check_secret_key( int algo, MPI *skey );
int rsa_encrypt( int algo, MPI *resarr, MPI data, MPI *pkey );
int rsa_decrypt( int algo, MPI *result, MPI *data, MPI *skey );
int rsa_sign( int algo, MPI *resarr, MPI data, MPI *skey );
int rsa_verify( int algo, MPI hash, MPI *data, MPI *pkey );
unsigned rsa_get_nbits( int algo, MPI *pkey );
#endif // DO_RSA_CRYPTO

// Some routines
int hex_to_val(unsigned char in);
int hexstr_to_bitstream(byte *bitstream, size_t leng, const byte *hexstr);
void bitstream_to_hexstr(byte *hexstr, const byte *bitstream, size_t leng);

#ifdef DO_ECC_CRYPTO
MPI EccChooseRandomNumber(MPI n, int keyBitLength);
void EccPubKeyEncryption(byte *ciphertext, MPI *pubKey, int keyBitLength, byte *plaintext, int  plaintextBitLength);
void EccPubKeyDecryption(byte *plaintext, int  plaintextBitLength, MPI *skey, int keyBitLength, byte *ciphertext);
#endif // DO_ECC_CRYPTO

/*-- cipher.c --*/
int string_to_cipher_algo( const char *string );
const char * cipher_algo_to_string( int algo );
void disable_cipher_algo( int algo );
int check_cipher_algo( int algo );
unsigned cipher_get_keylen( int algo );
unsigned cipher_get_blocksize( int algo );
CIPHER_HANDLE cipher_open( int algo, int mode, int secure );
void cipher_close( CIPHER_HANDLE c );
int  cipher_setkey( CIPHER_HANDLE c, byte *key, unsigned keylen );
void cipher_setiv( CIPHER_HANDLE c, const byte *iv, unsigned ivlen );
void cipher_encrypt( CIPHER_HANDLE c, byte *out, byte *in, unsigned nbytes );
void cipher_decrypt( CIPHER_HANDLE c, byte *out, byte *in, unsigned nbytes );
void cipher_sync( CIPHER_HANDLE c );

/*-- md.c --*/
int string_to_digest_algo( const char *string );
const char * digest_algo_to_string( int algo );
int check_digest_algo( int algo );
MD_HANDLE md_open( int algo, int secure );
void md_enable( MD_HANDLE hd, int algo );
MD_HANDLE md_copy( MD_HANDLE a );
void md_reset( MD_HANDLE a );
void md_close(MD_HANDLE a);
void md_write( MD_HANDLE a, const byte *inbuf, size_t inlen);
void md_final(MD_HANDLE a);
byte *md_read( MD_HANDLE a, int algo );
int md_digest( MD_HANDLE a, int algo, byte *buffer, int buflen );
int md_get_algo( MD_HANDLE a );
int md_algo_present( MD_HANDLE a, int algo );
int md_digest_length( int algo );
const byte *md_asn_oid( int algo, size_t *asnlen, size_t *mdlen );
void md_start_debug( MD_HANDLE a, const char *suffix );
void md_stop_debug( MD_HANDLE a );
#define md_is_secure(a) ((a)->secure)
#define md_putc(h,c)  \
            do {                                            \
                if ((h)->bufcount == (h)->bufsize )         \
                    md_write( (h), NULL, 0 );               \
                (h)->buffer[(h)->bufcount++] = (c) & 0xff;  \
            } while (0)
void rmd160_hash_buffer (char *outbuf, const char *buffer, size_t length);

/*-- misc --*/
void *xmalloc( size_t n );
void *xmalloc_clear( size_t n );
void *xcalloc (size_t n, size_t m);
void *xmalloc_secure( size_t n );
void *xmalloc_secure_clear( size_t n );
void *xrealloc( void *a, size_t n );
void xfree( void *p );
void m_check( const void *a );
/*void *m_copy( const void *a );*/
char *xstrdup( const char * a);
void wipememory(byte *ptr, int len);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // NETIA_CRYPTO_H
