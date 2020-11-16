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

#ifndef NETIA_WTLS_H
#define NETIA_WTLS_H

/* 1. Data structures here with variable length vector are
 *    for reference only.  They cannot be directly used to assemble
 *    the message transmitted over the network.
 * 2. All data structures with variable length are prepended with a "sz"
 *    between caller and callee.  The "sz" is for internal convenience
 *    only, and is not transmitted out.
 * 3. Though data structures here with constant length can be used
 *    directly to assemble the message transmitted over the network.
 *    endian_...() routines must be invoked on each element to
 *    make all data big-endian (as WTLS specified).
 * 4. _dummy is defined by WTLS 1.0 to indicate how large the enum type is.
 *    Current all the dummies are <= 255, thus uint8 is enough
 *    for all enum types.
 */
/*#include <limits.h>*/
#include "crypto.h"

/*
 * In SIMPLE MANET ECC, we will reduce communication overhead by using
 * a single fixed-length elliptic curve from all mobile nodes.
 * This way, there is no need to exchange the curve parameters
 * like the prime p and the modulo n,  as they are well-known
 * default values in the MANET.
 */
#define SIMPLE_MANET_ECC

/*****************************************************************
 * Data Structures
 *****************************************************************/
/* Section 8 Presentation Language */
typedef byte opaque;  /* byte and opaque are synonyms */
typedef UInt8  uint8;
typedef UInt16 uint16;
typedef UInt32  uint32;
typedef uint32  uint64[2];
/* WTLS 1.0 forgot to define the type of length for variable length vectors */
typedef uint16 length_t;
typedef opaque SessionSignature[128];

/* Section 9.1  Connection State */
typedef enum { entity_server=1, entity_client=2 } ConnectionEnd;
typedef uint8 BulkCipherAlgorithm;
typedef enum {
    ciphertype_stream=1, ciphertype_block=2, ciphertype_dummy=255
} CipherType;
typedef enum { exportable_false=0, exportable_true=1 } IsExportable;
typedef uint8 MACAlgorithm;
typedef enum { snm_off=0, snm_implicit=1, snm_explicit=2, snm_dummy=255 } SequenceNumberMode;
typedef uint8 CompressionMethod;

/***** The two definitions below are moved forward */
typedef uint8 KeyExchangeSuite;
/* opaque SessionID<0..8>; */
typedef opaque SessionID[8];    /* const leng: 8B */

typedef struct
{
    ConnectionEnd entity;
    BulkCipherAlgorithm bulk_cipher_algorithm;
    CipherType cipher_type;
    uint8 key_size; /* bytes */

    uint8 iv_size; /* bytes */
    uint8 key_material_length; /* bytes */
    IsExportable is_exportable;
    MACAlgorithm mac_algorithm;
    uint8 mac_key_size; /* bytes */
    uint8 mac_size; /* bytes */
    opaque master_secret[20];
    opaque client_random[16];
    opaque server_random[16];
    SequenceNumberMode sequence_number_mode;
    uint8 key_refresh;
    CompressionMethod compression_algorithm;

    /* Added by Jiejun Kong */
    KeyExchangeSuite key_exchange_suite;
    SessionID session_id;
    SessionSignature session_signature;
    uint16 refresh_seq; /* i.e., 2^key_refresh */
    uint16 cur_seq;     /* current sequence number */
} SecurityParameters;

/* Section 9.2 Record Layer */
typedef enum {
    ct_change_cipher_spec=1, ct_alert, ct_handshake, ct_application_data,
    ct_dummy=15
} ContentType;
typedef enum { sni_without=0, sni_with=1 } SequenceNumberIndication;
typedef enum { fli_without=0, fli_with=1 } FragmentLengthIndication;

typedef struct
{
    opaque record_type[1];
    /*
    select (SequenceNumberIndication) {
        case without: struct {};
        case with: uint16 sequence_number;
    }
    */
    uint16 sequence_number;
    /*
    select (FragmentLengthIndication) {
        case without: struct {};
        case with: uint16 length;
    }
    */
    uint16 length;
    opaque fragment[MAX_STRING_LENGTH]; /* need a loop here if `length'>MAX_STRING_LENGTH */
} WTLSPlaintext;

typedef struct
{
    opaque record_type[1];
    /*
    select (SequenceNumberIndication) {
        case without: struct {};
        case with: uint16 sequence_number;
    }
    */
    uint16 sequence_number;

    /*
    select (FragmentLengthIndication) {
        case without: struct {};
    case with: uint16 length;
    }
    */
    uint16 length;
    opaque fragment[MAX_STRING_LENGTH]; /* need a loop here if `length'>MAX_STRING_LENGTH */
} WTLSCompressed;

typedef struct stream_ciphered
{
    /* opaque content[WTLSCompressed.length]; */
    opaque content[MAX_STRING_LENGTH];  /* need a loop here if `length'>MAX_STRING_LENGTH */
    /* opaque MAC[SecurityParameters.mac_size]; */
    opaque MAC[20];     /* SHA1: 20 Byte.  MD5: 16 Byte */
} GenericStreamCipher;

typedef struct block_ciphered
{
    /*
    opaque content[WTLSCompressed.length];
    opaque MAC[SecurityParameters.mac_size];
    uint8 padding[padding_length];
    uint8 padding_length;
    */
    opaque content[MAX_STRING_LENGTH];
    opaque MAC[20];
    /* In this implementation of WTLS, padding is done by RFC1423,
       no need of explicit storage allocation */
} GenericBlockCipher;

typedef struct
{
    opaque record_type[1];

    /*
    select (SequenceNumberIndication) {
        case without: struct {};
        case with: uint16 sequence_number;
    }
    */
    uint16 sequence_number;

    /*
    select (FragmentLengthIndication) {
        case without: struct {};
        case with: uint16 length;
    }
    */
    uint16 length;

    /*
    select (SecurityParameters.cipher_type) {
        case stream: GenericStreamCipher;
        case block: GenericBlockCipher;
    } fragment;
    */
    union
    {
        GenericStreamCipher stream_cipher;
        GenericBlockCipher block_cipher;
    } fragment;
} WTLSCiphertext;

/* Section 10.1 Change Cipher Spec Protocol */
typedef enum { ccs_change_cipher_spec=1, ccs_dummy=255 } ChangeCipherSpec;

/* Section 10.2 Alert Protocol */
typedef enum { warning=1, critical, fatal, al_dummy=255} AlertLevel;

typedef enum {
    connection_close_notify=0, session_close_notify,
    no_connection=5, unexpected_message=10, time_required,
    bad_record_mac=20, decryption_failed, record_overflow,
    decompression_failure=30, handshake_failure=40,
    bad_certificate=42, unsupported_certificate/*43*/,
    certificate_revoked/*44*/, certificate_expired/*45*/,
    certificate_unknown/*46*/, illegal_parameter/*47*/,
    unknown_ca/*48*/, access_denied/*49*/, decode_error/*50*/,
    decrypt_error/*51*/, unknown_key_id/*52*/, disabled_key_id/*53*/,
    key_exchange_disabled/*54*/, session_not_ready/*55*/,
    unknown_parameter_index/*56*/, duplicate_finished_received/*57*/,
    export_restriction=60,
    protocol_version=70, insufficient_security,
    internal_error=80, user_canceled=90, no_renegotiation=100,
    ad_dummy=255
} AlertDescription;

typedef struct
{
    AlertLevel level;
    AlertDescription description;
    opaque checksum[4];
} Alert;

/* Section 10.5 Handshake Protocol */
typedef enum {
    hello_request=0, client_hello, server_hello,
    certificate=11, server_key_exchange, certificate_request,
    server_hello_done, certificate_verify, client_key_exchange,
    finished=20, ht_dummy=255
} HandshakeType;

typedef struct
{
    HandshakeType msg_type;
    uint16 length;
    /*
    select (msg_type) {
    case hello_request: HelloRequest;
    case client_hello: ClientHello;
    case server_hello: ServerHello;
    case certificate: Certificates;
    case server_key_exchange: ServerKeyExchange;
    case certificate_request: CertificateRequest;
    case server_hello_done: ServerHelloDone;
    case certificate_verify: CertificateVerify;
    case client_key_exchange: ClientKeyExchange;
    case finished: Finished;
    } body;
    */
} Handshake;

typedef struct { } HelloRequest;

typedef struct
{
    uint32 gmt_unix_time;
    opaque random_bytes[12];
} Random;       /* const leng: 16B */

typedef struct
{
    uint8 dh_e;
    /*
    opaque dh_p<1..2^16-1>;
    opaque dh_g<1..2^16-1>;
    */
} DHParameters; /* var leng */

typedef enum {
    ec_prime_p=1, ec_characteristic_two=2, ec_dummy=255
} ECFieldID;
typedef enum {
    ec_basis_onb=1, ec_basis_trinomial=2,
    ec_basis_pentanomial=3, ec_basis_polynomial=4
} ECBasisType;
typedef struct
{
    length_t nbits;

    /* opaque point <1..2^8-1>; */
#ifdef DO_ECC_CRYPTO
    MPI x_;
    MPI y_;
    MPI z_;
#endif // DO_ECC_CRYPTO
} ECPoint;      /* var leng */
typedef struct
{
    length_t nbits;

    /*
    opaque a <1..2^8-1>;
    opaque b <1..2^8-1>;
    optional opaque seed <0..2^8-1>;
    */
#ifdef DO_ECC_CRYPTO
#ifdef SIMPLE_MANET_ECC
    MPI p_;
#endif
    MPI a_,b_;
    ECPoint G;
    MPI n_;
    //MPI h_; =1  //!! We will need to change this value in 2-isogeny
#endif // DO_ECC_CRYPTO
} ECCurve;      /* var leng */

typedef struct
{
    ECFieldID fieldID;
    /* select (field) {
        case ec_prime_p: opaque prime_p <1..2^8-1>;
        case ec_characteristic_two:
            uint16 m;
            ECBasisType basis;
            select (basis) {
                case ec_basis_onb: struct { };
                case ec_trinomial: uint16 k;
                case ec_pentanomial:
                    uint16 k1;
                    uint16 k2;
                    uint16 k3;
                case ec_basis_polynomial: opaque irreducible <1..2^8-1>;
            };
    };
    */
#ifdef DO_ECC_CRYPTO
    union
    {
        MPI p_;
        struct
        {
            ECBasisType basis;
            MPI *k;
        } character;
    } field;
    ECCurve curve;
    ECPoint base;
#endif // DO_ECC_CRYPTO
    /*
    opaque order <1..2^8-1>;
    opaque cofactor <1..2^8-1>;
    */
} ECParameters; /* var leng */
    
typedef uint8 ParameterIndex;
typedef enum {
    algo_rsa, algo_diffie_hellman, algo_elliptic_curve
} PublicKeyAlgorithm;
typedef struct
{
    uint16 length;
    /*
    select (PublicKeyAlgorithm) {
        case rsa: struct {};
        case diffie_hellman: DHParameters params;
        case elliptic_curve: ECParameters params;
    }
    */
    union
    {
        DHParameters dh_params;
        ECParameters ec_params;
    } params;
} ParameterSet; /* var leng */

typedef struct
{
    ParameterIndex parameter_index;     /* uint8 */
    /*
    select (parameter_index) {
        case 255: ParameterSet parameter_set;
        default: struct {};
    }
    */
    ParameterSet parameter_set;
} ParameterSpecifier;   /* var leng */

typedef enum {
    null=0, text, binary,
    key_hash_sha=254, x509_name=255
} IdentifierType;
typedef uint16 CharacterSet;

typedef struct
{
    IdentifierType identifier_type;
    /*
    select (identifier_type) {
        case null: struct {};
        case text:
            CharacterSet character_set;
            opaque name<1.. 2^8-1>;
        case binary: opaque identifier<1..2^8-1>;
        case key_hash_sha: opaque key_hash[20];
        case x509_name: opaque distinguished_name<1..2^8-1>;
    }
    */
} Identifier;           /* var leng */

typedef struct
{
    KeyExchangeSuite key_exchange_suite;        /* uint8, see Appendix A */
    /*
    ParameterSpecifier parameter_specifier;
    Identifier identifier;
    */
} KeyExchangeId;        /* var leng */

typedef struct
{
    BulkCipherAlgorithm bulk_cipher_algorithm;
    MACAlgorithm mac_algorithm;
} CipherSuite;          /* const leng: 2B */

typedef struct
{
    uint8 client_version;
    Random random;
    SessionID session_id;
    /*
    KeyExchangeId client_key_ids<0..2^16-1>;
    KeyExchangeId trusted_key_ids<0..2^16-1>;
    CipherSuite cipher_suites<2..2^8-1>;
    CompressionMethod compression_methods<1..2^8-1>;
    */
    SequenceNumberMode sequence_number_mode;
    uint8 key_refresh;
} ClientHello;  /* var leng */

typedef struct
{
    uint8 server_version;
    Random random;
    SessionID session_id;
    uint8 client_key_id;
    CipherSuite cipher_suite;
    CompressionMethod compression_method;
    SequenceNumberMode sequence_number_mode;
    uint8 key_refresh;
} ServerHello;  /* const leng: 32B */

typedef enum {
    WTLSCert=1, X509Cert, X968Cert,
    CertURL=4, cf_dummy=255
} CertificateFormat;

/*
opaque X509Certificate<1..2^16-1>;
opaque X968Certificate<1..2^16-1>;
*/
typedef enum {
    SA_ANONYMOUS=0, SA_ECDSA_SHA, SA_RSA_SHA, SA_ECDSA_MD5, SA_RSA_MD5,
    SA_DUMMY=255
} SignatureAlgorithm;
typedef enum {
    pkt_rsa=2, pkt_ecdh, pkt_ecdsa, pkt_dummy=255
} PublicKeyType;
#ifdef DO_ECC_CRYPTO
typedef struct
{
    length_t nbits;
    MPI pk[11];
} ECPublicKey;
typedef struct
{
    length_t nbits;
    MPI sk[12];
    // Note that ECPrivateKey can be cast into ECPublicKey, but not vice versa
} ECPrivateKey;
#endif // DO_ECC_CRYPTO

typedef struct
{
    /*
    opaque rsa_exponent<1..2^16-1>;
    opaque rsa_modulus<1..2^16-1>;
    */
    length_t nbits;
    byte *e;
    byte *m;
} RSAPublicKey; /* var leng */

typedef struct
{
    length_t nbits;
    byte *e;
    byte *m;

    /* Secrecy followed */
    byte *d;
    byte *p;
    byte *q;
    byte *u;
} RSAPrivateKey;


typedef struct
{
    length_t var_length;
    /*
    select (PublicKeyType) {
        case ecdh: ECPublicKey;
        case ecdsa: ECPublicKey;
        case rsa: RSAPublicKey;
    }
    */
#ifdef DO_ECC_CRYPTO
    union
    {
        ECPublicKey ecPublicKey;
        RSAPublicKey rsaPublicKey;
    } key;
#endif // DO_ECC_CRYPTO
} WTLS_PublicKey;       /* var leng */

typedef struct
{
    length_t var_length;
#ifdef DO_ECC_CRYPTO
    union
    {
        ECPrivateKey ecKey;
        RSAPrivateKey rsaKey;
    } key;
#endif // DO_ECC_CRYPTO
} WTLS_PrivateKey;      /* var leng */

typedef struct
{
    uint8 certificate_version;
    SignatureAlgorithm signature_algorithm;
    Identifier issuer;
    uint32 valid_not_before;
    uint32 valid_not_after;
    Identifier subject;
    PublicKeyType public_key_type;
    ParameterSpecifier parameter_specifier;
    WTLS_PublicKey public_key;
} ToBeSignedCertificate;        /* var leng */

/*
select( SignatureAlgorithm ) {
    case anonymous: { };
    case ecdsa_sha:
        struct digitally-signed {
            opaque sha_hash[20]; // SHA-1 hash of data to be signed
        }
    case rsa_sha:
        struct digitally-signed {
            opaque sha_hash[20]; // SHA-1 hash of data to be signed
        }
} Signature;
*/
typedef opaque Signature[20];   /* const leng: 20B */

typedef struct
{
    ToBeSignedCertificate to_be_signed_certificate;
    Signature signature;
} WTLSCertificate;      /* var leng */

typedef struct
{
    CertificateFormat certificate_format;
    /*
    select (certificate_format) {
        case WTLSCert: WTLSCertificate;
        case X509Cert: X509Certificate;
        case X968Cert: X968Certificate;
        case CertURL: opaque url<0..255>;
    }
    */
} Certificate;  /* var leng */

typedef struct
{
    /*
    Certificate certificate_list<0..2^16-1>;
    */
} Certificates; /* var leng */

typedef enum {
    rsa, rsa_anon, dh_anon, ecdh_anon, ecdh_ecdsa
} KeyExchangeAlgorithm;

typedef struct
{
    length_t var_length;
    /*
    opaque dh_Y<1..2^16-1>;
    */
} DHPublicKey;  /* var leng */

typedef struct
{
    ParameterSpecifier parameter_specifier;

    length_t var_length;
    /*
    select (KeyExchangeAlgorithm) {
        case rsa_anon: RSAPublicKey params;
        case dh_anon: DHPublicKey params;
        case ecdh_anon: ECPublicKey params;
    }
    */
} ServerKeyExchange;    /* var leng */

typedef struct
{
    length_t var_length;
    /*
    KeyExchangeId trusted_authorities<0..2^16-1>;
    */
} CertificateRequest;   /* var leng */

typedef struct { } ServerHelloDone;

typedef struct
{
    length_t var_length;
    /*
    select (KeyExchangeAlgorithm) {
        case rsa: RSAEncryptedSecret param;
        case rsa_anon: RSAEncryptedSecret param;
        case dh_anon: DHPublicKey param; // client public value
        case ecdh_anon: ECPublicKey param; // client public value
        case ecdh_ecdsa: ECPublicKey param; // client public value
    } exchange_keys;
    */
} ClientKeyExchange;    /* var leng */

typedef struct
{
    uint8 client_version;
    opaque random[19];
} Secret;               /* const leng: 20B */

typedef struct
{
    length_t var_length;
    /*
    public-key-encrypted Secret secret;
    RSAEncryptedSecret rsa_encrypted_secret;
    DHPublicKey dh_encrypted_secret;
    ECPublicKey ec_encrypted_secret;
    */
} EncryptedSecret;      /* var leng */

typedef struct { Signature signature; } CertificateVerify;
/* const leng: 20B */

typedef struct { opaque verify_data[12]; } Finished;
/* const leng: 12B */

/*****************************************************************
 * Global Macros
 *****************************************************************/
/* Appendix A */

/* for KeyExchangeSuite */
/* #define NULL                 0*/
#define SHARED_SECRET           1
#define DH_anon                 2
#define DH_anon_512             3
#define DH_anon_768             4
#define RSA_anon                5
#define RSA_anon_512            6
#define RSA_anon_768            7
#define RSA                     8
#define RSA_512                 9
#define RSA_768                 10
#define ECDH_anon               11
#define ECDH_anon_113           12
#define ECDH_anon_131           13
#define ECDH_ECDSA              14
#define ECDH_anon_uncomp        15
#define ECDH_anon_uncomp_113    16
#define ECDH_anon_uncomp_131    17
#define ECDH_ECDSA_uncomp       18

/* for BulkCipherAlgorithm */
/* #define NULL                 0 */
#define RC5_CBC_40              1
#define RC5_CBC_56              2
#define RC5_CBC                 3
#define DES_CBC_40              4
#define DES_CBC                 5
#define TripleDES_CBC_EDE       6
#define IDEA_CBC_40             7
#define IDEA_CBC_56             8
#define IDEA_CBC                9

/* for MACAlgorithm */
#define SHA_0                   0
#define SHA_40                  1
#define SHA_80                  2
#define SHA                     3
#define SHA_XOR_40              4
#define MD5_40                  5
#define MD5_80                  6
#define MD5                     7

/* for CompressionMethod */
/* #define NULL                 0*/

/*****************************************************************
 * Function Prototypes
 *****************************************************************/
void PRF(byte *res, length_t res_leng,
         byte *secret, length_t secret_leng,
         const byte *label, length_t label_leng,
         byte *seed, SecurityParameters *sp);
void compute_master_secret(byte *master_secret,
                           byte *pre_master_secret,
                           byte *client_random,
                           byte *server_random,
                           SecurityParameters *sp);
int assign_keysizes(SecurityParameters *sp);
void key_block(byte *cw_mac, byte *cw_key, byte *cw_iv,
               byte *sw_mac, byte *sw_key, byte *sw_iv,
               SecurityParameters *sp);

void uint16_encode(byte *result, uint16 in);
uint16 uint16_decode(byte *in);
void uint16_endian(byte *in);
void uint32_encode(byte *result, uint32 in);
uint32 uint32_decode(byte *in);
void uint32_endian(byte *in);
void uint64_encode(byte *result, uint64 in);
void uint64_decode(uint64 result, byte *in);
void uint64_endian(byte *in);
void lengtht_encode(byte *result, length_t in);
length_t lengtht_decode(byte *in);
void lengtht_endian(byte *in);

length_t WTLSText_encode(byte *result,
                       int flag,
                       ContentType content_type,
                       SequenceNumberIndication seq_ind,
                       uint16 sequence_number,
                       uint16 length,
                       byte *fragment);
void WTLSText_TCP_encode(byte *result,
                         int flag,
                         ContentType content_type,
                         uint16 length);
void WTLSText_UDP_encode(byte *result,
                         int flag,
                         ContentType content_type,
                         uint16 sequence_number,
                         uint16 length);
length_t Handshake_encode(byte *result, HandshakeType msg_type,
                        uint16 length, byte *body);
length_t ParameterSet_encode(byte *result, length_t length, byte *params);
void ParameterSet_decode(byte *result,
                         byte **input, PublicKeyAlgorithm algo);
length_t ParameterSpecifier_encode(byte *result,
                                 ParameterIndex parameter_index,
                                 byte *parameter_set);
void ParameterSpecifier_decode(byte *result,
                               byte **input, PublicKeyAlgorithm algo);
length_t Identifier_encode(byte *result,
                         IdentifierType identifier_type,
                         CharacterSet character_set,    /* for text */
                         length_t leng,
                         byte *name,
                         byte *identifier,          /* for binary */
                         byte *key_hash,            /* for key_hash_sha */
                         byte *distinguished_name); /* for x509_name */
void Identifier_decode(byte *result, byte **input);
length_t KeyExchangeId_encode(byte *result,
                            KeyExchangeSuite key_exchange_suite,
                            byte *para_spec, byte *identifier);
void KeyExchangeId_decode(KeyExchangeSuite *suite,
                          byte *parameter_specifier,
                          byte *identifier,
                          byte **input);
length_t ToBeSignedCert_encode(byte *result,
                             uint8 cert_version,
                             SignatureAlgorithm signature_algorithm,
                             byte *issuer,
                             uint32 valid_not_before,
                             uint32 valid_not_after,
                             byte *subject,
                             PublicKeyType public_key_type,
                             byte *para_spec,
                             byte *public_key);
int ToBeSignedCert_decode(SignatureAlgorithm *sigalgo,
                          byte *issuer,         /* Identifier */
                          byte *subject,        /* Identifier */
                          RSAPublicKey *pk,
                          byte **input);
length_t RSAPublicKey_encode(byte *result, RSAPublicKey *pk);
void RSAPublicKey_decode(byte **input, RSAPublicKey *pk);
length_t WTLSCertificate_encode(byte *result,
                              byte *to_be_signed_cert,
                              byte *signature);


void send_handshake_msg(int sock,
                        HandshakeType msg_type, byte *body, length_t sz);
int recv_handshake_msg(int sock,
                       HandshakeType *msg_type, byte **body, length_t *leng);
length_t AssembleCompactCertificate(byte *res,
                                  char *id,
                                  length_t idLength, // in bytes
#ifdef DO_ECC_CRYPTO
                                  MPI *pubKey,
#endif // DO_ECC_CRYPTO
                                  length_t keyBitLength, // in bits
                                  uint32 tstart,
                                  uint32 tend);
void DeassembleCompactCertificate(byte *cert,
                                  char *id,     // placeholder
                                  length_t *idLength,// in bytes
#ifdef DO_ECC_CRYPTO
                                  MPI *pubKey,  // placeholder, initialized
#endif // DO_ECC_CRYPTO
                                  length_t *keyBitLength, // in bits
                                  uint32 *tstart,       // placeholder
                                  uint32 *tend);
length_t CompactCertificateLength(byte *cert);
void PrintCompactCertificate(FILE *out, byte *cert);
void SignCertificate(byte *plaincert,
                     length_t plaincert_leng,
                     byte *signature,
                     length_t *signature_leng,
                     SignatureAlgorithm sigalgo,
                     WTLS_PrivateKey *caSK);
int VerifyCertificate(byte *plaincert,
                      length_t plaincert_leng,
                      byte *signature,
                      length_t signature_leng,
                      SignatureAlgorithm sigalgo,
                      WTLS_PublicKey *caPK);

void generate_RSA_PK_SK_pair(unsigned nbits,
                             RSAPublicKey *PK,
                             RSAPrivateKey *SK);
int RSA_PK_crypt(byte *res, length_t *res_leng,
                 byte *src, length_t src_leng,
                 RSAPublicKey *pk, int flag);
int RSA_SK_crypt(byte *res, length_t *res_leng,
                 byte *src, length_t src_leng,
                 RSAPrivateKey *sk, int flag);

/*****************************************************************
 * External Variables
 *****************************************************************/
extern const byte *client_finish_label, *server_finish_label;
extern const byte *client_expansion_label, *server_expansion_label;
extern const byte *client_exportkey_label, *server_exportkey_label;
extern const byte *client_exportiv_label, *server_exportiv_label;

extern byte *RSA_parameter_specifier;
extern byte *RSA_identifier;
extern byte *issuer, *subject;
extern length_t num_trusted_key_ids;
extern byte *trusted_key_ids[];/*each prepended length_t leng*/
extern KeyExchangeSuite trusted_key_suites[];

/* Programming idiosyncrasies */
#define FREE_TCP_MSG(msg)       free(msg-3)
#define FREE_UDP_MSG(msg)       free(msg-5)

#endif // NETIA_WLTS_H
