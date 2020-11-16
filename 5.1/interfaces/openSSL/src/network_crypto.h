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



#ifndef NETSEC_CRYPTO_H
#define NETSEC_CRYPTO_H
#ifdef OPENSSL_LIB
#include <openssl/ssl.h>

// for encryption algorithms
#include <openssl/des.h>
#include <openssl/idea.h>
#include <openssl/blowfish.h>
#include <openssl/cast.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rc2.h>
#include <openssl/rsa.h>

// for digest/hash
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/mdc2.h>
#include <openssl/ripemd.h>
#endif

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
    int ivLength);
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
    int ivLength);
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
    int ivLength);

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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    int ivLength);
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
    char* cipherName);
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
    char* cipherName);
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
    int ivLength);
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
    int ivLength);

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
    char* authAlgo);
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
    char* authAlgo);
#define NONCE_SIZE 4
#endif
