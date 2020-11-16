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



#ifndef NETSEC_PKI_H
#define NETSEC_PKI_H

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <openssl/pem.h>

#include <openssl/pkcs12.h>
#include <openssl/err.h>

#include <openssl/conf.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/ossl_typ.h>
//#undef X509_NAME
#include <openssl/x509v3.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "network_pki_header.h"

#define SUBJECT_DETAIL  1
#define ISSUER_DETAIL   2

using namespace std;

struct PKIData
{
    map<string, X509CertificateDetails*> *sharedCertificate;
    map<string, X509CertificateDetails*> *certificateList;
};

// Constants for Certificate Extentions
#define Extension_For_Basic_Constraints "critical,CA:TRUE"
#define Extension_For_Key_Usage "critical,keyCertSign,cRLSign"
#define Extension_For_Subject_Key_Identifier "hash"
#define Extension_For_Netscape_Cert_Type "sslCA"
#define Extension_For_Netscape_Comment "example comment extension"

// Constants for Method X509_NAME_add_entry_by_txt
#define PKI_COMMON_NAME "CN"
#define PKI_COUNTRY "C"
#define PKI_LOCATION "L"
#define PKI_STATE "ST"
#define PKI_ORGANIZATION "O"
#define PKI_ORG_UNIT "OU"
#define PKI_EMAIL_ADDR "emailAddress"

#define PKI_RSA_KEY_LENGTH 1024

// /**
// API        :: PKISignPacket
// LAYER      :: Network
// PURPOSE    :: To sign the packet. Packet is signed with self private key,
//               but can only be verified by its pulblic key
// PARAMETERS ::
// + inPacket:  char* : packet to be signed
// + inputPacketLength :  int : length of packet to be signed
// + privateKey:  EVP_PKEY* : OpenSSL privtate key pointer
// + outPacketLength:  unsigned int* : length of signed packet will
//                                     be returned
// RETURN     :: unsigned char* : Pointer to signed packet
// **/
unsigned char* PKISignPacket(
    char* inPacket,
    int inputPacketLength,
    EVP_PKEY* privateKey,
    unsigned int* outPacketLength);

// /**
// API        :: PKIEncryptPacket
// LAYER      :: Network
// PURPOSE    :: To encrypt the packet.
// PARAMETERS ::
// + inPacket:  char* : input packet which need to encrypt
// + inputPacketLength :  int : packet length which need to encrypt
// + certificateDetails:  X509* :  OpenSSL certificate pointer
// + outPacketLength :  int* :  encrypted packet length
// RETURN     :: char* : encrypted packet
// **/
char* PKIEncryptPacket(
    char* inPacket,
    int inputPacketLength,
    X509* certificateDetails,
    int* outPacketLength);

// /**
// API        :: PKIDecryptPacket
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet.
// PARAMETERS ::
// + inPacket:  char* : input packet which need to decrypt
// + inPacketSize :  int : packet length which need to decrypt
// + certificateDetails:  X509* :  certificate pointer
// + privateKey :  EVP_PKEY* :  private key to decrypt the packet
// + outPacketSize :  int* :  packet length of decrypted Packet
// RETURN     :: char* : decrypted packet
// **/
char* PKIDecryptPacket(
    char* inPacket,
    int inPacketSize,
    X509* certificateDetails,
    EVP_PKEY* privateKey,
    int* outPacketLength);

// /**
// API        :: PKIDecryptPacketInMessage
// LAYER      :: Network
// PURPOSE    :: To decrypt the packet in Message.
// PARAMETERS ::
// + node:  Node* : node which is allocating the space
// + msg:  Message* : message which need to decrypt
// + crtDetails:  X509* :  certificate pointer
// + privateKey :  EVP_PKEY* :  private key to decrypt the packet
// RETURN     :: BOOL : true if message is decrypted successfully
// **/
BOOL PKIDecryptPacketInMessage(
    Node* node,
    Message* msg,
    X509* crtDetails,
    EVP_PKEY* privateKey);

// /**
// API       :: PKIPacketRealloc
// LAYER     :: ANY LAYER
// PURPOSE   :: To allocate new space for the packet
//              and return the payload with the new packet. It is mandatory
//              that the packet should be Non null while calling this
//              function. The previous packet content would be retained in
//              the newly allocated packet.
// PARAMETERS::
// + node    : Node* : node which is assembling the packet
// + msg: Message*  : message to reallocate
// + newPacketSize: int  : new packet size
// RETURN    :: void
// **/
void PKIPacketRealloc(Node* node,
                      Message* msg,
                      int newPacketSize);

#endif
