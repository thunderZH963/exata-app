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

#ifndef NETIA_SECURE_NEIGHBOR_H
#define NETIA_SECURE_NEIGHBOR_H

#include "crypto.h"

#define SECURENEIGHBOR_BROADCAST_JITTER         10 //MILLI_SECOND
#define SECURENEIGHBOR_DEFAULT_TTL_MAX          1
#define SECURENEIGHBOR_NONCE_LENGTH             16 // 128 bits = 16 bytes

#define SECURENEIGHBOR_DEFAULT_TIMEOUT  5000 //MILLI_SECOND
#define SECURENEIGHBOR_TIMEOUT  (secureneighbor->neighborTimeout)

// SND Packet Types
#define SND_DUMMY               0   // dummy
#define SND_HELLO               1   // periodic HELLO
#define SND_CERTIFIED_HELLO     2   // certified HELLO
#define SND_CHALLENGE           3   // CHALLENGE
#define SND_CERTIFIED_CHALLENGE 4   // certified CHALLENGE
#define SND_RESPONSE1           5   // RESPONSE1
#define SND_RESPONSE2           6   // RESPONSE2

// The SND-HELLO broadcast packet:
// it will incur authentication and key-agreement rounds
typedef struct
{
    unsigned char type; // SND_HELLO
} SecureneighborHelloPacket;

typedef struct
{
    unsigned char type; // SND_CERTIFIED_HELLO
    // Here we use the ISAKMP certificate payload format:
    // see Page 32 of RFC2408.
    char nextPayload;   // 0 in the secure neighbor protocol, no next payload
    char reserved;      // dummy
    short payloadLength;        // how long is the certificate
    // indicates the type of certificate,
    // 0: NONE in ISAKMP
    // (but indeed it is QualNet's WTLS compact certificate)
    char certEncoding;
    byte certificateData[QUALNET_MAX_CERTIFICATE_LENGTH];
    // certified HELLO packet itself is authenticated with digital signature
    byte signature[QUALNET_MAX_DIGITALSIGNATURE_LENGTH];
} SecureneighborCertifiedHelloPacket;

typedef struct
{
    unsigned char type; // SND_CHALLENGE
    byte challenge[SECURENEIGHBOR_NONCE_LENGTH];  // the encrypted nonce n1
} SecureneighborChallengePacket;

typedef struct
{
    unsigned char type; // SND_CERTIFIED_CHALLENGE
    // certified CHALLENGE length is determined as below:
    // 1. 4 bytes: 32-bit IP address as my ID
    // 2. QUALNET_ECC_PUBLIC_KEY(192): my public key length (in bytes)
    // 3. 4 bytes: starting valid time
    // 4. 4 bytes: ending valid time
    //
    // 5. encrypted nonce using the HELLO initiator's public key,
    //    which is of a public key length.
    byte challenge[(4 + QUALNET_ECC_PUBLIC_KEYLENG(QUALNET_ECC_KEYLENGTH)
                    + 4 + 4)
                   + QUALNET_ECC_PUBLIC_KEYLENG(QUALNET_ECC_KEYLENGTH)];
    // certified CHALLENGE packet itself
    // is authenticated with digital signature
    byte signature[QUALNET_MAX_DIGITALSIGNATURE_LENGTH];
} SecureneighborCertifiedChallengePacket; // Using public key cryptosystems

typedef struct
{
    unsigned char type; // SND_RESPONSE1
    byte nonce[SECURENEIGHBOR_NONCE_LENGTH];    // 2nd nonce n2
    byte response[SECURENEIGHBOR_NONCE_LENGTH]; // encrypted response
} SecureneighborResponse1Packet;

typedef struct
{
    unsigned char type; // SND_RESPONSE2
    byte nonce[SECURENEIGHBOR_NONCE_LENGTH];    // 3rd nonce n3
    byte response[SECURENEIGHBOR_NONCE_LENGTH]; // encrypted response
} SecureneighborResponse2Packet;

typedef struct
{
    char packetType;
    NodeAddress srcAddr; // the sender to which I will reply
    int interfaceIndex;  // incoming interface
    int ttl;             // In current 1-hop neighborhood, ttl is not used
} SecureneighborCryptoOverheadType;

typedef struct struct_sn_entry
{
    NodeAddress neighborAddr;
    int ttl;

    // The interface through which HELLO comes in
    int intf;

    // The expire moment of the neigbhor entry
    clocktype expireTime;

    byte certificate[MAX_STRING_LENGTH];

    struct struct_sn_entry *next;
} SecureneighborEntry;

typedef struct
{
    SecureneighborEntry* head;
    int   size;
} SecureneighborTable;

typedef struct
{
    unsigned int numHelloSent;
    unsigned int numHelloRecved;
    unsigned int numChallengeSent;
    unsigned int numChallengeRecved;
    unsigned int numResponse1Sent;
    unsigned int numResponse1Recved;
    unsigned int numResponse2Sent;
    unsigned int numResponse2Recved;

    unsigned int numHelloSentByte;
    unsigned int numHelloRecvedByte;
    unsigned int numChallengeSentByte;
    unsigned int numChallengeRecvedByte;
    unsigned int numResponse1SentByte;
    unsigned int numResponse1RecvedByte;
    unsigned int numResponse2SentByte;
    unsigned int numResponse2RecvedByte;
} SecureneighborStats;

typedef struct struct_sn_handshaking
{
    NodeAddress neighborAddr;

    // In case of multiple interfaces
    NodeAddress myAddr;

    // The starting time when the HELLO is received
    clocktype startTime;

    // TRUE: 2-way handshake; FALSE: 3-way handshake
    BOOL withoutResponse2;

    // 0: CHALLENGE already sent, waiting for RESPONSE1;
    // 1: RESPONSE1 already sent, waiting for RESPONSE2
    int state;

    struct struct_sn_handshaking *next;
} SecureneighborHandshakingList;

typedef struct
{
    // (per-node) Secure neighborhood maintenance:
    //
    // Every node periodically maintains an authenticated neighbor snapshot.
    // In other words, every node must prove its identity to its neighbors.
    // Any unauthenticated node is ignored above the physical layer by its
    // neighbors.
    //
    // Authentication is implemented on nonce-based challenge-response
    // where the nonce is encrypted by the prover's CERTIFIED public key.
    SecureneighborTable neighbors;
    clocktype neighborTimeout;
    int ttlMax;  // currently = 1
    BOOL doCertifiedHello;
    SecureneighborHandshakingList *handshaking;

    SecureneighborStats stats;

    RandomSeed seed; // for random broadcast jitter
} SecureneighborData;

void SecureneighborInit(
    Node *node,
    const NodeInput *nodeInput);

void SecureneighborFinalize(Node *node);

void SecureneighborHandleProtocolPacket(
    Node *node,
    Message *msg,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    int ttl,
    int interfaceIndex);

void SecureneighborHandleProtocolEvent(
    Node *node,
    Message *msg);

#endif // NETIA_SECURENEIGHBOR_H

