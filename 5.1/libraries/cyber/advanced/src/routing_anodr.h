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

#ifndef ANODR_H
#define ANODR_H

//---------------------------------------------------
// ASR (Anonymous Secure Routing) protocol is a variant of ANODR.
//
// @inproceedings{ZhuWKBD04,
//    author = {Bo Zhu and Zhiguo Wan and Mohan S. Kankanhalli and Feng Bao
//             and Robert H. Deng},
//    title = {{Anonymous Secure Routing in Mobile Ad-Hoc Networks}},
//    booktitle = {29th IEEE International Conference on Local
//                 Computer Networks (LCN'04)},
//    pages = {102-108},
//    year = {2004}}
//-----------------------------------------------------
// Search the string "#ifdef ASR_PROTOCOL" in anodr.cpp for differences.
// ASR uses one-time pad, while ANODR uses AES.
// This means ASR uses onion key (one-time only) per RREQ flood,
//      while ANODR uses per-node onion key (an AES key) during the node's
//      entire network lifetime.
// This is the major protocol-wise difference between ANODR and ASR.
//
// Uncomment the line below (make clean and make) to simulate ASR in QualNet.
// #define ASR_PROTOCOL

#include "crypto.h"

typedef struct struct_network_anodr_str AnodrData;

class D_AnodrPrint : public D_Command
{
    private:
        AnodrData *anodr;

    public:
        D_AnodrPrint(AnodrData *newAnodr) { anodr = newAnodr; }

        virtual void ExecuteAsString(const char *in, char *out);
};

#define ANODR_INVALID_PSEUDONYM  ((byte *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
#define isInvalid128Bit(x) (!memcmp(x, ANODR_INVALID_PSEUDONYM, 128/8))
#define ANODR_BROADCAST_PSEUDONYM \
((byte *)"\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377\377")
// 128-bit long source tag, can be any 128-bit long well-known message
#define ANODR_SRC_TAG     ((byte *)"I am the source ")
// 128-bit long destination tag, can be any 128-bit long well-known message
#define ANODR_DEST_TAG    ((byte *)"You are the dest")
#define ANODR_TEST_VECTOR ((byte *)"1234567890ABCDEF")

#define ANONYMOUS_IP    0xfffffffe

// Notation:
//
// {M}_{PK} means using public key PK to encrypt message M.
// K(M)     means using symmetric key K to encrypt message M.

#define AES_BLOCKLENGTH 128
#define ANODR_AES_KEYLENGTH     AES_BLOCKLENGTH
#define ANODR_PSEUDONYM_LENGTH  AES_BLOCKLENGTH

// Similar to the 802.11 link layer unicast retransmission count.
// This is for unicast control packets RREP and RERR
#define ANODR_UNICAST_RETRANSMISSION_COUNT      8

// Anodr default timer and constant values ref:
// draft-ietf-manet-anodr-08.txt section: 12

#define ANODR_DEFAULT_ACTIVE_ROUTE_TIMEOUT      (5000 * MILLI_SECOND)
#define ANODR_DEFAULT_NET_DIAMETER              (35)
#define ANODR_DEFAULT_NODE_TRAVERSAL_TIME       (40 * MILLI_SECOND)
#define ANODR_DEFAULT_ONION_PROCESSING_TIME     (AES_DEFAULT_DELAY)
#define ANODR_DEFAULT_RREQ_RETRIES              (2)
#define ANODR_DEFAULT_ROUTE_DELETE_CONST        (5)
#define ANODR_DEFAULT_MESSAGE_BUFFER_IN_PKT     (100)
#define ANODR_ACTIVE_ROUTE_TIMEOUT              (anodr->activeRouteTimeout)
#define ANODR_DEFAULT_MY_ROUTE_TIMEOUT   (2 * ANODR_ACTIVE_ROUTE_TIMEOUT)
#define ANODR_NET_DIAMETER              (anodr->netDiameter)
#define ANODR_NODE_TRAVERSAL_TIME       (anodr->nodeTraversalTime)
#define ANODR_RREQ_RETRIES              (anodr->rreqRetries)
#define ANODR_ROUTE_DELETE_CONST        (anodr->rtDeletionConstant)
#define ANODR_MY_ROUTE_TIMEOUT          (anodr->myRouteTimeout)
#define ANODR_NEXT_HOP_WAIT             (ANODR_NODE_TRAVERSAL_TIME + 10)

// This is what is stated in the ANODR spec for Net Traversal Time.
#define ANODR_NET_TRAVERSAL_TIME_NEW \
                (2 * ANODR_NODE_TRAVERSAL_TIME * ANODR_NET_DIAMETER)

#define ANODR_NET_TRAVERSAL_TIME \
                (3 * ANODR_NODE_TRAVERSAL_TIME * ANODR_NET_DIAMETER / 2)

#define ANODR_FLOOD_RECORD_TIME  (3 * ANODR_NET_TRAVERSAL_TIME)

#define ANODR_DELETE_PERIOD \
                (ANODR_ROUTE_DELETE_CONST * ANODR_ACTIVE_ROUTE_TIMEOUT)
#define ANODR_REV_ROUTE_LIFE            (ANODR_NET_TRAVERSAL_TIME)

#define ANODR_BROADCAST_JITTER          (10 * MILLI_SECOND)

// Performance Issue
#define ANODR_MEM_UNIT                     100
#define ANODR_SENT_HASH_TABLE_SIZE        20

// Anodr Packet Types
#define ANODR_DUMMY             0   // dummy
#define ANODR_RREQ              1   // route request packet type
#define ANODR_RREQ_SYMKEY       2   // route request packet with global
                                    // trapdoor encrypted in symmetric key
#define ANODR_RREP              3   // route reply packet type
#define ANODR_RERR              4   // route error packet type
#define ANODR_RREP_AACK         5   // anonymous ack to RREP unicast packets
#define ANODR_RERR_AACK         6   // anonymous ack to RERR unicast packets
#define ANODR_DATA_AACK         7   // anonymous data messages

// ANODR's trapdoor boomerang onion(TBO) is uniformly 128-bit long
#define ANODR_LOCALTRAPDOOR_LENGTH AES_BLOCKLENGTH

// ANODR's route pseudonym: 128-bit
// Also ANODR's per-hop Local Trapdoor:
//      128-bit TBO - Trapdoored Boomerang Onion
typedef struct
{
    byte bits[b2B(ANODR_PSEUDONYM_LENGTH)];
} AnodrPseudonym;
#define AnodrOnion      AnodrPseudonym

// ANODR's global trapdoor from source A to destination E is:
// {DEST_TAG, K_reveal, K_AE, optional_srcAddr}_{PK_E}, K_reveal(DEST_TAG)
//
// For GPG's ECC encryption:
// 1,2,3. R.x R.y R.z: In 192-bit ECC, each one is 192 bits,
//                     thus 3*192 = 576 bits
// 4. 512-bit plaintext: DEST_TAG, K_reveal, K_AE, optional_srcAddr.
//    The AES ciphertext C is also 512 bits.
// Thus the ECC ciphertext is totally 576 + 512 = 1088 bits = 136 bytes.
// Plus 128-bit trapdoor commitment K_reveal(DEST_TAG),
// totally 1216 bits = 152 bytes.

#define ANODR_GLOBALTRAPDOOR_LENGTH \
                (QUALNET_ECC_BLOCKLENGTH(4*AES_BLOCKLENGTH)+AES_BLOCKLENGTH)

// ANODR's Global Trapdoor:
// Suppose the source is node A, the destination is node E.
// "tr_dest =
// {DEST_TAG,K_reveal,K_AE,optional_srcAddr}_{PK_E}, K_reveal(DEST_TAG)"
// |128-bit  128-bit  128-bit    128-bit     |            128-bit
// |  1088 bits in ECC ciphertext |
// where K(M) means using symmetric key K to encrypt message M in AES,
// {M}_{PK} means using public key PK to encrypt message M in ECAES,
// and "," simply means concatenation.
// K_AE is the to-be-shared symmetric key between A and E used later.
// K_reveal is a nonce key for the purpose of trapdoor commitment.
// optional_srcAddr: For TCP traffic, this holds the source's IP address;
//                   Otherwise, for UDP traffic, this field is not needed.
//
// For new contacts, the global trapdoor is 1216 bits long.
typedef struct
{
    union
    {
        // "DEST_TAG, K_reveal, K_AE,optional_srcAddr":
        // 4*128 = 512 bits in plaintext.
        byte plaintext[b2B(4*AES_BLOCKLENGTH)];
        // "{DEST_TAG,K_reveal,K_AE,optional_srcAddr}_{PK_E}" encrypted in
        // destination E's ECC public key PK_E:
        // 512 + 3*192 = 1088 bits long in ECC ciphertext.
        byte ciphertext[b2B(QUALNET_ECC_BLOCKLENGTH(4*AES_BLOCKLENGTH))];
    } bits;

    // the commitment "K_{reveal}(DEST_TAG)"
    byte commitment[b2B(AES_BLOCKLENGTH)];
} AnodrGlobalTrapdoor;

// Symmetric key based global trapdoor for RREQ floods with established K_AE
// For 2nd contacts and later, the global trapdoor is
// 384-bit ciphertext + 128-bit commitment = 512 bits long.
typedef struct
{
    union
    {
        // "DEST_TAG, K_reveal, optional_srcAddr":
        // 3*128 = 384 bits in plaintext.
        byte plaintext[b2B(3*AES_BLOCKLENGTH)];
        // "K_AE(DEST_TAG, K_reveal)" encrypted by the shared
        // symmetric key K_AE
        byte ciphertext[b2B(3*AES_BLOCKLENGTH)];
    } bits;

    // the commitment "K_reveal(DEST_TAG)"
    byte commitment[b2B(AES_BLOCKLENGTH)];
} AnodrGlobalTrapdoorSymKey;

//------------------------
// ANODR packet structures
//------------------------

// ANODR route request message format
// See page 70, page 94 and page 96 of Jiejun Kong's Ph.D. dissertation.
//
// Assuming we are using 192-bit ECC and 128-bit Pseudonym,
// ANODR's RREQ packets (for 1st-time contact) are of a uniform length
// 8 + 1216 + 128 + 3*192 = 1928 bits = 241 bytes
typedef struct
{
    unsigned char  type;  // ANODR_RREQ for request

    // seqNum = globalTrapdoor (encrypted in ECC)
    AnodrGlobalTrapdoor globalTrapdoor;

    // TBO: the Trapdoored Boomerang Onion
    AnodrOnion  onion;

    // pk_onetime, only comprised of Q.x Q.y Q.z in ECC
    byte onetimePubKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
} AnodrRreqPacket;

// Symmetric key based RREQ packet for RREQ floods with established K_AE
typedef struct
{
    unsigned char  type;  // ANODR_RREQ_SYMKEY for request

    // seqNum = globalTrapdoor (encrypted in AES)
    AnodrGlobalTrapdoorSymKey globalTrapdoor;

    // TBO: the Trapdoored Boomerang Onion
    AnodrOnion  onion;

    // pk_onetime, only comprised of Q.x Q.y Q.z in ECC
    byte onetimePubKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
} AnodrRreqSymKeyPacket;

// ANODR route reply message format
// See page 75, page 94 and page 96 of Jiejun Kong's Ph.D. dissertation
//
// Assuming we are using 192-bit ECC and 128-bit Pseudonym,
// ECC encryption of the 128-bit pseudonym is of 128+576=704 bits.
// Thus ANODR's RREP packets are of a uniform length
// 8 + 704 + 128 + 128 = 968 bits = 121 bytes
typedef struct
{
    unsigned char type; // ANODR_RREP for reply

    union
    {
        // 128 bits plaintext
        // nym.pseudonym is unencrypted route pseudonym (i.e., in plaintext)
        AnodrPseudonym pseudonym;

        // 128+576 = 704 bits ECC ciphertext
        // this is nym.pseudonym encrypted by pk_{upstream} (using ECC)
        // pk_{upstream} is the one-time public key of the intended receiver
        // of the RREP packet).  Later this pseudonym functions as
        // a per-hop seed key K_seed.
      byte encryptedPseudonym[b2B(QUALNET_ECC_BLOCKLENGTH(AES_BLOCKLENGTH))];
    } nym;

    // 256-bit (pr_dest = K_reveal, TBO) encrypted by K_{seed} (using AES)
    union
    {
        struct
        {
            byte anonymousProof[b2B(AES_BLOCKLENGTH)];
            AnodrOnion  onion;
        } aesPlaintext;
        byte aesCiphertext[b2B(2*AES_BLOCKLENGTH)];
    } rrepPayload;

    //AnodrPseudonym test;
} AnodrRrepPacket;

//
// Assuming we are using 128-bit Pseudonym,
// ANODR's RRER, AACK packets are of a uniform length
// 8 + 128 = 129 bits = 17 bytes
//

// ANODR route error message format
// See page 77 of Jiejun Kong's Ph.D. dissertation
typedef struct
{
    unsigned char type;  //  ANODR_RERR for route error
    AnodrPseudonym pseudonym;  // Anonymous VCI
    // AnodrGlobalTrapdoor seqNum;  // This field is no longer needed
} AnodrRerrPacket;

// ANODR anonymous acknowledgement message format
typedef struct
{
    unsigned char type; // ANODR_CONTROL_AACK or ANODR_DATA_AACK
    AnodrPseudonym pseudonym;   // Anonymous VCI
} AnodrAackPacket;

//------------------------------------
// Anodr Routing table structure
//------------------------------------
// Anodr route entry of an anonymous virtual circuit of a connection
typedef struct str_anodr_route_table_row
{
    // This field is only meaningful at the source node or dest node
    NodeAddress remoteAddr;
    BOOL dest;

    // Table entries described in Jiejun Kong's Ph.D. dissertation.
    // Like the dissertation, here `input' and `output',
    //`upstream' and `downstream' are for the direction source ->destination.
    AnodrGlobalTrapdoorSymKey seqNum;   // seqNum = globalTrapdoor

    // onion_{old}, incoming RREQ TBO = outgoing RREP TBO
    AnodrOnion inputOnion;
#ifdef ASR_PROTOCOL
    // 128-bit TBO key.
    // In ANODR, this key is per-node based
    // (each node only has 1 such key to use in the entire network lifetime)
    // In ASR, this key is per-flood based
    // (each onion/RREQ flood must have a different such key: a one-time pad)
    AnodrOnion onionKey;
#endif // ASR_PROTOCOL
    // onion_{new}, outgoing RREQ TBO = incoming RREP TBO
    AnodrOnion outputOnion;

    // the commitment K_reveal(DEST_TAG)
    byte commitment[b2B(AES_BLOCKLENGTH)];
    // the committed K_reveal
    byte committed[b2B(AES_BLOCKLENGTH)];

    // pk_{upstream}, only need to know Q.x Q.y Q.z in ECC
    byte upstreamOnetimePublicKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
    // sk_{me}, only need to store Q.x Q.y Q.z in ECC
    byte myOnetimePublicKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];

    // Anonymous VCI towards the source
    AnodrPseudonym pseudonymUpstream;
    // Anonymous VCI towards the destination
    AnodrPseudonym pseudonymDownstream;

    // The interface through which inputOnion comes in during RREQ
    int inputInterface;
    // The interface through which outputOnion comes in during RREP
    int outputInterface;

    // The expire moment of the route entry
    clocktype          expireTime;
    // Whether the route is active, i.e., RREP ACKed
    BOOL               activated;
    // If as the destination, this is the corresponding end-to-end
    // symmetric key K_{AE} in the 1st RREQ packet's global trapdoor
    // encrypted by my ECC public key, which can only be decrypted and
    // know by me
    byte e2eKey[b2B(ANODR_AES_KEYLENGTH)];

    // UnRREPed RREQ retransmission count.
    int rreqRetry;
    // UnACKed unicast retransmission count.
    // Note that all unicast control flow follows the direction src <- dest
    // Note that all unicast data flow follows the direction src -> dest
    int unicastRrepRetry;
    int unicastRerrRetry;
    int unicastDataRetry;

    struct str_anodr_route_table_row* next;
    struct str_anodr_route_table_row* prev;
} AnodrRouteEntry;

typedef struct
{
    AnodrRouteEntry* head;
    int   size;
} AnodrRoutingTable;

//
// Structure to store packets temporarily until one route to the destination
// of the packet is found or the packets are timed out to find a route
//
typedef struct str_anodr_fifo_buffer
{
    NodeAddress destAddr;       // Destination address of the packet
    AnodrPseudonym pseudonym;   // If not null, need to store and query this
    Message *msg;               // The packet to be sent
    struct str_anodr_fifo_buffer *next; // Pointer to the next message.
} AnodrBufferNode;

// Link list for message buffer
typedef struct
{
    AnodrBufferNode *head;
    int size;                   // buffer size in # of packets
    int numByte;                // buffer size in # of bytes
} AnodrMessageBuffer;

#if 0
// Structure to store information about messages for which RREQ has been sent
// These information are necessary until a route is found for the destination

typedef struct str_anodr_sent_node
{
    NodeAddress destAddr;  // Destination for which the RREQ has been sent
    int ttl;               // Last used TTL to find the route
    int times;             // Number of times RREQ has been sent
    struct str_anodr_sent_node* hashNext;
} AnodrRreqSentNode;

// structure for Sent node entries
typedef struct
{
    AnodrRreqSentNode* sentHashTable[ANODR_SENT_HASH_TABLE_SIZE];
    int size;
} AnodrRreqSentTable;
#endif

// Memory Pool
typedef struct str_anodr_mem_poll
{
    AnodrRouteEntry routeEntry ;
    struct str_anodr_mem_poll* next;
} AnodrMemPollEntry;

// Structure to store the statistical informations of Anodr
typedef struct
{
    D_UInt32 numRequestInitiated;
    UInt32 numRequestResent;
    UInt32 numRequestRelayed;

    UInt32 numRequestRecved;
    UInt32 numRequestDuplicate;
    UInt32 numRequestRecvedAsDest;
    UInt32 numRequestRecvedAsDestWithSymKeyGlobalTrapdoor;

    UInt32 numReplyInitiatedAsDest;
    UInt32 numReplyForwarded;
    UInt32 numReplyAcked;
    UInt32 numReplyRecved;
    UInt32 numReplyRecvedAsSource;

    UInt32 numRerrInitiated;
    UInt32 numRerrForwarded;
    UInt32 numRerrAcked;
    UInt32 numRerrRecved;

    UInt32 numDataInitiated;
    UInt32 numDataForwarded;

    UInt32 numDataRecved;
    UInt32 numDataDroppedForNoRoute;
    UInt32 numDataDroppedForOverlimit;

    UInt32 numReplyAackRecved;
    UInt32 numRerrAackRecved;
    UInt32 numDataAackRecved;

    UInt32 numBrokenLinks;
} AnodrStats;

// Anodr main structure to storee all necessary informations for Anodr
typedef struct struct_network_anodr_str
{
#ifndef ASR_PROTOCOL
    // 128-bit TBO key.
    // In ANODR, this key is per-node based
    // (each node only has 1 such key to use in the entire network lifetime)
    AnodrOnion onionKey;
#endif // ASR_PROTOCOL

    // set of user configurable parameters
    int          netDiameter;
    clocktype    nodeTraversalTime;
    clocktype    nodeOnionProcessingTime;
    clocktype    myRouteTimeout;
    clocktype    activeRouteTimeout;
    int          rreqRetries;
    int          rtDeletionConstant;

    // set of anodr protocol dependent parameters
    AnodrRoutingTable routeTable;
    AnodrMessageBuffer msgBuffer;
    NodeAddress e2eNym;  // This pseudonym is for the destination

    int               bufferSizeInNumPacket;
    int               bufferSizeInByte;

    AnodrStats stats;
    BOOL statsCollected;
    BOOL statsPrinted;
    BOOL processAck;
    BOOL biDirectionalConn;
    int  ttlStart;
    int  ttlIncrement;
    int  ttlMax;
    clocktype lastBroadcastSent;

    // Performance Issue
    AnodrMemPollEntry* freeList;

    BOOL isExpireTimerSet;
    BOOL isDeleteTimerSet;

    // TRUE: do real crypto in the headers; FALSE: just simulate
    BOOL doCrypto;

    // TRUE: do RREP AACK; FALSE: don't
    BOOL doRrepAack;
#ifdef DO_ECC_CRYPTO
    // Elliptic Curve Cryptosystem keys
    // [0] E.p
    // [1] E.a
    // [2] E.b
    // [3] E.G.x
    // [4] E.G.y
    // [5] E.G.z
    // [6] E.n
    // [7] Q.x
    // [8] Q.y
    // [9] Q.z
    // [10] d
    // From [0] to [9] is public, [10] is secret
    // I added placeholder [11] for the random nonce k (for future signing)
    MPI eccKey[12];
#endif // DO_ECC_CRYPTO
    // for destination's pk
    byte destPubKey[b2B(3*QUALNET_ECC_KEYLENGTH)];

    // debug purpose
    unsigned int sendCounter, recvCounter;

    // for MAC broadcast jitter
    RandomSeed jitterSeed;
    // for route pseudonyms & onions;
    RandomSeed nymSeed;
#ifdef DO_ECC_CRYPTO
    // ECC seeds can be truly random.  The variance in the value
    // should not change crypto behavior (& ANODR protocol behavior)
    RandomSeed eccSeed;
#endif // DO_ECC_CRYPTO
} AnodrData;

typedef struct
{
    char packetType;    // RREQ or RREP
    int interfaceIndex; // incoming interface
    int ttl;            // In ANODR, ttl is not used
} AnodrCryptoOverheadType;

void AnodrInit(
    Node *node,
    AnodrData **anodrPtr,
    const NodeInput *nodeInput,
    int interfaceIndex);

void AnodrFinalize(Node *node);

void AnodrRouterFunction(
    Node *node,
    Message *msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL *packetWasRouted);

void
AnodrMacLayerStatusHandler(
    Node *node,
    const Message* msg,
    const NodeAddress nextHopAddress,
    const int incommingInterfaceIndex);

void AnodrHandleProtocolPacket(
    Node *node,
    Message *msg,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    int ttl,
    int interfaceIndex);

void
AnodrHandleProtocolEvent(
    Node *node,
    Message *msg);

BOOL
IsMyAnodrDataPacket(Node *node, Message* msg);

BOOL
IsMyAnodrUnicastControlFrame(Node *node, Message* msg,MAC_PROTOCOL protocol);

BOOL
IsMyAnodrForwardDataFrame(Node *node, Message* msg, MAC_PROTOCOL protocol);

BOOL
IsMyAnodrBroadcastFrame(Node *node, Message* msg, MAC_PROTOCOL protocol);
#endif
