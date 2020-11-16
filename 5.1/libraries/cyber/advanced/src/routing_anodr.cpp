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

// Note: Timeout and some system parameters are borrowed from
// draft-ietf-manet-aodv-08.txt

#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "network_ip.h"
#include "routing_anodr.h"
#include "buffer.h"

// If defined, RREQ floods that are not the 1st-time contact towards 'dest'
// would use short RREQ packets.  This is an optimization.
// Thus the featured ANODR simulation result will be changed.
#define DO_RREQ_SYMKEY

// SIMULATE_ANONYMOUS_DATA_UNICAST must be 1
// if MAC layer does *not* support anonymous DATA unicast.
//---------------------------------------------------------
// ANODR uses anonymous DATA unicast (see Chapter 5 of
// Jiejun Kong's Ph.D thesis for more details).
// At the link layer, an anonymous (unicast) data frame is
// transmited as a seemingly-broadcast frame with MAC destination
// address set to the broadcast address 0xffffffffffff.
// Nevertheless, immediately upon a pseudonym-match at a neigbhor's
// routing table, this matched neighbor node knows that it is
// the one-hop receiver, and can accordingly ACK the unicast with
// the same pseudonym.
//
// Unfortunately, it is non-trivial to modify EVERY MAC protocol in QualNet
// to implement this MAC layer anonymous DATA unicast.
// So far we have only implemented anonymous TDMA unicast,
// while anonymous unicast for other MAC protocols is simply simulated
// at the network layer by using an explicit unicast.
// This is temporarily implemented by putting downstream node's address
// in the 1st 32-bit of the RREP pseudonym and upstream node's address
// in the 2nd 32-bit of the RREP pseudonym.  Note that ANODR
// absolutely does NOT rely on such node address information at all.
// In real implementation, such a shortcut must *not* be allowed.
//
// To check the anonymous TDMA unicast, you must specify TDMA as
// the MAC-PROTOCOL in QualNet's .config file, set the macro
// SIMULATE_ANONYMOUS_DATA_UNICAST to be 0 here, then recompile
// routing_anodr.cpp so that all SIMULATE_ANONYMOUS_DATA_UNICAST
// places are disabled.
//---------------------------------------------------------
#define SIMULATE_ANONYMOUS_DATA_UNICAST 1

//---------------------------------------------------------
// If defined, the source will not leak its identity (IP address)
// to the destination.  This is described in the ANODR publications.
//---------------------------------------------------------
#define HIDE_SOURCE_FROM_DEST 1

// Implement network-layer unicast control packet AACK (anonymous ACK)
#define RREP_AACK
#define RERR_AACK
#undef DATA_AACK       // implemented but not tested

// Not yet implemented CSPRG pseudonym update
#undef DO_CSPRG_PSEUDONYM_UPDATE

#define DEFAULT_STRING {0}

// DEBUG options
#define  DEBUG  0
#define  DEBUG_ROUTE 0
#define  DEBUG_ECC   (DEBUG_ROUTE && 1)
#define  DEBUG_FAKE_GLOBALTRAPDOOR (anodr->doCrypto == FALSE && 1)
#define  DEBUG_ROUTE_TABLE 0
#define  DEBUG_INIT 0
#define  DEBUG_ANODR_TRACE 0

//-------------------------------------------------------------------------
// FUNCTION : Int32ToHexstring
// PURPOSE  : TO convert an int32 number into a hex string
// ARGUMENTS: *buffer,Pointer to the string
//             input,the number to be converted
// RETURN   : void
//-------------------------------------------------------------------------
static void
Int32ToHexstring(char *buffer, const Int32 input)
{
    sprintf(buffer, "%02x%02x%02x%02x",
            (input & 0xff000000) >> 24,
            (input & 0xff0000) >> 16,
            (input & 0xff00) >> 8,
            input & 0xff);
}


#if 0
//-------------------------------------------------------------------------
// FUNCTION : Print128BitInHex
// PURPOSE  :Convert 128-bit binaries into its hexadecimal string format
// CAVEAT   : the caller should make sure that there is no memory fault.
// ARGUMENTS:*output,pointer to the output hex string
//           *input,input binary
// RETURN   : void
//-------------------------------------------------------------------------
static void
Print128BitInHex(char *output, const byte *input)
{
    int i;

    output[0] = '0';
    output[1] = 'x';
    for (i=0; i<4; i++)
    {
        Int32ToHexstring(output+2+8*i, *((Int32 *)(input+4*i)));
    }
}
#endif


// FUNCTION : DebugPrint128BitInHex
// PURPOSE  :Convert 128-bit binaries into its hexadecimal string format
//           for Debug purposes.
// ARGUMENTS:*output,pointer to the output hex string
//           *input,input binary
// RETURN   : void
static void
DebugPrint128BitInHex(char *output, const byte *input)
{
    Int32ToHexstring(output, *((Int32 *)input));
    output[8] = '.';
    Int32ToHexstring(output+9, *((Int32 *)(input+4)));
    output[17] = '.';
    Int32ToHexstring(output+18, *((Int32 *)(input+8)));
    output[26] = '.';
    Int32ToHexstring(output+27, *((Int32 *)(input+12)));
    output[35] = '.';
    output[36] = 0;
}


#if 0
//-------------------------------------------------------------------------
// FUNCTION : Print384BitInHexPrint384BitInHex
// PURPOSE  :Convert 128-bit binaries into its hexadecimal string format
//           for Debug purposes.
// ARGUMENTS:*output,pointer to the output hex string
//           *input,input binary
// RETURN   : void
//-------------------------------------------------------------------------

static void
Print384BitInHex(char *output, const byte *input)
{
    int i;

    output[0] = '0';
    output[1] = 'x';
    for (i=0; i<12; i++)
    {
        Int32ToHexstring(output+2+8*i, *((Int32 *)(input+4*i)));
    }
}
#endif

//-------------------------------------------------------------------------
// FUNCTION : Generate128BitPRN
// PURPOSE  : Generate a random 128-bit pseudorandom number
// ARGUMENTS:*node,pointer to a node
//           *placeholder pointer to the 128 bit PRN number.
// RETURN   : void
//-------------------------------------------------------------------------

static void
Generate128BitPRN(Node *node, byte *placeholder)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    while (1)
    {
        int i;

        for (i=0; i<4; i++)
        {
            ((Int32 *)placeholder)[i] = RANDOM_nrand(anodr->nymSeed);
        }

        // The following 4 special pseudonyms are spared
        if (!memcmp(placeholder, ANODR_SRC_TAG, sizeof(AnodrPseudonym)))
            continue;
        if (!memcmp(placeholder, ANODR_DEST_TAG, sizeof(AnodrPseudonym)))
            continue;
        if (!memcmp(placeholder,
                    ANODR_INVALID_PSEUDONYM,
                    sizeof(AnodrPseudonym)))
            continue;
        if (!memcmp(placeholder,
                    ANODR_BROADCAST_PSEUDONYM,
                    sizeof(AnodrPseudonym)))
            continue;

        if (DEBUG_ROUTE)
        {
            // Put my default IP address at the beginning for debugging only
            *(NodeAddress *)placeholder =
                NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
        }

        return;
    }
}

//-------------------------------------------------------------------------
// FUNCTION : Assign128BitPseudonym
// PURPOSE  : Assign left pseudonym = right pseudonym
// ARGUMENTS:*left, pointer to the left pseudonym
//           *right, pointer to the right pseudonym
// RETURN   : void
//-------------------------------------------------------------------------

static void
Assign128BitPseudonym(AnodrPseudonym *left, const AnodrPseudonym *right)
{
    memcpy(left->bits, right->bits, sizeof(AnodrPseudonym));
}

#ifdef DO_ECC_CRYPTO

//-------------------------------------------------------------------------
// FUNCTION : AnodrEccChooseRandomNumber
// PURPOSE  : TO generate a random MPI
// ARGUMENTS:n,(data of type MPI)
// RETURN   : data of type MPI
//-------------------------------------------------------------------------

static MPI
AnodrEccChooseRandomNumber(AnodrData* anodr, MPI n)
{
    MPI result;

    while (1)
    {
        int i;

        // Choose the random nonce k
        byte k[b2B(QUALNET_ECC_KEYLENGTH)+3];
        for (i=0; i<(b2B(QUALNET_ECC_KEYLENGTH)+3)/4; i++)
        {
            ((Int32 *)k)[i] = RANDOM_nrand(anodr->eccSeed);
        }
        result = mpi_alloc_set_ui(0);
        mpi_from_bitstream(result, k, b2B(QUALNET_ECC_KEYLENGTH));

        // It must be in proper range
        if (mpi_cmp_ui(result, 5664) > 0 &&
           (n? (mpi_cmp(result, n) < 0) : 1))
        {
            return result;
        }
    }
}


//-------------------------------------------------------------------------
// FUNCTION : AnodrEccPubKeyEncryption
// PURPOSE  : TO encrypt a plain text to a ciphertext using ECC encryption.
// ARGUMENTS: anodr,pointer to data of type, AnodrData
//            ciphertext,pointer to the ciphertext
//            pubKey, an array of type byte and size of the public key
//            destAddr,nodeAddress of the destination
//            plaintext,pointer to the plaintext to be encrypted.
//            plaintextBitLength,Length of plaintext to be encrypted.
// RETURN   : Void
//-------------------------------------------------------------------------

static void
AnodrEccPubKeyEncryption(
    AnodrData* anodr,
    byte *ciphertext,
    byte pubKey[b2B(3*QUALNET_ECC_KEYLENGTH)],
    NodeAddress destAddr,
    byte *plaintext,
    int  plaintextBitLength)
{
    MPI pkMpi[11] = MPI_NULL;
    MPI plainMpi = mpi_alloc_set_ui(0);
    MPI cipherMpi[4] = MPI_NULL;
    int i=0;

    // Prepare the one-time public key of the RREQ upstream node
    // The first 7 MPIs are well-known parameters
    for (i=0; i<7; i++)
    {
        pkMpi[i] = mpi_copy(anodr->eccKey[i]);
    }
    // The next 3 MPIs are upstream's one-time public key
    for (i=0; i<3; i++)
    {
        pkMpi[7+i] = mpi_alloc_set_ui(0);
        mpi_from_bitstream(pkMpi[7+i],
                           pubKey + i*b2B(QUALNET_ECC_KEYLENGTH),
                           b2B(QUALNET_ECC_KEYLENGTH));
    }
    // The random nonce k
    pkMpi[10] = AnodrEccChooseRandomNumber(anodr, pkMpi[6]/*pk.n*/);

    // Prepare the plaintext placeholder
    mpi_from_bitstream(plainMpi, plaintext, b2B(plaintextBitLength));
    // Do the ECC encryption
    ecc_encrypt(PUBKEY_ALGO_ECC, cipherMpi, plainMpi, pkMpi);
    // Deliver the ciphertext
    memset(ciphertext, 0, b2B(QUALNET_ECC_BLOCKLENGTH(plaintextBitLength)));
    int ciphertextLength = 0;
    for (i=0; i<4; i++)
    {
        ciphertextLength +=
          mpi_to_bitstream(ciphertext + i*b2B(QUALNET_ECC_KEYLENGTH),
                           b2B(i==3?plaintextBitLength:QUALNET_ECC_KEYLENGTH),
                           cipherMpi[i],
                           1);
    }
    if (ciphertextLength != b2B(QUALNET_ECC_BLOCKLENGTH(plaintextBitLength)))
    {
        char address[MAX_STRING_LENGTH];
        IO_ConvertIpAddressToString(destAddr, address);
        fprintf(stderr, "Encryption anomaly for destination %s.\n", address);
    }

    if (DEBUG_ECC)
    {
        // Just for debug purpose.
        // Now get a vicarious decryption trial
        // (from the destination's private key)
        MPI skey[12];
        char buffer[MAX_STRING_LENGTH];
        char address[MAX_STRING_LENGTH];
        char keyFileName[MAX_STRING_LENGTH];

        IO_ConvertIpAddressToString(destAddr, address);
        sprintf(keyFileName, "default.privatekey.%s", address);

        FILE *keyFile = fopen(keyFileName, "r");
        if (keyFile == NULL)
        {
            sprintf(buffer,
                    "Cannot open node %s's private key file for reading.\n",
                     address);
            ERROR_ReportError(buffer);
        }

        /*
          sk.E.p_ = keyFile_line[0];
          sk.E.a_ = keyFile_line[1];
          sk.E.b_ = keyFile_line[2];
          sk.E.G.x_ = keyFile_line[3];
          sk.E.G.y_ = keyFile_line[4];
          sk.E.G.z_ = keyFile_line[5];
          sk.E.n_ = keyFile_line[6];
          sk.Q.x_ = keyFile_line[7];
          sk.Q.y_ = keyFile_line[8];
          sk.Q.z_ = keyFile_line[9];
          sk.d = keyFile_line[10];
        */
        // NOTE: The source node is NOT supposed to see the
        // destination's [10], which is the destination's private key sk.d
        for (i=0; i<11; i++)
        {
            fgets(buffer, QUALNET_MAX_STRING_LENGTH, keyFile);
            if (buffer[strlen(buffer)-1] != '\n')
            {
                sprintf(buffer,
                        "Private key file %s is corrupted."
                        " Please delete it.\n",
                        keyFileName);
                ERROR_ReportError(buffer);
            }
            buffer[strlen(buffer)-1] = '\0';

            // skip "0x"
            if (strlen(buffer+2) > (2*QUALNET_ECC_KEYLENGTH))
            {
                sprintf(buffer,
                        "Private key file %s is corrupted."
                        " Please delete it.\n",
                        keyFileName);
                ERROR_ReportError(buffer);
            }
            if (skey)
            {
                skey[i] = mpi_alloc_set_ui(0);
                mpi_fromstr(skey[i], buffer);
            }
        }
        fclose(keyFile);

        // Choose the random nonce k
        skey[11] = AnodrEccChooseRandomNumber(anodr, skey[6]/*sk.n*/);

        MPI decrypted = mpi_alloc_set_ui(0);
        ecc_decrypt(PUBKEY_ALGO_ECC, &decrypted, cipherMpi, skey);

        if (mpi_cmp(plainMpi, decrypted) != 0)
        {
            // Something is wrong. The decryption doesn't match plaintext
            IO_ConvertIpAddressToString(destAddr, address);
            sprintf(buffer,
                   "ECC encryption wrong for %s. Please rerun simulation.\n",
                    address);

            // Generate a new pair of keys for next run.
            int invalid = 1;

            while (invalid)
            {
                fprintf(stderr, "Generate Elliptic Curve Cryptosystem (ECC)"
                                " key for %s.\n",
                        address);

                // Choose the random nonce k
                mpi_free(skey[11]);
                skey[11] = AnodrEccChooseRandomNumber(anodr,skey[6]/*sk.n*/);
                invalid = ecc_generate(PUBKEY_ALGO_ECC,
                                       QUALNET_ECC_KEYLENGTH,
                                       skey,
                                       NULL);
            }

            char pubKeyFileName[MAX_STRING_LENGTH];
            FILE *pubKeyFile;

            keyFile = fopen(keyFileName, "w");
            sprintf(pubKeyFileName, "default.publickey.%s", address);
            pubKeyFile = fopen(pubKeyFileName, "w");

            if (!keyFile || !pubKeyFile)
            {
                sprintf(buffer, "Error in creating key file %s or %s\n",
                        keyFileName, pubKeyFileName);
                ERROR_ReportError(buffer);
            }

            // public key does NOT include sk.d
            for (i=0; i<10; i++)
            {
                fprintf(pubKeyFile, "0x");
                mpi_print(pubKeyFile, anodr->eccKey[i], 1);
                fputc('\n', pubKeyFile);
            }
            // key has all 11 elements
            for (i=0; i<11; i++)
            {
                fprintf(keyFile, "0x");
                mpi_print(keyFile, anodr->eccKey[i], 1);
                fputc('\n', keyFile);
            }
            ERROR_ReportError(buffer);
        }
        mpi_free(decrypted);
        for (i=0; i<12; i++)
        {
            mpi_free(skey[i]);
        }
    } // DEBUG_ECC && DEBUG_ROUTE

    // free the temporary MPIs
    for (i=0; i<11; i++)
    {
        mpi_free(pkMpi[i]);
    }
    for (i=0; i<4; i++)
    {
        mpi_free(cipherMpi[i]);
    }
    mpi_free(plainMpi);
}
//-------------------------------------------------------------------------
// FUNCTION : AnodrEccPubKeyDecryption
// PURPOSE  : TO decrypt a ciphertext to a plaintext using ECC encryption.
// ARGUMENTS: node,pointer to the node
//            plaintext,pointer to the plaintext generated after decryption
//            ciphertext,pointer to the ciphertext to be decrypted
//            plaintextBitLength,Length of plaintext.
// RETURN   : Void
//-------------------------------------------------------------------------
static void
AnodrEccPubKeyDecryption(
    Node *node,
    byte *plaintext,
    byte *ciphertext,
    int  plaintextBitLength)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    MPI cipherMpi[4] = { MPI_NULL };
    MPI plainMpi = MPI_NULL;
    int i = 0;

    // Acquire R.x R.y R.z
    for (i=0; i<3; i++)
    {
        cipherMpi[i] = mpi_alloc_set_ui(0);
        mpi_from_bitstream(
            cipherMpi[i],
            ciphertext + i*b2B(QUALNET_ECC_KEYLENGTH),
            b2B(QUALNET_ECC_KEYLENGTH));
    }
    // Acquire C (the AES ciphertext used in ECC)
    cipherMpi[3] = mpi_alloc_set_ui(0);
    mpi_from_bitstream(
        cipherMpi[3],
        ciphertext + b2B(QUALNET_ECC_PUBLIC_KEYLENGTH),
        b2B(plaintextBitLength));

    // Do the ECC decryption
    ecc_decrypt(PUBKEY_ALGO_ECC,
                &plainMpi,
                cipherMpi,
                anodr->eccKey);

    // Deliver the plaintext
    int plaintextLength =
        mpi_to_bitstream(plaintext,
                         b2B(plaintextBitLength),
                         plainMpi,
                         1);
    if (plaintextLength != b2B(plaintextBitLength))
    {
        fprintf(stderr, "Decryption anomaly for node %u.\n", node->nodeId);
    }

    // free the temporary memory
    for (i=0; i<4; i++)
    {
        mpi_free(cipherMpi[i]);
    }
    mpi_free(plainMpi);
}
#endif // DO_ECC_CRYPTO


//-------------------------------------------------------------------------
// FUNCTION : ProcessOnion
// PURPOSE  : Process the local trapdoor: encrypt TBO using a random
//            personal onion key
// ARGUMENTS: node,pointer to the node
//            inputOnion,the onion coming from the previous node.
//            onionKey,Used to generate the output onion from the
//            outputOnion,the onion produced by the node.
// RETURN   : void
//-------------------------------------------------------------------------

static void ProcessOnion(Node *node,
                         AnodrOnion *inputOnion,
                         AnodrOnion *onionKey,
                         AnodrOnion *outputOnion)
{
#ifdef ASR_PROTOCOL
    // ASR uses one-time pad
    int i;

    for (i=0; i<4; i++)
    {
        ((Int32 *)outputOnion->bits)[i] =
            ((Int32 *)onionKey->bits)[i] ^ ((Int32 *)inputOnion->bits)[i];
    }
#else // ASR_PROTOCOL
    // ANODR uses AES.
    // This is the only protocol-wise difference between ANODR and ASR.
#ifdef DO_AES_CRYPTO
    CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
    cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
    cipher_setiv(cipher, NULL, 0 ); // Zero IV
    cipher_setkey(cipher, onionKey->bits, b2B(AES_BLOCKLENGTH));
    cipher_encrypt(cipher,
                   outputOnion->bits,
                   inputOnion->bits,
                   b2B(AES_BLOCKLENGTH));
    cipher_close(cipher);
#else // DO_AES_CRYPTO
    // If no AES, just imitate ASR's one-time pad
    Generate128BitPRN(node, onionKey->bits); // also sync PRG

    int i;

    for (i=0; i<4; i++)
    {
        ((Int32 *)outputOnion->bits)[i] =
            ((Int32 *)onionKey->bits)[i] ^ ((Int32 *)inputOnion->bits)[i];
    }
#endif // DO_AES_CRYPTO
#endif // ASR_PROTOCOL

#ifdef SIMULATE_ANONYMOUS_DATA_UNICAST
    // Put my default IP address at the beginning of the output_onion
    // for wireless MAC protocols which do not support anonymous unicast.
    // This is for reverse directional traffic from ANODR-dest to ANODR-src.
    *(NodeAddress *)outputOnion =
        NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
#endif // SIMULATE_ANONYMOUS_DATA_UNICAST
}


//-------------------------------------------------------------------------
// FUNCTION : SetGlobalTrapdoor
// PURPOSE  :

// Suppose the source is node A, the destination is node E.
// They already share a pairwise symmetric key K_{AE}.
// then "tr_{dest} = K_{AE}(DEST_TAG, K_{reveal}), K_{reveal}(DEST_TAG)"
//                   |      128-bit   128-bit                 128-bit
// where K(M) means using symmetric key K to encrypt message M using AES,
// and "," simply means concatenation.  K_{reveal} is a nonce key for
// the purpose of trapdoor commitment.
// Because both DEST_TAG and nonce_key are 128 bits long,
// the global trapdoor tr_{dest} is 128*3 = 384 bits long.

// ARGUMENTS: node,pointer to the node
//            anodr,pointer to data containing ANODR information
//            sourceGlobalTrapdoor,pointer to the global trap door
//                                  information about a source node
//            destAddr,address of the destination to which the packet will
//                     be forwarded
//            commitment,the onion produced by the node.
//            e2eKey,NULL or established key between source and destination
//            newE2eKey,the key to be generated in case the e2eKey is NULL
// RETURN   : void
//-------------------------------------------------------------------------

static void
SetGlobalTrapdoor(Node *node,
                  AnodrData* anodr,
                  byte *sourceGlobalTrapdoor,
                  NodeAddress destAddr,
                  byte **commitment,
                  byte *e2eKey, // NULL or established K_AE
                  byte *newE2eKey)
{
    AnodrGlobalTrapdoor *seqNum0 =
        (AnodrGlobalTrapdoor *)sourceGlobalTrapdoor;
    AnodrGlobalTrapdoorSymKey *seqNum1 =
        (AnodrGlobalTrapdoorSymKey *)sourceGlobalTrapdoor;
    byte *destTag = sourceGlobalTrapdoor;
    byte *kReveal = sourceGlobalTrapdoor + b2B(AES_BLOCKLENGTH);
    byte *kAE = sourceGlobalTrapdoor + 2*b2B(AES_BLOCKLENGTH);

    // Set the destination tag
    memcpy(destTag, ANODR_DEST_TAG, b2B(AES_BLOCKLENGTH));
    // Choose the commitment key K_reveal
    Generate128BitPRN(node, kReveal);

    if (e2eKey == NULL)
    {
        // e2eKey not established.
        // Choose the symmetric key K_AE
        Generate128BitPRN(node, kAE);
        memcpy(newE2eKey, kAE, b2B(AES_BLOCKLENGTH));

        // A unique pseudo srcAddr selected by the ANODR source per dest
        // for the ANODR dest to identify the ANODR source.
        // It can be the ANODR source's real address if necessary.
        *(NodeAddress *)(sourceGlobalTrapdoor + 3*b2B(AES_BLOCKLENGTH))
#ifdef HIDE_SOURCE_FROM_DEST
            = anodr->e2eNym ^ destAddr;
#else
            = NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
#endif //HIDE_SOURCE_FROM_DEST

        *commitment = seqNum0->commitment;
    }
    else
    {
        // symmetric K_AE already established, no need to put it
        // in the symmetric-key encrypted global trapdoor.
        // dummy is for synchronizing QualNet's pseudorandom generator.
        byte dummy[128/8];
        Generate128BitPRN(node, dummy);

        // A unique pseudo srcAddr selected by the ANODR source per dest
        // for the ANODR dest to identify the ANODR source.
        // It can be the ANODR source's real address if necessary.
        *(NodeAddress *)(sourceGlobalTrapdoor + 2*b2B(AES_BLOCKLENGTH))
#ifdef HIDE_SOURCE_FROM_DEST
            = anodr->e2eNym ^ destAddr;
#else
            = NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
#endif //HIDE_SOURCE_FROM_DEST

        *commitment = seqNum1->commitment;
    }

    // Set the commitment plaintext
    memcpy(*commitment,  ANODR_DEST_TAG,  b2B(AES_BLOCKLENGTH));
#ifdef DO_AES_CRYPTO
    // Set the commitment  K_reveal(DEST_TAG):
    // Use K_reveal to encrypt the DEST_TAG
    CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
    cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
    cipher_setiv(cipher, NULL, 0 ); // Zero IV
    cipher_setkey(cipher, kReveal, b2B(AES_BLOCKLENGTH));  // K_reveal
    cipher_encrypt(cipher, *commitment, *commitment, b2B(AES_BLOCKLENGTH));
    cipher_close(cipher);
#endif // DO_AES_CRYPTO produces anonymous commitment K_reveal(DEST_TAG)

    if (e2eKey)
    {
        // end-to-end key K_{AE} has already been established.
        // This is true only AFTER 1st ECC-encrypted RREQ contact
        // with destAddr.
#ifdef DO_AES_CRYPTO
        // Use K_{AE} to encrypt (DEST_TAG, K_reveal)
        if (anodr->doCrypto)
        {
            CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
            cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
            cipher_setiv(cipher, NULL, 0 ); // Zero IV
            cipher_setkey(cipher, e2eKey, b2B(AES_BLOCKLENGTH));  // K_{AE}
            cipher_encrypt(cipher,
                           seqNum1->bits.ciphertext,
                           seqNum1->bits.plaintext,
                           b2B(3*AES_BLOCKLENGTH));
            cipher_close(cipher);

            return;
        }
#endif // DO_AES_CRYPTO produces encrypted (DEST_TAG, K_reveal)
    }
    else
    {
        // 1st-time contact: end-to-end key K_{AE} not yet established
#ifdef DO_ECC_CRYPTO
        if (anodr->doCrypto)
        {
            int i;
            char buffer[MAX_STRING_LENGTH] = DEFAULT_STRING;
            char address[MAX_STRING_LENGTH] = DEFAULT_STRING;
            char pubKeyFileName[MAX_STRING_LENGTH] = DEFAULT_STRING;
            FILE *pubKeyFile = NULL;

            // Now get the public key
            IO_ConvertIpAddressToString(destAddr, address);
            sprintf(pubKeyFileName, "default.publickey.%s", address);

            pubKeyFile = fopen(pubKeyFileName, "r");
            if (pubKeyFile == NULL)
            {
                sprintf(buffer,
                        "Cannot open node %s's public"
                        " key file for reading.\n",
                        address);
                ERROR_ReportError(buffer);
            }

            /*
              pk.E.p_ = keyFile_line[0];
              pk.E.a_ = keyFile_line[1];
              pk.E.b_ = keyFile_line[2];
              pk.E.G.x_ = keyFile_line[3];
              pk.E.G.y_ = keyFile_line[4];
              pk.E.G.z_ = keyFile_line[5];
              pk.E.n_ = keyFile_line[6];
              pk.Q.x_ = keyFile_line[7];
              pk.Q.y_ = keyFile_line[8];
              pk.Q.z_ = keyFile_line[9];
            */
            // NOTE: The source node is NOT supposed to see the
            // destination's [10],which is the destination's private key sk.d
            for (i=0; i<10; i++)
            {
                fgets(buffer, QUALNET_MAX_STRING_LENGTH, pubKeyFile);
                if (buffer[strlen(buffer)-1] != '\n')
                {
                    sprintf(buffer,
                            "Public key file %s is corrupted."
                            " Please delete it.\n",
                            pubKeyFileName);
                    ERROR_ReportError(buffer);
                }
                buffer[strlen(buffer)-1] = '\0';

                if (i >= 7)
                {
                    // skip "0x"
                    if (strlen(buffer+2) > (2*QUALNET_ECC_KEYLENGTH))
                    {
                        sprintf(buffer,
                                "Public key file %s is corrupted."
                                " Please delete it.\n",
                                pubKeyFileName);
                        ERROR_ReportError(buffer);
                    }
                    hexstr_to_bitstream(
                        anodr->destPubKey + (i-7)*b2B(QUALNET_ECC_KEYLENGTH),
                        b2B(QUALNET_ECC_KEYLENGTH),
                        (byte *)buffer+2);
                }
            }// end of for

            fclose(pubKeyFile);

            // Now encrypt (DEST_TAG, K_reveal, K_AE, opt_srcAddr) using PK_E
            AnodrEccPubKeyEncryption(anodr,
                                     seqNum0->bits.ciphertext,
                                     anodr->destPubKey,
                                     destAddr,
                                     seqNum0->bits.plaintext,
                                     4*AES_BLOCKLENGTH);
            return;
        }//end of if (anodr->doCrypto)
#endif // DO_ECC_CRYPTO encrypts global trapdoor
    }//end of if (e2eKey)

 // Otherwise, just simulate the global trapdoor because ECC is missing
#ifndef DO_ECC_CRYPTO
    memcpy(sourceGlobalTrapdoor, &destAddr, sizeof(destAddr));
#endif
}

void D_AnodrPrint::ExecuteAsString(const char *in, char *out)
{
#if 0
    AnodrRoutingTable* routeTable = &anodr->routeTable;
    AnodrRouteEntry* rtEntry = NULL;
    int i = 0;
    EXTERNAL_VarArray v;
    char str[MAX_STRING_LENGTH];

    EXTERNAL_VarArrayInit(&v, 400);

    EXTERNAL_VarArrayConcatString(
        &v,
        "The Routing Table is:\n"
        "      Dest       DestSeq  HopCount  Intf     NextHop    "
        "activated   lifetime    precursors\n"
        "-------------------------------------------------------------"
        "--------------------------\n");
    for (i = 0; i < ANODR_ROUTE_TABLE_SIZE; i++)
    {
        for (rtEntry = routeTable->rows[i];
             rtEntry != NULL;
             rtEntry = rtEntry->hashNext)
        {
            char time[MAX_STRING_LENGTH];
            char dest[MAX_STRING_LENGTH];
            char nextHop[MAX_STRING_LENGTH];
            char trueOrFalse[6];
            IO_ConvertIpAddressToString(rtEntry->destination.address, dest);
            IO_ConvertIpAddressToString(rtEntry->nextHop, nextHop);
            TIME_PrintClockInSecond(rtEntry->expireTime, time);

            if (rtEntry->activated)
            {
                strcpy(trueOrFalse, "TRUE");
            }
            else
            {
                strcpy(trueOrFalse, "FALSE");
            }

            sprintf(str, "%15s  %5u  %5d    %5d  %15s  %5s    %9s  ", dest,
                rtEntry->destination.seqNum, rtEntry->hopCount,
                rtEntry->interface, nextHop, trueOrFalse, time);
            EXTERNAL_VarArrayConcatString(&v, str);
        }
    }
    EXTERNAL_VarArrayConcatString(
        &v,
        "-------------------------------------------------------------"
        "-----------------------");

    strcpy(out, v.data);
    EXTERNAL_VarArrayFree(&v);
#endif
}


//------------------------------------------
// ANODR Memory Manager
//------------------------------------------

//-------------------------------------------------------------------------
// FUNCTION : AnodrMemoryChunkAlloc
// PURPOSE  : Function to allocate a chunk of memory
// ARGUMENTS: Pointer to Anodr main data structure
// RETURN   : void
//-------------------------------------------------------------------------

static
void AnodrMemoryChunkAlloc(AnodrData* anodr)
{
    int i = 0;
    AnodrMemPollEntry* freeList = NULL;

    anodr->freeList = (AnodrMemPollEntry*)MEM_malloc(ANODR_MEM_UNIT
                                            * sizeof(AnodrMemPollEntry));

    ERROR_Assert(anodr->freeList != NULL, " No available Memory");

    freeList = anodr->freeList;

    for (i = 0; i < ANODR_MEM_UNIT - 1; i++)
    {
        freeList[i].next = &freeList[i + 1];
    }

    freeList[ANODR_MEM_UNIT - 1].next = NULL;
}


//-------------------------------------------------------------------------
// FUNCTION  : AnodrMemoryMalloc
// PURPOSE   : Function to allocate a single cell of
//             memory from the memory chunk
// ARGUMENTS : Pointer to Anodr main data structure
// RETURN    : Address of free memory cell
//-------------------------------------------------------------------------

static
AnodrRouteEntry* AnodrMemoryMalloc(AnodrData* anodr)
{
    AnodrRouteEntry* temp = NULL;

    if (!anodr->freeList)
    {
        AnodrMemoryChunkAlloc(anodr);
    }

    temp = (AnodrRouteEntry*)anodr->freeList;
    anodr->freeList = anodr->freeList->next;
    return temp;
}


//-------------------------------------------------------------------------
// FUNCTION : AnodrMemoryFree
// PURPOSE  : Function to return a memory cell to the memory pool
// ARGUMENTS: Pointer to Anodr main data structure,
//            pointer to route entry
// RETURN   : void
//-------------------------------------------------------------------------

static
void AnodrMemoryFree(AnodrData* anodr, AnodrRouteEntry* ptr)
{
    AnodrMemPollEntry* temp = (AnodrMemPollEntry*)ptr;
    temp->next = anodr->freeList;
    anodr->freeList = temp;
}


//---------------------------------------------------------------
// FUNCTION :AnodrPrintTrace()
// PURPOSE  :Trace printing function to call for Anodr packet.
// ARGUMENTS:node,pointer to the node for which trace has to be printed
//           msg,pointer to the message to
//           sendOrReceive, 'S'or 'R'
// RETURN VALUE :void
//---------------------------------------------------------------

static
void AnodrPrintTrace(
         Node* node,
         Message* msg,
         char sendOrReceive)
{
#if 0
    byte* pktPtr = (byte *) MESSAGE_ReturnPacket(msg);
#endif

    char clockStr[MAX_STRING_LENGTH];
    FILE* fp = fopen("anodr.trace", "a");

    if (!fp)
    {
        ERROR_ReportError("Can't open anodr.trace\n");
    }

    TIME_PrintClockInSecond(node->getNodeTime(), clockStr);

    // print packet ID
    fprintf(fp, "%u, %d; %s; %u %c; ",
        msg->originatingNodeId,
        msg->sequenceNumber,
        clockStr,
        node->nodeId,
        sendOrReceive);

#if 0
    if (*pktPtr == ANODR_RREQ)
    {
        // Print content of route request packets
        AnodrRreqPacket* rreqPkt = (AnodrRreqPacket *) pktPtr;
    }
    if (*pktPtr == ANODR_RREQ_SYMKEY)
    {
        // Print content of route request packets
        AnodrRreqSymKeyPacket* rreqSymKeyPkt =
                                            (AnodrRreqSymKeyPacket *) pktPtr;
    }
    if (*pktPtr == ANODR_RREP)
    {
        // Print content of route reply packets
        AnodrRrepPacket* rrepPkt = (AnodrRrepPacket *) pktPtr;
    }
    if (*pktPtr == ANODR_RERR)
    {
        // Print content of route error packets
        unsigned int i;
        AnodrRerrPacket* rerrPkt = (AnodrRerrPacket *) pktPtr;
    }
#endif

    fprintf(fp, "\n");
    fclose(fp);
}


//-------------------------------------------------------------------------
// FUNCTION     :AnodrInitTrace()
// PURPOSE      :Enabling Anodr trace. The output will go in file anodr.trace
// ASSUMPTION   :None
// RETURN VALUE :None
//-------------------------------------------------------------------------

static
void AnodrInitTrace(void)
{
    if (DEBUG_ANODR_TRACE)
    {
        // Empty or create a file named anodr.trace to print the packet
        // contents
        FILE* fp = fopen("anodr.trace", "w");
        fclose(fp);
    }
}

//-----------------------------------------------------------------------
// FUNCTION : AnodrSetTimer
// PURPOSE  : Set timers for protocol events
// ARGUMENTS: node, The node which is scheduling an event
//            eventType, The event type of the message
//            destAddr, the destination, only meaningful at the source
//            onion,128-bit onion or pseudonym
//            interface,for multiple interfaces
//            delay,Time after which the event will expire
//-----------------------------------------------------------------------

static
void AnodrSetTimer(
         Node* node,
         const int eventType,
         const NodeAddress destAddr,    // only meaningful at the source
         const AnodrPseudonym *onion,   // 128-bit onion or pseudonym
         const int interface,           // for multiple interfaces
         const clocktype delay)
{
    Message* newMsg = NULL;
    char* info = NULL;

    if (DEBUG >= 3)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char address[MAX_STRING_LENGTH]= DEFAULT_STRING;

        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        IO_ConvertIpAddressToString(destAddr, address);

        printf("Node %u sets timer for dest %s at %s\n",
                node->nodeId,address, clockStr);

        TIME_PrintClockInSecond((node->getNodeTime() + delay), clockStr);
        printf("\ttimer to expire at %s\n", clockStr);
    }

    // Allocate message for the timer
    newMsg = MESSAGE_Alloc(node,
                           NETWORK_LAYER,
                           ROUTING_PROTOCOL_ANODR,
                           eventType);

    // Assign the address for which the timer is meant for
    MESSAGE_InfoAlloc(node,
                      newMsg,
                      sizeof(NodeAddress)+
                      sizeof(AnodrPseudonym)+
                      sizeof(int));

    info = (char *) MESSAGE_ReturnInfo(newMsg);
    if (onion != NULL)
    {
        // Embed 3 things in the timer:
        // destAddr,128-bit pseudonym or onion, and associated interfaceIndex
        memcpy(info, &destAddr, sizeof(NodeAddress));
        memcpy(info+sizeof(NodeAddress),
               onion,
               sizeof(AnodrPseudonym));
        memcpy(info+sizeof(NodeAddress)+sizeof(AnodrPseudonym),
               &interface,
               sizeof(int));
    }
    else
    {
        memset(info,
               0,
               sizeof(NodeAddress)+sizeof(AnodrPseudonym)+sizeof(int));
    }

    // Schedule the timer after the specified delay
    MESSAGE_Send(node, newMsg, delay);
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrSimulateCryptoOverhead
// PURPOSE  : Send message with estimate processing delay
// ARGUMENTS: node, The node which is scheduling an event
//            msg, The event type of the message
//            cryptoType,type of cryptography used ex,CIPHER_ALGO_AES256
//            packetType,type of ANODR packet e.g., ANODR_RREQ
//            incomingInterface,the interface from which the packet has come
//            ttl,time to live
//-----------------------------------------------------------------------

static void
AnodrSimulateCryptoOverhead(Node *node,
                            Message *msg,
                            char cryptoType,
                            char packetType,
                            int incomingInterface,
                            int ttl)
{
    AnodrData* anodr =
      (AnodrData*) NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrCryptoOverheadType infoType = DEFAULT_STRING;

    // Send message with estimate processing delay
    MESSAGE_InfoAlloc(node, msg, sizeof(AnodrCryptoOverheadType));

    infoType.packetType = packetType;
    infoType.interfaceIndex = incomingInterface;
    //the ttl should be decreased before forwarding the packet
    infoType.ttl = ttl - IP_TTL_DEC;
    memcpy(MESSAGE_ReturnInfo(msg),
           &infoType,
           sizeof(AnodrCryptoOverheadType));

    clocktype delay = 0;
    if ((packetType == ANODR_RREQ || packetType == ANODR_RREQ_SYMKEY) &&
       (anodr->nodeOnionProcessingTime!=ANODR_DEFAULT_ONION_PROCESSING_TIME))
    {
    delay = anodr->nodeOnionProcessingTime;
    }
    else
    {
    switch(cryptoType)
    {
        case CIPHER_ALGO_AES256:
        delay = AES_DEFAULT_DELAY;
        break;
        case PUBKEY_ALGO_ECC:
        delay = ECC_DEFAULT_DELAY;
        break;
        default:
        ERROR_Assert(FALSE, "Unsupported ANODR crypto type.\n");
    }
    }
    MESSAGE_SetLayer(msg, NETWORK_LAYER, ROUTING_PROTOCOL_ANODR);
    MESSAGE_SetEvent(msg, MSG_CRYPTO_Overhead);

    MESSAGE_Send(node, msg, delay);
}

//-----------------------------------------------------------------------
// FUNCTION : AnodrPrintRoutingTable
// PURPOSE  : Printing the different fields of the routing table of Anodr
// ARGUMENTS: node, The node printing the routing table
//            routeTable, Anodr routing table
// RETURN   : None
//-----------------------------------------------------------------------

static
void AnodrPrintRoutingTable(Node *node, AnodrRoutingTable* routeTable)
{
    int i = 0;
    AnodrRouteEntry* current = NULL;
    char destAddr[MAX_STRING_LENGTH] = DEFAULT_STRING;
    char seqNum[MAX_STRING_LENGTH] = DEFAULT_STRING;
    char nymUp[MAX_STRING_LENGTH] = DEFAULT_STRING;
    char nymDown[MAX_STRING_LENGTH] = DEFAULT_STRING;
    char time[MAX_STRING_LENGTH] = DEFAULT_STRING;

    printf("\n\nThe Routing Table of Node %u is:\n\n", node->nodeId);

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        i++;
        IO_ConvertIpAddressToString(current->remoteAddr, destAddr);
        DebugPrint128BitInHex(seqNum, current->seqNum.bits.ciphertext);
        DebugPrint128BitInHex(nymUp, current->pseudonymUpstream.bits);
        DebugPrint128BitInHex(nymDown, current->pseudonymDownstream.bits);
        TIME_PrintClockInSecond(current->expireTime,time);
        printf("remote=%s(%s),seq#=%s...\n\tnymUp=%36s"
               " nymDown=%36s\n\tinIntf=%d outIntf=%d %s expiry time %s\n",
               destAddr, current->dest?"dest":"src", seqNum, nymUp, nymDown,
               current->inputInterface, current->outputInterface,
               current->activated? "active" : "inactive",time);
    }
    if (i == 0 )
    {
        printf("\t\t\t\tThe Routing Table is Empty\n\n");
    }
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrInsertBuffer
// PURPOSE  : Insert a packet into the buffer if no route is available
// ARGUMENTS: msg, The message waiting for a route to destination
//            destAddr, The destination of the packet
//            pseudonym, If not null, need to record the pseudonym
//            buffer,   The buffer to store the message
// RETURN   : None
//-----------------------------------------------------------------------

static
void AnodrInsertBuffer(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    AnodrPseudonym *pseudonym,
    AnodrMessageBuffer* buffer)
{
    AnodrBufferNode* current = NULL;
    AnodrBufferNode* previous = NULL;
    AnodrBufferNode* newNode = NULL;
    AnodrData* anodr =
      (AnodrData*) NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    // if the buffer exceeds silently drop the packet
    // if no buffer size is specified in bytes it will only check for
    // number of packet.

    if (anodr->bufferSizeInByte == 0)
    {
        if (buffer->size == anodr->bufferSizeInNumPacket)
        {
            MESSAGE_Free(node, msg);
            anodr->stats.numDataDroppedForOverlimit++;
            if (DEBUG >= 2)
            {
                printf("Node %u: Max packets in buffer reached,"
                       "dropping this packet\n",
                        node->nodeId);
            }
            return;
        }
    }
    else
    {
        if ((buffer->numByte + MESSAGE_ReturnPacketSize(msg)) >
                                                     anodr->bufferSizeInByte)
        {
            MESSAGE_Free(node, msg);
            anodr->stats.numDataDroppedForOverlimit++;
            if (DEBUG >= 2)
            {
                printf("Node %u: Max size of buffer reached"
                       ",dropping this packet\n",node->nodeId);
            }
            return;
        }
    }

    // Find Insertion point.  Insert after all address matches.
    // This is to maintain a sorted list in ascending order of the
    // destination address
    previous = NULL;
    current = buffer->head;

    while (current && current->destAddr <= destAddr)
    {
        previous = current;
        current = current->next;
    }

    // Allocate space for the new message
    newNode = (AnodrBufferNode*) MEM_malloc(sizeof(AnodrBufferNode));

    // Store the allocate message along with the destination number
    newNode->destAddr = destAddr;
    if (pseudonym != NULL)
    {
        Assign128BitPseudonym(&newNode->pseudonym, pseudonym);
    }
    else
    {
        memcpy(&newNode->pseudonym,
               ANODR_INVALID_PSEUDONYM,
               sizeof(AnodrPseudonym));
    }
    newNode->msg = msg;
    newNode->next = current;

    // Increase the size of the buffer
    ++(buffer->size);
    buffer->numByte += MESSAGE_ReturnPacketSize(msg);

    // Got the insertion point
    if (previous == NULL)
    {
        // This is the first message in the buffer or to be
        // inserted in the first
        buffer->head = newNode;
    }
    else
    {
        // This is an intermediate node in the list
        previous->next = newNode;
    }
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrGetBufferedPacket
// PURPOSE  : Extract the packet that was buffered
// ARGUMENTS: destAddr, the destination address of the packet to be retrieved
//            pseudonym, If not null, need to match the pseudonym
//            buffer,   the message buffer
// RETURN   : The message for this destination
//-----------------------------------------------------------------------

static
Message* AnodrGetBufferedPacket(NodeAddress destAddr,
                                AnodrPseudonym *pseudonym,
                                AnodrMessageBuffer* buffer)
{
    AnodrBufferNode *current = buffer->head;
    Message* pktToDest = NULL;
    AnodrBufferNode *toFree = NULL;

    if (!current)
    {
        // No packet in the buffer so nothing to do
    }
    else if (current->destAddr == destAddr)
    {
        // The first packet is the desired packet

        if (pseudonym != NULL)
        {
            for (; current != NULL; current=current->next)
            {
                if (!memcmp(current->pseudonym.bits,
                            pseudonym->bits,
                            sizeof(AnodrPseudonym)))
                {
                    break;
                }
            }
            if (current == NULL)
            {
                // Unable to find a matching pseudonym
                return NULL;
            }
        }

        toFree = current;
        buffer->head = toFree->next;

        pktToDest = toFree->msg;

        buffer->numByte -= MESSAGE_ReturnPacketSize(toFree->msg);
        MEM_free(toFree);
        --(buffer->size);
    }
    else
    {
        while (current->next && current->next->destAddr < destAddr)
        {
            current = current->next;
        }

        if (current->next && current->next->destAddr == destAddr)
        {
            // Got the matched destination so return the packet
            if (pseudonym != NULL)
            {
                for (; current->next != NULL; current=current->next)
                {
                    if (!memcmp(current->next->pseudonym.bits,
                                pseudonym->bits,
                                sizeof(AnodrPseudonym)))
                    {
                        break;
                    }
                }
                if (current->next == NULL)
                {
                    // Unable to find a matching pseudonym
                    return NULL;
                }
            }

            toFree = current->next;

            pktToDest = toFree->msg;
            buffer->numByte -= MESSAGE_ReturnPacketSize(toFree->msg);
            current->next = toFree->next;
            MEM_free(toFree);
            --(buffer->size);
        }
    }
    return pktToDest;
}

//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckRouteExist
// PURPOSE  : To check whether route to a particular destination exist.
//            this function serves dual purpose, in case of invalid route it
//            return the pointer to the route with setting isActive flag to
//            FALSE. And in case of valid routes it returns the valid route
//            pointer with setting the isActive flag to TRUE
// ARGUMENTS: destAddr,   destination address of the packet
//            routeTable, anodr routing table to store possible routes
//            isActive,    to return if the route is a valid route or invalid
//                        route
// RETURN   : pointer to the route if it exists in the routing table,
//            NULL otherwise
//-----------------------------------------------------------------------

// The source uses destAddr
static
AnodrRouteEntry* AnodrCheckRouteExist(
    NodeAddress destAddr,
    AnodrRoutingTable* routeTable,
    BOOL* isActive)
{
    AnodrRouteEntry* current = NULL;

    *isActive = FALSE;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        if (current->remoteAddr == destAddr)
        {
            BOOL valid = FALSE;
            if (current->dest)
            {
                valid = memcmp(current->pseudonymUpstream.bits,
                               ANODR_INVALID_PSEUDONYM,
                               sizeof(AnodrPseudonym));
            }
            else
            {
                valid = memcmp(current->pseudonymDownstream.bits,
                               ANODR_INVALID_PSEUDONYM,
                               sizeof(AnodrPseudonym));
            }
            if (valid)
            {
                // Found the entry
                if (current->activated == TRUE)
                {
                    // The entry is a valid route
                    *isActive = TRUE;
                }
                return current;
            }
        }
    }
    return NULL;
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckSeqNumExist
// PURPOSE  : To check whether a seqnum exits in the the VCI table.
//ARGUMENTS : seqnum,sequence number to be checked
//            routeTable, anodr routing table to store possible routes
//            isActive, to return if the seqnum is valid or not.
// RETURN   : pointer to the route if it exists in the routing table,
//            NULL otherwise
//-----------------------------------------------------------------------

static
AnodrRouteEntry* AnodrCheckSeqNumExist(
    byte *seqNum,
    AnodrRoutingTable* routeTable,
    BOOL* isActive)
{
    AnodrRouteEntry* current;

    *isActive = FALSE;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        if (!memcmp(current->seqNum.bits.ciphertext,
                    seqNum,
                    sizeof(AnodrGlobalTrapdoorSymKey)))
        {
            if (current->activated == TRUE)
            {
                // Found the entry
                *isActive = TRUE;
            }
            return current;
        }
    }
    return NULL;
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckOutputOnionExist
// PURPOSE  : To check whether an onion bit sequence matches some
//            outputOnion bits stored in the routing table
//ARGUMENTS : onion,onion bits to be checked
//            routeTable, anodr routing table to store possible routes
//            isActive, to return if the onion is valid or not.
// RETURN   : pointer to the route if it exists in the routing table,
//            NULL otherwise
//-------------------------------------------------------------------
static
AnodrRouteEntry* AnodrCheckOutputOnionExist(
    AnodrOnion *onion,
    AnodrRoutingTable* routeTable,
    BOOL* isActive)
{
    AnodrRouteEntry* current;

    *isActive = FALSE;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        if (!memcmp(current->outputOnion.bits,
            onion->bits, sizeof(AnodrOnion)))
        {
            // Found the entry
            if (current->activated == TRUE)
            {
                *isActive = TRUE;
            }
            return current;
        }
    }
    return NULL;
}


//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckPseudonymUpstreamExist
// PURPOSE  : To check whether a pseudonym matches some upstream pseudonym
//            in the routing table
//ARGUMENTS : pseudonym,onion bits to be checked
//            interface, anodr routing table to store possible routes
//            matchPseudonym, returning matching pseudonym here
//            matchInterface,returning matching interface here
//            routeTable,routing table to store possible routes
//            isActive,to return if a matching upstream pseudonym is found
//                     or not.
// RETURN   : pointer to the route if it exists in the routing table,
//            NULL otherwise
//-------------------------------------------------------------------
static
AnodrRouteEntry* AnodrCheckPseudonymUpstreamExist(
    AnodrPseudonym *pseudonym,
    int interface,
    AnodrPseudonym *matchPseudonym,     // returning matching pseudonym here
    int *matchInterface,                // returning matching interface here
    AnodrRoutingTable* routeTable,
    BOOL* isActive)
{
    AnodrRouteEntry* current = NULL;

    ERROR_Assert(
        memcmp(pseudonym->bits,
               ANODR_INVALID_PSEUDONYM,
               sizeof(AnodrPseudonym)),
        "Invalid upstream pseudonym!\n");

    *isActive = FALSE;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL; current = current->next)
    {
        if (!(!memcmp(current->pseudonymUpstream.bits,
                     pseudonym->bits,
                     sizeof(AnodrPseudonym)) &&
             (interface == ANY_INTERFACE?
              TRUE : current->inputInterface == interface)))
        {
            continue;
        }

        if (matchPseudonym != NULL)
        {
            Assign128BitPseudonym(matchPseudonym,
                                  &current->pseudonymDownstream);
            *matchInterface = current->outputInterface;
        }
        if (current->activated == TRUE)
        {
            *isActive = TRUE;
        }
        return current;
    }
    return NULL;
}

//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckPseudonymDownstreamExist
// PURPOSE  : To check whether a pseudonym matches some downstream pseudonym
//            in the routing table
//ARGUMENTS : pseudonym,onion bits to be checked
//            interface, anodr routing table to store possible routes
//            matchPseudonym, returning matching pseudonym here
//            matchInterface,returning matching interface here
//            routeTable,routing table to store possible routes
//            isActive,to return if a matching downstream pseudonym is
//                     found or not.
// RETURN   : pointer to the route if it exists in the routing table,
//            NULL otherwise
//-------------------------------------------------------------------

static
AnodrRouteEntry* AnodrCheckPseudonymDownstreamExist(
    AnodrPseudonym *pseudonym,
    int interface,
    AnodrPseudonym *matchPseudonym,     // returning matching pseudonym here
    int *matchInterface,                // returning matching interface here
    AnodrRoutingTable* routeTable,
    BOOL* isActive)
{
    AnodrRouteEntry* current = NULL;

    ERROR_Assert(
        memcmp(pseudonym->bits,
               ANODR_INVALID_PSEUDONYM,
               sizeof(AnodrPseudonym)),
        "Invalid downstream pseudonym!\n");

    *isActive = FALSE;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        if (!(!memcmp(current->pseudonymDownstream.bits,
                      pseudonym->bits,
                      sizeof(AnodrPseudonym)) &&
              (interface == ANY_INTERFACE?
               TRUE : current->outputInterface == interface)))
        {
            continue;
        }

        if (matchPseudonym != NULL)
        {
           Assign128BitPseudonym(matchPseudonym,&current->pseudonymUpstream);
           *matchInterface = current->inputInterface;
        }
        if (current->activated == TRUE)
        {
            *isActive = TRUE;
        }
        return current;
    }
    return NULL;
}

//-----------------------------------------------------------------------
// FUNCTION : AnodrCheckSent
// PURPOSE  : Check if RREQ has been sent; return TRUE if sent
// ARGUMENTS: destAddress, destination address of the packet
//            routeTable,routing table to store possible routes
// RETURN   : pointer to the sent node if exists,NULL otherwise
//-----------------------------------------------------------------------

static AnodrRouteEntry*
AnodrCheckSent(NodeAddress destAddr,
               AnodrRoutingTable* routeTable)
{
    AnodrRouteEntry* current = NULL;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        if (destAddr != ANONYMOUS_IP &&
            current->remoteAddr == destAddr &&
            !current->dest)
        {
            return current;
        }
    }
    return NULL;
}

//--------------------------------------------------------------------
//  FUNCTION: AnodrReplaceInsertRouteTable
//  PURPOSE : Insert/Update an entry into the route table
// ARGUMENTS: node,       current node.
//            routeTable, Routing table
//            destAddr,   Destination Address
//                        (ANONYMOUS_IP if not at the source)
//            seqNum, The global trapdoor as the sequence number
//            inputOnion, the RREQ upstream sent me this one
//            onionKey,  my onion key
//            outputOnion, I will send this one to my RREQ downstream
//            commitment, The commitment field K_reveal(DEST_TAG),
//                        later only the destination can reveal the K_reveal
//            upstreamOnetimePublicKey, My RREQ upstream gave me this ECC key
//            pseudonymUpstream, SRC_TAG for the source
//            myOnetimePublicKey, I will give my RREQ downstream this ECC key
//            inputInterface, The interface through the message has been
//                            received (i.e..the interface in which to direct
//                            packet to reach the destination)
//            expireTime,   Life time of the route
//            e2eKey, End-to-end symmetric key. Must NOT be NULL.
//            retrialAtSource, true if this is a source doing retries
// RETURN   : The route just modified or created
//--------------------------------------------------------------------
static
AnodrRouteEntry* AnodrReplaceInsertRouteTable(
    Node *node,
    AnodrRoutingTable* routeTable,
    NodeAddress destAddr,
    byte *seqNum,  // = global trapdoor
    AnodrOnion *inputOnion,
    AnodrOnion *onionKey,
    AnodrOnion *outputOnion,
    byte *commitment,
    byte *upstreamOnetimePublicKey,
    AnodrPseudonym *pseudonymUpstream,
    byte *myOnetimePublicKey,
    int inputInterface,
    clocktype expireTime,
    byte *e2eKey,
    BOOL retrialAtSource)
{
    AnodrData* anodr = (AnodrData* )
            NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    int i = 0;
    AnodrRouteEntry* current = NULL;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head; current != NULL;current = current->next)
    {
        i++;

        if (destAddr != ANONYMOUS_IP)
        {
            // At the RREQ source
            if (current->remoteAddr == destAddr)
            {
                break;
            }
            continue;
        }
        // At RREQ forwarders
        if (!memcmp(current->seqNum.bits.ciphertext,
                    seqNum,
                    sizeof(AnodrGlobalTrapdoorSymKey)))
        {
            break;
        }
    }

    if (current == NULL)
    {
        if (i != routeTable->size)
        {
            char buffer[MAX_STRING_LENGTH];
            AnodrPrintRoutingTable(node, routeTable);
            sprintf(buffer,
                    "Node %u has inconsistent routing table"
                    " (item count = %u, but size = %u\n",
                    node->nodeId, i, routeTable->size);
            ERROR_ReportError(buffer);
        }

        // Insert at head
        (routeTable->size)++;
        current = (AnodrRouteEntry*) AnodrMemoryMalloc(anodr);
        memset(current, 0, sizeof(AnodrRouteEntry));

        current->prev = NULL;
        if (routeTable->head == NULL)
        {
            // The first entry
            current->next = NULL;
        }
        else
        {
            current->next = routeTable->head;
            current->next->prev = current;
        }
        routeTable->head = current;
    }//end of if (current == NULL)


    // Now set the values
    current->remoteAddr = destAddr;
    current->dest = FALSE;
    memcpy(current->seqNum.bits.ciphertext,
           seqNum,
           sizeof(AnodrGlobalTrapdoorSymKey));
    if (inputOnion != NULL)
    {
        Assign128BitPseudonym(&current->inputOnion, inputOnion);
    }
    if (onionKey != NULL)
    {
#ifdef ASR_PROTOCOL
        // 128-bit TBO key.
        // In ANODR, this key is per-node based
        // (each node only has 1 such key to use in the entire network
        //lifetime)
        // In ASR, this key is per-flood based
        //(each onion/RREQ flood must have a different such key: a one-time
        //pad)
        Assign128BitPseudonym(&current->onionKey, onionKey);
#else
        Assign128BitPseudonym(&anodr->onionKey, onionKey);
#endif
    }
    if (outputOnion != NULL)
    {
        Assign128BitPseudonym(&current->outputOnion, outputOnion);
    }
    if (commitment != NULL)
    {
        memcpy(current->commitment, commitment, b2B(AES_BLOCKLENGTH));
    }
    memcpy(current->committed, ANODR_INVALID_PSEUDONYM,b2B(AES_BLOCKLENGTH));
    if (upstreamOnetimePublicKey != NULL)
    {
        memcpy(current->upstreamOnetimePublicKey,
               upstreamOnetimePublicKey,
               b2B(QUALNET_ECC_PUBLIC_KEYLENGTH));
    }
    if (myOnetimePublicKey != NULL)
    {
        memcpy(current->myOnetimePublicKey,
               myOnetimePublicKey,
               b2B(QUALNET_ECC_PUBLIC_KEYLENGTH));
    }
    if (pseudonymUpstream != NULL)
    {
        Assign128BitPseudonym(&current->pseudonymUpstream,pseudonymUpstream);
    }
    memcpy(current->pseudonymDownstream.bits,
           ANODR_INVALID_PSEUDONYM, b2B(ANODR_PSEUDONYM_LENGTH));
    current->inputInterface = inputInterface;
    current->outputInterface = ANY_INTERFACE;
    current->expireTime = expireTime;
    current->activated = FALSE;
    memcpy(current->e2eKey, e2eKey, b2B(ANODR_AES_KEYLENGTH));
    if (!retrialAtSource)
    {
        current->rreqRetry = 0;
    } // else keep the entry unchanged
    current->unicastRrepRetry = 0;
    current->unicastRerrRetry = 0;
    current->unicastDataRetry = 0;
    return current;
}


//--------------------------------------------------------------------
// FUNCTION : AnodrDeleteRouteEntry
// PURPOSE  : Remove an entry from the route table
// ARGUMENTS: node, The node deleting the route entry
//            toFree, The route entry to be deleted
//            routeTable, Anodr routing table
// RETURN   : None
//--------------------------------------------------------------------

static
void AnodrDeleteRouteEntry(
         Node* node,
         AnodrRouteEntry* toFree,
         AnodrRoutingTable* routeTable)
{
    AnodrData* anodr = (AnodrData* )
            NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrRouteEntry* current = NULL;

    // Just do a sequential scan over the VCI table
    for (current = routeTable->head;current != NULL; current = current->next)
    {
        if (current == toFree)
        {
            break;
        }
    }

    ERROR_Assert(current != NULL, "Try to delete a non-existent"
                                  " route entry\n");

    if (current == routeTable->head)
    {
        routeTable->head = current->next;
    }
    else
    {
        if (current->next != NULL)
        {
            current->next->prev = current->prev;
        }
        current->prev->next = current->next;
    }

    if (DEBUG_ROUTE_TABLE)
    {
        char time[MAX_STRING_LENGTH];
        char seqNum[MAX_STRING_LENGTH];
        DebugPrint128BitInHex(seqNum, current->seqNum.bits.ciphertext);
        TIME_PrintClockInSecond(node->getNodeTime(), time);

        printf("Node %u deleted entry with seqNum=%s... at %s\n",
               node->nodeId, seqNum,time);
        AnodrPrintRoutingTable(node, routeTable);
    }

    AnodrMemoryFree(anodr, toFree);
    --(routeTable->size);

    // Future optimization: the last entry toward certain destination
    // node should be marked as invalid rather than deleted, because
    // the end-to-end key (e2eKey) should be kept.
}


//--------------------------------------------------------------------
// FUNCTION : AnodrTransmitData
// PURPOSE  : Forward the data packet to the next hop
// ARGUMENTS: node, The node which is transmitting or forwarding data
//            msg,  The packet to be forwarded
//            pseudonym, the pseudonym to be used to route towards the dest
//            reverseDir, FALSE if anodr-src=>anodr-dest, TRUE otherwise
//            interfaceIndex, the outgoing interface
// RETURN   : None
//--------------------------------------------------------------------

static
void AnodrTransmitData(
         Node* node,
         Message* msg,
         AnodrPseudonym *pseudonym,
         BOOL reverseDir,
         int interfaceIndex)
{
    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, msg, 'S');
    }

    if (DEBUG >= 2)
    {
        char pseudonymStr[MAX_STRING_LENGTH] = DEFAULT_STRING;

        DebugPrint128BitInHex(pseudonymStr, pseudonym->bits);
        printf("Node %u is sending DATA packet with pseudonym %s"
               "on interface %u\n",
               node->nodeId, pseudonymStr, interfaceIndex);
    }

    char *ptr = MESSAGE_ReturnPacket(msg);
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;
    AnodrPseudonym *nym = (AnodrPseudonym *)(ptr + IpHeaderSize(ipHeader));
    // Update the Virtual Circuit Pseudonym
    Assign128BitPseudonym(nym, pseudonym);

    NetworkIpSendPacketToMacLayer(
        node,
        msg,
        interfaceIndex,
#ifdef SIMULATE_ANONYMOUS_DATA_UNICAST
        reverseDir?
        *(NodeAddress *)(pseudonym->bits+4):
        *(NodeAddress *)pseudonym
#else
        ANY_IP
#endif
        );

#ifdef DATA_AACK
    // Insert into buffer under the ANONYMOUS_IP item
    AnodrInsertBuffer(
        node,
        MESSAGE_Duplicate(node, msg),
        ANONYMOUS_IP,
        pseudonym,
        &anodr->msgBuffer);

    // Schedule the timer to check the network layer DATA-AACK
    AnodrSetTimer(node,
                  MSG_NETWORK_CheckDataAck,
                  ANY_DEST,
                  pseudonym,
                  interfaceIndex,
                  2*ANODR_NODE_TRAVERSAL_TIME);
#endif // DATA_AACK
}


//--------------------------------------------- -----------------------
// FUNCTION : AnodrFloodRREQ
// PURPOSE  : Function to flood RREQ in all interfaces
// ARGUMENTS: node, The node which is flooding RREQ
//            type, RREQ or RREQ_SYMKEY
//            destAddr,only meaningful at source, ANY_DEST at immediate nodes
//            seqNum, sequence number = global trapdoor
//            outputOnion, the TBO in the packet
//            pk_onetime, my one-time ECC public key Q for my RREQ downstream
//            ttl, time-to-live to control flooding range
//            chkRplyDelay, period to wait for the reply
//            isRelay, is this a RREQ being relayed
// RETURN   : None
//--------------------------------------------------------------------
static
void AnodrFloodRREQ(
         Node* node,
         char type,   // ANODR_RREQ_SYMKEY or ANODR_RREQ,
         NodeAddress destAddr,
         byte *seqNum,
         AnodrOnion *outputOnion,
         byte *pk_onetime,
         int ttl,
         clocktype chkRplyDelay,
         BOOL isRelay)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    Message* newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0,
                                    MSG_MAC_FromNetwork);
    AnodrRreqPacket* rreqPkt = NULL;
    AnodrRreqSymKeyPacket* rreqSymKeyPkt = NULL;
    int i = 0;
    NetworkDataIp* ip = (NetworkDataIp *) node->networkData.networkVar;

    // Allocate the route request packet
    if (type == ANODR_RREQ)
    {
        MESSAGE_PacketAlloc(
            node,
            newMsg,
            sizeof(AnodrRreqPacket),
            TRACE_ANODR);
        rreqPkt = (AnodrRreqPacket *) MESSAGE_ReturnPacket(newMsg);

        rreqPkt->type = type;
        memcpy(rreqPkt->globalTrapdoor.bits.ciphertext,
               seqNum,
               sizeof(AnodrGlobalTrapdoor));
        Assign128BitPseudonym(&rreqPkt->onion, outputOnion);

#ifdef DO_ECC_CRYPTO
        memcpy(rreqPkt->onetimePubKey,
               pk_onetime,
               b2B(QUALNET_ECC_PUBLIC_KEYLENGTH));
#endif // DO_ECC_CRYPTO set pk_{onetime}
    }
    else
    {
        MESSAGE_PacketAlloc(
            node,
            newMsg,
            sizeof(AnodrRreqSymKeyPacket),
            TRACE_ANODR);
        rreqSymKeyPkt =(AnodrRreqSymKeyPacket *)MESSAGE_ReturnPacket(newMsg);

        rreqSymKeyPkt->type = type;
        memcpy(rreqSymKeyPkt->globalTrapdoor.bits.ciphertext,
               seqNum,
               sizeof(AnodrGlobalTrapdoorSymKey));
        Assign128BitPseudonym(&rreqSymKeyPkt->onion, outputOnion);

#ifdef DO_ECC_CRYPTO
        memcpy(rreqSymKeyPkt->onetimePubKey,
               pk_onetime,
               b2B(QUALNET_ECC_PUBLIC_KEYLENGTH));
#endif // DO_ECC_CRYPTO set pk_{onetime}
    }

    for (i = 0; i < node->numberInterfaces; i++)
    {
        IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];
        if (intfInfo->routingProtocolType == ROUTING_PROTOCOL_ANODR)
        {
            clocktype delay = (clocktype)
                (RANDOM_erand(anodr->jitterSeed) * ANODR_BROADCAST_JITTER);

            if (DEBUG_ANODR_TRACE)
            {
                AnodrPrintTrace(node, newMsg, 'S');
            }

            NetworkIpSendRawMessageToMacLayerWithDelay(
                node,
                MESSAGE_Duplicate(node, newMsg),
                ANONYMOUS_IP,           // global source
                ANY_DEST,               // global recipient
                IPTOS_PREC_INTERNETCONTROL,
                IPPROTO_ANODR,
                ttl,
                i,
                ANY_IP,         // the entire neighborhood
                delay);

            if (DEBUG >= 2)
            {
                char clockStr[MAX_STRING_LENGTH];
                TIME_PrintClockInSecond(delay, clockStr);
                printf("\tsending packet out on interface %u\n"
                    "\tRREQ jitter %s\n", i, clockStr);
            }
        }//end of if (intfInfo->routingProtocolType == ROUTING_PROTOCOL_ANODR)
    }//end of for


    // The RREQ packet has been copied and broadcasted to all the interfaces
    // so destroy the initially allocated message

    anodr->lastBroadcastSent = node->getNodeTime();

    // Set the CheckReply timer
    if (chkRplyDelay)
    {
        if (DEBUG >= 2)
        {
            printf("Node %u is setting timer MSG_NETWORK_CheckReplied\n",
                node->nodeId);
        }

        AnodrSetTimer(
            node,
            MSG_NETWORK_CheckReplied,
            destAddr,
            type == ANODR_RREQ? &rreqPkt->onion : &rreqSymKeyPkt->onion,
            ANY_INTERFACE,
            (clocktype) chkRplyDelay);
    }
    MESSAGE_Free(node, newMsg);
}

//--------------------------------------------------------------------
// FUNCTION     : AnodrInitiateRREQ
// PURPOSE      : Initiate a Route Request packet when no route to
//                destination is known
// PARAMETERS   : node, the node which is sending the Route Request
//                destAddr, the destination to which a route Anodr is
//                          looking for
//                rtEntry, NULL for no information towards destAddr
// RETURN       : None
//--------------------------------------------------------------------

static
void AnodrInitiateRREQ(Node* node,
                       NodeAddress destAddr,
                       AnodrRouteEntry *rtEntry)
{
    // A node floods a RREQ when it determines that it needs a route to
    // a destination and does not have one available.  This can happen
    // if the destination is previously unknown to the node, or if a
    // previously valid route to the destination expires or is broken
    // AODV draft Sec: 8.3
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    int ttl = ANODR_NET_DIAMETER;
    AnodrGlobalTrapdoor sourceGlobalTrapdoor = {{DEFAULT_STRING}};
    AnodrOnion onionCore = {DEFAULT_STRING};
    AnodrOnion onionKey = {DEFAULT_STRING};
    AnodrOnion outputOnion = {DEFAULT_STRING};
    clocktype expireTime = node->getNodeTime() + ANODR_FLOOD_RECORD_TIME;
    AnodrPseudonym sourcePseudonym = {DEFAULT_STRING};
    byte newE2eKey[b2B(ANODR_AES_KEYLENGTH)] = DEFAULT_STRING;
    byte *commitment = NULL;

    // Translate "destAddr" to global trapdoor,
    // Node addresses are never used in communication in ANODR
    SetGlobalTrapdoor(node,
                      anodr,
                      (byte *)&sourceGlobalTrapdoor,
                      destAddr,
                      &commitment,
                      rtEntry? rtEntry->e2eKey : NULL,
                      newE2eKey);
    if (DEBUG)
    {
        char address[MAX_STRING_LENGTH] = DEFAULT_STRING;
        IO_ConvertIpAddressToString(destAddr, address);
        printf("Node %u initRREQ(): Set the global trapdoor for %s\n",
               node->nodeId, address);
    }

    // Generate the onion
    Generate128BitPRN(node, onionCore.bits);
#ifdef ASR_PROTOCOL
    // 128-bit TBO key.
    // In ANODR, this key is per-node based
    // (each node only has 1 such key to use in the entire network lifetime)
    // In ASR, this key is per-flood based
    // (each onion/RREQ flood must have a different such key: a one-time pad)
    Generate128BitPRN(node, onionKey.bits);
#else // ASR_PROTOCOL
    Assign128BitPseudonym(&onionKey, &anodr->onionKey);
#endif // ASR_PROTOCOL
    ProcessOnion(node, &onionCore, &onionKey, &outputOnion);

    if (DEBUG >= 2)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;;
        char seq[MAX_STRING_LENGTH] = DEFAULT_STRING;;
        char tbo[MAX_STRING_LENGTH] = DEFAULT_STRING;;
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        DebugPrint128BitInHex(seq, sourceGlobalTrapdoor.bits.ciphertext);
        DebugPrint128BitInHex(tbo, outputOnion.bits);
        printf("Node %u initiating RREQ\n\t"
                "seq# = %s...\n\ttbo = %s\n\t\tat %s\n",
               node->nodeId, seq, tbo, clockStr);
    }

    byte *pk_onetime = NULL;
#ifdef DO_ECC_CRYPTO
    // In real implementation, each ANODR RREQ sender MUST generate
    // a new temporary ECC public key per RREQ forwarding.
    // In other words, the pk_{onetime} should be different per each
    // RREQ packet.
    //
    // However, here we are merely doing simulation.  Let's use
    // the node's permanent public key instead.  That is, Q.x Q.y Q.z.
    byte myOnetimePubKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
    int i;
    for (i=0; i<3; i++)
    {
        mpi_to_bitstream(myOnetimePubKey + i*b2B(QUALNET_ECC_KEYLENGTH),
                         b2B(QUALNET_ECC_KEYLENGTH),
                         anodr->eccKey[7+i],
                         1);
    }
    pk_onetime = myOnetimePubKey;
#endif // DO_ECC_CRYPTO per-hop one-time public key

    // Maintain the route table
    memcpy(sourcePseudonym.bits, ANODR_SRC_TAG, sizeof(AnodrPseudonym));
    AnodrReplaceInsertRouteTable(node,
                                 &anodr->routeTable,
                                 destAddr,
                                 sourceGlobalTrapdoor.bits.ciphertext,
                                 &onionCore,
                                 &onionKey,
                                 &outputOnion,
                                 commitment,
                                 NULL,  // upstreamOnetimePublicKey
                                 &sourcePseudonym,  // pseudonymUpstream,
                                 pk_onetime,  // myOnetimePublicKey,
                                 CPU_INTERFACE, // inputInterface
                                 expireTime,
                                 rtEntry? rtEntry->e2eKey : newE2eKey,
                                 FALSE);

    // The message will be broadcasted to all the interfaces which are
    // running Anodr as the routing protocol
    AnodrFloodRREQ(
        node,
        rtEntry? ANODR_RREQ_SYMKEY : ANODR_RREQ,
        destAddr,
        sourceGlobalTrapdoor.bits.ciphertext,
        &outputOnion,
        pk_onetime,
        ttl,
        ttl * 2 * ANODR_NODE_TRAVERSAL_TIME,
        FALSE);

    // Increase the statistical variable to store the number of
    // request sent
    anodr->stats.numRequestInitiated++;
}

//--------------------------------------------------------------------
// FUNCTION: AnodrRetryRREQ
// PURPOSE:  Send RREQ again after not receiving any RREP
// ARGUMENTS: node, the node sending rreq
//            destAddr, the destination for which rreq should be
//                      rebroadcasted
// RETURN:    None
//--------------------------------------------------------------------

static
void AnodrRetryRREQ(Node* node,
                    NodeAddress destAddr)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    AnodrRouteEntry *rtEntry = AnodrCheckSent(destAddr, &anodr->routeTable);
    int ttl = ANODR_NET_DIAMETER;
    AnodrGlobalTrapdoor sourceGlobalTrapdoor = {{DEFAULT_STRING}};
    AnodrOnion onionCore = {DEFAULT_STRING};
    AnodrOnion onionKey = {DEFAULT_STRING};
    AnodrOnion outputOnion = {DEFAULT_STRING};
    clocktype expireTime = node->getNodeTime() + ANODR_FLOOD_RECORD_TIME;
    AnodrPseudonym sourcePseudonym = {DEFAULT_STRING};
    byte *commitment = NULL;

    ERROR_Assert(rtEntry != NULL,"Sent node must have entry of destinatoin");

    // Translate "destAddr" to global trapdoor,
    // Node addresses are never used in communication in ANODR
    SetGlobalTrapdoor(node,
                      anodr,
                      (byte *)&sourceGlobalTrapdoor,
                      destAddr,
                      &commitment,
                      rtEntry->e2eKey,
                      NULL);
    if (DEBUG >= 2)
    {
        char address[MAX_STRING_LENGTH] = DEFAULT_STRING;
        IO_ConvertIpAddressToString(destAddr, address);
        printf("Node %u: RREQ RETRY %d: Set the global trapdoor for %s\n",
               node->nodeId, rtEntry->rreqRetry, address);
    }

    // Generate the onion:
    // a new RREQ packet for each flooding, even for the same dest
    Generate128BitPRN(node, onionCore.bits);
#ifdef ASR_PROTOCOL
    // 128-bit TBO key.
    // In ANODR, this key is per-node based
    // (each node only has 1 such key to use in the entire network lifetime)
    // In ASR, this key is per-flood based
    // (each onion/RREQ flood must have a different such key: a one-time pad)
    Generate128BitPRN(node, onionKey.bits);
#else // ASR_PROTOCOL
    byte dummy[b2B(ANODR_AES_KEYLENGTH)];
    Generate128BitPRN(node, dummy); // for pseudorandom sync
    Assign128BitPseudonym(&onionKey, &anodr->onionKey);
#endif // ASR_PROTOCOL
    ProcessOnion(node, &onionCore, &onionKey, &outputOnion);

    if (DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char seq[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char tbo[MAX_STRING_LENGTH]= DEFAULT_STRING;
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        DebugPrint128BitInHex(seq, sourceGlobalTrapdoor.bits.ciphertext);
        DebugPrint128BitInHex(tbo, outputOnion.bits);
        printf("Node %u retrying RREQ\n\t"
               "seq# = %s...\n\ttbo = %s\n\t\tat %s\n",
                node->nodeId, seq, tbo, clockStr);
    }

    byte *pk_onetime = NULL;
#ifdef DO_ECC_CRYPTO
    // In real implementation, each ANODR RREQ sender MUST generate
    // a new temporary ECC public key per RREQ forwarding.
    // In other words, the pk_{onetime} should be different per each
    // RREQ packet.
    //
    // However, here we are merely doing simulation.  Let's use
    // the node's permanent public key instead.  That is, Q.x Q.y Q.z.
    byte myOnetimePubKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
    int i;
    for (i=0; i<3; i++)
    {
        mpi_to_bitstream(myOnetimePubKey + i*b2B(QUALNET_ECC_KEYLENGTH),
                         b2B(QUALNET_ECC_KEYLENGTH),
                         anodr->eccKey[7+i],
                         1);
    }
    pk_onetime = myOnetimePubKey;
#endif // DO_ECC_CRYPTO per-hop one-time public key

    // Maintain the route table
    memcpy(sourcePseudonym.bits, ANODR_SRC_TAG, sizeof(AnodrPseudonym));
    AnodrReplaceInsertRouteTable(node,
                                 &anodr->routeTable,
                                 destAddr,
                                 sourceGlobalTrapdoor.bits.ciphertext,
                                 &onionCore,
                                 &onionKey,
                                 &outputOnion,
                                 commitment,
                                 NULL,  // upstreamOnetimePublicKey
                                 &sourcePseudonym,  // pseudonymUpstream,
                                 pk_onetime,  // myOnetimePublicKey,
                                 CPU_INTERFACE, // inputInterface
                                 expireTime,
                                 rtEntry->e2eKey,
                                 TRUE);

    // The message will be broadcasted to all the interfaces which are
    // running Anodr as the routing protocol
    AnodrFloodRREQ(
        node,
        rtEntry? ANODR_RREQ_SYMKEY : ANODR_RREQ,
        destAddr,
        sourceGlobalTrapdoor.bits.ciphertext,
        &outputOnion,
        pk_onetime,
        ttl,
        ttl * 2 * ANODR_NODE_TRAVERSAL_TIME,
        FALSE);

    anodr->stats.numRequestResent++;
}


//--------------------------------------------------------------------
// FUNCTION: AnodrRelayRREQ
// PURPOSE:  Forward (re-broadcast) the RREQ
// ARGUMENTS: node, The node forwarding the Route Request
//            type, RREQ or RREQ_SYMKEY
//            msg,The Rreq packet
//            globalTrapdoor,pointer to the global trap door information of
//            a node
//            outputOnion,the TBO in the packet
//            pk_onetime, my one-time ECC public key Q for my RREQ downstream
//            ttl, time-to-live to control flooding range
// RETURN:    None


static
void AnodrRelayRREQ(
         Node* node,
         char type,
         Message* msg,
         byte *globalTrapdoor,
         AnodrOnion *outputOnion,
         byte *pk_onetime,
         int ttl)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    if (DEBUG >= 2)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char seq[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char tbo[MAX_STRING_LENGTH]= DEFAULT_STRING;
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        DebugPrint128BitInHex(seq, globalTrapdoor);
        DebugPrint128BitInHex(tbo, outputOnion->bits);
        printf("Node %u relaying RREQ\n\t"
                "seq# = %s...\n\ttbo = %s\n\t\tat %s\n",
                node->nodeId, seq, tbo, clockStr);
    }

    // The message will be broadcasted to all the interfaces which are
    // running Anodr as there routing protocol

    AnodrFloodRREQ(
        node,
        type,
        ANY_DEST,
        globalTrapdoor,
        outputOnion,
        pk_onetime,
        ttl,
        0,  // No wait for Route Reply in this case
        TRUE);

    anodr->stats.numRequestRelayed++;
}

//--------------------------------------------------------------------
// FUNCTION: AnodrInitiateRREP
// PURPOSE:  Initiating route reply message
// ARGUMENTS: node, The node sending the route reply
//            anodr, Anodr main data structure
//            msg,  Received Route request message
//            onion,the onion for the node
//            rtEntry, The proper route entry.
// RETURN:    None
//--------------------------------------------------------------------

static void
AnodrInitiateRREP(Node* node,
                  AnodrData* anodr,
                  Message* msg,
                  AnodrOnion *onion,
                  AnodrRouteEntry *rtEntry)
{
    AnodrPseudonym *pseudonym = &rtEntry->pseudonymUpstream;
    byte *anonymousProof = rtEntry->committed;

    Message* newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_FromNetwork);
    MESSAGE_PacketAlloc(node, newMsg, sizeof(AnodrRrepPacket), TRACE_ANODR);
    AnodrRrepPacket* rrepPkt =
        (AnodrRrepPacket *) MESSAGE_ReturnPacket(newMsg);

    rrepPkt->type = ANODR_RREP;
    // Set up the AES plaintext (pr_dest, onion)
    // pr_test (anonymous proof) = K_reveal
    memcpy(rrepPkt->rrepPayload.aesPlaintext.anonymousProof,
           anonymousProof,
           b2B(AES_BLOCKLENGTH));
    // RREP onion is from the corresponding RREQ onion
    Assign128BitPseudonym(&rrepPkt->rrepPayload.aesPlaintext.onion,
                          onion);
#ifdef SIMULATE_ANONYMOUS_DATA_UNICAST
    // If underlying MAC doesn't support anonymous unicast,
    // the 1st 32-bit of the pseudonym holds downstream addr,
    // the 2nd 32-bit of the pseudonym holds upstream addr.
    *(NodeAddress *)pseudonym =
        NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
    *(NodeAddress *)(pseudonym->bits+4) =
        *(NodeAddress *)&(rtEntry->inputOnion);
#endif // SIMULATE_ANONYMOUS_DATA_UNICAST

    if (DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char onion[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char nym[MAX_STRING_LENGTH]= DEFAULT_STRING;

        DebugPrint128BitInHex(onion,
                              rrepPkt->rrepPayload.aesPlaintext.onion.bits);
        DebugPrint128BitInHex(nym, pseudonym->bits);
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u sends back RREP at %s "
                "on interface %u\n\ttbo = %s\n\tnym = %s\n",
                node->nodeId, clockStr, rtEntry->inputInterface, onion, nym);
    }

    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, newMsg, 'S');
    }

#ifdef DO_AES_CRYPTO
    // Use the pseudonym as K_seed to encrypt RREP payload
    if (anodr->doCrypto)
    {
        CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
            cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
        cipher_setiv(cipher, NULL, 0 ); // Zero IV
        cipher_setkey(cipher, pseudonym->bits, sizeof(AnodrPseudonym));
        cipher_encrypt(cipher,
                       rrepPkt->rrepPayload.aesCiphertext,
                       (byte *)&rrepPkt->rrepPayload.aesPlaintext,
                       b2B(2*AES_BLOCKLENGTH));
        cipher_close(cipher);
    }
#endif // DO_AES_CRYPTO  encrypt RREP payload
#ifdef DO_ECC_CRYPTO
    // Now encrypt the pseudonym using RREQ upstream's one-time public key
    //Assign128BitPseudonym(&rrepPkt->test, pseudonym);
    if (anodr->doCrypto)
    {
        AnodrEccPubKeyEncryption(anodr,
                                 rrepPkt->nym.encryptedPseudonym,
                                 rtEntry->upstreamOnetimePublicKey,
                                 *(NodeAddress *)onion->bits,
                                 pseudonym->bits,
                                 ANODR_PSEUDONYM_LENGTH);
    }
#else // DO_ECC_CRYPTO
    Assign128BitPseudonym(&rrepPkt->nym.pseudonym, pseudonym);
#endif // DO_ECC_CRYPTO  encrypt RREP K_seed

    NetworkIpSendRawMessageToMacLayer(
        node,
        newMsg,
        ANONYMOUS_IP,
        ANY_DEST,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ANODR,
        1,
        rtEntry->inputInterface,
        ANY_IP);        // the entire neighborhood

    anodr->stats.numReplyInitiatedAsDest++;

#ifdef RREP_AACK
    if (anodr->doRrepAack)
    {
    // Schedule the timer to check the network layer RREP-ACK
    AnodrSetTimer(node,
              MSG_NETWORK_CheckRrepAck,
              ANONYMOUS_IP,
              pseudonym,
              rtEntry->inputInterface,
              2*ANODR_NODE_TRAVERSAL_TIME);
    }
#endif
}

//--------------------------------------------------------------------
// FUNCTION: AnodrRelayRREP
// PURPOSE:  Forward the RREP packet
// ARGUMENTS: node, the node relaying reply
//            row, pointer to the matching row
// RETURN:   none
//--------------------------------------------------------------------

static void
AnodrRelayRREP(Node* node,
               AnodrRouteEntry* row)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    AnodrPseudonym *pseudonym = &row->pseudonymUpstream;
    byte *anonymousProof = row->committed;
    int interfaceIndex = row->inputInterface;

    Message* newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_FromNetwork);
    MESSAGE_PacketAlloc(node, newMsg, sizeof(AnodrRrepPacket), TRACE_ANODR);
    AnodrRrepPacket* rrepPkt =(AnodrRrepPacket*)MESSAGE_ReturnPacket(newMsg);

    rrepPkt->type = ANODR_RREP;
    // Set up the AES plaintext (pr_dest, onion)
    memcpy(rrepPkt->rrepPayload.aesPlaintext.anonymousProof,
           anonymousProof,
           b2B(AES_BLOCKLENGTH));
    // the RREP outgoing onion = the RREQ input onion
    Assign128BitPseudonym(&rrepPkt->rrepPayload.aesPlaintext.onion,
                          &row->inputOnion);
    // Let me choose the route pseudonym used between me
    // and my RREQ upstream (= my RREP downstream)
    Generate128BitPRN(node, pseudonym->bits);
#ifdef SIMULATE_ANONYMOUS_DATA_UNICAST
    // If underlying MAC doesn't support anonymous unicast,
    // the 1st 32-bit of the pseudonym holds downstream addr,
    // the 2nd 32-bit of the pseudonym holds upstream addr.
    *(NodeAddress *)pseudonym =
        NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE);
    *(NodeAddress *)(pseudonym->bits+4) =
        *(NodeAddress *)&(row->inputOnion);
#endif // SIMULATE_ANONYMOUS_DATA_UNICAST

#ifdef DO_AES_CRYPTO
    // Use the pseudonym as K_seed to encrypt RREP payload
    if (anodr->doCrypto)
    {
        CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
        cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
        cipher_setiv(cipher, NULL, 0); // Zero IV
        cipher_setkey(cipher,
                      pseudonym->bits,
                      sizeof(AnodrPseudonym));
        cipher_encrypt(cipher,
                       rrepPkt->rrepPayload.aesCiphertext,
                       (byte *)&rrepPkt->rrepPayload.aesPlaintext,
                       b2B(2*AES_BLOCKLENGTH));
        cipher_close(cipher);
    }
#endif // DO_AES_CRYPTO encrypt RREP payload
#ifdef DO_ECC_CRYPTO
    // Now encrypt the pseudonym using RREQ upstream's one-time public key
    //Assign128BitPseudonym(&rrepPkt->test, pseudonym);
    if (anodr->doCrypto)
    {
        AnodrEccPubKeyEncryption(anodr,
                                 rrepPkt->nym.encryptedPseudonym,
                                 row->upstreamOnetimePublicKey,
                                 *(NodeAddress *)row->inputOnion.bits,
                                 pseudonym->bits,
                                 ANODR_PSEUDONYM_LENGTH);
    }
#else // DO_ECC_CRYPTO
    Assign128BitPseudonym(&rrepPkt->nym.pseudonym, pseudonym);
#endif // DO_ECC_CRYPTO encrypt RREP K_seed

    if (DEBUG >= 2)
    {
        char onion[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char clockStr[MAX_STRING_LENGTH]= DEFAULT_STRING;
        char nym[MAX_STRING_LENGTH]= DEFAULT_STRING;

        DebugPrint128BitInHex(onion, row->inputOnion.bits);
        DebugPrint128BitInHex(nym, pseudonym->bits);
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u relays RREP (inputOnion = %s nym = %s)"
                " at %s on interface %u\n",
                node->nodeId, onion, nym, clockStr, row->inputInterface);
    }

    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, newMsg, 'S');
    }

    NetworkIpSendRawMessageToMacLayer(
        node,
        newMsg,
        ANONYMOUS_IP,
        ANY_DEST,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ANODR,
        1,
        interfaceIndex,
        ANY_IP);  // the entire neighborhood

    anodr->stats.numReplyForwarded++;

#ifdef RREP_AACK
    if (anodr->doRrepAack)
    {
    // Schedule the timer to check the network layer RREP-ACK
    AnodrSetTimer(node,
              MSG_NETWORK_CheckRrepAck,
              ANONYMOUS_IP,
              pseudonym,
              row->inputInterface,
              2*ANODR_NODE_TRAVERSAL_TIME);
    }
#endif
}

#if defined(RREP_AACK) || defined(RERR_AACK) || defined(DATA_AACK)

//--------------------------------------------------------------------
// FUNCTION:  AnodrSendUnicastAnonymousACK
// PURPOSE:   To generate an Anonymous ACK in response to a RERR/RREP/DATA
// ARGUMENTS: node, the node generating the AACK
//            type,type of packet in response to which AACK is generated
//            RERR/RREP/DATA
// RETURN:    none
//--------------------------------------------------------------------

static void
AnodrSendUnicastAnonymousACK(Node *node,
                             AnodrRouteEntry *matchingRow,
                             char type)
{
    AnodrData* anodr =
        (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    Message* newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_FromNetwork);
    MESSAGE_PacketAlloc(node, newMsg, sizeof(AnodrAackPacket), TRACE_ANODR);
    AnodrAackPacket* rackPkt =
        (AnodrAackPacket *)MESSAGE_ReturnPacket(newMsg);

    AnodrPseudonym *pseudonym = NULL;
    int interface = ANY_INTERFACE;
    if (type == ANODR_RREP)
    {
    if (!anodr->doRrepAack)
    {
        return;
    }
        rackPkt->type = ANODR_RREP_AACK;
        pseudonym = &matchingRow->pseudonymDownstream;
        interface = matchingRow->outputInterface;
    }
    else if (type == ANODR_RERR)
    {
        rackPkt->type = ANODR_RERR_AACK;
        pseudonym = &matchingRow->pseudonymDownstream;
        interface = matchingRow->outputInterface;
    }
    else
    {
        rackPkt->type = ANODR_DATA_AACK;
        pseudonym = &matchingRow->pseudonymUpstream;
        interface = matchingRow->inputInterface;
    }
    Assign128BitPseudonym(&rackPkt->pseudonym, pseudonym);

    if (DEBUG >= 2)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char nym[MAX_STRING_LENGTH]  = DEFAULT_STRING;

        DebugPrint128BitInHex(nym, pseudonym->bits);
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u reply %s-AACK (nym = %s) at %s on interface %u\n",
               node->nodeId,
               type==ANODR_RREP?"RREP" : (type==ANODR_RERR? "RERR" : "DATA"),
                                         nym, clockStr, interface);
    }

    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, newMsg, 'S');
    }

    NetworkIpSendRawMessageToMacLayer(
        node,
        newMsg,
        ANONYMOUS_IP,
        ANY_DEST,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ANODR,
        1,
        matchingRow->outputInterface,
        ANY_IP);  // the entire neighborhood

    switch (type)
    {
        case ANODR_RREP:
            anodr->stats.numReplyAcked++;
            break;
        case ANODR_RERR:
            anodr->stats.numRerrAcked++;
            break;
        case ANODR_DUMMY:
            break;
        default:
            ERROR_ReportError("Unknown ANODR anonymous ACK type.\n");
    }
}
#endif // defined(RREP_AACK) || defined(RERR_AACK) || defined(DATA_AACK)

//--------------------------------------------------------------------
// FUNCTION: AnodrHandleRequest
// PURPOSE:  Processing procedure when RREQ is received
// ARGUMENTS: node, The node which has received the RREQ msg
//            msg,the message received for the node.
//            ttl,  The ttl of the message
//            interfaceIndex, The interface index through which
//                            the RREQ has been received.
// RETURN:    None
//--------------------------------------------------------------------

static
void AnodrHandleRequest(
         Node* node,
         Message* msg,
         int ttl,
         int interfaceIndex)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrRreqPacket* rreqPkt = (AnodrRreqPacket *) MESSAGE_ReturnPacket(msg);
    char type = rreqPkt->type;
    byte *seqNum = rreqPkt->globalTrapdoor.bits.ciphertext;
    AnodrRreqSymKeyPacket *rreqSymKeyPkt = NULL;
    BOOL isSymKey = FALSE;
    if (type == ANODR_RREQ_SYMKEY)
    {
        isSymKey = TRUE;
        rreqSymKeyPkt = (AnodrRreqSymKeyPacket *)rreqPkt;
    }
    byte *commitment = NULL;
    byte *upstreamOnetimePublicKey = NULL;

    AnodrRouteEntry *row = NULL;
    BOOL isActiveRoute = FALSE;

    byte decryptedGlobalTrapdoor[b2B(4*AES_BLOCKLENGTH)];
    int globalTrapdoorOpened = 0;
    int i = 0;

    anodr->stats.numRequestRecved++;

    // When a node receives a flooded RREQ, it first checks to determine
    // whether it has received a RREQ with the same SEQNUM
    // within at least the last FLOOD_RECORD_TIME milliseconds.
    // If such a RREQ has been received, the node silently discards the
    // newly received RREQ. AODV draft Sec: 8.5
    if (!AnodrCheckSeqNumExist(seqNum,
                               &anodr->routeTable,
                               &isActiveRoute))
    {
        AnodrOnion inputOnion = {DEFAULT_STRING};
        AnodrOnion onionKey = {DEFAULT_STRING};
        AnodrOnion outputOnion = {DEFAULT_STRING};
        clocktype expireTime =
            (clocktype) node->getNodeTime() + ANODR_FLOOD_RECORD_TIME;

        // This is not a duplicate packet so process the request

        if (DEBUG >= 2)
        {
            printf("Node %u: RREQ is not a duplicate, process it\n",
                   node->nodeId);
        }

        // Process the onion and the RREQ packet
        if (type == ANODR_RREQ)
        {
            commitment = rreqPkt->globalTrapdoor.commitment;
            Assign128BitPseudonym(&inputOnion, &rreqPkt->onion);
            upstreamOnetimePublicKey = rreqPkt->onetimePubKey;
        }
        else
        {
            commitment = rreqSymKeyPkt->globalTrapdoor.commitment;
            Assign128BitPseudonym(&inputOnion, &rreqSymKeyPkt->onion);
            upstreamOnetimePublicKey = rreqSymKeyPkt->onetimePubKey;
        }
#ifdef ASR_PROTOCOL
        // 128-bit TBO key.
        // In ANODR, this key is per-node based
        // (each node only has 1 such key to use in the entire network
        // lifetime)
        // In ASR, this key is per-flood based
        // (each onion/RREQ flood must have a different such key: a one-time
        //  pad)
        Generate128BitPRN(node, onionKey.bits);
#else // ASR_PROTOCOL
        Assign128BitPseudonym(&onionKey, &anodr->onionKey);
#endif // ASR_PROTOCOL
        ProcessOnion(node, &inputOnion, &onionKey, &outputOnion);

        // My one-time public key
        byte *pk_onetime = NULL;
#ifdef DO_ECC_CRYPTO
        // In real implementation, each ANODR RREQ sender MUST generate
        // a new temporary ECC public key per RREQ forwarding.
        // In other words, the pk_{onetime} should be different per each
        // RREQ packet.
        //
        // However, here we are merely doing simulation.  Let's use the
        // node's permanent public key as a placeholder to save the
        // simulation host's precious CPU.  (Q.x Q.y Q.z is the public key).
        byte myOnetimePubKey[b2B(QUALNET_ECC_PUBLIC_KEYLENGTH)];
        for (i=0; i<3; i++)
        {
            mpi_to_bitstream(myOnetimePubKey + i*b2B(QUALNET_ECC_KEYLENGTH),
                             b2B(QUALNET_ECC_KEYLENGTH),
                             anodr->eccKey[7+i],
                             1);
        }
        pk_onetime = myOnetimePubKey;
#endif // DO_ECC_CRYPTO per-hop one-time public key

        // Maintain the route table
        row = AnodrReplaceInsertRouteTable(
            node,
            &anodr->routeTable,
            ANONYMOUS_IP,
            seqNum,
            &inputOnion,
            &onionKey,
            &outputOnion,
            commitment,
            upstreamOnetimePublicKey,
            NULL,               // pseudonymUpstream,
            pk_onetime,         // myOnetimePublicKey,
            interfaceIndex,     // inputInterface
            expireTime,
            ANODR_INVALID_PSEUDONYM,
            FALSE);

        // Forward the RREQ unconditionally:
        // Even if I'm the destination, I will forward the RREQ as usual to
        // avoid being identified as the destination.  This is for protecting
        // RECIPIENT ANONYMITY.
        //
        // Moreover, all crypto overhead for global trapdoor opening
        // is paid after RREQ forwarding.
        // Thus the only crypto delay for RREQ is the onion processing delay.
        AnodrRelayRREQ(node,
                       type,
                       msg,
                       seqNum,
                       &outputOnion,
                       pk_onetime,
                       ttl);

        // Try to open the global trapdoor
#if defined(DO_RREQ_SYMKEY) && defined(DO_AES_CRYPTO)\
    && defined(DO_ECC_CRYPTO)
        if (type == ANODR_RREQ_SYMKEY)
        {
            if (anodr->doCrypto)
            {
                AnodrRouteEntry* current = NULL;

                // Just do a sequential scan over the VCI table
                for (current = anodr->routeTable.head;
                     current != NULL;
                     current = current->next)
                {
                    if (current->activated == TRUE)
                    {
                        // Try to use K_{AE}'s to decrypt the global trapdoor
                        CIPHER_HANDLE cipher =
                        // algo AES256 CFB mode in secure memory
                        cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
                        cipher_setiv(cipher, NULL, 0 ); // Zero IV
                        cipher_setkey(cipher,
                                      current->e2eKey,
                                      b2B(ANODR_AES_KEYLENGTH));
                        cipher_decrypt
                              (cipher,
                               decryptedGlobalTrapdoor,
                               rreqSymKeyPkt->globalTrapdoor.bits.ciphertext,
                               b2B(2*AES_BLOCKLENGTH));
                               cipher_close(cipher);

                        // Check if I'm the destination
                        if (!strncmp((const char *)decryptedGlobalTrapdoor,
                                     (char *)ANODR_DEST_TAG,
                                     b2B(AES_BLOCKLENGTH)))
                        {
                            // The node is the destination of the route
                            globalTrapdoorOpened = 1;
                            anodr->stats.numRequestRecvedAsDestWithSymKeyGlobalTrapdoor++;
                            // Remember the (optional) srcAddr
                            row->remoteAddr = *(NodeAddress *)
                                (decryptedGlobalTrapdoor +
                                 b2B(2*AES_BLOCKLENGTH));
                            row->dest = TRUE;
                            break;
                        }
                    } // end of if (current->activated == TRUE)
                } //end of for loop
            }  // end of if (anodr->doCrypto)
        } // end of if (type == ANODR_RREQ_SYMKEY)
        else  // type == RREQ
#endif //DO_RREQ_SYMKEY tries to open global trapdoor
      // using all active e2eKeys
#ifdef DO_ECC_CRYPTO
        {
            if (anodr->doCrypto)
            {
                // Now try to decrypt the global trapdoor
                AnodrEccPubKeyDecryption(node,
                                         decryptedGlobalTrapdoor,
                                         seqNum,
                                         4*AES_BLOCKLENGTH);

                // Check if I'm the destination
                if (!strncmp((const char *)decryptedGlobalTrapdoor,
                             (char *)ANODR_DEST_TAG,
                             b2B(AES_BLOCKLENGTH)))
                {
                    // The node is the destination of the route
                    globalTrapdoorOpened = 1;

                    // Remember the end-to-end key K_{AE}
                    memcpy(row->e2eKey,
                           decryptedGlobalTrapdoor + b2B(2*AES_BLOCKLENGTH),
                           b2B(AES_BLOCKLENGTH));

                    // Remember the (optional) srcAddr
                    row->remoteAddr = *(NodeAddress *)
                        (decryptedGlobalTrapdoor + b2B(3*AES_BLOCKLENGTH));
                    row->dest = TRUE;
                }
            } // end of if (anodr->doCrypto)
        } // type == RREQ
#endif // DO_ECC_CRYPTO tries to open global trapdoor

#ifndef DO_ECC_CRYPTO
        if (DEBUG_FAKE_GLOBALTRAPDOOR || !globalTrapdoorOpened)
        {
            // fake global trapdoor due to no ECC encryption
            memcpy(decryptedGlobalTrapdoor,
                   seqNum,
                   b2B(4*AES_BLOCKLENGTH));
            for (i = 0; i < node->numberInterfaces; i++)
            {
                // The node is the destination of the route
                if (NetworkIpIsMyIP(
                       node,
                       *((NodeAddress *)decryptedGlobalTrapdoor)))
                {
                    globalTrapdoorOpened = 1;
                    if (isSymKey)
                    {
                        anodr->stats.numRequestRecvedAsDestWithSymKeyGlobalTrapdoor++;
                        // Remember the (optional) srcAddr
                        row->remoteAddr = *(NodeAddress *)
                            (decryptedGlobalTrapdoor+b2B(2*AES_BLOCKLENGTH));
                        row->dest = TRUE;
                    }
                    else
                    {
                        // Remember the (optional) srcAddr
                        row->remoteAddr = *(NodeAddress *)
                            (decryptedGlobalTrapdoor+b2B(3*AES_BLOCKLENGTH));
                        row->dest = TRUE;
                    }
                    break;
                }
            }
        }
#endif

        if (globalTrapdoorOpened)
        {
            // The node is the DESTINATION
            if (DEBUG)
            {
                char address[MAX_STRING_LENGTH];

                printf("Node %d opens the global trapdoor\n", node->nodeId);
                if (DEBUG_ROUTE)
                {
                    IO_ConvertIpAddressToString(
                                            *((NodeAddress*)inputOnion.bits),
                                             address);
                    printf("\tfrom %s\n", address);
                }
            }

            anodr->stats.numRequestRecvedAsDest++;

            if (DEBUG >= 2)
            {
                printf("\ti'm the destination\n");
            }

            //
            // Route Reply generated by the DESTINATION
            //
            // Set inputInterface properly
            row->inputInterface = interfaceIndex;
            // Set committed to K_reveal
            memcpy(row->committed,
                   decryptedGlobalTrapdoor + b2B(AES_BLOCKLENGTH),
                   b2B(AES_BLOCKLENGTH));
            // Set the outgoing values to CPU driven track
            memcpy(row->pseudonymDownstream.bits,
                   ANODR_DEST_TAG,
                   sizeof(AnodrPseudonym));
            row->outputInterface = CPU_INTERFACE;
            // Choose the pseudonym between me and my RREQ upstream
            Generate128BitPRN(node, row->pseudonymUpstream.bits);

            //  Send RREP back
            AnodrInitiateRREP(
                node,
                anodr,
                msg,
                &inputOnion,
                row);
#ifdef RREP_AACK
        if (!anodr->doRrepAack)
        {
        row->activated = TRUE;
        }
#else
            row->activated = TRUE;
#endif
        } //end of if (globalTrapdoorOpened)
    }
    else
    {
        // If this RREQ already has been processed then silently discard the
        // message to avoid "broadcast storm"
        anodr->stats.numRequestDuplicate++;
        if (DEBUG >= 3)
        {
            printf("Node %u: RREQ already seen, drop it\n", node->nodeId);
        }
    }//end of if (!AnodrCheckSeqNumExist(seqNum,
     //          &anodr->routeTable,&isActiveRoute))
  }

//--------------------------------------------------------------------
// FUNCTION: AnodrHandleReply
// PURPOSE:  Processing procedure when RREP is received
// ARGUMENTS: node, the node received reply
//            msg,  Message containing rrep packet
//            interfaceIndex,the interface from which reply has been received
// RETURN:   TRUE: my RREP;  FALSE: none of my business
//--------------------------------------------------------------------

static BOOL
AnodrHandleReply(Node* node,
                      Message* msg,
                      int interfaceIndex)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrRrepPacket* rrepPkt = (AnodrRrepPacket *) MESSAGE_ReturnPacket(msg);
    AnodrRouteEntry* matchingRow = NULL;
    BOOL isActiveRt = FALSE;

#ifdef DO_ECC_CRYPTO
    // Now try to decrypt the pseudonym (i.e., the K_seed)
    if (anodr->doCrypto)
    {
        if (DEBUG >= 3)
        {
            byte buffer[MAX_STRING_LENGTH];
            int i;
            mpi_to_hexstr(buffer, anodr->eccKey[10], 1);
            printf("Node %u decrypts with sk.d = %s\n",
                   node->nodeId, buffer);
        }
        AnodrEccPubKeyDecryption(node,
                                 rrepPkt->nym.pseudonym.bits,
                                 rrepPkt->nym.encryptedPseudonym,
                                 ANODR_PSEUDONYM_LENGTH);
    }
#endif // DO_ECC_CRYPTO decrypts RREP K_seed
#ifdef DO_AES_CRYPTO
    // Use the pseudonym as K_seed to decrypt (pr_dest, TBO)
    if (anodr->doCrypto)
    {
        CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
        cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
        cipher_setiv(cipher, NULL, 0 ); // Zero IV
        cipher_setkey(cipher,
                      rrepPkt->nym.pseudonym.bits,
                      b2B(ANODR_PSEUDONYM_LENGTH));
        cipher_decrypt(cipher,
                       (byte *)&rrepPkt->rrepPayload.aesPlaintext,
                       rrepPkt->rrepPayload.aesCiphertext,
                       b2B(2*AES_BLOCKLENGTH));
        cipher_close(cipher);
    }
#endif // DO_AES_CRYPTO decrypts RREP payload

    matchingRow = AnodrCheckOutputOnionExist(
        &(rrepPkt->rrepPayload.aesPlaintext.onion),
        &anodr->routeTable,
        &isActiveRt);

    if (matchingRow == NULL)
    {
        // Other node's RREP, none of my business
        return FALSE;
    }

#ifdef DO_AES_CRYPTO
    if (anodr->doCrypto)
    {
        // Test commitment K_reveal(DEST_TAG) =?= anonymousProof(DEST_TAG).
        // ANODR is not vulnerable to intermediate node's RREP injection.
        memcpy(matchingRow->committed,
               rrepPkt->rrepPayload.aesPlaintext.anonymousProof,
               b2B(AES_BLOCKLENGTH));
        byte commitmentTest[b2B(AES_BLOCKLENGTH)];
        memcpy(commitmentTest, ANODR_DEST_TAG, b2B(AES_BLOCKLENGTH));

        // Use "anonymousProof" to encrypt commitmentTest,
        // if the result matches matchingRow->commitment, then okay.
        // Otherwise, the RREP is injected by an active adversary
        CIPHER_HANDLE cipher = // algo AES256 CFB mode in secure memory
            cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
        cipher_setiv(cipher, NULL, 0); // Zero IV
        cipher_setkey(cipher,
                      rrepPkt->rrepPayload.aesPlaintext.anonymousProof,
                      b2B(AES_BLOCKLENGTH));
        cipher_encrypt(cipher,
                       commitmentTest,
                       commitmentTest,
                       b2B(AES_BLOCKLENGTH));
        cipher_close(cipher);

        if (memcmp(commitmentTest,
                   matchingRow->commitment,
                   b2B(AES_BLOCKLENGTH)))
        {
            printf("Commitment not fulfilled."
                    " RREP injected by an active adversary.\n");
            return FALSE;
        }
    }
#endif // DO_AES_CRYPTO commitment fulfillment test

    anodr->stats.numReplyRecved++;

    if (DEBUG)
    {
        char onion[MAX_STRING_LENGTH];

        DebugPrint128BitInHex(onion,
                              rrepPkt->rrepPayload.aesPlaintext.onion.bits);
        printf("Node %u is an intermediate node of RREP"
                " with matching onion %s\n",
               node->nodeId, onion);
        if (DEBUG >= 2)
        {
            if (isActiveRt == TRUE)
            {
                printf("\tThe route is already active."
                       " My RREP upstream haven't got my"
                       " previous RREP-ACK and sent this RREP.\n");
            }
        }
    }

    // Share the pseudonym, establish a virtual circuit link
    Assign128BitPseudonym(&matchingRow->pseudonymDownstream,
                          &rrepPkt->nym.pseudonym);
    matchingRow->outputInterface = interfaceIndex;

#ifdef RREP_AACK
    // Send back RREP-AACK
    AnodrSendUnicastAnonymousACK(node, matchingRow, ANODR_RREP);
#endif

    if (memcmp(matchingRow->pseudonymUpstream.bits,
               ANODR_SRC_TAG,
               sizeof(AnodrPseudonym)) != 0)
    {
        // Intermediate RREP forwarder:
        // Forward the packet to the upstream of the route

        if (!memcmp(matchingRow->pseudonymUpstream.bits,
                   ANODR_INVALID_PSEUDONYM,
                   sizeof(AnodrPseudonym)))
        {
            AnodrRelayRREP(node, matchingRow);
#ifdef RREP_AACK
        if (!anodr->doRrepAack)
        {
        matchingRow->activated = TRUE;
        }
#else
            matchingRow->activated = TRUE;
#endif
        }
        else
        {
            // RREP already forwarded.
            // Being here means: my RREQ downstream / RREP upstream
            // missed my Anonymous ACK.
            // Since I've just re-sent the RREP-AACK, do nothing.
        }
    }
    else
    {
        // RREP received by the SOURCE
        if (DEBUG)
        {
            char onion[MAX_STRING_LENGTH];

            DebugPrint128BitInHex(
                onion,
                rrepPkt->rrepPayload.aesPlaintext.onion.bits);
            printf("Node %u is the SOURCE accepting RREP with onion %s\n",
                   node->nodeId, onion);
        }

        anodr->stats.numReplyRecvedAsSource++;

        matchingRow->activated = TRUE;
        matchingRow->expireTime = node->getNodeTime() +
                                  ANODR_ACTIVE_ROUTE_TIMEOUT;

        Message *bufPkt = AnodrGetBufferedPacket(matchingRow->remoteAddr,
                                                 NULL,
                                                 &anodr->msgBuffer);

        // Send any buffered packets to the destination
        while (bufPkt)
        {
            anodr->stats.numDataInitiated++;
            //printf("Send buffered data packet\n");
            AnodrTransmitData(node,
                              bufPkt,
                              &matchingRow->pseudonymDownstream,
                              FALSE, // anodr-src => anodr->dest
                              matchingRow->outputInterface);
            if (matchingRow->activated)
            {
                bufPkt = AnodrGetBufferedPacket(matchingRow->remoteAddr,
                                            NULL,
                                            &anodr->msgBuffer);
            }
            else
            {
                bufPkt = NULL;
            }
        } // while having buffered packets
    } //end of if (!AnodrCheckSeqNumExist(seqNum,&anodr->routeTable,
     //                                  &isActiveRoute))


    return TRUE;
}

//--------------------------------------------------------------------
// FUNCTION: AnodrHandleData
// PURPOSE:  Processing procedure when data is received from another node.
//           this node is either intermediate hop or destination of the data
// ARGUMENTS: node, The node which has received data
//            msg,  The message received
// RETURN:    TRUE, if it is my data packet; FALSE, otherwise
//--------------------------------------------------------------------

static BOOL
AnodrHandleData(Node* node, Message* msg)
{
    AnodrData* anodr =
       (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    char *ptr = MESSAGE_ReturnPacket(msg);
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;
    AnodrPseudonym *nym = (AnodrPseudonym *) (ptr + IpHeaderSize(ipHeader));
    AnodrPseudonym matchPseudonym = {DEFAULT_STRING};
    int matchInterface = 0;
    BOOL isActiveRt = FALSE;
    BOOL reverseDir = FALSE;
    AnodrRouteEntry* rtEntry =
        AnodrCheckPseudonymUpstreamExist(
            nym,
            ANY_INTERFACE,
            &matchPseudonym,
            &matchInterface,
            &anodr->routeTable,
            &isActiveRt);

    if (rtEntry == NULL)
    {
        rtEntry = AnodrCheckPseudonymDownstreamExist(
            nym,
            ANY_INTERFACE,
            &matchPseudonym,
            &matchInterface,
            &anodr->routeTable,
            &isActiveRt);
        reverseDir = TRUE;
    }

    if (rtEntry == NULL)
    {
        // Somebody else's data packet, none of my business
        return FALSE;
    }

    // Since the data is incoming, the route must be active
    // (originating from the source) even if I haven't heard of
    // the AACK from my RREP downstream (RREQ upstream)
    if (!isActiveRt)
    {
        rtEntry->activated = TRUE;
        rtEntry->expireTime = node->getNodeTime() + ANODR_ACTIVE_ROUTE_TIMEOUT;
    }

#ifdef DATA_AACK
    AnodrSendUnicastAnonymousACK(node, rtEntry, ANODR_DUMMY);
#endif

    if ((!reverseDir &&
         !memcmp(matchPseudonym.bits,
                 ANODR_DEST_TAG,
                 sizeof(AnodrPseudonym))) ||
        (reverseDir &&
         !memcmp(matchPseudonym.bits,
                 ANODR_SRC_TAG,
                 sizeof(AnodrPseudonym))))
    {
        // The node is the DESTINATION node, or reversely the SRC node
        anodr->stats.numDataRecved++;

        NodeAddress srcAddr = 0;
        NodeAddress destAddr = 0;  // just 2 placeholders
        TosType priority = 0;
        unsigned char protocol = 0;
        unsigned ttl = 0;

        NetworkIpRemoveIpHeader(node, msg, &srcAddr,
                                &destAddr, &priority, &protocol, &ttl);
        MESSAGE_RemoveHeader(node, msg, sizeof(AnodrPseudonym), TRACE_ANODR);
        NetworkIpAddHeader(
            node, msg,
            rtEntry->remoteAddr,
            NetworkIpGetInterfaceAddress(node, DEFAULT_INTERFACE),
            priority, protocol, ttl);
        if (DEBUG)
        {
            printf("ANODR: Node %u is the destination, "
                   "let IP handle packet #%u.\n",
                   node->nodeId, ++anodr->recvCounter);
        }
    }
    else
    {
        // The node is an INTERMEDIATE node

        // There is a valid route towards the destination.
        // Relay the packet to the next hop of the route
        anodr->stats.numDataForwarded++;

        if (DEBUG)
        {
            char pseudonym1[MAX_STRING_LENGTH] = DEFAULT_STRING;
            char pseudonym2[MAX_STRING_LENGTH] = DEFAULT_STRING;

            DebugPrint128BitInHex(pseudonym1, nym->bits);
            DebugPrint128BitInHex(pseudonym2, matchPseudonym.bits);
            printf("Node %u forwards DATA packet (%s ==> %s)\n",
                   node->nodeId, pseudonym1, pseudonym2);
        }

        // Forward the data packet
        AnodrTransmitData(
            node,
            msg, //MESSAGE_Duplicate(node, msg), will cause problem at UDP!!
            &matchPseudonym,
            reverseDir,
            matchInterface);

        // reset the retry counter for downstream forwarding
        rtEntry->unicastDataRetry = 0;
    }

    // Each time a route is used to forward a data packet, its ExpireTime
    // field is updated to be no less than the current time plus
    // ACTIVE_ROUTE_TIMEOUT. Borrowed from related AODV draft Sec: 8.2

    rtEntry->expireTime = node->getNodeTime() + ANODR_ACTIVE_ROUTE_TIMEOUT;
    return TRUE;
}

#if defined(RREP_AACK) || defined(RERR_AACK)
//--------------------------------------------------------------------
// FUNCTION: AnodrHandleControlAack
// PURPOSE:  Processing procedure when anonymous unicast Control ACK
//           is received
// ARGUMENTS: node, the node received the ack
//            msg,  Message containing AACK packet
//            interfaceIndex, the interface through which ack received
//            packetType, ANODR_RREP_AACK or ANODR_RERR_AACK
// RETURN:   TRUE: my AACK;  FALSE: none of my business
//--------------------------------------------------------------------

static BOOL
AnodrHandleControlAack(
         Node* node,
         Message* msg,
         int interfaceIndex,
         char packetType)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrAackPacket* aackPkt = (AnodrAackPacket *) MESSAGE_ReturnPacket(msg);
    BOOL isActiveRt = FALSE;
    AnodrRouteEntry* matchingRow =
        AnodrCheckPseudonymUpstreamExist(&(aackPkt->pseudonym),
                                         interfaceIndex,
                                         NULL,
                                         NULL,
                                         &anodr->routeTable,
                                         &isActiveRt);
    if (matchingRow == NULL)
    {
        // Not ACKing me, none of my business
        return FALSE;
    }

    if (packetType == ANODR_RREP_AACK)
    {
        anodr->stats.numReplyAackRecved++;

        // The virtual circuit link is waiting for the AACK
        if (DEBUG >= 2)
        {
            printf("Node %u: got RREP-ACK"
                   " and the virtual circuit link is active\n",
                   node->nodeId);
        }
        matchingRow->activated = TRUE;
        matchingRow->expireTime =
            node->getNodeTime() + ANODR_ACTIVE_ROUTE_TIMEOUT;
    }
    else
    {
        anodr->stats.numRerrAackRecved++;

        if (DEBUG >= 2)
        {
            printf("Node %u: got RERR-AACK\n", node->nodeId);
        }
        AnodrDeleteRouteEntry(node, matchingRow, &anodr->routeTable);
    }
    return TRUE;
}
#endif

#ifdef DATA_AACK
//--------------------------------------------------------------------
// FUNCTION: AnodrHandleDataAack
// PURPOSE:  Processing procedure when Anonymous DATA ACK is received
// ARGUMENTS: node, the node received the ack
//            msg,  Message containing AACK packet
//            interfaceIndex,the interface from which ack has been received
// RETURN:   TRUE: my AACK;  FALSE: none of my business
//--------------------------------------------------------------------
static BOOL
AnodrHandleDataAack(
         Node* node,
         Message* msg,
         int interfaceIndex)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrAackPacket* aackPkt = (AnodrAackPacket *) MESSAGE_ReturnPacket(msg);
    BOOL isActiveRt = FALSE;
    BOOL reverseDir = FALSE;
    AnodrRouteEntry* matchingRow =
        AnodrCheckPseudonymDownstreamExist(
            &(aackPkt->pseudonym),
            interfaceIndex,
            NULL,
            NULL,
            &anodr->routeTable,
            &isActiveRt);
    if (matchingRow == NULL)
    {
        matchingRow = AnodrCheckPseudonymUpstreamExist(
            &(aackPkt->pseudonym),
            interfaceIndex,
            NULL,
            NULL,
            &anodr->routeTable,
            &isActiveRt);
        reverseDir = TRUE;
    }
    if (matchingRow == NULL)
    {
        // Not ACKing me, none of my business
        return FALSE;
    }

    anodr->stats.numDataAackRecved++;

    ERROR_Assert(isActiveRt == TRUE, "Inactive route, impossible!\n");
    Message *dataMsg = AnodrGetBufferedPacket(ANONYMOUS_IP,
                                              &(aackPkt->pseudonym),
                                              &anodr->msgBuffer);
    if (dataMsg != NULL)
    {
        AnodrTransmitData(node,
                          dataMsg,
                          &(aackPkt->pseudonym),
                          reverseDir,
                          interfaceIndex);
    }
    return TRUE;
}
#endif

//--------------------------------------------------------------------
// FUNCTION: AnodrSendRouteErrorPacket
// PURPOSE:  Sending route error message to other nodes if route is not
//           not available to any destination.
// ARGUMENTS:node, The node sending the route error message
//           pseudonym, The pseudonym to be marked on RERR packet
//           interfaceIndex, the interface failed or received route error
// RETURN:   None
//--------------------------------------------------------------------

static void
AnodrSendRouteErrorPacket(Node* node,
                          const AnodrPseudonym *pseudonym,
                          const int interfaceIndex)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    Message* newMsg = MESSAGE_Alloc(node, MAC_LAYER, 0, MSG_MAC_FromNetwork);
    MESSAGE_PacketAlloc(node, newMsg, sizeof(AnodrRerrPacket), TRACE_ANODR);
    AnodrRerrPacket* rerrPkt =(AnodrRerrPacket*)MESSAGE_ReturnPacket(newMsg);

    rerrPkt->type = ANODR_RERR;
    Assign128BitPseudonym(&rerrPkt->pseudonym, pseudonym);

    if (DEBUG >= 2)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char nym[MAX_STRING_LENGTH] = DEFAULT_STRING;

        DebugPrint128BitInHex(nym, pseudonym->bits);
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u sends RERR (nym = %s) at %s on interface %u\n",
               node->nodeId, nym, clockStr, interfaceIndex);
    }

    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, newMsg, 'S');
    }

    NetworkIpSendRawMessageToMacLayer(
        node,
        newMsg,
        ANONYMOUS_IP,
        ANY_DEST,
        IPTOS_PREC_INTERNETCONTROL,
        IPPROTO_ANODR,
        1,
        interfaceIndex,
        ANY_IP);  // the entire neighborhood

#ifdef RERR_AACK
    // Schedule the timer to check the network layer RREP-ACK
    AnodrSetTimer(node,
                  MSG_NETWORK_CheckRerrAck,
                  ANY_DEST,
                  pseudonym,
                  interfaceIndex,
                  2*ANODR_NODE_TRAVERSAL_TIME);
#endif
}

//--------------------------------------------------------------------
// FUNCTION: AnodrHandleRouteError
// PURPOSE:  Processing procedure when RERR is received
// ARGUMENTS: type, ANODR_RERR for receiving RERR, ANODR_DUMMY for data drop
//            node, The node failed to send data or received route error
//            msg, Message whose transmission failed or containing
//                 route error packet
//            interfaceIndex, the interface failed or received route error
// RETURN:    TRUE: is my RERR; FALSE: none of my business
//--------------------------------------------------------------------

static BOOL
AnodrHandleRouteError(int type,
                      Node* node,
                      const Message* msg,
                      const int interfaceIndex)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrPseudonym *nym = NULL;

    // RERR sending could be incurred by local data packet dropping
    // or receiving an RERR from downstream
    if (type == ANODR_DUMMY)
    {
        char *ptr = MESSAGE_ReturnPacket(msg);
        IpHeaderType *ipHeader = (IpHeaderType *) ptr;
        nym = (AnodrPseudonym *)(ptr + IpHeaderSize(ipHeader));
        // right behind the ip header
    }
    else if (type == ANODR_RERR)
    {
        AnodrRerrPacket* rerrPkt =
                            (AnodrRerrPacket *) MESSAGE_ReturnPacket(msg);
        nym = &rerrPkt->pseudonym;
    }

    AnodrPseudonym matchPseudonym = {DEFAULT_STRING};
    int matchInterface =0;
    BOOL isActiveRt = FALSE;
    AnodrRouteEntry* rtEntry =
        AnodrCheckPseudonymDownstreamExist(nym,
                                           interfaceIndex,
                                           &matchPseudonym,
                                           &matchInterface,
                                           &anodr->routeTable,
                                           &isActiveRt);

    if (rtEntry == NULL)
    {
        // If RERR, then somebody else's RERR, none of my business.
        // If dummy,then the route entry has expired before MAC notification.
        return FALSE;
    }

    if (type == ANODR_RERR)
    {
        //RERR packet received by this node.
        anodr->stats.numRerrRecved++;
#ifdef RERR_AACK
        // Send back RERR-AACK
        AnodrSendUnicastAnonymousACK(node, rtEntry, ANODR_RERR);
#endif
    }

    if (!memcmp(&matchPseudonym.bits, ANODR_SRC_TAG, sizeof(AnodrPseudonym)))
    {
        // RERR received by or packet dropped at the SOURCE
        if (DEBUG)
        {
            printf("Node %d receives RERR as the source.\n", node->nodeId);
        }
        AnodrInitiateRREQ(node,
                          rtEntry->remoteAddr,
#ifdef DO_RREQ_SYMKEY
                          rtEntry
#else
                          NULL
#endif
                          );
    }
    else
    {
        // Send RERR to RREQ upstream
        AnodrSendRouteErrorPacket(node,
                                  &matchPseudonym,
                                  matchInterface);

        if (type == ANODR_DUMMY)
        {
            anodr->stats.numRerrInitiated++;
        }
        else if (type == ANODR_RERR)
        {
            anodr->stats.numRerrForwarded++;
        }
    }
    return TRUE;
}

//---------------------------------------------------------------------------
// FUNCTION     IsMyAnodrDataPacket()
// PURPOSE      Determines whether is my ANODR data packet
//              (me as the DESTINATION)
// PARAMETERS   Node *node, Pointer to node.
//              msg, the Packet
// RETURNS      TRUE if packet should be delivered to node.
//              FALSE if packet should not be delivered to node.
//---------------------------------------------------------------------------

BOOL
IsMyAnodrDataPacket(Node *node, Message* msg)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    if (anodr == NULL)
    {
        return FALSE;
    }

    char *ptr = MESSAGE_ReturnPacket(msg);
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;

    if (anodr && ipHeader->ip_p != IPPROTO_ANODR)
    {
        // ANODR's data packet
        AnodrPseudonym *nym =
                          (AnodrPseudonym *) (ptr + IpHeaderSize(ipHeader));
        AnodrPseudonym matchPseudonym = {DEFAULT_STRING};
        int matchInterface = 0;
        BOOL isActiveRt = FALSE;
        BOOL tagHit = FALSE;
        AnodrRouteEntry* rtEntry =
            AnodrCheckPseudonymUpstreamExist(
                nym,
                ANY_INTERFACE,
                &matchPseudonym,
                &matchInterface,
                &anodr->routeTable,
                &isActiveRt);
        if (rtEntry == NULL)
        {
            rtEntry = AnodrCheckPseudonymDownstreamExist(
                nym,
                ANY_INTERFACE,
                &matchPseudonym,
                &matchInterface,
                &anodr->routeTable,
                &isActiveRt);
            tagHit = !memcmp(matchPseudonym.bits,
                             ANODR_SRC_TAG,
                             sizeof(AnodrPseudonym));
        }
        else
        {
            tagHit = !memcmp(matchPseudonym.bits,
                             ANODR_DEST_TAG,
                             sizeof(AnodrPseudonym));
        }

        if (tagHit)
        {
            return TRUE;
        }
    }//end of if (anodr && ipHeader->ip_p != IPPROTO_ANODR)
    return FALSE;
}

//The following functions are meant for future use.
#if 0
//---------------------------------------------------------------------------
// FUNCTION     IsMyAnodrUnicastControlFrame()
//            & IsMyAnodrForwardDataFrame() // as FORWARDER, not DESTINATION!
//            & IsMyAnodrBroadcastFrame()
// PURPOSE      Determines whether is my ANODR unicast frame
//              (me as the one-hop MAC layer receiver)
// PARAMETERS   Node *node, Pointer to node.
//              msg, the Packet
//              protocol,the MAC protocol to be used
// RETURNS      TRUE if packet should be delivered to node.
//              FALSE if packet should not be delivered to node.
//---------------------------------------------------------------------------

BOOL
IsMyAnodrUnicastControlFrame(Node *node, Message* msg, MAC_PROTOCOL protocol)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    char *ptr = MESSAGE_ReturnPacket(msg);
    switch (protocol)
    {
        //case MAC_PROTOCOL_DOT11:
        //ptr += sizeof(DOT11_FrameHdr);
        //break;
        case MAC_PROTOCOL_ANODR:
        default:
            ptr = ptr;
    }
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;
    AnodrPseudonym *nym = NULL;
    AnodrOnion *onion = NULL;

    if (anodr)
    {
        ptr += IpHeaderSize(ipHeader);

        if (ipHeader->ip_p != IPPROTO_ANODR)
        {
            return FALSE;
        }

        // ANODR's unicast control packet RREP and RERR
        unsigned char type = *(unsigned char *) ptr;
        switch(type)
        {
            case ANODR_RREP:
            {
                AnodrRrepPacket* rrepPkt = (AnodrRrepPacket *)ptr;
#ifdef DO_ECC_CRYPTO
                // Now try to decrypt the pseudonym (i.e., the K_seed)
                if (anodr->doCrypto)
                {
                    AnodrEccPubKeyDecryption(node,
                                             rrepPkt->nym.pseudonym.bits,
                                             rrepPkt->nym.encryptedPseudonym,
                                             AES_BLOCKLENGTH);
                }
#endif // DO_ECC_CRYPTO decrypts K_seed
#ifdef DO_AES_CRYPTO
                // Use the pseudonym as K_seed to decrypt (pr_dest, TBO)
                if (anodr->doCrypto)
                {
                    CIPHER_HANDLE cipher =
                        // algo AES256 CFB mode in secure memory
                    cipher_open(CIPHER_ALGO_AES256, CIPHER_MODE_CFB, 1);
                    cipher_setiv(cipher, NULL, 0 ); // Zero IV
                    cipher_setkey(cipher,
                                  rrepPkt->nym.pseudonym.bits,
                                  sizeof(AnodrPseudonym));
                    cipher_decrypt(cipher,
                                   rrepPkt->rrepPayload.aesCiphertext,
                                   rrepPkt->rrepPayload.aesCiphertext,
                                   b2B(2*AES_BLOCKLENGTH));
                    cipher_close(cipher);
                }
#endif // DO_AES_CRYPTO decrypts RREP payload
                onion = &(rrepPkt->rrepPayload.aesPlaintext.onion);
                // do outputOnion match
                BOOL isActiveRt = FALSE;
                AnodrRouteEntry* rtEntry =
                    AnodrCheckOutputOnionExist(onion,
                                               &anodr->routeTable,
                                               &isActiveRt);
                if (rtEntry != NULL)
                {
                    return TRUE;
                }
                break;
            }//end of case ANODR_RREP:
            case ANODR_RERR:
            {
                nym = &(((AnodrRerrPacket *)ptr)->pseudonym);
                // do pseudonym match
                AnodrPseudonym matchPseudonym;
                int matchInterface;
                BOOL isActiveRt = FALSE;
                AnodrRouteEntry* rtEntry =
                AnodrCheckPseudonymDownstreamExist(nym,
                                                   ANY_INTERFACE,
                                                   &matchPseudonym,
                                                   &matchInterface,
                                                   &anodr->routeTable,
                                                   &isActiveRt);
                if (rtEntry != NULL)
                {
                    return TRUE;
                }
                break;
            }
            case ANODR_RREP_AACK:
            case ANODR_RERR_AACK:
            {
                nym = &(((AnodrAackPacket *)ptr)->pseudonym);
                // do pseudonym match
                AnodrPseudonym matchPseudonym;
                int matchInterface;
                BOOL isActiveRt = FALSE;
                AnodrRouteEntry* rtEntry =
                    AnodrCheckPseudonymUpstreamExist(nym,
                                                     ANY_INTERFACE,
                                                     &matchPseudonym,
                                                     &matchInterface,
                                                     &anodr->routeTable,
                                                     &isActiveRt);
                if (rtEntry != NULL)
                {
                    return TRUE;
                }
                break;
            }
            default:
            {
               ERROR_Assert(FALSE,"Unknown unicast control frame for Anodr");
            }
        }//end of switch(type)
    }//end of  if (anodr)
    return FALSE;
}


//---------------------------------------------------------------------------
// FUNCTION     IsMyAnodrForwardDataFrame
// PURPOSE      Determines whether the data packet belongs to the node
//              (me as the one-hop MAC layer receiver)
// PARAMETERS   Node *node, Pointer to node.
//              msg, the Packet
//              protocol,the MAC protocol to be used
// RETURNS      TRUE if packet should be delivered to node.
//              FALSE if packet should not be delivered to node.
//---------------------------------------------------------------------------

BOOL
IsMyAnodrForwardDataFrame(Node *node, Message* msg, MAC_PROTOCOL protocol)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    char *ptr = MESSAGE_ReturnPacket(msg);
    switch (protocol)
    {
        //case MAC_PROTOCOL_DOT11:
        //ptr += sizeof(DOT11_FrameHdr);
        //break;
        case MAC_PROTOCOL_ANODR:
        default:
            ptr = ptr;
    }
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;
    AnodrPseudonym *nym = NULL;

    if (anodr)
    {
        ptr += IpHeaderSize(ipHeader);

        if (ipHeader->ip_p == IPPROTO_ANODR)
        {
            return FALSE;
        }

        nym = (AnodrPseudonym *) ptr;
        // do pseudonym match
        AnodrPseudonym matchPseudonym = DEFAULT_STRING;
        int matchInterface = 0;
        BOOL isActiveRt = FALSE;
        AnodrRouteEntry* rtEntry =
            AnodrCheckPseudonymUpstreamExist(nym,
                                             ANY_INTERFACE,
                                             &matchPseudonym,
                                             &matchInterface,
                                             &anodr->routeTable,
                                             &isActiveRt);
        if (rtEntry == NULL)
        {
            rtEntry = AnodrCheckPseudonymDownstreamExist(nym,
                                             ANY_INTERFACE,
                                             &matchPseudonym,
                                             &matchInterface,
                                             &anodr->routeTable,
                                             &isActiveRt);
        }
        if (rtEntry != NULL)
        {
            return TRUE;
        }
    }
    return FALSE;
}

//---------------------------------------------------------------------------
// FUNCTION     IsMyAnodrBroadcastFrame
// PURPOSE      Determines whether the packet is RREQ or not.
//              (me as the one-hop MAC layer receiver)
// PARAMETERS   Node *node, Pointer to node.
//              msg, the Packet
//              protocol,the MAC protocol to be used
// RETURNS      TRUE if packet should be delivered to node.
//              FALSE if packet should not be delivered to node.
//---------------------------------------------------------------------------

BOOL
IsMyAnodrBroadcastFrame(Node *node, Message* msg, MAC_PROTOCOL protocol)
{
    AnodrData* anodr =
      (AnodrData *)NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    char *ptr = MESSAGE_ReturnPacket(msg);
    switch (protocol)
    {
        //case MAC_PROTOCOL_DOT11:
        //ptr += sizeof(DOT11_FrameHdr);
        //break;
        case MAC_PROTOCOL_ANODR:
        default:
            ptr += 0;
    }
    IpHeaderType *ipHeader = (IpHeaderType *) ptr;

    if (anodr)
    {
        ptr += IpHeaderSize(ipHeader);

        if (ipHeader->ip_p == IPPROTO_ANODR)
        {
            // ANODR's broadcast control packet RREQ
            unsigned char type = *(unsigned char *) ptr;
            if (type == ANODR_RREQ || type == ANODR_RREQ_SYMKEY)
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}
#endif

//--------------------------------------------------------------------
// FUNCTION: AnodrMacLayerStatusHandler
// PURPOSE:  Reacts to the signal sent by the MAC protocol after link
//           failure
// ARGUMENTS: node, The node itself
//            msg,  The message not delivered
//            dummy, Not useful in ANODR, but is enforced by QualNet routine
//            incomingInterface, the interface in which the message was sent
// RETURN:    None
//--------------------------------------------------------------------

void
AnodrMacLayerStatusHandler(
    Node* node,
    const Message* msg,
    const NodeAddress dummy,
    const int incomingInterface)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    ERROR_Assert(MESSAGE_GetEvent(msg) == MSG_NETWORK_PacketDropped,
                 "ANODR: Unexpected event in MAC layer status handler.\n");

    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);

    if (DEBUG >= 2)
    {
        printf("Node %u mac failed to deliver packet using interface %d\n",
               node->nodeId, incomingInterface);
    }

    anodr->stats.numBrokenLinks++;

    if (ipHeader->ip_p != IPPROTO_ANODR)
    {
        // Data packet forwarding failed
        if (DEBUG)
        {
            printf("Node %u data forwarding failure, initiating RERR.\n",
                   node->nodeId);
        }
        AnodrHandleRouteError(ANODR_DUMMY, node, msg, incomingInterface);
    }
}


//--------------------------------------------------------------------
// FUNCTION: AnodrRouterFunction
// PURPOSE: Determine the routing action to take for a the given data packet
//          set the PacketWasRouted variable to TRUE if no further handling
//          of this packet by IP is necessary
// ARGUMENTS: node, The node handling the routing
//            msg,  The packet to route to the destination
//            destAddr, The destination of the packet
//            previousHopAddress, last hop of this packet
//            packetWasRouted, set to FALSE if ip is supposed to handle the
//                             routing otherwise TRUE
// RETURN:   None
//--------------------------------------------------------------------

void
AnodrRouterFunction(
    Node* node,
    Message* msg,
    NodeAddress destAddr,
    NodeAddress previousHopAddress,
    BOOL* packetWasRouted)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);

    IpHeaderType* ipHeader = (IpHeaderType *) MESSAGE_ReturnPacket(msg);
    AnodrRouteEntry* rtToDest = NULL;
    BOOL isActiveRt = FALSE;

    // Control packets
    if (ipHeader->ip_p == IPPROTO_ANODR)
    {
        return;
    }

    if (DEBUG >= 2)
    {
        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("ANODR: Node %u got packet at %s\n", node->nodeId, clockStr);
    }

    if (NetworkIpIsMyIP(node, destAddr) ||
        IsMyAnodrDataPacket(node, msg))
    {
        *packetWasRouted = FALSE;
    }
    else
    {
        *packetWasRouted = TRUE;
    }

    if (!NetworkIpIsMyIP(node, ipHeader->ip_src))  // THE LINE
    {
        // Intermediate node or destination of the route.
        //  To receive an ANODR data packet, the procedure is
        //  NetworkIpReceivePacketFromMacLayer() ->
        //  NetworkIpSendOnBackplane() ->
        //  DeliverPacket() -> here.
        AnodrHandleData(node, msg);
    }
    else
    {
        // Data packet initiated by the SOURCE
        if (NetworkIpIsMyIP(node, destAddr))
        {
            return;
        }

        if (DEBUG)
        {
            printf("ANODR: Node %u sends out packet no #%u.\n",
                   node->nodeId, ++anodr->sendCounter);
        }

        //Don't change DATA packet format, hide ANODR_HEADER behind IP Header
        NodeAddress srcAddr = 0;
        NodeAddress destAddr = 0;   // just 2 placeholders
        TosType priority = 0;
        unsigned char protocol = 0 ;
        unsigned ttl = 0;

        NetworkIpRemoveIpHeader(node, msg, &srcAddr, &destAddr,
                                &priority, &protocol, &ttl);
        MESSAGE_AddHeader(node, msg, sizeof(AnodrPseudonym), TRACE_ANODR);
        NetworkIpAddHeader(node, msg,
                           // srcAddr must not be ANY_IP, see THE LINE above
                           ANONYMOUS_IP,
                           ANONYMOUS_IP,
                           priority, protocol, ttl);

        rtToDest = AnodrCheckRouteExist(
                       destAddr,
                       &anodr->routeTable,
                       &isActiveRt);

        if (isActiveRt)
        {
            // source has a route to the destination
            if (rtToDest->outputInterface == ANY_INTERFACE)
            {
                AnodrPrintRoutingTable(node, &anodr->routeTable);
                ERROR_ReportError("Invalid ANODR routing table.\n");
            }
            //updating the expiry time of the route
            rtToDest->expireTime =
                node->getNodeTime() + ANODR_ACTIVE_ROUTE_TIMEOUT;

            if (rtToDest->dest)  // Am I ANODR's destination end?
            {
                AnodrTransmitData(node,
                                  msg,
                                  &rtToDest->pseudonymUpstream,
                                  TRUE,
                                  rtToDest->inputInterface);
                if (DEBUG)
                {
                    printf("\tANODR dest has route to remote, "
                           "so send immediately\n");
                }
            }
            else
            {
                AnodrTransmitData(node,
                                  msg,
                                  &rtToDest->pseudonymDownstream,
                                  FALSE,
                                  rtToDest->outputInterface);
                if (DEBUG)
                {
                    printf("\tANODR src has route to remote, "
                           "so send immediately\n");
                }
            }
            anodr->stats.numDataInitiated++;
        }
        else
        {
            // There is no route to the destination

            if (AnodrCheckSent(destAddr, &anodr->routeTable))
            {
                // There is no route but RREQ has already been sent.
                // Data packets waiting for a route (i.e., waiting for a
                // RREP after RREQ has been sent) SHOULD be buffered.
                // The buffering SHOULD be FIFO. Sec: 8.3
                if (DEBUG)
                {
                    printf("\talready sent RREQ, so buffer packet\n");
                }

                AnodrInsertBuffer(
                    node,
                    msg,
                    destAddr,
                    NULL,
                    &anodr->msgBuffer);
            }
            else
            {
                // There is no route and RREQ has not been sent
                if (DEBUG)
                {
                    printf("\tdon't have a route, "
                           "so insert into the buffer\n");
                }

                AnodrInsertBuffer(
                    node,
                    msg,
                    destAddr,
                    NULL,
                    &anodr->msgBuffer);

                if (DEBUG)
                {
                    printf("\tdon't have a route, so send RREQ\n");
                }

                AnodrInitiateRREQ(node, destAddr, NULL);
            }
        }
    }
}


//--------------------------------------------------------------------
// FUNCTION: AnodrInitializeConfigurableParameters
// PURPOSE: To initialize the user configurable parameters or initialize
//          the corresponding variables with the default values as specified
//          in draft-ietf-manet-anodr-08.txt
// PARAMETERS: node, the node pointer, which is running anodr as its routing
//                   protocol
//             nodeInput,pointer to the data structure containing
//             the input data for the node
//             anodr, anodr internal structure
//             interfaceIndex the interface for which it is initializing
// RETURN:     Null
// ASSUMPTION: None
//--------------------------------------------------------------------

static
void AnodrInitializeConfigurableParameters(
         Node* node,
         const NodeInput* nodeInput,
         AnodrData* anodr,
         int intfIndex)
{
    BOOL wasFound = FALSE;
    NodeAddress interfaceAddress = NetworkIpGetInterfaceAddress(
                                       node,
                                       intfIndex);

    NodeAddress nodeId = node->nodeId;

    IO_ReadInt(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-NET-DIAMETER",
        &wasFound,
        &anodr->netDiameter);

    if (!wasFound)
    {
        anodr->netDiameter = ANODR_DEFAULT_NET_DIAMETER;
    }


    ERROR_Assert(anodr->netDiameter > 0, "ANODR-NET-DIAMETER"
                 "needs to be a positive number\n");

    IO_ReadTime(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-NODE-TRAVERSAL-TIME",
        &wasFound,
        &anodr->nodeTraversalTime);

    if (!wasFound)
    {
        anodr->nodeTraversalTime = ANODR_DEFAULT_NODE_TRAVERSAL_TIME;
    }


    ERROR_Assert(anodr->nodeTraversalTime > 0, "ANODR-NODE-TRAVERSAL-TIME"
                 "needs to be a positive number\n");

    IO_ReadTime(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-ACTIVE-ROUTE-TIMEOUT",
        &wasFound,
        &anodr->activeRouteTimeout)
        ;
    if (!wasFound)
    {
        anodr->activeRouteTimeout = ANODR_DEFAULT_ACTIVE_ROUTE_TIMEOUT;
    }

    ERROR_Assert(anodr->activeRouteTimeout > 0, "ANODR-ACTIVE-ROUTE-TIMEOUT"
                 "needs to be a positive number\n");

    IO_ReadInt(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-RREQ-RETRIES",
        &wasFound,
        &anodr->rreqRetries);

    if (!wasFound)
    {
        anodr->rreqRetries = ANODR_DEFAULT_RREQ_RETRIES;
    }

    ERROR_Assert(anodr->rreqRetries >= 0, "ANODR_RREQ_RETRIES"
                 "needs to be a positive number\n");

    IO_ReadInt(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-BUFFER-MAX-PACKET",
        &wasFound,
        &anodr->bufferSizeInNumPacket);

    if (wasFound == FALSE)
    {
        anodr->bufferSizeInNumPacket = ANODR_DEFAULT_MESSAGE_BUFFER_IN_PKT;
    }

    ERROR_Assert(anodr->bufferSizeInNumPacket > 0, "ANODR-BUFFER-MAX-PACKET "
                 "needs to be a positive number\n");

    IO_ReadInt(
        node->nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-BUFFER-MAX-BYTE",
        &wasFound,
        &anodr->bufferSizeInByte);

    if (wasFound == FALSE)
    {
        anodr->bufferSizeInByte = 0;
    }

    ERROR_Assert(anodr->bufferSizeInByte >= 0, "ANODR-BUFFER-MAX-BYTE "
                 "cannot be negative\n");

    IO_ReadTime(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-NODE-ONION-PROCESSING-TIME",
        &wasFound,
        &anodr->nodeOnionProcessingTime);

    if (!wasFound)
    {
        anodr->nodeOnionProcessingTime = ANODR_DEFAULT_ONION_PROCESSING_TIME;
    }


    ERROR_Assert(anodr->nodeOnionProcessingTime > 0,
         "ANODR-NODE-ONION-PROCESSING-TIME "
                 "needs to be a positive number\n");

    IO_ReadBool(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-DO-RREP-AACK",
        &wasFound,
        &anodr->doRrepAack);

    if (!wasFound)
    {
    anodr->doRrepAack = TRUE;
    }

#if 0
    //These parameters will be implemented in future.
    IO_ReadTime(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-MY-ROUTE-TIMEOUT",
        &wasFound,
        &anodr->myRouteTimeout);

    if (!wasFound)
    {
        anodr->myRouteTimeout = ANODR_DEFAULT_MY_ROUTE_TIMEOUT;
    }

    ERROR_Assert(anodr->myRouteTimeout > 0,"ANODR-MY-ROUTE-TIMEOUT"
                "needs to be a positive number\n");
    IO_ReadInt(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-ROUTE-DELETION-CONSTANT",
        &wasFound,
        &anodr->rtDeletionConstant);

    if (!wasFound)
    {
        anodr->rtDeletionConstant = ANODR_DEFAULT_ROUTE_DELETE_CONST;
    }

    ERROR_Assert(anodr->rtDeletionConstant >0,"ANODR-ROUTE-DELETION-CONSTANT"
                 " needs to be a positive number\n");

    // Now default to process ACK
    char buf[MAX_STRING_LENGTH] = DEFAULT_STRING;
    IO_ReadString(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-PROCESS-ACK",
        &wasFound,
        buf);

    if ((wasFound == FALSE) || (strcmp(buf, "NO") == 0))
    {
        anodr->processAck = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        anodr->processAck = TRUE;
    }
    else
    {
        ERROR_ReportError("Needs YES/NO against ANODR-PROCESS-ACK");
    }

    // In the future, will enhance ANODR by scoped flooding
    IO_ReadString(
        nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-OPEN-BI-DIRECTIONAL-CONNECTION",
        &wasFound,
        buf);

    if ((wasFound == FALSE) || (strcmp(buf, "NO") == 0))
    {
        anodr->biDirectionalConn = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        anodr->biDirectionalConn = TRUE;
    }
    else
    {
        ERROR_ReportError("Needs YES/NO against "
            "ANODR-OPEN-BI-DIRECTIONAL-CONNECTION");
    }

    IO_ReadInt(
        node->nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-TTL-START",
        &wasFound,
        &anodr->ttlStart);

    if (wasFound == FALSE)
    {
        anodr->ttlStart = ANODR_DEFAULT_TTL_START;
    }

    ERROR_Assert(anodr->ttlStart > 0, "ANODR_TTL_START should be > 0");

    IO_ReadInt(
        node->nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-TTL-INCREMENT",
        &wasFound,
        &anodr->ttlIncrement);

    if (wasFound == FALSE)
    {
        anodr->ttlIncrement = ANODR_DEFAULT_TTL_INCREMENT;
    }

    ERROR_Assert(anodr->ttlIncrement > 0,
                "ANODR_TTL_INCREMENT should be > 0");

    IO_ReadInt(
        node->nodeId,
        interfaceAddress,
        nodeInput,
        "ANODR-TTL-THRESHOLD",
        &wasFound,
        &anodr->ttlMax);

    if (wasFound == FALSE)
    {
        anodr->ttlMax = ANODR_DEFAULT_TTL_THRESHOLD;
    }

    ERROR_Assert(anodr->ttlMax > 0, "ANODR_TTL_THRESHOLD should be > 0");
#endif
}


//--------------------------------------------------------------------
// FUNCTION: AnodrInit
// PURPOSE:  Initialization function for ANODR protocol
// ARGUMENTS: node, Anodr router which is initializing itself
//            anodrPtr, data space to store anodr information
//                        network layer
//            nodeInput,  The configuration file
//            interfaceIndex, the interface for which the ANODR protocol
//            needs to be enabled
// RETURN:    None
//--------------------------------------------------------------------

void
AnodrInit(
    Node* node,
    AnodrData** anodrPtr,
    const NodeInput* nodeInput,
    int interfaceIndex)
{
    assert(sizeof(AnodrGlobalTrapdoor)*8 == ANODR_GLOBALTRAPDOOR_LENGTH);
    AnodrData* anodr =
        (AnodrData *) MEM_malloc(sizeof(AnodrData));
    BOOL retVal;
    char buf[MAX_STRING_LENGTH];

    memset(anodr, 0, sizeof(AnodrData));
    (*anodrPtr) = anodr;

    // Read whether statistics needs to be collected for the protocol
    IO_ReadString(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ROUTING-STATISTICS",
        &retVal,
        buf);

    if ((retVal == FALSE) || (strcmp(buf, "NO") == 0))
    {
        anodr->statsCollected = FALSE;
    }
    else if (strcmp(buf, "YES") == 0)
    {
        anodr->statsCollected = TRUE;
    }
    else
    {
        ERROR_ReportError("Needs YES/NO against STATISTICS");
    }

    // Initialize statistical variables
    memset(&(anodr->stats), 0, sizeof(AnodrStats));

    anodr->statsPrinted = FALSE;

    AnodrInitTrace();

    // Read user configurable parameters from the configuration file or
    // initialize them with the default value.
    AnodrInitializeConfigurableParameters(
        node,
        nodeInput,
        anodr,
        interfaceIndex);

    // Initialize anodr routing table
    //The variables that have already been initialized in memset()
    //have been commented out.

    (&anodr->routeTable)->head = NULL;
    //(&anodr->routeTable)->size = 0;

    // Initialize buffer to store packets which don't have any route
    (&anodr->msgBuffer)->head = NULL;
    //(&anodr->msgBuffer)->size = 0;
   // (&anodr->msgBuffer)->numByte = 0;

    // Initialize Last Broadcast sent
   // anodr->lastBroadcastSent = (clocktype) 0;

    // Allocate chunk of memory
    AnodrMemoryChunkAlloc(anodr);

    // Allocate message for the periodic route freshness checking timer
    if (DEBUG >= 2)
    {
        printf("Node %u is setting timer "
               "MSG_NETWORK_CheckRouteTimeout\n",
               node->nodeId);

        char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %u sets timer at %s\n",node->nodeId,clockStr);

        TIME_PrintClockInSecond((node->getNodeTime() +
                                 ANODR_ACTIVE_ROUTE_TIMEOUT/2), clockStr);
        printf("\ttimer to expire at %s\n", clockStr);

    }
    Message *msg = MESSAGE_Alloc(
                 node,
                 NETWORK_LAYER,
                 ROUTING_PROTOCOL_ANODR,
                 MSG_NETWORK_CheckRouteTimeout);
    // The notion "ActiveRouteTimeout" is inherited from AODV.
    // However, AODV is bidirectional between source and dest.
    // ANODR is unidirectional, thus the timeout is divided by 2.
    MESSAGE_Send(node, msg, ANODR_ACTIVE_ROUTE_TIMEOUT/2);

    //anodr->isExpireTimerSet = FALSE;
    //anodr->isDeleteTimerSet = FALSE;

#if defined(DO_ECC_CRYPTO) || defined(DO_AES_CRYPTO)
    anodr->doCrypto = TRUE;
#else // either ECC_CRYPTO or AES_CRYPTO should be done
    anodr->doCrypto = FALSE;
#endif // DO_CRYPTO initialization
#ifndef ASR_PROTOCOL
    // 128-bit TBO key.
    // In ANODR, this key is per-node based
    // (each node only has 1 such key to use in the entire network lifetime)
    // In ASR, this key is per-flood based
    // (each onion/RREQ flood must have a different such key: a one-time pad)
    Generate128BitPRN(node, anodr->onionKey.bits);
#else // ASR_PROTOCOL
    // for pseudorandom sync between ANODR and ASR
    byte dummy[b2B(ANODR_AES_KEYLENGTH)] = DEFAULT_STRING;
    Generate128BitPRN(node, dummy);
#endif // ASR_PROTOCOL

    if (DEBUG_INIT)
    {
        printf("Node %u\n", node->nodeId);
        printf("\tNode Traversal Time: %e Sec\n"
               "\tNet Diameter: %u\n"
               "\tMy Route Time out: %e Sec\n"
               "\tActive Route Timeout: %e Sec\n"
               "\tRREQ retries: %u\n\n",
               (double) anodr->nodeTraversalTime / SECOND,
               anodr->netDiameter,
               (double) anodr->myRouteTimeout / SECOND,
               (double) anodr->activeRouteTimeout / SECOND,
               anodr->rreqRetries);
    }

    // Set the mac status handler function
    NetworkIpSetMacLayerStatusEventHandlerFunction(
        node,
        &AnodrMacLayerStatusHandler,
        interfaceIndex);

    // Set the router function
    NetworkIpSetRouterFunction(
        node,
        &AnodrRouterFunction,
        interfaceIndex);

#ifdef DO_ECC_CRYPTO
    if (anodr->doCrypto)
    {
        char buffer[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char address[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char keyFileName[MAX_STRING_LENGTH] = DEFAULT_STRING;
        char pubKeyFileName[MAX_STRING_LENGTH]= DEFAULT_STRING;
        FILE *keyFile = NULL;
        FILE *pubKeyFile = NULL;

        IO_ConvertIpAddressToString(
            node->networkData.networkVar->
            interfaceInfo[interfaceIndex]->ipAddress,
            address);

        sprintf(keyFileName, "default.privatekey.%s", address);
        sprintf(pubKeyFileName, "default.publickey.%s", address);

        keyFile = fopen(keyFileName, "r");
        pubKeyFile = fopen(pubKeyFileName, "r");
        if (keyFile == NULL || pubKeyFile == NULL)
        {
            // The node's key file doesn't exist, create it
            keyFile = fopen(keyFileName, "w");
            sprintf(buffer, "Error in creating key file %s\n", keyFileName);
            ERROR_Assert(keyFile != NULL, buffer);

            pubKeyFile = fopen(pubKeyFileName, "w");
            sprintf(buffer, "Error in creating public key file %s\n",
                    pubKeyFileName);
            ERROR_Assert(pubKeyFile != NULL, buffer);

            int invalid = 1;

            while (invalid)
            {
                fprintf(stderr,
                        "Generate Elliptic Curve Cryptosystem (ECC)"
                        " key for node %u\n", node->nodeId);

                // Choose the random nonce k
                anodr->eccKey[11] = AnodrEccChooseRandomNumber(anodr, NULL);
                invalid = ecc_generate(PUBKEY_ALGO_ECC,
                                       QUALNET_ECC_KEYLENGTH,
                                       anodr->eccKey,
                                       NULL);
            }

            /*
              well-known.E.p = sk.E.p = anodr->eccKey[0];
              well-known.E.a = sk.E.a = anodr->eccKey[1];
              well-known.E.b = sk.E.b = anodr->eccKey[2];
              well-known.E.G.x = sk.E.G.x = anodr->eccKey[3];
              well-known.E.G.x = sk.E.G.y = anodr->eccKey[4];
              well-known.E.G.x = sk.E.G.z = anodr->eccKey[5];
              well-known.E.G.x = sk.E.n = anodr->eccKey[6];
              pk.Q.x = sk.Q.x = anodr->eccKey[7];
              pk.Q.y = sk.Q.y = anodr->eccKey[8];
              pk.Q.z = sk.Q.z = anodr->eccKey[9];
              sk.d = anodr->eccKey[10];

              Amongst the parameters,
              d is the random secret, Q is supposed to be public key,
              so different Q's for different d's.

              The other parameters
              E.p, E.a, E.b, E.n, E.G.x, E.G.y, E.G.z are fixed and
              well-known for fixed-bit ECCs.

              For example, for 192-bit ECC:

              mpi_fromstr(E.p_,
              "0xfffffffffffffffffffffffffffffffeffffffffffffffff"))

              mpi_fromstr(E.a_,
              "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC"))
              i.e., "-0x3"

              mpi_fromstr(E.b_,
              "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1"))

              mpi_fromstr(E.n_,
              "0xffffffffffffffffffffffff99def836146bc9b1b4d22831"))

              mpi_fromstr(G->x_,
              "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012"))

              mpi_fromstr(G->y_,
              "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"))

              G->z_ = 1;
            */

            // public key does NOT include sk.d
            for (int i=0; i<10; i++)
            {
                fprintf(pubKeyFile, "0x");
                mpi_print(pubKeyFile, anodr->eccKey[i], 1);
                fputc('\n', pubKeyFile);
            }
            // key has all 11 elements
            for (int i=0; i<11; i++)
            {
                fprintf(keyFile, "0x");
                mpi_print(keyFile, anodr->eccKey[i], 1);
                fputc('\n', keyFile);
            }
        }
        else
        {
            // The pre-generated key is already in the file,
            // use it rather than generate it.  This saves simulation time.
            for (int i=0; i<11; i++)
            {
                fgets(buffer, QUALNET_MAX_STRING_LENGTH, keyFile);
                if (buffer[strlen(buffer)-1] != '\n')
                {
                    sprintf(buffer,
                            "Key file %s is corrupted. Please delete it.\n",
                            keyFileName);
                    ERROR_ReportError(buffer);
                }
                buffer[strlen(buffer)-1] = '\0';

                if (!anodr->eccKey[i])
                {
                    anodr->eccKey[i] = mpi_alloc_set_ui(0);
                }
                mpi_fromstr(anodr->eccKey[i], buffer);

                if (DEBUG >= 3)
                {
                    mpi_print(stdout, anodr->eccKey[i], 1);
                    fputc('\n', stdout);
                }
            }

            if (DEBUG)
            {
                // Test the ECC key

                // Choose the random nonce k
                anodr->eccKey[11] =
                    AnodrEccChooseRandomNumber(anodr,
                                               anodr->eccKey[6]/*sk.n*/);
                int invalid = test_ecc_key(PUBKEY_ALGO_ECC,
                                           anodr->eccKey,
                                           QUALNET_ECC_KEYLENGTH);
                fprintf(stderr, "Node %u's ECC key is %s.\n",
                        node->nodeId, invalid?"INVALID":"VALID");
                while (invalid)
                {
                    fprintf(stderr,
                        "Generate Elliptic Curve Cryptosystem (ECC) key"
                        " for node %u\n", node->nodeId);
                    // Choose the random nonce k
                    mpi_free(anodr->eccKey[11]);
                    anodr->eccKey[11] = AnodrEccChooseRandomNumber(anodr,
                                                                   NULL);
                    invalid = ecc_generate(PUBKEY_ALGO_ECC,
                                           QUALNET_ECC_KEYLENGTH,
                                           anodr->eccKey,
                                           NULL);
                }
            }
        }//end of if (keyFile == NULL || pubKeyFile == NULL)
        fflush(stderr);
        fclose(keyFile);
        fclose(pubKeyFile);
    }// end of if (anodr->doCrypto)

#endif // DO_ECC_CRYPTO initialization

    std::string path;
    D_Hierarchy *h = &node->partitionData->dynamicHierarchy;

    if (h->CreateRoutingPath(
            node,
            interfaceIndex,
            "anodr",
            "print",
            path))
    {
        h->AddObject(path, new D_AnodrPrint(anodr));
    }

    if (h->CreateRoutingPath(
            node,
            interfaceIndex,
            "anodr",
            "numRequestInitiated",
            path))
    {
        h->AddObject(
            path,
            new D_UInt32Obj(&anodr->stats.numRequestInitiated));
    }

    RANDOM_SetSeed(anodr->jitterSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_ANODR,
                   interfaceIndex);
    RANDOM_SetSeed(anodr->nymSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_ANODR,
                   interfaceIndex);
    // Choose the random e2eNym
    anodr->e2eNym = RANDOM_nrand(anodr->nymSeed);
#ifdef DO_ECC_CRYPTO
    RANDOM_SetSeed(anodr->eccSeed,
                   node->globalSeed,
                   node->nodeId,
                   ROUTING_PROTOCOL_ANODR,
                   interfaceIndex);
#endif // DO_ECC_CRYPTO
}


//--------------------------------------------------------------------
// FUNCTION: AnodrFinalize
// PURPOSE:  Called at the end of the simulation to collect the results
// ARGUMENTS: node, The node for which the statistics are to be printed
// RETURN:    None
//--------------------------------------------------------------------

void
AnodrFinalize(Node* node)
{
    AnodrData* anodr = (AnodrData *)
        NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    char buf[MAX_STRING_LENGTH];


    if (anodr->statsCollected && !anodr->statsPrinted)
    {
        anodr->statsPrinted = TRUE;

        sprintf(buf, "Number of RREQ Initiated = %u",
            (unsigned short) anodr->stats.numRequestInitiated);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREQ Retried = %u",
            anodr->stats.numRequestResent);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREQ Forwarded = %u",
            anodr->stats.numRequestRelayed);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREQ Received = %u",
            anodr->stats.numRequestRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of Duplicate RREQ Received = %u",
            anodr->stats.numRequestDuplicate);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREQ Received by Dest = %u",
            anodr->stats.numRequestRecvedAsDest);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf,"Number of RREQ received by Dest with global trapdoor"
                    " in symmetric key encryption = %u",
            anodr->stats.numRequestRecvedAsDestWithSymKeyGlobalTrapdoor);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP Initiated as Dest = %u",
            anodr->stats.numReplyInitiatedAsDest);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP Forwarded = %u",
            anodr->stats.numReplyForwarded);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP ACKed = %u",
            anodr->stats.numReplyAcked);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP Received = %u",
            anodr->stats.numReplyRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP Received as Source = %u",
            anodr->stats.numReplyRecvedAsSource);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RREP-AACK Received = %u",
            anodr->stats.numReplyAackRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RERR Initiated = %u",
            anodr->stats.numRerrInitiated);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RERR Forwarded = %u",
            anodr->stats.numRerrForwarded);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RERR ACKed = %u",
            anodr->stats.numRerrAcked);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RERR Received = %u",
            anodr->stats.numRerrRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of RERR-AACK Received = %u",
            anodr->stats.numRerrAackRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of Data packets sent as Source = %u",
            anodr->stats.numDataInitiated);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of Data Packets Forwarded = %u",
            anodr->stats.numDataForwarded);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of Data Packets Received = %u",
            anodr->stats.numDataRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of DATA-AACK Received = %u",
            anodr->stats.numDataAackRecved);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of Data Packets Dropped for no route = %u",
            anodr->stats.numDataDroppedForNoRoute);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf,
            "Number of Data Packets Dropped for buffer overflow = %u",
            anodr->stats.numDataDroppedForOverlimit);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        sprintf(buf, "Number of times link broke = %u",
            anodr->stats.numBrokenLinks);
        IO_PrintStat(
            node,
            "Network",
            "ANODR",
            ANY_DEST,
            -1,
            buf);

        if (DEBUG_ROUTE_TABLE)
        {
            printf("Routing table at the end of simulation\n");
            AnodrPrintRoutingTable(node, &anodr->routeTable);
        }

        //fflush(node->partitionData->statFd);
    }

#ifdef DO_ECC_CRYPTO
    for (int i=0; i<12; i++)
    {
        mpi_free(anodr->eccKey[i]);
    }
#endif // DO_ECC_CRYPTO
}


//--------------------------------------------------------------------
// FUNCTION : AnodrHandleProtocolPacket
// PURPOSE  : Called when Anodr packet is received from MAC, the packets
//            may be of following types, Route Request, Route Reply,
//            Route Error, Route Acknowledgement
// ARGUMENTS: node,     The node received message
//            msg,      The message received
//            srcAddr,  Source Address of the message
//            destAddr, Destination Address of the message
//            ttl,      time to live
//            interfaceIndex, receiving interface
// RETURN   : None
//--------------------------------------------------------------------

void
AnodrHandleProtocolPacket(
    Node* node,
    Message* msg,
    NodeAddress srcAddr,
    NodeAddress destAddr,
    int ttl,
    int interfaceIndex)
{
    char* packetType = MESSAGE_ReturnPacket(msg);

    if (DEBUG_ANODR_TRACE)
    {
        AnodrPrintTrace(node, msg, 'R');
    }

    switch (*packetType)
    {
        case ANODR_RREQ:
        case ANODR_RREQ_SYMKEY:
        {
            if (DEBUG >= 4)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                char address[MAX_STRING_LENGTH] = DEFAULT_STRING;

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got ANODR-RREQ at time %s\n", node->nodeId,
                    clockStr);

                IO_ConvertIpAddressToString(srcAddr, address);
                printf("\tsource: %s\n", address);

                IO_ConvertIpAddressToString(destAddr, address);
                printf("\tdestination: %s\n", address);
            }

            AnodrSimulateCryptoOverhead(node,
                                        msg,
                                        CIPHER_ALGO_AES256,
                                        *packetType,
                                        interfaceIndex,
                                        ttl);
            break;
        }

        case ANODR_RREP:
        {
            if (DEBUG >= 3)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                char address[MAX_STRING_LENGTH] = DEFAULT_STRING;

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got ANODR-RREP at time %s\n", node->nodeId,
                    clockStr);

                if (DEBUG >= 4)
                {
                    IO_ConvertIpAddressToString(srcAddr, address);
                    printf("\tsource: %s\n", address);

                    IO_ConvertIpAddressToString(destAddr, address);
                    printf("\tdestination: %s\n", address);
                }
            }

            AnodrSimulateCryptoOverhead(node,
                                        msg,
                                        PUBKEY_ALGO_ECC,
                                        ANODR_RREP,
                                        interfaceIndex,
                                        ttl);
            break;
        }

#if defined(RREP_AACK) || defined(RERR_AACK)
        case ANODR_RREP_AACK:
        case ANODR_RERR_AACK:
        {
            if (DEBUG >= 3)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;;
                char address[MAX_STRING_LENGTH] = DEFAULT_STRING;;

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got ANODR-RREP/RERR-AACK at time %s\n",
                       node->nodeId, clockStr);

                if (DEBUG >= 4)
                {
                    IO_ConvertIpAddressToString(srcAddr, address);
                    printf("\tsource: %s\n", address);

                    IO_ConvertIpAddressToString(destAddr, address);
                    printf("\tdestination: %s\n", address);
                }
            }

            AnodrHandleControlAack(node, msg, interfaceIndex, *packetType);

            MESSAGE_Free(node, msg);
            break;
        }
#endif

#ifdef DATA_AACK
        case ANODR_DATA_AACK:
        {
            if (DEBUG >= 3)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                char address[MAX_STRING_LENGTH] = DEFAULT_STRING;

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got ANODR-DATA-AACK at time %s\n",
                       node->nodeId, clockStr);

                if (DEBUG >= 4)
                {
                    IO_ConvertIpAddressToString(srcAddr, address);
                    printf("\tsource: %s\n", address);

                    IO_ConvertIpAddressToString(destAddr, address);
                    printf("\tdestination: %s\n", address);
                }
            }

            AnodrHandleDataAack(node, msg, interfaceIndex);

            MESSAGE_Free(node, msg);
            break;
        }
#endif

        case ANODR_RERR:
        {
            if (DEBUG >= 3)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                char address[MAX_STRING_LENGTH]= DEFAULT_STRING;

                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u got ANODR-RERR at time %s\n", node->nodeId,
                    clockStr);

                IO_ConvertIpAddressToString(srcAddr, address);
                printf("\tsource: %s\n", address);

                IO_ConvertIpAddressToString(destAddr, address);
                printf("\tdestination: %s\n", address);
            }

            AnodrHandleRouteError(ANODR_RERR,
                                  node,
                                  msg,
                                  interfaceIndex);

            MESSAGE_Free(node, msg);
            break;
        }

        default:
        {
           ERROR_Assert(FALSE, "Unknown packet type for Anodr");
           break;
        }
    }
}


//--------------------------------------------------------------------
// FUNCTION: AnodrHandleProtocolEvent
// PURPOSE: Handles all the protocol events
// ARGUMENTS: node, the node received the event
//            msg,  msg containing the event type
//--------------------------------------------------------------------

void
AnodrHandleProtocolEvent(
    Node* node,
    Message* msg)
{
    AnodrData* anodr = (AnodrData *)
    NetworkIpGetRoutingProtocol(node, ROUTING_PROTOCOL_ANODR);
    AnodrRoutingTable* routeTable = &anodr->routeTable;

    switch (MESSAGE_GetEvent(msg))
    {
        // Remove the route that has not been used for awhile
        case MSG_NETWORK_CheckRouteTimeout:
        {
            if (DEBUG >= 2)
            {   char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u MSG_NETWORK_CheckRouteTimeout Timer"
                       " expired at %s\n",
                       node->nodeId,clockStr);
            }
            AnodrRouteEntry* current = NULL;

            // Just do a sequential scan over the VCI table
            for (current = routeTable->head;
                 current != NULL; current = current->next)
            {
                if (current->expireTime < node->getNodeTime())
                {
                    // expired route entry, delete it
                    AnodrDeleteRouteEntry(node, current, routeTable);
                }
            }
            // Recheck the route table again after a while
            if (DEBUG >= 2)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                printf("Node %u is setting timer "
                   "MSG_NETWORK_CheckRouteTimeout\n",
                    node->nodeId);
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u sets timer at %s\n",node->nodeId,clockStr);
                TIME_PrintClockInSecond((node->getNodeTime() +
                                    ANODR_ACTIVE_ROUTE_TIMEOUT/2), clockStr);
                printf("\ttimer to expire at %s\n", clockStr);
            }
            MESSAGE_Send(node, msg, ANODR_ACTIVE_ROUTE_TIMEOUT/2);
            break;
        }

#ifdef RREP_AACK
        // We implement network-layer AACK for RREP unicast control packets
        // Check if RREP-AACK is received after sending RREP unicast.
        case MSG_NETWORK_CheckRrepAck:
        {
            if (DEBUG >= 2)
            {
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u retries RREP due to no ACK received at %s\n",
                        node->nodeId,clockStr);
            }
            char *ptr = MESSAGE_ReturnInfo(msg); // placeholder
            AnodrPseudonym *pseudonym =
                (AnodrPseudonym *)(ptr+sizeof(NodeAddress));
            int interfaceIndex =
                *(int *)(ptr+sizeof(NodeAddress)+sizeof(AnodrPseudonym));
            BOOL isActiveRoute = FALSE;
            AnodrRouteEntry *matchingRow =
                AnodrCheckPseudonymUpstreamExist(pseudonym,
                                                 interfaceIndex,
                                                 NULL,
                                                 NULL,
                                                 routeTable,
                                                 &isActiveRoute);
            if (matchingRow == NULL)
            {
                if (DEBUG >= 2)
                {
                    printf("Waiting for RREP-AACK!"
                           "Check debug info to see if RERR occured before"
                           " and already deleted the entry.\n");
                }
            }
            else if (isActiveRoute == FALSE)
            {
                // Here is the timer expired for RREP
                // Waiting for RREP-ACK but not received,
                // resend the anonymous RREP unicast again
                if (matchingRow->unicastRrepRetry <
                                          ANODR_UNICAST_RETRANSMISSION_COUNT)
                {
                    matchingRow->unicastRrepRetry++;
                    AnodrRelayRREP(node, matchingRow);
                }
                else
                {
                    // Stop retrying, leave as it is, do nothing.
                    // Fortunately, it's possible that DATA will
                    // come in later, and the route becomes active.
                    // See HandleData().
                }
            }
            else
            {
                // Route is already active, do nothing
            }
            MESSAGE_Free(node, msg);
            break;
        }
#endif
#ifdef RERR_AACK
        // We implement network-layer AACK for RERR unicast control packets
        // Check if RERR-AACK is received after sending RERR unicast.
        case MSG_NETWORK_CheckRerrAck:
        {
            if (DEBUG >= 2)
            {
                printf("Node %u retries RERR due to no ACK received\n",
                        node->nodeId);
            }
            char *ptr = MESSAGE_ReturnInfo(msg); // placeholder
            AnodrPseudonym *pseudonym =
                (AnodrPseudonym *)(ptr+sizeof(NodeAddress));
            int interfaceIndex =
                *(int *)(ptr+sizeof(NodeAddress)+sizeof(AnodrPseudonym));
            BOOL isActiveRoute = FALSE;
            AnodrRouteEntry *matchingRow =
                AnodrCheckPseudonymUpstreamExist(pseudonym,
                                                 interfaceIndex,
                                                 NULL,
                                                 NULL,
                                                 routeTable,
                                                 &isActiveRoute);
            if (matchingRow != NULL)
            {
                // Here is the timer expired for RERR
                // Waiting for RERR-ACK but not received,
                // resend the RERR unicast again
                if (matchingRow->unicastRerrRetry <
                                          ANODR_UNICAST_RETRANSMISSION_COUNT)
                {
                    matchingRow->unicastRerrRetry++;
                    AnodrSendRouteErrorPacket(node,
                                              pseudonym,
                                              interfaceIndex);
                }
                else
                {
                    AnodrDeleteRouteEntry(node, matchingRow, routeTable);
                }
            }
            else
            {
                // Matching row already deleted.
                // 1. RERR-AACK already received after the timer is set, or
                // 2. Re-transmission count uplimit already reached.
            }
            MESSAGE_Free(node, msg);
            break;
        }
#endif
#ifdef DATA_AACK
        case MSG_NETWORK_CheckDataAck:
        {
            if (DEBUG >= 2)
            {
                printf("Node %u retries DATA due to no ACK received\n",
                        node->nodeId);
            }
            char *ptr = MESSAGE_ReturnInfo(msg); // placeholder
            AnodrPseudonym *pseudonym =
                (AnodrPseudonym *)(ptr+sizeof(NodeAddress));
            AnodrPseudonym matchPseudonym = DEFAULT_STRING;
            int interfaceIndex =
                *(int *) (ptr+sizeof(NodeAddress)+sizeof(AnodrPseudonym));
            int matchInterface;
            BOOL isActiveRoute = FALSE;
            BOOL reverseDir = FALSE;
            AnodrRouteEntry *matchingRow =
                AnodrCheckPseudonymDownstreamExist(pseudonym,
                                                   interfaceIndex,
                                                   &matchPseudonym,
                                                   &matchInterface,
                                                   routeTable,
                                                   &isActiveRoute);
            if (matchingRow == NULL)
            {
                matchingRow = AnodrCheckPseudonymUpstreamExist(pseudonym,
                                                 interfaceIndex,
                                                 &matchPseudonym,
                                                 &matchInterface,
                                                 routeTable,
                                                 &isActiveRoute);
                reversDir = TRUE;
            }
            if (matchingRow != NULL)
            {
                // Here is the timer expired for data
                // Waiting for network-layer DATA-ACK but not received,
                // resend the DATA unicast again
                if (matchingRow->unicastDataRetry <
                                          ANODR_UNICAST_RETRANSMISSION_COUNT)
                {
                    matchingRow->unicastDataRetry++;
                    Message *dataMsg =
                        AnodrGetBufferedPacket(ANONYMOUS_IP,
                                               pseudonym,
                                               &anodr->msgBuffer);
                    if (dataMsg != NULL)
                    {
                        AnodrTransmitData(node,
                                          dataMsg,
                                          pseudonym,
                                          reverseDir,
                                          interfaceIndex);
                    }
                }
                else
                {
                    AnodrSendRouteErrorPacket(node,
                                              &matchPseudonym,
                                              matchInterface);
                }
            }
            else
            {
                // The route entry already expired, do nothing
            }
            MESSAGE_Free(node, msg);
            break;
        }
#endif

        // Check if RREP is received after sending RREQ
        case MSG_NETWORK_CheckReplied:
        {
            char *ptr = MESSAGE_ReturnInfo(msg); // placeholder
            NodeAddress destAddr = *(NodeAddress *)ptr;
            AnodrRouteEntry *rtEntry = NULL ;

            if (DEBUG >= 2)
            {
                char address[MAX_STRING_LENGTH];
                char clockStr[MAX_STRING_LENGTH] = DEFAULT_STRING;
                IO_ConvertIpAddressToString(destAddr, address);
                TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                printf("Node %u MSG_NETWORK_CheckReplied Timer"
                       " expired at %s for dest %s\n",
                       node->nodeId,clockStr,address);
            }

            if ((rtEntry = AnodrCheckSent(destAddr, &anodr->routeTable))
                != NULL)
            {
                //RETRY RREQ only if the route is inactive
                if (!(rtEntry->activated))
                {
                    // RREQ sent, but RREP has not been obtained
                    if (rtEntry->rreqRetry < ANODR_RREQ_RETRIES)
                    {
                        // If the RREP is not received within
                        // NET_TRAVERSAL_TIME milliseconds, the node MAY try
                        // again to flood the RREQ, up to a maximum of
                        // RREQ_RETRIES times.  Each new attempt MUST
                        // use a different SEQNUM. AODV draft Sec: 8.3
                        rtEntry->rreqRetry++;
                        if (DEBUG >= 2)
                        {
                            printf("\t retries RREQ flooding due to no"
                                   " RREP received\n");
                        }
                        AnodrRetryRREQ(node, destAddr);
                    }
                    else
                    {
                        // If a RREQ has been flooded RREQ_RETRIES times
                        // without receiving any RREP, all data packets
                        // destined for the corresponding destination
                        // SHOULD be dropped from the buffer and a
                        // Destination Unreachable message delivered to the
                        // application. AODV draft Sec: 8.3
                        // Note: The second part not done even in AODV
                        // due to simulation-only nature.
                        Message* messageToDelete = NULL;

                        // Remove all the messages destined to the
                        // destination
                        messageToDelete = AnodrGetBufferedPacket(
                            destAddr,
                            NULL,
                            &anodr->msgBuffer);

                        if (DEBUG >= 2 && messageToDelete)
                        {
                            printf("\t remove all the buffered packets"
                                   " for the destination %d \n",
                                   node->nodeId);
                        }

                        while (messageToDelete)
                        {
                            anodr->stats.numDataDroppedForNoRoute++;

                            MESSAGE_Free(node, messageToDelete);

                            messageToDelete = AnodrGetBufferedPacket(
                                destAddr,
                                NULL,
                                &anodr->msgBuffer);
                        }

                        // Remove from sent table.
                        AnodrDeleteRouteEntry(node, rtEntry, &anodr->routeTable);
                    }
                }
                else
                {
                    if (DEBUG >= 2)
                    {
                        printf("\t route already active.\n");
                    }
                } //end of if (!(rtEntry->activated))
            }// end of
            //  if (( rtEntry = AnodrCheckSent(destAddr,&anodr->routeTable))

            MESSAGE_Free(node, msg);
            break;
        }

        case MSG_CRYPTO_Overhead:
        {
            AnodrCryptoOverheadType infoType = DEFAULT_STRING;

            memcpy(&infoType,
                   MESSAGE_ReturnInfo(msg),
                   sizeof(AnodrCryptoOverheadType));

            switch (infoType.packetType)
            {
                case ANODR_RREQ:
                case ANODR_RREQ_SYMKEY: {
                    if (DEBUG >= 4)
                    {
                        char clockStr[MAX_STRING_LENGTH];

                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        printf("Node %u finishes RREQ crypto operations "
                               "at time %s\n",node->nodeId, clockStr);
                    }
                    AnodrHandleRequest(
                        node,
                        msg,
                        infoType.ttl,
                        infoType.interfaceIndex);

                    MESSAGE_Free(node, msg);
                    break;
                }
                case ANODR_RREP: {
                    if (DEBUG >= 4)
                    {
                        char clockStr[MAX_STRING_LENGTH];

                        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
                        printf("Node %u finishes RREP crypto operations"
                               " at time %s\n",node->nodeId, clockStr);
                    }

                    AnodrHandleReply(node, msg, infoType.interfaceIndex);

                    MESSAGE_Free(node, msg);
                    break;
                }
                default: {
                    ERROR_Assert(FALSE, "Anodr: Unknown crypto"
                                        " overhead type!\n");
                    break;
                }
            }
            break;
        }

        default: {
            ERROR_Assert(FALSE, "Anodr: Unknown MSG type!\n");
            break;
        }
    }
}
