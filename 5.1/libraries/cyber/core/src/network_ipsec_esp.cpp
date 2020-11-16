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


// /**
// PROTOCOL   :: ESP
// LAYER      :: Network
// REFERENCES ::
// + rfc 2406
// COMMENTS   :: None
// **/

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "network_ipsec.h"
#include "network_ipsec_esp.h"
#include "network_pki.h"

#ifdef OPENSSL_LIB
#include "network_crypto.h"
#endif
#ifdef EXATA
#include "external_socket.h"
#include "capture_interface_ipsec.h"

#include "ipne_qualnet_interface.h"
#endif

#define IPSEC_ESP_DEBUG 0

//Required for debugging the actual delays
//#define IPSEC_ESP_DELAY_DEBUG

#if IPSEC_ESP_DEBUG
#define dprintf printf
#else
#define dprintf(...)
#endif

#define CKSUM_CARRY(x) \
    (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))

// DESCRIPTION :: A table of available Authentication algorithm profiles
// of the system. This table is indexed by the algo name.
// Currently only those algo values are filled which shall be used
// in QualNet. Rest of the also entries are 0-filled.

IPsecAuthAlgoProfile
    IPsecAuthAlgoProfiles[IPsecAuthAlgoDefaultProfileCount] =
{
    //Algo Name,AlgoNameStr,authlen
    {IPSEC_AUTHALGO_LOWER, "NONE", 0},

    {IPSEC_HMAC_MD5, ALGO_HMAC_MD5, IPSEC_HMAC_MD5_AUTH_LEN},

    {IPSEC_HMAC_SHA1, ALGO_HMAC_SHA1, IPSEC_HMAC_SHA_1_AUTH_LEN},

    {IPSEC_HMAC_MD5_96, ALGO_HMAC_MD5_96, IPSEC_HMAC_MD5_96_AUTH_LEN},

    {IPSEC_HMAC_SHA_1_96, ALGO_HMAC_SHA1_96, IPSEC_HMAC_SHA_1_96_AUTH_LEN},

    {IPSEC_AES_XCBC_MAC_96,
     ALGO_AES_XCBC_MAC_96,
     IPSEC_AES_XCBC_MAC_96_AUTH_LEN},

    {IPSEC_NULL_AUTHENTICATION, ALGO_NULL_AUTH, 0}
};

// DESCRIPTION :: A table of available encryption algorithm profiles
// of the system. This table is indexed by the algo name.
// Currently only those algo values are filled which shall be used
// in QualNet. Rest of the also entries are 0-filled.

IPsecEncryptionAlgoProfile
    IPsecEncryptionAlgoProfiles[IPsecEncryptionAlgoDefaultProfileCount] =
{
    //Algo Name,AlgoNameStr,ivSize,iv[0],iv[1],iv[2],iv[3],blockSize
    {IPSEC_ENCRYPTIONALGO_LOWER,"NONE",0,{0,0,0,0},0},

    {IPSEC_DES_CBC,"DES-CBC",IPSEC_DES_IV_SIZE,
    {0,0,0,0},IPSEC_DES_BLOCK_SIZE},

    {IPSEC_SIMPLE,"NONE",0,{0,0,0,0},0},

    {IPSEC_BLOWFISH_CBC,"NONE",0,{0,0,0,0},0},

    {IPSEC_NULL_ENCRYPTION,"NULL",0,{0,0,0,0},1},

    {IPSEC_TRIPLE_DES_CBC,"DES-EDE3-CBC",IPSEC_TRIPLE_DES_CBC_IV_SIZE,
    {0,0,0,0},IPSEC_TRIPLE_DES_CBC_BLOCK_SIZE},

    {IPSEC_AES_CTR,"AES-CTR",IPSEC_AES_CTR_IV_SIZE,
    {0,0,0,0},IPSEC_AES_CTR_BLOCK_SIZE},

    {IPSEC_AES_CBC_128,"AES-CBC",IPSEC_AES_CBC_128_IV_SIZE,
    {0,0,0,0},IPSEC_AES_CBC_128_BLOCK_SIZE}
};

// /**
// FUNCTION   :: IPsecESPInit()
// LAYER      :: Network
// PURPOSE    :: Initialize ESP data for given SA
// PARAMETERS ::       :
// + node              : Node*         : The node processing inbound packet
// + esp               : IPsecEspData** : ESP data
// + authAlgoName      : IPsecAuthAlgo : Authentication algorithm to be used
// + encryptionAlgoName: IPsecEncryptionAlgo : Encryption algo to be used
// + authKey           : char*         : Key for authentication
// + enryptionKey      : char*         : Key for encryption
// + rateParams        : IPsecProcessingRate : rate parameters for
//                                               different algorithm
// RETURN     :: void : NULL
// **/
void IPsecESPInit(
    IPsecSecurityAssociationEntry* esp,
    IPsecAuthAlgo authAlgoName,
    IPsecEncryptionAlgo encryptAlgoName,
    char* authKey,
    char* encryptionKey,
    IPsecProcessingRate* rateParams)
{
    IPsecSecurityAssociationEntry* espData = esp;

    espData->encryp.encrypt_algo_name = encryptAlgoName;
    espData->auth.auth_algo_name = authAlgoName;
    if (authAlgoName != IPSEC_NULL_AUTHENTICATION)
    {
        strcpy(espData->auth.algo_priv_Key, authKey);
    }
    if (IPSEC_NULL_ENCRYPTION != espData->encryp.encrypt_algo_name)
    {
        strcpy(espData->encryp.algo_priv_Key, encryptionKey);
    }

    // set the Encryption algo parameters from the QualNet-supported
    // profiles.

    espData->encryp.blockSize =
        IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name]
        .blockSize;
    espData->encryp.ivSize =
       IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].ivSize;
    espData->encryp.iv[0] =
       IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].iv[0];
    espData->encryp.iv[1] =
       IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].iv[1];
    espData->encryp.iv[2] =
       IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].iv[2];
    espData->encryp.iv[3] =
       IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].iv[3];
    strcpy(espData->encryp.encrypt_algo_str,
           IPsecEncryptionAlgoProfiles[espData->encryp.encrypt_algo_name].
               encrypt_algo_str);

    // Now set the rate parameter. This parameter cannot be saved in the
    // table as this is a user-configurable parameter.

    espData->encryp.rate = (unsigned int) rateParams->desCbcRate;
    if (encryptAlgoName == IPSEC_NULL_ENCRYPTION)
    {
        espData->encryp.rate = 0;
    }

    // set the Authentication algo parameters from the QualNet-supported
    // profiles.

    espData->auth.authLen = IPsecAuthAlgoProfiles[authAlgoName].authLen;
    strcpy(espData->auth.auth_algo_str,
           IPsecAuthAlgoProfiles[authAlgoName].auth_algo_str);

    // Now set the rate parameter. This parameter cannot be saved in the
    // table as this is a user-configurable parameter.

    if (authAlgoName == IPSEC_HMAC_MD5)
    {
        espData->auth.rate = (unsigned int) rateParams->hmacMd5Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_MD5_96)
    {
        espData->auth.rate = (unsigned int) rateParams->hmacMd596Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_SHA1)
    {
        espData->auth.rate = (unsigned int) rateParams->hmacSha1Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_SHA_1_96)
    {
        espData->auth.rate = (unsigned int) rateParams->hmacSha196Rate;
    }
    else if (authAlgoName == IPSEC_AES_XCBC_MAC_96)
    {
        espData->auth.rate = (unsigned int) rateParams->aesXcbcMac96Rate;
    }
    else if (authAlgoName == IPSEC_NULL_AUTHENTICATION)
    {
        espData->auth.rate = 0;
    }
    else
    {
        ERROR_ReportError("Unknown authentication algorithm specified\n");
    }
    return;
}

// /**
// FUNCTION   :: IPsecDumpBytes()
// LAYER      :: Network
// PURPOSE    :: Prints the hexdump of the packet
// PARAMETERS ::       :
// + function_nm  : char*    : Function name from this function is invoked.
// + name         : char* : Caption of the data to be printed.
// + D      :  char* : buffer to be printed.
// + count  : UInt32 :length of the buffer to be printed.
// RETURN     :: void : NULL
// **/
void IPsecDumpBytes(
    char* function_nm,
    char* name,
    char* D,
    UInt64 count)
{

    UInt64 i;
    UInt64 base = 0;
    FILE* fp = stdout;

    dprintf("Name of the calling function: %s\n", function_nm);
    dprintf("Name of the string = %s   Size: %d\n", name, (int) count);

    dprintf("-------- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- ");
    dprintf("----------------\n" );
    for (; base+16 < count; base += 16)
    {
        dprintf("%08lX ", base );

        for (i = 0; i < 16; i++)
        {
            dprintf("%02X ",(unsigned char) D[base + i] );
        }

        dprintf("\n" );
    }
    dprintf("%08lX ", base );
    for (i = base; i < count; i++)
    {
        dprintf("%02X ", (unsigned char) D[i] );
    }

    dprintf("\n" );

    dprintf("------ -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- ");
    dprintf("----------------\n" );
    dprintf("\n" );
    fflush(fp);
}

// /**
// FUNCTION    :: IPsecInChecksum()
// LAYER       :: Network
// PURPOSE     :: Calculate the Checksum.
// PARAMETERS  ::
// + addr       : unsigned short*    : Starting Address from which checksum
//                                     needs to be calculated
// + len        : int                : Length of the payload for which the
//                                     checksum needs to be calculated
// RETURN       : int                : The checksum value
// **/

static
int IPsecInChecksum(
    unsigned short* addr,
    int len)
{
    int sum;

    sum = 0;

    while (len > 1)
    {
        sum += *addr++;
        len -= sizeof(unsigned short);
    }
    if (len == 1) //last byte remaining
    {
        sum += *(unsigned char*) addr;
    }

    return sum;
}

// /**
// FUNCTION    :: IPsecESPEncryptAuthHandle()
// LAYER       :: Network
// PURPOSE     :: Encrypts and authenticates the outgoing packet.
// PARAMETERS  ::
// + node    : node*    : Node pointer
// + msg     : Message* : Message pointer
// + saPtr   : IPsecSecurityAssociationEntry* : Ptr to security association
// + iv_size : unsigned int:  hash size for authentication.
// RETURN       : void
// **/
static
bool IPsecESPEncryptAuthHandle(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    unsigned int iv_size)
{
    IPsecSecurityAssociationEntry* espData = saPtr;
    IpHeaderType* ipHdr = NULL;
    int hLen = 0;
    unsigned int trm = 0;
    char* temp_packet = NULL;
    unsigned int* espp = NULL;
    int payloadSize = 0;
    unsigned char padLen = 0;
    char* dat = NULL;
    char* encrypt_start = NULL;
    unsigned int esphlen = 0;
    unsigned int encrypt_length = 0;
    unsigned char* signed_packet = NULL;
    unsigned int len = 0;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);

    // esphlen = spi (4 bytes) + seq no (4 bytes) + IV Size
    // so depending on iv_size, esphlen would be 8,16 or 24.

    switch (iv_size)
    {
        case 0:
            esphlen = 8;
            break;
        case 8:
            esphlen = 16;
            break;
        case 16:
           esphlen = 24;
            break;
        default:
            ERROR_ReportError("Invalid IV Size");
    }
    payloadSize = (int) ((IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len)
                 - (hLen + esphlen)) - msg->virtualPayloadSize);

    if (espData->encryp.encrypt_algo_name != IPSEC_NULL_ENCRYPTION)
    {
        padLen = (unsigned char) (espData->encryp.blockSize
                - ((payloadSize + ESP_TRAILER) % espData->encryp.blockSize));
    }
    // Even if the encryption algorithm is NULL, packet has to be aligned to
    // four byte boundary
    else
    {
        padLen = (unsigned char) (FOUR_BYTE_BOUNDARY
                 - ((payloadSize + ESP_TRAILER) % FOUR_BYTE_BOUNDARY));
    }

    trm = (unsigned int) (padLen + PADDING_LEN + NEXT_HEADER_FLD_LEN);
    len = msg->packetSize + trm;

    temp_packet = (char*) MEM_malloc((unsigned int) msg->packetSize);
    memcpy(temp_packet,
           MESSAGE_ReturnPacket(msg),
           (unsigned int) msg->packetSize);
    PKIPacketRealloc(node, msg, (int)len);
    memset(MESSAGE_ReturnPacket(msg), 0, (unsigned int) msg->packetSize);
    memcpy(MESSAGE_ReturnPacket(msg),
           temp_packet,
           (unsigned int) (msg->packetSize - trm));
    MEM_free(temp_packet);
    dat = (char*) MESSAGE_ReturnPacket(msg);

    dprintf("After Realloc\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                    MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    espp = (unsigned int*) (dat + hLen);
    ipHdr = (IpHeaderType*) dat;

    espData->seqCounter++;

    // If anti-replay is enabled the transmitted sequence
    // number never be allowed to cycle.

    if (espData->seqCounterOverFlow && espData->seqCounter == 0)
    {
        if (IPSEC_ESP_DEBUG)
        {
            printf("Node %u: SA %u expire\n", node->nodeId, espData->spi);
        }
        return false;
    }

    espp[0] = espData->spi;
    espp[1] = espData->seqCounter;

    // Fill in the IV only when the encryption algo is not NULL
    if (strcmp(espData->encryp.encrypt_algo_str, "NULL"))
    {
    switch (iv_size)    // Check for IV Wrap around needs to be checked
    {
        case 8:
            espp[2] = espData->encryp.iv[0];
            espp[3] = ~espp[2];
            espData->encryp.iv[0]++;
            espData->encryp.iv[1] = espp[3];
            break;
        case 16:
                UInt64* a;
                UInt64* b;
                a = (UInt64*)&(espData->encryp.iv[0]);
                b = (UInt64*)&(espp[2]);
            *b = *a;
            b++;
            *b = ~(*a);
            (*a)++;
            break;
        default:
            ERROR_ReportError("Invalid IV Size\n");
    }
    }

    //Filling up the Padding length and the next header fields at the last
    // two bytes

    dat[len - 1] = (char) ipHdr->ip_p;
    dat[len - 2] = (char) padLen;

    dprintf("After filling the IV and the ESP Trailer.\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    encrypt_start = dat + hLen + esphlen;
    encrypt_length = len - hLen - esphlen;

    // Encrypting the Payload, along with the payload padding,
    // padding length field and the next header field
    // Encrypting and updated the same message

    unsigned int out_leng = encrypt_length;
    unsigned int sign_leng = espData->auth.authLen;
    unsigned char* packet = NULL;

#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        char* encrypted_packet = NULL;
        out_leng = 0;
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&start, NULL);
        }
#endif
        encrypted_packet =
            (char*) CRYPTO_EncryptPacket(
                (unsigned char*) encrypt_start,
                (int) encrypt_length,
                &out_leng,
                espData->encryp.encrypt_algo_str,
                (unsigned char*) (espData->encryp.algo_priv_Key),
                (int) strlen(espData->encryp.algo_priv_Key),
                (unsigned char*) &espp[2],
                (int) iv_size);
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&end, NULL);
            dif_sec = (end.tv_sec - start.tv_sec)
                      + (end.tv_usec - start.tv_usec) / 1000000.00;
            printf("IPSEC_ESP: It took crypto lib %.10lf seconds"
                    " to encrypt the packet of length %d.\n",
                    dif_sec,
                    (int) encrypt_length);
        }
#endif
        if ((encrypted_packet == NULL) && (encrypt_length != 0))
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "IPSec: NULL Encrypted Payload Returned"
                            " for Non Null Packet Payload");
            ERROR_ReportWarning(errStr);
            return false;
        }

        dprintf("Encrypted Packet\n");
        IPsecPrintIPHeader(msg, node);
        IPsecDumpBytes((char*) __FUNCTION__,
                       (char*) "encrpyted_packet",
                        encrypted_packet,
                        (UInt64) out_leng);

        temp_packet = (char*) MEM_malloc((unsigned int) msg->packetSize);
        memcpy(temp_packet,
               MESSAGE_ReturnPacket(msg),
               (unsigned int) msg->packetSize);
        PKIPacketRealloc(node, msg, (int) (hLen + esphlen + out_leng));
        memset(MESSAGE_ReturnPacket(msg),
               0,
               (unsigned int) msg->packetSize);
        memcpy(MESSAGE_ReturnPacket(msg), temp_packet, hLen + esphlen);
        MEM_free(temp_packet);

        dat = (char*) MESSAGE_ReturnPacket(msg);
        encrypt_start = dat + hLen + esphlen;
        memcpy(encrypt_start, encrypted_packet, out_leng);

        MEM_free(encrypted_packet);
    }
#endif
    dprintf("Appending the encrypted packet to the message\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    // Performing Integrity check.
    // The signed output is appended at the rear of the packet

#ifdef EXATA
    // Now swap SPI/SEQ temporarily

    dat = (char*) MESSAGE_ReturnPacket(msg);
    packet = (unsigned char*) (dat + hLen);
    EXTERNAL_hton(packet, ESP_SPI_SIZE);
    packet += ESP_SPI_SIZE;
    EXTERNAL_hton(packet, ESP_SPI_SIZE);
#endif
#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        sign_leng = 0;
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&start, NULL);
        }
#endif //IPSEC_ESP_DELAY_DEBUG
        signed_packet =
            CRYPTO_GetIcvValue((unsigned char*) (dat + hLen),
                               (int) (esphlen + out_leng),
                               (unsigned char*) espData->auth.algo_priv_Key,
                               (int) (strlen(espData->auth.algo_priv_Key)),
                               &sign_leng,
                               espData->auth.auth_algo_str);
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&end, NULL);
            dif_sec = (end.tv_sec - start.tv_sec)
                      + (end.tv_usec - start.tv_usec) / 1000000.00;
            printf ("IPSEC_ESP: It took crypto lib %.10lf seconds"
                   " to sign the encrypted packet of length %d.\n",
                   dif_sec,
                   (int)(esphlen + out_leng));
        }
#endif //IPSEC_ESP_DELAY_DEBUG
        dprintf("Signed Packet\n");
        IPsecPrintIPHeader(msg, node);
        IPsecDumpBytes((char*) __FUNCTION__,
                       (char*) "signed_packet",
                       (char*) signed_packet,
                       (UInt64) sign_leng);

        dprintf("sign_leng = %u     espData->auth.authLen = %d\n"
                " espData->auth.auth_algo_str = %s\n",
                sign_leng,
                (int) espData->auth.authLen,
                espData->auth.auth_algo_str);
        if (strcmp(espData->auth.auth_algo_str,"NULL") &&
            ((signed_packet == NULL) ||
            (sign_leng != espData->auth.authLen)))
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "IPSec AH Packet ICV Calculation Failed");
            ERROR_ReportWarning(errStr);
            return false;
        }
    }
#endif
#ifdef EXATA
    // Swap back to host byte because the actual network order conversion
    // will be done in interface code

    dat = (char*) MESSAGE_ReturnPacket(msg);
    packet = (unsigned char*) (dat + hLen);
    EXTERNAL_hton(packet, ESP_SPI_SIZE);
    packet += ESP_SPI_SIZE;
    EXTERNAL_hton(packet, ESP_SPI_SIZE);
#endif
    temp_packet = (char*) MEM_malloc(hLen + esphlen + out_leng + sign_leng);
    memcpy(temp_packet,
           MESSAGE_ReturnPacket(msg),
           hLen + esphlen + out_leng);
    PKIPacketRealloc(node,
                     msg,
                     (int) (hLen + esphlen + out_leng + sign_leng));
    memset(MESSAGE_ReturnPacket(msg), 0, (unsigned int) msg->packetSize);
    memcpy(MESSAGE_ReturnPacket(msg),
           temp_packet,
           (unsigned int) (hLen + esphlen + out_leng));
    MEM_free(temp_packet);

    dat = (char*) MESSAGE_ReturnPacket(msg);
    encrypt_start = dat + hLen + esphlen;
    if (signed_packet)
    {
        memcpy(encrypt_start + out_leng, signed_packet, sign_leng);
        MEM_free(signed_packet);
    }

    ipHdr = (IpHeaderType*) dat;

    dprintf("Appending the signed packet to the message\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    ipHdr->ip_p = IPPROTO_ESP;
    unsigned int header_len = hLen + esphlen + out_leng + sign_leng
                             + msg->virtualPayloadSize;
    IpHeaderSetIpLength(&(ipHdr->ip_v_hl_tos_len), header_len);
    dprintf("Length of the packet = %d\n",
            hLen + esphlen + out_leng + sign_leng);

    ipHdr->ip_sum = 0;
#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        int sum = IPsecInChecksum((unsigned short*) ipHdr, (int) hLen);

        // Check if hLen is correct

        ipHdr->ip_sum = (unsigned short) CKSUM_CARRY(sum);
    }
#endif
    dprintf("Final Packet which is dumped out\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);
    return true;
}

// /**
// FUNCTION   :: IPsecESPEncapsulatePacket()
// LAYER      :: Network
// PURPOSE    :: Encapsulate the outbound packet.
// PARAMETERS ::
// + node      : Node*    : The node encapsulating packet
// + msg       : Message* : Packet pointer
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + delay     : clocktype* : Delay
// + interfaceIndex : the outputing interface
// RETURN     :: void : NULL
// **/
static
bool IPsecESPEncapsulatePacket(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    clocktype* delay,
    int interfaceIndex)
{
    IPsecSecurityAssociationEntry* espData = saPtr;
    IpHeaderType* ipHdr = NULL;
    int hLen = 0;
    int hLen_original = 0;
    int payloadSize = 0;
    unsigned char padLen = 0;
    char option[IP_MAX_HEADER_SIZE] = {'\0'};
    NodeAddress srcAddr = 0;
    NodeAddress dstAddr = 0;
    QueuePriorityType priority = 0;
    unsigned char ipProto = 0;
    unsigned ttl = 0;
    unsigned int hrm;
    unsigned int iv_size;
    UInt16 ip_id = 0;
    UInt16 ipFragment = 0;
    bool retVal = true;

    dprintf("Node = %d    Message Sequence Number= %d\n",
            node->nodeId,
            (*msg).sequenceNumber);

    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    hLen_original = (int) IpHeaderSize(ipHdr);

    // Copy option starting next to the fixed IP header. Hence move 1 byte
    // ahead.

    if (hLen != sizeof(IpHeaderType))
    {
        memcpy(option, ipHdr + 1, hLen - sizeof(IpHeaderType));
    }
    dprintf("Raw Packet\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    // For the purposes of ensuring that the bits to be encrypted
    // are a multiple of algorithm's blocksize.

    if (espData->enable_flags & IPSEC_ENABLE_COMBINED_ENCRYPT_AUTH_ALGO)
    {
        iv_size = 0;
    }
    else
    {
        iv_size = espData->encryp.ivSize;
    }

    hrm = SPI_LEN + SEQ_LEN + iv_size;

#ifdef EXATA
    ProcessOutgoingIPSecPacket(node, (UInt8*)MESSAGE_ReturnPacket(msg),msg);
#endif

    IPsecRemoveIpHeader(node,
                        msg,
                        &srcAddr,
                        &dstAddr,
                        &priority,
                        &ipProto,
                        &ttl,
                        &ip_id,
                        &ipFragment);
    MESSAGE_AddHeader(node, msg, (int) hrm, TRACE_ESP);

    IPsecAddIpHeader(node,
                     msg,
                     srcAddr,
                     dstAddr,
                     priority,
                     ipProto,
                     ttl,
                     ip_id,
                     ipFragment);

    // Copy option, if present

    if (hLen_original != sizeof(IpHeaderType))
    {
        int optLen = (int) (hLen_original - sizeof(IpHeaderType));
        MESSAGE_ExpandPacket(node, msg, optLen);
        memmove(msg->packet, msg->packet + optLen, sizeof(IpHeaderType));
        memcpy(msg->packet + sizeof(IpHeaderType),
               option,
               (unsigned int) optLen);
        ipHdr = (IpHeaderType*)MESSAGE_ReturnPacket(msg);
        unsigned int ipHeaderLength;

        //ip_v_hl_tos_len specifies the length of the IP packet header in
        //32 bit words so multiply with 4 to get the length in bytes.

        ipHeaderLength = IpHeaderGetHLen(ipHdr->ip_v_hl_tos_len) * 4;
        unsigned int ipPktLen = IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);
        IpHeaderSetIpLength(&(ipHdr->ip_v_hl_tos_len),
                            (ipPktLen + optLen));
        //Divide by word size = 4 as ip_hdr len is specified in 32 bit words

        unsigned int hdrSize_temp = (ipHeaderLength + optLen) / 4;
        IpHeaderSetHLen(&(ipHdr->ip_v_hl_tos_len), hdrSize_temp);
    }
    dprintf("After Moving the IP header\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);
    retVal = IPsecESPEncryptAuthHandle(node, msg, espData, iv_size);
    if (retVal == FALSE)
    {
        return retVal;
    }
    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    payloadSize = (int) (IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len)
                         - hLen);
    if (espData->encryp.encrypt_algo_name != IPSEC_NULL_ENCRYPTION)
    {
        padLen = (unsigned char) (espData->encryp.blockSize
                - ((payloadSize + ESP_TRAILER) % espData->encryp.blockSize));
    }
    // Even if the encryption algorithm is NULL, packet has to be aligned to
    // four byte boundary
    else
    {
        padLen = (unsigned char) (FOUR_BYTE_BOUNDARY
                 - ((payloadSize + ESP_TRAILER) % FOUR_BYTE_BOUNDARY));
    }

   // Calculate delay
   // Delay for encryption process
#ifdef TRANSPORT_AND_HAIPE
    IpInterfaceInfoType* intf =
        node->networkData.networkVar->interfaceInfo[interfaceIndex];
    if (strcmp(intf->haipeSpec.name, "Undefined") != 0)
    {
        double rate = intf->haipeSpec.operationRate;
        if (rate == 0)
        {
            *delay = 0;
        }
        else
        {
            *delay = (clocktype) (((payloadSize + padLen + ESP_TRAILER)
                      * 8.0) / rate);
        }
    }
    else
    {
        if (espData->encryp.rate != 0)
        {
            // Encryp processing rate is configured in bps.
            // Then multiply by 8 to get the delay for total bits.
            *delay = (clocktype) (((payloadSize + padLen + ESP_TRAILER)
                      * 8.0 * SECOND) / espData->encryp.rate);
        }
    }
    // Auth processing rate is configured in bps.
    // Then multiply by 8 to get the delay for total bits.
    if (espData->auth.rate > 0)
    {
        *delay += (clocktype) (((payloadSize
                   + padLen
                   + sizeof(IPsecEspHeader)
                   + espData->encryp.ivSize) * 8.0 * SECOND)
                   / espData->auth.rate);
    }
#else
    // Auth & Encryp rates are configured in bps.
    // Then multiply by 8 to get the delay for total bits.
    if (espData->encryp.rate)
    {
        *delay = ((payloadSize + padLen + ESP_TRAILER) * 8.0 * SECOND)
                  / (espData->encryp.rate);
    }
    // Delay for authentication process
    if (espData->auth.rate > 0)
    {
        *delay += ((payloadSize + padLen + sizeof(IPsecEspHeader)
               + espData->encryp.ivSize) * 8.0
               * SECOND / espData->auth.rate);
    }
#endif // TRANSPORT_AND_HAIPE
    return retVal;
}

// /**
// FUNCTION   :: IPsecESPProcessOutput()
// LAYER      :: Network
// PURPOSE    :: Process an outbound IP packet requires secure transfer.
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + interfaceIndex : the outputing interface
// RETURN     :: clocktype : delay
// **/
clocktype IPsecESPProcessOutput(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess)
{
    clocktype delay = 0;

    if (IPSEC_ESP_DEBUG)
    {
        printf("ESP [Node %u]: Receive outbound packet for processing\n",
               node->nodeId);
    }

    // Encapsulate packet
    *isSuccess = IPsecESPEncapsulatePacket(node,
                                           msg,
                                           saPtr,
                                           &delay,
                                           interfaceIndex);

    if (IPSEC_ESP_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH];

         TIME_PrintClockInSecond(delay, clockStr);
         printf("    Processing delay = %ss\n", clockStr);
    }

    return delay;
}

// /**
// FUNCTION   :: IPsecESPRemoveEspHeader()
// LAYER      :: Network
// PURPOSE    :: Remove ESP Header.
// PARAMETERS ::
// + node      : Node*    : The node processing inbound packet
// + msg       : Message* : Packet pointer
// + size:      int* : size of packet
// RETURN     :: void : NULL
// **/
static
void IPsecESPRemoveEspHeader(
    Node* node,
    Message* msg,
    int      size)
{
    MESSAGE_RemoveHeader(node, msg, size, TRACE_ESP);
}



// /**
// FUNCTION   :: IPsecESPDecryptnValidateICV()
// LAYER      :: Network
// PURPOSE    :: Will validate the packet, remove the ICV
//                      and return a pointer to the decrypted packet.
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + iv_size   : unsigned int : authentication hash size
// + hlen      :int           : ip header length including options
// + decrypt_length : unsigned int* : Length of the decrypted packet
// + proto     : unsigned int*  : Next Protocol field.
// + pad       : unsigned int*  : Pad Length
// RETURN     :: char* : decrypted packet pointer
// **/
static
char* IPsecESPValidateICVAndDecrypt(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    unsigned int iv_size,
    int hLen,
    unsigned int* decrypt_length,
    unsigned int* proto,
    unsigned int* pad)
{
    IPsecSecurityAssociationEntry* espData = saPtr;
    char* dat = NULL;
    unsigned int* espp;
    char* encrypt_start = NULL;
    char* decrypt_start = NULL;
    unsigned int iv[4], iv2[4];
    int seq = 0;
    UInt64 sign_leng = 0;
    UInt64 out_leng = 0;
    unsigned int esphlen = 0;
    unsigned int  len = 0;
    char* temp_packet = NULL;

    *decrypt_length = 0;
    *proto = 0;
    *pad = 0;
    unsigned char* packet = NULL;

    dprintf("Received Packet\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    dat   = (char*) MESSAGE_ReturnPacket(msg);
    len   = (unsigned int)msg->packetSize;

    espp  = (unsigned int*)(dat + hLen);
    packet = (unsigned char*)(dat + hLen);

    // esphlen = spi (4 bytes) + seq no (4 bytes) + IV Size
    // so depending on iv_size, esphlen would be 8,16 or 24.
    switch (iv_size)    // Check for IV Wrap around needs to be checked
    {
        case 0:
            iv[0] = 0;
            iv[1] = 0;
            iv[2] = 0;
            iv[3] = 0;
            esphlen = 8;
            break;
        case 8:
            iv[0] = espp[2];
            iv[1] = espp[3];
            iv[2] = 0;
            iv[3] = 0;
            esphlen = 16;
            break;
        case 16:
            iv[0] = espp[2];
            iv[1] = espp[3];
            iv[2] = espp[4];
            iv[3] = espp[5];
            esphlen = 24;
            break;
        default:
            ERROR_ReportError("Invalid IV Size\n");
    }

    seq = (int)espp[1];

    // Handle this sequence number for wrap arounds.
    // Check the replay window.

    iv2[0] = iv[0];
    iv2[1] = iv[1];

    sign_leng     = espData->auth.authLen;

    out_leng = len - hLen - esphlen - sign_leng;
    *decrypt_length = (unsigned int) out_leng;

    encrypt_start = dat + hLen + esphlen;
    decrypt_start = encrypt_start;

    if (encrypt_start > (dat + len))
    {
        dprintf("IPSec Payload Missing\n");
        return NULL;
    }

    dprintf("Validating ICV\n");
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "Validating ICV",
                   encrypt_start,
                   out_leng);
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    if (strcmp(espData->auth.auth_algo_str, "NULL"))
    {
#ifdef EXATA
        // Now swap SPI/SEQ temporarily

        packet = (unsigned char*) (dat + hLen);
        EXTERNAL_hton(packet, ESP_SPI_SIZE);
        packet += ESP_SPI_SIZE;
        EXTERNAL_hton(packet, ESP_SPI_SIZE);
#endif

#ifdef OPENSSL_LIB
        if (ip->isIPsecOpenSSLEnabled)
        {
#ifdef IPSEC_ESP_DELAY_DEBUG
            {
                gettimeofday(&start, NULL);
            }
#endif //IPSEC_ESP_DELAY_DEBUG
            if (!CRYPTO_VerifyIcvValue((unsigned char*) (dat + hLen),
                                       (int) (esphlen + out_leng),
                        (unsigned char*) espData->auth.algo_priv_Key,
                        (int) strlen(espData->auth.algo_priv_Key),
                                      (unsigned char*) (dat +
                                                        hLen +
                                                        esphlen +
                                                        out_leng),
                                       (int) sign_leng,
                                       espData->auth.auth_algo_str))
            {
                //Packet integrity failed, handle accordingly

                dprintf("Packet Integrity Failed\n");
                return NULL;
            }
#ifdef IPSEC_ESP_DELAY_DEBUG
            {
                gettimeofday(&end, NULL);
                dif_sec = (end.tv_sec - start.tv_sec)
                          + (end.tv_usec - start.tv_usec) / 1000000.00;
                printf ("IPSEC_ESP: It took crypto lib %.10lf seconds"
                       " to verify the decrypted packet of length %d.\n",
                       dif_sec,
                       *decrypt_length);
            }
#endif //IPSEC_ESP_DELAY_DEBUG
            dprintf("Signed Integrity Passed\n");
        }
#endif

#ifdef EXATA

        // Now swap SPI/SEQ again to retain correct value.

        packet = (unsigned char*) (dat + hLen);
        EXTERNAL_hton(packet, ESP_SPI_SIZE);
        packet += ESP_SPI_SIZE;
        EXTERNAL_hton(packet, ESP_SPI_SIZE);
#endif
    }

    dprintf("Decrypt_start\n");
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "decrypt_start",
                   encrypt_start,
                   out_leng);

#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        decrypt_start = NULL;
        *decrypt_length = 0;
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&start, NULL);
        }
#endif //IPSEC_ESP_DELAY_DEBUG
        decrypt_start = (char*) CRYPTO_DecryptPacket(
                           (unsigned char*) encrypt_start,
                           (int)out_leng,
                           decrypt_length,
                           espData->encryp.encrypt_algo_str,
                          (unsigned char*) (espData->encryp.algo_priv_Key),
                          (int) strlen(espData->encryp.algo_priv_Key),
                          (unsigned char*) &(iv[0]),
                          (int) iv_size);
#ifdef IPSEC_ESP_DELAY_DEBUG
        {
            gettimeofday(&end, NULL);
            dif_sec = (end.tv_sec - start.tv_sec)
                      + (end.tv_usec - start.tv_usec) / 1000000.00;
            printf ("IPSEC_ESP: It took crypto lib %.10lf seconds"
                   " to decrypt the packet of length %d.\n",
                   dif_sec,
                   *decrypt_length);
        }
#endif //IPSEC_ESP_DELAY_DEBUG
    }
#endif
    dprintf("Decrypted Payload\n");
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "decrypt_start",
                   decrypt_start,
                   *decrypt_length);
    if (decrypt_start == NULL)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr, "NULL Decrypted Packet Returned\n");
        ERROR_ReportWarning(errStr);
        return NULL;
    }

    // Extract protocol and pad from last two bytes

    *proto = (unsigned int) decrypt_start[(*decrypt_length) - 1];
    *pad   = (unsigned int) decrypt_start[(*decrypt_length) - 2];

    dprintf("Next Proto : %d     and Pad Length: %d\n", *proto, *pad);

    temp_packet = (char*) MEM_malloc(len - (unsigned int) sign_leng);
    memcpy(temp_packet,
           MESSAGE_ReturnPacket(msg),
           len - (unsigned int) sign_leng);
    PKIPacketRealloc(node, msg, (int) (len - sign_leng));
    memset(MESSAGE_ReturnPacket(msg), 0, (unsigned int) msg->packetSize);
    memcpy(MESSAGE_ReturnPacket(msg),
           temp_packet,
           (unsigned int) (len - sign_leng));
    MEM_free(temp_packet);

    dprintf("After removing the Signed Packet\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);
#ifdef OPENSSL_LIB
    if (!ip->isIPsecOpenSSLEnabled)
    {
        dat = (char*) MESSAGE_ReturnPacket(msg);
        decrypt_start = dat + hLen + esphlen;
    }
#endif

    return decrypt_start;
}

// /**
// FUNCTION   :: IPsecESPDecapsulatePacket()
// LAYER      :: Network
// PURPOSE    :: Decapsulate the inbound packet.
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + delay     : clocktype* : Delay
// + interfaceIndex : the inputing interface
// RETURN     :: void : NULL
// **/
static
bool IPsecESPDecapsulatePacket(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    clocktype* delay,
    int interfaceIndex)
{
    IPsecSecurityAssociationEntry* espData = saPtr;
    IpHeaderType* ipHdr = NULL;
    NodeAddress srcAddr = 0;
    NodeAddress dstAddr = 0;
    QueuePriorityType priority = 0;
    unsigned char ipProto = 0;
    unsigned ttl = 0;
    unsigned int payloadSize = 0;
    char* dat = NULL;
    char* decrypt_start = NULL;
    unsigned int hLen = 0;
    unsigned int hLen_original = 0;
    unsigned int decrypt_length = 0;
    unsigned int iv_size = 0;
    unsigned int proto = 0;
    unsigned int pad = 0;
    char* temp_packet = NULL;
    unsigned int temp_size = 0;
    UInt16 ip_id = 0;
    UInt16 ipFragment = 0;
    char option[IP_MAX_HEADER_SIZE] = {'\0'};
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    dprintf("Node = %d    Message Sequence Number= %d\n",
            node->nodeId,
            (*msg).sequenceNumber);

    if (espData->enable_flags & IPSEC_ENABLE_COMBINED_ENCRYPT_AUTH_ALGO)
    {
        iv_size = 0;
    }
    else
    {
        iv_size = espData->encryp.ivSize;
    }

    dat = (char*) MESSAGE_ReturnPacket(msg);
    ipHdr = (IpHeaderType*)dat;
    hLen = IpHeaderSize(ipHdr);
    hLen_original = IpHeaderSize(ipHdr);
    payloadSize = IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len) - hLen;

    // Copy option starting next to the fixed IP header. Hence move 1 byte
    // ahead.

    if (hLen != sizeof(IpHeaderType))
    {
        memcpy(option, ipHdr + 1, hLen - sizeof(IpHeaderType));
    }
    decrypt_start = IPsecESPValidateICVAndDecrypt(node,
                                                msg,
                                                saPtr,
                                                iv_size,
                                                (int)hLen,
                                                &decrypt_length,
                                                &proto,
                                                &pad);

    if (decrypt_start == NULL)
    {
        char errStr[MAX_STRING_LENGTH];
        sprintf(errStr,
                "IPSec Payload Missing Or Packet Integrity Failed\n");
        ERROR_ReportWarning(errStr);
        return false;
    }

    if (proto == IPSEC_DUMMY_NEXT_HEADER)
    {
        // Drop the packet and corresponding handling
        dprintf("Dropping an IPSec Dummy Packet\n");
        return true;
    }

    dat = MESSAGE_ReturnPacket(msg);

    IPsecRemoveIpHeader(node,
                        msg,
                        &srcAddr,
                        &dstAddr,
                        &priority,
                        &ipProto,
                        &ttl,
                        &ip_id,
                        &ipFragment);

    if ((msg->numberOfHeaders) &&
        (msg->headerProtocols[msg->numberOfHeaders - 1] == TRACE_FORWARD))
    {
        // Since the packet in this case is an emulated packet,
        // remove TRACE_FORWARD. Also, in this case, there is
        // no need to remove ESP header
        MESSAGE_RemoveHeader(node, msg, 0, TRACE_FORWARD);
    }
    else
    {
        IPsecESPRemoveEspHeader(node,
                                msg,
                                (int) (SPI_LEN + SEQ_LEN + iv_size));
    }

    if (espData->mode == IPSEC_TRANSPORT)
    {
        temp_size = hLen + decrypt_length;
#ifdef OPENSSL_LIB
        if ((ip->isIPsecOpenSSLEnabled) && decrypt_start)
        {
            PKIPacketRealloc(node, msg, (int) decrypt_length);
            memset(MESSAGE_ReturnPacket(msg),
                   0,
                   (unsigned int) msg->packetSize);
            memcpy(MESSAGE_ReturnPacket(msg),
                   decrypt_start,
                   decrypt_length);

            IPsecAddIpHeader(node,
                             msg,
                             srcAddr,
                             dstAddr,
                             priority,
                             ipProto,
                             ttl,
                             ip_id,
                             ipFragment);
            MEM_free(decrypt_start);
        }
        else if (decrypt_start)
        {
            IPsecAddIpHeader(node,
                             msg,
                             srcAddr,
                             dstAddr,
                             priority,
                             ipProto,
                             ttl,
                             ip_id,
                             ipFragment);
        }
#else
        if (decrypt_start)
        {

            IPsecAddIpHeader(node,
                             msg,
                             srcAddr,
                             dstAddr,
                             priority,
                             ipProto,
                             ttl,
                             ip_id,
                             ipFragment);
        }
#endif
        // Copy option, if present
        if (hLen_original != sizeof(IpHeaderType))
        {
            unsigned int optLen = hLen_original - sizeof(IpHeaderType);
            MESSAGE_ExpandPacket(node, msg, (int) optLen);
            memmove(msg->packet,
                    msg->packet + optLen,
                    sizeof(IpHeaderType));
            memcpy(msg->packet + sizeof(IpHeaderType), option, optLen);
            ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
            unsigned int ipHeaderLength;
            // ip_v_hl_tos_len specifies the length of the IP packet header
            // in 32 bit words so multiply with 4 to get the length in bytes
            ipHeaderLength = IpHeaderGetHLen(ipHdr->ip_v_hl_tos_len) * 4;
            unsigned int ipPktLen;
            ipPktLen = IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);
            IpHeaderSetIpLength(&(ipHdr->ip_v_hl_tos_len),
                              (ipPktLen + optLen));
            //Divide by word size = 4 as ip_hdr len is specified
            //in 32 bit words.
            unsigned int hdrSize_temp = (ipHeaderLength + optLen) / 4;
            IpHeaderSetHLen(&(ipHdr->ip_v_hl_tos_len), hdrSize_temp);
        }

        dat = MESSAGE_ReturnPacket(msg);
        dprintf("After Adding the Transport Mode Decrypted Packet\n");
        IPsecPrintIPHeader(msg, node);
        IPsecDumpBytes((char*) __FUNCTION__,
                       (char*) "msg->packet",
                       MESSAGE_ReturnPacket(msg),
                       (UInt32) msg->packetSize);

        temp_size -= (PADDING_LEN + NEXT_HEADER_FLD_LEN + pad);
    }
    else if (espData->mode == IPSEC_TUNNEL)
    {
#ifdef OPENSSL_LIB
        if ((ip->isIPsecOpenSSLEnabled) && decrypt_start)
        {
            PKIPacketRealloc(node, msg, (int) decrypt_length);
            memset(MESSAGE_ReturnPacket(msg),
                   0,
                   (unsigned int) msg->packetSize);
            memcpy(MESSAGE_ReturnPacket(msg),
                   decrypt_start,
                   decrypt_length);
            MEM_free(decrypt_start);
        }
#endif
        dat = MESSAGE_ReturnPacket(msg);
        dprintf("After Adding the Tunnel Mode Decrypted Packet\n");
        IPsecPrintIPHeader(msg, node);
        IPsecDumpBytes((char*) __FUNCTION__,
                       (char*) "msg->packet",
                       MESSAGE_ReturnPacket(msg),
                       (UInt64) msg->packetSize);
        temp_size = decrypt_length
                    - (PADDING_LEN + NEXT_HEADER_FLD_LEN + pad);
    }

    temp_packet = (char*) MEM_malloc(temp_size);
    memcpy(temp_packet, MESSAGE_ReturnPacket(msg), temp_size);
    PKIPacketRealloc(node, msg, (int) temp_size);
    memset(MESSAGE_ReturnPacket(msg), 0, (unsigned int) msg->packetSize);
    memcpy(MESSAGE_ReturnPacket(msg), temp_packet, temp_size);
    MEM_free(temp_packet);
    dat = MESSAGE_ReturnPacket(msg);

    dprintf("Packet After Removing the PADDING_LEN "
            "+ NEXT_HEADER_FLD_LEN + pad\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);
    ipHdr = (IpHeaderType*) dat;

    if (espData->mode == IPsecSAMode(IPSEC_TRANSPORT))
    {
        ipHdr->ip_p = (unsigned char) proto;
        IpHeaderSetIpLength(&(ipHdr->ip_v_hl_tos_len),
                          ((decrypt_length -
                          (PADDING_LEN + NEXT_HEADER_FLD_LEN + pad) + hLen)
                          + msg->virtualPayloadSize));
        ipHdr->ip_sum = 0;
        int sum = IPsecInChecksum((unsigned short*) ipHdr, (int) hLen);

          // Check if hLen is correct

        ipHdr->ip_sum = (unsigned short) CKSUM_CARRY(sum);

    }
#ifdef EXATA
    AutoIPNEHandleSniffedIPsecPacket(node, msg, dat, ipHdr, proto);
#endif
    dprintf("Final Decrypted Packet\n");
    IPsecPrintIPHeader(msg, node);
    IPsecDumpBytes((char*) __FUNCTION__,
                   (char*) "msg->packet",
                   MESSAGE_ReturnPacket(msg),
                   (UInt64) msg->packetSize);

    // Calculate delay
    // Delay for decryption process

#ifdef TRANSPORT_AND_HAIPE
    IpInterfaceInfoType* intf =
        node->networkData.networkVar->interfaceInfo[interfaceIndex];
    if (strcmp(intf->haipeSpec.name, "Undefined") != 0)
    {
        double rate = intf->haipeSpec.operationRate;

        if (rate == 0)
        {
            *delay = 0;
        }
        else
        {
            *delay = (clocktype) (((payloadSize + ESP_TRAILER
                     - (sizeof(IPsecEspHeader) + espData->encryp.ivSize
                     + espData->auth.authLen)) * 8.0) / rate);
        }
    }
    else
    {
        if (espData->encryp.rate)
        {
            // Encrypt rate is configured in bps.
            // Then multiply by 8 to get the delay for bits.
            *delay = (clocktype) (((payloadSize + ESP_TRAILER -
                 (sizeof(IPsecEspHeader) + espData->encryp.ivSize +
                 espData->auth.authLen)) * 8.0 * SECOND) /
                 espData->encryp.rate);
        }
    }
#else
    if (espData->encryp.rate)
    {
        // Encrypt rate is configured in bps.
        *delay = ((payloadSize + ESP_TRAILER - (sizeof(IPsecEspHeader)
              + espData->encryp.ivSize + espData->auth.authLen))
              * 8.0 * SECOND) / espData->encryp.rate;
    }
#endif

    // Delay for authentication process
    // Auth rate is configured in bps
    if (espData->auth.rate > 0)
    {
        *delay += (clocktype) ((payloadSize * 8.0 * SECOND) /
                  espData->auth.rate);
    }
    return true;
}

// /**
// FUNCTION   :: IPsecESPProcessInput()
// LAYER      :: Network
// PURPOSE    :: Process an inbound IPSEC packet
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + interfaceIndex : the inputing interface
// RETURN     :: void : clocktype
// **/
clocktype IPsecESPProcessInput(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess)
{
    clocktype delay = 0;

    if (IPSEC_ESP_DEBUG)
    {
        printf("ESP [Node %u]: Receive inbound packet for processing\n",
               node->nodeId);
    }

    // Decapsulate packet
    *isSuccess = IPsecESPDecapsulatePacket(node,
                                           msg,
                                           saPtr,
                                           &delay,
                                           interfaceIndex);

    if (IPSEC_ESP_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(delay, clockStr);
        printf("    Processing delay = %ss\n", clockStr);
    }

    return delay;
}

// /**
// FUNCTION   :: IPsecESPGetSPI()
// LAYER      :: Network
// PURPOSE    :: Extarct SPI from message.
// PARAMETERS ::
//  +msg       : Message* : Packet pointer
// RETURN      : unsigned int : spi
// **/
unsigned int IPsecESPGetSPI(Message* msg)
{
    char* dataPtr = NULL;
    NodeAddress spi = 0;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    dataPtr = MESSAGE_ReturnPacket(msg) + IpHeaderSize(ipHdr);
    memcpy(&spi, dataPtr, sizeof(unsigned int));

    return spi;
}

// /**
// FUNCTION   :: IPsecPrintIPHeader()
// LAYER      :: Network
// PURPOSE    :: Prints Ip header.
// PARAMETERS ::
//  +msg       : Message* : Packet pointer
//  +node      : Node*: :Node pointer
// RETURN      : void
// **/
void IPsecPrintIPHeader(Message* msg, Node* node)
{
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    dprintf("IP Header Data\n");
    dprintf("IP Version      : %u\n",
            IpHeaderGetVersion(ipHdr->ip_v_hl_tos_len));
    dprintf("IP Header Length: %u\n",
            IpHeaderGetHLen(ipHdr->ip_v_hl_tos_len));
    dprintf("IP Length       : %u\n",
            IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len));
    dprintf("IP Fragment     : %u\n",
            IpHeaderGetIpFragOffset(ipHdr->ipFragment));
    dprintf("IP Protocol     : %u\n", ipHdr->ip_p);

    if (node != NULL)
    {
        dprintf("Node: %d    Message Sequence No: %d\n",
                node->nodeId,
                (*msg).sequenceNumber);
    }
}
