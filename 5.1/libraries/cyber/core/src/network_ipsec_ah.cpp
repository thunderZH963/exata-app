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
// PROTOCOL   :: AH
// LAYER      :: Network
// REFERENCES ::
// + rfc 2402
// COMMENTS   :: None
// **/

#include "api.h"
#include "message.h"
#include "network_ip.h"
#include "network_ipsec.h"
#include "network_ipsec_ah.h"
#include "network_pki.h"

#ifdef OPENSSL_LIB
#include "network_crypto.h"
#endif
#ifdef EXATA
#include "external_socket.h"
#include "capture_interface_ipsec.h"

#include "ipne_qualnet_interface.h"
#endif

#define IPSEC_AH_DEBUG 0

#if IPSEC_AH_DEBUG
#define dprintf printf
#else
#define dprintf(...)
#endif

// DESCRIPTION :: A table of available Authentication algorithm profiles
// of the system. This table is indexed by the algo name.
// Currently only those algo values are filled which shall be used
// in QualNet. Rest of the also entries are 0-filled.

IPsecAHAuthAlgoProfile
    IPsecAHAuthAlgoProfiles[IPsecAHAuthAlgoDefaultProfileCount] =
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


// /**
// FUNCTION   :: IPsecAHRemoveAHHeader
// LAYER      :: Network
// PURPOSE    :: Removing AH Header from message.
// PARAMETERS ::
//  +node      :  Node*    : Node pointer
//  +msg       :  Message* : Packet pointer
//  +size      :  int : size of AH header
// RETURN     :: void
// **/
static
void IPsecAHRemoveAHHeader(
    Node* node,
    Message* msg,
    int      size)
{
    MESSAGE_RemoveHeader(node, msg, size, TRACE_AH);
}

// /**
// FUNCTION   :: IPsecAHGetSPI
// LAYER      :: Network
// PURPOSE    :: Extarct AH SPI from message.
// PARAMETERS ::
//  +msg      :  Message* : Packet pointer
// RETURN     :: unsigned int : spi
// **/
unsigned int IPsecAHGetSPI(Message* msg)
{
    char* dataPtr = NULL;
    NodeAddress spi = 0;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    dataPtr = MESSAGE_ReturnPacket(msg) + IpHeaderSize(ipHdr)+ AH_WORD_SIZE;
    memcpy(&spi, dataPtr, sizeof(unsigned int));

    return spi;
}

// /**
// FUNCTION   :: IPsecAHInit
// LAYER      :: Network
// PURPOSE    :: AH Initialization.
// PARAMETERS ::
// + ah           : IPsecSecurityAssociationEntry* :: AH's SA .
// + authAlgoName : IPsecAuthAlgo :: Authentication Algorithm name.
// + authKey      : char* :: Authentication Key.
// + rateParams   : IPsecProcessingRate* :: Processing rate.
// RETURN     :: void
// **/
void
IPsecAHInit(IPsecSecurityAssociationEntry* ah,
            IPsecAuthAlgo authAlgoName,
            char* authKey,
            IPsecProcessingRate* rateParams)
{
    IPsecSecurityAssociationEntry* ahData = ah;

    ahData->auth.auth_algo_name = authAlgoName;
    if (authAlgoName != IPSEC_NULL_AUTHENTICATION)
    {
        strcpy(ahData->auth.algo_priv_Key, authKey);
    }

    // set the Authentication algo parameters from the QualNet-supported
    // profiles.

    ahData->auth.authLen = IPsecAHAuthAlgoProfiles[authAlgoName].authLen;

    strcpy(ahData->auth.auth_algo_str,
           IPsecAHAuthAlgoProfiles[authAlgoName].auth_algo_str);

    // Now set the rate parameter. This parameter cannot be saved in the
    // table as this is a user-configurable parameter.

    if (authAlgoName == IPSEC_HMAC_MD5)
    {
        ahData->auth.rate = (unsigned int) rateParams->hmacMd5Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_MD5_96)
    {
        ahData->auth.rate = (unsigned int) rateParams->hmacMd596Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_SHA1)
    {
        ahData->auth.rate = (unsigned int) rateParams->hmacSha1Rate;
    }
    else if (authAlgoName == IPSEC_HMAC_SHA_1_96)
    {
        ahData->auth.rate = (unsigned int) rateParams->hmacSha196Rate;
    }
    else if (authAlgoName == IPSEC_AES_XCBC_MAC_96)
    {
        ahData->auth.rate = (unsigned int) rateParams->aesXcbcMac96Rate;
    }
    else if (authAlgoName == IPSEC_NULL_AUTHENTICATION)
    {
        ahData->auth.rate = 0;
    }
    else
    {
        ERROR_ReportError("Unknown authentication algorithm specified\n");
    }
    return;
}




// /**
// FUNCTION   :: IPsecAHValidatedHandler
// LAYER      :: Network
// PURPOSE    :: Will Validate the ICV of the Inbound AH Packet.
// PARAMETERS ::
// + node           : Node* :: The node processing packet.
// + msg            : Message* :: Packet pointer.
// + saPtr          : IPsecSecurityAssociationEntry* :: Pointer to SA.
// + ahLen          : int :: Complete AH packet length.
// + nextLayerProto : int :: Next layer protocol.
// + delay          : clocktype* :: Processing Delay.
// RETURN :: void.
// **/
static
bool IPsecAHValidateHandler(Node* node,
                             Message* msg,
                             IPsecSecurityAssociationEntry* saPtr,
                             int ahLen,
                             int nextLayerProto,
                             clocktype* delay)
{
    int hLen = 0;
    int hLen_original = 0;
    int ipPktLen = 0;
    int payloadSize = 0;
    char* temp_packet = NULL;
    IpHeaderType* ipHdr = NULL;
    unsigned char* ICV_signature = NULL;
    unsigned int sign_leng = saPtr->auth.authLen;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    int AHIcvLen = saPtr->auth.authLen;

    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    hLen_original = (int) IpHeaderSize(ipHdr);
    ipPktLen = (int) IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);

    payloadSize = (int) ((IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len)
                 - (hLen + ahLen))
                 - msg->virtualPayloadSize);

    // temp_packet is the temporary packet used to generate the ICV, which
    // is in turn used for ICV validation.
    temp_packet = (char*) MEM_malloc((unsigned int) msg->packetSize);
    memcpy(temp_packet,
           MESSAGE_ReturnPacket(msg),
           (unsigned int) msg->packetSize);

    // ICV_signature stores the AH ICV  present in the inbound packet.
    ICV_signature =
        (unsigned char*) MEM_malloc((unsigned int) saPtr->auth.authLen);
    memcpy(ICV_signature,
           temp_packet + hLen + AH_FIXED_HEADER_SIZE,
           (unsigned int) saPtr->auth.authLen);

    // Zeroing ICV location.
    char* tempICVLocation =
        (char*) (temp_packet + hLen + AH_FIXED_HEADER_SIZE);
    memset(tempICVLocation, 0, saPtr->auth.authLen);

    // Zeroing IP Header Mutable fields.
    int* ipHeaderData = (int*) (temp_packet);
    // Among IP header's first 32 bits TOS is zeroed.
    ipHeaderData[0] = (int) (ipHeaderData[0] & 0xff00ffff);
    // Among IP header's next 32 bits flags and fragment offset are zeroed.
    ipHeaderData[1] = (int) (ipHeaderData[1] & 0x0000ffff);
    // Among IP header's next 32 bits TTL and checksum are zeroed.
    ipHeaderData[2] = (int) (ipHeaderData[2] & 0x0000ff00);

    if (hLen != sizeof(IpHeaderType))
    {
        char* tempIPOptionsLocation =
            (char*) (temp_packet + sizeof(IpHeaderType) + 2);
        unsigned int mutableIpOptionsSize = hLen - sizeof(IpHeaderType) - 2;
        memset(tempIPOptionsLocation, 0, mutableIpOptionsSize);
    }

    // Swapping from Host order to Network order. This is done for ICV
    // calculation and Validation.
    char* tempIpHd = temp_packet;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, (AH_HALF_WORD_SIZE));
    tempIpHd += AH_WORD_SIZE;
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);

    char* tempAhHd = temp_packet + hLen_original;
    tempAhHd = tempAhHd + AH_WORD_SIZE;
    EXTERNAL_hton(tempAhHd, AH_WORD_SIZE);
    tempAhHd = tempAhHd + AH_WORD_SIZE;
    EXTERNAL_hton(tempAhHd, AH_WORD_SIZE);

    bool result = false;
#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        result =
            CRYPTO_VerifyIcvValue((unsigned char*) (temp_packet),
                                   (int) (msg->packetSize),
                                 (unsigned char*) saPtr->auth.algo_priv_Key,
                                   (int) strlen(saPtr->auth.algo_priv_Key),
                                   (ICV_signature),
                                   (int)sign_leng,
                                   saPtr->auth.auth_algo_str);
        if (result == false)
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "IPSec AH Packet Integrity Failed");
            ERROR_ReportWarning(errStr);
            MEM_free(temp_packet);
            MEM_free(ICV_signature);
            *delay = 0;
            return false;
        }
    }

#endif // OPENSSL_LIB

    NodeAddress srcAddr = 0;
    NodeAddress dstAddr = 0;
    QueuePriorityType priority = 0;
    unsigned char ipProto = 0;
    unsigned ttl = 0;
    UInt16 ip_id = 0;
    UInt16 ipFragment = 0;

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
        MESSAGE_RemoveHeader(node, msg, 0, TRACE_FORWARD);

        // Recreate the headers as they would have been lost
        // if received from external entity.

        msg->packet += AH_FIXED_HEADER_SIZE + AHIcvLen;
        msg->packetSize = msg->packetSize
                         - (int) (AH_FIXED_HEADER_SIZE + AHIcvLen);
        MESSAGE_AddHeader(node,
                          msg,
                          (int) (AH_FIXED_HEADER_SIZE + AHIcvLen),
                          TRACE_AH);
    }

    IPsecAHRemoveAHHeader(node, msg, AH_FIXED_HEADER_SIZE + AHIcvLen);
    if (saPtr->mode == IPSEC_TRANSPORT
        || saPtr->mode == ANY)
    {
        IPsecAddIpHeader(node,
                         msg,
                         srcAddr,
                         dstAddr,
                         priority,
                         (unsigned char) nextLayerProto,
                         ttl,
                         ip_id,
                         ipFragment);
    }
    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    char* dat = MESSAGE_ReturnPacket(msg);

#ifdef EXATA
    AutoIPNEHandleSniffedIPsecPacket(node,
                                     msg,
                                     dat,
                                     ipHdr,
                                     (unsigned int) nextLayerProto);
#endif
    if (saPtr->auth.rate != 0)
    {
        *delay += (clocktype) (((payloadSize + AH_FIXED_HEADER_SIZE
                                + AHIcvLen)
                                * 8.0 * SECOND) / (saPtr->auth.rate));
    }
    MEM_free(temp_packet);
    MEM_free(ICV_signature);
    return true;
}


// /**
// FUNCTION   :: IPsecAHAuthenticateHandler
// LAYER      :: Network
// PURPOSE    :: Will Prepare the ICV for Outbound AH Packet.
// PARAMETERS ::
// + node           : Node* :: The node processing packet.
// + msg            : Message* :: Packet pointer.
// + saPtr          : IPsecSecurityAssociationEntry* :: Pointer to SA.
// + ahLen          : int :: Complete AH packet length.
// + nextLayerProto : int :: Next layer protocol.
// + delay          : clocktype* :: Processing Delay.
// RETURN :: void.
// **/
static
bool IPsecAHAuthenticateHandler(Node* node,
                                Message* msg,
                                IPsecSecurityAssociationEntry* saPtr,
                                int ahLen,
                                int nextLayerProto,
                                clocktype* delay)
{
    int hLen = 0;
    int hLen_original = 0;
    int ipPktLen = 0;
    int payloadSize = 0;
    char* temp_packet = NULL;
    IpHeaderType* ipHdr = NULL;
    unsigned char* signed_packet = NULL;
    unsigned int sign_leng = saPtr->auth.authLen;
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    int AHIcvLen = saPtr->auth.authLen;
    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    hLen_original = (int) IpHeaderSize(ipHdr);
    ipPktLen = (int) IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);

    payloadSize = (int) ((IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len)
                 - (hLen + ahLen))
                 - msg->virtualPayloadSize);

    char* pp = (char*) (msg->packet + hLen);
    pp[0] = (char) nextLayerProto;
    // AH Packet Length : Num of Words(4byte is 1 word) - 2.
    pp[1] = (char) ((ahLen / AH_WORD_SIZE) - 2);

    int* packet_pointerx = (int*) (msg->packet + hLen);
    packet_pointerx[1] = (int) saPtr->spi;
    packet_pointerx[2] = (int) saPtr->seqCounter;

    // temp_packet is the temporary packet used to generate the ICV.
    temp_packet = (char*) MEM_malloc((unsigned int) msg->packetSize);
    memcpy(temp_packet,
           MESSAGE_ReturnPacket(msg),
           (unsigned int) msg->packetSize);

    // Zeroing ICV location.
    char* tempICVLocation =
        (char*) (temp_packet + hLen + AH_FIXED_HEADER_SIZE);
    memset(tempICVLocation, 0, saPtr->auth.authLen);

    // Zeroing IP Header Mutable fields.
    int* ipHeaderData = (int*) (temp_packet);
    // Among IP header's first 32 bits TOS is zeroed.
    ipHeaderData[0] = (int) (ipHeaderData[0] & 0xff00ffff);
    // Among IP header's next 32 bits flags and fragment offset are zeroed.
    ipHeaderData[1] = (int) (ipHeaderData[1] & 0x0000ffff);
    // Among IP header's next 32 bits TTL and checksum are zeroed.
    ipHeaderData[2] = (int) (ipHeaderData[2] & 0x0000ff00);

    if (hLen != sizeof(IpHeaderType))
    {
        char* tempIPOptionsLocation =
            (char*) (temp_packet + sizeof(IpHeaderType) + 2);
        unsigned int mutableIpOptionsSize = hLen - sizeof(IpHeaderType) - 2;
        memset(tempIPOptionsLocation, 0, mutableIpOptionsSize);
    }

    // Swapping from Host order to Network order. This is done for ICV
    // calculation.
    char* tempIpHd = temp_packet;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, (AH_HALF_WORD_SIZE));
    tempIpHd += AH_WORD_SIZE;
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);
    tempIpHd += AH_WORD_SIZE;
    EXTERNAL_hton(tempIpHd, AH_WORD_SIZE);

    char* tempAhHd = temp_packet + hLen_original;
    tempAhHd = tempAhHd + AH_WORD_SIZE;
    EXTERNAL_hton(tempAhHd, AH_WORD_SIZE);
    tempAhHd = tempAhHd + AH_WORD_SIZE;
    EXTERNAL_hton(tempAhHd, AH_WORD_SIZE);

#ifdef OPENSSL_LIB
    if (ip->isIPsecOpenSSLEnabled)
    {
        signed_packet =
            CRYPTO_GetIcvValue((unsigned char*) (temp_packet),
                               (int) (msg->packetSize),
                               (unsigned char*) saPtr->auth.algo_priv_Key,
                               (int) (strlen(saPtr->auth.algo_priv_Key)),
                               &sign_leng,
                               saPtr->auth.auth_algo_str);
        if (signed_packet == NULL)
        {
            char errStr[MAX_STRING_LENGTH];
            sprintf(errStr, "IPSec AH Packet ICV Calculation Failed");
            ERROR_ReportWarning(errStr);
            *delay = 0;
            MEM_free(temp_packet);
            return false;
        }

        char* packet_pointer = msg->packet + hLen + AH_FIXED_HEADER_SIZE;
        memcpy(packet_pointer, signed_packet, sign_leng);
        MEM_free(signed_packet);
    }
#endif // OPENSSL_LIB
    if (saPtr->auth.rate != 0)
    {
        *delay += (clocktype) (((payloadSize + AH_FIXED_HEADER_SIZE
                                + AHIcvLen)
                                * 8.0 * SECOND) / (saPtr->auth.rate));
    }
    MEM_free(temp_packet);
    return true;
}


// /**
// FUNCTION   :: IPsecAHProcessOutput
// LAYER      :: Network
// PURPOSE    :: Will Process Outbound AH Packet.
// PARAMETERS ::
// + node           : Node* :: The node processing packet.
// + msg            : Message* :: Packet pointer.
// + saPtr          : IPsecSecurityAssociationEntry* :: Pointer to SA.
// + interfaceIndex : int :: Interface Index of the Node.
// RETURN     :: clocktype :: Delay.
// **/
clocktype
IPsecAHProcessOutput(Node* node,
                     Message* msg,
                     IPsecSecurityAssociationEntry* saPtr,
                     int interfaceIndex,
                     bool* isSuccess)
{
    clocktype delay = 0;

    IpHeaderType* ipHdr = NULL;
    int hLen = 0;
    int hLen_original = 0;

    char option[IP_MAX_HEADER_SIZE] = {'\0'};
    NodeAddress srcAddr = 0;
    NodeAddress dstAddr = 0;
    QueuePriorityType priority = 0;
    unsigned char ipProto = 0;
    unsigned ttl = 0;
    unsigned int hrm;
    int ipPktLen = 0;
    UInt16 ip_id = 0;
    UInt16 ipFragment = 0;

    if (IPSEC_AH_DEBUG)
    {
        printf("AH [Node %u]: Receive outbound packet for processing\n",
               node->nodeId);
    }

    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    hLen_original = (int) IpHeaderSize(ipHdr);
    ipPktLen = (int) IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);

    // Copy option starting next to the fixed IP header. Hence move to the
    // byte next to ipHdr.
    if (hLen != sizeof(IpHeaderType))
    {
        memcpy(option, ipHdr + 1, hLen - sizeof(IpHeaderType));
    }

    hrm = (unsigned int) (AH_FIXED_HEADER_SIZE + saPtr->auth.authLen);

#ifdef EXATA
    ProcessOutgoingIPSecPacket(node,
                               (UInt8*)MESSAGE_ReturnPacket(msg),
                               msg);
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

    MESSAGE_AddHeader(node, msg, (int) hrm, TRACE_AH);


    IPsecAddIpHeader(node,
                     msg,
                     srcAddr,
                     dstAddr,
                     priority,
                     IPPROTO_AH,
                     ttl,
                     ip_id,
                     ipFragment);

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

    *isSuccess = IPsecAHAuthenticateHandler(node,
                                            msg,
                                            saPtr,
                                            (int) hrm,
                                            (int) ipProto,
                                            &delay);

    if (IPSEC_AH_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(delay, clockStr);
        printf("    Processing delay = %ss\n", clockStr);
    }

    return delay;
}



// /**
// FUNCTION   :: IPsecAHProcessInput
// LAYER      :: Network
// PURPOSE    :: Will Process Inbound AH Packet.
// PARAMETERS ::
// + node           : Node* :: The node processing packet.
// + msg            : Message* :: Packet pointer.
// + saPtr          : IPsecSecurityAssociationEntry* :: Pointer to SA.
// + interfaceIndex : int :: Interface Index of the Node.
// RETURN     :: clocktype :: Delay.
// **/
clocktype
IPsecAHProcessInput(Node* node,
                    Message* msg,
                    IPsecSecurityAssociationEntry* saPtr,
                    int interfaceIndex,
                    bool* isSuccess)
{
    clocktype delay = 0;

    IpHeaderType* ipHdr = NULL;
    int hLen = 0;
    int hLen_original = 0;
    char option[IP_MAX_HEADER_SIZE] = {'\0'};
    unsigned int hrm;
    int ipPktLen = 0;
    unsigned char* ahHdr;
    int nextLayerProto = 0;

    if (IPSEC_AH_DEBUG)
    {
        printf("AH [Node %u]: Receive inbound packet for processing\n",
               node->nodeId);
    }

    ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    hLen = (int) IpHeaderSize(ipHdr);
    hLen_original = (int) IpHeaderSize(ipHdr);
    ipPktLen = (int) IpHeaderGetIpLength(ipHdr->ip_v_hl_tos_len);
    ahHdr = (unsigned char*) (msg->packet + hLen);
    nextLayerProto = ahHdr[0];
    // Copy option starting next to the fixed IP header. Hence move to the
    // byte next to ipHdr.
    if (hLen != sizeof(IpHeaderType))
    {
        memcpy(option, ipHdr + 1, hLen - sizeof(IpHeaderType));
    }

    hrm = (unsigned int) AH_FIXED_HEADER_SIZE + saPtr->auth.authLen;


    *isSuccess = IPsecAHValidateHandler(node,
                                        msg,
                                        saPtr,
                                        (int) hrm,
                                        (int) nextLayerProto,
                                        &delay);
    if (*isSuccess)
    {
        // Copy option, if present
        if (hLen_original != sizeof(IpHeaderType))
        {
            unsigned int optLen = hLen_original - sizeof(IpHeaderType);
            MESSAGE_ExpandPacket(node, msg, (int) optLen);
            memmove(msg->packet,
                    msg->packet + optLen,
                    sizeof(IpHeaderType));
            memcpy(msg->packet + sizeof(IpHeaderType), option, optLen);
            ipHdr = (IpHeaderType*)MESSAGE_ReturnPacket(msg);
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
    }
    if (IPSEC_AH_DEBUG)
    {
        char clockStr[MAX_STRING_LENGTH];

        TIME_PrintClockInSecond(delay, clockStr);
        printf("    Processing delay = %ss\n", clockStr);
    }

    return delay;
}
