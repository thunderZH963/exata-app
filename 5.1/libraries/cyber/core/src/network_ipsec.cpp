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
// PROTOCOL   :: IPSec
// LAYER      :: Network
// REFERENCES ::
// + rfc 2401
// + rfc 2406
// COMMENTS   :: None
// **/


#include "api.h"
#include "main.h"
#include "network_ip.h"
#include "network_icmp.h"
#include "network_ipsec_esp.h"
#include "network_ipsec_ah.h"
#include "transport_tcp_hdr.h"
#include "transport_udp.h"
#include "network_ipsec.h"
#include <vector>
#include <iostream>
#include <sstream>

using namespace std;

#ifdef ADDON_DB
#include "dbapi.h"
#endif

#define IPSEC_DEBUG 0
const char authAlgoName[][14] =
    {
        "",
        "HMAC_MD5",
        "HMAC_SHA1",
        "HMAC_MD5_96",
        "HMAC_SHA_1_96",
        "NULL"
    };
const char encryptionAlgoName[][13] =
    {
        "",
        "DES_CBC",
        "3DES_CBC",
        "SIMPLE",
        "BLOWFISH-CBC",
        "NULL"
    };

#ifdef TRANSPORT_AND_HAIPE
// /**
// ENUMERATION ::  HAIPE devices
// DESCRIPTION ::  HAIPE (High Assurance Internet Protocol Encryptor) is
//         a Type 1 encryption device that complies with the National
//         Security Agency (NSA)'s HAIPE IS (formerly the HAIPIS,
//         the High Assurance Internet Protocol Interoperability
//         Specification), where HAIPE IS is based on IPsec.
// **/
typedef enum
{
    KG_75,
    KG_75A,
    KG_82,
    KG_84,
    KG_84A,
    KG_84C,
    KG_94,
    KG_94A,
    KG_95_1,
    KG_95_2,
    KG_175A_TACLANE,
    KG_175B_TACLANE,
    KG_175D_TACLANE,
    KG_194,
    KG_194A,
    KG_245X,
    KIV_7,
    KIV_7HS,
    KIV_7HSA,
    KIV_7HSB,
    KIV_19,
    KIV_19A,
    KY_57,
    Motorola_NES,
    HAIPE_DUMMY // must be the last one
}HAIPE_devices;

// /**
// STRUCT ::  Default HAIPE devices
// DESCRIPTION ::  The order must exactly match the order in the enum list
// **/
#define DEFAULT_HAIPE_SURROGATE_RATE 2000000.0

// http://www.jproc.ca/crypto/menu.html
// : http://www.jproc.ca/crypto/kg84.html
// : http://www.jproc.ca/crypto/walburn.html
// : http://www.jproc.ca/crypto/kiv7.html
// : http://www.jproc.ca/crypto/kiv19.html
const HAIPESpec defaultHAIPESpec[HAIPE_DUMMY] =
    {
        { "KG_75", 10000000000.0 },
        { "KG_75A", 10000000000.0 },
        { "KG_82", 64000.0 },
        { "KG_84", 64000.0 },
        { "KG_84A", 256000.0 },
        { "KG_84C", 64000.0 },
        { "KG_94", 13000000.0 },
        { "KG_94A", 13000000.0 },
        { "KG_95_1", 50000000.0 },
        { "KG_95_2", 44736000.0 },
        { "KG_175A_TACLANE", 2000000000.0 },
        { "KG_175B_TACLANE", 200000000.0 },
        { "KG_175D_TACLANE", 4000000.0 },
        { "KG_194", 13000000.0 },
        { "KG_194A", 13000000.0 },
        { "KG_245X", 1000000000.0 },
        { "KIV_7", 512000.0 },
        { "KIV_7HS", 1544000.0 },
        { "KIV_7HSA", 2048000.0 },
        { "KIV_7HSB", 2048000.0 },
        { "KIV_19", 13000000.0 },
        { "KIV_19A", 13000000.0 },
        { "KY_57", 16000.0 },
        { "Motorola_NES", DEFAULT_HAIPE_SURROGATE_RATE },
    };
#endif // TRANSPORT_AND_HAIPE

// /**
// FUNCTION   :: IPsecRemoveIpHeader
// PURPOSE    :: Removes the ip header from the incoming packet.
// PARAMETERS ::
// + node                : Node structure.
// + msg                 : Message structure.
// + sourceAddress       : ip header source address.
// + destinationAddress  : ip header dst address.
// + priority            : ip header priority.
// + ttl                 : ip header ttl.
// + protocol            : ip header protocol.
// + ip_id               : ip header ip_id.
// + ipFragment          : ip header ipFragment.
// RETURN     :: void.
// **/

void
IPsecRemoveIpHeader(
    Node* node,
    Message* msg,
    NodeAddress* sourceAddress,
    NodeAddress* destinationAddress,
    TosType* priority,
    unsigned char* protocol,
    unsigned* ttl,
    UInt16* ip_id,
    UInt16* ipFragment)
{
    IpHeaderType* ipHeader = (IpHeaderType*) msg->packet;

    *priority = (TosType) IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len);
    *ttl = ipHeader->ip_ttl;
    *ip_id = ipHeader->ip_id;
    *ipFragment = ipHeader->ipFragment;
    *protocol = ipHeader->ip_p;
    *sourceAddress = ipHeader->ip_src;
    *destinationAddress = ipHeader->ip_dst;

    MESSAGE_RemoveHeader(node, msg, (int) IpHeaderSize(ipHeader), TRACE_IP);
}


// /**
// FUNCTION   :: IPsecAddIpHeader
// PURPOSE    :: Recreates the ip header from the incoming packet.
// PARAMETERS ::
// + node                : Node structure.
// + msg                 : Message structure.
// + sourceAddress       : ip header source address.
// + destinationAddress  : ip header dst address.
// + priority            : ip header priority.
// + ttl                 : ip header ttl.
// + protocol            : ip header protocol.
// + ip_id               : ip header ip_id.
// + ipFragment          : ip header ipFragment.
// RETURN     :: void.
// **/
void
IPsecAddIpHeader(
    Node* node,
    Message* msg,
    NodeAddress sourceAddress,
    NodeAddress destinationAddress,
    TosType priority,
    unsigned char protocol,
    unsigned ttl,
    UInt16 ip_id,
    UInt16 ipFragment)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IpHeaderType* ipHeader;
    int hdrSize = sizeof(IpHeaderType);

    MESSAGE_AddHeader(node, msg, hdrSize, TRACE_IP);

    ipHeader = (IpHeaderType*) msg->packet;
    memset(ipHeader, 0, (unsigned int) hdrSize);

    IpHeaderSetVersion(&(ipHeader->ip_v_hl_tos_len), IPVERSION4) ;

    ipHeader->ip_src = sourceAddress;
    ipHeader->ip_dst = destinationAddress;

#ifdef ADDON_DB
    StatsDBAddMessageAddrInfo(node, msg, sourceAddress, destinationAddress);
#endif // ADDON_DB
    if (ttl == 0)
    {
        ipHeader->ip_ttl = IPDEFTTL;
    }
    else
    {
        ipHeader->ip_ttl = (unsigned char) ttl;
    }
    ipHeader->ip_id = ip_id;
    ipHeader->ipFragment = ipFragment;

    // TOS field (8 bit) in the IPV4 header
    IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len), (unsigned int) priority);


    if (ip->isPacketEcnCapable)
    {
        // Bits 6 and 7 of TOS field in the IPV4 header are used by ECN
        // and proposed respectively for the ECT and CE bits.
        // So before assign the value of priority to ip_tos, leave bits 6
        // and 7.
        if (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) & 0x03)
        {
            // User TOS specification conflicts with an ~enabled~ ECN
            char errorString[MAX_STRING_LENGTH];
            sprintf(errorString,
                    "~enabled~ ECN!!! ECN bits of TOS field in"
                    " application Input should contain zero values\n");
            ERROR_ReportError(errorString);
        }

        IpHeaderSetTOS(&(ipHeader->ip_v_hl_tos_len),
            (IpHeaderGetTOS(ipHeader->ip_v_hl_tos_len) | IPTOS_ECT));
        ip->isPacketEcnCapable = FALSE;
    }
    ipHeader->ip_p = protocol;

    ERROR_Assert(MESSAGE_ReturnPacketSize(msg) <= IP_MAXPACKET,
                 "IP datagram (including header) exceeds"
                 " IP_MAXPACKET bytes");
    IpHeaderSetIpLength(&(ipHeader->ip_v_hl_tos_len),
            (unsigned int) MESSAGE_ReturnPacketSize(msg));
    unsigned int hdrSize_temp = (unsigned int) (hdrSize/4);
    IpHeaderSetHLen(&(ipHeader->ip_v_hl_tos_len), hdrSize_temp);
}

// /**
// FUNCTION   :: IPsecCheckIfTransportModeSASelectorsMatch
// PURPOSE    :: Check if particular SA's pointer is to be stored in SP
//               or not
// PARAMETERS ::
// + entryPtr         : IPsecSecurityPolicyEntry - SP whose selectors
//                      are to be matched with that of SA.
// + addressMap       : IPsecSelectorAddrMap - Map containing all SAs for
//                      caller node.
// + indexOfSAFilter  : int - SA filter of SP whose selectors
//                      are to be matched with that of SA.
// RETURN            :: TRUE if selctors match, FALSE, otherwise.
// **/
BOOL IPsecCheckIfTransportModeSASelectorsMatch(
    IPsecSecurityPolicyEntry* entryPtr,
    IPsecSelectorAddrListEntry addressListEntry,
    int indexOfSAFilter)
{
    IPsecSelectorAddrListEntry tempAddressListEntry = addressListEntry;
    unsigned int i = (unsigned int) indexOfSAFilter;

    if (((entryPtr->srcAddr == tempAddressListEntry.src)
       || ((entryPtr->srcAddr & entryPtr->srcMask)
       == (tempAddressListEntry.src & entryPtr->srcMask))
       || (entryPtr->srcAddr == IPSEC_WILDCARD_ADDR)
       || (tempAddressListEntry.src == IPSEC_WILDCARD_ADDR))
       && ((entryPtr->destAddr == tempAddressListEntry.dest)
       || ((entryPtr->destAddr & entryPtr->destMask)
       == (tempAddressListEntry.dest & entryPtr->destMask))
       || (entryPtr->destAddr == IPSEC_WILDCARD_ADDR)
       || (tempAddressListEntry.dest == IPSEC_WILDCARD_ADDR))
       && (entryPtr->saFilter.at(i)->ipsecProto
       == tempAddressListEntry.securityProtocol)
       && ((entryPtr->saFilter.at(i)->ipsecMode
       == tempAddressListEntry.mode)
       || (tempAddressListEntry.mode == ANY)))
   {
       return TRUE;
   }
   else
   {
        return FALSE;
   }
}

// /**
// FUNCTION   :: IPsecCheckIfTunnelModeSASelectorsMatch
// PURPOSE    :: Check if particular SA's pointer is to be stored in SP
//               or not
// PARAMETERS ::
// + entryPtr         : IPsecSecurityPolicyEntry - SP whose selectors
//                      are to be matched with that of SA.
// + addressMap       : IPsecSelectorAddrMap - Map containing all SAs for
//                      caller node.
// + indexOfSAFilter  : int - SA filter of SP whose selectors
//                      are to be matched with that of SA.
// RETURN            :: TRUE if selctors match, FALSE, otherwise.
// **/
BOOL IPsecCheckIfTunnelModeSASelectorsMatch(
    IPsecSecurityPolicyEntry* entryPtr,
    IPsecSelectorAddrListEntry addressListEntry,
    int indexOfSAFilter)
{
    IPsecSelectorAddrListEntry tempAddressListEntry = addressListEntry;
    unsigned int i = (unsigned int) indexOfSAFilter;

    if (((entryPtr->saFilter.at(i)->tunnelSrcAddr
       == tempAddressListEntry.src)
       || (tempAddressListEntry.src == IPSEC_WILDCARD_ADDR))
       && ((entryPtr->saFilter.at(i)->tunnelDestAddr
       == tempAddressListEntry.dest)
       || (tempAddressListEntry.dest == IPSEC_WILDCARD_ADDR))
       && (entryPtr->saFilter.at(i)->ipsecProto
       == tempAddressListEntry.securityProtocol)
       && ((entryPtr->saFilter.at(i)->ipsecMode
       == tempAddressListEntry.mode)))
   {
       return TRUE;
   }
   else
   {
       return FALSE;
   }
}

// /**
// FUNCTION   :: IPsecIsValidIpAddress
// PURPOSE    :: Check if a numeric string is a valid IpV4 address.
// PARAMETERS ::
// + addressString : const char - address (without mask)
//                   to determine if valid IpV4 address.
// RETURN     :: TRUE if address is valid Ip address, FALSE, otherwise.
// **/
BOOL IPsecIsValidIpAddress(const char addressString[])
{
    int i = 0;

    string address (addressString);
    string delimiter = ".";
    size_t index;
    size_t previousIndex = 0;
    vector<int> tokenizedIntegralParts;

    // Tokenize string using dot(.) as a delimiter

    index = address.find(delimiter, previousIndex);

    if (index == string::npos)
    {
        return FALSE;
    }
    else
    {
        while (index != string::npos)
        {
            string tempToken (address, 0, index);
            int tempNumber = 0;

            // Convert extracted string to int
            istringstream (tempToken) >> tempNumber;
            tokenizedIntegralParts.push_back(tempNumber);
            i++;
            address.erase(0, index + 1);
            index = address.find(delimiter, previousIndex);

            if (index == string::npos)
            {
                tempNumber = 0;
                istringstream (address) >> tempNumber;
                tokenizedIntegralParts.push_back(tempNumber);
                i++;
            }
        }
    }

    // A proper IPv4 Address when split using dot(.) as a delimiter
    // should give 4 parts. In case, the number is not 4, address isn't
    // proper IPv4 address
    if (i != 4)
    {
        return FALSE;
    }
    for (int j = 0; j < i; j++)
    {
        if (tokenizedIntegralParts[j] < 0
            || tokenizedIntegralParts[j] > 255)
        {
            return FALSE;
        }
    }
    return TRUE;
}

// /**
// FUNCTION   :: IPsecValidateNodeID
// PURPOSE    :: Check if a string is a permissible Node id in SA/SP entry
//               or not
// PARAMETERS ::
// + nodeIDString     : char - address to determine if it is
//                      a valid Node id in SA entry or not
// RETURN     :: BOOL : TRUE if valid otherwise FALSE
// **/
BOOL IPsecValidateNodeID(char nodeIDString[])
{
    string firstToken = "[";
    string secondToken = "]";
    string nodeString (nodeIDString);
    size_t firstTokenIndex;
    size_t secondTokenIndex;

    // Calculate indices where opening and closing brackets
    // are present
    firstTokenIndex = nodeString.find(firstToken);
    secondTokenIndex = nodeString.find(secondToken);

    if (firstTokenIndex != string::npos)
    {
        if (secondTokenIndex == string::npos)
        {
            return FALSE;
        }
        else
        {
            // Valid Nodeid should be of the format - [Node id]
            // where Node id can vary from 1 to maximum number of supported
            // nodes in Qualnet. Thus, there should be a difference
            // of at least 1 index between location of "[" and "]". Also,
            // "[" and "]" should occur only once
            if ((firstTokenIndex + 1 >= secondTokenIndex)
                || (nodeString.find_first_of(firstToken)
                != nodeString.find_last_of(firstToken))
                || (nodeString.find_first_of(secondToken)
                != nodeString.find_last_of(secondToken)))
            {
                return FALSE;
            }
            else
            {
                return TRUE;
            }
        }
    }
    else
    {
        return FALSE;
    }
}

// /**
// FUNCTION   :: IPsecValidateSrcOrDestSPAddress
// PURPOSE    :: Check if a numeric string is a valid Source/Destination
//               SP address.
// PARAMETERS ::
// + addressString    : const char - address (without mask)
//                      to determine if valid source/dest SP address.
// + outputRange      : NodeAddress* - address (without mask)
//                      to determine if valid IpV4 address.
// + outputPortNumber : unsigned short* - port number
//                      in string if valid IpV4 address.
// + numHostBits      : int* - number of host bits in IpV4 address.
// + parameterName    : char* - source address or destination address.
// RETURN             : NULL.
// **/
void IPsecValidateSrcOrDestSPAddress(char addressString[],
                                     NodeAddress* outputRange,
                                     unsigned short* outputPortNumber,
                                     int* numHostBits,
                                     char* parameterName)
{
    char* firstTokenPtr = NULL;
    char* secondTokenPtr = NULL;
    char errorBuf[MAX_STRING_LENGTH];

    // Check if optional port is present
    firstTokenPtr = strchr(addressString, '[');
    secondTokenPtr = strchr(addressString, ']');

    if (firstTokenPtr)
    {
        int port = 0;

        if (!secondTokenPtr)
        {
            sscanf(errorBuf, "Missing ] for opening [ in %s",
                    parameterName);
            ERROR_Assert(FALSE, errorBuf);
        }

        *firstTokenPtr = 0;
        firstTokenPtr = firstTokenPtr + 1;
        *secondTokenPtr = 0;

        if (!strcmp(firstTokenPtr, "*"))
        {
            port = IPSEC_WILDCARD_PORT;
        }
        else
        {
            port = atoi(firstTokenPtr);

            if (port > TCP_MAX_PORT || port < 0)
            {
                strcpy(errorBuf, "Invalid port specification in ");
                strcat(errorBuf, parameterName);
                ERROR_Assert(FALSE, errorBuf);
            }
            else
            {
                *outputPortNumber = (unsigned short) port;
            }
        }
    }

    else
    {
        *outputPortNumber = IPSEC_WILDCARD_PORT;
    }

    // Read address's range
    if (!strcmp(addressString, "*"))
    {
        *outputRange = IPSEC_WILDCARD_ADDR;
        *numHostBits = 32;
    }
    else
    {
        BOOL isNodeId;

        if (strchr(addressString, '/') && strchr(addressString, '.'))
        {
            char** address = 0;
            char tempStr[MAX_STRING_LENGTH] = {0};
            char hostBits[MAX_STRING_LENGTH] = {0};

            address = (char**)MEM_malloc(sizeof(char*)* 2);
            address[0] = (char*)MEM_malloc(sizeof(char)
                                        * MAX_STRING_LENGTH);

            address[0] = strtok(addressString, "/");
            address[1] = strtok(NULL, "/");
            *numHostBits = atoi(address[1]);

            if (*numHostBits < 0 || *numHostBits > 32)
            {
                strcpy(errorBuf, "Error in SP entry - Invalid"
                                 " number of host bits in ");
                strcat(errorBuf, parameterName);
                ERROR_Assert(FALSE, errorBuf);
            }

            if (IPsecIsValidIpAddress(address[0]))
            {
                strcpy(tempStr, "N");
                sprintf(hostBits, "%d", 32-atoi(address[1]));
                strcat(tempStr, hostBits);
                strcat(tempStr, "-");
                strcat(tempStr, addressString);
                strcpy(addressString, tempStr);
                IO_ParseNodeIdHostOrNetworkAddress(addressString,
                                                   outputRange,
                                                   numHostBits,
                                                   &isNodeId);
            }
            else
            {

                strcpy(errorBuf, "Error in SP entry - Invalid");
                strcat(errorBuf, parameterName);
                ERROR_Assert(FALSE, errorBuf);
            }
            MEM_free(address);
        }
        else if (strchr(addressString, '.'))
        {
            IO_ParseNodeIdHostOrNetworkAddress(addressString,
                                               outputRange,
                                               numHostBits,
                                               &isNodeId);
        }
        else
        {
            strcpy(errorBuf, "Error in SP entry - Invalid");
            strcat(errorBuf, parameterName);
            ERROR_Assert(FALSE, errorBuf);
        }

        if (*outputRange == 0)
        {
            strcpy(errorBuf, "Error in SP entry - Invalid");
            strcat(errorBuf, parameterName);
            ERROR_Assert(FALSE, errorBuf);
        }
    }
}

// /**
// FUNCTION    :: IPsecGetSrcAndDestPort
// LAYER       :: Network
// PURPOSE     :: Get source port and destination port from the packet
// PARAMETERS  ::
// + msg       : Message* : Packet pointer
// + srcPort   : unsigned short* : Source port number
// + destPort  : unsigned short* : Destination port number
// RETURN      :: void : NULL
// **/
static
void IPsecGetSrcAndDestPort(
    Message* msg,
    unsigned short* srcPort,
    unsigned short* destPort)
{
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    char* pktPtr = (char*) ipHdr + IpHeaderSize(ipHdr);

    int protocol = ipHdr->ip_p;

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr* tcpHeader = (struct tcphdr*) pktPtr;
        *srcPort = tcpHeader->th_sport;
        *destPort = tcpHeader->th_dport;
    }
    else if (protocol == IPPROTO_UDP)
    {
        TransportUdpHeader* udpHeader  = (TransportUdpHeader*) pktPtr;
        *srcPort = udpHeader->sourcePort;
        *destPort = udpHeader->destPort;
    }
    else
    {
        *srcPort = 0;
        *destPort = 0;
    }
}

// /**
// FUNCTION   :: IPsecVerifyUpperLayerProtocol
// LAYER      :: Network
// PURPOSE    :: Verify next header protocol with upper layer prottocol
//               in SP
// PARAMETERS ::
// + SPupperLayerProtocol : unsigned char : upper layer prottocol in SP
// + ipNextHeaderProtocol : unsigned char : next header protocol in IPheader
// RETURN     :: BOOL: TRUE if matching otherwise FALSE
// **/
BOOL IPsecVerifyUpperLayerProtocol(
    unsigned char SPupperLayerProtocol,
    unsigned char ipNextHeaderProtocol)
{
    if ((ipNextHeaderProtocol == SPupperLayerProtocol)
        || (ipNextHeaderProtocol == IPPROTO_IPV6)
        || (!SPupperLayerProtocol
            && (ipNextHeaderProtocol == IPPROTO_TCP
                 || ipNextHeaderProtocol == IPPROTO_UDP
                 || ipNextHeaderProtocol == IPPROTO_ESP
                 || ipNextHeaderProtocol == IPPROTO_AH
                 || ipNextHeaderProtocol == IPPROTO_ICMP
                 || ipNextHeaderProtocol == IPPROTO_IGMP)))
    {
        return TRUE;
    }

    return FALSE;
}

// /**
// FUNCTION   :: IPsecGetMatchingSP
// LAYER      :: Network
// PURPOSE    :: Get policy entry that matches packets selector fields
// PARAMETERS ::
// + msg       : Message* : Packet pointer
// + spd       : IPsecSecurityPolicyDatabase* : Security Policy Database
// RETURN     :: IPsecSecurityPolicyEntry* : matching SP, NULL if no match
//               found
// **/

IPsecSecurityPolicyEntry* IPsecGetMatchingSP(
    Message* msg,
    IPsecSecurityPolicyDatabase* spd)
{
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    if (spd)
    {
        IPsecSecurityPolicyEntry* sp = NULL;
        for (size_t i = 0; i < spd->size(); i++)
        {
            sp = spd->at(i);
            // Match the selectors
            if (((sp->srcAddr == IPSEC_WILDCARD_ADDR)
                || ((ipHdr->ip_src & sp->srcMask)
                == (sp->srcAddr & sp->srcMask)))
                && ((sp->destAddr == IPSEC_WILDCARD_ADDR)
                || ((ipHdr->ip_dst & sp->destMask)
                == (sp->destAddr & sp->destMask))))
            {
                // Check for protocol
                // Support for Dual-IP added
                if (IPsecVerifyUpperLayerProtocol
                    ((unsigned char)sp->upperLayerProtocol, ipHdr->ip_p))
                {
                    unsigned short srcPort = 0;
                    unsigned short destPort = 0;
                    IPsecGetSrcAndDestPort(msg, &srcPort, &destPort);
                    if ((sp->srcPort == IPSEC_WILDCARD_PORT
                        || sp->srcPort == srcPort)
                        && (sp->destPort == IPSEC_WILDCARD_PORT
                        || sp->destPort == destPort))
                    {
                        return sp;
                    }
                }
            }
        }
    }

    return NULL;
}


// /**
// FUNCTION   :: IPsecGetMatchingSA
// LAYER      :: Network
// PURPOSE    :: Get security association for src,dest,protocol,spi match
//               This is used for an incoming packet. The SA is identified
//               based on SPI + src-addr + dst-addr + ipsec-proto.
//               If 2 SAs are defined with same SPI and ipsec proto, but
//               one SA with exact match of src and dst adresses and the
//               other wildcarded, then the SA configured at the end will
//               be chosen.
// PARAMETERS ::
// + node      : Node*         : The node processing packet
// + protocol  : int*          : IP header protocol
// + src       : NodeAddress   : IP source address (outer header)
// + dest      : NodeAddress   : IP destination address (outer header)
// + spi       : unsigned int  : Security protocol index
// RETURN     :: IPsecSecurityAssociationEntry* : matching SA, NULL if no
//                                                match found
// **/

static
IPsecSecurityAssociationEntry* IPsecGetMatchingSA(
    Node* node,
    int protocol,
    NodeAddress src,
    NodeAddress dest,
    unsigned int spi)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPsecSecurityAssociationDatabase* sad = ip->sad;
    size_t i = 0;
    IPsecSecurityAssociationEntry* sa = NULL;

    for (i = 0; i < sad->size(); i++)
    {
        sa = sad->at(i);
        // Find SA using Source Address,Destination address,Protocol
        // and SPI as selectors
        if ((sa->src == IPSEC_WILDCARD_ADDR || sa->src == src)
            && (sa->dest == IPSEC_WILDCARD_ADDR || sa->dest == dest)
            && ((sa->securityProtocol == IPSEC_ESP
            && protocol == IPPROTO_ESP)
            || (sa->securityProtocol == IPSEC_AH
            && protocol == IPPROTO_AH))
            && (sa->spi == spi))
        {
            return sa;
        }
    }
    // If no match found, return NULL
    return NULL;
}



// /**
// FUNCTION   :: IPsecIsMyIP
// LAYER      :: Network
// PURPOSE    :: Check if the given IP address is associated with this node
// PARAMETERS ::
// + node      : Node*          : Node pointer
// + addr      : NodeaAddtress  : Address to be checked
// RETURN     :: BOOL : TRUE, if this is my address, FALSE otherwise
// **/

BOOL IPsecIsMyIP(Node* node, NodeAddress addr)
{
    int i;

    for (i = 0; i < node->numberInterfaces; i++)
    {
        if (addr == NetworkIpGetInterfaceAddress(node, i))
        {
            return TRUE;
        }
    }

    return FALSE;
}

// /**
// FUNCTION   :: IPsecSADInit
// LAYER      :: Network
// PURPOSE    :: Initializes security association database
// PARAMETERS ::
// + sad       : IPsecSecurityAssociationDatabase** : Address of IPsec
//               Security Association Database
// RETURN     :: void : NULL
// **/

void IPsecSADInit(IPsecSecurityAssociationDatabase** sad)
{
    (*sad) = (IPsecSecurityAssociationDatabase*)
            MEM_malloc(sizeof(IPsecSecurityAssociationDatabase));

    // set memory to zero
    memset(*sad, 0, sizeof(IPsecSecurityAssociationDatabase));
}

// /**
// FUNCTION   :: IPsecSPDInit
// LAYER      :: Network
// PURPOSE    :: Initializes security policy database
// PARAMETERS ::
// + spdInfo   : IPsecSecurityPolicyInformation** : address of Security
//               Policy Information Database
// RETURN     :: void : NULL
// **/
void IPsecSPDInit(IPsecSecurityPolicyInformation** spdInfo)
{
    (*spdInfo) = (IPsecSecurityPolicyInformation*)MEM_malloc
                  (sizeof(IPsecSecurityPolicyInformation));
    memset(*spdInfo, 0, sizeof(IPsecSecurityPolicyInformation));
    (*spdInfo)->spd = (IPsecSecurityPolicyDatabase*)
                       MEM_malloc(sizeof(IPsecSecurityPolicyDatabase));
    // Set memory to zero
    memset((*spdInfo)->spd, 0, (sizeof(IPsecSecurityPolicyDatabase)));
}

// /**
// FUNCTION   :: IPsecSADAddEntry
// LAYER      :: Network
// PURPOSE    :: Adding one security assciation to Security Association
//               Database
// PARAMETERS ::
// + node      : Node*       : The  node adding entry
// + newSA     : IPsecSecurityAssociationEntry*    : New security association
// RETURN     :: void : NULL
// **/

void IPsecSADAddEntry(Node* node, IPsecSecurityAssociationEntry* newSA)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPsecSecurityAssociationDatabase* sad = ip->sad;
    IPsecSecurityAssociationEntry* copyOfNewSA;
    copyOfNewSA = (IPsecSecurityAssociationEntry*)
                   MEM_malloc(sizeof(IPsecSecurityAssociationEntry));
    // Initialize the allocated memory with 0
    memset(copyOfNewSA, 0, sizeof(IPsecSecurityAssociationEntry));
    copyOfNewSA->spi = newSA->spi;
    copyOfNewSA->pmtu = newSA->pmtu;
    copyOfNewSA->dest = newSA->dest;
    copyOfNewSA->src = newSA->src;
    copyOfNewSA->seqCounter = newSA->seqCounter;
    copyOfNewSA->seqCounterOverFlow = newSA->seqCounterOverFlow;
    copyOfNewSA->lifeTime = newSA->lifeTime;
    copyOfNewSA->mode = newSA->mode;
    copyOfNewSA->softStateLife = newSA->softStateLife;
    copyOfNewSA->handleInboundPkt = newSA->handleInboundPkt;
    copyOfNewSA->handleOutboundPkt = newSA->handleOutboundPkt;
    copyOfNewSA->enable_flags = newSA->enable_flags;
    copyOfNewSA->auth = newSA->auth;
    copyOfNewSA->encryp = newSA->encryp;
    copyOfNewSA->combined = newSA->combined;
    copyOfNewSA->securityProtocol = newSA->securityProtocol;
    sad->push_back(copyOfNewSA);
}

// /**
// FUNCTION   :: IPsecSPDAddEntry
// LAYER      :: Network
// PURPOSE    :: Adding one security policy to Security Policy Database
// PARAMETERS ::
// + node           : Node*                      : The  node adding entry
// + interfaceIndex : int                        : Interface Index
// + newSP          : IPsecSecurityPolicyEntry*  : New security policy
// RETURN     :: void : NULL
// **/

void IPsecSPDAddEntry(
     Node* node,
     int interfaceIndex,
     IPsecSecurityPolicyEntry* newSP)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IpInterfaceInfoType* intfInfo = ip->interfaceInfo[interfaceIndex];
    IPsecSecurityPolicyInformation* spdInfo = NULL;

    if (newSP->direction == IPSEC_IN)
    {
        spdInfo = intfInfo->spdIN;
    }
    else
    {
        spdInfo = intfInfo->spdOUT;
    }

    IPsecSecurityPolicyEntry* copyOfNewSP;
    copyOfNewSP = (IPsecSecurityPolicyEntry*)
                  MEM_malloc(sizeof(IPsecSecurityPolicyEntry));
    // Initialize the allocated memory with 0
    memset(copyOfNewSP, 0, sizeof(IPsecSecurityPolicyEntry));

    // Assign different fields of the new SP
    copyOfNewSP->srcAddr = newSP->srcAddr;
    copyOfNewSP->srcMask = newSP->srcMask;
    copyOfNewSP->destAddr = newSP->destAddr;
    copyOfNewSP->destMask = newSP->destMask;
    copyOfNewSP->srcPort = newSP->srcPort;
    copyOfNewSP->destPort = newSP->destPort;
    copyOfNewSP->upperLayerProtocol = newSP->upperLayerProtocol;
    copyOfNewSP->direction = newSP->direction;
    copyOfNewSP->policy = newSP->policy;
    copyOfNewSP->saFilter = newSP->saFilter;

    copyOfNewSP->numSA = 0;
    copyOfNewSP->processingRate = newSP->processingRate;
    copyOfNewSP->saPtr = (IPsecSecurityAssociationEntry**)
                          MEM_malloc(sizeof(IPsecSecurityAssociationEntry*)
                          * INITIAL_SA_BUNDLE_SIZE);
    spdInfo->spd->push_back(copyOfNewSP);
}

// /**
// FUNCTION   :: IPsecUpdateSApointerInSPD
// LAYER      :: Network
// PURPOSE    :: Updating SA pointers in Security Policy Database
// PARAMETERS ::
// + node     : Node*                        : The node updating pointers
// + addressList  : IPsecSelectorAddrList    : SA addressList
// + spdToBeUpdated  : IPsecSecurityPolicyDatabase* : SPD to be updated
// RETURN     :: void : NULL
// **/
void IPsecUpdateSApointerInSPD(Node* node,
        IPsecSelectorAddrList addressList,
        IPsecSecurityPolicyDatabase* spdToBeUpdated)
{
    IPsecSecurityPolicyDatabase* spd = spdToBeUpdated;
    size_t index = 0;
    IPsecSelectorAddrList tempAddressList = addressList;

    if (spd)
    {
        while (index < spd->size())
        {
            IPsecSecurityPolicyEntry* entryPtr = spd->at(index);

            // Update SA pointers only when policy states to use IPSec
            if (entryPtr->policy == IPsecPolicy(IPSEC_USE))
            {
                for (size_t i = 0; i < entryPtr->saFilter.size(); i++)
                {
                    BOOL numSAIncremented = FALSE;

                    // SP for Transport mode
                    if (entryPtr->saFilter.at(i)->ipsecMode
                        == IPSEC_TRANSPORT)
                    {
                        for (size_t j = 0; j < tempAddressList.size(); j++)
                        {
                            if (IPsecCheckIfTransportModeSASelectorsMatch
                                (entryPtr,
                                *(tempAddressList.at(j)),
                                (int) i))
                            {
                                entryPtr->saPtr[i] =
                                            tempAddressList.at(j)->saEntry;
                                if (!numSAIncremented)
                                {
                                    entryPtr->numSA++;
                                    numSAIncremented = TRUE;
                                }
                            }
                        }
                        tempAddressList = addressList;
                    }// if close

                    // SP for Tunnel mode
                    if (entryPtr->saFilter.at(i)->ipsecMode == IPSEC_TUNNEL)
                    {
                        for (size_t j = 0; j < tempAddressList.size(); j++)
                        {
                            if (IPsecCheckIfTunnelModeSASelectorsMatch
                                (entryPtr,
                                *(tempAddressList.at(j)),
                                (int) i))
                            {
                                entryPtr->saPtr[i] =
                                            tempAddressList.at(j)->saEntry;
                                if (!numSAIncremented)
                                {
                                    entryPtr->numSA++;
                                    numSAIncremented = TRUE;
                                }
                            }
                        }
                        tempAddressList = addressList;
                    }// if close
#ifdef IPSEC_DEBUG
                    // Throw a warning if user has configured a security
                    // policy with SA filters which couldn't be mapped to
                    // any valid security association for this node
                    if (!numSAIncremented)
                    {
                        string warningStr = "No SA found for one of the SA";
                        warningStr.append(" filters mentioned in SP for");
                        warningStr.append(" Node ");
                        ostringstream nodeString;
                        nodeString << node->nodeId;
                        warningStr.append(nodeString.str());
                        ERROR_ReportWarning(warningStr.c_str());
                    }
#endif // IPSEC_DEBUG
                }// for close
            }
            index++;
        }// while close
    }// if close
}

// /**
// FUNCTION   :: IPsecCreateNewSA
// LAYER      :: Network
// PURPOSE    :: Creating a new Security Association
// PARAMETERS ::
// + node              : Node*         : The  node creating new SA
// + src               : NodeAddress   : Source Adddress
// + dest              : NodeAddress   : Destination Adddress
// + securityProtocol  : IPsecProtocol : Security protocol to be used
// + spi               : unsigned int  : Security Protocol Index
// + authAlgoName      : IPsecAuthAlgo : Authentication algorithm to be used
// + authKey           : char*         : Key for authentication
// + encryptionAlgoName: IPsecEncryptionAlgo : Encryption algorithm
// + enryptionKey      : char*         : Key for encryption
// + rateParams        : IPsecProcessingRate : Rate parameters for
//                                               different algorithm
// RETURN     :: IPsecSecurityAssociationEntry* : Pointer to the newly
//                                                created SA
// **/

IPsecSecurityAssociationEntry* IPsecCreateNewSA(
    IPsecSAMode mode,
    NodeAddress src,
    NodeAddress dest,
    IPsecProtocol securityProtocol,
    char* spi,
    IPsecAuthAlgo authAlgoName,
    char* authKey,
    IPsecEncryptionAlgo encryptAlgoName,
    char* encryptionKey,
    IPsecProcessingRate* rateParams)
{
    // Allocate the new SA
    IPsecSecurityAssociationEntry* newSA = (IPsecSecurityAssociationEntry*)
                          MEM_malloc(sizeof(IPsecSecurityAssociationEntry));

    // Initialize the allocated memory with 0
    memset(newSA, 0, sizeof(IPsecSecurityAssociationEntry));

    // Assign different fields of the SA
    newSA->src = src;
    newSA->spi = (unsigned int)strtoul(spi, NULL, 0);
    newSA->mode = mode;
    newSA->dest = dest;
    newSA->enable_flags = 0;

    // If security protocol is ESP
    if (securityProtocol == IPSEC_ESP)
    {
        newSA->securityProtocol = securityProtocol;
        IPsecESPInit((IPsecSecurityAssociationEntry*) newSA,
                     authAlgoName,
                     encryptAlgoName,
                     authKey,
                     encryptionKey,
                     rateParams);

        newSA->handleOutboundPkt = &IPsecESPProcessOutput;
        newSA->handleInboundPkt = &IPsecESPProcessInput;
    }

    // If security protocol is AH
    else if (securityProtocol == IPSEC_AH)
    {
        newSA->securityProtocol = securityProtocol;
        IPsecAHInit((IPsecSecurityAssociationEntry*) newSA,
                     authAlgoName,
                     authKey,
                     rateParams);

        newSA->handleOutboundPkt = &IPsecAHProcessOutput;
        newSA->handleInboundPkt = &IPsecAHProcessInput;
    }

    else
    {
        ERROR_Assert(FALSE, "Security protocol should be ESP/AH only \n");
    }

    return newSA;
}

// /**
// FUNCTION   :: IPsecGetAuthenticationAlgo
// LAYER      :: Network
// PURPOSE    :: Function to return authentication algorithm enum value for
//               a particular algorithm string
// PARAMETERS ::
// + authAlgoStr : char*       : Authentication algorithm string
// RETURN     :: IPsecAuthAlgo : Enum value for the authentication algorithm
// **/

IPsecAuthAlgo IPsecGetAuthenticationAlgo(char* authAlgoStr)
{
    IPsecAuthAlgo  authAlgo = DEFAULT_AUTH_ALGO;

    if (!strcmp(authAlgoStr, ALGO_HMAC_MD5))
    {
        authAlgo = IPSEC_HMAC_MD5;
    }
    else if (!strcmp(authAlgoStr, ALGO_HMAC_SHA1))
    {
        authAlgo = IPSEC_HMAC_SHA1;
    }
    else if (!strcmp(authAlgoStr, ALGO_HMAC_MD5_96))
    {
        authAlgo = IPSEC_HMAC_MD5_96;
    }
    else if (!strcmp(authAlgoStr, ALGO_HMAC_SHA1_96))
    {
        authAlgo = IPSEC_HMAC_SHA_1_96;
    }
    else if (!strcmp(authAlgoStr, ALGO_NULL_ENCRP))
    {
        authAlgo = IPSEC_NULL_AUTHENTICATION;
    }
    else if (!strcmp(authAlgoStr, ALGO_AES_XCBC_MAC_96))
    {
        authAlgo = IPSEC_AES_XCBC_MAC_96;
    }
    else if (!strcmp(authAlgoStr, "DEFAULT"))  // ISAKMP
    {
        authAlgo = DEFAULT_AUTH_ALGO;
    }
    else
    {
        ERROR_ReportError("Unknown authentication algorithm");
    }

    return authAlgo;
}

// /**
// FUNCTION   :: IPsecGetAuthenticationAlgoName
// LAYER      :: Network
// PURPOSE    :: Function to get Authentication algorithm string
// PARAMETERS ::
// + protocol  : IPsecAuthAlgo : security protocol
// RETURN     :: char* : Authentication algorithm string
// **/

const char* IPsecGetAuthenticationAlgoName(IPsecAuthAlgo  authAlgo)
{
    if (authAlgo > IPSEC_AUTHALGO_LOWER && authAlgo < IPSEC_AUTHALGO_UPPER)
    {
        return authAlgoName[authAlgo];
    }
    else
    {
        ERROR_ReportError("Unknown authentication algorithm");
    }
    return NULL;
}

// /**
// FUNCTION   :: IPsecGetEncryptionAlgo
// LAYER      :: Network
// PURPOSE    :: Function to return encryption algorithm enum value for a
//               particular algorithm string
// PARAMETERS ::
// + encryptionAlgoStr : char* : encryption algorithm string
// RETURN     :: IPsecEncryptionAlgo : Enum value for the encryption
//               algorithm
// **/

IPsecEncryptionAlgo IPsecGetEncryptionAlgo(char* encryptionAlgoStr)
{
    IPsecEncryptionAlgo encryptionAlgo = DEFAULT_ENCRYP_ALGO;

    if (!strcmp(encryptionAlgoStr, ALGO_DES_CBC))
    {
        encryptionAlgo = IPSEC_DES_CBC;
    }
    else if (!strcmp(encryptionAlgoStr, "SIMPLE"))
    {
        encryptionAlgo = IPSEC_SIMPLE;
    }
    else if (!strcmp(encryptionAlgoStr, "BLOWFISH-CBC"))
    {
        encryptionAlgo = IPSEC_BLOWFISH_CBC;
    }
    else if (!strcmp(encryptionAlgoStr, "NULL"))
    {
        encryptionAlgo = IPSEC_NULL_ENCRYPTION;
    }
    else if (!strcmp(encryptionAlgoStr, "3DES-CBC"))
    {
        encryptionAlgo = IPSEC_TRIPLE_DES_CBC;
    }
    else if (!strcmp(encryptionAlgoStr, ALGO_AES_CTR))
    {
        encryptionAlgo = IPSEC_AES_CTR;
    }
    // AES-CBC is equal to AES-CBC128
    else if (!strcmp(encryptionAlgoStr, ALGO_AES_CBC))
    {
        encryptionAlgo = IPSEC_AES_CBC_128;
    }
    else if (!strcmp(encryptionAlgoStr, ALGO_AES_CBC128))
    {
        encryptionAlgo = IPSEC_AES_CBC_128;
    }
    else if (!strcmp(encryptionAlgoStr, "DEFAULT"))
    {
        encryptionAlgo = DEFAULT_ENCRYP_ALGO;
    }
    else
    {
        ERROR_ReportError("Unknown encryption algorithm");
    }

    return encryptionAlgo;
}

// /**
// FUNCTION   :: IPsecGetEncryptionAlgoName
// LAYER      :: Network
// PURPOSE    :: Function to get encryption algorithm string
// PARAMETERS ::
// + protocol  : IPsecEncryptionAlgo : security protocol
// RETURN     :: char* : encryption algorithm string
// **/

const char* IPsecGetEncryptionAlgoName(IPsecEncryptionAlgo encryptionAlgo)
{
    if (encryptionAlgo > IPSEC_ENCRYPTIONALGO_LOWER &&
        encryptionAlgo < IPSEC_ENCRYPTIONALGO_UPPER)
    {
        return encryptionAlgoName[encryptionAlgo];
    }
    else
    {
        ERROR_ReportError("Unknown encryption algorithm");
    }
    return NULL;
}

// /**
// FUNCTION   :: IPsecGetSecurityProtocol
// LAYER      :: Network
// PURPOSE    :: Function to return enum value for which security protocols
//               to be used
// PARAMETERS ::
// + protocol  : char* : security protocol string
// RETURN     :: IPsecProtocol : Enum value for the security protocol
// **/

IPsecProtocol IPsecGetSecurityProtocol(char* protocol)
{
    if (!strcmp(protocol, "AH"))
    {
        return IPSEC_AH;
    }
    else if (!strcmp(protocol, "ESP"))
    {
        return IPSEC_ESP;
    }
    else
    {
        ERROR_ReportError("Unknown security protocol");
    }
    return IPSEC_INVALID_PROTO;
}

// /**
// FUNCTION   :: IPsecGetSecurityProtocolName
// LAYER      :: Network
// PURPOSE    :: Function to get security protocol string
// PARAMETERS ::
// + protocol  : IPsecProtocol : security protocol
// RETURN     :: char* : security protocol string
// **/

const char* IPsecGetSecurityProtocolName(IPsecProtocol ipsecProtocol)
{
    switch (ipsecProtocol)
    {
        case IPSEC_ISAKMP:
        {
            return "ISAKMP";
        }
        case IPSEC_AH:
        {
            return "AH";
        }
        case IPSEC_ESP:
        {
            return "ESP";
        }
        case IPSEC_INVALID_PROTO:
        default:
        {
            ERROR_ReportError("Unknown security protocol");
        }
    }
    return NULL;
}

// /**
// FUNCTION   :: IPsecGetMode
// LAYER      :: Network
// PURPOSE    :: Function to return IPsec mode whether TUNNEL or TRANSPORT
// PARAMETERS ::
// + modeStr   : char*       : Mode string
// RETURN     :: IPsecSAMode : mode enum value
// **/

IPsecSAMode IPsecGetMode(char* modeStr)
{
    IPsecSAMode mode = DEFAULT_MODE;

    if (!strcmp(modeStr, "TRANSPORT"))
    {
        mode = IPSEC_TRANSPORT;
    }
    else if (!strcmp(modeStr, "TUNNEL"))
    {
        mode = IPSEC_TUNNEL;
    }
    else if (!strcmp(modeStr, "ANY"))
    {
        mode = DEFAULT_MODE;
    }
    else
    {
        ERROR_ReportError("Unknown mode");
    }

    return mode;
}

// /**
// FUNCTION   :: IPsecGetModeName
// LAYER      :: Network
// PURPOSE    :: Function to return IPsec mode string
// PARAMETERS ::
// + mode      : IPsecSAMode: mode
// RETURN     :: char* : Mode string
// **/

const char* IPsecGetModeName(IPsecSAMode mode)
{
    static char modeName[12];

    if (mode == IPSEC_TRANSPORT)
    {
        strcpy(modeName, "TRANSPORT");
    }
    else if (mode == IPSEC_TUNNEL)
    {
        strcpy(modeName, "TUNNEL");
    }
    else
    {
        ERROR_ReportError("Unknown mode");
    }
    return modeName;
}

// /**
// FUNCTION   :: IPsecIsDuplicateEncrypAlgo
// LAYER      :: Network
// PURPOSE    :: Checking whether two SAs have same encryption algorithms
//               or not
// PARAMETERS ::
// + newAlgo  : AlgoDetails : Details of authorization algorithm
//              of the SA to be added
// + previousAlgo  : AlgoDetails : Details of authorization algorithm
//                   of SA already present in sender's SAD
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/

BOOL IPsecIsDuplicateEncrypAlgo(
    AlgoDetails newAlgo,
    AlgoDetails previousAlgo)
{
    if ((strcmp(newAlgo.algo_priv_Key, previousAlgo.algo_priv_Key))
        || (newAlgo.encrypt_algo_name != previousAlgo.encrypt_algo_name))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

// /**
// FUNCTION   :: IPsecIsDuplicateAuthAlgo
// LAYER      :: Network
// PURPOSE    :: Checking whether two SAs have same authorization algorithms
//               or not
// PARAMETERS ::
// + newAlgo  : AlgoDetails : Details of authorization algorithm
//              of the SA to be added
// + previousAlgo  : AlgoDetails : Details of authorization algorithm
//                   of SA already present in sender's SAD
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/

BOOL IPsecIsDuplicateAuthAlgo(
    AlgoDetails newAlgo,
    AlgoDetails previousAlgo)
{
    if ((strcmp(newAlgo.algo_priv_Key, previousAlgo.algo_priv_Key))
        || (newAlgo.auth_algo_name != previousAlgo.auth_algo_name))
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

// /**
// FUNCTION   :: IPsecIsDuplicateSA
// LAYER      :: Network
// PURPOSE    :: Checking whether security association to be added
//               to SAD is duplicate or not
// PARAMETERS ::
// + node           : Node*                      : The  node adding entry
// + newSA          : IPsecSecurityAssociationEntry*  : New security
//                    association
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/

BOOL IPsecIsDuplicateSA(
     Node* node,
     IPsecSecurityAssociationEntry* newSA)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPsecSecurityAssociationDatabase* sad = ip->sad;
    unsigned int numEntries = 0;
    numEntries = (unsigned int) sad->size();

    if (numEntries != 0)
    {
        unsigned int index = 0;

        while (index < numEntries)
        {
            IPsecSecurityAssociationEntry* entryPtr = sad->at(index);

            if ((newSA->src == entryPtr->src)
                && (newSA->dest == entryPtr->dest)
                && (newSA->spi == entryPtr->spi)
                && (newSA->mode == entryPtr->mode)
                && (newSA->securityProtocol == entryPtr->securityProtocol))
            {
                if (newSA->securityProtocol == IPSEC_AH)
                {
                    if (IPsecIsDuplicateAuthAlgo(newSA->auth,
                                                entryPtr->auth))
                    {
                        return TRUE;
                    }
                }

                else if (newSA->securityProtocol == IPSEC_ESP)
                {
                    if (IPsecIsDuplicateAuthAlgo(newSA->auth,
                                                entryPtr->auth)
                    && IPsecIsDuplicateEncrypAlgo(newSA->encryp,
                                                entryPtr->encryp))
                    {
                        return TRUE;
                    }
                }
            }
            index++;
        }// while close
    }// if close
    return FALSE;
}

// /**
// FUNCTION   :: IPsecIsDuplicateSA
// LAYER      :: Network
// PURPOSE    :: Checking whether two security associations are same
//               or not
// PARAMETERS ::
// + firstSA  :: IPsecSecurityAssociationEntry*  : One of the
//               security associations under consideration
// + secondSA :: IPsecSecurityAssociationEntry*  : One of the
//               security associations under consideration
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/
BOOL IPsecIsDuplicateSA(IPsecSecurityAssociationEntry* firstSA,
                        IPsecSecurityAssociationEntry* secondSA)
{
    if ((firstSA->src == secondSA->src)
        && (firstSA->dest == secondSA->dest)
        && (firstSA->spi == secondSA->spi)
        && (firstSA->mode == secondSA->mode)
        && (firstSA->securityProtocol == secondSA->securityProtocol))
    {
        if (firstSA->securityProtocol == IPSEC_AH)
        {
            if (IPsecIsDuplicateAuthAlgo(firstSA->auth,
                                        secondSA->auth))
            {
                return TRUE;
            }
        }
        else if (firstSA->securityProtocol == IPSEC_ESP)
        {
            if (IPsecIsDuplicateAuthAlgo(firstSA->auth,
                                        secondSA->auth)
            && IPsecIsDuplicateEncrypAlgo(firstSA->encryp,
                                        secondSA->encryp))
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

// /**
// FUNCTION    :: IPsecPreProcessInputLine
// LAYER       :: Network
// PURPOSE     :: Function to remove redundant spaces in nodeId/Interface
//                Address in an input line read from IPSec configuration
//                file
// PARAMETERS  ::
// + preprocessedInputLine  :: string : The input line containing redundant
//                                      spaces in nodeId or Interface
//                                      Address string
// RETURN                   :: string : Modified input line
// **/
string IPsecPreProcessInputLine(string preprocessedInputLine)
{
    string str(preprocessedInputLine);
    int i = 0;
    int n = 0;
    int j = 0;
    int m = 0;
    string space = " ";

    // Extract nodeIdString using ']' as a delimiter and maintain the index
    // where nodeIdString ends. This index will be used later to replace the
    // modified nodeIdString in the input line.

    n = str.find_first_of("]");
    string nodeIdString = str.substr(0, n + 1);

    while (i < (int) nodeIdString.length() - 1)
    {
        if (!nodeIdString.compare(i, 1, space))
        {
            for (j = i + 1; j < (int) str.length(); j++)
            {
                if (!nodeIdString.compare(j, 1, space))
                {
                    m++;
                }
                else
                {
                    break;
                }
            }
            // Erase all spaces and reinitialize number of spaces' counter
            nodeIdString.erase(i, m + 1);
            m = 0;
        }
        i++;
    }

    // Replace modified nodeIdString in the input line and return that line
    str.replace(0, n + 1, nodeIdString);
    return str;
}

// /**
// FUNCTION    :: IPsecProcessSAKeywords
// LAYER       :: Network
// PURPOSE     :: Function to validate occurences of keywords in SA
// PARAMETERS  ::
// + keywords   : char** keywords : Array of tokens to be validated
// + caseNumber : IPsecSACaseNumber : To determine which combination
//                of keywords is expected
// RETURN      :: void : NULL
// **/
void IPsecProcessSAKeywords(char** keywords,
                            IPsecSACaseNumber caseNumber)
{
    switch (caseNumber)
    {
        case IPSEC_SA_AH_MODE:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "AH")
                || strcmp(keywords[2], "-m")
                || strcmp(keywords[3], "-A"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        case IPSEC_SA_AH_NO_MODE:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "AH")
                || strcmp(keywords[2], "-A"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        case IPSEC_SA_ESP_ENCR:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "ESP")
                || strcmp(keywords[2], "-E"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        case IPSEC_SA_ESP_MODE_ENCR:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "ESP")
                || strcmp(keywords[2], "-m")
                || strcmp(keywords[3], "-E"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        case IPSEC_SA_ESP_ENCR_AUTH:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "ESP")
                || strcmp(keywords[2], "-E")
                || strcmp(keywords[3], "-A"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        case IPSEC_SA_ESP_MODE_ENCR_AUTH:
        {
            if (strcmp(keywords[0], "SA")
                || strcmp(keywords[1], "ESP")
                || strcmp(keywords[2], "-m")
                || strcmp(keywords[3], "-E")
                || strcmp(keywords[4], "-A"))
            {
                ERROR_Assert(FALSE, "Invalid SA entry");
            }
            break;
        }
        default:
        {
            ERROR_ReportError("Invalid SA entry");
        }
    }
}

// /**
// FUNCTION    :: IPsecProcessSPKeywords
// LAYER       :: Network
// PURPOSE     :: Function to validate occurences of keywords in SP
// PARAMETERS  ::
// + keywords   : char** keywords : Array of tokens to be validated
// + caseNumber : IPsecSPCaseNumber : To determine which combination
//                of keywords is expected
// RETURN      :: void : NULL
// **/
void IPsecProcessSPKeywords(char** keywords,
                            IPsecSPCaseNumber caseNumber)
{
    switch (caseNumber)
    {
        case IPSEC_SP_PROT_DIR_POL:
        {
            if (strcmp(keywords[0], "SP")
                || strcmp(keywords[1], "-P"))
            {
                ERROR_Assert(FALSE, "Invalid SP entry");
            }
            break;
        }
        case IPSEC_SP_PROT_POL:
        {
            if (strcmp(keywords[0], "SP"))
            {
                ERROR_Assert(FALSE, "Invalid SP entry");
            }
            break;
        }
        default:
        {
            ERROR_ReportError("Invalid SP entry");
        }
    }
}

// /**
// FUNCTION    :: IPsecReadSecurityAssociation
// LAYER       :: Network
// PURPOSE     :: Function to read security association configured in
//                the IPsec configuration file
// PARAMETERS  ::
// + node       : Node* : The node trying to read its security association
// + inputLine  : const char* : Entry of the ipsec main configuration file
//                being read
// + rateParams: IPsecProcessingRate* : For future use
// + addrList   : IPsecSelectorAddrList
//              : temporary structure to store addresses of SA vs SA
//                selectors
// RETURN      :: void : NULL
// **/

static
void IPsecReadSecurityAssociation(
    Node* node,
    const char* inputLine,
    IPsecProcessingRate* rateParams,
    IPsecSelectorAddrList* addrList)
{
    int numValRead = 0;
    char nodeId[MAX_STRING_LENGTH] = {0};
    char modeStr[MAX_STRING_LENGTH] = {0};
    char srcStr[MAX_STRING_LENGTH] = {0};
    char destStr[MAX_STRING_LENGTH] = {0};
    IPsecSAMode mode = (IPsecSAMode)IPSEC_TRANSPORT;
    char spi[MAX_STRING_LENGTH] = {0};
    NodeAddress src = 0;
    NodeAddress dest = 0;
    IPsecAuthAlgo authAlgo = DEFAULT_AUTH_ALGO;
    IPsecEncryptionAlgo encryptionAlgo = DEFAULT_ENCRYP_ALGO;

    BOOL isAuthentication = FALSE;
    BOOL isEncryption = FALSE;

    char authAlgoStr[MAX_STRING_LENGTH] = {0};
    char authKey[BIG_STRING_LENGTH] = {0};

    char encryptionAlgoStr[MAX_STRING_LENGTH] = {0};
    char encryptionKey[BIG_STRING_LENGTH] = {0};
    IPsecProtocol securityProtocol = (IPsecProtocol)IPSEC_AH;
    int encryptionKeyLength = 0;
    int authKeyLength = 0;

    IPsecSecurityAssociationEntry* newSA = NULL;
    char nodeString[5];

    sprintf(nodeString, "%d", node->nodeId);

    string preprocessedInputLine(inputLine);
    string tempInputString;
    tempInputString = IPsecPreProcessInputLine(preprocessedInputLine);
    int tempInputStringLength = tempInputString.length();
    ERROR_Assert(tempInputStringLength < MAX_STRING_LENGTH,
                 "Invalid Entry - Length of the entry cannot be"
                 " beyond 512 characters");

    char* tempInputLine;
    tempInputLine = new char[tempInputString.size() + 1];
    strcpy(tempInputLine, tempInputString.c_str());

    // This array of strings will hold the keywords like "SA", "AH", "-m"
    // etc. It will be used in conjunction with caseNumber to validate the
    // occurences of keywords
    char** keywords;
    keywords = (char**) MEM_malloc(MAX_VALID_SA_TOKENS * sizeof(char*));
    for (int i = 0; i < MAX_VALID_SA_TOKENS; i++)
    {
        keywords[i] = (char*) MEM_malloc(MAX_STRING_LENGTH);
    }

    IPsecSACaseNumber caseNumber = IPSEC_SA_AH_MODE;

    // SA entry for AH
    if (strstr(tempInputLine, " AH ") && !strstr(tempInputLine, " ESP "))
    {
        if (!strstr(tempInputLine, " -A "))
        {
            ERROR_Assert(FALSE, "Invalid SA entry - "
                                "Authentication Algorithm missing");
        }
        if (strstr(tempInputLine, " -E "))
        {
            ERROR_Assert(FALSE, "Invalid SA entry - "
                                "-E cannot be used with AH protocol in SA");
        }
        else
        {
            if (strstr(tempInputLine, " -m "))
            {
                numValRead = sscanf(tempInputLine,
                                    "%s%s%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    modeStr,
                                    keywords[3],
                                    authAlgoStr,
                                    authKey);
                caseNumber = (IPsecSACaseNumber)IPSEC_SA_AH_MODE;
                if (numValRead != 11)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }
            }

            else
            {
                numValRead = sscanf(tempInputLine,
                                    "%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    authAlgoStr,
                                    authKey);
                caseNumber = IPSEC_SA_AH_NO_MODE;
                if (numValRead != 9)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }

                strcpy(modeStr, "ANY");
            }
            isAuthentication = TRUE;
        }
        securityProtocol = (IPsecProtocol)IPSEC_AH;

        // Check whether key contains quotes. If quotes are present, extract
        // the key (skipping the quotes), else, validate it considering it
        // as a hexstring and then convert it into a char string
        if (!strstr(authKey, "\""))
        {
            strcpy(authKey,
                    IPsecHexToChar(authKey, &authKeyLength));
        }
        else
        {
            // If the authentication algorithm is NULL, alert the user as
            // this algorithm is not supported with AH
            ERROR_Assert(strcmp(authAlgoStr, "NULL"),
                         "NULL Authentication not supported with AH");

            // If the authentication algorithm is anything but NULL and the
            // key size in the quotes is 0, it is a misconfiguration
            ERROR_Assert(strcmp(authKey, "\"\""),
                         "Invalid Authentication key in SA entry");
            char tempAuthKey[BIG_STRING_LENGTH];
            strcpy(tempAuthKey, IO_Chop(authKey + 1));
            strcpy(authKey, tempAuthKey);
        }
    }

    // SA entry for ESP
    else if (strstr(tempInputLine, " ESP ")
            && !strstr(tempInputLine, " AH "))
    {
        if (!strstr(tempInputLine, " -E "))
        {
            ERROR_Assert(FALSE, "Invalid SA entry - "
                                "Encryption Algorithm missing");
        }

        else
        {
            if (!strstr(tempInputLine, " -m ")
                && !strstr(tempInputLine, " -A "))
            {
                numValRead = sscanf(tempInputLine, "%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    encryptionAlgoStr,
                                    encryptionKey);
                caseNumber = IPSEC_SA_ESP_ENCR;
                if (numValRead != 9)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }

                isEncryption = TRUE;
                strcpy(modeStr, "ANY");
            }
            else if (strstr(tempInputLine, " -m ")
                    && !strstr(tempInputLine, " -A "))
            {
                numValRead = sscanf(tempInputLine,
                                    "%s%s%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    modeStr,
                                    keywords[3],
                                    encryptionAlgoStr,
                                    encryptionKey);

                caseNumber = IPSEC_SA_ESP_MODE_ENCR;
                if (numValRead != 11)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }

                isEncryption = TRUE;
            }
            else if (strstr(tempInputLine, " -A ")
                    && !strstr(tempInputLine, " -m "))
            {
                numValRead = sscanf(tempInputLine,
                                    "%s%s%s%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    encryptionAlgoStr,
                                    encryptionKey,
                                    keywords[3],
                                    authAlgoStr,
                                    authKey);
                caseNumber = IPSEC_SA_ESP_ENCR_AUTH;
                if (numValRead != 12)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }
                if (!strcmp(encryptionAlgoStr, "NULL")
                    && !strcmp(authAlgoStr, "NULL"))
                {
                    ERROR_Assert(FALSE, "Invalid SA entry - Both encryption"
                                        " and authentication algorithms"
                                        " cannot be NULL");
                }
                isAuthentication = TRUE;
                isEncryption = TRUE;
                strcpy(modeStr, "ANY");
            }

            else
            {
                numValRead = sscanf(tempInputLine,
                                    "%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                                    nodeId,
                                    keywords[0],
                                    srcStr,
                                    destStr,
                                    keywords[1],
                                    spi,
                                    keywords[2],
                                    modeStr,
                                    keywords[3],
                                    encryptionAlgoStr,
                                    encryptionKey,
                                    keywords[4],
                                    authAlgoStr,
                                    authKey);
                caseNumber = IPSEC_SA_ESP_MODE_ENCR_AUTH;
                if (numValRead != 14)
                {
                    ERROR_Assert(FALSE, "Invalid SA entry");
                }
                if (!strcmp(encryptionAlgoStr, "NULL")
                    && !strcmp(authAlgoStr, "NULL"))
                {
                    ERROR_Assert(FALSE, "Invalid SA entry - Both encryption"
                                        " and authentication algorithms"
                                        " cannot be NULL");
                }
                isAuthentication = TRUE;
                isEncryption = TRUE;
            }
        }
        securityProtocol = IPSEC_ESP;

        // Check whether key contains quotes. If quotes are present, extract
        // the key (skipping the quotes) else, validate it considering it as
        // a hexstring and then convert it into a char string
        if (strlen(encryptionKey))
        {
            if (!strstr(encryptionKey, "\""))
            {
                strcpy(encryptionKey,
                       IPsecHexToChar(encryptionKey,
                                      &encryptionKeyLength));
            }
            else
            {
                if (!strcmp(encryptionKey, "\"\"")
                    && strcmp(encryptionAlgoStr, "NULL"))
                {
                    ERROR_Assert(FALSE, "Invalid Encryption key"
                                        " in SA entry");
                }

                // Extract the key only if the Encryption algorithm is
                // not NULL
                if (strcmp(encryptionAlgoStr, "NULL"))
                {
                    char tempEncryptionKey[BIG_STRING_LENGTH];
                    strcpy(tempEncryptionKey, IO_Chop(encryptionKey + 1));
                    strcpy(encryptionKey, tempEncryptionKey);
                }
            }
        }
        if (strlen(authKey))
        {
            if (!strstr(authKey, "\""))
            {
                strcpy(authKey,
                       IPsecHexToChar(authKey, &authKeyLength));
            }
            else
            {
                if (!strcmp(authKey, "\"\"")
                    && strcmp(authAlgoStr, "NULL"))
                {
                    ERROR_Assert(FALSE, "Invalid Authentication key"
                                        " in SA entry");
                }

                // Extract the key only if the Authentication algorithm is
                // not NULL
                if (strcmp(authAlgoStr, "NULL"))
                {
                    char tempAuthKey[BIG_STRING_LENGTH];
                    strcpy(tempAuthKey, IO_Chop(authKey +1 ));
                    strcpy(authKey, tempAuthKey);
                }
            }
        }
    }
    else
    {
        ERROR_Assert(FALSE, "Invalid IPsec protocol in SA entry");
    }

    // Validate the keywords' occurences
    IPsecProcessSAKeywords(keywords, caseNumber);

    // Validate Node id
    if (strstr(nodeId, ".")
        || strstr(nodeId, "/")
        || !IPsecValidateNodeID(nodeId))
    {
        ERROR_Assert(FALSE, "Invalid Node id in SA entry");
    }

    // Validate Source and destination addresses
    if (!strstr(srcStr, ".") && strcmp(srcStr, "*"))
    {
        ERROR_Assert(FALSE, "Invalid Source address in SA entry");
    }

    if (!strstr(destStr, ".") && strcmp(destStr, "*"))
    {
        ERROR_Assert(FALSE, "Invalid Destination address in SA entry");
    }

    mode = IPsecGetMode(modeStr);

    if (!strcmp(srcStr, "*"))
    {
        src = IPSEC_WILDCARD_ADDR;
    }
    else
    {
        if (IPsecIsValidIpAddress(srcStr))
        {
            IO_ConvertStringToNodeAddress(srcStr, &src);
            ERROR_Assert(!NetworkIpIsMulticastAddress(node, src),
                         "Source address in SA entry can only be"
                         " a Unicast address");
        }

        else
        {
            ERROR_Assert(FALSE, "Invalid Source address in SA entry");
        }
    }

    // Parse destination address string
    if (!strcmp(destStr, "*"))
    {
        if (mode == IPSEC_TUNNEL)
        {
            ERROR_Assert(FALSE,
                         "IPsec: destination wildcard '*' invalid in"
                         " the TUNNEL mode, only valid in the TRANSPORT"
                         " mode");
        }
        else
        {
            dest = IPSEC_WILDCARD_ADDR;
        }
    }
    else
    {
        if (IPsecIsValidIpAddress(destStr))
        {
            IO_ConvertStringToNodeAddress(destStr, &dest);
        }

        else
        {
            ERROR_Assert(FALSE, "Invalid Destination address in SA entry");
        }
    }

    if (isAuthentication)
    {
        authAlgo = IPsecGetAuthenticationAlgo(authAlgoStr);
    }
    else
    {
        authAlgo = IPSEC_NULL_AUTHENTICATION;
    }

    if (isEncryption)
    {
        encryptionAlgo = IPsecGetEncryptionAlgo(encryptionAlgoStr);
    }
    else
    {
        encryptionAlgo = IPSEC_NULL_ENCRYPTION;
    }

    // Throw an error if encryption algo is NULL and key size isn't zero
    if (!strcmp(encryptionAlgoStr, "NULL") && strcmp(encryptionKey, "\"\""))
    {
        ERROR_Assert(FALSE, "Invalid Encryption key in SA entry. Key size "
                            "must be zero when using NULL encryption");
    }

    // Throw an error if authentication algo is NULL and key size isn't zero
    if (!strcmp(authAlgoStr, "NULL") && strcmp(authKey, "\"\""))
    {
        ERROR_Assert(FALSE, "Invalid Authentication key in SA entry. Key "
                            "size must be zero when using NULL"
                            " authentication");
    }

    // Checking whether this SA entry is for this node or not
    if (!strcmp(nodeString, IO_Chop(nodeId + 1)))
    {
        newSA = IPsecCreateNewSA(mode,
                                 src,
                                 dest,
                                 securityProtocol,
                                 spi,
                                 authAlgo,
                                 authKey,
                                 encryptionAlgo,
                                 encryptionKey,
                                 rateParams);

        // Assign selector address list
        struct IPsecSelectorAddrListEntry* newListEntry;
        newListEntry = (struct IPsecSelectorAddrListEntry*)
                       MEM_malloc(sizeof(struct
                       IPsecSelectorAddrListEntry));
        newListEntry->src = src;
        newListEntry->dest = dest;
        newListEntry->mode = mode;
        newListEntry->securityProtocol = securityProtocol;
        newListEntry->saEntry = newSA;
        addrList->push_back(newListEntry);

        // Creation of the new SA has been done. Now,associate the new SA
        // with this node's SAD. Prior to it, check if a matching SA
        // is already present in this node's Security Association Database
        if (!IPsecIsDuplicateSA(node, newSA))
        {
            IPsecSADAddEntry(node, newSA);
        }
        else
        {
            ERROR_Assert(FALSE, "Duplicate SA entry");
        }
    }

    // Free temporary variables
    delete [] tempInputLine;
    for (int i = 0; i < MAX_VALID_SA_TOKENS; i++)
    {
        MEM_free(keywords[i]);
    }
    MEM_free(keywords);
}


// /**
// FUNCTION   :: IPsecGetProtocolNumber
// LAYER      :: Network
// PURPOSE    :: Function to return IP protocol number for upper layer
//               protocol string
// PARAMETERS ::
// + protocol  : char* : Upper layer protocol string
// RETURN     :: int   : IP protocol number
// **/

int IPsecGetProtocolNumber(char* protocol)
{
    int ipProto = 0;
    if (!strcmp(protocol, "TCP"))
    {
        ipProto = IPPROTO_TCP;
    }
    else if (!strcmp(protocol, "UDP"))
    {
        ipProto = IPPROTO_UDP;
    }
    else if (!strcmp(protocol, "IP"))
    {
        ipProto = IPPROTO_IP;
    }
    else if (!strcmp(protocol, "ICMP"))
    {
        ipProto = IPPROTO_ICMP;
    }
    else if (!strcmp(protocol, "IGMP"))
    {
        ipProto = IPPROTO_IGMP;
    }
    else if (!strcmp(protocol, "ANY"))
    {
        ipProto = 0;
    }

    // If there are more protocols you want support add them
    // before this line

    else
    {
        ERROR_Assert(FALSE, "Unknown protocol specified");
    }

    return ipProto;
}

// /**
// FUNCTION   :: IPsecGetPolicy
// LAYER      :: Network
// PURPOSE    :: Function to return whether to drop, discard or use IPsec to
//               a packet for a particular IPsecSecurityPolicyDatabase entry
// PARAMETERS ::
// + policy    : char*       : Policy string
// RETURN     :: IPsecPolicy : policy enum value
// **/
static
IPsecPolicy IPsecGetPolicy(char* policy)
{
    if (!strcmp(policy, "DISCARD"))
    {
        return IPSEC_DISCARD;
    }
    else if (!strcmp(policy, "BYPASS"))
    {
        return IPSEC_NONE;
    }
    else if (!strcmp(policy, "IPSEC"))
    {
        return IPSEC_USE;
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown policy");
    }

    return IPSEC_DISCARD;
}

// /**
// FUNCTION   :: IPsecGetLevel
// LAYER      :: Network
// PURPOSE    :: Function to return whether to drop, discard or use IPsec to
//               a packet for a particular IPsecSecurityPolicyDatabase entry
// PARAMETERS ::
// + policy    : char*       : level string
// RETURN     :: IPsecLevel : level enum value
// **/
static
enum IPsecLevel IPsecGetLevel(char* level)
{
    if (!strcmp(level, "REQUIRE"))
    {
        return IPSEC_LEVEL_REQUIRE;
    }
    else if (!strcmp(level, "DEFAULT"))
    {
        return IPSEC_LEVEL_DEFAULT;
    }
    else if (!strcmp(level, "USE"))
    {
        return IPSEC_LEVEL_USE;
    }
    else if (!strcmp(level, "UNIQUE"))
    {
        return IPSEC_LEVEL_UNIQUE;
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown level");
    }

    return IPSEC_LEVEL_DEFAULT;
}

// /**
// FUNCTION   :: IPsecGetDirection
// LAYER      :: Network
// PURPOSE    :: Function to return whether the IPsecSecurityPolicyDatabase
//               entry for inbound or outbound packet
// PARAMETERS ::
// + directionStr : char*       : Direction string
// RETURN     :: IPsecDirection : Direction enum value
// **/
static
IPsecDirection IPsecGetDirection(char* directionStr)
{
    if (!strcmp(directionStr, "IN"))
    {
        return IPSEC_IN;
    }
    else if (!strcmp(directionStr, "OUT"))
    {
        return IPSEC_OUT;
    }
    else
    {
        ERROR_ReportError("Direction can only be IN or OUT");
    }

    return IPSEC_INVALID_DIRECTION;
}

// /**
// FUNCTION   :: IPsecCreateNewSP
// LAYER      :: Network
// PURPOSE    :: Creating a new Security Policy
// PARAMETERS ::
// + node           : Node*       : The  node creating new SP
// + interfaceindex : int         : Interface for which policy is created
// + src            : NodeAddress : Source network address
// + srcHostBits    : int : Number of host bits in source network
// + dest           : NodeAddress : Destination network address
// + destHostBits   : int : Number of host bits in dest network
// + srcPort        : unsigned short : Source port number
// + destPort       : unsigned short : Destination port number
// + protocol       : int            : Upper layer protocol
// + direction      : IPsecDirection : Inbound or Outboud
// + policy         : IPsecPolicy    : Discard, bypass or Use IPsec
// + level          : IPsecLevel     : Require, default or Use
// + rateParams     : IPsecProcessingRate* : Delay parameters for
//                    different algorithm
// RETURN     :: IPsecSecurityPolicyEntry* : Pointer to the newly created SP
// **/
IPsecSecurityPolicyEntry* IPsecCreateNewSP(
    Node* node,
    int interfaceIndex,
    NodeAddress src,
    int srcHostBits,
    NodeAddress dest,
    int destHostBits,
    unsigned short srcPort,
    unsigned short destPort,
    int protocol,
    IPsecDirection direction,
    IPsecPolicy policy,
    vector<IPsecSAFilter*> saFilter,
    IPsecProcessingRate* rateParams)
{
    // Create a new SP
    IPsecSecurityPolicyEntry* newSP = (IPsecSecurityPolicyEntry*)
                                       MEM_malloc(
                                       sizeof(IPsecSecurityPolicyEntry));
    if (IPSEC_DEBUG)
    {
        printf("IPSEC: Node %u interface %d\n\t"
               "src %x, srcHostBits %d, dest %x, destHostBits %d\n",
               node->nodeId, interfaceIndex, src, srcHostBits,
               dest, destHostBits);
    }
    // Initialize SPD on interface of corresponding Node
    int intf;
    IpInterfaceInfoType* intfInfo = NULL;
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;
    if (interfaceIndex == ANY_INTERFACE)
    {
        for (intf = 0; intf < node->numberInterfaces; intf++)
        {
            intfInfo = ip->interfaceInfo[intf];

           // Initialize inbound or outboud spd
            if (direction == IPSEC_IN)
            {
                // Initialize if not initialized
                if (intfInfo->spdIN == NULL)
                {
                    IPsecSPDInit(&intfInfo->spdIN);
                }
            }
            else
            {
                // Initialize if not initialized
                if (intfInfo->spdOUT == NULL)
                {
                    IPsecSPDInit(&intfInfo->spdOUT);
                }
            }
        }
    }
    else
    {
        intfInfo = ip->interfaceInfo[interfaceIndex];

        // Initialize inbound or outboud spd
        if (direction == IPSEC_IN)
        {
            // Initialize if not initialized
            if (intfInfo->spdIN == NULL)
            {
                IPsecSPDInit(&intfInfo->spdIN);
            }
        }
        else
        {
            // Initialize if not initialized
            if (intfInfo->spdOUT == NULL)
            {
                IPsecSPDInit(&intfInfo->spdOUT);
            }
        }
    }//end of else

    // Initialize the allocated memory with 0
    memset(newSP, 0, sizeof(IPsecSecurityPolicyEntry));

    // Assign different fields of the new SP
    newSP->srcAddr = src;
    newSP->srcMask = ConvertNumHostBitsToSubnetMask(srcHostBits);
    newSP->destAddr = dest;
    newSP->destMask = ConvertNumHostBitsToSubnetMask(destHostBits);
    newSP->srcPort = srcPort;
    newSP->destPort = destPort;
    newSP->upperLayerProtocol = protocol;
    newSP->direction = direction;
    newSP->policy = policy;
    newSP->saFilter = saFilter;
    newSP->numSA = 0;
    memcpy(&newSP->processingRate,
           rateParams,
           sizeof(IPsecProcessingRate));
    newSP->saPtr = (IPsecSecurityAssociationEntry**)
                    MEM_malloc(sizeof(IPsecSecurityAssociationEntry*)
                    * INITIAL_SA_BUNDLE_SIZE);
    return newSP;
}

// /**
// FUNCTION   :: IPsecCreateNewSP
// LAYER      :: Network
// PURPOSE    :: Creating a new Security Policy
// PARAMETERS ::
// + node           : Node*       : The  node creating new SP
// + interfaceindex : int         : Interface for which policy is created
// + src            : NodeAddress : Source network address
// + srcHostBits    : NodeAddress : Number of host bits in source network
// + dest           : NodeAddress : Destination network address
// + destHostBits   : NodeAddress : Number of host bits in dest network
// + srcPort        : unsigned short : Source port number
// + destPort       : unsigned short : Destination port number
// + protocol       : int            : Upper layer protocol
// + direction      : IPsecDirection : Inbound or Outboud
// + policy         : IPsecPolicy    : Discard, bypass or Use IPsec
// + level          : IPsecLevel     : Require, default or Use
// + rateParams     : IPsecProcessingRate* : Delay parameters for
//                    different algorithm
// RETURN     :: IPsecSecurityPolicyEntry* : Pointer to the newly created SP
// **/
IPsecSecurityPolicyEntry* IPsecCreateNewSP(
    Node* node,
    int interfaceIndex,
    NodeAddress src,
    int srcHostBits,
    NodeAddress dest,
    int destHostBits,
    unsigned short srcPort,
    unsigned short destPort,
    int protocol,
    IPsecDirection direction,
    IPsecPolicy policy,
    IPsecProcessingRate* rateParams)
{
    IPsecSecurityPolicyEntry* newSP = (IPsecSecurityPolicyEntry*)
                                       MEM_malloc(
                                       sizeof(IPsecSecurityPolicyEntry));

    if (IPSEC_DEBUG)
    {
        printf("IPSEC: Node %u interface %d\n\t"
               "src %x, srcHostBits %d, dest %x, destHostBits %d\n",
               node->nodeId, interfaceIndex, src, srcHostBits,
               dest, destHostBits);
    }

    // Initialize SPD on interface of corresponding Node

    int intf;
    IpInterfaceInfoType* intfInfo = NULL;
    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    if (interfaceIndex == ANY_INTERFACE)
    {
        for (intf = 0; intf < node->numberInterfaces; intf++)
        {
            intfInfo = ip->interfaceInfo[intf];

            // Initialize inbound or outbound spd
            if (direction == IPSEC_IN)
            {
                // Initialize if not initialized
                if (intfInfo->spdIN == NULL)
                {
                    IPsecSPDInit(&intfInfo->spdIN);
                }
            }
            else
            {
                // Initialize if not initialized
                if (intfInfo->spdOUT == NULL)
                {
                    IPsecSPDInit(&intfInfo->spdOUT);
                }
            }
        }
    }
    else
    {
        intfInfo = ip->interfaceInfo[interfaceIndex];
        // Initialize inbound or outbound spd
        if (direction == IPSEC_IN)
        {
            // Initialize if not initialized
            if (intfInfo->spdIN == NULL)
            {
                IPsecSPDInit(&intfInfo->spdIN);
            }
        }
        else
        {
            // Initialize if not initialized
            if (intfInfo->spdOUT == NULL)
            {
                IPsecSPDInit(&intfInfo->spdOUT);
            }
        }
    }//end of else

    // Initialize the allocated memory with 0
    memset(newSP, 0, sizeof(IPsecSecurityPolicyEntry));

    // Assign different fields of the new SP
    newSP->srcAddr = src;
    newSP->srcMask = ConvertNumHostBitsToSubnetMask(srcHostBits);
    newSP->destAddr = dest;
    newSP->destMask = ConvertNumHostBitsToSubnetMask(destHostBits);
    newSP->srcPort = srcPort;
    newSP->destPort = destPort;
    newSP->upperLayerProtocol = protocol;
    newSP->direction = direction;
    newSP->policy = policy;
    newSP->numSA = 0;
    memcpy(&newSP->processingRate,
           rateParams,
           sizeof(IPsecProcessingRate));

    newSP->saPtr = (IPsecSecurityAssociationEntry**)
                    MEM_malloc(sizeof(IPsecSecurityAssociationEntry*)
                    * INITIAL_SA_BUNDLE_SIZE);

    return newSP;
}

// /**
// FUNCTION   :: IPsecRemoveLeadingSpaces
// LAYER      :: Network
// PURPOSE    :: Function to remove leading spaces in a string
// PARAMETERS ::
// + inputString  : string : The string from which leading spaces are to
//                            be removed
// RETURN     :: string : Copy of input string with all the leading
//                        spaces trimmed
// **/
string IPsecRemoveLeadingSpaces(string inputString)
{
    string delimiter = " ";
    size_t index;
    size_t previousIndex = 0;
    index = inputString.find(delimiter, previousIndex);

    // Remove all the leading spaces (if any)
    while (index == 0)
    {
        inputString.erase(0, 1);
        index = inputString.find(delimiter, previousIndex);
    }
    return inputString;
}

// /**
// FUNCTION   :: IPsecGetProtocolModeSrcDestLevel
// LAYER      :: Network
// PURPOSE    :: Function to read security protcol configured in the IPsec
//               configuration file
// PARAMETERS ::
// + node        : Node* : The node trying to read its security policy
// + protocolModeString  : char* : The string to be parsed for protocol,
//                         level,mode,first endpoint and second endpoint
// + protocol   : char*  : protocol for which SP is to be configured
// + mode       : char*  : protocol for which SP is to be configured
// + firstEndpoint   : NodeAddress* : one of the end points for which SP is
//                                    to be configured
// + secondEndpoint  : NodeAddress* : second end point for which SP is to
//                                    be configured
// + level      : char*  : level for which SP is to be configured

// RETURN     :: void : NULL
// **/

void IPsecGetProtocolModeSrcDestLevel(Node* node,
                                      string modeString,
                                      char* protocol,
                                      char* mode,
                                      NodeAddress* firstEndpoint,
                                      NodeAddress* secondEndpoint,
                                      char* level)
{
    vector<string> tokens;
    int i = 0;

    // Mode string should have at least security protocol i.e. either ESP
    // or AH, mode i.e. TRANSPORT or TUNNEL, and level i.e. REQUIRE,
    // DEFAULT, USE, and UNIQUE. Hence, the variable minCount is set to
    // four (4)
    size_t minCount = 4;
    BOOL tunnelMode = FALSE;
    BOOL transportMode = FALSE;

    string delimiter = "/";
    size_t index;
    size_t previousIndex = 0;
    index = modeString.find(delimiter, previousIndex);

    if (index == string::npos)
    {
        ERROR_Assert(FALSE, "Error in SP entry - Invalid SA filter given");
    }

    else
    {
        while (index != string::npos)
        {
            string tempToken (modeString, 0, index);
            tokens.push_back(tempToken);
            i++;
            modeString.erase(0, index + 1);
            index = modeString.find(delimiter, previousIndex);
            if (index == string::npos)
            {
                tokens.push_back(modeString);
            }
        }
    }

    if ((tokens[0].compare("ESP") != 0) && (tokens[0].compare("AH") != 0))
    {
        ERROR_Assert(FALSE, "Error in SP entry - Invalid Protocol given");
    }

    if (tokens[1].compare("TRANSPORT") == 0)
    {
        transportMode = TRUE;
    }
    else if (tokens[1].compare("TUNNEL") == 0)
    {
        tunnelMode = TRUE;
    }

    else
    {
       ERROR_Assert(FALSE, "Error in SP entry - Invalid Mode given - "
                           "Mode can be only Transport or Tunnel");
    }

    if (tokens.size() != minCount)
    {
        ERROR_Assert(FALSE, "Error in SP entry"
                            " - Invalid number of Tunnel  mode"
                            " configuration parameters");
    }

    if (tunnelMode)
    {
        if (tokens[i - 1].find("-") == string::npos)
        {
            ERROR_Assert(FALSE, "Error in SP entry -"
                                " Invalid endpoints given");
        }

        else
        {
            strcpy(protocol, tokens[0].c_str());
            strcpy(level, tokens[i].c_str());
            strcpy(mode, "TUNNEL");
            string delimiter = "-";
            size_t index = 0;
            size_t previousIndex = 0;
            int j = 0;
            vector<string> endpointStr;

            index = tokens[i - 1].find(delimiter, previousIndex);

            if (index == string::npos)
            {
                ERROR_Assert(FALSE, "Error in SP entry -"
                                    " Invalid endpoints given");
            }
            else
            {
                while (index != string::npos)
                {
                    string entry (tokens[i - 1], previousIndex, index);
                    endpointStr.push_back(entry);
                    j++;
                    previousIndex = index + 1;
                    index = tokens[i - 1].find(delimiter, previousIndex);
                    if (index == string::npos)
                    {
                        endpointStr.push_back(string (tokens[i - 1],
                                                      previousIndex));
                    }
                }
            }

            if (j != 1)
            {
                ERROR_Assert(FALSE, "Error in SP entry -"
                                    " Invalid endpoints given");
            }

            else
            {
                if (IPsecIsValidIpAddress(endpointStr[0].c_str())
                    && IPsecIsValidIpAddress(endpointStr[1].c_str()))
                {
                    IO_ConvertStringToNodeAddress(endpointStr[0].c_str(),
                                                  firstEndpoint);
                    IO_ConvertStringToNodeAddress(endpointStr[1].c_str(),
                                                  secondEndpoint);

                    // Check whether endpoints are multicast
                    // addresses or not
                    if (NetworkIpIsMulticastAddress(node, *firstEndpoint) ||
                        NetworkIpIsMulticastAddress(node, *secondEndpoint))
                    {
                        ERROR_Assert(FALSE, "Error in SP entry - Invalid "
                                            "endpoints given. "
                                            "Endpoints can be only unicast "
                                            "addresses");
                    }
                }

                else
                {
                     ERROR_Assert(FALSE, "Error in SP entry - Invalid "
                                         "endpoints given.");
                }
            }
        }
    }

    else if (transportMode)
    {
        if (tokens[i - 1].find("-") != string::npos)
        {
            ERROR_Assert(FALSE,
                "Error in SP entry - Configuration parameters (endpoints)"
                " that are given are redundant since it is a policy for"
                " transport mode");
        }

        else
        {
            strcpy(protocol, tokens[0].c_str());
            strcpy(level, tokens[i].c_str());
            strcpy(mode, "TRANSPORT");
        }
    }

    else
    {
        ERROR_Assert(FALSE, "Error in SP entry - Invalid number/order"
                            " of configuration parameters");
    }

    if ((tokens[i].compare("REQUIRE") != 0)
        && (tokens[i].compare("DEFAULT") != 0)
        && (tokens[i].compare("USE") != 0))
    {
        ERROR_Assert(FALSE, "Error in SP entry - Invalid Level given");
    }
}

// /**
// FUNCTION   :: IPsecExtractSAFilters
// LAYER      :: Network
// PURPOSE    :: Function to retrieve SA filters mentioned in an SP entry
//               in the IPsec configuration file
// PARAMETERS ::
// + inputLine   : const char* : The SP entry of the ipsec main
//                 configuration file being processed
// + lastToken   : const char* : The token in SP entry after which only
//                 protocol-mode strings i.e. SA filters are expected
// + numberOfProtocolModeStrings    : int* : number of SA filters in input
//                                    SP entry
// RETURN     :: vector<string> : All extracted SA filters
// **/

vector<string> IPsecExtractSAFilters(const char* inputLine,
                                     const char* lastToken,
                                     int* numberOfProtocolModeStrings)
{
    int lastTokenLength;
    char* lastTokenPtr;
    char* protocolModeStringsBeginPtr;
    int i = 0;
    char spaceSeparatedLastToken[MAX_STRING_LENGTH];
    char tempLine[MAX_STRING_LENGTH];
    vector<string> protocolModeString;
    strcpy(tempLine, inputLine);

    strcpy(spaceSeparatedLastToken, " ");
    strcat(spaceSeparatedLastToken, lastToken);
    strcat(spaceSeparatedLastToken, " ");

    lastTokenLength = (int) strlen(spaceSeparatedLastToken);
    lastTokenPtr = strstr(tempLine, spaceSeparatedLastToken);
    protocolModeStringsBeginPtr = lastTokenPtr + lastTokenLength;
    string protocolModeStrings (protocolModeStringsBeginPtr);

    string delimiter = " ";
    size_t index;
    size_t previousIndex = 0;

    // Remove leading spaces (if any)
    protocolModeStrings = IPsecRemoveLeadingSpaces(protocolModeStrings);

    index = protocolModeStrings.find(delimiter, previousIndex);

    // If no space is found, it implies the entry in protocolModeStrings
    // is the only SA filter
    if (index == string::npos)
    {
        protocolModeString.push_back(protocolModeStrings);
        i++;
    }
    else
    {
        while (index != string::npos && i < MAX_SA_FILTERS)
        {
            string entry (protocolModeStrings, 0, index);
            protocolModeString.push_back(entry);
            i++;
            previousIndex = index + 1;
            protocolModeStrings.erase(0, previousIndex);

            // Remove leading spaces (if any)
            protocolModeStrings =
                              IPsecRemoveLeadingSpaces(protocolModeStrings);

            previousIndex = 0;
            index = protocolModeStrings.find(delimiter, previousIndex);
            if (index == string::npos)
            {
                // This condition will be hit when last filter is
                // being extracted
                protocolModeString.push_back(protocolModeStrings);
                i++;
            }
        }
    }

    *numberOfProtocolModeStrings = i;
    return protocolModeString;
}

// /**
// FUNCTION   :: IPSecDuplicateSAFilters
// LAYER      :: Network
// PURPOSE    :: Checking whether two SPs have same SA filters or not
// PARAMETERS ::
// + newSAFilter       : vector<IPsecSAFilter*>
//                       SA filters of the SP to be added
// + previousSAFilter  : vector<IPsecSAFilter*>
//                     : SA filters of SP present already in sender
//                       interface's SPD
// RETURN     :: BOOL  : TRUE if duplicate else FALSE
// **/

BOOL IPSecDuplicateSAFilters(
    vector<IPsecSAFilter*> newSAFilter,
    vector<IPsecSAFilter*> previousSAFilter)
{
    size_t newSAFilterSize = newSAFilter.size();
    size_t previousSAFilterSize = previousSAFilter.size();

    if (newSAFilterSize != previousSAFilterSize)
    {
        return FALSE;
    }
    else
    {
        for (size_t i = 0; i < newSAFilterSize; i++)
        {
            if (memcmp(newSAFilter.at(i),
                       previousSAFilter.at(i),
                       sizeof(IPsecSAFilter)))
            {
                return FALSE;
            }
        }
        return TRUE;
    }
}

// /**
// FUNCTION   :: IPsecIsDuplicateSP
// LAYER      :: Network
// PURPOSE    :: Checking whether security policy to be added
//               to SPD is duplicate or not
// PARAMETERS ::
// + node           : Node*                      : The  node adding entry
// + interfaceIndex : int                        : Interface Index
// + newSP          : IPsecSecurityPolicyEntry*  : New security policy
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/

BOOL IPsecIsDuplicateSP(
     Node* node,
     int interfaceIndex,
     IPsecSecurityPolicyEntry* newSP)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IpInterfaceInfoType* intfInfo = ip->interfaceInfo[interfaceIndex];
    IPsecSecurityPolicyInformation* spdInfo = NULL;
    IPsecSecurityPolicyDatabase* spd = NULL;
    size_t index = 0;

    if (newSP->direction == IPSEC_IN)
    {
        spdInfo = intfInfo->spdIN;
    }
    else
    {
        spdInfo = intfInfo->spdOUT;
    }

    if (spdInfo)
    {
        spd = spdInfo->spd;
    }

    if (spd)
    {
        while (index < spd->size())
        {
            IPsecSecurityPolicyEntry* entryPtr = spd->at(index);
            if ((newSP->srcAddr == entryPtr->srcAddr)
                && (newSP->srcMask == entryPtr->srcMask)
                && (newSP->destAddr == entryPtr->destAddr)
                && (newSP->destMask == entryPtr->destMask)
                && (newSP->direction == entryPtr->direction)
                && (newSP->policy == entryPtr->policy)
                && (newSP->srcPort == entryPtr->srcPort)
                && (newSP->destPort == entryPtr->destPort)
                && (newSP->upperLayerProtocol
                == entryPtr->upperLayerProtocol))
            {
                if (IPSecDuplicateSAFilters(newSP->saFilter,
                                            entryPtr->saFilter))
                {
                    return TRUE;
                }
            }
            index++;
        }// while close
    }// if close

    return FALSE;
}

// /**
// FUNCTION   :: IPsecReadSecurityPolicy
// LAYER      :: Network
// PURPOSE    :: Function to read security policy configured in the IPsec
//               configuration file for a node or any of its interface
// PARAMETERS ::
// + node        : Node* : The node trying to read its security policy
// + inputLine   : const char* : The SP entry of the ipsec main
//                 configuration file being processed
// + rateParams : IPsecProcessingRate* : For delays for different algorithm

// RETURN     :: void : NULL
// **/

static
void IPsecReadSecurityPolicy(
    Node* node,
    const char* inputLine,
    IPsecProcessingRate* rateParams)
{
    char srcStr[MAX_STRING_LENGTH] = {0};
    char destStr[MAX_STRING_LENGTH] = {0};
    char nodeIdOrInterfaceAddress[MAX_STRING_LENGTH] = {0};
    unsigned short srcPortNumber = 0;
    unsigned short destPortNumber = 0;

    NodeAddress srcRange = 0;
    int numSrcHostBits = 0;
    NodeAddress destRange = 0;
    int numDestHostBits = 0;
    int protocol = 0;
    IPsecDirection direction = IPsecDirection(IPSEC_OUT);
    IPsecPolicy policy = IPsecPolicy(IPSEC_USE);
    vector<IPsecSAFilter*> saFilter;
    IPsecSecurityPolicyEntry* newSP = NULL;
    int interfaceIndex = -1;
    int numValRead = 0;
    int numEntries = 0;
    char upperLevelProtocol[MAX_STRING_LENGTH] = {0};
    char trafficDirection[MAX_STRING_LENGTH] = {0};
    char policyToBeApplied[MAX_STRING_LENGTH] = {0};
    char lastToken[MAX_STRING_LENGTH] = {0};
    vector<string> protocolModeString;

    NodeAddress firstEndpoint = 0;
    NodeAddress secondEndpoint = 0;
    NodeAddress interfaceAddress = 0;
    char configurationProtocol[MAX_STRING_LENGTH] = {0};
    char configurationMode[MAX_STRING_LENGTH] = {0};
    char configurationLevel[MAX_STRING_LENGTH] = {0};
    char nodeString[5];

    string preprocessedInputLine(inputLine);
    string tempInputString;
    tempInputString = IPsecPreProcessInputLine(preprocessedInputLine);
    int tempInputStringLength = tempInputString.length();
    ERROR_Assert(tempInputStringLength < MAX_STRING_LENGTH,
                 "Invalid Entry - Length of the entry cannot be"
                 " beyond 512 characters");

    char* tempInputLine;
    tempInputLine = new char[tempInputString.size() + 1];
    strcpy(tempInputLine, tempInputString.c_str());

    // This array of strings will hold the keywords like "SP", "AH", "-P"
    // etc. It will be used in conjunction with caseNumber to validate the
    // occurences of keywords
    char** keywords;
    keywords = (char**) MEM_malloc(MAX_VALID_SA_TOKENS * sizeof(char*));
    for (int i = 0; i < MAX_VALID_SA_TOKENS; i++)
    {
        keywords[i] = (char*) MEM_malloc(MAX_STRING_LENGTH);
    }

    IPsecSPCaseNumber caseNumber = IPsecSPCaseNumber(IPSEC_SP_PROT_DIR_POL);

    // SP entry contains ESP and/or AH
    if ((strstr(tempInputLine, " ESP/") || strstr(tempInputLine, " AH/")))
    {
        if (strstr(tempInputLine, " -P ")
            && (strstr(tempInputLine, " DISCARD ")
            || strstr(tempInputLine, " BYPASS ")
            || strstr(tempInputLine, " IPSEC ")))
        {
            numValRead = sscanf(tempInputLine, "%s%s%s%s%s%s%s%s",
                                               nodeIdOrInterfaceAddress,
                                               keywords[0],
                                               srcStr,
                                               destStr,
                                               upperLevelProtocol,
                                               keywords[1],
                                               trafficDirection,
                                               policyToBeApplied);
            caseNumber = IPSEC_SP_PROT_DIR_POL;
            if (numValRead != 8)
            {
                ERROR_Assert(FALSE, "Invalid SP entry");
            }
            strcpy(lastToken, policyToBeApplied);
        }
        else if (!strstr(tempInputLine, " -P ")
                && (strstr(tempInputLine, " DISCARD ")
                || strstr(tempInputLine, " BYPASS ")
                || strstr(tempInputLine, " IPSEC ")))
        {
            numValRead = sscanf(tempInputLine, "%s%s%s%s%s%s",
                                               nodeIdOrInterfaceAddress,
                                               keywords[0],
                                               srcStr,
                                               destStr,
                                               upperLevelProtocol,
                                               policyToBeApplied);
            caseNumber = IPSEC_SP_PROT_POL;
            if (numValRead != 6)
            {
                ERROR_Assert(FALSE, "Invalid SP entry");
            }
            strcpy(trafficDirection, "OUT");
            strcpy(lastToken, policyToBeApplied);
        }
        else if (!strstr(tempInputLine, " -P ")
                && !(strstr(tempInputLine, " DISCARD ")
                || strstr(tempInputLine, " BYPASS ")
                || strstr(tempInputLine, " IPSEC ")))
        {
            numValRead = sscanf(tempInputLine, "%s%s%s%s%s",
                                               nodeIdOrInterfaceAddress,
                                               keywords[0],
                                               srcStr,
                                               destStr,
                                               upperLevelProtocol);
            caseNumber = IPSEC_SP_PROT_POL;
            if (numValRead != 5)
            {
                ERROR_Assert(FALSE, "Invalid SP entry");
            }
            strcpy(trafficDirection, "OUT");
            strcpy(policyToBeApplied, "IPSEC");
            strcpy(lastToken, upperLevelProtocol);
        }

        else
        {
            ERROR_Assert(FALSE, "Invalid SP entry");
        }
    }

    else
    {
        ERROR_Assert(FALSE, "Invalid IPsec protocol in SP entry");
    }

    // Validate the keywords' occurences
    IPsecProcessSPKeywords(keywords, caseNumber);

    // Validate Node id or Interface Address
    if ((strstr(nodeIdOrInterfaceAddress, ".")
        && strstr(nodeIdOrInterfaceAddress, "/"))
        || !IPsecValidateNodeID(nodeIdOrInterfaceAddress))
    {
        ERROR_Assert(FALSE, "Invalid Node id/Interface"
                            " Address in SP entry");
    }

    // Validate Source and destination addresses
    if (!strstr(srcStr, ".") && strcmp(srcStr, "*"))
    {
        ERROR_Assert(FALSE, "Invalid Source address in SP entry");
    }

    if (!strstr(destStr, ".") && strcmp(destStr, "*"))
    {
        ERROR_Assert(FALSE, "Invalid Destination address in SP entry");
    }

    if (strstr(nodeIdOrInterfaceAddress, ".")
        && !strstr(nodeIdOrInterfaceAddress, "/"))
    {
        IO_ConvertStringToNodeAddress(IO_Chop(nodeIdOrInterfaceAddress + 1),
                                      &interfaceAddress);
        interfaceIndex = NetworkIpGetInterfaceIndexFromAddress(node,
                                                    interfaceAddress);
    }

    sprintf(nodeString, "%d", node->nodeId);
    // Either it is a node id or this SP is meant for
    // an interface belonging to this node
    if ((!strstr(nodeIdOrInterfaceAddress, ".")
        && !strcmp(nodeString, IO_Chop(nodeIdOrInterfaceAddress + 1)))
        || interfaceIndex != -1)
    {
        // Validate Source address and get number of host bits etc
        IPsecValidateSrcOrDestSPAddress(srcStr,
                                        &srcRange,
                                        &srcPortNumber,
                                        &numSrcHostBits,
                                        (char*) "Source Address");
        // Validate Destination address and get number of host bits etc
        IPsecValidateSrcOrDestSPAddress(destStr,
                                        &destRange,
                                        &destPortNumber,
                                        &numDestHostBits,
                                        (char*) "Destination Address");
        protocol = IPsecGetProtocolNumber(upperLevelProtocol);
        direction = IPsecGetDirection(trafficDirection);
        policy = IPsecGetPolicy(policyToBeApplied);
        protocolModeString = IPsecExtractSAFilters(tempInputLine,
                                                   lastToken,
                                                   &numEntries);

        // If there are redundant spaces at the end of the SA filters string
        // remove them and decrement the count of SA filters as it would
        // have been incremented in that case
        if (protocolModeString[numEntries - 1].empty())
        {
            numEntries--;
            protocolModeString.pop_back();
        }

        // Check whether endpoints,mode,level and protocol are correct
        unsigned int i = 0;
        while (i < (unsigned int) numEntries)
        {
            IPsecSAFilter* filter;
            filter = (IPsecSAFilter*) MEM_malloc(sizeof(IPsecSAFilter));
            memset(filter, 0, sizeof(IPsecSAFilter));
            IPsecGetProtocolModeSrcDestLevel(node,
                                             protocolModeString[i],
                                             configurationProtocol,
                                             configurationMode,
                                             &firstEndpoint,
                                             &secondEndpoint,
                                             configurationLevel);

            filter->ipsecProto = IPsecGetSecurityProtocol(
                                        configurationProtocol);
            filter->ipsecLevel = IPsecGetLevel(configurationLevel);
            filter->ipsecMode = IPsecGetMode(configurationMode);
            filter->tunnelSrcAddr = firstEndpoint;
            filter->tunnelDestAddr = secondEndpoint;
            saFilter.push_back(filter);
            i++;
        }

        newSP = IPsecCreateNewSP(node,
                                 interfaceIndex,
                                 srcRange,
                                 numSrcHostBits,
                                 destRange,
                                 numDestHostBits,
                                 srcPortNumber,
                                 destPortNumber,
                                 protocol,
                                 direction,
                                 policy,
                                 saFilter,
                                 rateParams);

        // The new SP has been constructed so associate it with ip interface
        if (interfaceIndex == ANY_INTERFACE)
        {
            for (int i = 0; i < node->numberInterfaces; i++)
            {
                if (!IPsecIsDuplicateSP(node, i, newSP))
                {
                    IPsecSPDAddEntry(node, i, newSP);
                }
                else
                {
                    ERROR_Assert(FALSE, "Duplicate SP entry");
                }
            }
        }
        else
        {
            if (!IPsecIsDuplicateSP(node, (int) interfaceIndex, newSP))
            {
                IPsecSPDAddEntry(node, interfaceIndex, newSP);
            }
            else
            {
                ERROR_Assert(FALSE, "Duplicate SP entry");
            }
        }
        MEM_free(newSP);
    }

    // Free temporary variables
    delete [] tempInputLine;
    for (int i = 0; i < MAX_VALID_SA_TOKENS; i++)
    {
        MEM_free(keywords[i]);
    }
    MEM_free(keywords);
}

// /**
// FUNCTION   :: IPsecParseConfigFile
// LAYER      :: Network
// PURPOSE    :: Function to read IPsec main configuration file and
//               initialize Security association(s) and
//               security policy(-ies) configured for a node
// PARAMETERS ::
// + node            : Node* : The node trying to read its IPsec
//                             configuration
// + ipsecConf       : const NodeInput* : ipsec main configuration file
// + processingRate : IPsecProcessingRate* : Processing delay for
//                                           different algorithms
// RETURN     :: void : NULL
// **/
static
void IPsecParseConfigFile(
    Node* node,
    const NodeInput* ipsecConf,
    IPsecProcessingRate* processingRate)
{
    Int64 i = 0;
    IPsecSelectorAddrList addrList;
    vector<string> inputLines;

    NetworkDataIp* ip = (NetworkDataIp*)node->networkData.networkVar;

    IPsecSADInit(&ip->sad);

    const char* currentLine = ipsecConf->inputStrings[i];
    const char* nextLine;
    string delimiter = ";";
    string entry;
    string semiColonDelimitedInputLines (currentLine);

    while (i < ipsecConf->numLines)
    {
        if ((i + 1) % ipsecConf->numLines)
        {
            semiColonDelimitedInputLines.append(" ");
            nextLine = ipsecConf->inputStrings[i + 1];
            semiColonDelimitedInputLines.append(nextLine);
        }
        i++;
    }

    size_t index;
    size_t previousIndex = 0;
    index = semiColonDelimitedInputLines.find(delimiter, previousIndex);

    // Added this Assert to prevent crashes in case older format
    // of IPSec configuration files is used

    if (index == string::npos)
    {
        ERROR_ReportError("Invalid IPSec configuration file");
    }

    // Prepared a string which contains concatenated set of input lines
    // Now tokenise these lines using semi-colon as a delimiter and
    // push these lines in a vector.This vector will be used later to
    // process SAs and SPs
    while (index != string::npos)
    {
        string entry (semiColonDelimitedInputLines, 0, index);
        inputLines.push_back(entry);
        i++;
        semiColonDelimitedInputLines.erase(0, index + 1);
        index = semiColonDelimitedInputLines.find(delimiter, previousIndex);
    }

    for (unsigned int i = 0; i < inputLines.size(); i++)
    {
        char* entry = new char[inputLines[i].length() + 1];
        strcpy(entry, inputLines[i].c_str());

        if (strstr(entry, " SA "))
        {
            // Process a Security Association
            IPsecReadSecurityAssociation(node,
                                         entry,
                                         processingRate,
                                         &addrList);
        }

        else if (strstr(entry, " SP "))
        {
            // Process a Security Policy
            IPsecReadSecurityPolicy(node,
                                    entry,
                                    processingRate);
        }

        else
        {
            ERROR_ReportError("Invalid token in IPsec configuration file");
        }

        delete [] entry;
    }// for loop

    // Retrieved information about SAs and SPs for this node.
    // Now, update SA pointers in SPs

    // This BOOL variable will help determing whether a security policy is
    // defined or not. If not, an error will be thrown

    BOOL spFound = FALSE;

    // Update SA pointer in SPDIn
    for (int i = 0; i < node->numberInterfaces; i++)
    {
        IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];
        IPsecSecurityPolicyInformation* spdInfo = intfInfo->spdIN;
        if (spdInfo)
        {
            spFound = TRUE;
            IPsecUpdateSApointerInSPD(node, addrList, spdInfo->spd);
        }
    }

    // Update SA pointer in SPDOut
    for (int i = 0; i < node->numberInterfaces; i++)
    {
        IpInterfaceInfoType* intfInfo = ip->interfaceInfo[i];
        IPsecSecurityPolicyInformation* spdInfo = intfInfo->spdOUT;
        if (spdInfo)
        {
            spFound = TRUE;
            IPsecUpdateSApointerInSPD(node, addrList, spdInfo->spd);
        }
    }

    // Throw an error if no security policy is defined for the IPSec
    // enabled node
    if (!spFound)
    {
        string errorStr = "Node ";
        ostringstream nodeString;
        nodeString << node->nodeId;
        errorStr.append(nodeString.str());
        errorStr.append(" is IPSec enabled but no security"
                        " policy is defined for it.");
        ERROR_ReportError(errorStr.c_str());
    }
}

#ifdef TRANSPORT_AND_HAIPE
// /**
// FUNCTION    :: IPsecReadHAIPE
// LAYER       :: Network
// PURPOSE     :: Function to read HAIPE properties for different HAIPE
//                devices.
//      1. HAIPE (High Assurance Internet Protocol Encryptor) is a Type 1
//         encryption device that complies with the National Security
//         Agency (NSA)'s HAIPE IS (formerly the HAIPIS, the High Assurance
//         Internet Protocol Interoperability Specification), where
//         HAIPE IS is based on IPsec.
//      2. NSA defined two sets of crypto algorithms: Suite A and Suite B.
//         Suite B is used in civilian context.  All Suite B algorithms are
//         open to public, which are comprised of AES (for encryption),
//         SHA256 (for message authentication), ECDH, ECDSA (for public key
//         crypto).   Suite A is used in military context, and the
//         algorithms in Suite A are _NOT_ open to public.
//
//      In IPsec, QualNet supports both actual HAIPE measurement and
//      surrogate values (for civilian usage).
// PARAMETERS  ::
// + node            : Node* : The node trying to read delays
// + nodeInput       : const NodeInput* : QualNet main configuration file
// + processingRate : IPsecProcessingRate* : Processing delay for
//                                             different algorithms
// RETURN      :: void : NULL
// **/
void IPsecReadHAIPE(
    Node* node,
    const NodeInput* nodeInput,
    int interfaceIndex)
{
    IpInterfaceInfoType *intf =
        node->networkData.networkVar->interfaceInfo[interfaceIndex];
    char buf[MAX_STRING_LENGTH] = {'\0'};
    BOOL wasFound = FALSE;

    IO_ReadString(
        node->nodeId,
        intf->ipAddress,
        nodeInput,
        "HAIPE-SPECIFICATION",
        &wasFound,
        buf);

    if (wasFound)
    {
        if (isdigit(buf[0]))
        {
            strcpy(intf->haipeSpec.name, "User-defined HAIPE.");
            intf->haipeSpec.operationRate = strtod(buf, NULL);
        }
        else
        {
            // Read the default HAIPE specification
            int i = 0;
            while (i < HAIPE_DUMMY)
            {
                if (strcmp(defaultHAIPESpec[i].name, buf) == 0)
                {
                    strcpy(intf->haipeSpec.name, "User defined.");
                    intf->haipeSpec.operationRate =
                        defaultHAIPESpec[i].operationRate;
                    break;
                }
                else
                {
                    i++;
                }
            }
            if (i == HAIPE_DUMMY)
            {
                ERROR_ReportError(
                    "Unknown HAIPE device. Instead, please specify "
                    "encryption rate measured in bit-per-second.");
            }
        }
    }
}
#endif // TRANSPORT_AND_HAIPE

// /**
// FUNCTION    :: IPsecReadProcessingRate
// LAYER       :: Network
// PURPOSE     :: Function to read processing rates for different encryption
//                and authentication algorithms
// PARAMETERS  ::
// + node            : Node* : The node trying to read rates
// + nodeInput       : const NodeInput* : QualNet main configuration file
// + processingRate : IPsecProcessingRate* : Processing rates for
//                                             different algorithms
// RETURN      :: void : NULL
// **/
static
void IPsecReadProcessingRate(
    Node* node,
    const NodeInput* nodeInput,
    IPsecProcessingRate* processingRate)
{
    int buf = 0;
    char buffer[MAX_STRING_LENGTH] = {'\0'};
    BOOL wasFound = FALSE;

    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-DES-CBC-PROCESSING-RATE",
        &wasFound,
        &buf);

    if (wasFound)
    {
        processingRate->desCbcRate = (clocktype) buf;
    }
    else
    {
        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-DES-CBC-DELAY",
                      &wasFound,
                      buffer);

        if (wasFound)
        {
            ERROR_ReportWarning("This configuration has been deprecated."
                                " Please refer to the IPSEC section in"
                                " cyber/core model library for the new"
                                " configuration parameters. We shall"
                                " convert the configured delay in rate(bps)"
                                " and do further processing.\n");
            clocktype delay = TIME_ConvertToClock(buffer);
            //Delay is configured in per KB of data. So 1000 * 8 should be
            //the numerator to get the rate in bps.
            processingRate->desCbcRate = 8000 * SECOND / delay;
        }
        else
        {
            processingRate->desCbcRate = IPSEC_DES_CBC_PROCESSING_RATE;
        }
    }

    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-HMAC-MD5-PROCESSING-RATE",
        &wasFound,
        &buf);

    if (wasFound)
    {
        processingRate->hmacMd5Rate = (clocktype) buf;
    }
    else
    {
        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-HMAC-MD5-DELAY",
                      &wasFound,
                      buffer);
        if (wasFound)
        {
            ERROR_ReportWarning("This configuration has been deprecated."
                                " Please refer to the IPSEC section in"
                                " cyber/core model library for the new"
                                " configuration parameters. We shall"
                                " convert the configured delay in rate(bps)"
                                " and do further processing.\n");
            clocktype delay = TIME_ConvertToClock(buffer);
            //Delay is configured in per KB of data. So 1000 * 8 should be
            //the numerator to get the rate in bps.
            processingRate->hmacMd5Rate = 8000 * SECOND / delay;
        }
        else
        {
            processingRate->hmacMd5Rate = IPSEC_HMAC_MD5_PROCESSING_RATE;
        }
    }

    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-HMAC-MD5-96-PROCESSING-RATE",
        &wasFound,
        &buf);

    if (wasFound)
    {
        processingRate->hmacMd596Rate = (clocktype) buf;
    }
    else
    {
        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-HMAC-MD5-96-DELAY",
                      &wasFound,
                      buffer);
        if (wasFound)
        {
            ERROR_ReportWarning("This configuration has been deprecated."
                                " Please refer to the IPSEC section in"
                                " cyber/core model library for the new"
                                " configuration parameters. We shall"
                                " convert the configured delay in rate(bps)"
                                " and do further processing.\n");
            clocktype delay = TIME_ConvertToClock(buffer);
            //Delay is configured in per KB of data. So 1000 * 8 should be
            //the numerator to get the rate in bps.
            processingRate->hmacMd596Rate = 8000 * SECOND / delay;
        }
        else
        {
            processingRate->hmacMd596Rate =
                                          IPSEC_HMAC_MD5_96_PROCESSING_RATE;
        }
    }

    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-HMAC-SHA-1-PROCESSING-RATE",
        &wasFound,
        &buf);

    if (wasFound)
    {
        processingRate->hmacSha1Rate = (clocktype) buf;
    }
    else
    {
        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-HMAC-SHA-1-DELAY",
                      &wasFound,
                      buffer);
        if (wasFound)
        {
            ERROR_ReportWarning("This configuration has been deprecated."
                                " Please refer to the IPSEC section in"
                                " cyber/core model library for the new"
                                " configuration parameters. We shall"
                                " convert the configured delay in rate(bps)"
                                " and do further processing.\n");
            clocktype delay = TIME_ConvertToClock(buffer);
            //Delay is configured in per KB of data. So 1000 * 8 should be
            //the numerator to get the rate in bps.
            processingRate->hmacSha1Rate = 8000 * SECOND / delay;
        }
        else
        {
            processingRate->hmacSha1Rate = IPSEC_HMAC_SHA_1_PROCESSING_RATE;
        }
    }

    IO_ReadInt(
        node->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "IPSEC-HMAC-SHA-1-96-PROCESSING-RATE",
        &wasFound,
        &buf);

    if (wasFound)
    {
        processingRate->hmacSha196Rate = (clocktype) buf;
    }
    else
    {
        IO_ReadString(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-HMAC-SHA-1-96-DELAY",
                      &wasFound,
                      buffer);
        if (wasFound)
        {
            ERROR_ReportWarning("This configuration has been deprecated."
                                " Please refer to the IPSEC section in"
                                " cyber/core model library for the new"
                                " configuration parameters. We shall"
                                " convert the configured delay in rate(bps)"
                                " and do further processing.\n");
            clocktype delay = TIME_ConvertToClock(buffer);
            //Delay is configured in per KB of data. So 1000 * 8 should be
            //the numerator to get the rate in bps.
            processingRate->hmacSha196Rate = 8000 * SECOND / delay;
        }
        else
        {
            processingRate->hmacSha196Rate =
                                        IPSEC_HMAC_SHA_1_96_PROCESSING_RATE;
        }
    }

    if (processingRate->desCbcRate < 0
        || processingRate->hmacMd596Rate < 0
        || processingRate->hmacSha196Rate < 0)
    {
         ERROR_Assert(FALSE, "IPsec: Positive delay value is expected\n");
    }

}

// /**
// FUNCTION    :: IPsecHexToInt
// LAYER       :: Network
// PURPOSE     :: Helper Function to convert hex digit to integer
// PARAMETERS  ::
// + hex       : char : Hex number/digit to be converted into integer
// RETURN      :: int : Integer equiavlent of input hex number
// **/

int IPsecHexToInt(char hex)
{
    switch (hex)
    {
        case '0':        return 0;
        case '1':        return 1;
        case '2':        return 2;
        case '3':        return 3;
        case '4':        return 4;
        case '5':        return 5;
        case '6':        return 6;
        case '7':        return 7;
        case '8':        return 8;
        case '9':        return 9;
        case 'a':        return 10;
        case 'b':        return 11;
        case 'c':        return 12;
        case 'd':        return 13;
        case 'e':        return 14;
        case 'f':        return 15;
        default:
           ERROR_Assert(FALSE, "Key sent is not a hex string");
           return -1;
    }
}

// /**
// FUNCTION    :: IPsecHexToChar
// LAYER       :: Network
// PURPOSE     :: Function to convert hexadecimal string to char string
// PARAMETERS  ::
// + hexString : char*  : Input Hex string
// + length    : int*   : Length of the returned char string
// RETURN      :: char* : NULL
// **/

char* IPsecHexToChar(char* hexString, int* length)
{
    char* num;
    *length = (int) strlen((char*)hexString);
    ERROR_Assert(*length > 2, "Key sent is not a hex string");
    *length -= 2;

    if (*length % 2 == 0)
    {
        *length = *length / 2;
    }
    else
    {
        *length = (*length + 1) / 2;
    }
    num = (char*) MEM_malloc(sizeof(char) * ((*length) + 1));
    memset(num, 0, (unsigned int) ((*length) + 1));
    int i = 0;
    int flag = 0;
    if (strlen((char*)hexString) % 2 == 0)
    {
        i = 2;
    }
    else
    {
        hexString[1] = '0';
        i = 1;
        flag = 1;
    }

    int index = 0;
    for (;i < (int) strlen((char*)hexString); i++)
    {
        num[index] = (char) (num[index] | IPsecHexToInt(hexString[i]));
        if (!flag)
        {
            if (i % 2 == 0)
            {
                num[index] = num[index] << 4;
            }
            else
            {
                index++;
            }
        }
        else
        {
            if (i % 2 != 0)
            {
                num[index] = num[index] << 4;
            }
            else
            {
                index++;
            }
        }
    }
    num[*length] = '\0';
    return num;
}

// /**
// FUNCTION    :: IPsecInit
// LAYER       :: Network
// PURPOSE     :: Function to Initialize IPsec for a node
// PARAMETERS  ::
// + node       : Node* : The node initializing IPsec
// + nodeInput  : const NodeInput* : QualNet main configuration file
// RETURN      :: void : NULL
// **/
void IPsecInit(Node* node, const NodeInput* nodeInput)
{
    NodeInput ipsecInput;
    BOOL retVal = FALSE;
    IPsecProcessingRate processingRate;
    //Set different Delay Parameters to zero.
    memset(&processingRate, 0, sizeof(IPsecProcessingRate));
    IO_ReadCachedFile(node->nodeId,
                      ANY_ADDRESS,
                      nodeInput,
                      "IPSEC-CONFIG-FILE",
                      &retVal,
                      &ipsecInput);

    if (!retVal)
    {
      ERROR_Assert(FALSE, "IPsec configuration file missing");
    }

    IPsecReadProcessingRate(node, nodeInput, &processingRate);
    IPsecParseConfigFile(node, &ipsecInput, &processingRate);
}

// /**
// API        :: IsIPsecProcessed
// LAYER      :: Network
// PURPOSE    :: Function to check whether the packet has gone through IPsec
//               ESP/AH processing
// PARAMETERS ::
// + node      : Node*    : Node processing packet
// + msg       : Message* : The packet to check
// RETURN     :: BOOL : TRUE, if already processed by IPsec, FALSE otherwise
// **/
BOOL IsIPsecProcessed(Node* node, Message* msg)
{
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    BOOL retVal = FALSE;

    if (ipHdr->ip_p == IPPROTO_ESP)
    {
        if (msg->eventType == MSG_NETWORK_IPsec)
        {
            retVal = TRUE;
        }
        else if (IPsecIsMyIP(node, ipHdr->ip_src))
        {
            retVal = TRUE;
        }
        else if (msg->eventType == MSG_NETWORK_Ip_Fragment)
        {
            retVal = TRUE;
        }
        else
        {
            retVal = FALSE;
        }
    }
    else if (ipHdr->ip_p == IPPROTO_AH)
    {
        if (msg->eventType == MSG_NETWORK_IPsec)
        {
            retVal = TRUE;
        }
        else if (IPsecIsMyIP(node, ipHdr->ip_src))
        {
            retVal = TRUE;
        }
        else if (msg->eventType == MSG_NETWORK_Ip_Fragment)
        {
            retVal = TRUE;
        }
        else
        {
            retVal = FALSE;
        }
    }
    else
    {
        retVal = FALSE;
    }
    return retVal;
}


// /**
// API        :: IPsecRequireProcessing
// LAYER      :: Network
// PURPOSE    :: Function to check whether packet requires IPsec processing
// PARAMETERS ::
// + node      : Node*    : Node processing packet
// + msg       : Message* : The packet to check
// + incomingInterface : int : incoming interface ID
// RETURN     :: BOOL : TRUE, if require IPsec processing, FALSE otherwise
// **/
BOOL IPsecRequireProcessing(Node* node, Message* msg, int incomingInterface)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp* icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    BOOL retVal = FALSE;
    int protocol = ipHdr->ip_p;
    IPsecSecurityAssociationEntry* saPtr = NULL;
    unsigned int spi;

    if (protocol == IPPROTO_ESP)
    {
        spi = IPsecESPGetSPI(msg);
    }
    else if (protocol == IPPROTO_AH)
    {
        spi = IPsecAHGetSPI(msg);
    }

    else
    {
        return retVal;
    }


    saPtr = IPsecGetMatchingSA(node,
                               protocol,
                               ipHdr->ip_src,
                               ipHdr->ip_dst,
                               spi);

    //Support Fix for ticket#1408 start
    if (saPtr == NULL && ((ipHdr->ip_p == IPPROTO_ESP) ||
                         (ipHdr->ip_p == IPPROTO_AH)))
    //Support Fix for ticket#1408 end
    {
        if (ip->isIcmpEnable && icmp->securityFailureEnable)
        {
            NetworkIcmpCreateSecurityErrorMessage(node,
                                                  msg,
                                                  incomingInterface);
        }
    }

    if ((ipHdr->ip_p == IPPROTO_ESP) && (saPtr != NULL))
    {
        retVal = TRUE;
    }
    else if ((ipHdr->ip_p == IPPROTO_AH) && (saPtr != NULL))
    {
        retVal = TRUE;
    }
    else
    {
        retVal = FALSE;
    }

    return retVal;
}

// /**
// FUNCTION   :: IPsecHandleEvent
// LAYER      :: Network
// PURPOSE    :: Function to handle events for IPsec, required to simulate
//               delay
// PARAMETERS ::
// + node      : Node*    : The node processing the event
// + msg       : Message* : Event that expired
// RETURN     :: void     : NULL
// **/
void IPsecHandleEvent(Node* node, Message* msg)
{
    IPsecMsgInfoType infoType;

    memcpy(&infoType, MESSAGE_ReturnInfo(msg), sizeof(IPsecMsgInfoType));

    switch (infoType.inOut)
    {
        case 'i':
        {
            NetworkIpReceivePacket(
                node, msg, infoType.prevHop, infoType.inIntf);
            break;
        }
        case 'o':
        {
            if (infoType.isRoutingRequired == TRUE)
            {
                RoutePacketAndSendToMac(
                    node, msg, infoType.inIntf, infoType.outIntf, ANY_IP);
            }
            else
            {
                NetworkIpSendPacketOnInterface(node, msg,
                    infoType.inIntf, infoType.outIntf, infoType.nextHop);
            }
            break;
        }
        default:
        {
            ERROR_Assert(FALSE, "IPsec: Unknown event type\n");
            break;
        }
    }
}

// /**
// FUNCTION   :: IPsecConstructOuterIpHeader
// LAYER      :: Network
// PURPOSE    :: Header construction for tunnel mode
// PARAMETERS ::
// + node      : Node*    : The node adding tunnel header
// + msg       : Message* : Packet to which to add tunnel header
// + saPtr     : IPsecSecurityAssociationEntry* : Pointer to SA
// + outgoingInterface  : int   :IPsec enabled outgoing interface
// RETURN     :: void : NULL
// **/
static
void IPsecConstructOuterIpHeader(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    int outgoingInterface)
{
    IpHeaderType* innerIpHdr = NULL;
    QueuePriorityType priority = 0;

    innerIpHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    // carry over TOS from red IP header... DONT call ReturnPriorityForPHB
    // because that returns the QUEUE index for the TOS, which is
    // meaningless when it comes to TOS, DSCP, etc.
    priority = (unsigned char) IpHeaderGetTOS(innerIpHdr->ip_v_hl_tos_len);

    // Add IP Header
    // Use default value for TTL

    NetworkIpAddHeader(
        node, msg, saPtr->src, saPtr->dest,
        priority, IPPROTO_IPIP, 0);
#ifdef TRANSPORT_AND_HAIPE
    // Page 31, RFC2401:
    // Configuration determines whether to copy from
    // the inner header (IPv4 only), clear or set the DF.
    // Page 35, RFC2401:
    // .... (the TUNNEL mode) MUST support the option of
    // copying the DF bit from the original packet to the
    // encapsulating header (and processing ICMP PMTU messages).
    //
    // Here we need to extract the new and original IP headers
    // to set the DF bit in the new IP header.
    // But this is left in the to-do list in current
    // QualNet IPsec User Guide.
#endif // TRANSPORT_AND_HAIPE
}

// /**
// API        :: IPsecIsTransportMode
// LAYER      :: Network
// PURPOSE    :: To see if any transport mode SA exists on this interface
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + outgoingInterface    :  int :  outgoing interface
// RETURN     :: bool     : TRUE if packet has processed, FALSE otherwise
// **/
bool IPsecIsTransportMode(Node*     node,
                          Message*  msg,
                          int       outgoingInterface)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;

    int i = 0;
    bool retVal = FALSE;
    IPsecSecurityPolicyEntry* sp = NULL;
    IPsecSecurityPolicyInformation* spdInfo = NULL;
    IPsecSecurityPolicyDatabase* spd = NULL;
    spdInfo = ip->interfaceInfo[outgoingInterface]->spdOUT;

    if (spdInfo)
    {
        spd = spdInfo->spd;
        if (!sp)
        {
            // Locate policy in IPsecSecurityPolicyDatabase which will point
            // to zero or more SAs.
            sp = IPsecGetMatchingSP(msg, spd);
        }
        if (!sp || sp->policy == IPSEC_NONE)
        {
            // Bypass packet
            retVal = FALSE;
        }
        else
        {
            // Apply IPsec
            for (i = 0; i < sp->numSA; i++)
            {
                if (sp->saPtr[i]->mode == IPSEC_TRANSPORT
                    || sp->saPtr[i]->mode == ANY)
                {
                    retVal = TRUE;
                    break;
                }
                else if (sp->saPtr[i]->mode != IPSEC_TUNNEL)
                {
                    ERROR_Assert(FALSE, "IPsec: Unknown IPsec mode\n");
                }
            }
        }
    }
    return retVal;
}

// /**
// API        :: IPsecHandleOutboundPacket
// LAYER      :: Network
// PURPOSE    :: Process IPsec option over outbound packet
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + incomingInterface  :  int :  incoming interface
// + outgoingInterface  :  int :  outgoing interface
// + nextHop            : NodeAddress :  Next Hope Address
// + sp                 : IPsecSecurityPolicyEntry* Security Policy Entry
// + useNextHopSAOnly   : BOOL: if true use only those SA which has
//                              end-point equal to next-hop
// RETURN     :: BOOL : TRUE if packet has processed, FALSE otherwise
// **/
BOOL IPsecHandleOutboundPacket(
    Node* node,
    Message* msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop,
    IPsecSecurityPolicyEntry* sp,
    BOOL useNextHopSAOnly)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp* icmp = (NetworkDataIcmp*) ip->icmpStruct;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    int i = 0;
    clocktype delay = 0;
    clocktype calculatedDelay = 0;
    IPsecSecurityPolicyInformation* spdInfo = NULL;
    IPsecMsgInfoType infoType;
    BOOL retVal = FALSE;
    BOOL isRoutingRequired = FALSE;
    int prevPktSize = MESSAGE_ReturnPacketSize(msg);
    bool isSuccess = false;

    spdInfo = ip->interfaceInfo[outgoingInterface]->spdOUT;
    if (!sp)
    {
        // Locate policy in IPsecSecurityPolicyDatabase which will point to
        // zero or more SAs
        sp = IPsecGetMatchingSP(msg, spdInfo->spd);
    }

    if (!sp || sp->policy == IPSEC_NONE)
    {
        // Bypass packet
        retVal = FALSE;
    }
    else if (sp->policy == IPSEC_DISCARD)
    {
        // Drop the packet
        retVal = TRUE;
        if (ip->isIcmpEnable && icmp->securityFailureEnable)
        {
            BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                        msg,
                                        ipHdr->ip_src,
                                        incomingInterface,
                                        ICMP_SECURITY_FAILURES,
                                        ICMP_AUTHENICATION_FAILED,
                                        0,
                                        0);
            if (ICMPErrorMsgCreated)
            {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                char srcAddr[MAX_STRING_LENGTH];
                IO_ConvertIpAddressToString(ipHdr->ip_src, srcAddr);
                printf("Node %d sending security failed message to %s\n",
                       node->nodeId, srcAddr);
#endif
                (icmp->icmpErrorStat.icmpSecurityFailedSent)++;
            }
        }
        spdInfo->pktDropped++;
#ifdef ADDON_DB

        HandleNetworkDBEvents(
            node,
            msg,
            incomingInterface,
            "NetworkPacketDrop",
            "SP Policy At Tunnel End is IPSEC_DISCARD",
            0,
            0,
            0,
            0);
#endif
        MESSAGE_Free(node, msg);
    }
    else
    {
        IPsecPrintIPHeader(msg);
        IPsecDumpBytes((char*)__FUNCTION__,
                       (char*)"msg->packet_RAW",
                       MESSAGE_ReturnPacket(msg),
                       (UInt64) msg->packetSize);

        // To prevent crashes in case of several nested IPSec Tunnels
        ERROR_Assert(msg->numberOfHeaders < MAXIMUM_NUMBER_OF_HEADERS,
                     "Attemting to add headers more than the maximum"
                     " number of supported headers");

        // Apply IPsec
        for (i = 0; i < sp->numSA; i++)
        {
            if (useNextHopSAOnly && sp->saPtr[i]->dest != nextHop)
            {
                continue;
            }
            if (sp->saPtr[i]->mode == IPSEC_TUNNEL)
            {
                IPsecConstructOuterIpHeader(node,
                                            msg,
                                            sp->saPtr[i],
                                            outgoingInterface);

                // In case of tunnel mode we are encapsulating the packet
                // in new IP header so it is needed to send the packet
                // through routing again.
                isRoutingRequired = TRUE;
            }
            else if (sp->saPtr[i]->mode != IPSEC_TRANSPORT
                     && sp->saPtr[i]->mode != ANY)
            {
                ERROR_Assert(FALSE, "IPsec: Unknown IPsec mode\n");
            }

            // IPsec...ProcessOutput() is called here
            delay += (*(sp->saPtr[i]->handleOutboundPkt))(
                      node,
                      msg,
                      sp->saPtr[i],
                      outgoingInterface,
                      &isSuccess);
            if (isSuccess != true)
            {
                MESSAGE_Free(node, msg);
                break;
            }
            ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
        }
        retVal = TRUE;
        if (isSuccess == true)
        {
            spdInfo->pktProcessed++;
            spdInfo->delayOverhead += delay;
            //for synchronizing encryption processing
            if (spdInfo->encryptNextAvailTime < node->getNodeTime())
            {
                calculatedDelay = delay;
                spdInfo->encryptNextAvailTime = delay + node->getNodeTime();
            }
            else
            {
                calculatedDelay = spdInfo->encryptNextAvailTime + delay
                                  - node->getNodeTime();
                spdInfo->encryptNextAvailTime =
                                            spdInfo->encryptNextAvailTime
                                            + delay;
            }
            spdInfo->byteOverhead += MESSAGE_ReturnPacketSize(msg) -
                                     prevPktSize;
            // Send message with estimated processing delay
            MESSAGE_InfoAlloc(node, msg, sizeof(IPsecMsgInfoType));

            infoType.inOut = 'o';
            infoType.inIntf = incomingInterface;
            infoType.outIntf = outgoingInterface;
            infoType.nextHop = nextHop;
            infoType.isRoutingRequired = isRoutingRequired;
            memcpy(MESSAGE_ReturnInfo(msg),
                   &infoType,
                   sizeof(IPsecMsgInfoType));
            MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
            MESSAGE_SetEvent(msg, MSG_NETWORK_IPsec);
            MESSAGE_Send(node, msg, calculatedDelay);
        }
        else
        {
            // Drop the packet. This case should be hit when there is NO SA
            // defined for a particular SP

            if (ip->isIcmpEnable && icmp->securityFailureEnable)
            {
                BOOL ICMPErrorMsgCreated = FALSE;
                ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                      msg,
                                      ipHdr->ip_src,
                                      incomingInterface,
                                      ICMP_SECURITY_FAILURES,
                                      ICMP_AUTHENICATION_FAILED,
                                      0,
                                      0);
                if (ICMPErrorMsgCreated)
                {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
                    char srcAddr[MAX_STRING_LENGTH];
                    IO_ConvertIpAddressToString(ipHdr->ip_src, srcAddr);
                    printf("Node %d sending security failed message to %s\n",
                           node->nodeId, srcAddr);
#endif
                    (icmp->icmpErrorStat.icmpSecurityFailedSent)++;
                }
            }
            spdInfo->pktDropped++;
#ifdef ADDON_DB
            HandleNetworkDBEvents(node,
                                  msg,
                                  incomingInterface,
                                  "NetworkPacketDrop",
         "SP defined but no corresponding SA defined",
                                  0,
                                  0,
                                  0,
                                  0);
#endif
        }
    }
    return retVal;
}

// /**
// API        :: IPsecCompareSALists
// LAYER      :: Network
// PURPOSE    :: Process inbound packet
// PARAMETERS ::
// + IPsecSecurityAssociationList : saListToBeApplied : List of SAs that
//                                  must be applied as per SP
// + IPsecSecurityAssociationList : saListApplied : List of SAs that have
//                                  been applied
// RETURN     :: BOOL : TRUE, if both the SA lists match, otherwise, FALSE
// **/
BOOL IPsecCompareSALists(IPsecSecurityAssociationList saListToBeApplied,
                         IPsecSecurityAssociationList saListApplied)
{
    if (saListToBeApplied.size() != saListApplied.size())
    {
        return FALSE;
    }
    else
    {
        vector<IPsecSecurityAssociationEntry*>::iterator it;
        vector<IPsecSecurityAssociationEntry*>::reverse_iterator rit;
        rit = saListToBeApplied.rbegin();

        // Both the lists are to be compared in the reverse order as the
        // header applied in the end will be removed first; thus, the order
        // of the SAs applied should be an exact mirror replica of the
        // list of SAs that should have been applied as per SP
        for (it = saListApplied.begin();
            it < saListApplied.end(), rit < saListToBeApplied.rend();
            ++it, ++rit)
        {
            if (!IPsecIsDuplicateSA(*it, *rit))
            {
                return FALSE;
            }
        }
        return TRUE;
    }
}

// /**
// API        :: IPSecHandlePacketToBeDiscarded
// LAYER      :: Network
// PURPOSE    :: Generate and report ICMP error messages in case packet
//               is to be dropped and increment pktDropped statistics
//               in SPD
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + incomingInterface    :  int  : incoming interface
// + previousHopAddress   :  NodeAddress  : Previous hop
// + spdInfo   : IPsecSecurityPolicyInformation  : Security Policy Database
//               in which statistics are to be incremented
// RETURN     :: void : NULL
// **/
void IPSecHandlePacketToBeDiscarded(Node* node,
                                    Message* msg,
                                    int incomingInterface,
                                    IPsecSecurityPolicyInformation* spdInfo)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    NetworkDataIcmp* icmp = (NetworkDataIcmp*) ip->icmpStruct;

    if (ip->isIcmpEnable && icmp->securityFailureEnable)
    {
        IpHeaderType* ipHeader = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
        BOOL ICMPErrorMsgCreated = NetworkIcmpCreateErrorMessage(node,
                                           msg,
                                           ipHeader->ip_src,
                                           incomingInterface,
                                           ICMP_SECURITY_FAILURES,
                                           ICMP_AUTHENICATION_FAILED,
                                           0,
                                           0);
        if (ICMPErrorMsgCreated)
        {
#ifdef DEBUG_ICMP_ERROR_MESSAGES
            char srcAddr[MAX_STRING_LENGTH];
            IO_ConvertIpAddressToString(ipHdr->ip_src, srcAddr);
            printf("Node %d sending security failed message to %s\n",
                                        node->nodeId, srcAddr);
#endif
            (icmp->icmpErrorStat.icmpSecurityFailedSent)++;
        }
    }
    if (spdInfo)
    {
        spdInfo->pktDropped++;
    }
    else
    {
        ip->stats.ipInUnknownProtos++;
    }
#ifdef ADDON_DB
    HandleNetworkDBEvents(
                node,
                msg,
                incomingInterface,
                "NetworkPacketDrop",
                "No SP or SA At Tunnel End",
                0,
                0,
                0,
                0);
#endif
    MESSAGE_Free(node, msg);
}

// /**
// API        :: IPsecHandleInboundPacket
// LAYER      :: Network
// PURPOSE    :: Process inbound packet
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + incomingInterface    :  int  : incoming interface
// + previousHopAddress   :  NodeAddress  : Previous hop
// RETURN     :: void : NULL
// **/
void IPsecHandleInboundPacket(
    Node* node,
    Message* msg,
    int incomingInterface,
    NodeAddress previousHopAddress)
{
    IPsecSecurityAssociationList processedSaList;
    IPsecSecurityPolicyInformation* spdInfo = NULL;
    IPsecSecurityPolicyEntry* sp = NULL;
    clocktype delay = 0;
    IPsecMsgInfoType infoType;
    BOOL match = TRUE;
    NodeAddress srcAddress;
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
    IPsecSecurityAssociationEntry* saPtr = NULL;
    unsigned int spi = 0;
    unsigned char protocol;
    char* dataPtr = NULL;
    bool isSuccess = true;

    protocol = ipHdr->ip_p;
    spi = 0;
    spdInfo = ((NetworkDataIp*) (node->networkData.networkVar))->
               interfaceInfo[incomingInterface]->spdIN;

    // Maintain a copy of the received message; this copy will be used in
    // case the IPSec headers have been removed if the user has mentioned
    // SAs to decrypt/authenticate packet at the node but has configured the
    // SP with BYPASS option
    Message* copyOfReceivedMessage = NULL;
    copyOfReceivedMessage = MESSAGE_Duplicate(node, (const Message*) msg);

    if (protocol == IPPROTO_ESP)
    {
        dataPtr = MESSAGE_ReturnPacket(msg) + IpHeaderSize(ipHdr);
        memcpy(&spi, dataPtr, sizeof(unsigned int));
    }
    else if (protocol == IPPROTO_AH)
    {
        dataPtr = MESSAGE_ReturnPacket(msg)
                  + IpHeaderSize(ipHdr)
                  + AH_WORD_SIZE;
        memcpy(&spi, dataPtr, sizeof(unsigned int));
    }

    srcAddress = ipHdr->ip_src;

    saPtr = IPsecGetMatchingSA(node,
                               protocol,
                               ipHdr->ip_src,
                               ipHdr->ip_dst,
                               spi);

    if (spdInfo)
    {
        sp = IPsecGetMatchingSP(msg, spdInfo->spd);
    }
    if (saPtr == NULL)
    {
        // Throw a warning only if SP is configured with IPSEC option
        if (sp)
        {
            if (sp->policy == IPsecPolicy(IPSEC_USE))
            {
                string warningStr = "Incorrect IPSEC packet received by";
                warningStr.append(" node ");
                ostringstream nodeString;
                nodeString << node->nodeId;
                warningStr.append(nodeString.str());
                ERROR_ReportWarning(warningStr.c_str());
                match = FALSE;
            }
        }
    }

    // If got a matching SA, authenticate and/or decrypt the packet

    while (saPtr != NULL)
    {
        delay += (*(saPtr->handleInboundPkt)) (node,
                                               msg,
                                               saPtr,
                                               incomingInterface,
                                               &isSuccess);
        if (isSuccess == false)
        {
            match = FALSE;
            break;
        }

        processedSaList.push_back(saPtr);

        dataPtr = NULL;
        spi = 0;
        ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);
        dataPtr = MESSAGE_ReturnPacket(msg) + IpHeaderSize(ipHdr);
        protocol = ipHdr->ip_p;
        srcAddress = ipHdr->ip_src;

        if (protocol == IPPROTO_ESP)
        {
            memcpy(&spi, dataPtr, sizeof(unsigned int));
            IPsecDumpBytes((char*)__FUNCTION__,
                           (char*)"dataPtr",
                           (char*)dataPtr,
                           (UInt64)(msg->packetSize
                            - IpHeaderSize(ipHdr)));
        }
        else if (protocol == IPPROTO_AH)
        {
            dataPtr = dataPtr + AH_WORD_SIZE;
            memcpy(&spi, dataPtr, sizeof(unsigned int));
            IPsecDumpBytes((char*)__FUNCTION__,
                           (char*)"dataPtr",
                           (char*)dataPtr,
                           (UInt64)(msg->packetSize
                            - IpHeaderSize(ipHdr)
                            - AH_WORD_SIZE));
        }

        saPtr = IPsecGetMatchingSA(node,
                                   protocol,
                                   ipHdr->ip_src,
                                   ipHdr->ip_dst,
                                   spi);
    }

    // If no SA is found and the packet is meant for this node
    // and packet still has ESP or AH header, then drop the packet
    if (!saPtr
        && (ipHdr->ip_dst
        == NetworkIpGetInterfaceNetworkAddress(node, incomingInterface)
        || (NetworkIpIsMulticastAddress(node, ipHdr->ip_dst)
        && NetworkIpIsPartOfMulticastGroup(node, ipHdr->ip_dst)))
        && (ipHdr->ip_p == IPPROTO_ESP
        || ipHdr->ip_p == IPPROTO_AH))
    {
        match = FALSE;
    }

    // IPsec processing has been done or the packet has been dropped
    // Check SPD to ensure it matches policies there
    // If inbound validation succeeds, then go for SP check
    if (match)
    {
        if (spdInfo)
        {
            sp = IPsecGetMatchingSP(msg, spdInfo->spd);
        }

        if (sp == NULL)
        {
            // Drop the packet
            match = FALSE;
        }
        else if (sp->policy == IPsecPolicy(IPSEC_DISCARD)
                 || sp->policy == IPsecPolicy(IPSEC_NONE))
        {
            // Drop the packet if SP is configured with DISCARD policy
            // If the SP is configured with BYPASS policy, don't drop
            // the packet; just forward the received packet
            match = FALSE;
        }
        else
        {
            IPsecSecurityAssociationList saList;

            // This BOOL variable is used to store the result of comparison
            // of processed SAs' list and the SAs' list that was meant to be
            // used as per the SP
            BOOL saListsMatch = FALSE;

            // Populate the list of SAs that were meant to be applied as per
            // SP
            for (int i = 0; i < sp->numSA; i++)
            {
                saList.push_back(sp->saPtr[i]);
            }

            // Compare both the SAs' list. If they do not match, drop the
            // packet
            saListsMatch = IPsecCompareSALists(saList, processedSaList);

            // If SA lists do not match
            if (!saListsMatch)
            {
                // Drop the packet
                match = FALSE;
            }
        }
    }
    if (match)
    {
        spdInfo->pktProcessed++;
        spdInfo->delayOverhead += delay;
        // Send message with estimated processing delay
        MESSAGE_InfoAlloc(node, msg, sizeof(IPsecMsgInfoType));
        ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

        // Check if the packet belongs to this node or some other node
        // and set the variables in infoType accordingly
        if (IsMyPacket(node, ipHdr->ip_dst))
        {
            infoType.inOut = 'i';
        }
        else
        {
            infoType.inOut = 'o';
            infoType.outIntf = incomingInterface;
            infoType.isRoutingRequired = true;
            ((NetworkDataIp *) node->networkData.networkVar)
             ->stats.ipInForwardDatagrams++;
            ((NetworkDataIp *) node->networkData.networkVar)
             ->stats.ipInReceives++;
        }
        infoType.inIntf = incomingInterface;
        infoType.prevHop = previousHopAddress;
        memcpy(MESSAGE_ReturnInfo(msg),
               &infoType,
               sizeof(IPsecMsgInfoType));
        MESSAGE_SetLayer(msg, NETWORK_LAYER, NETWORK_PROTOCOL_IP);
        MESSAGE_SetEvent(msg, MSG_NETWORK_IPsec);

        MESSAGE_Send(node, msg, delay);
        MESSAGE_Free(node, copyOfReceivedMessage);
    }
    else
    {
        // If the packet is to be bypassed, forward the received message
        if (sp)
        {
            if (sp->policy == IPsecPolicy(IPSEC_NONE))
            {
                delay = 0;
                infoType.inOut = 'o';
                infoType.outIntf = incomingInterface;
                infoType.isRoutingRequired = true;
                infoType.inIntf = incomingInterface;
                infoType.prevHop = previousHopAddress;
                memcpy(MESSAGE_ReturnInfo(copyOfReceivedMessage),
                       &infoType,
                       sizeof(IPsecMsgInfoType));
                MESSAGE_SetLayer(copyOfReceivedMessage,
                                 NETWORK_LAYER,
                                 NETWORK_PROTOCOL_IP);
                MESSAGE_SetEvent(copyOfReceivedMessage,
                                 MSG_NETWORK_IPsec);
                MESSAGE_Send(node, copyOfReceivedMessage, delay);
                MESSAGE_Free(node, msg);
            }
            // If the packet is to be discarded and SP was found, the
            // below code will be hit
            else
            {
                IPSecHandlePacketToBeDiscarded(node,
                                               msg,
                                               incomingInterface,
                                               spdInfo);
                MESSAGE_Free(node, copyOfReceivedMessage);
            }
        }

        // If the packet is to be discarded and no SP was found, the
        // below code will be hit
        else
        {
            IPSecHandlePacketToBeDiscarded(node,
                                           msg,
                                           incomingInterface,
                                           spdInfo);
            MESSAGE_Free(node, copyOfReceivedMessage);
        }
    }
}

// /**
// FUNCTION   :: IPsecPrintStats()
// LAYER      :: Network
// PURPOSE    :: Print the status parameters.
// PARAMETERS ::
// + node      : Node * : Pointer to node.
// + spdInfo   : IPsecSecurityPolicyInformation* :address of Security Policy
//               Database Information
// + inOut     : IPsecDirection : Inbound or Outboud
// + intfId    : No. of interfaces
// RETURN     :: void : NULL
// **/
void IPsecPrintStats(
          Node* node,
          IPsecSecurityPolicyInformation* spdInfo,
          IPsecDirection inOut,
          int intfId)
{
    char buf[MAX_STRING_LENGTH] = {'\0'};
    char dirStr[15] = {'\0'};
    char clockStr[100] = {'\0'};
    NodeAddress intfAddr = NetworkIpGetInterfaceAddress(node, intfId);

    if (inOut == IPSEC_IN)
    {
        sprintf(dirStr, "IPSEC_IN");
    }
    else if (inOut == IPSEC_OUT)
    {
        sprintf(dirStr, "IPSEC_OUT");
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown direction \n");
        return;
    }
    sprintf(buf, "Packet Processed = %u", spdInfo->pktProcessed);
    IO_PrintStat(node, "Network", dirStr, intfAddr, -1, buf);
    sprintf(buf, "Packet Dropped = %u", spdInfo->pktDropped);
    IO_PrintStat(node, "Network", dirStr, intfAddr, -1, buf);

    if (inOut == IPSEC_OUT)
    {
        sprintf(buf, "Total Byte Overhead = %u", spdInfo->byteOverhead);
        IO_PrintStat(node, "Network", dirStr, intfAddr, -1, buf);
    }
    TIME_PrintClockInSecond(spdInfo->delayOverhead, clockStr);
    sprintf(buf, "Total Delay Overhead(s) = %s", clockStr);
    IO_PrintStat(node, "Network", dirStr, intfAddr, -1, buf);
}

// /**
// FUNCTION   :: IPsecFinalize()
// LAYER      :: Network
// PURPOSE    :: Finalize function for the IPSec model.
// PARAMETERS ::
// + node : Node * : Pointer to node.
// RETURN     :: void :NULL
// **/
void IPsecFinalize(Node* node)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    int i = 0;

    if (node->networkData.networkStats)
    {
        for (i = 0; i < node->numberInterfaces; i++)
        {
            if (ip->interfaceInfo[i]->spdIN)
            {
                IPsecPrintStats(
                    node, ip->interfaceInfo[i]->spdIN, IPSEC_IN, i);
            }

            if (ip->interfaceInfo[i]->spdOUT)
            {
                IPsecPrintStats(
                    node, ip->interfaceInfo[i]->spdOUT, IPSEC_OUT, i);
            }
        }
    }

#ifdef TRANSPORT_AND_HAIPE
    // SPD entries are not freed in previous implementations.
    // If freed, recall that SPD entries in the new implementation
    // may be shared amongst interfaces due to wildcard.
#endif // TRANSPORT_AND_HAIPE
}

// /**
// FUNCTION   :: IPsecRemoveMatchingSAfromSAD
// LAYER      :: Network
// PURPOSE    :: Remove security association from SA database
// PARAMETERS ::
// + node      : Node*         : The node processing packet
// + protocol  : IPsecProtocol : IP header protocol
// + dest      : NodeAddress   : IP destination address (outer header)
// + spi       : unsigned int  : Security protocol index
// RETURN     :: void
// **/

IPsecSecurityAssociationEntry* IPsecRemoveMatchingSAfromSAD(
    Node* node,
    IPsecProtocol protocol,
    NodeAddress dest,
    unsigned int spi)
{
    NetworkDataIp* ip = (NetworkDataIp*) node->networkData.networkVar;
    IPsecSecurityAssociationDatabase* sad = ip->sad;
    size_t i = 0;
    IPsecSecurityAssociationEntry* sa = NULL;
    for (i = 0; i < sad->size(); i++)
    {
        sa = sad->at(i);
        // Match the selectors
        if ((!sa->dest || sa->dest == IPSEC_WILDCARD_ADDR
            || sa->dest == dest)
            && sa->securityProtocol== protocol
            && sa->spi == spi)
        {
            sad->erase(sad->begin() + i - 1);
            return sa;
        }
    }
    return NULL;
}

// /**
// FUNCTION   :: IPsecRemoveSAfromSP
// LAYER      :: Network
// PURPOSE    :: Get policy entry that matches packets selector fields
// PARAMETERS ::
// + sp       : IPsecSecurityPolicyEntry: *    : SPD pointer
// + sa       : IPsecSecurityAssociationEntry* : SAD pointer
// RETURN     :: void
// **/

void IPsecRemoveSAfromSP(
    IPsecSecurityPolicyEntry* sp,
    IPsecSecurityAssociationEntry* sa)
{
    if (sa == NULL || sp == NULL)
    {
        return;
    }

    for (int j = 0; j < sp->numSA; j++)
    {
        if (sp->saPtr[j] == sa)
        {
            MEM_free(sa);

            // Move last sa to the vacant place
            sp->saPtr[j] = sp->saPtr[sp->numSA - 1];
            sp->saPtr[sp->numSA - 1] = NULL;
            sp->numSA--;
            if (sp->numSA == 0)
            {
                sp->policy = IPSEC_NONE;
            }
            return;
        }
    }
}

// FUNCTION   :: IPsecGetMatchingSP
// LAYER      :: Network
// PURPOSE    :: Get policy entry that matches packets selector fields
// PARAMETERS ::
// + localNetwork   Address : source network
// + RemoteNetwork  Address : destination network
// + upperProtocol  int : higher layer protocol number
// + spd       : IPsecSecurityPolicyDatabase* : Security Policy Database
// RETURN     :: IPsecSecurityPolicyEntry* : matching SP, NULL if no match
//               found

IPsecSecurityPolicyEntry* IPsecGetMatchingSP(
    Address localNetwork,
    Address RemoteNetwork,
    int  upperProtocol,
    IPsecSecurityPolicyDatabase* spd)
{
    if (spd)
    {
        size_t i;
        IPsecSecurityPolicyEntry* sp = NULL;
        for (i = 0; i < spd->size(); i++)
        {
            sp = spd->at(i);
            // Match the selectors
            if (((sp->srcAddr == IPSEC_WILDCARD_ADDR)
                || (localNetwork.interfaceAddr.ipv4
                == (sp->srcAddr & sp->srcMask)))
                && ((sp->destAddr == IPSEC_WILDCARD_ADDR)
                || (RemoteNetwork.interfaceAddr.ipv4
                == (sp->destAddr & sp->destMask))))
            {
                // Check for protocol
                if (!sp->upperLayerProtocol
                    || (upperProtocol == sp->upperLayerProtocol))
                {
                    // Check for Policy and Port needs to be added.
                    return sp;
                }
            }
        }
    }
    return NULL;
}


// /**
// FUNCTION   :: IPSecCheckSAforEndPoint
// LAYER      :: Network
// PURPOSE    :: To check whether SA contains an SA with given end-point
// PARAMETERS ::
// + sp                 : IPsecSecurityPolicyEntry* : Security Policy
// + endPointAddress    : NodeAddress : SA end-point address.
// RETURN     :: BOOL   : True if found else FALSE
// **/
BOOL IPSecCheckSAforEndPoint(IPsecSecurityPolicyEntry* sp,
                            NodeAddress endPointAddress)
{
    // go through all SA for this SP
    for (int i = 0; i < sp->numSA; i++)
    {
        if (sp->saPtr[i]->dest == endPointAddress)
        {
            return TRUE;
        }
    }
    return FALSE;
}

// /**
// FUNCTION   :: IPsecGetMatchingSPForSAEndPoint
// LAYER      :: Network
// PURPOSE    :: Get policy entry that matches packets selector fields and
//               has atleast one SA which has given end point address
// PARAMETERS ::
// + msg            : Message* : Packet pointer
// + spd            : IPsecSecurityPolicyDatabase* : Security Policy Database
// + endPointAddress: NodeAddress : SA end-point address.
// RETURN     :: IPsecSecurityPolicyEntry* : matching SP, NULL if no match
//               found
// **/
IPsecSecurityPolicyEntry* IPsecGetMatchingSPForSAEndPoint(
    Message* msg,
    IPsecSecurityPolicyDatabase* spd,
    NodeAddress endPointAddress)
{
    IpHeaderType* ipHdr = (IpHeaderType*) MESSAGE_ReturnPacket(msg);

    if (spd)
    {
        size_t i = 0;
        IPsecSecurityPolicyEntry* sp = NULL;
        for (i = 0; i <= spd->size(); i++)
        {
            sp = spd->at(i);
            // Match the selectors
            if (((sp->srcAddr == IPSEC_WILDCARD_ADDR)
                || ((ipHdr->ip_src & sp->srcMask)
                == (sp->srcAddr & sp->srcMask)))
                && ((sp->destAddr == IPSEC_WILDCARD_ADDR)
                || ((ipHdr->ip_dst & sp->destMask)
                == (sp->destAddr & sp->destMask))))
            {
                // Check for protocol
                // Support for Dual-IP added
                if (IPsecVerifyUpperLayerProtocol
                    ((unsigned char)sp->upperLayerProtocol, ipHdr->ip_p))
                {
                    unsigned short srcPort = 0;
                    unsigned short destPort = 0;
                    IPsecGetSrcAndDestPort(msg, &srcPort, &destPort);
                    if ((sp->srcPort == IPSEC_WILDCARD_PORT
                        || sp->srcPort == srcPort)
                        && (sp->destPort == IPSEC_WILDCARD_PORT
                        || sp->destPort == destPort))
                    {
                        if (IPSecCheckSAforEndPoint(sp, endPointAddress))
                        {
                            return sp;
                        }
                    }
                }
            }
        }
    }

    return NULL;
}
