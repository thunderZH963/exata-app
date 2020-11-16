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
// PROTOCOL :: ESP
// SUMMARY ::
//    Encapsulating Security Payload (ESP) header is designed to
//    provide a mix of security services in IPv4 and IPv6.  ESP may be
//    applied alone, in combination with the IP Authentication Header (AH)
//    or in a nested fashion. Security services can be provided between a
//    pair of communicating hosts, between a pair of communicating security
//    gateways, or between a security gateway and a host. The ESP header is
//    inserted before  an encapsulated IP header (tunnel mode) or in between
//    the IP header and the upper layer protocol header(transport mode) .
// STATISTICS ::
// + pktProcessed  : Number of Packet processed by IPsec
// + pktDropped    : Number of Packets dropped for IPsec
// + byteOverhead  : Number of Extra bytes added for IPsec
// + delayOverhead : Cumulative delay for IPsec
// APP_PARAM ::
// CONFIG_PARAM ::
// + IPSEC-ENABLED : Node Id. : Specify the nodes, which are IPSec enabled
// + IPSEC-CONFIG-FILE : <filename>.ipsec : Specify the IPSec configuration
//                                          File
// + IPSEC-REAL-CRYPTO-ENABLED : <YES|NO>.Specify if real crypto is enabled or
//                                  not.
// + IPSEC-DES-CBC-PROCESSING-RATE : clocktype : Processing rate for
//                                   DES-CBC algorithm
// + IPSEC-HMAC-MD5-96-PROCESSING-RATE : clocktype : Processing rate for
//                                       HMAC-MD5-96
//                                         algorithm
// + IPSEC-HMAC-SHA-1-96-PROCESSING-RATE : clocktype : Processing rate for
//                                           HMAC-SHA-1-96 algorithm

// SPECIAL_CONFIG :: <filenal\me>.ipsec : IPSec configuration File
// + To make an interface of a node IPSec enable
//   Syntax:
//   NODE <node-id> <interface index>
//   <node-id>          specifies the IPSec enabled node
//   <interface index>  specifies the IPSec enabled interface of the
//                        node specified in <node-id> field.
// + To create an SA ( Security Association)
//   Syntax:
//   SA <name-tag> TRANSPORT | TUNNEL <tunnel end point> <protocol> <spi>
//   [ -E <encryption_algo> <"key"> ] [ -A <auth_algo> <"key">> ]
//   <name-tag>         specifies the name of the Security Association Entry
//   <tunnel end point> specifies the address of an interface of the IPSec
//                      enabled tunnel-end node.
//   <protocol>         supports only 'ESP'(Encapsulating Security Payload)
//                      mode
//   <spi>              spi (security parameter index) is used to uniquely
//                      identify a SA.

//   <encryption_algo> specifies the encryption algorithm for the SA entry.
//   <auth_algo>      specifies the authorization algorithm for the SA entry.
//
// + To create an SPD (Security Policy Database Entry) entry
//
//   Syntax:
//
//   SP <src_range> <dest_range> <upper_layer_protocol> -P <IN | OUT>
//      <DISCARD | NONE | IPSEC> [ List of SA names ]
//
//   <src_range>            specifies the network address from where the
//                          packet(to be IPSec processed) orginates
//   <dest_range>           specifies the IPSec processed packet's
//                          destination network address.
//   <upper_layer_protocol> specifies the  protocol of transport layer. It
//                          may be TCP, UDP or ANY. Packets delevered by
//                          these protocols will be IPSec processed.
//
//
//   <IN | OUT>             specifies the traffic mode (inbound or outbound)
//                          for IPSec processing through the IPSec enabled
//                          interface. It can either be IN for inbound
//                          packet or OUT for outbound packet.
//   < List of SA names>    List of SA's those are assocated with this
//                          SP entry.
// VALIDATION ::$QUALNET_HOME/scenarios/cyber/ipsec
// IMPLEMENTED_FEATURES ::
// + TUNNEL mode and TRANSPORT mode.
// + Unicast packet transfer
// + Fragmentation and reassembly of IPSec packets.
// + Encapsulation of IP and upper layer protocols.
// + IPSec service is provided using Encapsulation Security Payload
//   (ESP) protocol
// + Delays for running encryption and authentication algorithms.
// + Following is the list of encryption and authentication algorithms
//   that are implemented:
// + Encryption: DES-CBC,3DES-CBC,AES-CBC,AES-CTR,NULL
// + Authentication: HMAC-MD5-96, HMAC-SHA1-96,NULL

// OMITTED_FEATURES :: (Title) : (Description) (list)
// + Authentication Header (AH)
// + IPv6, Multicast, and NAT (Network Address Translation)
// + Authentication and encryption algorithms other than mentioned above.
// + Internet Key Exchange (IKE) algorithm 
// + IP payload compression
// + Extended Sequence Number implementation

// ASSUMPTIONS ::
// + IPSec can only work with ESP (Encapsulating Security Protocol).
//   Using NULL encryption in ESP can imitate the unsupported AH protocol.
// + For the IPSec encryption and integrity check,
//   OpenSSL libraries will be used.
// + For Certificate Authority (CA), IPSec will use a configuration file.
// + Only basic SA between the transmitter and the receiver will be
//   established.
// + Extended Sequence Number implementation is not being implemented,
//   because this will require higher level SA to be established.
// + Only, delays for running different Authentication and Encryption
//   algorithms are considered.
// STANDARD :: Coding standard follows the following Coding Guidelines
//             1. SNT C Coding Guidelines for QualNet 3.2
// RELATED :: IPSec, IPv4
// **/

#ifndef IPSEC_ESP_H
#define IPSEC_ESP_H




// /**
// STRUCT      :: IPsecEspHeader
// DESCRIPTION :: Structure for Encapsulating Security Payload header
// **/
struct IPsecEspHeader
{
    NodeAddress spi;    // Security Parameters Index
    unsigned int seqCounter;
} ;

struct IPsecEspTrailer
{
    unsigned char padLen;
    unsigned char nextHeader;
};

// /**
// STRUCT :: IPsecAuthenticationAlgoProfile
// DESCRIPTION :: A data structure that describes the set of parameters
// associated with a given Authentication Algo.
// **/
struct IPsecAuthAlgoProfile
{
    // Name of the Authentication Algorithm
    IPsecAuthAlgo         auth_algo_name;
    // Stores the nane of the Authentication Algo Name
    char                  auth_algo_str[80];
    // Length in bytes for authorization algorithm
    unsigned char         authLen;
};
#define IPsecAuthAlgoDefaultProfileCount 7

extern IPsecAuthAlgoProfile
    IPsecAuthAlgoProfiles[IPsecAuthAlgoDefaultProfileCount];
// /**
// STRUCT :: IPsecEncryptionAlgoProfile
// DESCRIPTION :: A data structure that describes the set of parameters
// associated with a given Encryption Algo.
// **/

struct IPsecEncryptionAlgoProfile {
    // Name of the Encryption Algorithm
    IPsecEncryptionAlgo   encrypt_algo_name;
    // Stores the name of the Encryption Algo Name in string format
    char                  encrypt_algo_str[80];
    // IV Size
    unsigned char         ivSize;
    // Stores the IV Value
    unsigned char          iv[4];
    // Blocksize in bytes
    unsigned char         blockSize;
};
#define IPsecEncryptionAlgoDefaultProfileCount 8


extern IPsecEncryptionAlgoProfile
    IPsecEncryptionAlgoProfiles[IPsecEncryptionAlgoDefaultProfileCount];
// /**
// FUNCTION   :: IPsecESPInit
// LAYER      :: Network
// PURPOSE    :: Initialize ESP data for given SA
// PARAMETERS ::
// + node              : Node*    : The node processing inbound packet
// + esp               : IPsecEspData** : ESP data
// + authAlgoName      : IPsecAuthAlgo : Authentication algorithm to be used
// + encryptionAlgoName: IPsecEncryptionAlgo: Encryption algorithm to be used
// + authKey           : char*         : Key for authentication
// + enryptionKey      : char*         : Key for encryption
// + rateParams       : IPsecProcessingRate : Delay parameters for
//                                               different algorithm
// RETURN     :: void : NULL
// **/
void IPsecESPInit(
    IPsecSecurityAssociationEntry* esp,
    IPsecAuthAlgo authAlgoName,
    IPsecEncryptionAlgo encryptAlgoName,
    char* authKey,
    char* encryptionKey,
    IPsecProcessingRate* rateParams);

// /**
// FUNCTION   :: IPsecESPProcessOutput
// LAYER      :: Network
// PURPOSE    :: Process an outbound IP packet requires secure transfer.
// PARAMETERS ::
// + node     :  Node*    : The node processing packet
// + msg      :  Message* : Packet pointer
// + saPtr    :  IPsecSecurityAssociationEntry* : Pointer to SA
// + interfaceIndex : the outputing interface
// RETURN     :: clocktype : Processing delay
// **/
clocktype IPsecESPProcessOutput(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess);

// /**
// FUNCTION   :: IPsecESPProcessInput
// LAYER      :: Network
// PURPOSE    :: Process an inbound IPSEC packet
// PARAMETERS ::
// + node     :  Node*    : The node processing packet
// + msg      :  Message* : Packet pointer
// + saPtr    :  IPsecSecurityAssociationEntry* : Pointer to SA
// + interfaceIndex : the inputing interface
// RETURN     :: void : NULL
// **/
clocktype IPsecESPProcessInput(
    Node* node,
    Message* msg,
    IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess);

// /**
// FUNCTION   :: IPsecESPGetSPI
// LAYER      :: Network
// PURPOSE    :: Extarct SPI from message.
// PARAMETERS ::
//  +msg      :  Message* : Packet pointer
// RETURN     :: unsigned int : spi
// **/
unsigned int IPsecESPGetSPI(Message* msg);
// /**
// FUNCTION   :: IPsecDumpBytes()
// LAYER      :: Network
// PURPOSE    :: Prints the hexdump of the packet
// PARAMETERS ::       :
// + function_nm  : char*    : Function name from this function is invoked.
// + name         : char* : Caption of the data to be printed.
// + D      :  char* : buffer to be printed.
// + count  : UInt64 :length of the buffer to be printed.
// RETURN     :: void : NULL
void IPsecDumpBytes(char* function_nm,
                    char* name,
                    char* D,
                    UInt64 count);

// /**
// FUNCTION   :: IPsecPrintIPHeader()
// LAYER      :: Network
// PURPOSE    :: Prints Ip header.
// PARAMETERS ::
//  +msg       : Message* : Packet pointer
//  +node      : Node*: :Node pointer
// RETURN      : void
// **/
void IPsecPrintIPHeader(Message* msg, Node* node = NULL);

#define ESP_SPI_SIZE 4
#define ESP_SEQNO_SIZE 4
#endif  // ESP_H
