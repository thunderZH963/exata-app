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
// PROTOCOL :: IPSec
// SUMMARY ::
//    IPsec protocols and associated default algorithms are designed to
//    provide high quality security for Internet traffic.The set of security
//    services offered by IP Security includes access control,connectionless
//    integrity, data origin authentication, protection against replays
//    (a form of partial sequence integrity), confidentiality (encryption),
//    and limited traffic flow confidentiality. These services are provided
//    at the IP layer, offering protection for IP and upper layer protocols.
// LAYER ::  Network Layer
// STATISTICS ::
// + pktProcessed  : Number of Packets processed by IPsec
// + pktDropped    : Number of Packets dropped for IPsec
// + byteOverhead  : Number of Extra bytes added for IPsec
// + delayOverhead : Cumulative delay for IPsec
// APP_PARAM ::
// CONFIG_PARAM ::
// + IPSEC-ENABLED : Node NO. : Specify the nodes, which are IPSec enabled
// + IPSEC-CONFIG-FILE : <filename>.ipsec : Specify the IPSc configuration
//                                          File
// + IPSEC-DES-CBC-DELAY : clocktype : Processing delay for DES-CBC algorithm
// + IPSEC-HMAC-MD5-96-DELAY : clocktype : Processing delay for HMAC-MD5-96
//                                         algorithm
// + IPSEC-HMAC-SHA-1-96-DELAY : clocktype : Processing delay for
//                                           HMAC-SHA-1-96 algorithm
// VALIDATION ::$QUALNET_HOME/scenarios/cyber/ipsec
// IMPLEMENTED_FEATURES ::
// + TUNNEL mode and TRANSPORT mode.
// + Unicast/Multicast packet transfer
// + Fragmentation and reassembly of IPSec packets.
// + Encapsulation of IP and upper layer protocols.
// + IPSec service is provided using Encapsulation Security Payload
//   (ESP) protocol
// + Delays for running encryption and authentication algorithms.
// + Following is the list of encryption and authentication algorithms
//   that are implemented:
// + Encryption: DES-CBC,3DES-CBC,AES-CBC,AES-CTR,NULL
// + Authentication: HMAC-MD5-96, HMAC-SHA1-96,NULL
// + Authentication Header (AH)

// OMITTED_FEATURES :: (Title) : (Description) (list)

// + IPv6 and NAT (Network Address Translation)
// + Authentication and encryption algorithms other than mentioned above.
// + Internet Key Exchange (IKE) algorithm
// + IP payload compression
// + Extended Sequence Number implementation

// ASSUMPTIONS ::
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
// RELATED :: ESP/AH protocol, IPv4
// **/


#ifndef IPSEC_H

#define IPSEC_H

// This macro is a pre-requisite of CYBER_LIB
#define TRANSPORT_AND_HAIPE

// /**
// CONSTANT    :: INITIAL_SAD_SIZE
// DESCRIPTION :: Size of Initial Security Association Database
// **/
#define INITIAL_SAD_SIZE 10

// /**
// CONSTANT    :: INITIAL_SA_BUNDLE_SIZE
// DESCRIPTION :: No. of Initial Security Association Bundle
// **/
#define INITIAL_SA_BUNDLE_SIZE 3

// /**
// CONSTANT    :: INITIAL_SAD_SIZE
// DESCRIPTION :: Size of Initial Security Policy Database
// **/
#define INITIAL_SPD_SIZE 5

// /**
// CONSTANT    :: IPSEC_HMAC_MD5_PROCESSING_RATE
// DESCRIPTION :: Processing rate in bps for 'HMAC_MD5' algorithm
// **/
#define IPSEC_HMAC_MD5_PROCESSING_RATE     800000000

// /**
// CONSTANT    :: IPSEC_HMAC_MD5_96_PROCESSING_RATE
// DESCRIPTION :: Processing rate in bps for 'HMAC_MD5_96' algorithm
// **/
#define IPSEC_HMAC_MD5_96_PROCESSING_RATE     800000000

// /**
// CONSTANT   :: IPSEC_HMAC_SHA_1_PROCESSING_RATE
// DESCRIPTION:: Processing rate in bps for 'HMAC_SHA_1' algorithm
// **/
#define IPSEC_HMAC_SHA_1_PROCESSING_RATE   800000000

// /**
// CONSTANT    :: IPSEC_HMAC_SHA_1_96_PROCESSING_RATE
// DESCRIPTION :: Processing rate in bps for 'HMAC_SHA_1_96' algorithm
// **/
#define IPSEC_HMAC_SHA_1_96_PROCESSING_RATE   800000000

// /**
// CONSTANT    :: IPSEC_DES_CBC_PROCESSING_RATE
// DESCRIPTION :: Processing rate in bps for 'DES_CBC' algorithm
// **/
#define IPSEC_DES_CBC_PROCESSING_RATE         800000000

// /**
// CONSTANT    :: TCP_MAX_PORT
// DESCRIPTION :: Maximum value of Port
// **/
#define TCP_MAX_PORT    65535
//CONSTANT    :: IPSEC_DUMMY_NEXT_HEADER
//DESCRIPTION :: This field is filled for dummy packets in the IPSec Trailer
//
#define IPSEC_DUMMY_NEXT_HEADER           59
// /**
// CONSTANT    :: ESP_DES_IV_SIZE
// DESCRIPTION :: IV lengths (in bytes) for 'DES' algorithm
// **/
#define IPSEC_DES_IV_SIZE                 8

#define IPSEC_TRIPLE_DES_CBC_IV_SIZE      8

#define IPSEC_AES_CTR_IV_SIZE              8

#define IPSEC_AES_CBC_128_IV_SIZE         16

#define ALGO_DES_CBC                           "DES-CBC"
#define ALGO_AES_CBC                           "AES-CBC"
#define ALGO_AES_CBC128                        "AES-CBC128"
#define ALGO_NULL_ENCRP                        "NULL"
#define ALGO_AES_CTR                           "AES-CTR"
#define ALGO_HMAC_MD5                          "HMAC-MD5"
#define ALGO_HMAC_MD5_96                       "HMAC-MD5-96"
#define ALGO_HMAC_SHA1                         "HMAC-SHA1"
#define ALGO_HMAC_SHA1_96                      "HMAC-SHA-1-96"
#define ALGO_AES_XCBC_MAC_96                   "AES-XCBC-MAC-96"
#define ALGO_NULL_AUTH                         "NULL"


// /**
// CONSTANT    :: ESP_3DES_IV_SIZE
// DESCRIPTION :: IV lengths (in bytes) for '3DES' algorithm
// **/
#define IPSEC_3DES_IV_SIZE                8

// /**
// CONSTANT    :: ESP_BLF_IV_SIZE
// DESCRIPTION :: IV lengths (in bytes) for 'BLF' algorithm
// **/
#define IPSEC_BLF_IV_SIZE                 8

// /**
// CONSTANT    :: ESP_CAST_IV_SIZE
// DESCRIPTION :: IV lengths (in bytes) for 'CAST' algorithm
// **/
#define IPSEC_CAST_IV_SIZE                8

// /**
// CONSTANT    :: ESP_DES_BLOCK_SIZE
// DESCRIPTION :: Block sizes(in byte) for 'DES' algorithm
// **/
#define IPSEC_DES_BLOCK_SIZE              8

#define IPSEC_TRIPLE_DES_CBC_BLOCK_SIZE   8

#define IPSEC_AES_CTR_BLOCK_SIZE          16

#define IPSEC_AES_CBC_128_BLOCK_SIZE      16

// /**
// CONSTANT    :: ESP_3DES_BLOCK_SIZE
// DESCRIPTION :: Block sizes(in byte) for '3DES' algorithm
// **/
#define IPSEC_3DES_BLOCK_SIZE             8

// /**
// CONSTANT    :: ESP_BLF_BLOCK_SIZE
// DESCRIPTION :: Block sizes(in byte) for 'BLF' algorithm
// **/
#define IPSEC_BLF_BLOCK_SIZE              8

// /**
// CONSTANT    :: ESP_CAST_BLOCK_SIZE
// DESCRIPTION :: Block sizes(in byte) for 'CAST' algorithm
// **/
#define IPSEC_CAST_BLOCK_SIZE             8

// /**
// CONSTANT    :: ESP_HMAC_MD5_AUTH_LEN
// DESCRIPTION :: Length in bytes for 'HMAC_MD5' algorithm
// **///
#define IPSEC_HMAC_MD5_AUTH_LEN           16

// /**
// CONSTANT    :: ESP_HMAC_MD5_96_AUTH_LEN
// DESCRIPTION :: Length in bytes for 'HMAC_MD5_96' algorithm
// **///
#define IPSEC_HMAC_MD5_96_AUTH_LEN        12

// /**
// CONSTANT    :: ESP_HMAC_SHA_1_AUTH_LEN
// DESCRIPTION :: Length in bytes for 'HMAC_SHA_1' algorithm
// **/
#define IPSEC_HMAC_SHA_1_AUTH_LEN         16

// /**
// CONSTANT    :: ESP_HMAC_SHA_1_96_AUTH_LEN
// DESCRIPTION :: Length in bytes for 'HMAC_SHA_1_96' algorithm
// **/
#define IPSEC_HMAC_SHA_1_96_AUTH_LEN      12

#define IPSEC_AES_XCBC_MAC_96_AUTH_LEN    12

// /**
// CONSTANT    :: ESP_TRAILER
// DESCRIPTION :: Size of ESP trailer(in bytes)
// **/
#define ESP_TRAILER                       2
// references show the following header:
// ** CT IP Header = 20 bytes
// ** SPI = 4 bytes
// ** ESP Sequence Number = 4 bytes
// ** State Variable = 16 bytes
// ** Payload Sequence Number = 8 bytes
// ** Dummy = 1 byte
// ** Pad Length = 2 bytes
// ** Next Header = 1 byte
// ** Authentication Data = 4 bytes
//
// Total = 60 bytes... Minus 20 bytes for CT IP header
// which we are already adding = 40 bytes.
#define IAHEP_DEFAULT_OVERHEAD_SIZE 40
// /**
// CONSTANT    :: IPSEC_WILDCARD_ADDR
// CONSTANT    :: IPSEC_WILDCARD_PORT
// DESCRIPTION :: Wildcard * for net addresses
// DESCRIPTION :: Wildcard * for port number
// **/
#define IPSEC_WILDCARD_ADDR    ((NodeAddress)-1)
#define IPSEC_WILDCARD_PORT    0

#define DEFAULT_ENCRYP_ALGO         IPSEC_DES_CBC
#define DEFAULT_MODE                IPSEC_TRANSPORT
#define DEFAULT_AUTH_ALGO           IPSEC_HMAC_MD5

#define IPSEC_ENABLE_EXTENDED_SEQUENCE_NO        0x00000001
#define IPSEC_ENABLE_ANTI_REPLAY                 0x00000002
#define IPSEC_ENABLE_COMBINED_ENCRYPT_AUTH_ALGO  0x00000004

#define PADDING_LEN                              1
#define NEXT_HEADER_FLD_LEN                      1
#define SPI_LEN                                  4
#define SEQ_LEN                                  4

// /**
// CONSTANT    :: MAX_SA_FILTERS
// DESCRIPTION :: Maximum number of SA filters permitted in an SP entry
// **/
#define MAX_SA_FILTERS         3

// /**
// CONSTANT    :: FOUR_BYTE_BOUNDARY
// DESCRIPTION :: Boundary to which every IPSec packet has to be aligned
// **/
#define FOUR_BYTE_BOUNDARY 32

// /**
// CONSTANT    :: MAX_VALID_SA_TOKENS
// DESCRIPTION :: Total number of tokens that are permissible in any SA
// **/
#define MAX_VALID_SA_TOKENS 5

// /**
// CONSTANT    :: MAXIMUM_NUMBER_OF_HEADERS
// DESCRIPTION :: Maximum number of permissible headers in any packet
// **/
#define MAXIMUM_NUMBER_OF_HEADERS 10

// /**
// ENUMERATION :: IPsecSAMode
// DESCRIPTION :: Two mode of IPSec
// **/
typedef enum
{
    IPSEC_TRANSPORT,
    IPSEC_TUNNEL,
    ANY
} IPsecSAMode;

// /**
// ENUMERATION :: IPsecSAMode
// DESCRIPTION :: Two IPSec protocols
// **/
typedef enum
{
    IPSEC_AH,
    IPSEC_ESP,
    IPSEC_ISAKMP,
#ifdef ADDON_BOEINGFCS
    IPSEC_CES_ISAKMP,
#endif
    IPSEC_INVALID_PROTO
} IPsecProtocol;

// /**
// ENUMERATION :: IPsecLevel
// DESCRIPTION :: Four IPSec levels.
//                Currently, QualNet supports only "REQUIRE".
// **/
enum IPsecLevel
{
    IPSEC_LEVEL_REQUIRE,
    IPSEC_LEVEL_DEFAULT,
    IPSEC_LEVEL_USE,
    IPSEC_LEVEL_UNIQUE
};

// /**
// ENUMERATION ::  IPsecDirection
// DESCRIPTION ::  IPSec enabled direction i.e.IN or OUT
// **/
typedef enum
{
    IPSEC_IN,
    IPSEC_OUT,
    IPSEC_INVALID_DIRECTION
} IPsecDirection;

// /**
// ENUMERATION ::  IPsecPolicy
// DESCRIPTION ::  Different IPSec policies
// **/
typedef enum
{
    IPSEC_DISCARD,
    IPSEC_NONE,
    IPSEC_USE
} IPsecPolicy;

// /**
// ENUMERATION ::  IPsecAuthAlgo
// DESCRIPTION ::  IPSec authorization algorithms
// **/
typedef enum
{
    IPSEC_AUTHALGO_LOWER = 0, // must be the first and 0
    IPSEC_HMAC_MD5 = 1,
    IPSEC_HMAC_SHA1,
    IPSEC_HMAC_MD5_96,
    IPSEC_HMAC_SHA_1_96,
    IPSEC_AES_XCBC_MAC_96,
    IPSEC_NULL_AUTHENTICATION,
    IPSEC_AUTHALGO_UPPER // must be the last
} IPsecAuthAlgo;

typedef enum
{
//Currently there are no combined mode algos defined
    IPSEC_COMBINED_ALGO = 0,
}IPsecCombinedAlgo;

extern const char authAlgoName[][14];

// /**
// ENUMERATION ::  IPsecEncryptionAlgo
// DESCRIPTION ::  IPSec Encryption algorithms
// **/
typedef enum
{
    IPSEC_ENCRYPTIONALGO_LOWER = 0, // must be the first and 0
    IPSEC_DES_CBC = 1,
    IPSEC_SIMPLE,
    IPSEC_BLOWFISH_CBC,
    IPSEC_NULL_ENCRYPTION,
    IPSEC_TRIPLE_DES_CBC,
    IPSEC_AES_CTR,
    IPSEC_AES_CBC_128,
    IPSEC_ENCRYPTIONALGO_UPPER // must be the last
} IPsecEncryptionAlgo;

// /**
// ENUMERATION ::  IPsecSACaseNumber
// DESCRIPTION ::  This enumeration is used to distinguish between different
//                 kinds of SAs
// **/
typedef enum
{
    IPSEC_SA_AH_MODE = 0,
    IPSEC_SA_AH_NO_MODE,
    IPSEC_SA_ESP_ENCR,
    IPSEC_SA_ESP_MODE_ENCR,
    IPSEC_SA_ESP_ENCR_AUTH,
    IPSEC_SA_ESP_MODE_ENCR_AUTH
} IPsecSACaseNumber;

// /**
// ENUMERATION ::  IPsecSPCaseNumber
// DESCRIPTION ::  This enumeration is used to distinguish between different
//                 kinds of SPs
// **/
typedef enum
{
    IPSEC_SP_PROT_DIR_POL = 0,
    IPSEC_SP_PROT_POL
} IPsecSPCaseNumber;

extern const char encryptionAlgoName[][13];

// /**
// STRUCT      :: IPsecMsgInfoType
// DESCRIPTION :: IPSec message information structure.
// **/
typedef struct
{
    char inOut;
    int inIntf;
    int outIntf;
    BOOL isRoutingRequired;
    NodeAddress prevHop;
    NodeAddress nextHop;
} IPsecMsgInfoType;

// /**
// STRUCT      :: IPsecSecurityAssociationEntry
// DESCRIPTION :: Structure for Security Association Database entry
// **/
struct IPsecSecurityAssociationEntry;


// /**
// FUNCTION POINTER :: ProcessOutFunc
// LAYER            :: Network
// PURPOSE          :: Function to process outbound packet
// PARAMETERS       ::
// + node           :  Node* : The node initializing IPsec
// + msg            :  Message* : Packet pointer
// + IPsecSecurityAssociationEntry* : IPSec security association Entry
// + interfaceIndex : the outputing interface
// RETURN           :: clocktype : delay
// **/
typedef
clocktype (*ProcessOutFunc)(
    Node* node,
    Message* msg,
    struct IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess);

// /**
// FUNCTION POINTER :: ProcessInFunc
// LAYER            :: Network
// PURPOSE          :: Function to process inbound packet
// PARAMETERS       ::
// + node           :  Node* : The node initializing IPsec
// + msg            :  Message* : Packet pointer
// + IPsecSecurityAssociationEntry* : IPSec security association Entry
// + interfaceIndex : the inputing interface
// RETURN           :: clocktype : delay
// **/
typedef
clocktype (*ProcessInFunc)(
    Node* node,
    Message* msg,
    struct IPsecSecurityAssociationEntry* saPtr,
    int interfaceIndex,
    bool* isSuccess);

#ifdef TRANSPORT_AND_HAIPE
// /**
// STRUCT      :: HAIPE Specification
// DESCRIPTION :: Structure for storing specification of
//                different HAIPE encryption devices.
// **/
typedef struct struct_haipe_spec_str
{
    char name[MAX_STRING_LENGTH];
    double operationRate; // measured in bps
} HAIPESpec;
#endif // TRANSPORT_AND_HAIPE

// /**
// STRUCT      :: IPsecProcessingRate
// DESCRIPTION :: Structure for rate for different encryption
//                and authorization algorithm
// **/
typedef struct
{
    clocktype hmacMd5Rate;
    clocktype hmacMd596Rate;
    clocktype hmacSha1Rate;
    clocktype hmacSha196Rate;
    clocktype desCbcRate;
    clocktype aesXcbcMac96Rate;
} IPsecProcessingRate;


struct AlgoDetails
{
    // Anti Replay window counter
    unsigned int          antiReplayCounter;
    // Anti Replay Window Size
    void*                 antiReplayWnd;
    // Name of the Encryption Algorithm
    IPsecEncryptionAlgo   encrypt_algo_name;
    // Stores the nane of the Encryption Algo Name
    char                  encrypt_algo_str[80];
    // Name of the Authentication Algorithm
    IPsecAuthAlgo         auth_algo_name;
    // Stores the nane of the Authentication Algo Name
    char                  auth_algo_str[80];
    // Private Key
    char                  algo_priv_Key[BIG_STRING_LENGTH];
    // Public Key
    char                  algo_pub_key[BIG_STRING_LENGTH];
    // IV Size
    unsigned char         ivSize;
    // Stores the IV Value
    unsigned int          iv[4];
    // Extra field, if rate required
    unsigned int          rate;
    // Blocksize in bytes
    unsigned char         blockSize;
    // Length in bytes for
    unsigned char         authLen;
};

struct Combined_AlgoDetails
{
    // Anti Replay window counter
    unsigned int          antiReplayCounter;
    // Anti Replay Window Size
    void*                 antiReplayWnd;
    // Combined Algorithm Name
    // Either this field will be populated or the other two
    IPsecCombinedAlgo     comb_algo_name;
    // Stores the nane of the Combined Algo Name
    char                  comb_algo_str[80];
    // Combined Private Key
    char                  comb_algo_priv_Key[80];
    // Combined Public Key
    char                  comb_algo_pub_key[80];
    // IV Size
    unsigned char         ivSize;
    // Stores the IV Value
    unsigned int          iv[2];
    // Extra field, if rate required
    unsigned int          rate;
    // Blocksize in bytes
    unsigned char         blockSize;
    // Length in bytes for authorization algorithm
    unsigned char         authLen;

};


struct IPsecSecurityAssociationEntry
{
    unsigned int          spi;               // Security Parameters Index
    IPsecSAMode           mode;              // Tunnel or Transport
    NodeAddress           src;               // Transport start point
    NodeAddress           dest;              // Tunnel end point or
                                             // Transport end point
    IPsecProtocol         securityProtocol;  // AH or ESP

    unsigned int          enable_flags;      // This field will hold lots
                                             // of flags, such as
                                             // Combinational Algo Flag,
                                             // Extended Sequence Number
                                             // Flag, Anti - Replay Flag etc
                                             // (At the max 32 flags can be
                                             // stored here)

    AlgoDetails           encryp;            // Encryption Algorithm Details
    AlgoDetails           auth;              // Authentication Algorithm
                                             // Details
    Combined_AlgoDetails  combined;          // Combined Algorithm Details

    unsigned int          seqCounter;        // Sequence counter
    BOOL                  seqCounterOverFlow;// Sequence Number
                                             // Overflow Counter

    clocktype             lifeTime;
    clocktype             softStateLife;
    unsigned int          pmtu;

    ProcessOutFunc        handleOutboundPkt; // Function Pointer to handle
                                             // outbound packets
    ProcessInFunc         handleInboundPkt;  // Function Pointer to handle
                                             // inbound packets

};

// /**
// STRUCT      :: str_ipsec_security_policy_entry_sa_filter
// DESCRIPTION :: Structure for SA filter in Security Policy Database entry
// **/
typedef struct str_ipsec_security_policy_entry_sa_filter
{
    IPsecProtocol ipsecProto;
    NodeAddress tunnelSrcAddr;
    NodeAddress tunnelDestAddr;
    enum IPsecLevel ipsecLevel;
    IPsecSAMode ipsecMode;
}IPsecSAFilter;

// /**
// STRUCT      :: str_ipsec_security_policy_entry
// DESCRIPTION :: Structure for Security Policy Database entry
// **/
typedef struct str_ipsec_security_policy_entry
{
    NodeAddress srcAddr;       // original source address
    NodeAddress srcMask;
    NodeAddress destAddr;      // original destination address
    NodeAddress destMask;
    unsigned short srcPort;
    unsigned short destPort;
    int upperLayerProtocol;    // Transport Layer Protocol
    IPsecDirection direction;  // Inbound or Outbound
    IPsecPolicy policy;        // Ipsec policies, i.e DISCARD, USE and none
    IPsecProcessingRate processingRate;
    vector<IPsecSAFilter*> saFilter;
    int numSA;                 // No. of SAs associated with the SP entry
    IPsecSecurityAssociationEntry** saPtr;
} IPsecSecurityPolicyEntry;

// /**
// STRUCT      :: vector<IPsecSecurityAssociationEntry*>
// DESCRIPTION :: Structure for Security Association list.
//                This is the container for storing the SAs
//                applied while a packet's inbound processing
//                at a particular node
// **/
typedef vector<IPsecSecurityAssociationEntry*>
        IPsecSecurityAssociationList;

// /**
// STRUCT      :: vector<IPsecSecurityAssociationEntry*>
// DESCRIPTION :: Structure for Security Associations Database
// **/
typedef vector<IPsecSecurityAssociationEntry*>
        IPsecSecurityAssociationDatabase;

// /**
// STRUCT      :: vector<IPsecSecurityPolicyEntry*>
// DESCRIPTION :: Structure for Security Policy Database
// **/
typedef vector<IPsecSecurityPolicyEntry*>
        IPsecSecurityPolicyDatabase;

// /**
// STRUCT      :: str_ipsec_security_policy_info
// DESCRIPTION :: Structure for Security Policy Information.
//                It is a wrapper structure for Security Policy Database
// **/
typedef struct str_ipsec_security_policy_info
{
    IPsecSecurityPolicyDatabase* spd;

    // Stat fields
    int pktProcessed; // No of IPSec processed packet
    int pktDropped;   // No of IPSec dropped packet
    int byteOverhead; // Bytes overhead due to IPSec processing
    clocktype delayOverhead;
    //synchronization parameter for encryption process
    clocktype encryptNextAvailTime;
}IPsecSecurityPolicyInformation;

// /**
// FUNCTION   :: IPsecInit
// LAYER      :: Network
// PURPOSE    :: Function to Initialize IPsec for a node
// PARAMETERS ::
// + node     :  Node* : The node initializing IPsec
// + nodeInput:  const NodeInput* : QualNet main configuration file
// RETURN     :: void : NULL
// **/
void IPsecInit(Node* node, const NodeInput* nodeInput);

// /**
// FUNCTION   :: IPsecHandleEvent
// LAYER      :: Network
// PURPOSE    :: Function to handle events for IPsec, required to simulate
//               delay.
// PARAMETERS ::
// + node     :  Node*    : The node processing the event
// + msg      :  Message* : Event that expired
// RETURN     :: void : NULL
// **/
void IPsecHandleEvent(Node* node, Message* msg);

// /**
// FUNCTION   :: IPsecFinalize()
// LAYER      :: Network
// PURPOSE    :: Finalize function for the IPSec model.
// PARAMETERS
// + node     :  Node * : Pointer to node.
// RETURN     :: void   : NULL
// **/
void IPsecFinalize(Node* node);

// /**
// API        :: IPsecHandleOutboundPacket
// LAYER      :: Network
// PURPOSE    :: Process IPsec option over outbound packet
// PARAMETERS ::
// + node      : Node*          : The node processing packet
// + msg       : Message*       : Packet pointer
// + incomingInterface  :  int  : incoming interface
// + outgoingInterface  :  int  : outgoing interface
// + nextHop            :  NodeAddress  : Next Hope Address
// + sp                 :  IPsecSecurityPolicyEntry* Security Policy Entry
// + useNextHopSAOnly   :  BOOL: if true use only those SA which has
//                               end-point equal to next-hop
// RETURN     :: BOOL   : TRUE if packet is processed, FALSE otherwise
// **/
BOOL IPsecHandleOutboundPacket(
    Node* node,
    Message* msg,
    int incomingInterface,
    int outgoingInterface,
    NodeAddress nextHop,
    IPsecSecurityPolicyEntry* sp,
    BOOL useNextHopSAOnly);


// /**
// API        :: IPsecHandleInboundPacket
// LAYER      :: Network
// PURPOSE    :: Process inblound packet
// PARAMETERS ::
// + node      : Node*     :  The node processing packet
// + msg       : Message*  :  Packet pointer
// + incomingInterface     :  int  : incoming interface
// + previousHopAddress    :  NodeAddress  : Previous hop
// RETURN     :: void : None
// **/
void IPsecHandleInboundPacket(
    Node* node,
    Message* msg,
    int incomingInterface,
    NodeAddress previousHopAddress);

// /**
// API        :: IsIPsecProcessed
// LAYER      :: Network
// PURPOSE    :: Function to check whether the packet has gone through IPsec
//               processing
// PARAMETERS ::
// + node     :  Node*    : Node processing packet
// + msg      :  Message* : The packet to check
// RETURN     :: BOOL : TRUE, if already processed by IPsec, FALSE otherwise
// **/
BOOL IsIPsecProcessed(Node* node, Message* msg);


// /**
// API        :: IPsecIsTransportMode
// LAYER      :: Network
// PURPOSE    :: To see if any transport mode SA exists on this interface
// PARAMETERS ::
// + node      : Node*    : The node processing packet
// + msg       : Message* : Packet pointer
// + outgoingInterface  :  int :  outgoing interface
// RETURN     :: bool : TRUE if packet has processed, FALSE otherwise
// **/
bool IPsecIsTransportMode(Node* node,
                          Message* msg,
                          int outgoingInterface);

// /**
// API        :: IPsecRequireProcessing
// LAYER      :: Network
// PURPOSE    :: Function to check whether the require IPsec processing
// PARAMETERS ::
// + node     :  Node*    : Node processing packet
// + msg      :  Message* : The packet to check
// + incomingInterface    : int : incoming interface ID
// RETURN     :: BOOL     : TRUE, if require IPsec processing, FALSE
//                          otherwise.
// **/
BOOL IPsecRequireProcessing(Node* node,
                            Message* msg,
                            int incomingInterface);

#ifdef TRANSPORT_AND_HAIPE
void IPsecReadHAIPE(Node* node,
                    const NodeInput* nodeInput,
                    int interfaceIndex);
#endif // TRANSPORT_AND_HAIPE

IPsecEncryptionAlgo IPsecGetEncryptionAlgo(char* encryptionAlgoStr);
IPsecSAMode IPsecGetMode(char* modeStr);
IPsecAuthAlgo IPsecGetAuthenticationAlgo(char* authAlgoStr);
IPsecProtocol IPsecGetSecurityProtocol(char* protocol);
const char* IPsecGetAuthenticationAlgoName(IPsecAuthAlgo  authAlgo);
const char* IPsecGetEncryptionAlgoName(IPsecEncryptionAlgo encryptionAlgo);
const char* IPsecGetSecurityProtocolName(IPsecProtocol ipsecProtocol);
const char* IPsecGetModeName(IPsecSAMode mode);

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
    IPsecProcessingRate* rateParams);

IPsecSecurityAssociationEntry* IPsecCreateNewSA(
    IPsecSAMode mode,
    NodeAddress dest,
    IPsecProtocol securityProtocol,
    unsigned int spi,
    IPsecAuthAlgo authAlgoName,
    char* authKey,
    IPsecEncryptionAlgo encryptAlgoName,
    char* encryptionKey,
    IPsecProcessingRate* rateParams,
    bool isCombinedAlgo = FALSE);

IPsecSecurityPolicyEntry* IPsecCreateNewSP(Node* node,
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
                                           IPsecProcessingRate* rateParams);
IPsecSecurityPolicyEntry* IPsecCreateNewSP(Node* node,
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
                                           IPsecProcessingRate* rateParams);

void IPsecSPDAddEntry(Node* node,
                      int interfaceIndex,
                      IPsecSecurityPolicyEntry* newSP);

void IPsecSADAddEntry(Node* node, IPsecSecurityAssociationEntry* newSA);

void IPsecSPDInit(IPsecSecurityPolicyInformation** spdInfo);

void IPsecSADInit(IPsecSecurityAssociationDatabase** sad);

// FUNCTION   :: IPsecIsMyIP
// LAYER      :: Network
// PURPOSE    :: Check if the given IP address is associated with this node
// PARAMETERS ::
// + node      : Node*          : Node pointer
// + addr      : NodeaAddtress  : Address to be checked
// RETURN     :: BOOL : TRUE, if this is my address, FALSE otherwise
// **/

BOOL IPsecIsMyIP(Node* node, NodeAddress addr);

// /**
// FUNCTION   :: IPsecRemoveMatchingSAfromSAD
// LAYER      :: Network
// PURPOSE    :: Remove security association from SA database
// PARAMETERS ::
// + node      : Node*         : The node processing packet
// + protocol  : int*          : IP header protocol
// + dest      : NodeAddress   : IP destination address (outer header)
// + spi       : unsigned int  : Security protocol index
// RETURN     :: void
// **/

IPsecSecurityAssociationEntry* IPsecRemoveMatchingSAfromSAD(
    Node* node,
    IPsecProtocol protocol,
    NodeAddress dest,
    unsigned int spi);

// /**
// FUNCTION   :: IPsecRemoveSAfromSP
// LAYER      :: Network
// PURPOSE    ::
// PARAMETERS ::
// RETURN     :: void
// **/

void IPsecRemoveSAfromSP(
    IPsecSecurityPolicyEntry* sp,
    IPsecSecurityAssociationEntry* sa);

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
    IPsecSecurityPolicyDatabase* spd);

// FUNCTION   :: IPsecGetMatchingSP
// LAYER      :: Network
// PURPOSE    :: Get policy entry
// PARAMETERS ::
// RETURN     :: IPsecSecurityPolicyEntry* : matching SP, NULL if no match
//               found

IPsecSecurityPolicyEntry* IPsecGetMatchingSP(
    Address localNetwork,
    Address RemoteNetwork,
    int  upperProtocol,
    IPsecSecurityPolicyDatabase* spd);


// FUNCTION   :: IPsecGetProtocolNumber
// LAYER      :: Network
// PURPOSE    :: Function to return IP protocol number for upper layer
//               protocol string
// PARAMETERS ::
// + protocol  : char* : Upper layer protocol string
// RETURN     :: int   : IP protocol number

int IPsecGetProtocolNumber(char* protocol);

// /**
// FUNCTION    :: IPsecHexToChar
// LAYER       :: Network
// PURPOSE     :: Function to convert hexadecimal string to char string
// PARAMETERS  ::
// + hexString : char*  : Input Hex string
// + length    : int*   : Length of the returned char string
// RETURN      :: char* : NULL
// **/
char* IPsecHexToChar(char* hexString, int* length);

// /**
// FUNCTION    :: IPsecHexToInt
// LAYER       :: Network
// PURPOSE     :: Helper Function to convert hex digit to integer
// PARAMETERS  ::
// + hex       : char : Hex number/digit to be converted into integer
// RETURN      :: int : Integer equiavlent of input hex number
// **/
int IPsecHexToInt(char hex);

// /**
// FUNCTION   :: IPsecGetMatchingSPForSAEndPoint
// LAYER      :: Network
// PURPOSE    :: Get policy entry that matches packets selector fields and
//               has atleast one SA which has given end point address
// PARAMETERS ::
// + msg            : Message* : Packet pointer
// + spd            : IPsecSecurityPolicyDatabase* : Security Policy
//                    Database
// + endPointAddress: NodeAddress : SA end-point address.
// RETURN     :: IPsecSecurityPolicyEntry* : matching SP, NULL if no match
//               found
// **/
IPsecSecurityPolicyEntry* IPsecGetMatchingSPForSAEndPoint(
    Message* msg,
    IPsecSecurityPolicyDatabase* spd,
    NodeAddress endPointAddress);

// /**
// STRUCT      :: IPsecSelectorAddrListEntry
// DESCRIPTION :: Helper Structure for Security Association Entry and its
//                selectors' mapping
// **/
struct IPsecSelectorAddrListEntry
{
    IPsecSAMode mode;                           // Tunnel or Transport
    NodeAddress src;                            // Start point
    NodeAddress dest;                           // End point
    IPsecProtocol securityProtocol;
    IPsecSecurityAssociationEntry* saEntry;
};

// /**
// STRUCT      :: vector<struct IPsecSelectorAddrListEntry*>
// DESCRIPTION :: Structure for Security Associations map
// **/
typedef vector<struct IPsecSelectorAddrListEntry*> IPsecSelectorAddrList;

// /**
// FUNCTION   :: IPsecUpdateSApointerInSPD
// LAYER      :: Network
// PURPOSE    :: Updating SA pointers in Security Policy Database
// PARAMETERS ::
// + node             : Node*                   : The node updating pointers
// + addressMap       : IPsecSelectorAddrMap    : SA addressMap
// + spdToBeUpdated   : IPsecSecurityPolicyDatabase* : SPD to be updated
// RETURN     :: void : NULL
// **/
void IPsecUpdateSApointerInSPD(Node* node,
        IPsecSelectorAddrList addressList,
        IPsecSecurityPolicyDatabase* spdToBeUpdated);

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
    int indexOfSAFilter);

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
    int indexOfSAFilter);

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
    UInt16* ipFragment);

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
    UInt16 ipFragment);

// /**
// FUNCTION   :: IPSecDuplicateSAFilters
// LAYER      :: Network
// PURPOSE    :: Checking whether two SPs have same SA filters or not
// PARAMETERS ::
// + newSAFilter  : vector<IPsecSAFilter*>
//                : SA filters of the SP to be added
// + previousSAFilter  : vector<IPsecSAFilter*>
//                     : SA filters of SP present already in sender
//                       interface's SPD
// RETURN     :: BOOL  : TRUE if duplicate else FALSE
// **/
BOOL IPSecDuplicateSAFilters(
    vector<IPsecSAFilter*> newSAFilter,
    vector<IPsecSAFilter*> previousSAFilter);

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
string IPsecPreProcessInputLine(string preprocessedInputLine);

// /**
// FUNCTION   :: IPsecGetProtocolModeSrcDestLevel
// LAYER      :: Network
// PURPOSE    :: Function to read security protcol configured in the IPsec
//               configuration file
// PARAMETERS ::
// + node       : Node* : The node trying to read its security policy
// + protocolModeString : char* : The string to be parsed for protocol,
//                        level,mode,first endpoint and second endpoint
// + protocol   : char* : protocol for which SP is to be configured
// + mode       : char* : protocol for which SP is to be configured
// + firstEndpoint   : NodeAddress* : one of the end points for which SP is
//                                    to be configured
// + secondEndpoint  : NodeAddress* : second end point for which SP is to
//                                    be configured
// + level      : char* : level for which SP is to be configured
// RETURN     :: void   : NULL
// **/
void IPsecGetProtocolModeSrcDestLevel(Node* node,
                                      string modeString,
                                      char* protocol,
                                      char* mode,
                                      NodeAddress* firstEndpoint,
                                      NodeAddress* secondEndpoint,
                                      char* level);

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
                                     int* numberOfProtocolModeStrings);

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
                        IPsecSecurityAssociationEntry* secondSA);

// /**
// FUNCTION   :: IPsecIsDuplicateSA
// LAYER      :: Network
// PURPOSE    :: Checking whether security association to be added
//               to SAD is duplicate or not
// PARAMETERS ::
// + node      : Node*                           : The  node adding entry
// + newSA     : IPsecSecurityAssociationEntry*  : New security
//               association
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/
BOOL IPsecIsDuplicateSA(
     Node* node,
     IPsecSecurityAssociationEntry* newSA);

// /**
// FUNCTION   :: IPsecIsDuplicateSP
// LAYER      :: Network
// PURPOSE    :: Checking whether security policy to be added
//               to SPD is duplicate or not
// PARAMETERS ::
// + node             : Node*                      : The  node adding entry
// + interfaceIndex   : int                        : Interface Index
// + newSP            : IPsecSecurityPolicyEntry*  : New security policy
// RETURN     :: BOOL : TRUE if duplicate else FALSE
// **/
BOOL IPsecIsDuplicateSP(
     Node* node,
     int interfaceIndex,
     IPsecSecurityPolicyEntry* newSP);

// /**
// FUNCTION   :: IPsecValidateNodeID
// PURPOSE    :: Check if a string is a permissible Node id in SA/SP entry
//               or not
// PARAMETERS ::
// + nodeIDString     : char - address to determine if it is
//                      a valid Node id in SA entry or not
// RETURN     :: BOOL : TRUE if valid otherwise FALSE
// **/
BOOL IPsecValidateNodeID(char nodeIDString[]);

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
                            IPsecSACaseNumber caseNumber);

// /**
// FUNCTION    :: IPsecProcessSPKeywords
// LAYER       :: Network
// PURPOSE     :: Function to validate occurences of keywords in SP
// PARAMETERS  ::
// + keywords  : char** keywords : Array of tokens to be validated
// + caseNumber: IPsecSPCaseNumber : To determine which combination
//               of keywords is expected
// RETURN      :: void : NULL
// **/
void IPsecProcessSPKeywords(char** keywords,
                            IPsecSPCaseNumber caseNumber);

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
                  IPsecSecurityPolicyInformation* spdInfo);

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
string IPsecRemoveLeadingSpaces(string inputString);

#endif //IPSEC_H
