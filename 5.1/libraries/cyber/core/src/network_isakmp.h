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

//
// PROTOCOL :: ISAKMP

// MAJOR REFERENCES ::
// + RFC 2408
// + RFC 2409
// + RFC 2407
// MINOR REFERENCES ::
// + RFC 2401
// + RFC 2412

// COMMENTS   :: None

// SUMMARY ::
//  The Internet Security Association and Key Management Protocol
//  (ISAKMP) defines procedures and packet formats to establish,
//  negotiate, modify and delete Security Associations (SA). SAs contain
//  all the information required for execution of various network
//  security services, such as the IP layer services (such as header
//  authentication and payload encapsulation), transport or application
//  layer services, or self-protection of negotiation traffic.

//  The Internet Key Exchange (IKE) Protocol, is a hybrid protocol to obtain
//  authenticated keying material for use with ISAKMP, and for other
//  security associations such as AH and ESP for the IPsec DOI.

// LAYER ::  Network Layer

// STATISTICS ::
// + numOfBaseExch          Number of Base Exchange Performed.
// + numOfIdProtExch        Number of Identity Protection Exchange Performed.
// + numOfAuthOnlyExch      Number of Authentication Only Exchange Performed.
// + numOfAggresExch        Number of Aggressive Exchange Performed.
// + numOfIkeMainPreSharedExch     Number of IKE Main Pre-Shared Key Exchange
//                                 Performed.
// + numOfIkeMainDigSigExch        Number of IKE Main Digital Signature
//                                 Exchange Performed.
// + numOfIkeMainPubKeyExch        Number of IKE Main Public Key Exchange
//                                 Performed.
// + numOfIkeMainRevPubKeyExch     Number of IKE Main Revised Public Key
//                                 Exchange Performed.
// + numOfIkeAggresPreSharedExch   Number of IKE Aggressive Pre-Shared Key
//                                 Exchange Performed.
// + numOfIkeAggresDigSigExch      Number of IKE Aggressive Digital Signature
//                                 Exchange Performed.
// + numOfIkeAggresPubKeyExch      Number of IKE Aggressive Public Key
//                                 Exchange Performed.
// + numOfIkeAggresRevPubKeyExch   Number of IKE Aggressive Revised Public
//                                 Key Exchange Performed.
// + numOfIkeQuickExch      Number of IKE Quick Exchange Performed.
// + numOfIkeNewGroupExch   Number of IKE New Group Exchange Performed.
// + numOfInformExchSend    Number of Informational Exchange Send.
// + numOfInformExchRcv     Number of Informational Exchange Received.
// + numOfExchDropped       Number of Exchange Dropped.
// + numPayloadSASend       Number of SA Payload Message Send.
// + numPayloadSARcv        Number of SA Payload Message Received.
// + numPayloadNonceSend    Number of Nonce Payload Message Send.
// + numPayloadNonceRcv     Number of Nonce Payload Message Received.
// + numPayloadKeyExSend    Number of Key Exchange Payload Message Send.
// + numPayloadKeyExRcv     Number of Key Exchange Payload Message Received.
// + numPayloadIdSend       Number of ID Payload Message Send.
// + numPayloadIdRcv        Number of ID Payload Message Received.
// + numPayloadAuthSend     Number of Auth Payload Message Send.
// + numPayloadAuthRcv      Number of Auth Payload Message Received.
// + numPayloadHashSend     Number of Hash Payload Send.
// + numPayloadHashRcv      Number of Hash Payload Received.
// + numPayloadCertSend     Number of Certificate Payload Send.
// + numPayloadCertRcv      Number of Certificate Payload Received.
// + numPayloadNotifySend   Number of Notify Payload Message Send.
// + numPayloadNotifyRcv    Number of Notify Payload Message Received.
// + numPayloadDeleteSend   Number of Delete Payload Message Send.
// + numPayloadDeleteRcv    Number of Delete Payload Message Received.
// + numOfRetransmissions   Number of Message Retransmitted.
// + numOfReestablishments  Number of Phase2 Reestablishments Performed.

// APP_PARAM ::

// CONFIG_PARAM ::
// + ISAKMP-SERVER YES/NO to enable a node with ISAKMP
// + ISAKMP-CONFIG-FILE  *.isakmp
// + ISAKMP-PHASE-1-START-TIME phase-1 start time for initiator
// + ISAKMP-ENABLE-IPSEC YES/NO to enable ipsec on this node with isakmp

// VALIDATION ::$QUALNET_HOME/scenarios/network_security/isakmp.

// IMPLEMENTED_FEATURES ::
//  1. Payload and other header formats defined in RFC 2408 and RFC 2409.
//  2. Exchange types defined in section 4.4 to 4.8 of RFC 2408.
//  3. Exchange types defined in section 5.1 to 5.7 of RFC 2409.
//  4. Processing of all payloads except certificate request,
//     hash,and delete payloads defined in section 5 of RFC 2408.

// OMITTED_FEATURES ::
//  1.As Encryption, Decryption and Authentication is not required for
//    simulation, implementation for payloads such as, certificate,
//    certificate request and hash payloads are omitted.
//  2.Re-establishment of Phase-1 SA.
//  3.Implementation of Security Policy SIT_SECRECY and SIT_INTEGRITY type.
//  4.Multiple SA negotiation in a single Exchange is not supported.
//..5.Cryptography related to OAKLEY in RFC 2409.

// ASSUMPTIONS ::
//1.ISAKMP is implemented as a deamon process. Phase 1 is Started after the
//  initialization phase with user specified delay and phase 2 is started
//  after phase 1 is completed.
//2.IKE New Group mode is considered as a part of phase 1 only. After the
//  ISAKMP SA establishment, New Group mode (if enabled) will started as
//  Next Phase for phase 1.
//3.If certificate type exists, then certificate data payload is assumed
//  to be size 1024 which will send as virtual payload in message.
//4.In public key exchange, it is assumed that the initiator is already
//  having the responder’s public key. Similar assumption is applied for
//  pre-shared key.
//5.It is also possible to start phase 2 when some data packet comes at
//  ISAKMP server and it does't found any IPSec SA for that packet's source
//  and destination networks.
//6.Algorithms for creating cookies, generating keys and nonce is been
//  simulated by some simple stub functions.
//7.Established SAs are Bi-directional, that is same SA is used for both
//  inbound and outbound packets.
//8.Only one proposal is been sent during phase-1 establishment, however
//  multiple transform can be sent in a single proposal.

// STANDARD :: Coding standard follows the following Coding Guidelines
//             1. SNT C Coding Guidelines for QualNet 3.2


#ifndef ISAKMP_H
#define ISAKMP_H

//
// CONSTANT    :: INITIATOR , RESPONDER
// DESCRIPTION :: initiator or responder in a exchange
//
#define INITIATOR       0
#define RESPONDER       1

//
// CONSTANT    :: ISAKMP_SAVE_PHASE1 , ISAKMP_SAVE_PHASE2
// DESCRIPTION :: Macros to Save Phase1 and Phase2 SA in file.
//
//#define ISAKMP_SAVE_PHASE1
#define ISAKMP_SAVE_PHASE2

//
// CONSTANT    :: PHASE_1 , PHASE_2
// DESCRIPTION :: negotiation phase.
//
#define PHASE_1            1
#define PHASE_2            2

//
// CONSTANT    :: ISAKMP_PHASE1_START_TIME
// DESCRIPTION :: default phase 1 start time for the initiator.
//
#define ISAKMP_PHASE1_START_TIME   30 * SECOND

//
// CONSTANT    :: COOKIE_SIZE
// DESCRIPTION :: size of the cookie.
//
#define COOKIE_SIZE        8

//
// CONSTANT    :: MAX_TRANSFORMS
// DESCRIPTION :: max no of phase1 or phase2 transform supported
//
#define MAX_TRANSFORMS    10

//
// CONSTANT    :: DEFAULT_PHASE1_TRANSFORM_LIFETIME
// DESCRIPTION :: default phase 1 transform life time in minutes
//
#define DEFAULT_PHASE1_TRANSFORM_LIFETIME    60

//
// CONSTANT    :: DEFAULT_PHASE2_TRANSFORM_LIFETIME
// DESCRIPTION :: default phase 2 transform life time in minutes
//
#define DEFAULT_PHASE2_TRANSFORM_LIFETIME    10

//
// CONSTANT    :: KEY_SIZE
// DESCRIPTION :: size of the key assumed.
//
#define KEY_SIZE    8

//
// CONSTANT    :: NONCE_SIZE
// DESCRIPTION :: size of the nonce assumed.
//
#define NONCE_SIZE    4


//
// CONSTANT    :: CERT_PAYLOAD_SIZE
// DESCRIPTION :: size of the certificate payload assumed.
//
#define CERT_PAYLOAD_SIZE    1024



//
// CONSTANT    :: DEFAULT_ENCRYP_ALGO
// DESCRIPTION :: Default Encryption Algorithm.
//
#define DEFAULT_ENCRYP_ALGO         IPSEC_DES_CBC

//
// CONSTANT    :: DEFAULT_AUTH_ALGO
// DESCRIPTION :: Default Authentication Algorithm.
//
#define DEFAULT_AUTH_ALGO           IPSEC_HMAC_MD5

//
// CONSTANT    :: DEFAULT_HASH_ALGO
// DESCRIPTION :: Default hash Algorithm.
//
#undef DEFAULT_HASH_ALGO
#define DEFAULT_HASH_ALGO           IPSEC_HASH_MD5

//
// CONSTANT    :: DEFAULT_AUTH_METHOD
// DESCRIPTION :: Default Authentication Method.
//
#define DEFAULT_AUTH_METHOD         PRE_SHARED

//
// CONSTANT    :: DEFAULT_GROUP_DESCRIPTION
// DESCRIPTION :: Default Group Description.
//
#define DEFAULT_GROUP_DESCRIPTION   MODP_1024


//
// CONSTANT    :: DEFAULT_CERT_ENABLED
// DESCRIPTION :: Default Certificate Enabled State.
//
#define DEFAULT_CERT_ENABLED   FALSE

//
// CONSTANT    :: DEFAULT_NEW_GROUP_ENABLED
// DESCRIPTION :: Default IKE New Group Enabled State.
//
#define DEFAULT_NEW_GROUP_ENABLED   FALSE

//
// CONSTANT    :: DEFAULT_PROCESSING_DELAY
// DESCRIPTION :: Default Processing Delay (per KB data) for applying
//                cryptography
//
#define DEFAULT_PROCESSING_DELAY   (10 * MICRO_SECOND)



// Situation Identifiers
// RFC 2408, 2407
#define IPSEC_SIT_IDENTITY_ONLY           0x00000001
#define IPSEC_SIT_SECRECY                 0x00000002
#define IPSEC_SIT_INTEGRITY               0x00000004

// IPSEC Security Protocol Identifiers
// RFC 2407 4.4.1
#define IPSECDOI_PROTO_ISAKMP                   1
#define IPSECDOI_PROTO_IPSEC_AH                 2
#define IPSECDOI_PROTO_IPSEC_ESP                3

//IPSEC ISAKMP Transform identifier
//RFC 2407 4.4.2
#define   IPSEC_KEY_IKE                           1

//IPSEC AH Transform Identifiers
//RFC 2407 4.4.3
#define IPSEC_AH_MD5                              2
#define IPSEC_AH_SHA                              3
#define IPSEC_AH_DES                              4

 //IPSEC ESP Transform Identifiers
//RFC 2407 4.4.4
#define IPSEC_ESP_DES_IV64                        1
#define IPSEC_ESP_DES                             2
#define IPSEC_ESP_3DES                            3
#define IPSEC_ESP_RC5                             4
#define IPSEC_ESP_IDEA                            5
#define IPSEC_ESP_CAST                            6
#define IPSEC_ESP_BLOWFISH                        7
#define IPSEC_ESP_3IDEA                           8
#define IPSEC_ESP_DES_IV32                        9
#define IPSEC_ESP_RC4                            10
#define IPSEC_ESP_NULL                           11

// Next Payload Type
//RFC 2408 3.4 to 3.16
#define ISAKMP_NPTYPE_NONE   0      // NONE
#define ISAKMP_NPTYPE_SA     1      // Security Association
#define ISAKMP_NPTYPE_P      2      // Proposal
#define ISAKMP_NPTYPE_T      3      // Transform
#define ISAKMP_NPTYPE_KE     4      // Key Exchange
#define ISAKMP_NPTYPE_ID     5      // Identification
#define ISAKMP_NPTYPE_CERT   6      // Certificate
#define ISAKMP_NPTYPE_CR     7      // Certificate Request
#define ISAKMP_NPTYPE_HASH   8      // Hash
#define ISAKMP_NPTYPE_SIG    9      // Signature
#define ISAKMP_NPTYPE_NONCE 10      // Nonce
#define ISAKMP_NPTYPE_N     11      // Notification
#define ISAKMP_NPTYPE_D     12      // Delete
#define ISAKMP_NPTYPE_VID   13      // Vendor ID

// ISAKMP PROTOCOL VERSION
//RFC 2408 3.1
#define ISAKMP_MAJOR_VERSION  1
#define ISAKMP_MINOR_VERSION  0

// Exchange Types
// RFC 2408 4.4 to 4.8
#define ISAKMP_ETYPE_NONE   0       // NONE
#define ISAKMP_ETYPE_BASE   1       // Base
#define ISAKMP_ETYPE_IDENT  2       // Identity Proteciton
#define ISAKMP_ETYPE_AUTH   3       // Authentication Only
#define ISAKMP_ETYPE_AGG    4       // Aggressive
#define ISAKMP_ETYPE_INF    5        // Informational

// For IKE: RFC 2409 5.1 to 5.6
//For Main mode
#define ISAKMP_IKE_ETYPE_MAIN_PRE_SHARED    6 //Pre shared Key
#define ISAKMP_IKE_ETYPE_MAIN_DIG_SIG       7 //Digital Signature
#define ISAKMP_IKE_ETYPE_MAIN_PUB_KEY       8 //Public Key Encryption
#define ISAKMP_IKE_ETYPE_MAIN_REV_PUB_KEY   9 //Revised Public Key Encryption

//For Aggressive mode
#define ISAKMP_IKE_ETYPE_AGG_PRE_SHARED    10 //Pre shared Key
#define ISAKMP_IKE_ETYPE_AGG_DIG_SIG       11 //Digital Signature
#define ISAKMP_IKE_ETYPE_AGG_PUB_KEY       12 //Public Key Encryption
#define ISAKMP_IKE_ETYPE_AGG_REV_PUB_KEY   13 //Revised Public Key Encryption

//For New Group Mode
#define ISAKMP_IKE_ETYPE_NEW_GROUP         33    // New Group Mode

//For phase 2 IKE exchanges
#define ISAKMP_IKE_ETYPE_QUICK             32    // Quick mode


// Flags
// RFC 2408 3.1
#define ISAKMP_FLAG_E       0x01       // Encryption Bit
#define ISAKMP_FLAG_C       0x02       // Commit Bit
#define ISAKMP_FLAG_A       0x04       // Auth only Bit
#define ISAKMP_FLAG_NONE    0x00       // No Flag
#define ISAKMP_FLAG_INVALID 0xf8       //Invalid flag

// Notify Message Types - ERROR TYPES
// RFC 2408 3.14.1
#define ISAKMP_NTYPE_INVALID_PAYLOAD_TYPE           1
#define ISAKMP_NTYPE_DOI_NOT_SUPPORTED              2
#define ISAKMP_NTYPE_SITUATION_NOT_SUPPORTED        3
#define ISAKMP_NTYPE_INVALID_COOKIE                 4
#define ISAKMP_NTYPE_INVALID_MAJOR_VERSION          5
#define ISAKMP_NTYPE_INVALID_MINOR_VERSION          6
#define ISAKMP_NTYPE_INVALID_EXCHANGE_TYPE          7
#define ISAKMP_NTYPE_INVALID_FLAGS                  8
#define ISAKMP_NTYPE_INVALID_MESSAGE_ID             9
#define ISAKMP_NTYPE_INVALID_PROTOCOL_ID            10
#define ISAKMP_NTYPE_INVALID_SPI                    11
#define ISAKMP_NTYPE_INVALID_TRANSFORM_ID           12
#define ISAKMP_NTYPE_ATTRIBUTES_NOT_SUPPORTED       13
#define ISAKMP_NTYPE_NO_PROPOSAL_CHOSEN             14
#define ISAKMP_NTYPE_BAD_PROPOSAL_SYNTAX            15
#define ISAKMP_NTYPE_PAYLOAD_MALFORMED              16
#define ISAKMP_NTYPE_INVALID_KEY_INFORMATION        17
#define ISAKMP_NTYPE_INVALID_ID_INFORMATION         18
#define ISAKMP_NTYPE_INVALID_CERT_ENCODING          19
#define ISAKMP_NTYPE_INVALID_CERTIFICATE            20
#define ISAKMP_NTYPE_BAD_CERT_REQUEST_SYNTAX        21
#define ISAKMP_NTYPE_INVALID_CERT_AUTHORITY         22
#define ISAKMP_NTYPE_INVALID_HASH_INFORMATION       23
#define ISAKMP_NTYPE_AUTHENTICATION_FAILED          24
#define ISAKMP_NTYPE_INVALID_SIGNATURE              25
#define ISAKMP_NTYPE_ADDRESS_NOTIFICATION           26
#define ISAKMP_NTYPE_UNEQUAL_PAYLOAD_LENGTHS        27
#define ISAKMP_NTYPE_INVALID_RESERVED_FIELD         28

// NOTIFY MESSAGES - STATUS TYPES
// RFC 2408 3.14.1
#define ISAKMP_NTYPE_CONNECTED                   16384
#define ISAKMP_DROP_EXchange                     100
#define ISAKMP_DROP_Message                      101

// Phase 1 transform attributes
// RFC 2409 Appendix A
#define    AF_BIT                  0x8000
#define    SA_LIFE_PH1             0x8001
#define    SA_LIFE_DURATION_PH1    0x0002
#define    ENCRYP_ALGO_PH1         0x8003
#define    HASH_ALGO_PH1           0x8004
#define    AUTH_MEHTOD_PH1         0x8005
#define    GRP_DESC_PH1            0x8006
#define    CERT_TYPE_PH1           0x8007


// Phase 2 transform attributes
// RFC 2407 4.5
#define    SA_LIFE_PH2             0x8001
#define    SA_LIFE_DURATION_PH2    0x0002
#define    GRP_DESC_PH2            0x8003
#define    ENC_MODE_PH2            0x8004
#define    AUTH_ALGO_PH2           0x8005
#define    KEY_LEN_PH2             0x8006
#define    KEY_ROUND_PH2           0x8007

// macros defined for various payload size and header
#define SIZE_ISAKMP_HEADER        sizeof(ISAKMPHeader)
#define SIZE_DATA_ATTRIBUTE       sizeof(ISAKMPDataAttr)
#define SIZE_SA_Payload           sizeof(ISAKMPPaylSA)
#define SIZE_PROPOSAL_Payload     sizeof(ISAKMPPaylProp)
#define SIZE_TRANSFORM_Payload    sizeof(ISAKMPPaylTrans)
#define SIZE_KE_Payload           sizeof(ISAKMPPaylKeyEx)
#define SIZE_NONCE_Payload        sizeof(ISAKMPPaylNonce)
#define SIZE_ID_Payload           sizeof(ISAKMPPaylId)
#define SIZE_SIG_Payload          sizeof(ISAKMPPaylSig)
#define SIZE_HASH_Payload         sizeof(ISAKMPPaylHash)
#define SIZE_CERT_Payload         sizeof(ISAKMPPaylCert)
#define SIZE_CERTREQ_Payload      sizeof(ISAKMPPaylCertReq)
#define SIZE_NOTIFY_Payload       sizeof(ISAKMPPaylNotif)
#define SIZE_DELETE_Payload       sizeof(ISAKMPPaylDel)
#define SIZE_SPI                  4

//Identification Type
// RFC 2407 4.6.2.1
#define   ISAKMP_ID_IPV4_ADDR         1
#define   ISAKMP_ID_FQDN              2     //not supported
#define   ISAKMP_ID_USER_FQDN         3     //not supported
#define   ISAKMP_ID_IPV4_ADDR_SUBNET  4
#define   ISAKMP_ID_IPV6_ADDR         5     //not supported
#define   ISAKMP_ID_IPV6_ADDR_SUBNET  6     //not supported
#define   ISAKMP_ID_IPV4_ADDR_RANGE   7     //not supported
#define   ISAKMP_ID_IPV6_ADDR_RANGE   8     //not supported
#define   ISAKMP_ID_DER_ASN1_DN       9     //not supported
#define   ISAKMP_ID_DER_ASN1_GN       10    //not supported
#define   ISAKMP_ID_KEY_ID            11    //not supported
#define   ISAKMP_ID_INVALID           12



// RFC 2408 3.9
// ENUM         :: ISAKMPCertType
// DESCRIPTION  :: ISAKMP Certification Type
typedef enum
{
    ISAKMP_CERT_NONE = 0,
    ISAKMP_CERT_PKCS7,
    ISAKMP_CERT_PGP,
    ISAKMP_CERT_DNS_SIGNED,
    ISAKMP_CERT_X509_SIG,
    ISAKMP_CERT_X509_KEYEX,
    ISAKMP_CERT_KERBEROS,
    ISAKMP_CERT_CRL,
    ISAKMP_CERT_ARL,
    ISAKMP_CERT_SPKI,
    ISAKMP_CERT_X509_ATTRI
} ISAKMPCertType;


// ENUM         :: ISAKMPHashAlgo
// DESCRIPTION  :: ISAKMP Hash Algorithm
typedef enum
{
    IPSEC_HASH_MD5 = 1,
    IPSEC_HASH_SHA,
    IPSEC_HASH_TIGER
} ISAKMPHashAlgo;

// ENUM         :: ISAKMPAuthMethod
// DESCRIPTION  :: ISAKMP Authentication Mehod e.g using Certificates
//                 ,Pre-shared key etc.
// RFC 2409 [IKE] Appendix A
typedef enum
{
    PRE_SHARED = 1,         // Pre shared key
    DSS_SIG,                // DSS signatures
    RSA_SIG,                // RSA signatures
    RSA_ENCRYPT,            // Encryption with RSA
    REVISED_RSA_ENCRYPT     // Revised encryption with RSA
} ISAKMPAuthMethod;

// ENUM         :: ISAKMPGrpDesc
// DESCRIPTION  :: ISAKMP Group Description , Defiened in Appendix A of [IKE]
typedef enum
{
    MODP_768 = 1,
    MODP_1024,
    EC2N_155,
    EC2N_185
} ISAKMPGrpDesc;

// ENUM         :: DOI
// DESCRIPTION  :: Domain of Interpretation
typedef enum
{
    ISAKMP_DOI = 0,
    IPSEC_DOI,
    INVALID_DOI
} DOI;

// STRUCT       :: ISAKMPHeader
// DESCRIPTION  ::
//RFC 2408 3.1 ISAKMP Header Format
//         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !                          Initiator                            !
//        !                            Cookie                             !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !                          Responder                            !
//        !                            Cookie                             !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !  Next Payload ! MjVer ! MnVer ! Exchange Type !     Flags     !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !                          Message ID                           !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !                            Length                             !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct isakmp_header
{
    char init_cookie[COOKIE_SIZE];      // Initiator Cookie
    char resp_cookie[COOKIE_SIZE];      // Responder Cookie
    unsigned char np_type;              // Next Payload Type
    unsigned char vers;
    unsigned char exch_type;            // Exchange Type
    unsigned char flags;                // Flags
    UInt32 msgid;
    UInt32 len;                         // Length
}ISAKMPHeader;

// STRUCT         :: ISAKMPGenericHeader
// DESCRIPTION  ::
 //3.2 Payload Generic Header
 //        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 //       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 //       ! Next Payload  !   RESERVED    !         Payload Length        !
 //       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

typedef struct isakmp_gen
{
    unsigned char  np_type;     // Next Payload
    unsigned char  reserved;    // RESERVED, unused, must set to 0
    UInt16 len;                 // Payload Length
}ISAKMPGenericHeader;

// STRUCT         :: ISAKMPDataAttr
// DESCRIPTION  ::
// RFC 2408 3.3 Data Attributes
//         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        !A!       Attribute Type        !    AF=0  Attribute Length     !
//        !F!                             !    AF=1  Attribute Value      !
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//        .                   AF=0  Attribute Value                       .
//        .                   AF=1  Not Transmitted                       .
//        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
typedef struct isakmp_data_attr
{
    UInt16 type;     // defined by DOI-spec, and Attribute Format
    UInt16 lorv;     // if f equal 1, Attribute Length
                      // if f equal 0, Attribute Value
    // if f equal 1, Attribute Value
}ISAKMPDataAttr;

// STRUCT         :: ISAKMPPaylSA
// DESCRIPTION    :: RFC 2408 3.4 Security Association Payload
typedef struct isakmp_pl_sa
{
    ISAKMPGenericHeader h;
    UInt32 doi; // Domain of Interpretation
    UInt32 sit; // Situation
}ISAKMPPaylSA ;

// STRUCT         :: ISAKMPPaylProp
// DESCRIPTION    :: RFC 2408 3.5 Proposal Payload
typedef struct isakmp_pl_p
{
    ISAKMPGenericHeader h;
    unsigned char p_no;      // Proposal #
    unsigned char prot_id;   // Protocol
    unsigned char spi_size;  // SPI Size
    unsigned char num_t;     // Number of Transforms
    // SPI
}ISAKMPPaylProp;

// STRUCT         :: ISAKMPPaylTrans
// DESCRIPTION    :: RFC 2408 3.6 Transform Payload
typedef struct isakmp_pl_t {
    ISAKMPGenericHeader h;
    unsigned char  t_no;     // Transform #
    unsigned char  t_id;     // Transform-Id
    UInt16 reserved; // RESERVED2
    // SA Attributes
}ISAKMPPaylTrans;

// STRUCT         :: ISAKMPPaylKeyEx
// DESCRIPTION    :: RFC 2408 3.7 Key Exchange Payload
typedef struct isakmp_pl_ke {
    ISAKMPGenericHeader h;
    // Key Exchange Data
}ISAKMPPaylKeyEx;

// STRUCT         :: ISAKMPPaylId
// DESCRIPTION    :: RFC 2408 3.8 Identification Payload
typedef struct isakmp_pl_id {
    ISAKMPGenericHeader h;
    union
    {
        unsigned char  id_type;   // ID Type
        // DOI Specific ID Data
        UInt32 doi_data;
        struct
        {
            unsigned char  id_type;   // ID Type
            // IPSEC DOI RFC 2407 4.6.2
            unsigned char  protocol_id;   // protocol ID TCP/UDP
            UInt16         port_no;       // port no., Not Supported
        }ipsec_doi_data;
    } id_data;
    // Identification Data
}ISAKMPPaylId;

// STRUCT         :: ISAKMPPaylCert
// DESCRIPTION    :: RFC 2408 3.9 Certificate Payload
typedef struct isakmp_pl_cert {
    ISAKMPGenericHeader h;
    unsigned char encode; // Cert Encoding
        // Certificate Data
}ISAKMPPaylCert;


// STRUCT         :: ISAKMPPaylCertReq
// DESCRIPTION    :: RFC 2408 3.10 Certificate Request Payload
// NOTE           :: Not supported
typedef struct isakmp_pl_cr {
     ISAKMPGenericHeader h;
    unsigned char num_cert; //# Cert. Types
    //
    //Certificate Types (variable length)
    //  -- Contains a list of the types of certificates requested,
    //  sorted in order of preference.  Each individual certificate
    //  type is 1 octet.  This field is NOT requiredo
    //
    // # Certificate Authorities (1 octet)
    // Certificate Authorities (variable length)
}ISAKMPPaylCertReq;

// STRUCT         :: ISAKMPPaylHash
// DESCRIPTION    :: RFC 2408 3.11 Hash Payload
typedef struct isakmp_pl_hash{
    ISAKMPGenericHeader h;
    // Hash Data
}ISAKMPPaylHash ;

// STRUCT         :: ISAKMPPaylSig
// DESCRIPTION    :: RFC 2408 3.12 Signature Payload
typedef struct isakmp_pl_sig {
    ISAKMPGenericHeader h;
    // Signature Data
}ISAKMPPaylSig;

// STRUCT         :: ISAKMPPaylNonce
// DESCRIPTION    :: RFC 2408 3.13 Nonce Payload
typedef struct isakmp_pl_nonce {
    ISAKMPGenericHeader h;
    // Nonce Data
}ISAKMPPaylNonce;

// STRUCT         :: ISAKMPPaylNotif
// DESCRIPTION    :: RFC 2408, 3.14 Notification Payload
typedef struct isakmp_pl_n {
    ISAKMPGenericHeader h;
    UInt32 doi;      // Domain of Interpretation
    unsigned char  prot_id;  // Protocol-ID
    unsigned char  spi_size; // SPI Size
    UInt16 type;     // Notify Message Type
    // SPI
    // Notification Data
}ISAKMPPaylNotif;


// STRUCT         :: ISAKMPPaylDel
// DESCRIPTION    :: RFC 2408, 3.15 Delete Payload
typedef struct isakmp_pl_d
{
    ISAKMPGenericHeader h;
    UInt32 doi;      // Domain of Interpretation
    unsigned char  prot_id;  // Protocol-Id
    unsigned char  spi_size; // SPI Size
    UInt16 num_spi;  // # of SPIs
    // SPI(es)
}ISAKMPPaylDel;

// STRUCT         :: ISAKMPPhase1Transform
// DESCRIPTION    :: Phase-1 Transform
typedef struct isakmp_ph1_transform
{
    char                    transformName[MAX_STRING_LENGTH];
    char                    transformId;
    IPsecEncryptionAlgo     encryalgo;
    ISAKMPHashAlgo          hashalgo;
    ISAKMPCertType          certType;
    ISAKMPAuthMethod        authmethod;
    ISAKMPGrpDesc           groupdes;
    UInt16                  life;
    clocktype               processdelay;
    char*                   attributes;
    UInt16                  len_attr;
}ISAKMPPhase1Transform;

// STRUCT         :: ISAKMPPhase1TranList
// DESCRIPTION    :: Phase-1 Transform List
typedef struct isakmp_ph1_transform_list
{
    ISAKMPPhase1Transform    transform;
    isakmp_ph1_transform_list* next;
}ISAKMPPhase1TranList;

// STRUCT         :: ISAKMPPhase2Transform
// DESCRIPTION    :: Phase-2 Transform
typedef struct isakmp_ph2_transform
{
    char                    transformName[MAX_STRING_LENGTH];
    unsigned char           protocolId;
    char                    transformId;
    IPsecSAMode             mode;
    ISAKMPGrpDesc           groupdes;
    IPsecAuthAlgo           authalgo;
    UInt16                  life;
    char*                   attributes;
    UInt16                  len_attr;
}ISAKMPPhase2Transform;

// STRUCT         :: ISAKMPPhase2TranList
// DESCRIPTION    :: Phase-2 Transform List
typedef struct isakmp_ph2_transform_list
{
    ISAKMPPhase2Transform    transform;
    isakmp_ph2_transform_list*    next;
}ISAKMPPhase2TranList;

// STRUCT         :: ISAKMPProtocol
// DESCRIPTION    :: Phase-2 Protocol
typedef struct isakmp_protocol
{
    IPsecProtocol            protocolId;
    UInt32                   numofTransforms;
    ISAKMPPhase2Transform*   transform[MAX_TRANSFORMS];
    isakmp_protocol*         nextproto;
    UInt16                   len_transforms;
    unsigned char            proposalId;
}ISAKMPProtocol;

// STRUCT         :: ISAKMPProposal
// DESCRIPTION    :: Phase-2 Proposal
typedef struct isakmp_proposal
{
    unsigned char         proposalId;
    UInt32                numofProtocols;
    ISAKMPProtocol*       protocol;
    isakmp_proposal*      nextproposal;
    UInt16                len_protocols;
}ISAKMPProposal;

// STRUCT         :: ISAKMP_SA
// DESCRIPTION    :: Struct for ISAKMP SA Negotiated during Phase 1 Exchange
typedef struct
{
    char                    init_cookie[COOKIE_SIZE + 1]; //Initiator Cookie
    char                    resp_cookie[COOKIE_SIZE + 1]; //Responder Cookie
    UInt32                  doi;
    IPsecProtocol           proto;
    IPsecEncryptionAlgo     encryalgo;
    ISAKMPHashAlgo          hashalgo;
    ISAKMPCertType          certType;
    ISAKMPAuthMethod        authmethod;
    ISAKMPGrpDesc           groupdes;
    UInt16                  life;
    clocktype               processdelay;  //saving the encryption delay
} ISAKMP_SA;

// STRUCT         :: MapISAKMP_SA
// DESCRIPTION    :: Map of ISAKMP SA's  for a node with it's peers.
typedef struct isakmp_sa_map
{
    NodeAddress           nodeAddress;
    NodeAddress           peerAddress;
    UInt32                initiator;
    ISAKMP_SA*            isakmp_sa;
    isakmp_sa_map*        link;
} MapISAKMP_SA;

// STRUCT         :: IPSEC_SA
// DESCRIPTION    :: Struct for IPSEC SA Negotiated during Phase 2 Exchange
typedef struct
{
    UInt32                SPI;
    UInt32                doi;
    IPsecProtocol         proto;
    IPsecSAMode           mode;
    ISAKMPGrpDesc         groupdes;
    IPsecAuthAlgo         authalgo;
    UInt16                life;
} IPSEC_SA;

// STRUCT         :: ISAKMPPhase1
// DESCRIPTION    :: Phase-1 Configuration Parameters for a node
typedef struct isakmp_phase1
{
    UInt32                    doi;
    UInt32                    numofTransforms;
    ISAKMPPhase1Transform*    transform[MAX_TRANSFORMS];
    char*                     authkey;      // if authentication is based on
                                            // PRE-SHARED key.
    unsigned char             flags;
    unsigned char             exchtype;        // phase 1 exchange type
    BOOL                      isCertEnabled;
    BOOL                      isNewGroupModeEnabled;
    BOOL                      isNewGroupModePerformed; //used as an indicator
                                                       //only for new group
    ISAKMP_SA*                isakmp_sa;
}ISAKMPPhase1;

// STRUCT         :: ISAKMPPhase2
// DESCRIPTION    :: Phase-2 Configuration Parameters for a node
typedef struct isakmp_phase2
{
    unsigned char       localIdType;
    unsigned char       remoteIdType;
    UInt32              doi;
    Address             localNetwork;       // local Network address
    Address             localNetMask;
    Address             peerNetwork;        //  peer Network address
    Address             peerNetMask;
    UInt32              numofProposals;
    ISAKMPProposal*     proposal;
    unsigned char       upperProtocol;
    unsigned char       exchtype;
    unsigned char       flags;
    IPSEC_SA*           ipsec_sa;
}ISAKMPPhase2;

// STRUCT         :: ISAKMPPhase2List
// DESCRIPTION    :: List of Phase-2 Configuration Parameters for a node
typedef struct isakmp_phase2_list
{
    BOOL                is_ipsec_sa;
    BOOL                reestabRequired;
    ISAKMPPhase2*       phase2;
    isakmp_phase2_list* next;
}ISAKMPPhase2List;

//*************************************************************************
//    Declaration for List ,ExchFunc and FunList
//    List:      An Array of size 10, containg the pointer to functions that
//               are used in the Communtcation round of an exchange
//    ExchFunc:  An  array of size 2 containg a List for Initiator and
//               another for Responder in a Exchange.
//    FunList:   Pointer to a List
//**************************************************************************
struct isakmp_node_conf;
typedef void (*IsakmpList[10])(Node *,isakmp_node_conf* ,Message*);
typedef IsakmpList IsakmpExchFunc[2];
typedef IsakmpList* IsakmpFunList;

// STRUCT         :: ISAKMPExchange
// DESCRIPTION    :: Struct to save the status of current running exchange
typedef struct isakmp_exchange
{
    UInt32               initiator;
    UInt32               doi;
    UInt32               SPI;
    UInt32               msgid;
    IPsecProtocol        proto;
    IsakmpFunList        funcList;
    UInt16               retrycounter;
    UInt16               step;
    ISAKMPPaylTrans*     trans_selected;
    UInt16               phase1_trans_no_selected;
    ISAKMPPaylProp*      prop_selected;
    BOOL                 waitforcommit;
    unsigned char        flags;
    unsigned char        phase;
    unsigned char        exchType;
    unsigned char        expTime;         // time limit for the exchange
    char                 Key_i[KEY_SIZE + 1];
    char                 Key_r[KEY_SIZE + 1];
    char                 Key[KEY_SIZE + 1];
    char                 Ni[NONCE_SIZE + 1];
    char                 Nr[NONCE_SIZE + 1];
    char                 init_cookie[COOKIE_SIZE + 1];  // Initiator Cookie
    char                 resp_cookie[COOKIE_SIZE + 1];  // Responder Cookie
    char*                IDi;
    char*                IDr;
    char*                sig_i;
    char*                sig_r;
    char*                hash_i;
    char*                hash_r;
    char*                cert_i;
    char*                cert_r;
    Message*             lastSentPkt;
}ISAKMPExchange;

// STRUCT         :: ISAKMPNodeConf
// DESCRIPTION    :: Structure for the  Configuration of a ISAKMP Node
//                   with it's peer
typedef struct isakmp_node_conf
{
    UInt32               interfaceIndex;
    NodeAddress          nodeAddress;
    NodeAddress          peerAddress;
    ISAKMPPhase1*        phase1;
    ISAKMPPhase2List*    phase2_list;
    ISAKMPPhase2List*    current_pointer_list;
    ISAKMPPhase2*        phase2;
    IPSEC_SA*            ipsec_sa;
    ISAKMPProposal*      phase2proposals;
    ISAKMPProposal*      lastproposal;
    ISAKMPExchange*      exchange;
    isakmp_node_conf*    link;
}ISAKMPNodeConf;

// STRUCT         :: ISAKMPTimerInfo
// DESCRIPTION    :: ISAKMP Retransmission Timer
typedef struct isakmp_timer_info
{
    ISAKMPNodeConf* nodeconfig;
    UInt32 value;
    UInt16 phase;
}ISAKMPTimerInfo;

// STRUCT         :: ISAKMPStats
// DESCRIPTION    :: ISAKMP Stats to be collected
typedef struct isakmp_stats
{
    UInt32    numOfBaseExch;
    UInt32    numOfIdProtExch;
    UInt32    numOfAuthOnlyExch;
    UInt32    numOfAggresExch;
    UInt32    numOfIkeMainPreSharedExch;
    UInt32    numOfIkeMainDigSigExch;
    UInt32    numOfIkeMainPubKeyExch;
    UInt32    numOfIkeMainRevPubKeyExch;
    UInt32    numOfIkeAggresPreSharedExch;
    UInt32    numOfIkeAggresDigSigExch;
    UInt32    numOfIkeAggresPubKeyExch;
    UInt32    numOfIkeAggresRevPubKeyExch;
    UInt32    numOfIkeQuickExch;
    UInt32    numOfIkeNewGroupExch;
    UInt32    numOfInformExchSend;
    UInt32    numOfInformExchRcv;
    UInt32    numOfExchDropped;
    UInt32    numPayloadSASend;
    UInt32    numPayloadSARcv;
    UInt32    numPayloadNonceSend;
    UInt32    numPayloadNonceRcv;
    UInt32    numPayloadKeyExSend;
    UInt32    numPayloadKeyExRcv;
    UInt32    numPayloadIdSend;
    UInt32    numPayloadIdRcv;
    UInt32    numPayloadAuthSend;
    UInt32    numPayloadAuthRcv;
    UInt32    numPayloadHashSend;
    UInt32    numPayloadHashRcv;
    UInt32    numPayloadCertSend;
    UInt32    numPayloadCertRcv;
    UInt32    numPayloadNotifySend;
    UInt32    numPayloadNotifyRcv;
    UInt32    numPayloadDeleteSend;
    UInt32    numPayloadDeleteRcv;
    UInt32    numOfRetransmissions;
    UInt32    numOfReestablishments;
}ISAKMPStats;

// STRUCT         :: ISAKMPData
// DESCRIPTION    :: ISAKMP Database
typedef struct isakmp_data
{
    clocktype                phase1_start_time;
    ISAKMPNodeConf*          nodeConfData;
    ISAKMPNodeConf*          commonConfData;
    MapISAKMP_SA*            map_isakmp_sa;
    ISAKMPPhase1TranList*    ph1_trans_list;
    ISAKMPPhase2TranList*    ph2_trans_list;
    ISAKMPStats*             stats;
    RandomSeed               seed;
}ISAKMPData;

//*********************************************************************
//    function Declarations
//**********************************************************************

//
// FUNCTION   :: ISAKMPInitiatorSendCookie
// LAYER      :: Network
// PURPOSE    :: sending Initiator cookie
// PARAMETERS :: Node* node - node data
//               ISAKMPNodeConf* nodeconfig - isakmp config for a node-peer
//               Message* msg - isakmp message
// RETURN     :: void
// NOTE       ::

void ISAKMPInit(Node* node,
                const NodeInput* nodeInput,
                UInt32 interfaceIndex);

// FUNCTION   :: ISAKMPHandleProtocolEvent
// LAYER      :: Network
// PURPOSE    :: Handler for a ISAKMP Protocol event
// PARAMETERS :: Node* node - node data
//               Message* msg - isakmp protocol event
// RETURN     :: void
// NOTE       ::

void ISAKMPHandleProtocolEvent(Node* node, Message* msg);

//
// FUNCTION   :: ISAKMPSetUp_Negotiation
// LAYER      :: Network
// PURPOSE    :: to Setup a phase-1 or phase-2 negotiation
// PARAMETERS :: Node* node,
//               ISAKMPNodeConf* nodeconfig - node isakmp configuration
//               Message* msg - message received
//               NodeAddress source - node ip-address
//               NodeAddress dest -   peer ip-address
//               UInt32 i_r - whether initiator or responder
//               unsigned char phase - phase-1 or phase-1
// RETURN     :: void
// NOTE       ::

void ISAKMPSetUp_Negotiation(Node* node,
                             ISAKMPNodeConf* nodeconfig,
                             Message* msg,
                             NodeAddress source,
                             NodeAddress dest,
                             UInt32 i_r,
                             unsigned char phase);

// FUNCTION   :: ISAKMPHandleProtocolPacket
// LAYER      :: Network
// PURPOSE    :: Handler for a ISAKMP Protocol Packet
// PARAMETERS :: Node* node - node data
//               Message* msg - isakmp paccket received
//               NodeAddress source - isakmp paccket source
//               NodeAddress dest - isakmp paccket destination
// RETURN     :: void
// NOTE       ::

void ISAKMPHandleProtocolPacket(Node* node,
                                Message* msg,
                                NodeAddress source,
                                NodeAddress dest);

//
// FUNCTION   :: IsIPSecSAPresent
// LAYER      :: Network
// PURPOSE    :: check for an IPSEC SA for given source and dest network
// PARAMETERS :: Node* node - node data
//               NodeAddress source - source address
//               NodeAddress dest - peer address
//               UInt32 interfaceIndex - source interface index
// RETURN     :: BOOL - TRUE or FALSE
// NOTE       ::

BOOL IsIPSecSAPresent(Node* node,
                        NodeAddress source,
                        NodeAddress dest,
                        UInt32 interfaceIndex,
                        ISAKMPNodeConf* &nodeconfig);

//
// FUNCTION   :: IsISAKMPSAPresent
// LAYER      :: Network
// PURPOSE    :: check for an ISAKMP SA for given source and destination node
// PARAMETERS :: Node* node - node data
//               NodeAddress source - source address
//               NodeAddress dest - peer address
// RETURN     :: BOOL - TRUE or FALSE
// NOTE       ::

BOOL IsISAKMPSAPresent(Node* node, NodeAddress source, NodeAddress dest);

// FUNCTION   :: ISAKMPFinalize
// LAYER      :: Network
// PURPOSE    :: Finalise function for ISAKMP, to Print Collected Statistics
// PARAMETERS :: Node* node - node data
//               UInt32 interfaceIndex - interface index
// RETURN     :: void
// NOTE       ::

void ISAKMPFinalize(Node* node, UInt32 interfaceIndex);

//
// FUNCTION   :: ISAKMPGetNodeConfig
// LAYER      :: Network
// PURPOSE    :: Get NodeConfig for given source and destination ip address
// PARAMETERS :: Node*  - node information
//               NodeAddress node ip-Address
//               NodeAddress peer ip-Address
// RETURN     :: ISAKMPNodeConf*
// NOTE       ::

ISAKMPNodeConf* ISAKMPGetNodeConfig(Node* node,
                   NodeAddress source,
                   NodeAddress dest);

#endif // ISAKMP_H
