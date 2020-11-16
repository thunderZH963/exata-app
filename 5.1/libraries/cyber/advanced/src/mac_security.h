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

#ifndef MAC_SECURITY_H

#define MAC_SECURITY_H

// /**
// CONSTANT    :: WEP_RC4_DELAY
// DESCRIPTION :: Processing Delay for 'RC4' algorithm.
// **/
#define WEP_RC4_DELAY   (10 * MICRO_SECOND)

// /**
// CONSTANT    :: CCMP_AES_DELAY
// DESCRIPTION :: Processing Delay for 'CCMP_AES_DELAY'
//                algorithm.
// **/
#define CCMP_AES_DELAY  (10 * MICRO_SECOND)

// /**
// CONSTANT    :: WEP_FRAME_HDR_SIZE
// DESCRIPTION :: Size of WEP frame header.
// **/
#define WEP_FRAME_HDR_SIZE 4

// /**
// CONSTANT    :: WEP_FRAME_ICV_SIZE
// DESCRIPTION :: Size of WEP frame trailor.
// **/
#define WEP_FRAME_ICV_SIZE 4

// /**
// CONSTANT    :: CCMP_FRAME_HDR_SIZE
// DESCRIPTION :: Size of CCMP frame header.
// **/
#define CCMP_FRAME_HDR_SIZE 8

// /**
// CONSTANT    :: CCMP_FRAME_MIC_SIZE
// DESCRIPTION :: Size of CCMP frame trailor.
// **/
#define CCMP_FRAME_MIC_SIZE 8

// /**
// CONSTANT    :: WEP_CCMP_EXCLUDE_UNENCRYPTED
// DESCRIPTION :: Constant to check if unprotected data need to be send to
//                upper layers.
// **/
#define WEP_CCMP_EXCLUDE_UNENCRYPTED  FALSE

// /**
// CONSTANT    :: NUM_KEYMAPPINGS_PARAM
// DESCRIPTION :: Constant to check for any wrong KeyMappings line in
//                wep/ccmp config files.
// **/
#define NUM_KEYMAPPINGS_PARAM  5


// /**
// ENUMERATION ::  WepCcmpKeyType
// DESCRIPTION ::  Different Encryption/Decryption Key Types.
// **/
typedef enum
{
    WEP = 1,
    CCMP
} WepCcmpKeyType;

// /**
// STRUCT      :: WepCcmpKeyMappings
// DESCRIPTION :: WEP-CCMP Key Mappigs Table structure.
// **/
typedef struct key_mappings_table
{
    Address TA;
    int numHostBits;
    WepCcmpKeyType keytype;
    char* key;
    struct key_mappings_table* next;
} WepCcmpKeyMappings;

// /**
// STRUCT      :: WEP_FrameHdr
// DESCRIPTION :: WEP header information structure.
// **/
typedef struct
{
    unsigned int IV :24,        /*Initialization vector*/
                 pad:6,         /*padding*/
                 keyid:2;       /*keyid*/
} WEP_FrameHdr;

// /**
// STRUCT      :: CCMP_FrameHdr
// DESCRIPTION :: CCMP header information structure.
// **/
typedef struct
{
    unsigned char rsvd;         /*Reserved byte*/
    unsigned char rsvdBits:5,   /*Reserved bits*/
                  ExtIV:1,      /*ExtIV*/
                  keyid:2;      /*keyid*/
    unsigned char PN[6];        /*Packet number*/
} CCMP_FrameHdr;

// /**
// STRUCT      :: EncryptionStats
// DESCRIPTION :: Encryption statistics information structure.
// **/
typedef struct
{
    // Stat fields
    unsigned int pktEncrypted;  // No. of encrypted packet
    unsigned int pktDecrypted;  // No. of decrypted packet
    unsigned int excludedCount; //No. of unsecured MPDUs discarded
    unsigned int undecryptableCount; //No. of protected MPDUs unable
                                     //to decrypt
}EncryptionStats;

// /**
// STRUCT      :: EncryptionData
// DESCRIPTION :: Encryption data information structure.
// **/
typedef struct {
    MAC_SECURITY securityProtocol;
    WepCcmpKeyMappings* first;
    clocktype processingDelay;
    BOOL excludeUnencrypted;
    // statistics
    EncryptionStats stats;
} EncryptionData;


// /**
// FUNCTION   :: WepCcmpIsDuplicateEntry
// LAYER      :: Mac
// PURPOSE    :: Function to check if an entry is already there in key
//               mappings table of a node for given interface.
// PARAMETERS ::
// + node            : Node* : The node initializing WEP/CCMP.
// + interfaceIndex  : int : Index of the Interface.
// + transmitterAdd  : Address : Transmitter address as read from WEP/CCCMP
//                               configuration file.
// + numHostBits     : int : Number of host bits for transmitter address.
// RETURN     :: BOOL : TRUE if it's a duplicate entry, FALSE otherwise.
// **/
BOOL WepCcmpIsDuplicateEntry(Node* node,
                                int interfaceIndex,
                                Address transmitterAdd,
                                int numHostBits);
// /**
// FUNCTION   :: WepCcmpReadExcludeUnencrypted
// LAYER      :: Mac
// PURPOSE    :: Function to read QualNet main config file and initialize
//               excludeUnencrypted for an interface of a node.
// PARAMETERS ::
// + node            : Node* : The node initializing WEP/CCMP.
// + nodeInput       : const NodeInput* : QualNet main configuration file.
// + interfaceIndex  : int : Index of the Interface.
// RETURN     :: Void : NULL
// **/
void WepCcmpReadExcludeUnencrypted(Node* node,
                                const NodeInput* nodeInput,
                                int interfaceIndex);
// /**
// FUNCTION   :: WepCcmpReadDestAdd
// LAYER      :: Mac
// PURPOSE    :: Function to initialize destination address and to return
//               numHostBits for a node if destination is a subnet address.
// PARAMETERS ::
// + node            : Node* : The node initializing WEP/CCMP.
// + destAdd         : char* : Destination address as read from WEP/CCCMP
//                             configuration file.
// + transmitterAdd  : Address* : Transmitter address as read from WEP/CCCMP
//                                configuration file.
// RETURN     :: int : Number of masking bits if destination address is a
//                     subnet address, zero otherwise.
// **/
int WepCcmpReadDestAdd(Node* node, char* destAdd, Address* transmitterAdd);

// /**
// FUNCTION   :: WEPInit
// LAYER      :: Mac
// PURPOSE    :: Function to Initialize WEP for a node.
// PARAMETERS ::
// + node            :  Node* : The node initializing WEP.
// + interfaceIndex  : int : Index of the Interface.
// + nodeInput       :  const NodeInput* : QualNet main configuration file.
// + subnetAddress   : NodeAddress : Subnet address of the node.
// + numHostBits     : int : Number of subnet masking bits.
// RETURN     :: void : NULL
// **/

void WEPInit(Node* node,
            int interfaceIndex,
            const NodeInput* nodeInput,
            NodeAddress subnetAddress,
            int numHostBits);

// /**
// FUNCTION   :: WEPEncryptPacket
// LAYER      :: Mac
// PURPOSE    :: Encrypt outbound packet with WEP.
// PARAMETERS ::
// + node            : Node*     : The node processing packet.
// + msg             : Message*  : Packet pointer.
// + interfaceIndex  : int : Index of the Interface.
// + destAddr        : NodeAddress : Next hop address.
// RETURN     :: BOOL   : TRUE if packet has encrypted, FALSE otherwise.
// **/
BOOL WEPEncryptPacket(Node* node,
                    Message* msg,
                    int interfaceIndex,
                    Mac802Address destAddr);

// /**
// FUNCTION   :: WEPDecryptPacket
// LAYER      :: Mac
// PURPOSE    :: Decrypt inbound packet with WEP.
// PARAMETERS ::
// + node           : Node*     :  The node processing packet.
// + msg            : Message*  :  Packet pointer.
// + interfaceIndex : int :  Index of the Interface.
// + sourceAddr     : NodeAddress : previous hop address.
// + protection     : BOOL : True if packet is WEP protected, FALSE
//                           otherwise.
// RETURN     :: BOOL   : TRUE if packet has decrypted, FALSE otherwise.
// **/

BOOL WEPDecryptPacket(Node* node,
                    Message* msg,
                    int interfaceIndex,
                    Mac802Address sourceAddr,
                    BOOL protection);

// /**
// FUNCTION   :: WEPFinalize()
// LAYER      :: Mac
// PURPOSE    :: Finalize function for the WEP model.
// PARAMETERS
// + node            :  Node * : Pointer to node.
// + interfaceIndex  : int : Index of the Interface.
// RETURN     :: void : NULL
// **/

void WEPFinalize(Node* node, int interfaceIndex);

// /**
// FUNCTION   :: CCMPInit
// LAYER      :: Mac
// PURPOSE    :: Function to Initialize CCMP for a node.
// PARAMETERS ::
// + node            : Node* : The node initializing CCMP.
// + interfaceIndex  : int : Index of the Interface.
// + nodeInput       : const NodeInput* : QualNet main configuration file.
// + subnetAddress   : NodeAddress : Subnet address of the node.
// + numHostBits     : int : Number of subnet masking bits.
// RETURN     :: void : NULL
// **/

void CCMPInit(Node* node,
              int interfaceIndex,
              const NodeInput* nodeInput,
              NodeAddress subnetAddress,
              int numHostBits);

// /**
// FUNCTION   :: CCMPEncryptPacket
// LAYER      :: Mac
// PURPOSE    :: Encrypt outbound packet with CCMP.
// PARAMETERS ::
// + node            : Node*     : The node processing packet.
// + msg             : Message*  : Packet pointer.
// + interfaceIndex  : int : Index of the Interface.
// + destAddr        : NodeAddress : Next hop address.
// RETURN     :: BOOL : TRUE if packet has encrypted, FALSE otherwise.
// **/

BOOL CCMPEncryptPacket(Node* node,
                        Message* msg,
                        int interfaceIndex,
                        Mac802Address destAddr);

// /**
// FUNCTION   :: CCMPDecryptPacket
// LAYER      :: Mac
// PURPOSE    :: Decrypt inbound packet with CCMP.
// PARAMETERS ::
// + node           : Node*     :  The node processing packet.
// + msg            : Message*  :  Packet pointer.
// + interfaceIndex : int :  Index of the Interface.
// + sourceAddr     : NodeAddress : previous hop address.
// + protection     : BOOL : True if packet is protected, FALSE otherwise.
// RETURN     :: BOOL   : TRUE if packet has decrypted, FALSE otherwise.
// **/

BOOL CCMPDecryptPacket(Node* node,
                        Message* msg,
                        int interfaceIndex,
                        Mac802Address sourceAddr,
                        BOOL protection);

// /**
// FUNCTION   :: CCMPFinalize()
// LAYER      :: Mac
// PURPOSE    :: Finalize function for the CCMP model.
// PARAMETERS
// + node            : Node * : Pointer to node.
// + interfaceIndex  : int : Index of the Interface.
// RETURN     :: void   : NULL
// **/
void CCMPFinalize(Node* node, int interfaceIndex);

#endif /* MAC_SECURITY_H */
