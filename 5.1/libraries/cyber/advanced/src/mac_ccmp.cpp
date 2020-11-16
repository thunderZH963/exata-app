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
// PROTOCOL :: CCMP
//
// SUMMARY ::  CCMP (CTR with CBC-MAC Protocol) is an RSNA data
// confidentiality and integrity protocol. CCMP is based on the CCM of the
// AES encryption algorithm. It is a generic authenticate-and-encrypt block
// cipher mode. A unique temporal key (for each session) and a unique nonce
// value (for each frame) is required for protecting the MPDUs. CCMP uses a
// 48-bit packet number (PN) for this purpose. The PN is never repeated for
// a series of encrypted MPDUs using the same temporal key.
// CCMP encrypts the payload of a plaintext MPDU and encapsulates the
// resulting cipher text using the following steps:
// 1)Increment the PN, so that each MPDU has a unique PN for the same
//   temporal key.
// 2)Use the fields in the MPDU header to construct the additional
//   authentication data (AAD) for CCM. The CCM algorithm provides integrity
//   protection for the fields included in the AAD.
// 3)Construct the CCM Nonce block from the PN, A2, and the Priority field of
//   the MPDU where A2 is MPDU Address 2. The Priority field has a reserved
//   value set to 0.
// 4)Place the new PN and the key identifier into the 8-octet CCMP header.
// 5)Use the temporal key, AAD, nonce, and MPDU data to form the cipher text
//   and MIC. This step is known as CCM originator processing.
// 6)Form the encrypted MPDU by combining the original MPDU header, the CCMP
//   header, the encrypted data and MIC, as described in Sec-8.3.3.2.
// CCMP decrypts the payload of a cipher text MPDU and decapsulates plaintext
// MPDU using the following steps:
//
// 1)The encrypted MPDU is parsed to construct the AAD and nonce values.
// 2)The AAD is formed from the MPDU header of the encrypted MPDU.
// 3)The nonce value is constructed from the A2, PN, and Priority Octet
//   fields (reserved and set to 0).
// 4)The MIC is extracted for use in the CCM integrity checking.
// 5)The CCM recipient processing uses the temporal key, AAD, nonce, MIC, and
//   MPDU cipher text data to recover the MPDU plaintext data as well as to
//   check the integrity of the AAD and MPDU plaintext data.
// 6)The received MPDU header and the MPDU plaintext data from the CCM
//   recipient processing may be concatenated to form a plaintext MPDU.
// 7)The decryption processing prevents replay of MPDUs by validating that
//   the PN in the MPDU is greater than the replay counter maintained for the
//   session.
// The decapsulation process succeeds when the calculated MIC matches the
// MIC value obtained from decrypting the received encrypted MPDU. The
// original MPDU header is concatenated with the plaintext data resulting
// from the successful CCM recipient processing to create the plaintext MPDU.
//
// LAYER ::  Mac Layer
//
// STATISTICS ::
//  + pktEncrypted  : Number of Packets encrypted by CCMP.
//  + pktDecrypted  : Number of Packets decrypted by CCMP.
//  + excludedCount : Number of unsecured MPDUs discarded by CCMP.
//  + undecryptableCount : Number of protected MPDUs unable to decrypt by
//                         CCMP.
//
// CONFIG_PARAM ::
//  + MAC-PROTOCOL  MACDOT11
//  + MAC-SECURITY-PROTOCOL: CCMP
//  + CCMP-CONFIG-FILE : <filename>.ccmp : Specify the CCMP configuration
//                                         file.
//  + CCMP-AES-DELAY : clocktype : Processing delay for AES algorithm.
//  + WEP-CCMP-ALLOW-UNENC : bool : Allow unsecured data to be sent to upper
//                                 layers.

//  SPECIAL_CONFIG :: <filenale>.ccmp : CCMP configuration File.
//  + To add entries in Key Mappings table for a node,interface or a subnet.
//   Syntax:
//   KeyMappings <TA> <RA> <Key Type> <Key>
//   <TA>         specifies the transmitter address.
//   <RA>         specifies the receiver address.
//   <Key Type>   is wireless security protocol CCMP.
//   <Key>        is the actual key value used for encryption/decryption.

// VALIDATION ::

// IMPLEMENTED_FEATURES ::
// + Encapsulation of Mac layer protocols.
// + Currently, CCMP model does not include actual implementation of the
//   encryption algorithm. Only, delays for running the algorithm is
//   considered. CCMP uses AES encryption algorithm to support cryptography.
//
// OMITTED_FEATURES :: (Title) : (Description) (list)
// + Actual implementations of supported encryption algorithm is not followed
//   in current CCMP model. Only, delays for running the algorithm is
//   considered.
// + Current CCMP implementation does not support IPv6 addressing.
// + Implementation of CCMP for multicast/broadcast data.
//
// ASSUMPTIONS ::
// + All STAs running CCMP are RSNA capable.
// + Only, delays for running encryption algorithm is considered.
// + Every CCMP enable STAs are listed in config file in the form of a
//   table. For each CCMP enabled STA in the table a CCMP key is defined for
//   every reachable destination from that STA. If an entry is not found for
//   a RA in mappings table for a STA it means that CCMP is off for that STA.
// + Default keys are not implemented in CCMP. Corresponding Keyid subfield
//   in the header will be zero. PN and MIC in CCMP MPDU are dummy fields.
//   MIC will not be used to check erroneous packets.
//
// STANDARD :: Coding standard follows the following Coding Guidelines
//             1. SNT C Coding Guidelines for QualNet 3.2
// Reference:
// 1.IEEE 802.11-1999 Standard
// 2.IEEE 802.11i-2004 Standard
// RELATED :: (Name of related protocol) (list) {optional}
// **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "fileio.h"
#include "network_ip.h"
#include "mac_dot11.h"
#include "mac_security.h"

// /**
// FUNCTION   :: CCMPParseConfigFile
// LAYER      :: Mac
// PURPOSE    :: Function to read CCMP configuration file and
//               initialize CCMP KeyMappings table for an interface of a
//               node.
// PARAMETERS ::
// + node            : Node* : The node trying to read its CCMP
//                             configuration.
// + interfaceIndex  : int : Index of the Interface.
// + CCMPConf        : const NodeInput* : CCMP configuration file.
// + subnetAddress   : NodeAddress : Subnet address of the node.
// + maskBits        : int : Number of subnet masking bits.
// RETURN     :: void : NULL
// **/
static
void CCMPParseConfigFile(Node* node,
                        int interfaceIndex,
                        const NodeInput* CCMPConf,
                        NodeAddress subnetAddress,
                        int maskBits)
{
    int i;
    BOOL addEntry = FALSE;
    int lineLen = NI_GetMaxLen(CCMPConf);
    char *token = (char*) MEM_malloc(lineLen);

    for (i = 0; i < CCMPConf->numLines; i++)
    {
        const char* currentLine = CCMPConf->inputStrings[i];
        char sourceAdd[MAX_STRING_LENGTH] = {0};
        char destAdd[MAX_STRING_LENGTH] = {0};
        char keytype[MAX_STRING_LENGTH] = {0};
        char keystr[MAX_STRING_LENGTH] = {0};

        WepCcmpKeyType keyType = CCMP;
        NodeAddress outputNodeAddress = 0;
        int numHostBits = 0;
        Address transmitterAdd;
        memset(&transmitterAdd, 0, sizeof(Address));

        BOOL isNodeId = FALSE;
        BOOL wasFound = FALSE;
        memset(token,0,lineLen);
        int numValRead = sscanf(currentLine, "%s%s%s%s%s", token, sourceAdd,
                                                destAdd, keytype, keystr);
        if (!strcmp(token, "KeyMappings"))
        {
            if (numValRead != NUM_KEYMAPPINGS_PARAM)
            {
                ERROR_Assert(FALSE, "Wrong KeyMappings line");
            }
            if (!strcmp(keytype, "CCMP"))
            {
                keyType = CCMP;
            } else if (!strcmp(keytype, "WEP"))
            {
                keyType = WEP;
            }
            else
            {
                ERROR_Assert(FALSE, "Wrong Key Type");
            }

            IO_ParseNodeIdHostOrNetworkAddress(
                sourceAdd,
                &outputNodeAddress,
                &numHostBits,
                &isNodeId
                );

            if (numHostBits > 0)
            {
                if ((outputNodeAddress == subnetAddress)
                    && (numHostBits == maskBits))
                {
                    numHostBits = WepCcmpReadDestAdd(node, destAdd,
                                    &transmitterAdd);
                    wasFound = TRUE;
                }
            }
            else
            {
                if (isNodeId) //Node Id
                {
                    if (outputNodeAddress == node->nodeId)
                    {
                        numHostBits = WepCcmpReadDestAdd(node, destAdd,
                                        &transmitterAdd);
                        wasFound = TRUE;
                    }
                }
                else //IP Address
                {
                    NodeAddress nodeId =
                        MAPPING_GetNodeIdFromInterfaceAddress(
                                                node, outputNodeAddress);
                    if (nodeId == INVALID_MAPPING)
                    {
                        ERROR_Assert(FALSE, "No node exists for given IP\
                                            address");
                    }
                    if (outputNodeAddress ==
                                    MAPPING_GetInterfaceAddressForInterface(
                                        node, node->nodeId, interfaceIndex))
                    {
                        numHostBits = WepCcmpReadDestAdd(node, destAdd,
                                    &transmitterAdd);
                        wasFound = TRUE;
                    }
                }//end else
            }//end else
        }//end if
        else
        {
            ERROR_Assert(FALSE, "Invalid Token in CCMP");
        }
        if (wasFound)
        {
            BOOL retVal =
                  WepCcmpIsDuplicateEntry(node,interfaceIndex,transmitterAdd,
                                                            numHostBits);
            if (!retVal)
            {
                addEntry = TRUE;
                char* key = (char*) MEM_malloc(MAX_STRING_LENGTH);
                strcpy(key,keystr);

                EncryptionData* encData = (EncryptionData*)
                        node->macData[interfaceIndex]->encryptionVar;
                WepCcmpKeyMappings* temp = (WepCcmpKeyMappings*)
                                MEM_malloc(sizeof(WepCcmpKeyMappings));

                temp->TA = transmitterAdd;
                temp->numHostBits = numHostBits;
                temp->keytype = keyType;
                temp->key = key;

                //checking if the list is empty
                if (encData->first == NULL)
                {
                    encData->first = temp;
                    temp->next = NULL;
                }
                else
                {
                    temp->next = encData->first;
                    encData->first = temp;
                }
            }
        }
    }//end for
    if (!addEntry)
    {
        EncryptionData* encData = (EncryptionData*)
                        node->macData[interfaceIndex]->encryptionVar;
        encData->first = NULL;
    }

    MEM_free(token);
}
// /**
// FUNCTION    :: CCMPReadDelays
// LAYER       :: Mac
// PURPOSE     :: Function to read processing delay for AES encryption
//                algorithm.
// PARAMETERS  ::
// + node            : Node* : The node trying to read delays.
// + nodeInput       : const NodeInput* : QualNet main configuration file.
// + interfaceIndex  : int : Index of the Interface.
// RETURN      :: void : NULL
// **/
static
void CCMPReadDelays(Node* node,
                    const NodeInput* nodeInput,
                    int interfaceIndex)
{
    clocktype processingDelay;
    char buf[MAX_STRING_LENGTH];
    BOOL wasFound = FALSE;

    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "CCMP-AES-DELAY",
        &wasFound,
        buf);

    if (wasFound)
    {
        processingDelay = TIME_ConvertToClock(buf);
    }
    else
    {
        processingDelay = CCMP_AES_DELAY;
    }
    if (processingDelay < 0)
    {
        ERROR_Assert(FALSE,
            "The value of CCMP-AES-DELAY should be Positive\n");
    }
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    encData->processingDelay = processingDelay;
}

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
            int numHostBits)
{
    NodeInput CCMPInput;
    BOOL retVal = FALSE;

    node->macData[interfaceIndex]->encryptionVar  =
                                        MEM_malloc(sizeof(EncryptionData));
    memset(node->macData[interfaceIndex]->encryptionVar,0,
            sizeof(EncryptionData));
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;

    encData->securityProtocol = MAC_SECURITY_CCMP;
    NodeAddress nodeAddr = MAPPING_GetInterfaceAddressForInterface(
                                node, node->nodeId, interfaceIndex);

    IO_ReadCachedFile(node,
                      node->nodeId,
                      interfaceIndex,
                      nodeInput,
                      "CCMP-CONFIG-FILE",
                      &retVal,
                      &CCMPInput);
    if (!retVal)
    {
        ERROR_Assert(FALSE, "CCMP configuration file missing");
    }
    CCMPReadDelays(node, nodeInput, interfaceIndex);
    WepCcmpReadExcludeUnencrypted(node, nodeInput, interfaceIndex);
    CCMPParseConfigFile(node, interfaceIndex, &CCMPInput, subnetAddress,
                                                        numHostBits);
}
// /**
// FUNCTION   :: CCMPEncryptPacket
// LAYER      :: Mac
// PURPOSE    :: Encrypt outbound packet with CCMP.
// PARAMETERS ::
// + node            : Node*     : The node processing packet.
// + msg             : Message*  : Packet pointer.
// + interfaceIndex  : int : Index of the Interface.
// + destAddr        : Mac802Address : Next hop address.
// RETURN     :: BOOL : TRUE if packet has encrypted, FALSE otherwise.
// **/
BOOL CCMPEncryptPacket(Node* node,
                        Message* msg,
                        int interfaceIndex,
                        Mac802Address destAddr)
{
    BOOL wasFound = FALSE;
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    WepCcmpKeyMappings* temp = encData->first;
    while (temp != NULL)
    {
        //Mac Address To Ip Address
         MacHWAddress destHWAddr;
            Convert802AddressToVariableHWAddress(node, &destHWAddr, &destAddr);
            NodeAddress ipdestAddr = MacHWAddressToIpv4Address(node, interfaceIndex, &destHWAddr);

        if (temp->numHostBits > 0) //Subnet Address
        {
            BOOL isInSubnet = IsIpAddressInSubnet(
                                            ipdestAddr,
                                            temp->TA.interfaceAddr.ipv4,
                                            temp->numHostBits);
            if (isInSubnet)
            {
                if (temp->keytype == CCMP)
                {
                    //Encrypt the packet
                    wasFound = TRUE;
                    break;
                } else if (temp->keytype == WEP)
                {
                    BOOL isEncrypt = WEPEncryptPacket(node, msg,
                                interfaceIndex, destAddr);
                    return isEncrypt;
                }
                else
                {
                    ERROR_Assert(FALSE, "Invalid key type");
                }
            }
        }
        else
        {
            if (temp->numHostBits == 0) //Interface Address
            {
                if (temp->TA.interfaceAddr.ipv4 == ipdestAddr)
                {
                    if (temp->keytype == CCMP)
                    {
                        //Encrypt the packet
                        wasFound = TRUE;
                        break;
                    } else if (temp->keytype == WEP)
                    {
                        BOOL isEncrypt = WEPEncryptPacket(node, msg,
                                            interfaceIndex, destAddr);
                        return isEncrypt;
                    }
                    else
                    {
                        ERROR_Assert(FALSE, "Invalid key type");
                    }
                }
            }
        }
        temp = temp->next;
    }//end while
    if (wasFound)
    {
        MESSAGE_AddHeader(node, msg, CCMP_FRAME_HDR_SIZE,
                            TRACE_MACDOT11_CCMP);
        //Adding dummy values into CCMP header
        CCMP_FrameHdr* hdr = (CCMP_FrameHdr*) MESSAGE_ReturnPacket(msg);
        hdr->rsvd = 0;
        hdr->rsvdBits = 0;
        hdr->ExtIV = 1;
        hdr->keyid = 0;
        hdr->PN[0] = 0;
        hdr->PN[1] = 0;
        hdr->PN[2] = 0;
        hdr->PN[3] = 0;
        hdr->PN[4] = 0;
        hdr->PN[5] = 0;
        (*msg).virtualPayloadSize += CCMP_FRAME_MIC_SIZE;
        encData->stats.pktEncrypted++;
        return TRUE;
    } else
    {
        //Need not encrypt packet
        return FALSE;
    }
}

// /**
// FUNCTION   :: CCMPDecryptPacket
// LAYER      :: Mac
// PURPOSE    :: Decrypt inbound packet with CCMP.
// PARAMETERS ::
// + node           : Node*     :  The node processing packet.
// + msg            : Message*  :  Packet pointer.
// + interfaceIndex : int :  Index of the Interface.
// + sourceAddr     : Mac802Address : previous hop address.
// + protection     : BOOL : True if packet is protected, FALSE otherwise.
// RETURN     :: BOOL   : TRUE if packet has decrypted, FALSE otherwise.
// **/
BOOL CCMPDecryptPacket(Node* node,
                        Message* msg,
                        int interfaceIndex,
                        Mac802Address sourceAddr,
                        BOOL protection)
{
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    //Mac Address To Ip Address
            MacHWAddress sourceHWAddr;
            Convert802AddressToVariableHWAddress(node, &sourceHWAddr, &sourceAddr);
            NodeAddress ipsourceAddr = MacHWAddressToIpv4Address(node, interfaceIndex, &sourceHWAddr);

    if (!protection)
    {
        BOOL wasFound = FALSE;
        WepCcmpKeyMappings* temp = encData->first;
        while (temp != NULL)
        {
            if (temp->numHostBits > 0) //Subnet Address
            {
                BOOL isInSubnet = IsIpAddressInSubnet(
                                            ipsourceAddr,
                                            temp->TA.interfaceAddr.ipv4,
                                            temp->numHostBits);
                if (isInSubnet)
                {
                    wasFound = TRUE;
                    break;
                }
            }
            else
            {
                if (temp->numHostBits == 0) //Interface Address
                {
                    if (temp->TA.interfaceAddr.ipv4 == ipsourceAddr)
                    {
                        wasFound = TRUE;
                        break;
                    }
                }
            }
            temp = temp->next;
        }
        //if sourceAddr has an entry in key mappings table
        if (wasFound)
        {
            //Discard the packet
            encData->stats.excludedCount++;
            return FALSE;
        }
        else
        {
            //Recv the packet
            return TRUE;
        }
    }
    else
    {
        BOOL wasFound = FALSE;
        WepCcmpKeyMappings* temp = encData->first;
        while (temp != NULL)
        {
            if (temp->numHostBits > 0) //Subnet Address
            {
                BOOL isInSubnet = IsIpAddressInSubnet(
                                            ipsourceAddr,
                                            temp->TA.interfaceAddr.ipv4,
                                            temp->numHostBits);
                if (isInSubnet)
                {
                    if (temp->keytype == CCMP)
                    {
                        //Decrypt packet
                        wasFound = TRUE;
                        break;
                    } else if (temp->keytype == WEP)
                    {
                        BOOL isDecrypt = WEPDecryptPacket(node, msg,
                            interfaceIndex, sourceAddr, protection);
                        return isDecrypt;
                    }
                    else
                    {
                        //Discard the packet
                        encData->stats.undecryptableCount++;
                        return FALSE;
                    }
                }
            }
            else
            {
                if (temp->numHostBits == 0) //Interface Address
                {
                    if (temp->TA.interfaceAddr.ipv4 == ipsourceAddr)
                    {
                        if (temp->keytype == CCMP)
                        {
                            //Decrypt packet
                            wasFound = TRUE;
                            break;
                        } else if (temp->keytype == WEP)
                        {
                            BOOL isDecrypt = WEPDecryptPacket(node, msg,
                               interfaceIndex, sourceAddr, protection);
                            return isDecrypt;
                        }
                        else
                        {
                            //Discard the packet
                            encData->stats.undecryptableCount++;
                            return FALSE;
                        }
                    }
                }
            }
            temp = temp->next;
        }
        if (wasFound)
        {
            encData->stats.pktDecrypted++;
            MESSAGE_RemoveHeader(node, msg,
                    CCMP_FRAME_HDR_SIZE, TRACE_MACDOT11_CCMP);
            (*msg).virtualPayloadSize -= CCMP_FRAME_MIC_SIZE;
            return TRUE;
        } else
        {
            //Discard the packet
            encData->stats.undecryptableCount++;
            return FALSE;
        }
    }
}
// /**
// FUNCTION   :: CCMPFinalize()
// LAYER      :: Mac
// PURPOSE    :: Finalize function for the CCMP model.
// PARAMETERS
// + node            : Node * : Pointer to node.
// + interfaceIndex  : int : Index of the Interface.
// RETURN     :: void   : NULL
// **/
void CCMPFinalize(Node* node, int interfaceIndex)
{
    char buf[MAX_STRING_LENGTH];
    MacData* macData = node->macData[interfaceIndex];
    if (macData->macStats == TRUE)
    {
        NodeAddress intfAddr = MAPPING_GetInterfaceAddressForInterface(node,
                                            node->nodeId, interfaceIndex);
        EncryptionData* encData = (EncryptionData*)
                                    node->macData[interfaceIndex]
                                    ->encryptionVar;
        sprintf(buf, "Packets Encrypted = %u", encData->stats.pktEncrypted);
        IO_PrintStat(node, "MAC", "CCMP", intfAddr, -1, buf);
        sprintf(buf, "Packets Decrypted = %u", encData->stats.pktDecrypted);
        IO_PrintStat(node, "MAC", "CCMP", intfAddr, -1, buf);
        sprintf(buf, "Packets Discarded = %u", encData->stats.excludedCount);
        IO_PrintStat(node, "MAC", "CCMP", intfAddr, -1, buf);
        sprintf(buf, "Packets Undecrypted = %u",
                                        encData->stats.undecryptableCount);
        IO_PrintStat(node, "MAC", "CCMP", intfAddr, -1, buf);
    }
}

