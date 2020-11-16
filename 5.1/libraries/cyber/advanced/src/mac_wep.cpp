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
// PROTOCOL :: WEP
//
// SUMMARY :: Wired equivalent privacy (WEP) is a MAC layer security protocol
// intended to provide security for the wireless LAN equivalent to the
// security provided in wired LAN.
// In WEP a secret key is distributed to cooperating STAs by some external
// key management path independent of MAC layer. The secret key concatenated
// with an initialization vector (IV) resulting in a seed is input to a
// pseudorandom number generator PRNG. The PRNG outputs a key sequence k of
// pseudorandom octets.
// An integrity algorithm operates on plaintext data to produce an ICV to
// protect against unauthorized data modification. The key sequence k is then
// combined with the plaintext concatenated with the ICV to generate the
// ciphertext.
// The secret key remains constant while the IV changes periodically. Thus
// there is a one-to-one correspondence between the IV and k.
// The WEP algorithm is applied to the frame body of an MPDU.
// The (IV, frame body, ICV) triplet forms the actual data to be sent in the
// data frame. For WEP protected frames, the first four octets of the frame
// body contain the IV field for the MPDU. The IV is followed by the MPDU,
// which is followed by the ICV. The WEP ICV is 32 bits. While decrypting the
// message IV of the incoming message is used to generate the key sequence
// necessary to decipher the message. Combining the ciphertext with the
// proper key sequence yields the original plaintext and ICV. The integrity
// check algorithm is then performed on the recovered plaintext and the
// generated ICV is compared to ICV transmitted with the message. If ICV is
// not equal to ICV, the received MPDU is in error and an error indication is
// sent to MAC management.
//
//  LAYER ::  Mac Layer
//
//  STATISTICS ::
//  + pktEncrypted  : Number of Packets encrypted by WEP.
//  + pktDecrypted  : Number of Packets decrypted by WEP.
//  + excludedCount : Number of non-WEP MPDUs discarded by WEP.
//  + undecryptableCount : Number of protected MPDUs unable to decrypt by
//                         WEP.
//
//  CONFIG_PARAM ::
//  + MAC-PROTOCOL MACDOT11
//  + MAC-SECURITY-PROTOCOL WEP
//  + WEP-CONFIG-FILE : <filename>.wep : Specify the WEP configuration file.
//  + WEP-RC4-DELAY : clocktype : Processing delay for RC4 algorithm.
//  + WEP-CCMP-ALLOW-UNENC : bool : Allow unsecured data to be sent to upper
//                                 layers.
//
//  SPECIAL_CONFIG :: <filenale>.wep : WEP configuration File.
//  + To add entries in Key Mappings table for a node,interface or a subnet.
//   Syntax:
//   KeyMappings <TA> <RA> <Key Type> <Key>
//   <TA>         specifies the transmitter address.
//   <RA>         specifies the receiver address.
//   <Key Type>   is wireless security protocol WEP.
//   <Key>        is the actual key value used for encryption/decryption.
//
// VALIDATION ::

// IMPLEMENTED_FEATURES ::
// + Encapsulation of Mac layer protocols.
// + Currently, WEP model does not include actual implementation of the
//   encryption algorithm. Only, delays for running the algorithm is
//   considered. WEP uses RC4 encryption algorithm to support cryptography.

// OMITTED_FEATURES :: (Title) : (Description) (list)
// + Actual implementations of supported encryption algorithm is not followed
//   in current WEP model. Only, delays for running the algorithm is
//   considered.
// + Current WEP implementation does not support IPv6 addressing.
// + Implementation of WEP for multicast/broadcast data.

// ASSUMPTIONS ::
// + Only, delays for running encryption algorithm is considered.
// + Every WEP enable STAs are listed in config file in the form of a table.
//   For each WEP enabled STA in the table a WEP key is defined for every
//   reachable destination from that STA. If an entry is not found for a RA
//   in mappings table for a STA it means that WEP is off for that STA.
// + Default keys are not implemented in WEP. Corresponding Keyid subfield
//   in the header will be zero. IV and ICV in WEP MPDU are dummy fields. ICV
//   will not be used to check erroneous packets.

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
// FUNCTION   :: WEPParseConfigFile
// LAYER      :: Mac
// PURPOSE    :: Function to read WEP configuration file and
//               initialize WEP KeyMappings table for an interface of a node.
// PARAMETERS ::
// + node            : Node* : The node trying to read its WEP
//                             configuration.
// + interfaceIndex  : int : Index of the Interface.
// + WEPConf         : const NodeInput* : WEP configuration file.
// + subnetAddress   : NodeAddress : Subnet address of the node.
// + maskBits        : int : Number of subnet masking bits.
// RETURN     :: void : NULL
// **/
static
void WEPParseConfigFile(Node* node,
                        int interfaceIndex,
                        const NodeInput* WEPConf,
                        NodeAddress subnetAddress,
                        int maskBits)
{
    int i;
    BOOL addEntry = FALSE;
    int lineLen = NI_GetMaxLen(WEPConf);
    char *token = (char*) MEM_malloc(lineLen);

    for (i = 0; i < WEPConf->numLines; i++)
    {
        const char* currentLine = WEPConf->inputStrings[i];
        char sourceAdd[MAX_STRING_LENGTH] = {0};
        char destAdd[MAX_STRING_LENGTH] = {0};
        char keytype[MAX_STRING_LENGTH] = {0};
        char keystr[MAX_STRING_LENGTH] = {0};

        WepCcmpKeyType keyType = WEP;
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
            if (strcmp(keytype, "WEP"))
            {
                ERROR_Assert(FALSE, "Wrong Key Type");
            }

            keyType = WEP;

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
            ERROR_Assert(FALSE, "Invalid Token in WEP");
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
// FUNCTION    :: WEPReadDelays
// LAYER       :: Mac
// PURPOSE     :: Function to read processing delay for RC4 encryption
//                algorithm.
// PARAMETERS  ::
// + node            : Node* : The node trying to read delays.
// + nodeInput       : const NodeInput* : QualNet main configuration file.
// + interfaceIndex  : int : Index of the Interface.
// RETURN      :: void : NULL
// **/
static
void WEPReadDelays(Node* node,
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
        "WEP-RC4-DELAY",
        &wasFound,
        buf);

    if (wasFound)
    {
        processingDelay = TIME_ConvertToClock(buf);
    }
    else
    {
        processingDelay = WEP_RC4_DELAY;
    }
    if (processingDelay < 0)
    {
         ERROR_Assert(FALSE,
             "The value of WEP-RC4-DELAY should be Positive\n");
    }
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    encData->processingDelay = processingDelay;
}

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
                            int numHostBits)
{
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    WepCcmpKeyMappings* temp = encData->first;

    while (temp != NULL)
    {
        if ((temp->TA.interfaceAddr.ipv4 == transmitterAdd.interfaceAddr.ipv4)
            && (temp->numHostBits == numHostBits))
        {
            return TRUE;
        }
        temp = temp->next;
    }
    return FALSE;
}

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
                                int interfaceIndex)
{
    BOOL excludeUnencrypted = FALSE;
    char buf[MAX_STRING_LENGTH];
    BOOL wasFound = FALSE;

    IO_ReadString(
        node,
        node->nodeId,
        interfaceIndex,
        nodeInput,
        "WEP-CCMP-ALLOW-UNENC",
        &wasFound,
        buf);

    if (wasFound)
    {
        if (!strcmp(buf, "YES"))
        {
            excludeUnencrypted = FALSE;
        }
        else
        {
            if (!strcmp(buf, "NO"))
            {
                excludeUnencrypted = TRUE;
            }
            else
            {
                char buffer[MAX_STRING_LENGTH];
                sprintf(buffer, "Invalid WEP-CCMP-ALLOW-UNENC value %s",
                                    buf);
                ERROR_ReportError(buffer);
            }
        }
    }
    else
    {
        excludeUnencrypted = WEP_CCMP_EXCLUDE_UNENCRYPTED;
    }
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
    encData->excludeUnencrypted = excludeUnencrypted;
}

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
int WepCcmpReadDestAdd(Node* node, char* destAdd, Address* transmitterAdd)
{
    NodeAddress outputNodeAddress = 0;
    int numHostBits = 0;
    BOOL isNodeId = FALSE;

    IO_ParseNodeIdHostOrNetworkAddress(
                    destAdd,
                    &outputNodeAddress,
                    &numHostBits,
                    &isNodeId
                    );

    if (numHostBits > 0) //Dest Address is a subnet address
    {
        transmitterAdd->interfaceAddr.ipv4 = outputNodeAddress;
        return numHostBits;
    }
    else
    {
        if (isNodeId)
        {
            ERROR_Assert(FALSE, "Destination address should be an IP\
                            address");
        }
        NodeAddress nodeId =
                        MAPPING_GetNodeIdFromInterfaceAddress(
                                node, outputNodeAddress);
        if (nodeId == INVALID_MAPPING)
        {
            ERROR_Assert(FALSE, "No node exists for given IP address");
        }
        else
        {
            transmitterAdd->interfaceAddr.ipv4 = outputNodeAddress;
            return 0;
        }
    }
    return 0;
}

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
            int numHostBits)
{
    NodeInput WEPInput;
    BOOL retVal = FALSE;

    node->macData[interfaceIndex]->encryptionVar  =
                                        MEM_malloc(sizeof(EncryptionData));
    memset(node->macData[interfaceIndex]->encryptionVar, 0,
                sizeof(EncryptionData));
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;

    encData->securityProtocol = MAC_SECURITY_WEP;

    NodeAddress nodeAddr = MAPPING_GetInterfaceAddressForInterface(
                            node, node->nodeId, interfaceIndex);

    IO_ReadCachedFile(node,
                      node->nodeId,
                      interfaceIndex,
                      nodeInput,
                      "WEP-CONFIG-FILE",
                      &retVal,
                      &WEPInput);

    if (!retVal)
    {
        ERROR_Assert(FALSE, "WEP configuration file missing");
    }

    WEPReadDelays(node, nodeInput, interfaceIndex);
    WepCcmpReadExcludeUnencrypted(node, nodeInput, interfaceIndex);
    WEPParseConfigFile(node, interfaceIndex, &WEPInput, subnetAddress,
                        numHostBits);
}
// /**
// FUNCTION   :: WEPEncryptPacket
// LAYER      :: Mac
// PURPOSE    :: Encrypt outbound packet with WEP.
// PARAMETERS ::
// + node            : Node*     : The node processing packet.
// + msg             : Message*  : Packet pointer.
// + interfaceIndex  : int : Index of the Interface.
// + destAddr        : Mac802Address : Next hop address.
// RETURN     :: BOOL   : TRUE if packet has encrypted, FALSE otherwise.
// **/
BOOL WEPEncryptPacket(Node* node,
                    Message* msg,
                    int interfaceIndex,
                    Mac802Address destAddr)
{
    BOOL wasFound = FALSE;
    EncryptionData* encData = (EncryptionData*)
                                node->macData[interfaceIndex]->encryptionVar;
     //Mac Address To Ip Address
            MacHWAddress destHWAddr;
            Convert802AddressToVariableHWAddress(node, &destHWAddr, &destAddr);
            NodeAddress ipdestAddr = MacHWAddressToIpv4Address(node, interfaceIndex, &destHWAddr);

    WepCcmpKeyMappings* temp = encData->first;
    while (temp != NULL)
    {
        if (temp->numHostBits > 0) //Subnet Address
        {
            BOOL isInSubnet = IsIpAddressInSubnet(
                                            ipdestAddr,
                                            temp->TA.interfaceAddr.ipv4,
                                            temp->numHostBits);
            if (isInSubnet)
            {
                if (temp->keytype == WEP)
                {
                    //Encrypt the packet
                    wasFound = TRUE;
                    break;
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
                    if (temp->keytype == WEP)
                    {
                        //Encrypt the packet
                        wasFound = TRUE;
                        break;
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
        MESSAGE_AddHeader(node, msg, WEP_FRAME_HDR_SIZE, TRACE_MACDOT11_WEP);
        //Adding dummy values into WEP header
        WEP_FrameHdr* hdr = (WEP_FrameHdr*) MESSAGE_ReturnPacket(msg);
        hdr->IV = 0;
        hdr->keyid = 0;
        hdr->pad = 0;
        (*msg).virtualPayloadSize += WEP_FRAME_ICV_SIZE;
        encData->stats.pktEncrypted++;
        return TRUE;
    } else
    {
        //Need not encrypt packet
        return FALSE;
    }
}


// /**
// FUNCTION   :: WEPDecryptPacket
// LAYER      :: Mac
// PURPOSE    :: Decrypt inbound packet with WEP.
// PARAMETERS ::
// + node           : Node*     :  The node processing packet.
// + msg            : Message*  :  Packet pointer.
// + interfaceIndex : int :  Index of the Interface.
// + sourceAddr     : Mac802Address : previous hop address.
// + protection     : BOOL : True if packet is WEP protected, FALSE
//                           otherwise.
// RETURN     :: BOOL   : TRUE if packet has decrypted, FALSE otherwise.
// **/
BOOL WEPDecryptPacket(Node* node,
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
        if (encData->excludeUnencrypted)
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
                    if (temp->keytype == WEP)
                    {
                        //Decrypt packet
                        wasFound = TRUE;
                        break;
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
                        if (temp->keytype == WEP)
                        {
                            //Decrypt packet
                            wasFound = TRUE;
                            break;
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
        }//end while
        if (wasFound)
        {
            encData->stats.pktDecrypted++;
            MESSAGE_RemoveHeader(node, msg,
                    WEP_FRAME_HDR_SIZE, TRACE_MACDOT11_WEP);
            (*msg).virtualPayloadSize -= WEP_FRAME_ICV_SIZE;
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
// FUNCTION   :: WEPFinalize()
// LAYER      :: Mac
// PURPOSE    :: Finalize function for the WEP model.
// PARAMETERS
// + node            :  Node * : Pointer to node.
// + interfaceIndex  : int : Index of the Interface.
// RETURN     :: void : NULL
// **/
void WEPFinalize(Node* node, int interfaceIndex)
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
        IO_PrintStat(node, "MAC", "WEP", intfAddr, -1, buf);
        sprintf(buf, "Packets Decrypted = %u", encData->stats.pktDecrypted);
        IO_PrintStat(node, "MAC", "WEP", intfAddr, -1, buf);
        sprintf(buf, "Packets Discarded = %u", encData->stats.excludedCount);
        IO_PrintStat(node, "MAC", "WEP", intfAddr, -1, buf);
        sprintf(buf, "Packets Undecrypted = %u",
                                        encData->stats.undecryptableCount);
        IO_PrintStat(node, "MAC", "WEP", intfAddr, -1, buf);
    }
}
