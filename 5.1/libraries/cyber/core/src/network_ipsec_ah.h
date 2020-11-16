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

#ifndef IPSEC_AH_H
#define IPSEC_AH_H

#define AH_WORD_SIZE 4
#define AH_HALF_WORD_SIZE 2
#define AH_FIXED_HEADER_SIZE 12

struct IPsecAHAuthAlgoProfile
{
    // Name of the Authentication Algorithm
    IPsecAuthAlgo         auth_algo_name;
    // Stores the nane of the Authentication Algo Name
    char                  auth_algo_str[80];
    // Length in bytes for authorization algorithm
    unsigned char         authLen;
};

#define IPsecAHAuthAlgoDefaultProfileCount 7


// /**
// FUNCTION :: IPsecAHInit
// LAYER :: Network
// PURPOSE :: AH Initialization
// PARAMETERS ::
// + ah :: IPsecSecurityAssociationEntry* :: AH's SA.
// + authAlgoName :: IPsecAuthAlgo :: Authentication Algorithm name
// + authKey :: char* :: Authentication Key
// + rateParams :: IPsecProcessingRate* :: Processing rate.
// RETURN :: void.
// **/
void
IPsecAHInit(IPsecSecurityAssociationEntry* ah,
            IPsecAuthAlgo authAlgoName,
            char* authKey,
            IPsecProcessingRate* rateParams);


// /**
// FUNCTION :: IPsecAHProcessOutput
// LAYER :: Network
// PURPOSE :: Will Process Outbound AH Packet.
// PARAMETERS ::
// + node :: Node* :: The node processing packet.
// + msg :: Message* :: Packet pointer.
// + saPtr :: IPsecSecurityAssociationEntry* :: Pointer to SA.
// + interfaceIndex :: int :: Interface Index of the Node.
// RETURN :: clocktype :: Delay.
// **/
clocktype
IPsecAHProcessOutput(Node* node,
                     Message* msg,
                     IPsecSecurityAssociationEntry* saPtr,
                     int interfaceIndex,
                     bool* isSuccess);


// /**
// FUNCTION :: IPsecAHProcessInput
// LAYER :: Network
// PURPOSE :: Will Process Inbound AH Packet.
// PARAMETERS ::
// + node :: Node* :: The node processing packet.
// + msg :: Message* :: Packet pointer.
// + saPtr :: IPsecSecurityAssociationEntry* :: Pointer to SA.
// + interfaceIndex :: int :: Interface Index of the Node.
// RETURN :: clocktype :: Delay.
// **/
clocktype
IPsecAHProcessInput(Node* node,
                    Message* msg,
                    IPsecSecurityAssociationEntry* saPtr,
                    int interfaceIndex,
                    bool* isSuccess);

// /**
// FUNCTION   :: IPsecAHGetSPI
// LAYER      :: Network
// PURPOSE    :: Extarct AH SPI from message.
// PARAMETERS ::
//  +msg      :  Message* : Packet pointer
// RETURN     :: unsigned int : spi
// **/
unsigned int IPsecAHGetSPI(Message* msg);

#endif  // AH_H
