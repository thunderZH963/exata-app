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
// PACKAGE     :: Logical Link Control header
// DESCRIPTION :: Data structures and parameters used in mac layer
//                are defined here.
// **/

#ifndef MAC_LLC_H
#define MAC_LLC_H

// /**
// CONSTANT    :: LLC_HEADER_SIZE : 8
// DESCRIPTION :: Size of ethernet frame header.
// **/
#define LLC_HEADER_SIZE              8

// /**
// CONSTANT    :: LLC_DSAP : 0xAA
// DESCRIPTION :: Destination Service Access Point
// **/
#define LLC_DSAP                     0xAA 

// /**
// CONSTANT    :: LLC_SSAP : 0xAA
// DESCRIPTION :: Source Service Access Point
// **/
#define LLC_SSAP                     0xAA

// /**
// CONSTANT    :: LLC_CONTROL_VALUE : 0x03
// DESCRIPTION :: Control value
// **/
#define LLC_CONTROL_VALUE            0x03 

// /**
// CONSTANT    :: LLC_PROTOCOL_ID : 0x000000
// DESCRIPTION :: Organization Code
// **/
#define LLC_PROTOCOL_ID              0x000000

// /**
// CONSTANT    :: PROTOCOL_TYPE_MPLS : 0x0FFF
// DESCRIPTION :: Ether Type Field value for protocol MPLS TYPE
// **/
#define PROTOCOL_TYPE_MPLS                   0x8847

// /**
// STRUCT      :: LlcLsapHeader
// DESCRIPTION :: Struture of the Service access point
// **/
typedef struct llc_lsap
{
   unsigned char dsap;      // dest service access point, 8 bits
   unsigned char ssap;      // source service access point, 8 bits
   unsigned char ctrl;      // Control, 8 bits
}LlcLsapHeader;


// /**
// STRUCT      :: LlcHeader
// DESCRIPTION :: Struture of LLC header
// **/
struct LlcHeader
{
    LlcLsapHeader lsap;

    unsigned char orgCode[3];
    //unsigned short etherType; //whether IP, ARP, RARP
    UInt16 etherType; //whether IP, ARP, RARP
};


// /**
// FUNCTION     :: LlcAddHeader
//LAYER         :: MAC
// PURPOSE      :: Add the LLC header with incomping packet to MAC
//                 NOTES- The type 1 process of LLC header implemented.
//                 The details of LLC is out of scope in this code
// PARAMETERS   ::
// + node : Node* : Pointer to node.
// + msg  : Message* : Incoming message to MAC
// + type  : unsigned int : Whether ARP packet or IP packet
// RETURN      :: void : nothing
// **/

void LlcAddHeader(
         Node* node, 
         Message* msg, 
         UInt16 type);

// /**
// FUNCTION     :: LlcRemoveHeader
// LAYER        :: MAC
// PURPOSE      :: Remove the LLC header of outgoing packet from MAC.
//                 NOTES- The type 1 process of LLC header implemented.
//                 The details of LLC is out of scope in this code
// PARAMETERS   ::
// + node : Node* : Pointer to node which received the message.
// + interfaceIndex : int : outgoing interface.
// + msg : Message*a : msg : outgoing message of MAC to IP or ARP
// RETURN       :: void : NULL
// **/
void LlcRemoveHeader(
         Node* node, 
         Message* msg);

// /**
// FUNCTION     :: LlcHeaderPrint
// LAYER        :: MAC
// PURPOSE      :: To print the Header information of LLC for debug
//                 NOTES-  The type 1 process of LLC header implemented.
//                 The details of LLC is out of scope in this code
// PARAMETERS   ::
// + msg  : Message* : outgoing or incoming message of MAC of IP or 
//                     ARP vice-versa
// RETURN       :: void : None
// **/
void LlcHeaderPrint(Message* msg);

// /**
// FUNCTION     :: LlcIsEnabled
// LAYER        :: MAC
// PURPOSE      :: Check the whether LLC is enabled or not
// PARAMETERS   ::
// + node : Node* : Pointer to node.
// + interface  : int : The interface on which the LLC works
// RETURN      :: BOOL : TRUE if LLC found otherwise FALSE
// **/
BOOL LlcIsEnabled(Node* node, int interfaceindex);


    
// /**
// FUNCTION     :: MAC_LLCHandOffSuccessfullyReceivedPacket
// LAYER         :: MAC
// PURPOSE      :: Remove the LLC header with outgoing packet from MAC
// PARAMETERS   ::
// + node : Node* : Pointer to node.
// + interfaceIndex : int : interface of the node 
// + msg  : Message* : Incoming message to MAC
// + lastHopAddress : NodeAddress  : last hop address
// RETURN      :: void : nothing
// **/

void
MAC_LLCHandOffSuccessfullyReceivedPacket(
    Node *node,
    int interfaceIndex,
    Message *msg,
    NodeAddress lastHopAddress);


#endif //MAC_LLC_H
