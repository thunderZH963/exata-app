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
// PROTOCOL     :: Logical Link Control
// LAYER        :: MAC
// REFERENCES   :: IEEE 802 standard
// COMMENTS     :: The type 1 process of LLC header implemented.
//                 The details of LLC is out of scope in this code
// **/

#include "api.h"
#include "partition.h"
#include "network.h"
#include "network_ip.h"
#include "mac_arp.h"
#include "mac.h"
#include "mac_llc.h"
#define DEBUG_LLC 0

// /**
// FUNCTION     :: LlcIsEnabled
// LAYER        :: MAC
// PURPOSE      :: Check the whether LLC is enabled or not
// PARAMETERS   ::
// + node : Node* : Pointer to node.
// + interface  : int : The interface on which the LLC works
// RETURN      :: BOOL : TRUE if LLC found otherwise FALSE
// **/
BOOL LlcIsEnabled(Node* node, int interfaceIndex)
{
    if (node->macData[interfaceIndex] != NULL &&
        node->macData[interfaceIndex]->isLLCEnabled)
    {
        return TRUE;
    }
    return FALSE;
}



// /**
// FUNCTION     :: LlcAddHeader
// LAYER        :: MAC
// PURPOSE      :: Add the LLC header type 1 of IEEE 802 standard
// PARAMETERS   ::
// + node : Node* : Pointer to node.
// + msg  : Message* : Incoming message to MAC
// + type  : unsigned int : Whether ARP packet or IP packet
// RETURN      :: void : nothing
// **/
void LlcAddHeader(
   Node* node,
   Message* msg,
   UInt16 type)
{
    LlcHeader *llcHeader;

    if(!msg)
    {
        return;
    }
    MESSAGE_AddHeader(node, msg, LLC_HEADER_SIZE, TRACE_LLC);
    llcHeader = (LlcHeader *) MESSAGE_ReturnPacket(msg);

    llcHeader->lsap.dsap = (unsigned char) LLC_DSAP;
    llcHeader->lsap.ssap = (unsigned char) LLC_SSAP;
    llcHeader->lsap.ctrl = (unsigned char) LLC_CONTROL_VALUE;
    memset(&(llcHeader->orgCode), LLC_PROTOCOL_ID, 3*sizeof(unsigned char));
    llcHeader->etherType = (UInt16) type;

    if (DEBUG_LLC)
    {
        printf("\n Node %d has Added the LLC Header\n",node->nodeId);
        LlcHeaderPrint(msg);
    }
}

// /**
// FUNCTION     :: LlcRemoveHeader
// LAYER        :: MAC
// PURPOSE      :: Remove the LLC header of type 1 IEEE 802
// PARAMETERS   ::
// + node : Node* : Pointer to node which received the message.
// + interfaceIndex : int : outgoing interface.
// + msg : Message*a : msg : outgoing message of MAC to IP or ARP
// RETURN       :: void : nothing
// **/
void LlcRemoveHeader(Node* node, Message* msg)
{
    if (DEBUG_LLC)
    {
       printf("\n Node %d Removing the LLC Header\n",node->nodeId);
       LlcHeaderPrint(msg);
    }

    MESSAGE_RemoveHeader(node, msg, LLC_HEADER_SIZE, TRACE_LLC);
}

// /**
// FUNCTION     :: LlcHeaderPrint
// LAYER        :: MAC
// PURPOSE      :: To print the Header information of LLC for debuging
// PARAMETERS   ::
// + mgs  : Message* : outgoing or incoming message of MAC of IP or
//                     ARP vice-versa
// RETURN       :: void : nothing
// **/
void LlcHeaderPrint(Message* msg)
{
    LlcHeader* llc;
    llc = (LlcHeader *) MESSAGE_ReturnPacket(msg);
    //printf("\n------------------------------------\n");
    printf("-----------LLC Header----------------\n");
    printf("-------------------------------------\n");
    printf("|DSAP %X SSAP %X cntl %X|\n",llc->lsap.dsap,
                                         llc->lsap.ssap, llc->lsap.ctrl);
    printf("------------------------------------\n");
    printf("|Org %X%X%X EtherType %X |",llc->orgCode[0],llc->orgCode[1]
                                        ,llc->orgCode[2], llc->etherType);
    printf("\n------------------------------------\n");

}
