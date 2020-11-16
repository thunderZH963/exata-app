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
// use in compliance with the license agreement as part of the EXata
// software.  This source code and certain of the algorithms contained
// within it are confidential trade secrets of Scalable Network
// Technologies, Inc. and may not be used as the basis for any other
// software, hardware, product or service.

#ifndef _QUALNET_UPA_H_
#define _QUALNET_UPA_H_

#include "api.h"
#include "external.h"

#define UPA_DEV_MTU 1500
#define UPA_MTU (UPA_DEV_MTU - UPA_HDR_SIZE)

#define UPA_CONTROL_PORT        5134
#define UPA_DATA_PORT           5135
#define UPA_CONTROL_PORT_IPV6   5136
#define UPA_DATA_PORT_IPV6      5137
#define UPA_MULTICAST_PORT_IPV6 3134
#define WIN_AF_INET6    23
#define UNIX_AF_INET6   10

enum {
    EXTERNAL_MESSAGE_UPA_HandleIngressMessage,
    EXTERNAL_MESSAGE_UPA_HandleIngressData,
    EXTERNAL_MESSAGE_UPA_InsertHash,
    EXTERNAL_MESSAGE_UPA_SendPacket,
};

//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: UPA_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              UPAData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void UPA_Initialize(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: UPA_InitializeNodes
// PURPOSE   :: This function is where the bulk of the IPNetworkEmulator
//              initialization is done.  It will:
//                  - Parse the interface configuration data
//                  - Create mappings between real <-> qualnet proxy
//                    addresses
//                  - Create instances of the FORWARD app on each node that
//                    is associated with a qualnet proxy address
//                  - Initialize the libpcap/libnet libraries using the
//                    configuration data
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void UPA_InitializeNodes(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: UPA_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void UPA_Receive(EXTERNAL_Interface *iface);

// /**
// API       :: UPA_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void UPA_Forward(
    EXTERNAL_Interface *iface,
    Node *node,
    void *forwardData,
    int forwardSize);

// /**
// API       :: UPA_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void UPA_Finalize(EXTERNAL_Interface *iface);

void UPA_ProcessEvent(
    Node *node,
    void *arg);


void UPA_SendPacket(
    Node *node,
    int qualnet_fd,
    char *data,
    int dataSize,
    BOOL containsUpaHeader);


void UPA_CreateNewSocket(
    EXTERNAL_Interface* iface,
    Node* node,
    char* data,
    struct sockaddr* fromAddr);


void UPA_HandleIngressMessage(
    EXTERNAL_Interface *iface,
    struct sockaddr *fromAddr,
    int fromAddrLen,
    char *data,
    int length);

void UPA_HandleEgressPacket(
    Node *node,
    int qualnet_fd,
    char *data,
    int dataSize,
    struct sockaddr *fromAddr);

void UPA_TcpListen(
    Node *node,
    int qualnet_fd);

void UPA_TcpConnect(
    Node *node,
    int qualnet_fd,
    struct sockaddr *remoteAddr);

void UPA_SendDone(
    Node *node,
    int qualnet_fd,
    int length);

void UPA_TcpAccept(
    Node *node,
    int qualnet_fd);

void UPA_HandleExternalMessage(
    Node *node,
    Message *msg);

#endif 
