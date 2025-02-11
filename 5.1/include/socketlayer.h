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
#ifndef SOCKET_LAYER_H
#define SOCKET_LAYER_H


#define SL_MAX_SOCK_FDS 512
typedef struct sl_socket_data_str SLSocketData;

typedef struct socket_layer_data {
    SLSocketData *socketList[SL_MAX_SOCK_FDS];
    int nextPortNum;
} SLData;


void SocketLayerInit(
    Node *node,
    const NodeInput *nodeInput);

BOOL SocketLayerProcessEvent(
    Node *node,
    Message *msg);

#endif
