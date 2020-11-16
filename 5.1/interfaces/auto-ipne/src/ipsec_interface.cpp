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

#include <stdio.h>

#include "pcap.h"
#include "libnet.h"

#ifndef _NETINET_IN_H
#define _NETINET_IN_H
#endif

#include "api.h"
#include "partition.h"
#include "app_util.h"
#include "external.h"
#include "external_socket.h"
#include "auto-ipnetworkemulator.h"
//MTree Fix start
#include "network_ip.h"
//MTree Fix end
#include "ipsec_interface.h"
#ifdef CYBER_CORE
#include "network_ipsec_esp.h"

//**
// FUNCTION   :: ESPPacketHandler::ReformatIncomingPacket()
// LAYER      :: Network
// PURPOSE    :: Reformat incoming ESP packet.
// PARAMETERS ::
// + packet   :: unsigned char* : Incoming ESP packet to be formated.
// RETURN     :: void : NULL
//**
void ESPPacketHandler::ReformatIncomingPacket(unsigned char* packet)
{
    unsigned char* dataPtr = packet;

    // Swap bytes from network byte order to host byte order
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
}

//**
// FUNCTION   :: ESPPacketHandler::ReformatOutgoingPacket()
// LAYER      :: Network
// PURPOSE    :: Reformat outgoing ESP packet.
// PARAMETERS ::
// + packet   :: unsigned char* : Outgoing ESP packet to be formated.
// RETURN     :: void : NULL
//**
void ESPPacketHandler::ReformatOutgoingPacket(unsigned char* packet)
{
    unsigned char* dataPtr = packet;

    // Swap bytes from host byte order to network byte order
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
}

///**
// FUNCTION   :: AHPacketHandler::ReformatIncomingPacket()
// LAYER      :: Network
// PURPOSE    :: Reformat incoming AH packet.
// PARAMETERS ::
// + packet   :: unsigned char* : Incoming AH packet to be formated.
// RETURN     :: void : NULL
//**
void AHPacketHandler::ReformatIncomingPacket(unsigned char* packet)
{
    unsigned char* dataPtr = packet;

    // Swap bytes from network byte order to host byte order
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
}

//**
// FUNCTION   :: AHPacketHandler::ReformatOutgoingPacket()
// LAYER      :: Network
// PURPOSE    :: Reformat outgoing AH packet.
// PARAMETERS ::
// + packet   :: unsigned char* : Outgoing AH packet to be formated.
// RETURN     :: void : NULL
//**
void AHPacketHandler::ReformatOutgoingPacket(unsigned char* packet)
{
    unsigned char* dataPtr = packet;

    // Swap bytes from host byte order to network byte order
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
    dataPtr += ESP_SPI_SIZE;
    EXTERNAL_ntoh(dataPtr, ESP_SPI_SIZE);
}
#endif //CYBER_CORE
