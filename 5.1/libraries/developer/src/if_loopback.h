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


#ifndef IF_LOOPBACK_H
#define IF_LOOPBACK_H

//--------------------------------------------------------------------------
// File     : if_loopback.h
//                 Header file for QualNet Loopback Interface Implementation.
//
// Objective: The Loopback interface enables a client and a server on the
//            same host to communicate with each other using TCP/IP.
//            This is a simple version which just enable QualNet applications
//            to connect to themselves.//
// References:
//
// Ref[1] TCP/IP Illustrated, Volume 1 - W. Richard Stevens
// Ref[2]  http://en.wikipedia.org/wiki/Loopback
// Ref[3]  http://www.linuxforum.com/linux-network-admin/node66.html
// Ref[4]  http://compnetworking.about.com/library/weekly/aa042400c.htm
// Ref[5]  http://www.dcs.bbk.ac.uk/~mick/academic/networks/msc/data-link/loopback.shtml#stevens1994
//
// The implemented feature are as follows:
// 1. Allows a client and server on the same host to communicate
//    with each other using TCP/IP
// 2. Everything sent to the loopback address (normally 127.0.0.1)
//    appears as IP input.
// 3. Datagrams sent to a broadcast address or a multicast address are
//    copied to the loopback interface and sent out on the Ethernet.
//    This is because the definition of broadcasting and multicasting
//    includes the sending host.
// 4. Anything sent to one of the host's own IP addresses is sent to
//    the loopback interface.
//
//--------------------------------------------------------------------------

// /**
// CONSTANT    :: IP_LOOPBACK_ADDRESS   : 0x7F000000
// DESCRIPTION :: The class A network ID 127.0.0.0 is reserved for loopback.
//                The scope of the loop back address is 127.xxx.xxx.xxx.
//                The default loop back address is 127.0.0.1.
// **/

#define IP_LOOPBACK_ADDRESS         0x7F000000

// /**
// CONSTANT    :: IP_LOOPBACK_MASK   : 0xFF000000
// DESCRIPTION :: The class A network mask 255.0.0.0.
// **/

#define IP_LOOPBACK_MASK            0xFF000000

// /**
// CONSTANT    :: IP_LOOPBACK_DEFAULT_INTERFACE   : 0xFF000001
// DESCRIPTION :: The default loopback address  255.0.0.1.
// **/

#define IP_LOOPBACK_DEFAULT_INTERFACE  0x7F000001

// /**
// CONSTANT    :: IP_LOOPBACK_MAX_NUM_ENTRY   : 4
// DESCRIPTION :: Minimum number of rows in loopback table.
// **/

#define IP_LOOPBACK_MAX_NUM_ENTRY   4


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpIsLoopbackInterfaceAddress()
// PURPOSE      Checks for loopback address, 127.xxx.xxx.xxx.
// PARAMETERS   NodeAddress address
//                  IPv4 address.
// RETURN       (BOOL) TRUE for loopback address
//                     FALSE otherwise
//---------------------------------------------------------------------------

BOOL NetworkIpIsLoopbackInterfaceAddress(NodeAddress address);


//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableDisplay()
// PURPOSE      Display all entries in node's routing table for loopback.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackForwardingTableDisplay(Node *node);

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackBroadcastAndMulticastToSender()
// PURPOSE
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to msg
// RETURN       None.
//---------------------------------------------------------------------------

BOOL NetworkIpLoopbackLoopbackUnicastsToSender(
    Node* node,
    Message *msg);

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackBroadcastAndMulticastToSender()
// PURPOSE      Datagrams sent to a broadcast address or a multicast address
//              are copied to the loopback interface & sent out on Ethernet.
//              This is because the definition of broadcasting & multicasting
//              includes the sending host. - Ref [1]
// PARAMETERS   Node *node
//                  Pointer to node.
//              Message *msg
//                  Pointer to msg
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackBroadcastAndMulticastToSender(
    Node* node,
    Message *msg);

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackForwardingTableInit()
// PURPOSE      Initialize the IP Loopback fowarding table.
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackForwardingTableInit(Node *node);

//---------------------------------------------------------------------------
// FUNCTION     NetworkIpLoopbackInit()
// PURPOSE      The purpose of this function is Ip Loopback Interface
//              Configuration. By default loopback is enabled.
//              To disable this feature specify :
//
//              [node-id] IP-ENABLE-LOOPBACK   NO
//
//              If loopback is enabled, default loopback interface address
//              is IP_LOOPBACK_DEFAULT_INTERFACE, i.e., 127.0.0.1
//              If user want to configure default Loopback Interface Address,
//              the syntax is:
//
//              [node-id] IP-LOOPBACK-ADDRESS <loopback-interface-address>
//
// PARAMETERS   Node *node
//                  Pointer to node.
// RETURN       None.
//---------------------------------------------------------------------------

void NetworkIpLoopbackInit(Node *node, const NodeInput *nodeInput);


#endif // _IF_LOOPBACK_H_
