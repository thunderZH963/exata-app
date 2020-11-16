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

#ifndef INTERNET_GATEWAY_H
#define INTERNET_GATEWAY_H

#include <map>
//---------------------------------------------------------------------------
// External Interface Data structures
//---------------------------------------------------------------------------

typedef struct {
    unsigned short srcPort;
    unsigned short destPort;
    Address srcAddress;
    Address destAddress;
    char zero;
} AddressPortPair;

typedef struct {
    unsigned short natPort;
} GatewayNATData;

struct charStringCompareFunc 
{
    bool operator()(char const *a, char const *b) const
    {
        return strcmp(a, b) < 0;
    }
};

typedef struct {
    int rawSocketTcp;
    int rawSocketUdp;
    int rawSocketIcmp;

    unsigned int subnetAddress;
    unsigned int subnetMask;
    NodeAddress internetGateway; /* QualNet's Internet Gateway node */
    NodeAddress defaultInterfaceAddress; /* The interface on the Qualnet machine connecting to internet */
    
    NodeAddress internetRouter; /* Physical gateway that connect qualnet machine to internet */
    char internetRouterMacAddress[6]; /* mac address of the above device */ /* TODO: works for ethernet */
#define MAX_INTF_NAME_SIZE 64
    char defaultInterfaceName[MAX_INTF_NAME_SIZE];

    unsigned short lastNatPort;

    void *pcapHandle;
    void *libnetHandle;

    std::map<int, char*> *ingressNATTable;
    std::map<char*, int, charStringCompareFunc> *egressNATTable;

    in6_addr defaultIpv6InterfaceAddress;
    in6_addr ipv6InternetGateway;
    char ipv6InternetRouterMacAddress[6];
    char defaultIpv6InterfaceName[MAX_INTF_NAME_SIZE];
    void* ipv6PcapHandle;
    void* ipv6LibnetHandle;

} GatewayData;

//---------------------------------------------------------------------------
// External Interface API Functions
//---------------------------------------------------------------------------

// /**
// API       :: GATEWAY_Initialize
// PURPOSE   :: This function will allocate and initialize the
//              GATEWAYData structure
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + nodeInput : NodeInput* : The configuration file data
// RETURN    :: void
// **/
void GATEWAY_Initialize(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: GATEWAY_InitializeNodes
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
void GATEWAY_InitializeNodes(
    EXTERNAL_Interface *iface,
    NodeInput *nodeInput);

// /**
// API       :: GATEWAY_Receive
// PURPOSE   :: This function will handle receive packets through libpcap
//              and sending them through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void GATEWAY_Receive(EXTERNAL_Interface *iface);

// /**
// API       :: GATEWAY_Forward
// PURPOSE   :: This function will inject a packet back into the physical
//              network once it has travelled through the simulation.
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// + forwardData : void* : A pointer to the data to forward
// + forwardSize : int : The size of the data
// RETURN    :: void
// **/
void GATEWAY_Forward(
    EXTERNAL_Interface *iface,
    Node *node,
    void *forwardData,
    int forwardSize);

// /**
// API       :: GATEWAY_Finalize
// PURPOSE   :: This function will finalize the libpcap and libnet libraries
// PARAMETERS::
// + iface : EXTERNAL_Interface* : The interface
// RETURN    :: void
// **/
void GATEWAY_Finalize(EXTERNAL_Interface *iface);

void GATEWAY_ForwardToInternetGateway(
    Node *node,
    int interfaceIndex,
    Message *msg);

void GATEWAY_ForwardToIpv6InternetGateway(
    Node* node,
    int interfaceIndex,
    Message* msg);

#endif
