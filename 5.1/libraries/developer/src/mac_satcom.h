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

// Abstract satellite model.


#ifndef _SAT_COM_H_
#define _SAT_COM_H_

// Possible states.
typedef enum
{
    MAC_SATCOM_IDLE,
    MAC_SATCOM_BUSY
} MacSatStateType;


// Different type of satellite-related nodes.
typedef enum
{
    MAC_SATCOM_GROUND,
    MAC_SATCOM_SATELLITE,
    MAC_SATCOM_UNKNOWN
} MacSatComType;


//
// It is similar to the 802.3 header, but is 28 bytes
// (2 bytes longer than the 802.3 header and no padding for short packets)
//
typedef struct {
    char      framePreamble[8];
    NodeAddress sourceAddr;
    char      sourceAddrPadding[6 - sizeof(NodeAddress)];
    NodeAddress destAddr;
    char      destAddrPadding[6 - sizeof(NodeAddress)];
    char      length[2];
    char      checksum[4];
} MacSatComFrameHeader;


// Different statistics being collected
typedef struct {
    int packetsSent;
    int packetsReceived;
    int packetsRelayed;
} SatComStats;



typedef struct {
    MacData *myMacData;

    int satNodeIndex;

    int status;
    SubnetMemberData *nodeList;
    int numNodesInSubnet;

    SatComStats stats;

    MacSatComType type;
    clocktype uplinkDelay;
    clocktype downlinkDelay;

    BOOL userSpecifiedPropDelay;

#ifdef ADDON_DB
    // For phy summary table
    std::map<int, MacOneHopNeighborStats>* macOneHopData;
#endif

} MacSatComData;



// Name: MacSatComGetSubnetParameters
// Purpose: Get the parameters for a subnet.
// Parameter: node, node calling this function.
//            ipAddr, IP addres of the interface.
//            nodeInput, configuration file access.
//            networkType, Interface IP type
//            bandwidth, bandwidth of subnet.
//            userSpecifiedPropDelay, determines whether or not the user
//                                    specifies his/her own prop. delay.
//            uplinkDelay, uplink propagation delay of subnet.
//            downlinkDelay, downlink propagation delay of subnet.
// Return: Bandwidth, uplink and downlink propagation delay,
//         satellite type and Node ID

void
MacSatComGetSubnetParameters(
    Node* node,
    int interfaceIndex,
    Address* address,
    const NodeInput* nodeInput,
    Int64 *bandwidth,
    BOOL *userSpecifiedPropDelay,
    clocktype *uplinkDelay,
    clocktype *downlinkDelay);


// Name: MacSatComInit
// Purpose: Initialize SATCOM model.
// Parameter: node, node calling this function.
//            nodeInput, configuration file access.
//            interfaceIndex, interface to initialize.
//            nodeList, list of nodes in the subnet.
//            numNodesInSubnet, number of nodes in the subnet.
//            userSpecifiedPropDelay, determines whether or not the user
//                                    specifies his/her own prop. delay.
//            downlinkDelay, downlink propagation delay of subnet.
//            uplinkDelay, uplink propagation delay of subnet.
//            satType, satellite type to be returned
//            satelliteNodeId, Satellite node ID
//            subnetList, node list in subnet
// Return: TRUE if initialization was successful, FALSE otherwise.

BOOL
MacSatComInit(
    Node *node,
    const NodeInput* nodeInput,
    int interfaceIndex,
    int numNodesInSubnet,
    BOOL userSpecifiedPropDelay,
    clocktype uplinkDelay,
    clocktype downlinkDelay,
    const int subnetListIndex,
    SubnetMemberData* subnetList);


// Name: MacSatComNetworkLayerHasPacketToSend
// Purpose: Ground node has packets to send.
// Parameter: node, ground node.
//            satCom, SATCOM dataa structure.
// Return: None.

void
MacSatComNetworkLayerHasPacketToSend(
    Node *node,
    MacSatComData *satCom);


// Name: MacSatComLayer
// Purpose: Handle frames and timers.
// Parameter: node, node that is handling the frame or timer.
//            interfaceIndex, interface associated with frame or timer.
//            msg, frame or timer.
// Return: None.

void
MacSatComLayer(
    Node *node,
    int interfaceIndex,
    Message *msg);


// Name: MacSatComFinalize
// Purpose: Handle any finalization tasks.
// Parameter: node, node calling this function.
//            interfaceIndex, interface associated with the finalization tasks.
// Return: None.

void
MacSatComFinalize(
    Node *node,
    int interfaceIndex);



#endif /* _SAT_COM_H_ */

