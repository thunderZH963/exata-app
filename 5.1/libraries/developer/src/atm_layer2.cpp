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
//
//
// /**
// PROTOCOL     :: Atm_layer2.
// LAYER        :: ATM_LAYER2.
// REFERENCES   ::
//              RFC: 2225 for Classical IP and ARP over ATM
//              RFC: 2684 for Multi-protocol Encapsulation over
//                 ATM Adaptation Layer 5
//              ATM Forum Addressing Specification:
//              Reference Guide AF-RA-0106.000
// Assumtion :: 1. Two End System not connected by a Atm Link, There must
//               have some Atm Switches.
//            2. Point to point wire link.
//            3. Asymmetric connection.
//            4. Generic Flow Control is omitted.
// **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "api.h"
#include "partition.h"
#include "atm_queue.h"
#include "sch_atm.h"
#include "atm.h"
#include "adaptation_aal5.h"
#include "atm_layer2.h"

#ifdef PARALLEL // Parallel
#include "parallel.h"
#endif // endParallel


#define DEBUG 0
#define ASYNCHRONOUS_TEST_DEBUG 0

#define ATM_DEFAULT_QUEQE_SIZE 15000



// ----------------------------------------------------------------------
// Initialization
// ----------------------------------------------------------------------


// /**
// FUNCTION   :: Atm_Layer2GetAtmData
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Retrive AtmData ptr for particular interface of a node.
// PARAMETERS ::
// + node     : Node*    : The node
// + interfaceIndex      : int : Interface Index
// RETURN     : AtmLayer2Data* : AtmLayer2Data pointer.
// **/

AtmLayer2Data* Atm_Layer2GetAtmData(Node* node,
                                    int interfaceIndex)
{
    return (node->atmLayer2Data[interfaceIndex]);
}


// /**
// FUNCTION   :: Atm_Layer2GetAddForThisInterface
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Get Atm address Retrive AtmData ptr for
//               particular interface of a node.
// PARAMETERS ::
// + node     : Node*    : The node
// + interfaceIndex      : int : Interface Index
// RETURN     : AtmAddress : Atm address of the specified
//                           inteface of that node
// **/
static
AtmAddress Atm_Layer2GetAddForThisInterface(
                                            Node* node,
                                            int interfaceIndex)
{
    Address addr = MAPPING_GetInterfaceAddressForInterface(
        node, node->nodeId, NETWORK_ATM, interfaceIndex);

    if (addr.networkType != NETWORK_ATM)
    {
        ERROR_ReportError("ATM-INTERFACE: NOT a valid Interface.\n");
    }
    return (addr.interfaceAddr.atm);
}


// /**
// FUNCTION   :: Atm_Layer2GetInterface
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Get Interface for a particular Atm address.
// PARAMETERS ::
// + node     : Node*    : The node
// + linkAddressString : char* : Get interface for this address string.
// + interfaceIndex      : int* : Interface Index for atm address
// + interfaceAddress : NodeAddress* : Interface Address for atm address
// RETURN     : void : NULL
// **/
static
void Atm_Layer2GetInterface(Node* node,
                            char* linkAddressString,
                            int* interfaceIndex,
                            NodeAddress* interfaceAddress)
{
    char network[MAX_STRING_LENGTH] = {0};
    NodeAddress outputNodeAddress = 0;
    int numHostBits = 0;

    sscanf(linkAddressString, "%s\n", network);

    IO_ParseNetworkAddress(
        linkAddressString,
        &outputNodeAddress,
        &numHostBits);

    *interfaceAddress = MAPPING_GetInterfaceAddressForSubnet(
        node,
        node->nodeId,
        outputNodeAddress,
        numHostBits);

    *interfaceIndex = MAPPING_GetInterfaceIdForDestAddress(
        node,
        node->nodeId,
        *interfaceAddress);

    if (*interfaceIndex < 0)
    {
        char errorStr[MAX_STRING_LENGTH] = {0};

        sprintf(errorStr,
            "Network configuration for Router %u not proper\n"
            "Corresponding network statement is %s\n",
            node->nodeId,
            network);
        ERROR_ReportError(errorStr);
    }
}


// /**
// FUNCTION   :: Atm_Layer2AddQueue
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Add a queue with specific queue index into particular
//               interface.
// PARAMETERS ::
// + node      : Node*    : The node
// + nodeInput : const NodeInput* : Pointer to Node Input
// + interfaceIndex      : int : Interface Index for atm address
// + queueIndex : int: index of queue
// RETURN     : void : NULL
// **/
static
void Atm_Layer2AddQueue(Node *node,
                        const NodeInput *nodeInput,
                        int interfaceIndex,
                        int queueIndex)
{
    BOOL wasFound = FALSE;
    AtmRedQueue* queue = NULL;
    int queueSize;
    BOOL enableQueueStat = false;
    float weight = 0.0;
    RedParameters* redParams = NULL;
    char addStr[MAX_STRING_LENGTH];
    AtmLayer2Data* atmData = Atm_Layer2GetAtmData(node, interfaceIndex);
    void* spConfigInfo = NULL; // Queue Specific configurations.

    Address addr = MAPPING_GetInterfaceAddressForInterface(
        node, node->nodeId, NETWORK_ATM, interfaceIndex);


    IO_ConvertAtmAddressToString(addr.interfaceAddr.atm, addStr);

    IO_ReadIntInstance(
        node->nodeId,
        &addr,
        nodeInput,
        "ATM-QUEUE-SIZE",
        queueIndex,                 // parameterInstanceNumber
        TRUE,              // fallbackIfNoInstanceMatch
        &wasFound,
        &queueSize);

    if (!wasFound)
    {
        queueSize = ATM_DEFAULT_QUEQE_SIZE;
    }

    //GuiAtmStart

    if (node->guiOption==TRUE)
    {
        GUI_AddInterfaceQueue(node->nodeId,
            GUI_MAC_LAYER,
            interfaceIndex,
            queueIndex,
            queueSize,
            node->getNodeTime());
    }

    //GuiAtmEnd

    ReadRedConfigurationParameters(node,
        addr,
        nodeInput,
        enableQueueStat,
        queueIndex,
        &redParams);

    spConfigInfo = (void*)(redParams);

    // Initialize Queue depending on queueTypeString specification
    QUEUE_Setup(node,
        (Queue**)&queue,
        "ATM-RED",
        queueSize,
        interfaceIndex,
        queueIndex,
        0, // infoFieldSize
        enableQueueStat,
        true,
        node->getNodeTime(),
        spConfigInfo);

    // Scheduler add Queue Functionality
    atmData->atmScheduler->addQueue(queue, queueIndex, weight);
}


// /**
// FUNCTION   :: Atm_Layer2InitOutputQueueConfiguration
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Initializes ATM interface queue parameters during startup.
// PARAMETERS ::
// + node      : Node*    : The node
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + interfaceIndex      : int : Interface associated with queue
// RETURN     : void : NULL
// **/
static
void Atm_Layer2InitOutputQueueConfiguration(Node *node,
                                            const NodeInput *nodeInput,
                                            int interfaceIndex)
{
    char addStr[MAX_STRING_LENGTH];
    AtmScheduler* schedulerPtr = NULL;
    BOOL enableSchedulerStat = false;
    int i, j, k;
    BOOL wasFound = FALSE;
    char buf[MAX_STRING_LENGTH] = {0};


    AtmLayer2Data* atmData = Atm_Layer2GetAtmData(node, interfaceIndex);


    //    Atm_Layer2GetAddForThisInterface(node, interfaceIndex, &atmAddress);
    Address addr = MAPPING_GetInterfaceAddressForInterface(
        node, node->nodeId, NETWORK_ATM, interfaceIndex);

    IO_ConvertAtmAddressToString(addr.interfaceAddr.atm, addStr);

    // Read if Scheduler Statistics is enabled
    IO_ReadString(
        node->nodeId,
        &addr,
        nodeInput,
        "ATM-SCHEDULER-STATISTICS",
        &wasFound,
        buf);

    if (wasFound && (!strcmp(buf, "YES")))
    {
        enableSchedulerStat = true;
    }

    // Set the Scheduler
    SCHEDULER_Setup((Scheduler**)&schedulerPtr,
        "ATM",
        enableSchedulerStat);

    schedulerPtr->AtmSetTotalBW(atmData->bandwidth);
    atmData->atmScheduler = schedulerPtr;

    //add the queue dynamically when it needed
    for (i = 0; i <= node->numAtmInterfaces; i++)
    {
        Atm_Layer2AddQueue(node, nodeInput, interfaceIndex, i);
    }

    for (j = 0; j < interfaceIndex; j++)
    {
        AtmLayer2Data* tempAtmData = Atm_Layer2GetAtmData(node, j);

        for (k = tempAtmData->atmScheduler->numQueue();
        k < (node->numAtmInterfaces + 1); k++)
        {
            Atm_Layer2AddQueue(node, nodeInput, j, k);
        }
    }
}

// /**
// FUNCTION   :: Atm_Layer2InterfaceInitialize
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Interface initialization function for the ATM Layer2.
// PARAMETERS ::
// + node      : Node*    : pointer to the first node.
// + interfaceIndex  : int    : interface Index used.
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + nodeType  : BOOL : first node type
// + linkNodeType : BOOL : other node type
// + otherNode :: Node* : node pointer of opposite interface
//                        of the atm link.
// + otherNodeInterfaceIndex : int : interface of the other node
// + otherNodeId : NodeAddress : other node id
// RETURN     : void : NULL
// **/
void Atm_Layer2InterfaceInitialize(
                                   Node* node,
                                   int interfaceIndex,
                                   const NodeInput* nodeInput,
                                   BOOL nodeType,
                                   BOOL linkNodeType,
                                   Node* otherNode,
                                   int otherNodeInterfaceIndex,
                                   NodeAddress otherNodeId)
{
    int bandwidth;
    BOOL wasFound;
    clocktype propDelay;
    char yesOrNo[MAX_STRING_LENGTH];
    char addStr[MAX_STRING_LENGTH];

    node->numAtmInterfaces++;

    AtmLayer2Data* atmLayer2Data =
        (AtmLayer2Data*) MEM_malloc(sizeof(AtmLayer2Data));

    ERROR_Assert(atmLayer2Data != NULL, "Insufficient memory space\n");
    memset(atmLayer2Data, 0, sizeof(AtmLayer2Data));

    node->atmLayer2Data[interfaceIndex] = atmLayer2Data;


    Address addr = MAPPING_GetInterfaceAddressForInterface(
        node, node->nodeId, NETWORK_ATM, interfaceIndex);

    IO_ConvertAtmAddressToString(addr.interfaceAddr.atm, addStr);

    IO_ReadString(
        node->nodeId,
        &addr,
        nodeInput,
        "ATM-LAYER2-STATISTICS",
        &wasFound,
        yesOrNo);

    if (!wasFound || strcmp(yesOrNo, "NO") == 0)
    {
        atmLayer2Data->atmLayer2Stats = FALSE;
    }
    else if (strcmp(yesOrNo, "YES") == 0)
    {
        atmLayer2Data->atmLayer2Stats = TRUE;
    }
    else
    {
        ERROR_ReportError(
            "Expecting YES or NO for ATM-LAYER2-STATISTICS\n");
    }

    if (!nodeType)
    {
        atmLayer2Data->nodeType = ATM_LAYER2_ENDSYSTEM;
    }
    else
    {
        atmLayer2Data->nodeType = ATM_LAYER2_SWITCH;
    }


    atmLayer2Data->atmLayer2InfIsEnabled = TRUE;
    atmLayer2Data->otherNode = otherNode;
    atmLayer2Data->otherNodeId = otherNodeId;

    if ((!nodeType && linkNodeType) || (nodeType && !linkNodeType))
    {
        atmLayer2Data->interfaceType = ATM_LAYER2_INTF_UNI;
    }
    else
    {
        atmLayer2Data->interfaceType = ATM_LAYER2_INTF_NNI;
    }

    IO_ReadInt(
        node->nodeId,
        &addr,
        nodeInput,
        "ATM-LAYER2-LINK-BANDWIDTH",
        &wasFound,
        &bandwidth);

    if (!wasFound)
    {
        bandwidth = ATM_LAYER2_LINK_DEFAULT_BANDWIDTH;
    }
    else if (bandwidth < 0)
    {
        char errorStr[MAX_STRING_LENGTH];
        sprintf(errorStr, "ATM-LAYER2-LINK-BANDWIDTH for %s "
            "needs to be >= 0.\n", addStr);
        ERROR_ReportError(errorStr);
    }
    atmLayer2Data->bandwidth = bandwidth;

    atmLayer2Data->interfaceIndex = interfaceIndex;
    atmLayer2Data->otherNodeInterfaceIndex = otherNodeInterfaceIndex;

    IO_ReadTime(
        node->nodeId,
        &addr,
        nodeInput,
        "ATM-LAYER2-LINK-PROPAGATION-DELAY",
        &wasFound,
        &propDelay);

    if (!wasFound)
    {
        propDelay = ATM_LAYER2_LINK_DEFAULT_PROPAGATION_DELAY;
    }
    else if (propDelay < 0)
    {
        char errorStr[MAX_STRING_LENGTH];

        sprintf(errorStr,
            "ATM-LAYER2-LINK-PROPAGATION-DELAY for %s "
            "needs to be >= 0.\n", addStr);
        ERROR_ReportError(errorStr);
    }
    atmLayer2Data->propDelay = propDelay;

    Atm_Layer2InitOutputQueueConfiguration(node, nodeInput, interfaceIndex);

    //If end system Read Logical IP Subnet.
    atmLayer2Data->logicalSubnet = NULL;

    if (atmLayer2Data->nodeType == ATM_LAYER2_ENDSYSTEM)
    {
        atmLayer2Data->logicalSubnet = AtmReadLogicalSubnetAtEndNode(
            node,
            nodeInput,
            interfaceIndex);
    }

    //GuiAtmStart
    if (node->guiOption)
    {
        GUI_AddLink(node->nodeId,
            otherNode->nodeId,
            (GuiLayers) GUI_MAC_LAYER,
            GUI_ATM_LINK_TYPE,
            addr.interfaceAddr.atm.ICD,
            addr.interfaceAddr.atm.aid_pt1,
            addr.interfaceAddr.atm.aid_pt2,
            node->getNodeTime());
    }
    //GuiAtmEnd

    PARALLEL_SetProtocolIsNotEOTCapable(node);
    PARALLEL_SetMinimumLookaheadForInterface
            (node, propDelay);

}


// /**
// FUNCTION   :: ProcessInputFileLinkLineForAtm
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Parse the link line from the configuration
//               file for ATM Link.
// PARAMETERS ::
// + partitionData : PartitionData* : partition data
// + nodeInput : const NodeInput* : Pointer to NodeInput
// + linkLine : const char : current line of the node input
// RETURN     :: void : NULL
// **/
static
void ProcessInputFileLinkLineForAtm(PartitionData* partitionData,
                                    const NodeInput* nodeInput,
                                    const char linkLine[])
{
    char errorString[MAX_STRING_LENGTH];
    char linkAddressString[MAX_ADDRESS_STRING_LENGTH];
    char addrStr1[MAX_ADDRESS_STRING_LENGTH];
    char addrStr2[MAX_ADDRESS_STRING_LENGTH];
    NodeAddress nodeId1;
    NodeAddress nodeId2;
    Node* node1;
    Node* node2;
    Node* referenceNode1;
    Node* referenceNode2;

    int retVal;

    unsigned int u_atmVal[] = {0, 0, 0};

    Address address1;
    Address address2;

    int node1InterfaceIndex;
    int node2InterfaceIndex;

    int node1AtmInterface;
    int node2AtmInterface;
    int node1GenericInterface;
    int node2GenericInterface;

    BOOL node1IsAtmSwitch = TRUE;
    BOOL node2IsAtmSwitch = TRUE;

    char buf[MAX_STRING_LENGTH];

    retVal = sscanf(linkLine,
        "%s { %u, %u }",
        linkAddressString,
        &nodeId1,
        &nodeId2);

    IO_ParseNetworkAddress(linkAddressString, u_atmVal);

    if (retVal != 3)
    {
        sprintf(errorString, "Bad LINK declaration:\n  %s\n", linkLine);
        ERROR_ReportError(errorString);
    }

    int pIndex;
    pIndex = PARALLEL_GetPartitionForNode(nodeId1);

    if (pIndex == partitionData->partitionId) {
        node1 = MAPPING_GetNodePtrFromHash(
                    partitionData->nodeIdHash, nodeId1);
    }
    else {
        node1 = MAPPING_GetNodePtrFromHash(
                    partitionData->remoteNodeIdHash, nodeId1);
    }

    pIndex = PARALLEL_GetPartitionForNode(nodeId2);

    if (pIndex == partitionData->partitionId) {
        node2 = MAPPING_GetNodePtrFromHash(
                    partitionData->nodeIdHash, nodeId2);
    }
    else {
        node2 = MAPPING_GetNodePtrFromHash(
                    partitionData->remoteNodeIdHash, nodeId2);
    }

    referenceNode1 = node1;
    referenceNode2 = node2;

    node1InterfaceIndex = referenceNode1->numAtmInterfaces;
    node2InterfaceIndex = referenceNode2->numAtmInterfaces;

    address1 = MAPPING_GetNodeInfoFromAtmNetInfo(referenceNode1,
        referenceNode1->nodeId,
        &node1AtmInterface,
        &node1GenericInterface,
        u_atmVal);

    address2 = MAPPING_GetNodeInfoFromAtmNetInfo(referenceNode2,
        referenceNode2->nodeId,
        &node2AtmInterface,
        &node2GenericInterface,
        u_atmVal);

    ERROR_Assert((node1GenericInterface != -1
        && node1AtmInterface == node1InterfaceIndex),
        "ATM-INTERAFCE: Error in between Mapping & Partition\n");

    ERROR_Assert((node2GenericInterface != -1
        && node2AtmInterface == node2InterfaceIndex),
        "ATM-INTERAFCE: Error in between Mapping & Partition\n");

    IO_ConvertAtmAddressToString(address1.interfaceAddr.atm, addrStr1);
    IO_ConvertAtmAddressToString(address2.interfaceAddr.atm, addrStr2);

    if (DEBUG)
    {
        printf("Node %d assigning Address (%s) to AtmInf %d,GenInf %d, partition %d\n",
            referenceNode1->nodeId,
            addrStr1,
            node1AtmInterface,
            node1GenericInterface,
            referenceNode1->partitionId);

        printf("Node %d assigning Address (%s) to AtmInf %d,GenInf %d, partition %d\n",
            referenceNode2->nodeId,
            addrStr2,
            node2AtmInterface,
            node2GenericInterface,
            referenceNode2->partitionId);
    }

    // Check the type of ATM-NODE i.e.
    // if it is ATM-END-SYSTEM or ATM-SWITCH
    IO_ReadString(
        referenceNode1->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-END-SYSTEM",
        &retVal,
        buf);
    if (retVal && !strcmp(buf, "YES"))
    {
        node1IsAtmSwitch = FALSE;
    }

    IO_ReadString(
        referenceNode2->nodeId,
        ANY_ADDRESS,
        nodeInput,
        "ATM-END-SYSTEM",
        &retVal,
        buf);

    if (retVal && !strcmp(buf, "YES"))
    {
        node2IsAtmSwitch = FALSE;
    }

    if (!node1IsAtmSwitch && !node2IsAtmSwitch)
    {
        sprintf(errorString, "Bad ATM LINK, Both are End User\n");
        ERROR_ReportError(errorString);
    }

    //if ((node1 == NULL) || (node2 == NULL))
    if ((referenceNode1 == NULL) || (referenceNode2 == NULL))
    {
        ERROR_ReportError("ATM-LINK: Error initializing.\n");
    }

    // Initiatize the interface for FIRST NODE (node1)
    Atm_Layer2InterfaceInitialize(referenceNode1, node1InterfaceIndex,
        nodeInput, node1IsAtmSwitch, node2IsAtmSwitch,
        referenceNode2, node2InterfaceIndex, nodeId2);

    // Initiatize the interface for SCEOND NODE (node2)
    Atm_Layer2InterfaceInitialize(referenceNode2, node2InterfaceIndex,
        nodeInput, node2IsAtmSwitch, node1IsAtmSwitch,
        referenceNode1, node1InterfaceIndex, nodeId1);
/*
    // Initiatize the interface for FIRST NODE (node1)
    Atm_Layer2InterfaceInitialize(node1, node1InterfaceIndex,
        nodeInput, node1IsAtmSwitch, node2IsAtmSwitch,
        node2, node2InterfaceIndex, nodeId2);

    // Initiatize the interface for SCEOND NODE (node2)
    Atm_Layer2InterfaceInitialize(node2, node2InterfaceIndex,
        nodeInput, node2IsAtmSwitch, node1IsAtmSwitch,
        node1, node1InterfaceIndex, nodeId1);
*/

    if (DEBUG)
    {
        printf("%d assigning address %s to node %d at ATM interface %d\n",
            referenceNode1->partitionData->partitionId, addrStr1,
            referenceNode1->nodeId, referenceNode1->numAtmInterfaces);

        printf("%d assigning address %s to node %d at ATM interface %d\n",
            referenceNode2->partitionData->partitionId,addrStr2,
            referenceNode2->nodeId, referenceNode2->numAtmInterfaces);
    }
}


// /**
// FUNCTION   :: ATMLAYER2_Initialize
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Initialization function for the ATM Layer2.
// PARAMETERS ::
// + node : Node* : The Node
// + nodeInput : const NodeInput* : Pointer to NodeInput
// RETURN     :: void : NULL
// **/
void ATMLAYER2_Initialize(Node* node,
                          const NodeInput* nodeInput)
{
    int i;

    for (i = 0; i < nodeInput->numLines; i++)
    {
        if (strcmp(nodeInput->variableNames[i], "ATM-LINK") == 0)
        {
            ProcessInputFileLinkLineForAtm(node->partitionData,
                nodeInput,
                nodeInput->values[i]);
        }
    }
}



// ----------------------------------------------------------------------
// Layer Function
// ----------------------------------------------------------------------

// /**
// FUNCTION   :: Atm_Layer2CreateIdleCell
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Create a idle cell
// PARAMETERS ::
// + node : Node* : The Node Pointer
// RETURN     : Message* : pointer to Message
// **/
static
Message* Atm_Layer2CreateIdleCell(Node* node)
{
    Message* msg = MESSAGE_Alloc(node, ATM_LAYER2, 0, 0);

    MESSAGE_PacketAlloc(node,
        msg,
        ATM_CELL_LENGTH,
        TRACE_ATM_LAYER);

    char* packet = MESSAGE_ReturnPacket(msg);
    memset(packet, 0, ATM_CELL_LENGTH);

    unsigned int temp = 1;
    memcpy(packet, &temp, 4);
    return msg;
}

// /**
// FUNCTION   :: Atm_Layer2HasCellToSend
// LAYER      :: ATM_LAYER2
// PURPOSE    :: queue has packet to send.
// PARAMETERS ::
// +  node : Node* : The Node Pointer
// +  interfaceIndex : int : at this interface.
// +  atmScheduler : AtmScheduler* : atm scheduler at this interface.
// RETURN     : void : NULL
// **/
static
void Atm_Layer2HasCellToSend(Node* node,
                             int interfaceIndex,
                             AtmScheduler* atmScheduler)
{
    clocktype transmissionDelay;
    Message* msgList = NULL;
    Message* lastMsg = NULL;
    Message* nextMsg = NULL;
    Message* transmissionFinishedMsg = NULL;
    Message* newMsg = NULL;
    int i = 0;
    int queuePriority;

    AtmLayer2Data* atmLayer2Data =
        Atm_Layer2GetAtmData(node, interfaceIndex);

    if (atmLayer2Data->atmLinkStatus == ATM_LAYER2_LINK_IS_BUSY) {
        if (DEBUG)
        {
            printf("    channel is busy, so have to wait\n");
        }
        return;
    }

    if (DEBUG)
    {
        printf("    channel is idle\n");
    }

    for (i = 0; i < ATM_NUM_CELL_IN_FRAME; i++)
    {
        if (DEBUG)
        {
            printf("Node %u try to RETRIVE PACKET at Inf %d, numpkt %d\n",
                node->nodeId,
                interfaceIndex,
                atmScheduler->numberInQueue(ALL_PRIORITIES));
        }

        atmScheduler->retrieve(ALL_PRIORITIES,
            DEQUEUE_NEXT_PACKET,
            &nextMsg,
            &queuePriority,
            DEQUEUE_PACKET,
            node->getNodeTime());
        if (nextMsg == NULL)
        {
            if (DEBUG)
            {
                printf("    unsuccessfull to RETRIVE PACKET\n");
            }
            break;
        }

        //GuiAtmStart

        if (node->guiOption)
        {
            GUI_QueueDequeuePacket(node->nodeId,
                GUI_MAC_LAYER,
                interfaceIndex,
                queuePriority,
                MESSAGE_ReturnPacketSize(nextMsg),
                node->getNodeTime());
        }

        //GuiAtmEnd

        if (DEBUG)
        {
            printf("    successfully RETRIVE PACKET\n");
        }

        nextMsg->next = NULL;
        if (msgList == NULL)
        {
            msgList = nextMsg;
            lastMsg = msgList;
        }
        else
        {
            lastMsg->next = nextMsg;
            lastMsg = nextMsg;
        }

        //update statistics
        atmLayer2Data->atmCellForward++;
    }

    if (i != ATM_NUM_CELL_IN_FRAME)
    {
        int numIdleCell = ATM_NUM_CELL_IN_FRAME - i;
        int j = 0;
        if (ASYNCHRONOUS_TEST_DEBUG)
        {
            printf("\nWhen copy IdleCell, Number of AtmCell at inf%u:-\n",
                interfaceIndex);
            atmScheduler->PrintNumAtmCellEachQueque();
            printf("    Copy the Idle Cell into Frame\n");
        }

        for (j = 0; j < numIdleCell; j++)
        {
            Message* idleMsg = Atm_Layer2CreateIdleCell(node);
            idleMsg->next = NULL;
            if (msgList == NULL)
            {
                msgList = idleMsg;
                lastMsg = msgList;
            }
            else
            {
                lastMsg->next = idleMsg;
                lastMsg = idleMsg;
            }

            if (DEBUG)
            {
                printf("    Copy the Idle Cell into Frame\n");
            }
        }
    }

    newMsg = MESSAGE_PackMessage(node, msgList, TRACE_ATM_LAYER, NULL);
    MESSAGE_SetLayer(newMsg, ATM_LAYER2, 0);
    MESSAGE_SetEvent(newMsg, MSG_ATM_LAYER2_FrameIndication);

    // Handle case when link bandwidth is 0.  Here, we just drop the Cell.
    if (atmLayer2Data->bandwidth == 0)
    {
        if (DEBUG)
        {
            printf("    bandwidth is 0, so drop frame\n");
        }
        MESSAGE_Free(node, newMsg);
        return;
    }

    transmissionDelay =
        (clocktype)(ATM_CELL_LENGTH * ATM_NUM_CELL_IN_FRAME * 8 * SECOND /
        atmLayer2Data->bandwidth);

    if (atmLayer2Data->otherNode == NULL) {
        ERROR_ReportError("Destination of the ATM LINK is not set\n");
    }

    MESSAGE_SetInstanceId(
        newMsg, (short)atmLayer2Data->otherNodeInterfaceIndex);

    if (DEBUG)
    {
        char traClockStr[MAX_STRING_LENGTH];
        char proClockStr[MAX_STRING_LENGTH];
        TIME_PrintClockInSecond(transmissionDelay, traClockStr);
        TIME_PrintClockInSecond(atmLayer2Data->propDelay, proClockStr);

        printf("    Send frame at Interface %d for node =%u with "
            "transmissionDelay %s sec and propDelay %s sec\n",
            interfaceIndex, atmLayer2Data->otherNode->nodeId,
            traClockStr, proClockStr);
    }

    if (atmLayer2Data->otherNode->partitionId
            == node->partitionData->partitionId) {
        MESSAGE_Send(atmLayer2Data->otherNode,
            newMsg,
            transmissionDelay + atmLayer2Data->propDelay);
    }
    else
    {
        newMsg->nodeId =  atmLayer2Data->otherNodeId;
        newMsg->eventTime = node->getNodeTime() + transmissionDelay +
                            atmLayer2Data->propDelay;

        PARALLEL_SendRemoteMessages(newMsg,
                                    atmLayer2Data->otherNode->partitionData,
                                    atmLayer2Data->otherNode->partitionId);
    }

    atmLayer2Data->atmLinkStatus = ATM_LAYER2_LINK_IS_BUSY;
    atmLayer2Data->totalBusyTime += transmissionDelay;

    transmissionFinishedMsg = MESSAGE_Alloc(
        node,
        ATM_LAYER2,
        0,
        MSG_ATM_LAYER2_TransmissionFinished);

    MESSAGE_SetInstanceId(transmissionFinishedMsg,
        (short)interfaceIndex);

    MESSAGE_Send(node, transmissionFinishedMsg, transmissionDelay);
}


// /**
// FUNCTION   :: Atm_Layer2AddUniCellHeader
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Add UNI header into the cell
// PARAMETERS ::
// + node : Node* : The Node Pointer
// + msg : Message* : pointer to message.
// + aal5ToAtml2Info : Aal5ToAtml2Info* :  pointer to Aal5ToAtml2Info
// RETURN     : void : NULL
// **/
static
void Atm_Layer2AddUniCellHeader(Node* node,
                                Message* msg,
                                Aal5ToAtml2Info* aal5ToAtml2Info)
{
    // Add Atm layer specific header or primitive
    MESSAGE_AddHeader(node, msg, ATM_CELL_HEADER, TRACE_ATM_LAYER);

    char* header = MESSAGE_ReturnPacket(msg);
    memset(header, 0, ATM_CELL_HEADER);

    AtmUniPart atmUniPart;

    atmUniPart.atm_gfc = 0;
    atmUniPart.atm_vci = aal5ToAtml2Info->outVCI;
    atmUniPart.atm_vpi = aal5ToAtml2Info->outVPI;

    atmUniPart.atm_clp = 0;
    atmUniPart.atm_pt = 0;

    if (aal5ToAtml2Info->atmLP)
    {
        atmUniPart.atm_clp = 1;
    }

    if (aal5ToAtml2Info->atmUU)
    {
        atmUniPart.atm_pt |= 0x4;
    }
    memcpy(header, &atmUniPart, sizeof(AtmUniPart));

    if (DEBUG)
    {
        printf("    AddUniCellHeader\n");
    }
}

// /**
// FUNCTION   :: Atm_Layer2AddNniCellHeader
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Add NNI header into the cell
// PARAMETERS ::
// + node : Node* : The Node Pointer
// + msg : Message* : pointer to message.
// + aal5ToAtml2Info : Aal5ToAtml2Info* :  pointer to Aal5ToAtml2Info
// RETURN     : void : NULL
// **/
static
void Atm_Layer2AddNniCellHeader(Node* node,
                                Message* msg,
                                Aal5ToAtml2Info* aal5ToAtml2Info)
{
    // Add Atm layer specific header or primitive
    MESSAGE_AddHeader(node, msg, ATM_CELL_HEADER, TRACE_ATM_LAYER);

    char* header = MESSAGE_ReturnPacket(msg);
    memset(header, 0, ATM_CELL_HEADER);

    AtmNniPart atmNniPart;

    atmNniPart.atm_vci = aal5ToAtml2Info->outVCI;
    atmNniPart.atm_vpi = aal5ToAtml2Info->outVPI;
    atmNniPart.atm_clp = 0;
    atmNniPart.atm_pt = 0;

    if (aal5ToAtml2Info->atmLP)
    {
        atmNniPart.atm_clp = 1;
    }

    if (aal5ToAtml2Info->atmUU)
    {
        atmNniPart.atm_pt |= 0x4;
    }
    memcpy(header, &atmNniPart, sizeof(AtmNniPart));

    if (DEBUG)
    {
        printf("    AddNniCellHeader\n");
    }
}


// /**
// FUNCTION   :: Atm_Layer2CreateCellFromFrame
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Demultiplexing cell from frame
// PARAMETERS ::
// + node : Node* : The Node Pointer
// + interfaceIndex : int : Interface Index
// + msg : Message* :  Packet Pointer
// RETURN     : void : NULL
// **/
static
void Atm_Layer2CreateCellFromFrame(Node* node,
                                   int interfaceIndex,
                                   Message* msg)
{
    // Check the header for idle cell
    unsigned int val;

    memcpy(&val, MESSAGE_ReturnPacket(msg), 4);
    if (val == 1)
    {
        if (DEBUG)
        {
            printf("    Idle Cell, return\n");
        }
        MESSAGE_Free(node, msg);
        return;
    }

    if (DEBUG)
    {
        printf("    Active Cell, process\n");
    }

    MESSAGE_SetLayer(msg, ATM_LAYER2, 0);
    MESSAGE_SetEvent(msg, MSG_ATM_LAYER2_PhyDataIndication);
    MESSAGE_SetInstanceId(msg, (short)interfaceIndex);
    msg->originatingNodeId = node->nodeId;
    MESSAGE_Send(node, msg, 0);
}


// /**
// FUNCTION   :: Atm_Layer2InsertCellToQueue
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Insert cell into a particular queue.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + msg : Message* : message ptr that insert into queue.
// + queueIndex : int: queue with that queueIndex
// + interfaceIndex  : int : at the interface.
// + atmSchd : AtmScheduler* : pointer to AtmScheduler.
// RETURN     : void : NULL
// **/
static
void Atm_Layer2InsertCellToQueue(Node* node,
                                 Message* msg,
                                 int queueIndex,
                                 int interfaceIndex,
                                 AtmScheduler* atmSchd)
{
    BOOL isFull = false;
    BOOL queueWasEmpty = atmSchd->isEmpty(ALL_PRIORITIES);

    if (DEBUG)
    {
        printf("In Node %u at Interface %d insert the packet\n",
            node->nodeId, interfaceIndex);
    }
    atmSchd->insert(msg,
        &isFull,
        queueIndex,
        NULL, //const void* infoField,
        node->getNodeTime());

    //GuiAtmStart

    if (node->guiOption)
    {
        if (isFull) {
            GUI_QueueDropPacket(node->nodeId,
                GUI_MAC_LAYER,
                interfaceIndex,
                queueIndex,
                node->getNodeTime());
        }
        else {
            GUI_QueueInsertPacket(node->nodeId,
                GUI_MAC_LAYER,
                interfaceIndex,
                queueIndex,
                MESSAGE_ReturnPacketSize(msg),
                node->getNodeTime());
        }
    }

    //GuiAtmEnd

    if (isFull)
    {
        // Discard the Cell.
        MESSAGE_Free(node, msg);
        return;
    }

    if (queueWasEmpty && !atmSchd->isEmpty(ALL_PRIORITIES))
    {
        Atm_Layer2HasCellToSend(node, interfaceIndex, atmSchd);
    }
}


// /**
// FUNCTION :: Atm_Layer2CellSendUpperLayer
// LAYER    :: ATM_Layer2
// PURPOSE ::  Send cell into upper layer.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + cellVci : unsigned short : VCI value.
// + cellVpi : unsigned char : VPI value.
// + interfaceIndex  : int : at the interface.
// + atmNniPart : AtmNniPart* : pointer to AtmNniPart.
// + msg : Message* : message ptr that insert into queue.
// RETURN :: void : NULL
// **/
static
void Atm_Layer2CellSendUpperLayer(Node* node,
                                  unsigned short cellVci,
                                  unsigned char cellVpi,
                                  int interfaceIndex,
                                  AtmNniPart* atmNniPart,
                                  Message* msg)
{
    //remove atm header
    MESSAGE_RemoveHeader(node, msg, ATM_CELL_HEADER, TRACE_ATM_LAYER);

    //send data cell to upper layer
    MESSAGE_SetLayer(msg, ADAPTATION_LAYER, ATM_PROTOCOL_AAL);
    MESSAGE_SetEvent(msg, MSG_ATM_ADAPTATION_ATMDataIndication);
    MESSAGE_SetInstanceId(msg, 0);

    MESSAGE_InfoAlloc(node, msg, sizeof(Aal5ToAtml2Info));

    Aal5ToAtml2Info* aal5ToAtml2Info =
        (Aal5ToAtml2Info*) MESSAGE_ReturnInfo(msg);

    aal5ToAtml2Info->incomingIntf = interfaceIndex;
    aal5ToAtml2Info->incomingVCI = cellVci;
    aal5ToAtml2Info->incomingVPI = cellVpi;
    aal5ToAtml2Info->atmCI =
        (unsigned short) (atmNniPart->atm_pt & 0x2);
    aal5ToAtml2Info->atmUU = (atmNniPart->atm_pt & 0x4);
    aal5ToAtml2Info->atmLP = atmNniPart->atm_clp;

    if (DEBUG)
    {
        printf("Node %d parameters are:-\n", node->nodeId);
        printf("\tIntf=%u InVCI=%u InVPI=%u\n",
            aal5ToAtml2Info->incomingIntf,
            aal5ToAtml2Info->incomingVCI,
            aal5ToAtml2Info->incomingVPI);
        printf("\tAtmCI=%u AtmUU=%u AtmLP=%u\n", aal5ToAtml2Info->atmCI,
            aal5ToAtml2Info->atmUU, aal5ToAtml2Info->atmLP);
    }
    MESSAGE_Send(node, msg, 0);
}


// /**
// FUNCTION :: Atm_Layer2ReceiveCellFromPhy
// LAYER    :: ATM_Layer2
// PURPOSE ::  Receive cell from Phy layer.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + interfaceIndex  : int : at the interface.
// + msg : Message* : message ptr that insert into queue.
// RETURN :: void : NULL
// **/
static
void Atm_Layer2ReceiveCellFromPhy(Node* node,
                                  int interfaceIndex,
                                  Message* msg)
{
    unsigned short cellVci = 0;
    unsigned char cellVpi = 0;
    char* packet = MESSAGE_ReturnPacket(msg);

    AtmLayer2Data* atmLayer2Data =
        Atm_Layer2GetAtmData(node, interfaceIndex);

    if (atmLayer2Data == NULL)
    {
        printf("node Id: %d\n", node->nodeId);
        ERROR_Assert(FALSE, "Empty atmLayer2Data\n");
    }

    AtmNniPart atmNniPart;
    memcpy(&atmNniPart, packet, sizeof(AtmNniPart));


    //GuiAtmStart

    if (node->guiOption)
    {
        GUI_Receive(atmLayer2Data->otherNodeId,
            node->nodeId,
            GUI_MAC_LAYER,
            GUI_DEFAULT_DATA_TYPE,
            atmLayer2Data->otherNodeInterfaceIndex,
            interfaceIndex,
            node->getNodeTime());
    }

    //GuiAtmEnd

    if (atmLayer2Data->interfaceType == ATM_LAYER2_INTF_UNI)
    {
        AtmUniPart atmUniPart;
        memcpy(&atmUniPart, packet, sizeof(AtmUniPart));
        cellVci = atmUniPart.atm_vci;
        cellVpi = atmUniPart.atm_vpi;

        if (DEBUG)
        {
            printf("In Node %u interfaceType ATM_LAYER2_INTF_UNI "
                "cellVCI=%u cellVPI=%u\n", node->nodeId, cellVci, cellVpi);
        }
    }
    else if (atmLayer2Data->interfaceType == ATM_LAYER2_INTF_NNI)
    {
        cellVci = atmNniPart.atm_vci;
        cellVpi = atmNniPart.atm_vpi;

        if (DEBUG)
        {
            printf("In Node %u interfaceType ATM_LAYER2_INTF_NNI "
                "cellVCI=%u cellVPI=%u\n", node->nodeId, cellVci, cellVpi);
        }
    }
    else
    {
        ERROR_Assert(FALSE, "Unknown ATM Interface Type\n");
    }

    // For Signaling Cell
    if (cellVpi == 0 && cellVci == 5)
    {
        //update statistics
        atmLayer2Data->numAtmCellInDelivers++;
        atmLayer2Data->numControlCell++;

        if (DEBUG)
        {
            printf("    Control cell, Send to upper layer\n");
        }
        Atm_Layer2CellSendUpperLayer(node, cellVci, cellVpi,
            interfaceIndex, (AtmNniPart*)(&atmNniPart), msg);
        return;
    }

    //update statistics
    atmLayer2Data->atmCellReceive++;

    if (atmLayer2Data->nodeType == ATM_LAYER2_ENDSYSTEM)
    {
        //update statistics
        atmLayer2Data->numAtmCellInDelivers++;

        if (DEBUG)
        {
            printf("    Node %u is End System\n", node->nodeId);
        }

        // Is my Data Cell
        if (DEBUG)
        {
            printf("    Data cell, Send to upper layer\n");
        }

        Atm_Layer2CellSendUpperLayer(node, cellVci, cellVpi,
            interfaceIndex, (AtmNniPart*)(&atmNniPart), msg);
        return;
    }

    // For Data Cell
    //Search the Transmission table for outgoing interfaec.
    //Insert the cell into the proper interface queue.
    if (DEBUG)
    {
        printf("    Node %u is Switch\n", node->nodeId);
    }

    AtmTransTableRow* transTableRow = Aal5SearchTransTable(
        node, cellVci, cellVpi);

    if (transTableRow == NULL)
    {
        //Drop this cell, update statistics and return
        //update statistics
        atmLayer2Data->atmCellNoRoutes++;

        if (DEBUG)
        {
            printf("    Data cell, "
                "but path not find into trans Table\n");
        }
        MESSAGE_Free(node, msg);
        return;
    }

    int outGoingIntf = transTableRow->outIntf;
    AtmLayer2Data* outgoingAtmLayer2Data =
        Atm_Layer2GetAtmData(node, outGoingIntf);

    if (DEBUG)
    {
        printf("    Data cell, so insert to queue index=%u at "
            "interface %u\n", (interfaceIndex + 1), outGoingIntf);
        printf("    VCI = %d VPI %d finalVCI = %d finalVPI %d\n", cellVci,
            cellVpi, transTableRow->finalVCI, transTableRow->finalVPI);
    }

    if (outgoingAtmLayer2Data->interfaceType == ATM_LAYER2_INTF_UNI)
    {
        AtmUniPart tempAtmUniPart;

        tempAtmUniPart.atm_gfc = 0; //not uesd
        tempAtmUniPart.atm_vci = transTableRow->finalVCI;
        tempAtmUniPart.atm_vpi = transTableRow->finalVPI;
        tempAtmUniPart.atm_pt = atmNniPart.atm_pt;
        tempAtmUniPart.atm_clp = atmNniPart.atm_clp;
        memcpy(
            MESSAGE_ReturnPacket(msg),
            &tempAtmUniPart,
            sizeof(AtmUniPart));
        Atm_Layer2InsertCellToQueue(node, msg, interfaceIndex + 1,
            outGoingIntf, outgoingAtmLayer2Data->atmScheduler);
        return;
    }

    atmNniPart.atm_vci = transTableRow->finalVCI;
    atmNniPart.atm_vpi = transTableRow->finalVPI;

    memcpy(MESSAGE_ReturnPacket(msg), &atmNniPart, sizeof(AtmNniPart));

    Atm_Layer2InsertCellToQueue(node, msg, interfaceIndex + 1,
        outGoingIntf, outgoingAtmLayer2Data->atmScheduler);
}


// /**
// FUNCTION :: Atm_Layer2TransmissionFinished
// LAYER    :: ATM_Layer2
// PURPOSE ::  Transmission of the frame is complete.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + interfaceIndex  : int : at the interface.
// + msg : Message* : message ptr that insert into queue.
// RETURN :: void : NULL
// **/
static
void Atm_Layer2TransmissionFinished(Node* node,
                                    int interfaceIndex,
                                    Message* msg)
{
    AtmLayer2Data* atmLayer2Data =
        Atm_Layer2GetAtmData(node, interfaceIndex);

    assert(atmLayer2Data->atmLinkStatus == ATM_LAYER2_LINK_IS_BUSY);

    atmLayer2Data->atmLinkStatus = ATM_LAYER2_LINK_IS_IDLE;

    if (DEBUG)
    {
        char clockStr[20];
        TIME_PrintClockInSecond(node->getNodeTime(), clockStr);
        printf("Node %d finished transmitting packet at time %s at "
            "Inderface %u\n", node->nodeId, clockStr, interfaceIndex);
    }

    if (!atmLayer2Data->atmScheduler->isEmpty(ALL_PRIORITIES))
    {
        if (DEBUG)
        {
            printf("    there's more packets in the queue, "
                "so try to send the next packet\n");
        }

        Atm_Layer2HasCellToSend(node,
            interfaceIndex,
            atmLayer2Data->atmScheduler);
    }
    MESSAGE_Free(node, msg);
}


// /**
// FUNCTION :: ATMLAYER2_ProcessEvent
// LAYER    :: ATM_Layer2
// PURPOSE ::  Process Atm layer2 specific event.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + msg : Message* : message ptr that insert into queue.
// RETURN :: void : NULL
// **/
void ATMLAYER2_ProcessEvent(Node *node,
                            Message *msg)
{
    switch (msg->eventType)
    {
    case MSG_ATM_LAYER2_AtmDataRequest:
        {
            Aal5ToAtml2Info* aal5ToAtml2Info =
                (Aal5ToAtml2Info*) MESSAGE_ReturnInfo(msg);

            int interfaceIndex = aal5ToAtml2Info->outIntf;
            AtmLayer2Data* atmLayer2Data =
                Atm_Layer2GetAtmData(node, interfaceIndex);
            AtmScheduler*  atmSchd = atmLayer2Data->atmScheduler;

            if (DEBUG)
            {
                printf("In Node %u recvd msg from AAL5 with\n",
                    node->nodeId);
                printf("    VCI = %d VPI %d outIntf = %d\n",
                    aal5ToAtml2Info->incomingVCI,
                    aal5ToAtml2Info->incomingVPI,
                    aal5ToAtml2Info->outIntf);
                printf("\tAtmCI=%u AtmUU=%u AtmLP=%u\n",
                    aal5ToAtml2Info->atmCI,
                    aal5ToAtml2Info->atmUU,
                    aal5ToAtml2Info->atmLP);
            }

            if (atmLayer2Data->interfaceType  == ATM_LAYER2_INTF_UNI)
            {
                Atm_Layer2AddUniCellHeader(node, msg, aal5ToAtml2Info);
            }
            else
            {
                Atm_Layer2AddNniCellHeader(node, msg, aal5ToAtml2Info);
            }

            if (aal5ToAtml2Info->incomingVPI == 0 &&
                aal5ToAtml2Info->incomingVCI == 5)
            {
                Atm_Layer2InsertCellToQueue(node,
                    msg, 0, interfaceIndex, atmSchd);
            }
            else
            {
                Atm_Layer2InsertCellToQueue(node,
                    msg, interfaceIndex +1, interfaceIndex, atmSchd);
            }
            break;
        }
    case MSG_ATM_LAYER2_FrameIndication:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);

            Message* msgList;
            Message* tmpMsg;

            if (DEBUG)
            {
                printf("In Node %u at Interface %d Receive Frame\n",
                    node->nodeId, interfaceIndex);
            }

            msgList = MESSAGE_UnpackMessage(node, msg, FALSE, FALSE);
            while (msgList != NULL)
            {
                tmpMsg = msgList;
                msgList = msgList->next;
                tmpMsg->next = NULL;
                Atm_Layer2CreateCellFromFrame(node, interfaceIndex, tmpMsg);
            }
            MESSAGE_Free(node, msg);
            break;
        }
    case MSG_ATM_LAYER2_PhyDataIndication:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            Atm_Layer2ReceiveCellFromPhy(node, interfaceIndex, msg);
            break;
        }
    case MSG_ATM_LAYER2_TransmissionFinished:
        {
            int interfaceIndex = MESSAGE_GetInstanceId(msg);
            Atm_Layer2TransmissionFinished(node, interfaceIndex, msg);
            break;
        }
    default:
        {
            if (DEBUG)
            {
                printf("In Node %u and EventType=%u\n",
                    node->nodeId, msg->eventType);
            }
            ERROR_Assert(FALSE, "Unknown Event Type\n");
        }
    }
}

// /**
// FUNCTION   :: Atm_Layer2CongestionExperienced
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Check congestion is occur into this link or interface.
// PARAMETERS ::
// +   msg : Message* :  pointer to Message.
                            // RETURN     : void : NULL
// **/
void Atm_Layer2CongestionExperienced(Message* msg)
{
    AtmNniPart atmNniPart;
    memcpy(&atmNniPart, MESSAGE_ReturnPacket(msg), sizeof(AtmNniPart));

    atmNniPart.atm_pt |= 0x2;
    memcpy(MESSAGE_ReturnPacket(msg), &atmNniPart, sizeof(AtmNniPart));
}


// /**
// FUNCTION :: Atm_BWCheck
// LAYER    :: ATM_Layer2
// PURPOSE ::  Check congestion is occur into this link or interface.
// PARAMETERS ::
// + node : Node* : pointer to node.
// + incomingIntf : int : for which flow this BW specified.
// + outgoingIntf : int : in which interface
// + isAdd : BOOL : add this BW or reduce this BW.
// + bwInfo : AtmBWInfo* : pointer to AtmBWInfo.
// RETURN :: BOOL : Return TRUE if action executed properly,
//                  otherwise FALSE.
// **/
BOOL Atm_BWCheck(Node* node,
                 int incomingIntf,
                 int outgoingIntf,
                 BOOL isAdd,
                 AtmBWInfo* bwInfo)
{
    AtmLayer2Data* atmLayer2Data =
        Atm_Layer2GetAtmData(node, outgoingIntf);

    if (DEBUG)
    {
        if (incomingIntf == -1)
        {
            printf("In Node %u asking for BW=%u at Interface =%d for own's "
                "created cell\n",
                node->nodeId, bwInfo->reqdBw, outgoingIntf);
        }
        else
        {
            printf("In Node %u asking for BW=%u at Interface =%d for "
                " Interface =%d created cell\n",
                node->nodeId, bwInfo->reqdBw, outgoingIntf, incomingIntf);
        }
        if (isAdd)
        {
            printf("    Add BW\n");
        }
        else
        {
            printf("    Reduce BW\n");
        }
    }

    if (incomingIntf == -1)
    {
        incomingIntf = outgoingIntf;
    }

    return (atmLayer2Data->atmScheduler->AtmUpdateQueueSpecificBW(
        (incomingIntf + 1),
        bwInfo->reqdBw,
        isAdd));
}


// -----------------------------------------------------------------------
// Finalize
// -----------------------------------------------------------------------

// /**
// FUNCTION :: ATMLAYER2_Finalize
// LAYER    :: ATM_Layer2
// PURPOSE ::  Called at the end of simulation to collect the results of
//             the simulation of the ATM Layer2.
// PARAMETERS ::
// + node : Node* : pointer to node.
// RETURN :: void : NULL
// **/
void ATMLAYER2_Finalize(Node* node)
{
    double linkUtilization;
    char buf[100];
    int interfaceIndex;
    AtmScheduler* schedulerPtr = NULL;

    for (interfaceIndex = 0;
    interfaceIndex < node->numAtmInterfaces;
    interfaceIndex++)
    {
        AtmLayer2Data* atmLayer2Data =
            Atm_Layer2GetAtmData(node, interfaceIndex);


        if (atmLayer2Data->atmLayer2Stats == TRUE)
        {
            sprintf(buf, "Destination = %u", atmLayer2Data->otherNodeId);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);

            sprintf(buf, "Cell Received = %d",
                atmLayer2Data->atmCellReceive);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);

            sprintf(buf, "Cell Forward = %d", atmLayer2Data->atmCellForward);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);

            sprintf(buf, "Cell Discarded for no Route = %d",
                atmLayer2Data->atmCellNoRoutes);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);


            sprintf(buf, "Control Cell Received = %d",
                atmLayer2Data->numControlCell);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);

            sprintf(buf, "Cell Delivered to upper layer = %d",
                atmLayer2Data->numAtmCellInDelivers);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);

            if (node->getNodeTime() == 0)
            {
                linkUtilization = 0;
            }
            else
            {
                linkUtilization = (double) atmLayer2Data->totalBusyTime /
                    (double) node->getNodeTime();
            }
            sprintf(buf, "Link Utilization = %f", linkUtilization);
            IO_PrintStat(node, "ATM", "ATM LAYER2",
                ANY_DEST, interfaceIndex, buf);
        }

        schedulerPtr = atmLayer2Data->atmScheduler;
        (*schedulerPtr).finalize(node, "ATM", interfaceIndex);
    }
}

// /**
// FUNCTION   :: Atm_GetAddrForOppositeNodeId
// LAYER      :: ATM_LAYER2
// PURPOSE    :: Get the Address of opposite direction of a ATM-LINK
// PARAMETERS ::
// +   node : Node* :  pointer to Node.
// +   atmInfIndex : int :  interface used.
// RETURN     : Address : Associated address structure
// **/

Address Atm_GetAddrForOppositeNodeId(Node* node,
                                     int atmInfIndex)
{
    AtmLayer2Data* atmLayer2Data =
        Atm_Layer2GetAtmData(node, atmInfIndex);

    ERROR_Assert(atmInfIndex != -1,
        "ATM: InterfaceIndex should not be negative.\n");

    ERROR_Assert(atmLayer2Data != NULL,
        "AtmLayer2Data should not be NULL.\n");

    return (MAPPING_GetInterfaceAddressForInterface(node,
        atmLayer2Data->otherNodeId,
        NETWORK_ATM,
        atmLayer2Data->otherNodeInterfaceIndex));
}
